//! The port-zero probes and the initiated traffic through `start_raw`: the
//! honeypot behind whole Ethernet frames, as a NIC hands them over. Two
//! in-memory attachments stand for two cards on one link, joined by a task
//! that copies frames between their wires.

use std::net::Ipv4Addr;
use std::time::Duration;

use fictionet::stdlib::network::ethernet::frame::{self, Frame, Mac};
use fictionet::stdlib::network::ethernet::host::{Config, Host, Ipv4Config, Received};
use fictionet::stdlib::protocols::arp;
use fictionet::{Cx, End, Interface, InterfaceExt, Packet};
use fictionet_host::raw::{EthernetFrame, RawAttachment, RawWire};
use fictionet_test_support::world::world;
use honeypot_world::{Clock, start_raw};

#[path = "common/capture.rs"]
mod capture;
#[path = "common/initiated.rs"]
mod initiated;
#[path = "common/port_zero.rs"]
mod port_zero;

use capture::{Capture, config, sinks};
use port_zero::{Probe, lines};

const CLIENT_MAC: Mac = [0x02, 0, 0, 0, 0, 2];
const SERVER_MAC: Mac = [0x02, 0, 0, 0, 0, 1];

/// Copies every frame each wire's world sends onto the other wire.
async fn link(fcx: Cx, mut a: RawWire, mut b: RawWire) -> fictionet::Result {
    loop {
        let (frame, from_a) = tokio::select! {
            frame = a.recv(&fcx) => (frame?, true),
            frame = b.recv(&fcx) => (frame?, false),
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let to = if from_a { &b } else { &a };
        to.send(&fcx, frame).await?;
    }
}

/// The prober's network card: an Ethernet host at `address` that resolves
/// `gateway` first, then carries the packets of `end` in frames.
async fn card(
    fcx: Cx,
    mut raw: RawAttachment,
    mut end: End,
    address: Ipv4Addr,
    gateway: Ipv4Addr,
) -> fictionet::Result {
    let mut host = Host::new(
        Config {
            mac: raw.mac_address(),
            mtu: 1500,
            ipv4: Some(Ipv4Config { address, gateway }),
            ipv6: None,
        },
        fcx.now(),
    )?;
    while host.ipv4_gateway().is_none() {
        while let Some(frame) = host.transmit(fcx.now()) {
            raw.send(&fcx, EthernetFrame(frame)).await?;
        }
        let frame = raw.recv(&fcx).await?;
        host.receive(fcx.now(), &frame.0);
    }
    loop {
        tokio::select! {
            packet = end.recv(&fcx) => {
                let frame = host.send(fcx.now(), &packet?).expect("the gateway is resolved");
                raw.send(&fcx, EthernetFrame(frame)).await?;
            }
            frame = raw.recv(&fcx) => {
                if let Received::World(packet) = host.receive(fcx.now(), &frame?.0) {
                    end.send(Packet::new(packet.to_vec()));
                }
            }
        }
        while let Some(frame) = host.transmit(fcx.now()) {
            raw.send(&fcx, EthernetFrame(frame)).await?;
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// Checks the server's frame log: the ARP exchanges both ways, each probe
/// in an inbound IPv4 frame, in order, and no frame lost or dropped.
fn check_frames(frames: &Capture, probes: &[Vec<u8>]) {
    let records = lines(frames);
    let mut arp = Vec::new();
    let mut inbound_ipv4 = Vec::new();
    for record in &records {
        assert_eq!(record["lost"], 0);
        assert_eq!(record["rx_queue_dropped"], 0);
        assert_eq!(record["tx_queue_dropped"], 0);
        let bytes = unhex(record["bytes"].as_str().unwrap());
        let frame = Frame::parse(&bytes).expect("an Ethernet frame");
        let inbound = record["direction"] == "in";
        match frame.ethertype {
            frame::ARP => {
                let packet = arp::Packet::receive(frame.payload).expect("an ARP packet");
                arp.push((inbound, packet.operation, packet.target_ip));
            }
            frame::IPV4 if inbound => inbound_ipv4.push(frame.payload.to_vec()),
            _ => {}
        }
    }
    for exchange in [
        (true, arp::Operation::Request, port_zero::PEER),
        (false, arp::Operation::Reply, port_zero::CLIENT),
        (false, arp::Operation::Request, port_zero::CLIENT),
        (true, arp::Operation::Reply, port_zero::PEER),
    ] {
        assert!(arp.contains(&exchange), "{exchange:?} in {arp:?}");
    }
    let mut payloads = inbound_ipv4.iter();
    for probe in probes {
        assert!(
            payloads.any(|payload| payload.starts_with(probe)),
            "each probe arrives in a frame, in order"
        );
    }
}

#[test]
fn port_zero_probes_through_ethernet() {
    world(Duration::from_secs(30), |fcx| async move {
        let (client_raw, client_wire) = RawAttachment::in_memory(CLIENT_MAC);
        let (server_raw, server_wire) = RawAttachment::in_memory(SERVER_MAC);
        let queues = [server_raw.receive_stats(), server_raw.transmit_stats()];
        fcx.spawn(move |fcx| link(fcx, client_wire, server_wire));
        let (log, pcap, frames) = (Capture::default(), Capture::default(), Capture::default());
        let server = start_raw(
            &fcx,
            &config(port_zero::PEER, port_zero::CLIENT),
            Clock::starting_now(),
            sinks(&log, &pcap),
            server_raw,
            Box::new(frames.clone()),
        )?;
        let (end, relay) = fictionet::pair();
        fcx.spawn(move |fcx| card(fcx, client_raw, relay, port_zero::CLIENT, port_zero::PEER));
        let mut probe = Probe::new(&server, end).await?;
        probe.run(&fcx).await?;
        probe.check(&log, &pcap);
        check_frames(&frames, &probe.sent);
        assert!(queues.iter().all(|queue| queue.queue_dropped() == 0));
        Ok(())
    });
}

#[test]
fn initiated_traffic_through_ethernet() {
    world(Duration::from_secs(30), |fcx| async move {
        let (client_raw, client_wire) = RawAttachment::in_memory(CLIENT_MAC);
        let (server_raw, server_wire) = RawAttachment::in_memory(SERVER_MAC);
        fcx.spawn(move |fcx| link(fcx, client_wire, server_wire));
        let pcap = Capture::default();
        let client = start_raw(
            &fcx,
            &config(initiated::CLIENT, initiated::PEER),
            Clock::starting_now(),
            sinks(&Capture::default(), &pcap),
            client_raw,
            Box::new(std::io::sink()),
        )?;
        let remote = start_raw(
            &fcx,
            &config(initiated::PEER, initiated::CLIENT),
            Clock::starting_now(),
            sinks(&Capture::default(), &Capture::default()),
            server_raw,
            Box::new(std::io::sink()),
        )?;
        initiated::exchanges(&fcx, &client, &remote).await?;
        initiated::check(&pcap);
        Ok(())
    });
}
