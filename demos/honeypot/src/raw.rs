//! Complete Ethernet frames reach this world before any protocol parsing.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;

use fictionet::stdlib::network::ethernet::frame::{self, Frame, Mac};
use fictionet::stdlib::network::ip;
use fictionet::sync::Mutex;
use fictionet::{Cx, Interface, Packet};
use fictionet_host::raw::{EthernetFrame, RawAttachment};

use crate::{Clock, Config, Honeypot, INTERNET, observe::Hex, observe::Sink, observe::Sinks};

struct Capture {
    writer: Sink,
    lost: u64,
    clock: Clock,
}

impl Capture {
    fn frame(&mut self, fcx: &Cx, direction: &str, bytes: &[u8]) {
        let record = serde_json::json!({
            "at_us": self.clock.micros(fcx.now()),
            "direction": direction,
            "bytes": Hex(bytes.to_vec()),
            "lost": self.lost,
        });
        let mut line = serde_json::to_vec(&record).expect("a frame record is serializable");
        line.push(b'\n');
        if self.writer.put(&line) {
            self.lost = 0;
        } else {
            self.lost = self.lost.saturating_add(1);
        }
    }
}

/// Starts the existing honeypot behind a complete Ethernet attachment.
///
/// `raw_log` receives every frame, including malformed headers, VLAN tags,
/// unknown EtherTypes and Ethernet padding, as hexadecimal JSON lines before
/// parsing. Refused records are counted in the next accepted record; partial
/// records are completed before the next one. `sinks` retain the existing IP
/// capture and TCP option observations.
///
/// Only untagged IPv4 and IPv6 addressed to this NIC enter the IP attachment.
/// ARP for the configured IPv4 address is answered here. A bounded table of
/// source IP addresses and Ethernet senders supplies reply destinations;
/// eviction drops replies until another packet refreshes that source. IPv6
/// peers must have a static neighbor entry. The driver and its polling thread
/// must be opened outside `fictionet::run` and kept alive for the run.
pub fn start_raw(
    fcx: &Cx,
    config: &Config,
    clock: Clock,
    sinks: Sinks,
    raw: RawAttachment,
    raw_log: Box<dyn Write + Send>,
) -> fictionet::Result<Honeypot> {
    let mac = raw.mac_address();
    let (sender, mut receiver) = raw.split();
    let (attacher, attachments) = fictionet::attachments();
    let end = Arc::new(Mutex::new(attacher.attach(INTERNET)?));
    let honeypot = crate::start(fcx, config, clock, sinks, attachments)?;
    let peers = Arc::new(Mutex::new(BTreeMap::<IpAddr, Mac>::new()));
    let capture = Arc::new(Mutex::new(Capture {
        writer: Sink::new(raw_log),
        lost: 0,
        clock,
    }));
    let address = config.address;
    let incoming_end = end.clone();
    let incoming_peers = peers.clone();
    let incoming_capture = capture.clone();
    let incoming_sender = sender.clone();
    fcx.spawn(move |fcx| async move {
        // Keep the attacher alive for the lifetime of its internet endpoint.
        let _attacher = attacher;
        loop {
            let EthernetFrame(bytes) = receiver.recv(&fcx).await?;
            incoming_capture.lock().frame(&fcx, "in", &bytes);
            fcx.yield_now().await?;
            let Some(frame) = Frame::parse(&bytes) else {
                continue;
            };
            if frame::is_group(&frame.src) || (frame.dst != mac && frame.dst != frame::BROADCAST) {
                continue;
            }
            if let Some(reply) = arp_reply(&frame, mac, address) {
                incoming_capture.lock().frame(&fcx, "out", &reply);
                incoming_sender.send(&fcx, EthernetFrame(reply)).await?;
                continue;
            }
            let Some((source, packet)) = ip_packet(&frame) else {
                continue;
            };
            {
                let mut peers = incoming_peers.lock();
                if peers.len() >= 1024 && !peers.contains_key(&source) {
                    peers.pop_first();
                }
                peers.insert(source, frame.src);
            }
            incoming_end.lock().send(Packet(packet.to_vec()));
        }
    });
    fcx.spawn(move |fcx| async move {
        loop {
            let packet = std::future::poll_fn(|cx| end.lock().poll_recv(&fcx, cx)).await?;
            let Some(header) = ip::Header::parse(&packet.0) else {
                continue;
            };
            let Some(peer) = peers.lock().get(&header.dst).copied() else {
                continue;
            };
            let kind = if header.dst.is_ipv4() {
                frame::IPV4
            } else {
                frame::IPV6
            };
            let bytes = frame::frame(peer, mac, kind, &packet.0);
            capture.lock().frame(&fcx, "out", &bytes);
            sender.send(&fcx, EthernetFrame(bytes)).await?;
        }
    });
    Ok(honeypot)
}

fn ip_packet<'a>(frame: &Frame<'a>) -> Option<(IpAddr, &'a [u8])> {
    let version = match frame.ethertype {
        frame::IPV4 => 4,
        frame::IPV6 => 6,
        _ => return None,
    };
    if frame.payload.first()? >> 4 != version {
        return None;
    }
    let header = ip::Header::parse(frame.payload)?;
    Some((header.src, &frame.payload[..header.payload.end]))
}

fn arp_reply(frame: &Frame<'_>, mac: Mac, address: IpAddr) -> Option<Vec<u8>> {
    let IpAddr::V4(address) = address else {
        return None;
    };
    let p = frame.payload;
    if frame.ethertype != frame::ARP
        || p.len() < 28
        || p[..8] != [0, 1, 8, 0, 6, 4, 0, 1]
        || p[8..14] != frame.src
        || p[24..28] != address.octets()
    {
        return None;
    }
    let mut reply = p[..28].to_vec();
    reply[6..8].copy_from_slice(&2u16.to_be_bytes());
    reply[18..24].copy_from_slice(&frame.src);
    reply[24..28].copy_from_slice(&p[14..18]);
    reply[8..14].copy_from_slice(&mac);
    reply[14..18].copy_from_slice(&address.octets());
    Some(frame::frame(frame.src, mac, frame::ARP, &reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_padding_is_not_an_ip_payload() {
        let source = "192.0.2.5".parse().unwrap();
        let destination = "203.0.113.10".parse().unwrap();
        let packet = ip::packet(source, destination, 1, &[8, 0, 0, 0]);
        let bytes = frame::frame([2; 6], [4; 6], frame::IPV4, &packet.0);
        let parsed = Frame::parse(&bytes).unwrap();
        assert_eq!(ip_packet(&parsed), Some((source, packet.0.as_slice())));
        let mut malformed = bytes.clone();
        malformed[16..18].copy_from_slice(&200u16.to_be_bytes());
        assert!(ip_packet(&Frame::parse(&malformed).unwrap()).is_none());
        let vlan = frame::frame([2; 6], [4; 6], 0x8100, &packet.0);
        assert!(ip_packet(&Frame::parse(&vlan).unwrap()).is_none());
        let unknown = frame::frame([2; 6], [4; 6], 0x88b5, &packet.0);
        assert!(ip_packet(&Frame::parse(&unknown).unwrap()).is_none());
    }

    #[test]
    fn arp_answers_only_for_the_configured_address() {
        let mac = [2; 6];
        let peer = [4; 6];
        let address = "203.0.113.10".parse().unwrap();
        let mut payload = vec![0, 1, 8, 0, 6, 4, 0, 1];
        payload.extend_from_slice(&peer);
        payload.extend_from_slice(&[192, 0, 2, 5]);
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(&[203, 0, 113, 10]);
        let bytes = frame::frame(frame::BROADCAST, peer, frame::ARP, &payload);
        let request = Frame::parse(&bytes).unwrap();
        let bytes = arp_reply(&request, mac, address).unwrap();
        let reply = Frame::parse(&bytes).unwrap();
        assert_eq!(
            (reply.src, reply.dst, reply.ethertype),
            (mac, peer, frame::ARP)
        );
        assert_eq!(&reply.payload[6..8], &[0, 2]);
        assert_eq!(&reply.payload[8..14], &mac);
        assert_eq!(&reply.payload[14..18], &[203, 0, 113, 10]);
        assert_eq!(&reply.payload[18..24], &peer);
        assert_eq!(&reply.payload[24..28], &[192, 0, 2, 5]);
        assert!(arp_reply(&request, mac, "203.0.113.11".parse().unwrap()).is_none());
        assert!(Frame::parse(&[0; 13]).is_none());
    }
}
