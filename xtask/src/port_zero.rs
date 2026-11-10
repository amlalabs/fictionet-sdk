//! Literal port probes, executed only by the marked QEMU guest.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use fictionet::stdlib::network::ip;
use fictionet::{Cx, End, Interface, InterfaceExt, Packet};
use fictionet_host::raw::{EthernetFrame, RawAttachment, RawPump};
use honeypot_world::{Clock, observe::Sinks};

use super::egress::{Capture, config, endpoints, prepare_device, prepare_tun};

const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const PEER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

fn transport(protocol: u8, bytes: &mut [u8]) -> Packet {
    let offset = if protocol == 6 { 16 } else { 6 };
    let checksum = ip::transport_checksum(CLIENT.into(), PEER.into(), protocol, bytes);
    bytes[offset..offset + 2].copy_from_slice(&checksum.to_be_bytes());
    ip::packet(CLIENT.into(), PEER.into(), protocol, bytes)
}

fn tcp(ports: (u16, u16), seq: u32, ack: u32, flags: u8, data: &[u8]) -> Packet {
    let mut bytes = Vec::new();
    bytes.extend(ports.0.to_be_bytes());
    bytes.extend(ports.1.to_be_bytes());
    bytes.extend(seq.to_be_bytes());
    bytes.extend(ack.to_be_bytes());
    bytes.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    bytes.extend(data);
    transport(6, &mut bytes)
}

fn udp(ports: (u16, u16), data: &[u8]) -> Packet {
    let mut bytes = Vec::new();
    bytes.extend(ports.0.to_be_bytes());
    bytes.extend(ports.1.to_be_bytes());
    bytes.extend(((data.len() + 8) as u16).to_be_bytes());
    bytes.extend([0, 0]);
    bytes.extend(data);
    let mut packet = transport(17, &mut bytes);
    // A computed zero checksum is transmitted as all ones in UDP.
    if packet.0[26..28] == [0, 0] {
        packet.0[26..28].copy_from_slice(&[0xff, 0xff]);
    }
    packet
}

fn number(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

struct Probe {
    end: End,
    sent: Vec<Vec<u8>>,
}

impl Probe {
    fn send(&mut self, packet: Packet) {
        self.sent.push(packet.0.clone());
        self.end.send(packet);
    }

    async fn receive(&mut self, fcx: &Cx, protocol: u8) -> fictionet::Result<Vec<u8>> {
        let packet = tokio::time::timeout(Duration::from_secs(3), self.end.recv(fcx))
            .await
            .map_err(|_| {
                fictionet::Error::msg(format!(
                    "no protocol {protocol} reply after probe {}",
                    self.sent.len()
                ))
            })??;
        let header = ip::Header::parse_whole(&packet.0)
            .ok_or_else(|| fictionet::Error::msg("invalid reply IP header"))?;
        assert_eq!((header.src, header.dst), (PEER.into(), CLIENT.into()));
        assert_eq!(header.protocol, protocol);
        assert_eq!(ip::checksum(&packet.0[..header.payload.start]), 0);
        let bytes = header.payload(&packet.0);
        let checksum = if protocol == 1 {
            ip::checksum(bytes)
        } else {
            ip::transport_checksum(header.src, header.dst, protocol, bytes)
        };
        assert_eq!(checksum, 0, "reply checksum");
        Ok(bytes.to_vec())
    }

    async fn tcp_reply(
        &mut self,
        fcx: &Cx,
        ports: (u16, u16),
        ack: u32,
        flags: u8,
    ) -> fictionet::Result<Vec<u8>> {
        let bytes = self.receive(fcx, 6).await?;
        assert!(bytes.len() >= 20);
        assert_eq!(&bytes[..2], &ports.1.to_be_bytes());
        assert_eq!(&bytes[2..4], &ports.0.to_be_bytes());
        assert_eq!(bytes[13], flags, "TCP response flags");
        assert_eq!(number(&bytes, 8), ack, "TCP acknowledgement");
        Ok(bytes)
    }

    async fn run(
        &mut self,
        fcx: &Cx,
        name: &str,
        delivered: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    ) -> fictionet::Result {
        // Random sequence numbers and payloads bind responses to these probes.
        let mut random = [0; 32];
        fcx.fill_random(&mut random);
        let seq = number(&random, 0);
        for ports in [(41000, 0), (0, 0), (0, 18082), (41001, 18082)] {
            self.send(tcp(ports, seq, 0, 2, &[]));
            let reply = self
                .tcp_reply(fcx, ports, seq.wrapping_add(1), 0x14)
                .await?;
            assert_eq!(number(&reply, 4), 0);
            println!(
                "{name}: TCP {} -> {} SYN reset with matching acknowledgement",
                ports.0, ports.1
            );
        }
        // A bare ACK to a closed port is reset without an ACK flag.
        self.send(tcp((0, 0), seq, seq.wrapping_add(19), 0x10, &[]));
        let reply = self.tcp_reply(fcx, (0, 0), 0, 4).await?;
        assert_eq!(number(&reply, 4), seq.wrapping_add(19));

        // Exercise the ordinary listener before the source-zero handshake.
        self.send(tcp((41002, 80), seq, 0, 2, &[]));
        let reply = self
            .tcp_reply(fcx, (41002, 80), seq.wrapping_add(1), 0x12)
            .await?;
        self.send(tcp(
            (41002, 80),
            seq.wrapping_add(1),
            number(&reply, 4).wrapping_add(1),
            0x14,
            &[],
        ));

        self.send(tcp((0, 80), seq, 0, 2, &[]));
        let reply = self
            .tcp_reply(fcx, (0, 80), seq.wrapping_add(1), 0x12)
            .await?;
        println!("{name}: source-zero SYN received SYN-ACK");
        let server_seq = number(&reply, 4).wrapping_add(1);
        self.send(tcp((0, 80), seq.wrapping_add(1), server_seq, 0x10, &[]));
        let reply = self
            .tcp_reply(fcx, (0, 80), seq.wrapping_add(1), 0x11)
            .await?;
        assert_eq!(number(&reply, 4), server_seq);
        self.send(tcp(
            (0, 80),
            seq.wrapping_add(1),
            server_seq.wrapping_add(1),
            0x10,
            &[],
        ));
        println!(
            "{name}: TCP source zero to open port answered SYN, then closed with FIN after handshake"
        );

        for source in [41005, 0] {
            self.send(udp((source, 18081), &random));
            let (data, from) = tokio::time::timeout(Duration::from_secs(3), delivered.recv())
                .await?
                .ok_or_else(|| fictionet::Error::msg("UDP listener stopped"))?;
            assert_eq!(data, random);
            assert_eq!(from, SocketAddr::new(CLIENT.into(), source));
            println!(
                "{name}: UDP source {source} delivered random payload to open port with source preserved"
            );
        }

        for ports in [(41003, 0), (0, 0), (0, 18082), (41004, 18082)] {
            let packet = udp(ports, &random);
            let sent = packet.0.clone();
            self.send(packet);
            let reply = self.receive(fcx, 1).await?;
            assert!(
                reply.len() >= 36,
                "ICMP quote must contain IP and UDP headers"
            );
            assert_eq!(&reply[..2], &[3, 3], "ICMP destination port unreachable");
            let quote = &reply[8..];
            assert!(quote.len() <= sent.len());
            assert_eq!(
                quote,
                &sent[..quote.len()],
                "ICMP must quote the actual probe"
            );
            println!(
                "{name}: UDP {} -> {} returned port unreachable quoting the probe",
                ports.0, ports.1
            );
        }
        Ok(())
    }
}

fn sinks(log: &Capture, pcap: &Capture) -> Sinks {
    Sinks {
        log: Box::new(log.clone()),
        pcap: Box::new(pcap.clone()),
    }
}

fn observations(log: &Capture, pcap: &Capture, sent: &[Vec<u8>]) -> fictionet::Result {
    let captured = pcap.0.lock().unwrap();
    let mut blocks = captured.as_slice();
    let mut packets = Vec::new();
    while !blocks.is_empty() {
        let length = fictionet::stdlib::codec::le32(blocks, 4).expect("pcap block length") as usize;
        assert!(length >= 12 && length <= blocks.len());
        assert_eq!(
            fictionet::stdlib::codec::le32(blocks, length - 4),
            Some(length as u32)
        );
        if fictionet::stdlib::codec::le32(blocks, 0) == Some(6) {
            let count =
                fictionet::stdlib::codec::le32(blocks, 20).expect("captured length") as usize;
            packets.push(
                blocks
                    .get(28..28 + count)
                    .expect("complete captured packet")
                    .to_vec(),
            );
        }
        blocks = &blocks[length..];
    }
    let ingress: Vec<_> = packets
        .iter()
        .filter(|packet| ip::source(packet) == Some(CLIENT.into()))
        .collect();
    assert_eq!(
        ingress,
        sent.iter().collect::<Vec<_>>(),
        "capture preserves all probes byte for byte and in order"
    );
    let expected: Vec<_> = sent
        .iter()
        .filter_map(|packet| {
            let header = ip::Header::parse_whole(packet).unwrap();
            let bytes = header.payload(packet);
            let source = u16::from_be_bytes([bytes[0], bytes[1]]);
            let destination = u16::from_be_bytes([bytes[2], bytes[3]]);
            (source == 0 || destination == 0).then_some((
                packet,
                header.protocol,
                SocketAddr::new(header.src, source).to_string(),
                SocketAddr::new(header.dst, destination).to_string(),
            ))
        })
        .collect();
    let bytes = log.0.lock().unwrap();
    let records = std::str::from_utf8(&bytes)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let facts: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "port_zero")
        .collect();
    assert_eq!(
        facts.len(),
        expected.len(),
        "one observation per literal-zero ingress packet, no ordinary-port observations"
    );
    let mut last_capture = 0;
    for (fact, (packet, protocol, source, destination)) in facts.into_iter().zip(expected) {
        assert_eq!(fact["protocol"], protocol);
        assert_eq!(fact["src"], source);
        assert_eq!(fact["dst"], destination);
        assert_eq!(fact["attachment"], "internet");
        assert_eq!(fact["checksum_valid"], true);
        assert_eq!(fact["fragmented"], false);
        assert_eq!(fact["capture_queued"], true);
        let capture = fact["capture_packet"].as_u64().unwrap();
        assert!(
            capture > last_capture,
            "distinct ordered capture references"
        );
        assert_eq!(
            &packets[capture as usize - 1],
            packet,
            "observation references its exact captured input"
        );
        last_capture = capture;
    }
    println!(
        "Honeypot observations match every literal-zero input and exclude ordinary-port controls"
    );
    Ok(())
}

async fn udp_listener(
    fcx: &Cx,
    peer: &honeypot_world::Honeypot,
) -> fictionet::Result<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>> {
    let machine = endpoints(peer)?.await?;
    let mut udp = machine.udp.bind(18081)?;
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    fcx.spawn(move |fcx| async move {
        loop {
            let received = udp.recv(&fcx).await?;
            sender.send(received).await?;
        }
    });
    Ok(receiver)
}

async fn world() -> fictionet::Result {
    fictionet::run(fictionet::Seed::random(), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let end = attacher.attach(honeypot_world::INTERNET)?;
        let log = Capture::default();
        let pcap = Capture::default();
        let _peer = honeypot_world::start(
            &fcx,
            &config(PEER, CLIENT),
            Clock::starting_now(),
            sinks(&log, &pcap),
            attachments,
        )?;
        let mut delivered = udp_listener(&fcx, &_peer).await?;
        let mut probe = Probe {
            end,
            sent: Vec::new(),
        };
        probe.run(&fcx, "world", &mut delivered).await?;
        observations(&log, &pcap, &probe.sent)?;
        fcx.cancel();
        Ok(())
    })
    .await
}

async fn tun() -> fictionet::Result {
    println!(
        "Reference kernel: {}",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim()
    );
    let device = prepare_tun(PEER)?;
    let listener = tokio::net::TcpListener::bind((PEER, 80)).await?;
    let udp = tokio::net::UdpSocket::bind((PEER, 18081)).await?;
    fictionet::run(fictionet::Seed::random(), move |fcx| async move {
        let (accepted, accept_result) = tokio::sync::oneshot::channel();
        fcx.spawn(move |fcx| async move {
            // Match the persona: accept requests the peer address. The kernel,
            // not this fixture, must reject and release the source-zero child.
            let result = tokio::select! {
                _ = fcx.cancelled() => return Ok(()),
                result = listener.accept() => result,
            };
            let error = result.expect_err("source-zero accept must fail with an address buffer");
            assert_eq!(error.raw_os_error(), Some(libc::ECONNABORTED));
            println!("Guest Linux accept with peer address returned ECONNABORTED");
            let _ = accepted.send(());
            Ok(())
        });
        let (sender, mut delivered) = tokio::sync::mpsc::channel(2);
        fcx.spawn(move |fcx| async move {
            let mut bytes = vec![0; 1500];
            loop {
                let (count, from) = tokio::select! {
                    _ = fcx.cancelled() => return Ok(()),
                    result = udp.recv_from(&mut bytes) => result?,
                };
                sender.send((bytes[..count].to_vec(), from)).await?;
            }
        });
        let (end, relay) = fictionet::pair();
        fcx.spawn(move |fcx| device.relay(fcx, relay));
        let mut probe = Probe {
            end,
            sent: Vec::new(),
        };
        probe
            .run(&fcx, "guest Linux through TUN", &mut delivered)
            .await?;
        accept_result.await?;
        fcx.cancel();
        Ok(())
    })
    .await
}

async fn ethernet(fcx: Cx, mut raw: RawAttachment, mut end: End) -> fictionet::Result {
    use fictionet::stdlib::network::ethernet::host::{Config, Host, Ipv4Config, Received};
    let mut host = Host::new(
        Config {
            mac: raw.mac_address(),
            mtu: 1500,
            ipv4: Some(Ipv4Config {
                address: CLIENT,
                gateway: PEER,
            }),
            ipv6: None,
        },
        fcx.now(),
    )?;
    // Resolve the gateway before accepting a probe for transmission.
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
                let frame = host.send(fcx.now(), &packet?.0).map_err(|error| fictionet::Error::msg(format!("cannot send probe: {error:?}")))?;
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

async fn vfio() -> fictionet::Result {
    let (client_pump, client) = RawPump::attach(prepare_device("0000:00:03.0")?)?;
    let (peer_pump, peer) = RawPump::attach(prepare_device("0000:00:04.0")?)?;
    let result = fictionet::run(fictionet::Seed::random(), move |fcx| async move {
        let log = Capture::default();
        let pcap = Capture::default();
        let _peer = honeypot_world::start_raw(
            &fcx,
            &config(PEER, CLIENT),
            Clock::starting_now(),
            sinks(&log, &pcap),
            peer,
            Box::new(io::sink()),
        )?;
        let (end, relay) = fictionet::pair();
        fcx.spawn(move |fcx| ethernet(fcx, client, relay));
        let mut probe = Probe {
            end,
            sent: Vec::new(),
        };
        let mut delivered = udp_listener(&fcx, &_peer).await?;
        probe.run(&fcx, "VFIO", &mut delivered).await?;
        observations(&log, &pcap, &probe.sent)?;
        fcx.cancel();
        Ok(())
    })
    .await;
    let client_result = client_pump.shutdown();
    let peer_result = peer_pump.shutdown();
    result?;
    client_result?;
    peer_result
}

pub async fn run() -> fictionet::Result {
    tokio::time::timeout(Duration::from_secs(30), world()).await??;
    tokio::time::timeout(Duration::from_secs(30), tun()).await??;
    tokio::time::timeout(Duration::from_secs(30), vfio()).await??;
    Ok(())
}
