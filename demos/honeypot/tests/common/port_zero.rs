//! Sixteen probes at the server, eleven of them with a literal zero port,
//! and what the server answers and logs for them.
//!
//! TCP to port zero, from port zero, or to a closed port is reset. A SYN
//! from port zero to an open port is answered, and the connection is closed
//! after the handshake, as Linux closes it when `accept` cannot hand it out.
//! UDP from port zero reaches an open port with its source kept; UDP to port
//! zero or a closed port gets port unreachable quoting the probe.

use std::net::{Ipv4Addr, SocketAddr};

use fictionet::stdlib::network::{ip, udp};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet};
use honeypot_world::Honeypot;

use super::capture::{Written, endpoints, packet_at, packets};

/// The prober's address.
pub const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
/// The server's address.
pub const PEER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

/// The server's open UDP port, bound by a program on the server.
const UDP_PORT: u16 = 18081;
/// A port nothing listens on.
const CLOSED: u16 = 18082;

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
    let packet = transport(17, &mut bytes);
    if packet[26..28] != [0, 0] {
        return packet;
    }
    // A computed zero checksum is sent as all ones in UDP.
    let mut bytes = packet.into_vec();
    bytes[26..28].copy_from_slice(&[0xff, 0xff]);
    Packet::new(bytes)
}

fn number(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// The prober: its side of the link to the server, the server's UDP
/// listener, and every packet it sent, in order.
pub struct Probe {
    end: End,
    listener: udp::Socket,
    /// The probes, as sent.
    pub sent: Vec<Vec<u8>>,
}

impl Probe {
    /// A prober that sends by `end`, with a UDP listener on the server.
    pub async fn new(server: &Honeypot, end: End) -> fictionet::Result<Probe> {
        let listener = endpoints(server).await?.udp.bind(UDP_PORT)?;
        Ok(Probe {
            end,
            listener,
            sent: Vec::new(),
        })
    }

    fn send(&mut self, packet: Packet) {
        self.sent.push(packet.to_vec());
        self.end.send(packet);
    }

    /// The transport bytes of the next reply, after checking its addresses,
    /// protocol and checksums.
    async fn receive(&mut self, fcx: &Cx, protocol: u8) -> fictionet::Result<Vec<u8>> {
        let packet = self.end.recv(fcx).await?;
        let header = ip::Header::parse_whole(&packet).expect("reply IP header");
        assert_eq!((header.src, header.dst), (PEER.into(), CLIENT.into()));
        assert_eq!(header.protocol, protocol);
        assert_eq!(ip::checksum(&packet[..header.payload.start]), 0);
        let bytes = header.payload(&packet);
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

    /// Sends the probes and checks each answer.
    pub async fn run(&mut self, fcx: &Cx) -> fictionet::Result {
        // Random sequence numbers and payloads bind answers to these probes.
        let mut random = [0; 32];
        fcx.fill_random(&mut random);
        let seq = number(&random, 0);
        for ports in [(41000, 0), (0, 0), (0, CLOSED), (41001, CLOSED)] {
            self.send(tcp(ports, seq, 0, 2, &[]));
            let reply = self
                .tcp_reply(fcx, ports, seq.wrapping_add(1), 0x14)
                .await?;
            assert_eq!(number(&reply, 4), 0);
        }
        // A bare ACK to a closed port is reset without an ACK flag.
        self.send(tcp((0, 0), seq, seq.wrapping_add(19), 0x10, &[]));
        let reply = self.tcp_reply(fcx, (0, 0), 0, 4).await?;
        assert_eq!(number(&reply, 4), seq.wrapping_add(19));

        // An ordinary handshake with the listener comes first.
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

        // From port zero, the handshake completes and the server closes.
        self.send(tcp((0, 80), seq, 0, 2, &[]));
        let reply = self
            .tcp_reply(fcx, (0, 80), seq.wrapping_add(1), 0x12)
            .await?;
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

        for source in [41005, 0] {
            self.send(udp((source, UDP_PORT), &random));
            let (data, from) = self.listener.recv(fcx).await?;
            assert_eq!(data, random);
            assert_eq!(from, SocketAddr::new(CLIENT.into(), source));
        }

        for ports in [(41003, 0), (0, 0), (0, CLOSED), (41004, CLOSED)] {
            let packet = udp(ports, &random);
            let sent = packet.to_vec();
            self.send(packet);
            let reply = self.receive(fcx, 1).await?;
            assert!(reply.len() >= 36, "the quote holds the IP and UDP headers");
            assert_eq!(&reply[..2], &[3, 3], "destination port unreachable");
            let quote = &reply[8..];
            assert!(quote.len() <= sent.len());
            assert_eq!(quote, &sent[..quote.len()], "the quote is of the probe");
        }
        Ok(())
    }

    /// Checks that the IP capture holds every probe, byte for byte and in
    /// order, and that the log has one `port_zero` observation for each
    /// probe with a literal zero port, pointing at that probe in the
    /// capture by ordinal and by file offset, and none for the others.
    pub fn check(&self, written: &Written) {
        let capture = written.ip();
        let packets = packets(&capture);
        let ingress: Vec<_> = packets
            .iter()
            .filter(|packet| ip::source(packet) == Some(CLIENT.into()))
            .collect();
        assert_eq!(ingress, self.sent.iter().collect::<Vec<_>>());
        let expected: Vec<_> = self
            .sent
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
        let events = written.events();
        let facts: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "port_zero")
            .collect();
        assert_eq!(facts.len(), expected.len());
        let mut last_capture = 0;
        for (fact, (packet, protocol, source, destination)) in facts.into_iter().zip(expected) {
            assert_eq!(fact["protocol"], protocol);
            assert_eq!(fact["src"], source);
            assert_eq!(fact["dst"], destination);
            assert_eq!(fact["attachment"], honeypot_world::INTERNET);
            assert_eq!(fact["checksum_valid"], true);
            assert_eq!(fact["fragmented"], false);
            assert_eq!(fact["capture_queued"], true);
            let ordinal = fact["capture_packet"].as_u64().unwrap();
            assert!(ordinal > last_capture, "capture references are in order");
            assert_eq!(&packets[ordinal as usize - 1], packet);
            last_capture = ordinal;
            assert_eq!(fact["capture"]["available"], true);
            assert_eq!(fact["capture"]["direction"], "in");
            let offset = fact["capture"]["offset"].as_u64().unwrap() as usize;
            assert_eq!(&packet_at(&capture, offset), packet);
        }
    }
}
