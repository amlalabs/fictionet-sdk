#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use arbitrary::Arbitrary;
use fictionet::stdlib::layer::{
    Admit, Budget, Child, ChildId, Chunk, Direction, Driver, MuxEvent, ObservedEvent, PacketEvent,
};
use fictionet::stdlib::network::ip::{self, protocol};
use fictionet::stdlib::network::observer::{Limits, Observer};
use fictionet::stdlib::network::packet::{Capture, Ingress, ObservedIpPacket};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    byte_limit: u16,
    segment_limit: u8,
    connection_limit: u8,
    waiting_limit: u16,
    segments: Vec<Captured>,
    finish: bool,
}

#[derive(Arbitrary, Debug)]
struct Captured {
    flow: u8,
    seq: u32,
    ack: u32,
    flags: u8,
    relative: bool,
    payload: Vec<u8>,
}

/// The sender and receiver of one of eight directions: four connections,
/// each both ways.
fn ends(flow: u8) -> (SocketAddr, SocketAddr) {
    let a = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        40000 + u16::from(flow / 2),
    );
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 80);
    if flow & 1 == 0 { (a, b) } else { (b, a) }
}

/// What one child direction has delivered so far.
#[derive(Default)]
struct Seen {
    /// The sequence position the next data or gap must start at, once known.
    next: Option<u64>,
    ended: bool,
}

fuzz_target!(|input: Input| {
    let mut tcp = Driver::new(
        Observer::new(Limits {
            buffered: usize::from(input.byte_limit),
            segments: usize::from(input.segment_limit),
            connections: usize::from(input.connection_limit % 9),
            waiting: usize::from(input.waiting_limit),
        }),
        Arc::new(SeededEntropy::new(Seed::from_u64(1))),
        Budget::unlimited(),
        Instant::ZERO,
    );
    let limits = tcp.layer().limits();
    let mut children: BTreeMap<ChildId, Child> = BTreeMap::new();
    let mut closed = BTreeSet::new();
    let mut directions: BTreeMap<(ChildId, Direction), Seen> = BTreeMap::new();
    let mut octets = [0usize; 256];
    let mut next = [u32::MAX - 16; 8];
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut drain = |tcp: &mut Driver<Observer>, packets: &[Vec<u8>], octets: &mut [usize; 256]| loop {
        let mut batch = Vec::new();
        tcp.send_above(|event| {
            batch.push(event);
            Admit::Taken
        });
        if batch.is_empty() {
            break;
        }
        for event in batch {
            match event {
                MuxEvent::Opened(child, _, _) => {
                    assert!(tcp.command(child.grant(u64::MAX)).is_ok());
                    assert!(children.insert(child.id(), child).is_none());
                }
                MuxEvent::Child(id, event) => {
                    assert!(
                        children.contains_key(&id),
                        "events come between open and close"
                    );
                    let seen = directions.entry((id, event.direction())).or_default();
                    assert!(!seen.ended, "nothing follows a direction's end");
                    match event {
                        ObservedEvent::Data {
                            bytes,
                            sequence,
                            source,
                            ..
                        } => {
                            assert!(!bytes.is_empty());
                            assert!(seen.next.is_none_or(|next| next == sequence));
                            seen.next = Some(sequence + bytes.len() as u64);
                            if let Some(source) = source {
                                let packet = &packets[source.packet as usize - 1];
                                let end = source.offset + bytes.len();
                                assert_eq!(packet.get(source.offset..end), Some(&bytes[..]));
                            }
                            for byte in bytes.iter() {
                                let left = &mut octets[usize::from(*byte)];
                                *left = left.checked_sub(1).expect("delivered bytes were captured");
                            }
                        }
                        ObservedEvent::Gap {
                            sequence, missing, ..
                        } => {
                            assert!(seen.next.is_none_or(|next| next == sequence));
                            let missing = missing.expect("the observer knows what it skipped");
                            assert!(missing > 0);
                            seen.next = Some(sequence + missing);
                        }
                        ObservedEvent::End { .. } => seen.ended = true,
                    }
                }
                MuxEvent::Closed(id) => {
                    assert!(children.remove(&id).is_some());
                    assert!(closed.insert(id));
                    for direction in [Direction::Forward, Direction::Reverse] {
                        let seen = directions.remove(&(id, direction)).unwrap_or_default();
                        assert!(seen.ended, "a child closes after both its ends");
                    }
                }
                MuxEvent::Credit(..) => {}
                MuxEvent::Control(never) => match never {},
            }
        }
    };
    for captured in input.segments.iter().take(1024) {
        let flow = captured.flow % 8;
        let (from, to) = ends(flow);
        let payload = &captured.payload[..captured.payload.len().min(4096)];
        let seq = if captured.relative {
            next[usize::from(flow)].wrapping_add((captured.seq as i8 as i32) as u32)
        } else {
            captured.seq
        };
        let flags = if captured.flags & 0x80 != 0 {
            captured.flags
        } else {
            match captured.flags % 8 {
                0 => 2,
                1 => 0x11,
                2 => 0x14,
                3 => 0x12,
                _ => 0x18,
            }
        };
        next[usize::from(flow)] = seq
            .wrapping_add(payload.len() as u32)
            .wrapping_add(u32::from(flags & 2 != 0));
        for byte in payload {
            octets[usize::from(*byte)] += 1;
        }
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&from.port().to_be_bytes());
        segment[2..4].copy_from_slice(&to.port().to_be_bytes());
        segment[4..8].copy_from_slice(&seq.to_be_bytes());
        segment[8..12].copy_from_slice(&captured.ack.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = flags;
        segment.extend_from_slice(payload);
        let packet = ip::packet(from.ip(), to.ip(), protocol::TCP, &segment).0;
        packets.push(packet.clone());
        let ingress = Ingress {
            capture: Some(Capture {
                number: packets.len() as u64,
                at: Instant::ZERO,
                original_len: packet.len(),
            }),
            ..Ingress::default()
        };
        let packet = ObservedIpPacket::observed(Chunk::unpaid(packet), ingress);
        assert!(matches!(
            tcp.deliver(PacketEvent::Packet(packet)),
            Ok(Admit::Taken)
        ));
        drain(&mut tcp, &packets, &mut octets);
        assert!(tcp.layer().buffered() <= limits.buffered);
        assert!(tcp.layer().connections() <= limits.connections);
    }
    if input.finish {
        assert!(matches!(tcp.deliver(PacketEvent::Ended), Ok(Admit::Taken)));
        drain(&mut tcp, &packets, &mut octets);
        assert_eq!(tcp.layer().buffered(), 0);
        assert!(children.is_empty(), "the capture's end closes every child");
    }
});
