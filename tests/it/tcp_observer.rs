use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::common::alloc::allocations;
use fictionet::stdlib::codec::{Decode, Step, Stream, finish, pump};
use fictionet::stdlib::layer::{
    Admit, Budget, Child, Chunk, Direction, Driver, MuxEvent, ObservedEvent, PacketEvent,
    Termination,
};
use fictionet::stdlib::network::ip::{self, protocol};
use fictionet::stdlib::network::observer::{Limits, Observer};
use fictionet::stdlib::network::packet::{Capture as Captured, Ingress, ObservedIpPacket};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

/// A capture fed to a passive TCP observer one segment at a time, with
/// credit granted for every connection it opens.
pub(crate) struct Capture {
    tcp: Driver<Observer>,
    number: u64,
    children: Vec<Child>,
}

impl Capture {
    pub(crate) fn new(limits: Limits) -> Capture {
        Capture {
            tcp: Driver::new(
                Observer::new(limits),
                Arc::new(SeededEntropy::new(Seed::from_u64(1))),
                Budget::unlimited(),
                Instant::ZERO,
            ),
            number: 0,
            children: Vec::new(),
        }
    }

    /// Captures one TCP segment, in an IPv4 packet, and returns what its
    /// connections got, in order.
    pub(crate) fn segment(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<ObservedEvent> {
        let packet = self.packet(from, to, seq, ack, flags, payload);
        assert!(matches!(
            self.tcp.deliver(PacketEvent::Packet(packet)),
            Ok(Admit::Taken)
        ));
        self.events()
    }

    /// One TCP segment in an IPv4 packet, numbered as the next one captured.
    fn packet(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> ObservedIpPacket {
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&from.port().to_be_bytes());
        segment[2..4].copy_from_slice(&to.port().to_be_bytes());
        segment[4..8].copy_from_slice(&seq.to_be_bytes());
        segment[8..12].copy_from_slice(&ack.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = flags;
        segment.extend_from_slice(payload);
        let packet = ip::packet(from.ip(), to.ip(), protocol::TCP, &segment).0;
        self.number += 1;
        let ingress = Ingress {
            capture: Some(Captured {
                number: self.number,
                at: Instant::ZERO,
                original_len: packet.len(),
            }),
            ..Ingress::default()
        };
        ObservedIpPacket::observed(Chunk::unpaid(packet), ingress)
    }

    /// What the connections got since the last segment, in order, with
    /// credit granted to every child opened meanwhile.
    fn events(&mut self) -> Vec<ObservedEvent> {
        let mut events = Vec::new();
        loop {
            let mut batch = Vec::new();
            self.tcp.send_above(|event| {
                batch.push(event);
                Admit::Taken
            });
            if batch.is_empty() {
                return events;
            }
            for event in batch {
                match event {
                    MuxEvent::Opened(child, _, _) => {
                        assert!(self.tcp.command(child.grant(u64::MAX)).is_ok());
                        self.children.push(child);
                    }
                    MuxEvent::Child(_, event) => events.push(event),
                    MuxEvent::Closed(_) | MuxEvent::Credit(..) => {}
                    MuxEvent::Control(never) => match never {},
                }
            }
        }
    }

    pub(crate) fn buffered(&self) -> usize {
        self.tcp.layer().buffered()
    }

    pub(crate) fn limits(&self) -> Limits {
        self.tcp.layer().limits()
    }
}

struct UserDecoder;

impl Decode for UserDecoder {
    type Item = [u8; 2];
    type Error = Infallible;
    const NAME: &'static str = "user pairs";

    fn capacity(&self) -> usize {
        2
    }

    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Self::Item>, Self::Error> {
        Ok(match input.get(..2) {
            Some(pair) => Step::Item([pair[0], pair[1]], 2),
            None => Step::Need,
        })
    }
}

fn client() -> SocketAddr {
    "192.0.2.1:40000".parse().unwrap()
}

fn server() -> SocketAddr {
    "192.0.2.2:80".parse().unwrap()
}

#[test]
fn observed_events_drive_a_user_decoder_with_gap_and_end_hooks() {
    let mut tcp = Capture::new(Limits {
        buffered: 2,
        ..Limits::default()
    });
    let mut decoder = Stream::new(UserDecoder);
    let mut pairs = Vec::new();
    let mut gaps = 0;
    let mut ends = 0;
    for (seq, flags, payload) in [
        (100, 2, &b""[..]),
        (101, 0x18, &b"a"[..]),
        (104, 0x18, &b"de"[..]),
        (110, 0x18, &b"dropped"[..]),
        (106, 0x18, &b"fg"[..]),
        (108, 0x11, &b""[..]),
    ] {
        for event in tcp.segment(client(), server(), seq, 0, flags, payload) {
            match event {
                ObservedEvent::Data { bytes, .. } => {
                    pump(&mut decoder, &bytes, |pair| pairs.push(pair)).unwrap();
                }
                ObservedEvent::Gap { .. } => {
                    gaps += 1;
                    decoder = Stream::new(UserDecoder);
                }
                ObservedEvent::End { cause, .. } => {
                    assert_eq!(cause, Termination::Fin);
                    ends += 1;
                    finish(&mut decoder, |pair| pairs.push(pair)).unwrap();
                }
            }
        }
        assert!(tcp.buffered() <= tcp.limits().buffered);
    }
    assert_eq!(pairs, [*b"de", *b"fg"]);
    assert_eq!((gaps, ends), (1, 1));
    assert!(decoder.is_done());
}

/// A segment that only acknowledges carries nothing for a child, so taking
/// it allocates nothing. What comes after it still goes up in order: data,
/// then the ends a RST makes.
#[test]
fn a_pure_ack_allocates_nothing() {
    let mut tcp = Capture::new(Limits::default());
    tcp.tcp.keep_observations(0);
    tcp.segment(client(), server(), 100, 0, 0x02, b"");
    tcp.segment(server(), client(), 500, 101, 0x12, b"");
    tcp.segment(client(), server(), 101, 501, 0x18, b"hi");
    for _ in 0..3 {
        let packet = tcp.packet(server(), client(), 501, 103, 0x10, b"");
        let (taken, allocated) = allocations(|| tcp.tcp.deliver(PacketEvent::Packet(packet)));
        assert!(matches!(taken, Ok(Admit::Taken)));
        assert_eq!(allocated, 0);
        assert!(tcp.events().is_empty());
    }
    let events = tcp.segment(client(), server(), 103, 501, 0x14, b"!");
    assert!(matches!(
        &events[..],
        [
            ObservedEvent::Data { bytes, direction: Direction::Forward, .. },
            ObservedEvent::End { direction: Direction::Forward, cause: Termination::Reset },
            ObservedEvent::End { direction: Direction::Reverse, cause: Termination::Reset },
        ] if &bytes[..] == b"!"
    ));
}

#[test]
fn data_after_a_syn_at_the_end_of_sequence_space_reassembles_in_order() {
    let mut tcp = Capture::new(Limits::default());
    tcp.segment(client(), server(), u32::MAX, 0, 2, b"");
    assert!(
        tcp.segment(client(), server(), 2, 0, 0x18, b"cd")
            .is_empty()
    );
    let events = tcp.segment(client(), server(), 0, 0, 0x18, b"ab");
    let mut decoder = Stream::new(UserDecoder);
    let mut pairs = Vec::new();
    for event in events {
        if let ObservedEvent::Data { bytes, .. } = event {
            pump(&mut decoder, &bytes, |pair| pairs.push(pair)).unwrap();
        }
    }
    assert_eq!(pairs, [*b"ab", *b"cd"]);
    assert_eq!(tcp.buffered(), 0);
}
