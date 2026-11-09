use super::*;

use std::collections::BTreeSet;
use std::sync::Arc;

use fictionet::stdlib::layer::{Budget, Child, Driver};
use fictionet::stdlib::network::ip;
use fictionet::stdlib::network::packet::{Capture, Ingress, Scopes};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

const CLIENT: &str = "192.0.2.1:40000";
const SERVER: &str = "192.0.2.2:80";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

use Direction::{Forward, Reverse};

/// What a child got, with bytes counted the way a decoder above counts
/// them: `Data` and `Gap` carry how many bytes of their direction were
/// delivered before them, and `Data` where its first byte sits in the
/// packet just sent, past the IP and TCP headers, if it came from there.
#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Data(Direction, u64, Vec<u8>, Option<usize>),
    Gap(Direction, u64, Option<u64>),
    End(Direction, Termination),
}

#[derive(Debug, Default)]
struct Seen {
    events: Vec<(ChildId, Ev)>,
    /// Sequence positions of data and gaps, in order.
    sequences: Vec<(Direction, u64)>,
    /// Where each piece of data came from, in order.
    sources: Vec<Option<Source>>,
    opened: Vec<(ChildId, ObservedConnection)>,
    closed: Vec<ChildId>,
    reports: Vec<ObserverReport>,
}

impl Seen {
    fn evs(&self) -> Vec<&Ev> {
        self.events.iter().map(|(_, e)| e).collect()
    }

    fn segment(&self) -> (u32, u32, bool) {
        self.reports
            .iter()
            .find_map(|r| match r {
                ObserverReport::Segment {
                    sequence,
                    acknowledgment,
                    retransmission,
                    ..
                } => Some((*sequence, *acknowledgment, *retransmission)),
                _ => None,
            })
            .unwrap()
    }

    fn dropped(&self) -> bool {
        self.reports
            .iter()
            .any(|r| matches!(r, ObserverReport::Dropped { .. }))
    }

    fn late(&self) -> usize {
        self.reports
            .iter()
            .map(|r| match r {
                ObserverReport::Late { bytes, .. } => *bytes,
                _ => 0,
            })
            .sum()
    }
}

/// An observer driven packet by packet, granting credit as children open.
struct Watch {
    tcp: Driver<Observer>,
    number: u64,
    grant: bool,
    /// Bytes the capture leaves off the end of the next packet.
    cut: usize,
    handles: Vec<Child>,
    delivered: BTreeMap<(ChildId, Direction), u64>,
}

impl Watch {
    fn new(limits: Limits) -> Watch {
        Watch {
            tcp: Driver::new(
                Observer::new(limits),
                Arc::new(SeededEntropy::new(Seed::from_u64(3))),
                Budget::unlimited(),
                Instant::ZERO,
            ),
            number: 0,
            grant: true,
            cut: 0,
            handles: Vec::new(),
            delivered: BTreeMap::new(),
        }
    }

    fn observer(&mut self) -> &mut Observer {
        self.tcp.layer_mut()
    }

    /// The flow of the only connection, one way.
    fn flow(&mut self, direction: Direction) -> &mut Flow {
        let connection = self.observer().connections.values_mut().next().unwrap();
        connection.flows[index(direction)].as_mut().unwrap()
    }

    /// From the client to the server.
    fn up(&mut self, seq: u32, flags: u8, payload: &[u8]) -> Seen {
        self.send(Scope::ROOT, CLIENT, SERVER, seq, 0, flags, payload)
    }

    /// From the server to the client.
    fn down(&mut self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Seen {
        self.send(Scope::ROOT, SERVER, CLIENT, seq, ack, flags, payload)
    }

    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        scope: Scope,
        from: &str,
        to: &str,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Seen {
        let (from, to) = (addr(from), addr(to));
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
            scope,
            link: 0,
            capture: Some(Capture {
                number: self.number,
                at: Instant::ZERO,
                original_len: packet.len(),
            }),
        };
        let mut packet = packet;
        packet.truncate(packet.len() - std::mem::take(&mut self.cut));
        let packet = ObservedIpPacket::observed(Chunk::new(packet), ingress);
        assert!(matches!(
            self.tcp.deliver(PacketEvent::Packet(packet)),
            Ok(Admit::Taken)
        ));
        self.drain()
    }

    /// Ends the capture.
    fn finish(&mut self) -> Seen {
        assert!(matches!(
            self.tcp.deliver(PacketEvent::Ended),
            Ok(Admit::Taken)
        ));
        self.drain()
    }

    fn drain(&mut self) -> Seen {
        let mut seen = Seen {
            reports: self.tcp.observations().drain().collect(),
            ..Seen::default()
        };
        loop {
            let mut batch = Vec::new();
            self.tcp.send_above(|event| {
                batch.push(event);
                Admit::Taken
            });
            if batch.is_empty() {
                break;
            }
            for event in batch {
                match event {
                    MuxEvent::Opened(child, info, _) => {
                        if self.grant {
                            assert!(self.tcp.command(child.grant(u64::MAX)).is_ok());
                        }
                        seen.opened.push((child.id(), info));
                        self.handles.push(child);
                    }
                    MuxEvent::Child(id, event) => {
                        let direction = event.direction();
                        let delivered = self.delivered.entry((id, direction)).or_default();
                        let ev = match event {
                            ObservedEvent::Data {
                                bytes,
                                sequence,
                                source,
                                ..
                            } => {
                                seen.sequences.push((direction, sequence));
                                seen.sources.push(source);
                                let at = *delivered;
                                *delivered += bytes.len() as u64;
                                let input = source
                                    .filter(|s| s.packet == self.number)
                                    .map(|s| s.offset - 40);
                                Ev::Data(direction, at, bytes.to_vec(), input)
                            }
                            ObservedEvent::Gap {
                                sequence, missing, ..
                            } => {
                                seen.sequences.push((direction, sequence));
                                Ev::Gap(direction, *delivered, missing)
                            }
                            ObservedEvent::End { cause, .. } => Ev::End(direction, cause),
                        };
                        seen.events.push((id, ev));
                    }
                    MuxEvent::Closed(id) => seen.closed.push(id),
                    MuxEvent::Credit(..) | MuxEvent::Control(_) => {
                        panic!("an observer has no commands")
                    }
                }
            }
        }
        seen
    }
}

fn watch() -> Watch {
    Watch::new(Limits::default())
}

fn data(at: u64, bytes: &[u8], input: Option<usize>) -> Ev {
    Ev::Data(Forward, at, bytes.to_vec(), input)
}

fn gap(at: u64, missing: u64) -> Ev {
    Ev::Gap(Forward, at, Some(missing))
}

#[test]
fn ambiguous_serial_distance_is_dropped() {
    let mut tcp = watch();
    tcp.up(10, 2, b"");
    let ambiguous = tcp.up(11 + (1 << 31), 0x18, b"lost");
    assert!(ambiguous.events.is_empty());
    assert!(ambiguous.dropped());
    assert!(!ambiguous.segment().2);
    assert_eq!(tcp.observer().buffered(), 0);
    assert_eq!(tcp.up(11, 0x18, b"ok").evs(), [&data(0, b"ok", Some(0))]);
}

#[test]
fn in_order_and_midstream_capture() {
    let mut tcp = watch();
    let first = tcp.up(20, 0x18, b"abc");
    assert_eq!(first.evs(), [&data(0, b"abc", Some(0))]);
    assert_eq!(first.opened[0].1.opened, None);
    let result = tcp.up(23, 0x18, b"def");
    assert_eq!(result.segment().0, 3);
    assert_eq!(result.evs(), [&data(3, b"def", Some(0))]);
    // Midstream, the first byte seen is position zero.
    assert_eq!(result.sequences, [(Forward, 3)]);
    assert_eq!(tcp.observer().buffered(), 0);
    assert_eq!(tcp.observer().connections(), 1);
}

#[test]
fn out_of_order_and_overlapping_buffered_segments() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    assert!(tcp.up(105, 0x18, b"efgh").events.is_empty());
    assert!(tcp.up(103, 0x18, b"cdef").events.is_empty());
    assert_eq!(tcp.observer().buffered(), 8);
    let released = tcp.up(101, 0x18, b"ab");
    assert_eq!(
        released.evs(),
        [
            &data(0, b"ab", Some(0)),
            &data(2, b"cdef", None),
            &data(6, b"gh", None)
        ]
    );
    // After a SYN, the first payload byte is position one.
    assert_eq!(
        released.sequences,
        [(Forward, 1), (Forward, 3), (Forward, 7)]
    );
    assert_eq!(tcp.observer().buffered(), 0);
    assert_eq!(tcp.flow(Forward).held_segments(), 0);
}

/// Held bytes name the packet they came from, never the one that
/// released them.
#[test]
fn held_bytes_keep_the_packet_they_came_from() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.up(103, 0x18, b"cd");
    let held = tcp.number;
    let released = tcp.up(101, 0x18, b"ab");
    let at = |packet| Some(Source { packet, offset: 40 });
    assert_eq!(released.sources, [at(tcp.number), at(held)]);
}

#[test]
fn overlaps_and_retransmits() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.up(101, 0x18, b"abcd");
    let repeated = tcp.up(101, 0x18, b"abcd");
    assert!(repeated.segment().2);
    assert!(repeated.events.is_empty());
    let overlap = tcp.up(103, 0x18, b"XXef");
    assert!(!overlap.segment().2);
    assert_eq!(overlap.evs(), [&data(4, b"ef", Some(2))]);
    // The new in-order segment wins over an already held overlap.
    tcp.up(108, 0x18, b"Xij");
    assert_eq!(
        tcp.up(107, 0x18, b"gh").evs(),
        [&data(6, b"gh", Some(0)), &data(8, b"ij", None)]
    );
    assert_eq!(tcp.observer().buffered(), 0);
}

#[test]
fn buffered_retransmit_replaces_at_the_same_sequence() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.up(103, 0x18, b"old");
    tcp.up(103, 0x18, b"cd");
    assert_eq!(tcp.observer().buffered(), 2);
    assert_eq!(tcp.flow(Forward).held_segments(), 1);
    assert_eq!(
        tcp.up(101, 0x18, b"ab").evs(),
        [&data(0, b"ab", Some(0)), &data(2, b"cd", None)]
    );
}

/// A FIN seen before the bytes it follows is noted where it sits. Once
/// the bytes arrive they come up, then the clean end, once, with no need
/// for the FIN to be sent again.
#[test]
fn wraparound_and_early_fin() {
    let mut tcp = watch();
    let isn = u32::MAX - 2;
    tcp.up(isn, 2, b"");
    assert!(tcp.up(1, 0x19, b"de").events.is_empty());
    let done = tcp.up(isn.wrapping_add(1), 0x18, b"abc");
    assert_eq!(
        done.evs(),
        [
            &data(0, b"abc", Some(0)),
            &data(3, b"de", None),
            &Ev::End(Forward, Termination::Fin)
        ]
    );
    // The FIN sent again is nothing new, and nothing is late.
    let again = tcp.up(1, 0x19, b"de");
    assert!(again.events.is_empty());
    assert_eq!(again.late(), 0);
    assert_eq!(tcp.flow(Forward).next(), Some(4));
}

#[test]
fn held_segments_stay_ordered_after_a_full_sequence_wrap() {
    let mut tcp = watch();
    let isn = 1000u32;
    tcp.up(isn, 2, b"");
    tcp.flow(Forward)
        .set_position((1 << 32) - 10, isn.wrapping_sub(10));
    assert!(tcp.up(isn + 2, 0x18, b"xyz").events.is_empty());
    assert!(tcp.up(isn - 5, 0x18, b"fghijkl").events.is_empty());
    let released = tcp.up(isn - 10, 0x18, b"abcde");
    assert_eq!(
        released.evs(),
        [
            &data(0, b"abcde", Some(0)),
            &data(5, b"fghijkl", None),
            &data(12, b"xyz", None)
        ]
    );
    assert_eq!(released.sequences[2], (Forward, (1 << 32) + 2));
    assert_eq!(tcp.observer().buffered(), 0);
}

fn resume_two_large_gaps(tcp: &mut Watch, dropped: &[u8]) -> u32 {
    tcp.up(100, 2, b"");
    let mut next = 101u32;
    for offset in 0..2 {
        let resumed = next.wrapping_add(3 << 29);
        assert!(tcp.up(resumed, 0x18, b"x").events.is_empty());
        let seen = tcp.up(resumed.wrapping_add(100), 0x18, dropped);
        assert_eq!(
            seen.evs(),
            [
                &Ev::Gap(Forward, offset, Some(seen.gap_missing())),
                &data(offset, b"x", None)
            ]
        );
        next = resumed.wrapping_add(1);
    }
    assert_eq!(tcp.observer().buffered(), 0);
    next
}

impl Seen {
    fn gap_missing(&self) -> u64 {
        self.events
            .iter()
            .find_map(|(_, e)| match e {
                Ev::Gap(_, _, missing) => *missing,
                _ => None,
            })
            .unwrap()
    }
}

fn drain_near_bytes_before_distant_bytes(tcp: &mut Watch, next: u32) {
    assert!(tcp.up(next + 4, 0x18, b"BB").events.is_empty());
    assert!(
        tcp.up(next.wrapping_add(3 << 29), 0x18, b"C")
            .events
            .is_empty()
    );
    assert_eq!(
        tcp.up(next, 0x18, b"AAAA").evs(),
        [&data(2, b"AAAA", Some(0)), &data(6, b"BB", None)]
    );
    assert_eq!(tcp.observer().buffered(), 1);
    assert_eq!(tcp.flow(Forward).held_segments(), 1);
    // Fill the budget to resume again and verify that C was retained.
    let seen = tcp.up(next.wrapping_add(3 << 29).wrapping_add(100), 0x18, b"drop");
    assert_eq!(
        seen.evs(),
        [
            &Ev::Gap(Forward, 8, Some(seen.gap_missing())),
            &data(8, b"C", None)
        ]
    );
    assert_eq!(tcp.observer().buffered(), 0);
}

#[test]
fn held_segments_stay_ordered_after_large_gap_resumes() {
    let mut tcp = Watch::new(Limits {
        buffered: 1,
        ..Limits::default()
    });
    let next = resume_two_large_gaps(&mut tcp, b"x");
    tcp.observer().store.limits.buffered = 4;
    drain_near_bytes_before_distant_bytes(&mut tcp, next);
}

#[test]
fn public_pushes_keep_held_segments_ordered_after_large_gap_resumes() {
    let mut tcp = Watch::new(Limits {
        buffered: 4,
        ..Limits::default()
    });
    let next = resume_two_large_gaps(&mut tcp, b"drop");
    drain_near_bytes_before_distant_bytes(&mut tcp, next);
}

/// A segment past the byte bound is dropped, and reassembly skips to the
/// first held segment. The dropped segment's place is remembered: when
/// the bytes before it arrive, its bytes are reported missing.
#[test]
fn byte_bound_drops_incoming_and_resumes_at_first_held_segment() {
    let mut tcp = Watch::new(Limits {
        buffered: 4,
        ..Limits::default()
    });
    tcp.up(100, 2, b"");
    tcp.up(104, 0x18, b"de");
    tcp.up(106, 0x18, b"fg");
    assert_eq!(tcp.observer().buffered(), 4);
    let resumed = tcp.up(110, 0x18, b"lost");
    assert_eq!(
        resumed.evs(),
        [&gap(0, 3), &data(0, b"de", None), &data(2, b"fg", None)]
    );
    assert_eq!(
        resumed.sequences,
        [(Forward, 1), (Forward, 4), (Forward, 6)]
    );
    assert!(!resumed.dropped());
    assert_eq!(tcp.observer().buffered(), 0);
    let next = tcp.up(108, 0x18, b"hi");
    assert_eq!(next.evs(), [&data(4, b"hi", Some(0)), &gap(6, 4)]);
    assert_eq!(next.sequences, [(Forward, 8), (Forward, 10)]);
    // What follows the dropped bytes follows the gap.
    assert_eq!(tcp.up(114, 0x18, b"j").evs(), [&data(6, b"j", Some(0))]);
}

#[test]
fn segment_bound_skips_only_one_gap() {
    let mut tcp = Watch::new(Limits {
        segments: 2,
        ..Limits::default()
    });
    tcp.up(100, 2, b"");
    tcp.up(103, 0x18, b"c");
    tcp.up(105, 0x18, b"e");
    assert_eq!(
        tcp.up(107, 0x18, b"g").evs(),
        [&gap(0, 2), &data(0, b"c", None)]
    );
    assert_eq!(tcp.observer().buffered(), 1);
    assert_eq!(
        tcp.up(104, 0x18, b"d").evs(),
        [&data(1, b"d", Some(0)), &data(2, b"e", None)]
    );
}

#[test]
fn replacement_checks_the_bound_before_removing_old_bytes() {
    let mut tcp = Watch::new(Limits {
        buffered: 2,
        ..Limits::default()
    });
    tcp.up(100, 2, b"");
    tcp.up(103, 0x18, b"cd");
    assert_eq!(
        tcp.up(103, 0x18, b"XY").evs(),
        [&gap(0, 2), &data(0, b"cd", None)]
    );
}

#[test]
fn a_drop_without_held_bytes_waits_for_the_missing_segment() {
    for limits in [
        Limits {
            buffered: 0,
            ..Limits::default()
        },
        Limits {
            segments: 0,
            ..Limits::default()
        },
    ] {
        let mut tcp = Watch::new(limits);
        tcp.up(100, 2, b"");
        let dropped = tcp.up(103, 0x18, b"cd");
        assert!(dropped.events.is_empty());
        assert!(dropped.dropped());
        // The missing bytes come, covering the dropped ones: nothing is
        // missing after all.
        assert_eq!(
            tcp.up(101, 0x18, b"abcd").evs(),
            [&data(0, b"abcd", Some(0))]
        );
        assert_eq!(tcp.observer().buffered(), 0);
    }
}

/// Bytes dropped with no room to mark their place are still known to be
/// missing: a capture that ends before they come says Truncated.
#[test]
fn a_capture_that_ends_past_unmarked_dropped_bytes_is_truncated() {
    let mut tcp = Watch::new(Limits {
        segments: 0,
        ..Limits::default()
    });
    tcp.up(100, 2, b"");
    assert!(tcp.up(103, 0x18, b"cd").dropped());
    assert_eq!(
        tcp.finish().evs(),
        [
            &Ev::End(Forward, Termination::Truncated),
            &Ev::End(Reverse, Termination::Finalized),
        ]
    );
    // Once the bytes before them come and pass them, nothing is missing.
    let mut tcp = Watch::new(Limits {
        segments: 0,
        ..Limits::default()
    });
    tcp.up(100, 2, b"");
    tcp.up(103, 0x18, b"cd");
    tcp.up(101, 0x18, b"abcd");
    assert_eq!(
        tcp.finish().evs(),
        [
            &Ev::End(Forward, Termination::Finalized),
            &Ev::End(Reverse, Termination::Finalized),
        ]
    );
}

/// A shorter segment that replaces a held one drops the held one's tail:
/// a capture that ends before those bytes come again says Truncated.
#[test]
fn a_capture_that_ends_past_a_replaced_tail_is_truncated() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.up(103, 0x18, b"old");
    tcp.up(103, 0x18, b"cd");
    assert_eq!(
        tcp.up(101, 0x18, b"ab").evs(),
        [&data(0, b"ab", Some(0)), &data(2, b"cd", None)]
    );
    assert_eq!(
        tcp.finish().evs(),
        [
            &Ev::End(Forward, Termination::Truncated),
            &Ev::End(Reverse, Termination::Finalized),
        ]
    );
}

#[test]
fn fin_and_rst_follow_payload_and_are_reported_once() {
    for (flags, ends) in [
        (0x11, &[(Forward, Termination::Fin)][..]),
        (
            0x14,
            &[(Forward, Termination::Reset), (Reverse, Termination::Reset)][..],
        ),
        (
            0x15,
            &[(Forward, Termination::Fin), (Reverse, Termination::Reset)][..],
        ),
    ] {
        let mut tcp = watch();
        tcp.up(100, 2, b"");
        let mut expected = vec![data(0, b"ab", Some(0))];
        expected.extend(ends.iter().map(|(d, c)| Ev::End(*d, *c)));
        let closed = tcp.up(101, flags, b"ab");
        assert_eq!(closed.evs(), expected.iter().collect::<Vec<_>>());
        assert_eq!(closed.closed.len(), usize::from(flags & 4 != 0));
        assert!(tcp.up(101, flags, b"ab").events.is_empty());
    }
    // A reset ends both directions, even with bytes before it missing.
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    let reset = tcp.up(500, 4, b"");
    assert_eq!(
        reset.evs(),
        [
            &Ev::End(Forward, Termination::Reset),
            &Ev::End(Reverse, Termination::Reset)
        ]
    );
    assert_eq!(reset.closed.len(), 1);
    // What comes after is late: not delivered, and the connection is not
    // reopened for it.
    let late = tcp.up(101, 0x18, b"a");
    assert!(late.events.is_empty() && late.opened.is_empty());
    assert_eq!(late.late(), 1);
}

#[test]
fn both_directions_share_the_byte_budget_but_not_offsets() {
    let mut tcp = Watch::new(Limits {
        buffered: 2,
        ..Limits::default()
    });
    tcp.up(100, 2, b"");
    let header = tcp.down(500, 101, 0x12, b"");
    assert!(header.events.is_empty() && header.opened.is_empty());
    assert_eq!(header.segment().1, 1);
    tcp.up(103, 0x18, b"cd");
    let dropped = tcp.down(503, 101, 0x18, b"xy");
    assert!(dropped.events.is_empty());
    assert!(dropped.dropped());
    assert_eq!(
        tcp.down(501, 101, 0x18, b"ab").evs(),
        [
            &Ev::Data(Reverse, 0, b"ab".to_vec(), Some(0)),
            &Ev::Gap(Reverse, 2, Some(2))
        ]
    );
    assert_eq!(tcp.observer().buffered(), 2);
}

#[test]
fn syn_reuse_fast_open_and_the_connection_limit_release_held_bytes() {
    for ack in [101, 103] {
        let mut tcp = watch();
        let first = tcp.up(100, 2, b"ab");
        assert_eq!(first.evs(), [&data(0, b"ab", Some(0))]);
        assert_eq!(first.opened[0].1.opened, Some(Forward));
        tcp.up(105, 0x18, b"ef");
        let answer = tcp.down(500, ack, 0x12, b"");
        assert!(answer.events.is_empty() && answer.opened.is_empty());
        assert_eq!(tcp.observer().buffered(), 2);
        tcp.down(503, ack, 0x18, b"xy");
        assert_eq!(tcp.observer().buffered(), 4);
        let again = tcp.up(1000, 2, b"");
        assert_eq!(
            again.evs(),
            [
                &Ev::End(Forward, Termination::Replaced),
                &Ev::End(Reverse, Termination::Replaced)
            ]
        );
        assert_eq!(again.opened.len(), 1);
        assert_eq!(again.opened[0].1.generation, 1);
        assert_eq!(again.closed.len(), 1);
        assert_ne!(again.closed[0], again.opened[0].0);
        assert_eq!(tcp.observer().buffered(), 0);
        assert_eq!(tcp.observer().connections(), 1);
    }
    let mut tcp = Watch::new(Limits {
        connections: 0,
        ..Limits::default()
    });
    assert_eq!(tcp.observer().limits().connections, 1);
    let first = tcp.up(100, 2, b"");
    tcp.up(103, 0x18, b"cd");
    let other = tcp.send(Scope::ROOT, "192.0.2.1:40001", SERVER, 200, 0, 2, b"");
    // Only the connection seen longest ago is evicted.
    assert_eq!(
        other.events,
        [
            (first.opened[0].0, Ev::End(Forward, Termination::Evicted)),
            (first.opened[0].0, Ev::End(Reverse, Termination::Evicted))
        ]
    );
    assert_eq!(other.opened.len(), 1);
    assert_eq!(tcp.observer().buffered(), 0);
    assert_eq!(tcp.observer().connections(), 1);
}

/// A SYN or SYN-ACK with the sequence number its direction started at is
/// a retransmission, as a lossy capture shows when the first copy's
/// answer was lost. It neither restarts the connection nor rewinds the
/// direction, so the bytes after it still follow the bytes already
/// delivered.
#[test]
fn a_retransmitted_syn_does_not_rewind_its_direction() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.down(500, 101, 0x12, b"");
    assert_eq!(
        tcp.down(501, 101, 0x18, b"220 ready\r\n").evs(),
        [&Ev::Data(Reverse, 0, b"220 ready\r\n".to_vec(), Some(0))]
    );
    let again = tcp.down(500, 101, 0x12, b"");
    assert!(again.opened.is_empty() && again.closed.is_empty());
    assert!(again.events.is_empty());
    assert_eq!(
        tcp.down(512, 101, 0x18, b"next").evs(),
        [&Ev::Data(Reverse, 11, b"next".to_vec(), Some(0))]
    );
    assert_eq!(
        tcp.up(101, 0x18, b"EHLO").evs(),
        [&data(0, b"EHLO", Some(0))]
    );
    let again = tcp.up(100, 2, b"");
    assert!(again.opened.is_empty() && again.closed.is_empty());
    assert!(again.events.is_empty());
    assert_eq!(tcp.up(105, 0x18, b" x").evs(), [&data(4, b" x", Some(0))]);
}

#[test]
fn one_byte_at_a_time_has_no_accumulating_input_buffer() {
    let mut tcp = watch();
    tcp.up(0, 2, b"");
    for offset in 0..16384u32 {
        let byte = [offset as u8];
        assert_eq!(
            tcp.up(offset + 1, 0x18, &byte).evs(),
            [&data(u64::from(offset), &byte, Some(0))]
        );
        assert_eq!(tcp.observer().buffered(), 0);
    }
    // Each pending one-byte segment is removed once when the hole fills.
    for offset in (1..=256u32).rev() {
        assert!(
            tcp.up(16385 + offset, 0x18, &[offset as u8])
                .events
                .is_empty()
        );
    }
    let released = tcp.up(16385, 0x18, &[0]);
    assert_eq!(released.events.len(), 257);
    for (i, (_, event)) in released.events.iter().enumerate() {
        assert_eq!(
            *event,
            data(16384 + i as u64, &[i as u8], (i == 0).then_some(0))
        );
    }
    assert_eq!(tcp.observer().buffered(), 0);
}

/// An in-order FIN ends the direction at once. Bytes held past it are
/// never delivered.
#[test]
fn bytes_held_past_a_fin_are_late() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.up(104, 0x18, b"d");
    let closed = tcp.up(101, 0x11, b"ab");
    assert_eq!(
        closed.evs(),
        [
            &data(0, b"ab", Some(0)),
            &Ev::End(Forward, Termination::Fin)
        ]
    );
    assert_eq!(closed.late(), 1);
    assert!(tcp.up(104, 0x10, b"").events.is_empty());
    assert_eq!(tcp.observer().buffered(), 0);
}

#[test]
fn position_exhaustion_drops_payloads_and_fin_without_wrapping() {
    for (seq, flags, payload) in [
        (101, 0x18, b"x".as_slice()),
        (102, 0x18, b"x".as_slice()),
        (101, 0x11, b"".as_slice()),
    ] {
        let mut tcp = watch();
        tcp.up(100, 2, b"");
        tcp.flow(Forward).set_position(u64::MAX, 101);
        let seen = tcp.up(seq, flags, payload);
        assert!(seen.events.is_empty());
        assert!(seen.dropped());
        assert_eq!(tcp.observer().buffered(), 0);
        let flow = tcp.flow(Forward);
        assert_eq!(flow.position(), u64::MAX);
        assert_eq!(flow.next(), Some(101));
        assert!(!flow.ended());
    }
}

#[test]
fn buffered_payload_cannot_overflow_the_position() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.flow(Forward).set_position(u64::MAX - 1, 101);
    assert!(tcp.up(102, 0x18, b"xy").events.is_empty());
    let seen = tcp.up(101, 0x18, b"a");
    assert_eq!(seen.evs(), [&data(0, b"a", Some(0))]);
    assert!(seen.dropped());
    assert_eq!(tcp.observer().buffered(), 0);
    assert_eq!(tcp.flow(Forward).held_segments(), 0);
    let flow = tcp.flow(Forward);
    assert_eq!(flow.position(), u64::MAX);
    assert_eq!(flow.next(), Some(102));
}

/// The end of the capture finishes what is open: bytes held past a hole
/// come up after their gap, and a direction with bytes known missing is
/// truncated, while one with none is only finalized.
#[test]
fn the_capture_end_finishes_open_directions() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.down(500, 101, 0x12, b"");
    tcp.up(101, 0x18, b"ab");
    tcp.up(105, 0x18, b"ef");
    tcp.down(501, 101, 0x18, b"ok");
    let end = tcp.finish();
    assert_eq!(
        end.evs(),
        [
            &gap(2, 2),
            &data(2, b"ef", None),
            &Ev::End(Forward, Termination::Truncated),
            &Ev::End(Reverse, Termination::Finalized),
        ]
    );
    assert_eq!(end.closed.len(), 1);
    assert_eq!(tcp.observer().buffered(), 0);
    // A FIN still waiting for bytes before it is a known hole too.
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    tcp.up(103, 0x11, b"cd");
    assert_eq!(
        tcp.finish().evs(),
        [
            &gap(0, 2),
            &data(0, b"cd", Some(0)),
            &Ev::End(Forward, Termination::Truncated),
            &Ev::End(Reverse, Termination::Finalized),
        ]
    );
    // Nothing comes after the capture's end.
    assert!(matches!(
        tcp.tcp.deliver(PacketEvent::Ended),
        Ok(Admit::Closed(PacketEvent::Ended))
    ));
}

/// The same endpoints after the connection closed are a new connection,
/// one generation on. Late payload of the old one reopens nothing.
#[test]
fn tuple_reuse_starts_a_new_generation() {
    let mut tcp = watch();
    let first = tcp.up(100, 2, b"");
    tcp.down(500, 101, 0x12, b"");
    tcp.up(101, 0x11, b"bye");
    let closed = tcp.down(501, 105, 0x11, b"");
    assert_eq!(closed.evs(), [&Ev::End(Reverse, Termination::Fin)]);
    assert_eq!(closed.closed, [first.opened[0].0]);
    let late = tcp.up(105, 0x18, b"more");
    assert!(late.events.is_empty() && late.opened.is_empty());
    assert_eq!(late.late(), 4);
    let second = tcp.up(9000, 2, b"");
    assert_eq!(second.opened.len(), 1);
    assert_eq!(second.opened[0].1.generation, 1);
    assert_eq!(second.opened[0].1.opened, Some(Forward));
    assert_ne!(second.opened[0].1.key(), first.opened[0].1.key());
    assert_eq!(
        tcp.up(9001, 0x18, b"new").evs(),
        [&data(0, b"new", Some(0))]
    );
}

/// The same endpoints in another scope, such as inside a tunnel, are
/// another connection, with their own child and their own bytes.
#[test]
fn overlapping_tuples_in_other_scopes_do_not_alias() {
    let mut tcp = watch();
    let inner = Scopes::default().tunnel();
    let outer = tcp.send(Scope::ROOT, CLIENT, SERVER, 100, 0, 2, b"");
    let tunneled = tcp.send(inner, CLIENT, SERVER, 100, 0, 2, b"");
    assert_eq!((outer.opened.len(), tunneled.opened.len()), (1, 1));
    let (a, b) = (outer.opened[0], tunneled.opened[0]);
    assert_ne!(a.0, b.0);
    assert_eq!(b.1.scope, inner);
    let one = tcp.send(Scope::ROOT, CLIENT, SERVER, 101, 0, 0x18, b"outer");
    let two = tcp.send(inner, CLIENT, SERVER, 101, 0, 0x18, b"inner");
    assert_eq!(one.events, [(a.0, data(0, b"outer", Some(0)))]);
    assert_eq!(two.events, [(b.0, data(0, b"inner", Some(0)))]);
    let reset = tcp.send(inner, SERVER, CLIENT, 7, 0, 4, b"");
    assert!(reset.events.iter().all(|(id, _)| *id == b.0));
    assert_eq!(
        tcp.send(Scope::ROOT, CLIENT, SERVER, 106, 0, 0x18, b"!")
            .events,
        [(a.0, data(5, b"!", Some(0)))]
    );
}

/// Connections in many networks count against one capture's limit, so
/// adding networks does not multiply what the observer holds.
#[test]
fn networks_share_the_capture_connection_limit() {
    let mut tcp = Watch::new(Limits {
        connections: 2,
        ..Limits::default()
    });
    let scopes = Scopes::default();
    for _ in 0..8 {
        tcp.send(scopes.tunnel(), CLIENT, SERVER, 100, 0, 2, b"");
        assert!(tcp.observer().connections() <= 2);
    }
    assert_eq!(tcp.observer().connections(), 2);
}

/// A child's data waits for credit; its siblings go on. A child that
/// never takes what waits is evicted once the waiting bound is passed.
#[test]
fn data_waits_for_credit_within_a_bound() {
    let mut tcp = Watch::new(Limits {
        waiting: 1000,
        ..Limits::default()
    });
    tcp.grant = false;
    let stalled = tcp.up(100, 0x18, b"first");
    assert!(stalled.events.is_empty());
    let id = stalled.opened[0].0;
    // A sibling with credit still gets its bytes.
    let sibling = tcp.send(Scope::ROOT, "192.0.2.3:1", SERVER, 1, 0, 0x18, b"x");
    let handle = tcp.handles.pop().unwrap();
    assert!(tcp.tcp.command(handle.grant(1)).is_ok());
    let got = tcp.drain();
    assert_eq!(got.events, [(sibling.opened[0].0, data(0, b"x", Some(0)))]);
    // The stalled child is evicted once it holds too much.
    let mut evicted = Seen::default();
    for i in 0..20u32 {
        evicted = tcp.up(105 + i * 100, 0x18, &[b'a'; 100]);
        if !evicted.closed.is_empty() {
            break;
        }
    }
    assert_eq!(
        evicted.events,
        [
            (id, Ev::End(Forward, Termination::Evicted)),
            (id, Ev::End(Reverse, Termination::Evicted))
        ]
    );
    assert_eq!(evicted.closed, [id]);
    assert!(tcp.observer().outputs.waiting <= 1000);
    // Later bytes of that connection are not delivered.
    let after = tcp.up(5000, 0x18, b"z");
    assert!(after.events.is_empty() && after.opened.is_empty());
}

#[test]
fn closing_an_old_child_cannot_detach_its_replacement() {
    let mut tcp = Watch::new(Limits::default());
    tcp.grant = false;
    let first = tcp.up(100, 0x02, b"old");
    let old = tcp.handles.remove(0);
    let replacement = tcp.up(200, 0x02, b"new");
    let id = replacement.opened[0].0;
    assert_ne!(first.opened[0].0, id);
    assert!(tcp.tcp.command(old.close()).unwrap().moved());
    tcp.grant = true;
    assert!(
        tcp.tcp
            .command(tcp.handles[0].grant(u64::MAX))
            .unwrap()
            .moved()
    );
    let seen = tcp.drain();
    assert!(seen.events.iter().any(|(child, event)| *child == id
        && matches!(event, Ev::Data(_, _, bytes, _) if bytes == b"new")));
    let next = tcp.up(204, 0x10, b"more");
    assert!(next.events.iter().any(|(child, event)| *child == id
        && matches!(event, Ev::Data(_, _, bytes, _) if bytes == b"more")));
}

/// A child closed from above takes nothing more of its connection.
#[test]
fn a_child_closed_from_above_gets_nothing_more() {
    let mut tcp = watch();
    tcp.up(100, 2, b"");
    let child = tcp.handles.pop().unwrap();
    assert!(tcp.tcp.command(child.close()).is_ok());
    let after = tcp.up(101, 0x18, b"ignored");
    assert!(after.events.is_empty() && after.opened.is_empty());
    assert_eq!(after.late(), 7);
}

/// Random segments over a few connections, in tight bounds: each
/// direction's positions follow on through its data and gaps, nothing
/// follows an end, a child closes only after both its ends, delivered
/// bytes were captured, and the bounds hold.
#[test]
fn random_segments_keep_the_stream_rules() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..40 {
        let limits = Limits {
            buffered: (rand() % 64) as usize,
            segments: (rand() % 6) as usize,
            connections: (rand() % 4) as usize,
            waiting: (rand() % 2000) as usize,
        };
        let mut tcp = Watch::new(limits);
        tcp.grant = round % 3 != 0;
        let limits = tcp.observer().limits();
        let mut next: BTreeMap<(ChildId, Direction), u64> = BTreeMap::new();
        let mut ended = BTreeSet::new();
        let mut open = BTreeSet::new();
        let mut captured = [0usize; 256];
        let mut base = [0u32; 6];
        let mut check = |seen: Seen, captured: &mut [usize; 256]| {
            open.extend(seen.opened.iter().map(|(id, _)| *id));
            let mut sequences = seen.sequences.iter();
            for (id, event) in &seen.events {
                assert!(open.contains(id));
                let direction = match event {
                    Ev::Data(d, ..) | Ev::Gap(d, ..) | Ev::End(d, _) => *d,
                };
                assert!(!ended.contains(&(*id, direction)), "{event:?} after an end");
                match event {
                    Ev::Data(_, _, bytes, _) => {
                        let (_, sequence) = sequences.next().unwrap();
                        let expected = next.entry((*id, direction)).or_insert(*sequence);
                        assert_eq!(*expected, *sequence);
                        *expected += bytes.len() as u64;
                        assert!(!bytes.is_empty());
                        for byte in bytes {
                            let left = &mut captured[usize::from(*byte)];
                            *left = left.checked_sub(1).unwrap();
                        }
                    }
                    Ev::Gap(_, _, missing) => {
                        let (_, sequence) = sequences.next().unwrap();
                        let expected = next.entry((*id, direction)).or_insert(*sequence);
                        assert_eq!(*expected, *sequence);
                        *expected += missing.unwrap();
                    }
                    Ev::End(..) => {
                        ended.insert((*id, direction));
                    }
                }
            }
            for id in seen.closed {
                assert!(open.remove(&id));
                assert!(ended.contains(&(id, Forward)) && ended.contains(&(id, Reverse)));
            }
        };
        for _ in 0..300 {
            let flow = (rand() % 6) as usize;
            let client = format!("192.0.2.1:{}", 40000 + flow / 2);
            let (from, to) = if flow.is_multiple_of(2) {
                (client.as_str(), SERVER)
            } else {
                (SERVER, client.as_str())
            };
            let flags = [0x02, 0x12, 0x18, 0x18, 0x18, 0x11, 0x14, 0x10][(rand() % 8) as usize];
            let len = (rand() % 12) as usize;
            let payload: Vec<u8> = (0..len).map(|_| rand() as u8).collect();
            let seq = if rand() % 4 == 0 {
                rand() as u32
            } else {
                base[flow]
                    .wrapping_add((rand() % 40) as u32)
                    .wrapping_sub(10)
            };
            base[flow] = seq.wrapping_add(len as u32);
            for byte in &payload {
                captured[usize::from(*byte)] += 1;
            }
            let ack = base[flow ^ 1];
            let seen = tcp.send(Scope::ROOT, from, to, seq, ack, flags, &payload);
            check(seen, &mut captured);
            assert!(tcp.observer().buffered() <= limits.buffered);
            assert!(tcp.observer().connections() <= limits.connections);
        }
        if tcp.grant {
            let seen = tcp.finish();
            check(seen, &mut captured);
            assert!(open.is_empty(), "the capture's end closes every child");
            assert_eq!(tcp.observer().buffered(), 0);
        }
    }
}

/// A packet the capture cut short gives none of its payload, so nothing
/// is made up from the part that is there. Its SYN still opens the
/// direction, and the SYN sent again whole is a repeat of it.
#[test]
fn a_packet_cut_short_gives_no_payload() {
    let mut tcp = watch();
    tcp.cut = 1;
    let syn = tcp.up(100, 2, b"ab");
    assert_eq!(syn.opened.len(), 1);
    assert!(syn.events.is_empty());
    let again = tcp.up(100, 2, b"ab");
    assert!(again.opened.is_empty() && again.closed.is_empty());
    assert_eq!(again.evs(), [&data(0, b"ab", Some(0))]);
    tcp.cut = 2;
    assert!(tcp.up(103, 0x18, b"cdef").events.is_empty());
    // The same segment captured whole follows on.
    assert_eq!(
        tcp.up(103, 0x18, b"cdef").evs(),
        [&data(2, b"cdef", Some(0))]
    );
}
