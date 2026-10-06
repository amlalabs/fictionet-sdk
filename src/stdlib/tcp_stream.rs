use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// One TCP direction: source address, source port, destination address, port.
pub type FlowKey = (IpAddr, u16, IpAddr, u16);

/// Returns a connection's key with the lower endpoint first.
///
/// The flag is true when `key` runs in the reverse direction.
pub fn conversation_key(key: FlowKey) -> (FlowKey, bool) {
    let (a, b) = ((key.0, key.1), (key.2, key.3));
    if a <= b {
        (key, false)
    } else {
        ((key.2, key.3, key.0, key.1), true)
    }
}

/// Bounds on retained TCP state. No storage is reserved in advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Payload bytes held across all directions. The default is 8 MiB.
    /// Zero disables out-of-order buffering.
    pub max_buffered: usize,
    /// Segments held per direction. The default is 256.
    /// Zero disables out-of-order buffering.
    pub max_segments: usize,
    /// Directions tracked at once. The default is 512.
    /// Zero is raised to one. Adding a direction past this bound clears
    /// all state and sets [`Reassembled::cleared`].
    pub max_flows: usize,
}

impl Default for Limits {
    /// Uses 8 MiB, 256 segments per direction, and 512 directions.
    fn default() -> Self {
        Self {
            max_buffered: 8 << 20,
            max_segments: 256,
            max_flows: 512,
        }
    }
}

/// A captured TCP segment. Sequence numbers are the raw wire values.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    /// The segment's direction.
    pub key: FlowKey,
    /// Sequence number of the SYN, or of the first payload byte.
    pub seq: u32,
    /// Acknowledgment number. Used only when ACK is set.
    pub ack: u32,
    /// TCP flags: FIN is 0x01, SYN is 0x02, RST is 0x04, ACK is 0x10.
    pub flags: u8,
    /// Payload without TCP headers. A SYN consumes one number before it.
    pub payload: &'a [u8],
}

/// Ordered output for one direction of a captured TCP connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpEvent {
    /// New bytes, with retransmitted prefixes removed.
    Bytes {
        /// The direction that sent these bytes.
        dir: FlowKey,
        /// Number of bytes delivered earlier in this direction.
        /// Missing bytes and SYN/FIN sequence numbers do not count.
        offset: u64,
        /// A nonempty run of bytes in stream order.
        bytes: Vec<u8>,
        /// Offset within this call's segment payload, if it supplied the
        /// bytes. Buffered segments use `None`.
        input_offset: Option<usize>,
    },
    /// A payload was dropped because a bound was reached.
    Gap {
        /// The direction with missing bytes.
        dir: FlowKey,
        /// Number of bytes delivered before this event.
        offset: u64,
        /// True if reassembly skipped to the first buffered segment.
        /// Reset application framing and compression state before the
        /// following bytes. False means it still waits for missing bytes.
        resumed: bool,
    },
    /// An in-order FIN or a RST was observed.
    ///
    /// This reports the capture's close signal. Later captured payloads
    /// still pass through reassembly. An early FIN must be seen again
    /// once its preceding bytes have arrived. Repeated closes are silent
    /// until a SYN resets the direction.
    End {
        /// The direction that sent the close signal.
        dir: FlowKey,
        /// Number of bytes delivered before this event.
        offset: u64,
        /// True for RST; false for FIN. RST takes no sequence number.
        reset: bool,
    },
}

/// A segment's relative header values and ordered events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reassembled {
    /// Sequence number relative to the first segment seen in this direction.
    pub rel_seq: u32,
    /// ACK relative to the first reverse segment, or zero if unknown.
    pub rel_ack: u32,
    /// True if all payload sequence numbers have already been passed.
    pub retransmission: bool,
    /// A SYN started a new connection. Discard both application directions.
    /// A SYN-ACK acknowledging the observed SYN or its Fast Open data
    /// leaves this false.
    pub restarted: bool,
    /// The flow bound cleared every connection. Discard all application state.
    pub cleared: bool,
    /// Events in delivery order. Bytes precede the segment's end signal.
    pub events: Vec<TcpEvent>,
}

struct Flow {
    isn: u32,
    next: Option<u32>,
    // Relative sequence keys keep segments ordered across wire wraparound.
    held: BTreeMap<u32, Vec<u8>>,
    held_bytes: usize,
    delivered: u64,
    opened: Option<(u32, u32)>,
    ended: bool,
}

impl Flow {
    fn new(isn: u32) -> Self {
        Self {
            isn,
            next: None,
            held: BTreeMap::new(),
            held_bytes: 0,
            delivered: 0,
            opened: None,
            ended: false,
        }
    }

    fn bytes(
        &mut self,
        dir: FlowKey,
        seq: u32,
        bytes: &[u8],
        input_offset: Option<usize>,
    ) -> TcpEvent {
        let offset = self.delivered;
        let Some(delivered) = u64::try_from(bytes.len())
            .ok()
            .and_then(|n| offset.checked_add(n))
        else {
            return TcpEvent::Gap {
                dir,
                offset,
                resumed: false,
            };
        };
        self.delivered = delivered;
        self.next = Some(seq.wrapping_add(bytes.len() as u32));
        TcpEvent::Bytes {
            dir,
            offset,
            bytes: bytes.to_vec(),
            input_offset,
        }
    }
}

/// Bounded TCP reassembly for captured segments in either direction.
///
/// A new direction starts at its first payload sequence number, or just
/// after its SYN. In-order bytes are delivered immediately. Earlier bytes
/// are trimmed. Out-of-order segments are held under [`Limits`]. A later
/// segment at the same starting number replaces the buffered one. Other
/// overlaps keep the bytes delivered first.
///
/// If a new out-of-order segment would exceed either buffer bound, that
/// segment is dropped. Reassembly skips to the earliest buffered segment,
/// emits [`TcpEvent::Gap`], and drains its contiguous successors. With no
/// buffered segment it reports a gap and keeps waiting. The limits are
/// checked before replacement, including for retransmits of held data.
/// Returned events own their bytes and are outside the retained budget.
///
/// TCP sequence comparisons and advances deliberately wrap modulo 2^32.
/// As with TCP serial arithmetic, live sequence distances must be less
/// than 2^31. Payloads longer than `i32::MAX` are dropped with a gap.
/// Stream byte offsets use checked arithmetic; exhausting `u64` drops
/// that output with a gap. Missing bytes never increase the byte offset.
///
/// No application protocol types are required. Feed byte events to any
/// decoder and reset its state when reassembly resumes after a gap.
/// In-order one-byte segments take constant work. Buffered insertion and
/// removal take logarithmic work in the bounded segment count. Payloads
/// are copied only when inserted or delivered, never rescanned per arrival.
///
/// ```
/// use fictionet::stdlib::tcp_stream::{Reassembler, Segment, TcpEvent};
/// let key = ("192.0.2.1".parse()?, 40000, "192.0.2.2".parse()?, 80);
/// let mut tcp = Reassembler::default();
/// let result = tcp.push(Segment { key, seq: 10, ack: 0, flags: 0x18, payload: b"hello" });
/// assert!(matches!(&result.events[..], [TcpEvent::Bytes { offset: 0, bytes, .. }] if bytes == b"hello"));
/// assert_eq!(tcp.buffered(), 0);
/// # Ok::<(), std::net::AddrParseError>(())
/// ```
pub struct Reassembler {
    limits: Limits,
    flows: HashMap<FlowKey, Flow>,
    held: usize,
}

impl Default for Reassembler {
    /// Creates a reassembler with the default [`Limits`].
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

// Signed serial comparison deliberately uses modulo-2^32 subtraction.
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

// Retain the previous upper bound if accounting cannot be reduced.
fn release(held: &mut usize, bytes: usize) {
    if let Some(remaining) = held.checked_sub(bytes) {
        *held = remaining;
    }
}

impl Reassembler {
    /// Creates empty state with the given bounds. Raises `max_flows` to one.
    pub fn new(mut limits: Limits) -> Self {
        limits.max_flows = limits.max_flows.max(1);
        Self {
            limits,
            flows: HashMap::new(),
            held: 0,
        }
    }

    /// Returns the effective bounds.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns payload bytes held across all directions.
    pub fn buffered(&self) -> usize {
        self.held
    }

    /// Returns the number of tracked directions, including closed ones.
    pub fn flows(&self) -> usize {
        self.flows.len()
    }

    /// Returns the number of buffered segments in `dir`, or zero if unknown.
    pub fn buffered_segments(&self, dir: FlowKey) -> usize {
        self.flows.get(&dir).map_or(0, |flow| flow.held.len())
    }

    /// Tracks a segment and returns its header values and ordered events.
    ///
    /// SYN resets its direction. Unless it acknowledges an observed peer
    /// SYN, it also removes the reverse direction and sets `restarted`.
    /// FIN consumes one sequence number only when all preceding bytes
    /// have arrived. RST emits an end even when preceding bytes are missing.
    pub fn push(&mut self, segment: Segment<'_>) -> Reassembled {
        let Segment {
            key,
            seq,
            ack,
            flags,
            payload,
        } = segment;
        let mut result = Reassembled {
            rel_seq: 0,
            rel_ack: 0,
            retransmission: false,
            restarted: false,
            cleared: false,
            events: Vec::new(),
        };
        if self.flows.len() >= self.limits.max_flows && !self.flows.contains_key(&key) {
            self.flows.clear();
            self.held = 0;
            result.cleared = true;
        }
        let syn = flags & 0x02 != 0;
        let back = (key.2, key.3, key.0, key.1);
        if syn {
            let answers = flags & 0x10 != 0
                && self
                    .flows
                    .get(&back)
                    .and_then(|b| b.opened)
                    .is_some_and(|(a, b)| ack == a || ack == b);
            if !answers {
                result.restarted = true;
                if let Some(b) = self.flows.remove(&back) {
                    release(&mut self.held, b.held_bytes);
                }
            }
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow::new(seq));
        if syn {
            release(&mut self.held, flow.held_bytes);
            *flow = Flow::new(seq);
            flow.next = Some(seq.wrapping_add(1));
            flow.opened = Some((
                seq.wrapping_add(1),
                seq.wrapping_add(1).wrapping_add(payload.len() as u32),
            ));
        }
        result.rel_seq = seq.wrapping_sub(flow.isn);
        result.retransmission = flow.next.is_some_and(|next| {
            !payload.is_empty() && !before(next, seq.wrapping_add(payload.len() as u32)) && !syn
        });
        let seq = if syn { seq.wrapping_add(1) } else { seq };
        let next = *flow.next.get_or_insert(seq);
        let mut gap = false;
        if payload.len() > i32::MAX as usize {
            gap = true;
        } else if !payload.is_empty() {
            if seq == next || before(seq, next) {
                let skip = next.wrapping_sub(seq) as usize;
                if let Some(bytes) = payload.get(skip..).filter(|b| !b.is_empty()) {
                    result.events.push(flow.bytes(key, next, bytes, Some(skip)));
                }
            } else if self
                .held
                .checked_add(payload.len())
                .is_some_and(|n| n <= self.limits.max_buffered)
                && flow.held.len() < self.limits.max_segments
            {
                // The global check also bounds this direction's addition.
                if let (Some(total), Some(local)) = (
                    self.held.checked_add(payload.len()),
                    flow.held_bytes.checked_add(payload.len()),
                ) {
                    self.held = total;
                    flow.held_bytes = local;
                    if let Some(old) = flow
                        .held
                        .insert(seq.wrapping_sub(flow.isn), payload.to_vec())
                    {
                        release(&mut flow.held_bytes, old.len());
                        release(&mut self.held, old.len());
                    }
                }
            } else {
                gap = true;
            }
        }
        while let Some((&k, _)) = flow.held.first_key_value() {
            let next = flow.next.unwrap_or(seq);
            let s = k.wrapping_add(flow.isn);
            if before(next, s) && !gap {
                break;
            }
            let Some((_, bytes)) = flow.held.pop_first() else {
                break;
            };
            release(&mut flow.held_bytes, bytes.len());
            release(&mut self.held, bytes.len());
            if gap && before(next, s) {
                flow.next = Some(s);
                gap = false;
                result.events.push(TcpEvent::Gap {
                    dir: key,
                    offset: flow.delivered,
                    resumed: true,
                });
            }
            let next = flow.next.unwrap_or(s);
            let skip = if before(s, next) {
                next.wrapping_sub(s) as usize
            } else {
                0
            };
            if let Some(tail) = bytes.get(skip..).filter(|b| !b.is_empty()) {
                result
                    .events
                    .push(flow.bytes(key, s.wrapping_add(skip as u32), tail, None));
            }
        }
        if gap {
            result.events.push(TcpEvent::Gap {
                dir: key,
                offset: flow.delivered,
                resumed: false,
            });
        }
        let fin = flags & 0x01 != 0 && flow.next == Some(seq.wrapping_add(payload.len() as u32));
        if fin {
            flow.next = flow.next.map(|n| n.wrapping_add(1));
        }
        if !flow.ended && (fin || flags & 0x04 != 0) {
            flow.ended = true;
            result.events.push(TcpEvent::End {
                dir: key,
                offset: flow.delivered,
                reset: flags & 0x04 != 0,
            });
        }
        result.rel_ack = match self.flows.get(&back) {
            Some(b) if flags & 0x10 != 0 => ack.wrapping_sub(b.isn),
            _ => 0,
        };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key() -> FlowKey {
        (
            Ipv4Addr::new(192, 0, 2, 1).into(),
            40000,
            Ipv4Addr::new(192, 0, 2, 2).into(),
            80,
        )
    }

    fn segment(seq: u32, flags: u8, payload: &[u8]) -> Segment<'_> {
        Segment {
            key: key(),
            seq,
            ack: 0,
            flags,
            payload,
        }
    }

    fn bytes(offset: u64, data: &[u8], input_offset: Option<usize>) -> TcpEvent {
        TcpEvent::Bytes {
            dir: key(),
            offset,
            bytes: data.to_vec(),
            input_offset,
        }
    }

    fn gap(offset: u64, resumed: bool) -> TcpEvent {
        TcpEvent::Gap {
            dir: key(),
            offset,
            resumed,
        }
    }

    #[test]
    fn in_order_and_midstream_capture() {
        let mut tcp = Reassembler::default();
        assert_eq!(
            tcp.push(segment(20, 0x18, b"abc")).events,
            [bytes(0, b"abc", Some(0))]
        );
        let result = tcp.push(segment(23, 0x18, b"def"));
        assert_eq!(result.rel_seq, 3);
        assert_eq!(result.events, [bytes(3, b"def", Some(0))]);
        assert_eq!(tcp.buffered(), 0);
        assert_eq!(tcp.flows(), 1);
    }

    #[test]
    fn out_of_order_and_overlapping_buffered_segments() {
        let mut tcp = Reassembler::default();
        tcp.push(segment(100, 2, b""));
        assert!(tcp.push(segment(105, 0x18, b"efgh")).events.is_empty());
        assert!(tcp.push(segment(103, 0x18, b"cdef")).events.is_empty());
        assert_eq!(tcp.buffered(), 8);
        assert_eq!(
            tcp.push(segment(101, 0x18, b"ab")).events,
            [
                bytes(0, b"ab", Some(0)),
                bytes(2, b"cdef", None),
                bytes(6, b"gh", None)
            ]
        );
        assert_eq!(tcp.buffered(), 0);
        assert_eq!(tcp.buffered_segments(key()), 0);
    }

    #[test]
    fn overlaps_and_retransmits() {
        let mut tcp = Reassembler::default();
        tcp.push(segment(100, 2, b""));
        tcp.push(segment(101, 0x18, b"abcd"));
        let repeated = tcp.push(segment(101, 0x18, b"abcd"));
        assert!(repeated.retransmission);
        assert!(repeated.events.is_empty());
        let overlap = tcp.push(segment(103, 0x18, b"XXef"));
        assert!(!overlap.retransmission);
        assert_eq!(overlap.events, [bytes(4, b"ef", Some(2))]);
        // The new in-order segment wins over an already held overlap.
        tcp.push(segment(108, 0x18, b"Xij"));
        assert_eq!(
            tcp.push(segment(107, 0x18, b"gh")).events,
            [bytes(6, b"gh", Some(0)), bytes(8, b"ij", None)]
        );
        assert_eq!(tcp.buffered(), 0);
    }

    #[test]
    fn buffered_retransmit_replaces_at_the_same_sequence() {
        let mut tcp = Reassembler::default();
        tcp.push(segment(100, 2, b""));
        tcp.push(segment(103, 0x18, b"old"));
        tcp.push(segment(103, 0x18, b"cd"));
        assert_eq!(tcp.buffered(), 2);
        assert_eq!(tcp.buffered_segments(key()), 1);
        assert_eq!(
            tcp.push(segment(101, 0x18, b"ab")).events,
            [bytes(0, b"ab", Some(0)), bytes(2, b"cd", None)]
        );
    }

    #[test]
    fn wraparound_and_early_fin() {
        let mut tcp = Reassembler::default();
        let isn = u32::MAX - 2;
        tcp.push(segment(isn, 2, b""));
        assert!(tcp.push(segment(1, 0x19, b"de")).events.is_empty());
        assert_eq!(
            tcp.push(segment(isn.wrapping_add(1), 0x18, b"abc")).events,
            [bytes(0, b"abc", Some(0)), bytes(3, b"de", None)]
        );
        // As in the captured stream policy, the early FIN did not consume
        // a sequence number. Its retransmission can now close the stream.
        let end = TcpEvent::End {
            dir: key(),
            offset: 5,
            reset: false,
        };
        assert_eq!(tcp.push(segment(1, 0x19, b"de")).events, [end]);
        assert!(tcp.push(segment(1, 0x19, b"de")).events.is_empty());
        assert_eq!(tcp.flows.get(&key()).unwrap().next, Some(4));
    }

    #[test]
    fn byte_bound_drops_incoming_and_resumes_at_first_held_segment() {
        let mut tcp = Reassembler::new(Limits {
            max_buffered: 4,
            ..Limits::default()
        });
        tcp.push(segment(100, 2, b""));
        tcp.push(segment(104, 0x18, b"de"));
        tcp.push(segment(106, 0x18, b"fg"));
        assert_eq!(tcp.buffered(), 4);
        assert_eq!(
            tcp.push(segment(110, 0x18, b"lost")).events,
            [gap(0, true), bytes(0, b"de", None), bytes(2, b"fg", None)]
        );
        assert_eq!(tcp.buffered(), 0);
        assert_eq!(
            tcp.push(segment(108, 0x18, b"hi")).events,
            [bytes(4, b"hi", Some(0))]
        );
    }

    #[test]
    fn segment_bound_skips_only_one_gap() {
        let mut tcp = Reassembler::new(Limits {
            max_segments: 2,
            ..Limits::default()
        });
        tcp.push(segment(100, 2, b""));
        tcp.push(segment(103, 0x18, b"c"));
        tcp.push(segment(105, 0x18, b"e"));
        assert_eq!(
            tcp.push(segment(107, 0x18, b"g")).events,
            [gap(0, true), bytes(0, b"c", None)]
        );
        assert_eq!(tcp.buffered(), 1);
        assert_eq!(
            tcp.push(segment(104, 0x18, b"d")).events,
            [bytes(1, b"d", Some(0)), bytes(2, b"e", None)]
        );
    }

    #[test]
    fn replacement_checks_the_bound_before_removing_old_bytes() {
        let mut tcp = Reassembler::new(Limits {
            max_buffered: 2,
            ..Limits::default()
        });
        tcp.push(segment(100, 2, b""));
        tcp.push(segment(103, 0x18, b"cd"));
        assert_eq!(
            tcp.push(segment(103, 0x18, b"XY")).events,
            [gap(0, true), bytes(0, b"cd", None)]
        );
    }

    #[test]
    fn gap_without_held_bytes_waits_for_the_missing_segment() {
        for limits in [
            Limits {
                max_buffered: 0,
                ..Limits::default()
            },
            Limits {
                max_segments: 0,
                ..Limits::default()
            },
        ] {
            let mut tcp = Reassembler::new(limits);
            tcp.push(segment(100, 2, b""));
            assert_eq!(tcp.push(segment(103, 0x18, b"cd")).events, [gap(0, false)]);
            assert_eq!(
                tcp.push(segment(101, 0x18, b"abcd")).events,
                [bytes(0, b"abcd", Some(0))]
            );
            assert_eq!(tcp.buffered(), 0);
        }
    }

    #[test]
    fn fin_and_rst_follow_payload_and_are_reported_once() {
        for flags in [0x11, 0x14, 0x15] {
            let mut tcp = Reassembler::default();
            tcp.push(segment(100, 2, b""));
            assert_eq!(
                tcp.push(segment(101, flags, b"ab")).events,
                [
                    bytes(0, b"ab", Some(0)),
                    TcpEvent::End {
                        dir: key(),
                        offset: 2,
                        reset: flags & 4 != 0
                    }
                ]
            );
            assert!(tcp.push(segment(101, flags, b"ab")).events.is_empty());
        }
        let mut tcp = Reassembler::default();
        tcp.push(segment(100, 2, b""));
        assert_eq!(
            tcp.push(segment(500, 4, b"")).events,
            [TcpEvent::End {
                dir: key(),
                offset: 0,
                reset: true
            }]
        );
        assert_eq!(
            tcp.push(segment(101, 0x18, b"a")).events,
            [bytes(0, b"a", Some(0))]
        );
    }

    #[test]
    fn both_directions_share_the_byte_budget_but_not_offsets() {
        let mut tcp = Reassembler::new(Limits {
            max_buffered: 2,
            ..Limits::default()
        });
        let key = key();
        let back = (key.2, key.3, key.0, key.1);
        tcp.push(segment(100, 2, b""));
        let response = Segment {
            key: back,
            seq: 500,
            ack: 101,
            flags: 0x12,
            payload: b"",
        };
        let header = tcp.push(response);
        assert!(!header.restarted);
        assert_eq!(header.rel_ack, 1);
        tcp.push(segment(103, 0x18, b"cd"));
        assert_eq!(
            tcp.push(Segment {
                seq: 503,
                flags: 0x18,
                payload: b"xy",
                ..response
            })
            .events,
            [TcpEvent::Gap {
                dir: back,
                offset: 0,
                resumed: false
            }]
        );
        assert_eq!(
            tcp.push(Segment {
                seq: 501,
                flags: 0x18,
                payload: b"ab",
                ..response
            })
            .events,
            [TcpEvent::Bytes {
                dir: back,
                offset: 0,
                bytes: b"ab".to_vec(),
                input_offset: Some(0)
            }]
        );
        assert_eq!(tcp.buffered(), 2);
        assert_eq!(conversation_key(key), (key, false));
        assert_eq!(conversation_key(back), (key, true));
    }

    #[test]
    fn syn_reuse_fast_open_and_flow_limit_release_held_bytes() {
        for ack in [101, 103] {
            let mut tcp = Reassembler::default();
            let key = key();
            assert_eq!(
                tcp.push(segment(100, 2, b"ab")).events,
                [bytes(0, b"ab", Some(0))]
            );
            tcp.push(segment(105, 0x18, b"ef"));
            let back = (key.2, key.3, key.0, key.1);
            assert!(
                !tcp.push(Segment {
                    key: back,
                    seq: 500,
                    ack,
                    flags: 0x12,
                    payload: b""
                })
                .restarted
            );
            assert_eq!(tcp.buffered(), 2);
            tcp.push(Segment {
                key: back,
                seq: 503,
                ack,
                flags: 0x18,
                payload: b"xy",
            });
            assert_eq!(tcp.buffered(), 4);
            assert!(tcp.push(segment(1000, 2, b"")).restarted);
            assert_eq!(tcp.buffered(), 0);
            assert_eq!(tcp.flows(), 1);
        }
        let mut tcp = Reassembler::new(Limits {
            max_flows: 0,
            ..Limits::default()
        });
        assert_eq!(tcp.limits().max_flows, 1);
        tcp.push(segment(100, 2, b""));
        tcp.push(segment(103, 0x18, b"cd"));
        let mut other = segment(200, 2, b"");
        other.key.1 = 40001;
        assert!(tcp.push(other).cleared);
        assert_eq!(tcp.buffered(), 0);
        assert_eq!(tcp.flows(), 1);
    }

    #[test]
    fn one_byte_at_a_time_has_no_accumulating_input_buffer() {
        let mut tcp = Reassembler::default();
        tcp.push(segment(0, 2, b""));
        for offset in 0..16384u32 {
            let data = [offset as u8];
            assert_eq!(
                tcp.push(segment(offset + 1, 0x18, &data)).events,
                [bytes(u64::from(offset), &data, Some(0))]
            );
            assert_eq!(tcp.buffered(), 0);
        }
        // Each pending one-byte segment is removed once when the hole fills.
        for offset in (1..=256u32).rev() {
            assert!(
                tcp.push(segment(16385 + offset, 0x18, &[offset as u8]))
                    .events
                    .is_empty()
            );
        }
        let released = tcp.push(segment(16385, 0x18, &[0]));
        assert_eq!(released.events.len(), 257);
        for (i, event) in released.events.iter().enumerate() {
            assert_eq!(
                *event,
                bytes(16384 + i as u64, &[i as u8], (i == 0).then_some(0))
            );
        }
        assert_eq!(tcp.buffered(), 0);
    }

    #[test]
    fn offset_exhaustion_is_a_gap() {
        let mut tcp = Reassembler::default();
        tcp.push(segment(100, 2, b""));
        tcp.flows.get_mut(&key()).unwrap().delivered = u64::MAX;
        assert_eq!(
            tcp.push(segment(101, 0x18, b"x")).events,
            [gap(u64::MAX, false)]
        );
        assert_eq!(tcp.buffered(), 0);
    }
}
