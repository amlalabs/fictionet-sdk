//! One direction of an observed TCP connection put back in order: the
//! reassembly the [observer](super) runs for each direction it follows.

use std::collections::BTreeMap;

use smoltcp::wire::TcpSeqNumber;

use fictionet::stdlib::layer::Source;

use super::Limits;

/// TCP's FIN flag.
pub(super) const FIN: u8 = 0x01;
/// TCP's SYN flag.
pub(super) const SYN: u8 = 0x02;
/// TCP's RST flag.
pub(super) const RST: u8 = 0x04;
/// TCP's ACK flag.
pub(super) const ACK: u8 = 0x10;

/// What one direction gives up, in order. Sequence positions are counted
/// from the first sequence number seen in the direction, without wrapping.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// The next bytes, never empty.
    Data {
        sequence: u64,
        bytes: Vec<u8>,
        source: Option<Source>,
    },
    /// The sequence positions from `sequence` on, `missing` of them, will
    /// never be delivered.
    Gap { sequence: u64, missing: u64 },
    /// The sender's FIN, reached after every byte before it.
    Fin,
}

/// One captured segment, as one direction sees it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Segment<'a> {
    /// The raw sequence number: of the SYN, or of the first payload byte.
    pub seq: u32,
    /// The TCP flags.
    pub flags: u8,
    /// The payload, or `None` when the capture does not hold all of it.
    pub payload: Option<&'a [u8]>,
    /// Where the payload's first byte is in the capture.
    pub source: Option<Source>,
}

/// What one segment did to its direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Pushed {
    /// The sequence number relative to the first one seen.
    pub rel_seq: u32,
    /// Every payload sequence number had been passed already.
    pub retransmission: bool,
    /// Payload or a FIN could not be kept, and nothing was skipped for it:
    /// the direction still waits for earlier bytes.
    pub dropped: bool,
    /// Payload bytes that came after the direction's end, not delivered.
    pub late: usize,
}

/// Payload held out of order, or the place of payload dropped to stay in
/// bounds (`bytes` is `None`): bytes that will never be delivered.
#[derive(Debug)]
struct Held {
    bytes: Option<Vec<u8>>,
    len: usize,
    source: Option<Source>,
}

/// The out-of-order bytes held across every direction of an observer.
#[derive(Debug)]
pub(super) struct Store {
    pub limits: Limits,
    pub held: usize,
}

impl Store {
    fn release(&mut self, bytes: usize) {
        // Keep the earlier upper bound if the count cannot go down.
        if let Some(rest) = self.held.checked_sub(bytes) {
            self.held = rest;
        }
    }
}

/// One direction's reassembly state.
///
/// In-order bytes go up at once and earlier bytes are trimmed. Bytes ahead
/// of a hole are held under [`Limits`]; a later segment at the same
/// position replaces a held one, and other overlaps keep what came first.
/// A segment that would pass a bound is dropped. If anything is held, the
/// direction then gives up waiting for the hole and skips to the first held
/// segment with a gap. Either way the dropped segment's place is kept as a
/// marker, so that when the bytes before it arrive, the direction reports
/// its bytes missing instead of waiting for them for ever.
///
/// Wire sequence comparisons wrap modulo 2^32, and incoming distances must
/// be less than 2^31. Held segments are keyed by unwrapped positions, so
/// they stay ordered across wraps. Positions use checked arithmetic: what
/// would overflow is dropped.
#[derive(Debug)]
pub(super) struct Flow {
    isn: TcpSeqNumber,
    next: Option<TcpSeqNumber>,
    /// The unwrapped position of `next`, counting the SYN, the FIN and
    /// skipped gaps.
    position: u64,
    held: BTreeMap<u64, Held>,
    held_bytes: usize,
    /// The SYN's sequence number plus one, and the end of the payload it
    /// carried, when this direction was opened by a SYN.
    opened: Option<(TcpSeqNumber, TcpSeqNumber)>,
    /// Where the sender's FIN sits, once one was seen.
    fin: Option<u64>,
    /// The position just past the furthest payload dropped to stay in
    /// bounds, marked or not: bytes known to be missing until the position
    /// passes it.
    dropped_to: u64,
    ended: bool,
}

impl Flow {
    /// A direction first seen at `seq`, with no SYN.
    pub fn midstream(seq: u32) -> Flow {
        Flow {
            isn: TcpSeqNumber::new(seq),
            next: None,
            position: 0,
            held: BTreeMap::new(),
            held_bytes: 0,
            opened: None,
            fin: None,
            dropped_to: 0,
            ended: false,
        }
    }

    /// A direction opened by a SYN at `seq` carrying `payload` bytes, if
    /// they are known.
    pub fn opened(seq: u32, payload: Option<usize>) -> Flow {
        let isn = TcpSeqNumber::new(seq);
        // Payload the capture does not hold, or too long to place, counts
        // for nothing: an ACK of the SYN alone still answers it.
        let payload = payload.filter(|len| *len <= i32::MAX as usize).unwrap_or(0);
        Flow {
            next: Some(isn + 1),
            position: 1,
            opened: Some((isn + 1, isn + 1 + payload)),
            ..Flow::midstream(seq)
        }
    }

    /// Whether a SYN at `seq` repeats the one that opened this direction.
    pub fn repeats_syn(&self, seq: u32) -> bool {
        self.opened.is_some() && self.isn == TcpSeqNumber::new(seq)
    }

    /// Whether `ack` acknowledges the SYN that opened this direction, or
    /// the payload it carried.
    pub fn acknowledged_by(&self, ack: u32) -> bool {
        let ack = TcpSeqNumber::new(ack);
        self.opened
            .is_some_and(|(syn, data)| ack == syn || ack == data)
    }

    /// `ack` relative to this direction's first sequence number.
    pub fn relative(&self, ack: u32) -> u32 {
        TcpSeqNumber::new(ack).relative_to(self.isn)
    }

    /// Whether this direction has ended.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Whether bytes of this direction are known to be missing: a hole
    /// before held bytes, a marker, dropped bytes not yet passed, or a FIN
    /// not yet reached.
    pub fn holed(&self) -> bool {
        !self.held.is_empty()
            || self.dropped_to > self.position
            || self.fin.is_some_and(|fin| fin > self.position)
    }

    /// Ends the direction, giving back what it held.
    pub fn end(&mut self, store: &mut Store) {
        store.release(self.held_bytes);
        self.held.clear();
        self.held_bytes = 0;
        self.ended = true;
    }

    /// Gives the capture's end: everything held goes up, past its holes,
    /// and the direction ends.
    pub fn finish(&mut self, store: &mut Store, out: &mut Vec<Step>) {
        let mut pushed = Pushed::default();
        while let Some((&k, _)) = self.held.first_key_value() {
            if k > self.position {
                let Some(jump) = self.jump_to(k) else {
                    break;
                };
                gap(out, self.position, jump);
                self.skip(jump);
            }
            self.drain_first(store, out, &mut pushed);
        }
        self.end(store);
    }

    /// Takes one segment. A SYN opening the direction anew is handled by
    /// whoever owns the flow, which makes a new one with
    /// [`opened`](Self::opened) before passing the SYN here.
    pub fn push(&mut self, segment: Segment<'_>, store: &mut Store, out: &mut Vec<Step>) -> Pushed {
        let Segment {
            seq,
            flags,
            payload,
            source,
        } = segment;
        let syn = flags & SYN != 0;
        let seq = TcpSeqNumber::new(seq);
        let len = payload
            .map(<[u8]>::len)
            .filter(|len| *len <= i32::MAX as usize);
        let mut pushed = Pushed {
            rel_seq: seq.relative_to(self.isn),
            retransmission: self.next.is_some_and(|next| {
                len.is_some_and(|len| len != 0 && seq <= next && next >= seq + len && !syn)
            }),
            ..Pushed::default()
        };
        let seq = if syn { seq + 1 } else { seq };
        let next = *self.next.get_or_insert(seq);
        if self.ended {
            if let Some(len) = len.filter(|len| *len != 0)
                && seq.partial_cmp(&next).is_some()
            {
                let end = seq + len;
                if end > next {
                    pushed.late = (end - next).min(len);
                }
            }
            return pushed;
        }
        // Payload that could not be kept: whether reassembly may skip to
        // what it holds, and where the dropped bytes were, if known.
        let mut overflow = false;
        let mut dropped = None;
        if let Some(bytes) = payload {
            if bytes.len() > i32::MAX as usize || seq.partial_cmp(&next).is_none() {
                overflow = true;
            } else if !bytes.is_empty() {
                if seq <= next {
                    let skip = next - seq;
                    if let Some(rest) = bytes.get(skip..).filter(|b| !b.is_empty()) {
                        let source = source.map(|s| Source {
                            offset: s.offset.saturating_add(skip),
                            ..s
                        });
                        self.deliver(rest, source, out, &mut pushed);
                    }
                } else if let Some(at) = self.position.checked_add(u64::from(seq.relative_to(next)))
                {
                    if self.fin.is_some_and(|fin| at >= fin) {
                        pushed.late = bytes.len();
                    } else if let (Some(total), Some(local)) = (
                        store.held.checked_add(bytes.len()),
                        self.held_bytes.checked_add(bytes.len()),
                    ) && total <= store.limits.buffered
                        && self.held.len() < store.limits.segments
                    {
                        store.held = total;
                        self.held_bytes = local;
                        let held = Held {
                            bytes: Some(bytes.to_vec()),
                            len: bytes.len(),
                            source,
                        };
                        if let Some(old) = self.held.insert(at, held) {
                            // A longer one's tail is dropped with it.
                            if let Some(end) = at.checked_add(old.len as u64) {
                                self.dropped_to = self.dropped_to.max(end);
                            }
                            self.forget(&old, store);
                        }
                    } else {
                        overflow = true;
                        dropped = Some((at, bytes.len()));
                        if let Some(end) = at.checked_add(bytes.len() as u64) {
                            self.dropped_to = self.dropped_to.max(end);
                        }
                    }
                } else {
                    overflow = true;
                }
            }
        }
        if flags & FIN != 0
            && let Some(len) = len
            && seq.partial_cmp(&next).is_some()
        {
            self.record_fin(seq + len, store, &mut pushed);
        }
        while let Some((&k, _)) = self.held.first_key_value() {
            if k > self.position {
                if !overflow {
                    break;
                }
                // Skip to the first held bytes. Marked places before them
                // are inside the gap.
                let Some(target) = self
                    .held
                    .iter()
                    .find(|(_, held)| held.bytes.is_some())
                    .map(|(at, _)| *at)
                else {
                    break;
                };
                let Some(jump) = self.jump_to(target) else {
                    break;
                };
                let rest = self.held.split_off(&target);
                self.held = rest;
                gap(out, self.position, jump);
                self.skip(jump);
                overflow = false;
            }
            self.drain_first(store, out, &mut pushed);
        }
        if let Some((at, len)) = dropped
            && at > self.position
            && self.held.len() < store.limits.segments
            && !self.held.contains_key(&at)
        {
            self.held.insert(
                at,
                Held {
                    bytes: None,
                    len,
                    source: None,
                },
            );
        }
        if overflow {
            pushed.dropped = true;
        }
        if self.fin == Some(self.position) {
            match self.position.checked_add(1) {
                Some(position) => {
                    self.position = position;
                    self.next = self.next.map(|n| n + 1);
                    self.end(store);
                    out.push(Step::Fin);
                }
                None => {
                    self.fin = None;
                    pushed.dropped = true;
                }
            }
        }
        pushed
    }

    /// Notes a FIN at wire sequence number `end`, the end of its segment's
    /// payload. A FIN before bytes already delivered is ignored; held bytes
    /// past it will never be delivered.
    fn record_fin(&mut self, end: TcpSeqNumber, store: &mut Store, pushed: &mut Pushed) {
        let Some(next) = self.next else {
            return;
        };
        let at = if end >= next {
            self.position.checked_add(u64::from(end.relative_to(next)))
        } else {
            self.position.checked_sub(u64::from(next.relative_to(end)))
        };
        let Some(at) = at.filter(|at| *at >= self.position) else {
            return;
        };
        if self.fin.is_some() {
            return;
        }
        self.fin = Some(at);
        let after = self.held.split_off(&at);
        for held in after.values() {
            if held.bytes.is_some() {
                pushed.late = pushed.late.saturating_add(held.len);
            }
            self.forget(held, store);
        }
    }

    /// Gives back what `held` was charged.
    fn forget(&mut self, held: &Held, store: &mut Store) {
        if held.bytes.is_some() {
            if let Some(rest) = self.held_bytes.checked_sub(held.len) {
                self.held_bytes = rest;
            }
            store.release(held.len);
        }
    }

    /// How far it is to held position `k`, if a skip can go there.
    fn jump_to(&self, k: u64) -> Option<u64> {
        k.checked_sub(self.position)
            .filter(|n| *n <= i32::MAX as u64)
    }

    /// Skips `n` sequence positions that will never be delivered.
    fn skip(&mut self, n: u64) {
        self.position += n;
        self.next = self.next.map(|next| next + n as usize);
    }

    /// Takes the first held entry, which starts at or before the position,
    /// and gives up what of it is past the position.
    fn drain_first(&mut self, store: &mut Store, out: &mut Vec<Step>, pushed: &mut Pushed) {
        let Some((k, held)) = self.held.pop_first() else {
            return;
        };
        self.forget(&held, store);
        let Some(skip) = self
            .position
            .checked_sub(k)
            .and_then(|n| usize::try_from(n).ok())
        else {
            return;
        };
        match held.bytes {
            Some(bytes) => {
                if let Some(tail) = bytes.get(skip..).filter(|b| !b.is_empty()) {
                    let source = held.source.map(|s| Source {
                        offset: s.offset.saturating_add(skip),
                        ..s
                    });
                    self.deliver(tail, source, out, pushed);
                }
            }
            None => {
                if let Some(missing) = held.len.checked_sub(skip).filter(|n| *n != 0) {
                    let missing = missing as u64;
                    if self.position.checked_add(missing).is_some() {
                        gap(out, self.position, missing);
                        self.skip(missing);
                    }
                }
            }
        }
    }

    /// Delivers in-order `bytes` at the position, up to a FIN, or notes
    /// them dropped when the position would overflow.
    fn deliver(
        &mut self,
        bytes: &[u8],
        source: Option<Source>,
        out: &mut Vec<Step>,
        pushed: &mut Pushed,
    ) {
        let room = self
            .fin
            .map_or(bytes.len(), |fin| {
                usize::try_from(fin.saturating_sub(self.position)).unwrap_or(usize::MAX)
            })
            .min(bytes.len());
        pushed.late = pushed.late.saturating_add(bytes.len() - room);
        let bytes = &bytes[..room];
        if bytes.is_empty() {
            return;
        }
        let Some(position) = self.position.checked_add(bytes.len() as u64) else {
            pushed.dropped = true;
            return;
        };
        let sequence = self.position;
        self.position = position;
        self.next = self.next.map(|next| next + bytes.len());
        out.push(Step::Data {
            sequence,
            bytes: bytes.to_vec(),
            source,
        });
    }

    #[cfg(test)]
    pub(super) fn position(&self) -> u64 {
        self.position
    }

    #[cfg(test)]
    pub(super) fn set_position(&mut self, position: u64, next: u32) {
        self.position = position;
        self.next = Some(TcpSeqNumber::new(next));
    }

    #[cfg(test)]
    pub(super) fn next(&self) -> Option<u32> {
        self.next.map(TcpSeqNumber::to_bits)
    }

    #[cfg(test)]
    pub(super) fn held_segments(&self) -> usize {
        self.held.iter().filter(|(_, h)| h.bytes.is_some()).count()
    }
}

/// Adds a gap of `missing` positions at `sequence`, joining it to a gap
/// just before it.
fn gap(out: &mut Vec<Step>, sequence: u64, missing: u64) {
    if let Some(Step::Gap {
        sequence: start,
        missing: before,
    }) = out.last_mut()
        && start.checked_add(*before) == Some(sequence)
        && let Some(total) = before.checked_add(missing)
    {
        *before = total;
        return;
    }
    out.push(Step::Gap { sequence, missing });
}
