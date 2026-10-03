//! Following TCP connections across packets: relative sequence numbers,
//! retransmissions, and the byte streams that application protocols are
//! decoded from.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use super::app::{Conversation, Place};
use super::decode::Decoded;
use crate::watch::KeyLine;

/// One direction of a TCP connection: from `src` to `dst`.
pub(crate) type FlowKey = (IpAddr, u16, IpAddr, u16);

/// What a segment's header says, relative to its connection.
pub(crate) struct Segment {
    pub(crate) key: FlowKey,
    pub(crate) rel_seq: u32,
    pub(crate) rel_ack: u32,
    pub(crate) retransmission: bool,
}

/// Bytes held for all directions together while earlier segments are
/// missing. Past that, the stream skips ahead over the gap.
const MAX_HELD: usize = 8 << 20;

struct Flow {
    /// The first sequence number seen, so numbers can be shown from 0.
    isn: u32,
    /// The next sequence number expected in the stream, once known.
    next: Option<u32>,
    /// Segments that came before the ones ahead of them, by sequence number
    /// less `isn`, so that they sort in stream order across the point where
    /// sequence numbers wrap.
    held: BTreeMap<u32, Vec<u8>>,
    held_bytes: usize,
    /// Bytes delivered to the application so far.
    delivered: u64,
    /// The flow started with a SYN that was seen: the sequence numbers a
    /// SYN-ACK may acknowledge, the SYN alone or the SYN and its data (TCP
    /// Fast Open, RFC 7413).
    opened: Option<(u32, u32)>,
}

/// Every TCP connection a link has carried.
#[derive(Default)]
pub(crate) struct Streams {
    flows: HashMap<FlowKey, Flow>,
    /// Each connection's decoders, under the key both its directions
    /// share (see [`conversation_key`]).
    conversations: HashMap<FlowKey, Conversation>,
    /// Bytes held in every flow's `held`.
    held: usize,
}

/// How many directions of connections are followed at once. Past that, the
/// state of all of them is forgotten and decoding starts again.
const MAX_FLOWS: usize = 512;

/// The two directions of a connection share one key: the lower end first.
/// The flag says whether `key` itself is the reverse of that.
fn conversation_key(key: FlowKey) -> (FlowKey, bool) {
    let (a, b) = ((key.0, key.1), (key.2, key.3));
    if a <= b { ((key.0, key.1, key.2, key.3), false) } else { ((key.2, key.3, key.0, key.1), true) }
}

/// Whether sequence number `a` is before `b`, with wrapping.
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

impl Streams {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn segment(
        &mut self,
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        len: usize,
    ) -> Segment {
        let key = (src, sport, dst, dport);
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
            self.flows.clear();
            self.conversations.clear();
            self.held = 0;
        }
        let syn = flags & 0x02 != 0;
        let back = (dst, dport, src, sport);
        if syn {
            // A SYN starts a new connection on these ports, so its decoders
            // and the other direction start over. So does a SYN-ACK, unless
            // it answers the SYN seen.
            let answers = flags & 0x10 != 0 && self.flows.get(&back).and_then(|b| b.opened).is_some_and(|(a, b)| ack == a || ack == b);
            if !answers {
                self.conversations.remove(&conversation_key(key).0);
                if let Some(b) = self.flows.remove(&back) {
                    self.held -= b.held_bytes;
                }
            }
        }
        let fresh = || Flow { isn: seq, next: None, held: BTreeMap::new(), held_bytes: 0, delivered: 0, opened: None };
        let flow = self.flows.entry(key).or_insert_with(fresh);
        if syn {
            self.held -= flow.held_bytes;
            *flow = fresh();
            flow.next = Some(seq.wrapping_add(1));
            flow.opened = Some((seq.wrapping_add(1), seq.wrapping_add(1).wrapping_add(len as u32)));
        }
        let rel_seq = seq.wrapping_sub(flow.isn);
        let retransmission = match flow.next {
            Some(next) => len > 0 && !before(next, seq.wrapping_add(len as u32)) && !syn,
            None => false,
        };
        let rel_ack = match self.flows.get(&back) {
            Some(b) if flags & 0x10 != 0 => ack.wrapping_sub(b.isn),
            _ => 0,
        };
        Segment { key, rel_seq, rel_ack, retransmission }
    }

    /// Feeds a segment's payload, `p[range]` with sequence number `seq`, to
    /// the connection's application decoder, in stream order.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn payload(
        &mut self,
        key: FlowKey,
        seq: u32,
        fin: bool,
        p: &[u8],
        range: (usize, usize),
        d: &mut Decoded,
        keys: &[KeyLine],
    ) {
        let Some(flow) = self.flows.get_mut(&key) else { return };
        let data = &p[range.0..range.1];
        let next = *flow.next.get_or_insert(seq);
        let mut chunks: Vec<(u64, Vec<u8>, Option<usize>)> = Vec::new();
        let mut gap = false;
        if !data.is_empty() {
            if seq == next || before(seq, next) {
                // In order, or overlapping what came before: take the new part.
                let skip = next.wrapping_sub(seq) as usize;
                if skip < data.len() {
                    let start = flow.delivered;
                    chunks.push((start, data[skip..].to_vec(), Some(range.0 + skip)));
                    flow.delivered += (data.len() - skip) as u64;
                    flow.next = Some(seq.wrapping_add(data.len() as u32));
                }
            } else if self.held + data.len() <= MAX_HELD && flow.held.len() < 256 {
                flow.held_bytes += data.len();
                self.held += data.len();
                if let Some(old) = flow.held.insert(seq.wrapping_sub(flow.isn), data.to_vec()) {
                    flow.held_bytes -= old.len();
                    self.held -= old.len();
                }
            } else {
                gap = true;
            }
        }
        // Segments held for this one may follow it now. After a gap, the
        // stream goes on from the first segment held.
        loop {
            let next = flow.next.unwrap_or(seq);
            let Some((&k, _)) = flow.held.iter().next() else { break };
            let s = k.wrapping_add(flow.isn);
            if before(next, s) && !gap {
                break;
            }
            let bytes = flow.held.remove(&k).unwrap();
            flow.held_bytes -= bytes.len();
            self.held -= bytes.len();
            if gap && before(next, s) {
                flow.next = Some(s);
                gap = false;
                chunks.push((flow.delivered, Vec::new(), None));
            }
            let next = flow.next.unwrap_or(s);
            let skip = next.wrapping_sub(s) as usize;
            if !before(s, next) || skip < bytes.len() {
                let skip = if before(s, next) { skip } else { 0 };
                chunks.push((flow.delivered, bytes[skip..].to_vec(), None));
                flow.delivered += (bytes.len() - skip) as u64;
                flow.next = Some(s.wrapping_add(bytes.len() as u32));
            }
        }
        // A FIN takes one sequence number, once, when everything before it
        // has arrived; not when it comes early, nor when it is sent again.
        if fin && flow.next == Some(seq.wrapping_add(data.len() as u32)) {
            flow.next = flow.next.map(|n| n.wrapping_add(1));
        }
        if gap {
            d.tag("gap");
        }
        if chunks.is_empty() {
            return;
        }
        let (ckey, reversed) = conversation_key(key);
        let conversation = self.conversations.entry(ckey).or_insert_with(|| Conversation::new(ckey.1, ckey.3));
        let layers = d.layers.len() + d.cut;
        for (start, bytes, at) in chunks {
            if bytes.is_empty() {
                conversation.lost(reversed);
                continue;
            }
            let place = Place { stream_start: start, buf: 0, offset: at, len: bytes.len() };
            conversation.data(reversed, &bytes, place, d, keys);
        }
        if d.layers.len() + d.cut == layers && conversation.waiting(reversed) {
            d.info.push_str(" [part of a longer message]");
        }
    }
}
