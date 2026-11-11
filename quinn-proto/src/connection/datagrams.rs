use std::collections::VecDeque;

use bytes::Bytes;
use fictionet_buf::{Budget, Charge, Chunk};
use thiserror::Error;
use tracing::trace;

use super::{Connection, Event};
use crate::{
    frame::{Datagram, FrameStruct},
    TransportError,
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        let Some(max_buffer_payload) = send_buffer_size.checked_sub(size_of::<Datagram>()) else {
            return Err(SendDatagramError::TooLarge);
        };
        if data.len() > Ord::min(max, max_buffer_payload) {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            self.conn.datagrams.chunk.0 = None;
            self.conn
                .datagrams
                .make_space_for(data.len(), send_buffer_size);
        } else if self.has_pending_chunk()
            || !self
                .conn
                .datagrams
                .has_send_buffer_space(data.len(), send_buffer_size)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing.push_back(Datagram { data });
        Ok(())
    }

    /// Offer a charged datagram without allocating a queue descriptor.
    ///
    /// One chunk can wait for transmission at a time. Returns `Ok(false)`
    /// without taking or changing `data` when storage or a previous send
    /// prevents admission. Other errors also preserve `data`. A successful
    /// offer retains the backing until packet construction or a local drop;
    /// datagrams are never retained for retransmission. Do not mix this API
    /// with `send(..., true)` if local eviction is undesirable.
    /// Sending requires the peer's receive support, independently of whether
    /// this endpoint advertises support for receiving datagrams itself.
    pub fn send_chunk(
        &mut self,
        data: &mut Chunk,
        budget: &Budget,
    ) -> Result<bool, SendDatagramError> {
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max || data.len() > self.conn.config.datagram_send_buffer_size {
            return Err(SendDatagramError::TooLarge);
        }
        if !self.conn.datagrams.outgoing.is_empty() || self.has_pending_chunk() {
            self.conn.datagrams.send_blocked = true;
            return Ok(false);
        }
        Ok(self.conn.datagrams.chunk.admit(data, budget))
    }

    /// Whether the chunk accepted by `send_chunk` is still waiting for
    /// packet construction. Once false, the caller still has to retire any
    /// packet carrying it at its lower transport before reporting completion.
    pub fn has_pending_chunk(&self) -> bool {
        self.conn.datagrams.chunk.0.is_some()
    }

    /// Cancel the pending chunk, releasing its backing without transmission.
    pub fn discard_chunk(&mut self) {
        self.conn.datagrams.chunk.0 = None;
    }

    /// Charge receive storage to this budget, including any storage already held.
    /// A refusal leaves the previous budget and queued messages unchanged.
    /// Set this before processing application packets to pay before allocation.
    pub fn receive_budget(&mut self, budget: &Budget) -> bool {
        self.conn.datagrams.incoming.set_budget(budget)
    }

    /// Copy the next received datagram to charged storage before removing it.
    /// A budget refusal leaves the queue unchanged. Empty datagrams return
    /// `Some` of an empty chunk. The receive arena remains reserved for reuse.
    pub fn recv_chunk(&mut self, budget: &Budget) -> Option<Chunk> {
        self.conn.datagrams.incoming.recv_chunk(budget)
    }

    /// Discard queued datagrams that no longer fit the active path, waking blocked senders.
    pub(super) fn drop_oversized(&mut self) {
        let Some(max_datagram_size) = self.max_size() else {
            return;
        };
        if !self.conn.datagrams.drop_oversized(max_datagram_size)
            || !self.conn.datagrams.send_blocked
        {
            return;
        }

        self.conn.datagrams.send_blocked = false;
        self.conn.events.push_back(Event::DatagramsUnblocked);
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if the peer does not allow a datagram with a length field.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
            - Datagram::SIZE_BOUND;
        let limit = self.conn.peer_params.max_datagram_frame_size?.into_inner();
        // The encoder always includes a length, even for an empty payload.
        if limit < 2 {
            return None;
        }
        let limit = limit.saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        if self.has_pending_chunk() {
            return 0;
        }
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing.memory_used())
            .saturating_sub(size_of::<Datagram>())
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    incoming: ReceivedDatagrams,
    pub(super) outgoing: DatagramBuffer,
    pub(super) send_blocked: bool,
    chunk: DatagramSlot,
}

/// The descriptor is part of the connection itself; only the payload can
/// allocate. Keeping one slot bounds metadata independently of empty sends.
#[derive(Default)]
struct DatagramSlot(Option<Chunk>);

impl DatagramSlot {
    fn admit(&mut self, data: &mut Chunk, budget: &Budget) -> bool {
        if self.0.is_some() || (!data.is_paid_by(budget) && !data.repay(budget)) {
            return false;
        }
        self.0 = Some(std::mem::take(data));
        true
    }
}

impl DatagramState {
    pub(super) fn new(budget: Option<&Budget>) -> Self {
        Self {
            incoming: ReceivedDatagrams {
                charge: budget.map(Charge::nothing),
                ..ReceivedDatagrams::default()
            },
            ..Self::default()
        }
    }

    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        encoded_size: usize,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = receive_window(encoded_size, *window)?;

        Ok(self.incoming.push(&datagram.data, window))
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let Some(prev) = self.outgoing.pop_front() else {
                break;
            };
            trace!(len = prev.data.len(), "dropping outgoing datagram");
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self
            .outgoing
            .memory_used()
            .checked_add(datagram_len)
            .and_then(|total| total.checked_add(size_of::<Datagram>()))
        else {
            return false;
        };

        total <= send_buffer_size
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        if self
            .chunk
            .0
            .as_ref()
            .is_some_and(|data| data.len() > max_payload)
        {
            self.chunk.0 = None;
            dropped_any = true;
        }
        self.outgoing.queue.retain(|datagram| {
            let result = datagram.data.len() <= max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                self.outgoing.payload_bytes -= datagram.data.len();
                dropped_any = true;
            }
            result
        });
        dropped_any
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(&mut self, buf: &mut Vec<u8>, max_size: usize) -> bool {
        if let Some(chunk) = &self.chunk.0 {
            if Datagram::size_for(chunk.len(), true) > max_size.saturating_sub(buf.len()) {
                return false;
            }
            Datagram::encode_data(chunk, true, buf);
            self.chunk.0 = None;
            return true;
        }
        let datagram = match self.outgoing.pop_front() {
            Some(x) => x,
            None => return false,
        };

        if buf.len() + datagram.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        trace!(len = datagram.data.len(), "DATAGRAM");
        datagram.encode(true, buf);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        self.incoming.recv()
    }

    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.chunk
            .0
            .as_ref()
            .is_some_and(|chunk| Datagram::size_for(chunk.len(), true) <= max_size)
            || self.outgoing.can_send_1rtt(max_size)
    }

    pub(super) fn is_send_empty(&self) -> bool {
        self.chunk.0.is_none() && self.outgoing.is_empty()
    }
}

fn receive_window(encoded_size: usize, window: Option<usize>) -> Result<usize, TransportError> {
    let Some(window) = window.filter(|window| *window != 0) else {
        return Err(TransportError::PROTOCOL_VIOLATION(
            "unexpected DATAGRAM frame",
        ));
    };
    // Transport parameters cap the advertised frame size at this value.
    if encoded_size > window.min(u16::MAX as usize) {
        return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
    }
    Ok(window)
}

#[cfg(kani)]
#[path = "../../../verification/quic/kani/datagrams.rs"]
mod proofs;

/// A reusable byte ring owns the payloads instead of retaining arbitrarily
/// large packet backings. Lengths live in the ring, so empty datagrams also
/// consume bounded space and no descriptor queue grows on receipt.
#[derive(Default)]
struct ReceivedDatagrams {
    bytes: VecDeque<u8>,
    count: usize,
    payload: usize,
    charge: Option<Charge>,
}

impl ReceivedDatagrams {
    fn set_budget(&mut self, budget: &Budget) -> bool {
        if let Some(charge) = &mut self.charge {
            return charge.transfer(budget);
        }
        let Some(charge) = budget.charge(self.bytes.capacity()) else {
            return false;
        };
        self.charge = Some(charge);
        true
    }

    fn reserve(&mut self, window: usize) -> bool {
        if window > isize::MAX as usize {
            return false;
        }
        let capacity = self.bytes.capacity();
        if window <= capacity {
            return true;
        }
        // Reallocation may hold both buffers at once. Keep their combined
        // reservation until the old allocation is gone.
        let Some(transient) = capacity.checked_add(window) else {
            return false;
        };
        if let Some(charge) = &mut self.charge {
            if !charge.grow_to(transient) {
                return false;
            }
        }
        self.bytes.reserve_exact(window - self.bytes.len());
        if let Some(charge) = &mut self.charge {
            charge.shrink_to(self.bytes.capacity());
        }
        true
    }

    fn push(&mut self, data: &[u8], window: usize) -> bool {
        // Preserve the configured per-message allowance. The ring uses
        // only a length word of it; the remaining room is conservative.
        let Some(size) = data.len().checked_add(size_of::<Datagram>()) else {
            return false;
        };
        if size > window || !self.reserve(window) {
            return false;
        }
        let was_empty = self.is_empty();
        while self.memory_used() > window - size {
            self.discard();
        }
        self.bytes.extend(data.len().to_le_bytes());
        self.bytes.extend(data.iter().copied());
        self.count += 1;
        self.payload += data.len();
        was_empty
    }

    fn front_len(&self) -> Option<usize> {
        if self.is_empty() {
            return None;
        }
        let mut length = [0; size_of::<usize>()];
        for (out, byte) in length.iter_mut().zip(&self.bytes) {
            *out = *byte;
        }
        Some(usize::from_le_bytes(length))
    }

    fn front(&self, length: usize) -> impl Iterator<Item = u8> + '_ {
        self.bytes
            .iter()
            .skip(size_of::<usize>())
            .take(length)
            .copied()
    }

    fn discard(&mut self) {
        let length = self.front_len().expect("a queued datagram");
        self.bytes.drain(..size_of::<usize>() + length);
        self.count -= 1;
        self.payload -= length;
    }

    fn recv(&mut self) -> Option<Bytes> {
        let length = self.front_len()?;
        let data: Vec<u8> = self.front(length).collect();
        self.discard();
        Some(Bytes::from(data))
    }

    fn recv_chunk(&mut self, budget: &Budget) -> Option<Chunk> {
        let length = self.front_len()?;
        let mut chunk = Chunk::block(budget, 0, length)?;
        chunk.fill(|out| {
            for (out, byte) in out.iter_mut().zip(self.front(length)) {
                *out = byte;
            }
            length
        })?;
        self.discard();
        Some(chunk)
    }

    fn memory_used(&self) -> usize {
        self.payload + self.count * size_of::<Datagram>()
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Default)]
pub(super) struct DatagramBuffer {
    queue: VecDeque<Datagram>,
    payload_bytes: usize,
}

impl DatagramBuffer {
    fn push_back(&mut self, datagram: Datagram) {
        self.payload_bytes += datagram.data.len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<Datagram> {
        let datagram = self.queue.pop_front()?;
        self.payload_bytes -= datagram.data.len();
        Some(datagram)
    }

    fn push_front(&mut self, datagram: Datagram) {
        self.payload_bytes += datagram.data.len();
        self.queue.push_front(datagram);
    }

    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.queue.len() * size_of::<Datagram>())
    }

    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.queue.front().is_some_and(|x| x.size(true) <= max_size)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_ring_reuses_paid_storage_through_wraparound_and_eviction() {
        use crate::cost::{Charged, Costs, Linear};
        let window = 2 * size_of::<Datagram>() + 8;
        let budget = Budget::new(window);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        let mut costs = Costs::new("QUIC receive ring");
        for turn in 0..100u8 {
            let data = [turn; 4];
            costs.step(
                data.len(),
                window,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: if turn == 0 { window } else { 0 },
                },
                || {
                    incoming.push(&data, window);
                    Charged {
                        value: (),
                        charged: 0,
                    }
                },
            );
            assert_eq!(budget.used(), window);
            assert!(incoming.bytes.len() <= window);
            assert_eq!(incoming.count, usize::from(turn != 0) + 1);
        }
        assert_eq!(incoming.recv().unwrap(), &[98; 4][..]);
        assert_eq!(incoming.recv().unwrap(), &[99; 4][..]);
        for _ in 0..100 {
            incoming.push(&[], window);
            assert_eq!(incoming.recv().unwrap(), &[][..]);
        }
        assert!(incoming.is_empty());
        assert_eq!(budget.used(), window);
        drop(incoming);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn receive_ring_refuses_before_allocating_or_evicting() {
        use crate::cost::{Charged, Costs, Linear};
        let window = size_of::<Datagram>() + 4;
        let budget = Budget::new(window);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        let held = budget.charge(window).unwrap();
        let mut costs = Costs::new("QUIC receive refusal");
        let zero = Linear {
            num: 0,
            den: 1,
            fixed: 0,
        };
        assert!(!costs.step(4, 0, zero, || Charged {
            value: incoming.push(b"kept", window),
            charged: 0,
        }));
        assert!(incoming.is_empty());
        assert_eq!(incoming.bytes.capacity(), 0);
        drop(held);
        assert!(incoming.push(b"kept", window));
        let pointer = incoming.bytes.as_slices().0.as_ptr();
        assert!(!incoming.push(b"next", window + 1));
        assert_eq!(incoming.bytes.as_slices().0.as_ptr(), pointer);
        assert!(!incoming.set_budget(&Budget::new(window - 1)));
        assert!(incoming.recv_chunk(&Budget::new(0)).is_none());
        assert_eq!(incoming.recv().unwrap(), &b"kept"[..]);
        assert_eq!(budget.used(), window);
    }

    #[test]
    fn receive_ring_pays_for_both_allocations_during_growth() {
        use crate::cost::{Charged, Costs, Linear};
        let first = size_of::<Datagram>() + 4;
        let second = first * 2;
        let budget = Budget::new(first + second);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        let mut costs = Costs::new("QUIC receive growth");
        for window in [first, second] {
            let before = budget.used();
            costs.step(
                4,
                before + window,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: window,
                },
                || {
                    incoming.push(b"held", window);
                    Charged {
                        value: (),
                        charged: 0,
                    }
                },
            );
            assert_eq!(budget.used(), window);
        }
        let to = Budget::new(second);
        assert!(incoming.set_budget(&to));
        assert_eq!(budget.used(), 0);
        assert_eq!(to.used(), second);
        assert_eq!(incoming.recv().unwrap(), &b"held"[..]);
        assert_eq!(incoming.recv().unwrap(), &b"held"[..]);
    }

    #[test]
    fn receive_ring_rejects_unrepresentable_capacity_without_charging() {
        let budget = Budget::new(usize::MAX);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        assert!(!incoming.push(b"data", usize::MAX));
        assert_eq!(incoming.bytes.capacity(), 0);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn receive_does_not_retain_the_packet_backing() {
        struct Packet(std::sync::Arc<std::sync::atomic::AtomicBool>, [u8; 4096]);
        impl AsRef<[u8]> for Packet {
            fn as_ref(&self) -> &[u8] {
                &self.1
            }
        }
        impl Drop for Packet {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let freed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let packet = Bytes::from_owner(Packet(freed.clone(), [42; 4096]));
        let data = packet.slice(100..104);
        drop(packet);
        let mut state = DatagramState::default();
        assert!(state.received(Datagram { data }, 6, &Some(64)).unwrap());
        assert!(freed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(state.recv().unwrap(), &[42; 4][..]);
    }

    #[test]
    fn charged_datagrams_hold_backings_until_encoded_or_dropped() {
        use crate::cost::{Charged, Costs, Linear};
        let mut costs = Costs::new("QUIC datagram slot");
        let linear = Linear {
            num: 0,
            den: 1,
            fixed: 0,
        };
        for (size, capacity) in [(0, 0), (4, 4), (4, 8)] {
            let budget = Budget::new(capacity);
            let mut source = Chunk::block(&budget, 0, capacity).unwrap();
            source.extend_within(&b"data"[..size]).unwrap();
            let pointer = source.as_ptr();
            let mut state = DatagramState::default();
            let mut wire = Vec::with_capacity(32);
            let accepted = costs.step(size, 0, linear, || Charged {
                value: state.chunk.admit(&mut source, &budget),
                charged: 0,
            });
            assert!(accepted);
            assert!(source.is_empty());
            assert_eq!(state.chunk.0.as_ref().unwrap().as_ptr(), pointer);
            assert_eq!(budget.used(), capacity);
            assert!(!state.write(&mut wire, 1));
            assert!(wire.is_empty());
            assert_eq!(budget.used(), capacity);
            assert!(state.write(&mut wire, 32));
            assert_eq!(budget.used(), 0);
            assert!(!state.write(&mut wire, 32));
            let (frame, _) = crate::frame::Iter::new(Bytes::from(wire))
                .unwrap()
                .next_with_size()
                .unwrap();
            let crate::frame::Frame::Datagram(datagram) = frame.unwrap() else {
                panic!("datagram")
            };
            assert_eq!(datagram.data, &b"data"[..size]);
        }
        let budget = Budget::new(4);
        let unavailable = Budget::new(0);
        let mut source = Chunk::copy_of(&budget, b"held").unwrap();
        let pointer = source.as_ptr();
        let mut slot = DatagramSlot::default();
        let accepted = costs.step(4, 0, linear, || Charged {
            value: slot.admit(&mut source, &unavailable),
            charged: 0,
        });
        assert!(!accepted);
        assert_eq!(source.as_ptr(), pointer);
        assert_eq!(&*source, b"held");
        assert_eq!(budget.used(), 4);
        assert_eq!(unavailable.used(), 0);
        assert!(slot.0.is_none());
    }

    #[test]
    fn charged_datagram_slot_refuses_replacement_and_releases_on_path_change() {
        let budget = Budget::new(8);
        let mut first = Chunk::copy_of(&budget, b"held").unwrap();
        let mut second = Chunk::copy_of(&budget, b"next").unwrap();
        let pointer = second.as_ptr();
        let mut state = DatagramState::default();
        assert!(state.chunk.admit(&mut first, &budget));
        assert!(!state.chunk.admit(&mut second, &budget));
        assert_eq!(second.as_ptr(), pointer);
        assert!(!state.is_send_empty());
        assert!(state.can_send_1rtt(6));
        assert!(!state.can_send_1rtt(5));
        assert!(!state.drop_oversized(4));
        assert_eq!(budget.used(), 8);
        assert!(state.drop_oversized(3));
        assert!(state.is_send_empty());
        assert_eq!(budget.used(), 4);
        assert_eq!(&*second, b"next");
    }

    #[test]
    fn receive_checks_wire_size_before_storage() {
        use crate::frame::{Frame, Iter};
        for wire in [
            &[0x30, 42][..],
            &[0x31, 1, 42][..],
            &[0x31, 0x40, 1, 42][..],
            &[0x40, 0x31, 0x40, 1, 42][..],
        ] {
            let mut frames = Iter::new(Bytes::copy_from_slice(wire)).unwrap();
            let (frame, encoded_size) = frames.next_with_size().unwrap();
            assert_eq!(encoded_size, wire.len());
            assert!(frames.next().is_none());
            let Frame::Datagram(datagram) = frame.unwrap() else {
                panic!("datagram frame")
            };
            for window in [None, Some(0), Some(wire.len() - 1)] {
                let mut state = DatagramState::default();
                assert!(state
                    .received(datagram.clone(), encoded_size, &window)
                    .is_err());
                assert!(state.incoming.is_empty());
            }
            let mut state = DatagramState::default();
            assert!(!state
                .received(datagram.clone(), encoded_size, &Some(wire.len()))
                .unwrap());
            assert!(state.incoming.is_empty());
            assert!(state.received(datagram, encoded_size, &Some(128)).unwrap());
            assert_eq!(state.recv().unwrap(), &[42][..]);
        }
    }

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 7]),
        });
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 2]),
        });
        state.make_space_for(4, 10 + 2 * size_of::<Datagram>());

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].data.len(), 2);
        assert_eq!(state.outgoing.payload_bytes, 2);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.outgoing.queue.push_back(Datagram {
            data: Bytes::from_static(&[0]),
        });
        state.outgoing.payload_bytes = usize::MAX - 1;

        state.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing.payload_bytes, usize::MAX - 2);
    }

    #[test]
    fn make_space_for_accounts_for_empty_datagram_metadata() {
        let mut state = DatagramState::default();
        for _ in 0..2 {
            state.outgoing.push_back(Datagram { data: Bytes::new() });
        }
        let window = 2 * size_of::<Datagram>();

        assert!(!state.has_send_buffer_space(0, window));
        state.make_space_for(0, window);
        assert_eq!(state.outgoing.queue.len(), 1);
        assert!(state.has_send_buffer_space(0, window));
        state.outgoing.push_back(Datagram { data: Bytes::new() });
        assert_eq!(state.outgoing.memory_used(), window);
    }

    #[test]
    fn send_buffer_space_handles_metadata_overflow() {
        assert!(!DatagramState::default().has_send_buffer_space(usize::MAX, usize::MAX));
    }

    #[test]
    fn drop_oversized_keeps_datagrams_at_limit() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 10]),
        });
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 11]),
        });

        assert!(state.drop_oversized(10));

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].data.len(), 10);
        assert_eq!(state.outgoing.payload_bytes, 10);
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
