#[cfg(not(target_arch = "wasm32"))]
use crate::stdlib::layer::ChargedDeque;
#[cfg(not(target_arch = "wasm32"))]
use crate::{Budget, Charge, Chunk};
use crate::{PACKET_COST, Packet};

/// A packet FIFO, whose memory a [`Budget`] pays for: each packet's own
/// (its backing's capacity and record), charged when it is queued and
/// given back when it is taken out, and the queue's places, charged as
/// the queue grows ([`ChargedDeque`]) and given back when it empties. A
/// packet the budget has no room for is refused whole; what to do with it
/// is the caller's. A queue with no limit counts against a budget that
/// never refuses.
#[cfg(not(target_arch = "wasm32"))]
pub struct PacketQueue {
    /// Each packet, with its charge.
    packets: ChargedDeque<(Packet, Charge)>,
    budget: Budget,
}

/// What a queued packet costs on a limited cable: the memory it keeps
/// alive and its place in the cable's queue ([`PACKET_COST`]). `None`
/// when that is past what a count can hold, which no budget has room for.
pub(crate) fn cost(packet: &Packet) -> Option<usize> {
    packet.chunk().capacity().checked_add(PACKET_COST)
}

/// What a packet keeps alive apart from its place in a queue: its
/// backing's capacity and the backing's record ([`Chunk::RECORD_BYTES`]).
/// `None` past what a count can hold.
#[cfg(not(target_arch = "wasm32"))]
fn held(packet: &Packet) -> Option<usize> {
    packet.chunk().capacity().checked_add(Chunk::RECORD_BYTES)
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for PacketQueue {
    fn default() -> Self {
        PacketQueue::new(None)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PacketQueue {
    /// A queue whose packets and places hold at most `limit` bytes, or
    /// with no limit.
    pub fn new(limit: Option<usize>) -> Self {
        PacketQueue::on(&limit.map_or_else(Budget::unlimited, Budget::new))
    }

    /// A queue whose packets and places count against `budget`, beside
    /// whatever else it pays for.
    pub fn on(budget: &Budget) -> Self {
        PacketQueue {
            packets: ChargedDeque::new(budget, usize::MAX),
            budget: budget.clone(),
        }
    }

    /// Queues `packet`, charging the budget first for the packet and then
    /// for a place, if the queue must grow for one. Returns the queued
    /// packet, or the packet itself, with nothing charged, if the budget
    /// has no room for both.
    pub fn try_push(&mut self, packet: Packet) -> Result<&Packet, Packet> {
        let Some(charge) = held(&packet).and_then(|held| self.budget.charge(held)) else {
            return Err(packet);
        };
        let Some(place) = self.packets.place() else {
            return Err(packet);
        };
        place.push_back((packet, charge));
        Ok(&self.packets.iter().last().expect("just queued").0)
    }

    /// Takes out the oldest packet and gives back its charge. An emptied
    /// queue gives back its places too.
    pub fn pop(&mut self) -> Option<Packet> {
        let (packet, _) = self.packets.pop_front()?;
        if self.packets.is_empty() {
            self.packets.shrink_to(0);
        }
        Some(packet)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PacketQueue {
    /// What the queued packets hold apart from their places: each one's
    /// backing's capacity and record.
    pub fn bytes(&self) -> usize {
        self.packets
            .iter()
            .map(|(packet, _)| held(packet).expect("a queued packet was charged"))
            .sum()
    }

    /// What the queue's places are charged.
    pub fn places(&self) -> usize {
        self.packets.charged()
    }

    /// Borrows the oldest packet without giving back its charge.
    pub fn front(&self) -> Option<&Packet> {
        self.packets.front().map(|(packet, _)| packet)
    }

    /// The number of queued packets.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether no packets are queued.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Drops every queued packet and gives back their charges and the
    /// queue's places.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.packets.shrink_to(0);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// A queue's place, as its deque charges it.
    const PLACE: usize = size_of::<(Packet, Charge)>();

    /// What one packet of `len` exact bytes holds besides its place.
    fn holds(len: usize) -> usize {
        len + Chunk::RECORD_BYTES
    }

    #[test]
    fn retained_capacity_is_admitted_and_released() {
        let mut bytes = Vec::with_capacity(4096);
        bytes.push(1);
        let capacity = bytes.capacity();
        let mut queue = PacketQueue::new(Some(capacity));
        let packet = queue.try_push(Packet::new(bytes)).unwrap_err();
        assert!(queue.is_empty());
        let budget = Budget::new(capacity + Chunk::RECORD_BYTES + PLACE);
        let mut queue = PacketQueue::on(&budget);
        assert!(queue.try_push(packet).is_ok());
        assert_eq!(queue.bytes(), capacity + Chunk::RECORD_BYTES);
        assert_eq!(budget.used(), queue.bytes() + queue.places());
        assert_eq!(queue.pop().unwrap().chunk().capacity(), capacity);
        assert_eq!((queue.bytes(), queue.places(), budget.used()), (0, 0, 0));
    }

    #[test]
    fn a_shared_budget_limits_the_queue_with_everything_else_it_pays_for() {
        // Room for two packets and the first four places.
        let budget = Budget::new(2 * holds(1) + 4 * PLACE);
        let mut queue = PacketQueue::on(&budget);
        assert!(queue.try_push(Packet::new(vec![1])).is_ok());
        let places = queue.places();
        let other = budget.charge(budget.limit() - budget.used()).unwrap();
        let refused = Packet::new(vec![2]);
        assert_eq!(queue.try_push(refused.clone()), Err(refused.clone()));
        assert_eq!(budget.used(), budget.limit());
        assert_eq!(queue.places(), places, "a refusal grows nothing");
        drop(other);
        assert!(queue.try_push(refused).is_ok());
        queue.clear();
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exact_capacity_rejection_and_drain_preserve_order_and_charges() {
        // Room for two packets and the first four places, not a third
        // packet.
        let limit = holds(1) + holds(2) + 4 * PLACE;
        let budget = Budget::new(limit);
        let mut queue = PacketQueue::on(&budget);
        assert!(queue.try_push(Packet::new(vec![1])).is_ok());
        assert!(queue.try_push(Packet::new(vec![2, 3])).is_ok());
        assert_eq!(queue.bytes(), holds(1) + holds(2));
        assert_eq!(budget.used(), limit);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.front(), Some(&Packet::new(vec![1])));

        let rejected = Packet::new(vec![4]);
        assert_eq!(queue.try_push(rejected.clone()), Err(rejected));
        assert_eq!((queue.len(), budget.used()), (2, limit));
        assert_eq!(queue.pop(), Some(Packet::new(vec![1])));
        assert_eq!(queue.bytes(), holds(2));
        assert!(queue.try_push(Packet::new(vec![5])).is_ok());
        assert_eq!(queue.pop(), Some(Packet::new(vec![2, 3])));
        assert_eq!(queue.pop(), Some(Packet::new(vec![5])));
        assert_eq!((queue.bytes(), queue.places(), budget.used()), (0, 0, 0));
        assert_eq!(queue.front(), None);
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn an_empty_packet_still_pays_for_its_record() {
        let mut queue = PacketQueue::new(Some(Chunk::RECORD_BYTES - 1));
        assert_eq!(
            queue.try_push(Packet::new(vec![])),
            Err(Packet::new(vec![]))
        );
        assert!(queue.is_empty());
        let mut queue = PacketQueue::new(Some(Chunk::RECORD_BYTES + PLACE));
        assert!(queue.try_push(Packet::new(vec![])).is_ok());
        assert_eq!(queue.bytes(), Chunk::RECORD_BYTES);
        assert_eq!(
            queue.try_push(Packet::new(vec![])),
            Err(Packet::new(vec![]))
        );
        assert_eq!(queue.pop(), Some(Packet::new(vec![])));
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn clearing_and_taking_release_all_charges() {
        let budget = Budget::new(holds(1) + PLACE);
        let mut queue = PacketQueue::on(&budget);
        for _ in 0..2 {
            assert!(queue.try_push(Packet::new(vec![])).is_ok());
            queue.clear();
            assert_eq!((queue.bytes(), budget.used()), (0, 0));
            assert_eq!(queue.pop(), None);
            assert!(queue.is_empty());
        }
        assert!(queue.try_push(Packet::new(vec![3])).is_ok());
        let mut taken = std::mem::take(&mut queue);
        assert!(queue.is_empty());
        assert_eq!(taken.bytes(), holds(1));
        assert_eq!(taken.pop(), Some(Packet::new(vec![3])));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_packet_in_a_shared_backing_costs_the_memory_it_keeps() {
        let mut bytes = Chunk::unpaid(vec![7; 1000]);
        let head = bytes.split_to(10);
        let mut queue = PacketQueue::new(Some(999 + Chunk::RECORD_BYTES));
        let packet = queue.try_push(Packet::from_chunk(head)).unwrap_err();
        assert_eq!(packet.len(), 10, "a slice keeps its whole backing alive");
        drop(bytes);
    }
}
