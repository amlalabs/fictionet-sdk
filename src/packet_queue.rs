#[cfg(not(target_arch = "wasm32"))]
use std::collections::VecDeque;

#[cfg(not(target_arch = "wasm32"))]
use crate::{Budget, Charge};
use crate::{PACKET_COST, Packet};

/// A packet FIFO. Each packet costs the memory it keeps alive (its
/// backing's capacity) plus [`PACKET_COST`] for its place. A queue with a
/// limit charges that cost to a [`Budget`] from when the packet is queued
/// until it is taken out, and refuses whole a packet the budget has no room
/// for; what to do with it is the caller's. A queue with no limit charges
/// nothing.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
pub struct PacketQueue {
    /// Each packet, with its charge when the queue has a budget.
    packets: VecDeque<(Packet, Option<Charge>)>,
    budget: Option<Budget>,
}

/// What a queued packet costs: the memory it keeps alive plus its place in
/// the queue, for a [`PacketQueue`] and a limited cable alike. `None` when
/// that is past what a count can hold, which no budget has room for.
pub(crate) fn cost(packet: &Packet) -> Option<usize> {
    packet.chunk().capacity().checked_add(PACKET_COST)
}

#[cfg(not(target_arch = "wasm32"))]
impl PacketQueue {
    /// A queue whose packets hold at most `limit` bytes, counted as above,
    /// or with no limit.
    pub fn new(limit: Option<usize>) -> Self {
        PacketQueue {
            packets: VecDeque::new(),
            budget: limit.map(Budget::new),
        }
    }

    /// A queue whose packets count against `budget`, beside whatever else
    /// it pays for.
    pub fn on(budget: &Budget) -> Self {
        PacketQueue {
            packets: VecDeque::new(),
            budget: Some(budget.clone()),
        }
    }

    /// Queues `packet`, charging the budget first if there is one. Returns
    /// the queued packet, or the packet itself, with nothing charged, if
    /// the budget has no room.
    pub fn try_push(&mut self, packet: Packet) -> Result<&Packet, Packet> {
        let Some(cost) = cost(&packet) else {
            return Err(packet);
        };
        let charge = match &self.budget {
            Some(budget) => match budget.charge(cost) {
                Some(charge) => Some(charge),
                None => return Err(packet),
            },
            None => None,
        };
        self.packets.push_back((packet, charge));
        Ok(&self.packets.back().expect("just queued").0)
    }

    /// Takes out the oldest packet and gives back its charge.
    pub fn pop(&mut self) -> Option<Packet> {
        self.packets.pop_front().map(|(packet, _)| packet)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PacketQueue {
    /// Whether the queue has room for `packet` now.
    pub fn fits(&self, packet: &Packet) -> bool {
        let room = self.budget.as_ref().map_or(usize::MAX, |budget| {
            budget.limit().saturating_sub(budget.used())
        });
        cost(packet).is_some_and(|cost| cost <= room)
    }

    /// What the queued packets cost, including [`PACKET_COST`], whether or
    /// not the queue charges it.
    pub fn bytes(&self) -> usize {
        self.packets
            .iter()
            .map(|(packet, _)| cost(packet).expect("a queued packet has a cost"))
            .sum()
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

    /// Drops every queued packet and gives back their charges.
    pub fn clear(&mut self) {
        self.packets.clear();
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::Chunk;

    #[test]
    fn retained_capacity_is_admitted_and_released() {
        let mut bytes = Vec::with_capacity(4096);
        bytes.push(1);
        let capacity = bytes.capacity();
        let mut queue = PacketQueue::new(Some(PACKET_COST + 1));
        let packet = queue.try_push(Packet::new(bytes)).unwrap_err();
        assert!(queue.is_empty());
        let budget = Budget::new(PACKET_COST + capacity);
        let mut queue = PacketQueue::on(&budget);
        assert!(queue.try_push(packet).is_ok());
        assert_eq!(queue.bytes(), PACKET_COST + capacity);
        assert_eq!(budget.used(), queue.bytes());
        assert_eq!(queue.pop().unwrap().chunk().capacity(), capacity);
        assert_eq!((queue.bytes(), budget.used()), (0, 0));
    }

    #[test]
    fn a_shared_budget_limits_the_queue_with_everything_else_it_pays_for() {
        let budget = Budget::new(2 * (PACKET_COST + 1));
        let mut queue = PacketQueue::on(&budget);
        assert!(queue.try_push(Packet::new(vec![1])).is_ok());
        let other = budget.charge(PACKET_COST + 1).unwrap();
        let refused = Packet::new(vec![2]);
        assert!(!queue.fits(&refused));
        assert_eq!(queue.try_push(refused.clone()), Err(refused.clone()));
        assert_eq!(budget.used(), 2 * (PACKET_COST + 1));
        drop(other);
        assert!(queue.try_push(refused).is_ok());
        queue.clear();
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn unrepresentable_charges_never_fit() {
        let budget = Budget::unlimited();
        let mut queue = PacketQueue::on(&budget);
        assert!(queue.try_push(Packet::new(vec![1])).is_ok());
        let held = budget
            .charge(usize::MAX - budget.used() - PACKET_COST)
            .unwrap();
        let packet = Packet::new(vec![2]);
        assert!(!queue.fits(&packet));
        assert_eq!(queue.try_push(packet.clone()), Err(packet));
        assert_eq!(queue.len(), 1);
        drop(held);
    }

    #[test]
    fn exact_capacity_rejection_and_drain_preserve_order_and_charges() {
        let limit = 2 * PACKET_COST + 3;
        let mut queue = PacketQueue::new(Some(limit));
        assert!(queue.try_push(Packet::new(vec![1])).is_ok());
        assert!(queue.try_push(Packet::new(vec![2, 3])).is_ok());
        assert_eq!(queue.bytes(), limit);
        assert_eq!(queue.len(), 2);
        assert!(!queue.is_empty());
        assert_eq!(queue.front(), Some(&Packet::new(vec![1])));

        let rejected = Packet::new(vec![4]);
        assert_eq!(queue.try_push(rejected.clone()), Err(rejected));
        assert_eq!(queue.bytes(), limit);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), Some(Packet::new(vec![1])));
        assert_eq!(queue.bytes(), PACKET_COST + 2);
        assert!(queue.fits(&Packet::new(vec![5])));
        assert!(!queue.fits(&Packet::new(vec![5, 6])));
        assert!(PacketQueue::default().fits(&Packet::new(vec![5, 6])));
        assert!(queue.try_push(Packet::new(vec![5])).is_ok());
        assert_eq!(queue.pop(), Some(Packet::new(vec![2, 3])));
        assert_eq!(queue.bytes(), PACKET_COST + 1);
        assert_eq!(queue.pop(), Some(Packet::new(vec![5])));
        assert_eq!(queue.bytes(), 0);
        assert!(queue.is_empty());
        assert_eq!(queue.front(), None);
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn empty_packets_are_charged_and_oversized_packets_leave_room() {
        let mut queue = PacketQueue::new(Some(0));
        assert_eq!(
            queue.try_push(Packet::new(vec![])),
            Err(Packet::new(vec![]))
        );
        let mut queue = PacketQueue::new(Some(PACKET_COST));
        assert_eq!(
            queue.try_push(Packet::new(vec![1])),
            Err(Packet::new(vec![1]))
        );
        assert_eq!(queue.bytes(), 0);
        assert!(queue.is_empty());
        assert!(queue.try_push(Packet::new(vec![])).is_ok());
        assert_eq!(queue.bytes(), PACKET_COST);
        assert_eq!(
            queue.try_push(Packet::new(vec![])),
            Err(Packet::new(vec![]))
        );
        assert_eq!(queue.pop(), Some(Packet::new(vec![])));
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn clearing_and_taking_release_all_charges() {
        let budget = Budget::new(PACKET_COST + 1);
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
        assert_eq!(queue.bytes(), 0);
        assert!(queue.is_empty());
        assert_eq!(taken.bytes(), PACKET_COST + 1);
        assert_eq!(taken.pop(), Some(Packet::new(vec![3])));
        assert!(queue.try_push(Packet::new(vec![4])).is_ok());
    }

    #[test]
    fn a_packet_in_a_shared_backing_costs_the_memory_it_keeps() {
        let mut bytes = Chunk::unpaid(vec![7; 1000]);
        let head = bytes.split_to(10);
        let mut queue = PacketQueue::new(Some(PACKET_COST + 999));
        let packet = queue.try_push(Packet::from_chunk(head)).unwrap_err();
        assert_eq!(packet.len(), 10, "a slice keeps its whole backing alive");
        drop(bytes);
    }
}
