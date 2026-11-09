use std::collections::VecDeque;

use crate::{PACKET_COST, Packet};

/// A packet FIFO that charges each packet's retained allocation (its
/// vector's capacity) plus [`PACKET_COST`]. Capacity limits and the policy
/// for rejected packets belong to the caller.
#[derive(Default)]
pub struct PacketQueue {
    packets: VecDeque<Packet>,
    bytes: usize,
}

/// What a queued packet costs: the memory it retains plus its place in the
/// queue. Admission and release both use this.
fn charge(packet: &Packet) -> Option<usize> {
    packet.0.capacity().checked_add(PACKET_COST)
}

impl PacketQueue {
    /// Whether `packet` fits beside the queued packets within `limit`. Every
    /// packet fits when `limit` is `None`, unless the total charge would
    /// overflow.
    pub fn fits(&self, packet: &Packet, limit: Option<usize>) -> bool {
        self.admit(packet, limit).is_some()
    }

    /// The queue's total charge with `packet` added, if it fits.
    fn admit(&self, packet: &Packet, limit: Option<usize>) -> Option<usize> {
        let total = charge(packet)?.checked_add(self.bytes)?;
        limit.is_none_or(|limit| total <= limit).then_some(total)
    }

    /// Adds a packet if it [`fits`](Self::fits) within `limit`. Returns the
    /// queued packet, or the original packet if full.
    pub fn try_push(&mut self, packet: Packet, limit: Option<usize>) -> Result<&Packet, Packet> {
        let Some(total) = self.admit(&packet, limit) else {
            return Err(packet);
        };
        self.bytes = total;
        self.packets.push_back(packet);
        Ok(self.packets.back().expect("just queued"))
    }

    /// Removes the oldest packet and releases its charge.
    pub fn pop(&mut self) -> Option<Packet> {
        let packet = self.packets.pop_front()?;
        self.bytes -= charge(&packet).expect("admitted packets have a charge");
        Some(packet)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PacketQueue {
    /// The total charge of the queued packets, including [`PACKET_COST`].
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Borrows the oldest packet without releasing its charge.
    pub fn front(&self) -> Option<&Packet> {
        self.packets.front()
    }

    /// The number of queued packets.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether no packets are queued.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Drops every queued packet and releases their charges.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.bytes = 0;
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn retained_capacity_is_admitted_and_released() {
        let mut queue = PacketQueue::default();
        let mut bytes = Vec::with_capacity(4096);
        bytes.push(1);
        let capacity = bytes.capacity();
        let packet = queue
            .try_push(Packet(bytes), Some(PACKET_COST + 1))
            .unwrap_err();
        assert!(queue.is_empty());
        assert!(queue.try_push(packet, Some(PACKET_COST + capacity)).is_ok());
        assert_eq!(queue.bytes(), PACKET_COST + capacity);
        assert_eq!(queue.pop().unwrap().0.capacity(), capacity);
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn unrepresentable_charges_never_fit() {
        let mut queue = PacketQueue::default();
        assert!(queue.try_push(Packet(vec![1]), None).is_ok());
        queue.bytes = usize::MAX - PACKET_COST;
        let packet = Packet(vec![2]);
        assert!(!queue.fits(&packet, Some(usize::MAX)));
        assert!(!queue.fits(&packet, None));
        assert_eq!(queue.try_push(packet.clone(), None), Err(packet));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn exact_capacity_rejection_and_drain_preserve_order_and_charges() {
        let mut queue = PacketQueue::default();
        let limit = 2 * PACKET_COST + 3;
        assert!(queue.try_push(Packet(vec![1]), Some(limit)).is_ok());
        assert!(queue.try_push(Packet(vec![2, 3]), Some(limit)).is_ok());
        assert_eq!(queue.bytes(), limit);
        assert_eq!(queue.len(), 2);
        assert!(!queue.is_empty());
        assert_eq!(queue.front(), Some(&Packet(vec![1])));

        let rejected = Packet(vec![4]);
        assert_eq!(queue.try_push(rejected.clone(), Some(limit)), Err(rejected));
        assert_eq!(queue.bytes(), limit);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), Some(Packet(vec![1])));
        assert_eq!(queue.bytes(), PACKET_COST + 2);
        assert!(queue.fits(&Packet(vec![5]), Some(limit)));
        assert!(!queue.fits(&Packet(vec![5, 6]), Some(limit)));
        assert!(queue.fits(&Packet(vec![5, 6]), None));
        assert!(queue.try_push(Packet(vec![5]), Some(limit)).is_ok());
        assert_eq!(queue.pop(), Some(Packet(vec![2, 3])));
        assert_eq!(queue.bytes(), PACKET_COST + 1);
        assert_eq!(queue.pop(), Some(Packet(vec![5])));
        assert_eq!(queue.bytes(), 0);
        assert!(queue.is_empty());
        assert_eq!(queue.front(), None);
        assert_eq!(queue.pop(), None);
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn empty_packets_are_charged_and_oversized_packets_leave_room() {
        let mut queue = PacketQueue::default();
        assert_eq!(queue.try_push(Packet(vec![]), Some(0)), Err(Packet(vec![])));
        assert_eq!(
            queue.try_push(Packet(vec![1]), Some(PACKET_COST)),
            Err(Packet(vec![1]))
        );
        assert_eq!(queue.bytes(), 0);
        assert!(queue.is_empty());
        assert!(queue.try_push(Packet(vec![]), Some(PACKET_COST)).is_ok());
        assert_eq!(queue.bytes(), PACKET_COST);
        assert_eq!(
            queue.try_push(Packet(vec![]), Some(PACKET_COST)),
            Err(Packet(vec![]))
        );
        assert_eq!(queue.pop(), Some(Packet(vec![])));
        assert_eq!(queue.bytes(), 0);
    }

    #[test]
    fn clearing_and_taking_release_all_charges() {
        let mut queue = PacketQueue::default();
        for _ in 0..2 {
            assert!(queue.try_push(Packet(vec![1, 2]), None).is_ok());
            assert!(queue.try_push(Packet(vec![]), None).is_ok());
            assert_eq!(queue.bytes(), 2 * PACKET_COST + 2);
            queue.clear();
            assert_eq!(queue.bytes(), 0);
            assert_eq!(queue.pop(), None);
            assert!(queue.is_empty());
        }
        let limit = Some(PACKET_COST + 1);
        assert!(queue.try_push(Packet(vec![3]), limit).is_ok());
        let mut taken = std::mem::take(&mut queue);
        assert_eq!(queue.bytes(), 0);
        assert!(queue.is_empty());
        assert_eq!(taken.bytes(), PACKET_COST + 1);
        assert_eq!(taken.pop(), Some(Packet(vec![3])));
        assert!(queue.try_push(Packet(vec![4]), limit).is_ok());
    }
}
