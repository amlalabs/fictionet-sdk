//! The packet carrier: whole packets, each taken or refused whole.

use core::marker::PhantomData;

use fictionet::stdlib::layer::{Budget, Chunk, Credited, Datagram, Port};

/// Whole packets: `I` coming up, `O` going down. IP packets on an
/// interface, the packets an IP layer hands its transports, or packets
/// carried inside a tunnel's frames.
///
/// A packet is atomic. A receiver takes it whole or hands it back
/// ([`Admit::Blocked`](super::Admit::Blocked)), and nothing ever takes part
/// of one. An empty packet is still a packet. The carrier promises nothing
/// about delivery: a packet may be lost, repeated or reordered, and a
/// receiver that drops one says so in a report rather than by refusing it.
/// [`PacketEvent::Ended`] means the interface below closed, never that a
/// conversation finished.
///
/// This is not [`Datagrams`](super::Datagrams). A UDP application reads
/// datagrams with their socket addresses; a transport reads IP packets.
/// Their ports differ, so a UDP application cannot be stacked on raw IP
/// packets by mistake. A packet carried inside a byte stream needs an
/// explicit frame boundary, given by a framing layer.
///
/// The item types say how much is known about a packet. Raw input is a
/// [`Chunk`] of bytes from an endpoint's input path; an IP layer hands its
/// transports a checked envelope
/// ([`CheckedIpPacket`](fictionet::stdlib::network::packet::CheckedIpPacket)) whose
/// metadata was read from its own bytes.
pub struct Packets<I, O = I>(PhantomData<fn() -> (I, O)>);

impl<I, O> Port for Packets<I, O> {
    type Event = PacketEvent<I>;
    type Command = PacketCommand<O>;
}

/// What comes up a packet port.
#[derive(Debug)]
pub enum PacketEvent<I> {
    /// One whole packet.
    Packet(I),
    /// The interface below closed: no more packets.
    Ended,
}

/// What goes down a packet port.
#[derive(Debug)]
pub enum PacketCommand<O> {
    /// Send one whole packet.
    Send(O),
    /// Nothing more will be sent.
    End,
}

/// A whole packet's owned bytes, which a packet carrier charges and never
/// splits.
pub trait Whole {
    /// The packet's length in bytes.
    fn len(&self) -> usize;

    /// Whether the packet has no bytes. An empty packet is still a packet.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Makes sure the packet's backing storage is paid for, charging
    /// `budget` for what it does not pay for yet. Refuses, changing
    /// nothing, when it does not fit.
    fn reserve(&mut self, budget: &Budget) -> bool;
}

impl Whole for Chunk {
    fn len(&self) -> usize {
        Chunk::len(self)
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        self.repay(budget)
    }
}

impl<M> Whole for Datagram<M> {
    fn len(&self) -> usize {
        self.payload().len()
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        self.payload_mut().reserve(budget)
    }
}

impl<I: Whole> Credited for PacketEvent<I> {
    fn credit(&self) -> u64 {
        u64::from(matches!(self, PacketEvent::Packet(_)))
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            PacketEvent::Packet(packet) => packet.reserve(budget),
            PacketEvent::Ended => true,
        }
    }
}

impl<O: Whole> Credited for PacketCommand<O> {
    fn credit(&self) -> u64 {
        u64::from(matches!(self, PacketCommand::Send(_)))
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            PacketCommand::Send(packet) => packet.reserve(budget),
            PacketCommand::End => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_is_never_split_by_credit() {
        let packet = PacketEvent::Packet(Chunk::new(vec![7; 1500]));
        assert_eq!(packet.credit(), 1);
        assert!(!packet.splittable());
        let Err(packet) = packet.admit_credit(0) else {
            panic!("a packet passed without credit");
        };
        let Ok((PacketEvent::Packet(whole), None)) = packet.admit_credit(1) else {
            panic!("one credit did not admit one whole packet");
        };
        assert_eq!(whole.len(), 1500);
    }

    #[test]
    fn an_empty_packet_is_a_packet() {
        let empty = PacketCommand::Send(Datagram::new(Chunk::new(Vec::new()), ()));
        assert_eq!(empty.credit(), 1);
        assert_eq!(PacketCommand::<Chunk>::End.credit(), 0);
        assert_eq!(PacketEvent::<Chunk>::Ended.credit(), 0);
    }

    #[test]
    fn reserving_charges_the_payload_once_or_refuses_unchanged() {
        let tight = Budget::new(10);
        let mut big = PacketEvent::Packet(Datagram::new(Chunk::new(vec![1; 11]), 5u8));
        assert!(!big.reserve(&tight));
        assert_eq!(tight.used(), 0);
        let PacketEvent::Packet(datagram) = &big else {
            unreachable!()
        };
        assert_eq!((datagram.payload().len(), *datagram.meta()), (11, 5));

        let budget = Budget::new(100);
        assert!(big.reserve(&budget));
        let charged = budget.used();
        assert!(charged >= 11);
        // Already charged storage keeps its one charge.
        assert!(big.reserve(&budget));
        assert_eq!(budget.used(), charged);
        drop(big);
        assert_eq!(budget.used(), 0);
    }
}
