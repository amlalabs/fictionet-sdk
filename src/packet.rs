use std::ops::Deref;

use crate::{Budget, Chunk};

/// One IPv4 or IPv6 packet, exactly the bytes on the wire.
///
/// The core never parses a packet, so a program can send a broken one on
/// purpose. Parsing lives in [`stdlib`](crate::stdlib).
///
/// The bytes are a [`Chunk`], the one buffer type from the wire to the code
/// that reads them, so a packet moves through interfaces without being
/// copied or wrapped again. Reading is through [`Deref`]; changing a byte
/// is only through [`make_mut`](Self::make_mut), which copies a shared
/// backing and clears what a stack verified ([`Checksums`]). Two packets
/// are equal when their bytes are.
#[derive(Clone)]
pub struct Packet {
    bytes: Chunk,
    checksums: Checksums,
}

/// What a stack in this process verified of a packet, unchanged since.
///
/// Only Fictionet sets a flag, right after it computed or checked the sum,
/// and every path that can change a byte clears it: a packet from world
/// code ([`Packet::new`]), from a chunk ([`Packet::from_chunk`]) or from an
/// attached sandbox carries neither. A receiving stack may skip checking a
/// sum that is flagged, and nothing else changes.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Checksums {
    /// The IPv4 header checksum is right.
    pub ip_header: bool,
    /// The TCP or UDP checksum, over its pseudo-header, is right.
    pub transport: bool,
}

impl Packet {
    /// Bytes from world code or a test: nothing pays for them yet, and no
    /// sum is known to be right.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Packet {
        Packet::from_chunk(Chunk::unpaid(bytes))
    }

    /// A chunk a stack made or admitted, with no sum known to be right.
    pub fn from_chunk(bytes: Chunk) -> Packet {
        Packet {
            bytes,
            checksums: Checksums::default(),
        }
    }

    /// A chunk whose sums this crate computed or checked just now.
    #[cfg_attr(
        not(any(test, kani)),
        expect(
            dead_code,
            reason = "the TCP engine marks what it emits once its packets reach an interface whole"
        )
    )]
    pub(crate) fn verified(bytes: Chunk, checksums: Checksums) -> Packet {
        Packet { bytes, checksums }
    }

    /// The packet's length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the packet has no bytes. An empty packet is still a packet.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The bytes as the chunk that holds them.
    pub fn chunk(&self) -> &Chunk {
        &self.bytes
    }

    /// The chunk that holds the bytes, keeping nothing else.
    pub fn into_chunk(self) -> Chunk {
        self.bytes
    }

    /// What a stack verified of the bytes, unchanged since.
    pub fn checksums(&self) -> Checksums {
        self.checksums
    }

    /// The bytes to change, in place when this packet alone holds them and
    /// in a copy charged to `budget` when they are shared, as
    /// [`Chunk::make_mut`] does. Clears both checksum flags. `None`,
    /// changing nothing, when the budget refuses.
    pub fn make_mut(&mut self, budget: &Budget) -> Option<&mut [u8]> {
        let Packet { bytes, checksums } = self;
        let bytes = bytes.make_mut(budget)?;
        *checksums = Checksums::default();
        Some(bytes)
    }

    /// The bytes to change in the IP header only, as a router lowers the
    /// TTL and mends the header checksum: clears `ip_header` and keeps
    /// `transport`, which the header does not cover. `None`, changing
    /// nothing, when the budget refuses.
    pub(crate) fn header_mut(&mut self, budget: &Budget) -> Option<&mut [u8]> {
        let Packet { bytes, checksums } = self;
        let bytes = bytes.make_mut(budget)?;
        checksums.ip_header = false;
        Some(bytes)
    }

    /// The bytes as a vector: the allocation itself when nothing else
    /// holds or pays for it, a copy otherwise.
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes.into_vec()
    }
}

impl Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet")
            .field("bytes", &&*self.bytes)
            .field("checksums", &self.checksums)
            .finish()
    }
}

impl PartialEq for Packet {
    /// Equal bytes, whatever was verified of them.
    fn eq(&self, other: &Packet) -> bool {
        **self == **other
    }
}

impl Eq for Packet {}

impl PartialEq<[u8]> for Packet {
    fn eq(&self, other: &[u8]) -> bool {
        **self == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Packet {
    fn eq(&self, other: &[u8; N]) -> bool {
        **self == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified() -> Packet {
        let all = Checksums {
            ip_header: true,
            transport: true,
        };
        Packet::verified(Chunk::unpaid(vec![0x45, 0, 0, 20]), all)
    }

    #[test]
    fn packets_from_outside_carry_no_flag() {
        assert_eq!(Packet::new(vec![1]).checksums(), Checksums::default());
        let chunk = Chunk::unpaid(vec![1]);
        assert_eq!(Packet::from_chunk(chunk).checksums(), Checksums::default());
    }

    #[test]
    fn changing_any_byte_clears_every_flag() {
        let budget = Budget::unlimited();
        let mut packet = verified();
        packet.make_mut(&budget).unwrap()[3] ^= 1;
        assert_eq!(packet.checksums(), Checksums::default());

        // A shared packet is copied, and only the changed copy loses its
        // flags.
        let original = verified();
        let mut copy = original.clone();
        copy.make_mut(&budget).unwrap()[0] = 0x46;
        assert_eq!(copy.checksums(), Checksums::default());
        assert_eq!(original.checksums(), verified().checksums());
        assert_eq!(original, [0x45, 0, 0, 20]);
    }

    #[test]
    fn a_header_edit_keeps_the_transport_flag() {
        let budget = Budget::unlimited();
        let mut packet = verified();
        packet.header_mut(&budget).unwrap()[1] = 4;
        assert_eq!(
            packet.checksums(),
            Checksums {
                ip_header: false,
                transport: true,
            }
        );
    }

    #[test]
    fn a_refused_edit_changes_nothing() {
        let mut packet = verified();
        let shared = packet.clone();
        assert!(packet.make_mut(&Budget::new(0)).is_none());
        assert!(packet.header_mut(&Budget::new(0)).is_none());
        assert_eq!(packet.checksums(), shared.checksums());
        assert!(packet.chunk().shares(shared.chunk()));
    }

    #[test]
    fn equality_is_on_bytes_only() {
        assert_eq!(verified(), Packet::new(vec![0x45, 0, 0, 20]));
        assert_ne!(verified(), Packet::new(vec![0x45, 0, 0, 21]));
        assert_eq!(*verified(), [0x45, 0, 0, 20]);
    }
}

#[cfg(kani)]
#[path = "../verification/buf/kani/packet.rs"]
mod proofs;
