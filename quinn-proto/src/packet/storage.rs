use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};
use fictionet_buf::{Budget, Charge};

use super::PacketDecodeError;

/// Mutable wire storage whose reservation follows every retained packet and frame view.
///
/// Construct with `copy_from` before passing input to an endpoint. Conversion from
/// `BytesMut` preserves the legacy unbudgeted API. This accounts for wire backing
/// storage only, not connection state or copies made by reassembly and TLS.
#[derive(Debug)]
pub struct PacketBuffer {
    // Free storage before releasing its reservation.
    bytes: BytesMut,
    backing: Option<Arc<Charge>>,
    owner: Option<Charge>,
}

// bytes stores a Vec, its original-capacity word and a reference count when
// mutable views split. Arc adds two reference counts around the backing charge.
const BACKING_OVERHEAD: usize = size_of::<Vec<u8>>() + 4 * size_of::<usize>() + size_of::<Charge>();
// Bytes::from_owner stores its owner with one reference count. All fields have
// pointer alignment, so this also covers the wrapper's alignment.
const OWNER_OVERHEAD: usize = size_of::<PacketBuffer>() + size_of::<usize>();

impl PacketBuffer {
    /// Reserve the backing and its shared ownership before copying wire input.
    /// Refusal allocates nothing and leaves the caller's input untouched.
    pub fn copy_from(budget: &Budget, data: &[u8]) -> Option<Self> {
        let mut backing =
            budget.charge(data.len().checked_add(BACKING_OVERHEAD + OWNER_OVERHEAD)?)?;
        let owner = backing
            .split(OWNER_OVERHEAD)
            .expect("owner reservation included");
        Some(Self {
            bytes: BytesMut::from(data),
            backing: Some(Arc::new(backing)),
            owner: Some(owner),
        })
    }

    fn split_charge(&self) -> Result<Option<Charge>, PacketDecodeError> {
        self.backing
            .as_ref()
            .map(|charge| {
                charge
                    .budget()
                    .charge(OWNER_OVERHEAD)
                    .ok_or(PacketDecodeError::InvalidHeader(
                        "receive storage exhausted",
                    ))
            })
            .transpose()
    }

    pub(super) fn split_off(&mut self, at: usize) -> Result<Self, PacketDecodeError> {
        let owner = self.split_charge()?;
        Ok(Self {
            bytes: self.bytes.split_off(at),
            backing: self.backing.clone(),
            owner,
        })
    }

    pub(super) fn split_to(&mut self, at: usize) -> Result<Self, PacketDecodeError> {
        let owner = self.split_charge()?;
        Ok(Self {
            bytes: self.bytes.split_to(at),
            backing: self.backing.clone(),
            owner,
        })
    }

    pub(crate) fn freeze(self) -> Bytes {
        if self.owner.is_some() {
            Bytes::from_owner(self)
        } else {
            self.bytes.freeze()
        }
    }

    pub(crate) fn decrypt(
        &mut self,
        key: &dyn crate::crypto::PacketKey,
        number: u64,
        header: &[u8],
    ) -> Result<(), crate::crypto::CryptoError> {
        key.decrypt(number, header, &mut self.bytes)
    }
}

impl From<BytesMut> for PacketBuffer {
    fn from(bytes: BytesMut) -> Self {
        Self {
            bytes,
            backing: None,
            owner: None,
        }
    }
}

impl AsRef<[u8]> for PacketBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for PacketBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl DerefMut for PacketBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

#[cfg(test)]
impl Clone for PacketBuffer {
    fn clone(&self) -> Self {
        match &self.backing {
            Some(charge) => Self::copy_from(charge.budget(), &self.bytes).unwrap(),
            None => Self::from(self.bytes.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::{Charged, Costs, Linear};

    #[test]
    fn packet_storage_is_reserved_before_copying_and_splitting() {
        for len in [0, 1, 64, 1200, 65527] {
            let input = vec![7; len];
            let budget = Budget::new(len + BACKING_OVERHEAD + 4 * OWNER_OVERHEAD);
            let mut costs = Costs::new("QUIC wire backing");
            let mut packet = costs.step(
                len,
                0,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: 0,
                },
                || {
                    let packet = PacketBuffer::copy_from(&budget, &input).unwrap();
                    Charged::new(packet, budget.used())
                },
            );
            let before = budget.used();
            let tail = costs.step(
                0,
                before,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: BACKING_OVERHEAD,
                },
                || {
                    let tail = packet.split_off(len / 2).unwrap();
                    Charged::new(tail, budget.used() - before)
                },
            );
            let (head, tail) = costs.step(
                0,
                budget.used(),
                Linear {
                    num: 0,
                    den: 1,
                    fixed: 2 * OWNER_OVERHEAD,
                },
                || Charged::new((packet.freeze(), tail.freeze()), 0),
            );
            assert_eq!(&head[..], &input[..len / 2]);
            assert_eq!(&tail[..], &input[len / 2..]);
            let charge = budget.used();
            let (copy, slice) = costs.step(
                0,
                charge,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: 0,
                },
                || Charged::new((tail.clone(), tail.slice(..)), 0),
            );
            drop(head);
            drop(tail);
            assert!(budget.used() >= len + BACKING_OVERHEAD + OWNER_OVERHEAD);
            drop(copy);
            drop(slice);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn packet_storage_refusal_allocates_nothing() {
        let input = [3; 64];
        for limit in [
            0,
            input.len() + BACKING_OVERHEAD,
            input.len() + BACKING_OVERHEAD + OWNER_OVERHEAD - 1,
        ] {
            let budget = Budget::new(limit);
            let mut costs = Costs::new("QUIC wire refusal");
            let packet = costs.step(
                input.len(),
                0,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: 0,
                },
                || Charged::new(PacketBuffer::copy_from(&budget, &input), budget.used()),
            );
            assert!(packet.is_none());
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn refused_packet_split_preserves_bytes_and_reservation() {
        let budget = Budget::new(8 + BACKING_OVERHEAD + OWNER_OVERHEAD);
        let mut packet = PacketBuffer::copy_from(&budget, b"abcdefgh").unwrap();
        let before = budget.used();
        let pointer = packet.as_ptr();
        let mut costs = Costs::new("QUIC wire split refusal");
        for prefix in [false, true] {
            costs.step(
                0,
                0,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: 0,
                },
                || {
                    let split = if prefix {
                        packet.split_to(4)
                    } else {
                        packet.split_off(4)
                    };
                    assert!(split.is_err());
                    Charged::new((), 0)
                },
            );
            assert_eq!(&packet[..], b"abcdefgh");
            assert_eq!(packet.as_ptr(), pointer);
            assert_eq!(budget.used(), before);
        }
        drop(packet);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn split_packet_views_mutate_disjoint_bytes_and_keep_the_backing() {
        let budget = Budget::unlimited();
        let mut payload = PacketBuffer::copy_from(&budget, b"abcdefghijkl").unwrap();
        let base = payload.as_ptr();
        let mut rest = payload.split_off(8).unwrap();
        let mut header = payload.split_to(4).unwrap();
        header[0] = b'A';
        payload[0] = b'E';
        rest[0] = b'I';
        let header = header.freeze();
        let payload = payload.freeze();
        let rest = rest.freeze();
        assert_eq!(header.as_ptr(), base);
        assert_eq!(payload.as_ptr(), base.wrapping_add(4));
        assert_eq!(rest.as_ptr(), base.wrapping_add(8));
        assert_eq!(&header[..], b"Abcd");
        assert_eq!(&payload[..], b"Efgh");
        assert_eq!(&rest[..], b"Ijkl");
        let view = payload.slice(1..3);
        drop((header, payload, rest));
        assert_eq!(budget.used(), 12 + BACKING_OVERHEAD + OWNER_OVERHEAD);
        assert_eq!(&view[..], b"fg");
        drop(view);
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(kani)]
#[path = "../../../verification/quic/kani/packet_storage.rs"]
mod proofs;
