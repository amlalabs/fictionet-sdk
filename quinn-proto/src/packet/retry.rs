//! The Retry Pseudo-Packet (RFC 9001 section 5.8): the Original Destination
//! Connection ID, after its length, then the Retry packet. The Retry
//! Integrity Tag covers it whole, so the AEAD needs it contiguous.
//!
//! A server builds it inside the buffer it sends the Retry from, so a Retry
//! allocates nothing. A client copies the received Retry after the prefix,
//! into storage it charges to its budget first.

use fictionet_buf::{Budget, Charge};

use crate::shared::ConnectionId;

/// Appends to `buf` the integrity tag of the Retry packet `buf[start..]`,
/// which `tag` computes from the Pseudo-Packet for `orig_dst_cid`
///
/// The prefix is written after the packet and rotated in front of it, then
/// back, so `buf` holds `1 + orig_dst_cid.len()` bytes past the packet, at
/// most 21, before the 16 bytes of the tag. Given that room, nothing is
/// allocated.
pub(crate) fn tag_in_place(
    buf: &mut Vec<u8>,
    start: usize,
    orig_dst_cid: &ConnectionId,
    tag: impl FnOnce(&[u8]) -> [u8; 16],
) {
    let end = buf.len();
    let prefix = 1 + orig_dst_cid.len();
    buf.push(orig_dst_cid.len() as u8);
    buf.extend_from_slice(orig_dst_cid);
    buf[start..].rotate_right(prefix);
    let tag = tag(&buf[start..]);
    buf[start..].rotate_left(prefix);
    buf.truncate(end);
    buf.extend_from_slice(&tag);
}

/// A received Retry's Pseudo-Packet, ending in its tag, in storage paid for
/// by a budget while it lives
pub(crate) struct PseudoPacket {
    bytes: Vec<u8>,
    /// Released after `bytes` is freed: fields drop in order
    _charge: Option<Charge>,
}

impl PseudoPacket {
    /// The bytes a Pseudo-Packet of a Retry with `header` and `payload`
    /// (token and tag) occupies
    pub(crate) fn len(orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> usize {
        1 + orig_dst_cid.len() + header.len() + payload.len()
    }

    /// Copies the Retry with `header` and `payload` after the prefix for
    /// `orig_dst_cid`, charging `budget` for its storage first. `None`, with
    /// nothing allocated, when the budget refuses.
    pub(crate) fn new(
        budget: Option<&Budget>,
        orig_dst_cid: &ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> Option<Self> {
        let len = Self::len(orig_dst_cid, header, payload);
        let charge = match budget {
            Some(budget) => Some(budget.charge(len)?),
            None => None,
        };
        let mut bytes = Vec::with_capacity(len);
        bytes.push(orig_dst_cid.len() as u8);
        bytes.extend_from_slice(orig_dst_cid);
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(payload);
        Some(Self {
            bytes,
            _charge: charge,
        })
    }

    /// The Pseudo-Packet and the tag after it
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_CID_SIZE;

    #[test]
    fn the_tag_covers_the_pseudo_packet_and_follows_the_packet() {
        for cid in [&[][..], &[7; 8][..], &[9; MAX_CID_SIZE][..]] {
            let odcid = ConnectionId::new(cid);
            let mut buf = vec![0xee; 3];
            let packet = [0xf0, 1, 2, 3, 4, 5];
            buf.extend_from_slice(&packet);
            let mut seen = Vec::new();
            tag_in_place(&mut buf, 3, &odcid, |pseudo| {
                seen = pseudo.to_vec();
                [0xaa; 16]
            });
            let mut expected = vec![cid.len() as u8];
            expected.extend_from_slice(cid);
            expected.extend_from_slice(&packet);
            assert_eq!(seen, expected);
            assert_eq!(&buf[..3], &[0xee; 3]);
            assert_eq!(&buf[3..3 + packet.len()], &packet);
            assert_eq!(&buf[3 + packet.len()..], &[0xaa; 16]);
        }
    }

    #[test]
    fn a_received_pseudo_packet_is_charged_while_it_lives() {
        let odcid = ConnectionId::new(&[3; 8]);
        let (header, payload) = ([0xf0, 1, 2], [4; 20]);
        let len = PseudoPacket::len(&odcid, &header, &payload);
        assert!(
            PseudoPacket::new(Some(&Budget::new(len - 1)), &odcid, &header, &payload).is_none()
        );
        let budget = Budget::new(len);
        let mut pseudo = PseudoPacket::new(Some(&budget), &odcid, &header, &payload).unwrap();
        assert_eq!(budget.used(), len);
        assert_eq!(pseudo.bytes_mut()[0], 8);
        assert_eq!(&pseudo.bytes_mut()[9..12], &header);
        drop(pseudo);
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(kani)]
#[path = "../../../verification/quic/kani/retry_storage.rs"]
mod retry_storage_proofs;
