//! Storage of the Retry Pseudo-Packet (RFC 9001 section 5.8, RFC 9369
//! section 3.3.3): a server builds it in its send buffer and allocates
//! nothing; a client copies a received Retry only into storage its budget
//! paid for first.
use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    /// With room for the prefix in its send buffer, a server tags a Retry
    /// without allocating; the tag is computed over the Pseudo-Packet, and
    /// the buffer ends with the packet, unchanged, then the tag.
    #[kani::unwind(30)]
    fn a_server_tags_a_retry_in_its_send_buffer() {
        let cid: [u8; 4] = kani::any();
        let packet: [u8; 6] = kani::any();
        let marker: u8 = kani::any();
        let odcid = ConnectionId::new(&cid);
        // The packet, then room for the larger of the prefix and the tag.
        let mut buf = Vec::with_capacity(packet.len() + 16);
        buf.extend_from_slice(&packet);
        let mut covered = false;
        let ((), cost) = measure(|| {
            tag_in_place(&mut buf, 0, &odcid, |pseudo| {
                covered = pseudo.len() == 1 + cid.len() + packet.len()
                    && pseudo[0] == cid.len() as u8
                    && pseudo[1..5] == cid
                    && pseudo[5..] == packet;
                [marker; 16]
            })
        });
        assert!(covered);
        assert!(buf[..packet.len()] == packet);
        assert!(buf[packet.len()..] == [marker; 16]);
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
        std::mem::forget(buf);
    }
}

counted_proof! {
    /// A client's copy of a received Retry is refused, with nothing
    /// allocated, when its budget cannot pay for it. Otherwise the copy
    /// never holds more than the charge, and asks for one byte per byte of
    /// the Retry plus the prefix: `per` = 1, `fixed` = 1 + 20, the length
    /// byte and the longest connection ID.
    #[kani::unwind(12)]
    fn a_client_copies_a_retry_only_within_its_charge() {
        let cid: [u8; 2] = kani::any();
        let header: [u8; 3] = kani::any();
        let payload: [u8; 5] = kani::any();
        let limit: usize = kani::any();
        kani::assume(limit <= 16);
        let odcid = ConnectionId::new(&cid);
        let budget = Budget::new(limit);
        let len = PseudoPacket::len(&odcid, &header, &payload);
        let (pseudo, cost) = measure(|| PseudoPacket::new(Some(&budget), &odcid, &header, &payload));
        match pseudo {
            None => {
                assert!(limit < len);
                assert!(budget.used() == 0);
                assert!(cost.requested <= 0);
            }
            Some(mut pseudo) => {
                assert!(limit >= len);
                assert!(cost.peak <= budget.used());
                let per = 1;
                let fixed = 1 + crate::MAX_CID_SIZE;
                assert!(cost.requested <= per * (header.len() + payload.len()) + fixed);
                let bytes = pseudo.bytes_mut();
                assert!(bytes[0] == 2 && bytes[1..3] == cid);
                assert!(bytes[3..6] == header && bytes[6..] == payload);
                std::mem::forget(pseudo);
            }
        }
        std::mem::forget(budget);
    }
}
