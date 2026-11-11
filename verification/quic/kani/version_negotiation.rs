//! Storage of a server's Version Negotiation packet (RFC 9000 section
//! 17.2.1, RFC 9368 section 2.1): it is written into the send buffer and
//! allocates nothing.
use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    /// With room in its send buffer, a server writes a Version Negotiation
    /// packet listing its versions without allocating, and the packet
    /// echoes the connection IDs swapped and lists every supported version.
    #[kani::unwind(8)]
    fn version_negotiation_is_written_in_the_send_buffer() {
        let src: [u8; 4] = kani::any();
        let dst: [u8; 3] = kani::any();
        let version: u32 = kani::any();
        let random: u8 = kani::any();
        let supported = [crate::version::QUIC_V1, crate::version::QUIC_V2];
        let received_src = ConnectionId::new(&src);
        let received_dst = ConnectionId::new(&dst);
        let len = 7 + src.len() + dst.len() + 4 * (1 + supported.len());
        let mut buf = Vec::with_capacity(len);
        let ((), cost) = measure(|| {
            write_version_negotiation(
                &mut buf,
                random,
                &received_src,
                &received_dst,
                version,
                &supported,
            )
        });
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
        assert!(buf.len() == len);
        // Long header, version 0, then the IDs swapped.
        assert!(buf[0] & 0x80 != 0 && buf[1..5] == [0; 4]);
        assert!(buf[5] == 4 && buf[6..10] == src);
        assert!(buf[10] == 3 && buf[11..14] == dst);
        // A greasing version, never the one received, then the supported.
        let grease = u32::from_be_bytes(buf[14..18].try_into().unwrap());
        assert!(grease & 0x0f0f_0f0f == 0x0a0a_0a0a && grease != version);
        assert!(buf[18..22] == supported[0].to_be_bytes());
        assert!(buf[22..26] == supported[1].to_be_bytes());
        std::mem::forget(buf);
    }
}
