//! Storage of the first-flight reader (RFC 9368 section 2.3): a server
//! reads the client's Version Information from the transport parameters in
//! place. The whole reader, CRYPTO frames and ClientHello included, is
//! costed by the replay `the_reader_allocates_nothing_on_any_first_flight`
//! below it; CBMC ran out of 10 GiB on it under symbolic frames.
use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    /// For any Chosen Version and two Available Versions, after another
    /// parameter, the reader allocates nothing, and finds the offer exactly
    /// when it is valid.
    #[kani::unwind(10)]
    fn the_transport_parameter_offer_is_read_in_place() {
        let body: [u8; 12] = kani::any();
        // max_idle_timeout (0x01) of one byte, then Version Information.
        let mut params = [0; 17];
        params[..3].copy_from_slice(&[0x01, 1, 0x05]);
        params[3..5].copy_from_slice(&[0x11, 12]);
        params[5..].copy_from_slice(&body);
        let (offer, cost) = measure(|| transport_parameter(Cursor::contiguous(&params)));
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
        let word = |i: usize| u32::from_be_bytes(body[i..i + 4].try_into().unwrap());
        let (chosen, first, second) = (word(0), word(4), word(8));
        let valid = chosen != 0 && first != 0 && second != 0 && (chosen == first || chosen == second);
        assert!(offer.is_some() == valid);
        if let Some(offer) = offer {
            assert!(offer.chosen == chosen);
        }
    }
}
