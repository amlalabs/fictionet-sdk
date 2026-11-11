//! Storage of the version rules (RFC 9368): reading a client's Version
//! Information from its first Initial, choosing a compatible version, the
//! downgrade check and encoding Version Information allocate nothing.
use super::*;
use crate::counting::{counted_proof, measure};
use crate::transport_parameters::TransportParameters;

/// A CRYPTO frame carrying a ClientHello whose only extension is the QUIC
/// transport parameters, holding Version Information `body`
fn first_flight(body: [u8; 12]) -> [u8; 69] {
    let mut p = [0; 69];
    // CRYPTO frame: type, offset 0, length 65 as a two-byte varint.
    p[..4].copy_from_slice(&[0x06, 0x00, 0x40, 65]);
    // ClientHello, 61 bytes: legacy_version, random, no session ID, one
    // cipher suite, null compression, 18 bytes of extensions.
    p[4..8].copy_from_slice(&[0x01, 0, 0, 61]);
    p[8..10].copy_from_slice(&[0x03, 0x03]);
    p[42] = 0;
    p[43..47].copy_from_slice(&[0, 2, 0x13, 0x01]);
    p[47..49].copy_from_slice(&[1, 0]);
    p[49..51].copy_from_slice(&[0, 18]);
    // quic_transport_parameters, 14 bytes: Version Information, 12 bytes.
    p[51..55].copy_from_slice(&[0x00, 0x39, 0, 14]);
    p[55..57].copy_from_slice(&[0x11, 12]);
    p[57..].copy_from_slice(&body);
    p
}

counted_proof! {
    /// A server reads a client's Version Information from a first flight
    /// in place: for any Chosen Version and two Available Versions, the
    /// read allocates nothing, and finds them when they are valid.
    #[kani::unwind(70)]
    fn the_first_flight_offer_is_read_in_place() {
        let body: [u8; 12] = kani::any();
        let payload = first_flight(body);
        let (offer, cost) = measure(|| client_version_information(&payload));
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

counted_proof! {
    /// No first flight of 24 bytes, however malformed, makes the reader
    /// allocate.
    #[kani::unwind(26)]
    fn any_short_first_flight_is_read_in_place() {
        let payload: [u8; 24] = kani::any();
        let (_, cost) = measure(|| client_version_information(&payload));
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
    }
}

counted_proof! {
    /// Choosing a compatible version, the client's offer and the downgrade
    /// check hold their lists inline.
    #[kani::unwind(10)]
    fn version_choices_allocate_nothing() {
        let listed: [u32; 3] = kani::any();
        let original: u32 = kani::any();
        let negotiated: u32 = kani::any();
        let ((), cost) = measure(|| {
            let client = VersionList::known(listed);
            let preference = VersionList::new(&[QUIC_V2, QUIC_V1]).unwrap();
            let offered = preference.compatible_with(original);
            let chosen = select_compatible(original, &[QUIC_V2, QUIC_V1], &client);
            assert!(chosen == original || client.contains(chosen));
            let server = VersionInformation {
                chosen: negotiated,
                available: client,
                unknown_available: false,
            };
            let _ = negotiation_was_genuine(&offered, &server, negotiated);
        });
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
    }
}

counted_proof! {
    /// Version Information with up to two Available Versions is encoded
    /// into the caller's buffer without allocating.
    #[kani::unwind(24)]
    fn version_information_is_encoded_in_place() {
        let chosen: u32 = kani::any();
        let available: [u32; 2] = kani::any();
        let mut params = TransportParameters::default();
        params.version_information = Some(VersionInformation {
            chosen,
            available: VersionList::known(available),
            unknown_available: false,
        });
        let mut out = [0u8; 128];
        let (written, cost) = measure(|| {
            let mut w = &mut out[..];
            params.write(&mut w);
            128 - w.len()
        });
        assert!(cost.requested <= 0);
        assert!(cost.peak <= 0);
        assert!(written <= 128);
    }
}
