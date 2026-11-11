//! Storage of the version rules (RFC 9368): choosing a compatible version,
//! the downgrade check and encoding Version Information allocate nothing.
use super::*;
use crate::counting::{counted_proof, measure};
use crate::transport_parameters::TransportParameters;

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
            let _ = negotiation_was_genuine(&offered, &server, original, negotiated);
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
