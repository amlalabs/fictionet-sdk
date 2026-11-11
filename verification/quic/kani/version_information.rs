use super::*;
use crate::counting::{counted_proof, measure};

#[kani::proof]
#[kani::unwind(4)]
fn version_information_validates_all_versions_and_the_peer_role() {
    let chosen: u32 = kani::any();
    let first: u32 = kani::any();
    let second: u32 = kani::any();
    let server: bool = kani::any();
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&chosen.to_be_bytes());
    bytes[4..8].copy_from_slice(&first.to_be_bytes());
    bytes[8..].copy_from_slice(&second.to_be_bytes());
    let side = if server { Side::Server } else { Side::Client };
    let mut input = bytes.as_slice();
    let result = read_version_information(side, bytes.len(), None, &mut input);
    let valid = chosen != 0
        && first != 0
        && second != 0
        && (!server || chosen == first || chosen == second);
    assert_eq!(result.is_ok(), valid);
    if let Ok(version) = result {
        assert_eq!(version, chosen);
        assert!(input.is_empty());
    }
}

counted_proof! {
    #[kani::unwind(4)]
    fn version_information_body_checks_the_connection_without_allocating() {
        let bytes: [u8; 12] = kani::any();
        let connection: u32 = kani::any();
        let server: bool = kani::any();
        let side = if server { Side::Server } else { Side::Client };
        let (result, cost) = measure(|| {
            read_version_information(side, bytes.len(), Some(connection), &mut bytes.as_slice())
        });
        let chosen = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let first = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let second = u32::from_be_bytes(bytes[8..].try_into().unwrap());
        let valid = chosen != 0 && first != 0 && second != 0
            && (!server || chosen == first || chosen == second);
        if !valid {
            assert!(matches!(result, Err(Error::IllegalValue)));
        } else if chosen != connection {
            assert!(matches!(result, Err(Error::VersionMismatch)));
        } else {
            assert_eq!(result, Ok(connection));
        }
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
    }
}

counted_proof! {
    #[kani::unwind(3)]
    fn version_information_checks_the_connection_without_allocating() {
        let bytes: [u8; 12] = kani::any();
        let connection: u32 = kani::any();
        let server: bool = kani::any();
        let side = if server { Side::Server } else { Side::Client };
        let (result, cost) = measure(|| {
            let parameter = [
                0x11, 12, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
            ];
            TransportParameters::read_for_version(side, connection, &mut parameter.as_slice())
        });
        let chosen = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        let first = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let second = u32::from_be_bytes(bytes[8..].try_into().unwrap());
        let valid = chosen != 0 && first != 0 && second != 0
            && (!server || chosen == first || chosen == second);
        if !valid {
            assert!(matches!(result, Err(Error::IllegalValue)));
        } else if chosen != connection {
            assert!(matches!(result, Err(Error::VersionMismatch)));
        } else {
            assert!(result.is_ok());
        }
        // The parser borrows the input and keeps only inline state.
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
    }
}
