use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    #[kani::unwind(2)]
    fn listener_completion_preserves_its_owner_without_allocating() {
        let owner: u64 = kani::any();
        let kind: u8 = kani::any();
        let count: u64 = kani::any();
        let mut flight = match kind {
            0 => Transmission::Idle,
            1 => Transmission::Endpoint,
            _ => Transmission::Connection(owner),
        };
        let before = flight;
        let (result, cost) = measure(|| flight.complete(count));
        if count == 0 {
            assert!(matches!(result, Ok(None)));
            assert_eq!(flight, before);
        } else if count > 1 || kind == 0 {
            assert!(matches!(result, Err(Error::Completion)));
            assert_eq!(flight, before);
        } else {
            assert_eq!(flight, Transmission::Idle);
            assert_eq!(result.unwrap(), if kind == 1 { None } else { Some(owner) });
        }
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
    }
}
