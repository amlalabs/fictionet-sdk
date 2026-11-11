use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    #[kani::unwind(8)]
    fn http3_critical_types_are_unique_without_allocating() {
        let mut critical = Critical::default();
        let mut seen = [false; 3];
        for _ in 0..6 {
            let kind: u8 = kani::any();
            let unknown: u64 = kani::any();
            let header = match kind {
                0 => wire::StreamHeader::Control,
                1 => wire::StreamHeader::QpackEncoder,
                2 => wire::StreamHeader::QpackDecoder,
                3 => wire::StreamHeader::Push(unknown),
                _ => wire::StreamHeader::Unknown(unknown),
            };
            let (result, cost) = measure(|| critical.accept(header));
            if kind < 3 {
                assert_eq!(result, if seen[kind as usize] { Err(code::STREAM_CREATION_ERROR) } else { Ok(true) });
                seen[kind as usize] = true;
            } else {
                assert_eq!(result, if kind == 3 { Err(code::STREAM_CREATION_ERROR) } else { Ok(false) });
            }
            assert_eq!([critical.control, critical.encoder, critical.decoder], seen);
            assert!(cost.peak <= 0);
            assert!(cost.requested <= 0);
        }
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn http3_write_completion_rejects_excess_without_mutation() {
    let flight: u64 = kani::any();
    let bytes: u64 = kani::any();
    let body: u64 = kani::any();
    let pending: bool = kani::any();
    let unsent = if pending {
        Chunk::unpaid(vec![kani::any::<u8>()])
    } else {
        Chunk::default()
    };
    let mut sending = Sending {
        bytes: unsent,
        flight,
        body,
    };
    let result = sending.complete(bytes);
    if bytes > flight {
        assert_eq!(result, Err(()));
        assert_eq!(sending.flight, flight);
    } else {
        assert_eq!(sending.flight, flight - bytes);
        assert_eq!(result, Ok(bytes == flight && !pending));
    }
    assert_eq!(sending.body, body);
    std::mem::forget(sending);
}

counted_proof! {
    #[kani::unwind(4)]
    fn http3_refuses_connection_storage_before_allocating() {
        let budget = Budget::new(0);
        let mut h3 = Http3::new(Limits { streams: 2, ..Limits::default() });
        let (result, cost) = measure(|| h3.init(&budget));
        assert!(!result);
        assert!(!h3.initialized);
        assert_eq!(budget.used(), 0);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget(h3);
        std::mem::forget(budget);
    }
}
