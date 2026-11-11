//! Only the source admission step is measured. The caller's already-paid
//! backing and budgets are fixtures; queue and range metadata are excluded.

use super::*;
use crate::counting::{counted_proof, measure};

fn check_paid_source<const LIMIT: usize, const CAPACITY: usize>() {
    let bytes: [u8; 4] = kani::any();
    let budget = Budget::new(CAPACITY);
    let charge = budget.charge(CAPACITY).unwrap();
    let mut backing = Vec::with_capacity(CAPACITY);
    backing.extend_from_slice(&bytes);
    let mut data = Chunk::paid(backing, charge).unwrap();
    let pointer = data.as_ptr();
    let (taken, cost) = measure(|| {
        ChunkSource {
            data: &mut data,
            budget: &budget,
        }
        .pop_chunk(LIMIT)
        .unwrap()
    });
    assert_eq!(taken.0.len(), LIMIT);
    assert_eq!(taken.0.as_ptr(), pointer);
    assert_eq!(&taken.0[..], &bytes[..LIMIT]);
    assert_eq!(&data[..], &bytes[LIMIT..]);
    assert_eq!(budget.used(), CAPACITY);
    // No new storage is authorized or needed for a view of a paid backing.
    assert!(cost.peak <= 0);
    assert!(cost.requested <= 0);
    std::mem::forget((taken, data, budget));
}

counted_proof! {
    #[kani::unwind(6)]
    fn paid_partial_send_view_preserves_backing_without_allocating() {
        check_paid_source::<1, 4>();
    }
}

counted_proof! {
    #[kani::unwind(6)]
    fn paid_whole_send_view_preserves_backing_without_allocating() {
        check_paid_source::<4, 4>();
    }
}

counted_proof! {
    #[kani::unwind(6)]
    fn paid_partial_send_view_preserves_spare_capacity_without_allocating() {
        check_paid_source::<1, 8>();
    }
}

counted_proof! {
    #[kani::unwind(6)]
    fn paid_whole_send_view_preserves_spare_capacity_without_allocating() {
        check_paid_source::<4, 8>();
    }
}

counted_proof! {
    #[kani::unwind(6)]
    fn refused_send_backing_keeps_ownership_without_allocating() {
        let bytes: [u8; 4] = kani::any();
        let original = Budget::new(4);
        let unavailable = Budget::new(0);
        let mut data = Chunk::copy_of(&original, &bytes).unwrap();
        let pointer = data.as_ptr();
        let (taken, cost) = measure(|| {
            ChunkSource { data: &mut data, budget: &unavailable }.pop_chunk(4)
        });
        assert!(matches!(taken, Err(WriteError::Budget)));
        assert_eq!(&data[..], &bytes);
        assert_eq!(data.as_ptr(), pointer);
        assert_eq!(original.used(), 4);
        assert_eq!(unavailable.used(), 0);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget((taken, data, original, unavailable));
    }
}
