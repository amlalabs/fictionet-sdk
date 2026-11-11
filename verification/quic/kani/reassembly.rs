use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    #[kani::unwind(5)]
    fn reassembly_copy_refuses_before_allocating() {
        let budget = Budget::new(0);
        let (copy, cost) = measure(|| Compacted::new(4, Some(&budget)));
        assert!(copy.is_none());
        assert_eq!(budget.used(), 0);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget((copy, budget));
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn reassembly_copy_and_slices_fit_the_reservation() {
        let budget = Budget::new(4 + Compacted::OVERHEAD);
        let input: [u8; 4] = kani::any();
        let ((first, second), cost) = measure(|| {
            let mut copy = Compacted::new(4, Some(&budget)).unwrap();
            copy.bytes.extend_from_slice(&input);
            let bytes = Bytes::from_owner(copy);
            (bytes.slice(..2), bytes.slice(2..))
        });
        assert_eq!(&first[..], &input[..2]);
        assert_eq!(&second[..], &input[2..]);
        assert!(cost.peak <= budget.used());
        let per = 1;
        let fixed = Compacted::OVERHEAD;
        assert!(cost.requested <= per * input.len() + fixed);
        std::mem::forget((first, second, budget));
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn reassembly_descriptors_refuse_before_allocating() {
        let budget = Budget::new(0);
        let mut heap = BinaryHeap::new();
        let mut charge = Some(Charge::nothing(&budget));
        let offset: u64 = kani::any();
        let (result, cost) = measure(|| {
            push(&mut heap, &mut charge, Buffer::new(offset, Bytes::new(), 0))
        });
        assert!(result.is_err());
        assert!(heap.is_empty());
        assert_eq!(budget.used(), 0);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget((heap, charge, budget));
    }
}

counted_proof! {
    #[kani::unwind(8)]
    fn reassembly_descriptor_growth_fits_its_reservation() {
        let budget = Budget::new(12 * size_of::<Buffer>());
        let offset: u64 = kani::any();
        let ((heap, charge), cost) = measure(|| {
            let mut heap = BinaryHeap::new();
            let mut charge = Some(Charge::nothing(&budget));
            for _ in 0..5 {
                push(&mut heap, &mut charge, Buffer::new(offset, Bytes::new(), 0)).unwrap();
            }
            (heap, charge)
        });
        assert_eq!(heap.len(), 5);
        assert!(heap.iter().all(|entry| entry.offset == offset));
        assert!(cost.peak <= budget.used());
        // Initial four descriptors plus the replacement allocation of eight.
        let per = 0;
        let fixed = 12 * size_of::<Buffer>();
        assert!(cost.requested <= per * 0 + fixed);
        std::mem::forget((heap, charge, budget));
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn reassembly_empty_descriptor_growth_fits_its_reservation() {
        let budget = Budget::new(12 * size_of::<Buffer>());
        let ((heap, charge), cost) = measure(|| {
            let mut heap = BinaryHeap::new();
            let mut charge = Some(Charge::nothing(&budget));
            grow(&mut heap, &mut charge).unwrap();
            grow(&mut heap, &mut charge).unwrap();
            (heap, charge)
        });
        assert!(heap.is_empty());
        assert!(heap.capacity() >= 8);
        assert!(cost.peak <= budget.used());
        let per = 0;
        let fixed = 12 * size_of::<Buffer>();
        assert!(cost.requested <= per * 0 + fixed);
        std::mem::forget((heap, charge, budget));
    }
}
