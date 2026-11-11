use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    #[kani::unwind(5)]
    fn send_empty_descriptors_fit_their_reservation() {
        let budget = Budget::new(4 * size_of::<Segment>());
        let (buffer, cost) = measure(|| {
            let mut buffer = SendBuffer::new();
            buffer.set_budget(Some(&budget));
            assert!(buffer.prepare_write());
            assert!(buffer.prepare_write());
            buffer
        });
        assert!(buffer.unacked_segments.capacity() >= 4);
        assert!(buffer.unacked_segments.is_empty());
        assert!(cost.peak <= budget.used());
        let per = 0;
        let fixed = 4 * size_of::<Segment>();
        assert!(cost.requested <= per * 0 + fixed);
        std::mem::forget((buffer, budget));
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn send_descriptors_refuse_before_allocating() {
        let budget = Budget::new(0);
        let mut buffer = SendBuffer::new();
        buffer.set_budget(Some(&budget));
        let (admitted, cost) = measure(|| buffer.prepare_write());
        assert!(!admitted);
        assert_eq!(buffer.unacked_segments.capacity(), 0);
        assert_eq!(buffer.offset(), 0);
        assert_eq!(budget.used(), 0);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget((buffer, budget));
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn send_descriptors_fit_their_reservation() {
        let budget = Budget::new(4 * size_of::<Segment>());
        let (buffer, cost) = measure(|| {
            let mut buffer = SendBuffer::new();
            buffer.set_budget(Some(&budget));
            assert!(buffer.prepare_write());
            buffer.write(b"x".as_slice().into());
            assert!(buffer.prepare_write());
            buffer
        });
        assert_eq!(buffer.get(0..1), b"x");
        assert!(cost.peak <= budget.used());
        let per = 0;
        let fixed = 4 * size_of::<Segment>();
        assert!(cost.requested <= per * 1 + fixed);
        std::mem::forget((buffer, budget));
    }
}
