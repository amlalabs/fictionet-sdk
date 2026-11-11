use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    #[kani::unwind(5)]
    fn packet_storage_refuses_before_allocating() {
        let budget = Budget::new(0);
        let input: [u8; 4] = kani::any();
        let (packet, cost) = measure(|| PacketBuffer::copy_from(&budget, &input));
        assert!(packet.is_none());
        assert_eq!(budget.used(), 0);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget(packet);
        std::mem::forget(budget);
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn packet_storage_copy_fits_its_reservation() {
        let budget = Budget::new(4 + BACKING_OVERHEAD + OWNER_OVERHEAD);
        let input: [u8; 4] = kani::any();
        let (packet, cost) = measure(|| PacketBuffer::copy_from(&budget, &input).unwrap());
        assert_eq!(&packet[..], &input);
        assert!(cost.peak <= budget.used());
        let per = 1;
        let fixed = BACKING_OVERHEAD + OWNER_OVERHEAD;
        assert!(cost.requested <= per * input.len() + fixed);
        std::mem::forget(packet);
        std::mem::forget(budget);
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn packet_storage_prefix_and_freeze_fit_their_reservations() {
        let budget = Budget::new(4 + BACKING_OVERHEAD + 2 * OWNER_OVERHEAD);
        let input: [u8; 4] = kani::any();
        let ((head, tail), cost) = measure(|| {
            let mut packet = PacketBuffer::copy_from(&budget, &input).unwrap();
            let head = packet.split_to(2).unwrap();
            let tail = packet;
            (head.freeze(), tail.freeze())
        });
        assert_eq!(&head[..], &input[..2]);
        assert_eq!(&tail[..], &input[2..]);
        assert!(cost.peak <= budget.used());
        let per = 1;
        let fixed = BACKING_OVERHEAD + 2 * OWNER_OVERHEAD;
        assert!(cost.requested <= per * input.len() + fixed);
        std::mem::forget((head, tail));
        std::mem::forget(budget);
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn packet_storage_suffix_and_freeze_fit_their_reservations() {
        let budget = Budget::new(4 + BACKING_OVERHEAD + 2 * OWNER_OVERHEAD);
        let input: [u8; 4] = kani::any();
        let ((head, tail), cost) = measure(|| {
            let mut packet = PacketBuffer::copy_from(&budget, &input).unwrap();
            let tail = packet.split_off(2).unwrap();
            let head = packet;
            (head.freeze(), tail.freeze())
        });
        assert_eq!(&head[..], &input[..2]);
        assert_eq!(&tail[..], &input[2..]);
        assert!(cost.peak <= budget.used());
        let per = 1;
        let fixed = BACKING_OVERHEAD + 2 * OWNER_OVERHEAD;
        assert!(cost.requested <= per * input.len() + fixed);
        std::mem::forget((head, tail));
        std::mem::forget(budget);
    }
}

counted_proof! {
    #[kani::unwind(5)]
    fn packet_storage_refused_split_allocates_nothing() {
        let budget = Budget::new(4 + BACKING_OVERHEAD + OWNER_OVERHEAD);
        let input: [u8; 4] = kani::any();
        let mut packet = PacketBuffer::copy_from(&budget, &input).unwrap();
        let before = budget.used();
        let pointer = packet.as_ptr();
        let (result, cost) = measure(|| packet.split_off(2));
        assert!(result.is_err());
        assert_eq!(&packet[..], &input);
        assert_eq!(packet.as_ptr(), pointer);
        assert_eq!(budget.used(), before);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget((packet, result));
        std::mem::forget(budget);
    }
}
