use super::*;

#[kani::proof]
fn datagram_wire_limits_are_independent_of_storage() {
    let encoded_size: usize = kani::any();
    let window: Option<usize> = kani::any();
    let result = receive_window(encoded_size, window);
    let permitted = match window {
        Some(limit) => limit != 0 && encoded_size <= limit && encoded_size <= u16::MAX as usize,
        None => false,
    };
    assert_eq!(result.is_ok(), permitted);
    if let Ok(limit) = result {
        assert_eq!(Some(limit), window);
    }
}

use crate::counting::{counted_proof, measure};

counted_proof! {
    #[kani::unwind(6)]
    fn a_paid_datagram_moves_into_its_slot_without_allocating() {
        let payload: [u8; 4] = kani::any();
        let budget = Budget::new(4);
        let mut source = Chunk::copy_of(&budget, &payload).unwrap();
        let pointer = source.as_ptr();
        let mut slot = DatagramSlot::default();
        let (accepted, cost) = measure(|| slot.admit(&mut source, &budget));
        assert!(accepted);
        assert!(source.is_empty());
        assert_eq!(slot.0.as_ref().unwrap().as_ptr(), pointer);
        assert_eq!(&slot.0.as_ref().unwrap()[..], &payload);
        assert_eq!(budget.used(), 4);
        // The descriptor is inline and the caller already paid the backing.
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
        std::mem::forget((slot, source, budget));
    }
}

counted_proof! {
    #[kani::unwind(10)]
    fn received_datagrams_allocate_only_the_reserved_ring() {
        let payload: [u8; 4] = kani::any();
        let budget = Budget::new(64);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        let ((), cost) = measure(|| {
            assert!(incoming.push(&payload, 64));
            assert_eq!(incoming.front_len(), Some(4));
            for (actual, expected) in incoming.front(4).zip(payload) {
                assert_eq!(actual, expected);
            }
        });
        assert!(cost.peak <= budget.used());
        // The arena is allocated once at its fixed configured window;
        // payloads and their length words are copied into that storage.
        assert!(cost.requested <= 64);
        std::mem::forget((incoming, budget));
    }
}

counted_proof! {
    #[kani::unwind(2)]
    fn receive_ring_reservation_covers_its_allocation() {
        let budget = Budget::new(64);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        let (accepted, cost) = measure(|| incoming.reserve(64));
        assert!(accepted);
        assert!(cost.peak <= budget.used());
        assert!(cost.requested <= 64);
        assert!(incoming.bytes.capacity() <= budget.used());
        std::mem::forget((incoming, budget));
    }
}

counted_proof! {
    #[kani::unwind(2)]
    fn receive_ring_growth_pays_for_old_and_new_storage() {
        let budget = Budget::new(96);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        let ((), cost) = measure(|| {
            assert!(incoming.reserve(32));
            let before = crate::counting::so_far();
            assert!(incoming.reserve(64));
            let after = crate::counting::so_far();
            assert!(after.requested - before.requested <= 64);
        });
        // Growing from thirty-two to sixty-four reserves their sum until
        // the old allocation has been freed, then releases the old charge.
        assert!(cost.peak <= budget.limit());
        assert!(cost.requested <= 96);
        assert_eq!(budget.used(), 64);
        assert!(incoming.bytes.capacity() <= budget.used());
        std::mem::forget((incoming, budget));
    }
}

counted_proof! {
    #[kani::unwind(2)]
    fn receive_ring_growth_refuses_without_allocating() {
        let budget = Budget::new(64);
        let mut incoming = ReceivedDatagrams::default();
        assert!(incoming.set_budget(&budget));
        let ((), cost) = measure(|| {
            assert!(incoming.reserve(32));
            let before = crate::counting::so_far();
            assert!(!incoming.reserve(64));
            let after = crate::counting::so_far();
            assert!(after.requested - before.requested <= 0);
        });
        assert!(cost.peak <= budget.used());
        assert!(cost.requested <= 32);
        assert_eq!(budget.used(), 32);
        assert_eq!(incoming.bytes.capacity(), 32);
        std::mem::forget((incoming, budget));
    }
}
