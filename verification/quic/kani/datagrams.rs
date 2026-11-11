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
