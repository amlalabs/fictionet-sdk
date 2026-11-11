//! Kani proofs that a UDP socket pays for what it keeps before it
//! allocates it, with every allocation counted
//! (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a child module
//! of src/stdlib/network/udp/sockets.rs, so each harness calls the
//! production `Socket::keep` on the private `Socket`.
//!
//! A socket holding zero to three datagrams of five bytes keeps one more.
//! Its queue grows from no places to four on the first, so every count
//! here grows it at most once, from none. Every length is a constant.
//!
//! The bounds, for each step:
//!
//! - **Paid before allocated**: the most bytes live at once, counting the
//!   socket from its first allocation, is at most what its budget is
//!   charged after the step, besides the budget's own state.
//! - **Linear copying**: the step asks for no more than it charged: the
//!   datagram's bytes and its chunk's header, and the places it grew by.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

const PAYLOAD: [u8; 5] = *b"hello";

/// `count` datagrams kept, then one more, as one step.
fn keep_one(count: usize) {
    let ((own, used, step, charged), cost) = measure(|| {
        let budget = Budget::new(1 << 20);
        // The budget's own state: what nothing charges.
        let own = so_far().live;
        let mut socket = Socket {
            port: 53,
            queue: ChargedDeque::new(&budget, QUEUE / DATAGRAM_COST),
            bytes: 0,
            granted: 0,
            credit: 0,
            owed: 0,
            ending: false,
            ended: false,
            queued: false,
        };
        let peer = SocketAddr::from(([10, 0, 0, 2], 1234));
        for _ in 0..count {
            assert!(socket.keep(&budget, &PAYLOAD, peer).is_ok());
        }
        let (before, used_before) = (so_far(), budget.used());
        assert!(socket.keep(&budget, &PAYLOAD, peer).is_ok());
        let after = so_far();
        let used = budget.used();
        // Dropping the socket is not the step: the proof ends with it held.
        std::mem::forget(socket);
        std::mem::forget(budget);
        (
            own,
            used,
            after.requested - before.requested,
            used - used_before,
        )
    });
    assert!(
        cost.peak <= own + used,
        "the socket held more than its budget paid"
    );
    assert!(step <= charged, "the step asked for more than it charged");
}

counted_proof! {
    /// The first datagram, which grows the queue's places from none.
    #[kani::unwind(8)]
    fn the_first_datagram_is_paid_before_it_is_kept() {
        keep_one(0);
    }
}

counted_proof! {
    /// A second, into a place already paid for.
    #[kani::unwind(8)]
    fn a_second_datagram_is_paid_before_it_is_kept() {
        keep_one(1);
    }
}

counted_proof! {
    /// The fourth, into the last of the first four places.
    #[kani::unwind(8)]
    fn a_fourth_datagram_is_paid_before_it_is_kept() {
        keep_one(3);
    }
}
