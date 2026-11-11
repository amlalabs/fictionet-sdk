//! Kani proofs that the TCP socket's stores pay for what they hold before
//! they allocate it, with every allocation counted
//! (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -p smoltcp -Z stubbing -Z c-ffi -Z mem-predicates`, as a
//! child of `smoltcp/src/socket/tcp.rs`, so every harness calls the stores
//! themselves.
//!
//! The receive store holds zero, one or two pieces waiting out of order
//! and takes a segment that spans them, so it copies one to three pieces
//! of the segment. The send store holds zero, one or two short writes
//! gathered in a pooled block and takes one more. Every offset and length
//! is a constant.
//!
//! The bound, for each step: the most bytes live at once, counting the
//! store from its first allocation, is at most what its budget is charged
//! after the step and `PLACES`, what a socket is charged when it opens for
//! the places of its chunks and their backings' headers, besides the
//! budget's and pool's own state. The segment a step takes comes from
//! below, made before the proof counts.

use super::PLACES;
use super::rx::{RxStore, SLOT};
use super::tx::TxStore;
use crate::counting::{counted_proof, measure, so_far};
use fictionet_buf::{Budget, Chunk, Pool};

/// The window of the stores the harnesses build.
const WINDOW: usize = 64;

/// The pieces waiting before the segment: eight to twelve, and twenty to
/// twenty-four, of which the first `count`.
const WAITING: [(usize, usize); 2] = [(8, 4), (20, 4)];

/// A segment of `len` bytes at `at` from below, nothing paying for it yet.
fn from_below(at: usize, len: usize) -> Chunk {
    Chunk::unpaid(vec![at as u8; len])
}

/// `count` pieces waiting, then a segment from four to twenty-eight.
fn insert_across(count: usize) {
    let waiting: [Chunk; 2] = WAITING.map(|(at, len)| from_below(at, len));
    let segment = from_below(4, 24);
    let ((own, used), cost) = measure(|| {
        let budget = Budget::new(1 << 20);
        let pool = Pool::new(&budget, SLOT, 0);
        let own = so_far().live;
        let mut store = RxStore::new(WINDOW, budget.clone(), &pool);
        for (i, (at, _)) in WAITING.iter().enumerate().take(count) {
            assert!(store.insert(*at, &waiting[i]).is_ok());
        }
        assert!(store.insert(4, &segment).is_ok());
        let used = budget.used();
        // Dropping the store is not the step: the proof ends with it held.
        std::mem::forget((store, pool, budget));
        (own, used)
    });
    assert!(
        cost.peak <= own + used + PLACES,
        "the receive store held more than it paid for"
    );
    std::mem::forget((waiting, segment));
}

counted_proof! {
    /// A segment into an empty store: one piece copied.
    #[kani::unwind(66)]
    fn a_segment_into_an_empty_store_is_paid_for() {
        insert_across(0);
    }
}

counted_proof! {
    /// A segment across one waiting piece: two pieces copied.
    #[kani::unwind(66)]
    fn a_segment_across_a_waiting_piece_is_paid_for() {
        insert_across(1);
    }
}

counted_proof! {
    /// A segment across two waiting pieces: three pieces copied.
    #[kani::unwind(66)]
    fn a_segment_across_two_waiting_pieces_is_paid_for() {
        insert_across(2);
    }
}

/// `count` short writes, then one more, gathered into a pooled block.
fn write_short(count: usize) {
    let writes: [Chunk; 3] = [0u8, 1, 2].map(|i| Chunk::unpaid(vec![i; 5]));
    let ((own, used), cost) = measure(|| {
        let budget = Budget::new(1 << 20);
        let pool = Pool::new(&budget, SLOT, 0);
        let own = so_far().live;
        let mut store = TxStore::new(WINDOW, budget.clone(), &pool);
        for write in writes.iter().take(count + 1) {
            assert!(store.push(write.clone()).is_ok());
        }
        let used = budget.used();
        std::mem::forget((store, pool, budget));
        (own, used)
    });
    assert!(
        cost.peak <= own + used + PLACES,
        "the send store held more than it paid for"
    );
    std::mem::forget(writes);
}

counted_proof! {
    /// The first short write, which takes a pooled block.
    #[kani::unwind(8)]
    fn a_first_short_write_is_paid_for() {
        write_short(0);
    }
}

counted_proof! {
    /// A third short write, gathered after two.
    #[kani::unwind(8)]
    fn a_third_short_write_is_paid_for() {
        write_short(2);
    }
}
