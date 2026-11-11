//! Kani proofs that the layer foundation's charged containers hold no more
//! than their budget lets them, at every moment of a growth, with every
//! allocation counted (verification/resources/kani/counting.rs). Compiled
//! only under `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates
//! -Z restrict-vtable`, as a
//! child module of src/stdlib/layer/mod.rs.
//!
//! What is charged. A [`ChargedDeque`], [`ChargedVec`] or [`ChargedBytes`]
//! pays for its allocation from a [`Budget`] before it allocates (rule:
//! charge before growing, buf/src/budget.rs). Each harness gives the
//! container a budget of its own, so the budget's limit is the charge: the
//! most bytes live at any moment of a step are at most the limit, and
//! after the step they are what the budget counts.
//!
//! The step. One growth of a full container, which reallocates: a
//! reallocation counts as a new block of its full size and then the old
//! one freed (counting.rs), so for a moment both are live. The container
//! is made with its first places and filled before the step, inside the
//! measurement. Harnesses that pushed from empty through a doubling ran
//! CBMC out of 14 GiB.
//!
//! The sizes. Each limit is a constant, and the items are `u64`s, so
//! every allocation size is a constant on its path.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// The limit taken: the first four places (32 bytes) and 33 more, not
/// the old four again with even one more place (40). Before the move was
/// charged, the deque doubled to eight places with the four live, 96
/// bytes. With 16-byte items and room for the doubling (200 bytes) the
/// deque's harness ran CBMC past 30 minutes at 11 GiB, and this one, at
/// 130 bytes, passed once and once ran out of 14 GiB. The growth that
/// fits with its move is `charged_bytes_grow_within_their_budget_160`'s.
const TIGHT: usize = 65;

/// A full deque of [`FIRST_PLACES`] on a budget of `limit` alone takes one
/// more item: no moment holds more than `limit`, after the push what is
/// live is what the budget counts, and the push asks for at most the
/// places the deque is charged for after it.
fn deque_within(limit: usize) {
    let budget = Budget::new(limit);
    let ((), cost) = measure(|| {
        let mut deque: ChargedDeque<u64> =
            ChargedDeque::with_places(&budget, FIRST_PLACES, 64).unwrap();
        for _ in 0..FIRST_PLACES {
            assert!(deque.push_back(0).is_ok());
        }
        let before = so_far();
        let pushed = deque.push_back(0).is_ok();
        let after = so_far();
        assert!(
            after.live <= budget.used(),
            "the deque holds what is charged"
        );
        assert!(
            after.requested - before.requested <= budget.used(),
            "the push asked for more than the deque is charged"
        );
        if !pushed {
            assert!(
                after.requested == before.requested,
                "a refusal allocates nothing"
            );
        }
        std::mem::forget(deque);
    });
    assert!(cost.peak <= limit, "the deque held more than its budget");
}

counted_proof! {
    #[kani::unwind(10)]
    fn a_full_charged_deque_grows_within_a_tight_budget() {
        deque_within(TIGHT);
    }
}

/// As [`deque_within`], for a [`ChargedVec`].
fn vec_within(limit: usize) {
    let budget = Budget::new(limit);
    let ((), cost) = measure(|| {
        let mut items: ChargedVec<u64> =
            ChargedVec::with_places(&budget, FIRST_PLACES, 64).unwrap();
        for _ in 0..FIRST_PLACES {
            assert!(items.push(0).is_ok());
        }
        let before = so_far();
        let pushed = items.push(0).is_ok();
        let after = so_far();
        assert!(
            after.live <= budget.used(),
            "the vector holds what is charged"
        );
        assert!(
            after.requested - before.requested <= budget.used(),
            "the push asked for more than the vector is charged"
        );
        if !pushed {
            assert!(
                after.requested == before.requested,
                "a refusal allocates nothing"
            );
        }
        std::mem::forget(items);
    });
    assert!(cost.peak <= limit, "the vector held more than its budget");
}

counted_proof! {
    #[kani::unwind(10)]
    fn a_full_charged_vec_grows_within_a_tight_budget() {
        vec_within(TIGHT);
    }
}

/// What a report holds: its bytes' allocation.
fn report_heap(report: &Vec<u8>) -> Option<usize> {
    Some(report.capacity())
}

/// The bytes of each report.
const REPORT: usize = 8;

/// Reports into a store of at most four, on `bytes` of its own budget:
/// after each report what the store keeps is at most what its budget
/// counts, beside the budget's own record, and no moment holds more than
/// the budget's limit and the one report being made.
fn reports_within(bytes: usize, reports: usize) {
    let (record, cost) = measure(|| {
        let mut store: Observations<Vec<u8>> = Observations::bounded(4, bytes, report_heap);
        // The budget's record, made with the store: not charged to it.
        let record = so_far().live;
        for _ in 0..reports {
            store.observe(vec![0; REPORT]);
            assert!(
                so_far().live <= record + store.used(),
                "the store keeps more than it is charged"
            );
        }
        std::mem::forget(store);
        record
    });
    assert!(
        cost.peak <= record + bytes + REPORT,
        "the store held more than its budget and the report being made"
    );
}

counted_proof! {
    /// Room for every report and its place.
    #[kani::unwind(8)]
    fn kept_reports_are_charged_to_the_store() {
        reports_within(256, 3);
    }
}

counted_proof! {
    /// Room for one report and its place, not the next.
    #[kani::unwind(8)]
    fn reports_past_the_store_are_omitted_with_nothing_kept() {
        reports_within(REPORT + 4 * size_of::<(Vec<u8>, Charge)>(), 3);
    }
}

/// Bytes grown to `first`, then to `second`, on a budget of `limit`
/// alone: no moment holds more than `limit`.
fn bytes_within(limit: usize, first: usize, second: usize) {
    let budget = Budget::new(limit);
    let ((), cost) = measure(|| {
        let mut bytes = ChargedBytes::new(&budget);
        for to in [first, second] {
            let before = so_far();
            let grew = bytes.grow_to(to);
            let after = so_far();
            assert!(
                after.live <= budget.used(),
                "the bytes hold what is charged"
            );
            if !grew {
                assert!(
                    after.requested == before.requested,
                    "a refusal allocates nothing"
                );
            }
        }
        std::mem::forget(bytes);
    });
    assert!(cost.peak <= limit, "the bytes held more than their budget");
}

counted_proof! {
    /// Sixty bytes, then eighty: the second growth does not fit with the
    /// sixty live while they move. Before the move was charged it grew
    /// anyway, to 140 bytes live.
    #[kani::unwind(4)]
    fn charged_bytes_grow_within_their_budget_100() {
        bytes_within(100, 60, 80);
    }
}

counted_proof! {
    /// The same with room for the move.
    #[kani::unwind(4)]
    fn charged_bytes_grow_within_their_budget_160() {
        bytes_within(160, 60, 80);
    }
}
