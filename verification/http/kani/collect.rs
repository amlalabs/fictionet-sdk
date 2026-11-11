//! Kani proofs of how `Respond` collects a request body
//! (`collect_into`), with every allocation counted
//! (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a child module
//! of src/stdlib/web/httpd/http2/respond.rs. Run with
//! `-Z restrict-vtable`.
//!
//! The step. A body of eight one-byte pieces, each joined with
//! `collect_into`, as `Respond::collect` joins each DATA frame's data. The
//! pieces are a static byte: the harness allocates nothing.
//!
//! The bounds:
//!
//! - **Linear copying**: joining the body asks the allocator for at most
//!   `JOIN_PER` times its bytes. The body's storage doubles when it is
//!   full, so the sizes it asks for form a doubling series whose sum is
//!   under twice its last, and the last is under twice the body.
//! - **Within the charge**: the most bytes live at once is at most what
//!   was live before the body (the budget's own state), plus what the body
//!   is charged at the end, which is the most it is ever charged. This one
//!   is reported, not passing: `ChargedBytes` grows in place, charging
//!   only the growth, so while it reallocates the old allocation and the
//!   new one are both live with only the new one charged
//!   (`a_collected_body_stays_within_its_charge`).

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// See the module's bounds.
const JOIN_PER: usize = 4;

/// The data of one DATA frame.
static PIECE: [u8; 1] = *b"a";

/// The body, joined from eight pieces under a budget of `limit`: what was
/// live before it, the bytes it asked for, the bytes taken and its charge
/// at the end.
fn collect(limit: usize) -> ((usize, usize, usize, usize), crate::counting::Cost) {
    measure(|| {
        let budget = Budget::new(limit);
        let base = so_far().live;
        let mut body = None;
        let mut taken = 0;
        let before = so_far().requested;
        let mut join = || {
            let joined = collect_into(&mut body, &PIECE, usize::MAX, &budget);
            taken += usize::from(joined) * PIECE.len();
            joined
        };
        // Written out rather than looped, so that the unwinding bound stays
        // the small one the budget's own loops need.
        let _ = join() && join() && join() && join() && join() && join() && join() && join();
        let asked = so_far().requested - before;
        let charged = body.as_ref().map_or(0, ChargedBytes::charged);
        // Dropping the body and the budget is not the step.
        std::mem::forget((body, budget));
        (base, asked, taken, charged)
    })
}

counted_proof! {
    #[kani::unwind(3)]
    fn a_collected_body_copies_linearly() {
        let limit = if kani::any() { 1 << 12 } else { 6 };
        let ((_, asked, taken, _), _) = collect(limit);
        assert!(
            asked <= JOIN_PER * taken,
            "collecting the body copied more than its bytes allow"
        );
    }
}

counted_proof! {
    #[kani::unwind(3)]
    fn a_collected_body_stays_within_its_charge() {
        let ((base, _, _, charged), cost) = collect(1 << 12);
        assert!(
            cost.peak <= base + charged,
            "the body held more than it was charged"
        );
    }
}
