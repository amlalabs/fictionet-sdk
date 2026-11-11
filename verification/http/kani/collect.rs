//! Kani proofs of how `Respond` collects a request body
//! (`collect_into`), with every allocation counted
//! (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a child module
//! of src/stdlib/web/httpd/http2/respond.rs. Run with
//! `-Z restrict-vtable`.
//!
//! The step. A body of two one-byte pieces, each kept with
//! `collect_into`, as `Respond::collect` keeps each DATA frame's data. The
//! pieces are a static byte: the harness allocates nothing.
//!
//! The bounds. The body is kept in `ChargedSegments`, which grow by one
//! more segment and never move what they hold:
//!
//! - **No moves**: collecting a body of unknown length asks the allocator
//!   for its bytes, the room a new segment has past them (a share of what
//!   is held, at least `LEAST_SEGMENT`) and the places of its segments;
//!   a body whose `content-length` is known asks for that length and one
//!   place, once. Before, the body doubled, and each move asked for the
//!   new allocation while the old one was live.
//! - **Within the charge**: on a budget of exactly what that asks for,
//!   every piece is taken, and the most bytes live at once is at most
//!   what was live before the body (the budget's own state) plus the
//!   budget. A growth that moved would need the old allocation beside the
//!   new, which such a budget has no room for.

use super::*;
use fictionet::stdlib::layer::FIRST_PLACES;

/// The bytes of the body: two pieces of one.
const LENGTH: usize = 2;

/// What a body of unknown length asks for while it is under the least
/// segment: that segment, and the first places of the list it is in.
const UNKNOWN: usize = ChargedSegments::LEAST_SEGMENT + FIRST_PLACES * ChargedSegments::PLACE;

/// What a body of known length asks for: its length, and one place.
const KNOWN: usize = LENGTH + ChargedSegments::PLACE;

/// A budget with room for every growth many times over.
const ROOMY: usize = 1 << 12;

/// The data of one DATA frame.
static PIECE: [u8; 1] = *b"a";

use crate::counting::{counted_proof, measure, so_far};

/// The body, kept from two pieces under a budget of `limit`, its
/// length given or not: what was live before it, the bytes it asked for
/// and the bytes taken.
fn collect(limit: usize, length: Option<usize>) -> ((usize, usize, usize), crate::counting::Cost) {
    measure(|| {
        let budget = Budget::new(limit);
        let base = so_far().live;
        let mut body = None;
        let mut taken = 0;
        let before = so_far().requested;
        let mut keep = || {
            let kept = collect_into(&mut body, &PIECE, length, usize::MAX, &budget);
            taken += usize::from(kept) * PIECE.len();
            kept
        };
        // Written out rather than looped, so that the unwinding bound stays
        // the small one the budget's own loops need.
        let _ = keep() && keep();
        let asked = so_far().requested - before;
        // Dropping the body and the budget is not the step.
        std::mem::forget((body, budget));
        (base, asked, taken)
    })
}

counted_proof! {
    #[kani::unwind(3)]
    fn a_collected_body_moves_nothing() {
        let ((_, asked, taken), _) = collect(ROOMY, None);
        assert_eq!(taken, LENGTH);
        assert!(asked <= UNKNOWN, "collecting the body asked for more than its segment");
    }
}

counted_proof! {
    #[kani::unwind(3)]
    fn a_collected_body_stays_within_its_charge() {
        let ((base, asked, taken), cost) = collect(UNKNOWN, None);
        assert_eq!(taken, LENGTH, "a body that fits its charge is refused");
        assert!(cost.peak <= base + UNKNOWN, "the body held more than it was charged");
        assert!(asked <= UNKNOWN, "collecting the body asked for more than its segment");
    }
}

counted_proof! {
    #[kani::unwind(3)]
    fn a_body_of_known_length_is_reserved_once() {
        let ((base, asked, taken), cost) = collect(KNOWN, Some(LENGTH));
        assert_eq!(taken, LENGTH, "a body that fits its charge is refused");
        assert!(cost.peak <= base + KNOWN, "the body held more than it was charged");
        assert!(asked <= KNOWN, "collecting the body asked for more than its length");
    }
}
