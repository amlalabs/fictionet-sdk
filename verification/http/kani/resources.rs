//! Kani proofs that HTTP/1 head assembly holds no more than its budget
//! pays for and copies linearly, with every allocation counted
//! (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a child module
//! of src/stdlib/protocols/http1.rs, so each harness calls the production
//! `RequestStream::push` and builds its private state. Run with
//! `-Z restrict-vtable`: a block dropped gives its charge back through the
//! budget's wakers.
//!
//! What is charged. Every block a head is joined in is charged to the
//! connection's budget before it is allocated: a pool slot (`Pool::take`),
//! a block of its own (`Chunk::block`), or the largest block the budget
//! has room for (`Budget::charge_within`). The first delivery is taken as
//! it came and charged its capacity (`Chunk::repay`). So what the code
//! charges is what the budget lets it have: a harness gives the budget a
//! limit and checks that the head never held more than that, beside what
//! is uncharged by design: the budget's and the pools' own state, made
//! before the first piece, and a shared backing for each chunk live.
//!
//! The step. One head, delivered in ten pieces of `PIECE` bytes, each
//! pushed with `RequestStream::push`, until it is all joined or the budget
//! refuses a piece. The pools' slots are 4 and 8 bytes and the head limit
//! is 1 KiB, so a head passes both slots and moves through blocks of its
//! own.
//!
//! The bounds:
//!
//! - **Within the charge**: the most bytes live at once is at most what
//!   was live once the stream was made, plus the budget's limit, plus a
//!   backing for each of the three chunks live at once (the block held,
//!   the block it moves to, and the piece being pushed), plus the piece.
//! - **Linear copying**: the pushes ask the allocator for at most
//!   `JOIN_PER` times the bytes taken, plus both pool slots, plus a
//!   backing for each of the `HEAD_BLOCKS` blocks a head moves through.
//!
//! Every length is a constant on its path: the pieces have one size, and
//! the budget one of two limits.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// The pools' slots: small enough that a head passes both at once.
const SMALL: usize = 4;
const LARGE: usize = 8;

/// The head limit, which is the decoder's capacity here.
const LIMIT: usize = 1024;

/// The blocks a unit is joined in come to less than this many times its
/// bytes: a block is replaced only when full, by one at least twice what
/// it held and at most twice what it must hold, so the blocks form a
/// doubling series whose sum is under twice its last, and the last is
/// under twice the unit. A block the budget had no room to double is
/// replaced at most once more, by the largest block that fits, which is
/// at most twice the unit too, and that block is never replaced.
const JOIN_PER: usize = 4;

/// The most blocks a head of ten pieces moves through: the delivery
/// it starts in, both pool slots (passed over when a piece does not fit
/// them), the doubling blocks of its own up to the limit (128, 256, 512
/// and 1024), and one the budget had room for when it had none for
/// doubling.
const HEAD_BLOCKS: usize = 8;

/// The bytes of each of the ten pieces a head is delivered in.
const PIECE: usize = 64;

counted_proof! {
    /// A one-byte chunk allocates its byte and its backing, and the
    /// backing is within [`Chunk::HEADER`](fictionet::Chunk::HEADER).
    #[kani::unwind(4)]
    fn a_backing_is_within_its_constant() {
        let (chunk, cost) = measure(|| fictionet::Chunk::unpaid(vec![0u8]));
        std::mem::forget(chunk);
        assert!(cost.requested <= 1 + fictionet::Chunk::HEADER);
    }
}

/// A head of ten pieces, pushed into a stream whose budget is
/// `limit`, checked within the charge and with linear copying.
fn join(limit: usize) {
    let ((base, taken, asked), cost) = measure(|| {
        let budget = fictionet::Budget::new(limit);
        let small = fictionet::Pool::new(&budget, SMALL, 1);
        let large = fictionet::Pool::new(&budget, LARGE, 1);
        let mut events = RequestEvents::with_limits(Limits {
            head: LIMIT,
            body_chunk: 1,
            ..Limits::default()
        });
        events.storage(budget.clone(), small, large);
        let mut stream = RequestStream::new(events);
        assert!(stream.limit() <= LIMIT);
        let base = so_far().live;
        let (mut taken, mut asked) = (0, 0);
        // One piece: whether the stream took all of it.
        let mut push = || {
            let mut chunk = fictionet::Chunk::unpaid(vec![b'a'; PIECE]);
            let before = so_far().requested;
            let pushed = stream.push(&mut chunk);
            asked += so_far().requested - before;
            taken += pushed;
            pushed == PIECE
        };
        // Ten pieces, written out rather than looped, so that the
        // unwinding bound stays the small one the budget's own loops need.
        let _ = push()
            && push()
            && push()
            && push()
            && push()
            && push()
            && push()
            && push()
            && push()
            && push();
        // Dropping the stream and the budget is not the step, and their drop
        // glue makes the formulas larger: the proof ends with the head held.
        std::mem::forget((stream, budget));
        (base, taken, asked)
    });
    assert!(
        cost.peak <= base + limit + 3 * fictionet::Chunk::HEADER + PIECE,
        "the head held more than its budget pays for"
    );
    assert!(
        asked <= JOIN_PER * taken + SMALL + LARGE + HEAD_BLOCKS * fictionet::Chunk::HEADER,
        "joining the head copied more than its input and constants"
    );
}

counted_proof! {
    /// A roomy budget: the head is joined in doubling blocks.
    #[kani::unwind(3)]
    fn a_head_in_pieces_within_a_roomy_budget_copies_linearly() {
        join(1 << 12);
    }
}

counted_proof! {
    /// A tight budget: doubling is refused on the way (past 128 bytes at
    /// 350, past 256 at 500), and the head takes the largest block that
    /// fits, or waits.
    #[kani::unwind(3)]
    fn a_head_in_pieces_within_a_tight_budget_copies_linearly() {
        let limit = if kani::any() { 350 } else { 500 };
        join(limit);
    }
}
