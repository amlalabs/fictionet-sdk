//! Kani proofs that the TLS layer's input, while rustls joins a handshake
//! message from records, holds what its budget pays for and moves what it
//! holds a few times, not once a record, with every allocation counted
//! (verification/resources/kani/counting.rs). Compiled only under
//! `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a child module
//! of src/stdlib/services/tls/layer.rs, so each harness calls the
//! production `join` that `take_input` calls for every chunk while bytes
//! are held.
//!
//! The step. A handshake message joined from records of one byte each,
//! each record in a chunk of its own, as the security review of the
//! buffers round sent it (finding 2): the first chunk becomes the input,
//! paid for by the budget, and `join` takes each later one with the bytes
//! held so far counted as joined, as rustls's `joined()` reports them.
//! rustls itself is too large for CBMC, so the harness says what it would
//! have joined; the costed replay in tests/it/tls_costs.rs runs the layer
//! with rustls.
//!
//! The budget has room for everything. A refused charge records what it
//! needed, and a later release then reads the budget's list of runners to
//! wake, behind a lock: CBMC followed that list and the lock's spin to no
//! end (out of 10 minutes for three records). Refusals are left to the
//! replay and to the layer's tests (`a_record_without_room_waits_...`).
//!
//! The bounds:
//!
//! - **Paid**: after each record, the bytes the step has left allocated
//!   are at most what the budget is charged and one chunk's backing
//!   (`Chunk::BACKING`, which no budget pays for): the input holds nothing
//!   its budget does not pay for. That the new buffer is charged before it
//!   is made, while the old one is held, is `Join.tla`'s (`ChargeOld`) and
//!   the replay's.
//! - **Linear copying**: the bytes asked for are at most four times the
//!   bytes taken, plus twice a record, plus a backing for each buffer
//!   made and for the first record's. A new buffer has room for twice
//!   what is held, so its growths together are at most twice the last,
//!   which is at most twice what it holds; and so it makes at most
//!   `blocks(N)` buffers for `N` records.
//!
//! Every length is a constant on its path: the records are concrete, and
//! their count is a constant of each harness.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// A record of one byte: its header and the byte.
const RECORD: usize = HEADER + 1;

/// The most buffers `join` makes for `n` records of one byte, each at
/// least twice the size of the one before, from two records: one more than
/// the doublings from two records to `n`.
const fn blocks(n: usize) -> usize {
    let mut blocks = 1;
    let mut held = 2;
    while held < n {
        held *= 2;
        blocks += 1;
    }
    blocks
}

/// Joins `N` one-byte records, each in a chunk of its own, and checks the
/// bounds.
fn joins<const N: usize>() {
    // The budget is the caller's, made before the step.
    let budget = Budget::new(1 << 16);
    let ((taken, before), cost) = measure(|| {
        // The chunks the transport delivers, made first.
        let mut chunks: [Chunk; N] =
            core::array::from_fn(|_| Chunk::unpaid(vec![22u8, 3, 3, 0, 1, 7]));
        let before = so_far();
        // The first record, held as the input in a buffer of its own,
        // paid for: a copy, so that the chunks made before the step stay
        // allocated and nothing they held is counted as freed by it.
        let mut input = Chunk::copy_of(&budget, &chunks[0]).unwrap();
        let mut taken = RECORD;
        for chunk in chunks.iter_mut().skip(1) {
            let joined = input.len();
            match join(&mut input, chunk, joined, &budget) {
                Ok(Joined::Took) => taken += RECORD,
                Ok(Joined::Unpaid | Joined::Outgrew) => panic!("the budget has room"),
                // Not dropped: an error's drop reaches an I/O error's,
                // a call through a vtable CBMC follows to no end.
                Err(error) => {
                    std::mem::forget(error);
                    panic!("a record outgrew its buffer");
                }
            }
            assert!(
                so_far().live <= before.live + budget.used() + Chunk::BACKING,
                "the input held more than its budget pays for"
            );
        }
        // Measured whole: dropping them frees what the step made.
        std::mem::forget((input, chunks));
        (taken, before)
    });
    assert!(
        cost.requested - before.requested
            <= 4 * taken + 2 * RECORD + (blocks(N) + 1) * Chunk::BACKING,
        "the input copied what it held once a record"
    );
}

counted_proof! {
    /// A message of three records.
    #[kani::unwind(8)]
    fn joining_three_records_is_paid_for() {
        joins::<3>();
    }
}

counted_proof! {
    /// A message of eight records: enough that copying what is held once
    /// a record passes the linear bound.
    #[kani::unwind(12)]
    fn joining_eight_records_copies_linearly() {
        joins::<8>();
    }
}
