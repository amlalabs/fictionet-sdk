//! Kani proofs that rustls's read buffer holds no more than it is charged
//! and moves what it holds a few times, not once a record, with every
//! allocation counted (verification/resources/kani/counting.rs). Compiled
//! only under `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`, as a
//! child module of rustls/src/msgs/deframer/buffers.rs, so each harness
//! calls the production `DeframerVecBuffer::resize` and builds its private
//! state.
//!
//! The step. A handshake message joined from records of one byte each,
//! sized as `DeframerVecBuffer::read` sizes the buffer for them through
//! `prepare_read`: for each record, first to its header, then to its end,
//! with the most a buffer may hold a record's while nothing is joined and
//! 64 KiB once a part is. That is what `Acceptor::read_tls` does for a
//! ClientHello sent a byte a record, which was quadratic here
//! (600,410,229 bytes asked for on 60,018 read, rustls/src/budget/costs.rs).
//! `resize` is every allocation a read makes; harnesses on `read` itself,
//! with the record headers parsed, did not finish in 20 minutes, as CBMC
//! followed every error a header may give.
//!
//! The budget. A count that refuses past its limit and records the most it
//! held at once. Its limit is any of a few: room for everything, and less
//! room than the records need at three points, so that a growth is refused
//! partway and must change nothing.
//!
//! The bounds:
//!
//! - **Within the charge**: the most bytes live at once is at most the
//!   most the budget held at once. A buffer that grows by moving to a new
//!   allocation holds the old one beside it until it is freed, and both
//!   must be paid for.
//! - **Linear copying**: the bytes asked for are at most four times the
//!   bytes the buffer was sized for, plus twice a record's header and the
//!   longest body a header here declares. The buffer grows to at least
//!   twice its capacity, so its growths together are at most twice the
//!   last, which is at most twice what it holds; a record's buffer is
//!   sized to its header before its body arrives, and a growth may start
//!   from it.
//!
//! Every length is a constant on its path: the records are concrete, and
//! their count is a constant of each harness.

use core::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::budget::{BufferBudget, Paid};
use crate::counting::{counted_proof, measure};
use crate::sync::Arc;

/// A record's header.
const HEADER: usize = 5;

/// The body each record here declares.
const DECLARED: usize = 1;

/// A count of bytes that refuses past `limit`, and the most it held.
struct Room {
    used: AtomicUsize,
    most: AtomicUsize,
    limit: usize,
}

impl BufferBudget for Room {
    fn take(&self, bytes: usize) -> bool {
        let used = self.used.load(Ordering::Relaxed);
        if used + bytes > self.limit {
            return false;
        }
        self.used.store(used + bytes, Ordering::Relaxed);
        if used + bytes > self.most.load(Ordering::Relaxed) {
            self.most.store(used + bytes, Ordering::Relaxed);
        }
        true
    }

    fn give_back(&self, bytes: usize) {
        let used = self.used.load(Ordering::Relaxed);
        self.used.store(used - bytes, Ordering::Relaxed);
    }
}

/// Sizes a buffer paid from a budget of one of a few limits for `N`
/// one-byte records joined as a message, and checks the bounds.
fn joins<const N: usize>() {
    let record = HEADER + DECLARED;
    let limit = match kani::any::<u8>() % 4 {
        0 => 1 << 16,
        1 => record * N / 2,
        2 => record * N - 1,
        _ => record * N + record,
    };
    // The budget is the caller's, made before the step.
    let room = Arc::new(Room {
        used: AtomicUsize::new(0),
        most: AtomicUsize::new(0),
        limit,
    });
    let budget: Arc<dyn BufferBudget> = room.clone();
    let (sized, cost) = measure(|| {
        let mut buffer = DeframerVecBuffer::paid_with(Paid::open(&Some(budget)));
        let mut sized = 0;
        'records: for i in 0..N {
            let most = match i {
                0 => MAX_WIRE_SIZE,
                _ => MAX_HANDSHAKE_SIZE,
            };
            for end in [record * i + HEADER, record * (i + 1)] {
                if !buffer.resize(end, most) {
                    break 'records;
                }
                sized = end;
            }
        }
        // Measured whole: dropping it frees what the step made.
        core::mem::forget(buffer);
        sized
    });
    assert!(
        cost.peak <= room.most.load(Ordering::Relaxed),
        "the buffer held more than its charge"
    );
    assert!(
        cost.requested <= 4 * sized + 2 * (HEADER + DECLARED),
        "the buffer copied what it held once a record"
    );
}

counted_proof! {
    /// One record, its header, then its body.
    #[kani::unwind(8)]
    fn reading_a_record_stays_within_its_charge() {
        joins::<1>();
    }
}

counted_proof! {
    /// A message of three records.
    #[kani::unwind(8)]
    fn joining_three_records_stays_within_its_charge() {
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
