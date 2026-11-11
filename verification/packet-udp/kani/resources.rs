//! Kani proofs that fragment reassembly holds no more than it counts, with
//! every allocation counted (verification/resources/kani/counting.rs).
//! Compiled only under `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`,
//! as a child module of src/stdlib/network/ip.rs, so each harness calls
//! the production `Reassembly` and builds its private state.
//!
//! The table holds zero, one or two unfinished packets, each one fragment
//! of eight bytes at offset 8 from 10.0.0.2, and a third fragment arrives:
//! for a new packet, or for the oldest one. The limit is set so that two
//! packets fit and a third does not, so the step makes room by dropping
//! the oldest, its own packet included when it is the oldest. Every length
//! is a constant, as the method asks.
//!
//! The bounds, for each step:
//!
//! - **Within the count**: the most bytes live at once, counting the table
//!   from its first allocation, is at most the limit and the roots of the
//!   three maps (`Reassembly::MOST_HELD` with this limit), and the packet
//!   the step takes in, which the step builds and frees.
//! - **The count is honest**: what the table holds after the step is at
//!   most what it counts and the roots.
//! - **Linear copying**: the step asks for at most twice its packet (built,
//!   then its data copied in) and one leaf for each of the three maps it
//!   may add an entry to.

use super::*;
use crate::counting::{counted_proof, measure, so_far};

/// What a new packet of one eight-byte fragment counts.
const ONE: usize = 8 + PIECE_COST + PARTIAL_COST;

/// Room for two such packets and not three.
const LIMIT: usize = 2 * ONE + ONE / 2;

/// The roots of the three maps, which no packet counts.
const ROOTS: usize = Reassembly::MOST_HELD - MAX_WAITING;

/// One IPv4 fragment's bytes: 20 bytes of header and 8 of data at offset
/// 8, more to come, identification `id`, its header checksum filled in.
fn fragment(id: u8) -> [u8; 28] {
    let mut bytes = [
        0x45, 0, 0, 28, 0, id, 0x20, 1, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1, 7, 7, 7, 7, 7, 7,
        7, 7,
    ];
    let sum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes
}

/// What building a fragment's chunk allocates: its bytes and its header.
const INPUT: usize = 28 + Chunk::HEADER;

/// `count` packets, then a fragment for packet `id`, as one step.
fn arrive(count: u8, id: u8) {
    let ((size, step), cost) = measure(|| {
        let mut r = Reassembly {
            limit: LIMIT,
            ..Reassembly::default()
        };
        for k in 0..count {
            let packet = Chunk::unpaid(fragment(k).to_vec());
            assert!(matches!(r.push(packet, Instant::ZERO), Intake::Waiting));
        }
        let before = so_far();
        let packet = Chunk::unpaid(fragment(id).to_vec());
        assert!(matches!(r.push(packet, Instant::ZERO), Intake::Waiting));
        let after = so_far();
        assert!(r.size <= r.limit);
        assert!(
            after.live <= r.size + ROOTS,
            "the table holds more than it counts"
        );
        let size = r.size;
        // Dropping the table is not the step: the proof ends with it held.
        std::mem::forget(r);
        (size, after.requested - before.requested)
    });
    assert!(size <= LIMIT);
    assert!(
        cost.peak <= LIMIT + ROOTS + INPUT,
        "the table held more than its limit"
    );
    let leaves = tree_leaf(size_of::<(Key, Partial)>())
        + tree_leaf(size_of::<(Instant, Key)>())
        + tree_leaf(size_of::<(usize, Vec<u8>)>());
    assert!(
        step <= 2 * INPUT + leaves,
        "the step asked for more than its input and the leaves"
    );
}

counted_proof! {
    /// A first packet into an empty table.
    #[kani::unwind(13)]
    fn a_fragment_into_an_empty_table_stays_within_its_count() {
        arrive(0, 0);
    }
}

counted_proof! {
    /// A second packet beside one.
    #[kani::unwind(13)]
    fn a_second_packet_stays_within_its_count() {
        arrive(1, 1);
    }
}

counted_proof! {
    /// A third packet, past the limit: the oldest is dropped first.
    #[kani::unwind(13)]
    fn a_packet_past_the_limit_makes_room_first() {
        arrive(2, 2);
    }
}
