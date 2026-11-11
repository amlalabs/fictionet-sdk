//! What queued packets keep alive, counted by the binary's allocator,
//! against what their queues count for them (verification/README.md,
//! "Resource properties"; the bounds are in verification/world-net/README.md,
//! "Resource properties").

use crate::common::alloc::left_allocated;
use fictionet::relay::PacketQueue;
use fictionet::stdlib::layer::Budget;
use fictionet::{Interface, PACKET_COST, Packet, pair_with_limit};

/// The bytes of one block of a cable's channel (std's list flavor of
/// `mpsc`): 31 slots, each a packet and its state word, and the link to
/// the next block.
const BLOCK: usize = 31 * (size_of::<Packet>() + size_of::<usize>()) + size_of::<usize>();

/// What a cable's channel keeps allocated beside its slots' share: the
/// block it reads from and the one it writes to, each partly empty, and
/// the next one, made before the last slot of a block is written.
const CABLE_BLOCKS: usize = 3 * BLOCK;

/// Packet counts that fill none, one and many blocks, and their sizes.
const COUNTS: [usize; 6] = [1, 2, 31, 32, 100, 1000];
const SIZES: [usize; 3] = [0, 1, 1500];

/// A limited cable holds no more than it counts for the packets it holds,
/// each its capacity plus PACKET_COST, plus CABLE_BLOCKS. Before
/// PACKET_COST counted the packet's record, a hundred one-byte packets
/// kept 14,692 bytes alive against 6,500 counted.
#[test]
fn a_limited_cable_holds_no_more_than_it_counts() {
    for size in SIZES {
        for n in COUNTS {
            let (a, mut b) = pair_with_limit(usize::MAX);
            let ((), live) = left_allocated(|| {
                for _ in 0..n {
                    b.send(Packet::new(vec![7u8; size]));
                }
            });
            let counted = n * (size + PACKET_COST);
            assert!(
                live <= (counted + CABLE_BLOCKS) as i128,
                "{n} packets of {size} bytes keep {live} bytes alive, past {counted} \
                 counted and {CABLE_BLOCKS} for the channel's blocks"
            );
            drop((a, b));
        }
    }
}

/// A packet queue holds no more than its budget counts, packets and
/// places, as it fills, as it drains, and once empty. Before its places
/// were charged and a packet's record counted, a hundred one-byte packets
/// kept 16,868 bytes alive against 6,500 counted.
#[test]
fn a_packet_queue_holds_no_more_than_its_budget_counts() {
    for size in SIZES {
        for n in COUNTS {
            let budget = Budget::new(usize::MAX);
            let mut queue = PacketQueue::on(&budget);
            let ((), filled) = left_allocated(|| {
                for _ in 0..n {
                    assert!(queue.try_push(Packet::new(vec![7u8; size])).is_ok());
                }
            });
            assert!(
                filled <= budget.used() as i128,
                "{n} packets of {size} bytes keep {filled} bytes alive, past the \
                 {} charged",
                budget.used()
            );
            let ((), drained) = left_allocated(|| {
                for _ in 0..n / 2 {
                    drop(queue.pop());
                }
            });
            assert!(
                filled + drained <= budget.used() as i128,
                "half of {n} packets taken out: {} bytes alive, past the {} charged",
                filled + drained,
                budget.used()
            );
            let ((), emptied) = left_allocated(|| queue.clear());
            assert!(
                filled + drained + emptied <= 0,
                "an emptied queue holds nothing"
            );
            assert_eq!(budget.used(), 0);
        }
    }
}

/// A queue on a budget refuses what it cannot pay for, and what it holds
/// stays within the limit.
#[test]
fn a_full_packet_queue_holds_no_more_than_its_limit() {
    let limit = 64 << 10;
    let budget = Budget::new(limit);
    let mut queue = PacketQueue::on(&budget);
    let ((), live) = left_allocated(|| {
        let mut refused = 0;
        while refused < 8 {
            if queue.try_push(Packet::new(vec![1u8])).is_err() {
                refused += 1;
            }
        }
    });
    assert!(
        live <= limit as i128,
        "{live} bytes alive, past the {limit} limit"
    );
    assert!(budget.used() <= limit);
    queue.clear();
}
