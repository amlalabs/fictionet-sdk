//! The stores' resource properties (verification/README.md, "Resource
//! properties"): every step of a session, a segment taken in, bytes read,
//! a write queued or bytes acknowledged, is costed with the counting
//! allocator (verification/resources/cost.rs). What the store keeps live
//! at any moment is paid for: by the budgets that pay for its chunks, the
//! store's own and the one its packets' blocks came from, and by
//! [`FIXED`], what a socket holds besides its chunks. And the bytes the
//! session asks for stay linear in its input. The bounds and their
//! constants are in verification/tcp-store/README.md.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use fictionet_buf::{Budget, Chunk, Pool};

use super::PLACES;
use super::rx::{RxStore, SEGMENTS, SLOT, SMALL};
use super::tx::TxStore;
use crate::cost::{Charged, Costs, Linear};
use crate::storage::Assembler;

const MSS: usize = 1460;

/// What a store holds besides what its chunks' charges pay for: its
/// places and its backings' headers, which a socket is charged when it
/// opens ([`PLACES`]). Besides, the sender's pool keeps up to [`SEGMENTS`]
/// free blocks, whose headers its owner holds.
const FIXED: usize = PLACES + SEGMENTS * Chunk::HEADER;

/// A step's linear bound, held over each session's steps together
/// ([`Costs::amortized`]): a join copies bytes earlier steps brought, and
/// the step that joins charges only what the join adds, since the blocks
/// it replaces go back in the same step. The packet a segment arrives in,
/// or a write, is built inside its step: its bytes, the step's input, and
/// a chunk's header. Everything else the store allocates is charged to a
/// budget before it is allocated and counted with the step's charge: the
/// copies of pieces, the blocks for short pieces and joins, pooled slots.
/// Besides those, each new backing's header: at most one for each piece a
/// segment fills, [`SEGMENTS`] at most, and one for a join's block. A
/// store that copied what it holds on each delivery would break the sum.
const LINEAR: Linear = Linear {
    num: 1,
    den: 1,
    fixed: (SEGMENTS + 2) * Chunk::HEADER,
};

/// The byte of the peer's stream at `seq`.
fn byte(seq: usize) -> u8 {
    (seq ^ (seq >> 8) ^ (seq >> 16)) as u8
}

/// Where a segment's packet comes from.
#[derive(Clone, Copy)]
enum Source {
    /// A packet nothing pays for yet, which the store copies its piece of.
    Unpaid,
    /// A packet slot from the sender's pool, paid by the sender's budget,
    /// which the store keeps a piece of.
    Pooled,
}

/// One direction of a connection being received: the store, the
/// assembler a socket keeps beside it, and the budgets that pay.
struct Receiving {
    store: Option<RxStore>,
    holes: Assembler,
    budget: Budget,
    sender: Budget,
    pool: Pool,
    capacity: usize,
}

impl Receiving {
    fn new(capacity: usize) -> Receiving {
        let budget = Budget::new(64 << 20);
        let sender = Budget::new(64 << 20);
        Receiving {
            store: None,
            holes: Assembler::new(),
            pool: Pool::new(&sender, SLOT, SEGMENTS),
            budget,
            sender,
            capacity,
        }
    }

    /// What pays for what the store keeps: both budgets, and [`FIXED`].
    fn charge(&self) -> usize {
        self.budget.used() + self.sender.used() + FIXED
    }

    /// Opens the store, as one step: its places.
    fn open(&mut self, costs: &mut Costs) {
        let charge = self.charge();
        let (budget, pool, capacity) = (self.budget.clone(), self.pool.clone(), self.capacity);
        let store = costs.step(0, charge, LINEAR, || {
            Charged::new(RxStore::new(capacity, budget, &pool), PLACES)
        });
        self.store = Some(store);
    }

    /// A segment of `len` bytes at `offset` past the first byte not yet
    /// ready, clipped to the window, taken in as a socket does: inserted,
    /// then what became contiguous made ready.
    fn segment(&mut self, costs: &mut Costs, offset: usize, len: usize, source: Source) {
        let store = self.store.as_mut().expect("opened");
        let window = store.window();
        if offset >= window || len == 0 {
            return;
        }
        let len = len.min(window - offset);
        let input = match source {
            Source::Unpaid => 40 + len,
            Source::Pooled => SLOT,
        };
        // The packet is built inside the step: its bytes, unless the
        // sender's budget pays for them in the step, and its header.
        let built = match source {
            Source::Unpaid => 40 + len + Chunk::HEADER,
            Source::Pooled => Chunk::HEADER,
        };
        let charge = self.budget.used() + self.sender.used() + FIXED + built;
        let (pool, budget, sender, holes) =
            (&self.pool, &self.budget, &self.sender, &mut self.holes);
        costs.step(input, charge, LINEAR, || {
            let before = (budget.used(), sender.used());
            let mut packet = match source {
                Source::Unpaid => Chunk::unpaid(vec![0xee; 40 + len]),
                Source::Pooled => {
                    let mut block = pool.take(sender, 0).expect("the sender has room");
                    block.extend_within(&[0xee; 40]).unwrap();
                    block
                }
            };
            if let Source::Pooled = source {
                let bytes: Vec<u8> = (0..len).map(|i| byte(offset + i)).collect();
                packet.extend_within(&bytes).unwrap();
            } else {
                let bytes = packet.get_mut().unwrap();
                for (i, b) in bytes[40..].iter_mut().enumerate() {
                    *b = byte(offset + i);
                }
            }
            packet.advance(40);
            let saved = holes.clone();
            if let Ok(contiguous) = holes.add_then_remove_front(offset, len) {
                if store.insert(offset, &packet).is_err() {
                    *holes = saved;
                } else {
                    let mut taken = 0;
                    while taken < contiguous {
                        let chunk = store.take_contiguous().expect("contiguous bytes held");
                        taken += chunk.len();
                        store.commit(chunk);
                    }
                }
            }
            drop(packet);
            Charged::new(
                (),
                // What the step charged: the packet's slot, which the
                // sender paid for, and what the store made.
                budget.used().saturating_sub(before.0) + sender.used().saturating_sub(before.1),
            )
        });
    }

    /// The application reads up to `most` bytes, as one step.
    fn read(&mut self, costs: &mut Costs, most: usize) {
        let charge = self.charge();
        let store = self.store.as_mut().expect("opened");
        costs.step(0, charge, LINEAR, || {
            let mut want = most.min(store.len());
            while want > 0 {
                let chunk = store.pop(want).expect("ready bytes");
                want -= chunk.len();
            }
            Charged::new((), 0)
        });
    }
}

/// Random segments, reordered, duplicated and overlapping, from a byte to
/// a full MSS, from both sources, and random reads, some none while the
/// window closes: the differential test's traffic, costed.
#[test]
fn receiving_random_segments_stays_within_its_charge() {
    for seed in 0..12 {
        let mut rng = StdRng::seed_from_u64(seed);
        let capacity = [4096, 65536, 256 * 1024][seed as usize % 3];
        let mut costs = Costs::amortized(format!("rx random, seed {seed}"));
        let mut rx = Receiving::new(capacity);
        rx.open(&mut costs);
        for _ in 0..3000 {
            match rng.gen_range(0..10) {
                0..=6 => {
                    let len = match rng.gen_range(0..4) {
                        0 => rng.gen_range(1..SMALL),
                        _ => rng.gen_range(SMALL..=MSS),
                    };
                    let window = rx.store.as_ref().unwrap().window().max(1);
                    let offset = match rng.gen_range(0..3) {
                        0 => 0,
                        _ => rng.gen_range(0..window.min(16 * MSS)),
                    };
                    let source = if rng.gen_bool(0.5) {
                        Source::Unpaid
                    } else {
                        Source::Pooled
                    };
                    rx.segment(&mut costs, offset, len, source);
                }
                7 => rx.read(&mut costs, rng.gen_range(0..64)),
                _ => rx.read(&mut costs, rng.gen_range(0..4 * MSS)),
            }
        }
        eprintln!("cost: rx random, seed {seed}: {}", costs.summary());
    }
}

/// One-byte segments out of order, each with a gap after it, so none
/// becomes contiguous: every one needs a place, and past [`SEGMENTS`] the
/// store refuses them. From both sources.
#[test]
fn many_one_byte_segments_out_of_order_stay_within_their_charge() {
    for source in [Source::Unpaid, Source::Pooled] {
        let mut costs = Costs::amortized("rx one-byte, out of order");
        let mut rx = Receiving::new(64 * 1024);
        rx.open(&mut costs);
        for k in (1..2000).rev() {
            rx.segment(&mut costs, 2 * k, 1, source);
        }
        eprintln!("cost: rx one-byte, out of order: {}", costs.summary());
    }
}

/// One-byte segments in order with no reads, until the window closes:
/// each is gathered onto the last ready chunk.
#[test]
fn many_one_byte_segments_in_order_stay_within_their_charge() {
    for source in [Source::Unpaid, Source::Pooled] {
        let mut costs = Costs::amortized("rx one-byte, in order");
        let mut rx = Receiving::new(16 * 1024);
        rx.open(&mut costs);
        for _ in 0..16 * 1024 {
            rx.segment(&mut costs, 0, 1, source);
        }
        assert_eq!(rx.store.as_ref().unwrap().window(), 0);
        rx.read(&mut costs, usize::MAX);
        eprintln!("cost: rx one-byte, in order: {}", costs.summary());
    }
}

/// Full segments in order with no reads, until the window closes: past
/// [`SEGMENTS`] chunks the store joins neighbors to make room.
#[test]
fn a_slow_readers_window_joined_stays_within_its_charge() {
    for source in [Source::Unpaid, Source::Pooled] {
        let mut costs = Costs::amortized("rx joins");
        let mut rx = Receiving::new(256 * 1024);
        rx.open(&mut costs);
        while rx.store.as_ref().unwrap().window() > 0 {
            rx.segment(&mut costs, 0, MSS, source);
        }
        rx.read(&mut costs, usize::MAX);
        eprintln!("cost: rx joins: {}", costs.summary());
    }
}

/// Small out-of-order pieces of many lengths next to each other, so the
/// waiting chunks join, then the gap before them filled.
#[test]
fn contiguous_pieces_out_of_order_join_within_their_charge() {
    let mut costs = Costs::amortized("rx waiting joins");
    let mut rx = Receiving::new(256 * 1024);
    rx.open(&mut costs);
    let mut at = 64;
    let mut rng = StdRng::seed_from_u64(7);
    while at < 200 * 1024 {
        let len = rng.gen_range(1..2 * SMALL);
        rx.segment(&mut costs, at, len, Source::Unpaid);
        at += len;
    }
    rx.segment(&mut costs, 0, 64, Source::Unpaid);
    rx.read(&mut costs, usize::MAX);
    eprintln!("cost: rx waiting joins: {}", costs.summary());
}

/// Sending: writes of a byte to two MSS, from the application's own
/// blocks, partly acknowledged as they go, with the window full at times.
#[test]
fn sending_small_writes_stays_within_its_charge() {
    for seed in 0..6 {
        let mut rng = StdRng::seed_from_u64(seed);
        let capacity = [4096, 65536, 256 * 1024][seed as usize % 3];
        let budget = Budget::new(64 << 20);
        let app = Budget::new(64 << 20);
        let pool = Pool::new(&budget, SLOT, SEGMENTS);
        let mut costs = Costs::amortized(format!("tx, seed {seed}"));
        let charge = |budget: &Budget, app: &Budget| budget.used() + app.used() + FIXED;
        let mut store = costs.step(0, charge(&budget, &app), LINEAR, || {
            Charged::new(TxStore::new(capacity, budget.clone(), &pool), PLACES)
        });
        for _ in 0..3000 {
            if rng.gen_range(0..3) > 0 {
                let len = match rng.gen_range(0..3) {
                    0 => rng.gen_range(1..SMALL),
                    _ => rng.gen_range(SMALL..=2 * MSS),
                };
                // The write is made inside the step, its header with it.
                let at = charge(&budget, &app) + Chunk::HEADER;
                costs.step(len, at, LINEAR, || {
                    let before = (budget.used(), app.used());
                    let write = Chunk::copy_of(&app, &vec![3; len]).unwrap();
                    let _ = store.push(write);
                    Charged::new(
                        (),
                        budget.used().saturating_sub(before.0)
                            + app.used().saturating_sub(before.1),
                    )
                });
            } else {
                let acked = rng.gen_range(0..=store.len());
                costs.step(0, charge(&budget, &app), LINEAR, || {
                    store.ack(acked);
                    Charged::new((), 0)
                });
            }
        }
        eprintln!("cost: tx, seed {seed}: {}", costs.summary());
    }
}
