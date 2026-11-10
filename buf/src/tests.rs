use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{Budget, Chunk, Held, Pool};

/// `bytes` in an allocation of exactly their size that `budget` pays for.
fn paid(budget: &Budget, bytes: &[u8]) -> Chunk {
    Chunk::copy_of(budget, bytes).unwrap()
}

/// `bytes` in room for `capacity` that `budget` pays for.
fn paid_with_room(budget: &Budget, bytes: &[u8], capacity: usize) -> Chunk {
    let mut room = Vec::with_capacity(capacity);
    room.extend_from_slice(bytes);
    let charge = budget.charge(room.capacity()).unwrap();
    Chunk::paid(room, charge).unwrap()
}

#[test]
fn bytes_made_from_their_charge_carry_exactly_it() {
    let budget = Budget::new(64);
    let chunk = paid_with_room(&budget, &[1, 2, 3], 8);
    assert_eq!(chunk.charged(), chunk.capacity());
    assert_eq!(budget.used(), chunk.charged());
    assert_eq!(&*chunk, &[1, 2, 3]);
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_copy_is_charged_exactly_its_bytes() {
    let budget = Budget::new(64);
    let chunk = paid(&budget, &[1, 2, 3]);
    assert_eq!((chunk.capacity(), chunk.charged()), (3, 3));
    assert_eq!(budget.used(), 3);
    assert!(Chunk::copy_of(&Budget::new(2), &[1, 2, 3]).is_none());
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

#[test]
fn repaying_within_one_budget_never_refuses_or_raises_what_it_holds() {
    // The budget is full: anything that charged before releasing would be
    // refused.
    let budget = Budget::new(4);
    let mut whole = paid(&budget, &[1, 2, 3, 4]);
    assert!(whole.repay(&budget));
    assert_eq!(budget.used(), 4);
    let mut head = whole.split_to(1);
    let allocation = head.as_ptr();
    assert!(head.repay(&budget));
    assert_eq!(head.as_ptr(), allocation, "kept, not copied");
    assert_eq!((&*head, &*whole), (&[1][..], &[2, 3, 4][..]));
    assert_eq!(budget.used(), 4);
    drop((head, whole));
    assert_eq!(budget.used(), 0);

    // Spare capacity the chunk alone holds goes back.
    let budget = Budget::new(64);
    let mut chunk = paid_with_room(&budget, &[1, 2], 64);
    assert!(chunk.repay(&budget));
    assert!(budget.used() < 64);
    assert_eq!(chunk.charged(), chunk.capacity());
    assert_eq!(budget.used(), chunk.charged());
    assert_eq!(&*chunk, &[1, 2]);
}

#[test]
fn a_refused_repay_reallocates_and_releases_nothing() {
    let from = Budget::new(64);
    let mut chunk = paid_with_room(&from, &[1, 2], 64);
    let (allocation, room) = (chunk.as_ptr(), chunk.capacity());
    assert!(!chunk.repay(&Budget::new(1)));
    assert_eq!(chunk.as_ptr(), allocation);
    assert_eq!(chunk.capacity(), room);
    assert_eq!(chunk.charged(), room);
    assert_eq!(from.used(), room);
    assert_eq!(&*chunk, &[1, 2]);
}

#[test]
fn paid_bytes_need_room_for_their_capacity() {
    let budget = Budget::new(64);
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&[1, 2]);
    let room = budget.charge(8).unwrap();
    let Err((bytes, mut room)) = Chunk::paid(bytes, room) else {
        panic!("room for less than the capacity was taken")
    };
    assert_eq!((bytes.capacity(), room.bytes()), (16, 8));
    assert!(room.grow_to(32));
    let chunk = Chunk::paid(bytes, room).unwrap();
    assert_eq!(chunk.charged(), chunk.capacity());
    assert_eq!(budget.used(), chunk.charged());
    assert_eq!(&*chunk, &[1, 2]);
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

#[test]
fn editing_unique_bytes_keeps_the_allocation_and_reservation() {
    let budget = Budget::new(8);
    let mut chunk = paid(&budget, &[1, 2, 3, 4]);
    chunk.advance(1);
    let allocation = chunk.as_ptr();
    chunk.make_mut(&Budget::new(0)).unwrap()[0] = 9;
    assert_eq!(chunk.as_ptr(), allocation);
    assert_eq!(&*chunk, &[9, 3, 4]);
    assert_eq!(budget.used(), 4);
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

#[test]
fn editing_shared_bytes_reserves_before_copying_and_preserves_siblings() {
    let budget = Budget::new(6);
    let mut tail = paid(&budget, &[1, 2, 3, 4]);
    let mut head = tail.split_to(2);
    assert!(head.make_mut(&Budget::new(1)).is_none());
    assert_eq!(&*head, &[1, 2]);
    assert_eq!(budget.used(), 4);
    head.make_mut(&budget).unwrap()[0] = 9;
    assert_eq!(&*tail, &[3, 4]);
    assert_eq!(&*head, &[9, 2]);
    assert_eq!(budget.used(), 6);
    drop(tail);
    assert_eq!(budget.used(), 2);
    drop(head);
    assert_eq!(budget.used(), 0);
}

#[test]
fn editing_in_place_needs_a_sole_owner_and_charges_nothing() {
    let mut chunk = Chunk::unpaid(vec![1, 2, 3]);
    chunk.get_mut().unwrap()[0] = 7;
    assert_eq!((&*chunk, chunk.charged()), (&[7, 2, 3][..], 0));
    let sibling = chunk.clone();
    assert!(
        chunk.get_mut().is_none(),
        "a shared backing is never written"
    );
    drop(sibling);
    assert!(chunk.get_mut().is_some());
}

#[test]
fn repaying_unique_whole_backing_reuses_its_allocation() {
    let mut chunk = Chunk::unpaid(vec![1, 2, 3, 4]);
    let allocation = chunk.as_ptr();
    assert!(!chunk.repay(&Budget::new(3)));
    assert_eq!(chunk.charged(), 0);
    let budget = Budget::new(4);
    assert!(chunk.repay(&budget));
    assert_eq!(chunk.as_ptr(), allocation);
    assert_eq!(&*chunk, &[1, 2, 3, 4]);
    assert_eq!(budget.used(), 4);
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

#[test]
fn repaying_spare_capacity_pays_for_it_first_then_keeps_only_the_bytes() {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&[1, 2]);
    let mut chunk = Chunk::unpaid(bytes);
    let (allocation, room) = (chunk.as_ptr(), chunk.capacity());
    // The allocation is paid for whole before it shrinks: room for less is
    // refused, and nothing moves.
    assert!(!chunk.repay(&Budget::new(room - 1)));
    assert_eq!((chunk.as_ptr(), chunk.capacity()), (allocation, room));
    assert_eq!(chunk.charged(), 0);
    let budget = Budget::new(room);
    assert!(chunk.repay(&budget));
    assert!(chunk.capacity() < room);
    assert_eq!(chunk.charged(), chunk.capacity());
    assert_eq!(budget.used(), chunk.charged());
    assert_eq!(&*chunk, &[1, 2]);
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

#[test]
fn repaying_shared_backing_copies_and_leaves_siblings_alone() {
    let mut tail = Chunk::unpaid(vec![1, 2, 3, 4]);
    let mut head = tail.split_to(2);
    let budget = Budget::new(2);
    assert!(head.repay(&budget));
    assert!(!head.shares(&tail));
    assert_eq!(&*head, &[1, 2]);
    assert_eq!(&*tail, &[3, 4]);
    assert_eq!(tail.charged(), 0);
    assert_eq!(budget.used(), 2);
    drop(head);
    assert_eq!(budget.used(), 0);
}

#[test]
fn repaying_whole_unique_bytes_moves_the_charge_without_copying() {
    let from = Budget::new(4);
    let to = Budget::new(4);
    let mut chunk = paid(&from, &[1, 2, 3, 4]);
    let allocation = chunk.as_ptr();
    assert!(!chunk.repay(&Budget::new(3)));
    assert_eq!(from.used(), 4, "a refused repay leaves the old charge");
    assert!(chunk.repay(&to));
    assert_eq!(chunk.as_ptr(), allocation);
    assert_eq!(&*chunk, &[1, 2, 3, 4]);
    assert_eq!((from.used(), to.used()), (0, 4));
    drop(chunk);
    assert_eq!(to.used(), 0);
}

#[test]
fn repaying_spare_capacity_elsewhere_keeps_only_the_bytes_charged() {
    let from = Budget::new(64);
    let mut chunk = paid_with_room(&from, &[1, 2], 64);
    let to = Budget::new(64);
    assert!(chunk.repay(&to));
    assert_eq!(&*chunk, &[1, 2]);
    assert_eq!(from.used(), 0);
    assert!(to.used() < 64);
    assert_eq!(chunk.charged(), to.used());
    assert_eq!(chunk.charged(), chunk.capacity());
    drop(chunk);
    assert_eq!(to.used(), 0);
}

#[test]
fn repaying_shared_bytes_elsewhere_copies_them_and_keeps_the_sibling_charged() {
    let from = Budget::new(4);
    let to = Budget::new(4);
    let mut tail = paid(&from, &[1, 2, 3, 4]);
    let mut head = tail.split_to(1);
    assert!(head.repay(&to));
    assert_eq!(&*head, &[1]);
    assert_eq!(&*tail, &[2, 3, 4]);
    assert_eq!((from.used(), to.used()), (4, 1));
    drop(tail);
    assert_eq!(from.used(), 0);
    drop(head);
    assert_eq!(to.used(), 0);
}

#[test]
fn a_slice_shares_the_backing_and_takes_nothing() {
    let budget = Budget::new(4);
    let chunk = paid(&budget, &[1, 2, 3, 4]);
    let middle = chunk.slice(1..3);
    assert_eq!(middle.as_ptr(), chunk.as_ptr().wrapping_add(1));
    assert_eq!(&*middle, &[2, 3]);
    assert_eq!(chunk.len(), 4);
    drop(chunk);
    assert_eq!(budget.used(), 4, "the slice still holds the backing");
    drop(middle);
    assert_eq!(budget.used(), 0);
}

#[test]
#[should_panic(expected = "chunk slice exceeds its remaining bytes")]
fn a_slice_past_the_end_panics() {
    let _ = Chunk::unpaid(vec![1, 2]).slice(1..3);
}

#[test]
fn editing_unreserved_bytes_accounts_for_the_backing_capacity() {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&[1, 2]);
    let mut chunk = Chunk::unpaid(bytes);
    assert!(chunk.make_mut(&Budget::new(2)).is_none());
    assert_eq!(&*chunk, &[1, 2]);
    let budget = Budget::new(32);
    chunk.make_mut(&budget).unwrap()[1] = 3;
    assert_eq!(budget.used(), 32);
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

#[test]
fn moving_into_a_window_keeps_unique_unpooled_bytes_in_place() {
    let budget = Budget::new(64);
    let window = Arc::new(budget.charge(8).unwrap());
    let mut chunk = Chunk::unpaid(vec![1, 2, 3]);
    let allocation = chunk.as_ptr();
    chunk.move_into_window(window.clone());
    assert_eq!(chunk.as_ptr(), allocation);
    assert_eq!(chunk.charged(), 8, "the window pays for it");
    let mut sibling = chunk.clone();
    sibling.move_into_window(window);
    assert!(!sibling.shares(&chunk), "shared bytes are copied");
    assert_eq!(&*sibling, &[1, 2, 3]);
}

/// A value that counts how many of its kind are alive.
struct Lease(Arc<AtomicUsize>);

impl Lease {
    fn new(alive: &Arc<AtomicUsize>) -> Lease {
        alive.fetch_add(1, Ordering::SeqCst);
        Lease(alive.clone())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Held for Lease {}

#[test]
fn held_values_stay_until_the_last_piece_and_through_copies() {
    let alive = Arc::new(AtomicUsize::new(0));
    let mut chunk = Chunk::unpaid(vec![1, 2, 3, 4]);
    assert!(chunk.hold(Lease::new(&alive)).is_ok());
    let mut head = chunk.split_to(2);
    assert!(
        head.hold(Lease::new(&alive)).is_err(),
        "a shared backing takes nothing more"
    );
    assert_eq!(alive.load(Ordering::SeqCst), 1);
    let budget = Budget::new(64);
    head.make_mut(&budget).unwrap()[0] = 9;
    drop(chunk);
    assert_eq!(alive.load(Ordering::SeqCst), 1, "the copy holds it too");
    drop(head);
    assert_eq!(alive.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// Headroom and room

#[test]
fn prepending_needs_headroom_and_a_sole_owner() {
    let budget = Budget::new(64);
    let pool = Pool::new(&budget, 16, 2);
    let mut chunk = pool.take(&budget, 4).unwrap();
    assert_eq!((chunk.headroom(), chunk.len(), chunk.room()), (4, 0, 12));
    chunk.extend_within(&[5, 6]).unwrap();
    assert!(chunk.prepend(5).is_none(), "more than the headroom");
    let sibling = chunk.clone();
    assert!(chunk.prepend(2).is_none(), "shared");
    assert_eq!((&*chunk, chunk.headroom()), (&[5, 6][..], 4));
    drop(sibling);
    chunk.prepend(2).unwrap().copy_from_slice(&[3, 4]);
    assert_eq!((&*chunk, chunk.headroom()), (&[3, 4, 5, 6][..], 2));
    let used = budget.used();
    chunk.prepend(2).unwrap().copy_from_slice(&[1, 2]);
    assert_eq!(budget.used(), used, "prepending charges nothing");
    assert_eq!(&*chunk, &[1, 2, 3, 4, 5, 6]);
    assert!(chunk.prepend(1).is_none());
}

#[test]
fn appending_stays_within_the_room_of_a_sole_owner() {
    let budget = Budget::new(64);
    let pool = Pool::new(&budget, 8, 2);
    let mut chunk = pool.take(&budget, 2).unwrap();
    assert_eq!(chunk.extend_within(&[0; 7]), Err(1));
    assert!(chunk.is_empty(), "a refused append writes nothing");
    chunk.extend_within(&[1, 2, 3]).unwrap();
    assert_eq!(
        chunk.fill(|room| {
            room[..2].copy_from_slice(&[4, 5]);
            2
        }),
        Some(2)
    );
    assert_eq!((&*chunk, chunk.room()), (&[1, 2, 3, 4, 5][..], 1));
    let sibling = chunk.clone();
    assert_eq!(chunk.extend_within(&[6]), Err(1), "shared");
    assert_eq!(
        chunk.fill(|_| unreachable!("a shared backing is never written")),
        None
    );
    drop(sibling);
    chunk.extend_within(&[6]).unwrap();
    assert_eq!(chunk.room(), 0);
}

#[test]
#[should_panic(expected = "a fill counted more than its room")]
fn a_fill_that_counts_past_its_room_panics() {
    let budget = Budget::new(64);
    let mut chunk = Pool::new(&budget, 8, 1).take(&budget, 0).unwrap();
    chunk.fill(|room| room.len() + 1);
}

// ---------------------------------------------------------------------------
// Pools

#[test]
fn a_taken_backing_is_paid_whole_by_the_taker_and_comes_back_to_the_pool() {
    let owner = Budget::new(1024);
    let taker = Budget::new(1024);
    let pool = Pool::new(&owner, 64, 4);
    assert_eq!((owner.used(), pool.free()), (0, 0), "nothing until asked");
    let mut chunk = pool.take(&taker, 8).unwrap();
    chunk.extend_within(b"hello").unwrap();
    assert_eq!((chunk.charged(), chunk.capacity()), (64, 64));
    assert_eq!((owner.used(), taker.used()), (0, 64));
    let backing = chunk.backing_id();
    drop(chunk);
    assert_eq!((pool.free(), taker.used()), (1, 0));
    assert_eq!(pool.charged(), owner.used());
    assert!(owner.used() >= 64, "the owner pays for the free backing");
    let kept = owner.used();
    let again = pool.take(&taker, 0).unwrap();
    assert_eq!(
        again.backing_id(),
        backing,
        "the same backing, header and bytes"
    );
    assert_eq!((kept - owner.used(), taker.used()), (64, 64));
    assert_eq!(pool.charged(), owner.used());
}

#[test]
fn only_the_last_piece_gives_a_backing_back() {
    let budget = Budget::new(1024);
    let pool = Pool::new(&budget, 32, 4);
    let mut chunk = pool.take(&budget, 0).unwrap();
    chunk.extend_within(&[1, 2, 3, 4]).unwrap();
    let head = chunk.split_to(1);
    let copy = chunk.clone();
    drop(chunk);
    drop(head);
    assert_eq!(pool.free(), 0, "a piece still holds it");
    assert_eq!(&*copy, &[2, 3, 4]);
    drop(copy);
    assert_eq!(pool.free(), 1);
    assert_eq!(budget.used(), pool.charged());
}

#[test]
fn a_backing_paid_elsewhere_comes_back_only_if_the_pool_can_pay() {
    let owner = Budget::new(64);
    let other = Budget::new(1024);
    let pool = Pool::new(&owner, 32, 4);
    let mut first = pool.take(&other, 0).unwrap();
    let second = pool.take(&other, 0).unwrap();
    first.extend_within(&[1]).unwrap();
    // Admitted by a third budget, as a receiver admits it.
    let third = Budget::new(1024);
    assert!(first.repay(&third));
    assert_eq!((other.used(), third.used()), (32, 32));
    drop(first);
    assert_eq!((pool.free(), third.used()), (1, 0));
    let hog = owner.charge(owner.limit() - owner.used()).unwrap();
    drop(second);
    assert_eq!(pool.free(), 1, "the owner had no room: freed, not kept");
    assert_eq!(other.used(), 0);
    drop(hog);
    assert_eq!(owner.used(), pool.charged());
}

#[test]
fn a_full_free_list_frees_what_comes_back() {
    let budget = Budget::new(1 << 16);
    let pool = Pool::new(&budget, 16, 2);
    let taken: Vec<Chunk> = (0..5).map(|_| pool.take(&budget, 0).unwrap()).collect();
    drop(taken);
    assert_eq!(pool.free(), 2);
    assert_eq!(budget.used(), pool.charged());
    assert!(pool.charged() >= 2 * 16);
}

#[test]
fn a_refused_take_changes_nothing() {
    let budget = Budget::new(64);
    let pool = Pool::new(&budget, 32, 2);
    drop(pool.take(&budget, 0).unwrap());
    assert_eq!(pool.free(), 1);
    let poor = Budget::new(16);
    let used = (budget.used(), poor.used());
    assert!(pool.take(&poor, 0).is_none());
    assert_eq!(
        (budget.used(), poor.used(), pool.free()),
        (used.0, used.1, 1)
    );
    assert!(pool.take(&budget, 33).is_none(), "headroom past the slot");
    assert_eq!(pool.free(), 1);
}

#[test]
fn a_pooled_chunk_admitted_elsewhere_moves_in_place() {
    let sender = Budget::new(1024);
    let receiver = Budget::new(1024);
    let pool = Pool::new(&sender, 64, 2);
    let mut chunk = pool.take(&sender, 16).unwrap();
    chunk.extend_within(&[1, 2, 3]).unwrap();
    let allocation = chunk.as_ptr();
    assert!(chunk.repay(&receiver));
    assert_eq!(chunk.as_ptr(), allocation, "moved, not copied");
    assert_eq!((sender.used(), receiver.used()), (0, 64));
    assert!(!chunk.repay(&Budget::new(63)), "paid whole or not at all");
    assert_eq!(receiver.used(), 64);
}

#[test]
fn a_pooled_chunk_leaving_as_a_vector_goes_back_to_its_pool() {
    let budget = Budget::new(1024);
    let pool = Pool::new(&budget, 64, 2);
    let mut chunk = pool.take(&budget, 0).unwrap();
    chunk.extend_within(&[1, 2, 3]).unwrap();
    assert_eq!(chunk.into_vec(), [1, 2, 3]);
    assert_eq!(pool.free(), 1);
}

#[test]
fn what_a_pooled_backing_held_goes_when_it_comes_back() {
    let alive = Arc::new(AtomicUsize::new(0));
    let budget = Budget::new(1024);
    let pool = Pool::new(&budget, 64, 2);
    let mut chunk = pool.take(&budget, 0).unwrap();
    assert!(chunk.hold(Lease::new(&alive)).is_ok());
    drop(chunk);
    assert_eq!((alive.load(Ordering::SeqCst), pool.free()), (0, 1));
}

#[test]
fn the_control_reserve_pays_for_control_blocks_when_the_budget_is_full() {
    let budget = Budget::new(256);
    let pool = Pool::new(&budget, 32, 4);
    assert!(pool.reserve_control(&budget, 2));
    assert_eq!(budget.used(), 64);
    // The first backing back pays for the free list's places.
    drop(pool.take_control(0).unwrap());
    assert_eq!(budget.used(), pool.charged());
    let hog = budget.charge(budget.limit() - budget.used()).unwrap();
    assert!(pool.take(&budget, 0).is_none(), "data waits for memory");
    let first = pool.take_control(0).unwrap();
    let second = pool.take_control(0).unwrap();
    assert!(pool.take_control(0).is_none(), "the reserve is spent");
    assert_eq!(budget.used(), budget.limit(), "control blocks took no more");
    drop(first);
    assert_eq!(pool.free(), 1, "a free backing counts toward the reserve");
    let third = pool.take_control(0).unwrap();
    drop((second, third));
    drop(hog);
    assert_eq!(budget.used(), pool.charged());
    assert_eq!(pool.charged(), 64 + 4 * size_of::<usize>());
    // Blocks that left with their payment leave the reserve short until it
    // is refilled through the owner's budget, and only through it.
    let elsewhere = Budget::new(1024);
    let mut gone: Vec<Chunk> = (0..2).map(|_| pool.take_control(0).unwrap()).collect();
    for chunk in &mut gone {
        assert!(chunk.repay(&elsewhere));
    }
    assert!(pool.take_control(0).is_none());
    assert!(budget.used() < 64);
    assert!(
        !pool.refill(&Budget::new(1024)),
        "another budget never pays"
    );
    assert!(pool.refill(&budget));
    assert!(pool.take_control(0).is_some());
    drop(gone);
    assert_eq!(budget.used(), pool.charged());
}

#[test]
fn a_reserve_the_budget_cannot_pay_changes_nothing() {
    let budget = Budget::new(40);
    let pool = Pool::new(&budget, 32, 2);
    let mark = budget.refusals();
    assert!(!pool.reserve_control(&budget, 2));
    assert!(
        budget.refused_since(mark),
        "the caller's view sees the refusal"
    );
    assert_eq!(budget.used(), 0);
    assert!(pool.take_control(0).is_none());
}

#[test]
fn a_pool_dropped_before_its_backings_frees_them() {
    let budget = Budget::new(1024);
    let pool = Pool::new(&budget, 32, 2);
    let chunk = pool.take(&budget, 0).unwrap();
    drop(pool.take(&budget, 0).unwrap());
    drop(pool);
    assert_eq!(budget.used(), 32, "the pool's free backing went with it");
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

// ---------------------------------------------------------------------------
// The model

/// A deterministic stream of numbers from a seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// A live chunk and the bytes the model says it shows.
struct Live {
    chunk: Chunk,
    bytes: Vec<u8>,
}

/// What each budget must hold: one charge per distinct backing it pays
/// for among the live chunks, and the pool's for its budget.
fn check(live: &[Live], budgets: &[Budget; 2], pool: &Pool, most: usize) {
    let mut seen = Vec::new();
    let mut expected = [0usize; 2];
    expected[0] += pool.charged();
    for one in live {
        assert_eq!(
            &*one.chunk,
            &one.bytes[..],
            "a view shows its model's bytes"
        );
        if one.chunk.is_pooled() {
            assert_eq!(
                one.chunk.charged(),
                one.chunk.capacity(),
                "a pooled backing is paid whole"
            );
        }
        let id = one.chunk.backing_id();
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        if let Some(payer) = one.chunk.payer() {
            let i = budgets.iter().position(|b| b.same(&payer)).unwrap();
            expected[i] += one.chunk.charged();
        }
    }
    assert_eq!([budgets[0].used(), budgets[1].used()], expected);
    assert!(pool.free() <= most);
}

#[test]
fn random_calls_keep_every_backing_paid_once_and_every_view_true() {
    const SLOT: usize = 16;
    const MOST: usize = 4;
    for seed in 0..64u64 {
        let mut rng = Rng(seed);
        let budgets = [Budget::new(10 * SLOT), Budget::new(6 * SLOT)];
        let pool = Pool::new(&budgets[0], SLOT, MOST);
        let mut live: Vec<Live> = Vec::new();
        for _ in 0..400 {
            let pick = |rng: &mut Rng, live: &[Live]| rng.below(live.len());
            match rng.below(12) {
                0 | 1 => {
                    let b = rng.below(2);
                    let headroom = rng.below(SLOT + 2);
                    let before = (budgets[0].used(), budgets[1].used(), pool.free());
                    match pool.take(&budgets[b], headroom) {
                        Some(mut chunk) => {
                            let n = rng.below(chunk.room() + 1);
                            let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                            chunk.extend_within(&bytes).unwrap();
                            live.push(Live { chunk, bytes });
                        }
                        None => assert_eq!(
                            (budgets[0].used(), budgets[1].used(), pool.free()),
                            before,
                            "a refused take changes nothing"
                        ),
                    }
                }
                2 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let copy = Live {
                        chunk: live[i].chunk.clone(),
                        bytes: live[i].bytes.clone(),
                    };
                    live.push(copy);
                }
                3 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let n = rng.below(live[i].bytes.len() + 1);
                    let chunk = live[i].chunk.split_to(n);
                    let bytes = live[i].bytes.drain(..n).collect();
                    live.push(Live { chunk, bytes });
                }
                4 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let len = live[i].bytes.len();
                    let start = rng.below(len + 1);
                    let end = start + rng.below(len - start + 1);
                    let chunk = live[i].chunk.slice(start..end);
                    let bytes = live[i].bytes[start..end].to_vec();
                    live.push(Live { chunk, bytes });
                }
                5 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let n = rng.below(live[i].bytes.len() + 1);
                    live[i].chunk.advance(n);
                    live[i].bytes.drain(..n);
                }
                6 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let n = rng.below(5);
                    let header: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                    if let Some(room) = live[i].chunk.prepend(n) {
                        room.copy_from_slice(&header);
                        live[i].bytes.splice(0..0, header);
                    }
                }
                7 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let n = rng.below(5);
                    let more: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                    if live[i].chunk.extend_within(&more).is_ok() {
                        live[i].bytes.extend_from_slice(&more);
                    }
                }
                8 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let b = rng.below(2);
                    let before = [budgets[0].used(), budgets[1].used()];
                    if !live[i].chunk.repay(&budgets[b]) {
                        assert_eq!([budgets[0].used(), budgets[1].used()], before);
                    }
                }
                9 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let b = rng.below(2);
                    let value = rng.next() as u8;
                    if let Some(bytes) = live[i].chunk.make_mut(&budgets[b])
                        && let Some(first) = bytes.first_mut()
                    {
                        *first = value;
                        live[i].bytes[0] = value;
                    }
                }
                10 if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    let one = live.swap_remove(i);
                    if rng.below(2) == 0 {
                        assert_eq!(one.chunk.into_vec(), one.bytes);
                    }
                }
                _ if !live.is_empty() => {
                    let i = pick(&mut rng, &live);
                    drop(live.swap_remove(i));
                }
                _ => {}
            }
            check(&live, &budgets, &pool, MOST);
        }
        live.clear();
        assert_eq!(budgets[0].used(), pool.charged(), "seed {seed}");
        assert_eq!(budgets[1].used(), 0, "seed {seed}");
        assert!(pool.free() <= MOST);
    }
}

#[test]
fn backings_dropped_on_many_threads_come_back_consistent() {
    const SLOT: usize = 64;
    const MOST: usize = 8;
    let budget = Budget::unlimited();
    let pool = Pool::new(&budget, SLOT, MOST);
    std::thread::scope(|scope| {
        let mut senders = Vec::new();
        for _ in 0..4 {
            let (send, receive) = std::sync::mpsc::channel::<Chunk>();
            senders.push(send);
            scope.spawn(move || {
                for chunk in receive {
                    assert_eq!(chunk.charged(), SLOT);
                    drop(chunk);
                }
            });
        }
        for i in 0..20_000usize {
            let mut chunk = pool
                .take(&budget, 0)
                .expect("an unlimited budget never refuses");
            chunk.extend_within(&i.to_le_bytes()).unwrap();
            assert_eq!(&*chunk, &i.to_le_bytes());
            senders[i % 4].send(chunk).unwrap();
        }
    });
    assert_eq!(budget.used(), pool.charged());
    assert!(pool.free() <= MOST);
}
