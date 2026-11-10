//! Kani proofs over `fictionet-buf`: a chunk's cursor, its pieces, its
//! headroom, and what pays for a pooled backing. Compiled only under
//! `cargo kani -p fictionet-buf`, as a child module of `buf/src/lib.rs`, so
//! every harness calls the production code through its public API.
//!
//! The harnesses run fixed sequences of calls over symbolic values and
//! choices, with backings of a fixed size: a symbolic allocation size took
//! the solver past the memory cap in the layer proofs these come from.

use super::*;

/// The longest chunk the harnesses build, and the size of a pool's slot.
const CHUNK: usize = 4;

#[kani::proof]
#[kani::unwind(3)]
fn empty_views_do_not_need_a_backing_or_a_charge() {
    let budget = Budget::new(0);
    let mut chunk = Chunk::default();
    if kani::any() {
        chunk = chunk.clone();
    }
    if kani::any() {
        chunk = chunk.split_to(0);
    }
    assert!(chunk.repay(&budget));
    assert!(chunk.make_mut(&budget).unwrap().is_empty());
    assert!(chunk.prepend(0).unwrap().is_empty());
    assert!(chunk.extend_within(&[]).is_ok());
    assert_eq!(chunk.capacity(), 0);
    assert_eq!(chunk.charged(), 0);
    assert_eq!(budget.used(), 0);
    assert!(chunk.into_vec().is_empty());
}

// ---------------------------------------------------------------------------
// The cursor and pieces

/// For any four bytes, paid for by a charge or not, two advances of any
/// lengths that fit (zero and up to the end included) leave exactly the
/// suffix after both: `len`, `is_empty` and the bytes agree with the
/// original from the cursor on. The charge does not move with the cursor
/// (it pays for the whole allocation) and is given back when the chunk is
/// dropped.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(minisat)]
fn a_chunk_cursor_keeps_the_rest_in_place() {
    let bytes: [u8; CHUNK] = kani::any();
    let budget = Budget::new(CHUNK);
    let charged: bool = kani::any();
    let mut chunk = if charged {
        Chunk::copy_of(&budget, &bytes).unwrap()
    } else {
        Chunk::unpaid(bytes.to_vec())
    };
    let cost = if charged { CHUNK } else { 0 };
    assert_eq!(chunk.len(), CHUNK);
    assert_eq!(chunk.charged(), cost);

    let mut cursor = 0usize;
    for _ in 0..2 {
        let n: usize = kani::any();
        kani::assume(n <= CHUNK - cursor);
        chunk.advance(n);
        cursor += n;
        assert_eq!(chunk.len(), CHUNK - cursor);
        assert_eq!(chunk.is_empty(), cursor == CHUNK);
        for i in 0..CHUNK {
            if i < chunk.len() {
                assert_eq!(chunk[i], bytes[cursor + i]);
            }
        }
        assert_eq!(chunk.charged(), cost);
        assert_eq!(budget.used(), cost);
    }
    drop(chunk);
    assert_eq!(budget.used(), 0);
}

/// Advancing past the end panics instead of moving the cursor anywhere.
#[kani::proof]
#[kani::should_panic]
#[kani::unwind(6)]
#[kani::solver(minisat)]
fn a_chunk_cursor_never_passes_the_end() {
    let length: usize = kani::any();
    kani::assume(length <= CHUNK);
    let mut chunk = Chunk::unpaid(vec![0u8; length]);
    let n: usize = kani::any();
    kani::assume(n > length && n <= CHUNK + 1);
    chunk.advance(n);
}

/// A split at any point gives two pieces of one backing that see the two
/// halves of the original, disjoint and in order. Editing either one
/// copies it out, charged, and leaves the other's bytes as they were;
/// the backing's charge stays until both are gone.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(minisat)]
fn split_pieces_see_disjoint_bytes_of_one_backing() {
    let bytes: [u8; CHUNK] = kani::any();
    let at: usize = kani::any();
    kani::assume(at <= CHUNK);
    let budget = Budget::new(2 * CHUNK);
    let mut suffix = Chunk::copy_of(&budget, &bytes).unwrap();
    let mut prefix = suffix.split_to(at);
    assert!(prefix.shares(&suffix));
    assert_eq!(prefix.len() + suffix.len(), CHUNK);
    for i in 0..CHUNK {
        if i < at {
            assert_eq!(prefix[i], bytes[i]);
        } else {
            assert_eq!(suffix[i - at], bytes[i]);
        }
    }
    let value: u8 = kani::any();
    let edit_prefix: bool = kani::any();
    let (edited, other) = if edit_prefix {
        (&mut prefix, &suffix)
    } else {
        (&mut suffix, &prefix)
    };
    if let Some(first) = edited.make_mut(&budget).unwrap().first_mut() {
        *first = value;
    }
    assert!(!edited.shares(other));
    for i in 0..CHUNK {
        if i < at {
            if !edit_prefix || i > 0 {
                assert_eq!(prefix[i], bytes[i]);
            }
        } else if edit_prefix || i > at {
            assert_eq!(suffix[i - at], bytes[i]);
        }
    }
    drop((prefix, suffix));
    assert_eq!(budget.used(), 0);
}

/// A copied edit preserves its sibling, is reserved before allocation, and
/// returns both reservations when the owners leave.
#[kani::proof]
#[kani::unwind(6)]
fn a_shared_chunk_edit_preserves_ownership_and_budget() {
    let bytes: [u8; 4] = kani::any();
    let value: u8 = kani::any();
    let room: bool = kani::any();
    let budget = Budget::new(if room { 6 } else { 5 });
    let mut suffix = Chunk::copy_of(&budget, &bytes).unwrap();
    let mut prefix = suffix.split_to(2);
    let edited = prefix.make_mut(&budget);
    assert_eq!(edited.is_some(), room);
    if let Some(edited) = edited {
        edited[0] = value;
    }
    assert_eq!(&*suffix, &bytes[2..]);
    assert_eq!(prefix[0], if room { value } else { bytes[0] });
    assert_eq!(prefix[1], bytes[1]);
    assert_eq!(budget.used(), if room { 6 } else { 4 });
    drop(suffix);
    assert_eq!(budget.used(), if room { 2 } else { 4 });
    drop(prefix);
    assert_eq!(budget.used(), 0);
}

/// `Chunk::repay` pays the new budget before the old one lets go, and a
/// refusal changes nothing. Four bytes of any value paid by one budget,
/// moved to another with any room left, whole (moved in place) or as a
/// two-byte piece that shares its backing (copied); and repaid to the
/// budget that pays for them already. Over every `u8` room.
#[kani::proof]
#[kani::unwind(6)]
fn a_repay_pays_before_it_lets_go_and_a_refusal_changes_nothing() {
    let bytes: [u8; 4] = kani::any();
    let room: u8 = kani::any();
    kani::assume(room <= 8);
    let from = Budget::new(4);
    let to = Budget::new(8);
    let held = to.charge(usize::from(8 - room)).unwrap();
    let whole: bool = kani::any();
    let mut chunk = Chunk::copy_of(&from, &bytes).unwrap();
    let mut rest = (!whole).then(|| chunk.split_to(2));
    let want = if whole { 4 } else { 2 };
    let (before, used_from, used_to) = (chunk.to_vec(), from.used(), to.used());

    // Repaying the budget that pays already never raises it.
    assert!(chunk.repay(&from));
    assert!(from.used() <= used_from);
    assert_eq!((&*chunk, to.used()), (&before[..], used_to));
    let used_from = from.used();

    let paid = chunk.repay(&to);
    assert_eq!(paid, want <= usize::from(room));
    assert_eq!(&*chunk, &before[..]);
    if paid {
        assert_eq!(to.used(), used_to + chunk.charged());
        assert!(chunk.charged() >= chunk.len());
        // Moved whole, the old budget lets go; copied, the piece left
        // behind keeps what it shares.
        assert_eq!(from.used(), if whole { 0 } else { used_from });
    } else {
        assert_eq!((from.used(), to.used()), (used_from, used_to));
    }
    drop(rest.take());
    drop(chunk);
    drop(held);
    assert_eq!((from.used(), to.used()), (0, 0));
}

// ---------------------------------------------------------------------------
// Headroom

/// On a pooled backing with any headroom and any bytes after it, `prepend`
/// succeeds exactly when the headroom holds the asked bytes and no other
/// piece shares the backing. On success the cursor moves back by that
/// much, the written bytes come first and the old ones follow unchanged,
/// and nothing is charged; on refusal nothing changes.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(minisat)]
fn prepend_needs_room_and_uniqueness() {
    let budget = Budget::new(4 * CHUNK);
    let pool = Pool::new(&budget, CHUNK, 1);
    let headroom: usize = kani::any();
    kani::assume(headroom <= CHUNK);
    let mut chunk = pool.take(&budget, headroom).unwrap();
    let body: [u8; CHUNK] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= CHUNK - headroom);
    chunk.extend_within(&body[..len]).unwrap();
    let shared: bool = kani::any();
    let sibling = shared.then(|| chunk.clone());
    let n: usize = kani::any();
    kani::assume(n <= CHUNK + 1);
    let header: u8 = kani::any();
    let used = budget.used();
    match chunk.prepend(n) {
        Some(room) => {
            assert!(n <= headroom && !shared);
            assert_eq!(room.len(), n);
            room.fill(header);
            assert_eq!(chunk.headroom(), headroom - n);
            assert_eq!(chunk.len(), n + len);
            for i in 0..CHUNK {
                if i < n {
                    assert_eq!(chunk[i], header);
                } else if i < n + len {
                    assert_eq!(chunk[i], body[i - n]);
                }
            }
        }
        None => {
            assert!(n > headroom || shared);
            assert_eq!((chunk.headroom(), chunk.len()), (headroom, len));
        }
    }
    assert_eq!(budget.used(), used);
    drop(sibling);
}

// ---------------------------------------------------------------------------
// Pools

/// A pooled backing is paid for at its full size by exactly one budget at
/// every instant, whatever path it takes: taken by either budget, admitted
/// by either, shared or not, its pieces dropped in either order, and back
/// in the pool or freed. After every step the two budgets together hold
/// the pool's charge plus one slot while a piece lives, and the live
/// chunk's charge is its capacity.
#[kani::proof]
#[kani::unwind(6)]
fn a_pooled_backing_is_charged_to_one_budget_at_every_instant() {
    let owner = Budget::new(4 * CHUNK);
    let other = Budget::new(4 * CHUNK);
    let pool = Pool::new(&owner, CHUNK, 1);
    let total = || owner.used() + other.used();
    let by_owner: bool = kani::any();
    let taker = if by_owner { &owner } else { &other };
    let mut chunk = pool.take(taker, 0).unwrap();
    assert_eq!((chunk.charged(), chunk.capacity()), (CHUNK, CHUNK));
    assert_eq!(total(), pool.charged() + CHUNK);

    if kani::any() {
        let admitter = if kani::any() { &owner } else { &other };
        assert!(chunk.repay(admitter));
        assert_eq!(chunk.charged(), CHUNK);
        assert_eq!(total(), pool.charged() + CHUNK);
    }
    let piece = kani::any::<bool>().then(|| chunk.clone());
    if let Some(piece) = piece {
        if kani::any() {
            drop(chunk);
            assert_eq!(total(), pool.charged() + CHUNK);
            drop(piece);
        } else {
            drop(piece);
            assert_eq!(total(), pool.charged() + CHUNK);
            drop(chunk);
        }
    } else {
        drop(chunk);
    }
    assert_eq!(total(), pool.charged());
    assert_eq!(other.used(), 0);
    assert!(pool.free() <= 1);
    // A second take sees the same accounts.
    let again = pool.take(taker, 0).unwrap();
    assert_eq!(total(), pool.charged() + CHUNK);
    drop(again);
    assert_eq!(total(), pool.charged());
}

/// A backing goes back to its pool only when its last piece is dropped:
/// with any number of pieces up to three, made by cloning or splitting,
/// dropping all but one leaves the free list empty, and dropping the last
/// fills it.
#[kani::proof]
#[kani::unwind(6)]
fn recycle_happens_only_for_the_sole_owner() {
    let budget = Budget::new(4 * CHUNK);
    let pool = Pool::new(&budget, CHUNK, 2);
    let mut first = pool.take(&budget, 0).unwrap();
    first.extend_within(&[1, 2, 3, 4]).unwrap();
    let pieces: usize = kani::any();
    kani::assume((1..=3).contains(&pieces));
    let mut others = Vec::new();
    for _ in 1..pieces {
        if kani::any() {
            others.push(first.clone());
        } else {
            others.push(first.split_to(1));
        }
    }
    let first_last: bool = kani::any();
    if first_last {
        while let Some(piece) = others.pop() {
            drop(piece);
            assert_eq!(pool.free(), 0);
        }
        drop(first);
    } else {
        drop(first);
        while let Some(piece) = others.pop() {
            let last = others.is_empty();
            drop(piece);
            assert_eq!(pool.free(), usize::from(last));
        }
    }
    assert_eq!(pool.free(), 1);
    assert_eq!(budget.used(), pool.charged());
}
