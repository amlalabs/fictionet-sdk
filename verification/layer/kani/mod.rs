//! Kani proofs over the parts of the layer foundation that hold state of
//! their own: the child slots of a mux, the budget and its charges, a
//! layer's timers, and the cursor of a chunk. Compiled only under
//! `cargo kani`, as a child module of `src/stdlib/layer/mod.rs`, so every
//! harness calls the production code through its public API.
//!
//! The harnesses run fixed sequences of calls over symbolic values and
//! choices. Harnesses that chose every call symbolically, with a model
//! table written at symbolic positions, took CBMC past the 10 GB memory
//! cap.

use std::time::Duration;

use super::*;
use fictionet::time::Instant;

// ---------------------------------------------------------------------------
// Slots (src/stdlib/layer/carrier.rs, `Slots`)

/// Whether `id` answers to every lookup of `slots` as a live child with
/// `value`, or to none of them.
fn answers(slots: &mut Slots<u8>, id: ChildId, value: Option<u8>) {
    assert_eq!(slots.contains(id), value.is_some());
    assert_eq!(slots.get(id).copied(), value);
    assert_eq!(slots.get_mut(id).copied(), value);
    assert_eq!(slots.ids().any(|listed| listed == id), value.is_some());
}

/// For every limit up to three and any values, `insert` takes children
/// while fewer than the limit are live and refuses after, handing the
/// value back, so `len` never passes the limit; removing a child makes
/// room for exactly one more. The limits are run one by one: a symbolic
/// limit makes the number of slots symbolic, and the solver ran out of
/// memory on the vector growing by a symbolic amount.
#[kani::proof]
#[kani::unwind(6)]
fn slots_refuse_past_the_limit() {
    for limit in 0..=3 {
        refuse_past(limit);
    }
}

fn refuse_past(limit: usize) {
    let mut slots: Slots<u8> = Slots::new(limit);
    assert_eq!(slots.limit(), limit);
    let mut first: Option<ChildId> = None;
    for i in 0..4 {
        let value: u8 = kani::any();
        match slots.insert(value) {
            Ok(child) => {
                assert!(i < limit);
                if first.is_none() {
                    first = Some(child.id());
                }
            }
            Err(back) => {
                assert!(i >= limit);
                assert_eq!(back, value);
            }
        }
        assert_eq!(slots.len(), (i + 1).min(limit));
        assert!(slots.len() <= slots.limit());
    }
    if let Some(id) = first {
        assert!(slots.remove(id).is_some());
        assert_eq!(slots.len(), limit - 1);
        assert!(slots.insert(kani::any()).is_ok());
        assert!(slots.insert(kani::any()).is_err());
    }
}

/// With two live children, either one closed and its slot given to a
/// successor: the old id answers no lookup and removes nothing, the
/// successor's id is new, the other child is untouched, and every id
/// answers again exactly while its child is live. Values are symbolic.
#[kani::proof]
#[kani::unwind(5)]
fn slots_never_answer_a_stale_id() {
    let mut slots: Slots<u8> = Slots::new(2);
    let (va, vb, vc): (u8, u8, u8) = (kani::any(), kani::any(), kani::any());
    let a = slots.insert(va).unwrap().id();
    let b = slots.insert(vb).unwrap().id();
    assert_ne!(a, b);
    let close_a: bool = kani::any();
    let (gone, gone_value, kept, kept_value) = if close_a {
        (a, va, b, vb)
    } else {
        (b, vb, a, va)
    };
    assert_eq!(slots.remove(gone), Some(gone_value));
    answers(&mut slots, gone, None);
    answers(&mut slots, kept, Some(kept_value));
    assert_eq!(slots.remove(gone), None);
    assert_eq!(slots.len(), 1);

    // The successor takes the freed slot.
    let c = slots.insert(vc).unwrap().id();
    assert_ne!(c, gone);
    assert_ne!(c, kept);
    answers(&mut slots, gone, None);
    answers(&mut slots, kept, Some(kept_value));
    answers(&mut slots, c, Some(vc));
    assert_eq!(slots.remove(gone), None);
    assert_eq!(slots.len(), 2);
    assert_eq!(slots.ids().count(), 2);

    // And its successor again.
    assert_eq!(slots.remove(c), Some(vc));
    let d = slots.insert(vc).unwrap().id();
    assert!(d != gone && d != c && d != kept);
    answers(&mut slots, gone, None);
    answers(&mut slots, c, None);
    answers(&mut slots, d, Some(vc));
}

/// An id of another connection's slots never answers, even when its slot
/// and generation are those of a live child here: both first children
/// have slot 0 and generation 0, and only the scope differs.
#[kani::proof]
#[kani::unwind(4)]
fn slots_never_answer_another_connections_id() {
    let mut here: Slots<u8> = Slots::new(2);
    let mut there: Slots<u8> = Slots::new(2);
    let mine: u8 = kani::any();
    let ours = here.insert(mine).unwrap().id();
    let theirs = there.insert(kani::any()).unwrap().id();
    assert_ne!(ours, theirs);
    answers(&mut here, theirs, None);
    assert_eq!(here.remove(theirs), None);
    answers(&mut here, ours, Some(mine));
    assert!(!there.contains(ours));
    assert_eq!(there.remove(ours), None);
    assert_eq!(here.len(), 1);
    assert_eq!(there.len(), 1);
}

// ---------------------------------------------------------------------------
// Budget and Charge (src/stdlib/layer/budget.rs)

/// Over every `u8` limit and charge sizes: two charges, a split of the
/// first, a new size for the split part, and the three dropped in any
/// order. At every step the budget's count is the sum of the live charges
/// and never past the limit; a split moves bytes without changing the
/// total, and refuses, changing nothing, when the charge holds less; a
/// refused `set` changes nothing; every charge is given back when dropped,
/// so the count ends at zero.
#[kani::proof]
#[kani::unwind(4)]
fn charges_split_and_drop_within_the_limit() {
    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);

    let first: u8 = kani::any();
    let mut a = budget.charge(first as usize);
    assert_eq!(a.is_some(), first <= limit);
    let second: u8 = kani::any();
    let mut b = budget.charge(second as usize);
    let held = |a: &Option<Charge>, b: &Option<Charge>, c: &Option<Charge>| {
        a.as_ref().map_or(0, Charge::bytes)
            + b.as_ref().map_or(0, Charge::bytes)
            + c.as_ref().map_or(0, Charge::bytes)
    };
    let mut c: Option<Charge> = None;
    assert_eq!(budget.used(), held(&a, &b, &c));
    assert!(budget.used() <= budget.limit());

    if let Some(charge) = a.as_mut() {
        let was = charge.bytes();
        let total = budget.used();
        let part: u8 = kani::any();
        c = charge.split(part as usize);
        assert_eq!(c.is_some(), part as usize <= was);
        match &c {
            Some(split) => {
                assert_eq!(split.bytes(), part as usize);
                assert_eq!(charge.bytes(), was - part as usize);
            }
            None => assert_eq!(charge.bytes(), was),
        }
        assert_eq!(budget.used(), total);
    }
    assert_eq!(budget.used(), held(&a, &b, &c));
    assert!(budget.used() <= budget.limit());

    if let Some(split) = c.as_mut() {
        let was = split.bytes();
        let others = budget.used() - was;
        let to: u8 = kani::any();
        let fits = split.set(to as usize);
        assert_eq!(fits, others + to as usize <= limit as usize);
        assert_eq!(split.bytes(), if fits { to as usize } else { was });
    }
    assert_eq!(budget.used(), held(&a, &b, &c));
    assert!(budget.used() <= budget.limit());

    // Drop the three in any order.
    for _ in 0..3 {
        match kani::any::<u8>() % 3 {
            0 => a = None,
            1 => b = None,
            _ => c = None,
        }
        assert_eq!(budget.used(), held(&a, &b, &c));
    }
    drop((a, b, c));
    assert_eq!(budget.used(), 0);
}

/// `Charge::set` on a charge taken from the budget keeps the budget's
/// count equal to the sum of its charges and never past the limit: a change
/// that would pass it is refused and changes nothing, less always fits, and
/// dropping a charge gives it back. Moved here from the serving engine's
/// proofs, which checked the budget its connections were charged to.
#[kani::proof]
#[kani::unwind(4)]
fn charges_sum_to_the_budget_and_never_pass_its_limit() {
    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);
    let first: u8 = kani::any();
    let second: u8 = kani::any();
    let a = budget.charge(first as usize);
    assert_eq!(a.is_some(), first <= limit);
    let b = budget.charge(second as usize);
    let held = a.as_ref().map_or(0, Charge::bytes) + b.as_ref().map_or(0, Charge::bytes);
    assert_eq!(budget.used(), held);
    assert!(budget.used() <= budget.limit());
    if let Some(mut a) = a {
        let was = a.bytes();
        let to: u8 = kani::any();
        let fits = a.set(to as usize);
        assert_eq!(fits, held - was + to as usize <= limit as usize);
        assert_eq!(a.bytes(), if fits { to as usize } else { was });
        assert_eq!(budget.used(), held - was + a.bytes());
        assert!(budget.used() <= budget.limit());
        drop(a);
        assert_eq!(budget.used(), b.as_ref().map_or(0, Charge::bytes));
    }
    drop(b);
    assert_eq!(budget.used(), 0);
}

// ---------------------------------------------------------------------------
// Timers (src/stdlib/layer/timers.rs)

/// A moment `t` seconds into the run. Whole seconds keep the solver away
/// from the division in `Duration::from_millis`.
fn at(t: u8) -> Instant {
    Instant::from_since_start(Duration::from_secs(t as u64))
}

// Three arms at any times up to 255 s, so a name may be armed again
// (moving it) or not: `next` is the timer with the earliest time, and of
// those with the same time, the one armed first, where arming again counts
// as a new arming; `get` is each name's last arming and `len` counts the
// names armed. The five harnesses below are every way three arms can name
// timers, up to renaming; `Timers` only compares names, so they stand for
// every sequence of three names. Symbolic names, or the five patterns in
// one harness, took the solver past the memory cap, and so did the case of
// three different names with every check at once, so it is split in two.

/// Three different names: `next` and `len`.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(minisat)]
fn timers_in_order_three_names() {
    come_due_in_order([0, 1, 2], false);
}

/// Three different names: `get`.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(minisat)]
fn timers_get_three_names() {
    let times: [u8; 3] = [kani::any(), kani::any(), kani::any()];
    let mut timers: Timers<u8> = Timers::new();
    for n in 0..3u8 {
        timers.set(n, at(times[n as usize]));
    }
    for n in 0..3u8 {
        assert!(timers.get(&n) == Some(at(times[n as usize])));
    }
    assert!(timers.get(&3) == None);
}

/// The first name armed again last.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(minisat)]
fn timers_in_order_first_armed_again() {
    come_due_in_order([0, 1, 0], true);
}

/// The second name armed again.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(minisat)]
fn timers_in_order_second_armed_again() {
    come_due_in_order([0, 1, 1], true);
}

/// The first name armed twice, then another.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(minisat)]
fn timers_in_order_first_armed_twice() {
    come_due_in_order([0, 0, 1], true);
}

/// One name armed three times.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(minisat)]
fn timers_in_order_one_name_three_times() {
    come_due_in_order([0, 0, 0], true);
}

fn come_due_in_order(names: [u8; 3], check_get: bool) {
    let times: [u8; 3] = [kani::any(), kani::any(), kani::any()];
    let mut timers: Timers<u8> = Timers::new();
    for i in 0..3 {
        timers.set(names[i], at(times[i]));
    }
    // Arming i is still in force unless the same name was armed later.
    let live = |i: usize| (i + 1..3).all(|j| names[j] != names[i]);
    // The expected first timer, as its time and name.
    let mut first: Option<(u8, u8)> = None;
    let mut count = 0;
    for i in 0..3 {
        if live(i) {
            count += 1;
            // Ties go to the earlier arming: only a strictly earlier time wins.
            if first.is_none_or(|(t, _)| times[i] < t) {
                first = Some((times[i], names[i]));
            }
        }
    }
    assert!(timers.len() == count);
    let (t, n) = first.unwrap();
    assert!(timers.next() == Some((at(t), n)));
    if check_get {
        for n in 0..3u8 {
            let last = (0..3).rev().find(|&i| names[i] == n);
            assert!(timers.get(&n) == last.map(|i| at(times[i])));
        }
    }
}

/// Two timers armed at any times; then `cancel`, `fire` at any moment, or
/// `retain`, on either name. `cancel` reports the timer was armed and
/// disarms it; `fire` disarms exactly a timer that is due and says whether
/// it did; `retain` disarms what it is told to. The other timer is left
/// alone, and `next` is then the one left, if any.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(minisat)]
fn timers_cancel_fire_and_retain_touch_one_name() {
    let (t0, t1): (u8, u8) = (kani::any(), kani::any());
    let mut timers: Timers<u8> = Timers::new();
    timers.set(0, at(t0));
    timers.set(1, at(t1));
    let name: u8 = kani::any();
    kani::assume(name < 2);
    let (mine, other, other_name) = if name == 0 {
        (t0, t1, 1u8)
    } else {
        (t1, t0, 0u8)
    };
    let gone = match kani::any::<u8>() % 3 {
        0 => {
            assert!(timers.cancel(&name));
            assert!(!timers.cancel(&name));
            true
        }
        1 => {
            let now: u8 = kani::any();
            let fired = timers.fire(&name, at(now));
            assert_eq!(fired, mine <= now);
            fired
        }
        _ => {
            timers.retain(|t| *t != name);
            true
        }
    };
    assert_eq!(timers.get(&name), if gone { None } else { Some(at(mine)) });
    assert_eq!(timers.get(&other_name), Some(at(other)));
    assert_eq!(timers.len(), if gone { 1 } else { 2 });
    if gone {
        assert_eq!(timers.next(), Some((at(other), other_name)));
    }
}

// ---------------------------------------------------------------------------
// Chunk (src/stdlib/layer/carrier.rs, `Chunk`)

/// The longest chunk the harness builds.
const CHUNK: usize = 4;

/// For any four bytes, paid for by a charge or not, two advances of any
/// lengths that fit (zero and up to the end included) leave exactly the
/// suffix after both: `len`, `is_empty` and the bytes agree with the
/// original from the cursor on. The charge does not move with the cursor
/// (it pays for the whole allocation) and is given back when the chunk is
/// dropped. The length is fixed: a symbolic allocation size took the
/// solver past the memory cap.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(minisat)]
fn a_chunk_cursor_keeps_the_rest_in_place() {
    let bytes: [u8; CHUNK] = kani::any();
    let length = CHUNK;
    let budget = Budget::new(CHUNK);
    let charged: bool = kani::any();
    let mut chunk = if charged {
        let charge = budget.charge(length).unwrap();
        Chunk::with_charge(bytes.to_vec(), charge)
    } else {
        Chunk::new(bytes.to_vec())
    };
    let cost = if charged { length } else { 0 };
    assert_eq!(chunk.len(), length);
    assert_eq!(chunk.charged(), cost);

    let mut cursor = 0usize;
    for _ in 0..2 {
        let n: usize = kani::any();
        kani::assume(n <= length - cursor);
        chunk.advance(n);
        cursor += n;
        assert_eq!(chunk.len(), length - cursor);
        assert_eq!(chunk.is_empty(), cursor == length);
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
    let mut chunk = Chunk::new(vec![0u8; length]);
    let n: usize = kani::any();
    kani::assume(n > length && n <= CHUNK + 1);
    chunk.advance(n);
}

/// Splitting for a peer window preserves both byte order and the backing
/// reservation, whichever half is released first.
#[kani::proof]
#[kani::unwind(6)]
#[kani::solver(minisat)]
fn stream_credit_splits_keep_the_allocation_owned() {
    use super::{Credited, StreamCommand};
    let bytes: [u8; CHUNK] = kani::any();
    let units: usize = kani::any();
    kani::assume(units > 0 && units < CHUNK);
    let budget = Budget::new(CHUNK);
    let command = StreamCommand::Write(Chunk::with_charge(
        bytes.to_vec(),
        budget.charge(CHUNK).unwrap(),
    ));
    let (StreamCommand::Write(prefix), Some(StreamCommand::Write(suffix))) =
        command.admit_credit(units as u64).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(prefix.len(), units);
    assert_eq!(suffix.len(), CHUNK - units);
    for i in 0..CHUNK {
        assert_eq!(
            if i < units {
                prefix[i]
            } else {
                suffix[i - units]
            },
            bytes[i]
        );
    }
    assert_eq!(budget.used(), CHUNK);
    if kani::any() {
        drop(prefix);
        assert_eq!(budget.used(), CHUNK);
        drop(suffix);
    } else {
        drop(suffix);
        assert_eq!(budget.used(), CHUNK);
        drop(prefix);
    }
    assert_eq!(budget.used(), 0);
}

/// Invalidating an owner invalidates all its work, including leases retained
/// after the owner is dropped; a successor has an independent lifetime.
#[kani::proof]
#[kani::unwind(3)]
fn work_cancellation_stays_with_its_owner() {
    let owner = WorkOwner::new();
    let first = owner.own(kani::any::<u8>());
    let second = owner.own(kani::any::<u8>());
    assert!(!first.cancelled());
    assert!(!second.cancelled());
    if kani::any() {
        owner.cancel();
    }
    drop(owner);
    let successor = WorkOwner::new();
    let next = successor.own(());
    assert!(first.cancelled());
    assert!(second.cancelled());
    assert!(!next.cancelled());
}
