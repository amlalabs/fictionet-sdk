//! Kani proofs over the parts of the layer foundation that hold state of
//! their own: the child slots of a mux, the budget, its charges and the
//! containers they pay for, a layer's timers, and stream credit over chunks.
//! Compiled only under `cargo kani`, as a child module of
//! `src/stdlib/layer/mod.rs`, so every harness calls the production code
//! through its public API.
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
/// first, a growth or a shrink of the split part, and the three dropped in
/// any order. At every step the budget's count is the sum of the live
/// charges and never past the limit; a split moves bytes without changing
/// the total, and refuses, changing nothing, when the charge holds less; a
/// refused growth changes nothing, and a shrink always gives back what it
/// lets go; every charge is given back when dropped, so the count ends at
/// zero.
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
        if kani::any() {
            let grew = split.grow_to(to as usize);
            assert_eq!(
                grew,
                to as usize <= was || others + to as usize <= limit as usize
            );
            assert_eq!(split.bytes(), if grew { was.max(to as usize) } else { was });
        } else {
            split.shrink_to(to as usize);
            assert_eq!(split.bytes(), was.min(to as usize));
        }
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

/// `Charge::grow_to` and `Charge::shrink_to` on a charge taken from the
/// budget keep the budget's count equal to the sum of its charges and never
/// past the limit: a growth that would pass it is refused and changes
/// nothing, a shrink always fits, and dropping a charge gives it back.
/// Moved here from the serving engine's proofs, which checked the budget
/// its connections were charged to.
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
        if kani::any() {
            let grew = a.grow_to(to as usize);
            assert_eq!(
                grew,
                to as usize <= was || held - was + to as usize <= limit as usize
            );
            assert_eq!(a.bytes(), if grew { was.max(to as usize) } else { was });
        } else {
            a.shrink_to(to as usize);
            assert_eq!(a.bytes(), was.min(to as usize));
        }
        assert_eq!(budget.used(), held - was + a.bytes());
        assert!(budget.used() <= budget.limit());
        drop(a);
        assert_eq!(budget.used(), b.as_ref().map_or(0, Charge::bytes));
    }
    drop(b);
    assert_eq!(budget.used(), 0);
}

/// A charge within a range takes its end if that fits, else all the room
/// left if that covers its start, else nothing, changing nothing but the
/// count of refusals. Over every `u8` limit, charge held and range.
#[kani::proof]
#[kani::unwind(3)]
fn charge_within_takes_what_fits_or_nothing() {
    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);
    let held: u8 = kani::any();
    kani::assume(held <= limit);
    let _held = budget.charge(held as usize).unwrap();
    let (start, end): (u8, u8) = (kani::any(), kani::any());
    kani::assume(start <= end);
    let room = (limit - held) as usize;
    let mark = budget.refusals();
    match budget.charge_within(start as usize..=end as usize) {
        Some(charge) => {
            assert!(start as usize <= room);
            assert_eq!(charge.bytes(), (end as usize).min(room));
            assert_eq!(budget.used(), held as usize + charge.bytes());
        }
        None => {
            assert!(start as usize > room);
            assert_eq!(budget.used(), held as usize);
            assert!(budget.refused_since(mark));
        }
    }
}

/// Moving a charge within one budget changes nothing, even when the budget
/// is full and charging before releasing would be refused. Across budgets
/// the target is charged first, so a refusal changes neither count, and a
/// move takes exactly the charge from one count to the other. Over every
/// `u8` limit and size.
#[kani::proof]
#[kani::unwind(4)]
fn transfer_within_one_budget_never_raises_used() {
    let (first, second): (u8, u8) = (kani::any(), kani::any());
    let one = Budget::new(first as usize);
    let other = Budget::new(second as usize);
    let size: u8 = kani::any();
    kani::assume(size <= first);
    let mut charge = one.charge(size as usize).unwrap();
    let rest = one.charge((first - size) as usize).unwrap();
    assert!(charge.transfer(&one.clone()));
    assert_eq!(one.used(), first as usize);
    let taken: u8 = kani::any();
    kani::assume(taken <= second);
    let held = other.charge(taken as usize).unwrap();
    let moved = charge.transfer(&other);
    assert_eq!(moved, size <= second - taken);
    if moved {
        assert_eq!(one.used(), (first - size) as usize);
        assert_eq!(other.used(), taken as usize + size as usize);
        assert!(charge.budget().same(&other));
    } else {
        assert_eq!((one.used(), other.used()), (first as usize, taken as usize));
        assert!(charge.budget().same(&one));
    }
    drop((charge, rest, held));
    assert_eq!((one.used(), other.used()), (0, 0));
}

/// A runner that asks to be woken after a refusal is woken by the first
/// release that leaves room for the refused charge, once: a release that
/// leaves less wakes nothing, a later one wakes it no more, and asking
/// again before memory frees adds no second wake. A charge past the limit
/// is never woken for. Asking when nothing was refused wakes nothing, and
/// a runner asking through another view of the budget, which was not
/// refused, is never woken. Over every `u8` limit, request and release.
#[kani::proof]
#[kani::unwind(4)]
fn a_release_after_a_refusal_wakes_once() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);
    let (view, other) = (budget.view(), budget.view());
    let mut held = budget.charge(limit as usize).unwrap();
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let bystander = Arc::new(Count(AtomicUsize::new(0)));
    let waiter = Waiter::new(Waker::from(count.clone()));
    let unrefused = Waiter::new(Waker::from(bystander.clone()));
    let (mark, other_mark) = (view.refusals(), other.refusals());
    view.wake_when_freed(&waiter, mark);
    let more: u8 = kani::any();
    kani::assume(more > 0);
    assert!(view.charge(more as usize).is_none());
    view.wake_when_freed(&waiter, mark);
    view.wake_when_freed(&waiter, mark);
    // The other view was not refused: its runner waits for nothing.
    other.wake_when_freed(&unrefused, other_mark);
    assert_eq!(count.0.load(Ordering::Relaxed), 0);
    let keep: u8 = kani::any();
    kani::assume(keep < limit);
    held.shrink_to(keep as usize);
    let room = usize::from(limit - keep);
    assert_eq!(
        count.0.load(Ordering::Relaxed),
        usize::from(room >= more as usize)
    );
    drop(held);
    assert_eq!(count.0.load(Ordering::Relaxed), usize::from(more <= limit));
    assert_eq!(bystander.0.load(Ordering::Relaxed), 0);
}

/// Two views of one budget, a charge held through one and a charge of any
/// size asked through the other: the asking view records a refusal
/// exactly when the charge does not fit, and the holding view and the
/// budget's own handle record none. Over every `u8` limit and size.
#[kani::proof]
#[kani::unwind(4)]
fn a_view_records_only_its_own_refusals() {
    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);
    let (holder, asker) = (budget.view(), budget.view());
    let size: u8 = kani::any();
    kani::assume(size <= limit);
    let held = holder.charge(size as usize).unwrap();
    let marks = [&budget, &holder, &asker].map(Budget::refusals);
    let need: u8 = kani::any();
    let charged = asker.charge(need as usize);
    let fits = need <= limit - size;
    assert_eq!(charged.is_some(), fits);
    assert_eq!(asker.refused_since(marks[2]), !fits);
    assert!(asker.clone().refused_since(marks[2]) == !fits);
    assert!(!holder.refused_since(marks[1]));
    assert!(!budget.refused_since(marks[0]));
    drop((held, charged));
    assert_eq!(budget.used(), 0);
}

/// A refused charge is starved exactly when it needs more than the limit,
/// with that need and the limit, and its runner is never woken for it, not
/// even when every byte comes back. Over every `u8` limit, holding and
/// need.
#[kani::proof]
#[kani::unwind(4)]
fn starved_is_a_need_over_the_limit_and_never_wakes() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);
    let view = budget.view();
    let size: u8 = kani::any();
    kani::assume(size <= limit);
    let held = budget.charge(size as usize).unwrap();
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waiter = Waiter::new(Waker::from(count.clone()));
    let mark = view.refusals();
    let need: u16 = kani::any();
    kani::assume(usize::from(need) > usize::from(limit - size));
    assert!(view.charge(need as usize).is_none());
    let over = usize::from(need) > usize::from(limit);
    assert_eq!(
        view.starved_since(mark),
        over.then_some(Starved {
            need: need as usize,
            limit: limit as usize,
        })
    );
    view.wake_when_freed(&waiter, mark);
    drop(held);
    assert_eq!(budget.used(), 0);
    assert_eq!(count.0.load(Ordering::Relaxed), usize::from(!over));
}

// ---------------------------------------------------------------------------
// Charged containers (src/stdlib/layer/charged.rs)

/// Splitting a reservation into vector places neither charges twice nor
/// permits growth beyond the whole items that were reserved.
#[kani::proof]
#[kani::unwind(6)]
fn a_charge_becomes_bounded_vector_places() {
    let limit: u8 = kani::any();
    for bytes in [0, 3, 5] {
        let budget = Budget::new(limit as usize);
        let Some(charge) = budget.charge(bytes) else {
            assert!(bytes > limit as usize);
            assert_eq!(budget.used(), 0);
            continue;
        };
        let mut vector = ChargedVec::<u16>::from_charge(charge);
        let places = bytes / size_of::<u16>();
        assert_eq!(vector.places(), places);
        assert_eq!(budget.used(), places * size_of::<u16>());
        for _ in 0..places {
            let item: u16 = kani::any();
            assert!(vector.push(item).is_ok());
        }
        assert!(vector.push(0).is_err());
        assert_eq!(vector.charged(), budget.used());
        drop(vector);
        assert_eq!(budget.used(), 0);
    }
}

/// Bytes made from a charge are charged their capacity after every call:
/// made, grown, written past their room by a writer that is undone, written
/// within it, and trimmed, over every `u8` limit and byte. A growth the
/// budget has no room for is refused, and everything is given back when the
/// bytes are dropped. Sizes are run one by one: a symbolic allocation size
/// took the solver past the memory cap. Each pair of sizes is a harness of
/// its own: the three in one ran past 14 GiB after the buffers round.
#[kani::proof]
#[kani::unwind(7)]
fn charged_bytes_capacity_is_its_charge_from_none_to_two() {
    bytes_keep_their_cover(0, 2);
}

/// [`charged_bytes_capacity_is_its_charge_from_none_to_two`], from two
/// bytes grown to four.
#[kani::proof]
#[kani::unwind(7)]
fn charged_bytes_capacity_is_its_charge_from_two_to_four() {
    bytes_keep_their_cover(2, 4);
}

/// [`charged_bytes_capacity_is_its_charge_from_none_to_two`], from four
/// bytes asked to grow to three, which they already cover.
#[kani::proof]
#[kani::unwind(7)]
fn charged_bytes_capacity_is_its_charge_from_four_to_three() {
    bytes_keep_their_cover(4, 3);
}

fn bytes_keep_their_cover(start: usize, grown: usize) {
    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);
    let Some(mut bytes) = ChargedBytes::with_capacity(&budget, start) else {
        assert!(start > limit as usize);
        assert_eq!(budget.used(), 0);
        return;
    };
    assert_eq!(bytes.charged(), bytes.capacity());
    assert_eq!(budget.used(), start);
    assert_eq!(
        bytes.grow_to(grown),
        grown <= start || grown <= limit as usize
    );
    assert_eq!(bytes.charged(), bytes.capacity());
    assert_eq!(budget.used(), bytes.charged());
    let byte: u8 = kani::any();
    let room = bytes.room();
    let wrote = bytes.fill(|out| {
        for _ in 0..=room {
            out.push(byte);
        }
        Ok::<_, ()>(())
    });
    assert!(matches!(wrote, Err(WriteFailure::Bound)));
    assert!(bytes.is_empty());
    assert_eq!(bytes.capacity(), room);
    assert_eq!(bytes.charged(), bytes.capacity());
    assert_eq!(bytes.extend_within(&[byte]).is_ok(), room > 0);
    bytes.trim();
    assert_eq!(bytes.charged(), bytes.capacity());
    assert_eq!(budget.used(), bytes.charged());
    drop(bytes);
    assert_eq!(budget.used(), 0);
}

/// A growth that does not fit changes nothing: a charge keeps its bytes,
/// bytes keep their allocation, and a queue keeps its places, with the
/// budget's count as it was. Over every `u8` limit, charge held, growth and
/// item; allocation sizes are fixed.
#[kani::proof]
#[kani::unwind(6)]
fn a_refused_growth_changes_nothing() {
    let limit: u8 = kani::any();
    let budget = Budget::new(limit as usize);
    let held: u8 = kani::any();
    kani::assume(held <= limit);
    let other = budget.charge(held as usize).unwrap();
    let room = (limit - held) as usize;

    let mut charge = budget.charge(0).unwrap();
    let to: u8 = kani::any();
    let grew = charge.grow_to(to as usize);
    assert_eq!(grew, to as usize <= room);
    assert_eq!(charge.bytes(), if grew { to as usize } else { 0 });
    assert_eq!(budget.used(), held as usize + charge.bytes());
    drop(charge);

    if let Some(mut bytes) = ChargedBytes::with_capacity(&budget, 2) {
        let (pointer, used) = (bytes.as_ptr(), budget.used());
        let grew = bytes.grow_to(4);
        assert_eq!(grew, 2 <= room - 2);
        if !grew {
            assert_eq!(bytes.as_ptr(), pointer);
            assert_eq!(bytes.capacity(), 2);
            assert_eq!(budget.used(), used);
        }
    }

    let mut queue = ChargedDeque::<u16>::new(&budget, 4);
    let item: u16 = kani::any();
    let used = budget.used();
    match queue.push_back(item) {
        Ok(()) => assert_eq!(queue.charged(), queue.places() * size_of::<u16>()),
        Err(back) => {
            assert_eq!(back, item);
            assert_eq!((queue.len(), queue.places(), queue.charged()), (0, 0, 0));
            assert_eq!(budget.used(), used);
        }
    }
    drop((other, queue));
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
// Stream credit over chunks (src/stdlib/layer/carrier.rs; the chunk itself is
// proved in verification/buf/kani/mod.rs)

/// The longest chunk the harness builds.
const CHUNK: usize = 4;

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
    let command =
        StreamCommand::Write(ChargedBytes::copy_of(&budget, &bytes).unwrap().into_chunk());
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
