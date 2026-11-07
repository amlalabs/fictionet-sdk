//! Kani proofs over the pure parts of `serve`: the timer table, the
//! budget, the connection count and the wake handle.  Compiled only
//! under `cargo kani`, as a child module of `serve`.

use super::*;

/// Timer names, small enough for Kani to range over.
type Name = u8;

/// `arm` keeps one entry per name, at `now + d` for a set timer and none
/// for a cancelled one, and leaves other names alone; `due` finds the
/// earliest timer when it is due, and nothing otherwise.
#[kani::proof]
#[kani::unwind(6)]
fn timers_are_armed_once_and_the_earliest_is_due() {
    let now = Instant::from_since_start(Duration::from_millis(kani::any::<u16>() as u64));
    let mut timers: Vec<(Name, Instant)> = Vec::new();
    let names: [Name; 2] = [kani::any(), kani::any()];
    kani::assume(names[0] != names[1]);
    for name in names {
        timers.push((name, now + Duration::from_millis(kani::any::<u8>() as u64)));
    }
    let request: Name = kani::any();
    let set: bool = kani::any();
    let d = Duration::from_millis(kani::any::<u8>() as u64);
    let mut requests = vec![(request, if set { Some(d) } else { None })];
    let before = timers.clone();

    arm(&mut timers, &mut requests, now);

    assert!(requests.is_empty());
    for i in 0..timers.len() {
        for j in 0..timers.len() {
            assert!(i == j || timers[i].0 != timers[j].0);
        }
    }
    let armed = timers
        .iter()
        .find(|(n, _)| *n == request)
        .map(|(_, at)| *at);
    assert_eq!(armed, if set { Some(now + d) } else { None });
    for (name, at) in before {
        if name != request {
            assert!(timers.contains(&(name, at)));
        }
    }

    let at = Instant::from_since_start(Duration::from_millis(kani::any::<u16>() as u64));
    match due(&timers, at) {
        Some(i) => {
            assert!(i < timers.len());
            assert!(timers[i].1 <= at);
            for (_, other) in &timers {
                assert!(timers[i].1 <= *other);
            }
        }
        None => {
            for (_, other) in &timers {
                assert!(*other > at);
            }
        }
    }
}

/// `Charge::set` keeps the budget's count equal to the sum of its charges
/// and never past the limit: a change that would pass it is refused and
/// changes nothing, less always fits, and dropping a charge gives it back.
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

/// `Counted::enter` never counts past the maximum, and a dropped count
/// makes room for one more.
#[kani::proof]
#[kani::unwind(5)]
fn connections_are_counted_up_to_the_maximum() {
    let max: usize = kani::any();
    kani::assume(max <= 3);
    let open = Arc::new(AtomicUsize::new(0));
    let mut guards: [Option<Counted>; 4] = [None, None, None, None];
    for (i, slot) in guards.iter_mut().enumerate() {
        *slot = Counted::enter(&open, max);
        assert_eq!(slot.is_some(), i < max);
        assert_eq!(open.load(Ordering::SeqCst), (i + 1).min(max));
    }
    if max > 0 {
        guards[max - 1] = None;
        assert_eq!(open.load(Ordering::SeqCst), max - 1);
        assert!(Counted::enter(&open, max).is_some());
    }
}

/// A wake handle: a wake before or after the driver's poll makes the poll
/// ready, `take` reports it once, and a closed handle ignores wakes.
#[kani::proof]
#[kani::unwind(6)]
fn a_wake_is_seen_once_and_not_after_close() {
    let handle = WakeHandle::new();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);
    let mut pending = false;
    for _ in 0..4 {
        match kani::any::<u8>() % 4 {
            0 => {
                handle.wake();
                if !handle.is_closed() {
                    pending = true;
                }
            }
            1 => assert_eq!(handle.poll(&mut cx).is_ready(), pending),
            2 => {
                assert_eq!(handle.take(), pending);
                pending = false;
            }
            _ => {
                handle.close();
                assert!(handle.is_closed());
            }
        }
    }
}
