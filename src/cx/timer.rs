use std::task::{Context, Poll, Waker};

use super::{CancelWait, Cancelled, Cx};
use crate::time::Instant;

/// A sleep whose deadline can move, for a task that polls by hand and
/// whose next deadline changes often, such as a TCP endpoint's driver.
/// Moving the deadline reuses the same timer entry, where dropping one
/// [`Cx::sleep_until`] future and making another would add and remove an
/// entry, and allocate the boxed future, each time.
///
/// A poll with the deadline and waker the entry already has, or with a
/// later deadline, leaves the clock alone and takes none of its locks. A
/// later deadline keeps the entry at the earlier one: the timer wakes there
/// once, the task polls again, and the entry moves to the later deadline
/// then. Only an earlier deadline, a new waker, or a first deadline
/// changes the entry at once.
///
/// Create an inactive timer with [`Timer::new`]. Each call to
/// [`Timer::poll_until`] sets its deadline. [`Timer::clear`] removes the
/// deadline; dropping the timer also unregisters its cancellation waiter.
/// Use a timer with one region.
pub struct Timer {
    fcx: Cx,
    /// The timer's entry in the run's clock, if there is one.
    entry: Option<Entry>,
    wait: CancelWait,
}

/// A timer's entry in the run's clock: its registration, the instant it
/// wakes at, and a clone of the waker it wakes, for comparing without the
/// clock's lock.
struct Entry {
    id: u64,
    at: Instant,
    waker: Waker,
}

impl Timer {
    /// Creates an inactive timer owned by this context's run and region.
    pub fn new(fcx: &Cx) -> Self {
        Self {
            fcx: fcx.clone(),
            entry: None,
            wait: CancelWait::default(),
        }
    }

    /// Polls for `deadline` to pass: `Ready(Ok(()))` once it has. Until
    /// then, `cx`'s waker is woken when it passes or when the owning region is
    /// cancelled. It may also be woken once at an earlier deadline this
    /// timer was polled for. Cancellation returns `Ready(Err(Cancelled))`,
    /// even if the deadline has passed. `Duration::MAX` is an unarmed wait.
    /// Real deadlines beyond the host clock's range also wait only for
    /// cancellation.
    pub fn poll_until(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Instant,
    ) -> Poll<Result<(), Cancelled>> {
        if self.fcx.is_cancelled() {
            return Poll::Ready(Err(Cancelled));
        }
        let clock = &self.fcx.run.environment.clock;
        // A deadline past what the clock can hold never comes.
        if clock.finite(deadline) {
            let now = self.fcx.now();
            if now >= deadline {
                self.clear();
                return Poll::Ready(Ok(()));
            }
            let waker = cx.waker();
            let mut fired = false;
            match &mut self.entry {
                // The entry wakes the task first, at its own instant, and the
                // task polls again then.
                Some(entry) if entry.at == deadline || (entry.at < deadline && now < entry.at) => {
                    if !entry.waker.will_wake(waker) {
                        fired = !clock.update(entry.id, waker);
                        entry.waker = waker.clone();
                    }
                }
                // Earlier, or past the instant the entry woke at.
                Some(entry) => {
                    entry.id = clock.reset(entry.id, deadline, waker);
                    entry.at = deadline;
                    if !entry.waker.will_wake(waker) {
                        entry.waker = waker.clone();
                    }
                }
                None => {
                    self.entry = Some(Entry {
                        id: clock.add(deadline, waker.clone()),
                        at: deadline,
                        waker: waker.clone(),
                    });
                }
            }
            if fired {
                // The clock took the entry as due after `now` was read and
                // woke the waker it held, which may not reach this task:
                // this one is woken, and the next poll looks again.
                self.entry = None;
                waker.wake_by_ref();
            }
        } else {
            self.clear();
        }
        if self.fcx.register_cancel(cx.waker(), &mut self.wait) {
            return Poll::Ready(Err(Cancelled));
        }
        Poll::Pending
    }

    /// Removes the deadline and its timer entry, if any.
    /// The cancellation registration stays until the timer is dropped.
    pub fn clear(&mut self) {
        if let Some(entry) = self.entry.take() {
            self.fcx.run.environment.clock.remove(entry.id);
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use crate::time::{Duration, ms};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A splitmix64 step.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Reading a lab's time, and polling a timer for the deadline and
    /// waker its entry has, or for a later deadline, take no clock lock:
    /// they go through with the clock's lock held elsewhere.
    #[test]
    fn time_and_an_unchanged_or_later_deadline_take_no_clock_lock() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut world = Box::pin(crate::lab(
            fictionet::Seed::from_u64(0),
            move |fcx| async move {
                tx.send(fcx.clone()).unwrap();
                fcx.sleep(Duration::from_secs(3600)).await?;
                Ok(())
            },
        ));
        assert!(
            world
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let fcx = rx.recv().unwrap();
        let waker = Waker::from(Arc::new(Wakes::default()));
        let mut timer = Timer::new(&fcx);
        let base = fcx.now() + ms(10);
        assert!(
            timer
                .poll_until(&mut Context::from_waker(&waker), base)
                .is_pending()
        );
        let clock = fcx.run.environment.clock.clone();
        let held = clock.hold();
        let (done, finished) = std::sync::mpsc::channel();
        let polls = std::thread::spawn(move || {
            let mut cx = Context::from_waker(&waker);
            for i in 0..1000 {
                assert!(fcx.now() < base);
                assert!(timer.poll_until(&mut cx, base).is_pending());
                assert!(timer.poll_until(&mut cx, base + ms(i)).is_pending());
            }
            done.send(()).unwrap();
            // Dropping the timer takes the lock: hand it back instead.
            (timer, fcx)
        });
        let finished = finished.recv_timeout(std::time::Duration::from_secs(10));
        drop(held);
        drop(polls.join().unwrap());
        drop(world);
        assert_eq!(finished, Ok(()), "a read or a poll took the clock's lock");
    }

    /// A poll with a new waker that comes after the clock took the entry
    /// as due, but read the time before it did, wakes the new waker: the
    /// clock woke only the old one, which may no longer reach the task.
    #[test]
    fn a_new_waker_after_the_entry_fired_is_woken() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut world = Box::pin(crate::lab(
            fictionet::Seed::from_u64(0),
            move |fcx| async move {
                tx.send(fcx.clone()).unwrap();
                fcx.sleep(Duration::from_secs(3600)).await?;
                Ok(())
            },
        ));
        assert!(
            world
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let fcx = rx.recv().unwrap();
        let old = Arc::new(Wakes::default());
        let new = Arc::new(Wakes::default());
        let mut timer = Timer::new(&fcx);
        let deadline = fcx.now() + ms(10);
        let old_waker = Waker::from(old.clone());
        assert!(
            timer
                .poll_until(&mut Context::from_waker(&old_waker), deadline)
                .is_pending()
        );
        // The clock takes the entry as due and wakes the waker it held, as
        // its driver does when the instant comes on a real clock, between
        // the next poll's reading of the time and its update.
        let id = timer.entry.as_ref().unwrap().id;
        fcx.run.environment.clock.remove(id);
        old_waker.wake_by_ref();
        let new_waker = Waker::from(new.clone());
        assert!(
            timer
                .poll_until(&mut Context::from_waker(&new_waker), deadline)
                .is_pending()
        );
        assert_eq!(new.0.load(Ordering::SeqCst), 1, "the new waker never woke");
        drop(timer);
        drop(world);
    }

    /// A timer whose deadline moves at random, earlier or later, on the
    /// polls its wakes cause: in a lab it fires exactly at the deadline it
    /// was last polled for, and wakes at most once between a move and that
    /// deadline.
    #[test]
    fn a_moving_timer_fires_exactly_at_its_last_deadline() {
        for seed in 1..=8u64 {
            block_on(crate::lab(
                fictionet::Seed::from_u64(seed),
                move |fcx| async move {
                    let mut timer = Timer::new(&fcx);
                    let mut state = seed;
                    let mut deadline = fcx.now() + ms(1 + next(&mut state) % 100);
                    let mut pending_since_move = 0;
                    let mut fired = 0;
                    std::future::poll_fn(|cx| {
                        loop {
                            let now = fcx.now();
                            if now < deadline && next(&mut state).is_multiple_of(3) {
                                deadline = now + ms(1 + next(&mut state) % 100);
                                pending_since_move = 0;
                            }
                            match timer.poll_until(cx, deadline) {
                                Poll::Ready(Ok(())) => {
                                    assert_eq!(fcx.now(), deadline, "seed {seed}");
                                    fired += 1;
                                    if fired == 200 {
                                        return Poll::Ready(Ok::<(), Cancelled>(()));
                                    }
                                    deadline = fcx.now() + ms(1 + next(&mut state) % 100);
                                    pending_since_move = 0;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => {
                                    pending_since_move += 1;
                                    assert!(
                                        pending_since_move <= 2,
                                        "seed {seed}: woken twice before its deadline"
                                    );
                                    return Poll::Pending;
                                }
                            }
                        }
                    })
                    .await?;
                    Ok(())
                },
            ))
            .unwrap();
        }
    }

    #[test]
    fn a_timer_fires_at_its_latest_deadline() {
        /// Polls `timer` for `first`, then for `then` until it fires.
        /// Returns how long that took.
        async fn wait(
            fcx: &Cx,
            timer: &mut Timer,
            first: Duration,
            then: Duration,
        ) -> Result<std::time::Duration, Cancelled> {
            let start = fcx.now();
            let base = fcx.now();
            let mut moved = false;
            std::future::poll_fn(|cx| {
                if !moved {
                    moved = true;
                    assert!(timer.poll_until(cx, base + first).is_pending());
                }
                timer.poll_until(cx, base + then)
            })
            .await?;
            Ok(fcx.now().since_start() - start.since_start())
        }
        block_on(crate::lab(fictionet::Seed::from_u64(0), |fcx| async move {
            let mut timer = Timer::new(&fcx);
            // Moved later: the old deadline does not end the wait.
            let waited = wait(&fcx, &mut timer, ms(10), ms(120)).await?;
            assert_eq!(waited, ms(120));
            // Moved earlier: it fires at the new deadline, after it fired once
            // already under the same entry.
            let waited = wait(&fcx, &mut timer, ms(400), ms(30)).await?;
            assert_eq!(waited, ms(30));
            Ok(())
        }))
        .unwrap();
    }

    /// A lab wakes timers due at the same instant in the order they were
    /// set. A timer moved to a later deadline wakes once at its earlier one
    /// and is set again when its task polls it then, so it wakes after a
    /// timer that set the same deadline before.
    #[test]
    fn a_moved_timer_wakes_after_timers_set_before_the_move() {
        use fictionet::sync::Mutex;
        use std::sync::Arc;
        use std::task::{Context, Wake, Waker};

        struct Log(&'static str, Arc<Mutex<Vec<&'static str>>>);
        impl Wake for Log {
            fn wake(self: Arc<Self>) {
                self.1.lock().push(self.0);
            }
        }
        fn pending(timer: &mut Timer, waker: &Waker, at: Duration) -> bool {
            let deadline = Instant::from_since_start(at);
            timer
                .poll_until(&mut Context::from_waker(waker), deadline)
                .is_pending()
        }
        block_on(crate::lab(fictionet::Seed::from_u64(0), |fcx| async move {
            let woken = Arc::new(Mutex::new(Vec::new()));
            let first = Waker::from(Arc::new(Log("first", woken.clone())));
            let second = Waker::from(Arc::new(Log("second", woken.clone())));
            let mut a = Timer::new(&fcx);
            let mut b = Timer::new(&fcx);
            // `a` sets a deadline first, `b` sets 20 ms, then `a` moves to 20 ms.
            assert!(pending(&mut a, &first, ms(10)));
            assert!(pending(&mut b, &second, ms(20)));
            assert!(pending(&mut a, &first, ms(20)));
            fcx.sleep_until(Instant::from_since_start(ms(15))).await?;
            assert_eq!(*woken.lock(), ["first"], "the entry at 10 ms woke `a`");
            // `a`'s task polls it again, as a woken task does.
            assert!(pending(&mut a, &first, ms(20)));
            fcx.sleep_until(Instant::from_since_start(ms(30))).await?;
            assert_eq!(*woken.lock(), ["first", "second", "first"]);
            Ok(())
        }))
        .unwrap();
    }

    /// A timer polled outside the run, as by a harness thread that keeps a
    /// clone of the world's `Cx`, reads the clock and then registers its
    /// deadline. If the lab jumps past that deadline in between, the timer
    /// is due at once. The lab must not move its clock back to the late
    /// deadline: world code that measured a later time would see time run
    /// backwards.
    #[test]
    #[allow(
        unsafe_code,
        reason = "the regression requires intercepting a waker clone"
    )]
    fn a_lab_clock_never_moves_back_for_a_deadline_set_from_another_thread() {
        use fictionet::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};
        use std::task::{Context, RawWaker, RawWakerVTable, Waker};

        const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

        /// A waker whose first clone, which the timer makes right before it
        /// registers its deadline, waits until the test lets it go. It notes
        /// the clock when it is woken.
        struct Gate {
            hold: AtomicBool,
            entered: mpsc::Sender<()>,
            go: Mutex<mpsc::Receiver<()>>,
            fcx: Cx,
            woken_at: Mutex<Option<Instant>>,
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, release);
        unsafe fn clone(data: *const ()) -> RawWaker {
            // SAFETY: `data` came from `Arc::into_raw` of a `Gate`.
            unsafe { Arc::increment_strong_count(data.cast::<Gate>()) };
            // SAFETY: this waker still owns a count of the same live Gate.
            let gate = unsafe { &*data.cast::<Gate>() };
            if gate.hold.swap(false, Ordering::SeqCst) {
                gate.entered.send(()).unwrap();
                gate.go.lock().recv_timeout(WAIT).unwrap();
            }
            RawWaker::new(data, &VTABLE)
        }
        unsafe fn wake(data: *const ()) {
            // SAFETY: wake consumes this waker's count after borrowing it.
            unsafe { wake_by_ref(data) };
            // SAFETY: this is the one count consumed by wake.
            unsafe { release(data) };
        }
        unsafe fn wake_by_ref(data: *const ()) {
            // SAFETY: `data` came from `Arc::into_raw` of a `Gate`.
            let gate = unsafe { &*data.cast::<Gate>() };
            let now = gate.fcx.now();
            gate.woken_at.lock().get_or_insert(now);
        }
        unsafe fn release(data: *const ()) {
            // SAFETY: `data` came from `Arc::into_raw` of a `Gate`.
            unsafe { Arc::decrement_strong_count(data.cast::<Gate>()) };
        }

        block_on(crate::lab(fictionet::Seed::from_u64(0), |fcx| async move {
            let at = |t| Instant::from_since_start(ms(t));
            let (entered_tx, entered) = mpsc::channel();
            let (go, go_rx) = mpsc::channel();
            let gate = Arc::new(Gate {
                hold: AtomicBool::new(true),
                entered: entered_tx,
                go: Mutex::new(go_rx),
                fcx: fcx.clone(),
                woken_at: Mutex::new(None),
            });
            let outside = fcx.clone();
            let gate_ptr = Arc::into_raw(gate.clone()).cast::<()>() as usize;
            let harness = std::thread::spawn(move || {
                // SAFETY: the pointer owns one count of the `Gate`.
                let waker =
                    unsafe { Waker::from_raw(RawWaker::new(gate_ptr as *const (), &VTABLE)) };
                let mut timer = Timer::new(&outside);
                let polled = timer.poll_until(&mut Context::from_waker(&waker), at(7));
                assert!(polled.is_pending(), "the clock read 0 ms");
                timer
            });
            // The harness has read the clock at 0 ms and holds its deadline.
            entered.recv_timeout(WAIT).unwrap();
            fcx.sleep_until(at(10)).await?;
            assert_eq!(fcx.now(), at(10));
            go.send(()).unwrap();
            let timer = harness.join().unwrap();
            fcx.sleep_until(at(20)).await?;
            let woken_at = *gate.woken_at.lock();
            assert!(
                woken_at.is_some_and(|t| t >= at(10)),
                "the lab moved its clock back from 10 ms to {woken_at:?}"
            );
            assert_eq!(fcx.now(), at(20));
            drop(timer);
            Ok(())
        }))
        .unwrap();
    }
}
