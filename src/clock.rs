//! A run's logical clock and ordered timer registrations.

use fictionet::sync::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use std::sync::{Arc, Weak};
use std::task::{Wake, Waker};

use crate::time::{Duration, Instant};

/// The clock mode of a world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Time follows the host's monotonic clock.
    Real,
    /// Time starts at zero and advances when all runnable work has drained.
    Lab,
}

pub(crate) struct Clock {
    #[cfg(test)]
    pub(crate) reads: std::sync::atomic::AtomicUsize,
    /// Calls into the host wake driver.
    #[cfg(test)]
    host_calls: std::sync::atomic::AtomicUsize,
    origin: Option<crate::sys::Instant>,
    /// A lab's time. Only [`advance`](Clock::advance) moves it, under the
    /// lock of `state`; [`now`](Clock::now) reads it without that lock.
    lab_now: LabNow,
    state: Mutex<State>,
    wake: Option<Waker>,
}

/// A lab's time, readable without a lock. One writer at a time (the
/// clock's lock makes sure of it) and any number of readers: a sequence
/// lock over atomics. The sequence is odd while a write is under way, and
/// a reader that saw it odd, or saw it change, reads again.
#[derive(Default)]
struct LabNow {
    sequence: AtomicU64,
    secs: AtomicU64,
    nanos: AtomicU32,
}

impl LabNow {
    fn get(&self) -> Duration {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            let secs = self.secs.load(Ordering::Relaxed);
            let nanos = self.nanos.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            let after = self.sequence.load(Ordering::Relaxed);
            if before == after && before.is_multiple_of(2) {
                return Duration::new(secs, nanos);
            }
            std::hint::spin_loop();
        }
    }

    /// Sets the time. The caller holds the clock's lock, so it is the only
    /// writer.
    fn set(&self, now: Duration) {
        let sequence = self.sequence.load(Ordering::Relaxed);
        self.sequence
            .store(sequence.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.secs.store(now.as_secs(), Ordering::Relaxed);
        self.nanos.store(now.subsec_nanos(), Ordering::Relaxed);
        self.sequence
            .store(sequence.wrapping_add(2), Ordering::Release);
    }
}

#[derive(Default)]
struct State {
    next_id: u64,
    entries: BTreeMap<(Instant, u64), Waker>,
    deadlines: BTreeMap<u64, Instant>,
    host: Option<Host>,
}

/// The run's registration in the host wake driver.
struct Host {
    id: u64,
    /// The deadline the driver holds for `id`. `None` once the driver may
    /// have consumed the entry, so the next arm sets it again.
    armed: Option<crate::sys::Instant>,
}

impl Clock {
    pub(crate) fn new(mode: RunMode) -> Arc<Self> {
        Arc::new_cyclic(|wake| Self {
            #[cfg(test)]
            reads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            host_calls: std::sync::atomic::AtomicUsize::new(0),
            origin: (mode == RunMode::Real).then(crate::sys::Instant::now),
            lab_now: LabNow::default(),
            state: Mutex::new(State::default()),
            wake: (mode == RunMode::Real).then(|| Waker::from(Arc::new(HostWake(wake.clone())))),
        })
    }

    pub(crate) fn mode(&self) -> RunMode {
        if self.origin.is_some() {
            RunMode::Real
        } else {
            RunMode::Lab
        }
    }

    pub(crate) fn now(&self) -> Instant {
        #[cfg(test)]
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Instant::from_since_start(
            self.origin
                .map_or_else(|| self.lab_now.get(), |o| o.elapsed()),
        )
    }

    /// Holds the clock's lock, for tests that show a path never takes it.
    #[cfg(test)]
    pub(crate) fn hold(&self) -> impl Sized + '_ {
        self.state.lock()
    }

    pub(crate) fn finite(&self, at: Instant) -> bool {
        at.since_start() != Duration::MAX
            && self
                .origin
                .is_none_or(|o| o.checked_add(at.since_start()).is_some())
    }

    pub(crate) fn add(&self, at: Instant, waker: Waker) -> u64 {
        let mut s = self.state.lock();
        let id = Self::register(&mut s, at, waker);
        self.arm(&mut s);
        id
    }

    /// Moves registration `id` to `at`. The move is a new registration, so
    /// it wakes after every timer already set for the same instant, and the
    /// returned ID replaces `id`.
    pub(crate) fn reset(&self, id: u64, at: Instant, waker: &Waker) -> u64 {
        let mut s = self.state.lock();
        let old = s
            .deadlines
            .remove(&id)
            .and_then(|old| s.entries.remove(&(old, id)));
        let id = Self::register(&mut s, at, waker.clone());
        self.arm(&mut s);
        drop(s);
        drop(old);
        id
    }

    /// Adds an entry for `at` under the next registration ID, which orders
    /// it after every entry already due at the same instant.
    fn register(s: &mut State, at: Instant, waker: Waker) -> u64 {
        let id = s.next_id;
        s.next_id = s
            .next_id
            .checked_add(1)
            .expect("timer registration IDs exhausted");
        s.entries.insert((at, id), waker);
        s.deadlines.insert(id, at);
        id
    }

    pub(crate) fn update(&self, id: u64, waker: &Waker) {
        let mut s = self.state.lock();
        let old = s.deadlines.get(&id).copied().and_then(|at| {
            let old = s.entries.get_mut(&(at, id))?;
            (!old.will_wake(waker)).then(|| std::mem::replace(old, waker.clone()))
        });
        drop(s);
        drop(old);
    }

    pub(crate) fn remove(&self, id: u64) {
        let mut s = self.state.lock();
        let old = s
            .deadlines
            .remove(&id)
            .and_then(|at| s.entries.remove(&(at, id)));
        self.arm(&mut s);
        drop(s);
        drop(old);
    }

    // Only the earliest logical deadline is represented in the host driver,
    // and the driver is called only when that deadline changes.
    fn arm(&self, s: &mut State) {
        let Some(origin) = self.origin else { return };
        let next = s.entries.first_key_value().map(|((at, _), _)| *at);
        if let Some(at) = next {
            let deadline = origin.checked_add(at.since_start()).expect("finite timer");
            let waker = self.wake.as_ref().expect("real clock waker");
            match &mut s.host {
                Some(host) if host.armed == Some(deadline) => {}
                Some(host) => {
                    self.note_host_call();
                    crate::timer::timers().reset(host.id, deadline, waker);
                    host.armed = Some(deadline);
                }
                None => {
                    self.note_host_call();
                    let id = crate::timer::timers().add(deadline, waker.clone());
                    s.host = Some(Host {
                        id,
                        armed: Some(deadline),
                    });
                }
            }
        } else if let Some(host) = s.host.take() {
            self.note_host_call();
            crate::timer::timers().remove(host.id);
        }
    }

    fn note_host_call(&self) {
        #[cfg(test)]
        self.host_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn take_due(s: &mut State, now: Instant) -> Vec<Waker> {
        let mut due = Vec::new();
        while s
            .entries
            .first_key_value()
            .is_some_and(|((at, _), _)| *at <= now)
        {
            let ((_, id), waker) = s.entries.pop_first().unwrap();
            s.deadlines.remove(&id);
            due.push(waker);
        }
        due
    }

    pub(crate) fn advance(&self) -> crate::Result<Vec<Waker>> {
        let mut s = self.state.lock();
        let Some((&(at, _), _)) = s.entries.first_key_value() else {
            return Err(std::io::Error::other(
                "lab deadlock: live tasks have no runnable work or finite deadline",
            )
            .into());
        };
        // smoltcp represents elapsed time as signed microseconds.
        if at.since_start() > Duration::from_micros(i64::MAX as u64) {
            return Err(std::io::Error::other(
                "lab time exceeds the signed microsecond clock range",
            )
            .into());
        }
        // A timer registered from outside the run can name a deadline the
        // clock has already passed; it is due now, and the clock stays put.
        let now = self.lab_now.get().max(at.since_start());
        self.lab_now.set(now);
        let due = Self::take_due(&mut s, Instant::from_since_start(now));
        Ok(due)
    }
}

struct HostWake(Weak<Clock>);
impl Wake for HostWake {
    fn wake(self: Arc<Self>) {
        let Some(clock) = self.0.upgrade() else {
            return;
        };
        let now = clock.now();
        let mut s = clock.state.lock();
        // The driver removed the host entry before waking this waker, and
        // an arm since then may have skipped the driver for an unchanged
        // deadline. Set the entry again.
        if let Some(host) = &mut s.host {
            host.armed = None;
        }
        let due = Clock::take_due(&mut s, now);
        clock.arm(&mut s);
        drop(s);
        for waker in due {
            waker.wake();
        }
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        if let Some(host) = &self.state.get_mut().host {
            crate::timer::timers().remove(host.id);
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    const HOUR: Duration = Duration::from_secs(3600);
    const SECOND: Duration = Duration::from_secs(1);

    /// Readers on other threads see a lab's time as some value it was set
    /// to, never half of one write and half of another, and never going
    /// back.
    #[test]
    fn lab_time_reads_whole_and_in_order_while_it_moves() {
        const WRITES: u64 = 200_000;
        // Each written time's nanoseconds are a function of its seconds, so
        // a torn read shows.
        fn nanos(secs: u64) -> u32 {
            (secs.wrapping_mul(7_919) % 1_000_000_000) as u32
        }
        let now = Arc::new(LabNow::default());
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let now = now.clone();
                std::thread::spawn(move || {
                    let mut last = Duration::ZERO;
                    loop {
                        let read = now.get();
                        if read != Duration::ZERO {
                            assert_eq!(read.subsec_nanos(), nanos(read.as_secs()), "{read:?}");
                        }
                        assert!(read >= last, "{read:?} after {last:?}");
                        last = read;
                        if read.as_secs() == WRITES {
                            return;
                        }
                    }
                })
            })
            .collect();
        for secs in 1..=WRITES {
            now.set(Duration::new(secs, nanos(secs)));
        }
        for reader in readers {
            reader.join().unwrap();
        }
    }

    /// The deadline the host driver holds for `clock`, if any.
    fn driver_deadline(clock: &Clock) -> Option<crate::sys::Instant> {
        let id = clock.state.lock().host.as_ref()?.id;
        crate::timer::timers().deadline(id)
    }

    /// The host instant of logical instant `at` on `clock`.
    fn host_instant(clock: &Clock, at: Instant) -> crate::sys::Instant {
        clock.origin.unwrap().checked_add(at.since_start()).unwrap()
    }

    #[test]
    fn timers_after_the_earliest_leave_the_host_driver_alone() {
        let clock = Clock::new(RunMode::Real);
        let waker = Waker::noop();
        let first = clock.now() + HOUR;
        clock.add(first, waker.clone());
        let calls = clock.host_calls.load(Ordering::Relaxed);
        let tied = clock.add(first, waker.clone());
        let later = clock.add(first + SECOND, waker.clone());
        let later = clock.reset(later, first + 2 * SECOND, waker);
        let tied = clock.reset(tied, first + 3 * SECOND, waker);
        clock.remove(later);
        clock.remove(tied);
        assert_eq!(clock.host_calls.load(Ordering::Relaxed), calls);
        assert_eq!(driver_deadline(&clock), Some(host_instant(&clock, first)));
    }

    /// The driver removes a due entry before it wakes the clock, so an arm
    /// in between sees an unchanged deadline although the driver no longer
    /// holds it. The wake must set the entry again.
    #[test]
    fn a_host_wake_sets_the_driver_entry_again() {
        let clock = Clock::new(RunMode::Real);
        let waker = Waker::noop();
        let first = clock.now() + HOUR;
        clock.add(first, waker.clone());
        let id = clock.state.lock().host.as_ref().unwrap().id;
        crate::timer::timers().remove(id);
        clock.add(first + SECOND, waker.clone());
        clock.wake.as_ref().unwrap().wake_by_ref();
        assert_eq!(driver_deadline(&clock), Some(host_instant(&clock, first)));
    }

    #[test]
    fn removing_timers_moves_and_cancels_the_host_wake() {
        let clock = Clock::new(RunMode::Real);
        let waker = Waker::noop();
        let first = clock.now() + HOUR;
        let a = clock.add(first, waker.clone());
        let b = clock.add(first + SECOND, waker.clone());
        let id = clock.state.lock().host.as_ref().unwrap().id;
        clock.remove(a);
        assert_eq!(
            driver_deadline(&clock),
            Some(host_instant(&clock, first + SECOND))
        );
        clock.remove(b);
        assert_eq!(crate::timer::timers().deadline(id), None);
        clock.add(first, waker.clone());
        assert_eq!(driver_deadline(&clock), Some(host_instant(&clock, first)));
    }
}
