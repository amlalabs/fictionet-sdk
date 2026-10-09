//! A run's logical clock and ordered timer registrations.

use fictionet::sync::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use std::task::{Wake, Waker};

use crate::time::{Duration, Instant};

/// The clock and I/O policy of a world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Time follows the host's monotonic clock, and real I/O is available.
    Real,
    /// Time starts at zero and advances when all runnable work has drained.
    Lab,
}

pub(crate) struct Clock {
    origin: Option<crate::sys::Instant>,
    state: Mutex<State>,
    wake: Weak<Clock>,
}

#[derive(Default)]
struct State {
    now: Duration,
    next_id: u64,
    entries: BTreeMap<(Instant, u64), Waker>,
    deadlines: BTreeMap<u64, Instant>,
    host: Option<u64>,
}

impl Clock {
    pub(crate) fn new(mode: RunMode) -> Arc<Self> {
        Arc::new_cyclic(|wake| Self {
            origin: (mode == RunMode::Real).then(crate::sys::Instant::now),
            state: Mutex::new(State::default()),
            wake: wake.clone(),
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
        Instant::from_since_start(
            self.origin
                .map_or_else(|| self.state.lock().now, |o| o.elapsed()),
        )
    }

    pub(crate) fn finite(&self, at: Instant) -> bool {
        at.since_start() != Duration::MAX
            && self
                .origin
                .is_none_or(|o| o.checked_add(at.since_start()).is_some())
    }

    pub(crate) fn add(&self, at: Instant, waker: Waker) -> u64 {
        let mut s = self.state.lock();
        let id = s.next_id;
        s.next_id = s
            .next_id
            .checked_add(1)
            .expect("timer registration IDs exhausted");
        s.entries.insert((at, id), waker);
        s.deadlines.insert(id, at);
        self.arm(&mut s);
        id
    }

    pub(crate) fn reset(&self, id: u64, at: Instant, waker: &Waker) {
        let mut s = self.state.lock();
        let old = s
            .deadlines
            .insert(id, at)
            .and_then(|old| s.entries.remove(&(old, id)));
        s.entries.insert((at, id), waker.clone());
        self.arm(&mut s);
        drop(s);
        drop(old);
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

    // Only the earliest logical deadline is represented in the host driver.
    fn arm(&self, s: &mut State) {
        let Some(origin) = self.origin else { return };
        let next = s.entries.first_key_value().map(|((at, _), _)| *at);
        if let Some(at) = next {
            let deadline = origin.checked_add(at.since_start()).expect("finite timer");
            let waker = Waker::from(Arc::new(HostWake(self.wake.clone())));
            match s.host {
                Some(id) => crate::timer::timers().reset(id, deadline, &waker),
                None => s.host = Some(crate::timer::timers().add(deadline, waker)),
            }
        } else if let Some(id) = s.host.take() {
            crate::timer::timers().remove(id);
        }
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
        s.now = at.since_start();
        let due = Self::take_due(&mut s, at);
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
        if let Some(id) = self.state.get_mut().host {
            crate::timer::timers().remove(id);
        }
    }
}
