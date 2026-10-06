//! The wall-clock timers behind `Cx::sleep` under `run`: one helper thread
//! per process that waits for the earliest deadline and wakes its waker.
//!
//! A browser has no threads to spare. There a JavaScript `setTimeout` is
//! armed for the earliest deadline instead, and [`block_on`](crate::block_on)
//! fires the timers itself while it waits.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Condvar;
use std::sync::{Mutex, OnceLock};
use std::task::Waker;

use crate::sys::Instant;

pub(crate) struct Timers {
    state: Mutex<State>,
    #[cfg(not(target_arch = "wasm32"))]
    changed: Condvar,
}

struct State {
    /// Deadlines in order. Entries whose id is no longer in `entries`, or
    /// whose deadline is not that timer's deadline now, are stale and
    /// skipped.
    heap: BinaryHeap<Reverse<(Instant, u64)>>,
    entries: HashMap<u64, (Instant, Waker)>,
    next_id: u64,
}

pub(crate) fn timers() -> &'static Timers {
    static TIMERS: OnceLock<&'static Timers> = OnceLock::new();
    TIMERS.get_or_init(|| {
        let timers: &'static Timers = Box::leak(Box::new(Timers {
            state: Mutex::new(State { heap: BinaryHeap::new(), entries: HashMap::new(), next_id: 0 }),
            #[cfg(not(target_arch = "wasm32"))]
            changed: Condvar::new(),
        }));
        #[cfg(not(target_arch = "wasm32"))]
        std::thread::Builder::new()
            .name("fictionet-timers".into())
            .spawn(move || timers.thread())
            .expect("failed to start the fictionet timer thread");
        timers
    })
}

impl Timers {
    /// Wakes `waker` at `deadline`. Returns an id for `update` and `remove`.
    pub(crate) fn add(&self, deadline: Instant, waker: Waker) -> u64 {
        let mut state = self.state.lock().unwrap();
        let id = state.next_id;
        state.next_id += 1;
        let earliest = state.heap.peek().map(|Reverse((d, _))| *d);
        state.heap.push(Reverse((deadline, id)));
        state.entries.insert(id, (deadline, waker));
        if state.heap.len() > 2 * state.entries.len() + 64 {
            // Too many stale entries: rebuild from the live ones.
            state.heap = state.entries.iter().map(|(id, (d, _))| Reverse((*d, *id))).collect();
        }
        drop(state);
        if earliest.is_none_or(|e| deadline < e) {
            self.earlier(deadline);
        }
        id
    }

    /// Moves timer `id` to `deadline`, with `waker`. A timer that has
    /// fired already is added again, under the same id.
    pub(crate) fn reset(&self, id: u64, deadline: Instant, waker: &Waker) {
        let mut state = self.state.lock().unwrap();
        let earliest = state.heap.peek().map(|Reverse((d, _))| *d);
        let old = match state.entries.get_mut(&id) {
            Some((d, w)) => {
                *d = deadline;
                (!w.will_wake(waker)).then(|| std::mem::replace(w, waker.clone()))
            }
            None => {
                state.entries.insert(id, (deadline, waker.clone()));
                None
            }
        };
        // The entry at the old deadline is stale now: the thread skips
        // heap entries whose deadline is not their timer's.
        state.heap.push(Reverse((deadline, id)));
        if state.heap.len() > 2 * state.entries.len() + 64 {
            state.heap = state.entries.iter().map(|(id, (d, _))| Reverse((*d, *id))).collect();
        }
        drop(state);
        drop(old);
        if earliest.is_none_or(|e| deadline < e) {
            self.earlier(deadline);
        }
    }

    /// Replaces the waker of timer `id`, if it has not fired yet.
    pub(crate) fn update(&self, id: u64, waker: &Waker) {
        let mut state = self.state.lock().unwrap();
        let old = match state.entries.get_mut(&id) {
            Some((_, w)) if !w.will_wake(waker) => Some(std::mem::replace(w, waker.clone())),
            _ => None,
        };
        drop(state);
        // Dropped outside the lock: dropping a waker can run any code.
        drop(old);
    }

    pub(crate) fn remove(&self, id: u64) {
        let removed = self.state.lock().unwrap().entries.remove(&id);
        drop(removed);
    }

    /// Moves the wakeup earlier, to `deadline`.
    #[cfg(not(target_arch = "wasm32"))]
    fn earlier(&self, _deadline: Instant) {
        self.changed.notify_one();
    }

    /// Moves the wakeup earlier, to `deadline`.
    #[cfg(target_arch = "wasm32")]
    fn earlier(&self, deadline: Instant) {
        browser::arm(deadline);
    }

    /// Wakes every timer that is due now. Returns the next deadline, if
    /// any timer is left.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn fire(&self) -> Option<Instant> {
        loop {
            let mut due = Vec::new();
            let next = self.state.lock().unwrap().take_due(Instant::now(), &mut due);
            if due.is_empty() {
                return next;
            }
            // Woken outside the lock: waking can run any code.
            for waker in due {
                waker.wake();
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn thread(&self) {
        let mut state = self.state.lock().unwrap();
        loop {
            let now = Instant::now();
            let mut due = Vec::new();
            let next = state.take_due(now, &mut due);
            if !due.is_empty() {
                drop(state);
                for waker in due {
                    waker.wake();
                }
                state = self.state.lock().unwrap();
                continue;
            }
            state = match next {
                Some(deadline) => {
                    let wait = deadline.saturating_duration_since(now);
                    self.changed.wait_timeout(state, wait).unwrap().0
                }
                None => self.changed.wait(state).unwrap(),
            };
        }
    }
}

impl State {
    /// Moves the waker of every timer due at `now` into `due`. Returns the
    /// next deadline, if any timer is left.
    fn take_due(&mut self, now: Instant, due: &mut Vec<Waker>) -> Option<Instant> {
        while let Some(Reverse((deadline, id))) = self.heap.peek().copied() {
            // Stale: the timer is gone, or was moved to another deadline.
            if self.entries.get(&id).is_none_or(|(d, _)| *d != deadline) {
                self.heap.pop();
                continue;
            }
            if deadline > now {
                return Some(deadline);
            }
            self.heap.pop();
            if let Some((_, waker)) = self.entries.remove(&id) {
                due.push(waker);
            }
        }
        None
    }
}

/// The `setTimeout` that fires the timers in a browser.
#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::Cell;

    use wasm_bindgen::prelude::*;

    use crate::sys::Instant;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = setTimeout)]
        fn set_timeout(handler: &Closure<dyn FnMut()>, millis: f64) -> JsValue;
    }

    thread_local! {
        /// The earliest deadline a `setTimeout` is armed for.
        static ARMED: Cell<Option<Instant>> = const { Cell::new(None) };
        static FIRE: Closure<dyn FnMut()> = Closure::new(fired);
    }

    /// Makes sure a `setTimeout` fires the timers by `deadline`.
    pub(super) fn arm(deadline: Instant) {
        if ARMED.get().is_some_and(|armed| armed <= deadline) {
            return;
        }
        ARMED.set(Some(deadline));
        let wait = deadline.saturating_duration_since(Instant::now());
        FIRE.with(|fire| set_timeout(fire, wait.as_secs_f64() * 1000.0));
    }

    fn fired() {
        ARMED.set(None);
        if let Some(next) = super::timers().fire() {
            arm(next);
        }
    }
}
