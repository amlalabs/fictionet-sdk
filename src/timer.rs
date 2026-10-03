//! The wall-clock timers behind `Cx::sleep` under `run`: one helper thread
//! per process that waits for the earliest deadline and wakes its waker.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Condvar, Mutex, OnceLock};
use std::task::Waker;
use std::time::Instant;

pub(crate) struct Timers {
    state: Mutex<State>,
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
            changed: Condvar::new(),
        }));
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
            self.changed.notify_one();
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
            self.changed.notify_one();
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

    fn thread(&self) {
        let mut state = self.state.lock().unwrap();
        loop {
            let now = Instant::now();
            let mut due = Vec::new();
            while let Some(Reverse((deadline, id))) = state.heap.peek().copied() {
                // Stale: the timer is gone, or was moved to another deadline.
                if state.entries.get(&id).is_none_or(|(d, _)| *d != deadline) {
                    state.heap.pop();
                    continue;
                }
                if deadline > now {
                    break;
                }
                state.heap.pop();
                if let Some((_, waker)) = state.entries.remove(&id) {
                    due.push(waker);
                }
            }
            if !due.is_empty() {
                drop(state);
                for waker in due {
                    waker.wake();
                }
                state = self.state.lock().unwrap();
                continue;
            }
            state = match state.heap.peek() {
                Some(Reverse((deadline, _))) => {
                    let wait = deadline.saturating_duration_since(now);
                    self.changed.wait_timeout(state, wait).unwrap().0
                }
                None => self.changed.wait(state).unwrap(),
            };
        }
    }
}
