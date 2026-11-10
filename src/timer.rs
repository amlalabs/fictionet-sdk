//! The host wake driver of a real run: it wakes the run's clock at the
//! clock's earliest deadline. Each real clock owns its driver, and nothing
//! is shared between runs. Logical registrations and their order belong to
//! the clock.
//!
//! Natively the driver is one helper thread, started with the first
//! deadline and ended when the clock is dropped. A browser has no threads
//! to spare: there each deadline arms a JavaScript `setTimeout`, and a run
//! polled by [`block_on`](crate::block_on), which holds the thread so no
//! `setTimeout` can run, fires its due timers itself.

use std::task::Waker;

use crate::sys::Instant;

/// Wakes `wake` at the deadline it was last given.
pub(crate) struct Driver {
    #[cfg(not(target_arch = "wasm32"))]
    shared: std::sync::Arc<native::Shared>,
    #[cfg(target_arch = "wasm32")]
    wake: Waker,
}

impl Driver {
    /// A driver that wakes `wake`. It holds no deadline and runs nothing
    /// yet.
    pub(crate) fn new(wake: Waker) -> Driver {
        #[cfg(not(target_arch = "wasm32"))]
        return Driver {
            shared: native::Shared::new(wake),
        };
        #[cfg(target_arch = "wasm32")]
        return Driver { wake };
    }

    /// Wakes the clock at `deadline`, in place of the deadline set before.
    /// `None` takes the deadline away. The driver forgets a deadline once it
    /// has woken the clock for it.
    pub(crate) fn set(&self, deadline: Option<Instant>) {
        #[cfg(not(target_arch = "wasm32"))]
        native::Shared::set(&self.shared, deadline);
        #[cfg(target_arch = "wasm32")]
        if let Some(deadline) = deadline {
            browser::arm(deadline, self.wake.clone());
        }
    }

    /// The deadline the driver holds, if any.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.shared.state.lock().deadline
    }

    /// Forgets the deadline, as the driver does right before it wakes the
    /// clock.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn forget(&self) {
        self.shared.state.lock().deadline = None;
    }

    /// What the driver's thread holds, weakly: it is gone once the driver
    /// is dropped and its thread has ended.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn thread(&self) -> std::sync::Weak<native::Shared> {
        std::sync::Arc::downgrade(&self.shared)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        self.shared.close();
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use fictionet::sync::Mutex;
    use std::sync::{Arc, Condvar};
    use std::task::Waker;

    use crate::sys::Instant;

    /// What the clock and its driver's thread share.
    pub(crate) struct Shared {
        pub(super) state: Mutex<State>,
        changed: Condvar,
        /// How many times the thread has looked at its deadline.
        #[cfg(test)]
        pub(super) looks: std::sync::atomic::AtomicUsize,
        wake: Waker,
    }

    pub(super) struct State {
        pub(super) deadline: Option<Instant>,
        /// The thread was started. It starts with the first deadline.
        started: bool,
        /// The clock is gone: the thread ends.
        closed: bool,
    }

    impl Shared {
        pub(super) fn new(wake: Waker) -> Arc<Shared> {
            Arc::new(Shared {
                state: Mutex::new(State {
                    deadline: None,
                    started: false,
                    closed: false,
                }),
                changed: Condvar::new(),
                #[cfg(test)]
                looks: std::sync::atomic::AtomicUsize::new(0),
                wake,
            })
        }

        /// Only a deadline earlier than the one held, or one where none was,
        /// notifies the thread: one that moved later or went is found when
        /// the thread wakes for the old one, and every notify can cost the
        /// thread a wake.
        pub(super) fn set(this: &Arc<Shared>, deadline: Option<Instant>) {
            let mut state = this.state.lock();
            let earlier = match (state.deadline, deadline) {
                (_, None) => false,
                (None, Some(_)) => true,
                (Some(held), Some(new)) => new < held,
            };
            state.deadline = deadline;
            if deadline.is_some() && !state.started {
                state.started = true;
                let shared = this.clone();
                std::thread::Builder::new()
                    .name("fictionet-timer".into())
                    .spawn(move || shared.run())
                    .expect("failed to start a fictionet timer thread");
            }
            drop(state);
            if earlier {
                this.changed.notify_one();
            }
        }

        pub(super) fn close(&self) {
            self.state.lock().closed = true;
            self.changed.notify_one();
        }

        /// The thread: waits for the deadline, forgets it, wakes the clock.
        fn run(&self) {
            let mut state = self.state.lock();
            loop {
                #[cfg(test)]
                self.looks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if state.closed {
                    return;
                }
                let now = Instant::now();
                state = match state.deadline {
                    Some(deadline) if deadline <= now => {
                        state.deadline = None;
                        drop(state);
                        // Woken outside the lock: the clock sets the next
                        // deadline from inside the wake.
                        self.wake.wake_by_ref();
                        self.state.lock()
                    }
                    Some(deadline) => {
                        let wait = deadline.saturating_duration_since(now);
                        self.changed
                            .wait_timeout(state, wait)
                            .unwrap_or_else(|e| e.into_inner())
                            .0
                    }
                    None => self.changed.wait(state).unwrap_or_else(|e| e.into_inner()),
                };
            }
        }
    }
}

/// The `setTimeout` that wakes the clock in a browser.
#[cfg(target_arch = "wasm32")]
mod browser {
    use std::task::Waker;

    use wasm_bindgen::prelude::*;

    use crate::sys::Instant;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_name = setTimeout)]
        fn set_timeout(handler: &JsValue, millis: f64) -> JsValue;
    }

    /// Wakes `wake` at `deadline`. A timeout armed for a deadline that has
    /// moved since wakes the clock early, and the clock arms the next one.
    pub(super) fn arm(deadline: Instant, wake: Waker) {
        let wait = deadline.saturating_duration_since(Instant::now());
        let fire = Closure::once_into_js(move || wake.wake());
        set_timeout(&fire, wait.as_secs_f64() * 1000.0);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn wait_for(what: &str, done: impl Fn() -> bool) {
        let give_up = std::time::Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < give_up, "{what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Each driver wakes its own clock at its own deadline, not before, and
    /// forgets the deadline once it has; a deadline moved later is the one
    /// it waits for.
    #[test]
    fn each_driver_wakes_its_own_clock_at_its_deadline() {
        let wakes: Vec<Arc<Wakes>> = (0..2).map(|_| Arc::default()).collect();
        let drivers: Vec<Driver> = wakes
            .iter()
            .map(|w| Driver::new(Waker::from(w.clone())))
            .collect();
        let start = Instant::now();
        drivers[0].set(Some(start + Duration::from_secs(3600)));
        drivers[0].set(Some(start + Duration::from_millis(20)));
        drivers[1].set(Some(start + Duration::from_secs(3600)));
        wait_for("the first driver never woke its clock", || {
            wakes[0].0.load(Ordering::SeqCst) == 1
        });
        assert!(Instant::now() >= start + Duration::from_millis(20));
        assert_eq!(drivers[0].deadline(), None);
        assert_eq!(
            wakes[1].0.load(Ordering::SeqCst),
            0,
            "the other driver woke early"
        );
        assert!(drivers[1].deadline().is_some());
    }

    /// A deadline moved later leaves the sleeping thread asleep; one moved
    /// earlier wakes it.
    #[test]
    fn only_an_earlier_deadline_wakes_the_thread() {
        let driver = Driver::new(Waker::noop().clone());
        let start = Instant::now();
        driver.set(Some(start + Duration::from_secs(3600)));
        let looks = || driver.shared.looks.load(Ordering::SeqCst);
        wait_for("the thread never started", || looks() >= 1);
        // Holding the lock until the thread waits on it.
        drop(driver.shared.state.lock());
        let asleep = looks();
        for i in 1..=1000 {
            driver.set(Some(start + Duration::from_secs(3600 + i)));
        }
        driver.set(None);
        assert!(
            looks() <= asleep + 1,
            "{} looks for 1,001 later or no deadlines",
            looks() - asleep
        );
        driver.set(Some(start + Duration::from_secs(60)));
        wait_for("an earlier deadline did not wake the thread", || {
            looks() > asleep
        });
    }

    /// Dropping the driver, as its clock is dropped, ends its thread.
    #[test]
    fn dropping_the_driver_ends_its_thread() {
        let driver = Driver::new(Waker::noop().clone());
        let thread = driver.thread();
        driver.set(Some(Instant::now() + Duration::from_secs(3600)));
        drop(driver);
        wait_for("the driver's thread outlived its clock", || {
            thread.upgrade().is_none()
        });
    }
}
