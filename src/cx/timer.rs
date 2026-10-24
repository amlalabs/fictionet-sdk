use std::task::{Context, Poll};

use super::{CancelWait, Cancelled, Cx};
use crate::time::Instant;

/// A sleep whose deadline can move, for a task that polls by hand and
/// whose next deadline changes often, such as a TCP endpoint's driver.
/// Moving the deadline reuses the same timer entry, where dropping one
/// [`Cx::sleep_until`] future and making another would add and remove an
/// entry, and allocate the boxed future, each time.
/// Create an inactive timer with [`Timer::new`]. Each call to
/// [`Timer::poll_until`] sets its deadline. [`Timer::clear`] removes the
/// deadline; dropping the timer also unregisters its cancellation waiter.
/// Use a timer with one region.
pub struct Timer {
    fcx: Cx,
    /// The logical deadline of the timer entry, if there is one.
    deadline: Option<Instant>,
    entry: Option<u64>,
    wait: CancelWait,
}

impl Timer {
    /// Creates an inactive timer owned by this context's run and region.
    pub fn new(fcx: &Cx) -> Self {
        Self {
            fcx: fcx.clone(),
            deadline: None,
            entry: None,
            wait: CancelWait::default(),
        }
    }

    /// Polls for `deadline` to pass: `Ready(Ok(()))` once it has. Until
    /// then, `cx`'s waker is woken when it passes or when the owning region is
    /// cancelled. Cancellation returns `Ready(Err(Cancelled))`, even if
    /// the deadline has passed. `Duration::MAX` is an unarmed wait. Real
    /// deadlines beyond the host clock's range also wait only for cancellation.
    pub fn poll_until(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Instant,
    ) -> Poll<Result<(), Cancelled>> {
        if self.fcx.is_cancelled() {
            return Poll::Ready(Err(Cancelled));
        }
        // A deadline past what the clock can hold never comes.
        match self
            .fcx
            .run
            .environment
            .clock
            .finite(deadline)
            .then_some(deadline)
        {
            Some(at) => {
                if self.fcx.now() >= at {
                    self.clear();
                    return Poll::Ready(Ok(()));
                }
                match self.entry {
                    Some(id) if self.deadline == Some(at) => {
                        self.fcx.run.environment.clock.update(id, cx.waker())
                    }
                    Some(id) => self.fcx.run.environment.clock.reset(id, at, cx.waker()),
                    None => {
                        self.entry =
                            Some(self.fcx.run.environment.clock.add(at, cx.waker().clone()))
                    }
                }
                self.deadline = Some(at);
            }
            None => self.clear(),
        }
        if self.fcx.register_cancel(cx.waker(), &mut self.wait) {
            return Poll::Ready(Err(Cancelled));
        }
        Poll::Pending
    }

    /// Removes the deadline and its timer entry, if any.
    /// The cancellation registration stays until the timer is dropped.
    pub fn clear(&mut self) {
        if let Some(id) = self.entry.take() {
            self.fcx.run.environment.clock.remove(id);
        }
        self.deadline = None;
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
    /// set. A timer that moves its deadline is set again, so it wakes after
    /// a timer that set the same deadline before it moved.
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
            fcx.sleep_until(Instant::from_since_start(ms(30))).await?;
            assert_eq!(*woken.lock(), ["second", "first"]);
            Ok(())
        }))
        .unwrap();
    }
}
