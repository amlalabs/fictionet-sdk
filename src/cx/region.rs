use fictionet::sync::Mutex;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

use crate::run::RunShared;

/// One wait's place for its waker in a region, for waits polled outside the
/// run. See [`Cx::register_cancel`](crate::Cx::register_cancel). Dropping it takes the waker out.
/// Create an empty token with [`Default::default`]. Registering it with
/// another region removes its waker from the previous region.
#[derive(Default)]
pub struct CancelWait(pub(super) Option<(Arc<Region>, u64)>);

impl CancelWait {
    pub(super) fn clear(&mut self) {
        if let Some((region, key)) = self.0.take() {
            let removed = region.state.lock().foreign.remove(&key);
            drop(removed);
        }
    }
}

impl Drop for CancelWait {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A region: a group of work that is cancelled together and ends together.
pub(crate) struct Region {
    run: Weak<RunShared>,
    cancelled: AtomicBool,
    /// Cancelled by [`Cx::cancel`](crate::Cx::cancel): errors from then on are not kept.
    pub(super) stopped: AtomicBool,
    state: Mutex<RegionState>,
}

#[derive(Default)]
struct RegionState {
    children: Vec<Weak<Region>>,
    /// Wakers outside this run to wake on cancel, in [`CancelWait`]
    /// registration order.
    foreign: BTreeMap<u64, Waker>,
    next_key: u64,
    /// The first error of the region.
    error: Option<crate::Error>,
    /// Some of its work ended with a cancel instead of finishing.
    cancel_ended: bool,
    /// Spawned work that has not ended yet.
    live: usize,
    /// The owner observed completion; no more tasks may enter.
    completed: bool,
    /// Woken when `live` drops to zero.
    done: Option<Waker>,
}

impl Region {
    pub(crate) fn root(run: Weak<RunShared>) -> Arc<Region> {
        Arc::new(Region {
            run,
            cancelled: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            state: Mutex::default(),
        })
    }

    pub(super) fn child(self: &Arc<Self>) -> Arc<Region> {
        let child = Arc::new(Region {
            run: self.run.clone(),
            cancelled: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            state: Mutex::default(),
        });
        {
            let mut state = self.state.lock();
            if state.children.len() >= 16 && state.children.len().is_power_of_two() {
                state.children.retain(|c| c.strong_count() > 0);
            }
            state.children.push(Arc::downgrade(&child));
        }
        if self.is_cancelled() {
            child.cancel();
        }
        child
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Cancels this region and every region inside it.
    pub(crate) fn cancel(&self) {
        if self.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let (foreign, children) = {
            let mut state = self.state.lock();
            (
                std::mem::take(&mut state.foreign),
                std::mem::take(&mut state.children),
            )
        };
        for w in foreign.into_values() {
            w.wake();
        }
        for child in children.iter().filter_map(Weak::upgrade) {
            child.cancel();
        }
        if let Some(run) = self.run.upgrade() {
            run.wake_all();
        }
    }

    /// Records `error` if it is the first, and cancels the region.
    pub(crate) fn fail(&self, error: crate::Error) {
        self.record_error(error);
        self.cancel();
    }

    pub(super) fn add_foreign(&self, waker: &Waker) -> u64 {
        let mut state = self.state.lock();
        let key = state.next_key;
        state.next_key += 1;
        state.foreign.insert(key, waker.clone());
        key
    }

    pub(super) fn update_foreign(&self, key: u64, waker: &Waker) {
        let mut state = self.state.lock();
        if let Some(w) = state.foreign.get(&key)
            && w.will_wake(waker)
        {
            return;
        }
        // A key a cancel took is put back: the caller sees the cancel next.
        let old = state.foreign.insert(key, waker.clone());
        drop(state);
        // Dropped outside the lock: dropping a waker can run any code.
        drop(old);
    }

    /// Notes that work in the region ended with a cancel. It is not a
    /// failure: nothing is kept and nothing is cancelled.
    pub(crate) fn ended_by_cancel(&self) {
        self.state.lock().cancel_ended = true;
    }

    /// Whether the region was cancelled from outside, not stopped with
    /// [`Cx::cancel`](crate::Cx::cancel), and some of its work ended with the cancel.
    pub(super) fn cut_short(&self) -> bool {
        self.is_cancelled()
            && !self.stopped.load(Ordering::Acquire)
            && self.state.lock().cancel_ended
    }

    pub(crate) fn try_start_task(&self) -> bool {
        let mut state = self.state.lock();
        if state.completed {
            return false;
        }
        state.live += 1;
        true
    }

    /// Keeps `error` if it is the region's first and the region was not
    /// stopped with [`Cx::cancel`](crate::Cx::cancel). It cancels nothing: a failed task's
    /// error is kept with this before the task is dropped, and
    /// [`task_done`](Region::task_done) cancels after.
    pub(crate) fn record_error(&self, error: crate::Error) {
        let mut state = self.state.lock();
        if state.error.is_none() && !self.stopped.load(Ordering::Acquire) {
            state.error = Some(error);
        }
    }

    /// Counts one task as ended. `failed` cancels the region: the task's
    /// error was already kept with [`record_error`](Region::record_error).
    pub(crate) fn task_done(&self, failed: bool) {
        let done = {
            let mut state = self.state.lock();
            state.live -= 1;
            if state.live == 0 {
                state.done.take()
            } else {
                None
            }
        };
        if failed {
            self.cancel();
        }
        if let Some(w) = done {
            w.wake();
        }
    }

    pub(super) fn poll_done(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock();
        if state.live == 0 {
            state.completed = true;
            Poll::Ready(())
        } else {
            state.done = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    pub(crate) fn take_error(&self) -> Option<crate::Error> {
        self.state.lock().error.take()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::time::ms;
    use crate::{Cancelled, Cx, JoinError, block_on, run};
    use std::future::{Future, poll_fn};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn cancellation_registration_releases_wakers_outside_the_lock() {
        struct CheckDrop(Weak<Region>, Arc<AtomicBool>);
        impl std::task::Wake for CheckDrop {
            fn wake(self: Arc<Self>) {
                panic!("unregistering a waker must not wake it");
            }
        }
        impl Drop for CheckDrop {
            fn drop(&mut self) {
                assert!(self.0.upgrade().unwrap().state.try_lock().is_some());
                self.1.store(true, Ordering::SeqCst);
            }
        }
        for clear in [false, true] {
            let region = Region::root(Weak::new());
            let dropped = Arc::new(AtomicBool::new(false));
            let key = region.add_foreign(&Waker::from(Arc::new(CheckDrop(
                Arc::downgrade(&region),
                dropped.clone(),
            ))));
            let mut wait = CancelWait(Some((region.clone(), key)));
            if clear {
                wait.clear();
                assert!(dropped.load(Ordering::SeqCst));
                wait.clear();
            }
            drop(wait);
            assert!(dropped.load(Ordering::SeqCst));
            assert!(region.state.lock().foreign.is_empty());
        }
    }

    #[test]
    fn cancellation_wakes_in_registration_order() {
        struct WakeLog(usize, Arc<Mutex<Vec<usize>>>);
        impl std::task::Wake for WakeLog {
            fn wake(self: Arc<Self>) {
                self.1.lock().push(self.0);
            }
        }
        let region = Region::root(Weak::new());
        let log = Arc::new(Mutex::new(Vec::new()));
        for id in [8, 3, 12, 1, 9] {
            region.add_foreign(&Waker::from(Arc::new(WakeLog(id, log.clone()))));
        }
        region.cancel();
        assert_eq!(*log.lock(), [8, 3, 12, 1, 9]);
    }

    #[test]
    fn cancelling_a_child_wakes_a_parent_task_waiting_on_it() {
        block_on(crate::lab(
            fictionet::RunOptions::new(crate::Seed::from_u64(0)),
            |fcx| async move {
                fcx.region(|child| async move {
                    child.spawn(|task| async move {
                        task.sleep(ms(1)).await?;
                        task.cancel();
                        Ok(())
                    });
                    // The region's owner is polled in the parent's task.
                    poll_fn(|_| {
                        if child.is_cancelled() {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                    Ok(())
                })
                .await
            },
        ))
        .unwrap();
    }

    #[test]
    fn a_nested_region_waits_for_its_work_and_keeps_its_error() {
        let ended = Arc::new(AtomicUsize::new(0));
        let e = ended.clone();
        block_on(run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            move |fcx| async move {
                // Ok: waits for the region's work.
                let e1 = e.clone();
                fcx.region(|fcx| async move {
                    fcx.spawn(move |fcx| async move {
                        fcx.sleep(ms(20)).await?;
                        e1.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    });
                    Ok(())
                })
                .await?;
                assert_eq!(e.load(Ordering::SeqCst), 1);

                // A task's error cancels the nested region only, and comes back
                // from `region` instead of failing the run.
                let e2 = e.clone();
                let res = fcx
                    .region(|fcx| async move {
                        fcx.spawn(move |fcx| async move {
                            let r = fcx.sleep(std::time::Duration::from_secs(60)).await;
                            assert_eq!(r, Err(Cancelled));
                            e2.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        });
                        fcx.spawn(|_fcx| async { Err(crate::Error::msg("conn failed")) });
                        Ok(())
                    })
                    .await;
                assert_eq!(res.unwrap_err().to_string(), "conn failed");
                assert!(!fcx.is_cancelled());
                assert_eq!(e.load(Ordering::SeqCst), 2);
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A region future dropped before it ends, for example by a timeout
    /// around it, cancels its work, so the work cannot outlive it for long.
    #[test]
    fn dropping_a_region_cancels_its_work() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = block_on(run(
                fictionet::RunOptions::new(fictionet::Seed::random()),
                |fcx| async move {
                    let started = Arc::new(AtomicUsize::new(0));
                    let s = started.clone();
                    let mut region = std::pin::pin!(fcx.region(|fcx| async move {
                        fcx.spawn(move |fcx| async move {
                            s.fetch_add(1, Ordering::SeqCst);
                            fcx.sleep(std::time::Duration::from_secs(60)).await?;
                            Ok(())
                        });
                        fcx.sleep(std::time::Duration::from_secs(60)).await?;
                        Ok(())
                    }));
                    // Poll the region until its task has started, then give up
                    // on it, as a timeout would.
                    poll_fn(|cx| {
                        assert!(
                            region.as_mut().poll(cx).is_pending(),
                            "the region sleeps for 60 s"
                        );
                        if started.load(Ordering::SeqCst) == 1 {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    Ok(())
                },
            ));
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the receiver is gone only once recv_timeout below has failed the test"
            )]
            let _ = tx.send(out.map_err(|e| e.to_string()));
        });
        // The run ends once the task has seen the cancel; its Cancelled
        // error stays inside the dropped region.
        let out = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the dropped region's work kept running");
        assert_eq!(out, Ok(()));
    }

    /// `f` fails while its future still holds an interface. Dropping the
    /// future closes the interface, which wakes a watcher that cancels the
    /// nested region. The error came first, so `region` returns it.
    #[test]
    fn a_cancel_woken_by_dropping_a_failed_region_keeps_the_error() {
        struct CancelOnWake(Cx);
        impl std::task::Wake for CancelOnWake {
            fn wake(self: Arc<Self>) {
                self.0.cancel();
            }
        }
        let res = block_on(run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            |fcx| async move {
                use crate::Interface;
                let (inside, outside) = crate::pair();
                let watcher = Arc::new(Mutex::new(Some(outside)));
                let w = watcher.clone();
                let res = fcx
                    .region(move |fcx| {
                        let wake = Waker::from(Arc::new(CancelOnWake(fcx.clone())));
                        let mut outside = w.lock();
                        let polled = outside
                            .as_mut()
                            .unwrap()
                            .poll_recv(&fcx, &mut Context::from_waker(&wake));
                        assert!(polled.is_pending());
                        poll_fn(move |_| {
                            let _held = &inside;
                            Poll::Ready(Err(crate::Error::msg("failed holding a link")))
                        })
                    })
                    .await;
                drop(watcher);
                res
            },
        ));
        assert_eq!(res.unwrap_err().to_string(), "failed holding a link");
    }

    /// A task that ends with a cancel has not failed: here it waited on
    /// another region's `Cx`, which was stopped. Its own region keeps
    /// nothing, is not cancelled, and its joiner hears `Cancelled`.
    #[test]
    fn a_task_that_ends_with_a_cancel_does_not_fail_its_region() {
        let res = block_on(run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            |fcx| async move {
                let mut stopped = None;
                fcx.region(|inner| {
                    stopped = Some(inner.clone());
                    inner.cancel();
                    async { Ok(()) }
                })
                .await?;
                let stopped = stopped.unwrap();
                let task = fcx.spawn(move |_fcx| async move {
                    // A wrapper's `Cancelled` variant counts too.
                    let (mut a, _b) = crate::pair();
                    use crate::InterfaceExt;
                    a.recv(&stopped).await?;
                    Ok(())
                });
                assert!(matches!(task.join(&fcx).await, Err(JoinError::Cancelled)));
                assert!(!fcx.is_cancelled());
                Ok(())
            },
        ));
        assert!(res.is_ok(), "{res:?}");
    }

    /// `region` returns `Ok` when stopped with `Cx::cancel`, and
    /// `Cancelled` when cut short from outside, whatever error type its
    /// work used to say so.
    #[test]
    fn a_region_says_whether_it_was_stopped_or_cut_short() {
        let res = block_on(run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            |fcx| async move {
                let stopped = fcx
                    .region(|inner| async move {
                        inner.cancel();
                        inner.sleep(std::time::Duration::from_secs(60)).await?;
                        Ok(())
                    })
                    .await;
                assert!(stopped.is_ok(), "{stopped:?}");
                let outer = fcx.clone();
                let cut = fcx
                    .region(|inner| async move {
                        let (mut a, _b) = crate::pair();
                        use crate::InterfaceExt;
                        outer.spawn(move |fcx| async move {
                            fcx.sleep(ms(10)).await?;
                            fcx.cancel();
                            Ok(())
                        });
                        a.recv(&inner).await?;
                        Ok(())
                    })
                    .await;
                let e = cut.unwrap_err();
                assert!(e.is::<Cancelled>(), "{e:?}");
                Ok(())
            },
        ));
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn cancelling_a_region_cancels_regions_inside_it() {
        let res = block_on(run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            |fcx| async move {
                fcx.spawn(|fcx| async move {
                    let inner = fcx
                        .region(|fcx| async move {
                            fcx.sleep(std::time::Duration::from_secs(60))
                                .await
                                .map_err(Into::into)
                        })
                        .await;
                    assert!(inner.unwrap_err().is::<Cancelled>());
                    Ok(())
                });
                fcx.sleep(ms(10)).await?;
                Err(crate::Error::msg("outer"))
            },
        ));
        assert_eq!(res.unwrap_err().to_string(), "outer");
    }
}
