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
pub struct CancelWait(pub(super) Option<Registered>);

/// Where a [`CancelWait`] is registered, and a clone of the waker it left
/// there, so that registering the same waker again is a local comparison
/// and takes no lock.
pub(super) struct Registered {
    pub(super) region: Arc<Region>,
    pub(super) key: u64,
    pub(super) waker: Waker,
}

impl CancelWait {
    pub(super) fn clear(&mut self) {
        if let Some(registered) = self.0.take() {
            let removed = registered
                .region
                .state
                .lock()
                .foreign
                .remove(&registered.key);
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
    parent: Option<Weak<Region>>,
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
    /// Spawned work here or below that has not ended yet.
    live: usize,
    /// Keeps the ancestor accounting alive while descendants have tasks.
    active_parent: Option<Arc<Region>>,
    /// The owner observed completion; no more tasks may enter.
    completed: bool,
    /// Woken when `live` drops to zero.
    done: Option<Waker>,
    /// How many times this region was renewed ([`Region::renew`]). A
    /// renewal starts it with no children, so a region made in it before
    /// is no longer among them, and is never renewed under it again.
    renewals: u64,
    /// The parent's `renewals` when this region was made in it, or last
    /// renewed under it.
    made_in: u64,
}

impl Region {
    pub(crate) fn root(run: Weak<RunShared>) -> Arc<Region> {
        Arc::new(Region {
            run,
            parent: None,
            cancelled: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            state: Mutex::default(),
        })
    }

    pub(crate) fn child(self: &Arc<Self>) -> Arc<Region> {
        let child = {
            let mut state = self.state.lock();
            let child = Arc::new(Region {
                run: self.run.clone(),
                parent: Some(Arc::downgrade(self)),
                cancelled: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                state: Mutex::new(RegionState {
                    made_in: state.renewals,
                    ..RegionState::default()
                }),
            });
            if state.children.len() >= 16 && state.children.len().is_power_of_two() {
                state.children.retain(|c| c.strong_count() > 0);
            }
            state.children.push(Arc::downgrade(&child));
            child
        };
        if self.is_cancelled() {
            child.cancel();
        }
        child
    }

    /// Makes this region, whose tasks have all ended and which nothing
    /// else holds, the region of a new job under `parent`, the region it
    /// was made in: no error, no tasks, admission open, and cancelled only
    /// if `parent` is. Returns whether it could; it cannot, and nothing
    /// changes, when something else holds it, it was made elsewhere, or
    /// `parent` was renewed since, which left it out of `parent`'s
    /// children.
    ///
    /// The parent's lock orders this against the parent's cancel, which
    /// takes its children under that lock and cancels each after: a cancel
    /// that set the parent's flag before this read it leaves this region
    /// cancelled, and one after takes this region with the parent's
    /// children and cancels it once this returns.
    pub(crate) fn renew(self: &Arc<Self>, parent: &Arc<Region>) -> bool {
        if Arc::strong_count(self) != 1
            || !self
                .parent
                .as_ref()
                .is_some_and(|made_in| std::ptr::eq(made_in.as_ptr(), Arc::as_ptr(parent)))
        {
            return false;
        }
        let siblings = parent.state.lock();
        let mut state = self.state.lock();
        if state.live != 0 || state.made_in != siblings.renewals {
            return false;
        }
        // The children it had are gone or held by no context, so no task
        // can start in them; it starts with none, and they are never
        // renewed under it.
        let old = std::mem::take(&mut *state);
        state.renewals = old.renewals + 1;
        state.made_in = siblings.renewals;
        self.stopped.store(false, Ordering::Release);
        self.cancelled
            .store(parent.is_cancelled(), Ordering::Release);
        drop(state);
        drop(siblings);
        // Dropped outside the locks: dropping a waker can run any code.
        drop(old);
        true
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

    /// Puts `waker` in place of what registration `key` left. A key a
    /// cancel took is put back: the caller sees the cancel next.
    pub(super) fn update_foreign(&self, key: u64, waker: &Waker) {
        let old = self.state.lock().foreign.insert(key, waker.clone());
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
        let parent = match &self.parent {
            Some(parent) => match parent.upgrade() {
                Some(parent) if parent.try_start_task() => Some(parent),
                _ => return false,
            },
            None => None,
        };
        let mut state = self.state.lock();
        if state.completed {
            drop(state);
            if let Some(parent) = parent {
                parent.task_done(false);
            }
            return false;
        }
        if state.live == 0 {
            state.active_parent = parent;
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
        let (done, parent) = {
            let mut state = self.state.lock();
            state.live -= 1;
            if state.live == 0 {
                (state.done.take(), state.active_parent.take())
            } else {
                (None, state.active_parent.clone())
            }
        };
        if failed {
            self.cancel();
        }
        if let Some(w) = done {
            w.wake();
        }
        if let Some(parent) = parent {
            // Descendant completion releases accounting, not its local error.
            parent.task_done(false);
        }
    }

    pub(crate) fn poll_done(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock();
        if state.live == 0 {
            state.completed = true;
            Poll::Ready(())
        } else {
            let old = state.done.replace(cx.waker().clone());
            drop(state);
            drop(old);
            Poll::Pending
        }
    }

    pub(crate) fn take_error(&self) -> Option<crate::Error> {
        self.state.lock().error.take()
    }

    /// How many wakers outside the run wait for a cancel here.
    #[cfg(test)]
    pub(crate) fn foreign_waits(&self) -> usize {
        self.state.lock().foreign.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::ms;
    use crate::{Cancelled, Cx, JoinError, block_on, run};
    use std::future::{Future, poll_fn};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn completion_waits_for_descendants_and_preserves_error_isolation() {
        let root = Region::root(Weak::new());
        let child = root.child();
        let grandchild = child.child();
        let sibling = root.child();
        assert!(grandchild.try_start_task());
        assert!(sibling.try_start_task());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(root.poll_done(&mut cx).is_pending());
        assert!(child.poll_done(&mut cx).is_pending());
        assert_eq!(root.state.lock().live, 2);
        grandchild.task_done(true);
        assert!(grandchild.is_cancelled());
        assert!(!child.is_cancelled());
        assert!(!root.is_cancelled());
        assert!(!sibling.is_cancelled());
        assert!(child.poll_done(&mut cx).is_ready());
        assert!(root.poll_done(&mut cx).is_pending());
        sibling.task_done(false);
        assert!(root.poll_done(&mut cx).is_ready());
    }

    /// A region whose work ended, failed and was cancelled is new again
    /// once renewed under its parent: no error, admission open, not
    /// cancelled, and still among the parent's children, so the parent's
    /// cancel reaches it. It is not renewed while something else holds it
    /// or under another parent, and under a cancelled parent it stays
    /// cancelled.
    #[test]
    fn a_renewed_region_is_new_and_still_its_parents_child() {
        let root = Region::root(Weak::new());
        let other = Region::root(Weak::new());
        let job = root.child();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(job.try_start_task());
        job.record_error(crate::Error::msg("a task of the job failed"));
        job.task_done(true);
        assert!(job.poll_done(&mut cx).is_ready());
        assert!(job.is_cancelled());

        let held = job.clone();
        assert!(!job.renew(&root), "another holds it");
        drop(held);
        assert!(!job.renew(&other), "it was made under another region");
        assert!(job.is_cancelled(), "a refusal changes nothing");

        assert!(job.renew(&root));
        assert!(!job.is_cancelled());
        assert!(job.take_error().is_none());
        assert!(job.try_start_task(), "admission is open again");
        assert!(
            root.poll_done(&mut cx).is_pending(),
            "its task counts above"
        );
        job.task_done(false);
        assert!(root.poll_done(&mut cx).is_ready());

        root.cancel();
        assert!(job.is_cancelled(), "the parent's cancel reaches it");
        assert!(job.renew(&root));
        assert!(
            job.is_cancelled(),
            "under a cancelled parent it stays cancelled"
        );
    }

    /// A renewal starts a region with no children, so a region made in it
    /// before is never renewed under it again: it would be out of its
    /// parent's reach. One made after the renewal is.
    #[test]
    fn a_region_made_before_its_parent_was_renewed_is_not_renewed() {
        let root = Region::root(Weak::new());
        let job = root.child();
        let nested = job.child();
        job.cancel();
        assert!(job.renew(&root));
        assert!(!nested.renew(&job), "its parent was renewed since");
        assert!(nested.is_cancelled(), "a refusal changes nothing");
        let later = job.child();
        later.cancel();
        assert!(later.renew(&job));
        assert!(!later.is_cancelled());
        job.cancel();
        assert!(
            later.is_cancelled(),
            "the renewed parent's cancel reaches it"
        );
    }

    #[test]
    fn descendants_keep_accounting_alive_without_retaining_idle_regions() {
        let root = Region::root(Weak::new());
        let middle = root.child();
        let child = middle.child();
        let weak = Arc::downgrade(&middle);
        assert!(child.try_start_task());
        drop(middle);
        assert!(weak.upgrade().is_some());
        assert_eq!(root.state.lock().live, 1);
        child.task_done(false);
        assert!(weak.upgrade().is_none());
        assert_eq!(root.state.lock().live, 0);
        assert!(
            !child.try_start_task(),
            "an expired ancestor cannot be reopened"
        );
    }

    #[test]
    fn closed_admission_rolls_back_every_ancestor_reservation() {
        let root = Region::root(Weak::new());
        let middle = root.child();
        let child = middle.child();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(child.poll_done(&mut cx).is_ready());
        assert!(!child.try_start_task());
        assert_eq!(middle.state.lock().live, 0);
        assert_eq!(root.state.lock().live, 0);
        assert!(middle.poll_done(&mut cx).is_ready());
        assert!(!middle.child().try_start_task());
        assert_eq!(root.state.lock().live, 0);
        assert!(root.poll_done(&mut cx).is_ready());
        assert!(!root.child().child().try_start_task());
    }

    #[test]
    fn completion_waiter_replacement_releases_wakers_outside_the_lock() {
        struct CheckDrop(Weak<Region>, Arc<AtomicBool>);
        impl std::task::Wake for CheckDrop {
            fn wake(self: Arc<Self>) {
                panic!("replacing or releasing a waiter must not wake it");
            }
        }
        impl Drop for CheckDrop {
            fn drop(&mut self) {
                assert!(self.0.upgrade().unwrap().state.try_lock().is_some());
                self.1.store(true, Ordering::SeqCst);
            }
        }
        let region = Region::root(Weak::new());
        assert!(region.try_start_task());
        let dropped = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(CheckDrop(
            Arc::downgrade(&region),
            dropped.clone(),
        )));
        assert!(
            region
                .poll_done(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(waker);
        assert!(
            region
                .poll_done(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(dropped.load(Ordering::SeqCst));
        region.task_done(false);
        assert!(
            region
                .poll_done(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }

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
            let waker = Waker::from(Arc::new(CheckDrop(
                Arc::downgrade(&region),
                dropped.clone(),
            )));
            let key = region.add_foreign(&waker);
            let mut wait = CancelWait(Some(Registered {
                region: region.clone(),
                key,
                waker,
            }));
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

    /// The `Cx` of a run polled once, with the run, which must stay alive.
    fn outside_cx() -> (Cx, std::pin::Pin<Box<impl Future<Output = crate::Result>>>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut world = Box::pin(run(fictionet::Seed::from_u64(0), move |fcx| async move {
            tx.send(fcx.clone()).unwrap();
            std::future::pending::<()>().await;
            Ok(())
        }));
        assert!(
            world
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        (rx.recv().unwrap(), world)
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A wait outside the run that registers the waker it registered
    /// before takes no lock: it goes through with the region's lock held
    /// elsewhere.
    #[test]
    fn an_unchanged_waker_registers_again_without_the_region_lock() {
        let (fcx, world) = outside_cx();
        let waker = Waker::from(Arc::new(Wakes::default()));
        let mut wait = CancelWait::default();
        assert!(!fcx.register_cancel(&waker, &mut wait));
        let region = fcx.region.clone();
        let held = region.state.lock();
        let (done, finished) = std::sync::mpsc::channel();
        let again = std::thread::spawn(move || {
            for _ in 0..1000 {
                assert!(!fcx.register_cancel(&waker.clone(), &mut wait));
            }
            done.send(()).unwrap();
            // Dropping the wait takes the lock: hand it back instead.
            (fcx, wait)
        });
        let finished = finished.recv_timeout(std::time::Duration::from_secs(10));
        drop(held);
        drop(again.join().unwrap());
        drop(world);
        assert_eq!(finished, Ok(()), "registering the same waker took the lock");
    }

    /// Whatever wakers a wait registers in turn, a cancel wakes the last
    /// one once and none of the others.
    #[test]
    fn a_cancel_wakes_the_waker_registered_last_once() {
        let (fcx, world) = outside_cx();
        let counts: Vec<Arc<Wakes>> = (0..3).map(|_| Arc::default()).collect();
        let wakers: Vec<Waker> = counts.iter().map(|c| Waker::from(c.clone())).collect();
        let mut wait = CancelWait::default();
        for i in [0, 0, 1, 1, 2, 0, 2, 2] {
            assert!(!fcx.register_cancel(&wakers[i], &mut wait));
        }
        assert_eq!(fcx.region.state.lock().foreign.len(), 1);
        fcx.cancel();
        let woken: Vec<usize> = counts.iter().map(|c| c.0.load(Ordering::SeqCst)).collect();
        assert_eq!(woken, [0, 0, 1]);
        assert!(fcx.register_cancel(&wakers[2], &mut wait));
        drop(wait);
        drop(world);
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
        block_on(crate::lab(crate::Seed::from_u64(0), |fcx| async move {
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
        }))
        .unwrap();
    }

    #[test]
    fn a_nested_region_waits_for_its_work_and_keeps_its_error() {
        let ended = Arc::new(AtomicUsize::new(0));
        let e = ended.clone();
        block_on(run(fictionet::Seed::random(), move |fcx| async move {
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
        }))
        .unwrap();
    }

    /// A region future dropped before it ends, for example by a timeout
    /// around it, cancels its work, so the work cannot outlive it for long.
    #[test]
    fn dropping_a_region_cancels_its_work() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = block_on(run(fictionet::Seed::random(), |fcx| async move {
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
            }));
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
        let res = block_on(run(fictionet::Seed::random(), |fcx| async move {
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
        }));
        assert_eq!(res.unwrap_err().to_string(), "failed holding a link");
    }

    /// A task that ends with a cancel has not failed: here it waited on
    /// another region's `Cx`, which was stopped. Its own region keeps
    /// nothing, is not cancelled, and its joiner hears `Cancelled`.
    #[test]
    fn a_task_that_ends_with_a_cancel_does_not_fail_its_region() {
        let res = block_on(run(fictionet::Seed::random(), |fcx| async move {
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
        }));
        assert!(res.is_ok(), "{res:?}");
    }

    /// `region` returns `Ok` when stopped with `Cx::cancel`, and
    /// `Cancelled` when cut short from outside, whatever error type its
    /// work used to say so.
    #[test]
    fn a_region_says_whether_it_was_stopped_or_cut_short() {
        let res = block_on(run(fictionet::Seed::random(), |fcx| async move {
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
        }));
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn cancelling_a_region_cancels_regions_inside_it() {
        let res = block_on(run(fictionet::Seed::random(), |fcx| async move {
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
        }));
        assert_eq!(res.unwrap_err().to_string(), "outer");
    }
}
