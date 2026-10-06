use std::borrow::Cow;
use std::future::{Future, poll_fn};
use std::panic::Location;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use crate::run::RunShared;
use crate::watch::Group;
use crate::time::{Duration, Instant};
use crate::timer::timers;

/// The context that world code runs in.
///
/// A `Cx` is how world code reads the time, waits, draws random numbers and
/// starts background tasks. Fictionet has no global clock and no global
/// executor, so all four go through a `Cx`. That is why every stdlib
/// function that waits or starts a task takes `&Cx` as its first argument, and why the core works under
/// any async runtime. [`run`](crate::run) gives the world function its
/// first `Cx`.
///
/// # Regions
///
/// A region is a group of tasks that are cancelled together, and that their
/// owner waits for. Every `Cx` belongs to one region. [`Cx::spawn`] starts a
/// task in the caller's region and gives it a `Cx` of its own in that same
/// region. A clone of a `Cx` belongs to the same region too.
///
/// [`run`](crate::run) makes the outermost region, and the world function
/// is its first task. So the tasks the world starts, and the tasks those
/// tasks start, all share the world's region. Some stdlib code makes a
/// region inside the caller's for work that may fail on its own: for
/// example, [`web::Sites`](crate::stdlib::web::Sites) gives each HTTP
/// connection its own region, and runs its HTTP/2 streams in it. Cancelling
/// a region also cancels every region inside it.
///
/// Three rules hold for every region:
///
/// - A region ends only after all of its tasks have ended. No task outlives
///   the region that owns it.
/// - When the function that owns a region returns `Ok`, the region is not
///   cancelled. Its tasks keep running until they end on their own, or
///   until the region is cancelled from outside. This is how a world can
///   wire its network, return `Ok(())`, and leave the network running.
/// - When a task in the region returns an error, the region is cancelled.
///   The first error comes out once all of the region's tasks have ended.
///   [`Cx::cancel`] cancels a region without an error, and the region then
///   ends with `Ok`, unless a task failed before the cancel.
///
/// [`running`](crate::running#what-ends-what) has a table of every way a
/// world and its tasks end.
///
#[doc = include_str!("../docs/diagrams/regions.svg")]
///
/// # Groups
///
/// A group names a set of tasks for the people watching a world, such as
/// "office LAN" or "simulated hosts". [`Cx::group`] returns a `Cx` whose
/// tasks belong to a new group. Every task started with that `Cx`, and
/// every task those tasks start, belongs to the group too, and so do the
/// stdlib's own tasks, such as a [`router`](crate::stdlib::route::router)
/// or a [`tcp::endpoint`](crate::stdlib::tcp::endpoint). Groups nest: a
/// group made from a grouped `Cx` sits inside that group.
///
/// Groups change nothing about how the world runs. A grouped `Cx` stays in
/// the same [region](Cx#regions), so cancelling and errors work as before.
/// Only observers read groups: the [dashboard](crate::observe) draws a
/// group as one box, with the traffic that crosses its edge added up, and
/// opens it to show what is inside.
///
/// # Stopping
///
/// Stopping is cooperative. Cancelling a region does not drop its tasks.
/// Instead, [`Cx::cancelled`] finishes for every `Cx` in the region, and
/// every wait in the region (`recv`, `sleep`, and the rest) returns early
/// with [`Cancelled`]. Each task then ends on its own, usually by passing
/// that error up with `?`.
///
/// Only Fictionet's own waits see a cancel. A task waiting on something
/// else, such as a tokio socket or a database query, is not interrupted,
/// and keeps its region open until that wait ends. Such a task races the
/// wait against [`Cx::cancelled`], as
/// [`running`](crate::running#cancellation-is-cooperative) shows.
///
/// Stdlib tasks stop when their region is cancelled, or when they have
/// nothing left to do because the [`Interface`](crate::Interface)s they
/// read from have closed. Packets still in flight when a task stops are
/// lost, as they would be on a real network link that is unplugged.
#[derive(Clone)]
pub struct Cx {
    pub(crate) run: Arc<RunShared>,
    pub(crate) region: Arc<Region>,
    /// The [group](Cx#groups) its tasks belong to, if any.
    pub(crate) group: Option<Arc<Group>>,
}

impl Cx {
    /// The current time on the run's clock: how long ago the run started.
    ///
    /// Under [`run`](crate::run) this is real time, read from the system's
    /// monotonic clock.
    pub fn now(&self) -> Instant {
        Instant::from_since_start(self.run.start.elapsed())
    }

    /// Waits until the run's clock reaches `deadline`.
    ///
    /// Returns immediately if `deadline` has already passed. Returns early
    /// with [`Cancelled`] if this `Cx`'s [region](Cx#regions) is cancelled.
    pub async fn sleep_until(&self, deadline: Instant) -> Result<(), Cancelled> {
        // A deadline past what the clock can hold never comes: the sleep
        // waits until it is cancelled.
        let deadline = self.run.start.checked_add(deadline.since_start());
        Sleep { cx: self, deadline, timer: None, wait: CancelWait::default() }.await
    }

    /// Waits for `d` to pass.
    ///
    /// Returns early with [`Cancelled`] if this `Cx`'s [region](Cx#regions)
    /// is cancelled.
    pub async fn sleep(&self, d: Duration) -> Result<(), Cancelled> {
        match self.now().since_start().checked_add(d) {
            Some(deadline) => self.sleep_until(Instant::from_since_start(deadline)).await,
            None => Sleep { cx: self, deadline: None, timer: None, wait: CancelWait::default() }.await,
        }
    }

    /// A random 64-bit number.
    ///
    /// World code should draw all of its randomness from here, so that every
    /// random choice in a world goes through one place. Under
    /// [`run`](crate::run) the numbers come from the operating system
    /// (`getrandom`). Seeded, repeatable runs are on
    /// [the roadmap](crate::roadmap#the-lab).
    pub fn random_u64(&self) -> u64 {
        os_random_u64()
    }

    /// A random number from 0 up to, but not including, 1.
    ///
    /// Use it for choices such as "10% of the time":
    /// `cx.random_f64() < 0.1`.
    pub fn random_f64(&self) -> f64 {
        (self.random_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Lets the other ready tasks of the run take a turn, then continues.
    ///
    /// All of a run's tasks share one thread, and a task keeps that thread
    /// until it waits. A loop that always has more to do, such as one reading
    /// a busy [`Interface`](crate::Interface), calls this now and then so it
    /// cannot starve the rest of the run. Stdlib tasks yield after at most 64
    /// packets or messages in a row.
    ///
    /// Returns [`Cancelled`] instead if this `Cx`'s [region](Cx#regions) is
    /// cancelled.
    pub async fn yield_now(&self) -> Result<(), Cancelled> {
        let mut yielded = false;
        poll_fn(|task| {
            if self.is_cancelled() {
                return Poll::Ready(Err(Cancelled));
            }
            if yielded {
                return Poll::Ready(Ok(()));
            }
            yielded = true;
            task.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }

    /// Starts `work` as a background task in this `Cx`'s
    /// [region](Cx#regions), and returns immediately.
    ///
    /// `work` is called with a new `Cx` in the same region, and the future it
    /// returns runs as its own task. The returned [`Task`] lets you wait for
    /// it with [`Task::join`]. Dropping the `Task` does not stop the work:
    /// the region owns it, not the handle.
    ///
    /// **If `work` returns an error, its region fails.** The region is
    /// cancelled, so its other tasks stop, and the error goes to whoever
    /// owns the region. For the world's region, that means the error comes
    /// out of [`run`](crate::run). A failure deep inside a world therefore
    /// reaches the harness instead of disappearing. Work that is allowed to
    /// fail, such as serving one connection, handles its own errors and
    /// returns `Ok(())`.
    #[track_caller]
    pub fn spawn<F, Fut>(&self, work: F) -> Task
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = crate::Result> + Send + 'static,
    {
        self.spawn_as(crate::watch::task_name::<Fut>, work)
    }

    /// [`Cx::spawn`], with the name observers see for the task. The
    /// stdlib names its tasks after the function that starts them.
    #[track_caller]
    pub(crate) fn spawn_as<F, Fut>(&self, name: impl FnOnce() -> Cow<'static, str>, work: F) -> Task
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = crate::Result> + Send + 'static,
    {
        let location = Location::caller();
        let region = self.region.clone();
        let future = work(Cx { run: self.run.clone(), region: region.clone(), group: self.group.clone() });
        let join = Arc::new(JoinState::default());
        region.task_started();
        let group = self.group.as_ref();
        if let Err(future) = self.run.spawn(Box::pin(future), region.clone(), join.clone(), name, location, group) {
            // The run is gone, so the work can never run.
            drop(future);
            region.task_done(false);
            join.finish(Err(Box::new(Cancelled)));
        }
        Task { join }
    }

    /// Returns a `Cx` whose tasks belong to a new [group](Cx#groups) called
    /// `name`, inside this `Cx`'s group if it has one.
    ///
    /// The new `Cx` is in the same [region](Cx#regions) as this one, so
    /// only observers see the difference. Hand it to the code that builds
    /// one part of the world, and every task that code starts, directly or
    /// through the stdlib, belongs to the group:
    ///
    /// ```
    /// # use fictionet::{Cx, Interface, Result};
    /// # use fictionet::stdlib::{ip, tcp};
    /// fn office(cx: &Cx, uplink: impl Interface) -> Result {
    ///     let lan = cx.group("office LAN");
    ///     let (tcp, _udp, _icmp, _other) = ip::split_protocols(&lan, uplink);
    ///     let printer = tcp::endpoint(&lan, tcp, "10.1.0.20".parse()?);
    ///     let _ipp = printer.listen(631)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// A sandbox belongs to the group of the task that reads its
    /// [`Attachment`](crate::Attachment), such as a
    /// [`delay`](crate::stdlib::delay) started with a grouped `Cx`. Each
    /// call makes a new group,
    /// even with a name used before. Making a group allocates its name and
    /// one small struct. A task in a group holds two more reference counts,
    /// one in its `Cx` and one in what the run records about it, whether or
    /// not anyone observes the world.
    pub fn group(&self, name: impl Into<String>) -> Cx {
        let group = Group::new(self.run.graph.next_group(), name.into(), self.group.clone());
        Cx { run: self.run.clone(), region: self.region.clone(), group: Some(group) }
    }

    /// Whether an observer is following this world's events right now,
    /// such as the dashboard or `fictionet observe watch`.
    ///
    /// Use it to skip work that only an observer would see, like
    /// formatting a large payload for [`Cx::emit`]. It reads one number,
    /// so it is cheap to call on every packet.
    pub fn observed(&self) -> bool {
        self.run.graph.observed()
    }

    /// Starts a custom event called `name`, which observers see next to
    /// the task that sent it. Add fields, then call
    /// [`emit`](crate::observe::Event::emit).
    ///
    /// ```
    /// # fn handled(cx: &fictionet::Cx) {
    /// cx.event("http_request").str("host", "example.test").str("path", "/count").int("status", 200).emit();
    /// # }
    /// ```
    ///
    /// The event carries the task that sent it and the time on this `Cx`'s
    /// clock. While nothing observes the world, the event is never made at
    /// all: each call returns immediately. See
    /// [Custom events](crate::observe#custom-events).
    pub fn event(&self, name: &str) -> crate::observe::Event<'_> {
        crate::observe::Event::new(self, name)
    }

    /// Sends a custom event whose payload is JSON text already, such as the
    /// output of `serde_json::to_string`.
    ///
    /// Fails with [`NotJson`](crate::observe::NotJson) if `payload` is not
    /// one JSON value. The check runs only while the world is observed:
    /// with no observer, `emit` returns `Ok(())` immediately and the
    /// payload is not read. Use [`Cx::observed`] to skip building a payload
    /// no observer will see, and [`Cx::event`] for flat events.
    pub fn emit(&self, name: &str, payload: &str) -> Result<(), crate::observe::NotJson> {
        crate::observe::emit(self, name, payload)
    }

    /// Waits until this `Cx`'s [region](Cx#regions) is cancelled.
    ///
    /// Returns immediately if it already is.
    pub async fn cancelled(&self) {
        let mut wait = CancelWait::default();
        poll_fn(|task| {
            if self.is_cancelled() || self.register_cancel(task.waker(), &mut wait) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Whether this `Cx`'s [region](Cx#regions) has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.region.is_cancelled()
    }

    /// Stops this `Cx`'s [region](Cx#regions) on purpose: cancels it, and
    /// every region inside it, as a clean shutdown rather than a failure.
    ///
    /// Returns immediately. Every task in the region then stops at its next
    /// wait, as after any cancel (see [Stopping](Cx#stopping)). The region
    /// reports success: errors that its tasks return after this call, such
    /// as the [`Cancelled`] that a task passes up with `?`, are not kept. An
    /// error from before the call is still reported.
    ///
    /// The world function and every task it spawns share the world's
    /// region, so calling this on any of their `Cx`s stops the whole world,
    /// and [`run`](crate::run) returns `Ok(())` once every task has ended.
    /// Some stdlib code runs work in a region of its own inside the world's,
    /// and hands that region's `Cx` to callbacks: for example,
    /// [`web::Sites`](crate::stdlib::web::Sites) runs each HTTP connection,
    /// and the event callback for it, in the connection's own region.
    /// Calling `cancel` on such a `Cx` stops only that connection. To stop
    /// the world from there, keep a clone of the world's `Cx` and cancel
    /// that. A `Cx` is `Send` and
    /// `Clone`, so a harness can keep a clone and call this from another
    /// thread or a tokio task. [In a test](crate::running#in-a-test) shows
    /// the pattern.
    pub fn cancel(&self) {
        self.region.stopped.store(true, Ordering::Release);
        self.region.cancel();
    }

    /// Runs `f` in a new region inside this one, and waits for that region
    /// to end: until `f` has returned and all the work it spawned has
    /// ended.
    ///
    /// `f` runs inside the task that awaits this. Its work is cancelled when
    /// this region is. If `f` or any of its work returns an error, the new
    /// region is cancelled and the first error is returned once all of its
    /// work has ended. This region is not failed by it: the caller decides.
    /// For work that is allowed to fail as a whole, such as serving one
    /// connection with its HTTP/2 streams.
    ///
    /// Dropping the returned future before it finishes cancels the new
    /// region. Its work then ends on its own, as after any cancel, but
    /// nothing waits for it and its errors are lost.
    #[allow(dead_code)]
    pub(crate) async fn region<F, Fut>(&self, f: F) -> crate::Result
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = crate::Result>,
    {
        /// Cancels the region if this future is dropped before the region
        /// ended, so that its work stops instead of running on unowned.
        struct CancelOnDrop(Option<Arc<Region>>);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                if let Some(region) = self.0.take() {
                    region.cancel();
                }
            }
        }
        let child = self.region.child();
        let mut guard = CancelOnDrop(Some(child.clone()));
        // `f`'s future is dropped only after its error is kept: dropping it
        // can close interfaces, which can wake code that cancels.
        let mut work = Box::pin(f(Cx { run: self.run.clone(), region: child.clone(), group: self.group.clone() }));
        let result = work.as_mut().await;
        if let Err(e) = result {
            child.fail(e);
        }
        drop(work);
        poll_fn(|task| child.poll_done(task)).await;
        guard.0 = None;
        match child.take_error() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// What this run records for observers.
    #[inline]
    pub(crate) fn graph(&self) -> &Arc<crate::watch::Graph> {
        &self.run.graph
    }

    /// Makes sure `waker` is woken when this region is cancelled. Returns
    /// whether it already is cancelled.
    ///
    /// Work polled by this run needs no registration: cancelling a region
    /// wakes every task of the run. Any other waker, such as a tokio task
    /// that holds an interface and a clone of this `Cx`, is kept in the
    /// region in `wait`'s slot. Each wait keeps one `CancelWait` for as long
    /// as it lives, and dropping it takes the waker out of the region, so a
    /// region holds one waker per wait outside the run, no more.
    pub(crate) fn register_cancel(&self, waker: &Waker, wait: &mut CancelWait) -> bool {
        if crate::run::is_current_task(&self.run, waker) {
            wait.0 = None;
            return self.is_cancelled();
        }
        match &wait.0 {
            Some((region, key)) if Arc::ptr_eq(region, &self.region) => self.region.update_foreign(*key, waker),
            _ => {
                let key = self.region.add_foreign(waker);
                wait.0 = Some((self.region.clone(), key));
            }
        }
        // Checked after adding, so a cancel in between is not missed.
        self.is_cancelled()
    }
}

/// The error a wait returns when its [region](Cx#regions) is cancelled.
///
/// Every wait in Fictionet returns early with this when the region of the
/// `Cx` it was given is cancelled:
/// [`Cx::sleep`], [`Cx::sleep_until`], [`Cx::yield_now`], [`Task::join`],
/// [`Attachments::get`](crate::Attachments::get), and
/// [`recv`](crate::InterfaceExt::recv) (as
/// [`RecvError::Cancelled`](crate::RecvError::Cancelled)). Stdlib
/// connections end with
/// [`ConnError::Cancelled`](crate::stdlib::ConnError::Cancelled), and
/// [`Attachments::next`](crate::Attachments::next) returns `None`. A task
/// passes the error up with `?`, and so stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the region was cancelled")
    }
}

impl std::error::Error for Cancelled {}

impl From<Cancelled> for crate::RecvError {
    fn from(_: Cancelled) -> Self {
        crate::RecvError::Cancelled
    }
}

/// A handle to a background task started with [`Cx::spawn`].
///
/// Dropping it detaches the task: the task keeps running, because its
/// [region](Cx#regions) owns it, not the handle. A task stops when it
/// returns, or when its region is cancelled, together with the rest of the
/// region. Keep the handle to wait for the task with [`Task::join`].
pub struct Task {
    join: Arc<JoinState>,
}

impl Task {
    /// Waits for the task to end, and returns what it returned.
    ///
    /// If the task failed, the error returned here carries the same message,
    /// but the original error goes to the task's region, as [`Cx::spawn`]
    /// says. The copy is ready before the failure cancels the region, so a
    /// joiner in that same region still gets the message. If `cx`'s region
    /// is cancelled before the task ends, or the run is dropped, this
    /// returns [`Cancelled`] as the error.
    pub async fn join(self, cx: &Cx) -> crate::Result {
        let mut wait = CancelWait::default();
        poll_fn(|task| {
            let mut state = self.join.state.lock().unwrap();
            if let Some(result) = state.result.take() {
                return Poll::Ready(result);
            }
            if cx.is_cancelled() {
                return Poll::Ready(Err(Box::new(Cancelled)));
            }
            match &state.waker {
                Some(w) if w.will_wake(task.waker()) => {}
                _ => state.waker = Some(task.waker().clone()),
            }
            drop(state);
            if cx.register_cancel(task.waker(), &mut wait) {
                return Poll::Ready(Err(Box::new(Cancelled)));
            }
            Poll::Pending
        })
        .await
    }
}

/// What a [`Task`] returned, for [`Task::join`].
#[derive(Default)]
pub(crate) struct JoinState {
    state: Mutex<JoinInner>,
}

#[derive(Default)]
struct JoinInner {
    result: Option<crate::Result>,
    waker: Option<Waker>,
}

impl JoinState {
    pub(crate) fn finish(&self, result: crate::Result) {
        let waker = {
            let mut state = self.state.lock().unwrap();
            state.result = Some(result);
            state.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// One wait's place for its waker in a region, for waits polled outside the
/// run. See [`Cx::register_cancel`]. Dropping it takes the waker out.
#[derive(Default)]
pub(crate) struct CancelWait(Option<(Arc<Region>, u64)>);

impl Drop for CancelWait {
    fn drop(&mut self) {
        if let Some((region, key)) = self.0.take() {
            let removed = region.state.lock().unwrap().foreign.remove(&key);
            drop(removed);
        }
    }
}

/// The error [`Task::join`] returns when the work failed. The work's own
/// error goes to its region, and out of [`run`](crate::run), so the joiner
/// gets this copy of its message.
#[derive(Debug)]
pub(crate) struct TaskFailed(pub(crate) String);

impl std::fmt::Display for TaskFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TaskFailed {}

/// A region: a group of work that is cancelled together and ends together.
pub(crate) struct Region {
    run: Weak<RunShared>,
    cancelled: AtomicBool,
    /// Cancelled by [`Cx::cancel`]: errors from then on are not kept.
    stopped: AtomicBool,
    state: Mutex<RegionState>,
}

#[derive(Default)]
struct RegionState {
    children: Vec<Weak<Region>>,
    /// Wakers outside this run to wake on cancel, by [`CancelWait`] key.
    foreign: HashMap<u64, Waker>,
    next_key: u64,
    /// The first error of the region.
    error: Option<crate::Error>,
    /// Spawned work that has not ended yet.
    live: usize,
    /// Woken when `live` drops to zero.
    done: Option<Waker>,
}


impl Region {
    pub(crate) fn root(run: Weak<RunShared>) -> Arc<Region> {
        Arc::new(Region { run, cancelled: AtomicBool::new(false), stopped: AtomicBool::new(false), state: Mutex::default() })
    }

    fn child(self: &Arc<Self>) -> Arc<Region> {
        let child = Arc::new(Region {
            run: self.run.clone(),
            cancelled: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            state: Mutex::default(),
        });
        {
            let mut state = self.state.lock().unwrap();
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
            let mut state = self.state.lock().unwrap();
            (std::mem::take(&mut state.foreign), std::mem::take(&mut state.children))
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

    fn add_foreign(&self, waker: &Waker) -> u64 {
        let mut state = self.state.lock().unwrap();
        let key = state.next_key;
        state.next_key += 1;
        state.foreign.insert(key, waker.clone());
        key
    }

    fn update_foreign(&self, key: u64, waker: &Waker) {
        let mut state = self.state.lock().unwrap();
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

    pub(crate) fn task_started(&self) {
        self.state.lock().unwrap().live += 1;
    }

    /// Keeps `error` if it is the region's first and the region was not
    /// stopped with [`Cx::cancel`]. It cancels nothing: a failed task's
    /// error is kept with this before the task is dropped, and
    /// [`task_done`](Region::task_done) cancels after.
    pub(crate) fn record_error(&self, error: crate::Error) {
        let mut state = self.state.lock().unwrap();
        if state.error.is_none() && !self.stopped.load(Ordering::Acquire) {
            state.error = Some(error);
        }
    }

    /// Counts one task as ended. `failed` cancels the region: the task's
    /// error was already kept with [`record_error`](Region::record_error).
    pub(crate) fn task_done(&self, failed: bool) {
        let done = {
            let mut state = self.state.lock().unwrap();
            state.live -= 1;
            if state.live == 0 { state.done.take() } else { None }
        };
        if failed {
            self.cancel();
        }
        if let Some(w) = done {
            w.wake();
        }
    }

    fn poll_done(&self, task: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().unwrap();
        if state.live == 0 {
            Poll::Ready(())
        } else {
            state.done = Some(task.waker().clone());
            Poll::Pending
        }
    }

    pub(crate) fn take_error(&self) -> Option<crate::Error> {
        self.state.lock().unwrap().error.take()
    }
}

/// The future behind [`Cx::sleep_until`].
struct Sleep<'a> {
    cx: &'a Cx,
    /// `None` is a deadline too far away to represent: it never comes.
    deadline: Option<crate::sys::Instant>,
    timer: Option<u64>,
    wait: CancelWait,
}

impl Future for Sleep<'_> {
    type Output = Result<(), Cancelled>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.cx.is_cancelled() {
            return Poll::Ready(Err(Cancelled));
        }
        if let Some(deadline) = this.deadline {
            if crate::sys::Instant::now() >= deadline {
                return Poll::Ready(Ok(()));
            }
            match this.timer {
                None => this.timer = Some(timers().add(deadline, task.waker().clone())),
                Some(id) => timers().update(id, task.waker()),
            }
        }
        if this.cx.register_cancel(task.waker(), &mut this.wait) {
            return Poll::Ready(Err(Cancelled));
        }
        Poll::Pending
    }
}

impl Drop for Sleep<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.timer {
            timers().remove(id);
        }
    }
}

/// A sleep whose deadline can move, for a task that polls by hand and
/// whose next deadline changes often, such as a TCP endpoint's driver.
/// Moving the deadline reuses the same timer entry, where dropping one
/// [`Cx::sleep_until`] future and making another would add and remove an
/// entry, and allocate the boxed future, each time.
#[derive(Default)]
pub(crate) struct Timer {
    /// The wall-clock deadline of the timer entry, if there is one.
    deadline: Option<crate::sys::Instant>,
    entry: Option<u64>,
    wait: CancelWait,
}

impl Timer {
    /// Polls for `deadline` to pass: `Ready(Ok(()))` once it has. Until
    /// then, `task` is woken when it passes or when `cx`'s region is
    /// cancelled.
    pub(crate) fn poll_until(&mut self, cx: &Cx, task: &mut Context<'_>, deadline: Instant) -> Poll<Result<(), Cancelled>> {
        if cx.is_cancelled() {
            return Poll::Ready(Err(Cancelled));
        }
        // A deadline past what the clock can hold never comes.
        match cx.run.start.checked_add(deadline.since_start()) {
            Some(at) => {
                if crate::sys::Instant::now() >= at {
                    self.clear();
                    return Poll::Ready(Ok(()));
                }
                match self.entry {
                    Some(id) if self.deadline == Some(at) => timers().update(id, task.waker()),
                    Some(id) => timers().reset(id, at, task.waker()),
                    None => self.entry = Some(timers().add(at, task.waker().clone())),
                }
                self.deadline = Some(at);
            }
            None => self.clear(),
        }
        if cx.register_cancel(task.waker(), &mut self.wait) {
            return Poll::Ready(Err(Cancelled));
        }
        Poll::Pending
    }

    /// Stops waiting: the timer entry, if any, is removed.
    pub(crate) fn clear(&mut self) {
        if let Some(id) = self.entry.take() {
            timers().remove(id);
        }
        self.deadline = None;
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Eight random bytes from the operating system.
fn os_random_u64() -> u64 {
    // Fuzzing runs repeat: the numbers come from the input's seed.
    #[cfg(fuzzing)]
    if let Some(n) = crate::fuzzing::next_random() {
        return n;
    }
    let mut buf = [0u8; 8];
    if let Err(err) = crate::sys::random_bytes(&mut buf) {
        panic!("getrandom failed: {err}");
    }
    u64::from_ne_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::ms;
    use crate::{block_on, run};
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_timer_fires_at_its_latest_deadline() {
        /// Polls `timer` for `first`, then for `then` until it fires.
        /// Returns how long that took.
        async fn wait(cx: &Cx, timer: &mut Timer, first: Duration, then: Duration) -> Result<std::time::Duration, Cancelled> {
            let start = std::time::Instant::now();
            let base = cx.now();
            let mut moved = false;
            std::future::poll_fn(|task| {
                if !moved {
                    moved = true;
                    assert!(timer.poll_until(cx, task, base + first).is_pending());
                }
                timer.poll_until(cx, task, base + then)
            })
            .await?;
            Ok(start.elapsed())
        }
        block_on(run(|cx| async move {
            let mut timer = Timer::default();
            // Moved later: the old deadline does not end the wait.
            let waited = wait(&cx, &mut timer, ms(10), ms(120)).await?;
            assert!(waited >= std::time::Duration::from_millis(120), "{waited:?}");
            // Moved earlier: it fires at the new deadline, after it fired once
            // already under the same entry.
            let waited = wait(&cx, &mut timer, ms(400), ms(30)).await?;
            assert!(waited >= std::time::Duration::from_millis(30), "{waited:?}");
            assert!(waited < std::time::Duration::from_millis(400), "{waited:?}");
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn a_nested_region_waits_for_its_work_and_keeps_its_error() {
        let ended = Arc::new(AtomicUsize::new(0));
        let e = ended.clone();
        block_on(run(move |cx| async move {
            // Ok: waits for the region's work.
            let e1 = e.clone();
            cx.region(|cx| async move {
                cx.spawn(move |cx| async move {
                    cx.sleep(ms(20)).await?;
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
            let res = cx
                .region(|cx| async move {
                    cx.spawn(move |cx| async move {
                        let r = cx.sleep(std::time::Duration::from_secs(60)).await;
                        assert_eq!(r, Err(Cancelled));
                        e2.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    });
                    cx.spawn(|_cx| async { Err("conn failed".into()) });
                    Ok(())
                })
                .await;
            assert_eq!(res.unwrap_err().to_string(), "conn failed");
            assert!(!cx.is_cancelled());
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
            let out = block_on(run(|cx| async move {
                let started = Arc::new(AtomicUsize::new(0));
                let s = started.clone();
                let mut region = std::pin::pin!(cx.region(|cx| async move {
                    cx.spawn(move |cx| async move {
                        s.fetch_add(1, Ordering::SeqCst);
                        cx.sleep(std::time::Duration::from_secs(60)).await?;
                        Ok(())
                    });
                    cx.sleep(std::time::Duration::from_secs(60)).await?;
                    Ok(())
                }));
                // Poll the region until its task has started, then give up
                // on it, as a timeout would.
                poll_fn(|task| {
                    let _ = region.as_mut().poll(task);
                    if started.load(Ordering::SeqCst) == 1 { Poll::Ready(()) } else {
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                Ok(())
            }));
            let _ = tx.send(out.map_err(|e| e.to_string()));
        });
        // The run ends once the task has seen the cancel; its Cancelled
        // error stays inside the dropped region.
        let out = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("the dropped region's work kept running");
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
        let res = block_on(run(|cx| async move {
            use crate::Interface;
            let (inside, outside) = crate::pair();
            let watcher = Arc::new(Mutex::new(Some(outside)));
            let w = watcher.clone();
            let res = cx
                .region(move |cx| {
                    let wake = Waker::from(Arc::new(CancelOnWake(cx.clone())));
                    let mut outside = w.lock().unwrap();
                    let polled = outside.as_mut().unwrap().poll_recv(&cx, &mut Context::from_waker(&wake));
                    assert!(polled.is_pending());
                    poll_fn(move |_| {
                        let _held = &inside;
                        Poll::Ready(Err("failed holding a link".into()))
                    })
                })
                .await;
            drop(watcher);
            res
        }));
        assert_eq!(res.unwrap_err().to_string(), "failed holding a link");
    }

    #[test]
    fn cancelling_a_region_cancels_regions_inside_it() {
        let res = block_on(run(|cx| async move {
            cx.spawn(|cx| async move {
                let inner = cx.region(|cx| async move { cx.sleep(std::time::Duration::from_secs(60)).await.map_err(Into::into) }).await;
                assert!(inner.unwrap_err().is::<Cancelled>());
                Ok(())
            });
            cx.sleep(ms(10)).await?;
            Err("outer".into())
        }));
        assert_eq!(res.unwrap_err().to_string(), "outer");
    }
}
