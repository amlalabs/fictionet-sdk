use std::borrow::Cow;
use std::future::{Future, poll_fn};
use std::panic::Location;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use crate::events::{Event, EventLog};
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
///   A [`Cancelled`] is not such an error: it says a wait was cancelled.
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
/// with [`Cancelled`], or with its error type's `Cancelled` variant, before
/// anything the wait already holds. Each task then ends on its own, usually
/// by passing that error up with `?`. A task that ends with a cancel has
/// not failed, so its region keeps no error for it.
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
    ///
    /// A cancel is not a failure. Work that returns [`Cancelled`], or an
    /// error whose `Cancelled` variant says a wait was cancelled, ended
    /// because its region, or the region of a `Cx` it waited on, was
    /// cancelled. Its region keeps nothing and is not cancelled by it.
    ///
    /// A panic is not caught: it unwinds out of the run, which ends there.
    #[track_caller]
    pub fn spawn<F, Fut>(&self, work: F) -> Task
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = crate::Result> + Send + 'static,
    {
        self.spawn_as(crate::watch::task_name::<Fut>, work)
    }

    /// [`Cx::spawn`], with the name observers see for the task. The
    /// stdlib names its tasks after the function that starts them, and a
    /// copy of a stdlib file can do the same.
    #[track_caller]
    pub fn spawn_as<F, Fut>(&self, name: impl FnOnce() -> Cow<'static, str>, work: F) -> Task
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
            join.finish(Err(JoinError::Cancelled));
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

    /// Whether an observer, such as the dashboard or `fictionet observe
    /// watch`, is connected to this world right now.
    ///
    /// Events are recorded either way ([`Cx::record`]). Only packet copies
    /// and TLS session keys wait for an observer. It reads one number, so
    /// it is cheap to call on every packet.
    pub fn observed(&self) -> bool {
        self.run.graph.observed()
    }

    /// Sets application decoders for newly watched links in this world.
    /// Existing watches keep their registry and connection state. Call this
    /// before clients start observing to include custom protocols in the
    /// dashboard, JSON replies, and captured packet details.
    pub fn observe_protocols(&self, registry: crate::observe::Registry) {
        *self.run.graph.protocols.lock().unwrap_or_else(|e| e.into_inner()) = registry;
    }

    /// Records `event` in the run's [event log](crate::events), dated now
    /// on the run's clock, with the task that records it. Every run keeps
    /// its events, whether or not anyone reads them.
    ///
    /// ```
    /// # fn handled(cx: &fictionet::Cx) {
    /// use fictionet::events::Event;
    /// cx.record(Event::new("shop", "order").summary("an order for 3 pumps").field("count", 3u32));
    /// # }
    /// ```
    pub fn record(&self, event: Event) {
        self.record_at(self.now(), event);
    }

    /// Records `event` as having happened at `at`, which may be earlier
    /// than now.
    pub fn record_at(&self, at: Instant, mut event: Event) {
        let graph = &self.run.graph;
        event.at = at;
        event.origin = graph.origin(crate::watch::current_task());
        graph.events.push(event);
    }

    /// Records `event` as a repeat: one of a run of alike events that a
    /// flood can make, such as a packet the network refused or dropped.
    /// `detail` holds the facts that change with each repeat, such as a
    /// port or a length. The log records the first of a run, then counts
    /// the rest, and keeps repeats within bounds of their own, so they
    /// never push out other events. See
    /// [Repeats](crate::events#repeats).
    pub fn record_repeat(&self, mut event: Event, detail: crate::events::Fields) {
        let graph = &self.run.graph;
        event.at = self.now();
        event.origin = graph.origin(crate::watch::current_task());
        graph.events.push_repeat(event, detail);
    }

    /// The run's [event log](crate::events): what it holds, and readers
    /// for what comes. The handle stays readable after the run is over.
    pub fn events(&self) -> EventLog {
        EventLog::new(self.run.graph.events.clone())
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

    /// Runs `fut` until it finishes, `deadline` passes, or this `Cx`'s
    /// [region](Cx#regions) is cancelled, whichever comes first. `None`
    /// waits with no deadline.
    ///
    /// To race more than one thing, join them into `fut` with
    /// [`std::future::poll_fn`]: the first one ready gives the output.
    ///
    /// ```
    /// # fictionet::block_on(fictionet::run(|cx| async move {
    /// use fictionet::RaceError;
    /// let late = cx.race(Some(cx.now() + std::time::Duration::from_millis(5)), std::future::pending::<()>()).await;
    /// assert_eq!(late, Err(RaceError::Deadline));
    /// assert_eq!(cx.race(None, async { 7 }).await, Ok(7));
    /// # Ok(()) }))?;
    /// # Ok::<(), fictionet::Error>(())
    /// ```
    pub async fn race<T>(&self, deadline: Option<Instant>, fut: impl Future<Output = T>) -> Result<T, RaceError> {
        let mut fut = std::pin::pin!(fut);
        let mut sleep = std::pin::pin!(deadline.map(|d| self.sleep_until(d)));
        let mut cancelled = std::pin::pin!(self.cancelled());
        poll_fn(|task| {
            if let Poll::Ready(v) = fut.as_mut().poll(task) {
                return Poll::Ready(Ok(v));
            }
            if cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(RaceError::Cancelled));
            }
            if let Some(sleep) = sleep.as_mut().as_pin_mut() {
                match sleep.poll(task) {
                    Poll::Ready(Ok(())) => return Poll::Ready(Err(RaceError::Deadline)),
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(RaceError::Cancelled)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
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
    /// reports success: errors that its tasks return after this call are
    /// not kept, and the [`Cancelled`] that a task passes up with `?` is
    /// never a failure. An error from before the call is still reported.
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
    /// this region is. For work that is allowed to fail as a whole, such as
    /// serving one connection with its HTTP/2 streams. Once all of the new
    /// region's work has ended, this returns, as [`run`](crate::run) does:
    ///
    /// - `Ok(())` when every task, and `f`, returned `Ok`, or when the new
    ///   region was stopped with [`Cx::cancel`].
    /// - `Err` with the first failure when `f` or any of its work returned
    ///   an error that is not a cancel. The new region is cancelled by it;
    ///   this region is not failed by it: the caller decides.
    /// - `Err` with [`Cancelled`] when the new region was cancelled from
    ///   outside, because this region was, and some of its work ended with
    ///   the cancel instead of finishing.
    ///
    /// Dropping the returned future before it finishes cancels the new
    /// region. Its work then ends on its own, as after any cancel, but
    /// nothing waits for it and its errors are lost.
    pub async fn region<F, Fut>(&self, f: F) -> crate::Result
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
            if is_cancel(&*e) {
                child.ended_by_cancel();
            } else {
                child.fail(e);
            }
        }
        drop(work);
        poll_fn(|task| child.poll_done(task)).await;
        guard.0 = None;
        match child.take_error() {
            Some(e) => Err(e),
            None if child.cut_short() => Err(Cancelled.into()),
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

/// The one value that means "the [region](Cx#regions) was cancelled".
///
/// Every Fictionet function that waits takes a `&Cx` and returns a
/// `Result`. When the region of that `Cx` is cancelled, the wait returns
/// early, and its error says so in one of two ways:
///
/// - Waits that cannot fail any other way return this value:
///   [`Cx::sleep`], [`Cx::sleep_until`], [`Cx::yield_now`],
///   [`Attachments::get`](crate::Attachments::get),
///   [`Attachments::next`](crate::Attachments::next) and
///   [`Ports::next`](crate::stdlib::Ports::next).
/// - Waits with an error type of their own return its `Cancelled` variant,
///   which `?` makes from this value and whose
///   [`source`](std::error::Error::source) is this value:
///   [`RecvError::Cancelled`](crate::RecvError::Cancelled),
///   [`ConnError::Cancelled`](crate::stdlib::ConnError::Cancelled),
///   [`RaceError::Cancelled`], [`JoinError::Cancelled`],
///   [`HandshakeError::Cancelled`](crate::stdlib::tls::HandshakeError::Cancelled)
///   and [`ServeError::Cancelled`](crate::stdlib::serve::ServeError::Cancelled).
///
/// A cancel is never reported as `None`, as `Ok`, or as another error such
/// as a broken connection. A task passes the error up with `?`, and so
/// stops. A task that ends with a cancel has not failed: its region does
/// not keep the error and is not cancelled by it (see [`Cx::spawn`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancelled;

/// Whether `e` reports a cancel: it is [`Cancelled`], or `Cancelled` is in
/// its chain of [`source`](std::error::Error::source)s, as it is for every
/// error type's `Cancelled` variant.
pub(crate) fn is_cancel(e: &(dyn std::error::Error + 'static)) -> bool {
    std::iter::successors(Some(e), |e| e.source()).any(|e| e.is::<Cancelled>())
}

/// Why [`Cx::race`] ended without its future's output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaceError {
    /// The deadline passed first.
    Deadline,
    /// The region was cancelled first.
    Cancelled,
}

impl std::fmt::Display for RaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RaceError::Deadline => "the deadline passed",
            RaceError::Cancelled => "the region was cancelled",
        })
    }
}

impl std::error::Error for RaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RaceError::Deadline => None,
            RaceError::Cancelled => Some(&Cancelled),
        }
    }
}

impl From<Cancelled> for RaceError {
    fn from(_: Cancelled) -> Self {
        RaceError::Cancelled
    }
}

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

/// Why [`Task::join`] has no `Ok` for its task.
#[derive(Clone, Debug)]
pub enum JoinError {
    /// The task returned this error. It is the same error its region
    /// keeps, shared, not a copy: downcast it to the task's own type.
    Failed(crate::Error),
    /// The task did not finish: it ended with a cancel, or the region of
    /// the `Cx` passed to `join` was cancelled first, or the run was
    /// dropped.
    Cancelled,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::Failed(e) => write!(f, "the task failed: {e}"),
            JoinError::Cancelled => f.write_str("the region was cancelled"),
        }
    }
}

impl std::error::Error for JoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            JoinError::Failed(e) => Some(&**e),
            JoinError::Cancelled => Some(&Cancelled),
        }
    }
}

impl From<Cancelled> for JoinError {
    fn from(_: Cancelled) -> Self {
        JoinError::Cancelled
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
    /// Waits for the task to end. `Ok(())` if it returned `Ok`.
    ///
    /// If the task failed, this returns [`JoinError::Failed`] with the
    /// task's own error, the same one its region keeps, as [`Cx::spawn`]
    /// says. It is ready before the failure cancels the region, so a joiner
    /// in that same region still gets it. If the task ended with a cancel,
    /// or `cx`'s region is cancelled before the task ends, or the run is
    /// dropped, this returns [`JoinError::Cancelled`].
    pub async fn join(self, cx: &Cx) -> Result<(), JoinError> {
        let mut wait = CancelWait::default();
        poll_fn(|task| {
            let mut state = self.join.state.lock().unwrap();
            if let Some(result) = state.result.take() {
                return Poll::Ready(result);
            }
            if cx.is_cancelled() {
                return Poll::Ready(Err(JoinError::Cancelled));
            }
            match &state.waker {
                Some(w) if w.will_wake(task.waker()) => {}
                _ => state.waker = Some(task.waker().clone()),
            }
            drop(state);
            if cx.register_cancel(task.waker(), &mut wait) {
                return Poll::Ready(Err(JoinError::Cancelled));
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
    result: Option<Result<(), JoinError>>,
    waker: Option<Waker>,
}

impl JoinState {
    pub(crate) fn finish(&self, result: Result<(), JoinError>) {
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
    /// Some of its work ended with a cancel instead of finishing.
    cancel_ended: bool,
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

    /// Notes that work in the region ended with a cancel. It is not a
    /// failure: nothing is kept and nothing is cancelled.
    pub(crate) fn ended_by_cancel(&self) {
        self.state.lock().unwrap().cancel_ended = true;
    }

    /// Whether the region was cancelled from outside, not stopped with
    /// [`Cx::cancel`], and some of its work ended with the cancel.
    fn cut_short(&self) -> bool {
        self.is_cancelled() && !self.stopped.load(Ordering::Acquire) && self.state.lock().unwrap().cancel_ended
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
                    cx.spawn(|_cx| async { Err(crate::Error::msg("conn failed")) });
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
        let res = block_on(run(|cx| async move {
            let mut stopped = None;
            cx.region(|inner| {
                stopped = Some(inner.clone());
                inner.cancel();
                async { Ok(()) }
            })
            .await?;
            let stopped = stopped.unwrap();
            let task = cx.spawn(move |_cx| async move {
                // A wrapper's `Cancelled` variant counts too.
                let (mut a, _b) = crate::pair();
                use crate::InterfaceExt;
                a.recv(&stopped).await?;
                Ok(())
            });
            assert!(matches!(task.join(&cx).await, Err(JoinError::Cancelled)));
            assert!(!cx.is_cancelled());
            Ok(())
        }));
        assert!(res.is_ok(), "{res:?}");
    }

    /// `region` returns `Ok` when stopped with `Cx::cancel`, and
    /// `Cancelled` when cut short from outside, whatever error type its
    /// work used to say so.
    #[test]
    fn a_region_says_whether_it_was_stopped_or_cut_short() {
        let res = block_on(run(|cx| async move {
            let stopped = cx
                .region(|inner| async move {
                    inner.cancel();
                    inner.sleep(std::time::Duration::from_secs(60)).await?;
                    Ok(())
                })
                .await;
            assert!(stopped.is_ok(), "{stopped:?}");
            let outer = cx.clone();
            let cut = cx
                .region(|inner| async move {
                    let (mut a, _b) = crate::pair();
                    use crate::InterfaceExt;
                    outer.spawn(move |cx| async move {
                        cx.sleep(ms(10)).await?;
                        cx.cancel();
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
        let res = block_on(run(|cx| async move {
            cx.spawn(|cx| async move {
                let inner = cx.region(|cx| async move { cx.sleep(std::time::Duration::from_secs(60)).await.map_err(Into::into) }).await;
                assert!(inner.unwrap_err().is::<Cancelled>());
                Ok(())
            });
            cx.sleep(ms(10)).await?;
            Err(crate::Error::msg("outer"))
        }));
        assert_eq!(res.unwrap_err().to_string(), "outer");
    }
}
