use std::future::{Future, poll_fn};
use std::panic::Location;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Poll, Waker};

use crate::events::Event;
use crate::group::Group;
use crate::run::RunShared;
use crate::time::{Duration, Instant};

mod region;
mod task;
mod timer;

pub use region::CancelWait;
pub(crate) use region::Region;
pub(crate) use task::JoinState;
pub use task::{JoinError, Task};
pub use timer::Timer;

/// The context that world code runs in.
///
/// A `Cx` is how world code reads the time, waits, draws random numbers and
/// starts background tasks. Fictionet has no global clock and no global
/// executor, so all four go through a `Cx`. That is why every stdlib
/// function that waits or starts a task takes `&Cx` as its first argument, and why the core works under
/// any async runtime. [`run`](crate::run) gives the world function its
/// first `Cx`. In signatures and examples it is called `fcx`; `cx` is the
/// std task context, as in tokio and futures.
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
/// Once [`Cx::region`] returns, a retained `Cx` cannot start more tasks in
/// that region. Spawning returns a task whose join reports
/// [`JoinError::Cancelled`]. Cancellation alone does not close admission:
/// tasks in an active region can still spawn work to finish shutting down.
///
/// [`running`](crate::guide::running#what-ends-what) has a table of every way a
/// world and its tasks end.
///
#[doc = include_str!("../docs/diagrams/regions.svg")]
///
/// # Groups
///
/// A group names a set of tasks for the people watching a world, such as
/// "office LAN" or "simulated hosts". [`Cx::group`] returns a `Cx` whose
/// tasks belong to that group. Every task started with that `Cx`, and
/// every task those tasks start, belongs to the group too, and so do the
/// stdlib's own tasks, such as a [`router`](crate::stdlib::network::route::router)
/// or a [`tcp::endpoint`](crate::stdlib::network::tcp::endpoint). Groups nest: a
/// group made from a grouped `Cx` sits inside that group.
///
/// Groups change nothing about how the world runs. A grouped `Cx` stays in
/// the same [region](Cx#regions), with the same cancellation and error rules.
/// [`Cx::host`] also creates an explicit host entity with its own identity.
/// Observers can bind connections to the nearest enclosing host.
/// Both calls allocate group state even without topology interest; see their
/// method docs for costs. Core publishes topology changes. The
/// [companion crate](../fictionet_observe/index.html) collects them for display.
///
/// # Waiting
///
/// [`Cx::sleep`] and [`Cx::sleep_until`] wait on the run's clock.
/// [`Timer`] is an owned deadline wait for manual polling.
/// [`CancelWait`] and [`Cx::register_cancel`] register poll-time wakeups
/// for cancellation.
///
/// # Stopping
///
/// Stopping is cooperative. Cancelling a region does not drop its tasks.
/// Instead, [`Cx::cancelled`] finishes for every `Cx` in the region, and
/// waits such as `recv` and `sleep` return early with [`Cancelled`], or
/// with their error type's `Cancelled` variant, before held data or a due
/// deadline. Each task then ends on its own, usually by passing that error
/// up with `?`. A task that ends with a cancel has not failed, so its region
/// keeps no error for it.
///
/// Two waits give ready results precedence: [`Cx::race`] polls its work
/// before checking cancellation, and [`Task::join`] returns an already
/// stored task result before checking the joining `Cx`'s cancellation.
///
/// Only Fictionet's own waits see a cancel. A task waiting on something
/// else, such as a tokio socket or a database query, is not interrupted,
/// and keeps its region open until that wait ends. Such a task races the
/// wait against [`Cx::cancelled`], as
/// [`running`](crate::guide::running#cancellation-is-cooperative) shows.
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
    /// monotonic clock. Under [`lab`](crate::lab), it starts at zero and
    /// advances only when the executor has no runnable work.
    pub fn now(&self) -> Instant {
        self.run.environment.clock.now()
    }

    /// Returns the run's clock and real-I/O policy.
    pub fn mode(&self) -> crate::RunMode {
        self.run.environment.clock.mode()
    }

    /// Returns an error if this run is a lab and cannot use host I/O.
    pub fn require_real_io(&self) -> std::io::Result<()> {
        self.run.environment.require_real_io()
    }

    /// Waits until the run's clock reaches `deadline`.
    ///
    /// For an owned wait with a resettable deadline, use [`Timer`].
    ///
    /// Returns immediately if `deadline` has already passed. Returns early
    /// with [`Cancelled`] if this `Cx`'s [region](Cx#regions) is cancelled.
    pub async fn sleep_until(&self, deadline: Instant) -> Result<(), Cancelled> {
        let mut timer = Timer::new(self);
        poll_fn(|cx| timer.poll_until(cx, deadline)).await
    }

    /// Waits for `d` to pass.
    ///
    /// Returns early with [`Cancelled`] if this `Cx`'s [region](Cx#regions)
    /// is cancelled.
    pub async fn sleep(&self, d: Duration) -> Result<(), Cancelled> {
        let deadline = self
            .now()
            .since_start()
            .checked_add(d)
            .unwrap_or(Duration::MAX);
        self.sleep_until(Instant::from_since_start(deadline)).await
    }

    /// Fills `out` with random bytes from the run's stream.
    ///
    /// World code should draw all of its randomness from the [`Cx`], so
    /// that every random choice in a world goes through one place. The
    /// stream is ChaCha20, started from the run's [`Seed`](crate::Seed):
    /// a run with the same seed that makes the same calls in the same order
    /// gets the same bytes. [`random_u64`](Self::random_u64) and
    /// [`random_f64`](Self::random_f64) read the same stream.
    pub fn fill_random(&self, out: &mut [u8]) {
        crate::Entropy::fill_random(&self.run.environment.entropy, out);
    }

    /// A random 64-bit number: the next eight bytes of the run's stream
    /// ([`fill_random`](Self::fill_random)), read as little-endian.
    pub fn random_u64(&self) -> u64 {
        crate::Entropy::random_u64(self)
    }

    /// A random number from 0 up to, but not including, 1.
    ///
    /// Use it for choices such as "10% of the time":
    /// `fcx.random_f64() < 0.1`.
    pub fn random_f64(&self) -> f64 {
        crate::Entropy::random_f64(self)
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
        poll_fn(|cx| {
            if self.is_cancelled() {
                return Poll::Ready(Err(Cancelled));
            }
            if yielded {
                return Poll::Ready(Ok(()));
            }
            yielded = true;
            cx.waker().wake_by_ref();
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
    /// The task's recorded parent is the current task in this run, if any.
    /// Spawning from another run or outside a world task leaves no parent.
    ///
    /// If the region has completed, the returned task joins with
    /// [`JoinError::Cancelled`]. `work` is still called to construct the
    /// future, but that future is dropped without being polled. An active
    /// region still accepts tasks after cancellation; their waits see the
    /// cancel as usual.
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
        self.spawn_as(std::any::type_name::<Fut>, work)
    }

    /// [`Cx::spawn`], with the name observers see for the task. The
    /// stdlib names its tasks after the function that starts them, and a
    /// copy of a stdlib file can do the same.
    ///
    /// The `name` closure returns a borrowed static task name. It runs once
    /// if the region admits the task, even without an observer, before taking
    /// the scheduler's queue lock. It may call methods on this `Cx`, including
    /// [`Cx::cancel`].
    #[track_caller]
    pub fn spawn_as<F, Fut>(&self, name: impl FnOnce() -> &'static str, work: F) -> Task
    where
        F: FnOnce(Cx) -> Fut,
        Fut: Future<Output = crate::Result> + Send + 'static,
    {
        let location = Location::caller();
        let region = self.region.clone();
        let future = work(Cx {
            run: self.run.clone(),
            region: region.clone(),
            group: self.group.clone(),
        });
        let join = Arc::new(JoinState::default());
        if !region.try_start_task() {
            drop(future);
            join.finish(Err(JoinError::Cancelled));
            return Task { join };
        }
        let group = self.group.as_ref();
        if let Err(future) = self.run.spawn(
            Box::pin(future),
            region.clone(),
            join.clone(),
            name,
            location,
            group,
        ) {
            // The run is gone, so the work can never run.
            drop(future);
            region.task_done(false);
            join.finish(Err(JoinError::Cancelled));
        }
        Task { join }
    }

    /// Returns a `Cx` whose tasks belong to a [group](Cx#groups) called
    /// `name`, inside this `Cx`'s group if it has one.
    ///
    /// The returned `Cx` is in the same [region](Cx#regions) as this one, so
    /// only observers see the difference. Hand it to the code that builds
    /// one part of the world, and every task that code starts, directly or
    /// through the stdlib, belongs to the group:
    ///
    /// ```
    /// # use fictionet::{Cx, Interface, Result};
    /// # use fictionet::stdlib::network::{ip, tcp};
    /// fn office(fcx: &Cx, uplink: impl Interface) -> Result {
    ///     let lan = fcx.group("office LAN");
    ///     let (tcp, _udp, _icmp, _other) = ip::split_protocols(&lan, uplink);
    ///     let printer = tcp::endpoint(&lan, tcp, "10.1.0.20".parse()?);
    ///     let _ipp = printer.listen(631)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// A sandbox belongs to the group of the task that reads its
    /// [`Attachment`](crate::Attachment), such as a
    /// [`delay`](crate::stdlib::network::delay) started with a grouped `Cx`. Each
    /// call makes a distinct group, even when names match. It owns the name
    /// string, allocates one shared struct and assigns a run-scoped group id.
    /// This cost applies without an observer too. Group, host or connection
    /// topology interest adds a dispatch reference. Interested group creation
    /// and removal are published as topology, with bounded staging during polls.
    /// A grouped task holds two group references: one in its `Cx` and one in
    /// its runtime identity. A nested group also holds its parent.
    pub fn group(&self, name: impl Into<String>) -> Cx {
        self.make_group(name, false)
    }

    /// Makes a simulated host and its group inside this context's group.
    /// A host is its own topology entity, distinct from the group. It changes
    /// no scheduling, cancellation or packet behavior.
    ///
    /// Allocation and reference costs match [`Self::group`], even without
    /// topology interest. Group, host or connection interest also assigns a
    /// run-scoped host id, without another host allocation. Interested host
    /// creation and removal are published separately from group changes.
    /// The host and group live until the last group reference drops.
    pub fn host(&self, name: impl Into<String>) -> Cx {
        self.make_group(name, true)
    }

    /// Tells interested observers that a service in this context accepted
    /// `conn`, binding it to the serving task and the nearest
    /// [host](Cx::host). A custom service calls this when it accepts a
    /// connection, and [`Cx::connection_closed`] when it closes. This publishes
    /// topology; it changes nothing about the connection or world execution.
    /// Without connection topology interest it does nothing. With interest,
    /// it looks up the current task and nearest host and publishes the binding.
    /// During a task poll, bounded staging owns a copy of the connection data.
    pub fn connection_opened(&self, conn: &crate::events::ConnInfo) {
        use crate::events::{TaskId, TopologyKind, TopologyRef};
        if self.run.observer.topology_enabled(TopologyKind::Connection) {
            let host = std::iter::successors(self.group.as_ref(), |group| group.parent.as_ref())
                .find_map(|group| group.host);
            self.run.observer.topology(TopologyRef::ConnectionOpened {
                conn,
                task: crate::run::RunTask::current_in(self.run.id).map(|task| TaskId(task.id)),
                host,
            });
        }
    }

    /// Tells interested observers that `conn`, opened with
    /// [`Cx::connection_opened`], has closed. This publishes a topology removal;
    /// it does not close the connection itself. Without connection topology
    /// interest it does nothing. During a task poll, bounded staging owns a
    /// copy of the connection data.
    pub fn connection_closed(&self, conn: &crate::events::ConnInfo) {
        use crate::events::{TopologyKind, TopologyRef};
        if self.run.observer.topology_enabled(TopologyKind::Connection) {
            self.run
                .observer
                .topology(TopologyRef::ConnectionClosed { conn });
        }
    }

    fn make_group(&self, name: impl Into<String>, host: bool) -> Cx {
        let observer = &self.run.observer;
        let group = Group::new(
            self.run
                .next_group
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            name.into(),
            self.group.clone(),
            (observer.topology_enabled(crate::events::TopologyKind::Group)
                || observer.topology_enabled(crate::events::TopologyKind::Host)
                || observer.topology_enabled(crate::events::TopologyKind::Connection))
            .then(|| observer.shared().unwrap().clone()),
            host,
        );
        Cx {
            run: self.run.clone(),
            region: self.region.clone(),
            group: Some(group),
        }
    }

    /// A connection's TLS key adapter for interested observers.
    /// The typed stream stops when the run ends. The adapter does not retain the run.
    #[doc(hidden)]
    pub fn tls_key_log(
        &self,
        connection: Option<&crate::events::ConnInfo>,
    ) -> Option<Arc<dyn rustls::KeyLog>> {
        crate::tls_keys::KeyLog::for_cx(self, connection)
    }

    /// Checks interest before constructing event-specific tracking state.
    pub fn event_enabled(&self, source: &'static str, kind: &'static str) -> bool {
        self.run.observer.enabled(crate::events::Interest::Event(
            crate::events::Metadata { source, kind },
            &crate::events::ConnInfo::default(),
        ))
    }

    /// Builds and emits an event only when a destination is interested.
    /// With no observer this does not invoke `build`, read time, or number a record.
    pub fn emit(
        &self,
        source: &'static str,
        kind: &'static str,
        build: impl FnOnce(Event) -> Event,
    ) {
        if self.event_enabled(source, kind) {
            self.emit_observation(build(Event::new(source, kind)));
        }
    }

    /// Borrows an emitter carrying explicit connection context.
    pub fn emitter<'a>(
        &'a self,
        connection: &'a crate::events::ConnInfo,
    ) -> crate::events::Emitter<'a> {
        crate::events::Emitter {
            cx: self,
            connection,
        }
    }

    /// Reports facts omitted by a bounded producer before event delivery.
    /// Installed observers retain this loss status for completeness checks.
    pub fn events_lost(&self, count: u64) {
        self.run.observer.report_loss(crate::events::Loss {
            stream: crate::events::Stream::Events,
            reason: crate::events::LossReason::Staging,
            count,
            bytes: None,
            seqs: None,
        });
    }

    pub(crate) fn emit_observation(&self, mut event: Event) {
        event.origin = crate::run::current_origin(self.run.id);
        self.run.observer.emit(event, || self.now());
    }

    /// Waits until every task in this run is waiting, before a lab's clock
    /// jumps to its next deadline. Work spawned or woken by other tasks is
    /// drained first. This does not wait for future timers or host I/O.
    ///
    /// Useful for inspecting a closed world's state after it has processed
    /// its current input. The instant stays unchanged in a lab. Returns
    /// [`Cancelled`] if this context's region is cancelled.
    ///
    /// ```
    /// # fictionet::block_on(fictionet::lab(fictionet::RunOptions::new(fictionet::Seed::from_u64(1)), |cx| async move {
    /// let start = cx.now();
    /// cx.idle().await?;
    /// assert_eq!(cx.now(), start);
    /// # Ok(()) }))?;
    /// # Ok::<(), fictionet::Error>(())
    /// ```
    pub async fn idle(&self) -> Result<(), Cancelled> {
        if self.is_cancelled() {
            return Err(Cancelled);
        }
        self.race(None, self.run.idle())
            .await
            .map_err(|_| Cancelled)?;
        if self.is_cancelled() {
            Err(Cancelled)
        } else {
            Ok(())
        }
    }

    /// Waits until this `Cx`'s [region](Cx#regions) is cancelled.
    ///
    /// Returns immediately if it already is.
    pub async fn cancelled(&self) {
        let mut wait = CancelWait::default();
        poll_fn(|cx| {
            if self.is_cancelled() || self.register_cancel(cx.waker(), &mut wait) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Runs `fut` until it finishes, `deadline` passes, or this `Cx`'s
    /// [region](Cx#regions) is cancelled. `None` waits with no deadline.
    ///
    /// Each poll tries `fut` first: a ready output wins even if the region
    /// is already cancelled or the deadline is due. If `fut` is pending,
    /// cancellation wins over the deadline. This is an exception to the
    /// cancellation-first behavior of waits such as [`Cx::sleep`].
    ///
    /// To race more than one thing, join them into `fut` with
    /// [`std::future::poll_fn`]: the first one ready gives the output.
    ///
    /// ```
    /// # #[cfg(feature = "std")]
    /// # {
    /// # fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::random()), |fcx| async move {
    /// use fictionet::RaceError;
    /// let late = fcx.race(Some(fcx.now() + std::time::Duration::from_millis(5)), std::future::pending::<()>()).await;
    /// assert_eq!(late, Err(RaceError::Deadline));
    /// assert_eq!(fcx.race(None, async { 7 }).await, Ok(7));
    /// # Ok(()) }))?;
    /// # }
    /// # Ok::<(), fictionet::Error>(())
    /// ```
    pub async fn race<T>(
        &self,
        deadline: Option<Instant>,
        fut: impl Future<Output = T>,
    ) -> Result<T, RaceError> {
        let mut fut = std::pin::pin!(fut);
        let mut sleep = std::pin::pin!(deadline.map(|d| self.sleep_until(d)));
        let mut cancelled = std::pin::pin!(self.cancelled());
        poll_fn(|cx| {
            if let Poll::Ready(v) = fut.as_mut().poll(cx) {
                return Poll::Ready(Ok(v));
            }
            if cancelled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(RaceError::Cancelled));
            }
            if let Some(sleep) = sleep.as_mut().as_pin_mut() {
                match sleep.poll(cx) {
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
    /// thread or a tokio task. [In a test](crate::guide::running#in-a-test) shows
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
    /// Before returning, the new region closes admission. A retained `Cx`
    /// cannot reopen it with [`Cx::spawn`]. Completion does not itself
    /// cancel the region.
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
        let mut work = Box::pin(f(Cx {
            run: self.run.clone(),
            region: child.clone(),
            group: self.group.clone(),
        }));
        let result = work.as_mut().await;
        if let Err(e) = result {
            if is_cancel(&*e) {
                child.ended_by_cancel();
            } else {
                child.fail(e);
            }
        }
        drop(work);
        poll_fn(|cx| child.poll_done(cx)).await;
        guard.0 = None;
        match child.take_error() {
            Some(e) => Err(e),
            None if child.cut_short() => Err(Cancelled.into()),
            None => Ok(()),
        }
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
    /// Create the token with [`CancelWait::default`]. Call this method on
    /// each poll to update its waker. Registering it with another region,
    /// or from a task of this run, removes its previous registration.
    pub fn register_cancel(&self, waker: &Waker, wait: &mut CancelWait) -> bool {
        if crate::run::is_current_task(&self.run, waker) {
            wait.clear();
            return self.is_cancelled();
        }
        match &wait.0 {
            Some((region, key)) if Arc::ptr_eq(region, &self.region) => {
                self.region.update_foreign(*key, waker)
            }
            _ => {
                wait.clear();
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
///   [`Ports::next`](crate::stdlib::network::ports::Ports::next).
/// - Waits with an error type of their own return its `Cancelled` variant,
///   which `?` makes from this value and whose
///   [`source`](std::error::Error::source) is this value:
///   [`RecvError::Cancelled`](crate::RecvError::Cancelled),
///   [`ConnError::Cancelled`](crate::stdlib::network::ConnError::Cancelled),
///   [`RaceError::Cancelled`], [`JoinError::Cancelled`],
///   [`HandshakeError::Cancelled`](crate::stdlib::services::tls::HandshakeError::Cancelled)
///   and [`ServeError::Cancelled`](crate::stdlib::services::serve::ServeError::Cancelled).
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
            RaceError::Cancelled => "the race stopped",
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

impl crate::Entropy for Cx {
    fn fill_random(&self, out: &mut [u8]) {
        Cx::fill_random(self, out);
    }
}
