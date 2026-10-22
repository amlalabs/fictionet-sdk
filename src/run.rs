use fictionet::sync::Mutex;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::panic::Location;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Wake, Waker};

use crate::JoinError;
use crate::cx::{JoinState, Region, is_cancel};
use crate::sys::SystemTime;
use crate::{Cx, Result};

/// Run ids, unique in the process. They are only compared for equality,
/// never recorded, serialized, ordered or hashed into anything a world
/// sees, so they do not affect determinism.
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

/// Configuration installed before a run starts.
///
/// Options select the seed and one optional observer, shared by every region.
/// It receives events, packets, TLS keys and topology according to its interest.
/// Use [`Fanout`](crate::events::Fanout) to combine consumers.
/// Core keeps no history; consumers own storage.
pub struct RunOptions {
    seed: crate::Seed,
    observer: Option<Arc<dyn crate::events::Observer>>,
    fields: crate::events::Fields,
}

impl RunOptions {
    /// Uses this seed with no observer.
    pub fn new(seed: crate::Seed) -> Self {
        Self {
            seed,
            observer: None,
            fields: crate::events::Fields::new(),
        }
    }

    /// Installs the run's destination for events, packets, TLS keys and topology.
    /// Replaces any destination set on these options. Use
    /// [`Fanout`](crate::events::Fanout) to combine observers before the run.
    pub fn observer(mut self, observer: Arc<dyn crate::events::Observer>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Adds caller-owned metadata to the automatic `run.start` event.
    pub fn fields(mut self, fields: crate::events::Fields) -> Self {
        self.fields = fields;
        self
    }
}

/// Runs a world in real time, as one future that any executor can poll.
///
/// `world` is called with the [`Cx`] of a new [region](Cx#regions), and
/// becomes the first task in it. Every task the world starts with
/// [`Cx::spawn`] is polled inside this same future, so `run` needs no
/// executor of its own. Without tokio, poll it with
/// [`block_on`](crate::block_on).
///
/// Time is the wall clock. That is what a run with a real sandbox needs,
/// because the sandbox's kernel and programs time out on real time. Real
/// sockets, Redis and the internet all work, and their times agree with
/// [`Cx::now`]. Libraries built on tokio need a tokio runtime to poll the
/// world, not [`block_on`](crate::block_on). Because the clock is real,
/// timings vary a little from run to run. [`lab`] runs the same world on
/// simulated time instead.
///
/// Randomness comes from `seed`: every random number the world draws
/// through its [`Cx`] is the next part of one stream started from it. Use
/// [`Seed::random`](crate::Seed::random) for a fresh seed, or
/// [`Seed::from_u64`](crate::Seed::from_u64) for a fixed one.
/// The run emits `run.start` automatically to interested observers, once at
/// zero, with the seed and clock origin. Install the observer through
/// [`RunOptions`]. It can consume events, packets, TLS keys and topology.
/// [`events`](crate::events#interest-identity-and-order) says what observation
/// skips without one.
///
/// # When the future finishes
///
/// When `world` returns `Ok`, the tasks it started keep running, and the
/// future finishes once all of them have ended. A world that only wires its
/// network and returns `Ok(())` therefore runs until it is stopped from
/// outside.
///
/// When `world`, or any task in its region, returns an error, the region
/// is cancelled. The future returns the first error once all of the
/// region's tasks have ended. A task that ends with
/// [`Cancelled`](crate::Cancelled) has not failed (see
/// [`Cx::spawn`]). After
/// [`Cx::cancel`](crate::Cx::cancel), the future returns `Ok(())`, unless a
/// task failed before the cancel.
///
/// A panic in the world or in any of its tasks is not caught. It unwinds
/// out of the future, and the run ends there, as if it were dropped.
///
/// Dropping the future stops everything immediately: the world and all of
/// its tasks are dropped, without waiting for them. Its regions count as
/// cancelled from then on, so a wait outside the run on one of its `Cx`
/// clones, such as in a tokio task, returns
/// [`Cancelled`](crate::Cancelled). A harness that runs the world in its
/// own process can drop the future when a sample ends.
///
/// The future is `Send`, so it runs on any tokio runtime, and world code can
/// hand [`Interface`](crate::Interface)s to tokio tasks. All of the world's
/// own tasks are still polled inside this one future, on one thread.
///
/// # Taking turns
///
/// `run` polls the tasks that are ready in turns, round-robin, so every
/// task gets a turn. That only works if each task gives the thread back,
/// which it does whenever it waits. A task that always has more to do, such
/// as a loop on a busy [`Interface`](crate::Interface) whose `recv` is
/// always ready, calls [`Cx::yield_now`](crate::Cx::yield_now) now and
/// then. Every stdlib task yields after at most 64 packets or messages in a
/// row, as tokio's tasks do with their budget. Code that blocks the thread
/// stops every task in the run.
///
/// One run uses one core. To use more cores, start more runs: one per
/// sample.
///
/// This `main` connects to a database before the world starts, and hands
/// the pool to the world. It uses tokio, because the database client does:
///
/// ```no_run
/// # #[cfg(feature = "std")]
/// # mod sqlx {
/// #     pub struct PgPool;
/// #     impl PgPool {
/// #         pub async fn connect(_: &str) -> fictionet::Result<PgPool> { Ok(PgPool) }
/// #     }
/// # }
/// # #[cfg(feature = "std")]
/// #[tokio::main]
/// async fn main() -> fictionet::Result {
///     let db = sqlx::PgPool::connect("postgres://...").await?;
///     let (attacher, attachments) = fictionet::attachments();
///     let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
///     let _listening = fictionet::listen(socket, attacher)?;
///     fictionet::run(fictionet::RunOptions::new(fictionet::Seed::random()), |fcx| async move {
///         // Build the world with `fcx`, `attachments` and `db`.
/// #       let _ = (fcx, attachments, db);
///         Ok(())
///     }).await
/// }
/// # #[cfg(not(feature = "std"))]
/// # fn main() {}
/// ```
#[cfg(feature = "std")]
pub async fn run<F, Fut>(options: RunOptions, world: F) -> Result
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = Result> + Send + 'static,
{
    run_with(
        RunShared::with_options(options, crate::RunMode::Real),
        world,
    )
    .await
}

/// Runs a closed world on simulated time, for tests.
///
/// A lab runs the world on the same executor as [`run`], with randomness
/// from `seed` in the same way. Only the clock differs. It starts at zero,
/// and when every task is waiting it jumps to the earliest deadline, waking
/// timers due at the same instant in the order they were set. With a closed
/// world, the same seed and ordered inputs give the same observed events and
/// packets. This requires the world to use the run's clock, randomness and
/// task scheduling. [Repeatable runs](crate::guide::running#repeatable-runs)
/// lists the requirements and runtime boundaries.
///
/// Like [`run`], `lab` emits `run.start` automatically when an observer wants it.
/// Keep inputs, interests and limits fixed to repeat observations and stamps.
/// Each run has its own task identities. A lab started inside another
/// run's task has a world root with no parent in the outer run.
///
/// The test plays the sandboxes as tasks of the lab, through
/// [`attachments`](crate::attachments). A lab whose tasks all wait with no
/// deadline ends with an error that says so; a wait with no deadline at all
/// never moves the clock. Attachments fed by [`listen`](crate::listen) fail
/// the lab on their first `get`, `next` or `map`, before handing out an
/// attachment, and `get` and `next` return [`Cancelled`](crate::Cancelled).
/// `web::proxy` and `web::forward` refuse a lab too.
pub async fn lab<F, Fut>(options: RunOptions, world: F) -> Result
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = Result> + Send + 'static,
{
    run_with(RunShared::with_options(options, crate::RunMode::Lab), world).await
}

/// Runs the world using the shared runtime services.
pub(crate) async fn run_with<F, Fut>(shared: Arc<RunShared>, world: F) -> Result
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = Result> + Send + 'static,
{
    let root = Region::root(Arc::downgrade(&shared));
    let mut state = RunState {
        shared: shared.clone(),
        dispatch: shared.observer.shared().cloned(),
        root: root.clone(),
        slots: BTreeMap::new(),
        turn: VecDeque::new(),
        incoming: Vec::new(),
    };
    // Register the world before invoking its builder, which may itself emit
    // events or spawn tasks before returning a future.
    let id = {
        let mut queue = shared.queue.lock();
        let id = queue.next_id;
        queue.next_id += 1;
        id
    };
    let identity = TaskIdentity {
        origin: TaskOrigin {
            name: "world",
            location: Location::caller(),
            parent: 0,
        },
        group: None,
    };
    shared.task_added(id, &identity);
    let start = shared.start.lock().take();
    if let Some(mut event) = start {
        event.origin = Some(identity.origin.event(id));
        shared.observer.emit(event, || crate::time::Instant::ZERO);
    }
    let cx = Cx {
        run: shared.clone(),
        region: root.clone(),
        group: None,
    };
    let future = {
        let _guard =
            CurrentGuard::enter(shared.id, id, &identity, Waker::noop(), &mut state.dispatch);
        world(cx)
    };
    if root.try_start_task() {
        shared.queue.lock().incoming.push(NewTask {
            pending_announcement: false,
            identity,
            id,
            future: Box::pin(future),
            region: root,
            join: Arc::new(JoinState::default()),
        });
    } else {
        drop(future);
        shared.task_removed(id);
    }
    std::future::poll_fn(move |cx| state.poll(cx)).await
}

type BoxFuture = Pin<Box<dyn Future<Output = Result> + Send>>;

/// Shares dispatch only when a destination is installed.
pub(crate) struct RunObserver(Option<Arc<crate::events::Dispatch>>);

impl RunObserver {
    pub(crate) fn shared(&self) -> Option<&Arc<crate::events::Dispatch>> {
        self.0.as_ref()
    }
}

impl std::ops::Deref for RunObserver {
    type Target = crate::events::Dispatch;
    fn deref(&self) -> &Self::Target {
        static ABSENT: crate::events::Dispatch = crate::events::Dispatch::empty();
        self.0.as_deref().unwrap_or(&ABSENT)
    }
}

/// The part of a run that wakers and every [`Cx`] share.
pub(crate) struct RunShared {
    pub(crate) environment: Arc<crate::environment::RunEnvironment>,
    pub(crate) observer: RunObserver,
    pub(crate) next_group: AtomicU64,
    start: Mutex<Option<crate::events::Event>>,
    queue: Mutex<Queue>,
    pub(crate) id: u64,
}

#[derive(Default)]
struct Queue {
    /// Tasks to poll in the next turn, in order.
    ready: VecDeque<u64>,
    /// Tasks spawned since the last turn.
    incoming: Vec<NewTask>,
    /// The waker of whatever polls the run.
    outer: Option<Waker>,
    /// The run is being polled now, so it checks `ready` before it returns
    /// and wakes need not wake `outer`.
    polling: bool,
    /// A region was cancelled: poll every task once.
    wake_all: bool,
    /// The run was dropped.
    closed: bool,
    next_id: u64,
    idle: BTreeMap<u64, Waker>,
    next_idle: u64,
}

struct NewTask {
    identity: TaskIdentity,
    pending_announcement: bool,
    id: u64,
    future: BoxFuture,
    region: Arc<Region>,
    join: Arc<JoinState>,
}

impl RunShared {
    pub(crate) async fn idle(&self) {
        struct Wait<'a> {
            run: &'a RunShared,
            key: Option<u64>,
        }
        impl Drop for Wait<'_> {
            fn drop(&mut self) {
                if let Some(key) = self.key {
                    let removed = self.run.queue.lock().idle.remove(&key);
                    drop(removed);
                }
            }
        }
        let mut wait = Wait {
            run: self,
            key: None,
        };
        std::future::poll_fn(|cx| {
            let mut q = self.queue.lock();
            let (key, outer) = if let Some(key) = wait.key {
                if !q.idle.contains_key(&key) {
                    return Poll::Ready(());
                }
                (key, None)
            } else {
                let key = q.next_idle;
                q.next_idle += 1;
                wait.key = Some(key);
                (key, if q.polling { None } else { q.outer.clone() })
            };
            let old = q.idle.insert(key, cx.waker().clone());
            drop(q);
            drop(old);
            if let Some(outer) = outer {
                outer.wake();
            }
            Poll::Pending
        })
        .await
    }

    pub(crate) fn with_options(options: RunOptions, mode: crate::RunMode) -> Arc<Self> {
        let RunOptions {
            seed,
            observer,
            fields,
        } = options;
        let run_id = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let environment = Arc::new(crate::environment::RunEnvironment::new(seed, mode));
        let start_wall = if mode == crate::RunMode::Real {
            SystemTime::now()
        } else {
            crate::sys::UNIX_EPOCH
        };
        let observer = RunObserver(observer.map(|observer| {
            crate::events::Dispatch::for_run(Some(observer), run_id, &environment.clock)
        }));
        let start = observer
            .enabled(crate::events::Interest::Event(
                crate::events::Metadata {
                    source: "run",
                    kind: "start",
                },
                &crate::events::ConnInfo::default(),
            ))
            .then(|| {
                crate::events::Event::new("run", "start")
                    .summary("the run started")
                    .field(
                        "wall",
                        if mode == crate::RunMode::Lab {
                            crate::stdlib::protocols::json::Value::Null
                        } else {
                            start_wall
                                .duration_since(crate::sys::UNIX_EPOCH)
                                .map_or(crate::stdlib::protocols::json::Value::Null, |d| {
                                    crate::events::float(d.as_secs_f64())
                                })
                        },
                    )
                    .field("seed", seed.to_string())
                    .field("rng", "chacha20-v1")
                    .prepend_fields(fields)
            });
        Arc::new(Self {
            environment,
            observer,
            next_group: AtomicU64::new(1),
            start: Mutex::new(start),
            queue: Mutex::new(Queue {
                next_id: 1,
                ..Queue::default()
            }),
            id: run_id,
        })
    }

    fn task_added(&self, id: u64, identity: &TaskIdentity) {
        use crate::events::{GroupId, TaskId, TopologyRef};
        let origin = identity.origin;
        self.observer.topology(TopologyRef::TaskAdded {
            task: TaskId(id),
            parent: (origin.parent != 0).then_some(TaskId(origin.parent)),
            name: origin.name,
            file: origin.location.file(),
            line: origin.location.line(),
            group: identity.group.as_ref().map(|g| GroupId(g.id)),
        });
    }

    fn task_removed(&self, id: u64) {
        self.observer
            .topology(crate::events::TopologyRef::TaskRemoved {
                task: crate::events::TaskId(id),
            });
    }

    pub(crate) fn end(&self) {
        self.observer.end(|| self.environment.clock.now());
    }

    /// Adds a task. Gives the future back if the run is gone.
    pub(crate) fn spawn(
        &self,
        future: BoxFuture,
        region: Arc<Region>,
        join: Arc<JoinState>,
        name: impl FnOnce() -> &'static str,
        location: &'static Location<'static>,
        group: Option<&Arc<crate::group::Group>>,
    ) -> std::result::Result<(), BoxFuture> {
        let identity = TaskIdentity {
            origin: TaskOrigin {
                name: name(),
                location,
                parent: RunTask::current_in(self.id).map_or(0, |task| task.id),
            },
            group: group.cloned(),
        };
        let task_topology = self
            .observer
            .topology_enabled(crate::events::TopologyKind::Task);
        let announce = task_topology && identity.origin.parent != 0;
        let (id, announcement, outer) = {
            let mut q = self.queue.lock();
            if q.closed {
                return Err(future);
            }
            let id = q.next_id;
            q.next_id += 1;
            let task = NewTask {
                identity,
                pending_announcement: task_topology && !announce,
                id,
                future,
                region,
                join,
            };
            let announcement = announce.then(|| task.identity.clone());
            q.incoming.push(task);
            (
                id,
                announcement,
                if q.polling { None } else { q.outer.clone() },
            )
        };
        // A parent's poll stages its children's announcements before it
        // ends. Foreign spawns leave announcement to the run thread.
        if let Some(identity) = announcement {
            self.task_added(id, &identity);
        }
        if let Some(w) = outer {
            w.wake();
        }
        Ok(())
    }

    fn schedule(&self, id: u64) {
        let outer = {
            let mut q = self.queue.lock();
            if q.closed {
                return;
            }
            q.ready.push_back(id);
            if q.polling { None } else { q.outer.clone() }
        };
        if let Some(w) = outer {
            w.wake();
        }
    }

    /// Polls every task once more. Called when a region is cancelled, so
    /// that every wait sees it.
    pub(crate) fn wake_all(&self) {
        let outer = {
            let mut q = self.queue.lock();
            if q.closed {
                return;
            }
            q.wake_all = true;
            if q.polling { None } else { q.outer.clone() }
        };
        if let Some(w) = outer {
            w.wake();
        }
    }
}

/// The waker of one task: puts the task back in the queue.
struct TaskWaker {
    id: u64,
    /// The task is in `ready` already.
    queued: AtomicBool,
    run: Weak<RunShared>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref()
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel)
            && let Some(run) = self.run.upgrade()
        {
            run.schedule(self.id);
        }
    }
}

struct Slot {
    identity: TaskIdentity,
    pending_announcement: bool,
    future: BoxFuture,
    task_waker: Arc<TaskWaker>,
    waker: Waker,
    region: Arc<Region>,
    join: Arc<JoinState>,
}

/// A task number qualified by its run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunTask {
    pub(crate) run: u64,
    pub(crate) id: u64,
}

impl RunTask {
    pub(crate) fn current() -> Option<Self> {
        CURRENT.with(|current| current.get().map(|current| current.task))
    }

    /// The current task, only if it belongs to `run`.
    pub(crate) fn current_in(run: u64) -> Option<Self> {
        Self::current().filter(|t| t.run == run)
    }
}

/// Origin carried by a task from its queue entry through its last poll.
#[derive(Clone)]
struct TaskIdentity {
    origin: TaskOrigin,
    group: Option<Arc<crate::group::Group>>,
}

#[derive(Clone, Copy)]
struct TaskOrigin {
    name: &'static str,
    location: &'static Location<'static>,
    parent: u64,
}

impl TaskOrigin {
    fn event(self, task: u64) -> crate::events::Origin {
        crate::events::Origin {
            task,
            name: self.name.into(),
            file: self.location.file(),
            line: self.location.line(),
            parent: self.parent,
        }
    }
}

#[derive(Clone, Copy)]
struct CurrentTask {
    task: RunTask,
    origin: TaskOrigin,
    waker: *const (),
}

thread_local! {
    /// The run, task and waker being polled on this thread, if any.
    static DISPATCH: RefCell<Option<Arc<crate::events::Dispatch>>> = const { RefCell::new(None) };
    static CURRENT: Cell<Option<CurrentTask>> = const { Cell::new(None) };
}

/// Calls `f` with the dispatch of the run whose task this thread is
/// polling, if that run has an observer.
pub(crate) fn with_dispatch(f: impl FnOnce(Option<&Arc<crate::events::Dispatch>>)) {
    let Some(run) = RunTask::current().map(|task| task.run) else {
        return f(None);
    };
    DISPATCH.with(|dispatch| {
        f(dispatch
            .borrow()
            .as_ref()
            .filter(|dispatch| dispatch.run_id == run))
    });
}

/// The origin of the task this thread is polling in `run`.
pub(crate) fn current_origin(run: u64) -> Option<crate::events::Origin> {
    CURRENT.with(|current| {
        current
            .get()
            .filter(|current| current.task.run == run)
            .map(|current| current.origin.event(current.task.id))
    })
}

/// Whether `waker` is the waker of the task of `run` that is being polled
/// on this thread right now.
pub(crate) fn is_current_task(run: &Arc<RunShared>, waker: &Waker) -> bool {
    CURRENT.with(|c| {
        c.get()
            .is_some_and(|t| t.task.run == run.id && t.waker == waker.data())
    })
}

/// A run's dispatch, present only when the run has an observer.
type RunDispatch = Option<Arc<crate::events::Dispatch>>;

/// Restores [`CURRENT`] when a poll ends, even by a panic. Topology the
/// poll produces is delivered after it returns, outside any lock the task
/// held.
struct CurrentGuard<'a> {
    previous: Option<CurrentTask>,
    /// The run's dispatch, lent to [`DISPATCH`] for the poll. A run with no
    /// observer leaves the thread-local alone: [`with_dispatch`] only hands
    /// out a dispatch of the run being polled.
    dispatch: Option<(&'a mut RunDispatch, RunDispatch)>,
    _topology: Option<crate::events::staging::Scope>,
}

impl<'a> CurrentGuard<'a> {
    fn enter(
        run: u64,
        id: u64,
        identity: &TaskIdentity,
        waker: &Waker,
        dispatch: &'a mut Option<Arc<crate::events::Dispatch>>,
    ) -> Self {
        let current = CurrentTask {
            task: RunTask { run, id },
            origin: identity.origin,
            waker: waker.data(),
        };
        let topology = dispatch
            .as_ref()
            .map(|dispatch| crate::events::staging::Scope::new(Some(dispatch)));
        let dispatch = dispatch.is_some().then(|| {
            let previous = DISPATCH.with(|d| d.replace(dispatch.take()));
            (dispatch, previous)
        });
        Self {
            previous: CURRENT.with(|c| c.replace(Some(current))),
            dispatch,
            _topology: topology,
        }
    }
}

impl Drop for CurrentGuard<'_> {
    fn drop(&mut self) {
        CURRENT.with(|c| {
            c.replace(self.previous.take());
        });
        if let Some((dispatch, previous)) = &mut self.dispatch {
            **dispatch = DISPATCH.with(|d| d.replace(previous.take()));
        }
    }
}

/// The state of a run that only the future returned by [`run`] touches.
struct RunState {
    dispatch: Option<Arc<crate::events::Dispatch>>,
    shared: Arc<RunShared>,
    root: Arc<Region>,
    /// Live tasks in spawn order, including when their futures are dropped.
    slots: BTreeMap<u64, Slot>,
    /// The tasks being polled in this turn. Swapped with the queue's
    /// `ready` at the start of each turn, so neither allocates again once
    /// both have grown to what the run needs.
    turn: VecDeque<u64>,
    /// Tasks spawned since the last turn, swapped out of the queue the same
    /// way.
    incoming: Vec<NewTask>,
}

impl RunState {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result> {
        let mut turn = std::mem::take(&mut self.turn);
        debug_assert!(turn.is_empty());
        {
            let mut q = self.shared.queue.lock();
            match &q.outer {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => q.outer = Some(cx.waker().clone()),
            }
            q.polling = true;
            std::mem::swap(&mut q.incoming, &mut self.incoming);
            for new in self.incoming.drain(..) {
                let task_waker = Arc::new(TaskWaker {
                    id: new.id,
                    queued: AtomicBool::new(true),
                    run: Arc::downgrade(&self.shared),
                });
                let waker = Waker::from(task_waker.clone());
                self.slots.insert(
                    new.id,
                    Slot {
                        identity: new.identity,
                        pending_announcement: new.pending_announcement,
                        future: new.future,
                        task_waker,
                        waker,
                        region: new.region,
                        join: new.join,
                    },
                );
                q.ready.push_back(new.id);
            }
            if std::mem::take(&mut q.wake_all) {
                for &id in self.slots.keys() {
                    if !self.slots[&id]
                        .task_waker
                        .queued
                        .swap(true, Ordering::AcqRel)
                    {
                        q.ready.push_back(id);
                    }
                }
            }
            std::mem::swap(&mut q.ready, &mut turn);
        }

        while let Some(id) = turn.pop_front() {
            let Some(slot) = self.slots.get_mut(&id) else {
                continue;
            };
            if slot.pending_announcement {
                slot.pending_announcement = false;
                self.shared.task_added(id, &slot.identity);
            }
            slot.task_waker.queued.store(false, Ordering::Release);
            let result = {
                let _guard = CurrentGuard::enter(
                    self.shared.id,
                    id,
                    &slot.identity,
                    &slot.waker,
                    &mut self.dispatch,
                );
                slot.future
                    .as_mut()
                    .poll(&mut Context::from_waker(&slot.waker))
            };
            if let Poll::Ready(result) = result {
                let slot = self.slots.remove(&id).unwrap();
                let Slot {
                    identity,
                    future,
                    region,
                    join,
                    ..
                } = slot;
                // The order matters, because each step can wake code that
                // calls `Cx::cancel`, and a cancel discards later errors.
                // 1. The region takes the error before anything else runs.
                //    A cancel is not a failure: it is noted, not kept.
                let (joined, failed) = match result {
                    Ok(()) => (Ok(()), false),
                    Err(e) if is_cancel(&*e) => {
                        region.ended_by_cancel();
                        (Err(JoinError::Cancelled), false)
                    }
                    Err(e) => {
                        region.record_error(e.clone());
                        (Err(JoinError::Failed(e)), true)
                    }
                };
                // 2. Drop the work, so its interfaces close before a joiner
                //    or the region sees it as ended.
                drop(future);
                self.shared.task_removed(id);
                drop(identity);
                // 3. The joiner's result, before the failure cancels the
                //    region the joiner may be waiting in.
                join.finish(joined);
                // 4. The region counts the task as ended, and a failure
                //    cancels it.
                region.task_done(failed);
            }
        }

        // Keep the emptied queue for the next turn.
        self.turn = turn;
        let mut q = self.shared.queue.lock();
        q.polling = false;
        if self.slots.is_empty() && q.incoming.is_empty() {
            drop(q);
            return Poll::Ready(match self.root.take_error() {
                Some(e) => Err(e),
                None => Ok(()),
            });
        }
        let more = !q.ready.is_empty() || !q.incoming.is_empty() || q.wake_all;
        if !more && !q.idle.is_empty() {
            let idle = std::mem::take(&mut q.idle);
            drop(q);
            for waker in idle.into_values() {
                waker.wake();
            }
        } else if !more && self.shared.environment.clock.mode() == crate::RunMode::Lab {
            // Admission and the time jump share this boundary. A spawn or
            // wake cannot slip between checking the queue and advancing.
            let due = match self.shared.environment.clock.advance() {
                Ok(due) => due,
                Err(error) => return Poll::Ready(Err(error)),
            };
            drop(q);
            // Wakers may enqueue work or run arbitrary code: release both
            // queue and clock locks before invoking any of them.
            for waker in due {
                waker.wake();
            }
            cx.waker().wake_by_ref();
        } else if more {
            drop(q);
            // Give the executor its turn too, then come back.
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Drop for RunState {
    fn drop(&mut self) {
        let incoming = {
            let mut q = self.shared.queue.lock();
            q.closed = true;
            q.outer = None;
            std::mem::take(&mut q.incoming)
        };
        let joins: Vec<Arc<JoinState>> = incoming
            .iter()
            .map(|t| t.join.clone())
            .chain(self.slots.values().map(|s| s.join.clone()))
            .collect();
        for task in incoming {
            if task.pending_announcement {
                self.shared.task_added(task.id, &task.identity);
            }
            let NewTask {
                id,
                identity,
                future,
                region,
                join,
                ..
            } = task;
            drop((future, region, join));
            self.shared.task_removed(id);
            drop(identity);
        }
        // Task destructors run in ascending task ID order.
        for (id, slot) in std::mem::take(&mut self.slots) {
            if slot.pending_announcement {
                self.shared.task_added(id, &slot.identity);
            }
            let Slot {
                identity,
                future,
                task_waker,
                waker,
                region,
                join,
                ..
            } = slot;
            drop((future, task_waker, waker, region, join));
            self.shared.task_removed(id);
            drop(identity);
        }
        // Work spawned while the slots were dropped.
        let late = std::mem::take(&mut self.shared.queue.lock().incoming);
        drop(late);
        // Waits outside the run end too: joins of the dropped work, and
        // every wait on a `Cx` of the run, which reads `Cancelled`.
        for join in joins {
            join.finish(Err(JoinError::Cancelled));
        }
        self.root.cancel();
        self.shared.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Origins {
        events: Mutex<Vec<crate::events::Event>>,
        tasks: Mutex<Vec<(crate::events::Origin, Option<crate::events::GroupId>)>>,
    }

    impl crate::events::Observer for Origins {
        fn enabled(&self, interest: crate::events::Interest<'_>) -> bool {
            matches!(
                interest,
                crate::events::Interest::Event(_, _)
                    | crate::events::Interest::Topology(crate::events::TopologyKind::Task)
            )
        }

        fn observe(&self, _: crate::events::Stamp, item: crate::events::Observation<'_>) {
            use crate::events::{Observation, Origin, TaskId, TopologyRef};
            match item {
                Observation::Event(event) => self.events.lock().push(event.clone()),
                Observation::Topology(TopologyRef::TaskAdded {
                    task,
                    parent,
                    name,
                    file,
                    line,
                    group,
                }) => self.tasks.lock().push((
                    Origin {
                        task: task.get(),
                        parent: parent.map_or(0, TaskId::get),
                        name: name.to_owned().into(),
                        file,
                        line,
                    },
                    group,
                )),
                _ => {}
            }
        }
    }

    #[test]
    fn grouped_tasks_emit_their_own_origin_and_parent() {
        let observer = Arc::new(Origins::default());
        crate::block_on(crate::lab(
            RunOptions::new(crate::Seed::from_u64(7)).observer(observer.clone()),
            |cx| async move {
                let group = cx.group("workers");
                let parent = cx.clone();
                let child_line = line!() + 1;
                let child = group.spawn_as(
                    || "child",
                    move |cx| async move {
                        parent.emit("test", "child", |e| e.field("spawn_line", child_line));
                        cx.yield_now().await?;
                        cx.emit("test", "child", |e| e.field("spawn_line", child_line));
                        let grandchild_line = line!() + 1;
                        cx.spawn_as(
                            || "grandchild",
                            move |cx| async move {
                                cx.emit("test", "grandchild", |e| {
                                    e.field("spawn_line", grandchild_line)
                                });
                                Ok(())
                            },
                        )
                        .join(&cx)
                        .await?;
                        Ok(())
                    },
                );
                child.join(&cx).await?;
                cx.emit("test", "world", |e| e);
                Ok(())
            },
        ))
        .unwrap();
        let tasks = observer.tasks.lock();
        assert_eq!(tasks.len(), 3);
        for ((origin, group), (task, parent, name, expected_group)) in tasks.iter().zip([
            (1, 0, "world", None),
            (2, 1, "child", Some(crate::events::GroupId(1))),
            (3, 2, "grandchild", Some(crate::events::GroupId(1))),
        ]) {
            assert_eq!(
                (origin.task, origin.parent, origin.name.as_ref(), *group),
                (task, parent, name, expected_group)
            );
        }
        let events = observer.events.lock();
        assert_eq!(events.len(), 5);
        for event in events.iter() {
            let origin = event.origin.as_ref().unwrap();
            assert_eq!(
                origin,
                &tasks
                    .iter()
                    .find(|(task, _)| task.task == origin.task)
                    .unwrap()
                    .0
            );
            if let Some(line) = event.u64("spawn_line") {
                assert_eq!(u64::from(origin.line), line);
                assert_eq!(origin.file, file!());
            }
            let json = event.to_json();
            assert_eq!(
                json.get("node").unwrap().as_str(),
                Some(format!("t{}", origin.task).as_str())
            );
            assert_eq!(
                json.get("task").unwrap().as_str(),
                Some(origin.name.as_ref())
            );
            assert_eq!(json.get("file").unwrap().as_str(), Some(origin.file));
            assert_eq!(json.get("line"), Some(&origin.line.into()));
            assert_eq!(
                json.get("parent"),
                Some(&if origin.parent == 0 {
                    crate::stdlib::protocols::json::Value::Null
                } else {
                    format!("t{}", origin.parent).into()
                })
            );
        }
    }

    #[test]
    fn a_retained_log_outlives_completed_and_dropped_runs() {
        for complete in [true, false] {
            let log = Arc::new(fictionet::events::recorder::Recorder::default());
            let shared = RunShared::with_options(
                RunOptions::new(crate::Seed::from_u64(7)).observer(log.clone()),
                crate::RunMode::Lab,
            );
            let weak_run = Arc::downgrade(&shared);
            let weak_environment = Arc::downgrade(&shared.environment);
            let mut world = Box::pin(run_with(shared, move |fcx| async move {
                fcx.emit("test", "hello", |event| event);
                for _ in 0..2 {
                    fcx.emit("test", "repeat", |event| event);
                }
                fcx.yield_now().await?;
                Ok(())
            }));
            assert!(
                world
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            if complete {
                crate::block_on(world).unwrap();
            } else {
                drop(world);
            }
            assert!(weak_run.upgrade().is_none());
            assert!(weak_environment.upgrade().is_none());
            assert_eq!(Arc::strong_count(&log), 1);
            let events = log.all();
            assert_eq!(
                events
                    .iter()
                    .map(|e| (e.seq, e.source, e.kind))
                    .collect::<Vec<_>>(),
                [
                    (1, "run", "start"),
                    (2, "test", "hello"),
                    (3, "test", "repeat"),
                    (4, "test", "repeat")
                ]
            );
            for event in &events[1..] {
                assert_eq!(event.at, crate::time::Instant::ZERO);
                let origin = event.origin.as_ref().unwrap();
                assert_eq!(origin.task, 1);
                assert_eq!(origin.name, "world");
            }
            assert_eq!(log.all(), events);
        }
    }
}
