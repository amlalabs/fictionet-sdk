use fictionet::sync::Mutex;
use std::borrow::Cow;
use std::cell::Cell;
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
use crate::watch::Graph;
use crate::{Cx, Result};

/// Run ids, unique in the process. They are only compared for equality,
/// never recorded, serialized, ordered or hashed into anything a world
/// sees, so they do not affect determinism.
static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

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
/// [`Net::start`](crate::stdlib::net::Net::start) records the seed in
/// `run.start`. Worlds without `Net` call
/// [`EventLog::start`](crate::events::EventLog::start) explicitly; neither
/// `run` nor [`lab`] emits that event itself.
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
///     fictionet::run(fictionet::Seed::random(), |fcx| async move {
///         // Build the world with `fcx`, `attachments` and `db`.
/// #       let _ = (fcx, attachments, db);
///         Ok(())
///     }).await
/// }
/// # #[cfg(not(feature = "std"))]
/// # fn main() {}
/// ```
#[cfg(feature = "std")]
pub async fn run<F, Fut>(seed: crate::Seed, world: F) -> Result
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = Result> + Send + 'static,
{
    run_with(RunShared::new(seed, crate::RunMode::Real), world).await
}

/// Runs a closed world on simulated time, for tests.
///
/// A lab runs the world on the same executor as [`run`], with randomness
/// from `seed` in the same way. Only the clock differs. It starts at zero,
/// and when every task is waiting it jumps to the earliest deadline, waking
/// timers due at the same instant in the order they were set. With a closed
/// world, the same seed and ordered inputs give the same event log and
/// packets. This requires the world to use the run's clock, randomness and
/// task scheduling. [Repeatable runs](crate::running#repeatable-runs)
/// lists the requirements and the HTTP/2 host-clock exception.
///
/// Like [`run`], `lab` leaves `run.start` recording to
/// [`Net::start`](crate::stdlib::net::Net::start) or an explicit call to
/// [`EventLog::start`](crate::events::EventLog::start).
///
/// Each run has its own task identities. A lab started inside another
/// run's task has a world root with no parent in the outer run.
///
/// The test plays the sandboxes as tasks of the lab, through
/// [`attachments`](crate::attachments). A lab whose tasks all wait with no
/// deadline ends with an error that says so; a wait with no deadline at all
/// never moves the clock. Attachments fed by [`listen`](crate::listen) fail
/// the lab on their first `get`, `next` or `map`, before handing out an
/// attachment, and `get` and `next` return [`Cancelled`](crate::Cancelled).
/// Observer sessions, `web::proxy` and `web::forward` refuse a lab too.
pub async fn lab<F, Fut>(seed: crate::Seed, world: F) -> Result
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = Result> + Send + 'static,
{
    run_with(RunShared::new(seed, crate::RunMode::Lab), world).await
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
        root: root.clone(),
        slots: BTreeMap::new(),
        turn: VecDeque::new(),
        incoming: Vec::new(),
    };
    Cx {
        run: shared,
        region: root,
        group: None,
    }
    .spawn_as(|| Cow::Borrowed("world"), world);
    std::future::poll_fn(move |cx| state.poll(cx)).await
}

type BoxFuture = Pin<Box<dyn Future<Output = Result> + Send>>;

/// The part of a run that wakers and every [`Cx`] share.
pub(crate) struct RunShared {
    pub(crate) environment: Arc<crate::environment::RunEnvironment>,
    pub(crate) start_wall: SystemTime,
    /// The run's events, kept whether or not anyone observes.
    pub(crate) events: Arc<crate::events::Store>,
    /// The run's TLS key log, shared with the graph for observers.
    #[cfg(feature = "observe")]
    pub(crate) keys: Arc<crate::telemetry::KeyRecorder>,
    queue: Mutex<Queue>,
    /// What the run records for observers.
    pub(crate) graph: Arc<Graph>,
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

    pub(crate) fn new(seed: crate::Seed, mode: crate::RunMode) -> Arc<Self> {
        let run_id = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let environment = Arc::new(crate::environment::RunEnvironment::new(seed, mode));
        let start_wall = if mode == crate::RunMode::Real {
            SystemTime::now()
        } else {
            crate::sys::UNIX_EPOCH
        };
        let events = crate::events::Store::new(mode);
        #[cfg(feature = "observe")]
        let keys = Arc::new(crate::telemetry::KeyRecorder::default());
        let graph = Graph::new(
            run_id,
            environment.clone(),
            start_wall,
            events.clone(),
            #[cfg(feature = "observe")]
            keys.clone(),
        );
        Arc::new(Self {
            environment,
            start_wall,
            events,
            #[cfg(feature = "observe")]
            keys,
            queue: Mutex::new(Queue {
                next_id: 1,
                ..Queue::default()
            }),
            graph,
        })
    }

    pub(crate) fn end(&self) {
        self.graph.run_ended();
        // Nothing more is recorded: let callbacks and file writers go.
        self.events.close();
        // Nothing more crosses the world's links: stop watching them.
        #[cfg(feature = "observe")]
        self.graph.watches.end_run();
    }

    /// Adds a task. Gives the future back if the run is gone.
    pub(crate) fn spawn(
        &self,
        future: BoxFuture,
        region: Arc<Region>,
        join: Arc<JoinState>,
        name: impl FnOnce() -> Cow<'static, str>,
        location: &'static Location<'static>,
        group: Option<&Arc<crate::watch::Group>>,
    ) -> std::result::Result<(), BoxFuture> {
        let name = name();
        let outer = {
            let mut q = self.queue.lock();
            if q.closed {
                return Err(future);
            }
            let id = q.next_id;
            q.next_id += 1;
            // Before the task can be polled, so its links find it.
            self.graph.task_started(id, name, location, group.cloned());
            q.incoming.push(NewTask {
                id,
                future,
                region,
                join,
            });
            if q.polling { None } else { q.outer.clone() }
        };
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
    future: BoxFuture,
    task_waker: Arc<TaskWaker>,
    waker: Waker,
    region: Arc<Region>,
    join: Arc<JoinState>,
}

/// A task number qualified by its run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskId {
    run: u64,
    pub(crate) id: u64,
}

impl TaskId {
    pub(crate) fn current() -> Option<Self> {
        CURRENT.with(Cell::get).map(|current| current.task)
    }

    /// The current task, only if it belongs to `graph`'s run.
    pub(crate) fn current_in(graph: &Graph) -> Option<Self> {
        Self::current().filter(|t| t.run == graph.run_id)
    }

    /// The task number in `graph`, or 0 if it belongs to another run.
    pub(crate) fn in_graph(&self, graph: &Graph) -> u64 {
        if self.run == graph.run_id { self.id } else { 0 }
    }
}

#[derive(Clone, Copy)]
struct CurrentTask {
    task: TaskId,
    waker: *const (),
}

thread_local! {
    /// The run, task and waker being polled on this thread, if any.
    static CURRENT: Cell<Option<CurrentTask>> = const { Cell::new(None) };
}

/// The task this thread is polling in `graph`, or 0.
#[inline]
pub(crate) fn current_task(graph: &Graph) -> u64 {
    TaskId::current().map_or(0, |t| t.in_graph(graph))
}

/// Whether `waker` is the waker of the task of `run` that is being polled
/// on this thread right now.
pub(crate) fn is_current_task(run: &Arc<RunShared>, waker: &Waker) -> bool {
    CURRENT.with(|c| {
        c.get()
            .is_some_and(|t| t.task.run == run.graph.run_id && t.waker == waker.data())
    })
}

/// Restores [`CURRENT`] when a poll ends, even by a panic.
struct CurrentGuard(Option<CurrentTask>);

impl CurrentGuard {
    fn enter(graph: &Graph, id: u64, waker: &Waker) -> Self {
        let current = CurrentTask {
            task: TaskId {
                run: graph.run_id,
                id,
            },
            waker: waker.data(),
        };
        Self(CURRENT.with(|c| c.replace(Some(current))))
    }
}

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| c.set(self.0));
    }
}

/// The state of a run that only the future returned by [`run`] touches.
struct RunState {
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
            slot.task_waker.queued.store(false, Ordering::Release);
            let result = {
                let _guard = CurrentGuard::enter(&self.shared.graph, id, &slot.waker);
                slot.future
                    .as_mut()
                    .poll(&mut Context::from_waker(&slot.waker))
            };
            if let Poll::Ready(result) = result {
                let slot = self.slots.remove(&id).unwrap();
                let Slot {
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
                self.shared.graph.task_ended(id);
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
        drop(incoming);
        // Task destructors run in ascending task ID order.
        for slot in std::mem::take(&mut self.slots).into_values() {
            drop(slot);
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
    use crate::events::{Event, Fields};

    #[test]
    fn retained_logs_outlive_completed_and_dropped_runs() {
        for complete in [true, false] {
            let shared = RunShared::new(crate::Seed::from_u64(7), crate::RunMode::Lab);
            let graph = shared.graph.clone();
            let weak_run = Arc::downgrade(&shared);
            let weak_graph = Arc::downgrade(&graph);
            let weak_environment = Arc::downgrade(&shared.environment);
            let kept = Arc::new(Mutex::new(None));
            let keep = kept.clone();
            let delivered = Arc::new(Mutex::new(Vec::new()));
            let seen = delivered.clone();
            let observed = graph.clone();
            let mut world = Box::pin(run_with(shared, move |fcx| async move {
                let log = fcx.events();
                log.subscribe(move |event| {
                    if event.seq == 3 {
                        let state = observed.state();
                        assert!(state.ended);
                        assert!(state.tasks.is_empty());
                    }
                    seen.lock().push(event.seq);
                });
                fcx.record(Event::new("test", "hello"));
                for _ in 0..2 {
                    fcx.record_repeat(Event::new("test", "repeat"), Fields::new());
                }
                assert_eq!(log.recorded(), 2);
                *keep.lock() = Some(log);
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

            let log = kept.lock().take().unwrap();
            assert_eq!(*delivered.lock(), [1, 2, 3]);
            assert_eq!(Arc::strong_count(&delivered), 1, "callbacks are released");
            assert!(weak_run.upgrade().is_none());
            assert!(graph.state().ended);
            #[cfg(feature = "observe")]
            assert_eq!(graph.events.last(), log.recorded());
            drop(graph);
            assert!(weak_graph.upgrade().is_none());
            assert!(weak_environment.upgrade().is_none());

            let events = log.all();
            assert_eq!(events.len(), 3);
            assert_eq!(events[2].u64("count"), Some(1));
            for event in events {
                assert_eq!(event.at, crate::time::Instant::ZERO);
                let origin = event.origin.unwrap();
                assert_eq!(origin.task, 1);
                assert_eq!(origin.name, "world");
            }
            delivered.lock().clear();
            let replayed = delivered.clone();
            log.subscribe(move |event| replayed.lock().push(event.seq));
            assert_eq!(*delivered.lock(), [1, 2, 3]);
            assert_eq!(Arc::strong_count(&delivered), 1, "replay is not retained");
        }
    }
}
