use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::panic::Location;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};

use crate::JoinError;
use crate::cx::{JoinState, Region, is_cancel};
use crate::watch::{Graph, Polling};
use crate::{Cx, Result};

/// Runs a world in real time, as one future that any executor can poll.
///
/// `world` is called with the [`Cx`] of a new [region](Cx#regions), and
/// becomes the first task in it. Every task the world starts with
/// [`Cx::spawn`] is polled inside this same future, so `run` needs no
/// executor of its own. Without tokio, poll it with
/// [`block_on`](crate::block_on).
///
/// Time is the wall clock, and randomness comes from the operating system.
/// That is what a run with a real sandbox needs, because the sandbox's
/// kernel and programs time out on real time. Real sockets, Redis and the
/// internet all work, and their times agree with [`Cx::now`]. Libraries
/// built on tokio need a tokio runtime to poll the world, not
/// [`block_on`](crate::block_on). Because the clock is real, timings vary
/// a little from run to run.
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
/// # mod sqlx {
/// #     pub struct PgPool;
/// #     impl PgPool {
/// #         pub async fn connect(_: &str) -> fictionet::Result<PgPool> { Ok(PgPool) }
/// #     }
/// # }
/// # async fn world(_fcx: fictionet::Cx, _a: fictionet::Attachments, _db: sqlx::PgPool) -> fictionet::Result { Ok(()) }
/// #[tokio::main]
/// async fn main() -> fictionet::Result {
///     let db = sqlx::PgPool::connect("postgres://...").await?;
///     let (attacher, attachments) = fictionet::attachments();
///     let socket = fictionet::WorldSocket::UnixSocket("/run/fictionet/world.sock".into());
///     let _listening = fictionet::listen(socket, attacher)?;
///     fictionet::run(|fcx| world(fcx, attachments, db)).await
/// }
/// ```
pub async fn run<F, Fut>(world: F) -> Result
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = Result> + Send + 'static,
{
    run_with(Graph::new(), world).await
}

/// [`run`], recording what happens in `graph`.
pub(crate) async fn run_with<F, Fut>(graph: Arc<Graph>, world: F) -> Result
where
    F: FnOnce(Cx) -> Fut + Send,
    Fut: Future<Output = Result> + Send + 'static,
{
    let shared = Arc::new(RunShared {
        start: graph.start,
        queue: Mutex::new(Queue {
            next_id: 1,
            ..Queue::default()
        }),
        graph,
    });
    let root = Region::root(Arc::downgrade(&shared));
    let mut state = RunState {
        shared: shared.clone(),
        root: root.clone(),
        slots: HashMap::new(),
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
    /// The moment the run started: [`Instant::ZERO`](crate::time::Instant::ZERO).
    pub(crate) start: crate::sys::Instant,
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
}

struct NewTask {
    id: u64,
    future: BoxFuture,
    region: Arc<Region>,
    join: Arc<JoinState>,
}

impl RunShared {
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
        let outer = {
            let mut q = self.queue.lock().unwrap();
            if q.closed {
                return Err(future);
            }
            let id = q.next_id;
            q.next_id += 1;
            // Before the task can be polled, so its links find it.
            self.graph
                .task_started(id, name(), location, group.cloned());
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
            let mut q = self.queue.lock().unwrap();
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
            let mut q = self.queue.lock().unwrap();
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

thread_local! {
    /// The run and task being polled on this thread, if any: the run's
    /// address and the data pointer of the task's waker.
    static CURRENT: Cell<(*const RunShared, *const ())> =
        const { Cell::new((std::ptr::null(), std::ptr::null())) };
}

/// Whether `waker` is the waker of the task of `run` that is being polled
/// on this thread right now.
pub(crate) fn is_current_task(run: &Arc<RunShared>, waker: &Waker) -> bool {
    CURRENT.with(|c| {
        let (r, data) = c.get();
        r == Arc::as_ptr(run) && data == waker.data()
    })
}

/// Restores [`CURRENT`] when a poll ends, even by a panic.
struct CurrentGuard((*const RunShared, *const ()));

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| c.set(self.0));
    }
}

/// The state of a run that only the future returned by [`run`] touches.
struct RunState {
    shared: Arc<RunShared>,
    root: Arc<Region>,
    slots: HashMap<u64, Slot>,
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
            let mut q = self.shared.queue.lock().unwrap();
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
                let mut ids: Vec<u64> = self.slots.keys().copied().collect();
                ids.sort_unstable();
                for id in ids {
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

        let run_ptr = Arc::as_ptr(&self.shared);
        while let Some(id) = turn.pop_front() {
            let Some(slot) = self.slots.get_mut(&id) else {
                continue;
            };
            slot.task_waker.queued.store(false, Ordering::Release);
            let result = {
                let previous = CURRENT.with(|c| c.replace((run_ptr, slot.waker.data())));
                let _guard = CurrentGuard(previous);
                let _polling = Polling::enter(id);
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
        let mut q = self.shared.queue.lock().unwrap();
        q.polling = false;
        if self.slots.is_empty() && q.incoming.is_empty() {
            drop(q);
            return Poll::Ready(match self.root.take_error() {
                Some(e) => Err(e),
                None => Ok(()),
            });
        }
        let more = !q.ready.is_empty() || !q.incoming.is_empty() || q.wake_all;
        drop(q);
        if more {
            // Give the executor its turn too, then come back.
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl Drop for RunState {
    fn drop(&mut self) {
        let incoming = {
            let mut q = self.shared.queue.lock().unwrap();
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
        drop(std::mem::take(&mut self.slots));
        // Work spawned while the slots were dropped.
        let late = std::mem::take(&mut self.shared.queue.lock().unwrap().incoming);
        drop(late);
        // Waits outside the run end too: joins of the dropped work, and
        // every wait on a `Cx` of the run, which reads `Cancelled`.
        for join in joins {
            join.finish(Err(JoinError::Cancelled));
        }
        self.root.cancel();
        self.shared.graph.run_ended();
    }
}
