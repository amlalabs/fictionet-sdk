use fictionet::sync::Mutex;
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Wake, Waker};

use crate::JoinError;
use crate::cx::{JoinState, Region, is_cancel};
use crate::{Cx, Result, Seed};

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
/// ```
pub async fn run<F, Fut>(seed: Seed, world: F) -> Result
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
/// world, the same seed and ordered inputs give the same results and
/// packets. This requires the world to use the run's clock, randomness and
/// task scheduling. [Repeatable runs](crate::guide::running#repeatable-runs)
/// lists the requirements and runtime boundaries.
///
/// The test plays the sandboxes as tasks of the lab, through
/// [`attachments`](crate::attachments). A lab whose tasks all wait with no
/// deadline ends with an error that says so; a wait with no deadline at all
/// never moves the clock. Host I/O, including [`listen`](crate::listen) and
/// web upstreams, is allowed. Its timing and inputs are up to the world author.
pub async fn lab<F, Fut>(seed: Seed, world: F) -> Result
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
    let id = {
        let mut queue = shared.queue.lock();
        let id = queue.next_id;
        queue.next_id += 1;
        id
    };
    let cx = Cx {
        run: shared.clone(),
        region: root.clone(),
    };
    let future = {
        let _guard = CurrentGuard::enter(shared.id, id, Waker::noop());
        world(cx)
    };
    if root.try_start_task() {
        shared.queue.lock().incoming.push(NewTask {
            id,
            future: Box::pin(future),
            region: root,
            join: Arc::new(JoinState::default()),
        });
    } else {
        drop(future);
    }
    std::future::poll_fn(move |cx| state.poll(cx)).await
}

type BoxFuture = Pin<Box<dyn Future<Output = Result> + Send>>;

/// The part of a run that wakers and every [`Cx`] share.
pub(crate) struct RunShared {
    pub(crate) environment: Arc<crate::environment::RunEnvironment>,
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

    fn new(seed: Seed, mode: crate::RunMode) -> Arc<Self> {
        let run_id = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let environment = Arc::new(crate::environment::RunEnvironment::new(seed, mode));
        Arc::new(Self {
            environment,
            queue: Mutex::new(Queue {
                next_id: 1,
                ..Queue::default()
            }),
            id: run_id,
        })
    }

    /// Adds a task. Gives the future back if the run is gone.
    pub(crate) fn spawn(
        &self,
        future: BoxFuture,
        region: Arc<Region>,
        join: Arc<JoinState>,
    ) -> std::result::Result<(), BoxFuture> {
        let outer = {
            let mut q = self.queue.lock();
            if q.closed {
                return Err(future);
            }
            let id = q.next_id;
            q.next_id += 1;
            let task = NewTask {
                id,
                future,
                region,
                join,
            };
            q.incoming.push(task);
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
pub(crate) struct RunTask {
    pub(crate) run: u64,
    pub(crate) id: u64,
}

#[derive(Clone, Copy)]
struct CurrentTask {
    task: RunTask,
    waker: *const (),
}

thread_local! {
    /// The run, task and waker being polled on this thread, if any.
    static CURRENT: Cell<Option<CurrentTask>> = const { Cell::new(None) };
}

/// Whether `waker` is the waker of the task of `run` that is being polled
/// on this thread right now.
pub(crate) fn is_current_task(run: &Arc<RunShared>, waker: &Waker) -> bool {
    CURRENT.with(|c| {
        c.get()
            .is_some_and(|t| t.task.run == run.id && t.waker == waker.data())
    })
}

/// Restores the current task when a poll ends, even by a panic.
struct CurrentGuard {
    previous: Option<CurrentTask>,
}

impl CurrentGuard {
    fn enter(run: u64, id: u64, waker: &Waker) -> Self {
        let current = CurrentTask {
            task: RunTask { run, id },
            waker: waker.data(),
        };
        Self {
            previous: CURRENT.with(|c| c.replace(Some(current))),
        }
    }
}

impl Drop for CurrentGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| c.replace(self.previous.take()));
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
                let _guard = CurrentGuard::enter(self.shared.id, id, &slot.waker);
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
            // A waker outside the run does not wake it, so come back: a lab
            // jumps its clock next if the wakeups gave no task work.
            cx.waker().wake_by_ref();
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
        // The dropped work, as its region and joiner see it ending.
        let ended: Vec<(Arc<Region>, Arc<JoinState>)> = incoming
            .iter()
            .map(|t| (t.region.clone(), t.join.clone()))
            .chain(
                self.slots
                    .values()
                    .map(|s| (s.region.clone(), s.join.clone())),
            )
            .collect();
        for task in incoming {
            let NewTask {
                id: _,
                future,
                region,
                join,
                ..
            } = task;
            drop((future, region, join));
        }
        // Task destructors run in ascending task ID order.
        for (_id, slot) in std::mem::take(&mut self.slots) {
            let Slot {
                future,
                task_waker,
                waker,
                region,
                join,
                ..
            } = slot;
            drop((future, task_waker, waker, region, join));
        }
        // Work spawned while the slots were dropped.
        let late = std::mem::take(&mut self.shared.queue.lock().incoming);
        drop(late);
        // Every region of the run is cancelled before any of them sees its
        // dropped work end, so a wait outside the run on one of its `Cx`
        // clones reads `Cancelled`.
        self.root.cancel();
        // Waits outside the run end too: joins of the dropped work, and
        // regions waiting for it, which count it as ended by the cancel.
        for (region, join) in ended {
            join.finish(Err(JoinError::Cancelled));
            region.ended_by_cancel();
            region.task_done(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::ms;
    use crate::{Cancelled, block_on};

    /// A `Cx::idle` polled outside the run, as by a harness that keeps a
    /// clone of the world's `Cx`, is woken when the run goes idle. The lab
    /// must still jump its clock after that, or its sleeping tasks never
    /// wake.
    #[test]
    fn a_lab_keeps_advancing_after_waking_an_idle_wait_outside_the_run() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = block_on(lab(Seed::from_u64(0), |fcx| async move {
                let outside = fcx.clone();
                let mut idle = Box::pin(async move { outside.idle().await });
                // Polled with a waker that is not this run's task, as a
                // harness thread would poll it.
                assert!(
                    idle.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                fcx.sleep(ms(10)).await?;
                drop(idle);
                Ok(())
            }));
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the receiver is gone only once recv_timeout below has failed the test"
            )]
            let _ = tx.send(out.map_err(|e| e.to_string()));
        });
        let out = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the lab stopped jumping its clock after the idle wakeup");
        assert_eq!(out, Ok(()));
    }

    /// A task that waits on `Cx::idle` until another task's timer has done
    /// its work is waiting too. Once it has seen the run idle, the lab must
    /// jump its clock, or the timer never comes and the lab spins forever.
    #[test]
    fn a_lab_jumps_its_clock_while_a_task_waits_on_idle_in_a_loop() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let out = block_on(lab(Seed::from_u64(0), |fcx| async move {
                let fired = Arc::new(AtomicBool::new(false));
                let set = fired.clone();
                fcx.spawn(move |fcx| async move {
                    fcx.sleep(ms(10)).await?;
                    set.store(true, Ordering::SeqCst);
                    Ok(())
                });
                while !fired.load(Ordering::SeqCst) {
                    fcx.idle().await?;
                }
                assert_eq!(fcx.now().since_start(), ms(10));
                Ok(())
            }));
            #[expect(
                clippy::let_underscore_must_use,
                reason = "the receiver is gone only once recv_timeout below has failed the test"
            )]
            let _ = tx.send(out.map_err(|e| e.to_string()));
        });
        let out = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the lab never jumped its clock while a task waited on idle");
        assert_eq!(out, Ok(()));
    }

    /// `Cx::region` awaited outside the run is a wait on a `Cx` clone:
    /// once the run is dropped it must end with `Cancelled`, even though
    /// the work it spawned was dropped with the run instead of ending.
    #[test]
    fn a_region_outside_the_run_ends_when_the_run_is_dropped() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut world = Box::pin(run(Seed::from_u64(0), move |fcx| async move {
            tx.send(fcx.clone()).unwrap();
            std::future::pending::<()>().await;
            Ok(())
        }));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(world.as_mut().poll(&mut cx).is_pending());
        let fcx = rx.recv().unwrap();
        let mut region = Box::pin(fcx.region(|fcx| async move {
            fcx.spawn(|fcx| async move {
                fcx.sleep(std::time::Duration::from_secs(60)).await?;
                Ok(())
            });
            fcx.cancelled().await;
            Err(Cancelled.into())
        }));
        assert!(region.as_mut().poll(&mut cx).is_pending());
        drop(world);
        match region.as_mut().poll(&mut cx) {
            Poll::Ready(Err(e)) => assert!(e.is::<Cancelled>(), "{e:?}"),
            Poll::Ready(Ok(())) => panic!("the region was cut short, not finished"),
            Poll::Pending => panic!("the region waits for work the dropped run will never end"),
        }
    }
}
