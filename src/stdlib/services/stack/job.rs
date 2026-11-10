use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use fictionet::stdlib::layer::{
    Charge, ChildId, ChildWork, Driver, Layer, OwnedWork, Side, Worker,
};
use fictionet::time::Instant;
use fictionet::{Cx, Entropy};

use super::boxed::{BoxDone, BoxWork, Boxing};

/// Work a layer asks the world to do ([`Layer::Work`]), as whatever runs
/// the stack does it: a handler's async answer, the next frame of a
/// streamed body, a TLS config picked for a client's hello, code that
/// takes over a connection.
///
/// A layer never polls anything. It hands its work over in
/// [`take_work`](Layer::take_work); the runner polls the work here with the
/// world's context and gives the result back through
/// [`on_done`](Layer::on_done). Work carries what it needs and brings back
/// what the layer needs, such as a body it borrowed, so the layer can tell
/// a stale result by a generation it put in.
///
/// [`stream`](super::stream) and [`datagrams`](super::datagrams) do this
/// over a live connection or socket, and [`Polling`] in a
/// [`Harness`](fictionet::stdlib::layer::Harness).
pub trait Job: Send + 'static {
    /// What the layer hears when the work is done.
    type Done;

    /// Whether its owner has ended. Cancelled work is never polled again.
    fn cancelled(&self) -> bool {
        false
    }

    /// Moves the work on. `fcx` is the world's context, or `None` in a
    /// harness given none, where work that needs one finishes with its
    /// error.
    ///
    /// After returning `Ready`, release completed futures and private clones
    /// of the supplied context. Release input storage no longer needed by
    /// retained public state or the cancellation check.
    /// Transfer contexts needed by the result into that result. The runner
    /// retains completed work only to observe `cancelled`, while contexts
    /// transferred to the result keep its region open for deferred work.
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done>;

    /// This work behind one type, as a [`Boxed`](super::Boxed) stack hands
    /// it out: one allocation, which its result comes back in. Work that
    /// is boxed already goes out as it is.
    fn erase(self) -> BoxWork
    where
        Self: Sized,
        Self::Done: Send + 'static,
    {
        BoxWork::new(Boxing::new(self))
    }

    /// This work's result, back from a [`Boxed`](super::Boxed) stack, or
    /// the result as it came when it is another's.
    fn claim(done: BoxDone) -> Result<Self::Done, BoxDone>
    where
        Self: Sized,
        Self::Done: Send + 'static,
    {
        let mut boxing = done.downcast::<Boxing<Self>>()?;
        match boxing.done.take() {
            Some(done) => Ok(done),
            None => Err(boxing),
        }
    }
}

/// A composed layer's work: whichever part asked for it does it.
impl<A: Job, B: Job> Job for Side<A, B> {
    type Done = Side<A::Done, B::Done>;

    fn cancelled(&self) -> bool {
        match self {
            Side::Lower(a) => a.cancelled(),
            Side::Upper(b) => b.cancelled(),
        }
    }

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        match self {
            Side::Lower(a) => a.poll(fcx, cx).map(Side::Lower),
            Side::Upper(b) => b.poll(fcx, cx).map(Side::Upper),
        }
    }
}

impl<W: Job> Job for OwnedWork<W> {
    type Done = W::Done;
    fn cancelled(&self) -> bool {
        self.cancelled() || self.work.cancelled()
    }
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        self.work.poll(fcx, cx)
    }
}

/// A child's work wakes its child as well as the task polling it, so a
/// layer that shares state with its work is visited when the work moves.
impl<W: Job> Job for ChildWork<W> {
    type Done = (ChildId, W::Done);
    fn cancelled(&self) -> bool {
        Job::cancelled(&self.work)
    }
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        let waker = self.wake.waker(cx.waker());
        let result = self.work.poll(fcx, &mut Context::from_waker(&waker));
        if result.is_ready() {
            self.finished = true;
        }
        result.map(|done| (self.id(), done))
    }
}

impl<W: Job> Job for (ChildId, W) {
    type Done = (ChildId, W::Done);
    fn cancelled(&self) -> bool {
        self.1.cancelled()
    }
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        self.1.poll(fcx, cx).map(|done| (self.0, done))
    }
}

/// The work of a layer that asks for none.
impl Job for () {
    type Done = ();

    fn poll(&mut self, _: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

/// Work that cannot exist.
impl Job for Infallible {
    type Done = Infallible;

    fn poll(&mut self, _: Option<&Cx>, _: &mut Context<'_>) -> Poll<Infallible> {
        match *self {}
    }
}

/// The work a stack handed over that has not finished, in the order it
/// was handed over.
pub(crate) struct Jobs<W> {
    running: Vec<Running<W>>,
    storage: Option<Charge>,
    budget_failed: bool,
}

// The job count and intake are engine limits, independent of carrier credit.
const JOBS: usize = 64;
const INTAKE: usize = 8;

struct Running<W> {
    work: Option<W>,
    completed: bool,
    region: Option<Cx>,
}

impl<W> Drop for Running<W> {
    fn drop(&mut self) {
        if let Some(region) = &self.region {
            region.cancel();
        }
    }
}

impl<W: Job> Jobs<W> {
    pub(crate) fn new() -> Jobs<W> {
        Jobs {
            running: Vec::new(),
            storage: None,
            budget_failed: false,
        }
    }

    pub(crate) fn budget_exhausted(&self) -> bool {
        self.budget_failed
    }

    pub(crate) fn len(&self) -> usize {
        self.running.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    /// Takes the stack's new work from `driver`. Returns whether there was
    /// any.
    pub(crate) fn take<L: Layer<Work = W>>(&mut self, driver: &mut Driver<L>) -> bool {
        let mut took = false;
        for _ in 0..INTAKE {
            if self.running.len() == JOBS || self.budget_failed {
                break;
            }
            if self.running.len() == self.running.capacity() {
                let capacity = self.running.len() + 1;
                let bytes = capacity * std::mem::size_of::<Running<W>>();
                let reserved = match &mut self.storage {
                    Some(charge) => charge.grow_to(bytes),
                    None => {
                        self.storage = driver.budget().charge(bytes);
                        self.storage.is_some()
                    }
                };
                if !reserved {
                    // Existing jobs can release storage or budget when polled.
                    self.budget_failed = self.running.is_empty();
                    break;
                }
                if self.running.capacity() == 0 {
                    // Keep one reserved slot while idle so work can be checked
                    // even when the layer retains the rest of its budget.
                    self.running.reserve_exact(1);
                }
            }
            let Some(work) = driver.take_work() else {
                if let Some(charge) = &mut self.storage {
                    charge.shrink_to(self.running.capacity() * std::mem::size_of::<Running<W>>());
                }
                break;
            };
            if self.running.len() == self.running.capacity() {
                self.running.reserve_exact(1);
            }
            self.running.push(Running {
                work: Some(work),
                completed: false,
                region: None,
            });
            took = true;
        }
        took
    }

    /// End the tasks behind completed work once the whole stack is terminal.
    /// Half-closing one direction does not end their owner.
    pub(crate) fn close_completed(&mut self) {
        for running in &mut self.running {
            if running.completed {
                running.work = None;
                if let Some(region) = &running.region {
                    region.cancel();
                }
            }
        }
    }

    /// Polls every piece of work once, oldest first, and hands each result
    /// to `done` as it comes. Returns whether any finished.
    pub(crate) fn poll<E>(
        &mut self,
        fcx: Option<&Cx>,
        cx: &mut Context<'_>,
        mut done: impl FnMut(W::Done) -> Result<(), E>,
    ) -> Result<bool, E> {
        let mut finished = false;
        let before = self.running.len();
        let mut i = 0;
        while i < self.running.len() {
            let running = &mut self.running[i];
            if running.work.is_some() && running.region.is_none() {
                running.region = fcx.map(Cx::job_context);
            }
            // Work whose owner ended, or whose own region was cancelled or
            // failed, is never polled again: a task of its that failed
            // ends that work, and the failure goes to the parent below.
            let ended = running.work.as_ref().is_some_and(Job::cancelled)
                || (running.work.is_some()
                    && running.region.as_ref().is_some_and(Cx::is_cancelled));
            if ended {
                running.work = None;
                if let Some(region) = &running.region {
                    region.cancel();
                }
                finished = true;
            }
            if !running.completed
                && let Some(work) = &mut running.work
                && let Poll::Ready(result) = work.poll(running.region.as_ref(), cx)
            {
                // Returned streams may retain the context and start work later.
                // Keep the owner until both borrowed contexts and tasks end.
                running.completed = true;
                finished = true;
                done(result)?;
            }
            let drained = (running.completed || running.work.is_none())
                && running.region.as_ref().is_none_or(|region| {
                    (running.work.is_none() || region.poll_job_context_released(cx).is_ready())
                        && region.region.poll_done(cx).is_ready()
                });
            if drained {
                if let Some(region) = &running.region
                    && let Some(error) = region.region.take_error()
                    && let Some(parent) = fcx
                {
                    parent.region.fail(error);
                }
                self.running.remove(i);
                finished = true;
            } else {
                i += 1;
            }
        }
        if self.running.len() < before {
            // Release the allocation before returning its reservation.
            self.running.shrink_to(1);
            if let Some(charge) = &mut self.storage {
                charge.shrink_to(self.running.capacity() * std::mem::size_of::<Running<W>>());
            }
        }
        Ok(finished)
    }
}

/// Polls a stack's work for a [`Harness`](fictionet::stdlib::layer::Harness),
/// as the live runners do, each time the harness runs the stack. Work that
/// is not ready waits for the next call; work that wakes itself while it
/// is polled is polled again at once.
pub struct Polling<W> {
    jobs: Jobs<W>,
    fcx: Option<Cx>,
    woken: Arc<Flag>,
}

/// Set when polled work asks to be polled again.
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl<W: Job> Polling<W> {
    /// Polls the work with no world: work that needs one finishes with its
    /// error.
    pub fn new() -> Polling<W> {
        Polling {
            jobs: Jobs::new(),
            fcx: None,
            woken: Arc::new(Flag(AtomicBool::new(false))),
        }
    }

    /// Runs the stack in the world of `fcx`: the harness takes its entropy,
    /// reads its clock each time it runs the stack, and polls the work with
    /// it. Only the world moves the clock then:
    /// [`Harness::advance`](fictionet::stdlib::layer::Harness::advance)
    /// panics.
    pub fn in_world(fcx: Cx) -> Polling<W> {
        Polling {
            fcx: Some(fcx),
            ..Polling::new()
        }
    }
}

impl<W: Job> Default for Polling<W> {
    fn default() -> Polling<W> {
        Polling::new()
    }
}

impl<L> Worker<L> for Polling<L::Work>
where
    L: Layer,
    L::Work: Job<Done = L::Done>,
{
    fn work(&mut self, driver: &mut Driver<L>) -> Result<bool, L::Error> {
        if driver.layer().is_terminal() {
            self.jobs.close_completed();
        }
        let mut moved = self.jobs.take(driver);
        self.woken.0.store(false, Ordering::Relaxed);
        let waker = Waker::from(self.woken.clone());
        let mut cx = Context::from_waker(&waker);
        moved |= self
            .jobs
            .poll(self.fcx.as_ref(), &mut cx, |done| driver.complete(done))?;
        // Work that woke itself while it was polled has more to do.
        Ok(moved || self.woken.0.load(Ordering::Relaxed))
    }

    fn budget_exhausted(&self) -> bool {
        self.jobs.budget_exhausted()
    }

    fn running(&self) -> usize {
        self.jobs.len()
    }

    fn entropy(&self) -> Option<Arc<dyn Entropy>> {
        self.fcx
            .as_ref()
            .map(|fcx| Arc::new(fcx.clone()) as Arc<dyn Entropy>)
    }

    fn now(&self) -> Option<Instant> {
        self.fcx.as_ref().map(Cx::now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::layer::{Admit, Budget, Env, Top, WorkOwner};
    use fictionet::{Seed, SeededEntropy};
    use std::sync::atomic::AtomicUsize;

    type Start = Arc<fictionet::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>;

    struct PendingJob {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        tasks: Arc<AtomicUsize>,
        stopped: Arc<AtomicUsize>,
        start: Start,
        ready: bool,
        returned: Arc<AtomicUsize>,
    }
    struct TaskDrop(Arc<AtomicUsize>);
    impl Drop for TaskDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl Job for PendingJob {
        type Done = ();
        fn poll(&mut self, fcx: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
            let polls = self.polls.fetch_add(1, Ordering::Relaxed);
            if let Some(fcx) = fcx
                && polls == 0
            {
                let tasks = self.tasks.clone();
                let guard = TaskDrop(self.stopped.clone());
                let start = self.start.lock().take();
                let returned = self.returned.clone();
                let ready = self.ready;
                fcx.spawn(move |fcx| async move {
                    let _guard = guard;
                    if ready {
                        assert!(returned.load(Ordering::Relaxed) > 0);
                    }
                    tasks.fetch_add(1, Ordering::Relaxed);
                    if let Some(start) = start {
                        start.send(()).expect("the setup awaits task start");
                    }
                    fcx.cancelled().await;
                    Ok(())
                });
            }
            if self.ready {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
    impl Drop for PendingJob {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct Source {
        owner: WorkOwner,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        tasks: Arc<AtomicUsize>,
        stopped: Arc<AtomicUsize>,
        start: Start,
        ready: bool,
        returned: Arc<AtomicUsize>,
        extracted: usize,
        remaining: Option<usize>,
    }
    impl Source {
        fn new() -> Self {
            Self {
                owner: WorkOwner::new(),
                polls: Arc::default(),
                drops: Arc::default(),
                tasks: Arc::default(),
                stopped: Arc::default(),
                start: Arc::default(),
                ready: false,
                returned: Arc::default(),
                extracted: 0,
                remaining: None,
            }
        }
    }
    impl Layer for Source {
        type Lower = Top;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = OwnedWork<PendingJob>;
        type Done = ();
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            e: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match e {}
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<Infallible> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn take_work(&mut self) -> Option<Self::Work> {
            if let Some(remaining) = &mut self.remaining {
                *remaining = remaining.checked_sub(1)?;
            }
            self.extracted += 1;
            Some(self.owner.own(PendingJob {
                polls: self.polls.clone(),
                drops: self.drops.clone(),
                tasks: self.tasks.clone(),
                stopped: self.stopped.clone(),
                start: self.start.clone(),
                ready: self.ready,
                returned: self.returned.clone(),
            }))
        }
    }
    fn driver(budget: Budget) -> Driver<Source> {
        Driver::new(
            Source::new(),
            Arc::new(SeededEntropy::new(Seed::from_u64(0))),
            budget,
            Instant::ZERO,
        )
    }

    #[test]
    fn productive_work_source_has_bounded_intake_and_storage() {
        let budget = Budget::unlimited();
        let mut driver = driver(budget.clone());
        let mut jobs = Jobs::new();
        assert!(jobs.take(&mut driver));
        assert_eq!(jobs.len(), INTAKE);
        for _ in 0..JOBS {
            jobs.take(&mut driver);
        }
        assert_eq!(jobs.len(), JOBS);
        assert_eq!(driver.layer().extracted, JOBS);
        assert!(
            budget.used()
                >= jobs.running.capacity() * std::mem::size_of::<Running<OwnedWork<PendingJob>>>()
        );
        drop(jobs);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn cancelled_work_drops_before_another_poll() {
        let mut driver = driver(Budget::unlimited());
        let mut jobs = Jobs::new();
        jobs.take(&mut driver);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        jobs.poll(None, &mut cx, |_| Ok::<_, Infallible>(()))
            .unwrap();
        assert_eq!(driver.layer().polls.load(Ordering::Relaxed), INTAKE);
        driver.layer().owner.cancel();
        assert!(
            jobs.poll(None, &mut cx, |_| -> Result<(), Infallible> {
                panic!("cancelled work completed")
            })
            .unwrap()
        );
        assert!(jobs.is_empty());
        assert_eq!(driver.layer().polls.load(Ordering::Relaxed), INTAKE);
        assert_eq!(driver.layer().drops.load(Ordering::Relaxed), INTAKE);
    }

    #[test]
    fn checking_an_idle_layer_needs_only_one_reserved_job_slot() {
        let budget = Budget::new(std::mem::size_of::<Running<OwnedWork<PendingJob>>>());
        let mut driver = Driver::new(
            fictionet::stdlib::layer::Later::<Source>::new(),
            Arc::new(SeededEntropy::new(Seed::from_u64(0))),
            budget.clone(),
            Instant::ZERO,
        );
        let mut jobs = Jobs::new();
        assert!(!jobs.take(&mut driver));
        assert!(!jobs.budget_exhausted());
        assert!(jobs.is_empty());
        assert!(!jobs.take(&mut driver));
        assert!(!jobs.budget_exhausted());
        drop(jobs);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_full_job_reservation_keeps_existing_work_pollable() {
        let budget = Budget::new(std::mem::size_of::<Running<OwnedWork<PendingJob>>>());
        let mut driver = driver(budget.clone());
        driver.layer_mut().remaining = Some(1);
        let mut jobs = Jobs::new();
        assert!(jobs.take(&mut driver));
        assert_eq!(jobs.len(), 1);
        assert!(!jobs.budget_exhausted());
        assert!(!jobs.take(&mut driver));
        assert!(!jobs.budget_exhausted());
        assert_eq!(driver.layer().extracted, 1);
        let mut cx = Context::from_waker(Waker::noop());
        jobs.poll(None, &mut cx, |_| Ok::<_, Infallible>(()))
            .unwrap();
        assert_eq!(driver.layer().polls.load(Ordering::Relaxed), 1);
        driver.layer().owner.cancel();
        jobs.poll(None, &mut cx, |_| Ok::<_, Infallible>(()))
            .unwrap();
        assert!(jobs.is_empty());
        assert!(!jobs.take(&mut driver));
        assert!(!jobs.budget_exhausted());
        drop(jobs);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exhausted_job_storage_never_launches_work() {
        let mut driver = driver(Budget::new(0));
        let mut jobs = Jobs::new();
        assert!(!jobs.take(&mut driver));
        assert!(jobs.budget_exhausted());
        assert!(jobs.is_empty());
        assert!(!jobs.take(&mut driver));
        assert_eq!(driver.layer().extracted, 0);
        assert_eq!(driver.layer().polls.load(Ordering::Relaxed), 0);
        assert_eq!(driver.layer().drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn closing_work_cancels_its_tasks_while_sibling_work_continues() {
        fictionet::block_on(fictionet::lab(Seed::from_u64(13), |fcx| async move {
            let mut closing = driver(Budget::unlimited());
            let mut sibling = driver(Budget::unlimited());
            let (closing_start, closing_started) = tokio::sync::oneshot::channel();
            let (sibling_start, sibling_started) = tokio::sync::oneshot::channel();
            *closing.layer().start.lock() = Some(closing_start);
            *sibling.layer().start.lock() = Some(sibling_start);
            let mut jobs = Jobs::new();
            jobs.take(&mut closing);
            jobs.take(&mut sibling);
            std::future::poll_fn(|cx| {
                Poll::Ready(jobs.poll(Some(&fcx), cx, |_| Ok::<_, Infallible>(())))
            })
            .await
            .unwrap();
            // Establish that both child tasks entered before closing either owner.
            closing_started
                .await
                .expect("the closing owner's task started");
            sibling_started.await.expect("the sibling's task started");
            assert_eq!(closing.layer().tasks.load(Ordering::Relaxed), 1);
            assert_eq!(sibling.layer().tasks.load(Ordering::Relaxed), 1);
            let sibling_polls = sibling.layer().polls.load(Ordering::Relaxed);
            let closing_polls = closing.layer().polls.load(Ordering::Relaxed);
            closing.layer().owner.cancel();
            std::future::poll_fn(|cx| {
                jobs.poll(Some(&fcx), cx, |_| -> Result<(), Infallible> {
                    panic!("pending work must not complete")
                })
                .unwrap();
                if jobs.len() == INTAKE {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(closing.layer().stopped.load(Ordering::Relaxed), 1);
            assert_eq!(closing.layer().drops.load(Ordering::Relaxed), INTAKE);
            assert_eq!(closing.layer().polls.load(Ordering::Relaxed), closing_polls);
            assert_eq!(sibling.layer().stopped.load(Ordering::Relaxed), 0);
            assert!(sibling.layer().polls.load(Ordering::Relaxed) > sibling_polls);
            sibling.layer().owner.cancel();
            std::future::poll_fn(|cx| {
                jobs.poll(Some(&fcx), cx, |_| Ok::<_, Infallible>(()))
                    .unwrap();
                if jobs.is_empty() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(sibling.layer().stopped.load(Ordering::Relaxed), 1);
            Ok(())
        }))
        .expect("all owned tasks drain");
    }

    #[test]
    fn returned_work_keeps_its_producer_until_the_owner_closes() {
        fictionet::block_on(fictionet::lab(Seed::from_u64(14), |fcx| async move {
            let mut source = driver(Budget::unlimited());
            source.layer_mut().ready = true;
            let (start, started) = tokio::sync::oneshot::channel();
            *source.layer().start.lock() = Some(start);
            let returned = source.layer().returned.clone();
            let mut jobs = Jobs::new();
            jobs.take(&mut source);
            std::future::poll_fn(|cx| {
                Poll::Ready(jobs.poll(Some(&fcx), cx, |_| {
                    returned.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, Infallible>(())
                }))
            })
            .await
            .unwrap();
            started
                .await
                .expect("the returned response's producer runs");
            assert_eq!(returned.load(Ordering::Relaxed), INTAKE);
            assert_eq!(source.layer().tasks.load(Ordering::Relaxed), 1);
            assert_eq!(source.layer().stopped.load(Ordering::Relaxed), 0);
            assert_eq!(jobs.len(), 1);
            let polls = source.layer().polls.load(Ordering::Relaxed);
            std::future::poll_fn(|cx| {
                Poll::Ready(jobs.poll(Some(&fcx), cx, |_| -> Result<(), Infallible> {
                    panic!("a completed job cannot complete again")
                }))
            })
            .await
            .unwrap();
            assert_eq!(source.layer().polls.load(Ordering::Relaxed), polls);
            source.layer().owner.cancel();
            std::future::poll_fn(|cx| {
                jobs.poll(Some(&fcx), cx, |_| -> Result<(), Infallible> {
                    panic!("a cancelled job cannot complete")
                })
                .unwrap();
                if jobs.is_empty() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(source.layer().stopped.load(Ordering::Relaxed), 1);
            assert_eq!(source.layer().drops.load(Ordering::Relaxed), INTAKE);
            Ok(())
        }))
        .expect("the producer's lifetime follows its owner");
    }

    #[test]
    fn dropping_an_opened_stack_joins_its_tasks_in_the_enclosing_region() {
        use fictionet::stdlib::layer::{ByteStream, StreamCommand, StreamEvent};
        use fictionet::stdlib::network::{ConnError, Connection};
        struct ByteSource(Source);
        impl Layer for ByteSource {
            type Lower = ByteStream;
            type Upper = ByteStream;
            type Report = ();
            type Timer = ();
            type Work = OwnedWork<PendingJob>;
            type Done = ();
            type Error = ConnError;
            fn on_event(
                &mut self,
                _: &mut Env<'_, ()>,
                _: StreamEvent,
            ) -> Result<Admit<StreamEvent>, ConnError> {
                Ok(Admit::Taken)
            }
            fn on_command(
                &mut self,
                _: &mut Env<'_, ()>,
                command: StreamCommand,
            ) -> Result<Admit<StreamCommand>, ConnError> {
                Ok(Admit::Blocked(command))
            }
            fn take_event(&mut self) -> Option<StreamEvent> {
                None
            }
            fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
                None
            }
            fn take_work(&mut self) -> Option<Self::Work> {
                self.0.take_work()
            }
        }
        struct Waiting;
        impl Connection for Waiting {
            fn poll_read(
                &mut self,
                _: &Cx,
                _: &mut Context<'_>,
                _: &mut [u8],
            ) -> Poll<Result<usize, ConnError>> {
                Poll::Pending
            }
            fn poll_write(
                &mut self,
                _: &Cx,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<Result<usize, ConnError>> {
                Poll::Pending
            }
            fn poll_shutdown(
                &mut self,
                _: &Cx,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), ConnError>> {
                Poll::Pending
            }
        }
        fictionet::block_on(fictionet::lab(Seed::from_u64(15), |fcx| async move {
            let stopped = Arc::new(AtomicUsize::new(0));
            let count = stopped.clone();
            fcx.region(move |region| async move {
                let mut source = Source::new();
                source.stopped = count;
                let (start, started) = tokio::sync::oneshot::channel();
                *source.start.lock() = Some(start);
                let mut opened = super::super::Opened::new(
                    &region,
                    Waiting,
                    ByteSource(source),
                    Budget::unlimited(),
                );
                std::future::poll_fn(|cx| {
                    assert!(opened.poll_read(&region, cx, &mut [0; 1]).is_pending());
                    Poll::Ready(())
                })
                .await;
                started.await.expect("the stack's task entered");
                drop(opened);
                Ok(())
            })
            .await?;
            assert_eq!(stopped.load(Ordering::Relaxed), 1);
            Ok(())
        }))
        .expect("the enclosing region drains dropped stack work");
    }
}
