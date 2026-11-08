use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use fictionet::stdlib::layer::{Charge, ChildId, Driver, Layer, OwnedWork, Side, Worker};
use fictionet::time::Instant;
use fictionet::{Cx, Entropy};

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
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done>;
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
pub(super) struct Jobs<W> {
    running: Vec<Running<W>>,
    storage: Option<Charge>,
    budget_failed: bool,
}

// The job count and intake are engine limits, independent of carrier credit.
const JOBS: usize = 64;
const INTAKE: usize = 8;

struct Running<W> {
    work: Option<W>,
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
    pub(super) fn new() -> Jobs<W> {
        Jobs {
            running: Vec::new(),
            storage: None,
            budget_failed: false,
        }
    }

    pub(super) fn budget_exhausted(&self) -> bool {
        self.budget_failed
    }

    pub(super) fn len(&self) -> usize {
        self.running.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    /// Takes the stack's new work from `driver`. Returns whether there was
    /// any.
    pub(super) fn take<L: Layer<Work = W>>(&mut self, driver: &mut Driver<L>) -> bool {
        let mut took = false;
        for _ in 0..INTAKE {
            if self.running.len() == JOBS || self.budget_failed {
                break;
            }
            let Some(work) = driver.take_work() else {
                break;
            };
            if self.storage.is_none() {
                let Some(charge) = driver
                    .budget()
                    .charge(JOBS * std::mem::size_of::<Running<W>>())
                else {
                    self.budget_failed = true;
                    break;
                };
                self.running = Vec::with_capacity(JOBS);
                self.storage = Some(charge);
            }
            self.running.push(Running {
                work: Some(work),
                region: None,
            });
            took = true;
        }
        took
    }

    /// Polls every piece of work once, oldest first, and hands each result
    /// to `done` as it comes. Returns whether any finished.
    pub(super) fn poll<E>(
        &mut self,
        fcx: Option<&Cx>,
        cx: &mut Context<'_>,
        mut done: impl FnMut(W::Done) -> Result<(), E>,
    ) -> Result<bool, E> {
        let mut finished = false;
        let mut i = 0;
        while i < self.running.len() {
            let running = &mut self.running[i];
            if running.work.as_ref().is_some_and(Job::cancelled) {
                running.work = None;
                if let Some(region) = &running.region {
                    region.cancel();
                }
                finished = true;
            }
            if running.work.is_some() && running.region.is_none() {
                running.region = fcx.map(|parent| Cx {
                    run: parent.run.clone(),
                    region: parent.region.child(),
                });
            }
            if let Some(work) = &mut running.work {
                if let Poll::Ready(result) = work.poll(running.region.as_ref(), cx) {
                    running.work = None;
                    if let Some(region) = &running.region {
                        region.cancel();
                    }
                    finished = true;
                    done(result)?;
                }
            }
            let drained = running.work.is_none()
                && running
                    .region
                    .as_ref()
                    .is_none_or(|region| region.region.poll_done(cx).is_ready());
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

    struct PendingJob {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }
    impl Job for PendingJob {
        type Done = ();
        fn poll(&mut self, _: Option<&Cx>, _: &mut Context<'_>) -> Poll<()> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Poll::Pending
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
        extracted: usize,
    }
    impl Source {
        fn new() -> Self {
            Self {
                owner: WorkOwner::new(),
                polls: Arc::default(),
                drops: Arc::default(),
                extracted: 0,
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
        fn take_command(&mut self) -> Option<Infallible> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn take_work(&mut self) -> Option<Self::Work> {
            self.extracted += 1;
            Some(self.owner.own(PendingJob {
                polls: self.polls.clone(),
                drops: self.drops.clone(),
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
    fn exhausted_job_storage_never_launches_work() {
        let mut driver = driver(Budget::new(0));
        let mut jobs = Jobs::new();
        assert!(!jobs.take(&mut driver));
        assert!(jobs.budget_exhausted());
        assert!(jobs.is_empty());
        assert!(!jobs.take(&mut driver));
        assert_eq!(driver.layer().extracted, 1);
        assert_eq!(driver.layer().polls.load(Ordering::Relaxed), 0);
        assert_eq!(driver.layer().drops.load(Ordering::Relaxed), 1);
    }
}
