use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use fictionet::stdlib::layer::{Driver, Layer, Side, Worker};
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

    /// Moves the work on. `fcx` is the world's context, or `None` in a
    /// harness given none, where work that needs one finishes with its
    /// error.
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done>;
}

/// A composed layer's work: whichever part asked for it does it.
impl<A: Job, B: Job> Job for Side<A, B> {
    type Done = Side<A::Done, B::Done>;

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        match self {
            Side::Lower(a) => a.poll(fcx, cx).map(Side::Lower),
            Side::Upper(b) => b.poll(fcx, cx).map(Side::Upper),
        }
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
    running: Vec<W>,
}

impl<W: Job> Jobs<W> {
    pub(super) fn new() -> Jobs<W> {
        Jobs {
            running: Vec::new(),
        }
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
        while let Some(work) = driver.take_work() {
            self.running.push(work);
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
            match self.running[i].poll(fcx, cx) {
                Poll::Ready(result) => {
                    self.running.remove(i);
                    finished = true;
                    done(result)?;
                }
                Poll::Pending => i += 1,
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
