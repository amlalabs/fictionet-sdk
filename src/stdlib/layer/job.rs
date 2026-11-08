use std::convert::Infallible;
use std::task::{Context, Poll};

use fictionet::Cx;
use fictionet::stdlib::layer::Side;

/// Work a layer asks the world to do ([`Layer::Work`](super::Layer::Work)),
/// as whatever runs the stack does it: a handler's async answer, the next
/// frame of a streamed body, code that takes over a connection.
///
/// A layer never polls anything. It hands its work over in
/// [`take_work`](super::Layer::take_work); the runner polls the work here
/// with the world's context and gives the result back through
/// [`on_done`](super::Layer::on_done). Work carries what it needs and
/// brings back what the layer needs, such as a body it borrowed, so the
/// layer can tell a stale result by a generation it put in.
///
/// [`run`](super::live::run) does this over a live connection, and
/// [`Harness::running_work`](super::Harness::running_work) without one.
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

    pub(super) fn push(&mut self, work: W) {
        self.running.push(work);
    }

    pub(super) fn len(&self) -> usize {
        self.running.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.running.is_empty()
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
