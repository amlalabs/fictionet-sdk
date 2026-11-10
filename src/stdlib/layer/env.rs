use std::sync::Arc;
use std::task::Waker;

use fictionet::Entropy;
use fictionet::stdlib::layer::{Budget, Layer, MAX_DEPTH};
use fictionet::time::Instant;

use super::children::ChildWake;
use super::driver::StackWake;

/// Somewhere a layer's reports go. The driver keeps a bounded number of
/// them and counts the ones it had no room for ([`Observations`]).
///
/// [`Observations`]: super::Observations
pub trait Observe<E> {
    /// Takes one report. Never refuses: a full store drops it and counts.
    fn observe(&mut self, event: E);

    /// Whether this store keeps reports at all. One that keeps none says
    /// so, and its reports are then never made: [`Env::report`] drops them
    /// before any wrapping, and a layer can ask [`Env::observing`] before
    /// building one.
    fn interested(&self) -> bool {
        true
    }
}

/// What a layer may use during one call: the time, the entropy source, the
/// connection's budget, somewhere to report, and a way to be called again.
///
/// Each value comes from the driver. A layer never reads a clock or the
/// operating system's randomness itself, so the same inputs in the same
/// order give the same run.
///
/// An environment also knows how deep the layer it is for may be, so a
/// composition that grows while it runs, as a switch that hands over or a
/// router that makes a child, can check the new part against what is left
/// of [`MAX_DEPTH`] where it sits ([`fits_below`](Self::fits_below)).
pub struct Env<'a, E> {
    now: Instant,
    entropy: &'a dyn Entropy,
    budget: &'a Budget,
    observer: &'a mut dyn Observe<E>,
    /// The observer's interest, asked once: parts of the layer report
    /// through wrappers that only pass reports on.
    observing: bool,
    /// The most nested layer calls the layer called with this environment
    /// may make, its own included.
    room: usize,
    wakes: Wakes<'a>,
}

/// Who a layer's [`Env::waker`] wakes: the driver of the stack, and on the
/// way each [`Children`](super::Children) the layer runs inside.
#[derive(Clone, Copy)]
enum Wakes<'a> {
    /// An environment made outside a driver: nothing runs the layer again.
    Nothing,
    /// The driver, which wakes whatever runs the stack.
    Stack(&'a Arc<StackWake>),
    /// A child, which queues itself for a visit and wakes what it runs in.
    Child(&'a Arc<ChildWake>, &'a Wakes<'a>),
}

impl Wakes<'_> {
    fn waker(&self) -> Waker {
        match self {
            Wakes::Nothing => Waker::noop().clone(),
            Wakes::Stack(stack) => Waker::from(Arc::clone(stack)),
            Wakes::Child(child, around) => child.waker_in(around.waker()),
        }
    }
}

impl<'a, E> Env<'a, E> {
    /// An environment for one call to the top of a stack, which may be
    /// [`MAX_DEPTH`] deep, outside any driver: its [`waker`](Self::waker)
    /// wakes nothing.
    pub fn new(
        now: Instant,
        entropy: &'a dyn Entropy,
        budget: &'a Budget,
        observer: &'a mut dyn Observe<E>,
    ) -> Env<'a, E> {
        Env {
            now,
            entropy,
            budget,
            observing: observer.interested(),
            observer,
            room: MAX_DEPTH,
            wakes: Wakes::Nothing,
        }
    }

    /// Whether `part` may run one level below the layer this environment
    /// is for: whether its [`depth`](Layer::depth) fits in what is left of
    /// [`MAX_DEPTH`] below this layer. A layer that adds a part while it
    /// runs checks the part with this before it keeps it.
    pub fn fits_below(&self, part: &impl Layer) -> bool {
        part.depth() < self.room
    }

    /// An environment for one call to the top of a stack that a driver
    /// runs, whose [`waker`](Self::waker) wakes `stack`.
    pub(super) fn in_stack(
        now: Instant,
        entropy: &'a dyn Entropy,
        budget: &'a Budget,
        observer: &'a mut dyn Observe<E>,
        stack: &'a Arc<StackWake>,
    ) -> Env<'a, E> {
        Env {
            now,
            entropy,
            budget,
            observing: observer.interested(),
            observer,
            room: MAX_DEPTH,
            wakes: Wakes::Stack(stack),
        }
    }

    /// Gets this layer called again: for state that changes outside the
    /// layer's calls, such as a request another task makes. Waking it
    /// wakes whatever runs the stack, which then runs it
    /// ([`Driver::run`](super::Driver::run)), and a child of
    /// [`Children`](super::Children) is visited in that run. The waker
    /// stays good for as long as the layer runs in this stack, so a layer
    /// may keep the first one it gets.
    pub fn waker(&self) -> Waker {
        self.wakes.waker()
    }

    /// The run's time, read by the driver before this call.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// The run's entropy. Every draw comes from the same stream, in the
    /// order the calls make them.
    pub fn entropy(&self) -> &dyn Entropy {
        self.entropy
    }

    /// The connection's budget. Charge before allocating.
    pub fn budget(&self) -> &Budget {
        self.budget
    }

    /// Whether anything keeps this call's reports. A report that costs
    /// work to build can be skipped when nothing does.
    pub fn observing(&self) -> bool {
        self.observing
    }

    /// Reports `report`, unless nothing keeps reports.
    pub fn report(&mut self, report: E) {
        if self.observing {
            self.observer.observe(report);
        }
    }

    /// Runs `body` with an environment for a part of this layer, one level
    /// below it, that reports as this layer does. A layer that counts
    /// itself in its [`depth`](Layer::depth) calls its parts through this
    /// or [`scoped`](Self::scoped).
    pub fn part<R>(&mut self, body: impl FnOnce(&mut Env<'_, E>) -> R) -> R {
        // The part shares everything with this layer but the depth left,
        // so it borrows this environment rather than a copy of it.
        let room = self.room;
        self.room = room.saturating_sub(1);
        let result = body(self);
        self.room = room;
        result
    }

    /// Runs `body` with an environment for a part of this layer, one level
    /// below it, whose reports `wrap` turns into this layer's.
    pub fn scoped<P, R>(
        &mut self,
        wrap: impl FnMut(P) -> E,
        body: impl FnOnce(&mut Env<'_, P>) -> R,
    ) -> R {
        self.scoped_in(self.budget, wrap, body)
    }

    /// Runs a child, one level below this layer, in its own budget while
    /// preserving time, entropy and report ownership. The parent still
    /// accounts for its routing state.
    pub fn scoped_in<P, R>(
        &mut self,
        budget: &Budget,
        wrap: impl FnMut(P) -> E,
        body: impl FnOnce(&mut Env<'_, P>) -> R,
    ) -> R {
        let wakes = self.wakes;
        self.scope(budget, wakes, wrap, body)
    }

    /// Runs a call into a child of [`Children`](super::Children), as
    /// [`scoped_in`](Self::scoped_in) does, with a [`waker`](Self::waker)
    /// that gets the child visited.
    pub(super) fn scoped_child<P, R>(
        &mut self,
        budget: &Budget,
        child: &Arc<ChildWake>,
        wrap: impl FnMut(P) -> E,
        body: impl FnOnce(&mut Env<'_, P>) -> R,
    ) -> R {
        let around = self.wakes;
        self.scope(budget, Wakes::Child(child, &around), wrap, body)
    }

    fn scope<P, R>(
        &mut self,
        budget: &Budget,
        wakes: Wakes<'_>,
        wrap: impl FnMut(P) -> E,
        body: impl FnOnce(&mut Env<'_, P>) -> R,
    ) -> R {
        let mut wrapped = Wrapped {
            inner: &mut *self.observer,
            wrap,
        };
        let mut env = Env {
            now: self.now,
            entropy: self.entropy,
            budget,
            observer: &mut wrapped,
            observing: self.observing,
            room: self.room.saturating_sub(1),
            wakes,
        };
        body(&mut env)
    }
}

struct Wrapped<'b, E, F> {
    inner: &'b mut dyn Observe<E>,
    wrap: F,
}

impl<E, P, F: FnMut(P) -> E> Observe<P> for Wrapped<'_, E, F> {
    fn observe(&mut self, event: P) {
        self.inner.observe((self.wrap)(event));
    }

    fn interested(&self) -> bool {
        self.inner.interested()
    }
}
