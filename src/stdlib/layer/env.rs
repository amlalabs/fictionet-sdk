use std::sync::Arc;
use std::task::Waker;

use fictionet::Entropy;
use fictionet::stdlib::layer::Budget;
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
pub struct Env<'a, E> {
    now: Instant,
    entropy: &'a dyn Entropy,
    budget: &'a Budget,
    observer: &'a mut dyn Observe<E>,
    /// The observer's interest, asked once: parts of the layer report
    /// through wrappers that only pass reports on.
    observing: bool,
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
    /// An environment for one call, outside any driver: its
    /// [`waker`](Self::waker) wakes nothing.
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
            wakes: Wakes::Nothing,
        }
    }

    /// The same environment, in a driver whose stack `stack` wakes.
    pub(super) fn in_stack(self, stack: &'a Arc<StackWake>) -> Env<'a, E> {
        Env {
            wakes: Wakes::Stack(stack),
            ..self
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

    /// Runs `body` with an environment for a part of this layer, whose
    /// reports `wrap` turns into this layer's.
    pub fn scoped<P, R>(
        &mut self,
        wrap: impl FnMut(P) -> E,
        body: impl FnOnce(&mut Env<'_, P>) -> R,
    ) -> R {
        self.scoped_in(self.budget, wrap, body)
    }

    /// Runs a child in its own budget while preserving time, entropy and
    /// report ownership. The parent still accounts for its routing state.
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
