use fictionet::Entropy;
use fictionet::stdlib::layer::Budget;
use fictionet::time::Instant;

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
/// connection's budget, and somewhere to report.
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
}

impl<'a, E> Env<'a, E> {
    /// An environment for one call.
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
        }
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
