use std::collections::VecDeque;
use std::sync::Arc;

use fictionet::Entropy;
use fictionet::stdlib::layer::{Admit, Budget, Charge, CommandOf, Env, EventOf, Layer, Observe};
use fictionet::time::Instant;

/// How many timers and internal steps one [`Driver::run`] takes at most.
const STEPS: usize = 1024;
/// How many reports a driver keeps before it counts instead.
const KEPT: usize = 1024;

/// A layer's reports, as many as there is room for, and a count of the
/// ones there was no room for. Reports never hold up the protocol.
#[derive(Debug)]
pub struct Observations<E> {
    kept: VecDeque<(E, Charge)>,
    budget: Budget,
    storage: Option<Charge>,
    heap_bytes: fn(&E) -> Option<usize>,
    limit: usize,
    omitted: u64,
}

impl<E> Observations<E> {
    /// An empty store with an item limit. Unmeasured reports are omitted;
    /// use [`bounded`](Self::bounded) to supply their allocation bound.
    pub fn new(limit: usize) -> Observations<E> {
        Observations {
            kept: VecDeque::new(),
            budget: Budget::new(256 * 1024),
            storage: None,
            heap_bytes: |_| None,
            limit,
            omitted: 0,
        }
    }

    /// Bound report retention with a separate byte budget and an allocation
    /// size function. The function must include all retained backing storage.
    pub fn bounded(limit: usize, bytes: usize, heap_bytes: fn(&E) -> Option<usize>) -> Self {
        Self {
            budget: Budget::new(bytes),
            heap_bytes,
            ..Self::new(limit)
        }
    }

    /// Bytes reserved for report slots and retained payloads.
    pub fn used(&self) -> usize {
        self.budget.used()
    }

    /// Takes the kept reports, oldest first, making room for more.
    pub fn drain(&mut self) -> impl Iterator<Item = E> + '_ {
        self.kept.drain(..).map(|(event, _charge)| event)
    }

    /// The kept reports, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &E> + '_ {
        self.kept.iter().map(|(event, _)| event)
    }

    /// How many reports came while there was no room.
    pub fn omitted(&self) -> u64 {
        self.omitted
    }
}

impl<E> Observations<E> {
    /// Makes room for one more kept report: doubles the slots up to the
    /// limit, or adds one when the budget has no room to double. Whatever
    /// the event itself retains is already charged, so growth never takes
    /// the room it needs. Nothing changes when no slot fits.
    fn grow(&mut self) -> bool {
        let len = self.kept.len();
        if len < self.kept.capacity() {
            return true;
        }
        let slot = std::mem::size_of::<(E, Charge)>();
        let doubled = len.saturating_mul(2).max(1).min(self.limit);
        let reserved = [doubled, len + 1].into_iter().find(|&slots| {
            let Some(wanted) = slots.checked_mul(slot) else {
                return false;
            };
            match &mut self.storage {
                Some(charge) => charge.set(wanted),
                None => {
                    self.storage = self.budget.charge(wanted);
                    self.storage.is_some()
                }
            }
        });
        let Some(slots) = reserved else {
            return false;
        };
        self.kept.reserve_exact(slots - len);
        true
    }
}

impl<E> Observe<E> for Observations<E> {
    fn observe(&mut self, event: E) {
        if self.kept.len() < self.limit
            && let Some(bytes) = (self.heap_bytes)(&event)
            && let Some(charge) = self.budget.charge(bytes)
            && self.grow()
        {
            self.kept.push_back((event, charge));
            return;
        }
        self.omitted = self.omitted.saturating_add(1);
    }

    /// A store that keeps no reports wants none made, so none is counted
    /// in [`omitted`](Self::omitted) either.
    fn interested(&self) -> bool {
        self.limit > 0
    }
}

/// Runs one stack, with no I/O: whatever owns the carrier offers it input
/// and takes its output, and the driver does the rest.
///
/// [`run`](Self::run) fires due timers before anything else, then advances
/// the stack, a bounded number of steps at a time. The driver holds at most
/// one item of output each way that the carrier has not taken, with its
/// cursor if the carrier took part of it; the layer keeps the rest. Input
/// the stack refuses goes back to the caller, who still owns it.
///
/// The live runtime and [`Harness`](super::Harness) both drive stacks with
/// this.
pub struct Driver<L: Layer> {
    layer: L,
    entropy: Arc<dyn Entropy>,
    budget: Budget,
    now: Instant,
    observed: Observations<L::Report>,
    below: Option<CommandOf<L::Lower>>,
    above: Option<EventOf<L::Upper>>,
    /// An urgent event that went past the refused one above, refused too.
    urgent: Option<EventOf<L::Upper>>,
    steps: usize,
    exhausted: bool,
}

impl<L: Layer> Driver<L> {
    /// Drives `layer` at time `now`, drawing from `entropy` and charging
    /// `budget`.
    ///
    /// The composition's depth is checked here and wherever it grows: when
    /// a stack is boxed, and, against the depth left where the new part
    /// sits ([`Env::fits_below`]), when a later layer is set, when a switch
    /// hands over and when a child is made. No call walks the stack for it.
    pub fn new(layer: L, entropy: Arc<dyn Entropy>, budget: Budget, now: Instant) -> Driver<L> {
        assert!(layer.depth() <= super::MAX_DEPTH, "composition is too deep");
        Driver {
            layer,
            entropy,
            budget,
            now,
            observed: Observations {
                heap_bytes: L::report_bytes,
                ..Observations::new(KEPT)
            },
            below: None,
            above: None,
            urgent: None,
            steps: STEPS,
            exhausted: false,
        }
    }

    /// Draws from `entropy` and reads `now` from here on, as a harness that
    /// joins a world does before anything runs.
    pub(super) fn rebind(&mut self, entropy: Arc<dyn Entropy>, now: Instant) {
        self.entropy = entropy;
        self.now = now;
    }

    /// Keeps at most `limit` reports from now on. With none kept, the stack
    /// makes none ([`Env::observing`]).
    pub fn keep_observations(&mut self, limit: usize) {
        self.observed.limit = limit;
    }

    /// The stack.
    pub fn layer(&self) -> &L {
        &self.layer
    }

    /// The stack, to change from outside, as a test does.
    pub fn layer_mut(&mut self) -> &mut L {
        &mut self.layer
    }

    /// The time the driver last read.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Moves the time forward to `now`. Time never goes back.
    pub fn set_now(&mut self, now: Instant) {
        self.now = self.now.max(now);
    }

    /// The budget the stack is charged to.
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// The stack's reports.
    pub fn observations(&mut self) -> &mut Observations<L::Report> {
        &mut self.observed
    }

    /// Offers the stack an event from the carrier below.
    pub fn deliver(
        &mut self,
        event: EventOf<L::Lower>,
    ) -> Result<Admit<EventOf<L::Lower>>, L::Error> {
        let mut env = Env::new(self.now, &*self.entropy, &self.budget, &mut self.observed);
        self.layer.on_event(&mut env, event)
    }

    /// Offers the stack a command from above.
    pub fn command(
        &mut self,
        command: CommandOf<L::Upper>,
    ) -> Result<Admit<CommandOf<L::Upper>>, L::Error> {
        let mut env = Env::new(self.now, &*self.entropy, &self.budget, &mut self.observed);
        self.layer.on_command(&mut env, command)
    }

    /// Gives the stack the result of work it asked for.
    pub fn complete(&mut self, done: L::Done) -> Result<(), L::Error> {
        let mut env = Env::new(self.now, &*self.entropy, &self.budget, &mut self.observed);
        self.layer.on_done(&mut env, done)
    }

    /// Fires due timers and advances the stack until nothing moves or the
    /// step limit is reached. Returns whether anything moved; call it again
    /// after input or output has moved, or whenever [`exhausted`](Self::exhausted) is true.
    pub fn run(&mut self) -> Result<bool, L::Error> {
        self.exhausted = true;
        let mut moved = false;
        for _ in 0..self.steps {
            let mut env = Env::new(self.now, &*self.entropy, &self.budget, &mut self.observed);
            let due = self.layer.deadline().filter(|(at, _)| *at <= self.now);
            let mut step = false;
            if let Some((_, timer)) = due {
                self.layer.on_timer(&mut env, timer)?;
                step = true;
            }
            step |= self.layer.advance(&mut env)?;
            if !step {
                self.exhausted = false;
                break;
            }
            moved = true;
        }
        Ok(moved)
    }

    /// Whether the last run used its whole allowance and needs another visit.
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Offers the stack's output for the carrier below to `sink`, which
    /// takes what it can. Returns whether anything moved.
    pub fn send_below(
        &mut self,
        sink: impl FnMut(CommandOf<L::Lower>) -> Admit<CommandOf<L::Lower>>,
    ) -> bool {
        let mut env = Env::new(self.now, &*self.entropy, &self.budget, &mut self.observed);
        send(&mut self.below, || self.layer.take_command(&mut env), sink)
    }

    /// Takes the next command, transferring its ownership and reservation to
    /// the caller. A previously refused command is returned first.
    pub fn take_command(&mut self) -> Option<CommandOf<L::Lower>> {
        self.below.take().or_else(|| {
            let mut env = Env::new(self.now, &*self.entropy, &self.budget, &mut self.observed);
            self.layer.take_command(&mut env)
        })
    }

    /// Offers the stack's output for what is above it to `sink`. While the
    /// sink refuses an event, the stack's urgent events
    /// ([`Layer::take_urgent`]) still go to it. Returns whether anything
    /// moved.
    pub fn send_above(
        &mut self,
        mut sink: impl FnMut(EventOf<L::Upper>) -> Admit<EventOf<L::Upper>>,
    ) -> bool {
        let mut moved = false;
        if let Some(event) = self.urgent.take() {
            match sink(event) {
                Admit::Taken | Admit::Closed(_) => moved = true,
                Admit::Partial(event) | Admit::Blocked(event) => {
                    self.urgent = Some(event);
                    return false;
                }
            }
        }
        moved |= send(&mut self.above, || self.layer.take_event(), &mut sink);
        for _ in 0..STEPS {
            if self.above.is_none() {
                break;
            }
            let Some(event) = self.layer.take_urgent() else {
                break;
            };
            moved = true;
            if let Admit::Partial(event) | Admit::Blocked(event) = sink(event) {
                self.urgent = Some(event);
                break;
            }
        }
        moved
    }

    /// Whether the driver holds output the carrier below has not taken.
    pub fn holds_output(&self) -> bool {
        self.below.is_some()
    }

    /// The next piece of work the stack asks for.
    pub fn take_work(&mut self) -> Option<L::Work> {
        self.layer.take_work()
    }

    /// When the stack next needs time.
    pub fn deadline(&self) -> Option<Instant> {
        self.layer.deadline().map(|(at, _)| at)
    }
}

/// Moves output from `next` through `held` into `sink` until the sink
/// stops taking or there is no more. What the sink hands back stays held.
fn send<T>(
    held: &mut Option<T>,
    mut next: impl FnMut() -> Option<T>,
    mut sink: impl FnMut(T) -> Admit<T>,
) -> bool {
    let mut moved = false;
    for _ in 0..STEPS {
        let item = match held.take() {
            Some(item) => item,
            None => match next() {
                Some(item) => {
                    moved = true;
                    item
                }
                None => return moved,
            },
        };
        match sink(item) {
            // A closed carrier will never take it.
            Admit::Taken | Admit::Closed(_) => moved = true,
            Admit::Partial(rest) => {
                *held = Some(rest);
                return true;
            }
            Admit::Blocked(item) => {
                *held = Some(item);
                return moved;
            }
        }
    }
    moved
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::layer::{Port, Top};
    use crate::{Seed, SeededEntropy};
    use std::convert::Infallible;

    struct Units;
    impl Port for Units {
        type Event = ();
        type Command = ();
    }
    struct Productive {
        timers: usize,
        advances: usize,
    }
    impl Layer for Productive {
        type Lower = Units;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn on_event(&mut self, _: &mut Env<'_, ()>, _: ()) -> Result<Admit<()>, Infallible> {
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn on_timer(&mut self, _: &mut Env<'_, ()>, _: ()) -> Result<(), Infallible> {
            self.timers += 1;
            Ok(())
        }
        fn advance(&mut self, _: &mut Env<'_, ()>) -> Result<bool, Infallible> {
            self.advances += 1;
            Ok(true)
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<()> {
            Some(())
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn deadline(&self) -> Option<(Instant, ())> {
            Some((Instant::ZERO, ()))
        }
    }

    #[test]
    fn retention_leaves_room_for_the_event_before_growing() {
        let slot = std::mem::size_of::<(Vec<u8>, Charge)>();
        let mut reports = Observations::bounded(16, slot * 2, |v: &Vec<u8>| Some(v.capacity()));
        reports.observe(vec![0; slot]);
        assert_eq!(reports.iter().count(), 1);
        assert_eq!(reports.omitted(), 0);
        let used = reports.used();
        reports.observe(vec![0; slot * 2]);
        assert_eq!(reports.used(), used);
        assert_eq!(reports.omitted(), 1);
        drop(reports.drain().collect::<Vec<_>>());
        reports.observe(vec![0; slot]);
        assert_eq!(reports.iter().count(), 1);
    }

    #[test]
    fn reports_for_a_store_that_keeps_none_are_never_wrapped() {
        let entropy = SeededEntropy::new(Seed::from_u64(0));
        let budget = Budget::unlimited();
        let mut wrapped = 0;
        let mut none = Observations::bounded(0, 1024, |_: &u32| Some(0));
        Env::new(Instant::ZERO, &entropy, &budget, &mut none).scoped(
            |report: u8| {
                wrapped += 1;
                u32::from(report)
            },
            |env| env.report(1),
        );
        assert_eq!(wrapped, 0);
        assert_eq!((none.iter().count(), none.omitted()), (0, 0));
        let mut one = Observations::bounded(1, 1024, |_: &u32| Some(0));
        Env::new(Instant::ZERO, &entropy, &budget, &mut one).scoped(
            |report: u8| {
                wrapped += 1;
                u32::from(report)
            },
            |env| env.report(7),
        );
        assert_eq!(wrapped, 1);
        assert_eq!(one.iter().copied().collect::<Vec<_>>(), [7]);
    }

    #[test]
    fn report_retention_counts_backing_capacity_and_omits_unknown_sizes() {
        let mut reports = Observations::bounded(2, 512, |bytes: &Vec<u8>| Some(bytes.capacity()));
        let mut oversized = Vec::with_capacity(4096);
        oversized.push(1);
        reports.observe(oversized);
        assert_eq!(reports.iter().count(), 0);
        assert_eq!(reports.omitted(), 1);
        reports.observe(vec![1, 2]);
        assert_eq!(reports.iter().count(), 1);
        assert!(reports.used() <= 512);
        let held = reports.used();
        drop(reports.drain().collect::<Vec<_>>());
        assert!(reports.used() < held);
        let mut unknown = Observations::new(2);
        unknown.observe(vec![1]);
        assert_eq!(unknown.iter().count(), 0);
        assert_eq!(unknown.omitted(), 1);
    }

    #[test]
    fn erased_composition_cannot_hide_unbounded_depth() {
        use crate::stdlib::services::stack::Boxed;
        let mut stack = Boxed::new(Productive {
            timers: 0,
            advances: 0,
        });
        while stack.depth() < crate::stdlib::layer::MAX_DEPTH {
            stack = Boxed::new(stack);
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Boxed::new(stack))).is_err()
        );
    }

    #[test]
    fn continuous_output_and_timers_yield_without_starving_advance() {
        let mut driver = Driver::new(
            Productive {
                timers: 0,
                advances: 0,
            },
            Arc::new(SeededEntropy::new(Seed::from_u64(0))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        assert!(driver.run().unwrap());
        assert!(driver.exhausted());
        assert!(driver.layer().timers > 0);
        assert!(driver.layer().advances > 0);
        assert!(driver.layer().timers + driver.layer().advances <= STEPS * 2);
        let mut accepted = 0;
        assert!(driver.send_below(|()| {
            accepted += 1;
            Admit::Taken
        }));
        assert!(accepted > 0 && accepted <= STEPS);
        assert!(driver.run().unwrap());
        assert!(driver.layer().advances > STEPS);
    }
}
