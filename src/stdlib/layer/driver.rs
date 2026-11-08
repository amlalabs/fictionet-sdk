use std::collections::VecDeque;
use std::sync::Arc;

use fictionet::Entropy;
use fictionet::stdlib::layer::{Admit, Budget, CommandOf, Env, EventOf, Layer, Observe};
use fictionet::time::Instant;

/// How many timers and internal steps one [`Driver::run`] takes at most.
const STEPS: usize = 1024;
/// How many reports a driver keeps before it counts instead.
const KEPT: usize = 1024;

/// A layer's reports, as many as there is room for, and a count of the
/// ones there was no room for. Reports never hold up the protocol.
#[derive(Debug)]
pub struct Observations<E> {
    kept: VecDeque<E>,
    limit: usize,
    omitted: u64,
}

impl<E> Observations<E> {
    /// Room for `limit` reports.
    pub fn new(limit: usize) -> Observations<E> {
        Observations {
            kept: VecDeque::new(),
            limit,
            omitted: 0,
        }
    }

    /// Takes the kept reports, oldest first, making room for more.
    pub fn drain(&mut self) -> impl Iterator<Item = E> + '_ {
        self.kept.drain(..)
    }

    /// The kept reports, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &E> + '_ {
        self.kept.iter()
    }

    /// How many reports came while there was no room.
    pub fn omitted(&self) -> u64 {
        self.omitted
    }
}

impl<E> Observe<E> for Observations<E> {
    fn observe(&mut self, event: E) {
        if self.kept.len() < self.limit {
            self.kept.push_back(event);
        } else {
            self.omitted += 1;
        }
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
    steps: usize,
}

impl<L: Layer> Driver<L> {
    /// Drives `layer` at time `now`, drawing from `entropy` and charging
    /// `budget`.
    pub fn new(layer: L, entropy: Arc<dyn Entropy>, budget: Budget, now: Instant) -> Driver<L> {
        Driver {
            layer,
            entropy,
            budget,
            now,
            observed: Observations::new(KEPT),
            below: None,
            above: None,
            steps: STEPS,
        }
    }

    /// Draws from `entropy` and reads `now` from here on, as a harness that
    /// joins a world does before anything runs.
    pub(super) fn rebind(&mut self, entropy: Arc<dyn Entropy>, now: Instant) {
        self.entropy = entropy;
        self.now = now;
    }

    /// Keeps at most `limit` reports from now on.
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
    /// after input or output has moved.
    pub fn run(&mut self) -> Result<bool, L::Error> {
        let mut moved = false;
        for _ in 0..self.steps {
            let mut env = Env::new(self.now, &*self.entropy, &self.budget, &mut self.observed);
            let due = self.layer.deadline().filter(|(at, _)| *at <= self.now);
            let step = match due {
                Some((_, timer)) => {
                    self.layer.on_timer(&mut env, timer)?;
                    true
                }
                None => self.layer.advance(&mut env)?,
            };
            if !step {
                break;
            }
            moved = true;
        }
        Ok(moved)
    }

    /// Offers the stack's output for the carrier below to `sink`, which
    /// takes what it can. Returns whether anything moved.
    pub fn send_below(
        &mut self,
        sink: impl FnMut(CommandOf<L::Lower>) -> Admit<CommandOf<L::Lower>>,
    ) -> bool {
        send(&mut self.below, || self.layer.take_command(), sink)
    }

    /// Offers the stack's output for what is above it to `sink`. Returns
    /// whether anything moved.
    pub fn send_above(
        &mut self,
        sink: impl FnMut(EventOf<L::Upper>) -> Admit<EventOf<L::Upper>>,
    ) -> bool {
        send(&mut self.above, || self.layer.take_event(), sink)
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
    loop {
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
}
