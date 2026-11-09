use std::collections::VecDeque;

use fictionet::stdlib::layer::{
    Admit, CommandOf, Env, EventOf, Layer, OwnedWork, Port, Side, WorkOwner,
};
use fictionet::time::Instant;

/// A layer that can reach a protocol boundary after which something else
/// runs on its carrier: a successful CONNECT, a WebSocket upgrade,
/// STARTTLS.
///
/// At the boundary the layer stops taking input it would decode under the
/// wrong protocol. It keeps the input it already took past the boundary,
/// and the commands it took but did not use. Once its last output (the
/// CONNECT response, the STARTTLS go-ahead) has been handed below,
/// [`handover`](Self::handover) gives all of that up, with the typed choice
/// of what comes next.
pub trait Handoff: Layer {
    /// What may come next: the successors this protocol can negotiate,
    /// with what was negotiated for them.
    type Next;

    /// The handover, once the boundary is reached and every output before
    /// it has been handed over; until then `None`. After it returns `Some`
    /// the layer is finished and is dropped.
    ///
    /// What the successor reads of it is the successor's choice
    /// ([`Successor::inherits`]): the successor of STARTTLS reads none of
    /// the plaintext a client pipelined after its request, however the
    /// old layer hands it over.
    fn handover(&mut self) -> Option<Handover<Self::Next, Self::Lower, Self::Upper>>;
}

/// A layer that can run after a [`Handoff`] layer whose
/// [`Next`](Handoff::Next) is `N`, in a [`Switch`].
pub trait Successor<N>: Layer + Sized {
    /// The successor made from what the old protocol negotiated.
    fn succeed(next: N) -> Self;

    /// Whether the successor reads `event`, which came from below before
    /// it took over, under the old protocol. The switch drops each event it
    /// does not read: what the old layer handed over, and what the old
    /// layer refused and the layer below still holds. By default it reads
    /// every one, as a tunnel after CONNECT reads the bytes the client sent
    /// behind its request.
    ///
    /// TLS after STARTTLS reads no data that came before it. Events it
    /// declines must come from below in one order, as data on a byte
    /// stream does. Write completions are counted apart from the data, so
    /// a successor reads them; the old layer hands over only once its
    /// writes are complete, so none of its own are left.
    fn inherits(event: &EventOf<Self::Lower>) -> bool {
        let _ = event;
        true
    }
}

/// What a finished layer hands its successor.
pub struct Handover<N, L: Port, U: Port> {
    /// What comes next, as the old protocol negotiated it.
    pub next: N,
    /// Events from below that the old layer took and did not use, in
    /// order: the successor's first input.
    pub below: Vec<EventOf<L>>,
    /// Commands from above that the old layer took and did not use, in
    /// order.
    pub above: Vec<CommandOf<U>>,
}

enum Phase<A, B> {
    First(A),
    Then(B),
}

/// `A` until it hands over, then the `B` made from what it negotiated: the
/// typed choice at a protocol boundary.
///
/// `B` is often an enum of the successors `A` may negotiate, such as a
/// tunnel or a WebSocket. Both have the same ports, so what is above and
/// below the switch does not change: a CONNECT inside TLS replaces the HTTP
/// layer, not TLS.
///
/// The switch moves the handover's leftovers to `B` once each, before
/// anything newer, and drops `A` with its timers and work. A timer or a
/// result of `A`'s that arrives after the switch is ignored. Events from
/// below that came before the switch and that `B` does not
/// [inherit](Successor::inherits) never reach it, whether `A` handed them
/// over or refused them.
pub struct Switch<A, B>
where
    A: Handoff,
    B: Successor<A::Next, Lower = A::Lower, Upper = A::Upper>,
{
    phase: Phase<A, B>,
    owner: WorkOwner,
    below: VecDeque<EventOf<A::Lower>>,
    above: VecDeque<CommandOf<A::Upper>>,
    /// The layer below holds an event from before the switch that `A`
    /// refused and `B` does not inherit. It offers that event again before
    /// any newer one.
    owed: bool,
}

impl<A, B> Switch<A, B>
where
    A: Handoff,
    B: Successor<A::Next, Lower = A::Lower, Upper = A::Upper>,
{
    /// Starts with `first`.
    pub fn new(first: A) -> Switch<A, B> {
        assert!(first.depth() < super::MAX_DEPTH, "composition is too deep");
        Switch {
            owner: WorkOwner::new(),
            phase: Phase::First(first),
            below: VecDeque::new(),
            above: VecDeque::new(),
            owed: false,
        }
    }

    /// The first layer, while it runs.
    pub fn first(&self) -> Option<&A> {
        match &self.phase {
            Phase::First(a) => Some(a),
            Phase::Then(_) => None,
        }
    }

    /// The successor, once it runs.
    pub fn then(&self) -> Option<&B> {
        match &self.phase {
            Phase::First(_) => None,
            Phase::Then(b) => Some(b),
        }
    }
}

/// Offers the first of `queue` to the successor. Returns whether anything
/// moved.
fn feed<T>(queue: &mut VecDeque<T>, admit: Admit<T>) -> bool {
    match admit {
        Admit::Taken | Admit::Closed(_) => true,
        Admit::Partial(rest) => {
            queue.push_front(rest);
            true
        }
        Admit::Blocked(item) => {
            queue.push_front(item);
            false
        }
    }
}

impl<A, B> Layer for Switch<A, B>
where
    A: Handoff,
    B: Successor<A::Next, Lower = A::Lower, Upper = A::Upper>,
{
    type Lower = A::Lower;
    type Upper = A::Upper;
    type Report = Side<A::Report, B::Report>;
    type Timer = Side<A::Timer, B::Timer>;
    type Work = OwnedWork<Side<A::Work, B::Work>>;
    type Done = Side<A::Done, B::Done>;
    type Error = Side<A::Error, B::Error>;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: EventOf<A::Lower>,
    ) -> Result<Admit<EventOf<A::Lower>>, Self::Error> {
        match &mut self.phase {
            Phase::First(a) => {
                let declined = !B::inherits(&event);
                let admit = env
                    .scoped(Side::Lower, |env| a.on_event(env, event))
                    .map_err(Side::Lower)?;
                if declined {
                    self.owed = matches!(admit, Admit::Blocked(_) | Admit::Partial(_));
                }
                Ok(admit)
            }
            // What `A` refused before the switch comes again first, and
            // `B` does not read it.
            Phase::Then(_) if self.owed && !B::inherits(&event) => {
                self.owed = false;
                Ok(Admit::Taken)
            }
            // The old layer's leftovers go first.
            Phase::Then(_) if !self.below.is_empty() => Ok(Admit::Blocked(event)),
            Phase::Then(b) => env
                .scoped(Side::Upper, |env| b.on_event(env, event))
                .map_err(Side::Upper),
        }
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<A::Upper>,
    ) -> Result<Admit<CommandOf<A::Upper>>, Self::Error> {
        match &mut self.phase {
            Phase::First(a) => env
                .scoped(Side::Lower, |env| a.on_command(env, command))
                .map_err(Side::Lower),
            Phase::Then(_) if !self.above.is_empty() => Ok(Admit::Blocked(command)),
            Phase::Then(b) => env
                .scoped(Side::Upper, |env| b.on_command(env, command))
                .map_err(Side::Upper),
        }
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        timer: Self::Timer,
    ) -> Result<(), Self::Error> {
        match (&mut self.phase, timer) {
            (Phase::First(a), Side::Lower(t)) => env
                .scoped(Side::Lower, |env| a.on_timer(env, t))
                .map_err(Side::Lower),
            (Phase::Then(b), Side::Upper(t)) => env
                .scoped(Side::Upper, |env| b.on_timer(env, t))
                .map_err(Side::Upper),
            _ => Ok(()),
        }
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        done: Self::Done,
    ) -> Result<(), Self::Error> {
        match (&mut self.phase, done) {
            (Phase::First(a), Side::Lower(d)) => env
                .scoped(Side::Lower, |env| a.on_done(env, d))
                .map_err(Side::Lower),
            (Phase::Then(b), Side::Upper(d)) => env
                .scoped(Side::Upper, |env| b.on_done(env, d))
                .map_err(Side::Upper),
            _ => Ok(()),
        }
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Self::Error> {
        match &mut self.phase {
            Phase::First(a) => {
                let moved = env
                    .scoped(Side::Lower, |env| a.advance(env))
                    .map_err(Side::Lower)?;
                let Some(handover) = a.handover() else {
                    return Ok(moved);
                };
                self.below.extend(
                    handover
                        .below
                        .into_iter()
                        .filter(|event| B::inherits(event)),
                );
                self.above.extend(handover.above);
                let next = B::succeed(handover.next);
                assert!(next.depth() < super::MAX_DEPTH, "composition is too deep");
                self.owner = WorkOwner::new();
                self.phase = Phase::Then(next);
                Ok(true)
            }
            Phase::Then(b) => {
                let mut moved = env
                    .scoped(Side::Upper, |env| b.advance(env))
                    .map_err(Side::Upper)?;
                if let Some(event) = self.below.pop_front() {
                    let admit = env
                        .scoped(Side::Upper, |env| b.on_event(env, event))
                        .map_err(Side::Upper)?;
                    moved |= feed(&mut self.below, admit);
                }
                if let Some(command) = self.above.pop_front() {
                    let admit = env
                        .scoped(Side::Upper, |env| b.on_command(env, command))
                        .map_err(Side::Upper)?;
                    moved |= feed(&mut self.above, admit);
                }
                Ok(moved)
            }
        }
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<A::Lower>> {
        match &mut self.phase {
            Phase::First(a) => env.scoped(Side::Lower, |env| a.take_command(env)),
            Phase::Then(b) => env.scoped(Side::Upper, |env| b.take_command(env)),
        }
    }

    fn take_event(&mut self) -> Option<EventOf<A::Upper>> {
        match &mut self.phase {
            Phase::First(a) => a.take_event(),
            Phase::Then(b) => b.take_event(),
        }
    }

    fn take_urgent(&mut self) -> Option<EventOf<A::Upper>> {
        match &mut self.phase {
            Phase::First(a) => a.take_urgent(),
            Phase::Then(b) => b.take_urgent(),
        }
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        let work = match &mut self.phase {
            Phase::First(a) => a.take_work().map(Side::Lower),
            Phase::Then(b) => b.take_work().map(Side::Upper),
        }?;
        Some(self.owner.own(work))
    }

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        match report {
            Side::Lower(a) => A::report_bytes(a),
            Side::Upper(b) => B::report_bytes(b),
        }
    }

    fn depth(&self) -> usize {
        1 + match &self.phase {
            Phase::First(a) => a.depth(),
            Phase::Then(b) => b.depth(),
        }
    }

    fn is_terminal(&self) -> bool {
        match &self.phase {
            Phase::First(a) => a.is_terminal(),
            Phase::Then(b) => b.is_terminal(),
        }
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        match &self.phase {
            Phase::First(a) => a.deadline().map(|(at, t)| (at, Side::Lower(t))),
            Phase::Then(b) => b.deadline().map(|(at, t)| (at, Side::Upper(t))),
        }
    }
}
