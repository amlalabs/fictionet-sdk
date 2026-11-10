use fictionet::stdlib::layer::{Admit, CommandOf, Env, EventOf, Layer, MAX_DEPTH, Side};
use fictionet::time::Instant;

/// `B` stacked on `A`: `A`'s upper port is `B`'s lower port.
///
/// The chain is itself a layer, from `A`'s lower port to `B`'s upper port,
/// so chains nest. It keeps both parts' events, timers, work and errors
/// apart with [`Side`]. Between the parts it holds at most one item each
/// way: what one part handed over and the other has not taken yet. While
/// `B` refuses the event it holds, `A`'s urgent events
/// ([`take_urgent`](Layer::take_urgent)) go past it, one at a time.
/// [`advance`](Layer::advance) moves those items in a loop, never by one
/// part calling the other. Dispatch recurses through the composition, whose
/// depth is bounded by [`MAX_DEPTH`].
pub struct Chain<A: Layer, B: Layer<Lower = A::Upper>> {
    lower: A,
    upper: B,
    /// An event `A` handed up that `B` has not taken.
    up: Option<EventOf<A::Upper>>,
    /// An urgent event `A` handed up past a refused one, that `B` has not
    /// taken yet.
    urgent: Option<EventOf<A::Upper>>,
    /// A command `B` handed down that `A` has not taken.
    down: Option<CommandOf<A::Upper>>,
    lower_worked_last: bool,
    lower_fired_last: bool,
}

impl<A: Layer, B: Layer<Lower = A::Upper>> Chain<A, B> {
    /// `upper` on top of `lower`.
    pub fn new(lower: A, upper: B) -> Chain<A, B> {
        assert!(
            lower.depth().max(upper.depth()) < MAX_DEPTH,
            "composition depth exceeded"
        );
        Chain {
            lower,
            upper,
            up: None,
            urgent: None,
            down: None,
            lower_worked_last: false,
            lower_fired_last: false,
        }
    }

    /// Discards buffered events that no longer belong to the upper protocol.
    /// The lower layer must separately discard any events it still owns.
    /// Returns whether an event was discarded.
    pub fn retain_events(&mut self, mut keep: impl FnMut(&EventOf<A::Upper>) -> bool) -> bool {
        let mut discarded = false;
        for slot in [&mut self.up, &mut self.urgent] {
            if slot.as_ref().is_some_and(|event| !keep(event)) {
                *slot = None;
                discarded = true;
            }
        }
        discarded
    }

    /// The lower part.
    pub fn lower(&self) -> &A {
        &self.lower
    }

    /// The upper part.
    pub fn upper(&self) -> &B {
        &self.upper
    }

    /// The lower part.
    pub fn lower_mut(&mut self) -> &mut A {
        &mut self.lower
    }

    /// The upper part.
    pub fn upper_mut(&mut self) -> &mut B {
        &mut self.upper
    }
}

/// Offers `item` to a part and keeps what it hands back. Returns whether
/// anything moved. What a closed input refuses is dropped: it will never be
/// taken.
fn offer<T>(slot: &mut Option<T>, admit: Admit<T>) -> bool {
    match admit {
        Admit::Taken | Admit::Closed(_) => true,
        Admit::Partial(rest) => {
            *slot = Some(rest);
            true
        }
        Admit::Blocked(item) => {
            *slot = Some(item);
            false
        }
    }
}

impl<A: Layer, B: Layer<Lower = A::Upper>> Layer for Chain<A, B> {
    type Lower = A::Lower;
    type Upper = B::Upper;
    type Report = Side<A::Report, B::Report>;
    type Timer = Side<A::Timer, B::Timer>;
    type Work = Side<A::Work, B::Work>;
    type Done = Side<A::Done, B::Done>;
    type Error = Side<A::Error, B::Error>;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: EventOf<A::Lower>,
    ) -> Result<Admit<EventOf<A::Lower>>, Self::Error> {
        env.scoped(Side::Lower, |env| self.lower.on_event(env, event))
            .map_err(Side::Lower)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<B::Upper>,
    ) -> Result<Admit<CommandOf<B::Upper>>, Self::Error> {
        env.scoped(Side::Upper, |env| self.upper.on_command(env, command))
            .map_err(Side::Upper)
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        timer: Self::Timer,
    ) -> Result<bool, Self::Error> {
        self.lower_fired_last = matches!(timer, Side::Lower(_));
        match timer {
            Side::Lower(t) => env
                .scoped(Side::Lower, |env| self.lower.on_timer(env, t))
                .map_err(Side::Lower),
            Side::Upper(t) => env
                .scoped(Side::Upper, |env| self.upper.on_timer(env, t))
                .map_err(Side::Upper),
        }
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        done: Self::Done,
    ) -> Result<(), Self::Error> {
        match done {
            Side::Lower(d) => env
                .scoped(Side::Lower, |env| self.lower.on_done(env, d))
                .map_err(Side::Lower),
            Side::Upper(d) => env
                .scoped(Side::Upper, |env| self.upper.on_done(env, d))
                .map_err(Side::Upper),
        }
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Self::Error> {
        let mut moved = env
            .scoped(Side::Lower, |env| self.lower.advance(env))
            .map_err(Side::Lower)?;
        moved |= env
            .scoped(Side::Upper, |env| self.upper.advance(env))
            .map_err(Side::Upper)?;
        // An urgent event goes first, then whatever `A` has.
        if self.urgent.is_none() {
            self.urgent = self.lower.take_urgent();
        }
        if let Some(event) = self.urgent.take() {
            let admit = env
                .scoped(Side::Upper, |env| self.upper.on_event(env, event))
                .map_err(Side::Upper)?;
            moved |= offer(&mut self.urgent, admit);
        }
        if self.up.is_none() {
            self.up = self.lower.take_event();
            moved |= self.up.is_some();
        }
        if let Some(event) = self.up.take() {
            let admit = env
                .scoped(Side::Upper, |env| self.upper.on_event(env, event))
                .map_err(Side::Upper)?;
            moved |= offer(&mut self.up, admit);
        }
        if self.down.is_none() {
            self.down = env.scoped(Side::Upper, |env| self.upper.take_command(env));
            moved |= self.down.is_some();
        }
        if let Some(command) = self.down.take() {
            let admit = env
                .scoped(Side::Lower, |env| self.lower.on_command(env, command))
                .map_err(Side::Lower)?;
            moved |= offer(&mut self.down, admit);
        }
        Ok(moved)
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<A::Lower>> {
        env.scoped(Side::Lower, |env| self.lower.take_command(env))
    }

    fn take_event(&mut self) -> Option<EventOf<B::Upper>> {
        self.upper.take_event()
    }

    fn take_urgent(&mut self) -> Option<EventOf<B::Upper>> {
        self.upper.take_urgent()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        let work = if self.lower_worked_last {
            self.upper
                .take_work()
                .map(Side::Upper)
                .or_else(|| self.lower.take_work().map(Side::Lower))
        } else {
            self.lower
                .take_work()
                .map(Side::Lower)
                .or_else(|| self.upper.take_work().map(Side::Upper))
        };
        if let Some(ref work) = work {
            self.lower_worked_last = matches!(work, Side::Lower(_));
        }
        work
    }

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        match report {
            Side::Lower(report) => A::report_bytes(report),
            Side::Upper(report) => B::report_bytes(report),
        }
    }

    fn depth(&self) -> usize {
        1 + self.lower.depth().max(self.upper.depth())
    }

    fn is_terminal(&self) -> bool {
        self.upper.is_terminal()
    }

    fn waits_for_memory(&self) -> bool {
        self.lower.waits_for_memory() || self.upper.waits_for_memory()
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        let lower = self.lower.deadline();
        let upper = self.upper.deadline();
        match (lower, upper) {
            (Some((a, t)), Some((b, _))) if a < b || (a == b && !self.lower_fired_last) => {
                Some((a, Side::Lower(t)))
            }
            (_, Some((b, t))) => Some((b, Side::Upper(t))),
            (Some((a, t)), None) => Some((a, Side::Lower(t))),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::layer::{Budget, ByteStream, Driver, StreamCommand, StreamEvent};
    use crate::{Seed, SeededEntropy};
    use std::convert::Infallible;
    use std::sync::Arc;

    struct Clock(usize);
    impl Layer for Clock {
        type Lower = ByteStream;
        type Upper = ByteStream;
        type Report = ();
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            Ok(Admit::Blocked(event))
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            command: StreamCommand,
        ) -> Result<Admit<StreamCommand>, Infallible> {
            Ok(Admit::Blocked(command))
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<StreamEvent> {
            None
        }
        fn deadline(&self) -> Option<(Instant, ())> {
            Some((Instant::ZERO, ()))
        }
        fn on_timer(&mut self, _: &mut Env<'_, ()>, _: ()) -> Result<bool, Infallible> {
            self.0 += 1;
            Ok(true)
        }
    }

    #[test]
    fn equally_due_timers_rotate_between_permanently_ready_layers() {
        let mut driver = Driver::new(
            Chain::new(Clock(0), Clock(0)),
            Arc::new(SeededEntropy::new(Seed::from_u64(95))),
            Budget::new(1000),
            Instant::ZERO,
        );
        driver.run().unwrap();
        let a = driver.layer().lower().0;
        let b = driver.layer().upper().0;
        assert!(a > 0 && b > 0);
        assert!(a.abs_diff(b) <= 1);
        assert!(driver.exhausted());
    }
}
