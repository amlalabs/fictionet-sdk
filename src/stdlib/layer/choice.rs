//! Layers chosen at run time: one of two made at the start, or one made
//! once what it runs on has negotiated it.

use fictionet::stdlib::layer::{Admit, CommandOf, Credited, Env, EventOf, Layer, Port, Side};
use fictionet::time::Instant;

/// One of two layers with the same ports, chosen when the stack is made:
/// the typed choice at a boundary, such as HTTP/1 or HTTP/2 by what TLS
/// negotiated. Reports, timers, work and errors keep the side they came
/// from. A choice among more nests: `Side<A, Side<B, C>>`.
impl<A, B> Layer for Side<A, B>
where
    A: Layer,
    B: Layer<Lower = A::Lower, Upper = A::Upper>,
{
    type Lower = A::Lower;
    type Upper = A::Upper;
    type Report = Side<A::Report, B::Report>;
    type Timer = Side<A::Timer, B::Timer>;
    type Work = Side<A::Work, B::Work>;
    type Done = Side<A::Done, B::Done>;
    type Error = Side<A::Error, B::Error>;

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        match report {
            Side::Lower(a) => A::report_bytes(a),
            Side::Upper(b) => B::report_bytes(b),
        }
    }

    fn depth(&self) -> usize {
        1 + match self {
            Side::Lower(a) => a.depth(),
            Side::Upper(b) => b.depth(),
        }
    }

    fn is_terminal(&self) -> bool {
        match self {
            Side::Lower(a) => a.is_terminal(),
            Side::Upper(b) => b.is_terminal(),
        }
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: EventOf<A::Lower>,
    ) -> Result<Admit<EventOf<A::Lower>>, Self::Error> {
        match self {
            Side::Lower(a) => env
                .scoped(Side::Lower, |env| a.on_event(env, event))
                .map_err(Side::Lower),
            Side::Upper(b) => env
                .scoped(Side::Upper, |env| b.on_event(env, event))
                .map_err(Side::Upper),
        }
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<A::Upper>,
    ) -> Result<Admit<CommandOf<A::Upper>>, Self::Error> {
        match self {
            Side::Lower(a) => env
                .scoped(Side::Lower, |env| a.on_command(env, command))
                .map_err(Side::Lower),
            Side::Upper(b) => env
                .scoped(Side::Upper, |env| b.on_command(env, command))
                .map_err(Side::Upper),
        }
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        timer: Self::Timer,
    ) -> Result<bool, Self::Error> {
        match (self, timer) {
            (Side::Lower(a), Side::Lower(t)) => env
                .scoped(Side::Lower, |env| a.on_timer(env, t))
                .map_err(Side::Lower),
            (Side::Upper(b), Side::Upper(t)) => env
                .scoped(Side::Upper, |env| b.on_timer(env, t))
                .map_err(Side::Upper),
            _ => Ok(false),
        }
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        done: Self::Done,
    ) -> Result<(), Self::Error> {
        match (self, done) {
            (Side::Lower(a), Side::Lower(d)) => env
                .scoped(Side::Lower, |env| a.on_done(env, d))
                .map_err(Side::Lower),
            (Side::Upper(b), Side::Upper(d)) => env
                .scoped(Side::Upper, |env| b.on_done(env, d))
                .map_err(Side::Upper),
            _ => Ok(()),
        }
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Self::Error> {
        match self {
            Side::Lower(a) => env
                .scoped(Side::Lower, |env| a.advance(env))
                .map_err(Side::Lower),
            Side::Upper(b) => env
                .scoped(Side::Upper, |env| b.advance(env))
                .map_err(Side::Upper),
        }
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<A::Lower>> {
        match self {
            Side::Lower(a) => env.scoped(Side::Lower, |env| a.take_command(env)),
            Side::Upper(b) => env.scoped(Side::Upper, |env| b.take_command(env)),
        }
    }

    fn take_event(&mut self) -> Option<EventOf<A::Upper>> {
        match self {
            Side::Lower(a) => a.take_event(),
            Side::Upper(b) => b.take_event(),
        }
    }

    fn take_urgent(&mut self) -> Option<EventOf<A::Upper>> {
        match self {
            Side::Lower(a) => a.take_urgent(),
            Side::Upper(b) => b.take_urgent(),
        }
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        match self {
            Side::Lower(a) => a.take_work().map(Side::Lower),
            Side::Upper(b) => b.take_work().map(Side::Upper),
        }
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        match self {
            Side::Lower(a) => a.deadline().map(|(at, t)| (at, Side::Lower(t))),
            Side::Upper(b) => b.deadline().map(|(at, t)| (at, Side::Upper(t))),
        }
    }
}

/// A layer that is made later, once what it runs on has decided what it
/// is: what runs over TLS, made from the name and protocol the handshake
/// settled.
///
/// Until it is [`set`](Self::set), ordinary input and commands wait in order
/// and reach the layer first once it is there. Urgent events are accepted
/// and discarded because no upper layer exists to receive them. It gives
/// nothing until set. Put it on top of the layer
/// that decides with [`Chain`](super::Chain), and set it from whatever
/// owns the chain, during one of its own calls.
pub struct Later<U> {
    layer: Option<U>,
}

impl<U> Default for Later<U> {
    fn default() -> Later<U> {
        Later { layer: None }
    }
}

impl<U> Later<U> {
    /// No layer yet.
    pub fn new() -> Later<U> {
        Later::default()
    }

    /// The layer, once it is made. `env` is an environment for this
    /// `Later`, the one whatever holds it calls it with, and the layer must
    /// fit below it ([`Env::fits_below`]). Panics if it does not, or if a
    /// layer was made before: a layer is made once.
    pub fn set(&mut self, env: &Env<'_, U::Report>, layer: U)
    where
        U: Layer,
    {
        assert!(env.fits_below(&layer), "composition is too deep");
        assert!(self.layer.is_none(), "a later layer is made once");
        self.layer = Some(layer);
    }

    /// The layer, if it is made.
    pub fn get(&self) -> Option<&U> {
        self.layer.as_ref()
    }

    /// Whether the layer is made.
    pub fn is_set(&self) -> bool {
        self.layer.is_some()
    }
}

impl<U: Layer> Layer for Later<U>
where
    EventOf<U::Lower>: Credited,
{
    type Lower = U::Lower;
    type Upper = U::Upper;
    type Report = U::Report;
    type Timer = U::Timer;
    type Work = U::Work;
    type Done = U::Done;
    type Error = U::Error;

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        U::report_bytes(report)
    }

    fn depth(&self) -> usize {
        1 + self.layer.as_ref().map_or(0, Layer::depth)
    }

    fn is_terminal(&self) -> bool {
        self.layer.as_ref().is_some_and(Layer::is_terminal)
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, U::Report>,
        event: EventOf<U::Lower>,
    ) -> Result<Admit<EventOf<U::Lower>>, U::Error> {
        match &mut self.layer {
            Some(layer) => env.part(|env| layer.on_event(env, event)),
            None if <U::Lower as Port>::urgent(&event) => Ok(Admit::Taken),
            None => Ok(Admit::Blocked(event)),
        }
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, U::Report>,
        command: CommandOf<U::Upper>,
    ) -> Result<Admit<CommandOf<U::Upper>>, U::Error> {
        match &mut self.layer {
            Some(layer) => env.part(|env| layer.on_command(env, command)),
            None => Ok(Admit::Blocked(command)),
        }
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, U::Report>,
        timer: U::Timer,
    ) -> Result<bool, U::Error> {
        match &mut self.layer {
            Some(layer) => env.part(|env| layer.on_timer(env, timer)),
            None => Ok(false),
        }
    }

    fn on_done(&mut self, env: &mut Env<'_, U::Report>, done: U::Done) -> Result<(), U::Error> {
        match &mut self.layer {
            Some(layer) => env.part(|env| layer.on_done(env, done)),
            None => Ok(()),
        }
    }

    fn advance(&mut self, env: &mut Env<'_, U::Report>) -> Result<bool, U::Error> {
        match &mut self.layer {
            Some(layer) => env.part(|env| layer.advance(env)),
            None => Ok(false),
        }
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<U::Lower>> {
        let layer = self.layer.as_mut()?;
        env.part(|env| layer.take_command(env))
    }

    fn take_event(&mut self) -> Option<EventOf<U::Upper>> {
        self.layer.as_mut()?.take_event()
    }

    fn take_urgent(&mut self) -> Option<EventOf<U::Upper>> {
        self.layer.as_mut()?.take_urgent()
    }

    fn take_work(&mut self) -> Option<U::Work> {
        self.layer.as_mut()?.take_work()
    }

    fn deadline(&self) -> Option<(Instant, U::Timer)> {
        self.layer.as_ref()?.deadline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use fictionet::stdlib::layer::{
        Budget, ByteStream, Driver, Observations, StreamCommand, StreamEvent, Top,
    };
    use std::sync::Arc;

    struct Sink;
    impl Layer for Sink {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            _: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    #[test]
    fn an_unset_layer_takes_urgent_completions_and_keeps_regular_input_waiting() {
        let mut driver = Driver::new(
            Later::<Sink>::new(),
            Arc::new(fictionet::SeededEntropy::new(fictionet::Seed::from_u64(91))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        assert!(matches!(
            driver.deliver(StreamEvent::Written(7)),
            Ok(Admit::Taken)
        ));
        assert!(matches!(
            driver.deliver(StreamEvent::Reset),
            Ok(Admit::Taken)
        ));
        assert!(matches!(
            driver.deliver(StreamEvent::Ended),
            Ok(Admit::Blocked(StreamEvent::Ended))
        ));
        // The `Later` is the top of the stack: an environment for the top
        // is its own.
        let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(91));
        let budget = Budget::unlimited();
        let mut reports = Observations::new(0);
        let env = Env::new(Instant::ZERO, &entropy, &budget, &mut reports);
        driver.layer_mut().set(&env, Sink);
        assert!(matches!(
            driver.deliver(StreamEvent::Ended),
            Ok(Admit::Taken)
        ));
    }
}
