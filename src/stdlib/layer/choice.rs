//! Layers chosen at run time: one of two made at the start, or one made
//! once what it runs on has negotiated it.

use fictionet::stdlib::layer::{Admit, CommandOf, Env, EventOf, Layer, Side};
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
    ) -> Result<(), Self::Error> {
        match (self, timer) {
            (Side::Lower(a), Side::Lower(t)) => env
                .scoped(Side::Lower, |env| a.on_timer(env, t))
                .map_err(Side::Lower),
            (Side::Upper(b), Side::Upper(t)) => env
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

    fn take_command(&mut self) -> Option<CommandOf<A::Lower>> {
        match self {
            Side::Lower(a) => a.take_command(),
            Side::Upper(b) => b.take_command(),
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
/// Until it is [`set`](Self::set) it takes nothing, from below or above,
/// and gives nothing, so what is offered waits where it is, in order, and
/// reaches the layer first once it is there. Put it on top of the layer
/// that decides with [`Chain`](super::Chain), and set it from whatever
/// owns the chain.
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

    /// The layer, once it is made. Panics if it was made before: a layer
    /// is made once.
    pub fn set(&mut self, layer: U) {
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

impl<U: Layer> Layer for Later<U> {
    type Lower = U::Lower;
    type Upper = U::Upper;
    type Report = U::Report;
    type Timer = U::Timer;
    type Work = U::Work;
    type Done = U::Done;
    type Error = U::Error;

    fn on_event(
        &mut self,
        env: &mut Env<'_, U::Report>,
        event: EventOf<U::Lower>,
    ) -> Result<Admit<EventOf<U::Lower>>, U::Error> {
        match &mut self.layer {
            Some(layer) => layer.on_event(env, event),
            None => Ok(Admit::Blocked(event)),
        }
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, U::Report>,
        command: CommandOf<U::Upper>,
    ) -> Result<Admit<CommandOf<U::Upper>>, U::Error> {
        match &mut self.layer {
            Some(layer) => layer.on_command(env, command),
            None => Ok(Admit::Blocked(command)),
        }
    }

    fn on_timer(&mut self, env: &mut Env<'_, U::Report>, timer: U::Timer) -> Result<(), U::Error> {
        match &mut self.layer {
            Some(layer) => layer.on_timer(env, timer),
            None => Ok(()),
        }
    }

    fn on_done(&mut self, env: &mut Env<'_, U::Report>, done: U::Done) -> Result<(), U::Error> {
        match &mut self.layer {
            Some(layer) => layer.on_done(env, done),
            None => Ok(()),
        }
    }

    fn advance(&mut self, env: &mut Env<'_, U::Report>) -> Result<bool, U::Error> {
        match &mut self.layer {
            Some(layer) => layer.advance(env),
            None => Ok(false),
        }
    }

    fn take_command(&mut self) -> Option<CommandOf<U::Lower>> {
        self.layer.as_mut()?.take_command()
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
