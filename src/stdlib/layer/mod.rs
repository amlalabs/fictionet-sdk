//! Protocol layers: one way to stack any protocol on any carrier that has
//! the semantics it needs.
//!
//! A [`Port`] is one side of a boundary between two protocols: the events
//! that travel up through it and the commands that travel down. A
//! [`Layer`] sits between a lower port and an upper port. It takes events
//! from below and commands from above, and it gives commands downward and
//! events upward. TLS is a layer with an ordered byte stream on both sides;
//! HTTP/1 serving has a byte stream below and exchanges above; an HTTP/2
//! connection has a byte stream below and [multiplexed children](Mux)
//! above.
//!
//! Type equality proves only that the carrier fits. Whether a handshake
//! succeeded, a stream may be opened, or peer input is valid is still
//! decided at run time by each layer's state machine.
//!
//! # The carriers
//!
//! Four port shapes cover what protocols need from what is below them:
//!
//! | Port | What it keeps |
//! | --- | --- |
//! | [`ByteStream`] | Ordered bytes, each direction closing on its own, partial admission, reset, and write completion. Chunk boundaries mean nothing. |
//! | [`Datagrams`] | One whole message each, empty ones included, with its endpoint metadata. Admission is all or nothing. The end of a datagram is not the end of the conversation. |
//! | [`Messages`] | Whole typed protocol units. A message boundary is never turned into an end of input. |
//! | [`Mux`] | Connection control plus children, each owned through a [`Child`] handle and each with its own port, closing and credit. |
//!
//! A child handle cannot be used once it has been closed, because closing
//! consumes it:
//!
//! ```compile_fail,E0382
//! # use fictionet::stdlib::layer::*;
//! let mut slots = Slots::new(8);
//! let child = slots.insert(()).unwrap();
//! let bye: MuxCommand<ByteStream, Top> = child.close();
//! let again: MuxCommand<ByteStream, Top> = child.grant(1);
//! ```
//!
//! Using it before closing it is fine:
//!
//! ```
//! # use fictionet::stdlib::layer::*;
//! let mut slots = Slots::new(8);
//! let child = slots.insert(()).unwrap();
//! let more: MuxCommand<ByteStream, Top> = child.grant(1);
//! let bye: MuxCommand<ByteStream, Top> = child.close();
//! ```
//!
//! And a handle that outlives its child on the other side, because the peer
//! closed it, is refused at run time: each handle carries the generation of
//! its slot and the identity of its connection, so a successor in the same
//! slot, or a child of another connection, never answers to it.
//!
//! # The rules every layer and driver keeps
//!
//! 1. **Refusal keeps ownership.** An entry point takes an owned value and
//!    either takes it whole or hands it back in an [`Admit`]: the rest of a
//!    byte payload ([`Admit::Partial`]), or all of it ([`Admit::Blocked`],
//!    [`Admit::Closed`]). A protocol error is an `Err`, never a refusal. A
//!    pure refusal changes no state and draws no entropy.
//! 2. **Output has one owner.** A layer keeps its output until
//!    [`take_command`](Layer::take_command) or
//!    [`take_event`](Layer::take_event) hands it over. Whoever takes it
//!    holds at most one item per edge until the next owner takes it; a
//!    partly written stream chunk keeps its place. Datagrams are never
//!    split.
//! 3. **Admission is not delivery.** Taking bytes, handing them below, and
//!    their write completion ([`StreamEvent::Written`]) are three different
//!    facts.
//! 4. **Every retained allocation is charged** to the connection's
//!    [`Budget`], and the charge moves with what it pays for ([`Chunk`]).
//! 5. **Limits apply before growth.** Charge first, then allocate.
//! 6. **Progress is bounded and fair.** [`Layer::advance`] moves a bounded
//!    amount of work per call, and children are visited in a stable,
//!    rotating order. A stalled child holds only its own credit.
//! 7. **Timers belong to owners.** A layer keeps its own timers
//!    ([`Timers`]); they go when the layer goes. A child's timers are keyed
//!    by its [`ChildId`], generation included.
//! 8. **Closed input is explicit.** A layer whose input has ended says
//!    [`Admit::Closed`] instead of taking and dropping.
//!

mod budget;
mod carrier;
mod env;
mod timers;

pub use budget::{Budget, Charge};
pub use carrier::{
    ByteStream, Child, ChildId, Chunk, Credited, Datagram, DatagramCommand, DatagramEvent,
    Datagrams, MessageCommand, MessageEvent, Messages, Mux, MuxCommand, MuxEvent, MuxOp, Slots,
    StreamCommand, StreamEvent,
};
pub use env::{Env, Observe};
pub use timers::Timers;

use fictionet::time::Instant;

/// One side of a boundary between protocols: what travels up through it,
/// and what travels down.
pub trait Port {
    /// What the lower side gives the upper side.
    type Event;
    /// What the upper side gives the lower side.
    type Command;
}

/// The events of port `P`.
pub type EventOf<P> = <P as Port>::Event;
/// The commands of port `P`.
pub type CommandOf<P> = <P as Port>::Command;

/// The port above the top of a stack: nothing travels through it. An
/// application that answers its peer itself, such as a server, has `Top`
/// as its upper port.
#[derive(Clone, Copy, Debug)]
pub struct Top;

impl Port for Top {
    type Event = core::convert::Infallible;
    type Command = core::convert::Infallible;
}

/// What became of a value offered to a layer. Everything not taken is
/// handed back, so the caller still owns it.
#[must_use = "a refused value is handed back and must be kept or dropped on purpose"]
#[derive(Debug, PartialEq, Eq)]
pub enum Admit<T> {
    /// Taken whole.
    Taken,
    /// A prefix was taken; this is the rest. Only byte-stream data is ever
    /// split.
    Partial(T),
    /// Nothing was taken. Offer it again after the layer has made progress.
    Blocked(T),
    /// Nothing was taken, and nothing will be: this input has ended.
    Closed(T),
}

impl<T> Admit<T> {
    /// The same answer about a value of another type.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Admit<U> {
        match self {
            Admit::Taken => Admit::Taken,
            Admit::Partial(t) => Admit::Partial(f(t)),
            Admit::Blocked(t) => Admit::Blocked(f(t)),
            Admit::Closed(t) => Admit::Closed(f(t)),
        }
    }

    /// Whether the layer took anything.
    pub fn moved(&self) -> bool {
        matches!(self, Admit::Taken | Admit::Partial(_))
    }
}

/// Which part of a composed layer something belongs to: the lower part or
/// the upper one. A composed layer keeps both parts' events,
/// timers, work and errors apart with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side<L, U> {
    /// The lower part, or the first one of a switch.
    Lower(L),
    /// The upper part, or the successor of a switch.
    Upper(U),
}

impl<L: core::fmt::Display, U: core::fmt::Display> core::fmt::Display for Side<L, U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Side::Lower(l) => l.fmt(f),
            Side::Upper(u) => u.fmt(f),
        }
    }
}

impl<L: core::error::Error, U: core::error::Error> core::error::Error for Side<L, U> {}

/// One protocol between a lower port and an upper port, with no I/O.
///
/// Inputs arrive through four entry points: an event from below, a command
/// from above, a due timer, and the result of work the layer asked for.
/// Output leaves through [`take_command`](Self::take_command),
/// [`take_event`](Self::take_event) and [`take_work`](Self::take_work), and
/// [`deadline`](Self::deadline) says when the layer next needs time.
/// [`advance`](Self::advance) does internal work: a composed layer moves
/// items between its parts there.
///
/// Read [the rules](self#the-rules-every-layer-and-driver-keeps) before
/// writing one.
pub trait Layer: Sized {
    /// The port this layer runs over.
    type Lower: Port;
    /// The port this layer offers.
    type Upper: Port;
    /// What the layer reports about itself, such as a finished handshake.
    /// Reports go to [`Env::report`]; nothing needs to read them for the
    /// protocol to make progress.
    type Report;
    /// The layer's timer names. Use `()` for a layer with none.
    type Timer: Clone + Eq;
    /// Work the layer asks the world to do, such as a lookup or an
    /// application handler.
    type Work;
    /// The result of that work.
    type Done;
    /// Why the layer gave up on the whole connection.
    type Error;

    /// An event from the port below.
    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: EventOf<Self::Lower>,
    ) -> Result<Admit<EventOf<Self::Lower>>, Self::Error>;

    /// A command from the port above.
    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<Self::Upper>,
    ) -> Result<Admit<CommandOf<Self::Upper>>, Self::Error>;

    /// The timer `timer`, which [`deadline`](Self::deadline) named, is due.
    /// The layer disarms or rearms it.
    fn on_timer(
        &mut self,
        _env: &mut Env<'_, Self::Report>,
        _timer: Self::Timer,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Work from [`take_work`](Self::take_work) finished.
    fn on_done(
        &mut self,
        _env: &mut Env<'_, Self::Report>,
        _done: Self::Done,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Does a bounded amount of internal work. Returns whether anything
    /// changed; the driver calls it again while something does.
    fn advance(&mut self, _env: &mut Env<'_, Self::Report>) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Hands over the next command for the port below, if one is ready.
    fn take_command(&mut self) -> Option<CommandOf<Self::Lower>>;

    /// Hands over the next event for the port above, if one is ready.
    fn take_event(&mut self) -> Option<EventOf<Self::Upper>>;

    /// Hands over the next piece of work for the world, if there is one.
    fn take_work(&mut self) -> Option<Self::Work> {
        None
    }

    /// The earliest armed timer and when it is due. Of two due at the same
    /// moment, the one armed first.
    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        None
    }
}
