//! The observed stream: what a passive observer saw of one connection.

use core::convert::Infallible;

use fictionet::stdlib::layer::{Budget, Chunk, Credited, Port};

/// One connection as a passive observer put it back together from a
/// capture: each direction's bytes in order, with explicit gaps and a typed
/// end. A TCP observer over captured IP packets offers one per connection,
/// as a child of a [`Mux`](super::Mux) whose opening context names the
/// connection.
///
/// This is not a [`ByteStream`](super::ByteStream). An observer only
/// watches, so the port has no commands: nothing above can acknowledge,
/// write, end or reset anything, and nothing an observer does can put a
/// packet on the wire. Both directions travel in the one child, so that
/// what needs both (TLS negotiation, HTTP request and reply, HTTP/2 state)
/// keeps them together.
///
/// What arrives in each direction keeps these rules:
///
/// - [`Data`](ObservedEvent::Data) comes in stream order with nothing
///   repeated. Its `sequence` is where its first byte sits in the
///   direction's sequence space, counted from the first sequence number the
///   observer saw for that direction, without wrapping.
/// - Bytes the capture lacks are never invented. A
///   [`Gap`](ObservedEvent::Gap) says the next data does not follow on from
///   what came before; every decoder above it must resynchronize. The gap
///   advances the sequence position by its `missing` extent when that is
///   known, and never advances the count of delivered bytes, which counts
///   only bytes that arrived in `Data`.
/// - [`End`](ObservedEvent::End) comes once and is the direction's last
///   event: nothing in that direction follows it. Only
///   [`Termination::Fin`] is a clean end; every other cause leaves a
///   close-delimited body incomplete. A connection that starts again (a new
///   SYN) is a new child, never more input to a finished one.
///
/// Gap and end travel in this carrier, never only in a layer's reports,
/// which an observer above may not keep.
#[derive(Clone, Copy, Debug)]
pub struct ObservedStream;

impl Port for ObservedStream {
    type Event = ObservedEvent;
    type Command = Infallible;
}

/// Which way bytes went, relative to the order the connection's opening
/// context names its two endpoints: forward from the first to the second.
/// The order alone says nothing about which side is client or server; the
/// opening context says which side opened, when the observer saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// From the first endpoint to the second.
    Forward,
    /// From the second endpoint to the first.
    Reverse,
}

impl Direction {
    /// The other direction.
    pub fn reverse(self) -> Direction {
        match self {
            Direction::Forward => Direction::Reverse,
            Direction::Reverse => Direction::Forward,
        }
    }
}

/// Where observed bytes came from: a captured packet, by the number the
/// capture gave it, and where in that packet's captured bytes the first of
/// them sits. Bytes put together from several packets come as several
/// events, each with its own source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Source {
    /// The capture's number for the packet.
    pub packet: u64,
    /// The offset of the first byte in that packet's captured bytes.
    pub offset: usize,
}

/// How one direction of an observed connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Termination {
    /// The sender's FIN, reached after every byte before it was delivered:
    /// a clean end of this direction. A FIN seen before the bytes it
    /// follows ends the direction only once those bytes arrive.
    Fin,
    /// The connection was reset. Each direction not already ended gets this
    /// end. Data observed before the reset still comes first.
    Reset,
    /// The capture finished with bytes of this direction known to be
    /// missing: a hole before buffered data, before bytes dropped to stay
    /// within bounds, or before a FIN.
    Truncated,
    /// The observer dropped this connection to stay within its bounds.
    Evicted,
    /// A new connection on the same endpoints started (a new SYN) before
    /// this direction ended. What the sender did with this one after that
    /// is unknown.
    Replaced,
    /// The capture finished with no FIN, no reset and no known hole in this
    /// direction. What the sender did after the capture is unknown.
    Finalized,
}

impl Termination {
    /// Whether every byte the sender sent before closing was delivered.
    pub fn is_clean(self) -> bool {
        matches!(self, Termination::Fin)
    }
}

/// What comes up an observed stream. See [`ObservedStream`] for the rules.
#[derive(Debug)]
pub enum ObservedEvent {
    /// The next bytes in `direction`, never empty.
    Data {
        /// Which way they went.
        direction: Direction,
        /// The bytes.
        bytes: Chunk,
        /// The sequence position of the first byte.
        sequence: u64,
        /// The packet they came from, or `None` when that is not known.
        source: Option<Source>,
    },
    /// Bytes are missing in `direction` before the next data.
    Gap {
        /// Which way the missing bytes went.
        direction: Direction,
        /// The sequence position where the missing bytes start.
        sequence: u64,
        /// How many sequence positions are missing, when the observer knows.
        missing: Option<u64>,
    },
    /// `direction` ended. Nothing more comes that way.
    End {
        /// Which way ended.
        direction: Direction,
        /// Why.
        cause: Termination,
    },
}

impl ObservedEvent {
    /// The direction this event is about.
    pub fn direction(&self) -> Direction {
        match self {
            ObservedEvent::Data { direction, .. }
            | ObservedEvent::Gap { direction, .. }
            | ObservedEvent::End { direction, .. } => *direction,
        }
    }
}

impl Credited for ObservedEvent {
    fn credit(&self) -> u64 {
        match self {
            ObservedEvent::Data { bytes, .. } => bytes.len() as u64,
            _ => 0,
        }
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            ObservedEvent::Data { bytes, .. } => bytes.reserve(budget),
            _ => true,
        }
    }
}

/// A port with no commands, such as [`ObservedStream`], has nothing to
/// count.
impl Credited for Infallible {
    fn credit(&self) -> u64 {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(direction: Direction, bytes: &[u8]) -> ObservedEvent {
        ObservedEvent::Data {
            direction,
            bytes: Chunk::new(bytes.to_vec()),
            sequence: 1,
            source: None,
        }
    }

    #[test]
    fn data_is_counted_whole_and_ends_never_pass_it() {
        let event = data(Direction::Forward, b"hello");
        assert_eq!(event.credit(), 5);
        assert!(!event.splittable());
        assert!(event.admit_credit(4).is_err());
        let end = ObservedEvent::End {
            direction: Direction::Reverse,
            cause: Termination::Reset,
        };
        // A reset does not discard what was observed before it, and no
        // end goes past data that is waiting.
        assert!(!end.terminal_reset());
        assert!(!end.urgent());
        assert_eq!(end.credit(), 0);
        assert_eq!(end.direction(), Direction::Reverse);
    }

    #[test]
    fn only_a_fin_is_a_clean_end() {
        for cause in [
            Termination::Reset,
            Termination::Truncated,
            Termination::Evicted,
            Termination::Replaced,
            Termination::Finalized,
        ] {
            assert!(!cause.is_clean(), "{cause:?}");
        }
        assert!(Termination::Fin.is_clean());
    }

    #[test]
    fn observed_bytes_are_charged_before_they_are_kept() {
        let mut event = data(Direction::Forward, &[0; 64]);
        assert!(!event.reserve(&Budget::new(8)));
        let budget = Budget::new(128);
        assert!(event.reserve(&budget));
        assert!(budget.used() >= 64);
        drop(event);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn directions_reverse() {
        for direction in [Direction::Forward, Direction::Reverse] {
            assert_ne!(direction.reverse(), direction);
            assert_eq!(direction.reverse().reverse(), direction);
        }
    }
}
