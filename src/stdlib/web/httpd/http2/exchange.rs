//! The carrier between an HTTP/2 connection and the exchange on each of
//! its streams.

use http::{HeaderMap, StatusCode};

use fictionet::stdlib::layer::{Budget, Charge, Chunk, Credited, Owned, Port};
use fictionet::stdlib::protocols::http2::ErrorCode;
use fictionet::time::Instant;

/// One HTTP exchange on a multiplexed connection: the request comes up, the
/// response goes down. An HTTP/2 stream is one; [`Http2`](super::Http2)
/// offers one child of this port per stream.
///
/// The request's head opens the child ([`Opening`]). Its body comes up as
/// [`ExchangeEvent::Data`] within the credit the child grants, and its end
/// as [`End`](ExchangeEvent::End) or [`Trailers`](ExchangeEvent::Trailers).
/// The response goes down as a [`Head`](ExchangeCommand::Head), body
/// [`Data`](ExchangeCommand::Data) within the credit the connection grants,
/// and an [`End`](ExchangeCommand::End) or
/// [`Trailers`](ExchangeCommand::Trailers). The exchange is over when
/// [`ExchangeEvent::Closed`] comes up: the child is then dropped.
///
/// The connection keeps the stream states, both levels of flow control,
/// HPACK and the wire's stream numbers; the child keeps the application's
/// side of one exchange, such as a handler and its body, or a gRPC call.
#[derive(Clone, Copy, Debug)]
pub struct HttpExchange;

impl Port for HttpExchange {
    type Event = ExchangeEvent;
    type Command = ExchangeCommand;

    fn urgent(event: &ExchangeEvent) -> bool {
        matches!(event, ExchangeEvent::Written(_))
    }
}

/// What opens an exchange: the request's head, as the connection read and
/// checked it.
#[derive(Debug)]
pub struct Opening {
    /// The request without its body, with what it is charged to the
    /// connection's budget: whoever holds the head holds its charge, and
    /// one goes with the other ([`Owned::into_parts`]). Its version is the
    /// connection's.
    pub request: Owned<Box<http::Request<()>>>,
    /// Whether the request has no body: it ended with its head.
    pub ended: bool,
    /// When the head arrived, on the run's clock.
    pub at: Instant,
}

/// A request's trailers, as the connection read and checked them.
#[derive(Debug)]
pub struct RequestTrailers {
    /// The fields.
    pub fields: HeaderMap,
    /// What the trailers are charged to the connection's budget. Whoever
    /// holds them keeps it, and it goes back when they are dropped.
    pub charge: Charge,
}

/// What comes up an exchange.
#[derive(Debug)]
pub enum ExchangeEvent {
    /// The next bytes of the request's body. Each byte uses one unit of
    /// the child's credit.
    Data(Chunk),
    /// The request's trailers. The request has ended.
    Trailers(Box<RequestTrailers>),
    /// The request has ended.
    End,
    /// The connection could not hold the next this many bytes of the
    /// request's body: it drops them and the rest of the body. The
    /// request's end still comes.
    Overflow(u64),
    /// The transport has taken the whole frames of this many bytes of the
    /// response's body so far. The count only grows, so a later one says
    /// everything an earlier one did.
    Written(u64),
    /// The exchange is over. Nothing comes after it: the child is closed.
    Closed {
        /// How it ended.
        why: Ending,
        /// The response body bytes whose whole frames the transport took.
        written: u64,
    },
}

/// How an exchange ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// Every byte of the response, its end included, was written.
    Done,
    /// The stream was reset, by the peer or by the connection, with this
    /// code.
    Reset(ErrorCode),
    /// The connection is closing, or gone.
    Gone,
}

/// What goes down an exchange.
#[derive(Debug)]
pub enum ExchangeCommand {
    /// The response's head. With `end`, the response has no body and is
    /// complete.
    Head(Box<ResponseHead>),
    /// The next bytes of the response's body. Each byte uses one unit of
    /// the credit the connection granted.
    Data(Chunk),
    /// The response's trailers, which complete it.
    Trailers(Box<HeaderMap>),
    /// The response is complete.
    End,
    /// Reset the stream with this code: the response stops where it is.
    Reset(ErrorCode),
}

/// A response's head as it goes on the wire: the status and the fields,
/// with the framing fields the response policy chose.
#[derive(Debug)]
pub struct ResponseHead {
    /// The status.
    pub status: StatusCode,
    /// The fields. The connection drops fields HTTP/2 does not carry.
    pub headers: HeaderMap,
    /// Whether the response has no body.
    pub end: bool,
}

impl Credited for ExchangeEvent {
    fn credit(&self) -> u64 {
        match self {
            ExchangeEvent::Data(chunk) => chunk.len() as u64,
            _ => 0,
        }
    }

    /// Body bytes are paid for by the budget that admits them.
    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            ExchangeEvent::Data(chunk) => chunk.repay(budget),
            _ => true,
        }
    }

    fn terminal_reset(&self) -> bool {
        matches!(self, ExchangeEvent::Closed { .. })
    }
}

impl Credited for ExchangeCommand {
    fn credit(&self) -> u64 {
        match self {
            ExchangeCommand::Data(chunk) => chunk.len() as u64,
            _ => 0,
        }
    }

    fn splittable(&self) -> bool {
        matches!(self, ExchangeCommand::Data(_))
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            ExchangeCommand::Data(chunk) => chunk.repay(budget),
            _ => true,
        }
    }

    fn admit_credit(self, units: u64) -> Result<(Self, Option<Self>), Self> {
        if self.credit() <= units {
            return Ok((self, None));
        }
        match self {
            ExchangeCommand::Data(mut chunk) if units > 0 => {
                let prefix = chunk.split_to(units as usize);
                Ok((
                    ExchangeCommand::Data(prefix),
                    Some(ExchangeCommand::Data(chunk)),
                ))
            }
            command => Err(command),
        }
    }
}
