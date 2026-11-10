//! The carrier between an HTTP/2 connection and the exchange on each of
//! its streams.

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};

use fictionet::stdlib::layer::{Budget, Chunk, Credited, Port};
use fictionet::stdlib::protocols::fields::Fields;
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
    /// The request without its body.
    pub head: RequestHead,
    /// Whether the request has no body: it ended with its head.
    pub ended: bool,
    /// When the head arrived, on the run's clock.
    pub at: Instant,
}

/// A request's head as the connection decoded and checked it: its fields,
/// pseudo-fields first, in the one block HPACK decoded them into
/// ([`Fields`]). The block carries what pays for it, so whoever holds the
/// head holds its charge, and the block goes back to the connection when
/// the head is dropped. Reading it allocates nothing;
/// [`to_http`](Self::to_http) makes an [`http::Request`] of it, which does.
///
/// The connection checked it as RFC 9113 section 8.3 asks: `:method` is a
/// token and comes once; a CONNECT has an `:authority` and no `:scheme` or
/// `:path`, any other method a `:scheme` and a `:path`; every regular
/// field is in lower case and not connection-specific; and every
/// `content-length` agrees.
#[derive(Clone, Debug)]
pub struct RequestHead {
    fields: Fields,
    content_length: Option<u64>,
}

impl RequestHead {
    /// A head the connection checked.
    pub(super) fn new(fields: Fields, content_length: Option<u64>) -> RequestHead {
        RequestHead {
            fields,
            content_length,
        }
    }

    /// Every field, in the order it came, pseudo-fields first.
    pub fn fields(&self) -> &Fields {
        &self.fields
    }

    /// The block of fields, with what pays for it.
    pub fn into_fields(self) -> Fields {
        self.fields
    }

    /// The value of the pseudo-field `:name`.
    fn pseudo(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields
            .iter()
            .take_while(|(field, _)| field.starts_with(b":"))
            .find(|(field, _)| &field[1..] == name)
            .map(|(_, value)| value)
    }

    /// `:method`.
    pub fn method(&self) -> &[u8] {
        self.pseudo(b"method").unwrap_or_default()
    }

    /// `:scheme`, which every request but a CONNECT has.
    pub fn scheme(&self) -> Option<&[u8]> {
        self.pseudo(b"scheme")
    }

    /// `:authority`, if the request has one.
    pub fn authority(&self) -> Option<&[u8]> {
        self.pseudo(b"authority")
    }

    /// `:path`, which every request but a CONNECT has.
    pub fn path(&self) -> Option<&[u8]> {
        self.pseudo(b"path")
    }

    /// The regular fields, in order.
    pub fn headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.fields
            .iter()
            .skip_while(|(field, _)| field.starts_with(b":"))
    }

    /// The body's length, if `content-length` gives it.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// The most [`to_http`](Self::to_http)'s request holds, counted as
    /// the server counts a request's head: its parts, its strings, and its
    /// header map's places and octets. A map made for `n` fields has
    /// fewer than `2n` places, and grows past that only when names
    /// collide in runs of 128, so only with 128 fields or more, and to
    /// fewer than `8n`; a value joined from several `cookie` fields adds
    /// two octets for each.
    pub fn most_http(&self) -> usize {
        let fields = self.fields.len();
        let places = if fields < 128 { 2 * fields } else { 8 * fields };
        (places + fields)
            .saturating_mul(size_of::<(HeaderName, HeaderValue)>())
            .saturating_add(self.fields.octets())
            .saturating_add(2 * fields)
            .saturating_add(size_of::<http::request::Parts>())
    }

    /// The head as an [`http::Request`], its version HTTP/2, its URI made
    /// from the pseudo-fields, and its fields in a map, a client's split
    /// `cookie` fields joined with `"; "` (RFC 9113 section 8.2.3). It
    /// allocates. `None` for an authority or path the `http` crate does
    /// not take.
    pub fn to_http(&self) -> Option<http::Request<()>> {
        let method = Method::from_bytes(self.method()).ok()?;
        let mut uri = http::uri::Parts::default();
        uri.authority = self
            .authority()
            .map(http::uri::Authority::try_from)
            .transpose()
            .ok()?;
        if method != Method::CONNECT {
            if uri.authority.is_some() {
                uri.scheme = Some(http::uri::Scheme::try_from(self.scheme()?).ok()?);
            }
            uri.path_and_query = Some(http::uri::PathAndQuery::try_from(self.path()?).ok()?);
        }
        let mut headers: HeaderMap = HeaderMap::with_capacity(self.fields.len());
        let mut cookie: Option<Vec<u8>> = None;
        for (name, value) in self.headers() {
            if name == b"cookie"
                && let Some(first) = headers.get(http::header::COOKIE)
            {
                let joined = cookie.get_or_insert_with(|| first.as_bytes().to_vec());
                joined.extend_from_slice(b"; ");
                joined.extend_from_slice(value);
            } else {
                headers.append(
                    HeaderName::from_bytes(name).ok()?,
                    HeaderValue::from_bytes(value).ok()?,
                );
            }
        }
        if let Some(cookie) = cookie {
            headers.insert(http::header::COOKIE, HeaderValue::from_bytes(&cookie).ok()?);
        }
        let mut request = http::Request::builder()
            .method(method)
            .uri(http::Uri::from_parts(uri).ok()?)
            .version(http::Version::HTTP_2)
            .body(())
            .ok()?;
        *request.headers_mut() = headers;
        Some(request)
    }
}

/// A request's trailers, as the connection decoded and checked them: in
/// one block, which carries what pays for it, charged at the most the
/// encoded block could hold before it was decoded. Whoever holds them
/// holds the charge, and it goes back when they are dropped.
#[derive(Clone, Debug)]
pub struct RequestTrailers {
    fields: Fields,
}

impl RequestTrailers {
    /// Trailers the connection checked.
    pub(super) fn new(fields: Fields) -> RequestTrailers {
        RequestTrailers { fields }
    }

    /// The fields, in order.
    pub fn fields(&self) -> &Fields {
        &self.fields
    }

    /// The fields in a map. It allocates.
    pub fn to_http(&self) -> HeaderMap {
        let mut map = HeaderMap::with_capacity(self.fields.len());
        for (name, value) in self.fields.iter() {
            if let (Ok(name), Ok(value)) =
                (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
            {
                map.append(name, value);
            }
        }
        map
    }
}

/// What comes up an exchange.
#[derive(Debug)]
pub enum ExchangeEvent {
    /// The next bytes of the request's body. Each byte uses one unit of
    /// the child's credit.
    Data(Chunk),
    /// The request's trailers. The request has ended.
    Trailers(RequestTrailers),
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
