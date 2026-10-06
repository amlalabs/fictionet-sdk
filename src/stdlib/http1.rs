//! HTTP/1 request and response heads and bodies, with RFC 9112 framing.
//!
//! Content-Length, chunked bodies, connection close, Expect: 100-continue,
//! and CONNECT handoff use the shared codec drivers. Non-empty trailers and
//! chunk extensions are refused. Requests ignore Upgrade offers and continue
//! as HTTP; 101 responses end HTTP for handoff without handling Upgrade.

use fictionet::stdlib::codec::{
    Buffer, Decode, Ending, Fail, LineError, Lines, PumpError, Step, Stream, Wire, finish, try_pump,
};
use fictionet::stdlib::json;
use std::collections::VecDeque;
use std::fmt;

/// The largest owned body accepted by [`Request`] and [`Response`]: 8 MiB.
/// The event decoders [`Requests`] and [`Responses`] have no total body limit.
pub const MAX_BODY: usize = 8 << 20;
/// The largest whole message retained for exact forwarding: 9 MiB.
/// This includes the head, body, and all chunk framing.
pub const MAX_MESSAGE: usize = 9 << 20;
/// The largest chunk-size line, excluding CRLF: 128 bytes.
pub const MAX_CHUNK_LINE: usize = 128;
/// The most request methods waiting for responses: 128.
pub const MAX_PENDING_REQUESTS: usize = 128;
/// The most empty CRLF lines ignored before each request line: eight.
pub const MAX_EMPTY_LINES: usize = 8;

/// Head and streaming buffer limits. Line lengths exclude CRLF.
///
/// Defaults are 8 KiB per start line, 8 KiB per header line, 100 headers,
/// 64 KiB for the complete head, and 8 KiB per body event. The head limit
/// includes every CRLF and the final empty line. Decoders clamp byte limits
/// to [`Buffer::MAX_LIMIT`] and raise a zero body block size to one.
/// Ignored empty lines before a request do not count toward its head limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum start-line content bytes. Default: 8192.
    pub start_line: usize,
    /// Maximum header-line content bytes. Default: 8192.
    pub header_line: usize,
    /// Maximum header fields. Default: 100.
    pub headers: usize,
    /// Maximum complete head bytes. Default: 65536.
    pub head: usize,
    /// Maximum bytes in one body event. Default: 8192.
    /// Blocks end when full, at a wire chunk boundary, or at body end.
    /// Boundaries do not depend on input chunking. Use smaller blocks for
    /// low latency on close-delimited streams.
    pub body_chunk: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            start_line: 8192,
            header_line: 8192,
            headers: 100,
            head: 65536,
            body_chunk: 8192,
        }
    }
}

impl Limits {
    fn bounded(self) -> Self {
        Self {
            start_line: self.start_line.min(Buffer::MAX_LIMIT.saturating_sub(2)),
            header_line: self.header_line.min(Buffer::MAX_LIMIT.saturating_sub(2)),
            head: self.head.min(Buffer::MAX_LIMIT),
            body_chunk: self.body_chunk.clamp(1, Buffer::MAX_LIMIT),
            ..self
        }
    }
}

/// A framing, syntax, limit, or writer error. Each decode error is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The start line exceeds `Limits::start_line`.
    StartLineTooLong,
    /// A header line exceeds `Limits::header_line`.
    HeaderLineTooLong,
    /// The number of fields exceeds `Limits::headers`.
    TooManyHeaders,
    /// The complete head exceeds `Limits::head`.
    HeadTooLong,
    /// A line does not end in CRLF.
    LineEnding,
    /// A Wire value ends early, or EOF leaves unfinished body framing with
    /// no unread bytes. Partial buffered units use the driver's Truncated.
    Incomplete,
    /// Extra bytes follow a complete value passed to `Wire::parse`.
    Trailing,
    /// A method, target, status line, or reason phrase is invalid.
    StartLine,
    /// Only HTTP/1.0 and HTTP/1.1 are supported.
    Version,
    /// A field name, value, or folded field is invalid.
    Header,
    /// HTTP/1.1 requires exactly one syntactically valid Host field.
    Host,
    /// Content-Length is empty, invalid, or exceeds `u64`.
    ContentLength,
    /// Content-Length values disagree, including comma-separated values.
    ConflictingContentLength,
    /// Transfer-Encoding and Content-Length occur together.
    TransferEncodingAndContentLength,
    /// Transfer-Encoding is empty, malformed, or has unsupported parameters.
    TransferEncoding,
    /// Chunked is repeated or is not the last transfer coding.
    ChunkedNotLast,
    /// A request's Transfer-Encoding does not end in chunked.
    RequestTransferEncoding,
    /// HTTP/1.0 cannot use Transfer-Encoding.
    Http10TransferEncoding,
    /// A writer found forbidden framing fields on 1xx, 204, or CONNECT 2xx.
    ForbiddenFraming,
    /// A writer or Wire parser refuses a 101 protocol switch. The streaming
    /// response decoders accept it only to end HTTP for handoff.
    Upgrade,
    /// The chunk-size line exceeds [`MAX_CHUNK_LINE`].
    ChunkLineTooLong,
    /// A chunk size is invalid or exceeds `u64`.
    ChunkSize,
    /// Chunk extensions are refused, including extensions on the last chunk.
    ChunkExtension,
    /// Chunk data is not followed by CRLF.
    ChunkEnding,
    /// A non-empty trailer section is outside this module's scope.
    Trailers,
    /// An owned body exceeds its configured byte limit or [`MAX_BODY`].
    BodyTooLong,
    /// A whole message exceeds its wire byte limit, including chunk framing.
    MessageTooLong,
    /// A body does not agree with its head's framing.
    BodyLength,
    /// The response method queue is full.
    TooManyRequests,
    /// The framing state or buffer accounting is inconsistent.
    State,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StartLineTooLong => "HTTP start line exceeds limit",
            Self::HeaderLineTooLong => "HTTP header line exceeds limit",
            Self::TooManyHeaders => "HTTP header count exceeds limit",
            Self::HeadTooLong => "HTTP head exceeds limit",
            Self::LineEnding => "HTTP lines require CRLF",
            Self::Incomplete => "incomplete HTTP message",
            Self::Trailing => "bytes follow the HTTP value",
            Self::StartLine => "invalid HTTP start line",
            Self::Version => "unsupported HTTP version",
            Self::Header => "invalid HTTP header",
            Self::Host => "invalid or missing HTTP Host field",
            Self::ContentLength => "invalid HTTP Content-Length",
            Self::ConflictingContentLength => "differing HTTP Content-Length values",
            Self::TransferEncodingAndContentLength => {
                "Transfer-Encoding with Content-Length is refused"
            }
            Self::TransferEncoding => "invalid or unsupported HTTP Transfer-Encoding",
            Self::ChunkedNotLast => "chunked must occur once and last",
            Self::RequestTransferEncoding => "request transfer coding must end in chunked",
            Self::Http10TransferEncoding => "HTTP/1.0 cannot use Transfer-Encoding",
            Self::ForbiddenFraming => "framing fields are forbidden for this response",
            Self::Upgrade => "HTTP Upgrade is not supported",
            Self::ChunkLineTooLong => "HTTP chunk-size line exceeds limit",
            Self::ChunkSize => "invalid or overflowing HTTP chunk size",
            Self::ChunkExtension => "HTTP chunk extensions are not supported",
            Self::ChunkEnding => "HTTP chunk data requires CRLF",
            Self::Trailers => "non-empty HTTP trailers are not supported",
            Self::BodyTooLong => "owned HTTP body exceeds limit",
            Self::MessageTooLong => "HTTP message wire bytes exceed limit",
            Self::BodyLength => "HTTP body does not match its framing",
            Self::TooManyRequests => "HTTP response method queue is full",
            Self::State => "inconsistent HTTP framing state",
        })
    }
}
impl std::error::Error for Error {}

/// Supported HTTP versions. HTTP/1.0 defaults to closing the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0, with optional explicit keep-alive.
    Http10,
    /// HTTP/1.1, with persistent connections by default.
    Http11,
}

impl Version {
    /// Returns the exact start-line spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

/// An owned header. Order, duplicate fields, and name casing are preserved.
/// Values are bytes, so non-UTF-8 field content is preserved. Parsing removes
/// outer spaces and tabs. Writers refuse outer whitespace in constructed
/// values, invalid token names, and controls other than horizontal tab.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// A non-empty ASCII token.
    pub name: String,
    /// The field value without outer whitespace.
    pub value: Vec<u8>,
}

/// An HTTP request head. The body follows separately.
///
/// `Wire` reads and writes exactly a head, using default limits. No body is
/// required to write a head; [`Request`] validates the complete body length.
/// HTTP/1.1 requires one Host field, which may be empty. Obsolete folding
/// is refused. Upgrade offers are accepted without switching protocols.
///
/// ```
/// use fictionet::stdlib::{codec::Wire, http1::RequestHead};
/// let head = RequestHead::parse(b"POST /tools HTTP/1.1\r\nHost: example.test\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n")?;
/// assert!(head.expects_continue());
/// assert!(head.keep_alive()?);
/// # Ok::<(), fictionet::stdlib::http1::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHead {
    /// Case-sensitive method token.
    pub method: String,
    /// Request target, preserved as visible ASCII. Fragments are refused.
    pub target: String,
    /// Start-line protocol version.
    pub version: Version,
    /// Ordered header fields.
    pub headers: Vec<Header>,
}

impl RequestHead {
    /// Whether an HTTP/1.1 Expect field contains `100-continue`.
    /// HTTP/1.0 expectations are ignored (RFC 9110 section 10.1.1).
    pub fn expects_continue(&self) -> bool {
        self.version == Version::Http11 && has_option(&self.headers, "expect", b"100-continue")
    }
    /// Whether the head permits another HTTP message after this one.
    /// CONNECT still requires the connection owner to handle the response.
    pub fn keep_alive(&self) -> Result<bool, Error> {
        Ok(!fields(&self.headers, self.version)?.close)
    }
}

/// An HTTP response head with an uninterpreted byte reason phrase.
///
/// `Wire` reads and writes exactly the head with default limits. A head can
/// be sent before a streamed body. Use [`ResponseHead::continue_100`] to
/// accept a request body after `Expect: 100-continue`.
/// [`Responses`] accepts Content-Length on 204 and 1xx responses other than 101,
/// including `Content-Length: 0`, and reads no body. The writer and Wire
/// parser refuse those fields because RFC 9110 forbids sending them.
///
/// ```
/// use fictionet::stdlib::{codec::Wire, http1::ResponseHead};
/// let bytes = ResponseHead::continue_100().to_bytes()?;
/// assert_eq!(bytes, b"HTTP/1.1 100 Continue\r\n\r\n");
/// # Ok::<(), fictionet::stdlib::http1::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    /// Start-line protocol version.
    pub version: Version,
    /// Three-digit status in the range 100 through 599.
    pub status: u16,
    /// Reason phrase; spaces, tabs, visible ASCII, and non-ASCII bytes.
    pub reason: Vec<u8>,
    /// Ordered header fields.
    pub headers: Vec<Header>,
}

impl ResponseHead {
    /// Creates an HTTP/1.1 interim `100 Continue` head with no fields.
    pub fn continue_100() -> Self {
        Self {
            version: Version::Http11,
            status: 100,
            reason: b"Continue".to_vec(),
            headers: Vec::new(),
        }
    }
    /// Whether connection options permit reuse. A close-delimited body still
    /// ends the connection even when this method returns true.
    pub fn keep_alive(&self) -> Result<bool, Error> {
        Ok(!fields(&self.headers, self.version)?.close)
    }
}

/// One streamed message event. Every message emits Head, zero or more Body
/// events, then Done. Done is a message boundary; [`Step::End`] ends HTTP.
///
/// Body bytes have chunked framing removed. Other transfer codings stay
/// encoded and named in the head. Transfer coding parameters are refused.
/// Chunked must occur once and last; an invalid order is always refused.
/// Events depend on their head for writing;
/// they are not independent `Wire` values. Use heads and [`Chunk`] for
/// streaming output, or [`Request`] and [`Response`] for generic Wire tools.
/// Feed Body bytes to a `Collect<M>` and end it at Done to parse a bounded
/// JSON or other payload. `Pipe` suits a continuous body such as SSE; it ends
/// its inner stream only when HTTP ends, not at each Done event. Use a separate
/// Collect per body when the inner value needs EOF. `Assemble` can join Body
/// events with an empty final fragment at Done while passing heads through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<H> {
    /// A complete head, before any body bytes are consumed.
    Head(H),
    /// A non-empty block of body bytes.
    Body(Vec<u8>),
    /// The current message is complete.
    Done,
}

/// Streaming requests built on [`Lines`], with bounded input and no body
/// accumulation. Chunk extensions and non-empty trailers are refused.
/// Framing follows [RFC 9112 section 6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3),
/// with strict refusal of ambiguous length fields and unsupported features.
///
/// Capacity is the larger of the head limit, body block size, and 130 bytes.
/// No input bytes are held outside the driver's buffer. Head scanning is
/// linear even when fed one byte at a time. After Connection: close, Done
/// is followed by End. Every CONNECT request also ends HTTP after Done.
/// To accept it, send a 2xx response and use [`Stream::into_parts`] for the
/// unread tunnel bytes. To reject it and keep reading HTTP, use
/// `stream.swap(Requests::new(limits))`, or close the connection.
/// Upgrade offers are treated as ordinary HTTP requests. Up to
/// [`MAX_EMPTY_LINES`] empty CRLF lines are ignored before each request line.
/// A partial buffered head or body returns Need at EOF for the driver's
/// Truncated error. EOF between body parts with no unread bytes reports
/// [`Error::Incomplete`]; Need on an empty buffer would mean a clean end.
///
/// ```
/// use fictionet::stdlib::{codec::Stream, http1::{Event, Limits, Requests}};
/// let mut stream = Stream::new(Requests::new(Limits::default()));
/// let bytes = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
/// assert_eq!(stream.push(bytes), bytes.len());
/// assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
/// assert_eq!(stream.next(), Some(Ok(Event::Done)));
/// ```
pub struct Requests {
    core: Reader,
    empty_lines: usize,
}

impl Requests {
    /// Creates a request decoder with the given limits.
    pub fn new(limits: Limits) -> Self {
        Self {
            core: Reader::new(limits),
            empty_lines: 0,
        }
    }
}

impl Default for Requests {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Decode for Requests {
    type Item = Event<RequestHead>;
    type Error = Error;
    const NAME: &'static str = "HTTP/1 requests";
    fn capacity(&self) -> usize {
        self.core.capacity()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Error> {
        if let Some(step) = self.core.body(input, eof)? {
            return Ok(step);
        }
        if self.core.scanned == 0 {
            if input == b"\r" {
                return Ok(Step::Need);
            }
            if input.starts_with(b"\r\n") {
                if self.empty_lines >= MAX_EMPTY_LINES {
                    return Err(Error::StartLine);
                }
                self.empty_lines = self.empty_lines.saturating_add(1);
                self.core.lines = Lines::new(self.core.limits.start_line, Ending::Crlf);
                return Ok(Step::Skip(2));
            }
        }
        let Some(n) = self.core.head(input)? else {
            return Ok(Step::Need);
        };
        let (head, info, framing) = request_head(&input[..n])?;
        self.empty_lines = 0;
        self.core
            .begin(framing, info.close || head.method == "CONNECT");
        Ok(Step::Item(Event::Head(head), n))
    }
}

/// Streaming responses, with the same event shape and limits as [`Requests`].
///
/// Queue request methods in send order with [`expect_method`](Self::expect_method).
/// Informational responses leave the first method queued; final responses
/// remove it. If no method is queued, ordinary (GET) framing is used. The
/// queue stores only three method classes, at most [`MAX_PENDING_REQUESTS`]
/// bytes of held state. Queue before feeding the corresponding response.
/// HEAD, 1xx, 204, and 304 have no body. A successful CONNECT ends HTTP after
/// Done, leaving tunnel bytes in `Stream::into_parts`. A response without a
/// length or final chunked coding ends at EOF. Status 101 also ends HTTP
/// after Done for handoff. Upgrade negotiation is left to the caller.
/// Valid length fields on bodyless responses do not create a body. Conflicting
/// lengths and Transfer-Encoding with Content-Length are always refused.
/// Writers additionally refuse framing fields forbidden by HTTP semantics.
///
/// ```
/// use fictionet::stdlib::{codec::Stream, http1::{Event, Responses}};
/// let mut decoder = Responses::default();
/// decoder.expect_method("HEAD")?;
/// let mut stream = Stream::new(decoder);
/// let bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
/// assert_eq!(stream.push(bytes), bytes.len());
/// assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
/// assert_eq!(stream.next(), Some(Ok(Event::Done)));
/// # Ok::<(), fictionet::stdlib::http1::Error>(())
/// ```
pub struct Responses {
    core: Reader,
    methods: VecDeque<Method>,
    strict: bool,
}

impl Responses {
    /// Creates a response decoder with the given limits.
    pub fn new(limits: Limits) -> Self {
        Self {
            core: Reader::new(limits),
            methods: VecDeque::new(),
            strict: false,
        }
    }
    /// Queues a request method. Invalid tokens and a full queue are refused
    /// without changing the queue. Method names are case-sensitive.
    pub fn expect_method(&mut self, method: &str) -> Result<(), Error> {
        let method = Method::parse(method)?;
        if self.methods.len() >= MAX_PENDING_REQUESTS {
            return Err(Error::TooManyRequests);
        }
        self.methods.push_back(method);
        Ok(())
    }
}

impl Default for Responses {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Decode for Responses {
    type Item = Event<ResponseHead>;
    type Error = Error;
    const NAME: &'static str = "HTTP/1 responses";
    fn capacity(&self) -> usize {
        self.core.capacity()
    }
    fn held(&self) -> usize {
        self.methods.len()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Error> {
        if let Some(step) = self.core.body(input, eof)? {
            return Ok(step);
        }
        let Some(n) = self.core.head(input)? else {
            return Ok(Step::Need);
        };
        let (head, info) = response_head(&input[..n])?;
        let method = self.methods.front().copied().unwrap_or(Method::Other);
        let framing = if self.strict {
            writable_response(&head, info, method)?
        } else {
            response_framing(&head, info, method)?
        };
        response_size(&head, self.core.limits)?;
        let tunnel =
            head.status == 101 || (method == Method::Connect && (200..300).contains(&head.status));
        if head.status >= 200 {
            self.methods.pop_front();
        }
        self.core
            .begin(framing, (head.status >= 200 && info.close) || tunnel);
        Ok(Step::Item(Event::Head(head), n))
    }
}

/// Whole requests on a persistent connection, built from [`Requests`].
///
/// Each item consumes its complete wire message. These message decoders give
/// generic tools whole messages. [`Stream::with_next`] exposes the original
/// head and all chunk-size lines and endings with each item.
/// The driver's buffer retains these bytes until Done. The decoder holds
/// only scan positions, which keep one-byte feeding linear, and builds the
/// head and body from the buffer in one pass at Done. Leading empty CRLF
/// lines remain skips.
///
/// Default bounds are [`MAX_BODY`] for the decoded body and [`MAX_MESSAGE`]
/// for the wire message. A message can reach either limit first. A
/// Content-Length or chunk size that cannot fit is refused from its header. Use
/// [`Requests`] when the body must be streamed without accumulation.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire, test_support}, http1::RequestMessages};
/// let bytes = b"GET / HTTP/1.1\r\nHost:test\r\n\r\nGET /next HTTP/1.1\r\nHost:test\r\n\r\n";
/// let mut stream = Stream::new(RequestMessages::default());
/// assert_eq!(stream.push(bytes), bytes.len());
/// let mut raw = Vec::new();
/// let mut encoded = Vec::new();
/// let mut requests = Vec::new();
/// while let Some(result) = stream.with_next(|request, wire, range| {
///     assert_eq!(range.start, u64::try_from(raw.len()).unwrap());
///     raw.extend_from_slice(wire);
///     assert_eq!(range.end, u64::try_from(raw.len()).unwrap());
///     request
/// }) {
///     let request = result?;
///     request.write(&mut encoded)?;
///     requests.push(request);
/// }
/// assert_eq!(raw, bytes);
/// assert_eq!(requests.len(), 2);
/// assert_eq!(test_support::decode_all(RequestMessages::default, &encoded), (requests, None));
/// assert!(!stream.is_done());
/// stream.end();
/// assert!(stream.next().is_none());
/// assert!(stream.is_done());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct RequestMessages {
    inner: Requests,
    message: Message,
}

impl RequestMessages {
    /// Creates a decoder with these head limits and default message bounds.
    pub fn new(limits: Limits) -> Self {
        Self::with_limits(limits, MAX_BODY, MAX_MESSAGE)
    }
    /// Creates a decoder with smaller body and wire byte bounds. Bounds
    /// are clamped to MAX_BODY and MAX_MESSAGE. Head limits are unchanged.
    pub fn with_limits(mut limits: Limits, body: usize, wire: usize) -> Self {
        let message = Message::new(body, wire);
        limits.body_chunk = limits.body_chunk.min(message.body_limit.saturating_add(1));
        Self {
            inner: Requests::new(limits),
            message,
        }
    }
}

impl Default for RequestMessages {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Decode for RequestMessages {
    type Item = Request;
    type Error = Error;
    const NAME: &'static str = "HTTP/1 whole requests";
    fn capacity(&self) -> usize {
        self.message.capacity()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Request>, Error> {
        Ok(map_message(
            self.message.decode(&mut self.inner, input, eof)?,
            |head, body| Request { head, body },
        ))
    }
}

/// Whole responses on a persistent connection, built from [`Responses`].
///
/// Wire bytes and held state have the same bounds and accounting as
/// [`RequestMessages`]. Informational responses are separate items. A
/// close-delimited response needs EOF. Queue methods before the matching
/// response with [`Self::expect_method`]. Forwarding preserves HEAD and
/// CONNECT bytes; replacements of those responses need [`Response::write_for`].
pub struct ResponseMessages {
    inner: Responses,
    message: Message,
}

impl ResponseMessages {
    /// Creates a decoder with these head limits and default message bounds.
    pub fn new(limits: Limits) -> Self {
        Self::with_limits(limits, MAX_BODY, MAX_MESSAGE)
    }
    /// Creates a decoder with body and wire byte bounds, clamped to MAX_BODY
    /// and MAX_MESSAGE. Head limits are unchanged.
    pub fn with_limits(mut limits: Limits, body: usize, wire: usize) -> Self {
        let message = Message::new(body, wire);
        limits.body_chunk = limits.body_chunk.min(message.body_limit.saturating_add(1));
        Self {
            inner: Responses::new(limits),
            message,
        }
    }
    /// Queues a method with the same validation and bound as
    /// [`Responses::expect_method`]. Interim responses keep it queued.
    pub fn expect_method(&mut self, method: &str) -> Result<(), Error> {
        self.inner.expect_method(method)
    }
}

impl Default for ResponseMessages {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Decode for ResponseMessages {
    type Item = Response;
    type Error = Error;
    const NAME: &'static str = "HTTP/1 whole responses";
    fn capacity(&self) -> usize {
        self.message.capacity()
    }
    fn held(&self) -> usize {
        self.inner.held()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Response>, Error> {
        Ok(map_message(
            self.message.decode(&mut self.inner, input, eof)?,
            |head, body| Response { head, body },
        ))
    }
}

// The raw message stays in the driver, so generic tools need no HTTP path.
// Only scan positions into the stable unread slice live here. The head and
// body are built from that slice in one pass when the message is done.
struct Message {
    // Head length once the inner decoder has read a head.
    head_bytes: Option<usize>,
    // Body framing chosen by that head, for the final pass.
    framing: State,
    body_bytes: usize,
    scanned: usize,
    body_limit: usize,
    wire_limit: usize,
}

// What a whole-message decoder needs from its streaming decoder.
trait Framed<H>: Decode<Item = Event<H>, Error = Error> {
    fn reader(&self) -> &Reader;
    fn parse_head(bytes: &[u8]) -> Result<H, Error>;
}

impl Framed<RequestHead> for Requests {
    fn reader(&self) -> &Reader {
        &self.core
    }
    fn parse_head(bytes: &[u8]) -> Result<RequestHead, Error> {
        Ok(request_head(bytes)?.0)
    }
}

impl Framed<ResponseHead> for Responses {
    fn reader(&self) -> &Reader {
        &self.core
    }
    fn parse_head(bytes: &[u8]) -> Result<ResponseHead, Error> {
        Ok(response_head(bytes)?.0)
    }
}

impl Message {
    fn new(body: usize, wire: usize) -> Self {
        Self {
            head_bytes: None,
            framing: State::Done,
            body_bytes: 0,
            scanned: 0,
            body_limit: body.min(MAX_BODY),
            wire_limit: wire.min(MAX_MESSAGE),
        }
    }
    fn capacity(&self) -> usize {
        self.wire_limit.saturating_add(1)
    }
    // Refuses a declared length or chunk size that cannot fit, before any
    // of its bytes arrive.
    fn check_declared(&self, state: State) -> Result<(), Error> {
        let (State::Length(n) | State::Data(n)) = state else {
            return Ok(());
        };
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        if self.body_bytes.saturating_add(n) > self.body_limit {
            return Err(Error::BodyTooLong);
        }
        if self.scanned.saturating_add(n) > self.wire_limit {
            return Err(Error::MessageTooLong);
        }
        Ok(())
    }
    fn decode<H, D: Framed<H>>(
        &mut self,
        inner: &mut D,
        input: &[u8],
        eof: bool,
    ) -> Result<Step<(H, Vec<u8>)>, Error> {
        let window = &input[..input.len().min(self.wire_limit)];
        loop {
            let rest = window.get(self.scanned..).ok_or(Error::State)?;
            let step = inner.decode(rest, eof && input.len() <= self.wire_limit)?;
            let used = match step {
                Step::Item(Event::Head(_), n) => {
                    if self.head_bytes.is_some() {
                        return Err(Error::State);
                    }
                    self.head_bytes = Some(n);
                    self.framing = inner.reader().state;
                    n
                }
                Step::Item(Event::Body(data), n) => {
                    self.body_bytes = self
                        .body_bytes
                        .checked_add(data.len())
                        .filter(|n| *n <= self.body_limit)
                        .ok_or(Error::BodyTooLong)?;
                    n
                }
                Step::Item(Event::Done, n) => {
                    let used = self.scanned.checked_add(n).ok_or(Error::MessageTooLong)?;
                    let head_bytes = self.head_bytes.take().ok_or(Error::State)?;
                    let bytes = window.get(..used).ok_or(Error::State)?;
                    let head = D::parse_head(&bytes[..head_bytes])?;
                    let body = collect_body(
                        inner.reader().limits,
                        self.framing,
                        &bytes[head_bytes..],
                        self.body_bytes,
                    )?;
                    self.body_bytes = 0;
                    self.scanned = 0;
                    return Ok(Step::Item((head, body), used));
                }
                Step::Skip(n) if self.head_bytes.is_none() => return Ok(Step::Skip(n)),
                Step::Skip(n) => n,
                Step::Need => {
                    if input.len() > self.wire_limit {
                        return Err(Error::MessageTooLong);
                    }
                    return Ok(Step::Need);
                }
                Step::End => {
                    return if self.head_bytes.is_some() {
                        Err(Error::Incomplete)
                    } else {
                        Ok(Step::End)
                    };
                }
            };
            if used == 0 || used > rest.len() {
                return Err(Error::State);
            }
            self.scanned = self
                .scanned
                .checked_add(used)
                .ok_or(Error::MessageTooLong)?;
            self.check_declared(inner.reader().state)?;
        }
    }
}

// Removes the framing from a complete body the scan already checked.
fn collect_body(
    limits: Limits,
    framing: State,
    bytes: &[u8],
    size: usize,
) -> Result<Vec<u8>, Error> {
    let mut reader = Reader::new(limits);
    reader.state = framing;
    reader.lines = Lines::new(MAX_CHUNK_LINE, Ending::Crlf);
    let mut body = Vec::new();
    body.try_reserve_exact(size)
        .map_err(|_| Error::BodyTooLong)?;
    let mut at = 0;
    loop {
        let rest = bytes.get(at..).ok_or(Error::State)?;
        let n = match reader.body::<()>(rest, true)? {
            Some(Step::Item(Event::Body(data), n)) => {
                body.extend_from_slice(&data);
                n
            }
            Some(Step::Skip(n)) => n,
            Some(Step::Item(Event::Done, _)) if rest.is_empty() && body.len() == size => {
                return Ok(body);
            }
            _ => return Err(Error::State),
        };
        if n == 0 {
            return Err(Error::State);
        }
        at = at.checked_add(n).ok_or(Error::State)?;
    }
}

fn map_message<H, T>(step: Step<(H, Vec<u8>)>, f: impl FnOnce(H, Vec<u8>) -> T) -> Step<T> {
    match step {
        Step::Item((head, body), n) => Step::Item(f(head, body), n),
        Step::Skip(n) => Step::Skip(n),
        Step::Need => Step::Need,
        Step::End => Step::End,
    }
}

/// One complete request for proxies, recorders, and item fault tools.
///
/// The body has chunked framing removed and is bounded by [`MAX_BODY`].
/// `Wire` uses default head limits. `Collect<Request>` reads exactly one
/// bounded wire message at EOF; use [`RequestMessages`] for persistent streams.
/// Editing a body requires updating Content-Length, or choosing chunked.
/// Writers validate the entire message before appending any bytes.
///
/// ```
/// use fictionet::stdlib::{codec::{Collect, Stream, Wire}, http1::Request};
/// let mut stream = Stream::new(Collect::<Request>::new(4096));
/// let bytes = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\none";
/// assert_eq!(stream.push(bytes), bytes.len());
/// stream.end();
/// let mut request = stream.next().unwrap()?;
/// request.body.copy_from_slice(b"two");
/// assert!(request.to_bytes()?.ends_with(b"two"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Request metadata, available for header rewriting.
    pub head: RequestHead,
    /// Body bytes, with chunked framing removed.
    pub body: Vec<u8>,
}

/// One complete response, bounded by [`MAX_BODY`] and default head limits.
///
/// `Wire` and `Collect<Response>` use ordinary GET response framing.
/// HEAD and CONNECT need the request method: use [`parse_for`](Self::parse_for)
/// and [`write_for`](Self::write_for), or [`Responses::expect_method`]. Method
/// context is not a wire field. A close-delimited response uses the end of
/// the supplied slice as EOF; the sender must then close its connection.
///
/// ```
/// use fictionet::stdlib::{codec::Wire, http1::Response};
/// let mut response = Response::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
/// response.body = b"[]".to_vec();
/// assert!(response.to_bytes()?.ends_with(b"[]"));
/// # Ok::<(), fictionet::stdlib::http1::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Response metadata, available for header rewriting.
    pub head: ResponseHead,
    /// Body bytes, with chunked framing removed.
    pub body: Vec<u8>,
}

impl Response {
    /// Creates an empty HTTP/1.1 response with an empty reason phrase.
    /// Adds Content-Length: 0 except for 1xx, 204, and 304 responses.
    /// The writer validates the status before emitting any bytes.
    pub fn status(status: u16) -> Self {
        let mut headers = Vec::new();
        if status >= 200 && status != 204 && status != 304 {
            headers.push(Header {
                name: "Content-Length".into(),
                value: b"0".to_vec(),
            });
        }
        Self {
            head: ResponseHead {
                version: Version::Http11,
                status,
                reason: Vec::new(),
                headers,
            },
            body: Vec::new(),
        }
    }
    /// Creates a 200 response with application/json and an exact
    /// Content-Length. Copies at most MAX_BODY bytes. The caller supplies
    /// encoded JSON; this constructor does not parse or normalize it.
    pub fn json(body: &[u8]) -> Result<Self, Error> {
        if body.len() > MAX_BODY {
            return Err(Error::BodyTooLong);
        }
        Ok(Self::with_content(200, "application/json", body.to_vec()))
    }
    /// Creates the head that opens a 200 event stream for an MCP session.
    /// Sets text/event-stream, Cache-Control: no-cache, Mcp-Session-Id,
    /// and Transfer-Encoding: chunked. Write the head, then write each
    /// encoded SSE event through [`Chunk`]. An empty Chunk ends the stream.
    /// No body or final chunk is written by this head's Wire implementation.
    /// Invalid session field bytes are refused when the head is written.
    ///
    /// ```
    /// use fictionet::stdlib::{codec::Wire, http1::{Chunk, Response}};
    /// let mut out = Response::event_stream("session-1").to_bytes()?;
    /// Chunk(b"data: {}\n\n".to_vec()).write(&mut out)?;
    /// Chunk(Vec::new()).write(&mut out)?;
    /// assert_eq!(Response::parse(&out)?.body, b"data: {}\n\n");
    /// # Ok::<(), fictionet::stdlib::http1::Error>(())
    /// ```
    pub fn event_stream(session_id: &str) -> ResponseHead {
        ResponseHead {
            version: Version::Http11,
            status: 200,
            reason: Vec::new(),
            headers: vec![
                Header {
                    name: "Content-Type".into(),
                    value: b"text/event-stream".to_vec(),
                },
                Header {
                    name: "Cache-Control".into(),
                    value: b"no-cache".to_vec(),
                },
                Header {
                    name: "Mcp-Session-Id".into(),
                    value: session_id.as_bytes().to_vec(),
                },
                Header {
                    name: "Transfer-Encoding".into(),
                    value: b"chunked".to_vec(),
                },
            ],
        }
    }
    /// Creates an application/problem+json response with `type` set to
    /// `about:blank`, the status, and the supplied detail. Uses [`json::Value`]
    /// to escape strings and set Content-Length from the encoded bytes.
    /// Refuses statuses outside 400..=599 and problems beyond [`json::MAX_SIZE`].
    pub fn problem(status: u16, detail: &str) -> Result<Self, Error> {
        if !(400..=599).contains(&status) {
            return Err(Error::StartLine);
        }
        if detail.len() > json::MAX_SIZE {
            return Err(Error::BodyTooLong);
        }
        let value = json::Value::Object(vec![
            ("type".into(), json::Value::from("about:blank")),
            ("status".into(), json::Value::from(u32::from(status))),
            ("detail".into(), json::Value::from(detail)),
        ]);
        let body = value.to_bytes().map_err(|_| Error::BodyTooLong)?;
        Ok(Self::with_content(status, "application/problem+json", body))
    }
    fn with_content(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            head: ResponseHead {
                version: Version::Http11,
                status,
                reason: Vec::new(),
                headers: vec![
                    Header {
                        name: "Content-Type".into(),
                        value: content_type.as_bytes().to_vec(),
                    },
                    Header {
                        name: "Content-Length".into(),
                        value: body.len().to_string().into_bytes(),
                    },
                ],
            },
            body,
        }
    }
    /// Parses exactly one response with the given request method. Tunnel
    /// bytes after a CONNECT head are trailing bytes here; use Responses
    /// and Stream for handoff. Informational responses are separate values.
    /// Applies the same field and framing validation as [`Self::write_for`].
    pub fn parse_for(bytes: &[u8], method: &str) -> Result<Self, Error> {
        let mut decoder = Responses::default();
        decoder.expect_method(method)?;
        decoder.strict = true;
        let (head, body) = whole(decoder, bytes)?;
        Ok(Self { head, body })
    }
    /// Appends a response using the given request method. Validates the
    /// entire value first. HEAD and successful CONNECT require empty bodies.
    /// A successful CONNECT writer refuses Content-Length and Transfer-Encoding.
    pub fn write_for(&self, method: &str, out: &mut Vec<u8>) -> Result<(), Error> {
        let method = Method::parse(method)?;
        let framing = validate_response_for(&self.head, method)?;
        validate_body(&self.body, framing)?;
        emit_response(&self.head, out);
        emit_body(&self.body, framing, out);
        Ok(())
    }
}

/// One bounded chunk for streaming output. An empty chunk writes the final
/// `0\r\n\r\n`; non-empty chunks write a hexadecimal size, data, and CRLF.
/// Extensions and trailers are refused. Each value is bounded by [`MAX_BODY`].
///
/// ```
/// use fictionet::stdlib::{codec::Wire, http1::Chunk};
/// let mut out = Chunk(b"hello".to_vec()).to_bytes()?;
/// Chunk(Vec::new()).write(&mut out)?;
/// assert_eq!(out, b"5\r\nhello\r\n0\r\n\r\n");
/// # Ok::<(), fictionet::stdlib::http1::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk(
    /// Chunk data; empty means the last chunk and an empty trailer section.
    pub Vec<u8>,
);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Method {
    Other,
    Head,
    Connect,
}
impl Method {
    fn parse(method: &str) -> Result<Self, Error> {
        if !token(method.as_bytes()) {
            return Err(Error::StartLine);
        }
        Ok(match method {
            "HEAD" => Self::Head,
            "CONNECT" => Self::Connect,
            _ => Self::Other,
        })
    }
}

#[derive(Clone, Copy)]
enum Framing {
    Empty,
    Length(u64),
    Chunked,
    Close,
}
#[derive(Clone, Copy)]
enum State {
    Head,
    Length(u64),
    Size,
    Data(u64),
    DataEnd,
    Trailers,
    Close,
    Done,
    Boundary,
    End,
}

struct Reader {
    limits: Limits,
    lines: Lines,
    scanned: usize,
    count: usize,
    state: State,
    close: bool,
}

impl Reader {
    fn new(limits: Limits) -> Self {
        let limits = limits.bounded();
        Self {
            limits,
            lines: Lines::new(limits.start_line, Ending::Crlf),
            scanned: 0,
            count: 0,
            state: State::Head,
            close: false,
        }
    }
    fn capacity(&self) -> usize {
        self.limits
            .head
            .max(self.limits.body_chunk)
            .max(MAX_CHUNK_LINE.saturating_add(2))
    }
    fn head(&mut self, input: &[u8]) -> Result<Option<usize>, Error> {
        loop {
            let rest = input.get(self.scanned..).ok_or(Error::State)?;
            let room = self.limits.head.saturating_sub(self.scanned);
            let window = &rest[..rest.len().min(room)];
            let step = match self.lines.decode(window, false) {
                Ok(s) => s,
                Err(e) => match e {},
            };
            match step {
                Step::Item(line, n) => {
                    let line = line.map_err(|e| match e {
                        LineError::TooLong { .. } if self.scanned == 0 => Error::StartLineTooLong,
                        LineError::TooLong { .. } => Error::HeaderLineTooLong,
                        _ => Error::LineEnding,
                    })?;
                    let first = self.scanned == 0;
                    self.scanned = self.scanned.checked_add(n).ok_or(Error::HeadTooLong)?;
                    if !first && line.is_empty() {
                        return Ok(Some(self.scanned));
                    }
                    if !first {
                        self.count = self.count.checked_add(1).ok_or(Error::TooManyHeaders)?;
                        if self.count > self.limits.headers {
                            return Err(Error::TooManyHeaders);
                        }
                    }
                    self.lines = Lines::new(self.limits.header_line, Ending::Crlf);
                }
                _ => {
                    if input.is_empty() && self.scanned == 0 {
                        return Ok(None);
                    }
                    if window.len() == room {
                        return Err(Error::HeadTooLong);
                    }
                    return Ok(None);
                }
            }
        }
    }
    fn begin(&mut self, framing: Framing, close: bool) {
        self.close = close;
        self.state = match framing {
            Framing::Empty | Framing::Length(0) => State::Done,
            Framing::Length(n) => State::Length(n),
            Framing::Chunked => State::Size,
            Framing::Close => {
                self.close = true;
                State::Close
            }
        };
        self.lines = Lines::new(MAX_CHUNK_LINE, Ending::Crlf);
    }
    fn body<H>(&mut self, input: &[u8], eof: bool) -> Result<Option<Step<Event<H>>>, Error> {
        let step = match self.state {
            State::Head => return Ok(None),
            State::Boundary => {
                if self.close {
                    self.state = State::End;
                    return Ok(Some(Step::End));
                }
                self.scanned = 0;
                self.count = 0;
                self.lines = Lines::new(self.limits.start_line, Ending::Crlf);
                self.state = State::Head;
                return Ok(None);
            }
            State::End => Step::End,
            State::Done => {
                self.state = State::Boundary;
                Step::Item(Event::Done, 0)
            }
            State::Length(left) | State::Data(left) => {
                let n = usize::try_from(left)
                    .unwrap_or(usize::MAX)
                    .min(self.limits.body_chunk);
                if input.len() < n {
                    Step::Need
                } else {
                    let remaining = left.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
                    self.state = match self.state {
                        State::Length(_) if remaining == 0 => State::Done,
                        State::Length(_) => State::Length(remaining),
                        _ if remaining == 0 => State::DataEnd,
                        _ => State::Data(remaining),
                    };
                    Step::Item(Event::Body(input[..n].to_vec()), n)
                }
            }
            State::Close => {
                let n = input.len().min(self.limits.body_chunk);
                if n == self.limits.body_chunk || (eof && n != 0) {
                    Step::Item(Event::Body(input[..n].to_vec()), n)
                } else if eof {
                    self.state = State::End;
                    Step::Item(Event::Done, 0)
                } else {
                    Step::Need
                }
            }
            State::Size | State::DataEnd | State::Trailers => {
                match chunk_framing(&mut self.lines, self.state, input)? {
                    Some((state, n)) => {
                        self.state = state;
                        Step::Skip(n)
                    }
                    None => Step::Need,
                }
            }
        };
        // Stream treats Need at empty EOF as a clean end. An unfinished
        // body with no buffered partial unit must still report a failure.
        if matches!(step, Step::Need) && eof && input.is_empty() {
            return Err(Error::Incomplete);
        }
        Ok(Some(step))
    }
}

fn chunk_framing(
    lines: &mut Lines,
    state: State,
    input: &[u8],
) -> Result<Option<(State, usize)>, Error> {
    if matches!(state, State::Size) {
        let step = match lines.decode(input, false) {
            Ok(s) => s,
            Err(e) => match e {},
        };
        let Step::Item(line, n) = step else {
            return Ok(None);
        };
        let line = line.map_err(|e| match e {
            LineError::TooLong { .. } => Error::ChunkLineTooLong,
            _ => Error::LineEnding,
        })?;
        let size = chunk_size(&line)?;
        return Ok(Some((
            if size == 0 {
                State::Trailers
            } else {
                State::Data(size)
            },
            n,
        )));
    }
    let trailer = matches!(state, State::Trailers);
    let error = if trailer {
        Error::Trailers
    } else {
        Error::ChunkEnding
    };
    if input.first().is_some_and(|b| *b != b'\r') {
        return Err(error);
    }
    let Some(second) = input.get(1) else {
        return Ok(None);
    };
    if *second != b'\n' {
        return Err(error);
    }
    Ok(Some((if trailer { State::Done } else { State::Size }, 2)))
}

fn token(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}
fn field_byte(b: u8) -> bool {
    b == b'\t' || (b >= b' ' && b != 127)
}
fn trim(mut b: &[u8]) -> &[u8] {
    while b.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        b = &b[1..];
    }
    while b.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
        b = &b[..b.len().saturating_sub(1)];
    }
    b
}
fn named<'a>(headers: &'a [Header], name: &'a str) -> impl Iterator<Item = &'a [u8]> {
    headers
        .iter()
        .filter(move |h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_slice())
}
fn has_option(headers: &[Header], name: &str, option: &[u8]) -> bool {
    named(headers, name)
        .flat_map(|v| v.split(|b| *b == b','))
        .any(|v| trim(v).eq_ignore_ascii_case(option))
}
fn version(b: &[u8]) -> Result<Version, Error> {
    match b {
        b"HTTP/1.0" => Ok(Version::Http10),
        b"HTTP/1.1" => Ok(Version::Http11),
        _ => Err(Error::Version),
    }
}
fn number(b: &[u8], radix: u32, error: Error) -> Result<u64, Error> {
    if b.is_empty() {
        return Err(error);
    }
    b.iter().try_fold(0u64, |n, b| {
        let digit = char::from(*b).to_digit(radix).ok_or(error)?;
        n.checked_mul(u64::from(radix))
            .and_then(|n| n.checked_add(u64::from(digit)))
            .ok_or(error)
    })
}
fn chunk_size(b: &[u8]) -> Result<u64, Error> {
    if b.contains(&b';') {
        return Err(Error::ChunkExtension);
    }
    number(b, 16, Error::ChunkSize)
}

#[derive(Clone, Copy)]
struct Fields {
    length: Option<u64>,
    transfer: bool,
    chunked: bool,
    close: bool,
}
fn fields(headers: &[Header], version: Version) -> Result<Fields, Error> {
    let mut result = Fields {
        length: None,
        transfer: false,
        chunked: false,
        close: false,
    };
    let mut keep = false;
    if named(headers, "transfer-encoding").next().is_some()
        && named(headers, "content-length").next().is_some()
    {
        return Err(Error::TransferEncodingAndContentLength);
    }
    for h in headers {
        if !token(h.name.as_bytes())
            || !h.value.iter().copied().all(field_byte)
            || trim(&h.value) != h.value
        {
            return Err(Error::Header);
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            for value in h.value.split(|b| *b == b',') {
                let n = number(trim(value), 10, Error::ContentLength)?;
                if result.length.is_some_and(|old| old != n) {
                    return Err(Error::ConflictingContentLength);
                }
                result.length = Some(n);
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            if version == Version::Http10 {
                return Err(Error::Http10TransferEncoding);
            }
            for value in h.value.split(|b| *b == b',') {
                let value = trim(value);
                if value.is_empty() {
                    continue;
                }
                if result.chunked {
                    return Err(Error::ChunkedNotLast);
                }
                if !token(value) {
                    return Err(Error::TransferEncoding);
                }
                result.transfer = true;
                result.chunked = value.eq_ignore_ascii_case(b"chunked");
            }
        } else if h.name.eq_ignore_ascii_case("connection") {
            for value in h.value.split(|b| *b == b',') {
                let value = trim(value);
                if value.is_empty() {
                    continue;
                }
                if !token(value) {
                    return Err(Error::Header);
                }
                result.close |= value.eq_ignore_ascii_case(b"close");
                keep |= value.eq_ignore_ascii_case(b"keep-alive");
            }
        }
    }
    if named(headers, "transfer-encoding").next().is_some() && !result.transfer {
        return Err(Error::TransferEncoding);
    }
    result.close |= version == Version::Http10 && !keep;
    Ok(result)
}
fn request_framing(info: Fields) -> Result<Framing, Error> {
    if info.transfer {
        if !info.chunked {
            return Err(Error::RequestTransferEncoding);
        }
        Ok(Framing::Chunked)
    } else {
        Ok(Framing::Length(info.length.unwrap_or(0)))
    }
}
fn response_framing(head: &ResponseHead, info: Fields, method: Method) -> Result<Framing, Error> {
    if head.status < 200 || head.status == 204 {
        return Ok(Framing::Empty);
    }
    if method == Method::Head
        || head.status == 304
        || (method == Method::Connect && (200..300).contains(&head.status))
    {
        return Ok(Framing::Empty);
    }
    Ok(if info.chunked {
        Framing::Chunked
    } else if info.transfer {
        Framing::Close
    } else if let Some(n) = info.length {
        Framing::Length(n)
    } else {
        Framing::Close
    })
}

fn split_head(b: &[u8]) -> Result<(&[u8], Vec<Header>), Error> {
    let mut lines = b.split(|b| *b == b'\n');
    let first = lines
        .next()
        .and_then(|b| b.strip_suffix(b"\r"))
        .ok_or(Error::LineEnding)?;
    let mut headers = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").ok_or(Error::LineEnding)?;
        if line.is_empty() {
            return Ok((first, headers));
        }
        let colon = line.iter().position(|b| *b == b':').ok_or(Error::Header)?;
        let name = &line[..colon];
        let value = trim(&line[colon.saturating_add(1)..]);
        headers.push(Header {
            name: String::from_utf8(name.to_vec()).map_err(|_| Error::Header)?,
            value: value.to_vec(),
        });
    }
    Err(Error::Incomplete)
}
fn valid_authority(value: &[u8], require_port: bool) -> bool {
    if value.is_empty()
        || !value.iter().all(|b| b.is_ascii_graphic())
        || value.iter().any(|b| b"/@?#,".contains(b))
    {
        return false;
    }
    let (host, port) = if value.starts_with(b"[") {
        let Some(end) = value.iter().position(|b| *b == b']') else {
            return false;
        };
        let Ok(ip) = std::str::from_utf8(&value[1..end]) else {
            return false;
        };
        if ip.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (&value[..=end], &value[end.saturating_add(1)..])
    } else {
        let at = value.iter().position(|b| *b == b':').unwrap_or(value.len());
        let host = &value[..at];
        if !host
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~%!$&'()*+;=".contains(b))
        {
            return false;
        }
        (host, &value[at..])
    };
    !host.is_empty()
        && if port.is_empty() {
            !require_port
        } else {
            port.first() == Some(&b':')
                && ((!require_port && port.len() == 1)
                    || number(&port[1..], 10, Error::Host).is_ok_and(|n| n <= 65535))
        }
}
fn validate_target(method: &str, target: &str) -> Result<(), Error> {
    if !token(method.as_bytes())
        || target.is_empty()
        || !target.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
    {
        return Err(Error::StartLine);
    }
    let valid = if method == "CONNECT" {
        valid_authority(target.as_bytes(), true)
    } else if target == "*" {
        method == "OPTIONS"
    } else if target.starts_with('/') {
        true
    } else if let Some((scheme, rest)) = target.split_once("://") {
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
            && valid_authority(authority.as_bytes(), false)
    } else {
        false
    };
    if valid { Ok(()) } else { Err(Error::StartLine) }
}
fn validate_host(head: &RequestHead) -> Result<(), Error> {
    let mut hosts = named(&head.headers, "host");
    match hosts.next() {
        None if head.version == Version::Http10 => Ok(()),
        Some(host)
            if (host.is_empty() || valid_authority(host, false)) && hosts.next().is_none() =>
        {
            Ok(())
        }
        _ => Err(Error::Host),
    }
}
fn request_head(b: &[u8]) -> Result<(RequestHead, Fields, Framing), Error> {
    let (line, headers) = split_head(b)?;
    let mut parts = line.split(|b| *b == b' ');
    let method = parts.next().ok_or(Error::StartLine)?;
    let target = parts.next().ok_or(Error::StartLine)?;
    let version = version(parts.next().ok_or(Error::StartLine)?)?;
    if parts.next().is_some() {
        return Err(Error::StartLine);
    }
    let head = RequestHead {
        method: String::from_utf8(method.to_vec()).map_err(|_| Error::StartLine)?,
        target: String::from_utf8(target.to_vec()).map_err(|_| Error::StartLine)?,
        version,
        headers,
    };
    let (info, framing) = request_info(&head)?;
    Ok((head, info, framing))
}
fn response_head(b: &[u8]) -> Result<(ResponseHead, Fields), Error> {
    let (line, headers) = split_head(b)?;
    let mut parts = line.splitn(3, |b| *b == b' ');
    let version = version(parts.next().ok_or(Error::StartLine)?)?;
    let status = parts.next().ok_or(Error::StartLine)?;
    if status.len() != 3 {
        return Err(Error::StartLine);
    }
    let status =
        u16::try_from(number(status, 10, Error::StartLine)?).map_err(|_| Error::StartLine)?;
    let reason = parts.next().unwrap_or_default();
    if !(100..=599).contains(&status) || !reason.iter().copied().all(field_byte) {
        return Err(Error::StartLine);
    }
    let head = ResponseHead {
        version,
        status,
        reason: reason.to_vec(),
        headers,
    };
    let info = fields(&head.headers, head.version)?;
    Ok((head, info))
}

fn head_size(start: usize, headers: &[Header], limits: Limits) -> Result<(), Error> {
    if start > limits.start_line {
        return Err(Error::StartLineTooLong);
    }
    if headers.len() > limits.headers {
        return Err(Error::TooManyHeaders);
    }
    let mut total = start.checked_add(4).ok_or(Error::HeadTooLong)?;
    for h in headers {
        let line = h
            .name
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(h.value.len()))
            .ok_or(Error::HeaderLineTooLong)?;
        if line > limits.header_line {
            return Err(Error::HeaderLineTooLong);
        }
        total = total
            .checked_add(line)
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::HeadTooLong)?;
    }
    if total > limits.head {
        return Err(Error::HeadTooLong);
    }
    Ok(())
}
fn request_info(head: &RequestHead) -> Result<(Fields, Framing), Error> {
    validate_target(&head.method, &head.target)?;
    validate_host(head)?;
    let info = fields(&head.headers, head.version)?;
    Ok((info, request_framing(info)?))
}
fn validate_request(head: &RequestHead) -> Result<Framing, Error> {
    let (_, framing) = request_info(head)?;
    let start = head
        .method
        .len()
        .checked_add(head.target.len())
        .and_then(|n| n.checked_add(10))
        .ok_or(Error::StartLineTooLong)?;
    head_size(start, &head.headers, Limits::default())?;
    Ok(framing)
}
fn validate_response_for(head: &ResponseHead, method: Method) -> Result<Framing, Error> {
    if !(100..=599).contains(&head.status) || !head.reason.iter().copied().all(field_byte) {
        return Err(Error::StartLine);
    }
    let info = fields(&head.headers, head.version)?;
    response_size(head, Limits::default())?;
    writable_response(head, info, method)
}
fn response_size(head: &ResponseHead, limits: Limits) -> Result<(), Error> {
    head_size(
        head.reason
            .len()
            .checked_add(13)
            .ok_or(Error::StartLineTooLong)?,
        &head.headers,
        limits,
    )
}
fn writable_response(head: &ResponseHead, info: Fields, method: Method) -> Result<Framing, Error> {
    if head.status == 101 {
        return Err(Error::Upgrade);
    }
    if (head.status < 200
        || head.status == 204
        || (method == Method::Connect && (200..300).contains(&head.status)))
        && (info.length.is_some() || info.transfer)
    {
        return Err(Error::ForbiddenFraming);
    }
    response_framing(head, info, method)
}
fn emit_headers(headers: &[Header], out: &mut Vec<u8>) {
    for h in headers {
        out.extend_from_slice(h.name.as_bytes());
        out.push(b':');
        out.extend_from_slice(&h.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}
fn emit_request(head: &RequestHead, out: &mut Vec<u8>) {
    out.extend_from_slice(head.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.version.as_str().as_bytes());
    out.extend_from_slice(b"\r\n");
    emit_headers(&head.headers, out);
}
fn emit_response(head: &ResponseHead, out: &mut Vec<u8>) {
    out.extend_from_slice(head.version.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(&head.reason);
    out.extend_from_slice(b"\r\n");
    emit_headers(&head.headers, out);
}
fn validate_body(body: &[u8], framing: Framing) -> Result<(), Error> {
    if body.len() > MAX_BODY {
        return Err(Error::BodyTooLong);
    }
    match framing {
        Framing::Empty if !body.is_empty() => Err(Error::BodyLength),
        Framing::Length(n) if u64::try_from(body.len()).ok() != Some(n) => Err(Error::BodyLength),
        _ => Ok(()),
    }
}
fn emit_chunk(body: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n");
}
fn emit_body(body: &[u8], framing: Framing, out: &mut Vec<u8>) {
    if matches!(framing, Framing::Chunked) {
        if !body.is_empty() {
            emit_chunk(body, out);
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        out.extend_from_slice(body);
    }
}
fn exact_head(b: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(Limits::default());
    let n = reader.head(b)?.ok_or(Error::Incomplete)?;
    if n != b.len() {
        return Err(Error::Trailing);
    }
    Ok(())
}
fn whole<H, D: Decode<Item = Event<H>, Error = Error>>(
    decoder: D,
    b: &[u8],
) -> Result<(H, Vec<u8>), Error> {
    let mut stream = Stream::new(decoder);
    let mut head = None;
    let mut body = Vec::new();
    let mut done = false;
    // A handler refusal stops at the first Done. None marks completion;
    // Some(error) marks a refused value or an oversized owned body.
    let mut collect = |event| -> Result<(), Option<Error>> {
        match event {
            Event::Head(h) => head = Some(h),
            Event::Body(data) => {
                if body
                    .len()
                    .checked_add(data.len())
                    .is_none_or(|n| n > MAX_BODY)
                {
                    return Err(Some(Error::BodyTooLong));
                }
                body.extend_from_slice(&data);
            }
            Event::Done => {
                done = true;
                return Err(None);
            }
        }
        Ok(())
    };
    match try_pump(&mut stream, b, &mut collect) {
        Err(PumpError::Decode(error)) => return Err(wire_failure(error)),
        Err(PumpError::Handler(Some(error))) => return Err(error),
        Err(PumpError::Handler(None)) => {}
        Ok(_) => {
            let mut result = Ok(());
            let ended = finish(&mut stream, |event| {
                if result.is_ok() {
                    result = collect(event);
                }
            });
            if let Err(Some(error)) = result {
                return Err(error);
            }
            ended.map_err(wire_failure)?;
        }
    }
    if !done {
        return Err(Error::Incomplete);
    }
    if stream.offset() != u64::try_from(b.len()).map_err(|_| Error::Trailing)? {
        return Err(Error::Trailing);
    }
    Ok((head.ok_or(Error::Incomplete)?, body))
}

fn wire_failure(failure: Fail<Error>) -> Error {
    match failure {
        Fail::Protocol(error) => error,
        Fail::Truncated { .. } => Error::Incomplete,
        Fail::Stuck { .. } => Error::State,
    }
}

impl Wire for RequestHead {
    type ParseError = Error;
    type WriteError = Error;
    /// Parses exactly one request head under default limits. Ignores up to
    /// eight leading empty CRLF lines, as [`Request::parse`] does.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let mut b = b;
        for _ in 0..MAX_EMPTY_LINES {
            let Some(rest) = b.strip_prefix(b"\r\n") else {
                break;
            };
            b = rest;
        }
        if b.starts_with(b"\r\n") {
            return Err(Error::StartLine);
        }
        exact_head(b)?;
        let (head, _, _) = request_head(b)?;
        Ok(head)
    }
    /// Validates the complete head before appending it. No body is written.
    /// Uses default limits and emits fields as `name:value`. The written
    /// head fits the same limits as the decoder. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        validate_request(self)?;
        emit_request(self, out);
        Ok(())
    }
}
impl Wire for ResponseHead {
    type ParseError = Error;
    type WriteError = Error;
    /// Parses exactly one response head under default limits.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        exact_head(b)?;
        let (head, info) = response_head(b)?;
        response_size(&head, Limits::default())?;
        writable_response(&head, info, Method::Other)?;
        Ok(head)
    }
    /// Validates the complete head before appending it. No body is written.
    /// Uses default limits, `name:value` fields, and a space after the
    /// status even with an empty reason. The written head fits the decoder's
    /// limits. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        validate_response_for(self, Method::Other)?;
        emit_response(self, out);
        Ok(())
    }
}
impl Wire for Request {
    type ParseError = Error;
    type WriteError = Error;
    /// Parses exactly one request with default head limits and MAX_BODY.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (head, body) = whole(Requests::default(), b)?;
        Ok(Self { head, body })
    }
    /// Validates all fields and the body length before appending any bytes.
    /// Chunked bodies are written as one data chunk and an empty last chunk.
    /// Uses default head limits and MAX_BODY. Fields use `name:value`.
    /// Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let framing = validate_request(&self.head)?;
        validate_body(&self.body, framing)?;
        emit_request(&self.head, out);
        emit_body(&self.body, framing, out);
        Ok(())
    }
}
impl Wire for Response {
    type ParseError = Error;
    type WriteError = Error;
    /// Parses exactly one ordinary response with default limits. Uses EOF
    /// for a close-delimited body. Use parse_for for HEAD and CONNECT.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse_for(b, "GET")
    }
    /// Validates an ordinary response and its full body before writing.
    /// Use write_for for HEAD and CONNECT. Close-delimited output needs EOF.
    /// Uses default head limits and MAX_BODY. Fields use `name:value`; the
    /// status always has a following space. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.write_for("GET", out)
    }
}
impl Wire for Chunk {
    type ParseError = Error;
    type WriteError = Error;
    /// Parses one complete chunk, including the empty trailer section for
    /// a zero chunk. Extra bytes, extensions, and trailers are refused.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let mut lines = Lines::new(MAX_CHUNK_LINE, Ending::Crlf);
        let (state, used) = chunk_framing(&mut lines, State::Size, b)?.ok_or(Error::Incomplete)?;
        let (size, ending) = match state {
            State::Data(size) => (size, State::DataEnd),
            State::Trailers => (0, State::Trailers),
            _ => return Err(Error::State),
        };
        let n = usize::try_from(size).map_err(|_| Error::BodyTooLong)?;
        if n > MAX_BODY {
            return Err(Error::BodyTooLong);
        }
        let end = used.checked_add(n).ok_or(Error::BodyTooLong)?;
        let tail = b.get(end..).ok_or(Error::Incomplete)?;
        let (_, used_tail) = chunk_framing(&mut lines, ending, tail)?.ok_or(Error::Incomplete)?;
        if tail.len() != used_tail {
            return Err(Error::Trailing);
        }
        Ok(Self(b[used..end].to_vec()))
    }
    /// Refuses an oversized chunk before writing its size, data, and CRLF.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.len() > MAX_BODY {
            return Err(Error::BodyTooLong);
        }
        emit_chunk(&self.0, out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Assemble, Assembled, Carry, Collect, CollectError, Demux, Fragment, Layered, Lcg, Pipe,
        contract, pump, test_support,
    };

    const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const POST: &[u8] =
        b"POST /tools HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";
    const CHUNKED: &[u8] = b"POST /tools HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n";
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    fn small() -> Limits {
        Limits {
            body_chunk: 2,
            ..Limits::default()
        }
    }
    fn request_with(fields: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("POST / HTTP/1.1\r\nHost: example.test\r\n{fields}\r\n").into_bytes();
        out.extend_from_slice(body);
        out
    }
    fn response_with(fields: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 200 OK\r\n{fields}\r\n").into_bytes();
        out.extend_from_slice(body);
        out
    }
    fn request_error(bytes: &[u8], expected: Error) {
        let (_, error) = test_support::decode_all(Requests::default, bytes);
        assert_eq!(error, Some(Fail::Protocol(expected)), "{bytes:?}");
        contract::check_decode(Requests::default, bytes);
    }
    fn response_error(bytes: &[u8], expected: Error) {
        let (_, error) = test_support::decode_all(Responses::default, bytes);
        assert_eq!(error, Some(Fail::Protocol(expected)), "{bytes:?}");
        contract::check_decode(Responses::default, bytes);
    }
    fn refused<T: Wire<WriteError = Error> + fmt::Debug>(value: &T, expected: Error) {
        let mut out = b"unchanged".to_vec();
        assert_eq!(value.write(&mut out), Err(expected), "{value:?}");
        assert_eq!(out, b"unchanged");
    }

    #[test]
    fn requests_and_responses_round_trip() {
        for bytes in [GET, POST, CHUNKED] {
            let request = Request::parse(bytes).unwrap();
            contract::check_wire::<Request>(bytes);
            contract::check_wire_value(&request.head);
            contract::check_decode_with_held_limit(|| Requests::new(small()), bytes, 0);
            let (events, failure) = test_support::decode_all(|| Requests::new(small()), bytes);
            assert_eq!(failure, None);
            assert_eq!(events.first(), Some(&Event::Head(request.head)));
            assert_eq!(events.last(), Some(&Event::Done));
            let body: Vec<u8> = events
                .into_iter()
                .flat_map(|e| match e {
                    Event::Body(b) => b,
                    _ => Vec::new(),
                })
                .collect();
            assert_eq!(body, request.body);
        }
        let chunked = response_with("Transfer-Encoding: chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n");
        for bytes in [OK, chunked.as_slice(), b"HTTP/1.0 200 Fine\r\n\r\nhello"] {
            contract::check_wire::<Response>(bytes);
            let response = Response::parse(bytes).unwrap();
            assert_eq!(response.body, b"hello");
            contract::check_wire_value(&response.head);
            contract::check_decode_with_held_limit(
                || Responses::new(small()),
                bytes,
                MAX_PENDING_REQUESTS,
            );
        }
        for bytes in [b"5\r\nhello\r\n".as_slice(), b"0\r\n\r\n", b"000\r\n\r\n"] {
            contract::check_wire::<Chunk>(bytes);
        }
    }

    #[test]
    fn every_head_limit_at_boundary_and_one_past() {
        let bytes = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let exact = Limits {
            start_line: 14,
            header_line: 7,
            headers: 1,
            head: bytes.len(),
            body_chunk: 1,
        };
        let (_, error) = test_support::decode_all(|| Requests::new(exact), bytes);
        assert_eq!(error, None);
        let cases = [
            (
                Limits {
                    start_line: 13,
                    ..exact
                },
                Error::StartLineTooLong,
            ),
            (
                Limits {
                    header_line: 6,
                    ..exact
                },
                Error::HeaderLineTooLong,
            ),
            (
                Limits {
                    headers: 0,
                    ..exact
                },
                Error::TooManyHeaders,
            ),
            (
                Limits {
                    head: bytes.len().saturating_sub(1),
                    ..exact
                },
                Error::HeadTooLong,
            ),
            (Limits { head: 0, ..exact }, Error::HeadTooLong),
        ];
        for (limits, error) in cases {
            assert_eq!(
                test_support::decode_all(|| Requests::new(limits), bytes).1,
                Some(Fail::Protocol(error))
            );
            contract::check_decode(|| Requests::new(limits), bytes);
        }
        let response = b"HTTP/1.1 204 No Content\r\nX: y\r\n\r\n";
        let exact = Limits {
            start_line: 23,
            header_line: 4,
            headers: 1,
            head: response.len(),
            body_chunk: 1,
        };
        assert_eq!(
            test_support::decode_all(|| Responses::new(exact), response).1,
            None
        );
        for limits in [
            Limits {
                start_line: 21,
                ..exact
            },
            Limits {
                header_line: 3,
                ..exact
            },
            Limits {
                headers: 0,
                ..exact
            },
            Limits {
                head: response.len().saturating_sub(1),
                ..exact
            },
        ] {
            assert!(
                test_support::decode_all(|| Responses::new(limits), response)
                    .1
                    .is_some()
            );
            contract::check_decode(|| Responses::new(limits), response);
        }
        let huge = Limits {
            start_line: usize::MAX,
            header_line: usize::MAX,
            headers: usize::MAX,
            head: usize::MAX,
            body_chunk: usize::MAX,
        };
        assert!(Requests::new(huge).capacity() <= Buffer::MAX_LIMIT);
        assert_eq!(
            Requests::new(Limits {
                body_chunk: 0,
                ..small()
            })
            .core
            .limits
            .body_chunk,
            1
        );
    }

    #[test]
    fn one_byte_feeding_and_large_bodies_stay_bounded() {
        let mut stream = Stream::new(Requests::new(small()));
        let mut events = Vec::new();
        for chunk in test_support::chunks(CHUNKED, &[1]) {
            assert_eq!(
                pump(&mut stream, chunk, |e| events.push(e)).unwrap(),
                chunk.len()
            );
            assert_eq!(stream.held(), 0);
        }
        finish(&mut stream, |e| events.push(e)).unwrap();
        assert_eq!(
            events,
            test_support::decode_all(|| Requests::new(small()), CHUNKED).0
        );
        let body = vec![b'x'; 100_003];
        let bytes = request_with(&format!("Content-Length: {}\r\n", body.len()), &body);
        let limits = Limits {
            head: 1024,
            body_chunk: 97,
            ..small()
        };
        let mut stream = Stream::new(Requests::new(limits));
        let mut total = 0usize;
        pump(&mut stream, &bytes, |e| {
            if let Event::Body(b) = e {
                assert!(b.len() <= 97);
                total = total.saturating_add(b.len());
            }
        })
        .unwrap();
        assert_eq!(total, body.len());
        assert_eq!(stream.held(), 0);
        assert!(stream.buffered() <= 1024);
        // The declared chunk is much larger than any allocation needed to parse it.
        let bytes = request_with("Transfer-Encoding: chunked\r\n", b"ffffffffffffffff\r\nab");
        let mut stream = Stream::new(Requests::new(small()));
        assert_eq!(stream.push(&bytes), bytes.len());
        assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
        assert_eq!(stream.next(), Some(Ok(Event::Body(b"ab".to_vec()))));
        assert_eq!(stream.held(), 0);
    }

    #[test]
    fn content_length_and_transfer_encoding_failures() {
        for (fields, error) in [
            (
                "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
                Error::TransferEncodingAndContentLength,
            ),
            (
                "Transfer-Encoding: chunked\r\nContent-Length: bad\r\n",
                Error::TransferEncodingAndContentLength,
            ),
            (
                "Content-Length: 2\r\nContent-Length: 3\r\n",
                Error::ConflictingContentLength,
            ),
            ("Content-Length: 2, 3\r\n", Error::ConflictingContentLength),
            ("Content-Length: \r\n", Error::ContentLength),
            ("Content-Length: +1\r\n", Error::ContentLength),
            ("Content-Length: -1\r\n", Error::ContentLength),
            (
                "Content-Length: 18446744073709551616\r\n",
                Error::ContentLength,
            ),
            ("Content-Length: 2,\r\n", Error::ContentLength),
            (
                "Transfer-Encoding: chunked, gzip\r\n",
                Error::ChunkedNotLast,
            ),
            (
                "Transfer-Encoding: chunked, chunked\r\n",
                Error::ChunkedNotLast,
            ),
            (
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
                Error::ChunkedNotLast,
            ),
            ("Transfer-Encoding: \r\n", Error::TransferEncoding),
            (
                "Transfer-Encoding: chunked;x=1\r\n",
                Error::TransferEncoding,
            ),
        ] {
            request_error(&request_with(fields, b""), error);
            response_error(&response_with(fields, b""), error);
        }
        request_error(
            &request_with("Transfer-Encoding: gzip\r\n", b"abc"),
            Error::RequestTransferEncoding,
        );
        let bytes = response_with("Transfer-Encoding: gzip\r\n", b"abc");
        assert_eq!(Response::parse(&bytes).unwrap().body, b"abc");
        contract::check_wire::<Response>(&bytes);
        for fields in [
            "Content-Length: 5, 005\r\n",
            "Content-Length: 5\r\ncontent-length: 5\r\n",
        ] {
            let bytes = request_with(fields, b"hello");
            assert_eq!(Request::parse(&bytes).unwrap().body, b"hello");
            contract::check_wire::<Request>(&bytes);
        }
        let bytes = request_with(
            "Transfer-Encoding: gzip, CHUNKED\r\n",
            b"3\r\nzip\r\n0\r\n\r\n",
        );
        assert_eq!(Request::parse(&bytes).unwrap().body, b"zip");
        contract::check_wire::<Request>(&bytes);
    }

    #[test]
    fn list_elements_and_upgrade_offers_allow_http_pipelines() {
        for fields in [
            "Connection:\r\n",
            "Connection: keep-alive, \r\n",
            "Connection: , ,keep-alive,,\r\n",
            "Upgrade: h2c\r\n",
            "Connection: upgrade\r\n",
            "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABk\r\n",
        ] {
            let request = request_with(fields, b"");
            let bytes = [&request, GET].concat();
            let (events, failure) = test_support::decode_all(Requests::default, &bytes);
            assert_eq!(failure, None, "{fields}");
            assert_eq!(events.len(), 4, "{fields}");
            contract::check_decode(Requests::default, &bytes);
            contract::check_wire::<Request>(&request);
        }
        for fields in [
            "Transfer-Encoding: , chunked\r\n",
            "Transfer-Encoding: chunked,\r\n",
            "Transfer-Encoding: ,gzip,, chunked, ,\r\n",
            "Transfer-Encoding: ,\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: ,\r\n",
        ] {
            let request = request_with(fields, b"1\r\na\r\n0\r\n\r\n");
            let response = response_with(fields, b"1\r\na\r\n0\r\n\r\n");
            assert_eq!(Request::parse(&request).unwrap().body, b"a");
            assert_eq!(Response::parse(&response).unwrap().body, b"a");
            contract::check_decode(Requests::default, &request);
            contract::check_decode(Responses::default, &response);
            contract::check_wire::<Request>(&request);
            contract::check_wire::<Response>(&response);
        }
        request_error(
            &request_with("Content-Length: ,0\r\n", b""),
            Error::ContentLength,
        );
        request_error(
            &request_with("Transfer-Encoding: , ,\r\n", b""),
            Error::TransferEncoding,
        );
    }

    #[test]
    fn empty_lines_before_requests_are_bounded_and_reset_per_message() {
        for bytes in [
            b"\r\n".to_vec(),
            [b"\r\n".as_slice(), GET].concat(),
            [POST, b"\r\n", GET, b"\r\n"].concat(),
            [b"\r\n".repeat(MAX_EMPTY_LINES), GET.to_vec()].concat(),
            [
                b"\r\n".repeat(MAX_EMPTY_LINES),
                GET.to_vec(),
                b"\r\n".repeat(MAX_EMPTY_LINES),
                GET.to_vec(),
            ]
            .concat(),
        ] {
            let (events, failure) = test_support::decode_all(Requests::default, &bytes);
            assert_eq!(failure, None);
            let expected = bytes
                .windows(GET.len())
                .filter(|w| *w == GET)
                .count()
                .saturating_add(usize::from(bytes.starts_with(POST)));
            assert_eq!(
                events.iter().filter(|e| matches!(e, Event::Done)).count(),
                expected
            );
            contract::check_decode(Requests::default, &bytes);
        }
        request_error(
            &b"\r\n".repeat(MAX_EMPTY_LINES.saturating_add(1)),
            Error::StartLine,
        );
        let (_, failure) = test_support::decode_all(Requests::default, b"\r\n\r");
        assert_eq!(failure, Some(Fail::Truncated { unread: 1 }));
        for head in [0, 1, 2] {
            let make = || {
                Requests::new(Limits {
                    head,
                    start_line: 0,
                    ..small()
                })
            };
            assert_eq!(test_support::decode_all(make, b"\r\n").1, None);
            contract::check_decode(make, b"\r\n");
        }
    }

    #[test]
    fn empty_host_and_port_are_valid_but_connect_requires_a_port() {
        for host in ["", "a:", "[::1]:"] {
            let bytes = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            let head = RequestHead::parse(bytes.as_bytes()).unwrap();
            assert_eq!(head.headers[0].value, host.as_bytes());
            contract::check_wire::<RequestHead>(bytes.as_bytes());
            contract::check_decode(Requests::default, bytes.as_bytes());
        }
        for authority in ["a", "a:", "[::1]:"] {
            let bytes = format!("CONNECT {authority} HTTP/1.1\r\nHost: a\r\n\r\n");
            request_error(bytes.as_bytes(), Error::StartLine);
        }
        request_error(b"GET / HTTP/1.1\r\nHost:\r\nHost:\r\n\r\n", Error::Host);
    }

    #[test]
    fn missing_reason_phrase_and_method_aware_validation() {
        let bytes = b"HTTP/1.1 200\r\nContent-Length:0\r\n\r\n";
        let response = Response::parse(bytes).unwrap();
        assert!(response.head.reason.is_empty());
        assert_eq!(
            response.to_bytes().unwrap(),
            b"HTTP/1.1 200 \r\nContent-Length:0\r\n\r\n"
        );
        contract::check_wire::<Response>(bytes);
        contract::check_wire::<ResponseHead>(bytes);
        contract::check_decode(Responses::default, bytes);
        for (method, bytes) in [
            (
                "HEAD",
                b"HTTP/1.1 200 OK\r\nContent-Length:20\r\n\r\n".as_slice(),
            ),
            ("CONNECT", b"HTTP/1.1 200\r\n\r\n"),
            (
                "CONNECT",
                b"HTTP/1.1 403 Denied\r\nContent-Length:2\r\n\r\nno",
            ),
            ("GET", b"HTTP/1.1 100 Continue\r\n\r\n"),
        ] {
            let response = Response::parse_for(bytes, method).unwrap();
            let mut out = Vec::new();
            response.write_for(method, &mut out).unwrap();
            assert_eq!(Response::parse_for(&out, method), Ok(response));
        }
        for (method, status) in [("GET", 100), ("HEAD", 103), ("GET", 204), ("CONNECT", 200)] {
            for field in ["Content-Length:0", "Transfer-Encoding:chunked"] {
                let bytes = format!("HTTP/1.1 {status} Fine\r\n{field}\r\n\r\n");
                let make = || {
                    let mut decoder = Responses::default();
                    decoder.expect_method(method).unwrap();
                    decoder
                };
                let (events, failure) = test_support::decode_all(make, bytes.as_bytes());
                assert_eq!(failure, None);
                let Event::Head(head) = &events[0] else {
                    panic!("head")
                };
                let response = Response {
                    head: head.clone(),
                    body: Vec::new(),
                };
                assert_eq!(
                    Response::parse_for(bytes.as_bytes(), method),
                    Err(Error::ForbiddenFraming)
                );
                let mut out = b"prefix".to_vec();
                assert_eq!(
                    response.write_for(method, &mut out),
                    Err(Error::ForbiddenFraming)
                );
                assert_eq!(out, b"prefix");
            }
        }
    }

    #[test]
    fn received_head_limits_allow_writing_and_rewriting() {
        for (request, prefix) in [
            (true, b"GET / HTTP/1.1\r\nHost:a\r\n".as_slice()),
            (false, b"HTTP/1.1 200 \r\nContent-Length:0\r\n"),
        ] {
            let mut line_boundary = prefix.to_vec();
            line_boundary.extend_from_slice(b"X:");
            line_boundary.extend_from_slice(&vec![b'a'; 8190]);
            line_boundary.extend_from_slice(b"\r\n\r\n");
            let mut head_boundary = prefix.to_vec();
            while head_boundary.len().saturating_add(2) < Limits::default().head {
                let line = Limits::default()
                    .head
                    .saturating_sub(head_boundary.len())
                    .saturating_sub(2)
                    .min(8194);
                head_boundary.extend_from_slice(b"X:");
                head_boundary.extend_from_slice(&vec![b'a'; line.saturating_sub(4)]);
                head_boundary.extend_from_slice(b"\r\n");
            }
            head_boundary.extend_from_slice(b"\r\n");
            assert_eq!(head_boundary.len(), Limits::default().head);
            for bytes in [line_boundary, head_boundary] {
                if request {
                    let (events, failure) = test_support::decode_all(Requests::default, &bytes);
                    assert_eq!(failure, None);
                    let Event::Head(mut head) = events[0].clone() else {
                        panic!("head")
                    };
                    assert_eq!(head.to_bytes().unwrap(), bytes);
                    head.headers[1].value[0] = b'b';
                    contract::check_wire_value(&head);
                    contract::check_wire::<Request>(&bytes);
                    let (values, failure) =
                        test_support::decode_all(|| Collect::<Request>::new(bytes.len()), &bytes);
                    assert_eq!(failure, None);
                    assert_eq!(values.len(), 1);
                } else {
                    let (events, failure) = test_support::decode_all(Responses::default, &bytes);
                    assert_eq!(failure, None);
                    let Event::Head(mut head) = events[0].clone() else {
                        panic!("head")
                    };
                    assert_eq!(head.to_bytes().unwrap(), bytes);
                    head.headers[1].value[0] = b'b';
                    contract::check_wire_value(&head);
                    contract::check_wire::<Response>(&bytes);
                }
            }
        }
        let bytes = request_with(&format!("X:{}\r\n", "a".repeat(8191)), b"");
        request_error(&bytes, Error::HeaderLineTooLong);
        assert_eq!(RequestHead::parse(&bytes), Err(Error::HeaderLineTooLong));
    }

    #[test]
    fn malformed_chunks_extensions_trailers_and_truncation() {
        for (body, error) in [
            (b"1;x=y\r\na\r\n0\r\n\r\n".as_slice(), Error::ChunkExtension),
            (b"0;last=yes\r\n\r\n", Error::ChunkExtension),
            (b"10000000000000000\r\n", Error::ChunkSize),
            (b"-1\r\n", Error::ChunkSize),
            (b"+1\r\n", Error::ChunkSize),
            (b"0x1\r\n", Error::ChunkSize),
            (b"\r\n", Error::ChunkSize),
            (b"1 \r\n", Error::ChunkSize),
            (b"1\na\r\n", Error::LineEnding),
            (b"1\r\naX\n", Error::ChunkEnding),
            (b"1\r\na\rX", Error::ChunkEnding),
            (b"0\r\nX: y\r\n\r\n", Error::Trailers),
        ] {
            request_error(&request_with("Transfer-Encoding: chunked\r\n", body), error);
            response_error(
                &response_with("Transfer-Encoding: chunked\r\n", body),
                error,
            );
            assert_eq!(Chunk::parse(body), Err(error));
        }
        let too_long = vec![b'0'; MAX_CHUNK_LINE.saturating_add(2)];
        request_error(
            &request_with("Transfer-Encoding: chunked\r\n", &too_long),
            Error::ChunkLineTooLong,
        );
        let mut exact = vec![b'0'; MAX_CHUNK_LINE];
        exact.extend_from_slice(b"\r\n\r\n");
        assert_eq!(Chunk::parse(&exact), Ok(Chunk(Vec::new())));
        for body in [b"".as_slice(), b"1\r\n", b"1\r\nx", b"0\r\n"] {
            request_error(
                &request_with("Transfer-Encoding: chunked\r\n", body),
                Error::Incomplete,
            );
        }
        for body in [b"1".as_slice(), b"2\r\nx", b"1\r\nx\r", b"0\r\n\r"] {
            let request = request_with("Transfer-Encoding: chunked\r\n", body);
            let response = response_with("Transfer-Encoding: chunked\r\n", body);
            assert_eq!(
                test_support::decode_all(Requests::default, &request).1,
                Some(Fail::Truncated { unread: 1 })
            );
            assert_eq!(
                test_support::decode_all(Responses::default, &response).1,
                Some(Fail::Truncated { unread: 1 })
            );
            contract::check_decode(Requests::default, &request);
            contract::check_decode(Responses::default, &response);
            assert_eq!(Chunk::parse(body), Err(Error::Incomplete));
        }
        let request = request_with("Content-Length: 3\r\n", b"ab");
        let response = response_with("Content-Length: 3\r\n", b"ab");
        assert_eq!(
            test_support::decode_all(Requests::default, &request).1,
            Some(Fail::Truncated { unread: 2 })
        );
        assert_eq!(
            test_support::decode_all(Responses::default, &response).1,
            Some(Fail::Truncated { unread: 2 })
        );
        let request = b"GET / HTTP/1.1\r\nHost: x\r\n";
        let response = b"HTTP/1.1 200 OK\r\n";
        assert_eq!(
            test_support::decode_all(Requests::default, request).1,
            Some(Fail::Truncated {
                unread: request.len()
            })
        );
        assert_eq!(
            test_support::decode_all(Responses::default, response).1,
            Some(Fail::Truncated {
                unread: response.len()
            })
        );
        contract::check_decode(Requests::default, request);
        contract::check_decode(Responses::default, response);
    }

    #[test]
    fn interim_close_waits_for_the_final_response() {
        for (bytes, interim, body, closed) in [
            (
                b"HTTP/1.1 103 Early Hints\r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".as_slice(),
                103,
                b"hi".as_slice(),
                false,
            ),
            (
                b"HTTP/1.0 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx",
                100,
                b"x",
                true,
            ),
        ] {
            let make = || {
                let mut decoder = Responses::default();
                decoder.expect_method("GET").unwrap();
                decoder
            };
            let mut stream = Stream::new(make());
            assert_eq!(stream.push(bytes), bytes.len());
            assert!(matches!(stream.next(), Some(Ok(Event::Head(h))) if h.status == interim));
            assert_eq!(stream.next(), Some(Ok(Event::Done)));
            assert!(matches!(stream.next(), Some(Ok(Event::Head(h))) if h.status == 200));
            assert_eq!(stream.next(), Some(Ok(Event::Body(body.to_vec()))));
            assert_eq!(stream.next(), Some(Ok(Event::Done)));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.is_done(), closed);
            assert!(stream.unread().is_empty());
            assert_eq!(stream.failed(), None);
            contract::check_decode(make, bytes);
        }
    }

    #[test]
    fn whole_messages_refuse_declared_lengths_from_the_head() {
        let head = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n";
        let mut stream = Stream::new(RequestMessages::with_limits(Limits::default(), 10, 4096));
        assert_eq!(stream.push(head), head.len());
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::BodyTooLong))));
        let mut stream = Stream::new(RequestMessages::with_limits(
            Limits::default(),
            MAX_BODY,
            4096,
        ));
        assert_eq!(stream.push(head), head.len());
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(Error::MessageTooLong)))
        );
        let mut stream = Stream::new(ResponseMessages::with_limits(Limits::default(), 10, 4096));
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n";
        assert_eq!(stream.push(head), head.len());
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::BodyTooLong))));
        // A chunk larger than the remaining body bound is refused from its size line.
        let chunked = request_with("Transfer-Encoding: chunked\r\n", b"4\r\nabcd\r\n10\r\n");
        let mut stream = Stream::new(RequestMessages::with_limits(small(), 10, 4096));
        assert_eq!(stream.push(&chunked), chunked.len());
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::BodyTooLong))));
    }

    #[test]
    fn whole_messages_hold_no_input_while_they_need_more() {
        for limits in [Limits::default(), small()] {
            let mut decoder = RequestMessages::with_limits(limits, MAX_BODY, MAX_MESSAGE);
            let partial = request_with("Content-Length: 10\r\n", b"hello");
            assert!(matches!(decoder.decode(&partial, false), Ok(Step::Need)));
            assert_eq!(decoder.held(), 0);
            let whole = request_with("Content-Length: 10\r\n", b"helloworld");
            let Ok(Step::Item(request, n)) = decoder.decode(&whole, false) else {
                panic!("expected a whole request");
            };
            assert_eq!(n, whole.len());
            assert_eq!(request.body, b"helloworld");
            assert_eq!(decoder.held(), 0);
        }
        let chunked = request_with("Transfer-Encoding: chunked\r\n", b"2\r\nhe\r\n3\r\nllo\r\n");
        let mut decoder = RequestMessages::with_limits(small(), MAX_BODY, MAX_MESSAGE);
        assert!(matches!(decoder.decode(&chunked, false), Ok(Step::Need)));
        assert_eq!(decoder.held(), 0);
        let mut done = chunked.clone();
        done.extend_from_slice(b"0\r\n\r\n");
        let Ok(Step::Item(request, n)) = decoder.decode(&done, false) else {
            panic!("expected a whole request");
        };
        assert_eq!(
            (request.body.as_slice(), n),
            (b"hello".as_slice(), done.len())
        );
    }

    #[test]
    fn whole_messages_obey_contracts_and_limits() {
        let pipeline = [CHUNKED, GET, POST].concat();
        let make = || RequestMessages::with_limits(small(), 5, CHUNKED.len());
        contract::check_decode_with_held_limit(make, &pipeline, CHUNKED.len() + 5);
        contract::check_decode_with_alloc_limit(make, &pipeline, (CHUNKED.len() + 1) * 2);
        let (messages, error) = test_support::decode_all(make, &pipeline);
        assert_eq!(error, None);
        assert_eq!(
            messages,
            [
                Request::parse(CHUNKED).unwrap(),
                Request::parse(GET).unwrap(),
                Request::parse(POST).unwrap()
            ]
        );
        for bytes in [CHUNKED, POST] {
            let make = || RequestMessages::with_limits(small(), 4, 512);
            assert_eq!(
                test_support::decode_all(make, bytes).1,
                Some(Fail::Protocol(Error::BodyTooLong))
            );
            contract::check_decode(make, bytes);
            let make = || RequestMessages::with_limits(small(), 5, bytes.len() - 1);
            assert_eq!(
                test_support::decode_all(make, bytes).1,
                Some(Fail::Protocol(Error::MessageTooLong))
            );
            contract::check_decode(make, bytes);
        }
        for bytes in [GET, b"", b"\r", b"\r\n", b"GET"] {
            for limit in [0, 1, 2, GET.len() - 1, GET.len()] {
                contract::check_decode(|| RequestMessages::with_limits(small(), 0, limit), bytes);
            }
        }
        let make = || {
            let mut decoder = ResponseMessages::with_limits(small(), 5, 128);
            decoder.expect_method("HEAD").unwrap();
            decoder.expect_method("GET").unwrap();
            decoder
        };
        let bytes = b"HTTP/1.1 103 Early Hints\r\nConnection: close\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 90\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        contract::check_decode_with_held_limit(make, bytes, 135);
        let (responses, error) = test_support::decode_all(make, bytes);
        assert_eq!(error, None);
        assert_eq!(responses.len(), 3);
        assert!(responses[1].body.is_empty());
        assert_eq!(responses[2].body, b"hello");
        for bytes in [OK, b"HTTP/1.1 200 OK\r\n\r\nhello"] {
            let make = || ResponseMessages::with_limits(small(), 5, bytes.len());
            contract::check_decode(make, bytes);
            assert_eq!(
                test_support::decode_all(make, bytes),
                (vec![Response::parse(bytes).unwrap()], None)
            );
            let make = || ResponseMessages::with_limits(small(), 4, 128);
            contract::check_decode(make, bytes);
            assert_eq!(
                test_support::decode_all(make, bytes).1,
                Some(Fail::Protocol(Error::BodyTooLong))
            );
        }
        // Long runs of tiny chunks must not exhaust the driver's zero-step budget.
        let mut tiny = request_with("Transfer-Encoding: chunked\r\n", b"");
        tiny.extend_from_slice(&b"0001\r\nx\r\n".repeat(256));
        tiny.extend_from_slice(b"0\r\n\r\n");
        contract::check_decode(RequestMessages::default, &tiny);
        assert_eq!(
            test_support::decode_all(RequestMessages::default, &tiny).0[0]
                .body
                .len(),
            256
        );
    }

    #[test]
    fn whole_messages_preserve_handoff_and_response_queue_bounds() {
        for bytes in [
            b"HTTP/1.1 101 Switching Protocols\r\n\r\ntunnel".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\ntunnel",
        ] {
            let make = || {
                let mut decoder = ResponseMessages::default();
                decoder.expect_method("CONNECT").unwrap();
                decoder
            };
            let mut stream = Stream::new(make());
            assert_eq!(stream.push(bytes), bytes.len());
            assert!(stream.next().unwrap().unwrap().body.is_empty());
            assert_eq!(stream.next(), None);
            assert!(stream.is_done());
            assert_eq!(stream.unread(), b"tunnel");
            contract::check_decode(make, bytes);
        }
        let mut decoder = ResponseMessages::default();
        assert_eq!(decoder.expect_method("bad method"), Err(Error::StartLine));
        for _ in 0..MAX_PENDING_REQUESTS {
            decoder.expect_method("GET").unwrap();
        }
        assert_eq!(decoder.expect_method("GET"), Err(Error::TooManyRequests));
        assert_eq!(decoder.held(), MAX_PENDING_REQUESTS);
    }

    #[test]
    fn leading_empty_lines_agree_between_request_wire_types() {
        for n in 0..=MAX_EMPTY_LINES + 1 {
            let bytes = [b"\r\n".repeat(n), GET.to_vec()].concat();
            assert_eq!(
                Request::parse(&bytes).map(|r| r.head),
                RequestHead::parse(&bytes)
            );
            contract::check_wire::<Request>(&bytes);
            contract::check_wire::<RequestHead>(&bytes);
        }
    }

    #[test]
    fn empty_reason_space_counts_toward_response_limits() {
        let response = Response::status(204);
        assert_eq!(response.to_bytes().unwrap(), b"HTTP/1.1 204 \r\n\r\n");
        let short = b"HTTP/1.1 204\r\n\r\n";
        let limits = Limits {
            head: short.len(),
            ..Limits::default()
        };
        assert_eq!(
            test_support::decode_all(|| Responses::new(limits), short).1,
            Some(Fail::Protocol(Error::HeadTooLong))
        );
        contract::check_decode(|| Responses::new(limits), short);
        let limits = Limits {
            start_line: 12,
            ..Limits::default()
        };
        assert_eq!(
            test_support::decode_all(|| Responses::new(limits), short).1,
            Some(Fail::Protocol(Error::StartLineTooLong))
        );
        let limits = Limits {
            head: short.len() + 1,
            start_line: 13,
            ..Limits::default()
        };
        assert_eq!(
            test_support::decode_all(|| Responses::new(limits), short).1,
            None
        );
        contract::check_decode(|| Responses::new(limits), short);
        let mut head = response.head;
        head.reason = vec![b'a'; Limits::default().start_line - 13];
        contract::check_wire_value(&head);
        head.reason.push(b'a');
        refused(&head, Error::StartLineTooLong);
    }

    #[test]
    fn response_constructors_use_wire_and_json() {
        for status in [100, 202, 204, 304, 404] {
            let response = Response::status(status);
            contract::check_wire_value(&response);
            assert_eq!(
                named(&response.head.headers, "content-length").next(),
                if [100, 204, 304].contains(&status) {
                    None
                } else {
                    Some(b"0".as_slice())
                }
            );
        }
        refused(&Response::status(99), Error::StartLine);
        let response = Response::json(b" {\"ok\": true} \n").unwrap();
        assert_eq!(response.body, b" {\"ok\": true} \n");
        assert_eq!(
            named(&response.head.headers, "content-type").next(),
            Some(b"application/json".as_slice())
        );
        contract::check_wire_value(&response);
        assert!(Response::json(b"not JSON").is_ok());
        assert_eq!(
            Response::json(&vec![b'x'; MAX_BODY + 1]),
            Err(Error::BodyTooLong)
        );
        let detail = "quote \" slash \\ newline\n tab\t café";
        let response = Response::problem(404, detail).unwrap();
        assert_eq!(
            named(&response.head.headers, "content-type").next(),
            Some(b"application/problem+json".as_slice())
        );
        let value = json::Value::parse(&response.body).unwrap();
        assert_eq!(
            value.get("type").and_then(json::Value::as_str),
            Some("about:blank")
        );
        assert_eq!(value.get("status").and_then(json::Value::as_u64), Some(404));
        assert_eq!(
            value.get("detail").and_then(json::Value::as_str),
            Some(detail)
        );
        contract::check_wire_value(&response);
        assert_eq!(Response::problem(204, "bad"), Err(Error::StartLine));
        assert_eq!(
            Response::problem(400, &"\n".repeat(json::MAX_SIZE)),
            Err(Error::BodyTooLong)
        );
        let head = Response::event_stream("session-1");
        contract::check_wire_value(&head);
        assert_eq!(
            named(&head.headers, "content-type").next(),
            Some(b"text/event-stream".as_slice())
        );
        assert_eq!(
            named(&head.headers, "mcp-session-id").next(),
            Some(b"session-1".as_slice())
        );
        assert_eq!(
            named(&head.headers, "cache-control").next(),
            Some(b"no-cache".as_slice())
        );
        assert_eq!(named(&head.headers, "content-length").next(), None);
        let mut out = head.to_bytes().unwrap();
        let mut stream = Stream::new(Responses::default());
        assert_eq!(stream.push(&out), out.len());
        assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
        assert_eq!(stream.next(), None);
        assert!(!stream.is_done());
        Chunk(b"data: {}\n\n".to_vec()).write(&mut out).unwrap();
        Chunk(Vec::new()).write(&mut out).unwrap();
        assert_eq!(Response::parse(&out).unwrap().body, b"data: {}\n\n");
        refused(&Response::event_stream("bad\r\nfield"), Error::Header);
    }

    #[test]
    fn switching_protocols_leaves_bytes_for_handoff() {
        let bytes = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: example\r\n\r\ntunnel";
        let mut stream = Stream::new(Responses::default());
        assert_eq!(stream.push(bytes), bytes.len());
        assert!(matches!(stream.next(), Some(Ok(Event::Head(h))) if h.status == 101));
        assert_eq!(stream.next(), Some(Ok(Event::Done)));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.failed(), None);
        assert_eq!(stream.unread(), b"tunnel");
        contract::check_decode(Responses::default, bytes);
    }

    #[test]
    fn bodyless_responses_and_expectation_queue() {
        for status in [100, 103, 199, 204, 304] {
            let bytes = format!("HTTP/1.1 {status} Fine\r\n\r\n");
            let (events, error) = test_support::decode_all(Responses::default, bytes.as_bytes());
            assert_eq!(error, None);
            assert_eq!(events.len(), 2);
            assert_eq!(events[1], Event::Done);
            contract::check_wire::<Response>(bytes.as_bytes());
            contract::check_decode(Responses::default, bytes.as_bytes());
        }
        // RFC 9112 section 6.3: these fields do not create a response body.
        for (method, status) in [("HEAD", 200), ("GET", 100), ("GET", 204), ("GET", 304)] {
            let bytes = format!("HTTP/1.1 {status} Fine\r\nContent-Length: 999\r\n\r\n");
            let make = || {
                let mut d = Responses::new(small());
                d.expect_method(method).unwrap();
                d
            };
            assert_eq!(test_support::decode_all(make, bytes.as_bytes()).0.len(), 2);
            contract::check_decode(make, bytes.as_bytes());
        }
        let bytes = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let make = || {
            let mut d = Responses::default();
            d.expect_method("HEAD").unwrap();
            d.expect_method("GET").unwrap();
            d
        };
        let (events, error) = test_support::decode_all(make, bytes);
        assert_eq!(error, None);
        assert_eq!(events.len(), 7);
        assert_eq!(events[5], Event::Body(b"hi".to_vec()));
        contract::check_decode(make, bytes);
        let mut d = Responses::default();
        assert_eq!(d.expect_method("bad method"), Err(Error::StartLine));
        assert_eq!(d.held(), 0);
        for _ in 0..MAX_PENDING_REQUESTS {
            d.expect_method("HEAD").unwrap();
        }
        assert_eq!(d.held(), MAX_PENDING_REQUESTS);
        assert_eq!(d.expect_method("GET"), Err(Error::TooManyRequests));
        assert_eq!(d.held(), MAX_PENDING_REQUESTS);
    }

    #[test]
    fn close_keep_alive_and_pipelining() {
        let mut pipeline = Vec::new();
        for bytes in [GET, POST, CHUNKED, GET] {
            pipeline.extend_from_slice(bytes);
        }
        let (events, error) = test_support::decode_all(Requests::default, &pipeline);
        assert_eq!(error, None);
        assert_eq!(
            events.iter().filter(|e| matches!(e, Event::Done)).count(),
            4
        );
        contract::check_decode(Requests::default, &pipeline);
        let mut responses = Vec::new();
        for _ in 0..4 {
            responses.extend_from_slice(OK);
        }
        contract::check_decode(Responses::default, &responses);
        assert_eq!(
            test_support::decode_all(Responses::default, &responses)
                .0
                .len(),
            12
        );
        for bytes in [
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, CLOSE\r\n\r\ntail".as_slice(),
            b"GET / HTTP/1.0\r\n\r\ntail",
        ] {
            let mut stream = Stream::new(Requests::default());
            assert_eq!(stream.push(bytes), bytes.len());
            assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
            assert_eq!(stream.next(), Some(Ok(Event::Done)));
            assert_eq!(stream.next(), None);
            assert!(stream.is_done());
            assert_eq!(stream.into_parts().0.unread(), b"tail");
            contract::check_decode(Requests::default, bytes);
        }
        let bytes = b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.0\r\n\r\n";
        assert_eq!(
            test_support::decode_all(Requests::default, bytes).0.len(),
            4
        );
        let bytes = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhitail";
        let mut stream = Stream::new(Responses::default());
        assert_eq!(stream.push(bytes), bytes.len());
        assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
        assert_eq!(stream.next(), Some(Ok(Event::Body(b"hi".to_vec()))));
        assert_eq!(stream.next(), Some(Ok(Event::Done)));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.into_parts().0.unread(), b"tail");
        contract::check_decode(Responses::default, bytes);
    }

    #[test]
    fn read_until_close_flushes_last_block_only_at_eof() {
        let bytes = b"HTTP/1.1 200 OK\r\n\r\nhello";
        let mut stream = Stream::new(Responses::new(small()));
        assert_eq!(stream.push(bytes), bytes.len());
        assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
        assert_eq!(stream.next(), Some(Ok(Event::Body(b"he".to_vec()))));
        assert_eq!(stream.next(), Some(Ok(Event::Body(b"ll".to_vec()))));
        assert_eq!(stream.next(), None);
        stream.end();
        assert_eq!(stream.next(), Some(Ok(Event::Body(b"o".to_vec()))));
        assert_eq!(stream.next(), Some(Ok(Event::Done)));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        contract::check_decode(|| Responses::new(small()), bytes);
    }

    #[test]
    fn expect_continue_is_visible_before_the_body() {
        let bytes = request_with("Expect: 100-Continue\r\nContent-Length: 5\r\n", b"");
        let mut stream = Stream::new(Requests::default());
        assert_eq!(stream.push(&bytes), bytes.len());
        let Some(Ok(Event::Head(mut head))) = stream.next() else {
            panic!("head")
        };
        assert!(head.expects_continue());
        head.version = Version::Http10;
        assert!(!head.expects_continue());
        assert_eq!(
            ResponseHead::continue_100().to_bytes().unwrap(),
            b"HTTP/1.1 100 Continue\r\n\r\n"
        );
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"hello"), 5);
        assert_eq!(stream.next(), Some(Ok(Event::Body(b"hello".to_vec()))));
        assert_eq!(stream.next(), Some(Ok(Event::Done)));
    }

    #[test]
    fn connect_pump_ends_after_done() {
        let bytes = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n";
        let mut stream = Stream::new(Requests::default());
        let mut events = Vec::new();
        assert_eq!(
            pump(&mut stream, bytes, |e| events.push(e)),
            Ok(bytes.len())
        );
        assert!(matches!(events.as_slice(), [Event::Head(_), Event::Done]));
        assert!(stream.is_done());
        assert_eq!(stream.failed(), None);
        assert_eq!(stream.next(), None);
        contract::check_decode(Requests::default, bytes);
    }

    #[test]
    fn connect_drivers_preserve_tunnel_bytes() {
        let head = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n";
        for tunnel in [
            b"\x16\x03\x01\x00\x05hello".as_slice(),
            b"SSH-2.0-OpenSSH_9.6\r\n",
        ] {
            let bytes = [head.as_slice(), tunnel].concat();
            for fallible in [false, true] {
                let mut stream = Stream::new(Requests::default());
                let mut events = Vec::new();
                let taken = if fallible {
                    try_pump(&mut stream, &bytes, |e| {
                        events.push(e);
                        Ok::<(), Error>(())
                    })
                    .unwrap()
                } else {
                    pump(&mut stream, &bytes, |e| events.push(e)).unwrap()
                };
                assert_eq!(taken, bytes.len());
                assert!(matches!(events.as_slice(), [Event::Head(_), Event::Done]));
                assert_eq!(stream.failed(), None);
                assert!(stream.is_done());
                assert_eq!(stream.into_parts().0.unread(), tunnel);
            }
            contract::check_decode(Requests::default, &bytes);
        }
    }

    #[test]
    fn connect_rejection_swaps_back_to_http() {
        let head = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n";
        let bytes = [head.as_slice(), GET].concat();
        let limits = Limits::default();
        let mut stream = Stream::new(Requests::new(limits));
        let mut events = Vec::new();
        assert_eq!(
            pump(&mut stream, &bytes, |e| events.push(e)),
            Ok(bytes.len())
        );
        assert!(matches!(events.as_slice(), [Event::Head(_), Event::Done]));
        assert!(stream.is_done());
        assert_eq!(stream.unread(), GET);
        let mut stream = stream.swap(Requests::new(limits));
        events.clear();
        finish(&mut stream, |e| events.push(e)).unwrap();
        assert_eq!(events, test_support::decode_all(Requests::default, GET).0);
        assert!(stream.unread().is_empty());
        assert_eq!(stream.failed(), None);
    }

    #[test]
    fn connect_handoff_in_both_directions() {
        let request = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\ntunnel";
        let mut stream = Stream::new(Requests::default());
        assert_eq!(stream.push(request), request.len());
        assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
        assert_eq!(stream.next(), Some(Ok(Event::Done)));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.into_parts().0.unread(), b"tunnel");
        for fields in [
            "",
            "Content-Length: 1000\r\n",
            "Transfer-Encoding: chunked\r\n",
        ] {
            let response = response_with(fields, b"tunnel");
            let make = || {
                let mut d = Responses::default();
                d.expect_method("CONNECT").unwrap();
                d
            };
            let mut stream = Stream::new(make());
            assert_eq!(stream.push(&response), response.len());
            assert!(matches!(stream.next(), Some(Ok(Event::Head(_)))));
            assert_eq!(stream.next(), Some(Ok(Event::Done)));
            assert_eq!(stream.next(), None);
            assert!(stream.is_done());
            assert_eq!(stream.into_parts().0.unread(), b"tunnel");
            contract::check_decode(make, &response);
        }
        let make = || {
            let mut d = Responses::default();
            d.expect_method("CONNECT").unwrap();
            d
        };
        let (events, error) =
            test_support::decode_all(make, b"HTTP/1.1 403 Denied\r\nContent-Length: 2\r\n\r\nno");
        assert_eq!(error, None);
        assert_eq!(events[1], Event::Body(b"no".to_vec()));
        let head = b"HTTP/1.1 200 OK\r\nContent-Length:99\r\n\r\n";
        let value = Response::parse_for(head, "HEAD").unwrap();
        let mut out = Vec::new();
        value.write_for("HEAD", &mut out).unwrap();
        assert_eq!(out, head);
        refused(&value, Error::BodyLength);
        assert_eq!(
            value.write_for("CONNECT", &mut out),
            Err(Error::ForbiddenFraming)
        );
        assert_eq!(out, head);
    }

    #[test]
    fn syntax_errors_and_header_bytes() {
        for bytes in [
            b"GET / HTTP/1.1\nHost: x\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: x\n\r\n",
        ] {
            request_error(bytes, Error::LineEnding);
        }
        for field in [
            "bad name: x\r\n",
            "x : y\r\n",
            " x: y\r\n",
            "x: a\0b\r\n",
            "x: a\rb\r\n",
            "x: a\x7fb\r\n",
        ] {
            request_error(&request_with(field, b""), Error::Header);
        }
        request_error(b"GET / HTTP/1.1\r\n\r\n", Error::Host);
        request_error(&request_with("Host: other.test\r\n", b""), Error::Host);
        request_error(b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", Error::Version);
        request_error(
            b"GET /#fragment HTTP/1.1\r\nHost: x\r\n\r\n",
            Error::StartLine,
        );
        request_error(b"CONNECT / HTTP/1.1\r\nHost: x\r\n\r\n", Error::StartLine);
        assert_eq!(
            Response::parse(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            Err(Error::Upgrade)
        );
        request_error(
            b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            Error::Http10TransferEncoding,
        );
        let bytes = b"GET / HTTP/1.1\r\nhOsT:\tx \t\r\nX-Data: \xff\tvalue\r\n\r\n";
        let request = Request::parse(bytes).unwrap();
        assert_eq!(request.head.headers[0].name, "hOsT");
        assert_eq!(request.head.headers[0].value, b"x");
        assert_eq!(request.head.headers[1].value, b"\xff\tvalue");
        contract::check_wire::<Request>(bytes);
        for line in [
            "GET http://example.test:80/a?b HTTP/1.1",
            "OPTIONS * HTTP/1.1",
            "CONNECT [::1]:443 HTTP/1.1",
        ] {
            let bytes = format!("{line}\r\nHost: example.test\r\n\r\n");
            assert!(Request::parse(bytes.as_bytes()).is_ok());
        }
        for status in ["99", "099", "600", "1000", "+20", "2a0"] {
            response_error(
                format!("HTTP/1.1 {status} Bad\r\n\r\n").as_bytes(),
                Error::StartLine,
            );
        }
    }

    #[test]
    fn writers_validate_before_any_output() {
        let base = Request::parse(POST).unwrap();
        let mut value = base.clone();
        value.body.push(0);
        refused(&value, Error::BodyLength);
        value = base.clone();
        value.head.method = "GET\r\n".into();
        refused(&value, Error::StartLine);
        value = base.clone();
        value.head.target = "/bad target".into();
        refused(&value, Error::StartLine);
        for (name, bytes) in [
            ("bad name", b"value".as_slice()),
            ("X", b"\r"),
            ("X", b"\n"),
            ("X", b"\0"),
            ("X", b" value"),
            ("X", b"value\t"),
        ] {
            value = base.clone();
            value.head.headers.push(Header {
                name: name.into(),
                value: bytes.to_vec(),
            });
            refused(&value, Error::Header);
            contract::check_wire_value(&value);
        }
        value = base.clone();
        value.head.headers.push(Header {
            name: "Transfer-Encoding".into(),
            value: b"chunked".to_vec(),
        });
        refused(&value, Error::TransferEncodingAndContentLength);
        value = base.clone();
        value.body = vec![0; MAX_BODY.saturating_add(1)];
        refused(&value, Error::BodyTooLong);
        refused(
            &Chunk(vec![0; MAX_BODY.saturating_add(1)]),
            Error::BodyTooLong,
        );
        value = base.clone();
        value.head.target = format!("/{}", "a".repeat(8192));
        refused(&value, Error::StartLineTooLong);
        value = base.clone();
        value.head.headers.push(Header {
            name: "X".into(),
            value: vec![b'a'; 8192],
        });
        refused(&value, Error::HeaderLineTooLong);
        value = base.clone();
        value.head.headers.extend((0..100).map(|_| Header {
            name: "X".into(),
            value: Vec::new(),
        }));
        refused(&value, Error::TooManyHeaders);
        value = base;
        value.head.headers.extend((0..9).map(|_| Header {
            name: "X".into(),
            value: vec![b'a'; 8000],
        }));
        refused(&value, Error::HeadTooLong);
        let mut response = Response::parse(OK).unwrap();
        for status in [0, 99, 600, 1000] {
            response.head.status = status;
            refused(&response, Error::StartLine);
        }
        response.head.status = 200;
        response.head.reason = b"OK\r\nX: bad".to_vec();
        refused(&response, Error::StartLine);
        response = Response::parse(OK).unwrap();
        response.head.status = 204;
        refused(&response, Error::ForbiddenFraming);
        response.head.status = 304;
        refused(&response, Error::BodyLength);
        response.head.status = 200;
        response.body.clear();
        refused(&response, Error::BodyLength);
        assert_eq!(
            Request::parse(&[GET, b"tail"].concat()),
            Err(Error::Trailing)
        );
        assert_eq!(RequestHead::parse(POST), Err(Error::Trailing));
        assert_eq!(
            Response::parse(&[OK, b"tail"].concat()),
            Err(Error::Trailing)
        );
        assert_eq!(ResponseHead::parse(OK), Err(Error::Trailing));
        assert_eq!(Chunk::parse(b"0\r\n\r\ntail"), Err(Error::Trailing));
    }

    #[test]
    fn collect_assemble_pipe_and_demux_use_public_contracts() {
        let make = || Collect::<Request>::new(POST.len());
        contract::check_decode(make, POST);
        let (items, error) = test_support::decode_all(make, POST);
        assert_eq!(error, None);
        assert_eq!(items, vec![Request::parse(POST).unwrap()]);
        assert_eq!(
            test_support::decode_all(
                || Collect::<Request>::new(POST.len().saturating_sub(1)),
                POST
            )
            .1,
            Some(Fail::Protocol(CollectError::TooLong {
                limit: POST.len().saturating_sub(1)
            }))
        );
        let assemble = || {
            Assemble::new(Requests::new(small()), 10, |e| match e {
                Event::Head(h) => Fragment::Whole(h),
                Event::Body(data) => Fragment::Part { data, last: false },
                Event::Done => Fragment::Part {
                    data: Vec::new(),
                    last: true,
                },
            })
        };
        contract::check_stack(assemble, CHUNKED);
        let (items, error) = test_support::decode_all(assemble, CHUNKED);
        assert_eq!(error, None);
        assert_eq!(items.len(), 2);
        assert_eq!(items[1], Assembled::Message(b"hello".to_vec()));
        let bytes = response_with("Connection: close\r\nContent-Length: 4\r\n", b"a\nb\n");
        let pipe = || {
            Pipe::new(
                Responses::new(small()),
                Lines::new(16, Ending::LfOrCrlf),
                |event| match event {
                    Event::Body(data) => Carry::Bytes(data),
                    other => Carry::Through(other),
                },
            )
        };
        contract::check_stack(pipe, &bytes);
        let (items, error) = test_support::decode_all(pipe, &bytes);
        assert_eq!(error, None);
        assert!(items.contains(&Layered::Inner(Ok(b"a".to_vec()))));
        assert!(items.contains(&Layered::Inner(Ok(b"b".to_vec()))));
        let mut demux = Demux::new(2, 1 << 20, |_: &u8| Requests::default());
        assert_eq!(demux.push(&1, GET), GET.len());
        assert_eq!(demux.push(&2, POST), POST.len());
        let mut count = 0usize;
        while let Some((_, event)) = demux.next() {
            assert!(event.is_ok());
            count = count.saturating_add(1);
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn generated_inputs_and_mutations_obey_contracts() {
        let mut rng = Lcg::new(9112);
        for _ in 0..24 {
            let mut bytes = if rng.below(2) == 0 {
                POST.to_vec()
            } else {
                CHUNKED.to_vec()
            };
            test_support::mutate(&mut rng, &mut bytes);
            contract::check_decode(|| Requests::new(small()), &bytes);
            contract::check_wire::<Request>(&bytes);
            let mut response = OK.to_vec();
            test_support::mutate(&mut rng, &mut response);
            contract::check_decode(|| Responses::new(small()), &response);
            contract::check_wire::<Response>(&response);
        }
        for _ in 0..16 {
            let bytes = rng.bytes(128);
            contract::check_decode(Requests::default, &bytes);
            contract::check_decode(Responses::default, &bytes);
            contract::check_wire::<RequestHead>(&bytes);
            contract::check_wire::<ResponseHead>(&bytes);
            contract::check_wire::<Chunk>(&bytes);
        }
    }
}
