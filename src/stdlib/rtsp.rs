//! RTSP: reading and writing Real-Time Streaming Protocol messages and
//! interleaved data, with no I/O.
//!
//! `Message` and `Frame` implement `Wire`, and `Frames` decodes messages and
//! interleaved data. `Session` represents a header value, not a connection
//! state machine. This module has no streaming `Service`, media transport, or
//! playback engine.
//!
//! RTSP is how IP cameras, video recorders and media servers are told to
//! stream. A client asks about a stream with DESCRIBE, agrees on how the
//! media travels with SETUP, and starts and stops it with PLAY, PAUSE and
//! TEARDOWN. Messages look like HTTP: a start line, header fields, a blank
//! line and a body, which is usually an SDP description. They go over TCP,
//! usually on port 554. The media goes over RTP, either on UDP ports the
//! two sides name in the Transport header, or on the same TCP connection
//! as binary frames that start with `$` (interleaved data). This module
//! follows RFC 2326 (RTSP 1.0) and RFC 7826 (RTSP 2.0), and reads and
//! writes both versions.
//!
//! Nothing here reads a socket. A world that plays a camera pushes the
//! bytes it reads into [`Stream<Frames>`](fictionet::stdlib::codec::Stream), which splits the
//! stream into [`Frame`]s: messages, by their Content-Length, and
//! interleaved frames, by their length. It reads the headers it needs with
//! [`Message::cseq`], [`Message::session`], [`Message::transports`] and
//! [`Message::range`], builds its answer (often with [`Message::reply`]),
//! and writes it with [`Wire::write`]. Bodies stay as bytes.
//! Which streams exist, and what they hold, is up to world code.
//!
//! Every reader checks lengths and characters, because the agent can send
//! any bytes it likes. Header values are read when asked for, so a request
//! with one malformed header can still be answered, as a real camera
//! would. Writers check what they write and return an error instead of
//! bytes that would not read back.
//!
//! RTSP 1.0 accepts CRLF and bare LF. RTSP 2.0 requires CRLF. Empty CRLF
//! and LF keep-alive lines are skipped between units in either version.
//! Writers always emit CRLF. Lines exclude their endings and are bounded
//! by [`MAX_LINE`]. The whole head, including endings, is bounded by
//! [`MAX_HEAD`]; the header count by [`MAX_HEADERS`]; bodies by [`MAX_BODY`].
//! Interleaved `$` frames are separate [`Frame`]s, with [`MAX_INTERLEAVED`]
//! payload bytes and a four-byte header.
//!
//! Content-Length selects exactly that many body bytes. Without it, there
//! is no body. RTSP 1.0 status 1xx, 204, and 304 ignore Content-Length and
//! have no body. RTSP 2.0 has no status-based body exception.
//!
//! A malformed start line or unrelated header with a trusted message
//! boundary is an error item. An over-limit line, head, or body, or an
//! untrusted Content-Length is a stream error. An RTSP 2.0 head with bare
//! LF also ends the stream because its CRLF boundary cannot be trusted.
//! Header-count errors are items. The driver reports truncated input at
//! EOF. Bodies remain bytes; SDP belongs to [`fictionet::stdlib::sdp`].
//!
//! A [`Service`](fictionet::stdlib::serve::Service) can use this decoder through
//! [`serve::connection`](fictionet::stdlib::serve::connection). Change its mode
//! between items with [`Driver::decoder`](fictionet::stdlib::serve::Driver::decoder).
//! See `docs/services.md` for an SMTP DATA service.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::rtsp::{Frame, Frames, Interleaved, TransportParam};
//!
//! let mut stream = Stream::new(Frames::new());
//! let request_bytes = b"SETUP rtsp://example.com/foo/bar/baz.rm RTSP/1.0\r\n\
//!     CSeq: 302\r\n\
//!     Transport: RTP/AVP;unicast;client_port=4588-4589\r\n\r\n";
//! assert_eq!(stream.push(request_bytes), request_bytes.len());
//! let Some(Ok(Ok(Frame::Message(request)))) = stream.next() else { panic!() };
//! assert_eq!(request.method(), Some("SETUP"));
//! assert_eq!(request.cseq(), Ok(302));
//! let mut transport = request.transports().unwrap().remove(0);
//! assert_eq!(transport.lower, None);
//! assert_eq!(transport.client_port(), Some((4588, Some(4589))));
//!
//! // The camera picks its own ports and answers, copying the CSeq.
//! transport.params.push(TransportParam::ServerPort(6256, Some(6257)));
//! let mut reply = request.reply(200, "OK");
//! reply.push_header("Session", "47112344");
//! reply.push_value("Transport", &transport).unwrap();
//! assert_eq!(
//!     reply.to_bytes().unwrap(),
//!     b"RTSP/1.0 200 OK\r\nCSeq: 302\r\nSession: 47112344\r\n\
//!       Transport: RTP/AVP;unicast;client_port=4588-4589;server_port=6256-6257\r\n\r\n"
//! );
//!
//! // Media over the same connection comes in frames that start with `$`.
//! assert_eq!(stream.push(b"$\x00\x00\x04abcd"), 8);
//! let frame = Interleaved { channel: 0, data: b"abcd".to_vec() };
//! assert_eq!(stream.next(), Some(Ok(Ok(Frame::Interleaved(frame)))));
//! assert_eq!(stream.next(), None);
//! ```

use fictionet::stdlib::codec::ascii::{self, is_tchar as is_token_byte, trim_ows_str as trim_ws};
use fictionet::stdlib::codec::head_body::{self, Header, Scanner};
use fictionet::stdlib::codec::{Decode, LineError, Step, Wire};

/// The TCP port RTSP servers listen on.
pub const PORT: u16 = 554;
/// The TCP port RTSP servers listen on for TLS (`rtsps`), from RFC 7826.
pub const TLS_PORT: u16 = 322;
/// The longest head a message may have: the start line, the header lines
/// and the blank line after them.
pub const MAX_HEAD: usize = 65_536;
/// The most content bytes in one codec start or header line, excluding CRLF.
pub const MAX_LINE: usize = MAX_HEAD - 2;
/// The longest body a message may carry.
pub const MAX_BODY: usize = 1_048_576;
/// The longest message: the longest head and the longest body.
pub const MAX_MESSAGE: usize = MAX_HEAD + MAX_BODY;
/// The most header fields one message may have, counting folded lines as
/// part of the field they continue.
pub const MAX_HEADERS: usize = 256;
/// The most transport specifications one message's Transport headers may
/// list.
pub const MAX_TRANSPORTS: usize = 16;
/// The most parameters one transport specification may have, and the
/// most items in one of its lists (SSRCs, modes, addresses).
pub const MAX_PARAMS: usize = 32;
/// The longest session identifier, from RFC 7826.
pub const MAX_SESSION_ID: usize = 256;
/// The largest number of seconds in a Session timeout or a normal play
/// time: 19 digits, as RFC 7826 section 20.2.3 allows.
const MAX_SECONDS: u64 = 9_999_999_999_999_999_999;
/// The byte that starts an interleaved frame.
pub const INTERLEAVED_MARKER: u8 = b'$';
/// The length of an interleaved frame's header: the marker, the channel
/// and a 16-bit length.
pub const INTERLEAVED_HEADER_LEN: usize = 4;
/// The most data one interleaved frame may carry, since its length is 16
/// bits.
pub const MAX_INTERLEAVED: usize = 65_535;

/// Request methods from RFC 2326 and RFC 7826.
pub mod method {
    /// The `DESCRIBE` request method.
    pub const DESCRIBE: &str = "DESCRIBE";
    /// The `ANNOUNCE` request method.
    pub const ANNOUNCE: &str = "ANNOUNCE";
    /// The `GET_PARAMETER` request method.
    pub const GET_PARAMETER: &str = "GET_PARAMETER";
    /// The `OPTIONS` request method.
    pub const OPTIONS: &str = "OPTIONS";
    /// The `PAUSE` request method.
    pub const PAUSE: &str = "PAUSE";
    /// The `PLAY` request method.
    pub const PLAY: &str = "PLAY";
    /// The `PLAY_NOTIFY` request method.
    pub const PLAY_NOTIFY: &str = "PLAY_NOTIFY";
    /// The `RECORD` request method.
    pub const RECORD: &str = "RECORD";
    /// The `REDIRECT` request method.
    pub const REDIRECT: &str = "REDIRECT";
    /// The `SETUP` request method.
    pub const SETUP: &str = "SETUP";
    /// The `SET_PARAMETER` request method.
    pub const SET_PARAMETER: &str = "SET_PARAMETER";
    /// The `TEARDOWN` request method.
    pub const TEARDOWN: &str = "TEARDOWN";
}

/// The protocol versions this module reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// `RTSP/1.0`, from RFC 2326.
    Rtsp10,
    /// `RTSP/2.0`, from RFC 7826.
    Rtsp20,
}

impl Version {
    /// The version as it appears on the start line.
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Rtsp10 => "RTSP/1.0",
            Version::Rtsp20 => "RTSP/2.0",
        }
    }
}

/// Why bytes are not an RTSP message or frame, or why a value cannot be
/// read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ended before a complete wire unit arrived.
    Incomplete,
    /// Bytes remain after the wire unit.
    Trailing,
    /// Writing would change a field or the body's framing.
    Unwritable,
    /// The head, a header value, the body, or a frame's data is longer
    /// than [`MAX_HEAD`], [`MAX_BODY`], or [`MAX_INTERLEAVED`].
    TooLong,
    /// More header fields than [`MAX_HEADERS`], more transports than
    /// [`MAX_TRANSPORTS`], or more parameters than [`MAX_PARAMS`].
    TooMany,
    /// A CR in the head that is not part of a CRLF pair, or, in RTSP 2.0,
    /// an LF that is not.
    LineEnding,
    /// The message head or header value is not UTF-8.
    Utf8,
    /// The request line or status line is malformed.
    StartLine,
    /// The version is well formed but is neither RTSP/1.0 nor RTSP/2.0. A
    /// server answers this with 505.
    Version,
    /// A header line has no colon or a bad name, or the first one starts
    /// with a space, as if it continued a field before it.
    HeaderLine,
    /// A header value holds a control character.
    HeaderValue,
    /// A Content-Length is not a number, or two disagree.
    ContentLength,
    /// Bytes read as an interleaved frame do not start with `$`.
    Marker,
    /// A header a read needs is absent. It names the header.
    Missing(&'static str),
    /// A header's value does not follow its grammar, or a header that may
    /// appear once appears twice. It names the header.
    HeaderSyntax(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Incomplete => f.write_str("incomplete wire unit"),
            Error::Trailing => f.write_str("bytes after wire unit"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::TooLong => {
                write!(
                    f,
                    "head or header value over {MAX_HEAD}, body over {MAX_BODY} or frame over {MAX_INTERLEAVED} bytes"
                )
            }
            Error::TooMany => {
                write!(
                    f,
                    "over {MAX_HEADERS} headers, {MAX_TRANSPORTS} transports or {MAX_PARAMS} parameters"
                )
            }
            Error::LineEnding => f.write_str("CR or LF outside a CRLF pair"),
            Error::Utf8 => f.write_str("head or header value is not UTF-8"),
            Error::StartLine => f.write_str("malformed request or status line"),
            Error::Version => f.write_str("version is not RTSP/1.0 or RTSP/2.0"),
            Error::HeaderLine => f.write_str("malformed header line"),
            Error::HeaderValue => f.write_str("control character in a header value"),
            Error::ContentLength => f.write_str("bad Content-Length"),
            Error::Marker => f.write_str("interleaved frame does not start with $"),
            Error::Missing(name) => write!(f, "no {name} header"),
            Error::HeaderSyntax(name) => write!(f, "malformed {name}"),
        }
    }
}

impl std::error::Error for Error {}

/// The first line of a message: a request line or a status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartLine {
    /// A request: the `method`, the request URI `uri` as written (an
    /// `rtsp://` URL, or `*` for OPTIONS), and the `version`.
    Request {
        /// The request method.
        method: String,
        /// The request URI as written.
        uri: String,
        /// The protocol version.
        version: Version,
    },
    /// A response: the `version`, the status `code`, 100 to 599, and the
    /// `reason` phrase.
    Status {
        /// The protocol version.
        version: Version,
        /// The status code.
        code: u16,
        /// The reason phrase.
        reason: String,
    },
}

/// One RTSP message: a start line, header fields in order, and a body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The request line or status line.
    pub start: StartLine,
    /// The header fields, in the order they came.
    pub headers: Vec<Header>,
    /// The body's bytes, unread.
    pub body: Vec<u8>,
}

impl Message {
    /// A request with no headers and no body.
    pub fn request(version: Version, method: &str, uri: &str) -> Message {
        Message {
            start: StartLine::Request {
                method: method.to_string(),
                uri: uri.to_string(),
                version,
            },
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A response with no headers and no body.
    pub fn response(version: Version, code: u16, reason: &str) -> Message {
        Message {
            start: StartLine::Status {
                version,
                code,
                reason: reason.to_string(),
            },
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// The method, for a request.
    pub fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            StartLine::Status { .. } => None,
        }
    }

    /// The request URI as written, for a request.
    pub fn uri(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { uri, .. } => Some(uri),
            StartLine::Status { .. } => None,
        }
    }

    /// The status code, for a response.
    pub fn status(&self) -> Option<u16> {
        match &self.start {
            StartLine::Status { code, .. } => Some(*code),
            StartLine::Request { .. } => None,
        }
    }

    /// The reason phrase, for a response.
    pub fn reason(&self) -> Option<&str> {
        match &self.start {
            StartLine::Status { reason, .. } => Some(reason),
            StartLine::Request { .. } => None,
        }
    }

    /// The protocol version on the start line.
    pub fn version(&self) -> Version {
        match &self.start {
            StartLine::Request { version, .. } | StartLine::Status { version, .. } => *version,
        }
    }

    /// The headers named `name`, in order. Case does not matter.
    pub fn headers_named<'a, 'n>(
        &'a self,
        name: &'n str,
    ) -> impl Iterator<Item = &'a Header> + use<'a, 'n> {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
    }

    /// The value of the first header named `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers_named(name).next().map(|h| h.value.as_str())
    }

    /// Adds a header at the end.
    pub fn push_header(&mut self, name: &str, value: &str) {
        self.headers.push(Header::new(name, value));
    }

    /// Adds a header from a wire value. Refuses a failed value write or
    /// invalid UTF-8, and leaves the headers unchanged on error.
    /// The message writer checks the header name, text, and size limits.
    pub fn push_value(
        &mut self,
        name: &str,
        value: &impl Wire<WriteError = Error>,
    ) -> Result<(), Error> {
        let value = String::from_utf8(value.to_bytes()?).map_err(|_| Error::Utf8)?;
        self.headers.push(Header {
            name: name.to_string(),
            value,
        });
        Ok(())
    }

    /// Sets the header named `name` to `value`: the first one is changed
    /// and any others are removed. With none, it is added at the end.
    pub fn set_header(&mut self, name: &str, value: &str) {
        match self
            .headers
            .iter()
            .position(|h| h.name.eq_ignore_ascii_case(name))
        {
            Some(i) => {
                self.headers[i].value = value.to_string();
                let mut seen = 0usize;
                self.headers.retain(|h| {
                    if !h.name.eq_ignore_ascii_case(name) {
                        return true;
                    }
                    seen += 1;
                    seen == 1
                });
            }
            None => self.push_header(name, value),
        }
    }

    /// Removes every header named `name`, and says how many there were.
    pub fn remove_header(&mut self, name: &str) -> usize {
        let before = self.headers.len();
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
        before - self.headers.len()
    }

    /// The CSeq: the request's sequence number, which its response copies.
    /// In RTSP 2.0 it is 1 to 9 digits, as RFC 7826 section 20.2.3 says.
    /// RTSP 1.0 sets no limit; a value over `u32::MAX` is
    /// [`Error::HeaderSyntax`].
    pub fn cseq(&self) -> Result<u32, Error> {
        let v = self.single("CSeq")?;
        if self.version() == Version::Rtsp20 && v.len() > 9 {
            return Err(Error::HeaderSyntax("CSeq"));
        }
        let n = parse_u64(v).ok_or(Error::HeaderSyntax("CSeq"))?;
        u32::try_from(n).map_err(|_| Error::HeaderSyntax("CSeq"))
    }

    /// The Session header: which session a request belongs to.
    pub fn session(&self) -> Result<Session, Error> {
        Session::read_value(self.single("Session")?)
    }

    /// The transport specifications of every Transport header, in order,
    /// most preferred first. With no Transport header, the list is empty.
    pub fn transports(&self) -> Result<Vec<Transport>, Error> {
        let mut out = Vec::new();
        for h in self.headers_named("Transport") {
            for t in Transport::read_list(&h.value)? {
                if out.len() >= MAX_TRANSPORTS {
                    return Err(Error::TooMany);
                }
                out.push(t);
            }
        }
        Ok(out)
    }

    /// The Range header: which part of a stream to play. RTSP 2.0 has no
    /// `time` parameter, so in an RTSP 2.0 message one is
    /// [`Error::HeaderSyntax`].
    pub fn range(&self) -> Result<Range, Error> {
        let range = Range::read_value(self.single("Range")?)?;
        if self.version() == Version::Rtsp20 && range.time.is_some() {
            return Err(Error::HeaderSyntax("Range"));
        }
        Ok(range)
    }

    /// The Content-Length, if the message has one.
    pub fn content_length(&self) -> Result<Option<usize>, Error> {
        let mut length = None;
        for h in self.headers_named("Content-Length") {
            let n = parse_content_length(&h.value)?;
            if length.is_some_and(|l| l != n) {
                return Err(Error::ContentLength);
            }
            length = Some(n);
        }
        Ok(length)
    }

    /// A response to this request in the same version, with its CSeq,
    /// Session and Timestamp headers copied in order. RFC 7826 section
    /// 18.20 has every response copy the CSeq, and RFC 2326 section 12.38
    /// and RFC 7826 section 18.53 have it echo the Timestamp.
    pub fn reply(&self, code: u16, reason: &str) -> Message {
        let mut reply = Message::response(self.version(), code, reason);
        reply.headers = self
            .headers
            .iter()
            .filter(|h| {
                ["CSeq", "Session", "Timestamp"]
                    .iter()
                    .any(|n| h.name.eq_ignore_ascii_case(n))
            })
            .cloned()
            .collect();
        reply
    }

    /// The value of the one header named `name`.
    fn single(&self, name: &'static str) -> Result<&str, Error> {
        let mut found = self.headers_named(name);
        let h = found.next().ok_or(Error::Missing(name))?;
        if found.next().is_some() {
            return Err(Error::HeaderSyntax(name));
        }
        Ok(&h.value)
    }
}

/// One frame of interleaved binary data: RTP or RTCP packets sent on the
/// RTSP connection itself, as RFC 2326 section 10.12 and RFC 7826 section
/// 14 describe. The Transport header's `interleaved` parameter says which
/// channel carries what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interleaved {
    /// The channel the frame is on.
    pub channel: u8,
    /// The frame's data, at most [`MAX_INTERLEAVED`] bytes.
    pub data: Vec<u8>,
}

impl Interleaved {
    /// Reads the frame at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the frame and how many bytes
    /// of `b` it took. Bytes that do not start with `$` are
    /// [`Error::Marker`].
    fn parse_prefix(b: &[u8]) -> Result<Option<(Interleaved, usize)>, Error> {
        match b.first() {
            None => return Ok(None),
            Some(&INTERLEAVED_MARKER) => {}
            Some(_) => return Err(Error::Marker),
        }
        if b.len() < INTERLEAVED_HEADER_LEN {
            return Ok(None);
        }
        let n = usize::from(u16::from_be_bytes([b[2], b[3]]));
        let end = INTERLEAVED_HEADER_LEN + n;
        let Some(data) = b.get(INTERLEAVED_HEADER_LEN..end) else {
            return Ok(None);
        };
        Ok(Some((
            Interleaved {
                channel: b[1],
                data: data.to_vec(),
            },
            end,
        )))
    }
}

/// What an RTSP connection carries: a message or an interleaved frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A request or a response.
    Message(Message),
    /// A frame of binary data.
    Interleaved(Interleaved),
}

/// Reads complete RTSP units with bounded line and body framing.
///
/// Use with [`Stream<Frames>`](fictionet::stdlib::codec::Stream). Items are `Result<Frame, Error>`.
/// A bad start line or header is an error item once a trusted body length
/// and the complete unit are available. Invalid lengths and byte limits
/// end the stream. Once the head is complete, bare LF in RTSP 2.0 ends the
/// stream because only CRLF can establish its message boundary. RTSP 1.0
/// accepts bare LF. Partial units return [`Step::Need`], including at EOF.
/// The driver reports truncation and returns stream errors once.
///
/// [`Scanner`] scans incrementally; each head byte is scanned a fixed number
/// of times. The driver retains the whole unit, so
/// [`fictionet::stdlib::codec::Stream::with_next`] includes its head and body.
/// Capacity is [`MAX_MESSAGE`]; no input bytes are held in decoder state.
/// Body framing follows Content-Length automatically, from the headers.
/// Each call yields at most one unit and returns control to the caller.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire}, rtsp::{Frames, Message}};
///
/// let bytes = b"RTSP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
/// let message = <Message as Wire>::parse(bytes)?;
/// let mut stream = Stream::new(Frames::new());
/// assert_eq!(stream.push(bytes), bytes.len());
/// assert_eq!(stream.next(), Some(Ok(Ok(fictionet::stdlib::rtsp::Frame::Message(message)))));
/// stream.end();
/// assert_eq!(stream.next(), None);
/// # Ok::<(), fictionet::stdlib::rtsp::Error>(())
/// ```
pub struct Frames {
    scanner: Scanner,
}

impl core::fmt::Debug for Frames {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frames")
            .field("scanner", &self.scanner)
            .finish_non_exhaustive()
    }
}

impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}

impl Frames {
    /// Creates a decoder using [`MAX_LINE`], [`MAX_HEAD`], and [`MAX_BODY`].
    pub fn new() -> Self {
        Self {
            scanner: Scanner::new(MAX_LINE, MAX_HEAD, false),
        }
    }
}

impl Decode for Frames {
    type Item = Result<Frame, Error>;
    type Error = Error;
    const NAME: &'static str = "RTSP";

    fn capacity(&self) -> usize {
        MAX_MESSAGE
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        if self.scanner.is_start() {
            let skip = skip_crlfs(input)?;
            if skip != 0 {
                self.scanner = Scanner::new(MAX_LINE, MAX_HEAD, false);
                return Ok(Step::Skip(skip));
            }
            if input.first() == Some(&INTERLEAVED_MARKER) {
                return Ok(match Interleaved::parse_prefix(input)? {
                    Some((frame, used)) => Step::Item(Ok(Frame::Interleaved(frame)), used),
                    None => Step::Need,
                });
            }
        }
        let Some((head, used)) = self.scanner.scan(input, frame_body_length, framing_error)? else {
            return Ok(Step::Need);
        };
        let body = &input[head..used];
        let message = parse_head(input.get(..head).ok_or(Error::TooLong)?).map(|mut message| {
            message.body = body.to_vec();
            message
        });
        Ok(Step::Item(message.map(Frame::Message), used))
    }
}

// Find the length independently of message syntax. This lets a malformed
// start line or unrelated header be returned as an item at a known boundary.
// Only offsets and lengths survive Need; header strings are never cached.
fn frame_body_length(head: &[u8]) -> Result<usize, Error> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let first = lines.next().unwrap_or_default();
    if let Ok(text) = core::str::from_utf8(first)
        && let Ok((version, code, _, _)) = start_line_parts(text)
    {
        if version == Version::Rtsp20
            && head
                .windows(2)
                .any(|pair| pair[1] == b'\n' && pair[0] != b'\r')
        {
            return Err(Error::LineEnding);
        }
        if code.is_some_and(|code| bodyless(version, code)) {
            return Ok(0);
        }
    }
    head_body::content_length(
        lines,
        |name| name.eq_ignore_ascii_case(b"Content-Length"),
        parse_content_length,
        true,
        Error::ContentLength,
    )
    .map(|length| length.unwrap_or(0))
}

#[inline]
fn framing_error(error: LineError) -> Error {
    match error {
        LineError::TooLong { .. } => Error::TooLong,
        _ => Error::LineEnding,
    }
}

fn read_wire(bytes: &[u8]) -> Result<Frame, Error> {
    if bytes.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let mut frames = Frames::new();
    let mut rest = bytes;
    loop {
        match frames.decode(rest, true)? {
            Step::Item(item, used) => {
                let item = item?;
                if used != rest.len() {
                    return Err(Error::Trailing);
                }
                return Ok(item);
            }
            Step::Skip(used) => rest = rest.get(used..).ok_or(Error::Incomplete)?,
            _ => return Err(Error::Incomplete),
        }
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete RTSP message. Leading CRLF and LF keep-alives
    /// are skipped. RTSP 1.0 allows bare LF; RTSP 2.0 requires CRLF.
    /// Content-Length selects the body. Without it there is no body.
    /// RTSP 1.0 status 1xx, 204, and 304 ignore Content-Length and have no
    /// body (RFC 2326 section 4.4). RTSP 2.0 has no such exception.
    /// Refuses malformed, incomplete, trailing, or over-limit input and
    /// values whose CRLF form would exceed the head or line limit.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let Frame::Message(message) = read_wire(bytes)? else {
            return Err(Error::StartLine);
        };
        message_size(&message)?;
        Ok(message)
    }

    /// Appends a CRLF message without changing any field. Leaves `out`
    /// unchanged on error. Content-Length fields are preserved, including
    /// spelling, position, and digits. Set them to match the body before
    /// writing. Values that need trimming or header injection are refused.
    /// A body length mismatch is [`Error::Unwritable`]. Refuses invalid
    /// methods (including those starting with `$`), URIs with spaces,
    /// status codes outside 100 to 599, bad header names or controls,
    /// and heads, lines, bodies, or header counts over their named limits.
    /// RTSP 1.0 status 1xx, 204, and 304 refuse a nonempty body.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let total = message_size(self)?;
        out.try_reserve(total).map_err(|_| Error::TooLong)?;
        match &self.start {
            StartLine::Request {
                method,
                uri,
                version,
            } => {
                out.extend_from_slice(method.as_bytes());
                out.push(b' ');
                out.extend_from_slice(uri.as_bytes());
                out.push(b' ');
                out.extend_from_slice(version.as_str().as_bytes());
            }
            StartLine::Status {
                version,
                code,
                reason,
            } => {
                out.extend_from_slice(version.as_str().as_bytes());
                out.extend_from_slice(format!(" {code} {reason}").as_bytes());
            }
        }
        out.extend_from_slice(b"\r\n");
        for header in &self.headers {
            out.extend_from_slice(header.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(header.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

fn message_size(message: &Message) -> Result<usize, Error> {
    let too_long = Error::TooLong;
    if message.body.len() > MAX_BODY {
        return Err(too_long);
    }
    if message.headers.len() > MAX_HEADERS {
        return Err(Error::TooMany);
    }
    // Count before formatting or copying caller-owned strings.
    let start = match &message.start {
        StartLine::Request {
            method,
            uri,
            version,
        } => method
            .len()
            .checked_add(uri.len())
            .and_then(|n| n.checked_add(version.as_str().len()))
            .and_then(|n| n.checked_add(2))
            .ok_or(too_long)?,
        StartLine::Status {
            version,
            code,
            reason,
        } => {
            if !(100..=599).contains(code) {
                return Err(Error::StartLine);
            }
            reason
                .len()
                .checked_add(version.as_str().len())
                .and_then(|n| n.checked_add(5))
                .ok_or(too_long)?
        }
    };
    if start > MAX_LINE {
        return Err(too_long);
    }
    let mut head = start.checked_add(4).ok_or(too_long)?;
    for header in &message.headers {
        let line = header
            .name
            .len()
            .checked_add(header.value.len())
            .and_then(|n| n.checked_add(2))
            .ok_or(too_long)?;
        if line > MAX_LINE {
            return Err(too_long);
        }
        head = head
            .checked_add(line)
            .and_then(|n| n.checked_add(2))
            .ok_or(too_long)?;
        if head > MAX_HEAD {
            return Err(too_long);
        }
    }
    if head > MAX_HEAD {
        return Err(too_long);
    }
    let total = head.checked_add(message.body.len()).ok_or(too_long)?;
    match &message.start {
        StartLine::Request { method, uri, .. } if !valid_method(method) || !valid_uri(uri) => {
            return Err(Error::StartLine);
        }
        StartLine::Status { reason, .. } if !valid_value(reason) => return Err(Error::StartLine),
        _ => {}
    }
    for header in &message.headers {
        if !is_token(&header.name) {
            return Err(Error::HeaderLine);
        }
        if !valid_value(&header.value) {
            return Err(Error::HeaderValue);
        }
        if trim_ws(&header.value) != header.value {
            return Err(Error::Unwritable);
        }
    }
    let length = match message.start {
        StartLine::Status { version, code, .. } if bodyless(version, code) => 0,
        _ => message.content_length()?.unwrap_or(0),
    };
    if length != message.body.len() {
        return Err(Error::Unwritable);
    }
    Ok(total)
}

impl Wire for Interleaved {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one `$` frame: marker, channel, 16-bit length, data.
    /// Refuses a different marker, incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Self::parse_prefix(bytes)? {
            Some((frame, used)) if used == bytes.len() => Ok(frame),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Incomplete),
        }
    }

    /// Appends `$`, the channel, the 16-bit length, and the data.
    /// Refuses data over [`MAX_INTERLEAVED`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let n = u16::try_from(self.data.len()).map_err(|_| Error::TooLong)?;
        out.extend_from_slice(&[INTERLEAVED_MARKER, self.channel]);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one message or `$` frame, skipping leading keep-alives.
    /// Refuses malformed or incomplete units, trailing bytes, and values
    /// whose canonical form exceeds a named limit.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let item = read_wire(bytes)?;
        if let Frame::Message(message) = &item {
            message_size(message)?;
        }
        Ok(item)
    }

    /// Appends a message or `$` frame. Refuses invalid fields, body length
    /// mismatches, and values over their named limits. Leaves `out`
    /// unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Message(message) => Wire::write(message, out),
            Self::Interleaved(frame) => Wire::write(frame, out),
        }
    }
}

/// A Session header's value: the session identifier and how long the
/// server keeps the session without hearing from the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// The identifier: 1 to [`MAX_SESSION_ID`] letters, digits and
    /// `$ - _ . +`.
    pub id: String,
    /// The `timeout` parameter, in seconds, at most 19 digits.
    pub timeout: Option<u64>,
}

impl Session {
    fn read_value(v: &str) -> Result<Session, Error> {
        if v.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        const BAD: Error = Error::HeaderSyntax("Session");
        let mut parts = v.split(';');
        let id = trim_ws(parts.next().unwrap_or(""));
        if !valid_session_id(id) {
            return Err(BAD);
        }
        let mut timeout = None;
        for p in parts {
            let (name, value) = p.split_once('=').ok_or(BAD)?;
            if !trim_ws(name).eq_ignore_ascii_case("timeout") || timeout.is_some() {
                return Err(BAD);
            }
            timeout = Some(
                parse_u64(trim_ws(value))
                    .filter(|&t| t <= MAX_SECONDS)
                    .ok_or(BAD)?,
            );
        }
        Ok(Session {
            id: id.to_string(),
            timeout,
        })
    }

    fn format_value(&self) -> Result<String, Error> {
        if !valid_session_id(&self.id) || self.timeout.is_some_and(|t| t > MAX_SECONDS) {
            return Err(Error::HeaderSyntax("Session"));
        }
        Ok(match self.timeout {
            Some(t) => format!("{};timeout={t}", self.id),
            None => self.id.clone(),
        })
    }
}

/// The lower transport under RTP: what carries the packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lower {
    /// UDP, the default when a transport names none.
    Udp,
    /// TCP, usually the RTSP connection itself, with interleaved frames.
    Tcp,
    /// Any other token, which RFC 7826 allows, kept as written. It is
    /// never `TCP` or `UDP` in any case. For a transport identifier with
    /// more than three parts, which RFC 7826's `other-trans` allows, it
    /// holds every part after the profile, joined by `/`.
    Other(String),
}

/// One parameter of a transport specification, from RFC 2326 section
/// 12.39 and RFC 7826 section 18.54. Names are read in any case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportParam {
    /// `unicast`: the media goes to one place.
    Unicast,
    /// `multicast`: the media goes to a multicast group.
    Multicast,
    /// `destination` or `destination=address` (RTSP 1.0): where to send
    /// the media.
    Destination(Option<String>),
    /// `source=address` (RTSP 1.0): where the media comes from.
    Source(String),
    /// `interleaved=0-1`: the first channel, and the last if it names a
    /// range, for frames on the RTSP connection.
    Interleaved(u8, Option<u8>),
    /// `append` (RTSP 1.0): record onto the end of what is there.
    Append,
    /// `ttl=127`: the multicast time to live.
    Ttl(u8),
    /// `layers=2`: how many multicast layers to use.
    Layers(u32),
    /// `port=3456-3457`: the multicast port, and the last if it names a
    /// range.
    Port(u16, Option<u16>),
    /// `client_port=4588-4589` (RTSP 1.0): the client's RTP port, and its
    /// RTCP port.
    ClientPort(u16, Option<u16>),
    /// `server_port=6256-6257` (RTSP 1.0): the server's RTP port, and its
    /// RTCP port.
    ServerPort(u16, Option<u16>),
    /// `ssrc=0A13C760`: the synchronization sources, exactly 8 hex digits
    /// each, joined by `/` in RTSP 2.0.
    Ssrc(Vec<u32>),
    /// `mode="PLAY"` or `mode="PLAY,RECORD"`: what the session is for.
    /// Both RFCs quote the list. It is read unquoted too, as many clients
    /// send it, and always written quoted.
    Mode(Vec<String>),
    /// `dest_addr=":4588"/":4589"` (RTSP 2.0): where to send RTP, then
    /// RTCP, each a host and port, with an empty host meaning the
    /// client's own address.
    DestAddr(Vec<String>),
    /// `src_addr="192.0.2.5:6256"/"192.0.2.5:6257"` (RTSP 2.0): where the
    /// media comes from.
    SrcAddr(Vec<String>),
    /// `setup=active`, `passive` or `actpass` (RTSP 2.0): which side opens
    /// a TCP media connection. The value is one of those three in any
    /// case, kept as written.
    Setup(String),
    /// `connection=new` or `existing` (RTSP 2.0): whether to reuse a TCP
    /// media connection. The value is one of those two in any case, kept
    /// as written.
    Connection(String),
    /// `RTCP-mux` (RTSP 2.0): RTP and RTCP share one port.
    RtcpMux,
    /// Any other parameter, such as `MIKEY`. The value is kept as written:
    /// a run, possibly empty, of quoted strings (with their quotes) and
    /// printable ASCII other than `"`, `;` and `,`, as RFC 7826's
    /// `trn-par-value` has it. Printable bytes outside RFC 7826's
    /// `rtsp-unreserved`, such as `:` and `/`, are kept for RTSP 1.0 peers
    /// and base64 values.
    Other {
        /// The parameter name.
        name: String,
        /// The optional value as written.
        value: Option<String>,
    },
}

/// Parameter names this module reads into their own variants, lowercase.
const KNOWN_PARAMS: [&str; 18] = [
    "unicast",
    "multicast",
    "destination",
    "source",
    "interleaved",
    "append",
    "ttl",
    "layers",
    "port",
    "client_port",
    "server_port",
    "ssrc",
    "mode",
    "dest_addr",
    "src_addr",
    "setup",
    "connection",
    "rtcp-mux",
];

/// One transport specification from a Transport header, such as
/// `RTP/AVP/TCP;unicast;interleaved=0-1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transport {
    /// The transport protocol, such as `RTP`.
    pub protocol: String,
    /// The profile, such as `AVP`, `SAVP`, `AVPF` or `SAVPF`. It is empty
    /// when the transport identifier is one token, as RFC 7826's
    /// `other-trans` allows, and then `lower` is `None`.
    pub profile: String,
    /// The lower transport, if named. With none, it is UDP.
    pub lower: Option<Lower>,
    /// The parameters, in order.
    pub params: Vec<TransportParam>,
}

impl Transport {
    fn read_value(spec: &str) -> Result<Transport, Error> {
        if spec.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        const BAD: Error = Error::HeaderSyntax("Transport");
        let parts = split_unquoted(spec, b';', MAX_PARAMS + 1, "Transport")?;
        let mut parts = parts.into_iter();
        let id = trim_ws(parts.next().unwrap_or(""));
        let mut names = id.splitn(3, '/');
        let protocol = names.next().filter(|p| is_token(p)).ok_or(BAD)?;
        let profile = match names.next() {
            None => "",
            Some(p) if is_token(p) => p,
            Some(_) => return Err(BAD),
        };
        let lower = match names.next() {
            None => None,
            Some(l) if l.eq_ignore_ascii_case("TCP") => Some(Lower::Tcp),
            Some(l) if l.eq_ignore_ascii_case("UDP") => Some(Lower::Udp),
            Some(l) if valid_other_lower(l) => Some(Lower::Other(l.to_string())),
            Some(_) => return Err(BAD),
        };
        let mut params = Vec::new();
        for p in parts {
            let p = trim_ws(p);
            if !p.is_empty() {
                params.push(parse_param(p).ok_or(BAD)?);
            }
        }
        if params.len() > MAX_PARAMS {
            return Err(Error::TooMany);
        }
        if both_deliveries(&params) {
            return Err(BAD);
        }
        Ok(Transport {
            protocol: protocol.to_string(),
            profile: profile.to_string(),
            lower,
            params,
        })
    }

    /// Reads a Transport header's value: one or more specifications
    /// separated by commas.
    fn read_list(v: &str) -> Result<Vec<Transport>, Error> {
        split_unquoted(v, b',', MAX_TRANSPORTS, "Transport")?
            .into_iter()
            .map(|s| Transport::read_value(trim_ws(s)))
            .collect()
    }

    fn format_value(&self) -> Result<String, Error> {
        const BAD: Error = Error::HeaderSyntax("Transport");
        let profile_ok =
            is_token(&self.profile) || (self.profile.is_empty() && self.lower.is_none());
        if !is_token(&self.protocol) || !profile_ok {
            return Err(BAD);
        }
        if self.params.len() > MAX_PARAMS {
            return Err(Error::TooMany);
        }
        if both_deliveries(&self.params) {
            return Err(BAD);
        }
        // Bound all caller-owned text before cloning or joining it.
        let mut size = self
            .protocol
            .len()
            .checked_add(self.profile.len())
            .ok_or(Error::TooLong)?;
        if let Some(Lower::Other(lower)) = &self.lower {
            size = size.checked_add(lower.len()).ok_or(Error::TooLong)?;
        }
        for param in &self.params {
            let strings: &[String] = match param {
                TransportParam::Destination(Some(value))
                | TransportParam::Source(value)
                | TransportParam::Setup(value)
                | TransportParam::Connection(value) => core::slice::from_ref(value),
                TransportParam::Mode(values)
                | TransportParam::DestAddr(values)
                | TransportParam::SrcAddr(values) => {
                    if values.len() > MAX_PARAMS {
                        return Err(Error::TooMany);
                    }
                    values
                }
                TransportParam::Other { name, value } => {
                    size = size
                        .checked_add(value.as_ref().map_or(0, String::len))
                        .ok_or(Error::TooLong)?;
                    core::slice::from_ref(name)
                }
                _ => &[],
            };
            for value in strings {
                size = size.checked_add(value.len()).ok_or(Error::TooLong)?;
            }
            if size > MAX_HEAD {
                return Err(Error::TooLong);
            }
        }
        if size > MAX_HEAD {
            return Err(Error::TooLong);
        }
        let mut out = self.protocol.clone();
        if !self.profile.is_empty() {
            out.push('/');
            out.push_str(&self.profile);
        }
        match &self.lower {
            Some(Lower::Tcp) => out.push_str("/TCP"),
            Some(Lower::Udp) => out.push_str("/UDP"),
            Some(Lower::Other(l)) => {
                if !valid_other_lower(l) {
                    return Err(BAD);
                }
                out.push('/');
                out.push_str(l);
            }
            None => {}
        }
        for p in &self.params {
            out.push(';');
            write_param(&mut out, p)?;
        }
        Ok(out)
    }

    /// The first `interleaved` parameter's channels.
    pub fn interleaved(&self) -> Option<(u8, Option<u8>)> {
        self.params.iter().find_map(|p| match p {
            TransportParam::Interleaved(a, b) => Some((*a, *b)),
            _ => None,
        })
    }

    /// The first `client_port` parameter's ports.
    pub fn client_port(&self) -> Option<(u16, Option<u16>)> {
        self.params.iter().find_map(|p| match p {
            TransportParam::ClientPort(a, b) => Some((*a, *b)),
            _ => None,
        })
    }

    /// The first `server_port` parameter's ports.
    pub fn server_port(&self) -> Option<(u16, Option<u16>)> {
        self.params.iter().find_map(|p| match p {
            TransportParam::ServerPort(a, b) => Some((*a, *b)),
            _ => None,
        })
    }

    /// The first `ssrc` parameter's synchronization sources.
    pub fn ssrc(&self) -> Option<&[u32]> {
        self.params.iter().find_map(|p| match p {
            TransportParam::Ssrc(list) => Some(list.as_slice()),
            _ => None,
        })
    }

    /// The first `mode` parameter's modes, such as `PLAY` or `RECORD`. With
    /// none, the mode is `PLAY`.
    pub fn modes(&self) -> Option<&[String]> {
        self.params.iter().find_map(|p| match p {
            TransportParam::Mode(list) => Some(list.as_slice()),
            _ => None,
        })
    }

    /// Whether the specification names `multicast`. With neither
    /// `unicast` nor `multicast` named, RFC 2326 section 12.39 makes
    /// multicast the default, while RFC 7826 section 18.54 requires one of
    /// them; many RTSP 1.0 servers take such a request as unicast, so world
    /// code that cares checks for [`TransportParam::Unicast`] too.
    pub fn is_multicast(&self) -> bool {
        self.params
            .iter()
            .any(|p| matches!(p, TransportParam::Multicast))
    }
}

/// A Range header's value: a span of a stream, and the wall-clock time
/// to act at, if given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// The span.
    pub span: Span,
    /// The `time` parameter (RTSP 1.0), a UTC time such as
    /// `19970123T153600Z`.
    pub time: Option<String>,
}

/// A span of a stream in one of the three time formats. With neither
/// end, the header names only the format, as RFC 7826 section 4.4 allows
/// in GET_PARAMETER requests (`Range: npt`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Span {
    /// `npt=10-15`: normal play time, from `start` to `end`.
    Npt {
        /// The start of the span, if given.
        start: Option<Npt>,
        /// The end of the span, if given.
        end: Option<Npt>,
    },
    /// `smpte=10:07:00-10:07:33:05.01`: SMPTE time codes at a frame `rate`.
    Smpte {
        /// The SMPTE frame rate.
        rate: SmpteRate,
        /// The start of the span, if given.
        start: Option<Smpte>,
        /// The end of the span, if given.
        end: Option<Smpte>,
    },
    /// `clock=19961108T142300Z-19961108T143520Z`: UTC times, as written.
    Clock {
        /// The start of the span, if given.
        start: Option<String>,
        /// The end of the span, if given.
        end: Option<String>,
    },
}

/// A normal play time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Npt {
    /// `now`: the live point.
    Now,
    /// A time from the start of the stream, in whole `seconds` and
    /// `nanos` below a second. Written as seconds, it is read from seconds
    /// or from `h:mm:ss`; digits past nanoseconds are dropped.
    Time {
        /// Whole seconds from the start.
        seconds: u64,
        /// Nanoseconds below one second.
        nanos: u32,
    },
}

/// The frame rate a SMPTE range counts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpteRate {
    /// `smpte`: 30 frames a second.
    Smpte30,
    /// `smpte-30-drop`: 29.97 frames a second, with drop-frame counting.
    Smpte30Drop,
    /// `smpte-25`: 25 frames a second.
    Smpte25,
}

impl SmpteRate {
    /// The unit's name in a Range header.
    pub fn as_str(self) -> &'static str {
        match self {
            SmpteRate::Smpte30 => "smpte",
            SmpteRate::Smpte30Drop => "smpte-30-drop",
            SmpteRate::Smpte25 => "smpte-25",
        }
    }
}

/// A SMPTE time code: hours, minutes, seconds, and optionally frames and
/// hundredths of a frame. Hours and subframes are at most 99, minutes and
/// seconds at most 59, and frames below the rate (30 or 25).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Smpte {
    /// Hours.
    pub hours: u8,
    /// Minutes.
    pub minutes: u8,
    /// Seconds.
    pub seconds: u8,
    /// Frames.
    pub frames: Option<u8>,
    /// Hundredths of a frame, only given with frames.
    pub subframes: Option<u8>,
}

impl Range {
    fn read_value(v: &str) -> Result<Range, Error> {
        if v.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        const BAD: Error = Error::HeaderSyntax("Range");
        let mut parts = v.split(';');
        let spec = trim_ws(parts.next().unwrap_or(""));
        let mut time = None;
        for p in parts {
            let (name, value) = p.split_once('=').ok_or(BAD)?;
            let value = trim_ws(value);
            if !trim_ws(name).eq_ignore_ascii_case("time") || time.is_some() || !valid_utc(value) {
                return Err(BAD);
            }
            time = Some(value.to_string());
        }
        // With no `=`, the value names only the format.
        let (unit, a, b) = match spec.split_once('=') {
            None => (spec, None, None),
            Some((unit, value)) => {
                let (a, b) = trim_ws(value).split_once('-').ok_or(BAD)?;
                let (a, b) = (trim_ws(a), trim_ws(b));
                if a.is_empty() && b.is_empty() {
                    return Err(BAD);
                }
                (
                    trim_ws(unit),
                    (!a.is_empty()).then_some(a),
                    (!b.is_empty()).then_some(b),
                )
            }
        };
        let span = if unit.eq_ignore_ascii_case("npt") {
            Span::Npt {
                start: opt(a, parse_npt).ok_or(BAD)?,
                end: opt(b, parse_npt).ok_or(BAD)?,
            }
        } else if unit.eq_ignore_ascii_case("clock") {
            let utc = |s: &str| valid_utc(s).then(|| s.to_string());
            Span::Clock {
                start: opt(a, utc).ok_or(BAD)?,
                end: opt(b, utc).ok_or(BAD)?,
            }
        } else {
            let rate = [
                SmpteRate::Smpte30,
                SmpteRate::Smpte30Drop,
                SmpteRate::Smpte25,
            ]
            .into_iter()
            .find(|r| unit.eq_ignore_ascii_case(r.as_str()))
            .ok_or(BAD)?;
            let smpte = |s: &str| parse_smpte(s, rate);
            Span::Smpte {
                rate,
                start: opt(a, smpte).ok_or(BAD)?,
                end: opt(b, smpte).ok_or(BAD)?,
            }
        };
        Ok(Range { span, time })
    }

    fn format_value(&self) -> Result<String, Error> {
        if self.time.as_ref().is_some_and(|time| time.len() > 26) {
            return Err(Error::HeaderSyntax("Range"));
        }
        const BAD: Error = Error::HeaderSyntax("Range");
        let (unit, start, end) = match &self.span {
            Span::Npt { start, end } => (
                "npt",
                opt(start.as_ref(), write_npt),
                opt(end.as_ref(), write_npt),
            ),
            Span::Smpte { rate, start, end } => {
                let smpte = |t: &Smpte| write_smpte(t, *rate);
                (
                    rate.as_str(),
                    opt(start.as_ref(), smpte),
                    opt(end.as_ref(), smpte),
                )
            }
            Span::Clock { start, end } => {
                let utc = |s: &String| valid_utc(s).then(|| s.clone());
                ("clock", opt(start.as_ref(), utc), opt(end.as_ref(), utc))
            }
        };
        let mut out = match (start.ok_or(BAD)?, end.ok_or(BAD)?) {
            (None, None) => unit.to_string(),
            (start, end) => format!(
                "{unit}={}-{}",
                start.unwrap_or_default(),
                end.unwrap_or_default()
            ),
        };
        if let Some(t) = &self.time {
            if !valid_utc(t) {
                return Err(BAD);
            }
            out.push_str(";time=");
            out.push_str(t);
        }
        Ok(out)
    }
}

/// `f` applied to `x` if it is there: `None` if `f` fails, and
/// `Some(None)` if there was no `x`.
fn opt<T, U>(x: Option<T>, f: impl Fn(T) -> Option<U>) -> Option<Option<U>> {
    match x {
        None => Some(None),
        Some(x) => f(x).map(Some),
    }
}

/// Reads `now`, seconds with an optional fraction, or `h:mm:ss` with an
/// optional fraction.
fn parse_npt(s: &str) -> Option<Npt> {
    if s.eq_ignore_ascii_case("now") {
        return Some(Npt::Now);
    }
    let (whole, fraction) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if !fraction.bytes().all(|d| d.is_ascii_digit()) {
        return None;
    }
    let mut nanos = 0u32;
    for i in 0..9 {
        let d = fraction
            .as_bytes()
            .get(i)
            .map_or(0, |d| u32::from(d - b'0'));
        nanos = nanos * 10 + d;
    }
    let seconds = if whole.contains(':') {
        let mut parts = whole.split(':');
        let (h, m, sec) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || m.len() > 2 || sec.len() > 2 {
            return None;
        }
        let (h, m, sec) = (parse_u64(h)?, parse_u64(m)?, parse_u64(sec)?);
        if m > 59 || sec > 59 {
            return None;
        }
        h.checked_mul(3600)?.checked_add(m * 60 + sec)?
    } else {
        parse_u64(whole)?
    };
    if seconds > MAX_SECONDS {
        return None;
    }
    Some(Npt::Time { seconds, nanos })
}

fn write_npt(t: &Npt) -> Option<String> {
    match *t {
        Npt::Now => Some("now".to_string()),
        Npt::Time { seconds, .. } if seconds > MAX_SECONDS => None,
        Npt::Time { seconds, nanos: 0 } => Some(seconds.to_string()),
        Npt::Time { seconds, nanos } if nanos < 1_000_000_000 => {
            let f = format!("{nanos:09}");
            Some(format!("{seconds}.{}", f.trim_end_matches('0')))
        }
        Npt::Time { .. } => None,
    }
}

/// Reads `hh:mm:ss`, `hh:mm:ss:ff` or `hh:mm:ss:ff.ss`, each part one or
/// two digits, and checks the time exists at `rate`.
fn parse_smpte(s: &str, rate: SmpteRate) -> Option<Smpte> {
    let two = |p: &str| {
        if (1..=2).contains(&p.len()) {
            parse_u64(p).map(|n| n as u8)
        } else {
            None
        }
    };
    let mut parts = s.split(':');
    let (h, m, sec) = (parts.next()?, parts.next()?, parts.next()?);
    let last = parts.next();
    if parts.next().is_some() {
        return None;
    }
    let (frames, subframes) = match last {
        None => (None, None),
        Some(f) => match f.split_once('.') {
            Some((f, sub)) => (Some(two(f)?), Some(two(sub)?)),
            None => (Some(two(f)?), None),
        },
    };
    let t = Smpte {
        hours: two(h)?,
        minutes: two(m)?,
        seconds: two(sec)?,
        frames,
        subframes,
    };
    smpte_exists(&t, rate).then_some(t)
}

/// Whether `t` is a time at `rate`: RFC 2326 section 3.5 and RFC 7826
/// section 4.4.1 count frames from 0 below the rate, and minutes and
/// seconds are clock values.
fn smpte_exists(t: &Smpte, rate: SmpteRate) -> bool {
    let fps = match rate {
        SmpteRate::Smpte30 | SmpteRate::Smpte30Drop => 30,
        SmpteRate::Smpte25 => 25,
    };
    t.hours <= 99
        && t.minutes <= 59
        && t.seconds <= 59
        && t.frames.is_none_or(|f| f < fps)
        && t.subframes.is_none_or(|s| s <= 99)
}

fn write_smpte(t: &Smpte, rate: SmpteRate) -> Option<String> {
    let ok = |n: u8| n <= 99;
    if !smpte_exists(t, rate) {
        return None;
    }
    let mut out = format!("{:02}:{:02}:{:02}", t.hours, t.minutes, t.seconds);
    match (t.frames, t.subframes) {
        (None, None) => {}
        (Some(f), None) if ok(f) => out.push_str(&format!(":{f:02}")),
        (Some(f), Some(s)) if ok(f) && ok(s) => out.push_str(&format!(":{f:02}.{s:02}")),
        _ => return None,
    }
    Some(out)
}

/// Whether `s` is a UTC time: 8 digits, `T`, 6 digits, an optional
/// fraction of 1 to 9 digits, and `Z`, as RFC 7826 section 20.2.3 has it,
/// naming a date and time that exist. A second of 60 is allowed for leap
/// seconds.
fn valid_utc(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: &[u8]| !r.is_empty() && r.iter().all(u8::is_ascii_digit);
    if !(16..=26).contains(&b.len())
        || b[8] != b'T'
        || b[b.len() - 1] != b'Z'
        || !digits(&b[..8])
        || !digits(&b[9..15])
    {
        return false;
    }
    let fraction_ok = match &b[15..b.len() - 1] {
        [] => true,
        [b'.', rest @ ..] => rest.len() <= 9 && digits(rest),
        _ => false,
    };
    let n = |r: &[u8]| r.iter().fold(0u32, |a, d| a * 10 + u32::from(d - b'0'));
    let (year, month, day) = (n(&b[..4]), n(&b[4..6]), n(&b[6..8]));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    fraction_ok
        && (1..=days).contains(&day)
        && n(&b[9..11]) <= 23
        && n(&b[11..13]) <= 59
        && n(&b[13..15]) <= 60
}

/// Whether `l` can be [`Lower::Other`]: tokens joined by `/`, and not
/// `TCP` or `UDP`.
fn valid_other_lower(l: &str) -> bool {
    l.split('/').all(is_token) && !l.eq_ignore_ascii_case("TCP") && !l.eq_ignore_ascii_case("UDP")
}

/// Whether `params` names both `unicast` and `multicast`.
fn both_deliveries(params: &[TransportParam]) -> bool {
    params.contains(&TransportParam::Unicast) && params.contains(&TransportParam::Multicast)
}

/// Whether `v` is a `setup` value (`setup` true) or a `connection` value.
fn valid_tcp_choice(v: &str, setup: bool) -> bool {
    let allowed: &[&str] = if setup {
        &["active", "passive", "actpass"]
    } else {
        &["new", "existing"]
    };
    allowed.iter().any(|a| v.eq_ignore_ascii_case(a))
}

/// Reads one transport parameter, `name` or `name=value`, trimmed.
fn parse_param(p: &str) -> Option<TransportParam> {
    use TransportParam as P;
    let (name, value) = match p.split_once('=') {
        Some((n, v)) => (trim_ws(n), Some(trim_ws(v))),
        None => (p, None),
    };
    if !is_token(name) {
        return None;
    }
    let flag = |p: P| value.is_none().then_some(p);
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "unicast" => flag(P::Unicast),
        "multicast" => flag(P::Multicast),
        "append" => flag(P::Append),
        "rtcp-mux" => flag(P::RtcpMux),
        "destination" => match value {
            None => Some(P::Destination(None)),
            Some(v) => is_plain_value(v).then(|| P::Destination(Some(v.to_string()))),
        },
        "source" => value
            .filter(|v| is_plain_value(v))
            .map(|v| P::Source(v.to_string())),
        "interleaved" => {
            let (a, b) = pair(value?, 3)?;
            Some(P::Interleaved(
                u8::try_from(a).ok()?,
                opt(b, |b| u8::try_from(b).ok())?,
            ))
        }
        "ttl" => Some(P::Ttl(u8::try_from(parse_digits(value?, 3)?).ok()?)),
        "layers" => Some(P::Layers(u32::try_from(parse_u64(value?)?).ok()?)),
        "port" | "client_port" | "server_port" => {
            let (a, b) = pair(value?, 5)?;
            let (a, b) = (u16::try_from(a).ok()?, opt(b, |b| u16::try_from(b).ok())?);
            Some(match lower.as_str() {
                "port" => P::Port(a, b),
                "client_port" => P::ClientPort(a, b),
                _ => P::ServerPort(a, b),
            })
        }
        "ssrc" => {
            let mut out = Vec::new();
            for h in value?.split('/') {
                let h = trim_ws(h);
                if out.len() >= MAX_PARAMS
                    || h.len() != 8
                    || !h.bytes().all(|d| d.is_ascii_hexdigit())
                {
                    return None;
                }
                out.push(u32::from_str_radix(h, 16).ok()?);
            }
            Some(P::Ssrc(out))
        }
        "mode" => {
            let v = value?;
            if !v.starts_with('"') {
                return is_token(v).then(|| P::Mode(vec![v.to_string()]));
            }
            if !valid_quoted(v) {
                return None;
            }
            let mut out = Vec::new();
            for m in v[1..v.len() - 1].split(',') {
                let m = trim_ws(m);
                if out.len() >= MAX_PARAMS || !is_token(m) {
                    return None;
                }
                out.push(m.to_string());
            }
            Some(P::Mode(out))
        }
        "dest_addr" => parse_addr_list(value?).map(P::DestAddr),
        "src_addr" => parse_addr_list(value?).map(P::SrcAddr),
        "setup" => value
            .filter(|v| valid_tcp_choice(v, true))
            .map(|v| P::Setup(v.to_string())),
        "connection" => value
            .filter(|v| valid_tcp_choice(v, false))
            .map(|v| P::Connection(v.to_string())),
        _ => match value {
            None => Some(P::Other {
                name: name.to_string(),
                value: None,
            }),
            Some(v) if valid_ext_value(v) => Some(P::Other {
                name: name.to_string(),
                value: Some(v.to_string()),
            }),
            Some(_) => None,
        },
    }
}

/// Writes one transport parameter, checking it reads back.
fn write_param(out: &mut String, p: &TransportParam) -> Result<(), Error> {
    use TransportParam as P;
    const BAD: Error = Error::HeaderSyntax("Transport");
    let list_ok = |n: usize| {
        if n == 0 {
            Err(BAD)
        } else if n > MAX_PARAMS {
            Err(Error::TooMany)
        } else {
            Ok(())
        }
    };
    let range = |a: u16, b: Option<u16>| match b {
        Some(b) => format!("{a}-{b}"),
        None => a.to_string(),
    };
    match p {
        P::Unicast => out.push_str("unicast"),
        P::Multicast => out.push_str("multicast"),
        P::Append => out.push_str("append"),
        P::RtcpMux => out.push_str("RTCP-mux"),
        P::Destination(None) => out.push_str("destination"),
        P::Destination(Some(v)) | P::Source(v) => {
            if !is_plain_value(v) {
                return Err(BAD);
            }
            out.push_str(if matches!(p, P::Source(_)) {
                "source="
            } else {
                "destination="
            });
            out.push_str(v);
        }
        P::Interleaved(a, b) => out.push_str(&format!(
            "interleaved={}",
            range(u16::from(*a), b.map(u16::from))
        )),
        P::Ttl(t) => out.push_str(&format!("ttl={t}")),
        P::Layers(n) => out.push_str(&format!("layers={n}")),
        P::Port(a, b) => out.push_str(&format!("port={}", range(*a, *b))),
        P::ClientPort(a, b) => out.push_str(&format!("client_port={}", range(*a, *b))),
        P::ServerPort(a, b) => out.push_str(&format!("server_port={}", range(*a, *b))),
        P::Ssrc(list) => {
            list_ok(list.len())?;
            let hex: Vec<String> = list.iter().map(|s| format!("{s:08X}")).collect();
            out.push_str("ssrc=");
            out.push_str(&hex.join("/"));
        }
        P::Mode(list) => {
            list_ok(list.len())?;
            if !list.iter().all(|m| is_token(m)) {
                return Err(BAD);
            }
            out.push_str("mode=\"");
            out.push_str(&list.join(","));
            out.push('"');
        }
        P::DestAddr(list) | P::SrcAddr(list) => {
            list_ok(list.len())?;
            if !list.iter().all(|a| valid_addr(a)) {
                return Err(BAD);
            }
            out.push_str(if matches!(p, P::DestAddr(_)) {
                "dest_addr="
            } else {
                "src_addr="
            });
            let quoted: Vec<String> = list.iter().map(|a| format!("\"{a}\"")).collect();
            out.push_str(&quoted.join("/"));
        }
        P::Setup(v) | P::Connection(v) => {
            if !valid_tcp_choice(v, matches!(p, P::Setup(_))) {
                return Err(BAD);
            }
            out.push_str(if matches!(p, P::Setup(_)) {
                "setup="
            } else {
                "connection="
            });
            out.push_str(v);
        }
        P::Other { name, value } => {
            if !is_token(name) || KNOWN_PARAMS.iter().any(|k| k.eq_ignore_ascii_case(name)) {
                return Err(BAD);
            }
            out.push_str(name);
            if let Some(v) = value {
                if !valid_ext_value(v) {
                    return Err(BAD);
                }
                out.push('=');
                out.push_str(v);
            }
        }
    }
    Ok(())
}

/// Reads `n` or `n-m`, each 1 to `max` digits.
fn pair(v: &str, max: usize) -> Option<(u64, Option<u64>)> {
    match v.split_once('-') {
        Some((a, b)) => Some((parse_digits(a, max)?, Some(parse_digits(b, max)?))),
        None => Some((parse_digits(v, max)?, None)),
    }
}

/// Reads 1 to `max` decimal digits.
fn parse_digits(s: &str, max: usize) -> Option<u64> {
    if s.len() > max {
        return None;
    }
    parse_u64(s)
}

/// Reads quoted addresses joined by `/`, with spaces or tabs allowed
/// around each `/`, as RFC 7826 section 20.1 defines SLASH.
fn parse_addr_list(v: &str) -> Option<Vec<String>> {
    let b = v.as_bytes();
    let skip_ws = |mut i: usize| {
        while matches!(b.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        i
    };
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        if b.get(i) != Some(&b'"') || out.len() >= MAX_PARAMS {
            return None;
        }
        let end = quoted_end(b, i)?;
        let inner = &v[i + 1..end - 1];
        if !valid_addr(inner) {
            return None;
        }
        out.push(inner.to_string());
        i = skip_ws(end);
        match b.get(i) {
            None => return Some(out),
            Some(b'/') => i = skip_ws(i + 1),
            Some(_) => return None,
        }
    }
}

/// Whether `s` can sit inside the quotes of `dest_addr` or `src_addr`.
fn valid_addr(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// Whether `s` is an unquoted parameter value: printable ASCII but for
/// `"`, `;` and `,`.
fn is_plain_value(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b';' | b','))
}

/// Whether `s` is an extension parameter's value: a run, possibly empty,
/// of quoted strings and bytes [`is_plain_value`] allows.
fn valid_ext_value(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            match quoted_end(b, i) {
                Some(end) => i = end,
                None => return false,
            }
        } else if b[i].is_ascii_graphic() && !matches!(b[i], b';' | b',') {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

/// Whether `s` is exactly one quoted string.
fn valid_quoted(s: &str) -> bool {
    s.starts_with('"') && quoted_end(s.as_bytes(), 0) == Some(s.len())
}

/// Where the quoted string that starts at `b[i]` ends, just past its
/// closing quote. A backslash escapes the byte after it. Control
/// characters are not allowed.
fn quoted_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i.checked_add(1)?;
    loop {
        match *b.get(j)? {
            b'"' => return Some(j + 1),
            b'\\' => {
                if is_ctl(*b.get(j + 1)?) {
                    return None;
                }
                j += 2;
            }
            c if is_ctl(c) => return None,
            _ => j += 1,
        }
    }
}

/// `s` split at each `sep` outside quoted strings. More than `max` parts
/// is [`Error::TooMany`], and an empty or unclosed part is
/// [`Error::HeaderSyntax`]. A part may be empty only when `sep` is `;`.
fn split_unquoted<'a>(
    s: &'a str,
    sep: u8,
    max: usize,
    name: &'static str,
) -> Result<Vec<&'a str>, Error> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut push = |part: &'a str| {
        if sep != b';' && trim_ws(part).is_empty() {
            return Err(Error::HeaderSyntax(name));
        }
        if out.len() >= max {
            return Err(Error::TooMany);
        }
        out.push(part);
        Ok(())
    };
    let (mut start, mut i) = (0, 0);
    while i < b.len() {
        if b[i] == b'"' {
            i = quoted_end(b, i).ok_or(Error::HeaderSyntax(name))?;
            continue;
        }
        if b[i] == sep {
            push(&s[start..i])?;
            start = i + 1;
        }
        i += 1;
    }
    push(&s[start..])?;
    Ok(out)
}

fn valid_session_id(s: &str) -> bool {
    (1..=MAX_SESSION_ID).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'$' | b'-' | b'_' | b'.' | b'+'))
}

/// How many bytes of CRLF pairs and bare LFs start `b`.
fn skip_crlfs(b: &[u8]) -> Result<usize, Error> {
    let mut skip = 0usize;
    loop {
        let n = match b.get(skip..).unwrap_or_default() {
            [b'\r', b'\n', ..] => 2,
            [b'\n', ..] => 1,
            _ => return Ok(skip),
        };
        skip = skip.checked_add(n).ok_or(Error::TooLong)?;
    }
}

/// Whether an RTSP 1.0 response with this status may not carry a body:
/// 1xx, 204 and 304, from RFC 2326 section 4.4. RFC 7826 has no such rule.
fn bodyless(version: Version, code: u16) -> bool {
    version == Version::Rtsp10 && (code < 200 || code == 204 || code == 304)
}

/// Reads a head after framing has checked its body length. Lines end with
/// CRLF, or in RTSP 1.0 with a bare LF too.
fn parse_head(head: &[u8]) -> Result<Message, Error> {
    let text = std::str::from_utf8(head).map_err(|_| Error::Utf8)?;
    let text = text.strip_suffix('\n').ok_or(Error::LineEnding)?;
    let mut bare_lf = !text.ends_with('\r');
    let text = text.strip_suffix('\r').unwrap_or(text);
    let text = text.strip_suffix('\n').ok_or(Error::LineEnding)?;
    let mut lines = text.split('\n').map(|line| match line.strip_suffix('\r') {
        Some(l) => (l, false),
        None => (line, true),
    });
    let (first, bare) = lines.next().unwrap_or(("", false));
    bare_lf |= bare;
    if first.contains('\r') {
        return Err(Error::LineEnding);
    }
    let start = parse_start_line(first)?;
    let version = match &start {
        StartLine::Request { version, .. } | StartLine::Status { version, .. } => *version,
    };
    let mut headers: Vec<Header> = Vec::new();
    for (line, bare) in lines {
        bare_lf |= bare;
        if line.contains('\r') || (bare_lf && version == Version::Rtsp20) {
            return Err(Error::LineEnding);
        }
        if line.starts_with([' ', '\t']) {
            let last = headers.last_mut().ok_or(Error::HeaderLine)?;
            let more = trim_ws(line);
            if !more.is_empty() {
                if !last.value.is_empty() {
                    last.value.push(' ');
                }
                last.value.push_str(more);
            }
            continue;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(Error::TooMany);
        }
        let colon = line.find(':').ok_or(Error::HeaderLine)?;
        let name = line[..colon].trim_end_matches([' ', '\t']);
        if !is_token(name) {
            return Err(Error::HeaderLine);
        }
        headers.push(Header::new(name, trim_ws(&line[colon + 1..])));
    }
    if bare_lf && version == Version::Rtsp20 {
        return Err(Error::LineEnding);
    }
    if !headers.iter().all(|h| valid_value(&h.value)) {
        return Err(Error::HeaderValue);
    }
    Ok(Message {
        start,
        headers,
        body: Vec::new(),
    })
}

fn parse_start_line(line: &str) -> Result<StartLine, Error> {
    let (version, code, first, second) = start_line_parts(line)?;
    Ok(match code {
        Some(code) => StartLine::Status {
            version,
            code,
            reason: first.to_owned(),
        },
        None => StartLine::Request {
            version,
            method: first.to_owned(),
            uri: second.to_owned(),
        },
    })
}

// Validate without allocating while finding the frame boundary.
#[inline]
fn start_line_parts(line: &str) -> Result<(Version, Option<u16>, &str, &str), Error> {
    if line
        .as_bytes()
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"RTSP/"))
    {
        let (version, rest) = line.split_once(' ').ok_or(Error::StartLine)?;
        let version = parse_version(version)?;
        let (code, reason) = rest.split_once(' ').unwrap_or((rest, ""));
        if code.len() != 3 || !valid_value(reason) {
            return Err(Error::StartLine);
        }
        let code = parse_u64(code).ok_or(Error::StartLine)? as u16;
        if !(100..=599).contains(&code) {
            return Err(Error::StartLine);
        }
        return Ok((version, Some(code), reason, ""));
    }
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::StartLine);
    };
    let version = parse_version(version)?;
    if !valid_method(method) || !valid_uri(uri) {
        return Err(Error::StartLine);
    }
    Ok((version, None, method, uri))
}

/// Reads `RTSP/1.0` or `RTSP/2.0`, ignoring leading zeros in each number
/// as RFC 2068 section 3.1, which RFC 2326 section 3.1 adopts, says.
/// Another well-formed version is [`Error::Version`].
fn parse_version(s: &str) -> Result<Version, Error> {
    let rest = s
        .get(5..)
        .filter(|_| s.as_bytes()[..5].eq_ignore_ascii_case(b"RTSP/"))
        .ok_or(Error::StartLine)?;
    match rest {
        "1.0" => Ok(Version::Rtsp10),
        "2.0" => Ok(Version::Rtsp20),
        _ => {
            let digits = |d: &str| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit());
            match rest.split_once('.') {
                Some((major, minor)) if digits(major) && digits(minor) => {
                    match (major.trim_start_matches('0'), minor.trim_start_matches('0')) {
                        ("1", "") => Ok(Version::Rtsp10),
                        ("2", "") => Ok(Version::Rtsp20),
                        _ => Err(Error::Version),
                    }
                }
                _ => Err(Error::StartLine),
            }
        }
    }
}

fn parse_content_length(v: &str) -> Result<usize, Error> {
    if v.is_empty() || !v.bytes().all(|d| d.is_ascii_digit()) {
        return Err(Error::ContentLength);
    }
    let mut n = 0usize;
    for d in v.bytes() {
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(d - b'0')))
            .ok_or(Error::TooLong)?;
        if n > MAX_BODY {
            return Err(Error::TooLong);
        }
    }
    Ok(n)
}

/// Reads decimal digits, with no sign or spaces, failing on overflow.
fn parse_u64(s: &str) -> Option<u64> {
    ascii::decimal(s.as_bytes(), usize::MAX, u64::MAX)
}

fn is_ctl(b: u8) -> bool {
    b < 0x20 || b == 0x7f
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_token_byte)
}

/// A method is a token that does not start with `$`, so it cannot be
/// taken for an interleaved frame.
fn valid_method(s: &str) -> bool {
    is_token(s) && !s.starts_with('$')
}

/// A request URI is printable ASCII with no spaces.
fn valid_uri(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())
}

fn valid_value(s: &str) -> bool {
    !s.bytes().any(|b| is_ctl(b) && b != b'\t')
}

/// A Transport header's ordered, nonempty list of specifications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transports {
    /// At most [`MAX_TRANSPORTS`] transport specifications.
    pub values: Vec<Transport>,
}

impl Transports {
    fn read_value(value: &str) -> Result<Self, Error> {
        Transport::read_list(value).map(|values| Self { values })
    }

    fn format_value(&self) -> Result<String, Error> {
        if self.values.is_empty() {
            return Err(Error::HeaderSyntax("Transport"));
        }
        if self.values.len() > MAX_TRANSPORTS {
            return Err(Error::TooMany);
        }
        let mut out = String::new();
        for value in &self.values {
            let text = value.format_value()?;
            let size = out
                .len()
                .checked_add(text.len())
                .and_then(|n| n.checked_add(usize::from(!out.is_empty())))
                .ok_or(Error::TooLong)?;
            if size > MAX_HEAD {
                return Err(Error::TooLong);
            }
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(&text);
        }
        Ok(out)
    }
}

// Header values share UTF-8, size, round-trip, and transactional checks.
macro_rules! wire_value {
    ($ty:ty, $(#[$parse:meta])* parse, $(#[$write:meta])* write) => {
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = Error;

            $(#[$parse])*
            /// Refuses input over [`MAX_HEAD`], invalid UTF-8, and values
            /// whose canonical form exceeds that limit or changes a field.
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() > MAX_HEAD {
                    return Err(Error::TooLong);
                }
                let text = core::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
                let value = Self::read_value(text)?;
                value.write(&mut Vec::new())?;
                Ok(value)
            }

            $(#[$write])*
            /// Refuses values that would read back differently. Leaves `out`
            /// unchanged on error. Output is bounded by [`MAX_HEAD`].
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                let text = self.format_value()?;
                if text.len() > MAX_HEAD {
                    return Err(Error::TooLong);
                }
                if Self::read_value(&text)? != *self {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(text.as_bytes());
                Ok(())
            }
        }
    };
}

wire_value!(
    Session,
    /// Reads a Session header's value, such as `47112344;timeout=60`.
    /// Parameters other than `timeout`, and a timeout over 19 digits, are
    /// [`Error::HeaderSyntax`].
    parse,
    /// The header value. A bad identifier, or a timeout over 19 digits,
    /// is [`Error::HeaderSyntax`].
    write
);

wire_value!(
    Transport,
    /// Reads one transport specification: `protocol/profile`, an
    /// optional `/lower`, and parameters after semicolons. RFC 7826 also
    /// allows other transport names with one token or more than three:
    /// one token leaves the profile empty, and the parts past the third
    /// go into [`Lower::Other`]. A specification naming both `unicast`
    /// and `multicast` is [`Error::HeaderSyntax`], since both RFCs make them
    /// exclusive.
    parse,
    /// The specification as text. A protocol or profile that is not a
    /// token (the profile may be empty only with no lower transport), a
    /// parameter value that would not read back, an `Other` named like a
    /// known parameter, both `unicast` and `multicast`, or more than
    /// [`MAX_PARAMS`] parameters or list items is an error.
    write
);

wire_value!(
    Range,
    /// Reads a Range header's value with one span, such as `npt=0-`,
    /// `clock=19961108T142300Z-;time=19970123T153600Z`, or a format alone,
    /// such as `npt`. A list of spans, which RFC 2326 allows and RFC 7826
    /// does not, is [`Error::HeaderSyntax`]. So are SMPTE subframes with no
    /// frames, which RFC 2326 allows and RFC 7826 does not. Times must
    /// exist: SMPTE minutes and seconds below 60 and frames below the
    /// rate, a real UTC date and time with at most 9 fraction digits, and
    /// normal play time below 10^19 seconds.
    parse,
    /// The header value. A span with neither end is written as the format
    /// alone. A value out of range or a malformed UTC time is
    /// [`Error::HeaderSyntax`].
    write
);

wire_value!(
    Transports,
    /// Reads a nonempty comma-separated list. Refuses more than
    /// [`MAX_TRANSPORTS`] specifications or malformed values.
    parse,
    /// Writes specifications in order, separated by commas. Refuses an
    /// empty list, invalid values, or more than [`MAX_TRANSPORTS`] entries.
    write
);

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{Error, Frame, Transports};
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::test_support::contract;

    /// Checks parsed values and their public accessors.
    pub fn round_trip(item: &Frame) {
        contract::check_wire_value(item);
        if let Frame::Interleaved(frame) = item {
            frame.to_bytes().unwrap();
            return;
        }
        if let Err(error) = item.to_bytes() {
            assert!(
                matches!(error, Error::TooLong | Error::TooMany),
                "{error:?} for {item:?}"
            );
            return;
        }
        if let Frame::Message(message) = item {
            if let Ok(value) = message.session() {
                contract::check_wire_value(&value);
                value.to_bytes().unwrap();
            }
            if let Ok(value) = message.range() {
                contract::check_wire_value(&value);
                value.to_bytes().unwrap();
            }
            if let Ok(values) = message.transports()
                && !values.is_empty()
            {
                let value = Transports { values };
                contract::check_wire_value(&value);
                value.to_bytes().unwrap();
            }
            if message.method().is_some() {
                let reply = message.reply(100, "Continue");
                contract::check_wire_value(&reply);
                assert!(matches!(
                    reply.to_bytes(),
                    Ok(_) | Err(Error::TooLong | Error::TooMany)
                ));
            }
        }
    }

    /// Checks a value read directly from text.
    pub fn text_value<
        T: Wire<ParseError = Error, WriteError = Error> + PartialEq + core::fmt::Debug,
    >(
        value: Result<T, Error>,
    ) {
        if let Ok(value) = value {
            contract::check_wire_value(&value);
            assert!(
                matches!(value.to_bytes(), Ok(_) | Err(Error::TooLong)),
                "{value:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::harness::{round_trip, text_value};
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    #[test]
    fn unexpected_line_error_is_malformed_head() {
        assert_eq!(
            super::framing_error(super::LineError::Unterminated),
            super::Error::LineEnding
        );
        assert_eq!(
            super::framing_error(super::LineError::BareLf),
            super::Error::LineEnding
        );
    }

    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::codec::{Fail, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn wire_text<T: Wire<WriteError = Error>>(value: &T) -> Result<String, Error> {
        String::from_utf8(value.to_bytes()?).map_err(|_| Error::Utf8)
    }

    fn msg(b: &[u8]) -> Message {
        Message::parse(b).unwrap()
    }

    // RFC 2326 section 10.1.
    const OPTIONS: &[u8] = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nRequire: implicit-play\r\n\
        Proxy-Require: gzipped-messages\r\n\r\n";
    const OPTIONS_OK: &[u8] =
        b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n\r\n";

    // RFC 2326 section 10.2, with an SDP body.
    fn describe_ok() -> Vec<u8> {
        let body =
            b"v=0\r\no=mhandley 2890844526 2890842807 IN IP4 126.16.64.4\r\ns=SDP Seminar\r\n";
        let mut b = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 312\r\nDate: 23 Jan 1997 15:35:06 GMT\r\n\
             Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        b.extend_from_slice(body);
        b
    }

    // RFC 7826 section 13.4, a PLAY in RTSP 2.0.
    const PLAY2: &[u8] = b"PLAY rtsp://example.com/audio RTSP/2.0\r\nCSeq: 836\r\n\
        Session: ULExwZCXh2pd0xuFgkgZJW\r\nRange: npt=3.52-\r\nUser-Agent: PhonyClient/1.2\r\n\r\n";

    #[test]
    fn options_example() {
        let m = msg(OPTIONS);
        assert_eq!(
            m.start,
            StartLine::Request {
                method: "OPTIONS".into(),
                uri: "*".into(),
                version: Version::Rtsp10
            }
        );
        assert_eq!(m.cseq(), Ok(1));
        assert_eq!(m.header("require"), Some("implicit-play"));
        let r = msg(OPTIONS_OK);
        assert_eq!(r.status(), Some(200));
        assert_eq!(r.reason(), Some("OK"));
        assert_eq!(m.reason(), None);
        assert_eq!(r.version(), Version::Rtsp10);
        let mut reply = m.reply(200, "OK");
        reply.push_header("Public", "DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE");
        assert_eq!(reply.to_bytes().unwrap(), OPTIONS_OK);
    }

    #[test]
    fn describe_body() {
        let b = describe_ok();
        let m = msg(&b);
        assert_eq!(m.content_length(), Ok(Some(m.body.len())));
        assert!(m.body.starts_with(b"v=0\r\n"));
        // The writer preserves the header order and body.
        let back = msg(&m.to_bytes().unwrap());
        assert_eq!(back, m);
    }

    #[test]
    fn play_2_0_example() {
        let m = msg(PLAY2);
        assert_eq!(m.version(), Version::Rtsp20);
        assert_eq!(m.method(), Some(method::PLAY));
        assert_eq!(m.uri(), Some("rtsp://example.com/audio"));
        assert_eq!(
            m.session(),
            Ok(Session {
                id: "ULExwZCXh2pd0xuFgkgZJW".into(),
                timeout: None
            })
        );
        let r = m.range().unwrap();
        assert_eq!(
            r.span,
            Span::Npt {
                start: Some(Npt::Time {
                    seconds: 3,
                    nanos: 520_000_000
                }),
                end: None
            }
        );
        assert_eq!(wire_text(&r).unwrap(), "npt=3.52-");
        let reply = m.reply(200, "OK");
        assert_eq!(reply.version(), Version::Rtsp20);
        assert_eq!(reply.header("Session"), Some("ULExwZCXh2pd0xuFgkgZJW"));
        assert!(
            reply
                .to_bytes()
                .unwrap()
                .starts_with(b"RTSP/2.0 200 OK\r\nCSeq: 836\r\n")
        );
    }

    #[test]
    fn sessions() {
        let s = Session::parse("47112344;timeout=60".as_bytes()).unwrap();
        assert_eq!(
            s,
            Session {
                id: "47112344".into(),
                timeout: Some(60)
            }
        );
        assert_eq!(wire_text(&s).unwrap(), "47112344;timeout=60");
        assert_eq!(
            Session::parse(" QKyjN8nt2WqbWw4tIYof52 ; Timeout = 60 ".as_bytes())
                .unwrap()
                .timeout,
            Some(60)
        );
        for bad in [
            "",
            "a b",
            "x;timeout",
            "x;timeout=",
            "x;timeout=1;timeout=2",
            "x;foo=1",
            "a\"b",
        ] {
            assert_eq!(
                Session::parse(bad.as_bytes()),
                Err(Error::HeaderSyntax("Session")),
                "{bad}"
            );
        }
        assert!(Session::parse("a".repeat(MAX_SESSION_ID).as_bytes()).is_ok());
        assert!(Session::parse("a".repeat(MAX_SESSION_ID + 1).as_bytes()).is_err());
        assert!(Session::parse("x;timeout=99999999999999999999".as_bytes()).is_err());
        assert!(
            wire_text(&Session {
                id: "a;b".into(),
                timeout: None
            })
            .is_err()
        );
    }

    #[test]
    fn transports_rfc_2326() {
        use TransportParam as P;
        let t = Transport::parse("RTP/AVP;multicast;ttl=127;mode=\"PLAY\"".as_bytes()).unwrap();
        assert_eq!(t.protocol, "RTP");
        assert_eq!(t.profile, "AVP");
        assert_eq!(t.lower, None);
        assert_eq!(
            t.params,
            [P::Multicast, P::Ttl(127), P::Mode(vec!["PLAY".into()])]
        );
        assert!(t.is_multicast());
        let t = Transport::parse("RTP/AVP/TCP;interleaved=0-1".as_bytes()).unwrap();
        assert_eq!(t.lower, Some(Lower::Tcp));
        assert_eq!(t.interleaved(), Some((0, Some(1))));
        assert_eq!(wire_text(&t).unwrap(), "RTP/AVP/TCP;interleaved=0-1");
        let list = Transports::parse(
            "RTP/AVP;unicast;client_port=3456-3457;mode=\"PLAY\", RTP/AVP/UDP;unicast;destination=192.0.2.1;\
             ssrc=0A13C760;server_port=9000;mode=\"PLAY, RECORD\";append"
                .as_bytes(),
        )
        .unwrap()
        .values;
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].client_port(), Some((3456, Some(3457))));
        assert_eq!(list[1].server_port(), Some((9000, None)));
        assert_eq!(list[1].ssrc(), Some(&[0x0A13C760][..]));
        assert_eq!(
            list[1].modes(),
            Some(&["PLAY".to_string(), "RECORD".to_string()][..])
        );
        assert_eq!(list[0].ssrc(), None);
        assert_eq!(
            Transport::parse("RTP/AVP".as_bytes()).unwrap().modes(),
            None
        );
        assert_eq!(
            list[1].params,
            [
                P::Unicast,
                P::Destination(Some("192.0.2.1".into())),
                P::Ssrc(vec![0x0A13C760]),
                P::ServerPort(9000, None),
                P::Mode(vec!["PLAY".into(), "RECORD".into()]),
                P::Append,
            ]
        );
        let text = wire_text(&Transports {
            values: list.clone(),
        })
        .unwrap();
        assert_eq!(Transports::parse(text.as_bytes()).unwrap().values, list);
    }

    #[test]
    fn transports_rfc_7826() {
        use TransportParam as P;
        let list = Transports::parse(
            "RTP/AVP/UDP;unicast;dest_addr=\":4588\"/\":4589\", RTP/AVP/TCP;unicast;interleaved=0-1"
                .as_bytes(),
        )
        .unwrap()
        .values;
        assert_eq!(
            list[0].params,
            [
                P::Unicast,
                P::DestAddr(vec![":4588".into(), ":4589".into()])
            ]
        );
        let t = Transport::parse(
            "RTP/SAVPF/TCP;unicast;src_addr=\"192.0.2.5:6256\"/\"192.0.2.5:6257\";setup=passive;\
             connection=new;RTCP-mux;ssrc=93CB001E/0000002a;MIKEY=AQAFgM0XflABAAAAAAAAAAAAAAsAyO"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(t.profile, "SAVPF");
        assert_eq!(
            t.params,
            [
                P::Unicast,
                P::SrcAddr(vec!["192.0.2.5:6256".into(), "192.0.2.5:6257".into()]),
                P::Setup("passive".into()),
                P::Connection("new".into()),
                P::RtcpMux,
                P::Ssrc(vec![0x93CB001E, 0x2a]),
                P::Other {
                    name: "MIKEY".into(),
                    value: Some("AQAFgM0XflABAAAAAAAAAAAAAAsAyO".into())
                },
            ]
        );
        assert_eq!(
            Transport::parse(wire_text(&t).unwrap().as_bytes()).unwrap(),
            t
        );
        // A trailing semicolon and spaces are allowed.
        assert_eq!(
            Transport::parse(" RTP/AVP ; unicast ; ".as_bytes())
                .unwrap()
                .params,
            [P::Unicast]
        );
        // Quoted values of unknown parameters keep their quotes.
        let t = Transport::parse("RTP/AVP;x=\"a;b,c\"".as_bytes()).unwrap();
        assert_eq!(
            t.params,
            [P::Other {
                name: "x".into(),
                value: Some("\"a;b,c\"".into())
            }]
        );
    }

    #[test]
    fn bad_transports() {
        let bad = Error::HeaderSyntax("Transport");
        for t in [
            "",
            "RTP/",
            "RTP/AVP/TCP/",
            "RTP//AVP",
            "RTP AVP",
            "RTP/AVP;unicast=1",
            "RTP/AVP;interleaved=256",
            "RTP/AVP;interleaved=0-",
            "RTP/AVP;interleaved",
            "RTP/AVP;client_port=65536",
            "RTP/AVP;client_port=+1",
            "RTP/AVP;ttl=300",
            "RTP/AVP;layers=x",
            "RTP/AVP;ssrc=123456789",
            "RTP/AVP;ssrc=",
            "RTP/AVP;ssrc=zz",
            "RTP/AVP;mode=\"\"",
            "RTP/AVP;mode=\"PLAY",
            "RTP/AVP;dest_addr=x",
            "RTP/AVP;dest_addr=\"x\"/",
            "RTP/AVP;dest_addr=\"\"",
            "RTP/AVP;setup=\"x\"",
            "RTP/AVP;source",
            "RTP/AVP;x=a b",
            "RTP/AVP;a b",
        ] {
            assert_eq!(Transport::parse(t.as_bytes()), Err(bad), "{t}");
        }
        assert_eq!(Transports::parse("RTP/AVP,".as_bytes()), Err(bad));
        assert_eq!(Transports::parse("RTP/AVP,,RTP/AVP".as_bytes()), Err(bad));
        let many = vec!["RTP/AVP"; MAX_TRANSPORTS + 1].join(",");
        assert_eq!(Transports::parse(many.as_bytes()), Err(Error::TooMany));
        let params = format!("RTP/AVP{}", ";unicast".repeat(MAX_PARAMS + 1));
        assert_eq!(Transport::parse(params.as_bytes()), Err(Error::TooMany));
        assert!(
            Transport::parse(format!("RTP/AVP{}", ";unicast".repeat(MAX_PARAMS)).as_bytes())
                .is_ok()
        );
        // A message with too many across its headers.
        let mut m = Message::request(Version::Rtsp10, "SETUP", "rtsp://h/a");
        for _ in 0..=MAX_TRANSPORTS {
            m.push_header("Transport", "RTP/AVP");
        }
        assert_eq!(m.transports(), Err(Error::TooMany));
    }

    #[test]
    fn transport_writer_checks() {
        use TransportParam as P;
        let mut t = Transport {
            protocol: "RTP".into(),
            profile: "AVP".into(),
            lower: None,
            params: vec![],
        };
        assert_eq!(wire_text(&t).unwrap(), "RTP/AVP");
        for p in [
            P::Other {
                name: "unicast".into(),
                value: None,
            },
            P::Other {
                name: "x".into(),
                value: Some("a;b".into()),
            },
            P::Mode(vec![]),
            P::Mode(vec!["a b".into()]),
            P::Ssrc(vec![]),
            P::DestAddr(vec!["a\"b".into()]),
            P::Source(String::new()),
            P::Setup("a,b".into()),
        ] {
            t.params = vec![p.clone()];
            assert!(wire_text(&t).is_err(), "{p:?}");
        }
        t.params = vec![P::Ssrc(vec![1; MAX_PARAMS + 1])];
        assert_eq!(wire_text(&t), Err(Error::TooMany));
        t.params = vec![P::Unicast; MAX_PARAMS + 1];
        assert_eq!(wire_text(&t), Err(Error::TooMany));
        t.params = vec![];
        t.profile = "A/B".into();
        assert!(wire_text(&t).is_err());
        assert!(wire_text(&Transports { values: vec![] }).is_err());
    }

    #[test]
    fn ranges() {
        let r = Range::parse("npt=10-15".as_bytes()).unwrap();
        assert_eq!(
            r.span,
            Span::Npt {
                start: Some(Npt::Time {
                    seconds: 10,
                    nanos: 0
                }),
                end: Some(Npt::Time {
                    seconds: 15,
                    nanos: 0
                })
            }
        );
        let r = Range::parse("npt=12:05:35.3-".as_bytes()).unwrap();
        assert_eq!(
            r.span,
            Span::Npt {
                start: Some(Npt::Time {
                    seconds: 43535,
                    nanos: 300_000_000
                }),
                end: None
            }
        );
        assert_eq!(wire_text(&r).unwrap(), "npt=43535.3-");
        let r = Range::parse("npt=now-".as_bytes()).unwrap();
        assert_eq!(
            r.span,
            Span::Npt {
                start: Some(Npt::Now),
                end: None
            }
        );
        assert_eq!(
            wire_text(&Range::parse("npt=-20".as_bytes()).unwrap()).unwrap(),
            "npt=-20"
        );
        assert_eq!(
            wire_text(&Range::parse("npt=1.-2.0000000019".as_bytes()).unwrap()).unwrap(),
            "npt=1-2.000000001"
        );
        let r = Range::parse("smpte=10:07:00-10:07:33:05.01".as_bytes()).unwrap();
        assert_eq!(
            r.span,
            Span::Smpte {
                rate: SmpteRate::Smpte30,
                start: Some(Smpte {
                    hours: 10,
                    minutes: 7,
                    seconds: 0,
                    frames: None,
                    subframes: None
                }),
                end: Some(Smpte {
                    hours: 10,
                    minutes: 7,
                    seconds: 33,
                    frames: Some(5),
                    subframes: Some(1)
                }),
            }
        );
        assert_eq!(wire_text(&r).unwrap(), "smpte=10:07:00-10:07:33:05.01");
        let r = Range::parse("smpte-25=10:07:00:10-".as_bytes()).unwrap();
        assert!(matches!(
            r.span,
            Span::Smpte {
                rate: SmpteRate::Smpte25,
                ..
            }
        ));
        let r = Range::parse("clock=19961108T142300Z-19961108T143520Z".as_bytes()).unwrap();
        assert_eq!(
            wire_text(&r).unwrap(),
            "clock=19961108T142300Z-19961108T143520Z"
        );
        let r = Range::parse("clock=19961110T1925-19961110T2015;time=19970123T153600Z".as_bytes());
        assert!(r.is_err());
        let r =
            Range::parse("clock=19961110T192500Z-;time=19970123T153600.25Z".as_bytes()).unwrap();
        assert_eq!(r.time.as_deref(), Some("19970123T153600.25Z"));
        assert_eq!(Range::parse(wire_text(&r).unwrap().as_bytes()).unwrap(), r);
        for bad in [
            "",
            "npt=",
            "npt=-",
            "npt=1",
            "npt=1-2-3",
            "npt=a-",
            "npt=1:60:00-",
            "npt=1:00-",
            "npt=1.x-",
            "npt=99999999999999999999-",
            "frames=1-2",
            "smpte=1:2-",
            "smpte=100:00:00-",
            "smpte=1:2:3.4-",
            "smpte=1:2:3:4:5-",
            "clock=1996-",
            "clock=19961108T142300-",
            "npt=0-;time=x",
            "npt=0-;foo=19970123T153600Z",
            "npt=0-;time",
            "npt=0-;time=19970123T153600Z;time=19970123T153600Z",
            "npt=0-,npt=5-",
        ] {
            assert_eq!(
                Range::parse(bad.as_bytes()),
                Err(Error::HeaderSyntax("Range")),
                "{bad}"
            );
        }
        let bad = Range {
            span: Span::Npt {
                start: Some(Npt::Time {
                    seconds: 0,
                    nanos: 2_000_000_000,
                }),
                end: None,
            },
            time: None,
        };
        assert!(wire_text(&bad).is_err());
        let s = Smpte {
            hours: 1,
            minutes: 2,
            seconds: 3,
            frames: None,
            subframes: Some(1),
        };
        let bad = Range {
            span: Span::Smpte {
                rate: SmpteRate::Smpte30Drop,
                start: Some(s),
                end: None,
            },
            time: None,
        };
        assert!(wire_text(&bad).is_err());
        let bad = Range {
            span: Span::Clock {
                start: Some("x".into()),
                end: None,
            },
            time: None,
        };
        assert!(wire_text(&bad).is_err());
    }

    #[test]
    fn spec_review() {
        use TransportParam as P;
        let bad = Error::HeaderSyntax("Transport");
        // RFC 2326 section 3.4 and RFC 7826 section 20.2.3: safe is `$ - _ . +`.
        assert_eq!(
            Session::parse("a~b".as_bytes()),
            Err(Error::HeaderSyntax("Session"))
        );
        assert!(
            wire_text(&Session {
                id: "a~b".into(),
                timeout: None
            })
            .is_err()
        );
        // Both RFCs: an SSRC is exactly 8 hex digits.
        for t in [
            "RTP/AVP;ssrc=1",
            "RTP/AVP;ssrc=0A13C76",
            "RTP/AVP;ssrc=0A13C760/2a",
        ] {
            assert_eq!(Transport::parse(t.as_bytes()), Err(bad), "{t}");
        }
        // Both RFCs: ttl and channel are 1 to 3 digits, a port 1 to 5.
        for t in [
            "RTP/AVP;ttl=0127",
            "RTP/AVP;interleaved=0000",
            "RTP/AVP;client_port=000001-2",
        ] {
            assert_eq!(Transport::parse(t.as_bytes()), Err(bad), "{t}");
        }
        assert_eq!(
            Transport::parse("RTP/AVP;ttl=001;port=00001".as_bytes())
                .unwrap()
                .params,
            [P::Ttl(1), P::Port(1, None)]
        );
        // Both RFCs quote mode-spec, even with one mode.
        let mut t = Transport {
            protocol: "RTP".into(),
            profile: "AVP".into(),
            lower: None,
            params: vec![],
        };
        t.params = vec![P::Mode(vec!["PLAY".into()])];
        assert_eq!(wire_text(&t).unwrap(), "RTP/AVP;mode=\"PLAY\"");
        // RFC 7826 section 20.2.3: lower-transport may be any token.
        let t = Transport::parse("RTP/AVP/SCTP;unicast".as_bytes()).unwrap();
        assert_eq!(t.lower, Some(Lower::Other("SCTP".into())));
        assert_eq!(wire_text(&t).unwrap(), "RTP/AVP/SCTP;unicast");
        for l in ["tcp", "UDP", "a/", "/a", "a//b", ""] {
            let t = Transport {
                protocol: "RTP".into(),
                profile: "AVP".into(),
                lower: Some(Lower::Other(l.into())),
                params: vec![],
            };
            assert_eq!(wire_text(&t), Err(bad), "{l}");
        }
        // RFC 7826: trn-par-value may be empty.
        let t = Transport::parse("RTP/AVP;x=".as_bytes()).unwrap();
        assert_eq!(
            t.params,
            [P::Other {
                name: "x".into(),
                value: Some(String::new())
            }]
        );
        assert_eq!(wire_text(&t).unwrap(), "RTP/AVP;x=");
        // RFC 7826 section 4.4: a Range may name only its format.
        let only = [
            (
                "npt",
                Span::Npt {
                    start: None,
                    end: None,
                },
            ),
            (
                "smpte-25",
                Span::Smpte {
                    rate: SmpteRate::Smpte25,
                    start: None,
                    end: None,
                },
            ),
            (
                "clock",
                Span::Clock {
                    start: None,
                    end: None,
                },
            ),
        ];
        for (v, span) in only {
            let r = Range::parse(v.as_bytes()).unwrap();
            assert_eq!(r.span, span);
            assert_eq!(wire_text(&r).unwrap(), v);
        }
        for v in ["npt=", "npt=-", " = 1-"] {
            assert_eq!(
                Range::parse(v.as_bytes()),
                Err(Error::HeaderSyntax("Range")),
                "{v}"
            );
        }
    }

    #[test]
    fn bodyless_responses_in_rtsp_1_0() {
        // RFC 2326 section 4.4: a 1xx, 204 or 304 response ends at the
        // blank line, whatever its Content-Length says.
        let stream = b"RTSP/1.0 304 Not Modified\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\n\
            RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";
        let items = items_of(stream);
        assert_eq!(items.len(), 2, "{items:?}");
        let Ok(Frame::Message(first)) = &items[0] else {
            panic!()
        };
        assert!(first.body.is_empty());
        let Ok(Frame::Message(second)) = &items[1] else {
            panic!()
        };
        assert_eq!(second.cseq(), Ok(2));
        // RFC 7826 section 5.4: in RTSP 2.0 the Content-Length always counts.
        let m = msg(b"RTSP/2.0 304 Not Modified\r\nCSeq: 1\r\nContent-Length: 2\r\n\r\nab");
        assert_eq!(m.body, b"ab");
        // The writer refuses a body there in RTSP 1.0.
        for code in [100, 199, 204, 304] {
            let mut m = Message::response(Version::Rtsp10, code, "x");
            m.body = b"ab".to_vec();
            m.push_header("Content-Length", "2");
            assert_eq!(m.to_bytes(), Err(Error::Unwritable), "{code}");
            m.start = StartLine::Status {
                version: Version::Rtsp20,
                code,
                reason: "x".into(),
            };
            assert!(m.to_bytes().is_ok());
        }
    }

    #[test]
    fn transport_review_fixes() {
        use TransportParam as P;
        let bad = Error::HeaderSyntax("Transport");
        // RFC 2326 section 12.39, RFC 7826 section 18.54: mutually exclusive.
        assert_eq!(
            Transport::parse("RTP/AVP;unicast;multicast".as_bytes()),
            Err(bad)
        );
        let both = Transport {
            protocol: "RTP".into(),
            profile: "AVP".into(),
            lower: None,
            params: vec![P::Multicast, P::Unicast],
        };
        assert_eq!(wire_text(&both), Err(bad));
        // RFC 7826 section 20.1: SLASH allows whitespace around it.
        let t = Transport::parse(
            "RTP/AVP;ssrc=00000001 / 00000002;dest_addr=\":5004\" / \":5005\"".as_bytes(),
        )
        .unwrap();
        assert_eq!(
            t.params,
            [
                P::Ssrc(vec![1, 2]),
                P::DestAddr(vec![":5004".into(), ":5005".into()])
            ]
        );
        // RFC 7826 section 20.2.3: other-trans is one token or more.
        let list = Transports::parse("X;unicast,RTP/AVP/TCP;unicast;interleaved=0-1".as_bytes())
            .unwrap()
            .values;
        assert_eq!(list.len(), 2);
        assert_eq!(
            (
                list[0].protocol.as_str(),
                list[0].profile.as_str(),
                &list[0].lower
            ),
            ("X", "", &None)
        );
        assert_eq!(wire_text(&list[0]).unwrap(), "X;unicast");
        let t = Transport::parse("A/B/C/D;unicast".as_bytes()).unwrap();
        assert_eq!(t.lower, Some(Lower::Other("C/D".into())));
        assert_eq!(wire_text(&t).unwrap(), "A/B/C/D;unicast");
        let t = Transport::parse("RTP/AVP/TCP/X".as_bytes()).unwrap();
        assert_eq!(t.lower, Some(Lower::Other("TCP/X".into())));
        assert_eq!(
            Transport::parse(wire_text(&t).unwrap().as_bytes()).unwrap(),
            t
        );
        let no_profile = Transport {
            protocol: "X".into(),
            profile: String::new(),
            lower: Some(Lower::Tcp),
            params: vec![],
        };
        assert_eq!(wire_text(&no_profile), Err(bad));
        // RFC 7826 section 20.2.3: setup and connection take fixed values.
        for v in ["RTP/AVP;setup=banana", "RTP/AVP;connection=banana"] {
            assert_eq!(Transport::parse(v.as_bytes()), Err(bad), "{v}");
        }
        let t = Transport::parse("RTP/AVP;setup=actpass;connection=existing".as_bytes()).unwrap();
        assert_eq!(
            t.params,
            [P::Setup("actpass".into()), P::Connection("existing".into())]
        );
        for p in [P::Setup("banana".into()), P::Connection("old".into())] {
            let t = Transport {
                protocol: "RTP".into(),
                profile: "AVP".into(),
                lower: None,
                params: vec![p],
            };
            assert_eq!(wire_text(&t), Err(bad));
        }
        // trn-par-value is a run of unreserved bytes and quoted strings.
        let t = Transport::parse("RTP/AVP;unicast;x=a\"b\"c".as_bytes()).unwrap();
        assert_eq!(
            t.params[1],
            P::Other {
                name: "x".into(),
                value: Some("a\"b\"c".into())
            }
        );
        assert_eq!(
            Transport::parse(wire_text(&t).unwrap().as_bytes()).unwrap(),
            t
        );
        assert_eq!(Transport::parse("RTP/AVP;x=a\"b".as_bytes()), Err(bad));
    }

    #[test]
    fn value_review_fixes() {
        let bad = Error::HeaderSyntax("Range");
        let mut m = Message::request(Version::Rtsp20, "PLAY", "rtsp://h/a");
        // RFC 7826 section 4.4.1: frames below the rate, minutes and
        // seconds below 60.
        for v in [
            "smpte-25=00:00:00:25-",
            "smpte=00:00:00:30-",
            "smpte=00:60:00-",
            "smpte=00:00:60-",
        ] {
            m.set_header("Range", v);
            assert_eq!(m.range(), Err(bad), "{v}");
            assert_eq!(Range::parse(v.as_bytes()), Err(bad), "{v}");
        }
        m.set_header("Range", "smpte-25=00:59:59:24-");
        assert_eq!(
            m.range(),
            Ok(Range {
                span: Span::Smpte {
                    rate: SmpteRate::Smpte25,
                    start: Some(Smpte {
                        hours: 0,
                        minutes: 59,
                        seconds: 59,
                        frames: Some(24),
                        subframes: None
                    }),
                    end: None,
                },
                time: None,
            })
        );
        assert!(Range::parse("smpte-25=00:00:00:24-".as_bytes()).is_ok());
        let s = Smpte {
            hours: 0,
            minutes: 0,
            seconds: 0,
            frames: Some(25),
            subframes: None,
        };
        let r = Range {
            span: Span::Smpte {
                rate: SmpteRate::Smpte25,
                start: Some(s),
                end: None,
            },
            time: None,
        };
        assert_eq!(wire_text(&r), Err(bad));
        // RFC 7826 section 4.4.3: a real UTC date and time, and at most 9
        // fraction digits.
        for v in [
            "clock=20230230T000000Z-",
            "clock=20230101T250000Z-",
            "clock=20231301T000000Z-",
            "clock=20230229T000000Z-",
        ] {
            m.set_header("Range", v);
            assert_eq!(m.range(), Err(bad), "{v}");
            assert_eq!(Range::parse(v.as_bytes()), Err(bad), "{v}");
        }
        assert!(Range::parse("clock=20240229T235960.123456789Z-".as_bytes()).is_ok());
        assert_eq!(
            Range::parse("clock=20240229T000000.1234567890Z-".as_bytes()),
            Err(bad)
        );
        // RFC 7826 section 20.2.3: 1*19DIGIT seconds.
        m.set_header("Range", "npt=10000000000000000000-");
        assert_eq!(m.range(), Err(bad));
        m.set_header("Range", "npt=9999999999999999999-");
        assert_eq!(
            m.range(),
            Ok(Range {
                span: Span::Npt {
                    start: Some(Npt::Time {
                        seconds: 9_999_999_999_999_999_999,
                        nanos: 0
                    }),
                    end: None
                },
                time: None,
            })
        );
        assert_eq!(
            Range::parse("npt=10000000000000000000-".as_bytes()),
            Err(bad)
        );
        assert!(Range::parse("npt=9999999999999999999-".as_bytes()).is_ok());
        let r = Range {
            span: Span::Npt {
                start: Some(Npt::Time {
                    seconds: u64::MAX,
                    nanos: 0,
                }),
                end: None,
            },
            time: None,
        };
        assert_eq!(wire_text(&r), Err(bad));
        let s = Session {
            id: "a".into(),
            timeout: Some(u64::MAX),
        };
        assert!(wire_text(&s).is_err());
        m.set_header("Session", "a;timeout=10000000000000000000");
        assert_eq!(m.session(), Err(Error::HeaderSyntax("Session")));
        m.set_header("Session", "a;timeout=9999999999999999999");
        assert_eq!(
            m.session(),
            Ok(Session {
                id: "a".into(),
                timeout: Some(9_999_999_999_999_999_999)
            })
        );
        assert!(Session::parse("a;timeout=10000000000000000000".as_bytes()).is_err());
        assert!(Session::parse("a;timeout=9999999999999999999".as_bytes()).is_ok());
        // RFC 7826 has no time parameter on Range.
        m.set_header("Range", "npt=0-;time=19970123T153600Z");
        assert_eq!(m.range(), Err(bad));
        m.start = StartLine::Request {
            method: "PLAY".into(),
            uri: "rtsp://h/a".into(),
            version: Version::Rtsp10,
        };
        assert!(m.range().is_ok());
    }

    #[test]
    fn message_review_fixes() {
        // RFC 2326 section 12.17: any number of digits in RTSP 1.0.
        let mut m = Message::request(Version::Rtsp10, "OPTIONS", "*");
        m.push_header("CSeq", "1000000000");
        assert_eq!(m.cseq(), Ok(1_000_000_000));
        m.set_header("CSeq", "4294967296");
        assert_eq!(m.cseq(), Err(Error::HeaderSyntax("CSeq")));
        let mut m = Message::request(Version::Rtsp20, "OPTIONS", "*");
        m.push_header("CSeq", "1000000000");
        assert_eq!(m.cseq(), Err(Error::HeaderSyntax("CSeq")));
        // RFC 2326 section 12.38: the response echoes the Timestamp.
        let m = msg(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nTimestamp: 123.5\r\n\r\n");
        assert_eq!(m.reply(200, "OK").header("Timestamp"), Some("123.5"));
        // RFC 2326 section 4: bare LF ends lines in RTSP 1.0.
        let m = msg(b"OPTIONS * RTSP/1.0\nCSeq: 1\n\n");
        assert_eq!(m.cseq(), Ok(1));
        let m = msg(b"\nOPTIONS * RTSP/1.0\r\nCSeq: 1\n\r\n");
        assert_eq!(m.cseq(), Ok(1));
        assert_eq!(
            Message::parse(b"OPTIONS * RTSP/2.0\nCSeq: 1\n\n"),
            Err(Error::LineEnding)
        );
        assert_eq!(
            Message::parse(b"OPTIONS * RTSP/2.0\r\nCSeq: 1\r\n\n"),
            Err(Error::LineEnding)
        );
        // RFC 2068 section 3.1, which RFC 2326 section 3.1 adopts: leading
        // zeros in the version are ignored.
        let m = msg(b"OPTIONS * RTSP/01.00\r\nCSeq: 1\r\n\r\n");
        assert_eq!(m.version(), Version::Rtsp10);
        assert_eq!(msg(b"RTSP/002.0 200 OK\r\n\r\n").version(), Version::Rtsp20);
        let p = |b: &[u8]| Message::parse(b).map(|_| ());
        assert_eq!(
            p(b"OPTIONS * RTSP/99999999999999999999991.0\r\n\r\n"),
            Err(Error::Version)
        );
        assert_eq!(p(b"OPTIONS * RTSP/1.01\r\n\r\n"), Err(Error::Version));
    }

    #[test]
    fn interleaved_frames() {
        let frame = Interleaved {
            channel: 0,
            data: vec![0x80, 0x60, 0, 1],
        };
        let bytes = frame.to_bytes().unwrap();
        // RFC 2326 section 10.12.
        assert_eq!(bytes, [b'$', 0, 0, 4, 0x80, 0x60, 0, 1]);
        assert_eq!(Interleaved::parse(&bytes), Ok(frame));
        for n in 0..bytes.len() {
            assert_eq!(Interleaved::parse(&bytes[..n]), Err(Error::Incomplete));
        }
        assert_eq!(Interleaved::parse(b"R"), Err(Error::Marker));
        let big = Interleaved {
            channel: 1,
            data: vec![7; MAX_INTERLEAVED],
        };
        assert_eq!(
            big.to_bytes().unwrap().len(),
            MAX_INTERLEAVED + INTERLEAVED_HEADER_LEN
        );
        let too_big = Interleaved {
            channel: 1,
            data: vec![7; MAX_INTERLEAVED + 1],
        };
        assert_eq!(too_big.to_bytes(), Err(Error::TooLong));
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(b"\r\n$\x01\x00\x00x"), 7);
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(Frame::Interleaved(Interleaved {
                channel: 1,
                data: vec![]
            }))))
        );
        assert_eq!(stream.unread(), b"x");
        assert_eq!(Frame::parse(b"\r\n$\x01\x00\x00x"), Err(Error::Trailing));
    }

    #[test]
    fn every_error_path() {
        let p = |b: &[u8]| Message::parse(b);
        assert_eq!(
            p(b"OPTIONS * RTSP/1.0\r\nX: \x01\r\n\r\n"),
            Err(Error::HeaderValue)
        );
        assert_eq!(
            p(b"OPTIONS * RTSP/1.0\r\nX\r\n\r\n"),
            Err(Error::HeaderLine)
        );
        assert_eq!(
            p(b"OPTIONS * RTSP/1.0\r\n Y: z\r\n\r\n"),
            Err(Error::HeaderLine)
        );
        assert_eq!(
            p(b"OPTIONS * RTSP/1.0\r\nA B: z\r\n\r\n"),
            Err(Error::HeaderLine)
        );
        assert_eq!(
            p(b"OPTIONS * RTSP/2.0\nX: y\r\n\r\n"),
            Err(Error::LineEnding)
        );
        assert_eq!(
            p(b"OPTIONS * RTSP/1.0\r\nX: y\rz\r\n\r\n"),
            Err(Error::LineEnding)
        );
        assert_eq!(p(b"OPTIONS \xff RTSP/1.0\r\n\r\n"), Err(Error::Utf8));
        assert_eq!(p(b"OPTIONS * RTSP/1.1\r\n\r\n"), Err(Error::Version));
        assert_eq!(p(b"RTSP/3.0 200 OK\r\n\r\n"), Err(Error::Version));
        assert_eq!(p(b"OPTIONS * HTTP/1.1\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"OPTIONS *\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"OPTIONS  RTSP/1.0\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"OPT;ONS * RTSP/1.0\r\n\r\n"), Err(Error::StartLine));
        // A leading $ selects interleaved framing before start-line validation.
        assert_eq!(p(b"$X * RTSP/1.0\r\n\r\n"), Err(Error::Incomplete));
        assert_eq!(p(b"RTSP/1.0 99 Low\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"RTSP/1.0 600 High\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"RTSP/1.0 2x0 OK\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"RTSP/1.0\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"RTSP/1.x 200 OK\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(p(b"RTSP/1.0 200 O\x7fK\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(
            p(b"RTSP/1.0 200 OK\r\nContent-Length: x\r\n\r\n"),
            Err(Error::ContentLength)
        );
        assert_eq!(
            p(b"RTSP/1.0 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"),
            Err(Error::ContentLength)
        );
        assert_eq!(
            p(b"RTSP/1.0 200 OK\r\nContent-Length: 1048577\r\n\r\n"),
            Err(Error::TooLong)
        );
        assert_eq!(p(&vec![b'A'; MAX_HEAD]), Err(Error::TooLong));
        assert_eq!(p(&vec![b'A'; MAX_HEAD - 1]), Err(Error::Incomplete));
        let mut many = b"OPTIONS * RTSP/1.0\r\n".to_vec();
        for _ in 0..=MAX_HEADERS {
            many.extend_from_slice(b"X: y\r\n");
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(p(&many), Err(Error::TooMany));
        // A status line with no reason phrase.
        assert_eq!(
            p(b"RTSP/1.0 200\r\n\r\n").unwrap().start,
            StartLine::Status {
                version: Version::Rtsp10,
                code: 200,
                reason: String::new()
            }
        );

        // Header reads.
        let m =
            msg(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nCSeq: 2\r\nSession: a b\r\nRange: x\r\n\r\n");
        assert_eq!(m.cseq(), Err(Error::HeaderSyntax("CSeq")));
        assert_eq!(m.session(), Err(Error::HeaderSyntax("Session")));
        assert_eq!(m.range(), Err(Error::HeaderSyntax("Range")));
        let m = msg(b"OPTIONS * RTSP/1.0\r\n\r\n");
        assert_eq!(m.cseq(), Err(Error::Missing("CSeq")));
        assert_eq!(m.session(), Err(Error::Missing("Session")));
        assert_eq!(m.range(), Err(Error::Missing("Range")));
        assert_eq!(m.transports(), Ok(vec![]));
        for bad in ["", "x", "-1", "+1", "1234567890", "1 2"] {
            let mut m = Message::request(Version::Rtsp20, "OPTIONS", "*");
            m.push_header("CSeq", bad);
            assert_eq!(m.cseq(), Err(Error::HeaderSyntax("CSeq")), "{bad}");
        }
        let mut m = Message::request(Version::Rtsp10, "OPTIONS", "*");
        m.push_header("CSeq", "999999999");
        assert_eq!(m.cseq(), Ok(999_999_999));

        // Writers.
        let w = |m: &Message| m.to_bytes();
        assert_eq!(
            w(&Message::request(Version::Rtsp10, "A B", "*")),
            Err(Error::StartLine)
        );
        assert_eq!(
            w(&Message::request(Version::Rtsp10, "$A", "*")),
            Err(Error::StartLine)
        );
        assert_eq!(
            w(&Message::request(Version::Rtsp10, "A", "a b")),
            Err(Error::StartLine)
        );
        assert_eq!(
            w(&Message::request(Version::Rtsp10, "A", "")),
            Err(Error::StartLine)
        );
        assert_eq!(
            w(&Message::response(Version::Rtsp10, 99, "x")),
            Err(Error::StartLine)
        );
        assert_eq!(
            w(&Message::response(Version::Rtsp10, 200, "a\r\n")),
            Err(Error::StartLine)
        );
        let mut m = Message::response(Version::Rtsp20, 200, "OK");
        m.push_header("A:", "x");
        assert_eq!(w(&m), Err(Error::HeaderLine));
        m.headers[0].name = "A".into();
        m.headers[0].value = "x\ny".into();
        assert_eq!(w(&m), Err(Error::HeaderValue));
        m.headers[0].value = "x".repeat(MAX_HEAD);
        assert_eq!(w(&m), Err(Error::TooLong));
        m.headers.clear();
        m.body = vec![0; MAX_BODY + 1];
        assert_eq!(w(&m), Err(Error::TooLong));
        m.body = vec![0; 3];
        m.push_header("Content-Length", "3");
        for _ in 0..MAX_HEADERS {
            m.push_header("X", "y");
        }
        assert_eq!(w(&m), Err(Error::TooMany));
        m.headers.pop();
        assert_eq!(
            Message::parse(&w(&m).unwrap()).unwrap().headers.len(),
            MAX_HEADERS
        );
    }

    #[test]
    fn every_truncated_prefix_waits() {
        let mut items = vec![
            OPTIONS.to_vec(),
            OPTIONS_OK.to_vec(),
            describe_ok(),
            PLAY2.to_vec(),
        ];
        items.push(
            Interleaved {
                channel: 3,
                data: vec![1, 2, 3, 4, 5],
            }
            .to_bytes()
            .unwrap(),
        );
        for bytes in &items {
            contract::check_decode_with_alloc_limit(Frames::new, bytes, 2 * MAX_MESSAGE);
            for n in 0..bytes.len() {
                assert_eq!(Frame::parse(&bytes[..n]), Err(Error::Incomplete));
            }
            assert!(Frame::parse(bytes).is_ok());
        }
    }

    #[test]
    fn headers_edit() {
        let mut m = msg(OPTIONS);
        m.set_header("cseq", "5");
        assert_eq!(m.cseq(), Ok(5));
        m.push_header("X", "1");
        m.push_header("x", "2");
        m.set_header("X", "3");
        assert_eq!(m.headers_named("x").count(), 1);
        assert_eq!(m.header("X"), Some("3"));
        assert_eq!(m.remove_header("x"), 1);
        assert_eq!(m.remove_header("x"), 0);
        // Folded lines join with a space.
        let m = msg(b"OPTIONS * RTSP/1.0\r\nX: a\r\n  b\r\n\t\r\n\r\n");
        assert_eq!(m.header("X"), Some("a b"));
    }

    #[test]
    fn header_values_append_only_after_a_valid_write() {
        let mut message = msg(OPTIONS);
        let transport = Transport::parse(b"RTP/AVP/TCP;interleaved=0-1").unwrap();
        message.push_value("Transport", &transport).unwrap();
        assert_eq!(message.transports(), Ok(vec![transport]));
        let before = message.clone();
        let invalid = Session {
            id: "a;b".into(),
            timeout: None,
        };
        assert_eq!(
            message.push_value("Session", &invalid),
            Err(Error::HeaderSyntax("Session"))
        );
        assert_eq!(message, before);
        let binary = Interleaved {
            channel: 0xff,
            data: vec![],
        };
        assert_eq!(message.push_value("X", &binary), Err(Error::Utf8));
        assert_eq!(message, before);
    }

    #[test]
    fn stream_splits_messages_and_frames() {
        let frame = Interleaved {
            channel: 0,
            data: b"rtp!".to_vec(),
        };
        let mut bytes = OPTIONS.to_vec();
        frame.write(&mut bytes).unwrap();
        bytes.extend(b"\r\n");
        bytes.extend(describe_ok());
        frame.write(&mut bytes).unwrap();
        bytes.extend(PLAY2);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_MESSAGE);
        let want = vec![
            Ok(Frame::Message(msg(OPTIONS))),
            Ok(Frame::Interleaved(frame.clone())),
            Ok(Frame::Message(msg(&describe_ok()))),
            Ok(Frame::Interleaved(frame)),
            Ok(Frame::Message(msg(PLAY2))),
        ];
        assert_eq!(decode_all(Frames::new, &bytes), (want, None));
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(b"RTSP/9.9 200 OK\r\n\r\n"), 19);
        assert_eq!(stream.next(), Some(Ok(Err(Error::Version))));
        assert_eq!(stream.push(OPTIONS), OPTIONS.len());
        assert_eq!(stream.next(), Some(Ok(Ok(Frame::Message(msg(OPTIONS))))));
        assert_eq!(stream.push(&vec![b'A'; MAX_HEAD - 1]), MAX_HEAD - 1);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"A"), 1);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TooLong))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&Fail::Protocol(Error::TooLong)));
    }

    #[test]
    fn stream_takes_many_small_items_in_linear_time() {
        assert_linear(
            "stream_takes_many_small_items_in_linear_time",
            rounds(12_500),
            |size| {
                let mut one = OPTIONS.to_vec();
                Interleaved {
                    channel: 0,
                    data: vec![9; 10],
                }
                .write(&mut one)
                .unwrap();
                let bytes = one.repeat(size);
                let (items, failure) = decode_all(Frames::new, &bytes);
                assert_eq!(failure, None);
                assert_eq!(items.len(), size * 2);
                assert!(items.iter().all(Result::is_ok));
            },
        );
        assert_linear("large_rtsp_body", MAX_BODY / 4, |size| {
            let mut message = Message::response(Version::Rtsp10, 200, "OK");
            message.body = vec![b'x'; size];
            message.push_header("Content-Length", &size.to_string());
            let bytes = message.to_bytes().unwrap();
            contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_MESSAGE);
            assert_eq!(
                decode_all(Frames::new, &bytes),
                (vec![Ok(Frame::Message(message))], None)
            );
        });
    }

    fn items_of(bytes: &[u8]) -> Vec<Result<Frame, Error>> {
        let (items, failure) = decode_all(Frames::new, bytes);
        assert_eq!(failure, None);
        items
    }

    fn check(data: &[u8]) -> usize {
        contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_MESSAGE);
        contract::check_decode_with_held_limit(Frames::new, data, 0);
        contract::check_wire::<Message>(data);
        contract::check_wire::<Frame>(data);
        contract::check_wire::<Interleaved>(data);
        let (items, _) = decode_all(Frames::new, data);
        for item in items.iter().flatten() {
            round_trip(item);
        }
        values_round_trip(data);
        items.iter().flatten().count()
    }

    fn values_round_trip(bytes: &[u8]) {
        macro_rules! check {
            ($($ty:ty),+) => {$(
                contract::check_wire::<$ty>(bytes);
                // Read text directly so a writer failure cannot hide as a parse refusal.
                if let Ok(text) = core::str::from_utf8(bytes) {
                    text_value(<$ty>::read_value(text));
                }
            )+};
        }
        check!(Session, Transport, Transports, Range);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5eed_0554);
        let frame = Interleaved {
            channel: 1,
            data: b"\r\n\r\nRTSP".to_vec(),
        }
        .to_bytes()
        .unwrap();
        let mut setup = b"SETUP rtsp://h/s RTSP/2.0\r\nCSeq: 3\r\nSession: abc;timeout=30\r\n\
            Transport: RTP/AVP/TCP;unicast;interleaved=0-1;mode=\"PLAY,RECORD\", RTP/AVP;dest_addr=\":1\"/\":2\"\r\n\
            Range: smpte=10:07:00-10:07:33:05.01;time=19970123T153600Z\r\n\r\n"
            .to_vec();
        setup.extend(&frame);
        let bare = b"OPTIONS * RTSP/1.0\nCSeq: 1\nX: a\n b\r\n\n".to_vec();
        let not_modified =
            b"RTSP/1.0 304 Not Modified\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\n".to_vec();
        let seeds: Vec<Vec<u8>> = vec![
            OPTIONS.to_vec(),
            OPTIONS_OK.to_vec(),
            describe_ok(),
            PLAY2.to_vec(),
            setup,
            bare,
            not_modified,
        ];
        let mut stream = Vec::new();
        for s in &seeds {
            stream.extend(s);
            stream.extend(&frame);
        }
        let values: [&[u8]; 6] = [
            b"RTP/AVP/UDP;unicast;client_port=4588-4589;server_port=6256-6257;ssrc=0A13C760/00000001;x=\"q\\\"\"",
            b"RTP/SAVP;multicast;ttl=127;port=3456-3457;layers=2;destination;source=a;setup=active;RTCP-mux",
            b"npt=12:05:35.3-now",
            b"clock=19961108T142300Z-19961108T143520.5Z",
            b"QKyjN8nt2WqbWw4tIYof52;timeout=60",
            b"smpte-30-drop=1:2:3:4.5-",
        ];
        let mut read = 0;
        for round in 0..fictionet::stdlib::test_support::rounds(1500) {
            let base: &[u8] = match round % 3 {
                0 => &stream,
                1 => seeds[rng.index(seeds.len())].as_slice(),
                _ => values[rng.index(values.len())],
            };
            let mut data = base.to_vec();
            for _ in 0..1 + rng.index(6) {
                mutate(&mut rng, &mut data);
            }
            read += check(&data);
        }
        assert!(read > 3000, "only {read} items read");
        // Mix arbitrary bytes into text as well as checking byte noise.
        for _ in 0..fictionet::stdlib::test_support::rounds(750) {
            let mut text = rng.text(200).into_bytes();
            let at = rng.index(text.len().saturating_add(1));
            text.splice(at..at, rng.bytes(4));
            let _ = check(&text);
            let _ = check(&rng.bytes(200));
        }
    }

    #[test]
    fn writers_only_write_what_reads_back() {
        use TransportParam as P;
        let mut rng = Lcg::new(42);
        let words = [
            "", "a", "PLAY", "a b", "x;y", "q\"", ":1", "AQ==", "\"z\"", "\"", "TCP", "unicast",
            "é",
        ];
        let mut written = 0;
        for _ in 0..rounds(20_000) {
            let w = |rng: &mut Lcg| {
                let mut value = words[rng.index(words.len())].to_string();
                if rng.index(16) == 0 {
                    value.push_str(&String::from_utf8_lossy(&rng.bytes(3)));
                }
                value
            };
            let mut params = Vec::new();
            for _ in 0..rng.index(4) {
                let n = rng.next() as u32;
                params.push(match rng.index(12) {
                    0 => P::Destination(if n.is_multiple_of(2) {
                        None
                    } else {
                        Some(w(&mut rng))
                    }),
                    1 => P::Source(w(&mut rng)),
                    2 => P::Interleaved(n as u8, n.is_multiple_of(3).then_some((n >> 8) as u8)),
                    3 => P::ClientPort(n as u16, n.is_multiple_of(3).then_some((n >> 16) as u16)),
                    4 => P::Ssrc((0..rng.index(3)).map(|i| n.rotate_left(i as u32)).collect()),
                    5 => P::Mode((0..rng.index(3)).map(|_| w(&mut rng)).collect()),
                    6 => P::DestAddr((0..rng.index(3)).map(|_| w(&mut rng)).collect()),
                    7 => P::Setup(w(&mut rng)),
                    8 => P::Other {
                        name: w(&mut rng),
                        value: if n.is_multiple_of(2) {
                            None
                        } else {
                            Some(w(&mut rng))
                        },
                    },
                    9 => P::Ttl(n as u8),
                    10 => P::Layers(n),
                    _ => P::RtcpMux,
                });
            }
            let lowers = [
                None,
                Some(Lower::Tcp),
                Some(Lower::Udp),
                Some(Lower::Other(w(&mut rng))),
            ];
            let t = Transport {
                protocol: w(&mut rng),
                profile: w(&mut rng),
                lower: lowers[rng.index(lowers.len())].clone(),
                params,
            };
            contract::check_wire_value(&t);
            if let Ok(text) = wire_text(&t) {
                assert_eq!(Transport::parse(text.as_bytes()).unwrap(), t, "{text}");
                written += 1;
            }
            let s = Session {
                id: w(&mut rng),
                timeout: rng.coin().then(|| rng.next()),
            };
            contract::check_wire_value(&s);
            if let Ok(text) = wire_text(&s) {
                assert_eq!(Session::parse(text.as_bytes()).unwrap(), s);
            }
            let n = rng.next() as u32;
            let npt = |n: u32| match n % 3 {
                0 => None,
                1 => Some(Npt::Now),
                _ => Some(Npt::Time {
                    seconds: u64::from(n),
                    nanos: n % 1_100_000_000,
                }),
            };
            let smpte = |n: u32| {
                (!n.is_multiple_of(3)).then(|| Smpte {
                    hours: n as u8,
                    minutes: (n >> 8) as u8 % 100,
                    seconds: 59,
                    frames: n.is_multiple_of(2).then_some(29),
                    subframes: n.is_multiple_of(5).then_some(99),
                })
            };
            let span = match rng.index(3) {
                0 => Span::Npt {
                    start: npt(n),
                    end: npt(n >> 3),
                },
                1 => Span::Smpte {
                    rate: SmpteRate::Smpte30Drop,
                    start: smpte(n),
                    end: smpte(n >> 4),
                },
                _ => Span::Clock {
                    start: Some(w(&mut rng)),
                    end: Some("19961108T142300Z".into()),
                },
            };
            let r = Range {
                span,
                time: n
                    .is_multiple_of(4)
                    .then(|| "19970123T153600.1Z".to_string()),
            };
            contract::check_wire_value(&r);
            if let Ok(text) = wire_text(&r) {
                assert_eq!(Range::parse(text.as_bytes()).unwrap(), r, "{text}");
                written += 1;
            }
            let mut m = if rng.coin() {
                Message::request(Version::Rtsp20, &w(&mut rng), &w(&mut rng))
            } else {
                Message::response(Version::Rtsp10, (n % 700) as u16, &w(&mut rng))
            };
            m.push_header(&w(&mut rng), &w(&mut rng));
            m.body = rng.bytes(3);
            m.set_header("Content-Length", &m.body.len().to_string());
            contract::check_wire_value(&m);
            if let Ok(b) = m.to_bytes() {
                let back = Message::parse(&b).unwrap();
                assert_eq!(back.start, m.start);
                assert_eq!(back.body, m.body);
                written += 1;
            }
        }
        assert!(written > 10_000, "only {written} written");
    }
}
