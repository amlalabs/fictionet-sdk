//! SIP: reading and writing Session Initiation Protocol messages, with no
//! I/O.
//!
//! `Message` implements `Wire`, and `Messages` decodes TCP message framing.
//! There is no transaction or dialog state machine, retransmission scheduler,
//! SIP `Service`, authentication, or media transport.
//!
//! SIP is how VoIP phones, PBXs and proxies set up calls. A phone sends a
//! request such as INVITE, REGISTER or OPTIONS to a SIP URI like
//! `sip:bob@biloxi.com`, and the other side answers with a status such as
//! `180 Ringing` or `200 OK`. Messages look like HTTP: a start line, header
//! fields, a blank line and a body, which is usually an SDP offer. They go
//! over UDP or TCP, usually on port 5060. This module follows RFC 3261.
//!
//! Nothing here reads a socket. A world that plays a phone or a proxy reads
//! a UDP message with [`Message::read_datagram`]. Over TCP, it pushes bytes
//! into [`Stream<Messages>`](fictionet::stdlib::codec::Stream), which splits messages by
//! their Content-Length. Either way, it reads the headers it needs with
//! [`Message::vias`], [`Message::from`], [`Message::cseq`] and the others,
//! builds its answer (often with [`Message::reply`]), and sends the bytes
//! [`Wire::write`] produces. Bodies stay as bytes. Which users exist,
//! and whether a call is answered, is up to world code.
//!
//! Every reader checks lengths and characters, because the agent can send
//! any bytes it likes. Header values are read when asked for, so a message
//! with one malformed header can still be answered, as a real phone would.
//! Writers check what they write and return an error instead of bytes that
//! would not read back.
//!
//! SIP accepts only CRLF and writers always emit CRLF. Empty CRLF
//! keep-alive lines are skipped between messages. Lines exclude their
//! endings and are bounded by [`MAX_LINE`]. The whole head, including
//! endings, is bounded by [`MAX_HEAD`]; the header count by [`MAX_HEADERS`];
//! bodies by [`MAX_BODY`]. Stream messages, including bodiless responses,
//! require Content-Length (or compact `l`). No status overrides it.
//! [`Message::parse`] requires a length and refuses trailing bytes.
//! [`Message::read_datagram`] uses the rest of the datagram as the body
//! when no length is present, and discards bytes after a declared body.
//!
//! A malformed start line or unrelated header with a trusted message
//! boundary is an error item. An over-limit line, head, or body, or an
//! untrusted Content-Length is a stream error. Bare LF also ends the
//! stream because it cannot establish a SIP message boundary. Header-count
//! errors are items. The driver reports truncated input at EOF.
//! Bodies remain bytes; SDP belongs to [`fictionet::stdlib::sdp`].
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::sip::{Message, Uri};
//!
//! let datagram = b"OPTIONS sip:carol@chicago.com SIP/2.0\r\n\
//!     Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\n\
//!     Max-Forwards: 70\r\n\
//!     To: <sip:carol@chicago.com>\r\n\
//!     From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
//!     Call-ID: a84b4c76e66710\r\n\
//!     CSeq: 63104 OPTIONS\r\n\
//!     Contact: <sip:alice@pc33.atlanta.com>\r\n\
//!     Accept: application/sdp\r\n\
//!     Content-Length: 0\r\n\r\n";
//! let request = Message::read_datagram(datagram).unwrap();
//! assert_eq!(request.method(), Some("OPTIONS"));
//! let uri = Uri::parse(request.request_uri().unwrap().as_bytes()).unwrap();
//! assert_eq!(uri.user.as_deref(), Some("carol"));
//! assert_eq!(request.from().unwrap().tag(), Some("1928301774"));
//! assert_eq!(request.cseq().unwrap().seq, 63104);
//!
//! // Carol's phone answers. The reply copies Via, From, To, Call-ID and CSeq.
//! let mut reply = request.reply(200, "OK");
//! reply.push_header("Allow", "INVITE, ACK, CANCEL, OPTIONS, BYE");
//! reply.push_header("Content-Length", "0");
//! let bytes = reply.to_bytes().unwrap();
//! assert!(bytes.starts_with(
//!     b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\n"
//! ));
//! assert!(bytes.ends_with(b"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\nContent-Length: 0\r\n\r\n"));
//! assert_eq!(Message::parse(&bytes).unwrap().status(), Some(200));
//! ```

use fictionet::stdlib::codec::ascii::{trim_ows_str as trim_ws};
use fictionet::stdlib::codec::{Decode, LineError, Step, Wire};
use fictionet::stdlib::codec::head_body::{self, Header, Scanner};

/// The port SIP servers listen on, for UDP and TCP.
pub const PORT: u16 = 5060;
/// The port SIP servers listen on for TLS.
pub const TLS_PORT: u16 = 5061;
/// The only protocol version this module reads and writes.
pub const VERSION: &str = "SIP/2.0";
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
/// The most comma-separated values one read may return.
pub const MAX_VALUES: usize = 256;
/// The most parameters a URI or a header value may have, and the most
/// headers a URI may have.
pub const MAX_PARAMS: usize = 64;

/// Compact header names and the full names they stand for. RFC 3261
/// section 7.3.3 defines c, e, f, i, k, l, m, s, t and v. The others come
/// from later RFCs.
const COMPACT: [(u8, &str); 19] = [
    (b'a', "Accept-Contact"),
    (b'b', "Referred-By"),
    (b'c', "Content-Type"),
    (b'd', "Request-Disposition"),
    (b'e', "Content-Encoding"),
    (b'f', "From"),
    (b'i', "Call-ID"),
    (b'j', "Reject-Contact"),
    (b'k', "Supported"),
    (b'l', "Content-Length"),
    (b'm', "Contact"),
    (b'o', "Event"),
    (b'r', "Refer-To"),
    (b's', "Subject"),
    (b't', "To"),
    (b'u', "Allow-Events"),
    (b'v', "Via"),
    (b'x', "Session-Expires"),
    (b'y', "Identity"),
];

/// The full name a compact header name stands for, such as `Via` for `v`,
/// in either case. Any other name comes back as it is.
pub fn full_name(name: &str) -> &str {
    if let [b] = name.as_bytes() {
        let b = b.to_ascii_lowercase();
        if let Some((_, full)) = COMPACT.iter().find(|(c, _)| *c == b) {
            return full;
        }
    }
    name
}

/// The compact form of a full header name, such as `v` for `Via`, if it
/// has one. Case does not matter.
pub fn compact_name(name: &str) -> Option<&'static str> {
    const LETTERS: &str = "abcdefijklmorstuvxy";
    let i = COMPACT.iter().position(|(_, full)| full.eq_ignore_ascii_case(name))?;
    LETTERS.get(i..i + 1)
}

/// Whether two header names name the same field: equal but for case, or
/// one the compact form of the other.
pub fn same_name(a: &str, b: &str) -> bool {
    full_name(a).eq_ignore_ascii_case(full_name(b))
}

/// Why bytes are not a SIP message, or why a value cannot be read or
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ended before a complete wire unit arrived.
    Incomplete,
    /// Bytes remain after the wire unit.
    Trailing,
    /// Writing would change a field or the body's framing.
    Unwritable,
    /// The head or the body is longer than [`MAX_HEAD`] or [`MAX_BODY`],
    /// or a header value to read or write is longer than [`MAX_HEAD`].
    TooLong,
    /// More header fields than [`MAX_HEADERS`], or more values than
    /// [`MAX_VALUES`].
    TooMany,
    /// A CR or LF in the head that is not part of a CRLF pair.
    LineEnding,
    /// The message head or header value is not UTF-8.
    Utf8,
    /// The request line or status line is malformed.
    StartLine,
    /// The start line is well formed, but its version is not SIP/2.0. A
    /// server answers this with 505.
    Version,
    /// A header line has no colon or a bad name, or the first one starts
    /// with a space, as if it continued a field before it.
    HeaderLine,
    /// A header value holds a control character.
    HeaderValue,
    /// A Content-Length is not a number, or there are two.
    ContentLength,
    /// A message has no Content-Length or compact `l`. Exact messages
    /// and streams require a length. RFC 3261 section 18.3 requires one
    /// over TCP.
    MissingContentLength,
    /// A header a read needs is absent. It names the header.
    Missing(&'static str),
    /// A header's value does not follow its grammar, or a header that may
    /// appear once appears twice. It names the header.
    Malformed(&'static str),
    /// A SIP URI is malformed.
    Uri,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Incomplete => f.write_str("incomplete wire unit"),
            Error::Trailing => f.write_str("bytes after wire unit"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::TooLong => write!(f, "head or header value over {MAX_HEAD} bytes or body over {MAX_BODY} bytes"),
            Error::TooMany => write!(f, "over {MAX_HEADERS} headers or {MAX_VALUES} values"),
            Error::LineEnding => f.write_str("CR or LF outside a CRLF pair"),
            Error::Utf8 => f.write_str("head or header value is not UTF-8"),
            Error::StartLine => f.write_str("malformed request or status line"),
            Error::Version => f.write_str("version is not SIP/2.0"),
            Error::HeaderLine => f.write_str("malformed header line"),
            Error::HeaderValue => f.write_str("control character in a header value"),
            Error::ContentLength => f.write_str("bad Content-Length"),
            Error::MissingContentLength => f.write_str("no Content-Length"),
            Error::Missing(name) => write!(f, "no {name} header"),
            Error::Malformed(name) => write!(f, "malformed {name}"),
            Error::Uri => f.write_str("malformed SIP URI"),
        }
    }
}

impl std::error::Error for Error {}

/// The first line of a message: a request line or a status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartLine {
    /// A request: the `method` and the Request-URI, `uri`, as written.
    Request {
        /// The request method.
        method: String,
        /// The request URI as written.
        uri: String,
    },
    /// A response: the status `code`, 100 to 699, and the `reason` phrase.
    Status {
        /// The status code.
        code: u16,
        /// The reason phrase.
        reason: String,
    },
}

/// One SIP message: a start line, header fields in order, and a body.
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
    pub fn request(method: &str, uri: &str) -> Message {
        Message {
            start: StartLine::Request { method: method.to_string(), uri: uri.to_string() },
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A response with no headers and no body.
    pub fn response(code: u16, reason: &str) -> Message {
        Message { start: StartLine::Status { code, reason: reason.to_string() }, headers: Vec::new(), body: Vec::new() }
    }

    /// Reads one UDP datagram with CRLF lines, per RFC 3261 section 18.3.
    /// With Content-Length or compact `l`, the body is that many bytes;
    /// bytes after it are discarded. Without a length, the body is the
    /// rest of the datagram. Refuses malformed heads, duplicate lengths,
    /// incomplete heads or declared bodies, and heads, lines, bodies, or
    /// header counts over their named limits.
    ///
    /// This reader preserves the headers. To write a message received
    /// without Content-Length, set that header to the body length first.
    pub fn read_datagram(datagram: &[u8]) -> Result<Message, Error> {
        let mut scanner = Scanner::new(MAX_LINE, MAX_HEAD, true);
        let end = scanner.scan_head(datagram).map_err(framing_error)?.ok_or(Error::Incomplete)?;
        let (mut message, length) = parse_head(datagram.get(..end).ok_or(Error::Incomplete)?)?;
        let rest = datagram.get(end..).ok_or(Error::Incomplete)?;
        let body = match length {
            Some(length) => rest.get(..length).ok_or(Error::Incomplete)?,
            None if rest.len() > MAX_BODY => return Err(Error::TooLong),
            None => rest,
        };
        message.body = body.to_vec();
        Ok(message)
    }

    /// The method, for a request.
    pub fn method(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            StartLine::Status { .. } => None,
        }
    }

    /// The Request-URI as written, for a request. [`Uri::parse`] reads it
    /// when it is a SIP URI.
    pub fn request_uri(&self) -> Option<&str> {
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

    /// The headers named `name`, in order. Case does not matter, and a
    /// compact name matches its full name.
    pub fn headers_named<'a, 'n>(&'a self, name: &'n str) -> impl Iterator<Item = &'a Header> + use<'a, 'n> {
        self.headers.iter().filter(move |h| same_name(&h.name, name))
    }

    /// The value of the first header named `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers_named(name).next().map(|h| h.value.as_str())
    }

    /// The comma-separated values of every header named `name`, in order,
    /// trimmed. Commas inside quoted strings and angle brackets do not
    /// split. RFC 3261 section 7.3.1 makes several headers with one name
    /// the same as one header listing their values. An unclosed quote or
    /// bracket is [`Error::Malformed`].
    pub fn values(&self, name: &str) -> Result<Vec<&str>, Error> {
        let mut out = Vec::new();
        for h in self.headers_named(name) {
            split_commas(&h.value, &mut out, "comma-separated value")?;
        }
        Ok(out)
    }

    /// Adds a header at the end.
    pub fn push_header(&mut self, name: &str, value: &str) {
        self.headers.push(Header::new(name, value));
    }

    /// Adds a header from a wire value. Refuses a failed value write or
    /// invalid UTF-8, and leaves the headers unchanged on error.
    /// The message writer checks the header name, text, and size limits.
    pub fn push_value(&mut self, name: &str, value: &impl Wire<WriteError = Error>) -> Result<(), Error> {
        let value = String::from_utf8(value.to_bytes()?).map_err(|_| Error::Utf8)?;
        self.headers.push(Header { name: name.to_string(), value });
        Ok(())
    }

    /// Sets the header named `name` to `value`: the first one is changed
    /// and any others are removed. With none, it is added at the end.
    pub fn set_header(&mut self, name: &str, value: &str) {
        match self.headers.iter().position(|h| same_name(&h.name, name)) {
            Some(i) => {
                self.headers[i].value = value.to_string();
                let mut seen = 0usize;
                self.headers.retain(|h| {
                    if !same_name(&h.name, name) {
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
        self.headers.retain(|h| !same_name(&h.name, name));
        before - self.headers.len()
    }

    /// The Via headers' values, top one first. Each says where a request
    /// has been, and where its response goes back. A Via header with no
    /// value, or with an empty item in its list, is [`Error::Malformed`].
    pub fn vias(&self) -> Result<Vec<Via>, Error> {
        let mut parts = Vec::new();
        for h in self.headers_named("Via") {
            split_list(&h.value, &mut parts, "Via")?;
        }
        parts.into_iter().map(Via::read_value).collect()
    }

    /// The From header: who sent the request.
    pub fn from(&self) -> Result<NameAddr, Error> {
        NameAddr::read_value(self.single("From")?).map_err(|_| Error::Malformed("From"))
    }

    /// The To header: whom the request is for.
    pub fn to(&self) -> Result<NameAddr, Error> {
        NameAddr::read_value(self.single("To")?).map_err(|_| Error::Malformed("To"))
    }

    /// The Call-ID, the same in every message of a call: a word, or two
    /// words joined by `@` (RFC 3261 section 25.1). A word is printable
    /// ASCII but for `,`, `;`, `=`, `@`, `#`, `$`, `&`, `^` and `|`.
    pub fn call_id(&self) -> Result<&str, Error> {
        let v = self.single("Call-ID")?;
        let mut words = v.split('@');
        let first = words.next().unwrap_or("");
        let second = words.next();
        if !is_word(first) || second.is_some_and(|w| !is_word(w)) || words.next().is_some() {
            return Err(Error::Malformed("Call-ID"));
        }
        Ok(v)
    }

    /// The CSeq: a sequence number and the request's method.
    pub fn cseq(&self) -> Result<CSeq, Error> {
        CSeq::read_value(self.single("CSeq")?)
    }

    /// The Contact headers' addresses, or [`Contacts::All`] for `*`. With
    /// no Contact header, the list is empty. A Contact header with no
    /// value, or with an empty item in its list, is [`Error::Malformed`],
    /// since RFC 3261 gives it at least one and no empty ones.
    pub fn contacts(&self) -> Result<Contacts, Error> {
        let mut parts = Vec::new();
        for h in self.headers_named("Contact") {
            split_list(&h.value, &mut parts, "Contact")?;
        }
        Contacts::from_values(&parts)
    }

    /// The Content-Length, if the message has one. Two Content-Length
    /// headers are [`Error::ContentLength`], even if they agree, since RFC
    /// 3261 section 7.3.1 lets only list headers repeat.
    pub fn content_length(&self) -> Result<Option<usize>, Error> {
        let mut found = self.headers_named("Content-Length");
        let Some(h) = found.next() else { return Ok(None) };
        if found.next().is_some() {
            return Err(Error::ContentLength);
        }
        parse_content_length(&h.value).map(Some)
    }

    /// A response to this request, with its Via, From, To, Call-ID and CSeq
    /// headers copied in order, as RFC 3261 section 8.2.6.2 says. A 100
    /// copies Timestamp too, as section 8.2.6.1 says; adding a delay to it
    /// is up to the caller. Adding a tag to To, and a Contact or
    /// Record-Route, is up to the caller.
    pub fn reply(&self, code: u16, reason: &str) -> Message {
        let mut reply = Message::response(code, reason);
        const COPIED: [&str; 5] = ["Via", "From", "To", "Call-ID", "CSeq"];
        let copied = |h: &&Header| {
            COPIED.iter().any(|n| same_name(&h.name, n)) || (code == 100 && same_name(&h.name, "Timestamp"))
        };
        reply.headers = self.headers.iter().filter(copied).cloned().collect();
        reply
    }

    /// The value of the one header named `name`.
    fn single(&self, name: &'static str) -> Result<&str, Error> {
        let mut found = self.headers_named(name);
        let h = found.next().ok_or(Error::Missing(name))?;
        if found.next().is_some() {
            return Err(Error::Malformed(name));
        }
        Ok(&h.value)
    }
}

/// Reads complete SIP units with bounded line and body framing.
///
/// Use with [`Stream<Messages>`](fictionet::stdlib::codec::Stream). Items are `Result<Message, Error>`.
/// A bad start line or header is an error item once a trusted body length
/// and the complete unit are available. Invalid lengths and byte limits
/// end the stream. Bare LF is a stream error: only CRLF ends SIP lines,
/// so framing cannot resume after it. Partial units return [`Step::Need`],
/// including at EOF. The driver reports truncation and returns stream
/// errors once.
///
/// [`Scanner`] scans incrementally; each head byte is scanned a fixed number
/// of times. The driver retains the whole unit, so
/// [`fictionet::stdlib::codec::Stream::with_next`] includes its head and body.
/// Capacity is [`MAX_MESSAGE`]; no input bytes are held in decoder state.
/// Body framing follows Content-Length automatically, from the headers.
/// Each call yields at most one unit and returns control to the caller.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire}, sip::{Message, Messages}};
///
/// let bytes = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
/// let message = <Message as Wire>::parse(bytes)?;
/// let mut stream = Stream::new(Messages::new());
/// assert_eq!(stream.push(bytes), bytes.len());
/// assert_eq!(stream.next(), Some(Ok(Ok(message))));
/// stream.end();
/// assert_eq!(stream.next(), None);
/// # Ok::<(), fictionet::stdlib::sip::Error>(())
/// ```
pub struct Messages {
    scanner: Scanner,
}

impl core::fmt::Debug for Messages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Messages").field("scanner", &self.scanner).finish_non_exhaustive()
    }
}

impl Default for Messages {
    fn default() -> Self {
        Self::new()
    }
}

impl Messages {
    /// Creates a decoder using [`MAX_LINE`], [`MAX_HEAD`], and [`MAX_BODY`].
    pub fn new() -> Self {
        Self { scanner: Scanner::new(MAX_LINE, MAX_HEAD, true) }
    }
}

impl Decode for Messages {
    type Item = Result<Message, Error>;
    type Error = Error;
    const NAME: &'static str = "SIP";

    fn capacity(&self) -> usize {
        MAX_MESSAGE
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        if self.scanner.is_start() {
            let mut skip = 0usize;
            while input.get(skip..).is_some_and(|b| b.starts_with(b"\r\n")) {
                skip = skip.checked_add(2).ok_or(Error::TooLong)?;
            }
            if skip != 0 {
                self.scanner = Scanner::new(MAX_LINE, MAX_HEAD, true);
                return Ok(Step::Skip(skip));
            }
        }
        let Some((head, used)) = self.scanner.scan(input, frame_body_length, framing_error)? else {
            return Ok(Step::Need);
        };
        let body = &input[head..used];
        let message = parse_head(input.get(..head).ok_or(Error::TooLong)?).map(|(mut message, _)| {
            message.body = body.to_vec();
            message
        });
        Ok(Step::Item(message, used))
    }
}

// Find the length independently of message syntax. This lets a malformed
// start line or unrelated header be returned as an item at a known boundary.
// Only offsets and lengths survive Need; header strings are never cached.
fn frame_body_length(head: &[u8]) -> Result<usize, Error> {
    let mut lines = head.split(|&b| b == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let _ = lines.next();
    head_body::content_length(lines, |name| name.eq_ignore_ascii_case(b"Content-Length") || name.eq_ignore_ascii_case(b"l"),
        parse_content_length, false, Error::ContentLength)?.ok_or(Error::MissingContentLength)
}

#[inline]
fn framing_error(error: LineError) -> Error {
    match error {
        LineError::TooLong { .. } => Error::TooLong,
        _ => Error::LineEnding,
    }
}

fn read_wire(bytes: &[u8]) -> Result<Message, Error> {
    if bytes.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let mut frames = Messages::new();
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

    /// Reads one complete SIP message with CRLF lines. Leading CRLF
    /// keep-alives are skipped. Content-Length or compact `l` is required
    /// and selects the body, even for status 1xx, 204, and 304.
    /// Refuses missing or duplicate lengths, malformed or incomplete input,
    /// trailing bytes, and heads or bodies over their named limits.
    /// The canonical CRLF head must also fit [`MAX_HEAD`] and [`MAX_LINE`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let message = read_wire(bytes)?;
        message_size(&message)?;
        Ok(message)
    }

    /// Appends a CRLF message without changing any field. Leaves `out`
    /// unchanged on error. Content-Length fields are preserved, including
    /// spelling, position, and digits. Set them to match the body before
    /// writing. Values that need trimming or header injection are refused.
    /// A body length mismatch is [`Error::Unwritable`]. Refuses invalid
    /// methods, URIs, status codes outside 100 to 699, bad header names
    /// or controls, and heads, lines, bodies, or header counts over their
    /// named limits. Missing and duplicate Content-Length are refused.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let total = message_size(self)?;
        out.try_reserve(total).map_err(|_| Error::TooLong)?;
        match &self.start {
            StartLine::Request { method, uri } => {
                out.extend_from_slice(method.as_bytes());
                out.push(b' ');
                out.extend_from_slice(uri.as_bytes());
                out.push(b' ');
                out.extend_from_slice(VERSION.as_bytes());
            }
            StartLine::Status { code, reason } => {
                out.extend_from_slice(VERSION.as_bytes());
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
        StartLine::Request { method, uri } => method
            .len()
            .checked_add(uri.len())
            .and_then(|n| n.checked_add(VERSION.len()))
            .and_then(|n| n.checked_add(2))
            .ok_or(too_long)?,
        StartLine::Status { code, reason } => {
            if !(100..=699).contains(code) {
                return Err(Error::StartLine);
            }
            reason.len().checked_add(VERSION.len()).and_then(|n| n.checked_add(5)).ok_or(too_long)?
        }
    };
    if start > MAX_LINE {
        return Err(too_long);
    }
    let mut head = start.checked_add(4).ok_or(too_long)?;
    for header in &message.headers {
        let line = header.name.len().checked_add(header.value.len()).and_then(|n| n.checked_add(2)).ok_or(too_long)?;
        if line > MAX_LINE {
            return Err(too_long);
        }
        head = head.checked_add(line).and_then(|n| n.checked_add(2)).ok_or(too_long)?;
        if head > MAX_HEAD {
            return Err(too_long);
        }
    }
    if head > MAX_HEAD {
        return Err(too_long);
    }
    let total = head.checked_add(message.body.len()).ok_or(too_long)?;
    match &message.start {
        StartLine::Request { method, uri } if !is_token(method) || !valid_uri_text(uri) => {
            return Err(Error::StartLine);
        }
        StartLine::Status { reason, .. } if !valid_value(reason) => return Err(Error::StartLine),
        _ => {}
    }
    for header in &message.headers {
        if !is_token(&header.name) {
            return Err(Error::HeaderLine);
        }
        if !valid_field(&header.value) {
            return Err(Error::HeaderValue);
        }
        if trim_ws(&header.value) != header.value {
            return Err(Error::Unwritable);
        }
    }
    let length = message.content_length()?.ok_or(Error::MissingContentLength)?;
    if length != message.body.len() {
        return Err(Error::Unwritable);
    }
    Ok(total)
}

/// A SIP URI's scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `sip:`.
    Sip,
    /// `sips:`, which asks for TLS on every hop.
    Sips,
}

/// A parameter: `;name` or `;name=value`. In a header value, the value is
/// kept as written, so a quoted string keeps its quotes;
/// [`Param::unquoted`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    /// The parameter's name.
    pub name: String,
    /// The value after `=`, if there is one.
    pub value: Option<String>,
}

impl Param {
    /// A parameter with this name and value.
    pub fn new(name: &str, value: Option<&str>) -> Param {
        Param { name: name.to_string(), value: value.map(str::to_string) }
    }

    /// The value with quotes and backslash escapes taken out, if it has a
    /// value.
    pub fn unquoted(&self) -> Option<String> {
        self.value.as_deref().map(unquote)
    }
}

/// A SIP or SIPS URI (RFC 3261 section 19.1), such as
/// `sip:alice:secret@atlanta.com:5060;transport=tcp?subject=lunch`. Each
/// part is kept as written, so `%20` stays `%20`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uri {
    /// `sip` or `sips`.
    pub scheme: Scheme,
    /// The user part, before `@`, if there is one.
    pub user: Option<String>,
    /// The password after the user and `:`. RFC 3261 advises against it.
    pub password: Option<String>,
    /// A host name, an IPv4 address, or an IPv6 address in brackets.
    pub host: String,
    /// The port, if one is given.
    pub port: Option<u16>,
    /// The URI parameters, such as `transport` and `lr`.
    pub params: Vec<Param>,
    /// The headers after `?`, as names and values.
    pub headers: Vec<(String, String)>,
}

impl Uri {
    /// A URI with this scheme and host, and nothing else.
    pub fn new(scheme: Scheme, host: &str) -> Uri {
        Uri {
            scheme,
            user: None,
            password: None,
            host: host.to_string(),
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
        }
    }

    fn read_value(s: &str) -> Result<Uri, Error> {
        if s.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        let colon = s.find(':').ok_or(Error::Uri)?;
        let scheme = match &s[..colon] {
            x if x.eq_ignore_ascii_case("sip") => Scheme::Sip,
            x if x.eq_ignore_ascii_case("sips") => Scheme::Sips,
            _ => return Err(Error::Uri),
        };
        let rest = &s[colon + 1..];
        let (userinfo, rest) = match rest.find('@') {
            Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
            None => (None, rest),
        };
        let (user, password) = match userinfo {
            None => (None, None),
            Some(info) => {
                let (u, p) = match info.find(':') {
                    Some(i) => (&info[..i], Some(&info[i + 1..])),
                    None => (info, None),
                };
                if u.is_empty() || !escaped_ok(u, is_user_char) {
                    return Err(Error::Uri);
                }
                if p.is_some_and(|p| !escaped_ok(p, is_password_char)) {
                    return Err(Error::Uri);
                }
                (Some(u.to_string()), p.map(str::to_string))
            }
        };
        let (main, header_part) = match rest.find('?') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        let mut parts = main.split(';');
        let (host, port) = parse_hostport(parts.next().unwrap_or("")).ok_or(Error::Uri)?;
        let mut params = Vec::new();
        for p in parts {
            if params.len() >= MAX_PARAMS {
                return Err(Error::Uri);
            }
            let (name, value) = match p.find('=') {
                Some(i) => (&p[..i], Some(&p[i + 1..])),
                None => (p, None),
            };
            if !valid_uri_param(name, value) || params.iter().any(|q: &Param| uri_name_eq(&q.name, name)) {
                return Err(Error::Uri);
            }
            params.push(Param::new(name, value));
        }
        let mut headers = Vec::new();
        if let Some(hp) = header_part {
            for item in hp.split('&') {
                if headers.len() >= MAX_PARAMS {
                    return Err(Error::Uri);
                }
                let i = item.find('=').ok_or(Error::Uri)?;
                let (name, value) = (&item[..i], &item[i + 1..]);
                if !valid_uri_header(name, value) {
                    return Err(Error::Uri);
                }
                headers.push((name.to_string(), value.to_string()));
            }
        }
        Ok(Uri { scheme, user, password, host, port, params, headers })
    }

    fn format_value(&self) -> Result<String, Error> {
        if self.params.len() > MAX_PARAMS || self.headers.len() > MAX_PARAMS {
            return Err(Error::Uri);
        }
        let parts = [self.user.as_deref(), self.password.as_deref(), Some(self.host.as_str())];
        let params = self.params.iter().flat_map(|p| [p.name.len(), p.value.as_deref().map_or(0, str::len)]);
        let headers = self.headers.iter().flat_map(|(n, v)| [n.len(), v.len()]);
        if !fits(parts.iter().map(|p| p.map_or(0, str::len)).chain(params).chain(headers)) {
            return Err(Error::TooLong);
        }
        let mut out = String::from(match self.scheme {
            Scheme::Sip => "sip:",
            Scheme::Sips => "sips:",
        });
        match (&self.user, &self.password) {
            (Some(u), p) => {
                if u.is_empty() || !escaped_ok(u, is_user_char) {
                    return Err(Error::Uri);
                }
                out.push_str(u);
                if let Some(p) = p {
                    if !escaped_ok(p, is_password_char) {
                        return Err(Error::Uri);
                    }
                    out.push(':');
                    out.push_str(p);
                }
                out.push('@');
            }
            (None, Some(_)) => return Err(Error::Uri),
            (None, None) => {}
        }
        if !valid_host(&self.host) {
            return Err(Error::Uri);
        }
        out.push_str(&self.host);
        if let Some(port) = self.port {
            out.push_str(&format!(":{port}"));
        }
        for (i, p) in self.params.iter().enumerate() {
            if !valid_uri_param(&p.name, p.value.as_deref())
                || self.params[..i].iter().any(|q| uri_name_eq(&q.name, &p.name))
            {
                return Err(Error::Uri);
            }
            out.push(';');
            out.push_str(&p.name);
            if let Some(v) = &p.value {
                out.push('=');
                out.push_str(v);
            }
        }
        for (i, (name, value)) in self.headers.iter().enumerate() {
            if !valid_uri_header(name, value) {
                return Err(Error::Uri);
            }
            out.push(if i == 0 { '?' } else { '&' });
            out.push_str(name);
            out.push('=');
            out.push_str(value);
        }
        if out.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        Ok(out)
    }

    /// The parameter named `name`, in any case. A `%` escape of a
    /// character that need not be escaped matches the character, so
    /// `%6C%72` is `lr` (RFC 3261 section 19.1.4).
    pub fn param(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|p| uri_name_eq(&p.name, name))
    }
}

/// A name and address, as in From, To and Contact:
/// `"Display Name" <sip:user@host>;tag=abc`. The URI is kept as written
/// and may have any scheme; [`NameAddr::sip_uri`] reads a SIP one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameAddr {
    /// The display name, with quotes and escapes taken out. An empty one
    /// reads as `None`.
    pub display: Option<String>,
    /// The URI, as written.
    pub uri: String,
    /// The header parameters after the address, such as `tag`, `q` and
    /// `expires`.
    pub params: Vec<Param>,
}

impl NameAddr {
    /// An address with this URI and no display name or parameters.
    pub fn new(uri: &str) -> NameAddr {
        NameAddr { display: None, uri: uri.to_string(), params: Vec::new() }
    }

    fn read_value(s: &str) -> Result<NameAddr, Error> {
        if s.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        Self::parse_inner(s).ok_or(Error::Malformed("address"))
    }

    fn parse_inner(s: &str) -> Option<NameAddr> {
        if !valid_field(s) {
            return None;
        }
        let s = trim_ws(s);
        let b = s.as_bytes();
        let (display, uri, rest) = if b.first() == Some(&b'"') {
            let end = quoted_end(b, 0)?;
            let display = unquote(&s[..end]);
            let after = trim_ws(&s[end..]).strip_prefix('<')?;
            let close = after.find('>')?;
            (Some(display), &after[..close], &after[close + 1..])
        } else if let Some(lt) = s.find('<') {
            let words = &s[..lt];
            if !words.bytes().all(|c| is_token_byte(c) || is_ws(c)) {
                return None;
            }
            let mut display = String::with_capacity(words.len());
            for w in words.split([' ', '\t']).filter(|w| !w.is_empty()) {
                if !display.is_empty() {
                    display.push(' ');
                }
                display.push_str(w);
            }
            let after = &s[lt + 1..];
            let close = after.find('>')?;
            (Some(display), &after[..close], &after[close + 1..])
        } else {
            let end = s.find(';').unwrap_or(s.len());
            (None, trim_ws(&s[..end]), &s[end..])
        };
        if !valid_uri_text(uri) {
            return None;
        }
        let params = parse_gen_params(rest, false)?;
        let display = display.filter(|d| !d.is_empty());
        Some(NameAddr { display, uri: uri.to_string(), params })
    }

    fn format_value(&self) -> Result<String, Error> {
        let bad = Error::Malformed("address");
        if !fits([self.raw_len()]) {
            return Err(Error::TooLong);
        }
        let mut out = String::new();
        if let Some(d) = self.display.as_deref().filter(|d| !d.is_empty()) {
            if d.contains(['\r', '\n']) {
                return Err(bad);
            }
            out.push('"');
            for c in d.chars() {
                if c == '"' || c == '\\' || (c.is_ascii_control() && c != '\t') {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push_str("\" ");
        }
        if !valid_uri_text(&self.uri) {
            return Err(bad);
        }
        out.push('<');
        out.push_str(&self.uri);
        out.push('>');
        write_gen_params(&mut out, &self.params, false).ok_or(bad)?;
        if out.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        Ok(out)
    }

    /// The length of the parts, before quotes and separators are added.
    fn raw_len(&self) -> usize {
        let params = self.params.iter().map(|p| p.name.len().saturating_add(p.value.as_deref().map_or(0, str::len)));
        let display = self.display.as_deref().map_or(0, str::len);
        params.fold(display.saturating_add(self.uri.len()), usize::saturating_add)
    }

    /// The URI read as a SIP or SIPS URI.
    pub fn sip_uri(&self) -> Result<Uri, Error> {
        Uri::read_value(&self.uri)
    }

    /// The first parameter named `name`, in any case.
    pub fn param(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// The `tag` parameter's value: half of what names a dialog.
    pub fn tag(&self) -> Option<&str> {
        self.param("tag")?.value.as_deref()
    }
}

/// The Contact header's values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Contacts {
    /// `*`: every binding, as in a REGISTER that removes them all.
    All,
    /// The addresses listed, which may be none.
    List(Vec<NameAddr>),
}

impl Contacts {
    fn from_values(parts: &[&str]) -> Result<Contacts, Error> {
        let bad = Error::Malformed("Contact");
        if parts.contains(&"*") {
            return if parts.len() == 1 { Ok(Contacts::All) } else { Err(bad) };
        }
        let read = |p: &&str| match NameAddr::read_value(p) {
            Ok(a) if contact_params_ok(&a) => Ok(a),
            Err(Error::TooLong) => Err(Error::TooLong),
            _ => Err(bad),
        };
        parts.iter().map(read).collect::<Result<_, _>>().map(Contacts::List)
    }

    fn read_value(s: &str) -> Result<Contacts, Error> {
        if s.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        let mut parts = Vec::new();
        split_list(s, &mut parts, "Contact")?;
        Contacts::from_values(&parts)
    }

    fn format_value(&self) -> Result<String, Error> {
        let bad = Error::Malformed("Contact");
        match self {
            Contacts::All => Ok("*".to_string()),
            Contacts::List(list) => {
                if list.is_empty() {
                    return Err(bad);
                }
                if list.len() > MAX_VALUES {
                    return Err(Error::TooMany);
                }
                if !fits(list.iter().map(NameAddr::raw_len)) {
                    return Err(Error::TooLong);
                }
                let mut out = String::new();
                for a in list {
                    if !contact_params_ok(a) {
                        return Err(bad);
                    }
                    let v = a.format_value().map_err(|e| if e == Error::TooLong { e } else { bad })?;
                    if !out.is_empty() {
                        out.push_str(", ");
                    }
                    out.push_str(&v);
                    if out.len() > MAX_HEAD {
                        return Err(Error::TooLong);
                    }
                }
                Ok(out)
            }
        }
    }
}

/// One Via value: `SIP/2.0/UDP host:port;branch=z9hG4bK...`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Via {
    /// The transport, such as `UDP`, `TCP` or `TLS`, as written.
    pub transport: String,
    /// The host the sender gave: a name, an IPv4 address, or an IPv6
    /// address in brackets.
    pub host: String,
    /// The port, if one is given.
    pub port: Option<u16>,
    /// The parameters, such as `branch`, `received` and `rport`.
    pub params: Vec<Param>,
}

impl Via {
    /// A Via with this transport and host, and no port or parameters.
    pub fn new(transport: &str, host: &str) -> Via {
        Via { transport: transport.to_string(), host: host.to_string(), port: None, params: Vec::new() }
    }

    fn read_value(s: &str) -> Result<Via, Error> {
        if s.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        Self::parse_inner(s).ok_or(Error::Malformed("Via"))
    }

    fn parse_inner(s: &str) -> Option<Via> {
        if !valid_field(s) {
            return None;
        }
        let b = s.as_bytes();
        let mut i = skip_ws(b, 0);
        let mut words = [""; 3];
        for (n, word) in words.iter_mut().enumerate() {
            if n > 0 {
                i = skip_ws(b, i);
                if b.get(i) != Some(&b'/') {
                    return None;
                }
                i = skip_ws(b, i + 1);
            }
            let end = token_end(b, i);
            if end == i {
                return None;
            }
            *word = &s[i..end];
            i = end;
        }
        if !words[0].eq_ignore_ascii_case("SIP") || words[1] != "2.0" {
            return None;
        }
        let after = skip_ws(b, i);
        if after == i {
            return None;
        }
        i = after;
        let host_start = i;
        if b.get(i) == Some(&b'[') {
            i += s[i..].find(']')? + 1;
        } else {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'-' || b[i] == b'.') {
                i += 1;
            }
        }
        let host = &s[host_start..i];
        if !valid_host(host) {
            return None;
        }
        let mut port = None;
        let j = skip_ws(b, i);
        if b.get(j) == Some(&b':') {
            let start = skip_ws(b, j + 1);
            let mut end = start;
            while end < b.len() && b[end].is_ascii_digit() {
                end += 1;
            }
            port = Some(parse_port(&s[start..end])?);
            i = end;
        }
        let params = parse_gen_params(&s[i..], true)?;
        Some(Via { transport: words[2].to_string(), host: host.to_string(), port, params })
    }

    fn format_value(&self) -> Result<String, Error> {
        let bad = Error::Malformed("Via");
        let params = self.params.iter().map(|p| p.name.len().saturating_add(p.value.as_deref().map_or(0, str::len)));
        if !fits([self.transport.len(), self.host.len()].into_iter().chain(params)) {
            return Err(Error::TooLong);
        }
        if !is_token(&self.transport) || !valid_host(&self.host) {
            return Err(bad);
        }
        let mut out = format!("SIP/2.0/{} {}", self.transport, self.host);
        if let Some(port) = self.port {
            out.push_str(&format!(":{port}"));
        }
        write_gen_params(&mut out, &self.params, true).ok_or(bad)?;
        if out.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        Ok(out)
    }

    /// The first parameter named `name`, in any case.
    pub fn param(&self, name: &str) -> Option<&Param> {
        self.params.iter().find(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// The `branch` parameter's value, which names the transaction. Since
    /// RFC 3261 it starts with `z9hG4bK`.
    pub fn branch(&self) -> Option<&str> {
        self.param("branch")?.value.as_deref()
    }
}

/// A CSeq value: `314159 INVITE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSeq {
    /// The sequence number. RFC 3261 section 8.1.1.5 says senders keep it
    /// below 2^31. [`Wire`] enforces this for parsing and writing.
    /// [`Message::cseq`] can inspect any 32-bit received number.
    pub seq: u32,
    /// The request's method.
    pub method: String,
}

impl CSeq {
    fn read_value(s: &str) -> Result<CSeq, Error> {
        if s.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        let bad = Error::Malformed("CSeq");
        let s = trim_ws(s);
        let split = s.find([' ', '\t']).ok_or(bad)?;
        let (digits, method) = (&s[..split], trim_ws(&s[split..]));
        if digits.is_empty() || !digits.bytes().all(|d| d.is_ascii_digit()) || !is_token(method) {
            return Err(bad);
        }
        let seq = digits.bytes().try_fold(0u32, |n, d| n.checked_mul(10)?.checked_add(u32::from(d - b'0')));
        Ok(CSeq { seq: seq.ok_or(bad)?, method: method.to_string() })
    }

    fn format_value(&self) -> Result<String, Error> {
        if self.method.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        if !is_token(&self.method) || self.seq >= 1 << 31 {
            return Err(Error::Malformed("CSeq"));
        }
        let out = format!("{} {}", self.seq, self.method);
        if out.len() > MAX_HEAD {
            return Err(Error::TooLong);
        }
        Ok(out)
    }
}

/// Reads a head that ends with CRLF CRLF: the message with no body, and
/// its Content-Length.
fn parse_head(head: &[u8]) -> Result<(Message, Option<usize>), Error> {
    let text = std::str::from_utf8(head).map_err(|_| Error::Utf8)?;
    let text = text.strip_suffix("\r\n\r\n").ok_or(Error::Incomplete)?;
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    if first.contains(['\r', '\n']) {
        return Err(Error::LineEnding);
    }
    let start = parse_start_line(first)?;
    let mut headers: Vec<Header> = Vec::new();
    for line in lines {
        if line.contains(['\r', '\n']) {
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
    if !headers.iter().all(|h| valid_field(&h.value)) {
        return Err(Error::HeaderValue);
    }
    let message = Message { start, headers, body: Vec::new() };
    let length = message.content_length()?;
    Ok((message, length))
}

fn parse_start_line(line: &str) -> Result<StartLine, Error> {
    if line.as_bytes().get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"SIP/")) {
        let (version, rest) = match line.find(' ') {
            Some(i) => (&line[..i], Some(&line[i + 1..])),
            None => (line, None),
        };
        if !is_sip_version(version) {
            return Err(Error::StartLine);
        }
        let rest = rest.ok_or(Error::StartLine)?;
        let (code, reason) = match rest.find(' ') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        if code.len() != 3 || !code.bytes().all(|d| d.is_ascii_digit()) || !valid_value(reason) {
            return Err(Error::StartLine);
        }
        let code = code.bytes().fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
        if !(100..=699).contains(&code) {
            return Err(Error::StartLine);
        }
        check_version(version)?;
        return Ok(StartLine::Status { code, reason: reason.to_string() });
    }
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::StartLine);
    };
    if !is_token(method) || !valid_uri_text(uri) || !is_sip_version(version) {
        return Err(Error::StartLine);
    }
    check_version(version)?;
    Ok(StartLine::Request { method: method.to_string(), uri: uri.to_string() })
}

/// Checks that a well-formed SIP-Version is SIP/2.0.
fn check_version(version: &str) -> Result<(), Error> {
    if version.eq_ignore_ascii_case(VERSION) { Ok(()) } else { Err(Error::Version) }
}

/// Whether `s` is a SIP-Version: `SIP/`, digits, a dot and digits.
fn is_sip_version(s: &str) -> bool {
    let Some(rest) = s.get(4..).filter(|_| s.as_bytes()[..4].eq_ignore_ascii_case(b"SIP/")) else {
        return false;
    };
    let digits = |d: &str| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit());
    rest.split_once('.').is_some_and(|(major, minor)| digits(major) && digits(minor))
}

fn parse_content_length(v: &str) -> Result<usize, Error> {
    if v.is_empty() || !v.bytes().all(|d| d.is_ascii_digit()) {
        return Err(Error::ContentLength);
    }
    let mut n = 0usize;
    for d in v.bytes() {
        n = n.checked_mul(10).and_then(|n| n.checked_add(usize::from(d - b'0'))).ok_or(Error::TooLong)?;
        if n > MAX_BODY {
            return Err(Error::TooLong);
        }
    }
    Ok(n)
}

/// Adds the items of a list header's value to `out`, trimmed. An empty
/// value or an empty item is [`Error::Malformed`].
fn split_list<'a>(s: &'a str, out: &mut Vec<&'a str>, name: &'static str) -> Result<(), Error> {
    let before = out.len();
    split(s, out, name, true)?;
    if out[before..].iter().any(|i| i.is_empty()) {
        return Err(Error::Malformed(name));
    }
    Ok(())
}

/// Adds the comma-separated values in `s` to `out`, trimmed, skipping
/// empty ones.
fn split_commas<'a>(s: &'a str, out: &mut Vec<&'a str>, name: &'static str) -> Result<(), Error> {
    split(s, out, name, false)
}

/// Adds the comma-separated values in `s` to `out`, trimmed. Empty ones
/// are kept only if `keep_empty`.
fn split<'a>(s: &'a str, out: &mut Vec<&'a str>, name: &'static str, keep_empty: bool) -> Result<(), Error> {
    let b = s.as_bytes();
    let push = |part: &'a str, out: &mut Vec<&'a str>| {
        let part = trim_ws(part);
        if part.is_empty() && !keep_empty {
            return Ok(());
        }
        if out.len() >= MAX_VALUES {
            return Err(Error::TooMany);
        }
        out.push(part);
        Ok(())
    };
    let (mut start, mut i) = (0, 0);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = quoted_end(b, i).ok_or(Error::Malformed(name))?;
                continue;
            }
            b'<' => {
                i += s[i..].find('>').ok_or(Error::Malformed(name))? + 1;
                continue;
            }
            b',' => {
                push(&s[start..i], out)?;
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    push(&s[start..], out)
}

/// Reads header parameters: any number of `;name` or `;name=value`, with
/// spaces allowed around `;` and `=`. A value is a token, an IPv6
/// reference or a quoted string. In a Via, `received` may also hold an
/// IPv6 address with no brackets, as RFC 3261 section 25.1 writes it.
fn parse_gen_params(s: &str, via: bool) -> Option<Vec<Param>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        i = skip_ws(b, i);
        if i == b.len() {
            return Some(out);
        }
        if b[i] != b';' || out.len() >= MAX_PARAMS {
            return None;
        }
        i = skip_ws(b, i + 1);
        let end = token_end(b, i);
        if end == i {
            return None;
        }
        let name = &s[i..end];
        i = skip_ws(b, end);
        let mut value = None;
        if b.get(i) == Some(&b'=') {
            i = skip_ws(b, i + 1);
            let start = i;
            match b.get(i) {
                Some(b'"') => i = quoted_end(b, i)?,
                Some(b'[') => i += s[i..].find(']')? + 1,
                _ if via && name.eq_ignore_ascii_case("received") => {
                    while i < b.len() && (is_token_byte(b[i]) || b[i] == b':') {
                        i += 1;
                    }
                }
                _ => i = token_end(b, i),
            }
            let v = &s[start..i];
            if !valid_gen_value(name, v, via) {
                return None;
            }
            value = Some(v.to_string());
        }
        out.push(Param { name: name.to_string(), value });
        if !params_ok(&out, via) {
            return None;
        }
    }
}

/// Writes header parameters, or `None` if one would not read back.
fn write_gen_params(out: &mut String, params: &[Param], via: bool) -> Option<()> {
    if params.len() > MAX_PARAMS || !params_ok(params, via) {
        return None;
    }
    for p in params {
        if !is_token(&p.name) || p.value.as_deref().is_some_and(|v| !valid_gen_value(&p.name, v, via)) {
            return None;
        }
        out.push(';');
        out.push_str(&p.name);
        if let Some(v) = &p.value {
            out.push('=');
            out.push_str(v);
        }
    }
    Some(())
}

/// Whether no name appears twice in header parameters (RFC 3261 section
/// 7.3.1), and the ones RFC 3261 section 25.1 names follow their grammar:
/// in a Via, `branch`, `ttl`, `maddr`, `received`, and `rport` from RFC
/// 3581; elsewhere, `tag`. A `received` may hold an IPv6 address in
/// brackets too, as many senders write it.
fn params_ok(params: &[Param], via: bool) -> bool {
    params.iter().enumerate().all(|(i, p)| {
        let is = |n: &str| p.name.eq_ignore_ascii_case(n);
        let v = p.value.as_deref();
        let ok = match via {
            true if is("branch") => v.is_some_and(is_token),
            true if is("ttl") => v.is_some_and(|v| v.len() <= 3 && parse_port(v).is_some_and(|n| n <= 255)),
            true if is("maddr") => v.is_some_and(valid_host),
            true if is("received") => {
                v.is_some_and(|v| is_ipv4(v) || is_ipv6(v) || (v.starts_with('[') && valid_host(v)))
            }
            true if is("rport") => v.is_none_or(|v| parse_port(v).is_some()),
            false if is("tag") => v.is_some_and(is_token),
            _ => true,
        };
        ok && !params[..i].iter().any(|q| q.name.eq_ignore_ascii_case(&p.name))
    })
}

/// Whether a Contact address's `q` and `expires` follow RFC 3261 section
/// 25.1: a qvalue from 0 to 1 with up to three decimals, and a number of
/// seconds.
fn contact_params_ok(a: &NameAddr) -> bool {
    a.params.iter().all(|p| {
        let v = p.value.as_deref();
        if p.name.eq_ignore_ascii_case("q") {
            v.is_some_and(is_qvalue)
        } else if p.name.eq_ignore_ascii_case("expires") {
            v.is_some_and(|v| !v.is_empty() && v.bytes().all(|d| d.is_ascii_digit()))
        } else {
            true
        }
    })
}

/// Whether `v` is a qvalue: `0` with up to three decimals, or `1` with up
/// to three zeros after the dot.
fn is_qvalue(v: &str) -> bool {
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    frac.len() <= 3
        && match int {
            "0" => frac.bytes().all(|d| d.is_ascii_digit()),
            "1" => frac.bytes().all(|d| d == b'0'),
            _ => false,
        }
}

/// Whether `v` is the value of the header parameter `name`: a token, an
/// IPv6 reference or a whole quoted string with no control characters.
/// In a Via, `received` may also be an IPv6 address with no brackets.
fn valid_gen_value(name: &str, v: &str, via: bool) -> bool {
    let b = v.as_bytes();
    match b.first() {
        Some(b'"') => quoted_end(b, 0) == Some(b.len()) && valid_field(v),
        Some(b'[') => valid_host(v),
        _ if is_token(v) => true,
        _ => via && name.eq_ignore_ascii_case("received") && is_ipv6(v),
    }
}

/// The index just past the quoted string that starts at `b[i]`, which is
/// `"`. A backslash must escape an ASCII character other than CR or LF.
fn quoted_end(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'"' => return Some(j + 1),
            b'\\' => {
                let next = *b.get(j + 1)?;
                if !next.is_ascii() || next == b'\r' || next == b'\n' {
                    return None;
                }
                j += 2;
            }
            _ => j += 1,
        }
    }
    None
}

/// A quoted string's contents with its escapes taken out. Text that is
/// not quoted comes back as it is.
fn unquote(s: &str) -> String {
    let Some(inner) = s.strip_prefix('"').and_then(|r| r.strip_suffix('"')) else {
        return s.to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for c in inner.chars() {
        if escaped || c != '\\' {
            out.push(c);
            escaped = false;
        } else {
            escaped = true;
        }
    }
    out
}

fn parse_hostport(s: &str) -> Option<(String, Option<u16>)> {
    let (host, rest) = if s.starts_with('[') {
        let end = s.find(']')? + 1;
        (&s[..end], &s[end..])
    } else {
        match s.find(':') {
            Some(i) => (&s[..i], &s[i..]),
            None => (s, ""),
        }
    };
    if !valid_host(host) {
        return None;
    }
    let port = if rest.is_empty() { None } else { Some(parse_port(rest.strip_prefix(':')?)?) };
    Some((host.to_string(), port))
}

fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|d| d.is_ascii_digit()) {
        return None;
    }
    s.bytes().try_fold(0u16, |n, d| n.checked_mul(10)?.checked_add(u16::from(d - b'0')))
}

/// Whether `s` is a host (RFC 3261 section 25.1): a host name, an IPv4
/// address, or an IPv6 address in brackets. A host name is labels of
/// letters, digits and inner `-`, joined by dots, perhaps with a dot at
/// the end. The last label starts with a letter.
fn valid_host(s: &str) -> bool {
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return is_ipv6(inner);
    }
    if is_ipv4(s) {
        return true;
    }
    let name = s.strip_suffix('.').unwrap_or(s);
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        match (b.first(), b.last()) {
            (Some(f), Some(e)) => {
                f.is_ascii_alphanumeric()
                    && e.is_ascii_alphanumeric()
                    && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            }
            _ => false,
        }
    };
    let top_ok = name.rsplit('.').next().is_some_and(|t| t.as_bytes().first().is_some_and(u8::is_ascii_alphabetic));
    name.split('.').all(label_ok) && top_ok
}

/// Whether `s` is an IPv6 address, as RFC 3261 section 25.1 writes it:
/// eight groups of one to four hex digits, or fewer around one `::`. The
/// last two groups may be an IPv4 address instead.
fn is_ipv6(s: &str) -> bool {
    let (sides, gap) = match s.split_once("::") {
        Some((head, tail)) => ([head, tail], true),
        None => ([s, ""], false),
    };
    let mut count = 0usize;
    for (n, side) in sides.iter().enumerate() {
        if side.is_empty() {
            continue;
        }
        let ends_address = if gap { n == 1 } else { n == 0 };
        let mut groups = side.split(':').peekable();
        while let Some(g) = groups.next() {
            if ends_address && groups.peek().is_none() && g.contains('.') {
                if !is_ipv4(g) {
                    return false;
                }
                count += 2;
            } else if (1..=4).contains(&g.len()) && g.bytes().all(|c| c.is_ascii_hexdigit()) {
                count += 1;
            } else {
                return false;
            }
            if count > 8 {
                return false;
            }
        }
    }
    if gap { count <= 7 } else { count == 8 }
}

/// Whether `s` is an IPv4 address: four numbers up to 255, with dots.
fn is_ipv4(s: &str) -> bool {
    let mut parts = 0;
    for p in s.split('.') {
        parts += 1;
        if parts > 4 || !(1..=3).contains(&p.len()) || !p.bytes().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if p.bytes().fold(0u16, |n, d| n * 10 + u16::from(d - b'0')) > 255 {
            return false;
        }
    }
    parts == 4
}

/// Whether `s` is URI text a header or a request line can carry (RFC 3261
/// section 25.1): a SIP or SIPS URI that [`Uri::parse`] reads, or another
/// scheme, a colon, and at least one URI character or `%` escape.
fn valid_uri_text(s: &str) -> bool {
    let b = s.as_bytes();
    let Some(colon) = b.iter().position(|&c| c == b':') else { return false };
    let scheme = &s[..colon];
    if scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips") {
        return Uri::read_value(s).is_ok();
    }
    colon >= 1
        && b[0].is_ascii_alphabetic()
        && b[1..colon].iter().all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.')
        && colon + 1 < b.len()
        && escaped_ok(&s[colon + 1..], is_uri_char)
}

/// Whether `b` may stand in a URI as it is: reserved, unreserved, or a
/// bracket of an IPv6 reference.
fn is_uri_char(b: u8) -> bool {
    is_unreserved(b) || b";/?:@&=+$,[]".contains(&b)
}

/// Whether the sum of `lens` is at most [`MAX_HEAD`]. Writers check the
/// lengths of their parts with it before copying them.
fn fits(lens: impl IntoIterator<Item = usize>) -> bool {
    lens.into_iter().try_fold(0usize, |total, n| total.checked_add(n).filter(|&t| t <= MAX_HEAD)).is_some()
}

/// The bytes of URI text with `%` escapes of unreserved characters taken
/// out and letters in lower case, for comparing names. Escapes of other
/// characters stay, with their hex digits in lower case.
fn uri_name_bytes(s: &str) -> impl Iterator<Item = u8> + '_ {
    let b = s.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        let c = *b.get(i)?;
        if c == b'%'
            && let Some(d) = b.get(i + 1..i + 3).filter(|h| h.iter().all(u8::is_ascii_hexdigit))
            && let Ok(d) = std::str::from_utf8(d)
            && let Ok(d) = u8::from_str_radix(d, 16)
            && is_unreserved(d)
        {
            i += 3;
            return Some(d.to_ascii_lowercase());
        }
        i += 1;
        Some(c.to_ascii_lowercase())
    })
}

/// Whether two URI parameter names are the same name.
fn uri_name_eq(a: &str, b: &str) -> bool {
    uri_name_bytes(a).eq(uri_name_bytes(b))
}

fn valid_uri_param(name: &str, value: Option<&str>) -> bool {
    !name.is_empty()
        && escaped_ok(name, is_param_char)
        && value.is_none_or(|v| !v.is_empty() && escaped_ok(v, is_param_char))
}

fn valid_uri_header(name: &str, value: &str) -> bool {
    !name.is_empty() && escaped_ok(name, is_header_char) && escaped_ok(value, is_header_char)
}

/// Whether every byte of `s` is allowed or is part of a `%` escape with
/// two hex digits.
fn escaped_ok(s: &str, allowed: fn(u8) -> bool) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3).is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
            if !hex {
                return false;
            }
            i += 3;
        } else if allowed(b[i]) {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b)
}

fn is_user_char(b: u8) -> bool {
    is_unreserved(b) || b"&=+$,;?/".contains(&b)
}

fn is_password_char(b: u8) -> bool {
    is_unreserved(b) || b"&=+$,".contains(&b)
}

fn is_param_char(b: u8) -> bool {
    is_unreserved(b) || b"[]/:&+$".contains(&b)
}

fn is_header_char(b: u8) -> bool {
    is_unreserved(b) || b"[]/?:+$".contains(&b)
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&b)
}

/// Whether `s` is a Call-ID word.
fn is_word(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| is_token_byte(b) || b"()<>:\\\"/[]?{}".contains(&b))
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_token_byte)
}

fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Whether `s` may be a reason phrase or a display name: no control
/// characters but tab.
fn valid_value(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// Whether `s` may be a header value: no control characters but tab, but
/// for one escaped by a backslash inside a quoted string. RFC 3261 section
/// 25.1 lets a quoted-pair escape any ASCII character but CR and LF.
fn valid_field(s: &str) -> bool {
    let b = s.as_bytes();
    let (mut i, mut quoted) = (0, false);
    while i < b.len() {
        let c = b[i];
        if quoted && c == b'\\' && b.get(i + 1).is_some_and(|&n| n.is_ascii() && n != b'\r' && n != b'\n') {
            i += 2;
            continue;
        }
        if c == b'"' {
            quoted = !quoted;
        } else if c != b'\t' && (c < 0x20 || c == 0x7f) {
            return false;
        }
        i += 1;
    }
    true
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && is_ws(b[i]) {
        i += 1;
    }
    i
}

fn token_end(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && is_token_byte(b[i]) {
        i += 1;
    }
    i
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
    Uri,
    /// Reads a SIP or SIPS URI. The scheme may be in any case. Other
    /// schemes, such as `tel:`, are [`Error::Uri`], and so is a parameter
    /// name that appears twice (RFC 3261 section 19.1.1). Text over
    /// [`MAX_HEAD`] bytes is [`Error::TooLong`].
    parse,
    /// The URI as text. A part with a character its place does not allow,
    /// an empty user, a password with no user, a parameter name given
    /// twice, or more than [`MAX_PARAMS`] parameters or headers is
    /// [`Error::Uri`]. Text over [`MAX_HEAD`] bytes is [`Error::TooLong`].
    write
);

wire_value!(
    NameAddr,
    /// Reads a name-addr (`Name <uri>;params`) or an addr-spec
    /// (`uri;params`). In the second form, everything after the first `;`
    /// is a header parameter, as RFC 3261 section 20 says. A parameter
    /// name given twice, or a `tag` that is not a token, is
    /// [`Error::Malformed`]. Text over [`MAX_HEAD`] bytes is
    /// [`Error::TooLong`].
    parse,
    /// The address as a header value: the display name quoted, the URI in
    /// angle brackets, then the parameters. In the display name, quotes,
    /// backslashes and control characters other than tab are escaped with
    /// a backslash. A CR or LF in the display name, a URI that does not
    /// follow its grammar, or a bad parameter is [`Error::Malformed`].
    /// Text over [`MAX_HEAD`] bytes is [`Error::TooLong`].
    write
);

wire_value!(
    Contacts,
    /// Reads a Contact header's value: `*` or at least one address, with
    /// no empty items. A value over [`MAX_HEAD`] bytes is
    /// [`Error::TooLong`].
    parse,
    /// The value as a Contact header's value, the addresses separated by
    /// commas. An empty list is [`Error::Malformed`], since it would not
    /// read back; leave the header out instead. So is a bad address, or a
    /// `q` or `expires` that does not follow its grammar. More than
    /// [`MAX_VALUES`] addresses is [`Error::TooMany`], and text over
    /// [`MAX_HEAD`] bytes is [`Error::TooLong`].
    write
);

wire_value!(
    Via,
    /// Reads one Via value. Spaces around the slashes and around the colon
    /// before the port are allowed, as RFC 3261 allows them. A parameter
    /// name given twice, or a `branch`, `ttl`, `maddr`, `received` or
    /// `rport` that does not follow its grammar, is [`Error::Malformed`].
    /// Text over [`MAX_HEAD`] bytes is [`Error::TooLong`].
    parse,
    /// The value as text. A transport that is not a token, a bad host or
    /// a bad parameter is [`Error::Malformed`]. Text over [`MAX_HEAD`]
    /// bytes is [`Error::TooLong`].
    write
);

wire_value!(
    CSeq,
    /// Reads a CSeq value. Refuses sequence numbers of 2^31 or more;
    /// [`Message::cseq`] can inspect any 32-bit received number.
    /// Text over [`MAX_HEAD`] bytes is [`Error::TooLong`].
    parse,
    /// The value as text. A method that is not a token, or a sequence
    /// number of 2^31 or more, is [`Error::Malformed`]. Text over
    /// [`MAX_HEAD`] bytes is [`Error::TooLong`].
    write
);

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{CSeq, Contacts, Error, Message, NameAddr};
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::test_support::contract;

    /// Checks parsed values and their public accessors.
    pub fn round_trip(message: &Message) {
        contract::check_wire_value(message);
        if let Err(error) = message.to_bytes() {
            assert!(matches!(error, Error::TooLong | Error::TooMany), "{error:?} for {message:?}");
            return;
        }
        if let Ok(vias) = message.vias() {
            for value in vias {
                contract::check_wire_value(&value);
                value.to_bytes().unwrap();
            }
        }
        for read in [Message::from, Message::to] {
            if let Ok(value) = read(message) {
                contract::check_wire_value(&value);
                value.to_bytes().unwrap();
            }
        }
        if let Ok(value) = message.cseq() {
            cseq_round_trip(&value);
        }
        if let Ok(value) = message.contacts() {
            contract::check_wire_value(&value);
            if let Err(error) = value.to_bytes() {
                assert_eq!(value, Contacts::List(vec![]), "{error:?}");
            }
        }
        if let Some(uri) = message.request_uri()
            && let Ok(value) = NameAddr::new(uri).sip_uri()
        {
            contract::check_wire_value(&value);
            value.to_bytes().unwrap();
            for param in &value.params {
                assert!(value.param(&param.name).is_some());
            }
        }
        if message.method().is_some() {
            let mut reply = message.reply(100, "Trying");
            reply.set_header("Content-Length", "0");
            contract::check_wire_value(&reply);
            assert!(matches!(reply.to_bytes(), Ok(_) | Err(Error::TooLong | Error::TooMany)));
        }
    }

    /// Checks parsed values and their public accessors.
    pub fn cseq_round_trip(value: &CSeq) {
        contract::check_wire_value(value);
        if let Err(error) = value.to_bytes() {
            assert!(value.seq >= 1 << 31, "{error:?} for {value:?}");
        }
    }

    /// Checks a value read directly from text.
    pub fn text_value<T: Wire<ParseError = Error, WriteError = Error> + PartialEq + core::fmt::Debug>(value: Result<T, Error>) {
        if let Ok(value) = value {
            contract::check_wire_value(&value);
            assert!(matches!(value.to_bytes(), Ok(_) | Err(Error::TooLong)), "{value:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use super::harness::{round_trip, cseq_round_trip, text_value};
    #[test]
    fn unexpected_line_error_is_malformed_head() {
        assert_eq!(super::framing_error(super::LineError::Unterminated), super::Error::LineEnding);
        assert_eq!(super::framing_error(super::LineError::BareLf), super::Error::LineEnding);
    }

    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::codec::{
        Lcg,
    };
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn wire_text<T: Wire<WriteError = Error>>(value: &T) -> Result<String, Error> {
        String::from_utf8(value.to_bytes()?).map_err(|_| Error::Utf8)
    }

    /// The INVITE from RFC 3261 section 4, with a short SDP body.
    fn invite() -> Vec<u8> {
        let body = "v=0\r\no=alice 2890844526 2890844526 IN IP4 pc33.atlanta.com\r\n";
        format!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
             Max-Forwards: 70\r\n\
             To: Bob <sip:bob@biloxi.com>\r\n\
             From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
             Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
             CSeq: 314159 INVITE\r\n\
             Contact: <sip:alice@pc33.atlanta.com>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// The 200 OK from RFC 3261 section 4 (message F9 of section 24), with
    /// no body.
    fn ok() -> Vec<u8> {
        b"SIP/2.0 200 OK\r\n\
          Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bKnashds8;received=192.0.2.3\r\n\
          Via: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1;received=192.0.2.2\r\n\
          Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds ;received=192.0.2.1\r\n\
          To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
          From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
          Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
          CSeq: 314159 INVITE\r\n\
          Contact: <sip:bob@192.0.2.4>\r\n\
          Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    /// A message using compact names, folding, a Via with spaces, a
    /// Contact list and a quoted display name.
    fn compact() -> Vec<u8> {
        b"REGISTER sips:ss2.biloxi.example.com SIP/2.0\r\n\
          v: SIP / 2.0 / TLS first.example.com: 4000;ttl=16;maddr=224.2.1.1 ;branch=z9hG4bKa7c6a8dlze.1\r\n\
          v: SIP/2.0/UDP [2001:db8::9]:5070;rport;received=[2001:db8::1], SIP/2.0/TCP 192.0.2.1\r\n\
          f: \"A. G. \\\"Bell\\\"\" <sip:agb@bell-telephone.com> ;tag=a48s\r\n\
          t: sip:+12125551212@server.phone2net.com;tag=887s\r\n\
          i: f81d4fae-7dec-11d0-a765-00a0c91e6bf6@192.0.2.4\r\n\
          CSeq: 4711 REGISTER\r\n\
          m: \"Mr. Watson\" <sip:watson@worcester.bell-telephone.com>;q=0.7; expires=3600,\r\n\
          \t\"Mr. Watson\" <mailto:watson@bell-telephone.com> ;q=0.1\r\n\
          Subject: I know you're there,\r\n         pick up the phone\r\n         and talk to me!\r\n\
          l: 4\r\n\r\nbody"
            .to_vec()
    }

    #[test]
    fn rfc_3261_invite() {
        let m = Message::parse(&invite()).unwrap();
        assert_eq!(m.method(), Some("INVITE"));
        assert_eq!(m.request_uri(), Some("sip:bob@biloxi.com"));
        assert_eq!(m.status(), None);
        let vias = m.vias().unwrap();
        assert_eq!(vias.len(), 1);
        assert_eq!(vias[0].transport, "UDP");
        assert_eq!(vias[0].host, "pc33.atlanta.com");
        assert_eq!(vias[0].port, None);
        assert_eq!(vias[0].branch(), Some("z9hG4bK776asdhds"));
        let from = m.from().unwrap();
        assert_eq!(from.display.as_deref(), Some("Alice"));
        assert_eq!(from.uri, "sip:alice@atlanta.com");
        assert_eq!(from.tag(), Some("1928301774"));
        let to = m.to().unwrap();
        assert_eq!(to.tag(), None);
        assert_eq!(to.sip_uri().unwrap().user.as_deref(), Some("bob"));
        assert_eq!(m.call_id(), Ok("a84b4c76e66710@pc33.atlanta.com"));
        assert_eq!(m.cseq().unwrap(), CSeq { seq: 314159, method: "INVITE".into() });
        let Contacts::List(c) = m.contacts().unwrap() else { panic!() };
        assert_eq!(c, [NameAddr::new("sip:alice@pc33.atlanta.com")]);
        assert_eq!(m.header("max-forwards"), Some("70"));
        assert_eq!(m.content_length(), Ok(Some(m.body.len())));
        assert!(m.body.starts_with(b"v=0\r\n"));
        // It writes back to the same bytes.
        assert_eq!(m.to_bytes().unwrap(), invite());
    }

    #[test]
    fn rfc_3261_response() {
        let m = Message::parse(&ok()).unwrap();
        assert_eq!(m.status(), Some(200));
        assert_eq!(m.start, StartLine::Status { code: 200, reason: "OK".into() });
        let vias = m.vias().unwrap();
        assert_eq!(vias.len(), 3);
        assert_eq!(vias[2].param("received").unwrap().value.as_deref(), Some("192.0.2.1"));
        assert_eq!(vias[1].branch(), Some("z9hG4bK77ef4c2312983.1"));
        assert_eq!(m.to().unwrap().tag(), Some("a6c85cf"));
        assert_eq!(m.to_bytes().unwrap(), ok());
        assert!(m.body.is_empty());
    }

    #[test]
    fn compact_forms_folding_and_lists() {
        let m = Message::parse(&compact()).unwrap();
        assert_eq!(m.header("Subject"), Some("I know you're there, pick up the phone and talk to me!"));
        assert_eq!(m.header("Via"), m.header("v"));
        let vias = m.vias().unwrap();
        assert_eq!(vias.len(), 3);
        assert_eq!(vias[0].transport, "TLS");
        assert_eq!((vias[0].host.as_str(), vias[0].port), ("first.example.com", Some(4000)));
        assert_eq!(vias[0].param("maddr").unwrap().value.as_deref(), Some("224.2.1.1"));
        assert_eq!(vias[1].host, "[2001:db8::9]");
        assert_eq!(vias[1].port, Some(5070));
        assert_eq!(vias[1].param("rport"), Some(&Param::new("rport", None)));
        assert_eq!(vias[1].param("received").unwrap().value.as_deref(), Some("[2001:db8::1]"));
        assert_eq!((vias[2].transport.as_str(), vias[2].host.as_str()), ("TCP", "192.0.2.1"));
        let from = m.from().unwrap();
        assert_eq!(from.display.as_deref(), Some("A. G. \"Bell\""));
        assert_eq!(from.tag(), Some("a48s"));
        // An addr-spec: the parameter belongs to the header, not the URI.
        let to = m.to().unwrap();
        assert_eq!(to.uri, "sip:+12125551212@server.phone2net.com");
        assert_eq!(to.tag(), Some("887s"));
        assert_eq!(m.call_id(), Ok("f81d4fae-7dec-11d0-a765-00a0c91e6bf6@192.0.2.4"));
        let Contacts::List(c) = m.contacts().unwrap() else { panic!() };
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].param("q").unwrap().value.as_deref(), Some("0.7"));
        assert_eq!(c[0].param("expires").unwrap().value.as_deref(), Some("3600"));
        assert_eq!(c[1].uri, "mailto:watson@bell-telephone.com");
        assert!(c[1].sip_uri().is_err());
        assert_eq!(m.body, b"body");
        // Written and read again, the values stay the same.
        let again = Message::parse(&m.to_bytes().unwrap()).unwrap();
        assert_eq!(again.vias(), m.vias());
        assert_eq!(again.from(), m.from());
        assert_eq!(again.contacts(), m.contacts());
        assert_eq!(again.header("Subject"), m.header("Subject"));
        assert_eq!(again.body, m.body);
    }

    #[test]
    fn several_headers_are_one_list() {
        // RFC 3261 section 7.3.1.
        let a = b"BYE sip:x@y SIP/2.0\r\nRoute: <sip:alice@atlanta.com>\r\nSubject: Lunch\r\n\
                  Route: <sip:bob@biloxi.com>\r\nRoute: <sip:carol@chicago.com>\r\nl: 0\r\n\r\n";
        let b = b"BYE sip:x@y SIP/2.0\r\nRoute: <sip:alice@atlanta.com>, <sip:bob@biloxi.com>,\r\n \
                  <sip:carol@chicago.com>\r\nSubject: Lunch\r\nl: 0\r\n\r\n";
        let (a, b) = (Message::parse(a).unwrap(), Message::parse(b).unwrap());
        assert_eq!(a.values("route").unwrap(), b.values("Route").unwrap());
        assert_eq!(a.values("Route").unwrap().len(), 3);
        // Commas in quotes and brackets do not split.
        let mut m = Message::request("INVITE", "sip:a@b");
        m.push_header("Contact", "\"Doe, John\" <sip:j@d;x=1,2>, <sip:k@e>");
        assert_eq!(m.values("m").unwrap(), ["\"Doe, John\" <sip:j@d;x=1,2>", "<sip:k@e>"]);
    }

    #[test]
    fn uris_from_rfc_3261() {
        // Section 19.1.3. Each reads, and writes back as written.
        for text in [
            "sip:alice@atlanta.com",
            "sip:alice:secretword@atlanta.com;transport=tcp",
            "sips:alice@atlanta.com?subject=project%20x&priority=urgent",
            "sip:+1-212-555-1212:1234@gateway.com;user=phone",
            "sips:1212@gateway.com",
            "sip:alice@192.0.2.4",
            "sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com",
            "sip:alice;day=tuesday@atlanta.com",
            "sip:[2001:db8::10]:5070;lr",
            "sip:biloxi.com:5060;maddr=239.255.255.1;ttl=15",
        ] {
            let uri = Uri::parse(text.as_bytes()).unwrap();
            assert_eq!(wire_text(&uri).unwrap(), text);
        }
        let u =
            Uri::parse("SIP:alice:secretword@atlanta.com:5061;transport=tcp;lr?h=1&i=".as_bytes()).unwrap();
        assert_eq!(u.scheme, Scheme::Sip);
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.password.as_deref(), Some("secretword"));
        assert_eq!((u.host.as_str(), u.port), ("atlanta.com", Some(5061)));
        assert_eq!(u.param("TRANSPORT").unwrap().value.as_deref(), Some("tcp"));
        assert_eq!(u.param("lr").unwrap().value, None);
        assert_eq!(u.headers, [("h".to_string(), "1".to_string()), ("i".to_string(), String::new())]);
        let u = Uri::parse("sip:alice;day=tuesday@atlanta.com".as_bytes()).unwrap();
        assert_eq!(u.user.as_deref(), Some("alice;day=tuesday"));
        assert!(u.params.is_empty());
    }

    #[test]
    fn bad_uris() {
        for text in [
            "",
            "sip",
            "tel:+1-201-555-0123",
            "sip:",
            "sip:@host",
            "sip:a b@host",
            "sip:alice@",
            "sip:alice@host:",
            "sip:alice@host:65536",
            "sip:alice@host:5x",
            "sip:alice@ho_st",
            "sip:host;",
            "sip:host;a=",
            "sip:host;a=b=c",
            "sip:host?x",
            "sip:host?=1",
            "sip:%zz@host",
            "sip:a%2@host",
            "sip:[::1",
            "sip:[]",
            "sip:[1.2.3.4]",
            "sip:a:p@ss@host",
        ] {
            assert_eq!(Uri::parse(text.as_bytes()), Err(Error::Uri), "{text:?}");
        }
        let params = |n: usize| (0..n).map(|i| format!(";p{i}")).collect::<String>();
        assert_eq!(Uri::parse(format!("sip:h{}", params(MAX_PARAMS + 1)).as_bytes()), Err(Error::Uri));
        assert!(Uri::parse(format!("sip:h{}", params(MAX_PARAMS)).as_bytes()).is_ok());
        // Writers refuse what would not read back.
        let mut u = Uri::new(Scheme::Sip, "atlanta.com");
        u.password = Some("x".into());
        assert_eq!(wire_text(&u), Err(Error::Uri));
        u.user = Some(String::new());
        assert_eq!(wire_text(&u), Err(Error::Uri));
        u.user = Some("al ice".into());
        assert_eq!(wire_text(&u), Err(Error::Uri));
        u.user = Some("alice".into());
        assert_eq!(wire_text(&u).unwrap(), "sip:alice:x@atlanta.com");
        u.params.push(Param::new("a", Some("")));
        assert_eq!(wire_text(&u), Err(Error::Uri));
        u.params = vec![];
        u.headers.push((String::new(), "x".into()));
        assert_eq!(wire_text(&u), Err(Error::Uri));
        assert_eq!(wire_text(&Uri::new(Scheme::Sips, "::1")), Err(Error::Uri));
        assert_eq!(wire_text(&Uri::new(Scheme::Sips, "[::1]")).unwrap(), "sips:[::1]");
    }

    #[test]
    fn name_addrs() {
        let a = NameAddr::parse("The Operator <sip:operator@cs.columbia.edu>;tag=287447".as_bytes()).unwrap();
        assert_eq!(a.display.as_deref(), Some("The Operator"));
        assert_eq!(a.tag(), Some("287447"));
        assert_eq!(wire_text(&a).unwrap(), "\"The Operator\" <sip:operator@cs.columbia.edu>;tag=287447");
        let b = NameAddr::parse("  <sip:x@y>  ".as_bytes()).unwrap();
        assert_eq!(b, NameAddr::new("sip:x@y"));
        let c = NameAddr::parse("\"\" <sip:x@y>;foo=\"a \\\"b\\\"\"".as_bytes()).unwrap();
        assert_eq!(c.display, None);
        assert_eq!(c.param("foo").unwrap().unquoted().as_deref(), Some("a \"b\""));
        assert_eq!(NameAddr::parse(wire_text(&c).unwrap().as_bytes()).unwrap(), c);
        for bad in [
            "",
            "<sip:x@y",
            "\"Bob <sip:x@y>",
            "Bob \"x\" <sip:x@y>",
            "\"Bob\" sip:x@y",
            "<nocolon>",
            "<:x>",
            "<1sip:x>",
            "<sip:a b>",
            "<sip:x@y>;",
            "<sip:x@y>;=1",
            "<sip:x@y>;a=",
            "<sip:x@y>;a=\"x",
            "<sip:x@y> junk",
            "<sip:x@y>;a=[::1",
            "\"a\\\r\" <sip:x@y>",
            "\u{1} <sip:x@y>",
        ] {
            assert_eq!(NameAddr::parse(bad.as_bytes()), Err(Error::Malformed("address")), "{bad:?}");
        }
        let mut d = NameAddr::new("sip:x@y");
        d.display = Some("a\nb".into());
        assert!(wire_text(&d).is_err());
        d.display = Some("\\ and \"".into());
        assert_eq!(NameAddr::parse(wire_text(&d).unwrap().as_bytes()).unwrap(), d);
        d.params.push(Param::new("x y", None));
        assert!(wire_text(&d).is_err());
        d.params = vec![Param::new("q", Some("\"unclosed"))];
        assert!(wire_text(&d).is_err());
        assert!(wire_text(&NameAddr::new("no scheme")).is_err());
    }

    #[test]
    fn contacts() {
        assert_eq!(Contacts::parse("*".as_bytes()), Ok(Contacts::All));
        assert_eq!(wire_text(&Contacts::All).unwrap(), "*");
        assert_eq!(Contacts::parse("*, <sip:a@b>".as_bytes()), Err(Error::Malformed("Contact")));
        // RFC 3261 section 25.1: a Contact holds `*` or at least one address.
        assert_eq!(Contacts::parse("".as_bytes()), Err(Error::Malformed("Contact")));
        assert_eq!(Contacts::parse(" , ".as_bytes()), Err(Error::Malformed("Contact")));
        assert_eq!(wire_text(&Contacts::List(vec![])), Err(Error::Malformed("Contact")));
        let m = Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nm: <sip:a@b>\r\nContact:\r\nl: 0\r\n\r\n").unwrap();
        assert_eq!(m.contacts(), Err(Error::Malformed("Contact")));
        assert_eq!(Contacts::parse("<sip:a@b>, junk junk".as_bytes()), Err(Error::Malformed("Contact")));
        assert_eq!(Contacts::parse("<sip:a@b".as_bytes()), Err(Error::Malformed("Contact")));
        let list = Contacts::parse("<sip:a@b>;expires=60, \"C\" <sip:c@d>".as_bytes()).unwrap();
        assert_eq!(Contacts::parse(wire_text(&list).unwrap().as_bytes()).unwrap(), list);
        let many = vec!["<sip:a@b>"; MAX_VALUES + 1].join(",");
        assert_eq!(Contacts::parse(many.as_bytes()), Err(Error::TooMany));
        let long = Contacts::List(vec![NameAddr::new("sip:a@b"); MAX_VALUES + 1]);
        assert_eq!(wire_text(&long), Err(Error::TooMany));
        let m = Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nl: 0\r\n\r\n").unwrap();
        assert_eq!(m.contacts(), Ok(Contacts::List(vec![])));
    }

    #[test]
    fn vias_and_cseqs() {
        let v =
            Via::parse("SIP/2.0/UDP 192.0.2.1:5060 ;received=192.0.2.207;branch=z9hG4bK77asjd".as_bytes())
                .unwrap();
        assert_eq!(
            wire_text(&v).unwrap(),
            "SIP/2.0/UDP 192.0.2.1:5060;received=192.0.2.207;branch=z9hG4bK77asjd"
        );
        assert_eq!(v.branch(), Some("z9hG4bK77asjd"));
        for bad in [
            "",
            "SIP/2.0/UDP",
            "SIP/2.0/UDP ",
            "SIP/3.0/UDP host",
            "HTTP/2.0/UDP host",
            "SIP/2.0 host",
            "SIP/2.0/UDPhost",
            "SIP/2.0/UDP host:",
            "SIP/2.0/UDP host:99999",
            "SIP/2.0/UDP host;",
            "SIP/2.0/UDP host junk",
            "SIP/2.0/UDP [::1",
            "SIP/2.0/UDP _bad",
            "SIP/2.0/UDP host;branch=\u{1}",
        ] {
            assert_eq!(Via::parse(bad.as_bytes()), Err(Error::Malformed("Via")), "{bad:?}");
        }
        let mut w = Via { transport: "U P".into(), host: "h".into(), port: None, params: vec![] };
        assert!(wire_text(&w).is_err());
        w.transport = "UDP".into();
        w.host = "a b".into();
        assert!(wire_text(&w).is_err());
        w.host = "h".into();
        w.params.push(Param::new("received", Some("[::1]")));
        assert_eq!(Via::parse(wire_text(&w).unwrap().as_bytes()).unwrap(), w);

        assert_eq!(
            CSeq::parse("4711 INVITE".as_bytes()).unwrap(),
            CSeq { seq: 4711, method: "INVITE".into() }
        );
        assert_eq!(CSeq::parse(b" 4294967295\t ACK "), Err(Error::Malformed("CSeq")));
        for bad in ["", "INVITE", "1", "1 ", "x INVITE", "4294967296 INVITE", "1 IN VITE", "-1 ACK", "1 A@B"] {
            assert_eq!(CSeq::parse(bad.as_bytes()), Err(Error::Malformed("CSeq")), "{bad:?}");
        }
        assert!(wire_text(&CSeq { seq: 1, method: "A B".into() }).is_err());
        assert_eq!(wire_text(&CSeq { seq: 7, method: "BYE".into() }).unwrap(), "7 BYE");
    }

    #[test]
    fn cseq_reader_accepts_lws_and_checks_overflow() {
        let mut message = Message::request("ACK", "sip:a@b");
        // The received number may use all 32 bits. The writer limit is lower.
        message.push_header("CSeq", " 4294967295\t ACK ");
        assert_eq!(message.cseq(), Ok(CSeq { seq: u32::MAX, method: "ACK".into() }));
        message.set_header("CSeq", "4294967296 INVITE");
        assert_eq!(message.cseq(), Err(Error::Malformed("CSeq")));
    }

    #[test]
    fn header_values_append_only_after_a_valid_write() {
        let mut message = Message::request("INVITE", "sip:a@b");
        let cseq = CSeq { seq: 1, method: "INVITE".into() };
        message.push_value("CSeq", &cseq).unwrap();
        assert_eq!(message.cseq(), Ok(cseq));
        let before = message.clone();
        let invalid = CSeq { seq: 1 << 31, method: "INVITE".into() };
        assert_eq!(message.push_value("CSeq", &invalid), Err(Error::Malformed("CSeq")));
        assert_eq!(message, before);
        let mut binary = Message::response(200, "OK");
        binary.body = vec![0xff];
        binary.push_header("Content-Length", "1");
        assert_eq!(message.push_value("X", &binary), Err(Error::Utf8));
        assert_eq!(message, before);
    }

    #[test]
    fn via_received_holds_a_bare_ipv6_address() {
        // RFC 3261 section 25.1: via-received = "received" EQUAL
        // (IPv4address / IPv6address). The example is from RFC 5118 section 4.5.
        let text = "SIP/2.0/UDP [2001:db8::9:1];received=2001:db8::9:255;branch=z9hG4bKas3-111";
        let v = Via::parse(text.as_bytes()).unwrap();
        assert_eq!(v.param("received").unwrap().value.as_deref(), Some("2001:db8::9:255"));
        assert_eq!(wire_text(&v).unwrap(), text);
        // Only in a Via, and only for received.
        assert!(Via::parse("SIP/2.0/UDP h;maddr=2001:db8::1".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;received=2001:zz::1".as_bytes()).is_err());
        assert!(NameAddr::parse("<sip:a@b>;received=2001:db8::1".as_bytes()).is_err());
        let mut a = NameAddr::new("sip:a@b");
        a.params.push(Param::new("received", Some("2001:db8::1")));
        assert!(wire_text(&a).is_err());
    }

    #[test]
    fn call_id_follows_its_grammar() {
        // RFC 3261 section 25.1: callid = word [ "@" word ].
        let read = |id: &str| {
            let m = Message::parse(format!("OPTIONS sip:a@b SIP/2.0\r\ni: {id}\r\nl: 0\r\n\r\n").as_bytes()).unwrap();
            m.call_id().map(str::to_string)
        };
        for good in ["a84b4c76e66710", "f81d4fae-7dec@192.0.2.4", "x(y)<z>:\\\"/[]?{}@[::1]"] {
            assert_eq!(read(good).as_deref(), Ok(good), "{good:?}");
        }
        for bad in ["a,b", "a;b", "a=b", "a@b@c", "x@", "@x", "a#b", "a b"] {
            assert_eq!(read(bad), Err(Error::Malformed("Call-ID")), "{bad:?}");
        }
    }

    #[test]
    fn version_error_needs_a_well_formed_version() {
        // A malformed line is a 400, not a 505.
        let e = |b: &[u8]| Message::parse(b).unwrap_err();
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0 \r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"SIP/2.0x 200 OK\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"SIP/ 200 OK\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"OPTIONS sip:a@b sip/3.10\r\nl: 0\r\n\r\n"), Error::Version);
        assert_eq!(e(b"SIP/1.0 200 OK\r\nl: 0\r\n\r\n"), Error::Version);
    }

    #[test]
    fn ipv6_addresses_follow_their_grammar() {
        // RFC 3261 section 25.1, after RFC 2373.
        for good in [
            "::",
            "::1",
            "2001:db8::9",
            "1:2:3:4:5:6:7:8",
            "1::8",
            "1:2:3:4:5:6:7::",
            "::ffff:192.0.2.1",
            "1:2:3:4:5:6:192.0.2.1",
            "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210",
        ] {
            assert!(Uri::parse(format!("sip:[{good}]").as_bytes()).is_ok(), "{good:?}");
            assert!(Via::parse(format!("SIP/2.0/UDP h;received={good}").as_bytes()).is_ok(), "{good:?}");
        }
        for bad in [
            "",
            ":",
            ":::",
            "::::",
            "1:2",
            "1:2:3:4:5:6:7:8:9",
            "1:2:3:4:5:6:7::8",
            "1::2::3",
            ":1::",
            "1::2:",
            "12345::",
            "::1.2.3",
            "::1.2.3.256",
            "::1.2.3.4:1",
            "1.2.3.4::",
            "1.2.3.4:5060",
            "1:2:3:4:5:6:7:1.2.3.4",
        ] {
            assert_eq!(Uri::parse(format!("sip:[{bad}]").as_bytes()), Err(Error::Uri), "{bad:?}");
            assert!(Via::parse(format!("SIP/2.0/UDP [{bad}]").as_bytes()).is_err(), "{bad:?}");
            assert!(Via::parse(format!("SIP/2.0/UDP h;received={bad}").as_bytes()).is_err(), "{bad:?}");
            assert!(wire_text(&Uri::new(Scheme::Sip, &format!("[{bad}]"))).is_err(), "{bad:?}");
            let mut v = Via::new("UDP", "h");
            v.params.push(Param::new("received", Some(bad)));
            assert!(wire_text(&v).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn version_error_needs_an_otherwise_good_line() {
        // A server answers Version with 505, so it must not hide a 400.
        let e = |b: &[u8]| Message::parse(b).unwrap_err();
        assert_eq!(e(b"OPT@ONS sip:a@b SIP/3.0\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"OPTIONS nocolon SIP/3.0\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"SIP/3.0 2x0 OK\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"SIP/3.0\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(e(b"SIP/3.0 200 OK\r\nl: 0\r\n\r\n"), Error::Version);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/3.0\r\nl: 0\r\n\r\n"), Error::Version);
    }

    #[test]
    fn accessors_for_world_code() {
        let m = Message::parse(&ok()).unwrap();
        assert_eq!(m.reason(), Some("OK"));
        assert_eq!(Message::parse(&invite()).unwrap().reason(), None);
        let mut v = Via::new("TCP", "[2001:db8::1]");
        v.port = Some(5060);
        v.params.push(Param::new("branch", Some("z9hG4bK1")));
        assert_eq!(wire_text(&v).unwrap(), "SIP/2.0/TCP [2001:db8::1]:5060;branch=z9hG4bK1");
        assert_eq!(Via::parse(wire_text(&v).unwrap().as_bytes()).unwrap(), v);
    }

    #[test]
    fn header_reads_fail_cleanly() {
        let m = Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nl: 0\r\n\r\n").unwrap();
        assert_eq!(m.from(), Err(Error::Missing("From")));
        assert_eq!(m.to(), Err(Error::Missing("To")));
        assert_eq!(m.call_id(), Err(Error::Missing("Call-ID")));
        assert_eq!(m.cseq(), Err(Error::Missing("CSeq")));
        assert_eq!(m.vias(), Ok(vec![]));
        let m = Message::parse(
            b"OPTIONS sip:a@b SIP/2.0\r\nFrom: <sip:a@b>\r\nf: <sip:c@d>\r\nTo: x\r\nCall-ID: a b\r\n\
              CSeq: x\r\nVia: SIP/2.0/UDP h, junk\r\nContact: <sip:a\r\nX: \"\r\nl: 0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(m.from(), Err(Error::Malformed("From")));
        assert_eq!(m.to(), Err(Error::Malformed("To")));
        assert_eq!(m.call_id(), Err(Error::Malformed("Call-ID")));
        assert_eq!(m.cseq(), Err(Error::Malformed("CSeq")));
        assert_eq!(m.vias(), Err(Error::Malformed("Via")));
        assert_eq!(m.contacts(), Err(Error::Malformed("Contact")));
        assert_eq!(m.values("X"), Err(Error::Malformed("comma-separated value")));
        assert_eq!(m.values("absent"), Ok(vec![]));
    }

    #[test]
    fn datagram_framing() {
        // RFC 3261 section 18.3: bytes past a declared body are dropped.
        let bytes = b"OPTIONS sip:a@b SIP/2.0\r\nContent-Length: 01\r\n\r\nab";
        let message = Message::read_datagram(bytes).unwrap();
        assert_eq!(message.body, b"a");
        assert_eq!(message.header("Content-Length"), Some("01"));
        round_trip(&message);
        // Without Content-Length, every body prefix is a complete datagram.
        let head = b"OPTIONS sip:a@b SIP/2.0\r\nX: a\r\n b\r\n\r\n";
        let body = b"\0\xff\r\nSIP/2.0";
        let bytes = [head.as_slice(), body].concat();
        for n in 0..=body.len() {
            let mut message = Message::read_datagram(&bytes[..head.len() + n]).unwrap();
            assert_eq!(message.body, body[..n]);
            assert_eq!(message.header("X"), Some("a b"));
            assert_eq!(message.content_length(), Ok(None));
            message.push_header("Content-Length", &n.to_string());
            round_trip(&message);
        }
        assert_eq!(
            Message::read_datagram(b"OPTIONS sip:a@b SIP/2.0\r\nl: 3\r\n\r\nab"),
            Err(Error::Incomplete)
        );
        assert_eq!(
            Message::read_datagram(b"OPTIONS sip:a@b SIP/2.0\r\nl: 0\r\nContent-Length: 0\r\n\r\n"),
            Err(Error::ContentLength)
        );
        assert_eq!(Message::read_datagram(b"OPTIONS sip:a@b SIP/2.0\n\n"), Err(Error::LineEnding));
    }

    #[test]
    fn message_errors() {
        let e = |b: &[u8]| Message::parse(b).unwrap_err();
        assert_eq!(e(b""), Error::Incomplete);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\n"), Error::Incomplete);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nl: 5\r\n\r\nabc"), Error::Incomplete);
        assert_eq!(e(&vec![b'a'; MAX_HEAD]), Error::TooLong);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nl: 1048577\r\n\r\n"), Error::TooLong);
        let mut big = format!("OPTIONS sip:a@b SIP/2.0\r\nl: {}\r\n\r\n", MAX_BODY + 1).into_bytes();
        big.resize(big.len() + MAX_BODY + 1, 0);
        assert_eq!(e(&big), Error::TooLong);
        let many = format!("OPTIONS sip:a@b SIP/2.0\r\nl: 0\r\n{}\r\n", "X: 1\r\n".repeat(MAX_HEADERS));
        assert_eq!(e(many.as_bytes()), Error::TooMany);
        let enough = format!("OPTIONS sip:a@b SIP/2.0\r\nl: 0\r\n{}\r\n", "X: 1\r\n".repeat(MAX_HEADERS - 1));
        assert!(Message::parse(enough.as_bytes()).is_ok());
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\nX: 1\r\nl: 0\r\n\r\n"), Error::LineEnding);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nX: 1\r2\r\nl: 0\r\n\r\n"), Error::LineEnding);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\n\r\r\nl: 0\r\n\r\n"), Error::LineEnding);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nX: \xff\r\nl: 0\r\n\r\n"), Error::Utf8);
        // The stream skips an empty keep-alive line, then needs a start line.
        assert_eq!(e(b"\r\nl: 0\r\n\r\n"), Error::MissingContentLength);
        assert_eq!(e(b"\r\nX: 1\r\nl: 0\r\n\r\n"), Error::StartLine);
        assert_eq!(Message::read_datagram(b"\r\nl: 0\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(Message::read_datagram(b"\r\nX: 1\r\n\r\n"), Err(Error::StartLine));
        for line in [
            " ",
            "OPTIONS",
            "OPTIONS sip:a@b",
            "OPTIONS  sip:a@b SIP/2.0",
            "OPTIONS sip:a@b HTTP/1.1",
            "OPT@ONS sip:a@b SIP/2.0",
            "OPTIONS nocolon SIP/2.0",
            "OPTIONS sip:a<b SIP/2.0",
            "SIP/2.0",
            "SIP/2.0 20 OK",
            "SIP/2.0 2000 OK",
            "SIP/2.0 099 Low",
            "SIP/2.0 700 High",
            "SIP/2.0 2x0 OK",
            "SIP/2.0 200 O\u{1}K",
        ] {
            let msg = format!("{line}\r\nl: 0\r\n\r\n");
            assert_eq!(e(msg.as_bytes()), Error::StartLine, "{line:?}");
        }
        assert_eq!(e(b"SIP/3.0 200 OK\r\nl: 0\r\n\r\n"), Error::Version);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/1.0\r\nl: 0\r\n\r\n"), Error::Version);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\n folded\r\nl: 0\r\n\r\n"), Error::HeaderLine);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nNo colon\r\nl: 0\r\n\r\n"), Error::HeaderLine);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nBad Name: 1\r\nl: 0\r\n\r\n"), Error::HeaderLine);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\n: 1\r\nl: 0\r\n\r\n"), Error::HeaderLine);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nX: a\x00b\r\nl: 0\r\n\r\n"), Error::HeaderValue);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nl: x\r\n\r\n"), Error::ContentLength);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nl: \r\n\r\n"), Error::ContentLength);
        assert_eq!(e(b"OPTIONS sip:a@b SIP/2.0\r\nl: 1\r\nContent-Length: 2\r\n\r\nab"), Error::ContentLength);
        // Exact stream messages refuse bytes past the body.
        assert_eq!(
            Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nContent-Length: 01\r\n\r\nab"),
            Err(Error::Trailing)
        );
        // Lenient bits: status line with no reason, spaces before the colon.
        let m = Message::parse(b"sip/2.0 404\r\nX-A \t: v\r\nl: 0\r\n\r\n").unwrap();
        assert_eq!(m.start, StartLine::Status { code: 404, reason: String::new() });
        assert_eq!(m.header("x-a"), Some("v"));
        assert_eq!(Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\n\r\n"), Err(Error::MissingContentLength));
    }

    #[test]
    fn writer_errors() {
        let w = |m: &Message| m.to_bytes().unwrap_err();
        assert_eq!(w(&Message::request("BAD METHOD", "sip:a@b")), Error::StartLine);
        assert_eq!(w(&Message::request("", "sip:a@b")), Error::StartLine);
        assert_eq!(w(&Message::request("INVITE", "sip:a b")), Error::StartLine);
        assert_eq!(w(&Message::request("INVITE", "nocolon")), Error::StartLine);
        assert_eq!(w(&Message::response(99, "x")), Error::StartLine);
        assert_eq!(w(&Message::response(700, "x")), Error::StartLine);
        assert_eq!(w(&Message::response(200, "O\r\nK")), Error::StartLine);
        let mut m = Message::response(200, "OK");
        m.push_header("Content-Length", "0");
        m.push_header("Bad:Name", "x");
        assert_eq!(w(&m), Error::HeaderLine);
        let mut m = Message::response(200, "OK");
        m.push_header("Content-Length", "0");
        m.push_header("X", "a\r\nInjected: 1");
        assert_eq!(w(&m), Error::HeaderValue);
        let mut m = Message::response(200, "OK");
        m.push_header("Content-Length", "0");
        m.body = vec![0; MAX_BODY + 1];
        assert_eq!(w(&m), Error::TooLong);
        let mut m = Message::response(200, "OK");
        m.push_header("Content-Length", "0");
        for _ in 0..MAX_HEADERS {
            m.push_header("X", "1");
        }
        assert_eq!(w(&m), Error::TooMany);
        m.headers.pop();
        assert!(Message::parse(&m.to_bytes().unwrap()).is_ok());
        let mut m = Message::response(200, "OK");
        m.push_header("Content-Length", "0");
        m.push_header("X", &"a".repeat(MAX_HEAD));
        assert_eq!(w(&m), Error::TooLong);
        // The writer refuses a length mismatch and preserves corrected fields.
        let mut m = Message::request("MESSAGE", "sip:a@b");
        m.push_header("l", "99");
        m.push_header("Content-Type", "text/plain");
        m.body = b"hi".to_vec();
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        m.set_header("l", "2");
        assert_eq!(
            m.to_bytes().unwrap(),
            b"MESSAGE sip:a@b SIP/2.0\r\nl: 2\r\nContent-Type: text/plain\r\n\r\nhi"
        );
    }

    #[test]
    fn header_editing() {
        let mut m = Message::request("INVITE", "sip:a@b");
        m.push_header("v", "SIP/2.0/UDP a");
        m.push_header("X", "1");
        m.push_header("Via", "SIP/2.0/UDP b");
        m.set_header("VIA", "SIP/2.0/UDP c");
        assert_eq!(m.headers, [Header::new("v", "SIP/2.0/UDP c"), Header::new("X", "1")]);
        m.set_header("Y", "2");
        assert_eq!(m.header("y"), Some("2"));
        assert_eq!(m.remove_header("x"), 1);
        assert_eq!(m.remove_header("x"), 0);
        assert_eq!(full_name("V"), "Via");
        assert_eq!(full_name("Max-Forwards"), "Max-Forwards");
        assert_eq!(full_name("q"), "q");
        for (letter, full) in COMPACT {
            assert_eq!(compact_name(full), Some(std::str::from_utf8(&[letter]).unwrap()));
            assert_eq!(compact_name(&full.to_uppercase()), Some(std::str::from_utf8(&[letter]).unwrap()));
        }
        assert_eq!(compact_name("Max-Forwards"), None);
        assert!(same_name("i", "call-id"));
        assert!(!same_name("i", "Contact"));
    }

    #[test]
    fn reply_copies_the_right_headers() {
        let m = Message::parse(&invite()).unwrap();
        let mut r = m.reply(180, "Ringing");
        let names: Vec<_> = r.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["Via", "To", "From", "Call-ID", "CSeq"]);
        r.push_header("Content-Length", "0");
        let back = Message::parse(&r.to_bytes().unwrap()).unwrap();
        assert_eq!(back.status(), Some(180));
        assert_eq!(back.cseq(), m.cseq());
    }

    #[test]
    fn stream_framing() {
        let bytes = [b"\r\n\r\n".as_slice(), &invite(), b"\r\n", &ok()].concat();
        contract::check_decode_with_alloc_limit(Messages::new, &bytes, 2 * MAX_MESSAGE);
        assert_eq!(
            decode_all(Messages::new, &bytes),
            (vec![Ok(Message::parse(&invite()).unwrap()), Ok(Message::parse(&ok()).unwrap())], None)
        );
        let mut stream = Stream::new(Messages::new());
        let missing = b"OPTIONS sip:a@b SIP/2.0\r\n\r\n";
        assert_eq!(stream.push(missing), missing.len());
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::MissingContentLength))));
        assert_eq!(stream.push(&invite()), invite().len());
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&Fail::Protocol(Error::MissingContentLength)));
        assert_eq!(stream.unread(), missing);
        let bytes = vec![b'X'; MAX_HEAD];
        contract::check_decode_with_alloc_limit(Messages::new, &bytes, 2 * MAX_MESSAGE);
        assert_eq!(decode_all(Messages::new, &bytes).1, Some(Fail::Protocol(Error::TooLong)));
        assert_eq!(Messages::new().decode(&bytes[..MAX_HEAD - 1], false), Ok(Step::Need));
        assert_eq!(
            decode_all(Messages::new, b"INFO sip:a@b SIP/2.0\r\nl: 9999999\r\n\r\n").1,
            Some(Fail::Protocol(Error::TooLong))
        );
    }

    #[test]
    fn stream_takes_many_small_messages_in_linear_time() {
        assert_linear("stream_takes_many_small_messages_in_linear_time", rounds(12_500), |size| {
            let one = b"\r\nOPTIONS sip:a@b SIP/2.0\r\nl: 1\r\n\r\nx";
            let bytes = one.repeat(size);
            let (items, failure) = decode_all(Messages::new, &bytes);
            assert_eq!(failure, None);
            assert_eq!(items.len(), size);
            assert!(items.iter().all(Result::is_ok));
        });
    }

    #[test]
    fn every_truncated_prefix() {
        for whole in [invite(), ok(), compact()] {
            contract::check_decode_with_alloc_limit(Messages::new, &whole, 2 * MAX_MESSAGE);
            for n in 0..whole.len() {
                let part = &whole[..n];
                assert_eq!(Messages::new().decode(part, false), Ok(Step::Need), "{n} bytes");
                assert_eq!(Message::parse(part), Err(Error::Incomplete), "{n} bytes");
                assert_eq!(Message::read_datagram(part), Err(Error::Incomplete), "{n} bytes");
            }
            assert!(Message::parse(&whole).is_ok());
            assert_eq!(Message::read_datagram(&whole), Message::parse(&whole));
        }
        // Prefixes of values never panic and never read as the whole.
        for text in [
            "\"A. G. Bell\" <sip:agb@bell-telephone.com>;tag=a48s",
            "SIP / 2.0 / UDP first.example.com: 4000;ttl=16;received=[2001:db8::1]",
            "sips:alice:pw@[2001:db8::1]:5061;transport=tcp?subject=x%20y&a=b",
            "314159 INVITE",
        ] {
            for n in 0..text.len() {
                let p = &text[..n];
                let _ = (
                    NameAddr::parse(p.as_bytes()),
                    Via::parse(p.as_bytes()),
                    Uri::parse(p.as_bytes()),
                    CSeq::parse(p.as_bytes()),
                    Contacts::parse(p.as_bytes()),
                );
            }
        }
    }

    fn check(data: &[u8]) -> usize {
        contract::check_decode_with_alloc_limit(Messages::new, data, 2 * MAX_MESSAGE);
        contract::check_decode_with_held_limit(Messages::new, data, 0);
        contract::check_wire::<Message>(data);
        let (items, _) = decode_all(Messages::new, data);
        for message in items.iter().flatten() {
            round_trip(message);
        }
        let datagram = Message::read_datagram(data);
        let datagrams = usize::from(datagram.is_ok());
        if let Ok(mut message) = datagram {
            if message.content_length().unwrap().is_none() {
                message.push_header("Content-Length", &message.body.len().to_string());
            }
            round_trip(&message);
        }
        values_round_trip(data);
        items.iter().flatten().count() + datagrams
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
        check!(Uri, NameAddr, Via, Contacts);
        contract::check_wire::<CSeq>(bytes);
        if let Ok(text) = core::str::from_utf8(bytes)
            && let Ok(value) = CSeq::read_value(text)
        {
            cseq_round_trip(&value);
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5eed_5160);
        let seeds = [invite(), ok(), compact()];
        let mut stream = Vec::new();
        for s in &seeds {
            stream.extend(b"\r\n");
            stream.extend(s);
        }
        let values: [&[u8]; 5] = [
            b"\"A. G. \\\"Bell\\\"\" <sip:agb@bell.com;transport=tcp?x=y> ;tag=a48s;q=\"1\"",
            b"SIP / 2.0 / TLS [2001:db8::9]: 5070;rport;received=[::1];branch=z9hG4bK1",
            b"sips:alice:pw@atlanta.com:5061;transport=tcp;lr?subject=x%20y&a=",
            b"4711 REGISTER",
            b"<sip:a@b>;expires=60, \"C, D\" <sip:c@d>, mailto:x@y;q=0.1",
        ];
        let mut read = 0;
        let rounds = fictionet::stdlib::test_support::rounds(1500);
        for round in 0..rounds {
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
        // With this seed, a round reads about 0.45 messages (675 in 1500
        // rounds, 2800 in 6000); allow a small margin.
        assert!(read > rounds * 43 / 100, "only {read} messages read in {rounds} rounds");
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
        let mut rng = Lcg::new(42);
        let text = |rng: &mut Lcg, max| {
            let mut value = rng.text(max);
            if rng.index(8) == 0 {
                value.push_str(&String::from_utf8_lossy(&rng.bytes(3)));
            }
            value
        };
        let words = ["", "alice", "a b", "x%20", "%zz", "sip", "[::1]", "::1", "host.com", "a;b", "q\"", "UDP"];
        let mut written = 0;
        for _ in 0..rounds(20_000) {
            let mut u =
                Uri::new(if rng.coin() { Scheme::Sip } else { Scheme::Sips }, words[rng.index(words.len())]);
            if rng.coin() {
                u.user = Some(text(&mut rng, 6));
            }
            if rng.index(3) == 0 {
                u.password = Some(text(&mut rng, 4));
            }
            if rng.coin() {
                u.port = Some(rng.next() as u16);
            }
            for _ in 0..rng.index(3) {
                let value = if rng.coin() { None } else { Some(text(&mut rng, 4)) };
                u.params.push(Param { name: text(&mut rng, 4), value });
            }
            for _ in 0..rng.index(2) {
                u.headers.push((text(&mut rng, 3), text(&mut rng, 3)));
            }
            contract::check_wire_value(&u);
            if let Ok(text) = wire_text(&u) {
                assert_eq!(Uri::parse(text.as_bytes()).unwrap(), u, "{text}");
                written += 1;
            }

            let mut params = Vec::new();
            for _ in 0..rng.index(3) {
                let value = match rng.index(3) {
                    0 => None,
                    1 => Some(text(&mut rng, 5)),
                    _ => Some(format!("\"{}\"", text(&mut rng, 5))),
                };
                params.push(Param { name: text(&mut rng, 4), value });
            }
            let display = if rng.coin() { None } else { Some(text(&mut rng, 8)) };
            let a = NameAddr { display, uri: text(&mut rng, 10), params: params.clone() };
            contract::check_wire_value(&a);
            if let Ok(text) = wire_text(&a) {
                assert_eq!(NameAddr::parse(text.as_bytes()).unwrap(), a, "{text}");
                written += 1;
            }
            let port = if rng.coin() { None } else { Some(rng.next() as u16) };
            let v = Via {
                transport: words[rng.index(words.len())].to_string(),
                host: words[rng.index(words.len())].to_string(),
                port,
                params,
            };
            contract::check_wire_value(&v);
            if let Ok(text) = wire_text(&v) {
                assert_eq!(Via::parse(text.as_bytes()).unwrap(), v, "{text}");
                written += 1;
            }
            let c = CSeq { seq: rng.next() as u32, method: text(&mut rng, 5) };
            contract::check_wire_value(&c);
            if let Ok(text) = wire_text(&c) {
                assert_eq!(CSeq::parse(text.as_bytes()).unwrap(), c);
            }

            let mut m = if rng.coin() {
                Message::request(&text(&mut rng, 5), &text(&mut rng, 8))
            } else {
                Message::response(rng.index(800) as u16, &text(&mut rng, 6))
            };
            for _ in 0..rng.index(4) {
                let name = ["Via", "l", "X", "Bad Name", "f"][rng.index(5)].to_string();
                m.push_header(&name, &text(&mut rng, 8));
            }
            m.body = text(&mut rng, 6).into_bytes();
            m.set_header("Content-Length", &m.body.len().to_string());
            contract::check_wire_value(&m);
            if let Ok(bytes) = m.to_bytes() {
                assert_eq!(Message::parse(&bytes).unwrap(), m);
                written += 1;
            }
        }
        assert!(written > 5000, "only {written} writes succeeded");
    }

    #[test]
    fn stream_holds_at_most_one_message() {
        let mut stream = Stream::new(Messages::new());
        let bytes = vec![b'\r'; MAX_MESSAGE + 1];
        assert_eq!(stream.push(&bytes), MAX_MESSAGE);
        assert_eq!(stream.push(b"extra"), 0);
        assert_eq!(stream.buffered(), MAX_MESSAGE);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TooLong))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(&bytes), bytes.len());
        let one = b"OPTIONS sip:a@b SIP/2.0\r\nl: 4\r\n\r\nbody";
        let n = rounds(40_000);
        let (items, failure) = decode_all(Messages::new, &one.repeat(n));
        assert_eq!(failure, None);
        assert_eq!(items.len(), n);
        assert!(items.iter().all(Result::is_ok));
        let mut crlfs = b"\r\n".repeat(MAX_MESSAGE);
        crlfs.extend(one);
        let (items, failure) = decode_all(Messages::new, &crlfs);
        assert_eq!(failure, None);
        assert_eq!(items, [Ok(Message::parse(one).unwrap())]);
        contract::check_decode_with_alloc_limit(Messages::new, &crlfs, 2 * MAX_MESSAGE);
    }

    #[test]
    fn value_readers_and_writers_are_bounded() {
        let long = "a".repeat(MAX_HEAD);
        assert_eq!(Uri::parse(format!("sip:{long}@h").as_bytes()), Err(Error::TooLong));
        assert_eq!(NameAddr::parse(format!("<sip:{long}@h>").as_bytes()), Err(Error::TooLong));
        assert_eq!(
            NameAddr::parse(format!("{}<sip:a@h>", "x ".repeat(MAX_HEAD)).as_bytes()),
            Err(Error::TooLong)
        );
        assert_eq!(Via::parse(format!("SIP/2.0/UDP {long}").as_bytes()), Err(Error::TooLong));
        assert_eq!(CSeq::parse(format!("1 {long}").as_bytes()), Err(Error::TooLong));
        assert_eq!(Contacts::parse(format!("<sip:{long}@h>").as_bytes()), Err(Error::TooLong));
        // Writers refuse what readers would.
        let mut u = Uri::new(Scheme::Sip, "h");
        u.user = Some(long.clone());
        assert_eq!(wire_text(&u), Err(Error::TooLong));
        let a = NameAddr { display: Some(long.clone()), uri: "sip:a@h".into(), params: vec![] };
        assert_eq!(wire_text(&a), Err(Error::TooLong));
        assert_eq!(wire_text(&Contacts::List(vec![a])), Err(Error::TooLong));
        assert_eq!(wire_text(&Via::new("UDP", &long)), Err(Error::TooLong));
        assert_eq!(wire_text(&CSeq { seq: 1, method: long.clone() }), Err(Error::TooLong));
        // Display-name words are joined without a list of them.
        let a = NameAddr::parse("  Mr.   Watson\t <sip:w@h>".as_bytes()).unwrap();
        assert_eq!(a.display.as_deref(), Some("Mr. Watson"));
    }

    #[test]
    fn message_writer_checks_lengths_first() {
        let huge = "a".repeat(MAX_HEAD + 1);
        assert_eq!(Message::response(200, &huge).to_bytes(), Err(Error::TooLong));
        assert_eq!(Message::request("INVITE", &format!("sip:{huge}@h")).to_bytes(), Err(Error::TooLong));
        assert_eq!(Message::request(&huge, "sip:a@h").to_bytes(), Err(Error::TooLong));
        let mut m = Message::response(200, "OK");
        m.push_header("X", &huge);
        assert_eq!(m.to_bytes(), Err(Error::TooLong));
        // Right at the limit, it writes and reads back.
        let mut m = Message::response(200, "OK");
        let fixed = "SIP/2.0 200 OK\r\nX: \r\nContent-Length: 0\r\n\r\n".len();
        m.push_header("X", &"a".repeat(MAX_HEAD - fixed));
        m.push_header("Content-Length", "0");
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_HEAD);
        assert!(Message::parse(&bytes).is_ok());
        m.headers[0].value.push('a');
        assert_eq!(m.to_bytes(), Err(Error::TooLong));
    }

    #[test]
    fn uris_follow_the_sip_grammar() {
        // RFC 3261 section 25.1.
        assert_eq!(Message::request("OPTIONS", "sip:%GG@h").to_bytes(), Err(Error::StartLine));
        assert_eq!(Message::parse(b"OPTIONS sip:%GG@h SIP/2.0\r\nl: 0\r\n\r\n"), Err(Error::StartLine));
        assert_eq!(Message::request("OPTIONS", "tel:12{3}").to_bytes(), Err(Error::StartLine));
        let mut message = Message::request("OPTIONS", "tel:+1-201-555-0123");
        message.push_header("Content-Length", "0");
        assert!(message.to_bytes().is_ok());
        assert!(wire_text(&NameAddr::new("sip:")).is_err());
        assert!(NameAddr::parse("<sip:>".as_bytes()).is_err());
        assert!(NameAddr::parse("<mailto:a@b>".as_bytes()).is_ok());
        for bad in ["sip:.", "sip:-bad.example", "sip:bad-.example", "sip:a..b", "sip:1.2.3", "sip:example.123"] {
            assert_eq!(Uri::parse(bad.as_bytes()), Err(Error::Uri), "{bad:?}");
        }
        for good in ["sip:example.com.", "sip:a-b.c", "sip:x1.y2z", "sip:192.0.2.1", "sip:h"] {
            assert!(Uri::parse(good.as_bytes()).is_ok(), "{good:?}");
        }
        assert!(Via::parse("SIP/2.0/UDP -bad".as_bytes()).is_err());
        assert!(wire_text(&Via::new("UDP", "-bad")).is_err());
    }

    #[test]
    fn recognized_parameters_follow_their_grammar() {
        // RFC 3261 section 25.1: tag-param, via-received, via-branch,
        // via-ttl, via-maddr, c-p-q and c-p-expires.
        assert!(NameAddr::parse("<sip:a@b>;tag=\"two words\"".as_bytes()).is_err());
        assert!(NameAddr::parse("<sip:a@b>;tag".as_bytes()).is_err());
        assert!(NameAddr::parse("<sip:a@b>;tag=a.b-c!".as_bytes()).is_ok());
        assert!(Via::parse("SIP/2.0/UDP h;received=garbage".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;branch=\"a b\"".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;branch".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;ttl=256".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;ttl=1000".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;maddr=-x".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;rport=x".as_bytes()).is_err());
        assert!(
            Via::parse(
                "SIP/2.0/UDP h;rport;received=1.2.3.4;ttl=255;maddr=m.example;branch=z9hG4bK.x".as_bytes()
            )
            .is_ok()
        );
        assert!(Via::parse("SIP/2.0/UDP h;rport=5060".as_bytes()).is_ok());
        for bad in ["q=2.0", "q=1.5", "q=0.1234", "q=x", "q", "expires=tomorrow", "expires=-1", "expires"] {
            assert_eq!(
                Contacts::parse(format!("<sip:a@b>;{bad}").as_bytes()),
                Err(Error::Malformed("Contact")),
                "{bad:?}"
            );
        }
        for good in ["q=0", "q=0.", "q=0.7", "q=0.123", "q=1", "q=1.000", "expires=3600", "expires=0"] {
            assert!(Contacts::parse(format!("<sip:a@b>;{good}").as_bytes()).is_ok(), "{good:?}");
        }
        // Other headers' generic parameters keep the generic grammar.
        assert!(NameAddr::parse("<sip:a@b>;q=2.0".as_bytes()).is_ok());
        // Writers refuse the same.
        let mut a = NameAddr::new("sip:a@b");
        a.params.push(Param::new("tag", Some("\"x y\"")));
        assert!(wire_text(&a).is_err());
        let mut c = NameAddr::new("sip:a@b");
        c.params.push(Param::new("q", Some("2.0")));
        assert_eq!(wire_text(&Contacts::List(vec![c])), Err(Error::Malformed("Contact")));
        let mut v = Via::new("UDP", "h");
        v.params.push(Param::new("received", Some("garbage")));
        assert!(wire_text(&v).is_err());
    }

    #[test]
    fn duplicate_parameters_are_refused() {
        // RFC 3261 sections 7.3.1 and 19.1.1.
        assert_eq!(Uri::parse("sip:h;transport=tcp;TRANSPORT=udp".as_bytes()), Err(Error::Uri));
        assert_eq!(Uri::parse("sip:h;lr;%6C%72".as_bytes()), Err(Error::Uri));
        assert!(Uri::parse("sip:h;lr;lr2".as_bytes()).is_ok());
        assert!(NameAddr::parse("<sip:a@b>;tag=one;TAG=two".as_bytes()).is_err());
        assert!(Via::parse("SIP/2.0/UDP h;branch=z9hG4bK1;branch=z9hG4bK2".as_bytes()).is_err());
        let mut u = Uri::new(Scheme::Sip, "h");
        u.params = vec![Param::new("lr", None), Param::new("LR", None)];
        assert_eq!(wire_text(&u), Err(Error::Uri));
        let mut a = NameAddr::new("sip:a@b");
        a.params = vec![Param::new("x", None), Param::new("X", Some("1"))];
        assert!(wire_text(&a).is_err());
        let mut v = Via::new("UDP", "h");
        v.params = vec![Param::new("rport", None), Param::new("rport", None)];
        assert!(wire_text(&v).is_err());
    }

    #[test]
    fn uri_param_lookup_reads_escapes() {
        // RFC 3261 section 19.1.4; the URI is from RFC 4475 section 3.1.1.3.
        let u = Uri::parse("sip:proxy.example;%6C%72".as_bytes()).unwrap();
        assert_eq!(u.param("lr").map(|p| p.name.as_str()), Some("%6C%72"));
        assert_eq!(u.param("LR").map(|p| p.name.as_str()), Some("%6C%72"));
        assert_eq!(wire_text(&u).unwrap(), "sip:proxy.example;%6C%72");
        // An escaped reserved character is not the character itself.
        let u = Uri::parse("sip:h;a%2Fb".as_bytes()).unwrap();
        assert!(u.param("a/b").is_none());
        assert!(u.param("a%2fb").is_some());
    }

    #[test]
    fn quoted_pairs_may_escape_control_characters() {
        // RFC 3261 section 25.1: quoted-pair = "\" (%x00-09 / %x0B-0C /
        // %x0E-7F). RFC 4475 section 3.1.1.2 quotes a NUL this way.
        let m = Message::parse(
            b"OPTIONS sip:a@b SIP/2.0\r\nTo: \"BEL:\\\x07 NUL:\\\x00 DEL:\\\x7F\" <sip:a@b>\r\nl: 0\r\n\r\n",
        )
        .unwrap();
        let to = m.to().unwrap();
        assert_eq!(to.display.as_deref(), Some("BEL:\u{7} NUL:\u{0} DEL:\u{7f}"));
        assert_eq!(NameAddr::parse(wire_text(&to).unwrap().as_bytes()).unwrap(), to);
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap().to().unwrap(), to);
        // Bare ones are still refused, in quotes or out.
        assert_eq!(
            Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nTo: \"a\x07\" <sip:a@b>\r\nl: 0\r\n\r\n"),
            Err(Error::HeaderValue)
        );
        assert!(NameAddr::parse("\"a\u{7}\" <sip:a@b>".as_bytes()).is_err());
        assert!(NameAddr::parse("<sip:a@b>;x=\"\\\u{0}\"".as_bytes()).is_ok());
        // Writers escape them, and refuse CR and LF.
        let mut a = NameAddr::new("sip:a@b");
        a.display = Some("a\u{0}b".into());
        assert_eq!(wire_text(&a).unwrap(), "\"a\\\u{0}b\" <sip:a@b>");
        a.display = Some("a\rb".into());
        assert!(wire_text(&a).is_err());
    }

    #[test]
    fn cseq_writer_keeps_below_2_pow_31() {
        // RFC 3261 section 8.1.1.5.
        assert_eq!(
            wire_text(&CSeq { seq: (1 << 31) - 1, method: "INVITE".into() }).unwrap(),
            "2147483647 INVITE"
        );
        assert_eq!(wire_text(&CSeq { seq: 1 << 31, method: "INVITE".into() }), Err(Error::Malformed("CSeq")));
        assert_eq!(CSeq::parse(b"2147483648 INVITE"), Err(Error::Malformed("CSeq")));
        let mut message = Message::request("INVITE", "sip:a@b");
        message.push_header("CSeq", "2147483648 INVITE");
        assert_eq!(message.cseq().unwrap().seq, 1 << 31);
    }

    #[test]
    fn empty_list_elements_are_refused() {
        // RFC 3261 section 25.1: Contact and Via lists have no empty items.
        assert_eq!(Contacts::parse(",*,".as_bytes()), Err(Error::Malformed("Contact")));
        assert_eq!(Contacts::parse("<sip:a@b>,,".as_bytes()), Err(Error::Malformed("Contact")));
        assert_eq!(
            Contacts::parse("<sip:a@b>, <sip:c@d>".as_bytes()),
            Ok(Contacts::List(vec![NameAddr::new("sip:a@b"), NameAddr::new("sip:c@d")]))
        );
        let m = Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nm: ,*\r\nVia:\r\nl: 0\r\n\r\n").unwrap();
        assert_eq!(m.contacts(), Err(Error::Malformed("Contact")));
        assert_eq!(m.vias(), Err(Error::Malformed("Via")));
        let m =
            Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP a,,SIP/2.0/UDP b\r\nl: 0\r\n\r\n").unwrap();
        assert_eq!(m.vias(), Err(Error::Malformed("Via")));
    }

    #[test]
    fn content_length_may_appear_once() {
        // RFC 3261 section 7.3.1: only list headers may repeat.
        let e = Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nContent-Length: 1\r\nl: 01\r\n\r\na");
        assert_eq!(e, Err(Error::ContentLength));
        let e = Message::parse(b"OPTIONS sip:a@b SIP/2.0\r\nl: 0\r\nl: 0\r\n\r\n");
        assert_eq!(e, Err(Error::ContentLength));
    }

    #[test]
    fn trying_copies_timestamp() {
        // RFC 3261 section 8.2.6.1.
        let mut m = Message::parse(&invite()).unwrap();
        m.push_header("Timestamp", "54");
        assert_eq!(m.reply(100, "Trying").header("Timestamp"), Some("54"));
        assert_eq!(m.reply(180, "Ringing").header("Timestamp"), None);
    }
}
