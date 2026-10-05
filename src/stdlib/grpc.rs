//! gRPC: message framing, status codes, timeouts and the header rules a
//! server follows, with no I/O.
//!
//! gRPC is how many services call each other: a client names a method,
//! sends one or more messages, and gets messages back followed by a
//! status. It runs over HTTP/2, usually on TCP port 443 with TLS or 50051
//! without. Each call is one HTTP/2 stream. The request is a block of
//! headers, then messages in DATA frames. The response is a block of
//! headers, messages, then trailers that carry the status. This module
//! follows "gRPC over HTTP2" (`doc/PROTOCOL-HTTP2.md` in the gRPC
//! repository), and its status code and HTTP mapping documents.
//!
//! Nothing here reads a socket or speaks HTTP/2. A world that plays a gRPC
//! server takes a stream's headers from its HTTP/2 code and checks them
//! with [`Request::parse`]. It feeds the stream's DATA bytes to a
//! [`Decoder`] and gets [`Message`]s back. Each message body stays as
//! bytes: reading it (as protobuf, JSON or anything else) is up to world
//! code. So is the answer. The world writes [`response_headers`], each
//! reply with [`Message::to_bytes`], and ends with [`Status::to_trailers`].
//! A call that fails at once ends with [`Status::trailers_only`] instead.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. The decoder never holds more than one message, and
//! refuses a message longer than its limit as soon as the length arrives.
//!
//! ```
//! use fictionet::stdlib::grpc::{response_headers, Code, Decoder, Message, Request, Status};
//!
//! let request = Request::parse([
//!     (":method", "POST"),
//!     (":scheme", "http"),
//!     (":path", "/helloworld.Greeter/SayHello"),
//!     ("te", "trailers"),
//!     ("content-type", "application/grpc"),
//!     ("grpc-timeout", "1S"),
//! ])
//! .unwrap();
//! assert_eq!(request.path.service(), "helloworld.Greeter");
//! assert_eq!(request.path.method(), "SayHello");
//! assert_eq!(request.timeout.unwrap().as_duration().as_secs(), 1);
//!
//! // One DATA frame: an uncompressed message of 3 bytes.
//! let data = [0, 0, 0, 0, 3, 0x0a, 0x01, b'x'];
//! let mut decoder = Decoder::new();
//! assert_eq!(decoder.feed(&data), data.len());
//! let message = decoder.next_message().unwrap().unwrap();
//! assert_eq!(message.data, [0x0a, 0x01, b'x']);
//! assert!(decoder.finish().is_ok());
//!
//! // The reply: headers, the same message back, then the status.
//! let headers = response_headers(&request.content_type);
//! assert_eq!(headers[0], (":status".to_string(), "200".to_string()));
//! let reply = Message { compressed: false, data: message.data }.to_bytes();
//! assert_eq!(reply, data);
//! let trailers = Status::new(Code::NotFound, "no user 'x'").to_trailers();
//! assert_eq!(trailers[0], ("grpc-status".to_string(), "5".to_string()));
//! assert_eq!(trailers[1], ("grpc-message".to_string(), "no user 'x'".to_string()));
//! ```

use std::fmt;
use std::time::Duration;

/// The TCP port gRPC servers most often listen on without TLS. With TLS
/// they usually use 443.
pub const PORT: u16 = 50051;
/// The length of the prefix before each message: a compressed flag and a
/// 4-byte big-endian length.
pub const HEADER_LEN: usize = 5;
/// The longest message this module reads or writes: 16 MiB. The format
/// allows up to 4 GiB, but no decoder here holds more than this.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// The message limit a [`Decoder`] starts with: 4 MiB, the default most
/// gRPC servers use.
pub const DEFAULT_MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// The largest request header block [`Request::parse`] accepts: 8 KiB, the
/// limit the specification suggests. It is counted as HTTP/2 counts it:
/// each header's name and value lengths, plus 32.
pub const MAX_HEADER_LIST: usize = 8 * 1024;
/// The longest status message, in bytes of UTF-8 text, before
/// percent-encoding. Longer text is cut at a character boundary.
pub const MAX_STATUS_MESSAGE: usize = 1024;
/// The longest content-type subtype, the part after `application/grpc+`.
pub const MAX_SUBTYPE: usize = 64;
/// The longest `:path` a method can have.
pub const MAX_PATH: usize = 1024;
/// The largest number a `grpc-timeout` value may hold: 8 digits.
pub const MAX_TIMEOUT_VALUE: u32 = 99_999_999;
/// The HTTP status a server answers with when the content-type is not
/// gRPC.
pub const UNSUPPORTED_MEDIA_TYPE: u16 = 415;
/// The HTTP status this module answers with when the method is not POST.
/// The specification names none. The HTTP handler in gRPC's Go server
/// uses this one.
pub const METHOD_NOT_ALLOWED: u16 = 405;

// ---------------------------------------------------------------------
// Messages and the decoder.
// ---------------------------------------------------------------------

/// One length-prefixed message from a call's DATA frames.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Message {
    /// Whether the body is compressed with the call's `grpc-encoding`.
    pub compressed: bool,
    /// The body, as sent. This module never decompresses it.
    pub data: Vec<u8>,
}

/// Why bytes are not a gRPC message stream. After any of these the stream
/// holds no more messages a reader can find. A server ends the call with
/// the status [`FrameError::code`] gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// The compressed flag was neither 0 nor 1.
    Flag(u8),
    /// The length prefix was over the limit.
    TooLarge {
        /// The length the prefix gave.
        length: u32,
        /// The limit it broke.
        limit: usize,
    },
    /// The stream ended inside a message.
    Truncated {
        /// How many bytes of the message had come.
        buffered: usize,
    },
}

impl FrameError {
    /// The status code a server ends the call with: `RESOURCE_EXHAUSTED`
    /// for a message over the limit, and `INTERNAL` otherwise.
    pub fn code(self) -> Code {
        match self {
            FrameError::TooLarge { .. } => Code::ResourceExhausted,
            FrameError::Flag(_) | FrameError::Truncated { .. } => Code::Internal,
        }
    }

    /// The status a server ends the call with, with this error as its
    /// message.
    pub fn to_status(self) -> Status {
        Status::new(self.code(), &self.to_string())
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Flag(b) => write!(f, "compressed flag {b}, not 0 or 1"),
            FrameError::TooLarge { length, limit } => {
                write!(f, "message of {length} bytes, over the limit of {limit}")
            }
            FrameError::Truncated { buffered } => {
                write!(f, "stream ended inside a message, after {buffered} bytes")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl Message {
    /// Reads the message at the start of `b`, allowing up to
    /// [`MAX_MESSAGE`] bytes of body. It returns `Ok(None)` if `b` holds
    /// only part of one, and otherwise the message and how many bytes of
    /// `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Message, usize)>, FrameError> {
        let Some(&flag) = b.first() else {
            return Ok(None);
        };
        if flag > 1 {
            return Err(FrameError::Flag(flag));
        }
        let Some(head) = b.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let length = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        let len = match usize::try_from(length) {
            Ok(n) if n <= MAX_MESSAGE => n,
            _ => return Err(FrameError::TooLarge { length, limit: MAX_MESSAGE }),
        };
        let Some(end) = HEADER_LEN.checked_add(len) else {
            return Err(FrameError::TooLarge { length, limit: MAX_MESSAGE });
        };
        match b.get(HEADER_LEN..end) {
            Some(data) => Ok(Some((Message { compressed: flag == 1, data: data.to_vec() }, end))),
            None => Ok(None),
        }
    }

    /// The message with its length prefix. A body longer than
    /// [`MAX_MESSAGE`] is cut to that length. [`Message::parse`] reads
    /// every message this writes. A [`Decoder`] reads it when the body is
    /// within the decoder's own limit.
    pub fn to_bytes(&self) -> Vec<u8> {
        let data = &self.data[..self.data.len().min(MAX_MESSAGE)];
        // MAX_MESSAGE fits in a u32, so this never saturates.
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let mut out = Vec::with_capacity(HEADER_LEN + data.len());
        out.push(u8::from(self.compressed));
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Checks the compressed flag against the call's `grpc-encoding`. A
    /// compressed message in a call with no encoding, or with `identity`,
    /// breaks the protocol, and the server ends the call with `INTERNAL`.
    /// Whether the world can decompress a named encoding is up to it. If
    /// it cannot, it usually answers `UNIMPLEMENTED`.
    pub fn check_encoding(&self, encoding: Option<&str>) -> Result<(), Status> {
        let named = matches!(encoding, Some(e) if !e.eq_ignore_ascii_case("identity"));
        if self.compressed && !named {
            return Err(Status::new(Code::Internal, "compressed message without a grpc-encoding"));
        }
        Ok(())
    }
}

/// Splits a call's DATA bytes into messages. Feed it the bytes in order
/// and take messages out until it has none. It holds at most one message,
/// so `feed` stops taking bytes once a whole message is waiting.
///
/// ```
/// use fictionet::stdlib::grpc::Decoder;
///
/// let stream = [0, 0, 0, 0, 1, 7, 0, 0, 0, 0, 1, 8];
/// let mut decoder = Decoder::new();
/// let mut rest = &stream[..];
/// let mut bodies = Vec::new();
/// loop {
///     let used = decoder.feed(rest);
///     rest = &rest[used..];
///     match decoder.next_message() {
///         Some(Ok(m)) => bodies.push(m.data),
///         Some(Err(e)) => panic!("{e}"),
///         None => break,
///     }
/// }
/// assert_eq!(bodies, [[7], [8]]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoder {
    limit: usize,
    head: [u8; HEADER_LEN],
    head_len: usize,
    want: usize,
    body: Vec<u8>,
    ready: bool,
    failed: Option<FrameError>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, with the limit [`DEFAULT_MAX_MESSAGE`].
    pub fn new() -> Decoder {
        Decoder::with_limit(DEFAULT_MAX_MESSAGE)
    }

    /// A decoder that refuses messages longer than `limit` bytes. A limit
    /// above [`MAX_MESSAGE`] is lowered to it.
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder {
            limit: limit.min(MAX_MESSAGE),
            head: [0; HEADER_LEN],
            head_len: 0,
            want: 0,
            body: Vec::new(),
            ready: false,
            failed: None,
        }
    }

    /// The longest message this decoder accepts.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Takes bytes from the start of `bytes` and returns how many it took.
    /// It stops after the end of a message, and takes no more until that
    /// message is taken out with [`next_message`](Self::next_message).
    /// After a [`FrameError`] it takes every byte and drops it.
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        let mut used = 0;
        while used < bytes.len() && !self.ready {
            let rest = &bytes[used..];
            if self.head_len < HEADER_LEN {
                let n = (HEADER_LEN - self.head_len).min(rest.len());
                self.head[self.head_len..self.head_len + n].copy_from_slice(&rest[..n]);
                self.head_len += n;
                used += n;
                if self.head[0] > 1 {
                    return self.fail(FrameError::Flag(self.head[0]), bytes.len());
                }
                if self.head_len == HEADER_LEN {
                    let h = self.head;
                    let length = u32::from_be_bytes([h[1], h[2], h[3], h[4]]);
                    match usize::try_from(length) {
                        Ok(n) if n <= self.limit => self.want = n,
                        _ => {
                            let e = FrameError::TooLarge { length, limit: self.limit };
                            return self.fail(e, bytes.len());
                        }
                    }
                    self.body = Vec::new();
                    self.ready = self.want == 0;
                }
            } else {
                let n = (self.want - self.body.len()).min(rest.len());
                self.body.extend_from_slice(&rest[..n]);
                used += n;
                self.ready = self.body.len() == self.want;
            }
        }
        used
    }

    fn fail(&mut self, e: FrameError, all: usize) -> usize {
        self.failed = Some(e);
        self.head_len = 0;
        self.body = Vec::new();
        self.ready = false;
        all
    }

    /// The next whole message, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken.
    pub fn next_message(&mut self) -> Option<Result<Message, FrameError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        if !self.ready {
            return None;
        }
        self.ready = false;
        self.head_len = 0;
        Some(Ok(Message { compressed: self.head[0] == 1, data: std::mem::take(&mut self.body) }))
    }

    /// Checks that the stream can end here: at end of stream, the bytes
    /// held must not be part of a message.
    pub fn finish(&self) -> Result<(), FrameError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.head_len > 0 && !self.ready {
            return Err(FrameError::Truncated { buffered: self.buffered() });
        }
        Ok(())
    }

    /// How many bytes are held, prefix included.
    pub fn buffered(&self) -> usize {
        if self.head_len == 0 { 0 } else { self.head_len + self.body.len() }
    }
}

// ---------------------------------------------------------------------
// Status codes.
// ---------------------------------------------------------------------

/// A gRPC status code, as `grpc-status` carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    /// 0: the call succeeded.
    Ok,
    /// 1: the call was cancelled, usually by the caller.
    Cancelled,
    /// 2: an error with no better code.
    Unknown,
    /// 3: the client sent an argument that is wrong whatever the state.
    InvalidArgument,
    /// 4: the deadline passed before the call finished.
    DeadlineExceeded,
    /// 5: something the call asked for does not exist.
    NotFound,
    /// 6: something the call tried to create already exists.
    AlreadyExists,
    /// 7: the caller may not do this.
    PermissionDenied,
    /// 8: a resource ran out, such as a quota or a size limit.
    ResourceExhausted,
    /// 9: the system is not in the state the call needs.
    FailedPrecondition,
    /// 10: the call was aborted, usually by a conflict.
    Aborted,
    /// 11: the call went past a valid range.
    OutOfRange,
    /// 12: the server does not have this method.
    Unimplemented,
    /// 13: something the server relies on broke.
    Internal,
    /// 14: the service cannot answer now. Trying again may work.
    Unavailable,
    /// 15: data was lost or corrupted beyond repair.
    DataLoss,
    /// 16: the call carries no valid credentials.
    Unauthenticated,
}

const CODES: [(Code, &str); 17] = [
    (Code::Ok, "OK"),
    (Code::Cancelled, "CANCELLED"),
    (Code::Unknown, "UNKNOWN"),
    (Code::InvalidArgument, "INVALID_ARGUMENT"),
    (Code::DeadlineExceeded, "DEADLINE_EXCEEDED"),
    (Code::NotFound, "NOT_FOUND"),
    (Code::AlreadyExists, "ALREADY_EXISTS"),
    (Code::PermissionDenied, "PERMISSION_DENIED"),
    (Code::ResourceExhausted, "RESOURCE_EXHAUSTED"),
    (Code::FailedPrecondition, "FAILED_PRECONDITION"),
    (Code::Aborted, "ABORTED"),
    (Code::OutOfRange, "OUT_OF_RANGE"),
    (Code::Unimplemented, "UNIMPLEMENTED"),
    (Code::Internal, "INTERNAL"),
    (Code::Unavailable, "UNAVAILABLE"),
    (Code::DataLoss, "DATA_LOSS"),
    (Code::Unauthenticated, "UNAUTHENTICATED"),
];

impl Code {
    /// The code's number.
    pub fn number(self) -> u32 {
        self as u32
    }

    /// The code with this number, if there is one.
    pub fn from_number(n: u32) -> Option<Code> {
        CODES.get(usize::try_from(n).ok()?).map(|&(c, _)| c)
    }

    /// The code's name in capitals, such as `NOT_FOUND`.
    pub fn name(self) -> &'static str {
        CODES[self as usize].1
    }

    /// The code with this name in capitals, if there is one.
    pub fn from_name(name: &str) -> Option<Code> {
        CODES.iter().find(|&&(_, n)| n == name).map(|&(c, _)| c)
    }

    /// The code a client reports when a response has this HTTP status and
    /// no `grpc-status`, from gRPC's HTTP to gRPC status mapping.
    pub fn from_http_status(status: u16) -> Code {
        match status {
            400 => Code::Internal,
            401 => Code::Unauthenticated,
            403 => Code::PermissionDenied,
            404 => Code::Unimplemented,
            429 | 502 | 503 | 504 => Code::Unavailable,
            _ => Code::Unknown,
        }
    }

    /// The code a call ends with when its stream is reset with this HTTP/2
    /// error code. `STREAM_CLOSED` (5) has none: there is no open call to
    /// tell. `CANCEL` (8) is `CANCELLED` when the server sends it, and
    /// cancels the call when the client does. Codes HTTP/2 does not define
    /// count as `INTERNAL_ERROR`.
    pub fn from_rst_stream(error: u32) -> Option<Code> {
        match error {
            5 => None,
            7 => Some(Code::Unavailable),
            8 => Some(Code::Cancelled),
            11 => Some(Code::ResourceExhausted),
            12 => Some(Code::PermissionDenied),
            _ => Some(Code::Internal),
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A call's outcome: a code and a message for people.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Status {
    /// The status code.
    pub code: Code,
    /// The message, as plain UTF-8 text. It may be empty.
    pub message: String,
}

/// Why trailers do not give a call's status. [`Status::from_trailers`]
/// turns each of these into a status, as a client must.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrailerError {
    /// There was no `grpc-status`.
    MissingStatus,
    /// `grpc-status` was not a decimal number, or came twice.
    BadStatus,
    /// `:status` was not 200. A `:status` that is not a number reads as 0.
    HttpStatus(u16),
}

impl fmt::Display for TrailerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrailerError::MissingStatus => f.write_str("no grpc-status"),
            TrailerError::BadStatus => f.write_str("malformed grpc-status"),
            TrailerError::HttpStatus(s) => write!(f, "HTTP status {s}, not 200"),
        }
    }
}

impl std::error::Error for TrailerError {}

impl Status {
    /// A status with this code and message. A message longer than
    /// [`MAX_STATUS_MESSAGE`] bytes is cut at a character boundary.
    pub fn new(code: Code, message: &str) -> Status {
        Status { code, message: floor_char(message, MAX_STATUS_MESSAGE).to_string() }
    }

    /// The status of a call that succeeded, with no message.
    pub fn ok() -> Status {
        Status { code: Code::Ok, message: String::new() }
    }

    /// Whether the code is `OK`.
    pub fn is_ok(&self) -> bool {
        self.code == Code::Ok
    }

    /// The trailers that end a call: `grpc-status`, then `grpc-message`
    /// if the message is not empty. Custom metadata may follow them. A
    /// message longer than [`MAX_STATUS_MESSAGE`] bytes is cut, as
    /// [`encode_message`] does, so it reads back shorter.
    pub fn to_trailers(&self) -> Vec<(String, String)> {
        let mut out = vec![("grpc-status".to_string(), self.code.number().to_string())];
        if !self.message.is_empty() {
            out.push(("grpc-message".to_string(), encode_message(&self.message)));
        }
        out
    }

    /// The single header block of a call that fails before any message:
    /// `:status` 200, the content-type, then the trailers. The HTTP/2
    /// HEADERS frame carrying it ends the stream.
    pub fn trailers_only(&self, content_type: &ContentType) -> Vec<(String, String)> {
        let mut out = response_headers(content_type);
        out.extend(self.to_trailers());
        out
    }

    /// Reads a status from trailers, or from a trailers-only header block.
    /// Header names match without regard to case. Other headers are
    /// ignored.
    pub fn parse_trailers<I, N, V>(headers: I) -> Result<Status, TrailerError>
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let t = TrailerScan::new(headers);
        if let Some(h) = t.http
            && h != 200
        {
            return Err(TrailerError::HttpStatus(h));
        }
        t.status()
    }

    /// Reads a status the way a client must: as
    /// [`parse_trailers`](Self::parse_trailers) does, but making one up from what is there
    /// when the trailers are broken. A well-formed `grpc-status` is always
    /// used, whatever the `:status`. Without one, a non-200 `:status` maps
    /// through [`Code::from_http_status`], and anything else gives
    /// `UNKNOWN`.
    pub fn from_trailers<I, N, V>(headers: I) -> Status
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let t = TrailerScan::new(headers);
        match (t.status(), t.http) {
            (Ok(s), _) => s,
            (Err(_), Some(h)) if h != 200 => {
                Status::new(Code::from_http_status(h), &format!("HTTP status {h}"))
            }
            (Err(e), _) => Status::new(Code::Unknown, &e.to_string()),
        }
    }
}

/// What a header block says about a call's status, before any rule about
/// `:status` is applied.
struct TrailerScan {
    code: Option<Code>,
    bad: bool,
    message: Option<String>,
    http: Option<u16>,
}

impl TrailerScan {
    fn new<I, N, V>(headers: I) -> TrailerScan
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut t = TrailerScan { code: None, bad: false, message: None, http: None };
        for (name, value) in headers {
            let (name, value) = (name.as_ref(), value.as_ref());
            if name.eq_ignore_ascii_case(b"grpc-status") {
                if t.code.is_some() {
                    t.bad = true;
                }
                match parse_decimal(value) {
                    Some(n) => t.code = Some(Code::from_number(n).unwrap_or(Code::Unknown)),
                    None => t.bad = true,
                }
            } else if name.eq_ignore_ascii_case(b"grpc-message") {
                if t.message.is_none() {
                    t.message = Some(decode_message(value));
                }
            } else if name.eq_ignore_ascii_case(b":status") && t.http.is_none() {
                let n = parse_decimal(value).and_then(|n| u16::try_from(n).ok());
                t.http = Some(n.unwrap_or(0));
            }
        }
        t
    }

    /// The status from `grpc-status` and `grpc-message` alone.
    fn status(&self) -> Result<Status, TrailerError> {
        if self.bad {
            return Err(TrailerError::BadStatus);
        }
        let code = self.code.ok_or(TrailerError::MissingStatus)?;
        Ok(Status { code, message: self.message.clone().unwrap_or_default() })
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "{}", self.code)
        } else {
            write!(f, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for Status {}

/// The headers that start a response: `:status` 200 and the content-type.
pub fn response_headers(content_type: &ContentType) -> Vec<(String, String)> {
    vec![(":status".to_string(), "200".to_string()), ("content-type".to_string(), content_type.to_header())]
}

// ---------------------------------------------------------------------
// grpc-message.
// ---------------------------------------------------------------------

/// Percent-encodes status message text for `grpc-message`. Bytes from
/// space to `~` stay as they are, except `%`. Every other byte of the
/// UTF-8 becomes `%` and two capital hex digits. Text longer than
/// [`MAX_STATUS_MESSAGE`] bytes is cut at a character boundary first.
pub fn encode_message(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let text = floor_char(text, MAX_STATUS_MESSAGE);
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
    }
    out
}

/// Decodes a `grpc-message` value. It never fails, as the specification
/// requires. A `%` not followed by two hex digits stays as it is. Bytes
/// that are not UTF-8 become U+FFFD. The text is cut to
/// [`MAX_STATUS_MESSAGE`] bytes at a character boundary.
pub fn decode_message(value: &[u8]) -> String {
    // Enough bytes for the limit and one more character, so the cut below
    // lands where it would on the whole text.
    let cap = MAX_STATUS_MESSAGE + 4;
    let mut bytes = Vec::with_capacity(value.len().min(cap));
    let mut i = 0;
    while i < value.len() && bytes.len() < cap {
        let b = value[i];
        let hi = value.get(i + 1).and_then(|&c| hex(c));
        let lo = value.get(i + 2).and_then(|&c| hex(c));
        if let (b'%', Some(hi), Some(lo)) = (b, hi, lo) {
            bytes.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        bytes.push(b);
        i += 1;
    }
    let text = String::from_utf8_lossy(&bytes);
    floor_char(&text, MAX_STATUS_MESSAGE).to_string()
}

// ---------------------------------------------------------------------
// grpc-timeout.
// ---------------------------------------------------------------------

/// The unit of a `grpc-timeout`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutUnit {
    /// `H`: hours.
    Hours,
    /// `M`: minutes.
    Minutes,
    /// `S`: seconds.
    Seconds,
    /// `m`: milliseconds.
    Millis,
    /// `u`: microseconds.
    Micros,
    /// `n`: nanoseconds.
    Nanos,
}

impl TimeoutUnit {
    /// The letter that names the unit.
    pub fn letter(self) -> u8 {
        match self {
            TimeoutUnit::Hours => b'H',
            TimeoutUnit::Minutes => b'M',
            TimeoutUnit::Seconds => b'S',
            TimeoutUnit::Millis => b'm',
            TimeoutUnit::Micros => b'u',
            TimeoutUnit::Nanos => b'n',
        }
    }

    /// The unit this letter names, if any.
    pub fn from_letter(c: u8) -> Option<TimeoutUnit> {
        Some(match c {
            b'H' => TimeoutUnit::Hours,
            b'M' => TimeoutUnit::Minutes,
            b'S' => TimeoutUnit::Seconds,
            b'm' => TimeoutUnit::Millis,
            b'u' => TimeoutUnit::Micros,
            b'n' => TimeoutUnit::Nanos,
            _ => return None,
        })
    }

    /// How many nanoseconds one unit is.
    pub fn nanos(self) -> u64 {
        match self {
            TimeoutUnit::Hours => 3_600_000_000_000,
            TimeoutUnit::Minutes => 60_000_000_000,
            TimeoutUnit::Seconds => 1_000_000_000,
            TimeoutUnit::Millis => 1_000_000,
            TimeoutUnit::Micros => 1_000,
            TimeoutUnit::Nanos => 1,
        }
    }
}

/// A `grpc-timeout` value: how long the client will wait for the call,
/// counted from when the server receives it. A request without one has no
/// deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Timeout {
    value: u32,
    unit: TimeoutUnit,
}

/// Why a `grpc-timeout` value cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutError {
    /// The number was missing, had more than 8 digits, or held something
    /// other than digits.
    Value,
    /// The unit was missing or not one of `HMSmun`.
    Unit,
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutError::Value => f.write_str("grpc-timeout value is not 1 to 8 digits"),
            TimeoutError::Unit => f.write_str("grpc-timeout unit is not one of HMSmun"),
        }
    }
}

impl std::error::Error for TimeoutError {}

impl Timeout {
    /// A timeout of `value` units, or `None` if `value` is over
    /// [`MAX_TIMEOUT_VALUE`].
    pub fn new(value: u32, unit: TimeoutUnit) -> Option<Timeout> {
        (value <= MAX_TIMEOUT_VALUE).then_some(Timeout { value, unit })
    }

    /// The shortest timeout, in the finest unit that can hold it, that is
    /// at least `d`. A duration over 99,999,999 hours gives that many
    /// hours.
    pub fn from_duration(d: Duration) -> Timeout {
        let nanos = d.as_nanos();
        const UNITS: [TimeoutUnit; 6] = [
            TimeoutUnit::Nanos,
            TimeoutUnit::Micros,
            TimeoutUnit::Millis,
            TimeoutUnit::Seconds,
            TimeoutUnit::Minutes,
            TimeoutUnit::Hours,
        ];
        for unit in UNITS {
            let per = u128::from(unit.nanos());
            let value = nanos / per + u128::from(!nanos.is_multiple_of(per));
            if let Ok(v) = u32::try_from(value)
                && v <= MAX_TIMEOUT_VALUE
            {
                return Timeout { value: v, unit };
            }
        }
        Timeout { value: MAX_TIMEOUT_VALUE, unit: TimeoutUnit::Hours }
    }

    /// Reads a `grpc-timeout` value, such as `100m`. The specification
    /// asks for a positive number, but this reads `0` too, as gRPC's Go
    /// server does: the deadline has already passed.
    pub fn parse(value: &[u8]) -> Result<Timeout, TimeoutError> {
        let Some((&letter, digits)) = value.split_last() else {
            return Err(TimeoutError::Value);
        };
        if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(TimeoutError::Value);
        }
        let unit = TimeoutUnit::from_letter(letter).ok_or(TimeoutError::Unit)?;
        let value = parse_decimal(digits).ok_or(TimeoutError::Value)?;
        Ok(Timeout { value, unit })
    }

    /// The number of units.
    pub fn value(self) -> u32 {
        self.value
    }

    /// The unit.
    pub fn unit(self) -> TimeoutUnit {
        self.unit
    }

    /// The timeout as a duration.
    pub fn as_duration(self) -> Duration {
        let nanos = u128::from(self.value) * u128::from(self.unit.nanos());
        // At most 99,999,999 hours, well within a Duration.
        let secs = u64::try_from(nanos / 1_000_000_000).unwrap_or(u64::MAX);
        Duration::new(secs, (nanos % 1_000_000_000) as u32)
    }

    /// The header value, such as `100m`.
    pub fn to_header(self) -> String {
        format!("{}{}", self.value, char::from(self.unit.letter()))
    }
}

// ---------------------------------------------------------------------
// Content-type, path and request headers.
// ---------------------------------------------------------------------

/// A gRPC content-type: `application/grpc`, maybe with a subtype that
/// names how messages are written, such as `proto` or `json`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct ContentType {
    subtype: Option<String>,
}

impl ContentType {
    /// `application/grpc`, with no subtype. Messages are protobuf.
    pub fn plain() -> ContentType {
        ContentType { subtype: None }
    }

    /// `application/grpc+` and `subtype`. It returns `None` unless the
    /// subtype is 1 to [`MAX_SUBTYPE`] token characters. It is kept in
    /// lower case.
    pub fn with_subtype(subtype: &str) -> Option<ContentType> {
        let s = subtype.as_bytes();
        if s.is_empty() || s.len() > MAX_SUBTYPE || !s.iter().all(|&c| is_token(c)) {
            return None;
        }
        Some(ContentType { subtype: Some(subtype.to_ascii_lowercase()) })
    }

    /// The subtype, such as `proto`, if there is one.
    pub fn subtype(&self) -> Option<&str> {
        self.subtype.as_deref()
    }

    /// Reads a content-type header. It returns `None` unless the value is
    /// `application/grpc`, alone, followed by `+` and a subtype, or
    /// followed by `;` and parameters, which are ignored. Case does not
    /// matter. A server answers `None` with HTTP status 415.
    pub fn parse(value: &[u8]) -> Option<ContentType> {
        const PREFIX: &[u8] = b"application/grpc";
        let value = trim(value);
        let head = value.get(..PREFIX.len())?;
        if !head.eq_ignore_ascii_case(PREFIX) {
            return None;
        }
        let rest = &value[PREFIX.len()..];
        let (subtype, _params) = match rest.iter().position(|&c| c == b';') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, &rest[rest.len()..]),
        };
        // Space may come before the parameters, but not before or inside
        // the subtype.
        match trim(subtype) {
            [] => Some(ContentType::plain()),
            _ if subtype.first() != Some(&b'+') => None,
            [b'+', s @ ..] => ContentType::with_subtype(std::str::from_utf8(s).ok()?),
            _ => None,
        }
    }

    /// The header value, such as `application/grpc+proto`.
    pub fn to_header(&self) -> String {
        match &self.subtype {
            Some(s) => format!("application/grpc+{s}"),
            None => "application/grpc".to_string(),
        }
    }
}

/// A method's `:path`: `/`, the service name, `/`, the method name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MethodPath {
    service: String,
    method: String,
}

impl MethodPath {
    /// The path for this service and method. It returns `None` unless
    /// both are non-empty, hold only printable ASCII other than `/`, and
    /// the path fits in [`MAX_PATH`] bytes.
    pub fn new(service: &str, method: &str) -> Option<MethodPath> {
        let ok = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_graphic() && c != b'/');
        let len = service.len().checked_add(method.len())?.checked_add(2)?;
        if !ok(service) || !ok(method) || len > MAX_PATH {
            return None;
        }
        Some(MethodPath { service: service.to_string(), method: method.to_string() })
    }

    /// Reads a `:path` value. Case matters.
    pub fn parse(path: &[u8]) -> Option<MethodPath> {
        let path = std::str::from_utf8(path).ok()?;
        let (service, method) = path.strip_prefix('/')?.split_once('/')?;
        MethodPath::new(service, method)
    }

    /// The service name, such as `helloworld.Greeter`.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The method name, such as `SayHello`.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The `:path` value.
    pub fn to_path(&self) -> String {
        format!("/{}/{}", self.service, self.method)
    }
}

/// A call's request headers, checked.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The method called.
    pub path: MethodPath,
    /// The content-type. The response uses the same one.
    pub content_type: ContentType,
    /// The `grpc-timeout`, if the client sent one.
    pub timeout: Option<Timeout>,
    /// The `grpc-encoding`: how compressed messages are compressed.
    pub encoding: Option<String>,
    /// `:authority`, the virtual host, if sent.
    pub authority: Option<String>,
    /// Whether `te: trailers` was sent. Clients send it to detect proxies
    /// that drop trailers. This module does not require it.
    pub te_trailers: bool,
    /// Every other header that is not a pseudo-header, in order, with its
    /// name in lower case. Names ending in `-bin` hold base64, which this
    /// module leaves as it is.
    pub metadata: Vec<(String, Vec<u8>)>,
}

/// How a server turns down a request whose headers break the rules.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// Answer with this HTTP status and end the stream, with no gRPC
    /// status. This is for requests that may not be gRPC at all.
    Http(u16),
    /// Answer with [`Status::trailers_only`].
    Status(Status),
}

impl Rejection {
    /// The header block that answers the request and ends the stream.
    pub fn to_headers(&self) -> Vec<(String, String)> {
        match self {
            Rejection::Http(s) => vec![(":status".to_string(), s.to_string())],
            Rejection::Status(s) => s.trailers_only(&ContentType::plain()),
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::Http(s) => write!(f, "HTTP status {s}"),
            Rejection::Status(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for Rejection {}

impl Request {
    /// A request for `path` with this content-type, `te: trailers`, and
    /// no timeout, encoding, authority or metadata.
    pub fn new(path: MethodPath, content_type: ContentType) -> Request {
        Request {
            path,
            content_type,
            timeout: None,
            encoding: None,
            authority: None,
            te_trailers: true,
            metadata: Vec::new(),
        }
    }

    /// The value of the first metadata entry with this name, matched
    /// without regard to case.
    pub fn metadata_value(&self, name: &str) -> Option<&[u8]> {
        self.metadata.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }

    /// Checks a request's headers, in the order they came. Header names
    /// match without regard to case. The rules, in the order they are
    /// checked:
    ///
    /// - A header block over [`MAX_HEADER_LIST`] gets
    ///   `RESOURCE_EXHAUSTED`.
    /// - `:method`, `:path`, `content-type`, `grpc-timeout` or
    ///   `grpc-encoding` twice gets `INTERNAL`.
    /// - A content-type that is missing or not gRPC gets HTTP 415.
    /// - A method other than POST gets HTTP 405.
    /// - A path that is not `/service/method` gets `UNIMPLEMENTED`.
    /// - A malformed `grpc-timeout` gets `INTERNAL`.
    pub fn parse<I, N, V>(headers: I) -> Result<Request, Rejection>
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        const ONCE: [&[u8]; 5] = [b":method", b":path", b"content-type", b"grpc-timeout", b"grpc-encoding"];
        let mut seen: [Option<Vec<u8>>; 5] = Default::default();
        let mut size: usize = 0;
        let mut authority = None;
        let mut te_trailers = false;
        let mut metadata = Vec::new();
        for (name, value) in headers {
            let (name, value) = (name.as_ref(), value.as_ref());
            size = size.saturating_add(name.len()).saturating_add(value.len()).saturating_add(32);
            if size > MAX_HEADER_LIST {
                let msg = format!("request headers over {MAX_HEADER_LIST} bytes");
                return Err(Rejection::Status(Status::new(Code::ResourceExhausted, &msg)));
            }
            if let Some(i) = ONCE.iter().position(|n| name.eq_ignore_ascii_case(n)) {
                if seen[i].is_some() {
                    let msg = format!("duplicate header {}", String::from_utf8_lossy(ONCE[i]));
                    return Err(Rejection::Status(Status::new(Code::Internal, &msg)));
                }
                seen[i] = Some(value.to_vec());
            } else if name.eq_ignore_ascii_case(b":authority") {
                if authority.is_none() {
                    authority = Some(String::from_utf8_lossy(value).into_owned());
                }
            } else if name.eq_ignore_ascii_case(b"te") {
                te_trailers |= trim(value).eq_ignore_ascii_case(b"trailers");
            } else if !name.starts_with(b":") {
                let name = String::from_utf8_lossy(name).to_ascii_lowercase();
                metadata.push((name, value.to_vec()));
            }
        }
        let [method, path, content_type, timeout, encoding] = seen;
        let Some(content_type) = content_type.as_deref().and_then(ContentType::parse) else {
            return Err(Rejection::Http(UNSUPPORTED_MEDIA_TYPE));
        };
        if method.as_deref() != Some(b"POST") {
            return Err(Rejection::Http(METHOD_NOT_ALLOWED));
        }
        let path_bytes = path.unwrap_or_default();
        let Some(path) = MethodPath::parse(&path_bytes) else {
            let msg = format!("unknown method {}", String::from_utf8_lossy(&path_bytes));
            return Err(Rejection::Status(Status::new(Code::Unimplemented, &msg)));
        };
        let timeout = match timeout {
            None => None,
            Some(t) => match Timeout::parse(&t) {
                Ok(t) => Some(t),
                Err(e) => return Err(Rejection::Status(Status::new(Code::Internal, &e.to_string()))),
            },
        };
        let encoding = encoding.map(|e| String::from_utf8_lossy(trim(&e)).into_owned());
        Ok(Request { path, content_type, timeout, encoding, authority, te_trailers, metadata })
    }

    /// The request headers a client sends for this call: method, scheme,
    /// path, `te`, content-type, and the authority, timeout and encoding
    /// when set, then the metadata. [`Request::parse`] always accepts what
    /// this writes. So the authority, the encoding and each metadata value
    /// are written only if they are printable ASCII and fit in
    /// [`MAX_HEADER_LIST`]. Metadata named like a pseudo-header, `te`,
    /// or a header this struct already holds is left out.
    pub fn to_headers(&self) -> Vec<(String, String)> {
        fn size(name: &str, value: &str) -> usize {
            name.len().saturating_add(value.len()).saturating_add(32)
        }
        fn printable(v: &[u8]) -> bool {
            v.iter().all(|c| (0x20..=0x7e).contains(c))
        }
        let path = self.path.to_path();
        let content_type = self.content_type.to_header();
        let timeout = self.timeout.map(Timeout::to_header);
        // The headers always written. With MAX_PATH and MAX_SUBTYPE they
        // come to well under MAX_HEADER_LIST.
        let mut used = size(":method", "POST")
            + size(":scheme", "http")
            + size(":path", &path)
            + size("te", "trailers")
            + size("content-type", &content_type)
            + timeout.as_deref().map_or(0, |t| size("grpc-timeout", t));
        let mut fits = |name: &str, value: &str| {
            let n = size(name, value);
            let ok = printable(value.as_bytes()) && used.saturating_add(n) <= MAX_HEADER_LIST;
            if ok {
                used += n;
            }
            ok
        };
        let authority = self.authority.as_deref().filter(|a| fits(":authority", a));
        let encoding = self.encoding.as_deref().filter(|e| fits("grpc-encoding", e));
        let mut out = vec![
            (":method".to_string(), "POST".to_string()),
            (":scheme".to_string(), "http".to_string()),
            (":path".to_string(), path),
        ];
        if let Some(a) = authority {
            out.push((":authority".to_string(), a.to_string()));
        }
        out.push(("te".to_string(), "trailers".to_string()));
        if let Some(t) = timeout {
            out.push(("grpc-timeout".to_string(), t));
        }
        out.push(("content-type".to_string(), content_type));
        if let Some(e) = encoding {
            out.push(("grpc-encoding".to_string(), e.to_string()));
        }
        for (name, value) in &self.metadata {
            let reserved = name.starts_with(':')
                || ["te", "content-type", "grpc-timeout", "grpc-encoding"]
                    .iter()
                    .any(|r| name.eq_ignore_ascii_case(r));
            if reserved {
                continue;
            }
            if let Ok(v) = std::str::from_utf8(value)
                && fits(name, v)
            {
                out.push((name.clone(), v.to_string()));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------

/// The longest start of `s` that is at most `max` bytes and ends on a
/// character boundary.
fn floor_char(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A decimal number of 1 to 10 digits that fits in a u32.
fn parse_decimal(b: &[u8]) -> Option<u32> {
    if b.is_empty() || b.len() > 10 {
        return None;
    }
    let mut n: u32 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u32::from(c - b'0'))?;
    }
    Some(n)
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn is_token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = b {
        b = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = b {
        b = rest;
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything a decoder gives for `data`, fed `chunk` bytes at a time.
    fn decode(mut d: Decoder, data: &[u8], chunk: usize) -> Vec<Result<Message, FrameError>> {
        let mut out = Vec::new();
        for piece in data.chunks(chunk.max(1)) {
            let mut rest = piece;
            loop {
                let used = d.feed(rest);
                rest = &rest[used..];
                match d.next_message() {
                    Some(Ok(m)) => out.push(Ok(m)),
                    Some(Err(e)) => {
                        out.push(Err(e));
                        return out;
                    }
                    None => break,
                }
            }
            assert!(rest.is_empty());
        }
        out
    }

    /// Everything [`Message::parse`] finds in `data`, one after another.
    fn parse_all(data: &[u8]) -> Vec<Result<Message, FrameError>> {
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            match Message::parse(&data[at..]) {
                Ok(Some((m, used))) => {
                    out.push(Ok(m));
                    at += used;
                }
                Ok(None) => return out,
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        }
    }

    fn strings(h: &[(String, String)]) -> Vec<(&str, &str)> {
        h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
    }

    fn good_request() -> Vec<(&'static str, &'static str)> {
        vec![
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/google.pubsub.v2.PublisherService/CreateTopic"),
            (":authority", "pubsub.googleapis.com"),
            ("grpc-timeout", "1S"),
            ("content-type", "application/grpc+proto"),
            ("grpc-encoding", "gzip"),
            ("authorization", "Bearer y235.wef315yfh138vh31hv93hv8h3v"),
        ]
    }

    #[test]
    fn spec_request_example() {
        // The sample unary call from PROTOCOL-HTTP2.md.
        let r = Request::parse(good_request()).unwrap();
        assert_eq!(r.path.service(), "google.pubsub.v2.PublisherService");
        assert_eq!(r.path.method(), "CreateTopic");
        assert_eq!(r.authority.as_deref(), Some("pubsub.googleapis.com"));
        assert_eq!(r.timeout, Timeout::new(1, TimeoutUnit::Seconds));
        assert_eq!(r.content_type.subtype(), Some("proto"));
        assert_eq!(r.encoding.as_deref(), Some("gzip"));
        assert!(!r.te_trailers);
        assert_eq!(r.metadata, [("authorization".to_string(), b"Bearer y235.wef315yfh138vh31hv93hv8h3v".to_vec())]);
        // What it writes reads back the same, with te added.
        let again = Request::parse(strings(&r.to_headers())).unwrap();
        assert!(again.te_trailers);
        assert_eq!(Request { te_trailers: false, ..again }, r);
    }

    #[test]
    fn spec_response_example() {
        let ct = ContentType::with_subtype("proto").unwrap();
        assert_eq!(
            strings(&response_headers(&ct)),
            [(":status", "200"), ("content-type", "application/grpc+proto")]
        );
        let trailers = [("grpc-status", "0"), ("trace-proto-bin", "jher831yy13JHy3hc")];
        assert_eq!(Status::parse_trailers(trailers), Ok(Status::ok()));
        assert_eq!(strings(&Status::ok().to_trailers()), [("grpc-status", "0")]);
    }

    #[test]
    fn message_framing() {
        let m = Message { compressed: false, data: vec![1, 2, 3] };
        assert_eq!(m.to_bytes(), [0, 0, 0, 0, 3, 1, 2, 3]);
        let c = Message { compressed: true, data: vec![] };
        assert_eq!(c.to_bytes(), [1, 0, 0, 0, 0]);
        let mut stream = m.to_bytes();
        stream.extend(c.to_bytes());
        stream.push(0);
        let (a, used) = Message::parse(&stream).unwrap().unwrap();
        assert_eq!((a, used), (m.clone(), 8));
        let (b, used2) = Message::parse(&stream[8..]).unwrap().unwrap();
        assert_eq!((b, used2), (c.clone(), 5));
        assert_eq!(Message::parse(&stream[13..]), Ok(None));
        assert_eq!(parse_all(&stream), [Ok(m), Ok(c)]);
    }

    #[test]
    fn every_truncated_prefix_waits() {
        let bytes = Message { compressed: true, data: (0..40).collect() }.to_bytes();
        for n in 0..bytes.len() {
            assert_eq!(Message::parse(&bytes[..n]), Ok(None), "{n} bytes");
            let mut d = Decoder::new();
            assert_eq!(d.feed(&bytes[..n]), n);
            assert_eq!(d.next_message(), None);
            assert_eq!(d.buffered(), n);
            if n == 0 {
                assert_eq!(d.finish(), Ok(()));
            } else {
                assert_eq!(d.finish(), Err(FrameError::Truncated { buffered: n }));
            }
        }
        assert!(Message::parse(&bytes).unwrap().is_some());
    }

    #[test]
    fn frame_errors() {
        assert_eq!(Message::parse(&[2]), Err(FrameError::Flag(2)));
        assert_eq!(Message::parse(&[0xff, 0, 0]), Err(FrameError::Flag(0xff)));
        let big = (MAX_MESSAGE as u32 + 1).to_be_bytes();
        let b = [0, big[0], big[1], big[2], big[3]];
        assert_eq!(Message::parse(&b), Err(FrameError::TooLarge { length: MAX_MESSAGE as u32 + 1, limit: MAX_MESSAGE }));
        assert_eq!(Message::parse(&[0, 0xff, 0xff, 0xff, 0xff]), Err(FrameError::TooLarge { length: u32::MAX, limit: MAX_MESSAGE }));
        // Exactly the limit is allowed, and waits for its bytes.
        let at = (MAX_MESSAGE as u32).to_be_bytes();
        assert_eq!(Message::parse(&[0, at[0], at[1], at[2], at[3]]), Ok(None));
        assert_eq!(FrameError::Flag(2).code(), Code::Internal);
        assert_eq!(FrameError::TooLarge { length: 9, limit: 1 }.code(), Code::ResourceExhausted);
        assert_eq!(FrameError::Truncated { buffered: 1 }.to_status().code, Code::Internal);
        assert!(FrameError::TooLarge { length: 9, limit: 1 }.to_string().contains("limit of 1"));
    }

    #[test]
    fn decoder_limit() {
        let mut d = Decoder::with_limit(3);
        assert_eq!(d.limit(), 3);
        let ok = Message { compressed: false, data: vec![1, 2, 3] }.to_bytes();
        let over = Message { compressed: false, data: vec![1, 2, 3, 4] }.to_bytes();
        let mut stream = ok.clone();
        stream.extend(&over);
        let got = decode(Decoder::with_limit(3), &stream, 1);
        assert_eq!(got, [Ok(Message { compressed: false, data: vec![1, 2, 3] }), Err(FrameError::TooLarge { length: 4, limit: 3 })]);
        // Refused as soon as the length is in, before the body.
        assert_eq!(d.feed(&over[..5]), 5);
        assert_eq!(d.next_message(), Some(Err(FrameError::TooLarge { length: 4, limit: 3 })));
        // A broken stream stays broken, takes everything, and holds nothing.
        assert_eq!(d.feed(&ok), ok.len());
        assert_eq!(d.next_message(), Some(Err(FrameError::TooLarge { length: 4, limit: 3 })));
        assert_eq!(d.buffered(), 0);
        assert!(d.finish().is_err());
        assert_eq!(Decoder::with_limit(usize::MAX).limit(), MAX_MESSAGE);
        assert_eq!(Decoder::default().limit(), DEFAULT_MAX_MESSAGE);
    }

    #[test]
    fn decoder_bad_flag_and_waiting_message() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(&[0, 0, 0, 0, 1, 9, 0, 0]), 6);
        assert_eq!(d.feed(&[0, 0]), 0);
        assert_eq!(d.finish(), Ok(()));
        assert_eq!(d.next_message(), Some(Ok(Message { compressed: false, data: vec![9] })));
        assert_eq!(d.next_message(), None);
        assert_eq!(d.feed(&[7, 0]), 2);
        assert_eq!(d.next_message(), Some(Err(FrameError::Flag(7))));
    }

    #[test]
    fn decoder_splits_a_stream() {
        let msgs: Vec<Message> = (0..5u8)
            .map(|i| Message { compressed: i % 2 == 1, data: vec![i; usize::from(i) * 3] })
            .collect();
        let stream: Vec<u8> = msgs.iter().flat_map(Message::to_bytes).collect();
        let want: Vec<_> = msgs.into_iter().map(Ok).collect();
        for chunk in [1, 2, 3, 5, 7, stream.len()] {
            assert_eq!(decode(Decoder::new(), &stream, chunk), want, "chunk {chunk}");
        }
    }

    #[test]
    fn writers_cap_what_they_write() {
        let m = Message { compressed: false, data: vec![1; MAX_MESSAGE + 10] };
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN + MAX_MESSAGE);
        let (back, _) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(back.data.len(), MAX_MESSAGE);
        let long = "é".repeat(MAX_STATUS_MESSAGE);
        let s = Status::new(Code::Internal, &long);
        assert!(s.message.len() <= MAX_STATUS_MESSAGE);
        assert_eq!(Status::parse_trailers(strings(&s.to_trailers())), Ok(s.clone()));
        // A status's trailers fit in a request-sized header block.
        let size: usize = s.trailers_only(&ContentType::plain()).iter().map(|(n, v)| n.len() + v.len() + 32).sum();
        assert!(size <= MAX_HEADER_LIST);
        let enc = encode_message(&"x".repeat(5000));
        assert_eq!(enc.len(), MAX_STATUS_MESSAGE);
    }

    #[test]
    fn compression_flag_rules() {
        let c = Message { compressed: true, data: vec![] };
        let p = Message { compressed: false, data: vec![] };
        assert_eq!(c.check_encoding(Some("gzip")), Ok(()));
        assert_eq!(c.check_encoding(None).unwrap_err().code, Code::Internal);
        assert_eq!(c.check_encoding(Some("identity")).unwrap_err().code, Code::Internal);
        assert_eq!(p.check_encoding(None), Ok(()));
    }

    #[test]
    fn codes() {
        assert_eq!(CODES.len(), 17);
        for n in 0..17 {
            let c = Code::from_number(n).unwrap();
            assert_eq!(c.number(), n);
            assert_eq!(Code::from_name(c.name()), Some(c));
        }
        assert_eq!(Code::from_number(17), None);
        assert_eq!(Code::from_number(u32::MAX), None);
        assert_eq!(Code::from_name("nope"), None);
        assert_eq!(Code::DeadlineExceeded.name(), "DEADLINE_EXCEEDED");
        assert_eq!(Code::Unauthenticated.number(), 16);
        assert_eq!(Code::NotFound.to_string(), "NOT_FOUND");
    }

    #[test]
    fn http_and_rst_stream_mapping() {
        assert_eq!(Code::from_http_status(400), Code::Internal);
        assert_eq!(Code::from_http_status(401), Code::Unauthenticated);
        assert_eq!(Code::from_http_status(403), Code::PermissionDenied);
        assert_eq!(Code::from_http_status(404), Code::Unimplemented);
        for s in [429, 502, 503, 504] {
            assert_eq!(Code::from_http_status(s), Code::Unavailable);
        }
        assert_eq!(Code::from_http_status(500), Code::Unknown);
        assert_eq!(Code::from_rst_stream(0), Some(Code::Internal));
        assert_eq!(Code::from_rst_stream(5), None);
        assert_eq!(Code::from_rst_stream(7), Some(Code::Unavailable));
        assert_eq!(Code::from_rst_stream(8), Some(Code::Cancelled));
        assert_eq!(Code::from_rst_stream(11), Some(Code::ResourceExhausted));
        assert_eq!(Code::from_rst_stream(12), Some(Code::PermissionDenied));
        assert_eq!(Code::from_rst_stream(99), Some(Code::Internal));
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(encode_message("hello world"), "hello world");
        assert_eq!(encode_message("100%"), "100%25");
        assert_eq!(encode_message("a\nb"), "a%0Ab");
        assert_eq!(encode_message("\u{7f}"), "%7F");
        assert_eq!(encode_message("日"), "%E6%97%A5");
        assert_eq!(decode_message(b"%E6%97%A5 ok"), "日 ok");
        assert_eq!(decode_message(b"%e6%97%a5"), "日");
        // Broken escapes stay as they are.
        assert_eq!(decode_message(b"50% off %"), "50% off %");
        assert_eq!(decode_message(b"%4"), "%4");
        assert_eq!(decode_message(b"%zz"), "%zz");
        // Bytes that are not UTF-8 become U+FFFD.
        assert_eq!(decode_message(b"%FF!"), "\u{fffd}!");
        assert_eq!(decode_message(b""), "");
        for s in ["", "plain", "tab\there", "%%%", "naïve 🦀 50%", "~ !$&'()"] {
            assert_eq!(decode_message(encode_message(s).as_bytes()), s);
        }
        let long = "y".repeat(3 * MAX_STATUS_MESSAGE);
        assert_eq!(decode_message(long.as_bytes()).len(), MAX_STATUS_MESSAGE);
    }

    #[test]
    fn timeouts() {
        let t = Timeout::parse(b"100m").unwrap();
        assert_eq!((t.value(), t.unit()), (100, TimeoutUnit::Millis));
        assert_eq!(t.as_duration(), Duration::from_millis(100));
        assert_eq!(t.to_header(), "100m");
        for (s, d) in [
            ("1H", Duration::from_secs(3600)),
            ("2M", Duration::from_secs(120)),
            ("3S", Duration::from_secs(3)),
            ("4u", Duration::from_micros(4)),
            ("5n", Duration::from_nanos(5)),
            ("0n", Duration::ZERO),
            ("00000007S", Duration::from_secs(7)),
        ] {
            let t = Timeout::parse(s.as_bytes()).unwrap();
            assert_eq!(t.as_duration(), d, "{s}");
            assert_eq!(Timeout::parse(t.to_header().as_bytes()), Ok(t));
        }
        let max = Timeout::parse(b"99999999H").unwrap();
        assert_eq!(max.as_duration(), Duration::from_secs(99_999_999 * 3600));
        assert_eq!(Timeout::parse(b""), Err(TimeoutError::Value));
        assert_eq!(Timeout::parse(b"S"), Err(TimeoutError::Value));
        assert_eq!(Timeout::parse(b"123456789S"), Err(TimeoutError::Value));
        assert_eq!(Timeout::parse(b"-1S"), Err(TimeoutError::Value));
        assert_eq!(Timeout::parse(b"1 S"), Err(TimeoutError::Value));
        assert_eq!(Timeout::parse(b"10"), Err(TimeoutError::Unit));
        assert_eq!(Timeout::parse(b"10s"), Err(TimeoutError::Unit));
        assert_eq!(Timeout::new(MAX_TIMEOUT_VALUE + 1, TimeoutUnit::Nanos), None);
    }

    #[test]
    fn timeouts_from_durations() {
        assert_eq!(Timeout::from_duration(Duration::ZERO).to_header(), "0n");
        assert_eq!(Timeout::from_duration(Duration::from_nanos(99_999_999)).to_header(), "99999999n");
        assert_eq!(Timeout::from_duration(Duration::from_nanos(100_000_000)).to_header(), "100000u");
        // Rounded up, never down.
        assert_eq!(Timeout::from_duration(Duration::new(100_000, 1)).to_header(), "100001S");
        assert_eq!(Timeout::from_duration(Duration::MAX).to_header(), "99999999H");
        for d in [Duration::from_millis(1500), Duration::new(7, 3), Duration::from_secs(86_400 * 365 * 10)] {
            let t = Timeout::from_duration(d);
            assert!(t.as_duration() >= d);
            assert_eq!(Timeout::parse(t.to_header().as_bytes()), Ok(t));
        }
    }

    #[test]
    fn content_types() {
        assert_eq!(ContentType::parse(b"application/grpc"), Some(ContentType::plain()));
        assert_eq!(ContentType::parse(b"Application/GRPC+Proto").unwrap().subtype(), Some("proto"));
        assert_eq!(ContentType::parse(b"application/grpc+json; charset=utf-8").unwrap().subtype(), Some("json"));
        assert_eq!(ContentType::parse(b"application/grpc;x=y"), Some(ContentType::plain()));
        assert_eq!(ContentType::parse(b"  application/grpc  "), Some(ContentType::plain()));
        for bad in [&b"application/json"[..], b"application/grpc-web", b"application/grpcx", b"application/grpc+", b"application/grp", b"", b"application/grpc+a b"] {
            assert_eq!(ContentType::parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        let long = format!("application/grpc+{}", "a".repeat(MAX_SUBTYPE + 1));
        assert_eq!(ContentType::parse(long.as_bytes()), None);
        assert_eq!(ContentType::with_subtype(""), None);
        assert_eq!(ContentType::with_subtype("a/b"), None);
        let ct = ContentType::with_subtype("Thrift").unwrap();
        assert_eq!(ct.to_header(), "application/grpc+thrift");
        assert_eq!(ContentType::parse(ct.to_header().as_bytes()), Some(ct));
    }

    #[test]
    fn paths() {
        let p = MethodPath::parse(b"/helloworld.Greeter/SayHello").unwrap();
        assert_eq!(p.to_path(), "/helloworld.Greeter/SayHello");
        for bad in [&b""[..], b"/", b"//", b"/a", b"/a/", b"//b", b"a/b", b"/a/b/c", b"/a b/c", b"/\xff/c"] {
            assert_eq!(MethodPath::parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        assert!(MethodPath::new(&"s".repeat(MAX_PATH), "m").is_none());
        assert!(MethodPath::new(&"s".repeat(MAX_PATH - 3), "m").is_some());
    }

    #[test]
    fn request_rejections() {
        let with = |name: &'static str, value: &'static str| {
            let mut h = good_request();
            h.retain(|(n, _)| *n != name);
            if !value.is_empty() {
                h.push((name, value));
            }
            Request::parse(h)
        };
        assert_eq!(with("content-type", ""), Err(Rejection::Http(415)));
        assert_eq!(with("content-type", "text/html"), Err(Rejection::Http(415)));
        assert_eq!(with(":method", "GET"), Err(Rejection::Http(405)));
        assert_eq!(with(":method", ""), Err(Rejection::Http(405)));
        let code = |r: Result<Request, Rejection>| match r {
            Err(Rejection::Status(s)) => s.code,
            other => panic!("{other:?}"),
        };
        assert_eq!(code(with(":path", "/nope")), Code::Unimplemented);
        assert_eq!(code(with(":path", "")), Code::Unimplemented);
        assert_eq!(code(with("grpc-timeout", "soon")), Code::Internal);
        let mut twice = good_request();
        twice.push((":path", "/a/b"));
        assert_eq!(code(Request::parse(twice)), Code::Internal);
        let mut big = good_request();
        let filler = "v".repeat(MAX_HEADER_LIST);
        big.push(("x-filler", Box::leak(filler.into_boxed_str())));
        assert_eq!(code(Request::parse(big)), Code::ResourceExhausted);
        // Rejections write headers a client can read.
        assert_eq!(strings(&Rejection::Http(415).to_headers()), [(":status", "415")]);
        let r = Rejection::Status(Status::new(Code::Unimplemented, "unknown method /x"));
        let h = r.to_headers();
        assert_eq!(Status::parse_trailers(strings(&h)).unwrap().code, Code::Unimplemented);
        assert!(r.to_string().starts_with("UNIMPLEMENTED"));
    }

    #[test]
    fn trailer_errors_and_synthesis() {
        assert_eq!(Status::parse_trailers([("x", "y")]), Err(TrailerError::MissingStatus));
        assert_eq!(Status::parse_trailers([("grpc-status", "")]), Err(TrailerError::BadStatus));
        assert_eq!(Status::parse_trailers([("grpc-status", "abc")]), Err(TrailerError::BadStatus));
        assert_eq!(Status::parse_trailers([("grpc-status", "99999999999")]), Err(TrailerError::BadStatus));
        assert_eq!(Status::parse_trailers([("grpc-status", "1"), ("grpc-status", "1")]), Err(TrailerError::BadStatus));
        assert_eq!(Status::parse_trailers([(":status", "503")]), Err(TrailerError::HttpStatus(503)));
        assert_eq!(Status::parse_trailers([(":status", "x"), ("grpc-status", "0")]), Err(TrailerError::HttpStatus(0)));
        // Unknown numbers read as UNKNOWN; names match any case.
        assert_eq!(Status::parse_trailers([("GRPC-STATUS", "42")]).unwrap().code, Code::Unknown);
        let s = Status::parse_trailers([(":status", "200"), ("grpc-status", "3"), ("grpc-message", "bad%20arg")]).unwrap();
        assert_eq!(s, Status::new(Code::InvalidArgument, "bad arg"));
        assert_eq!(s.to_string(), "INVALID_ARGUMENT: bad arg");
        assert_eq!(Status::from_trailers([(":status", "503")]).code, Code::Unavailable);
        assert_eq!(Status::from_trailers([(":status", "404")]).code, Code::Unimplemented);
        assert_eq!(Status::from_trailers([("a", "b")]).code, Code::Unknown);
        assert_eq!(Status::from_trailers([("grpc-status", "5")]).code, Code::NotFound);
        assert!(TrailerError::HttpStatus(1).to_string().contains('1'));
    }

    #[test]
    fn status_round_trips() {
        for (code, _) in CODES {
            for msg in ["", "x", "100% wrong\r\n", "ünïcödé"] {
                let s = Status::new(code, msg);
                assert_eq!(Status::parse_trailers(strings(&s.to_trailers())), Ok(s.clone()));
                let only = s.trailers_only(&ContentType::with_subtype("proto").unwrap());
                assert_eq!(Status::parse_trailers(strings(&only)), Ok(s));
            }
        }
    }

    #[test]
    fn grpc_status_wins_over_http_status() {
        // The HTTP mapping is only for responses with no grpc-status.
        let s = Status::from_trailers([(":status", "503"), ("grpc-status", "5"), ("grpc-message", "gone")]);
        assert_eq!(s, Status::new(Code::NotFound, "gone"));
        // With a malformed grpc-status, the HTTP status still maps.
        assert_eq!(Status::from_trailers([(":status", "503"), ("grpc-status", "x")]).code, Code::Unavailable);
        // A 200 with no grpc-status is UNKNOWN.
        assert_eq!(Status::from_trailers([(":status", "200")]).code, Code::Unknown);
    }

    #[test]
    fn content_type_space_before_subtype() {
        assert_eq!(ContentType::parse(b"application/grpc +proto"), None);
        assert_eq!(ContentType::parse(b"application/grpc+ proto"), None);
        assert_eq!(ContentType::parse(b"application/grpc ;charset=utf-8"), Some(ContentType::plain()));
        assert_eq!(ContentType::parse(b"application/grpc+proto ;x"), Some(ContentType::with_subtype("proto").unwrap()));
    }

    #[test]
    fn status_header_name_any_case() {
        assert_eq!(Status::parse_trailers([(":STATUS", "503")]), Err(TrailerError::HttpStatus(503)));
    }

    #[test]
    fn world_author_api() {
        let path = MethodPath::new("helloworld.Greeter", "SayHello").unwrap();
        let mut r = Request::new(path.clone(), ContentType::plain());
        r.metadata.push(("x-user".to_string(), b"ada".to_vec()));
        let back = Request::parse(strings(&r.to_headers())).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.metadata_value("X-User"), Some(&b"ada"[..]));
        assert_eq!(back.metadata_value("x-none"), None);
        // Paths key a map of handlers; decoders copy with a world's state.
        let mut routes = std::collections::HashMap::new();
        routes.insert(path.clone(), 1);
        assert_eq!(routes.get(&back.path), Some(&1));
        let mut d = Decoder::new();
        d.feed(&[0, 0, 0, 0, 2, 7]);
        let mut copy = d.clone();
        assert_eq!(copy, d);
        assert_eq!(copy.feed(&[8]), 1);
        assert_eq!(copy.next_message(), Some(Ok(Message { compressed: false, data: vec![7, 8] })));
        assert_eq!(d.buffered(), 6);
        assert!(Status::ok().is_ok());
        assert!(!Status::new(Code::Aborted, "").is_ok());
        assert_eq!(Message::default().to_bytes(), [0; HEADER_LEN]);
    }

    #[test]
    fn request_writer_output_parses() {
        let mut r = Request::parse(good_request()).unwrap();
        // Metadata the parser would read as something else, or refuse.
        r.metadata.push(("grpc-timeout".to_string(), b"1S".to_vec()));
        r.metadata.push(("Content-Type".to_string(), b"text/html".to_vec()));
        r.metadata.push((":path".to_string(), b"/a/b".to_vec()));
        r.metadata.push(("te".to_string(), b"gzip".to_vec()));
        r.metadata.push(("x-ctl".to_string(), b"a\x01b".to_vec()));
        r.metadata.push(("x-big".to_string(), vec![b'v'; MAX_HEADER_LIST]));
        r.encoding = Some("x".repeat(MAX_HEADER_LIST));
        r.authority = Some("a\nb".to_string());
        let back = Request::parse(strings(&r.to_headers())).unwrap();
        assert_eq!(back.metadata, r.metadata[..1]);
        assert_eq!((back.encoding, back.authority), (None, None));
        // A request near the limit, with no te or :scheme, still writes
        // headers that read back.
        let mut near = vec![(":method", "POST"), (":path", "/a/b"), ("content-type", "application/grpc")];
        let used: usize = near.iter().map(|(n, v)| n.len() + v.len() + 32).sum();
        let filler = "v".repeat(MAX_HEADER_LIST - used - 32 - "x-filler".len());
        near.push(("x-filler", Box::leak(filler.into_boxed_str())));
        let r = Request::parse(near).unwrap();
        assert!(Request::parse(strings(&r.to_headers())).is_ok());
    }

    /// A small linear congruential generator, so the loop is the same on
    /// every run.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u8
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x67_72_70_63);
        for round in 0..4000 {
            let len = usize::from(rng.next()) % 64;
            let mut data: Vec<u8> = (0..len).map(|_| rng.next()).collect();
            // Keep flags and lengths small often, so real messages come up.
            if round % 2 == 0 {
                let mut i = 0;
                while i + HEADER_LEN <= data.len() {
                    data[i] &= 1;
                    data[i + 1] = 0;
                    data[i + 2] = 0;
                    data[i + 3] = 0;
                    data[i + 4] %= 12;
                    i += HEADER_LEN + usize::from(data[i + 4]);
                }
            }
            let want = parse_all(&data);
            let whole = decode(Decoder::with_limit(MAX_MESSAGE), &data, data.len());
            let bytewise = decode(Decoder::with_limit(MAX_MESSAGE), &data, 1);
            assert_eq!(whole, want);
            assert_eq!(bytewise, want);
            for m in want.iter().flatten() {
                let b = m.to_bytes();
                assert_eq!(Message::parse(&b), Ok(Some((m.clone(), b.len()))));
            }
            for n in 0..data.len() {
                let _ = Message::parse(&data[..n]);
            }
            // Header readers on the same bytes.
            if let Ok(t) = Timeout::parse(&data) {
                assert_eq!(Timeout::parse(t.to_header().as_bytes()), Ok(t));
            }
            if let Some(ct) = ContentType::parse(&data) {
                assert_eq!(ContentType::parse(ct.to_header().as_bytes()), Some(ct));
            }
            if let Some(p) = MethodPath::parse(&data) {
                assert_eq!(MethodPath::parse(p.to_path().as_bytes()), Some(p));
            }
            let text = decode_message(&data);
            assert_eq!(decode_message(encode_message(&text).as_bytes()), text);
            let mut parts = data.split(|&b| b == 0);
            let mut headers = Vec::new();
            while let (Some(n), Some(v)) = (parts.next(), parts.next()) {
                headers.push((n, v));
            }
            let synthesized = Status::from_trailers(headers.iter().copied());
            if let Ok(s) = Status::parse_trailers(headers.iter().copied()) {
                // A client uses a status it can read as it is.
                assert_eq!(synthesized, s);
                assert_eq!(Status::parse_trailers(strings(&s.to_trailers())), Ok(s));
            }
            if let Ok(r) = Request::parse(headers.iter().copied()) {
                assert!(Request::parse(strings(&r.to_headers())).is_ok());
            }
        }
    }

    #[test]
    fn fuzz_requests() {
        // Mutations of a good request, so the checks past content-type run.
        let mut rng = Lcg(7);
        let base = good_request();
        for _ in 0..3000 {
            let mut h: Vec<(Vec<u8>, Vec<u8>)> =
                base.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect();
            for _ in 0..1 + rng.next() % 4 {
                let i = usize::from(rng.next()) % h.len();
                let v = &mut h[i].1;
                match rng.next() % 3 {
                    0 if !v.is_empty() => {
                        let j = usize::from(rng.next()) % v.len();
                        v[j] = rng.next();
                    }
                    1 => {
                        let n = usize::from(rng.next()) % (v.len() + 1);
                        v.truncate(n);
                    }
                    _ => v.push(rng.next()),
                }
            }
            match Request::parse(h.iter().map(|(n, v)| (n, v))) {
                Ok(r) => {
                    let again = Request::parse(strings(&r.to_headers())).unwrap();
                    assert_eq!((&again.path, &again.content_type, again.timeout), (&r.path, &r.content_type, r.timeout));
                }
                Err(rej) => {
                    let headers = rej.to_headers();
                    if let Rejection::Status(s) = &rej {
                        assert_eq!(Status::parse_trailers(strings(&headers)).as_ref(), Ok(s));
                    }
                }
            }
        }
    }
}
