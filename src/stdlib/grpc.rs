//! gRPC: message framing, status codes, timeouts and the header rules a
//! server follows, with no I/O.
//!
//! `Message` implements `Wire` and supports `codec::Frames<Message>` for
//! length-prefixed payloads. Header and status helpers do not provide an RPC
//! session, `Service`, HTTP/2 transport, or protobuf decoding. Compressed
//! payloads stay as bytes.
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
//! with [`Request::parse`]. It pushes the stream's DATA bytes into a
//! [`Stream<codec::Frames<Message>>`](fictionet::stdlib::codec::Stream) and gets [`Message`]s back. Each message body stays as
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
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::grpc::{response_headers, Code, Message, Request, Status};
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
//! let mut decoder = Stream::new(Frames::<Message>::new());
//! assert_eq!(decoder.push(&data), data.len());
//! let message = decoder.next().unwrap().unwrap();
//! assert_eq!(message.data, [0x0a, 0x01, b'x']);
//! decoder.end();
//! assert_eq!(decoder.next(), None);
//!
//! // The reply: headers, the same message back, then the status.
//! let headers = response_headers(&request.content_type);
//! assert_eq!(headers[0], (":status".to_string(), "200".to_string()));
//! let reply = Message { compressed: false, data: message.data }.to_bytes().unwrap();
//! assert_eq!(reply, data);
//! let trailers = Status::new(Code::NotFound, "no user 'x'").to_trailers().unwrap();
//! assert_eq!(trailers[0], ("grpc-status".to_string(), "5".to_string()));
//! assert_eq!(trailers[1], ("grpc-message".to_string(), "no user 'x'".to_string()));
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::ascii::{
    self, hex_upper, hex_value as hex, is_tchar as is_token, trim_ows as trim,
};
use fictionet::stdlib::codec::base64::{self, Padding};
use fictionet::stdlib::codec::leb128;
use std::fmt;
use std::time::Duration;

use fictionet::stdlib::codec::{self, Wire};

/// The TCP port gRPC servers most often listen on without TLS. With TLS
/// they usually use 443.
pub const PORT: u16 = 50051;
/// The length of the prefix before each message: a compressed flag and a
/// 4-byte big-endian length.
pub const HEADER_LEN: usize = 5;
/// The longest message this module reads or writes: 16 MiB. The format
/// allows up to 4 GiB, but no decoder here holds more than this.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;
/// The body limit [`codec::Frames<Message>`](fictionet::stdlib::codec::Frames) starts with: 4 MiB, the
/// default most gRPC servers use.
pub const DEFAULT_MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// The largest request header block [`Request::parse`] accepts: 8 KiB, the
/// limit the specification suggests. It is counted as HTTP/2 counts it:
/// each header's name and value lengths, plus 32.
pub const MAX_HEADER_LIST: usize = 8 * 1024;
/// The longest status message, in bytes of UTF-8 text, before
/// percent-encoding. Writers refuse longer text. [`Status::new`] and
/// [`decode_message`] shorten it at a character boundary.
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

/// Why bytes are not a gRPC message stream, trailers do not give a call's
/// status, a `grpc-timeout` value cannot be read, or headers cannot be
/// written. After an error from [`codec::Frames<Message>`](fictionet::stdlib::codec::Frames) the stream holds no more
/// messages a reader can find, and a server ends the call with the status
/// [`Error::code`] gives. [`Status::from_trailers`] turns a trailer error
/// into a status, as a client must.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The compressed flag was neither 0 nor 1.
    Flag(u8),
    /// The length prefix was over the limit.
    TooLarge {
        /// The length the prefix gave.
        length: u32,
        /// The limit it broke.
        limit: usize,
    },
    /// Input ended before a complete message.
    Truncated {
        /// Number of available bytes.
        unread: usize,
    },
    /// Bytes followed the first complete message.
    Trailing {
        /// The number of bytes after the message.
        remaining: usize,
    },
    /// There was no `grpc-status`.
    MissingStatus,
    /// `grpc-status` was not a decimal number without leading zeros, or
    /// came twice.
    BadStatus,
    /// `:status` was not 200. A `:status` that is not a number reads as 0.
    HttpStatus(u16),
    /// The block has a `:status`, so it is a trailers-only response, but
    /// its content-type is missing or not gRPC.
    ContentType,
    /// `grpc-status-details-bin` came with `grpc-status` 0, where the
    /// specification does not allow it, or holds a status code that is
    /// not the one `grpc-status` gives.
    BadDetails,
    /// A `grpc-timeout` number was missing, had more than 8 digits, or
    /// held something other than digits.
    TimeoutValue,
    /// A `grpc-timeout` unit was missing or not one of `HMSmun`.
    TimeoutUnit,
    /// A metadata name is not one or more of `0-9 a-z _ - .`, or is one
    /// the request writes itself (`te`, `content-type`, `grpc-timeout`,
    /// `grpc-encoding`), or one HTTP/2 forbids, such as `connection`.
    Name(String),
    /// A value gRPC does not allow, in the header named: an authority that
    /// is not one or more visible ASCII characters, an encoding that is
    /// not a token, a metadata value that is not printable ASCII or starts
    /// or ends with a space, or a `-bin` value that is not base64.
    Value(String),
    /// The headers come to more than [`MAX_HEADER_LIST`] bytes, counted
    /// as [`Request::parse`] counts them.
    HeadersTooLarge(usize),
}

impl Error {
    /// The status code a server ends the call with: `RESOURCE_EXHAUSTED`
    /// for a message over the limit, and `INTERNAL` otherwise.
    pub fn code(&self) -> Code {
        match self {
            Error::TooLarge { .. } => Code::ResourceExhausted,
            _ => Code::Internal,
        }
    }

    /// The status a server ends the call with, with this error as its
    /// message.
    pub fn to_status(&self) -> Status {
        Status::new(self.code(), &self.to_string())
    }
}

fictionet::error_display!(Error, f, {
    Error::Flag(b) => write!(f, "compressed flag {b}, not 0 or 1"),
    Error::TooLarge { length, limit } => {
        write!(f, "message of {length} bytes, over the limit of {limit}")
    }
    Error::Truncated { unread } => write!(f, "message ended after {unread} bytes"),
    Error::Trailing { remaining } => {
        write!(f, "trailing bytes after the message: {remaining}")
    }
    Error::MissingStatus => f.write_str("no grpc-status"),
    Error::BadStatus => f.write_str("malformed grpc-status"),
    Error::HttpStatus(s) => write!(f, "HTTP status {s}, not 200"),
    Error::ContentType => f.write_str("content-type is not gRPC"),
    Error::BadDetails => f.write_str("grpc-status-details-bin contradicts grpc-status"),
    Error::TimeoutValue => f.write_str("grpc-timeout value is not 1 to 8 digits"),
    Error::TimeoutUnit => f.write_str("grpc-timeout unit is not one of HMSmun"),
    Error::Name(n) => write!(f, "header name {n:?} is not allowed in gRPC metadata"),
    Error::Value(n) => write!(f, "value of header {n:?} is not allowed"),
    Error::HeadersTooLarge(n) => {
        write!(f, "request headers of {n} bytes, over {MAX_HEADER_LIST}")
    }
});

/// The status a server sends when a message stream fails.
/// Protocol failures use [`Error::to_status`]. A truncated message,
/// including a partial length prefix, a stalled decoder, or refused input
/// gives `INTERNAL`.
pub fn fail_status(fail: &codec::Fail<Error>) -> Status {
    match fail {
        codec::Fail::Protocol(error) => error.to_status(),
        codec::Fail::Truncated { .. } | codec::Fail::Stuck { .. } | codec::Fail::Refused { .. } => {
            Status::new(Code::Internal, &fail.to_string())
        }
    }
}

impl Message {
    /// Reads the message at the start of `b`, allowing up to
    /// [`MAX_MESSAGE`] bytes of body. It returns `Ok(None)` if `b` holds
    /// only part of one, and otherwise the message and how many bytes of
    /// `b` it took.
    pub fn parse_prefix(b: &[u8]) -> Result<Option<(Message, usize)>, Error> {
        parse_message(b, MAX_MESSAGE)
    }

    /// Checks the compressed flag against the call's `grpc-encoding`. A
    /// compressed message in a call with no encoding, or with `identity`,
    /// breaks the protocol, and the server ends the call with `INTERNAL`.
    /// Whether the world can decompress a named encoding is up to it. If
    /// it cannot, it usually answers `UNIMPLEMENTED`.
    /// An encoding that is empty or not a token names nothing.
    pub fn check_encoding(&self, encoding: Option<&str>) -> Result<(), Status> {
        let named =
            matches!(encoding, Some(e) if is_coding(e) && !e.eq_ignore_ascii_case("identity"));
        if self.compressed && !named {
            return Err(Status::new(
                Code::Internal,
                "compressed message without a grpc-encoding",
            ));
        }
        Ok(())
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one message with at most [`MAX_MESSAGE`] body bytes.
    /// Returns [`Error::Truncated`] for incomplete input and
    /// [`Error::Trailing`] for extra bytes. A flag other than
    /// 0 or 1 or a body above the limit returns [`Error::Flag`] or
    /// [`Error::TooLarge`]. Compressed
    /// bodies remain flagged bytes.
    fn parse(b: &[u8]) -> Result<Self, Self::ParseError> {
        match Message::parse_prefix(b)? {
            Some((message, used)) if used == b.len() => Ok(message),
            Some((_, used)) => Err(Error::Trailing {
                remaining: b.len().saturating_sub(used),
            }),
            None => Err(Error::Truncated { unread: b.len() }),
        }
    }

    /// Appends a header and at most [`MAX_MESSAGE`] body bytes.
    /// A longer body returns [`Error::TooLarge`] without changing `out`.
    /// Its `length` is the body length, capped at `u32::MAX`. The error's
    /// [`code`](Error::code) is [`Code::ResourceExhausted`]. A stream
    /// accepts the output when its body fits the stream's own limit.
    /// No compression is performed.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let length = message_length(self.data.len())?;
        out.push(u8::from(self.compressed));
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Decodes a call's continuous HTTP/2 DATA payload bytes into messages.
    ///
    /// This decoder owns no input. [`codec::Stream::new`] holds at most
    /// [`HEADER_LEN`] plus [`limit`](fictionet::stdlib::codec::Frames::limit) unread bytes. The five-byte
    /// header suffices to refuse an oversized body. Partial messages return
    /// [`fictionet::stdlib::codec::Step::Need`], including at EOF, so the driver reports
    /// [`codec::Fail::Truncated`]. Compressed bodies remain flagged bytes.
    ///
    /// ```
    /// use fictionet::stdlib::codec::{Frames, Stream, finish, pump};
    ///
    /// let mut stream = Stream::new(Frames::<fictionet::stdlib::grpc::Message>::with_limit(16));
    /// let mut messages = Vec::new();
    /// // Two DATA payloads split the message header.
    /// pump(&mut stream, &[0, 0], |m| messages.push(m))?;
    /// pump(&mut stream, &[0, 0, 2, 7, 8], |m| messages.push(m))?;
    /// finish(&mut stream, |m| messages.push(m))?;
    /// assert_eq!(messages.len(), 1);
    /// assert_eq!(messages.first().map(|m| m.data.as_slice()), Some(&[7, 8][..]));
    /// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::grpc::Error>>(())
    /// ```
    Message => (Message, Error, usize);
    name = "gRPC";
    default { DEFAULT_MAX_MESSAGE }
    normalize(limit) { limit.min(MAX_MESSAGE) }
    capacity(limit) { let limit = *limit;
        HEADER_LEN.saturating_add(limit) }

    /// Reads one message or waits for more bytes. A flag other than 0 or 1
    /// returns [`Error::Flag`]; a declared body above the configured
    /// limit returns [`Error::TooLarge`]. Partial input returns
    /// [`fictionet::stdlib::codec::Step::Need`], including at EOF.
    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        parse_message(input, limit)
    }
}

// Shared prefix parsing. Only a complete, bounded body is copied.
fn parse_message(b: &[u8], limit: usize) -> Result<Option<(Message, usize)>, Error> {
    let Some(&flag) = b.first() else {
        return Ok(None);
    };
    if flag > 1 {
        return Err(Error::Flag(flag));
    }
    let Some(&[_, n0, n1, n2, n3]) = b.get(..HEADER_LEN) else {
        return Ok(None);
    };
    let length = u32::from_be_bytes([n0, n1, n2, n3]);
    let len = match usize::try_from(length) {
        Ok(n) if n <= limit => n,
        _ => return Err(Error::TooLarge { length, limit }),
    };
    let end = HEADER_LEN
        .checked_add(len)
        .ok_or(Error::TooLarge { length, limit })?;
    Ok(b.get(HEADER_LEN..end).map(|data| {
        (
            Message {
                compressed: flag == 1,
                data: data.to_vec(),
            },
            end,
        )
    }))
}

fn message_length(len: usize) -> Result<u32, Error> {
    match u32::try_from(len) {
        Ok(n) if len <= MAX_MESSAGE => Ok(n),
        Ok(n) => Err(Error::TooLarge {
            length: n,
            limit: MAX_MESSAGE,
        }),
        Err(_) => Err(Error::TooLarge {
            length: u32::MAX,
            limit: MAX_MESSAGE,
        }),
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
/// [`Status::new`] clips the message to [`MAX_STATUS_MESSAGE`] bytes at a
/// character boundary. Trailer writers refuse longer struct literal values.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Status {
    /// The status code.
    pub code: Code,
    /// The message, as plain UTF-8 text. It may be empty.
    pub message: String,
}

impl Status {
    /// A status with this code and message. A message longer than
    /// [`MAX_STATUS_MESSAGE`] bytes is cut at a character boundary.
    pub fn new(code: Code, message: &str) -> Status {
        Status {
            code,
            message: clip_text(message, MAX_STATUS_MESSAGE).to_string(),
        }
    }

    /// The status of a call that succeeded, with no message.
    pub fn ok() -> Status {
        Status {
            code: Code::Ok,
            message: String::new(),
        }
    }

    /// Whether the code is `OK`.
    pub fn is_ok(&self) -> bool {
        self.code == Code::Ok
    }

    /// The trailers that end a call: `grpc-status`, then `grpc-message`
    /// if the message is not empty. Custom metadata may follow them. A
    /// message longer than [`MAX_STATUS_MESSAGE`] bytes returns an error.
    pub fn to_trailers(&self) -> Result<Vec<(String, String)>, Error> {
        let mut out = vec![("grpc-status".to_string(), self.code.number().to_string())];
        if !self.message.is_empty() {
            out.push(("grpc-message".to_string(), encode_message(&self.message)?));
        }
        Ok(out)
    }

    /// The single header block of a call that fails before any message:
    /// `:status` 200, the content-type, then the trailers. The HTTP/2
    /// HEADERS frame carrying it ends the stream.
    pub fn trailers_only(
        &self,
        content_type: &ContentType,
    ) -> Result<Vec<(String, String)>, Error> {
        let mut out = response_headers(content_type);
        out.extend(self.to_trailers()?);
        Ok(out)
    }

    /// Reads a status from trailers, or from a trailers-only header block.
    /// A block with a `:status` is read as trailers-only: the status must
    /// be 200 and the content-type gRPC. Header names match without regard
    /// to case. When `grpc-status-details-bin` holds a status code, it must
    /// match `grpc-status`; details that are not base64 of a protobuf
    /// message cannot be checked and are ignored. Other headers are
    /// ignored.
    pub fn parse_trailers<I, N, V>(headers: I) -> Result<Status, Error>
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let t = TrailerScan::new(headers);
        if let Some(h) = t.http {
            if h != 200 {
                return Err(Error::HttpStatus(h));
            }
            if !t.grpc_type {
                return Err(Error::ContentType);
            }
        }
        t.status()
    }

    /// Reads a status the way a client must: as
    /// [`parse_trailers`](Self::parse_trailers) does, but making one up
    /// from what is there when the trailers are broken. These rules follow
    /// gRPC's HTTP mapping document and gRPC's Go client:
    ///
    /// - A trailers-only block whose content-type is missing or not gRPC
    ///   is not a gRPC response. Its `:status` maps through
    ///   [`Code::from_http_status`], whatever `grpc-status` says.
    /// - Otherwise a well-formed `grpc-status` is used, whatever the
    ///   `:status`, unless the status details contradict it, which gives
    ///   `INTERNAL`.
    /// - A malformed or repeated `grpc-status` gives `UNKNOWN`.
    /// - With no `grpc-status`, a non-200 `:status` maps through
    ///   [`Code::from_http_status`], and anything else gives `UNKNOWN`.
    pub fn from_trailers<I, N, V>(headers: I) -> Status
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let t = TrailerScan::new(headers);
        let from_http =
            |h: u16| Status::new(Code::from_http_status(h), &format!("HTTP status {h}"));
        match (t.status(), t.http) {
            (_, Some(h)) if !t.grpc_type && h != 200 => from_http(h),
            (_, Some(_)) if !t.grpc_type => {
                Status::new(Code::Unknown, &Error::ContentType.to_string())
            }
            (Ok(s), _) => s,
            (Err(Error::MissingStatus), Some(h)) if h != 200 => from_http(h),
            (Err(e @ Error::BadDetails), _) => Status::new(Code::Internal, &e.to_string()),
            (Err(e), _) => Status::new(Code::Unknown, &e.to_string()),
        }
    }
}

/// What a header block says about a call's status, before any rule about
/// `:status` is applied.
struct TrailerScan {
    /// The `grpc-status` number as sent.
    code: Option<u32>,
    bad: bool,
    message: Option<String>,
    http: Option<u16>,
    /// Whether the first content-type was gRPC.
    grpc_type: bool,
    seen_type: bool,
    /// Whether any `grpc-status-details-bin` came.
    details: bool,
    /// The status code the details hold, if they could be read and hold
    /// one, as protobuf's int32 reads it.
    details_code: Option<i32>,
    /// Two details values held different codes.
    details_mixed: bool,
}

impl TrailerScan {
    fn new<I, N, V>(headers: I) -> TrailerScan
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut t = TrailerScan {
            code: None,
            bad: false,
            message: None,
            http: None,
            grpc_type: false,
            seen_type: false,
            details: false,
            details_code: None,
            details_mixed: false,
        };
        for (name, value) in headers {
            let (name, value) = (name.as_ref(), value.as_ref());
            if name.eq_ignore_ascii_case(b"grpc-status") {
                if t.code.is_some() {
                    t.bad = true;
                }
                // The specification writes the number without leading zeros.
                let leading_zero = value.len() > 1 && value.first() == Some(&b'0');
                match parse_decimal(value) {
                    Some(n) if !leading_zero => t.code = Some(n),
                    _ => t.bad = true,
                }
            } else if name.eq_ignore_ascii_case(b"grpc-status-details-bin") {
                t.details = true;
                // Values joined with "," are read one by one.
                for piece in value.split(|&c| c == b',') {
                    if let Some(c) = details_code(trim(piece)) {
                        if t.details_code.is_some_and(|d| d != c) {
                            t.details_mixed = true;
                        }
                        t.details_code = Some(c);
                    }
                }
            } else if name.eq_ignore_ascii_case(b"content-type") {
                if !t.seen_type {
                    t.seen_type = true;
                    t.grpc_type = ContentType::parse(value).is_some();
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
    fn status(&self) -> Result<Status, Error> {
        if self.bad {
            return Err(Error::BadStatus);
        }
        let n = self.code.ok_or(Error::MissingStatus)?;
        // protobuf's int32 keeps the low 32 bits of the varint, as here.
        let contradicts = self.details_code.is_some_and(|d| d as u32 != n);
        if self.details && (n == 0 || contradicts || self.details_mixed) {
            return Err(Error::BadDetails);
        }
        let code = Code::from_number(n).unwrap_or(Code::Unknown);
        Ok(Status {
            code,
            message: self.message.clone().unwrap_or_default(),
        })
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
    vec![
        (":status".to_string(), "200".to_string()),
        ("content-type".to_string(), content_type.to_header()),
    ]
}

// ---------------------------------------------------------------------
// grpc-message.
// ---------------------------------------------------------------------

/// Percent-encodes status message text for `grpc-message`. Bytes from
/// space to `~` stay as they are, except `%`. Every other byte of the
/// UTF-8 becomes `%` and two capital hex digits. Text longer than
/// [`MAX_STATUS_MESSAGE`] bytes returns an error.
pub fn encode_message(text: &str) -> Result<String, Error> {
    if text.len() > MAX_STATUS_MESSAGE {
        return Err(Error::Value("grpc-message".into()));
    }
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(hex_upper(b >> 4)));
            out.push(char::from(hex_upper(b)));
        }
    }
    Ok(out)
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
    ascii::percent_decode_into(value, false, &mut bytes, cap);
    let text = String::from_utf8_lossy(&bytes);
    clip_text(&text, MAX_STATUS_MESSAGE).to_string()
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
        Timeout {
            value: MAX_TIMEOUT_VALUE,
            unit: TimeoutUnit::Hours,
        }
    }

    /// Reads a `grpc-timeout` value, such as `100m`. The specification
    /// asks for a positive number, but this reads `0` too, as gRPC's Go
    /// server does: the deadline has already passed.
    pub fn parse(value: &[u8]) -> Result<Timeout, Error> {
        let Some((&letter, digits)) = value.split_last() else {
            return Err(Error::TimeoutValue);
        };
        if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(Error::TimeoutValue);
        }
        let unit = TimeoutUnit::from_letter(letter).ok_or(Error::TimeoutUnit)?;
        let value = parse_decimal(digits).ok_or(Error::TimeoutValue)?;
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
        Some(ContentType {
            subtype: Some(subtype.to_ascii_lowercase()),
        })
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
    /// both are non-empty URI path segments (RFC 3986, section 3.3:
    /// letters, digits, `-._~!$&'()*+,;=:@`, and `%` with two hex digits)
    /// and the path fits in [`MAX_PATH`] bytes.
    pub fn new(service: &str, method: &str) -> Option<MethodPath> {
        let ok = |s: &str| is_segment(s.as_bytes());
        let len = service.len().checked_add(method.len())?.checked_add(2)?;
        if !ok(service) || !ok(method) || len > MAX_PATH {
            return None;
        }
        Some(MethodPath {
            service: service.to_string(),
            method: method.to_string(),
        })
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

/// A request's `:scheme`: gRPC allows `http` and `https`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// `http`: the call runs without TLS.
    #[default]
    Http,
    /// `https`: the call runs over TLS.
    Https,
}

impl Scheme {
    /// The header value, `http` or `https`.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// Reads a `:scheme` value. Case does not matter.
    pub fn parse(value: &[u8]) -> Option<Scheme> {
        if value.eq_ignore_ascii_case(b"http") {
            Some(Scheme::Http)
        } else if value.eq_ignore_ascii_case(b"https") {
            Some(Scheme::Https)
        } else {
            None
        }
    }
}

/// A call's request headers, checked.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The `:scheme`. A request without one reads as `http`.
    pub scheme: Scheme,
    /// The method called.
    pub path: MethodPath,
    /// The content-type. The response uses the same one.
    pub content_type: ContentType,
    /// The `grpc-timeout`, if the client sent one.
    pub timeout: Option<Timeout>,
    /// The `grpc-encoding`: how compressed messages are compressed. It is
    /// always a token. An empty `grpc-encoding` reads as none.
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
    /// status. This is for requests that may not be gRPC at all. The
    /// status should be an error, 400 to 599.
    Http(u16),
    /// Answer with [`Status::trailers_only`].
    Status(Status),
}

impl Rejection {
    /// The header block that answers the request and ends the stream. An
    /// HTTP status outside 400 to 599 returns an error. A status message
    /// above [`MAX_STATUS_MESSAGE`] also returns an error.
    pub fn to_headers(&self) -> Result<Vec<(String, String)>, Error> {
        match self {
            Rejection::Http(s) => {
                if !(400..=599).contains(s) {
                    return Err(Error::Value(":status".into()));
                }
                Ok(vec![(":status".to_string(), s.to_string())])
            }
            Rejection::Status(s) => s.trailers_only(&ContentType::plain()),
        }
    }
}

fictionet::error_display!(Rejection, f, {
    Rejection::Http(s) => write!(f, "HTTP status {s}"),
    Rejection::Status(s) => write!(f, "{s}"),
});

impl Request {
    /// A request for `path` with this content-type, scheme `http`,
    /// `te: trailers`, and no timeout, encoding, authority or metadata.
    pub fn new(path: MethodPath, content_type: ContentType) -> Request {
        Request {
            scheme: Scheme::Http,
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
        self.metadata
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// Checks a request's headers, in the order they came. Header names
    /// match without regard to case. The rules, in the order they are
    /// checked:
    ///
    /// - A header block over [`MAX_HEADER_LIST`] gets
    ///   `RESOURCE_EXHAUSTED`.
    /// - `:method`, `:scheme`, `:path`, `content-type`, `grpc-timeout` or
    ///   `grpc-encoding` twice gets `INTERNAL`.
    /// - A content-type that is missing or not gRPC gets HTTP 415.
    /// - A method other than POST gets HTTP 405.
    /// - A path that is not `/service/method` gets `UNIMPLEMENTED`.
    /// - A `:scheme` other than `http` or `https` gets `INTERNAL`.
    /// - A malformed `grpc-timeout` gets `INTERNAL`.
    /// - A `grpc-encoding` that is not a token gets `INTERNAL`.
    pub fn parse<I, N, V>(headers: I) -> Result<Request, Rejection>
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        const ONCE: [&[u8]; 6] = [
            b":method",
            b":scheme",
            b":path",
            b"content-type",
            b"grpc-timeout",
            b"grpc-encoding",
        ];
        let mut seen: [Option<Vec<u8>>; 6] = Default::default();
        let mut size: usize = 0;
        let mut authority = None;
        let mut te_trailers = false;
        let mut metadata = Vec::new();
        for (name, value) in headers {
            let (name, value) = (name.as_ref(), value.as_ref());
            size = size
                .saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(32);
            if size > MAX_HEADER_LIST {
                let msg = format!("request headers over {MAX_HEADER_LIST} bytes");
                return Err(Rejection::Status(Status::new(
                    Code::ResourceExhausted,
                    &msg,
                )));
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
        let [method, scheme, path, content_type, timeout, encoding] = seen;
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
        let scheme = match scheme {
            None => Scheme::Http,
            Some(s) => match Scheme::parse(&s) {
                Some(s) => s,
                None => {
                    let msg = format!("unsupported scheme {}", String::from_utf8_lossy(&s));
                    return Err(Rejection::Status(Status::new(Code::Internal, &msg)));
                }
            },
        };
        let timeout = match timeout {
            None => None,
            Some(t) => match Timeout::parse(&t) {
                Ok(t) => Some(t),
                Err(e) => {
                    return Err(Rejection::Status(Status::new(
                        Code::Internal,
                        &e.to_string(),
                    )));
                }
            },
        };
        let encoding = match encoding.as_deref().map(trim) {
            None | Some([]) => None,
            Some(e) => match std::str::from_utf8(e) {
                Ok(e) if is_coding(e) => Some(e.to_string()),
                _ => {
                    let msg = format!("malformed grpc-encoding {}", String::from_utf8_lossy(e));
                    return Err(Rejection::Status(Status::new(Code::Internal, &msg)));
                }
            },
        };
        Ok(Request {
            scheme,
            path,
            content_type,
            timeout,
            encoding,
            authority,
            te_trailers,
            metadata,
        })
    }

    /// The request headers a client sends for this call: method, scheme,
    /// path, the authority when set, `te`, the timeout when set, the
    /// content-type, the encoding when set, then the metadata in order.
    /// [`Request::parse`] reads what this writes back as the same request,
    /// with `te_trailers` set. It writes nothing it would have to change:
    /// a header gRPC or HTTP/2 does not allow, or a block over
    /// [`MAX_HEADER_LIST`], is a [`Error`].
    pub fn to_headers(&self) -> Result<Vec<(String, String)>, Error> {
        let mut out = vec![
            (":method".to_string(), "POST".to_string()),
            (":scheme".to_string(), self.scheme.as_str().to_string()),
            (":path".to_string(), self.path.to_path()),
        ];
        if let Some(a) = &self.authority {
            if a.is_empty() || !a.bytes().all(|c| c.is_ascii_graphic()) {
                return Err(Error::Value(":authority".to_string()));
            }
            out.push((":authority".to_string(), a.clone()));
        }
        out.push(("te".to_string(), "trailers".to_string()));
        if let Some(t) = self.timeout {
            out.push(("grpc-timeout".to_string(), t.to_header()));
        }
        out.push(("content-type".to_string(), self.content_type.to_header()));
        if let Some(e) = &self.encoding {
            if !is_coding(e) {
                return Err(Error::Value("grpc-encoding".to_string()));
            }
            out.push(("grpc-encoding".to_string(), e.clone()));
        }
        for (name, value) in &self.metadata {
            let reserved =
                ["te", "content-type", "grpc-timeout", "grpc-encoding"].contains(&name.as_str());
            if !is_metadata_name(name) || reserved || is_connection_header(name) {
                return Err(Error::Name(name.clone()));
            }
            let ok = if name.ends_with("-bin") {
                value
                    .split(|&c| c == b',')
                    .all(|v| base64::is_valid(v, Padding::Optional))
            } else {
                value.iter().all(|c| (0x20..=0x7e).contains(c))
                    && value.first() != Some(&b' ')
                    && value.last() != Some(&b' ')
            };
            // Every byte checked above is ASCII.
            match std::str::from_utf8(value) {
                Ok(v) if ok => out.push((name.clone(), v.to_string())),
                _ => return Err(Error::Value(name.clone())),
            }
        }
        let size = out.iter().fold(0usize, |n, (k, v)| {
            n.saturating_add(k.len())
                .saturating_add(v.len())
                .saturating_add(32)
        });
        if size > MAX_HEADER_LIST {
            return Err(Error::HeadersTooLarge(size));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------

/// The longest start of `s` that is at most `max` bytes and ends on a
/// character boundary.
fn clip_text(s: &str, max: usize) -> &str {
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
    ascii::decimal(b, 10, u64::from(u32::MAX)).map(|n| n as u32)
}

/// Whether `e` can be a content-coding: one or more token characters.
fn is_coding(e: &str) -> bool {
    !e.is_empty() && e.bytes().all(is_token)
}

/// Whether `s` is a non-empty URI path segment: RFC 3986 `pchar`s, with
/// each `%` followed by two hex digits.
fn is_segment(s: &[u8]) -> bool {
    let mut i = 0;
    while let Some(&c) = s.get(i) {
        if c == b'%' {
            let (Some(&h), Some(&l)) = (s.get(i + 1), s.get(i + 2)) else {
                return false;
            };
            if hex(h).is_none() || hex(l).is_none() {
                return false;
            }
            i += 3;
            continue;
        }
        if !(c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&c)) {
            return false;
        }
        i += 1;
    }
    !s.is_empty()
}

/// Whether `name` is a header HTTP/2 forbids: one tied to an HTTP/1
/// connection (RFC 9113, section 8.2.2).
fn is_connection_header(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

/// Whether `name` is a gRPC metadata name: one or more of `0-9 a-z _ - .`.
fn is_metadata_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || b"_-.".contains(&c))
}

/// Reads a protobuf varint. `Err` means the bytes ran out inside it, or it
/// overflowed a u64.
fn varint(b: &mut impl Iterator<Item = u8>) -> Result<u64, ()> {
    leb128::decode_with(|| b.next().ok_or(()), 10, u64::MAX, ())
}

/// The status code in a `grpc-status-details-bin` value: the `code` field
/// (number 1) of a `google.rpc.Status`, the last one if it comes more than
/// once, as protobuf reads it. It is `None` when the value has no code or
/// is not base64 of a protobuf message. It reads the value once, holding
/// nothing.
fn details_code(v: &[u8]) -> Option<i32> {
    let mut b = base64::decoded(v, Padding::Optional)?.peekable();
    let mut code = None;
    loop {
        if b.peek().is_none() {
            return code;
        }
        let tag = varint(&mut b).ok()?;
        if tag >> 3 == 0 || tag >> 3 > 0x1fff_ffff {
            return None;
        }
        let skip = match tag & 7 {
            0 => {
                let n = varint(&mut b).ok()?;
                if tag >> 3 == 1 {
                    // int32 keeps the low 32 bits.
                    code = Some(n as u32 as i32);
                }
                0
            }
            1 => 8,
            2 => varint(&mut b).ok()?,
            5 => 4,
            _ => return None,
        };
        for _ in 0..skip {
            b.next()?;
        }
    }
}

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    /// Borrows header names and values.
    pub fn strings(h: &[(String, String)]) -> Vec<(&str, &str)> {
        h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::harness::strings;
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::codec::Step;
    use fictionet::stdlib::codec::{Decode, Fail, Stream, finish, pump};
    use fictionet::stdlib::test_support;
    use fictionet::stdlib::test_support::contract;

    #[test]
    fn status_details_refuse_varint_overflow() {
        for bytes in [vec![0x80; 11], [vec![0x80; 9], vec![2]].concat()] {
            assert_eq!(varint(&mut bytes.iter().copied()), Err(()));
            let mut message = vec![8];
            message.extend_from_slice(&bytes);
            assert_eq!(details_code(base64::encode(&message).as_bytes()), None);
        }
    }

    #[test]
    fn messages_limits_and_header_refusals() {
        assert_eq!(Frames::<Message>::new(), Frames::<Message>::default());
        assert_eq!(Frames::<Message>::new().limit(), DEFAULT_MAX_MESSAGE);
        for limit in [0, 3, DEFAULT_MAX_MESSAGE, MAX_MESSAGE, usize::MAX] {
            let d = Frames::<Message>::with_limit(limit);
            assert_eq!(d.limit(), limit.min(MAX_MESSAGE));
            assert_eq!(d.capacity(), HEADER_LEN + d.limit());
            assert_eq!(d.held(), 0);
            assert!(d.capacity() <= codec::Buffer::MAX_LIMIT);
        }
        for flag in 2..=255 {
            assert_eq!(
                Frames::<Message>::new().decode(&[flag], false),
                Err(Error::Flag(flag))
            );
        }
        for (limit, header, length) in [
            (0, [0, 0, 0, 0, 1], 1),
            (3, [1, 0, 0, 0, 4], 4),
            (MAX_MESSAGE, [0, 255, 255, 255, 255], u32::MAX),
        ] {
            let mut stream = Stream::new(Frames::<Message>::with_limit(limit));
            for byte in header.iter().take(4) {
                assert_eq!(stream.push(core::slice::from_ref(byte)), 1);
                assert_eq!(stream.next(), None);
                assert_eq!(stream.held(), 0);
            }
            assert_eq!(stream.push(header.get(4..).unwrap()), 1);
            let fail = Fail::Protocol(Error::TooLarge { length, limit });
            assert_eq!(stream.next(), Some(Err(fail.clone())));
            assert_eq!(stream.buffered(), HEADER_LEN);
            assert_eq!(stream.held(), 0);
            assert_eq!(stream.offset(), 0);
            assert_eq!(stream.failed(), Some(&fail));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.push(b"body after failure"), 18);
            assert_eq!(stream.unread(), header);
        }
        let mut empty = Frames::<Message>::with_limit(0);
        for compressed in [false, true] {
            let message = Message {
                compressed,
                data: vec![],
            };
            assert_eq!(
                empty.decode(&message.to_bytes().unwrap(), false),
                Ok(Step::Item(message, HEADER_LEN))
            );
        }
    }

    #[test]
    fn messages_eof_at_every_prefix() {
        let message = Message {
            compressed: true,
            data: b"opaque bytes".to_vec(),
        };
        let bytes = message.to_bytes().unwrap();
        for cut in 0..=bytes.len() {
            let prefix = bytes.get(..cut).unwrap();
            let mut stream = Stream::new(Frames::<Message>::with_limit(message.data.len()));
            assert_eq!(stream.push(prefix), cut);
            stream.end();
            let want = match cut {
                0 => None,
                n if n == bytes.len() => Some(Ok(message.clone())),
                n => Some(Err(Fail::Truncated { unread: n })),
            };
            assert_eq!(stream.next(), want, "prefix {cut}");
            assert_eq!(stream.next(), None);
            assert!(stream.is_done());
            assert_eq!(stream.held(), 0);
        }
    }

    #[test]
    fn messages_bytewise_and_raw_ranges() {
        const LIMIT: usize = 64 * 1024;
        let message = Message {
            compressed: true,
            data: vec![0xa5; LIMIT],
        };
        let bytes = message.to_bytes().unwrap();
        let mut stream = Stream::new(Frames::<Message>::with_limit(LIMIT));
        for (at, byte) in bytes.iter().enumerate() {
            assert_eq!(stream.push(core::slice::from_ref(byte)), 1);
            if at + 1 < bytes.len() {
                assert_eq!(stream.next(), None);
                assert_eq!(stream.buffered(), at + 1);
            }
            assert_eq!(stream.held(), 0);
        }
        assert_eq!(
            stream.with_next(|item, raw, range| {
                assert_eq!(raw, bytes);
                assert_eq!(range, 0..bytes.len() as u64);
                item
            }),
            Some(Ok(message))
        );
        assert_eq!(stream.buffered(), 0);
        finish(&mut stream, |_| panic!("extra message")).unwrap();
    }

    #[test]
    fn message_wire_exact_parse_preserves_prefix_api() {
        let message = Message {
            compressed: true,
            data: vec![0xff, 0, 7],
        };
        let bytes = message.to_bytes().unwrap();
        assert_eq!(<Message as Wire>::parse(&bytes), Ok(message.clone()));
        assert_eq!(Wire::to_bytes(&message), Ok(bytes.clone()));
        for cut in 0..bytes.len() {
            assert_eq!(
                <Message as Wire>::parse(bytes.get(..cut).unwrap()),
                Err(Error::Truncated { unread: cut })
            );
        }
        for tail in [&[0xff][..], &[0, 0, 0, 0, 0]] {
            let joined = [bytes.as_slice(), tail].concat();
            assert_eq!(
                Message::parse_prefix(&joined),
                Ok(Some((message.clone(), bytes.len())))
            );
            assert_eq!(
                <Message as Wire>::parse(&joined),
                Err(Error::Trailing {
                    remaining: tail.len()
                })
            );
        }
        let error = Error::Flag(2);
        assert_eq!(<Message as Wire>::parse(&[2]), Err(error.clone()));
        assert!(core::error::Error::source(&error).is_none());
        let trailing = Error::Trailing { remaining: 1 };
        assert!(core::error::Error::source(&trailing).is_none());
        assert_eq!(trailing.to_string(), "trailing bytes after the message: 1");
    }

    #[test]
    fn message_wire_appends_and_rolls_back() {
        let prefix = [0xaa, 0xbb];
        for compressed in [false, true] {
            let message = Message {
                compressed,
                data: vec![1, 2, 3],
            };
            let mut out = prefix.to_vec();
            message.write(&mut out).unwrap();
            assert_eq!(
                out,
                [prefix.as_slice(), &message.to_bytes().unwrap()].concat()
            );
            contract::check_wire_value(&message);
        }
        let too_large = Message {
            compressed: false,
            data: vec![0; MAX_MESSAGE + 1],
        };
        let mut out = prefix.to_vec();
        assert_eq!(
            too_large.write(&mut out),
            Err(Error::TooLarge {
                length: MAX_MESSAGE as u32 + 1,
                limit: MAX_MESSAGE
            })
        );
        assert_eq!(out, prefix);
        contract::check_wire_value(&too_large);
    }

    #[test]
    fn messages_and_wire_accept_maximum_body() {
        let message = Message {
            compressed: true,
            data: vec![0x42; MAX_MESSAGE],
        };
        let bytes = Wire::to_bytes(&message).unwrap();
        assert_eq!(<Message as Wire>::parse(&bytes), Ok(message.clone()));
        let mut stream = Stream::new(Frames::<Message>::with_limit(usize::MAX));
        assert_eq!(
            pump(&mut stream, &bytes, |item| assert_eq!(item, message)),
            Ok(bytes.len())
        );
        finish(&mut stream, |_| panic!("extra message")).unwrap();
    }

    #[test]
    fn messages_and_wire_contracts() {
        let mut rng = fictionet::stdlib::codec::Lcg::new(0x67_72_70_63);
        for _ in 0..128 {
            let mut data = [0; 64];
            rng.fill(&mut data);
            contract::check_decode(Frames::<Message>::new, &data);
            contract::check_wire::<Message>(&data);

            let mut bytes = Vec::new();
            for payload in data.chunks(8) {
                let message = Message {
                    compressed: rng.coin(),
                    data: payload.to_vec(),
                };
                let encoded = message.to_bytes().unwrap();
                contract::check_wire::<Message>(&encoded);
                bytes.extend(encoded);
            }
            // Exercise accepted messages, small-limit refusals, and every EOF prefix.
            for limit in [0, 7, 8, MAX_MESSAGE] {
                contract::check_decode_with_held_limit(
                    || Frames::<Message>::with_limit(limit),
                    &bytes,
                    0,
                );
                contract::check_decode_with_alloc_limit(
                    || Frames::<Message>::with_limit(limit),
                    &bytes,
                    2 * (HEADER_LEN + limit),
                );
            }
        }
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
        assert_eq!(
            r.metadata,
            [(
                "authorization".to_string(),
                b"Bearer y235.wef315yfh138vh31hv93hv8h3v".to_vec()
            )]
        );
        // What it writes reads back the same, with te added.
        let again = Request::parse(strings(&r.to_headers().unwrap())).unwrap();
        assert!(again.te_trailers);
        assert_eq!(
            Request {
                te_trailers: false,
                ..again
            },
            r
        );
    }

    #[test]
    fn spec_response_example() {
        let ct = ContentType::with_subtype("proto").unwrap();
        assert_eq!(
            strings(&response_headers(&ct)),
            [
                (":status", "200"),
                ("content-type", "application/grpc+proto")
            ]
        );
        let trailers = [
            ("grpc-status", "0"),
            ("trace-proto-bin", "jher831yy13JHy3hc"),
        ];
        assert_eq!(Status::parse_trailers(trailers), Ok(Status::ok()));
        assert_eq!(
            strings(&Status::ok().to_trailers().unwrap()),
            [("grpc-status", "0")]
        );
    }

    #[test]
    fn message_framing() {
        let m = Message {
            compressed: false,
            data: vec![1, 2, 3],
        };
        assert_eq!(m.to_bytes().unwrap(), [0, 0, 0, 0, 3, 1, 2, 3]);
        let c = Message {
            compressed: true,
            data: vec![],
        };
        assert_eq!(c.to_bytes().unwrap(), [1, 0, 0, 0, 0]);
        let mut stream = m.to_bytes().unwrap();
        stream.extend(c.to_bytes().unwrap());
        stream.push(0);
        let (a, used) = Message::parse_prefix(&stream).unwrap().unwrap();
        assert_eq!((a, used), (m.clone(), 8));
        let (b, used2) = Message::parse_prefix(&stream[8..]).unwrap().unwrap();
        assert_eq!((b, used2), (c.clone(), 5));
        assert_eq!(Message::parse_prefix(&stream[13..]), Ok(None));
        contract::check_decode(|| Frames::<Message>::with_limit(MAX_MESSAGE), &stream);
    }

    #[test]
    fn every_truncated_prefix_waits() {
        let bytes = Message {
            compressed: true,
            data: (0..40).collect(),
        }
        .to_bytes()
        .unwrap();
        contract::check_decode(Frames::<Message>::new, &bytes);
        for n in 0..bytes.len() {
            let mut stream = Stream::new(Frames::<Message>::new());
            assert_eq!(stream.push(&bytes[..n]), n);
            assert_eq!(stream.next(), None);
            stream.end();
            assert_eq!(
                stream.next(),
                (n > 0).then_some(Err(Fail::Truncated { unread: n }))
            );
            if let Some(fail) = stream.failed() {
                assert_eq!(fail_status(fail).code, Code::Internal);
            }
            assert_eq!(stream.next(), None);
        }
    }

    #[test]
    fn frame_errors() {
        assert_eq!(Message::parse_prefix(&[2]), Err(Error::Flag(2)));
        assert_eq!(Message::parse_prefix(&[0xff, 0, 0]), Err(Error::Flag(0xff)));
        let big = (MAX_MESSAGE as u32 + 1).to_be_bytes();
        let b = [0, big[0], big[1], big[2], big[3]];
        fictionet::assert_cases!(Message::parse_prefix;
            (&b) => Err(Error::TooLarge { length: MAX_MESSAGE as u32 + 1, limit: MAX_MESSAGE }),
            (&[0, 0xff, 0xff, 0xff, 0xff]) =>
                Err(Error::TooLarge { length: u32::MAX, limit: MAX_MESSAGE }),
        );
        // Exactly the limit is allowed, and waits for its bytes.
        let at = (MAX_MESSAGE as u32).to_be_bytes();
        assert_eq!(
            Message::parse_prefix(&[0, at[0], at[1], at[2], at[3]]),
            Ok(None)
        );
        assert_eq!(Error::Flag(2).code(), Code::Internal);
        assert_eq!(
            Error::TooLarge {
                length: 9,
                limit: 1
            }
            .code(),
            Code::ResourceExhausted
        );
        assert_eq!(Error::Flag(2).to_status().code, Code::Internal);
        for error in [
            Error::Flag(2),
            Error::TooLarge {
                length: 9,
                limit: 1,
            },
        ] {
            assert_eq!(
                fail_status(&Fail::Protocol(error.clone())),
                error.to_status()
            );
        }
        assert_eq!(
            fail_status(&Fail::Stuck {
                unread: HEADER_LEN,
                capacity: HEADER_LEN
            })
            .code,
            Code::Internal
        );
        assert!(
            Error::TooLarge {
                length: 9,
                limit: 1
            }
            .to_string()
            .contains("limit of 1")
        );
    }

    #[test]
    fn stream_limit() {
        let mut stream = Stream::new(Frames::<Message>::with_limit(3));
        let ok = Message {
            compressed: false,
            data: vec![1, 2, 3],
        };
        let over = Message {
            compressed: false,
            data: vec![1, 2, 3, 4],
        }
        .to_bytes()
        .unwrap();
        assert_eq!(stream.push(&ok.to_bytes().unwrap()), 8);
        assert_eq!(stream.next(), Some(Ok(ok)));
        assert_eq!(stream.push(&over[..5]), 5);
        let error = Fail::Protocol(Error::TooLarge {
            length: 4,
            limit: 3,
        });
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
        assert_eq!(stream.push(&over), over.len());
        assert_eq!(
            Frames::<Message>::with_limit(usize::MAX).limit(),
            MAX_MESSAGE
        );
        assert_eq!(Frames::<Message>::default().limit(), DEFAULT_MAX_MESSAGE);
    }

    #[test]
    fn stream_bad_flag_after_message() {
        let mut stream = Stream::new(Frames::<Message>::new());
        assert_eq!(stream.push(&[0, 0, 0, 0, 1, 9, 7, 0]), 8);
        assert_eq!(
            stream.next(),
            Some(Ok(Message {
                compressed: false,
                data: vec![9]
            }))
        );
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::Flag(7)))));
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn stream_splits_a_stream() {
        let msgs: Vec<Message> = (0..5u8)
            .map(|i| Message {
                compressed: i % 2 == 1,
                data: vec![i; usize::from(i) * 3],
            })
            .collect();
        let stream: Vec<u8> = msgs.iter().flat_map(|m| m.to_bytes().unwrap()).collect();
        contract::check_decode(Frames::<Message>::new, &stream);
        let mut decoder = Stream::new(Frames::<Message>::new());
        let mut got = Vec::new();
        codec::pump(&mut decoder, &stream, |message| got.push(message)).unwrap();
        codec::finish(&mut decoder, |message| got.push(message)).unwrap();
        assert_eq!(got, msgs);
    }

    #[test]
    fn writers_cap_what_they_write() {
        // A body over the limit is refused, not cut.
        let m = Message {
            compressed: false,
            data: vec![7; MAX_MESSAGE + 1],
        };
        let e = m.to_bytes().unwrap_err();
        assert_eq!(
            e,
            Error::TooLarge {
                length: MAX_MESSAGE as u32 + 1,
                limit: MAX_MESSAGE
            }
        );
        assert_eq!(e.code(), Code::ResourceExhausted);
        let m = Message {
            compressed: true,
            data: vec![1; MAX_MESSAGE],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + MAX_MESSAGE);
        assert_eq!(Message::parse_prefix(&bytes), Ok(Some((m, bytes.len()))));
        let long = "é".repeat(MAX_STATUS_MESSAGE);
        let s = Status::new(Code::Internal, &long);
        assert!(s.message.len() <= MAX_STATUS_MESSAGE);
        assert_eq!(
            Status::parse_trailers(strings(&s.to_trailers().unwrap())),
            Ok(s.clone())
        );
        // A status's trailers fit in a request-sized header block.
        let size: usize = s
            .trailers_only(&ContentType::plain())
            .unwrap()
            .iter()
            .map(|(n, v)| n.len() + v.len() + 32)
            .sum();
        assert!(size <= MAX_HEADER_LIST);
        assert!(encode_message(&"x".repeat(5000)).is_err());
    }

    #[test]
    fn compression_flag_rules() {
        let c = Message {
            compressed: true,
            data: vec![],
        };
        let p = Message {
            compressed: false,
            data: vec![],
        };
        assert_eq!(c.check_encoding(Some("gzip")), Ok(()));
        assert_eq!(c.check_encoding(None).unwrap_err().code, Code::Internal);
        assert_eq!(
            c.check_encoding(Some("identity")).unwrap_err().code,
            Code::Internal
        );
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
        assert_eq!(encode_message("hello world").unwrap(), "hello world");
        assert_eq!(encode_message("100%").unwrap(), "100%25");
        assert_eq!(encode_message("a\nb").unwrap(), "a%0Ab");
        assert_eq!(encode_message("\u{7f}").unwrap(), "%7F");
        assert_eq!(encode_message("日").unwrap(), "%E6%97%A5");
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
            assert_eq!(decode_message(encode_message(s).unwrap().as_bytes()), s);
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
        assert_eq!(Timeout::parse(b""), Err(Error::TimeoutValue));
        assert_eq!(Timeout::parse(b"S"), Err(Error::TimeoutValue));
        assert_eq!(Timeout::parse(b"123456789S"), Err(Error::TimeoutValue));
        assert_eq!(Timeout::parse(b"-1S"), Err(Error::TimeoutValue));
        assert_eq!(Timeout::parse(b"1 S"), Err(Error::TimeoutValue));
        assert_eq!(Timeout::parse(b"10"), Err(Error::TimeoutUnit));
        assert_eq!(Timeout::parse(b"10s"), Err(Error::TimeoutUnit));
        assert_eq!(
            Timeout::new(MAX_TIMEOUT_VALUE + 1, TimeoutUnit::Nanos),
            None
        );
    }

    #[test]
    fn timeouts_from_durations() {
        fictionet::assert_cases!(|input| Timeout::from_duration(input).to_header();
            (Duration::ZERO) => "0n",
            (Duration::from_nanos(99_999_999)) => "99999999n",
            (Duration::from_nanos(100_000_000)) => "100000u",
            // Rounded up, never down.
            (Duration::new(100_000, 1)) => "100001S",
            (Duration::MAX) => "99999999H",
        );
        for d in [
            Duration::from_millis(1500),
            Duration::new(7, 3),
            Duration::from_secs(86_400 * 365 * 10),
        ] {
            let t = Timeout::from_duration(d);
            assert!(t.as_duration() >= d);
            assert_eq!(Timeout::parse(t.to_header().as_bytes()), Ok(t));
        }
    }

    #[test]
    fn content_types() {
        assert_eq!(
            ContentType::parse(b"application/grpc"),
            Some(ContentType::plain())
        );
        fictionet::assert_cases!(|input| ContentType::parse(input).unwrap().subtype();
            mixed_case: b"Application/GRPC+Proto" => Some("proto"),
            parameters: b"application/grpc+json; charset=utf-8" => Some("json"),
        );
        assert_eq!(
            ContentType::parse(b"application/grpc;x=y"),
            Some(ContentType::plain())
        );
        assert_eq!(
            ContentType::parse(b"  application/grpc  "),
            Some(ContentType::plain())
        );
        for bad in [
            &b"application/json"[..],
            b"application/grpc-web",
            b"application/grpcx",
            b"application/grpc+",
            b"application/grp",
            b"",
            b"application/grpc+a b",
        ] {
            assert_eq!(
                ContentType::parse(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
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
        for bad in [
            &b""[..],
            b"/",
            b"//",
            b"/a",
            b"/a/",
            b"//b",
            b"a/b",
            b"/a/b/c",
            b"/a b/c",
            b"/\xff/c",
        ] {
            assert_eq!(
                MethodPath::parse(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
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
        assert_eq!(
            strings(&Rejection::Http(415).to_headers().unwrap()),
            [(":status", "415")]
        );
        let r = Rejection::Status(Status::new(Code::Unimplemented, "unknown method /x"));
        let h = r.to_headers().unwrap();
        assert_eq!(
            Status::parse_trailers(strings(&h)).unwrap().code,
            Code::Unimplemented
        );
        assert!(r.to_string().starts_with("UNIMPLEMENTED"));
    }

    #[test]
    fn trailer_errors_and_synthesis() {
        fictionet::assert_cases!(Status::parse_trailers;
            ([("x", "y")]) => Err(Error::MissingStatus),
            ([("grpc-status", "")]) => Err(Error::BadStatus),
            ([("grpc-status", "abc")]) => Err(Error::BadStatus),
            ([("grpc-status", "99999999999")]) => Err(Error::BadStatus),
            ([("grpc-status", "1"), ("grpc-status", "1")]) => Err(Error::BadStatus),
            ([(":status", "503")]) => Err(Error::HttpStatus(503)),
            ([(":status", "x"), ("grpc-status", "0")]) => Err(Error::HttpStatus(0)),
        );
        // Unknown numbers read as UNKNOWN; names match any case.
        assert_eq!(
            Status::parse_trailers([("GRPC-STATUS", "42")])
                .unwrap()
                .code,
            Code::Unknown
        );
        let s = Status::parse_trailers([
            (":status", "200"),
            ("content-type", "application/grpc"),
            ("grpc-status", "3"),
            ("grpc-message", "bad%20arg"),
        ])
        .unwrap();
        assert_eq!(s, Status::new(Code::InvalidArgument, "bad arg"));
        assert_eq!(s.to_string(), "INVALID_ARGUMENT: bad arg");
        fictionet::assert_cases!(|input| Status::from_trailers(input).code;
            ([(":status", "503")]) => Code::Unavailable,
            ([(":status", "404")]) => Code::Unimplemented,
            ([("a", "b")]) => Code::Unknown,
            ([("grpc-status", "5")]) => Code::NotFound,
        );
        assert!(Error::HttpStatus(1).to_string().contains('1'));
        assert!(Error::BadDetails.to_string().contains("details"));
    }

    #[test]
    fn status_round_trips() {
        for (code, _) in CODES {
            for msg in ["", "x", "100% wrong\r\n", "ünïcödé"] {
                let s = Status::new(code, msg);
                assert_eq!(
                    Status::parse_trailers(strings(&s.to_trailers().unwrap())),
                    Ok(s.clone())
                );
                let only = s
                    .trailers_only(&ContentType::with_subtype("proto").unwrap())
                    .unwrap();
                assert_eq!(Status::parse_trailers(strings(&only)), Ok(s));
            }
        }
    }

    #[test]
    fn grpc_status_wins_over_http_status() {
        // The HTTP mapping is only for responses with no grpc-status.
        let ct = ("content-type", "application/grpc");
        let s = Status::from_trailers([
            (":status", "503"),
            ct,
            ("grpc-status", "5"),
            ("grpc-message", "gone"),
        ]);
        assert_eq!(s, Status::new(Code::NotFound, "gone"));
        // A response that is not gRPC maps its HTTP status, whatever it says.
        fictionet::assert_cases!(|input| Status::from_trailers(input).code;
            ([(":status", "503"), ("grpc-status", "5")]) => Code::Unavailable,
            ([(":status", "503"), ("grpc-status", "x")]) => Code::Unavailable,
            // A 200 with no grpc-status is UNKNOWN.
            ([(":status", "200")]) => Code::Unknown,
        );
    }

    #[test]
    fn content_type_space_before_subtype() {
        assert_eq!(ContentType::parse(b"application/grpc +proto"), None);
        assert_eq!(ContentType::parse(b"application/grpc+ proto"), None);
        assert_eq!(
            ContentType::parse(b"application/grpc ;charset=utf-8"),
            Some(ContentType::plain())
        );
        assert_eq!(
            ContentType::parse(b"application/grpc+proto ;x"),
            Some(ContentType::with_subtype("proto").unwrap())
        );
    }

    #[test]
    fn status_header_name_any_case() {
        assert_eq!(
            Status::parse_trailers([(":STATUS", "503")]),
            Err(Error::HttpStatus(503))
        );
    }

    #[test]
    fn world_author_api() {
        let path = MethodPath::new("helloworld.Greeter", "SayHello").unwrap();
        let mut r = Request::new(path.clone(), ContentType::plain());
        r.metadata.push(("x-user".to_string(), b"ada".to_vec()));
        let back = Request::parse(strings(&r.to_headers().unwrap())).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.metadata_value("X-User"), Some(&b"ada"[..]));
        assert_eq!(back.metadata_value("x-none"), None);
        // Paths key a map of handlers; decoders copy with a world's state.
        let mut routes = std::collections::HashMap::new();
        routes.insert(path.clone(), 1);
        assert_eq!(routes.get(&back.path), Some(&1));
        let mut stream = Stream::new(Frames::<Message>::new());
        assert_eq!(stream.push(&[0, 0, 0, 0, 2, 7]), 6);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(&[8]), 1);
        assert_eq!(
            stream.next(),
            Some(Ok(Message {
                compressed: false,
                data: vec![7, 8]
            }))
        );
        assert!(Status::ok().is_ok());
        assert!(!Status::new(Code::Aborted, "").is_ok());
        assert_eq!(Message::default().to_bytes().unwrap(), [0; HEADER_LEN]);
    }

    #[test]
    fn request_writer_output_parses() {
        let r = Request::parse(good_request()).unwrap();
        let bad_name = |name: &str| {
            let mut r = r.clone();
            r.metadata.push((name.to_string(), b"x".to_vec()));
            r.to_headers()
        };
        // Names the parser would read as something else, that are not
        // gRPC metadata names, or that HTTP/2 forbids.
        for name in [
            "grpc-timeout",
            "content-type",
            "te",
            "grpc-encoding",
            ":path",
            "Content-Type",
            "X-Test",
            "bad name",
            "",
            "connection",
            "upgrade",
            "transfer-encoding",
        ] {
            assert_eq!(
                bad_name(name),
                Err(Error::Name(name.to_string())),
                "{name:?}"
            );
        }
        let bad_value = |name: &str, value: &[u8]| {
            let mut r = r.clone();
            r.metadata.push((name.to_string(), value.to_vec()));
            r.to_headers()
        };
        for (name, value) in [
            ("x-ctl", &b"a\x01b"[..]),
            ("x-tab", b"a\tb"),
            ("x-lead", b" a"),
            ("x-trail", b"a "),
            ("x-bin", b"!"),
            ("x-bin", b"abcde"),
            ("x-bin", b"ab=c"),
            ("x-bin", b"YQ"),
        ] {
            let got = bad_value(name, value);
            if name == "x-bin" && value == b"YQ" {
                // Unpadded base64 is what gRPC sends.
                assert!(got.is_ok());
            } else {
                assert_eq!(got, Err(Error::Value(name.to_string())), "{name} {value:?}");
            }
        }
        assert!(bad_value("x-bin", b"YQ==,YWI=").is_ok());
        assert!(bad_value("x-empty", b"").is_ok());
        let mut a = r.clone();
        a.authority = Some("a\nb".to_string());
        assert_eq!(a.to_headers(), Err(Error::Value(":authority".to_string())));
        a.authority = Some(String::new());
        assert_eq!(a.to_headers(), Err(Error::Value(":authority".to_string())));
        let mut e = r.clone();
        e.encoding = Some(String::new());
        assert_eq!(
            e.to_headers(),
            Err(Error::Value("grpc-encoding".to_string()))
        );
        // Too many headers is an error, and nothing is left out.
        let mut big = Request::new(MethodPath::new("s", "m").unwrap(), ContentType::plain());
        big.metadata.push(("x-pad".to_string(), vec![b'v'; 7900]));
        big.metadata
            .push(("authorization".to_string(), b"Bearer x".to_vec()));
        assert!(matches!(big.to_headers(), Err(Error::HeadersTooLarge(n)) if n > MAX_HEADER_LIST));
        big.metadata[0].1.truncate(7000);
        let back = Request::parse(strings(&big.to_headers().unwrap())).unwrap();
        assert_eq!(back, big);
        // A request that read in near the limit, with no te or :scheme,
        // grows past it when they are written.
        let mut near = vec![
            (":method", "POST"),
            (":path", "/a/b"),
            ("content-type", "application/grpc"),
        ];
        let used: usize = near.iter().map(|(n, v)| n.len() + v.len() + 32).sum();
        let filler = "v".repeat(MAX_HEADER_LIST - used - 32 - "x-filler".len());
        near.push(("x-filler", Box::leak(filler.into_boxed_str())));
        let r = Request::parse(near).unwrap();
        assert!(matches!(r.to_headers(), Err(Error::HeadersTooLarge(_))));
        assert!(Error::HeadersTooLarge(9000).to_string().contains("9000"));
    }

    #[test]
    fn scheme_is_kept() {
        let r = Request::parse(good_request()).unwrap();
        assert_eq!(r.scheme, Scheme::Https);
        let h = r.to_headers().unwrap();
        assert!(strings(&h).contains(&(":scheme", "https")));
        assert_eq!(Request::parse(strings(&h)).unwrap().scheme, Scheme::Https);
        let mut ftp = good_request();
        ftp.retain(|(n, _)| *n != ":scheme");
        assert_eq!(Request::parse(ftp.clone()).unwrap().scheme, Scheme::Http);
        ftp.push((":scheme", "ftp"));
        assert!(
            matches!(Request::parse(ftp), Err(Rejection::Status(s)) if s.code == Code::Internal)
        );
        let mut twice = good_request();
        twice.push((":scheme", "https"));
        assert!(
            matches!(Request::parse(twice), Err(Rejection::Status(s)) if s.code == Code::Internal)
        );
        assert_eq!(Scheme::parse(b"HTTPS"), Some(Scheme::Https));
        assert_eq!(Scheme::default().as_str(), "http");
    }

    #[test]
    fn status_details_must_agree_with_grpc_status() {
        // "CA4" is base64 for 08 0e: a google.rpc.Status with code 14.
        let t = [("grpc-status", "5"), ("grpc-status-details-bin", "CA4")];
        assert_eq!(Status::parse_trailers(t), Err(Error::BadDetails));
        assert_eq!(Status::from_trailers(t).code, Code::Internal);
        // Details are not allowed with OK.
        let ok = [("grpc-status", "0"), ("grpc-status-details-bin", "")];
        assert_eq!(Status::parse_trailers(ok), Err(Error::BadDetails));
        // Matching details, padded or not, and details with no code, pass.
        for d in ["CA4", "CA4=", "CA4,CA4", "EgF4"] {
            let t = [("grpc-status", "14"), ("grpc-status-details-bin", d)];
            assert_eq!(
                Status::parse_trailers(t).unwrap().code,
                Code::Unavailable,
                "{d}"
            );
        }
        // The last code field wins, as protobuf reads it: 08 05 08 0e.
        let t = [("grpc-status", "5"), ("grpc-status-details-bin", "CAUIDg")];
        assert_eq!(Status::parse_trailers(t), Err(Error::BadDetails));
        // Details that are not base64 or not protobuf cannot be checked.
        for d in ["!!", "CA", "/w"] {
            let t = [("grpc-status", "5"), ("grpc-status-details-bin", d)];
            assert_eq!(
                Status::parse_trailers(t).unwrap().code,
                Code::NotFound,
                "{d}"
            );
        }
        // A code over 31 bits compares as protobuf's int32 does.
        let t = [
            ("grpc-status", "5"),
            ("grpc-status-details-bin", "CIWAgIAQ"),
        ];
        assert_eq!(Status::parse_trailers(t).unwrap().code, Code::NotFound);
    }

    #[test]
    fn trailers_only_needs_a_grpc_content_type() {
        let html = [
            (":status", "200"),
            ("content-type", "text/html"),
            ("grpc-status", "0"),
        ];
        assert_eq!(Status::parse_trailers(html), Err(Error::ContentType));
        assert_eq!(Status::from_trailers(html).code, Code::Unknown);
        let none = [(":status", "200"), ("grpc-status", "0")];
        assert_eq!(Status::parse_trailers(none), Err(Error::ContentType));
        let html503 = [
            (":status", "503"),
            ("content-type", "text/html"),
            ("grpc-status", "0"),
        ];
        assert_eq!(Status::from_trailers(html503).code, Code::Unavailable);
        // Trailers after the response headers carry no :status or content-type.
        assert_eq!(
            Status::parse_trailers([("grpc-status", "0")]),
            Ok(Status::ok())
        );
    }

    #[test]
    fn malformed_grpc_status_is_unknown_whatever_the_http_status() {
        let t = [
            (":status", "503"),
            ("content-type", "application/grpc"),
            ("grpc-status", "x"),
        ];
        assert_eq!(Status::from_trailers(t).code, Code::Unknown);
        let t = [
            (":status", "503"),
            ("content-type", "application/grpc"),
            ("grpc-status", "1"),
            ("grpc-status", "1"),
        ];
        assert_eq!(Status::from_trailers(t).code, Code::Unknown);
    }

    #[test]
    fn grpc_status_with_leading_zeros_is_malformed() {
        for v in ["00", "05", "014"] {
            assert_eq!(
                Status::parse_trailers([("grpc-status", v)]),
                Err(Error::BadStatus),
                "{v}"
            );
            assert_eq!(
                Status::from_trailers([("grpc-status", v)]).code,
                Code::Unknown,
                "{v}"
            );
        }
        assert_eq!(
            Status::parse_trailers([("grpc-status", "0")]),
            Ok(Status::ok())
        );
        assert_eq!(
            Status::parse_trailers([("grpc-status", "10")])
                .unwrap()
                .code,
            Code::Aborted
        );
    }

    #[test]
    fn empty_or_malformed_encoding_names_nothing() {
        let c = Message {
            compressed: true,
            data: vec![],
        };
        for e in ["", " ", "gz ip", "gzip,br", "a\u{1}"] {
            assert_eq!(
                c.check_encoding(Some(e)).unwrap_err().code,
                Code::Internal,
                "{e:?}"
            );
        }
        let with = |v: &'static str| {
            let mut h = good_request();
            h.retain(|(n, _)| *n != "grpc-encoding");
            h.push(("grpc-encoding", v));
            Request::parse(h)
        };
        // An empty grpc-encoding is the same as none.
        assert_eq!(with("").unwrap().encoding, None);
        assert_eq!(with("  ").unwrap().encoding, None);
        assert_eq!(with(" gzip ").unwrap().encoding.as_deref(), Some("gzip"));
        for bad in ["gz ip", "gzip,br", "a/b"] {
            match with(bad) {
                Err(Rejection::Status(s)) => assert_eq!(s.code, Code::Internal, "{bad}"),
                other => panic!("{bad}: {other:?}"),
            }
        }
    }

    #[test]
    fn method_paths_hold_only_uri_path_characters() {
        for bad in [
            "Call#frag",
            "Call?x=1",
            "a\\b",
            "50%",
            "%zz",
            "%4",
            "a\"b",
            "a{b}",
            "a|b",
            "a^b",
            "a`b",
            "a[0]",
            "<a>",
        ] {
            assert_eq!(MethodPath::new("svc", bad), None, "{bad}");
            assert_eq!(MethodPath::new(bad, "m"), None, "{bad}");
        }
        for good in ["SayHello", "a.b_c-d~e", "x%2Fy", "a:b@c!$&'()*+,;="] {
            let p = MethodPath::new("svc", good).unwrap();
            assert_eq!(MethodPath::parse(p.to_path().as_bytes()), Some(p), "{good}");
        }
    }

    #[test]
    fn http_rejections_require_a_final_error_status() {
        for code in [0, 103, 200, 65535] {
            assert!(Rejection::Http(code).to_headers().is_err());
        }
        for (code, expected) in [(400, "400"), (599, "599")] {
            assert_eq!(
                strings(&Rejection::Http(code).to_headers().unwrap()),
                [(":status", expected)]
            );
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x67_72_70_63);
        for round in 0..4000 {
            let mut data = rng.bytes(63);
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
            contract::check_decode(|| Frames::<Message>::with_limit(MAX_MESSAGE), &data);
            contract::check_wire::<Message>(&data);
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
            assert_eq!(
                decode_message(encode_message(&text).unwrap().as_bytes()),
                text
            );
            let mut parts = data.split(|&b| b == 0);
            let mut headers = Vec::new();
            while let (Some(n), Some(v)) = (parts.next(), parts.next()) {
                headers.push((n, v));
            }
            let synthesized = Status::from_trailers(headers.iter().copied());
            if let Ok(s) = Status::parse_trailers(headers.iter().copied()) {
                // A client uses a status it can read as it is.
                assert_eq!(synthesized, s);
                assert_eq!(
                    Status::parse_trailers(strings(&s.to_trailers().unwrap())),
                    Ok(s)
                );
            }
            if let Ok(r) = Request::parse(headers.iter().copied())
                && let Ok(h) = r.to_headers()
            {
                assert_eq!(
                    Request::parse(strings(&h)),
                    Ok(Request {
                        te_trailers: true,
                        ..r
                    })
                );
            }
        }
    }

    #[test]
    fn fuzz_requests() {
        // Mutations of a good request, so the checks past content-type run.
        let mut rng = Lcg::new(7);
        let base = good_request();
        for _ in 0..3000 {
            let mut h: Vec<(Vec<u8>, Vec<u8>)> = base
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect();
            for _ in 0..1 + rng.below(4) {
                let i = rng.index(h.len());
                let v = &mut h[i].1;
                test_support::mutate(&mut rng, v);
            }
            match Request::parse(h.iter().map(|(n, v)| (n, v))) {
                Ok(r) => {
                    // What can be written reads back the same.
                    if let Ok(h) = r.to_headers() {
                        assert_eq!(
                            Request::parse(strings(&h)),
                            Ok(Request {
                                te_trailers: true,
                                ..r
                            })
                        );
                    }
                }
                Err(rej) => {
                    let headers = rej.to_headers().unwrap();
                    if let Rejection::Status(s) = &rej {
                        assert_eq!(Status::parse_trailers(strings(&headers)).as_ref(), Ok(s));
                    }
                }
            }
        }
    }
}
