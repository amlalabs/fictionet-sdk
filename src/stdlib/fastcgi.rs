//! FastCGI: reading and writing records, name and value pairs, and whole
//! requests and responses, with no I/O.
//!
//! FastCGI is how a web server hands a request to an application running
//! in a separate process, such as PHP-FPM behind nginx. The web server
//! opens a connection, usually TCP port 9000 or a Unix socket, and sends
//! each request as a series of records: one that begins the request, a
//! stream of CGI parameters (`SCRIPT_FILENAME`, `REQUEST_METHOD` and the
//! like), and a stream holding the request body. The application answers
//! with a stream of output, which starts with CGI headers, and a record
//! that ends the request. Several requests can share one connection, told
//! apart by their request ID. This module follows the FastCGI
//! Specification 1.0.
//!
//! Nothing here reads a socket. A world that plays an application feeds
//! the bytes it reads from a connection to [`Frames`] with
//! [`super::codec::Stream`], gets [`Record`]s back, and hands each one
//! to a [`Server`], which puts the streams of each request back
//! together and gives a [`Request`] once all of it has come. The world
//! writes the bytes of the [`Response`] it chooses back to the
//! connection and tells the server with [`Server::end`]. A world that
//! plays a web server does the reverse with [`Request::to_bytes`] and a
//! [`Client`].
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Each stream a request carries has a size limit, and so do the
//! bytes a decoder holds, the stream bytes held across all open requests,
//! and the number of requests open at once.
//!
//! Use [`Frames`] with [`super::codec::Stream`] for bounded input, explicit
//! EOF handling and errors reported once.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, finish, pump};
//! use fictionet::stdlib::fastcgi::{Frames, Request, Role, Server, ServerEvent};
//!
//! // What a web server sends for GET /hello: two parameters and no body.
//! let sent = Request {
//!     id: 1,
//!     role: Role::Responder,
//!     keep_conn: false,
//!     params: vec![
//!         (b"REQUEST_METHOD".to_vec(), b"GET".to_vec()),
//!         (b"SCRIPT_NAME".to_vec(), b"/hello".to_vec()),
//!     ],
//!     stdin: Vec::new(),
//!     data: Vec::new(),
//! }
//! .to_bytes();
//!
//! let mut stream = Stream::new(Frames::new());
//! let mut server = Server::new();
//! let mut reply = Vec::new();
//! pump(&mut stream, &sent, |record| {
//!     match server.receive(&record) {
//!         Ok(Some(ServerEvent::Request(req))) => {
//!             assert_eq!(req.param(b"SCRIPT_NAME"), Some(&b"/hello"[..]));
//!             let page = b"Content-Type: text/plain\r\n\r\nhello".to_vec();
//!             reply.extend(req.respond(page).to_bytes());
//!             // END_REQUEST has gone out, so the request ID is free again.
//!             server.end(req.id);
//!         }
//!         Ok(_) => {}
//!         Err(e) => panic!("{e}"),
//!     }
//! }).unwrap();
//! finish(&mut stream, |_| unreachable!()).unwrap();
//! // The reply starts with a STDOUT record for request 1: 33 bytes of
//! // output and 7 of padding.
//! assert_eq!(reply[..8], [1, 6, 0, 1, 0, 33, 7, 0]);
//! ```

extern crate alloc;

use super::codec::{Decode, Step, Wire};
use alloc::{collections::BTreeMap, vec::Vec};

/// The TCP port FastCGI applications such as PHP-FPM listen on by
/// convention. The specification names no port.
pub const PORT: u16 = 9000;
/// The protocol version every record carries.
pub const VERSION: u8 = 1;
/// The length of a record header.
pub const HEADER_LEN: usize = 8;
/// The most content one record can carry.
pub const MAX_CONTENT: usize = 0xffff;
/// The most padding one record can carry.
pub const MAX_PADDING: usize = 0xff;
/// The longest record: the header, the most content and the most padding.
pub const MAX_RECORD: usize = HEADER_LEN + MAX_CONTENT + MAX_PADDING;
/// The request ID of management records, which belong to no request.
pub const NULL_REQUEST_ID: u16 = 0;

/// The most name and value pairs one stream or record may hold.
pub const MAX_PAIRS: usize = 1024;
/// The longest name or value a pair can carry: its length field has 31
/// bits.
pub const MAX_PAIR_LEN: usize = 0x7fff_ffff;
/// The most bytes of encoded parameters one request may carry.
pub const MAX_PARAMS: usize = 256 * 1024;
/// The most bytes one STDIN, DATA, STDOUT or STDERR stream may carry.
pub const MAX_STREAM: usize = 8 * 1024 * 1024;
/// The most requests a [`Server`] or [`Client`] keeps open at once.
pub const MAX_REQUESTS: usize = 32;
/// The most stream bytes a [`Server`] or [`Client`] holds across all the
/// requests it is putting together. It is room for two of the largest
/// requests, so each limit on its own can be reached.
pub const MAX_HELD: usize = 4 * MAX_STREAM;
/// The most bytes a [`Decoder`] holds that have not been taken out as
/// records. The largest request [`Request::to_bytes`] writes fits, so it
/// can be fed in one go.
pub const MAX_BUFFERED: usize = 4 * MAX_STREAM;

/// How much content each record of a stream carries when this module
/// writes one. A multiple of 8, so the records need no padding.
const CHUNK: usize = MAX_CONTENT - 7;

/// Record types.
pub mod kind {
    /// Starts a request. Its body is a [`super::BeginRequest`].
    pub const BEGIN_REQUEST: u8 = 1;
    /// The web server gives up on a request. It has no body.
    pub const ABORT_REQUEST: u8 = 2;
    /// Ends a request. Its body is a [`super::EndRequest`].
    pub const END_REQUEST: u8 = 3;
    /// A piece of the stream of CGI parameters, as name and value pairs.
    pub const PARAMS: u8 = 4;
    /// A piece of the request body.
    pub const STDIN: u8 = 5;
    /// A piece of the application's output.
    pub const STDOUT: u8 = 6;
    /// A piece of the application's error output.
    pub const STDERR: u8 = 7;
    /// A piece of the file a filter works on.
    pub const DATA: u8 = 8;
    /// A management record asking for the values of some names.
    pub const GET_VALUES: u8 = 9;
    /// A management record answering GET_VALUES.
    pub const GET_VALUES_RESULT: u8 = 10;
    /// A management record saying a management type was not known.
    pub const UNKNOWN_TYPE: u8 = 11;
}

/// The names a GET_VALUES record may ask about.
pub mod values {
    /// How many connections the application accepts at once.
    pub const MAX_CONNS: &[u8] = b"FCGI_MAX_CONNS";
    /// How many requests the application accepts at once.
    pub const MAX_REQS: &[u8] = b"FCGI_MAX_REQS";
    /// "1" if the application runs several requests on one connection.
    pub const MPXS_CONNS: &[u8] = b"FCGI_MPXS_CONNS";
}

/// The flag in a BEGIN_REQUEST body that asks the application to keep the
/// connection open after the request.
pub const KEEP_CONN: u8 = 1;

/// A name and a value, as raw bytes.
pub type Pair = (Vec<u8>, Vec<u8>);

/// One record: the header's fields and the content it carries. The
/// header's version is always [`VERSION`] and its content length is the
/// content's, so neither is kept. Padding bytes are ignored on reading and
/// written as zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The record type, one of [`kind`].
    pub kind: u8,
    /// The request it belongs to, or [`NULL_REQUEST_ID`] for a management
    /// record.
    pub request_id: u16,
    /// What the record carries.
    pub content: Vec<u8>,
    /// How many padding bytes follow the content.
    pub padding: u8,
}

/// Why bytes are not a FastCGI record. The connection holds no more
/// records a reader can find, and a real application closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The version byte was not 1.
    Version(u8),
    /// A [`Decoder`] was fed more than [`MAX_BUFFERED`] bytes without
    /// records being taken out.
    TooLong,
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecordError::Version(v) => write!(f, "FastCGI version {v}, not 1"),
            RecordError::TooLong => write!(f, "more than {MAX_BUFFERED} bytes buffered"),
        }
    }
}

impl core::error::Error for RecordError {}

impl Record {
    /// A record carrying `content`, padded to a multiple of 8 bytes as the
    /// specification recommends. Content past [`MAX_CONTENT`] is cut off.
    pub fn new(kind: u8, request_id: u16, content: &[u8]) -> Record {
        let content = &content[..content.len().min(MAX_CONTENT)];
        let padding = ((8 - content.len() % 8) % 8) as u8;
        Record { kind, request_id, content: content.to_vec(), padding }
    }

    /// Reads the record at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the record and how many bytes
    /// of `b` it took, padding included.
    pub fn parse(b: &[u8]) -> Result<Option<(Record, usize)>, RecordError> {
        // A bad version is known from the first byte.
        match b.first() {
            None => return Ok(None),
            Some(&v) if v != VERSION => return Err(RecordError::Version(v)),
            Some(_) => {}
        }
        if b.len() < HEADER_LEN {
            return Ok(None);
        }
        let content_len = usize::from(be16(b, 4));
        let padding = b[6];
        let content_end = HEADER_LEN + content_len;
        let end = content_end + usize::from(padding);
        if b.len() < end {
            return Ok(None);
        }
        let record =
            Record { kind: b[1], request_id: be16(b, 2), content: b[HEADER_LEN..content_end].to_vec(), padding };
        Ok(Some((record, end)))
    }

    /// The record's bytes: the header, the content and the padding.
    /// Content longer than [`MAX_CONTENT`] is cut to that length, since no
    /// record can hold more.
    pub fn to_bytes(&self) -> Vec<u8> {
        let content = &self.content[..self.content.len().min(MAX_CONTENT)];
        let mut out = Vec::with_capacity(HEADER_LEN + content.len() + usize::from(self.padding));
        out.push(VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.push(self.padding);
        out.push(0);
        out.extend_from_slice(content);
        out.resize(out.len() + usize::from(self.padding), 0);
        out
    }

    /// Whether this is a management record: one with request ID 0.
    pub fn is_management(&self) -> bool {
        self.request_id == NULL_REQUEST_ID
    }

    /// A BEGIN_REQUEST record for request `id`.
    pub fn begin_request(id: u16, body: BeginRequest) -> Record {
        Record::new(kind::BEGIN_REQUEST, id, &body.to_bytes())
    }

    /// An ABORT_REQUEST record for request `id`.
    pub fn abort_request(id: u16) -> Record {
        Record::new(kind::ABORT_REQUEST, id, &[])
    }

    /// An END_REQUEST record for request `id`.
    pub fn end_request(id: u16, body: EndRequest) -> Record {
        Record::new(kind::END_REQUEST, id, &body.to_bytes())
    }

    /// The UNKNOWN_TYPE management record that answers a management record
    /// of type `unknown`.
    pub fn unknown_type(unknown: u8) -> Record {
        Record::new(kind::UNKNOWN_TYPE, NULL_REQUEST_ID, &[unknown, 0, 0, 0, 0, 0, 0, 0])
    }

    /// A GET_VALUES management record asking for `names`. Names that do
    /// not fit in one record are left out.
    pub fn get_values(names: &[&[u8]]) -> Record {
        let (bytes, _) = encode_pairs_within(names.iter().map(|n| (*n, &[][..])), MAX_CONTENT);
        Record::new(kind::GET_VALUES, NULL_REQUEST_ID, &bytes)
    }

    /// A GET_VALUES_RESULT management record answering with `pairs`.
    /// Pairs that do not fit in one record are left out.
    pub fn get_values_result(pairs: &[Pair]) -> Record {
        let (bytes, _) = encode_pairs_within(borrowed(pairs), MAX_CONTENT);
        Record::new(kind::GET_VALUES_RESULT, NULL_REQUEST_ID, &bytes)
    }
}

/// Why an exact [`Wire`] parse did not read one complete FastCGI record.
/// [`Record::parse`] keeps its prefix parsing behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordParseError {
    /// The record header is invalid.
    Record(RecordError),
    /// The input ended before a complete record, including empty input.
    Truncated,
    /// Bytes follow the first complete record.
    Trailing,
}

impl core::fmt::Display for RecordParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Record(e) => e.fmt(f),
            Self::Truncated => f.write_str("input ended before a complete FastCGI record"),
            Self::Trailing => f.write_str("bytes follow the FastCGI record"),
        }
    }
}

impl core::error::Error for RecordParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Record(e) => Some(e),
            Self::Truncated | Self::Trailing => None,
        }
    }
}

/// Why a record cannot be written without losing content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordWriteError {
    /// The content exceeds [`MAX_CONTENT`] bytes.
    TooLong,
}

impl core::fmt::Display for RecordWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "record content exceeds {MAX_CONTENT} bytes")
    }
}

impl core::error::Error for RecordWriteError {}

impl Wire for Record {
    type ParseError = RecordParseError;
    type WriteError = RecordWriteError;

    /// Reads exactly one record. Incomplete input and trailing bytes are errors.
    fn parse(b: &[u8]) -> Result<Self, RecordParseError> {
        match Self::parse(b).map_err(RecordParseError::Record)? {
            Some((record, used)) if used == b.len() => Ok(record),
            Some(_) => Err(RecordParseError::Trailing),
            None => Err(RecordParseError::Truncated),
        }
    }

    /// Appends at most [`MAX_RECORD`] bytes. Leaves `out` unchanged on error.
    /// Unlike [`Record::to_bytes`], this refuses content that would be clipped.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), RecordWriteError> {
        if self.content.len() > MAX_CONTENT {
            return Err(RecordWriteError::TooLong);
        }
        out.extend_from_slice(&self.to_bytes());
        Ok(())
    }
}

/// Why a bounded FastCGI frame stream cannot continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The record header is invalid.
    Record(RecordError),
    /// The record exceeds the configured limit, including padding.
    TooLong {
        /// The record length, including its header and padding.
        length: usize,
        /// The maximum accepted record length.
        limit: usize,
    },
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Record(e) => e.fmt(f),
            Self::TooLong { length, limit } => write!(f, "record length {length} exceeds {limit}"),
        }
    }
}

impl core::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Record(e) => Some(e),
            Self::TooLong { .. } => None,
        }
    }
}

fn parse_record_limited(b: &[u8], limit: usize) -> Result<Option<(Record, usize)>, FrameError> {
    // Preserve Record::parse error ordering: Version comes before TooLong.
    if let Some(&version) = b.first()
        && version != VERSION
    {
        return Err(FrameError::Record(RecordError::Version(version)));
    }
    if let Some(&[_, _, _, _, hi, lo, padding, _]) = b.get(..HEADER_LEN) {
        // The two length fields bound this sum by MAX_RECORD.
        let length = HEADER_LEN
            .saturating_add(usize::from(u16::from_be_bytes([hi, lo])))
            .saturating_add(usize::from(padding));
        if length > limit {
            return Err(FrameError::TooLong { length, limit });
        }
    }
    Record::parse(b).map_err(FrameError::Record)
}

/// Reads FastCGI records without holding input bytes.
///
/// Use with [`super::codec::Stream`] for input bounded by [`Self::limit`].
/// Partial records return [`Step::Need`], including at EOF. The stream reports
/// truncation at EOF and framing errors once. Body parsing stays separate.
///
/// ```
/// use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
/// use fictionet::stdlib::fastcgi::{Frames, Record, kind};
///
/// let record = Record { kind: kind::STDIN, request_id: 1, content: vec![7, 8], padding: 0 };
/// let bytes = Wire::to_bytes(&record)?;
/// let mut stream = Stream::new(Frames::new());
/// let mut records = Vec::new();
/// pump(&mut stream, &bytes[..3], |record| records.push(record))?;
/// pump(&mut stream, &bytes[3..], |record| records.push(record))?;
/// finish(&mut stream, |record| records.push(record))?;
/// assert_eq!(records, [record]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Accepts records up to [`MAX_RECORD`] bytes, including padding.
    pub fn new() -> Self {
        Self::with_limit(MAX_RECORD)
    }

    /// Sets the record limit, including its header and padding.
    /// Clamps it to [`HEADER_LEN`] through [`MAX_RECORD`]. The header alone
    /// suffices to refuse an oversized record.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.clamp(HEADER_LEN, MAX_RECORD) }
    }

    /// The maximum record length, including its header and padding.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Frames {
    type Item = Record;
    type Error = FrameError;
    const NAME: &'static str = "FastCGI";

    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Record>, FrameError> {
        Ok(match parse_record_limited(input, self.limit)? {
            Some((record, used)) => Step::Item(record, used),
            None => Step::Need,
        })
    }
}

/// Splits a FastCGI byte stream into records. Feed it the bytes a
/// connection reads, in order, and take records out until it has none.
/// It holds at most [`MAX_BUFFERED`] bytes that have not been taken out.
///
/// This compatibility decoder keeps its original feed limits and repeated
/// errors. Use [`Frames`] with [`super::codec::Stream`] for EOF handling
/// and errors reported once.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small records costs time in proportion to their bytes.
    start: usize,
    failed: Option<RecordError>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection. If they would make the decoder
    /// hold more than [`MAX_BUFFERED`] bytes, the stream breaks with
    /// [`RecordError::TooLong`], so take records out between feeds. After
    /// a [`RecordError`] the stream cannot be read any further, and bytes
    /// are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() && self.buffered().saturating_add(bytes.len()) > MAX_BUFFERED {
            self.failed = Some(RecordError::TooLong);
            self.buf = Vec::new();
            self.start = 0;
        }
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next whole record, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken.
    pub fn next_record(&mut self) -> Option<Result<Record, RecordError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match Record::parse(&self.buf[self.start..]) {
            Ok(Some((record, used))) => {
                self.start += used;
                Some(Ok(record))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a record.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

/// Why a record's content is not the body its type needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyError;

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("record body is not 8 bytes")
    }
}

impl core::error::Error for BodyError {}

/// The role a request asks the application to play. Roles compare by
/// number, so `Role::Other(1)` equals `Role::Responder`.
#[derive(Clone, Copy, Debug)]
pub enum Role {
    /// Role 1: answer an HTTP request, like a CGI program.
    Responder,
    /// Role 2: decide whether an HTTP request may go ahead. It gets
    /// parameters but no body.
    Authorizer,
    /// Role 3: answer with a filtered version of a file, which comes as the
    /// DATA stream after the body.
    Filter,
    /// Any other role.
    Other(u16),
}

impl PartialEq for Role {
    fn eq(&self, other: &Role) -> bool {
        self.code() == other.code()
    }
}

impl Eq for Role {}

impl Role {
    /// The role's number.
    pub fn code(self) -> u16 {
        match self {
            Role::Responder => 1,
            Role::Authorizer => 2,
            Role::Filter => 3,
            Role::Other(c) => c,
        }
    }

    /// The role for number `c`.
    pub fn from_code(c: u16) -> Role {
        match c {
            1 => Role::Responder,
            2 => Role::Authorizer,
            3 => Role::Filter,
            c => Role::Other(c),
        }
    }
}

/// The body of a BEGIN_REQUEST record: 8 bytes, of which the last 5 are
/// reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeginRequest {
    /// The role the application is to play.
    pub role: Role,
    /// Flags; [`KEEP_CONN`] is the only one defined.
    pub flags: u8,
}

impl BeginRequest {
    /// Reads a BEGIN_REQUEST body. The reserved bytes may hold anything.
    pub fn parse(content: &[u8]) -> Result<BeginRequest, BodyError> {
        if content.len() != 8 {
            return Err(BodyError);
        }
        Ok(BeginRequest { role: Role::from_code(be16(content, 0)), flags: content[2] })
    }

    /// The body's 8 bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let [a, b] = self.role.code().to_be_bytes();
        [a, b, self.flags, 0, 0, 0, 0, 0]
    }

    /// Whether the web server asks to keep the connection open after this
    /// request.
    pub fn keep_conn(&self) -> bool {
        self.flags & KEEP_CONN != 0
    }
}

/// How a request ended, as far as the protocol goes. Statuses compare by
/// number, so `ProtocolStatus::Other(0)` equals
/// `ProtocolStatus::RequestComplete`.
#[derive(Clone, Copy, Debug)]
pub enum ProtocolStatus {
    /// Status 0: the request ran.
    RequestComplete,
    /// Status 1: the application refused a second request on a connection,
    /// since it runs one request per connection.
    CantMpxConn,
    /// Status 2: the application is out of some resource.
    Overloaded,
    /// Status 3: the application does not play the role asked for.
    UnknownRole,
    /// Any other status.
    Other(u8),
}

impl PartialEq for ProtocolStatus {
    fn eq(&self, other: &ProtocolStatus) -> bool {
        self.code() == other.code()
    }
}

impl Eq for ProtocolStatus {}

impl ProtocolStatus {
    /// The status's number.
    pub fn code(self) -> u8 {
        match self {
            ProtocolStatus::RequestComplete => 0,
            ProtocolStatus::CantMpxConn => 1,
            ProtocolStatus::Overloaded => 2,
            ProtocolStatus::UnknownRole => 3,
            ProtocolStatus::Other(c) => c,
        }
    }

    /// The status for number `c`.
    pub fn from_code(c: u8) -> ProtocolStatus {
        match c {
            0 => ProtocolStatus::RequestComplete,
            1 => ProtocolStatus::CantMpxConn,
            2 => ProtocolStatus::Overloaded,
            3 => ProtocolStatus::UnknownRole,
            c => ProtocolStatus::Other(c),
        }
    }
}

/// The body of an END_REQUEST record: 8 bytes, of which the last 3 are
/// reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndRequest {
    /// The application's exit status, as a CGI program's would be.
    pub app_status: u32,
    /// How the request ended, as far as the protocol goes.
    pub protocol_status: ProtocolStatus,
}

impl EndRequest {
    /// Reads an END_REQUEST body. The reserved bytes may hold anything.
    pub fn parse(content: &[u8]) -> Result<EndRequest, BodyError> {
        if content.len() != 8 {
            return Err(BodyError);
        }
        let app_status = u32::from_be_bytes([content[0], content[1], content[2], content[3]]);
        Ok(EndRequest { app_status, protocol_status: ProtocolStatus::from_code(content[4]) })
    }

    /// The body's 8 bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let [a, b, c, d] = self.app_status.to_be_bytes();
        [a, b, c, d, self.protocol_status.code(), 0, 0, 0]
    }
}

/// Reads the body of an UNKNOWN_TYPE record: the type that was not known.
pub fn parse_unknown_type(content: &[u8]) -> Result<u8, BodyError> {
    if content.len() != 8 {
        return Err(BodyError);
    }
    Ok(content[0])
}

/// Why bytes are not a list of name and value pairs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairError {
    /// A length, name or value runs past the end of the bytes.
    Truncated,
    /// There are more than [`MAX_PAIRS`] pairs.
    TooMany,
}

impl core::fmt::Display for PairError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PairError::Truncated => f.write_str("name and value pair runs past the end"),
            PairError::TooMany => write!(f, "more than {MAX_PAIRS} name and value pairs"),
        }
    }
}

impl core::error::Error for PairError {}

/// Reads name and value pairs. Each pair is the name's length, the
/// value's length, the name and the value. A length below 128 takes one
/// byte; a longer one takes four, with the top bit of the first set.
pub fn parse_pairs(b: &[u8]) -> Result<Vec<Pair>, PairError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if out.len() >= MAX_PAIRS {
            return Err(PairError::TooMany);
        }
        let (name_len, at) = read_len(b, i)?;
        let (value_len, at) = read_len(b, at)?;
        let name_end = at.checked_add(name_len).filter(|&e| e <= b.len()).ok_or(PairError::Truncated)?;
        let value_end = name_end.checked_add(value_len).filter(|&e| e <= b.len()).ok_or(PairError::Truncated)?;
        out.push((b[at..name_end].to_vec(), b[name_end..value_end].to_vec()));
        i = value_end;
    }
    Ok(out)
}

/// Writes name and value pairs, each length in one byte if it is below
/// 128 and in four otherwise. Pairs past the first [`MAX_PAIRS`] are left
/// out, and so is any pair with a name or value longer than
/// [`MAX_PAIR_LEN`], so [`parse_pairs`] always reads the output.
pub fn encode_pairs(pairs: &[Pair]) -> Vec<u8> {
    encode_pairs_within(borrowed(pairs), usize::MAX).0
}

/// The pairs as borrowed names and values.
fn borrowed(pairs: &[Pair]) -> impl Iterator<Item = (&[u8], &[u8])> {
    pairs.iter().map(|(n, v)| (n.as_slice(), v.as_slice()))
}

/// Like [`encode_pairs`], but also leaves out each pair that would take the
/// output past `max` bytes. It returns the bytes and where each pair in
/// them ends. Nothing is copied but the pairs written.
fn encode_pairs_within<'a>(pairs: impl Iterator<Item = (&'a [u8], &'a [u8])>, max: usize) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::new();
    let mut ends = Vec::new();
    let mut count = 0;
    for (name, value) in pairs {
        if count >= MAX_PAIRS {
            break;
        }
        if name.len() > MAX_PAIR_LEN || value.len() > MAX_PAIR_LEN {
            continue;
        }
        let size = len_size(name.len())
            .checked_add(len_size(value.len()))
            .and_then(|s| s.checked_add(name.len()))
            .and_then(|s| s.checked_add(value.len()))
            .and_then(|s| s.checked_add(out.len()));
        match size {
            Some(total) if total <= max => {}
            _ => continue,
        }
        write_len(&mut out, name.len());
        write_len(&mut out, value.len());
        out.extend_from_slice(name);
        out.extend_from_slice(value);
        ends.push(out.len());
        count += 1;
    }
    (out, ends)
}

fn len_size(n: usize) -> usize {
    if n < 0x80 { 1 } else { 4 }
}

fn write_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        out.extend_from_slice(&(n as u32 | 0x8000_0000).to_be_bytes());
    }
}

/// The length at `b[i..]` and where the bytes after it start.
fn read_len(b: &[u8], i: usize) -> Result<(usize, usize), PairError> {
    let first = *b.get(i).ok_or(PairError::Truncated)?;
    if first < 0x80 {
        return Ok((usize::from(first), i + 1));
    }
    let four = b.get(i..).and_then(|r| r.get(..4)).ok_or(PairError::Truncated)?;
    let n = u32::from_be_bytes([four[0], four[1], four[2], four[3]]) & 0x7fff_ffff;
    let n = usize::try_from(n).map_err(|_| PairError::Truncated)?;
    Ok((n, i + 4))
}

/// Appends the records of a stream: the data in records of at most
/// [`MAX_CONTENT`] bytes, then the empty record that ends the stream.
fn write_stream(out: &mut Vec<u8>, kind: u8, id: u16, data: &[u8]) {
    for chunk in data.chunks(CHUNK) {
        out.extend(Record::new(kind, id, chunk).to_bytes());
    }
    out.extend(Record::new(kind, id, &[]).to_bytes());
}

/// Appends the records of a PARAMS stream holding `bytes`, whose pairs end
/// at `ends`. Each record ends at the end of a pair when one fits, since
/// some applications, PHP-FPM among them, read the pairs of each PARAMS
/// record on their own. A pair too long for one record spans records.
fn write_params(out: &mut Vec<u8>, id: u16, bytes: &[u8], ends: &[usize]) {
    let mut start = 0;
    while start < bytes.len() {
        let limit = start.saturating_add(CHUNK).min(bytes.len());
        // The last pair end that fits, or the limit if none does.
        let at = ends.partition_point(|&e| e <= limit);
        let cut = match at.checked_sub(1).map(|i| ends[i]) {
            Some(e) if e > start => e,
            _ => limit,
        };
        out.extend(Record::new(kind::PARAMS, id, &bytes[start..cut]).to_bytes());
        start = cut;
    }
    out.extend(Record::new(kind::PARAMS, id, &[]).to_bytes());
}

/// The bytes of a whole stream of type `kind` for request `id`: the data
/// in as many records as it needs, then the empty record that ends the
/// stream. The data is cut to the limit a [`Server`] or [`Client`] takes
/// for the stream: [`MAX_PARAMS`] bytes for PARAMS and [`MAX_STREAM`] for
/// the others.
pub fn stream_bytes(kind: u8, id: u16, data: &[u8]) -> Vec<u8> {
    let limit = if kind == kind::PARAMS { MAX_PARAMS } else { MAX_STREAM };
    let mut out = Vec::new();
    write_stream(&mut out, kind, id, &data[..data.len().min(limit)]);
    out
}

/// A whole request: the BEGIN_REQUEST body and every stream it carries,
/// put back together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The request ID. 0 belongs to management records, so
    /// [`Request::to_bytes`] writes 0 as 1.
    pub id: u16,
    /// The role the application is to play.
    pub role: Role,
    /// Whether the web server asks to keep the connection open afterward.
    pub keep_conn: bool,
    /// The CGI parameters, in the order they came.
    pub params: Vec<Pair>,
    /// The request body. An authorizer gets none.
    pub stdin: Vec<u8>,
    /// The file a filter works on. Other roles get none.
    pub data: Vec<u8>,
}

impl Request {
    /// The value of the first parameter called `name`.
    pub fn param(&self, name: &[u8]) -> Option<&[u8]> {
        self.params.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
    }

    /// The bytes a web server sends for this request: BEGIN_REQUEST, then
    /// the PARAMS stream, then the STDIN stream unless the role is
    /// [`Role::Authorizer`], then the DATA stream if the role is
    /// [`Role::Filter`]. A role given as [`Role::Other`] with the number of
    /// a named role is written as that role. Any other role is written with
    /// a STDIN stream, and a [`Server`] refuses it with
    /// [`StreamError::UnknownRole`]. Parameters that would take the PARAMS
    /// stream past [`MAX_PARAMS`] bytes are left out, and STDIN and DATA
    /// are cut to [`MAX_STREAM`] bytes, so a [`Server`] takes the whole of
    /// what is written. Each PARAMS record holds whole pairs, unless a pair
    /// is too long for one record.
    pub fn to_bytes(&self) -> Vec<u8> {
        let id = self.id.max(1);
        // `Role::Other(3)` is the filter role too, and carries DATA.
        let role = Role::from_code(self.role.code());
        let begin = BeginRequest { role, flags: if self.keep_conn { KEEP_CONN } else { 0 } };
        let mut out = Record::begin_request(id, begin).to_bytes();
        let (params, ends) = encode_pairs_within(borrowed(&self.params), MAX_PARAMS);
        write_params(&mut out, id, &params, &ends);
        if role != Role::Authorizer {
            write_stream(&mut out, kind::STDIN, id, &self.stdin[..self.stdin.len().min(MAX_STREAM)]);
        }
        if role == Role::Filter {
            write_stream(&mut out, kind::DATA, id, &self.data[..self.data.len().min(MAX_STREAM)]);
        }
        out
    }

    /// A response to this request that writes `stdout` and ends with
    /// application status 0.
    pub fn respond(&self, stdout: Vec<u8>) -> Response {
        Response {
            id: self.id,
            stdout,
            stderr: Vec::new(),
            app_status: 0,
            protocol_status: ProtocolStatus::RequestComplete,
        }
    }
}

/// A whole response: the STDOUT and STDERR streams of one request and how
/// it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The request ID. [`Response::to_bytes`] writes 0 as 1.
    pub id: u16,
    /// The output: CGI headers, a blank line, then the body.
    pub stdout: Vec<u8>,
    /// Error output, which a web server usually logs.
    pub stderr: Vec<u8>,
    /// The application's exit status.
    pub app_status: u32,
    /// How the request ended, as far as the protocol goes.
    pub protocol_status: ProtocolStatus,
}

impl Response {
    /// The bytes an application sends for this response: the STDOUT
    /// stream, the STDERR stream if it holds anything, and END_REQUEST.
    /// Each stream is cut to [`MAX_STREAM`] bytes, so a [`Client`] takes
    /// the whole of what is written.
    pub fn to_bytes(&self) -> Vec<u8> {
        let id = self.id.max(1);
        let mut out = Vec::new();
        write_stream(&mut out, kind::STDOUT, id, &self.stdout[..self.stdout.len().min(MAX_STREAM)]);
        if !self.stderr.is_empty() {
            write_stream(&mut out, kind::STDERR, id, &self.stderr[..self.stderr.len().min(MAX_STREAM)]);
        }
        let end = EndRequest { app_status: self.app_status, protocol_status: self.protocol_status };
        out.extend(Record::end_request(id, end).to_bytes());
        out
    }
}

/// Why a record cannot be taken into a request.
///
/// For a [`Server`], an error about a request whose streams were coming in
/// drops what it held, and later records for it are ignored. The request
/// stays open, as the specification keeps its ID active, until the
/// application sends END_REQUEST and calls [`Server::end`]. A request
/// refused at its BEGIN_REQUEST ([`StreamError::Body`],
/// [`StreamError::UnknownRole`] or [`StreamError::TooManyRequests`]) is
/// not opened.
///
/// For a [`Client`], an error drops the output gathered for the request,
/// and its later STDOUT and STDERR records and its END_REQUEST are
/// ignored. [`StreamError::TooManyRequests`] keeps nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// A record's content is not what its type needs: a BEGIN_REQUEST or
    /// END_REQUEST body that is not 8 bytes, or PARAMS or GET_VALUES that
    /// are not name and value pairs.
    Body {
        /// The request.
        id: u16,
        /// The record type.
        kind: u8,
    },
    /// A request asks for a role a [`Server`] does not play. The
    /// application answers with [`ProtocolStatus::UnknownRole`].
    UnknownRole {
        /// The request.
        id: u16,
        /// The role asked for.
        role: u16,
    },
    /// [`MAX_REQUESTS`] are already open. The request is not taken, and an
    /// application answers with [`ProtocolStatus::Overloaded`].
    TooManyRequests {
        /// The request.
        id: u16,
    },
    /// A stream grew past its limit: [`MAX_PARAMS`] for PARAMS and
    /// [`MAX_STREAM`] for the others. Or the stream bytes held across all
    /// open requests grew past [`MAX_HELD`].
    TooLarge {
        /// The request.
        id: u16,
        /// The record type.
        kind: u8,
    },
    /// A BEGIN_REQUEST came for a request that was already open. The new
    /// one is refused. If the first one's streams were still coming in,
    /// they are dropped, and the first stays open until [`Server::end`].
    Duplicate {
        /// The request.
        id: u16,
    },
    /// A stream record came after the record that ended the stream.
    AfterEnd {
        /// The request.
        id: u16,
        /// The record type.
        kind: u8,
    },
    /// A stream record came before the streams that go ahead of it had
    /// ended. A web server sends PARAMS, then STDIN, then DATA.
    OutOfOrder {
        /// The request.
        id: u16,
        /// The record type.
        kind: u8,
    },
}

impl StreamError {
    /// The request the error is about.
    pub fn id(&self) -> u16 {
        match *self {
            StreamError::Body { id, .. }
            | StreamError::UnknownRole { id, .. }
            | StreamError::TooManyRequests { id }
            | StreamError::TooLarge { id, .. }
            | StreamError::Duplicate { id }
            | StreamError::AfterEnd { id, .. }
            | StreamError::OutOfOrder { id, .. } => id,
        }
    }
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StreamError::Body { id, kind } => write!(f, "request {id}: malformed body in record type {kind}"),
            StreamError::UnknownRole { id, role } => write!(f, "request {id}: unknown role {role}"),
            StreamError::TooManyRequests { id } => write!(f, "request {id}: more than {MAX_REQUESTS} open"),
            StreamError::TooLarge { id, kind } => write!(f, "request {id}: stream of record type {kind} too large"),
            StreamError::Duplicate { id } => write!(f, "request {id}: begun twice"),
            StreamError::AfterEnd { id, kind } => {
                write!(f, "request {id}: record type {kind} after its stream ended")
            }
            StreamError::OutOfOrder { id, kind } => {
                write!(f, "request {id}: record type {kind} before the streams ahead of it ended")
            }
        }
    }
}

impl core::error::Error for StreamError {}

/// What a [`Server`] makes of a record, when it makes something of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerEvent {
    /// A request has come whole. The application answers it with a
    /// [`Response`].
    Request(Request),
    /// The web server aborted the open request with this ID, whether its
    /// streams had all come or not. The application answers with an
    /// END_REQUEST record and calls [`Server::end`], and
    /// [`Server::keep_conn`] says whether to keep the connection open
    /// afterward. Records still coming for the request are ignored.
    Abort(u16),
    /// A GET_VALUES record asked for these names. The application answers
    /// with [`Record::get_values_result`].
    GetValues(Vec<Vec<u8>>),
    /// A management record of a type the application does not know. It
    /// answers with [`Record::unknown_type`].
    UnknownType(u8),
}

/// A request a [`Server`] is still putting together.
#[derive(Clone, Debug)]
struct Incoming {
    role: Role,
    keep_conn: bool,
    params: Vec<u8>,
    params_done: bool,
    stdin: Vec<u8>,
    stdin_done: bool,
    data: Vec<u8>,
    data_done: bool,
}

/// Puts requests back together from the records a web server sends, for a
/// world that plays an application. It plays the responder, authorizer
/// and filter roles, and runs several requests on one connection.
///
/// As in the specification, a request ID is active from its BEGIN_REQUEST
/// until the application sends END_REQUEST. The server cannot see what the
/// world writes, so the world calls [`Server::end`] when it sends
/// END_REQUEST. Until then the request counts toward [`MAX_REQUESTS`], an
/// ABORT_REQUEST for it gives [`ServerEvent::Abort`], and a second
/// BEGIN_REQUEST for it is refused. This holds for a request whose streams
/// failed with a [`StreamError`] too, so the world answers it with
/// END_REQUEST and calls [`Server::end`] as well. The streams must come in
/// the order the specification gives: PARAMS, then STDIN, then DATA.
#[derive(Clone, Debug, Default)]
pub struct Server {
    open: BTreeMap<u16, Incoming>,
    /// Requests that are whole, aborted or failed, which the application
    /// is answering, and whether each asked to keep the connection open.
    answering: BTreeMap<u16, bool>,
}

impl Server {
    /// A server with no requests open.
    pub fn new() -> Server {
        Server::default()
    }

    /// How many requests are open: those still coming in and those the
    /// application is answering.
    pub fn open(&self) -> usize {
        self.open.len() + self.answering.len()
    }

    /// How many stream bytes are held across the requests still coming in.
    /// It is never more than [`MAX_HELD`].
    pub fn held(&self) -> usize {
        self.open.values().map(|r| r.params.len() + r.stdin.len() + r.data.len()).sum()
    }

    /// Whether open request `id` asked to keep the connection open after
    /// it, or `None` if it is not open. An application that answers an
    /// abort or an error with END_REQUEST closes the connection when this
    /// is false.
    pub fn keep_conn(&self, id: u16) -> Option<bool> {
        self.open.get(&id).map(|r| r.keep_conn).or_else(|| self.answering.get(&id).copied())
    }

    /// Marks request `id` as ended, because the application has sent its
    /// END_REQUEST. The ID is free for a new request after this. It
    /// returns whether the request was open. An application may end a
    /// request before all of its streams have come, and records still
    /// coming for it are then ignored.
    pub fn end(&mut self, id: u16) -> bool {
        let incoming = self.open.remove(&id).is_some();
        let answering = self.answering.remove(&id).is_some();
        incoming || answering
    }

    /// Drops what request `id` held while its streams came in, and keeps
    /// it open until [`Server::end`].
    fn fail(&mut self, id: u16) {
        if let Some(req) = self.open.remove(&id) {
            self.answering.insert(id, req.keep_conn);
        }
    }

    /// Takes in one record. It returns an event when the record completes
    /// a request or asks for an answer, and `Ok(None)` otherwise. Records
    /// for requests that are not open are ignored, and so are stream
    /// records for requests the application is answering and records of
    /// types an application does not read, such as STDOUT.
    pub fn receive(&mut self, record: &Record) -> Result<Option<ServerEvent>, StreamError> {
        let id = record.request_id;
        if record.is_management() {
            return match record.kind {
                // The values of a GET_VALUES record are empty.
                kind::GET_VALUES => match parse_pairs(&record.content) {
                    Ok(pairs) if pairs.iter().all(|(_, v)| v.is_empty()) => {
                        Ok(Some(ServerEvent::GetValues(pairs.into_iter().map(|(n, _)| n).collect())))
                    }
                    _ => Err(StreamError::Body { id, kind: record.kind }),
                },
                k => Ok(Some(ServerEvent::UnknownType(k))),
            };
        }
        match record.kind {
            kind::BEGIN_REQUEST => {
                if self.open.contains_key(&id) || self.answering.contains_key(&id) {
                    self.fail(id);
                    return Err(StreamError::Duplicate { id });
                }
                let body =
                    BeginRequest::parse(&record.content).map_err(|_| StreamError::Body { id, kind: record.kind })?;
                if let Role::Other(role) = body.role {
                    return Err(StreamError::UnknownRole { id, role });
                }
                if self.open() >= MAX_REQUESTS {
                    return Err(StreamError::TooManyRequests { id });
                }
                let incoming = Incoming {
                    role: body.role,
                    keep_conn: body.keep_conn(),
                    params: Vec::new(),
                    params_done: false,
                    stdin: Vec::new(),
                    stdin_done: false,
                    data: Vec::new(),
                    data_done: false,
                };
                self.open.insert(id, incoming);
                Ok(None)
            }
            kind::ABORT_REQUEST => {
                self.fail(id);
                Ok(self.answering.contains_key(&id).then_some(ServerEvent::Abort(id)))
            }
            kind::PARAMS | kind::STDIN | kind::DATA => {
                let held = self.held();
                let Some(req) = self.open.get_mut(&id) else { return Ok(None) };
                // The streams come one after another: PARAMS, then STDIN,
                // then DATA. `ahead` is whether those before this one ended.
                let (buf, done, limit, ahead) = match record.kind {
                    kind::PARAMS => (&mut req.params, &mut req.params_done, MAX_PARAMS, true),
                    kind::STDIN if req.role != Role::Authorizer => {
                        (&mut req.stdin, &mut req.stdin_done, MAX_STREAM, req.params_done)
                    }
                    kind::DATA if req.role == Role::Filter => {
                        (&mut req.data, &mut req.data_done, MAX_STREAM, req.params_done && req.stdin_done)
                    }
                    _ => return Ok(None),
                };
                let added = if ahead {
                    add_to_stream(buf, done, limit, held, id, record)
                } else {
                    Err(StreamError::OutOfOrder { id, kind: record.kind })
                };
                if let Err(e) = added {
                    self.fail(id);
                    return Err(e);
                }
                let complete = req.params_done
                    && (req.role == Role::Authorizer || req.stdin_done)
                    && (req.role != Role::Filter || req.data_done);
                if !complete {
                    return Ok(None);
                }
                let Some(req) = self.open.remove(&id) else { return Ok(None) };
                self.answering.insert(id, req.keep_conn);
                let params = parse_pairs(&req.params).map_err(|_| StreamError::Body { id, kind: kind::PARAMS })?;
                Ok(Some(ServerEvent::Request(Request {
                    id,
                    role: req.role,
                    keep_conn: req.keep_conn,
                    params,
                    stdin: req.stdin,
                    data: req.data,
                })))
            }
            _ => Ok(None),
        }
    }
}

/// Adds a stream record's content to `buf`, or ends the stream if it is
/// empty. `held` is how many stream bytes are held across all requests,
/// which must stay within [`MAX_HELD`].
fn add_to_stream(
    buf: &mut Vec<u8>,
    done: &mut bool,
    limit: usize,
    held: usize,
    id: u16,
    record: &Record,
) -> Result<(), StreamError> {
    if *done {
        return Err(StreamError::AfterEnd { id, kind: record.kind });
    }
    if record.content.is_empty() {
        *done = true;
        return Ok(());
    }
    let room = limit.saturating_sub(buf.len()).min(MAX_HELD.saturating_sub(held));
    if record.content.len() > room {
        return Err(StreamError::TooLarge { id, kind: record.kind });
    }
    buf.extend_from_slice(&record.content);
    Ok(())
}

/// What a [`Client`] makes of a record, when it makes something of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    /// A request has ended, with all its output.
    Response(Response),
    /// The application answered a GET_VALUES record with these pairs.
    Values(Vec<Pair>),
    /// The application did not know a management record of this type.
    UnknownType(u8),
}

/// A response a [`Client`] is still putting together.
#[derive(Clone, Debug, Default)]
struct Outgoing {
    stdout: Vec<u8>,
    stdout_done: bool,
    stderr: Vec<u8>,
    stderr_done: bool,
    /// An error was reported for the response. It holds no output, and its
    /// records are ignored until its END_REQUEST.
    failed: bool,
}

/// Puts responses back together from the records an application sends,
/// for a world that plays a web server. A request's output is gathered
/// from its first STDOUT or STDERR record until its END_REQUEST.
#[derive(Clone, Debug, Default)]
pub struct Client {
    open: BTreeMap<u16, Outgoing>,
}

impl Client {
    /// A client with no responses open.
    pub fn new() -> Client {
        Client::default()
    }

    /// How many responses are being gathered.
    pub fn open(&self) -> usize {
        self.open.len()
    }

    /// How many stream bytes are held across the responses being gathered.
    /// It is never more than [`MAX_HELD`].
    pub fn held(&self) -> usize {
        self.open.values().map(|r| r.stdout.len() + r.stderr.len()).sum()
    }

    /// Takes in one record. It returns an event when the record ends a
    /// request or answers a management record, and `Ok(None)` otherwise.
    /// Records of types a web server does not read, such as STDIN, are
    /// ignored, and so are the records of a response after an error about
    /// it, up to and including its END_REQUEST.
    pub fn receive(&mut self, record: &Record) -> Result<Option<ClientEvent>, StreamError> {
        let id = record.request_id;
        if record.is_management() {
            return match record.kind {
                kind::GET_VALUES_RESULT => match parse_pairs(&record.content) {
                    Ok(pairs) => Ok(Some(ClientEvent::Values(pairs))),
                    Err(_) => Err(StreamError::Body { id, kind: record.kind }),
                },
                kind::UNKNOWN_TYPE => match parse_unknown_type(&record.content) {
                    Ok(k) => Ok(Some(ClientEvent::UnknownType(k))),
                    Err(_) => Err(StreamError::Body { id, kind: record.kind }),
                },
                _ => Ok(None),
            };
        }
        match record.kind {
            kind::STDOUT | kind::STDERR => {
                if !self.open.contains_key(&id) && self.open.len() >= MAX_REQUESTS {
                    return Err(StreamError::TooManyRequests { id });
                }
                let held = self.held();
                let out = self.open.entry(id).or_default();
                if out.failed {
                    return Ok(None);
                }
                let (buf, done) = if record.kind == kind::STDOUT {
                    (&mut out.stdout, &mut out.stdout_done)
                } else {
                    (&mut out.stderr, &mut out.stderr_done)
                };
                if let Err(e) = add_to_stream(buf, done, MAX_STREAM, held, id, record) {
                    *out = Outgoing { failed: true, ..Outgoing::default() };
                    return Err(e);
                }
                Ok(None)
            }
            kind::END_REQUEST => {
                let out = self.open.remove(&id).unwrap_or_default();
                if out.failed {
                    return Ok(None);
                }
                let end =
                    EndRequest::parse(&record.content).map_err(|_| StreamError::Body { id, kind: record.kind })?;
                Ok(Some(ClientEvent::Response(Response {
                    id,
                    stdout: out.stdout,
                    stderr: out.stderr,
                    app_status: end.app_status,
                    protocol_status: end.protocol_status,
                })))
            }
            _ => Ok(None),
        }
    }
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(n: &str, v: &str) -> Pair {
        (n.as_bytes().to_vec(), v.as_bytes().to_vec())
    }

    fn records(bytes: &[u8]) -> Vec<Record> {
        let mut d = Decoder::new();
        d.feed(bytes);
        let mut out = Vec::new();
        while let Some(r) = d.next_record() {
            out.push(r.unwrap());
        }
        assert_eq!(d.buffered(), 0);
        out
    }

    fn serve(bytes: &[u8]) -> Vec<Result<Option<ServerEvent>, StreamError>> {
        let mut s = Server::new();
        records(bytes).iter().map(|r| s.receive(r)).collect()
    }

    // The module doc's example, run here too.
    #[test]
    fn module_example() {
        let sent = Request {
            id: 1,
            role: Role::Responder,
            keep_conn: false,
            params: vec![pair("REQUEST_METHOD", "GET"), pair("SCRIPT_NAME", "/hello")],
            stdin: Vec::new(),
            data: Vec::new(),
        }
        .to_bytes();
        let mut decoder = Decoder::new();
        let mut server = Server::new();
        let mut reply = Vec::new();
        decoder.feed(&sent);
        while let Some(record) = decoder.next_record() {
            match server.receive(&record.unwrap()) {
                Ok(Some(ServerEvent::Request(req))) => {
                    assert_eq!(req.param(b"SCRIPT_NAME"), Some(&b"/hello"[..]));
                    let page = b"Content-Type: text/plain\r\n\r\nhello".to_vec();
                    reply.extend(req.respond(page).to_bytes());
                    assert!(server.end(req.id));
                }
                Ok(_) => {}
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(reply[..8], [1, 6, 0, 1, 0, 33, 7, 0]);
    }

    // Examples from the FastCGI Specification 1.0, appendix B: a responder
    // request with params and stdin, and its reply.
    #[test]
    fn spec_responder_example() {
        let mut sent = Record::begin_request(1, BeginRequest { role: Role::Responder, flags: 0 }).to_bytes();
        // {FCGI_PARAMS, 1, "\013\002SERVER_PORT80\013\016SERVER_ADDR199.170.183.42 ... "}
        let mut params = vec![11, 2];
        params.extend_from_slice(b"SERVER_PORT80");
        params.extend_from_slice(&[11, 14]);
        params.extend_from_slice(b"SERVER_ADDR199.170.183.42");
        sent.extend(Record::new(kind::PARAMS, 1, &params).to_bytes());
        sent.extend(Record::new(kind::PARAMS, 1, &[]).to_bytes());
        sent.extend(Record::new(kind::STDIN, 1, b"quantity=100&item=3047936").to_bytes());
        sent.extend(Record::new(kind::STDIN, 1, &[]).to_bytes());
        assert_eq!(sent[..16], [1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let events = serve(&sent);
        let Some(Ok(Some(ServerEvent::Request(req)))) = events.last() else { panic!("{events:?}") };
        assert_eq!(req.params, [pair("SERVER_PORT", "80"), pair("SERVER_ADDR", "199.170.183.42")]);
        assert_eq!(req.stdin, b"quantity=100&item=3047936");
        assert_eq!(req.to_bytes(), sent);

        let resp = Response {
            id: 1,
            stdout: b"Content-type: text/html\r\n\r\n<html>\n<head> ... ".to_vec(),
            stderr: Vec::new(),
            app_status: 0,
            protocol_status: ProtocolStatus::RequestComplete,
        };
        let bytes = resp.to_bytes();
        let rs = records(&bytes);
        assert_eq!(rs.len(), 3);
        assert_eq!(rs[2].to_bytes(), [1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut c = Client::new();
        let got: Vec<_> = rs.iter().map(|r| c.receive(r).unwrap()).collect();
        assert_eq!(got[2], Some(ClientEvent::Response(resp)));
    }

    #[test]
    fn spec_stderr_and_multiplexing() {
        // Two requests interleaved on one connection, as in appendix B.
        let a = Request {
            id: 1,
            role: Role::Responder,
            keep_conn: true,
            params: vec![pair("A", "1")],
            stdin: b"one".to_vec(),
            data: vec![],
        };
        let b = Request { id: 2, stdin: b"two".to_vec(), ..a.clone() };
        let ra = records(&a.to_bytes());
        let rb = records(&b.to_bytes());
        let mut s = Server::new();
        let mut got = Vec::new();
        for (x, y) in ra.iter().zip(&rb) {
            for r in [x, y] {
                if let Some(ServerEvent::Request(req)) = s.receive(r).unwrap() {
                    got.push(req);
                }
            }
        }
        assert_eq!(got, [a.clone(), b]);
        let resp = Response {
            id: 1,
            stdout: b"Status: 500\r\n\r\n".to_vec(),
            stderr: b"config error: missing SI_UID\n".to_vec(),
            app_status: 3,
            protocol_status: ProtocolStatus::RequestComplete,
        };
        let mut c = Client::new();
        let events: Vec<_> = records(&resp.to_bytes()).iter().map(|r| c.receive(r).unwrap()).collect();
        assert_eq!(events.last().unwrap(), &Some(ClientEvent::Response(resp)));
        assert_eq!(c.open(), 0);
    }

    #[test]
    fn records_and_padding() {
        let r = Record::new(kind::STDOUT, 0x0102, b"hello");
        assert_eq!(r.padding, 3);
        let bytes = r.to_bytes();
        assert_eq!(bytes, [1, 6, 1, 2, 0, 5, 3, 0, b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
        assert_eq!(Record::parse(&bytes), Ok(Some((r, 16))));
        // Padding bytes may hold anything, and a record need not be aligned.
        let odd = [1, 6, 0, 1, 0, 1, 2, 0, b'x', 0xaa, 0xbb, 1];
        let (rec, used) = Record::parse(&odd).unwrap().unwrap();
        assert_eq!(used, 11);
        assert_eq!(rec, Record { kind: 6, request_id: 1, content: b"x".to_vec(), padding: 2 });
        // Every prefix is incomplete.
        for n in 0..16 {
            assert_eq!(Record::parse(&bytes[..n]), Ok(None), "{n} bytes");
        }
        // A wrong version is known from the first byte.
        assert_eq!(Record::parse(&[2]), Err(RecordError::Version(2)));
        assert_eq!(Record::parse(&[0, 1, 0, 1, 0, 0, 0, 0]), Err(RecordError::Version(0)));
        // The longest record.
        let big = Record { kind: 5, request_id: 9, content: vec![7; MAX_CONTENT + 10], padding: 255 };
        let bytes = big.to_bytes();
        assert_eq!(bytes.len(), MAX_RECORD);
        let (back, used) = Record::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, MAX_RECORD);
        assert_eq!(back.content.len(), MAX_CONTENT);
        assert_eq!(Record::new(5, 1, &vec![0; MAX_CONTENT + 1]).content.len(), MAX_CONTENT);
    }

    #[test]
    fn pairs() {
        // Lengths below 128 take one byte, others four.
        let long = "v".repeat(200);
        let ps = vec![pair("SCRIPT_NAME", "/x"), pair("HTTP_COOKIE", &long), pair("", "")];
        let bytes = encode_pairs(&ps);
        assert_eq!(bytes[..2], [11, 2]);
        assert_eq!(bytes[15..20], [11, 0x80, 0, 0, 200]);
        assert_eq!(parse_pairs(&bytes), Ok(ps));
        // A four-byte length for a short value is read too.
        assert_eq!(parse_pairs(&[0x80, 0, 0, 1, 0x80, 0, 0, 0, b'a']), Ok(vec![pair("a", "")]));
        // Every truncated prefix of a pair fails.
        let one = encode_pairs(&[pair("NAME", &long)]);
        for n in 1..one.len() {
            assert_eq!(parse_pairs(&one[..n]), Err(PairError::Truncated), "{n} bytes");
        }
        // A huge length is refused, not allocated.
        assert_eq!(parse_pairs(&[0xff, 0xff, 0xff, 0xff, 0]), Err(PairError::Truncated));
        // Too many pairs.
        let many = vec![0u8; 2 * (MAX_PAIRS + 1)];
        assert_eq!(parse_pairs(&many), Err(PairError::TooMany));
        assert_eq!(parse_pairs(&many[..2 * MAX_PAIRS]).unwrap().len(), MAX_PAIRS);
        let too_many: Vec<Pair> = (0..MAX_PAIRS + 5).map(|_| pair("", "")).collect();
        assert_eq!(parse_pairs(&encode_pairs(&too_many)).unwrap().len(), MAX_PAIRS);
    }

    #[test]
    fn bodies() {
        let b = BeginRequest { role: Role::Filter, flags: KEEP_CONN };
        assert_eq!(b.to_bytes(), [0, 3, 1, 0, 0, 0, 0, 0]);
        assert_eq!(BeginRequest::parse(&b.to_bytes()), Ok(b));
        assert!(b.keep_conn());
        let e = EndRequest { app_status: 0x01020304, protocol_status: ProtocolStatus::Overloaded };
        assert_eq!(e.to_bytes(), [1, 2, 3, 4, 2, 0, 0, 0]);
        assert_eq!(EndRequest::parse(&e.to_bytes()), Ok(e));
        assert_eq!(parse_unknown_type(&Record::unknown_type(42).content), Ok(42));
        for n in 0..8 {
            assert_eq!(BeginRequest::parse(&b.to_bytes()[..n]), Err(BodyError));
            assert_eq!(EndRequest::parse(&e.to_bytes()[..n]), Err(BodyError));
            assert_eq!(parse_unknown_type(&[0; 8][..n]), Err(BodyError));
        }
        assert_eq!(BeginRequest::parse(&[0; 9]), Err(BodyError));
        for c in 0..=255u8 {
            assert_eq!(ProtocolStatus::from_code(c).code(), c);
        }
        for c in [0u16, 1, 2, 3, 4, 0xffff] {
            assert_eq!(Role::from_code(c).code(), c);
        }
    }

    #[test]
    fn management_records() {
        let ask = Record::get_values(&[values::MAX_CONNS, values::MAX_REQS, values::MPXS_CONNS]);
        let mut s = Server::new();
        let Ok(Some(ServerEvent::GetValues(names))) = s.receive(&ask) else { panic!() };
        assert_eq!(names, [values::MAX_CONNS, values::MAX_REQS, values::MPXS_CONNS]);
        let answer = Record::get_values_result(&[(values::MAX_REQS.to_vec(), b"32".to_vec())]);
        let mut c = Client::new();
        assert_eq!(c.receive(&answer), Ok(Some(ClientEvent::Values(vec![pair("FCGI_MAX_REQS", "32")]))));
        // An unknown management type, and the answer.
        let odd = Record::new(200, 0, &[]);
        assert_eq!(s.receive(&odd), Ok(Some(ServerEvent::UnknownType(200))));
        assert_eq!(c.receive(&Record::unknown_type(200)), Ok(Some(ClientEvent::UnknownType(200))));
        // Malformed management bodies.
        let bad = Record::new(kind::GET_VALUES, 0, &[5]);
        assert_eq!(s.receive(&bad), Err(StreamError::Body { id: 0, kind: kind::GET_VALUES }));
        let bad = Record::new(kind::GET_VALUES_RESULT, 0, &[5]);
        assert_eq!(c.receive(&bad), Err(StreamError::Body { id: 0, kind: kind::GET_VALUES_RESULT }));
        let bad = Record::new(kind::UNKNOWN_TYPE, 0, &[5]);
        assert_eq!(c.receive(&bad), Err(StreamError::Body { id: 0, kind: kind::UNKNOWN_TYPE }));
        // A GET_VALUES_RESULT too big for one record keeps what fits.
        let big: Vec<Pair> = (0..10).map(|i| (vec![b'a' + i], vec![0; 10_000])).collect();
        let r = Record::get_values_result(&big);
        assert!(r.content.len() <= MAX_CONTENT);
        assert_eq!(parse_pairs(&r.content).unwrap().len(), 6);
    }

    #[test]
    fn server_errors() {
        let begin = |id, role| Record::begin_request(id, BeginRequest { role, flags: 0 });
        let mut s = Server::new();
        // A bad BEGIN_REQUEST body.
        assert_eq!(
            s.receive(&Record::new(kind::BEGIN_REQUEST, 1, &[0, 1])),
            Err(StreamError::Body { id: 1, kind: kind::BEGIN_REQUEST })
        );
        // An unknown role.
        assert_eq!(s.receive(&begin(1, Role::Other(9))), Err(StreamError::UnknownRole { id: 1, role: 9 }));
        assert_eq!(s.open(), 0);
        // Begun twice: the first stays open until it is ended.
        assert_eq!(s.receive(&begin(1, Role::Responder)), Ok(None));
        assert_eq!(s.receive(&begin(1, Role::Responder)), Err(StreamError::Duplicate { id: 1 }));
        assert_eq!(s.open(), 1);
        // Records for a failed request are ignored.
        assert_eq!(s.receive(&Record::new(kind::PARAMS, 1, b"x")), Ok(None));
        // Records for requests that are not open are ignored.
        assert_eq!(s.receive(&Record::new(kind::STDIN, 9, b"x")), Ok(None));
        // A stream record after its end.
        s.receive(&begin(2, Role::Responder)).unwrap();
        s.receive(&Record::new(kind::PARAMS, 2, &[1, 0, b'A'])).unwrap();
        s.receive(&Record::new(kind::PARAMS, 2, &[])).unwrap();
        assert_eq!(
            s.receive(&Record::new(kind::PARAMS, 2, b"late")),
            Err(StreamError::AfterEnd { id: 2, kind: kind::PARAMS })
        );
        // Bad pairs in PARAMS, found once the stream ends.
        s.receive(&begin(3, Role::Authorizer)).unwrap();
        s.receive(&Record::new(kind::PARAMS, 3, &[9])).unwrap();
        assert_eq!(s.receive(&Record::new(kind::PARAMS, 3, &[])), Err(StreamError::Body { id: 3, kind: kind::PARAMS }));
        // PARAMS past its limit.
        s.receive(&begin(4, Role::Responder)).unwrap();
        let chunk = vec![0u8; MAX_CONTENT];
        let mut result = Ok(None);
        for _ in 0..=MAX_PARAMS / MAX_CONTENT {
            result = s.receive(&Record::new(kind::PARAMS, 4, &chunk));
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(StreamError::TooLarge { id: 4, kind: kind::PARAMS }));
        assert_eq!(s.open(), 4);
        assert_eq!(s.held(), 0);
        // STDIN past its limit.
        s.receive(&begin(5, Role::Responder)).unwrap();
        s.receive(&Record::new(kind::PARAMS, 5, &[])).unwrap();
        let mut result = Ok(None);
        for _ in 0..=MAX_STREAM / MAX_CONTENT {
            result = s.receive(&Record::new(kind::STDIN, 5, &chunk));
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(StreamError::TooLarge { id: 5, kind: kind::STDIN }));
        // Each failed request stays open until the application ends it.
        assert_eq!(s.open(), 5);
        for id in 1..=5 {
            assert!(s.end(id));
        }
        // Too many requests at once.
        for id in 1..=MAX_REQUESTS as u16 {
            assert_eq!(s.receive(&begin(id, Role::Responder)), Ok(None));
        }
        let over = MAX_REQUESTS as u16 + 1;
        assert_eq!(s.receive(&begin(over, Role::Responder)), Err(StreamError::TooManyRequests { id: over }));
        assert_eq!(s.open(), MAX_REQUESTS);
        // Abort.
        assert_eq!(s.receive(&Record::abort_request(1)), Ok(Some(ServerEvent::Abort(1))));
        assert!(s.end(1));
        assert_eq!(s.receive(&Record::abort_request(1)), Ok(None));
        // STDOUT means nothing to an application.
        assert_eq!(s.receive(&Record::new(kind::STDOUT, 2, b"x")), Ok(None));
        for e in [StreamError::Duplicate { id: 7 }, StreamError::TooLarge { id: 7, kind: 5 }] {
            assert_eq!(e.id(), 7);
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn client_errors() {
        let mut c = Client::new();
        assert_eq!(
            c.receive(&Record::new(kind::END_REQUEST, 1, &[0; 3])),
            Err(StreamError::Body { id: 1, kind: kind::END_REQUEST })
        );
        c.receive(&Record::new(kind::STDOUT, 1, &[])).unwrap();
        assert_eq!(
            c.receive(&Record::new(kind::STDOUT, 1, b"x")),
            Err(StreamError::AfterEnd { id: 1, kind: kind::STDOUT })
        );
        for id in 1..=MAX_REQUESTS as u16 {
            assert_eq!(c.receive(&Record::new(kind::STDERR, id, b"e")), Ok(None));
        }
        let over = MAX_REQUESTS as u16 + 1;
        assert_eq!(c.receive(&Record::new(kind::STDOUT, over, b"x")), Err(StreamError::TooManyRequests { id: over }));
        let chunk = vec![1u8; MAX_CONTENT];
        let mut result = Ok(None);
        for _ in 0..=MAX_STREAM / MAX_CONTENT {
            result = c.receive(&Record::new(kind::STDOUT, 2, &chunk));
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(StreamError::TooLarge { id: 2, kind: kind::STDOUT }));
        // Records a web server does not read are ignored.
        assert_eq!(c.receive(&Record::new(kind::STDIN, 3, b"x")), Ok(None));
        assert_eq!(c.receive(&Record::new(kind::GET_VALUES, 0, &[])), Ok(None));
    }

    #[test]
    fn roles_get_their_streams() {
        let base = Request {
            id: 7,
            role: Role::Authorizer,
            keep_conn: false,
            params: vec![pair("REMOTE_USER", "ann")],
            stdin: Vec::new(),
            data: Vec::new(),
        };
        let events = serve(&base.to_bytes());
        assert_eq!(events.last(), Some(&Ok(Some(ServerEvent::Request(base.clone())))));
        let filter = Request { role: Role::Filter, stdin: b"in".to_vec(), data: b"file".to_vec(), ..base };
        let events = serve(&filter.to_bytes());
        assert_eq!(events.last(), Some(&Ok(Some(ServerEvent::Request(filter.clone())))));
        // Id 0 is written as 1.
        let zero = Request { id: 0, ..filter };
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&zero.to_bytes()).pop() else { panic!() };
        assert_eq!(got.id, 1);
    }

    // The specification keeps a request ID active from BEGIN_REQUEST until
    // the application sends END_REQUEST, not until its streams end.
    #[test]
    fn request_stays_active_until_ended() {
        let req = Request {
            id: 4,
            role: Role::Responder,
            keep_conn: true,
            params: vec![pair("A", "1")],
            stdin: b"body".to_vec(),
            data: Vec::new(),
        };
        let mut s = Server::new();
        let mut got = None;
        for r in records(&req.to_bytes()) {
            if let Some(ServerEvent::Request(back)) = s.receive(&r).unwrap() {
                got = Some(back);
            }
        }
        assert_eq!(got, Some(req.clone()));
        // The application is still answering, so the request is open.
        assert_eq!(s.open(), 1);
        // An abort while it answers reaches the world.
        assert_eq!(s.receive(&Record::abort_request(4)), Ok(Some(ServerEvent::Abort(4))));
        // A second BEGIN_REQUEST for it is refused, and the first stays.
        let begin = Record::begin_request(4, BeginRequest { role: Role::Responder, flags: 0 });
        assert_eq!(s.receive(&begin), Err(StreamError::Duplicate { id: 4 }));
        assert_eq!(s.open(), 1);
        // Stray stream records for it are ignored.
        assert_eq!(s.receive(&Record::new(kind::STDIN, 4, b"x")), Ok(None));
        // Once END_REQUEST goes out, the ID is free again.
        assert!(s.end(4));
        assert!(!s.end(4));
        assert_eq!(s.open(), 0);
        assert_eq!(s.receive(&Record::abort_request(4)), Ok(None));
        assert_eq!(s.receive(&begin), Ok(None));
        // An abort before the streams end leaves the ID active too.
        assert_eq!(s.receive(&Record::abort_request(4)), Ok(Some(ServerEvent::Abort(4))));
        assert_eq!(s.open(), 1);
        assert_eq!(s.receive(&Record::new(kind::PARAMS, 4, &[])), Ok(None));
        assert!(s.end(4));
        // Requests being answered count toward the limit.
        for id in 1..=MAX_REQUESTS as u16 {
            let r = Request { id, ..req.clone() };
            let Some(Ok(Some(ServerEvent::Request(_)))) = records(&r.to_bytes()).iter().map(|x| s.receive(x)).last()
            else {
                panic!()
            };
        }
        let over = MAX_REQUESTS as u16 + 1;
        let begin = Record::begin_request(over, BeginRequest { role: Role::Responder, flags: 0 });
        assert_eq!(s.receive(&begin), Err(StreamError::TooManyRequests { id: over }));
        assert!(s.end(1));
        assert_eq!(s.receive(&begin), Ok(None));
    }

    // A role given by number is written as the role it names, so a server
    // waits for the streams that role carries.
    #[test]
    fn roles_by_number_are_written_as_named() {
        let req = Request {
            id: 2,
            role: Role::Other(3),
            keep_conn: false,
            params: Vec::new(),
            stdin: b"in".to_vec(),
            data: b"file".to_vec(),
        };
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&req.to_bytes()).pop() else { panic!() };
        assert_eq!(got.role, Role::Filter);
        assert_eq!(got.data, b"file");
        let auth = Request { role: Role::Other(2), ..req };
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&auth.to_bytes()).pop() else { panic!() };
        assert_eq!(got.role, Role::Authorizer);
        assert!(got.stdin.is_empty());
    }

    #[test]
    fn writers_cap_what_they_write() {
        // Long streams split over several records and come back whole, cut
        // to their limits.
        let req = Request {
            id: 3,
            role: Role::Responder,
            keep_conn: true,
            params: (0..300).map(|i| (format!("P{i}").into_bytes(), vec![b'x'; 1000])).collect(),
            stdin: vec![9; MAX_STREAM + 100],
            data: Vec::new(),
        };
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&req.to_bytes()).pop() else { panic!() };
        assert_eq!(got.stdin.len(), MAX_STREAM);
        assert!(got.params.len() < 300 && got.params.len() > 200);
        assert_eq!(got.params[..], req.params[..got.params.len()]);
        let resp = Response {
            id: 3,
            stdout: vec![1; MAX_STREAM + 1],
            stderr: vec![2; 70_000],
            app_status: 1,
            protocol_status: ProtocolStatus::RequestComplete,
        };
        let mut c = Client::new();
        let mut last = None;
        for r in records(&resp.to_bytes()) {
            assert!(r.content.len() <= MAX_CONTENT);
            last = c.receive(&r).unwrap();
        }
        let Some(ClientEvent::Response(back)) = last else { panic!() };
        assert_eq!(back.stdout.len(), MAX_STREAM);
        assert_eq!(back.stderr, resp.stderr);
        assert_eq!(stream_bytes(kind::STDIN, 1, &[]), Record::new(kind::STDIN, 1, &[]).to_bytes());
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = Record::new(kind::STDIN, 1, b"abc").to_bytes();
        let b = Record::new(kind::STDIN, 1, &[]).to_bytes();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(r) = d.next_record() {
                got.push(r.unwrap().content);
            }
        }
        assert_eq!(got, [b"abc".to_vec(), vec![]]);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        d.feed(&[3, 1, 0, 1, 0, 0, 0, 0]);
        assert_eq!(d.next_record(), Some(Err(RecordError::Version(3))));
        d.feed(&a);
        assert_eq!(d.next_record(), Some(Err(RecordError::Version(3))));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_records_in_linear_time() {
        let one = Record::new(kind::STDIN, 1, b"x").to_bytes();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut n = 0;
        while let Some(r) = d.next_record() {
            r.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
    }

    // The decoder holds at most MAX_BUFFERED bytes not taken out, and a
    // whole request of the largest size still fits.
    #[test]
    fn decoder_bounds_what_it_holds() {
        let big = Request {
            id: 1,
            role: Role::Filter,
            keep_conn: false,
            params: (0..300).map(|i| (format!("P{i}").into_bytes(), vec![b'x'; 1000])).collect(),
            stdin: vec![1; MAX_STREAM],
            data: vec![2; MAX_STREAM],
        };
        let bytes = big.to_bytes();
        assert!(bytes.len() <= MAX_BUFFERED);
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&bytes).pop() else { panic!() };
        assert_eq!(got.data.len(), MAX_STREAM);

        let mut d = Decoder::new();
        d.feed(&vec![1; MAX_BUFFERED]);
        assert_eq!(d.buffered(), MAX_BUFFERED);
        d.feed(&[1]);
        assert_eq!(d.next_record(), Some(Err(RecordError::TooLong)));
        assert_eq!(d.buffered(), 0);
        d.feed(&Record::abort_request(1).to_bytes());
        assert_eq!(d.next_record(), Some(Err(RecordError::TooLong)));
        assert!(!RecordError::TooLong.to_string().is_empty());
        // Taking records out between feeds makes room.
        let mut d = Decoder::new();
        let one = Record::new(kind::STDIN, 1, &vec![0; MAX_CONTENT]).to_bytes();
        for _ in 0..2 * MAX_BUFFERED / one.len() {
            d.feed(&one);
            assert!(d.next_record().unwrap().is_ok());
            assert!(d.buffered() <= MAX_BUFFERED);
        }
    }

    // The stream bytes held across all open requests stay within MAX_HELD.
    #[test]
    fn held_bytes_are_bounded() {
        let chunk = vec![0u8; MAX_CONTENT];
        let mut s = Server::new();
        let mut failed = None;
        'outer: for id in 1..=MAX_REQUESTS as u16 {
            s.receive(&Record::begin_request(id, BeginRequest { role: Role::Filter, flags: 0 })).unwrap();
            s.receive(&Record::new(kind::PARAMS, id, &[])).unwrap();
            for k in [kind::STDIN, kind::DATA] {
                for _ in 0..MAX_STREAM / MAX_CONTENT {
                    if let Err(e) = s.receive(&Record::new(k, id, &chunk)) {
                        failed = Some(e);
                        break 'outer;
                    }
                    assert!(s.held() <= MAX_HELD);
                }
                if k == kind::STDIN {
                    s.receive(&Record::new(k, id, &[])).unwrap();
                }
            }
        }
        let Some(StreamError::TooLarge { id, .. }) = failed else { panic!("{failed:?}") };
        // Two whole requests' worth fit before the limit.
        assert!(id > 2);
        assert!(s.held() <= MAX_HELD);
        // The failed request is dropped, and its room is free again.
        let before = s.held();
        assert!(s.end(1));
        assert!(s.held() < before);
        let snapshot = s.clone();
        assert_eq!(snapshot.open(), s.open());

        let mut c = Client::new();
        let mut failed = None;
        'client: for id in 1..=MAX_REQUESTS as u16 {
            for k in [kind::STDOUT, kind::STDERR] {
                for _ in 0..MAX_STREAM / MAX_CONTENT {
                    if let Err(e) = c.receive(&Record::new(k, id, &chunk)) {
                        failed = Some(e);
                        break 'client;
                    }
                    assert!(c.held() <= MAX_HELD);
                }
            }
        }
        assert!(matches!(failed, Some(StreamError::TooLarge { id, .. }) if id > 2));
        assert!(c.held() <= MAX_HELD);
        // An END_REQUEST frees what its response held.
        let before = c.held();
        let end =
            Record::end_request(1, EndRequest { app_status: 0, protocol_status: ProtocolStatus::RequestComplete });
        assert!(matches!(c.receive(&end), Ok(Some(ClientEvent::Response(_)))));
        assert!(c.held() < before);
    }

    /// A small linear congruential generator, so the fuzz loop is the same
    /// on every run.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
        /// Up to `max - 1` random bytes.
        fn some(&mut self, max: u32) -> Vec<u8> {
            let n = self.below(max) as usize;
            self.bytes(n)
        }
    }

    /// Everything the fuzz target checks, on one input.
    fn check(data: &[u8]) {
        let mut whole = Decoder::new();
        whole.feed(data);
        let mut recs = Vec::new();
        while let Some(Ok(r)) = whole.next_record() {
            recs.push(r);
        }
        let mut bytewise = Decoder::new();
        let mut again = Vec::new();
        for b in data {
            bytewise.feed(std::slice::from_ref(b));
            while let Some(Ok(r)) = bytewise.next_record() {
                again.push(r);
            }
        }
        // A feed past MAX_BUFFERED breaks the decoder fed all at once.
        if data.len() <= MAX_BUFFERED {
            assert_eq!(recs, again);
        } else {
            assert!(recs.is_empty());
        }
        let mut server = Server::new();
        let mut client = Client::new();
        for r in &recs {
            let bytes = r.to_bytes();
            assert_eq!(Record::parse(&bytes), Ok(Some((r.clone(), bytes.len()))));
            if let Ok(Some(ServerEvent::Request(req))) = server.receive(r) {
                let Some(Ok(Some(ServerEvent::Request(back)))) = serve(&req.to_bytes()).pop() else { panic!() };
                assert_eq!(back, req);
            }
            if let Ok(Some(ClientEvent::Response(resp))) = client.receive(r) {
                let mut c = Client::new();
                let mut last = None;
                for r in records(&resp.to_bytes()) {
                    last = c.receive(&r).unwrap();
                }
                assert_eq!(last, Some(ClientEvent::Response(resp)));
            }
            assert!(server.open() <= MAX_REQUESTS && client.open() <= MAX_REQUESTS);
        }
        if let Ok(pairs) = parse_pairs(data) {
            assert_eq!(parse_pairs(&encode_pairs(&pairs)), Ok(pairs));
        }
        let _ = BeginRequest::parse(data);
        let _ = EndRequest::parse(data);
    }

    #[test]
    fn fuzz_random_bytes() {
        let mut rng = Lcg(1);
        for _ in 0..5000 {
            let len = rng.below(64) as usize;
            let mut data = rng.bytes(len);
            // Mostly version 1, so records get read.
            if let Some(b) = data.first_mut()
                && rng.below(8) != 0
            {
                *b = 1;
            }
            check(&data);
        }
    }

    #[test]
    fn fuzz_random_records() {
        let mut rng = Lcg(2);
        for _ in 0..3000 {
            let mut data = Vec::new();
            for _ in 0..rng.below(12) {
                let id = rng.below(3) as u16;
                let k = rng.below(13) as u8;
                let content = match rng.below(4) {
                    0 => Vec::new(),
                    1 => BeginRequest { role: Role::from_code(rng.below(5) as u16), flags: rng.next() as u8 }
                        .to_bytes()
                        .to_vec(),
                    2 => encode_pairs(&[(rng.some(4), rng.some(140))]),
                    _ => {
                        let n = rng.below(20) as usize;
                        rng.bytes(n)
                    }
                };
                let mut r = Record::new(k, id, &content);
                r.padding = rng.below(10) as u8;
                data.extend(r.to_bytes());
            }
            check(&data);
            // And with bytes cut off the end.
            let cut = rng.below(data.len() as u32 + 1) as usize;
            check(&data[..cut]);
        }
    }

    #[test]
    fn fuzz_requests_round_trip_in_pieces() {
        let mut rng = Lcg(3);
        for _ in 0..2000 {
            let role = [Role::Responder, Role::Authorizer, Role::Filter][rng.below(3) as usize];
            let params = (0..rng.below(5)).map(|_| (rng.some(130), rng.some(200))).collect();
            let req = Request {
                id: 1 + rng.below(1000) as u16,
                role,
                keep_conn: rng.below(2) == 1,
                params,
                stdin: if role == Role::Authorizer { Vec::new() } else { rng.some(50) },
                data: if role == Role::Filter { rng.some(50) } else { Vec::new() },
            };
            let bytes = req.to_bytes();
            let mut d = Decoder::new();
            let mut s = Server::new();
            let mut got = None;
            let mut i = 0;
            while i < bytes.len() {
                let n = (1 + rng.below(9) as usize).min(bytes.len() - i);
                d.feed(&bytes[i..i + n]);
                i += n;
                while let Some(r) = d.next_record() {
                    if let Some(ServerEvent::Request(back)) = s.receive(&r.unwrap()).unwrap() {
                        got = Some(back);
                    }
                }
            }
            assert_eq!(got, Some(req));
            // Every truncated prefix leaves the request unfinished.
            let cut = rng.below(bytes.len() as u32) as usize;
            let mut s = Server::new();
            for r in records_prefix(&bytes[..cut]) {
                assert!(!matches!(s.receive(&r), Ok(Some(ServerEvent::Request(_)))));
            }
        }
    }

    // A response that failed does not come back later as a successful one
    // holding only the output sent after the failure.
    #[test]
    fn client_failed_response_stays_failed() {
        let mut c = Client::new();
        c.receive(&Record::new(kind::STDOUT, 1, b"a")).unwrap();
        c.receive(&Record::new(kind::STDOUT, 1, &[])).unwrap();
        assert_eq!(
            c.receive(&Record::new(kind::STDOUT, 1, b"x")),
            Err(StreamError::AfterEnd { id: 1, kind: kind::STDOUT })
        );
        assert_eq!(c.receive(&Record::new(kind::STDOUT, 1, b"b")), Ok(None));
        assert_eq!(c.receive(&Record::new(kind::STDOUT, 1, &[])), Ok(None));
        let end = EndRequest { app_status: 0, protocol_status: ProtocolStatus::RequestComplete };
        assert_eq!(c.receive(&Record::end_request(1, end)), Ok(None));
        assert_eq!(c.open(), 0);
        // The ID can be used again after END_REQUEST.
        c.receive(&Record::new(kind::STDOUT, 1, b"c")).unwrap();
        let Ok(Some(ClientEvent::Response(r))) = c.receive(&Record::end_request(1, end)) else { panic!() };
        assert_eq!(r.stdout, b"c");
    }

    // PARAMS records written for a request each hold whole pairs when the
    // pairs fit, since PHP-FPM reads the pairs of each record on its own.
    #[test]
    fn params_records_hold_whole_pairs() {
        let req = Request {
            id: 1,
            role: Role::Responder,
            keep_conn: false,
            params: (0..66).map(|i| (format!("P{i:02}").into_bytes(), vec![b'x'; 1000])).collect(),
            stdin: Vec::new(),
            data: Vec::new(),
        };
        let rs = records(&req.to_bytes());
        let params: Vec<_> = rs.iter().filter(|r| r.kind == kind::PARAMS && !r.content.is_empty()).collect();
        assert_eq!(params.len(), 2);
        let mut n = 0;
        for r in params {
            assert!(r.content.len() <= MAX_CONTENT);
            n += parse_pairs(&r.content).unwrap().len();
        }
        assert_eq!(n, 66);
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&req.to_bytes()).pop() else { panic!() };
        assert_eq!(got, req);
        // A pair too long for one record still spans records and comes back.
        let big = Request { params: vec![pair("A", "1"), (b"B".to_vec(), vec![7; 100_000]), pair("C", "3")], ..req };
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&big.to_bytes()).pop() else { panic!() };
        assert_eq!(got, big);
    }

    // stream_bytes cuts a stream to the limit a reader takes.
    #[test]
    fn stream_bytes_keeps_to_the_limit() {
        let mut c = Client::new();
        for r in records(&stream_bytes(kind::STDOUT, 1, &vec![1; MAX_STREAM + 1])) {
            assert_eq!(c.receive(&r), Ok(None));
        }
        let end = EndRequest { app_status: 0, protocol_status: ProtocolStatus::RequestComplete };
        let Ok(Some(ClientEvent::Response(r))) = c.receive(&Record::end_request(1, end)) else { panic!() };
        assert_eq!(r.stdout.len(), MAX_STREAM);
        let mut s = Server::new();
        s.receive(&Record::begin_request(1, BeginRequest { role: Role::Authorizer, flags: 0 })).unwrap();
        let mut last = Ok(None);
        for r in records(&stream_bytes(kind::PARAMS, 1, &vec![0; MAX_PARAMS + 2])) {
            last = s.receive(&r);
        }
        // The stream is cut to MAX_PARAMS, so it is not too large. Its
        // 2-byte empty pairs are more than MAX_PAIRS.
        assert_eq!(last, Err(StreamError::Body { id: 1, kind: kind::PARAMS }));
    }

    // A role or status given by number is the same value as the named one.
    #[test]
    fn numbered_roles_and_statuses_equal_named_ones() {
        let b = BeginRequest { role: Role::Other(1), flags: 0 };
        assert_eq!(BeginRequest::parse(&b.to_bytes()), Ok(b));
        assert_eq!(Role::Other(3), Role::Filter);
        assert_ne!(Role::Other(4), Role::Filter);
        let e = EndRequest { app_status: 0, protocol_status: ProtocolStatus::Other(0) };
        assert_eq!(EndRequest::parse(&e.to_bytes()), Ok(e));
        assert_eq!(ProtocolStatus::Other(2), ProtocolStatus::Overloaded);
    }

    // PARAMS, then STDIN, then DATA, as the specification orders them.
    #[test]
    fn streams_come_in_order() {
        let mut s = Server::new();
        s.receive(&Record::begin_request(1, BeginRequest { role: Role::Responder, flags: 0 })).unwrap();
        assert_eq!(
            s.receive(&Record::new(kind::STDIN, 1, b"x")),
            Err(StreamError::OutOfOrder { id: 1, kind: kind::STDIN })
        );
        assert_eq!(s.receive(&Record::new(kind::PARAMS, 1, &[])), Ok(None));
        assert_eq!(s.receive(&Record::new(kind::STDIN, 1, &[])), Ok(None));
        assert!(s.end(1));
        s.receive(&Record::begin_request(2, BeginRequest { role: Role::Filter, flags: 0 })).unwrap();
        s.receive(&Record::new(kind::PARAMS, 2, &[])).unwrap();
        assert_eq!(
            s.receive(&Record::new(kind::DATA, 2, &[])),
            Err(StreamError::OutOfOrder { id: 2, kind: kind::DATA })
        );
        assert!(!StreamError::OutOfOrder { id: 2, kind: 8 }.to_string().is_empty());
        assert_eq!(StreamError::OutOfOrder { id: 2, kind: 8 }.id(), 2);
    }

    // The world can learn whether to keep the connection open for a
    // request it is answering, aborted ones included.
    #[test]
    fn keep_conn_survives_abort() {
        let mut s = Server::new();
        for (id, flags) in [(1, 0), (2, KEEP_CONN)] {
            s.receive(&Record::begin_request(id, BeginRequest { role: Role::Responder, flags })).unwrap();
            assert_eq!(s.receive(&Record::abort_request(id)), Ok(Some(ServerEvent::Abort(id))));
        }
        assert_eq!(s.keep_conn(1), Some(false));
        assert_eq!(s.keep_conn(2), Some(true));
        assert_eq!(s.keep_conn(3), None);
        assert!(s.end(2));
        assert_eq!(s.keep_conn(2), None);
    }

    // A request whose streams failed stays active until END_REQUEST.
    #[test]
    fn failed_request_stays_active_until_ended() {
        let begin = Record::begin_request(1, BeginRequest { role: Role::Responder, flags: 0 });
        let mut s = Server::new();
        s.receive(&begin).unwrap();
        s.receive(&Record::new(kind::PARAMS, 1, &[])).unwrap();
        s.receive(&Record::new(kind::STDIN, 1, b"a")).unwrap();
        // A second BEGIN_REQUEST does not drop the first.
        assert_eq!(s.receive(&begin), Err(StreamError::Duplicate { id: 1 }));
        assert_eq!(s.open(), 1);
        assert_eq!(s.receive(&begin), Err(StreamError::Duplicate { id: 1 }));
        assert!(s.end(1));
        assert_eq!(s.receive(&begin), Ok(None));
        s.receive(&Record::new(kind::PARAMS, 1, &[])).unwrap();
        s.receive(&Record::new(kind::STDIN, 1, &[])).ok();
        assert!(s.end(1));
        s.receive(&begin).unwrap();
        s.receive(&Record::new(kind::PARAMS, 1, &[])).unwrap();
        s.receive(&Record::new(kind::STDIN, 1, b"a")).unwrap();
        // Bad PARAMS found at the end of the stream.
        let mut s2 = Server::new();
        s2.receive(&Record::begin_request(5, BeginRequest { role: Role::Authorizer, flags: 0 })).unwrap();
        s2.receive(&Record::new(kind::PARAMS, 5, &[9])).unwrap();
        assert!(s2.receive(&Record::new(kind::PARAMS, 5, &[])).is_err());
        assert_eq!(
            s2.receive(&Record::begin_request(5, BeginRequest { role: Role::Authorizer, flags: 0 })),
            Err(StreamError::Duplicate { id: 5 })
        );
        // A stream record after its end.
        let mut s3 = Server::new();
        s3.receive(&begin).unwrap();
        s3.receive(&Record::new(kind::PARAMS, 1, &[1, 0, b'A'])).unwrap();
        s3.receive(&Record::new(kind::PARAMS, 1, &[])).unwrap();
        assert!(s3.receive(&Record::new(kind::PARAMS, 1, b"x")).is_err());
        assert_eq!(s3.receive(&begin), Err(StreamError::Duplicate { id: 1 }));
        assert_eq!(s3.open(), 1);
        assert_eq!(s3.held(), 0);
    }

    // GET_VALUES carries names with empty values.
    #[test]
    fn get_values_values_are_empty() {
        let mut s = Server::new();
        let bad = Record::new(kind::GET_VALUES, 0, &[1, 1, b'A', b'B']);
        assert_eq!(s.receive(&bad), Err(StreamError::Body { id: 0, kind: kind::GET_VALUES }));
        // Names too long for one record are left out.
        let long = vec![b'n'; MAX_CONTENT];
        let r = Record::get_values(&[b"A", &long, b"B"]);
        assert_eq!(s.receive(&r), Ok(Some(ServerEvent::GetValues(vec![b"A".to_vec(), b"B".to_vec()]))));
    }

    // A feed past MAX_BUFFERED breaks a decoder fed all at once, but not
    // one fed a byte at a time. The fuzz check allows for that.
    #[test]
    fn fuzz_check_allows_an_oversized_feed() {
        let mut data = Record::abort_request(1).to_bytes();
        data.resize(MAX_BUFFERED + 1, 0);
        check(&data);
    }

    fn records_prefix(bytes: &[u8]) -> Vec<Record> {
        let mut d = Decoder::new();
        d.feed(bytes);
        let mut out = Vec::new();
        while let Some(Ok(r)) = d.next_record() {
            out.push(r);
        }
        out
    }
}
