//! FastCGI: reading and writing records, name and value pairs, and whole
//! requests and responses, with no I/O.
//!
//! `Record` and complete requests and responses implement `Wire`.
//! `codec::Frames<Record>` decodes the stream. `Client` and `Server` provide
//! caller-driven request bookkeeping, but there is no `Service`, process
//! manager, or live transport.
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
//! Nothing here reads a socket. A world that plays an application passes
//! bytes from a connection to [`Stream<codec::Frames<Record>>`](fictionet::stdlib::codec::Stream),
//! gets [`Record`]s back, and hands each one
//! to a [`Server`], which puts the streams of each request back
//! together and gives a [`Request`] once all of it has come. The world
//! writes the bytes of the [`Response`] it chooses back to the
//! connection and tells the server with [`Server::end`]. A world that
//! plays a web server does the reverse with [`Request::to_bytes`] and a
//! [`Client`].
//!
//! Each stream a request carries has a size limit, and so do the
//! bytes a decoder holds, the stream bytes held across all open requests,
//! and the number of requests open at once.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
//! use fictionet::stdlib::fastcgi::{Pairs, Request, Role, Server, ServerEvent};
//!
//! // What a web server sends for GET /hello: two parameters and no body.
//! let sent = Request {
//!     id: 1,
//!     role: Role::Responder,
//!     keep_conn: false,
//!     params: Pairs(vec![
//!         (b"REQUEST_METHOD".to_vec(), b"GET".to_vec()),
//!         (b"SCRIPT_NAME".to_vec(), b"/hello".to_vec()),
//!     ]),
//!     stdin: Vec::new(),
//!     data: Vec::new(),
//! }
//! .to_bytes().unwrap();
//!
//! let mut stream = Stream::new(Frames::<fictionet::stdlib::fastcgi::Record>::new());
//! let mut server = Server::new();
//! let mut reply = Vec::new();
//! pump(&mut stream, &sent, |record| {
//!     match server.receive(&record) {
//!         Ok(Some(ServerEvent::Request(req))) => {
//!             assert_eq!(req.param(b"SCRIPT_NAME"), Some(&b"/hello"[..]));
//!             let page = b"Content-Type: text/plain\r\n\r\nhello".to_vec();
//!             req.respond(page).write(&mut reply).unwrap();
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

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use fictionet::stdlib::codec::{Wire, be16};

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

/// Why bytes are not FastCGI records, pairs, bodies or a whole request or
/// response, why a value cannot be written, or why a [`Server`] or
/// [`Client`] cannot take a record into a request.
///
/// A record fault from [`codec::Frames<Record>`](fictionet::stdlib::codec::Frames) ends the stream: the connection holds
/// no more records a reader can find, and a real application closes it.
///
/// For a [`Server`], an error about a request whose streams were coming in
/// drops what it held, and later records for it are ignored. The request
/// stays open, as the specification keeps its ID active, until the
/// application sends END_REQUEST and calls [`Server::end`]. A request
/// refused at its BEGIN_REQUEST ([`Error::Body`],
/// [`Error::UnknownRole`] or [`Error::TooManyRequests`]) is
/// not opened.
///
/// For a [`Client`], an error drops the output gathered for the request,
/// and its later STDOUT and STDERR records and its END_REQUEST are
/// ignored. [`Error::TooManyRequests`] keeps nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A record's version byte was not 1.
    Version(u8),
    /// An exact record parse found the input ended before a complete
    /// record, including empty input.
    RecordTruncated,
    /// An exact record parse found bytes after the first complete record.
    Trailing,
    /// The record exceeds the configured limit, including padding.
    RecordTooLong {
        /// The record length, including its header and padding.
        length: usize,
        /// The maximum accepted record length.
        limit: usize,
    },
    /// A record's content is not the body its type needs: it is not 8
    /// bytes.
    BodyLength,
    /// A length, name or value in name and value pairs runs past the end
    /// of the bytes.
    PairTruncated,
    /// There are more than [`MAX_PAIRS`] name and value pairs.
    TooManyPairs,
    /// The encoded name and value pairs exceed [`MAX_PARAMS`] bytes.
    PairsTooLong,
    /// Records for a whole stream, request or response end before
    /// completion.
    SequenceTruncated,
    /// Records have different IDs, an unexpected type, or follow completion.
    Unexpected,
    /// The value cannot be written without changing it.
    Unwritable,
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

impl Error {
    /// The request the error is about, for an error a [`Server`] or
    /// [`Client`] reports about one request.
    pub fn id(&self) -> Option<u16> {
        match *self {
            Error::Body { id, .. }
            | Error::UnknownRole { id, .. }
            | Error::TooManyRequests { id }
            | Error::TooLarge { id, .. }
            | Error::Duplicate { id }
            | Error::AfterEnd { id, .. }
            | Error::OutOfOrder { id, .. } => Some(id),
            _ => None,
        }
    }
}

fictionet::error_display!(Error, f, {
    Error::Version(v) => write!(f, "FastCGI version {v}, not 1"),
    Error::RecordTruncated => f.write_str("input ended before a complete FastCGI record"),
    Error::Trailing => f.write_str("bytes follow the FastCGI record"),
    Error::RecordTooLong { length, limit } => {
        write!(f, "record length {length} exceeds {limit}")
    }
    Error::BodyLength => f.write_str("record body is not 8 bytes"),
    Error::PairTruncated => f.write_str("name and value pair runs past the end"),
    Error::TooManyPairs => write!(f, "more than {MAX_PAIRS} name and value pairs"),
    Error::PairsTooLong => write!(f, "pairs exceed {MAX_PARAMS} bytes"),
    Error::SequenceTruncated => f.write_str("input ends before completion"),
    Error::Unexpected => f.write_str("unexpected record in sequence"),
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
    Error::Body { id, kind } => {
        write!(f, "request {id}: malformed body in record type {kind}")
    }
    Error::UnknownRole { id, role } => write!(f, "request {id}: unknown role {role}"),
    Error::TooManyRequests { id } => {
        write!(f, "request {id}: more than {MAX_REQUESTS} open")
    }
    Error::TooLarge { id, kind } => {
        write!(f, "request {id}: stream of record type {kind} too large")
    }
    Error::Duplicate { id } => write!(f, "request {id}: begun twice"),
    Error::AfterEnd { id, kind } => {
        write!(f, "request {id}: record type {kind} after its stream ended")
    }
    Error::OutOfOrder { id, kind } => {
        write!(
            f,
            "request {id}: record type {kind} before the streams ahead of it ended"
        )
    }
});

impl Record {
    /// A record carrying `content`, padded to a multiple of 8 bytes as the
    /// specification recommends. Writing refuses content over [`MAX_CONTENT`].
    pub fn new(kind: u8, request_id: u16, content: &[u8]) -> Record {
        let padding = ((8 - content.len() % 8) % 8) as u8;
        Record {
            kind,
            request_id,
            content: content.to_vec(),
            padding,
        }
    }

    /// Reads the record at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the record and how many bytes
    /// of `b` it took, padding included.
    fn parse_prefix(b: &[u8], limit: usize) -> Result<Option<(Record, usize)>, Error> {
        // A bad version is known from the first byte.
        match b.first() {
            None => return Ok(None),
            Some(&v) if v != VERSION => return Err(Error::Version(v)),
            Some(_) => {}
        }
        let Some(&[_, kind, id_hi, id_lo, hi, lo, padding, _]) = b.get(..HEADER_LEN) else {
            return Ok(None);
        };
        let content_len = usize::from(u16::from_be_bytes([hi, lo]));
        let request_id = u16::from_be_bytes([id_hi, id_lo]);
        let content_end = HEADER_LEN + content_len;
        let end = content_end + usize::from(padding);
        if end > limit {
            return Err(Error::RecordTooLong { length: end, limit });
        }
        if b.len() < end {
            return Ok(None);
        }
        let record = Record {
            kind,
            request_id,
            content: b[HEADER_LEN..content_end].to_vec(),
            padding,
        };
        Ok(Some((record, end)))
    }

    /// Whether this is a management record: one with request ID 0.
    pub fn is_management(&self) -> bool {
        self.request_id == NULL_REQUEST_ID
    }

    /// A BEGIN_REQUEST record for request `id`.
    pub fn begin_request(id: u16, body: BeginRequest) -> Record {
        Record::new(
            kind::BEGIN_REQUEST,
            id,
            &body.to_bytes().unwrap_or_else(|never| match never {}),
        )
    }

    /// An ABORT_REQUEST record for request `id`.
    pub fn abort_request(id: u16) -> Record {
        Record::new(kind::ABORT_REQUEST, id, &[])
    }

    /// An END_REQUEST record for request `id`.
    pub fn end_request(id: u16, body: EndRequest) -> Record {
        Record::new(
            kind::END_REQUEST,
            id,
            &body.to_bytes().unwrap_or_else(|never| match never {}),
        )
    }

    /// The UNKNOWN_TYPE management record that answers a management record
    /// of type `unknown`.
    pub fn unknown_type(unknown: u8) -> Record {
        Record::new(
            kind::UNKNOWN_TYPE,
            NULL_REQUEST_ID,
            &UnknownType(unknown)
                .to_bytes()
                .unwrap_or_else(|never| match never {}),
        )
    }

    /// A GET_VALUES record asking for every name. Refuses excess pair
    /// counts and names that cannot fit together in one record.
    pub fn get_values(names: &[&[u8]]) -> Result<Record, Error> {
        let (bytes, _) = encode_pairs_within(names.iter().map(|n| (*n, &[][..])), MAX_CONTENT)?;
        Ok(Record::new(kind::GET_VALUES, NULL_REQUEST_ID, &bytes))
    }

    /// A GET_VALUES_RESULT record carrying every pair. Refuses excess
    /// pair counts and pairs that cannot fit together in one record.
    pub fn get_values_result(pairs: &Pairs) -> Result<Record, Error> {
        let (bytes, _) = encode_pairs_within(borrowed(&pairs.0), MAX_CONTENT)?;
        Ok(Record::new(
            kind::GET_VALUES_RESULT,
            NULL_REQUEST_ID,
            &bytes,
        ))
    }
}

impl Wire for Record {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one record, including padding. Refuses a version other
    /// than 1, incomplete input, and trailing bytes. Padding bytes may hold anything.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match Self::parse_prefix(b, MAX_RECORD)? {
            Some((record, used)) if used == b.len() => Ok(record),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::RecordTruncated),
        }
    }

    /// Appends the header, content, and zero padding. Refuses content over
    /// [`MAX_CONTENT`] or output length overflow without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.content.len() > MAX_CONTENT {
            return Err(Error::Unwritable);
        }
        let length = HEADER_LEN + self.content.len() + usize::from(self.padding);
        let end = out.len().checked_add(length).ok_or(Error::Unwritable)?;
        out.push(VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&(self.content.len() as u16).to_be_bytes());
        out.push(self.padding);
        out.push(0);
        out.extend_from_slice(&self.content);
        out.resize(end, 0);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Reads FastCGI records without holding input bytes.
    ///
    /// Use with [`fictionet::stdlib::codec::Stream`] for input bounded by [`Frames::limit`](fictionet::stdlib::codec::Frames::limit).
    /// Partial records return [`fictionet::stdlib::codec::Step::Need`], including at EOF. The stream reports
    /// truncation at EOF and framing errors once. Body parsing stays separate.
    ///
    /// ```
    /// use fictionet::stdlib::codec::Frames;
    /// use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
    /// use fictionet::stdlib::fastcgi::{Record, kind};
    ///
    /// let record = Record { kind: kind::STDIN, request_id: 1, content: vec![7, 8], padding: 0 };
    /// let bytes = Wire::to_bytes(&record)?;
    /// let mut stream = Stream::new(Frames::<Record>::new());
    /// let mut records = Vec::new();
    /// pump(&mut stream, &bytes[..3], |record| records.push(record))?;
    /// pump(&mut stream, &bytes[3..], |record| records.push(record))?;
    /// finish(&mut stream, |record| records.push(record))?;
    /// assert_eq!(records, [record]);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    Record => (Record, Error, usize);
    name = "FastCGI";
    default { MAX_RECORD }
    normalize(limit) { limit.clamp(HEADER_LEN, MAX_RECORD) }
    capacity(limit) { *limit }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        Record::parse_prefix(input, limit)
    }
}

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

macro_rules! fixed_body {
    ($ty:ty, $read:expr, $write:expr) => {
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = core::convert::Infallible;

            /// Reads an eight-byte body. Refuses any other length.
            /// Reserved bytes may hold anything.
            fn parse(content: &[u8]) -> Result<Self, Error> {
                if content.len() != 8 {
                    return Err(Error::BodyLength);
                }
                ($read)(content)
            }

            /// Appends eight bytes with zero reserved bytes. Refuses no values.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
                out.extend_from_slice(&($write)(self));
                Ok(())
            }
        }
    };
}

fixed_body!(
    BeginRequest,
    |b: &[u8]| Ok(BeginRequest {
        role: Role::from_code(be16(b, 0).ok_or(Error::BodyLength)?),
        flags: b[2]
    }),
    |v: &BeginRequest| {
        let [a, b] = v.role.code().to_be_bytes();
        [a, b, v.flags, 0, 0, 0, 0, 0]
    }
);
fixed_body!(
    EndRequest,
    |b: &[u8]| Ok(EndRequest {
        app_status: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        protocol_status: ProtocolStatus::from_code(b[4]),
    }),
    |v: &EndRequest| {
        let [a, b, c, d] = v.app_status.to_be_bytes();
        [a, b, c, d, v.protocol_status.code(), 0, 0, 0]
    }
);

/// The eight-byte UNKNOWN_TYPE body, naming the unrecognized record type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownType(
    /// The unrecognized record type.
    pub u8,
);

fixed_body!(
    UnknownType,
    |b: &[u8]| Ok(UnknownType(b[0])),
    |v: &UnknownType| [v.0, 0, 0, 0, 0, 0, 0, 0]
);

/// A list of FastCGI name and value pairs, bounded by [`MAX_PARAMS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pairs(
    /// The names and values, in order.
    pub Vec<(Vec<u8>, Vec<u8>)>,
);

impl Wire for Pairs {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads name and value pairs. Each pair is the name's length, the
    /// value's length, the name and the value. A length below 128 takes one
    /// byte; a longer one takes four, with the top bit of the first set.
    /// Refuses truncated pairs, excess pair counts, and input over [`MAX_PARAMS`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_PARAMS {
            return Err(Error::PairsTooLong);
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if out.len() >= MAX_PAIRS {
                return Err(Error::TooManyPairs);
            }
            let (name_len, at) = read_len(b, i)?;
            let (value_len, at) = read_len(b, at)?;
            let name_end = at
                .checked_add(name_len)
                .filter(|&e| e <= b.len())
                .ok_or(Error::PairTruncated)?;
            let value_end = name_end
                .checked_add(value_len)
                .filter(|&e| e <= b.len())
                .ok_or(Error::PairTruncated)?;
            out.push((b[at..name_end].to_vec(), b[name_end..value_end].to_vec()));
            i = value_end;
        }
        Ok(Pairs(out))
    }

    /// Appends pairs with one-byte or four-byte lengths. Refuses excess
    /// counts, lengths, or total size without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let (bytes, _) = encode_pairs_within(borrowed(&self.0), MAX_PARAMS)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// The pairs as borrowed names and values.
fn borrowed(pairs: &[(Vec<u8>, Vec<u8>)]) -> impl Iterator<Item = (&[u8], &[u8])> {
    pairs.iter().map(|(n, v)| (n.as_slice(), v.as_slice()))
}

/// Encodes all pairs within `max` bytes, or refuses the value.
/// Returns the bytes and the end of each pair for PARAMS record boundaries.
fn encode_pairs_within<'a>(
    pairs: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    max: usize,
) -> Result<(Vec<u8>, Vec<usize>), Error> {
    let mut out = Vec::new();
    let mut ends = Vec::new();
    for (count, (name, value)) in pairs.enumerate() {
        if count >= MAX_PAIRS || name.len() > MAX_PAIR_LEN || value.len() > MAX_PAIR_LEN {
            return Err(Error::Unwritable);
        }
        let size = len_size(name.len())
            .checked_add(len_size(value.len()))
            .and_then(|s| s.checked_add(name.len()))
            .and_then(|s| s.checked_add(value.len()))
            .and_then(|s| s.checked_add(out.len()));
        match size {
            Some(total) if total <= max => {}
            _ => return Err(Error::Unwritable),
        }
        write_len(&mut out, name.len());
        write_len(&mut out, value.len());
        out.extend_from_slice(name);
        out.extend_from_slice(value);
        ends.push(out.len());
    }
    Ok((out, ends))
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
fn read_len(b: &[u8], i: usize) -> Result<(usize, usize), Error> {
    let first = *b.get(i).ok_or(Error::PairTruncated)?;
    if first < 0x80 {
        return Ok((usize::from(first), i + 1));
    }
    let four = b
        .get(i..)
        .and_then(|r| r.get(..4))
        .ok_or(Error::PairTruncated)?;
    let n = u32::from_be_bytes([four[0], four[1], four[2], four[3]]) & 0x7fff_ffff;
    let n = usize::try_from(n).map_err(|_| Error::PairTruncated)?;
    Ok((n, i + 4))
}

/// Appends the records of a stream: the data in records of at most
/// [`MAX_CONTENT`] bytes, then the empty record that ends the stream.
fn write_stream(out: &mut Vec<u8>, kind: u8, id: u16, data: &[u8]) -> Result<(), Error> {
    for chunk in data.chunks(CHUNK) {
        Record::new(kind, id, chunk).write(out)?;
    }
    Record::new(kind, id, &[]).write(out)
}

/// Appends the records of a PARAMS stream holding `bytes`, whose pairs end
/// at `ends`. Each record ends at the end of a pair when one fits, since
/// some applications, PHP-FPM among them, read the pairs of each PARAMS
/// record on their own. A pair too long for one record spans records.
fn write_params(out: &mut Vec<u8>, id: u16, bytes: &[u8], ends: &[usize]) -> Result<(), Error> {
    let mut start = 0;
    while start < bytes.len() {
        let limit = start.saturating_add(CHUNK).min(bytes.len());
        // The last pair end that fits, or the limit if none does.
        let at = ends.partition_point(|&e| e <= limit);
        let cut = match at.checked_sub(1).map(|i| ends[i]) {
            Some(e) if e > start => e,
            _ => limit,
        };
        Record::new(kind::PARAMS, id, &bytes[start..cut]).write(out)?;
        start = cut;
    }
    Record::new(kind::PARAMS, id, &[]).write(out)
}

/// A stream's data carried in records, ending with an empty record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordStream {
    /// The record type, such as STDIN or PARAMS.
    pub kind: u8,
    /// The request ID.
    pub request_id: u16,
    /// The complete stream contents.
    pub data: Vec<u8>,
}

impl Wire for RecordStream {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a terminated record stream. Refuses mixed types or IDs,
    /// missing termination, trailing records, and excess stream lengths.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut value: Option<Self> = None;
        read_sequence(bytes, |record| {
            let v = value.get_or_insert_with(|| Self {
                kind: record.kind,
                request_id: record.request_id,
                data: Vec::new(),
            });
            if v.kind != record.kind {
                return Err(Error::Unexpected);
            }
            let limit = if v.kind == kind::PARAMS {
                MAX_PARAMS
            } else {
                MAX_STREAM
            };
            if record.content.len() > limit.saturating_sub(v.data.len()) {
                return Err(Error::TooLarge {
                    id: v.request_id,
                    kind: v.kind,
                });
            }
            v.data.extend_from_slice(&record.content);
            Ok(if record.content.is_empty() {
                value.take()
            } else {
                None
            })
        })
    }

    /// Appends records and an empty terminator. Refuses data over
    /// [`MAX_PARAMS`] for PARAMS or [`MAX_STREAM`] otherwise, without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let limit = if self.kind == kind::PARAMS {
            MAX_PARAMS
        } else {
            MAX_STREAM
        };
        if self.data.len() > limit {
            return Err(Error::Unwritable);
        }
        let mut bytes = Vec::new();
        write_stream(&mut bytes, self.kind, self.request_id, &self.data)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

fn read_sequence<T>(
    mut bytes: &[u8],
    mut receive: impl FnMut(&Record) -> Result<Option<T>, Error>,
) -> Result<T, Error> {
    let mut id = None;
    while !bytes.is_empty() {
        let (record, used) =
            Record::parse_prefix(bytes, MAX_RECORD)?.ok_or(Error::SequenceTruncated)?;
        if id.is_some_and(|id| id != record.request_id) {
            return Err(Error::Unexpected);
        }
        id = Some(record.request_id);
        bytes = &bytes[used..];
        if let Some(value) = receive(&record)? {
            return if bytes.is_empty() {
                Ok(value)
            } else {
                Err(Error::Unexpected)
            };
        }
    }
    Err(Error::SequenceTruncated)
}

/// A whole request: the BEGIN_REQUEST body and every stream it carries,
/// put back together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The nonzero request ID. 0 belongs to management records.
    pub id: u16,
    /// The role the application is to play.
    pub role: Role,
    /// Whether the web server asks to keep the connection open afterward.
    pub keep_conn: bool,
    /// The CGI parameters, in the order they came.
    pub params: Pairs,
    /// The request body. An authorizer gets none.
    pub stdin: Vec<u8>,
    /// The file a filter works on. Other roles get none.
    pub data: Vec<u8>,
}

impl Request {
    /// The value of the first parameter called `name`.
    pub fn param(&self, name: &[u8]) -> Option<&[u8]> {
        self.params
            .0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
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
    /// The nonzero request ID.
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

impl Wire for Request {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads BEGIN_REQUEST, PARAMS, STDIN, and DATA for one request.
    /// Refuses malformed or out-of-order records, excess stream lengths,
    /// unsupported roles, BEGIN_REQUEST flags other than KEEP_CONN, missing
    /// completion, and trailing records.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut server = Server::new();
        let mut first = true;
        read_sequence(bytes, |record| {
            if record.request_id == 0
                || (first && record.kind != kind::BEGIN_REQUEST)
                || !matches!(
                    record.kind,
                    kind::BEGIN_REQUEST | kind::PARAMS | kind::STDIN | kind::DATA
                )
            {
                return Err(Error::Unexpected);
            }
            first = false;
            if record.kind == kind::BEGIN_REQUEST
                && record
                    .content
                    .get(2)
                    .is_some_and(|flags| flags & !KEEP_CONN != 0)
            {
                return Err(Error::Unexpected);
            }
            match server.receive(record)? {
                Some(ServerEvent::Request(request)) => Ok(Some(request)),
                None => Ok(None),
                _ => Err(Error::Unexpected),
            }
        })
    }

    /// Appends BEGIN_REQUEST, then PARAMS, then STDIN unless the role is
    /// [`Role::Authorizer`], then DATA for [`Role::Filter`]. A numbered role
    /// equal to a named role has the same encoding. Each PARAMS record holds
    /// whole pairs unless a pair is too long for one record.
    /// Refuses zero IDs, unsupported roles, unused stream data, and excess
    /// lengths or pair counts without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let role = Role::from_code(self.role.code());
        if self.id == 0
            || matches!(role, Role::Other(_))
            || (role == Role::Authorizer && !self.stdin.is_empty())
            || (role != Role::Filter && !self.data.is_empty())
            || self.stdin.len() > MAX_STREAM
            || self.data.len() > MAX_STREAM
        {
            return Err(Error::Unwritable);
        }
        let (params, ends) = encode_pairs_within(borrowed(&self.params.0), MAX_PARAMS)?;
        let begin = BeginRequest {
            role,
            flags: if self.keep_conn { KEEP_CONN } else { 0 },
        };
        let mut bytes = Record::begin_request(self.id, begin).to_bytes()?;
        write_params(&mut bytes, self.id, &params, &ends)?;
        if role != Role::Authorizer {
            write_stream(&mut bytes, kind::STDIN, self.id, &self.stdin)?;
        }
        if role == Role::Filter {
            write_stream(&mut bytes, kind::DATA, self.id, &self.data)?;
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Response {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads STDOUT, STDERR, and END_REQUEST for one response. Refuses
    /// invalid records, excess stream lengths, zero or mixed IDs, missing
    /// END_REQUEST, and trailing records.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut client = Client::new();
        read_sequence(bytes, |record| {
            if record.request_id == 0
                || !matches!(record.kind, kind::STDOUT | kind::STDERR | kind::END_REQUEST)
            {
                return Err(Error::Unexpected);
            }
            match client.receive(record)? {
                Some(ClientEvent::Response(response)) => Ok(Some(response)),
                None => Ok(None),
                _ => Err(Error::Unexpected),
            }
        })
    }

    /// Appends STDOUT, nonempty STDERR, and END_REQUEST. Refuses zero IDs
    /// and streams over [`MAX_STREAM`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.id == 0 || self.stdout.len() > MAX_STREAM || self.stderr.len() > MAX_STREAM {
            return Err(Error::Unwritable);
        }
        let mut bytes = Vec::new();
        write_stream(&mut bytes, kind::STDOUT, self.id, &self.stdout)?;
        if !self.stderr.is_empty() {
            write_stream(&mut bytes, kind::STDERR, self.id, &self.stderr)?;
        }
        let end = EndRequest {
            app_status: self.app_status,
            protocol_status: self.protocol_status,
        };
        Record::end_request(self.id, end).write(&mut bytes)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

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
/// failed with an [`Error`] too, so the world answers it with
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
        self.open
            .values()
            .map(|r| r.params.len() + r.stdin.len() + r.data.len())
            .sum()
    }

    /// Whether open request `id` asked to keep the connection open after
    /// it, or `None` if it is not open. An application that answers an
    /// abort or an error with END_REQUEST closes the connection when this
    /// is false.
    pub fn keep_conn(&self, id: u16) -> Option<bool> {
        self.open
            .get(&id)
            .map(|r| r.keep_conn)
            .or_else(|| self.answering.get(&id).copied())
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
    pub fn receive(&mut self, record: &Record) -> Result<Option<ServerEvent>, Error> {
        let id = record.request_id;
        if record.is_management() {
            return match record.kind {
                // The values of a GET_VALUES record are empty.
                kind::GET_VALUES => match Pairs::parse(&record.content).map(|pairs| pairs.0) {
                    Ok(pairs) if pairs.iter().all(|(_, v)| v.is_empty()) => Ok(Some(
                        ServerEvent::GetValues(pairs.into_iter().map(|(n, _)| n).collect()),
                    )),
                    _ => Err(Error::Body {
                        id,
                        kind: record.kind,
                    }),
                },
                k => Ok(Some(ServerEvent::UnknownType(k))),
            };
        }
        match record.kind {
            kind::BEGIN_REQUEST => {
                if self.open.contains_key(&id) || self.answering.contains_key(&id) {
                    self.fail(id);
                    return Err(Error::Duplicate { id });
                }
                let body = BeginRequest::parse(&record.content).map_err(|_| Error::Body {
                    id,
                    kind: record.kind,
                })?;
                if let Role::Other(role) = body.role {
                    return Err(Error::UnknownRole { id, role });
                }
                if self.open() >= MAX_REQUESTS {
                    return Err(Error::TooManyRequests { id });
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
                Ok(self
                    .answering
                    .contains_key(&id)
                    .then_some(ServerEvent::Abort(id)))
            }
            kind::PARAMS | kind::STDIN | kind::DATA => {
                let held = self.held();
                let Some(req) = self.open.get_mut(&id) else {
                    return Ok(None);
                };
                // The streams come one after another: PARAMS, then STDIN,
                // then DATA. `ahead` is whether those before this one ended.
                let (buf, done, limit, ahead) = match record.kind {
                    kind::PARAMS => (&mut req.params, &mut req.params_done, MAX_PARAMS, true),
                    kind::STDIN if req.role != Role::Authorizer => (
                        &mut req.stdin,
                        &mut req.stdin_done,
                        MAX_STREAM,
                        req.params_done,
                    ),
                    kind::DATA if req.role == Role::Filter => (
                        &mut req.data,
                        &mut req.data_done,
                        MAX_STREAM,
                        req.params_done && req.stdin_done,
                    ),
                    _ => return Ok(None),
                };
                let added = if ahead {
                    add_to_stream(buf, done, limit, held, id, record)
                } else {
                    Err(Error::OutOfOrder {
                        id,
                        kind: record.kind,
                    })
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
                let Some(req) = self.open.remove(&id) else {
                    return Ok(None);
                };
                self.answering.insert(id, req.keep_conn);
                let params = Pairs::parse(&req.params).map_err(|_| Error::Body {
                    id,
                    kind: kind::PARAMS,
                })?;
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
) -> Result<(), Error> {
    if *done {
        return Err(Error::AfterEnd {
            id,
            kind: record.kind,
        });
    }
    if record.content.is_empty() {
        *done = true;
        return Ok(());
    }
    let room = limit
        .saturating_sub(buf.len())
        .min(MAX_HELD.saturating_sub(held));
    if record.content.len() > room {
        return Err(Error::TooLarge {
            id,
            kind: record.kind,
        });
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
    Values(Pairs),
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
        self.open
            .values()
            .map(|r| r.stdout.len() + r.stderr.len())
            .sum()
    }

    /// Takes in one record. It returns an event when the record ends a
    /// request or answers a management record, and `Ok(None)` otherwise.
    /// Records of types a web server does not read, such as STDIN, are
    /// ignored, and so are the records of a response after an error about
    /// it, up to and including its END_REQUEST.
    pub fn receive(&mut self, record: &Record) -> Result<Option<ClientEvent>, Error> {
        let id = record.request_id;
        if record.is_management() {
            return match record.kind {
                kind::GET_VALUES_RESULT => match Pairs::parse(&record.content) {
                    Ok(pairs) => Ok(Some(ClientEvent::Values(pairs))),
                    Err(_) => Err(Error::Body {
                        id,
                        kind: record.kind,
                    }),
                },
                kind::UNKNOWN_TYPE => match UnknownType::parse(&record.content) {
                    Ok(k) => Ok(Some(ClientEvent::UnknownType(k.0))),
                    Err(_) => Err(Error::Body {
                        id,
                        kind: record.kind,
                    }),
                },
                _ => Ok(None),
            };
        }
        match record.kind {
            kind::STDOUT | kind::STDERR => {
                if !self.open.contains_key(&id) && self.open.len() >= MAX_REQUESTS {
                    return Err(Error::TooManyRequests { id });
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
                    *out = Outgoing {
                        failed: true,
                        ..Outgoing::default()
                    };
                    return Err(e);
                }
                Ok(None)
            }
            kind::END_REQUEST => {
                let out = self.open.remove(&id).unwrap_or_default();
                if out.failed {
                    return Ok(None);
                }
                let end = EndRequest::parse(&record.content).map_err(|_| Error::Body {
                    id,
                    kind: record.kind,
                })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Decode, Step};
    use fictionet::stdlib::codec::{Fail, Lcg, Stream, finish, pump};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::rounds;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn pair(n: &str, v: &str) -> (Vec<u8>, Vec<u8>) {
        (n.as_bytes().to_vec(), v.as_bytes().to_vec())
    }

    fn records(bytes: &[u8]) -> Vec<Record> {
        let (records, error) = decode_all(Frames::<Record>::new, bytes);
        assert_eq!(error, None);
        records
    }

    fn serve(bytes: &[u8]) -> Vec<Result<Option<ServerEvent>, Error>> {
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
            params: Pairs(vec![
                pair("REQUEST_METHOD", "GET"),
                pair("SCRIPT_NAME", "/hello"),
            ]),
            stdin: Vec::new(),
            data: Vec::new(),
        }
        .to_bytes()
        .unwrap();
        let mut stream = Stream::new(Frames::<Record>::new());
        let mut server = Server::new();
        let mut reply = Vec::new();
        pump(&mut stream, &sent, |record| match server.receive(&record) {
            Ok(Some(ServerEvent::Request(req))) => {
                assert_eq!(req.param(b"SCRIPT_NAME"), Some(&b"/hello"[..]));
                let page = b"Content-Type: text/plain\r\n\r\nhello".to_vec();
                reply.extend(req.respond(page).to_bytes().unwrap());
                assert!(server.end(req.id));
            }
            Ok(_) => {}
            Err(e) => panic!("{e}"),
        })
        .unwrap();
        finish(&mut stream, |_| unreachable!()).unwrap();
        assert_eq!(reply[..8], [1, 6, 0, 1, 0, 33, 7, 0]);
    }

    // Examples from the FastCGI Specification 1.0, appendix B: a responder
    // request with params and stdin, and its reply.
    #[test]
    fn spec_responder_example() {
        let mut sent = Record::begin_request(
            1,
            BeginRequest {
                role: Role::Responder,
                flags: 0,
            },
        )
        .to_bytes()
        .unwrap();
        // {FCGI_PARAMS, 1, "\013\002SERVER_PORT80\013\016SERVER_ADDR199.170.183.42 ... "}
        let mut params = vec![11, 2];
        params.extend_from_slice(b"SERVER_PORT80");
        params.extend_from_slice(&[11, 14]);
        params.extend_from_slice(b"SERVER_ADDR199.170.183.42");
        sent.extend(Record::new(kind::PARAMS, 1, &params).to_bytes().unwrap());
        sent.extend(Record::new(kind::PARAMS, 1, &[]).to_bytes().unwrap());
        sent.extend(
            Record::new(kind::STDIN, 1, b"quantity=100&item=3047936")
                .to_bytes()
                .unwrap(),
        );
        sent.extend(Record::new(kind::STDIN, 1, &[]).to_bytes().unwrap());
        assert_eq!(sent[..16], [1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let events = serve(&sent);
        let Some(Ok(Some(ServerEvent::Request(req)))) = events.last() else {
            panic!("{events:?}")
        };
        assert_eq!(
            req.params.0,
            [
                pair("SERVER_PORT", "80"),
                pair("SERVER_ADDR", "199.170.183.42")
            ]
        );
        assert_eq!(req.stdin, b"quantity=100&item=3047936");
        assert_eq!(req.to_bytes().unwrap(), sent);

        let resp = Response {
            id: 1,
            stdout: b"Content-type: text/html\r\n\r\n<html>\n<head> ... ".to_vec(),
            stderr: Vec::new(),
            app_status: 0,
            protocol_status: ProtocolStatus::RequestComplete,
        };
        let bytes = resp.to_bytes().unwrap();
        let rs = records(&bytes);
        assert_eq!(rs.len(), 3);
        assert_eq!(
            rs[2].to_bytes().unwrap(),
            [1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
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
            params: Pairs(vec![pair("A", "1")]),
            stdin: b"one".to_vec(),
            data: vec![],
        };
        let b = Request {
            id: 2,
            stdin: b"two".to_vec(),
            ..a.clone()
        };
        let ra = records(&a.to_bytes().unwrap());
        let rb = records(&b.to_bytes().unwrap());
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
        let events: Vec<_> = records(&resp.to_bytes().unwrap())
            .iter()
            .map(|r| c.receive(r).unwrap())
            .collect();
        assert_eq!(events.last().unwrap(), &Some(ClientEvent::Response(resp)));
        assert_eq!(c.open(), 0);
    }

    #[test]
    fn records_and_padding() {
        let r = Record::new(kind::STDOUT, 0x0102, b"hello");
        assert_eq!(r.padding, 3);
        let bytes = r.to_bytes().unwrap();
        assert_eq!(
            bytes,
            [
                1, 6, 1, 2, 0, 5, 3, 0, b'h', b'e', b'l', b'l', b'o', 0, 0, 0
            ]
        );
        assert_eq!(Record::parse(&bytes), Ok(r));
        let odd = [1, 6, 0, 1, 0, 1, 2, 0, b'x', 0xaa, 0xbb, 1];
        assert_eq!(Record::parse(&odd), Err(Error::Trailing));
        assert_eq!(
            Record::parse(&odd[..11]),
            Ok(Record {
                kind: 6,
                request_id: 1,
                content: b"x".to_vec(),
                padding: 2
            })
        );
        for n in 0..16 {
            assert_eq!(
                Frames::<Record>::new().decode(&bytes[..n], false),
                Ok(Step::Need),
                "{n} bytes"
            );
            assert_eq!(Record::parse(&bytes[..n]), Err(Error::RecordTruncated));
        }
        assert_eq!(Record::parse(&[2]), Err(Error::Version(2)));
        assert_eq!(
            Record::parse(&[0, 1, 0, 1, 0, 0, 0, 0]),
            Err(Error::Version(0))
        );
        let mut big = Record {
            kind: 5,
            request_id: 9,
            content: vec![7; MAX_CONTENT + 10],
            padding: 255,
        };
        contract::check_wire_value(&big);
        assert_eq!(big.to_bytes(), Err(Error::Unwritable));
        big.content.truncate(MAX_CONTENT);
        let bytes = big.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_RECORD);
        assert_eq!(Record::parse(&bytes), Ok(big));
        let oversized = Record::new(5, 1, &vec![0; MAX_CONTENT + 1]);
        assert_eq!(oversized.content.len(), MAX_CONTENT + 1);
        assert_eq!(oversized.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn pairs() {
        // Lengths below 128 take one byte, others four.
        let long = "v".repeat(200);
        let ps = vec![
            pair("SCRIPT_NAME", "/x"),
            pair("HTTP_COOKIE", &long),
            pair("", ""),
        ];
        let bytes = Pairs(ps.clone()).to_bytes().unwrap();
        assert_eq!(bytes[..2], [11, 2]);
        assert_eq!(bytes[15..20], [11, 0x80, 0, 0, 200]);
        assert_eq!(Pairs::parse(&bytes).map(|pairs| pairs.0), Ok(ps));
        // A four-byte length for a short value is read too.
        assert_eq!(
            Pairs::parse(&[0x80, 0, 0, 1, 0x80, 0, 0, 0, b'a']).map(|pairs| pairs.0),
            Ok(vec![pair("a", "")])
        );
        // Every truncated prefix of a pair fails.
        let one = Pairs(vec![pair("NAME", &long)]).to_bytes().unwrap();
        for n in 1..one.len() {
            assert_eq!(
                Pairs::parse(&one[..n]).map(|pairs| pairs.0),
                Err(Error::PairTruncated),
                "{n} bytes"
            );
        }
        // A huge length is refused, not allocated.
        assert_eq!(
            Pairs::parse(&[0xff, 0xff, 0xff, 0xff, 0]).map(|pairs| pairs.0),
            Err(Error::PairTruncated)
        );
        // Too many pairs.
        let many = vec![0u8; 2 * (MAX_PAIRS + 1)];
        assert_eq!(
            Pairs::parse(&many).map(|pairs| pairs.0),
            Err(Error::TooManyPairs)
        );
        assert_eq!(
            Pairs::parse(&many[..2 * MAX_PAIRS])
                .map(|pairs| pairs.0)
                .unwrap()
                .len(),
            MAX_PAIRS
        );
        let too_many: Vec<(Vec<u8>, Vec<u8>)> = (0..MAX_PAIRS + 5).map(|_| pair("", "")).collect();
        contract::check_wire_value(&Pairs(too_many.clone()));
        assert_eq!(Pairs(too_many).to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn bodies() {
        let b = BeginRequest {
            role: Role::Filter,
            flags: KEEP_CONN,
        };
        assert_eq!(b.to_bytes().unwrap(), [0, 3, 1, 0, 0, 0, 0, 0]);
        assert_eq!(BeginRequest::parse(&b.to_bytes().unwrap()), Ok(b));
        assert!(b.keep_conn());
        let e = EndRequest {
            app_status: 0x01020304,
            protocol_status: ProtocolStatus::Overloaded,
        };
        assert_eq!(e.to_bytes().unwrap(), [1, 2, 3, 4, 2, 0, 0, 0]);
        assert_eq!(EndRequest::parse(&e.to_bytes().unwrap()), Ok(e));
        assert_eq!(
            UnknownType::parse(&Record::unknown_type(42).content),
            Ok(UnknownType(42))
        );
        for n in 0..8 {
            assert_eq!(
                BeginRequest::parse(&b.to_bytes().unwrap()[..n]),
                Err(Error::BodyLength)
            );
            assert_eq!(
                EndRequest::parse(&e.to_bytes().unwrap()[..n]),
                Err(Error::BodyLength)
            );
            assert_eq!(UnknownType::parse(&[0; 8][..n]), Err(Error::BodyLength));
        }
        assert_eq!(BeginRequest::parse(&[0; 9]), Err(Error::BodyLength));
        for c in 0..=255u8 {
            assert_eq!(ProtocolStatus::from_code(c).code(), c);
        }
        for c in [0u16, 1, 2, 3, 4, 0xffff] {
            assert_eq!(Role::from_code(c).code(), c);
        }
    }

    #[test]
    fn management_records() {
        let ask =
            Record::get_values(&[values::MAX_CONNS, values::MAX_REQS, values::MPXS_CONNS]).unwrap();
        let mut s = Server::new();
        let Ok(Some(ServerEvent::GetValues(names))) = s.receive(&ask) else {
            panic!()
        };
        assert_eq!(
            names,
            [values::MAX_CONNS, values::MAX_REQS, values::MPXS_CONNS]
        );
        let answer =
            Record::get_values_result(&Pairs(vec![(values::MAX_REQS.to_vec(), b"32".to_vec())]))
                .unwrap();
        let mut c = Client::new();
        assert_eq!(
            c.receive(&answer),
            Ok(Some(ClientEvent::Values(Pairs(vec![pair(
                "FCGI_MAX_REQS",
                "32"
            )]))))
        );
        // An unknown management type, and the answer.
        let odd = Record::new(200, 0, &[]);
        assert_eq!(s.receive(&odd), Ok(Some(ServerEvent::UnknownType(200))));
        assert_eq!(
            c.receive(&Record::unknown_type(200)),
            Ok(Some(ClientEvent::UnknownType(200)))
        );
        // Malformed management bodies.
        let bad = Record::new(kind::GET_VALUES, 0, &[5]);
        assert_eq!(
            s.receive(&bad),
            Err(Error::Body {
                id: 0,
                kind: kind::GET_VALUES
            })
        );
        let bad = Record::new(kind::GET_VALUES_RESULT, 0, &[5]);
        assert_eq!(
            c.receive(&bad),
            Err(Error::Body {
                id: 0,
                kind: kind::GET_VALUES_RESULT
            })
        );
        let bad = Record::new(kind::UNKNOWN_TYPE, 0, &[5]);
        assert_eq!(
            c.receive(&bad),
            Err(Error::Body {
                id: 0,
                kind: kind::UNKNOWN_TYPE
            })
        );
        // Every management pair must fit in one record.
        let big: Vec<(Vec<u8>, Vec<u8>)> =
            (0..10).map(|i| (vec![b'a' + i], vec![0; 10_000])).collect();
        assert_eq!(
            Record::get_values_result(&Pairs(big)),
            Err(Error::Unwritable)
        );
        assert_eq!(
            Record::get_values(&[&vec![0; MAX_CONTENT]]),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn server_errors() {
        let begin = |id, role| Record::begin_request(id, BeginRequest { role, flags: 0 });
        let mut s = Server::new();
        // A bad BEGIN_REQUEST body.
        assert_eq!(
            s.receive(&Record::new(kind::BEGIN_REQUEST, 1, &[0, 1])),
            Err(Error::Body {
                id: 1,
                kind: kind::BEGIN_REQUEST
            })
        );
        // An unknown role.
        assert_eq!(
            s.receive(&begin(1, Role::Other(9))),
            Err(Error::UnknownRole { id: 1, role: 9 })
        );
        assert_eq!(s.open(), 0);
        // Begun twice: the first stays open until it is ended.
        assert_eq!(s.receive(&begin(1, Role::Responder)), Ok(None));
        assert_eq!(
            s.receive(&begin(1, Role::Responder)),
            Err(Error::Duplicate { id: 1 })
        );
        assert_eq!(s.open(), 1);
        // Records for a failed request are ignored.
        assert_eq!(s.receive(&Record::new(kind::PARAMS, 1, b"x")), Ok(None));
        // Records for requests that are not open are ignored.
        assert_eq!(s.receive(&Record::new(kind::STDIN, 9, b"x")), Ok(None));
        // A stream record after its end.
        s.receive(&begin(2, Role::Responder)).unwrap();
        s.receive(&Record::new(kind::PARAMS, 2, &[1, 0, b'A']))
            .unwrap();
        s.receive(&Record::new(kind::PARAMS, 2, &[])).unwrap();
        assert_eq!(
            s.receive(&Record::new(kind::PARAMS, 2, b"late")),
            Err(Error::AfterEnd {
                id: 2,
                kind: kind::PARAMS
            })
        );
        // Bad pairs in PARAMS, found once the stream ends.
        s.receive(&begin(3, Role::Authorizer)).unwrap();
        s.receive(&Record::new(kind::PARAMS, 3, &[9])).unwrap();
        assert_eq!(
            s.receive(&Record::new(kind::PARAMS, 3, &[])),
            Err(Error::Body {
                id: 3,
                kind: kind::PARAMS
            })
        );
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
        assert_eq!(
            result,
            Err(Error::TooLarge {
                id: 4,
                kind: kind::PARAMS
            })
        );
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
        assert_eq!(
            result,
            Err(Error::TooLarge {
                id: 5,
                kind: kind::STDIN
            })
        );
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
        assert_eq!(
            s.receive(&begin(over, Role::Responder)),
            Err(Error::TooManyRequests { id: over })
        );
        assert_eq!(s.open(), MAX_REQUESTS);
        // Abort.
        assert_eq!(
            s.receive(&Record::abort_request(1)),
            Ok(Some(ServerEvent::Abort(1)))
        );
        assert!(s.end(1));
        assert_eq!(s.receive(&Record::abort_request(1)), Ok(None));
        // STDOUT means nothing to an application.
        assert_eq!(s.receive(&Record::new(kind::STDOUT, 2, b"x")), Ok(None));
        for e in [
            Error::Duplicate { id: 7 },
            Error::TooLarge { id: 7, kind: 5 },
        ] {
            assert_eq!(e.id(), Some(7));
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn client_errors() {
        let mut c = Client::new();
        assert_eq!(
            c.receive(&Record::new(kind::END_REQUEST, 1, &[0; 3])),
            Err(Error::Body {
                id: 1,
                kind: kind::END_REQUEST
            })
        );
        c.receive(&Record::new(kind::STDOUT, 1, &[])).unwrap();
        assert_eq!(
            c.receive(&Record::new(kind::STDOUT, 1, b"x")),
            Err(Error::AfterEnd {
                id: 1,
                kind: kind::STDOUT
            })
        );
        for id in 1..=MAX_REQUESTS as u16 {
            assert_eq!(c.receive(&Record::new(kind::STDERR, id, b"e")), Ok(None));
        }
        let over = MAX_REQUESTS as u16 + 1;
        assert_eq!(
            c.receive(&Record::new(kind::STDOUT, over, b"x")),
            Err(Error::TooManyRequests { id: over })
        );
        let chunk = vec![1u8; MAX_CONTENT];
        let mut result = Ok(None);
        for _ in 0..=MAX_STREAM / MAX_CONTENT {
            result = c.receive(&Record::new(kind::STDOUT, 2, &chunk));
            if result.is_err() {
                break;
            }
        }
        assert_eq!(
            result,
            Err(Error::TooLarge {
                id: 2,
                kind: kind::STDOUT
            })
        );
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
            params: Pairs(vec![pair("REMOTE_USER", "ann")]),
            stdin: Vec::new(),
            data: Vec::new(),
        };
        let events = serve(&base.to_bytes().unwrap());
        assert_eq!(
            events.last(),
            Some(&Ok(Some(ServerEvent::Request(base.clone()))))
        );
        let filter = Request {
            role: Role::Filter,
            stdin: b"in".to_vec(),
            data: b"file".to_vec(),
            ..base
        };
        let events = serve(&filter.to_bytes().unwrap());
        assert_eq!(
            events.last(),
            Some(&Ok(Some(ServerEvent::Request(filter.clone()))))
        );
        // Management IDs cannot name a request.
        let zero = Request { id: 0, ..filter };
        contract::check_wire_value(&zero);
        assert_eq!(zero.to_bytes(), Err(Error::Unwritable));
    }

    // The specification keeps a request ID active from BEGIN_REQUEST until
    // the application sends END_REQUEST, not until its streams end.
    #[test]
    fn request_stays_active_until_ended() {
        let req = Request {
            id: 4,
            role: Role::Responder,
            keep_conn: true,
            params: Pairs(vec![pair("A", "1")]),
            stdin: b"body".to_vec(),
            data: Vec::new(),
        };
        let mut s = Server::new();
        let mut got = None;
        for r in records(&req.to_bytes().unwrap()) {
            if let Some(ServerEvent::Request(back)) = s.receive(&r).unwrap() {
                got = Some(back);
            }
        }
        assert_eq!(got, Some(req.clone()));
        // The application is still answering, so the request is open.
        assert_eq!(s.open(), 1);
        // An abort while it answers reaches the world.
        assert_eq!(
            s.receive(&Record::abort_request(4)),
            Ok(Some(ServerEvent::Abort(4)))
        );
        // A second BEGIN_REQUEST for it is refused, and the first stays.
        let begin = Record::begin_request(
            4,
            BeginRequest {
                role: Role::Responder,
                flags: 0,
            },
        );
        assert_eq!(s.receive(&begin), Err(Error::Duplicate { id: 4 }));
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
        assert_eq!(
            s.receive(&Record::abort_request(4)),
            Ok(Some(ServerEvent::Abort(4)))
        );
        assert_eq!(s.open(), 1);
        assert_eq!(s.receive(&Record::new(kind::PARAMS, 4, &[])), Ok(None));
        assert!(s.end(4));
        // Requests being answered count toward the limit.
        for id in 1..=MAX_REQUESTS as u16 {
            let r = Request { id, ..req.clone() };
            let Some(Ok(Some(ServerEvent::Request(_)))) = records(&r.to_bytes().unwrap())
                .iter()
                .map(|x| s.receive(x))
                .last()
            else {
                panic!()
            };
        }
        let over = MAX_REQUESTS as u16 + 1;
        let begin = Record::begin_request(
            over,
            BeginRequest {
                role: Role::Responder,
                flags: 0,
            },
        );
        assert_eq!(s.receive(&begin), Err(Error::TooManyRequests { id: over }));
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
            params: Pairs(Vec::new()),
            stdin: b"in".to_vec(),
            data: b"file".to_vec(),
        };
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&req.to_bytes().unwrap()).pop()
        else {
            panic!()
        };
        assert_eq!(got.role, Role::Filter);
        assert_eq!(got.data, b"file");
        let auth = Request {
            role: Role::Other(2),
            stdin: vec![],
            data: vec![],
            ..req
        };
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&auth.to_bytes().unwrap()).pop()
        else {
            panic!()
        };
        assert_eq!(got.role, Role::Authorizer);
        assert!(got.stdin.is_empty());
    }

    #[test]
    fn request_refuses_unknown_begin_flags() {
        for flags in [0, KEEP_CONN, 2, KEEP_CONN | 2, u8::MAX] {
            let mut bytes = Vec::new();
            Record::begin_request(
                1,
                BeginRequest {
                    role: Role::Authorizer,
                    flags,
                },
            )
            .write(&mut bytes)
            .unwrap();
            Record::new(kind::PARAMS, 1, &[]).write(&mut bytes).unwrap();
            if flags & !KEEP_CONN == 0 {
                assert_eq!(
                    Request::parse(&bytes).unwrap().keep_conn,
                    flags & KEEP_CONN != 0
                );
            } else {
                assert_eq!(Request::parse(&bytes), Err(Error::Unexpected));
            }
        }
    }

    #[test]
    fn writers_refuse_loss_and_preserve_long_streams() {
        let mut req = Request {
            id: 3,
            role: Role::Responder,
            keep_conn: true,
            params: Pairs(
                (0..300)
                    .map(|i| (format!("P{i}").into_bytes(), vec![b'x'; 1000]))
                    .collect(),
            ),
            stdin: vec![9; MAX_STREAM + 100],
            data: Vec::new(),
        };
        contract::check_wire_value(&req);
        assert_eq!(req.to_bytes(), Err(Error::Unwritable));
        req.stdin.truncate(MAX_STREAM);
        assert_eq!(req.to_bytes(), Err(Error::Unwritable));
        req.params.0.truncate(200);
        contract::check_wire_value(&req);
        assert_eq!(Request::parse(&req.to_bytes().unwrap()), Ok(req.clone()));
        for bad in [
            Request {
                id: 0,
                ..req.clone()
            },
            Request {
                role: Role::Other(99),
                ..req.clone()
            },
            Request {
                role: Role::Authorizer,
                ..req.clone()
            },
            Request {
                data: vec![1],
                ..req
            },
        ] {
            contract::check_wire_value(&bad);
            assert_eq!(bad.to_bytes(), Err(Error::Unwritable));
        }
        let mut resp = Response {
            id: 3,
            stdout: vec![1; MAX_STREAM + 1],
            stderr: vec![2; 70_000],
            app_status: 1,
            protocol_status: ProtocolStatus::RequestComplete,
        };
        contract::check_wire_value(&resp);
        assert_eq!(resp.to_bytes(), Err(Error::Unwritable));
        resp.stdout.truncate(MAX_STREAM);
        contract::check_wire_value(&resp);
        assert_eq!(Response::parse(&resp.to_bytes().unwrap()), Ok(resp.clone()));
        resp.id = 0;
        contract::check_wire_value(&resp);
        assert_eq!(resp.to_bytes(), Err(Error::Unwritable));
        let empty = RecordStream {
            kind: kind::STDIN,
            request_id: 1,
            data: vec![],
        };
        assert_eq!(
            empty.to_bytes().unwrap(),
            Record::new(kind::STDIN, 1, &[]).to_bytes().unwrap()
        );
    }

    #[test]
    fn stream_splits_records() {
        let a = Record::new(kind::STDIN, 1, b"abc");
        let b = Record::new(kind::STDIN, 1, &[]);
        let mut bytes = a.to_bytes().unwrap();
        b.write(&mut bytes).unwrap();
        contract::check_decode_with_alloc_limit(Frames::<Record>::new, &bytes, 2 * MAX_RECORD);
        assert_eq!(
            decode_all(Frames::<Record>::new, &bytes),
            (vec![a, b], None)
        );
        let mut stream = Stream::new(Frames::<Record>::new());
        assert_eq!(stream.push(&[3, 1, 0, 1, 0, 0, 0, 0]), 8);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::Version(3)))));
        assert_eq!(stream.push(&bytes), bytes.len());
        assert!(stream.next().is_none());
        assert_eq!(stream.buffered(), 8);
    }

    #[test]
    fn stream_reads_many_small_records_in_linear_time() {
        let n = rounds(200_000);
        let one = Record::new(kind::STDIN, 1, b"x").to_bytes().unwrap();
        let mut stream = Stream::new(Frames::<Record>::new());
        let mut count = 0;
        pump(&mut stream, &one.repeat(n), |_| count += 1).unwrap();
        finish(&mut stream, |_| count += 1).unwrap();
        assert_eq!(count, n);
        assert_eq!(stream.buffered(), 0);
    }

    // A stream bounds input while complete requests may span many records.
    #[test]
    fn stream_bounds_input_and_accepts_large_requests() {
        let big = Request {
            id: 1,
            role: Role::Filter,
            keep_conn: false,
            params: Pairs(
                (0..200)
                    .map(|i| (format!("P{i}").into_bytes(), vec![b'x'; 1000]))
                    .collect(),
            ),
            stdin: vec![1; MAX_STREAM],
            data: vec![2; MAX_STREAM],
        };
        let bytes = big.to_bytes().unwrap();
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&bytes).pop() else {
            panic!()
        };
        assert_eq!(got, big);
        let mut stream = Stream::new(Frames::<Record>::new());
        assert_eq!(stream.push(&vec![1; MAX_RECORD + 1]), MAX_RECORD);
        assert_eq!(stream.buffered(), MAX_RECORD);
        let one = Record::new(kind::STDIN, 1, &vec![0; MAX_CONTENT])
            .to_bytes()
            .unwrap();
        let mut stream = Stream::new(Frames::<Record>::new());
        let mut count = 0;
        pump(&mut stream, &one.repeat(20), |_| count += 1).unwrap();
        finish(&mut stream, |_| count += 1).unwrap();
        assert_eq!(count, 20);
    }

    // The stream bytes held across all open requests stay within MAX_HELD.
    #[test]
    fn held_bytes_are_bounded() {
        let chunk = vec![0u8; MAX_CONTENT];
        let mut s = Server::new();
        let mut failed = None;
        'outer: for id in 1..=MAX_REQUESTS as u16 {
            s.receive(&Record::begin_request(
                id,
                BeginRequest {
                    role: Role::Filter,
                    flags: 0,
                },
            ))
            .unwrap();
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
        let Some(Error::TooLarge { id, .. }) = failed else {
            panic!("{failed:?}")
        };
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
        assert!(matches!(failed, Some(Error::TooLarge { id, .. }) if id > 2));
        assert!(c.held() <= MAX_HELD);
        // An END_REQUEST frees what its response held.
        let before = c.held();
        let end = Record::end_request(
            1,
            EndRequest {
                app_status: 0,
                protocol_status: ProtocolStatus::RequestComplete,
            },
        );
        assert!(matches!(
            c.receive(&end),
            Ok(Some(ClientEvent::Response(_)))
        ));
        assert!(c.held() < before);
    }

    /// Everything the fuzz target checks, on one input.
    fn check(data: &[u8]) {
        contract::check_decode_with_alloc_limit(Frames::<Record>::new, data, 2 * MAX_RECORD);
        contract::check_wire::<Record>(data);
        contract::check_wire::<Pairs>(data);
        contract::check_wire::<BeginRequest>(data);
        contract::check_wire::<EndRequest>(data);
        contract::check_wire::<UnknownType>(data);
        contract::check_wire::<RecordStream>(data);
        contract::check_wire::<Request>(data);
        contract::check_wire::<Response>(data);
        let recs = decode_all(Frames::<Record>::new, data).0;
        let mut server = Server::new();
        let mut client = Client::new();
        for r in &recs {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(Record::parse(&bytes), Ok(r.clone()));
            if let Ok(Some(ServerEvent::Request(req))) = server.receive(r) {
                let Some(Ok(Some(ServerEvent::Request(back)))) =
                    serve(&req.to_bytes().unwrap()).pop()
                else {
                    panic!()
                };
                assert_eq!(back, req);
            }
            if let Ok(Some(ClientEvent::Response(resp))) = client.receive(r) {
                let mut c = Client::new();
                let mut last = None;
                for r in records(&resp.to_bytes().unwrap()) {
                    last = c.receive(&r).unwrap();
                }
                assert_eq!(last, Some(ClientEvent::Response(resp)));
            }
            assert!(server.open() <= MAX_REQUESTS && client.open() <= MAX_REQUESTS);
        }
        if let Ok(pairs) = Pairs::parse(data).map(|pairs| pairs.0) {
            assert_eq!(
                Pairs::parse(&Pairs(pairs.clone()).to_bytes().unwrap()).map(|pairs| pairs.0),
                Ok(pairs)
            );
        }
        let _ = BeginRequest::parse(data);
        let _ = EndRequest::parse(data);
    }

    #[test]
    fn fuzz_random_bytes() {
        let mut rng = Lcg::new(1);
        for _ in 0..5000 {
            let len = rng.index(64);
            let mut data = rng.bytes(len);
            // Mostly version 1, so records get read.
            if let Some(b) = data.first_mut()
                && rng.index(8) != 0
            {
                *b = 1;
            }
            check(&data);
        }
    }

    #[test]
    fn fuzz_random_records() {
        let mut rng = Lcg::new(2);
        for _ in 0..3000 {
            let mut data = Vec::new();
            for _ in 0..rng.index(12) {
                let id = rng.index(3) as u16;
                let k = rng.index(13) as u8;
                let content = match rng.index(4) {
                    0 => Vec::new(),
                    1 => BeginRequest {
                        role: Role::from_code(rng.index(5) as u16),
                        flags: rng.next() as u8,
                    }
                    .to_bytes()
                    .unwrap()
                    .to_vec(),
                    2 => Pairs(vec![(rng.bytes(4), rng.bytes(140))])
                        .to_bytes()
                        .unwrap(),
                    _ => {
                        let n = rng.index(20);
                        rng.bytes(n)
                    }
                };
                let mut r = Record::new(k, id, &content);
                r.padding = rng.index(10) as u8;
                data.extend(r.to_bytes().unwrap());
            }
            check(&data);
            let mut changed = data.clone();
            mutate(&mut rng, &mut changed);
            check(&changed);
            // And with bytes cut off the end.
            let cut = rng.index(data.len() + 1);
            check(&data[..cut]);
        }
    }

    #[test]
    fn fuzz_requests_round_trip_in_pieces() {
        let mut rng = Lcg::new(3);
        for _ in 0..2000 {
            let role = [Role::Responder, Role::Authorizer, Role::Filter][rng.index(3)];
            let params = (0..rng.index(5))
                .map(|_| (rng.bytes(130), rng.bytes(200)))
                .collect();
            let req = Request {
                id: 1 + rng.index(1000) as u16,
                role,
                keep_conn: rng.coin(),
                params: Pairs(params),
                stdin: if role == Role::Authorizer {
                    Vec::new()
                } else {
                    rng.bytes(50)
                },
                data: if role == Role::Filter {
                    rng.bytes(50)
                } else {
                    Vec::new()
                },
            };
            let bytes = req.to_bytes().unwrap();
            contract::check_wire_value(&req);
            contract::check_decode_with_alloc_limit(Frames::<Record>::new, &bytes, 2 * MAX_RECORD);
            assert_eq!(Request::parse(&bytes), Ok(req));
            // Every truncated prefix leaves the request unfinished.
            let cut = rng.index(bytes.len());
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
            Err(Error::AfterEnd {
                id: 1,
                kind: kind::STDOUT
            })
        );
        assert_eq!(c.receive(&Record::new(kind::STDOUT, 1, b"b")), Ok(None));
        assert_eq!(c.receive(&Record::new(kind::STDOUT, 1, &[])), Ok(None));
        let end = EndRequest {
            app_status: 0,
            protocol_status: ProtocolStatus::RequestComplete,
        };
        assert_eq!(c.receive(&Record::end_request(1, end)), Ok(None));
        assert_eq!(c.open(), 0);
        // The ID can be used again after END_REQUEST.
        c.receive(&Record::new(kind::STDOUT, 1, b"c")).unwrap();
        let Ok(Some(ClientEvent::Response(r))) = c.receive(&Record::end_request(1, end)) else {
            panic!()
        };
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
            params: Pairs(
                (0..66)
                    .map(|i| (format!("P{i:02}").into_bytes(), vec![b'x'; 1000]))
                    .collect(),
            ),
            stdin: Vec::new(),
            data: Vec::new(),
        };
        let rs = records(&req.to_bytes().unwrap());
        let params: Vec<_> = rs
            .iter()
            .filter(|r| r.kind == kind::PARAMS && !r.content.is_empty())
            .collect();
        assert_eq!(params.len(), 2);
        let mut n = 0;
        for r in params {
            assert!(r.content.len() <= MAX_CONTENT);
            n += Pairs::parse(&r.content).map(|pairs| pairs.0).unwrap().len();
        }
        assert_eq!(n, 66);
        let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&req.to_bytes().unwrap()).pop()
        else {
            panic!()
        };
        assert_eq!(got, req);
        // A pair too long for one record still spans records and comes back.
        for offset in (0..rounds(100_000)).step_by(100_000) {
            let size = (rounds(100_000) - offset).min(100_000);
            let big = Request {
                params: Pairs(vec![
                    pair("A", "1"),
                    (b"B".to_vec(), vec![7; size]),
                    pair("C", "3"),
                ]),
                ..req.clone()
            };
            let Some(Ok(Some(ServerEvent::Request(got)))) = serve(&big.to_bytes().unwrap()).pop()
            else {
                panic!()
            };
            assert_eq!(got, big);
        }
    }

    // A record stream preserves every byte or refuses the value.
    #[test]
    fn record_stream_refuses_excess_lengths() {
        for (kind, limit) in [(kind::STDOUT, MAX_STREAM), (kind::PARAMS, MAX_PARAMS)] {
            let mut value = RecordStream {
                kind,
                request_id: 1,
                data: vec![1; limit + 1],
            };
            contract::check_wire_value(&value);
            assert_eq!(value.to_bytes(), Err(Error::Unwritable));
            value.data.truncate(limit);
            contract::check_wire_value(&value);
            assert_eq!(RecordStream::parse(&value.to_bytes().unwrap()), Ok(value));
        }
        let mut server = Server::new();
        server
            .receive(&Record::begin_request(
                1,
                BeginRequest {
                    role: Role::Authorizer,
                    flags: 0,
                },
            ))
            .unwrap();
        let pairs = RecordStream {
            kind: kind::PARAMS,
            request_id: 1,
            data: vec![0; MAX_PARAMS],
        };
        let last = records(&pairs.to_bytes().unwrap())
            .iter()
            .map(|r| server.receive(r))
            .last()
            .unwrap();
        assert_eq!(
            last,
            Err(Error::Body {
                id: 1,
                kind: kind::PARAMS
            })
        );
    }

    // A role or status given by number is the same value as the named one.
    #[test]
    fn numbered_roles_and_statuses_equal_named_ones() {
        let b = BeginRequest {
            role: Role::Other(1),
            flags: 0,
        };
        assert_eq!(BeginRequest::parse(&b.to_bytes().unwrap()), Ok(b));
        assert_eq!(Role::Other(3), Role::Filter);
        assert_ne!(Role::Other(4), Role::Filter);
        let e = EndRequest {
            app_status: 0,
            protocol_status: ProtocolStatus::Other(0),
        };
        assert_eq!(EndRequest::parse(&e.to_bytes().unwrap()), Ok(e));
        assert_eq!(ProtocolStatus::Other(2), ProtocolStatus::Overloaded);
    }

    // PARAMS, then STDIN, then DATA, as the specification orders them.
    #[test]
    fn streams_come_in_order() {
        let mut s = Server::new();
        s.receive(&Record::begin_request(
            1,
            BeginRequest {
                role: Role::Responder,
                flags: 0,
            },
        ))
        .unwrap();
        assert_eq!(
            s.receive(&Record::new(kind::STDIN, 1, b"x")),
            Err(Error::OutOfOrder {
                id: 1,
                kind: kind::STDIN
            })
        );
        assert_eq!(s.receive(&Record::new(kind::PARAMS, 1, &[])), Ok(None));
        assert_eq!(s.receive(&Record::new(kind::STDIN, 1, &[])), Ok(None));
        assert!(s.end(1));
        s.receive(&Record::begin_request(
            2,
            BeginRequest {
                role: Role::Filter,
                flags: 0,
            },
        ))
        .unwrap();
        s.receive(&Record::new(kind::PARAMS, 2, &[])).unwrap();
        assert_eq!(
            s.receive(&Record::new(kind::DATA, 2, &[])),
            Err(Error::OutOfOrder {
                id: 2,
                kind: kind::DATA
            })
        );
        assert!(!Error::OutOfOrder { id: 2, kind: 8 }.to_string().is_empty());
        assert_eq!(Error::OutOfOrder { id: 2, kind: 8 }.id(), Some(2));
    }

    // The world can learn whether to keep the connection open for a
    // request it is answering, aborted ones included.
    #[test]
    fn keep_conn_survives_abort() {
        let mut s = Server::new();
        for (id, flags) in [(1, 0), (2, KEEP_CONN)] {
            s.receive(&Record::begin_request(
                id,
                BeginRequest {
                    role: Role::Responder,
                    flags,
                },
            ))
            .unwrap();
            assert_eq!(
                s.receive(&Record::abort_request(id)),
                Ok(Some(ServerEvent::Abort(id)))
            );
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
        let begin = Record::begin_request(
            1,
            BeginRequest {
                role: Role::Responder,
                flags: 0,
            },
        );
        let mut s = Server::new();
        s.receive(&begin).unwrap();
        s.receive(&Record::new(kind::PARAMS, 1, &[])).unwrap();
        s.receive(&Record::new(kind::STDIN, 1, b"a")).unwrap();
        // A second BEGIN_REQUEST does not drop the first.
        assert_eq!(s.receive(&begin), Err(Error::Duplicate { id: 1 }));
        assert_eq!(s.open(), 1);
        assert_eq!(s.receive(&begin), Err(Error::Duplicate { id: 1 }));
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
        s2.receive(&Record::begin_request(
            5,
            BeginRequest {
                role: Role::Authorizer,
                flags: 0,
            },
        ))
        .unwrap();
        s2.receive(&Record::new(kind::PARAMS, 5, &[9])).unwrap();
        assert!(s2.receive(&Record::new(kind::PARAMS, 5, &[])).is_err());
        assert_eq!(
            s2.receive(&Record::begin_request(
                5,
                BeginRequest {
                    role: Role::Authorizer,
                    flags: 0
                }
            )),
            Err(Error::Duplicate { id: 5 })
        );
        // A stream record after its end.
        let mut s3 = Server::new();
        s3.receive(&begin).unwrap();
        s3.receive(&Record::new(kind::PARAMS, 1, &[1, 0, b'A']))
            .unwrap();
        s3.receive(&Record::new(kind::PARAMS, 1, &[])).unwrap();
        assert!(s3.receive(&Record::new(kind::PARAMS, 1, b"x")).is_err());
        assert_eq!(s3.receive(&begin), Err(Error::Duplicate { id: 1 }));
        assert_eq!(s3.open(), 1);
        assert_eq!(s3.held(), 0);
    }

    // GET_VALUES carries names with empty values.
    #[test]
    fn get_values_values_are_empty() {
        let mut s = Server::new();
        let bad = Record::new(kind::GET_VALUES, 0, &[1, 1, b'A', b'B']);
        assert_eq!(
            s.receive(&bad),
            Err(Error::Body {
                id: 0,
                kind: kind::GET_VALUES
            })
        );
        // Every name must fit; no name is dropped.
        let long = vec![b'n'; MAX_CONTENT];
        assert_eq!(
            Record::get_values(&[b"A", &long, b"B"]),
            Err(Error::Unwritable)
        );
        let r = Record::get_values(&[b"A", b"B"]).unwrap();
        assert_eq!(
            s.receive(&r),
            Ok(Some(ServerEvent::GetValues(vec![
                b"A".to_vec(),
                b"B".to_vec()
            ])))
        );
    }

    #[test]
    fn stream_checks_an_input_larger_than_capacity() {
        let mut data = Record::abort_request(1).to_bytes().unwrap();
        data.resize(MAX_RECORD + 1, 0);
        check(&data);
    }

    fn records_prefix(bytes: &[u8]) -> Vec<Record> {
        decode_all(Frames::<Record>::new, bytes).0
    }
}
