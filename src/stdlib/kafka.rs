//! Apache Kafka: reading and writing the protocol's frames, headers and
//! primitive types, and the ApiVersions and Metadata messages, with no
//! I/O.
//!
//! Kafka is a log of messages that many services write to and read from.
//! Clients talk to a broker over TCP, usually on port 9092. Every message
//! is a frame: a 4-byte big-endian size, then that many bytes. A request
//! starts with a header that names the API (its key), the API's version,
//! a correlation ID the response copies, and the client's ID. The body
//! that follows depends on the key and version. This module follows the
//! Kafka protocol guide (kafka.apache.org/protocol) and the message
//! definitions in Kafka's source.
//!
//! Nothing here reads a socket. A world that plays a broker passes TCP
//! bytes to [`Stream<Frames>`](super::codec::Stream), gets each frame's
//! payload back, reads it
//! with [`Request::parse`], and writes the reply from
//! [`Response::to_frame`] back to the connection. Which topics exist,
//! and what the broker says about them, is up to world code.
//!
//! Requests carry their key and version, so [`Request::parse`] reads them
//! on its own. Responses do not: a client matches each response to its
//! request by correlation ID and then calls [`Response::parse`] with the
//! request's key and version. [`ApiVersions`](api_key::API_VERSIONS)
//! versions 0 to 5 and [`Metadata`](api_key::METADATA) versions 0 to 13
//! have full bodies. Every other API, and any other version, keeps its
//! body as bytes.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Lengths, counts and frame sizes are bounded by the limits below,
//! and by the bytes that are there. A parsed body can take a few dozen
//! times its size in memory, since each field of a few bytes becomes a
//! struct. A world that wants less sets a lower frame limit with
//! [`Frames::with_limit`].
//!
//! Writers refuse with [`Error::Unwritable`] any value that cannot be
//! preserved in its version, including excess lengths, invalid tags, and
//! non-default fields that version lacks. Primitive fields have named
//! wire values, such as [`Int32`], [`CompactString`], and [`TaggedFields`].
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
//! use fictionet::stdlib::kafka::{
//!     api_key, ApiVersion, ApiVersionsResponse, Frames, Request, RequestBody, Response, ResponseBody,
//!     ResponseHeader,
//! };
//!
//! let mut stream = Stream::new(Frames::new());
//! let mut frames = Vec::new();
//! // ApiVersions version 0, correlation ID 1, client ID "x".
//! let bytes = [0, 0, 0, 11, 0, 18, 0, 0, 0, 0, 0, 1, 0, 1, b'x'];
//! pump(&mut stream, &bytes, |frame| frames.push(frame)).unwrap();
//! finish(&mut stream, |_| unreachable!()).unwrap();
//! let request = Request::parse(&frames.pop().unwrap().0).unwrap();
//! assert_eq!(request.header.client_id.as_deref(), Some("x"));
//! assert!(matches!(request.body, RequestBody::ApiVersions(_)));
//!
//! // The broker says it speaks ApiVersions versions 0 to 4.
//! let range = ApiVersion { api_key: api_key::API_VERSIONS, min_version: 0, max_version: 4, tagged_fields: vec![] };
//! let versions = ApiVersionsResponse { api_keys: vec![range], ..ApiVersionsResponse::default() };
//! let response = Response {
//!     header: ResponseHeader { correlation_id: request.header.correlation_id, tagged_fields: vec![] },
//!     body: ResponseBody::ApiVersions(versions),
//! };
//! let bytes = response.to_frame(request.header.api_key, request.header.api_version).unwrap().to_bytes().unwrap();
//! assert_eq!(bytes, [0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 18, 0, 0, 0, 4]);
//! assert_eq!(Response::parse(&bytes[4..], api_key::API_VERSIONS, 0).unwrap(), response);
//! ```

extern crate alloc;

extern crate self as fictionet;

use fictionet::stdlib::codec::{Decode, Step, Wire};
use alloc::{borrow::ToOwned, string::String, vec::Vec};

/// The TCP port Kafka brokers listen on.
pub const PORT: u16 = 9092;
/// The largest frame payload this module reads or writes, in bytes. It is
/// Kafka's default for the broker setting `socket.request.max.bytes`.
pub const MAX_FRAME: usize = 104_857_600;
/// The length of a frame's size prefix.
pub const SIZE_LEN: usize = 4;
/// The longest string, in bytes. Kafka refuses longer strings in both the
/// classic and the compact forms.
pub const MAX_STRING: usize = 32_767;
/// The most elements one array may hold.
pub const MAX_ARRAY: usize = 1 << 20;
/// The most tagged fields one tagged-field section may hold.
pub const MAX_TAGGED_FIELDS: usize = 1024;
/// The highest tag a tagged field may have: tags are 31 bits.
pub const MAX_TAG: u32 = i32::MAX as u32;
/// The highest ApiVersions version with a full body here.
pub const API_VERSIONS_MAX_VERSION: i16 = 5;
/// The highest Metadata version with a full body here.
pub const METADATA_MAX_VERSION: i16 = 13;

/// API keys: the numbers that name each request type.
pub mod api_key {
    /// Produce (0).
    pub const PRODUCE: i16 = 0;
    /// Fetch (1).
    pub const FETCH: i16 = 1;
    /// List offsets (2).
    pub const LIST_OFFSETS: i16 = 2;
    /// Metadata (3).
    pub const METADATA: i16 = 3;
    /// Controlled shutdown (7).
    pub const CONTROLLED_SHUTDOWN: i16 = 7;
    /// Offset commit (8).
    pub const OFFSET_COMMIT: i16 = 8;
    /// Offset fetch (9).
    pub const OFFSET_FETCH: i16 = 9;
    /// Find coordinator (10).
    pub const FIND_COORDINATOR: i16 = 10;
    /// Join group (11).
    pub const JOIN_GROUP: i16 = 11;
    /// Heartbeat (12).
    pub const HEARTBEAT: i16 = 12;
    /// Leave group (13).
    pub const LEAVE_GROUP: i16 = 13;
    /// Sync group (14).
    pub const SYNC_GROUP: i16 = 14;
    /// Describe groups (15).
    pub const DESCRIBE_GROUPS: i16 = 15;
    /// List groups (16).
    pub const LIST_GROUPS: i16 = 16;
    /// Sasl handshake (17).
    pub const SASL_HANDSHAKE: i16 = 17;
    /// Api versions (18).
    pub const API_VERSIONS: i16 = 18;
    /// Create topics (19).
    pub const CREATE_TOPICS: i16 = 19;
    /// Delete topics (20).
    pub const DELETE_TOPICS: i16 = 20;
    /// Init producer id (22).
    pub const INIT_PRODUCER_ID: i16 = 22;
    /// Sasl authenticate (36).
    pub const SASL_AUTHENTICATE: i16 = 36;
}

/// Error codes a broker puts in responses. These are the ones a world
/// playing a broker needs most. Kafka defines many more.
pub mod error_code {
    /// None (0).
    pub const NONE: i16 = 0;
    /// Unknown server error (-1).
    pub const UNKNOWN_SERVER_ERROR: i16 = -1;
    /// Corrupt message (2).
    pub const CORRUPT_MESSAGE: i16 = 2;
    /// Unknown topic or partition (3).
    pub const UNKNOWN_TOPIC_OR_PARTITION: i16 = 3;
    /// Leader not available (5).
    pub const LEADER_NOT_AVAILABLE: i16 = 5;
    /// Not leader or follower (6).
    pub const NOT_LEADER_OR_FOLLOWER: i16 = 6;
    /// Invalid topic exception (17).
    pub const INVALID_TOPIC_EXCEPTION: i16 = 17;
    /// Topic authorization failed (29).
    pub const TOPIC_AUTHORIZATION_FAILED: i16 = 29;
    /// Cluster authorization failed (31).
    pub const CLUSTER_AUTHORIZATION_FAILED: i16 = 31;
    /// Unsupported version (35).
    pub const UNSUPPORTED_VERSION: i16 = 35;
    /// Invalid request (42).
    pub const INVALID_REQUEST: i16 = 42;
    /// Unknown topic id (100).
    pub const UNKNOWN_TOPIC_ID: i16 = 100;
}

/// The first version of each API, by key, that uses the flexible
/// encoding: compact strings and arrays, and tagged fields. -1 means no
/// version does. Keys past the end are flexible from version 0, as every
/// API added since Kafka 2.4 is.
const FIRST_FLEXIBLE: [i16; 55] = [
    9, 12, 6, 9, 4, 2, 6, 3, 8, 6, // 0..=9
    3, 6, 4, 4, 4, 5, 3, -1, 3, 5, // 10..=19
    4, 2, 2, 4, 3, 3, 3, 1, 3, 2, // 20..=29
    2, 2, 4, 2, 2, 2, 2, 2, 2, 2, // 30..=39
    2, 2, 2, 2, 1, 0, 0, 1, 1, 1, // 40..=49
    0, 0, 0, 1, 1, // 50..=54
];

/// Whether version `api_version` of the API `api_key` uses the flexible
/// encoding. A negative key is never flexible.
pub fn is_flexible(api_key: i16, api_version: i16) -> bool {
    if api_key < 0 {
        return false;
    }
    match FIRST_FLEXIBLE.get(api_key as usize) {
        Some(&first) => first >= 0 && api_version >= first,
        None => true,
    }
}

/// The request header version that version `api_version` of `api_key`
/// uses: 0 for ControlledShutdown version 0, 2 for flexible versions, and
/// 1 for the rest. Kafka's newest header version, 3, is written like 2,
/// so this gives 2 for it too.
pub fn request_header_version(api_key: i16, api_version: i16) -> u8 {
    if api_key == api_key::CONTROLLED_SHUTDOWN && api_version == 0 {
        0
    } else if is_flexible(api_key, api_version) {
        2
    } else {
        1
    }
}

/// The response header version that version `api_version` of `api_key`
/// uses: 1 for flexible versions and 0 for the rest. ApiVersions always
/// uses 0, so a client that does not yet know what a broker speaks can
/// read its answer.
pub fn response_header_version(api_key: i16, api_version: i16) -> u8 {
    if api_key != api_key::API_VERSIONS && is_flexible(api_key, api_version) { 1 } else { 0 }
}

/// Why bytes could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes ended in the middle of a field.
    Truncated,
    /// A frame's size was negative or over the limit. The stream cannot be
    /// read any further, and a broker closes the connection.
    FrameSize(i32),
    /// An input payload is longer than [`MAX_FRAME`].
    TooLarge(usize),
    /// A varint ran past its last allowed byte.
    Varint,
    /// A string, bytes or array length was negative, over its limit, or
    /// more than the bytes left could hold.
    Length(i64),
    /// A string was not UTF-8.
    Utf8,
    /// A null where this version does not allow one.
    Null,
    /// A tagged field's tag was not above the one before it.
    TagOrder(u32),
    /// A header version this module does not read: above 2 for a
    /// request header, or above 1 for a response header.
    HeaderVersion(u8),
    /// A body version this module has no full body for.
    UnsupportedVersion {
        /// The API key.
        api_key: i16,
        /// The version asked for.
        api_version: i16,
    },
    /// The value cannot be written without changing it.
    Unwritable,
    /// This many bytes were left after the last field.
    Trailing(usize),
    /// A value Kafka does not allow here: a topic named and identified in
    /// a way that version does not support, a tagged field
    /// whose bytes do not match its defined type, or a tag over 31 bits.
    /// The text names which.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => f.write_str("bytes end in the middle of a field"),
            Error::FrameSize(n) => write!(f, "frame size {n} is negative or over the limit"),
            Error::TooLarge(n) => write!(f, "frame payload of {n} bytes is over {MAX_FRAME}"),
            Error::Varint => f.write_str("varint is too long"),
            Error::Length(n) => write!(f, "length {n} is out of range"),
            Error::Utf8 => f.write_str("string is not UTF-8"),
            Error::Null => f.write_str("null where this version does not allow one"),
            Error::TagOrder(t) => write!(f, "tagged field {t} is out of order"),
            Error::HeaderVersion(v) => write!(f, "header version {v} is not one this module reads"),
            Error::UnsupportedVersion { api_key, api_version } => {
                write!(f, "no full body for API {api_key} version {api_version}")
            }
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Trailing(n) => write!(f, "{n} bytes left after the last field"),
            Error::Invalid(what) => write!(f, "not allowed: {what}"),
        }
    }
}

impl core::error::Error for Error {}

/// One tagged field: a tag number and its value's bytes, unread. Flexible
/// versions end each structure with a list of these, so new fields can be
/// added without a new version.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaggedField {
    /// The field's tag.
    pub tag: u32,
    /// The field's value, as sent.
    pub data: Vec<u8>,
}

/// Reads Kafka's primitive types from a byte slice, front to back. Every
/// read checks that its bytes are there and returns [`Error::Truncated`]
/// if they are not.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    /// How many bytes are left.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// How many bytes have been read.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Every byte left.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    /// Succeeds if every byte has been read.
    pub fn finish(&self) -> Result<(), Error> {
        match self.remaining() {
            0 => Ok(()),
            n => Err(Error::Trailing(n)),
        }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// A BOOLEAN: one byte, and any byte but 0 is true.
    pub fn bool(&mut self) -> Result<bool, Error> {
        Ok(self.u8()? != 0)
    }

    /// One unsigned byte.
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }

    /// An INT8.
    pub fn i8(&mut self) -> Result<i8, Error> {
        Ok(i8::from_be_bytes(self.fixed()?))
    }

    /// An INT16, big-endian.
    pub fn i16(&mut self) -> Result<i16, Error> {
        Ok(i16::from_be_bytes(self.fixed()?))
    }

    /// A UINT16, big-endian.
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    /// An INT32, big-endian.
    pub fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_be_bytes(self.fixed()?))
    }

    /// A UINT32, big-endian.
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    /// An INT64, big-endian.
    pub fn i64(&mut self) -> Result<i64, Error> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    /// A FLOAT64: an IEEE 754 double, big-endian.
    pub fn f64(&mut self) -> Result<f64, Error> {
        Ok(f64::from_be_bytes(self.fixed()?))
    }

    /// A UUID: 16 bytes.
    pub fn uuid(&mut self) -> Result<[u8; 16], Error> {
        self.fixed()
    }

    /// An UNSIGNED_VARINT: 7 bits per byte, low bits first, with the top
    /// bit set on every byte but the last. It takes at most 5 bytes, and
    /// the fifth may hold only the top 4 bits of a u32.
    pub fn uvarint(&mut self) -> Result<u32, Error> {
        let mut value = 0u32;
        for i in 0..5 {
            let b = self.u8()?;
            if i == 4 && b > 0x0f {
                return Err(Error::Varint);
            }
            value |= u32::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::Varint)
    }

    /// A VARINT: a zigzag-encoded i32 in an unsigned varint, so small
    /// negative numbers stay short.
    pub fn varint(&mut self) -> Result<i32, Error> {
        let v = self.uvarint()?;
        Ok((v >> 1) as i32 ^ -((v & 1) as i32))
    }

    /// A VARLONG: a zigzag-encoded i64 in at most 10 bytes, the tenth
    /// holding only the top bit.
    pub fn varlong(&mut self) -> Result<i64, Error> {
        let mut value = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            if i == 9 && b > 0x01 {
                return Err(Error::Varint);
            }
            value |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                return Ok((value >> 1) as i64 ^ -((value & 1) as i64));
            }
        }
        Err(Error::Varint)
    }

    fn utf8(&mut self, n: usize) -> Result<String, Error> {
        let b = self.take(n)?;
        core::str::from_utf8(b).map(str::to_owned).map_err(|_| Error::Utf8)
    }

    /// A STRING: an INT16 length, then that many bytes of UTF-8.
    pub fn string(&mut self) -> Result<String, Error> {
        self.nullable_string()?.ok_or(Error::Null)
    }

    /// A NULLABLE_STRING: a STRING, or length -1 for null.
    pub fn nullable_string(&mut self) -> Result<Option<String>, Error> {
        match self.i16()? {
            -1 => Ok(None),
            n if n < 0 => Err(Error::Length(n.into())),
            n => self.utf8(n as usize).map(Some),
        }
    }

    /// A COMPACT_STRING: an unsigned varint holding the length plus 1,
    /// then that many bytes of UTF-8.
    pub fn compact_string(&mut self) -> Result<String, Error> {
        self.compact_nullable_string()?.ok_or(Error::Null)
    }

    /// A COMPACT_NULLABLE_STRING: a COMPACT_STRING, or 0 for null.
    pub fn compact_nullable_string(&mut self) -> Result<Option<String>, Error> {
        match self.uvarint()? {
            0 => Ok(None),
            n => {
                let len = (n - 1) as usize;
                if len > MAX_STRING {
                    return Err(Error::Length(len as i64));
                }
                self.utf8(len).map(Some)
            }
        }
    }

    /// BYTES: an INT32 length, then that many bytes. A length over
    /// [`MAX_FRAME`] is an error.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        self.nullable_bytes()?.ok_or(Error::Null)
    }

    /// NULLABLE_BYTES: BYTES, or length -1 for null.
    pub fn nullable_bytes(&mut self) -> Result<Option<&'a [u8]>, Error> {
        match self.i32()? {
            -1 => Ok(None),
            n if n < 0 || n as usize > MAX_FRAME => Err(Error::Length(n.into())),
            n => self.take(n as usize).map(Some),
        }
    }

    /// COMPACT_BYTES: an unsigned varint holding the length plus 1, then
    /// that many bytes. A length over [`MAX_FRAME`] is an error.
    pub fn compact_bytes(&mut self) -> Result<&'a [u8], Error> {
        self.compact_nullable_bytes()?.ok_or(Error::Null)
    }

    /// COMPACT_NULLABLE_BYTES: COMPACT_BYTES, or 0 for null.
    pub fn compact_nullable_bytes(&mut self) -> Result<Option<&'a [u8]>, Error> {
        match self.uvarint()? {
            0 => Ok(None),
            n => {
                let len = (n - 1) as usize;
                if len > MAX_FRAME {
                    return Err(Error::Length(len as i64));
                }
                self.take(len).map(Some)
            }
        }
    }

    /// Checks an array's element count against [`MAX_ARRAY`] and the bytes
    /// left. Every element takes at least one byte.
    fn count(&self, n: usize) -> Result<usize, Error> {
        if n > MAX_ARRAY || n > self.remaining() { Err(Error::Length(n as i64)) } else { Ok(n) }
    }

    /// An ARRAY's element count: an INT32, or -1 for a null array. The
    /// elements follow, and the caller reads them.
    pub fn array_len(&mut self) -> Result<Option<usize>, Error> {
        match self.i32()? {
            -1 => Ok(None),
            n if n < 0 => Err(Error::Length(n.into())),
            n => self.count(n as usize).map(Some),
        }
    }

    /// A COMPACT_ARRAY's element count: an unsigned varint holding the
    /// count plus 1, or 0 for a null array.
    pub fn compact_array_len(&mut self) -> Result<Option<usize>, Error> {
        match self.uvarint()? {
            0 => Ok(None),
            n => self.count((n - 1) as usize).map(Some),
        }
    }

    /// A tagged-field section: an unsigned varint count, then each field's
    /// tag, size and bytes. Tags must rise and fit in 31 bits, and a size
    /// over [`MAX_FRAME`] is an error.
    pub fn tagged_fields(&mut self) -> Result<Vec<TaggedField>, Error> {
        let n = self.uvarint()? as usize;
        if n > MAX_TAGGED_FIELDS || n > self.remaining() {
            return Err(Error::Length(n as i64));
        }
        let mut out: Vec<TaggedField> = Vec::new();
        for _ in 0..n {
            let tag = self.uvarint()?;
            if tag > MAX_TAG {
                return Err(Error::Invalid("tag over 31 bits"));
            }
            if out.last().is_some_and(|last| tag <= last.tag) {
                return Err(Error::TagOrder(tag));
            }
            let size = self.uvarint()? as usize;
            if size > MAX_FRAME {
                return Err(Error::Length(size as i64));
            }
            let data = self.take(size)?.to_vec();
            out.push(TaggedField { tag, data });
        }
        Ok(out)
    }

    // The same reads in the classic or the flexible form.

    fn str_f(&mut self, flex: bool) -> Result<String, Error> {
        if flex { self.compact_string() } else { self.string() }
    }

    fn nstr_f(&mut self, flex: bool) -> Result<Option<String>, Error> {
        if flex { self.compact_nullable_string() } else { self.nullable_string() }
    }

    fn arr_f(&mut self, flex: bool) -> Result<Option<usize>, Error> {
        if flex { self.compact_array_len() } else { self.array_len() }
    }

    fn tags_f(&mut self, flex: bool) -> Result<Vec<TaggedField>, Error> {
        if flex { self.tagged_fields() } else { Ok(Vec::new()) }
    }

    fn i32s(&mut self, flex: bool) -> Result<Vec<i32>, Error> {
        let n = self.arr_f(flex)?.ok_or(Error::Null)?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(self.i32()?);
        }
        Ok(out)
    }
}

// Scalar and field units share exact parsing and transactional writing.
macro_rules! wire_field {
    ($name:ident, $read:expr, $write:expr) => {
        impl Wire for $name {
            type ParseError = Error;
            type WriteError = Error;

            /// Reads exactly one field. Refuses invalid encodings, excess
            /// lengths or counts, incomplete input, and trailing bytes.
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() > MAX_FRAME + 5 { return Err(Error::TooLarge(bytes.len())); }
                let mut reader = Reader::new(bytes);
                let value = ($read)(&mut reader)?;
                reader.finish()?;
                Ok(Self(value))
            }

            /// Appends the field. Refuses excess lengths or counts and
            /// invalid tagged fields without changing `out`.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                let mut writer = Writer::new();
                writer.limit = MAX_FRAME + 5;
                ($write)(&mut writer, &self.0);
                out.extend_from_slice(&writer.finish()?);
                Ok(())
            }
        }
    };
}

/// A BOOLEAN; zero reads as false and every other byte as true.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boolean(
    /// The field value.
    pub bool,
);

wire_field!(Boolean, |r: &mut Reader<'_>| r.bool(), |w: &mut Writer, v: &bool| w.bool(*v));

/// An INT8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Int8(
    /// The field value.
    pub i8,
);

wire_field!(Int8, |r: &mut Reader<'_>| r.i8(), |w: &mut Writer, v: &i8| w.i8(*v));

/// An unsigned byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uint8(
    /// The field value.
    pub u8,
);

wire_field!(Uint8, |r: &mut Reader<'_>| r.u8(), |w: &mut Writer, v: &u8| w.u8(*v));

/// An INT16.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Int16(
    /// The field value.
    pub i16,
);

wire_field!(Int16, |r: &mut Reader<'_>| r.i16(), |w: &mut Writer, v: &i16| w.i16(*v));

/// A UINT16.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uint16(
    /// The field value.
    pub u16,
);

wire_field!(Uint16, |r: &mut Reader<'_>| r.u16(), |w: &mut Writer, v: &u16| w.u16(*v));

/// An INT32.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Int32(
    /// The field value.
    pub i32,
);

wire_field!(Int32, |r: &mut Reader<'_>| r.i32(), |w: &mut Writer, v: &i32| w.i32(*v));

/// A UINT32.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uint32(
    /// The field value.
    pub u32,
);

wire_field!(Uint32, |r: &mut Reader<'_>| r.u32(), |w: &mut Writer, v: &u32| w.u32(*v));

/// An INT64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Int64(
    /// The field value.
    pub i64,
);

wire_field!(Int64, |r: &mut Reader<'_>| r.i64(), |w: &mut Writer, v: &i64| w.i64(*v));

/// A FLOAT64, compared by its bits.
#[derive(Clone, Debug)]
pub struct Float64(
    /// The field value.
    pub f64,
);

wire_field!(Float64, |r: &mut Reader<'_>| r.f64(), |w: &mut Writer, v: &f64| w.f64(*v));

/// A UUID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uuid(
    /// The field value.
    pub [u8; 16],
);

wire_field!(Uuid, |r: &mut Reader<'_>| r.uuid(), |w: &mut Writer, v: &[u8; 16]| w.uuid(v));

/// An UNSIGNED_VARINT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedVarint(
    /// The field value.
    pub u32,
);

wire_field!(UnsignedVarint, |r: &mut Reader<'_>| r.uvarint(), |w: &mut Writer, v: &u32| w.uvarint(*v));

/// A zigzag VARINT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Varint(
    /// The field value.
    pub i32,
);

wire_field!(Varint, |r: &mut Reader<'_>| r.varint(), |w: &mut Writer, v: &i32| w.varint(*v));

/// A zigzag VARLONG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Varlong(
    /// The field value.
    pub i64,
);

wire_field!(Varlong, |r: &mut Reader<'_>| r.varlong(), |w: &mut Writer, v: &i64| w.varlong(*v));

/// A STRING with a signed 16-bit length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct String16(
    /// The field value.
    pub String,
);

wire_field!(String16, |r: &mut Reader<'_>| r.string(), |w: &mut Writer, v: &String| w.string(v));

/// A NULLABLE_STRING.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullableString(
    /// The field value.
    pub Option<String>,
);

wire_field!(NullableString, |r: &mut Reader<'_>| r.nullable_string(), |w: &mut Writer, v: &Option<String>| w.nullable_string(v.as_deref()));

/// A COMPACT_STRING.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactString(
    /// The field value.
    pub String,
);

wire_field!(CompactString, |r: &mut Reader<'_>| r.compact_string(), |w: &mut Writer, v: &String| w.compact_string(v));

/// A COMPACT_NULLABLE_STRING.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactNullableString(
    /// The field value.
    pub Option<String>,
);

wire_field!(CompactNullableString, |r: &mut Reader<'_>| r.compact_nullable_string(), |w: &mut Writer, v: &Option<String>| w.compact_nullable_string(v.as_deref()));

/// A BYTES field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytesValue(
    /// The field value.
    pub Vec<u8>,
);

wire_field!(BytesValue, |r: &mut Reader<'_>| r.bytes().map(|bytes| bytes.to_vec()), |w: &mut Writer, v: &Vec<u8>| w.bytes(v));

/// A NULLABLE_BYTES field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullableBytes(
    /// The field value.
    pub Option<Vec<u8>>,
);

wire_field!(NullableBytes, |r: &mut Reader<'_>| r.nullable_bytes().map(|value| value.map(|bytes| bytes.to_vec())), |w: &mut Writer, v: &Option<Vec<u8>>| w.nullable_bytes(v.as_deref()));

/// A COMPACT_BYTES field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBytes(
    /// The field value.
    pub Vec<u8>,
);

wire_field!(CompactBytes, |r: &mut Reader<'_>| r.compact_bytes().map(|bytes| bytes.to_vec()), |w: &mut Writer, v: &Vec<u8>| w.compact_bytes(v));

/// A COMPACT_NULLABLE_BYTES field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactNullableBytes(
    /// The field value.
    pub Option<Vec<u8>>,
);

wire_field!(CompactNullableBytes, |r: &mut Reader<'_>| r.compact_nullable_bytes().map(|value| value.map(|bytes| bytes.to_vec())), |w: &mut Writer, v: &Option<Vec<u8>>| w.compact_nullable_bytes(v.as_deref()));

/// A ARRAY count alone; elements are separate wire values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArrayLength(
    /// The field value.
    pub Option<usize>,
);

wire_field!(ArrayLength, |r: &mut Reader<'_>| read_array_count(r, false), |w: &mut Writer, v: &Option<usize>| w.array_len(*v));

/// A COMPACT_ARRAY count alone; elements are separate wire values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactArrayLength(
    /// The field value.
    pub Option<usize>,
);

wire_field!(CompactArrayLength, |r: &mut Reader<'_>| read_array_count(r, true), |w: &mut Writer, v: &Option<usize>| w.compact_array_len(*v));

/// A tagged-field section in strictly increasing tag order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaggedFields(
    /// The field value.
    pub Vec<TaggedField>,
);

wire_field!(TaggedFields, |r: &mut Reader<'_>| r.tagged_fields(), |w: &mut Writer, v: &Vec<TaggedField>| w.tagged_fields(v));

impl PartialEq for Float64 {
    fn eq(&self, other: &Self) -> bool { self.0.to_bits() == other.0.to_bits() }
}

impl Eq for Float64 {}

fn read_array_count(reader: &mut Reader<'_>, compact: bool) -> Result<Option<usize>, Error> {
    let count = if compact { i64::from(reader.uvarint()?) - 1 } else { i64::from(reader.i32()?) };
    match count {
        -1 => Ok(None),
        n if n >= 0 && n <= MAX_ARRAY as i64 => Ok(Some(n as usize)),
        n => Err(Error::Length(n)),
    }
}

/// Builds a bounded encoding for a Wire value.
#[derive(Clone, Debug, Default)]
struct Writer {
    out: Vec<u8>,
    failed: bool,
    limit: usize,
}

impl Writer {
    /// A writer with nothing written.
    fn new() -> Writer {
        Writer { out: Vec::new(), failed: false, limit: MAX_FRAME }
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        if self.failed { Err(Error::Unwritable) } else { Ok(self.out) }
    }

    fn raw(&mut self, bytes: &[u8]) {
        if self.failed || bytes.len() > self.limit.saturating_sub(self.out.len()) {
            self.failed = true;
        } else {
            self.out.extend_from_slice(bytes);
        }
    }

    /// A BOOLEAN.
    fn bool(&mut self, v: bool) {
        self.u8(u8::from(v));
    }

    fn u8(&mut self, value: u8) {
        self.raw(&[value]);
    }

    /// An INT8.
    fn i8(&mut self, v: i8) {
        self.raw(&v.to_be_bytes());
    }

    /// An INT16.
    fn i16(&mut self, v: i16) {
        self.raw(&v.to_be_bytes());
    }

    /// A UINT16.
    fn u16(&mut self, v: u16) {
        self.raw(&v.to_be_bytes());
    }

    /// An INT32.
    fn i32(&mut self, v: i32) {
        self.raw(&v.to_be_bytes());
    }

    /// A UINT32.
    fn u32(&mut self, v: u32) {
        self.raw(&v.to_be_bytes());
    }

    /// An INT64.
    fn i64(&mut self, v: i64) {
        self.raw(&v.to_be_bytes());
    }

    /// A FLOAT64.
    fn f64(&mut self, v: f64) {
        self.raw(&v.to_be_bytes());
    }

    /// A UUID.
    fn uuid(&mut self, v: &[u8; 16]) {
        self.raw(v);
    }

    /// An UNSIGNED_VARINT, in the fewest bytes.
    fn uvarint(&mut self, mut v: u32) {
        while v >= 0x80 {
            self.u8((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.u8(v as u8);
    }

    /// A VARINT.
    fn varint(&mut self, v: i32) {
        self.uvarint(((v << 1) ^ (v >> 31)) as u32);
    }

    /// A VARLONG.
    fn varlong(&mut self, v: i64) {
        let mut u = ((v << 1) ^ (v >> 63)) as u64;
        while u >= 0x80 {
            self.u8((u as u8 & 0x7f) | 0x80);
            u >>= 7;
        }
        self.u8(u as u8);
    }

    /// A STRING.
    fn string(&mut self, s: &str) {
        if s.len() > MAX_STRING { self.failed = true; return; }
        self.i16(s.len() as i16);
        self.raw(s.as_bytes());
    }

    /// A NULLABLE_STRING.
    fn nullable_string(&mut self, s: Option<&str>) {
        match s {
            Some(s) => self.string(s),
            None => self.i16(-1),
        }
    }

    /// A COMPACT_STRING.
    fn compact_string(&mut self, s: &str) {
        if s.len() > MAX_STRING { self.failed = true; return; }
        self.uvarint(s.len() as u32 + 1);
        self.raw(s.as_bytes());
    }

    /// A COMPACT_NULLABLE_STRING.
    fn compact_nullable_string(&mut self, s: Option<&str>) {
        match s {
            Some(s) => self.compact_string(s),
            None => self.uvarint(0),
        }
    }

    /// BYTES.
    fn bytes(&mut self, b: &[u8]) {
        if b.len() > MAX_FRAME { self.failed = true; return; }
        self.i32(b.len() as i32);
        self.raw(b);
    }

    /// NULLABLE_BYTES.
    fn nullable_bytes(&mut self, b: Option<&[u8]>) {
        match b {
            Some(b) => self.bytes(b),
            None => self.i32(-1),
        }
    }

    /// COMPACT_BYTES.
    fn compact_bytes(&mut self, b: &[u8]) {
        if b.len() > MAX_FRAME { self.failed = true; return; }
        self.uvarint(b.len() as u32 + 1);
        self.raw(b);
    }

    /// COMPACT_NULLABLE_BYTES.
    fn compact_nullable_bytes(&mut self, b: Option<&[u8]>) {
        match b {
            Some(b) => self.compact_bytes(b),
            None => self.uvarint(0),
        }
    }

    /// An ARRAY count, refusing counts over MAX_ARRAY.
    fn array_len(&mut self, n: Option<usize>) {
        match n {
            Some(n) if n <= MAX_ARRAY => self.i32(n as i32),
            Some(_) => self.failed = true,
            None => self.i32(-1),
        }
    }

    /// A COMPACT_ARRAY count, refusing counts over MAX_ARRAY.
    fn compact_array_len(&mut self, n: Option<usize>) {
        match n {
            Some(n) if n <= MAX_ARRAY => self.uvarint(n as u32 + 1),
            Some(_) => self.failed = true,
            None => self.uvarint(0),
        }
    }

    fn tagged_fields(&mut self, fields: &[TaggedField]) {
        if fields.len() > MAX_TAGGED_FIELDS
            || fields.windows(2).any(|pair| pair[0].tag >= pair[1].tag)
            || fields.iter().any(|field| field.tag > MAX_TAG || field.data.len() > MAX_FRAME)
        { self.failed = true; return; }
        self.uvarint(fields.len() as u32);
        for field in fields {
            self.uvarint(field.tag);
            self.uvarint(field.data.len() as u32);
            self.raw(&field.data);
        }
    }

    // The same writes in the classic or the flexible form.

    fn str_f(&mut self, flex: bool, s: &str) {
        if flex { self.compact_string(s) } else { self.string(s) }
    }

    fn nstr_f(&mut self, flex: bool, s: Option<&str>) {
        if flex { self.compact_nullable_string(s) } else { self.nullable_string(s) }
    }

    fn arr_f(&mut self, flex: bool, n: Option<usize>) {
        if flex { self.compact_array_len(n) } else { self.array_len(n) }
    }

    fn tags_f(&mut self, flex: bool, fields: &[TaggedField]) {
        if flex {
            self.tagged_fields(fields);
        } else if !fields.is_empty() {
            self.failed = true;
        }
    }

    fn i32s(&mut self, flex: bool, v: &[i32]) {
        if v.len() > MAX_ARRAY { self.failed = true; return; }
        self.arr_f(flex, Some(v.len()));
        for &x in v {
            self.i32(x);
        }
    }
}

/// Checks a container count before walking or copying its elements.
fn bounded<T>(values: &[T]) -> Result<&[T], Error> {
    if values.len() > MAX_ARRAY { Err(Error::Unwritable) } else { Ok(values) }
}

/// Reads the frame at the start of `b`: a 4-byte size, then the payload.
/// It returns `Ok(None)` if `b` holds only part of one, and otherwise the
/// payload and how many bytes of `b` the frame took. A size that is
/// negative or over `limit` is an error, known from the first 4 bytes.
fn parse_frame(b: &[u8], limit: usize) -> Result<Option<(&[u8], usize)>, Error> {
    let Some(head) = b.get(..SIZE_LEN) else { return Ok(None) };
    let size = i32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if size < 0 || size as usize > limit.min(MAX_FRAME) {
        return Err(Error::FrameSize(size));
    }
    let end = SIZE_LEN + size as usize;
    match b.get(SIZE_LEN..end) {
        Some(payload) => Ok(Some((payload, end))),
        None => Ok(None),
    }
}

/// The correlation ID at the start of a response payload, so a client can
/// find the request it answers before reading the rest.
pub fn correlation_id(payload: &[u8]) -> Option<i32> {
    let b = payload.get(..4)?;
    Some(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// A Kafka frame payload, bounded by [`MAX_FRAME`].
///
/// [`Wire::parse`] reads exactly one size-prefixed frame. Request and response
/// parsing stays separate because responses need the request's key and version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame(
    /// Payload bytes without the four-byte size prefix.
    pub Vec<u8>,
);

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one frame. Refuses negative or excess sizes,
    /// incomplete input, and trailing bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match parse_frame(b, MAX_FRAME)? {
            Some((payload, used)) if used == b.len() => Ok(Self(payload.to_vec())),
            Some((_, used)) => Err(Error::Trailing(b.len().saturating_sub(used))),
            None => Err(Error::Truncated),
        }
    }

    /// Appends a length prefix and payload. Refuses payloads over
    /// [`MAX_FRAME`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.len() > MAX_FRAME { return Err(Error::Unwritable); }
        out.extend_from_slice(&(self.0.len() as i32).to_be_bytes());
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

/// Reads Kafka frames without holding input bytes.
///
/// Use with [`super::codec::Stream`] for input bounded by [`SIZE_LEN`] plus
/// [`Self::limit`]. Partial frames return [`Step::Need`], including at EOF.
/// The stream reports truncation at EOF and framing errors once. Map frames
/// through [`Request::parse`] to receive body errors as items.
///
/// ```
/// use fictionet::stdlib::codec::{Decode, Stream, Wire, finish, pump};
/// use fictionet::stdlib::kafka::{Frames, Request};
///
/// let bytes = [0, 0, 0, 11, 0, 18, 0, 0, 0, 0, 0, 1, 0, 1, b'x'];
/// let mut stream = Stream::new(Frames::new().map(|frame| Request::parse(&frame.0)));
/// let mut requests = Vec::new();
/// pump(&mut stream, &bytes[..2], |request| requests.push(request))?;
/// pump(&mut stream, &bytes[2..], |request| requests.push(request))?;
/// finish(&mut stream, |request| requests.push(request))?;
/// assert_eq!(requests.len(), 1);
/// assert_eq!(requests[0].as_ref().unwrap().header.client_id.as_deref(), Some("x"));
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::kafka::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Accepts frames with up to [`MAX_FRAME`] payload bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_FRAME)
    }

    /// Sets the payload limit, clamped to [`MAX_FRAME`]. Zero accepts empty
    /// payloads. An oversized frame is refused from its four-byte header.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.min(MAX_FRAME) }
    }

    /// The maximum payload length, excluding the size prefix.
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
    type Item = Frame;
    type Error = Error;
    const NAME: &'static str = "Kafka";

    fn capacity(&self) -> usize {
        SIZE_LEN.saturating_add(self.limit)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, Error> {
        Ok(match parse_frame(input, self.limit)? {
            Some((payload, used)) => Step::Item(Frame(payload.to_vec()), used),
            None => Step::Need,
        })
    }
}

/// A request header. Version 0 has the first three fields, version 1 adds
/// the client ID, and version 2 adds tagged fields. The version follows
/// from the API key and version: see [`request_header_version`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestHeader {
    /// Which API the request is for.
    pub api_key: i16,
    /// The version of that API.
    pub api_version: i16,
    /// Chosen by the client and copied into the response.
    pub correlation_id: i32,
    /// The client's name for itself. Version 0 has none. It is never a
    /// compact string, even in version 2.
    pub client_id: Option<String>,
    /// Version 2's tagged fields.
    pub tagged_fields: Vec<TaggedField>,
}

impl RequestHeader {
    /// This header's version.
    pub fn version(&self) -> u8 {
        request_header_version(self.api_key, self.api_version)
    }

    /// Reads a header from `r`, in the version its API key and version
    /// call for.
    pub fn read(r: &mut Reader<'_>) -> Result<RequestHeader, Error> {
        let mut peek = r.clone();
        let api_key = peek.i16()?;
        let api_version = peek.i16()?;
        RequestHeader::read_version(r, request_header_version(api_key, api_version))
    }

    /// Reads a header in header version `version` from `r`.
    pub fn read_version(r: &mut Reader<'_>, version: u8) -> Result<RequestHeader, Error> {
        if version > 2 {
            return Err(Error::HeaderVersion(version));
        }
        let api_key = r.i16()?;
        let api_version = r.i16()?;
        let correlation_id = r.i32()?;
        let client_id = if version >= 1 { r.nullable_string()? } else { None };
        let tagged_fields = if version >= 2 { r.tagged_fields()? } else { Vec::new() };
        Ok(RequestHeader { api_key, api_version, correlation_id, client_id, tagged_fields })
    }

    fn encode(&self, w: &mut Writer) {
        let version = self.version();
        if (version == 0 && self.client_id.is_some()) || (version < 2 && !self.tagged_fields.is_empty()) {
            w.failed = true;
            return;
        }
        w.i16(self.api_key);
        w.i16(self.api_version);
        w.i32(self.correlation_id);
        if version >= 1 {
            w.nullable_string(self.client_id.as_deref());
        }
        if version >= 2 {
            w.tagged_fields(&self.tagged_fields);
        }
    }
}

/// A response header. Version 0 is the correlation ID alone, and version 1
/// adds tagged fields. The version follows from the request's API key and
/// version: see [`response_header_version`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseHeader {
    /// The request's correlation ID.
    pub correlation_id: i32,
    /// Version 1's tagged fields.
    pub tagged_fields: Vec<TaggedField>,
}

impl ResponseHeader {
    /// Reads a header in header version `version` from `r`.
    pub fn read_version(r: &mut Reader<'_>, version: u8) -> Result<ResponseHeader, Error> {
        if version > 1 {
            return Err(Error::HeaderVersion(version));
        }
        let correlation_id = r.i32()?;
        let tagged_fields = if version >= 1 { r.tagged_fields()? } else { Vec::new() };
        Ok(ResponseHeader { correlation_id, tagged_fields })
    }

    fn encode(&self, w: &mut Writer, version: u8) {
        if version > 1 || (version == 0 && !self.tagged_fields.is_empty()) { w.failed = true; return; }
        w.i32(self.correlation_id);
        if version >= 1 {
            w.tagged_fields(&self.tagged_fields);
        }
    }
}

impl Wire for RequestHeader {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one request header. Refuses malformed fields,
    /// excess lengths, input over [`MAX_FRAME`], incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_FRAME { return Err(Error::TooLarge(bytes.len())); }
        let mut reader = Reader::new(bytes);
        let header = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(header)
    }

    /// Appends a header in the version selected by its API key and version.
    /// Refuses excess lengths, invalid tags, and fields absent in that
    /// version without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut writer = Writer::new();
        self.encode(&mut writer);
        out.extend_from_slice(&writer.finish()?);
        Ok(())
    }
}

/// A response header with the version supplied by the request's schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead<const VERSION: u8>(
    /// The correlation ID and tagged fields.
    pub ResponseHeader,
);

impl<const VERSION: u8> Wire for ResponseHead<VERSION> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one response header. Refuses versions above 1,
    /// malformed fields, input over [`MAX_FRAME`], incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_FRAME { return Err(Error::TooLarge(bytes.len())); }
        let mut reader = Reader::new(bytes);
        let header = ResponseHeader::read_version(&mut reader, VERSION)?;
        reader.finish()?;
        Ok(Self(header))
    }

    /// Appends the header. Refuses versions above 1, excess lengths,
    /// invalid tags, or tags in version 0 without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut writer = Writer::new();
        self.0.encode(&mut writer, VERSION);
        out.extend_from_slice(&writer.finish()?);
        Ok(())
    }
}

/// Whether this module has a full body for version `api_version` of
/// `api_key`.
pub fn has_body(api_key: i16, api_version: i16) -> bool {
    match api_key {
        api_key::API_VERSIONS => (0..=API_VERSIONS_MAX_VERSION).contains(&api_version),
        api_key::METADATA => (0..=METADATA_MAX_VERSION).contains(&api_version),
        _ => false,
    }
}

fn check_version(api_key: i16, api_version: i16) -> Result<(), Error> {
    if has_body(api_key, api_version) { Ok(()) } else { Err(Error::UnsupportedVersion { api_key, api_version }) }
}

/// Finishes a body only if its versioned reader preserves the value.
fn finish_body<T: PartialEq>(
    writer: Writer,
    value: &T,
    version: i16,
    parse: impl FnOnce(&[u8], i16) -> Result<T, Error>,
) -> Result<Vec<u8>, Error> {
    let bytes = writer.finish()?;
    if parse(&bytes, version).as_ref() != Ok(value) {
        return Err(Error::Unwritable);
    }
    Ok(bytes)
}

/// An ApiVersions request: a client asking which versions of each API the
/// broker speaks. Versions 0 to 2 have no fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiVersionsRequest {
    /// The client's software name, from version 3.
    pub client_software_name: String,
    /// The client's software version, from version 3.
    pub client_software_version: String,
    /// The cluster the client means to reach, from version 5.
    pub cluster_id: Option<String>,
    /// The broker the client means to reach, from version 5, or -1.
    pub node_id: i32,
    /// The body's tagged fields, from version 3.
    pub tagged_fields: Vec<TaggedField>,
}

impl Default for ApiVersionsRequest {
    fn default() -> ApiVersionsRequest {
        ApiVersionsRequest {
            client_software_name: String::new(),
            client_software_version: String::new(),
            cluster_id: None,
            node_id: -1,
            tagged_fields: Vec::new(),
        }
    }
}

impl ApiVersionsRequest {
    /// Whether a broker takes this request in version `version`, as
    /// Kafka's does. From version 3 the software name and version must
    /// each be letters and digits, with dots and dashes allowed between
    /// them. From version 5 the cluster ID and node ID come together, or
    /// neither does. A broker answers a request that is not valid with
    /// [`error_code::INVALID_REQUEST`]. Parsing and writing do not check
    /// this, so a world can read such a request and answer it.
    pub fn is_valid(&self, version: i16) -> bool {
        fn software(s: &str) -> bool {
            let b = s.as_bytes();
            let inner = |c: &u8| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'.';
            match (b.first(), b.last()) {
                (Some(f), Some(l)) => f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() && b.iter().all(inner),
                _ => false,
            }
        }
        if version >= 5 && self.cluster_id.is_some() != (self.node_id != -1) {
            return false;
        }
        version < 3 || (software(&self.client_software_name) && software(&self.client_software_version))
    }

    /// Reads the body of an ApiVersions request of version `version`.
    /// Fields the version does not have get their defaults.
    pub fn parse(body: &[u8], version: i16) -> Result<ApiVersionsRequest, Error> {
        check_version(api_key::API_VERSIONS, version)?;
        let mut out = ApiVersionsRequest::default();
        let mut r = Reader::new(body);
        if version >= 3 {
            out.client_software_name = r.compact_string()?;
            out.client_software_version = r.compact_string()?;
            if version >= 5 {
                out.cluster_id = r.compact_nullable_string()?;
                out.node_id = r.i32()?;
            }
            out.tagged_fields = r.tagged_fields()?;
        }
        r.finish()?;
        Ok(out)
    }

    fn encode(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::API_VERSIONS, version).map_err(|_| Error::Unwritable)?;
        let mut w = Writer::new();
        if version >= 3 {
            w.compact_string(&self.client_software_name);
            w.compact_string(&self.client_software_version);
            if version >= 5 {
                w.compact_nullable_string(self.cluster_id.as_deref());
                w.i32(self.node_id);
            }
            w.tagged_fields(&self.tagged_fields);
        }
        finish_body(w, self, version, Self::parse)
    }
}

/// One API a broker speaks, in an ApiVersions response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiVersion {
    /// The API key.
    pub api_key: i16,
    /// The lowest version the broker speaks.
    pub min_version: i16,
    /// The highest version the broker speaks.
    pub max_version: i16,
    /// The entry's tagged fields, from version 3.
    pub tagged_fields: Vec<TaggedField>,
}

/// An ApiVersions response. A broker that does not speak the version a
/// client asked for answers in version 0 with
/// [`error_code::UNSUPPORTED_VERSION`], so any client can read it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiVersionsResponse {
    /// 0, or why the request failed.
    pub error_code: i16,
    /// The APIs the broker speaks.
    pub api_keys: Vec<ApiVersion>,
    /// How long the request was held back by a quota, in milliseconds,
    /// from version 1.
    pub throttle_time_ms: i32,
    /// The body's tagged fields, from version 3: supported features (tag
    /// 0), the finalized features' epoch (1), the finalized features (2)
    /// and whether ZooKeeper migration is ready (3), as bytes. Their
    /// bytes are checked against those types, but not read into fields.
    pub tagged_fields: Vec<TaggedField>,
}

impl ApiVersionsResponse {
    /// Reads the body of an ApiVersions response of version `version`.
    /// A broker that does not speak that version answers in version 0
    /// with [`error_code::UNSUPPORTED_VERSION`], so bytes that do not
    /// read in `version` are read again in version 0, and taken if they
    /// carry that error. The body's tagged fields 0 to 3 must hold what
    /// Kafka defines for them.
    pub fn parse(body: &[u8], version: i16) -> Result<ApiVersionsResponse, Error> {
        match ApiVersionsResponse::parse_exact(body, version) {
            Err(e) if version > 0 => match ApiVersionsResponse::parse_exact(body, 0) {
                Ok(r) if r.error_code == error_code::UNSUPPORTED_VERSION => Ok(r),
                _ => Err(e),
            },
            other => other,
        }
    }

    fn parse_exact(body: &[u8], version: i16) -> Result<ApiVersionsResponse, Error> {
        check_version(api_key::API_VERSIONS, version)?;
        let flex = version >= 3;
        let mut r = Reader::new(body);
        let error_code = r.i16()?;
        let n = r.arr_f(flex)?.ok_or(Error::Null)?;
        let mut api_keys = Vec::new();
        for _ in 0..n {
            api_keys.push(ApiVersion {
                api_key: r.i16()?,
                min_version: r.i16()?,
                max_version: r.i16()?,
                tagged_fields: r.tags_f(flex)?,
            });
        }
        let throttle_time_ms = if version >= 1 { r.i32()? } else { 0 };
        let tagged_fields = r.tags_f(flex)?;
        r.finish()?;
        check_feature_tags(&tagged_fields)?;
        Ok(ApiVersionsResponse { error_code, api_keys, throttle_time_ms, tagged_fields })
    }

    fn encode(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::API_VERSIONS, version).map_err(|_| Error::Unwritable)?;
        if version >= 3 {
            check_feature_tags(&self.tagged_fields).map_err(|_| Error::Unwritable)?;
        }
        let flex = version >= 3;
        let mut w = Writer::new();
        w.i16(self.error_code);
        let keys = bounded(&self.api_keys)?;
        w.arr_f(flex, Some(keys.len()));
        for k in keys {
            w.i16(k.api_key);
            w.i16(k.min_version);
            w.i16(k.max_version);
            w.tags_f(flex, &k.tagged_fields);
        }
        if version >= 1 {
            w.i32(self.throttle_time_ms);
        }
        w.tags_f(flex, &self.tagged_fields);
        finish_body(w, self, version, Self::parse)
    }
}

/// Checks the ApiVersions response's own tagged fields: the supported
/// features (tag 0) and the finalized features (2) are each a compact
/// array of a name, two INT16s and tagged fields, the finalized features'
/// epoch (1) is an INT64, and whether ZooKeeper migration is ready (3) is
/// a BOOLEAN. Other tags are unknown, and anything goes.
fn check_feature_tags(fields: &[TaggedField]) -> Result<(), Error> {
    fn features(r: &mut Reader<'_>) -> Result<(), Error> {
        let n = r.compact_array_len()?.ok_or(Error::Null)?;
        for _ in 0..n {
            r.compact_string()?;
            r.i16()?;
            r.i16()?;
            r.tagged_fields()?;
        }
        Ok(())
    }
    for f in fields {
        let mut r = Reader::new(&f.data);
        let read = match f.tag {
            0 | 2 => features(&mut r),
            1 => r.i64().map(drop),
            3 => r.bool().map(drop),
            _ => continue,
        };
        if read.and_then(|()| r.finish()).is_err() {
            return Err(Error::Invalid(match f.tag {
                0 => "supported features (tag 0)",
                1 => "finalized features epoch (tag 1)",
                2 => "finalized features (tag 2)",
                _ => "ZooKeeper migration ready (tag 3)",
            }));
        }
    }
    Ok(())
}

/// One topic a Metadata request asks about.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataRequestTopic {
    /// The topic's ID, when asking by ID. All zeros when asking by name,
    /// and always before version 12. Versions 10 and 11 carry the field,
    /// but Kafka does not take IDs in them.
    pub topic_id: [u8; 16],
    /// The topic's name, or null when asking by ID. Never null before
    /// version 12, as for the ID.
    pub name: Option<String>,
    /// The entry's tagged fields, from version 9.
    pub tagged_fields: Vec<TaggedField>,
}

/// A Metadata request: a client asking which brokers there are, which
/// topics, and which broker leads each partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataRequest {
    /// The topics to describe, or `None` for every topic. Version 0 has no
    /// null: there an empty list means every topic, and `None` is written
    /// as one.
    pub topics: Option<Vec<MetadataRequestTopic>>,
    /// Whether the broker may create topics that do not exist, from
    /// version 4. True by default.
    pub allow_auto_topic_creation: bool,
    /// Whether to say what the client may do to the cluster, in versions 8
    /// to 10.
    pub include_cluster_authorized_operations: bool,
    /// Whether to say what the client may do to each topic, from version 8.
    pub include_topic_authorized_operations: bool,
    /// The body's tagged fields, from version 9.
    pub tagged_fields: Vec<TaggedField>,
}

impl Default for MetadataRequest {
    fn default() -> MetadataRequest {
        MetadataRequest {
            topics: None,
            allow_auto_topic_creation: true,
            include_cluster_authorized_operations: false,
            include_topic_authorized_operations: false,
            tagged_fields: Vec::new(),
        }
    }
}

impl MetadataRequest {
    /// Reads the body of a Metadata request of version `version`. Fields
    /// the version does not have get their defaults.
    pub fn parse(body: &[u8], version: i16) -> Result<MetadataRequest, Error> {
        check_version(api_key::METADATA, version)?;
        let flex = version >= 9;
        let mut r = Reader::new(body);
        let topics = match r.arr_f(flex)? {
            None if version == 0 => return Err(Error::Null),
            None => None,
            Some(n) => {
                let mut topics = Vec::new();
                for _ in 0..n {
                    let topic_id = if version >= 10 { r.uuid()? } else { [0; 16] };
                    let name = if version >= 10 { r.nstr_f(flex)? } else { Some(r.str_f(flex)?) };
                    let tagged_fields = r.tags_f(flex)?;
                    topics.push(MetadataRequestTopic { topic_id, name, tagged_fields });
                }
                Some(topics)
            }
        };
        if let Some(topics) = &topics {
            check_request_topics(topics, version)?;
        }
        let mut out = MetadataRequest { topics, ..MetadataRequest::default() };
        if version >= 4 {
            out.allow_auto_topic_creation = r.bool()?;
        }
        if (8..=10).contains(&version) {
            out.include_cluster_authorized_operations = r.bool()?;
        }
        if version >= 8 {
            out.include_topic_authorized_operations = r.bool()?;
        }
        out.tagged_fields = r.tags_f(flex)?;
        r.finish()?;
        Ok(out)
    }

    fn encode(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::METADATA, version).map_err(|_| Error::Unwritable)?;
        if version < 4 && !self.allow_auto_topic_creation {
            return Err(Error::Unwritable);
        }
        if !(8..=10).contains(&version) && self.include_cluster_authorized_operations {
            return Err(Error::Unwritable);
        }
        if version < 8 && self.include_topic_authorized_operations {
            return Err(Error::Unwritable);
        }
        if let Some(topics) = &self.topics {
            check_request_topics(bounded(topics)?, version).map_err(|_| Error::Unwritable)?;
        }
        let flex = version >= 9;
        let mut w = Writer::new();
        match &self.topics {
            None if version == 0 => return Err(Error::Unwritable),
            None => w.arr_f(flex, None),
            Some(topics) => {
                let topics = bounded(topics)?;
                w.arr_f(flex, Some(topics.len()));
                for t in topics {
                    if version >= 10 {
                        w.uuid(&t.topic_id);
                        w.nstr_f(flex, t.name.as_deref());
                    } else {
                        w.str_f(flex, t.name.as_deref().unwrap_or_default());
                    }
                    w.tags_f(flex, &t.tagged_fields);
                }
            }
        }
        if version >= 4 {
            w.bool(self.allow_auto_topic_creation);
        }
        if (8..=10).contains(&version) {
            w.bool(self.include_cluster_authorized_operations);
        }
        if version >= 8 {
            w.bool(self.include_topic_authorized_operations);
        }
        w.tags_f(flex, &self.tagged_fields);
        finish_body(w, self, version, Self::parse)
    }
}

/// Before version 12 a Metadata request's topics are asked for by name:
/// Kafka's client refuses to write a null name or an ID there, and its
/// broker refuses to read them.
fn check_request_topics(topics: &[MetadataRequestTopic], version: i16) -> Result<(), Error> {
    if version >= 12 {
        return Ok(());
    }
    for t in topics {
        if t.name.is_none() {
            return Err(Error::Invalid("a null topic name needs version 12"));
        }
        if t.topic_id != [0; 16] {
            return Err(Error::Invalid("a topic ID needs version 12"));
        }
    }
    Ok(())
}

/// A Metadata response's topics each have a name or an ID, and a name
/// whenever there is no error. Names are never null before version 12.
fn check_response_topics(topics: &[MetadataTopic], version: i16) -> Result<(), Error> {
    for t in topics {
        if t.name.is_none() {
            if version < 12 {
                return Err(Error::Invalid("a null topic name needs version 12"));
            }
            if t.error_code == error_code::NONE {
                return Err(Error::Invalid("a topic with no error has a name"));
            }
            if t.topic_id == [0; 16] {
                return Err(Error::Invalid("a topic has a name or an ID"));
            }
        }
    }
    Ok(())
}

/// One broker in a Metadata response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataBroker {
    /// The broker's ID.
    pub node_id: i32,
    /// The host name clients connect to.
    pub host: String,
    /// The port clients connect to.
    pub port: i32,
    /// The broker's rack, from version 1, or `None`.
    pub rack: Option<String>,
    /// The entry's tagged fields, from version 9.
    pub tagged_fields: Vec<TaggedField>,
}

/// One partition of a topic in a Metadata response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataPartition {
    /// 0, or what is wrong with the partition.
    pub error_code: i16,
    /// The partition's number.
    pub partition_index: i32,
    /// The broker that leads the partition.
    pub leader_id: i32,
    /// The leader's epoch, from version 7, or -1.
    pub leader_epoch: i32,
    /// Every broker holding a copy.
    pub replica_nodes: Vec<i32>,
    /// The brokers whose copies are in sync with the leader.
    pub isr_nodes: Vec<i32>,
    /// The brokers whose copies are offline, from version 5.
    pub offline_replicas: Vec<i32>,
    /// The entry's tagged fields, from version 9.
    pub tagged_fields: Vec<TaggedField>,
}

impl Default for MetadataPartition {
    fn default() -> MetadataPartition {
        MetadataPartition {
            error_code: 0,
            partition_index: 0,
            leader_id: 0,
            leader_epoch: -1,
            replica_nodes: Vec::new(),
            isr_nodes: Vec::new(),
            offline_replicas: Vec::new(),
            tagged_fields: Vec::new(),
        }
    }
}

/// One topic in a Metadata response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataTopic {
    /// 0, or what is wrong with the topic.
    pub error_code: i16,
    /// The topic's name. It may be null from version 12, for a topic asked
    /// for by an ID that does not exist: then the error code is not 0 and
    /// the ID is not all zeros. It is never null before version 12.
    pub name: Option<String>,
    /// The topic's ID, from version 10.
    pub topic_id: [u8; 16],
    /// Whether Kafka uses the topic for itself, from version 1.
    pub is_internal: bool,
    /// The topic's partitions.
    pub partitions: Vec<MetadataPartition>,
    /// What the client may do to the topic, as a bit field, from version
    /// 8. `i32::MIN` when not asked for.
    pub topic_authorized_operations: i32,
    /// The entry's tagged fields, from version 9.
    pub tagged_fields: Vec<TaggedField>,
}

impl Default for MetadataTopic {
    fn default() -> MetadataTopic {
        MetadataTopic {
            error_code: 0,
            name: Some(String::new()),
            topic_id: [0; 16],
            is_internal: false,
            partitions: Vec::new(),
            topic_authorized_operations: i32::MIN,
            tagged_fields: Vec::new(),
        }
    }
}

/// A Metadata response: the brokers, the controller and the topics asked
/// about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataResponse {
    /// How long the request was held back by a quota, in milliseconds,
    /// from version 3.
    pub throttle_time_ms: i32,
    /// The brokers in the cluster.
    pub brokers: Vec<MetadataBroker>,
    /// The cluster's ID, from version 2, or `None`.
    pub cluster_id: Option<String>,
    /// The controller's broker ID, from version 1, or -1.
    pub controller_id: i32,
    /// The topics.
    pub topics: Vec<MetadataTopic>,
    /// What the client may do to the cluster, as a bit field, in versions
    /// 8 to 10. `i32::MIN` when not asked for.
    pub cluster_authorized_operations: i32,
    /// 0, or why the whole request failed, from version 13.
    pub error_code: i16,
    /// The body's tagged fields, from version 9.
    pub tagged_fields: Vec<TaggedField>,
}

impl Default for MetadataResponse {
    fn default() -> MetadataResponse {
        MetadataResponse {
            throttle_time_ms: 0,
            brokers: Vec::new(),
            cluster_id: None,
            controller_id: -1,
            topics: Vec::new(),
            cluster_authorized_operations: i32::MIN,
            error_code: 0,
            tagged_fields: Vec::new(),
        }
    }
}

impl MetadataResponse {
    /// Reads the body of a Metadata response of version `version`. Fields
    /// the version does not have get their defaults.
    pub fn parse(body: &[u8], version: i16) -> Result<MetadataResponse, Error> {
        check_version(api_key::METADATA, version)?;
        let flex = version >= 9;
        let mut r = Reader::new(body);
        let mut out = MetadataResponse::default();
        if version >= 3 {
            out.throttle_time_ms = r.i32()?;
        }
        let n = r.arr_f(flex)?.ok_or(Error::Null)?;
        for _ in 0..n {
            let node_id = r.i32()?;
            let host = r.str_f(flex)?;
            let port = r.i32()?;
            let rack = if version >= 1 { r.nstr_f(flex)? } else { None };
            let tagged_fields = r.tags_f(flex)?;
            out.brokers.push(MetadataBroker { node_id, host, port, rack, tagged_fields });
        }
        if version >= 2 {
            out.cluster_id = r.nstr_f(flex)?;
        }
        if version >= 1 {
            out.controller_id = r.i32()?;
        }
        let n = r.arr_f(flex)?.ok_or(Error::Null)?;
        for _ in 0..n {
            let mut t = MetadataTopic { error_code: r.i16()?, ..MetadataTopic::default() };
            t.name = if version >= 12 { r.nstr_f(flex)? } else { Some(r.str_f(flex)?) };
            if version >= 10 {
                t.topic_id = r.uuid()?;
            }
            if version >= 1 {
                t.is_internal = r.bool()?;
            }
            let n = r.arr_f(flex)?.ok_or(Error::Null)?;
            for _ in 0..n {
                let mut p = MetadataPartition {
                    error_code: r.i16()?,
                    partition_index: r.i32()?,
                    leader_id: r.i32()?,
                    ..MetadataPartition::default()
                };
                if version >= 7 {
                    p.leader_epoch = r.i32()?;
                }
                p.replica_nodes = r.i32s(flex)?;
                p.isr_nodes = r.i32s(flex)?;
                if version >= 5 {
                    p.offline_replicas = r.i32s(flex)?;
                }
                p.tagged_fields = r.tags_f(flex)?;
                t.partitions.push(p);
            }
            if version >= 8 {
                t.topic_authorized_operations = r.i32()?;
            }
            t.tagged_fields = r.tags_f(flex)?;
            out.topics.push(t);
        }
        if (8..=10).contains(&version) {
            out.cluster_authorized_operations = r.i32()?;
        }
        if version >= 13 {
            out.error_code = r.i16()?;
        }
        out.tagged_fields = r.tags_f(flex)?;
        r.finish()?;
        check_response_topics(&out.topics, version)?;
        Ok(out)
    }

    fn encode(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::METADATA, version).map_err(|_| Error::Unwritable)?;
        check_response_topics(bounded(&self.topics)?, version).map_err(|_| Error::Unwritable)?;
        let flex = version >= 9;
        let mut w = Writer::new();
        if version >= 3 {
            w.i32(self.throttle_time_ms);
        }
        let brokers = bounded(&self.brokers)?;
        w.arr_f(flex, Some(brokers.len()));
        for b in brokers {
            w.i32(b.node_id);
            w.str_f(flex, &b.host);
            w.i32(b.port);
            if version >= 1 {
                w.nstr_f(flex, b.rack.as_deref());
            }
            w.tags_f(flex, &b.tagged_fields);
        }
        if version >= 2 {
            w.nstr_f(flex, self.cluster_id.as_deref());
        }
        if version >= 1 {
            w.i32(self.controller_id);
        }
        let topics = bounded(&self.topics)?;
        w.arr_f(flex, Some(topics.len()));
        for t in topics {
            w.i16(t.error_code);
            if version >= 12 {
                w.nstr_f(flex, t.name.as_deref());
            } else {
                w.str_f(flex, t.name.as_deref().unwrap_or_default());
            }
            if version >= 10 {
                w.uuid(&t.topic_id);
            }
            if version >= 1 {
                w.bool(t.is_internal);
            }
            let partitions = bounded(&t.partitions)?;
            w.arr_f(flex, Some(partitions.len()));
            for p in partitions {
                w.i16(p.error_code);
                w.i32(p.partition_index);
                w.i32(p.leader_id);
                if version >= 7 {
                    w.i32(p.leader_epoch);
                }
                w.i32s(flex, &p.replica_nodes);
                w.i32s(flex, &p.isr_nodes);
                if version >= 5 {
                    w.i32s(flex, &p.offline_replicas);
                }
                w.tags_f(flex, &p.tagged_fields);
            }
            if version >= 8 {
                w.i32(t.topic_authorized_operations);
            }
            w.tags_f(flex, &t.tagged_fields);
        }
        if (8..=10).contains(&version) {
            w.i32(self.cluster_authorized_operations);
        }
        if version >= 13 {
            w.i16(self.error_code);
        }
        w.tags_f(flex, &self.tagged_fields);
        finish_body(w, self, version, Self::parse)
    }
}

/// A request's body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestBody {
    /// An ApiVersions request, versions 0 to 5.
    ApiVersions(ApiVersionsRequest),
    /// A Metadata request, versions 0 to 13.
    Metadata(MetadataRequest),
    /// Any other API or version, with its body unread.
    Other(Vec<u8>),
}

/// A whole request: the payload of one frame a client sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The header.
    pub header: RequestHeader,
    /// The body.
    pub body: RequestBody,
}

impl Wire for Request {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a frame's payload as a request. Refuses malformed fields,
    /// incomplete input, and trailing bytes after known bodies. The header says which body
    /// follows. A body this module reads in full must use every byte, and
    /// a payload longer than [`MAX_FRAME`] is [`Error::TooLarge`].
    fn parse(payload: &[u8]) -> Result<Request, Error> {
        if payload.len() > MAX_FRAME {
            return Err(Error::TooLarge(payload.len()));
        }
        let mut r = Reader::new(payload);
        let header = RequestHeader::read(&mut r)?;
        let rest = r.rest();
        let (key, version) = (header.api_key, header.api_version);
        let body = if !has_body(key, version) {
            RequestBody::Other(rest.to_vec())
        } else if key == api_key::API_VERSIONS {
            RequestBody::ApiVersions(ApiVersionsRequest::parse(rest, version)?)
        } else {
            RequestBody::Metadata(MetadataRequest::parse(rest, version)?)
        };
        Ok(Request { header, body })
    }

    /// Appends the request payload. Refuses mismatched bodies, invalid
    /// fields or tags, excess lengths, and values a version would change
    /// or omit. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let (key, version) = (self.header.api_key, self.header.api_version);
        let body = match &self.body {
            RequestBody::ApiVersions(b) if key == api_key::API_VERSIONS => b.encode(version)?,
            RequestBody::Metadata(b) if key == api_key::METADATA => b.encode(version)?,
            RequestBody::Other(b) if !has_body(key, version) && b.len() <= MAX_FRAME => b.clone(),
            _ => return Err(Error::Unwritable),
        };
        let mut w = Writer::new();
        self.header.encode(&mut w);
        w.raw(&body);
        out.extend_from_slice(&w.finish()?);
        Ok(())
    }
}

impl Request {
    /// Wraps this request's payload in a frame. Refuses values that the
    /// header's version cannot preserve or that exceed their limits.
    pub fn to_frame(&self) -> Result<Frame, Error> {
        Ok(Frame(self.to_bytes()?))
    }
}

/// A response's body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseBody {
    /// An ApiVersions response, versions 0 to 5.
    ApiVersions(ApiVersionsResponse),
    /// A Metadata response, versions 0 to 13.
    Metadata(MetadataResponse),
    /// Any other API or version, with its body unread.
    Other(Vec<u8>),
}

/// A whole response: the payload of one frame a broker sends. It does not
/// say which request it answers, so reading and writing it takes the
/// request's API key and version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The header.
    pub header: ResponseHeader,
    /// The body.
    pub body: ResponseBody,
}

impl Response {
    /// Reads a frame's payload as the response to version `api_version`
    /// of `api_key`. A body this module reads in full must use every byte,
    /// and a payload longer than [`MAX_FRAME`] is [`Error::TooLarge`]. An
    /// ApiVersions response may be in version 0 whatever was asked for:
    /// see [`ApiVersionsResponse::parse`].
    pub fn parse(payload: &[u8], api_key: i16, api_version: i16) -> Result<Response, Error> {
        if payload.len() > MAX_FRAME {
            return Err(Error::TooLarge(payload.len()));
        }
        let mut r = Reader::new(payload);
        let header = ResponseHeader::read_version(&mut r, response_header_version(api_key, api_version))?;
        let rest = r.rest();
        let body = if !has_body(api_key, api_version) {
            ResponseBody::Other(rest.to_vec())
        } else if api_key == api_key::API_VERSIONS {
            ResponseBody::ApiVersions(ApiVersionsResponse::parse(rest, api_version)?)
        } else {
            ResponseBody::Metadata(MetadataResponse::parse(rest, api_version)?)
        };
        Ok(Response { header, body })
    }

    /// Wraps the response payload in a frame for the request's API key
    /// and version. Refuses mismatched bodies, invalid fields or tags,
    /// excess lengths, and values that version would change or omit.
    /// ApiVersions errors for unsupported versions should use version 0.
    pub fn to_frame(&self, api_key: i16, api_version: i16) -> Result<Frame, Error> {
        let body = match &self.body {
            ResponseBody::ApiVersions(b) if api_key == api_key::API_VERSIONS => b.encode(api_version)?,
            ResponseBody::Metadata(b) if api_key == api_key::METADATA => b.encode(api_version)?,
            ResponseBody::Other(b) if !has_body(api_key, api_version) && b.len() <= MAX_FRAME => b.clone(),
            _ => return Err(Error::Unwritable),
        };
        let mut writer = Writer::new();
        self.header.encode(&mut writer, response_header_version(api_key, api_version));
        writer.raw(&body);
        Ok(Frame(writer.finish()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Stream, Fail, contract, pump, finish, test_support::{Lcg, mutate, decode_all}};

    enum BodyCase {
        Request(Request),
        Response(Response, i16),
    }

    trait BodyFixture {
        fn case(&self, version: i16) -> BodyCase;
    }

    macro_rules! body_fixture {
        (request, $ty:ident, $key:expr, $variant:ident) => {
            impl BodyFixture for $ty {
                fn case(&self, version: i16) -> BodyCase {
                    BodyCase::Request(Request {
                        header: RequestHeader { api_key: $key, api_version: version, ..Default::default() },
                        body: RequestBody::$variant(self.clone()),
                    })
                }
            }
        };
        (response, $ty:ident, $key:expr, $variant:ident) => {
            impl BodyFixture for $ty {
                fn case(&self, _version: i16) -> BodyCase {
                    BodyCase::Response(Response {
                        header: ResponseHeader::default(), body: ResponseBody::$variant(self.clone()),
                    }, $key)
                }
            }
        };
    }
    body_fixture!(request, ApiVersionsRequest, api_key::API_VERSIONS, ApiVersions);
    body_fixture!(request, MetadataRequest, api_key::METADATA, Metadata);
    body_fixture!(response, ApiVersionsResponse, api_key::API_VERSIONS, ApiVersions);
    body_fixture!(response, MetadataResponse, api_key::METADATA, Metadata);

    fn body_bytes(value: &impl BodyFixture, version: i16) -> Result<Vec<u8>, Error> {
        let (bytes, response_version) = match value.case(version) {
            BodyCase::Request(request) => (request.to_bytes()?, None),
            BodyCase::Response(response, key) => (response.to_frame(key, version)?.0, Some(response_header_version(key, version))),
        };
        let mut reader = Reader::new(&bytes);
        if let Some(version) = response_version { ResponseHeader::read_version(&mut reader, version)?; }
        else { RequestHeader::read(&mut reader)?; }
        Ok(reader.rest().to_vec())
    }

    fn tag(tag: u32, data: &[u8]) -> TaggedField {
        TaggedField { tag, data: data.to_vec() }
    }

    // Varint examples from the protocol guide, which follows Protocol
    // Buffers' encoding.

    #[test]
    fn varint_examples() {
        assert_eq!(UnsignedVarint(0).to_bytes().unwrap(), [0]);
        assert_eq!(UnsignedVarint(1).to_bytes().unwrap(), [1]);
        assert_eq!(UnsignedVarint(127).to_bytes().unwrap(), [0x7f]);
        assert_eq!(UnsignedVarint(128).to_bytes().unwrap(), [0x80, 0x01]);
        assert_eq!(UnsignedVarint(300).to_bytes().unwrap(), [0xac, 0x02]);
        assert_eq!(UnsignedVarint(u32::MAX).to_bytes().unwrap(), [0xff, 0xff, 0xff, 0xff, 0x0f]);
        // Zigzag: 0, -1, 1, -2 are 0, 1, 2, 3.
        for (v, z) in [(0, 0u8), (-1, 1), (1, 2), (-2, 3), (2147483647, 0xfe), (-2147483648, 0xff)] {
            let mut w = Vec::new();
            Varint(v).write(&mut w).unwrap();
            let b = w;
            assert_eq!(b[0], z, "{v}");
            assert_eq!(Reader::new(&b).varint(), Ok(v));
        }
        for v in [0i64, -1, 1, i64::MAX, i64::MIN, 1 << 40, -(1 << 50)] {
            let mut w = Vec::new();
            Varlong(v).write(&mut w).unwrap();
            let b = w;
            assert!(b.len() <= 10);
            let mut r = Reader::new(&b);
            assert_eq!(r.varlong(), Ok(v));
            assert_eq!(r.finish(), Ok(()));
        }
        for v in [0u32, 1, 127, 128, 16383, 16384, 1 << 21, 1 << 28, u32::MAX] {
            let b = UnsignedVarint(v).to_bytes().unwrap();
            assert_eq!(Reader::new(&b).uvarint(), Ok(v));
        }
        // A longer encoding of the same value reads too.
        assert_eq!(Reader::new(&[0x81, 0x00]).uvarint(), Ok(1));
    }

    #[test]
    fn varint_errors() {
        // A sixth byte, and a fifth that overflows a u32.
        assert_eq!(Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]).uvarint(), Err(Error::Varint));
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff, 0x10]).uvarint(), Err(Error::Varint));
        assert_eq!(Reader::new(&[0x80, 0x80]).uvarint(), Err(Error::Truncated));
        let mut long = vec![0x80; 9];
        long.push(0x02);
        assert_eq!(Reader::new(&long).varlong(), Err(Error::Varint));
        assert_eq!(Reader::new(&[0x80; 11]).varlong(), Err(Error::Varint));
        assert_eq!(Reader::new(&[0x80]).varlong(), Err(Error::Truncated));
    }

    #[test]
    fn primitives_round_trip() {
        let id = [7u8; 16];
        let mut w = Vec::new();
        Boolean(true).write(&mut w).unwrap();
        Int8(-3).write(&mut w).unwrap();
        Int16(-300).write(&mut w).unwrap();
        Uint16(65000).write(&mut w).unwrap();
        Int32(-70000).write(&mut w).unwrap();
        Uint32(4_000_000_000).write(&mut w).unwrap();
        Int64(-1 << 40).write(&mut w).unwrap();
        Float64(1.5).write(&mut w).unwrap();
        Uuid(id).write(&mut w).unwrap();
        String16("héllo".to_owned()).write(&mut w).unwrap();
        NullableString(None.map(str::to_owned)).write(&mut w).unwrap();
        CompactString("kafka".to_owned()).write(&mut w).unwrap();
        CompactNullableString(None.map(str::to_owned)).write(&mut w).unwrap();
        BytesValue(b"abc".to_vec()).write(&mut w).unwrap();
        NullableBytes(None.map(<[u8]>::to_vec)).write(&mut w).unwrap();
        CompactBytes(b"".to_vec()).write(&mut w).unwrap();
        CompactNullableBytes(None.map(<[u8]>::to_vec)).write(&mut w).unwrap();
        ArrayLength(Some(0)).write(&mut w).unwrap();
        ArrayLength(None).write(&mut w).unwrap();
        CompactArrayLength(Some(0)).write(&mut w).unwrap();
        CompactArrayLength(None).write(&mut w).unwrap();
        TaggedFields(vec![tag(1, b"yz"), tag(5, b"x")]).write(&mut w).unwrap();
        assert!(!w.is_empty());
        let b = w;
        let mut r = Reader::new(&b);
        assert_eq!(r.bool(), Ok(true));
        assert_eq!(r.i8(), Ok(-3));
        assert_eq!(r.i16(), Ok(-300));
        assert_eq!(r.u16(), Ok(65000));
        assert_eq!(r.i32(), Ok(-70000));
        assert_eq!(r.u32(), Ok(4_000_000_000));
        assert_eq!(r.i64(), Ok(-1 << 40));
        assert_eq!(r.f64(), Ok(1.5));
        assert_eq!(r.uuid(), Ok(id));
        assert_eq!(r.string().as_deref(), Ok("héllo"));
        assert_eq!(r.nullable_string(), Ok(None));
        assert_eq!(r.compact_string().as_deref(), Ok("kafka"));
        assert_eq!(r.compact_nullable_string(), Ok(None));
        assert_eq!(r.bytes(), Ok(&b"abc"[..]));
        assert_eq!(r.nullable_bytes(), Ok(None));
        assert_eq!(r.compact_bytes(), Ok(&b""[..]));
        assert_eq!(r.compact_nullable_bytes(), Ok(None));
        assert_eq!(r.array_len(), Ok(Some(0)));
        assert_eq!(r.array_len(), Ok(None));
        assert_eq!(r.compact_array_len(), Ok(Some(0)));
        assert_eq!(r.compact_array_len(), Ok(None));
        // Tagged fields retain their order and contents.
        assert_eq!(r.tagged_fields(), Ok(vec![tag(1, b"yz"), tag(5, b"x")]));
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.position(), b.len());
    }

    #[test]
    fn primitive_layouts() {
        let mut w = Vec::new();
        String16("ab".to_owned()).write(&mut w).unwrap();
        CompactString("ab".to_owned()).write(&mut w).unwrap();
        CompactNullableString(None.map(str::to_owned)).write(&mut w).unwrap();
        NullableString(None.map(str::to_owned)).write(&mut w).unwrap();
        CompactArrayLength(Some(2)).write(&mut w).unwrap();
        TaggedFields(vec![tag(0, &[9])]).write(&mut w).unwrap();
        assert_eq!(w, [0, 2, b'a', b'b', 3, b'a', b'b', 0, 0xff, 0xff, 3, 1, 0, 1, 9]);
    }

    #[test]
    fn primitive_errors() {
        assert_eq!(Reader::new(&[0xff, 0xff]).string(), Err(Error::Null));
        assert_eq!(Reader::new(&[0xff, 0xfe]).nullable_string(), Err(Error::Length(-2)));
        assert_eq!(Reader::new(&[0, 3, b'a']).string(), Err(Error::Truncated));
        assert_eq!(Reader::new(&[0, 1, 0xff]).string(), Err(Error::Utf8));
        assert_eq!(Reader::new(&[0]).compact_string(), Err(Error::Null));
        assert_eq!(Reader::new(&[2, 0xc3]).compact_string(), Err(Error::Utf8));
        // A compact string over the limit.
        let mut w = Vec::new();
        UnsignedVarint(MAX_STRING as u32 + 2).write(&mut w).unwrap();
        assert_eq!(Reader::new(&w).compact_string(), Err(Error::Length(MAX_STRING as i64 + 1)));
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff]).bytes(), Err(Error::Null));
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xfe]).nullable_bytes(), Err(Error::Length(-2)));
        assert_eq!(Reader::new(&[0, 0, 0, 5, 1]).bytes(), Err(Error::Truncated));
        assert_eq!(Reader::new(&[0]).compact_bytes(), Err(Error::Null));
        assert_eq!(Reader::new(&[3, 1]).compact_bytes(), Err(Error::Truncated));
        // Array counts below -1, over the bytes left, or over the limit.
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xfe]).array_len(), Err(Error::Length(-2)));
        assert_eq!(Reader::new(&[0, 0, 0, 2, 1]).array_len(), Err(Error::Length(2)));
        assert_eq!(Reader::new(&[0, 0, 0, 1, 1]).array_len(), Ok(Some(1)));
        assert_eq!(Reader::new(&[3, 1]).compact_array_len(), Err(Error::Length(2)));
        let mut big = vec![0x00, 0x10, 0x00, 0x01];
        big.resize(MAX_ARRAY + 10, 0);
        assert_eq!(Reader::new(&big).array_len(), Err(Error::Length(MAX_ARRAY as i64 + 1)));
        // Tagged fields out of order, repeated, too many, or cut short.
        assert_eq!(Reader::new(&[2, 3, 0, 1, 0]).tagged_fields(), Err(Error::TagOrder(1)));
        assert_eq!(Reader::new(&[2, 3, 0, 3, 0]).tagged_fields(), Err(Error::TagOrder(3)));
        assert_eq!(Reader::new(&[3, 3, 0]).tagged_fields(), Err(Error::Length(3)));
        assert_eq!(Reader::new(&[1, 3, 4, 1]).tagged_fields(), Err(Error::Truncated));
        let mut many = UnsignedVarint(MAX_TAGGED_FIELDS as u32 + 1).to_bytes().unwrap();
        many.resize(5000, 0);
        assert_eq!(Reader::new(&many).tagged_fields(), Err(Error::Length(MAX_TAGGED_FIELDS as i64 + 1)));
        // Trailing bytes.
        let r = Reader::new(&[1, 2]);
        assert_eq!(r.finish(), Err(Error::Trailing(2)));
        assert_eq!(Reader::new(&[]).i64(), Err(Error::Truncated));
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        fn refuses(value: &(impl Wire + PartialEq + core::fmt::Debug)) {
            contract::check_wire_value(value);
            let mut bytes = vec![7];
            assert!(value.write(&mut bytes).is_err());
            assert_eq!(bytes, [7]);
        }
        let long = "é".repeat(MAX_STRING);
        refuses(&String16(long.clone()));
        refuses(&CompactString(long));
        refuses(&ArrayLength(Some(usize::MAX)));
        refuses(&CompactArrayLength(Some(usize::MAX)));
        refuses(&TaggedFields((0..2000).map(|tag| TaggedField { tag, data: vec![] }).collect()));
        refuses(&TaggedFields(vec![tag(5, b"x"), tag(1, b"yz"), tag(5, b"dup")]));
        refuses(&TaggedFields(vec![tag(1, b"x"), tag(1, b"dup")]));
        for value in [ArrayLength(None), ArrayLength(Some(MAX_ARRAY))] { contract::check_wire_value(&value); }
        contract::check_wire_value(&CompactArrayLength(Some(MAX_ARRAY)));
        contract::check_wire_value(&String16("x".repeat(MAX_STRING)));
        contract::check_wire_value(&Float64(f64::NAN));
    }

    #[test]
    fn header_versions() {
        assert_eq!(request_header_version(api_key::PRODUCE, 8), 1);
        assert_eq!(request_header_version(api_key::PRODUCE, 9), 2);
        assert_eq!(request_header_version(api_key::FETCH, 12), 2);
        assert_eq!(request_header_version(api_key::METADATA, 8), 1);
        assert_eq!(request_header_version(api_key::METADATA, 9), 2);
        assert_eq!(request_header_version(api_key::CONTROLLED_SHUTDOWN, 0), 0);
        assert_eq!(request_header_version(api_key::CONTROLLED_SHUTDOWN, 1), 1);
        assert_eq!(request_header_version(api_key::CONTROLLED_SHUTDOWN, 3), 2);
        assert_eq!(request_header_version(api_key::SASL_HANDSHAKE, 1), 1);
        assert_eq!(request_header_version(api_key::API_VERSIONS, 2), 1);
        assert_eq!(request_header_version(api_key::API_VERSIONS, 3), 2);
        assert_eq!(request_header_version(47, 0), 1);
        assert_eq!(request_header_version(47, 1), 2);
        assert_eq!(request_header_version(68, 0), 2);
        assert_eq!(request_header_version(1000, 0), 2);
        assert_eq!(request_header_version(-1, 5), 1);
        assert_eq!(response_header_version(api_key::API_VERSIONS, 3), 0);
        assert_eq!(response_header_version(api_key::METADATA, 9), 1);
        assert_eq!(response_header_version(api_key::METADATA, 8), 0);
    }

    #[test]
    fn request_headers() {
        // Version 1: ApiVersions 0 with client ID "x".
        let b = [0, 18, 0, 0, 0, 0, 0, 1, 0, 1, b'x'];
        let h = RequestHeader::read(&mut Reader::new(&b)).unwrap();
        assert_eq!(h.version(), 1);
        assert_eq!(h.client_id.as_deref(), Some("x"));
        // Version 0: ControlledShutdown 0, no client ID.
        let b0 = [0, 7, 0, 0, 0, 0, 0, 9];
        let h0 = RequestHeader::read(&mut Reader::new(&b0)).unwrap();
        assert_eq!(h0, RequestHeader { api_key: 7, api_version: 0, correlation_id: 9, ..Default::default() });
        let mut w = Vec::new();
        h0.write(&mut w).unwrap();
        assert_eq!(w, b0);
        // Version 2: a null client ID, then one tagged field.
        let b2 = [0, 3, 0, 12, 0, 0, 0, 2, 0xff, 0xff, 1, 0, 2, 0xaa, 0xbb];
        let h2 = RequestHeader::read(&mut Reader::new(&b2)).unwrap();
        assert_eq!(h2.client_id, None);
        assert_eq!(h2.tagged_fields, vec![tag(0, &[0xaa, 0xbb])]);
        let mut w = Vec::new();
        h2.write(&mut w).unwrap();
        assert_eq!(w, b2);
        assert_eq!(RequestHeader::read_version(&mut Reader::new(&b2), 3), Err(Error::HeaderVersion(3)));
        assert_eq!(ResponseHeader::read_version(&mut Reader::new(&b2), 2), Err(Error::HeaderVersion(2)));
        // Every prefix is cut short.
        for n in 0..b2.len() {
            assert!(RequestHeader::read(&mut Reader::new(&b2[..n])).is_err(), "{n}");
        }
    }

    /// ApiVersions version 3 as a Java client sends it: header version 2
    /// with client ID "adminclient-1", and the client's software name and
    /// version.
    fn api_versions_v3_request() -> Vec<u8> {
        let mut p = vec![0, 18, 0, 3, 0, 0, 0, 5, 0, 13];
        p.extend_from_slice(b"adminclient-1");
        p.push(0);
        p.push(18);
        p.extend_from_slice(b"apache-kafka-java");
        p.push(6);
        p.extend_from_slice(b"3.7.0");
        p.push(0);
        p
    }

    #[test]
    fn api_versions_request_v3() {
        let p = api_versions_v3_request();
        let req = Request::parse(&p).unwrap();
        assert_eq!(req.header.correlation_id, 5);
        assert_eq!(req.header.client_id.as_deref(), Some("adminclient-1"));
        let RequestBody::ApiVersions(body) = &req.body else { panic!() };
        assert_eq!(body.client_software_name, "apache-kafka-java");
        assert_eq!(body.client_software_version, "3.7.0");
        assert_eq!(body.node_id, -1);
        assert_eq!(req.to_bytes().unwrap(), p);
        let framed = req.to_frame().unwrap().to_bytes().unwrap();
        assert_eq!(&framed[..4], &(p.len() as i32).to_be_bytes());
        // Every truncated prefix of the payload is an error, not a panic.
        for n in 0..p.len() {
            assert!(Request::parse(&p[..n]).is_err(), "{n}");
        }
        // A trailing byte too.
        let mut extra = p.clone();
        extra.push(0);
        assert_eq!(Request::parse(&extra), Err(Error::Trailing(1)));
    }

    #[test]
    fn api_versions_response_v3() {
        // Header version 0, even though the body is flexible.
        let resp = Response {
            header: ResponseHeader { correlation_id: 5, tagged_fields: vec![] },
            body: ResponseBody::ApiVersions(ApiVersionsResponse {
                error_code: 0,
                api_keys: vec![
                    ApiVersion { api_key: 3, min_version: 0, max_version: 12, tagged_fields: vec![] },
                    ApiVersion { api_key: 18, min_version: 0, max_version: 3, tagged_fields: vec![] },
                ],
                throttle_time_ms: 0,
                tagged_fields: vec![tag(1, &[0, 0, 0, 0, 0, 0, 0, 7])],
            }),
        };
        let p = resp.to_frame(18, 3).map(|frame| frame.0).unwrap();
        let mut want = vec![0, 0, 0, 5, 0, 0, 3, 0, 3, 0, 0, 0, 12, 0, 0, 18, 0, 0, 0, 3, 0, 0, 0, 0, 0];
        want.extend_from_slice(&[1, 1, 8, 0, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(p, want);
        assert_eq!(Response::parse(&p, 18, 3), Ok(resp));
        for n in 0..p.len() {
            assert!(Response::parse(&p[..n], 18, 3).is_err(), "{n}");
        }
        assert_eq!(correlation_id(&p), Some(5));
        assert_eq!(correlation_id(&p[..3]), None);
    }

    #[test]
    fn api_versions_every_version_round_trips() {
        let req = ApiVersionsRequest {
            client_software_name: "c".into(),
            client_software_version: "1".into(),
            cluster_id: Some("cluster".into()),
            node_id: 4,
            tagged_fields: vec![tag(9, b"t")],
        };
        let resp = ApiVersionsResponse {
            error_code: 35,
            api_keys: vec![ApiVersion {
                api_key: 0,
                min_version: 3,
                max_version: 11,
                tagged_fields: vec![tag(2, b"")],
            }],
            throttle_time_ms: 100,
            tagged_fields: vec![tag(3, &[1])],
        };
        for v in 0..=API_VERSIONS_MAX_VERSION {
            let req = if v < 3 { ApiVersionsRequest::default() }
                else if v < 5 { ApiVersionsRequest { cluster_id: None, node_id: -1, ..req.clone() } }
                else { req.clone() };
            let mut resp = resp.clone();
            if v == 0 { resp.throttle_time_ms = 0; }
            if v < 3 { resp.tagged_fields.clear(); for key in &mut resp.api_keys { key.tagged_fields.clear(); } }

            let b = body_bytes(&req, v).unwrap();
            let back = ApiVersionsRequest::parse(&b, v).unwrap();
            assert_eq!(body_bytes(&back, v).unwrap(), b);
            if v == 0 {
                assert!(b.is_empty());
                assert_eq!(back, ApiVersionsRequest::default());
            }
            if v == 5 {
                assert_eq!(back, req);
            }
            let b = body_bytes(&resp, v).unwrap();
            let back = ApiVersionsResponse::parse(&b, v).unwrap();
            assert_eq!(body_bytes(&back, v).unwrap(), b);
            if v >= 3 {
                assert_eq!(back, resp);
            }
            // A prefix that happens to read as a version 0 answer with
            // UNSUPPORTED_VERSION is taken as one.
            for n in 0..b.len() {
                if let Ok(got) = ApiVersionsResponse::parse(&b[..n], v) {
                    assert!(v > 0, "{n}");
                    assert_eq!(Ok(got), ApiVersionsResponse::parse(&b[..n], 0), "{v} {n}");
                }
            }
        }
        assert_eq!(body_bytes(&req, 6), Err(Error::Unwritable));
        assert_eq!(
            ApiVersionsResponse::parse(&[], -1),
            Err(Error::UnsupportedVersion { api_key: 18, api_version: -1 })
        );
        // A null array of keys.
        assert_eq!(ApiVersionsResponse::parse(&[0, 0, 0xff, 0xff, 0xff, 0xff], 0), Err(Error::Null));
        // A version 0 request with a body.
        assert_eq!(ApiVersionsRequest::parse(&[1], 0), Err(Error::Trailing(1)));
    }

    #[test]
    fn metadata_request_examples() {
        // Version 0, topics "test": header version 1, client ID "c".
        let p = [0, 3, 0, 0, 0, 0, 0, 7, 0, 1, b'c', 0, 0, 0, 1, 0, 4, b't', b'e', b's', b't'];
        let req = Request::parse(&p).unwrap();
        let RequestBody::Metadata(m) = &req.body else { panic!() };
        let topics = m.topics.as_ref().unwrap();
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0].name.as_deref(), Some("test"));
        assert_eq!(req.to_bytes().unwrap(), p);
        // Version 0 requires an explicit empty array for every topic.
        assert_eq!(MetadataRequest::parse(&[0xff, 0xff, 0xff, 0xff], 0), Err(Error::Null));
        assert_eq!(body_bytes(&MetadataRequest::default(), 0), Err(Error::Unwritable));
        let all = MetadataRequest { topics: Some(vec![]), ..Default::default() };
        assert_eq!(body_bytes(&all, 0).unwrap(), [0, 0, 0, 0]);
        // Version 1, every topic: a null array.
        assert_eq!(MetadataRequest::parse(&[0xff, 0xff, 0xff, 0xff], 1).unwrap().topics, None);
        // Version 4 adds allow_auto_topic_creation.
        assert!(!MetadataRequest::parse(&[0, 0, 0, 0, 0], 4).unwrap().allow_auto_topic_creation);
        // Version 9: compact, topic "a", no auto creation, both flags, tags.
        let b9 = [2, 2, b'a', 0, 0, 1, 0, 0];
        let m9 = MetadataRequest::parse(&b9, 9).unwrap();
        assert_eq!(m9.topics.as_ref().unwrap()[0].name.as_deref(), Some("a"));
        assert!(!m9.allow_auto_topic_creation);
        assert!(m9.include_cluster_authorized_operations);
        assert!(!m9.include_topic_authorized_operations);
        assert_eq!(body_bytes(&m9, 9).unwrap(), b9);
        // Version 12 asks by ID with a null name.
        let mut b12 = vec![2];
        b12.extend_from_slice(&[0x11; 16]);
        b12.extend_from_slice(&[0, 0, 1, 0, 0]);
        let m12 = MetadataRequest::parse(&b12, 12).unwrap();
        let t = &m12.topics.as_ref().unwrap()[0];
        assert_eq!((t.topic_id, t.name.clone()), ([0x11; 16], None));
        assert_eq!(body_bytes(&m12, 12).unwrap(), b12);
        // A null name before version 10 is refused.
        assert_eq!(MetadataRequest::parse(&[2, 0, 0, 1, 0, 0, 0], 9), Err(Error::Null));
        // Version 11 drops include_cluster_authorized_operations.
        assert!(MetadataRequest::parse(&[0, 1, 1, 0], 11).unwrap().include_topic_authorized_operations);
        assert_eq!(MetadataRequest::parse(&[0, 1, 1, 0], 10), Err(Error::Truncated));
        for n in 0..p.len() {
            assert!(Request::parse(&p[..n]).is_err(), "{n}");
        }
    }

    fn sample_metadata() -> MetadataResponse {
        MetadataResponse {
            throttle_time_ms: 5,
            brokers: vec![
                MetadataBroker {
                    node_id: 1,
                    host: "b1".into(),
                    port: 9092,
                    rack: Some("r".into()),
                    tagged_fields: vec![],
                },
                MetadataBroker {
                    node_id: 2,
                    host: "b2".into(),
                    port: 9093,
                    rack: None,
                    tagged_fields: vec![tag(4, b"")],
                },
            ],
            cluster_id: Some("abc".into()),
            controller_id: 1,
            topics: vec![MetadataTopic {
                error_code: 0,
                name: Some("orders".into()),
                topic_id: [3; 16],
                is_internal: true,
                partitions: vec![MetadataPartition {
                    error_code: 0,
                    partition_index: 0,
                    leader_id: 1,
                    leader_epoch: 7,
                    replica_nodes: vec![1, 2],
                    isr_nodes: vec![1],
                    offline_replicas: vec![2],
                    tagged_fields: vec![tag(0, b"p")],
                }],
                topic_authorized_operations: 0x0f,
                tagged_fields: vec![],
            }],
            cluster_authorized_operations: 0x10,
            error_code: 0,
            tagged_fields: vec![tag(2, b"q")],
        }
    }

    #[test]
    fn metadata_response_v0_bytes() {
        let m = sample_metadata();
        let b = body_bytes(&fit_response(m.clone(), 0), 0).unwrap();
        #[rustfmt::skip]
        let want = [
            0, 0, 0, 2, // two brokers
            0, 0, 0, 1, 0, 2, b'b', b'1', 0, 0, 0x23, 0x84,
            0, 0, 0, 2, 0, 2, b'b', b'2', 0, 0, 0x23, 0x85,
            0, 0, 0, 1, // one topic
            0, 0, 0, 6, b'o', b'r', b'd', b'e', b'r', b's',
            0, 0, 0, 1, // one partition
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2,
            0, 0, 0, 1, 0, 0, 0, 1,
        ];
        assert_eq!(b, want);
        let back = MetadataResponse::parse(&b, 0).unwrap();
        assert_eq!(back.controller_id, -1);
        assert_eq!(back.topics[0].partitions[0].leader_epoch, -1);
        assert_eq!(body_bytes(&back, 0).unwrap(), b);
    }

    #[test]
    fn metadata_every_version_round_trips() {
        let m = sample_metadata();
        let req = MetadataRequest {
            topics: Some(vec![MetadataRequestTopic {
                topic_id: [9; 16],
                name: Some("orders".into()),
                tagged_fields: vec![tag(1, b"")],
            }]),
            allow_auto_topic_creation: false,
            include_cluster_authorized_operations: true,
            include_topic_authorized_operations: true,
            tagged_fields: vec![tag(0, b"z")],
        };
        for v in 0..=METADATA_MAX_VERSION {
            let m = fit_response(m.clone(), v);
            let b = body_bytes(&m, v).unwrap();
            let back = MetadataResponse::parse(&b, v).unwrap();
            assert_eq!(body_bytes(&back, v).unwrap(), b, "{v}");
            assert_eq!(MetadataResponse::parse(&body_bytes(&back, v).unwrap(), v).unwrap(), back);
            if v == 10 {
                assert_eq!(back, m, "{v}");
            }
            for n in 0..b.len() {
                assert!(MetadataResponse::parse(&b[..n], v).is_err(), "{v} {n}");
            }
            let req = fit_request(req.clone(), v);
            let b = body_bytes(&req, v).unwrap();
            let back = MetadataRequest::parse(&b, v).unwrap();
            assert_eq!(body_bytes(&back, v).unwrap(), b, "{v}");
            if v >= 9 {
                assert_eq!(back, req, "{v}");
            }
            for n in 0..b.len() {
                assert!(MetadataRequest::parse(&b[..n], v).is_err(), "{v} {n}");
            }
            // As whole requests and responses, with headers.
            let full = Request {
                header: RequestHeader {
                    api_key: 3,
                    api_version: v,
                    correlation_id: 1,
                    client_id: Some("c".into()),
                    tagged_fields: vec![],
                },
                body: RequestBody::Metadata(back),
            };
            assert_eq!(Request::parse(&full.to_bytes().unwrap()).unwrap(), full);
            let resp = Response {
                header: ResponseHeader {
                    correlation_id: 1,
                    tagged_fields: if v >= 9 { vec![tag(0, b"h")] } else { vec![] },
                },
                body: ResponseBody::Metadata(MetadataResponse::parse(&body_bytes(&m, v).unwrap(), v).unwrap()),
            };
            assert_eq!(Response::parse(&resp.to_frame(3, v).map(|frame| frame.0).unwrap(), 3, v).unwrap(), resp);
        }
        // Version 12 and later carry a null topic name, for a topic with
        // an error; earlier versions have none.
        let mut nameless = m.clone();
        nameless.topics[0].name = None;
        nameless.topics[0].error_code = error_code::UNKNOWN_TOPIC_ID;
        let b = body_bytes(&fit_response(nameless.clone(), 12), 12).unwrap();
        assert_eq!(MetadataResponse::parse(&b, 12).unwrap().topics[0].name, None);
        assert!(matches!(body_bytes(&nameless, 11), Err(Error::Unwritable)));
        assert_eq!(body_bytes(&m, 14), Err(Error::Unwritable));
        // Version 13's top-level error code is last, after the topics.
        let mut failed = MetadataResponse { error_code: 29, ..MetadataResponse::default() };
        failed.tagged_fields.clear();
        assert_eq!(body_bytes(&failed, 13).unwrap(), [0, 0, 0, 0, 1, 0, 0xff, 0xff, 0xff, 0xff, 1, 0, 29, 0]);
    }

    #[test]
    fn mismatched_bodies() {
        let header = RequestHeader { api_key: 3, api_version: 1, ..Default::default() };
        let req = Request { header: header.clone(), body: RequestBody::ApiVersions(ApiVersionsRequest::default()) };
        assert_eq!(req.to_bytes(), Err(Error::Unwritable));
        let req = Request { header: header.clone(), body: RequestBody::Other(vec![]) };
        assert_eq!(req.to_bytes(), Err(Error::Unwritable));
        // A version with no full body is an Other.
        let header = RequestHeader { api_key: 3, api_version: 99, ..Default::default() };
        let req = Request { header: header.clone(), body: RequestBody::Metadata(MetadataRequest::default()) };
        assert_eq!(req.to_bytes(), Err(Error::Unwritable));
        let req = Request { header, body: RequestBody::Other(vec![1, 2, 3]) };
        let back = Request::parse(&req.to_bytes().unwrap()).unwrap();
        assert_eq!(back, req);
        let resp = Response { header: ResponseHeader::default(), body: ResponseBody::Other(vec![]) };
        assert_eq!(resp.to_frame(18, 0).map(|frame| frame.0), Err(Error::Unwritable));
        assert_eq!(Response::parse(&resp.to_frame(0, 9).map(|frame| frame.0).unwrap(), 0, 9).unwrap(), resp);
        let resp =
            Response { header: ResponseHeader::default(), body: ResponseBody::Metadata(MetadataResponse::default()) };
        assert_eq!(resp.to_frame(18, 0).map(|frame| frame.0), Err(Error::Unwritable));
    }

    #[test]
    fn frames() {
        let value = Frame(vec![1, 2, 3]);
        let bytes = value.to_bytes().unwrap();
        assert_eq!(bytes, [0, 0, 0, 3, 1, 2, 3]);
        assert_eq!(Frame::parse(&bytes), Ok(value));
        for n in 0..bytes.len() {
            assert_eq!(Frames::new().decode(&bytes[..n], false), Ok(Step::Need), "{n}");
            assert_eq!(Frame::parse(&bytes[..n]), Err(Error::Truncated));
        }
        assert_eq!(Frame::parse(&[0; 4]), Ok(Frame(vec![])));
        assert_eq!(Frame::parse(&[0xff; 4]), Err(Error::FrameSize(-1)));
        assert_eq!(Frames::with_limit(3).decode(&[0, 0, 0, 4], false), Err(Error::FrameSize(4)));
        assert_eq!(Frame::parse(&[0x7f, 0xff, 0xff, 0xff]), Err(Error::FrameSize(i32::MAX)));
        assert_eq!(Frame(vec![0; MAX_FRAME + 1]).to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn stream_splits_frames() {
        let a = Frame(api_versions_v3_request());
        let b = Frame(vec![0, 18, 0, 0, 0, 0, 0, 2, 0xff, 0xff]);
        let mut bytes = a.to_bytes().unwrap();
        b.write(&mut bytes).unwrap();
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * Frames::new().capacity());
        assert_eq!(decode_all(Frames::new, &bytes), (vec![a, b], None));
        for (limit, header, error) in [
            (MAX_FRAME, [0x80, 0, 0, 0], Error::FrameSize(i32::MIN)),
            (4, [0, 0, 0, 5], Error::FrameSize(5)),
            (usize::MAX, [0x7f, 0xff, 0xff, 0xff], Error::FrameSize(i32::MAX)),
        ] {
            let mut stream = Stream::new(Frames::with_limit(limit));
            assert_eq!(stream.push(&header), 4);
            assert_eq!(stream.next(), Some(Err(Fail::Protocol(error))));
            assert_eq!(stream.push(&bytes), bytes.len());
            assert!(stream.next().is_none());
        }
        // A cloned stateless decoder can read the same pending frame.
        let mut decoder = Frames::new();
        assert_eq!(decoder.decode(&bytes[..3], false), Ok(Step::Need));
        let mut copy = decoder;
        assert_eq!(decoder.decode(&bytes, false), copy.decode(&bytes, false));
    }

    #[test]
    fn stream_reads_many_small_frames_in_linear_time() {
        let one = Frame(vec![0, 18, 0, 0, 0, 0, 0, 1, 0xff, 0xff]).to_bytes().unwrap();
        let started = std::time::Instant::now();
        let mut stream = Stream::new(Frames::new());
        let mut count = 0;
        pump(&mut stream, &one.repeat(200_000), |_| count += 1).unwrap();
        finish(&mut stream, |_| count += 1).unwrap();
        assert_eq!(count, 200_000);
        assert_eq!(stream.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn errors_display() {
        let all = [
            Error::Truncated,
            Error::FrameSize(-1),
            Error::TooLarge(1),
            Error::Varint,
            Error::Length(-2),
            Error::Utf8,
            Error::Null,
            Error::TagOrder(1),
            Error::HeaderVersion(3),
            Error::UnsupportedVersion { api_key: 1, api_version: 2 },
            Error::Unwritable,
            Error::Trailing(1),
            Error::Invalid("x"),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
        // A response header has no version 2, and the message must not
        // say that 2 is allowed.
        let e = ResponseHeader::read_version(&mut Reader::new(&[0; 8]), 2).unwrap_err();
        assert_eq!(e, Error::HeaderVersion(2));
        assert!(!e.to_string().contains("0, 1 or 2"), "{e}");
    }

    /// Exercises framing, exact requests, and contextual responses.
    fn check(data: &[u8]) {
        contract::check_decode_with_alloc_limit(Frames::new, data, 2 * Frames::new().capacity());
        contract::check_wire::<Frame>(data);
        contract::check_wire::<Request>(data);
        contract::check_wire::<RequestHeader>(data);
        contract::check_wire::<TaggedFields>(data);
        let frames = decode_all(Frames::new, data).0;
        let mut payloads: Vec<&[u8]> = frames.iter().map(|frame| frame.0.as_slice()).collect();
        payloads.push(data);
        for p in payloads {
            if let Ok(req) = Request::parse(p) {
                let bytes = req.to_bytes().unwrap();
                assert_eq!(Request::parse(&bytes), Ok(req));
            }
            for key in [api_key::API_VERSIONS, api_key::METADATA, api_key::PRODUCE] {
                for version in [0, 1, 3, 5, 8, 9, 10, 12, 13] {
                    if let Ok(resp) = Response::parse(p, key, version) {
                        let bytes = resp.to_frame(key, version).map(|frame| frame.0).unwrap();
                        assert_eq!(Response::parse(&bytes, key, version), Ok(resp));
                    }
                }
            }
            let mut r = Reader::new(p);
            let _ = r.tagged_fields();
            let _ = r.varlong();
            let _ = r.compact_nullable_bytes();
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x6b_6166_6b61);
        // Valid encodings to mutate, so the fuzz reaches deep fields.
        let m = sample_metadata();
        let mut seeds: Vec<Vec<u8>> = vec![Frame(api_versions_v3_request()).to_bytes().unwrap()];
        for v in 0..=METADATA_MAX_VERSION {
            let resp = Response { header: ResponseHeader::default(), body: ResponseBody::Metadata(fit_response(m.clone(), v)) };
            seeds.push(resp.to_frame(3, v).unwrap().to_bytes().unwrap());
            let req = Request {
                header: RequestHeader {
                    api_key: 3,
                    api_version: v,
                    correlation_id: 1,
                    client_id: Some("c".into()),
                    tagged_fields: vec![],
                },
                body: RequestBody::Metadata(MetadataRequest {
                    topics: Some(vec![MetadataRequestTopic { name: Some("t".into()), ..Default::default() }]),
                    ..Default::default()
                }),
            };
            seeds.push(req.to_frame().unwrap().to_bytes().unwrap());
        }
        for _ in 0..4000 {
            let data: Vec<u8> = if rng.coin() {
                let len = rng.index(64);
                let mut d: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                // Often a frame size that fits.
                if len >= 4 && rng.coin() {
                    d[..4].copy_from_slice(&((len - 4) as i32).to_be_bytes());
                }
                d
            } else {
                let mut d = seeds[rng.index(seeds.len())].clone();
                mutate(&mut rng, &mut d);
                d
            };
            check(&data);
            // The payload alone, as a request and a response.
            if data.len() > 4 {
                check(&data[4..]);
            }
        }
    }

    // Random values for every field, to check that what a writer makes is
    // always read back.

    fn any_string(rng: &mut Lcg) -> String {
        match rng.index(6) {
            0 => String::new(),
            // Multibyte text near the length limit.
            1 => "\u{e9}".repeat(MAX_STRING / 2 - rng.index(3)),
            _ => rng.text(7),
        }
    }

    fn any_option(rng: &mut Lcg) -> Option<String> {
        if rng.index(3) == 0 { None } else { Some(any_string(rng)) }
    }

    fn any_tags(rng: &mut Lcg) -> Vec<TaggedField> {
        let mut tags: Vec<_> = (0..rng.index(4))
            .map(|_| tag(rng.index(5) as u32, &vec![rng.next() as u8; rng.index(3)]))
            .collect();
        tags.sort_by_key(|field| field.tag);
        tags.dedup_by_key(|field| field.tag);
        tags
    }

    fn any_i32s(rng: &mut Lcg) -> Vec<i32> {
        (0..rng.index(4)).map(|_| rng.next() as i32).collect()
    }

    fn any_metadata_response(rng: &mut Lcg) -> MetadataResponse {
        MetadataResponse {
            throttle_time_ms: rng.next() as i32,
            brokers: (0..rng.index(3))
                .map(|_| MetadataBroker {
                    node_id: rng.next() as i32,
                    host: any_string(rng),
                    port: rng.next() as i32,
                    rack: any_option(rng),
                    tagged_fields: any_tags(rng),
                })
                .collect(),
            cluster_id: any_option(rng),
            controller_id: rng.next() as i32,
            topics: (0..rng.index(3))
                .map(|_| MetadataTopic {
                    error_code: rng.next() as i16,
                    name: any_option(rng),
                    topic_id: [rng.next() as u8; 16],
                    is_internal: rng.coin(),
                    partitions: (0..rng.index(3))
                        .map(|_| MetadataPartition {
                            error_code: rng.next() as i16,
                            partition_index: rng.next() as i32,
                            leader_id: rng.next() as i32,
                            leader_epoch: rng.next() as i32,
                            replica_nodes: any_i32s(rng),
                            isr_nodes: any_i32s(rng),
                            offline_replicas: any_i32s(rng),
                            tagged_fields: any_tags(rng),
                        })
                        .collect(),
                    topic_authorized_operations: rng.next() as i32,
                    tagged_fields: any_tags(rng),
                })
                .collect(),
            cluster_authorized_operations: rng.next() as i32,
            error_code: rng.next() as i16,
            tagged_fields: any_tags(rng),
        }
    }

    fn fit_request(mut req: MetadataRequest, v: i16) -> MetadataRequest {
        if v < 4 {
            req.allow_auto_topic_creation = true;
        }
        if !(8..=10).contains(&v) {
            req.include_cluster_authorized_operations = false;
        }
        if v < 8 {
            req.include_topic_authorized_operations = false;
        }
        if v < 9 {
            req.tagged_fields.clear();
        }
        if v == 0 && req.topics.is_none() {
            req.topics = Some(vec![]);
        }
        for topic in req.topics.iter_mut().flatten() {
            if v < 12 {
                topic.topic_id = [0; 16];
                topic.name.get_or_insert_with(String::new);
            }
            if v < 9 {
                topic.tagged_fields.clear();
            }
        }
        req
    }

    fn fit_response(mut resp: MetadataResponse, v: i16) -> MetadataResponse {
        if v < 3 {
            resp.throttle_time_ms = 0;
        }
        if v < 2 {
            resp.cluster_id = None;
        }
        if v < 1 {
            resp.controller_id = -1;
        }
        if !(8..=10).contains(&v) {
            resp.cluster_authorized_operations = i32::MIN;
        }
        if v < 13 {
            resp.error_code = 0;
        }
        if v < 9 {
            resp.tagged_fields.clear();
        }
        for broker in &mut resp.brokers {
            if v < 1 {
                broker.rack = None;
            }
            if v < 9 {
                broker.tagged_fields.clear();
            }
        }
        for topic in &mut resp.topics {
            if v < 12 || topic.error_code == 0 || topic.topic_id == [0; 16] {
                topic.name.get_or_insert_with(String::new);
            }
            if v < 10 {
                topic.topic_id = [0; 16];
            }
            if v < 1 {
                topic.is_internal = false;
            }
            if v < 8 {
                topic.topic_authorized_operations = i32::MIN;
            }
            if v < 9 {
                topic.tagged_fields.clear();
            }
            for part in &mut topic.partitions {
                if v < 7 {
                    part.leader_epoch = -1;
                }
                if v < 5 {
                    part.offline_replicas.clear();
                }
                if v < 9 {
                    part.tagged_fields.clear();
                }
            }
        }
        resp
    }

    /// Tagged fields with tags past the ones an ApiVersions response
    /// defines.
    fn any_unknown_tags(rng: &mut Lcg) -> Vec<TaggedField> {
        let mut tags = any_tags(rng);
        for t in &mut tags {
            t.tag += 4;
        }
        tags
    }

    fn any_metadata_request(rng: &mut Lcg) -> MetadataRequest {
        MetadataRequest {
            topics: if rng.index(3) == 0 {
                None
            } else {
                Some(
                    (0..rng.index(3))
                        .map(|_| MetadataRequestTopic {
                            topic_id: [rng.next() as u8; 16],
                            name: any_option(rng),
                            tagged_fields: any_tags(rng),
                        })
                        .collect(),
                )
            },
            allow_auto_topic_creation: rng.coin(),
            include_cluster_authorized_operations: rng.coin(),
            include_topic_authorized_operations: rng.coin(),
            tagged_fields: any_tags(rng),
        }
    }

    #[test]
    fn writers_always_make_what_readers_take() {
        let mut rng = Lcg::new(0x77_7269_7465);
        for _ in 0..300 {
            let mut header = RequestHeader {
                api_key: [api_key::API_VERSIONS, api_key::METADATA, api_key::CONTROLLED_SHUTDOWN, 500]
                    [rng.index(4)],
                api_version: rng.index(16) as i16 - 1,
                correlation_id: rng.next() as i32,
                client_id: any_option(&mut rng),
                tagged_fields: any_tags(&mut rng),
            };
            let (key, version) = (header.api_key, header.api_version);
            if header.version() == 0 {
                header.client_id = None;
            }
            if header.version() < 2 {
                header.tagged_fields.clear();
            }
            let mut body = if !has_body(key, version) {
                RequestBody::Other(rng.bytes(4))
            } else if key == api_key::API_VERSIONS {
                RequestBody::ApiVersions(ApiVersionsRequest {
                    client_software_name: any_string(&mut rng),
                    client_software_version: any_string(&mut rng),
                    cluster_id: any_option(&mut rng),
                    node_id: rng.next() as i32,
                    tagged_fields: any_tags(&mut rng),
                })
            } else {
                RequestBody::Metadata(fit_request(any_metadata_request(&mut rng), version))
            };
            if let RequestBody::ApiVersions(body) = &mut body {
                if version < 3 {
                    body.client_software_name.clear();
                    body.client_software_version.clear();
                    body.tagged_fields.clear();
                }
                if version < 5 {
                    body.cluster_id = None;
                    body.node_id = -1;
                }
            }
            let req = Request { header, body };
            contract::check_wire_value(&req);
            let bytes = req.to_bytes().unwrap();
            assert_eq!(Request::parse(&bytes), Ok(req.clone()));
            let frame = req.to_frame().unwrap();
            assert_eq!(decode_all(Frames::new, &frame.to_bytes().unwrap()), (vec![Frame(bytes)], None));

            let mut rbody = if !has_body(key, version) {
                ResponseBody::Other(rng.bytes(4))
            } else if key == api_key::API_VERSIONS {
                ResponseBody::ApiVersions(ApiVersionsResponse {
                    error_code: rng.next() as i16,
                    api_keys: (0..rng.index(4))
                        .map(|_| ApiVersion {
                            api_key: rng.next() as i16,
                            min_version: rng.next() as i16,
                            max_version: rng.next() as i16,
                            tagged_fields: any_tags(&mut rng),
                        })
                        .collect(),
                    throttle_time_ms: rng.next() as i32,
                    tagged_fields: any_unknown_tags(&mut rng),
                })
            } else {
                ResponseBody::Metadata(fit_response(any_metadata_response(&mut rng), version))
            };
            if let ResponseBody::ApiVersions(body) = &mut rbody {
                if version < 1 {
                    body.throttle_time_ms = 0;
                }
                if version < 3 {
                    body.tagged_fields.clear();
                    for key in &mut body.api_keys {
                        key.tagged_fields.clear();
                    }
                }
            }
            let mut header = ResponseHeader { correlation_id: 1, tagged_fields: any_tags(&mut rng) };
            if response_header_version(key, version) == 0 {
                header.tagged_fields.clear();
            }
            let resp = Response {
                header,
                body: rbody,
            };
            let frame = resp.to_frame(key, version).unwrap();
            contract::check_wire_value(&frame);
            assert_eq!(Response::parse(&frame.0, key, version), Ok(resp));

        }
    }

    // Regressions from review.

    #[test]
    fn stream_refuses_bad_sizes_with_bounded_input() {
        let mut stream = Stream::new(Frames::with_limit(16));
        let mut junk = vec![0, 0, 0, 17];
        junk.resize(100_000, 0xaa);
        assert_eq!(stream.push(&junk), 20);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::FrameSize(17)))));
        assert_eq!(stream.buffered(), 20);
        assert!(stream.next().is_none());
        let mut stream = Stream::new(Frames::with_limit(16));
        assert_eq!(stream.push(&[0, 0, 0, 1, 7, 0xff]), 6);
        assert_eq!(stream.next(), Some(Ok(Frame(vec![7]))));
        assert_eq!(stream.push(&[0xff, 0xff, 0xff, 1, 2, 3]), 6);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::FrameSize(-1)))));
        let mut stream = Stream::new(Frames::with_limit(16));
        assert_eq!(stream.push(&[0, 0]), 2);
        assert!(stream.next().is_none());
        assert_eq!(stream.buffered(), 2);
        assert_eq!(stream.push(&[1, 0, 9, 9]), 4);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::FrameSize(256)))));
    }

    #[test]
    fn parsers_refuse_payloads_over_the_frame_limit() {
        // Produce version 0: a body this module keeps as bytes.
        let mut p = vec![0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff];
        p.resize(MAX_FRAME + 1, 0);
        assert_eq!(Request::parse(&p), Err(Error::TooLarge(MAX_FRAME + 1)));
        assert_eq!(RequestHeader::parse(&p), Err(Error::TooLarge(MAX_FRAME + 1)));
        assert_eq!(ResponseHead::<1>::parse(&p), Err(Error::TooLarge(MAX_FRAME + 1)));
        assert_eq!(Response::parse(&p, api_key::PRODUCE, 0), Err(Error::TooLarge(MAX_FRAME + 1)));
        p.truncate(MAX_FRAME);
        let req = Request::parse(&p).unwrap();
        assert_eq!(req.to_frame().unwrap().to_bytes().unwrap().len(), MAX_FRAME + SIZE_LEN);
        // Byte strings and tagged-field values longer than a writer makes.
        let mut big = ((MAX_FRAME + 1) as i32).to_be_bytes().to_vec();
        big.resize(MAX_FRAME + 5, 0);
        assert_eq!(Reader::new(&big).bytes(), Err(Error::Length(MAX_FRAME as i64 + 1)));
        let mut big = UnsignedVarint(MAX_FRAME as u32 + 2).to_bytes().unwrap();
        big.resize(MAX_FRAME + 5, 0);
        assert_eq!(Reader::new(&big).compact_bytes(), Err(Error::Length(MAX_FRAME as i64 + 1)));
        let mut big = vec![1, 0];
        big.extend(UnsignedVarint(MAX_FRAME as u32 + 1).to_bytes().unwrap());
        big.resize(MAX_FRAME + 10, 0);
        assert_eq!(Reader::new(&big).tagged_fields(), Err(Error::Length(MAX_FRAME as i64 + 1)));
    }

    #[test]
    fn api_versions_response_falls_back_to_version_0() {
        // A broker that does not speak ApiVersions version 3 answers in
        // version 0: correlation ID 1, UNSUPPORTED_VERSION, no APIs.
        let p = [0, 0, 0, 1, 0, 0x23, 0, 0, 0, 0];
        let want = ApiVersionsResponse { error_code: error_code::UNSUPPORTED_VERSION, ..Default::default() };
        for v in 1..=API_VERSIONS_MAX_VERSION {
            let resp = Response::parse(&p, api_key::API_VERSIONS, v).unwrap();
            assert_eq!(resp.body, ResponseBody::ApiVersions(want.clone()), "{v}");
        }
        // With the APIs the broker speaks, as Kafka 2.4 and later send.
        let p = [0, 0x23, 0, 0, 0, 1, 0, 18, 0, 0, 0, 2];
        let got = ApiVersionsResponse::parse(&p, 3).unwrap();
        assert_eq!(got.api_keys, [ApiVersion { api_key: 18, min_version: 0, max_version: 2, tagged_fields: vec![] }]);
        // Only for UNSUPPORTED_VERSION.
        assert!(ApiVersionsResponse::parse(&[0, 0, 0, 0, 0, 0], 3).is_err());
    }

    #[test]
    fn metadata_request_refuses_fields_its_version_lacks() {
        let named = |name: &str| MetadataRequestTopic { name: Some(name.into()), ..Default::default() };
        let no_auto = MetadataRequest {
            topics: Some(vec![named("missing-topic")]),
            allow_auto_topic_creation: false,
            ..Default::default()
        };
        for v in 0..4 {
            assert!(matches!(body_bytes(&no_auto, v), Err(Error::Unwritable)), "{v}");
        }
        assert!(!MetadataRequest::parse(&body_bytes(&no_auto, 4).unwrap(), 4).unwrap().allow_auto_topic_creation);
        let cluster_ops = MetadataRequest { include_cluster_authorized_operations: true, ..Default::default() };
        for v in 0..=METADATA_MAX_VERSION {
            assert_eq!(body_bytes(&cluster_ops, v).is_ok(), (8..=10).contains(&v), "{v}");
        }
        let topic_ops = MetadataRequest { include_topic_authorized_operations: true, ..Default::default() };
        for v in 0..=METADATA_MAX_VERSION {
            assert_eq!(body_bytes(&topic_ops, v).is_ok(), v >= 8, "{v}");
        }
    }

    #[test]
    fn metadata_request_asks_by_id_from_version_12() {
        let by_id = MetadataRequest {
            topics: Some(vec![MetadataRequestTopic { topic_id: [0x11; 16], name: None, tagged_fields: vec![] }]),
            ..Default::default()
        };
        for v in 0..12 {
            assert!(matches!(body_bytes(&by_id, v), Err(Error::Unwritable)), "{v}");
        }
        let b = body_bytes(&by_id, 12).unwrap();
        assert_eq!(MetadataRequest::parse(&b, 12).unwrap(), by_id);
        // Versions 10 and 11 have the fields, but Kafka refuses them there.
        assert!(matches!(MetadataRequest::parse(&b, 11), Err(Error::Invalid(_))));
        let mut named_id = by_id.clone();
        named_id.topics.as_mut().unwrap()[0].name = Some("t".into());
        assert!(matches!(body_bytes(&named_id, 11), Err(Error::Unwritable)));
        let mut b10 = vec![2];
        b10.extend_from_slice(&[0x11; 16]);
        b10.extend_from_slice(&[2, b't', 0, 1, 0, 0, 0]);
        assert!(matches!(MetadataRequest::parse(&b10, 10), Err(Error::Invalid(_))));
        // A null name with no ID is refused before version 12 too.
        let nameless = MetadataRequest { topics: Some(vec![MetadataRequestTopic::default()]), ..Default::default() };
        assert!(matches!(body_bytes(&nameless, 3), Err(Error::Unwritable)));
    }

    #[test]
    fn api_versions_request_validity() {
        let mut req = ApiVersionsRequest {
            client_software_name: "apache-kafka-java".into(),
            client_software_version: "3.7.0".into(),
            ..Default::default()
        };
        for v in 0..=API_VERSIONS_MAX_VERSION {
            assert!(req.is_valid(v), "{v}");
            assert!(ApiVersionsRequest::default().is_valid(v) == (v < 3), "{v}");
        }
        for bad in ["", "-a", "a-", "a b", "é"] {
            req.client_software_version = bad.into();
            assert!(!req.is_valid(3), "{bad:?}");
        }
        req.client_software_version = "1".into();
        assert!(req.is_valid(3));
        // Version 5: the cluster and node IDs come together or not at all.
        req.cluster_id = Some("c".into());
        assert!(!req.is_valid(5));
        assert!(req.is_valid(4));
        req.node_id = 2;
        assert!(req.is_valid(5));
        req.cluster_id = None;
        assert!(!req.is_valid(5));
    }

    #[test]
    fn api_versions_known_tags_are_checked() {
        let with = |t: TaggedField| ApiVersionsResponse { tagged_fields: vec![t], ..Default::default() };
        // FinalizedFeaturesEpoch is an INT64, and ZkMigrationReady a BOOLEAN.
        for t in [tag(1, b""), tag(1, &[0; 7]), tag(3, b""), tag(3, &[1, 1])] {
            let r = with(t.clone());
            assert!(matches!(body_bytes(&r, 3), Err(Error::Unwritable)), "{t:?}");
            let mut b = vec![0, 0, 1, 0, 0, 0, 0, 1];
            b.push(t.tag as u8);
            b.push(t.data.len() as u8);
            b.extend_from_slice(&t.data);
            assert!(ApiVersionsResponse::parse(&b, 3).is_err(), "{t:?}");
        }
        // The feature lists: a compact array of name, two INT16s and tags.
        let mut features = vec![2, 4];
        features.extend_from_slice(b"abc");
        features.extend_from_slice(&[0, 1, 0, 2, 0]);
        for good in [tag(0, &features), tag(2, &features), tag(0, &[1]), tag(1, &[0; 8]), tag(3, &[1]), tag(9, b"")] {
            let r = with(good.clone());
            assert_eq!(ApiVersionsResponse::parse(&body_bytes(&r, 3).unwrap(), 3), Ok(r), "{good:?}");
        }
        for bad in [&features[..features.len() - 1], &[0], &[2, 1, 0], &[]] {
            assert!(matches!(body_bytes(&with(tag(0, bad)), 4), Err(Error::Unwritable)), "{bad:?}");
            assert!(matches!(body_bytes(&with(tag(2, bad)), 4), Err(Error::Unwritable)), "{bad:?}");
        }
        // Tagged fields with tags of the same numbers inside the API entries
        // are not these fields, and stay opaque.
        let r = ApiVersionsResponse {
            api_keys: vec![ApiVersion { tagged_fields: vec![tag(1, b"")], ..Default::default() }],
            ..Default::default()
        };
        assert_eq!(ApiVersionsResponse::parse(&body_bytes(&r, 3).unwrap(), 3), Ok(r));
    }

    #[test]
    fn tags_are_31_bits() {
        let max = i32::MAX as u32;
        let mut ok = vec![1];
        ok.extend(UnsignedVarint(max).to_bytes().unwrap());
        ok.push(0);
        assert_eq!(Reader::new(&ok).tagged_fields(), Ok(vec![tag(max, b"")]));
        for t in [max + 1, u32::MAX] {
            let mut b = vec![1];
            b.extend(UnsignedVarint(t).to_bytes().unwrap());
            b.push(0);
            assert!(matches!(Reader::new(&b).tagged_fields(), Err(Error::Invalid(_))), "{t}");
            let fields = TaggedFields(vec![tag(t, b"x"), tag(3, b"y")]);
            contract::check_wire_value(&fields);
            assert_eq!(fields.to_bytes(), Err(Error::Unwritable));
        }
    }

    #[test]
    fn metadata_response_topics_name_or_fail() {
        let topic = |error_code: i16, name: Option<&str>, topic_id: [u8; 16]| MetadataResponse {
            topics: vec![MetadataTopic { error_code, name: name.map(Into::into), topic_id, ..Default::default() }],
            ..Default::default()
        };
        // A topic asked for by an unknown ID: no name, an error.
        let unknown = topic(error_code::UNKNOWN_TOPIC_ID, None, [5; 16]);
        assert_eq!(MetadataResponse::parse(&body_bytes(&unknown, 12).unwrap(), 12), Ok(unknown.clone()));
        // Before version 12 a name is never null.
        assert!(matches!(body_bytes(&unknown, 11), Err(Error::Unwritable)));
        // A topic with no error always has a name, and one of name and ID
        // is always there.
        for (bad, v) in [(topic(0, None, [5; 16]), 12), (topic(error_code::UNKNOWN_TOPIC_ID, None, [0; 16]), 13)] {
            assert!(matches!(body_bytes(&bad, v), Err(Error::Unwritable)));
            let mut ok = bad.clone();
            ok.topics[0].name = Some("t".into());
            let b = body_bytes(&ok, v).unwrap();
            // The same bytes with the name made null.
            let at = b.windows(2).position(|x| x == [2, b't']).unwrap();
            let mut nulled = b.clone();
            nulled.splice(at..at + 2, [0]);
            assert!(matches!(MetadataResponse::parse(&nulled, v), Err(Error::Invalid(_))), "{v}");
        }
    }

}
