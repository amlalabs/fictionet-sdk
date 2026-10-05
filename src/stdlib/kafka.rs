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
//! Nothing here reads a socket. A world that plays a broker feeds the
//! bytes it reads from a TCP connection to a [`Decoder`], gets each
//! frame's payload back, reads it with [`Request::parse`], and writes the
//! reply from [`Response::to_frame`] back to the connection. Which topics
//! exist, and what the broker says about them, is up to world code.
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
//! [`Decoder::with_limit`].
//!
//! ```
//! use fictionet::stdlib::kafka::{
//!     api_key, ApiVersion, ApiVersionsResponse, Decoder, Request, RequestBody, Response, ResponseBody,
//!     ResponseHeader,
//! };
//!
//! let mut decoder = Decoder::new();
//! // ApiVersions version 0, correlation ID 1, client ID "x".
//! decoder.feed(&[0, 0, 0, 11, 0, 18, 0, 0, 0, 0, 0, 1, 0, 1, b'x']);
//! let payload = decoder.next_frame().unwrap().unwrap();
//! let request = Request::parse(&payload).unwrap();
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
//! let bytes = response.to_frame(request.header.api_key, request.header.api_version).unwrap();
//! assert_eq!(bytes, [0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 18, 0, 0, 0, 4]);
//! assert_eq!(Response::parse(&bytes[4..], api_key::API_VERSIONS, 0).unwrap(), response);
//! ```

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
/// The highest ApiVersions version with a full body here.
pub const API_VERSIONS_MAX_VERSION: i16 = 5;
/// The highest Metadata version with a full body here.
pub const METADATA_MAX_VERSION: i16 = 13;

/// API keys: the numbers that name each request type.
pub mod api_key {
    #![allow(missing_docs)]
    pub const PRODUCE: i16 = 0;
    pub const FETCH: i16 = 1;
    pub const LIST_OFFSETS: i16 = 2;
    pub const METADATA: i16 = 3;
    pub const CONTROLLED_SHUTDOWN: i16 = 7;
    pub const OFFSET_COMMIT: i16 = 8;
    pub const OFFSET_FETCH: i16 = 9;
    pub const FIND_COORDINATOR: i16 = 10;
    pub const JOIN_GROUP: i16 = 11;
    pub const HEARTBEAT: i16 = 12;
    pub const LEAVE_GROUP: i16 = 13;
    pub const SYNC_GROUP: i16 = 14;
    pub const DESCRIBE_GROUPS: i16 = 15;
    pub const LIST_GROUPS: i16 = 16;
    pub const SASL_HANDSHAKE: i16 = 17;
    pub const API_VERSIONS: i16 = 18;
    pub const CREATE_TOPICS: i16 = 19;
    pub const DELETE_TOPICS: i16 = 20;
    pub const INIT_PRODUCER_ID: i16 = 22;
    pub const SASL_AUTHENTICATE: i16 = 36;
}

/// Error codes a broker puts in responses. These are the ones a world
/// playing a broker needs most. Kafka defines many more.
pub mod error_code {
    #![allow(missing_docs)]
    pub const NONE: i16 = 0;
    pub const UNKNOWN_SERVER_ERROR: i16 = -1;
    pub const CORRUPT_MESSAGE: i16 = 2;
    pub const UNKNOWN_TOPIC_OR_PARTITION: i16 = 3;
    pub const LEADER_NOT_AVAILABLE: i16 = 5;
    pub const NOT_LEADER_OR_FOLLOWER: i16 = 6;
    pub const INVALID_TOPIC_EXCEPTION: i16 = 17;
    pub const TOPIC_AUTHORIZATION_FAILED: i16 = 29;
    pub const CLUSTER_AUTHORIZATION_FAILED: i16 = 31;
    pub const UNSUPPORTED_VERSION: i16 = 35;
    pub const INVALID_REQUEST: i16 = 42;
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
    /// A frame payload to write is longer than [`MAX_FRAME`].
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
    /// A body that does not match the API key and version it is written
    /// for.
    Mismatch,
    /// This many bytes were left after the last field.
    Trailing(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            Error::Mismatch => f.write_str("body does not match the API key and version"),
            Error::Trailing(n) => write!(f, "{n} bytes left after the last field"),
        }
    }
}

impl std::error::Error for Error {}

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
        std::str::from_utf8(b).map(str::to_owned).map_err(|_| Error::Utf8)
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

    /// BYTES: an INT32 length, then that many bytes.
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        self.nullable_bytes()?.ok_or(Error::Null)
    }

    /// NULLABLE_BYTES: BYTES, or length -1 for null.
    pub fn nullable_bytes(&mut self) -> Result<Option<&'a [u8]>, Error> {
        match self.i32()? {
            -1 => Ok(None),
            n if n < 0 => Err(Error::Length(n.into())),
            n => self.take(n as usize).map(Some),
        }
    }

    /// COMPACT_BYTES: an unsigned varint holding the length plus 1, then
    /// that many bytes.
    pub fn compact_bytes(&mut self) -> Result<&'a [u8], Error> {
        self.compact_nullable_bytes()?.ok_or(Error::Null)
    }

    /// COMPACT_NULLABLE_BYTES: COMPACT_BYTES, or 0 for null.
    pub fn compact_nullable_bytes(&mut self) -> Result<Option<&'a [u8]>, Error> {
        match self.uvarint()? {
            0 => Ok(None),
            n => self.take((n - 1) as usize).map(Some),
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
    /// tag, size and bytes. Tags must rise.
    pub fn tagged_fields(&mut self) -> Result<Vec<TaggedField>, Error> {
        let n = self.uvarint()? as usize;
        if n > MAX_TAGGED_FIELDS || n > self.remaining() {
            return Err(Error::Length(n as i64));
        }
        let mut out: Vec<TaggedField> = Vec::new();
        for _ in 0..n {
            let tag = self.uvarint()?;
            if out.last().is_some_and(|last| tag <= last.tag) {
                return Err(Error::TagOrder(tag));
            }
            let size = self.uvarint()? as usize;
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

/// Writes Kafka's primitive types to a growing buffer. Strings longer than
/// [`MAX_STRING`] are cut at a character boundary, and byte strings and
/// tagged-field values longer than [`MAX_FRAME`] are cut, so what a
/// [`Reader`] reads back is what was written. An array count over
/// [`MAX_ARRAY`] is written as [`MAX_ARRAY`], so write at most that many
/// elements after one.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// A writer with nothing written.
    pub fn new() -> Writer {
        Writer::default()
    }

    /// The bytes written.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// How many bytes have been written.
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Bytes as they are, with no length.
    pub fn raw(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    /// A BOOLEAN.
    pub fn bool(&mut self, v: bool) {
        self.out.push(u8::from(v));
    }

    /// One unsigned byte.
    pub fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    /// An INT8.
    pub fn i8(&mut self, v: i8) {
        self.raw(&v.to_be_bytes());
    }

    /// An INT16.
    pub fn i16(&mut self, v: i16) {
        self.raw(&v.to_be_bytes());
    }

    /// A UINT16.
    pub fn u16(&mut self, v: u16) {
        self.raw(&v.to_be_bytes());
    }

    /// An INT32.
    pub fn i32(&mut self, v: i32) {
        self.raw(&v.to_be_bytes());
    }

    /// A UINT32.
    pub fn u32(&mut self, v: u32) {
        self.raw(&v.to_be_bytes());
    }

    /// An INT64.
    pub fn i64(&mut self, v: i64) {
        self.raw(&v.to_be_bytes());
    }

    /// A FLOAT64.
    pub fn f64(&mut self, v: f64) {
        self.raw(&v.to_be_bytes());
    }

    /// A UUID.
    pub fn uuid(&mut self, v: &[u8; 16]) {
        self.raw(v);
    }

    /// An UNSIGNED_VARINT, in the fewest bytes.
    pub fn uvarint(&mut self, mut v: u32) {
        while v >= 0x80 {
            self.out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        self.out.push(v as u8);
    }

    /// A VARINT.
    pub fn varint(&mut self, v: i32) {
        self.uvarint(((v << 1) ^ (v >> 31)) as u32);
    }

    /// A VARLONG.
    pub fn varlong(&mut self, v: i64) {
        let mut u = ((v << 1) ^ (v >> 63)) as u64;
        while u >= 0x80 {
            self.out.push((u as u8 & 0x7f) | 0x80);
            u >>= 7;
        }
        self.out.push(u as u8);
    }

    /// A STRING.
    pub fn string(&mut self, s: &str) {
        let s = cut(s);
        self.i16(s.len() as i16);
        self.raw(s.as_bytes());
    }

    /// A NULLABLE_STRING.
    pub fn nullable_string(&mut self, s: Option<&str>) {
        match s {
            Some(s) => self.string(s),
            None => self.i16(-1),
        }
    }

    /// A COMPACT_STRING.
    pub fn compact_string(&mut self, s: &str) {
        let s = cut(s);
        self.uvarint(s.len() as u32 + 1);
        self.raw(s.as_bytes());
    }

    /// A COMPACT_NULLABLE_STRING.
    pub fn compact_nullable_string(&mut self, s: Option<&str>) {
        match s {
            Some(s) => self.compact_string(s),
            None => self.uvarint(0),
        }
    }

    /// BYTES.
    pub fn bytes(&mut self, b: &[u8]) {
        let b = &b[..b.len().min(MAX_FRAME)];
        self.i32(b.len() as i32);
        self.raw(b);
    }

    /// NULLABLE_BYTES.
    pub fn nullable_bytes(&mut self, b: Option<&[u8]>) {
        match b {
            Some(b) => self.bytes(b),
            None => self.i32(-1),
        }
    }

    /// COMPACT_BYTES.
    pub fn compact_bytes(&mut self, b: &[u8]) {
        let b = &b[..b.len().min(MAX_FRAME)];
        self.uvarint(b.len() as u32 + 1);
        self.raw(b);
    }

    /// COMPACT_NULLABLE_BYTES.
    pub fn compact_nullable_bytes(&mut self, b: Option<&[u8]>) {
        match b {
            Some(b) => self.compact_bytes(b),
            None => self.uvarint(0),
        }
    }

    /// An ARRAY's element count, or `None` for a null array. A count over
    /// [`MAX_ARRAY`] is written as [`MAX_ARRAY`].
    pub fn array_len(&mut self, n: Option<usize>) {
        match n {
            Some(n) => self.i32(n.min(MAX_ARRAY) as i32),
            None => self.i32(-1),
        }
    }

    /// A COMPACT_ARRAY's element count, or `None` for a null array. A
    /// count over [`MAX_ARRAY`] is written as [`MAX_ARRAY`].
    pub fn compact_array_len(&mut self, n: Option<usize>) {
        match n {
            Some(n) => self.uvarint(n.min(MAX_ARRAY) as u32 + 1),
            None => self.uvarint(0),
        }
    }

    /// A tagged-field section. Fields are written in rising tag order, a
    /// repeated tag keeps only its first field, and fields past
    /// [`MAX_TAGGED_FIELDS`] are left out.
    pub fn tagged_fields(&mut self, fields: &[TaggedField]) {
        let mut sorted: Vec<&TaggedField> = fields.iter().collect();
        sorted.sort_by_key(|f| f.tag);
        sorted.dedup_by_key(|f| f.tag);
        sorted.truncate(MAX_TAGGED_FIELDS);
        self.uvarint(sorted.len() as u32);
        for f in sorted {
            let data = &f.data[..f.data.len().min(MAX_FRAME)];
            self.uvarint(f.tag);
            self.uvarint(data.len() as u32);
            self.raw(data);
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
        }
    }

    fn i32s(&mut self, flex: bool, v: &[i32]) {
        let v = capped(v);
        self.arr_f(flex, Some(v.len()));
        for &x in v {
            self.i32(x);
        }
    }
}

/// `s`, cut to at most [`MAX_STRING`] bytes at a character boundary.
fn cut(s: &str) -> &str {
    if s.len() <= MAX_STRING {
        return s;
    }
    let mut end = MAX_STRING;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// `v`, cut to at most [`MAX_ARRAY`] elements.
fn capped<T>(v: &[T]) -> &[T] {
    &v[..v.len().min(MAX_ARRAY)]
}

/// Reads the frame at the start of `b`: a 4-byte size, then the payload.
/// It returns `Ok(None)` if `b` holds only part of one, and otherwise the
/// payload and how many bytes of `b` the frame took. A size that is
/// negative or over `limit` is an error, known from the first 4 bytes.
pub fn parse_frame(b: &[u8], limit: usize) -> Result<Option<(&[u8], usize)>, Error> {
    let Some(head) = b.get(..SIZE_LEN) else { return Ok(None) };
    let size = i32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if size < 0 || size as usize > limit {
        return Err(Error::FrameSize(size));
    }
    let end = SIZE_LEN + size as usize;
    match b.get(SIZE_LEN..end) {
        Some(payload) => Ok(Some((payload, end))),
        None => Ok(None),
    }
}

/// A frame holding `payload`: its size, then its bytes. A payload longer
/// than [`MAX_FRAME`] is an error.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_FRAME {
        return Err(Error::TooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(SIZE_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as i32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// The correlation ID at the start of a response payload, so a client can
/// find the request it answers before reading the rest.
pub fn correlation_id(payload: &[u8]) -> Option<i32> {
    let b = payload.get(..4)?;
    Some(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Splits a Kafka byte stream into frame payloads. Feed it the bytes a
/// connection reads, in order, and take payloads out until it has none.
#[derive(Clone, Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small frames costs time in proportion to their bytes.
    start: usize,
    limit: usize,
    failed: Option<Error>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, which takes frames up to [`MAX_FRAME`].
    pub fn new() -> Decoder {
        Decoder::with_limit(MAX_FRAME)
    }

    /// A decoder that takes frames up to `limit` bytes, or [`MAX_FRAME`]
    /// if `limit` is higher.
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder { buf: Vec::new(), start: 0, limit: limit.min(MAX_FRAME), failed: None }
    }

    /// Adds bytes read from the connection. After an error the stream
    /// cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next whole frame's payload, if one has come. It returns `None`
    /// when it needs more bytes, and keeps returning the same error once
    /// the stream has broken. A decoder holds every byte fed and not yet
    /// taken out. Bytes already taken out are dropped by the next `feed`
    /// once they make up half the buffer.
    pub fn next_frame(&mut self) -> Option<Result<Vec<u8>, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match parse_frame(&self.buf[self.start..], self.limit) {
            Ok(Some((payload, used))) => {
                let payload = payload.to_vec();
                self.start += used;
                Some(Ok(payload))
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

    /// How many bytes are held, waiting for the rest of a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
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

    /// Writes the header in the version its API key and version call for.
    /// Fields that version does not have are left out.
    pub fn write(&self, w: &mut Writer) {
        let version = self.version();
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

    /// Writes the header in header version `version`, which is 0 or 1.
    /// Any other version is written as 1.
    pub fn write(&self, w: &mut Writer, version: u8) {
        w.i32(self.correlation_id);
        if version >= 1 {
            w.tagged_fields(&self.tagged_fields);
        }
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

    /// The body's bytes in version `version`. Fields the version does not
    /// have are left out.
    pub fn to_bytes(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::API_VERSIONS, version)?;
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
        Ok(w.into_bytes())
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
    /// and whether ZooKeeper migration is ready (3), unread.
    pub tagged_fields: Vec<TaggedField>,
}

impl ApiVersionsResponse {
    /// Reads the body of an ApiVersions response of version `version`.
    pub fn parse(body: &[u8], version: i16) -> Result<ApiVersionsResponse, Error> {
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
        Ok(ApiVersionsResponse { error_code, api_keys, throttle_time_ms, tagged_fields })
    }

    /// The body's bytes in version `version`.
    pub fn to_bytes(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::API_VERSIONS, version)?;
        let flex = version >= 3;
        let mut w = Writer::new();
        w.i16(self.error_code);
        let keys = capped(&self.api_keys);
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
        Ok(w.into_bytes())
    }
}

/// One topic a Metadata request asks about.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataRequestTopic {
    /// The topic's ID, from version 10. All zeros when asking by name.
    pub topic_id: [u8; 16],
    /// The topic's name. It may be null from version 10, when asking by
    /// ID. Before that a null is written as an empty name.
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

    /// The body's bytes in version `version`. Fields the version does not
    /// have are left out.
    pub fn to_bytes(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::METADATA, version)?;
        let flex = version >= 9;
        let mut w = Writer::new();
        match &self.topics {
            None if version == 0 => w.arr_f(flex, Some(0)),
            None => w.arr_f(flex, None),
            Some(topics) => {
                let topics = capped(topics);
                w.arr_f(flex, Some(topics.len()));
                for t in topics {
                    if version >= 10 {
                        w.uuid(&t.topic_id);
                        w.nstr_f(flex, t.name.as_deref());
                    } else {
                        w.str_f(flex, t.name.as_deref().unwrap_or(""));
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
        Ok(w.into_bytes())
    }
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
    /// for by an ID that does not exist. Before that a null is written as
    /// an empty name.
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
        Ok(out)
    }

    /// The body's bytes in version `version`. Fields the version does not
    /// have are left out.
    pub fn to_bytes(&self, version: i16) -> Result<Vec<u8>, Error> {
        check_version(api_key::METADATA, version)?;
        let flex = version >= 9;
        let mut w = Writer::new();
        if version >= 3 {
            w.i32(self.throttle_time_ms);
        }
        let brokers = capped(&self.brokers);
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
        let topics = capped(&self.topics);
        w.arr_f(flex, Some(topics.len()));
        for t in topics {
            w.i16(t.error_code);
            if version >= 12 {
                w.nstr_f(flex, t.name.as_deref());
            } else {
                w.str_f(flex, t.name.as_deref().unwrap_or(""));
            }
            if version >= 10 {
                w.uuid(&t.topic_id);
            }
            if version >= 1 {
                w.bool(t.is_internal);
            }
            let partitions = capped(&t.partitions);
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
        Ok(w.into_bytes())
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

impl Request {
    /// Reads a frame's payload as a request. The header says which body
    /// follows. A body this module reads in full must use every byte.
    pub fn parse(payload: &[u8]) -> Result<Request, Error> {
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

    /// The request's payload: header, then body. The body must match the
    /// header's API key and version: an [`RequestBody::Other`] for a key
    /// and version with a full body here, or a typed body for another, is
    /// [`Error::Mismatch`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let (key, version) = (self.header.api_key, self.header.api_version);
        let body = match &self.body {
            RequestBody::ApiVersions(b) if key == api_key::API_VERSIONS => b.to_bytes(version)?,
            RequestBody::Metadata(b) if key == api_key::METADATA => b.to_bytes(version)?,
            RequestBody::Other(b) if !has_body(key, version) => b.clone(),
            _ => return Err(Error::Mismatch),
        };
        let mut w = Writer::new();
        self.header.write(&mut w);
        w.raw(&body);
        Ok(w.into_bytes())
    }

    /// The request as a whole frame, size first.
    pub fn to_frame(&self) -> Result<Vec<u8>, Error> {
        frame(&self.to_bytes()?)
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
    /// of `api_key`. A body this module reads in full must use every byte.
    pub fn parse(payload: &[u8], api_key: i16, api_version: i16) -> Result<Response, Error> {
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

    /// The response's payload, as the answer to version `api_version` of
    /// `api_key`. The body must match, as for [`Request::to_bytes`].
    pub fn to_bytes(&self, api_key: i16, api_version: i16) -> Result<Vec<u8>, Error> {
        let body = match &self.body {
            ResponseBody::ApiVersions(b) if api_key == api_key::API_VERSIONS => b.to_bytes(api_version)?,
            ResponseBody::Metadata(b) if api_key == api_key::METADATA => b.to_bytes(api_version)?,
            ResponseBody::Other(b) if !has_body(api_key, api_version) => b.clone(),
            _ => return Err(Error::Mismatch),
        };
        let mut w = Writer::new();
        self.header.write(&mut w, response_header_version(api_key, api_version));
        w.raw(&body);
        Ok(w.into_bytes())
    }

    /// The response as a whole frame, size first.
    pub fn to_frame(&self, api_key: i16, api_version: i16) -> Result<Vec<u8>, Error> {
        frame(&self.to_bytes(api_key, api_version)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(tag: u32, data: &[u8]) -> TaggedField {
        TaggedField { tag, data: data.to_vec() }
    }

    fn uvarint_bytes(v: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.uvarint(v);
        w.into_bytes()
    }

    // Varint examples from the protocol guide, which follows Protocol
    // Buffers' encoding.

    #[test]
    fn varint_examples() {
        assert_eq!(uvarint_bytes(0), [0]);
        assert_eq!(uvarint_bytes(1), [1]);
        assert_eq!(uvarint_bytes(127), [0x7f]);
        assert_eq!(uvarint_bytes(128), [0x80, 0x01]);
        assert_eq!(uvarint_bytes(300), [0xac, 0x02]);
        assert_eq!(uvarint_bytes(u32::MAX), [0xff, 0xff, 0xff, 0xff, 0x0f]);
        // Zigzag: 0, -1, 1, -2 are 0, 1, 2, 3.
        for (v, z) in [(0, 0u8), (-1, 1), (1, 2), (-2, 3), (2147483647, 0xfe), (-2147483648, 0xff)] {
            let mut w = Writer::new();
            w.varint(v);
            let b = w.into_bytes();
            assert_eq!(b[0], z, "{v}");
            assert_eq!(Reader::new(&b).varint(), Ok(v));
        }
        for v in [0i64, -1, 1, i64::MAX, i64::MIN, 1 << 40, -(1 << 50)] {
            let mut w = Writer::new();
            w.varlong(v);
            let b = w.into_bytes();
            assert!(b.len() <= 10);
            let mut r = Reader::new(&b);
            assert_eq!(r.varlong(), Ok(v));
            assert_eq!(r.finish(), Ok(()));
        }
        for v in [0u32, 1, 127, 128, 16383, 16384, 1 << 21, 1 << 28, u32::MAX] {
            let b = uvarint_bytes(v);
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
        let mut w = Writer::new();
        w.bool(true);
        w.i8(-3);
        w.i16(-300);
        w.u16(65000);
        w.i32(-70000);
        w.u32(4_000_000_000);
        w.i64(-1 << 40);
        w.f64(1.5);
        w.uuid(&id);
        w.string("héllo");
        w.nullable_string(None);
        w.compact_string("kafka");
        w.compact_nullable_string(None);
        w.bytes(b"abc");
        w.nullable_bytes(None);
        w.compact_bytes(b"");
        w.compact_nullable_bytes(None);
        w.array_len(Some(0));
        w.array_len(None);
        w.compact_array_len(Some(0));
        w.compact_array_len(None);
        w.tagged_fields(&[tag(5, b"x"), tag(1, b"yz"), tag(5, b"dup")]);
        assert!(!w.is_empty());
        let b = w.into_bytes();
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
        // Sorted, and the repeated tag keeps its first field.
        assert_eq!(r.tagged_fields(), Ok(vec![tag(1, b"yz"), tag(5, b"x")]));
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.position(), b.len());
    }

    #[test]
    fn primitive_layouts() {
        let mut w = Writer::new();
        w.string("ab");
        w.compact_string("ab");
        w.compact_nullable_string(None);
        w.nullable_string(None);
        w.compact_array_len(Some(2));
        w.tagged_fields(&[tag(0, &[9])]);
        assert_eq!(w.into_bytes(), [0, 2, b'a', b'b', 3, b'a', b'b', 0, 0xff, 0xff, 3, 1, 0, 1, 9]);
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
        let mut w = Writer::new();
        w.uvarint(MAX_STRING as u32 + 2);
        assert_eq!(Reader::new(&w.into_bytes()).compact_string(), Err(Error::Length(MAX_STRING as i64 + 1)));
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
        let mut many = uvarint_bytes(MAX_TAGGED_FIELDS as u32 + 1);
        many.resize(5000, 0);
        assert_eq!(Reader::new(&many).tagged_fields(), Err(Error::Length(MAX_TAGGED_FIELDS as i64 + 1)));
        // Trailing bytes.
        let r = Reader::new(&[1, 2]);
        assert_eq!(r.finish(), Err(Error::Trailing(2)));
        assert_eq!(Reader::new(&[]).i64(), Err(Error::Truncated));
    }

    #[test]
    fn writers_cut_long_values() {
        // A long string is cut at a character boundary.
        let long = "é".repeat(MAX_STRING);
        let mut w = Writer::new();
        w.string(&long);
        w.compact_string(&long);
        let b = w.into_bytes();
        let mut r = Reader::new(&b);
        let s = r.string().unwrap();
        assert!(s.len() <= MAX_STRING && s.len() >= MAX_STRING - 1);
        assert_eq!(r.compact_string().unwrap(), s);
        assert_eq!(r.finish(), Ok(()));
        // Too many tagged fields.
        let fields: Vec<TaggedField> = (0..2000).map(|t| tag(t, b"")).collect();
        let mut w = Writer::new();
        w.tagged_fields(&fields);
        assert_eq!(Reader::new(&w.into_bytes()).tagged_fields().unwrap().len(), MAX_TAGGED_FIELDS);
        // An oversized array count.
        let mut w = Writer::new();
        w.array_len(Some(usize::MAX));
        assert_eq!(w.into_bytes(), (MAX_ARRAY as i32).to_be_bytes());
        let mut w = Writer::new();
        w.compact_array_len(Some(usize::MAX));
        assert_eq!(Reader::new(&w.into_bytes()).uvarint(), Ok(MAX_ARRAY as u32 + 1));
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
        let mut w = Writer::new();
        h0.write(&mut w);
        assert_eq!(w.into_bytes(), b0);
        // Version 2: a null client ID, then one tagged field.
        let b2 = [0, 3, 0, 12, 0, 0, 0, 2, 0xff, 0xff, 1, 0, 2, 0xaa, 0xbb];
        let h2 = RequestHeader::read(&mut Reader::new(&b2)).unwrap();
        assert_eq!(h2.client_id, None);
        assert_eq!(h2.tagged_fields, vec![tag(0, &[0xaa, 0xbb])]);
        let mut w = Writer::new();
        h2.write(&mut w);
        assert_eq!(w.into_bytes(), b2);
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
        let framed = req.to_frame().unwrap();
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
        let p = resp.to_bytes(18, 3).unwrap();
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
            let b = req.to_bytes(v).unwrap();
            let back = ApiVersionsRequest::parse(&b, v).unwrap();
            assert_eq!(back.to_bytes(v).unwrap(), b);
            if v == 0 {
                assert!(b.is_empty());
                assert_eq!(back, ApiVersionsRequest::default());
            }
            if v == 5 {
                assert_eq!(back, req);
            }
            let b = resp.to_bytes(v).unwrap();
            let back = ApiVersionsResponse::parse(&b, v).unwrap();
            assert_eq!(back.to_bytes(v).unwrap(), b);
            if v >= 3 {
                assert_eq!(back, resp);
            }
            for n in 0..b.len() {
                assert!(ApiVersionsResponse::parse(&b[..n], v).is_err(), "{v} {n}");
            }
        }
        assert_eq!(req.to_bytes(6), Err(Error::UnsupportedVersion { api_key: 18, api_version: 6 }));
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
        // Version 0 has no null array, and writes None as every topic.
        assert_eq!(MetadataRequest::parse(&[0xff, 0xff, 0xff, 0xff], 0), Err(Error::Null));
        assert_eq!(MetadataRequest::default().to_bytes(0).unwrap(), [0, 0, 0, 0]);
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
        assert_eq!(m9.to_bytes(9).unwrap(), b9);
        // Version 10 asks by ID with a null name.
        let mut b10 = vec![2];
        b10.extend_from_slice(&[0x11; 16]);
        b10.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
        let m10 = MetadataRequest::parse(&b10, 10).unwrap();
        let t = &m10.topics.as_ref().unwrap()[0];
        assert_eq!((t.topic_id, t.name.clone()), ([0x11; 16], None));
        assert_eq!(m10.to_bytes(10).unwrap(), b10);
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
        let b = m.to_bytes(0).unwrap();
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
        assert_eq!(back.to_bytes(0).unwrap(), b);
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
            let b = m.to_bytes(v).unwrap();
            let back = MetadataResponse::parse(&b, v).unwrap();
            assert_eq!(back.to_bytes(v).unwrap(), b, "{v}");
            assert_eq!(MetadataResponse::parse(&back.to_bytes(v).unwrap(), v).unwrap(), back);
            if v == 10 {
                assert_eq!(back, m, "{v}");
            }
            for n in 0..b.len() {
                assert!(MetadataResponse::parse(&b[..n], v).is_err(), "{v} {n}");
            }
            let b = req.to_bytes(v).unwrap();
            let back = MetadataRequest::parse(&b, v).unwrap();
            assert_eq!(back.to_bytes(v).unwrap(), b, "{v}");
            if v == 10 {
                assert_eq!(back, req);
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
                body: ResponseBody::Metadata(MetadataResponse::parse(&m.to_bytes(v).unwrap(), v).unwrap()),
            };
            assert_eq!(Response::parse(&resp.to_bytes(3, v).unwrap(), 3, v).unwrap(), resp);
        }
        // Version 12 and later carry a null topic name; earlier versions
        // write it as empty.
        let mut nameless = m.clone();
        nameless.topics[0].name = None;
        let b = nameless.to_bytes(12).unwrap();
        assert_eq!(MetadataResponse::parse(&b, 12).unwrap().topics[0].name, None);
        let b = nameless.to_bytes(11).unwrap();
        assert_eq!(MetadataResponse::parse(&b, 11).unwrap().topics[0].name.as_deref(), Some(""));
        assert_eq!(m.to_bytes(14), Err(Error::UnsupportedVersion { api_key: 3, api_version: 14 }));
        // Version 13's top-level error code is last, after the topics.
        let mut failed = MetadataResponse { error_code: 29, ..MetadataResponse::default() };
        failed.tagged_fields.clear();
        assert_eq!(failed.to_bytes(13).unwrap(), [0, 0, 0, 0, 1, 0, 0xff, 0xff, 0xff, 0xff, 1, 0, 29, 0]);
    }

    #[test]
    fn mismatched_bodies() {
        let header = RequestHeader { api_key: 3, api_version: 1, ..Default::default() };
        let req = Request { header: header.clone(), body: RequestBody::ApiVersions(ApiVersionsRequest::default()) };
        assert_eq!(req.to_bytes(), Err(Error::Mismatch));
        let req = Request { header: header.clone(), body: RequestBody::Other(vec![]) };
        assert_eq!(req.to_bytes(), Err(Error::Mismatch));
        // A version with no full body is an Other.
        let header = RequestHeader { api_key: 3, api_version: 99, ..Default::default() };
        let req = Request { header: header.clone(), body: RequestBody::Metadata(MetadataRequest::default()) };
        assert_eq!(req.to_bytes(), Err(Error::UnsupportedVersion { api_key: 3, api_version: 99 }));
        let req = Request { header, body: RequestBody::Other(vec![1, 2, 3]) };
        let back = Request::parse(&req.to_bytes().unwrap()).unwrap();
        assert_eq!(back, req);
        let resp = Response { header: ResponseHeader::default(), body: ResponseBody::Other(vec![]) };
        assert_eq!(resp.to_bytes(18, 0), Err(Error::Mismatch));
        assert_eq!(Response::parse(&resp.to_bytes(0, 9).unwrap(), 0, 9).unwrap(), resp);
        let resp =
            Response { header: ResponseHeader::default(), body: ResponseBody::Metadata(MetadataResponse::default()) };
        assert_eq!(resp.to_bytes(18, 0), Err(Error::Mismatch));
    }

    #[test]
    fn frames() {
        let f = frame(&[1, 2, 3]).unwrap();
        assert_eq!(f, [0, 0, 0, 3, 1, 2, 3]);
        assert_eq!(parse_frame(&f, MAX_FRAME), Ok(Some((&[1u8, 2, 3][..], 7))));
        for n in 0..f.len() {
            assert_eq!(parse_frame(&f[..n], MAX_FRAME), Ok(None), "{n}");
        }
        assert_eq!(parse_frame(&[0, 0, 0, 0], MAX_FRAME), Ok(Some((&[][..], 4))));
        assert_eq!(parse_frame(&[0xff, 0xff, 0xff, 0xff], MAX_FRAME), Err(Error::FrameSize(-1)));
        assert_eq!(parse_frame(&[0, 0, 0, 4], 3), Err(Error::FrameSize(4)));
        assert_eq!(parse_frame(&[0x7f, 0xff, 0xff, 0xff], MAX_FRAME), Err(Error::FrameSize(i32::MAX)));
        assert_eq!(frame(&vec![0; MAX_FRAME + 1]), Err(Error::TooLarge(MAX_FRAME + 1)));
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = frame(&api_versions_v3_request()).unwrap();
        let b = frame(&[0, 18, 0, 0, 0, 0, 0, 2, 0xff, 0xff]).unwrap();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(p) = d.next_frame() {
                got.push(Request::parse(&p.unwrap()).unwrap().header.correlation_id);
            }
        }
        assert_eq!(got, [5, 2]);
        assert_eq!(d.buffered(), 0);
        // A copy taken in the middle of a frame goes on the same way.
        d.feed(&b[..3]);
        let mut copy = d.clone();
        d.feed(&b[3..]);
        copy.feed(&b[3..]);
        assert_eq!(d.next_frame(), copy.next_frame());
        // A broken stream stays broken.
        d.feed(&[0x80, 0, 0, 0]);
        assert_eq!(d.next_frame(), Some(Err(Error::FrameSize(i32::MIN))));
        d.feed(&a);
        assert_eq!(d.next_frame(), Some(Err(Error::FrameSize(i32::MIN))));
        assert_eq!(d.buffered(), 0);
        // A lower limit.
        let mut d = Decoder::with_limit(4);
        d.feed(&[0, 0, 0, 5]);
        assert_eq!(d.next_frame(), Some(Err(Error::FrameSize(5))));
        let mut d = Decoder::with_limit(usize::MAX);
        d.feed(&[0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(d.next_frame(), Some(Err(Error::FrameSize(i32::MAX))));
    }

    #[test]
    fn decoder_takes_many_small_frames_in_linear_time() {
        let one = frame(&[0, 18, 0, 0, 0, 0, 0, 1, 0xff, 0xff]).unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::default();
        d.feed(&stream);
        let mut n = 0;
        while let Some(p) = d.next_frame() {
            p.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
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
            Error::Mismatch,
            Error::Trailing(1),
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

    /// A deterministic generator, so a failure repeats.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
    }

    /// What the fuzz target checks, for one buffer.
    fn check(data: &[u8]) {
        let mut whole = Decoder::new();
        whole.feed(data);
        let mut frames = Vec::new();
        while let Some(Ok(f)) = whole.next_frame() {
            frames.push(f);
        }
        let mut bytewise = Decoder::new();
        let mut again = Vec::new();
        for b in data {
            bytewise.feed(std::slice::from_ref(b));
            while let Some(Ok(f)) = bytewise.next_frame() {
                again.push(f);
            }
        }
        assert_eq!(frames, again);
        let mut payloads: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        payloads.push(data);
        for p in payloads {
            if let Ok(req) = Request::parse(p) {
                let bytes = req.to_bytes().unwrap();
                assert_eq!(Request::parse(&bytes), Ok(req));
            }
            for key in [api_key::API_VERSIONS, api_key::METADATA, api_key::PRODUCE] {
                for version in [0, 1, 3, 5, 8, 9, 10, 12, 13] {
                    if let Ok(resp) = Response::parse(p, key, version) {
                        let bytes = resp.to_bytes(key, version).unwrap();
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
        let mut rng = Lcg(0x6b_6166_6b61);
        // Valid encodings to mutate, so the fuzz reaches deep fields.
        let m = sample_metadata();
        let mut seeds: Vec<Vec<u8>> = vec![frame(&api_versions_v3_request()).unwrap()];
        for v in 0..=METADATA_MAX_VERSION {
            let resp = Response { header: ResponseHeader::default(), body: ResponseBody::Metadata(m.clone()) };
            seeds.push(frame(&resp.to_bytes(3, v).unwrap()).unwrap());
            let req = Request {
                header: RequestHeader {
                    api_key: 3,
                    api_version: v,
                    correlation_id: 1,
                    client_id: Some("c".into()),
                    tagged_fields: vec![],
                },
                body: RequestBody::Metadata(MetadataRequest {
                    topics: Some(vec![MetadataRequestTopic::default()]),
                    ..Default::default()
                }),
            };
            seeds.push(frame(&req.to_bytes().unwrap()).unwrap());
        }
        for _ in 0..4000 {
            let data: Vec<u8> = if rng.below(2) == 0 {
                let len = rng.below(64) as usize;
                let mut d: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                // Often a frame size that fits.
                if len >= 4 && rng.below(2) == 0 {
                    d[..4].copy_from_slice(&((len - 4) as i32).to_be_bytes());
                }
                d
            } else {
                let mut d = seeds[rng.below(seeds.len() as u32) as usize].clone();
                for _ in 0..1 + rng.below(4) {
                    let i = rng.below(d.len() as u32) as usize;
                    match rng.below(3) {
                        0 => d[i] = rng.next() as u8,
                        1 => d[i] ^= 1 << rng.below(8),
                        _ => d.truncate(i.max(4)),
                    }
                }
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
        match rng.below(6) {
            0 => String::new(),
            // Over the limit, with a two-byte character at the cut.
            1 => "\u{e9}".repeat(MAX_STRING / 2 + 1 + rng.below(3) as usize),
            _ => (0..rng.below(8)).map(|_| char::from(b'a' + rng.below(26) as u8)).collect(),
        }
    }

    fn any_option(rng: &mut Lcg) -> Option<String> {
        if rng.below(3) == 0 { None } else { Some(any_string(rng)) }
    }

    fn any_tags(rng: &mut Lcg) -> Vec<TaggedField> {
        // Out of order and repeated tags too.
        (0..rng.below(4)).map(|_| tag(rng.below(5), &vec![rng.next() as u8; rng.below(3) as usize])).collect()
    }

    fn any_i32s(rng: &mut Lcg) -> Vec<i32> {
        (0..rng.below(4)).map(|_| rng.next() as i32).collect()
    }

    fn any_metadata_response(rng: &mut Lcg) -> MetadataResponse {
        MetadataResponse {
            throttle_time_ms: rng.next() as i32,
            brokers: (0..rng.below(3))
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
            topics: (0..rng.below(3))
                .map(|_| MetadataTopic {
                    error_code: rng.next() as i16,
                    name: any_option(rng),
                    topic_id: [rng.next() as u8; 16],
                    is_internal: rng.below(2) == 0,
                    partitions: (0..rng.below(3))
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

    fn any_metadata_request(rng: &mut Lcg) -> MetadataRequest {
        MetadataRequest {
            topics: if rng.below(3) == 0 {
                None
            } else {
                Some(
                    (0..rng.below(3))
                        .map(|_| MetadataRequestTopic {
                            topic_id: [rng.next() as u8; 16],
                            name: any_option(rng),
                            tagged_fields: any_tags(rng),
                        })
                        .collect(),
                )
            },
            allow_auto_topic_creation: rng.below(2) == 0,
            include_cluster_authorized_operations: rng.below(2) == 0,
            include_topic_authorized_operations: rng.below(2) == 0,
            tagged_fields: any_tags(rng),
        }
    }

    #[test]
    fn writers_always_make_what_readers_take() {
        let mut rng = Lcg(0x77_7269_7465);
        for _ in 0..300 {
            let header = RequestHeader {
                api_key: [api_key::API_VERSIONS, api_key::METADATA, api_key::CONTROLLED_SHUTDOWN, 500]
                    [rng.below(4) as usize],
                api_version: rng.below(16) as i16 - 1,
                correlation_id: rng.next() as i32,
                client_id: any_option(&mut rng),
                tagged_fields: any_tags(&mut rng),
            };
            let (key, version) = (header.api_key, header.api_version);
            let body = if !has_body(key, version) {
                RequestBody::Other((0..rng.below(5)).map(|_| rng.next() as u8).collect())
            } else if key == api_key::API_VERSIONS {
                RequestBody::ApiVersions(ApiVersionsRequest {
                    client_software_name: any_string(&mut rng),
                    client_software_version: any_string(&mut rng),
                    cluster_id: any_option(&mut rng),
                    node_id: rng.next() as i32,
                    tagged_fields: any_tags(&mut rng),
                })
            } else {
                RequestBody::Metadata(any_metadata_request(&mut rng))
            };
            let req = Request { header, body };
            let bytes = req.to_bytes().unwrap();
            let back = Request::parse(&bytes).unwrap();
            assert_eq!(back.to_bytes().unwrap(), bytes);
            let mut d = Decoder::new();
            d.feed(&req.to_frame().unwrap());
            assert_eq!(d.next_frame(), Some(Ok(bytes)));

            let rbody = if !has_body(key, version) {
                ResponseBody::Other((0..rng.below(5)).map(|_| rng.next() as u8).collect())
            } else if key == api_key::API_VERSIONS {
                ResponseBody::ApiVersions(ApiVersionsResponse {
                    error_code: rng.next() as i16,
                    api_keys: (0..rng.below(4))
                        .map(|_| ApiVersion {
                            api_key: rng.next() as i16,
                            min_version: rng.next() as i16,
                            max_version: rng.next() as i16,
                            tagged_fields: any_tags(&mut rng),
                        })
                        .collect(),
                    throttle_time_ms: rng.next() as i32,
                    tagged_fields: any_tags(&mut rng),
                })
            } else {
                ResponseBody::Metadata(any_metadata_response(&mut rng))
            };
            let resp = Response {
                header: ResponseHeader { correlation_id: 1, tagged_fields: any_tags(&mut rng) },
                body: rbody,
            };
            let bytes = resp.to_bytes(key, version).unwrap();
            let back = Response::parse(&bytes, key, version).unwrap();
            assert_eq!(back.to_bytes(key, version).unwrap(), bytes);
            assert_eq!(Response::parse(&bytes, key, version), Ok(back));
        }
    }
}
