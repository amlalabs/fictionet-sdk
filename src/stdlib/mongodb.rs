//! MongoDB: reading and writing BSON documents and wire protocol messages,
//! with no I/O.
//!
//! A MongoDB client talks to a server over TCP, usually on port 27017. Each
//! message starts with a 16-byte header that gives its length, its request
//! ID, the request it answers, and its op code. Clients send commands as
//! OP_MSG messages, which carry BSON documents: a command such as
//! `{ find: "users", filter: { name: "ada" }, $db: "app" }` goes out, and a
//! document such as `{ cursor: {...}, ok: 1.0 }` comes back. A client may
//! open a connection with the legacy OP_QUERY handshake, which a server
//! answers with an OP_REPLY. This module follows the MongoDB Wire Protocol
//! reference and the BSON 1.1 specification at bsonspec.org.
//!
//! A world that plays a database server passes bytes from a
//! [`tcp`](fictionet::stdlib::tcp) connection to
//! [`Stream<Frames>`](fictionet::stdlib::codec::Stream), reads each message's command document,
//! and writes the reply's bytes back to the connection. Which databases
//! and collections exist, and what they hold, is up to world code.
//!
//! Every reader checks lengths, nesting and sizes, because the agent can
//! send any bytes it likes. Documents nest at most [`MAX_DEPTH`] deep and
//! hold at most [`MAX_DOCUMENT_SIZE`] bytes ([`MAX_COMMAND_SIZE`] for a
//! command or reply document in a message), and a message holds at most
//! [`MAX_MESSAGE_SIZE`] bytes. The stream holds at most one message's
//! bytes. OP_MSG checksums (CRC-32C) are checked and
//! written. Compressed messages (OP_COMPRESSED) are reported with their
//! compressor and bytes, not decompressed. Every writer checks the same
//! limits, so what it writes always reads back.
//!
//! ```
//! use fictionet::stdlib::mongodb::{Body, Bson, Frames, Document, Message, Msg, Reply};
//! use fictionet::stdlib::codec::{Stream, Wire};
//!
//! /// Answers the handshake and `ping`, and nothing else.
//! fn answer(request: &Message, next_id: i32) -> Message {
//!     let ok = Document::new().with("ok", Bson::Double(1.0));
//!     let body = match &request.body {
//!         Body::Query(q) if q.collection == "admin.$cmd" => {
//!             let hello = ok.with("isWritablePrimary", Bson::Boolean(true)).with("maxWireVersion", Bson::Int32(21));
//!             Body::Reply(Reply::new(vec![hello]))
//!         }
//!         Body::Msg(m) if m.body.get("ping").is_some() => Body::Msg(Msg::new(ok)),
//!         _ => {
//!             let error = Document::new()
//!                 .with("ok", Bson::Double(0.0))
//!                 .with("errmsg", Bson::String("no such command".into()));
//!             Body::Msg(Msg::new(error))
//!         }
//!     };
//!     request.reply(next_id, body)
//! }
//!
//! // A client's ping, as its bytes come off the connection.
//! let ping = Document::new().with("ping", Bson::Int32(1)).with("$db", Bson::String("admin".into()));
//! let bytes = Message { request_id: 7, response_to: 0, body: Body::Msg(Msg::new(ping)) }.to_bytes().unwrap();
//! // The header, the flag bits, a section kind byte and a 30-byte document.
//! assert_eq!(bytes.len(), 16 + 4 + 1 + 30);
//! assert_eq!(bytes[12..16], [0xdd, 0x07, 0, 0]); // op code 2013, OP_MSG
//!
//! let mut stream = Stream::new(Frames::new());
//! for b in &bytes {
//!     assert_eq!(stream.push(std::slice::from_ref(b)), 1);
//! }
//! let request = stream.next().unwrap().unwrap().unwrap();
//! let reply = answer(&request, 1);
//! assert_eq!(reply.response_to, 7);
//!
//! let out = reply.to_bytes().unwrap();
//! let back = Message::parse(&out).unwrap();
//! let Body::Msg(m) = back.body else { panic!("not an OP_MSG") };
//! assert_eq!(m.body.get("ok"), Some(&Bson::Double(1.0)));
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The TCP port MongoDB servers listen on.
pub const PORT: u16 = 27017;
/// The length of the message header: length, request ID, response-to ID
/// and op code, each a 4-byte little-endian integer.
pub const HEADER_LEN: usize = 16;
/// The longest message, header included. This is the `maxMessageSizeBytes`
/// a server reports in its handshake reply.
pub const MAX_MESSAGE_SIZE: usize = 48_000_000;
/// The largest BSON document. This is the `maxBsonObjectSize` a server
/// reports in its handshake reply. [`Document::parse`] and
/// [`Document::to_bytes`] hold documents to it, and so do messages for each
/// document of an OP_MSG document sequence.
pub const MAX_DOCUMENT_SIZE: usize = 16 * 1024 * 1024;
/// The largest command document: an OP_MSG body, an OP_QUERY's query and
/// fields, and each OP_REPLY document. It is [`MAX_DOCUMENT_SIZE`] plus
/// 16 KiB, as on a MongoDB server, so that a reply can carry a document of
/// the full size inside its cursor and other fields. Documents nested in a
/// command document are held to the same limit.
pub const MAX_COMMAND_SIZE: usize = MAX_DOCUMENT_SIZE + 16 * 1024;
/// How deep documents may nest. A top-level document is depth 1, and each
/// embedded document, array or JavaScript scope adds 1.
pub const MAX_DEPTH: usize = 100;
/// The most elements one document, or all the documents of one message,
/// may hold, nested elements included. It bounds the memory a parse takes.
pub const MAX_ELEMENTS: usize = 1_000_000;
/// The most documents one OP_MSG document sequence, or one OP_REPLY, may
/// carry. This is the `maxWriteBatchSize` a server reports. All the
/// sequences of one OP_MSG together may carry twice as many, room for a
/// `bulkWrite` with a full batch in `ops` and a namespace for each in
/// `nsInfo`.
pub const MAX_DOCUMENTS: usize = 100_000;
/// The most document sequences one OP_MSG may carry. Clients send one or
/// two, such as `ops` and `nsInfo` for a `bulkWrite`.
pub const MAX_SEQUENCES: usize = 64;

/// Op codes, the header's last field, which says what the message is.
pub mod op_code {
    /// A reply to an OP_QUERY. Legacy, kept for the handshake.
    pub const REPLY: i32 = 1;
    /// A legacy update, removed in MongoDB 5.1.
    pub const UPDATE: i32 = 2001;
    /// A legacy insert, removed in MongoDB 5.1.
    pub const INSERT: i32 = 2002;
    /// A query. Legacy, kept for the handshake.
    pub const QUERY: i32 = 2004;
    /// A legacy request for more cursor results, removed in MongoDB 5.1.
    pub const GET_MORE: i32 = 2005;
    /// A legacy delete, removed in MongoDB 5.1.
    pub const DELETE: i32 = 2006;
    /// A legacy request to close cursors, removed in MongoDB 5.1.
    pub const KILL_CURSORS: i32 = 2007;
    /// Another message, compressed.
    pub const COMPRESSED: i32 = 2012;
    /// A command or its reply: the message every current client sends.
    pub const MSG: i32 = 2013;
}

/// OP_MSG flag bits. Bits 0 to 15 are required: a reader must refuse a
/// message with one it does not know. Bits 16 to 31 are optional: a reader
/// ignores the ones it does not know and drops them from [`Msg::flags`],
/// and a writer refuses any bit not in [`KNOWN`](flag::KNOWN), since a sender must set
/// unused bits to 0.
pub mod flag {
    /// The message ends with a CRC-32C checksum.
    pub const CHECKSUM_PRESENT: u32 = 1 << 0;
    /// Another message follows without a request for it.
    pub const MORE_TO_COME: u32 = 1 << 1;
    /// The client can take several replies to one request.
    pub const EXHAUST_ALLOWED: u32 = 1 << 16;
    /// The required bits, 0 to 15.
    pub const REQUIRED: u32 = 0xffff;
    /// Every bit this module knows.
    pub const KNOWN: u32 = CHECKSUM_PRESENT | MORE_TO_COME | EXHAUST_ALLOWED;
}

/// The type bytes of BSON elements.
pub mod element_type {
    /// BSON double type.
    pub const DOUBLE: u8 = 0x01;
    /// BSON string type.
    pub const STRING: u8 = 0x02;
    /// BSON document type.
    pub const DOCUMENT: u8 = 0x03;
    /// BSON array type.
    pub const ARRAY: u8 = 0x04;
    /// BSON binary type.
    pub const BINARY: u8 = 0x05;
    /// BSON undefined type.
    pub const UNDEFINED: u8 = 0x06;
    /// BSON object id type.
    pub const OBJECT_ID: u8 = 0x07;
    /// BSON boolean type.
    pub const BOOLEAN: u8 = 0x08;
    /// BSON date time type.
    pub const DATE_TIME: u8 = 0x09;
    /// BSON null type.
    pub const NULL: u8 = 0x0a;
    /// BSON regex type.
    pub const REGEX: u8 = 0x0b;
    /// BSON db pointer type.
    pub const DB_POINTER: u8 = 0x0c;
    /// BSON javascript type.
    pub const JAVASCRIPT: u8 = 0x0d;
    /// BSON symbol type.
    pub const SYMBOL: u8 = 0x0e;
    /// BSON javascript with scope type.
    pub const JAVASCRIPT_WITH_SCOPE: u8 = 0x0f;
    /// BSON int32 type.
    pub const INT32: u8 = 0x10;
    /// BSON timestamp type.
    pub const TIMESTAMP: u8 = 0x11;
    /// BSON int64 type.
    pub const INT64: u8 = 0x12;
    /// BSON decimal128 type.
    pub const DECIMAL128: u8 = 0x13;
    /// BSON min key type.
    pub const MIN_KEY: u8 = 0xff;
    /// BSON max key type.
    pub const MAX_KEY: u8 = 0x7f;
}

/// Compressor IDs an OP_COMPRESSED message may name.
pub mod compressor {
    /// No compression: the bytes are the message as is.
    pub const NOOP: u8 = 0;
    /// Snappy.
    pub const SNAPPY: u8 = 1;
    /// zlib.
    pub const ZLIB: u8 = 2;
    /// Zstandard.
    pub const ZSTD: u8 = 3;
}

/// One BSON value.
///
/// Values compare exactly: doubles compare by their bits, so a NaN equals
/// the same NaN, and 0.0 and -0.0 differ.
#[derive(Clone, Debug)]
pub enum Bson {
    /// A 64-bit IEEE 754 float.
    Double(f64),
    /// A UTF-8 string. It may hold zero bytes.
    String(String),
    /// An embedded document.
    Document(Document),
    /// An array. On the wire it is a document whose keys are "0", "1" and
    /// so on, in order. A reader refuses any other keys, and a writer
    /// writes them.
    Array(Vec<Bson>),
    /// Binary data and its subtype (0 for generic, 4 for a UUID, and so on).
    /// Under the old subtype 2, the bytes must start with a 4-byte
    /// little-endian length that counts the bytes after it.
    Binary {
        /// The subtype byte.
        subtype: u8,
        /// The bytes.
        bytes: Vec<u8>,
    },
    /// Undefined. A historical BSON wire type.
    Undefined,
    /// A 12-byte ObjectId.
    ObjectId([u8; 12]),
    /// A boolean.
    Boolean(bool),
    /// A UTC time, in milliseconds since the Unix epoch.
    DateTime(i64),
    /// Null.
    Null,
    /// A regular expression. Neither part may hold a zero byte, and the
    /// options must be in alphabetical order, each at most once.
    Regex {
        /// The pattern.
        pattern: String,
        /// The options, such as "i" or "ms".
        options: String,
    },
    /// A reference to a document in another collection. A historical BSON wire type.
    DbPointer {
        /// The collection's namespace.
        namespace: String,
        /// The document's ObjectId.
        id: [u8; 12],
    },
    /// JavaScript code.
    JavaScript(String),
    /// A symbol. A historical BSON wire type.
    Symbol(String),
    /// JavaScript code and the variables in scope for it. A historical BSON wire type.
    JavaScriptWithScope {
        /// The code.
        code: String,
        /// The variables.
        scope: Document,
    },
    /// A 32-bit integer.
    Int32(i32),
    /// A replication timestamp. On the wire it is one 64-bit integer, the
    /// time in its high half.
    Timestamp {
        /// Seconds since the Unix epoch.
        time: u32,
        /// An ordinal among operations in the same second.
        increment: u32,
    },
    /// A 64-bit integer.
    Int64(i64),
    /// A 128-bit IEEE 754 decimal, as its 16 little-endian bytes.
    Decimal128([u8; 16]),
    /// Compares lower than every other value.
    MinKey,
    /// Compares higher than every other value.
    MaxKey,
}

impl PartialEq for Bson {
    fn eq(&self, other: &Bson) -> bool {
        match (self, other) {
            (Bson::Double(a), Bson::Double(b)) => a.to_bits() == b.to_bits(),
            (Bson::String(a), Bson::String(b))
            | (Bson::JavaScript(a), Bson::JavaScript(b))
            | (Bson::Symbol(a), Bson::Symbol(b)) => a == b,
            (Bson::Document(a), Bson::Document(b)) => a == b,
            (Bson::Array(a), Bson::Array(b)) => a == b,
            (Bson::Binary { subtype: s, bytes: a }, Bson::Binary { subtype: t, bytes: b }) => s == t && a == b,
            (Bson::Undefined, Bson::Undefined)
            | (Bson::Null, Bson::Null)
            | (Bson::MinKey, Bson::MinKey)
            | (Bson::MaxKey, Bson::MaxKey) => true,
            (Bson::ObjectId(a), Bson::ObjectId(b)) => a == b,
            (Bson::Boolean(a), Bson::Boolean(b)) => a == b,
            (Bson::DateTime(a), Bson::DateTime(b)) | (Bson::Int64(a), Bson::Int64(b)) => a == b,
            (Bson::Regex { pattern: p, options: o }, Bson::Regex { pattern: q, options: r }) => p == q && o == r,
            (Bson::DbPointer { namespace: n, id: a }, Bson::DbPointer { namespace: m, id: b }) => n == m && a == b,
            (Bson::JavaScriptWithScope { code: c, scope: s }, Bson::JavaScriptWithScope { code: d, scope: t }) => {
                c == d && s == t
            }
            (Bson::Int32(a), Bson::Int32(b)) => a == b,
            (Bson::Timestamp { time: t, increment: i }, Bson::Timestamp { time: u, increment: j }) => t == u && i == j,
            (Bson::Decimal128(a), Bson::Decimal128(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Bson {}

impl Bson {
    /// The type byte this value is written with.
    pub fn element_type(&self) -> u8 {
        use element_type as t;
        match self {
            Bson::Double(_) => t::DOUBLE,
            Bson::String(_) => t::STRING,
            Bson::Document(_) => t::DOCUMENT,
            Bson::Array(_) => t::ARRAY,
            Bson::Binary { .. } => t::BINARY,
            Bson::Undefined => t::UNDEFINED,
            Bson::ObjectId(_) => t::OBJECT_ID,
            Bson::Boolean(_) => t::BOOLEAN,
            Bson::DateTime(_) => t::DATE_TIME,
            Bson::Null => t::NULL,
            Bson::Regex { .. } => t::REGEX,
            Bson::DbPointer { .. } => t::DB_POINTER,
            Bson::JavaScript(_) => t::JAVASCRIPT,
            Bson::Symbol(_) => t::SYMBOL,
            Bson::JavaScriptWithScope { .. } => t::JAVASCRIPT_WITH_SCOPE,
            Bson::Int32(_) => t::INT32,
            Bson::Timestamp { .. } => t::TIMESTAMP,
            Bson::Int64(_) => t::INT64,
            Bson::Decimal128(_) => t::DECIMAL128,
            Bson::MinKey => t::MIN_KEY,
            Bson::MaxKey => t::MAX_KEY,
        }
    }

    /// The text of a [`Bson::String`], or `None` for any other value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Bson::String(s) => Some(s),
            _ => None,
        }
    }

    /// The value of a [`Bson::Int32`], or `None` for any other value.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Bson::Int32(v) => Some(*v),
            _ => None,
        }
    }

    /// The value of a [`Bson::Int64`], or `None` for any other value.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Bson::Int64(v) => Some(*v),
            _ => None,
        }
    }

    /// The value of a [`Bson::Double`], or `None` for any other value.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Bson::Double(v) => Some(*v),
            _ => None,
        }
    }

    /// The value of a [`Bson::Boolean`], or `None` for any other value.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Bson::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    /// The document of a [`Bson::Document`], or `None` for any other value.
    pub fn as_document(&self) -> Option<&Document> {
        match self {
            Bson::Document(d) => Some(d),
            _ => None,
        }
    }

    /// The values of a [`Bson::Array`], or `None` for any other value.
    pub fn as_array(&self) -> Option<&[Bson]> {
        match self {
            Bson::Array(v) => Some(v),
            _ => None,
        }
    }
}

/// A BSON document: keys and values, in the order they were written. Keys
/// may repeat, as they may on the wire. A key may not hold a zero byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document(
    /// Elements in wire order.
    pub Vec<(String, Bson)>,
);

/// Why bytes are not a BSON document, or why a document cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BsonError {
    /// A length or a value runs past the bytes there are.
    Truncated,
    /// Bytes remain after the document.
    Trailing,
    /// A length field is out of range: a document under 5 bytes or over
    /// its limit ([`MAX_DOCUMENT_SIZE`], or [`MAX_COMMAND_SIZE`] for a
    /// command document in a message), a string under 1 byte, a negative binary
    /// length, or a JavaScript-with-scope length that does not match what
    /// it holds.
    Length(i32),
    /// A document or string does not end with a zero byte, a key or regex
    /// part has none, or a document's elements end before its length says.
    Terminator,
    /// An element type this module does not know.
    Type(u8),
    /// A string, key or regex part is not UTF-8.
    Utf8,
    /// A boolean byte other than 0 or 1.
    Bool(u8),
    /// Documents nest deeper than [`MAX_DEPTH`].
    Depth,
    /// More elements than [`MAX_ELEMENTS`].
    TooManyElements,
    /// The value cannot be written without changing it.
    Unwritable,
    /// An array's keys are not "0", "1", "2" and so on, in order.
    ArrayKey,
    /// Binary data of the old subtype 2 does not start with a 4-byte
    /// length that counts the bytes after it.
    OldBinary,
    /// Regex options are not in alphabetical order, or one repeats.
    RegexOptions,
}

impl std::fmt::Display for BsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BsonError::Unwritable => f.write_str("value cannot be written without changing it"),
            BsonError::Trailing => f.write_str("bytes after BSON document"),
            BsonError::Truncated => f.write_str("BSON runs past the end of its bytes"),
            BsonError::Length(n) => write!(f, "BSON length field {n} out of range"),
            BsonError::Terminator => f.write_str("BSON document, string or name not terminated"),
            BsonError::Type(t) => write!(f, "unknown BSON element type 0x{t:02x}"),
            BsonError::Utf8 => f.write_str("BSON string is not UTF-8"),
            BsonError::Bool(b) => write!(f, "BSON boolean byte {b}, not 0 or 1"),
            BsonError::Depth => write!(f, "BSON nests deeper than {MAX_DEPTH}"),
            BsonError::TooManyElements => write!(f, "more than {MAX_ELEMENTS} BSON elements"),
            BsonError::ArrayKey => f.write_str("BSON array keys are not 0, 1, 2 and so on"),
            BsonError::OldBinary => f.write_str("BSON binary subtype 2 length does not match its bytes"),
            BsonError::RegexOptions => f.write_str("BSON regex options are not in alphabetical order"),
        }
    }
}

impl std::error::Error for BsonError {}

impl Document {
    /// An empty document.
    pub fn new() -> Document {
        Document::default()
    }

    /// The document with `key` and `value` added at the end.
    pub fn with(mut self, key: impl Into<String>, value: Bson) -> Document {
        self.0.push((key.into(), value));
        self
    }

    /// Adds `key` and `value` at the end.
    pub fn push(&mut self, key: impl Into<String>, value: Bson) {
        self.0.push((key.into(), value));
    }

    /// The value of the first element named `key`.
    pub fn get(&self, key: &str) -> Option<&Bson> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The value of the first element named `key`, to change.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Bson> {
        self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The keys and values, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Bson)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The first key, which names the command in a command document.
    pub fn command_name(&self) -> Option<&str> {
        self.0.first().map(|(k, _)| k.as_str())
    }

    /// How many elements the document holds, not counting nested ones.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the document holds no elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

}

impl Wire for Document {
    type ParseError = BsonError;
    type WriteError = BsonError;

    /// Reads one BSON document. Refuses trailing bytes, invalid elements,
    /// and documents beyond the size, nesting, or element limits.
    fn parse(b: &[u8]) -> Result<Self, BsonError> {
        let mut budget = MAX_ELEMENTS;
        let (doc, used) = parse_document(b, 1, MAX_DOCUMENT_SIZE, &mut budget)?;
        if used != b.len() {
            return Err(BsonError::Trailing);
        }
        Ok(doc)
    }

    /// Appends a document. Refuses invalid binary lengths, regex options,
    /// zero bytes in names, and values beyond the reader's limits.
    /// Leaves the destination unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), BsonError> {
        let start = out.len();
        let mut budget = MAX_ELEMENTS;
        if write_top(self, MAX_DOCUMENT_SIZE, &mut budget, out).is_err() {
            out.truncate(start);
            return Err(BsonError::Unwritable);
        }
        Ok(())
    }
}

/// A cursor over bytes. It never reads past them.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0 }
    }

    fn rest(&self) -> &'a [u8] {
        self.b.get(self.pos..).unwrap_or(&[])
    }

    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    fn i32(&mut self) -> Option<i32> {
        self.array().map(i32::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn i64(&mut self) -> Option<i64> {
        self.array().map(i64::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }

    /// A zero-terminated UTF-8 string.
    fn cstring(&mut self) -> Result<String, BsonError> {
        let rest = self.rest();
        let n = rest.iter().position(|&c| c == 0).ok_or(BsonError::Terminator)?;
        let s = std::str::from_utf8(&rest[..n]).map_err(|_| BsonError::Utf8)?;
        self.pos += n + 1;
        Ok(s.to_owned())
    }

    /// A BSON string: a length that counts the trailing zero, the bytes,
    /// and the zero.
    fn string(&mut self) -> Result<String, BsonError> {
        let n = self.i32().ok_or(BsonError::Truncated)?;
        if n < 1 {
            return Err(BsonError::Length(n));
        }
        let bytes = self.take(n as usize).ok_or(BsonError::Truncated)?;
        let (&last, text) = bytes.split_last().ok_or(BsonError::Truncated)?;
        if last != 0 {
            return Err(BsonError::Terminator);
        }
        std::str::from_utf8(text).map(str::to_owned).map_err(|_| BsonError::Utf8)
    }

    /// The document at the cursor, one level deeper than `depth`.
    fn document(&mut self, depth: usize, max: usize, budget: &mut usize) -> Result<Document, BsonError> {
        let next = depth.checked_add(1).ok_or(BsonError::Depth)?;
        let (doc, used) = parse_document(self.rest(), next, max, budget)?;
        self.pos += used;
        Ok(doc)
    }
}

/// Reads a document at `depth` from the start of `b`, at most `max` bytes,
/// taking one element from `budget` for each element it holds.
fn parse_document(b: &[u8], depth: usize, max: usize, budget: &mut usize) -> Result<(Document, usize), BsonError> {
    if depth > MAX_DEPTH {
        return Err(BsonError::Depth);
    }
    let head: [u8; 4] = b.get(..4).and_then(|h| h.try_into().ok()).ok_or(BsonError::Truncated)?;
    let len = i32::from_le_bytes(head);
    if len < 5 || len as usize > max {
        return Err(BsonError::Length(len));
    }
    let len = len as usize;
    let whole = b.get(..len).ok_or(BsonError::Truncated)?;
    let (&last, inner) = whole.split_last().ok_or(BsonError::Truncated)?;
    if last != 0 {
        return Err(BsonError::Terminator);
    }
    let mut r = Reader { b: inner, pos: 4 };
    let mut elements = Vec::new();
    while !r.done() {
        let ty = r.u8().ok_or(BsonError::Truncated)?;
        if ty == 0 {
            return Err(BsonError::Terminator);
        }
        *budget = budget.checked_sub(1).ok_or(BsonError::TooManyElements)?;
        let key = r.cstring()?;
        let value = parse_value(&mut r, ty, depth, max, budget)?;
        elements.push((key, value));
    }
    Ok((Document(elements), len))
}

fn parse_value(r: &mut Reader<'_>, ty: u8, depth: usize, max: usize, budget: &mut usize) -> Result<Bson, BsonError> {
    use element_type as t;
    const T: BsonError = BsonError::Truncated;
    Ok(match ty {
        t::DOUBLE => Bson::Double(f64::from_le_bytes(r.array().ok_or(T)?)),
        t::STRING => Bson::String(r.string()?),
        t::DOCUMENT => Bson::Document(r.document(depth, max, budget)?),
        t::ARRAY => {
            let doc = r.document(depth, max, budget)?;
            let mut values = Vec::with_capacity(doc.0.len());
            for (i, (key, value)) in doc.0.into_iter().enumerate() {
                if !is_index(&key, i) {
                    return Err(BsonError::ArrayKey);
                }
                values.push(value);
            }
            Bson::Array(values)
        }
        t::BINARY => {
            let n = r.i32().ok_or(T)?;
            if n < 0 {
                return Err(BsonError::Length(n));
            }
            let subtype = r.u8().ok_or(T)?;
            let bytes = r.take(n as usize).ok_or(T)?;
            check_binary(subtype, bytes)?;
            Bson::Binary { subtype, bytes: bytes.to_vec() }
        }
        t::UNDEFINED => Bson::Undefined,
        t::OBJECT_ID => Bson::ObjectId(r.array().ok_or(T)?),
        t::BOOLEAN => match r.u8().ok_or(T)? {
            0 => Bson::Boolean(false),
            1 => Bson::Boolean(true),
            b => return Err(BsonError::Bool(b)),
        },
        t::DATE_TIME => Bson::DateTime(r.i64().ok_or(T)?),
        t::NULL => Bson::Null,
        t::REGEX => {
            let pattern = r.cstring()?;
            let options = r.cstring()?;
            check_regex_options(&options)?;
            Bson::Regex { pattern, options }
        }
        t::DB_POINTER => {
            let namespace = r.string()?;
            Bson::DbPointer { namespace, id: r.array().ok_or(T)? }
        }
        t::JAVASCRIPT => Bson::JavaScript(r.string()?),
        t::SYMBOL => Bson::Symbol(r.string()?),
        t::JAVASCRIPT_WITH_SCOPE => {
            // The total length counts itself, the string and the document.
            let total = r.i32().ok_or(T)?;
            if total < 14 {
                return Err(BsonError::Length(total));
            }
            let body = r.take(total as usize - 4).ok_or(T)?;
            let mut inner = Reader::new(body);
            let code = inner.string()?;
            let scope = inner.document(depth, max, budget)?;
            if !inner.done() {
                return Err(BsonError::Length(total));
            }
            Bson::JavaScriptWithScope { code, scope }
        }
        t::INT32 => Bson::Int32(r.i32().ok_or(T)?),
        t::TIMESTAMP => {
            let v = r.u64().ok_or(T)?;
            Bson::Timestamp { time: (v >> 32) as u32, increment: v as u32 }
        }
        t::INT64 => Bson::Int64(r.i64().ok_or(T)?),
        t::DECIMAL128 => Bson::Decimal128(r.array().ok_or(T)?),
        t::MIN_KEY => Bson::MinKey,
        t::MAX_KEY => Bson::MaxKey,
        other => return Err(BsonError::Type(other)),
    })
}

/// Where a writer must stop: the largest document allowed, and the
/// length `out` may not pass, which is that much past the start of the
/// outermost document being written. Every write that can be long checks
/// it first, so a writer gives up before it holds much more than `max`.
#[derive(Clone, Copy)]
struct Limit {
    max: usize,
    end: usize,
}

impl Limit {
    /// Fails if adding `n` bytes to `out` would pass the end.
    fn room(self, out: &[u8], n: usize) -> Result<(), BsonError> {
        let at = out.len().saturating_add(n);
        if at > self.end { Err(BsonError::Unwritable) } else { Ok(()) }
    }
}

/// Writes `doc` as an outermost document of at most `max` bytes.
fn write_top(doc: &Document, max: usize, budget: &mut usize, out: &mut Vec<u8>) -> Result<(), BsonError> {
    let limit = Limit { max, end: out.len().saturating_add(max) };
    write_document(doc, 1, limit, budget, out)
}

fn write_document(
    doc: &Document,
    depth: usize,
    limit: Limit,
    budget: &mut usize,
    out: &mut Vec<u8>,
) -> Result<(), BsonError> {
    write_elements(doc.0.iter().map(|(k, v)| (k.as_str(), v)), depth, limit, budget, out)
}

/// Writes a document holding `elements`, with the same checks the reader
/// makes: depth, element count and size.
fn write_elements<'a, K: AsRef<str>>(
    elements: impl Iterator<Item = (K, &'a Bson)>,
    depth: usize,
    limit: Limit,
    budget: &mut usize,
    out: &mut Vec<u8>,
) -> Result<(), BsonError> {
    if depth > MAX_DEPTH {
        return Err(BsonError::Depth);
    }
    let start = out.len();
    limit.room(out, 5)?;
    out.extend_from_slice(&[0; 4]);
    for (key, value) in elements {
        *budget = budget.checked_sub(1).ok_or(BsonError::TooManyElements)?;
        let key = key.as_ref();
        limit.room(out, key.len().saturating_add(2))?;
        out.push(value.element_type());
        write_cstring(key, out)?;
        write_value(value, depth, limit, budget, out)?;
        // The trailing zero is still to come.
        let len = out.len() - start + 1;
        if len > limit.max {
            return Err(BsonError::Unwritable);
        }
        limit.room(out, 1)?;
    }
    out.push(0);
    let len = out.len() - start;
    out[start..start + 4].copy_from_slice(&(len as i32).to_le_bytes());
    Ok(())
}

fn write_value(
    value: &Bson,
    depth: usize,
    limit: Limit,
    budget: &mut usize,
    out: &mut Vec<u8>,
) -> Result<(), BsonError> {
    let next = depth.checked_add(1).ok_or(BsonError::Depth)?;
    // Fixed-size values are at most 16 bytes; what follows each element
    // checks the limit again.
    match value {
        Bson::Double(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bson::String(s) | Bson::JavaScript(s) | Bson::Symbol(s) => write_string(s, limit, out)?,
        Bson::Document(d) => write_document(d, next, limit, budget, out)?,
        Bson::Array(values) => {
            write_elements(values.iter().enumerate().map(|(i, v)| (i.to_string(), v)), next, limit, budget, out)?
        }
        Bson::Binary { subtype, bytes } => {
            limit.room(out, bytes.len().saturating_add(5))?;
            check_binary(*subtype, bytes)?;
            out.extend_from_slice(&(bytes.len() as i32).to_le_bytes());
            out.push(*subtype);
            out.extend_from_slice(bytes);
        }
        Bson::Undefined | Bson::Null | Bson::MinKey | Bson::MaxKey => {}
        Bson::ObjectId(id) => out.extend_from_slice(id),
        Bson::Boolean(b) => out.push(u8::from(*b)),
        Bson::DateTime(v) | Bson::Int64(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bson::Regex { pattern, options } => {
            check_regex_options(options)?;
            limit.room(out, pattern.len().saturating_add(options.len()).saturating_add(2))?;
            write_cstring(pattern, out)?;
            write_cstring(options, out)?;
        }
        Bson::DbPointer { namespace, id } => {
            write_string(namespace, limit, out)?;
            out.extend_from_slice(id);
        }
        Bson::JavaScriptWithScope { code, scope } => {
            let start = out.len();
            limit.room(out, 4)?;
            out.extend_from_slice(&[0; 4]);
            write_string(code, limit, out)?;
            write_document(scope, next, limit, budget, out)?;
            let total = out.len() - start;
            if total > limit.max {
                return Err(BsonError::Unwritable);
            }
            out[start..start + 4].copy_from_slice(&(total as i32).to_le_bytes());
        }
        Bson::Int32(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bson::Timestamp { time, increment } => {
            let v = (u64::from(*time) << 32) | u64::from(*increment);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bson::Decimal128(d) => out.extend_from_slice(d),
    }
    Ok(())
}

/// Whether `key` is `i` written in decimal, as array keys are.
fn is_index(key: &str, i: usize) -> bool {
    let mut digits = [0u8; 20];
    let mut n = i;
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    key.as_bytes() == &digits[at..]
}

/// Binary of the old subtype 2 holds a 4-byte length and that many bytes.
fn check_binary(subtype: u8, bytes: &[u8]) -> Result<(), BsonError> {
    if subtype != 2 {
        return Ok(());
    }
    let inner = bytes.get(..4).map(|h| i32::from_le_bytes([h[0], h[1], h[2], h[3]]));
    match inner {
        Some(n) if usize::try_from(n).is_ok_and(|n| n == bytes.len() - 4) => Ok(()),
        _ => Err(BsonError::OldBinary),
    }
}

/// Regex options must be stored in alphabetical order. Each one appears
/// at most once.
fn check_regex_options(options: &str) -> Result<(), BsonError> {
    if options.as_bytes().windows(2).all(|w| w[0] < w[1]) { Ok(()) } else { Err(BsonError::RegexOptions) }
}

/// A BSON string. The limit, at most [`MAX_COMMAND_SIZE`] past the
/// document's start, keeps its length within an `i32`.
fn write_string(s: &str, limit: Limit, out: &mut Vec<u8>) -> Result<(), BsonError> {
    limit.room(out, s.len().saturating_add(5))?;
    out.extend_from_slice(&(s.len() as i32 + 1).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    Ok(())
}

/// A zero-terminated name. Callers check its size against their limit
/// first: a document's, or the message's.
fn write_cstring(s: &str, out: &mut Vec<u8>) -> Result<(), BsonError> {
    if s.as_bytes().contains(&0) {
        return Err(BsonError::Unwritable);
    }
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    Ok(())
}

/// CRC-32C (Castagnoli) of `bytes`, the checksum OP_MSG uses.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c = CRC32C_TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// The reflected polynomial 0x1EDC6F41, one entry per byte value.
const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82f6_3b78 } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// A message header's four fields, as they are on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The whole message's length, header included.
    pub length: i32,
    /// Chosen by the sender to name this message.
    pub request_id: i32,
    /// The request ID this message answers, or 0.
    pub response_to: i32,
    /// What the message is: one of [`op_code`].
    pub op_code: i32,
}

impl Wire for Header {
    type ParseError = MessageError;
    type WriteError = std::convert::Infallible;

    /// Reads exactly 16 header bytes. Refuses incomplete or trailing bytes.
    /// Field values are left unchecked until the complete message is read.
    fn parse(b: &[u8]) -> Result<Self, MessageError> {
        if b.len() > HEADER_LEN {
            return Err(MessageError::Trailing);
        }
        let mut r = Reader::new(b);
        let e = MessageError::Truncated;
        Ok(Header { length: r.i32().ok_or(e)?, request_id: r.i32().ok_or(e)?,
            response_to: r.i32().ok_or(e)?, op_code: r.i32().ok_or(e)? })
    }

    /// Appends the four header fields without refusing any field value.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        for field in [self.length, self.request_id, self.response_to, self.op_code] {
            out.extend_from_slice(&field.to_le_bytes());
        }
        Ok(())
    }
}

/// One wire protocol message: the header's IDs and the body its op code
/// names. The length and op code are worked out from the body, so neither
/// is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Chosen by the sender to name this message.
    pub request_id: i32,
    /// The request ID this message answers, or 0 for a request.
    pub response_to: i32,
    /// What the message carries.
    pub body: Body,
}

/// What a message carries, by op code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// OP_MSG: a command or its reply.
    Msg(Msg),
    /// OP_QUERY: a legacy query, sent now only for the handshake.
    Query(Query),
    /// OP_REPLY: the answer to an OP_QUERY.
    Reply(Reply),
    /// OP_COMPRESSED: another message, compressed. It is not decompressed.
    Compressed(Compressed),
    /// Any other op code, with the bytes after the header unread. A writer
    /// refuses the op codes the other variants stand for.
    Other {
        /// The op code.
        op_code: i32,
        /// The bytes after the header.
        data: Vec<u8>,
    },
}

impl Body {
    /// The op code this body is sent with.
    pub fn op_code(&self) -> i32 {
        match self {
            Body::Msg(_) => op_code::MSG,
            Body::Query(_) => op_code::QUERY,
            Body::Reply(_) => op_code::REPLY,
            Body::Compressed(_) => op_code::COMPRESSED,
            Body::Other { op_code, .. } => *op_code,
        }
    }
}

/// An OP_MSG: flag bits, one body document, and any number of document
/// sequences, at most [`MAX_SEQUENCES`], each with its own identifier.
/// The body's top-level field names are all different, and no sequence's
/// identifier names a field the body has. A writer puts the body first. If [`flag::CHECKSUM_PRESENT`]
/// is set, a reader checks the CRC-32C at the end, and a writer adds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    /// The flag bits: see [`flag`]. Only bits in [`flag::KNOWN`] are kept
    /// or written.
    pub flags: u32,
    /// The body section (kind 0): the command or reply.
    pub body: Document,
    /// The document sequence sections (kind 1), such as the documents of
    /// an `insert` command.
    pub sequences: Vec<Sequence>,
}

impl Msg {
    /// A message with no flags and no sequences.
    pub fn new(body: Document) -> Msg {
        Msg { flags: 0, body, sequences: Vec::new() }
    }

    /// The document sequence named `identifier`, such as `documents` for
    /// an `insert`.
    pub fn sequence(&self, identifier: &str) -> Option<&Sequence> {
        self.sequences.iter().find(|s| s.identifier == identifier)
    }
}

/// An OP_MSG document sequence: documents that stand for one field of the
/// body, such as `documents` of an `insert`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sequence {
    /// The field the documents stand for. It may not hold a zero byte.
    pub identifier: String,
    /// The documents.
    pub documents: Vec<Document>,
}

/// An OP_QUERY. Clients still send `{ isMaster: 1 }` or `{ hello: 1 }` this
/// way to the `admin.$cmd` collection when a connection opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The flag bits, such as 4 for a query a secondary may answer.
    pub flags: u32,
    /// The full collection name, such as `admin.$cmd`. It may not hold a
    /// zero byte.
    pub collection: String,
    /// How many documents to skip.
    pub number_to_skip: i32,
    /// How many documents to return in the first reply.
    pub number_to_return: i32,
    /// The query, or the command.
    pub query: Document,
    /// Which fields to return, if the query says.
    pub fields: Option<Document>,
}

/// An OP_REPLY. The count of documents on the wire is worked out from
/// `documents`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The flag bits, such as 8 (`AwaitCapable`).
    pub flags: u32,
    /// The cursor to ask for more results with, or 0.
    pub cursor_id: i64,
    /// Where in the cursor this reply starts.
    pub starting_from: i32,
    /// The documents returned.
    pub documents: Vec<Document>,
}

impl Reply {
    /// A reply with no flags and no cursor, holding `documents`.
    pub fn new(documents: Vec<Document>) -> Reply {
        Reply { flags: 0, cursor_id: 0, starting_from: 0, documents }
    }
}

/// An OP_COMPRESSED message, reported as it came.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compressed {
    /// The op code of the message inside.
    pub original_op_code: i32,
    /// The length of the message inside once decompressed, header not
    /// included. It is at most [`MAX_MESSAGE_SIZE`] less [`HEADER_LEN`],
    /// and with [`compressor::NOOP`] it is the length of `data`.
    pub uncompressed_size: i32,
    /// Which compressor: see [`compressor`].
    pub compressor: u8,
    /// The compressed bytes.
    pub data: Vec<u8>,
}

/// Why bytes are not a message, or why a message cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// The length field is under [`HEADER_LEN`] or over the largest message
    /// allowed. The stream cannot be split any further.
    Length(i32),
    /// A field runs past the end of the message.
    Truncated,
    /// Bytes are left after what the op code holds.
    Trailing,
    /// A document, or a name in the message, is not well formed.
    Bson(BsonError),
    /// An OP_MSG sets a required flag bit this module does not know.
    Flags(u32),
    /// An OP_MSG section kind other than 0 or 1. This includes kind 2,
    /// which only servers use among themselves, and kind 3, telemetry a
    /// client sends only to a server that says it takes it. The OP_MSG
    /// specification says the connection must then be closed, so [`Frames`]
    /// stops here for good.
    SectionKind(u8),
    /// An OP_MSG has this many body sections, not exactly one.
    BodyCount(usize),
    /// An OP_MSG document sequence's size is out of range, or does not
    /// match the documents it holds.
    SequenceLength(i32),
    /// An OP_MSG checksum does not match its bytes.
    Checksum {
        /// The checksum of the bytes.
        expected: u32,
        /// The checksum the message carries.
        found: u32,
    },
    /// An OP_REPLY's document count is negative or does not match the
    /// documents it holds.
    NumberReturned(i32),
    /// More documents than [`MAX_DOCUMENTS`].
    TooManyDocuments,
    /// The value cannot be written without changing it.
    Unwritable,
    /// Two OP_MSG document sequences share an identifier.
    DuplicateIdentifier,
    /// An OP_MSG body has two top-level fields with the same name, or a
    /// document sequence's identifier names a field the body also has.
    DuplicateField,
    /// An OP_COMPRESSED message's uncompressed size is negative, larger
    /// than a message's bytes after its header may be, or, with the
    /// [`compressor::NOOP`] compressor, not the length of its bytes.
    UncompressedSize(i32),
    /// More OP_MSG document sequences than [`MAX_SEQUENCES`].
    TooManySequences,
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageError::Unwritable => f.write_str("value cannot be written without changing it"),
            MessageError::Length(n) => write!(f, "message length {n} out of range"),
            MessageError::Truncated => f.write_str("a field runs past the end of the message"),
            MessageError::Trailing => f.write_str("bytes left at the end of the message"),
            MessageError::Bson(e) => e.fmt(f),
            MessageError::Flags(b) => write!(f, "unknown required OP_MSG flag bits in 0x{b:08x}"),
            MessageError::SectionKind(k) => write!(f, "unknown OP_MSG section kind {k}"),
            MessageError::BodyCount(n) => write!(f, "{n} OP_MSG body sections, not 1"),
            MessageError::SequenceLength(n) => write!(f, "OP_MSG document sequence size {n} out of range"),
            MessageError::Checksum { expected, found } => {
                write!(f, "OP_MSG checksum 0x{found:08x}, expected 0x{expected:08x}")
            }
            MessageError::NumberReturned(n) => write!(f, "OP_REPLY says {n} documents, which does not match"),
            MessageError::TooManyDocuments => write!(f, "more than {MAX_DOCUMENTS} documents in one message"),
            MessageError::DuplicateIdentifier => f.write_str("two OP_MSG document sequences share an identifier"),
            MessageError::TooManySequences => write!(f, "more than {MAX_SEQUENCES} OP_MSG document sequences"),
            MessageError::DuplicateField => f.write_str("an OP_MSG body field is given twice"),
            MessageError::UncompressedSize(n) => write!(f, "OP_COMPRESSED uncompressed size {n} out of range"),
        }
    }
}

impl std::error::Error for MessageError {}

impl From<BsonError> for MessageError {
    fn from(e: BsonError) -> MessageError {
        MessageError::Bson(e)
    }
}

/// The length of the message at the start of `b`, once all of it is there.
/// A bad length is known from the first four bytes.
fn frame_len(b: &[u8], max: usize) -> Result<Option<usize>, MessageError> {
    let Some(head) = b.get(..4) else { return Ok(None) };
    let len = i32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    if len < HEADER_LEN as i32 || len as usize > max {
        return Err(MessageError::Length(len));
    }
    let len = len as usize;
    Ok(if b.len() < len { None } else { Some(len) })
}

impl Message {
    /// Reads one whole message, whose length field is already checked.
    fn from_frame(frame: &[u8]) -> Result<Message, MessageError> {
        let header = Header::parse(frame.get(..HEADER_LEN).ok_or(MessageError::Truncated)?)?;
        let data = &frame[HEADER_LEN..];
        let body = match header.op_code {
            op_code::MSG => Body::Msg(parse_msg(frame, data)?),
            op_code::QUERY => Body::Query(parse_query(data)?),
            op_code::REPLY => Body::Reply(parse_reply(data)?),
            op_code::COMPRESSED => {
                let mut r = Reader::new(data);
                let t = MessageError::Truncated;
                let original_op_code = r.i32().ok_or(t)?;
                let uncompressed_size = r.i32().ok_or(t)?;
                let compressor = r.u8().ok_or(t)?;
                let data = r.rest();
                check_uncompressed(uncompressed_size, compressor, data)?;
                Body::Compressed(Compressed { original_op_code, uncompressed_size, compressor, data: data.to_vec() })
            }
            op_code => Body::Other { op_code, data: data.to_vec() },
        };
        Ok(Message { request_id: header.request_id, response_to: header.response_to, body })
    }

    fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&self.request_id.to_le_bytes());
        out.extend_from_slice(&self.response_to.to_le_bytes());
        out.extend_from_slice(&self.body.op_code().to_le_bytes());
        let mut budget = MAX_ELEMENTS;
        let checksum = match &self.body {
            Body::Msg(m) => {
                write_msg(m, &mut budget, &mut out)?;
                m.flags & flag::CHECKSUM_PRESENT != 0
            }
            Body::Query(q) => {
                out.extend_from_slice(&q.flags.to_le_bytes());
                check_size(out.len().saturating_add(q.collection.len()).saturating_add(1))?;
                write_cstring(&q.collection, &mut out)?;
                out.extend_from_slice(&q.number_to_skip.to_le_bytes());
                out.extend_from_slice(&q.number_to_return.to_le_bytes());
                write_top(&q.query, MAX_COMMAND_SIZE, &mut budget, &mut out)?;
                check_size(out.len())?;
                if let Some(fields) = &q.fields {
                    write_top(fields, MAX_COMMAND_SIZE, &mut budget, &mut out)?;
                }
                false
            }
            Body::Reply(r) => {
                if r.documents.len() > MAX_DOCUMENTS {
                    return Err(MessageError::TooManyDocuments);
                }
                out.extend_from_slice(&r.flags.to_le_bytes());
                out.extend_from_slice(&r.cursor_id.to_le_bytes());
                out.extend_from_slice(&r.starting_from.to_le_bytes());
                out.extend_from_slice(&(r.documents.len() as i32).to_le_bytes());
                for d in &r.documents {
                    write_top(d, MAX_COMMAND_SIZE, &mut budget, &mut out)?;
                    check_size(out.len())?;
                }
                false
            }
            Body::Compressed(c) => {
                check_size(HEADER_LEN + 9 + c.data.len())?;
                check_uncompressed(c.uncompressed_size, c.compressor, &c.data)?;
                out.extend_from_slice(&c.original_op_code.to_le_bytes());
                out.extend_from_slice(&c.uncompressed_size.to_le_bytes());
                out.push(c.compressor);
                out.extend_from_slice(&c.data);
                false
            }
            Body::Other { op_code, data } => {
                if matches!(*op_code, op_code::MSG | op_code::QUERY | op_code::REPLY | op_code::COMPRESSED) {
                    return Err(MessageError::Unwritable);
                }
                check_size(HEADER_LEN + data.len())?;
                out.extend_from_slice(data);
                false
            }
        };
        let len = out.len() + if checksum { 4 } else { 0 };
        check_size(len)?;
        out[..4].copy_from_slice(&(len as i32).to_le_bytes());
        if checksum {
            let crc = crc32c(&out);
            out.extend_from_slice(&crc.to_le_bytes());
        }
        Ok(out)
    }

    /// A message that answers this one with `body`, with `request_id` as
    /// its own ID.
    pub fn reply(&self, request_id: i32, body: Body) -> Message {
        Message { request_id, response_to: self.request_id, body }
    }
}

// Only complete, bounded messages reach the body parser.
fn parse_message(b: &[u8], limit: usize) -> Result<Option<(Message, usize)>, MessageError> {
    let Some(len) = frame_len(b, limit)? else { return Ok(None) };
    let frame = b.get(..len).ok_or(MessageError::Truncated)?;
    Ok(Some((Message::from_frame(frame)?, len)))
}

impl Wire for Message {
    type ParseError = MessageError;
    type WriteError = MessageError;

    /// Reads exactly one message, bounded by [`MAX_MESSAGE_SIZE`].
    /// Incomplete input and trailing bytes are errors.
    fn parse(b: &[u8]) -> Result<Self, MessageError> {
        match parse_message(b, MAX_MESSAGE_SIZE)? {
            Some((message, used)) if used == b.len() => Ok(message),
            Some(_) => Err(MessageError::Trailing),
            None => Err(MessageError::Truncated),
        }
    }

    /// Appends a message. Refuses invalid BSON or names, unknown flags,
    /// conflicting op codes, invalid compressed sizes, duplicate fields,
    /// and values beyond the message limits. Leaves `out` unchanged
    /// on error. Computes OP_MSG checksums from the completed message.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), MessageError> {
        let bytes = self.encode().map_err(|_| MessageError::Unwritable)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Reads MongoDB messages without holding input bytes.
///
/// Use with [`codec::Stream`](fictionet::stdlib::codec::Stream) for a buffer bounded
/// by [`limit`](Self::limit), including the header. Oversized messages
/// are refused from the first four bytes. Partial messages return
/// [`Step::Need`], including at EOF, so the stream reports truncation.
///
/// Items are `Result<Message, MessageError>`. A body error consumes its
/// frame and is returned as an error item, so the next message can still
/// be read. Only [`MessageError::Length`] from the length field and
/// [`MessageError::SectionKind`] end the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Reads messages up to [`MAX_MESSAGE_SIZE`] bytes, header included.
    pub fn new() -> Self {
        Self::with_limit(MAX_MESSAGE_SIZE)
    }

    /// Sets the message limit, including the header. Clamps it to
    /// [`HEADER_LEN`] through [`MAX_MESSAGE_SIZE`].
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.clamp(HEADER_LEN, MAX_MESSAGE_SIZE) }
    }

    /// The maximum message size, including its header.
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
    type Item = Result<Message, MessageError>;
    type Error = MessageError;
    const NAME: &'static str = "MongoDB";

    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, MessageError> {
        let Some(len) = frame_len(input, self.limit)? else {
            return Ok(Step::Need);
        };
        let message = Message::from_frame(&input[..len]);
        if let Err(e @ MessageError::SectionKind(_)) = message {
            return Err(e);
        }
        Ok(Step::Item(message, len))
    }
}

fn check_size(len: usize) -> Result<(), MessageError> {
    if len > MAX_MESSAGE_SIZE { Err(MessageError::Unwritable) } else { Ok(()) }
}

/// An OP_COMPRESSED size names the bytes of a message after its header,
/// and with no compression it is the length of the bytes there are.
fn check_uncompressed(size: i32, compressor: u8, data: &[u8]) -> Result<(), MessageError> {
    let fits = usize::try_from(size).is_ok_and(|n| n <= MAX_MESSAGE_SIZE - HEADER_LEN);
    if !fits || (compressor == compressor::NOOP && size as usize != data.len()) {
        return Err(MessageError::UncompressedSize(size));
    }
    Ok(())
}

/// The field a document sequence's identifier names is not in the body,
/// and the body's top-level names are all different. A dotted identifier
/// such as `a.b` names field `b` of the document in field `a`.
fn check_fields(body: &Document, sequences: &[Sequence]) -> Result<(), MessageError> {
    // Grow as fields are checked, without reserving for an unchecked body.
    let mut names = std::collections::HashSet::with_capacity(body.len().min(1024));
    for (key, _) in body.iter() {
        if !names.insert(key) {
            return Err(MessageError::DuplicateField);
        }
    }
    for seq in sequences {
        let mut parts = seq.identifier.split('.');
        let first = parts.next().unwrap_or("");
        if !names.contains(first) {
            continue;
        }
        let mut at = body.get(first);
        for part in parts {
            at = match at {
                Some(Bson::Document(d)) => d.get(part),
                _ => None,
            };
        }
        if at.is_some() {
            return Err(MessageError::DuplicateField);
        }
    }
    Ok(())
}

fn parse_msg(frame: &[u8], data: &[u8]) -> Result<Msg, MessageError> {
    let t = MessageError::Truncated;
    let flags = Reader::new(data).u32().ok_or(t)?;
    if flags & flag::REQUIRED & !flag::KNOWN != 0 {
        return Err(MessageError::Flags(flags));
    }
    // Unknown optional bits are ignored, and dropped so that a message
    // read and written again does not pass them on.
    let flags = flags & flag::KNOWN;
    let mut end = data.len();
    if flags & flag::CHECKSUM_PRESENT != 0 {
        if end < 8 {
            return Err(t);
        }
        end -= 4;
        let found = u32::from_le_bytes([data[end], data[end + 1], data[end + 2], data[end + 3]]);
        let expected = crc32c(&frame[..frame.len() - 4]);
        if found != expected {
            return Err(MessageError::Checksum { expected, found });
        }
    }
    let mut r = Reader::new(&data[4..end]);
    let mut budget = MAX_ELEMENTS;
    let mut documents = 0usize;
    let mut bodies = Vec::new();
    let mut sequences = Vec::new();
    while !r.done() {
        match r.u8().ok_or(t)? {
            0 => {
                if !bodies.is_empty() {
                    return Err(MessageError::BodyCount(2));
                }
                let (doc, used) = parse_document(r.rest(), 1, MAX_COMMAND_SIZE, &mut budget)?;
                r.pos += used;
                bodies.push(doc);
            }
            1 => {
                let size = r.i32().ok_or(t)?;
                // The size counts itself and at least the identifier's zero.
                if size < 5 || size as usize - 4 > r.rest().len() {
                    return Err(MessageError::SequenceLength(size));
                }
                let mut s = Reader::new(r.take(size as usize - 4).ok_or(t)?);
                let identifier = s.cstring()?;
                if sequences.len() >= MAX_SEQUENCES {
                    return Err(MessageError::TooManySequences);
                }
                if sequences.iter().any(|q: &Sequence| q.identifier == identifier) {
                    return Err(MessageError::DuplicateIdentifier);
                }
                let mut docs = Vec::new();
                while !s.done() {
                    documents += 1;
                    if docs.len() >= MAX_DOCUMENTS || documents > 2 * MAX_DOCUMENTS {
                        return Err(MessageError::TooManyDocuments);
                    }
                    let (doc, used) = parse_document(s.rest(), 1, MAX_DOCUMENT_SIZE, &mut budget)?;
                    s.pos += used;
                    docs.push(doc);
                }
                sequences.push(Sequence { identifier, documents: docs });
            }
            kind => return Err(MessageError::SectionKind(kind)),
        }
    }
    let body = bodies.pop().ok_or(MessageError::BodyCount(0))?;
    check_fields(&body, &sequences)?;
    Ok(Msg { flags, body, sequences })
}

fn write_msg(m: &Msg, budget: &mut usize, out: &mut Vec<u8>) -> Result<(), MessageError> {
    if m.flags & !flag::KNOWN != 0 {
        return Err(MessageError::Flags(m.flags));
    }
    if m.sequences.len() > MAX_SEQUENCES {
        return Err(MessageError::TooManySequences);
    }
    for (i, seq) in m.sequences.iter().enumerate() {
        if m.sequences[..i].iter().any(|q| q.identifier == seq.identifier) {
            return Err(MessageError::DuplicateIdentifier);
        }
    }
    let mut documents = 0usize;
    for seq in &m.sequences {
        documents = documents.saturating_add(seq.documents.len());
        if seq.documents.len() > MAX_DOCUMENTS || documents > 2 * MAX_DOCUMENTS {
            return Err(MessageError::TooManyDocuments);
        }
    }
    check_fields(&m.body, &m.sequences)?;
    out.extend_from_slice(&m.flags.to_le_bytes());
    out.push(0);
    write_top(&m.body, MAX_COMMAND_SIZE, budget, out)?;
    check_size(out.len())?;
    for seq in &m.sequences {
        out.push(1);
        let start = out.len();
        out.extend_from_slice(&[0; 4]);
        check_size(out.len().saturating_add(seq.identifier.len()).saturating_add(1))?;
        write_cstring(&seq.identifier, out)?;
        for d in &seq.documents {
            write_top(d, MAX_DOCUMENT_SIZE, budget, out)?;
            check_size(out.len())?;
        }
        let size = out.len() - start;
        out[start..start + 4].copy_from_slice(&(size as i32).to_le_bytes());
    }
    Ok(())
}

fn parse_query(data: &[u8]) -> Result<Query, MessageError> {
    let t = MessageError::Truncated;
    let mut r = Reader::new(data);
    let flags = r.u32().ok_or(t)?;
    let collection = r.cstring()?;
    let number_to_skip = r.i32().ok_or(t)?;
    let number_to_return = r.i32().ok_or(t)?;
    let mut budget = MAX_ELEMENTS;
    let (query, used) = parse_document(r.rest(), 1, MAX_COMMAND_SIZE, &mut budget)?;
    r.pos += used;
    let fields = if r.done() {
        None
    } else {
        let (fields, used) = parse_document(r.rest(), 1, MAX_COMMAND_SIZE, &mut budget)?;
        r.pos += used;
        Some(fields)
    };
    if !r.done() {
        return Err(MessageError::Trailing);
    }
    Ok(Query { flags, collection, number_to_skip, number_to_return, query, fields })
}

fn parse_reply(data: &[u8]) -> Result<Reply, MessageError> {
    let t = MessageError::Truncated;
    let mut r = Reader::new(data);
    let flags = r.u32().ok_or(t)?;
    let cursor_id = r.i64().ok_or(t)?;
    let starting_from = r.i32().ok_or(t)?;
    let number = r.i32().ok_or(t)?;
    if number < 0 || number as usize > MAX_DOCUMENTS {
        return Err(MessageError::NumberReturned(number));
    }
    let mut budget = MAX_ELEMENTS;
    let mut documents = Vec::new();
    while !r.done() {
        if documents.len() == number as usize {
            return Err(MessageError::NumberReturned(number));
        }
        let (doc, used) = parse_document(r.rest(), 1, MAX_COMMAND_SIZE, &mut budget)?;
        r.pos += used;
        documents.push(doc);
    }
    if documents.len() != number as usize {
        return Err(MessageError::NumberReturned(number));
    }
    Ok(Reply { flags, cursor_id, starting_from, documents })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream, contract,
        test_support::{decode_all, mutate},
    };

    fn s(v: &str) -> Bson {
        Bson::String(v.to_owned())
    }

    /// A document with one element of every type.
    fn every_type() -> Document {
        Document::new()
            .with("double", Bson::Double(-2.5))
            .with("string", s("héllo\0world"))
            .with("doc", Bson::Document(Document::new().with("a", Bson::Int32(1))))
            .with("array", Bson::Array(vec![Bson::Int32(1), s("two"), Bson::Array(vec![])]))
            .with("binary", Bson::Binary { subtype: 4, bytes: (0..16).collect() })
            .with("undefined", Bson::Undefined)
            .with("oid", Bson::ObjectId([0x65, 0x1f, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]))
            .with("t", Bson::Boolean(true))
            .with("f", Bson::Boolean(false))
            .with("date", Bson::DateTime(1_696_000_000_000))
            .with("null", Bson::Null)
            .with("regex", Bson::Regex { pattern: "^a.*z$".into(), options: "im".into() })
            .with("dbp", Bson::DbPointer { namespace: "db.c".into(), id: [7; 12] })
            .with("js", Bson::JavaScript("x + 1".into()))
            .with("sym", Bson::Symbol("sym".into()))
            .with(
                "jsws",
                Bson::JavaScriptWithScope { code: "x".into(), scope: Document::new().with("x", Bson::Int64(-9)) },
            )
            .with("i32", Bson::Int32(i32::MIN))
            .with("ts", Bson::Timestamp { time: 1_700_000_000, increment: 3 })
            .with("i64", Bson::Int64(i64::MAX))
            .with("dec", Bson::Decimal128([0x31; 16]))
            .with("min", Bson::MinKey)
            .with("max", Bson::MaxKey)
            .with("nan", Bson::Double(f64::NAN))
    }

    fn msg(request_id: i32, body: Document) -> Message {
        Message { request_id, response_to: 0, body: Body::Msg(Msg::new(body)) }
    }

    // Examples from bsonspec.org/faq.html.

    #[test]
    fn hello_world_example() {
        let bytes = b"\x16\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00\x00";
        let doc = Document::new().with("hello", s("world"));
        assert_eq!(doc.to_bytes().unwrap(), bytes);
        assert_eq!(Document::parse(bytes).unwrap(), doc);
    }

    #[test]
    fn array_example() {
        let bytes = b"\x31\x00\x00\x00\x04BSON\x00\x26\x00\x00\x00\x020\x00\x08\x00\x00\x00awesome\x00\
            \x011\x00\x33\x33\x33\x33\x33\x33\x14\x40\x102\x00\xc2\x07\x00\x00\x00\x00";
        let doc = Document::new().with("BSON", Bson::Array(vec![s("awesome"), Bson::Double(5.05), Bson::Int32(1986)]));
        assert_eq!(doc.to_bytes().unwrap(), bytes);
        assert_eq!(Document::parse(bytes).unwrap(), doc);
    }

    #[test]
    fn empty_document() {
        assert_eq!(Document::new().to_bytes().unwrap(), [5, 0, 0, 0, 0]);
        assert_eq!(Document::parse(&[5, 0, 0, 0, 0, 9]), Err(BsonError::Trailing));
        assert_eq!(Document::parse(&[5, 0, 0, 0, 0]), Ok(Document::new()));
    }

    #[test]
    fn every_type_round_trips() {
        let doc = every_type();
        let bytes = doc.to_bytes().unwrap();
        let back = Document::parse(&bytes).unwrap();
        assert_eq!(back, doc);
        assert_eq!(back.get("i64"), Some(&Bson::Int64(i64::MAX)));
        assert_eq!(back.get("missing"), None);
        assert_eq!(back.len(), 23);
        // Doubles compare by bits.
        assert_ne!(Bson::Double(0.0), Bson::Double(-0.0));
        assert_ne!(Bson::Int32(1), Bson::Int64(1));
    }

    #[test]
    fn timestamp_layout() {
        let doc = Document::new().with("t", Bson::Timestamp { time: 0x0102_0304, increment: 0x0506_0708 });
        let bytes = doc.to_bytes().unwrap();
        // Increment in the low half, written first in little-endian order.
        assert_eq!(&bytes[7..15], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    /// `{ a: <array> }`, the array written as `inner`, a document.
    fn array_of(inner: &Document) -> Vec<u8> {
        let mut bytes = vec![element_type::ARRAY, b'a', 0];
        bytes.extend_from_slice(&inner.to_bytes().unwrap());
        raw(&bytes)
    }

    #[test]
    fn array_keys_must_count_from_zero() {
        // bsonspec.org: array keys are integers, starting at 0 and
        // continuing in order.
        let good = Document::new().with("0", Bson::Int32(1)).with("1", Bson::Int32(2));
        let doc = Document::parse(&array_of(&good)).unwrap();
        assert_eq!(doc, Document::new().with("a", Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)])));
        for bad in [
            Document::new().with("x", Bson::Int32(1)),
            Document::new().with("1", Bson::Int32(1)),
            Document::new().with("0", Bson::Null).with("0", Bson::Null),
            Document::new().with("00", Bson::Null),
            Document::new().with("", Bson::Null),
        ] {
            assert_eq!(Document::parse(&array_of(&bad)), Err(BsonError::ArrayKey), "{bad:?}");
        }
    }

    #[test]
    fn old_binary_holds_its_own_length() {
        // Subtype 2: the bytes are an int32 and that many bytes.
        let good = Bson::Binary { subtype: 2, bytes: vec![2, 0, 0, 0, 7, 8] };
        let doc = Document::new().with("b", good);
        assert_eq!(Document::parse(&doc.to_bytes().unwrap()).unwrap(), doc);
        for bytes in [vec![], vec![1, 0, 0], vec![3, 0, 0, 0, 7, 8], vec![0xff, 0xff, 0xff, 0xff]] {
            let bad = Document::new().with("b", Bson::Binary { subtype: 2, bytes: bytes.clone() });
            assert_eq!(bad.to_bytes(), Err(BsonError::Unwritable), "{bytes:?}");
            let mut inner = vec![element_type::BINARY, b'b', 0];
            inner.extend_from_slice(&(bytes.len() as i32).to_le_bytes());
            inner.push(2);
            inner.extend_from_slice(&bytes);
            assert_eq!(Document::parse(&raw(&inner)), Err(BsonError::OldBinary), "{bytes:?}");
        }
    }

    #[test]
    fn regex_options_are_in_alphabetical_order() {
        let re = |o: &str| Document::new().with("r", Bson::Regex { pattern: "a".into(), options: o.into() });
        for ok in ["", "i", "ilmsux", "mx"] {
            let doc = re(ok);
            assert_eq!(Document::parse(&doc.to_bytes().unwrap()).unwrap(), doc);
        }
        for bad in ["mi", "ii", "xs"] {
            assert_eq!(re(bad).to_bytes(), Err(BsonError::Unwritable), "{bad}");
            let mut inner = vec![element_type::REGEX, b'r', 0, b'a', 0];
            inner.extend_from_slice(bad.as_bytes());
            inner.push(0);
            assert_eq!(Document::parse(&raw(&inner)), Err(BsonError::RegexOptions), "{bad}");
        }
    }

    #[test]
    fn sequence_identifiers_are_unique() {
        let seq = |id: &str| Sequence { identifier: id.into(), documents: vec![Document::new()] };
        let mut m = Msg::new(Document::new());
        m.sequences = vec![seq("documents"), seq("documents")];
        let bad = Message { request_id: 0, response_to: 0, body: Body::Msg(m) };
        assert_eq!(bad.to_bytes(), Err(MessageError::Unwritable));
        // The same by hand.
        let mut d = 0u32.to_le_bytes().to_vec();
        d.extend_from_slice(&[0, 5, 0, 0, 0, 0]);
        for _ in 0..2 {
            // Size 11: itself, "d" and its zero, and one empty document.
            d.extend_from_slice(&[1, 11, 0, 0, 0, b'd', 0, 5, 0, 0, 0, 0]);
        }
        assert_eq!(Message::parse(&frame(op_code::MSG, &d)), Err(MessageError::DuplicateIdentifier));
    }

    #[test]
    fn sequence_count_limit() {
        let ids: Vec<String> = (0..=MAX_SEQUENCES).map(|i| format!("s{i}")).collect();
        let mut m = Msg::new(Document::new());
        m.sequences = ids.iter().map(|id| Sequence { identifier: id.clone(), documents: vec![] }).collect();
        let bad = Message { request_id: 0, response_to: 0, body: Body::Msg(m.clone()) };
        assert_eq!(bad.to_bytes(), Err(MessageError::Unwritable));
        // The same by hand, and one fewer reads.
        let mut d = 0u32.to_le_bytes().to_vec();
        d.extend_from_slice(&[0, 5, 0, 0, 0, 0]);
        for id in &ids {
            d.push(1);
            d.extend_from_slice(&((4 + id.len() + 1) as i32).to_le_bytes());
            d.extend_from_slice(id.as_bytes());
            d.push(0);
        }
        assert_eq!(Message::parse(&frame(op_code::MSG, &d)), Err(MessageError::TooManySequences));
        m.sequences.pop();
        let ok = Message { request_id: 0, response_to: 0, body: Body::Msg(m) };
        let bytes = ok.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), ok);
    }

    #[test]
    fn every_truncated_document_prefix_is_refused() {
        let bytes = every_type().to_bytes().unwrap();
        for n in 0..bytes.len() {
            assert_eq!(Document::parse(&bytes[..n]), Err(BsonError::Truncated), "{n} bytes");
        }
    }

    /// A document whose bytes after the length are `inner` and a zero.
    fn raw(inner: &[u8]) -> Vec<u8> {
        let mut b = ((inner.len() + 5) as i32).to_le_bytes().to_vec();
        b.extend_from_slice(inner);
        b.push(0);
        b
    }

    #[test]
    fn bson_errors() {
        use BsonError as E;
        assert_eq!(Document::parse(&[4, 0, 0, 0, 0]), Err(E::Length(4)));
        assert_eq!(Document::parse(&[0xff, 0xff, 0xff, 0xff, 0]), Err(E::Length(-1)));
        let big = (MAX_DOCUMENT_SIZE as i32 + 1).to_le_bytes();
        assert_eq!(Document::parse(&big), Err(E::Length(big_i32())));
        assert_eq!(Document::parse(&[5, 0, 0, 0, 1]), Err(E::Terminator));
        assert_eq!(Document::parse(&[6, 0, 0, 0, 0, 0]), Err(E::Terminator)); // ends early
        assert_eq!(Document::parse(&raw(&[0x20, b'a', 0])), Err(E::Type(0x20)));
        assert_eq!(Document::parse(&raw(&[0x0a, b'a'])), Err(E::Terminator)); // key with no zero
        assert_eq!(Document::parse(&raw(&[0x0a, 0xff, 0])), Err(E::Utf8));
        assert_eq!(Document::parse(&raw(&[0x08, b'a', 0, 2])), Err(E::Bool(2)));
        assert_eq!(Document::parse(&raw(&[0x10, b'a', 0, 1, 2])), Err(E::Truncated));
        // Strings: length 0, a missing zero, bad UTF-8, running past the end.
        assert_eq!(Document::parse(&raw(&[2, b'a', 0, 0, 0, 0, 0])), Err(E::Length(0)));
        assert_eq!(Document::parse(&raw(&[2, b'a', 0, 1, 0, 0, 0, b'x'])), Err(E::Terminator));
        assert_eq!(Document::parse(&raw(&[2, b'a', 0, 2, 0, 0, 0, 0xc3, 0])), Err(E::Utf8));
        assert_eq!(Document::parse(&raw(&[2, b'a', 0, 9, 0, 0, 0, b'x', 0])), Err(E::Truncated));
        // Binary with a negative length.
        assert_eq!(Document::parse(&raw(&[5, b'a', 0, 0xff, 0xff, 0xff, 0xff, 0])), Err(E::Length(-1)));
        // An embedded document longer than its parent.
        assert_eq!(Document::parse(&raw(&[3, b'a', 0, 9, 0, 0, 0, 0])), Err(E::Truncated));
        // JavaScript with scope: too short, and a length that does not match.
        assert_eq!(Document::parse(&raw(&[0x0f, b'a', 0, 13, 0, 0, 0])), Err(E::Length(13)));
        let mut jsws = vec![0x0f, b'a', 0, 15, 0, 0, 0, 1, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0];
        assert_eq!(Document::parse(&raw(&jsws)), Err(E::Length(15)));
        jsws[3] = 14;
        jsws.pop();
        assert!(Document::parse(&raw(&jsws)).is_ok());
    }

    fn big_i32() -> i32 {
        MAX_DOCUMENT_SIZE as i32 + 1
    }

    fn nested(levels: usize) -> Document {
        let mut doc = Document::new();
        for _ in 1..levels {
            doc = Document::new().with("d", Bson::Document(doc));
        }
        doc
    }

    #[test]
    fn depth_limit() {
        let ok = nested(MAX_DEPTH);
        let bytes = ok.to_bytes().unwrap();
        assert_eq!(Document::parse(&bytes).unwrap(), ok);
        assert_eq!(nested(MAX_DEPTH + 1).to_bytes(), Err(BsonError::Unwritable));
        // The same, built by hand: one more level around the bytes above.
        let mut inner = vec![3, b'd', 0];
        inner.extend_from_slice(&bytes);
        assert_eq!(Document::parse(&raw(&inner)), Err(BsonError::Depth));
        // Arrays and scopes count too.
        let mut v = Bson::Null;
        for _ in 0..MAX_DEPTH {
            v = Bson::Array(vec![v]);
        }
        assert_eq!(Document::new().with("a", v).to_bytes(), Err(BsonError::Unwritable));
    }

    #[test]
    fn element_limit() {
        let many = Document::new().with("a", Bson::Array(vec![Bson::Null; MAX_ELEMENTS]));
        assert_eq!(many.to_bytes(), Err(BsonError::Unwritable));
        // MAX_ELEMENTS + 1 nulls with empty keys.
        let mut inner = Vec::with_capacity(2 * (MAX_ELEMENTS + 1));
        for _ in 0..=MAX_ELEMENTS {
            inner.extend_from_slice(&[0x0a, 0]);
        }
        assert_eq!(Document::parse(&raw(&inner)), Err(BsonError::TooManyElements));
        inner.truncate(2 * MAX_ELEMENTS);
        assert_eq!(Document::parse(&raw(&inner)).unwrap().len(), MAX_ELEMENTS);
    }

    #[test]
    fn writers_refuse_what_readers_refuse() {
        let huge = "x".repeat(MAX_DOCUMENT_SIZE);
        assert!(matches!(Document::new().with("s", s(&huge)).to_bytes(), Err(BsonError::Unwritable)));
        let half = "x".repeat(MAX_DOCUMENT_SIZE / 2);
        let two = Document::new().with("a", s(&half)).with("b", s(&half));
        assert!(matches!(two.to_bytes(), Err(BsonError::Unwritable)));
        let bin = Bson::Binary { subtype: 0, bytes: vec![0; MAX_DOCUMENT_SIZE] };
        assert!(matches!(Document::new().with("b", bin).to_bytes(), Err(BsonError::Unwritable)));
        assert_eq!(Document::new().with("a\0b", Bson::Null).to_bytes(), Err(BsonError::Unwritable));
        let re = Bson::Regex { pattern: "a\0".into(), options: String::new() };
        assert_eq!(Document::new().with("r", re).to_bytes(), Err(BsonError::Unwritable));
        // The largest document a writer allows reads back.
        let fits = "x".repeat(MAX_DOCUMENT_SIZE - 4 - 3 - 4 - 1 - 1);
        let doc = Document::new().with("s", s(&fits));
        let bytes = doc.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_DOCUMENT_SIZE);
        assert_eq!(Document::parse(&bytes).unwrap(), doc);
    }

    #[test]
    fn accessors() {
        let mut doc = every_type();
        assert_eq!(doc.command_name(), Some("double"));
        assert_eq!(Document::new().command_name(), None);
        assert_eq!(doc.get("string").and_then(Bson::as_str), Some("héllo\0world"));
        assert_eq!(doc.get("i32").and_then(Bson::as_i32), Some(i32::MIN));
        assert_eq!(doc.get("i64").and_then(Bson::as_i64), Some(i64::MAX));
        assert_eq!(doc.get("double").and_then(Bson::as_f64), Some(-2.5));
        assert_eq!(doc.get("t").and_then(Bson::as_bool), Some(true));
        assert_eq!(doc.get("doc").and_then(Bson::as_document).map(Document::len), Some(1));
        assert_eq!(doc.get("array").and_then(Bson::as_array).map(<[Bson]>::len), Some(3));
        assert_eq!(doc.get("i32").and_then(Bson::as_str), None);
        assert_eq!(doc.get("string").and_then(Bson::as_i64), None);
        *doc.get_mut("t").unwrap() = Bson::Boolean(false);
        assert_eq!(doc.get("t"), Some(&Bson::Boolean(false)));
        assert!(doc.get_mut("missing").is_none());
        let keys: Vec<&str> = doc.iter().map(|(k, _)| k).take(3).collect();
        assert_eq!(keys, ["double", "string", "doc"]);
        let mut m = Msg::new(Document::new().with("insert", s("c")));
        m.sequences.push(Sequence { identifier: "documents".into(), documents: vec![Document::new()] });
        assert_eq!(m.sequence("documents").map(|q| q.documents.len()), Some(1));
        assert!(m.sequence("updates").is_none());
    }

    #[test]
    fn element_budget_is_shared_the_same_way_by_reader_and_writer() {
        // Half the budget in the body and half in a sequence fits; one more
        // element anywhere does not, for the writer and the reader alike.
        let half = |n: usize| Document::new().with("a", Bson::Array(vec![Bson::Null; n]));
        let n = MAX_ELEMENTS / 2 - 1;
        let mut m = Msg::new(half(n));
        m.sequences.push(Sequence { identifier: "d".into(), documents: vec![half(n)] });
        let ok = Message { request_id: 0, response_to: 0, body: Body::Msg(m.clone()) };
        let bytes = ok.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), ok);
        m.sequences[0].documents[0] = half(n + 1);
        let over = Message { request_id: 0, response_to: 0, body: Body::Msg(m) };
        assert_eq!(over.to_bytes(), Err(MessageError::Unwritable));
        // The same by hand: one more null at the end of the sequence's
        // array, with the four lengths around it fixed.
        let mut longer = bytes.clone();
        longer.truncate(longer.len() - 2); // the array's and document's zeros
        let key = n.to_string();
        longer.push(element_type::NULL);
        longer.extend_from_slice(key.as_bytes());
        longer.extend_from_slice(&[0, 0, 0]);
        let grow = (2 + key.len()) as i32;
        // Lengths to fix: the message, the sequence, the document, the array.
        let body_len = i32::from_le_bytes(bytes[21..25].try_into().unwrap()) as usize;
        let seq_at = 21 + body_len + 1;
        let doc_at = seq_at + 4 + 2;
        let arr_at = doc_at + 4 + 3;
        for at in [0, seq_at, doc_at, arr_at] {
            let v = i32::from_le_bytes(longer[at..at + 4].try_into().unwrap()) + grow;
            longer[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        assert_eq!(Message::parse(&longer), Err(MessageError::Bson(BsonError::TooManyElements)));
    }

    #[test]
    fn crc32c_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn op_msg_with_sequence_and_checksum() {
        let insert = Document::new().with("insert", s("users")).with("$db", s("app"));
        let docs = vec![Document::new().with("_id", Bson::Int32(1)), Document::new().with("_id", Bson::Int32(2))];
        let m = Message {
            request_id: 3,
            response_to: 0,
            body: Body::Msg(Msg {
                flags: flag::CHECKSUM_PRESENT | flag::EXHAUST_ALLOWED,
                body: insert,
                sequences: vec![Sequence { identifier: "documents".into(), documents: docs }],
            }),
        };
        let bytes = m.to_bytes().unwrap();
        let header = Header::parse(&bytes[..HEADER_LEN]).unwrap();
        assert_eq!(header.length as usize, bytes.len());
        assert_eq!(header.op_code, op_code::MSG);
        let crc = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
        assert_eq!(crc, crc32c(&bytes[..bytes.len() - 4]));
        assert_eq!(Message::parse(&bytes).unwrap(), m);
        // A changed byte fails the checksum.
        let mut bad = bytes.clone();
        bad[30] ^= 1;
        assert!(matches!(Message::parse(&bad), Err(MessageError::Checksum { found, .. }) if found == crc));
    }

    #[test]
    fn sequence_before_body_reads() {
        // Kind 1 first, then kind 0, by hand.
        let body = Document::new().with("x", Bson::Int32(1)).to_bytes().unwrap();
        let mut data = 0u32.to_le_bytes().to_vec();
        data.extend_from_slice(&[1, 6, 0, 0, 0, b'd', 0]);
        data.push(0);
        data.extend_from_slice(&body);
        let bytes = frame(op_code::MSG, &data);
        let m = Message::parse(&bytes).unwrap();
        let Body::Msg(msg) = m.body else { panic!() };
        assert_eq!(msg.sequences, vec![Sequence { identifier: "d".into(), documents: vec![] }]);
        assert_eq!(msg.body.get("x"), Some(&Bson::Int32(1)));
    }

    /// A message with `op` and the bytes after the header.
    fn frame(op: i32, data: &[u8]) -> Vec<u8> {
        let mut b = ((HEADER_LEN + data.len()) as i32).to_le_bytes().to_vec();
        b.extend_from_slice(&1i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&op.to_le_bytes());
        b.extend_from_slice(data);
        b
    }

    #[test]
    fn handshake_query_and_reply() {
        let q = Message {
            request_id: 1,
            response_to: 0,
            body: Body::Query(Query {
                flags: 4,
                collection: "admin.$cmd".into(),
                number_to_skip: 0,
                number_to_return: -1,
                query: Document::new().with("isMaster", Bson::Int32(1)),
                fields: None,
            }),
        };
        let bytes = q.to_bytes().unwrap();
        // flags, "admin.$cmd\0", skip, return, then { isMaster: 1 } (19 bytes).
        assert_eq!(bytes.len(), 16 + 4 + 11 + 4 + 4 + 19);
        assert_eq!(&bytes[20..31], b"admin.$cmd\0");
        assert_eq!(&bytes[35..39], &[0xff; 4]);
        assert_eq!(Message::parse(&bytes).unwrap(), q.clone());
        let mut with_fields = q.clone();
        if let Body::Query(query) = &mut with_fields.body {
            query.fields = Some(Document::new().with("a", Bson::Int32(1)));
        }
        let b = with_fields.to_bytes().unwrap();
        assert_eq!(Message::parse(&b).unwrap(), with_fields);

        let hello = Document::new().with("ismaster", Bson::Boolean(true)).with("ok", Bson::Double(1.0));
        let r = q.reply(9, Body::Reply(Reply { flags: 8, ..Reply::new(vec![hello]) }));
        assert_eq!(r.response_to, 1);
        let bytes = r.to_bytes().unwrap();
        assert_eq!(Header::parse(&bytes[..HEADER_LEN]).unwrap().op_code, op_code::REPLY);
        assert_eq!(&bytes[32..36], &1i32.to_le_bytes()); // numberReturned
        assert_eq!(Message::parse(&bytes).unwrap(), r);
    }

    #[test]
    fn compressed_and_other_messages() {
        let c = Message {
            request_id: 2,
            response_to: 0,
            body: Body::Compressed(Compressed {
                original_op_code: op_code::MSG,
                uncompressed_size: 100,
                compressor: compressor::ZSTD,
                data: vec![1, 2, 3],
            }),
        };
        let bytes = c.to_bytes().unwrap();
        assert_eq!(bytes.len(), 16 + 9 + 3);
        assert_eq!(Message::parse(&bytes).unwrap(), c);
        let o =
            Message { request_id: 2, response_to: 0, body: Body::Other { op_code: op_code::INSERT, data: vec![9] } };
        let bytes = o.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), o);
        let bad = Message { request_id: 2, response_to: 0, body: Body::Other { op_code: op_code::MSG, data: vec![] } };
        assert_eq!(bad.to_bytes(), Err(MessageError::Unwritable));
    }

    #[test]
    fn every_truncated_message_prefix_waits() {
        let m = Message {
            request_id: 5,
            response_to: 4,
            body: Body::Msg(Msg {
                flags: flag::CHECKSUM_PRESENT,
                body: every_type(),
                sequences: vec![Sequence { identifier: "s".into(), documents: vec![every_type()] }],
            }),
        };
        let bytes = m.to_bytes().unwrap();
        for n in 0..bytes.len() {
            assert_eq!(Message::parse(&bytes[..n]), Err(MessageError::Truncated), "{n} bytes");
            assert_eq!(Frames::new().decode(&bytes[..n], false), Ok(Step::Need));
        }
        assert_eq!(Message::parse(&bytes).unwrap(), m);
    }

    #[test]
    fn message_errors() {
        use MessageError as E;
        let body = Document::new().to_bytes().unwrap();
        let with = |flags: u32, rest: &[u8]| {
            let mut d = flags.to_le_bytes().to_vec();
            d.extend_from_slice(rest);
            frame(op_code::MSG, &d)
        };
        let sec0: Vec<u8> = [&[0u8][..], &body].concat();
        // Length.
        assert_eq!(Message::parse(&15i32.to_le_bytes()), Err(E::Length(15)));
        assert_eq!(Message::parse(&(-1i32).to_le_bytes()), Err(E::Length(-1)));
        assert_eq!(Message::parse(&(MAX_MESSAGE_SIZE as i32 + 1).to_le_bytes()), Err(E::Length(48_000_001)));
        // Truncated flags, and a checksum flag with no room.
        assert_eq!(Message::parse(&frame(op_code::MSG, &[0, 0])), Err(E::Truncated));
        assert_eq!(Message::parse(&with(1, &[0, 0])), Err(E::Truncated));
        // Flags.
        assert_eq!(Message::parse(&with(1 << 2, &sec0)), Err(E::Flags(4)));
        // Optional bits pass, and are dropped.
        let m = Message::parse(&with(1 << 20 | 1 << 1, &sec0)).unwrap();
        assert!(matches!(m.body, Body::Msg(Msg { flags: flag::MORE_TO_COME, .. })));
        // Section kinds and body counts.
        assert_eq!(Message::parse(&with(0, &[2])), Err(E::SectionKind(2)));
        assert_eq!(Message::parse(&with(0, &[])), Err(E::BodyCount(0)));
        assert_eq!(Message::parse(&with(0, &[sec0.clone(), sec0.clone()].concat())), Err(E::BodyCount(2)));
        assert_eq!(Message::parse(&with(0, &[0, 5, 0, 0])), Err(E::Bson(BsonError::Truncated)));
        // Sequence sizes.
        assert_eq!(Message::parse(&with(0, &[1, 4, 0, 0, 0])), Err(E::SequenceLength(4)));
        assert_eq!(Message::parse(&with(0, &[1, 9, 0, 0, 0, b'a', 0])), Err(E::SequenceLength(9)));
        assert_eq!(Message::parse(&with(0, &[1, 6, 0])), Err(E::Truncated));
        assert_eq!(Message::parse(&with(0, &[1, 6, 0, 0, 0, b'a', b'b'])), Err(E::Bson(BsonError::Terminator)));
        assert_eq!(Message::parse(&with(0, &[1, 8, 0, 0, 0, b'a', 0, 5, 0])), Err(E::Bson(BsonError::Truncated)));
        // Query: truncated, and bytes after the fields document.
        assert_eq!(Message::parse(&frame(op_code::QUERY, &[0, 0, 0, 0, b'a', 0, 0])), Err(E::Truncated));
        assert_eq!(Message::parse(&frame(op_code::QUERY, &[0, 0, 0, 0, b'a'])), Err(E::Bson(BsonError::Terminator)));
        let mut q = vec![0, 0, 0, 0, b'a', 0, 0, 0, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&body);
        assert!(Message::parse(&frame(op_code::QUERY, &q)).is_ok());
        q.push(7);
        assert_eq!(Message::parse(&frame(op_code::QUERY, &q)), Err(E::Bson(BsonError::Truncated)));
        q.pop();
        q.extend_from_slice(&body);
        assert!(Message::parse(&frame(op_code::QUERY, &q)).is_ok());
        q.extend_from_slice(&body);
        assert_eq!(Message::parse(&frame(op_code::QUERY, &q)), Err(E::Trailing));
        // Reply: counts that do not match.
        let reply = |n: i32, docs: usize| {
            let mut d = vec![0; 16];
            d.extend_from_slice(&n.to_le_bytes());
            for _ in 0..docs {
                d.extend_from_slice(&body);
            }
            frame(op_code::REPLY, &d)
        };
        assert!(Message::parse(&reply(2, 2)).is_ok());
        assert_eq!(Message::parse(&reply(1, 2)), Err(E::NumberReturned(1)));
        assert_eq!(Message::parse(&reply(3, 2)), Err(E::NumberReturned(3)));
        assert_eq!(Message::parse(&reply(-1, 0)), Err(E::NumberReturned(-1)));
        assert_eq!(Message::parse(&frame(op_code::REPLY, &[0; 19])), Err(E::Truncated));
        // Compressed, truncated.
        assert_eq!(Message::parse(&frame(op_code::COMPRESSED, &[0; 8])), Err(E::Truncated));
    }

    #[test]
    fn document_count_limit() {
        let empty = Document::new();
        let mut d = 0u32.to_le_bytes().to_vec();
        d.extend_from_slice(&[0, 5, 0, 0, 0, 0]);
        let size = 4 + 2 + 5 * (MAX_DOCUMENTS + 1);
        d.push(1);
        d.extend_from_slice(&(size as i32).to_le_bytes());
        d.extend_from_slice(&[b'd', 0]);
        for _ in 0..=MAX_DOCUMENTS {
            d.extend_from_slice(&[5, 0, 0, 0, 0]);
        }
        assert_eq!(Message::parse(&frame(op_code::MSG, &d)), Err(MessageError::TooManyDocuments));
        let seq = |id: &str, n: usize| Sequence { identifier: id.into(), documents: vec![empty.clone(); n] };
        let one = Msg { flags: 0, body: empty.clone(), sequences: vec![seq("a", MAX_DOCUMENTS + 1)] };
        let m = Message { request_id: 0, response_to: 0, body: Body::Msg(one) };
        assert_eq!(m.to_bytes(), Err(MessageError::Unwritable));
        let three = vec![seq("a", MAX_DOCUMENTS), seq("b", MAX_DOCUMENTS), seq("c", 1)];
        let m = Message {
            request_id: 0,
            response_to: 0,
            body: Body::Msg(Msg { sequences: three, ..Msg::new(empty.clone()) }),
        };
        assert_eq!(m.to_bytes(), Err(MessageError::Unwritable));
        let r =
            Message { request_id: 0, response_to: 0, body: Body::Reply(Reply::new(vec![empty; MAX_DOCUMENTS + 1])) };
        assert_eq!(r.to_bytes(), Err(MessageError::Unwritable));
    }

    #[test]
    fn message_writers_refuse_bad_input() {
        let mut m = Msg::new(Document::new());
        m.flags = 1 << 5;
        let bad = Message { request_id: 0, response_to: 0, body: Body::Msg(m) };
        assert_eq!(bad.to_bytes(), Err(MessageError::Unwritable));
        let mut m = Msg::new(Document::new());
        m.sequences.push(Sequence { identifier: "a\0".into(), documents: vec![] });
        let bad = Message { request_id: 0, response_to: 0, body: Body::Msg(m) };
        assert_eq!(bad.to_bytes(), Err(MessageError::Unwritable));
        let big = Message {
            request_id: 0,
            response_to: 0,
            body: Body::Other { op_code: 1234, data: vec![0; MAX_MESSAGE_SIZE] },
        };
        assert_eq!(big.to_bytes(), Err(MessageError::Unwritable));
        // Two full documents in a sequence fit; a third does not.
        let full = Document::new().with("s", s(&"x".repeat(MAX_DOCUMENT_SIZE - 13)));
        let mut m = Msg::new(Document::new());
        m.sequences.push(Sequence { identifier: "d".into(), documents: vec![full.clone(); 2] });
        let ok = Message { request_id: 0, response_to: 0, body: Body::Msg(m.clone()) };
        let bytes = ok.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), ok);
        m.sequences[0].documents.push(full);
        let bad = Message { request_id: 0, response_to: 0, body: Body::Msg(m) };
        assert!(matches!(bad.to_bytes(), Err(MessageError::Unwritable)));
    }

    #[test]
    fn stream_splits_messages_and_keeps_body_errors() {
        let a = msg(1, Document::new().with("ping", Bson::Int32(1))).to_bytes().unwrap();
        let b = msg(2, Document::new().with("hello", Bson::Int32(1))).to_bytes().unwrap();
        for (body, terminal) in [(&[0, 0, 0, 0, 9][..], true), (&[0, 0, 0, 0][..], false)] {
            let bytes = [&a[..], &frame(op_code::MSG, body), &b].concat();
            contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_MESSAGE_SIZE);
            let (items, failure) = decode_all(Frames::new, &bytes);
            let ids: Vec<_> = items.into_iter().map(|m| m.map(|m| m.request_id)).collect();
            if terminal {
                assert_eq!(ids, [Ok(1)]);
                assert_eq!(failure, Some(Fail::Protocol(MessageError::SectionKind(9))));
            } else {
                assert_eq!(ids, [Ok(1), Err(MessageError::BodyCount(0)), Ok(2)]);
                assert_eq!(failure, None);
            }
        }
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&[3, 0, 0, 0]), 4);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(MessageError::Length(3)))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&Fail::Protocol(MessageError::Length(3))));
    }

    #[test]
    fn stream_limit() {
        let a = msg(1, Document::new().with("ping", Bson::Int32(1))).to_bytes().unwrap();
        assert_eq!(decode_all(|| Frames::with_limit(a.len()), &a).0.len(), 1);
        assert_eq!(decode_all(|| Frames::with_limit(a.len() - 1), &a).1,
            Some(Fail::Protocol(MessageError::Length(a.len() as i32))));
        assert_eq!(Frames::with_limit(0).limit(), HEADER_LEN);
        assert_eq!(Frames::with_limit(usize::MAX).limit(), MAX_MESSAGE_SIZE);
    }

    #[test]
    fn stream_takes_many_small_messages_in_linear_time() {
        let one = msg(1, Document::new().with("ping", Bson::Int32(1))).to_bytes().unwrap();
        let bytes = one.repeat(100_000);
        let started = std::time::Instant::now();
        let (items, failure) = decode_all(Frames::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(items.len(), 100_000);
        assert!(items.iter().all(Result::is_ok));
        assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
    }

    #[test]
    fn stream_holds_at_most_one_message() {
        let a = msg(1, Document::new().with("ping", Bson::Int32(1))).to_bytes().unwrap();
        let bytes = a.repeat(1000);
        contract::check_decode_with_alloc_limit(|| Frames::with_limit(a.len()), &bytes, 2 * a.len());
        assert_eq!(decode_all(|| Frames::with_limit(a.len()), &bytes).0.len(), 1000);
        let mut stream = Stream::new(Frames::with_limit(16));
        assert_eq!(stream.push(&vec![0x41; 1 << 20]), 16);
        assert_eq!(stream.push(&[0x41; 8]), 0);
        assert_eq!(stream.buffered(), 16);
        assert!(stream.next().unwrap().is_err());
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn writers_stop_at_the_limit_before_holding_more() {
        // Each level's key alone nearly fills a document. A writer that
        // wrote every key before checking would hold four times the limit.
        let key = "k".repeat(MAX_DOCUMENT_SIZE - 1);
        let mut doc = Document::new().with(key.clone(), Bson::Null);
        for _ in 0..3 {
            doc = Document::new().with(key.clone(), Bson::Document(doc));
        }
        let mut out = Vec::new();
        let mut budget = MAX_ELEMENTS;
        assert!(
            matches!(write_top(&doc, MAX_DOCUMENT_SIZE, &mut budget, &mut out), Err(BsonError::Unwritable))
        );
        assert!(out.len() <= MAX_DOCUMENT_SIZE, "held {} bytes", out.len());
        // Strings and binary inside a nested document, the same.
        let half = "x".repeat(MAX_DOCUMENT_SIZE / 2);
        let inner = Document::new().with("a", s(&half)).with("b", s(&half)).with("c", s(&half));
        let mut out = Vec::new();
        let doc = Document::new().with("d", Bson::Document(inner));
        assert!(matches!(write_top(&doc, MAX_DOCUMENT_SIZE, &mut budget, &mut out), Err(BsonError::Unwritable)));
        assert!(out.len() <= MAX_DOCUMENT_SIZE);
    }

    #[test]
    fn a_reply_can_carry_a_full_size_document() {
        // A find reply with one document of the largest size in its cursor.
        let full = Document::new().with("s", s(&"x".repeat(MAX_DOCUMENT_SIZE - 13)));
        assert_eq!(full.to_bytes().unwrap().len(), MAX_DOCUMENT_SIZE);
        let cursor = Document::new()
            .with("firstBatch", Bson::Array(vec![Bson::Document(full)]))
            .with("id", Bson::Int64(0))
            .with("ns", s("db.c"));
        let body = Document::new().with("cursor", Bson::Document(cursor)).with("ok", Bson::Double(1.0));
        assert!(matches!(body.to_bytes(), Err(BsonError::Unwritable)));
        let m = msg(1, body.clone());
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), m);
        let r = Message { request_id: 1, response_to: 0, body: Body::Reply(Reply::new(vec![body])) };
        let bytes = r.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), r);
        // The command limit holds too.
        let over = Document::new().with("s", s(&"x".repeat(MAX_COMMAND_SIZE - 12)));
        assert!(matches!(msg(1, over).to_bytes(), Err(MessageError::Unwritable)));
        // A sequence document is held to the document limit.
        let big = Document::new().with("s", s(&"x".repeat(MAX_DOCUMENT_SIZE - 12)));
        let mut m = Msg::new(Document::new());
        m.sequences.push(Sequence { identifier: "d".into(), documents: vec![big] });
        let m = Message { request_id: 1, response_to: 0, body: Body::Msg(m) };
        assert!(matches!(m.to_bytes(), Err(MessageError::Unwritable)));
    }

    #[test]
    fn body_fields_are_unique() {
        // Wire protocol, OP_MSG kind 0: top-level field names are unique.
        let body = Document::new().with("ping", Bson::Int32(1)).with("$db", s("a")).with("$db", s("b"));
        assert_eq!(msg(1, body.clone()).to_bytes(), Err(MessageError::Unwritable));
        let mut d = 0u32.to_le_bytes().to_vec();
        d.push(0);
        d.extend_from_slice(&body.to_bytes().unwrap());
        assert_eq!(Message::parse(&frame(op_code::MSG, &d)), Err(MessageError::DuplicateField));
        // Repeated keys deeper down are still fine.
        let inner = Document::new().with("a", Bson::Null).with("a", Bson::Null);
        let ok = msg(1, Document::new().with("x", Bson::Document(inner)));
        assert_eq!(Message::parse(&ok.to_bytes().unwrap()).unwrap(), ok);
    }

    #[test]
    fn sequence_identifiers_are_not_in_the_body() {
        // Wire protocol, OP_MSG kind 1: the identifier must not also exist
        // in the body.
        let seq = |id: &str| Sequence { identifier: id.into(), documents: vec![] };
        let body = Document::new()
            .with("insert", s("c"))
            .with("documents", Bson::Array(vec![]))
            .with("a", Bson::Document(Document::new().with("b", Bson::Int32(1))))
            .with("$db", s("db"));
        for (id, bad) in [("documents", true), ("a.b", true), ("a", true), ("a.c", false), ("x.b", false), ("b", false)]
        {
            let m = Message {
                request_id: 1,
                response_to: 0,
                body: Body::Msg(Msg { sequences: vec![seq(id)], ..Msg::new(body.clone()) }),
            };
            let mut d = 0u32.to_le_bytes().to_vec();
            d.push(0);
            d.extend_from_slice(&body.to_bytes().unwrap());
            d.push(1);
            d.extend_from_slice(&((4 + id.len() + 1) as i32).to_le_bytes());
            d.extend_from_slice(id.as_bytes());
            d.push(0);
            let parsed = Message::parse(&frame(op_code::MSG, &d));
            if bad {
                assert_eq!(m.to_bytes(), Err(MessageError::Unwritable), "{id}");
                assert_eq!(parsed, Err(MessageError::DuplicateField), "{id}");
            } else {
                assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m, "{id}");
                assert!(parsed.is_ok(), "{id}");
            }
        }
    }

    #[test]
    fn a_full_bulk_write_fits() {
        // bulkWrite: a full batch in ops, and nsInfo beside it.
        let op = Document::new().with("insert", Bson::Int32(0)).with("document", Bson::Document(Document::new()));
        let body = Document::new().with("bulkWrite", Bson::Int32(1)).with("$db", s("admin"));
        let m = Msg {
            sequences: vec![
                Sequence { identifier: "ops".into(), documents: vec![op; MAX_DOCUMENTS] },
                Sequence { identifier: "nsInfo".into(), documents: vec![Document::new().with("ns", s("db.c"))] },
            ],
            ..Msg::new(body)
        };
        let m = Message { request_id: 1, response_to: 0, body: Body::Msg(m) };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), m);
    }

    #[test]
    fn compressed_sizes_are_checked() {
        let c = |size: i32, compressor: u8, data: Vec<u8>| Message {
            request_id: 1,
            response_to: 0,
            body: Body::Compressed(Compressed {
                original_op_code: op_code::MSG,
                uncompressed_size: size,
                compressor,
                data,
            }),
        };
        let raw = |size: i32, compressor: u8, data: &[u8]| {
            let mut d = op_code::MSG.to_le_bytes().to_vec();
            d.extend_from_slice(&size.to_le_bytes());
            d.push(compressor);
            d.extend_from_slice(data);
            frame(op_code::COMPRESSED, &d)
        };
        let too_big = (MAX_MESSAGE_SIZE - HEADER_LEN + 1) as i32;
        for (size, comp, data) in [
            (-1, compressor::ZLIB, vec![]),
            (too_big, compressor::ZLIB, vec![1]),
            (i32::MAX, compressor::SNAPPY, vec![]),
            (1, compressor::NOOP, vec![]),
        ] {
            assert_eq!(c(size, comp, data.clone()).to_bytes(), Err(MessageError::Unwritable));
            assert_eq!(Message::parse(&raw(size, comp, &data)), Err(MessageError::UncompressedSize(size)));
        }
        let ok = c(3, compressor::NOOP, vec![1, 2, 3]);
        let bytes = ok.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).unwrap(), ok);
        let ok = c(too_big - 1, compressor::ZSTD, vec![1]);
        assert!(ok.to_bytes().is_ok());
    }

    #[test]
    fn long_names_written_as_read() {
        // A sequence identifier and a collection name of the document size
        // limit and more: what reads also writes.
        for n in [MAX_DOCUMENT_SIZE - 1, MAX_DOCUMENT_SIZE, MAX_DOCUMENT_SIZE + 1] {
            let id = "x".repeat(n);
            let m = Message {
                request_id: 1,
                response_to: 0,
                body: Body::Msg(Msg {
                    sequences: vec![Sequence { identifier: id.clone(), documents: vec![] }],
                    ..Msg::new(Document::new())
                }),
            };
            let mut d = 0u32.to_le_bytes().to_vec();
            d.extend_from_slice(&[0, 5, 0, 0, 0, 0, 1]);
            d.extend_from_slice(&((4 + n + 1) as i32).to_le_bytes());
            d.extend_from_slice(id.as_bytes());
            d.push(0);
            let bytes = frame(op_code::MSG, &d);
            assert_eq!(Message::parse(&bytes).unwrap(), m);
            assert_eq!(m.to_bytes().unwrap(), bytes);
            let q = Message {
                request_id: 1,
                response_to: 0,
                body: Body::Query(Query {
                    flags: 0,
                    collection: id,
                    number_to_skip: 0,
                    number_to_return: 1,
                    query: Document::new(),
                    fields: None,
                }),
            };
            let bytes = q.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes).unwrap(), q);
        }
    }

    #[test]
    fn writers_send_no_unknown_flag_bits() {
        // OP_MSG flagBits: a sender sets unused bits to 0.
        let m = Message {
            request_id: 0,
            response_to: 0,
            body: Body::Msg(Msg { flags: 1 << 20, ..Msg::new(Document::new()) }),
        };
        assert_eq!(m.to_bytes(), Err(MessageError::Unwritable));
    }

    fn check(data: &[u8]) {
        contract::check_wire::<Document>(data);
        contract::check_wire::<Message>(data);
        contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_MESSAGE_SIZE);
        for message in decode_all(Frames::new, data).0.into_iter().flatten() {
            assert!(message.to_bytes().is_ok(), "{message:?}");
            contract::check_wire_value(&message);
        }
    }

    #[test]
    fn generated_inputs_obey_contracts() {
        let mut rng = Lcg::new(0x6d_6f6e_676f_6462);
        let mut seeds: Vec<Vec<u8>> = vec![every_type().to_bytes().unwrap()];
        let full = Msg {
            flags: flag::CHECKSUM_PRESENT,
            body: Document::new().with("insert", s("c")),
            sequences: vec![Sequence { identifier: "documents".into(), documents: vec![every_type()] }],
        };
        seeds.push(Message { request_id: 1, response_to: 0, body: Body::Msg(full) }.to_bytes().unwrap());
        seeds.push(msg(2, Document::new().with("ping", Bson::Int32(1))).to_bytes().unwrap());
        let query = Query {
            flags: 0,
            collection: "admin.$cmd".into(),
            number_to_skip: 0,
            number_to_return: -1,
            query: Document::new().with("hello", Bson::Int32(1)),
            fields: Some(Document::new()),
        };
        seeds.push(Message { request_id: 3, response_to: 0, body: Body::Query(query) }.to_bytes().unwrap());
        let reply = Reply::new(vec![every_type(), Document::new()]);
        seeds.push(Message { request_id: 4, response_to: 3, body: Body::Reply(reply) }.to_bytes().unwrap());
        for _ in 0..6000 {
            let mut data = if rng.coin() { rng.bytes(64) } else { seeds[rng.index(seeds.len())].clone() };
            mutate(&mut rng, &mut data);
            check(&data);
            // Bytes after a header, as each op code.
            for op in [op_code::MSG, op_code::QUERY, op_code::REPLY, op_code::COMPRESSED] {
                check(&frame(op, &data));
            }
        }
    }
}
