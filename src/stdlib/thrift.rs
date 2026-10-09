//! Apache Thrift: reading and writing messages and values in the binary
//! and compact protocols, and the framed transport, with no I/O.
//!
//! `EncodedMessage` and `Frame` implement `Wire`. `EncodedMessages` and
//! `codec::Frames<Frame>` decode unframed and framed streams. Values are
//! schema-free, with no IDL compiler, RPC session, `Service`, or live
//! transport.
//!
//! Thrift is a remote procedure call system. A client calls a method on a
//! service by sending a message: the method's name, a sequence number, and
//! its arguments as a struct of numbered fields. The server answers with a
//! message that carries the result, or an exception. Servers commonly
//! listen on TCP port 9090. This module follows the Apache Thrift binary
//! protocol and compact protocol specifications (`doc/specs` in the Apache
//! Thrift source).
//!
//! There are two ways to put values into bytes. The binary protocol writes
//! fixed-size big-endian numbers. Its messages come in a strict form, which
//! starts with a version number, and an older form, which starts with the
//! method name. The compact protocol writes numbers as variable-length
//! integers and packs field numbers and types together. Both carry the same
//! values: booleans, integers, doubles, byte strings, UUIDs, structs,
//! lists, sets and maps. Many servers wrap each message in a frame, which
//! is a 4-byte big-endian length followed by the message.
//!
//! Nothing here reads a socket. A world that plays a Thrift server
//! passes TCP bytes to [`Stream<codec::Frames<Frame>>`](fictionet::stdlib::codec::Stream), reads
//! each frame's [`EncodedMessage`], and writes
//! the reply's bytes back. Values are read without a schema, into a
//! tree of [`Value`]s, so world code decides what each field number
//! means. On a connection without frames, an [`EncodedMessages`] decoder takes
//! the bytes and gives back whole messages.
//!
//! Every reader checks lengths, counts and nesting against the limits
//! below, because the agent can send any bytes it likes. Every writer
//! checks the same limits, so what it writes always reads back.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
//! use fictionet::stdlib::thrift::{exception_kind, field, Field, EncodedMessage, Message, Protocol, Value};
//!
//! /// A calculator service with one method: i32 add(1: i32 a, 2: i32 b).
//! fn answer(call: &Message) -> Message {
//!     match (call.name.as_str(), field(&call.body, 1), field(&call.body, 2)) {
//!         ("add", Some(Value::I32(a)), Some(Value::I32(b))) => {
//!             // The result struct holds the return value in field 0.
//!             call.reply(vec![Field { id: 0, value: Value::I32(a.wrapping_add(*b)) }])
//!         }
//!         _ => call.exception(exception_kind::UNKNOWN_METHOD, "no such method"),
//!     }
//! }
//!
//! let mut stream = Stream::new(Frames::<fictionet::stdlib::thrift::Frame>::new());
//! let mut frames = Vec::new();
//! // A framed call to add(2, 3), sequence number 1, in the strict binary form.
//! pump(&mut stream, &[0, 0, 0, 30], |frame| frames.push(frame)).unwrap();
//! let header = [0x80, 0x01, 0x00, 0x01, 0, 0, 0, 3, b'a', b'd', b'd', 0, 0, 0, 1];
//! pump(&mut stream, &header, |frame| frames.push(frame)).unwrap();
//! let body = [0x08, 0, 1, 0, 0, 0, 2, 0x08, 0, 2, 0, 0, 0, 3, 0x00];
//! pump(&mut stream, &body, |frame| frames.push(frame)).unwrap();
//! finish(&mut stream, |_| unreachable!()).unwrap();
//! let payload = frames.pop().unwrap().0;
//! let EncodedMessage { message: call, protocol } = EncodedMessage::parse(&payload).unwrap();
//! assert_eq!(protocol, Protocol::Binary);
//! let reply = answer(&call).to_frame(protocol).unwrap().to_bytes().unwrap();
//! assert_eq!(
//!     reply,
//!     [
//!         0, 0, 0, 23, // the frame's length
//!         0x80, 0x01, 0x00, 0x02, // version 1, a reply
//!         0, 0, 0, 3, b'a', b'd', b'd', 0, 0, 0, 1, // name and sequence number
//!         0x08, 0, 0, 0, 0, 0, 5, // field 0, an i32: 5
//!         0x00, // the end of the struct
//!     ]
//! );
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use fictionet::stdlib::codec::leb128;
use fictionet::stdlib::codec::{Decode, Reader as ByteReader, Step, Truncated, Wire, Work};

/// The TCP port Thrift servers commonly listen on.
pub const PORT: u16 = 9090;
/// The length of a frame's header: a 4-byte big-endian length.
pub const FRAME_HEADER_LEN: usize = 4;
/// The longest frame payload, the default in Apache Thrift.
pub const MAX_FRAME: usize = 16_384_000;
/// The longest byte string, including a message's name.
pub const MAX_BINARY_LEN: usize = MAX_FRAME;
/// The longest standalone value, allowing a byte string and its length prefix.
pub const MAX_VALUE_LEN: usize = MAX_BINARY_LEN + 10;
/// The most elements one list or set may hold, or entries one map.
pub const MAX_CONTAINER_LEN: usize = 1_000_000;
/// The most values one read may hold, counting every field, element, key
/// and container, at any depth. It bounds the memory a read takes.
pub const MAX_VALUES: usize = 1 << 20;
/// The deepest nesting of values. A message's body is at depth 1, its
/// fields at depth 2, and so on. Apache Thrift uses the same default.
pub const MAX_DEPTH: usize = 64;
/// The longest message [`EncodedMessages`] reads or [`EncodedMessage`] reads and
/// writes. [`Message::to_frame`] enforces this limit too. It is the same
/// as [`MAX_FRAME`].
pub const MAX_MESSAGE: usize = MAX_FRAME;
/// The most elements or entries a reader sets room aside for before it
/// reads them. A list may claim more than it holds, and lists nest, so
/// room past this grows only as elements arrive.
pub const MAX_PREALLOC: usize = 1024;

/// The kinds of exception a server reports in an application exception.
pub mod exception_kind {
    /// A failure of no other kind.
    pub const UNKNOWN: i32 = 0;
    /// The service has no method by the call's name.
    pub const UNKNOWN_METHOD: i32 = 1;
    /// The message's type was not one the server expected.
    pub const INVALID_MESSAGE_TYPE: i32 = 2;
    /// A reply's method name did not match the call's.
    pub const WRONG_METHOD_NAME: i32 = 3;
    /// A reply's sequence number did not match the call's.
    pub const BAD_SEQUENCE_ID: i32 = 4;
    /// A reply carried no result and no declared exception.
    pub const MISSING_RESULT: i32 = 5;
    /// The server failed while handling the call.
    pub const INTERNAL_ERROR: i32 = 6;
    /// The call's bytes could not be read.
    pub const PROTOCOL_ERROR: i32 = 7;
    /// A transform the call asked for is not supported.
    pub const INVALID_TRANSFORM: i32 = 8;
    /// The protocol the call used is not supported.
    pub const INVALID_PROTOCOL: i32 = 9;
    /// The kind of client is not supported.
    pub const UNSUPPORTED_CLIENT_TYPE: i32 = 10;
}

/// How values are put into bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// The binary protocol, with messages in the strict form.
    Binary,
    /// The binary protocol, with messages in the old form, which has no
    /// version number. Values are the same as in [`Protocol::Binary`].
    BinaryOld,
    /// The compact protocol.
    Compact,
}

impl Protocol {
    fn compact(self) -> bool {
        self == Protocol::Compact
    }
}

/// The type of a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    /// A boolean.
    Bool,
    /// A signed 8-bit integer (`i8`, also called `byte`).
    Byte,
    /// A signed 16-bit integer.
    I16,
    /// A signed 32-bit integer.
    I32,
    /// A signed 64-bit integer.
    I64,
    /// A 64-bit floating point number.
    Double,
    /// A byte string. Thrift's `string` and `binary` are both this.
    Binary,
    /// A 16-byte UUID.
    Uuid,
    /// A struct: numbered fields. Exceptions and unions are structs too.
    Struct,
    /// A list of values of one type.
    List,
    /// A set of values of one type.
    Set,
    /// A map from keys of one type to values of one type.
    Map,
}

impl Type {
    /// The type's code in the binary protocol.
    pub fn binary_code(self) -> u8 {
        match self {
            Type::Bool => 2,
            Type::Byte => 3,
            Type::Double => 4,
            Type::I16 => 6,
            Type::I32 => 8,
            Type::I64 => 10,
            Type::Binary => 11,
            Type::Struct => 12,
            Type::Map => 13,
            Type::Set => 14,
            Type::List => 15,
            Type::Uuid => 16,
        }
    }

    /// The type for a code in the binary protocol, if there is one. Code 0
    /// ends a struct and code 1 (void) never carries a value, so neither
    /// is a type here.
    pub fn from_binary_code(code: u8) -> Option<Type> {
        Some(match code {
            2 => Type::Bool,
            3 => Type::Byte,
            4 => Type::Double,
            6 => Type::I16,
            8 => Type::I32,
            10 => Type::I64,
            11 => Type::Binary,
            12 => Type::Struct,
            13 => Type::Map,
            14 => Type::Set,
            15 => Type::List,
            16 => Type::Uuid,
            _ => return None,
        })
    }

    /// The type's code in the compact protocol. A boolean is 1 here. In a
    /// field header, 1 means true and 2 means false.
    pub fn compact_code(self) -> u8 {
        match self {
            Type::Bool => 1,
            Type::Byte => 3,
            Type::I16 => 4,
            Type::I32 => 5,
            Type::I64 => 6,
            Type::Double => 7,
            Type::Binary => 8,
            Type::List => 9,
            Type::Set => 10,
            Type::Map => 11,
            Type::Struct => 12,
            Type::Uuid => 13,
        }
    }

    /// The type for a code in the compact protocol, if there is one. Both
    /// 1 and 2 are booleans, since writers differ on which they use for
    /// the elements of a list, set or map.
    pub fn from_compact_code(code: u8) -> Option<Type> {
        Some(match code {
            1 | 2 => Type::Bool,
            3 => Type::Byte,
            4 => Type::I16,
            5 => Type::I32,
            6 => Type::I64,
            7 => Type::Double,
            8 => Type::Binary,
            9 => Type::List,
            10 => Type::Set,
            11 => Type::Map,
            12 => Type::Struct,
            13 => Type::Uuid,
            _ => return None,
        })
    }
}

/// A value of any type, read without a schema. Two values are equal when
/// they write the same bytes: a NaN double equals a NaN with the same bits,
/// and 0.0 does not equal -0.0.
#[derive(Clone, Debug)]
pub enum Value {
    /// A boolean.
    Bool(bool),
    /// A signed 8-bit integer.
    Byte(i8),
    /// A signed 16-bit integer.
    I16(i16),
    /// A signed 32-bit integer.
    I32(i32),
    /// A signed 64-bit integer.
    I64(i64),
    /// A 64-bit floating point number.
    Double(f64),
    /// A byte string. A Thrift `string` holds UTF-8, but nothing on the
    /// wire says which byte strings are strings, so none is checked.
    Binary(Vec<u8>),
    /// A UUID's 16 bytes, in the order they are sent.
    Uuid([u8; 16]),
    /// A struct's fields, in the order they are sent.
    Struct(Vec<Field>),
    /// A list.
    List(List),
    /// A set. Its elements are kept in the order they are sent, duplicates
    /// included.
    Set(List),
    /// A map.
    Map(Map),
}

/// One field of a struct: its number and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field's number, from the schema.
    pub id: i16,
    /// The field's value. Its type is sent along with it.
    pub value: Value,
}

/// The elements of a list or set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    /// The type of every element.
    pub elem: Type,
    /// The elements. A writer refuses an element of another type.
    pub items: Vec<Value>,
}

/// The entries of a map.
/// Compact writers refuse empty maps with key or value types other than
/// [`Type::Byte`], since the encoding cannot preserve those types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Map {
    /// The type of every key.
    pub key: Type,
    /// The type of every value.
    pub value: Type,
    /// The keys and values, in the order they are sent, duplicates
    /// included. An empty map in the compact protocol carries no types,
    /// so reading one gives [`Type::Byte`] for both.
    pub entries: Vec<(Value, Value)>,
}

impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Byte(a), Value::Byte(b)) => a == b,
            (Value::I16(a), Value::I16(b)) => a == b,
            (Value::I32(a), Value::I32(b)) => a == b,
            (Value::I64(a), Value::I64(b)) => a == b,
            (Value::Double(a), Value::Double(b)) => a.to_bits() == b.to_bits(),
            (Value::Binary(a), Value::Binary(b)) => a == b,
            (Value::Uuid(a), Value::Uuid(b)) => a == b,
            (Value::Struct(a), Value::Struct(b)) => a == b,
            (Value::List(a), Value::List(b)) | (Value::Set(a), Value::Set(b)) => a == b,
            (Value::Map(a), Value::Map(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

impl Value {
    /// The value's type.
    pub fn ty(&self) -> Type {
        match self {
            Value::Bool(_) => Type::Bool,
            Value::Byte(_) => Type::Byte,
            Value::I16(_) => Type::I16,
            Value::I32(_) => Type::I32,
            Value::I64(_) => Type::I64,
            Value::Double(_) => Type::Double,
            Value::Binary(_) => Type::Binary,
            Value::Uuid(_) => Type::Uuid,
            Value::Struct(_) => Type::Struct,
            Value::List(_) => Type::List,
            Value::Set(_) => Type::Set,
            Value::Map(_) => Type::Map,
        }
    }

    /// Reads a value of type `ty` from the start of `b`, and returns it
    /// with how many bytes of `b` it took. The value is at depth 1.
    /// Refuses invalid encodings and values over [`MAX_VALUE_LEN`],
    /// [`MAX_DEPTH`], or [`MAX_VALUES`].
    fn parse_prefix(protocol: Protocol, ty: Type, b: &[u8]) -> Result<(Value, usize), Error> {
        let mut r = Fields::new(&b[..b.len().min(MAX_VALUE_LEN + 1)], protocol.compact());
        let result = r.value(ty, 1);
        if r.cursor.position() > MAX_VALUE_LEN
            || (result == Err(Error::Truncated) && b.len() > MAX_VALUE_LEN)
        {
            return Err(Error::TooLong);
        }
        Ok((result?, r.cursor.position()))
    }
}

/// A standalone value with its protocol and type supplied by the caller.
/// `COMPACT` selects compact encoding; otherwise the binary encoding is used.
/// `TYPE` is always a binary type code from [`Type::binary_code`].
/// For example, `ValueBody<true, 8>` carries a compact i32 without a type prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueBody<const COMPACT: bool, const TYPE: u8>(
    /// The value. Its type must match `TYPE` when written.
    pub Value,
);

impl<const COMPACT: bool, const TYPE: u8> Wire for ValueBody<COMPACT, TYPE> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one value at depth 1. Refuses invalid types or encodings,
    /// values over [`MAX_VALUE_LEN`], [`MAX_DEPTH`], or [`MAX_VALUES`], excess
    /// container counts or byte lengths, incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_VALUE_LEN {
            return Err(Error::TooLong);
        }
        let ty = Type::from_binary_code(TYPE).ok_or(Error::BadType(TYPE))?;
        let protocol = if COMPACT {
            Protocol::Compact
        } else {
            Protocol::Binary
        };
        let (value, used) = Value::parse_prefix(protocol, ty, bytes)?;
        if used != bytes.len() {
            return Err(Error::Trailing);
        }
        Ok(Self(value))
    }

    /// Appends the value. Refuses a type mismatch, excess depth, counts or
    /// lengths, and compact empty maps with types other than [`Type::Byte`].
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if Some(self.0.ty()) != Type::from_binary_code(TYPE) {
            return Err(Error::Unwritable);
        }
        let mut bytes = Vec::new();
        Writer::new(&mut bytes, COMPACT).value(&self.0, 1)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// The value of the first field numbered `id`, if there is one.
pub fn field(fields: &[Field], id: i16) -> Option<&Value> {
    fields.iter().find(|f| f.id == id).map(|f| &f.value)
}

/// What a message is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// A call that expects a reply.
    Call,
    /// The answer to a call: a result struct whose field 0 is the return
    /// value, or whose other fields are the exceptions the method
    /// declares.
    Reply,
    /// A failure outside the method's declared exceptions, such as an
    /// unknown method. The body is an application exception.
    Exception,
    /// A call that expects no reply.
    Oneway,
}

impl MessageType {
    /// The message type's code.
    pub fn code(self) -> u8 {
        match self {
            MessageType::Call => 1,
            MessageType::Reply => 2,
            MessageType::Exception => 3,
            MessageType::Oneway => 4,
        }
    }

    /// The message type for a code, if there is one.
    pub fn from_code(code: u8) -> Option<MessageType> {
        Some(match code {
            1 => MessageType::Call,
            2 => MessageType::Reply,
            3 => MessageType::Exception,
            4 => MessageType::Oneway,
            _ => return None,
        })
    }
}

/// One Thrift message: a call, a reply or an exception.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The method's name.
    pub name: String,
    /// What the message is for.
    pub kind: MessageType,
    /// Chosen by the client and copied into the reply, so it can match
    /// replies to calls.
    pub seq: i32,
    /// The fields of the message's struct: the arguments of a call, or
    /// the result of a reply.
    pub body: Vec<Field>,
}

impl Message {
    /// Reads the message at the start of `b`, in whichever protocol its
    /// first byte shows. It returns the message, the protocol it was in,
    /// and how many bytes of `b` it took. A reply should use the same
    /// protocol.
    fn parse_prefix(b: &[u8]) -> Result<(Message, Protocol, usize), Error> {
        let mut r = Fields::new(b, false);
        r.message()
    }

    fn encode(&self, protocol: Protocol) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let name = self.name.as_bytes();
        let kind = self.kind.code();
        let mut w = Writer::new(&mut out, protocol.compact());
        w.limit = MAX_MESSAGE;
        match protocol {
            Protocol::Binary => {
                w.raw(&[0x80, 0x01, 0x00, kind]);
                w.binary(name)?;
                w.raw(&self.seq.to_be_bytes());
            }
            Protocol::BinaryOld => {
                w.binary(name)?;
                w.byte(kind);
                w.raw(&self.seq.to_be_bytes());
            }
            Protocol::Compact => {
                w.raw(&[0x82, (kind << 5) | 1]);
                w.varint(u64::from(self.seq as u32));
                w.binary(name)?;
            }
        }
        w.enter(1)?;
        w.fields(&self.body, 1)?;
        Ok(out)
    }

    /// Wraps this message in a transport frame using `protocol`. Refuses
    /// invalid values and messages longer than [`MAX_MESSAGE`].
    pub fn to_frame(&self, protocol: Protocol) -> Result<Frame, Error> {
        Ok(Frame(self.encode(protocol)?))
    }

    /// A reply to this message, with the same name and sequence number,
    /// carrying `body` as its result struct.
    pub fn reply(&self, body: Vec<Field>) -> Message {
        Message {
            name: self.name.clone(),
            kind: MessageType::Reply,
            seq: self.seq,
            body,
        }
    }

    /// An exception answering this message, with the same name and
    /// sequence number. Its body is an application exception: field 1 is
    /// `text` and field 2 is `kind`, one of [`exception_kind`].
    pub fn exception(&self, kind: i32, text: &str) -> Message {
        let body = vec![
            Field {
                id: 1,
                value: Value::Binary(text.as_bytes().to_vec()),
            },
            Field {
                id: 2,
                value: Value::I32(kind),
            },
        ];
        Message {
            name: self.name.clone(),
            kind: MessageType::Exception,
            seq: self.seq,
            body,
        }
    }
}

/// One complete message and the protocol carried in its header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedMessage {
    /// The call, reply, or exception.
    pub message: Message,
    /// The protocol used by its header and values.
    pub protocol: Protocol,
}

impl Wire for EncodedMessage {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one message, identifying its protocol from the first
    /// byte. Replies should use that protocol. Refuses invalid headers or
    /// values, excess depth, counts or lengths, incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let (message, protocol, used) = Message::parse_prefix(bytes)?;
        if used != bytes.len() {
            return Err(Error::Trailing);
        }
        Ok(Self { message, protocol })
    }

    /// Appends a message. Refuses invalid values, compact empty maps with
    /// types other than [`Type::Byte`], and messages over [`MAX_MESSAGE`].
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.message.encode(self.protocol)?);
        Ok(())
    }
}

/// Why bytes are not a Thrift message, value or frame, or a value cannot
/// be written so that it reads back. A frame fault from [`codec::Frames<Frame>`](fictionet::stdlib::codec::Frames) ends the
/// stream: the connection holds no more frames a reader can find, and a
/// real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Bytes follow the complete wire value.
    Trailing,
    /// The bytes end before the message or value does. On a connection
    /// without frames, more bytes may finish it.
    Truncated,
    /// A message's first byte is not that of any protocol here.
    BadProtocol(u8),
    /// A message's version is not 1. In the binary protocol this is the
    /// whole first word, and in the compact protocol the version bits.
    BadVersion(u32),
    /// A message's type is not call, reply, exception or oneway.
    BadMessageType(u8),
    /// A message's name is not UTF-8.
    BadUtf8,
    /// A type code is not one of the protocol's types.
    BadType(u8),
    /// A boolean's byte is not one the protocol uses.
    BadBool(u8),
    /// A variable-length integer is too long, or too big for its type.
    BadVarint,
    /// A length or count is negative, or above its limit.
    Length(i64),
    /// Values are nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// There are more values than [`MAX_VALUES`].
    TooMany,
    /// A message exceeds [`MAX_MESSAGE`] or a value exceeds [`MAX_VALUE_LEN`].
    TooLong,
    /// A frame's length was negative or above the configured limit.
    FrameLength(i32),
    /// An exact frame parse found the input ended before a complete
    /// frame, including empty input.
    FrameTruncated,
    /// An exact frame parse found bytes after the first complete frame.
    FrameTrailing,
    /// The value cannot be written without changing it.
    Unwritable,
}

fictionet::error_display!(Error, f, {
    Error::Trailing => f.write_str("bytes follow the wire value"),
    Error::Truncated => write!(f, "the bytes end inside a message or value"),
    Error::BadProtocol(b) => write!(f, "first byte {b:#04x} is not a Thrift message"),
    Error::BadVersion(v) => write!(f, "version {v:#x}, not 1"),
    Error::BadMessageType(t) => write!(f, "message type {t}, not 1 to 4"),
    Error::BadUtf8 => write!(f, "the message name is not UTF-8"),
    Error::BadType(t) => write!(f, "type code {t} is not a type"),
    Error::BadBool(b) => write!(f, "boolean byte {b} is not true or false"),
    Error::BadVarint => write!(f, "a variable-length integer is too long or too big"),
    Error::Length(n) => write!(f, "length {n} is negative or over its limit"),
    Error::TooDeep => write!(f, "values nested deeper than {MAX_DEPTH}"),
    Error::TooMany => write!(f, "more than {MAX_VALUES} values"),
    Error::TooLong => f.write_str("message or value exceeds its size limit"),
    Error::FrameLength(n) => write!(f, "frame length {n} is negative or over the limit"),
    Error::FrameTruncated => f.write_str("input ended before a complete Thrift frame"),
    Error::FrameTrailing => f.write_str("bytes follow the Thrift frame"),
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
});

fn parse_frame_limited(b: &[u8], limit: usize) -> Result<Option<(&[u8], usize)>, Error> {
    let Some(header) = b.get(..FRAME_HEADER_LEN) else {
        return Ok(None);
    };
    let n = i32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if n < 0 || n as usize > limit {
        return Err(Error::FrameLength(n));
    }
    let end = FRAME_HEADER_LEN + n as usize;
    match b.get(FRAME_HEADER_LEN..end) {
        Some(payload) => Ok(Some((payload, end))),
        None => Ok(None),
    }
}

/// A framed Thrift payload, bounded by [`MAX_FRAME`].
///
/// [`Wire::parse`] reads exactly one length-prefixed frame. Use
/// [`EncodedMessage::parse`] to read its payload and identify the message protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame(
    /// Payload bytes without the four-byte length prefix.
    pub Vec<u8>,
);

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one frame. Refuses negative or excess lengths,
    /// incomplete input, and trailing bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match parse_frame_limited(b, MAX_FRAME)? {
            Some((payload, used)) if used == b.len() => Ok(Self(payload.to_vec())),
            Some(_) => Err(Error::FrameTrailing),
            None => Err(Error::FrameTruncated),
        }
    }

    /// Appends the length prefix and payload. Refuses payloads over
    /// [`MAX_FRAME`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.len() > MAX_FRAME {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Reads framed Thrift payloads without holding input bytes.
    ///
    /// Use with [`fictionet::stdlib::codec::Stream`] for input bounded by [`FRAME_HEADER_LEN`]
    /// plus [`Frames::limit`](fictionet::stdlib::codec::Frames::limit). Partial frames return [`Step::Need`], including at EOF.
    /// The stream reports truncation at EOF and framing errors once. Map frames
    /// through [`EncodedMessage::parse`] to receive body errors as items.
    /// This reads framed transport; [`EncodedMessages`] reads unframed transport.
    ///
    /// ```
    /// use fictionet::stdlib::codec::Frames;
    /// use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
    /// use fictionet::stdlib::thrift::Frame;
    ///
    /// let mut stream = Stream::new(Frames::<Frame>::with_limit(16));
    /// let mut frames = Vec::new();
    /// pump(&mut stream, &[0, 0], |frame| frames.push(frame))?;
    /// pump(&mut stream, &[0, 2, 7, 8], |frame| frames.push(frame))?;
    /// finish(&mut stream, |frame| frames.push(frame))?;
    /// assert_eq!(frames, [Frame(vec![7, 8])]);
    /// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::thrift::Error>>(())
    /// ```
    Frame => (Frame, Error, usize);
    name = "Thrift framed transport";
    default { MAX_FRAME }
    normalize(limit) { limit.min(MAX_FRAME) }
    capacity(limit) { let limit = *limit;
        FRAME_HEADER_LEN.saturating_add(limit) }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        Ok(parse_frame_limited(input, limit)?
            .map(|(payload, used)| (Frame(payload.to_vec()), used)))
    }
}

/// Reads unframed Thrift messages without holding input bytes.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for input bounded by [`MAX_MESSAGE`]
/// plus one byte, which lets the scanner refuse an oversized message.
/// The scan cursor is relative to the unread start and resets after each
/// item. The task stack reserves two slots per level of [`MAX_DEPTH`];
/// [`Decode::held`] reports that storage, which cannot grow on [`Step::Need`].
/// Partial messages return [`Step::Need`], including at EOF, so the stream
/// reports truncation at EOF and protocol errors once.
///
/// ```
/// use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
/// use fictionet::stdlib::thrift::{EncodedMessage, EncodedMessages, Message, MessageType, Protocol};
///
/// let call = Message { name: "ping".into(), kind: MessageType::Call, seq: 1, body: vec![] };
/// let bytes = EncodedMessage { message: call.clone(), protocol: Protocol::Compact }.to_bytes()?;
/// let mut stream = Stream::new(EncodedMessages::new());
/// let mut messages = Vec::new();
/// pump(&mut stream, &bytes[..2], |item| messages.push(item))?;
/// pump(&mut stream, &bytes[2..], |item| messages.push(item))?;
/// finish(&mut stream, |item| messages.push(item))?;
/// assert_eq!(messages, [EncodedMessage { message: call, protocol: Protocol::Compact }]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct EncodedMessages {
    pos: usize,
    tasks: Vec<Task>,
    compact: bool,
    values: Work,
    examined: u64,
}

impl EncodedMessages {
    /// Creates an unframed decoder with a scan stack bounded by [`MAX_DEPTH`].
    pub fn new() -> Self {
        // Reserve the whole stack now: Need may advance a scan but must not
        // grow held storage. Each nesting level needs at most two tasks.
        let mut tasks = Vec::with_capacity(2 * MAX_DEPTH);
        tasks.push(Task::Head);
        Self {
            pos: 0,
            tasks,
            compact: false,
            values: Work::new("MAX_VALUES", MAX_VALUES),
            examined: 0,
        }
    }

    /// Cumulative charged scanner and parser work, including speculative calls.
    /// Saturates at `u64::MAX`.
    #[inline]
    pub fn examined(&self) -> u64 {
        self.examined
    }

    fn parse(&mut self, input: &[u8]) -> Result<(Message, Protocol, usize), Error> {
        let mut reader = Fields::new(input, false);
        let result = reader.message();
        self.examined = self.examined.saturating_add(reader.values.used() as u64);
        result
    }

    fn scan(&mut self, input: &[u8]) -> Result<bool, Error> {
        if self.pos > input.len() {
            self.pos = 0;
            self.tasks.clear();
            self.tasks.push(Task::Head);
            self.compact = false;
            self.values = Work::new("MAX_VALUES", MAX_VALUES);
        }
        while let Some(&task) = self.tasks.last() {
            let mut r = Fields::new(input.get(self.pos..).ok_or(Error::Truncated)?, self.compact);
            r.values = self.values;
            let result = step(task, &mut r, &mut self.tasks);
            self.examined = self
                .examined
                .saturating_add((r.values.used() - self.values.used()) as u64);
            match result {
                Ok(()) => {
                    self.pos += r.cursor.position();
                    self.values = r.values;
                    self.compact = r.compact;
                    debug_assert!(self.tasks.len() <= 2 * MAX_DEPTH);
                    if self.pos > MAX_MESSAGE {
                        return Err(Error::TooLong);
                    }
                }
                Err(Error::Truncated) => {
                    if input.len() > MAX_MESSAGE {
                        return Err(Error::TooLong);
                    }
                    return Ok(false);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

impl Clone for EncodedMessages {
    fn clone(&self) -> Self {
        // Vec::clone drops spare capacity, which would let held storage grow on Need.
        let mut tasks = Vec::with_capacity(self.tasks.capacity());
        tasks.extend_from_slice(&self.tasks);
        Self {
            pos: self.pos,
            tasks,
            compact: self.compact,
            values: self.values,
            examined: self.examined,
        }
    }
}

impl Default for EncodedMessages {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for EncodedMessages {
    type Item = EncodedMessage;
    type Error = Error;
    const NAME: &'static str = "Thrift unframed transport";

    fn capacity(&self) -> usize {
        MAX_MESSAGE + 1
    }

    fn held(&self) -> usize {
        self.tasks.capacity() * core::mem::size_of::<Task>()
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        match self.scan(input) {
            Ok(false) => Ok(Step::Need),
            Ok(true) => {
                let (message, protocol, used) =
                    self.parse(input.get(..self.pos).ok_or(Error::Truncated)?)?;
                self.pos = 0;
                self.tasks.clear();
                self.tasks.push(Task::Head);
                self.compact = false;
                self.values = Work::new("MAX_VALUES", MAX_VALUES);
                Ok(Step::Item(EncodedMessage { message, protocol }, used))
            }
            Err(e) => Err(match self.parse(input) {
                Err(first) if first != Error::Truncated => first,
                _ => e,
            }),
        }
    }
}

/// Something an unframed reader has still to read.
#[derive(Clone, Copy, Debug)]
enum Task {
    /// A message's header, then its struct.
    Head,
    /// A value of type `ty` at `depth`.
    Value { ty: Type, depth: usize },
    /// The rest of a struct at `depth`, whose last field was numbered `last`.
    Fields { depth: usize, last: i16 },
    /// `left` more elements of a list or set at `depth`.
    Items {
        elem: Type,
        left: usize,
        depth: usize,
    },
    /// `left` more keys and values of a map at `depth`, taking turns, with
    /// a key when `left` is even.
    Entries {
        key: Type,
        value: Type,
        left: usize,
        depth: usize,
    },
}

/// Reads one piece of a message for `task`, then updates `tasks`. The
/// tasks are changed only after every read has succeeded, so a piece that
/// is cut short can be read again from its start.
fn step(task: Task, r: &mut Fields, tasks: &mut Vec<Task>) -> Result<(), Error> {
    match task {
        Task::Head => {
            r.head()?;
            r.enter(1)?;
            tasks.pop();
            tasks.push(Task::Fields { depth: 1, last: 0 });
        }
        Task::Fields { depth, last } => {
            let header = r.field_header(last)?;
            tasks.pop();
            if let Some((id, head)) = header {
                tasks.push(Task::Fields { depth, last: id });
                match head {
                    FieldHead::Bool(_) => r.enter(depth + 1)?,
                    FieldHead::Typed(ty) => tasks.push(Task::Value {
                        ty,
                        depth: depth + 1,
                    }),
                }
            }
        }
        Task::Value { ty, depth } => {
            let next = match ty {
                Type::Struct => {
                    r.enter(depth)?;
                    Some(Task::Fields { depth, last: 0 })
                }
                Type::List | Type::Set => {
                    r.enter(depth)?;
                    let (elem, left) = r.list_header()?;
                    Some(Task::Items { elem, left, depth })
                }
                Type::Map => {
                    r.enter(depth)?;
                    let (key, value, n) = r.map_header()?;
                    Some(Task::Entries {
                        key,
                        value,
                        left: n * 2,
                        depth,
                    })
                }
                Type::Binary => {
                    // Skipped without a copy: it is copied once the whole
                    // message is read.
                    r.enter(depth)?;
                    let n = r.len(MAX_BINARY_LEN)?;
                    r.cursor.take(n)?;
                    None
                }
                _ => {
                    r.value(ty, depth)?;
                    None
                }
            };
            tasks.pop();
            tasks.extend(next);
        }
        Task::Items { elem, left, depth } => {
            tasks.pop();
            if left > 0 {
                tasks.push(Task::Items {
                    elem,
                    left: left - 1,
                    depth,
                });
                tasks.push(Task::Value {
                    ty: elem,
                    depth: depth + 1,
                });
            }
        }
        Task::Entries {
            key,
            value,
            left,
            depth,
        } => {
            tasks.pop();
            if left > 0 {
                let ty = if left % 2 == 0 { key } else { value };
                tasks.push(Task::Entries {
                    key,
                    value,
                    left: left - 1,
                    depth,
                });
                tasks.push(Task::Value {
                    ty,
                    depth: depth + 1,
                });
            }
        }
    }
    Ok(())
}

/// Reads values from a byte slice, counting them against [`MAX_VALUES`].
struct Fields<'a> {
    cursor: ByteReader<'a>,
    compact: bool,
    values: Work,
}

impl<'a> Fields<'a> {
    fn new(b: &'a [u8], compact: bool) -> Fields<'a> {
        Fields {
            cursor: ByteReader::new(b),
            compact,
            values: Work::new("MAX_VALUES", MAX_VALUES),
        }
    }

    fn message(&mut self) -> Result<(Message, Protocol, usize), Error> {
        let (name, kind, seq, protocol) = self.head()?;
        self.enter(1)?;
        let body = self.fields(1)?;
        Ok((
            Message {
                name,
                kind,
                seq,
                body,
            },
            protocol,
            self.cursor.position(),
        ))
    }

    /// A variable-length integer of at most `max_bytes` bytes, no bigger
    /// than `max`.
    fn varint(&mut self, max_bytes: usize, max: u64) -> Result<u64, Error> {
        leb128::decode_with(
            || self.cursor.u8().map_err(Error::from),
            max_bytes,
            max,
            Error::BadVarint,
        )
    }

    fn varint32(&mut self) -> Result<u32, Error> {
        Ok(self.varint(5, u64::from(u32::MAX))? as u32)
    }

    fn zigzag32(&mut self) -> Result<i32, Error> {
        let n = self.varint32()?;
        Ok(((n >> 1) as i32) ^ -((n & 1) as i32))
    }

    fn i16v(&mut self) -> Result<i16, Error> {
        if self.compact {
            i16::try_from(self.zigzag32()?).map_err(|_| Error::BadVarint)
        } else {
            Ok(i16::from_be_bytes(self.cursor.array()?))
        }
    }

    fn i32v(&mut self) -> Result<i32, Error> {
        if self.compact {
            self.zigzag32()
        } else {
            Ok(i32::from_be_bytes(self.cursor.array()?))
        }
    }

    fn i64v(&mut self) -> Result<i64, Error> {
        if self.compact {
            let n = self.varint(10, u64::MAX)?;
            Ok(((n >> 1) as i64) ^ -((n & 1) as i64))
        } else {
            Ok(i64::from_be_bytes(self.cursor.array()?))
        }
    }

    /// A length or count, checked against `limit`.
    fn len(&mut self, limit: usize) -> Result<usize, Error> {
        let n = if self.compact {
            i64::from(self.varint32()?)
        } else {
            i64::from(i32::from_be_bytes(self.cursor.array()?))
        };
        if n < 0 || n as u64 > limit as u64 {
            Err(Error::Length(n))
        } else {
            Ok(n as usize)
        }
    }

    fn name(&mut self) -> Result<String, Error> {
        let n = self.len(MAX_BINARY_LEN)?;
        core::str::from_utf8(self.cursor.take(n)?)
            .map(str::to_owned)
            .map_err(|_| Error::BadUtf8)
    }

    /// A message's header: everything before its struct. It picks the
    /// protocol from the first byte and reads the rest in it.
    fn head(&mut self) -> Result<(String, MessageType, i32, Protocol), Error> {
        let first = self.cursor.peek_u8().ok_or(Error::Truncated)?;
        let protocol = match first {
            0x82 => Protocol::Compact,
            0x80 => Protocol::Binary,
            0x00..=0x7f => Protocol::BinaryOld,
            _ => return Err(Error::BadProtocol(first)),
        };
        self.compact = protocol.compact();
        let (name, kind, seq) = match protocol {
            Protocol::Compact => {
                self.cursor.u8()?;
                let h = self.cursor.u8()?;
                if h & 0x1f != 1 {
                    return Err(Error::BadVersion(u32::from(h & 0x1f)));
                }
                let code = h >> 5;
                let kind = MessageType::from_code(code).ok_or(Error::BadMessageType(code))?;
                let seq = self.varint32()? as i32;
                (self.name()?, kind, seq)
            }
            Protocol::Binary => {
                let word = u32::from_be_bytes(self.cursor.array()?);
                if word & 0xffff_0000 != 0x8001_0000 {
                    return Err(Error::BadVersion(word));
                }
                let code = (word & 0xff) as u8;
                let kind = MessageType::from_code(code).ok_or(Error::BadMessageType(code))?;
                let name = self.name()?;
                (name, kind, self.i32v()?)
            }
            Protocol::BinaryOld => {
                let name = self.name()?;
                let code = self.cursor.u8()?;
                let kind = MessageType::from_code(code).ok_or(Error::BadMessageType(code))?;
                (name, kind, self.i32v()?)
            }
        };
        Ok((name, kind, seq, protocol))
    }

    /// Counts one value at `depth` against the limits.
    fn enter(&mut self, depth: usize) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        self.values.charge(1).map_err(|_| Error::TooMany)
    }

    fn value(&mut self, ty: Type, depth: usize) -> Result<Value, Error> {
        self.enter(depth)?;
        Ok(match ty {
            Type::Bool => {
                let b = self.cursor.u8()?;
                match (self.compact, b) {
                    (_, 1) => Value::Bool(true),
                    (false, 0) | (true, 0 | 2) => Value::Bool(false),
                    _ => return Err(Error::BadBool(b)),
                }
            }
            Type::Byte => Value::Byte(self.cursor.u8()? as i8),
            Type::I16 => Value::I16(self.i16v()?),
            Type::I32 => Value::I32(self.i32v()?),
            Type::I64 => Value::I64(self.i64v()?),
            Type::Double => {
                let a = self.cursor.array()?;
                Value::Double(if self.compact {
                    f64::from_le_bytes(a)
                } else {
                    f64::from_be_bytes(a)
                })
            }
            Type::Binary => {
                let n = self.len(MAX_BINARY_LEN)?;
                Value::Binary(self.cursor.take(n)?.to_vec())
            }
            Type::Uuid => Value::Uuid(self.cursor.array()?),
            Type::Struct => Value::Struct(self.fields(depth)?),
            Type::List => Value::List(self.list(depth)?),
            Type::Set => Value::Set(self.list(depth)?),
            Type::Map => Value::Map(self.map(depth)?),
        })
    }

    /// A struct's fields, up to and including its stop byte. The struct
    /// itself is at `depth`.
    fn fields(&mut self, depth: usize) -> Result<Vec<Field>, Error> {
        let mut fields = Vec::new();
        let mut last: i16 = 0;
        while let Some((id, head)) = self.field_header(last)? {
            last = id;
            let value = match head {
                FieldHead::Bool(b) => {
                    self.enter(depth + 1)?;
                    Value::Bool(b)
                }
                FieldHead::Typed(ty) => self.value(ty, depth + 1)?,
            };
            fields.push(Field { id, value });
        }
        Ok(fields)
    }

    /// A field's number and type, or `None` at a struct's stop byte.
    /// `last` is the number of the field before it.
    fn field_header(&mut self, last: i16) -> Result<Option<(i16, FieldHead)>, Error> {
        let h = self.cursor.u8()?;
        if h == 0 {
            return Ok(None);
        }
        if self.compact {
            let (delta, code) = (h >> 4, h & 0x0f);
            let id = if delta == 0 {
                self.i16v()?
            } else {
                last.wrapping_add(i16::from(delta))
            };
            let head = if code == 1 || code == 2 {
                // A boolean field's value is in its type code.
                FieldHead::Bool(code == 1)
            } else {
                FieldHead::Typed(Type::from_compact_code(code).ok_or(Error::BadType(code))?)
            };
            Ok(Some((id, head)))
        } else {
            let ty = Type::from_binary_code(h).ok_or(Error::BadType(h))?;
            Ok(Some((self.i16v()?, FieldHead::Typed(ty))))
        }
    }

    /// A list or set's element type and count.
    fn list_header(&mut self) -> Result<(Type, usize), Error> {
        if self.compact {
            let h = self.cursor.u8()?;
            let code = h & 0x0f;
            let elem = Type::from_compact_code(code).ok_or(Error::BadType(code))?;
            let n = if h >> 4 == 15 {
                self.len(MAX_CONTAINER_LEN)?
            } else {
                usize::from(h >> 4)
            };
            Ok((elem, n))
        } else {
            let code = self.cursor.u8()?;
            let elem = Type::from_binary_code(code).ok_or(Error::BadType(code))?;
            Ok((elem, self.len(MAX_CONTAINER_LEN)?))
        }
    }

    /// A map's key type, value type and count.
    fn map_header(&mut self) -> Result<(Type, Type, usize), Error> {
        if self.compact {
            let n = self.len(MAX_CONTAINER_LEN)?;
            if n == 0 {
                return Ok((Type::Byte, Type::Byte, 0));
            }
            let h = self.cursor.u8()?;
            let key = Type::from_compact_code(h >> 4).ok_or(Error::BadType(h >> 4))?;
            let value = Type::from_compact_code(h & 0x0f).ok_or(Error::BadType(h & 0x0f))?;
            Ok((key, value, n))
        } else {
            let [k, v] = self.cursor.array()?;
            let key = Type::from_binary_code(k).ok_or(Error::BadType(k))?;
            let value = Type::from_binary_code(v).ok_or(Error::BadType(v))?;
            Ok((key, value, self.len(MAX_CONTAINER_LEN)?))
        }
    }

    fn list(&mut self, depth: usize) -> Result<List, Error> {
        let (elem, n) = self.list_header()?;
        // Every element takes at least one byte.
        if n > self.cursor.remaining() {
            return Err(Error::Truncated);
        }
        let mut items = Vec::with_capacity(n.min(MAX_PREALLOC));
        for _ in 0..n {
            items.push(self.value(elem, depth + 1)?);
        }
        Ok(List { elem, items })
    }

    fn map(&mut self, depth: usize) -> Result<Map, Error> {
        let (key, value, n) = self.map_header()?;
        // Every key and every value takes at least one byte.
        if n.saturating_mul(2) > self.cursor.remaining() {
            return Err(Error::Truncated);
        }
        let mut entries = Vec::with_capacity(n.min(MAX_PREALLOC));
        for _ in 0..n {
            let k = self.value(key, depth + 1)?;
            let v = self.value(value, depth + 1)?;
            entries.push((k, v));
        }
        Ok(Map {
            key,
            value,
            entries,
        })
    }
}

/// What a field's header says about its value.
#[derive(Clone, Copy)]
enum FieldHead {
    /// A compact boolean field, whose value is in its header.
    Bool(bool),
    /// A value of this type follows.
    Typed(Type),
}

/// Writes values, checking the same limits a [`Fields`] does.
struct Writer<'o> {
    out: &'o mut Vec<u8>,
    compact: bool,
    values: Work,
    limit: usize,
    failed: bool,
}

impl<'o> Writer<'o> {
    fn new(out: &'o mut Vec<u8>, compact: bool) -> Writer<'o> {
        Writer {
            out,
            compact,
            values: Work::new("MAX_VALUES", MAX_VALUES),
            limit: MAX_VALUE_LEN,
            failed: false,
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        if self.failed || bytes.len() > self.limit.saturating_sub(self.out.len()) {
            self.failed = true;
            return;
        }
        self.out.extend_from_slice(bytes);
    }

    fn byte(&mut self, byte: u8) {
        self.raw(&[byte]);
    }

    fn check(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Unwritable)
        } else {
            Ok(())
        }
    }

    fn enter(&mut self, depth: usize) -> Result<(), Error> {
        self.check()?;
        if depth > MAX_DEPTH {
            return Err(Error::Unwritable);
        }
        self.values.charge(1).map_err(|_| Error::Unwritable)?;
        self.check()
    }

    fn varint(&mut self, v: u64) {
        leb128::encode_with(v, |b| self.byte(b));
    }

    fn i16w(&mut self, v: i16) {
        if self.compact {
            self.i32w(i32::from(v))
        } else {
            self.raw(&v.to_be_bytes())
        }
    }

    fn i32w(&mut self, v: i32) {
        if self.compact {
            self.varint(u64::from(((v << 1) ^ (v >> 31)) as u32));
        } else {
            self.raw(&v.to_be_bytes());
        }
    }

    fn i64w(&mut self, v: i64) {
        if self.compact {
            self.varint(((v << 1) ^ (v >> 63)) as u64);
        } else {
            self.raw(&v.to_be_bytes());
        }
    }

    /// A length or count, after checking it against `limit`.
    fn len(&mut self, n: usize, limit: usize) -> Result<(), Error> {
        if n > limit {
            return Err(Error::Unwritable);
        }
        if self.compact {
            self.varint(n as u64);
        } else {
            self.raw(&(n as u32).to_be_bytes());
        }
        self.check()
    }

    fn binary(&mut self, b: &[u8]) -> Result<(), Error> {
        self.len(b.len(), MAX_BINARY_LEN)?;
        self.raw(b);
        self.check()
    }

    fn code(&self, ty: Type) -> u8 {
        if self.compact {
            ty.compact_code()
        } else {
            ty.binary_code()
        }
    }

    fn value(&mut self, v: &Value, depth: usize) -> Result<(), Error> {
        self.enter(depth)?;
        match v {
            Value::Bool(b) => self.byte(match (self.compact, *b) {
                (true, true) => 1,
                (true, false) => 2,
                (false, b) => u8::from(b),
            }),
            Value::Byte(x) => self.byte(*x as u8),
            Value::I16(x) => self.i16w(*x),
            Value::I32(x) => self.i32w(*x),
            Value::I64(x) => self.i64w(*x),
            Value::Double(x) => {
                let a = if self.compact {
                    x.to_le_bytes()
                } else {
                    x.to_be_bytes()
                };
                self.raw(&a);
            }
            Value::Binary(b) => self.binary(b)?,
            Value::Uuid(u) => self.raw(u),
            Value::Struct(fields) => self.fields(fields, depth)?,
            Value::List(l) | Value::Set(l) => self.list(l, depth)?,
            Value::Map(m) => self.map(m, depth)?,
        }
        self.check()
    }

    /// A struct's fields and its stop byte. The struct itself is at
    /// `depth`.
    fn fields(&mut self, fields: &[Field], depth: usize) -> Result<(), Error> {
        let mut last: i16 = 0;
        for f in fields {
            if self.compact {
                let code = match f.value {
                    Value::Bool(true) => 1,
                    Value::Bool(false) => 2,
                    ref v => v.ty().compact_code(),
                };
                let delta = i32::from(f.id) - i32::from(last);
                if (1..=15).contains(&delta) {
                    self.byte(((delta as u8) << 4) | code);
                } else {
                    self.byte(code);
                    self.i16w(f.id);
                }
                last = f.id;
                if let Value::Bool(_) = f.value {
                    self.enter(depth + 1)?;
                } else {
                    self.value(&f.value, depth + 1)?;
                }
            } else {
                self.byte(f.value.ty().binary_code());
                self.i16w(f.id);
                self.value(&f.value, depth + 1)?;
            }
        }
        self.byte(0);
        self.check()
    }

    fn list(&mut self, l: &List, depth: usize) -> Result<(), Error> {
        let n = l.items.len();
        if n > MAX_CONTAINER_LEN {
            return Err(Error::Unwritable);
        }
        if l.items.iter().any(|v| v.ty() != l.elem) {
            return Err(Error::Unwritable);
        }
        let code = self.code(l.elem);
        if self.compact {
            if n < 15 {
                self.byte(((n as u8) << 4) | code);
            } else {
                self.byte(0xf0 | code);
                self.varint(n as u64);
            }
        } else {
            self.byte(code);
            self.raw(&(n as u32).to_be_bytes());
        }
        for v in &l.items {
            self.value(v, depth + 1)?;
        }
        self.check()
    }

    fn map(&mut self, m: &Map, depth: usize) -> Result<(), Error> {
        let n = m.entries.len();
        if self.compact && n == 0 && (m.key != Type::Byte || m.value != Type::Byte) {
            return Err(Error::Unwritable);
        }
        if n > MAX_CONTAINER_LEN {
            return Err(Error::Unwritable);
        }
        if m.entries
            .iter()
            .any(|(k, v)| k.ty() != m.key || v.ty() != m.value)
        {
            return Err(Error::Unwritable);
        }
        let (k, v) = (self.code(m.key), self.code(m.value));
        if self.compact {
            self.varint(n as u64);
            if n > 0 {
                self.byte((k << 4) | v);
            }
        } else {
            self.raw(&[k, v]);
            self.raw(&(n as u32).to_be_bytes());
        }
        for (key, value) in &m.entries {
            self.value(key, depth + 1)?;
            self.value(value, depth + 1)?;
        }
        self.check()
    }
}

fictionet::codec_from!(Error, Truncated, |_| Error::Truncated);

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg, Stream, finish, pump};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use fictionet::stdlib::test_support::{chunks, decode_all, mutate};

    const ALL_TYPES: [Type; 12] = [
        Type::Bool,
        Type::Byte,
        Type::I16,
        Type::I32,
        Type::I64,
        Type::Double,
        Type::Binary,
        Type::Uuid,
        Type::Struct,
        Type::List,
        Type::Set,
        Type::Map,
    ];
    const PROTOCOLS: [Protocol; 3] = [Protocol::Binary, Protocol::BinaryOld, Protocol::Compact];

    fn value_bytes(value: &Value, protocol: Protocol) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        Writer::new(&mut out, protocol.compact()).value(value, 1)?;
        Ok(out)
    }

    fn add_call() -> Message {
        Message {
            name: "add".into(),
            kind: MessageType::Call,
            seq: 1,
            body: vec![
                Field {
                    id: 1,
                    value: Value::I32(2),
                },
                Field {
                    id: 2,
                    value: Value::I32(3),
                },
            ],
        }
    }

    // The examples below follow the binary and compact protocol
    // specifications byte by byte.

    #[test]
    fn strict_binary_message() {
        let bytes = [
            0x80, 0x01, 0x00, 0x01, 0, 0, 0, 3, b'a', b'd', b'd', 0, 0, 0, 1, 0x08, 0, 1, 0, 0, 0,
            2, 0x08, 0, 2, 0, 0, 0, 3, 0x00,
        ];
        assert_eq!(
            EncodedMessage::parse(&bytes),
            Ok(EncodedMessage {
                message: add_call(),
                protocol: Protocol::Binary
            })
        );
        assert_eq!(
            EncodedMessage {
                message: add_call(),
                protocol: Protocol::Binary
            }
            .to_bytes()
            .unwrap(),
            bytes
        );
        // The unused third byte of the version word is ignored.
        let mut other = bytes;
        other[2] = 0x55;
        assert_eq!(EncodedMessage::parse(&other).unwrap().message, add_call());
    }

    #[test]
    fn old_binary_message() {
        let bytes = [
            0, 0, 0, 3, b'a', b'd', b'd', 0x01, 0, 0, 0, 1, 0x08, 0, 1, 0, 0, 0, 2, 0x08, 0, 2, 0,
            0, 0, 3, 0x00,
        ];
        assert_eq!(
            EncodedMessage::parse(&bytes),
            Ok(EncodedMessage {
                message: add_call(),
                protocol: Protocol::BinaryOld
            })
        );
        assert_eq!(
            EncodedMessage {
                message: add_call(),
                protocol: Protocol::BinaryOld
            }
            .to_bytes()
            .unwrap(),
            bytes
        );
    }

    #[test]
    fn compact_message() {
        // Protocol id, type 1 and version 1, sequence 1, name, two short
        // field headers with zigzag values, stop.
        let bytes = [
            0x82, 0x21, 0x01, 0x03, b'a', b'd', b'd', 0x15, 0x04, 0x15, 0x06, 0x00,
        ];
        assert_eq!(
            EncodedMessage::parse(&bytes),
            Ok(EncodedMessage {
                message: add_call(),
                protocol: Protocol::Compact
            })
        );
        assert_eq!(
            EncodedMessage {
                message: add_call(),
                protocol: Protocol::Compact
            }
            .to_bytes()
            .unwrap(),
            bytes
        );
        // A negative sequence number is a 5-byte varint, not zigzag.
        let m = Message {
            seq: -1,
            body: vec![],
            ..add_call()
        };
        let b = EncodedMessage {
            message: m.clone(),
            protocol: Protocol::Compact,
        }
        .to_bytes()
        .unwrap();
        assert_eq!(b[2..7], [0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert_eq!(EncodedMessage::parse(&b).unwrap().message, m);
    }

    #[test]
    fn doc_example() {
        fn answer(call: &Message) -> Message {
            match (
                call.name.as_str(),
                field(&call.body, 1),
                field(&call.body, 2),
            ) {
                ("add", Some(Value::I32(a)), Some(Value::I32(b))) => call.reply(vec![Field {
                    id: 0,
                    value: Value::I32(a.wrapping_add(*b)),
                }]),
                _ => call.exception(exception_kind::UNKNOWN_METHOD, "no such method"),
            }
        }
        let mut decoder = Stream::new(Frames::<Frame>::new());
        assert_eq!(decoder.push(&[0, 0, 0, 30]), 4);
        assert_eq!(
            decoder.push(&[
                0x80, 0x01, 0x00, 0x01, 0, 0, 0, 3, b'a', b'd', b'd', 0, 0, 0, 1
            ]),
            15
        );
        assert_eq!(
            decoder.push(&[0x08, 0, 1, 0, 0, 0, 2, 0x08, 0, 2, 0, 0, 0, 3, 0x00]),
            15
        );
        let payload = decoder.next().unwrap().unwrap().0;
        let EncodedMessage {
            message: call,
            protocol,
        } = EncodedMessage::parse(&payload).unwrap();
        assert_eq!(protocol, Protocol::Binary);
        let reply = answer(&call)
            .to_frame(protocol)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert_eq!(
            reply,
            [
                0, 0, 0, 23, 0x80, 0x01, 0x00, 0x02, 0, 0, 0, 3, b'a', b'd', b'd', 0, 0, 0, 1,
                0x08, 0, 0, 0, 0, 0, 5, 0x00,
            ]
        );
        let other = Message {
            name: "sub".into(),
            ..call
        };
        let e = answer(&other);
        assert_eq!(e.kind, MessageType::Exception);
        assert_eq!(
            field(&e.body, 1),
            Some(&Value::Binary(b"no such method".to_vec()))
        );
        assert_eq!(
            field(&e.body, 2),
            Some(&Value::I32(exception_kind::UNKNOWN_METHOD))
        );
        assert_eq!(field(&e.body, 3), None);
    }

    #[test]
    fn compact_values() {
        let c = Protocol::Compact;
        // Zigzag: 0, -1, 1, -2 become 0, 1, 2, 3.
        for (v, b) in [(0, 0u8), (-1, 1), (1, 2), (-2, 3)] {
            assert_eq!(value_bytes(&Value::I32(v), c).unwrap(), [b]);
        }
        assert_eq!(
            value_bytes(&Value::I64(i64::MIN), c).unwrap(),
            [0xff; 9].iter().copied().chain([0x01]).collect::<Vec<_>>()
        );
        assert_eq!(value_bytes(&Value::I16(300), c).unwrap(), [0xd8, 0x04]);
        // Doubles are little-endian.
        assert_eq!(
            value_bytes(&Value::Double(1.0), c).unwrap(),
            [0, 0, 0, 0, 0, 0, 0xf0, 0x3f]
        );
        assert_eq!(
            value_bytes(&Value::Double(1.0), Protocol::Binary).unwrap(),
            [0x3f, 0xf0, 0, 0, 0, 0, 0, 0]
        );
        // A short list header: size 3, type i32.
        let l = Value::List(List {
            elem: Type::I32,
            items: vec![Value::I32(1), Value::I32(2), Value::I32(3)],
        });
        assert_eq!(value_bytes(&l, c).unwrap(), [0x35, 0x02, 0x04, 0x06]);
        // A long list header: 0xf0 and the type, then the size. Booleans
        // in lists are 1 for true and 2 for false.
        let bools: Vec<Value> = (0..15).map(|i| Value::Bool(i % 2 == 0)).collect();
        let l = Value::List(List {
            elem: Type::Bool,
            items: bools.clone(),
        });
        let b = value_bytes(&l, c).unwrap();
        assert_eq!(b[..4], [0xf1, 0x0f, 1, 2]);
        assert_eq!(Value::parse_prefix(c, Type::List, &b), Ok((l, b.len())));
        // Readers take 2 as the bool element type, and 0 as false.
        assert_eq!(
            Value::parse_prefix(c, Type::Set, &[0x22, 0, 1]),
            Ok((
                Value::Set(List {
                    elem: Type::Bool,
                    items: vec![Value::Bool(false), Value::Bool(true)]
                }),
                3
            ))
        );
        // Maps: an empty one is one zero byte; otherwise size, then types.
        let m = Map {
            key: Type::I32,
            value: Type::Binary,
            entries: vec![],
        };
        let typed = ValueBody::<true, 13>(Value::Map(m));
        contract::check_wire_value(&typed);
        assert_eq!(typed.to_bytes(), Err(Error::Unwritable));
        let empty = ValueBody::<true, 13>(Value::Map(Map {
            key: Type::Byte,
            value: Type::Byte,
            entries: vec![],
        }));
        contract::check_wire_value(&empty);
        assert_eq!(empty.to_bytes().unwrap(), [0]);
        assert_eq!(
            Value::parse_prefix(c, Type::Map, &[0]),
            Ok((
                Value::Map(Map {
                    key: Type::Byte,
                    value: Type::Byte,
                    entries: vec![]
                }),
                1
            ))
        );
        let m = Map {
            key: Type::I32,
            value: Type::Binary,
            entries: vec![(Value::I32(1), Value::Binary(b"a".to_vec()))],
        };
        let b = value_bytes(&Value::Map(m.clone()), c).unwrap();
        assert_eq!(b, [0x01, 0x58, 0x02, 0x01, b'a']);
        assert_eq!(
            Value::parse_prefix(c, Type::Map, &b),
            Ok((Value::Map(m), 5))
        );
    }

    #[test]
    fn compact_field_headers() {
        let c = Protocol::Compact;
        let s = Value::Struct(vec![
            Field {
                id: 1,
                value: Value::Bool(true),
            },
            Field {
                id: 2,
                value: Value::Bool(false),
            },
            // A jump of more than 15: the long form.
            Field {
                id: 100,
                value: Value::Byte(7),
            },
            // Going down: the long form too.
            Field {
                id: 3,
                value: Value::Byte(-1),
            },
            Field {
                id: 18,
                value: Value::Uuid([9; 16]),
            },
        ]);
        let b = value_bytes(&s, c).unwrap();
        let mut want = vec![0x11, 0x12, 0x03, 0xc8, 0x01, 7, 0x03, 0x06, 0xff, 0xfd];
        want.extend_from_slice(&[9; 16]);
        want.push(0);
        assert_eq!(b, want);
        assert_eq!(Value::parse_prefix(c, Type::Struct, &b), Ok((s, b.len())));
        // Overlong but valid varints are read.
        assert_eq!(
            Value::parse_prefix(c, Type::I32, &[0x82, 0x80, 0x00]),
            Ok((Value::I32(1), 3))
        );
        // A delta that runs past 32767 wraps, as Apache Thrift does.
        let b = [0x03, 0xfc, 0xff, 0x03, 0, 0x23, 0, 0];
        let (v, _) = Value::parse_prefix(c, Type::Struct, &b).unwrap();
        let Value::Struct(f) = &v else { panic!() };
        assert_eq!(f[0].id, i16::MAX - 1);
        assert_eq!(f[1].id, i16::MIN);
        let again = value_bytes(&v, c).unwrap();
        assert_eq!(
            Value::parse_prefix(c, Type::Struct, &again),
            Ok((v, again.len()))
        );
    }

    #[test]
    fn binary_values() {
        let b = Protocol::Binary;
        let v = Value::Struct(vec![
            Field {
                id: -1,
                value: Value::Bool(true),
            },
            Field {
                id: 5,
                value: Value::Map(Map {
                    key: Type::Binary,
                    value: Type::I64,
                    entries: vec![(Value::Binary(b"k".to_vec()), Value::I64(-2))],
                }),
            },
        ]);
        let bytes = value_bytes(&v, b).unwrap();
        let want = [
            0x02, 0xff, 0xff, 1, 0x0d, 0, 5, 11, 10, 0, 0, 0, 1, 0, 0, 0, 1, b'k', 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0,
        ];
        assert_eq!(bytes, want);
        assert_eq!(
            Value::parse_prefix(b, Type::Struct, &bytes),
            Ok((v.clone(), want.len()))
        );
        assert_eq!(
            Value::parse_prefix(Protocol::BinaryOld, Type::Struct, &bytes),
            Ok((v, want.len()))
        );
        let s = Value::Set(List {
            elem: Type::I16,
            items: vec![Value::I16(1)],
        });
        assert_eq!(value_bytes(&s, b).unwrap(), [6, 0, 0, 0, 1, 0, 1]);
    }

    #[test]
    fn parse_errors() {
        let (b, c) = (Protocol::Binary, Protocol::Compact);
        assert_eq!(EncodedMessage::parse(&[]), Err(Error::Truncated));
        assert_eq!(
            EncodedMessage::parse(&[0x81]),
            Err(Error::BadProtocol(0x81))
        );
        assert_eq!(
            EncodedMessage::parse(&[0x80, 0x02, 0, 1]),
            Err(Error::BadVersion(0x8002_0001))
        );
        assert_eq!(
            EncodedMessage::parse(&[0x82, 0x22]),
            Err(Error::BadVersion(2))
        );
        assert_eq!(
            EncodedMessage::parse(&[0x82, 0xa1]),
            Err(Error::BadMessageType(5))
        );
        assert_eq!(
            EncodedMessage::parse(&[0x80, 0x01, 0, 0]),
            Err(Error::BadMessageType(0))
        );
        assert_eq!(
            EncodedMessage::parse(&[0, 0, 0, 0, 9]),
            Err(Error::BadMessageType(9))
        );
        assert_eq!(
            EncodedMessage::parse(&[0x82, 0x21, 0, 1, 0xff]),
            Err(Error::BadUtf8)
        );
        assert_eq!(
            EncodedMessage::parse(&[0x7f, 0xff, 0xff, 0xff]),
            Err(Error::Length(0x7fff_ffff))
        );
        // Bad types in fields and containers.
        assert_eq!(
            Value::parse_prefix(b, Type::Struct, &[1, 0, 1]),
            Err(Error::BadType(1))
        );
        assert_eq!(
            Value::parse_prefix(b, Type::Struct, &[5, 0, 1]),
            Err(Error::BadType(5))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::Struct, &[0x10]),
            Err(Error::BadType(0))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::Struct, &[0x1e]),
            Err(Error::BadType(14))
        );
        assert_eq!(
            Value::parse_prefix(b, Type::List, &[0, 0, 0, 0, 0]),
            Err(Error::BadType(0))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::List, &[0x10]),
            Err(Error::BadType(0))
        );
        assert_eq!(
            Value::parse_prefix(b, Type::Map, &[8, 1, 0, 0, 0, 0]),
            Err(Error::BadType(1))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::Map, &[1, 0xe5]),
            Err(Error::BadType(14))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::Map, &[1, 0x5f]),
            Err(Error::BadType(15))
        );
        // Booleans.
        assert_eq!(
            Value::parse_prefix(b, Type::Bool, &[2]),
            Err(Error::BadBool(2))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::Bool, &[3]),
            Err(Error::BadBool(3))
        );
        // Varints: too long, and too big.
        assert_eq!(
            Value::parse_prefix(c, Type::I32, &[0x80, 0x80, 0x80, 0x80, 0x80, 0]),
            Err(Error::BadVarint)
        );
        assert_eq!(
            Value::parse_prefix(c, Type::I32, &[0xff, 0xff, 0xff, 0xff, 0x1f]),
            Err(Error::BadVarint)
        );
        assert_eq!(
            Value::parse_prefix(c, Type::I16, &[0x80, 0x80, 0x04]),
            Err(Error::BadVarint)
        );
        assert_eq!(
            Value::parse_prefix(
                c,
                Type::I64,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]
            ),
            Err(Error::BadVarint)
        );
        assert!(
            Value::parse_prefix(
                c,
                Type::I64,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
            )
            .is_ok()
        );
        // Lengths: negative, and over the limits.
        assert_eq!(
            Value::parse_prefix(b, Type::Binary, &[0xff, 0xff, 0xff, 0xff]),
            Err(Error::Length(-1))
        );
        assert_eq!(
            Value::parse_prefix(b, Type::List, &[8, 0, 0x0f, 0x42, 0x41]),
            Err(Error::Length(1_000_001))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::List, &[0xf5, 0xc1, 0x84, 0x3d]),
            Err(Error::Length(1_000_001))
        );
        assert_eq!(
            Value::parse_prefix(c, Type::Binary, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
            Err(Error::Length(0xffff_ffff))
        );
        // A count bigger than the bytes left.
        assert_eq!(
            Value::parse_prefix(b, Type::List, &[8, 0, 0, 0, 3, 0, 0]),
            Err(Error::Truncated)
        );
        assert_eq!(
            Value::parse_prefix(c, Type::Map, &[3, 0x55, 0, 0, 0, 0]),
            Err(Error::Truncated)
        );
    }

    /// `depth` lists, each holding the next, around an empty list.
    fn nested(depth: usize) -> Value {
        let mut v = Value::List(List {
            elem: Type::I32,
            items: vec![],
        });
        for _ in 1..depth {
            v = Value::List(List {
                elem: Type::List,
                items: vec![v],
            });
        }
        v
    }

    #[test]
    fn depth_limit() {
        for p in PROTOCOLS {
            let ok = nested(MAX_DEPTH);
            let b = value_bytes(&ok, p).unwrap();
            assert_eq!(Value::parse_prefix(p, Type::List, &b), Ok((ok, b.len())));
            assert_eq!(
                value_bytes(&nested(MAX_DEPTH + 1), p),
                Err(Error::Unwritable)
            );
            // One more level by hand.
            let mut deeper = if p == Protocol::Compact {
                vec![0x19]
            } else {
                vec![15, 0, 0, 0, 1]
            };
            deeper.extend_from_slice(&b);
            assert_eq!(
                Value::parse_prefix(p, Type::List, &deeper),
                Err(Error::TooDeep)
            );
        }
        // A message body counts as depth 1.
        let m = Message {
            body: vec![Field {
                id: 1,
                value: nested(MAX_DEPTH - 1),
            }],
            ..add_call()
        };
        assert!(
            EncodedMessage {
                message: m.clone(),
                protocol: Protocol::Compact
            }
            .to_bytes()
            .is_ok()
        );
        let m = Message {
            body: vec![Field {
                id: 1,
                value: nested(MAX_DEPTH),
            }],
            ..add_call()
        };
        assert_eq!(
            EncodedMessage {
                message: m.clone(),
                protocol: Protocol::Compact
            }
            .to_bytes(),
            Err(Error::Unwritable)
        );
        // A boolean field counts too.
        let mut v = Value::Struct(vec![Field {
            id: 1,
            value: Value::Bool(true),
        }]);
        for _ in 2..MAX_DEPTH {
            v = Value::Struct(vec![Field { id: 1, value: v }]);
        }
        let b = value_bytes(&v, Protocol::Compact).unwrap();
        assert!(Value::parse_prefix(Protocol::Compact, Type::Struct, &b).is_ok());
        let v = Value::Struct(vec![Field { id: 1, value: v }]);
        assert_eq!(value_bytes(&v, Protocol::Compact), Err(Error::Unwritable));
    }

    #[test]
    fn value_count_limit() {
        let half = Value::List(List {
            elem: Type::Bool,
            items: vec![Value::Bool(true); MAX_VALUES / 2],
        });
        let v = Value::Struct(vec![
            Field {
                id: 1,
                value: half.clone(),
            },
            Field { id: 2, value: half },
        ]);
        for p in PROTOCOLS {
            let mut out = vec![7];
            let result = if p == Protocol::Compact {
                ValueBody::<true, 12>(v.clone()).write(&mut out)
            } else {
                ValueBody::<false, 12>(v.clone()).write(&mut out)
            };
            assert_eq!(result, Err(Error::Unwritable));
            assert_eq!(out, [7]);
        }
        // Built by hand: two lists of half the limit each.
        let n = (MAX_VALUES / 2) as u32;
        let mut b = Vec::new();
        for id in [1u8, 2] {
            b.extend_from_slice(&[15, 0, id, 2]);
            b.extend_from_slice(&n.to_be_bytes());
            b.extend(std::iter::repeat_n(1u8, n as usize));
        }
        b.push(0);
        assert_eq!(
            Value::parse_prefix(Protocol::Binary, Type::Struct, &b),
            Err(Error::TooMany)
        );
    }

    /// The address space this process has ever reserved, in kB.
    #[cfg(target_os = "linux")]
    fn vm_peak_kb() -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = s.lines().find(|l| l.starts_with("VmPeak:")).unwrap();
        line.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn declared_counts_do_not_reserve_memory() {
        // 62 nested lists that each claim a million elements, around a
        // million bytes. Reserving every claimed count at once would take
        // 62 million values' worth of memory for one megabyte of input.
        let n = MAX_CONTAINER_LEN as u32;
        let mut b = Vec::new();
        for _ in 0..62 {
            b.push(15);
            b.extend_from_slice(&n.to_be_bytes());
        }
        b.push(3);
        b.extend_from_slice(&n.to_be_bytes());
        b.extend(std::iter::repeat_n(0u8, n as usize));
        let before = vm_peak_kb();
        assert_eq!(
            Value::parse_prefix(Protocol::Binary, Type::List, &b),
            Err(Error::Truncated)
        );
        let grew = vm_peak_kb() - before;
        assert!(grew < 1 << 20, "reserved {grew} kB more");
    }

    #[test]
    fn write_errors() {
        for p in PROTOCOLS {
            let l = Value::List(List {
                elem: Type::I32,
                items: vec![Value::I32(1), Value::I64(1)],
            });
            assert_eq!(value_bytes(&l, p), Err(Error::Unwritable));
            let m = Value::Map(Map {
                key: Type::I32,
                value: Type::I32,
                entries: vec![(Value::I32(1), Value::Bool(true))],
            });
            assert_eq!(value_bytes(&m, p), Err(Error::Unwritable));
            let long = Value::List(List {
                elem: Type::Byte,
                items: vec![Value::Byte(0); MAX_CONTAINER_LEN + 1],
            });
            assert_eq!(value_bytes(&long, p), Err(Error::Unwritable));
            let at = Value::List(List {
                elem: Type::Byte,
                items: vec![Value::Byte(0); MAX_CONTAINER_LEN],
            });
            let b = value_bytes(&at, p).unwrap();
            assert_eq!(Value::parse_prefix(p, Type::List, &b), Ok((at, b.len())));
            let entries = vec![(Value::Byte(0), Value::Byte(0)); MAX_CONTAINER_LEN + 1];
            let long = Value::Map(Map {
                key: Type::Byte,
                value: Type::Byte,
                entries,
            });
            assert_eq!(value_bytes(&long, p), Err(Error::Unwritable));
        }
        let big = Value::Binary(vec![0; MAX_BINARY_LEN + 1]);
        assert_eq!(value_bytes(&big, Protocol::Binary), Err(Error::Unwritable));
        let at = Value::Binary(vec![0; MAX_BINARY_LEN]);
        let b = ValueBody::<true, 11>(at.clone()).to_bytes().unwrap();
        assert_eq!(
            Value::parse_prefix(Protocol::Compact, Type::Binary, &b),
            Ok((at, b.len()))
        );
        let m = Message {
            name: "x".repeat(MAX_BINARY_LEN + 1),
            ..add_call()
        };
        assert_eq!(
            EncodedMessage {
                message: m.clone(),
                protocol: Protocol::BinaryOld
            }
            .to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(
            Frame(vec![0; MAX_FRAME + 1]).to_bytes(),
            Err(Error::Unwritable)
        );
        let f = Frame(vec![0; MAX_FRAME]).to_bytes().unwrap();
        assert_eq!(Frame::parse(&f).unwrap().0.len(), MAX_FRAME);
    }

    #[test]
    fn frames() {
        let value = add_call().to_frame(Protocol::Compact).unwrap();
        let bytes = value.to_bytes().unwrap();
        assert_eq!(bytes[..4], (value.0.len() as u32).to_be_bytes());
        contract::check_wire_value(&value);
        assert_eq!(Frame::parse(&bytes), Ok(value));
        for n in 0..bytes.len() {
            assert_eq!(
                Frames::<Frame>::new().decode(&bytes[..n], false),
                Ok(Step::Need),
                "{n} bytes"
            );
            assert_eq!(Frame::parse(&bytes[..n]), Err(Error::FrameTruncated));
        }
        assert_eq!(Frame::parse(&[0; 4]), Ok(Frame(vec![])));
        assert_eq!(Frame::parse(&[0xff; 4]), Err(Error::FrameLength(-1)));
        assert_eq!(
            Frame::parse(&[0x00, 0xfa, 0x00, 0x01]),
            Err(Error::FrameLength(16_384_001))
        );
    }

    #[test]
    fn stream_splits_frames() {
        let a = add_call().to_frame(Protocol::Binary).unwrap();
        let b = Message {
            seq: 2,
            ..add_call()
        }
        .to_frame(Protocol::Compact)
        .unwrap();
        let mut bytes = a.to_bytes().unwrap();
        b.write(&mut bytes).unwrap();
        contract::check_decode_with_alloc_limit(
            Frames::<Frame>::new,
            &bytes,
            2 * Frames::<Frame>::new().capacity(),
        );
        assert_eq!(decode_all(Frames::<Frame>::new, &bytes), (vec![a, b], None));
        let mut stream = Stream::new(Frames::<Frame>::new());
        assert_eq!(stream.push(&[0x80, 0, 0, 0]), 4);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(Error::FrameLength(i32::MIN))))
        );
        assert_eq!(stream.push(&bytes), bytes.len());
        assert!(stream.next().is_none());
        assert_eq!(stream.buffered(), 4);
    }

    #[test]
    fn stream_reads_many_small_frames_in_linear_time() {
        assert_linear(
            "stream_reads_many_small_frames_in_linear_time",
            rounds(50_000),
            |size| {
                let one = Frame(vec![1, 2, 3]).to_bytes().unwrap();
                let mut stream = Stream::new(Frames::<Frame>::new());
                let mut n = 0;
                pump(&mut stream, &one.repeat(size), |frame| {
                    assert_eq!(frame.0, [1, 2, 3]);
                    n += 1;
                })
                .unwrap();
                finish(&mut stream, |_| unreachable!()).unwrap();
                assert_eq!(n, size);
                assert_eq!(stream.buffered(), 0);
            },
        );
    }

    fn check_messages(bytes: &[u8]) {
        contract::check_decode_with_alloc_limit(
            EncodedMessages::new,
            bytes,
            2 * EncodedMessages::new().capacity(),
        );
        contract::check_decode_with_held_limit(
            EncodedMessages::new,
            bytes,
            EncodedMessages::new().held(),
        );
        contract::check_wire::<EncodedMessage>(bytes);
        let mut rest = bytes;
        let mut want = Vec::new();
        let end = loop {
            match Message::parse_prefix(rest) {
                Ok((message, protocol, used)) => {
                    assert!(used > 0 && used <= rest.len());
                    want.push(EncodedMessage { message, protocol });
                    rest = &rest[used..];
                }
                Err(error) => break error,
            }
        };
        let (items, failure) = decode_all(EncodedMessages::new, bytes);
        assert_eq!(items, want);
        if end != Error::Truncated {
            assert_eq!(failure, Some(Fail::Protocol(end)));
        } else if rest.is_empty() {
            assert_eq!(failure, None);
        }
        for item in items {
            contract::check_wire_value(&item);
        }
    }

    /// A double that is NaN equals itself, so a message read twice from the
    /// same bytes is equal both times. Values are equal when their bytes
    /// are, which also tells 0.0 from -0.0.
    #[test]
    fn doubles_compare_by_their_bits() {
        let b = [
            0x82, 0x81, 0x10, 0x00, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x2d,
            0x00, 0x7a, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xff,
        ];
        assert_eq!(EncodedMessage::parse(&b), Err(Error::Trailing));
        let Step::Item(
            EncodedMessage {
                message: m,
                protocol: p,
            },
            used,
        ) = EncodedMessages::new().decode(&b, false).unwrap()
        else {
            panic!()
        };
        assert_eq!(EncodedMessage::parse(&b[..used]).unwrap().message, m);
        assert_eq!(p, Protocol::Compact);
        assert!(matches!(m.body[0].value, Value::Double(x) if x.is_nan()));
        assert_eq!(m, m.clone());
        check_messages(&b);
        assert_eq!(Value::Double(f64::NAN), Value::Double(f64::NAN));
        assert_ne!(Value::Double(0.0), Value::Double(-0.0));
    }

    #[test]
    fn messages_split_a_stream_and_report_early_errors() {
        let mut bytes = Vec::new();
        let mut want = Vec::new();
        for (seq, protocol) in PROTOCOLS.into_iter().enumerate() {
            let message = Message {
                seq: seq as i32,
                ..add_call()
            };
            EncodedMessage {
                message: message.clone(),
                protocol,
            }
            .write(&mut bytes)
            .unwrap();
            want.push(EncodedMessage { message, protocol });
        }
        check_messages(&bytes);
        assert_eq!(decode_all(EncodedMessages::new, &bytes), (want, None));
        let a = EncodedMessage {
            message: add_call(),
            protocol: Protocol::Binary,
        }
        .to_bytes()
        .unwrap();
        let mut stream = Stream::new(EncodedMessages::new());
        assert_eq!(stream.push(&a[..5]), 5);
        assert!(stream.next().is_none());
        assert_eq!(stream.buffered(), 5);
        assert_eq!(stream.push(&a[5..]), a.len() - 5);
        assert_eq!(
            stream.next(),
            Some(Ok(EncodedMessage {
                message: add_call(),
                protocol: Protocol::Binary
            }))
        );
        assert_eq!((stream.next(), stream.buffered()), (None, 0));
        assert_eq!(stream.push(&[0x81]), 1);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(Error::BadProtocol(0x81))))
        );
        assert_eq!(stream.push(&a), a.len());
        assert!(stream.next().is_none());
        for (bytes, error) in [
            (
                &[0x80, 0x01, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0x05][..],
                Error::BadType(5),
            ),
            (&[0x82, 0x21, 0, 1, 0xff][..], Error::BadUtf8),
            (
                &[0x82, 0x21, 0, 0, 0x19, 0xf9, 0x05, 0x0e][..],
                Error::BadType(14),
            ),
        ] {
            assert_eq!(EncodedMessages::new().decode(bytes, false), Err(error));
            assert_eq!(
                decode_all(EncodedMessages::new, bytes),
                (vec![], Some(Fail::Protocol(error)))
            );
            check_messages(bytes);
        }
        let bad = [0x82, 0x21, 0, 0, 0x19, 0xf9, 0x05, 0x0e];
        assert_eq!(EncodedMessage::parse(&bad), Err(Error::Truncated));
        // An exact read checks its whole-input limit first. A stream can
        // reject the first byte before it reaches that limit.
        let oversized = vec![0x81; MAX_MESSAGE + 1];
        assert_eq!(
            EncodedMessages::new().decode(&oversized, false),
            Err(Error::BadProtocol(0x81))
        );
        assert_eq!(EncodedMessage::parse(&oversized), Err(Error::TooLong));
    }

    #[test]
    fn messages_match_reference_after_complete_prefix() {
        let mut prefix = Vec::new();
        let mut want = Vec::new();
        for protocol in PROTOCOLS {
            let message = add_call();
            EncodedMessage {
                message: message.clone(),
                protocol,
            }
            .write(&mut prefix)
            .unwrap();
            want.push(EncodedMessage { message, protocol });
        }
        for (tail, failure) in [
            (&[0x81][..], Fail::Protocol(Error::BadProtocol(0x81))),
            (
                &[0x82, 0x21, 0, 1, 0xff][..],
                Fail::Protocol(Error::BadUtf8),
            ),
            (&[0x82, 0x21][..], Fail::Truncated { unread: 2 }),
        ] {
            let mut bytes = prefix.clone();
            bytes.extend_from_slice(tail);
            check_messages(&bytes);
            assert_eq!(
                decode_all(EncodedMessages::new, &bytes),
                (want.clone(), Some(failure))
            );
        }
    }

    #[test]
    fn messages_scan_in_linear_time() {
        for offset in (0..rounds(400_000)).step_by(400_000) {
            let size = (rounds(400_000) - offset).min(400_000);
            let body = (0..size)
                .map(|i| Field {
                    id: (i % 15 + 1) as i16,
                    value: Value::Bool(i % 3 == 0),
                })
                .collect();
            let dense = Message { body, ..add_call() };
            let binary = Message {
                body: vec![Field {
                    id: 1,
                    value: Value::Binary(vec![7; 1 << 20]),
                }],
                ..add_call()
            };
            for (message, protocol, size) in [
                (dense, Protocol::Compact, 1),
                (binary, Protocol::Binary, 16),
            ] {
                let bytes = EncodedMessage {
                    message: message.clone(),
                    protocol,
                }
                .to_bytes()
                .unwrap();
                fictionet::stdlib::test_support::check_work(
                    EncodedMessages::new,
                    &bytes,
                    EncodedMessages::examined,
                    32,
                    16,
                );
                let mut stream = Stream::new(EncodedMessages::new());
                let mut got = Vec::new();
                for part in chunks(&bytes, &[size]) {
                    pump(&mut stream, part, |item| got.push(item)).unwrap();
                }
                finish(&mut stream, |item| got.push(item)).unwrap();
                assert_eq!(got, [EncodedMessage { message, protocol }]);
            }
        }
    }

    #[test]
    fn messages_limit_a_message() {
        let mut bytes = vec![0x80, 0x01, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 11, 0, 1];
        bytes.extend_from_slice(&(MAX_BINARY_LEN as u32).to_be_bytes());
        let overhead = bytes.len() + 1;
        bytes.resize(overhead + MAX_BINARY_LEN, 0);
        let mut stream = Stream::new(EncodedMessages::new());
        let result = chunks(&bytes, &[1 << 20])
            .try_for_each(|part| pump(&mut stream, part, |_| unreachable!()).map(|_| ()));
        assert_eq!(result, Err(Fail::Protocol(Error::TooLong)));
        assert!(stream.buffered() <= stream.decoder().capacity());
        let message = Message {
            body: vec![Field {
                id: 1,
                value: Value::Binary(vec![0; MAX_MESSAGE - overhead]),
            }],
            name: String::new(),
            ..add_call()
        };
        let bytes = EncodedMessage {
            message: message.clone(),
            protocol: Protocol::Binary,
        }
        .to_bytes()
        .unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        assert_eq!(
            decode_all(EncodedMessages::new, &bytes),
            (
                vec![EncodedMessage {
                    message,
                    protocol: Protocol::Binary
                }],
                None
            )
        );
    }

    #[test]
    fn messages_refuse_oversize_within_capacity() {
        // The binary value fits its own limit, but the whole message does not.
        let message = Message {
            body: vec![Field {
                id: 1,
                value: Value::Binary(vec![0; MAX_BINARY_LEN]),
            }],
            ..add_call()
        };
        let value = EncodedMessage {
            message,
            protocol: Protocol::Binary,
        };
        contract::check_wire_value(&value);
        assert_eq!(value.to_bytes(), Err(Error::Unwritable));
        let mut bytes = vec![
            0x80, 1, 0, 1, 0, 0, 0, 3, b'a', b'd', b'd', 0, 0, 0, 1, 11, 0, 1,
        ];
        bytes.extend_from_slice(&(MAX_BINARY_LEN as u32).to_be_bytes());
        bytes.resize(bytes.len() + MAX_BINARY_LEN + 1, 0);
        let mut stream = Stream::new(EncodedMessages::new());
        let capacity = stream.decoder().capacity();
        assert_eq!(capacity, MAX_MESSAGE + 1);
        assert!(bytes.len() > capacity);
        assert_eq!(stream.push(&bytes), capacity);
        assert_eq!(stream.buffered(), capacity);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TooLong))));
        assert_eq!(stream.failed(), Some(&Fail::Protocol(Error::TooLong)));
        assert!(stream.buffered() <= capacity);
        assert!(stream.next().is_none());

        // A message exactly at the limit still succeeds.
        let overhead = bytes.len() - MAX_BINARY_LEN;
        let message = Message {
            body: vec![Field {
                id: 1,
                value: Value::Binary(vec![0; MAX_MESSAGE - overhead]),
            }],
            ..add_call()
        };
        let bytes = EncodedMessage {
            message: message.clone(),
            protocol: Protocol::Binary,
        }
        .to_bytes()
        .unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        let mut stream = Stream::new(EncodedMessages::new());
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(
            stream.next(),
            Some(Ok(EncodedMessage {
                message,
                protocol: Protocol::Binary
            }))
        );
        assert_eq!(stream.buffered(), 0);
    }

    #[test]
    fn messages_clone_preserves_scan_storage() {
        let message = add_call();
        for protocol in PROTOCOLS {
            let bytes = EncodedMessage {
                message: message.clone(),
                protocol,
            }
            .to_bytes()
            .unwrap();
            let mut decoder = EncodedMessages::new();
            let held = decoder.held();
            for end in 0..bytes.len() {
                assert_eq!(decoder.decode(&bytes[..end], false), Ok(Step::Need));
                let mut cloned = decoder.clone();
                assert_eq!(cloned.held(), held);
                assert_eq!(cloned.decode(&bytes[..end], false), Ok(Step::Need));
                assert_eq!(cloned.held(), held);
                assert_eq!(
                    cloned.decode(&bytes, false),
                    Ok(Step::Item(
                        EncodedMessage {
                            message: message.clone(),
                            protocol
                        },
                        bytes.len()
                    ))
                );
            }
        }
    }

    #[test]
    fn messages_rescan_after_shorter_input() {
        let message = Message {
            name: "ping".into(),
            kind: MessageType::Call,
            seq: 1,
            body: vec![],
        };
        for protocol in PROTOCOLS {
            let bytes = EncodedMessage {
                message: message.clone(),
                protocol,
            }
            .to_bytes()
            .unwrap();
            for (len, eof) in [(0, true), (2, false)] {
                let mut decoder = EncodedMessages::new();
                assert_eq!(
                    decoder.decode(&bytes[..bytes.len() - 1], false),
                    Ok(Step::Need)
                );
                assert_eq!(decoder.decode(&bytes[..len], eof), Ok(Step::Need));
                assert_eq!(
                    decoder.decode(&bytes, false),
                    Ok(Step::Item(
                        EncodedMessage {
                            message: message.clone(),
                            protocol
                        },
                        bytes.len()
                    ))
                );
            }
        }
    }

    #[test]
    fn messages_check_nested_structs_across_protocols() {
        let mut bytes = Vec::new();
        let mut want = Vec::new();
        for (seq, protocol) in PROTOCOLS.into_iter().enumerate() {
            let message = Message {
                seq: seq as i32,
                body: vec![Field {
                    id: 1,
                    value: Value::Struct(vec![Field {
                        id: 2,
                        value: Value::I64(-123),
                    }]),
                }],
                ..add_call()
            };
            EncodedMessage {
                message: message.clone(),
                protocol,
            }
            .write(&mut bytes)
            .unwrap();
            want.push(EncodedMessage { message, protocol });
        }
        check_messages(&bytes);
        assert_eq!(decode_all(EncodedMessages::new, &bytes), (want, None));
    }

    #[test]
    fn messages_bound_scan_state_and_check_contract() {
        // A chain of structs reaches the nesting limit, then exceeds it.
        for depth in [MAX_DEPTH, MAX_DEPTH + 1] {
            let mut bytes = vec![0x82, 0x21, 0, 0];
            bytes.extend(core::iter::repeat_n(0x1c, depth - 1));
            bytes.extend(core::iter::repeat_n(0, depth));
            let mut decoder = EncodedMessages::new();
            let held = decoder.held();
            assert!(held > 0 && held <= 2 * MAX_DEPTH * core::mem::size_of::<Task>());
            for end in 0..bytes.len() {
                let step = decoder.decode(&bytes[..end], false);
                assert_eq!(decoder.held(), held);
                if depth <= MAX_DEPTH {
                    assert_eq!(step, Ok(Step::Need));
                } else if step == Err(Error::TooDeep) {
                    break;
                }
            }
            if depth <= MAX_DEPTH {
                assert!(
                    matches!(decoder.decode(&bytes, false), Ok(Step::Item(_, n)) if n == bytes.len())
                );
                // State is relative to the new unread start after an item.
                assert_eq!(decoder.decode(&[], false), Ok(Step::Need));
                assert!(
                    matches!(decoder.decode(&bytes, false), Ok(Step::Item(_, n)) if n == bytes.len())
                );
            } else {
                assert_eq!(
                    EncodedMessages::new().decode(&bytes, false),
                    Err(Error::TooDeep)
                );
            }
            contract::check_decode_with_held_limit(EncodedMessages::new, &bytes, held);
        }
        for protocol in PROTOCOLS {
            let bytes = EncodedMessage {
                message: add_call(),
                protocol,
            }
            .to_bytes()
            .unwrap();
            for at in 0..bytes.len() {
                let mut malformed = bytes.clone();
                malformed[at] = 0xff;
                contract::check_decode_with_alloc_limit(
                    EncodedMessages::new,
                    &malformed,
                    2 * EncodedMessages::new().capacity(),
                );
            }
        }
        contract::check_decode_with_alloc_limit(
            EncodedMessages::new,
            &[0x82, 0x21, 0, 0, 0x19, 0xf9, 0x05, 0x0e],
            2 * EncodedMessages::new().capacity(),
        );
    }

    #[test]
    fn replies() {
        let call = add_call();
        let r = call.reply(vec![]);
        assert_eq!(
            (r.name.as_str(), r.kind, r.seq),
            ("add", MessageType::Reply, 1)
        );
        let e = call.exception(exception_kind::INTERNAL_ERROR, "boom");
        assert_eq!((e.kind, e.seq), (MessageType::Exception, 1));
        for code in 0..=255u8 {
            if let Some(t) = MessageType::from_code(code) {
                assert_eq!(t.code(), code);
            }
            if let Some(t) = Type::from_binary_code(code) {
                assert_eq!(t.binary_code(), code);
            }
            if let Some(t) = Type::from_compact_code(code) {
                assert!(t.compact_code() == code || code == 2);
            }
        }
        for t in ALL_TYPES {
            assert_eq!(Type::from_binary_code(t.binary_code()), Some(t));
            assert_eq!(Type::from_compact_code(t.compact_code()), Some(t));
        }
        assert!(!Error::TooDeep.to_string().is_empty());
        assert!(!Error::Unwritable.to_string().is_empty());
        assert!(!Error::FrameLength(-1).to_string().is_empty());
    }

    fn random_type(r: &mut Lcg, depth: usize) -> Type {
        let n = if depth >= 4 { 8 } else { ALL_TYPES.len() };
        ALL_TYPES[r.index(n)]
    }

    fn random_value(r: &mut Lcg, ty: Type, depth: usize) -> Value {
        let big = (r.next() << 31) ^ r.next();
        match ty {
            Type::Bool => Value::Bool(r.coin()),
            Type::Byte => Value::Byte(big as i8),
            Type::I16 => Value::I16(big as i16),
            Type::I32 => Value::I32(if r.coin() {
                big as i32
            } else {
                r.index(20) as i32 - 10
            }),
            Type::I64 => Value::I64((big << r.index(40)) as i64),
            Type::Double => Value::Double(big as i64 as f64 / 7.0),
            Type::Binary => Value::Binary(r.bytes(5)),
            Type::Uuid => Value::Uuid([r.next() as u8; 16]),
            Type::Struct => {
                let mut id: i16 = 0;
                let fields = (0..r.index(5))
                    .map(|_| {
                        id = match r.index(3) {
                            0 => id.wrapping_add(1),
                            1 => id.wrapping_add(r.index(20) as i16),
                            _ => r.next() as i16,
                        };
                        let t = random_type(r, depth + 1);
                        Field {
                            id,
                            value: random_value(r, t, depth + 1),
                        }
                    })
                    .collect();
                Value::Struct(fields)
            }
            Type::List | Type::Set => {
                let elem = random_type(r, depth + 1);
                let n = if r.index(8) == 0 {
                    15 + r.index(5)
                } else {
                    r.index(4)
                };
                let items = (0..n).map(|_| random_value(r, elem, depth + 1)).collect();
                let l = List { elem, items };
                if ty == Type::List {
                    Value::List(l)
                } else {
                    Value::Set(l)
                }
            }
            Type::Map => {
                let n = r.index(4);
                let (key, value) = if n == 0 {
                    (Type::Byte, Type::Byte)
                } else {
                    (random_type(r, depth + 1), random_type(r, depth + 1))
                };
                let entries = (0..n)
                    .map(|_| {
                        (
                            random_value(r, key, depth + 1),
                            random_value(r, value, depth + 1),
                        )
                    })
                    .collect();
                Value::Map(Map {
                    key,
                    value,
                    entries,
                })
            }
        }
    }

    fn random_message(r: &mut Lcg) -> Message {
        let Value::Struct(body) = random_value(r, Type::Struct, 1) else {
            unreachable!()
        };
        Message {
            name: ["", "ping", "getUser", "\u{e9}t\u{e9}"][r.index(4)].to_string(),
            kind: MessageType::from_code(1 + r.index(4) as u8).unwrap(),
            seq: r.next() as i32 - (1 << 30),
            body,
        }
    }

    /// Checks that a message read from damaged bytes writes and reads back
    /// to the same bytes.
    fn rewrites(m: &Message, p: Protocol) {
        let b = EncodedMessage {
            message: m.clone(),
            protocol: p,
        }
        .to_bytes()
        .unwrap();
        let EncodedMessage {
            message: again,
            protocol: q,
        } = EncodedMessage::parse(&b).unwrap();
        assert_eq!(q, p);
        assert_eq!(
            EncodedMessage {
                message: again.clone(),
                protocol: p
            }
            .to_bytes()
            .unwrap(),
            b
        );
    }

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg::new(9090);
        for i in 0..fictionet::stdlib::test_support::rounds(1000) {
            let m = random_message(&mut r);
            let p = PROTOCOLS[i % 3];
            let b = EncodedMessage {
                message: m.clone(),
                protocol: p,
            }
            .to_bytes()
            .unwrap();
            assert_eq!(
                EncodedMessage::parse(&b),
                Ok(EncodedMessage {
                    message: m.clone(),
                    protocol: p
                })
            );
            // Every proper prefix is truncated.
            for n in 0..b.len() {
                assert_eq!(
                    EncodedMessage::parse(&b[..n]),
                    Err(Error::Truncated),
                    "{n} of {}",
                    b.len()
                );
            }
            // Each value type alone round trips too.
            let t = random_type(&mut r, 1);
            let v = random_value(&mut r, t, 1);
            let vb = value_bytes(&v, p).unwrap();
            assert_eq!(Value::parse_prefix(p, t, &vb), Ok((v, vb.len())));
            for n in 0..vb.len() {
                assert_eq!(Value::parse_prefix(p, t, &vb[..n]), Err(Error::Truncated));
            }
            // Damaged copies never panic, and what parses rewrites the same.
            for _ in 0..4 {
                let mut d = b.clone();
                mutate(&mut r, &mut d);
                if let Ok(EncodedMessage {
                    message: m,
                    protocol: q,
                }) = EncodedMessage::parse(&d)
                {
                    rewrites(&m, q);
                }
                check_messages(&d);
                for t in ALL_TYPES {
                    for p in PROTOCOLS {
                        if let Ok((v, used)) = Value::parse_prefix(p, t, &d) {
                            assert!(used <= d.len());
                            let vb = value_bytes(&v, p).unwrap();
                            let (back, n) = Value::parse_prefix(p, t, &vb).unwrap();
                            assert_eq!(n, vb.len());
                            assert_eq!(value_bytes(&back, p).unwrap(), vb);
                        }
                    }
                }
            }
            // Random bytes.
            let junk = r.bytes(39);
            if let Ok(EncodedMessage {
                message: m,
                protocol: q,
            }) = EncodedMessage::parse(&junk)
            {
                rewrites(&m, q);
            }
            check_messages(&junk);
            for t in ALL_TYPES {
                let _ = Value::parse_prefix(Protocol::Compact, t, &junk);
                let _ = Value::parse_prefix(Protocol::Binary, t, &junk);
            }
        }
    }

    #[test]
    fn lcg_fuzz_streams() {
        let mut r = Lcg::new(1);
        for _ in 0..1000 {
            // Framed messages, sometimes damaged, checked across input partitions.
            let mut stream = Vec::new();
            for _ in 0..1 + r.index(3) {
                let p = PROTOCOLS[r.index(3)];
                stream.extend(
                    random_message(&mut r)
                        .to_frame(p)
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                );
            }
            if r.index(3) == 0 {
                let at = r.index(stream.len());
                stream[at] = r.next() as u8;
            }
            contract::check_decode_with_alloc_limit(
                Frames::<Frame>::new,
                &stream,
                2 * Frames::<Frame>::new().capacity(),
            );
            let frames = decode_all(Frames::<Frame>::new, &stream).0;
            // The same messages without frames, sometimes damaged.
            let mut bare = Vec::new();
            for _ in 0..1 + r.index(3) {
                let p = PROTOCOLS[r.index(3)];
                bare.extend(
                    EncodedMessage {
                        message: random_message(&mut r),
                        protocol: p,
                    }
                    .to_bytes()
                    .unwrap(),
                );
            }
            if r.coin() {
                let at = r.index(bare.len());
                bare[at] = r.next() as u8;
            }
            check_messages(&bare);
            for f in frames {
                if let Ok(EncodedMessage {
                    message: m,
                    protocol: q,
                }) = EncodedMessage::parse(&f.0)
                {
                    rewrites(&m, q);
                }
            }
        }
    }
}
