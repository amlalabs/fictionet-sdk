//! Protocol Buffers: reading and writing the wire format, with no schema
//! and no I/O.
//!
//! Protocol Buffers (protobuf) is how gRPC, and many other systems, pack
//! structured data into bytes. A message is a list of fields. Each field
//! starts with a tag: a varint holding the field number and a wire type.
//! The wire type says how long the value is: a varint, 4 bytes, 8 bytes,
//! a length and that many bytes, or a group of fields closed by an end tag.
//! This module follows the encoding documentation at
//! <https://protobuf.dev/programming-guides/encoding/>, and the gRPC
//! message framing in the gRPC over HTTP/2 protocol document.
//!
//! The wire format does not say what a field means. A varint may be an
//! `int32`, a `bool` or an enum, and length-delimited bytes may be a
//! string, an embedded message or a packed list. So [`Message::parse`]
//! keeps each field as it came, as a [`Field`] with a [`Value`], and world
//! code that knows the schema reads them with helpers such as
//! [`Message::int32`], [`Message::string`] and [`Message::message`]. The
//! helpers follow the encoding rules for fields that appear more than once:
//! the last scalar wins, embedded messages merge, and repeated numbers may
//! come packed or one by one.
//!
//! Nothing here reads a socket. A world that plays a gRPC server takes
//! the request body from its HTTP/2 stream, feeds it to [`Frames`] through
//! [`super::codec::Stream`],
//! parses each [`Frame`]'s data as a [`Message`], and writes the reply's
//! bytes back. Every reader checks lengths and limits, because the agent
//! can send any bytes it likes. Messages are capped at [`MAX_MESSAGE`]
//! bytes and [`MAX_FIELDS`] fields, and groups and embedded messages nest
//! at most [`MAX_DEPTH`] deep. Writers keep to the same limits, so whatever they write, the
//! parser reads back.
//!
//! Use [`Frames`] with [`super::codec::Stream`] for bounded framing.
//! [`Wire`] reads complete messages, gRPC frames, and [`DelimitedFrame`]s.
//! The deprecated [`Decoder`] keeps its original buffering and errors.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, finish, pump};
//! use fictionet::stdlib::protobuf::{Frame, Frames, Framing, Message};
//!
//! // A gRPC request carrying `{ name: "tank-3", level: 150 }`, where
//! // name is field 1 (a string) and level is field 2 (an int32).
//! let mut stream = Stream::new(Frames::new(Framing::Grpc));
//! let bytes = [0, 0, 0, 0, 11, 0x0a, 6, b't', b'a', b'n', b'k', b'-', b'3', 0x10, 0x96, 0x01];
//! let mut frames = Vec::new();
//! pump(&mut stream, &bytes, |frame| frames.push(frame)).unwrap();
//! finish(&mut stream, |frame| frames.push(frame)).unwrap();
//! let frame = frames.pop().unwrap();
//! assert!(!frame.compressed);
//! let request = Message::parse(&frame.data).unwrap();
//! assert_eq!(request.string(1), Ok(Some("tank-3")));
//! assert_eq!(request.int32(2), Some(150));
//!
//! // The reply: `{ ok: true, readings: [3, 270] }`, with readings packed.
//! let mut reply = Message::new();
//! reply.push_bool(1, true);
//! reply.push_packed_varints(2, &[3, 270]);
//! let data = reply.to_bytes().unwrap();
//! assert_eq!(data, [0x08, 0x01, 0x12, 0x03, 0x03, 0x8e, 0x02]);
//! let bytes = Frame { compressed: false, data }.to_bytes(Framing::Grpc).unwrap();
//! assert_eq!(bytes[..5], [0, 0, 0, 0, 7]);
//! ```

extern crate alloc;

use alloc::vec::Vec;
use super::codec::{Decode, Step, Wire};

/// The largest message, in bytes, that this module reads or writes. It is
/// the default limit on a received message in gRPC (4 MiB).
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// The most fields one message may hold, counting the fields inside its
/// groups.
pub const MAX_FIELDS: usize = 65_536;
/// How deep groups and embedded messages may nest. It matches the default
/// recursion limit of the protobuf libraries. [`Message::parse_at`],
/// [`Message::message_at`] and [`Message::repeated_messages_at`] take the
/// depth reached so far, so a walk through embedded messages stops here.
pub const MAX_DEPTH: usize = 100;
/// The largest field number: 2^29 - 1.
pub const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;
/// The longest varint, in bytes. Ten bytes hold 64 bits.
pub const MAX_VARINT_LEN: usize = 10;
/// The length of the header gRPC puts before each message: a flag byte
/// and a 4-byte length.
pub const GRPC_HEADER_LEN: usize = 5;
/// The most bytes a [`Decoder`] holds that have not yet been taken out as
/// frames: room for two of the largest gRPC frames.
pub const MAX_BUFFERED: usize = 2 * (GRPC_HEADER_LEN + MAX_MESSAGE);

/// The wire types a tag can carry.
pub mod wire_type {
    /// A varint: `int32`, `int64`, `uint32`, `uint64`, `sint32`, `sint64`,
    /// `bool` and enums.
    pub const VARINT: u8 = 0;
    /// Eight bytes: `fixed64`, `sfixed64` and `double`.
    pub const I64: u8 = 1;
    /// A varint length, then that many bytes: strings, bytes, embedded
    /// messages and packed repeated fields.
    pub const LEN: u8 = 2;
    /// The start of a group (deprecated).
    pub const SGROUP: u8 = 3;
    /// The end of a group (deprecated).
    pub const EGROUP: u8 = 4;
    /// Four bytes: `fixed32`, `sfixed32` and `float`.
    pub const I32: u8 = 5;
}

/// Why bytes are not a protobuf message, a frame, or the value asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes ended inside a field, a length ran past the end, or a
    /// packed body ended inside a value.
    Truncated,
    /// A varint ran past 10 bytes or past 64 bits.
    VarintOverflow,
    /// A tag held field number 0 or one above [`MAX_FIELD_NUMBER`].
    FieldNumber(u64),
    /// A tag held wire type 6 or 7, which do not exist.
    WireType(u8),
    /// An end-group tag with this field number came with no group of that
    /// number open.
    EndGroup(u32),
    /// The bytes ended while the group with this field number was open.
    UnclosedGroup(u32),
    /// A message or frame was longer than [`MAX_MESSAGE`].
    TooLong,
    /// A message held more than [`MAX_FIELDS`] fields.
    TooManyFields,
    /// Groups nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A string field was not UTF-8.
    Utf8,
    /// A gRPC frame's flag byte was not 0 or 1.
    Flag(u8),
    /// A compressed frame was to be written with [`Framing::Delimited`],
    /// which has no way to say so.
    Compressed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => write!(f, "protobuf: the bytes end inside a field"),
            Error::VarintOverflow => write!(f, "protobuf: a varint is longer than 64 bits"),
            Error::FieldNumber(n) => write!(f, "protobuf: field number {n} is out of range"),
            Error::WireType(t) => write!(f, "protobuf: wire type {t} does not exist"),
            Error::EndGroup(n) => write!(f, "protobuf: end of group {n}, which is not open"),
            Error::UnclosedGroup(n) => write!(f, "protobuf: group {n} is never closed"),
            Error::TooLong => write!(f, "protobuf: longer than {MAX_MESSAGE} bytes"),
            Error::TooManyFields => write!(f, "protobuf: more than {MAX_FIELDS} fields"),
            Error::TooDeep => write!(f, "protobuf: groups nest deeper than {MAX_DEPTH}"),
            Error::Utf8 => write!(f, "protobuf: a string is not UTF-8"),
            Error::Flag(b) => write!(f, "gRPC: flag byte {b} is not 0 or 1"),
            Error::Compressed => write!(f, "protobuf: delimited framing cannot mark compression"),
        }
    }
}

impl core::error::Error for Error {}

/// Reads the varint at the start of `b`. It returns the value and how many
/// bytes it took. Varints may carry extra zero groups (an overlong
/// encoding), and those are read like any other.
pub fn decode_varint(b: &[u8]) -> Result<(u64, usize), Error> {
    let mut v = 0u64;
    for i in 0..MAX_VARINT_LEN {
        let Some(&byte) = b.get(i) else { return Err(Error::Truncated) };
        // The tenth byte holds only bit 63.
        if i == MAX_VARINT_LEN - 1 && byte > 1 {
            return Err(Error::VarintOverflow);
        }
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((v, i + 1));
        }
    }
    Err(Error::VarintOverflow)
}

/// Appends `v` to `out` as a varint, in the shortest form.
pub fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Maps a signed 64-bit number onto an unsigned one, so that small
/// negative numbers make short varints: 0, -1, 1, -2 become 0, 1, 2, 3.
pub fn zigzag_encode64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Undoes [`zigzag_encode64`].
pub fn zigzag_decode64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Maps a signed 32-bit number onto an unsigned one, as `sint32` fields do.
pub fn zigzag_encode32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

/// Undoes [`zigzag_encode32`].
pub fn zigzag_decode32(v: u32) -> i32 {
    ((v >> 1) as i32) ^ -((v & 1) as i32)
}

/// One field's value, as the wire type carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 1: eight bytes, little-endian.
    Fixed64(u64),
    /// Wire type 2: the bytes after the length.
    Bytes(Vec<u8>),
    /// Wire types 3 and 4: the fields between the start and end tags.
    Group(Message),
    /// Wire type 5: four bytes, little-endian.
    Fixed32(u32),
}

impl Value {
    /// The wire type this value is written with. A group's start tag has
    /// [`wire_type::SGROUP`].
    pub fn wire_type(&self) -> u8 {
        match self {
            Value::Varint(_) => wire_type::VARINT,
            Value::Fixed64(_) => wire_type::I64,
            Value::Bytes(_) => wire_type::LEN,
            Value::Group(_) => wire_type::SGROUP,
            Value::Fixed32(_) => wire_type::I32,
        }
    }
}

/// One field: its number and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field number, from 1 to [`MAX_FIELD_NUMBER`].
    pub number: u32,
    /// The value.
    pub value: Value,
}

/// A message: its fields in the order they came. The same number may
/// appear more than once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// The fields, in order.
    pub fields: Vec<Field>,
}

impl Message {
    /// A message with no fields.
    pub fn new() -> Message {
        Message::default()
    }

    /// Reads a whole message from `b`. Every byte must belong to a field.
    pub fn parse(b: &[u8]) -> Result<Message, Error> {
        Message::parse_at(b, 0)
    }

    /// Reads a message that sits `depth` levels inside others, so that
    /// groups inside it count toward [`MAX_DEPTH`] from there. A world that
    /// walks embedded messages by hand passes the depth it has reached.
    pub fn parse_at(b: &[u8], depth: usize) -> Result<Message, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let mut pos = 0;
        let mut count = 0;
        parse_fields(b, &mut pos, depth, None, &mut count)
    }

    /// The message's bytes. It fails if a field number is out of range,
    /// or the message breaks [`MAX_MESSAGE`], [`MAX_FIELDS`] or
    /// [`MAX_DEPTH`], so that [`Message::parse`] reads back whatever this
    /// writes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut count = 0;
        write_fields(self, 0, &mut out, &mut count)?;
        Ok(out)
    }

    /// Every value with field number `number`, in order.
    pub fn all(&self, number: u32) -> impl Iterator<Item = &Value> {
        self.fields.iter().filter(move |f| f.number == number).map(|f| &f.value)
    }

    /// The last value with field number `number`. For a scalar field the
    /// last one wins.
    pub fn last(&self, number: u32) -> Option<&Value> {
        self.fields.iter().rev().find(|f| f.number == number).map(|f| &f.value)
    }

    /// The last varint with field number `number`, as a `uint64`. Values
    /// of other wire types are skipped.
    pub fn uint64(&self, number: u32) -> Option<u64> {
        self.all(number).filter_map(|v| if let Value::Varint(x) = v { Some(*x) } else { None }).last()
    }

    /// The field as an `int64`.
    pub fn int64(&self, number: u32) -> Option<i64> {
        self.uint64(number).map(|v| v as i64)
    }

    /// The field as a `uint32`: the low 32 bits of the varint.
    pub fn uint32(&self, number: u32) -> Option<u32> {
        self.uint64(number).map(|v| v as u32)
    }

    /// The field as an `int32` or an enum: the low 32 bits of the varint.
    pub fn int32(&self, number: u32) -> Option<i32> {
        self.uint64(number).map(|v| v as u32 as i32)
    }

    /// The field as a `sint32`, zigzag-encoded.
    pub fn sint32(&self, number: u32) -> Option<i32> {
        self.uint64(number).map(|v| zigzag_decode32(v as u32))
    }

    /// The field as a `sint64`, zigzag-encoded.
    pub fn sint64(&self, number: u32) -> Option<i64> {
        self.uint64(number).map(zigzag_decode64)
    }

    /// The field as a `bool`: any varint but 0 is true.
    pub fn bool(&self, number: u32) -> Option<bool> {
        self.uint64(number).map(|v| v != 0)
    }

    /// The last four-byte value with field number `number`, as a `fixed32`.
    pub fn fixed32(&self, number: u32) -> Option<u32> {
        self.all(number).filter_map(|v| if let Value::Fixed32(x) = v { Some(*x) } else { None }).last()
    }

    /// The field as a `sfixed32`.
    pub fn sfixed32(&self, number: u32) -> Option<i32> {
        self.fixed32(number).map(|v| v as i32)
    }

    /// The field as a `float`.
    pub fn float(&self, number: u32) -> Option<f32> {
        self.fixed32(number).map(f32::from_bits)
    }

    /// The last eight-byte value with field number `number`, as a
    /// `fixed64`.
    pub fn fixed64(&self, number: u32) -> Option<u64> {
        self.all(number).filter_map(|v| if let Value::Fixed64(x) = v { Some(*x) } else { None }).last()
    }

    /// The field as a `sfixed64`.
    pub fn sfixed64(&self, number: u32) -> Option<i64> {
        self.fixed64(number).map(|v| v as i64)
    }

    /// The field as a `double`.
    pub fn double(&self, number: u32) -> Option<f64> {
        self.fixed64(number).map(f64::from_bits)
    }

    /// The last length-delimited value with field number `number`, as
    /// `bytes`.
    pub fn bytes(&self, number: u32) -> Option<&[u8]> {
        self.all(number).filter_map(|v| if let Value::Bytes(b) = v { Some(&b[..]) } else { None }).last()
    }

    /// The field as a `string`: the last occurrence wins. It fails if the
    /// bytes of any occurrence are not UTF-8, as protobuf parsers reject a
    /// message with a bad string even when a later one replaces it.
    pub fn string(&self, number: u32) -> Result<Option<&str>, Error> {
        let mut last = None;
        for v in self.all(number) {
            if let Value::Bytes(b) = v {
                last = Some(core::str::from_utf8(b).map_err(|_| Error::Utf8)?);
            }
        }
        Ok(last)
    }

    /// The field as an embedded message. When the field appears more than
    /// once, the copies merge, as the encoding rules say: each copy must
    /// be a whole message on its own, and the merged message holds their
    /// fields in order. For a `repeated` message field, use
    /// [`Message::repeated_messages`] instead. The message read sits one
    /// level below `self`; a world that walks a recursive schema uses
    /// [`Message::message_at`], so that the walk stops at [`MAX_DEPTH`].
    pub fn message(&self, number: u32) -> Result<Option<Message>, Error> {
        self.message_at(number, 0)
    }

    /// Like [`Message::message`], for a message `self` that sits `depth`
    /// levels inside others. The message read sits at `depth + 1`, and
    /// groups inside it count toward [`MAX_DEPTH`] from there. It fails
    /// with [`Error::TooDeep`] if the field is present and `depth + 1` is
    /// above [`MAX_DEPTH`].
    pub fn message_at(&self, number: u32, depth: usize) -> Result<Option<Message>, Error> {
        // The merged message must fit in one, as its bytes joined would.
        let len =
            self.all(number).map(|v| if let Value::Bytes(b) = v { b.len() } else { 0 }).fold(0, usize::saturating_add);
        if len > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let mut merged: Option<Message> = None;
        let mut count = 0;
        for v in self.all(number) {
            if let Value::Bytes(b) = v {
                let m = parse_entry(b, depth, &mut count)?;
                merged.get_or_insert_with(Message::new).fields.extend(m.fields);
            }
        }
        Ok(merged)
    }

    /// Every entry of a `repeated` embedded message field, each read as its
    /// own message, in order. It fails if any entry is not a message, or if
    /// the entries hold more than [`MAX_FIELDS`] fields between them,
    /// counting the fields inside their groups.
    pub fn repeated_messages(&self, number: u32) -> Result<Vec<Message>, Error> {
        self.repeated_messages_at(number, 0)
    }

    /// Like [`Message::repeated_messages`], for a message `self` that sits
    /// `depth` levels inside others, as with [`Message::message_at`].
    pub fn repeated_messages_at(&self, number: u32, depth: usize) -> Result<Vec<Message>, Error> {
        let mut out = Vec::new();
        let mut count = 0;
        for v in self.all(number) {
            if let Value::Bytes(b) = v {
                out.push(parse_entry(b, depth, &mut count)?);
            }
        }
        Ok(out)
    }

    /// Every entry of a `repeated` string field, in order. It fails if any
    /// entry is not UTF-8.
    pub fn repeated_strings(&self, number: u32) -> Result<Vec<&str>, Error> {
        let mut out = Vec::new();
        for v in self.all(number) {
            if let Value::Bytes(b) = v {
                out.push(core::str::from_utf8(b).map_err(|_| Error::Utf8)?);
            }
        }
        Ok(out)
    }

    /// The field as a singular group. Groups follow the rules of embedded
    /// messages, so when the field appears more than once the copies merge:
    /// the result holds their fields in order. For a `repeated` group
    /// field, read each occurrence from [`Message::all`].
    pub fn group(&self, number: u32) -> Option<Message> {
        let mut merged: Option<Message> = None;
        for v in self.all(number) {
            if let Value::Group(g) = v {
                merged.get_or_insert_with(Message::new).fields.extend(g.fields.iter().cloned());
            }
        }
        merged
    }

    /// Every number in a repeated varint field, whether it came packed,
    /// one by one, or both. Parsers must accept either form.
    pub fn repeated_varints(&self, number: u32) -> Result<Vec<u64>, Error> {
        let mut out = Vec::new();
        for v in self.all(number) {
            match v {
                Value::Varint(x) => out.push(*x),
                Value::Bytes(b) => {
                    let mut rest = &b[..];
                    while !rest.is_empty() {
                        let (x, n) = decode_varint(rest)?;
                        out.push(x);
                        rest = &rest[n..];
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Every number in a repeated four-byte field, packed or not.
    pub fn repeated_fixed32(&self, number: u32) -> Result<Vec<u32>, Error> {
        let mut out = Vec::new();
        for v in self.all(number) {
            match v {
                Value::Fixed32(x) => out.push(*x),
                Value::Bytes(b) => {
                    if b.len() % 4 != 0 {
                        return Err(Error::Truncated);
                    }
                    out.extend(b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])));
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Every number in a repeated eight-byte field, packed or not.
    pub fn repeated_fixed64(&self, number: u32) -> Result<Vec<u64>, Error> {
        let mut out = Vec::new();
        for v in self.all(number) {
            match v {
                Value::Fixed64(x) => out.push(*x),
                Value::Bytes(b) => {
                    if b.len() % 8 != 0 {
                        return Err(Error::Truncated);
                    }
                    out.extend(b.chunks_exact(8).map(|c| {
                        let mut a = [0u8; 8];
                        a.copy_from_slice(c);
                        u64::from_le_bytes(a)
                    }));
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Adds a field.
    pub fn push(&mut self, number: u32, value: Value) {
        self.fields.push(Field { number, value });
    }

    /// Adds a `uint64` field.
    pub fn push_uint64(&mut self, number: u32, v: u64) {
        self.push(number, Value::Varint(v));
    }

    /// Adds an `int64` field.
    pub fn push_int64(&mut self, number: u32, v: i64) {
        self.push(number, Value::Varint(v as u64));
    }

    /// Adds a `uint32` field.
    pub fn push_uint32(&mut self, number: u32, v: u32) {
        self.push(number, Value::Varint(u64::from(v)));
    }

    /// Adds an `int32` or enum field. A negative value takes ten bytes, as
    /// the encoding rules say.
    pub fn push_int32(&mut self, number: u32, v: i32) {
        self.push(number, Value::Varint(i64::from(v) as u64));
    }

    /// Adds a `sint32` field.
    pub fn push_sint32(&mut self, number: u32, v: i32) {
        self.push(number, Value::Varint(u64::from(zigzag_encode32(v))));
    }

    /// Adds a `sint64` field.
    pub fn push_sint64(&mut self, number: u32, v: i64) {
        self.push(number, Value::Varint(zigzag_encode64(v)));
    }

    /// Adds a `bool` field.
    pub fn push_bool(&mut self, number: u32, v: bool) {
        self.push(number, Value::Varint(u64::from(v)));
    }

    /// Adds a `fixed32` field.
    pub fn push_fixed32(&mut self, number: u32, v: u32) {
        self.push(number, Value::Fixed32(v));
    }

    /// Adds a `sfixed32` field.
    pub fn push_sfixed32(&mut self, number: u32, v: i32) {
        self.push(number, Value::Fixed32(v as u32));
    }

    /// Adds a `float` field.
    pub fn push_float(&mut self, number: u32, v: f32) {
        self.push(number, Value::Fixed32(v.to_bits()));
    }

    /// Adds a `fixed64` field.
    pub fn push_fixed64(&mut self, number: u32, v: u64) {
        self.push(number, Value::Fixed64(v));
    }

    /// Adds a `sfixed64` field.
    pub fn push_sfixed64(&mut self, number: u32, v: i64) {
        self.push(number, Value::Fixed64(v as u64));
    }

    /// Adds a `double` field.
    pub fn push_double(&mut self, number: u32, v: f64) {
        self.push(number, Value::Fixed64(v.to_bits()));
    }

    /// Adds a `bytes` field.
    pub fn push_bytes(&mut self, number: u32, v: &[u8]) {
        self.push(number, Value::Bytes(v.to_vec()));
    }

    /// Adds a `string` field.
    pub fn push_string(&mut self, number: u32, v: &str) {
        self.push_bytes(number, v.as_bytes());
    }

    /// Adds an embedded message. It fails if `m` cannot be written.
    pub fn push_message(&mut self, number: u32, m: &Message) -> Result<(), Error> {
        let b = m.to_bytes()?;
        self.push(number, Value::Bytes(b));
        Ok(())
    }

    /// Adds a group.
    pub fn push_group(&mut self, number: u32, m: Message) {
        self.push(number, Value::Group(m));
    }

    /// Adds a packed repeated varint field. Nothing is added for an empty
    /// list, as protobuf writers do.
    pub fn push_packed_varints(&mut self, number: u32, vs: &[u64]) {
        if vs.is_empty() {
            return;
        }
        let mut b = Vec::new();
        for &v in vs {
            encode_varint(v, &mut b);
        }
        self.push(number, Value::Bytes(b));
    }

    /// Adds a packed repeated four-byte field.
    pub fn push_packed_fixed32(&mut self, number: u32, vs: &[u32]) {
        if !vs.is_empty() {
            self.push(number, Value::Bytes(vs.iter().flat_map(|v| v.to_le_bytes()).collect()));
        }
    }

    /// Adds a packed repeated eight-byte field.
    pub fn push_packed_fixed64(&mut self, number: u32, vs: &[u64]) {
        if !vs.is_empty() {
            self.push(number, Value::Bytes(vs.iter().flat_map(|v| v.to_le_bytes()).collect()));
        }
    }
}

/// Reads one occurrence of an embedded message field of a message at
/// `depth`, adding its fields, group members included, to `count`.
fn parse_entry(b: &[u8], depth: usize, count: &mut usize) -> Result<Message, Error> {
    let depth = depth.checked_add(1).filter(|&d| d <= MAX_DEPTH).ok_or(Error::TooDeep)?;
    if b.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let mut pos = 0;
    parse_fields(b, &mut pos, depth, None, count)
}

/// Reads fields from `b[*pos..]` until the end, or until the end tag of
/// `group`. The depth check before each group bounds the recursion.
fn parse_fields(
    b: &[u8],
    pos: &mut usize,
    depth: usize,
    group: Option<u32>,
    count: &mut usize,
) -> Result<Message, Error> {
    let mut m = Message::new();
    loop {
        let Some(rest) = b.get(*pos..).filter(|r| !r.is_empty()) else {
            return match group {
                Some(n) => Err(Error::UnclosedGroup(n)),
                None => Ok(m),
            };
        };
        let (key, n) = decode_varint(rest)?;
        *pos += n;
        let number = key >> 3;
        if number == 0 || number > u64::from(MAX_FIELD_NUMBER) {
            return Err(Error::FieldNumber(number));
        }
        let number = number as u32;
        let wire = (key & 7) as u8;
        let rest = &b[*pos..];
        let value = match wire {
            wire_type::VARINT => {
                let (v, n) = decode_varint(rest)?;
                *pos += n;
                Value::Varint(v)
            }
            wire_type::I64 => {
                let a: [u8; 8] = rest.get(..8).ok_or(Error::Truncated)?.try_into().map_err(|_| Error::Truncated)?;
                *pos += 8;
                Value::Fixed64(u64::from_le_bytes(a))
            }
            wire_type::LEN => {
                let (len, n) = decode_varint(rest)?;
                let body =
                    usize::try_from(len).ok().and_then(|len| rest.get(n..)?.get(..len)).ok_or(Error::Truncated)?;
                *pos += n + body.len();
                Value::Bytes(body.to_vec())
            }
            wire_type::SGROUP => {
                if depth >= MAX_DEPTH {
                    return Err(Error::TooDeep);
                }
                // Count the group before its members, as the writer does.
                *count += 1;
                if *count > MAX_FIELDS {
                    return Err(Error::TooManyFields);
                }
                let inner = parse_fields(b, pos, depth + 1, Some(number), count)?;
                m.fields.push(Field { number, value: Value::Group(inner) });
                continue;
            }
            wire_type::EGROUP => {
                if group == Some(number) {
                    return Ok(m);
                }
                return Err(Error::EndGroup(number));
            }
            wire_type::I32 => {
                let a: [u8; 4] = rest.get(..4).ok_or(Error::Truncated)?.try_into().map_err(|_| Error::Truncated)?;
                *pos += 4;
                Value::Fixed32(u32::from_le_bytes(a))
            }
            other => return Err(Error::WireType(other)),
        };
        *count += 1;
        if *count > MAX_FIELDS {
            return Err(Error::TooManyFields);
        }
        m.fields.push(Field { number, value });
    }
}

/// Appends the fields of `m` to `out`, checking every limit the parser
/// checks. The depth check before each group bounds the recursion.
fn write_fields(m: &Message, depth: usize, out: &mut Vec<u8>, count: &mut usize) -> Result<(), Error> {
    for f in &m.fields {
        if f.number == 0 || f.number > MAX_FIELD_NUMBER {
            return Err(Error::FieldNumber(u64::from(f.number)));
        }
        *count += 1;
        if *count > MAX_FIELDS {
            return Err(Error::TooManyFields);
        }
        let tag = |wire: u8| (u64::from(f.number) << 3) | u64::from(wire);
        encode_varint(tag(f.value.wire_type()), out);
        match &f.value {
            Value::Varint(v) => encode_varint(*v, out),
            Value::Fixed64(v) => out.extend_from_slice(&v.to_le_bytes()),
            Value::Fixed32(v) => out.extend_from_slice(&v.to_le_bytes()),
            Value::Bytes(b) => {
                // Check before copying, so a huge value is never copied.
                if out.len().saturating_add(b.len()) > MAX_MESSAGE {
                    return Err(Error::TooLong);
                }
                encode_varint(b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Value::Group(g) => {
                if depth >= MAX_DEPTH {
                    return Err(Error::TooDeep);
                }
                write_fields(g, depth + 1, out, count)?;
                encode_varint(tag(wire_type::EGROUP), out);
            }
        }
        if out.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
    }
    Ok(())
}

/// How messages are marked off in a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// gRPC's framing: a flag byte (1 if the message is compressed), a
    /// 4-byte big-endian length, then the message.
    Grpc,
    /// A varint length, then the message, as the protobuf libraries'
    /// delimited readers and writers do.
    Delimited,
}

/// One message taken from a stream, still as bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Whether the sender compressed the message. This module does not
    /// decompress; a world that accepts compression does that itself.
    /// Always false with [`Framing::Delimited`].
    pub compressed: bool,
    /// The message's bytes.
    pub data: Vec<u8>,
}

impl Frame {
    /// Reads the frame at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the frame and how many bytes
    /// of `b` it took.
    pub fn parse(framing: Framing, b: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
        let (compressed, len, start) = match framing {
            Framing::Grpc => {
                let Some(&flag) = b.first() else { return Ok(None) };
                if flag > 1 {
                    return Err(Error::Flag(flag));
                }
                let Some(h) = b.get(1..GRPC_HEADER_LEN) else { return Ok(None) };
                let len = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
                (flag == 1, u64::from(len), GRPC_HEADER_LEN)
            }
            Framing::Delimited => match decode_varint(b) {
                Ok((len, n)) => (false, len, n),
                Err(Error::Truncated) => return Ok(None),
                Err(e) => return Err(e),
            },
        };
        if len > MAX_MESSAGE as u64 {
            return Err(Error::TooLong);
        }
        let end = start + len as usize;
        let Some(data) = b.get(start..end) else { return Ok(None) };
        Ok(Some((Frame { compressed, data: data.to_vec() }, end)))
    }

    /// The frame's bytes. It fails if the data is longer than
    /// [`MAX_MESSAGE`], or if a compressed frame is to be written with
    /// [`Framing::Delimited`].
    pub fn to_bytes(&self, framing: Framing) -> Result<Vec<u8>, Error> {
        if self.data.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let mut out = Vec::with_capacity(GRPC_HEADER_LEN + self.data.len());
        match framing {
            Framing::Grpc => {
                out.push(u8::from(self.compressed));
                out.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
            }
            Framing::Delimited => {
                if self.compressed {
                    return Err(Error::Compressed);
                }
                encode_varint(self.data.len() as u64, &mut out);
            }
        }
        out.extend_from_slice(&self.data);
        Ok(out)
    }
}

/// Why an exact framed parse failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// Invalid framing or incomplete input.
    Frame(Error),
    /// Bytes followed the first complete frame.
    Trailing {
        /// The number of bytes after the frame.
        remaining: usize,
    },
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Trailing { remaining } => {
                write!(f, "trailing bytes after the frame: {remaining}")
            }
        }
    }
}

impl core::error::Error for FrameParseError {}

fn exact_frame(framing: Framing, input: &[u8]) -> Result<Frame, FrameParseError> {
    match Frame::parse(framing, input).map_err(FrameParseError::Frame)? {
        Some((frame, used)) if used == input.len() => Ok(frame),
        Some((_, used)) => Err(FrameParseError::Trailing {
            remaining: input.len().saturating_sub(used),
        }),
        None => Err(FrameParseError::Frame(Error::Truncated)),
    }
}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = Error;

    /// Reads exactly one gRPC frame. The inherent parser still takes a framing.
    fn parse(input: &[u8]) -> Result<Self, FrameParseError> {
        exact_frame(Framing::Grpc, input)
    }

    /// Appends one gRPC frame. Refuses oversized bodies before changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.to_bytes(Framing::Grpc)?);
        Ok(())
    }
}

/// A frame whose [`Wire`] form uses a varint length instead of gRPC framing.
/// Compressed values are refused by the writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelimitedFrame(
    /// The message bytes and compression flag.
    pub Frame,
);

impl Wire for DelimitedFrame {
    type ParseError = FrameParseError;
    type WriteError = Error;

    fn parse(input: &[u8]) -> Result<Self, FrameParseError> {
        exact_frame(Framing::Delimited, input).map(Self)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.0.to_bytes(Framing::Delimited)?);
        Ok(())
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(input: &[u8]) -> Result<Self, Error> {
        Self::parse(input)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.to_bytes()?);
        Ok(())
    }
}

/// Reads length-prefixed frames without retaining input bytes.
///
/// Both framings use [`Frame::parse`]. Malformed headers and oversized
/// lengths end the stream. Incomplete frames return
/// [`Step::Need`], including at EOF. Capacity is [`MAX_MESSAGE`] plus
/// [`GRPC_HEADER_LEN`] or [`MAX_VARINT_LEN`], according to the framing.
/// Map items through [`Message::parse`]
/// to handle payload errors per item. Use [`codec::Stream`](super::codec::Stream) for bounded input.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, finish, pump}, protobuf::{Frame, Frames, Framing}};
///
/// let mut stream = Stream::new(Frames::new(Framing::Delimited));
/// let mut frames = Vec::new();
/// pump(&mut stream, &[2, 0x08], |frame| frames.push(frame))?;
/// pump(&mut stream, &[1], |frame| frames.push(frame))?;
/// finish(&mut stream, |frame| frames.push(frame))?;
/// assert_eq!(frames, vec![Frame { compressed: false, data: vec![0x08, 1] }]);
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::protobuf::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Frames {
    framing: Framing,
}

impl Frames {
    /// Reads `framing` with bodies bounded by [`MAX_MESSAGE`].
    pub fn new(framing: Framing) -> Self {
        Self { framing }
    }

    /// The framing this decoder reads.
    pub fn framing(&self) -> Framing {
        self.framing
    }
}

impl Decode for Frames {
    type Item = Frame;
    type Error = Error;
    const NAME: &'static str = "Protobuf";

    fn capacity(&self) -> usize {
        match self.framing {
            Framing::Grpc => GRPC_HEADER_LEN.saturating_add(MAX_MESSAGE),
            Framing::Delimited => MAX_VARINT_LEN.saturating_add(MAX_MESSAGE),
        }
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, Error> {
        Ok(match Frame::parse(self.framing, input)? {
            Some((frame, used)) => Step::Item(frame, used),
            None => Step::Need,
        })
    }
}

/// Splits a byte stream into frames. Feed it the bytes a connection or
/// request body reads, in order, and take frames out until it has none.
/// It holds at most [`MAX_BUFFERED`] bytes that have not been taken out.
/// Two decoders are equal when they read the same framing, hold the same
/// bytes not yet taken out, and have broken in the same way, if at all.
#[derive(Clone, Debug)]
#[deprecated(note = "use codec::Stream with protobuf::Frames")]
pub struct Decoder {
    framing: Framing,
    buf: Vec<u8>,
    // Bytes before `start` belong to frames already taken out.
    start: usize,
    failed: Option<Error>,
}

#[allow(deprecated)] // Preserve the compatibility API.
impl PartialEq for Decoder {
    fn eq(&self, other: &Decoder) -> bool {
        self.framing == other.framing && self.pending() == other.pending() && self.failed == other.failed
    }
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Eq for Decoder {}

#[allow(deprecated)] // Preserve the compatibility API.
impl Decoder {
    /// A decoder for `framing`, holding no bytes.
    pub fn new(framing: Framing) -> Decoder {
        Decoder { framing, buf: Vec::new(), start: 0, failed: None }
    }

    /// Adds bytes read from the stream. If they would make the decoder
    /// hold more than [`MAX_BUFFERED`] bytes, the stream breaks with
    /// [`Error::TooLong`]. So take frames out between feeds. After an
    /// error the stream cannot be read any further, and bytes are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        if self.buffered().saturating_add(bytes.len()) > MAX_BUFFERED {
            self.fail(Error::TooLong);
            return;
        }
        // Drop the bytes of frames taken out once they outweigh the rest,
        // so each byte moves a bounded number of times.
        if self.start > 0 && self.start >= self.buffered() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole frame, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken.
    pub fn next_frame(&mut self) -> Option<Result<Frame, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match Frame::parse(self.framing, self.pending()) {
            Ok(Some((frame, used))) => {
                // Move the start instead of the bytes, so that taking out
                // many small frames costs time in line with their size.
                self.start = self.start.saturating_add(used).min(self.buf.len());
                if self.start == self.buf.len() {
                    self.buf.clear();
                    self.start = 0;
                }
                Some(Ok(frame))
            }
            Ok(None) => None,
            Err(e) => {
                self.fail(e);
                Some(Err(e))
            }
        }
    }

    /// The framing this decoder reads.
    pub fn framing(&self) -> Framing {
        self.framing
    }

    /// How many bytes are held that have not been taken out as frames.
    pub fn buffered(&self) -> usize {
        self.pending().len()
    }

    fn pending(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or(&[])
    }

    fn fail(&mut self, e: Error) {
        self.failed = Some(e);
        self.buf = Vec::new();
        self.start = 0;
    }
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the compatibility API.
mod tests {
    use super::*;

    fn varint(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(v, &mut out);
        out
    }

    // Examples from https://protobuf.dev/programming-guides/encoding/.

    #[test]
    fn varint_examples() {
        assert_eq!(varint(1), [0x01]);
        assert_eq!(varint(150), [0x96, 0x01]);
        assert_eq!(decode_varint(&[0x96, 0x01, 0xff]), Ok((150, 2)));
        // A negative int32 is sign-extended to ten bytes.
        let mut m = Message::new();
        m.push_int32(1, -1);
        let b = m.to_bytes().unwrap();
        assert_eq!(b, [0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert_eq!(Message::parse(&b).unwrap().int32(1), Some(-1));
        assert_eq!(varint(u64::MAX).len(), MAX_VARINT_LEN);
        assert_eq!(decode_varint(&varint(u64::MAX)), Ok((u64::MAX, 10)));
        // Overlong forms read the same.
        assert_eq!(decode_varint(&[0x81, 0x80, 0x80, 0x00]), Ok((1, 4)));
        for v in [0, 1, 127, 128, 16383, 16384, u64::from(u32::MAX), u64::MAX - 1] {
            assert_eq!(decode_varint(&varint(v)), Ok((v, varint(v).len())));
        }
    }

    #[test]
    fn zigzag_examples() {
        for (s, u) in [(0i64, 0u64), (-1, 1), (1, 2), (-2, 3), (0x7fff_ffff, 0xffff_fffe), (-0x8000_0000, 0xffff_ffff)]
        {
            assert_eq!(zigzag_encode64(s), u);
            assert_eq!(zigzag_decode64(u), s);
            assert_eq!(zigzag_encode32(s as i32), u as u32);
            assert_eq!(zigzag_decode32(u as u32), s as i32);
        }
        assert_eq!(zigzag_encode64(i64::MIN), u64::MAX);
        assert_eq!(zigzag_decode64(u64::MAX), i64::MIN);
        let mut m = Message::new();
        m.push_sint32(1, -2);
        m.push_sint64(2, i64::MAX);
        let p = Message::parse(&m.to_bytes().unwrap()).unwrap();
        assert_eq!(p.sint32(1), Some(-2));
        assert_eq!(p.sint64(2), Some(i64::MAX));
    }

    #[test]
    fn spec_messages() {
        // Test1 { a: 150 }
        let t1 = Message::parse(&[0x08, 0x96, 0x01]).unwrap();
        assert_eq!(t1.fields, [Field { number: 1, value: Value::Varint(150) }]);
        // Test2 { b: "testing" }
        let t2 = Message::parse(&[0x12, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67]).unwrap();
        assert_eq!(t2.string(2), Ok(Some("testing")));
        // Test3 { c: Test1 { a: 150 } }
        let t3 = Message::parse(&[0x1a, 0x03, 0x08, 0x96, 0x01]).unwrap();
        assert_eq!(t3.message(3), Ok(Some(t1.clone())));
        let mut w = Message::new();
        w.push_message(3, &t1).unwrap();
        assert_eq!(w.to_bytes().unwrap(), [0x1a, 0x03, 0x08, 0x96, 0x01]);
        // Test5 { f: [3, 270, 86942] }, packed.
        let packed = [0x32, 0x06, 0x03, 0x8e, 0x02, 0x9e, 0xa7, 0x05];
        let t5 = Message::parse(&packed).unwrap();
        assert_eq!(t5.repeated_varints(6), Ok(vec![3, 270, 86942]));
        let mut w = Message::new();
        w.push_packed_varints(6, &[3, 270, 86942]);
        assert_eq!(w.to_bytes().unwrap(), packed);
        // A float 1.0 in field 1, and a double in field 2.
        let mut w = Message::new();
        w.push_float(1, 1.0);
        w.push_double(2, -2.5);
        let b = w.to_bytes().unwrap();
        assert_eq!(b[..5], [0x0d, 0x00, 0x00, 0x80, 0x3f]);
        let p = Message::parse(&b).unwrap();
        assert_eq!(p.float(1), Some(1.0));
        assert_eq!(p.double(2), Some(-2.5));
        assert_eq!(p.float(2), None);
    }

    #[test]
    fn repeated_fields_follow_the_rules() {
        // The last scalar wins.
        let m = Message::parse(&[0x08, 0x01, 0x08, 0x02, 0x10, 0x05, 0x08, 0x03]).unwrap();
        assert_eq!(m.uint64(1), Some(3));
        assert_eq!(m.all(1).count(), 3);
        // Embedded messages merge: { a: 1 } then { b: "x" }, and a later a.
        let m =
            Message::parse(&[0x1a, 0x02, 0x08, 0x01, 0x1a, 0x03, 0x12, 0x01, b'x', 0x1a, 0x02, 0x08, 0x07]).unwrap();
        let c = m.message(3).unwrap().unwrap();
        assert_eq!(c.uint64(1), Some(7));
        assert_eq!(c.string(2), Ok(Some("x")));
        assert_eq!(m.message(4), Ok(None));
        // Packed and unpacked mix.
        let m = Message::parse(&[0x30, 0x01, 0x32, 0x02, 0x02, 0x03, 0x30, 0x04]).unwrap();
        assert_eq!(m.repeated_varints(6), Ok(vec![1, 2, 3, 4]));
        let mut w = Message::new();
        w.push_packed_fixed32(1, &[1, 2]);
        w.push_fixed32(1, 3);
        w.push_packed_fixed64(2, &[u64::MAX]);
        w.push_fixed64(2, 5);
        w.push_packed_varints(3, &[]);
        let p = Message::parse(&w.to_bytes().unwrap()).unwrap();
        assert_eq!(p.repeated_fixed32(1), Ok(vec![1, 2, 3]));
        assert_eq!(p.repeated_fixed64(2), Ok(vec![u64::MAX, 5]));
        assert_eq!(p.last(3), None);
        // Bad packed bodies.
        let m = Message::parse(&[0x0a, 0x03, 1, 2, 3, 0x12, 0x01, 0x80]).unwrap();
        assert_eq!(m.repeated_fixed32(1), Err(Error::Truncated));
        assert_eq!(m.repeated_fixed64(1), Err(Error::Truncated));
        assert_eq!(m.repeated_varints(2), Err(Error::Truncated));
    }

    #[test]
    fn repeated_messages_stay_apart() {
        // Two entries of a repeated message field: { a: 1 } and { a: 2 }.
        let b = [0x1a, 0x02, 0x08, 0x01, 0x1a, 0x02, 0x08, 0x02, 0x10, 0x05];
        let m = Message::parse(&b).unwrap();
        let rs = m.repeated_messages(3).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].uint64(1), Some(1));
        assert_eq!(rs[1].uint64(1), Some(2));
        // The singular reader merges them instead.
        assert_eq!(m.message(3).unwrap().unwrap().all(1).count(), 2);
        assert_eq!(m.repeated_messages(4), Ok(vec![]));
        // A bad entry fails the whole list.
        let m = Message::parse(&[0x1a, 0x01, 0x08]).unwrap();
        assert_eq!(m.repeated_messages(3), Err(Error::Truncated));
        // The fields of all entries together are capped.
        let entry = [0x1a, 0x02, 0x08, 0x00];
        let m = Message::parse(&entry.repeat(MAX_FIELDS)).unwrap();
        assert_eq!(m.repeated_messages(3).unwrap().len(), MAX_FIELDS);
        let mut over = entry.repeat(MAX_FIELDS - 1);
        over.extend_from_slice(&[0x1a, 0x04, 0x08, 0x00, 0x08, 0x00]);
        let m = Message::parse(&over).unwrap();
        assert_eq!(m.repeated_messages(3), Err(Error::TooManyFields));
        // Strings, one by one.
        let mut w = Message::new();
        w.push_string(1, "a");
        w.push_uint64(1, 9);
        w.push_string(1, "bc");
        let p = Message::parse(&w.to_bytes().unwrap()).unwrap();
        assert_eq!(p.repeated_strings(1), Ok(vec!["a", "bc"]));
        let mut bad = p.clone();
        bad.push_bytes(1, &[0xff]);
        assert_eq!(bad.repeated_strings(1), Err(Error::Utf8));
    }

    #[test]
    fn writers_match_readers() {
        let mut w = Message::new();
        w.push_uint32(1, u32::MAX);
        w.push_sfixed32(2, -7);
        w.push_sfixed64(3, i64::MIN);
        let b = w.to_bytes().unwrap();
        // A uint32 is never sign-extended.
        assert_eq!(b[..6], [0x08, 0xff, 0xff, 0xff, 0xff, 0x0f]);
        let p = Message::parse(&b).unwrap();
        assert_eq!(p.uint32(1), Some(u32::MAX));
        assert_eq!(p.sfixed32(2), Some(-7));
        assert_eq!(p.sfixed64(3), Some(i64::MIN));
        // A decoder can be copied, partway through a frame.
        let mut d = Decoder::new(Framing::Grpc);
        d.feed(&[0, 0, 0, 0, 2, 0x08]);
        let mut e = d.clone();
        assert_eq!(d, e);
        assert_eq!(e.framing(), Framing::Grpc);
        e.feed(&[0x01]);
        assert_eq!(e.next_frame(), Some(Ok(Frame { compressed: false, data: vec![0x08, 0x01] })));
        assert_eq!(d.next_frame(), None);
        // Equal by what they hold, not where it sits in the buffer.
        let mut a = Decoder::new(Framing::Delimited);
        a.feed(&[0, 0, 1]);
        assert_eq!(a.next_frame(), Some(Ok(Frame { compressed: false, data: vec![] })));
        assert_eq!(a.next_frame(), Some(Ok(Frame { compressed: false, data: vec![] })));
        let mut b = Decoder::new(Framing::Delimited);
        b.feed(&[1]);
        assert_eq!(a, b);
        assert_ne!(a, Decoder::new(Framing::Grpc));
    }

    #[test]
    fn scalar_helpers() {
        let mut w = Message::new();
        w.push_uint64(1, u64::MAX);
        w.push_int64(2, -5);
        w.push_bool(3, true);
        w.push_fixed32(4, 0xffff_fffe);
        w.push_fixed64(5, u64::MAX - 1);
        w.push_bytes(6, &[0xff]);
        w.push_string(7, "hi");
        let p = Message::parse(&w.to_bytes().unwrap()).unwrap();
        assert_eq!(p.uint64(1), Some(u64::MAX));
        assert_eq!(p.uint32(1), Some(u32::MAX));
        assert_eq!(p.int32(1), Some(-1));
        assert_eq!(p.int64(2), Some(-5));
        assert_eq!(p.bool(3), Some(true));
        assert_eq!(p.sfixed32(4), Some(-2));
        assert_eq!(p.sfixed64(5), Some(-2));
        assert_eq!(p.bytes(6), Some(&[0xff][..]));
        assert_eq!(p.string(6), Err(Error::Utf8));
        assert_eq!(p.string(7), Ok(Some("hi")));
        assert_eq!(p.string(8), Ok(None));
        assert_eq!(p.uint64(6), None);
        assert_eq!(p.bytes(1), None);
        assert_eq!(p.group(1), None);
    }

    #[test]
    fn groups() {
        // Group 1 holding { 2: 150 }, then field 3.
        let b = [0x0b, 0x10, 0x96, 0x01, 0x0c, 0x18, 0x01];
        let m = Message::parse(&b).unwrap();
        let g = m.group(1).unwrap();
        assert_eq!(g.uint64(2), Some(150));
        assert_eq!(m.uint64(3), Some(1));
        assert_eq!(m.to_bytes().unwrap(), b);
        // Nested groups and an empty one.
        let mut inner = Message::new();
        inner.push_group(5, Message::new());
        let mut outer = Message::new();
        outer.push_group(4, inner);
        let b = outer.to_bytes().unwrap();
        assert_eq!(b, [0x23, 0x2b, 0x2c, 0x24]);
        assert_eq!(Message::parse(&b).unwrap(), outer);
    }

    #[test]
    fn errors() {
        assert_eq!(Message::parse(&[0x08]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x08, 0x80]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x09, 1, 2, 3]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x0d, 1, 2, 3]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x0a, 0x05, 1]), Err(Error::Truncated));
        let huge_len = [0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(Message::parse(&huge_len), Err(Error::Truncated));
        // Varints past 64 bits.
        assert_eq!(decode_varint(&[0xff; 11]), Err(Error::VarintOverflow));
        assert_eq!(
            decode_varint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]),
            Err(Error::VarintOverflow)
        );
        assert_eq!(
            Message::parse(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            Err(Error::VarintOverflow)
        );
        // Field numbers.
        assert_eq!(Message::parse(&[0x00, 0x01]), Err(Error::FieldNumber(0)));
        assert_eq!(Message::parse(&[0x80, 0x80, 0x80, 0x80, 0x10, 0]), Err(Error::FieldNumber(1 << 29)));
        assert!(Message::parse(&[0xf8, 0xff, 0xff, 0xff, 0x0f, 0]).is_ok());
        let mut w = Message::new();
        w.push_uint64(0, 1);
        assert_eq!(w.to_bytes(), Err(Error::FieldNumber(0)));
        let mut w = Message::new();
        w.push_uint64(MAX_FIELD_NUMBER + 1, 1);
        assert_eq!(w.to_bytes(), Err(Error::FieldNumber(1 << 29)));
        // Wire types.
        assert_eq!(Message::parse(&[0x0e]), Err(Error::WireType(6)));
        assert_eq!(Message::parse(&[0x0f]), Err(Error::WireType(7)));
        // Groups that do not match.
        assert_eq!(Message::parse(&[0x0c]), Err(Error::EndGroup(1)));
        assert_eq!(Message::parse(&[0x0b, 0x14]), Err(Error::EndGroup(2)));
        assert_eq!(Message::parse(&[0x0b, 0x08, 0x01]), Err(Error::UnclosedGroup(1)));
        // Too long.
        assert_eq!(Message::parse(&vec![0; MAX_MESSAGE + 1]), Err(Error::TooLong));
        let mut w = Message::new();
        w.push_bytes(1, &vec![0; MAX_MESSAGE]);
        assert_eq!(w.to_bytes(), Err(Error::TooLong));
        let mut w = Message::new();
        w.push_bytes(1, &vec![0; MAX_MESSAGE - 5]);
        let b = w.to_bytes().unwrap();
        assert_eq!(b.len(), MAX_MESSAGE);
        assert!(Message::parse(&b).is_ok());
        w.push_bool(2, true);
        assert_eq!(w.to_bytes(), Err(Error::TooLong));
        let mut a = Message::new();
        a.push_bytes(1, &vec![0; MAX_MESSAGE / 2 + 1]);
        a.push_bytes(1, &vec![0; MAX_MESSAGE / 2 + 1]);
        assert_eq!(a.message(1), Err(Error::TooLong));
        // Too many fields, both ways.
        let many: Vec<u8> = [0x08, 0x00].repeat(MAX_FIELDS + 1);
        assert_eq!(Message::parse(&many), Err(Error::TooManyFields));
        assert_eq!(Message::parse(&many[..2 * MAX_FIELDS]).unwrap().fields.len(), MAX_FIELDS);
        let mut w = Message { fields: vec![Field { number: 1, value: Value::Varint(0) }; MAX_FIELDS] };
        assert!(w.to_bytes().is_ok());
        w.push_bool(1, false);
        assert_eq!(w.to_bytes(), Err(Error::TooManyFields));
        // Groups nested too deep, both ways.
        let deep = |n: usize| [vec![0x0b; n], vec![0x0c; n]].concat();
        assert!(Message::parse(&deep(MAX_DEPTH)).is_ok());
        assert_eq!(Message::parse(&deep(MAX_DEPTH + 1)), Err(Error::TooDeep));
        assert_eq!(Message::parse_at(&deep(1), MAX_DEPTH), Err(Error::TooDeep));
        assert_eq!(Message::parse_at(&[], MAX_DEPTH + 1), Err(Error::TooDeep));
        let mut m = Message::new();
        for _ in 0..MAX_DEPTH {
            let mut outer = Message::new();
            outer.push_group(1, m);
            m = outer;
        }
        assert_eq!(m.to_bytes().unwrap(), deep(MAX_DEPTH));
        let mut outer = Message::new();
        outer.push_group(1, m);
        assert_eq!(outer.to_bytes(), Err(Error::TooDeep));
        assert_eq!(outer.clone().push_message(2, &outer), Err(Error::TooDeep));
        // Every error prints.
        for e in [Error::Truncated, Error::Flag(2), Error::Compressed, Error::TooDeep] {
            assert!(!e.to_string().is_empty());
        }
    }

    fn sample() -> Message {
        let mut inner = Message::new();
        inner.push_string(1, "a");
        inner.push_sint64(2, -300);
        let mut m = Message::new();
        m.push_uint64(1, 300);
        m.push_fixed64(2, 7);
        m.push_message(3, &inner).unwrap();
        m.push_group(4, inner);
        m.push_float(5, 0.5);
        m.push_packed_varints(6, &[1, 1 << 40]);
        m
    }

    #[test]
    fn every_truncated_prefix() {
        let m = sample();
        let b = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&b), Ok(m.clone()));
        for n in 0..b.len() {
            match Message::parse(&b[..n]) {
                // A prefix that ends between fields holds the first fields.
                Ok(p) => assert_eq!(p.fields[..], m.fields[..p.fields.len()], "{n} bytes"),
                Err(e) => assert!(matches!(e, Error::Truncated | Error::UnclosedGroup(4)), "{n} bytes: {e:?}"),
            }
        }
        for framing in [Framing::Grpc, Framing::Delimited] {
            let f = Frame { compressed: false, data: b.clone() }.to_bytes(framing).unwrap();
            for n in 0..f.len() {
                assert_eq!(Frame::parse(framing, &f[..n]), Ok(None), "{framing:?} {n} bytes");
            }
            assert_eq!(Frame::parse(framing, &f), Ok(Some((Frame { compressed: false, data: b.clone() }, f.len()))));
        }
    }

    #[test]
    fn frames() {
        let f = Frame { compressed: true, data: vec![0x08, 0x01] };
        let b = f.to_bytes(Framing::Grpc).unwrap();
        assert_eq!(b, [1, 0, 0, 0, 2, 0x08, 0x01]);
        assert_eq!(Frame::parse(Framing::Grpc, &b), Ok(Some((f.clone(), 7))));
        assert_eq!(f.to_bytes(Framing::Delimited), Err(Error::Compressed));
        let plain = Frame { compressed: false, data: vec![0x08, 0x01] };
        assert_eq!(plain.to_bytes(Framing::Delimited).unwrap(), [2, 0x08, 0x01]);
        // Errors.
        assert_eq!(Frame::parse(Framing::Grpc, &[2]), Err(Error::Flag(2)));
        assert_eq!(Frame::parse(Framing::Grpc, &[0, 0x00, 0x40, 0x00, 0x01]), Err(Error::TooLong));
        assert_eq!(Frame::parse(Framing::Grpc, &[0, 0x00, 0x40, 0x00, 0x00]), Ok(None));
        assert_eq!(Frame::parse(Framing::Delimited, &[0x81, 0x80, 0x80, 0x02]), Err(Error::TooLong));
        assert_eq!(Frame::parse(Framing::Delimited, &[0xff; 10]), Err(Error::VarintOverflow));
        let big = Frame { compressed: false, data: vec![0; MAX_MESSAGE + 1] };
        assert_eq!(big.to_bytes(Framing::Grpc), Err(Error::TooLong));
        let max = Frame { compressed: false, data: vec![0; MAX_MESSAGE] };
        for framing in [Framing::Grpc, Framing::Delimited] {
            let b = max.to_bytes(framing).unwrap();
            assert!(Frame::parse(framing, &b).unwrap().is_some());
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        for framing in [Framing::Grpc, Framing::Delimited] {
            let a = Frame { compressed: false, data: sample().to_bytes().unwrap() }.to_bytes(framing).unwrap();
            let b = Frame { compressed: false, data: vec![] }.to_bytes(framing).unwrap();
            let stream: Vec<u8> = a.iter().chain(&b).chain(&a).copied().collect();
            let mut d = Decoder::new(framing);
            let mut got = Vec::new();
            for byte in &stream {
                d.feed(std::slice::from_ref(byte));
                while let Some(f) = d.next_frame() {
                    got.push(f.unwrap().data.len());
                }
            }
            let n = sample().to_bytes().unwrap().len();
            assert_eq!(got, [n, 0, n]);
            assert_eq!(d.buffered(), 0);
            // A broken stream stays broken.
            d.feed(&[0xff; 12]);
            let e = d.next_frame().unwrap().unwrap_err();
            d.feed(&a);
            assert_eq!(d.next_frame(), Some(Err(e)));
            assert_eq!(d.buffered(), 0);
        }
    }

    #[test]
    fn decoder_buffer_is_bounded() {
        // Feeding without taking frames out stops at MAX_BUFFERED.
        let mut d = Decoder::new(Framing::Delimited);
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..MAX_BUFFERED / chunk.len() {
            d.feed(&chunk);
        }
        assert_eq!(d.buffered(), MAX_BUFFERED / chunk.len() * chunk.len());
        d.feed(&chunk);
        assert!(d.buffered() <= MAX_BUFFERED);
        assert_eq!(d.next_frame(), Some(Err(Error::TooLong)));
    }

    #[test]
    fn decoder_takes_many_small_frames_in_linear_time() {
        // Each zero byte is an empty delimited frame. Taking them out one
        // by one must not move the rest of the buffer each time.
        let mut d = Decoder::new(Framing::Delimited);
        d.feed(&vec![0u8; MAX_MESSAGE]);
        let mut n = 0;
        while let Some(f) = d.next_frame() {
            assert!(f.unwrap().data.is_empty());
            n += 1;
        }
        assert_eq!(n, MAX_MESSAGE);
        assert_eq!(d.buffered(), 0);
    }

    // Counts fields as MAX_FIELDS does: group members included.
    fn total_fields(m: &Message) -> usize {
        m.fields.iter().map(|f| 1 + if let Value::Group(g) = &f.value { total_fields(g) } else { 0 }).sum()
    }

    #[test]
    fn repeated_messages_count_group_members() {
        // Two entries, each one group of 32,768 varints: 65,538 fields.
        let mut entry = vec![0x0b];
        entry.extend([0x10, 0x00].repeat(32_768));
        entry.push(0x0c);
        let mut b = Vec::new();
        for _ in 0..2 {
            b.push(0x1a);
            encode_varint(entry.len() as u64, &mut b);
            b.extend_from_slice(&entry);
        }
        let m = Message::parse(&b).unwrap();
        assert_eq!(m.repeated_messages(3), Err(Error::TooManyFields));
        assert_eq!(m.message(3), Err(Error::TooManyFields));
        // One such entry is within the limit.
        let one = Message::parse(&b[..b.len() / 2]).unwrap();
        assert_eq!(total_fields(&one.repeated_messages(3).unwrap()[0]), 32_769);
    }

    #[test]
    fn merged_messages_keep_their_boundaries() {
        // [08] lacks its value and [01] has field number 0; joined they
        // would read as { 1: 1 }.
        let m = Message::parse(&[0x0a, 0x01, 0x08, 0x0a, 0x01, 0x01]).unwrap();
        assert_eq!(m.message(1), Err(Error::Truncated));
        // A group may not open in one copy and close in the next.
        let m = Message::parse(&[0x0a, 0x01, 0x0b, 0x0a, 0x01, 0x0c]).unwrap();
        assert_eq!(m.message(1), Err(Error::UnclosedGroup(1)));
    }

    #[test]
    fn every_string_occurrence_is_utf8() {
        let m = Message::parse(&[0x12, 0x01, 0xff, 0x12, 0x01, b'a']).unwrap();
        assert_eq!(m.string(2), Err(Error::Utf8));
        let m = Message::parse(&[0x12, 0x01, b'b', 0x10, 0x01, 0x12, 0x01, b'a']).unwrap();
        assert_eq!(m.string(2), Ok(Some("a")));
    }

    #[test]
    fn singular_groups_merge() {
        // Group 1 twice: { 2: 1 }, then { 3: 2, 2: 5 }.
        let m = Message::parse(&[0x0b, 0x10, 0x01, 0x0c, 0x0b, 0x18, 0x02, 0x10, 0x05, 0x0c]).unwrap();
        let g = m.group(1).unwrap();
        assert_eq!(g.uint64(3), Some(2));
        assert_eq!(g.uint64(2), Some(5));
        assert_eq!(g.all(2).count(), 2);
        assert_eq!(m.all(1).count(), 2);
    }

    #[test]
    fn embedded_message_walks_stop_at_max_depth() {
        // message Node { Node child = 1; }, nested MAX_DEPTH + 1 deep.
        let mut b = Vec::new();
        for _ in 0..=MAX_DEPTH {
            let mut outer = vec![0x0a];
            encode_varint(b.len() as u64, &mut outer);
            outer.extend_from_slice(&b);
            b = outer;
        }
        let mut m = Message::parse(&b).unwrap();
        let mut depth = 0;
        loop {
            match m.message_at(1, depth) {
                Ok(Some(child)) => {
                    m = child;
                    depth += 1;
                }
                Ok(None) => panic!("the chain ended at {depth}"),
                Err(e) => {
                    assert_eq!(e, Error::TooDeep);
                    break;
                }
            }
        }
        assert_eq!(depth, MAX_DEPTH);
        assert_eq!(m.repeated_messages_at(1, MAX_DEPTH), Err(Error::TooDeep));
        assert_eq!(m.message_at(2, MAX_DEPTH), Ok(None));
        assert_eq!(m.message_at(1, usize::MAX), Err(Error::TooDeep));
        // Groups inside an embedded message count from its depth.
        let groups = |n: usize| [vec![0x0b; n], vec![0x0c; n]].concat();
        let mut w = Message::new();
        w.push_bytes(1, &groups(MAX_DEPTH - 1));
        assert!(w.message(1).is_ok());
        let mut w = Message::new();
        w.push_bytes(1, &groups(MAX_DEPTH));
        assert_eq!(w.message(1), Err(Error::TooDeep));
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn bytes(&mut self, max: usize) -> Vec<u8> {
            (0..self.below(max + 1)).map(|_| self.next() as u8).collect()
        }
        fn wide(&mut self) -> u64 {
            let v = (self.next() << 31) ^ self.next();
            v >> self.below(64)
        }
    }

    fn random(r: &mut Lcg, depth: usize) -> Message {
        let mut m = Message::new();
        for _ in 0..r.below(6) {
            let number = [1, 2, 15, 16, 2047, 2048, MAX_FIELD_NUMBER][r.below(7)];
            let value = match r.below(if depth >= 3 { 4 } else { 5 }) {
                0 => Value::Varint(r.wide()),
                1 => Value::Fixed64(r.wide()),
                2 => Value::Bytes(r.bytes(10)),
                3 => Value::Fixed32(r.next() as u32),
                _ => Value::Group(random(r, depth + 1)),
            };
            m.push(number, value);
        }
        m
    }

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg(11);
        for _ in 0..3000 {
            // Built messages round trip.
            let m = random(&mut r, 0);
            let b = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&b).as_ref(), Ok(&m));
            // Damaged copies never panic, and what parses writes and
            // reads back the same.
            let mut bad = b.clone();
            for _ in 0..r.below(3) + 1 {
                if !bad.is_empty() {
                    let i = r.below(bad.len());
                    bad[i] = r.next() as u8;
                }
            }
            let junk = r.bytes(24);
            for input in [&bad[..], &junk[..], &b[..b.len() / 2]] {
                if let Ok(p) = Message::parse(input) {
                    let again = p.to_bytes().unwrap();
                    assert_eq!(Message::parse(&again).as_ref(), Ok(&p));
                    for f in &p.fields {
                        let _ = p.string(f.number);
                        let _ = p.message(f.number);
                        let _ = p.repeated_varints(f.number);
                        let _ = p.repeated_fixed32(f.number);
                        let _ = p.repeated_fixed64(f.number);
                        let _ = p.repeated_strings(f.number);
                        if let Ok(rs) = p.repeated_messages(f.number) {
                            assert!(rs.iter().map(total_fields).sum::<usize>() <= MAX_FIELDS);
                        }
                    }
                }
                // Decoders, all at once and a byte at a time.
                for framing in [Framing::Grpc, Framing::Delimited] {
                    let mut whole = Decoder::new(framing);
                    whole.feed(input);
                    let mut frames = Vec::new();
                    while let Some(Ok(f)) = whole.next_frame() {
                        frames.push(f);
                    }
                    let mut bytewise = Decoder::new(framing);
                    let mut again = Vec::new();
                    for byte in input {
                        bytewise.feed(std::slice::from_ref(byte));
                        while let Some(Ok(f)) = bytewise.next_frame() {
                            again.push(f);
                        }
                    }
                    assert_eq!(frames, again);
                    // And in chunks of random sizes, several frames at once.
                    let mut chunked = Decoder::new(framing);
                    let mut third = Vec::new();
                    let mut rest = input;
                    while !rest.is_empty() {
                        let (head, tail) = rest.split_at(r.below(rest.len()) + 1);
                        chunked.feed(head);
                        rest = tail;
                        while let Some(Ok(f)) = chunked.next_frame() {
                            third.push(f);
                        }
                    }
                    assert_eq!(frames, third);
                    for f in &frames {
                        let bytes = f.to_bytes(framing).unwrap();
                        assert_eq!(Frame::parse(framing, &bytes), Ok(Some((f.clone(), bytes.len()))));
                    }
                }
            }
        }
    }
}
