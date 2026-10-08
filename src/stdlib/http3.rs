//! HTTP/3 frames, streams and field sections, with no I/O.
//!
//! Callers supply ordered QUIC stream bytes. This module follows
//! [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114), uses the sibling
//! [`qpack`] implementation of RFC 9204, and reads priorities from RFC 9218.
//! Extended CONNECT follows RFC 9220 and RFC 8441. Priority dictionaries
//! use the RFC 8941 grammar, including values and parameters we ignore.
//!
//! [`Session`] routes ordered stream bytes under a shared input budget.
//! For a single stream, use [`Stream<codec::Frames<Frame>>`](fictionet::stdlib::codec::Stream),
//! [`ControlFrames`], or [`StreamHeaders`]. [`RequestStream`] validates decoded
//! request and push frames. QPACK tables and blocked sections belong to the
//! caller, who applies instructions and sends acknowledgment values between
//! items. Unknown frames are returned for inspection.
//!
//! Buffers and field lists have the public limits below. DATA is returned
//! one frame at a time; message bodies are never collected. These are local
//! resource limits, not wire limits. Connection management remains with the
//! caller: enforce unique critical streams, push permissions and promised
//! IDs across streams, QUIC stream limits, settings negotiation and 0-RTT.
//! URI scheme policy beyond HTTP(S), routing, scheduling, authentication,
//! TLS and QUIC transport are outside this module.
//!
//! ```
//! use fictionet::stdlib::{codec::Wire, http3::{HeaderKind, HeaderList, Frame,
//!     RequestStream, RequestResult, MessageSide, Event, MAX_FIELD_SECTION_SIZE}, qpack};
//! let headers = HeaderList { fields: vec![
//!     qpack::Field::new(":method", "GET"),
//!     qpack::Field::new(":scheme", "https"),
//!     qpack::Field::new(":authority", "example.net"),
//!     qpack::Field::new(":path", "/"),
//! ] };
//! let mut encoder = qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE);
//! let section = headers.section(&mut encoder, 0, HeaderKind::Request { extended_connect: false })?;
//! let frame = Frame::headers(&section)?;
//! let mut state = RequestStream::new(0, MessageSide::Request, false)?;
//! let table = qpack::Table::new(0);
//! assert_eq!(state.step(&frame, &table)?, RequestResult::Event { event: Ok(Event::Headers(headers)), ack: None });
//! state.finish()?;
//! # Ok::<(), fictionet::stdlib::http3::Error>(())
//! ```

use fictionet::stdlib::codec::{Prefixed, Frames};
use fictionet::stdlib::codec::ascii::{self, trim_ows, is_tchar as token};
use fictionet::stdlib::{
    codec::{self, Decode, Step, Wire},
    qpack, quic,
};

/// The greatest QUIC variable-length integer, including a stream or push ID.
pub const MAX_VARINT: u64 = quic::MAX_VARINT;
/// The most payload bytes in a frame accepted or written here.
pub const MAX_FRAME_PAYLOAD: usize = 1 << 20;
/// The most bytes in a frame's type and length integers.
pub const MAX_FRAME_HEADER: usize = 16;
/// The most bytes in an encoded frame.
pub const MAX_FRAME: usize = MAX_FRAME_HEADER + MAX_FRAME_PAYLOAD;
/// The most entries in a SETTINGS frame.
pub const MAX_SETTINGS: usize = 128;
/// The most bytes in a SETTINGS payload, with two eight-byte integers per entry.
pub const MAX_SETTINGS_BYTES: usize = MAX_SETTINGS * 16;
/// The most bytes in a unidirectional stream header, including a push ID.
pub const MAX_STREAM_HEADER: usize = 16;
/// The most encoded bytes in a QPACK field section.
pub const MAX_SECTION_BYTES: usize = qpack::MAX_SECTION_BYTES;
/// The most decoded bytes in a field section, including 32 bytes per field.
pub const MAX_FIELD_SECTION_SIZE: u64 = qpack::MAX_FIELD_SECTION_SIZE;
/// The most fields in a header or trailer section.
pub const MAX_FIELDS: usize = qpack::MAX_FIELDS;
/// The most bytes in a field name or field value.
pub const MAX_FIELD_BYTES: usize = qpack::MAX_STRING;
/// The most bytes in a Priority field value.
pub const MAX_PRIORITY_BYTES: usize = 4096;
/// The most dictionary members or parameters in a Priority field value.
pub const MAX_PRIORITY_MEMBERS: usize = 128;
/// The most inner-list items in a Priority field value.
pub const MAX_PRIORITY_ITEMS: usize = 128;
/// HTTP/3 frame type identifiers.
pub mod frame_type {
    /// Message content.
    pub const DATA: u64 = 0;
    /// A compressed header or trailer section.
    pub const HEADERS: u64 = 1;
    /// Cancellation of a server push.
    pub const CANCEL_PUSH: u64 = 3;
    /// Connection settings.
    pub const SETTINGS: u64 = 4;
    /// A promised request.
    pub const PUSH_PROMISE: u64 = 5;
    /// Graceful connection shutdown.
    pub const GOAWAY: u64 = 7;
    /// The greatest permitted push ID.
    pub const MAX_PUSH_ID: u64 = 0x0d;
    /// A request stream's updated priority.
    pub const PRIORITY_UPDATE_REQUEST: u64 = 0x0f0700;
    /// A push's updated priority.
    pub const PRIORITY_UPDATE_PUSH: u64 = 0x0f0701;
}

/// SETTINGS identifiers understood here. Other identifiers are preserved.
/// RFC 9218's SETTINGS_NO_RFC7540_PRIORITIES is an HTTP/2 setting only.
pub mod setting {
    /// The maximum QPACK dynamic table capacity; default zero.
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 1;
    /// The maximum uncompressed field section size; default unlimited.
    pub const MAX_FIELD_SECTION_SIZE: u64 = 6;
    /// The number of QPACK streams allowed to block; default zero.
    pub const QPACK_BLOCKED_STREAMS: u64 = 7;
    /// Whether extended CONNECT is enabled; zero or one, default zero.
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 8;
}

/// HTTP/3 and QPACK application error codes. Unknown wire codes are retained
/// by callers and treated like NO_ERROR in contexts where they are unknown.
pub mod error_code {
    /// Normal closure.
    pub const NO_ERROR: u64 = 0x100;
    /// A general protocol violation.
    pub const GENERAL_PROTOCOL_ERROR: u64 = 0x101;
    /// An implementation failure.
    pub const INTERNAL_ERROR: u64 = 0x102;
    /// An illegal or duplicate critical stream.
    pub const STREAM_CREATION_ERROR: u64 = 0x103;
    /// A critical stream closed.
    pub const CLOSED_CRITICAL_STREAM: u64 = 0x104;
    /// A frame is not permitted here.
    pub const FRAME_UNEXPECTED: u64 = 0x105;
    /// A frame has an invalid layout.
    pub const FRAME_ERROR: u64 = 0x106;
    /// A local resource limit was exceeded.
    pub const EXCESSIVE_LOAD: u64 = 0x107;
    /// A stream or push identifier is invalid.
    pub const ID_ERROR: u64 = 0x108;
    /// A SETTINGS entry is invalid.
    pub const SETTINGS_ERROR: u64 = 0x109;
    /// The control stream did not start with SETTINGS.
    pub const MISSING_SETTINGS: u64 = 0x10a;
    /// A request was rejected before processing.
    pub const REQUEST_REJECTED: u64 = 0x10b;
    /// A request was cancelled.
    pub const REQUEST_CANCELLED: u64 = 0x10c;
    /// A request ended before it was complete.
    pub const REQUEST_INCOMPLETE: u64 = 0x10d;
    /// Invalid HTTP fields or message semantics.
    pub const MESSAGE_ERROR: u64 = 0x10e;
    /// A CONNECT tunnel failed.
    pub const CONNECT_ERROR: u64 = 0x10f;
    /// Retry using an older HTTP version.
    pub const VERSION_FALLBACK: u64 = 0x110;
    /// A QPACK field section could not be decoded.
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
    /// Invalid instructions on the QPACK encoder stream.
    pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x201;
    /// Invalid instructions on the QPACK decoder stream.
    pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x202;
}

/// Why a reader or writer refused bytes or values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// A public resource limit was exceeded.
    Limit,
    /// A frame's payload has an invalid size or layout, or ended early.
    Frame,
    /// This frame type is forbidden or out of order.
    UnexpectedFrame(u64),
    /// A SETTINGS identifier occurred more than once.
    DuplicateSetting(u64),
    /// An HTTP/2-only SETTINGS identifier was used.
    Http2Setting(u64),
    /// A known setting has an invalid value.
    SettingValue(u64),
    /// A control stream's first frame was not SETTINGS.
    MissingSettings,
    /// A stream or push ID violates its rules.
    Id,
    /// A critical control stream was closed.
    ClosedCriticalStream,
    /// An HTTP field section or message is malformed.
    Message(&'static str),
    /// The stream ended without a complete final message.
    Incomplete,
    /// A QPACK operation failed.
    Qpack(qpack::Error),
    /// Invalid QPACK encoder-stream framing or instruction contents.
    QpackEncoderStream(qpack::Error),
    /// Invalid QPACK decoder-stream framing or instruction contents.
    QpackDecoderStream(qpack::Error),
    /// Invalid RFC 8941 Priority dictionary syntax.
    Priority,
    /// The caller must resume a blocked section or use the appropriate state. This is not a peer protocol error.
    State,
    /// An exact parse ran out of input before a complete frame or stream
    /// header, including empty input.
    Truncated,
    /// Bytes follow the first complete value of an exact parse.
    Trailing,
}

impl Error {
    /// The suggested application error code, or None for a local API condition,
    /// an exact parse that did not read one whole value, or an invalid Priority
    /// dictionary that the application can ignore.
    /// MESSAGE_ERROR applies to the stream; framing errors affect the connection.
    pub fn application_code(self) -> Option<u64> {
        use error_code as c;
        Some(match self {
            Self::Limit => c::EXCESSIVE_LOAD,
            Self::Frame => c::FRAME_ERROR,
            Self::UnexpectedFrame(_) => c::FRAME_UNEXPECTED,
            Self::DuplicateSetting(_) | Self::Http2Setting(_) | Self::SettingValue(_) => c::SETTINGS_ERROR,
            Self::MissingSettings => c::MISSING_SETTINGS,
            Self::Id => c::ID_ERROR,
            Self::ClosedCriticalStream => c::CLOSED_CRITICAL_STREAM,
            Self::Message(_) => c::MESSAGE_ERROR,
            Self::Incomplete => c::REQUEST_INCOMPLETE,
            Self::Unwritable | Self::State | Self::Priority | Self::Truncated | Self::Trailing => return None,
            Self::Qpack(_) => c::QPACK_DECOMPRESSION_FAILED,
            Self::QpackEncoderStream(_) => c::QPACK_ENCODER_STREAM_ERROR,
            Self::QpackDecoderStream(_) => c::QPACK_DECODER_STREAM_ERROR,
        })
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unwritable => f.write_str("value cannot be written without changing it"),
            Self::Message(s) => f.write_str(s),
            Self::Qpack(_) => f.write_str("malformed QPACK field section"),
            Self::QpackEncoderStream(_) => f.write_str("malformed QPACK encoder stream"),
            Self::QpackDecoderStream(_) => f.write_str("malformed QPACK decoder stream"),
            Self::Truncated => f.write_str("input ended before a complete HTTP/3 value"),
            Self::Trailing => f.write_str("bytes follow the HTTP/3 value"),
            _ => write!(f, "HTTP/3: {self:?}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Qpack(e) | Self::QpackEncoderStream(e) | Self::QpackDecoderStream(e) => Some(e),
            _ => None,
        }
    }
}

/// Whether a frame type, setting, stream type or error code is in the
/// reserved grease sequence 0x1f * N + 0x21.
pub fn is_reserved(value: u64) -> bool {
    (0x21..=MAX_VARINT).contains(&value) && (value - 0x21).is_multiple_of(0x1f)
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    quic::read_varint(bytes).ok()
}
fn put_varint(value: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    quic::VarInt(value).write(out).map_err(|_| Error::Unwritable)
}
fn integer_at(bytes: &[u8], offset: &mut usize) -> Result<u64, Error> {
    let (v, n) = varint(bytes.get(*offset..).ok_or(Error::Frame)?).ok_or(Error::Frame)?;
    *offset = offset.checked_add(n).ok_or(Error::Limit)?;
    Ok(v)
}
fn check_setting(id: u64, value: u64) -> Result<(), Error> {
    if id > MAX_VARINT || value > MAX_VARINT {
        return Err(Error::Unwritable);
    }
    if matches!(id, 2..=5) {
        return Err(Error::Http2Setting(id));
    }
    if id == setting::ENABLE_CONNECT_PROTOCOL && value > 1 {
        return Err(Error::SettingValue(id));
    }
    Ok(())
}

/// A SETTINGS entry. Unknown entries are preserved and otherwise ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    /// The parameter identifier.
    pub id: u64,
    /// Its value.
    pub value: u64,
}

/// A bounded, ordered SETTINGS payload, including unknown parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Entries in wire order. Writers check count, duplicates and values.
    pub entries: Vec<Setting>,
}
impl Settings {
    /// The explicitly supplied value, or None if the identifier was absent.
    pub fn get(&self, id: u64) -> Option<u64> {
        self.entries.iter().take(MAX_SETTINGS).find(|s| s.id == id).map(|s| s.value)
    }
}

/// The element whose priority a client updates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriorityElement {
    /// A client-initiated bidirectional stream ID, including zero.
    Request(u64),
    /// A push ID. The caller checks that it has been promised and permitted.
    Push(u64),
}

/// One HTTP/3 frame. HEADERS and PUSH_PROMISE retain their encoded QPACK
/// sections; use HeaderList or RequestStream to validate their HTTP fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A chunk of message content or tunnel data.
    Data(Vec<u8>),
    /// A QPACK field section.
    Headers(Vec<u8>),
    /// Cancel this push ID.
    CancelPush(u64),
    /// Connection settings.
    Settings(Settings),
    /// The request for a promised response.
    PushPromise {
        /// The push ID, checked against connection permissions by the caller.
        push_id: u64,
        /// A QPACK request field section.
        field_section: Vec<u8>,
    },
    /// The first request or push ID the sender will not accept.
    Goaway(u64),
    /// The largest push ID the client permits.
    MaxPushId(u64),
    /// A client's priority update. Malformed dictionaries can be ignored by
    /// the application; ASCII syntax is checked separately by Priority::parse.
    PriorityUpdate {
        /// The request stream or promised push being updated.
        element: PriorityElement,
        /// The original ASCII Priority field value, at most MAX_PRIORITY_BYTES.
        value: Vec<u8>,
    },
    /// An extension or reserved frame. Known and HTTP/2-only types are refused
    /// by the writer, so writing and parsing preserves this variant.
    Unknown {
        /// The unrecognized frame type.
        frame_type: u64,
        /// Opaque payload bytes.
        payload: Vec<u8>,
    },
}
fn known_frame(t: u64) -> bool {
    matches!(t, 0..=9 | 0x0d | 0x0f0700 | 0x0f0701)
}
fn forbidden_frame(t: u64) -> bool {
    matches!(t, 2 | 6 | 8 | 9)
}
fn frame_payload_limit(kind: u64) -> usize {
    match kind {
        frame_type::HEADERS => MAX_SECTION_BYTES,
        frame_type::SETTINGS => MAX_SETTINGS_BYTES,
        frame_type::PUSH_PROMISE => MAX_SECTION_BYTES + 8,
        frame_type::PRIORITY_UPDATE_REQUEST | frame_type::PRIORITY_UPDATE_PUSH => MAX_PRIORITY_BYTES + 8,
        _ => MAX_FRAME_PAYLOAD,
    }
}
fn field_bytes(b: &[u8]) -> Result<(), Error> {
    if b.len() > MAX_SECTION_BYTES { Err(Error::Limit) } else { Ok(()) }
}
fn priority_bytes(b: &[u8]) -> Result<(), Error> {
    if b.len() > MAX_PRIORITY_BYTES {
        return Err(Error::Limit);
    }
    if b.iter().any(|b| !matches!(b, b'\t' | 0x20..=0x7e)) {
        return Err(Error::Frame);
    }
    Ok(())
}
// Header failures are terminal; payload failures retain the next frame boundary.
fn frame_header(bytes: &[u8]) -> Result<Option<(u64, usize, usize)>, Error> {
    let Some((t, a)) = varint(bytes) else { return Ok(None) };
    if forbidden_frame(t) {
        return Err(Error::UnexpectedFrame(t));
    }
    let Some((len, b)) = varint(bytes.get(a..).ok_or(Error::Frame)?) else { return Ok(None) };
    let len = usize::try_from(len).map_err(|_| Error::Limit)?;
    let limit = frame_payload_limit(t);
    if len > limit {
        return Err(Error::Limit);
    }
    if matches!(t, 3 | 7 | 0x0d) && !(1..=8).contains(&len) {
        return Err(Error::Frame);
    }
    let start = a.checked_add(b).ok_or(Error::Limit)?;
    let end = start.checked_add(len).ok_or(Error::Limit)?;
    Ok(Some((t, start, end)))
}

impl Frame {
    /// Builds a HEADERS frame around an encoded field section.
    /// Refuses sections that cannot be written within the QPACK limits.
    pub fn headers(section: &qpack::FieldSection) -> Result<Self, Error> {
        section.to_bytes().map(Self::Headers).map_err(|_| Error::Unwritable)
    }

    /// The wire type of this frame.
    pub fn frame_type(&self) -> u64 {
        match self {
            Self::Data(_) => 0,
            Self::Headers(_) => 1,
            Self::CancelPush(_) => 3,
            Self::Settings(_) => 4,
            Self::PushPromise { .. } => 5,
            Self::Goaway(_) => 7,
            Self::MaxPushId(_) => 0x0d,
            Self::PriorityUpdate { element: PriorityElement::Request(_), .. } => 0x0f0700,
            Self::PriorityUpdate { .. } => 0x0f0701,
            Self::Unknown { frame_type, .. } => *frame_type,
        }
    }
    /// Reads one frame and its consumed length. None means more bytes are
    /// needed. Oversized lengths and forbidden types fail before allocation.
    /// Nonminimal QUIC integers are accepted; writers use the shortest form.
    fn parse_prefix(bytes: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let Some((t, start, end)) = frame_header(bytes)? else { return Ok(None) };
        let Some(payload) = bytes.get(start..end) else { return Ok(None) };
        Ok(Some((Self::parse_payload(t, payload)?, end)))
    }

    fn parse_payload(t: u64, payload: &[u8]) -> Result<Self, Error> {
        let frame = match t {
            0 => Self::Data(payload.to_vec()),
            1 => Self::Headers(payload.to_vec()),
            4 => Self::Settings(Settings::parse(payload)?),
            3 | 7 | 0x0d => {
                let (id, used) = varint(payload).ok_or(Error::Frame)?;
                if used != payload.len() {
                    return Err(Error::Frame);
                }
                match t {
                    3 => Self::CancelPush(id),
                    7 => Self::Goaway(id),
                    _ => Self::MaxPushId(id),
                }
            }
            5 => {
                let (push_id, used) = varint(payload).ok_or(Error::Frame)?;
                let section = payload.get(used..).ok_or(Error::Frame)?;
                field_bytes(section)?;
                Self::PushPromise { push_id, field_section: section.to_vec() }
            }
            0x0f0700 | 0x0f0701 => {
                let (id, used) = varint(payload).ok_or(Error::Frame)?;
                if t == 0x0f0700 && id % 4 != 0 {
                    return Err(Error::Id);
                }
                let value = payload.get(used..).ok_or(Error::Frame)?;
                priority_bytes(value)?;
                let element = if t == 0x0f0700 { PriorityElement::Request(id) } else { PriorityElement::Push(id) };
                Self::PriorityUpdate { element, value: value.to_vec() }
            }
            _ => Self::Unknown { frame_type: t, payload: payload.to_vec() },
        };
        Ok(frame)
    }
}

/// The prefix of a unidirectional stream. Unknown and reserved types must be
/// discarded by the caller, not interpreted as HTTP/3 frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamHeader {
    /// Type 0: one control stream per endpoint.
    Control,
    /// Type 1: a server push stream, followed by this push ID.
    Push(u64),
    /// Type 2: QPACK encoder instructions.
    QpackEncoder,
    /// Type 3: QPACK decoder instructions.
    QpackDecoder,
    /// Another type, including reserved types.
    Unknown(u64),
}
impl StreamHeader {
    /// Reads just the stream prefix and returns its consumed length.
    fn parse_prefix(bytes: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let Some((t, used)) = varint(bytes) else { return Ok(None) };
        let header = match t {
            0 => Self::Control,
            1 => {
                let Some((id, n)) = varint(bytes.get(used..).ok_or(Error::Frame)?) else { return Ok(None) };
                return Ok(Some((Self::Push(id), used + n)));
            }
            2 => Self::QpackEncoder,
            3 => Self::QpackDecoder,
            _ => Self::Unknown(t),
        };
        Ok(Some((header, used)))
    }
}

/// Recognized Priority dictionary members. Missing or ignored members stay
/// None, so a response can override only the parameters it actually supplies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Priority {
    /// Urgency from zero (highest) to seven (lowest).
    pub urgency: Option<u8>,
    /// Whether the response can be processed incrementally.
    pub incremental: Option<bool>,
}
impl Priority {
    /// The request urgency, using the default of three when absent.
    pub fn effective_urgency(self) -> u8 {
        self.urgency.filter(|u| *u <= 7).unwrap_or(3)
    }
    /// The request incremental flag, using false when absent.
    pub fn effective_incremental(self) -> bool {
        self.incremental.unwrap_or(false)
    }
}
impl Wire for Priority {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an RFC 8941 dictionary. Refuses invalid syntax and size or member limits.
    /// Unknown members and invalid member values are ignored. The last duplicate wins.
    /// Canonical writing keeps only `u` and `i`, dropping unknown members and parameters.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PRIORITY_BYTES {
            return Err(Error::Limit);
        }
        let mut p = Dictionary { bytes, pos: 0, members: 0, items: 0 };
        let mut result = Self::default();
        p.spaces();
        while p.peek().is_some() {
            p.member()?;
            let key = p.key()?;
            let value = if p.eat(b'=') { p.value()? } else { Scalar::Boolean(true) };
            p.parameters()?;
            match key {
                b"u" => {
                    result.urgency = match value {
                        Scalar::Integer(n) if (0..=7).contains(&n) => Some(n as u8),
                        _ => None,
                    }
                }
                b"i" => {
                    result.incremental = match value {
                        Scalar::Boolean(v) => Some(v),
                        _ => None,
                    }
                }
                _ => {}
            }
            p.ows();
            if p.peek().is_none() {
                break;
            }
            if !p.eat(b',') {
                return Err(Error::Priority);
            }
            p.ows();
            if p.peek().is_none() {
                return Err(Error::Priority);
            }
        }
        Ok(result)
    }

    /// Writes recognized members in canonical form. Refuses urgency above seven.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::with_capacity(MAX_PRIORITY_BYTES);
        if let Some(u) = self.urgency {
            if u > 7 {
                return Err(Error::Unwritable);
            }
            out.extend_from_slice(&[b'u', b'=', b'0' + u]);
        }
        if let Some(i) = self.incremental {
            if !out.is_empty() {
                out.extend_from_slice(b", ");
            }
            out.extend_from_slice(if i { b"i" } else { b"i=?0" });
        }
        destination.extend_from_slice(&out);
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Scalar {
    Integer(i64),
    Boolean(bool),
    Other,
}
struct Dictionary<'a> {
    bytes: &'a [u8],
    pos: usize,
    members: usize,
    items: usize,
}
impl<'a> Dictionary<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn spaces(&mut self) {
        while self.eat(b' ') {}
    }
    fn ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }
    fn member(&mut self) -> Result<(), Error> {
        if self.members >= MAX_PRIORITY_MEMBERS {
            return Err(Error::Limit);
        }
        self.members += 1;
        Ok(())
    }
    fn key(&mut self) -> Result<&'a [u8], Error> {
        let start = self.pos;
        if !matches!(self.peek(), Some(b'a'..=b'z' | b'*')) {
            return Err(Error::Priority);
        }
        self.pos += 1;
        while matches!(self.peek(), Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')) {
            self.pos += 1;
        }
        self.bytes.get(start..self.pos).ok_or(Error::Priority)
    }
    fn parameters(&mut self) -> Result<(), Error> {
        while self.eat(b';') {
            self.member()?;
            self.spaces();
            self.key()?;
            if self.eat(b'=') {
                self.bare()?;
            }
        }
        Ok(())
    }
    fn value(&mut self) -> Result<Scalar, Error> {
        if !self.eat(b'(') {
            return self.bare();
        }
        loop {
            self.spaces();
            if self.eat(b')') {
                return Ok(Scalar::Other);
            }
            if self.items >= MAX_PRIORITY_ITEMS {
                return Err(Error::Limit);
            }
            self.items += 1;
            self.bare()?;
            self.parameters()?;
            if !matches!(self.peek(), Some(b' ' | b')')) {
                return Err(Error::Priority);
            }
        }
    }
    fn bare(&mut self) -> Result<Scalar, Error> {
        match self.peek().ok_or(Error::Priority)? {
            b'?' => {
                self.pos += 1;
                let b = self.peek().ok_or(Error::Priority)?;
                if !matches!(b, b'0' | b'1') {
                    return Err(Error::Priority);
                }
                self.pos += 1;
                Ok(Scalar::Boolean(b == b'1'))
            }
            b'-' | b'0'..=b'9' => {
                let negative = self.eat(b'-');
                let mut digits = 0;
                let mut value = 0i64;
                while let Some(c @ b'0'..=b'9') = self.peek() {
                    if digits == 15 {
                        return Err(Error::Priority);
                    }
                    value = value
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(i64::from(c - b'0')))
                        .ok_or(Error::Priority)?;
                    digits += 1;
                    self.pos += 1;
                }
                if digits == 0 {
                    return Err(Error::Priority);
                }
                if self.eat(b'.') {
                    if digits > 12 {
                        return Err(Error::Priority);
                    }
                    let mut fraction = 0;
                    while matches!(self.peek(), Some(b'0'..=b'9')) {
                        fraction += 1;
                        self.pos += 1;
                        if fraction > 3 {
                            return Err(Error::Priority);
                        }
                    }
                    if fraction == 0 {
                        return Err(Error::Priority);
                    }
                    Ok(Scalar::Other)
                } else {
                    Ok(Scalar::Integer(if negative { -value } else { value }))
                }
            }
            b'"' => {
                self.pos += 1;
                loop {
                    let b = self.peek().ok_or(Error::Priority)?;
                    self.pos += 1;
                    match b {
                        b'"' => return Ok(Scalar::Other),
                        b'\\' => {
                            if !matches!(self.peek(), Some(b'"' | b'\\')) {
                                return Err(Error::Priority);
                            }
                            self.pos += 1;
                        }
                        0x20..=0x7e => {}
                        _ => return Err(Error::Priority),
                    }
                }
            }
            b':' => {
                self.pos += 1;
                let start = self.pos;
                while self.peek().is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/')) {
                    self.pos += 1;
                }
                let digits = self.pos - start;
                let mut padding = 0;
                while self.eat(b'=') {
                    padding += 1;
                    if padding > 2 {
                        return Err(Error::Priority);
                    }
                }
                // RFC 8941 synthesizes missing base64 padding. Pad bits do
                // not affect priority semantics, and need not be zero.
                let allowed_padding = match digits % 4 {
                    0 => 0,
                    2 => 2,
                    3 => 1,
                    _ => return Err(Error::Priority),
                };
                if padding > allowed_padding || !self.eat(b':') {
                    return Err(Error::Priority);
                }
                Ok(Scalar::Other)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'*' => {
                self.pos += 1;
                while self.peek().is_some_and(|b| token(b) || matches!(b, b':' | b'/')) {
                    self.pos += 1;
                }
                Ok(Scalar::Other)
            }
            _ => Err(Error::Priority),
        }
    }
}

/// The HTTP meaning of a field section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderKind {
    /// Request headers, including promised requests.
    Request {
        /// True only when extended CONNECT has been enabled by the server.
        extended_connect: bool,
    },
    /// A PUSH_PROMISE request: request rules without extended CONNECT, and
    /// :authority is required (RFC 9114 section 4.6); Host alone is not enough.
    /// Whether the method is safe and cacheable is left to the caller, which
    /// cancels unwanted pushes with CANCEL_PUSH.
    Promise,
    /// Initial or informational response headers.
    Response,
    /// Trailers, in which pseudo-headers and framing fields are forbidden.
    Trailers,
}

/// An HTTP field list in wire order. QPACK's never_index flag is preserved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderList {
    /// Fields to validate or encode, limited by MAX_FIELDS and
    /// MAX_FIELD_SECTION_SIZE. Public edits are checked again by the writer.
    pub fields: Vec<qpack::Field>,
}
#[derive(Default)]
struct HeaderInfo {
    status: Option<u16>,
    content_length: Option<u64>,
    connect: bool,
    trace: bool,
}
/// Receive-side tolerance that writers never get.
#[derive(Clone, Copy, Default)]
struct Receive {
    /// Accept a Content-Length repeated as a list of one value (RFC 9110
    /// section 8.6); the decoder then rewrites it as one field.
    length_list: bool,
    /// Accept Content-Length on any 2xx response to CONNECT, which the
    /// client ignores (RFC 9110 section 9.3.6).
    connect_response: bool,
}
/// Replaces repeated or list-form Content-Length fields with one field
/// holding the decimal value, at the place of the first.
fn normalize_length(fields: &mut Vec<qpack::Field>, length: Option<u64>) {
    let Some(n) = length else { return };
    let count = fields.iter().filter(|f| f.name == b"content-length").count();
    if count <= 1 && !fields.iter().any(|f| f.name == b"content-length" && f.value.contains(&b',')) {
        return;
    }
    let mut first = true;
    fields.retain_mut(|f| {
        if f.name != b"content-length" {
            return true;
        }
        if first {
            first = false;
            f.value = n.to_string().into_bytes();
            return true;
        }
        false
    });
}
fn nonempty_token(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|c| token(*c))
}
fn decimal(b: &[u8]) -> Option<u64> {
    ascii::decimal(b, usize::MAX, u64::MAX)
}
fn reg_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        )
}
fn authority(value: &[u8], port_required: bool) -> bool {
    if value.is_empty()
        || value.iter().any(|b| !matches!(b, 0x21..=0x7e) || matches!(b, b'@' | b'/' | b'?' | b'#' | b'\\'))
    {
        return false;
    }
    let rest = if value.first() == Some(&b'[') {
        let Some(end) = value.iter().position(|b| *b == b']') else { return false };
        if end <= 1 {
            return false;
        }
        let Ok(ip) = std::str::from_utf8(value.get(1..end).unwrap_or_default()) else { return false };
        let future = ip.strip_prefix('v').or_else(|| ip.strip_prefix('V')).is_some_and(|v| {
            v.split_once('.').is_some_and(|(version, address)| {
                !version.is_empty()
                    && version.bytes().all(|b| b.is_ascii_hexdigit())
                    && !address.is_empty()
                    && address.bytes().all(|b| reg_name_char(b) || b == b':')
            })
        });
        if ip.parse::<std::net::Ipv6Addr>().is_err() && !future {
            return false;
        }
        value.get(end + 1..).unwrap_or_default()
    } else {
        let end = value.iter().position(|b| *b == b':').unwrap_or(value.len());
        let host = value.get(..end).unwrap_or_default();
        if host.is_empty() || !host.iter().all(|b| reg_name_char(*b) || *b == b'%') || !uri_path(host) {
            return false;
        }
        value.get(end..).unwrap_or_default()
    };
    if rest.is_empty() {
        return !port_required;
    }
    if rest == b":" {
        return !port_required;
    }
    rest.first() == Some(&b':') && decimal(rest.get(1..).unwrap_or_default()).is_some_and(|p| p <= 65535)
}
fn uri_path(path: &[u8]) -> bool {
    let mut pos = 0;
    while let Some(&b) = path.get(pos) {
        if b == b'%' {
            if !path.get(pos + 1).is_some_and(u8::is_ascii_hexdigit)
                || !path.get(pos + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            pos += 3;
        } else {
            if !(b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b':'
                        | b'@'
                        | b'/'
                        | b'?'
                ))
            {
                return false;
            }
            pos += 1;
        }
    }
    true
}
impl HeaderList {
    /// Validates received fields and normalizes repeated identical Content-Length
    /// values to one field. For response context such
    /// as HEAD or CONNECT, use [`RequestStream`] to enforce message semantics.
    pub fn from_fields(fields: Vec<qpack::Field>, kind: HeaderKind) -> Result<Self, Error> {
        Self::received(fields, kind, false).map(|(headers, _)| headers)
    }
    fn received(
        fields: Vec<qpack::Field>,
        kind: HeaderKind,
        connect_response: bool,
    ) -> Result<(Self, HeaderInfo), Error> {
        let mut headers = Self { fields };
        let info = headers.info(kind, Receive { length_list: true, connect_response })?;
        normalize_length(&mut headers.fields, info.content_length);
        Ok((headers, info))
    }

    /// Checks bounds, field characters, forbidden connection fields, pseudo-header
    /// placement and uniqueness, required fields, CONNECT and status rules.
    /// For non-HTTP schemes the caller also checks scheme-specific URI rules.
    /// These are the writer's rules: Content-Length must be one field with one
    /// decimal value. Decoders accept a repeated identical value and rewrite it.
    pub fn validate(&self, kind: HeaderKind) -> Result<(), Error> {
        self.info(kind, Receive::default()).map(|_| ())
    }
    fn info(&self, kind: HeaderKind, receive: Receive) -> Result<HeaderInfo, Error> {
        let bad = Error::Message;
        if self.fields.len() > MAX_FIELDS {
            return Err(Error::Limit);
        }
        let mut size = 0u64;
        let (mut method, mut scheme, mut auth, mut path, mut status, mut protocol, mut host) =
            (None, None, None, None, None, None, None);
        let mut regular = false;
        let mut lengths = 0usize;
        let request = matches!(kind, HeaderKind::Request { .. } | HeaderKind::Promise);
        let mut info = HeaderInfo::default();
        for field in &self.fields {
            let (name, value) = (field.name.as_slice(), field.value.as_slice());
            if name.len() > MAX_FIELD_BYTES || value.len() > MAX_FIELD_BYTES {
                return Err(Error::Limit);
            }
            size = size.checked_add(name.len() as u64 + value.len() as u64 + 32).ok_or(Error::Limit)?;
            if size > MAX_FIELD_SECTION_SIZE {
                return Err(Error::Limit);
            }
            if value.iter().any(|b| matches!(b, 0..=8 | 10..=31 | 127))
                || matches!(value.first(), Some(b' ' | b'\t'))
                || matches!(value.last(), Some(b' ' | b'\t'))
            {
                return Err(bad("invalid field value"));
            }
            if name.first() == Some(&b':') {
                if regular || kind == HeaderKind::Trailers {
                    return Err(bad("pseudo-header after regular fields or in trailers"));
                }
                let slot = match (name, request) {
                    (b":method", true) => &mut method,
                    (b":scheme", true) => &mut scheme,
                    (b":authority", true) => &mut auth,
                    (b":path", true) => &mut path,
                    (b":protocol", true) => &mut protocol,
                    (b":status", false) if kind == HeaderKind::Response => &mut status,
                    _ => return Err(bad("unknown pseudo-header or wrong message kind")),
                };
                if slot.replace(value).is_some() {
                    return Err(bad("duplicate pseudo-header"));
                }
            } else {
                regular = true;
                if !nonempty_token(name) || name.iter().any(u8::is_ascii_uppercase) {
                    return Err(bad("invalid field name"));
                }
                if matches!(
                    name,
                    b"connection" | b"proxy-connection" | b"keep-alive" | b"transfer-encoding" | b"upgrade"
                ) {
                    return Err(bad("connection-specific field"));
                }
                if name == b"te" && (!request || !value.eq_ignore_ascii_case(b"trailers")) {
                    return Err(bad("TE is only trailers in request headers"));
                }
                if kind == HeaderKind::Trailers && matches!(name, b"content-length" | b"host" | b"trailer") {
                    return Err(bad("framing field in trailers"));
                }
                if name == b"host" && host.replace(value).is_some() {
                    return Err(bad("duplicate Host"));
                }
                if name == b"content-length" {
                    lengths += 1;
                    if !receive.length_list && (lengths > 1 || value.contains(&b',')) {
                        return Err(bad("Content-Length must be one decimal value"));
                    }
                    for v in value.split(|b| *b == b',') {
                        let n = decimal(trim_ows(v)).ok_or(bad("invalid Content-Length"))?;
                        if info.content_length.is_some_and(|old| old != n) {
                            return Err(bad("conflicting Content-Length"));
                        }
                        info.content_length = Some(n);
                    }
                }
            }
        }
        match kind {
            HeaderKind::Request { .. } | HeaderKind::Promise => {
                let extended_connect = matches!(kind, HeaderKind::Request { extended_connect: true });
                let method = method.ok_or(bad("missing :method"))?;
                if !nonempty_token(method) {
                    return Err(bad("invalid :method"));
                }
                if kind == HeaderKind::Promise && auth.is_none() {
                    return Err(bad("promised request needs :authority"));
                }
                info.connect = method == b"CONNECT";
                info.trace = method == b"TRACE";
                if info.trace && info.content_length.is_some_and(|n| n > 0) {
                    return Err(bad("content forbidden in TRACE"));
                }
                if auth.is_some_and(|a| a.is_empty()) || host.is_some_and(|h| h.is_empty()) {
                    return Err(bad("empty authority"));
                }
                if let (Some(a), Some(h)) = (auth, host)
                    && a != h {
                        return Err(bad("Host differs from :authority"));
                    }
                if let Some(p) = protocol {
                    if !info.connect || !extended_connect || !nonempty_token(p) {
                        return Err(bad("invalid or unnegotiated :protocol"));
                    }
                    if auth.is_none() {
                        return Err(bad("extended CONNECT needs :authority"));
                    }
                }
                if info.connect && protocol.is_none() {
                    if scheme.is_some() || path.is_some() || !auth.is_some_and(|a| authority(a, true)) {
                        return Err(bad("CONNECT needs only :method and host:port :authority"));
                    }
                } else {
                    let scheme = scheme.ok_or(bad("missing :scheme"))?;
                    if !scheme.first().is_some_and(u8::is_ascii_alphabetic)
                        || !scheme.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
                    {
                        return Err(bad("invalid :scheme"));
                    }
                    let path = path.ok_or(bad("missing :path"))?;
                    let http = scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"https");
                    if !uri_path(path)
                        || (http && !(path.first() == Some(&b'/') || (path == b"*" && method == b"OPTIONS")))
                    {
                        return Err(bad("invalid :path"));
                    }
                    if http && !auth.or(host).is_some_and(|a| authority(a, false)) {
                        return Err(bad("HTTP URI needs a valid authority"));
                    }
                }
            }
            HeaderKind::Response => {
                let value = status.ok_or(bad("missing :status"))?;
                let n = decimal(value).ok_or(bad("invalid :status"))?;
                if value.len() != 3 || !(100..=599).contains(&n) || n == 101 {
                    return Err(bad("invalid HTTP/3 status"));
                }
                let ignored = receive.connect_response && (200..300).contains(&n);
                if (n < 200 || n == 204) && info.content_length.is_some() && !ignored {
                    return Err(bad("Content-Length forbidden for this status"));
                }
                info.status = Some(n as u16);
            }
            HeaderKind::Trailers => {}
        }
        Ok(info)
    }
    /// Builds a validated field section using the connection's QPACK encoder.
    /// An invalid caller stream ID is never silently truncated.
    pub fn section(
        &self,
        encoder: &mut qpack::Encoder,
        stream: u64,
        kind: HeaderKind,
    ) -> Result<qpack::FieldSection, Error> {
        if stream > MAX_VARINT {
            return Err(Error::Id);
        }
        self.validate(kind)?;
        encoder.section(stream, &self.fields).map_err(Error::Qpack)
    }

    /// Parses all Priority field lines as one dictionary in wire order.
    /// Missing fields return an empty Priority; malformed dictionaries return
    /// an error for the caller to ignore or report according to its policy.
    pub fn priority(&self) -> Result<Priority, Error> {
        if self.fields.len() > MAX_FIELDS {
            return Err(Error::Limit);
        }
        let mut out = Vec::new();
        let mut seen = false;
        for field in &self.fields {
            if field.name == b"priority" {
                let end = out
                    .len()
                    .checked_add(field.value.len())
                    .and_then(|n| n.checked_add(if seen { 2 } else { 0 }))
                    .ok_or(Error::Limit)?;
                if end > MAX_PRIORITY_BYTES {
                    return Err(Error::Limit);
                }
                if out.capacity() == 0 {
                    out = Vec::with_capacity(MAX_PRIORITY_BYTES);
                }
                if seen {
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(&field.value);
                seen = true;
            }
        }
        Priority::parse(&out)
    }
}

/// The endpoint that sent a control stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A client.
    Client,
    /// A server.
    Server,
}

#[derive(Clone, Debug)]
struct ControlState {
    sender: Endpoint,
    settings: bool,
    goaway: Option<u64>,
    max_push: Option<u64>,
}
impl ControlState {
    fn new(sender: Endpoint) -> Self {
        Self { sender, settings: false, goaway: None, max_push: None }
    }
    fn accept(&mut self, frame: &Frame) -> Result<(), Error> {
        if !self.settings {
            if !matches!(frame, Frame::Settings(_)) {
                return Err(Error::MissingSettings);
            }
            self.settings = true;
            return Ok(());
        }
        let unexpected = Error::UnexpectedFrame(frame.frame_type());
        match frame {
            Frame::Settings(_) | Frame::Data(_) | Frame::Headers(_) | Frame::PushPromise { .. } => Err(unexpected),
            Frame::MaxPushId(id) => {
                if self.sender != Endpoint::Client {
                    return Err(unexpected);
                }
                if self.max_push.is_some_and(|old| *id < old) {
                    return Err(Error::Id);
                }
                self.max_push = Some(*id);
                Ok(())
            }
            Frame::Goaway(id) => {
                if self.sender == Endpoint::Server && id % 4 != 0 {
                    return Err(Error::Id);
                }
                if self.goaway.is_some_and(|old| *id > old) {
                    return Err(Error::Id);
                }
                self.goaway = Some(*id);
                Ok(())
            }
            Frame::PriorityUpdate { .. } if self.sender != Endpoint::Client => Err(unexpected),
            _ => Ok(()),
        }
    }
}

/// The HTTP message direction and request context needed to read a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageSide {
    /// A request sent by a client.
    Request,
    /// A response to an ordinary method other than HEAD or CONNECT.
    Response,
    /// A response to HEAD; Content-Length describes hypothetical content.
    HeadResponse,
    /// A response to CONNECT; a successful response starts a tunnel.
    ConnectResponse,
}

/// One event from a request or push stream. Returned payloads and field lists
/// belong to the caller and are no longer counted in the decoder's buffers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Initial request headers or final response headers.
    Headers(HeaderList),
    /// An informational response (100 through 199, excluding 101).
    Informational(HeaderList),
    /// A body chunk or tunnel bytes.
    Data(Vec<u8>),
    /// The one optional trailer section.
    Trailers(HeaderList),
    /// A promised request, independent of the surrounding response.
    PushPromise {
        /// The promised push ID; the caller checks connection permissions.
        push_id: u64,
        /// The promised request's validated fields.
        headers: HeaderList,
    },
    /// A frame with an unknown or reserved type. Ignore it for HTTP semantics.
    Unknown(Frame),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageState {
    Initial,
    Body,
    Trailers,
}
#[derive(Clone, Copy, Debug)]
enum PendingSection {
    Headers,
    Promise(u64),
}

/// One request-session result. The caller owns blocked sections and output instructions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestResult {
    /// An HTTP event or field-validation error, with its QPACK acknowledgment.
    /// Even rejected HTTP fields can form a successfully decoded QPACK section;
    /// send its acknowledgment before handling the HTTP stream error.
    Event {
        /// The message event, with received field lists normalized, or their error.
        event: Result<Event, Error>,
        /// Send this value on the decoder stream before taking an insert increment.
        ack: Option<qpack::DecoderInstruction>,
    },
    /// Call [`Session::pause`] until the section can be retried, then
    /// [`RequestStream::resume`] and [`Session::unpause`] before reading more frames.
    Blocked(qpack::BlockedSection),
}

/// Request or push message state over decoded [`Frame`] values.
///
/// Drive [`codec::Frames<Frame>`](fictionet::stdlib::codec::Frames) with [`codec::Stream`] or route [`Session`] frame items
/// here. This state checks message order: HEADERS and
/// DATA ordering, trailers, interim responses, CONNECT, and Content-Length.
/// Received duplicate identical Content-Length values are normalized.
/// No input, blocked field bytes, or acknowledgment queue is retained here.
/// Hold returned blocked sections in [`qpack::BlockedSections`] and call
/// [`Session::pause`] for this stream (or stop driving its standalone
/// [`codec::Stream`]). Pass its retried result to [`Self::resume`], then call
/// [`Session::unpause`] once it is no longer blocked. Send every returned
/// acknowledgment in order, even on reset, before [`qpack::Table::take_increment`].
/// Use [`Self::with_field_limit`] to enforce the advertised
/// SETTINGS_MAX_FIELD_SECTION_SIZE on immediate and retried sections.
/// Protocol errors stop the session; local [`Error::State`] leaves it intact.
/// After the byte decoder reaches a clean FIN, call [`Self::finish`].
///
/// ```
/// use fictionet::stdlib::codec::Frames;
/// use fictionet::stdlib::{codec::{Stream, Wire}, http3::{self, Frame, MessageSide}, qpack};
/// let headers = http3::HeaderList { fields: vec![
///     qpack::Field::new(":status", "200"), qpack::Field::new("content-length", "0"),
/// ] };
/// let mut encoder = qpack::Encoder::new(0, http3::MAX_FIELD_SECTION_SIZE);
/// let section = headers.section(&mut encoder, 0, http3::HeaderKind::Response)?;
/// let mut input = Stream::new(Frames::<http3::Frame>::new());
/// let frame = Wire::to_bytes(&Frame::headers(&section)?)?;
/// assert_eq!(input.push(&frame), frame.len());
/// let table = qpack::Table::new(0);
/// let mut state = http3::RequestStream::new(0, MessageSide::Response, false)?;
/// let result = state.step(&input.next().unwrap()??, &table)?;
/// assert!(matches!(result, http3::RequestResult::Event { event: Ok(http3::Event::Headers(_)), ack: None }));
/// input.end();
/// assert!(input.next().is_none());
/// state.finish()?;
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct RequestStream {
    stream: u64,
    side: MessageSide,
    push: bool,
    extended_connect: bool,
    state: MessageState,
    pending: Option<PendingSection>,
    field_limit: u64,
    content_length: Option<u64>,
    body_bytes: u64,
    no_content: bool,
    no_trailers: bool,
    tunnel: bool,
    stopped: bool,
}
impl RequestStream {
    /// Makes message state for stream 0, 4, 8, and so on. Set extended_connect only
    /// when the server's ENABLE_CONNECT_PROTOCOL setting permits it.
    pub fn new(stream: u64, side: MessageSide, extended_connect: bool) -> Result<Self, Error> {
        if stream > MAX_VARINT || !stream.is_multiple_of(4) {
            return Err(Error::Id);
        }
        Ok(Self {
            stream,
            side,
            push: false,
            extended_connect,
            state: MessageState::Initial,
            pending: None,
            field_limit: MAX_FIELD_SECTION_SIZE,
            content_length: None,
            body_bytes: 0,
            no_content: false,
            no_trailers: false,
            tunnel: false,
            stopped: false,
        })
    }
    /// Makes response state for a server-initiated unidirectional push
    /// stream (IDs 3, 7, 11, ...). Its type and push ID must already be read.
    /// Push permissions and duplicate push streams are checked by the caller.
    /// It reads a response to GET; call set_push_side for a promised HEAD.
    pub fn push(stream: u64) -> Result<Self, Error> {
        if stream > MAX_VARINT || stream % 4 != 3 {
            return Err(Error::Id);
        }
        let mut decoder = Self::new(0, MessageSide::Response, false)?;
        decoder.stream = stream;
        decoder.push = true;
        Ok(decoder)
    }
    /// Sets the received field-section limit, capped by [`MAX_FIELD_SECTION_SIZE`].
    /// Call after [`Self::new`] or [`Self::push`] with the endpoint's advertised
    /// SETTINGS_MAX_FIELD_SECTION_SIZE. The default is [`MAX_FIELD_SECTION_SIZE`].
    /// Counts name and value bytes plus [`qpack::ENTRY_OVERHEAD`] per field;
    /// zero permits only empty sections. Blocked sections retain the limit
    /// used when they were first stepped, including across later retries.
    pub fn with_field_limit(mut self, limit: u64) -> Self {
        self.field_limit = limit.min(MAX_FIELD_SECTION_SIZE);
        self
    }
    /// Sets the promised method's response side on a push stream: Response
    /// or HeadResponse. Push stream bytes can arrive before their PUSH_PROMISE,
    /// call this before step returns the final
    /// headers. Other sides, request streams and later calls are State errors.
    pub fn set_push_side(&mut self, side: MessageSide) -> Result<(), Error> {
        if !self.push
            || self.stopped
            || self.state != MessageState::Initial
            || self.pending.is_some()
            || !matches!(side, MessageSide::Response | MessageSide::HeadResponse)
        {
            return Err(Error::State);
        }
        self.side = side;
        Ok(())
    }
    /// The QUIC stream ID to use when routing QPACK results.
    pub fn stream_id(&self) -> u64 {
        self.stream
    }
    /// Whether the caller holds a section that must be retried and resumed.
    pub fn is_blocked(&self) -> bool {
        self.pending.is_some()
    }
    fn fail(&mut self) {
        self.stopped = true;
        self.pending = None;
    }
    fn kind(&self, pending: PendingSection) -> HeaderKind {
        if matches!(pending, PendingSection::Promise(_)) {
            return HeaderKind::Promise;
        }
        if self.state != MessageState::Initial {
            return HeaderKind::Trailers;
        }
        if self.side == MessageSide::Request {
            HeaderKind::Request { extended_connect: self.extended_connect }
        } else {
            HeaderKind::Response
        }
    }
    fn accept_fields(&mut self, pending: PendingSection, fields: Vec<qpack::Field>) -> Result<Event, Error> {
        let kind = self.kind(pending);
        let (headers, info) = HeaderList::received(fields, kind, self.side == MessageSide::ConnectResponse)?;
        if let PendingSection::Promise(push_id) = pending {
            return Ok(Event::PushPromise { push_id, headers });
        }
        if kind == HeaderKind::Trailers {
            self.state = MessageState::Trailers;
            return Ok(Event::Trailers(headers));
        }
        if info.status.is_some_and(|n| n < 200) {
            return Ok(Event::Informational(headers));
        }
        self.state = MessageState::Body;
        // Any 2xx response to CONNECT opens a tunnel; its Content-Length is
        // ignored and its status puts no limit on tunnel bytes.
        self.tunnel = (self.side == MessageSide::Request && info.connect)
            || (self.side == MessageSide::ConnectResponse && info.status.is_some_and(|s| (200..300).contains(&s)));
        // RFC 9110: HEAD responses, 204, 205 and 304 carry no content, nor
        // do TRACE requests; 204 and 304 carry no trailers either.
        self.no_content = !self.tunnel
            && (self.side == MessageSide::HeadResponse
                || (self.side == MessageSide::Request && info.trace)
                || matches!(info.status, Some(204 | 205 | 304)));
        self.no_trailers = !self.tunnel && matches!(info.status, Some(204 | 304));
        let hypothetical = self.side == MessageSide::HeadResponse || info.status == Some(304);
        self.content_length = if self.tunnel || hypothetical { None } else { info.content_length };
        Ok(Event::Headers(headers))
    }
    fn pending_section<'a>(&self, frame: &'a Frame) -> Result<Option<(PendingSection, &'a [u8])>, Error> {
        let t = frame.frame_type();
        // RFC 9114 section 4.4: an open tunnel carries only DATA and extension
        // frames. This is checked before QPACK sees a section.
        let refused = if self.tunnel && !matches!(frame, Frame::Data(_) | Frame::Unknown { .. }) {
            Some(Error::UnexpectedFrame(t))
        } else if self.no_trailers && matches!(frame, Frame::Headers(_)) {
            Some(Error::Message("trailers forbidden for this response"))
        } else {
            None
        };
        if let Some(e) = refused {
            return Err(e);
        }
        let pending = match frame {
            Frame::Headers(bytes) if self.state != MessageState::Trailers => {
                Some((PendingSection::Headers, bytes.as_slice()))
            }
            Frame::PushPromise { push_id, field_section } if self.side != MessageSide::Request && !self.push => {
                Some((PendingSection::Promise(*push_id), field_section.as_slice()))
            }
            _ => None,
        };
        Ok(pending)
    }
    fn accept_frame(&mut self, frame: &Frame) -> Result<Event, Error> {
        let t = frame.frame_type();
        match frame {
            Frame::Data(data) if self.state == MessageState::Body => {
                if self.no_content && !data.is_empty() {
                    Err(Error::Message("content forbidden for this response"))
                } else if let Some(total) = self.body_bytes.checked_add(data.len() as u64) {
                    if self.content_length.is_some_and(|n| total > n) {
                        Err(Error::Message("DATA exceeds Content-Length"))
                    } else {
                        self.body_bytes = total;
                        Ok(Event::Data(data.clone()))
                    }
                } else {
                    Err(Error::Limit)
                }
            }
            other @ Frame::Unknown { .. } => Ok(Event::Unknown(other.clone())),
            _ => Err(Error::UnexpectedFrame(t)),
        }
    }
    fn accept_section(
        &mut self,
        pending: PendingSection,
        section: qpack::SectionResult,
    ) -> Result<RequestResult, Error> {
        match section {
            qpack::SectionResult::Fields { fields, ack } => {
                self.pending = None;
                let event = self.accept_fields(pending, fields);
                if event.is_err() {
                    self.fail();
                }
                Ok(RequestResult::Event { event, ack })
            }
            qpack::SectionResult::Blocked(section) => {
                self.pending = Some(pending);
                Ok(RequestResult::Blocked(section))
            }
        }
    }
    /// Validates one decoded frame against the receiving QPACK table.
    /// A blocked or finished session returns State without consuming the frame.
    /// On Blocked, call [`Session::pause`], retain the returned section, and
    /// resume it before [`Session::unpause`] allows the next frame.
    /// Field-validation errors are carried beside their acknowledgment in
    /// [`RequestResult::Event`]; send that acknowledgment even for invalid HTTP
    /// fields. Placement and QPACK decoding failures return `Err`.
    pub fn step(&mut self, frame: &Frame, table: &qpack::Table) -> Result<RequestResult, Error> {
        if self.stopped || self.pending.is_some() {
            return Err(Error::State);
        }
        let result = self.pending_section(frame).and_then(|pending| {
            if let Some((pending, bytes)) = pending {
                let section = qpack::decode_section_with_limit(table, self.stream, bytes, self.field_limit)
                    .map_err(Error::Qpack)?;
                self.accept_section(pending, section)
            } else {
                self.accept_frame(frame).map(|event| RequestResult::Event { event: Ok(event), ack: None })
            }
        });
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Supplies this stream's retried section, including errors from retry.
    /// A still-blocked value is returned for the caller to retain again.
    /// A mismatched stream or a session without a pending section returns State.
    pub fn resume(
        &mut self,
        stream: u64,
        section: Result<qpack::SectionResult, qpack::Error>,
    ) -> Result<RequestResult, Error> {
        if self.stopped
            || stream != self.stream
            || matches!(&section, Ok(qpack::SectionResult::Blocked(blocked)) if blocked.stream_id() != stream)
        {
            return Err(Error::State);
        }
        let pending = self.pending.ok_or(Error::State)?;
        let result = section.map_err(Error::Qpack).and_then(|section| self.accept_section(pending, section));
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Checks message completeness and Content-Length after a clean byte-stream FIN.
    /// A blocked session must resume first; State leaves its pending section intact.
    /// Success or a protocol error closes the session to further frames.
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.stopped || self.pending.is_some() {
            return Err(Error::State);
        }
        let result = if self.state == MessageState::Initial {
            Err(Error::Incomplete)
        } else if self.content_length.is_some_and(|n| n != self.body_bytes) {
            Err(Error::Message("DATA differs from Content-Length"))
        } else {
            Ok(())
        };
        self.fail();
        result
    }
}

// ---------------------------------------------------------------------
// Slice decoders and the connection's shared input budget.

fn exact<T>(result: Result<Option<(T, usize)>, Error>, len: usize) -> Result<T, Error> {
    match result? {
        Some((value, used)) if used == len => Ok(value),
        Some(_) => Err(Error::Trailing),
        None => Err(Error::Truncated),
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one frame. Refuses truncation, trailing bytes, forbidden types, invalid payloads, and limits.
    /// Nonminimal QUIC integers are accepted. QPACK bytes remain opaque.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(Self::parse_prefix(bytes), bytes.len())
    }

    /// Writes one frame. Refuses invalid IDs, known types disguised as unknown, invalid payloads, and limits.
    /// Encoded QPACK bytes remain opaque. Integers use their shortest form.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        let t = self.frame_type();
        let payload = match self {
            Self::Data(b) | Self::Unknown { payload: b, .. } => {
                if matches!(self, Self::Unknown { .. }) && known_frame(t) {
                    return Err(Error::Unwritable);
                }
                if t > MAX_VARINT {
                    return Err(Error::Unwritable);
                }
                if b.len() > MAX_FRAME_PAYLOAD {
                    return Err(Error::Unwritable);
                }
                b.clone()
            }
            Self::Headers(b) => {
                field_bytes(b).map_err(|_| Error::Unwritable)?;
                b.clone()
            }
            Self::Settings(s) => s.to_bytes()?,
            Self::CancelPush(id) | Self::Goaway(id) | Self::MaxPushId(id) => {
                let mut out = Vec::with_capacity(MAX_STREAM_HEADER);
                put_varint(*id, &mut out)?;
                out
            }
            Self::PushPromise { push_id, field_section } => {
                field_bytes(field_section).map_err(|_| Error::Unwritable)?;
                let mut out = Vec::with_capacity(MAX_SECTION_BYTES + 8);
                put_varint(*push_id, &mut out)?;
                out.extend_from_slice(field_section);
                out
            }
            Self::PriorityUpdate { element, value } => {
                priority_bytes(value).map_err(|_| Error::Unwritable)?;
                let id = match element {
                    PriorityElement::Request(id) if id % 4 != 0 => return Err(Error::Unwritable),
                    PriorityElement::Request(id) | PriorityElement::Push(id) => *id,
                };
                let mut out = Vec::with_capacity(MAX_PRIORITY_BYTES + 8);
                put_varint(id, &mut out)?;
                out.extend_from_slice(value);
                out
            }
        };
        let mut out = Vec::with_capacity(payload.len().checked_add(MAX_FRAME_HEADER).ok_or(Error::Unwritable)?);
        put_varint(t, &mut out)?;
        put_varint(payload.len() as u64, &mut out)?;
        out.extend_from_slice(&payload);
        destination.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Settings {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete SETTINGS payload. Refuses incomplete pairs, duplicates, invalid settings, and limits.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SETTINGS_BYTES {
            return Err(Error::Limit);
        }
        let mut entries: Vec<Setting> = Vec::with_capacity(MAX_SETTINGS);
        let mut pos = 0;
        while pos < bytes.len() {
            if entries.len() == MAX_SETTINGS {
                return Err(Error::Limit);
            }
            let id = integer_at(bytes, &mut pos)?;
            let value = integer_at(bytes, &mut pos)?;
            check_setting(id, value)?;
            if entries.iter().any(|s| s.id == id) {
                return Err(Error::DuplicateSetting(id));
            }
            entries.push(Setting { id, value });
        }
        Ok(Self { entries })
    }

    /// Writes a SETTINGS payload. Refuses duplicates, invalid settings, and excessive counts.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        if self.entries.len() > MAX_SETTINGS {
            return Err(Error::Unwritable);
        }
        let mut out = Vec::with_capacity(MAX_SETTINGS_BYTES);
        for (i, entry) in self.entries.iter().enumerate() {
            check_setting(entry.id, entry.value).map_err(|_| Error::Unwritable)?;
            if self.entries.iter().take(i).any(|s| s.id == entry.id) {
                return Err(Error::Unwritable);
            }
            put_varint(entry.id, &mut out)?;
            put_varint(entry.value, &mut out)?;
        }
        destination.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for StreamHeader {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one stream prefix. Refuses truncation and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(Self::parse_prefix(bytes), bytes.len())
    }

    /// Writes the shortest prefix. Refuses oversized IDs and unknown types that alias a defined type.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::with_capacity(MAX_STREAM_HEADER);
        let t = match *self {
            Self::Control => 0,
            Self::Push(_) => 1,
            Self::QpackEncoder => 2,
            Self::QpackDecoder => 3,
            Self::Unknown(t) if t <= 3 => return Err(Error::Unwritable),
            Self::Unknown(t) => t,
        };
        put_varint(t, &mut out)?;
        if let Self::Push(id) = *self {
            put_varint(id, &mut out)?;
        }
        destination.extend_from_slice(&out);
        Ok(())
    }
}

/// Reads one complete frame per call without holding input.
///
/// Declared payloads above [`MAX_FRAME_PAYLOAD`] or the smaller per-type
/// limits, forbidden frame types, and invalid single-varint lengths end
/// framing as soon as the header is known. Other complete-frame
/// failures are error items, preserving the next boundary. Applications
/// enforce the associated HTTP/3 connection or stream error policy.
/// Partial frames return [`Step::Need`], including at EOF, so [`codec::Stream`]
/// reports truncation. Allocation grows only when the driver receives bytes.
impl Prefixed for Frame {
    type Item = Result<Frame, Error>;
    type Error = Error;
    type Limit = ();
    const NAME: &'static str = "HTTP/3 frames";

    #[inline]
    fn default_limit() -> Self::Limit {}

    #[inline]
    fn capacity(_limit: &Self::Limit) -> usize {
        MAX_FRAME
    }

    #[inline]
    fn parse_prefix(input: &[u8], _limit: &Self::Limit) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let Some((kind, start, end)) = frame_header(input)? else { return Ok(None) };
        let Some(payload) = input.get(start..end) else { return Ok(None) };
        Ok(Some((Frame::parse_payload(kind, payload), end)))
    }
}


/// Reads one unidirectional stream header, then returns [`Step::End`].
///
/// The item consumes only the type integer and, for a push stream, its push
/// ID. All following bytes stay unread for [`codec::Stream::swap`]. Capacity
/// is [`MAX_STREAM_HEADER`]. At EOF, a partial prefix is reported as truncated;
/// the connection may discard that stream as RFC 9114 section 6.2 permits.
///
/// ```
/// use fictionet::stdlib::codec::{Frames, Stream, Wire};
/// use fictionet::stdlib::http3::{Frame, StreamHeader, StreamHeaders};
/// let mut bytes = Wire::to_bytes(&StreamHeader::Push(7))?;
/// Wire::write(&Frame::Data(vec![1, 2]), &mut bytes)?;
/// let mut stream = Stream::new(StreamHeaders::new());
/// assert_eq!(stream.push(&bytes), bytes.len());
/// assert_eq!(stream.next(), Some(Ok(StreamHeader::Push(7))));
/// assert_eq!(stream.next(), None); // End leaves the DATA bytes unread.
/// let mut stream = stream.swap(Frames::<Frame>::new());
/// assert_eq!(stream.next(), Some(Ok(Ok(Frame::Data(vec![1, 2])))));
/// # Ok::<(), fictionet::stdlib::http3::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamHeaders {
    taken: bool,
}

impl StreamHeaders {
    /// Creates a decoder for one stream prefix.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Decode for StreamHeaders {
    type Item = StreamHeader;
    type Error = Error;
    const NAME: &'static str = "HTTP/3 stream header";

    fn capacity(&self) -> usize {
        MAX_STREAM_HEADER
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<StreamHeader>, Error> {
        if self.taken {
            return Ok(Step::End);
        }
        Ok(match StreamHeader::parse_prefix(input)? {
            Some((header, used)) => {
                self.taken = true;
                Step::Item(header, used)
            }
            None => Step::Need,
        })
    }
}

/// Reads frames on a control stream after its type header.
///
/// Validates first and unique SETTINGS, frame placement, sender restrictions,
/// and monotonic GOAWAY and MAX_PUSH_ID values. Complete invalid units are
/// error items. The caller decides the connection response before reading
/// again. State changes only on accepted frame items. Any FIN, including one
/// in the middle of a frame, ends with [`Error::ClosedCriticalStream`].
#[derive(Clone, Debug)]
pub struct ControlFrames {
    state: ControlState,
}

impl ControlFrames {
    /// Creates a control decoder for the endpoint sending this stream.
    pub fn new(sender: Endpoint) -> Self {
        Self { state: ControlState::new(sender) }
    }
}

impl Decode for ControlFrames {
    type Item = Result<Frame, Error>;
    type Error = Error;
    const NAME: &'static str = "HTTP/3 control stream";

    fn capacity(&self) -> usize {
        MAX_FRAME
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Error> {
        if eof && input.is_empty() {
            return Err(Error::ClosedCriticalStream);
        }
        Ok(match Frames::<Frame>::new().decode(input, eof)? {
            Step::Item(item, used) => Step::Item(
                item.and_then(|frame| {
                    self.state.accept(&frame)?;
                    Ok(frame)
                }),
                used,
            ),
            Step::Need if eof => return Err(Error::ClosedCriticalStream),
            Step::Need => Step::Need,
            Step::Skip(n) => Step::Skip(n),
            Step::End => Step::End,
        })
    }
}

/// A single unit read on one connection stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamItem {
    /// A stream prefix. The next item belongs to the selected decoder.
    Header(StreamHeader),
    /// A control, request, or push frame. QPACK sections remain encoded.
    Frame(Frame),
    /// One instruction to apply to the session's receiving QPACK table.
    EncoderInstruction(qpack::EncoderInstruction),
    /// One acknowledgment, cancellation, or insert-count increment.
    DecoderInstruction(qpack::DecoderInstruction),
}

#[derive(Clone, Debug)]
enum StreamKind {
    Header(StreamHeaders),
    Frames,
    Control(ControlFrames),
    Encoder,
    Decoder,
    Ignore,
    Invalid,
    Paused(usize),
}

/// The selected byte decoder for a single HTTP/3 stream.
///
/// [`Session`] drives these with [`codec::Demux`]. Tables, blocked
/// sections, acknowledgment values, and HTTP request semantics belong to
/// the caller. Use [`RequestStream::step`] between frame items, or
/// [`qpack::decode_section`] and [`HeaderList::from_fields`] for standalone
/// sections. Unknown stream payloads are skipped in bounded
/// chunks. Every variant owns no input and retains no output queue. Any FIN
/// on a control or QPACK stream, including within a partial unit, returns
/// [`Error::ClosedCriticalStream`].
#[derive(Clone, Debug)]
pub struct StreamItems {
    kind: StreamKind,
}

impl StreamItems {
    /// Reads request or response frames without a unidirectional prefix.
    pub fn request() -> Self {
        Self { kind: StreamKind::Frames }
    }
    /// Reads one unidirectional header and ends for a driver handoff.
    pub fn unidirectional() -> Self {
        Self { kind: StreamKind::Header(StreamHeaders::new()) }
    }
    /// Selects the decoder for bytes after a complete stream header.
    /// Use [`codec::Stream::swap`] so unread bytes and EOF are preserved.
    pub fn after_header(header: StreamHeader, sender: Endpoint) -> Self {
        let kind = match header {
            StreamHeader::Control => StreamKind::Control(ControlFrames::new(sender)),
            StreamHeader::Push(_) => StreamKind::Frames,
            StreamHeader::QpackEncoder => StreamKind::Encoder,
            StreamHeader::QpackDecoder => StreamKind::Decoder,
            StreamHeader::Unknown(_) => StreamKind::Ignore,
        };
        Self { kind }
    }
}

fn stream_step<T>(
    step: Step<T>,
    wrap: impl FnOnce(T) -> Result<StreamItem, Error>,
) -> Step<Result<StreamItem, Error>> {
    match step {
        Step::Item(item, used) => Step::Item(wrap(item), used),
        Step::Need => Step::Need,
        Step::End => Step::End,
        Step::Skip(n) => Step::Skip(n),
    }
}

impl Decode for StreamItems {
    type Item = Result<StreamItem, Error>;
    type Error = Error;
    const NAME: &'static str = "HTTP/3 stream";

    fn capacity(&self) -> usize {
        match self.kind {
            StreamKind::Header(_) => MAX_STREAM_HEADER,
            StreamKind::Encoder => qpack::MAX_INSTRUCTION,
            StreamKind::Decoder => qpack::MAX_INTEGER_BYTES,
            StreamKind::Frames | StreamKind::Control(_) => MAX_FRAME,
            StreamKind::Ignore | StreamKind::Invalid => MAX_STREAM_HEADER,
            StreamKind::Paused(held) => held.saturating_add(1),
        }
    }

    fn held(&self) -> usize {
        match self.kind {
            StreamKind::Paused(held) => held,
            _ => 0,
        }
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Error> {
        Ok(match &mut self.kind {
            StreamKind::Header(decoder) => {
                stream_step(decoder.decode(input, eof)?, |header| Ok(StreamItem::Header(header)))
            }
            StreamKind::Frames => stream_step(Frames::<Frame>::new().decode(input, eof)?, |frame| Ok(StreamItem::Frame(frame?))),
            StreamKind::Control(decoder) => {
                stream_step(decoder.decode(input, eof)?, |frame| Ok(StreamItem::Frame(frame?)))
            }
            StreamKind::Encoder => {
                if eof && input.is_empty() {
                    return Err(Error::ClosedCriticalStream);
                }
                let step = Frames::<qpack::EncoderInstruction>::new().decode(input, eof).map_err(Error::QpackEncoderStream)?;
                if eof && matches!(step, Step::Need) {
                    return Err(Error::ClosedCriticalStream);
                }
                stream_step(step, |item| item.map(StreamItem::EncoderInstruction).map_err(Error::QpackEncoderStream))
            }
            StreamKind::Decoder => {
                if eof && input.is_empty() {
                    return Err(Error::ClosedCriticalStream);
                }
                let step = Frames::<qpack::DecoderInstruction>::new().decode(input, eof).map_err(Error::QpackDecoderStream)?;
                if eof && matches!(step, Step::Need) {
                    return Err(Error::ClosedCriticalStream);
                }
                stream_step(step, |item| item.map(StreamItem::DecoderInstruction).map_err(Error::QpackDecoderStream))
            }
            StreamKind::Ignore if input.is_empty() => Step::Need,
            StreamKind::Ignore => Step::Skip(input.len()),
            StreamKind::Invalid => return Err(Error::Id),
            StreamKind::Paused(_) => Step::Need,
        })
    }
}

type StreamFactory = Box<dyn FnMut(&u64) -> StreamItems + Send>;

/// Ordered QUIC stream input under one aggregate connection budget.
///
/// This is an input owner, separate from the I/O [`fictionet::stdlib::Connection`] trait.
/// Each stream has its own decoder inside [`codec::Demux`]. The constructor
/// bounds both stream count and the sum of unread and decoder-held bytes.
/// Buffers allocate as input arrives. Metadata and allocator overhead are
/// separate from the byte budget and bounded by `max_streams`.
///
/// Unidirectional headers yield an item, then `End`. Before returning the
/// item, this owner swaps the same stream to its selected decoder, keeping
/// unread bytes, offset, and EOF. The next call reads the first payload byte.
/// Bidirectional client streams start directly with frames. Invalid stream
/// IDs fail on decoding. Remove closed keys only after QUIC has retired them.
///
/// This owner does not enforce unique critical streams, push permissions,
/// request ordering, or settings negotiation. Those are session decisions
/// made between items. The caller owns [`qpack::Table`] and
/// [`qpack::BlockedSections`]; their limits are separate from input.
/// Use [`RequestStream::step`] for request/push frame items, or
/// [`HeaderList::from_fields`] for standalone received fields.
/// A paused stream yields [`Step::Need`] without receiving EOF. Its saved
/// stream retains input and EOF, charged to the shared budget as held bytes.
/// On [`RequestResult::Blocked`], call [`Self::pause`] so later frames stay
/// in the input budget. Retry the section and call [`RequestStream::resume`],
/// then [`Self::unpause`] when it is no longer blocked.
/// Acknowledgments and insert increments come back as values to send.
pub struct Session {
    streams: codec::Demux<u64, StreamItems, StreamFactory>,
    paused: std::collections::BTreeMap<u64, codec::Stream<StreamItems>>,
    sender: Endpoint,
}

impl Session {
    /// Creates input routing for bytes sent by one peer endpoint.
    /// `max_streams` bounds open and closed keys; `max_bytes` is shared by
    /// every input stream, including control and both QPACK streams.
    /// Set `max_bytes` to at least [`MAX_FRAME`], plus room for partial units
    /// on other concurrent streams. A smaller budget may stall on a valid frame.
    /// Even with that minimum, multiple partial frames can exhaust the budget:
    /// if push returns zero and nothing can be drained, reset/remove a stream
    /// to release input before retrying. The budget is not raised automatically.
    pub fn new(sender: Endpoint, max_streams: usize, max_bytes: usize) -> Self {
        Self {
            streams: codec::Demux::new(
                max_streams,
                max_bytes,
                Box::new(move |id: &u64| {
                    let uni_sender = match sender {
                        Endpoint::Client => 2,
                        Endpoint::Server => 3,
                    };
                    if *id > MAX_VARINT || (!(*id).is_multiple_of(4) && *id % 4 != uni_sender) {
                        StreamItems {
                            kind: StreamKind::Invalid,
                        }
                    } else if id.is_multiple_of(4) {
                        StreamItems::request()
                    } else {
                        StreamItems::unidirectional()
                    }
                }),
            ),
            paused: std::collections::BTreeMap::new(),
            sender,
        }
    }
    /// Accepts what fits in the shared budget. Drain items and retry the
    /// suffix after this count. A zero count means no input currently fits.
    /// If draining makes no progress, reset/remove a stream to free its budget.
    /// After EOF or a terminal result, accepts and drops bytes like `Demux`.
    /// Paused streams always return zero, including after [`Self::end`].
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, stream: u64, bytes: &[u8]) -> usize {
        if self.paused.contains_key(&stream) {
            return 0;
        }
        self.streams.push(&stream, bytes)
    }
    /// Stops an existing stream between items, retaining all unread bytes in
    /// the shared budget. [`Self::push`] refuses its input and [`Self::next`]
    /// yields nothing for it until [`Self::unpause`]. Other streams keep running.
    /// Repeated pauses, absent keys, and completed or failed streams are unchanged.
    pub fn pause(&mut self, id: u64) {
        if self.paused.contains_key(&id) {
            return;
        }
        if let Some(stream) = self.streams.get_mut(&id)
            && !stream.is_done()
        {
            let held = stream.buffered().saturating_add(stream.held());
            let idle = codec::Stream::new(StreamItems { kind: StreamKind::Paused(held) });
            self.paused.insert(id, core::mem::replace(stream, idle));
        }
    }
    /// Resumes a paused stream with its recorded EOF state.
    /// Buffered bytes and their offsets are preserved. Call after the blocked
    /// section has been retried and accepted by [`RequestStream::resume`].
    /// Absent and unpaused keys are unchanged; terminal failures are not restarted.
    pub fn unpause(&mut self, id: u64) {
        if let Some(saved) = self.paused.remove(&id)
            && let Some(stream) = self.streams.get_mut(&id)
        {
            *stream = saved;
        }
    }
    /// Marks EOF on an existing stream. Partial request/push units report
    /// truncation; any control or QPACK stream FIN is ClosedCriticalStream.
    /// A unidirectional stream closed inside its type prefix ends with
    /// [`codec::Fail::Truncated`], which is not a connection error; the caller discards the stream.
    /// On a paused stream, records EOF for [`Self::unpause`] without decoding.
    pub fn end(&mut self, stream: u64) {
        if let Some(saved) = self.paused.get_mut(&stream) {
            saved.end();
        } else {
            self.streams.end(&stream);
        }
    }
    /// Takes one item or terminal error, with its QUIC stream ID.
    /// Complete-unit errors are the inner result; framing errors are outer.
    /// A header handoff is completed before another payload item is read.
    #[allow(clippy::should_implement_trait, clippy::type_complexity)]
    pub fn next(&mut self) -> Option<(u64, Result<Result<StreamItem, Error>, codec::Fail<Error>>)> {
        let (id, result) = self.streams.next()?;
        if let Ok(Ok(StreamItem::Header(header))) = &result
            && let Some(stream) = self.streams.get_mut(&id)
        {
            // The header decoder has yielded its one item. Its next step
            // is End, which consumes none of the already buffered payload.
            let _ = stream.next();
            let next = StreamItems::after_header(*header, self.sender);
            Self::swap_stream(stream, next);
        }
        Some((id, result))
    }
    fn swap_stream(stream: &mut codec::Stream<StreamItems>, next: StreamItems) {
        // swap takes ownership; the temporary stream allocates no input buffer.
        let previous = core::mem::replace(stream, codec::Stream::new(StreamItems::unidirectional()));
        *stream = previous.swap(next);
    }
    /// The aggregate unread and decoder-held bytes across every stream.
    pub fn buffered(&self) -> usize {
        self.streams.total()
    }
    /// The number of stream keys, including completed streams.
    pub fn len(&self) -> usize {
        self.streams.len()
    }
    /// Whether there are no stream keys.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }
    /// Removes a retired key and returns its stream, including unread bytes
    /// and any terminal failure. The next push for this key can reopen it.
    pub fn remove(&mut self, stream: u64) -> Option<codec::Stream<StreamItems>> {
        let active = self.streams.remove(&stream);
        self.paused.remove(&stream).or(active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream,
    };
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn event(state: &mut RequestStream, frame: Frame, table: &qpack::Table) -> Result<Event, Error> {
        match state.step(&frame, table)? {
            RequestResult::Event { event, .. } => event,
            RequestResult::Blocked(_) => Err(Error::State),
        }
    }

    fn received(table: &qpack::Table, stream: u64, bytes: &[u8], kind: HeaderKind) -> Result<HeaderList, Error> {
        let qpack::SectionResult::Fields { fields, .. } =
            qpack::decode_section(table, stream, bytes).map_err(Error::Qpack)?
        else {
            return Err(Error::State);
        };
        HeaderList::from_fields(fields, kind)
    }

    const MAX_TEST_BYTES: usize = 2048;
    const FUZZ_CASES: usize = 3000;
    fn fields(pairs: &[(&str, &str)]) -> HeaderList {
        HeaderList { fields: pairs.iter().map(|(n, v)| qpack::Field::new(n, v)).collect() }
    }
    fn request() -> HeaderList {
        fields(&[(":method", "GET"), (":scheme", "https"), (":authority", "example.net"), (":path", "/")])
    }
    fn response(status: &str) -> HeaderList {
        fields(&[(":status", status)])
    }
    fn plain_qpack() -> qpack::Table {
        qpack::Table::new(0)
    }
    fn encoded(list: &HeaderList) -> Vec<u8> {
        qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE).section(0, &list.fields).unwrap().to_bytes().unwrap()
    }
    fn headers(list: &HeaderList) -> Frame {
        Frame::Headers(encoded(list))
    }
    fn settings() -> Frame {
        Frame::Settings(Settings::default())
    }
    fn join(frames: &[Frame]) -> Vec<u8> {
        let mut out = Vec::new();
        for frame in frames {
            out.extend_from_slice(&frame.to_bytes().unwrap());
        }
        out
    }
    fn roundtrip(frame: &Frame) {
        let bytes = frame.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_FRAME);
        assert_eq!(Frame::parse(&bytes), Ok(frame.clone()));
    }
    fn messages(side: MessageSide, frames: &[Frame]) -> (Vec<Event>, Result<(), Error>) {
        let mut state = RequestStream::new(0, side, false).unwrap();
        let table = plain_qpack();
        let (items, failure) = decode_all(Frames::<Frame>::new, &join(frames));
        assert!(failure.is_none());
        let mut events = Vec::new();
        for frame in items {
            match frame.and_then(|frame| event(&mut state, frame, &table)) {
                Ok(item) => events.push(item),
                Err(error) => return (events, Err(error)),
            }
        }
        (events, state.finish())
    }
    fn control(sender: Endpoint, frames: &[Frame]) -> Result<(), Error> {
        let (items, failure) = decode_all(|| ControlFrames::new(sender), &join(frames));
        for item in items {
            item?;
        }
        match failure {
            Some(Fail::Protocol(Error::ClosedCriticalStream)) => Ok(()),
            Some(Fail::Protocol(error)) => Err(error),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rfc_frame_layout_exact_bytes() {
        let examples = [
            (Frame::Data(b"abc".to_vec()), vec![0, 3, b'a', b'b', b'c']),
            (Frame::CancelPush(64), vec![3, 2, 0x40, 0x40]),
            (Frame::Goaway(4), vec![7, 1, 4]),
            (Frame::MaxPushId(63), vec![0x0d, 1, 63]),
            (Frame::Headers(vec![0, 0, 0xd9]), vec![1, 3, 0, 0, 0xd9]),
            (Frame::PushPromise { push_id: 0, field_section: vec![0, 0, 0xd1] }, vec![5, 4, 0, 0, 0, 0xd1]),
            (Frame::Unknown { frame_type: 0x21, payload: vec![0xaa] }, vec![0x21, 1, 0xaa]),
        ];
        for (frame, bytes) in examples {
            assert_eq!(frame.to_bytes().unwrap(), bytes);
            roundtrip(&frame);
        }
    }
    #[test]
    fn rfc9204_appendix_b1_section_exact_bytes() {
        // Appendix B.1's literal static-name reference is preserved by framing.
        let mut section = vec![0, 0, 0x51, 0x0b];
        section.extend_from_slice(b"/index.html");
        let mut expected = vec![1, 15];
        expected.extend_from_slice(&section);
        assert_eq!(Frame::Headers(section.clone()).to_bytes().unwrap(), expected);
        assert_eq!(
            qpack::decode_section(&plain_qpack(), 0, &section),
            Ok(qpack::SectionResult::Fields { fields: vec![qpack::Field::new(":path", "/index.html")], ack: None })
        );
        // Complete HTTP/3 response using static entry 25 (:status: 200).
        assert_eq!(
            response("200")
                .section(&mut qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE), 0, HeaderKind::Response)
                .unwrap()
                .to_bytes()
                .unwrap(),
            [0, 0, 0xd9]
        );
    }
    #[test]
    fn settings_exact_bytes_and_unknown_entries() {
        let s = Settings {
            entries: vec![
                Setting { id: 1, value: 4096 },
                Setting { id: 6, value: 1024 },
                Setting { id: 7, value: 16 },
                Setting { id: 8, value: 1 },
                Setting { id: 0x21, value: 42 },
                Setting { id: 0x99, value: 0 },
            ],
        };
        assert_eq!(s.to_bytes().unwrap(), [1, 0x50, 0, 6, 0x44, 0, 7, 16, 8, 1, 0x21, 42, 0x40, 0x99, 0]);
        assert_eq!(s.get(1), Some(4096));
        assert_eq!(s.get(9), None);
        roundtrip(&Frame::Settings(s));
        roundtrip(&settings());
    }
    #[test]
    fn rfc9218_priority_examples_exact_bytes() {
        for (bytes, expected) in [
            (b"u=0".as_slice(), Priority { urgency: Some(0), incremental: None }),
            (b"u=5, i".as_slice(), Priority { urgency: Some(5), incremental: Some(true) }),
            (b"u=1".as_slice(), Priority { urgency: Some(1), incremental: None }),
        ] {
            assert_eq!(Priority::parse(bytes), Ok(expected));
            assert_eq!(expected.to_bytes().unwrap(), bytes);
        }
        let frame = Frame::PriorityUpdate { element: PriorityElement::Request(0), value: b"u=0, i".to_vec() };
        assert_eq!(frame.to_bytes().unwrap(), [0x80, 0x0f, 7, 0, 7, 0, b'u', b'=', b'0', b',', b' ', b'i']);
        roundtrip(&frame);
        roundtrip(&Frame::PriorityUpdate { element: PriorityElement::Push(MAX_VARINT), value: vec![] });
    }
    #[test]
    fn all_varint_widths_and_nonminimal_forms() {
        for id in [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, MAX_VARINT] {
            roundtrip(&Frame::CancelPush(id));
            roundtrip(&Frame::MaxPushId(id));
            let header = StreamHeader::Push(id);
            let bytes = header.to_bytes().unwrap();
            assert_eq!(StreamHeader::parse(&bytes), Ok(header));
        }
        let wire = [0x40, 0, 0x80, 0, 0, 1, 0xff];
        assert_eq!(Frame::parse(&wire), Ok(Frame::Data(vec![0xff])));
        assert_eq!(Frame::parse(&[3, 2, 0x40, 0]), Ok(Frame::CancelPush(0)));
        assert_eq!(StreamHeader::parse(&[0x40, 0]), Ok(StreamHeader::Control));
    }
    #[test]
    fn reserved_sequences_and_http2_frame_types() {
        for n in 0..100 {
            assert!(is_reserved(0x21 + n * 0x1f));
        }
        for n in [0, 0x20, 0x22, MAX_VARINT + 1, u64::MAX] {
            assert!(!is_reserved(n));
        }
        for t in [2, 6, 8, 9] {
            assert_eq!(Frame::parse(&[t]), Err(Error::UnexpectedFrame(u64::from(t))));
            assert!(Frame::Unknown { frame_type: u64::from(t), payload: vec![] }.to_bytes().is_err());
        }
        for t in [0, 1, 3, 4, 5, 7, 0x0d, 0x0f0700, 0x0f0701] {
            assert!(Frame::Unknown { frame_type: t, payload: vec![] }.to_bytes().is_err());
        }
        for t in [0x21, 0x40, 0xff, MAX_VARINT] {
            roundtrip(&Frame::Unknown { frame_type: t, payload: vec![] });
        }
    }
    #[test]
    fn frame_payload_refusals() {
        for t in [3, 7, 0x0d] {
            for payload in [vec![], vec![0, 0], vec![0x40], vec![0; 9]] {
                let mut bytes = vec![t, payload.len() as u8];
                bytes.extend_from_slice(&payload);
                assert_eq!(Frame::parse(&bytes), Err(Error::Frame));
            }
        }
        for bytes in [vec![5, 0], vec![5, 1, 0x40], vec![0x80, 0x0f, 7, 0, 0]] {
            assert_eq!(Frame::parse(&bytes), Err(Error::Frame));
        }
        for id in [1, 2, 3, MAX_VARINT] {
            let mut b = vec![0x80, 0x0f, 7, 0];
            let mut payload = Vec::new();
            put_varint(id, &mut payload).unwrap();
            put_varint(payload.len() as u64, &mut b).unwrap();
            b.extend_from_slice(&payload);
            assert_eq!(Frame::parse(&b), Err(Error::Id));
            assert_eq!(
                Frame::PriorityUpdate { element: PriorityElement::Request(id), value: vec![] }.to_bytes(),
                Err(Error::Unwritable)
            );
        }
        for value in [vec![0], vec![b'\r'], vec![b'\n'], vec![0x80]] {
            assert_eq!(
                Frame::PriorityUpdate { element: PriorityElement::Push(0), value }.to_bytes(),
                Err(Error::Unwritable)
            );
        }
    }
    #[test]
    fn settings_duplicate_http2_and_value_refusals() {
        for id in [1, 6, 7, 8, 0x21, 0x99] {
            let s = Settings { entries: vec![Setting { id, value: 0 }, Setting { id, value: 0 }] };
            assert_eq!(s.to_bytes(), Err(Error::Unwritable));
            let mut b = Vec::new();
            for _ in 0..2 {
                put_varint(id, &mut b).unwrap();
                put_varint(0, &mut b).unwrap();
            }
            assert_eq!(Settings::parse(&b), Err(Error::DuplicateSetting(id)));
        }
        for id in 2..=5 {
            assert_eq!(Settings::parse(&[id, 0]), Err(Error::Http2Setting(u64::from(id))));
            assert_eq!(
                Settings { entries: vec![Setting { id: u64::from(id), value: 0 }] }.to_bytes(),
                Err(Error::Unwritable)
            );
        }
        assert_eq!(Settings::parse(&[8, 2]), Err(Error::SettingValue(8)));
        assert_eq!(Settings { entries: vec![Setting { id: 8, value: 2 }] }.to_bytes(), Err(Error::Unwritable));
        for bytes in [vec![1], vec![1, 0x40], vec![0x40]] {
            assert_eq!(Settings::parse(&bytes), Err(Error::Frame));
        }
        // Identifier 9 is not an HTTP/3-defined boolean setting.
        assert!(Settings::parse(&[9, 42]).is_ok());
    }
    #[test]
    fn writer_and_parser_resource_limits() {
        assert_eq!(Frame::Data(vec![0; MAX_FRAME_PAYLOAD + 1]).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Frame::Headers(vec![0; MAX_SECTION_BYTES + 1]).to_bytes(), Err(Error::Unwritable));
        assert_eq!(
            Frame::PushPromise { push_id: 0, field_section: vec![0; MAX_SECTION_BYTES + 1] }.to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(
            Frame::PriorityUpdate { element: PriorityElement::Push(0), value: vec![b'a'; MAX_PRIORITY_BYTES + 1] }
                .to_bytes(),
            Err(Error::Unwritable)
        );
        for t in [0, 1, 4, 5, 0x0f0700] {
            let mut bytes = Vec::new();
            put_varint(t, &mut bytes).unwrap();
            put_varint(MAX_FRAME_PAYLOAD as u64 + 1, &mut bytes).unwrap();
            assert_eq!(Frame::parse(&bytes), Err(Error::Limit));
        }
        let s = Settings { entries: (0..=MAX_SETTINGS).map(|n| Setting { id: 100 + n as u64, value: 0 }).collect() };
        assert_eq!(s.to_bytes(), Err(Error::Unwritable));
        let mut b = Vec::new();
        for entry in &s.entries {
            put_varint(entry.id, &mut b).unwrap();
            put_varint(0, &mut b).unwrap();
        }
        assert_eq!(Settings::parse(&b), Err(Error::Limit));
        for f in [
            Frame::Goaway(u64::MAX),
            Frame::CancelPush(MAX_VARINT + 1),
            Frame::MaxPushId(MAX_VARINT + 1),
            Frame::Unknown { frame_type: u64::MAX, payload: vec![] },
        ] {
            assert_eq!(f.to_bytes(), Err(Error::Unwritable));
        }
        roundtrip(&Frame::Data(vec![7; MAX_FRAME_PAYLOAD]));
        roundtrip(&Frame::Headers(vec![0; MAX_SECTION_BYTES]));
    }
    #[test]
    fn frame_allocation_and_prefix_contracts() {
        for frame in [
            settings(),
            Frame::Data(vec![42; 257]),
            headers(&request()),
            Frame::CancelPush(MAX_VARINT),
            Frame::Unknown { frame_type: MAX_VARINT, payload: vec![1, 2] },
        ] {
            let bytes = frame.to_bytes().unwrap();
            contract::check_wire_value(&frame);
            contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_FRAME);
            assert_eq!(decode_all(Frames::<Frame>::new, &bytes), (vec![Ok(frame)], None));
        }
    }
    #[test]
    fn stream_header_contract_and_handoff() {
        for header in [
            StreamHeader::Control,
            StreamHeader::Push(MAX_VARINT),
            StreamHeader::QpackEncoder,
            StreamHeader::QpackDecoder,
            StreamHeader::Unknown(MAX_VARINT),
            StreamHeader::Unknown(0x21),
        ] {
            let mut bytes = header.to_bytes().unwrap();
            contract::check_wire_value(&header);
            bytes.extend_from_slice(b"body");
            contract::check_decode_with_alloc_limit(StreamHeaders::new, &bytes, 2 * MAX_STREAM_HEADER);
            let mut stream = Stream::new(StreamHeaders::new());
            assert_eq!(stream.push(&bytes), bytes.len());
            assert_eq!(stream.next(), Some(Ok(header)));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.unread(), b"body");
        }
        for header in [
            StreamHeader::Unknown(0),
            StreamHeader::Unknown(1),
            StreamHeader::Unknown(2),
            StreamHeader::Unknown(3),
            StreamHeader::Unknown(u64::MAX),
            StreamHeader::Push(u64::MAX),
        ] {
            assert_eq!(header.to_bytes(), Err(Error::Unwritable));
        }
    }
    #[test]
    fn frame_stream_compaction_and_backpressure_contract() {
        let big = Frame::Data(vec![0xab; MAX_FRAME_PAYLOAD]);
        let frames = [Frame::Data(vec![]), big.clone(), big];
        let bytes = join(&frames);
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_FRAME);
        assert_eq!(decode_all(Frames::<Frame>::new, &bytes), (frames.into_iter().map(Ok).collect(), None));
    }
    #[test]
    fn framing_errors_are_terminal_and_fin_checks_truncation() {
        let mut stream = Stream::new(Frames::<Frame>::new());
        assert_eq!(stream.push(&[2, 0]), 2);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::UnexpectedFrame(2)))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(&[0, 0]), 2);
        for bytes in [vec![0x40], vec![0], vec![0, 1]] {
            let (_, error) = decode_all(Frames::<Frame>::new, &bytes);
            assert!(matches!(error, Some(Fail::Truncated { .. })));
        }
    }
    #[test]
    fn control_requires_first_and_unique_settings() {
        for frame in [Frame::Data(vec![]), Frame::Goaway(0), Frame::Unknown { frame_type: 0x21, payload: vec![] }] {
            assert_eq!(control(Endpoint::Client, &[frame]), Err(Error::MissingSettings));
        }
        assert_eq!(control(Endpoint::Client, &[settings(), settings()]), Err(Error::UnexpectedFrame(4)));
        for frame in
            [Frame::Data(vec![]), Frame::Headers(vec![]), Frame::PushPromise { push_id: 0, field_section: vec![] }]
        {
            let t = frame.frame_type();
            assert_eq!(control(Endpoint::Client, &[settings(), frame]), Err(Error::UnexpectedFrame(t)));
        }
        for sender in [Endpoint::Client, Endpoint::Server] {
            let mut stream = Stream::new(ControlFrames::new(sender));
            stream.end();
            assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::ClosedCriticalStream))));
            assert_eq!(stream.push(&[4, 0]), 2);
            assert_eq!(stream.next(), None);
        }
    }
    #[test]
    fn control_sender_and_id_rules() {
        for frame in [
            Frame::MaxPushId(0),
            Frame::PriorityUpdate { element: PriorityElement::Request(0), value: vec![] },
            Frame::PriorityUpdate { element: PriorityElement::Push(0), value: vec![] },
        ] {
            assert_eq!(
                control(Endpoint::Server, &[settings(), frame.clone()]),
                Err(Error::UnexpectedFrame(frame.frame_type()))
            );
            assert_eq!(control(Endpoint::Client, &[settings(), frame]), Ok(()));
        }
        assert_eq!(control(Endpoint::Client, &[settings(), Frame::MaxPushId(2), Frame::MaxPushId(1)]), Err(Error::Id));
        assert_eq!(
            control(Endpoint::Client, &[settings(), Frame::MaxPushId(2), Frame::MaxPushId(2), Frame::MaxPushId(3)]),
            Ok(())
        );
        for sender in [Endpoint::Client, Endpoint::Server] {
            assert_eq!(control(sender, &[settings(), Frame::Goaway(8), Frame::Goaway(4), Frame::Goaway(4)]), Ok(()));
            assert_eq!(control(sender, &[settings(), Frame::Goaway(4), Frame::Goaway(8)]), Err(Error::Id));
            assert_eq!(control(sender, &[settings(), Frame::CancelPush(0)]), Ok(()));
        }
        assert_eq!(control(Endpoint::Server, &[settings(), Frame::Goaway(1)]), Err(Error::Id));
        assert_eq!(control(Endpoint::Client, &[settings(), Frame::Goaway(1)]), Ok(()));
    }
    #[test]
    fn control_stream_contract() {
        let frames = [
            settings(),
            Frame::MaxPushId(400),
            Frame::Goaway(23),
            Frame::Unknown { frame_type: 0x21, payload: vec![0; 20] },
        ];
        let bytes = join(&frames);
        contract::check_decode_with_alloc_limit(|| ControlFrames::new(Endpoint::Client), &bytes, 2 * MAX_FRAME);
        let (items, error) = decode_all(|| ControlFrames::new(Endpoint::Client), &bytes);
        assert_eq!(items, frames.into_iter().map(Ok).collect::<Vec<_>>());
        assert_eq!(error, Some(Fail::Protocol(Error::ClosedCriticalStream)));
    }
    #[test]
    fn requests_responses_and_trailers_roundtrip_qpack() {
        for (list, kind) in [
            (request(), HeaderKind::Request { extended_connect: false }),
            (response("200"), HeaderKind::Response),
            (fields(&[("digest", "sha-256=abc")]), HeaderKind::Trailers),
        ] {
            let bytes =
                list.section(&mut qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE), 0, kind).unwrap().to_bytes().unwrap();
            assert_eq!(received(&plain_qpack(), 0, &bytes, kind), Ok(list));
        }
        let trailer = fields(&[("x-check", "ok")]);
        let (events, result) =
            messages(MessageSide::Request, &[headers(&request()), Frame::Data(vec![1, 2]), headers(&trailer)]);
        assert_eq!(result, Ok(()));
        assert_eq!(events, [Event::Headers(request()), Event::Data(vec![1, 2]), Event::Trailers(trailer)]);
    }
    #[test]
    fn request_frame_contract_and_message_sequence() {
        let frames = [headers(&request()), Frame::Data(vec![1; 80]), headers(&fields(&[("x-check", "ok")]))];
        let bytes = join(&frames);
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_FRAME);
        let (events, result) = messages(MessageSide::Request, &frames);
        assert_eq!(
            events,
            [Event::Headers(request()), Event::Data(vec![1; 80]), Event::Trailers(fields(&[("x-check", "ok")]))]
        );
        assert_eq!(result, Ok(()));
    }
    #[test]
    fn request_stream_frame_placement() {
        for side in [MessageSide::Request, MessageSide::Response] {
            for frame in [
                settings(),
                Frame::CancelPush(0),
                Frame::Goaway(0),
                Frame::MaxPushId(0),
                Frame::PriorityUpdate { element: PriorityElement::Request(0), value: vec![] },
            ] {
                assert_eq!(messages(side, std::slice::from_ref(&frame)).1, Err(Error::UnexpectedFrame(frame.frame_type())));
            }
            assert_eq!(messages(side, &[Frame::Data(vec![])]).1, Err(Error::UnexpectedFrame(0)));
        }
        assert_eq!(
            messages(MessageSide::Request, &[Frame::PushPromise { push_id: 0, field_section: encoded(&request()) }]).1,
            Err(Error::UnexpectedFrame(5))
        );
        for id in [1, 2, 3, u64::MAX] {
            assert!(RequestStream::new(id, MessageSide::Request, false).is_err());
        }
        for id in [0, 1, 2, u64::MAX] {
            assert!(RequestStream::push(id).is_err());
        }
    }
    #[test]
    fn informational_response_and_trailer_ordering() {
        let trailer = fields(&[("x", "y")]);
        let frames = [
            headers(&response("100")),
            headers(&response("103")),
            headers(&response("200")),
            Frame::Data(vec![42]),
            headers(&trailer),
        ];
        let (events, result) = messages(MessageSide::Response, &frames);
        assert_eq!(result, Ok(()));
        assert!(matches!(events.first(), Some(Event::Informational(_))));
        assert_eq!(events.len(), 5);
        assert_eq!(
            messages(MessageSide::Response, &[headers(&response("103")), Frame::Data(vec![])]).1,
            Err(Error::UnexpectedFrame(0))
        );
        assert_eq!(messages(MessageSide::Response, &[headers(&response("103"))]).1, Err(Error::Incomplete));
        assert!(matches!(
            messages(MessageSide::Response, &[headers(&response("200")), headers(&response("201"))]).1,
            Err(Error::Message(_))
        ));
        for last in [headers(&trailer), Frame::Data(vec![])] {
            assert_eq!(
                messages(MessageSide::Request, &[headers(&request()), headers(&trailer), last.clone()]).1,
                Err(Error::UnexpectedFrame(last.frame_type()))
            );
        }
        assert!(matches!(
            messages(MessageSide::Request, &[headers(&request()), headers(&request())]).1,
            Err(Error::Message(_))
        ));
    }
    #[test]
    fn unknowns_and_promises_do_not_change_message_state() {
        let unknown = Frame::Unknown { frame_type: 0x21, payload: vec![42] };
        let promise = Frame::PushPromise { push_id: 7, field_section: encoded(&request()) };
        let trailer = headers(&fields(&[]));
        let frames = [
            unknown.clone(),
            promise.clone(),
            headers(&response("103")),
            promise.clone(),
            headers(&response("200")),
            unknown.clone(),
            trailer,
            promise.clone(),
            unknown,
        ];
        let (events, result) = messages(MessageSide::Response, &frames);
        assert_eq!(result, Ok(()));
        assert_eq!(events.len(), frames.len());
        let mut state = RequestStream::push(3).unwrap();
        assert_eq!(event(&mut state, promise, &plain_qpack()), Err(Error::UnexpectedFrame(5)));
        let mut state = RequestStream::push(3).unwrap();
        assert!(matches!(event(&mut state, headers(&response("103")), &plain_qpack()), Ok(Event::Informational(_))));
        assert!(matches!(event(&mut state, headers(&response("200")), &plain_qpack()), Ok(Event::Headers(_))));
        assert_eq!(state.finish(), Ok(()));
    }
    #[test]
    fn pseudo_header_presence_placement_and_uniqueness() {
        let kind = HeaderKind::Request { extended_connect: false };
        for index in [0, 1, 2, 3] {
            let mut h = request();
            h.fields.remove(index);
            assert!(h.validate(kind).is_err());
        }
        for name in [":method", ":scheme", ":authority", ":path"] {
            let mut h = request();
            let f = h.fields.iter().find(|f| f.name == name.as_bytes()).unwrap().clone();
            h.fields.push(f);
            assert!(h.validate(kind).is_err());
        }
        for pseudo in [":unknown", ":status"] {
            let mut h = request();
            h.fields.push(qpack::Field::new(pseudo, "200"));
            assert!(h.validate(kind).is_err());
        }
        let mut h = request();
        h.fields.insert(0, qpack::Field::new("x", "y"));
        assert!(h.validate(kind).is_err());
        let mut h = response("200");
        h.fields.push(qpack::Field::new(":status", "200"));
        assert!(h.validate(HeaderKind::Response).is_err());
        for name in [":method", ":scheme", ":authority", ":path", ":protocol"] {
            assert!(fields(&[(name, "x"), (":status", "200")]).validate(HeaderKind::Response).is_err());
        }
        assert!(fields(&[]).validate(HeaderKind::Response).is_err());
        assert!(request().validate(HeaderKind::Trailers).is_err());
    }
    #[test]
    fn invalid_field_names_values_and_hop_fields() {
        for name in ["", "Upper", "x y", "x:y", "x\r", "x\0", "é"] {
            assert!(fields(&[(name, "v")]).validate(HeaderKind::Trailers).is_err());
        }
        for value in ["a\0b", "a\rb", "a\nb", "a\u{7f}b", " leading", "trailing ", "\t", "a\u{01}b"] {
            assert!(fields(&[("x", value)]).validate(HeaderKind::Trailers).is_err());
        }
        assert!(fields(&[("x", "a\tb"), ("x", ""), ("x", "é")]).validate(HeaderKind::Trailers).is_ok());
        for name in ["connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"] {
            let mut h = request();
            h.fields.push(qpack::Field::new(name, "x"));
            assert!(h.validate(HeaderKind::Request { extended_connect: false }).is_err());
        }
        let mut h = request();
        h.fields.push(qpack::Field::new("te", "Trailers"));
        assert!(h.validate(HeaderKind::Request { extended_connect: false }).is_ok());
        for value in ["gzip", "trailers, gzip", ""] {
            let mut h = request();
            h.fields.push(qpack::Field::new("te", value));
            assert!(h.validate(HeaderKind::Request { extended_connect: false }).is_err());
        }
        let mut h = response("200");
        h.fields.push(qpack::Field::new("te", "trailers"));
        assert!(h.validate(HeaderKind::Response).is_err());
        for name in ["te", "host", "content-length", "trailer"] {
            assert!(fields(&[(name, "trailers")]).validate(HeaderKind::Trailers).is_err());
        }
    }
    #[test]
    fn method_scheme_authority_path_and_status_values() {
        let kind = HeaderKind::Request { extended_connect: false };
        for (name, value) in [
            (":method", ""),
            (":method", "GE T"),
            (":scheme", ""),
            (":scheme", "1http"),
            (":scheme", "http:"),
            (":authority", ""),
            (":authority", "a@b"),
            (":authority", "a/b"),
            (":path", ""),
            (":path", "relative"),
            (":path", "*"),
            (":path", "/a#b"),
            (":path", "/a%zz"),
        ] {
            let mut h = request();
            h.fields.iter_mut().find(|f| f.name == name.as_bytes()).unwrap().value = value.as_bytes().to_vec();
            assert!(h.validate(kind).is_err(), "{name}={value}");
        }
        let mut h = request();
        h.fields.retain(|f| f.name != b":authority");
        h.fields.push(qpack::Field::new("host", "example.net"));
        assert!(h.validate(kind).is_ok());
        let mut h = request();
        h.fields.push(qpack::Field::new("host", "example.net"));
        assert!(h.validate(kind).is_ok());
        h.fields.push(qpack::Field::new("host", "example.net"));
        assert!(h.validate(kind).is_err());
        let mut h = request();
        h.fields.push(qpack::Field::new("host", "different.net"));
        assert!(h.validate(kind).is_err());
        assert!(
            fields(&[(":method", "OPTIONS"), (":scheme", "https"), (":authority", "example.net"), (":path", "*")])
                .validate(kind)
                .is_ok()
        );
        assert!(fields(&[(":method", "GET"), (":scheme", "custom"), (":path", "")]).validate(kind).is_ok());
        for status in ["", "99", "099", "101", "600", "999", "2000", "2a0", "+20"] {
            assert!(response(status).validate(HeaderKind::Response).is_err());
        }
        for status in ["100", "103", "200", "304", "599"] {
            assert!(response(status).validate(HeaderKind::Response).is_ok());
        }
    }
    #[test]
    fn classic_and_extended_connect_rules() {
        let classic = fields(&[(":method", "CONNECT"), (":authority", "example.net:443")]);
        for enabled in [false, true] {
            assert!(classic.validate(HeaderKind::Request { extended_connect: enabled }).is_ok());
        }
        for auth in [
            "example.net",
            ":443",
            "example.net:",
            "example.net:abc",
            "example.net:65536",
            "a@b:443",
            "[bad]:443",
            "::1:443",
        ] {
            assert!(
                fields(&[(":method", "CONNECT"), (":authority", auth)])
                    .validate(HeaderKind::Request { extended_connect: false })
                    .is_err()
            );
        }
        assert!(
            fields(&[(":method", "CONNECT"), (":authority", "[::1]:443")])
                .validate(HeaderKind::Request { extended_connect: false })
                .is_ok()
        );
        for name in [":scheme", ":path"] {
            let mut h = classic.clone();
            h.fields.push(qpack::Field::new(name, "x"));
            assert!(h.validate(HeaderKind::Request { extended_connect: true }).is_err());
        }
        let extended = fields(&[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "example.net"),
            (":path", "/chat"),
            (":protocol", "websocket"),
        ]);
        assert!(extended.validate(HeaderKind::Request { extended_connect: true }).is_ok());
        assert!(extended.validate(HeaderKind::Request { extended_connect: false }).is_err());
        for name in [":scheme", ":authority", ":path"] {
            let mut h = extended.clone();
            h.fields.retain(|f| f.name != name.as_bytes());
            assert!(h.validate(HeaderKind::Request { extended_connect: true }).is_err());
        }
        for method in ["GET", "connect"] {
            let mut h = extended.clone();
            h.fields.get_mut(0).unwrap().value = method.as_bytes().to_vec();
            assert!(h.validate(HeaderKind::Request { extended_connect: true }).is_err());
        }
        for protocol in ["", "web socket"] {
            let mut h = extended.clone();
            h.fields.last_mut().unwrap().value = protocol.as_bytes().to_vec();
            assert!(h.validate(HeaderKind::Request { extended_connect: true }).is_err());
        }
        let mut d = RequestStream::new(0, MessageSide::Request, true).unwrap();
        assert_eq!(event(&mut d, headers(&extended), &plain_qpack()), Ok(Event::Headers(extended)));
        assert_eq!(d.finish(), Ok(()));
    }
    #[test]
    fn authority_uri_literals_ports_and_escapes() {
        let kind = HeaderKind::Request { extended_connect: false };
        for auth in ["example.net:", "example%2enet", "[::1]", "[v1.a-b]", "[Vf.test:1]:443"] {
            let h = fields(&[(":method", "GET"), (":scheme", "https"), (":authority", auth), (":path", "/")]);
            assert!(h.validate(kind).is_ok(), "{auth}");
        }
        for auth in ["example%", "example%zz", "[v.a]", "[v1.]", "[v1.%41]", "[::1]junk", "host:80:90"] {
            let h = fields(&[(":method", "GET"), (":scheme", "https"), (":authority", auth), (":path", "/")]);
            assert!(h.validate(kind).is_err(), "{auth}");
        }
    }
    #[test]
    fn content_length_and_bodyless_contexts() {
        let mut h = request();
        h.fields.push(qpack::Field::new("content-length", "2"));
        assert_eq!(messages(MessageSide::Request, &[headers(&h), Frame::Data(vec![1, 2])]).1, Ok(()));
        assert!(matches!(
            messages(MessageSide::Request, &[headers(&h), Frame::Data(vec![1])]).1,
            Err(Error::Message(_))
        ));
        assert!(matches!(
            messages(MessageSide::Request, &[headers(&h), Frame::Data(vec![1, 2, 3])]).1,
            Err(Error::Message(_))
        ));
        h.fields.push(qpack::Field::new("content-length", "2, 2"));
        // Writers refuse the list form; readers accept it and rewrite it.
        assert!(h.validate(HeaderKind::Request { extended_connect: false }).is_err());
        assert_eq!(messages(MessageSide::Request, &[headers(&h), Frame::Data(vec![1, 2])]).1, Ok(()));
        h.fields.push(qpack::Field::new("content-length", "3"));
        assert!(matches!(messages(MessageSide::Request, &[headers(&h)]).1, Err(Error::Message(_))));
        for value in ["-1", "+1", "", "1,", "1,2", "18446744073709551616"] {
            let mut h = request();
            h.fields.push(qpack::Field::new("content-length", value));
            assert!(h.validate(HeaderKind::Request { extended_connect: false }).is_err());
        }
        for status in ["103", "204"] {
            let mut h = response(status);
            h.fields.push(qpack::Field::new("content-length", "0"));
            assert!(h.validate(HeaderKind::Response).is_err());
        }
        for (side, status) in [(MessageSide::HeadResponse, "200"), (MessageSide::Response, "304")] {
            let mut h = response(status);
            h.fields.push(qpack::Field::new("content-length", "99"));
            assert_eq!(messages(side, &[headers(&h)]).1, Ok(()));
            assert!(matches!(messages(side, &[headers(&h), Frame::Data(vec![1])]).1, Err(Error::Message(_))));
        }
        assert_eq!(
            messages(MessageSide::ConnectResponse, &[headers(&response("200")), Frame::Data(vec![0; 50])]).1,
            Ok(())
        );
        // RFC 9110 section 9.3.6: the client ignores this Content-Length.
        let mut h = response("200");
        h.fields.push(qpack::Field::new("content-length", "0"));
        assert_eq!(messages(MessageSide::ConnectResponse, &[headers(&h), Frame::Data(vec![1])]).1, Ok(()));
    }
    #[test]
    fn header_limits_and_never_index_roundtrip() {
        let mut h = request();
        h.fields.push(qpack::Field::new("x", "secret"));
        h.fields.last_mut().unwrap().never_index = true;
        let kind = HeaderKind::Request { extended_connect: false };
        let bytes =
            h.section(&mut qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE), 0, kind).unwrap().to_bytes().unwrap();
        assert_eq!(received(&plain_qpack(), 0, &bytes, kind), Ok(h));
        let too_many = HeaderList { fields: vec![qpack::Field::new("x", ""); MAX_FIELDS + 1] };
        assert_eq!(too_many.validate(HeaderKind::Trailers), Err(Error::Limit));
        let large = HeaderList {
            fields: vec![qpack::Field {
                name: b"x".to_vec(),
                value: vec![b'x'; MAX_FIELD_BYTES + 1],
                never_index: false,
            }],
        };
        assert_eq!(large.validate(HeaderKind::Trailers), Err(Error::Limit));
        let large = HeaderList { fields: vec![qpack::Field::new("x", vec![b'a'; MAX_FIELD_BYTES]); 4] };
        assert_eq!(large.validate(HeaderKind::Trailers), Err(Error::Limit));
        assert_eq!(
            request().section(&mut qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE), u64::MAX, kind),
            Err(Error::Id)
        );
        assert_eq!(received(&plain_qpack(), u64::MAX, &[], kind), Err(Error::Qpack(qpack::Error::IntegerOverflow)));
    }
    #[test]
    fn qpack_dynamic_blocking_resume_and_stream_routing() {
        let mut encoder = qpack::Encoder::new(4096, MAX_FIELD_SECTION_SIZE);
        let capacity = encoder.set_capacity(4096).unwrap();
        let insert = encoder.insert(b"x-test", b"value").unwrap().1;
        encoder.apply_instruction(qpack::DecoderInstruction::InsertCountIncrement(1)).unwrap();
        let mut headers = request();
        headers.fields.push(qpack::Field::new("x-test", "value"));
        let section = headers.section(&mut encoder, 0, HeaderKind::Request { extended_connect: false }).unwrap();
        let wire = join(&[Frame::headers(&section).unwrap(), Frame::Data(vec![42])]);
        let mut table = qpack::Table::new(4096);
        let mut state = RequestStream::new(0, MessageSide::Request, false).unwrap();
        let mut session = Session::new(Endpoint::Client, 4, MAX_FRAME);
        assert_eq!(session.push(0, &wire), wire.len());
        let (_, Ok(Ok(StreamItem::Frame(frame)))) = session.next().unwrap() else { panic!() };
        let RequestResult::Blocked(blocked) = state.step(&frame, &table).unwrap() else { panic!() };
        session.pause(0);
        assert_eq!(session.push(0, &[0]), 0);
        assert_eq!(session.next(), None);
        assert_eq!(state.finish(), Err(Error::State));
        assert_eq!(state.resume(4, blocked.clone().retry(&table)), Err(Error::State));
        assert!(state.is_blocked());
        table.apply(capacity).unwrap();
        table.apply(insert).unwrap();
        let RequestResult::Event { event: result, ack } = state.resume(0, blocked.retry(&table)).unwrap() else {
            panic!()
        };
        assert_eq!(result, Ok(Event::Headers(headers)));
        encoder.apply_instruction(ack.unwrap()).unwrap();
        session.unpause(0);
        let (_, Ok(Ok(StreamItem::Frame(frame)))) = session.next().unwrap() else { panic!() };
        assert_eq!(event(&mut state, frame, &table), Ok(Event::Data(vec![42])));
        assert_eq!(state.finish(), Ok(()));
    }
    #[test]
    fn blocked_informational_trailers_and_promises() {
        for pending in 0..3 {
            let mut encoder = qpack::Encoder::new(4096, MAX_FIELD_SECTION_SIZE);
            let capacity = encoder.set_capacity(4096).unwrap();
            let insert = encoder.insert(b"x", b"y").unwrap().1;
            encoder.apply_instruction(qpack::DecoderInstruction::InsertCountIncrement(1)).unwrap();
            let mut table = qpack::Table::new(4096);
            let mut state = RequestStream::new(0, MessageSide::Response, false).unwrap();
            let mut list = match pending {
                0 => response("103"),
                1 => fields(&[]),
                _ => request(),
            };
            list.fields.push(qpack::Field::new("x", "y"));
            if pending == 1 {
                event(&mut state, headers(&response("200")), &table).unwrap();
            }
            let block = encoder.section(0, &list.fields).unwrap().to_bytes().unwrap();
            let frame = if pending == 2 {
                Frame::PushPromise { push_id: 1, field_section: block }
            } else {
                Frame::Headers(block)
            };
            let RequestResult::Blocked(blocked) = state.step(&frame, &table).unwrap() else { panic!() };
            table.apply(capacity).unwrap();
            table.apply(insert).unwrap();
            let RequestResult::Event { event, ack } = state.resume(0, blocked.retry(&table)).unwrap() else { panic!() };
            assert_eq!(
                event,
                Ok(match pending {
                    0 => Event::Informational(list),
                    1 => Event::Trailers(list),
                    _ => Event::PushPromise { push_id: 1, headers: list },
                })
            );
            encoder.apply_instruction(ack.unwrap()).unwrap();
        }
    }
    #[test]
    fn qpack_errors_and_blocked_validation_are_not_suppressed() {
        let mut state = RequestStream::new(0, MessageSide::Request, false).unwrap();
        assert_eq!(
            event(&mut state, Frame::Headers(vec![]), &plain_qpack()),
            Err(Error::Qpack(qpack::Error::Truncated))
        );
        assert_eq!(state.step(&Frame::Data(vec![]), &plain_qpack()), Err(Error::State));
        let mut state = RequestStream::new(0, MessageSide::Request, false).unwrap();
        state.pending = Some(PendingSection::Headers);
        let result =
            state.resume(0, Ok(qpack::SectionResult::Fields { fields: response("200").fields, ack: None })).unwrap();
        assert!(matches!(result, RequestResult::Event { event: Err(Error::Message(_)), .. }));
        let mut state = RequestStream::new(0, MessageSide::Request, false).unwrap();
        state.pending = Some(PendingSection::Headers);
        assert_eq!(state.resume(0, Err(qpack::Error::Huffman)), Err(Error::Qpack(qpack::Error::Huffman)));
    }

    #[test]
    fn response_and_push_message_sequences() {
        let frames = [
            headers(&response("103")),
            headers(&response("200")),
            Frame::Data(vec![42; 100]),
            headers(&fields(&[("x", "end")])),
        ];
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &join(&frames), 2 * MAX_FRAME);
        for push in [false, true] {
            let mut state = if push {
                RequestStream::push(3).unwrap()
            } else {
                RequestStream::new(0, MessageSide::Response, false).unwrap()
            };
            let events: Vec<_> =
                frames.iter().cloned().map(|frame| event(&mut state, frame, &plain_qpack()).unwrap()).collect();
            assert_eq!(
                events,
                [
                    Event::Informational(response("103")),
                    Event::Headers(response("200")),
                    Event::Data(vec![42; 100]),
                    Event::Trailers(fields(&[("x", "end")]))
                ]
            );
            assert_eq!(state.finish(), Ok(()));
        }
    }
    #[test]
    fn push_stream_refuses_push_promise() {
        let table = plain_qpack();
        let promise = Frame::PushPromise { push_id: 7, field_section: encoded(&request()) };
        for started in [false, true] {
            let mut state = RequestStream::push(3).unwrap();
            if started {
                assert_eq!(event(&mut state, headers(&response("200")), &table), Ok(Event::Headers(response("200"))));
            }
            assert_eq!(
                event(&mut state, promise.clone(), &table),
                Err(Error::UnexpectedFrame(frame_type::PUSH_PROMISE))
            );
        }
    }
    #[test]
    fn request_fin_refuses_partial_frames_and_missing_headers() {
        for bytes in [vec![], vec![0x21, 0]] {
            let (items, error) = decode_all(Frames::<Frame>::new, &bytes);
            assert!(error.is_none());
            let mut state = RequestStream::new(0, MessageSide::Request, false).unwrap();
            for frame in items {
                event(&mut state, frame.unwrap(), &plain_qpack()).unwrap();
            }
            assert_eq!(state.finish(), Err(Error::Incomplete));
        }
        for suffix in [vec![0], vec![0, 2, 1], vec![0x40]] {
            let mut bytes = headers(&request()).to_bytes().unwrap();
            bytes.extend(suffix);
            let (items, error) = decode_all(Frames::<Frame>::new, &bytes);
            assert_eq!(items.len(), 1);
            assert!(matches!(error, Some(Fail::Truncated { .. })));
        }
    }
    #[test]
    fn priority_unknown_types_parameters_and_duplicates() {
        for value in [b"".as_slice(), b"u=9, i=7", b"u=-1, i=token", b"u=3.0, i=\"yes\"", b"u=(1 2), i=:YQ==:"] {
            assert_eq!(Priority::parse(value), Ok(Priority::default()));
        }
        assert_eq!(Priority::parse(b"u=1, u=5, i=?0, i"), Ok(Priority { urgency: Some(5), incremental: Some(true) }));
        assert_eq!(Priority::parse(b"u=1, u=unknown, i, i=42"), Ok(Priority::default()));
        let value = b"u=2;a=token;b=\"escaped\\\"\", other=(1;p=?0 \"x,y\" :YWI=:);v=1.2, i;z=?1";
        assert_eq!(Priority::parse(value), Ok(Priority { urgency: Some(2), incremental: Some(true) }));
        assert_eq!(Priority::default().effective_urgency(), 3);
        assert!(!Priority::default().effective_incremental());
        assert_eq!(Priority::parse(b"u=-0, i=?0"), Ok(Priority { urgency: Some(0), incremental: Some(false) }));
        for u in 0..=7 {
            for i in [None, Some(false), Some(true)] {
                let p = Priority { urgency: Some(u), incremental: i };
                assert_eq!(Priority::parse(&p.to_bytes().unwrap()), Ok(p));
            }
        }
    }
    #[test]
    fn priority_malformed_and_limit_refusals() {
        for value in [
            "u=",
            "u=1,",
            ",u=1",
            "u =1",
            "U=1",
            "u=+1",
            "i=?2",
            "i=?10",
            "u=1.0000",
            "u=1234567890123456",
            "u=1234567890123.1",
            "u=1.",
            "u=\"unterminated",
            "u=\"bad\\q\"",
            "x=((1))",
            "x=(1\t2)",
            "x=(1,2)",
            "x=:a:",
            "x=:====:",
            "x=:a===:",
            "x=\"a\nb\"",
            "x=é",
            "x=@1",
            "x;=1",
        ] {
            assert_eq!(Priority::parse(value.as_bytes()), Err(Error::Priority), "{value:?}");
        }
        assert_eq!(Priority { urgency: Some(8), incremental: None }.to_bytes(), Err(Error::Unwritable));
        assert_eq!(Priority::parse(&vec![b' '; MAX_PRIORITY_BYTES + 1]), Err(Error::Limit));
        assert_eq!(
            Priority::parse("x,".repeat(MAX_PRIORITY_MEMBERS + 1).trim_end_matches(',').as_bytes()),
            Err(Error::Limit)
        );
        let value = format!("x=({})", "1 ".repeat(MAX_PRIORITY_ITEMS + 1));
        assert_eq!(Priority::parse(value.as_bytes()), Err(Error::Limit));
        let value = format!("x{}", ";a".repeat(MAX_PRIORITY_MEMBERS));
        assert_eq!(Priority::parse(value.as_bytes()), Err(Error::Limit));
    }
    #[test]
    fn priority_field_lines_are_combined_in_order() {
        let h = fields(&[("priority", "u=5"), ("x", "y"), ("priority", "i, u=1")]);
        assert_eq!(h.priority(), Ok(Priority { urgency: Some(1), incremental: Some(true) }));
        assert_eq!(request().priority(), Ok(Priority::default()));
        let h = fields(&[("priority", "u=5,"), ("priority", "i")]);
        assert_eq!(h.priority(), Err(Error::Priority));
    }
    #[test]
    fn structured_fields_whitespace_and_base64_padding() {
        for value in ["\tu=1", " \tu=1", "\t"] {
            assert_eq!(Priority::parse(value.as_bytes()), Err(Error::Priority));
        }
        assert_eq!(Priority::parse(b"  u=1\t,\ti\t"), Ok(Priority { urgency: Some(1), incremental: Some(true) }));
        for binary in ["", "YQ", "YQ=", "YQ==", "YWI", "YWI=", "YWJj", "YR=="] {
            let value = format!("x=:{binary}:, u=2");
            assert_eq!(Priority::parse(value.as_bytes()), Ok(Priority { urgency: Some(2), incremental: None }));
        }
        for binary in ["Y", "Y=", "=", "YWI==", "YWJj=", "Y Q==", "YQ\n=="] {
            assert_eq!(Priority::parse(format!("x=:{binary}:").as_bytes()), Err(Error::Priority));
        }
    }
    #[test]
    fn all_error_codes_and_error_mappings() {
        let codes = [
            error_code::NO_ERROR,
            error_code::GENERAL_PROTOCOL_ERROR,
            error_code::INTERNAL_ERROR,
            error_code::STREAM_CREATION_ERROR,
            error_code::CLOSED_CRITICAL_STREAM,
            error_code::FRAME_UNEXPECTED,
            error_code::FRAME_ERROR,
            error_code::EXCESSIVE_LOAD,
            error_code::ID_ERROR,
            error_code::SETTINGS_ERROR,
            error_code::MISSING_SETTINGS,
            error_code::REQUEST_REJECTED,
            error_code::REQUEST_CANCELLED,
            error_code::REQUEST_INCOMPLETE,
            error_code::MESSAGE_ERROR,
            error_code::CONNECT_ERROR,
            error_code::VERSION_FALLBACK,
        ];
        for (i, code) in codes.iter().enumerate() {
            assert_eq!(*code, 0x100 + i as u64);
        }
        assert_eq!(error_code::QPACK_DECOMPRESSION_FAILED, qpack::error_code::DECOMPRESSION_FAILED);
        assert_eq!(error_code::QPACK_ENCODER_STREAM_ERROR, qpack::error_code::ENCODER_STREAM_ERROR);
        assert_eq!(error_code::QPACK_DECODER_STREAM_ERROR, qpack::error_code::DECODER_STREAM_ERROR);
        for (error, code) in [
            (Error::Limit, 0x107),
            (Error::Frame, 0x106),
            (Error::UnexpectedFrame(4), 0x105),
            (Error::DuplicateSetting(1), 0x109),
            (Error::Http2Setting(2), 0x109),
            (Error::SettingValue(8), 0x109),
            (Error::MissingSettings, 0x10a),
            (Error::Id, 0x108),
            (Error::ClosedCriticalStream, 0x104),
            (Error::Message("bad"), 0x10e),
            (Error::Incomplete, 0x10d),
            (Error::Qpack(qpack::Error::Huffman), 0x200),
        ] {
            assert_eq!(error.application_code(), Some(code));
            assert!(!error.to_string().is_empty());
        }
        for error in [Error::State, Error::Priority, Error::Unwritable] {
            assert_eq!(error.application_code(), None);
        }
    }

    #[test]
    fn generated_wire_and_stream_contracts() {
        let mut rng = Lcg::new(0x4854_5450_3321);
        for _ in 0..FUZZ_CASES {
            let mut bytes = rng.bytes(MAX_TEST_BYTES);
            mutate(&mut rng, &mut bytes);
            contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_FRAME);
            contract::check_decode_with_alloc_limit(StreamHeaders::new, &bytes, 2 * MAX_STREAM_HEADER);
            contract::check_wire::<Frame>(&bytes);
            contract::check_wire::<Settings>(&bytes);
            contract::check_wire::<Priority>(&bytes);
            contract::check_wire::<StreamHeader>(&bytes);
            let budget = MAX_FRAME + MAX_TEST_BYTES;
            let mut session = Session::new(Endpoint::Client, 5, budget);
            for (index, chunk) in bytes.chunks(17).enumerate() {
                let _ = session.push([0, 2, 4, 6, 10][index % 5], chunk);
                while session.next().is_some() {}
                assert!(session.buffered() <= budget);
            }
            for id in [0, 2, 4, 6, 10] {
                session.end(id);
            }
            while session.next().is_some() {}
            assert!(session.buffered() <= budget);
            let (items, _) = decode_all(Frames::<Frame>::new, &bytes);
            for frame in items.iter().flatten() {
                contract::check_wire_value(frame);
            }
            for extended_connect in [false, true] {
                for mut state in [
                    RequestStream::new(0, MessageSide::Request, extended_connect).unwrap(),
                    RequestStream::new(0, MessageSide::Response, extended_connect).unwrap(),
                    RequestStream::new(0, MessageSide::HeadResponse, extended_connect).unwrap(),
                    RequestStream::new(0, MessageSide::ConnectResponse, extended_connect).unwrap(),
                    RequestStream::push(3).unwrap(),
                ] {
                    for item in &items {
                        if item.clone().and_then(|frame| event(&mut state, frame, &plain_qpack())).is_err() {
                            break;
                        }
                    }
                    let _ = state.finish();
                }
            }
            let frame = match rng.index(5) {
                0 => Frame::Data(bytes.clone()),
                1 => Frame::Headers(bytes.clone()),
                2 => Frame::Unknown { frame_type: 0x21, payload: bytes.clone() },
                3 => Frame::PushPromise { push_id: rng.next(), field_section: bytes.clone() },
                _ => Frame::Goaway(rng.next()),
            };
            roundtrip(&frame);
            let mut list = request();
            list.fields.push(qpack::Field { name: b"x-fuzz".to_vec(), value: bytes, never_index: rng.coin() });
            let kind = HeaderKind::Request { extended_connect: false };
            if let Ok(section) = list.section(&mut qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE), 0, kind) {
                assert_eq!(received(&plain_qpack(), 0, &section.to_bytes().unwrap(), kind), Ok(list));
            }
        }
    }

    #[test]
    fn unidirectional_stream_closed_before_type_can_be_discarded() {
        // RFC 9114 section 6.2 permits the owner to discard an incomplete type.
        for bytes in [&[][..], &[0x40][..], &[1][..], &[1, 0x80, 0][..]] {
            let (items, failure) = decode_all(StreamHeaders::new, bytes);
            assert!(items.is_empty());
            if bytes.is_empty() {
                assert!(failure.is_none());
            } else {
                assert!(matches!(failure, Some(Fail::Truncated { .. })));
            }
        }
    }
    #[test]
    fn connect_tunnel_allows_only_data_and_extensions() {
        // RFC 9114 section 4.4: other known frames after the tunnel opens.
        let promise = Frame::PushPromise { push_id: 0, field_section: encoded(&request()) };
        for status in ["200", "204", "299"] {
            for late in [headers(&fields(&[])), headers(&fields(&[("x", "y")])), promise.clone()] {
                let (events, result) = messages(
                    MessageSide::ConnectResponse,
                    &[headers(&response(status)), Frame::Data(b"x".to_vec()), late.clone()],
                );
                assert_eq!(events.len(), 2, "{status}");
                assert_eq!(result, Err(Error::UnexpectedFrame(late.frame_type())));
            }
        }
        let connect = fields(&[(":method", "CONNECT"), (":authority", "example.net:443")]);
        let (_, result) =
            messages(MessageSide::Request, &[headers(&connect), Frame::Data(b"x".to_vec()), headers(&fields(&[]))]);
        assert_eq!(result, Err(Error::UnexpectedFrame(frame_type::HEADERS)));
        let unknown = Frame::Unknown { frame_type: 0x21, payload: vec![1] };
        let (events, result) = messages(MessageSide::ConnectResponse, &[headers(&response("200")), unknown.clone()]);
        assert_eq!((events.last(), result), (Some(&Event::Unknown(unknown)), Ok(())));
        // A failed CONNECT is an ordinary response and may carry trailers.
        let (_, result) =
            messages(MessageSide::ConnectResponse, &[headers(&response("404")), headers(&fields(&[("x", "y")]))]);
        assert_eq!(result, Ok(()));
        // The check happens before QPACK, so a section that would block is refused too.
        let table = qpack::Table::new(4096);
        let mut state = RequestStream::new(0, MessageSide::ConnectResponse, false).unwrap();
        event(&mut state, headers(&response("200")), &table).unwrap();
        assert_eq!(
            event(&mut state, Frame::Headers(vec![2, 0, 0x80]), &table),
            Err(Error::UnexpectedFrame(frame_type::HEADERS))
        );
        assert!(!state.is_blocked());
    }
    #[test]
    fn connect_success_ignores_content_length_and_204() {
        // RFC 9110 section 9.3.6: any 2xx opens the tunnel; Content-Length is ignored.
        for status in ["200", "204", "206"] {
            let (_, result) =
                messages(MessageSide::ConnectResponse, &[headers(&response(status)), Frame::Data(b"tunnel".to_vec())]);
            assert_eq!(result, Ok(()), "{status}");
            let mut h = response(status);
            h.fields.push(qpack::Field::new("content-length", "0"));
            let (events, result) =
                messages(MessageSide::ConnectResponse, &[headers(&h), Frame::Data(b"tunnel".to_vec())]);
            assert_eq!(result, Ok(()), "{status}");
            assert_eq!(events.first(), Some(&Event::Headers(h)));
        }
        // The writer still refuses Content-Length on 204.
        let mut h = response("204");
        h.fields.push(qpack::Field::new("content-length", "0"));
        assert!(h.validate(HeaderKind::Response).is_err());
    }
    #[test]
    fn pushed_head_response() {
        let mut h = response("200");
        h.fields.push(qpack::Field::new("content-length", "99"));
        let run = |side: Option<MessageSide>, frames: &[Frame]| {
            let mut d = RequestStream::push(3).unwrap();
            // The promise may arrive after the push stream's bytes.
            if let Some(side) = side {
                d.set_push_side(side).unwrap();
            }
            for frame in frames {
                event(&mut d, frame.clone(), &plain_qpack())?;
            }
            d.finish()
        };
        assert_eq!(run(Some(MessageSide::HeadResponse), &[headers(&h)]), Ok(()));
        assert!(matches!(
            run(Some(MessageSide::HeadResponse), &[headers(&h), Frame::Data(vec![1])]),
            Err(Error::Message(_))
        ));
        assert!(matches!(run(None, &[headers(&h)]), Err(Error::Message(_))));
        let mut d = RequestStream::push(3).unwrap();
        assert_eq!(d.set_push_side(MessageSide::Request), Err(Error::State));
        assert_eq!(d.set_push_side(MessageSide::ConnectResponse), Err(Error::State));
        event(&mut d, headers(&response("200")), &plain_qpack()).unwrap();
        assert_eq!(d.set_push_side(MessageSide::HeadResponse), Err(Error::State));
        let mut d = RequestStream::new(0, MessageSide::Response, false).unwrap();
        assert_eq!(d.set_push_side(MessageSide::HeadResponse), Err(Error::State));
    }
    #[test]
    fn promised_requests_need_authority() {
        // RFC 9114 section 4.6: the server MUST include :authority.
        let host_only = fields(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), ("host", "example.net")]);
        assert_eq!(host_only.validate(HeaderKind::Request { extended_connect: false }), Ok(()));
        assert!(matches!(host_only.validate(HeaderKind::Promise), Err(Error::Message(_))));
        assert_eq!(request().validate(HeaderKind::Promise), Ok(()));
        let promise = Frame::PushPromise { push_id: 0, field_section: encoded(&host_only) };
        let (_, result) = messages(MessageSide::Response, &[promise]);
        assert!(matches!(result, Err(Error::Message(_))));
        let mut encoder = qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE);
        assert!(host_only.section(&mut encoder, 0, HeaderKind::Promise).is_err());
        let connect = fields(&[(":method", "CONNECT"), (":authority", "example.net:443"), (":protocol", "websocket")]);
        assert!(connect.validate(HeaderKind::Promise).is_err());
    }
    #[test]
    fn no_trailers_after_204_or_304() {
        // RFC 9110 sections 15.3.5 and 15.4.5: no content or trailers.
        for status in ["204", "304"] {
            let (_, result) =
                messages(MessageSide::Response, &[headers(&response(status)), headers(&fields(&[("x-check", "ok")]))]);
            assert!(matches!(result, Err(Error::Message(_))), "{status}");
        }
        let (_, result) =
            messages(MessageSide::Response, &[headers(&response("200")), headers(&fields(&[("x-check", "ok")]))]);
        assert_eq!(result, Ok(()));
    }
    #[test]
    fn no_content_for_205_or_trace() {
        // RFC 9110 sections 15.3.6 and 9.3.8.
        let (_, result) = messages(MessageSide::Response, &[headers(&response("205")), Frame::Data(b"x".to_vec())]);
        assert!(matches!(result, Err(Error::Message(_))));
        assert_eq!(messages(MessageSide::Response, &[headers(&response("205")), Frame::Data(vec![])]).1, Ok(()));
        let trace =
            fields(&[(":method", "TRACE"), (":scheme", "https"), (":authority", "example.net"), (":path", "/")]);
        let (_, result) = messages(MessageSide::Request, &[headers(&trace), Frame::Data(b"x".to_vec())]);
        assert!(matches!(result, Err(Error::Message(_))));
        assert_eq!(messages(MessageSide::Request, &[headers(&trace)]).1, Ok(()));
        let mut long = trace.clone();
        long.fields.push(qpack::Field::new("content-length", "5"));
        assert!(matches!(messages(MessageSide::Request, &[headers(&long)]).1, Err(Error::Message(_))));
    }
    #[test]
    fn repeated_content_length_is_normalized() {
        // RFC 9110 section 8.6: replace "2, 2" with one value or reject it.
        let kind = HeaderKind::Request { extended_connect: false };
        let mut h = request();
        h.fields.push(qpack::Field::new("content-length", "2, 2"));
        h.fields.push(qpack::Field::new("x", "y"));
        h.fields.push(qpack::Field::new("content-length", "2"));
        let mut want = request();
        want.fields.push(qpack::Field::new("content-length", "2"));
        want.fields.push(qpack::Field::new("x", "y"));
        assert!(h.validate(kind).is_err());
        assert!(h.section(&mut qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE), 0, kind).is_err());
        assert_eq!(received(&plain_qpack(), 0, &encoded(&h), kind), Ok(want.clone()));
        let (events, result) = messages(MessageSide::Request, &[headers(&h), Frame::Data(vec![1, 2])]);
        assert_eq!((events.first(), result), (Some(&Event::Headers(want.clone())), Ok(())));
        assert_eq!(want.validate(kind), Ok(()));
    }
}
