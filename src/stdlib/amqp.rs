//! AMQP 0-9-1: reading and writing frames, methods, field tables and
//! content headers, with no I/O.
//!
//! AMQP 0-9-1 is the protocol RabbitMQ speaks. A client opens a TCP
//! connection, usually to port 5672, and sends an 8-byte protocol header.
//! After that both sides send frames. Each frame has a type, a channel
//! number, a size and a payload, and ends with the byte 0xCE. A method
//! frame carries a command, such as `queue.declare` or `basic.publish`. A
//! message is a method frame, a content header frame with its properties,
//! and body frames with its bytes. Heartbeat frames keep an idle connection
//! alive. This module follows the AMQP 0-9-1 specification and RabbitMQ's
//! reference for it, including RabbitMQ's field value types and its
//! extensions to the connection and basic classes.
//!
//! Nothing here reads a socket. A world that plays a broker pushes the bytes
//! it reads from a TCP connection to a [`Stream<Frames>`](super::codec::Stream), gets [`Frame`]s back,
//! reads each method frame's [`Method`], and writes the reply's bytes back
//! to the connection. Which exchanges and queues exist, and where a message
//! goes, is up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A frame the stream cannot hold breaks the stream with a
//! [`FrameError`]. A payload that breaks the specification gives a
//! [`DecodeError`], whose [`DecodeError::reply_code`] is the code a broker
//! closes the connection with. Writers return an [`EncodeError`] rather
//! than write bytes a reader would refuse.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::amqp::{
//!     content_frames, BasicProperties, ContentHeader, Frames, Frame, FrameKind, Method, Table, DEFAULT_FRAME_MAX,
//!     PROTOCOL_HEADER,
//! };
//!
//! let mut decoder = Stream::new(Frames::server());
//! let _ = decoder.push(&PROTOCOL_HEADER);
//! assert!(decoder.next().is_none());
//! assert!(decoder.decoder().header_received());
//!
//! // The broker speaks first, on channel 0.
//! let start = Method::ConnectionStart {
//!     version_major: 0,
//!     version_minor: 9,
//!     server_properties: Table::new(),
//!     mechanisms: b"PLAIN".to_vec(),
//!     locales: b"en_US".to_vec(),
//! };
//! let bytes = Frame::method(0, &start).unwrap().to_bytes().unwrap();
//! // A method frame on channel 0 with 28 bytes: class 10, method 10, ...
//! assert_eq!(bytes[..11], [1, 0, 0, 0, 0, 0, 28, 0, 10, 0, 10]);
//! assert_eq!(bytes.len(), 7 + 28 + 1);
//! assert_eq!(bytes[35], 0xce);
//!
//! // Later, the client publishes "hello" on channel 1.
//! let publish = Method::BasicPublish {
//!     exchange: String::new(),
//!     routing_key: "orders".to_string(),
//!     mandatory: false,
//!     immediate: false,
//! };
//! let frames = content_frames(1, &publish, &BasicProperties::default(), b"hello", DEFAULT_FRAME_MAX).unwrap();
//! for f in &frames {
//!     let bytes = f.to_bytes().unwrap();
//!     // A decoder takes what fits in its buffer, which here is all of it.
//!     assert_eq!(decoder.push(&bytes), bytes.len());
//! }
//! let method = decoder.next().unwrap().unwrap();
//! assert_eq!(Method::parse(&method.payload), Ok(publish));
//! let header = decoder.next().unwrap().unwrap();
//! assert_eq!(ContentHeader::parse(&header.payload).unwrap().body_size, 5);
//! let body = decoder.next().unwrap().unwrap();
//! assert_eq!((body.kind, body.channel, &body.payload[..]), (FrameKind::Body, 1, &b"hello"[..]));
//! assert!(decoder.next().is_none());
//! ```

use super::codec::{Decode, Step, Wire};

/// The TCP port AMQP brokers listen on.
pub const PORT: u16 = 5672;
/// The bytes a client sends first: "AMQP", then 0, 0, 9, 1.
pub const PROTOCOL_HEADER: [u8; 8] = *b"AMQP\x00\x00\x09\x01";
/// The length of a frame's header: type, channel and size.
pub const FRAME_HEADER_LEN: usize = 7;
/// The byte every frame ends with.
pub const FRAME_END: u8 = 0xce;
/// The bytes a frame adds to its payload: the header and the end byte.
pub const FRAME_OVERHEAD: u32 = 8;
/// The frame size every peer must accept, whatever was negotiated.
pub const FRAME_MIN_SIZE: u32 = 4096;
/// The frame size a [`Stream<Frames>`](super::codec::Stream) accepts until told otherwise. RabbitMQ
/// offers it in `connection.tune`.
pub const DEFAULT_FRAME_MAX: u32 = 131_072;
/// The largest frame this module reads or writes, whatever was negotiated.
/// A frame-max of 0 means "no limit" in the protocol, and means this here.
pub const MAX_FRAME_SIZE: u32 = 1 << 20;
/// The longest payload a frame of [`MAX_FRAME_SIZE`] carries. It also caps
/// every long string and field table a writer writes.
pub const MAX_PAYLOAD: usize = (MAX_FRAME_SIZE - FRAME_OVERHEAD) as usize;
/// The longest short string: its length is one byte.
pub const MAX_SHORT_STRING: usize = 255;
/// How deep field tables and arrays may nest inside one another. The
/// outermost table is at depth 1.
pub const MAX_DEPTH: usize = 32;

/// Frame type codes.
pub mod frame_type {
    #![allow(missing_docs)]
    pub const METHOD: u8 = 1;
    pub const HEADER: u8 = 2;
    pub const BODY: u8 = 3;
    pub const HEARTBEAT: u8 = 8;
}

/// Class identifiers this module reads and writes.
pub mod class {
    #![allow(missing_docs)]
    pub const CONNECTION: u16 = 10;
    pub const CHANNEL: u16 = 20;
    pub const EXCHANGE: u16 = 40;
    pub const QUEUE: u16 = 50;
    pub const BASIC: u16 = 60;
    pub const CONFIRM: u16 = 85;
    pub const TX: u16 = 90;
}

/// Reply codes, sent in `connection.close`, `channel.close` and
/// `basic.return`.
pub mod reply {
    #![allow(missing_docs)]
    pub const SUCCESS: u16 = 200;
    pub const CONTENT_TOO_LARGE: u16 = 311;
    pub const NO_ROUTE: u16 = 312;
    pub const NO_CONSUMERS: u16 = 313;
    pub const CONNECTION_FORCED: u16 = 320;
    pub const INVALID_PATH: u16 = 402;
    pub const ACCESS_REFUSED: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const RESOURCE_LOCKED: u16 = 405;
    pub const PRECONDITION_FAILED: u16 = 406;
    pub const FRAME_ERROR: u16 = 501;
    pub const SYNTAX_ERROR: u16 = 502;
    pub const COMMAND_INVALID: u16 = 503;
    pub const CHANNEL_ERROR: u16 = 504;
    pub const UNEXPECTED_FRAME: u16 = 505;
    pub const RESOURCE_ERROR: u16 = 506;
    pub const NOT_ALLOWED: u16 = 530;
    pub const NOT_IMPLEMENTED: u16 = 540;
    pub const INTERNAL_ERROR: u16 = 541;
}

/// The largest frame a peer must accept when `frame_max` was negotiated: 0
/// means [`MAX_FRAME_SIZE`], and other values are kept between
/// [`FRAME_MIN_SIZE`] and [`MAX_FRAME_SIZE`].
pub fn frame_limit(frame_max: u32) -> u32 {
    if frame_max == 0 { MAX_FRAME_SIZE } else { frame_max.clamp(FRAME_MIN_SIZE, MAX_FRAME_SIZE) }
}

/// What a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// A method: a class, a method and its arguments.
    Method,
    /// A content header: a message's size and properties.
    Header,
    /// Some of a message's bytes.
    Body,
    /// A heartbeat, always on channel 0 and always empty.
    Heartbeat,
}

impl FrameKind {
    /// The frame type's code.
    pub fn code(self) -> u8 {
        match self {
            FrameKind::Method => frame_type::METHOD,
            FrameKind::Header => frame_type::HEADER,
            FrameKind::Body => frame_type::BODY,
            FrameKind::Heartbeat => frame_type::HEARTBEAT,
        }
    }

    /// The frame kind for code `c`, if it is one.
    pub fn from_code(c: u8) -> Option<FrameKind> {
        match c {
            frame_type::METHOD => Some(FrameKind::Method),
            frame_type::HEADER => Some(FrameKind::Header),
            frame_type::BODY => Some(FrameKind::Body),
            frame_type::HEARTBEAT => Some(FrameKind::Heartbeat),
            _ => None,
        }
    }
}

/// One frame: its kind, its channel and its payload. The size field and
/// the end byte are worked out when it is written, so neither is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// What the payload holds.
    pub kind: FrameKind,
    /// The channel, or 0 for the connection itself.
    pub channel: u16,
    /// The bytes between the header and the end byte.
    pub payload: Vec<u8>,
}

/// Why bytes are not an AMQP frame stream. The stream holds no more frames
/// a reader can find, and a broker closes the connection. Whether it sends
/// `connection.close` first is [`FrameError::sends_close`], and the code it
/// sends is [`FrameError::reply_code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The client's first 8 bytes were not [`PROTOCOL_HEADER`]. A broker
    /// writes its own header back and closes the connection.
    ProtocolHeader([u8; 8]),
    /// The frame type is not one AMQP 0-9-1 defines.
    Type(u8),
    /// A heartbeat frame was not on channel 0, or was not empty.
    Heartbeat {
        /// The channel it named.
        channel: u16,
        /// The payload size it named.
        size: u32,
    },
    /// The frame, with its header and end byte, is larger than the limit.
    TooLarge {
        /// The payload size the frame named.
        size: u32,
        /// The limit it broke.
        frame_max: u32,
    },
    /// The byte after the payload was not [`FRAME_END`].
    FrameEnd(u8),
    /// A content header or body frame, or a method frame of a class other
    /// than connection, was on channel 0. Channel 0 is for the connection
    /// alone (AMQP 0-9-1 sections 4.2.3 and 4.2.6.1).
    ChannelZero(FrameKind),
    /// A method frame of the connection class was on a channel other
    /// than 0 (section 4.2.3).
    NotChannelZero {
        /// The channel it named.
        channel: u16,
    },
}

impl FrameError {
    /// The reply code for the error, as section 4.2.3 and 4.2.6.1 give
    /// them: 503 (command invalid) for a connection method or a heartbeat
    /// off channel 0, and for another class's method on it; 504 (channel
    /// error) for content on channel 0; and 501 (frame error) otherwise.
    pub fn reply_code(self) -> u16 {
        match self {
            FrameError::Heartbeat { channel, .. } if channel != 0 => reply::COMMAND_INVALID,
            FrameError::NotChannelZero { .. } | FrameError::ChannelZero(FrameKind::Method) => reply::COMMAND_INVALID,
            FrameError::ChannelZero(_) => reply::CHANNEL_ERROR,
            _ => reply::FRAME_ERROR,
        }
    }

    /// Whether a broker sends `connection.close` with
    /// [`FrameError::reply_code`] before it closes the socket. A bad
    /// protocol header is answered with the broker's own header instead,
    /// and a bad frame type or end byte with nothing at all: the
    /// specification says to close the connection without sending any
    /// further data (sections 4.2.2 and 4.2.3).
    pub fn sends_close(self) -> bool {
        !matches!(self, FrameError::ProtocolHeader(_) | FrameError::Type(_) | FrameError::FrameEnd(_))
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::ProtocolHeader(b) => write!(f, "protocol header {b:02x?}, not AMQP 0-9-1"),
            FrameError::Type(t) => write!(f, "frame type {t}, not one AMQP 0-9-1 defines"),
            FrameError::Heartbeat { channel, size } => {
                write!(f, "heartbeat frame on channel {channel} with {size} bytes; it must be on 0 and empty")
            }
            FrameError::TooLarge { size, frame_max } => {
                write!(f, "frame payload of {size} bytes is over the frame-max of {frame_max}")
            }
            FrameError::FrameEnd(b) => write!(f, "frame ends with 0x{b:02x}, not 0xce"),
            FrameError::ChannelZero(k) => write!(f, "{k:?} frame on channel 0, which is for the connection alone"),
            FrameError::NotChannelZero { channel } => {
                write!(f, "connection method on channel {channel}; it must be on 0")
            }
        }
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// Reads the frame at the start of `b`, allowing frames up to
    /// [`frame_limit`]`(frame_max)` bytes. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the frame and how many bytes
    /// of `b` it took. A bad type is known from the first byte, and a bad
    /// size from the first 7. A frame on a channel its kind or class may
    /// not use is refused once its end byte is in.
    fn parse_prefix(b: &[u8], frame_max: u32) -> Result<Option<(Frame, usize)>, FrameError> {
        let Some(&code) = b.first() else { return Ok(None) };
        let kind = FrameKind::from_code(code).ok_or(FrameError::Type(code))?;
        if b.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let channel = u16::from_be_bytes([b[1], b[2]]);
        let size = u32::from_be_bytes([b[3], b[4], b[5], b[6]]);
        if kind == FrameKind::Heartbeat && (channel != 0 || size != 0) {
            return Err(FrameError::Heartbeat { channel, size });
        }
        let limit = frame_limit(frame_max);
        if u64::from(size) + u64::from(FRAME_OVERHEAD) > u64::from(limit) {
            return Err(FrameError::TooLarge { size, frame_max: limit });
        }
        // The size is at most MAX_PAYLOAD here, so this cannot overflow.
        let end = FRAME_HEADER_LEN + size as usize;
        let Some(&last) = b.get(end) else { return Ok(None) };
        if last != FRAME_END {
            return Err(FrameError::FrameEnd(last));
        }
        let payload = &b[FRAME_HEADER_LEN..end];
        channel_rules(kind, channel, payload)?;
        Ok(Some((Frame { kind, channel, payload: payload.to_vec() }, end + 1)))
    }

    /// A method frame carrying `method` on `channel`. Connection methods
    /// go on channel 0 and every other method on another channel.
    pub fn method(channel: u16, method: &Method) -> Result<Frame, EncodeError> {
        let payload = method.to_bytes()?;
        channel_rules(FrameKind::Method, channel, &payload).map_err(|_| EncodeError::Unwritable)?;
        Ok(Frame { kind: FrameKind::Method, channel, payload })
    }

    /// A content header frame carrying `header` on `channel`, which may
    /// not be 0.
    pub fn header(channel: u16, header: &ContentHeader) -> Result<Frame, EncodeError> {
        channel_rules(FrameKind::Header, channel, &[]).map_err(|_| EncodeError::Unwritable)?;
        Ok(Frame { kind: FrameKind::Header, channel, payload: header.to_bytes()? })
    }

    /// A body frame carrying `bytes` on `channel`. [`Frame::to_bytes`]
    /// refuses it if `channel` is 0 or `bytes` is longer than
    /// [`MAX_PAYLOAD`].
    pub fn body(channel: u16, bytes: Vec<u8>) -> Frame {
        Frame { kind: FrameKind::Body, channel, payload: bytes }
    }

    /// A heartbeat frame.
    pub fn heartbeat() -> Frame {
        Frame { kind: FrameKind::Heartbeat, channel: 0, payload: Vec::new() }
    }
}

/// Why bytes do not contain exactly one AMQP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// The frame was refused.
    Frame(FrameError),
    /// The input ended before a complete frame arrived.
    Truncated,
    /// Bytes followed the frame.
    Trailing,
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Truncated => f.write_str("AMQP frame ended early"),
            Self::Trailing => f.write_str("bytes after the AMQP frame"),
        }
    }
}

impl core::error::Error for FrameParseError {}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = EncodeError;

    /// Reads exactly one frame, bounded by [`MAX_FRAME_SIZE`].
    /// Refuses bad types, channels, heartbeat fields, end bytes, and incomplete or trailing input.
    fn parse(bytes: &[u8]) -> Result<Self, FrameParseError> {
        match Self::parse_prefix(bytes, MAX_FRAME_SIZE).map_err(FrameParseError::Frame)? {
            Some((frame, used)) if used == bytes.len() => Ok(frame),
            Some(_) => Err(FrameParseError::Trailing),
            None => Err(FrameParseError::Truncated),
        }
    }

    /// Appends a frame. Refuses payloads above [`MAX_PAYLOAD`], nonempty
    /// heartbeats, and channels forbidden by the frame kind or method class.
    /// Leaves `out` unchanged on error. The caller enforces the negotiated
    /// frame limit; [`content_frames`] splits bodies to fit it.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let size = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        if self.payload.len() > MAX_PAYLOAD {
            return Err(EncodeError::Unwritable);
        }
        if self.kind == FrameKind::Heartbeat && (self.channel != 0 || size != 0) {
            return Err(EncodeError::Unwritable);
        }
        channel_rules(self.kind, self.channel, &self.payload).map_err(|_| EncodeError::Unwritable)?;
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len() + 1);
        bytes.push(self.kind.code());
        bytes.extend_from_slice(&self.channel.to_be_bytes());
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.push(FRAME_END);
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Reads AMQP frames without retaining input bytes.
///
/// Use with [`super::codec::Stream`] for bounded input and one-time errors.
/// Partial frames return [`Step::Need`], including at EOF. Frame faults
/// end the stream. Parse method and content payloads separately to receive
/// their [`DecodeError`] values as items with [`Decode::map`].
///
/// ```
/// use fictionet::stdlib::{amqp::{Frame, Frames}, codec::{Stream, Wire}};
///
/// let frame = Frame::heartbeat();
/// let bytes = Wire::to_bytes(&frame)?;
/// let mut stream = Stream::new(Frames::new());
/// assert_eq!(stream.push(&bytes), bytes.len());
/// assert_eq!(stream.next(), Some(Ok(frame)));
/// stream.end();
/// assert_eq!(stream.next(), None);
/// # Ok::<(), fictionet::stdlib::amqp::EncodeError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Frames {
    frame_max: u32,
    expect_header: bool,
    header_received: bool,
}

impl Frames {
    /// Reads frames up to [`DEFAULT_FRAME_MAX`] bytes, including framing.
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_FRAME_MAX)
    }

    /// Reads frames up to [`frame_limit`]`(frame_max)` bytes.
    /// A larger frame is refused from its header.
    pub fn with_limit(frame_max: u32) -> Self {
        Self { frame_max: frame_limit(frame_max), expect_header: false, header_received: false }
    }

    /// Reads the client's protocol header before reading frames.
    /// The header is consumed as [`Step::Skip`].
    pub fn server() -> Self {
        Self { expect_header: true, ..Self::new() }
    }

    /// Sets the negotiated frame limit between items.
    /// The value is clamped by [`frame_limit`].
    pub fn set_frame_max(&mut self, frame_max: u32) {
        self.frame_max = frame_limit(frame_max);
    }

    /// The maximum frame size, including framing bytes.
    pub fn frame_max(&self) -> u32 {
        self.frame_max
    }

    /// Whether a decoder made by [`Frames::server`] read its protocol header.
    pub fn header_received(&self) -> bool {
        self.header_received
    }
}

impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Frames {
    type Item = Frame;
    type Error = FrameError;
    const NAME: &'static str = "AMQP 0-9-1";

    fn capacity(&self) -> usize {
        self.frame_max as usize
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, FrameError> {
        if self.expect_header && !self.header_received {
            let Some(header) = input.get(..PROTOCOL_HEADER.len()) else { return Ok(Step::Need) };
            if header != PROTOCOL_HEADER {
                let mut got = [0; 8];
                got.copy_from_slice(header);
                return Err(FrameError::ProtocolHeader(got));
            }
            self.header_received = true;
            return Ok(Step::Skip(PROTOCOL_HEADER.len()));
        }
        Ok(match Frame::parse_prefix(input, self.frame_max)? {
            Some((frame, used)) => Step::Item(frame, used),
            None => Step::Need,
        })
    }
}

/// Checks the channel rules of AMQP 0-9-1 sections 4.2.3 and 4.2.6.1:
/// content goes on a channel other than 0, connection methods on 0, and
/// other methods off it. A method payload too short to name its class is
/// left for [`Method::parse`] to refuse.
fn channel_rules(kind: FrameKind, channel: u16, payload: &[u8]) -> Result<(), FrameError> {
    match kind {
        FrameKind::Header | FrameKind::Body if channel == 0 => Err(FrameError::ChannelZero(kind)),
        FrameKind::Method => match payload {
            [a, b, ..] => {
                let connection = u16::from_be_bytes([*a, *b]) == class::CONNECTION;
                match (connection, channel == 0) {
                    (true, false) => Err(FrameError::NotChannelZero { channel }),
                    (false, true) => Err(FrameError::ChannelZero(kind)),
                    _ => Ok(()),
                }
            }
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

/// The frames that send a message on `channel`: the method frame for
/// `method` (`basic.publish`, `basic.deliver`, `basic.get-ok` or
/// `basic.return`), a content header with `properties` and the body's
/// size, and the body cut into body frames that fit in
/// [`frame_limit`]`(frame_max)`. An empty body gets no body frames. It
/// fails if the method carries no content, if `channel` is 0, or if the
/// method or the header does not fit in one frame.
pub fn content_frames(
    channel: u16,
    method: &Method,
    properties: &BasicProperties,
    body: &[u8],
    frame_max: u32,
) -> Result<Vec<Frame>, EncodeError> {
    if !method.has_content() {
        return Err(EncodeError::Unwritable);
    }
    let room = (frame_limit(frame_max) - FRAME_OVERHEAD) as usize;
    let method = Frame::method(channel, method)?;
    channel_rules(FrameKind::Header, channel, &[]).map_err(|_| EncodeError::Unwritable)?;
    let header = Frame { kind: FrameKind::Header, channel, payload: header_payload(body.len() as u64, properties)? };
    for f in [&method, &header] {
        if f.payload.len() > room {
            return Err(EncodeError::Unwritable);
        }
    }
    let mut frames = vec![method, header];
    frames.extend(body.chunks(room).map(|c| Frame::body(channel, c.to_vec())));
    Ok(frames)
}

/// Why a payload is not a method, a content header or a field table this
/// module can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload ended before the last field, or a length inside it ran
    /// past its end.
    Truncated,
    /// Bytes were left after the last field.
    TrailingBytes,
    /// The class and method are not ones this module knows.
    UnknownMethod {
        /// The class identifier read.
        class_id: u16,
        /// The method identifier read.
        method_id: u16,
    },
    /// A short string was not UTF-8.
    Utf8,
    /// A field value had a type tag this module does not know.
    FieldType(u8),
    /// Field tables and arrays nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A content header named a class other than basic (60).
    ContentClass(u16),
    /// A content header set property flags basic does not define, or the
    /// flag that says more flags follow.
    PropertyFlags(u16),
    /// The payload was longer than [`MAX_PAYLOAD`] bytes, more than any
    /// frame holds. It holds the length.
    TooLarge(usize),
    /// A short string held a zero byte, which section 4.2.5.3 forbids.
    ZeroByte,
    /// A field table named the same field twice, which section 4.2.5.5
    /// forbids.
    DuplicateField,
    /// A content header's weight was not 0, which section 4.2.6.1
    /// requires. It holds the weight.
    Weight(u16),
}

impl DecodeError {
    /// The reply code a broker closes the connection with: 540 (not
    /// implemented) for an unknown method, 501 (frame error) for a payload
    /// too large for a frame or a content header of the wrong class
    /// (section 4.2.6.1), 505 (unexpected frame) for another badly formed
    /// content header (section 4.2.6), and 502 (syntax error) otherwise.
    pub fn reply_code(self) -> u16 {
        match self {
            DecodeError::UnknownMethod { .. } => reply::NOT_IMPLEMENTED,
            DecodeError::TooLarge(_) | DecodeError::ContentClass(_) => reply::FRAME_ERROR,
            DecodeError::PropertyFlags(_) | DecodeError::Weight(_) => reply::UNEXPECTED_FRAME,
            _ => reply::SYNTAX_ERROR,
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("payload ends before its last field"),
            DecodeError::TrailingBytes => f.write_str("bytes left after the last field"),
            DecodeError::UnknownMethod { class_id, method_id } => {
                write!(f, "unknown method {class_id}.{method_id}")
            }
            DecodeError::Utf8 => f.write_str("short string is not UTF-8"),
            DecodeError::FieldType(t) => write!(f, "unknown field value type 0x{t:02x}"),
            DecodeError::TooDeep => write!(f, "field tables nested deeper than {MAX_DEPTH}"),
            DecodeError::ContentClass(c) => write!(f, "content header for class {c}, not basic (60)"),
            DecodeError::PropertyFlags(p) => write!(f, "property flags 0x{p:04x} set bits basic does not define"),
            DecodeError::TooLarge(n) => write!(f, "payload of {n} bytes is more than a frame holds"),
            DecodeError::ZeroByte => f.write_str("short string holds a zero byte"),
            DecodeError::DuplicateField => f.write_str("field table names a field twice"),
            DecodeError::Weight(w) => write!(f, "content header weight {w}, not 0"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a value cannot be written. A reader would refuse what it would
/// have written, so nothing is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The value cannot be written without changing it.
    Unwritable,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AMQP value cannot be written without changing it")
    }
}

impl std::error::Error for EncodeError {}

/// A field table: names and values, in the order they were sent. Each name
/// appears once: section 4.2.5.5 makes duplicate fields illegal, so readers
/// refuse a table that repeats one and writers refuse to write one.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Table {
    /// The names and values.
    pub entries: Vec<(String, FieldValue)>,
}

impl Table {
    /// An empty table.
    pub fn new() -> Table {
        Table::default()
    }

    /// The first value named `name`.
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.entries.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Sets `name` to `value`, replacing the first value of that name or
    /// adding it at the end.
    pub fn insert(&mut self, name: impl Into<String>, value: FieldValue) {
        let name = name.into();
        match self.entries.iter_mut().find(|(n, _)| *n == name) {
            Some((_, v)) => *v = value,
            None => self.entries.push((name, value)),
        }
    }
}

impl Wire for Table {
    type ParseError = DecodeError;
    type WriteError = EncodeError;

    /// Reads one field table, including its four-byte length. Refuses
    /// malformed fields, duplicate names, excess nesting, more than
    /// [`MAX_PAYLOAD`] bytes, and trailing bytes.
    fn parse(b: &[u8]) -> Result<Table, DecodeError> {
        let mut r = Reader::payload(b)?;
        let t = r.table(1)?;
        r.finish()?;
        Ok(t)
    }

    /// Appends the complete value. Refuses invalid fields, excess nesting,
    /// or size limits. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let mut w = Writer::new();
        w.table(self, 1)?;
        let bytes = w.out;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// A value in a field table or array. The type tags are the ones RabbitMQ
/// and most clients use, which differ from the 0-9-1 specification's own
/// table for a few types. In the specification `s` is a short string and
/// `l` is unsigned; here, as in RabbitMQ, both are signed integers.
///
/// Float equality compares the wire bits, including NaNs.
#[derive(Clone, Debug)]
pub enum FieldValue {
    /// `t`: a boolean, one byte. Any byte but 0 is true.
    Bool(bool),
    /// `b`: a signed byte.
    I8(i8),
    /// `B`: an unsigned byte.
    U8(u8),
    /// `s`: a signed 16-bit integer.
    I16(i16),
    /// `u`: an unsigned 16-bit integer.
    U16(u16),
    /// `I`: a signed 32-bit integer.
    I32(i32),
    /// `i`: an unsigned 32-bit integer.
    U32(u32),
    /// `l`: a signed 64-bit integer. The older tag `L` reads as this too,
    /// as RabbitMQ reads it, and is written back as `l`.
    I64(i64),
    /// `f`: a 32-bit float.
    F32(f32),
    /// `d`: a 64-bit float.
    F64(f64),
    /// `D`: a decimal, `value` divided by 10 to the power `scale`. The
    /// value is signed (section 4.2.5.5, and RabbitMQ's errata).
    Decimal {
        /// How many digits of `value` follow the decimal point.
        scale: u8,
        /// The digits, with their sign.
        value: i32,
    },
    /// `S`: a long string, any bytes.
    LongString(Vec<u8>),
    /// `A`: an array of values.
    Array(Vec<FieldValue>),
    /// `T`: a timestamp, in seconds since the Unix epoch.
    Timestamp(u64),
    /// `F`: a nested table.
    Table(Table),
    /// `V`: no value.
    Void,
    /// `x`: a byte array.
    Bytes(Vec<u8>),
}

impl PartialEq for FieldValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::I8(a), Self::I8(b)) => a == b,
            (Self::U8(a), Self::U8(b)) => a == b,
            (Self::I16(a), Self::I16(b)) => a == b,
            (Self::U16(a), Self::U16(b)) => a == b,
            (Self::I32(a), Self::I32(b)) => a == b,
            (Self::U32(a), Self::U32(b)) => a == b,
            (Self::I64(a), Self::I64(b)) => a == b,
            (Self::F32(a), Self::F32(b)) => a.to_bits() == b.to_bits(),
            (Self::F64(a), Self::F64(b)) => a.to_bits() == b.to_bits(),
            (Self::Decimal { scale: a, value: x }, Self::Decimal { scale: b, value: y }) => a == b && x == y,
            (Self::LongString(a), Self::LongString(b)) | (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => a == b,
            (Self::Timestamp(a), Self::Timestamp(b)) => a == b,
            (Self::Table(a), Self::Table(b)) => a == b,
            (Self::Void, Self::Void) => true,
            _ => false,
        }
    }
}

impl FieldValue {
    /// The value as a boolean, if it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            FieldValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The value as an `i64`, if it is an integer of any width. Clients
    /// differ in which integer type they send, so this reads them all.
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            FieldValue::I8(n) => Some(i64::from(n)),
            FieldValue::U8(n) => Some(i64::from(n)),
            FieldValue::I16(n) => Some(i64::from(n)),
            FieldValue::U16(n) => Some(i64::from(n)),
            FieldValue::I32(n) => Some(i64::from(n)),
            FieldValue::U32(n) => Some(i64::from(n)),
            FieldValue::I64(n) => Some(n),
            _ => None,
        }
    }

    /// The bytes of a long string or byte array.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FieldValue::LongString(b) | FieldValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// A long string as text, if it is UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::LongString(b) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    /// The nested table, if this is one.
    pub fn as_table(&self) -> Option<&Table> {
        match self {
            FieldValue::Table(t) => Some(t),
            _ => None,
        }
    }

    /// The array's values, if this is an array.
    pub fn as_array(&self) -> Option<&[FieldValue]> {
        match self {
            FieldValue::Array(v) => Some(v),
            _ => None,
        }
    }
}

/// The user name and password in a SASL PLAIN response, as a client sends
/// in `connection.start-ok`: an optional authorization identity, a zero
/// byte, the user, a zero byte and the password (RFC 4616, section 2). It
/// returns `None` unless the response holds exactly two zero bytes, every
/// part is UTF-8, and the user and password are not empty. An
/// authorization identity asks to act as another user, which this
/// function cannot allow, so it returns `None` for one that differs from
/// the user.
pub fn plain_credentials(response: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut parts = response.split(|&b| b == 0);
    let (authzid, user, password) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || user.is_empty() || password.is_empty() {
        return None;
    }
    if [authzid, user, password].iter().any(|p| std::str::from_utf8(p).is_err()) {
        return None;
    }
    if !authzid.is_empty() && authzid != user {
        return None;
    }
    Some((user, password))
}

/// A content header: the size and properties of the message whose body
/// follows in body frames. Only the basic class carries content in AMQP
/// 0-9-1, so the class is not kept. The weight field is unused and must be
/// 0: it is written as 0, and a header with another weight is refused.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ContentHeader {
    /// The body's length in bytes, across all its body frames.
    pub body_size: u64,
    /// The message's properties.
    pub properties: BasicProperties,
}

/// Property flag bits in a basic content header.
pub mod property_flag {
    #![allow(missing_docs)]
    pub const CONTENT_TYPE: u16 = 1 << 15;
    pub const CONTENT_ENCODING: u16 = 1 << 14;
    pub const HEADERS: u16 = 1 << 13;
    pub const DELIVERY_MODE: u16 = 1 << 12;
    pub const PRIORITY: u16 = 1 << 11;
    pub const CORRELATION_ID: u16 = 1 << 10;
    pub const REPLY_TO: u16 = 1 << 9;
    pub const EXPIRATION: u16 = 1 << 8;
    pub const MESSAGE_ID: u16 = 1 << 7;
    pub const TIMESTAMP: u16 = 1 << 6;
    pub const TYPE: u16 = 1 << 5;
    pub const USER_ID: u16 = 1 << 4;
    pub const APP_ID: u16 = 1 << 3;
    pub const CLUSTER_ID: u16 = 1 << 2;
}

/// A message's properties. Each is sent only when set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BasicProperties {
    /// The body's MIME type, such as `application/json`.
    pub content_type: Option<String>,
    /// The body's encoding, such as `gzip`.
    pub content_encoding: Option<String>,
    /// Headers the application chose.
    pub headers: Option<Table>,
    /// 1 for a transient message, 2 for a persistent one.
    pub delivery_mode: Option<u8>,
    /// The message's priority, 0 to 9.
    pub priority: Option<u8>,
    /// Matches a reply to its request.
    pub correlation_id: Option<String>,
    /// The queue a reply should go to.
    pub reply_to: Option<String>,
    /// How long the message may wait, in milliseconds, as text.
    pub expiration: Option<String>,
    /// The application's identifier for the message.
    pub message_id: Option<String>,
    /// When the message was sent, in seconds since the Unix epoch.
    pub timestamp: Option<u64>,
    /// The message's type name.
    pub kind: Option<String>,
    /// The user who sent it. RabbitMQ checks it against the connection's
    /// user.
    pub user_id: Option<String>,
    /// The application that sent it.
    pub app_id: Option<String>,
    /// Unused in AMQP 0-9-1; kept so it reads back.
    pub cluster_id: Option<String>,
}

impl Wire for ContentHeader {
    type ParseError = DecodeError;
    type WriteError = EncodeError;

    /// Reads one basic content header payload. Refuses other classes,
    /// nonzero weight, reserved property flags, malformed fields, excess
    /// nesting, more than [`MAX_PAYLOAD`] bytes, and trailing bytes.
    fn parse(payload: &[u8]) -> Result<ContentHeader, DecodeError> {
        use property_flag as p;
        let mut r = Reader::payload(payload)?;
        let class_id = r.u16()?;
        if class_id != class::BASIC {
            return Err(DecodeError::ContentClass(class_id));
        }
        let weight = r.u16()?;
        if weight != 0 {
            return Err(DecodeError::Weight(weight));
        }
        let body_size = r.u64()?;
        let flags = r.u16()?;
        if flags & 0b11 != 0 {
            return Err(DecodeError::PropertyFlags(flags));
        }
        let on = |bit: u16| flags & bit != 0;
        let s = |r: &mut Reader, bit: u16| if on(bit) { r.shortstr().map(Some) } else { Ok(None) };
        let content_type = s(&mut r, p::CONTENT_TYPE)?;
        let content_encoding = s(&mut r, p::CONTENT_ENCODING)?;
        let headers = if on(p::HEADERS) { Some(r.table(1)?) } else { None };
        let delivery_mode = if on(p::DELIVERY_MODE) { Some(r.u8()?) } else { None };
        let priority = if on(p::PRIORITY) { Some(r.u8()?) } else { None };
        let correlation_id = s(&mut r, p::CORRELATION_ID)?;
        let reply_to = s(&mut r, p::REPLY_TO)?;
        let expiration = s(&mut r, p::EXPIRATION)?;
        let message_id = s(&mut r, p::MESSAGE_ID)?;
        let timestamp = if on(p::TIMESTAMP) { Some(r.u64()?) } else { None };
        let kind = s(&mut r, p::TYPE)?;
        let user_id = s(&mut r, p::USER_ID)?;
        let app_id = s(&mut r, p::APP_ID)?;
        let cluster_id = s(&mut r, p::CLUSTER_ID)?;
        r.finish()?;
        Ok(ContentHeader {
            body_size,
            properties: BasicProperties {
                content_type,
                content_encoding,
                headers,
                delivery_mode,
                priority,
                correlation_id,
                reply_to,
                expiration,
                message_id,
                timestamp,
                kind,
                user_id,
                app_id,
                cluster_id,
            },
        })
    }

    /// Appends the complete value. Refuses invalid fields, excess nesting,
    /// or size limits. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let bytes = header_payload(self.body_size, &self.properties)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// A content header payload for a body of `body_size` bytes with
/// properties `pr`, written from borrowed properties so nothing is copied
/// before the writer's limits are checked.
fn header_payload(body_size: u64, pr: &BasicProperties) -> Result<Vec<u8>, EncodeError> {
    use property_flag as p;
    let mut flags = 0u16;
    let mut set = |present: bool, bit: u16| {
        if present {
            flags |= bit;
        }
    };
    set(pr.content_type.is_some(), p::CONTENT_TYPE);
    set(pr.content_encoding.is_some(), p::CONTENT_ENCODING);
    set(pr.headers.is_some(), p::HEADERS);
    set(pr.delivery_mode.is_some(), p::DELIVERY_MODE);
    set(pr.priority.is_some(), p::PRIORITY);
    set(pr.correlation_id.is_some(), p::CORRELATION_ID);
    set(pr.reply_to.is_some(), p::REPLY_TO);
    set(pr.expiration.is_some(), p::EXPIRATION);
    set(pr.message_id.is_some(), p::MESSAGE_ID);
    set(pr.timestamp.is_some(), p::TIMESTAMP);
    set(pr.kind.is_some(), p::TYPE);
    set(pr.user_id.is_some(), p::USER_ID);
    set(pr.app_id.is_some(), p::APP_ID);
    set(pr.cluster_id.is_some(), p::CLUSTER_ID);
    let mut w = Writer::new();
    w.u16(class::BASIC);
    w.u16(0);
    w.u64(body_size);
    w.u16(flags);
    let s = |w: &mut Writer, v: &Option<String>| v.as_deref().map_or(Ok(()), |v| w.shortstr(v));
    s(&mut w, &pr.content_type)?;
    s(&mut w, &pr.content_encoding)?;
    if let Some(t) = &pr.headers {
        w.table(t, 1)?;
    }
    if let Some(v) = pr.delivery_mode {
        w.u8(v);
    }
    if let Some(v) = pr.priority {
        w.u8(v);
    }
    s(&mut w, &pr.correlation_id)?;
    s(&mut w, &pr.reply_to)?;
    s(&mut w, &pr.expiration)?;
    s(&mut w, &pr.message_id)?;
    if let Some(v) = pr.timestamp {
        w.u64(v);
    }
    s(&mut w, &pr.kind)?;
    s(&mut w, &pr.user_id)?;
    s(&mut w, &pr.app_id)?;
    s(&mut w, &pr.cluster_id)?;
    w.finish()
}

/// A method: a command and its arguments, read from or written as a
/// method frame's payload. Reserved arguments (the old access tickets,
/// `insist`, `known-hosts` and the like) are skipped when read and written
/// as zero or empty. Each variant's doc gives its class and method numbers
/// and names its arguments; flags are `bool`s, short strings are
/// `String`s, and long strings are byte vectors.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Method {
    /// 10.10, broker to client: the protocol version, the broker's
    /// properties, and the SASL mechanisms and locales it offers, each
    /// list separated by spaces.
    ConnectionStart {
        version_major: u8,
        version_minor: u8,
        server_properties: Table,
        mechanisms: Vec<u8>,
        locales: Vec<u8>,
    },
    /// 10.11: the client's properties, its chosen mechanism and locale,
    /// and its SASL response (for PLAIN, a zero byte, the user, a zero
    /// byte and the password).
    ConnectionStartOk { client_properties: Table, mechanism: String, response: Vec<u8>, locale: String },
    /// 10.20: a SASL challenge.
    ConnectionSecure { challenge: Vec<u8> },
    /// 10.21: the client's answer to a challenge.
    ConnectionSecureOk { response: Vec<u8> },
    /// 10.30, broker to client: the most channels, the largest frame and
    /// the heartbeat interval in seconds the broker proposes. 0 means no
    /// limit, or no heartbeats.
    ConnectionTune { channel_max: u16, frame_max: u32, heartbeat: u16 },
    /// 10.31: what the client settles on.
    ConnectionTuneOk { channel_max: u16, frame_max: u32, heartbeat: u16 },
    /// 10.40: open the virtual host named.
    ConnectionOpen { virtual_host: String },
    /// 10.41.
    ConnectionOpenOk,
    /// 10.50: close the connection, with a reply code and text, and the
    /// class and method that caused it, or zeros.
    ConnectionClose { reply_code: u16, reply_text: String, class_id: u16, method_id: u16 },
    /// 10.51.
    ConnectionCloseOk,
    /// 10.60, a RabbitMQ extension: the broker has stopped reading
    /// publishes, for the reason given.
    ConnectionBlocked { reason: String },
    /// 10.61, a RabbitMQ extension: the broker reads publishes again.
    ConnectionUnblocked,
    /// 10.70, a RabbitMQ extension: a new secret, such as a refreshed
    /// OAuth token.
    ConnectionUpdateSecret { new_secret: Vec<u8>, reason: String },
    /// 10.71.
    ConnectionUpdateSecretOk,
    /// 20.10: open the frame's channel.
    ChannelOpen,
    /// 20.11.
    ChannelOpenOk,
    /// 20.20: pause (`active` false) or resume content on the channel.
    ChannelFlow { active: bool },
    /// 20.21.
    ChannelFlowOk { active: bool },
    /// 20.40: close the channel, as [`Method::ConnectionClose`] does the
    /// connection.
    ChannelClose { reply_code: u16, reply_text: String, class_id: u16, method_id: u16 },
    /// 20.41.
    ChannelCloseOk,
    /// 40.10: create an exchange of type `kind` (`direct`, `fanout`,
    /// `topic`, `headers`), or with `passive`, check that it exists.
    ExchangeDeclare {
        exchange: String,
        kind: String,
        passive: bool,
        durable: bool,
        auto_delete: bool,
        internal: bool,
        no_wait: bool,
        arguments: Table,
    },
    /// 40.11.
    ExchangeDeclareOk,
    /// 40.20: delete an exchange.
    ExchangeDelete { exchange: String, if_unused: bool, no_wait: bool },
    /// 40.21.
    ExchangeDeleteOk,
    /// 40.30, a RabbitMQ extension: route from exchange `source` to
    /// exchange `destination`.
    ExchangeBind { destination: String, source: String, routing_key: String, no_wait: bool, arguments: Table },
    /// 40.31.
    ExchangeBindOk,
    /// 40.40, a RabbitMQ extension: undo an exchange binding.
    ExchangeUnbind { destination: String, source: String, routing_key: String, no_wait: bool, arguments: Table },
    /// 40.51.
    ExchangeUnbindOk,
    /// 50.10: create a queue, or with `passive`, check that it exists. An
    /// empty name asks the broker to choose one.
    QueueDeclare {
        queue: String,
        passive: bool,
        durable: bool,
        exclusive: bool,
        auto_delete: bool,
        no_wait: bool,
        arguments: Table,
    },
    /// 50.11: the queue's name and how many messages and consumers it has.
    QueueDeclareOk { queue: String, message_count: u32, consumer_count: u32 },
    /// 50.20: route messages from `exchange` with `routing_key` to `queue`.
    QueueBind { queue: String, exchange: String, routing_key: String, no_wait: bool, arguments: Table },
    /// 50.21.
    QueueBindOk,
    /// 50.30: drop every message in a queue.
    QueuePurge { queue: String, no_wait: bool },
    /// 50.31: how many messages were dropped.
    QueuePurgeOk { message_count: u32 },
    /// 50.40: delete a queue.
    QueueDelete { queue: String, if_unused: bool, if_empty: bool, no_wait: bool },
    /// 50.41: how many messages were dropped with it.
    QueueDeleteOk { message_count: u32 },
    /// 50.50: undo a queue binding.
    QueueUnbind { queue: String, exchange: String, routing_key: String, arguments: Table },
    /// 50.51.
    QueueUnbindOk,
    /// 60.10: how many bytes and messages may be sent to consumers before
    /// they acknowledge, on this channel or, with `global`, the
    /// connection.
    BasicQos { prefetch_size: u32, prefetch_count: u16, global: bool },
    /// 60.11.
    BasicQosOk,
    /// 60.20: start a consumer on `queue`. An empty tag asks the broker to
    /// choose one.
    BasicConsume {
        queue: String,
        consumer_tag: String,
        no_local: bool,
        no_ack: bool,
        exclusive: bool,
        no_wait: bool,
        arguments: Table,
    },
    /// 60.21: the consumer's tag.
    BasicConsumeOk { consumer_tag: String },
    /// 60.30: stop a consumer.
    BasicCancel { consumer_tag: String, no_wait: bool },
    /// 60.31.
    BasicCancelOk { consumer_tag: String },
    /// 60.40: publish the message that follows to `exchange` with
    /// `routing_key`. Content follows.
    BasicPublish { exchange: String, routing_key: String, mandatory: bool, immediate: bool },
    /// 60.50: a mandatory message could not be routed, and comes back.
    /// Content follows.
    BasicReturn { reply_code: u16, reply_text: String, exchange: String, routing_key: String },
    /// 60.60: a message for a consumer. Content follows.
    BasicDeliver { consumer_tag: String, delivery_tag: u64, redelivered: bool, exchange: String, routing_key: String },
    /// 60.70: take one message from `queue`.
    BasicGet { queue: String, no_ack: bool },
    /// 60.71: the message taken, and how many are left. Content follows.
    BasicGetOk { delivery_tag: u64, redelivered: bool, exchange: String, routing_key: String, message_count: u32 },
    /// 60.72: the queue was empty.
    BasicGetEmpty,
    /// 60.80: acknowledge a delivery, or with `multiple`, every one up to
    /// it. In confirm mode the broker sends it for publishes.
    BasicAck { delivery_tag: u64, multiple: bool },
    /// 60.90: refuse one delivery.
    BasicReject { delivery_tag: u64, requeue: bool },
    /// 60.100: redeliver unacknowledged messages, with no reply.
    BasicRecoverAsync { requeue: bool },
    /// 60.110: redeliver unacknowledged messages.
    BasicRecover { requeue: bool },
    /// 60.111.
    BasicRecoverOk,
    /// 60.120, a RabbitMQ extension: refuse a delivery, or with
    /// `multiple`, every one up to it.
    BasicNack { delivery_tag: u64, multiple: bool, requeue: bool },
    /// 85.10, a RabbitMQ extension: put the channel in confirm mode.
    ConfirmSelect { no_wait: bool },
    /// 85.11.
    ConfirmSelectOk,
    /// 90.10: put the channel in transaction mode.
    TxSelect,
    /// 90.11.
    TxSelectOk,
    /// 90.20: commit the transaction.
    TxCommit,
    /// 90.21.
    TxCommitOk,
    /// 90.30: drop the transaction.
    TxRollback,
    /// 90.31.
    TxRollbackOk,
}

impl Method {
    /// The class and method numbers.
    pub fn ids(&self) -> (u16, u16) {
        use Method::*;
        match self {
            ConnectionStart { .. } => (10, 10),
            ConnectionStartOk { .. } => (10, 11),
            ConnectionSecure { .. } => (10, 20),
            ConnectionSecureOk { .. } => (10, 21),
            ConnectionTune { .. } => (10, 30),
            ConnectionTuneOk { .. } => (10, 31),
            ConnectionOpen { .. } => (10, 40),
            ConnectionOpenOk => (10, 41),
            ConnectionClose { .. } => (10, 50),
            ConnectionCloseOk => (10, 51),
            ConnectionBlocked { .. } => (10, 60),
            ConnectionUnblocked => (10, 61),
            ConnectionUpdateSecret { .. } => (10, 70),
            ConnectionUpdateSecretOk => (10, 71),
            ChannelOpen => (20, 10),
            ChannelOpenOk => (20, 11),
            ChannelFlow { .. } => (20, 20),
            ChannelFlowOk { .. } => (20, 21),
            ChannelClose { .. } => (20, 40),
            ChannelCloseOk => (20, 41),
            ExchangeDeclare { .. } => (40, 10),
            ExchangeDeclareOk => (40, 11),
            ExchangeDelete { .. } => (40, 20),
            ExchangeDeleteOk => (40, 21),
            ExchangeBind { .. } => (40, 30),
            ExchangeBindOk => (40, 31),
            ExchangeUnbind { .. } => (40, 40),
            ExchangeUnbindOk => (40, 51),
            QueueDeclare { .. } => (50, 10),
            QueueDeclareOk { .. } => (50, 11),
            QueueBind { .. } => (50, 20),
            QueueBindOk => (50, 21),
            QueuePurge { .. } => (50, 30),
            QueuePurgeOk { .. } => (50, 31),
            QueueDelete { .. } => (50, 40),
            QueueDeleteOk { .. } => (50, 41),
            QueueUnbind { .. } => (50, 50),
            QueueUnbindOk => (50, 51),
            BasicQos { .. } => (60, 10),
            BasicQosOk => (60, 11),
            BasicConsume { .. } => (60, 20),
            BasicConsumeOk { .. } => (60, 21),
            BasicCancel { .. } => (60, 30),
            BasicCancelOk { .. } => (60, 31),
            BasicPublish { .. } => (60, 40),
            BasicReturn { .. } => (60, 50),
            BasicDeliver { .. } => (60, 60),
            BasicGet { .. } => (60, 70),
            BasicGetOk { .. } => (60, 71),
            BasicGetEmpty => (60, 72),
            BasicAck { .. } => (60, 80),
            BasicReject { .. } => (60, 90),
            BasicRecoverAsync { .. } => (60, 100),
            BasicRecover { .. } => (60, 110),
            BasicRecoverOk => (60, 111),
            BasicNack { .. } => (60, 120),
            ConfirmSelect { .. } => (85, 10),
            ConfirmSelectOk => (85, 11),
            TxSelect => (90, 10),
            TxSelectOk => (90, 11),
            TxCommit => (90, 20),
            TxCommitOk => (90, 21),
            TxRollback => (90, 30),
            TxRollbackOk => (90, 31),
        }
    }

    /// The class number.
    pub fn class_id(&self) -> u16 {
        self.ids().0
    }

    /// The method number within its class.
    pub fn method_id(&self) -> u16 {
        self.ids().1
    }

    /// Whether a content header and body follow this method.
    pub fn has_content(&self) -> bool {
        matches!(
            self,
            Method::BasicPublish { .. }
                | Method::BasicReturn { .. }
                | Method::BasicDeliver { .. }
                | Method::BasicGetOk { .. }
        )
    }
}

impl Wire for Method {
    type ParseError = DecodeError;
    type WriteError = EncodeError;

    /// Reads exactly one payload. Refuses malformed fields, excess nesting, oversized input, and trailing bytes.
    fn parse(payload: &[u8]) -> Result<Method, DecodeError> {
        use Method::*;
        let mut r = Reader::payload(payload)?;
        let class_id = r.u16()?;
        let method_id = r.u16()?;
        let m = match (class_id, method_id) {
            (10, 10) => ConnectionStart {
                version_major: r.u8()?,
                version_minor: r.u8()?,
                server_properties: r.table(1)?,
                mechanisms: r.longstr()?,
                locales: r.longstr()?,
            },
            (10, 11) => ConnectionStartOk {
                client_properties: r.table(1)?,
                mechanism: r.shortstr()?,
                response: r.longstr()?,
                locale: r.shortstr()?,
            },
            (10, 20) => ConnectionSecure { challenge: r.longstr()? },
            (10, 21) => ConnectionSecureOk { response: r.longstr()? },
            (10, 30) => ConnectionTune { channel_max: r.u16()?, frame_max: r.u32()?, heartbeat: r.u16()? },
            (10, 31) => ConnectionTuneOk { channel_max: r.u16()?, frame_max: r.u32()?, heartbeat: r.u16()? },
            (10, 40) => {
                let virtual_host = r.shortstr()?;
                r.skip_shortstr()?;
                r.bit()?;
                ConnectionOpen { virtual_host }
            }
            (10, 41) => {
                r.skip_shortstr()?;
                ConnectionOpenOk
            }
            (10, 50) => ConnectionClose {
                reply_code: r.u16()?,
                reply_text: r.shortstr()?,
                class_id: r.u16()?,
                method_id: r.u16()?,
            },
            (10, 51) => ConnectionCloseOk,
            (10, 60) => ConnectionBlocked { reason: r.shortstr()? },
            (10, 61) => ConnectionUnblocked,
            (10, 70) => ConnectionUpdateSecret { new_secret: r.longstr()?, reason: r.shortstr()? },
            (10, 71) => ConnectionUpdateSecretOk,
            (20, 10) => {
                r.skip_shortstr()?;
                ChannelOpen
            }
            (20, 11) => {
                r.long_bytes()?;
                ChannelOpenOk
            }
            (20, 20) => ChannelFlow { active: r.bit()? },
            (20, 21) => ChannelFlowOk { active: r.bit()? },
            (20, 40) => ChannelClose {
                reply_code: r.u16()?,
                reply_text: r.shortstr()?,
                class_id: r.u16()?,
                method_id: r.u16()?,
            },
            (20, 41) => ChannelCloseOk,
            (40, 10) => {
                r.u16()?;
                ExchangeDeclare {
                    exchange: r.shortstr()?,
                    kind: r.shortstr()?,
                    passive: r.bit()?,
                    durable: r.bit()?,
                    auto_delete: r.bit()?,
                    internal: r.bit()?,
                    no_wait: r.bit()?,
                    arguments: r.table(1)?,
                }
            }
            (40, 11) => ExchangeDeclareOk,
            (40, 20) => {
                r.u16()?;
                ExchangeDelete { exchange: r.shortstr()?, if_unused: r.bit()?, no_wait: r.bit()? }
            }
            (40, 21) => ExchangeDeleteOk,
            (40, 30) | (40, 40) => {
                r.u16()?;
                let (destination, source, routing_key) = (r.shortstr()?, r.shortstr()?, r.shortstr()?);
                let (no_wait, arguments) = (r.bit()?, r.table(1)?);
                if method_id == 30 {
                    ExchangeBind { destination, source, routing_key, no_wait, arguments }
                } else {
                    ExchangeUnbind { destination, source, routing_key, no_wait, arguments }
                }
            }
            (40, 31) => ExchangeBindOk,
            (40, 51) => ExchangeUnbindOk,
            (50, 10) => {
                r.u16()?;
                QueueDeclare {
                    queue: r.shortstr()?,
                    passive: r.bit()?,
                    durable: r.bit()?,
                    exclusive: r.bit()?,
                    auto_delete: r.bit()?,
                    no_wait: r.bit()?,
                    arguments: r.table(1)?,
                }
            }
            (50, 11) => QueueDeclareOk { queue: r.shortstr()?, message_count: r.u32()?, consumer_count: r.u32()? },
            (50, 20) => {
                r.u16()?;
                QueueBind {
                    queue: r.shortstr()?,
                    exchange: r.shortstr()?,
                    routing_key: r.shortstr()?,
                    no_wait: r.bit()?,
                    arguments: r.table(1)?,
                }
            }
            (50, 21) => QueueBindOk,
            (50, 30) => {
                r.u16()?;
                QueuePurge { queue: r.shortstr()?, no_wait: r.bit()? }
            }
            (50, 31) => QueuePurgeOk { message_count: r.u32()? },
            (50, 40) => {
                r.u16()?;
                QueueDelete { queue: r.shortstr()?, if_unused: r.bit()?, if_empty: r.bit()?, no_wait: r.bit()? }
            }
            (50, 41) => QueueDeleteOk { message_count: r.u32()? },
            (50, 50) => {
                r.u16()?;
                QueueUnbind {
                    queue: r.shortstr()?,
                    exchange: r.shortstr()?,
                    routing_key: r.shortstr()?,
                    arguments: r.table(1)?,
                }
            }
            (50, 51) => QueueUnbindOk,
            (60, 10) => BasicQos { prefetch_size: r.u32()?, prefetch_count: r.u16()?, global: r.bit()? },
            (60, 11) => BasicQosOk,
            (60, 20) => {
                r.u16()?;
                BasicConsume {
                    queue: r.shortstr()?,
                    consumer_tag: r.shortstr()?,
                    no_local: r.bit()?,
                    no_ack: r.bit()?,
                    exclusive: r.bit()?,
                    no_wait: r.bit()?,
                    arguments: r.table(1)?,
                }
            }
            (60, 21) => BasicConsumeOk { consumer_tag: r.shortstr()? },
            (60, 30) => BasicCancel { consumer_tag: r.shortstr()?, no_wait: r.bit()? },
            (60, 31) => BasicCancelOk { consumer_tag: r.shortstr()? },
            (60, 40) => {
                r.u16()?;
                BasicPublish {
                    exchange: r.shortstr()?,
                    routing_key: r.shortstr()?,
                    mandatory: r.bit()?,
                    immediate: r.bit()?,
                }
            }
            (60, 50) => BasicReturn {
                reply_code: r.u16()?,
                reply_text: r.shortstr()?,
                exchange: r.shortstr()?,
                routing_key: r.shortstr()?,
            },
            (60, 60) => BasicDeliver {
                consumer_tag: r.shortstr()?,
                delivery_tag: r.u64()?,
                redelivered: r.bit()?,
                exchange: r.shortstr()?,
                routing_key: r.shortstr()?,
            },
            (60, 70) => {
                r.u16()?;
                BasicGet { queue: r.shortstr()?, no_ack: r.bit()? }
            }
            (60, 71) => BasicGetOk {
                delivery_tag: r.u64()?,
                redelivered: r.bit()?,
                exchange: r.shortstr()?,
                routing_key: r.shortstr()?,
                message_count: r.u32()?,
            },
            (60, 72) => {
                r.skip_shortstr()?;
                BasicGetEmpty
            }
            (60, 80) => BasicAck { delivery_tag: r.u64()?, multiple: r.bit()? },
            (60, 90) => BasicReject { delivery_tag: r.u64()?, requeue: r.bit()? },
            (60, 100) => BasicRecoverAsync { requeue: r.bit()? },
            (60, 110) => BasicRecover { requeue: r.bit()? },
            (60, 111) => BasicRecoverOk,
            (60, 120) => BasicNack { delivery_tag: r.u64()?, multiple: r.bit()?, requeue: r.bit()? },
            (85, 10) => ConfirmSelect { no_wait: r.bit()? },
            (85, 11) => ConfirmSelectOk,
            (90, 10) => TxSelect,
            (90, 11) => TxSelectOk,
            (90, 20) => TxCommit,
            (90, 21) => TxCommitOk,
            (90, 30) => TxRollback,
            (90, 31) => TxRollbackOk,
            _ => return Err(DecodeError::UnknownMethod { class_id, method_id }),
        };
        r.finish()?;
        Ok(m)
    }

    /// Appends the complete value. Refuses invalid fields, excess nesting,
    /// or size limits. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use Method::*;
        let mut w = Writer::new();
        let (class_id, method_id) = self.ids();
        w.u16(class_id);
        w.u16(method_id);
        match self {
            ConnectionStart { version_major, version_minor, server_properties, mechanisms, locales } => {
                w.u8(*version_major);
                w.u8(*version_minor);
                w.table(server_properties, 1)?;
                w.longstr(mechanisms)?;
                w.longstr(locales)?;
            }
            ConnectionStartOk { client_properties, mechanism, response, locale } => {
                w.table(client_properties, 1)?;
                w.shortstr(mechanism)?;
                w.longstr(response)?;
                w.shortstr(locale)?;
            }
            ConnectionSecure { challenge: b } | ConnectionSecureOk { response: b } => w.longstr(b)?,
            ConnectionTune { channel_max, frame_max, heartbeat }
            | ConnectionTuneOk { channel_max, frame_max, heartbeat } => {
                w.u16(*channel_max);
                w.u32(*frame_max);
                w.u16(*heartbeat);
            }
            ConnectionOpen { virtual_host } => {
                w.shortstr(virtual_host)?;
                w.shortstr("")?;
                w.bit(false);
            }
            ConnectionOpenOk | ChannelOpen | BasicGetEmpty => w.shortstr("")?,
            ConnectionClose { reply_code, reply_text, class_id, method_id }
            | ChannelClose { reply_code, reply_text, class_id, method_id } => {
                w.u16(*reply_code);
                w.shortstr(reply_text)?;
                w.u16(*class_id);
                w.u16(*method_id);
            }
            ConnectionBlocked { reason } => w.shortstr(reason)?,
            ConnectionUpdateSecret { new_secret, reason } => {
                w.longstr(new_secret)?;
                w.shortstr(reason)?;
            }
            ChannelOpenOk => w.longstr(&[])?,
            ChannelFlow { active } | ChannelFlowOk { active } => w.bit(*active),
            ExchangeDeclare { exchange, kind, passive, durable, auto_delete, internal, no_wait, arguments } => {
                w.u16(0);
                w.shortstr(exchange)?;
                w.shortstr(kind)?;
                for b in [passive, durable, auto_delete, internal, no_wait] {
                    w.bit(*b);
                }
                w.table(arguments, 1)?;
            }
            ExchangeDelete { exchange, if_unused, no_wait } => {
                w.u16(0);
                w.shortstr(exchange)?;
                w.bit(*if_unused);
                w.bit(*no_wait);
            }
            ExchangeBind { destination, source, routing_key, no_wait, arguments }
            | ExchangeUnbind { destination, source, routing_key, no_wait, arguments } => {
                w.u16(0);
                w.shortstr(destination)?;
                w.shortstr(source)?;
                w.shortstr(routing_key)?;
                w.bit(*no_wait);
                w.table(arguments, 1)?;
            }
            QueueDeclare { queue, passive, durable, exclusive, auto_delete, no_wait, arguments } => {
                w.u16(0);
                w.shortstr(queue)?;
                for b in [passive, durable, exclusive, auto_delete, no_wait] {
                    w.bit(*b);
                }
                w.table(arguments, 1)?;
            }
            QueueDeclareOk { queue, message_count, consumer_count } => {
                w.shortstr(queue)?;
                w.u32(*message_count);
                w.u32(*consumer_count);
            }
            QueueBind { queue, exchange, routing_key, no_wait, arguments } => {
                w.u16(0);
                w.shortstr(queue)?;
                w.shortstr(exchange)?;
                w.shortstr(routing_key)?;
                w.bit(*no_wait);
                w.table(arguments, 1)?;
            }
            QueuePurge { queue, no_wait } => {
                w.u16(0);
                w.shortstr(queue)?;
                w.bit(*no_wait);
            }
            QueuePurgeOk { message_count } | QueueDeleteOk { message_count } => w.u32(*message_count),
            QueueDelete { queue, if_unused, if_empty, no_wait } => {
                w.u16(0);
                w.shortstr(queue)?;
                w.bit(*if_unused);
                w.bit(*if_empty);
                w.bit(*no_wait);
            }
            QueueUnbind { queue, exchange, routing_key, arguments } => {
                w.u16(0);
                w.shortstr(queue)?;
                w.shortstr(exchange)?;
                w.shortstr(routing_key)?;
                w.table(arguments, 1)?;
            }
            BasicQos { prefetch_size, prefetch_count, global } => {
                w.u32(*prefetch_size);
                w.u16(*prefetch_count);
                w.bit(*global);
            }
            BasicConsume { queue, consumer_tag, no_local, no_ack, exclusive, no_wait, arguments } => {
                w.u16(0);
                w.shortstr(queue)?;
                w.shortstr(consumer_tag)?;
                for b in [no_local, no_ack, exclusive, no_wait] {
                    w.bit(*b);
                }
                w.table(arguments, 1)?;
            }
            BasicConsumeOk { consumer_tag } | BasicCancelOk { consumer_tag } => w.shortstr(consumer_tag)?,
            BasicCancel { consumer_tag, no_wait } => {
                w.shortstr(consumer_tag)?;
                w.bit(*no_wait);
            }
            BasicPublish { exchange, routing_key, mandatory, immediate } => {
                w.u16(0);
                w.shortstr(exchange)?;
                w.shortstr(routing_key)?;
                w.bit(*mandatory);
                w.bit(*immediate);
            }
            BasicReturn { reply_code, reply_text, exchange, routing_key } => {
                w.u16(*reply_code);
                w.shortstr(reply_text)?;
                w.shortstr(exchange)?;
                w.shortstr(routing_key)?;
            }
            BasicDeliver { consumer_tag, delivery_tag, redelivered, exchange, routing_key } => {
                w.shortstr(consumer_tag)?;
                w.u64(*delivery_tag);
                w.bit(*redelivered);
                w.shortstr(exchange)?;
                w.shortstr(routing_key)?;
            }
            BasicGet { queue, no_ack } => {
                w.u16(0);
                w.shortstr(queue)?;
                w.bit(*no_ack);
            }
            BasicGetOk { delivery_tag, redelivered, exchange, routing_key, message_count } => {
                w.u64(*delivery_tag);
                w.bit(*redelivered);
                w.shortstr(exchange)?;
                w.shortstr(routing_key)?;
                w.u32(*message_count);
            }
            BasicAck { delivery_tag, multiple: flag } | BasicReject { delivery_tag, requeue: flag } => {
                w.u64(*delivery_tag);
                w.bit(*flag);
            }
            BasicRecoverAsync { requeue } | BasicRecover { requeue } => w.bit(*requeue),
            BasicNack { delivery_tag, multiple, requeue } => {
                w.u64(*delivery_tag);
                w.bit(*multiple);
                w.bit(*requeue);
            }
            ConfirmSelect { no_wait } => w.bit(*no_wait),
            ConnectionCloseOk
            | ConnectionUnblocked
            | ConnectionUpdateSecretOk
            | ChannelCloseOk
            | ExchangeDeclareOk
            | ExchangeDeleteOk
            | ExchangeBindOk
            | ExchangeUnbindOk
            | QueueBindOk
            | QueueUnbindOk
            | BasicQosOk
            | BasicRecoverOk
            | ConfirmSelectOk
            | TxSelect
            | TxSelectOk
            | TxCommit
            | TxCommitOk
            | TxRollback
            | TxRollbackOk => {}
        }
        let bytes = w.finish()?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Reads fields from a payload, front to back. Bits share an octet with
/// the bits right before them, lowest bit first, as the specification
/// packs them.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    bit_byte: u8,
    /// The next bit of `bit_byte` to read, or 0 when no bit octet is open.
    bit_next: u8,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0, bit_byte: 0, bit_next: 0 }
    }

    /// A reader for a whole payload. A payload no frame can hold is
    /// refused, since what it holds could not be written back.
    fn payload(b: &'a [u8]) -> Result<Reader<'a>, DecodeError> {
        if b.len() > MAX_PAYLOAD {
            return Err(DecodeError::TooLarge(b.len()));
        }
        Ok(Reader::new(b))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        self.bit_next = 0;
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let s = self.b.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        self.array().map(u64::from_be_bytes)
    }

    fn bit(&mut self) -> Result<bool, DecodeError> {
        if self.bit_next == 0 || self.bit_next >= 8 {
            self.bit_byte = self.u8()?;
        }
        let v = self.bit_byte >> self.bit_next & 1 == 1;
        self.bit_next += 1;
        Ok(v)
    }

    fn skip_shortstr(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    fn shortstr(&mut self) -> Result<String, DecodeError> {
        let b = self.skip_shortstr()?;
        if b.contains(&0) {
            return Err(DecodeError::ZeroByte);
        }
        std::str::from_utf8(b).map(str::to_owned).map_err(|_| DecodeError::Utf8)
    }

    fn long_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u32()?;
        self.take(usize::try_from(n).unwrap_or(usize::MAX))
    }

    fn longstr(&mut self) -> Result<Vec<u8>, DecodeError> {
        self.long_bytes().map(<[u8]>::to_vec)
    }

    fn table(&mut self, depth: usize) -> Result<Table, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::TooDeep);
        }
        let mut inner = Reader::new(self.long_bytes()?);
        let mut entries = Vec::new();
        while inner.pos < inner.b.len() {
            let name = inner.shortstr()?;
            let value = inner.value(depth)?;
            entries.push((name, value));
        }
        if has_duplicates(&entries) {
            return Err(DecodeError::DuplicateField);
        }
        Ok(Table { entries })
    }

    fn value(&mut self, depth: usize) -> Result<FieldValue, DecodeError> {
        Ok(match self.u8()? {
            b't' => FieldValue::Bool(self.u8()? != 0),
            b'b' => FieldValue::I8(i8::from_be_bytes(self.array()?)),
            b'B' => FieldValue::U8(self.u8()?),
            b's' => FieldValue::I16(i16::from_be_bytes(self.array()?)),
            b'u' => FieldValue::U16(self.u16()?),
            b'I' => FieldValue::I32(i32::from_be_bytes(self.array()?)),
            b'i' => FieldValue::U32(self.u32()?),
            b'l' | b'L' => FieldValue::I64(i64::from_be_bytes(self.array()?)),
            b'f' => FieldValue::F32(f32::from_be_bytes(self.array()?)),
            b'd' => FieldValue::F64(f64::from_be_bytes(self.array()?)),
            b'D' => FieldValue::Decimal { scale: self.u8()?, value: i32::from_be_bytes(self.array()?) },
            b'S' => FieldValue::LongString(self.longstr()?),
            b'A' => {
                if depth + 1 > MAX_DEPTH {
                    return Err(DecodeError::TooDeep);
                }
                let mut inner = Reader::new(self.long_bytes()?);
                let mut values = Vec::new();
                while inner.pos < inner.b.len() {
                    values.push(inner.value(depth + 1)?);
                }
                FieldValue::Array(values)
            }
            b'T' => FieldValue::Timestamp(self.u64()?),
            b'F' => FieldValue::Table(self.table(depth + 1)?),
            b'V' => FieldValue::Void,
            b'x' => FieldValue::Bytes(self.longstr()?),
            t => return Err(DecodeError::FieldType(t)),
        })
    }

    fn finish(&self) -> Result<(), DecodeError> {
        if self.pos == self.b.len() { Ok(()) } else { Err(DecodeError::TrailingBytes) }
    }
}

/// Whether two entries share a name, found by sorting references to the
/// names, so a large table costs n log n time and no copies.
fn has_duplicates(entries: &[(String, FieldValue)]) -> bool {
    let mut names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    names.windows(2).any(|w| w[0] == w[1])
}

/// Writes fields into a payload, packing bits as [`Reader`] reads them.
struct Writer {
    out: Vec<u8>,
    /// The open bit octet's index and how many of its bits are used.
    bits: Option<(usize, u8)>,
}

impl Writer {
    fn new() -> Writer {
        Writer { out: Vec::new(), bits: None }
    }

    fn bytes(&mut self, b: &[u8]) {
        self.bits = None;
        self.out.extend_from_slice(b);
    }

    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }

    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_be_bytes());
    }

    fn bit(&mut self, v: bool) {
        match self.bits {
            Some((i, n)) if n < 8 => {
                if v && let Some(b) = self.out.get_mut(i) {
                    *b |= 1 << n;
                }
                self.bits = Some((i, n + 1));
            }
            _ => {
                self.out.push(u8::from(v));
                self.bits = Some((self.out.len() - 1, 1));
            }
        }
    }

    fn shortstr(&mut self, s: &str) -> Result<(), EncodeError> {
        let n = u8::try_from(s.len()).map_err(|_| EncodeError::Unwritable)?;
        if s.as_bytes().contains(&0) {
            return Err(EncodeError::Unwritable);
        }
        self.u8(n);
        self.bytes(s.as_bytes());
        Ok(())
    }

    fn longstr(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        if b.len() > MAX_PAYLOAD {
            return Err(EncodeError::Unwritable);
        }
        self.u32(b.len() as u32);
        self.bytes(b);
        self.check()
    }

    /// Writes a 4-byte length, then whatever `body` writes, then fills in
    /// the length.
    fn counted(&mut self, body: impl FnOnce(&mut Writer) -> Result<(), EncodeError>) -> Result<(), EncodeError> {
        let at = self.out.len();
        self.u32(0);
        body(self)?;
        let len = self.out.len() - at - 4;
        if len > MAX_PAYLOAD {
            return Err(EncodeError::Unwritable);
        }
        self.out[at..at + 4].copy_from_slice(&(len as u32).to_be_bytes());
        self.bits = None;
        Ok(())
    }

    fn table(&mut self, t: &Table, depth: usize) -> Result<(), EncodeError> {
        if depth > MAX_DEPTH {
            return Err(EncodeError::Unwritable);
        }
        if t.entries.len() > MAX_PAYLOAD / 2 || has_duplicates(&t.entries) {
            return Err(EncodeError::Unwritable);
        }
        self.counted(|w| {
            for (name, value) in &t.entries {
                w.shortstr(name)?;
                w.value(value, depth)?;
                w.check()?;
            }
            Ok(())
        })
    }

    fn value(&mut self, v: &FieldValue, depth: usize) -> Result<(), EncodeError> {
        match v {
            FieldValue::Bool(b) => self.bytes(&[b't', u8::from(*b)]),
            FieldValue::I8(n) => self.bytes(&[b'b', n.to_be_bytes()[0]]),
            FieldValue::U8(n) => self.bytes(&[b'B', *n]),
            FieldValue::I16(n) => {
                self.u8(b's');
                self.bytes(&n.to_be_bytes());
            }
            FieldValue::U16(n) => {
                self.u8(b'u');
                self.u16(*n);
            }
            FieldValue::I32(n) => {
                self.u8(b'I');
                self.bytes(&n.to_be_bytes());
            }
            FieldValue::U32(n) => {
                self.u8(b'i');
                self.u32(*n);
            }
            FieldValue::I64(n) => {
                self.u8(b'l');
                self.bytes(&n.to_be_bytes());
            }
            FieldValue::F32(n) => {
                self.u8(b'f');
                self.bytes(&n.to_be_bytes());
            }
            FieldValue::F64(n) => {
                self.u8(b'd');
                self.bytes(&n.to_be_bytes());
            }
            FieldValue::Decimal { scale, value } => {
                self.u8(b'D');
                self.u8(*scale);
                self.bytes(&value.to_be_bytes());
            }
            FieldValue::LongString(b) => {
                self.u8(b'S');
                self.longstr(b)?;
            }
            FieldValue::Array(values) => {
                if depth + 1 > MAX_DEPTH {
                    return Err(EncodeError::Unwritable);
                }
                self.u8(b'A');
                self.counted(|w| {
                    for v in values {
                        w.value(v, depth + 1)?;
                        w.check()?;
                    }
                    Ok(())
                })?;
            }
            FieldValue::Timestamp(t) => {
                self.u8(b'T');
                self.u64(*t);
            }
            FieldValue::Table(t) => {
                self.u8(b'F');
                self.table(t, depth + 1)?;
            }
            FieldValue::Void => self.u8(b'V'),
            FieldValue::Bytes(b) => {
                self.u8(b'x');
                self.longstr(b)?;
            }
        }
        Ok(())
    }

    /// Stops a writer whose output has grown past what any frame holds, so
    /// a huge table costs no more than one frame's memory to refuse.
    fn check(&self) -> Result<(), EncodeError> {
        if self.out.len() > MAX_PAYLOAD { Err(EncodeError::Unwritable) } else { Ok(()) }
    }

    fn finish(self) -> Result<Vec<u8>, EncodeError> {
        self.check()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{
        Fail, Stream, contract, pump,
        test_support::{Lcg, decode_all, mutate},
    };

    fn s(v: &str) -> String {
        v.to_string()
    }

    fn sample_table() -> Table {
        let mut inner = Table::new();
        inner.insert("publisher_confirms", FieldValue::Bool(true));
        let mut t = Table::new();
        t.insert("capabilities", FieldValue::Table(inner));
        t.insert("product", FieldValue::LongString(b"RabbitMQ".to_vec()));
        t.insert("x-max-length", FieldValue::I32(1000));
        t.insert(
            "all",
            FieldValue::Array(vec![
                FieldValue::Bool(false),
                FieldValue::I8(-3),
                FieldValue::U8(250),
                FieldValue::I16(-30000),
                FieldValue::U16(65000),
                FieldValue::I32(-7),
                FieldValue::U32(4_000_000_000),
                FieldValue::I64(i64::MIN),
                FieldValue::F32(1.5),
                FieldValue::F64(-2.25),
                FieldValue::Decimal { scale: 2, value: 12345 },
                FieldValue::LongString(vec![0, 255, 7]),
                FieldValue::Array(vec![]),
                FieldValue::Timestamp(1_700_000_000),
                FieldValue::Table(Table::new()),
                FieldValue::Void,
                FieldValue::Bytes(vec![1, 2, 3]),
            ]),
        );
        t
    }

    /// The channel a method may go on: 0 for the connection class, and 5
    /// for the rest.
    fn channel_for(m: &Method) -> u16 {
        if m.class_id() == class::CONNECTION { 0 } else { 5 }
    }

    /// One of every method, with arguments that are not all zero.
    fn every_method() -> Vec<Method> {
        use Method::*;
        let t = sample_table;
        vec![
            ConnectionStart {
                version_major: 0,
                version_minor: 9,
                server_properties: t(),
                mechanisms: b"PLAIN AMQPLAIN".to_vec(),
                locales: b"en_US".to_vec(),
            },
            ConnectionStartOk {
                client_properties: t(),
                mechanism: s("PLAIN"),
                response: b"\0guest\0guest".to_vec(),
                locale: s("en_US"),
            },
            ConnectionSecure { challenge: vec![1, 2] },
            ConnectionSecureOk { response: vec![3] },
            ConnectionTune { channel_max: 2047, frame_max: 131072, heartbeat: 60 },
            ConnectionTuneOk { channel_max: 2047, frame_max: 131072, heartbeat: 60 },
            ConnectionOpen { virtual_host: s("/") },
            ConnectionOpenOk,
            ConnectionClose { reply_code: 320, reply_text: s("CONNECTION_FORCED"), class_id: 0, method_id: 0 },
            ConnectionCloseOk,
            ConnectionBlocked { reason: s("low on memory") },
            ConnectionUnblocked,
            ConnectionUpdateSecret { new_secret: b"token".to_vec(), reason: s("refresh") },
            ConnectionUpdateSecretOk,
            ChannelOpen,
            ChannelOpenOk,
            ChannelFlow { active: true },
            ChannelFlowOk { active: false },
            ChannelClose { reply_code: 404, reply_text: s("NOT_FOUND - no queue 'x'"), class_id: 50, method_id: 10 },
            ChannelCloseOk,
            ExchangeDeclare {
                exchange: s("logs"),
                kind: s("fanout"),
                passive: false,
                durable: true,
                auto_delete: false,
                internal: true,
                no_wait: false,
                arguments: t(),
            },
            ExchangeDeclareOk,
            ExchangeDelete { exchange: s("logs"), if_unused: true, no_wait: true },
            ExchangeDeleteOk,
            ExchangeBind {
                destination: s("a"),
                source: s("b"),
                routing_key: s("k.#"),
                no_wait: true,
                arguments: Table::new(),
            },
            ExchangeBindOk,
            ExchangeUnbind { destination: s("a"), source: s("b"), routing_key: s(""), no_wait: false, arguments: t() },
            ExchangeUnbindOk,
            QueueDeclare {
                queue: s("tasks"),
                passive: true,
                durable: false,
                exclusive: true,
                auto_delete: false,
                no_wait: true,
                arguments: t(),
            },
            QueueDeclareOk { queue: s("amq.gen-abc"), message_count: 5, consumer_count: 1 },
            QueueBind { queue: s("q"), exchange: s("e"), routing_key: s("r"), no_wait: true, arguments: t() },
            QueueBindOk,
            QueuePurge { queue: s("q"), no_wait: true },
            QueuePurgeOk { message_count: 9 },
            QueueDelete { queue: s("q"), if_unused: false, if_empty: true, no_wait: true },
            QueueDeleteOk { message_count: u32::MAX },
            QueueUnbind { queue: s("q"), exchange: s("e"), routing_key: s("r"), arguments: Table::new() },
            QueueUnbindOk,
            BasicQos { prefetch_size: 0, prefetch_count: 10, global: true },
            BasicQosOk,
            BasicConsume {
                queue: s("q"),
                consumer_tag: s("ctag"),
                no_local: false,
                no_ack: true,
                exclusive: false,
                no_wait: true,
                arguments: t(),
            },
            BasicConsumeOk { consumer_tag: s("ctag") },
            BasicCancel { consumer_tag: s("ctag"), no_wait: true },
            BasicCancelOk { consumer_tag: s("ctag") },
            BasicPublish { exchange: s(""), routing_key: s("q"), mandatory: true, immediate: false },
            BasicReturn { reply_code: 312, reply_text: s("NO_ROUTE"), exchange: s("e"), routing_key: s("r") },
            BasicDeliver {
                consumer_tag: s("ctag"),
                delivery_tag: u64::MAX,
                redelivered: true,
                exchange: s("e"),
                routing_key: s("r"),
            },
            BasicGet { queue: s("q"), no_ack: true },
            BasicGetOk { delivery_tag: 1, redelivered: false, exchange: s("e"), routing_key: s("r"), message_count: 3 },
            BasicGetEmpty,
            BasicAck { delivery_tag: 7, multiple: true },
            BasicReject { delivery_tag: 8, requeue: true },
            BasicRecoverAsync { requeue: true },
            BasicRecover { requeue: false },
            BasicRecoverOk,
            BasicNack { delivery_tag: 9, multiple: false, requeue: true },
            ConfirmSelect { no_wait: true },
            ConfirmSelectOk,
            TxSelect,
            TxSelectOk,
            TxCommit,
            TxCommitOk,
            TxRollback,
            TxRollbackOk,
        ]
    }

    fn full_properties() -> BasicProperties {
        BasicProperties {
            content_type: Some(s("application/json")),
            content_encoding: Some(s("gzip")),
            headers: Some(sample_table()),
            delivery_mode: Some(2),
            priority: Some(5),
            correlation_id: Some(s("c1")),
            reply_to: Some(s("amq.rabbitmq.reply-to")),
            expiration: Some(s("60000")),
            message_id: Some(s("m1")),
            timestamp: Some(1_700_000_000),
            kind: Some(s("order.created")),
            user_id: Some(s("guest")),
            app_id: Some(s("shop")),
            cluster_id: Some(s("")),
        }
    }

    #[test]
    fn protocol_header_and_server_decoder() {
        assert_eq!(&PROTOCOL_HEADER, b"AMQP\x00\x00\x09\x01");
        let mut stream = Stream::new(Frames::server());
        assert_eq!(stream.push(&PROTOCOL_HEADER[..7]), 7);
        assert_eq!(stream.next(), None);
        assert!(!stream.decoder().header_received());
        assert_eq!(stream.push(&PROTOCOL_HEADER[7..]), 1);
        assert_eq!(stream.next(), None);
        assert!(stream.decoder().header_received());
        let bytes = Frame::heartbeat().to_bytes().unwrap();
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Ok(Frame::heartbeat())));
        for header in [b"AMQP\x00\x01\x00\x00", b"GET / HT"] {
            assert_eq!(decode_all(Frames::server, header).1, Some(Fail::Protocol(FrameError::ProtocolHeader(*header))));
        }
        assert_eq!(decode_all(Frames::new, &PROTOCOL_HEADER).1, Some(Fail::Protocol(FrameError::Type(b'A'))));
    }

    #[test]
    fn tune_example() {
        // connection.tune as RabbitMQ sends it: channel-max 2047,
        // frame-max 131072, heartbeat 60.
        let bytes = [1, 0, 0, 0, 0, 0, 12, 0, 10, 0, 30, 0x07, 0xff, 0, 2, 0, 0, 0, 60, 0xce];
        let frame = Frame::parse(&bytes).unwrap();
        assert_eq!((frame.kind, frame.channel), (FrameKind::Method, 0));
        let m = Method::parse(&frame.payload).unwrap();
        assert_eq!(m, Method::ConnectionTune { channel_max: 2047, frame_max: 131072, heartbeat: 60 });
        assert_eq!(Frame::method(0, &m).unwrap().to_bytes().unwrap(), bytes);
    }

    #[test]
    fn heartbeat_example() {
        assert_eq!(Frame::heartbeat().to_bytes().unwrap(), [8, 0, 0, 0, 0, 0, 0, 0xce]);
        // A heartbeat off channel 0, or with a payload, is refused rather
        // than written as something else.
        let odd = Frame { kind: FrameKind::Heartbeat, channel: 3, payload: vec![1] };
        assert_eq!(odd.to_bytes(), Err(EncodeError::Unwritable));
        let odd = Frame { kind: FrameKind::Heartbeat, channel: 0, payload: vec![1] };
        assert_eq!(odd.to_bytes(), Err(EncodeError::Unwritable));
        assert_eq!(FrameError::Heartbeat { channel: 3, size: 0 }.reply_code(), 503);
        assert_eq!(FrameError::Heartbeat { channel: 0, size: 1 }.reply_code(), 501);
    }

    #[test]
    fn bits_pack_into_one_octet() {
        // queue.declare: ticket, "q", then passive, durable, exclusive,
        // auto-delete and no-wait in one octet, then an empty table.
        let m = Method::QueueDeclare {
            queue: s("q"),
            passive: false,
            durable: true,
            exclusive: false,
            auto_delete: false,
            no_wait: true,
            arguments: Table::new(),
        };
        assert_eq!(m.to_bytes().unwrap(), [0, 50, 0, 10, 0, 0, 1, b'q', 0b10010, 0, 0, 0, 0]);
        // basic.deliver: a bit octet between a long-long and a short string.
        let m = Method::BasicDeliver {
            consumer_tag: s("c"),
            delivery_tag: 1,
            redelivered: true,
            exchange: s(""),
            routing_key: s("k"),
        };
        assert_eq!(m.to_bytes().unwrap(), [0, 60, 0, 60, 1, b'c', 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, b'k']);
        // basic.nack's two bits share one octet.
        let m = Method::BasicNack { delivery_tag: 2, multiple: true, requeue: true };
        assert_eq!(m.to_bytes().unwrap(), [0, 60, 0, 120, 0, 0, 0, 0, 0, 0, 0, 2, 0b11]);
        // Unused bits are ignored when read.
        let p = [0, 60, 0, 120, 0, 0, 0, 0, 0, 0, 0, 2, 0xfd];
        assert_eq!(Method::parse(&p), Ok(Method::BasicNack { delivery_tag: 2, multiple: true, requeue: false }));
    }

    #[test]
    fn table_example() {
        let mut t = Table::new();
        t.insert("a", FieldValue::I32(1));
        t.insert("b", FieldValue::LongString(b"hi".to_vec()));
        let bytes = [0, 0, 0, 16, 1, b'a', b'I', 0, 0, 0, 1, 1, b'b', b'S', 0, 0, 0, 2, b'h', b'i'];
        assert_eq!(t.to_bytes().unwrap(), bytes);
        assert_eq!(Table::parse(&bytes), Ok(t.clone()));
        assert_eq!(t.get("b"), Some(&FieldValue::LongString(b"hi".to_vec())));
        assert_eq!(t.get("c"), None);
        t.insert("a", FieldValue::Void);
        assert_eq!(t.entries.len(), 2);
        assert_eq!(t.get("a"), Some(&FieldValue::Void));
        // Every value type reads back.
        let t = sample_table();
        assert_eq!(Table::parse(&t.to_bytes().unwrap()), Ok(t));
    }

    #[test]
    fn rabbitmq_unsigned_and_spec_long_tags() {
        // RabbitMQ's table has 'u' (u16) and 'i' (u32), and its parser
        // reads the 0-9 tag 'L' as a signed 64-bit integer.
        let bytes = [
            0, 0, 0, 23, 1, b'u', b'u', 0xff, 0xfe, 1, b'i', b'i', 0xff, 0xff, 0xff, 0xfd, 1, b'L', b'L', 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let t = Table::parse(&bytes).unwrap();
        assert_eq!(t.get("u"), Some(&FieldValue::U16(0xfffe)));
        assert_eq!(t.get("i"), Some(&FieldValue::U32(0xffff_fffd)));
        assert_eq!(t.get("L"), Some(&FieldValue::I64(-1)));
        // 'L' is written back as 'l', RabbitMQ's tag; the rest are kept.
        let mut out = bytes.to_vec();
        out[18] = b'l';
        assert_eq!(t.to_bytes().unwrap(), out);
        for n in 0..bytes.len() {
            assert!(Table::parse(&bytes[..n]).is_err(), "cut to {n}");
        }
        // The 0-9 tag 'U' stays unknown, as in RabbitMQ, and so does a tag
        // no table uses.
        assert_eq!(Table::parse(&[0, 0, 0, 5, 1, b'a', b'U', 0, 1]), Err(DecodeError::FieldType(b'U')));
        assert_eq!(Table::parse(&[0, 0, 0, 4, 1, b'a', b'z', 0]), Err(DecodeError::FieldType(b'z')));
    }

    #[test]
    fn every_method_round_trips() {
        let all = every_method();
        assert_eq!(all.len(), 64);
        let mut ids: Vec<_> = all.iter().map(Method::ids).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), all.len());
        for m in &all {
            let p = m.to_bytes().unwrap();
            assert_eq!(Method::parse(&p).as_ref(), Ok(m), "{m:?}");
            assert_eq!(p[..4], [(m.class_id() >> 8) as u8, m.class_id() as u8, 0, m.method_id() as u8]);
            let f = Frame::method(channel_for(m), m).unwrap();
            let Step::Item(back, _) = Frames::with_limit(0).decode(&f.to_bytes().unwrap(), false).unwrap() else {
                panic!("expected frame")
            };
            assert_eq!(back, f);
            // Every strict prefix is cut short, and one more byte is extra.
            for n in 0..p.len() {
                assert_eq!(Method::parse(&p[..n]), Err(DecodeError::Truncated), "{m:?} cut to {n}");
            }
            let mut longer = p.clone();
            longer.push(0);
            assert_eq!(Method::parse(&longer), Err(DecodeError::TrailingBytes), "{m:?}");
        }
        let content: Vec<_> = all.iter().filter(|m| m.has_content()).map(Method::ids).collect();
        assert_eq!(content, [(60, 40), (60, 50), (60, 60), (60, 71)]);
    }

    #[test]
    fn reserved_fields_are_skipped() {
        // connection.open with capabilities "x" and insist set.
        let p = [0, 10, 0, 40, 1, b'/', 1, b'x', 1];
        assert_eq!(Method::parse(&p), Ok(Method::ConnectionOpen { virtual_host: s("/") }));
        // channel.open-ok with a channel id; basic.publish with a ticket.
        assert_eq!(Method::parse(&[0, 20, 0, 11, 0, 0, 0, 2, 9, 9]), Ok(Method::ChannelOpenOk));
        let p = [0, 60, 0, 40, 0, 5, 0, 1, b'q', 0];
        let m = Method::parse(&p).unwrap();
        assert_eq!(m.to_bytes().unwrap(), [0, 60, 0, 40, 0, 0, 0, 1, b'q', 0]);
    }

    #[test]
    fn method_errors() {
        assert_eq!(Method::parse(&[0, 10, 0, 99]), Err(DecodeError::UnknownMethod { class_id: 10, method_id: 99 }));
        assert_eq!(Method::parse(&[0, 30, 0, 10]), Err(DecodeError::UnknownMethod { class_id: 30, method_id: 10 }));
        assert_eq!(DecodeError::UnknownMethod { class_id: 1, method_id: 1 }.reply_code(), 540);
        // A queue name that is not UTF-8.
        assert_eq!(Method::parse(&[0, 60, 0, 21, 2, 0xc3, 0x28]), Err(DecodeError::Utf8));
        assert_eq!(DecodeError::Utf8.reply_code(), 502);
        // An unknown field type in queue.declare's arguments.
        let p = [0, 50, 0, 10, 0, 0, 1, b'q', 0, 0, 0, 0, 3, 1, b'a', b'?'];
        assert_eq!(Method::parse(&p), Err(DecodeError::FieldType(b'?')));
        // A table length past the payload's end.
        let p = [0, 50, 0, 10, 0, 0, 1, b'q', 0, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Method::parse(&p), Err(DecodeError::Truncated));
        // A table whose entry runs past its own length.
        assert_eq!(Table::parse(&[0, 0, 0, 3, 1, b'a', b'I', 0, 0, 0, 1]), Err(DecodeError::Truncated));
        assert_eq!(Table::parse(&[0, 0, 0, 0, 9]), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn nesting_is_limited() {
        // Tables nested MAX_DEPTH deep read and write; one more does not.
        let nest = |levels: usize| {
            let mut t = Table::new();
            for _ in 1..levels {
                let mut outer = Table::new();
                outer.insert("t", FieldValue::Table(t));
                t = outer;
            }
            t
        };
        let ok = nest(MAX_DEPTH);
        let bytes = ok.to_bytes().unwrap();
        assert_eq!(Table::parse(&bytes), Ok(ok));
        assert_eq!(nest(MAX_DEPTH + 1).to_bytes(), Err(EncodeError::Unwritable));
        let mut deep = Vec::new();
        for _ in 0..MAX_DEPTH {
            deep.extend_from_slice(&[0, 0, 0, 0, 1, b't', b'F']);
        }
        deep.extend_from_slice(&[0, 0, 0, 0]);
        // Fill in the lengths from the inside out.
        let mut end = deep.len();
        for i in (0..MAX_DEPTH).rev() {
            let at = i * 7;
            let len = (end - at - 4) as u32;
            deep[at..at + 4].copy_from_slice(&len.to_be_bytes());
            end = deep.len();
        }
        assert_eq!(Table::parse(&deep), Err(DecodeError::TooDeep));
        // Arrays count too.
        let mut v = FieldValue::Void;
        for _ in 0..MAX_DEPTH {
            v = FieldValue::Array(vec![v]);
        }
        let mut t = Table::new();
        t.insert("a", v);
        assert_eq!(t.to_bytes(), Err(EncodeError::Unwritable));
        let FieldValue::Array(inner) = &t.entries[0].1 else { panic!() };
        let mut t = Table::new();
        t.insert("a", inner[0].clone());
        let bytes = t.to_bytes().unwrap();
        assert_eq!(Table::parse(&bytes), Ok(t));
    }

    #[test]
    fn deep_input_is_refused_not_recursed() {
        // A hundred thousand arrays, each holding the next, all lengths
        // right. Reading stops at MAX_DEPTH.
        let n = 100_000;
        let mut arrays = Vec::with_capacity(5 * n + 1);
        for i in 0..n {
            arrays.push(b'A');
            arrays.extend_from_slice(&((5 * (n - 1 - i) + 1) as u32).to_be_bytes());
        }
        arrays.push(b'V');
        let mut b = ((arrays.len() + 2) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(&[1, b'a']);
        b.extend_from_slice(&arrays);
        assert_eq!(Table::parse(&b), Err(DecodeError::TooDeep));
    }

    #[test]
    fn encode_errors() {
        let long = "x".repeat(256);
        let m = Method::BasicConsumeOk { consumer_tag: long.clone() };
        assert_eq!(m.to_bytes(), Err(EncodeError::Unwritable));
        assert_eq!(Frame::method(1, &m), Err(EncodeError::Unwritable));
        let m = Method::BasicConsumeOk { consumer_tag: "x".repeat(255) };
        assert!(Method::parse(&m.to_bytes().unwrap()).is_ok());
        let big = Method::ConnectionSecure { challenge: vec![0; MAX_PAYLOAD] };
        assert!(matches!(big.to_bytes(), Err(EncodeError::Unwritable)));
        let fits = Method::ConnectionSecure { challenge: vec![0; MAX_PAYLOAD - 8] };
        let f = Frame::method(0, &fits).unwrap();
        assert_eq!(f.to_bytes().unwrap().len(), MAX_FRAME_SIZE as usize);
        assert!(matches!(Frames::with_limit(0).decode(&f.to_bytes().unwrap(), false), Ok(Step::Item(_, _))));
        let mut t = Table::new();
        for i in 0..20 {
            t.insert(format!("k{i}"), FieldValue::Bytes(vec![0; MAX_PAYLOAD / 16]));
        }
        assert!(matches!(t.to_bytes(), Err(EncodeError::Unwritable)));
        let mut h = ContentHeader::default();
        h.properties.app_id = Some(long);
        assert_eq!(h.to_bytes(), Err(EncodeError::Unwritable));
    }

    #[test]
    fn oversized_payloads_are_refused() {
        // connection.secure with a challenge of MAX_PAYLOAD bytes: the
        // payload is longer than any frame, so it could not be written back.
        let mut p = vec![0, 10, 0, 20];
        p.extend_from_slice(&(MAX_PAYLOAD as u32).to_be_bytes());
        p.resize(p.len() + MAX_PAYLOAD, 0);
        assert_eq!(Method::parse(&p), Err(DecodeError::TooLarge(MAX_PAYLOAD + 8)));
        assert_eq!(DecodeError::TooLarge(1).reply_code(), 501);
        // A table that size, and a content header.
        let mut t = vec![0; 4];
        t[..4].copy_from_slice(&(MAX_PAYLOAD as u32 - 3).to_be_bytes());
        t.extend_from_slice(&[1, b'a', b'x']);
        t.extend_from_slice(&(MAX_PAYLOAD as u32 - 10).to_be_bytes());
        t.resize(MAX_PAYLOAD + 1, 0);
        assert_eq!(Table::parse(&t), Err(DecodeError::TooLarge(MAX_PAYLOAD + 1)));
        let h = vec![0; MAX_PAYLOAD + 1];
        assert_eq!(ContentHeader::parse(&h), Err(DecodeError::TooLarge(MAX_PAYLOAD + 1)));
        // At exactly MAX_PAYLOAD bytes a payload reads and writes back.
        p.truncate(MAX_PAYLOAD);
        p[4..8].copy_from_slice(&(MAX_PAYLOAD as u32 - 8).to_be_bytes());
        let m = Method::parse(&p).unwrap();
        assert_eq!(m.to_bytes().unwrap(), p);
    }

    #[test]
    fn field_value_accessors() {
        let t = sample_table();
        let caps = t.get("capabilities").and_then(FieldValue::as_table).unwrap();
        assert_eq!(caps.get("publisher_confirms").and_then(FieldValue::as_bool), Some(true));
        assert_eq!(t.get("product").and_then(FieldValue::as_str), Some("RabbitMQ"));
        assert_eq!(t.get("product").and_then(FieldValue::as_bytes), Some(&b"RabbitMQ"[..]));
        assert_eq!(t.get("x-max-length").and_then(FieldValue::as_i64), Some(1000));
        let all = t.get("all").and_then(FieldValue::as_array).unwrap();
        let ints: Vec<_> = all.iter().filter_map(FieldValue::as_i64).collect();
        assert_eq!(ints, [-3, 250, -30000, 65000, -7, 4_000_000_000, i64::MIN]);
        assert_eq!(FieldValue::Bytes(vec![0xff]).as_bytes(), Some(&[0xff][..]));
        assert_eq!(FieldValue::Bytes(vec![0x61]).as_str(), None);
        assert_eq!(FieldValue::LongString(vec![0xff]).as_str(), None);
        assert_eq!(FieldValue::Void.as_bool(), None);
        assert_eq!(FieldValue::Timestamp(1).as_i64(), None);
        assert_eq!(FieldValue::Void.as_table(), None);
        assert_eq!(FieldValue::Void.as_array(), None);
    }

    #[test]
    fn plain_response() {
        assert_eq!(plain_credentials(b"\0guest\0secret"), Some((&b"guest"[..], &b"secret"[..])));
        assert_eq!(plain_credentials(b"guest\0guest\0secret"), Some((&b"guest"[..], &b"secret"[..])));
        // RFC 4616: the user and password are not empty, every part is
        // UTF-8, and an authorization identity for another user is refused.
        assert_eq!(plain_credentials(b"admin\0guest\0"), None);
        assert_eq!(plain_credentials(b"\0\0"), None);
        assert_eq!(plain_credentials(b"\0guest\0"), None);
        assert_eq!(plain_credentials(b"\0\0secret"), None);
        assert_eq!(plain_credentials(b"\0\xff\0p"), None);
        assert_eq!(plain_credentials(b"\0u\0\xff"), None);
        assert_eq!(plain_credentials(b"\xff\0u\0p"), None);
        assert_eq!(plain_credentials(b"admin\0guest\0secret"), None);
        assert_eq!(plain_credentials(b""), None);
        assert_eq!(plain_credentials(b"guest"), None);
        assert_eq!(plain_credentials(b"\0guest"), None);
        assert_eq!(plain_credentials(b"\0a\0b\0c"), None);
    }

    #[test]
    fn content_header_example() {
        // A header with content-type "text/plain" and delivery-mode 2, for
        // a body of 5 bytes.
        let h = ContentHeader {
            body_size: 5,
            properties: BasicProperties {
                content_type: Some(s("text/plain")),
                delivery_mode: Some(2),
                ..Default::default()
            },
        };
        let mut bytes = vec![0, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0x90, 0x00, 10];
        bytes.extend_from_slice(b"text/plain");
        bytes.push(2);
        assert_eq!(h.to_bytes().unwrap(), bytes);
        assert_eq!(ContentHeader::parse(&bytes), Ok(h));
        // Every property reads back, and every prefix is cut short.
        let h = ContentHeader { body_size: 1 << 40, properties: full_properties() };
        let bytes = h.to_bytes().unwrap();
        assert_eq!(ContentHeader::parse(&bytes), Ok(h));
        for n in 0..bytes.len() {
            assert_eq!(ContentHeader::parse(&bytes[..n]), Err(DecodeError::Truncated), "cut to {n}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(ContentHeader::parse(&longer), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn content_header_errors() {
        assert_eq!(
            ContentHeader::parse(&[0, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::ContentClass(50))
        );
        // The continuation flag and the unused bit are refused.
        assert_eq!(
            ContentHeader::parse(&[0, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Err(DecodeError::PropertyFlags(1))
        );
        assert_eq!(
            ContentHeader::parse(&[0, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            Err(DecodeError::PropertyFlags(2))
        );
        // A nonzero weight is refused (section 4.2.6.1).
        assert_eq!(ContentHeader::parse(&[0, 60, 0, 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0]), Err(DecodeError::Weight(9)));
        assert_eq!(ContentHeader::parse(&[0, 60, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(DecodeError::Weight(1)));
        assert_eq!(DecodeError::Weight(1).reply_code(), 505);
        // A wrong class is a frame error (section 4.2.6.1).
        assert_eq!(DecodeError::ContentClass(50).reply_code(), 501);
    }

    #[test]
    fn frame_errors_and_prefixes() {
        let f = Frame { kind: FrameKind::Body, channel: 9, payload: b"abc".to_vec() };
        let bytes = f.to_bytes().unwrap();
        assert_eq!(bytes, [3, 0, 9, 0, 0, 0, 3, b'a', b'b', b'c', 0xce]);
        for n in 0..bytes.len() {
            assert_eq!(Frames::with_limit(0).decode(&bytes[..n], false), Ok(Step::Need), "{n} bytes");
        }
        // Unknown type, known from the first byte.
        assert_eq!(Frames::with_limit(0).decode(&[4], false), Err(FrameError::Type(4)));
        assert_eq!(Frames::with_limit(0).decode(&[0], false), Err(FrameError::Type(0)));
        // A heartbeat off channel 0, or with a payload.
        assert_eq!(
            Frames::with_limit(0).decode(&[8, 0, 1, 0, 0, 0, 0], false),
            Err(FrameError::Heartbeat { channel: 1, size: 0 })
        );
        assert_eq!(
            Frames::with_limit(0).decode(&[8, 0, 0, 0, 0, 0, 1], false),
            Err(FrameError::Heartbeat { channel: 0, size: 1 })
        );
        // Too large, known from the header.
        assert_eq!(
            Frames::with_limit(4096).decode(&[3, 0, 1, 0, 0, 0x10, 0x00], false),
            Err(FrameError::TooLarge { size: 4096, frame_max: 4096 })
        );
        assert_eq!(Frames::with_limit(4096).decode(&[3, 0, 1, 0, 0, 0x0f, 0xf8], false), Ok(Step::Need));
        assert_eq!(
            Frames::with_limit(0).decode(&[3, 0, 1, 0xff, 0xff, 0xff, 0xff], false),
            Err(FrameError::TooLarge { size: u32::MAX, frame_max: MAX_FRAME_SIZE })
        );
        // A wrong end byte.
        assert_eq!(
            Frames::with_limit(0).decode(&[3, 0, 1, 0, 0, 0, 1, b'x', 0xcd], false),
            Err(FrameError::FrameEnd(0xcd))
        );
        assert_eq!(FrameError::FrameEnd(0).reply_code(), 501);
        // A bad type or end byte closes the socket with nothing sent.
        assert!(!FrameError::FrameEnd(0).sends_close());
        assert!(!FrameError::Type(0).sends_close());
        assert!(!FrameError::ProtocolHeader([0; 8]).sends_close());
        assert!(FrameError::TooLarge { size: 1, frame_max: 2 }.sends_close());
        // Frame limits.
        assert_eq!(frame_limit(0), MAX_FRAME_SIZE);
        assert_eq!(frame_limit(1), FRAME_MIN_SIZE);
        assert_eq!(frame_limit(u32::MAX), MAX_FRAME_SIZE);
        assert_eq!(frame_limit(131072), 131072);
        // A payload longer than a frame holds is refused, not cut short.
        let f = Frame::body(1, vec![0; MAX_PAYLOAD + 1]);
        assert_eq!(f.to_bytes(), Err(EncodeError::Unwritable));
        let f = Frame::body(1, vec![0; MAX_PAYLOAD]);
        let bytes = f.to_bytes().unwrap();
        assert_eq!(Frames::with_limit(0).decode(&bytes, false), Ok(Step::Item(f, MAX_FRAME_SIZE as usize)));
        for k in [1, 2, 3, 8] {
            assert_eq!(FrameKind::from_code(k).unwrap().code(), k);
        }
    }

    #[test]
    fn stream_splits_a_stream() {
        let frames =
            [Frame::method(1, &Method::BasicAck { delivery_tag: 1, multiple: false }).unwrap(), Frame::heartbeat()];
        let bytes: Vec<_> = frames.iter().flat_map(|f| f.to_bytes().unwrap()).collect();
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * DEFAULT_FRAME_MAX as usize);
        assert_eq!(decode_all(Frames::new, &bytes), (frames.to_vec(), None));
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&[3, 0, 1, 0, 0, 0, 0, 0]), 8);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(FrameError::FrameEnd(0)))));
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn stream_frame_max() {
        let big = Frame::body(1, vec![7; 10_000]).to_bytes().unwrap();
        let mut frames = Frames::new();
        assert_eq!(frames.frame_max(), DEFAULT_FRAME_MAX);
        frames.set_frame_max(4096);
        assert_eq!(frames.frame_max(), 4096);
        assert_eq!(frames.decode(&big[..7], false), Err(FrameError::TooLarge { size: 10_000, frame_max: 4096 }));
        assert_eq!(decode_all(Frames::default, &big).0[0].payload.len(), 10_000);
    }

    #[test]
    fn content_frames_split_the_body() {
        let publish =
            Method::BasicPublish { exchange: s("e"), routing_key: s("r"), mandatory: false, immediate: false };
        let body = vec![1u8; 10_000];
        let frames = content_frames(3, &publish, &full_properties(), &body, 4096).unwrap();
        let sizes: Vec<_> = frames[2..].iter().map(|f| f.payload.len()).collect();
        assert_eq!(sizes, [4088, 4088, 1824]);
        let mut d = Stream::new(Frames::with_limit(4096));
        let mut got = Vec::new();
        for f in &frames {
            let bytes = f.to_bytes().unwrap();
            assert_eq!(d.push(&bytes), bytes.len());
            got.push(d.next().unwrap().unwrap());
        }
        assert_eq!(got, frames);
        assert_eq!(Method::parse(&got[0].payload), Ok(publish.clone()));
        let h = ContentHeader::parse(&got[1].payload).unwrap();
        assert_eq!(h.body_size, 10_000);
        let joined: Vec<u8> = got[2..].iter().flat_map(|f| f.payload.clone()).collect();
        assert_eq!(joined, body);
        // No body frames for an empty body.
        assert_eq!(content_frames(1, &publish, &BasicProperties::default(), &[], 0).unwrap().len(), 2);
        // A header too big for the frame size is refused.
        let mut props = BasicProperties::default();
        let mut t = Table::new();
        t.insert("big", FieldValue::LongString(vec![0; 5000]));
        props.headers = Some(t);
        assert!(matches!(content_frames(1, &publish, &props, &[], 4096), Err(EncodeError::Unwritable)));
    }

    #[test]
    fn stream_takes_many_small_frames_in_linear_time() {
        let bytes = Frame::heartbeat().to_bytes().unwrap().repeat(200_000);
        let started = std::time::Instant::now();
        let mut stream = Stream::new(Frames::new());
        let mut n = 0;
        pump(&mut stream, &bytes, |_| n += 1).unwrap();
        assert_eq!(n, 200_000);
        assert_eq!(stream.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn errors_display() {
        for e in [
            FrameError::ProtocolHeader([0; 8]),
            FrameError::Type(9),
            FrameError::Heartbeat { channel: 1, size: 0 },
            FrameError::TooLarge { size: 1, frame_max: 2 },
            FrameError::FrameEnd(0),
            FrameError::ChannelZero(FrameKind::Body),
            FrameError::NotChannelZero { channel: 1 },
        ] {
            assert!(!e.to_string().is_empty());
        }
        for e in [
            DecodeError::Truncated,
            DecodeError::TrailingBytes,
            DecodeError::UnknownMethod { class_id: 1, method_id: 2 },
            DecodeError::Utf8,
            DecodeError::FieldType(0),
            DecodeError::TooDeep,
            DecodeError::ContentClass(1),
            DecodeError::PropertyFlags(1),
            DecodeError::TooLarge(1),
            DecodeError::ZeroByte,
            DecodeError::DuplicateField,
            DecodeError::Weight(1),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(EncodeError::Unwritable.to_string(), "AMQP value cannot be written without changing it");
    }

    fn publish() -> Method {
        Method::BasicPublish { exchange: s(""), routing_key: s("q"), mandatory: false, immediate: false }
    }

    #[test]
    fn deep_properties_are_refused_without_copying() {
        // A hundred thousand nested arrays in the headers. content_frames
        // reads the properties where they are, so it stops at MAX_DEPTH
        // rather than copying every level first.
        let mut v = FieldValue::Void;
        for _ in 0..100_000 {
            v = FieldValue::Array(vec![v]);
        }
        let mut t = Table::new();
        t.entries.push((s("a"), v));
        let mut props = BasicProperties { headers: Some(t), ..Default::default() };
        assert_eq!(content_frames(1, &publish(), &props, b"", 0), Err(EncodeError::Unwritable));
        // Take the value apart a level at a time, so dropping it does not
        // recurse either.
        let Some(mut t) = props.headers.take() else { panic!() };
        let mut next = t.entries.pop().map(|(_, v)| v);
        while let Some(FieldValue::Array(mut inner)) = next {
            next = inner.pop();
        }
    }

    #[test]
    fn stream_buffer_is_bounded() {
        let chunk = vec![3u8; 100_000];
        contract::check_decode_with_alloc_limit(Frames::new, &chunk, 2 * DEFAULT_FRAME_MAX as usize);
        assert!(matches!(decode_all(Frames::new, &chunk).1, Some(Fail::Protocol(FrameError::TooLarge { .. }))));
        let one = Frame::method(1, &Method::BasicAck { delivery_tag: 1, multiple: false }).unwrap();
        let mut bytes = PROTOCOL_HEADER.to_vec();
        bytes.extend(one.to_bytes().unwrap().repeat(1000));
        let make = || {
            let mut f = Frames::server();
            f.set_frame_max(4096);
            f
        };
        contract::check_decode_with_alloc_limit(make, &bytes, 8192);
        assert_eq!(decode_all(make, &bytes), (vec![one; 1000], None));
    }

    #[test]
    fn content_needs_a_content_method_and_a_channel() {
        assert_eq!(
            content_frames(1, &Method::TxSelect, &BasicProperties::default(), b"x", 4096),
            Err(EncodeError::Unwritable)
        );
        assert_eq!(
            content_frames(0, &publish(), &BasicProperties::default(), b"x", 4096),
            Err(EncodeError::Unwritable)
        );
        assert_eq!(Frame::header(0, &ContentHeader::default()), Err(EncodeError::Unwritable));
    }

    #[test]
    fn channel_rules() {
        // Connection methods go on channel 0 and the rest off it (section
        // 4.2.3), in writers and readers alike.
        assert_eq!(Frame::method(1, &Method::ConnectionCloseOk), Err(EncodeError::Unwritable));
        assert_eq!(Frame::method(0, &Method::ChannelOpen), Err(EncodeError::Unwritable));
        let close_ok = [1, 0, 1, 0, 0, 0, 4, 0, 10, 0, 51, 0xce];
        assert_eq!(Frames::with_limit(0).decode(&close_ok, false), Err(FrameError::NotChannelZero { channel: 1 }));
        assert_eq!(FrameError::NotChannelZero { channel: 1 }.reply_code(), 503);
        let open = [1, 0, 0, 0, 0, 0, 5, 0, 20, 0, 10, 0, 0xce];
        assert_eq!(Frames::with_limit(0).decode(&open, false), Err(FrameError::ChannelZero(FrameKind::Method)));
        assert_eq!(FrameError::ChannelZero(FrameKind::Method).reply_code(), 503);
        // Content on channel 0 is a channel error (section 4.2.6.1).
        let body = Frame::body(0, vec![1]);
        assert_eq!(body.to_bytes(), Err(EncodeError::Unwritable));
        assert_eq!(
            Frames::with_limit(0).decode(&[3, 0, 0, 0, 0, 0, 1, 1, 0xce], false),
            Err(FrameError::ChannelZero(FrameKind::Body))
        );
        assert_eq!(
            Frames::with_limit(0).decode(&[2, 0, 0, 0, 0, 0, 0, 0xce], false),
            Err(FrameError::ChannelZero(FrameKind::Header))
        );
        assert_eq!(FrameError::ChannelZero(FrameKind::Body).reply_code(), 504);
        // A method frame too short to name its class is left to Method::parse.
        assert!(matches!(Frames::with_limit(0).decode(&[1, 0, 0, 0, 0, 0, 1, 0, 0xce], false), Ok(Step::Item(_, _))));
    }

    #[test]
    fn short_strings_hold_no_zero_byte() {
        // Section 4.2.5.3.
        let m = Method::BasicConsumeOk { consumer_tag: s("a\0b") };
        assert_eq!(m.to_bytes(), Err(EncodeError::Unwritable));
        assert_eq!(Method::parse(&[0, 60, 0, 21, 3, b'a', 0, b'b']), Err(DecodeError::ZeroByte));
        // Field names are short strings too.
        let t = Table { entries: vec![(s("a\0"), FieldValue::Void)] };
        assert_eq!(t.to_bytes(), Err(EncodeError::Unwritable));
        assert_eq!(Table::parse(&[0, 0, 0, 4, 2, b'a', 0, b'V']), Err(DecodeError::ZeroByte));
        // Long strings may hold any bytes.
        let t = Table { entries: vec![(s("a"), FieldValue::LongString(vec![0]))] };
        assert_eq!(Table::parse(&t.to_bytes().unwrap()), Ok(t));
    }

    #[test]
    fn duplicate_fields_are_refused() {
        // Section 4.2.5.5: duplicate fields are illegal.
        let t = Table { entries: vec![(s("a"), FieldValue::I32(1)), (s("a"), FieldValue::I32(2))] };
        assert_eq!(t.to_bytes(), Err(EncodeError::Unwritable));
        let b = [0, 0, 0, 8, 1, b'a', b'V', 1, b'b', b'V', 1, b'a', b'V'];
        let b = [&[0, 0, 0, 9][..], &b[4..]].concat();
        assert_eq!(Table::parse(&b), Err(DecodeError::DuplicateField));
        // The same name in different tables is fine.
        let mut inner = Table::new();
        inner.insert("a", FieldValue::Void);
        let mut t = Table::new();
        t.insert("a", FieldValue::Table(inner));
        assert_eq!(Table::parse(&t.to_bytes().unwrap()), Ok(t));
    }

    #[test]
    fn decimals_are_signed() {
        // Section 4.2.5.5: a scale octet, then a signed 32-bit value.
        let b = [0, 0, 0, 8, 1, b'd', b'D', 2, 0xff, 0xff, 0xff, 0xff];
        let t = Table::parse(&b).unwrap();
        assert_eq!(t.get("d"), Some(&FieldValue::Decimal { scale: 2, value: -1 }));
        assert_eq!(t.to_bytes().unwrap(), b);
        let t = Table { entries: vec![(s("d"), FieldValue::Decimal { scale: 0, value: i32::MIN })] };
        assert_eq!(Table::parse(&t.to_bytes().unwrap()), Ok(t));
    }

    #[test]
    fn float_wire_bits_round_trip() {
        let table = Table { entries: vec![
            ("nan32".into(), FieldValue::F32(f32::from_bits(0x7fc0_0001))),
            ("nan64".into(), FieldValue::F64(f64::from_bits(0x7ff8_0000_0000_0001))),
            ("negative_zero".into(), FieldValue::F64(-0.0)),
        ] };
        contract::check_wire_value(&table);
        contract::check_wire::<Table>(&table.to_bytes().unwrap());
    }

    fn check_payload(p: &[u8]) {
        contract::check_wire::<Method>(p);
        contract::check_wire::<ContentHeader>(p);
        contract::check_wire::<Table>(p);
    }

    fn check_stream(data: &[u8], server: bool) {
        let make = || if server { Frames::server() } else { Frames::new() };
        contract::check_decode_with_alloc_limit(make, data, 2 * DEFAULT_FRAME_MAX as usize);
        for frame in decode_all(make, data).0 {
            contract::check_wire_value(&frame);
            check_payload(&frame.payload);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x5eed);
        // Valid payloads and streams to mutate.
        let mut seeds: Vec<Vec<u8>> = every_method().iter().map(|m| m.to_bytes().unwrap()).collect();
        seeds.push(ContentHeader { body_size: 9, properties: full_properties() }.to_bytes().unwrap());
        seeds.push(sample_table().to_bytes().unwrap());
        let mut stream = PROTOCOL_HEADER.to_vec();
        for m in every_method().iter().take(20) {
            stream.extend(Frame::method(channel_for(m), m).unwrap().to_bytes().unwrap());
        }
        stream.extend(Frame::heartbeat().to_bytes().unwrap());
        stream.extend(Frame::body(2, b"body".to_vec()).to_bytes().unwrap());
        for round in 0..4000 {
            let mut buf = match round % 3 {
                0 => rng.bytes(64),
                1 => seeds[rng.index(seeds.len())].clone(),
                _ => stream.clone(),
            };
            for _ in 0..rng.index(6) {
                mutate(&mut rng, &mut buf);
            }
            check_payload(&buf);
            let _ = Frames::with_limit(rng.next() as u32).decode(&buf, false);
            if round % 3 == 2 {
                check_stream(&buf, true);
                check_stream(&buf[PROTOCOL_HEADER.len().min(buf.len())..], false);
            } else {
                check_stream(&buf, false);
            }
        }
    }
}
