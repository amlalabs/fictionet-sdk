//! HTTP/2 frames and directional state (RFC 9113).
//!
//! Use [`Session`] for strict decoding. A capture reads frames with
//! [`Frames::for_observation`] and header blocks with
//! [`HeaderBlocks::for_observation`], which report what they cannot read
//! instead of failing; observe's HTTP/2 presenter is built on them.
//! Route SETTINGS and WINDOW_UPDATE to the opposite direction's
//! [`Session::peer_settings`] and [`Session::peer_window_update`].
//! Route RST_STREAM through [`Session::peer_reset`], then retire both halves.
//! In-flight DATA on a peer-reset stream still consumes connection credit.
//! Its headers still update HPACK. Neither produces an event, even after retire.
//! For GOAWAY, the caller identifies abandoned streams above `last_stream`,
//! closes both halves with `peer_reset`, and retires their DATA decoders.
//! Idle-stream checks and stream ownership belong to the caller.
//! SETTINGS reductions take effect when the sending direction reads its ACK.

use fictionet::stdlib::{
    codec::{Decode, Fail, Step, Stream, Wire},
    hpack,
};
use std::collections::{BTreeMap, BTreeSet};

/// The client's connection preface from RFC 9113, Section 3.4.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Bytes in a frame header.
pub const HEADER_LEN: usize = 9;
/// The largest payload representable by a frame header.
pub const MAX_FRAME_SIZE: usize = 0xff_ffff;
/// The initial maximum frame payload size.
pub const DEFAULT_FRAME_SIZE: usize = 16_384;
/// The largest stream identifier and flow-control window.
pub const MAX_WINDOW: u32 = 0x7fff_ffff;

/// An RFC 9113 connection error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// No error occurred.
    NoError = 0,
    /// A protocol rule was broken.
    ProtocolError = 1,
    /// The implementation failed internally.
    InternalError = 2,
    /// A flow-control window was exceeded.
    FlowControlError = 3,
    /// Settings were not acknowledged in time.
    SettingsTimeout = 4,
    /// A frame arrived on a closed stream.
    StreamClosed = 5,
    /// A frame has an invalid length.
    FrameSizeError = 6,
    /// The stream was refused before processing.
    RefusedStream = 7,
    /// The stream was canceled.
    Cancel = 8,
    /// HPACK decoding failed.
    CompressionError = 9,
    /// The connection could not be established.
    ConnectError = 10,
    /// A configured resource limit was reached.
    EnhanceYourCalm = 11,
    /// Transport security was insufficient.
    InadequateSecurity = 12,
    /// The peer requires HTTP/1.1.
    Http11Required = 13,
}

impl ErrorCode {
    /// The RFC name for a wire code, or `None` for an extension code.
    pub fn name(code: u32) -> Option<&'static str> {
        const NAMES: [&str; 14] = [
            "NO_ERROR",
            "PROTOCOL_ERROR",
            "INTERNAL_ERROR",
            "FLOW_CONTROL_ERROR",
            "SETTINGS_TIMEOUT",
            "STREAM_CLOSED",
            "FRAME_SIZE_ERROR",
            "REFUSED_STREAM",
            "CANCEL",
            "COMPRESSION_ERROR",
            "CONNECT_ERROR",
            "ENHANCE_YOUR_CALM",
            "INADEQUATE_SECURITY",
            "HTTP_1_1_REQUIRED",
        ];
        NAMES.get(usize::try_from(code).ok()?).copied()
    }
}

/// A terminal error, including the code to put in GOAWAY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    /// RFC 9113 error code.
    pub code: ErrorCode,
    /// A short description without captured bytes.
    pub reason: &'static str,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HTTP/2 {:?}: {}", self.code, self.reason)
    }
}
impl core::error::Error for Error {}
fn error(code: ErrorCode, reason: &'static str) -> Error {
    Error { code, reason }
}
fn protocol(reason: &'static str) -> Error {
    error(ErrorCode::ProtocolError, reason)
}
fn size(reason: &'static str) -> Error {
    error(ErrorCode::FrameSizeError, reason)
}
fn budget(reason: &'static str) -> Error {
    error(ErrorCode::EnhanceYourCalm, reason)
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| size("integer offset overflow"))?;
    let b = bytes
        .get(at..end)
        .ok_or_else(|| size("truncated integer"))?;
    let a: [u8; 4] = b.try_into().map_err(|_| size("truncated integer"))?;
    Ok(u32::from_be_bytes(a))
}

/// The nine-byte header. Reserved stream bits are ignored when reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length, excluding this header.
    pub length: usize,
    /// Frame type code. Unknown codes are retained.
    pub kind: u8,
    /// All flag bits, including undefined flags.
    pub flags: u8,
    /// A 31-bit stream identifier. Zero identifies the connection.
    pub stream: u32,
}
impl Wire for FrameHeader {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads exactly nine bytes. Type-specific rules belong to [`Frame`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let [a, c, d, kind, flags, s0, s1, s2, s3] = b else {
            return Err(size("a frame header is nine bytes"));
        };
        Ok(Self {
            length: (usize::from(*a) << 16) | (usize::from(*c) << 8) | usize::from(*d),
            kind: *kind,
            flags: *flags,
            stream: u32::from_be_bytes([*s0, *s1, *s2, *s3]) & MAX_WINDOW,
        })
    }
    /// Appends a header. Rejects lengths over 24 bits and stream IDs over
    /// 31 bits before changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.length > MAX_FRAME_SIZE || self.stream > MAX_WINDOW {
            return Err(size("header integer out of range"));
        }
        out.try_reserve(HEADER_LEN)
            .map_err(|_| budget("allocation failed"))?;
        out.extend_from_slice(&[
            (self.length >> 16) as u8,
            (self.length >> 8) as u8,
            self.length as u8,
            self.kind,
            self.flags,
        ]);
        out.extend_from_slice(&self.stream.to_be_bytes());
        Ok(())
    }
}
impl FrameHeader {
    /// The registered frame name, or `UNKNOWN`.
    pub fn name(&self) -> &'static str {
        match self.kind {
            0 => "DATA",
            1 => "HEADERS",
            2 => "PRIORITY",
            3 => "RST_STREAM",
            4 => "SETTINGS",
            5 => "PUSH_PROMISE",
            6 => "PING",
            7 => "GOAWAY",
            8 => "WINDOW_UPDATE",
            9 => "CONTINUATION",
            _ => "UNKNOWN",
        }
    }
    fn validate(&self) -> Result<(), Error> {
        match self.kind {
            0..=3 | 5 | 9 if self.stream == 0 => return Err(protocol("frame requires a stream")),
            4 | 6 | 7 if self.stream != 0 => return Err(protocol("frame requires stream zero")),
            _ => {}
        }
        let valid = match self.kind {
            2 => self.length == 5,
            3 | 8 => self.length == 4,
            4 if self.flags & 1 != 0 => self.length == 0,
            4 => self.length.is_multiple_of(6),
            6 => self.length == 8,
            7 => self.length >= 8,
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(size("invalid frame payload length"))
        }
    }
}

/// DATA payload and its stream. Padding octets are retained exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    /// Stream identifier, greater than zero.
    pub stream: u32,
    /// Flags, including END_STREAM (1) and PADDED (8).
    pub flags: u8,
    /// Application bytes, excluding padding.
    pub data: Vec<u8>,
    /// Padding octets. `Some` requires PADDED, including zero padding.
    pub padding: Option<Vec<u8>>,
}
/// A priority dependency. The weight is the wire value, from 0 to 255.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dependency {
    /// A 31-bit stream identifier, possibly zero.
    pub stream: u32,
    /// Whether the dependency is exclusive.
    pub exclusive: bool,
    /// Encoded weight; its scheduling weight is this value plus one.
    pub weight: u8,
}
/// HEADERS with an encoded HPACK fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Headers {
    /// Stream identifier, greater than zero.
    pub stream: u32,
    /// Flags, including END_STREAM, END_HEADERS, PADDED, and PRIORITY.
    pub flags: u8,
    /// Encoded HPACK bytes.
    pub fragment: Vec<u8>,
    /// Priority fields, present exactly when flag 0x20 is set.
    pub priority: Option<Dependency>,
    /// Padding octets, present exactly when PADDED is set.
    pub padding: Option<Vec<u8>>,
}
/// A PRIORITY frame. RFC 9113 deprecates priority scheduling, but retains framing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Priority {
    /// Stream identifier, greater than zero.
    pub stream: u32,
    /// Undefined flag bits, retained as received.
    pub flags: u8,
    /// Dependency and weight.
    pub dependency: Dependency,
}
/// RST_STREAM with an unrestricted error code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reset {
    /// Stream identifier, greater than zero.
    pub stream: u32,
    /// Undefined flag bits, retained as received.
    pub flags: u8,
    /// The peer's error code.
    pub code: u32,
}
/// One SETTINGS entry. Unknown identifiers are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    /// SETTINGS identifier.
    pub id: u16,
    /// Unsigned setting value.
    pub value: u32,
}
/// SETTINGS on stream zero, preserving entry order and duplicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Flags. ACK (1) requires an empty entry list.
    pub flags: u8,
    /// Settings in wire order.
    pub entries: Vec<Setting>,
}
/// PUSH_PROMISE with an encoded HPACK fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushPromise {
    /// Associated stream identifier, greater than zero.
    pub stream: u32,
    /// Flags, including END_HEADERS (4) and PADDED (8).
    pub flags: u8,
    /// Promised stream identifier, greater than zero.
    pub promised: u32,
    /// Encoded HPACK bytes.
    pub fragment: Vec<u8>,
    /// Padding octets, present exactly when PADDED is set.
    pub padding: Option<Vec<u8>>,
}
/// PING on stream zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ping {
    /// Flags, including ACK (1).
    pub flags: u8,
    /// Eight opaque octets.
    pub opaque: [u8; 8],
}
/// GOAWAY on stream zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoAway {
    /// Undefined flag bits, retained as received.
    pub flags: u8,
    /// Highest processed stream identifier.
    pub last_stream: u32,
    /// The peer's error code.
    pub code: u32,
    /// Opaque debug bytes.
    pub debug: Vec<u8>,
}
/// WINDOW_UPDATE for a stream or the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowUpdate {
    /// Stream identifier, or zero for the connection window.
    pub stream: u32,
    /// Undefined flag bits, retained as received.
    pub flags: u8,
    /// A nonzero 31-bit increment.
    pub increment: u32,
}
/// CONTINUATION carrying the next fragment of a header block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    /// The stream of the preceding HEADERS or PUSH_PROMISE.
    pub stream: u32,
    /// Flags, including END_HEADERS (4).
    pub flags: u8,
    /// Encoded HPACK bytes.
    pub fragment: Vec<u8>,
}
/// An unrecognized frame type with its raw payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unknown {
    /// A type code outside 0 through 9.
    pub kind: u8,
    /// All flag bits.
    pub flags: u8,
    /// A 31-bit stream identifier.
    pub stream: u32,
    /// Uninterpreted payload bytes.
    pub payload: Vec<u8>,
}
/// One complete HTTP/2 frame, including its header in [`Wire`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Application bytes.
    Data(Data),
    /// The start of a header block.
    Headers(Headers),
    /// Stream dependency and weight.
    Priority(Priority),
    /// Stream cancellation.
    Reset(Reset),
    /// Connection settings or their acknowledgment.
    Settings(Settings),
    /// A promised stream and request headers.
    PushPromise(PushPromise),
    /// Liveness probe or acknowledgment.
    Ping(Ping),
    /// Connection shutdown.
    GoAway(GoAway),
    /// Flow-control credit.
    WindowUpdate(WindowUpdate),
    /// More header block bytes.
    Continuation(Continuation),
    /// An extension frame.
    Unknown(Unknown),
}
fn unpad(payload: &[u8], flags: u8) -> Result<(&[u8], Option<Vec<u8>>), Error> {
    if flags & 8 == 0 {
        return Ok((payload, None));
    }
    let (&pad, rest) = payload
        .split_first()
        .ok_or_else(|| size("missing pad length"))?;
    let end = rest
        .len()
        .checked_sub(usize::from(pad))
        .ok_or_else(|| protocol("padding longer than payload"))?;
    Ok((
        rest.get(..end).ok_or_else(|| size("padding"))?,
        Some(rest.get(end..).ok_or_else(|| size("padding"))?.to_vec()),
    ))
}
// A payload too short for its fields is a FRAME_SIZE_ERROR (RFC 9113 4.2).
// Padding that leaves too few bytes for them is a PROTOCOL_ERROR (6.2, 6.6).
fn unpad_fields(payload: &[u8], flags: u8, need: usize) -> Result<(&[u8], Option<Vec<u8>>), Error> {
    if payload.len() < need.saturating_add(usize::from(flags & 8 != 0)) {
        return Err(size("frame too short for its fields"));
    }
    let (b, padding) = unpad(payload, flags)?;
    if b.len() < need {
        return Err(protocol("padding covers required fields"));
    }
    Ok((b, padding))
}
fn dependency(b: &[u8]) -> Result<Dependency, Error> {
    let stream = u32_at(b, 0)?;
    Ok(Dependency {
        stream: stream & MAX_WINDOW,
        exclusive: stream & !MAX_WINDOW != 0,
        weight: *b.get(4).ok_or_else(|| size("missing priority weight"))?,
    })
}
fn setting_valid(s: Setting) -> Result<(), Error> {
    match s.id {
        2 | 8 if s.value > 1 => Err(protocol("boolean setting exceeds one")),
        4 if s.value > MAX_WINDOW => Err(error(
            ErrorCode::FlowControlError,
            "initial window exceeds 31 bits",
        )),
        5 if !(DEFAULT_FRAME_SIZE as u32..=MAX_FRAME_SIZE as u32).contains(&s.value) => {
            Err(protocol("invalid maximum frame size"))
        }
        _ => Ok(()),
    }
}
impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads exactly one frame. Checks lengths, stream-zero rules, padding,
    /// settings values, window increments, and priority self-dependencies.
    /// Undefined flags and unknown frame payloads are retained.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let h = FrameHeader::parse(
            bytes
                .get(..HEADER_LEN)
                .ok_or_else(|| size("truncated header"))?,
        )?;
        h.validate()?;
        let b = bytes
            .get(HEADER_LEN..)
            .ok_or_else(|| size("truncated payload"))?;
        if b.len() != h.length {
            return Err(size("payload length does not match header"));
        }
        let (stream, flags) = (h.stream, h.flags);
        Ok(match h.kind {
            0 => {
                let (data, padding) = unpad(b, flags)?;
                Self::Data(Data {
                    stream,
                    flags,
                    data: data.to_vec(),
                    padding,
                })
            }
            1 => {
                let (b, padding) = unpad_fields(b, flags, if flags & 0x20 != 0 { 5 } else { 0 })?;
                let (priority, fragment) = if flags & 0x20 != 0 {
                    let p = dependency(b)?;
                    if p.stream == stream {
                        return Err(protocol("stream depends on itself"));
                    }
                    (
                        Some(p),
                        b.get(5..).ok_or_else(|| size("short HEADERS priority"))?,
                    )
                } else {
                    (None, b)
                };
                Self::Headers(Headers {
                    stream,
                    flags,
                    fragment: fragment.to_vec(),
                    priority,
                    padding,
                })
            }
            2 => {
                let dependency = dependency(b)?;
                if dependency.stream == stream {
                    return Err(protocol("stream depends on itself"));
                }
                Self::Priority(Priority {
                    stream,
                    flags,
                    dependency,
                })
            }
            3 => Self::Reset(Reset {
                stream,
                flags,
                code: u32_at(b, 0)?,
            }),
            4 => {
                let mut entries = Vec::new();
                for b in b.as_chunks::<6>().0 {
                    let id = u16::from_be_bytes([
                        *b.first().ok_or_else(|| size("setting"))?,
                        *b.get(1).ok_or_else(|| size("setting"))?,
                    ]);
                    let s = Setting {
                        id,
                        value: u32_at(b, 2)?,
                    };
                    setting_valid(s)?;
                    entries.push(s);
                }
                Self::Settings(Settings { flags, entries })
            }
            5 => {
                let (b, padding) = unpad_fields(b, flags, 4)?;
                let promised = u32_at(b, 0)? & MAX_WINDOW;
                if promised == 0 {
                    return Err(protocol("promised stream is zero"));
                }
                Self::PushPromise(PushPromise {
                    stream,
                    flags,
                    promised,
                    fragment: b
                        .get(4..)
                        .ok_or_else(|| size("short PUSH_PROMISE"))?
                        .to_vec(),
                    padding,
                })
            }
            6 => Self::Ping(Ping {
                flags,
                opaque: b.try_into().map_err(|_| size("PING length"))?,
            }),
            7 => Self::GoAway(GoAway {
                flags,
                last_stream: u32_at(b, 0)? & MAX_WINDOW,
                code: u32_at(b, 4)?,
                debug: b.get(8..).ok_or_else(|| size("GOAWAY length"))?.to_vec(),
            }),
            8 => {
                let increment = u32_at(b, 0)? & MAX_WINDOW;
                if increment == 0 {
                    return Err(protocol("zero window increment"));
                }
                Self::WindowUpdate(WindowUpdate {
                    stream,
                    flags,
                    increment,
                })
            }
            9 => Self::Continuation(Continuation {
                stream,
                flags,
                fragment: b.to_vec(),
            }),
            kind => Self::Unknown(Unknown {
                kind,
                stream,
                flags,
                payload: b.to_vec(),
            }),
        })
    }
    /// Appends a complete frame. Validates every field before touching
    /// `out`. A value that cannot round-trip is refused, including padding
    /// or priority fields inconsistent with their flags.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let (header, payload) = self.encode()?;
        let mut encoded = Vec::new();
        header.write(&mut encoded)?;
        encoded
            .try_reserve(payload.len())
            .map_err(|_| budget("allocation failed"))?;
        encoded.extend_from_slice(&payload);
        if Self::parse(&encoded)?.ne(self) {
            return Err(protocol("frame would read back differently"));
        }
        out.try_reserve(encoded.len())
            .map_err(|_| budget("allocation failed"))?;
        out.extend_from_slice(&encoded);
        Ok(())
    }
}
fn append(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    if out
        .len()
        .checked_add(b.len())
        .is_none_or(|n| n > MAX_FRAME_SIZE)
    {
        return Err(size("payload exceeds 24 bits"));
    }
    out.try_reserve(b.len())
        .map_err(|_| budget("allocation failed"))?;
    out.extend_from_slice(b);
    Ok(())
}
fn put_dependency(out: &mut Vec<u8>, d: Dependency) -> Result<(), Error> {
    if d.stream > MAX_WINDOW {
        return Err(protocol("dependency exceeds 31 bits"));
    }
    append(
        out,
        &(d.stream | if d.exclusive { 0x8000_0000 } else { 0 }).to_be_bytes(),
    )?;
    append(out, &[d.weight])
}
fn pad_start(out: &mut Vec<u8>, pad: &Option<Vec<u8>>, flags: u8) -> Result<(), Error> {
    if pad.is_some() != (flags & 8 != 0) {
        return Err(protocol("padding disagrees with flags"));
    }
    if let Some(pad) = pad {
        let n = u8::try_from(pad.len()).map_err(|_| protocol("padding exceeds 255 bytes"))?;
        append(out, &[n])?;
    }
    Ok(())
}
fn pad_end(out: &mut Vec<u8>, pad: &Option<Vec<u8>>) -> Result<(), Error> {
    if let Some(pad) = pad {
        append(out, pad)?;
    }
    Ok(())
}
impl Frame {
    fn encode(&self) -> Result<(FrameHeader, Vec<u8>), Error> {
        let mut p = Vec::new();
        let (kind, flags, stream) = match self {
            Self::Data(v) => {
                pad_start(&mut p, &v.padding, v.flags)?;
                append(&mut p, &v.data)?;
                pad_end(&mut p, &v.padding)?;
                (0, v.flags, v.stream)
            }
            Self::Headers(v) => {
                if v.priority.is_some() != (v.flags & 0x20 != 0) {
                    return Err(protocol("priority disagrees with flags"));
                }
                pad_start(&mut p, &v.padding, v.flags)?;
                if let Some(d) = v.priority {
                    put_dependency(&mut p, d)?;
                }
                append(&mut p, &v.fragment)?;
                pad_end(&mut p, &v.padding)?;
                (1, v.flags, v.stream)
            }
            Self::Priority(v) => {
                put_dependency(&mut p, v.dependency)?;
                (2, v.flags, v.stream)
            }
            Self::Reset(v) => {
                append(&mut p, &v.code.to_be_bytes())?;
                (3, v.flags, v.stream)
            }
            Self::Settings(v) => {
                if v.entries.len() > MAX_FRAME_SIZE / 6 {
                    return Err(size("too many settings"));
                }
                for e in &v.entries {
                    append(&mut p, &e.id.to_be_bytes())?;
                    append(&mut p, &e.value.to_be_bytes())?;
                }
                (4, v.flags, 0)
            }
            Self::PushPromise(v) => {
                pad_start(&mut p, &v.padding, v.flags)?;
                append(&mut p, &v.promised.to_be_bytes())?;
                append(&mut p, &v.fragment)?;
                pad_end(&mut p, &v.padding)?;
                (5, v.flags, v.stream)
            }
            Self::Ping(v) => {
                append(&mut p, &v.opaque)?;
                (6, v.flags, 0)
            }
            Self::GoAway(v) => {
                append(&mut p, &v.last_stream.to_be_bytes())?;
                append(&mut p, &v.code.to_be_bytes())?;
                append(&mut p, &v.debug)?;
                (7, v.flags, 0)
            }
            Self::WindowUpdate(v) => {
                append(&mut p, &v.increment.to_be_bytes())?;
                (8, v.flags, v.stream)
            }
            Self::Continuation(v) => {
                append(&mut p, &v.fragment)?;
                (9, v.flags, v.stream)
            }
            Self::Unknown(v) => {
                if v.kind <= 9 {
                    return Err(protocol("known type used as unknown"));
                }
                append(&mut p, &v.payload)?;
                (v.kind, v.flags, v.stream)
            }
        };
        Ok((
            FrameHeader {
                length: p.len(),
                kind,
                flags,
                stream,
            },
            p,
        ))
    }
}
macro_rules! frame_wire {
    ($($name:ident => $len:expr),+ $(,)?) => { $(impl Wire for $name {
        type ParseError = Error;
        type WriteError = Error;
        /// Reads exactly this frame type, including its nine-byte header.
        /// All framing rules checked by [`Frame::parse`] apply.
        fn parse(bytes: &[u8]) -> Result<Self, Error> {
            match Frame::parse(bytes)? { Frame::$name(v) => Ok(v), _ => Err(protocol("wrong frame type")) }
        }
        /// Appends this frame, including its header. Invalid fields leave
        /// `out` unchanged. The same strict checks as [`Frame::write`] apply.
        fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
            if ($len)(self) > MAX_FRAME_SIZE { return Err(size("payload exceeds 24 bits")); }
            Frame::$name(self.clone()).write(out)
        }
    })+ };
}
frame_wire!(
    Data => |v: &Data| v.data.len().saturating_add(v.padding.as_ref().map_or(0, |p| p.len().saturating_add(1))),
    Headers => |v: &Headers| v.fragment.len().saturating_add(v.padding.as_ref().map_or(0, |p| p.len().saturating_add(1))).saturating_add(if v.priority.is_some() { 5 } else { 0 }),
    Priority => |_: &Priority| 5,
    Reset => |_: &Reset| 4,
    Settings => |v: &Settings| v.entries.len().saturating_mul(6),
    PushPromise => |v: &PushPromise| v.fragment.len().saturating_add(4).saturating_add(v.padding.as_ref().map_or(0, |p| p.len().saturating_add(1))),
    Ping => |_: &Ping| 8,
    GoAway => |v: &GoAway| v.debug.len().saturating_add(8),
    WindowUpdate => |_: &WindowUpdate| 4,
    Continuation => |v: &Continuation| v.fragment.len(),
    Unknown => |v: &Unknown| v.payload.len(),
);

/// A frame or preface read by [`Frames`]. Refused capture frames are items,
/// so a capture can continue after malformed or oversized payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameItem {
    /// The client's complete connection preface.
    Preface,
    /// A complete valid frame.
    Frame(Frame),
    /// A capture frame that strict parsing refused.
    Refused {
        /// The frame header, including the advertised payload length.
        header: FrameHeader,
        /// Why strict parsing refused the frame.
        error: Error,
        /// Whether only the header was consumed. The payload is then skipped.
        oversized: bool,
    },
}
/// A bounded frame decoder. Use [`Stream`] to own its unread bytes.
/// Strict mode is partition invariant and refuses oversized frames from
/// their header. Capture mode can accept a complete larger frame when
/// the caller supplies bounded read-ahead, as observe's HTTP/2 presenter does.
pub struct Frames {
    limit: usize,
    preface: u8,
    capture: bool,
    skip: usize,
}
impl Default for Frames {
    fn default() -> Self {
        Self::with_limit(DEFAULT_FRAME_SIZE)
    }
}
impl Frames {
    /// Reads frames without a preface, bounded by `limit` payload bytes.
    /// Limits above the 24-bit wire maximum are clamped.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_FRAME_SIZE),
            preface: 0,
            capture: false,
            skip: 0,
        }
    }
    /// Requires the client preface before frames.
    pub fn client_side(limit: usize) -> Self {
        Self {
            preface: 1,
            ..Self::with_limit(limit)
        }
    }
    /// Enables capture policy: accepts an optional preface, reports bad
    /// frames as items, and skips incomplete oversized payloads.
    /// `check_decode` does not apply above the chosen limit; complete
    /// frames in read-ahead are retained.
    pub fn for_observation(limit: usize) -> Self {
        Self {
            preface: 2,
            capture: true,
            ..Self::with_limit(limit)
        }
    }
    /// Changes the accepted payload limit between frames.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(MAX_FRAME_SIZE);
    }
    /// Whether an oversized capture payload is still being skipped.
    pub fn pending(&self) -> bool {
        self.skip != 0
    }
}
impl Decode for Frames {
    type Item = FrameItem;
    type Error = Error;
    const NAME: &'static str = "HTTP/2";
    /// The most unread frame bytes needed for a decoding step.
    fn capacity(&self) -> usize {
        (HEADER_LEN + self.limit).max(PREFACE.len())
    }
    /// Reads one frame or display item, or skips a refused payload.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<FrameItem>, Error> {
        if self.skip != 0 {
            let n = input.len().min(self.skip);
            if n == 0 {
                return if eof {
                    Err(size("truncated skipped payload"))
                } else {
                    Ok(Step::Need)
                };
            }
            self.skip -= n;
            return Ok(Step::Skip(n));
        }
        if self.preface != 0 {
            if input.len() < PREFACE.len() && PREFACE.starts_with(input) {
                return Ok(Step::Need);
            }
            if input.starts_with(PREFACE) {
                self.preface = 0;
                return Ok(Step::Item(FrameItem::Preface, PREFACE.len()));
            }
            if self.preface == 1 {
                return Err(protocol("invalid client preface"));
            }
            // No state changes until a complete frame or refused header is returned.
        }
        let Some(bytes) = input.get(..HEADER_LEN) else {
            return Ok(Step::Need);
        };
        let header = FrameHeader::parse(bytes)?;
        let total = HEADER_LEN + header.length;
        if header.length > self.limit && (!self.capture || input.len() < total) {
            let error = size("frame exceeds configured limit");
            if !self.capture {
                return Err(error);
            }
            self.skip = header.length;
            self.preface = 0;
            return Ok(Step::Item(
                FrameItem::Refused {
                    header,
                    error,
                    oversized: true,
                },
                HEADER_LEN,
            ));
        }
        if !self.capture {
            header.validate()?;
        }
        let Some(bytes) = input.get(..total) else {
            return Ok(Step::Need);
        };
        let item = match Frame::parse(bytes) {
            Ok(frame) => FrameItem::Frame(frame),
            Err(error) if self.capture => FrameItem::Refused {
                header,
                error,
                oversized: false,
            },
            Err(error) => return Err(error),
        };
        self.preface = 0;
        Ok(Step::Item(item, total))
    }
}

/// Limits for a direction. Values are clamped to the protocol and HPACK
/// bounds. DATA bodies belong in a caller-owned [`codec::Demux`](fictionet::stdlib::codec::Demux),
/// with one byte budget for all streams and both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Local payload ceiling, independent of the peer's negotiated limit.
    pub frame: usize,
    /// Maximum encoded bytes in one assembled header block.
    pub header_block: usize,
    /// Maximum retained decoded name and value bytes in a block.
    /// Indexed references can expand a few encoded bytes up to this limit.
    pub header_list: usize,
    /// Maximum tracked stream states, including ended streams until retired.
    pub streams: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame: MAX_FRAME_SIZE,
            header_block: 64 << 10,
            header_list: hpack::MAX_DECODED,
            streams: 256,
        }
    }
}
impl Limits {
    fn bounded(mut self) -> Self {
        self.frame = self.frame.min(MAX_FRAME_SIZE);
        self.header_block = self.header_block.min(hpack::MAX_BLOCK);
        self.header_list = self.header_list.min(hpack::MAX_DECODED);
        self.streams = self.streams.min(65_536);
        self
    }
}
/// The last known values announced by one endpoint. Unknown settings still
/// appear in [`Event::Settings`], without allocating a map of unknown IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingsState {
    /// SETTINGS_HEADER_TABLE_SIZE.
    pub header_table_size: u32,
    /// SETTINGS_ENABLE_PUSH.
    pub enable_push: bool,
    /// SETTINGS_MAX_CONCURRENT_STREAMS, if announced.
    pub max_concurrent_streams: Option<u32>,
    /// SETTINGS_INITIAL_WINDOW_SIZE.
    pub initial_window_size: u32,
    /// SETTINGS_MAX_FRAME_SIZE.
    pub max_frame_size: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE, if announced.
    pub max_header_list_size: Option<u32>,
}
impl Default for SettingsState {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: 65_535,
            max_frame_size: DEFAULT_FRAME_SIZE as u32,
            max_header_list_size: None,
        }
    }
}
impl SettingsState {
    fn apply(&mut self, settings: &Settings) -> Result<(), Error> {
        if settings.entries.len() > MAX_FRAME_SIZE / 6 {
            return Err(size("too many settings"));
        }
        if settings.flags & 1 != 0 {
            if !settings.entries.is_empty() {
                return Err(size("SETTINGS ack has a payload"));
            }
            return Ok(());
        }
        for s in &settings.entries {
            setting_valid(*s)?;
            match s.id {
                1 => self.header_table_size = s.value,
                2 => self.enable_push = s.value != 0,
                3 => self.max_concurrent_streams = Some(s.value),
                4 => self.initial_window_size = s.value,
                5 => self.max_frame_size = s.value,
                6 => self.max_header_list_size = Some(s.value),
                _ => {}
            }
        }
        Ok(())
    }
}
/// Events produced by a direction. SETTINGS and WINDOW_UPDATE describe
/// credit for the opposite direction; apply them there between reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client preface was read.
    Preface,
    /// Initial or informational HTTP headers.
    Headers {
        /// Stream identifier.
        stream: u32,
        /// Decoded fields, in wire order.
        fields: Vec<hpack::Field>,
        /// END_STREAM on the initiating HEADERS frame.
        end: bool,
    },
    /// DATA without padding. Route these bytes through a shared Demux.
    Data {
        /// Stream identifier.
        stream: u32,
        /// Application payload bytes.
        data: Vec<u8>,
        /// END_STREAM on this frame.
        end: bool,
    },
    /// Final trailing fields. Trailers always end the direction's stream.
    Trailers {
        /// Stream identifier.
        stream: u32,
        /// Decoded fields, including any grpc-status.
        fields: Vec<hpack::Field>,
    },
    /// The stream was reset.
    Reset {
        /// Stream identifier.
        stream: u32,
        /// Error code, including unknown values.
        code: u32,
    },
    /// Connection shutdown. Buffered in-flight frames may still follow.
    GoAway {
        /// Last processed stream.
        last_stream: u32,
        /// Error code, including unknown values.
        code: u32,
        /// Opaque debug bytes.
        debug: Vec<u8>,
    },
    /// Announced settings or an ACK.
    Settings(Settings),
    /// PING or its ACK.
    Ping(Ping),
    /// Credit for the opposite direction.
    WindowUpdate(WindowUpdate),
    /// Legacy stream priority.
    Priority(Priority),
    /// A complete promised request header block.
    PushPromise {
        /// Associated stream.
        stream: u32,
        /// Promised stream.
        promised: u32,
        /// Decoded request fields.
        fields: Vec<hpack::Field>,
    },
    /// An extension frame that was ignored by connection state.
    Unknown(Unknown),
}
struct Pending {
    stream: u32,
    end: bool,
    promised: Option<u32>,
    bytes: Option<Vec<u8>>,
}
/// What [`HeaderBlocks::read`] found in one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRead {
    /// The frame's stream.
    pub stream: u32,
    /// Whether the header block ends its stream (END_STREAM on its HEADERS).
    pub end: bool,
    /// The stream a PUSH_PROMISE promises.
    pub promised: Option<u32>,
    /// The decoded block, once its last fragment is read.
    pub block: Option<hpack::Block>,
    /// What an observer cannot read, in order, as a field name and a
    /// sentence. Only [`HeaderBlocks::for_observation`] writes these.
    pub notes: Vec<(&'static str, String)>,
    /// Whether the frame broke the header block rules.
    pub malformed: bool,
    /// Whether this frame cut off a header block still open. The first
    /// note then says so.
    pub interrupted: bool,
}
impl BlockRead {
    fn note(&mut self, name: &'static str, text: &str) {
        self.notes.push((name, text.into()));
    }
}
/// Header block assembly and HPACK decoding for one direction: HEADERS,
/// PUSH_PROMISE and CONTINUATION fragments joined and decoded.
/// [`Session`] uses one strictly. Made with
/// [`for_observation`](Self::for_observation), it reads what a capture
/// holds: a fragment that breaks the rules, is cut off, or is too long is
/// noted in the [`BlockRead`] and forgotten, and the next block is read.
pub struct HeaderBlocks {
    table: hpack::Table,
    pending: Option<Pending>,
    limit: usize,
    decoded: usize,
    capture: bool,
}
impl HeaderBlocks {
    fn new(limits: Limits, capture: bool) -> Self {
        Self {
            table: if capture {
                hpack::Table::for_observation()
            } else {
                hpack::Table::new(4096)
            },
            pending: None,
            limit: limits.header_block,
            decoded: limits.header_list,
            capture,
        }
    }
    /// Reads a capture with the default [`Limits`]: an HPACK table that
    /// tolerates entries it never saw, and notes instead of errors.
    pub fn for_observation() -> Self {
        Self::new(Limits::default().bounded(), true)
    }
    /// Drops a block in progress and the HPACK table, as after a gap in
    /// the capture.
    pub fn forget(&mut self) {
        self.pending = None;
        self.table.forget();
    }
    /// Bytes held: the HPACK table and a block in progress.
    pub fn held(&self) -> usize {
        self.table.table_size().saturating_add(
            self.pending
                .as_ref()
                .and_then(|p| p.bytes.as_ref())
                .map_or(0, Vec::len),
        )
    }
    /// Whether a header block waits for its CONTINUATION.
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    /// Sets the most decoded header bytes the next block may hold. A
    /// capture sets it to the room left in its display.
    pub fn set_list_limit(&mut self, bytes: usize) {
        self.decoded = bytes;
    }
    /// Reads one frame's part of a header block. Frames other than
    /// HEADERS, PUSH_PROMISE and CONTINUATION only check that no block is
    /// open. `payload` is `None` for a frame whose payload a capture could
    /// not keep: that block is then not decoded, and HPACK is forgotten,
    /// but the CONTINUATION boundary is kept.
    pub fn read(&mut self, h: FrameHeader, payload: Option<&[u8]>) -> Result<BlockRead, Error> {
        let mut out = BlockRead {
            stream: h.stream,
            end: h.kind == 1 && h.flags & 1 != 0,
            promised: None,
            block: None,
            notes: Vec::new(),
            malformed: false,
            interrupted: false,
        };
        if self
            .pending
            .as_ref()
            .is_some_and(|p| h.kind != 9 || h.stream != p.stream)
        {
            if !self.capture {
                return Err(protocol("interleaved header block"));
            }
            self.forget();
            out.interrupted = true;
            out.note(
                "Header block",
                "the one before was cut off by this frame, so later headers may not be known",
            );
            out.malformed = true;
        }
        if !matches!(h.kind, 1 | 5 | 9) {
            return Ok(out);
        }
        let fragment = payload.and_then(|p| match h.kind {
            1 => {
                let (b, _) = unpad(p, h.flags).ok()?;
                if h.flags & 0x20 != 0 {
                    b.get(5..)
                } else {
                    Some(b)
                }
            }
            5 => {
                let (b, _) = unpad(p, h.flags).ok()?;
                let id = u32_at(b, 0).ok()? & MAX_WINDOW;
                out.promised = Some(id);
                out.notes.push(("Promised stream", id.to_string()));
                b.get(4..)
            }
            _ => Some(p),
        });
        if payload.is_some() && fragment.is_none() {
            if !self.capture {
                return Err(protocol("short padded header frame"));
            }
            out.note(
                "Header block",
                "the frame is too short for its padding or fields",
            );
            out.malformed = true;
        }
        let mut p = if h.kind == 9 {
            let Some(p) = self.pending.take() else {
                if !self.capture {
                    return Err(protocol("CONTINUATION without a header block"));
                }
                out.note(
                    "Header block",
                    "a CONTINUATION with no header block to continue",
                );
                out.malformed = true;
                self.table.forget();
                return Ok(out);
            };
            p
        } else {
            Pending {
                stream: h.stream,
                end: out.end,
                promised: out.promised,
                bytes: Some(Vec::new()),
            }
        };
        out.end = p.end;
        match (&mut p.bytes, fragment) {
            (Some(bytes), Some(f))
                if bytes
                    .len()
                    .checked_add(f.len())
                    .is_some_and(|n| n <= self.limit) =>
            {
                bytes
                    .try_reserve(f.len())
                    .map_err(|_| budget("header allocation failed"))?;
                bytes.extend_from_slice(f);
            }
            (Some(_), fragment) => {
                if !self.capture {
                    return Err(budget("header block exceeds limit"));
                }
                if fragment.is_some() {
                    out.note("Header block", "longer than the 64 KiB kept");
                }
                p.bytes = None;
                self.table.forget();
            }
            _ => {}
        }
        let Some(bytes) = &p.bytes else {
            out.note(
                "Header block",
                "not decoded, so later headers may not be known",
            );
            if h.flags & 4 == 0 {
                self.pending = Some(p);
            }
            return Ok(out);
        };
        if h.flags & 4 == 0 {
            out.note("Header block", "continues in the next frame");
            self.pending = Some(p);
            return Ok(out);
        }
        match self.table.decode_block(bytes, self.decoded) {
            Ok(block) => {
                if !self.capture && block.more != 0 {
                    return Err(budget("decoded header list exceeds limit"));
                }
                out.promised = p.promised;
                out.block = Some(block);
            }
            Err(_) => {
                if !self.capture {
                    return Err(error(ErrorCode::CompressionError, "invalid HPACK block"));
                }
                out.note("Header block", "could not be decoded: it is malformed");
                out.malformed = true;
            }
        }
        Ok(out)
    }
}
struct StreamState {
    window: i64,
    headers: bool,
    closed: bool,
    reset_by_peer: bool,
}

struct SettingsUpdate {
    table_min: Option<usize>,
    table_final: usize,
    window: u32,
    window_max: u32,
    frame_size: u32,
    frame_max: u32,
}

/// One sending direction of an HTTP/2 connection, with a [`Stream<Frames>`]
/// inside. `client_side` reads client-to-server bytes, including the preface;
/// `server_side` reads server-to-client bytes. A nonempty direction requires
/// initial SETTINGS. An empty direction can end cleanly.
///
/// Route SETTINGS, WINDOW_UPDATE, and RST_STREAM as described in the module
/// docs. Use [`peer_reset`](Self::peer_reset) for streams abandoned by GOAWAY.
/// SETTINGS reductions take effect when that sender acknowledges them.
/// This owner handles framing, compression, stream endings, and flow control.
/// The caller coordinates request IDs, push permission, HTTP field semantics,
/// SETTINGS acknowledgments, and transport writes across the two directions.
/// It does not perform I/O or generate replies.
///
/// Drain [`next`](Self::next) after each [`push`](Self::push), retry the
/// unaccepted suffix, and drain again after [`end`](Self::end). An error is
/// returned once and retained by [`failed`](Self::failed). DATA ownership
/// passes to the caller; route it to a [`fictionet::stdlib::codec::Demux`]
/// of [`fictionet::stdlib::grpc::Messages`] for gRPC under one shared budget.
pub struct Session {
    frames: Stream<Frames>,
    blocks: HeaderBlocks,
    limits: Limits,
    settings: SettingsState,
    peer: SettingsState,
    streams: BTreeMap<u32, StreamState>,
    peer_resets: BTreeSet<u32>,
    reset_before: [u32; 2],
    window: i64,
    first: bool,
    client: bool,
    stopped: bool,
    failed: Option<Error>,
    settings_updates: std::collections::VecDeque<SettingsUpdate>,
    initial_window: u32,
    frame_size: u32,
}
impl Session {
    /// Starts a client-to-server direction requiring the client preface.
    pub fn client_side(limits: Limits) -> Self {
        Self::new(limits, true)
    }
    /// Starts a server-to-client direction, beginning with SETTINGS.
    pub fn server_side(limits: Limits) -> Self {
        Self::new(limits, false)
    }
    fn new(limits: Limits, client: bool) -> Self {
        let limits = limits.bounded();
        let limit = limits.frame.min(DEFAULT_FRAME_SIZE);
        Self {
            frames: Stream::new(if client {
                Frames::client_side(limit)
            } else {
                Frames::with_limit(limit)
            }),
            blocks: HeaderBlocks::new(limits, false),
            limits,
            settings: SettingsState::default(),
            peer: SettingsState::default(),
            streams: BTreeMap::new(),
            peer_resets: BTreeSet::new(),
            reset_before: [0; 2],
            window: 65_535,
            first: true,
            client,
            stopped: false,
            failed: None,
            settings_updates: std::collections::VecDeque::new(),
            initial_window: 65_535,
            frame_size: DEFAULT_FRAME_SIZE as u32,
        }
    }
    /// Accepts what fits. After a terminal error or gap, accepts and drops
    /// bytes. Drain events before retrying bytes past the returned count.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        if self.stopped {
            bytes.len()
        } else {
            self.frames.push(bytes)
        }
    }
    /// Marks transport EOF. Continue calling `next` to check partial frames
    /// and incomplete CONTINUATION assemblies.
    pub fn end(&mut self) {
        self.frames.end();
    }
    /// Discards framing, HPACK, windows, and stream state after a gap, and
    /// stops this direction. A gap has no trustworthy frame boundary.
    /// Construct a new direction only at a known new connection boundary.
    pub fn lost(&mut self) {
        self.frames = Stream::new(Frames::with_limit(
            self.limits.frame.min(DEFAULT_FRAME_SIZE),
        ));
        self.blocks.forget();
        self.streams.clear();
        self.peer_resets.clear();
        self.reset_before = [0; 2];
        self.settings_updates.clear();
        self.initial_window = 65_535;
        self.frame_size = DEFAULT_FRAME_SIZE as u32;
        self.settings = SettingsState::default();
        self.peer = SettingsState::default();
        self.window = 65_535;
        self.stopped = true;
    }
    /// The terminal error, retained after its single report.
    pub fn failed(&self) -> Option<&Error> {
        self.failed.as_ref()
    }
    /// Whether this direction has ended, failed, or lost frame alignment.
    pub fn is_done(&self) -> bool {
        self.stopped || self.frames.is_done()
    }
    /// Unread frame bytes held by the inner driver.
    pub fn buffered(&self) -> usize {
        self.frames.buffered()
    }
    /// Encoded header bytes and HPACK table bytes retained between frames.
    /// Stream metadata and recent peer-reset IDs are each separately bounded
    /// by `limits.streams`.
    pub fn held(&self) -> usize {
        self.blocks.held()
    }
    /// Settings announced by the sender of this direction.
    pub fn settings(&self) -> SettingsState {
        self.settings
    }
    /// The latest announced peer settings. Reductions can still await an ACK.
    pub fn peer(&self) -> SettingsState {
        self.peer
    }
    /// Remaining connection DATA credit, including padding accounting.
    pub fn connection_window(&self) -> i64 {
        self.window
    }
    /// Remaining DATA credit for a tracked stream. A settings reduction
    /// can make a stream window negative until more credit is granted.
    pub fn stream_window(&self, stream: u32) -> Option<i64> {
        self.streams.get(&stream).map(|s| s.window)
    }
    /// Releases an ended stream's metadata once the caller has retired its
    /// DATA decoder. Returns false for an unknown or still-open stream.
    /// Peer-reset tracking survives retirement.
    pub fn retire(&mut self, stream: u32) -> bool {
        if self.streams.get(&stream).is_some_and(|s| s.closed) {
            self.streams.remove(&stream);
            true
        } else {
            false
        }
    }
    /// Marks a stream closed after a peer reset or abandonment by GOAWAY.
    /// The caller can then release it with [`retire`](Self::retire).
    /// In-flight DATA is charged to the connection window, then dropped.
    /// Headers still update HPACK, then are dropped. The caller validates
    /// idle-stream rules, including resets before this direction's headers.
    ///
    /// Keeps at most `limits.streams` recent reset IDs. Older IDs fall
    /// below a per-parity watermark. Untracked streams at or below that
    /// watermark are also dropped. Tracked streams keep their own state.
    pub fn peer_reset(&mut self, stream: u32) {
        if stream == 0 || stream > MAX_WINDOW {
            return;
        }
        if let Some(state) = self.streams.get_mut(&stream) {
            state.closed = true;
            state.reset_by_peer = true;
        }
        let parity = (stream % 2) as usize;
        if stream > self.reset_before[parity] {
            self.peer_resets.insert(stream);
        }
        if self.peer_resets.len() > self.limits.streams
            && let Some(oldest) = self.peer_resets.pop_first()
        {
            let before = &mut self.reset_before[(oldest % 2) as usize];
            *before = (*before).max(oldest);
        }
    }
    fn reset_by_peer(&self, stream: u32) -> bool {
        self.streams.get(&stream).map_or_else(
            || {
                self.peer_resets.contains(&stream)
                    || stream <= self.reset_before[(stream % 2) as usize]
            },
            |state| state.reset_by_peer,
        )
    }
    /// Applies SETTINGS announced in the other direction. Increases can
    /// apply at once. HPACK, window, and frame-size reductions wait for this
    /// direction's SETTINGS ACK. At most 64 unacknowledged sets are retained.
    /// Errors stop the direction.
    pub fn peer_settings(&mut self, settings: &Settings) -> Result<(), Error> {
        if self.stopped {
            return Ok(());
        }
        let result = self.apply_peer(settings);
        self.remember(result)
    }
    fn apply_peer(&mut self, settings: &Settings) -> Result<(), Error> {
        let mut peer = self.peer;
        peer.apply(settings)?;
        if settings.flags & 1 != 0 {
            return Ok(());
        }
        if self.settings_updates.len() >= 64 {
            return Err(budget("too many unacknowledged settings"));
        }
        let mut window_min = peer.initial_window_size;
        let mut window_max = peer.initial_window_size;
        let mut frame_max = peer.max_frame_size;
        let mut table_min: Option<u32> = None;
        for setting in &settings.entries {
            match setting.id {
                1 => table_min = Some(table_min.map_or(setting.value, |n| n.min(setting.value))),
                4 => {
                    window_min = window_min.min(setting.value);
                    window_max = window_max.max(setting.value);
                }
                5 => frame_max = frame_max.max(setting.value),
                _ => {}
            }
        }
        // Check all intermediate window extremes, then apply one net delta.
        // Reductions remain optional until ACK, including for new streams.
        let initial = self.initial_window.max(window_max);
        self.set_initial_window(initial, window_min, initial)?;
        if peer.header_table_size > self.peer.header_table_size {
            self.blocks
                .table
                .set_settings_limit(peer.header_table_size as usize);
        }
        self.settings_updates.push_back(SettingsUpdate {
            table_min: table_min.map(|n| n as usize),
            table_final: peer.header_table_size as usize,
            window: peer.initial_window_size,
            window_max,
            frame_size: peer.max_frame_size,
            frame_max,
        });
        self.peer = peer;
        self.set_frame_size(self.frame_size.max(frame_max));
        Ok(())
    }
    fn set_initial_window(&mut self, value: u32, min: u32, max: u32) -> Result<(), Error> {
        let delta = i64::from(value) - i64::from(self.initial_window);
        let low = i64::from(min) - i64::from(self.initial_window);
        let high = i64::from(max) - i64::from(self.initial_window);
        for state in self.streams.values_mut() {
            if state.window.checked_add(low).is_none()
                || state
                    .window
                    .checked_add(high)
                    .is_none_or(|n| n > i64::from(MAX_WINDOW))
            {
                return Err(error(ErrorCode::FlowControlError, "window overflow"));
            }
            state.window = state
                .window
                .checked_add(delta)
                .ok_or_else(|| error(ErrorCode::FlowControlError, "window overflow"))?;
        }
        self.initial_window = value;
        Ok(())
    }
    fn set_frame_size(&mut self, value: u32) {
        self.frame_size = value;
        self.frames
            .decoder()
            .set_limit(self.limits.frame.min(value as usize));
    }
    fn acknowledge_settings(&mut self) -> Result<(), Error> {
        let Some(update) = self.settings_updates.pop_front() else {
            return Ok(());
        };
        if let Some(limit) = update.table_min {
            self.blocks.table.set_settings_limit(limit);
            self.blocks.table.set_settings_limit(update.table_final);
        }
        // Later increases may already be in use before their own ACK.
        let mut window = update.window;
        let mut frame_size = update.frame_size;
        for pending in &self.settings_updates {
            window = window.max(pending.window_max);
            frame_size = frame_size.max(pending.frame_max);
        }
        self.set_initial_window(window, window, window)?;
        self.set_frame_size(frame_size);
        Ok(())
    }
    /// Applies credit announced by the other direction. Unknown streams
    /// are ignored, including streams whose metadata was retired. The caller
    /// checks idle-stream rules using both directions' opening headers.
    /// Overflow and invalid increments stop decoding.
    pub fn peer_window_update(&mut self, update: &WindowUpdate) -> Result<(), Error> {
        if self.stopped {
            return Ok(());
        }
        let result = (|| {
            if update.increment == 0 || update.increment > MAX_WINDOW {
                return Err(protocol("invalid window increment"));
            }
            let window = if update.stream == 0 {
                &mut self.window
            } else if let Some(state) = self.streams.get_mut(&update.stream) {
                &mut state.window
            } else {
                return Ok(());
            };
            let next = window
                .checked_add(i64::from(update.increment))
                .ok_or_else(|| error(ErrorCode::FlowControlError, "window overflow"))?;
            if next > i64::from(MAX_WINDOW) {
                return Err(error(ErrorCode::FlowControlError, "window overflow"));
            }
            *window = next;
            Ok(())
        })();
        self.remember(result)
    }
    fn remember<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if let Err(e) = &result {
            self.failed = Some(*e);
            self.stopped = true;
        }
        result
    }
    fn stream_state(&mut self, id: u32) -> Result<&mut StreamState, Error> {
        if !self.streams.contains_key(&id) && self.streams.len() >= self.limits.streams {
            return Err(budget("stream state limit"));
        }
        Ok(self.streams.entry(id).or_insert(StreamState {
            window: i64::from(self.initial_window),
            headers: false,
            closed: false,
            reset_by_peer: false,
        }))
    }
    /// Returns the next event, or the direction's error once. `None` means
    /// more input is needed or the direction is done. Partial header blocks
    /// consume frames without yielding an event until END_HEADERS arrives.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<Event, Error>> {
        if self.stopped {
            return None;
        }
        loop {
            let next = self
                .frames
                .with_next(|item, bytes, _| (item, bytes.to_vec()));
            let result = match next {
                Some(Ok((item, bytes))) => self.step(item, &bytes),
                Some(Err(Fail::Protocol(e))) => Err(e),
                Some(Err(Fail::Truncated { .. })) => Err(size("truncated frame or preface")),
                Some(Err(Fail::Stuck { .. } | Fail::Refused { .. })) => {
                    Err(budget("frame buffer exhausted"))
                }
                None if self.frames.is_done() && self.blocks.pending.is_some() => {
                    Err(protocol("incomplete header block at EOF"))
                }
                None if self.frames.is_done() && self.first && self.frames.offset() != 0 => {
                    Err(protocol("missing initial SETTINGS"))
                }
                None => return None,
            };
            match self.remember(result) {
                Ok(Some(event)) => return Some(Ok(event)),
                Ok(None) => {}
                Err(e) => return Some(Err(e)),
            }
        }
    }
    fn step(&mut self, item: FrameItem, bytes: &[u8]) -> Result<Option<Event>, Error> {
        let frame = match item {
            FrameItem::Preface => return Ok(Some(Event::Preface)),
            FrameItem::Frame(f) => f,
            FrameItem::Refused { error, .. } => return Err(error),
        };
        if self.first {
            if !matches!(&frame, Frame::Settings(s) if s.flags & 1 == 0) {
                return Err(protocol("first frame must be SETTINGS"));
            }
            self.first = false;
        }
        let h = FrameHeader::parse(
            bytes
                .get(..HEADER_LEN)
                .ok_or_else(|| size("missing frame header"))?,
        )?;
        let block = self.blocks.read(h, bytes.get(HEADER_LEN..))?;
        if matches!(
            frame,
            Frame::Headers(_) | Frame::PushPromise(_) | Frame::Continuation(_)
        ) && self.reset_by_peer(h.stream)
        {
            return Ok(None);
        }
        if let Some(block_fields) = block.block {
            let fields = block_fields
                .headers
                .into_iter()
                .map(|h| {
                    Ok(hpack::Field {
                        name: h.name.ok_or_else(|| {
                            error(ErrorCode::CompressionError, "unknown header name")
                        })?,
                        value: h.value.ok_or_else(|| {
                            error(ErrorCode::CompressionError, "unknown header value")
                        })?,
                        never_index: h.never_index,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            if let Some(promised) = block.promised {
                if self.client {
                    return Err(protocol("client sent PUSH_PROMISE"));
                }
                return Ok(Some(Event::PushPromise {
                    stream: block.stream,
                    promised,
                    fields,
                }));
            }
            let informational = fields
                .iter()
                .any(|f| f.name == b":status" && f.value.first() == Some(&b'1'));
            let s = self.stream_state(block.stream)?;
            if s.closed {
                return Err(error(ErrorCode::StreamClosed, "headers on ended stream"));
            }
            let trailers = s.headers;
            if trailers && !block.end {
                return Err(protocol("trailers must end the stream"));
            }
            if informational && block.end {
                return Err(protocol("informational response ends stream"));
            }
            s.headers |= !informational;
            s.closed = block.end;
            return Ok(Some(if trailers {
                Event::Trailers {
                    stream: block.stream,
                    fields,
                }
            } else {
                Event::Headers {
                    stream: block.stream,
                    fields,
                    end: block.end,
                }
            }));
        }
        Ok(match frame {
            Frame::Headers(_) | Frame::PushPromise(_) | Frame::Continuation(_) => None,
            Frame::Data(d) => {
                let cost = i64::try_from(h.length).map_err(|_| size("DATA length"))?;
                if self.window < cost {
                    return Err(error(
                        ErrorCode::FlowControlError,
                        "connection window exhausted",
                    ));
                }
                if self.reset_by_peer(d.stream) {
                    self.window -= cost;
                    return Ok(None);
                }
                let s = self
                    .streams
                    .get_mut(&d.stream)
                    .ok_or_else(|| protocol("DATA before headers"))?;
                if s.closed {
                    return Err(error(ErrorCode::StreamClosed, "DATA on ended stream"));
                }
                if !s.headers {
                    return Err(protocol("DATA before final headers"));
                }
                if cost != 0 && s.window < cost {
                    return Err(error(
                        ErrorCode::FlowControlError,
                        "stream window exhausted",
                    ));
                }
                s.window -= cost;
                self.window -= cost;
                let end = d.flags & 1 != 0;
                s.closed = end;
                Some(Event::Data {
                    stream: d.stream,
                    data: d.data,
                    end,
                })
            }
            Frame::Settings(s) => {
                if s.flags & 1 != 0 {
                    self.acknowledge_settings()?;
                } else {
                    self.settings.apply(&s)?;
                }
                Some(Event::Settings(s))
            }
            Frame::Priority(p) => Some(Event::Priority(p)),
            Frame::Reset(r) => {
                if let Some(state) = self.streams.get_mut(&r.stream) {
                    state.closed = true;
                }
                Some(Event::Reset {
                    stream: r.stream,
                    code: r.code,
                })
            }
            Frame::Ping(p) => Some(Event::Ping(p)),
            Frame::GoAway(g) => Some(Event::GoAway {
                last_stream: g.last_stream,
                code: g.code,
                debug: g.debug,
            }),
            Frame::WindowUpdate(w) => Some(Event::WindowUpdate(w)),
            Frame::Unknown(u) => Some(Event::Unknown(u)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::contract;

    fn raw(kind: u8, flags: u8, stream: u32, body: &[u8]) -> Vec<u8> {
        let mut out = FrameHeader {
            length: body.len(),
            kind,
            flags,
            stream,
        }
        .to_bytes()
        .unwrap();
        out.extend_from_slice(body);
        out
    }
    fn settings() -> Vec<u8> {
        raw(4, 0, 0, &[])
    }
    fn run(bytes: &[u8], chunk: usize) -> Vec<Result<Event, Error>> {
        let mut c = Session::client_side(Limits::default());
        let mut out = Vec::new();
        for chunk in bytes.chunks(chunk) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let n = c.push(rest);
                rest = &rest[n..];
                while let Some(e) = c.next() {
                    out.push(e);
                }
                assert!(n > 0 || rest.is_empty());
            }
        }
        c.end();
        while let Some(e) = c.next() {
            out.push(e);
        }
        assert!(c.is_done());
        assert!(c.next().is_none());
        out
    }
    fn accept(c: &mut Session, bytes: &[u8]) -> Vec<Event> {
        let mut rest = bytes;
        let mut out = Vec::new();
        loop {
            let n = c.push(rest);
            rest = &rest[n..];
            while let Some(e) = c.next() {
                out.push(e.unwrap());
            }
            if rest.is_empty() {
                return out;
            }
            assert!(n > 0);
        }
    }
    #[test]
    fn every_frame_type_round_trips_and_writes_transactionally() {
        let frames = [
            raw(0, 0x81, 1, b"data"),
            raw(1, 0x25, 1, &[0x80, 0, 0, 0, 255, 0x82]),
            raw(2, 0xff, 1, &[0, 0, 0, 3, 0]),
            raw(3, 0, 1, &8u32.to_be_bytes()),
            raw(4, 0, 0, &[0, 1, 0, 0, 16, 0, 0xff, 0xff, 1, 2, 3, 4]),
            raw(5, 4, 1, &[0, 0, 0, 2, 0x82]),
            raw(6, 1, 0, b"12345678"),
            raw(7, 0x80, 0, &[0, 0, 0, 1, 0, 0, 0, 8, b'x']),
            raw(8, 0, 0, &[0, 0, 0, 1]),
            raw(9, 4, 1, &[0x84]),
            raw(255, 255, 3, b"opaque"),
        ];
        for bytes in &frames {
            contract::check_wire::<Frame>(bytes);
            let frame = Frame::parse(bytes).unwrap();
            assert_eq!(frame.to_bytes().unwrap(), *bytes);
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Frame::parse(&trailing).is_err());
            contract::check_decode(|| Frames::with_limit(128), bytes);
        }
        macro_rules! wire { ($($ty:ty => $i:expr),+) => { $(contract::check_wire::<$ty>(&frames[$i]);)+ }; }
        wire!(Data => 0, Headers => 1, Priority => 2, Reset => 3, Settings => 4, PushPromise => 5,
            Ping => 6, GoAway => 7, WindowUpdate => 8, Continuation => 9, Unknown => 10);
        let mut out = vec![7, 8];
        let invalid = Data {
            stream: 0,
            flags: 8,
            data: vec![1],
            padding: None,
        };
        assert!(invalid.write(&mut out).is_err());
        assert_eq!(out, [7, 8]);
        let invalid = WindowUpdate {
            stream: 0,
            flags: 0,
            increment: 0,
        };
        assert!(invalid.write(&mut out).is_err());
        assert_eq!(out, [7, 8]);
        let h = FrameHeader {
            length: MAX_FRAME_SIZE + 1,
            kind: 0,
            flags: 0,
            stream: 1,
        };
        assert!(h.write(&mut out).is_err());
        assert_eq!(out, [7, 8]);
        contract::check_wire::<FrameHeader>(&frames[0][..9]);
    }
    #[test]
    fn padding_round_trips_for_data_headers_and_push_promise() {
        for pad in [0, 1, 255] {
            for (kind, mut body) in [
                (0, b"hi".to_vec()),
                (1, vec![0x82]),
                (5, vec![0, 0, 0, 2, 0x82]),
            ] {
                body.insert(0, pad);
                body.extend(vec![0xa5; pad as usize]);
                let bytes = raw(kind, 0xc, 1, &body);
                assert_eq!(Frame::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
            }
        }
        assert!(Frame::parse(&raw(0, 8, 1, &[3, 1, 2])).is_err());
        assert!(Frame::parse(&raw(1, 8, 1, &[])).is_err());
    }
    #[test]
    fn padding_over_mandatory_fields_is_a_protocol_error() {
        // RFC 9113 4.2 and 6.2: a payload too short for its fields is a
        // FRAME_SIZE_ERROR; padding that covers them is a PROTOCOL_ERROR.
        for (kind, flags, body, code) in [
            (0, 8, vec![], ErrorCode::FrameSizeError),
            (1, 8, vec![], ErrorCode::FrameSizeError),
            (1, 0x28, vec![0, 0, 0, 0], ErrorCode::FrameSizeError),
            (1, 0x20, vec![0, 0, 0, 0], ErrorCode::FrameSizeError),
            (1, 0x28, vec![2, 0, 0, 0, 3, 0], ErrorCode::ProtocolError),
            (5, 8, vec![0, 0, 0], ErrorCode::FrameSizeError),
            (5, 0, vec![0, 0, 0], ErrorCode::FrameSizeError),
            (5, 8, vec![2, 0, 0, 0, 2], ErrorCode::ProtocolError),
            (0, 8, vec![3, 1, 2], ErrorCode::ProtocolError),
        ] {
            assert_eq!(
                Frame::parse(&raw(kind, flags, 1, &body)).unwrap_err().code,
                code,
                "kind {kind}, flags {flags:#x}, body {body:?}"
            );
        }
    }
    #[test]
    fn rejects_bad_lengths_zero_streams_and_invalid_values() {
        for (kind, stream, body) in [
            (2, 1, vec![0; 4]),
            (3, 1, vec![0; 5]),
            (4, 0, vec![0]),
            (6, 0, vec![0; 7]),
            (7, 0, vec![0; 7]),
            (8, 1, vec![0; 5]),
        ] {
            assert_eq!(
                Frame::parse(&raw(kind, 0, stream, &body)).unwrap_err().code,
                ErrorCode::FrameSizeError
            );
        }
        for kind in [0, 1, 2, 3, 5, 9] {
            assert!(Frame::parse(&raw(kind, 0, 0, &[])).is_err());
        }
        for kind in [4, 6, 7] {
            assert!(Frame::parse(&raw(kind, 0, 1, &[])).is_err());
        }
        for bytes in [
            raw(4, 1, 0, &[0; 6]),
            raw(4, 0, 0, &[0, 2, 0, 0, 0, 2]),
            raw(4, 0, 0, &[0, 5, 0, 0, 0, 0]),
            raw(8, 0, 1, &[0; 4]),
            raw(2, 0, 1, &[0, 0, 0, 1, 2]),
        ] {
            assert!(Frame::parse(&bytes).is_err());
        }
        let mut s = Stream::new(Frames::with_limit(2));
        assert_eq!(s.push(&raw(0, 0, 1, b"abc")), 12);
        assert!(s.next().unwrap().is_err());
        assert!(s.next().is_none());
        assert!(s.failed().is_some());
    }
    #[test]
    fn continuation_headers_and_trailers_are_partition_invariant() {
        let fields = [
            hpack::Field::new(":method", "POST"),
            hpack::Field::new(":path", "/s/m"),
        ];
        let mut encoder = hpack::Encoder::new(4096);
        let mut block = Vec::new();
        encoder.encode_block(&fields, &mut block).unwrap();
        let mut bytes = [PREFACE.as_slice(), &settings()].concat();
        bytes.extend(raw(1, 0, 1, &block[..1]));
        bytes.extend(raw(9, 4, 1, &block[1..]));
        bytes.extend(raw(0, 0, 1, b"abc"));
        let mut trailers = Vec::new();
        encoder
            .encode_block(&[hpack::Field::new("grpc-status", "0")], &mut trailers)
            .unwrap();
        bytes.extend(raw(1, 1, 1, &trailers[..2]));
        bytes.extend(raw(9, 4, 1, &trailers[2..]));
        let expected = run(&bytes, bytes.len());
        assert_eq!(run(&bytes, 1), expected);
        assert!(
            matches!(&expected[2], Ok(Event::Headers { fields: h, end: false, .. }) if h == &fields)
        );
        assert!(
            matches!(&expected[4], Ok(Event::Trailers { fields, .. }) if fields[0].name == b"grpc-status")
        );
        contract::check_decode(|| Frames::client_side(DEFAULT_FRAME_SIZE), &bytes);
    }
    #[test]
    fn continuation_failures_and_eof_are_reported_once() {
        for tail in [raw(6, 0, 0, &[0; 8]), raw(9, 4, 3, &[0x84]), Vec::new()] {
            let bytes = [
                PREFACE.as_slice(),
                &settings(),
                &raw(1, 0, 1, &[0x82]),
                &tail,
            ]
            .concat();
            let events = run(&bytes, 1);
            assert_eq!(events.iter().filter(|e| e.is_err()).count(), 1);
            assert_eq!(
                events.last().unwrap().as_ref().unwrap_err().code,
                ErrorCode::ProtocolError
            );
        }
        let mut c = Session::server_side(Limits {
            header_block: 1,
            ..Limits::default()
        });
        accept(&mut c, &settings());
        accept(&mut c, &raw(1, 0, 1, &[0x88]));
        assert_eq!(c.push(&raw(9, 4, 1, &[0x88])), 10);
        assert_eq!(
            c.next().unwrap().unwrap_err().code,
            ErrorCode::EnhanceYourCalm
        );
        assert!(c.next().is_none());
        assert!(c.failed().is_some());
    }
    #[test]
    fn peer_credit_before_response_headers_and_after_retirement_is_allowed() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        let update = WindowUpdate {
            stream: 1,
            flags: 0,
            increment: 1 << 20,
        };
        // The caller has observed the request HEADERS in the other direction.
        c.peer_window_update(&update).unwrap();
        accept(&mut c, &raw(1, 4, 1, &[0x88]));
        accept(&mut c, &raw(0, 1, 1, b"done"));
        assert!(c.retire(1));
        c.peer_window_update(&update).unwrap();
        assert!(c.failed().is_none());
    }

    #[test]
    fn peer_reset_drops_in_flight_data_before_and_after_retire() {
        for retired in [false, true] {
            let mut c = Session::client_side(Limits::default());
            accept(&mut c, PREFACE);
            accept(&mut c, &settings());
            accept(&mut c, &raw(1, 4, 1, &[0x82]));
            accept(&mut c, &raw(0, 0, 1, b"abc"));
            c.peer_reset(1);
            if retired {
                assert!(c.retire(1));
            }
            // Padding also consumes connection credit on a reset stream.
            assert!(accept(&mut c, &raw(0, 9, 1, b"\x02def\0\0")).is_empty());
            assert_eq!(c.connection_window(), 65_535 - 9);
            assert!(c.failed().is_none());
            assert!(matches!(
                accept(&mut c, &raw(6, 0, 0, &[0; 8]))[..],
                [Event::Ping(_)]
            ));
        }
    }

    #[test]
    fn peer_reset_trailers_keep_hpack_in_sync_after_retire() {
        for retired in [false, true] {
            let mut c = Session::client_side(Limits::default());
            accept(&mut c, PREFACE);
            accept(&mut c, &settings());
            accept(&mut c, &raw(1, 4, 1, &[0x82]));
            c.peer_reset(1);
            if retired {
                assert!(c.retire(1));
            }
            // Incrementally indexed x: y, split over HEADERS and CONTINUATION.
            assert!(accept(&mut c, &raw(1, 1, 1, &[0x40, 1, b'x'])).is_empty());
            assert!(accept(&mut c, &raw(9, 4, 1, &[1, b'y'])).is_empty());
            let events = accept(&mut c, &raw(1, 4, 3, &[0x82, 0xbe]));
            assert!(matches!(&events[..], [Event::Headers { fields, .. }]
                if fields[1] == hpack::Field::new("x", "y")));
            assert!(c.failed().is_none());
        }
    }

    #[test]
    fn peer_reset_records_stay_bounded_and_preserve_other_streams() {
        let mut c = Session::server_side(Limits {
            streams: 2,
            ..Limits::default()
        });
        accept(&mut c, &settings());
        accept(&mut c, &raw(1, 4, 3, &[0x88]));
        for stream in [1, 2, 4, 5, 6, 7] {
            accept(&mut c, &raw(1, 4, stream, &[0x88]));
            c.peer_reset(stream);
            assert!(c.retire(stream));
            assert!(c.peer_resets.len() <= 2);
        }
        for stream in [1, 2, 4, 5, 6, 7] {
            assert!(accept(&mut c, &raw(0, 1, stream, b"late")).is_empty());
            assert!(accept(&mut c, &raw(1, 5, stream, &[])).is_empty());
        }
        assert_eq!(c.connection_window(), 65_535 - 24);
        assert!(matches!(
            accept(&mut c, &raw(0, 1, 3, b"done"))[..],
            [Event::Data { stream: 3, .. }]
        ));
        assert!(c.failed().is_none());
        // A tracked stream ended normally still rejects further DATA.
        assert_eq!(c.push(&raw(0, 0, 3, b"late")), 13);
        assert_eq!(c.next().unwrap().unwrap_err().code, ErrorCode::StreamClosed);
    }

    #[test]
    fn peer_reset_before_headers_keeps_connection_checks() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        c.peer_reset(1);
        assert!(accept(&mut c, &raw(1, 4, 1, &[0x88])).is_empty());
        assert!(accept(&mut c, &raw(0, 0, 1, b"late")).is_empty());
        assert_eq!(c.stream_window(1), None);
        c.window = 3;
        assert_eq!(c.push(&raw(0, 1, 1, b"late")), 13);
        assert_eq!(
            c.next().unwrap().unwrap_err().code,
            ErrorCode::FlowControlError
        );

        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        c.peer_reset(1);
        assert_eq!(c.push(&raw(1, 5, 1, &[0xff])), 10);
        assert_eq!(
            c.next().unwrap().unwrap_err().code,
            ErrorCode::CompressionError
        );
    }

    #[test]
    fn caller_can_retire_streams_abandoned_by_goaway() {
        let mut c = Session::server_side(Limits {
            streams: 4,
            ..Limits::default()
        });
        accept(&mut c, &settings());
        for stream in [1, 3, 5, 7] {
            accept(&mut c, &raw(1, 4, stream, &[0x88]));
        }
        // The peer's GOAWAY accepted only stream 1. The caller owns this list.
        for stream in [3, 5, 7] {
            c.peer_reset(stream);
            assert!(c.retire(stream));
        }
        c.peer_reset(99);
        assert!(!c.retire(99));
        assert!(!c.retire(1));
        for stream in [9, 11, 13] {
            accept(&mut c, &raw(1, 4, stream, &[0x88]));
        }
        assert!(c.failed().is_none());
    }

    #[test]
    fn window_reductions_accept_in_flight_data_until_ack() {
        for already_open in [false, true] {
            let mut c = Session::client_side(Limits::default());
            if already_open {
                accept(&mut c, &[PREFACE.as_slice(), &settings()].concat());
                accept(&mut c, &raw(1, 4, 1, &[0x82]));
            }
            c.peer_settings(&Settings {
                flags: 0,
                entries: vec![Setting {
                    id: 4,
                    value: 16_384,
                }],
            })
            .unwrap();
            if !already_open {
                accept(&mut c, &[PREFACE.as_slice(), &settings()].concat());
                accept(&mut c, &raw(1, 4, 1, &[0x82]));
            }
            accept(&mut c, &raw(0, 0, 1, &[0; 16_384]));
            accept(&mut c, &raw(0, 0, 1, &[0; 10_000]));
            accept(&mut c, &raw(4, 1, 0, &[]));
            assert_eq!(c.stream_window(1), Some(-10_000));
            assert_eq!(c.push(&raw(0, 0, 1, &[0])), 10);
            assert_eq!(
                c.next().unwrap().unwrap_err().code,
                ErrorCode::FlowControlError
            );
        }
    }

    #[test]
    fn frame_size_reductions_accept_in_flight_frames_until_ack() {
        let mut c = Session::server_side(Limits {
            frame: 32_768,
            ..Limits::default()
        });
        accept(&mut c, &settings());
        for value in [32_768, 16_384] {
            c.peer_settings(&Settings {
                flags: 0,
                entries: vec![Setting { id: 5, value }],
            })
            .unwrap();
            if value == 32_768 {
                accept(&mut c, &raw(4, 1, 0, &[]));
            }
        }
        accept(&mut c, &raw(1, 4, 1, &[0x88]));
        accept(&mut c, &raw(0, 0, 1, &[0; 20_000]));
        accept(&mut c, &raw(4, 1, 0, &[]));
        let header = FrameHeader {
            length: 20_000,
            kind: 0,
            flags: 0,
            stream: 1,
        };
        assert_eq!(c.push(&header.to_bytes().unwrap()), 9);
        assert_eq!(
            c.next().unwrap().unwrap_err().code,
            ErrorCode::FrameSizeError
        );
    }

    #[test]
    fn settings_update_opposite_direction_and_padding_spends_credit() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        accept(&mut c, &raw(1, 4, 1, &[0x88]));
        accept(&mut c, &raw(0, 8, 1, &[2, b'a', 0, 0]));
        assert_eq!(c.connection_window(), 65_531);
        assert_eq!(c.stream_window(1), Some(65_531));
        let announced = Settings {
            flags: 0,
            entries: vec![
                Setting { id: 4, value: 2 },
                Setting {
                    id: 5,
                    value: 32_768,
                },
                Setting { id: 1, value: 0 },
            ],
        };
        c.peer_settings(&announced).unwrap();
        assert_eq!(c.stream_window(1), Some(65_531));
        assert_eq!(c.peer().max_frame_size, 32_768);
        assert_eq!(c.settings().max_frame_size, 16_384);
        c.peer_window_update(&WindowUpdate {
            stream: 1,
            flags: 0,
            increment: 10,
        })
        .unwrap();
        assert_eq!(c.stream_window(1), Some(65_541));
        accept(&mut c, &raw(4, 1, 0, &[]));
        assert_eq!(c.stream_window(1), Some(8));
        assert_eq!(c.blocks.table.settings_limit(), Some(0));
        accept(&mut c, &raw(1, 4, 3, &[0x20, 0x88]));
        assert_eq!(c.stream_window(3), Some(2));
        accept(&mut c, &raw(0, 1, 3, b"ok"));
        assert!(c.retire(3));
        assert!(!c.retire(1));
        let overflow = c
            .peer_window_update(&WindowUpdate {
                stream: 0,
                flags: 0,
                increment: MAX_WINDOW,
            })
            .unwrap_err();
        assert_eq!(overflow.code, ErrorCode::FlowControlError);
        assert!(c.next().is_none());
    }
    #[test]
    fn hpack_settings_increases_do_not_require_a_spurious_reduction() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        c.peer_settings(&Settings {
            flags: 0,
            entries: vec![Setting { id: 1, value: 8192 }],
        })
        .unwrap();
        let mut block = Vec::new();
        fictionet::stdlib::prefix_int::write(&mut block, 5, 0x20, 8192).unwrap();
        block.push(0x88);
        accept(&mut c, &raw(1, 4, 1, &block));
        accept(&mut c, &raw(4, 1, 0, &[]));
        accept(&mut c, &raw(1, 4, 3, &[0x88]));
        c.peer_settings(&Settings {
            flags: 0,
            entries: vec![
                Setting { id: 1, value: 1024 },
                Setting { id: 1, value: 2048 },
            ],
        })
        .unwrap();
        accept(&mut c, &raw(4, 1, 0, &[]));
        block.clear();
        fictionet::stdlib::prefix_int::write(&mut block, 5, 0x20, 1024).unwrap();
        fictionet::stdlib::prefix_int::write(&mut block, 5, 0x20, 2048).unwrap();
        block.push(0x88);
        accept(&mut c, &raw(1, 4, 5, &block));
        assert_eq!(c.blocks.table.table_capacity(), Some(2048));
    }

    #[test]
    fn hpack_errors_and_flow_control_limits_stop_the_connection() {
        for (frame, code) in [
            (raw(1, 4, 1, &[0xff]), ErrorCode::CompressionError),
            (raw(0, 0, 1, &[0; 2]), ErrorCode::FlowControlError),
        ] {
            let mut c = Session::server_side(Limits::default());
            accept(&mut c, &settings());
            accept(&mut c, &raw(1, 4, 1, &[0x88]));
            c.peer_settings(&Settings {
                flags: 0,
                entries: vec![Setting { id: 4, value: 1 }],
            })
            .unwrap();
            accept(&mut c, &raw(4, 1, 0, &[]));
            assert_eq!(c.push(&frame), frame.len());
            assert_eq!(c.next().unwrap().unwrap_err().code, code);
            assert!(c.next().is_none());
        }
    }
    #[test]
    fn gap_discards_compression_assembly_and_frame_state() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        accept(&mut c, &raw(1, 0, 1, &[0x40, 1, b'x']));
        assert!(c.held() > 0);
        c.lost();
        assert_eq!(c.held(), 0);
        assert_eq!(c.buffered(), 0);
        assert_eq!(c.push(&raw(9, 4, 1, &[1, b'y'])), 11);
        assert!(c.next().is_none());
    }
    #[test]
    fn empty_directions_end_cleanly_but_a_preface_requires_settings() {
        for mut c in [
            Session::client_side(Limits::default()),
            Session::server_side(Limits::default()),
        ] {
            c.end();
            assert!(c.next().is_none());
            assert!(c.is_done());
            assert!(c.failed().is_none());
        }
        let mut c = Session::client_side(Limits::default());
        accept(&mut c, PREFACE);
        c.end();
        assert_eq!(
            c.next().unwrap().unwrap_err().reason,
            "missing initial SETTINGS"
        );
    }

    #[test]
    fn queued_window_reductions_and_increases_follow_ack_order() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        accept(&mut c, &raw(1, 4, 1, &[0x88]));
        for values in [vec![0], vec![100_000], vec![10, 20]] {
            c.peer_settings(&Settings {
                flags: 0,
                entries: values
                    .into_iter()
                    .map(|value| Setting { id: 4, value })
                    .collect(),
            })
            .unwrap();
        }
        assert_eq!(c.stream_window(1), Some(100_000));
        for expected in [100_000, 100_000, 20] {
            accept(&mut c, &raw(4, 1, 0, &[]));
            assert_eq!(c.stream_window(1), Some(expected));
        }
        c.peer_window_update(&WindowUpdate {
            stream: 1,
            flags: 0,
            increment: MAX_WINDOW - 20,
        })
        .unwrap();
        let error = c
            .peer_settings(&Settings {
                flags: 0,
                entries: vec![Setting { id: 4, value: 21 }, Setting { id: 4, value: 20 }],
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::FlowControlError);
    }

    #[test]
    fn frame_contracts_on_arbitrary_bytes() {
        let mut rng = fictionet::stdlib::codec::Lcg::new(0x6832);
        for _ in 0..128 {
            let bytes = rng.bytes(128);
            contract::check_wire::<Frame>(&bytes);
            contract::check_wire::<FrameHeader>(&bytes);
            contract::check_decode(|| Frames::with_limit(128), &bytes);
        }
    }
}
