//! HTTP/2 frames and directional state (RFC 9113).
//!
//! `Frame` implements `Wire`, `Inputs` decodes the stream, and `Session` tracks
//! one direction rather than a whole client or server. This module has no
//! server layer or live transport. The native server in
//! `fictionet::stdlib::web::httpd` and the observe presenter share this frame layer.
//!
//! Use [`Session`] for endpoint decoding. [`Inputs`] reports frame errors
//! with their scope and frame context. Passive capture reconstruction lives
//! beside the HTTP/2 dissector and shares the neutral framing primitives.
//! Announce a request's opening HEADERS to the response direction's
//! [`Session::peer_open`] before routing WINDOW_UPDATE. The direction that
//! reads a PUSH_PROMISE registers its promised stream. This retains credit
//! received before response headers.
//! Route SETTINGS and WINDOW_UPDATE to the opposite direction's
//! [`Session::peer_settings`] and [`Session::peer_window_update`].
//! Route RST_STREAM through [`Session::peer_reset`], then retire both halves.
//! In-flight DATA on a peer-reset stream still consumes connection credit.
//! Its headers still update HPACK. Neither produces an event, even after retire.
//! For GOAWAY, the caller identifies abandoned streams above `last_stream`,
//! closes both halves with `peer_reset`, and retires their DATA decoders.
//! Idle-stream checks and stream ownership belong to the caller.
//! SETTINGS reductions take effect when the sending direction reads its ACK.
//! Later pending HPACK increases do not cancel required size updates.
//!
//! ```
//! use fictionet::stdlib::protocols::http2::{Limits, Session, WindowUpdate};
//!
//! let mut response = Session::server_side(Limits::default());
//! // The request direction has emitted opening HEADERS for stream 1.
//! response.peer_open(1)?;
//! response.peer_window_update(&WindowUpdate {
//!     stream: 1, flags: 0, increment: 65_536,
//! })?;
//! assert_eq!(response.stream_window(1), Some(131_071));
//! # Ok::<(), fictionet::stdlib::protocols::http2::Error>(())
//! ```

use fictionet::stdlib::codec::Side;
use fictionet::stdlib::{
    codec::{Decode, Fail, Step, Storage, Stream, Wire, be32},
    protocols::{fields::Fields, hpack},
};
use fictionet::{Budget, Chunk};
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
    at.checked_add(4)
        .ok_or_else(|| size("integer offset overflow"))?;
    be32(bytes, at).ok_or_else(|| size("truncated integer"))
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
        let bytes = self.to_array()?;
        out.try_reserve(HEADER_LEN)
            .map_err(|_| budget("allocation failed"))?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}
impl FrameHeader {
    /// The nine bytes of the header, for a writer that puts them in place
    /// rather than appending them. Rejects lengths over 24 bits and stream
    /// IDs over 31 bits.
    pub fn to_array(&self) -> Result<[u8; HEADER_LEN], Error> {
        if self.length > MAX_FRAME_SIZE || self.stream > MAX_WINDOW {
            return Err(size("header integer out of range"));
        }
        let [_, length @ ..] = (self.length as u32).to_be_bytes();
        let [s0, s1, s2, s3] = self.stream.to_be_bytes();
        let [l0, l1, l2] = length;
        Ok([l0, l1, l2, self.kind, self.flags, s0, s1, s2, s3])
    }
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
fn unpad(payload: &[u8], flags: u8) -> Result<(&[u8], Option<&[u8]>), Error> {
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
        Some(rest.get(end..).ok_or_else(|| size("padding"))?),
    ))
}
// A payload too short for its fields is a FRAME_SIZE_ERROR (RFC 9113 4.2).
// Padding that leaves too few bytes for them is a PROTOCOL_ERROR (6.2, 6.6).
fn unpad_fields(payload: &[u8], flags: u8, need: usize) -> Result<(&[u8], Option<&[u8]>), Error> {
    if payload.len() < need.saturating_add(usize::from(flags & 8 != 0)) {
        return Err(size("frame too short for its fields"));
    }
    let (b, padding) = unpad(payload, flags)?;
    if b.len() < need {
        return Err(protocol("padding covers required fields"));
    }
    Ok((b, padding))
}
/// Borrowed header-block payload after padding and mandatory fields are split.
pub struct HeaderPayload<'a> {
    /// Priority or promised-stream fields preceding the compressed bytes.
    pub fields: &'a [u8],
    /// Encoded HPACK fragment.
    pub fragment: &'a [u8],
    /// Padding retained without its length octet.
    pub padding: Option<&'a [u8]>,
}
impl<'a> HeaderPayload<'a> {
    /// Splits a HEADERS, PUSH_PROMISE, or CONTINUATION payload.
    pub fn parse(payload: &'a [u8], kind: u8, flags: u8) -> Result<Self, Error> {
        let need = match kind {
            1 if flags & 0x20 != 0 => 5,
            5 => 4,
            _ => 0,
        };
        let (b, padding) = if kind == 9 {
            (payload, None)
        } else {
            unpad_fields(payload, flags, need)?
        };
        let (fields, fragment) = b.split_at(need);
        Ok(Self {
            fields,
            fragment,
            padding,
        })
    }
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
/// One six-byte SETTINGS entry, checked.
fn setting(b: &[u8]) -> Result<Setting, Error> {
    let [i0, i1, ..] = *b else {
        return Err(size("setting"));
    };
    let s = Setting {
        id: u16::from_be_bytes([i0, i1]),
        value: u32_at(b, 2)?,
    };
    setting_valid(s)?;
    Ok(s)
}

/// A frame that carries neither data nor a header block, read from its
/// fixed fields: everything [`FrameReader`] reads whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    /// Stream dependency and weight.
    Priority(Priority),
    /// Stream cancellation.
    Reset(Reset),
    /// Liveness probe or acknowledgment.
    Ping(Ping),
    /// Connection shutdown. Its debug bytes are skipped, not kept: `debug`
    /// is empty.
    GoAway(GoAway),
    /// Flow-control credit.
    WindowUpdate(WindowUpdate),
    /// An extension frame, its payload skipped.
    Unknown,
}

/// The frame of kind 2, 3, 6, 7 or 8 that header `h` begins, from `b`:
/// its whole payload, or for GOAWAY at least its first eight bytes, whose
/// debug bytes it leaves out.
fn control(h: FrameHeader, b: &[u8]) -> Result<Control, Error> {
    let (stream, flags) = (h.stream, h.flags);
    Ok(match h.kind {
        2 => {
            let dependency = dependency(b)?;
            if dependency.stream == stream {
                return Err(protocol("stream depends on itself"));
            }
            Control::Priority(Priority {
                stream,
                flags,
                dependency,
            })
        }
        3 => Control::Reset(Reset {
            stream,
            flags,
            code: u32_at(b, 0)?,
        }),
        6 => Control::Ping(Ping {
            flags,
            opaque: b.try_into().map_err(|_| size("PING length"))?,
        }),
        7 => Control::GoAway(GoAway {
            flags,
            last_stream: u32_at(b, 0)? & MAX_WINDOW,
            code: u32_at(b, 4)?,
            debug: Vec::new(),
        }),
        8 => {
            let increment = u32_at(b, 0)? & MAX_WINDOW;
            if increment == 0 {
                return Err(protocol("zero window increment"));
            }
            Control::WindowUpdate(WindowUpdate {
                stream,
                flags,
                increment,
            })
        }
        _ => Control::Unknown,
    })
}

impl Control {
    /// The frame this is, for the kinds whose payload it holds whole.
    fn into_frame(self) -> Frame {
        match self {
            Control::Priority(p) => Frame::Priority(p),
            Control::Reset(r) => Frame::Reset(r),
            Control::Ping(p) => Frame::Ping(p),
            Control::GoAway(g) => Frame::GoAway(g),
            Control::WindowUpdate(w) => Frame::WindowUpdate(w),
            Control::Unknown => unreachable!("an extension frame keeps its payload"),
        }
    }
}

impl Frame {
    /// Parses a complete payload and validates standalone frame rules.
    pub fn parse_payload(h: FrameHeader, b: &[u8]) -> Result<Self, Error> {
        let frame = Self::decode_payload(h, b)?;
        if matches!(&frame, Self::Headers(f) if f.priority.as_ref().is_some_and(|p| p.stream == f.stream))
        {
            return Err(protocol("stream depends on itself"));
        }
        Ok(frame)
    }
    fn decode_payload(h: FrameHeader, b: &[u8]) -> Result<Self, Error> {
        h.validate()?;
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
                    padding: padding.map(<[u8]>::to_vec),
                })
            }
            1 => {
                let payload = HeaderPayload::parse(b, h.kind, flags)?;
                let priority = if flags & 0x20 != 0 {
                    let p = dependency(payload.fields)?;
                    Some(p)
                } else {
                    None
                };
                Self::Headers(Headers {
                    stream,
                    flags,
                    fragment: payload.fragment.to_vec(),
                    priority,
                    padding: payload.padding.map(<[u8]>::to_vec),
                })
            }
            2 | 3 => control(h, b)?.into_frame(),
            4 => {
                let mut entries = Vec::new();
                for b in b.as_chunks::<6>().0 {
                    entries.push(setting(b)?);
                }
                Self::Settings(Settings { flags, entries })
            }
            5 => {
                let payload = HeaderPayload::parse(b, h.kind, flags)?;
                let promised = u32_at(payload.fields, 0)? & MAX_WINDOW;
                if promised == 0 {
                    return Err(protocol("promised stream is zero"));
                }
                Self::PushPromise(PushPromise {
                    stream,
                    flags,
                    promised,
                    fragment: payload.fragment.to_vec(),
                    padding: payload.padding.map(<[u8]>::to_vec),
                })
            }
            6 | 8 => control(h, b)?.into_frame(),
            7 => {
                let Control::GoAway(mut goaway) = control(h, b)? else {
                    unreachable!("a GOAWAY's fields are a GOAWAY")
                };
                goaway.debug = b.get(8..).ok_or_else(|| size("GOAWAY length"))?.to_vec();
                Self::GoAway(goaway)
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
        Self::parse_payload(h, &bytes[HEADER_LEN..])
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
    fn header(&self, length: usize) -> FrameHeader {
        let (kind, flags, stream) = match self {
            Self::Data(f) => (0, f.flags, f.stream),
            Self::Headers(f) => (1, f.flags, f.stream),
            Self::Priority(f) => (2, f.flags, f.stream),
            Self::Reset(f) => (3, f.flags, f.stream),
            Self::Settings(f) => (4, f.flags, 0),
            Self::PushPromise(f) => (5, f.flags, f.stream),
            Self::Ping(f) => (6, f.flags, 0),
            Self::GoAway(f) => (7, f.flags, 0),
            Self::WindowUpdate(f) => (8, f.flags, f.stream),
            Self::Continuation(f) => (9, f.flags, f.stream),
            Self::Unknown(f) => (f.kind, f.flags, f.stream),
        };
        FrameHeader {
            length,
            kind,
            flags,
            stream,
        }
    }
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

/// The scope of a malformed frame before connection state is considered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorScope {
    /// The connection cannot continue under the endpoint protocol rules.
    Connection,
    /// The named stream can be reset while retaining connection state.
    Stream,
}
/// A frame, preface, or typed frame refusal read by [`Inputs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// The client's complete connection preface.
    Preface,
    /// A complete frame. Self-dependent HEADERS retain their compressed bytes
    /// so the caller can decode the block before resetting the stream.
    Frame(Frame),
    /// A malformed frame, with enough context for caller-owned recovery.
    Refused {
        /// The frame header, including the advertised payload length.
        header: FrameHeader,
        /// Why parsing refused the frame.
        error: Error,
        /// Protocol error scope; connection state can require escalation.
        scope: ErrorScope,
        /// The payload exceeds the configured limit and will be skipped.
        oversized: bool,
    },
}
/// A bounded frame decoder. Use [`Stream`] to own its unread bytes.
/// Frame refusals are partition invariant and retain their frame header.
/// Callers decide whether to stop or continue after a refusal.
pub struct Inputs {
    limit: usize,
    preface: bool,
    skip: usize,
}
impl Default for Inputs {
    fn default() -> Self {
        Self::with_limit(DEFAULT_FRAME_SIZE)
    }
}
impl Inputs {
    /// Reads frames without a preface, bounded by `limit` payload bytes.
    /// Limits above the 24-bit wire maximum are clamped.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_FRAME_SIZE),
            preface: false,
            skip: 0,
        }
    }
    /// Requires the client preface before frames.
    pub fn client_side(limit: usize) -> Self {
        Self {
            preface: true,
            ..Self::with_limit(limit)
        }
    }
    /// Changes the accepted payload limit between frames.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(MAX_FRAME_SIZE);
    }
    /// Whether a refused payload is still being skipped.
    pub fn pending(&self) -> bool {
        self.skip != 0
    }
}
impl Decode for Inputs {
    type Item = Input;
    type Error = Error;
    const NAME: &'static str = "HTTP/2";
    fn capacity(&self) -> usize {
        (HEADER_LEN + self.limit).max(PREFACE.len())
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Input>, Error> {
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
        if self.preface {
            if input.len() < PREFACE.len() && PREFACE.starts_with(input) {
                return Ok(Step::Need);
            }
            if !input.starts_with(PREFACE) {
                return Err(protocol("invalid client preface"));
            }
            self.preface = false;
            return Ok(Step::Item(Input::Preface, PREFACE.len()));
        }
        let Some(bytes) = input.get(..HEADER_LEN) else {
            return Ok(Step::Need);
        };
        let header = FrameHeader::parse(bytes)?;
        if header.length > self.limit {
            self.skip = header.length;
            return Ok(Step::Item(
                Input::Refused {
                    header,
                    error: size("frame exceeds configured limit"),
                    scope: ErrorScope::Connection,
                    oversized: true,
                },
                HEADER_LEN,
            ));
        }
        if !(header.kind == 2 && header.stream != 0)
            && let Err(error) = header.validate()
        {
            self.skip = header.length;
            return Ok(Step::Item(
                Input::Refused {
                    header,
                    error,
                    scope: ErrorScope::Connection,
                    oversized: false,
                },
                HEADER_LEN,
            ));
        }
        let total = HEADER_LEN + header.length;
        let Some(bytes) = input.get(..total) else {
            return Ok(Step::Need);
        };
        let item = match Frame::decode_payload(header, &bytes[HEADER_LEN..]) {
            Ok(frame) => Input::Frame(frame),
            Err(error) => Input::Refused {
                header,
                error,
                scope: scope_of(header, error),
                oversized: false,
            },
        };
        Ok(Step::Item(item, total))
    }
}

/// The scope of an error in a frame's payload: a PRIORITY that is
/// malformed, or a WINDOW_UPDATE with a zero increment, on a stream,
/// concerns that stream; every other, the connection.
fn scope_of(header: FrameHeader, error: Error) -> ErrorScope {
    let stream = header.stream != 0
        && ((header.kind == 2
            && matches!(
                error.code,
                ErrorCode::ProtocolError | ErrorCode::FrameSizeError
            ))
            || (header.kind == 8 && error.code == ErrorCode::ProtocolError));
    if stream {
        ErrorScope::Stream
    } else {
        ErrorScope::Connection
    }
}

/// The most bytes [`FrameReader`] gathers in one place: a frame header,
/// which is longer than any frame's fixed fields (eight for PING and
/// GOAWAY, six for a SETTINGS entry or a padded HEADERS with priority).
const GATHER: usize = HEADER_LEN;

/// One step of a frame, as [`FrameReader`] reads it. A frame that is not
/// refused is a [`Begin`], then its SETTINGS entries or its content in
/// pieces, then an [`End`](Read::End).
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// The client's complete connection preface.
    Preface,
    /// A frame refused as [`Input::Refused`] refuses it. Nothing more of
    /// it is read: its payload is skipped.
    Refused {
        /// The frame header, including the advertised payload length.
        header: FrameHeader,
        /// Why the frame was refused.
        error: Error,
        /// Protocol error scope; connection state can require escalation.
        scope: ErrorScope,
        /// The payload exceeds the configured limit.
        oversized: bool,
    },
    /// A frame begins: its header and fixed fields are read and checked.
    Begin(Begin),
    /// The next entry of the SETTINGS frame begun last, checked.
    Setting(Setting),
    /// The next bytes of the content of the DATA, HEADERS, PUSH_PROMISE or
    /// CONTINUATION frame begun last: its data or its header block
    /// fragment, without padding. A piece of the input, sharing its
    /// backing: nothing is copied.
    Content(Chunk),
    /// The frame begun last is over: its content and padding are read.
    End(FrameHeader),
}

/// What a frame is, read from its header and fixed fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Begin {
    /// DATA with `len` bytes of data, its padding left out.
    Data {
        /// The frame header.
        header: FrameHeader,
        /// The data bytes that come as content.
        len: usize,
    },
    /// HEADERS with `len` bytes of header block fragment.
    Headers {
        /// The frame header.
        header: FrameHeader,
        /// Its priority fields, present exactly when flag 0x20 is set.
        priority: Option<Dependency>,
        /// The fragment bytes that come as content.
        len: usize,
    },
    /// PUSH_PROMISE with `len` bytes of header block fragment.
    PushPromise {
        /// The frame header.
        header: FrameHeader,
        /// The promised stream, greater than zero.
        promised: u32,
        /// The fragment bytes that come as content.
        len: usize,
    },
    /// CONTINUATION: its whole payload is fragment, `header.length` bytes.
    Continuation {
        /// The frame header.
        header: FrameHeader,
    },
    /// SETTINGS: its entries come as [`Read::Setting`].
    Settings {
        /// The frame header.
        header: FrameHeader,
    },
    /// A frame of fixed fields only. GOAWAY's debug bytes and an extension
    /// frame's payload are skipped.
    Control {
        /// The frame header.
        header: FrameHeader,
        /// What it says.
        control: Control,
    },
}

impl Begin {
    /// The frame's header.
    pub fn header(&self) -> FrameHeader {
        match self {
            Begin::Data { header, .. }
            | Begin::Headers { header, .. }
            | Begin::PushPromise { header, .. }
            | Begin::Continuation { header }
            | Begin::Settings { header }
            | Begin::Control { header, .. } => *header,
        }
    }
}

/// Where a [`FrameReader`] is in its input.
#[derive(Clone, Copy, Debug)]
enum Phase {
    /// This many bytes of the client preface matched.
    Preface(usize),
    /// Between frames: gathering the next header.
    Header,
    /// Gathering `want` bytes of fixed fields of `header`'s frame.
    Fields { header: FrameHeader, want: usize },
    /// `left` bytes of content, then `pad` bytes of padding.
    Content {
        header: FrameHeader,
        left: usize,
        pad: usize,
    },
    /// `left` bytes of SETTINGS entries.
    Settings { header: FrameHeader, left: usize },
    /// `left` bytes to skip, then the end of `end`'s frame, if it was not
    /// refused.
    Skip {
        left: usize,
        end: Option<FrameHeader>,
    },
}

/// HTTP/2 frames read from input that comes in pieces, a step at a time,
/// copying no content.
///
/// It reads what [`Inputs`] reads and refuses what it refuses, with the
/// same codes and scopes, but it never holds a frame: a frame header or a
/// frame's fixed fields split across pieces are gathered in a few bytes of
/// its own, and content (DATA's data, a header block fragment) comes out
/// as pieces of the input ([`Read::Content`]) as soon as they arrive. A
/// frame larger than the limit is refused and skipped, as are a GOAWAY's
/// debug bytes and an extension frame's payload. It allocates nothing.
///
/// A frame whose fixed fields are malformed is refused once they are read;
/// a SETTINGS entry, when it is reached, after the entries before it.
#[derive(Clone, Debug)]
pub struct FrameReader {
    limit: usize,
    phase: Phase,
    gathered: [u8; GATHER],
    have: usize,
}

impl FrameReader {
    /// Reads frames without a preface, bounded by `limit` payload bytes.
    /// Limits above the 24-bit wire maximum are clamped.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_FRAME_SIZE),
            phase: Phase::Header,
            gathered: [0; GATHER],
            have: 0,
        }
    }

    /// Requires the client preface before frames.
    pub fn client_side(limit: usize) -> Self {
        Self {
            phase: Phase::Preface(0),
            ..Self::with_limit(limit)
        }
    }

    /// Changes the accepted payload limit for the frames after this one.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(MAX_FRAME_SIZE);
    }

    /// Reads the next step from the front of `input`, taking the bytes it
    /// reads from it. `None` when `input` is used up before a step is
    /// whole: what it read of the step so far is kept for the next call.
    /// An error is a connection error the input cannot recover from.
    pub fn next(&mut self, input: &mut Chunk) -> Option<Result<Read, Error>> {
        loop {
            match self.phase {
                Phase::Preface(matched) => {
                    if input.is_empty() {
                        return None;
                    }
                    let n = (PREFACE.len() - matched).min(input.len());
                    if input[..n] != PREFACE[matched..matched + n] {
                        return Some(Err(protocol("invalid client preface")));
                    }
                    input.advance(n);
                    if matched + n < PREFACE.len() {
                        self.phase = Phase::Preface(matched + n);
                        return None;
                    }
                    self.phase = Phase::Header;
                    return Some(Ok(Read::Preface));
                }
                Phase::Header => {
                    if !self.gather(input, HEADER_LEN) {
                        return None;
                    }
                    let [a, b, c, kind, flags, s0, s1, s2, s3] = self.gathered;
                    let header = FrameHeader {
                        length: (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c),
                        kind,
                        flags,
                        stream: u32::from_be_bytes([s0, s1, s2, s3]) & MAX_WINDOW,
                    };
                    if let Some(read) = self.begin(header) {
                        return Some(Ok(read));
                    }
                }
                Phase::Fields { header, want } => {
                    if !self.gather(input, want) {
                        return None;
                    }
                    return Some(Ok(self.fields(header, want)));
                }
                Phase::Content { header, left, pad } => {
                    if left == 0 {
                        self.phase = Phase::Skip {
                            left: pad,
                            end: Some(header),
                        };
                        continue;
                    }
                    if input.is_empty() {
                        return None;
                    }
                    let n = left.min(input.len());
                    self.phase = Phase::Content {
                        header,
                        left: left - n,
                        pad,
                    };
                    return Some(Ok(Read::Content(input.split_to(n))));
                }
                Phase::Settings { header, left } => {
                    if left == 0 {
                        self.phase = Phase::Header;
                        return Some(Ok(Read::End(header)));
                    }
                    if !self.gather(input, 6) {
                        return None;
                    }
                    let left = left - 6;
                    return Some(Ok(match setting(&self.gathered[..6]) {
                        Ok(entry) => {
                            self.phase = Phase::Settings { header, left };
                            Read::Setting(entry)
                        }
                        Err(error) => self.refuse(header, error, left),
                    }));
                }
                Phase::Skip { left, end } => {
                    let n = left.min(input.len());
                    input.advance(n);
                    if n < left {
                        self.phase = Phase::Skip {
                            left: left - n,
                            end,
                        };
                        return None;
                    }
                    self.phase = Phase::Header;
                    if let Some(header) = end {
                        return Some(Ok(Read::End(header)));
                    }
                }
            }
        }
    }

    /// The input is over: an error if it ended inside the preface or a
    /// frame.
    pub fn finish(&self) -> Result<(), Error> {
        match self.phase {
            Phase::Preface(0) => Ok(()),
            Phase::Header if self.have == 0 => Ok(()),
            _ => Err(protocol("truncated HTTP/2 frame")),
        }
    }

    /// Gathers bytes from `input` until `want` are gathered. Whether they
    /// are; once they are, the next gathering starts afresh.
    fn gather(&mut self, input: &mut Chunk, want: usize) -> bool {
        let n = (want - self.have).min(input.len());
        self.gathered[self.have..self.have + n].copy_from_slice(&input[..n]);
        input.advance(n);
        self.have += n;
        if self.have < want {
            return false;
        }
        self.have = 0;
        true
    }

    /// Refuses `header`'s frame for `error` in its payload, as [`Inputs`]
    /// scopes it, and skips the `left` bytes of it not yet read.
    fn refuse(&mut self, header: FrameHeader, error: Error, left: usize) -> Read {
        self.refuse_as(header, error, scope_of(header, error), false, left)
    }

    fn refuse_as(
        &mut self,
        header: FrameHeader,
        error: Error,
        scope: ErrorScope,
        oversized: bool,
        left: usize,
    ) -> Read {
        self.phase = Phase::Skip { left, end: None };
        Read::Refused {
            header,
            error,
            scope,
            oversized,
        }
    }

    /// Checks a header just read and sets up the rest of its frame. The
    /// step to give now, if there is one before the fixed fields.
    fn begin(&mut self, header: FrameHeader) -> Option<Read> {
        let length = header.length;
        if length > self.limit {
            let error = size("frame exceeds configured limit");
            return Some(self.refuse_as(header, error, ErrorScope::Connection, true, length));
        }
        // A PRIORITY on a stream is that stream's error, checked below.
        if !(header.kind == 2 && header.stream != 0)
            && let Err(error) = header.validate()
        {
            return Some(self.refuse_as(header, error, ErrorScope::Connection, false, length));
        }
        let padded = usize::from(header.flags & 8 != 0);
        let want = match header.kind {
            0 => padded,
            1 => padded + if header.flags & 0x20 != 0 { 5 } else { 0 },
            2 if length != 5 => {
                let error = size("invalid frame payload length");
                return Some(self.refuse(header, error, length));
            }
            2 => 5,
            3 | 8 => 4,
            5 => padded + 4,
            6 | 7 => 8,
            4 => {
                self.phase = Phase::Settings {
                    header,
                    left: length,
                };
                return Some(Read::Begin(Begin::Settings { header }));
            }
            9 => {
                self.phase = Phase::Content {
                    header,
                    left: length,
                    pad: 0,
                };
                return Some(Read::Begin(Begin::Continuation { header }));
            }
            _ => {
                self.phase = Phase::Skip {
                    left: length,
                    end: Some(header),
                };
                let control = Control::Unknown;
                return Some(Read::Begin(Begin::Control { header, control }));
            }
        };
        if length < want {
            // A payload too short for its fields: FRAME_SIZE_ERROR (RFC
            // 9113 section 4.2).
            return Some(self.refuse(header, size("frame too short for its fields"), length));
        }
        self.phase = Phase::Fields { header, want };
        None
    }

    /// The frame `header` begins, from its `want` fixed fields, gathered:
    /// its [`Begin`], with the rest of it set up, or its refusal.
    fn fields(&mut self, header: FrameHeader, want: usize) -> Read {
        let gathered = self.gathered;
        let fixed = &gathered[..want];
        let rest = header.length - want;
        if !matches!(header.kind, 0 | 1 | 5) {
            return match control(header, fixed) {
                Ok(control) => {
                    self.phase = Phase::Skip {
                        left: rest,
                        end: Some(header),
                    };
                    Read::Begin(Begin::Control { header, control })
                }
                Err(error) => self.refuse(header, error, rest),
            };
        }
        let padded = header.flags & 8 != 0;
        let (pad, fields) = match fixed.split_first() {
            Some((&pad, fields)) if padded => (usize::from(pad), fields),
            _ => (0, fixed),
        };
        // Padding that leaves too few bytes for the fields is a
        // PROTOCOL_ERROR (RFC 9113 sections 6.1, 6.2 and 6.6).
        let Some(content) = (header.length - usize::from(padded)).checked_sub(pad) else {
            return self.refuse(header, protocol("padding longer than payload"), rest);
        };
        let Some(len) = content.checked_sub(fields.len()) else {
            return self.refuse(header, protocol("padding covers required fields"), rest);
        };
        let begin = match header.kind {
            0 => Begin::Data { header, len },
            1 => {
                let priority = match fields.is_empty() {
                    true => None,
                    false => match dependency(fields) {
                        Ok(priority) => Some(priority),
                        Err(error) => return self.refuse(header, error, rest),
                    },
                };
                Begin::Headers {
                    header,
                    priority,
                    len,
                }
            }
            _ => {
                let promised = match u32_at(fields, 0) {
                    Ok(promised) => promised & MAX_WINDOW,
                    Err(error) => return self.refuse(header, error, rest),
                };
                if promised == 0 {
                    return self.refuse(header, protocol("promised stream is zero"), rest);
                }
                Begin::PushPromise {
                    header,
                    promised,
                    len,
                }
            }
        };
        self.phase = Phase::Content {
            header,
            left: len,
            pad,
        };
        Read::Begin(begin)
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
    /// Maximum tracked stream states, including peer openings and promised
    /// streams before headers, and ended streams until retired.
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
        fields: Fields,
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
        fields: Fields,
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
        fields: Fields,
    },
    /// An extension frame that was ignored by connection state.
    Unknown(Unknown),
}
/// The block being read: the frame that opened it and what that frame
/// said. Its fragments so far, when they had to be joined, are in the
/// assembly storage.
#[derive(Clone, Copy)]
struct Pending {
    stream: u32,
    end: bool,
    promised: Option<u32>,
}
/// Where a header block stands once a frame of it is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRead {
    /// The frame's stream.
    pub stream: u32,
    /// END_STREAM from the opening HEADERS.
    pub end: bool,
    /// The stream a PUSH_PROMISE promises.
    pub promised: Option<u32>,
    /// The block is whole and was decoded into the caller's fields; until
    /// then it waits for CONTINUATION.
    pub complete: bool,
}
/// Endpoint header assembly and HPACK decoding for one direction.
/// Every decoded field is complete. Oversized decoded lists still update
/// the compression table and are counted in the [`Fields`] they are
/// decoded into, for the caller to reject.
///
/// A block that arrives whole, in one HEADERS frame whose fragment is in
/// one piece, is decoded from where it lies. A block split into
/// CONTINUATION frames, or a fragment that came in pieces, is joined in
/// storage `S`: a vector, or a container whose growth is paid for first,
/// such as a layer's [`ChargedBytes`](fictionet::stdlib::layer::ChargedBytes).
///
/// A frame is read either whole ([`read`](Self::read)) or in steps, as a
/// reader that gets its input in pieces does: [`begin`](Self::begin) with
/// its header, [`join`](Self::join) each piece of its fragment, then
/// [`end_frame`](Self::end_frame), and, for a block it completes,
/// [`decode`](Self::decode) with the caller's choice of fields.
pub struct HeaderBlocks<S = Vec<u8>> {
    table: hpack::Table,
    /// The block being read, from its first frame's header to its last.
    pending: Option<Pending>,
    /// The frame being read ends its block.
    last: bool,
    /// The fragment bytes of the frame being read.
    frame_len: usize,
    /// The fragments of the pending block, joined; empty between blocks,
    /// with its floor allocated.
    assembly: S,
    /// The storage the assembly keeps between blocks ([`keep`](Self::keep)).
    floor: usize,
    limit: usize,
    decoded: usize,
}
impl HeaderBlocks {
    /// Bounds encoded block storage and retained decoded field bytes.
    pub fn with_limits(limits: Limits) -> Self {
        Self::in_storage(limits, Vec::new())
    }
}
impl<S: Storage> HeaderBlocks<S> {
    /// As [`with_limits`](HeaderBlocks::with_limits), joining split blocks
    /// in `storage`, which grows only as far as it allows.
    pub fn in_storage(limits: Limits, mut storage: S) -> Self {
        let limits = limits.bounded();
        storage.shrink_to(0);
        Self {
            table: hpack::Table::new(4096),
            pending: None,
            last: false,
            frame_len: 0,
            assembly: storage,
            limit: limits.header_block,
            decoded: limits.header_list,
            floor: 0,
        }
    }

    /// The assembly storage, to see what pays for it.
    pub fn storage(&self) -> &S {
        &self.assembly
    }

    /// Keeps `floor` bytes of assembly storage, within the block limit,
    /// from now on: grown to it now, and given back no further than it
    /// after each block, so a block split across frames or pieces that
    /// fits in it is joined without growing. `false`, changing nothing,
    /// if the storage cannot grow to it.
    #[must_use = "a refused floor keeps no storage"]
    pub fn keep(&mut self, floor: usize) -> bool {
        let floor = floor.min(self.limit);
        if !self.assembly.grow_within(floor..=floor) {
            return false;
        }
        self.floor = floor;
        true
    }

    fn assembly_capacity(&self, len: usize, capacity: usize, fragment: usize) -> usize {
        let needed = len.saturating_add(fragment).min(self.limit);
        if needed > capacity {
            needed.max(capacity.saturating_mul(2)).min(self.limit)
        } else {
            capacity
        }
    }

    /// The joined length of the pending block.
    fn joined(&self) -> usize {
        if self.pending.is_some() {
            self.assembly.bytes().len()
        } else {
            0
        }
    }

    /// The most a block whose encoded bytes come to `len` keeps once
    /// decoded with this direction's limit, as the table is now. A caller
    /// pays for it before [`decode`](Self::decode) decodes the block.
    pub fn most_block(&self, len: usize) -> hpack::BlockBound {
        self.table.most_block(len, self.decoded)
    }

    /// The encoded bytes of the pending block joined so far.
    pub fn joined_len(&self) -> usize {
        self.joined()
    }

    /// The most the compression table holds while the settings limit stays
    /// where it is: see [`hpack::Table::most_held`].
    pub fn most_table(&self) -> usize {
        self.table.most_held()
    }

    /// Bytes retained by the compression table and an unfinished block.
    pub fn held(&self) -> usize {
        self.table.table_size().saturating_add(self.joined())
    }
    /// Bytes allocated by the compression table and an unfinished block.
    pub fn allocated(&self) -> usize {
        self.table.held().saturating_add(self.assembly.capacity())
    }
    /// Bytes allocated by the compression table.
    pub fn table_held(&self) -> usize {
        self.table.held()
    }
    /// The most [`allocated`](Self::allocated) reaches while the table's
    /// settings limit stays where it is: the table's own bound, and an
    /// unfinished block's storage, which grows to at most the block limit.
    pub fn most_allocated(&self) -> usize {
        self.table.most_held().saturating_add(self.limit)
    }
    /// Whether a block waits for CONTINUATION, or for the rest of the
    /// frame being read.
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Starts reading a header-block frame with header `h`: HEADERS,
    /// PUSH_PROMISE with the stream it `promised`, or CONTINUATION, whose
    /// fragment is `fragment` bytes.
    /// Enforces continuation sequencing. Returns the block's stream and
    /// the END_STREAM of its opening HEADERS.
    pub fn begin(
        &mut self,
        h: FrameHeader,
        promised: Option<u32>,
        fragment: usize,
    ) -> Result<BlockRead, Error> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| h.kind != 9 || h.stream != p.stream)
        {
            return Err(protocol("interleaved header block"));
        }
        let pending = if h.kind == 9 {
            self.pending
                .ok_or_else(|| protocol("CONTINUATION without a header block"))?
        } else {
            Pending {
                stream: h.stream,
                end: h.kind == 1 && h.flags & 1 != 0,
                promised,
            }
        };
        self.pending = Some(pending);
        self.last = h.flags & 4 != 0;
        self.frame_len = fragment;
        Ok(BlockRead {
            stream: h.stream,
            end: pending.end,
            promised: pending.promised,
            complete: false,
        })
    }

    /// Whether `fragment`, all of the fragment of the frame begun last,
    /// is a whole block: nothing joined before it, and the frame ends the
    /// block. Such a block is decoded from where it lies.
    pub fn is_whole(&self, fragment: usize) -> bool {
        self.last && self.joined() == 0 && fragment == self.frame_len
    }

    /// Joins `piece`, the next bytes of the fragment of the frame begun
    /// last, to the pending block. `Ok(false)`, changing nothing, when the
    /// storage refuses room for it, so the caller can join it again once
    /// memory frees. A block past the direction's limit is an error.
    pub fn join(&mut self, piece: &[u8]) -> Result<bool, Error> {
        let len = self.joined();
        let Some(needed) = len.checked_add(piece.len()).filter(|&n| n <= self.limit) else {
            self.assembly.clear_to(self.floor);
            return Err(self::budget("header block exceeds limit"));
        };
        if needed > self.assembly.capacity() {
            let target = self.assembly_capacity(len, self.assembly.capacity(), piece.len());
            if !self.assembly.grow_within(needed..=target) {
                return Ok(false);
            }
        }
        // Within the capacity, so this cannot fail.
        let resized = self.assembly.resize_within(needed);
        debug_assert!(resized, "the assembly has room for the fragment");
        self.assembly.bytes_mut()[len..needed].copy_from_slice(piece);
        Ok(true)
    }

    /// Ends the frame begun last: whether it ends its block, which the
    /// caller then decodes.
    pub fn end_frame(&self) -> bool {
        self.last
    }

    /// Decodes the block the last frame ended into `out`, its room
    /// charged to `budget`: from `whole`, the block as it lies when it
    /// came whole ([`is_whole`](Self::is_whole)), or else from what was
    /// joined. The joined fragments go, and the next frame starts a new
    /// block.
    pub fn decode(
        &mut self,
        whole: Option<&[u8]>,
        out: &mut Fields,
        budget: &Budget,
    ) -> Result<(), Error> {
        self.pending = None;
        let encoded = match whole {
            Some(whole) => whole,
            None => self.assembly.bytes(),
        };
        let decoded = self.table.decode_block(encoded, out, budget, self.decoded);
        // The block is decoded: its joined fragments go.
        self.assembly.clear_to(self.floor);
        decoded.map_err(|_| error(ErrorCode::CompressionError, "invalid HPACK block"))
    }

    /// Reads a complete frame payload, enforces continuation sequencing,
    /// and decodes a block the frame completes into `out`, charging its
    /// room to `budget`. A frame that cannot be joined for want of storage
    /// is an error.
    pub fn read(
        &mut self,
        h: FrameHeader,
        payload: &[u8],
        out: &mut Fields,
        budget: &Budget,
    ) -> Result<BlockRead, Error> {
        if !matches!(h.kind, 1 | 5 | 9) {
            return self.read_fragment(h, None, out, budget);
        }
        let payload = HeaderPayload::parse(payload, h.kind, h.flags)?;
        let promised = if h.kind == 5 {
            Some(u32_at(payload.fields, 0)? & MAX_WINDOW)
        } else {
            None
        };
        self.read_fragment(h, Some((payload.fragment, promised)), out, budget)
    }
    /// Reads a frame already decoded by the shared frame decoder, as
    /// [`read`](Self::read) does.
    pub fn read_frame(
        &mut self,
        frame: &Frame,
        out: &mut Fields,
        budget: &Budget,
    ) -> Result<BlockRead, Error> {
        let fragment = match frame {
            Frame::Headers(f) => Some((&f.fragment[..], None)),
            Frame::PushPromise(f) => Some((&f.fragment[..], Some(f.promised))),
            Frame::Continuation(f) => Some((&f.fragment[..], None)),
            _ => None,
        };
        self.read_fragment(frame.header(0), fragment, out, budget)
    }
    fn read_fragment(
        &mut self,
        h: FrameHeader,
        fragment: Option<(&[u8], Option<u32>)>,
        out: &mut Fields,
        budget: &Budget,
    ) -> Result<BlockRead, Error> {
        let Some((fragment, promised)) = fragment else {
            if self.pending.is_some() {
                return Err(protocol("interleaved header block"));
            }
            return Ok(BlockRead {
                stream: h.stream,
                end: h.kind == 1 && h.flags & 1 != 0,
                promised: None,
                complete: false,
            });
        };
        let mut read = self.begin(h, promised, fragment.len())?;
        if self.is_whole(fragment.len()) {
            self.decode(Some(fragment), out, budget)?;
            read.complete = true;
            return Ok(read);
        }
        if !self.join(fragment)? {
            self.assembly.clear_to(self.floor);
            return Err(self::budget("header allocation failed"));
        }
        if self.end_frame() {
            self.decode(None, out, budget)?;
            read.complete = true;
        }
        Ok(read)
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

/// One sending direction of an HTTP/2 connection, with a [`Stream<Inputs>`]
/// inside. `client_side` reads client-to-server bytes, including the preface;
/// `server_side` reads server-to-client bytes. A nonempty direction requires
/// initial SETTINGS. An empty direction can end cleanly.
///
/// Announce request openings to the response direction's
/// [`peer_open`](Self::peer_open) before routing WINDOW_UPDATE. Promised streams
/// are registered here when PUSH_PROMISE is read. Route SETTINGS, WINDOW_UPDATE,
/// and RST_STREAM as described in the module docs. Use
/// [`peer_reset`](Self::peer_reset) for streams abandoned by GOAWAY.
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
/// of [`fictionet::stdlib::codec::Frames<grpc::Message>`] for gRPC under one shared budget.
pub struct Session {
    frames: Stream<Inputs>,
    blocks: HeaderBlocks,
    /// Pays for decoded header blocks: a direction has no limit of its
    /// own beyond [`Limits`].
    budget: Budget,
    limits: Limits,
    settings: SettingsState,
    peer: SettingsState,
    streams: BTreeMap<u32, StreamState>,
    retired_before: [u32; 2],
    peer_resets: BTreeSet<u32>,
    reset_before: [u32; 2],
    window: i64,
    first: bool,
    side: Side,
    stopped: bool,
    failed: Option<Error>,
    settings_updates: std::collections::VecDeque<SettingsUpdate>,
    table_limit: usize,
    initial_window: u32,
    frame_size: u32,
}
impl Session {
    /// Starts a client-to-server direction requiring the client preface.
    pub fn client_side(limits: Limits) -> Self {
        Self::new(limits, Side::Client)
    }
    /// Starts a server-to-client direction, beginning with SETTINGS.
    pub fn server_side(limits: Limits) -> Self {
        Self::new(limits, Side::Server)
    }
    fn new(limits: Limits, side: Side) -> Self {
        let limits = limits.bounded();
        let limit = limits.frame.min(DEFAULT_FRAME_SIZE);
        Self {
            frames: Stream::new(if side == Side::Client {
                Inputs::client_side(limit)
            } else {
                Inputs::with_limit(limit)
            }),
            blocks: HeaderBlocks::with_limits(limits),
            budget: Budget::unlimited(),
            limits,
            settings: SettingsState::default(),
            peer: SettingsState::default(),
            streams: BTreeMap::new(),
            retired_before: [0; 2],
            peer_resets: BTreeSet::new(),
            reset_before: [0; 2],
            window: 65_535,
            first: true,
            side,
            stopped: false,
            failed: None,
            settings_updates: std::collections::VecDeque::new(),
            table_limit: 4096,
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
        self.frames = Stream::new(Inputs::with_limit(
            self.limits.frame.min(DEFAULT_FRAME_SIZE),
        ));
        self.blocks.pending = None;
        self.blocks.table = hpack::Table::new(0);
        self.streams.clear();
        self.retired_before = [0; 2];
        self.peer_resets.clear();
        self.reset_before = [0; 2];
        self.settings_updates.clear();
        self.table_limit = 4096;
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
    /// Keeps the highest retired ID for each parity. Untracked IDs at or below
    /// it cannot reopen. Announce peer openings in stream ID order with
    /// [`peer_open`](Self::peer_open) so lower active streams remain tracked.
    /// Peer-reset tracking survives retirement.
    pub fn retire(&mut self, stream: u32) -> bool {
        if self.streams.get(&stream).is_some_and(|s| s.closed) {
            self.streams.remove(&stream);
            let before = &mut self.retired_before[(stream % 2) as usize];
            *before = (*before).max(stream);
            true
        } else {
            false
        }
    }
    /// Registers a stream opened by a request in the other direction.
    /// Call this on the response direction before routing WINDOW_UPDATE.
    /// PUSH_PROMISE registers its promised stream in the direction that reads
    /// it. The caller checks ownership and opening order.
    ///
    /// Reserves one of [`Limits::streams`] states using the current initial
    /// window. It does not mark this direction's headers as received; DATA
    /// still requires final headers. Repeated calls preserve existing credit.
    /// Closed, retired, and peer-reset streams are not reopened. See
    /// [`retire`](Self::retire) for the retirement watermark.
    /// Invalid IDs and stream state exhaustion stop the direction.
    pub fn peer_open(&mut self, stream: u32) -> Result<(), Error> {
        if self.stopped {
            return Ok(());
        }
        let result = self.open_stream(stream);
        self.remember(result)
    }
    fn open_stream(&mut self, stream: u32) -> Result<(), Error> {
        if stream == 0 || stream > MAX_WINDOW {
            return Err(protocol("invalid stream ID"));
        }
        if self.retired(stream) || self.reset_by_peer(stream) {
            return Ok(());
        }
        self.stream_state(stream).map(|_| ())
    }
    fn retired(&self, stream: u32) -> bool {
        !self.streams.contains_key(&stream) && stream <= self.retired_before[(stream % 2) as usize]
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
    /// ACKs apply in announcement order. HPACK allows later pending increases
    /// while retaining any required minimum-size update at the next block.
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
        if peer.header_table_size as usize > self.table_limit {
            self.table_limit = peer.header_table_size as usize;
            self.blocks.table.set_settings_limit(self.table_limit);
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
        }
        // Later increases may already be in use before their own ACK.
        let mut table_limit = update.table_final;
        let mut window = update.window;
        let mut frame_size = update.frame_size;
        for pending in &self.settings_updates {
            table_limit = table_limit.max(pending.table_final);
            window = window.max(pending.window_max);
            frame_size = frame_size.max(pending.frame_max);
        }
        self.table_limit = table_limit;
        self.blocks.table.set_settings_limit(table_limit);
        self.set_initial_window(window, window, window)?;
        self.set_frame_size(frame_size);
        Ok(())
    }
    /// Applies credit announced by the other direction. Register peer openings
    /// with [`peer_open`](Self::peer_open) first to retain credit before headers.
    /// Unknown, closed, and retired streams are ignored. The caller checks
    /// idle-stream rules using both directions' opening headers.
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
                if state.closed {
                    return Ok(());
                }
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
        if self.retired(id) {
            return Err(error(ErrorCode::StreamClosed, "headers on retired stream"));
        }
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
                .with_next(|item, bytes, _| (item, bytes.len() - HEADER_LEN));
            let result = match next {
                Some(Ok((item, length))) => self.step(item, length),
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
    fn step(&mut self, item: Input, length: usize) -> Result<Option<Event>, Error> {
        let frame = match item {
            Input::Preface => return Ok(Some(Event::Preface)),
            Input::Frame(f) => f,
            Input::Refused { error, .. } => return Err(error),
        };
        if self.first {
            if !matches!(&frame, Frame::Settings(s) if s.flags & 1 == 0) {
                return Err(protocol("first frame must be SETTINGS"));
            }
            self.first = false;
        }
        let h = frame.header(length);
        let mut fields = Fields::new();
        let block = self.blocks.read_frame(&frame, &mut fields, &self.budget)?;
        if block.complete && fields.left_out() != 0 {
            return Err(budget("decoded header list exceeds limit"));
        }
        if matches!(&frame, Frame::Headers(f) if f.priority.as_ref().is_some_and(|p| p.stream == f.stream))
        {
            return Err(protocol("stream depends on itself"));
        }
        if matches!(
            frame,
            Frame::Headers(_) | Frame::PushPromise(_) | Frame::Continuation(_)
        ) && self.reset_by_peer(h.stream)
        {
            return Ok(None);
        }
        if block.complete {
            if let Some(promised) = block.promised {
                if self.side == Side::Client {
                    return Err(protocol("client sent PUSH_PROMISE"));
                }
                self.open_stream(promised)?;
                return Ok(Some(Event::PushPromise {
                    stream: block.stream,
                    promised,
                    fields,
                }));
            }
            let informational = fields
                .iter()
                .any(|(name, value)| name == b":status" && value.first() == Some(&b'1'));
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

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::*;

    const MAX_ACTIONS: usize = 64;
    const STREAMS: u32 = 16;
    const VALUES: [u32; 9] = [0, 1, 1024, 2048, 4096, 65_535, 65_536, 100_000, MAX_WINDOW];

    #[derive(Clone, Copy, Debug)]
    enum Action {
        Open { stream: u32, end: bool, table: u8 },
        Settings { id: u16, value: u32 },
        Ack,
        Credit { stream: u32, increment: u32 },
        Reset(u32),
        Retire(u32),
        Data { stream: u32, len: usize, end: bool },
        Eof,
        Loss,
    }

    struct Pair {
        sessions: [Session; 2],
        events: Vec<(usize, Result<Event, Error>)>,
        data: [usize; 2],
        chunk: usize,
    }

    impl Pair {
        fn new(chunk: usize) -> Self {
            let limits = Limits {
                frame: DEFAULT_FRAME_SIZE,
                streams: 8,
                ..Limits::default()
            };
            let mut pair = Self {
                sessions: [Session::client_side(limits), Session::server_side(limits)],
                events: Vec::new(),
                data: [0; 2],
                chunk,
            };
            pair.feed(0, PREFACE);
            for dir in 0..2 {
                pair.frame(
                    dir,
                    &Settings {
                        flags: 0,
                        entries: vec![],
                    },
                );
            }
            // Consume the initial announcements so later ACKs belong to actions.
            for dir in 0..2 {
                pair.apply(dir, Action::Ack);
            }
            pair.events.clear();
            pair
        }

        fn drain(&mut self, dir: usize) {
            while let Some(event) = self.sessions[dir].next() {
                let peer = &mut self.sessions[1 - dir];
                let routed = match &event {
                    Ok(Event::Headers { stream, .. }) => peer.peer_open(*stream),
                    Ok(Event::PushPromise { promised, .. }) => peer.peer_open(*promised),
                    Ok(Event::Settings(settings)) => peer.peer_settings(settings),
                    Ok(Event::WindowUpdate(update)) => peer.peer_window_update(update),
                    Ok(Event::Reset { stream, .. }) => {
                        peer.peer_reset(*stream);
                        Ok(())
                    }
                    Ok(Event::Data { data, .. }) => {
                        self.data[dir] += data.len();
                        Ok(())
                    }
                    _ => Ok(()),
                };
                self.events.push((dir, event));
                if let Err(error) = routed {
                    assert_eq!(self.sessions[1 - dir].failed(), Some(&error));
                    assert!(self.sessions[1 - dir].is_done());
                    self.events.push((1 - dir, Err(error)));
                }
            }
        }

        fn feed(&mut self, dir: usize, bytes: &[u8]) {
            for part in bytes.chunks(self.chunk) {
                let mut rest = part;
                while !rest.is_empty() {
                    let n = self.sessions[dir].push(rest);
                    assert!(n <= rest.len());
                    self.drain(dir);
                    assert!(n > 0, "session made no progress after draining");
                    rest = &rest[n..];
                }
            }
        }

        fn frame(&mut self, dir: usize, frame: &impl Wire) {
            self.feed(dir, &frame.to_bytes().unwrap());
        }

        fn apply(&mut self, dir: usize, action: Action) {
            match action {
                Action::Open { stream, end, table } => {
                    let mut fragment = Vec::new();
                    let updates: &[u64] = match table % 4 {
                        1 => &[1024],
                        2 => &[1024, 2048],
                        3 => &[0, 4096],
                        _ => &[],
                    };
                    for &size in updates {
                        fictionet::stdlib::protocols::prefix_int::write(
                            &mut fragment,
                            5,
                            0x20,
                            size,
                        )
                        .unwrap();
                    }
                    fragment.push(if dir == 0 { 0x82 } else { 0x88 });
                    self.frame(
                        dir,
                        &Headers {
                            stream,
                            flags: 4 | u8::from(end),
                            fragment,
                            priority: None,
                            padding: None,
                        },
                    );
                }
                Action::Settings { id, value } => self.frame(
                    dir,
                    &Settings {
                        flags: 0,
                        entries: vec![Setting { id, value }],
                    },
                ),
                Action::Ack => self.frame(
                    dir,
                    &Settings {
                        flags: 1,
                        entries: vec![],
                    },
                ),
                Action::Credit { stream, increment } => self.frame(
                    dir,
                    &WindowUpdate {
                        stream,
                        flags: 0,
                        increment,
                    },
                ),
                Action::Reset(stream) => self.frame(
                    dir,
                    &Reset {
                        stream,
                        flags: 0,
                        code: 8,
                    },
                ),
                Action::Retire(stream) => {
                    self.sessions[dir].retire(stream);
                }
                Action::Data { stream, len, end } => {
                    // Four legal frames cross the initial window with a four-byte input.
                    let mut left = len.min(65_536);
                    loop {
                        let take = left.min(DEFAULT_FRAME_SIZE);
                        left -= take;
                        self.frame(
                            dir,
                            &Data {
                                stream,
                                flags: u8::from(end && left == 0),
                                data: vec![0x61; take],
                                padding: None,
                            },
                        );
                        if left == 0 {
                            break;
                        }
                    }
                }
                Action::Eof => {
                    self.sessions[dir].end();
                    self.drain(dir);
                    assert!(self.sessions[dir].is_done());
                }
                Action::Loss => {
                    self.sessions[dir].lost();
                    assert!(self.sessions[dir].is_done());
                    assert_eq!(self.sessions[dir].held(), 0);
                    assert_eq!(self.sessions[dir].buffered(), 0);
                    assert!(self.sessions[dir].next().is_none());
                }
            }
        }

        fn compare(&self, other: &Self) {
            assert_eq!(self.events, other.events);
            assert_eq!(self.data, other.data);
            for (a, b) in self.sessions.iter().zip(&other.sessions) {
                assert_eq!(a.failed(), b.failed());
                assert_eq!(a.is_done(), b.is_done());
                assert_eq!(a.settings(), b.settings());
                assert_eq!(a.peer(), b.peer());
                assert_eq!(a.connection_window(), b.connection_window());
                assert_eq!(a.held(), b.held());
                assert_eq!(a.buffered(), b.buffered());
                assert!(a.streams.len() <= a.limits.streams);
                assert!(a.peer_resets.len() <= a.limits.streams);
                assert!(a.settings_updates.len() <= 64);
                for stream in 1..=STREAMS {
                    assert_eq!(a.stream_window(stream), b.stream_window(stream));
                }
            }
        }
    }

    fn run(actions: impl IntoIterator<Item = (usize, Action)>, chunk: usize) -> Pair {
        let mut whole = Pair::new(usize::MAX);
        let mut split = Pair::new(chunk);
        for (dir, action) in actions
            .into_iter()
            .take(MAX_ACTIONS)
            .chain([(0, Action::Eof), (1, Action::Eof)])
        {
            whole.events.clear();
            split.events.clear();
            whole.apply(dir, action);
            split.apply(dir, action);
            whole.compare(&split);
        }
        // Keep the pre-loss state for deterministic regressions.
        for dir in 0..2 {
            split.apply(dir, Action::Loss);
        }
        whole
    }

    /// Runs at most 64 four-byte actions through paired directions. The first
    /// byte selects the operation and direction, the second selects a stream,
    /// and the last two select bounded values and flags. Compares events and
    /// state under whole-frame and fragmented delivery, including invalid orders.
    pub fn check_actions(bytes: &[u8]) {
        let actions = bytes.as_chunks::<4>().0.iter().take(MAX_ACTIONS).map(|b| {
            let dir = usize::from(b[0] & 1);
            let stream = u32::from(b[1]) % STREAMS + 1;
            let value = VALUES[usize::from(b[2]) % VALUES.len()];
            let end = b[3] & 1 != 0;
            let action = match (b[0] / 2) % 10 {
                0 => Action::Open {
                    stream,
                    end,
                    table: b[3] >> 1,
                },
                1 => Action::Settings { id: 1, value },
                2 => Action::Settings { id: 4, value },
                3 => Action::Ack,
                4 => Action::Credit {
                    stream: if b[3] & 2 != 0 { 0 } else { stream },
                    increment: value.max(1),
                },
                5 => Action::Reset(stream),
                6 => Action::Retire(stream),
                7 => Action::Data {
                    stream,
                    len: [0, 1, 16_384, 65_535, 65_536][usize::from(b[2]) % 5],
                    end,
                },
                8 => Action::Eof,
                _ => Action::Loss,
            };
            (dir, action)
        });
        run(actions, usize::from(bytes.last().copied().unwrap_or(0)) + 1);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn open(stream: u32) -> Action {
            Action::Open {
                stream,
                end: false,
                table: 0,
            }
        }

        #[test]
        fn paired_early_credit_is_spent_beyond_initial_window() {
            let pair = run(
                [
                    (0, open(1)),
                    (
                        0,
                        Action::Credit {
                            stream: 1,
                            increment: 65_536,
                        },
                    ),
                    (
                        0,
                        Action::Credit {
                            stream: 0,
                            increment: 65_536,
                        },
                    ),
                    (1, open(1)),
                    (
                        1,
                        Action::Data {
                            stream: 1,
                            len: 65_536,
                            end: true,
                        },
                    ),
                ],
                7,
            );
            assert_eq!(pair.data, [0, 65_536]);
            assert_eq!(pair.sessions[1].stream_window(1), Some(65_535));
            assert_eq!(pair.sessions[1].connection_window(), 65_535);
            assert!(pair.sessions.iter().all(|s| s.failed().is_none()));
        }

        #[test]
        fn paired_hpack_rebound_waits_for_ordered_acks() {
            let pair = run(
                [
                    (0, Action::Settings { id: 1, value: 1024 }),
                    (0, Action::Settings { id: 1, value: 2048 }),
                    (1, open(1)),
                    (1, Action::Ack),
                    (
                        1,
                        Action::Open {
                            stream: 3,
                            end: false,
                            table: 2,
                        },
                    ),
                    (1, Action::Ack),
                    (1, open(5)),
                ],
                1,
            );
            assert!(pair.sessions.iter().all(|s| s.failed().is_none()));
            for stream in [1, 3, 5] {
                assert_eq!(pair.sessions[1].stream_window(stream), Some(65_535));
            }
            assert_eq!(pair.sessions[1].blocks.table.table_capacity(), 2048);
        }

        #[test]
        fn paired_reset_and_retire_discard_in_flight_data() {
            let pair = run(
                [
                    (0, open(1)),
                    (1, open(1)),
                    (1, Action::Reset(1)),
                    (0, Action::Retire(1)),
                    (1, Action::Retire(1)),
                    (
                        0,
                        Action::Data {
                            stream: 1,
                            len: 16_384,
                            end: true,
                        },
                    ),
                    (0, open(3)),
                    (1, open(3)),
                ],
                17,
            );
            assert_eq!(pair.data, [0, 0]);
            assert_eq!(pair.sessions[0].connection_window(), 65_535 - 16_384);
            assert!(pair.sessions.iter().all(|s| s.failed().is_none()));
            assert!(pair.sessions.iter().all(|s| s.stream_window(1).is_none()));
        }

        #[test]
        fn paired_compact_actions_are_bounded_and_repeatable() {
            use fictionet::stdlib::{codec::Lcg, test_support::rounds};
            let mut rng = Lcg::new(0x4832);
            for _ in 0..rounds(100) {
                let mut bytes = vec![0; 4 * (MAX_ACTIONS + 1)];
                rng.fill(&mut bytes);
                check_actions(&bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    fn fixture_window_update(stream: u32, flags: u8, increment: u32) -> WindowUpdate {
        WindowUpdate {
            stream,
            flags,
            increment,
        }
    }

    use super::*;
    use fictionet::stdlib::codec::Stream;
    use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};

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
    /// A block's fields as owned fields, marks included, to compare with
    /// the fields that were encoded.
    fn owned(fields: &Fields) -> Vec<hpack::Field> {
        fields
            .iter_marked()
            .map(|(name, value, never_index)| hpack::Field {
                name: name.to_vec(),
                value: value.to_vec(),
                never_index,
            })
            .collect()
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
            let frame = Frame::parse(bytes).unwrap();
            assert_write(&frame).unwrap();
            assert_eq!(frame.to_bytes().unwrap(), *bytes);
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Frame::parse(&trailing).is_err());
            assert_eq!(
                decode_chunks(
                    &mut Stream::new(Inputs::with_limit(128)),
                    chunks(bytes, &[1, 7, 64]),
                    |_| {}
                ),
                decode_all(|| Inputs::with_limit(128), bytes)
            );
        }
        macro_rules! wire { ($($ty:ty => $i:expr),+) => { $(if let Ok(value) = <$ty>::parse(&frames[$i]) { assert_write(&value).unwrap(); };)+ }; }
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
        let invalid = fixture_window_update(0, 0, 0);
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
        if let Ok(value) = FrameHeader::parse(&frames[0][..9]) {
            assert_write(&value).unwrap();
        }
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
    fn parsed_header_fragments_match_raw_assembly() {
        for pad in [None, Some(0), Some(1), Some(255)] {
            for kind in [1, 5] {
                for priority in [false, true] {
                    let mut encoder = hpack::Encoder::new(4096);
                    let fields = [hpack::Field::new("x-saved", "value")];
                    let mut block = Vec::new();
                    encoder.encode_block(&fields, &mut block).unwrap();
                    let mut indexed = Vec::new();
                    encoder.encode_block(&fields, &mut indexed).unwrap();
                    assert!(indexed.len() < block.len());
                    for split in 0..=block.len() {
                        let padding = pad.map(|n| vec![0xa5; n]);
                        let flags = if pad.is_some() { 8 } else { 0 };
                        let first = if kind == 1 {
                            Frame::Headers(Headers {
                                stream: 1,
                                flags: flags | 1 | if priority { 0x20 } else { 0 },
                                fragment: block[..split].to_vec(),
                                priority: priority.then_some(Dependency {
                                    stream: 3,
                                    exclusive: true,
                                    weight: 255,
                                }),
                                padding,
                            })
                        } else {
                            Frame::PushPromise(PushPromise {
                                stream: 1,
                                flags,
                                promised: 2,
                                fragment: block[..split].to_vec(),
                                padding,
                            })
                        };
                        let frames = [
                            first.to_bytes().unwrap(),
                            raw(9, 0x2c, 1, &block[split..]),
                            raw(1, 4, 3, &indexed),
                            raw(6, 0, 0, b"12345678"),
                        ];
                        let mut raw_blocks = HeaderBlocks::with_limits(Limits::default());
                        let mut parsed_blocks = HeaderBlocks::with_limits(Limits::default());
                        let budget = Budget::unlimited();
                        for bytes in frames {
                            let header = FrameHeader::parse(&bytes[..HEADER_LEN]).unwrap();
                            let frame = Frame::parse(&bytes).unwrap();
                            assert_eq!(frame.header(bytes.len() - HEADER_LEN), header);
                            let (mut from_raw, mut from_parsed) = (Fields::new(), Fields::new());
                            assert_eq!(
                                raw_blocks.read(
                                    header,
                                    &bytes[HEADER_LEN..],
                                    &mut from_raw,
                                    &budget
                                ),
                                parsed_blocks.read_frame(&frame, &mut from_parsed, &budget),
                            );
                            assert_eq!(from_raw, from_parsed);
                            assert_eq!(raw_blocks.held(), parsed_blocks.held());
                            assert_eq!(raw_blocks.pending(), parsed_blocks.pending());
                        }
                    }
                }
            }
        }
    }
    /// Blocks cut into fragments of every size, some past the block
    /// limit: header assembly never allocates more than its bound.
    #[test]
    fn header_assembly_stays_within_its_bound() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        let rng = SeededEntropy::new(Seed::from_u64(9));
        let below = |n: u64| rng.random_below(n) as usize;
        let limits = Limits {
            header_block: 3000,
            ..Limits::default()
        };
        let mut blocks = HeaderBlocks::with_limits(limits);
        let most = blocks.most_allocated();
        let mut encoder = hpack::Encoder::new(4096);
        let (mut whole, mut refused) = (0, 0);
        for stream in (1..400).step_by(2) {
            let fields: Vec<_> = (0..below(16))
                .map(|i| {
                    let mut value = vec![0; below(400)];
                    rng.fill_random(&mut value);
                    hpack::Field::new(format!("x-{i}"), value)
                })
                .collect();
            let mut block = Vec::new();
            encoder.encode_block(&fields, &mut block).unwrap();
            let mut rest = &block[..];
            let mut kind = 1;
            loop {
                let n = rest.len().min(1 + below(700));
                let last = n == rest.len();
                let frame = raw(kind, if last { 4 } else { 0 }, stream, &rest[..n]);
                let header = FrameHeader::parse(&frame[..HEADER_LEN]).unwrap();
                let bound = blocks.most_block(blocks.joined_len() + n);
                let mut fields = Fields::new();
                let budget = Budget::unlimited();
                let read = blocks.read(header, &frame[HEADER_LEN..], &mut fields, &budget);
                assert!(
                    blocks.allocated() <= most,
                    "{} > {most}",
                    blocks.allocated()
                );
                match read {
                    Err(_) => {
                        // The connection would end here; the encoder's
                        // table moved on without the decoder.
                        refused += 1;
                        blocks = HeaderBlocks::with_limits(limits);
                        encoder = hpack::Encoder::new(4096);
                        break;
                    }
                    Ok(read) if last => {
                        assert!(read.complete);
                        let record = fictionet::stdlib::protocols::fields::RECORD;
                        let written = fields.octets() + fields.len() * record;
                        assert!(written <= bound.bytes(), "{written} > {}", bound.bytes());
                        assert_eq!(blocks.storage().capacity(), 0, "the joined block stayed");
                        whole += 1;
                        break;
                    }
                    Ok(_) => {}
                }
                rest = &rest[n..];
                kind = 9;
            }
        }
        assert!(whole > 0 && refused > 0, "{whole} whole, {refused} refused");
    }
    /// Storage kept for joining stays between blocks: a split block that
    /// fits it is joined in it, and one that does not grows it, which
    /// gives the growth back once the block is decoded. Both decode to
    /// their fields.
    #[test]
    fn kept_assembly_storage_stays_between_blocks() {
        let mut blocks = HeaderBlocks::with_limits(Limits::default());
        assert!(blocks.keep(64));
        let kept = blocks.storage().capacity();
        assert!(kept >= 64);
        let budget = Budget::unlimited();
        for (stream, len) in [(1, 40), (3, 200), (5, 64)] {
            // `len` fields of :method GET, each one indexed byte.
            let block = vec![0x82; len];
            let mut fields = Fields::new();
            for (kind, flags, fragment) in [(1, 0, &block[..len / 2]), (9, 4, &block[len / 2..])] {
                let frame = raw(kind, flags, stream, fragment);
                let header = FrameHeader::parse(&frame[..HEADER_LEN]).unwrap();
                blocks
                    .read(header, &frame[HEADER_LEN..], &mut fields, &budget)
                    .unwrap();
                if len <= kept {
                    assert_eq!(blocks.storage().capacity(), kept);
                }
            }
            assert_eq!(fields.len(), len);
            assert_eq!(blocks.storage().capacity(), kept, "the kept storage stayed");
        }
    }
    #[test]
    fn header_assembly_retains_opening_context() {
        for kind in [1, 5] {
            let mut blocks = HeaderBlocks::with_limits(Limits::default());
            let (body, promised, end) = if kind == 5 {
                (vec![0, 0, 0, 2, 0x82], Some(2), false)
            } else {
                (vec![0x82], None, true)
            };
            let budget = Budget::unlimited();
            let mut fields = Fields::new();
            let first = raw(kind, u8::from(end), 1, &body);
            let header = FrameHeader::parse(&first[..9]).unwrap();
            assert_eq!(
                blocks
                    .read(header, &first[9..], &mut fields, &budget)
                    .unwrap(),
                BlockRead {
                    stream: 1,
                    end,
                    promised,
                    complete: false,
                }
            );
            assert!(blocks.pending());
            assert!(
                fields.is_empty(),
                "nothing is decoded before the block ends"
            );
            let last = raw(9, 4, 1, &[0x84]);
            let header = FrameHeader::parse(&last[..9]).unwrap();
            assert_eq!(
                blocks
                    .read(header, &last[9..], &mut fields, &budget)
                    .unwrap(),
                BlockRead {
                    stream: 1,
                    end,
                    promised,
                    complete: true,
                }
            );
            let decoded: Vec<_> = fields.iter().collect();
            assert_eq!(decoded, [(&b":method"[..], &b"GET"[..]), (b":path", b"/")]);
            assert!(!blocks.pending());
        }
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
        let mut s = Stream::new(Inputs::with_limit(2));
        assert_eq!(s.push(&raw(0, 0, 1, b"abc")), 12);
        assert!(matches!(
            s.next().unwrap().unwrap(),
            Input::Refused {
                scope: ErrorScope::Connection,
                oversized: true,
                ..
            }
        ));
        assert!(s.next().is_none());
        assert!(!s.decoder().pending());
    }
    #[test]
    fn frame_refusals_keep_scope_context_and_following_frames() {
        for (kind, stream, body, scope, code) in [
            (
                2,
                1,
                vec![0; 4],
                ErrorScope::Stream,
                ErrorCode::FrameSizeError,
            ),
            (
                2,
                1,
                vec![0, 0, 0, 1, 0],
                ErrorScope::Stream,
                ErrorCode::ProtocolError,
            ),
            (
                8,
                1,
                vec![0; 4],
                ErrorScope::Stream,
                ErrorCode::ProtocolError,
            ),
            (
                8,
                0,
                vec![0; 4],
                ErrorScope::Connection,
                ErrorCode::ProtocolError,
            ),
            (
                8,
                1,
                vec![0; 3],
                ErrorScope::Connection,
                ErrorCode::FrameSizeError,
            ),
            (
                2,
                0,
                vec![0; 5],
                ErrorScope::Connection,
                ErrorCode::ProtocolError,
            ),
        ] {
            let first = raw(kind, 0, stream, &body);
            let header = FrameHeader::parse(&first[..HEADER_LEN]).unwrap();
            let bytes = [first, settings()].concat();
            let expected = decode_all(Inputs::default, &bytes);
            for chunk in [1, 7, 64] {
                assert_eq!(
                    decode_chunks(
                        &mut Stream::new(Inputs::default()),
                        chunks(&bytes, &[chunk]),
                        |_| {}
                    ),
                    expected
                );
            }
            let mut input = Stream::new(Inputs::default());
            assert_eq!(input.push(&bytes), bytes.len());
            assert!(matches!(input.next().unwrap().unwrap(), Input::Refused {
                header: found, error, scope: found_scope, oversized: false,
            } if found == header && error.code == code && found_scope == scope));
            assert!(matches!(
                input.next().unwrap().unwrap(),
                Input::Frame(Frame::Settings(_))
            ));
            assert!(input.next().is_none());
        }
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
            matches!(&expected[2], Ok(Event::Headers { fields: h, end: false, .. }) if owned(h) == fields)
        );
        assert!(
            matches!(&expected[4], Ok(Event::Trailers { fields, .. }) if owned(fields)[0].name == b"grpc-status")
        );
        assert_eq!(
            decode_chunks(
                &mut Stream::new(Inputs::client_side(DEFAULT_FRAME_SIZE)),
                chunks(&bytes, &[1, 7, 64]),
                |_| {}
            ),
            decode_all(|| Inputs::client_side(DEFAULT_FRAME_SIZE), &bytes)
        );
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
        let update = fixture_window_update(1, 0, 65_536);
        // The caller has observed the request HEADERS in the other direction.
        c.peer_open(1).unwrap();
        c.peer_window_update(&update).unwrap();
        c.peer_window_update(&fixture_window_update(0, 0, 65_536))
            .unwrap();
        accept(&mut c, &raw(1, 4, 1, &[0x88]));
        for i in 0..4 {
            let events = accept(&mut c, &raw(0, u8::from(i == 3), 1, &[0; 16_384]));
            assert!(matches!(&events[..], [Event::Data { data, .. }] if data.len() == 16_384));
        }
        assert_eq!(c.stream_window(1), Some(65_535));
        assert_eq!(c.connection_window(), 65_535);
        c.peer_open(1).unwrap();
        c.peer_window_update(&fixture_window_update(1, 0, MAX_WINDOW))
            .unwrap();
        assert_eq!(c.stream_window(1), Some(65_535));
        assert!(c.retire(1));
        c.peer_open(1).unwrap();
        c.peer_window_update(&update).unwrap();
        assert_eq!(c.stream_window(1), None);
        assert!(c.failed().is_none());
    }

    #[test]
    fn peer_open_preserves_credit_and_bounds_stream_state() {
        let mut c = Session::server_side(Limits {
            streams: 2,
            ..Limits::default()
        });
        c.peer_open(1).unwrap();
        c.peer_window_update(&fixture_window_update(1, 0, 10))
            .unwrap();
        c.peer_open(1).unwrap();
        assert_eq!(c.stream_window(1), Some(65_545));
        c.peer_open(3).unwrap();
        c.peer_open(1).unwrap();
        assert_eq!(c.streams.len(), 2);
        let e = c.peer_open(5).unwrap_err();
        assert_eq!(e.code, ErrorCode::EnhanceYourCalm);
        assert_eq!(c.failed(), Some(&e));
        assert_eq!(c.stream_window(5), None);
        assert!(c.next().is_none());
    }

    #[test]
    fn push_promise_retains_early_credit_and_bounds_stream_state() {
        let mut c = Session::server_side(Limits {
            streams: 2,
            ..Limits::default()
        });
        accept(&mut c, &settings());
        accept(&mut c, &raw(1, 4, 1, &[0x88]));
        let promise = raw(5, 4, 1, &[0, 0, 0, 2, 0x82]);
        assert!(matches!(
            accept(&mut c, &promise)[..],
            [Event::PushPromise { promised: 2, .. }]
        ));
        for stream in [2, 0] {
            c.peer_window_update(&fixture_window_update(stream, 0, 65_536))
                .unwrap();
        }
        accept(&mut c, &promise);
        accept(&mut c, &raw(1, 4, 2, &[0x88]));
        for i in 0..4 {
            let events = accept(&mut c, &raw(0, u8::from(i == 3), 2, &[0; 16_384]));
            assert!(matches!(&events[..], [Event::Data { data, .. }] if data.len() == 16_384));
        }
        assert_eq!(c.stream_window(2), Some(65_535));
        assert_eq!(c.connection_window(), 65_535);
        assert!(c.retire(2));
        accept(&mut c, &promise);
        assert_eq!(c.stream_window(2), None);
        c.peer_reset(4);
        accept(&mut c, &raw(5, 4, 1, &[0, 0, 0, 4, 0x82]));
        assert_eq!(c.stream_window(4), None);
        accept(&mut c, &raw(5, 4, 1, &[0, 0, 0, 6, 0x82]));
        assert_eq!(c.stream_window(6), Some(65_535));
        assert_eq!(c.push(&raw(5, 4, 1, &[0, 0, 0, 8, 0x82])), 14);
        let e = c.next().unwrap().unwrap_err();
        assert_eq!(e.code, ErrorCode::EnhanceYourCalm);
        assert_eq!(c.failed(), Some(&e));
        assert_eq!(c.stream_window(8), None);
        assert!(c.next().is_none());
    }

    #[test]
    fn peer_open_validates_ids_and_still_requires_headers() {
        for stream in [0, MAX_WINDOW + 1] {
            let mut c = Session::server_side(Limits::default());
            let e = c.peer_open(stream).unwrap_err();
            assert_eq!(e.code, ErrorCode::ProtocolError);
            assert_eq!(c.failed(), Some(&e));
            assert!(c.streams.is_empty());
        }
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        c.peer_open(1).unwrap();
        assert_eq!(c.push(&raw(0, 0, 1, b"early")), 14);
        assert_eq!(
            c.next().unwrap().unwrap_err().code,
            ErrorCode::ProtocolError
        );
    }

    #[test]
    fn peer_open_uses_current_settings_and_retains_credit_across_ack() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        for value in [70_000, 2] {
            c.peer_settings(&Settings {
                flags: 0,
                entries: vec![Setting { id: 4, value }],
            })
            .unwrap();
        }
        c.peer_open(1).unwrap();
        assert_eq!(c.stream_window(1), Some(70_000));
        c.peer_window_update(&fixture_window_update(1, 0, 10))
            .unwrap();
        accept(&mut c, &raw(4, 1, 0, &[]));
        assert_eq!(c.stream_window(1), Some(70_010));
        accept(&mut c, &raw(4, 1, 0, &[]));
        assert_eq!(c.stream_window(1), Some(12));
        assert!(matches!(
            accept(&mut c, &raw(1, 4, 1, &[0x88]))[..],
            [Event::Headers { .. }]
        ));
        accept(&mut c, &raw(0, 1, 1, &[0; 12]));
        assert_eq!(c.stream_window(1), Some(0));
    }

    #[test]
    fn peer_open_after_retirement_preserves_lower_active_streams_and_parity() {
        let mut c = Session::server_side(Limits {
            streams: 2,
            ..Limits::default()
        });
        accept(&mut c, &settings());
        c.peer_open(1).unwrap();
        c.peer_open(3).unwrap();
        accept(&mut c, &raw(1, 5, 3, &[0x88]));
        assert!(c.retire(3));
        c.peer_open(3).unwrap();
        assert_eq!(c.stream_window(3), None);
        c.peer_open(2).unwrap();
        assert_eq!(c.stream_window(2), Some(65_535));
        c.peer_open(1).unwrap();
        c.peer_window_update(&fixture_window_update(1, 0, 10))
            .unwrap();
        accept(&mut c, &raw(1, 5, 1, &[0x88]));
        assert_eq!(c.stream_window(1), Some(65_545));
        assert_eq!(c.push(&raw(1, 5, 3, &[0x88])), 10);
        assert_eq!(c.next().unwrap().unwrap_err().code, ErrorCode::StreamClosed);
    }

    #[test]
    fn peer_open_does_not_revive_reset_streams() {
        let mut c = Session::server_side(Limits {
            streams: 1,
            ..Limits::default()
        });
        accept(&mut c, &settings());
        for stream in [1, 3, 5] {
            c.peer_reset(stream);
            c.peer_open(stream).unwrap();
            c.peer_window_update(&fixture_window_update(stream, 0, MAX_WINDOW))
                .unwrap();
            assert_eq!(c.stream_window(stream), None);
        }
        c.peer_open(1).unwrap();
        assert_eq!(c.stream_window(1), None);
        assert!(accept(&mut c, &raw(0, 1, 1, b"late")).is_empty());
        assert_eq!(c.connection_window(), 65_531);
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
                if owned(fields)[1] == hpack::Field::new("x", "y")));
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
        c.peer_window_update(&fixture_window_update(1, 0, 10))
            .unwrap();
        assert_eq!(c.stream_window(1), Some(65_541));
        accept(&mut c, &raw(4, 1, 0, &[]));
        assert_eq!(c.stream_window(1), Some(8));
        assert_eq!(c.blocks.table.settings_limit(), 0);
        accept(&mut c, &raw(1, 4, 3, &[0x20, 0x88]));
        assert_eq!(c.stream_window(3), Some(2));
        accept(&mut c, &raw(0, 1, 3, b"ok"));
        assert!(c.retire(3));
        assert!(!c.retire(1));
        let overflow = c
            .peer_window_update(&fixture_window_update(0, 0, MAX_WINDOW))
            .unwrap_err();
        assert_eq!(overflow.code, ErrorCode::FlowControlError);
        assert!(c.next().is_none());
    }
    #[test]
    fn padded_data_charges_the_full_payload_at_the_window_boundary() {
        for (data, padding, cost) in [(vec![], 0, 1), (vec![b'a'], 2, 4), (vec![], 255, 256)] {
            for window in [cost - 1, cost] {
                let mut c = Session::server_side(Limits::default());
                accept(&mut c, &settings());
                c.peer_settings(&Settings {
                    flags: 0,
                    entries: vec![Setting {
                        id: 4,
                        value: window,
                    }],
                })
                .unwrap();
                accept(&mut c, &raw(4, 1, 0, &[]));
                accept(&mut c, &raw(1, 4, 1, &[0x88]));
                let bytes = Data {
                    stream: 1,
                    flags: 9,
                    data: data.clone(),
                    padding: Some(vec![0xa5; padding]),
                }
                .to_bytes()
                .unwrap();
                assert_eq!(c.push(&bytes), bytes.len());
                if window < cost {
                    assert_eq!(
                        c.next().unwrap().unwrap_err(),
                        error(ErrorCode::FlowControlError, "stream window exhausted"),
                    );
                } else {
                    assert_eq!(
                        c.next().unwrap().unwrap(),
                        Event::Data {
                            stream: 1,
                            data: data.clone(),
                            end: true
                        },
                    );
                    assert_eq!(c.stream_window(1), Some(0));
                    assert_eq!(c.connection_window(), 65_535 - i64::from(cost));
                }
            }
        }
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
        fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, 8192).unwrap();
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
        fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, 1024).unwrap();
        fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, 2048).unwrap();
        block.push(0x88);
        accept(&mut c, &raw(1, 4, 5, &block));
        assert_eq!(c.blocks.table.table_capacity(), 2048);
    }

    #[test]
    fn hpack_pending_rebound_keeps_in_flight_headers_valid() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        for value in [1024, 2048] {
            c.peer_settings(&Settings {
                flags: 0,
                entries: vec![Setting { id: 1, value }],
            })
            .unwrap();
        }
        assert_eq!(c.peer().header_table_size, 2048);
        let events = accept(&mut c, &raw(1, 4, 1, &[0x88]));
        assert!(matches!(&events[..], [Event::Headers { fields, .. }]
            if owned(fields) == [hpack::Field::new(":status", "200")]));
        assert_eq!(c.blocks.table.settings_limit(), 4096);

        accept(&mut c, &raw(4, 1, 0, &[]));
        let mut block = Vec::new();
        fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, 1024).unwrap();
        fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, 2048).unwrap();
        block.push(0x88);
        accept(&mut c, &raw(1, 4, 3, &block));
        assert_eq!(c.blocks.table.settings_limit(), 2048);
        accept(&mut c, &raw(4, 1, 0, &[]));
        accept(&mut c, &raw(1, 4, 5, &[0x88]));
        assert_eq!(c.blocks.table.table_capacity(), 2048);
    }

    #[test]
    fn hpack_acknowledged_minima_allow_later_pending_increases() {
        let mut c = Session::server_side(Limits::default());
        accept(&mut c, &settings());
        for value in [2048, 1024, 8192] {
            c.peer_settings(&Settings {
                flags: 0,
                entries: vec![Setting { id: 1, value }],
            })
            .unwrap();
        }
        accept(&mut c, &raw(1, 4, 1, &[0x88]));
        for (stream, minimum) in [(3, 2048), (5, 1024)] {
            accept(&mut c, &raw(4, 1, 0, &[]));
            let mut block = Vec::new();
            fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, minimum).unwrap();
            fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, 8192).unwrap();
            block.push(0x88);
            accept(&mut c, &raw(1, 4, stream, &block));
            assert_eq!(c.blocks.table.table_capacity(), 8192);
            assert_eq!(c.blocks.table.settings_limit(), 8192);
        }
        accept(&mut c, &raw(4, 1, 0, &[]));
        accept(&mut c, &raw(1, 4, 7, &[0x88]));
    }

    #[test]
    fn hpack_pending_increases_preserve_required_acknowledged_reductions() {
        for ack_count in [1, 2] {
            for update in [None, Some(2048)] {
                let mut c = Session::server_side(Limits::default());
                accept(&mut c, &settings());
                for value in [1024, 8192] {
                    c.peer_settings(&Settings {
                        flags: 0,
                        entries: vec![Setting { id: 1, value }],
                    })
                    .unwrap();
                }
                for _ in 0..ack_count {
                    accept(&mut c, &raw(4, 1, 0, &[]));
                }
                let mut block = Vec::new();
                if let Some(value) = update {
                    fictionet::stdlib::protocols::prefix_int::write(&mut block, 5, 0x20, value)
                        .unwrap();
                }
                block.push(0x88);
                let frame = raw(1, 4, 1, &block);
                assert_eq!(c.push(&frame), frame.len());
                assert_eq!(
                    c.next().unwrap().unwrap_err().code,
                    ErrorCode::CompressionError
                );
                assert!(c.next().is_none());
            }
        }
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
        c.peer_window_update(&fixture_window_update(1, 0, MAX_WINDOW - 20))
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
            if let Ok(value) = Frame::parse(&bytes) {
                assert_write(&value).unwrap();
            }
            if let Ok(value) = FrameHeader::parse(&bytes) {
                assert_write(&value).unwrap();
            }
            assert_eq!(
                decode_chunks(
                    &mut Stream::new(Inputs::with_limit(128)),
                    chunks(&bytes, &[1, 7, 64]),
                    |_| {}
                ),
                decode_all(|| Inputs::with_limit(128), &bytes)
            );
        }
    }

    /// What a frame says, with what [`FrameReader`] skips left out: the
    /// padding octets, GOAWAY's debug bytes and an extension frame's
    /// payload. Refusals compare by code and scope.
    #[derive(Debug, PartialEq, Eq)]
    enum Seen {
        Preface,
        Frame(Frame),
        Refused(FrameHeader, ErrorCode, ErrorScope, bool),
    }

    fn seen(input: Input) -> Seen {
        match input {
            Input::Preface => Seen::Preface,
            Input::Refused {
                header,
                error,
                scope,
                oversized,
            } => Seen::Refused(header, error.code, scope, oversized),
            Input::Frame(mut frame) => {
                match &mut frame {
                    Frame::Data(f) => f.padding = None,
                    Frame::Headers(f) => f.padding = None,
                    Frame::PushPromise(f) => f.padding = None,
                    Frame::GoAway(f) => f.debug.clear(),
                    Frame::Unknown(f) => f.payload.clear(),
                    _ => {}
                }
                Seen::Frame(frame)
            }
        }
    }

    /// The frames a reader's steps make up, as [`seen`] shows them.
    fn fold(steps: Vec<Read>) -> Vec<Seen> {
        let mut out = Vec::new();
        let mut begun = None;
        let mut content = Vec::new();
        let mut entries = Vec::new();
        for step in steps {
            match step {
                Read::Preface => out.push(Seen::Preface),
                Read::Refused {
                    header,
                    error,
                    scope,
                    oversized,
                } => {
                    assert!(begun.is_none() || matches!(begun, Some(Begin::Settings { .. })));
                    begun = None;
                    entries.clear();
                    out.push(Seen::Refused(header, error.code, scope, oversized));
                }
                Read::Begin(begin) => {
                    assert!(begun.is_none(), "a frame begins inside another");
                    begun = Some(begin);
                }
                Read::Setting(entry) => entries.push(entry),
                Read::Content(piece) => {
                    assert!(!piece.is_empty(), "content comes in pieces with bytes");
                    content.extend_from_slice(&piece);
                }
                Read::End(header) => {
                    let begin = begun.take().expect("a frame ends after it begins");
                    assert_eq!(begin.header(), header);
                    let (stream, flags) = (header.stream, header.flags);
                    let content = std::mem::take(&mut content);
                    let frame = match begin {
                        Begin::Data { len, .. } => {
                            assert_eq!(content.len(), len);
                            Frame::Data(Data {
                                stream,
                                flags,
                                data: content,
                                padding: None,
                            })
                        }
                        Begin::Headers { priority, len, .. } => {
                            assert_eq!(content.len(), len);
                            Frame::Headers(Headers {
                                stream,
                                flags,
                                fragment: content,
                                priority,
                                padding: None,
                            })
                        }
                        Begin::PushPromise { promised, len, .. } => {
                            assert_eq!(content.len(), len);
                            Frame::PushPromise(PushPromise {
                                stream,
                                flags,
                                promised,
                                fragment: content,
                                padding: None,
                            })
                        }
                        Begin::Continuation { .. } => Frame::Continuation(Continuation {
                            stream,
                            flags,
                            fragment: content,
                        }),
                        Begin::Settings { .. } => Frame::Settings(Settings {
                            flags,
                            entries: std::mem::take(&mut entries),
                        }),
                        Begin::Control {
                            control: Control::Unknown,
                            ..
                        } => Frame::Unknown(Unknown {
                            kind: header.kind,
                            flags,
                            stream,
                            payload: Vec::new(),
                        }),
                        Begin::Control { control, .. } => control.into_frame(),
                    };
                    out.push(Seen::Frame(frame));
                }
            }
        }
        assert!(begun.is_none(), "a frame was left unfinished");
        out
    }

    /// A frame of a random kind, flags, stream and payload, its length
    /// right: most are malformed in some way, some are not.
    fn random_frame(rng: &mut fictionet::stdlib::codec::Lcg, out: &mut Vec<u8>) {
        let kind = rng.below(11) as u8;
        let flags = [0, 1, 4, 5, 8, 9, 0x20, 0x24, 0x2d, 0xff][rng.index(10)];
        let stream = rng.below(4) as u32;
        let mut body = rng.bytes(40);
        // Often a payload of the length its kind wants, to get past the
        // header's checks.
        match (kind, rng.below(3)) {
            (2, 0) => body.resize(5, 0),
            (3 | 8, 0) => body.resize(4, 1),
            (4, 0) => body.truncate(body.len() / 6 * 6),
            (6 | 7, 0) => body.resize(8 + usize::from(kind == 7) * body.len(), 2),
            (0 | 1 | 5, 0) if !body.is_empty() => body[0] = (body.len() / 3) as u8,
            _ => {}
        }
        out.extend(raw(kind, flags, stream, &body));
    }

    /// The reader reads what [`Inputs`] reads, whole or in pieces: the
    /// same frames, the same refusals with the same codes and scopes, in
    /// the same order, over random streams of frames, malformed or not,
    /// cut into random pieces, with and without the preface, and past the
    /// size limit. It never gives empty content, and every frame that
    /// begins ends.
    #[test]
    fn the_reader_reads_what_whole_frames_read_in_any_pieces() {
        use fictionet::stdlib::test_support::rounds;
        let mut rng = fictionet::stdlib::codec::Lcg::new(0x4852);
        for round in 0..rounds(400) {
            let preface = round % 4 == 0;
            let limit = if round % 3 == 0 {
                24
            } else {
                DEFAULT_FRAME_SIZE
            };
            let mut bytes = Vec::new();
            if preface {
                bytes.extend_from_slice(PREFACE);
            }
            for _ in 0..rng.below(12) {
                random_frame(&mut rng, &mut bytes);
            }
            let make = || {
                if preface {
                    Inputs::client_side(limit)
                } else {
                    Inputs::with_limit(limit)
                }
            };
            let (items, failure) = decode_all(make, &bytes);
            assert!(failure.is_none(), "{failure:?}");
            let want: Vec<Seen> = items.into_iter().map(seen).collect();
            let mut reader = if preface {
                FrameReader::client_side(limit)
            } else {
                FrameReader::with_limit(limit)
            };
            let mut steps = Vec::new();
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                let n = 1 + rng.index(rest.len().min(30));
                let mut input = Chunk::unpaid(rest[..n].to_vec());
                rest = &rest[n..];
                while let Some(step) = reader.next(&mut input) {
                    steps.push(step.unwrap());
                }
                assert!(input.is_empty(), "the reader leaves input it could read");
            }
            assert_eq!(reader.finish(), Ok(()));
            assert_eq!(fold(steps), want, "{bytes:02x?}");
        }
    }

    /// Content is the input itself, never a copy: each piece shares the
    /// backing of the input it came from, and a frame that came whole in
    /// one input comes out in one piece.
    #[test]
    fn content_is_a_piece_of_the_input() {
        let mut bytes = raw(0, 9, 1, b"\x03payload...");
        bytes.extend(raw(1, 4, 3, &[0x82, 0x86, 0x84]));
        let mut input = Chunk::unpaid(bytes);
        let mut reader = FrameReader::with_limit(DEFAULT_FRAME_SIZE);
        let mut pieces = Vec::new();
        while let Some(step) = reader.next(&mut input) {
            if let Read::Content(piece) = step.unwrap() {
                assert!(piece.shares(&input));
                pieces.push(piece.to_vec());
            }
        }
        assert_eq!(pieces, [b"payload".to_vec(), vec![0x82, 0x86, 0x84]]);
    }

    /// Input that ends inside the preface or a frame is truncated; input
    /// that ends between frames is not.
    #[test]
    fn input_that_ends_inside_a_frame_is_truncated() {
        let frame = raw(6, 0, 0, b"12345678");
        for cut in 0..=frame.len() {
            let mut reader = FrameReader::with_limit(DEFAULT_FRAME_SIZE);
            let mut input = Chunk::unpaid(frame[..cut].to_vec());
            while reader.next(&mut input).is_some() {}
            assert_eq!(reader.finish().is_ok(), cut == 0 || cut == frame.len());
        }
        for cut in 0..PREFACE.len() {
            let mut reader = FrameReader::client_side(DEFAULT_FRAME_SIZE);
            let mut input = Chunk::unpaid(PREFACE[..cut].to_vec());
            while reader.next(&mut input).is_some() {}
            assert_eq!(reader.finish().is_ok(), cut == 0);
        }
    }
}
