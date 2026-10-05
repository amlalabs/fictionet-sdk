//! WebSocket (RFC 6455): the opening handshake, frames and messages, with
//! no I/O.
//!
//! A WebSocket is a long-lived, two-way channel that starts as an HTTP/1.1
//! request. The client sends a `GET` with `Upgrade: websocket` and a random
//! `Sec-WebSocket-Key`. The server answers `101 Switching Protocols` with a
//! `Sec-WebSocket-Accept` value worked out from that key. From then on both
//! sides send frames: text, binary, ping, pong and close. A message may be
//! split over several frames, and every frame a client sends is masked with
//! a 4-byte key. This module follows RFC 6455 and the IANA registry of
//! close codes. It negotiates no extensions, so the three reserved bits of
//! every frame must be 0.
//!
//! Nothing here reads a socket. A world that plays a WebSocket server
//! parses the request line and header fields itself, hands the fields to
//! [`check_request`], and writes back the fields from
//! [`Upgrade::response_headers`]. It then feeds the bytes it reads from the
//! connection to a [`codec::Stream`] of [`Messages`], gets whole [`Message`]s
//! back, and writes the bytes of its replies. Answering pings, and when to
//! close, is up to world code.
//!
//! New sessions use [`Frames`] or [`Messages`] with [`codec::Stream`].
//! [`Wire`] for [`Frame`] writes strictly and parses an exact frame.
//! The legacy [`Decoder`] retains its original behavior.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A frame or message that breaks the specification becomes an
//! [`Error`], and [`Error::close_code`] says which close code a real server
//! sends before it drops the connection.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::websocket::{check_request, Frame, Message, Messages, Opcode, Role};
//!
//! // The client's opening request, from RFC 6455 section 1.3.
//! let headers = [
//!     ("Host", "server.example.com"),
//!     ("Upgrade", "websocket"),
//!     ("Connection", "Upgrade"),
//!     ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
//!     ("Origin", "http://example.com"),
//!     ("Sec-WebSocket-Protocol", "chat, superchat"),
//!     ("Sec-WebSocket-Version", "13"),
//! ];
//! let upgrade = check_request(&headers).unwrap();
//! assert_eq!(upgrade.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
//! assert_eq!(upgrade.protocols, ["chat", "superchat"]);
//! // The world answers "101 Switching Protocols" with these fields.
//! let reply = upgrade.response_headers(Some("chat"));
//! assert!(reply.contains(&("Sec-WebSocket-Accept".to_string(), upgrade.accept.clone())));
//!
//! // A masked text frame from the client, from section 5.7.
//! let mut stream = Stream::new(Messages::new(Role::Server));
//! let bytes = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
//! assert_eq!(stream.push(&bytes), bytes.len());
//! let message = stream.next().unwrap().unwrap();
//! assert_eq!(message, Message::Text("Hello".to_string()));
//! assert!(stream.next().is_none());
//! // A server sends its frames unmasked.
//! let frame = Frame::new(Opcode::Text, b"Hello".to_vec());
//! assert_eq!(Wire::to_bytes(&frame).unwrap(), [0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
//! ```

use super::codec::{self, Step, Wire};

/// The fixed string a server appends to the client's key before hashing it
/// into `Sec-WebSocket-Accept`.
pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The only protocol version this module speaks, as sent in
/// `Sec-WebSocket-Version`.
pub const VERSION: &str = "13";
/// How many random bytes a client's `Sec-WebSocket-Key` encodes.
pub const KEY_LEN: usize = 16;
/// The longest frame header: 2 bytes, an 8-byte length and a masking key.
pub const MAX_HEADER_LEN: usize = 14;
/// The longest payload a control frame (close, ping or pong) may carry.
pub const MAX_CONTROL_PAYLOAD: usize = 125;
/// The longest close reason, after the 2-byte code.
pub const MAX_CLOSE_REASON: usize = MAX_CONTROL_PAYLOAD - 2;
/// The longest payload one frame may carry here. The RFC allows up to
/// 2^63 - 1 bytes. This module refuses more than 16 MiB, so a reader never
/// holds more than that for one frame.
pub const MAX_PAYLOAD: usize = 1 << 24;
/// The longest message [`Messages`] or a legacy [`Decoder`] reassembles,
/// and the most a writer puts in one message.
pub const MAX_MESSAGE: usize = 1 << 24;
/// The most header fields [`check_request`] and [`check_response`] read.
pub const MAX_HEADERS: usize = 256;
/// The most subprotocols a request may offer.
pub const MAX_PROTOCOLS: usize = 32;
/// The most extensions a request may offer.
pub const MAX_EXTENSIONS: usize = 32;
/// The longest value, in bytes, of a header field the handshake reads.
/// RFC 9110 section 5.4 lets a server set such a limit; this one keeps
/// what a check holds small whatever the fields hold.
pub const MAX_FIELD_LEN: usize = 8192;

/// Close codes, sent in the first two bytes of a close frame's payload.
/// The numbers come from RFC 6455 section 7.4.1 and the IANA registry.
pub mod close_code {
    /// The purpose of the connection has been met.
    pub const NORMAL: u16 = 1000;
    /// The endpoint is going away, such as a server shutting down.
    pub const GOING_AWAY: u16 = 1001;
    /// The peer broke the protocol.
    pub const PROTOCOL_ERROR: u16 = 1002;
    /// The peer sent a kind of data the endpoint cannot accept.
    pub const UNSUPPORTED_DATA: u16 = 1003;
    /// No code was present. Never sent on the wire.
    pub const NO_STATUS: u16 = 1005;
    /// The connection dropped without a close frame. Never sent on the wire.
    pub const ABNORMAL: u16 = 1006;
    /// A message's data was not what its type says, such as text that is
    /// not UTF-8.
    pub const INVALID_DATA: u16 = 1007;
    /// The peer broke the endpoint's policy.
    pub const POLICY_VIOLATION: u16 = 1008;
    /// A message was too big to process.
    pub const MESSAGE_TOO_BIG: u16 = 1009;
    /// The client needed an extension the server did not agree to.
    pub const MANDATORY_EXTENSION: u16 = 1010;
    /// The server hit an unexpected condition.
    pub const INTERNAL_ERROR: u16 = 1011;
    /// The server is restarting.
    pub const SERVICE_RESTART: u16 = 1012;
    /// The server is overloaded; the client may try again later.
    pub const TRY_AGAIN_LATER: u16 = 1013;
    /// A gateway got a bad answer from the server behind it.
    pub const BAD_GATEWAY: u16 = 1014;
    /// The TLS handshake failed. Never sent on the wire.
    pub const TLS_HANDSHAKE: u16 = 1015;

    /// Whether a close frame may carry this code: the registered codes
    /// that may be sent, and the 3000 to 4999 range left to libraries and
    /// applications. Codes below 1000, 1004 to 1006, 1015 and the rest of
    /// the reserved 1000 to 2999 range may not.
    pub fn is_sendable(code: u16) -> bool {
        matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
    }
}

/// What a frame carries, from its 4-bit opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// More of the message an earlier text or binary frame started (0x0).
    Continuation,
    /// The start of a UTF-8 text message (0x1).
    Text,
    /// The start of a binary message (0x2).
    Binary,
    /// A close frame (0x8).
    Close,
    /// A ping, which the other side answers with a pong (0x9).
    Ping,
    /// A pong, the answer to a ping (0xA).
    Pong,
}

impl Opcode {
    /// The opcode for a 4-bit value, or `None` for the reserved values.
    pub fn from_u8(value: u8) -> Option<Opcode> {
        match value {
            0x0 => Some(Opcode::Continuation),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Close),
            0x9 => Some(Opcode::Ping),
            0xa => Some(Opcode::Pong),
            _ => None,
        }
    }

    /// The opcode's 4-bit value.
    pub fn to_u8(self) -> u8 {
        match self {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xa,
        }
    }

    /// Whether frames with this opcode are control frames: close, ping and
    /// pong. Control frames are never split and carry at most 125 bytes.
    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

/// Why bytes are not a WebSocket frame. Each one is found from the header
/// alone, before the payload arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// One of the three reserved bits was set, and no extension that uses
    /// them was agreed. The value holds the three bits.
    ReservedBits(u8),
    /// The opcode was one of the reserved values.
    ReservedOpcode(u8),
    /// A control frame did not have its final bit set.
    FragmentedControl,
    /// A control frame's payload was longer than 125 bytes.
    ControlTooLong,
    /// The length used a longer form than it needed. A 16-bit length must
    /// be at least 126, and a 64-bit length more than 65535.
    NonMinimalLength,
    /// The most significant bit of a 64-bit length was set.
    LengthHighBit,
    /// The payload was longer than [`MAX_PAYLOAD`].
    TooLarge(u64),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::ReservedBits(b) => write!(f, "reserved bits {b:#05b} set with no extension agreed"),
            FrameError::ReservedOpcode(o) => write!(f, "reserved opcode {o:#x}"),
            FrameError::FragmentedControl => write!(f, "control frame without the final bit"),
            FrameError::ControlTooLong => write!(f, "control frame payload over {MAX_CONTROL_PAYLOAD} bytes"),
            FrameError::NonMinimalLength => write!(f, "payload length not in its shortest form"),
            FrameError::LengthHighBit => write!(f, "64-bit payload length with its top bit set"),
            FrameError::TooLarge(n) => write!(f, "payload of {n} bytes is over the {MAX_PAYLOAD}-byte limit"),
        }
    }
}

impl std::error::Error for FrameError {}

/// A frame header: everything before the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Whether this is the last frame of its message.
    pub fin: bool,
    /// What the frame carries.
    pub opcode: Opcode,
    /// The masking key, present on every frame a client sends.
    pub mask: Option<[u8; 4]>,
    /// The payload length, at most [`MAX_PAYLOAD`].
    pub len: usize,
    /// The header's own length, 2 to [`MAX_HEADER_LEN`] bytes.
    pub header_len: usize,
}

impl Header {
    /// Reads the header at the start of `b`. It returns `Ok(None)` when `b`
    /// ends before the header does. An error depends only on the bytes it
    /// has seen, so it shows up as soon as the bad byte arrives.
    pub fn parse(b: &[u8]) -> Result<Option<Header>, FrameError> {
        let Some(&b0) = b.first() else { return Ok(None) };
        let rsv = (b0 >> 4) & 0x07;
        if rsv != 0 {
            return Err(FrameError::ReservedBits(rsv));
        }
        let opcode = Opcode::from_u8(b0 & 0x0f).ok_or(FrameError::ReservedOpcode(b0 & 0x0f))?;
        let fin = b0 & 0x80 != 0;
        if opcode.is_control() && !fin {
            return Err(FrameError::FragmentedControl);
        }
        let Some(&b1) = b.get(1) else { return Ok(None) };
        let short = b1 & 0x7f;
        if opcode.is_control() && usize::from(short) > MAX_CONTROL_PAYLOAD {
            return Err(FrameError::ControlTooLong);
        }
        let (len, mut at) = match short {
            126 => {
                let Some(x) = b.get(2..4) else { return Ok(None) };
                let n = u16::from_be_bytes([x[0], x[1]]);
                if n < 126 {
                    return Err(FrameError::NonMinimalLength);
                }
                (u64::from(n), 4)
            }
            127 => {
                let Some(x) = b.get(2..10) else { return Ok(None) };
                let mut a = [0u8; 8];
                a.copy_from_slice(x);
                let n = u64::from_be_bytes(a);
                if n >> 63 != 0 {
                    return Err(FrameError::LengthHighBit);
                }
                if n <= 0xffff {
                    return Err(FrameError::NonMinimalLength);
                }
                (n, 10)
            }
            n => (u64::from(n), 2),
        };
        let len = match usize::try_from(len) {
            Ok(n) if n <= MAX_PAYLOAD => n,
            _ => return Err(FrameError::TooLarge(len)),
        };
        let mask = if b1 & 0x80 != 0 {
            let Some(x) = b.get(at..at + 4) else { return Ok(None) };
            at += 4;
            Some([x[0], x[1], x[2], x[3]])
        } else {
            None
        };
        Ok(Some(Header { fin, opcode, mask, len, header_len: at }))
    }

    /// The header and payload lengths together: the whole frame. For a
    /// header built by hand with a huge length it stops at `usize::MAX`.
    pub fn frame_len(&self) -> usize {
        self.header_len.saturating_add(self.len)
    }
}

/// One WebSocket frame. The payload is kept unmasked; the masking key, if
/// any, is applied when the frame is written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Whether this is the last frame of its message.
    pub fin: bool,
    /// What the frame carries.
    pub opcode: Opcode,
    /// The masking key. A client must mask every frame and a server none.
    pub mask: Option<[u8; 4]>,
    /// The payload, unmasked.
    pub payload: Vec<u8>,
}

impl Frame {
    /// A final, unmasked frame.
    pub fn new(opcode: Opcode, payload: Vec<u8>) -> Frame {
        Frame { fin: true, opcode, mask: None, payload }
    }

    /// Reads one frame from the start of `b` and says how many bytes it
    /// used. It returns `Ok(None)` when `b` ends before the frame does.
    /// It checks what one frame can show on its own; whether frames come
    /// in a valid order, and whether masking matches the sender, is for a
    /// [`Decoder`] to check.
    pub fn parse(b: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
        let Some(h) = Header::parse(b)? else { return Ok(None) };
        let end = h.frame_len();
        let Some(body) = b.get(h.header_len..end) else {
            return Ok(None);
        };
        let mut payload = body.to_vec();
        if let Some(key) = h.mask {
            apply_mask(&mut payload, key, 0);
        }
        Ok(Some((Frame { fin: h.fin, opcode: h.opcode, mask: h.mask, payload }, end)))
    }

    /// The frame's bytes, in the shortest length form. So that
    /// [`Frame::parse`] always reads them back, a control frame is always
    /// written as final and with at most 125 bytes of payload, and any
    /// other frame with at most [`MAX_PAYLOAD`] bytes; the rest is cut off.
    pub fn to_bytes(&self) -> Vec<u8> {
        let control = self.opcode.is_control();
        let limit = if control { MAX_CONTROL_PAYLOAD } else { MAX_PAYLOAD };
        let payload = &self.payload[..self.payload.len().min(limit)];
        let mut out = Vec::with_capacity(MAX_HEADER_LEN + payload.len());
        let fin = if self.fin || control { 0x80 } else { 0 };
        out.push(fin | self.opcode.to_u8());
        let masked = if self.mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => out.push(masked | n as u8),
            n if n <= 0xffff => {
                out.push(masked | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(masked | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        if let Some(key) = self.mask {
            out.extend_from_slice(&key);
        }
        let start = out.len();
        out.extend_from_slice(payload);
        if let Some(key) = self.mask {
            apply_mask(&mut out[start..], key, 0);
        }
        out
    }
}

/// Masks or unmasks `data` in place with a 4-byte key. Masking twice with
/// the same key gives the data back. `offset` is how far into the payload
/// `data` starts, for a payload handled in pieces.
pub fn apply_mask(data: &mut [u8], key: [u8; 4], offset: usize) {
    for (i, byte) in data.iter_mut().enumerate() {
        // 2^64 is a multiple of 4, so wrapping keeps the key's phase.
        *byte ^= key[offset.wrapping_add(i) % 4];
    }
}

/// Why a close frame's payload is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseError {
    /// The payload was 1 byte: too short for a code.
    Short,
    /// The payload was longer than a control frame may carry.
    TooLong,
    /// The code may not be sent in a close frame.
    Code(u16),
    /// The reason was not UTF-8.
    Utf8,
}

impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseError::Short => write!(f, "close payload of 1 byte"),
            CloseError::TooLong => write!(f, "close payload over {MAX_CONTROL_PAYLOAD} bytes"),
            CloseError::Code(c) => write!(f, "close code {c} may not be sent"),
            CloseError::Utf8 => write!(f, "close reason is not UTF-8"),
        }
    }
}

impl std::error::Error for CloseError {}

/// The code and reason a close frame carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Close {
    /// Why the connection is closing; see [`close_code`].
    pub code: u16,
    /// Text for people reading logs, at most [`MAX_CLOSE_REASON`] bytes.
    pub reason: String,
}

impl Close {
    /// A close with a code and an empty reason.
    pub fn new(code: u16) -> Close {
        Close { code, reason: String::new() }
    }

    /// Reads a close frame's payload. An empty payload carries no code,
    /// and gives `Ok(None)`.
    pub fn parse(payload: &[u8]) -> Result<Option<Close>, CloseError> {
        match payload {
            [] => Ok(None),
            [_] => Err(CloseError::Short),
            _ if payload.len() > MAX_CONTROL_PAYLOAD => Err(CloseError::TooLong),
            [hi, lo, rest @ ..] => {
                let code = u16::from_be_bytes([*hi, *lo]);
                if !close_code::is_sendable(code) {
                    return Err(CloseError::Code(code));
                }
                let reason = std::str::from_utf8(rest).map_err(|_| CloseError::Utf8)?;
                Ok(Some(Close { code, reason: reason.to_string() }))
            }
        }
    }

    /// The payload for a close frame. So that [`Close::parse`] reads it
    /// back, a code that may not be sent is written as 1000 (normal), and
    /// the reason is cut to [`MAX_CLOSE_REASON`] bytes at a character
    /// boundary.
    pub fn to_payload(&self) -> Vec<u8> {
        let code = if close_code::is_sendable(self.code) { self.code } else { close_code::NORMAL };
        let reason = &self.reason[..floor_boundary(&self.reason, MAX_CLOSE_REASON)];
        let mut out = Vec::with_capacity(2 + reason.len());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(reason.as_bytes());
        out
    }
}

/// A whole message, put back together from its frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A text message, checked to be UTF-8.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A ping and its payload. The other side should answer with a pong
    /// carrying the same payload.
    Ping(Vec<u8>),
    /// A pong and its payload.
    Pong(Vec<u8>),
    /// A close frame, with its code and reason if it had one. The other
    /// side should answer with a close frame of its own, then stop.
    Close(Option<Close>),
}

impl Message {
    /// The opcode of the message's first frame.
    pub fn opcode(&self) -> Opcode {
        match self {
            Message::Text(_) => Opcode::Text,
            Message::Binary(_) => Opcode::Binary,
            Message::Ping(_) => Opcode::Ping,
            Message::Pong(_) => Opcode::Pong,
            Message::Close(_) => Opcode::Close,
        }
    }

    /// The message as frames of at most `max_fragment` payload bytes each,
    /// all masked with `mask` if it is given. RFC 6455 section 5.3 asks a
    /// client for a fresh, unpredictable key for every frame, so a client
    /// that splits a message should use [`Message::to_masked_frames`].
    ///
    /// So that a [`Decoder`] reads the frames back, `max_fragment` is
    /// clamped to 1 to [`MAX_PAYLOAD`], text and binary data are cut to
    /// [`MAX_MESSAGE`] bytes (text at a character boundary), ping and pong
    /// payloads to 125 bytes, and a close is written as
    /// [`Close::to_payload`] does. Control messages are always one frame.
    /// Text may be split inside a character; the reader checks UTF-8 over
    /// the whole message.
    pub fn to_frames(&self, max_fragment: usize, mask: Option<[u8; 4]>) -> Vec<Frame> {
        let size = max_fragment.clamp(1, MAX_PAYLOAD);
        let one = |opcode, payload| vec![Frame { fin: true, opcode, mask, payload }];
        let (opcode, data): (Opcode, &[u8]) = match self {
            Message::Ping(p) => return one(Opcode::Ping, p[..p.len().min(MAX_CONTROL_PAYLOAD)].to_vec()),
            Message::Pong(p) => return one(Opcode::Pong, p[..p.len().min(MAX_CONTROL_PAYLOAD)].to_vec()),
            Message::Close(c) => return one(Opcode::Close, c.as_ref().map_or_else(Vec::new, Close::to_payload)),
            Message::Text(s) => (Opcode::Text, &s.as_bytes()[..floor_boundary(s, MAX_MESSAGE)]),
            Message::Binary(b) => (Opcode::Binary, &b[..b.len().min(MAX_MESSAGE)]),
        };
        if data.is_empty() {
            return one(opcode, Vec::new());
        }
        let count = data.len().div_ceil(size);
        data.chunks(size)
            .enumerate()
            .map(|(i, chunk)| Frame {
                fin: i + 1 == count,
                opcode: if i == 0 { opcode } else { Opcode::Continuation },
                mask,
                payload: chunk.to_vec(),
            })
            .collect()
    }

    /// The message as [`Message::to_frames`] splits it, with each frame
    /// masked by its own key from `next_key`, which is called once per
    /// frame, in order. It should return 4 fresh random bytes each time.
    pub fn to_masked_frames(&self, max_fragment: usize, mut next_key: impl FnMut() -> [u8; 4]) -> Vec<Frame> {
        let mut frames = self.to_frames(max_fragment, None);
        for f in &mut frames {
            f.mask = Some(next_key());
        }
        frames
    }

    /// The message as the bytes of one frame, masked with `mask` if it is
    /// given. It is cut as [`Message::to_frames`] describes.
    pub fn to_bytes(&self, mask: Option<[u8; 4]>) -> Vec<u8> {
        self.to_frames(MAX_PAYLOAD, mask).iter().flat_map(Frame::to_bytes).collect()
    }
}

/// Which side of the connection a [`Decoder`] reads for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The server, reading a client's frames, which must all be masked.
    Server,
    /// The client, reading a server's frames, which must not be masked.
    Client,
}

/// Why a stream of frames cannot be read any further. A real endpoint
/// sends a close frame with [`Error::close_code`] and drops the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A frame's header was not valid.
    Frame(FrameError),
    /// A server read a frame that was not masked.
    Unmasked,
    /// A client read a frame that was masked.
    Masked,
    /// A continuation frame came with no message in progress.
    UnexpectedContinuation,
    /// A new text or binary frame came before the last message ended.
    ExpectedContinuation,
    /// A text message was not UTF-8.
    InvalidUtf8,
    /// A message was longer than the decoder's limit.
    TooBig,
    /// A close frame's payload was not valid.
    Close(CloseError),
}

impl Error {
    /// The close code a real endpoint sends for this error: 1007 for bad
    /// text, 1009 for a message or frame too big, and 1002 for the rest.
    pub fn close_code(self) -> u16 {
        match self {
            Error::InvalidUtf8 | Error::Close(CloseError::Utf8) => close_code::INVALID_DATA,
            Error::TooBig | Error::Frame(FrameError::TooLarge(_)) => close_code::MESSAGE_TOO_BIG,
            _ => close_code::PROTOCOL_ERROR,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Frame(e) => write!(f, "bad frame: {e}"),
            Error::Unmasked => write!(f, "client frame not masked"),
            Error::Masked => write!(f, "server frame masked"),
            Error::UnexpectedContinuation => write!(f, "continuation frame with no message in progress"),
            Error::ExpectedContinuation => write!(f, "new message before the last one ended"),
            Error::InvalidUtf8 => write!(f, "text message is not UTF-8"),
            Error::TooBig => write!(f, "message over the decoder's size limit"),
            Error::Close(e) => write!(f, "bad close frame: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// A text or binary message whose last frame has not come yet.
#[derive(Clone, Debug)]
struct Partial {
    opcode: Opcode,
    data: Vec<u8>,
    /// How many bytes of text are known to be valid UTF-8.
    checked: usize,
}

/// Turns a WebSocket byte stream into messages. Feed it the bytes a
/// connection reads, in order, and take messages out until it has none.
/// It joins fragmented messages, passes on control frames that come in
/// between, checks text is UTF-8 and bounds how much it holds. A clone
/// carries on from where the original stands.
#[derive(Clone, Debug)]
pub struct Decoder {
    role: Role,
    max_message: usize,
    /// Bytes fed in. Those before `pos` have been read already.
    buf: Vec<u8>,
    pos: usize,
    partial: Option<Partial>,
    failed: Option<Error>,
    closed: bool,
}

impl Decoder {
    /// A decoder for `role` holding no bytes, taking messages up to
    /// [`MAX_MESSAGE`] bytes.
    pub fn new(role: Role) -> Decoder {
        Decoder::with_max_message(role, MAX_MESSAGE)
    }

    /// A decoder for `role` taking messages up to `max_message` bytes,
    /// clamped to [`MAX_MESSAGE`].
    pub fn with_max_message(role: Role, max_message: usize) -> Decoder {
        Decoder {
            role,
            max_message: max_message.min(MAX_MESSAGE),
            buf: Vec::new(),
            pos: 0,
            partial: None,
            failed: None,
            closed: false,
        }
    }

    /// Takes bytes read from the connection, from the start of `bytes`,
    /// and returns how many it took. It takes them all unless that would
    /// make it hold more unread bytes than [`Decoder::capacity`], which is
    /// one whole frame of the largest kind it accepts. Then take messages
    /// out and feed it the rest. When it takes no bytes, the next call to
    /// [`Decoder::next_message`] reads at least one frame or fails, so a
    /// loop of feeding and taking out always ends. After an [`Error`] or a
    /// close frame the stream holds nothing more to read, and it takes
    /// every byte and drops it.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() || self.closed {
            return bytes.len();
        }
        // Drop the bytes already read once they are at least half the
        // buffer, so each byte is moved a bounded number of times.
        if self.pos > 0 && self.pos >= self.buf.len() - self.pos {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        let n = bytes.len().min(self.capacity().saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The most unread bytes the decoder holds: a frame header and the
    /// longest payload it accepts, which is the message limit (at most
    /// [`MAX_PAYLOAD`]) or a control frame's 125 bytes, whichever is more.
    pub fn capacity(&self) -> usize {
        MAX_HEADER_LEN + self.max_message.clamp(MAX_CONTROL_PAYLOAD, MAX_PAYLOAD)
    }

    /// The next whole message, if one has come. It returns `None` when it
    /// needs more bytes or after a close frame, and keeps returning the
    /// same error once the stream has broken. A frame too big for the
    /// limit is refused from its header, before its payload is held. A
    /// decoder never holds more than [`Decoder::capacity`] unread bytes
    /// and one message being put together. Bytes already read are let go
    /// by a later `feed` once there are at least as many of them as unread
    /// ones, so reading many frames takes time linear in their length.
    pub fn next_message(&mut self) -> Option<Result<Message, Error>> {
        loop {
            if let Some(e) = self.failed {
                return Some(Err(e));
            }
            if self.closed {
                return None;
            }
            let unread = self.buf.get(self.pos..).unwrap_or(&[]);
            let h = match Header::parse(unread) {
                Ok(Some(h)) => h,
                Ok(None) => return None,
                Err(e) => return self.fail(Error::Frame(e)),
            };
            match (self.role, h.mask.is_some()) {
                (Role::Server, false) => return self.fail(Error::Unmasked),
                (Role::Client, true) => return self.fail(Error::Masked),
                _ => {}
            }
            let held = match (&self.partial, h.opcode) {
                (None, Opcode::Continuation) => return self.fail(Error::UnexpectedContinuation),
                (Some(_), Opcode::Text | Opcode::Binary) => return self.fail(Error::ExpectedContinuation),
                (Some(p), _) => p.data.len(),
                (None, _) => 0,
            };
            if !h.opcode.is_control() && held.saturating_add(h.len) > self.max_message {
                return self.fail(Error::TooBig);
            }
            let body = unread.get(h.header_len..h.frame_len())?;
            let mut payload = body.to_vec();
            self.pos += h.frame_len();
            if self.pos == self.buf.len() {
                self.buf.clear();
                self.pos = 0;
            }
            if let Some(key) = h.mask {
                apply_mask(&mut payload, key, 0);
            }
            match h.opcode {
                Opcode::Ping => return Some(Ok(Message::Ping(payload))),
                Opcode::Pong => return Some(Ok(Message::Pong(payload))),
                Opcode::Close => {
                    return match Close::parse(&payload) {
                        Ok(close) => {
                            self.closed = true;
                            self.buf = Vec::new();
                            self.pos = 0;
                            self.partial = None;
                            Some(Ok(Message::Close(close)))
                        }
                        Err(e) => self.fail(Error::Close(e)),
                    };
                }
                Opcode::Text | Opcode::Binary => {
                    self.partial = Some(Partial { opcode: h.opcode, data: payload, checked: 0 });
                }
                Opcode::Continuation => {
                    if let Some(p) = self.partial.as_mut() {
                        p.data.extend_from_slice(&payload);
                    }
                }
            }
            let Some(p) = self.partial.as_mut() else { continue };
            if p.opcode == Opcode::Text {
                // Check only the new bytes, and fail as soon as the text
                // cannot be valid, as section 8.1 asks.
                let rest = p.data.get(p.checked..).unwrap_or(&[]);
                match std::str::from_utf8(rest) {
                    Ok(_) => p.checked = p.data.len(),
                    Err(e) if e.error_len().is_some() => return self.fail(Error::InvalidUtf8),
                    Err(e) => p.checked += e.valid_up_to(),
                }
            }
            if !h.fin {
                continue;
            }
            let Some(p) = self.partial.take() else { continue };
            return match p.opcode {
                Opcode::Text => match String::from_utf8(p.data) {
                    Ok(s) => Some(Ok(Message::Text(s))),
                    Err(_) => self.fail(Error::InvalidUtf8),
                },
                _ => Some(Ok(Message::Binary(p.data))),
            };
        }
    }

    /// How many bytes are held, waiting for the rest of a frame. Parts of
    /// a message already read are not counted.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether a close frame has been read.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The error the stream broke on, if it has broken.
    pub fn error(&self) -> Option<Error> {
        self.failed
    }

    /// Which side of the connection the decoder reads for.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The longest message the decoder reassembles, after clamping.
    pub fn max_message(&self) -> usize {
        self.max_message
    }

    fn fail(&mut self, e: Error) -> Option<Result<Message, Error>> {
        self.failed = Some(e);
        self.buf = Vec::new();
        self.pos = 0;
        self.partial = None;
        Some(Err(e))
    }
}

/// Why a byte slice is not exactly one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// The frame header is invalid.
    Frame(FrameError),
    /// A close frame's payload is invalid.
    Close(CloseError),
    /// The frame is incomplete.
    Truncated,
    /// Bytes follow the frame.
    Trailing,
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Close(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete WebSocket frame"),
            Self::Trailing => f.write_str("bytes after WebSocket frame"),
        }
    }
}

impl core::error::Error for FrameParseError {}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = Error;

    /// Reads exactly one frame, validating close payloads. Mask direction,
    /// continuation order, and text messages are checked by [`Frames`] and
    /// [`Messages`].
    fn parse(bytes: &[u8]) -> Result<Self, FrameParseError> {
        match Frame::parse(bytes).map_err(FrameParseError::Frame)? {
            Some((frame, used)) if used == bytes.len() => {
                if frame.opcode == Opcode::Close {
                    Close::parse(&frame.payload).map_err(FrameParseError::Close)?;
                }
                Ok(frame)
            }
            Some(_) => Err(FrameParseError::Trailing),
            None => Err(FrameParseError::Truncated),
        }
    }

    /// Writes without clipping payloads or changing FIN. Invalid close
    /// payloads are refused with [`Error::Close`]; other invalid frames with
    /// [`Error::Frame`]. All checks happen before appending. Temporary storage
    /// is bounded by [`MAX_HEADER_LEN`] plus [`MAX_PAYLOAD`].
    /// The legacy [`Frame::to_bytes`] is unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.opcode.is_control() {
            if !self.fin {
                return Err(Error::Frame(FrameError::FragmentedControl));
            }
            if self.payload.len() > MAX_CONTROL_PAYLOAD {
                return Err(Error::Frame(FrameError::ControlTooLong));
            }
        }
        if self.payload.len() > MAX_PAYLOAD {
            return Err(Error::Frame(FrameError::TooLarge(
                u64::try_from(self.payload.len()).unwrap_or(u64::MAX),
            )));
        }
        if self.opcode == Opcode::Close {
            Close::parse(&self.payload).map_err(Error::Close)?;
        }
        out.extend_from_slice(&self.to_bytes());
        Ok(())
    }
}

/// Reads one frame per call without retaining input bytes.
///
/// Headers and mask direction follow [`Role`]. Data payloads are bounded
/// by [`Self::limit`]; control payloads may still use all 125 bytes.
/// Lengths are refused from the header. Partial frames return [`Step::Need`],
/// including at EOF, so [`codec::Stream`] reports truncation.
/// A valid close payload yields its frame, then [`Step::End`]. Use
/// [`codec::Stream::into_parts`] or [`codec::Stream::swap`] to retain the
/// unread suffix. Keep any bytes not accepted by [`codec::pump`] as well.
/// Use [`Messages`] for continuation order and text validation.
#[derive(Clone, Debug)]
pub struct Frames {
    role: Role,
    limit: usize,
    closed: bool,
}

impl Frames {
    /// Reads frames for `role` with data payloads up to [`MAX_PAYLOAD`].
    pub fn new(role: Role) -> Self {
        Self::with_limit(role, MAX_PAYLOAD)
    }

    /// Sets the data payload limit, clamped to [`MAX_PAYLOAD`]. Zero
    /// permits empty data frames. Control frames keep their protocol limit.
    pub fn with_limit(role: Role, limit: usize) -> Self {
        Self { role, limit: limit.min(MAX_PAYLOAD), closed: false }
    }

    /// The largest accepted data payload, excluding its header.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The endpoint receiving these frames.
    pub fn role(&self) -> Role {
        self.role
    }

    fn header(&self, input: &[u8]) -> Result<Option<Header>, Error> {
        let Some(h) = Header::parse(input).map_err(Error::Frame)? else { return Ok(None) };
        match (self.role, h.mask.is_some()) {
            (Role::Server, false) => return Err(Error::Unmasked),
            (Role::Client, true) => return Err(Error::Masked),
            _ => {}
        }
        if !h.opcode.is_control() && h.len > self.limit {
            return Err(Error::TooBig);
        }
        Ok(Some(h))
    }
}

impl codec::Decode for Frames {
    type Item = Frame;
    type Error = Error;
    const NAME: &'static str = "WebSocket frames";

    fn capacity(&self) -> usize {
        MAX_HEADER_LEN + self.limit.max(MAX_CONTROL_PAYLOAD)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, Error> {
        if self.closed {
            return Ok(Step::End);
        }
        let Some(h) = self.header(input)? else { return Ok(Step::Need) };
        let Some(body) = input.get(h.header_len..h.frame_len()) else { return Ok(Step::Need) };
        let mut payload = body.to_vec();
        if let Some(key) = h.mask {
            apply_mask(&mut payload, key, 0);
        }
        if h.opcode == Opcode::Close {
            Close::parse(&payload).map_err(Error::Close)?;
            self.closed = true;
        }
        Ok(Step::Item(Frame { fin: h.fin, opcode: h.opcode, mask: h.mask, payload }, h.frame_len()))
    }
}

/// Joins [`Frames`] into messages as one [`codec::Decode`] stack.
///
/// Unlike a byte [`codec::Pipe`], this layer keeps frame opcodes and FIN
/// boundaries. Ping and pong pass through without changing the partial
/// message. Close releases that partial message and yields its own item,
/// then `End`, preserving unread bytes for handoff. Continuation errors
/// and invalid UTF-8 are terminal. Text is checked incrementally, including
/// characters split across fragments. EOF inside a frame is truncation;
/// EOF between fragments is [`codec::AssembleError::Incomplete`], even
/// when the unfinished message is empty. Held bytes never exceed the
/// configured message limit, which is clamped to [`MAX_MESSAGE`].
///
/// Errors use [`codec::AssembleError::Inner`] for protocol failures and
/// [`codec::AssembleError::Incomplete`] for EOF between fragments. A message
/// over the limit, in one frame or several, gives `Inner(Error::TooBig)`,
/// whose [`Error::close_code`] is [`close_code::MESSAGE_TOO_BIG`]. The
/// `TooLong` and `Allocation` variants are not returned by this decoder.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire}, websocket::{Messages, Frame, Opcode, Role}};
/// let mut stream = Stream::new(Messages::new(Role::Server));
/// let frame = Frame { fin: true, opcode: Opcode::Close, mask: Some([1; 4]), payload: vec![] };
/// let mut bytes = Wire::to_bytes(&frame)?;
/// bytes.extend_from_slice(b"next protocol");
/// assert_eq!(stream.push(&bytes), bytes.len());
/// assert!(stream.next().is_some());
/// assert!(stream.next().is_none());
/// let (buffer, _) = stream.into_parts();
/// assert_eq!(buffer.unread(), b"next protocol");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Messages {
    frames: Frames,
    limit: usize,
    partial: Option<Partial>,
}

impl Messages {
    /// Reads messages up to [`MAX_MESSAGE`] for the receiving `role`.
    pub fn new(role: Role) -> Self {
        Self::with_limit(role, MAX_MESSAGE)
    }

    /// Uses `limit` for data frames and assembled messages, clamped to
    /// [`MAX_MESSAGE`]. Control frames retain their 125-byte limit.
    pub fn with_limit(role: Role, limit: usize) -> Self {
        Self::from_frames(Frames::with_limit(role, limit), limit)
    }

    /// Wraps a frame decoder with a separate message limit. The frame
    /// decoder keeps its own input capacity. Assembly refuses an excessive
    /// sum from the next frame's header, before copying its payload.
    pub fn from_frames(frames: Frames, limit: usize) -> Self {
        Self { frames, limit: limit.min(MAX_MESSAGE), partial: None }
    }

    /// The largest assembled data message in bytes.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl codec::Decode for Messages {
    type Item = Message;
    type Error = codec::AssembleError<Error>;
    const NAME: &'static str = "WebSocket messages";

    fn capacity(&self) -> usize {
        self.frames.capacity()
    }

    fn held(&self) -> usize {
        self.partial.as_ref().map_or(0, |p| p.data.len())
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Message>, Self::Error> {
        use codec::AssembleError::{Incomplete, Inner};
        if self.frames.closed {
            return Ok(Step::End);
        }
        if let Some(h) = self.frames.header(input).map_err(|error| match error {
            Error::Frame(FrameError::TooLarge(_)) => Inner(Error::TooBig),
            other => Inner(other),
        })? {
            match (&self.partial, h.opcode) {
                (None, Opcode::Continuation) => return Err(Inner(Error::UnexpectedContinuation)),
                (Some(_), Opcode::Text | Opcode::Binary) => return Err(Inner(Error::ExpectedContinuation)),
                _ => {}
            }
            if !h.opcode.is_control() && self.held().saturating_add(h.len) > self.limit {
                return Err(Inner(Error::TooBig));
            }
        }
        let (frame, used) = match self.frames.decode(input, eof).map_err(Inner)? {
            Step::Item(frame, used) => (frame, used),
            Step::Need if eof && input.is_empty() && self.partial.is_some() => {
                return Err(Incomplete { held: self.held() });
            }
            Step::Need => return Ok(Step::Need),
            Step::Skip(n) => return Ok(Step::Skip(n)),
            Step::End => return Ok(Step::End),
        };
        match frame.opcode {
            Opcode::Ping => return Ok(Step::Item(Message::Ping(frame.payload), used)),
            Opcode::Pong => return Ok(Step::Item(Message::Pong(frame.payload), used)),
            Opcode::Close => {
                let close = Close::parse(&frame.payload).map_err(|e| Inner(Error::Close(e)))?;
                self.partial = None;
                return Ok(Step::Item(Message::Close(close), used));
            }
            Opcode::Text | Opcode::Binary => {
                self.partial = Some(Partial { opcode: frame.opcode, data: frame.payload, checked: 0 });
            }
            Opcode::Continuation => {
                if let Some(p) = self.partial.as_mut() {
                    p.data.extend_from_slice(&frame.payload);
                }
            }
        }
        if let Some(p) = self.partial.as_mut() {
            if p.opcode == Opcode::Text {
                let rest = p.data.get(p.checked..).unwrap_or_default();
                match core::str::from_utf8(rest) {
                    Ok(_) => p.checked = p.data.len(),
                    Err(e) if e.error_len().is_some() || frame.fin => return Err(Inner(Error::InvalidUtf8)),
                    Err(e) => p.checked = p.checked.saturating_add(e.valid_up_to()),
                }
            }
            if frame.fin {
                let data = core::mem::take(&mut p.data);
                let message = if p.opcode == Opcode::Text {
                    Message::Text(String::from_utf8(data).map_err(|_| Inner(Error::InvalidUtf8))?)
                } else {
                    Message::Binary(data)
                };
                self.partial = None;
                return Ok(Step::Item(message, used));
            }
        }
        Ok(Step::Skip(used))
    }
}

/// Why an opening handshake is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// There were more than [`MAX_HEADERS`] header fields.
    TooManyHeaders,
    /// A field the handshake reads had a value longer than
    /// [`MAX_FIELD_LEN`] bytes. A server answers `431 Request Header
    /// Fields Too Large`.
    FieldTooLong,
    /// The request had no `Host` field, more than one, or one that is not
    /// a host with an optional port (RFC 3986 section 3.2).
    MissingHost,
    /// The request had more than one `Origin` field (RFC 6454 section
    /// 7.3).
    Origin,
    /// A request's `Upgrade` did not list `websocket`, or a response's
    /// `Upgrade` held anything other than `websocket` alone.
    Upgrade,
    /// `Connection` did not list `Upgrade`.
    Connection,
    /// `Sec-WebSocket-Version` named a version other than 13. A server
    /// answers `426 Upgrade Required` with `Sec-WebSocket-Version: 13`, so
    /// the client can retry.
    Version,
    /// `Sec-WebSocket-Version` was missing or repeated. The request is
    /// malformed, and a server answers `400 Bad Request`.
    MissingVersion,
    /// `Sec-WebSocket-Key` was missing, repeated, or not base64 for 16
    /// bytes.
    Key,
    /// `Sec-WebSocket-Accept` was missing or did not match the key.
    Accept,
    /// `Sec-WebSocket-Protocol` held something other than tokens, no
    /// name at all, too many of them, a name twice, or, in a response,
    /// one the client did not offer.
    Protocol,
    /// `Sec-WebSocket-Extensions` did not follow the grammar of RFC 6455
    /// section 9.1, held no extension at all, or too many of them; or a
    /// response held the field at all, since this module offers none.
    Extension,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HandshakeError::TooManyHeaders => "too many header fields",
            HandshakeError::FieldTooLong => "header field value too long",
            HandshakeError::MissingHost => "no single, valid Host field",
            HandshakeError::Origin => "more than one Origin field",
            HandshakeError::Upgrade => "Upgrade does not list websocket",
            HandshakeError::Connection => "Connection does not list Upgrade",
            HandshakeError::Version => "Sec-WebSocket-Version is not 13",
            HandshakeError::MissingVersion => "no single Sec-WebSocket-Version field",
            HandshakeError::Key => "Sec-WebSocket-Key is missing or not 16 bytes of base64",
            HandshakeError::Accept => "Sec-WebSocket-Accept does not match the key",
            HandshakeError::Protocol => "bad Sec-WebSocket-Protocol",
            HandshakeError::Extension => "bad Sec-WebSocket-Extensions",
        };
        f.write_str(s)
    }
}

impl HandshakeError {
    /// The HTTP status a server answers a request it refuses with: 426
    /// (with `Sec-WebSocket-Version: 13`) for [`HandshakeError::Version`],
    /// 431 for [`HandshakeError::FieldTooLong`], and 400 for the rest. The errors only [`check_response`] gives have
    /// no status, since a client answers nothing; they get 400 too.
    pub fn status_code(self) -> u16 {
        match self {
            HandshakeError::Version => 426,
            HandshakeError::FieldTooLong => 431,
            _ => 400,
        }
    }
}

impl std::error::Error for HandshakeError {}

/// A valid client upgrade request, as [`check_request`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upgrade {
    /// The client's `Sec-WebSocket-Key`, trimmed.
    pub key: String,
    /// The `Sec-WebSocket-Accept` value the server must answer with, as
    /// [`accept_key`] works it out from `key`.
    pub accept: String,
    /// The subprotocols the client offered, in its order of preference.
    pub protocols: Vec<String>,
    /// The names of the extensions the client offered. This module agrees
    /// to none of them.
    pub extensions: Vec<String>,
    /// The `Origin` field, which browsers send.
    pub origin: Option<String>,
}

impl Upgrade {
    /// The header fields of the server's `101 Switching Protocols` reply.
    /// `protocol` is the subprotocol the server picks. It is left out
    /// unless the client offered it and it is a token, so
    /// [`check_response`] accepts the reply. The accept value is worked
    /// out again from `key`, so the reply matches the key even if world
    /// code changed `accept`.
    pub fn response_headers(&self, protocol: Option<&str>) -> Vec<(String, String)> {
        let mut out = vec![
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            ("Sec-WebSocket-Accept".to_string(), accept_key(self.key.trim_matches(OWS))),
        ];
        let usable = |p: &&str| is_token(p) && p.len() <= MAX_FIELD_LEN && self.protocols.iter().any(|o| o == p);
        if let Some(p) = protocol.filter(usable) {
            out.push(("Sec-WebSocket-Protocol".to_string(), p.to_string()));
        }
        out
    }
}

/// The `Sec-WebSocket-Accept` value for a client's key: the base64 of the
/// SHA-1 of the key followed by [`GUID`].
pub fn accept_key(key: &str) -> String {
    let mut input = Vec::with_capacity(key.len() + GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(GUID.as_bytes());
    base64_encode(&sha1(&input))
}

/// The `Sec-WebSocket-Key` value for 16 random bytes a client picked.
pub fn key_from_bytes(nonce: [u8; KEY_LEN]) -> String {
    base64_encode(&nonce)
}

/// Checks the header fields of a client's opening request, given as name
/// and value pairs, and works out the accept value. Names are matched
/// without regard to case. The caller checks the request line itself: a
/// `GET` with HTTP/1.1 or later.
pub fn check_request<N: AsRef<str>, V: AsRef<str>>(headers: &[(N, V)]) -> Result<Upgrade, HandshakeError> {
    if headers.len() > MAX_HEADERS {
        return Err(HandshakeError::TooManyHeaders);
    }
    check_lengths(headers)?;
    let mut hosts = fields(headers, "host");
    match (hosts.next(), hosts.next()) {
        (Some(h), None) if is_authority(h) => {}
        _ => return Err(HandshakeError::MissingHost),
    }
    if !field_list(headers, "upgrade").iter().any(|t| t.eq_ignore_ascii_case("websocket")) {
        return Err(HandshakeError::Upgrade);
    }
    check_connection(headers)?;
    let mut versions = fields(headers, "sec-websocket-version");
    match (versions.next(), versions.next()) {
        (Some(v), None) if v == VERSION => {}
        (Some(_), None) => return Err(HandshakeError::Version),
        _ => return Err(HandshakeError::MissingVersion),
    }
    let mut keys = fields(headers, "sec-websocket-key");
    let key = match (keys.next(), keys.next()) {
        (Some(k), None) if k.len() == 24 && base64_decode(k).is_some_and(|b| b.len() == KEY_LEN) => k,
        _ => return Err(HandshakeError::Key),
    };
    let mut protocols = Vec::new();
    for value in fields(headers, "sec-websocket-protocol") {
        // Section 4.1: the field is 1#token, so it holds at least one.
        let items = split_list(value);
        if items.is_empty() {
            return Err(HandshakeError::Protocol);
        }
        for item in items {
            if !is_token(item) || protocols.len() >= MAX_PROTOCOLS || protocols.iter().any(|p| p == item) {
                return Err(HandshakeError::Protocol);
            }
            protocols.push(item.to_string());
        }
    }
    let mut extensions = Vec::new();
    for value in fields(headers, "sec-websocket-extensions") {
        // Section 9.1: the field is 1#extension.
        let items = split_list(value);
        if items.is_empty() {
            return Err(HandshakeError::Extension);
        }
        for item in items {
            match extension_name(item) {
                Some(name) if extensions.len() < MAX_EXTENSIONS => extensions.push(name.to_string()),
                _ => return Err(HandshakeError::Extension),
            }
        }
    }
    let mut origins = fields(headers, "origin");
    let origin = origins.next().map(str::to_string);
    if origins.next().is_some() {
        return Err(HandshakeError::Origin);
    }
    Ok(Upgrade { key: key.to_string(), accept: accept_key(key), protocols, extensions, origin })
}

/// The header fields of a client's opening request, for the caller to
/// write after `GET <path> HTTP/1.1`. `nonce` should be 16 fresh random
/// bytes. `host` must hold the server's host, and optionally `:port`, as
/// [`check_request`] accepts it; anything else gives
/// [`HandshakeError::MissingHost`]. Protocols that are not tokens, repeat
/// an earlier one, come past the first [`MAX_PROTOCOLS`], or would make
/// the field longer than [`MAX_FIELD_LEN`], are left out, so
/// [`check_request`] accepts the fields.
pub fn request_headers(
    host: &str,
    nonce: [u8; KEY_LEN],
    protocols: &[&str],
) -> Result<Vec<(String, String)>, HandshakeError> {
    if host.len() > MAX_FIELD_LEN || !is_authority(host) {
        return Err(HandshakeError::MissingHost);
    }
    let mut out = vec![
        ("Host".to_string(), host.to_string()),
        ("Upgrade".to_string(), "websocket".to_string()),
        ("Connection".to_string(), "Upgrade".to_string()),
        ("Sec-WebSocket-Key".to_string(), key_from_bytes(nonce)),
        ("Sec-WebSocket-Version".to_string(), VERSION.to_string()),
    ];
    let mut offered: Vec<&str> = Vec::new();
    let mut len = 0;
    for &p in protocols {
        // Each name after the first adds ", " before it.
        let add = p.len() + if offered.is_empty() { 0 } else { 2 };
        if is_token(p) && !offered.contains(&p) && offered.len() < MAX_PROTOCOLS && len + add <= MAX_FIELD_LEN {
            offered.push(p);
            len += add;
        }
    }
    if !offered.is_empty() {
        out.push(("Sec-WebSocket-Protocol".to_string(), offered.join(", ")));
    }
    Ok(out)
}

/// Checks the header fields of a server's reply to the request a client
/// sent with `key` and the subprotocols `offered`. It returns the
/// subprotocol the server picked, if any. The caller checks the status
/// line itself: status 101.
pub fn check_response<N: AsRef<str>, V: AsRef<str>>(
    headers: &[(N, V)],
    key: &str,
    offered: &[&str],
) -> Result<Option<String>, HandshakeError> {
    if headers.len() > MAX_HEADERS {
        return Err(HandshakeError::TooManyHeaders);
    }
    check_lengths(headers)?;
    // Section 4.1: the reply's Upgrade field holds "websocket" and nothing
    // else.
    match field_list(headers, "upgrade")[..] {
        [t] if t.eq_ignore_ascii_case("websocket") => {}
        _ => return Err(HandshakeError::Upgrade),
    }
    check_connection(headers)?;
    let mut accepts = fields(headers, "sec-websocket-accept");
    match (accepts.next(), accepts.next()) {
        (Some(a), None) if a == accept_key(key.trim_matches(OWS)) => {}
        _ => return Err(HandshakeError::Accept),
    }
    // Section 4.1: the client offered no extensions, so the reply may
    // name none, and an empty field is not valid either.
    if fields(headers, "sec-websocket-extensions").next().is_some() {
        return Err(HandshakeError::Extension);
    }
    let mut protocols = fields(headers, "sec-websocket-protocol");
    match (protocols.next(), protocols.next()) {
        (None, _) => Ok(None),
        (Some(p), None) if offered.contains(&p) => Ok(Some(p.to_string())),
        _ => Err(HandshakeError::Protocol),
    }
}

/// The spaces and tabs HTTP allows around a field value.
const OWS: &[char] = &[' ', '\t'];

/// The trimmed values of every field named `name`, which must be lower
/// case. Names are not trimmed: HTTP allows no whitespace around them.
fn fields<'a, N: AsRef<str>, V: AsRef<str>>(headers: &'a [(N, V)], name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(n, _)| n.as_ref().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_ref().trim_matches(OWS))
}

/// The items of every field named `name`, as one list.
fn field_list<'a, N: AsRef<str>, V: AsRef<str>>(headers: &'a [(N, V)], name: &'a str) -> Vec<&'a str> {
    fields(headers, name).flat_map(split_list).collect()
}

/// Checks that the `Connection` field both sides send lists `Upgrade`.
fn check_connection<N: AsRef<str>, V: AsRef<str>>(headers: &[(N, V)]) -> Result<(), HandshakeError> {
    if field_list(headers, "connection").iter().any(|t| t.eq_ignore_ascii_case("upgrade")) {
        Ok(())
    } else {
        Err(HandshakeError::Connection)
    }
}

/// The header fields a handshake check reads.
const READ_FIELDS: [&str; 9] = [
    "host",
    "upgrade",
    "connection",
    "sec-websocket-version",
    "sec-websocket-key",
    "sec-websocket-accept",
    "sec-websocket-protocol",
    "sec-websocket-extensions",
    "origin",
];

/// Checks that no field a handshake check reads is longer than
/// [`MAX_FIELD_LEN`], so what the check holds stays small.
fn check_lengths<N: AsRef<str>, V: AsRef<str>>(headers: &[(N, V)]) -> Result<(), HandshakeError> {
    let read = |n: &str| READ_FIELDS.iter().any(|r| n.eq_ignore_ascii_case(r));
    if headers.iter().any(|(n, v)| v.as_ref().len() > MAX_FIELD_LEN && read(n.as_ref())) {
        return Err(HandshakeError::FieldTooLong);
    }
    Ok(())
}

/// Splits `value` on `sep` where it falls outside a quoted string.
fn split_unquoted(value: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in value.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c == sep && !quoted => {
                out.push(&value[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&value[start..]);
    out
}

/// Splits an HTTP list on commas outside quoted strings, trims each item
/// and drops empty ones.
fn split_list(value: &str) -> Vec<&str> {
    split_unquoted(value, ',').into_iter().map(|s| s.trim_matches(OWS)).filter(|s| !s.is_empty()).collect()
}

/// The name of one extension in `Sec-WebSocket-Extensions`, if the item
/// follows RFC 6455 section 9.1: a token, then parameters, each
/// `; name` or `; name=value`. A value is a token, or a quoted string
/// that is a token once its escapes are undone.
fn extension_name(item: &str) -> Option<&str> {
    let mut parts = split_unquoted(item, ';').into_iter();
    let name = parts.next()?.trim_matches(OWS);
    if !is_token(name) {
        return None;
    }
    for param in parts {
        let param = param.trim_matches(OWS);
        let (key, value) = match param.split_once('=') {
            Some((k, v)) => (k.trim_matches(OWS), Some(v.trim_matches(OWS))),
            None => (param, None),
        };
        if !is_token(key) || value.is_some_and(|v| !is_token(v) && !is_quoted_token(v)) {
            return None;
        }
    }
    Some(name)
}

/// Whether `s` is a quoted string (RFC 9110 section 5.6.4) whose value,
/// with its escapes undone, is a token.
fn is_quoted_token(s: &str) -> bool {
    let Some(inner) = s.strip_prefix('"').and_then(|r| r.strip_suffix('"')) else { return false };
    let (mut any, mut escaped) = (false, false);
    for b in inner.bytes() {
        if escaped {
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
            continue;
        }
        if !is_tchar(b) {
            return false;
        }
        any = true;
    }
    any && !escaped
}

/// Whether `s` is a host with an optional port, as the `Host` field
/// holds it (RFC 9110 section 7.2, RFC 3986 section 3.2): a bracketed IP
/// literal or a non-empty registered name or IPv4 address, then `:` and
/// digits if there is a port.
fn is_authority(s: &str) -> bool {
    let (host_ok, port) = match s.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((literal, after)) => (is_ip_literal(literal), after),
            None => return false,
        },
        None => {
            let (host, port) = s.split_at(s.find(':').unwrap_or(s.len()));
            (!host.is_empty() && is_reg_name(host), port)
        }
    };
    host_ok && (port.is_empty() || port.strip_prefix(':').is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit())))
}

/// Whether `s` is the inside of an RFC 3986 IP literal: an IPv6 address,
/// or `v`, hex digits, `.` and more characters for a future version.
fn is_ip_literal(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix(['v', 'V']) {
        let Some((version, body)) = rest.split_once('.') else { return false };
        return !version.is_empty()
            && version.bytes().all(|b| b.is_ascii_hexdigit())
            && !body.is_empty()
            && body.bytes().all(|b| is_unreserved(b) || is_sub_delim(b) || b == b':');
    }
    s.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Whether `s` is an RFC 3986 registered name: unreserved characters,
/// sub-delimiters and `%` with two hex digits.
fn is_reg_name(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            match b.get(i + 1..i + 3) {
                Some([x, y]) if x.is_ascii_hexdigit() && y.is_ascii_hexdigit() => i += 3,
                _ => return false,
            }
        } else if is_unreserved(c) || is_sub_delim(c) {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~".contains(&b)
}

fn is_sub_delim(b: u8) -> bool {
    b"!$&'()*+,;=".contains(&b)
}

/// Whether `s` is an HTTP token: one or more of the characters RFC 9110
/// allows in names.
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_tchar)
}

/// Whether `b` may appear in an HTTP token.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The largest index no greater than `max` that falls on a character
/// boundary of `s`.
fn floor_boundary(s: &str, max: usize) -> usize {
    if s.len() <= max {
        return s.len();
    }
    let mut i = max;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// SHA-1 (FIPS 180-4). It is broken for signatures, but the handshake only
/// uses it to show the server read the key.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        sha1_block(&mut h, block);
    }
    let rest = blocks.remainder();
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let n = if rest.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8);
    tail[n - 8..n].copy_from_slice(&bits.to_be_bytes());
    for block in tail[..n].chunks_exact(64) {
        sha1_block(&mut h, block);
    }
    let mut out = [0u8; 20];
    for (o, word) in out.chunks_exact_mut(4).zip(h) {
        o.copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha1_block(h: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (wi, b) in w.iter_mut().zip(block.chunks_exact(4)) {
        *wi = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
        *x = x.wrapping_add(y);
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 section 4).
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(BASE64[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard, padded base64. It refuses anything else, including
/// padding bits that are not zero, so each value has one encoding.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let count = b.len() / 4;
    let mut out = Vec::with_capacity(count * 3);
    for (i, c) in b.chunks_exact(4).enumerate() {
        let pad = match (c[2], c[3]) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            _ => 0,
        };
        if pad > 0 && i + 1 != count {
            return None;
        }
        let mut n = 0u32;
        for (j, &ch) in c.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { u32::from(base64_value(ch)?) };
            n = (n << 6) | v;
        }
        let [_, x, y, z] = n.to_be_bytes();
        match pad {
            0 => out.extend_from_slice(&[x, y, z]),
            1 if z == 0 => out.extend_from_slice(&[x, y]),
            2 if y == 0 && z == 0 => out.push(x),
            _ => return None,
        }
    }
    Some(out)
}

fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6455 section 5.7.
    const HELLO: [u8; 7] = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
    const HELLO_MASKED: [u8; 11] = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
    const HEL: [u8; 5] = [0x01, 0x03, 0x48, 0x65, 0x6c];
    const LO: [u8; 4] = [0x80, 0x02, 0x6c, 0x6f];
    const PING: [u8; 7] = [0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
    const PONG_MASKED: [u8; 11] = [0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];

    fn rfc_request() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Host", "server.example.com"),
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("Origin", "http://example.com"),
            ("Sec-WebSocket-Protocol", "chat, superchat"),
            ("Sec-WebSocket-Version", "13"),
        ]
    }

    fn without(name: &str) -> Vec<(&'static str, &'static str)> {
        rfc_request().into_iter().filter(|(n, _)| *n != name).collect()
    }

    fn with<'a>(name: &'static str, value: &'a str) -> Vec<(&'a str, &'a str)> {
        let mut h = without(name);
        h.push((name, value));
        h
    }

    /// Feeds `b`, which must all be taken.
    fn feed(d: &mut Decoder, b: &[u8]) {
        assert_eq!(d.feed(b), b.len());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Every message a decoder gives for `bytes`, fed all at once, and the
    /// error it stopped on, if any.
    fn decode(role: Role, bytes: &[u8]) -> (Vec<Message>, Option<Error>) {
        decode_chunked(role, bytes, &[usize::MAX])
    }

    fn decode_bytewise(role: Role, bytes: &[u8]) -> (Vec<Message>, Option<Error>) {
        decode_chunked(role, bytes, &[1])
    }

    /// Like [`decode`], with `bytes` fed in pieces whose sizes cycle
    /// through `sizes`.
    fn decode_chunked(role: Role, mut bytes: &[u8], sizes: &[usize]) -> (Vec<Message>, Option<Error>) {
        let mut d = Decoder::new(role);
        let mut out = Vec::new();
        let mut sizes = sizes.iter().cycle();
        while !bytes.is_empty() {
            let n = sizes.next().copied().unwrap_or(1).clamp(1, bytes.len());
            let (mut piece, rest) = bytes.split_at(n);
            bytes = rest;
            // Feed the piece, taking messages out whenever the decoder is
            // full.
            while !piece.is_empty() {
                let took = d.feed(piece);
                assert!(d.buffered() <= d.capacity());
                piece = &piece[took..];
                let mut any = false;
                while let Some(m) = d.next_message() {
                    any = true;
                    match m {
                        Ok(m) => out.push(m),
                        Err(e) => return (out, Some(e)),
                    }
                }
                assert!(took > 0 || any || d.buffered() < d.capacity(), "a full decoder read nothing");
            }
        }
        (out, None)
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&sha1(&[b'a'; 1_000_000])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        // Lengths around the padding boundary.
        assert_eq!(hex(&sha1(&[b'a'; 55])), "c1c8bbdc22796e28c0e15163d20899b65621d65a");
        assert_eq!(hex(&sha1(&[b'a'; 56])), "c2db330f6083854c99d4b5bfb6e8f29f201be699");
        assert_eq!(hex(&sha1(&[b'a'; 64])), "0098ba824b5c16427bd7a1122a5a442a25ec644d");
    }

    #[test]
    fn base64_vectors() {
        // RFC 4648 section 10.
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, coded) in cases {
            assert_eq!(base64_encode(plain.as_bytes()), coded);
            assert_eq!(base64_decode(coded).as_deref(), Some(plain.as_bytes()));
        }
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
        for bad in ["Zg", "Zg=", "Zh==", "Zm9=", "Zg==Zg==", "Z===", "====", "Zm9v\n", "Zm 9", "A=B="] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn accept_key_example() {
        // RFC 6455 section 1.3.
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        // Section 4.2.1's key.
        assert_eq!(key_from_bytes(*b"the sample nonce"), "dGhlIHNhbXBsZSBub25jZQ==");
    }

    #[test]
    fn handshake_request_example() {
        let u = check_request(&rfc_request()).unwrap();
        assert_eq!(u.key, "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(u.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(u.protocols, ["chat", "superchat"]);
        assert!(u.extensions.is_empty());
        assert_eq!(u.origin.as_deref(), Some("http://example.com"));
        let reply = u.response_headers(Some("chat"));
        assert_eq!(check_response(&reply, &u.key, &["chat", "superchat"]), Ok(Some("chat".to_string())));
        // A protocol the client did not offer is left out.
        let reply = u.response_headers(Some("other"));
        assert!(!reply.iter().any(|(n, _)| n == "Sec-WebSocket-Protocol"));
        assert_eq!(check_response(&reply, &u.key, &["chat"]), Ok(None));
    }

    #[test]
    fn handshake_is_lenient_where_http_is() {
        let h = vec![
            ("host", "x"),
            ("UPGRADE", "  WebSocket "),
            ("connection", "keep-alive, upgrade"),
            ("sec-websocket-key", " dGhlIHNhbXBsZSBub25jZQ== "),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Protocol", "a,, b"),
            ("Sec-WebSocket-Protocol", "c"),
            ("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits, x-foo; q=\"a\\b\""),
        ];
        let u = check_request(&h).unwrap();
        assert_eq!(u.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(u.protocols, ["a", "b", "c"]);
        assert_eq!(u.extensions, ["permessage-deflate", "x-foo"]);
        assert_eq!(u.origin, None);
    }

    #[test]
    fn handshake_request_errors() {
        assert_eq!(check_request(&without("Host")), Err(HandshakeError::MissingHost));
        assert_eq!(check_request(&without("Upgrade")), Err(HandshakeError::Upgrade));
        assert_eq!(check_request(&with("Upgrade", "h2c")), Err(HandshakeError::Upgrade));
        assert_eq!(check_request(&without("Connection")), Err(HandshakeError::Connection));
        assert_eq!(check_request(&with("Connection", "keep-alive")), Err(HandshakeError::Connection));
        assert_eq!(check_request(&without("Sec-WebSocket-Version")), Err(HandshakeError::MissingVersion));
        assert_eq!(check_request(&with("Sec-WebSocket-Version", "8")), Err(HandshakeError::Version));
        assert_eq!(check_request(&without("Sec-WebSocket-Key")), Err(HandshakeError::Key));
        assert_eq!(check_request(&with("Sec-WebSocket-Key", "not base64!")), Err(HandshakeError::Key));
        // Fifteen bytes, then seventeen.
        assert_eq!(check_request(&with("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAA")), Err(HandshakeError::Key));
        assert_eq!(check_request(&with("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAAA=")), Err(HandshakeError::Key));
        let mut twice = rfc_request();
        twice.push(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(check_request(&twice), Err(HandshakeError::Key));
        assert_eq!(check_request(&with("Sec-WebSocket-Protocol", "a b")), Err(HandshakeError::Protocol));
        let many = vec!["p"; MAX_PROTOCOLS + 1].join(",");
        let mut h: Vec<(&str, &str)> = without("Sec-WebSocket-Protocol");
        h.push(("Sec-WebSocket-Protocol", &many));
        assert_eq!(check_request(&h), Err(HandshakeError::Protocol));
        assert_eq!(check_request(&with("Sec-WebSocket-Extensions", "a/b")), Err(HandshakeError::Extension));
        assert_eq!(check_request(&with("Sec-WebSocket-Extensions", "; x=1")), Err(HandshakeError::Extension));
        let many = vec!["e"; MAX_EXTENSIONS + 1].join(",");
        let mut h: Vec<(&str, &str)> = rfc_request();
        h.push(("Sec-WebSocket-Extensions", &many));
        assert_eq!(check_request(&h), Err(HandshakeError::Extension));
        let mut h = rfc_request();
        h.extend(std::iter::repeat_n(("X", "y"), MAX_HEADERS));
        assert_eq!(check_request(&h), Err(HandshakeError::TooManyHeaders));
        assert_eq!(check_response(&h, "k", &[]), Err(HandshakeError::TooManyHeaders));
    }

    #[test]
    fn subprotocols_offered_must_be_unique() {
        // Section 4.1: the protocol names a client offers "MUST all be
        // unique strings".
        assert_eq!(check_request(&with("Sec-WebSocket-Protocol", "chat, chat")), Err(HandshakeError::Protocol));
        let mut h = rfc_request();
        h.push(("Sec-WebSocket-Protocol", "chat"));
        assert_eq!(check_request(&h), Err(HandshakeError::Protocol));
        // Names differing in case are different strings.
        assert!(check_request(&with("Sec-WebSocket-Protocol", "chat, Chat")).is_ok());
        // The writer offers each name once.
        let h = request_headers("example.com", [1; KEY_LEN], &["a", "b", "a"]).unwrap();
        assert_eq!(check_request(&h).unwrap().protocols, ["a", "b"]);
    }

    #[test]
    fn response_upgrade_must_be_websocket_alone() {
        // Section 4.1: the client fails the connection if the response's
        // Upgrade field holds a value other than "websocket".
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        for upgrade in ["websocket, h2c", "h2c, websocket", "websocket, websocket"] {
            let h = [
                ("Upgrade", upgrade),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ];
            assert_eq!(check_response(&h, key, &[]), Err(HandshakeError::Upgrade), "{upgrade}");
        }
        let h = [
            ("Upgrade", " WebSocket"),
            ("Connection", "upgrade"),
            ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ];
        assert_eq!(check_response(&h, key, &[]), Ok(None));
        // A request may still list other protocols beside websocket.
        assert!(check_request(&with("Upgrade", "h2c, websocket")).is_ok());
    }

    #[test]
    fn host_must_be_present_once_and_not_empty() {
        // Section 4.1: the Host field's value holds the host, and HTTP
        // allows one Host field per request.
        assert_eq!(check_request(&with("Host", "")), Err(HandshakeError::MissingHost));
        assert_eq!(check_request(&with("Host", "   ")), Err(HandshakeError::MissingHost));
        let mut h = rfc_request();
        h.push(("Host", "other.example.com"));
        assert_eq!(check_request(&h), Err(HandshakeError::MissingHost));
    }

    #[test]
    fn field_names_are_not_trimmed() {
        // HTTP allows no whitespace in or around a field name, so "Host "
        // is not the Host field.
        let mut h = without("Host");
        h.push(("Host ", "server.example.com"));
        assert_eq!(check_request(&h), Err(HandshakeError::MissingHost));
        let mut h = without("Sec-WebSocket-Key");
        h.push((" Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(check_request(&h), Err(HandshakeError::Key));
    }

    #[test]
    fn handshake_response_errors() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let good = [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        ];
        assert_eq!(check_response(&good, key, &[]), Ok(None));
        assert_eq!(check_response(&good, "AAAAAAAAAAAAAAAAAAAAAA==", &[]), Err(HandshakeError::Accept));
        assert_eq!(check_response(&good[..2], key, &[]), Err(HandshakeError::Accept));
        assert_eq!(check_response(&good[1..], key, &[]), Err(HandshakeError::Upgrade));
        assert_eq!(check_response(&[good[0], good[2]], key, &[]), Err(HandshakeError::Connection));
        let mut h = good.to_vec();
        h.push(("Sec-WebSocket-Extensions", "permessage-deflate"));
        assert_eq!(check_response(&h, key, &[]), Err(HandshakeError::Extension));
        let mut h = good.to_vec();
        h.push(("Sec-WebSocket-Protocol", "chat"));
        assert_eq!(check_response(&h, key, &["superchat"]), Err(HandshakeError::Protocol));
        assert_eq!(check_response(&h, key, &["chat"]), Ok(Some("chat".to_string())));
        h.push(("Sec-WebSocket-Protocol", "chat"));
        assert_eq!(check_response(&h, key, &["chat"]), Err(HandshakeError::Protocol));
    }

    #[test]
    fn request_headers_round_trip() {
        // A host the request could not carry is refused, not cleaned up.
        for bad in ["example.com\r\nX-Evil: 1", "", " example.com", "a/b"] {
            assert_eq!(request_headers(bad, [0; KEY_LEN], &[]), Err(HandshakeError::MissingHost), "{bad:?}");
        }
        let h = request_headers("example.com:8080", *b"the sample nonce", &["chat", "bad token", "v2"]).unwrap();
        assert_eq!(h[0].1, "example.com:8080");
        let u = check_request(&h).unwrap();
        assert_eq!(u.key, "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(u.protocols, ["chat", "v2"]);
        let reply = u.response_headers(Some("v2"));
        assert_eq!(check_response(&reply, &u.key, &["chat", "v2"]), Ok(Some("v2".to_string())));
        let h = request_headers("[::1]:80", [0; KEY_LEN], &[]).unwrap();
        assert!(check_request(&h).unwrap().protocols.is_empty());
    }

    #[test]
    fn rfc_frame_examples() {
        let (f, used) = Frame::parse(&HELLO).unwrap().unwrap();
        assert_eq!(used, 7);
        assert_eq!(f, Frame::new(Opcode::Text, b"Hello".to_vec()));
        assert_eq!(f.to_bytes(), HELLO);
        let (f, _) = Frame::parse(&HELLO_MASKED).unwrap().unwrap();
        assert_eq!(f.payload, b"Hello");
        assert_eq!(f.mask, Some([0x37, 0xfa, 0x21, 0x3d]));
        assert_eq!(f.to_bytes(), HELLO_MASKED);
        let (f, _) = Frame::parse(&HEL).unwrap().unwrap();
        assert_eq!((f.fin, f.opcode, &f.payload[..]), (false, Opcode::Text, &b"Hel"[..]));
        let (f, _) = Frame::parse(&LO).unwrap().unwrap();
        assert_eq!((f.fin, f.opcode, &f.payload[..]), (true, Opcode::Continuation, &b"lo"[..]));
        let (f, _) = Frame::parse(&PING).unwrap().unwrap();
        assert_eq!(f, Frame::new(Opcode::Ping, b"Hello".to_vec()));
        let (f, _) = Frame::parse(&PONG_MASKED).unwrap().unwrap();
        assert_eq!((f.opcode, &f.payload[..]), (Opcode::Pong, &b"Hello"[..]));
        // 256 bytes of binary data: the 16-bit form.
        let f = Frame::new(Opcode::Binary, vec![7; 256]);
        let bytes = f.to_bytes();
        assert_eq!(bytes[..4], [0x82, 0x7e, 0x01, 0x00]);
        assert_eq!(bytes.len(), 260);
        assert_eq!(Frame::parse(&bytes).unwrap().unwrap(), (f, 260));
        // 64 KiB: the 64-bit form.
        let f = Frame::new(Opcode::Binary, vec![7; 65536]);
        let bytes = f.to_bytes();
        assert_eq!(bytes[..10], [0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(Frame::parse(&bytes).unwrap().unwrap(), (f, 65546));
    }

    #[test]
    fn length_forms_are_minimal() {
        for (n, header) in [(0, 2), (125, 2), (126, 4), (65535, 4), (65536, 10)] {
            for mask in [None, Some([1, 2, 3, 4])] {
                let f = Frame { fin: true, opcode: Opcode::Binary, mask, payload: vec![0xa5; n] };
                let bytes = f.to_bytes();
                let extra = if mask.is_some() { 4 } else { 0 };
                assert_eq!(bytes.len(), header + extra + n);
                let h = Header::parse(&bytes).unwrap().unwrap();
                assert_eq!((h.len, h.header_len, h.frame_len()), (n, header + extra, bytes.len()));
                assert_eq!(Frame::parse(&bytes).unwrap().unwrap(), (f, bytes.len()));
            }
        }
        assert_eq!(Header::parse(&[0x82, 126, 0, 125]), Err(FrameError::NonMinimalLength));
        assert_eq!(Header::parse(&[0x82, 126, 0, 0]), Err(FrameError::NonMinimalLength));
        assert_eq!(Header::parse(&[0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff]), Err(FrameError::NonMinimalLength));
        assert_eq!(Header::parse(&[0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0]), Err(FrameError::LengthHighBit));
        assert_eq!(Header::parse(&[0x82, 127, 0, 0, 0, 0, 1, 0, 0, 1]), Err(FrameError::TooLarge((1 << 24) + 1)));
        assert!(Header::parse(&[0x82, 127, 0, 0, 0, 0, 1, 0, 0, 0]).unwrap().is_some());
    }

    #[test]
    fn frame_errors() {
        assert_eq!(Header::parse(&[0xc1]), Err(FrameError::ReservedBits(4)));
        assert_eq!(Header::parse(&[0x91]), Err(FrameError::ReservedBits(1)));
        for op in [3, 4, 5, 6, 7, 0xb, 0xc, 0xd, 0xe, 0xf] {
            assert_eq!(Header::parse(&[0x80 | op]), Err(FrameError::ReservedOpcode(op)));
            assert_eq!(Opcode::from_u8(op), None);
        }
        assert_eq!(Header::parse(&[0x09]), Err(FrameError::FragmentedControl));
        assert_eq!(Header::parse(&[0x88, 126]), Err(FrameError::ControlTooLong));
        assert_eq!(Header::parse(&[0x8a, 0xff]), Err(FrameError::ControlTooLong));
        assert!(Header::parse(&[0x89, 125]).unwrap().is_some());
        for e in [
            FrameError::ReservedBits(1),
            FrameError::ReservedOpcode(3),
            FrameError::FragmentedControl,
            FrameError::ControlTooLong,
            FrameError::NonMinimalLength,
            FrameError::LengthHighBit,
            FrameError::TooLarge(1),
        ] {
            assert!(!e.to_string().is_empty());
            assert!(!Error::Frame(e).to_string().is_empty());
        }
        for op in 0..16u8 {
            if let Some(o) = Opcode::from_u8(op) {
                assert_eq!(o.to_u8(), op);
            }
        }
    }

    #[test]
    fn truncated_frames_wait_for_more() {
        let long =
            Frame { fin: true, opcode: Opcode::Binary, mask: Some([9, 8, 7, 6]), payload: vec![1; 300] }.to_bytes();
        let longer = Frame::new(Opcode::Binary, vec![2; 70000]).to_bytes();
        let close = Message::Close(Some(Close { code: 1001, reason: "bye".into() })).to_bytes(Some([1, 2, 3, 4]));
        for valid in [&HELLO[..], &HELLO_MASKED, &HEL, &LO, &PING, &PONG_MASKED, &long, &close] {
            for n in 0..valid.len() {
                assert_eq!(Frame::parse(&valid[..n]), Ok(None), "{n} bytes of {valid:?}");
            }
        }
        for n in (0..longer.len()).step_by(997).chain([longer.len() - 1]) {
            assert_eq!(Frame::parse(&longer[..n]), Ok(None));
        }
        // The decoder too, for a masked stream.
        let stream: Vec<u8> = [&HELLO_MASKED[..], &long, &close].concat();
        for n in 0..stream.len() {
            let mut d = Decoder::new(Role::Server);
            feed(&mut d, &stream[..n]);
            while let Some(m) = d.next_message() {
                assert!(m.is_ok(), "{n} bytes");
            }
        }
    }

    #[test]
    fn decoder_joins_fragments_around_control_frames() {
        // Client side: section 5.7's fragmented "Hello" with a ping between.
        let stream: Vec<u8> = [&HEL[..], &PING, &LO, &HELLO].concat();
        let want = vec![Message::Ping(b"Hello".to_vec()), Message::Text("Hello".into()), Message::Text("Hello".into())];
        assert_eq!(decode(Role::Client, &stream), (want.clone(), None));
        assert_eq!(decode_bytewise(Role::Client, &stream), (want, None));
        // Server side.
        let stream: Vec<u8> = [&HELLO_MASKED[..], &PONG_MASKED].concat();
        let (got, err) = decode(Role::Server, &stream);
        assert_eq!(got, [Message::Text("Hello".into()), Message::Pong(b"Hello".to_vec())]);
        assert_eq!(err, None);
        // Empty frames and messages.
        let stream = [0x02, 0x00, 0x00, 0x00, 0x80, 0x00, 0x81, 0x00];
        let (got, _) = decode(Role::Client, &stream);
        assert_eq!(got, [Message::Binary(vec![]), Message::Text(String::new())]);
    }

    #[test]
    fn utf8_is_checked_across_fragments() {
        // "é" is c3 a9, split between two frames.
        let stream = [0x01, 0x01, 0xc3, 0x80, 0x01, 0xa9];
        assert_eq!(decode(Role::Client, &stream), (vec![Message::Text("é".into())], None));
        // Bad text in one frame.
        assert_eq!(decode(Role::Client, &[0x81, 0x02, 0xc3, 0x28]).1, Some(Error::InvalidUtf8));
        // A bad byte fails at once, before the last frame.
        let mut d = Decoder::new(Role::Client);
        feed(&mut d, &[0x01, 0x02, 0x61, 0xff]);
        assert_eq!(d.next_message(), Some(Err(Error::InvalidUtf8)));
        // A character cut off at the end of the message.
        assert_eq!(decode(Role::Client, &[0x01, 0x01, 0x61, 0x80, 0x01, 0xc3]).1, Some(Error::InvalidUtf8));
        // Binary messages are not checked.
        assert_eq!(decode(Role::Client, &[0x82, 0x01, 0xff]).0, [Message::Binary(vec![0xff])]);
        // Surrogates encoded in UTF-8 are invalid.
        assert_eq!(decode(Role::Client, &[0x81, 0x03, 0xed, 0xa0, 0x80]).1, Some(Error::InvalidUtf8));
    }

    #[test]
    fn decoder_errors() {
        assert_eq!(decode(Role::Server, &HELLO).1, Some(Error::Unmasked));
        assert_eq!(decode(Role::Client, &HELLO_MASKED).1, Some(Error::Masked));
        assert_eq!(decode(Role::Client, &LO).1, Some(Error::UnexpectedContinuation));
        assert_eq!(decode(Role::Client, &[&HEL[..], &HELLO].concat()).1, Some(Error::ExpectedContinuation));
        assert_eq!(decode(Role::Client, &[0xc1, 0]).1, Some(Error::Frame(FrameError::ReservedBits(4))));
        assert_eq!(decode(Role::Client, &[0x88, 0x01, 0x03]).1, Some(Error::Close(CloseError::Short)));
        assert_eq!(decode(Role::Client, &[0x88, 0x02, 0x03, 0xed]).1, Some(Error::Close(CloseError::Code(1005))));
        assert_eq!(decode(Role::Client, &[0x88, 0x03, 0x03, 0xe8, 0xff]).1, Some(Error::Close(CloseError::Utf8)));
        // A broken stream stays broken and holds nothing.
        let mut d = Decoder::new(Role::Server);
        feed(&mut d, &HELLO);
        assert_eq!(d.next_message(), Some(Err(Error::Unmasked)));
        feed(&mut d, &HELLO_MASKED);
        assert_eq!(d.next_message(), Some(Err(Error::Unmasked)));
        assert_eq!(d.buffered(), 0);
        // Close codes for each error.
        assert_eq!(Error::InvalidUtf8.close_code(), 1007);
        assert_eq!(Error::Close(CloseError::Utf8).close_code(), 1007);
        assert_eq!(Error::TooBig.close_code(), 1009);
        assert_eq!(Error::Frame(FrameError::TooLarge(1 << 30)).close_code(), 1009);
        for e in [
            Error::Unmasked,
            Error::Masked,
            Error::UnexpectedContinuation,
            Error::ExpectedContinuation,
            Error::Frame(FrameError::NonMinimalLength),
            Error::Close(CloseError::Short),
        ] {
            assert_eq!(e.close_code(), 1002);
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn decoder_bounds_message_size() {
        // A frame over the limit is refused from its header alone.
        let mut d = Decoder::with_max_message(Role::Client, 10);
        feed(&mut d, &[0x82, 11]);
        assert_eq!(d.next_message(), Some(Err(Error::TooBig)));
        // Fragments that add up to more than the limit.
        let mut d = Decoder::with_max_message(Role::Client, 10);
        feed(&mut d, &[0x02, 6, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d.next_message(), None);
        feed(&mut d, &[0x80, 5]);
        assert_eq!(d.next_message(), Some(Err(Error::TooBig)));
        // Exactly the limit is fine, and control frames do not count.
        let mut d = Decoder::with_max_message(Role::Client, 3);
        feed(&mut d, &[0x02, 2, 1, 2, 0x89, 5, 1, 2, 3, 4, 5, 0x80, 1, 3]);
        assert_eq!(d.next_message(), Some(Ok(Message::Ping(vec![1, 2, 3, 4, 5]))));
        assert_eq!(d.next_message(), Some(Ok(Message::Binary(vec![1, 2, 3]))));
        // The limit is clamped.
        let d = Decoder::with_max_message(Role::Client, usize::MAX);
        assert_eq!(d.max_message(), MAX_MESSAGE);
    }

    #[test]
    fn decoder_reads_many_frames_from_one_feed_in_linear_time() {
        // Two-byte pongs, two million of them, fed at once. Removing each
        // frame from the front of the buffer would move the rest every
        // time, about 4 * 10^12 bytes in all.
        let n = 1 << 21;
        let stream: Vec<u8> = [0x8a, 0x00].repeat(n);
        let start = std::time::Instant::now();
        let mut d = Decoder::new(Role::Client);
        feed(&mut d, &stream);
        let mut count = 0;
        while let Some(m) = d.next_message() {
            assert_eq!(m, Ok(Message::Pong(vec![])));
            count += 1;
        }
        assert_eq!(count, n);
        assert_eq!(d.buffered(), 0);
        assert!(start.elapsed() < std::time::Duration::from_secs(10), "{:?}", start.elapsed());
        // Feeding after some frames are taken out keeps the order.
        let mut d = Decoder::new(Role::Client);
        feed(&mut d, &[&PING[..], &HEL, &PING].concat());
        assert_eq!(d.next_message(), Some(Ok(Message::Ping(b"Hello".to_vec()))));
        assert_eq!(d.buffered(), HEL.len() + PING.len());
        feed(&mut d, &LO[..1]);
        assert_eq!(d.next_message(), Some(Ok(Message::Ping(b"Hello".to_vec()))));
        assert_eq!(d.buffered(), 1);
        assert_eq!(d.next_message(), None);
        feed(&mut d, &LO[1..]);
        assert_eq!(d.next_message(), Some(Ok(Message::Text("Hello".into()))));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_has_accessors_and_clones() {
        let mut d = Decoder::with_max_message(Role::Server, 100);
        assert_eq!((d.role(), d.max_message(), d.error()), (Role::Server, 100, None));
        feed(&mut d, &HELLO_MASKED[..4]);
        // A copy picks up where the original stands.
        let mut copy = d.clone();
        feed(&mut d, &HELLO_MASKED[4..]);
        feed(&mut copy, &HELLO_MASKED[4..]);
        assert_eq!(d.next_message(), copy.next_message());
        feed(&mut d, &HELLO);
        assert_eq!(d.next_message(), Some(Err(Error::Unmasked)));
        assert_eq!(d.error(), Some(Error::Unmasked));
        assert_eq!(copy.error(), None);
    }

    #[test]
    fn frame_len_of_a_hand_built_header_never_overflows() {
        // Header's fields are public, so a world can build one with any
        // length.
        let h = Header { fin: true, opcode: Opcode::Binary, mask: None, len: usize::MAX, header_len: 2 };
        assert_eq!(h.frame_len(), usize::MAX);
    }

    #[test]
    fn version_errors_tell_400_from_426() {
        // Section 4.2.2: a version the server does not speak gets 426 with
        // Sec-WebSocket-Version: 13. Section 4.2.1: a request without the
        // field, or with it twice, is malformed and gets 400.
        assert_eq!(check_request(&with("Sec-WebSocket-Version", "8")), Err(HandshakeError::Version));
        assert_eq!(HandshakeError::Version.status_code(), 426);
        assert_eq!(check_request(&without("Sec-WebSocket-Version")), Err(HandshakeError::MissingVersion));
        let mut twice = rfc_request();
        twice.push(("Sec-WebSocket-Version", "13"));
        assert_eq!(check_request(&twice), Err(HandshakeError::MissingVersion));
        for e in [
            HandshakeError::TooManyHeaders,
            HandshakeError::MissingHost,
            HandshakeError::Origin,
            HandshakeError::Upgrade,
            HandshakeError::Connection,
            HandshakeError::MissingVersion,
            HandshakeError::Key,
            HandshakeError::Protocol,
            HandshakeError::Extension,
        ] {
            assert_eq!(e.status_code(), 400, "{e:?}");
        }
    }

    #[test]
    fn decoder_stops_after_close() {
        let mut d = Decoder::new(Role::Client);
        feed(&mut d, &[0x88, 0x02, 0x03, 0xe8]);
        feed(&mut d, &HELLO);
        assert_eq!(d.next_message(), Some(Ok(Message::Close(Some(Close::new(1000))))));
        assert!(d.is_closed());
        assert_eq!(d.next_message(), None);
        feed(&mut d, &HELLO);
        assert_eq!(d.next_message(), None);
        assert_eq!(d.buffered(), 0);
        assert_eq!(decode(Role::Client, &[0x88, 0x00]).0, [Message::Close(None)]);
    }

    #[test]
    fn close_payloads() {
        // Section 7.4.1: 1000 with a reason.
        let p = [0x03, 0xe8, b'b', b'y', b'e'];
        let c = Close::parse(&p).unwrap().unwrap();
        assert_eq!(c, Close { code: 1000, reason: "bye".into() });
        assert_eq!(c.to_payload(), p);
        assert_eq!(Close::parse(&[]), Ok(None));
        assert_eq!(Close::parse(&[3]), Err(CloseError::Short));
        assert_eq!(Close::parse(&[0x03, 0xe8, 0xc3]), Err(CloseError::Utf8));
        assert_eq!(Close::parse(&[0x03; 126]), Err(CloseError::TooLong));
        for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535] {
            assert!(!close_code::is_sendable(code));
            assert_eq!(Close::parse(&code.to_be_bytes()), Err(CloseError::Code(code)));
            // Writers replace it with 1000.
            assert_eq!(Close::new(code).to_payload(), [0x03, 0xe8]);
        }
        for code in [1000u16, 1001, 1002, 1003, 1007, 1011, 1012, 1014, 3000, 4999] {
            assert_eq!(Close::parse(&code.to_be_bytes()), Ok(Some(Close::new(code))));
        }
        // A long reason is cut at a character boundary.
        let c = Close { code: 4000, reason: "é".repeat(100) };
        let p = c.to_payload();
        assert_eq!(p.len(), 2 + 122);
        assert_eq!(Close::parse(&p).unwrap().unwrap().reason, "é".repeat(61));
        for e in [CloseError::Short, CloseError::TooLong, CloseError::Code(1), CloseError::Utf8] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_clamp_what_they_write() {
        // Control frames: always final, at most 125 bytes.
        let f = Frame { fin: false, opcode: Opcode::Ping, mask: None, payload: vec![1; 300] };
        let (back, _) = Frame::parse(&f.to_bytes()).unwrap().unwrap();
        assert!(back.fin);
        assert_eq!(back.payload.len(), MAX_CONTROL_PAYLOAD);
        let m = Message::Pong(vec![2; 200]).to_bytes(Some([1, 1, 1, 1]));
        assert_eq!(decode(Role::Server, &m).0, [Message::Pong(vec![2; 125])]);
        // Data frames: at most MAX_PAYLOAD bytes.
        let f = Frame::new(Opcode::Binary, vec![0; MAX_PAYLOAD + 5]);
        let bytes = f.to_bytes();
        assert_eq!(bytes.len(), 10 + MAX_PAYLOAD);
        assert_eq!(Frame::parse(&bytes).unwrap().unwrap().0.payload.len(), MAX_PAYLOAD);
        // Text is cut at a character boundary.
        let mut s = "a".repeat(MAX_MESSAGE - 1);
        s.push('é');
        let (got, err) = decode(Role::Client, &Message::Text(s).to_bytes(None));
        assert_eq!(err, None);
        let Message::Text(t) = &got[0] else { panic!() };
        assert_eq!(t.len(), MAX_MESSAGE - 1);
        // Fragment sizes are clamped to at least 1.
        let frames = Message::Binary(vec![1, 2, 3]).to_frames(0, None);
        assert_eq!(frames.len(), 3);
        assert_eq!(Message::Close(Some(Close::new(1006))).to_frames(1, None)[0].payload, [0x03, 0xe8]);
    }

    #[test]
    fn messages_round_trip_through_fragments() {
        let messages = [
            Message::Text("Grüße, мир! 😀".into()),
            Message::Binary((0..=255).collect()),
            Message::Text(String::new()),
            Message::Binary(vec![]),
            Message::Ping(b"are you there".to_vec()),
            Message::Pong(vec![]),
            Message::Close(Some(Close { code: 4001, reason: "done".into() })),
        ];
        for size in [1, 2, 3, 7, 1000] {
            let mut stream = Vec::new();
            for m in &messages {
                let frames = m.to_frames(size, Some([0xde, 0xad, 0xbe, 0xef]));
                assert!(m.opcode().is_control() || frames.iter().all(|f| f.payload.len() <= size));
                assert!(frames.last().unwrap().fin);
                for f in frames {
                    stream.extend(f.to_bytes());
                }
            }
            assert_eq!(decode(Role::Server, &stream), (messages.to_vec(), None));
            assert_eq!(decode_bytewise(Role::Server, &stream), (messages.to_vec(), None));
        }
        assert_eq!(Message::Text("x".into()).opcode(), Opcode::Text);
        assert_eq!(Message::Close(None).opcode(), Opcode::Close);
    }

    #[test]
    fn masking() {
        let mut d = *b"Hello";
        apply_mask(&mut d, [0x37, 0xfa, 0x21, 0x3d], 0);
        assert_eq!(d, HELLO_MASKED[6..]);
        // In two pieces, with an offset.
        let mut d = *b"Hello";
        let (a, b) = d.split_at_mut(3);
        apply_mask(a, [0x37, 0xfa, 0x21, 0x3d], 0);
        apply_mask(b, [0x37, 0xfa, 0x21, 0x3d], 3);
        assert_eq!(d, HELLO_MASKED[6..]);
        apply_mask(&mut d, [0x37, 0xfa, 0x21, 0x3d], usize::MAX - 3);
        assert_eq!(&d, b"Hello");
        assert!(Opcode::Close.is_control() && !Opcode::Continuation.is_control());
        for e in [
            HandshakeError::TooManyHeaders,
            HandshakeError::MissingHost,
            HandshakeError::Origin,
            HandshakeError::Upgrade,
            HandshakeError::Connection,
            HandshakeError::Version,
            HandshakeError::FieldTooLong,
            HandshakeError::MissingVersion,
            HandshakeError::Key,
            HandshakeError::Accept,
            HandshakeError::Protocol,
            HandshakeError::Extension,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
        fn message(&mut self) -> Message {
            const CHARS: [char; 6] = ['a', 'Z', ' ', 'é', '€', '😀'];
            let n = if self.below(20) == 0 { 126 + self.below(200) } else { self.below(30) };
            match self.below(5) {
                0 => Message::Text((0..n).map(|_| CHARS[self.below(CHARS.len())]).collect()),
                1 => Message::Binary(self.bytes(n)),
                2 => Message::Ping(self.bytes(n.min(125))),
                3 => Message::Pong(self.bytes(n.min(125))),
                _ => {
                    let codes = [1000, 1001, 1011, 3000, 4999];
                    let reason = (0..n.min(40)).map(|_| CHARS[self.below(CHARS.len())]).collect();
                    Message::Close(Some(Close { code: codes[self.below(codes.len())], reason }))
                }
            }
        }
    }

    /// What the fuzz target checks, for one buffer.
    fn check_buffer(data: &[u8]) {
        for role in [Role::Server, Role::Client] {
            let whole = decode(role, data);
            assert_eq!(whole, decode_bytewise(role, data));
            assert_eq!(whole, decode_chunked(role, data, &[3, 1, 7, 2, 64]));
            let mask = if role == Role::Server { Some([5, 6, 7, 8]) } else { None };
            for m in &whole.0 {
                assert_eq!(decode(role, &m.to_bytes(mask)), (vec![m.clone()], None));
            }
        }
        let mut rest = data;
        while let Ok(Some((f, used))) = Frame::parse(rest) {
            let bytes = f.to_bytes();
            assert_eq!(bytes, rest[..used]);
            assert_eq!(Frame::parse(&bytes), Ok(Some((f, used))));
            rest = &rest[used..];
        }
        if let Ok(Some(c)) = Close::parse(data) {
            assert_eq!(c.to_payload(), data);
        }
        let _ = Header::parse(data);
    }

    #[test]
    fn random_buffers_never_panic() {
        let mut rng = Lcg(0x5eed_1234);
        for round in 0..4000 {
            let data = match round % 3 {
                0 => {
                    let n = rng.below(48);
                    rng.bytes(n)
                }
                _ => {
                    // A valid stream with a few bytes changed.
                    let masked = round % 2 == 0;
                    let mut data = Vec::new();
                    let mut sent = Vec::new();
                    for _ in 0..1 + rng.below(4) {
                        let m = rng.message();
                        let mask = masked.then(|| [rng.next() as u8, 3, 1, 4]);
                        for f in m.to_frames(1 + rng.below(40), mask) {
                            data.extend(f.to_bytes());
                        }
                        sent.push(m);
                    }
                    let role = if masked { Role::Server } else { Role::Client };
                    let ends = sent.iter().position(|m| matches!(m, Message::Close(_))).map_or(sent.len(), |i| i + 1);
                    let want = (sent[..ends].to_vec(), None);
                    assert_eq!(decode(role, &data), want);
                    // The same stream a byte at a time, and in random pieces.
                    assert_eq!(decode_bytewise(role, &data), want);
                    let sizes: Vec<usize> = (0..1 + rng.below(5)).map(|_| 1 + rng.below(50)).collect();
                    assert_eq!(decode_chunked(role, &data, &sizes), want);
                    for _ in 0..rng.below(4) {
                        if !data.is_empty() {
                            let i = rng.below(data.len());
                            data[i] = rng.next() as u8;
                        }
                    }
                    data
                }
            };
            check_buffer(&data);
        }
    }

    #[test]
    fn random_headers_never_panic() {
        let mut rng = Lcg(42);
        let names = [
            "Host",
            "Upgrade",
            "Connection",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Extensions",
            "Sec-WebSocket-Accept",
            "Origin",
        ];
        let values = [
            "websocket",
            "Upgrade",
            "13",
            "dGhlIHNhbXBsZSBub25jZQ==",
            "a, b",
            "\"x,y\"",
            "",
            "  ",
            "é",
            "a;b=\"c\\\"",
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        ];
        for _ in 0..3000 {
            let mut h: Vec<(&str, &str)> = rfc_request();
            for _ in 0..rng.below(6) {
                let i = rng.below(h.len());
                if rng.below(2) == 0 {
                    h.remove(i);
                } else {
                    h.push((names[rng.below(names.len())], values[rng.below(values.len())]));
                }
                if h.is_empty() {
                    break;
                }
            }
            if let Ok(u) = check_request(&h) {
                assert_eq!(u.accept, accept_key(&u.key));
                let pick = u.protocols.first().map(String::as_str);
                let offered: Vec<&str> = u.protocols.iter().map(String::as_str).collect();
                assert_eq!(check_response(&u.response_headers(pick), &u.key, &offered), Ok(pick.map(str::to_string)));
            }
            let _ = check_response(&h, "dGhlIHNhbXBsZSBub25jZQ==", &["chat"]);
        }
    }

    #[test]
    fn review_feed_is_bounded() {
        // One large feed with a tiny limit holds at most one control frame.
        let mut d = Decoder::with_max_message(Role::Client, 1);
        let _ = d.feed(&vec![0x82; 1 << 20]);
        assert!(d.buffered() <= MAX_HEADER_LEN + MAX_CONTROL_PAYLOAD, "{}", d.buffered());
        // Repeated feeds without taking messages out stop growing.
        let mut d = Decoder::new(Role::Client);
        let chunk = [0x8a, 0x00].repeat(1 << 22);
        for _ in 0..3 {
            let _ = d.feed(&chunk);
        }
        assert!(d.buffered() <= MAX_HEADER_LEN + MAX_PAYLOAD, "{}", d.buffered());
    }

    #[test]
    fn review_field_values_are_bounded() {
        let commas = format!("Upgrade{}", ",".repeat(1 << 20));
        let key = "A".repeat(1 << 20);
        let origin = "o".repeat(MAX_FIELD_LEN + 1);
        for (name, value) in [("Connection", &commas), ("Sec-WebSocket-Key", &key), ("Origin", &origin)] {
            let mut h = without(name);
            h.push((name, value));
            assert_eq!(check_request(&h), Err(HandshakeError::FieldTooLong), "{name}");
            assert_eq!(check_response(&h, "k", &[]), Err(HandshakeError::FieldTooLong), "{name}");
        }
        assert_eq!(HandshakeError::FieldTooLong.status_code(), 431);
        // Exactly the limit is read, and fields the check does not read
        // may be longer.
        let origin = "o".repeat(MAX_FIELD_LEN);
        let cookie = "c".repeat(4 * MAX_FIELD_LEN);
        let mut h = with("Origin", &origin);
        h.push(("Cookie", &cookie));
        assert_eq!(check_request(&h).unwrap().origin.as_deref(), Some(&origin[..]));
        // A key of the wrong length is refused before it is decoded.
        assert_eq!(check_request(&with("Sec-WebSocket-Key", &key[..MAX_FIELD_LEN])), Err(HandshakeError::Key));
        // The writer keeps its protocol list under the limit.
        let long = "p".repeat(MAX_FIELD_LEN / 3);
        let names: Vec<String> = (0..4).map(|i| format!("{long}{i}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let h = request_headers("example.com", [2; KEY_LEN], &names).unwrap();
        assert_eq!(check_request(&h).unwrap().protocols.len(), 2);
    }

    #[test]
    fn review_extension_grammar() {
        for bad in [
            "permessage-deflate; =bad",
            "permessage-deflate;",
            "permessage-deflate; a=\"b",
            "x-foo; q=\"a,b\"",
            "x; a=b=c",
            "x; a=\"b c\"",
            "x; a=\"\"",
            "",
            ",",
            " , ,",
        ] {
            assert_eq!(check_request(&with("Sec-WebSocket-Extensions", bad)), Err(HandshakeError::Extension), "{bad:?}");
        }
        for good in ["x; a", "x;a=b", "x ; a = b", "x; a=\"b\"", "x; a=\"\\b\"", "a, b; c=1,, d"] {
            assert!(check_request(&with("Sec-WebSocket-Extensions", good)).is_ok(), "{good:?}");
        }
        for bad in ["", ",", " , "] {
            assert_eq!(check_request(&with("Sec-WebSocket-Protocol", bad)), Err(HandshakeError::Protocol), "{bad:?}");
        }
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let h = [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ("Sec-WebSocket-Extensions", ""),
        ];
        assert_eq!(check_response(&h, key, &[]), Err(HandshakeError::Extension));
    }

    #[test]
    fn review_host_is_an_authority() {
        for bad in [
            "example.com/path",
            "example.com:abc",
            "a b",
            "example.comX-Evil: 1",
            "[::1",
            "[zz]",
            "[::1]x",
            "user@example.com",
            "%4",
            "a:1:2",
        ] {
            assert_eq!(check_request(&with("Host", bad)), Err(HandshakeError::MissingHost), "{bad:?}");
        }
        for good in ["example.com", "example.com:8080", "example.com:", "[::1]:443", "[::1]", "127.0.0.1", "%41b", "[v1.x:y]", "a-b_c~d!$&'()*+,;="] {
            assert!(check_request(&with("Host", good)).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn review_response_writer_ignores_bad_public_fields() {
        let mut u = check_request(&rfc_request()).unwrap();
        u.accept.clear();
        assert_eq!(check_response(&u.response_headers(None), &u.key, &[]), Ok(None));
        u.protocols.push("a\r\nb".to_string());
        let reply = u.response_headers(Some("a\r\nb"));
        assert!(!reply.iter().any(|(n, _)| n == "Sec-WebSocket-Protocol"));
    }

    #[test]
    fn review_origin_appears_once() {
        let mut h = rfc_request();
        h.push(("Origin", "https://other.example"));
        assert_eq!(check_request(&h), Err(HandshakeError::Origin));
        assert_eq!(HandshakeError::Origin.status_code(), 400);
    }

    #[test]
    fn review_split_messages_get_a_key_per_frame() {
        let m = Message::Text("abcdé".into());
        let mut n = 0u8;
        let frames = m.to_masked_frames(2, || {
            n += 1;
            [n, n, n, n]
        });
        assert_eq!(frames.len(), 3);
        let keys: Vec<_> = frames.iter().map(|f| f.mask).collect();
        assert_eq!(keys, [Some([1; 4]), Some([2; 4]), Some([3; 4])]);
        let stream: Vec<u8> = frames.iter().flat_map(Frame::to_bytes).collect();
        assert_eq!(decode(Role::Server, &stream), (vec![m], None));
        let close = Message::Close(None).to_masked_frames(1, || [9; 4]);
        assert_eq!(close, [Frame { fin: true, opcode: Opcode::Close, mask: Some([9; 4]), payload: vec![] }]);
    }

    #[test]
    fn review_feed_takes_what_fits_and_loops_end() {
        let mut d = Decoder::with_max_message(Role::Client, 3);
        assert_eq!(d.capacity(), MAX_HEADER_LEN + MAX_CONTROL_PAYLOAD);
        let stream = [0x8a, 0x00].repeat(200);
        let took = d.feed(&stream);
        assert_eq!(took, d.capacity());
        assert_eq!(d.feed(&stream[took..]), 0);
        assert_eq!(d.next_message(), Some(Ok(Message::Pong(vec![]))));
        assert_eq!(d.feed(&stream[took..]), 2);
        // A frame over the limit fails from its header, so a full decoder
        // never waits for more.
        let mut d = Decoder::with_max_message(Role::Client, 3);
        let big = [&[0x82, 126, 0x01, 0x00][..], &[0; 256]].concat();
        let took = d.feed(&big);
        assert_eq!(took, d.capacity());
        assert_eq!(d.next_message(), Some(Err(Error::TooBig)));
        assert_eq!(d.feed(&big[took..]), big.len() - took);
        assert_eq!(d.buffered(), 0);
        // After a close, bytes are taken and dropped.
        let mut d = Decoder::new(Role::Client);
        feed(&mut d, &[0x88, 0x00]);
        assert_eq!(d.next_message(), Some(Ok(Message::Close(None))));
        assert_eq!(d.feed(&stream), stream.len());
        assert_eq!(d.buffered(), 0);
    }
}
