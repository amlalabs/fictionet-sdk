//! The SSH transport layer before encryption: reading and writing the
//! version exchange, binary packets and the first messages, with no I/O.
//!
//! SSH runs over TCP, usually on port 22. Each side first sends a line that
//! names its protocol version and software, such as
//! `SSH-2.0-OpenSSH_9.6`. A server may send other lines before it. After
//! that line, everything is a binary packet: a length, some padding and a
//! payload whose first byte says which message it is. The two sides then
//! trade KEXINIT messages to agree on algorithms, run a key exchange, and
//! send NEWKEYS. From then on the packets are encrypted. This module
//! follows RFC 4253 (the transport layer) and RFC 4251 (the data types).
//!
//! It covers what comes before encryption: the version line and the lines
//! before it, packet framing with the padding rules for the unencrypted
//! phase, the data types (byte, boolean, uint32, uint64, string, mpint and
//! name-list), and the messages DISCONNECT, IGNORE, UNIMPLEMENTED, DEBUG,
//! SERVICE_REQUEST, SERVICE_ACCEPT, KEXINIT and NEWKEYS. It does no
//! cryptography, so it cannot run a key exchange or read encrypted
//! packets. A world that needs to go further plays its part up to NEWKEYS
//! and then decides what to do, for example send DISCONNECT.
//!
//! Nothing here reads a socket. A world feeds the bytes it reads from a
//! TCP connection to a [`Decoder`], gets [`Event`]s back, reads each
//! packet's payload with [`Message::parse`], and writes its answers with
//! [`Identification::to_bytes`] and [`Message::to_packet`]. Which
//! algorithms the world offers, and what its software line says, is up to
//! world code.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. Every buffer is bounded by a named limit, such as
//! [`MAX_PACKET`] and [`MAX_BANNER_LINES`].
//!
//! ```
//! use fictionet::stdlib::ssh::{Decoder, Event, Identification, KexInit, Message, Packet};
//!
//! // The world plays a server, and sends its own line first.
//! let ours = Identification::new("2.0", "OpenSSH_9.6", None).unwrap();
//! assert_eq!(ours.to_bytes(), b"SSH-2.0-OpenSSH_9.6\r\n");
//!
//! // The client's line and its KEXINIT arrive in one read.
//! let theirs = KexInit {
//!     cookie: [7; 16],
//!     kex_algorithms: vec!["curve25519-sha256".to_string()],
//!     ..KexInit::default()
//! };
//! let mut bytes = b"SSH-2.0-paramiko_3.4.0\r\n".to_vec();
//! bytes.extend(Message::KexInit(theirs.clone()).to_packet());
//!
//! let mut decoder = Decoder::new();
//! decoder.feed(&bytes);
//! let Some(Ok(Event::Version(client))) = decoder.next_event() else { panic!() };
//! assert_eq!(client.software(), "paramiko_3.4.0");
//! let Some(Ok(Event::Packet { sequence: 0, packet })) = decoder.next_event() else { panic!() };
//! assert_eq!(Message::parse(&packet.payload), Ok(Message::KexInit(theirs.clone())));
//! assert!(decoder.next_event().is_none());
//!
//! // The key exchange is the client's first choice the server also has.
//! let server = ["ecdh-sha2-nistp256".to_string(), "curve25519-sha256".to_string()];
//! assert_eq!(KexInit::choose(&theirs.kex_algorithms, &server), Some("curve25519-sha256"));
//!
//! // Packets are padded to a multiple of 8 bytes.
//! assert_eq!(Packet::new(vec![21]).to_bytes().len(), 16);
//! ```

/// The TCP port SSH servers listen on.
pub const PORT: u16 = 22;
/// The longest version line, counting its CR LF.
pub const MAX_VERSION_LINE: usize = 255;
/// The longest line a server may send before its version line, counting
/// its line ending. RFC 4253 sets no limit, so this one is generous.
pub const MAX_BANNER_LINE: usize = 1024;
/// The most lines a [`Decoder`] reads before the version line.
pub const MAX_BANNER_LINES: usize = 1024;
/// The block size packets are padded to before encryption.
pub const BLOCK: usize = 8;
/// The fewest padding bytes a packet may carry.
pub const MIN_PADDING: u8 = 4;
/// The longest packet, counting its length field: RFC 4253 says every
/// implementation must handle this much.
pub const MAX_PACKET: usize = 35000;
/// The largest value of a packet's length field, which does not count
/// itself.
pub const MAX_PACKET_LENGTH: u32 = (MAX_PACKET - 4) as u32;
/// The longest payload a packet may carry.
pub const MAX_PAYLOAD: usize = 32768;
/// The shortest packet, counting its length field.
pub const MIN_PACKET: usize = 16;
/// The longest algorithm name, service name or language tag.
pub const MAX_NAME: usize = 64;
/// The longest name-list in a KEXINIT, in bytes.
pub const MAX_NAME_LIST: usize = 3072;
/// The longest text in a DISCONNECT or DEBUG message, in bytes.
pub const MAX_TEXT: usize = 8192;
/// The longest data an IGNORE message may carry: what is left of the
/// largest payload after the message number and the string length.
pub const MAX_DATA: usize = MAX_PAYLOAD - 5;

/// Message numbers this module reads and writes.
pub mod msg {
    #![allow(missing_docs)]
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
}

/// Why a byte stream is not SSH. After any of these the stream cannot be
/// read any further, and a real peer closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// A line ran past [`MAX_BANNER_LINE`] bytes, or a version line past
    /// [`MAX_VERSION_LINE`], without ending.
    LineTooLong,
    /// A line before the packets held a NUL byte.
    Nul,
    /// A line began with `SSH-` and was not a well-formed version line.
    BadVersion,
    /// More than [`MAX_BANNER_LINES`] lines came before the version line.
    TooManyLines,
    /// A packet's length field was below 12, above [`MAX_PACKET_LENGTH`],
    /// or did not make the packet a multiple of [`BLOCK`] bytes.
    PacketLength(u32),
    /// A packet's padding length was below [`MIN_PADDING`] or left no room
    /// for the padding-length byte itself.
    Padding(u8),
    /// A packet's payload was longer than [`MAX_PAYLOAD`].
    PayloadTooLong(u32),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::LineTooLong => f.write_str("line too long"),
            StreamError::Nul => f.write_str("NUL byte in a line"),
            StreamError::BadVersion => f.write_str("malformed SSH version line"),
            StreamError::TooManyLines => f.write_str("too many lines before the version line"),
            StreamError::PacketLength(n) => write!(f, "packet length {n} not allowed"),
            StreamError::Padding(n) => write!(f, "padding length {n} not allowed"),
            StreamError::PayloadTooLong(n) => write!(f, "payload of {n} bytes, over {MAX_PAYLOAD}"),
        }
    }
}

impl std::error::Error for StreamError {}

/// The version line: `SSH-protoversion-softwareversion`, then optionally
/// a space and comments. Both versions are printable US-ASCII with no
/// spaces or minus signs. RFC 4253 does not limit the comments, so they
/// may be any UTF-8 text without CR, LF or NUL. A value of this type
/// always fits in [`MAX_VERSION_LINE`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identification {
    proto: String,
    software: String,
    comments: Option<String>,
}

impl Identification {
    /// A version line, if the parts are allowed and fit in
    /// [`MAX_VERSION_LINE`] bytes. Otherwise it gives
    /// [`StreamError::BadVersion`] or [`StreamError::LineTooLong`].
    pub fn new(
        proto: &str,
        software: &str,
        comments: Option<&str>,
    ) -> Result<Identification, StreamError> {
        let id = Identification {
            proto: proto.to_string(),
            software: software.to_string(),
            comments: comments.map(str::to_string),
        };
        if !version_part(proto.as_bytes()) || !version_part(software.as_bytes()) {
            return Err(StreamError::BadVersion);
        }
        if let Some(c) = comments
            && c.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
        {
            return Err(StreamError::BadVersion);
        }
        if id.len() > MAX_VERSION_LINE {
            return Err(StreamError::LineTooLong);
        }
        Ok(id)
    }

    /// Reads a version line's text, without its line ending.
    fn parse(line: &[u8]) -> Result<Identification, StreamError> {
        let rest = line.strip_prefix(b"SSH-").ok_or(StreamError::BadVersion)?;
        let dash = rest
            .iter()
            .position(|&b| b == b'-')
            .ok_or(StreamError::BadVersion)?;
        let (proto, rest) = (&rest[..dash], &rest[dash + 1..]);
        let (software, comments) = match rest.iter().position(|&b| b == b' ') {
            Some(sp) => (&rest[..sp], Some(&rest[sp + 1..])),
            None => (rest, None),
        };
        let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| StreamError::BadVersion);
        let comments = match comments {
            Some(c) => Some(text(c)?),
            None => None,
        };
        Identification::new(&text(proto)?, &text(software)?, comments.as_deref())
    }

    /// The protocol version, such as `2.0`.
    pub fn proto(&self) -> &str {
        &self.proto
    }

    /// The software version, such as `OpenSSH_9.6`.
    pub fn software(&self) -> &str {
        &self.software
    }

    /// The comments after the software version, if there is a space.
    pub fn comments(&self) -> Option<&str> {
        self.comments.as_deref()
    }

    /// Whether the peer speaks SSH 2: protocol `2.0`, or `1.99`, which old
    /// servers send to say they speak both 1 and 2.
    pub fn is_v2(&self) -> bool {
        self.proto == "2.0" || self.proto == "1.99"
    }

    /// The line's bytes, ending in CR LF.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(b"SSH-");
        out.extend_from_slice(self.proto.as_bytes());
        out.push(b'-');
        out.extend_from_slice(self.software.as_bytes());
        if let Some(c) = &self.comments {
            out.push(b' ');
            out.extend_from_slice(c.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    fn len(&self) -> usize {
        let comments = self
            .comments
            .as_ref()
            .map_or(0, |c| c.len().saturating_add(1));
        (7 + self.proto.len())
            .saturating_add(self.software.len())
            .saturating_add(comments)
    }
}

/// Whether [`parse_line`] would still return `Ok(None)` for `b`, given
/// that its first `scanned` bytes hold no LF or NUL. Only the bytes after
/// those are looked at.
fn line_pending(b: &[u8], scanned: usize) -> bool {
    let limit = if b.starts_with(b"SSH-") {
        MAX_VERSION_LINE
    } else {
        MAX_BANNER_LINE
    };
    b.len() < limit
        && b.get(scanned..)
            .is_some_and(|new| !new.iter().any(|&c| c == b'\n' || c == 0))
}

/// Whether `b` may be a protocol or software version: not empty, and
/// printable US-ASCII with no space or minus sign.
fn version_part(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&c| (0x21..=0x7e).contains(&c) && c != b'-')
}

/// One line read before the packets start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// A line that does not begin with `SSH-`, without its line ending. A
    /// server may send these before its version line. A client may not,
    /// so a world playing a server can treat one as an error.
    Banner(Vec<u8>),
    /// The version line.
    Version(Identification),
}

/// Reads the line at the start of `b`. It returns `Ok(None)` if `b` holds
/// only part of one, and otherwise the line and how many bytes of `b` it
/// took. A line ends at LF. A CR before the LF is dropped, and a line
/// ending in LF alone is accepted, as RFC 4253 suggests for old software.
/// Errors are found as soon as the bytes that cause them arrive, so the
/// result does not depend on how the stream was split.
pub fn parse_line(b: &[u8]) -> Result<Option<(Line, usize)>, StreamError> {
    let limit = if b.starts_with(b"SSH-") {
        MAX_VERSION_LINE
    } else {
        MAX_BANNER_LINE
    };
    for (i, &c) in b.iter().enumerate() {
        let len = i + 1;
        if c == 0 {
            return Err(StreamError::Nul);
        }
        if c == b'\n' {
            let text = &b[..i];
            let text = text.strip_suffix(b"\r").unwrap_or(text);
            let line = if text.starts_with(b"SSH-") {
                Line::Version(Identification::parse(text)?)
            } else {
                Line::Banner(text.to_vec())
            };
            return Ok(Some((line, len)));
        }
        if len >= limit {
            return Err(StreamError::LineTooLong);
        }
    }
    Ok(None)
}

/// The bytes of a line a server sends before its version line, ending in
/// CR LF. It returns `None` if `text` begins with `SSH-`, holds a CR, LF
/// or NUL, or is too long for [`MAX_BANNER_LINE`].
pub fn banner_line(text: &str) -> Option<Vec<u8>> {
    if text.starts_with("SSH-")
        || text.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
        || text.len() + 2 > MAX_BANNER_LINE
    {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() + 2);
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\r\n");
    Some(out)
}

/// One binary packet, unencrypted and with no MAC: the payload and the
/// padding after it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Packet {
    /// The message: its number, then its fields.
    pub payload: Vec<u8>,
    /// The padding bytes. RFC 4253 asks for random ones. This module has
    /// no randomness, so a world that wants them supplies them.
    pub padding: Vec<u8>,
}

impl Packet {
    /// A packet carrying `payload`, with the least padding allowed, all
    /// zeros.
    pub fn new(payload: Vec<u8>) -> Packet {
        Packet {
            payload,
            padding: Vec::new(),
        }
    }

    /// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the packet and how many bytes
    /// of `b` it took. A bad length is known from the first 4 bytes, and a
    /// bad padding length from the fifth.
    pub fn parse(b: &[u8]) -> Result<Option<(Packet, usize)>, StreamError> {
        let Some(head) = b.get(..4) else {
            return Ok(None);
        };
        let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if length < (MIN_PACKET - 4) as u32
            || length > MAX_PACKET_LENGTH
            || !(length as usize + 4).is_multiple_of(BLOCK)
        {
            return Err(StreamError::PacketLength(length));
        }
        let Some(&pad) = b.get(4) else {
            return Ok(None);
        };
        if pad < MIN_PADDING || u32::from(pad) >= length {
            return Err(StreamError::Padding(pad));
        }
        let payload_len = length - 1 - u32::from(pad);
        if payload_len as usize > MAX_PAYLOAD {
            return Err(StreamError::PayloadTooLong(payload_len));
        }
        let end = 4 + length as usize;
        let Some(body) = b.get(5..end) else {
            return Ok(None);
        };
        let (payload, padding) = body.split_at(payload_len as usize);
        Ok(Some((
            Packet {
                payload: payload.to_vec(),
                padding: padding.to_vec(),
            },
            end,
        )))
    }

    /// The packet's bytes. A payload longer than [`MAX_PAYLOAD`] is cut to
    /// that length. The padding is this packet's padding, followed by
    /// zeros where more is needed: at least [`MIN_PADDING`] bytes, and
    /// enough to make the packet a multiple of [`BLOCK`]. Padding past 255
    /// bytes, or past what the block size allows, is left out.
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload = &self.payload[..self.payload.len().min(MAX_PAYLOAD)];
        let mut pad = self.padding.len().clamp(usize::from(MIN_PADDING), 255);
        while !(5 + payload.len() + pad).is_multiple_of(BLOCK) {
            pad += 1;
        }
        if pad > 255 {
            pad -= BLOCK;
        }
        let length = 1 + payload.len() + pad;
        let mut out = Vec::with_capacity(4 + length);
        out.extend_from_slice(&(length as u32).to_be_bytes());
        out.push(pad as u8);
        out.extend_from_slice(payload);
        let given = &self.padding[..self.padding.len().min(pad)];
        out.extend_from_slice(given);
        out.resize(4 + length, 0);
        out
    }
}

/// What a [`Decoder`] finds in the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A line before the version line, without its line ending.
    Banner(Vec<u8>),
    /// The version line. Packets follow it.
    Version(Identification),
    /// A binary packet.
    Packet {
        /// The packet's sequence number: how many packets came before it,
        /// wrapping at 2^32. UNIMPLEMENTED names a packet by this number.
        sequence: u32,
        /// The packet.
        packet: Packet,
    },
}

/// Splits an SSH byte stream into lines, then packets. Feed it the bytes a
/// connection reads, in order, and take events out until it has none.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small packets costs time in proportion to their bytes.
    start: usize,
    /// How many pending bytes of a partial line are known to hold no LF
    /// or NUL, so a line arriving in small pieces is read once, not again
    /// from its start each time.
    scanned: usize,
    lines: usize,
    packets: bool,
    sequence: u32,
    failed: Option<StreamError>,
}

impl Decoder {
    /// A decoder holding no bytes, expecting the version exchange first.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// A decoder for a stream whose version line has already been read,
    /// expecting packets.
    pub fn after_version() -> Decoder {
        Decoder {
            packets: true,
            ..Decoder::default()
        }
    }

    /// Adds bytes read from the connection. After a [`StreamError`] the
    /// stream cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next event, if one has come. It returns `None` when it needs
    /// more bytes, and keeps returning the same error once the stream has
    /// broken. A decoder never holds more than one line's or one packet's
    /// bytes beyond what has been taken out, plus what one `feed` added.
    pub fn next_event(&mut self) -> Option<Result<Event, StreamError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let pending = self.buf.get(self.start..).unwrap_or_default();
        let result = if self.packets {
            Packet::parse(pending).map(|p| {
                p.map(|(packet, used)| {
                    let sequence = self.sequence;
                    self.sequence = self.sequence.wrapping_add(1);
                    (Event::Packet { sequence, packet }, used)
                })
            })
        } else if line_pending(pending, self.scanned) {
            self.scanned = pending.len();
            Ok(None)
        } else {
            self.scanned = 0;
            match parse_line(pending) {
                Ok(Some((Line::Version(id), used))) => {
                    self.packets = true;
                    Ok(Some((Event::Version(id), used)))
                }
                Ok(Some((Line::Banner(text), used))) => {
                    self.lines += 1;
                    if self.lines > MAX_BANNER_LINES {
                        Err(StreamError::TooManyLines)
                    } else {
                        Ok(Some((Event::Banner(text), used)))
                    }
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        };
        match result {
            Ok(Some((event, used))) => {
                self.start = self.start.saturating_add(used);
                Some(Ok(event))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                self.scanned = 0;
                Some(Err(e))
            }
        }
    }

    /// Whether the version line has been read, so packets come next.
    pub fn in_packets(&self) -> bool {
        self.packets
    }

    /// The sequence number the next packet will have.
    pub fn next_sequence(&self) -> u32 {
        self.sequence
    }

    /// How many bytes are held, waiting for the rest of a line or packet.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }
}

/// Why bytes are not the data or message expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload was empty, so it had no message number.
    Empty,
    /// The bytes ended before a field did.
    Truncated,
    /// Bytes were left after the last field.
    Trailing,
    /// A string, text or name-list was longer than its limit, or a payload
    /// longer than [`MAX_PAYLOAD`].
    TooLong,
    /// A text field was not UTF-8.
    Utf8,
    /// A name-list held an empty name, a name longer than [`MAX_NAME`], a
    /// name with a byte outside printable US-ASCII, or a name whose `@`
    /// is repeated or has no text on one side.
    Name,
    /// An mpint had a leading 0x00 or 0xff byte it did not need.
    Mpint,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DecodeError::Empty => "empty payload",
            DecodeError::Truncated => "field cut short",
            DecodeError::Trailing => "bytes after the last field",
            DecodeError::TooLong => "field too long",
            DecodeError::Utf8 => "text is not UTF-8",
            DecodeError::Name => "malformed name-list",
            DecodeError::Mpint => "mpint not in its shortest form",
        })
    }
}

impl std::error::Error for DecodeError {}

/// A multiple-precision integer, in two's complement, big-endian, in its
/// shortest form: zero has no bytes, and there is no leading 0x00 or 0xff
/// byte that the sign does not need.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mpint(Vec<u8>);

impl Mpint {
    /// The integer whose two's complement bytes, most significant first,
    /// are `b`. Extra leading bytes are dropped.
    pub fn from_signed_bytes(b: &[u8]) -> Mpint {
        Mpint(shortest(b).to_vec())
    }

    /// The non-negative integer whose bytes, most significant first, are
    /// `b`.
    pub fn from_unsigned_bytes(b: &[u8]) -> Mpint {
        let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        let b = &b[start..];
        let mut out = Vec::with_capacity(b.len() + 1);
        if b.first().is_some_and(|&x| x >= 0x80) {
            out.push(0);
        }
        out.extend_from_slice(b);
        Mpint(out)
    }

    /// The integer `v`.
    pub fn from_i64(v: i64) -> Mpint {
        Mpint::from_signed_bytes(&v.to_be_bytes())
    }

    /// The integer, if it fits in an `i64`.
    pub fn to_i64(&self) -> Option<i64> {
        if self.0.len() > 8 {
            return None;
        }
        let mut b = [if self.is_negative() { 0xff } else { 0 }; 8];
        b[8 - self.0.len()..].copy_from_slice(&self.0);
        Some(i64::from_be_bytes(b))
    }

    /// The two's complement bytes, as they go on the wire.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the integer is below zero.
    pub fn is_negative(&self) -> bool {
        self.0.first().is_some_and(|&b| b >= 0x80)
    }
}

/// `b` without the leading bytes its sign does not need.
fn shortest(mut b: &[u8]) -> &[u8] {
    loop {
        match b {
            [0, rest @ ..] if rest.first().is_none_or(|&x| x < 0x80) => b = rest,
            [0xff, next, ..] if *next >= 0x80 => b = &b[1..],
            _ => return b,
        }
    }
}

/// Reads the RFC 4251 data types from the front of a byte slice. Nothing
/// it returns is larger than the slice, so it allocates no more than the
/// input holds.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `b`.
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { rest: b }
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    /// A `byte`.
    pub fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// A `boolean`: any byte but 0 is true.
    pub fn boolean(&mut self) -> Result<bool, DecodeError> {
        Ok(self.byte()? != 0)
    }

    /// A `uint32`, most significant byte first.
    pub fn uint32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A `uint64`, most significant byte first.
    pub fn uint64(&mut self) -> Result<u64, DecodeError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(a))
    }

    /// A `string`: a `uint32` length, then that many bytes.
    pub fn string(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.uint32()?;
        self.take(usize::try_from(n).map_err(|_| DecodeError::Truncated)?)
    }

    /// A `string` holding UTF-8 text of at most `max` bytes.
    pub fn text(&mut self, max: usize) -> Result<String, DecodeError> {
        let b = self.string()?;
        if b.len() > max {
            return Err(DecodeError::TooLong);
        }
        String::from_utf8(b.to_vec()).map_err(|_| DecodeError::Utf8)
    }

    /// An `mpint`, which must be in its shortest form.
    pub fn mpint(&mut self) -> Result<Mpint, DecodeError> {
        let b = self.string()?;
        if shortest(b).len() != b.len() {
            return Err(DecodeError::Mpint);
        }
        Ok(Mpint(b.to_vec()))
    }

    /// A `name-list` of at most `max` bytes: names split by commas. An
    /// empty string is an empty list. Each name must follow the RFC 4251
    /// rules for algorithm names: 1 to [`MAX_NAME`] bytes of printable
    /// US-ASCII, and at most one `@`, with text on both sides of it.
    pub fn name_list(&mut self, max: usize) -> Result<Vec<String>, DecodeError> {
        let b = self.string()?;
        if b.len() > max {
            return Err(DecodeError::TooLong);
        }
        if b.is_empty() {
            return Ok(Vec::new());
        }
        b.split(|&c| c == b',')
            .map(|name| {
                if is_name(name) {
                    Ok(String::from_utf8_lossy(name).into_owned())
                } else {
                    Err(DecodeError::Name)
                }
            })
            .collect()
    }

    /// The bytes not yet read.
    pub fn remaining(&self) -> &'a [u8] {
        self.rest
    }

    /// Checks that every byte has been read.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }
}

/// Whether `b` may be a name in a name-list: 1 to [`MAX_NAME`] bytes of
/// printable US-ASCII, with no comma. A name with an `@` is an extension
/// name, `name@domainname`, so it has one `@` with text on both sides.
fn is_name(b: &[u8]) -> bool {
    let at_ok = match b.iter().position(|&c| c == b'@') {
        None => true,
        Some(i) => i > 0 && i + 1 < b.len() && !b[i + 1..].contains(&b'@'),
    };
    !b.is_empty()
        && b.len() <= MAX_NAME
        && at_ok
        && b.iter().all(|&c| (0x21..=0x7e).contains(&c) && c != b',')
}

/// Writes a `byte`.
pub fn put_byte(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

/// Writes a `boolean` as 0 or 1.
pub fn put_boolean(out: &mut Vec<u8>, v: bool) {
    out.push(u8::from(v));
}

/// Writes a `uint32`.
pub fn put_uint32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Writes a `uint64`.
pub fn put_uint64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Writes a `string`. Bytes past what a `uint32` length can count are left
/// out.
pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    let n = u32::try_from(s.len()).unwrap_or(u32::MAX);
    put_uint32(out, n);
    out.extend_from_slice(&s[..n as usize]);
}

/// Writes an `mpint`.
pub fn put_mpint(out: &mut Vec<u8>, v: &Mpint) {
    put_string(out, &v.0);
}

/// Writes a `name-list` of at most `max` bytes. Names that are not allowed
/// in a name-list, and names that would take the list past `max`, are left
/// out.
pub fn put_name_list(out: &mut Vec<u8>, names: &[String], max: usize) {
    let mut list = Vec::new();
    for name in names.iter().filter(|n| is_name(n.as_bytes())) {
        let sep = usize::from(!list.is_empty());
        if list.len() + sep + name.len() > max {
            continue;
        }
        if sep == 1 {
            list.push(b',');
        }
        list.extend_from_slice(name.as_bytes());
    }
    put_string(out, &list);
}

/// The reason codes a DISCONNECT gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // the names are those of RFC 4253, section 11.1
pub enum DisconnectReason {
    HostNotAllowedToConnect,
    ProtocolError,
    KeyExchangeFailed,
    MacError,
    CompressionError,
    ServiceNotAvailable,
    ProtocolVersionNotSupported,
    HostKeyNotVerifiable,
    ConnectionLost,
    ByApplication,
    TooManyConnections,
    AuthCancelledByUser,
    NoMoreAuthMethodsAvailable,
    IllegalUserName,
    /// Any other code, including 4, which RFC 4253 reserves.
    /// [`DisconnectReason::from_code`] never gives this for a code that has
    /// a name above, so `Other(2)` is written as code 2 and reads back as
    /// [`DisconnectReason::ProtocolError`].
    Other(u32),
}

impl DisconnectReason {
    /// The reason code's number.
    pub fn code(self) -> u32 {
        match self {
            DisconnectReason::HostNotAllowedToConnect => 1,
            DisconnectReason::ProtocolError => 2,
            DisconnectReason::KeyExchangeFailed => 3,
            DisconnectReason::MacError => 5,
            DisconnectReason::CompressionError => 6,
            DisconnectReason::ServiceNotAvailable => 7,
            DisconnectReason::ProtocolVersionNotSupported => 8,
            DisconnectReason::HostKeyNotVerifiable => 9,
            DisconnectReason::ConnectionLost => 10,
            DisconnectReason::ByApplication => 11,
            DisconnectReason::TooManyConnections => 12,
            DisconnectReason::AuthCancelledByUser => 13,
            DisconnectReason::NoMoreAuthMethodsAvailable => 14,
            DisconnectReason::IllegalUserName => 15,
            DisconnectReason::Other(c) => c,
        }
    }

    /// The reason for code `c`.
    pub fn from_code(c: u32) -> DisconnectReason {
        match c {
            1 => DisconnectReason::HostNotAllowedToConnect,
            2 => DisconnectReason::ProtocolError,
            3 => DisconnectReason::KeyExchangeFailed,
            5 => DisconnectReason::MacError,
            6 => DisconnectReason::CompressionError,
            7 => DisconnectReason::ServiceNotAvailable,
            8 => DisconnectReason::ProtocolVersionNotSupported,
            9 => DisconnectReason::HostKeyNotVerifiable,
            10 => DisconnectReason::ConnectionLost,
            11 => DisconnectReason::ByApplication,
            12 => DisconnectReason::TooManyConnections,
            13 => DisconnectReason::AuthCancelledByUser,
            14 => DisconnectReason::NoMoreAuthMethodsAvailable,
            15 => DisconnectReason::IllegalUserName,
            c => DisconnectReason::Other(c),
        }
    }
}

/// A KEXINIT message: the algorithms one side supports, each list in order
/// of preference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KexInit {
    /// 16 bytes the sender should choose at random. This module has no
    /// randomness, so world code fills them.
    pub cookie: [u8; 16],
    /// Key exchange methods, such as `curve25519-sha256`.
    pub kex_algorithms: Vec<String>,
    /// Host key types, such as `ssh-ed25519`.
    pub server_host_key_algorithms: Vec<String>,
    /// Ciphers from client to server, such as `aes128-ctr`.
    pub encryption_client_to_server: Vec<String>,
    /// Ciphers from server to client.
    pub encryption_server_to_client: Vec<String>,
    /// MACs from client to server, such as `hmac-sha2-256`.
    pub mac_client_to_server: Vec<String>,
    /// MACs from server to client.
    pub mac_server_to_client: Vec<String>,
    /// Compression from client to server, such as `none`.
    pub compression_client_to_server: Vec<String>,
    /// Compression from server to client.
    pub compression_server_to_client: Vec<String>,
    /// Language tags from client to server, usually empty.
    pub languages_client_to_server: Vec<String>,
    /// Language tags from server to client, usually empty.
    pub languages_server_to_client: Vec<String>,
    /// Whether the sender guessed the key exchange and its first key
    /// exchange packet follows.
    pub first_kex_packet_follows: bool,
    /// Reserved for later use. Senders write 0.
    pub reserved: u32,
}

impl KexInit {
    /// The algorithm both sides use, by the rule of RFC 4253 section 7.1:
    /// the first one in the client's list that is also in the server's.
    pub fn choose<'a>(client: &'a [String], server: &[String]) -> Option<&'a str> {
        client
            .iter()
            .find(|c| server.contains(c))
            .map(String::as_str)
    }

    fn lists(&self) -> [&Vec<String>; 10] {
        [
            &self.kex_algorithms,
            &self.server_host_key_algorithms,
            &self.encryption_client_to_server,
            &self.encryption_server_to_client,
            &self.mac_client_to_server,
            &self.mac_server_to_client,
            &self.compression_client_to_server,
            &self.compression_server_to_client,
            &self.languages_client_to_server,
            &self.languages_server_to_client,
        ]
    }
}

/// A transport layer message, read from or written as a packet's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // one KEXINIT per key exchange
pub enum Message {
    /// DISCONNECT (1): the sender is closing the connection.
    Disconnect {
        /// Why.
        reason: DisconnectReason,
        /// Text for a person, UTF-8, at most [`MAX_TEXT`] bytes.
        description: String,
        /// The text's language tag, usually empty.
        language: String,
    },
    /// IGNORE (2): data the receiver drops, at most [`MAX_DATA`] bytes.
    Ignore(Vec<u8>),
    /// UNIMPLEMENTED (3): the sender does not know the message in the
    /// packet with this sequence number.
    Unimplemented(u32),
    /// DEBUG (4): a note for debugging.
    Debug {
        /// Whether the receiver should show it even when not asked to.
        always_display: bool,
        /// The note, UTF-8, at most [`MAX_TEXT`] bytes.
        message: String,
        /// The note's language tag, usually empty.
        language: String,
    },
    /// SERVICE_REQUEST (5): the client asks for a service, such as
    /// `ssh-userauth`. At most [`MAX_NAME`] bytes.
    ServiceRequest(String),
    /// SERVICE_ACCEPT (6): the server grants the service named.
    ServiceAccept(String),
    /// KEXINIT (20): the algorithms the sender supports.
    KexInit(KexInit),
    /// NEWKEYS (21): the sender uses the new keys from now on.
    NewKeys,
    /// Any message number this module does not read, with its data
    /// unread.
    Other {
        /// The message number.
        number: u8,
        /// The bytes after the number.
        data: Vec<u8>,
    },
}

impl Message {
    /// Reads the message in a packet's payload. Fields must fill the
    /// payload exactly, and texts and lists must be within their limits.
    pub fn parse(payload: &[u8]) -> Result<Message, DecodeError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(DecodeError::TooLong);
        }
        let (&number, data) = payload.split_first().ok_or(DecodeError::Empty)?;
        let mut r = Reader::new(data);
        let m = match number {
            msg::DISCONNECT => Message::Disconnect {
                reason: DisconnectReason::from_code(r.uint32()?),
                description: r.text(MAX_TEXT)?,
                language: r.text(MAX_NAME)?,
            },
            msg::IGNORE => Message::Ignore(r.string()?.to_vec()),
            msg::UNIMPLEMENTED => Message::Unimplemented(r.uint32()?),
            msg::DEBUG => Message::Debug {
                always_display: r.boolean()?,
                message: r.text(MAX_TEXT)?,
                language: r.text(MAX_NAME)?,
            },
            msg::SERVICE_REQUEST => Message::ServiceRequest(r.text(MAX_NAME)?),
            msg::SERVICE_ACCEPT => Message::ServiceAccept(r.text(MAX_NAME)?),
            msg::KEXINIT => {
                let mut cookie = [0u8; 16];
                cookie.copy_from_slice(r.take(16)?);
                let mut list = || r.name_list(MAX_NAME_LIST);
                let k = KexInit {
                    cookie,
                    kex_algorithms: list()?,
                    server_host_key_algorithms: list()?,
                    encryption_client_to_server: list()?,
                    encryption_server_to_client: list()?,
                    mac_client_to_server: list()?,
                    mac_server_to_client: list()?,
                    compression_client_to_server: list()?,
                    compression_server_to_client: list()?,
                    languages_client_to_server: list()?,
                    languages_server_to_client: list()?,
                    first_kex_packet_follows: r.boolean()?,
                    reserved: r.uint32()?,
                };
                Message::KexInit(k)
            }
            msg::NEWKEYS => Message::NewKeys,
            _ => {
                let data = r.remaining().to_vec();
                r = Reader::new(&[]);
                Message::Other { number, data }
            }
        };
        r.finish()?;
        Ok(m)
    }

    /// The message number.
    pub fn number(&self) -> u8 {
        match self {
            Message::Disconnect { .. } => msg::DISCONNECT,
            Message::Ignore(_) => msg::IGNORE,
            Message::Unimplemented(_) => msg::UNIMPLEMENTED,
            Message::Debug { .. } => msg::DEBUG,
            Message::ServiceRequest(_) => msg::SERVICE_REQUEST,
            Message::ServiceAccept(_) => msg::SERVICE_ACCEPT,
            Message::KexInit(_) => msg::KEXINIT,
            Message::NewKeys => msg::NEWKEYS,
            Message::Other { number, .. } => *number,
        }
    }

    /// The message's payload. Texts and data past their limits are cut,
    /// texts at a character boundary. Names a name-list may not hold are
    /// left out. So the payload always fits in a packet and reads back.
    /// An [`Message::Other`] whose number is one this module reads cannot
    /// be written as it stands, so it is written as an IGNORE carrying its
    /// bytes.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = vec![self.number()];
        match self {
            Message::Disconnect {
                reason,
                description,
                language,
            } => {
                put_uint32(&mut out, reason.code());
                put_string(&mut out, cut(description, MAX_TEXT).as_bytes());
                put_string(&mut out, cut(language, MAX_NAME).as_bytes());
            }
            Message::Ignore(data) => put_string(&mut out, &data[..data.len().min(MAX_DATA)]),
            Message::Unimplemented(seq) => put_uint32(&mut out, *seq),
            Message::Debug {
                always_display,
                message,
                language,
            } => {
                put_boolean(&mut out, *always_display);
                put_string(&mut out, cut(message, MAX_TEXT).as_bytes());
                put_string(&mut out, cut(language, MAX_NAME).as_bytes());
            }
            Message::ServiceRequest(name) | Message::ServiceAccept(name) => {
                put_string(&mut out, cut(name, MAX_NAME).as_bytes());
            }
            Message::KexInit(k) => {
                out.extend_from_slice(&k.cookie);
                for list in k.lists() {
                    put_name_list(&mut out, list, MAX_NAME_LIST);
                }
                put_boolean(&mut out, k.first_kex_packet_follows);
                put_uint32(&mut out, k.reserved);
            }
            Message::NewKeys => {}
            Message::Other { number, data } => {
                if is_known(*number) {
                    let mut raw = Vec::with_capacity(1 + data.len().min(MAX_DATA));
                    raw.push(*number);
                    raw.extend_from_slice(&data[..data.len().min(MAX_DATA - 1)]);
                    return Message::Ignore(raw).to_payload();
                }
                out.extend_from_slice(&data[..data.len().min(MAX_PAYLOAD - 1)]);
            }
        }
        out
    }

    /// The bytes of a packet carrying this message, with the least zero
    /// padding allowed.
    pub fn to_packet(&self) -> Vec<u8> {
        Packet::new(self.to_payload()).to_bytes()
    }
}

/// Whether [`Message::parse`] reads message number `n` as its own variant.
fn is_known(n: u8) -> bool {
    matches!(n, 1..=6 | 20 | 21)
}

/// `s` cut to at most `max` bytes, at a character boundary.
fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // The examples of RFC 4251, section 5.

    #[test]
    fn mpint_examples() {
        let cases: [(&[u8], &[u8]); 5] = [
            (&[], &[0, 0, 0, 0]),
            (
                &[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
                &[0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
            ),
            (&[0x00, 0x80], &[0, 0, 0, 2, 0x00, 0x80]),
            (&[0xed, 0xcc], &[0, 0, 0, 2, 0xed, 0xcc]),
            (
                &[0xff, 0x21, 0x52, 0x41, 0x11],
                &[0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41, 0x11],
            ),
        ];
        for (value, wire) in cases {
            let m = Mpint::from_signed_bytes(value);
            assert_eq!(m.as_bytes(), value);
            let mut out = Vec::new();
            put_mpint(&mut out, &m);
            assert_eq!(out, wire);
            let mut r = Reader::new(wire);
            assert_eq!(r.mpint(), Ok(m));
            assert_eq!(r.finish(), Ok(()));
        }
        assert_eq!(Mpint::from_i64(0).as_bytes(), &[] as &[u8]);
        assert_eq!(
            Mpint::from_unsigned_bytes(&[0x80]).as_bytes(),
            &[0x00, 0x80]
        );
        assert_eq!(Mpint::from_i64(-0x1234).as_bytes(), &[0xed, 0xcc]);
        assert_eq!(
            Mpint::from_i64(-0xdeadbeef).as_bytes(),
            &[0xff, 0x21, 0x52, 0x41, 0x11]
        );
        assert_eq!(
            Mpint::from_unsigned_bytes(&[0, 0, 0x09, 0xa3]).as_bytes(),
            &[0x09, 0xa3]
        );
        assert_eq!(Mpint::from_unsigned_bytes(&[0, 0]).as_bytes(), &[] as &[u8]);
        assert_eq!(Mpint::from_signed_bytes(&[0xff, 0xff]).as_bytes(), &[0xff]);
        assert!(Mpint::from_i64(-1).is_negative());
        for v in [
            0,
            1,
            -1,
            127,
            128,
            -128,
            -129,
            255,
            256,
            i64::MAX,
            i64::MIN,
            -1234,
            0x9a378f9b2e332a7,
        ] {
            assert_eq!(Mpint::from_i64(v).to_i64(), Some(v), "{v}");
        }
        assert_eq!(
            Mpint::from_unsigned_bytes(&[0x80, 0, 0, 0, 0, 0, 0, 0]).to_i64(),
            None
        );
        // Leading bytes the sign does not need are refused.
        for wire in [
            &[0, 0, 0, 1, 0][..],
            &[0, 0, 0, 2, 0, 0x7f],
            &[0, 0, 0, 2, 0xff, 0x80],
        ] {
            assert_eq!(Reader::new(wire).mpint(), Err(DecodeError::Mpint));
        }
    }

    #[test]
    fn name_list_examples() {
        let cases: [(&[&str], &[u8]); 3] = [
            (&[], &[0, 0, 0, 0]),
            (&["zlib"], &[0, 0, 0, 4, 0x7a, 0x6c, 0x69, 0x62]),
            (
                &["zlib", "none"],
                &[
                    0, 0, 0, 9, 0x7a, 0x6c, 0x69, 0x62, 0x2c, 0x6e, 0x6f, 0x6e, 0x65,
                ],
            ),
        ];
        for (list, wire) in cases {
            let mut out = Vec::new();
            put_name_list(&mut out, &names(list), MAX_NAME_LIST);
            assert_eq!(out, wire);
            assert_eq!(Reader::new(wire).name_list(MAX_NAME_LIST), Ok(names(list)));
        }
        // Empty names, spaces, control bytes and names that are too long.
        for bad in [&b"a,,b"[..], b",a", b"a,", b"a b", b"a\0", &[b'x'; 65]] {
            let mut wire = Vec::new();
            put_string(&mut wire, bad);
            assert_eq!(
                Reader::new(&wire).name_list(MAX_NAME_LIST),
                Err(DecodeError::Name),
                "{bad:?}"
            );
        }
        let mut wire = Vec::new();
        put_string(&mut wire, b"abcdef");
        assert_eq!(Reader::new(&wire).name_list(5), Err(DecodeError::TooLong));
        // The writer leaves out names the reader would refuse.
        let mut out = Vec::new();
        put_name_list(
            &mut out,
            &names(&["a", "", "b c", "d,e", &"x".repeat(65), "f"]),
            MAX_NAME_LIST,
        );
        assert_eq!(
            Reader::new(&out).name_list(MAX_NAME_LIST),
            Ok(names(&["a", "f"]))
        );
        // And names past the limit.
        let mut out = Vec::new();
        put_name_list(&mut out, &names(&["abc", "defg", "hi"]), 6);
        assert_eq!(Reader::new(&out).name_list(6), Ok(names(&["abc", "hi"])));
    }

    #[test]
    fn plain_types() {
        let mut out = Vec::new();
        put_byte(&mut out, 7);
        put_boolean(&mut out, true);
        put_boolean(&mut out, false);
        put_uint32(&mut out, 0x29b7f4aa);
        put_uint64(&mut out, 0x0102030405060708);
        put_string(&mut out, b"testing");
        assert_eq!(
            out,
            [
                7, 1, 0, 0x29, 0xb7, 0xf4, 0xaa, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 7, b't', b'e',
                b's', b't', b'i', b'n', b'g'
            ]
        );
        let mut r = Reader::new(&out);
        assert_eq!(r.byte(), Ok(7));
        assert_eq!(r.boolean(), Ok(true));
        assert_eq!(r.boolean(), Ok(false));
        assert_eq!(r.uint32(), Ok(0x29b7f4aa));
        assert_eq!(r.uint64(), Ok(0x0102030405060708));
        assert_eq!(r.string(), Ok(&b"testing"[..]));
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.byte(), Err(DecodeError::Truncated));
        // Any byte but 0 is true.
        assert_eq!(Reader::new(&[0x42]).boolean(), Ok(true));
        // A length past the end, and the largest length.
        assert_eq!(
            Reader::new(&[0, 0, 0, 5, 1]).string(),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).string(),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            Reader::new(&[0, 0, 0, 1, 0xff]).text(10),
            Err(DecodeError::Utf8)
        );
        assert_eq!(
            Reader::new(&[0, 0, 0, 2, b'a', b'b']).text(1),
            Err(DecodeError::TooLong)
        );
        assert_eq!(Reader::new(&[1]).finish(), Err(DecodeError::Trailing));
        // Every truncated prefix of each type.
        for n in 0..out.len() {
            let mut r = Reader::new(&out[..n]);
            let got = (|| {
                r.byte()?;
                r.boolean()?;
                r.boolean()?;
                r.uint32()?;
                r.uint64()?;
                r.string()?;
                Ok(())
            })();
            assert_eq!(got, Err(DecodeError::Truncated), "{n}");
        }
    }

    #[test]
    fn version_lines() {
        let (line, used) = parse_line(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\nrest")
            .unwrap()
            .unwrap();
        assert_eq!(used, 40);
        let Line::Version(id) = line else { panic!() };
        assert_eq!(
            (id.proto(), id.software(), id.comments()),
            ("2.0", "OpenSSH_9.6p1", Some("Ubuntu-3ubuntu13"))
        );
        assert!(id.is_v2());
        assert_eq!(id.to_bytes(), b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n");
        // LF alone, and the 1.99 compatibility version.
        // A minus sign in the software version is refused.
        assert_eq!(
            parse_line(b"SSH-1.99-Cisco-1.25\n"),
            Err(StreamError::BadVersion)
        );
        let Some((Line::Version(id), 19)) = parse_line(b"SSH-1.99-Cisco1.25\n").unwrap() else {
            panic!()
        };
        assert!(id.is_v2());
        assert!(!Identification::new("1.5", "x", None).unwrap().is_v2());
        // Bad version lines.
        for bad in [
            &b"SSH-2.0\r\n"[..],
            b"SSH--x\r\n",
            b"SSH-2.0-\r\n",
            b"SSH-2.0-a-b\r\n",
            b"SSH-2.0-a\tb\r\n",
            b"SSH-2.0-a\rb\r\n",
            b"SSH-2.0-\xc3\xa9\r\n",
        ] {
            assert_eq!(parse_line(bad), Err(StreamError::BadVersion), "{bad:?}");
        }
        // The longest version line, and one byte more.
        let long = format!("SSH-2.0-{}\r\n", "a".repeat(MAX_VERSION_LINE - 10));
        assert_eq!(long.len(), MAX_VERSION_LINE);
        assert!(parse_line(long.as_bytes()).unwrap().is_some());
        let longer = format!("SSH-2.0-{}\r\n", "a".repeat(MAX_VERSION_LINE - 9));
        assert_eq!(parse_line(longer.as_bytes()), Err(StreamError::LineTooLong));
        assert_eq!(
            Identification::new("2.0", &"a".repeat(MAX_VERSION_LINE - 9), None),
            Err(StreamError::LineTooLong)
        );
        assert!(Identification::new("2.0", &"a".repeat(MAX_VERSION_LINE - 10), None).is_ok());
        // The writer refuses what the reader would.
        assert_eq!(
            Identification::new("2.0", "a b", None),
            Err(StreamError::BadVersion)
        );
        assert_eq!(
            Identification::new("", "a", None),
            Err(StreamError::BadVersion)
        );
        assert_eq!(
            Identification::new("2.0", "a", Some("\n")),
            Err(StreamError::BadVersion)
        );
        let id = Identification::new("2.0", "x", Some("")).unwrap();
        assert_eq!(id.to_bytes(), b"SSH-2.0-x \r\n");
        assert_eq!(
            parse_line(&id.to_bytes()),
            Ok(Some((Line::Version(id), 12)))
        );
    }

    #[test]
    fn banner_lines() {
        let b = banner_line("Welcome to the tank farm").unwrap();
        assert_eq!(b, b"Welcome to the tank farm\r\n");
        assert_eq!(
            parse_line(&b),
            Ok(Some((
                Line::Banner(b"Welcome to the tank farm".to_vec()),
                b.len()
            )))
        );
        assert_eq!(parse_line(b"\n"), Ok(Some((Line::Banner(vec![]), 1))));
        assert_eq!(parse_line(b"a\0b\n"), Err(StreamError::Nul));
        assert_eq!(
            parse_line(&[b'x'; MAX_BANNER_LINE]),
            Err(StreamError::LineTooLong)
        );
        let mut longest = vec![b'x'; MAX_BANNER_LINE - 1];
        longest.push(b'\n');
        assert!(parse_line(&longest).unwrap().is_some());
        assert_eq!(banner_line("SSH-2.0-x"), None);
        assert_eq!(banner_line("a\nb"), None);
        assert_eq!(banner_line(&"x".repeat(MAX_BANNER_LINE - 1)), None);
        assert!(banner_line(&"x".repeat(MAX_BANNER_LINE - 2)).is_some());
        // Every prefix of a line is incomplete, not an error.
        let line = b"SSH-2.0-OpenSSH_9.6 c\r\n";
        for n in 0..line.len() {
            assert_eq!(parse_line(&line[..n]), Ok(None), "{n}");
        }
    }

    #[test]
    fn packets() {
        // NEWKEYS: 1 payload byte, so 10 padding bytes make 16.
        let bytes = Packet::new(vec![21]).to_bytes();
        assert_eq!(bytes, [0, 0, 0, 12, 10, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (p, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(
            (p.payload.as_slice(), p.padding.len(), used),
            (&[21u8][..], 10, 16)
        );
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse(&bytes[..n]), Ok(None), "{n}");
        }
        // Padding given is kept, and topped up to a whole block.
        let p = Packet {
            payload: vec![1, 2, 3],
            padding: vec![9; 5],
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes.len() % BLOCK, 0);
        let (back, _) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(back.payload, [1, 2, 3]);
        assert_eq!(&back.padding[..5], &[9; 5]);
        // Too much padding is cut to what fits in a byte.
        for payload in 0..16 {
            let p = Packet {
                payload: vec![7; payload],
                padding: vec![1; 300],
            };
            let (back, used) = Packet::parse(&p.to_bytes()).unwrap().unwrap();
            assert!(back.padding.len() <= 255 && back.padding.len() > 240);
            assert_eq!(used % BLOCK, 0);
        }
        // Lengths: too short, unaligned, too long.
        assert_eq!(
            Packet::parse(&[0, 0, 0, 4]),
            Err(StreamError::PacketLength(4))
        );
        assert_eq!(
            Packet::parse(&[0, 0, 0, 13]),
            Err(StreamError::PacketLength(13))
        );
        assert_eq!(
            Packet::parse(&[0, 0, 0x88, 0xbc]),
            Err(StreamError::PacketLength(35004))
        );
        assert_eq!(
            Packet::parse(&[0xff, 0xff, 0xff, 0xff]),
            Err(StreamError::PacketLength(u32::MAX))
        );
        assert_eq!(Packet::parse(&[0, 0, 0x88, 0xb4]), Ok(None));
        // Padding: too little, and more than the packet.
        assert_eq!(
            Packet::parse(&[0, 0, 0, 12, 3]),
            Err(StreamError::Padding(3))
        );
        assert_eq!(
            Packet::parse(&[0, 0, 0, 12, 12]),
            Err(StreamError::Padding(12))
        );
        assert_eq!(Packet::parse(&[0, 0, 0, 12, 11]), Ok(None));
        // A payload past the limit.
        assert_eq!(
            Packet::parse(&[0, 0, 0x88, 0xb4, 4]),
            Err(StreamError::PayloadTooLong(34991))
        );
        // The largest payload fits.
        let big = Packet::new(vec![2; MAX_PAYLOAD + 100]).to_bytes();
        let (back, used) = Packet::parse(&big).unwrap().unwrap();
        assert_eq!((back.payload.len(), used), (MAX_PAYLOAD, big.len()));
        assert!(big.len() <= MAX_PACKET);
    }

    fn samples() -> Vec<Message> {
        vec![
            Message::Disconnect {
                reason: DisconnectReason::ProtocolError,
                description: "bad packet".into(),
                language: "en".into(),
            },
            Message::Disconnect {
                reason: DisconnectReason::Other(99),
                description: "é".into(),
                language: String::new(),
            },
            Message::Ignore(vec![1, 2, 3]),
            Message::Ignore(vec![]),
            Message::Unimplemented(7),
            Message::Debug {
                always_display: true,
                message: "hello".into(),
                language: String::new(),
            },
            Message::ServiceRequest("ssh-userauth".into()),
            Message::ServiceAccept("ssh-userauth".into()),
            Message::KexInit(KexInit {
                cookie: [0xab; 16],
                kex_algorithms: names(&[
                    "curve25519-sha256",
                    "curve25519-sha256@libssh.org",
                    "kex-strict-s-v00@openssh.com",
                ]),
                server_host_key_algorithms: names(&["ssh-ed25519"]),
                encryption_client_to_server: names(&[
                    "aes128-ctr",
                    "chacha20-poly1305@openssh.com",
                ]),
                encryption_server_to_client: names(&["aes128-ctr"]),
                mac_client_to_server: names(&["hmac-sha2-256"]),
                mac_server_to_client: names(&["hmac-sha2-256"]),
                compression_client_to_server: names(&["none", "zlib@openssh.com"]),
                compression_server_to_client: names(&["none"]),
                languages_client_to_server: vec![],
                languages_server_to_client: vec![],
                first_kex_packet_follows: false,
                reserved: 0,
            }),
            Message::NewKeys,
            Message::Other {
                number: 50,
                data: vec![0, 0, 0, 4, b'r', b'o', b'o', b't'],
            },
            Message::Other {
                number: 0,
                data: vec![],
            },
        ]
    }

    #[test]
    fn messages_round_trip() {
        for m in samples() {
            let payload = m.to_payload();
            assert_eq!(payload[0], m.number());
            assert_eq!(Message::parse(&payload), Ok(m.clone()));
            let bytes = m.to_packet();
            let (p, used) = Packet::parse(&bytes).unwrap().unwrap();
            assert_eq!((p.payload, used), (payload.clone(), bytes.len()));
            // Every truncated prefix fails.
            for n in 0..payload.len() {
                if matches!(m, Message::Other { .. }) && n > 0 {
                    continue;
                }
                let want = if n == 0 {
                    DecodeError::Empty
                } else {
                    DecodeError::Truncated
                };
                assert_eq!(Message::parse(&payload[..n]), Err(want), "{m:?} cut to {n}");
            }
        }
    }

    #[test]
    fn message_wire_examples() {
        assert_eq!(Message::NewKeys.to_payload(), [21]);
        assert_eq!(
            Message::ServiceRequest("ssh-userauth".into()).to_payload(),
            b"\x05\0\0\0\x0cssh-userauth"
        );
        assert_eq!(
            Message::Unimplemented(0x01020304).to_payload(),
            [3, 1, 2, 3, 4]
        );
        assert_eq!(
            Message::Disconnect {
                reason: DisconnectReason::ByApplication,
                description: "bye".into(),
                language: "".into()
            }
            .to_payload(),
            [1, 0, 0, 0, 11, 0, 0, 0, 3, b'b', b'y', b'e', 0, 0, 0, 0]
        );
        assert_eq!(
            Message::Debug {
                always_display: false,
                message: "".into(),
                language: "".into()
            }
            .to_payload(),
            [4, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        for c in 0..=20 {
            assert_eq!(DisconnectReason::from_code(c).code(), c);
        }
        assert_eq!(DisconnectReason::from_code(4), DisconnectReason::Other(4));
    }

    #[test]
    fn message_errors() {
        assert_eq!(Message::parse(&[]), Err(DecodeError::Empty));
        assert_eq!(Message::parse(&[21, 0]), Err(DecodeError::Trailing));
        assert_eq!(
            Message::parse(&[3, 0, 0, 0, 1, 9]),
            Err(DecodeError::Trailing)
        );
        assert_eq!(
            Message::parse(&[5, 0, 0, 0, 1, 0xff]),
            Err(DecodeError::Utf8)
        );
        assert_eq!(
            Message::parse(&vec![50; MAX_PAYLOAD + 1]),
            Err(DecodeError::TooLong)
        );
        let mut long = vec![5];
        put_string(&mut long, &[b'a'; MAX_NAME + 1]);
        assert_eq!(Message::parse(&long), Err(DecodeError::TooLong));
        let mut long = vec![1, 0, 0, 0, 1];
        put_string(&mut long, &vec![b'a'; MAX_TEXT + 1]);
        put_string(&mut long, b"");
        assert_eq!(Message::parse(&long), Err(DecodeError::TooLong));
        let mut kex = vec![20];
        kex.extend_from_slice(&[0; 16]);
        put_string(&mut kex, b"a,,b");
        assert_eq!(Message::parse(&kex), Err(DecodeError::Name));
        let mut kex = vec![20];
        kex.extend_from_slice(&[0; 16]);
        put_string(&mut kex, &vec![b'a'; MAX_NAME_LIST + 1]);
        assert_eq!(Message::parse(&kex), Err(DecodeError::TooLong));
        // A boolean other than 0 or 1 still reads as true.
        let mut k = Message::KexInit(KexInit::default()).to_payload();
        let flag = k.len() - 5;
        k[flag] = 9;
        let Ok(Message::KexInit(k)) = Message::parse(&k) else {
            panic!()
        };
        assert!(k.first_kex_packet_follows);
    }

    #[test]
    fn writers_cap_what_they_write() {
        let huge = "é".repeat(MAX_TEXT);
        let m = Message::Disconnect {
            reason: DisconnectReason::ProtocolError,
            description: huge.clone(),
            language: huge.clone(),
        };
        let Ok(Message::Disconnect {
            description,
            language,
            ..
        }) = Message::parse(&m.to_payload())
        else {
            panic!()
        };
        assert_eq!((description.len(), language.len()), (MAX_TEXT, MAX_NAME));
        let m = Message::Debug {
            always_display: true,
            message: format!("a{huge}"),
            language: String::new(),
        };
        let Ok(Message::Debug { message, .. }) = Message::parse(&m.to_payload()) else {
            panic!()
        };
        assert_eq!(message.len(), MAX_TEXT - 1);
        let m = Message::Ignore(vec![0; MAX_PAYLOAD * 2]);
        let p = m.to_payload();
        assert_eq!(p.len(), MAX_PAYLOAD);
        assert!(Packet::parse(&m.to_packet()).unwrap().is_some());
        let m = Message::ServiceAccept(huge);
        assert!(Message::parse(&m.to_payload()).is_ok());
        let full = vec!["x".repeat(MAX_NAME); 1000];
        let k = KexInit {
            kex_algorithms: full.clone(),
            server_host_key_algorithms: full.clone(),
            encryption_client_to_server: full.clone(),
            encryption_server_to_client: full.clone(),
            mac_client_to_server: full.clone(),
            mac_server_to_client: full.clone(),
            compression_client_to_server: full.clone(),
            compression_server_to_client: full.clone(),
            languages_client_to_server: full.clone(),
            languages_server_to_client: full,
            ..KexInit::default()
        };
        let p = Message::KexInit(k).to_payload();
        assert!(p.len() <= MAX_PAYLOAD);
        assert!(Message::parse(&p).is_ok());
        // An Other with a number this module reads goes out as IGNORE.
        let m = Message::Other {
            number: 1,
            data: vec![0; 3],
        };
        assert_eq!(
            Message::parse(&m.to_payload()),
            Ok(Message::Ignore(vec![1, 0, 0, 0]))
        );
        let m = Message::Other {
            number: 21,
            data: vec![0; MAX_PAYLOAD],
        };
        assert!(Message::parse(&m.to_payload()).is_ok());
        let m = Message::Other {
            number: 99,
            data: vec![0; MAX_PAYLOAD],
        };
        assert_eq!(m.to_payload().len(), MAX_PAYLOAD);
        assert!(Message::parse(&m.to_payload()).is_ok());
    }

    #[test]
    fn version_comments_are_free_text() {
        // RFC 4253 limits the characters of the two versions, not of the
        // comments, so UTF-8 text and tabs there are allowed.
        let line = "SSH-2.0-x caf\u{e9}\tok 1-2\r\n";
        let Ok(Some((Line::Version(id), n))) = parse_line(line.as_bytes()) else {
            panic!()
        };
        assert_eq!((id.comments(), n), (Some("caf\u{e9}\tok 1-2"), line.len()));
        assert_eq!(id.to_bytes(), line.as_bytes());
        // A CR or LF inside the comments cannot be written.
        for bad in ["a\rb", "a\nb", "a\0b"] {
            assert_eq!(
                Identification::new("2.0", "x", Some(bad)),
                Err(StreamError::BadVersion)
            );
        }
        assert_eq!(
            parse_line(b"SSH-2.0-x a\rb\r\n"),
            Err(StreamError::BadVersion)
        );
        assert_eq!(
            parse_line(b"SSH-2.0-x \xff\r\n"),
            Err(StreamError::BadVersion)
        );
    }

    #[test]
    fn names_have_at_most_one_at_sign() {
        // RFC 4251 section 6: extension names are name@domainname.
        let mut wire = Vec::new();
        put_string(&mut wire, b"aes@x.org,b");
        assert_eq!(
            Reader::new(&wire).name_list(MAX_NAME_LIST),
            Ok(names(&["aes@x.org", "b"]))
        );
        for bad in [&b"a@b@c"[..], b"@b", b"a@", b"@"] {
            let mut wire = Vec::new();
            put_string(&mut wire, bad);
            assert_eq!(
                Reader::new(&wire).name_list(MAX_NAME_LIST),
                Err(DecodeError::Name),
                "{bad:?}"
            );
        }
        let mut out = Vec::new();
        put_name_list(&mut out, &names(&["a@b@c", "x@y", "@z"]), MAX_NAME_LIST);
        assert_eq!(
            Reader::new(&out).name_list(MAX_NAME_LIST),
            Ok(names(&["x@y"]))
        );
    }

    #[test]
    fn decoder_takes_many_packets_from_one_feed() {
        let one = Message::NewKeys.to_packet();
        let mut d = Decoder::after_version();
        let count = 50_000;
        d.feed(&one.repeat(count));
        d.feed(&one[..3]);
        for i in 0..count {
            assert!(matches!(
                d.next_event(),
                Some(Ok(Event::Packet { sequence, .. })) if sequence as usize == i
            ));
        }
        assert_eq!((d.next_event(), d.buffered()), (None, 3));
        d.feed(&one[3..]);
        assert!(matches!(d.next_event(), Some(Ok(Event::Packet { .. }))));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_packets_in_linear_time() {
        // Taking an event out must not move the bytes after it each time,
        // or a large feed of small packets costs time in its square.
        let one = Message::NewKeys.to_packet();
        let count = 400_000;
        let mut stream = b"SSH-2.0-x\r\n".to_vec();
        stream.extend(one.repeat(count));
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        d.feed(&stream);
        assert!(matches!(d.next_event(), Some(Ok(Event::Version(_)))));
        let mut n = 0;
        while let Some(e) = d.next_event() {
            e.unwrap();
            n += 1;
        }
        assert_eq!((n, d.buffered()), (count, 0));
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
        // Bytes taken out are dropped on a later feed, so a long
        // connection read in small pieces holds only what is pending.
        for _ in 0..1000 {
            d.feed(&one);
            d.feed(&one[..5]);
            assert!(matches!(d.next_event(), Some(Ok(Event::Packet { .. }))));
            assert_eq!(d.next_event(), None);
            d.feed(&one[5..]);
            assert!(matches!(d.next_event(), Some(Ok(Event::Packet { .. }))));
            assert_eq!(d.buffered(), 0);
        }
        assert!(d.buf.len() <= 4 * one.len(), "{}", d.buf.len());
    }

    #[test]
    fn decoder_reads_long_lines_byte_by_byte_in_linear_time() {
        // The most lines before the version line, each as long as allowed,
        // arriving one byte at a time. A decoder that read each line from
        // its start on every byte would do this in the square of its size.
        let mut line = vec![b'x'; MAX_BANNER_LINE - 2];
        line.extend_from_slice(b"\r\n");
        let mut stream = line.repeat(MAX_BANNER_LINES);
        stream.extend_from_slice(b"SSH-2.0-x\r\n");
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        let mut banners = 0;
        for b in &stream {
            d.feed(std::slice::from_ref(b));
            while let Some(e) = d.next_event() {
                match e.unwrap() {
                    Event::Banner(text) => {
                        assert_eq!(text.len(), MAX_BANNER_LINE - 2);
                        banners += 1;
                    }
                    Event::Version(_) => assert!(d.in_packets()),
                    Event::Packet { .. } => panic!(),
                }
            }
        }
        assert_eq!(
            (banners, d.in_packets(), d.buffered()),
            (MAX_BANNER_LINES, true, 0)
        );
        assert!(
            started.elapsed().as_millis() < 1000,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn choose_follows_the_client() {
        let client = names(&["a", "b", "c"]);
        assert_eq!(KexInit::choose(&client, &names(&["c", "b"])), Some("b"));
        assert_eq!(KexInit::choose(&client, &names(&["d"])), None);
        assert_eq!(KexInit::choose(&[], &client), None);
    }

    fn stream() -> Vec<u8> {
        let mut s = Vec::new();
        s.extend(banner_line("Hello").unwrap());
        s.extend(b"second line\n");
        s.extend(
            Identification::new("2.0", "Test_1.0", Some("ok"))
                .unwrap()
                .to_bytes(),
        );
        for m in samples() {
            s.extend(m.to_packet());
        }
        s
    }

    fn collect(d: &mut Decoder, out: &mut Vec<Result<Event, StreamError>>) {
        while let Some(e) = d.next_event() {
            let stop = e.is_err();
            out.push(e);
            if stop {
                break;
            }
        }
    }

    fn decode_whole(b: &[u8]) -> Vec<Result<Event, StreamError>> {
        let mut d = Decoder::new();
        d.feed(b);
        let mut out = Vec::new();
        collect(&mut d, &mut out);
        out
    }

    fn decode_bytewise(b: &[u8]) -> Vec<Result<Event, StreamError>> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        for byte in b {
            if out
                .last()
                .is_some_and(|e: &Result<Event, StreamError>| e.is_err())
            {
                break;
            }
            d.feed(std::slice::from_ref(byte));
            collect(&mut d, &mut out);
        }
        out
    }

    #[test]
    fn decoder_reads_a_stream() {
        let s = stream();
        let events = decode_whole(&s);
        assert_eq!(events, decode_bytewise(&s));
        assert_eq!(events.len(), 3 + samples().len());
        assert_eq!(events[0], Ok(Event::Banner(b"Hello".to_vec())));
        assert_eq!(events[1], Ok(Event::Banner(b"second line".to_vec())));
        let Ok(Event::Version(id)) = &events[2] else {
            panic!()
        };
        assert_eq!(id.comments(), Some("ok"));
        for (i, (e, m)) in events[3..].iter().zip(samples()).enumerate() {
            let Ok(Event::Packet { sequence, packet }) = e else {
                panic!()
            };
            assert_eq!(*sequence as usize, i);
            assert_eq!(Message::parse(&packet.payload), Ok(m));
        }
        // Every prefix gives a prefix of the events, with no error.
        for n in 0..s.len() {
            let got = decode_whole(&s[..n]);
            assert!(got.iter().all(Result::is_ok));
            assert_eq!(&events[..got.len()], &got[..]);
        }
    }

    #[test]
    fn decoder_errors_stick() {
        let mut d = Decoder::new();
        d.feed(b"SSH-2.0-x\r\n\0\0\0\x05");
        assert!(matches!(d.next_event(), Some(Ok(Event::Version(_)))));
        assert!(d.in_packets());
        assert_eq!(d.next_event(), Some(Err(StreamError::PacketLength(5))));
        d.feed(&Message::NewKeys.to_packet());
        assert_eq!(d.next_event(), Some(Err(StreamError::PacketLength(5))));
        assert_eq!(d.buffered(), 0);
        // Too many lines before the version line.
        let mut d = Decoder::new();
        let mut n = 0;
        let mut last = None;
        for _ in 0..=MAX_BANNER_LINES {
            d.feed(b"x\r\n");
            match d.next_event() {
                Some(Ok(Event::Banner(_))) => n += 1,
                other => last = other,
            }
        }
        assert_eq!(
            (n, last),
            (MAX_BANNER_LINES, Some(Err(StreamError::TooManyLines)))
        );
        // A decoder that starts after the version line.
        let mut d = Decoder::after_version();
        d.feed(&Message::NewKeys.to_packet());
        d.feed(&Message::NewKeys.to_packet());
        assert!(matches!(
            d.next_event(),
            Some(Ok(Event::Packet { sequence: 0, .. }))
        ));
        assert!(matches!(
            d.next_event(),
            Some(Ok(Event::Packet { sequence: 1, .. }))
        ));
        assert_eq!(d.next_sequence(), 2);
        assert_eq!(d.next_event(), None);
    }

    /// A small deterministic generator, so the fuzz loop runs the same
    /// every time.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
        fn text(&mut self, n: usize) -> String {
            let pool = [
                "a",
                "b",
                "-",
                ",",
                " ",
                "é",
                "\u{1F600}",
                "\0",
                "SSH-",
                "x@y.z",
            ];
            (0..n).map(|_| pool[self.below(pool.len())]).collect()
        }
        fn list(&mut self) -> Vec<String> {
            (0..self.below(6))
                .map(|_| {
                    let n = self.below(80);
                    self.text(n)
                })
                .collect()
        }
    }

    fn check_stream(b: &[u8]) {
        let events = decode_whole(b);
        assert_eq!(events, decode_bytewise(b));
        for e in events.iter().flatten() {
            match e {
                Event::Banner(text) => assert!(!text.starts_with(b"SSH-") && !text.contains(&0)),
                Event::Version(id) => {
                    let bytes = id.to_bytes();
                    assert_eq!(
                        parse_line(&bytes),
                        Ok(Some((Line::Version(id.clone()), bytes.len())))
                    );
                }
                Event::Packet { packet, .. } => {
                    let bytes = packet.to_bytes();
                    assert_eq!(
                        Packet::parse(&bytes),
                        Ok(Some((packet.clone(), bytes.len())))
                    );
                    if let Ok(m) = Message::parse(&packet.payload) {
                        assert_eq!(Message::parse(&m.to_payload()), Ok(m));
                    }
                }
            }
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut g = Lcg(0x5eed);
        let base = stream();
        let kinds: Vec<Vec<u8>> = samples().iter().map(Message::to_payload).collect();
        for round in 0..4000 {
            // Random bytes, a valid stream with a few bytes changed, and
            // the version line followed by random packets.
            let n = g.below(300);
            let random = g.bytes(n);
            check_stream(&random);
            let mut mutated = base.clone();
            for _ in 0..=g.below(4) {
                let i = g.below(mutated.len());
                mutated[i] = g.next() as u8;
            }
            let cut = g.below(mutated.len() + 1);
            check_stream(&mutated[..cut]);
            let mut s = b"SSH-2.0-x\r\n".to_vec();
            for _ in 0..g.below(4) {
                let mut payload = kinds[g.below(kinds.len())].clone();
                if !payload.is_empty() && g.below(2) == 0 {
                    let i = g.below(payload.len());
                    payload[i] = g.next() as u8;
                }
                let pad = g.below(20);
                s.extend(
                    Packet {
                        payload,
                        padding: g.bytes(pad),
                    }
                    .to_bytes(),
                );
            }
            check_stream(&s);
            // Any bytes as a payload, and through the reader.
            let _ = Message::parse(&random);
            let mut r = Reader::new(&random);
            let _ = (
                r.mpint(),
                r.name_list(MAX_NAME_LIST),
                r.text(MAX_TEXT),
                r.uint64(),
                r.boolean(),
            );
            // Writers given arbitrary values write what reads back.
            let m = match round % 7 {
                0 => Message::Disconnect {
                    reason: DisconnectReason::from_code(g.next()),
                    description: {
                        let n = g.below(50);
                        g.text(n)
                    },
                    language: {
                        let n = g.below(80);
                        g.text(n)
                    },
                },
                1 => Message::Debug {
                    always_display: g.below(2) == 0,
                    message: g.text(20),
                    language: g.text(3),
                },
                2 => Message::ServiceRequest({
                    let n = g.below(100);
                    g.text(n)
                }),
                3 => {
                    let mut cookie = [0u8; 16];
                    cookie.copy_from_slice(&g.bytes(16));
                    Message::KexInit(KexInit {
                        cookie,
                        kex_algorithms: g.list(),
                        server_host_key_algorithms: g.list(),
                        encryption_client_to_server: g.list(),
                        encryption_server_to_client: g.list(),
                        mac_client_to_server: g.list(),
                        mac_server_to_client: g.list(),
                        compression_client_to_server: g.list(),
                        compression_server_to_client: g.list(),
                        languages_client_to_server: g.list(),
                        languages_server_to_client: g.list(),
                        first_kex_packet_follows: g.below(2) == 0,
                        reserved: g.next(),
                    })
                }
                4 => Message::Other {
                    number: g.next() as u8,
                    data: {
                        let n = g.below(30);
                        g.bytes(n)
                    },
                },
                5 => Message::Ignore({
                    let n = g.below(30);
                    g.bytes(n)
                }),
                _ => Message::Unimplemented(g.next()),
            };
            let payload = m.to_payload();
            let back = Message::parse(&payload).unwrap();
            assert_eq!(back.to_payload(), payload);
            check_stream(&{
                let mut s = b"SSH-2.0-x\r\n".to_vec();
                s.extend(m.to_packet());
                s
            });
            // Identification from arbitrary parts reads back when allowed.
            let (p, sw, c) = (
                g.text(3),
                {
                    let n = g.below(10);
                    g.text(n)
                },
                g.text(2),
            );
            if let Ok(id) = Identification::new(&p, &sw, Some(&c)) {
                let bytes = id.to_bytes();
                assert_eq!(
                    parse_line(&bytes),
                    Ok(Some((Line::Version(id), bytes.len())))
                );
            }
            if let Some(b) = banner_line(&sw) {
                assert!(matches!(parse_line(&b), Ok(Some((Line::Banner(_), _)))));
            }
        }
    }
}
