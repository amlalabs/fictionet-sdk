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
//! Nothing here reads a socket. A world pushes TCP bytes through
//! [`Stream<Events>`](fictionet::stdlib::codec::Stream) for the version exchange and
//! numbered packets, or [`Stream<codec::Frames<Packet>>`](fictionet::stdlib::codec::Stream) after it.
//! It reads payloads with [`Message::parse`] and builds replies with
//! [`Identification::new`] and [`Packet::from_message`]. Which
//! algorithms the world offers, and what its software line says, is up to
//! world code.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. Every buffer is bounded by a named limit, such as
//! [`MAX_PACKET`], [`MAX_BANNER_LINES`] and [`MAX_PAYLOAD`].
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::ssh::{Events, Event, Identification, KexInit, Message, Packet};
//! use fictionet::stdlib::codec::{Stream, Wire};
//!
//! // The world plays a server, and sends its own line first.
//! let ours = Identification::new("2.0", "OpenSSH_9.6", None).unwrap();
//! assert_eq!(ours.to_bytes().unwrap(), b"SSH-2.0-OpenSSH_9.6\r\n");
//!
//! // The client's line and its KEXINIT arrive in one read.
//! let theirs = KexInit {
//!     cookie: [7; 16],
//!     kex_algorithms: vec!["curve25519-sha256".to_string()],
//!     ..KexInit::default()
//! };
//! let mut bytes = b"SSH-2.0-paramiko_3.4.0\r\n".to_vec();
//! bytes.extend(Packet::from_message(&Message::KexInit(theirs.clone())).unwrap().to_bytes().unwrap());
//!
//! let mut stream = Stream::new(Events::new());
//! stream.push(&bytes);
//! let Some(Ok(Event::Version(client))) = stream.next() else { panic!() };
//! assert_eq!(client.software(), "paramiko_3.4.0");
//! let Some(Ok(Event::Packet { sequence: 0, packet })) = stream.next() else { panic!() };
//! assert_eq!(Message::parse(&packet.payload), Ok(Message::KexInit(theirs.clone())));
//! assert!(stream.next().is_none());
//!
//! // The key exchange is the client's first choice the server also has.
//! let server = ["ecdh-sha2-nistp256".to_string(), "curve25519-sha256".to_string()];
//! assert_eq!(KexInit::choose(&theirs.kex_algorithms, &server), Some("curve25519-sha256"));
//!
//! // Frames::<Packet> are padded to a multiple of 8 bytes.
//! assert_eq!(Packet::new(vec![21]).to_bytes().unwrap().len(), 16);
//! ```

use fictionet::stdlib::codec::Prefixed;
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Step, Wire, Reader as ByteReader, Truncated};

/// The TCP port SSH servers listen on.
pub const PORT: u16 = 22;
/// The longest version line, counting its CR LF.
pub const MAX_VERSION_LINE: usize = 255;
/// The longest line a server may send before its version line, counting
/// its line ending. RFC 4253 sets no limit, so this one is generous.
pub const MAX_BANNER_LINE: usize = 1024;
/// The most lines a [`Events`] reads before the version line.
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
/// The longest algorithm name or service name.
pub const MAX_NAME: usize = 64;
/// The longest name-list a KEXINIT can carry, in bytes: what is left of
/// the largest payload after the fixed fields and nine empty lists. RFC
/// 4253 sets no smaller limit. A writer shares this room among the ten
/// lists.
pub const MAX_NAME_LIST: usize = MAX_PAYLOAD - KEXINIT_FIXED;
/// The longest text, or language tag, a DISCONNECT or DEBUG message can
/// carry, in bytes: what is left of the largest payload after a DEBUG's
/// fixed fields. RFC 4253 sets no smaller limit. A writer shares this room
/// between the text and its language tag.
pub const MAX_TEXT: usize = MAX_PAYLOAD - DEBUG_FIXED;
/// The bytes of a KEXINIT that are not inside its name-lists.
const KEXINIT_FIXED: usize = 1 + 16 + 10 * 4 + 1 + 4;
/// The bytes of a DEBUG that are not inside its two strings.
const DEBUG_FIXED: usize = 1 + 1 + 4 + 4;
/// The bytes of a DISCONNECT that are not inside its two strings.
const DISCONNECT_FIXED: usize = 1 + 4 + 4 + 4;
/// The longest data an IGNORE message may carry: what is left of the
/// largest payload after the message number and the string length.
pub const MAX_DATA: usize = MAX_PAYLOAD - 5;

/// Message numbers this module reads and writes.
pub mod msg {
    /// End the connection with a reason.
    pub const DISCONNECT: u8 = 1;
    /// Data the peer ignores.
    pub const IGNORE: u8 = 2;
    /// The sequence number of an unsupported packet.
    pub const UNIMPLEMENTED: u8 = 3;
    /// A diagnostic message.
    pub const DEBUG: u8 = 4;
    /// Request an SSH service.
    pub const SERVICE_REQUEST: u8 = 5;
    /// Accept an SSH service.
    pub const SERVICE_ACCEPT: u8 = 6;
    /// Propose key exchange algorithms.
    pub const KEXINIT: u8 = 20;
    /// Activate the negotiated keys.
    pub const NEWKEYS: u8 = 21;
}

/// Why bytes are not SSH, or not the data or message expected, or why a
/// value cannot be written as it stands. After an error from [`Lines`],
/// [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames) or [`Events`] the stream cannot be read any further, and a
/// real peer closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
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
    /// The bytes ended before a line's LF, a whole binary packet, or a
    /// field.
    Truncated,
    /// Bytes follow the first line or packet, or the last field.
    Trailing,
    /// The payload was empty, so it had no message number.
    Empty,
    /// A string, text or name-list was longer than its limit, or a payload
    /// longer than [`MAX_PAYLOAD`].
    FieldTooLong,
    /// A text field was not UTF-8.
    Utf8,
    /// A name-list held an empty name, a name longer than [`MAX_NAME`], a
    /// name with a byte outside printable US-ASCII, or a name whose `@`
    /// is repeated or has no text on one side.
    Name,
    /// An mpint had a leading 0x00 or 0xff byte it did not need.
    Mpint,
    /// A field, variant, or length cannot be written without changing it.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::LineTooLong => f.write_str("line too long"),
            Error::Nul => f.write_str("NUL byte in a line"),
            Error::BadVersion => f.write_str("malformed SSH version line"),
            Error::TooManyLines => f.write_str("too many lines before the version line"),
            Error::PacketLength(n) => write!(f, "packet length {n} not allowed"),
            Error::Padding(n) => write!(f, "padding length {n} not allowed"),
            Error::PayloadTooLong(n) => write!(f, "payload of {n} bytes, over {MAX_PAYLOAD}"),
            Error::Truncated => f.write_str("SSH line, packet or field cut short"),
            Error::Trailing => f.write_str("bytes follow the SSH line, packet or last field"),
            Error::Empty => f.write_str("empty payload"),
            Error::FieldTooLong => f.write_str("field too long"),
            Error::Utf8 => f.write_str("text is not UTF-8"),
            Error::Name => f.write_str("malformed name-list"),
            Error::Mpint => f.write_str("mpint not in its shortest form"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
        }
    }
}

impl std::error::Error for Error {}

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
    /// [`Error::BadVersion`] or [`Error::LineTooLong`].
    pub fn new(
        proto: &str,
        software: &str,
        comments: Option<&str>,
    ) -> Result<Identification, Error> {
        Self::with_ending(proto, software, comments, 2)
    }

    fn with_ending(proto: &str, software: &str, comments: Option<&str>, ending: usize) -> Result<Self, Error> {
        // Everything is checked before anything is copied, so a long part
        // costs no allocation.
        if !version_part(proto.as_bytes()) || !version_part(software.as_bytes()) {
            return Err(Error::BadVersion);
        }
        if let Some(c) = comments
            && c.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
        {
            return Err(Error::BadVersion);
        }
        if line_len(proto, software, comments).saturating_sub(2 - ending) > MAX_VERSION_LINE {
            return Err(Error::LineTooLong);
        }
        Ok(Identification {
            proto: proto.to_string(),
            software: software.to_string(),
            comments: comments.map(str::to_string),
        })
    }

    /// Reads a version line's text, without its line ending.
    fn parse_text(line: &[u8], ending: usize) -> Result<Identification, Error> {
        let rest = line.strip_prefix(b"SSH-").ok_or(Error::BadVersion)?;
        let dash = rest
            .iter()
            .position(|&b| b == b'-')
            .ok_or(Error::BadVersion)?;
        let (proto, rest) = (&rest[..dash], &rest[dash + 1..]);
        let (software, comments) = match rest.iter().position(|&b| b == b' ') {
            Some(sp) => (&rest[..sp], Some(&rest[sp + 1..])),
            None => (rest, None),
        };
        fn text(b: &[u8]) -> Result<&str, Error> { core::str::from_utf8(b).map_err(|_| Error::BadVersion) }
        let comments = match comments {
            Some(c) => Some(text(c)?),
            None => None,
        };
        Identification::with_ending(text(proto)?, text(software)?, comments, ending)
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

    fn len(&self) -> usize {
        line_len(&self.proto, &self.software, self.comments.as_deref())
    }
}

/// The length of a version line with these parts, counting its CR LF.
fn line_len(proto: &str, software: &str, comments: Option<&str>) -> usize {
    let comments = comments.map_or(0, |c| c.len().saturating_add(1));
    7usize
        .saturating_add(proto.len())
        .saturating_add(software.len())
        .saturating_add(comments)
}

#[cfg(test)]
std::thread_local! {
    // Count scan visits inside the reader so the linear-time test needs no timing bound.
    static LINE_BYTES_SCANNED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
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
            .is_some_and(|new| !new.iter().any(|&c| {
                #[cfg(test)]
                LINE_BYTES_SCANNED.with(|count| count.set(count.get().saturating_add(1)));
                c == b'\n' || c == 0
            }))
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
fn parse_line(b: &[u8]) -> Result<Option<(Line, usize)>, Error> {
    let limit = if b.starts_with(b"SSH-") {
        MAX_VERSION_LINE
    } else {
        MAX_BANNER_LINE
    };
    for (i, &c) in b.iter().enumerate() {
        let len = i + 1;
        if c == 0 {
            return Err(Error::Nul);
        }
        if c == b'\n' {
            let text = &b[..i];
            let text = text.strip_suffix(b"\r").unwrap_or(text);
            let line = if text.starts_with(b"SSH-") {
                Line::Version(Identification::parse_text(text, len - text.len())?)
            } else {
                Line::Banner(text.to_vec())
            };
            return Ok(Some((line, len)));
        }
        if len >= limit {
            return Err(Error::LineTooLong);
        }
    }
    Ok(None)
}

impl Wire for Identification {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete identification line. Refuses banners, invalid parts,
    /// excess length, truncation, and bytes after the line ending.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Line::parse(bytes)? {
            Line::Version(id) => Ok(id),
            Line::Banner(_) => Err(Error::BadVersion),
        }
    }

    /// Appends the identification with CR LF, or LF when only that fits.
    /// Refuses allocation failure.
    /// Construction already checks its fields and length.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.try_reserve_exact(self.len())
            .map_err(|_| Error::Unwritable)?;
        out.extend_from_slice(b"SSH-");
        out.extend_from_slice(self.proto.as_bytes());
        out.push(b'-');
        out.extend_from_slice(self.software.as_bytes());
        if let Some(c) = &self.comments {
            out.push(b' ');
            out.extend_from_slice(c.as_bytes());
        }
        out.extend_from_slice(if self.len() <= MAX_VERSION_LINE { b"\r\n" } else { b"\n" });
        Ok(())
    }
}

impl Wire for Line {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one line. Accepts LF or CR LF. Refuses NUL, invalid
    /// identification fields, excess length, truncation, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match parse_line(bytes)? {
            Some((line, used)) if used == bytes.len() => Ok(line),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Truncated),
        }
    }

    /// Appends one line. Refuses LF or NUL inside a banner, an `SSH-` banner,
    /// and lengths over the line limit. Uses LF alone for a full-length banner.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Version(id) => id.write(out),
            Self::Banner(text) => {
                if text.len() >= MAX_BANNER_LINE
                    || text.starts_with(b"SSH-")
                    || text.iter().any(|b| matches!(b, 0 | b'\n'))
                {
                    return Err(Error::Unwritable);
                }
                let ending: &[u8] = if text.len() + 2 <= MAX_BANNER_LINE {
                    b"\r\n"
                } else if text.last() != Some(&b'\r') {
                    b"\n"
                } else {
                    return Err(Error::Unwritable);
                };
                out.try_reserve_exact(text.len() + ending.len())
                    .map_err(|_| Error::Unwritable)?;
                out.extend_from_slice(text);
                out.extend_from_slice(ending);
                Ok(())
            }
        }
    }
}

/// Reads lines before the SSH binary transport starts. Retains only a scan offset.
#[derive(Clone, Debug, Default)]
pub struct Lines {
    scanned: usize,
}

impl Lines {
    /// Starts at the beginning of a line.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Decode for Lines {
    type Item = Line;
    type Error = Error;
    const NAME: &'static str = "SSH lines";
    fn capacity(&self) -> usize {
        MAX_BANNER_LINE
    }
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Line>, Error> {
        if line_pending(input, self.scanned) {
            self.scanned = input.len();
            return Ok(Step::Need);
        }
        self.scanned = 0;
        Ok(match parse_line(input)? {
            Some((line, used)) => Step::Item(line, used),
            None => Step::Need,
        })
    }
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
    /// Creates a packet with the least allowed zero padding. An oversized
    /// payload stays intact and will be refused by its writer.
    pub fn new(payload: Vec<u8>) -> Packet {
        let padding = usize::from(MIN_PADDING)
            + (BLOCK - (5 + payload.len() % BLOCK + usize::from(MIN_PADDING)) % BLOCK) % BLOCK;
        Packet {
            payload,
            padding: vec![0; padding],
        }
    }

    /// Builds a packet around a message. Refuses values its message writer refuses.
    pub fn from_message(message: &Message) -> Result<Self, Error> {
        Ok(Self::new(message.to_bytes()?))
    }

    /// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the packet and how many bytes
    /// of `b` it took. A bad length is known from the first 4 bytes, and a
    /// bad padding length from the fifth.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Packet, usize)>, Error> {
        let Some(head) = b.get(..4) else {
            return Ok(None);
        };
        let length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if length < (MIN_PACKET - 4) as u32
            || length > MAX_PACKET_LENGTH
            || !(length as usize + 4).is_multiple_of(BLOCK)
        {
            return Err(Error::PacketLength(length));
        }
        let Some(&pad) = b.get(4) else {
            return Ok(None);
        };
        if pad < MIN_PADDING || u32::from(pad) >= length {
            return Err(Error::Padding(pad));
        }
        let payload_len = length - 1 - u32::from(pad);
        if payload_len as usize > MAX_PAYLOAD {
            return Err(Error::PayloadTooLong(payload_len));
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
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one binary packet. Refuses invalid length or padding,
    /// excess payload, truncation, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Packet::parse_prefix(bytes)? {
            Some((packet, used)) if used == bytes.len() => Ok(packet),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Truncated),
        }
    }

    /// Appends the packet with its exact padding. Refuses padding outside
    /// 4 to 255 bytes, a total not divisible by 8, and oversized payloads.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let pad = u8::try_from(self.padding.len()).map_err(|_| Error::Unwritable)?;
        let total = 5usize
            .checked_add(self.payload.len())
            .and_then(|n| n.checked_add(self.padding.len()))
            .ok_or(Error::Unwritable)?;
        if self.payload.len() > MAX_PAYLOAD
            || pad < MIN_PADDING
            || !(MIN_PACKET..=MAX_PACKET).contains(&total)
            || !total.is_multiple_of(BLOCK)
        {
            return Err(Error::Unwritable);
        }
        let length = u32::try_from(total.saturating_sub(4)).map_err(|_| Error::Unwritable)?;
        out.try_reserve_exact(total)
            .map_err(|_| Error::Unwritable)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.push(pad);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.padding);
        Ok(())
    }
}

/// Reads cleartext binary packets after the SSH version exchange.
///
/// This decoder owns no input. Its capacity is the configured packet
/// limit, including the length field. Oversized packets are refused from
/// their four-byte length. Partial packets return [`Step::Need`], including
/// at EOF, so [`fictionet::stdlib::codec::Stream`] reports truncation.
/// Use [`Lines`] or [`Events`] for the bounded version exchange.
/// Stop using this framer when keys take effect. It performs no encryption
/// or MAC processing. Payload messages are parsed separately by [`Message::parse`].
impl Prefixed for Packet {
    type Item = Packet;
    type Error = Error;
    type Limit = usize;
    const NAME: &'static str = "SSH cleartext packets";

    #[inline]
    fn default_limit() -> Self::Limit { MAX_PACKET }

    #[inline]
    fn normalize_limit(limit: Self::Limit) -> Self::Limit { limit.clamp(MIN_PACKET, MAX_PACKET) }

    #[inline]
    fn capacity(limit: &Self::Limit) -> usize { *limit }

    #[inline]
    fn parse_prefix(input: &[u8], limit: &Self::Limit) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        if let Some(&[a, b, c, d]) = input.get(..4) {
            let length = u32::from_be_bytes([a, b, c, d]);
            let total = usize::try_from(length).ok().and_then(|n| n.checked_add(4));
            if total.is_none_or(|n| n > limit) {
                return Err(Error::PacketLength(length));
            }
        }
        Packet::parse_prefix(input)
    }
}


/// What a [`Events`] finds in the stream.
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

/// Reads the version exchange, then binary packets with sequence numbers.
/// The decoder retains counters only. Its input capacity is [`MAX_PACKET`].
/// Stop at NEWKEYS before encryption takes effect.
#[derive(Clone, Debug, Default)]
pub struct Events {
    lines: Lines,
    count: usize,
    packets: bool,
    sequence: u32,
}

impl Events {
    /// Starts with the version exchange.
    pub fn new() -> Self {
        Self::default()
    }
    /// Starts after a version exchange already handled by the caller.
    pub fn after_version() -> Self {
        Self {
            packets: true,
            ..Self::default()
        }
    }
    /// Whether the identification has been read, so packets come next.
    pub fn in_packets(&self) -> bool {
        self.packets
    }
    /// The sequence number of the next binary packet.
    pub fn next_sequence(&self) -> u32 {
        self.sequence
    }
}

impl Decode for Events {
    type Item = Event;
    type Error = Error;
    const NAME: &'static str = "SSH";
    fn capacity(&self) -> usize {
        MAX_PACKET
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Event>, Error> {
        if self.packets {
            return Ok(match Packet::parse_prefix(input)? {
                Some((packet, used)) => {
                    let sequence = self.sequence;
                    self.sequence = sequence.wrapping_add(1);
                    Step::Item(Event::Packet { sequence, packet }, used)
                }
                None => Step::Need,
            });
        }
        Ok(match self.lines.decode(input, eof)? {
            Step::Item(Line::Version(id), used) => {
                self.packets = true;
                Step::Item(Event::Version(id), used)
            }
            Step::Item(Line::Banner(text), used) => {
                if self.count >= MAX_BANNER_LINES {
                    return Err(Error::TooManyLines);
                }
                self.count += 1;
                Step::Item(Event::Banner(text), used)
            }
            _ => Step::Need,
        })
    }
}

/// A multiple-precision integer, in two's complement, big-endian, in its
/// shortest form: zero has no bytes, and there is no leading 0x00 or 0xff
/// byte that the sign does not need.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mpint(Vec<u8>);

impl Mpint {
    /// The integer whose two's complement bytes, most significant first,
    /// are `b`. Extra sign bytes are removed. Refuses more than
    /// [`MAX_PAYLOAD`] significant bytes.
    pub fn from_signed_bytes(b: &[u8]) -> Result<Mpint, Error> {
        let bytes = shortest(b);
        if bytes.len() > MAX_PAYLOAD {
            return Err(Error::Unwritable);
        }
        Ok(Mpint(bytes.to_vec()))
    }

    /// The non-negative integer whose bytes, most significant first, are
    /// `b`. Refuses more than [`MAX_PAYLOAD`] significant bytes, including a sign byte.
    pub fn from_unsigned_bytes(b: &[u8]) -> Result<Mpint, Error> {
        let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        let b = &b[start..];
        let size = b
            .len()
            .saturating_add(usize::from(b.first().is_some_and(|&x| x >= 0x80)));
        if size > MAX_PAYLOAD {
            return Err(Error::Unwritable);
        }
        let mut out = Vec::with_capacity(size);
        if b.first().is_some_and(|&x| x >= 0x80) {
            out.push(0);
        }
        out.extend_from_slice(b);
        Ok(Mpint(out))
    }

    /// The integer `v`.
    pub fn from_i64(v: i64) -> Mpint {
        Mpint(shortest(&v.to_be_bytes()).to_vec())
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

/// Reads the RFC 4251 data types from the front of a byte slice. What it
/// allocates grows in proportion to the bytes it reads: a string or mpint
/// is a copy of its bytes, and each name in a name-list costs one `String`
/// for at least two bytes of input.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    cursor: ByteReader<'a>,
}

impl<'a> Reader<'a> {
    /// A reader over `b`.
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { cursor: ByteReader::new(b) }
    }

    /// The next `n` bytes.
    #[inline]
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.cursor.take(n).map_err(Error::from)
    }

    /// A `byte`.
    #[inline]
    pub fn byte(&mut self) -> Result<u8, Error> {
        self.cursor.u8().map_err(Error::from)
    }

    /// A `boolean`: any byte but 0 is true.
    pub fn boolean(&mut self) -> Result<bool, Error> {
        Ok(self.byte()? != 0)
    }

    /// A `uint32`, most significant byte first.
    #[inline]
    pub fn uint32(&mut self) -> Result<u32, Error> {
        self.cursor.u32_be().map_err(Error::from)
    }

    /// A `uint64`, most significant byte first.
    #[inline]
    pub fn uint64(&mut self) -> Result<u64, Error> {
        self.cursor.u64_be().map_err(Error::from)
    }

    /// A `string`: a `uint32` length, then that many bytes.
    pub fn string(&mut self) -> Result<&'a [u8], Error> {
        let n = self.uint32()?;
        self.take(usize::try_from(n).map_err(|_| Error::Truncated)?)
    }

    /// A `string` holding UTF-8 text of at most `max` bytes, bounded by [`MAX_PAYLOAD`].
    pub fn text(&mut self, max: usize) -> Result<String, Error> {
        let b = self.string()?;
        if b.len() > max.min(MAX_PAYLOAD) {
            return Err(Error::FieldTooLong);
        }
        String::from_utf8(b.to_vec()).map_err(|_| Error::Utf8)
    }

    /// An `mpint` in its shortest form, with at most [`MAX_PAYLOAD`] content bytes.
    pub fn mpint(&mut self) -> Result<Mpint, Error> {
        let b = self.string()?;
        if b.len() > MAX_PAYLOAD {
            return Err(Error::FieldTooLong);
        }
        if shortest(b).len() != b.len() {
            return Err(Error::Mpint);
        }
        Ok(Mpint(b.to_vec()))
    }

    /// A `name-list` of at most `max` bytes, bounded by [`MAX_PAYLOAD`]. An
    /// empty string is an empty list. Each name must follow the RFC 4251
    /// rules for algorithm names: 1 to [`MAX_NAME`] bytes of printable
    /// US-ASCII, and at most one `@`, with text on both sides of it.
    pub fn name_list(&mut self, max: usize) -> Result<Vec<String>, Error> {
        self.list(max, is_name)
    }

    /// A name-list whose names pass `ok`.
    fn list(&mut self, max: usize, ok: fn(&[u8]) -> bool) -> Result<Vec<String>, Error> {
        let b = self.string()?;
        if b.len() > max.min(MAX_PAYLOAD) {
            return Err(Error::FieldTooLong);
        }
        if b.is_empty() {
            return Ok(Vec::new());
        }
        b.split(|&c| c == b',')
            .map(|name| {
                if ok(name) {
                    String::from_utf8(name.to_vec()).map_err(|_| Error::Name)
                } else {
                    Err(Error::Name)
                }
            })
            .collect()
    }

    /// The bytes not yet read.
    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        self.cursor.clone().rest()
    }

    /// Checks that every byte has been read.
    #[inline]
    pub fn finish(&self) -> Result<(), Error> {
        self.cursor.finish().map_err(|_| Error::Trailing)
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

/// Whether `b` may be a language tag in a KEXINIT's name-list. RFC 4253
/// section 7.1 names RFC 3066 tags, which may be longer than an algorithm
/// name, so only the name-list rules of RFC 4251 section 5 apply: at least
/// one byte of printable US-ASCII, with no comma.
fn is_tag(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&c| (0x21..=0x7e).contains(&c) && c != b',')
}

fn put_boolean(out: &mut Vec<u8>, v: bool) {
    out.push(u8::from(v));
}
fn put_uint32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_uint32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn list_len(names: &[String], ok: fn(&[u8]) -> bool) -> Result<usize, Error> {
    let mut size = names.len().saturating_sub(1);
    for name in names {
        size = size.saturating_add(name.len());
        if size > MAX_NAME_LIST || !ok(name.as_bytes()) {
            return Err(Error::Unwritable);
        }
    }
    Ok(size)
}

fn write_list(out: &mut Vec<u8>, names: &[String], len: usize) {
    put_uint32(out, len as u32);
    for (i, name) in names.iter().enumerate() {
        if i != 0 {
            out.push(b',');
        }
        out.extend_from_slice(name.as_bytes());
    }
}

macro_rules! scalar_wire {
    ($name:ident, $value:ty, $read:ident, $size:expr, $bytes:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(#[doc = "The field's value."] pub $value);
        impl Wire for $name {
            type ParseError = Error;
            type WriteError = Error;
            /// Reads one field. Refuses short input and trailing bytes.
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                let mut reader = Reader::new(bytes);
                let value = reader.$read()?;
                reader.finish()?;
                Ok(Self(value))
            }
            /// Appends the field. Refuses allocation failure.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                out.try_reserve_exact($size)
                    .map_err(|_| Error::Unwritable)?;
                out.extend_from_slice(&($bytes)(self.0));
                Ok(())
            }
        }
    };
}
scalar_wire!(Byte, u8, byte, 1, |v| [v], "An SSH byte field.");
scalar_wire!(
    Boolean,
    bool,
    boolean,
    1,
    |v: bool| [u8::from(v)],
    "An SSH boolean field. Any nonzero input byte is true."
);
scalar_wire!(
    Uint32,
    u32,
    uint32,
    4,
    u32::to_be_bytes,
    "An SSH unsigned 32-bit field."
);
scalar_wire!(
    Uint64,
    u64,
    uint64,
    8,
    u64::to_be_bytes,
    "An SSH unsigned 64-bit field."
);

/// An SSH length-prefixed string, bounded by [`MAX_PAYLOAD`] content bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshString(
    /// The string's bytes.
    pub Vec<u8>,
);

impl Wire for SshString {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one string. Refuses truncation, trailing bytes, and excess content.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let value = r.string()?;
        if value.len() > MAX_PAYLOAD {
            return Err(Error::FieldTooLong);
        }
        r.finish()?;
        Ok(Self(value.to_vec()))
    }
    /// Appends one string. Refuses content over [`MAX_PAYLOAD`] bytes.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_string(&self.0, out)
    }
}

fn write_string(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Unwritable);
    }
    out.try_reserve_exact(4 + bytes.len())
        .map_err(|_| Error::Unwritable)?;
    put_string(out, bytes);
    Ok(())
}

impl Wire for Mpint {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one signed integer. Refuses nonminimal encoding, excess content,
    /// truncation, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let value = r.mpint()?;
        r.finish()?;
        Ok(value)
    }
    /// Appends one integer. Refuses content over [`MAX_PAYLOAD`] bytes.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_string(&self.0, out)
    }
}

/// A comma-separated list of SSH algorithm names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameList(
    /// The names, in preference order.
    pub Vec<String>,
);

impl Wire for NameList {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one list. Refuses invalid names, excess length, truncation,
    /// and bytes after the list.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let names = r.name_list(MAX_NAME_LIST)?;
        r.finish()?;
        Ok(Self(names))
    }
    /// Appends one list. Refuses invalid names and lengths over [`MAX_NAME_LIST`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let len = list_len(&self.0, is_name)?;
        out.try_reserve_exact(4 + len)
            .map_err(|_| Error::Unwritable)?;
        write_list(out, &self.0, len);
        Ok(())
    }
}

/// The reason codes a DISCONNECT gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The host is not allowed to connect.
    HostNotAllowedToConnect,
    /// The peer violated the SSH protocol.
    ProtocolError,
    /// The key exchange failed.
    KeyExchangeFailed,
    /// A message authentication code did not match.
    MacError,
    /// Packet decompression failed.
    CompressionError,
    /// The requested service is unavailable.
    ServiceNotAvailable,
    /// The peer's protocol version is unsupported.
    ProtocolVersionNotSupported,
    /// The host key could not be verified.
    HostKeyNotVerifiable,
    /// The connection was lost.
    ConnectionLost,
    /// The application ended the connection.
    ByApplication,
    /// The server has too many connections.
    TooManyConnections,
    /// The user canceled authentication.
    AuthCancelledByUser,
    /// No authentication methods remain.
    NoMoreAuthMethodsAvailable,
    /// The user name is not allowed.
    IllegalUserName,
    /// Any other code, including 4, which RFC 4253 reserves.
    /// [`DisconnectReason::from_code`] never gives this for a code that has
    /// a name above. Writers refuse aliases such as `Other(2)`.
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

/// One KEXINIT name-list and the check each of its names must pass.
type KexList<'a> = (&'a Vec<String>, fn(&[u8]) -> bool);

impl KexInit {
    /// The first algorithm in the client's list that is also in the
    /// server's. For ciphers, MACs and compression this is the whole rule
    /// of RFC 4253 section 7.1, so it is the algorithm both sides use. For
    /// key exchange and host keys that section adds more: if both first
    /// choices match, that key exchange is used, and otherwise a key
    /// exchange needs a host key algorithm both sides have that can sign or
    /// encrypt as it requires. This function knows nothing of what an
    /// algorithm can do, so world code that offers key exchanges with
    /// different needs checks those itself. It takes time in proportion to
    /// the two lists' lengths together.
    pub fn choose<'a>(client: &'a [String], server: &[String]) -> Option<&'a str> {
        let server: std::collections::HashSet<&str> = server.iter().map(String::as_str).collect();
        client
            .iter()
            .map(String::as_str)
            .find(|c| server.contains(c))
    }

    /// The ten name-lists in wire order, each with the check its names
    /// must pass: algorithm names for the first eight, language tags for
    /// the last two.
    fn lists(&self) -> [KexList<'_>; 10] {
        [
            (&self.kex_algorithms, is_name),
            (&self.server_host_key_algorithms, is_name),
            (&self.encryption_client_to_server, is_name),
            (&self.encryption_server_to_client, is_name),
            (&self.mac_client_to_server, is_name),
            (&self.mac_server_to_client, is_name),
            (&self.compression_client_to_server, is_name),
            (&self.compression_server_to_client, is_name),
            (&self.languages_client_to_server, is_tag),
            (&self.languages_server_to_client, is_tag),
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
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the message in a packet's payload. Refuses excess length,
    /// incomplete fields, trailing bytes, invalid UTF-8, and malformed lists.
    fn parse(payload: &[u8]) -> Result<Message, Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::FieldTooLong);
        }
        let (&number, data) = payload.split_first().ok_or(Error::Empty)?;
        let mut r = Reader::new(data);
        let m = match number {
            msg::DISCONNECT => Message::Disconnect {
                reason: DisconnectReason::from_code(r.uint32()?),
                description: r.text(MAX_TEXT)?,
                language: r.text(MAX_TEXT)?,
            },
            msg::IGNORE => Message::Ignore(r.string()?.to_vec()),
            msg::UNIMPLEMENTED => Message::Unimplemented(r.uint32()?),
            msg::DEBUG => Message::Debug {
                always_display: r.boolean()?,
                message: r.text(MAX_TEXT)?,
                language: r.text(MAX_TEXT)?,
            },
            msg::SERVICE_REQUEST => Message::ServiceRequest(r.text(MAX_NAME)?),
            msg::SERVICE_ACCEPT => Message::ServiceAccept(r.text(MAX_NAME)?),
            msg::KEXINIT => {
                let mut cookie = [0u8; 16];
                cookie.copy_from_slice(r.take(16)?);
                let k = KexInit {
                    cookie,
                    kex_algorithms: r.list(MAX_NAME_LIST, is_name)?,
                    server_host_key_algorithms: r.list(MAX_NAME_LIST, is_name)?,
                    encryption_client_to_server: r.list(MAX_NAME_LIST, is_name)?,
                    encryption_server_to_client: r.list(MAX_NAME_LIST, is_name)?,
                    mac_client_to_server: r.list(MAX_NAME_LIST, is_name)?,
                    mac_server_to_client: r.list(MAX_NAME_LIST, is_name)?,
                    compression_client_to_server: r.list(MAX_NAME_LIST, is_name)?,
                    compression_server_to_client: r.list(MAX_NAME_LIST, is_name)?,
                    languages_client_to_server: r.list(MAX_NAME_LIST, is_tag)?,
                    languages_server_to_client: r.list(MAX_NAME_LIST, is_tag)?,
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

    /// Appends the payload. Refuses oversized fields or lists, invalid names,
    /// known-number `Other` variants, and values exceeding [`MAX_PAYLOAD`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let (size, list_lengths) = self.encoded_lengths()?;
        out.try_reserve_exact(size)
            .map_err(|_| Error::Unwritable)?;
        out.push(self.number());
        match self {
            Self::Disconnect {
                reason,
                description,
                language,
            } => {
                put_uint32(out, reason.code());
                put_string(out, description.as_bytes());
                put_string(out, language.as_bytes());
            }
            Self::Ignore(data) => put_string(out, data),
            Self::Unimplemented(sequence) => put_uint32(out, *sequence),
            Self::Debug {
                always_display,
                message,
                language,
            } => {
                put_boolean(out, *always_display);
                put_string(out, message.as_bytes());
                put_string(out, language.as_bytes());
            }
            Self::ServiceRequest(name) | Self::ServiceAccept(name) => {
                put_string(out, name.as_bytes())
            }
            Self::KexInit(k) => {
                out.extend_from_slice(&k.cookie);
                for ((list, _), len) in k.lists().into_iter().zip(list_lengths) {
                    write_list(out, list, len);
                }
                put_boolean(out, k.first_kex_packet_follows);
                put_uint32(out, k.reserved);
            }
            Self::NewKeys => {}
            Self::Other { data, .. } => out.extend_from_slice(data),
        }
        Ok(())
    }
}

impl Message {
    /// Checks the payload size and all ten KEXINIT list lengths before writing.
    fn encoded_lengths(&self) -> Result<(usize, [usize; 10]), Error> {
        let mut list_lengths = [0; 10];
        let size = match self {
            Self::Disconnect {
                reason,
                description,
                language,
            } => {
                if DisconnectReason::from_code(reason.code()) != *reason
                    || description.len() > MAX_TEXT
                    || language.len() > MAX_TEXT
                {
                    return Err(Error::Unwritable);
                }
                DISCONNECT_FIXED
                    .saturating_add(description.len())
                    .saturating_add(language.len())
            }
            Self::Debug {
                message, language, ..
            } => {
                if message.len() > MAX_TEXT || language.len() > MAX_TEXT {
                    return Err(Error::Unwritable);
                }
                DEBUG_FIXED
                    .saturating_add(message.len())
                    .saturating_add(language.len())
            }
            Self::Ignore(data) => 5usize.saturating_add(data.len()),
            Self::Unimplemented(_) => 5,
            Self::ServiceRequest(name) | Self::ServiceAccept(name) => {
                if name.len() > MAX_NAME {
                    return Err(Error::Unwritable);
                }
                5 + name.len()
            }
            Self::KexInit(k) => {
                let mut len = KEXINIT_FIXED;
                for ((list, ok), length) in k.lists().into_iter().zip(&mut list_lengths) {
                    *length = list_len(list, ok)?;
                    len = len.saturating_add(*length);
                }
                len
            }
            Self::NewKeys => 1,
            Self::Other { number, data } => {
                if is_known(*number) {
                    return Err(Error::Unwritable);
                }
                1usize.saturating_add(data.len())
            }
        };
        if size > MAX_PAYLOAD {
            Err(Error::Unwritable)
        } else {
            Ok((size, list_lengths))
        }
    }
}

/// Whether [`Message::parse`] reads message number `n` as its own variant.
fn is_known(n: u8) -> bool {
    matches!(n, 1..=6 | 20 | 21)
}

impl From<Truncated> for Error {
    #[inline]
    fn from(_: Truncated) -> Self { Error::Truncated }
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream, pump,
    };
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{chunks, decode_all, mutate};
    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
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
    fn review_version_line_endings_at_limit() {
        for ending in ["\n", "\r\n"] {
            let text = format!("SSH-2.0-{}", "x".repeat(MAX_VERSION_LINE - 8 - ending.len()));
            let bytes = format!("{text}{ending}").into_bytes();
            assert_eq!(bytes.len(), MAX_VERSION_LINE);
            let id = Identification::parse(&bytes).unwrap();
            assert_eq!(Identification::parse(&id.to_bytes().unwrap()), Ok(id));
            let long = format!("{text}x{ending}");
            assert_eq!(Identification::parse(long.as_bytes()), Err(Error::LineTooLong));
        }
    }

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
            let m = Mpint::from_signed_bytes(value).unwrap();
            assert_eq!(m.as_bytes(), value);
            let mut out = Vec::new();
            m.write(&mut out).unwrap();
            assert_eq!(out, wire);
            let mut r = Reader::new(wire);
            assert_eq!(r.mpint(), Ok(m));
            assert_eq!(r.finish(), Ok(()));
        }
        assert_eq!(Mpint::from_i64(0).as_bytes(), &[] as &[u8]);
        assert_eq!(
            Mpint::from_unsigned_bytes(&[0x80]).unwrap().as_bytes(),
            &[0x00, 0x80]
        );
        assert_eq!(Mpint::from_i64(-0x1234).as_bytes(), &[0xed, 0xcc]);
        assert_eq!(
            Mpint::from_i64(-0xdeadbeef).as_bytes(),
            &[0xff, 0x21, 0x52, 0x41, 0x11]
        );
        assert_eq!(
            Mpint::from_unsigned_bytes(&[0, 0, 0x09, 0xa3])
                .unwrap()
                .as_bytes(),
            &[0x09, 0xa3]
        );
        assert_eq!(
            Mpint::from_unsigned_bytes(&[0, 0]).unwrap().as_bytes(),
            &[] as &[u8]
        );
        assert_eq!(
            Mpint::from_signed_bytes(&[0xff, 0xff]).unwrap().as_bytes(),
            &[0xff]
        );
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
            Mpint::from_unsigned_bytes(&[0x80, 0, 0, 0, 0, 0, 0, 0])
                .unwrap()
                .to_i64(),
            None
        );
        // Leading bytes the sign does not need are refused.
        for wire in [
            &[0, 0, 0, 1, 0][..],
            &[0, 0, 0, 2, 0, 0x7f],
            &[0, 0, 0, 2, 0xff, 0x80],
        ] {
            assert_eq!(Reader::new(wire).mpint(), Err(Error::Mpint));
        }
    }

    #[test]
    fn plain_types() {
        let mut out = Vec::new();
        Byte(7).write(&mut out).unwrap();
        Boolean(true).write(&mut out).unwrap();
        Boolean(false).write(&mut out).unwrap();
        Uint32(0x29b7f4aa).write(&mut out).unwrap();
        Uint64(0x0102030405060708).write(&mut out).unwrap();
        SshString((b"testing").to_vec()).write(&mut out).unwrap();
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
        assert_eq!(r.byte(), Err(Error::Truncated));
        // Any byte but 0 is true.
        assert_eq!(Reader::new(&[0x42]).boolean(), Ok(true));
        // A length past the end, and the largest length.
        assert_eq!(
            Reader::new(&[0, 0, 0, 5, 1]).string(),
            Err(Error::Truncated)
        );
        assert_eq!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).string(),
            Err(Error::Truncated)
        );
        assert_eq!(
            Reader::new(&[0, 0, 0, 1, 0xff]).text(10),
            Err(Error::Utf8)
        );
        assert_eq!(
            Reader::new(&[0, 0, 0, 2, b'a', b'b']).text(1),
            Err(Error::FieldTooLong)
        );
        assert_eq!(Reader::new(&[1]).finish(), Err(Error::Trailing));
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
            assert_eq!(got, Err(Error::Truncated), "{n}");
        }
    }

    #[test]
    fn message_wire_examples() {
        assert_eq!(Message::NewKeys.to_bytes().unwrap(), [21]);
        assert_eq!(
            Message::ServiceRequest("ssh-userauth".into())
                .to_bytes()
                .unwrap(),
            b"\x05\0\0\0\x0cssh-userauth"
        );
        assert_eq!(
            Message::Unimplemented(0x01020304).to_bytes().unwrap(),
            [3, 1, 2, 3, 4]
        );
        assert_eq!(
            Message::Disconnect {
                reason: DisconnectReason::ByApplication,
                description: "bye".into(),
                language: "".into()
            }
            .to_bytes()
            .unwrap(),
            [1, 0, 0, 0, 11, 0, 0, 0, 3, b'b', b'y', b'e', 0, 0, 0, 0]
        );
        assert_eq!(
            Message::Debug {
                always_display: false,
                message: "".into(),
                language: "".into()
            }
            .to_bytes()
            .unwrap(),
            [4, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        for c in 0..=20 {
            assert_eq!(DisconnectReason::from_code(c).code(), c);
        }
        assert_eq!(DisconnectReason::from_code(4), DisconnectReason::Other(4));
    }

    #[test]
    fn message_errors() {
        assert_eq!(Message::parse(&[]), Err(Error::Empty));
        assert_eq!(Message::parse(&[21, 0]), Err(Error::Trailing));
        assert_eq!(
            Message::parse(&[3, 0, 0, 0, 1, 9]),
            Err(Error::Trailing)
        );
        assert_eq!(
            Message::parse(&[5, 0, 0, 0, 1, 0xff]),
            Err(Error::Utf8)
        );
        assert_eq!(
            Message::parse(&vec![50; MAX_PAYLOAD + 1]),
            Err(Error::FieldTooLong)
        );
        let mut long = vec![5];
        SshString([b'a'; MAX_NAME + 1].to_vec())
            .write(&mut long)
            .unwrap();
        assert_eq!(Message::parse(&long), Err(Error::FieldTooLong));
        let mut long = vec![1, 0, 0, 0, 1];
        SshString(vec![b'a'; MAX_TEXT + 1])
            .write(&mut long)
            .unwrap();
        SshString((b"").to_vec()).write(&mut long).unwrap();
        assert_eq!(Message::parse(&long), Err(Error::FieldTooLong));
        let mut kex = vec![20];
        kex.extend_from_slice(&[0; 16]);
        SshString((b"a,,b").to_vec()).write(&mut kex).unwrap();
        assert_eq!(Message::parse(&kex), Err(Error::Name));
        let mut kex = vec![20];
        kex.extend_from_slice(&[0; 16]);
        SshString(vec![b'a'; MAX_NAME_LIST + 1])
            .write(&mut kex)
            .unwrap();
        assert_eq!(Message::parse(&kex), Err(Error::FieldTooLong));
        // A boolean other than 0 or 1 still reads as true.
        let mut k = Message::KexInit(KexInit::default()).to_bytes().unwrap();
        let flag = k.len() - 5;
        k[flag] = 9;
        let Ok(Message::KexInit(k)) = Message::parse(&k) else {
            panic!()
        };
        assert!(k.first_kex_packet_follows);
    }

    #[test]
    fn long_fields_that_fit_a_payload_are_read() {
        // RFC 4253 limits DEBUG text and KEXINIT lists only by the payload.
        let m = Message::Debug {
            always_display: false,
            message: "a".repeat(8193),
            language: String::new(),
        };
        let p = m.to_bytes().unwrap();
        assert_eq!(p.len(), 8203);
        assert_eq!(Message::parse(&p), Ok(m));
        let list: Vec<String> = (0..200).map(|i| format!("k{i:03}@example.com")).collect();
        let k = KexInit {
            kex_algorithms: list.clone(),
            server_host_key_algorithms: names(&["ssh-ed25519"]),
            ..KexInit::default()
        };
        let p = Message::KexInit(k.clone()).to_bytes().unwrap();
        assert_eq!(Message::parse(&p), Ok(Message::KexInit(k)));
        // Lists that together fill the payload are all written and read.
        let k = KexInit {
            kex_algorithms: list.clone(),
            server_host_key_algorithms: list.clone(),
            encryption_client_to_server: list.clone(),
            encryption_server_to_client: list.clone(),
            mac_client_to_server: list.clone(),
            mac_server_to_client: list.clone(),
            compression_client_to_server: list.clone(),
            compression_server_to_client: list,
            ..KexInit::default()
        };
        let p = Message::KexInit(k.clone()).to_bytes().unwrap();
        assert!(p.len() <= MAX_PAYLOAD);
        assert_eq!(Message::parse(&p), Ok(Message::KexInit(k)));
    }

    #[test]
    fn language_tags_may_be_longer_than_names() {
        // RFC 3066 tags have no length limit, so the 64-byte limit for
        // algorithm names does not apply to them.
        let tag = format!("x-{}abcdefgh", "abcdefgh-".repeat(7));
        assert!(tag.len() > MAX_NAME);
        let k = KexInit {
            kex_algorithms: names(&["curve25519-sha256"]),
            languages_client_to_server: vec![tag.clone(), "en".into()],
            languages_server_to_client: vec![tag.clone()],
            ..KexInit::default()
        };
        let m = Message::KexInit(k);
        assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m));
        let m = Message::Disconnect {
            reason: DisconnectReason::ByApplication,
            description: "bye".into(),
            language: tag.clone(),
        };
        assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m));
        // Tags still follow the name-list rules: no empty tags or commas.
        let mut kex = vec![20];
        kex.extend_from_slice(&[0; 16]);
        for _ in 0..8 {
            SshString((b"a").to_vec()).write(&mut kex).unwrap();
        }
        SshString((b"en,,fr").to_vec()).write(&mut kex).unwrap();
        SshString((b"").to_vec()).write(&mut kex).unwrap();
        kex.extend_from_slice(&[0; 5]);
        assert_eq!(Message::parse(&kex), Err(Error::Name));
    }

    #[test]
    fn choose_follows_the_client() {
        let client = names(&["a", "b", "c"]);
        assert_eq!(KexInit::choose(&client, &names(&["c", "b"])), Some("b"));
        assert_eq!(KexInit::choose(&client, &names(&["d"])), None);
        assert_eq!(KexInit::choose(&[], &client), None);
    }

    #[test]
    fn choose_takes_linear_time() {
        assert_linear("choose_takes_linear_time", rounds(12_500), |size| {
            let client: Vec<String> = (0..size).map(|i| format!("client-{i:08}")).collect();
            let server: Vec<String> = (0..size).map(|i| format!("server-{i:08}")).collect();
            assert_eq!(KexInit::choose(&client, &server), None);
            let mut both = server.clone();
            both.push(client[size - 1].clone());
            both.push(client[123].clone());
            assert_eq!(KexInit::choose(&client, &both), Some("client-00000123"));
        });
    }

    #[test]
    fn name_list_examples() {
        for (names, wire) in [
            (vec![], b"\0\0\0\0".as_slice()),
            (vec!["zlib".to_string()], b"\0\0\0\x04zlib"),
            (
                vec!["zlib".to_string(), "none".to_string()],
                b"\0\0\0\x09zlib,none",
            ),
        ] {
            assert_eq!(NameList(names.clone()).to_bytes().unwrap(), wire);
            assert_eq!(NameList::parse(wire), Ok(NameList(names)));
        }
        for bad in [
            b"a,,b".as_slice(),
            b",a",
            b"a,",
            b"a b",
            b"a\0",
            &[b'x'; 65],
            b"a@b@c",
            b"@b",
            b"a@",
            b"@",
        ] {
            let wire = SshString(bad.to_vec()).to_bytes().unwrap();
            assert_eq!(NameList::parse(&wire), Err(Error::Name));
        }
        let wire = SshString(b"abcdef".to_vec()).to_bytes().unwrap();
        assert_eq!(Reader::new(&wire).name_list(5), Err(Error::FieldTooLong));
        for bad in ["", "b c", "d,e", &"x".repeat(65), "a@b@c", "@z"] {
            assert_eq!(
                NameList(names(&["a", bad, "f"])).to_bytes(),
                Err(Error::Unwritable)
            );
        }
        let valid = NameList(names(&["aes@x.org", "b", "x@y"]));
        assert!(valid.to_bytes().is_ok());
        contract::check_wire_value(&valid);
        assert_eq!(
            NameList(vec!["a".repeat(MAX_NAME); 600]).to_bytes(),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn version_lines() {
        let bytes = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n";
        let id = Identification::parse(bytes).unwrap();
        assert_eq!(
            (id.proto(), id.software(), id.comments()),
            ("2.0", "OpenSSH_9.6p1", Some("Ubuntu-3ubuntu13"))
        );
        assert!(id.is_v2());
        assert_eq!(id.to_bytes().unwrap(), bytes);
        let mut trailing = bytes.to_vec();
        trailing.extend_from_slice(b"rest");
        assert_eq!(Identification::parse(&trailing), Err(Error::Trailing));
        let id = Identification::parse(b"SSH-1.99-Cisco1.25\n").unwrap();
        assert!(id.is_v2());
        assert!(!Identification::new("1.5", "x", None).unwrap().is_v2());
        for bad in [
            b"SSH-1.99-Cisco-1.25\n".as_slice(),
            b"SSH-2.0\r\n",
            b"SSH--x\r\n",
            b"SSH-2.0-\r\n",
            b"SSH-2.0-a-b\r\n",
            b"SSH-2.0-a\tb\r\n",
            b"SSH-2.0-a\rb\r\n",
            b"SSH-2.0-\xc3\xa9\r\n",
            b"SSH-2.0-x a\rb\r\n",
            b"SSH-2.0-x \xff\r\n",
        ] {
            assert_eq!(Line::parse(bad), Err(Error::BadVersion), "{bad:?}");
        }
        for (extra, valid) in [(0, true), (1, false)] {
            let software = "a".repeat(MAX_VERSION_LINE - 10 + extra);
            let line = format!("SSH-2.0-{software}\r\n");
            assert_eq!(Identification::parse(line.as_bytes()).is_ok(), valid);
            assert_eq!(Identification::new("2.0", &software, None).is_ok(), valid);
        }
        for (proto, software, comments) in [
            ("2.0", "a b", None),
            ("", "a", None),
            ("2.0", "x", Some("a\rb")),
            ("2.0", "x", Some("a\nb")),
            ("2.0", "x", Some("a\0b")),
        ] {
            assert_eq!(
                Identification::new(proto, software, comments),
                Err(Error::BadVersion)
            );
        }
        let id = Identification::new("2.0", "x", Some("")).unwrap();
        assert_eq!(id.to_bytes().unwrap(), b"SSH-2.0-x \r\n");
        let text = "SSH-2.0-x café\tok 1-2\r\n";
        let id = Identification::parse(text.as_bytes()).unwrap();
        assert_eq!(id.comments(), Some("café\tok 1-2"));
        assert_eq!(id.to_bytes().unwrap(), text.as_bytes());
        contract::check_wire_value(&id);
    }

    #[test]
    fn banner_lines() {
        let line = Line::Banner(b"Welcome to the tank farm".to_vec());
        assert_eq!(line.to_bytes().unwrap(), b"Welcome to the tank farm\r\n");
        contract::check_wire_value(&line);
        assert_eq!(Line::parse(b"\n"), Ok(Line::Banner(vec![])));
        assert_eq!(Line::parse(b"a\0b\n"), Err(Error::Nul));
        assert_eq!(
            Line::parse(&[b'x'; MAX_BANNER_LINE]),
            Err(Error::LineTooLong)
        );
        let longest = [vec![b'x'; MAX_BANNER_LINE - 1], vec![b'\n']].concat();
        contract::check_wire::<Line>(&longest);
        for bad in [
            b"SSH-2.0-x".as_slice(),
            b"a\nb",
            b"a\0b",
            &[b'x'; MAX_BANNER_LINE],
        ] {
            assert_eq!(
                Line::Banner(bad.to_vec()).to_bytes(),
                Err(Error::Unwritable)
            );
        }
        for text in [
            b"a\rb".to_vec(),
            vec![b'x'; MAX_BANNER_LINE - 1],
            vec![b'x'; MAX_BANNER_LINE - 2],
        ] {
            contract::check_wire_value(&Line::Banner(text));
        }
        let line = b"SSH-2.0-OpenSSH_9.6 c\r\n";
        for n in 0..line.len() {
            assert_eq!(Line::parse(&line[..n]), Err(Error::Truncated));
        }
        contract::check_decode_with_alloc_limit(Lines::new, line, 2 * MAX_BANNER_LINE);
    }

    #[test]
    fn packets() {
        let packet = Packet::new(vec![21]);
        let bytes = packet.to_bytes().unwrap();
        assert_eq!(bytes, [0, 0, 0, 12, 10, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Packet::parse(&bytes), Ok(packet));
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse(&bytes[..n]), Err(Error::Truncated));
        }
        let exact = Packet {
            payload: vec![1, 2, 3],
            padding: vec![9; 8],
        };
        contract::check_wire_value(&exact);
        for padding in [0, 3, 5, 256, 300] {
            assert_eq!(
                Packet {
                    payload: vec![1, 2, 3],
                    padding: vec![9; padding]
                }
                .to_bytes(),
                Err(Error::Unwritable)
            );
        }
        for length in [4u32, 13, 35004, u32::MAX] {
            assert_eq!(
                Packet::parse(&length.to_be_bytes()),
                Err(Error::PacketLength(length))
            );
        }
        assert_eq!(
            Packet::parse(&[0, 0, 0x88, 0xb4]),
            Err(Error::Truncated)
        );
        for pad in [3, 12] {
            assert_eq!(
                Packet::parse(&[0, 0, 0, 12, pad]),
                Err(Error::Padding(pad))
            );
        }
        assert_eq!(
            Packet::parse(&[0, 0, 0, 12, 11]),
            Err(Error::Truncated)
        );
        assert_eq!(
            Packet::parse(&[0, 0, 0x88, 0xb4, 4]),
            Err(Error::PayloadTooLong(34991))
        );
        contract::check_wire_value(&Packet::new(vec![2; MAX_PAYLOAD]));
        assert_eq!(
            Packet::new(vec![2; MAX_PAYLOAD + 100]).to_bytes(),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn messages_round_trip() {
        for m in samples() {
            let payload = m.to_bytes().unwrap();
            assert_eq!(payload[0], m.number());
            contract::check_wire_value(&m);
            let packet = Packet::from_message(&m).unwrap();
            assert_eq!(packet.payload, payload);
            contract::check_wire_value(&packet);
            for n in 0..payload.len() {
                if matches!(m, Message::Other { .. }) && n > 0 {
                    continue;
                }
                let error = if n == 0 {
                    Error::Empty
                } else {
                    Error::Truncated
                };
                assert_eq!(Message::parse(&payload[..n]), Err(error));
            }
        }
    }

    #[test]
    fn writers_refuse_clipping_and_aliases() {
        let half = "é".repeat(MAX_PAYLOAD / 4);
        let full = vec!["x".repeat(MAX_NAME); 1000];
        for m in [
            Message::Disconnect {
                reason: DisconnectReason::ProtocolError,
                description: half.clone(),
                language: half.clone(),
            },
            Message::Disconnect {
                reason: DisconnectReason::Other(1),
                description: String::new(),
                language: String::new(),
            },
            Message::Debug {
                always_display: true,
                message: format!("a{}", "é".repeat(MAX_PAYLOAD)),
                language: "en".into(),
            },
            Message::Ignore(vec![0; MAX_PAYLOAD * 2]),
            Message::ServiceAccept(half),
            Message::KexInit(KexInit {
                kex_algorithms: full.clone(),
                server_host_key_algorithms: full,
                ..KexInit::default()
            }),
            Message::KexInit(KexInit {
                kex_algorithms: names(&["valid", "a b"]),
                ..KexInit::default()
            }),
            Message::Other {
                number: 1,
                data: vec![0; 3],
            },
            Message::Other {
                number: 21,
                data: vec![0; MAX_PAYLOAD],
            },
            Message::Other {
                number: 99,
                data: vec![0; MAX_PAYLOAD],
            },
        ] {
            assert_eq!(m.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&m);
        }
        assert_eq!(
            SshString(vec![0; MAX_PAYLOAD + 1]).to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(
            Mpint::from_signed_bytes(&vec![1; MAX_PAYLOAD + 1]),
            Err(Error::Unwritable)
        );
        assert_eq!(
            Mpint::from_unsigned_bytes(&vec![0xff; MAX_PAYLOAD]),
            Err(Error::Unwritable)
        );
    }

    fn stream() -> Vec<u8> {
        let mut bytes = b"Hello\r\nsecond line\r\nSSH-2.0-x ok\r\n".to_vec();
        for message in samples() {
            Packet::from_message(&message)
                .unwrap()
                .write(&mut bytes)
                .unwrap();
        }
        bytes
    }

    #[test]
    fn stream_reads_exchange_and_sequence_numbers() {
        let bytes = stream();
        contract::check_decode_with_alloc_limit(Events::new, &bytes, 2 * MAX_PACKET);
        let (events, failure) = decode_all(Events::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(events.len(), 3 + samples().len());
        assert_eq!(events[0], Event::Banner(b"Hello".to_vec()));
        assert_eq!(events[1], Event::Banner(b"second line".to_vec()));
        let Event::Version(id) = &events[2] else {
            panic!()
        };
        assert_eq!(id.comments(), Some("ok"));
        for (i, (event, message)) in events[3..].iter().zip(samples()).enumerate() {
            let Event::Packet { sequence, packet } = event else {
                panic!()
            };
            assert_eq!(*sequence as usize, i);
            assert_eq!(Message::parse(&packet.payload), Ok(message));
        }
        for n in 0..bytes.len() {
            let (prefix, failure) = decode_all(Events::new, &bytes[..n]);
            assert_eq!(prefix, events[..prefix.len()]);
            assert!(matches!(failure, None | Some(Fail::Truncated { .. })));
        }
        let mut dec = Events::after_version();
        dec.sequence = u32::MAX;
        let bytes = Packet::from_message(&Message::NewKeys)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(matches!(
            dec.decode(&bytes, false),
            Ok(Step::Item(
                Event::Packet {
                    sequence: u32::MAX,
                    ..
                },
                _
            ))
        ));
        assert_eq!(dec.next_sequence(), 0);
        assert!(dec.in_packets());
    }

    #[test]
    fn stream_reports_errors_once_and_bounds_buffers() {
        let mut stream = Stream::new(Events::new());
        assert_eq!(stream.push(b"SSH-2.0-x\r\n\0\0\0\x05"), 15);
        assert!(matches!(stream.next(), Some(Ok(Event::Version(_)))));
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(Error::PacketLength(5))))
        );
        assert!(stream.next().is_none());
        assert_eq!(stream.push(b"more"), 4);
        let (items, failure) = decode_all(Events::new, &b"x\r\n".repeat(MAX_BANNER_LINES + 1));
        assert_eq!(items.len(), MAX_BANNER_LINES);
        assert_eq!(failure, Some(Fail::Protocol(Error::TooManyLines)));
        let big = Packet::from_message(&Message::Ignore(vec![1; MAX_DATA]))
            .unwrap()
            .to_bytes()
            .unwrap();
        let bytes = big.repeat(3);
        contract::check_decode_with_alloc_limit(Events::after_version, &bytes, 2 * MAX_PACKET);
        assert_eq!(decode_all(Events::after_version, &bytes).0.len(), 3);
        let long_line = vec![b'x'; rounds(200_000)];
        contract::check_decode_with_alloc_limit(Events::new, &long_line, 2 * MAX_PACKET);
        assert_eq!(
            decode_all(Events::new, &long_line).1,
            Some(Fail::Protocol(Error::LineTooLong))
        );
        contract::check_decode_with_alloc_limit(
            Frames::<Packet>::new,
            &[0, 0, 0x88, 0xb4, 4],
            2 * MAX_PACKET,
        );
        assert_eq!(
            decode_all(Events::after_version, &[0, 0, 0x88, 0xb4, 4]).1,
            Some(Fail::Protocol(Error::PayloadTooLong(34_991)))
        );
    }

    #[test]
    fn stream_takes_many_packets_and_partial_suffixes() {
        assert_linear("stream_takes_many_packets_and_partial_suffixes", rounds(100_000), |size| {
            let one = Packet::from_message(&Message::NewKeys)
                .unwrap()
                .to_bytes()
                .unwrap();
            let mut bytes = one.repeat(size);
            bytes.extend_from_slice(&one[..3]);
            let (events, failure) = decode_all(Events::after_version, &bytes);
            assert_eq!(events.len(), size);
            assert_eq!(failure, Some(Fail::Truncated { unread: 3 }));
            assert!(matches!(
                events.last(),
                Some(Event::Packet {
                    sequence,
                    ..
                }) if *sequence as usize == size - 1
            ));
        });
    }

    #[test]
    fn stream_scans_long_lines_once() {
        let mut line = vec![b'x'; MAX_BANNER_LINE - 2];
        line.extend_from_slice(b"\r\n");
        let mut bytes = line.repeat(MAX_BANNER_LINES);
        bytes.extend_from_slice(b"SSH-2.0-x\r\n");
        let mut stream = Stream::new(Events::new());
        let mut banners = 0;
        LINE_BYTES_SCANNED.with(|count| count.set(0));
        for part in chunks(&bytes, &[1]) {
            pump(&mut stream, part, |event| match event {
                Event::Banner(text) => {
                    assert_eq!(text.len(), MAX_BANNER_LINE - 2);
                    banners += 1;
                }
                Event::Version(_) => {}
                Event::Packet { .. } => panic!(),
            })
            .unwrap();
        }
        assert_eq!(banners, MAX_BANNER_LINES);
        assert_eq!(stream.buffered(), 0);
        let scanned = LINE_BYTES_SCANNED.with(|count| count.get());
        assert!(scanned <= bytes.len(), "scanned {scanned} bytes for {} input bytes", bytes.len());
    }

    #[test]
    fn fuzz_loop() {
        let mut g = Lcg::new(0x5eed);
        let base = stream();
        let payloads: Vec<_> = samples().iter().map(|m| m.to_bytes().unwrap()).collect();
        let text = |g: &mut Lcg, max| {
            let pool = ["é", "🙂", "\0", "SSH-", ",", " ", "x@y.z"];
            let mut value = g.text(max);
            for _ in 0..g.index(5) {
                value.push_str(pool[g.index(pool.len())]);
            }
            value
        };
        let list = |g: &mut Lcg| (0..g.index(6)).map(|_| text(g, 80)).collect();
        for _ in 0..fictionet::stdlib::test_support::rounds(1000) {
            for sample in &payloads {
                let mut payload = sample.clone();
                mutate(&mut g, &mut payload);
                contract::check_wire::<Message>(&payload);
            }
            let mut bytes = if g.coin() { g.bytes(300) } else { base.clone() };
            mutate(&mut g, &mut bytes);
            contract::check_decode_with_alloc_limit(Events::new, &bytes, 2 * MAX_PACKET);
            contract::check_decode_with_alloc_limit(Events::after_version, &bytes, 2 * MAX_PACKET);
            contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &bytes, 2 * MAX_PACKET);
            contract::check_decode_with_alloc_limit(Lines::new, &bytes, 2 * MAX_BANNER_LINE);
            contract::check_wire::<Message>(&bytes);
            contract::check_wire::<Packet>(&bytes);
            contract::check_wire::<Line>(&bytes);
            contract::check_wire::<Identification>(&bytes);
            contract::check_wire::<Mpint>(&bytes);
            contract::check_wire::<NameList>(&bytes);
            contract::check_wire::<SshString>(&bytes);
            contract::check_wire::<Boolean>(&bytes);
            let message = match g.index(7) {
                0 => Message::Disconnect {
                    reason: if g.coin() {
                        DisconnectReason::from_code(g.index(17) as u32)
                    } else {
                        DisconnectReason::Other(g.next() as u32)
                    },
                    description: text(&mut g, 60),
                    language: text(&mut g, 80),
                },
                1 => Message::Debug {
                    always_display: g.coin(),
                    message: text(&mut g, 30),
                    language: text(&mut g, 10),
                },
                2 => Message::ServiceRequest(text(&mut g, 100)),
                3 => Message::KexInit(KexInit {
                    cookie: {
                        let mut cookie = [0; 16];
                        g.fill(&mut cookie);
                        cookie
                    },
                    kex_algorithms: list(&mut g),
                    server_host_key_algorithms: list(&mut g),
                    encryption_client_to_server: list(&mut g),
                    encryption_server_to_client: list(&mut g),
                    mac_client_to_server: list(&mut g),
                    mac_server_to_client: list(&mut g),
                    compression_client_to_server: list(&mut g),
                    compression_server_to_client: list(&mut g),
                    languages_client_to_server: list(&mut g),
                    languages_server_to_client: list(&mut g),
                    first_kex_packet_follows: g.coin(),
                    reserved: g.next() as u32,
                }),
                4 => Message::Other {
                    number: g.next() as u8,
                    data: g.bytes(40),
                },
                5 => Message::Ignore(g.bytes(40)),
                _ => Message::Unimplemented(g.next() as u32),
            };
            contract::check_wire_value(&message);
            contract::check_wire_value(&NameList(list(&mut g)));
            let packet = Packet {
                payload: g.bytes(40),
                padding: g.bytes(20),
            };
            contract::check_wire_value(&packet);
            if let Ok(id) = Identification::new(&text(&mut g, 3), &text(&mut g, 10), Some(&text(&mut g, 3))) {
                contract::check_wire_value(&id);
            }
            contract::check_wire_value(&Line::Banner(g.bytes(100)));
        }
    }
}
