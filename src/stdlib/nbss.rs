//! The NetBIOS Session Service: reading and writing session packets, with
//! no I/O.
//!
//! Before SMB ran straight over TCP port 445, Windows file sharing ran over
//! NetBIOS sessions on TCP port 139, and many hosts still answer there. A
//! client opens a TCP connection, sends a session request that names the
//! server it wants (the called name) and itself (the calling name), and
//! waits for a positive response, a negative response with an error code,
//! or a retarget response that points it at another address and port. Once
//! the session is up, each SMB message travels in a session message, and
//! either side may send keepalives. Every packet starts with a 4-byte
//! header: a type, a flags byte, and a 16-bit length that the flags byte's
//! low bit extends to 17 bits. This module follows RFC 1001, section 14,
//! and RFC 1002, sections 4.1 and 4.3.
//!
//! A world that plays a file server pushes bytes from a TCP connection
//! into a [`Stream<Frames>`](fictionet::stdlib::codec::Stream), gets [`Packet`]s
//! back, and writes the bytes of its answers back to the connection. Which
//! names it listens on, and what it says to a session request, is up to
//! world code.
//!
//! Names are carried in the first-level encoding: each of a name's 16
//! bytes becomes two letters from `A` to `P`, so `F` (0x46) becomes `EG`.
//! The encoded name is a 32-byte label, which may be followed by the
//! labels of a scope.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A packet that breaks the specification is an [`Error`], and the
//! stream cannot be read past it. A stream holds at most one packet's
//! bytes. Writers return an [`Error::Unwritable`] rather than write bytes a
//! reader would refuse or read back as a different value.
//!
//! ```
//! use fictionet::stdlib::{codec::{Stream, Wire}, nbss::{Frames, Name, NegativeCode, Packet}};
//!
//! /// A server that answers to FILESERVER and to *SMBSERVER.
//! fn answer(packet: &Packet) -> Option<Packet> {
//!     match packet {
//!         Packet::Request { called, .. } => {
//!             let ours = [Name::new("FILESERVER", 0x20), Name::new("*SMBSERVER", 0x20)];
//!             if ours.contains(called) {
//!                 Some(Packet::Positive)
//!             } else {
//!                 Some(Packet::Negative(NegativeCode::CalledNameNotPresent))
//!             }
//!         }
//!         _ => None,
//!     }
//! }
//!
//! let request = Packet::Request {
//!     called: Name::new("fileserver", 0x20),
//!     calling: Name::new("LAPTOP", 0x00),
//! };
//! let bytes = request.to_bytes().unwrap();
//! // The header: type 0x81, no flags, a body of two 34-byte names.
//! assert_eq!(bytes[..4], [0x81, 0x00, 0x00, 68]);
//! // The called name starts with F (0x46), encoded as "EG".
//! assert_eq!(bytes[4..7], [0x20, b'E', b'G']);
//!
//! let mut decoder = Stream::new(Frames::new());
//! // The request arrives in two pieces.
//! assert_eq!(decoder.push(&bytes[..10]), 10);
//! assert_eq!(decoder.next(), None);
//! assert_eq!(decoder.push(&bytes[10..]), bytes.len() - 10);
//! let packet = decoder.next().unwrap().unwrap();
//! assert_eq!(packet, request);
//! let reply = answer(&packet).unwrap();
//! assert_eq!(reply.to_bytes().unwrap(), [0x82, 0x00, 0x00, 0x00]);
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The TCP port the session service listens on.
pub const PORT: u16 = 139;
/// The length of a packet's header, before its body.
pub const HEADER_LEN: usize = 4;
/// The longest body a packet may carry: 17 bits of length.
pub const MAX_LENGTH: usize = 0x1_ffff;
/// The longest packet: the header and the longest body.
pub const MAX_PACKET: usize = HEADER_LEN + MAX_LENGTH;
/// The length of a NetBIOS name: 15 characters and a suffix byte.
pub const NAME_LEN: usize = 16;
/// The length of a NetBIOS name in the first-level encoding.
pub const ENCODED_LEN: usize = 2 * NAME_LEN;
/// The longest label in a name's scope.
pub const MAX_LABEL: usize = 63;
/// The longest encoded name: every length byte, every label, and the zero
/// byte at the end.
pub const MAX_NAME_LEN: usize = 255;
/// The length of a retarget response's body: an IPv4 address and a port.
pub const RETARGET_LEN: usize = 6;

/// The packet types RFC 1002 defines.
pub mod kind {
    /// Carries data, such as an SMB message, once a session is up.
    pub const MESSAGE: u8 = 0x00;
    /// Asks for a session, naming the server and the client.
    pub const REQUEST: u8 = 0x81;
    /// Accepts a session request.
    pub const POSITIVE: u8 = 0x82;
    /// Refuses a session request, with an error code.
    pub const NEGATIVE: u8 = 0x83;
    /// Points the client at another address and port.
    pub const RETARGET: u8 = 0x84;
    /// Keeps an idle session open.
    pub const KEEP_ALIVE: u8 = 0x85;
}

/// The flags byte's bits.
pub mod flags {
    /// The length extension: the 17th bit of the body's length.
    pub const EXTEND: u8 = 0x01;
    /// The bits RFC 1002 reserves. They must be zero.
    pub const RESERVED: u8 = 0xfe;
}

/// The first-level encoding of a 16-byte NetBIOS name: each byte becomes
/// two letters, `A` plus its high half, then `A` plus its low half.
pub fn encode_first_level(name: &[u8; NAME_LEN]) -> [u8; ENCODED_LEN] {
    let mut out = [0u8; ENCODED_LEN];
    for (i, b) in name.iter().enumerate() {
        out[2 * i] = b'A' + (b >> 4);
        out[2 * i + 1] = b'A' + (b & 0x0f);
    }
    out
}

/// The 16-byte name a first-level label encodes. It returns `None` unless
/// the label is 32 bytes, each an uppercase letter from `A` to `P`.
pub fn decode_first_level(label: &[u8]) -> Option<[u8; NAME_LEN]> {
    if label.len() != ENCODED_LEN {
        return None;
    }
    let half = |c: u8| if (b'A'..=b'P').contains(&c) { Some(c - b'A') } else { None };
    let mut out = [0u8; NAME_LEN];
    for (i, pair) in label.chunks_exact(2).enumerate() {
        out[i] = half(pair[0])? << 4 | half(pair[1])?;
    }
    Some(out)
}

/// A NetBIOS name, with its scope.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name {
    /// The 16 bytes: up to 15 characters padded with spaces, then the
    /// suffix.
    pub bytes: [u8; NAME_LEN],
    /// The scope's labels, such as `["NETBIOS", "COM"]`. Most networks use
    /// none. Each label must hold 1 to [`MAX_LABEL`] bytes, and the
    /// encoded name must fit in [`MAX_NAME_LEN`]; [`Name::to_bytes`]
    /// refuses a name that breaks either rule.
    pub scope: Vec<Vec<u8>>,
}

impl Name {
    /// The name `name` with suffix `suffix` and no scope. ASCII letters
    /// are put in uppercase, as Windows does, and the name is cut to 15
    /// bytes, at a character boundary, and padded with spaces. File
    /// servers use suffix 0x20. The bytes are the string's UTF-8 bytes.
    /// Windows writes a name with letters outside ASCII in the host's OEM
    /// code page instead, so build such a name by setting
    /// [`Name::bytes`] directly.
    pub fn new(name: &str, suffix: u8) -> Name {
        let mut bytes = [b' '; NAME_LEN];
        let mut end = name.len().min(NAME_LEN - 1);
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        for (slot, b) in bytes.iter_mut().zip(name[..end].bytes()) {
            *slot = b.to_ascii_uppercase();
        }
        bytes[NAME_LEN - 1] = suffix;
        Name { bytes, scope: Vec::new() }
    }

    /// The name's characters: its first 15 bytes, without the spaces that
    /// pad them.
    pub fn base(&self) -> &[u8] {
        let base = &self.bytes[..NAME_LEN - 1];
        let end = base.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        &base[..end]
    }

    /// The suffix: the last byte, which says what kind of service the
    /// name is for.
    pub fn suffix(&self) -> u8 {
        self.bytes[NAME_LEN - 1]
    }

    /// Reads the encoded name at the start of `b`, and how many bytes it
    /// took. It returns `None` if the first label is not a first-level
    /// encoded name, if a label is longer than [`MAX_LABEL`] (which
    /// includes the compression pointers of DNS, which the session
    /// service does not use), if the name passes [`MAX_NAME_LEN`], or if
    /// `b` ends before the zero byte.
    fn read_prefix(b: &[u8]) -> Option<(Name, usize)> {
        if *b.first()? as usize != ENCODED_LEN {
            return None;
        }
        let bytes = decode_first_level(b.get(1..1 + ENCODED_LEN)?)?;
        let mut at = 1 + ENCODED_LEN;
        let mut scope = Vec::new();
        loop {
            let n = usize::from(*b.get(at)?);
            at += 1;
            if n == 0 {
                break;
            }
            // The label and at least the zero byte after it.
            if n > MAX_LABEL || at + n + 1 > MAX_NAME_LEN {
                return None;
            }
            scope.push(b.get(at..at + n)?.to_vec());
            at += n;
        }
        Some((Name { bytes, scope }, at))
    }
}

impl Wire for Name {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete name. Refuses invalid first-level labels, compression
    /// pointers, labels over 63 bytes, names over 255 bytes, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (name, used) = Self::read_prefix(bytes).ok_or(Error::Name)?;
        if used != bytes.len() {
            return Err(Error::Trailing { remaining: bytes.len() - used });
        }
        Ok(name)
    }

    /// Appends the first-level label, scope, and terminal zero. Refuses empty
    /// scope labels, labels over 63 bytes, and names over 255 bytes.
    /// Leaves the destination unchanged on error.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::with_capacity(ENCODED_LEN + 2);
        out.push(ENCODED_LEN as u8);
        out.extend_from_slice(&encode_first_level(&self.bytes));
        for label in &self.scope {
            // The label, its length byte, and the zero byte at the end.
            if label.is_empty() || label.len() > MAX_LABEL || out.len() + 1 + label.len() + 1 > MAX_NAME_LEN {
                return Err(Error::Unwritable);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        destination.extend_from_slice(&out);
        Ok(())
    }
}

/// The error codes of a negative session response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NegativeCode {
    /// 0x80: the server does not listen on the called name.
    NotListeningOnCalledName,
    /// 0x81: the server listens on the called name, but not for this
    /// calling name.
    NotListeningForCallingName,
    /// 0x82: the called name is not on this host.
    CalledNameNotPresent,
    /// 0x83: the called name is here, but the server has no room for
    /// another session.
    InsufficientResources,
    /// 0x8F: some other error.
    Unspecified,
    /// Any other code. RFC 1002 defines only the codes above, but a
    /// reader keeps any other as it is. A packet that carries one of the
    /// codes above reads back as that code's own variant, so a writer
    /// refuses `Other` holding one of them with [`Error::Unwritable`].
    /// Build codes with [`NegativeCode::from_code`] when the code is a
    /// number.
    Other(u8),
}

impl NegativeCode {
    /// The error code's number.
    pub fn code(self) -> u8 {
        match self {
            NegativeCode::NotListeningOnCalledName => 0x80,
            NegativeCode::NotListeningForCallingName => 0x81,
            NegativeCode::CalledNameNotPresent => 0x82,
            NegativeCode::InsufficientResources => 0x83,
            NegativeCode::Unspecified => 0x8f,
            NegativeCode::Other(c) => c,
        }
    }

    /// The error for code `c`.
    pub fn from_code(c: u8) -> NegativeCode {
        match c {
            0x80 => NegativeCode::NotListeningOnCalledName,
            0x81 => NegativeCode::NotListeningForCallingName,
            0x82 => NegativeCode::CalledNameNotPresent,
            0x83 => NegativeCode::InsufficientResources,
            0x8f => NegativeCode::Unspecified,
            c => NegativeCode::Other(c),
        }
    }
}

/// One session packet.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Packet {
    /// A session message: data for the session, such as an SMB message.
    Message(Vec<u8>),
    /// A session request.
    Request {
        /// The name of the server the client wants.
        called: Name,
        /// The client's own name.
        calling: Name,
    },
    /// A positive session response: the session is up.
    Positive,
    /// A negative session response: the request is refused.
    Negative(NegativeCode),
    /// A retarget session response: the client should try again at this
    /// IPv4 address and TCP port.
    Retarget {
        /// The address, in network order.
        address: [u8; 4],
        /// The port.
        port: u16,
    },
    /// A session keepalive.
    KeepAlive,
}

/// Why a session packet or name could not be read or written.
/// An error from [`Frames`] ends the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The type is not one RFC 1002 defines.
    Type(u8),
    /// A reserved bit of the flags byte was set. The byte is given whole.
    Flags(u8),
    /// The body's length is past the limit: [`MAX_LENGTH`], or a
    /// decoder's own limit.
    TooLong(u32),
    /// The body does not fit the type given: a positive response or
    /// keepalive with a body, a negative response that is not one byte, a
    /// retarget response that is not six, or a session request that is
    /// not two well-formed names. The type is given.
    Body(u8),
    /// The encoded name is incomplete or invalid.
    Name,
    /// The input ends before the packet is complete.
    Incomplete,
    /// Bytes follow a complete wire value.
    Trailing {
        /// Number of trailing bytes.
        remaining: usize,
    },
    /// The value cannot be written without changing it.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Name => f.write_str("invalid NBSS name"),
            Error::Incomplete => f.write_str("incomplete NBSS packet"),
            Error::Trailing { remaining } => write!(f, "{remaining} bytes after NBSS value"),
            Error::Unwritable => f.write_str("NBSS value cannot be written without changing it"),
            Error::Type(t) => write!(f, "packet type {t:#04x} is not a session packet"),
            Error::Flags(b) => write!(f, "flags byte {b:#04x} sets reserved bits"),
            Error::TooLong(n) => write!(f, "body length {n} is past the limit"),
            Error::Body(t) => write!(f, "body is not well formed for packet type {t:#04x}"),
        }
    }
}

impl std::error::Error for Error {}

impl Packet {
    /// The packet's type, one of the values in [`kind`].
    pub fn kind(&self) -> u8 {
        match self {
            Packet::Message(_) => kind::MESSAGE,
            Packet::Request { .. } => kind::REQUEST,
            Packet::Positive => kind::POSITIVE,
            Packet::Negative(_) => kind::NEGATIVE,
            Packet::Retarget { .. } => kind::RETARGET,
            Packet::KeepAlive => kind::KEEP_ALIVE,
        }
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one packet. Refuses unknown types, reserved flags,
    /// invalid bodies, incomplete packets, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match parse_limited(bytes, MAX_LENGTH)? {
            Some((packet, used)) if used == bytes.len() => Ok(packet),
            Some((_, used)) => Err(Error::Trailing { remaining: bytes.len() - used }),
            None => Err(Error::Incomplete),
        }
    }

    /// Appends a header and body. Refuses messages over [`MAX_LENGTH`],
    /// invalid names, and named negative codes stored as `Other`.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut body = Vec::new();
        let body: &[u8] = match self {
            Packet::Message(data) => {
                if data.len() > MAX_LENGTH {
                    return Err(Error::Unwritable);
                }
                data
            }
            Packet::Request { called, calling } => {
                called.write(&mut body)?;
                calling.write(&mut body)?;
                &body
            }
            Packet::Positive | Packet::KeepAlive => &[],
            Packet::Negative(code) => {
                let c = code.code();
                if NegativeCode::from_code(c) != *code {
                    return Err(Error::Unwritable);
                }
                body.push(c);
                &body
            }
            Packet::Retarget { address, port } => {
                body.extend_from_slice(address);
                body.extend_from_slice(&port.to_be_bytes());
                &body
            }
        };
        out.push(self.kind());
        // The body is at most MAX_LENGTH, which fits in 17 bits.
        let flags = if body.len() > 0xffff { flags::EXTEND } else { 0 };
        out.push(flags);
        out.extend_from_slice(&((body.len() & 0xffff) as u16).to_be_bytes());
        out.extend_from_slice(body);
        Ok(())
    }
}

/// Reads session packets without retaining input.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for bounded buffering. The header
/// suffices to refuse a body above [`limit`](Self::limit). Partial packets
/// return [`Step::Need`], including at EOF. The driver reports truncation
/// and reports errors once. All packet errors end this decoder.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire, finish, pump}, nbss::{Frames, Packet}};
/// let packet = Packet::Message(b"hello".to_vec());
/// let bytes = Wire::to_bytes(&packet)?;
/// let mut stream = Stream::new(Frames::with_limit(1024));
/// let mut packets = Vec::new();
/// for chunk in bytes.chunks(3) {
///     pump(&mut stream, chunk, |item| packets.push(item))?;
/// }
/// finish(&mut stream, |item| packets.push(item))?;
/// assert_eq!(packets, vec![packet]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Creates a decoder accepting bodies up to [`MAX_LENGTH`] bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_LENGTH)
    }

    /// Sets the body limit, clamped to [`MAX_LENGTH`]. Zero permits empty bodies.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.min(MAX_LENGTH) }
    }

    /// The largest accepted body, excluding its four-byte header.
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
    type Item = Packet;
    type Error = Error;
    const NAME: &'static str = "NBSS";

    fn capacity(&self) -> usize {
        HEADER_LEN.saturating_add(self.limit)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Packet>, Error> {
        Ok(match parse_limited(input, self.limit)? {
            Some((packet, used)) => Step::Item(packet, used),
            None => Step::Need,
        })
    }
}

/// Reads one packet whose body may be at most `limit` bytes.
fn parse_limited(b: &[u8], limit: usize) -> Result<Option<(Packet, usize)>, Error> {
    let Some(&t) = b.first() else { return Ok(None) };
    if !matches!(
        t,
        kind::MESSAGE | kind::REQUEST | kind::POSITIVE | kind::NEGATIVE | kind::RETARGET | kind::KEEP_ALIVE
    ) {
        return Err(Error::Type(t));
    }
    let Some(&f) = b.get(1) else { return Ok(None) };
    if f & flags::RESERVED != 0 {
        return Err(Error::Flags(f));
    }
    let (Some(&hi), Some(&lo)) = (b.get(2), b.get(3)) else { return Ok(None) };
    let length = u32::from(f & flags::EXTEND) << 16 | u32::from(hi) << 8 | u32::from(lo);
    let len = length as usize;
    if len > limit.min(MAX_LENGTH) {
        return Err(Error::TooLong(length));
    }
    // Fixed-size bodies are checked before the body arrives.
    let fixed = match t {
        kind::POSITIVE | kind::KEEP_ALIVE => Some(0),
        kind::NEGATIVE => Some(1),
        kind::RETARGET => Some(RETARGET_LEN),
        // Two names, each at least 34 bytes and at most MAX_NAME_LEN.
        kind::REQUEST if !(2 * (ENCODED_LEN + 2)..=2 * MAX_NAME_LEN).contains(&len) => return Err(Error::Body(t)),
        _ => None,
    };
    if fixed.is_some_and(|n| n != len) {
        return Err(Error::Body(t));
    }
    let end = HEADER_LEN + len;
    let Some(body) = b.get(HEADER_LEN..end) else { return Ok(None) };
    let packet = match t {
        kind::MESSAGE => Packet::Message(body.to_vec()),
        kind::REQUEST => {
            let (called, used) = Name::read_prefix(body).ok_or(Error::Body(t))?;
            let rest = &body[used..];
            let (calling, used) = Name::read_prefix(rest).ok_or(Error::Body(t))?;
            if used != rest.len() {
                return Err(Error::Body(t));
            }
            Packet::Request { called, calling }
        }
        kind::POSITIVE => Packet::Positive,
        kind::NEGATIVE => Packet::Negative(NegativeCode::from_code(body[0])),
        kind::RETARGET => Packet::Retarget {
            address: [body[0], body[1], body[2], body[3]],
            port: u16::from_be_bytes([body[4], body[5]]),
        },
        _ => Packet::KeepAlive,
    };
    Ok(Some((packet, end)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Stream, Fail, contract, test_support::{Lcg, mutate, decode_all}};

    /// "FRED" padded with spaces, from RFC 1002, section 4.1.
    const FRED: &[u8; 32] = b"EGFCEFEECACACACACACACACACACACACA";

    fn fred() -> Name {
        Name { bytes: *b"FRED            ", scope: Vec::new() }
    }

    #[test]
    fn first_level_encoding_example() {
        assert_eq!(&fred().to_bytes().unwrap()[1..33], FRED);
        assert_eq!(decode_first_level(FRED), Some(fred().bytes));
        // Name::new pads the same way, with suffix 0x20, a space.
        assert_eq!(Name::new("Fred", b' '), fred());
        assert_eq!(decode_first_level(b"EGFCEFEECACACACACACACACACACACACQ"), None);
        assert_eq!(decode_first_level(b"egfcefeecacacacacacacacacacacaca"), None);
        assert_eq!(decode_first_level(&FRED[..30]), None);
        for b in 0..=255u8 {
            let name = [b; NAME_LEN];
            let bytes = Name { bytes: name, scope: vec![] }.to_bytes().unwrap();
            assert_eq!(decode_first_level(&bytes[1..33]), Some(name));
        }
    }

    #[test]
    fn name_with_scope_example() {
        // FRED.NETBIOS.COM, from RFC 1002, section 4.1.
        let name = Name { scope: vec![b"NETBIOS".to_vec(), b"COM".to_vec()], ..fred() };
        let mut want = vec![0x20];
        want.extend_from_slice(FRED);
        want.extend_from_slice(b"\x07NETBIOS\x03COM\x00");
        assert_eq!(name.to_bytes().unwrap(), want);
        assert_eq!(Name::parse(&want), Ok(name));
        for n in 0..want.len() {
            assert_eq!(Name::parse(&want[..n]), Err(Error::Name), "{n} bytes");
        }
    }

    #[test]
    fn rfc_1001_example() {
        // "The NetBIOS name" in scope SCOPE.ID.COM, from RFC 1001, section
        // 14.1. The RFC prints FEGHGF... and ...CAHEGBGNGF, but 'h' (0x68)
        // encodes as GI and 'n' (0x6E) as GO. The corrected label is here.
        let name = Name {
            bytes: *b"The NetBIOS name",
            scope: vec![b"SCOPE".to_vec(), b"ID".to_vec(), b"COM".to_vec()],
        };
        let label = b"FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF";
        assert_eq!(&name.to_bytes().unwrap()[1..33], label);
        let mut want = vec![0x20];
        want.extend_from_slice(label);
        want.extend_from_slice(b"\x05SCOPE\x02ID\x03COM\x00");
        assert_eq!(name.to_bytes().unwrap(), want);
        assert_eq!(Name::parse(&want), Ok(name.clone()));
        assert_eq!(name.base(), b"The NetBIOS nam");
        assert_eq!(name.suffix(), b'e');
    }

    #[test]
    fn longest_name() {
        // Three 63-byte labels and one of 28 make exactly MAX_NAME_LEN.
        let scope = vec![vec![b'A'; 63], vec![b'B'; 63], vec![b'C'; 63], vec![b'D'; 28]];
        let name = Name { scope, ..fred() };
        let bytes = name.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_NAME_LEN);
        assert_eq!(Name::parse(&bytes), Ok(name.clone()));
        // One byte more in the last label is too long to read, and too
        // long to write.
        let mut long = bytes[..MAX_NAME_LEN - 30].to_vec();
        long.push(29);
        long.extend_from_slice(&[b'D'; 29]);
        long.push(0);
        assert_eq!(long.len(), MAX_NAME_LEN + 1);
        assert_eq!(Name::parse(&long), Err(Error::Name));
        let mut over = name;
        over.scope[3].push(b'D');
        assert_eq!(over.to_bytes(), Err(Error::Unwritable));
        // Two of the longest names make the longest request.
        let full = Name::parse(&bytes).unwrap();
        let req = Packet::Request { called: full.clone(), calling: full };
        let wire = req.to_bytes().unwrap();
        assert_eq!(wire.len(), HEADER_LEN + 2 * MAX_NAME_LEN);
        assert_eq!(Packet::parse(&wire), Ok(req));
    }

    #[test]
    fn named_codes_read_back_as_named() {
        // Other holding a named code would read back as the named variant,
        // so the writer refuses it.
        for c in [0x80, 0x81, 0x82, 0x83, 0x8f] {
            assert_eq!(Packet::Negative(NegativeCode::Other(c)).to_bytes(), Err(Error::Unwritable));
        }
        // Every value from_code gives writes and reads back the same.
        for c in 0..=255u8 {
            let p = Packet::Negative(NegativeCode::from_code(c));
            assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(p));
        }
        assert!(!Error::Unwritable.to_string().is_empty());
    }

    #[test]
    fn packet_hashes_and_partial_input() {
        let bytes = request().to_bytes().unwrap();
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&bytes[..20]), 20);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(&bytes[20..]), bytes.len() - 20);
        assert_eq!(stream.next(), Some(Ok(request())));
        let set: std::collections::HashSet<_> = [request(), Packet::KeepAlive].into();
        assert!(set.contains(&request()));
        let errors: std::collections::HashSet<Error> = [Error::Body(0x81), Error::Body(0x81)].into();
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn name_new_cuts_at_a_character() {
        // 14 ASCII bytes, then a two-byte character that would split at
        // byte 15.
        let n = Name::new("abcdefghijklmn\u{e9}", 0x20);
        assert_eq!(n.base(), b"ABCDEFGHIJKLMN");
        // A character that fits is kept as its UTF-8 bytes.
        assert_eq!(Name::new("caf\u{e9}", 0x20).base(), "CAF\u{e9}".as_bytes());
        assert_eq!(Name::new("\u{1f600}\u{1f600}\u{1f600}\u{1f600}", 0).base(), "\u{1f600}\u{1f600}\u{1f600}".as_bytes());
    }

    #[test]
    fn stream_bounds() {
        let data = [0x85, 0, 0, 0].repeat(1_000);
        contract::check_decode_with_alloc_limit(|| Frames::with_limit(0), &data, 2 * HEADER_LEN);
        let (packets, error) = decode_all(|| Frames::with_limit(0), &data);
        assert_eq!(packets, vec![Packet::KeepAlive; 1_000]);
        assert_eq!(error, None);
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&vec![0; 3 * MAX_PACKET]), MAX_PACKET);
        assert_eq!(stream.push(&[0]), 0);
    }

    #[test]
    fn name_parts() {
        let n = Name::new("*SMBSERVER", 0x20);
        assert_eq!(n.base(), b"*SMBSERVER");
        assert_eq!(n.suffix(), 0x20);
        assert_eq!(Name::new("", 0).base(), b"");
        assert_eq!(Name::new("AVERYLONGNAMEINDEED", 3).base(), b"AVERYLONGNAMEIN");
    }

    #[test]
    fn bad_names() {
        let good = fred().to_bytes().unwrap();
        // The first label is not 32 bytes.
        let mut b = good.clone();
        b[0] = 0x1f;
        assert_eq!(Name::parse(&b), Err(Error::Name));
        // A compression pointer where a scope label would be.
        let mut b = good[..33].to_vec();
        b.extend_from_slice(&[0xc0, 0x0c]);
        assert_eq!(Name::parse(&b), Err(Error::Name));
        // Scope labels that pass MAX_NAME_LEN.
        let mut b = good[..33].to_vec();
        for _ in 0..4 {
            b.push(63);
            b.extend_from_slice(&[b'X'; 63]);
        }
        b.push(0);
        assert_eq!(Name::parse(&b), Err(Error::Name));
        assert_eq!(Name::parse(&[]), Err(Error::Name));
    }

    #[test]
    fn name_writer_refuses_names_it_cannot_write() {
        // An empty label, a label past MAX_LABEL, and a name past
        // MAX_NAME_LEN would each be refused or read as another name.
        let bad = [
            vec![vec![]],
            vec![b"NETBIOS".to_vec(), vec![]],
            vec![vec![b'A'; 64]],
            vec![vec![b'A'; 63], vec![b'B'; 63], vec![b'C'; 63], vec![b'D'; 63]],
        ];
        for scope in bad {
            let name = Name { scope, ..fred() };
            assert_eq!(name.to_bytes(), Err(Error::Unwritable));
            let req = Packet::Request { called: name.clone(), calling: fred() };
            assert_eq!(req.to_bytes(), Err(Error::Unwritable));
            let req = Packet::Request { called: fred(), calling: name };
            assert_eq!(req.to_bytes(), Err(Error::Unwritable));
        }
        // The longest label is fine.
        let name = Name { scope: vec![vec![b'A'; 63]], ..fred() };
        let bytes = name.to_bytes().unwrap();
        assert_eq!(Name::parse(&bytes), Ok(name));
        assert!(!Error::Unwritable.to_string().is_empty());
    }

    fn request() -> Packet {
        Packet::Request { called: Name::new("FILESERVER", 0x20), calling: Name::new("LAPTOP", 0) }
    }

    #[test]
    fn session_request() {
        let bytes = request().to_bytes().unwrap();
        assert_eq!(bytes.len(), 4 + 68);
        assert_eq!(bytes[..4], [0x81, 0, 0, 68]);
        assert_eq!(bytes[4], 0x20);
        assert_eq!(bytes[37], 0);
        assert_eq!(bytes[38], 0x20);
        assert_eq!(bytes[71], 0);
        // LAPTOP's suffix 0x00 encodes as "AA".
        assert_eq!(&bytes[69..71], b"AA");
        assert_eq!(Packet::parse(&bytes), Ok(request()));
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse(&bytes[..n]), Err(Error::Incomplete), "{n} bytes");
        }
    }

    #[test]
    fn fixed_packets() {
        assert_eq!(Packet::Positive.to_bytes().unwrap(), [0x82, 0, 0, 0]);
        assert_eq!(Packet::KeepAlive.to_bytes().unwrap(), [0x85, 0, 0, 0]);
        assert_eq!(Packet::Negative(NegativeCode::CalledNameNotPresent).to_bytes().unwrap(), [0x83, 0, 0, 1, 0x82]);
        let r = Packet::Retarget { address: [10, 0, 0, 7], port: 139 };
        assert_eq!(r.to_bytes().unwrap(), [0x84, 0, 0, 6, 10, 0, 0, 7, 0, 139]);
        for p in [Packet::Positive, Packet::KeepAlive, Packet::Negative(NegativeCode::Other(0x42)), r] {
            let bytes = p.to_bytes().unwrap();
            assert_eq!(Packet::parse(&bytes), Ok(p));
            for n in 0..bytes.len() {
                assert_eq!(Packet::parse(&bytes[..n]), Err(Error::Incomplete), "{n} bytes");
            }
        }
    }

    #[test]
    fn negative_codes() {
        for c in 0..=255u8 {
            assert_eq!(NegativeCode::from_code(c).code(), c);
        }
        assert_eq!(NegativeCode::from_code(0x8f), NegativeCode::Unspecified);
        assert_eq!(NegativeCode::from_code(0x80), NegativeCode::NotListeningOnCalledName);
        assert_eq!(NegativeCode::from_code(0x81), NegativeCode::NotListeningForCallingName);
        assert_eq!(NegativeCode::from_code(0x83), NegativeCode::InsufficientResources);
    }

    #[test]
    fn messages_and_the_length_extension() {
        let short = Packet::Message(vec![0xfe, b'S', b'M', b'B']);
        assert_eq!(short.to_bytes().unwrap(), [0, 0, 0, 4, 0xfe, b'S', b'M', b'B']);
        assert_eq!(Packet::Message(vec![]).to_bytes().unwrap(), [0, 0, 0, 0]);
        // 0x10000 bytes need the 17th bit.
        let long = Packet::Message(vec![7; 0x1_0000]);
        let bytes = long.to_bytes().unwrap();
        assert_eq!(bytes[..4], [0, 1, 0, 0]);
        assert_eq!(Packet::parse(&bytes), Ok(long));
        assert_eq!(Packet::parse(&bytes[..bytes.len() - 1]), Err(Error::Incomplete));
        // The longest message, and one past it, which no packet holds.
        let longest = Packet::Message(vec![1; MAX_LENGTH]);
        let bytes = longest.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        assert_eq!(bytes[..4], [0, 1, 0xff, 0xff]);
        assert_eq!(Packet::parse(&bytes), Ok(longest));
        let over = Packet::Message(vec![1; MAX_LENGTH + 1]);
        assert_eq!(over.to_bytes(), Err(Error::Unwritable));
        assert!(!Error::Unwritable.to_string().is_empty());
    }

    #[test]
    fn errors() {
        // Unknown types, known from the first byte.
        assert_eq!(Packet::parse(&[0x01]), Err(Error::Type(1)));
        assert_eq!(Packet::parse(&[0x86, 0, 0, 0]), Err(Error::Type(0x86)));
        assert_eq!(Packet::parse(b"GET / HTTP/1.1"), Err(Error::Type(b'G')));
        // Reserved flag bits, known from the second.
        assert_eq!(Packet::parse(&[0x00, 0x02]), Err(Error::Flags(2)));
        assert_eq!(Packet::parse(&[0x85, 0x80, 0, 0]), Err(Error::Flags(0x80)));
        // Bodies that do not fit their type, known from the header.
        assert_eq!(Packet::parse(&[0x82, 0, 0, 1]), Err(Error::Body(0x82)));
        assert_eq!(Packet::parse(&[0x85, 0, 0, 2]), Err(Error::Body(0x85)));
        assert_eq!(Packet::parse(&[0x83, 0, 0, 0]), Err(Error::Body(0x83)));
        assert_eq!(Packet::parse(&[0x83, 0, 0, 2]), Err(Error::Body(0x83)));
        assert_eq!(Packet::parse(&[0x84, 0, 0, 5]), Err(Error::Body(0x84)));
        assert_eq!(Packet::parse(&[0x81, 0, 0, 67]), Err(Error::Body(0x81)));
        assert_eq!(Packet::parse(&[0x81, 0, 0x01, 0xff]), Err(Error::Body(0x81)));
        assert_eq!(Packet::parse(&[0x81, 1, 0, 0]), Err(Error::Body(0x81)));
        // A request whose names are bad, known once the body is in.
        let mut bytes = request().to_bytes().unwrap();
        bytes[5] = b'Z';
        assert_eq!(Packet::parse(&bytes), Err(Error::Body(0x81)));
        // A request with a byte after the second name.
        let mut bytes = request().to_bytes().unwrap();
        bytes[3] += 1;
        bytes.push(0);
        assert_eq!(Packet::parse(&bytes), Err(Error::Body(0x81)));
        // A request with only one name, padded out.
        let mut bytes = vec![0x81, 0, 0, 68];
        bytes.extend_from_slice(&fred().to_bytes().unwrap());
        bytes.extend_from_slice(&[0; 34]);
        assert_eq!(Packet::parse(&bytes), Err(Error::Body(0x81)));
        // Error messages.
        assert!(Error::Type(1).to_string().contains("0x01"));
        assert!(Error::TooLong(9).to_string().contains('9'));
        assert!(!Error::Flags(2).to_string().is_empty());
        assert!(!Error::Body(0x81).to_string().is_empty());
    }

    #[test]
    fn stream_limit() {
        let make = || Frames::with_limit(10);
        assert_eq!(make().limit(), 10);
        let packet = Packet::Message(vec![1; 10]);
        assert_eq!(decode_all(make, &packet.to_bytes().unwrap()), (vec![packet], None));
        assert_eq!(decode_all(make, &[0, 0, 0, 11]).1, Some(Fail::Protocol(Error::TooLong(11))));
        assert_eq!(decode_all(make, &request().to_bytes().unwrap()[..4]).1, Some(Fail::Protocol(Error::TooLong(68))));
        assert_eq!(Frames::with_limit(usize::MAX).limit(), MAX_LENGTH);
        assert_eq!(Frames::default().limit(), MAX_LENGTH);
    }

    #[test]
    fn stream_splits_packets() {
        let packets = [
            request(),
            Packet::Positive,
            Packet::Message(b"\xffSMBr".to_vec()),
            Packet::KeepAlive,
            Packet::Message(vec![9; 70_000]),
            Packet::Retarget { address: [192, 168, 1, 2], port: 1139 },
        ];
        let stream: Vec<u8> = packets.iter().flat_map(|p| p.to_bytes().unwrap()).collect();
        contract::check_decode_with_alloc_limit(Frames::new, &stream, 2 * MAX_PACKET);
        assert_eq!(decode_all(Frames::new, &stream), (packets.to_vec(), None));
        assert_eq!(decode_all(Frames::new, &[0x99, 0, 0, 0]).1, Some(Fail::Protocol(Error::Type(0x99))));
    }

    #[test]
    fn stream_takes_many_small_packets_in_linear_time() {
        let bytes = Packet::KeepAlive.to_bytes().unwrap().repeat(200_000);
        let started = std::time::Instant::now();
        let (packets, error) = decode_all(Frames::new, &bytes);
        assert_eq!(packets.len(), 200_000);
        assert_eq!(error, None);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn generated_packets_and_names() {
        let mut rng = Lcg::new(0x5eed);
        for _ in 0..fictionet::stdlib::codec::test_support::rounds(17_500) {
            let mut data = if rng.coin() {
                request().to_bytes().unwrap()
            } else {
                let mut bytes = rng.bytes(120);
                if bytes.len() >= HEADER_LEN && rng.coin() {
                    let kinds = [
                        kind::MESSAGE,
                        kind::REQUEST,
                        kind::POSITIVE,
                        kind::NEGATIVE,
                        kind::RETARGET,
                        kind::KEEP_ALIVE,
                    ];
                    bytes[0] = kinds[rng.index(kinds.len())];
                    bytes[1] = 0;
                    let length = (bytes.len() - HEADER_LEN) as u16;
                    bytes[2..4].copy_from_slice(&length.to_be_bytes());
                }
                bytes
            };
            mutate(&mut rng, &mut data);
            contract::check_decode_with_alloc_limit(Frames::new, &data, 2 * MAX_PACKET);
            contract::check_wire::<Packet>(&data);
            contract::check_wire::<Name>(&data);
            let mut scope: Vec<Vec<u8>> =
                data.chunks(rng.index(80) + 1).map(<[u8]>::to_vec).collect();
            if rng.index(8) == 0 {
                scope.push(Vec::new());
            }
            let name = Name { bytes: [rng.next() as u8; NAME_LEN], scope };
            let fits = name
                .scope
                .iter()
                .all(|label| (1..=MAX_LABEL).contains(&label.len()))
                && 2 + ENCODED_LEN
                    + name
                        .scope
                        .iter()
                        .map(|label| 1 + label.len())
                        .sum::<usize>()
                    <= MAX_NAME_LEN;
            assert_eq!(name.to_bytes().is_ok(), fits);
            contract::check_wire_value(&name);
            contract::check_wire_value(&Packet::Request { called: name, calling: fred() });
            contract::check_wire_value(&Packet::Negative(NegativeCode::Other(rng.next() as u8)));
        }
    }
}
