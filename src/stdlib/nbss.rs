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
//! Nothing here reads a socket. A world that plays a file server feeds the
//! bytes it reads from a TCP connection to a [`Decoder`], gets [`Packet`]s
//! back, and writes the bytes of its answers back to the connection. Which
//! names it listens on, and what it says to a session request, is up to
//! world code.
//!
//! Names are carried in the first-level encoding: each of a name's 16
//! bytes becomes two letters from `A` to `P`, so `F` (0x46) becomes `EG`.
//! See [`encode_first_level`]. The encoded name is a 32-byte label, which
//! may be followed by the labels of a scope.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A packet that breaks the specification is an [`Error`], and the
//! stream cannot be read past it. A [`Decoder`] holds at most one packet's
//! bytes. Writers return an [`EncodeError`] rather than write bytes a
//! reader would refuse or read back as a different value.
//!
//! ```
//! use fictionet::stdlib::nbss::{Decoder, Name, NegativeCode, Packet};
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
//! let mut decoder = Decoder::new();
//! // The request arrives in two pieces.
//! assert_eq!(decoder.feed(&bytes[..10]), 10);
//! assert_eq!(decoder.next_packet(), None);
//! assert_eq!(decoder.feed(&bytes[10..]), bytes.len() - 10);
//! let packet = decoder.next_packet().unwrap().unwrap();
//! assert_eq!(packet, request);
//! let reply = answer(&packet).unwrap();
//! assert_eq!(reply.to_bytes().unwrap(), [0x82, 0x00, 0x00, 0x00]);
//! ```

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

    /// The name's bytes as a packet carries them: the encoded name as a
    /// 32-byte label, the scope's labels, and a zero byte. It returns
    /// [`EncodeError::Name`] if a scope label is empty or longer than
    /// [`MAX_LABEL`], or if the result would be longer than
    /// [`MAX_NAME_LEN`], since a reader would refuse those bytes or read
    /// them as another name.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(ENCODED_LEN + 2);
        out.push(ENCODED_LEN as u8);
        out.extend_from_slice(&encode_first_level(&self.bytes));
        for label in &self.scope {
            // The label, its length byte, and the zero byte at the end.
            if label.is_empty() || label.len() > MAX_LABEL || out.len() + 1 + label.len() + 1 > MAX_NAME_LEN {
                return Err(EncodeError::Name);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        Ok(out)
    }

    /// Reads the encoded name at the start of `b`, and how many bytes it
    /// took. It returns `None` if the first label is not a first-level
    /// encoded name, if a label is longer than [`MAX_LABEL`] (which
    /// includes the compression pointers of DNS, which the session
    /// service does not use), if the name passes [`MAX_NAME_LEN`], or if
    /// `b` ends before the zero byte.
    pub fn parse(b: &[u8]) -> Option<(Name, usize)> {
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
    /// refuses `Other` holding one of them with [`EncodeError::Code`].
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

/// Why bytes are not a session packet. Either way, the connection holds no
/// more packets a reader can find, and a real server closes it.
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
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Type(t) => write!(f, "packet type {t:#04x} is not a session packet"),
            Error::Flags(b) => write!(f, "flags byte {b:#04x} sets reserved bits"),
            Error::TooLong(n) => write!(f, "body length {n} is past the limit"),
            Error::Body(t) => write!(f, "body is not well formed for packet type {t:#04x}"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a value cannot be written as a session packet. A writer returns one
/// rather than write bytes a reader would refuse or read back as a
/// different value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EncodeError {
    /// A message longer than [`MAX_LENGTH`]. Its length is given.
    TooLong(usize),
    /// A name with an empty scope label, a scope label longer than
    /// [`MAX_LABEL`], or an encoding longer than [`MAX_NAME_LEN`].
    Name,
    /// [`NegativeCode::Other`] holding a code that has its own variant.
    /// The code is given.
    Code(u8),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooLong(n) => write!(f, "a message of {n} bytes is longer than one packet holds"),
            EncodeError::Name => f.write_str("the name's scope does not fit the limits on labels and names"),
            EncodeError::Code(c) => write!(f, "error code {c:#04x} has its own variant, not Other"),
        }
    }
}

impl std::error::Error for EncodeError {}

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

    /// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the packet and how many bytes
    /// of `b` it took. A bad type or bad flags is reported as soon as its
    /// byte arrives, and a body that cannot fit its type as soon as the
    /// header has. Since the length has only 17 bits, this never returns
    /// [`Error::TooLong`].
    pub fn parse(b: &[u8]) -> Result<Option<(Packet, usize)>, Error> {
        parse_limited(b, MAX_LENGTH)
    }

    /// The packet's bytes: the header, then the body. When it returns
    /// bytes, they parse back as this packet. It returns
    /// [`EncodeError::TooLong`] for a message longer than [`MAX_LENGTH`],
    /// the error of [`Name::to_bytes`] for a name it cannot write, and
    /// [`EncodeError::Code`] for a [`NegativeCode::Other`] that holds a
    /// named code.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut body = Vec::new();
        let body: &[u8] = match self {
            Packet::Message(data) => {
                if data.len() > MAX_LENGTH {
                    return Err(EncodeError::TooLong(data.len()));
                }
                data
            }
            Packet::Request { called, calling } => {
                body.extend_from_slice(&called.to_bytes()?);
                body.extend_from_slice(&calling.to_bytes()?);
                &body
            }
            Packet::Positive | Packet::KeepAlive => &[],
            Packet::Negative(code) => {
                let c = code.code();
                if NegativeCode::from_code(c) != *code {
                    return Err(EncodeError::Code(c));
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
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(self.kind());
        // The body is at most MAX_LENGTH, which fits in 17 bits.
        let flags = if body.len() > 0xffff { flags::EXTEND } else { 0 };
        out.push(flags);
        out.extend_from_slice(&((body.len() & 0xffff) as u16).to_be_bytes());
        out.extend_from_slice(body);
        Ok(out)
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
            let (called, used) = Name::parse(body).ok_or(Error::Body(t))?;
            let rest = &body[used..];
            let (calling, used) = Name::parse(rest).ok_or(Error::Body(t))?;
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

/// Splits a session service byte stream into packets. Feed it the bytes a
/// connection reads, in order, and take packets out until it has none.
#[derive(Clone, Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small packets costs time in proportion to their bytes.
    start: usize,
    /// The longest body this decoder accepts.
    limit: usize,
    failed: Option<Error>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, which accepts bodies up to
    /// [`MAX_LENGTH`].
    pub fn new() -> Decoder {
        Decoder::with_limit(MAX_LENGTH)
    }

    /// A decoder holding no bytes, which accepts bodies up to `limit`
    /// bytes, or [`MAX_LENGTH`] if `limit` is larger. A longer body is an
    /// [`Error::TooLong`] as soon as its header arrives, so the decoder
    /// never waits for it.
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder { buf: Vec::new(), start: 0, limit: limit.min(MAX_LENGTH), failed: None }
    }

    /// The longest body this decoder accepts.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The most bytes this decoder holds: [`HEADER_LEN`] plus its limit,
    /// the longest packet it accepts.
    pub fn max_buffered(&self) -> usize {
        HEADER_LEN + self.limit
    }

    /// Takes bytes read from the connection, from the start of `bytes`,
    /// and returns how many it took. It takes them all unless that would
    /// make it hold more than [`Decoder::max_buffered`] bytes. Then take
    /// packets out with [`Decoder::next_packet`] and feed it the rest.
    /// Once it is full, `next_packet` always gives a packet or an error,
    /// so a loop of feeding and taking out always ends. After an
    /// [`Error`] the stream cannot be read any further, and every byte is
    /// taken and dropped.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes.len().min(self.max_buffered().saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The next whole packet, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken.
    pub fn next_packet(&mut self) -> Option<Result<Packet, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match parse_limited(&self.buf[self.start..], self.limit) {
            Ok(Some((packet, used))) => {
                self.start += used;
                Some(Ok(packet))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a packet.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "FRED" padded with spaces, from RFC 1002, section 4.1.
    const FRED: &[u8; 32] = b"EGFCEFEECACACACACACACACACACACACA";

    /// Feeds all of `bytes`, which must fit.
    fn feed_all(d: &mut Decoder, bytes: &[u8]) {
        assert_eq!(d.feed(bytes), bytes.len());
    }

    fn fred() -> Name {
        Name { bytes: *b"FRED            ", scope: Vec::new() }
    }

    #[test]
    fn first_level_encoding_example() {
        assert_eq!(&encode_first_level(&fred().bytes), FRED);
        assert_eq!(decode_first_level(FRED), Some(fred().bytes));
        // Name::new pads the same way, with suffix 0x20, a space.
        assert_eq!(Name::new("Fred", b' '), fred());
        assert_eq!(decode_first_level(b"EGFCEFEECACACACACACACACACACACACQ"), None);
        assert_eq!(decode_first_level(b"egfcefeecacacacacacacacacacacaca"), None);
        assert_eq!(decode_first_level(&FRED[..30]), None);
        for b in 0..=255u8 {
            let name = [b; NAME_LEN];
            assert_eq!(decode_first_level(&encode_first_level(&name)), Some(name));
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
        assert_eq!(Name::parse(&want), Some((name, want.len())));
        for n in 0..want.len() {
            assert_eq!(Name::parse(&want[..n]), None, "{n} bytes");
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
        assert_eq!(&encode_first_level(&name.bytes), label);
        let mut want = vec![0x20];
        want.extend_from_slice(label);
        want.extend_from_slice(b"\x05SCOPE\x02ID\x03COM\x00");
        assert_eq!(name.to_bytes().unwrap(), want);
        assert_eq!(Name::parse(&want), Some((name.clone(), want.len())));
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
        assert_eq!(Name::parse(&bytes), Some((name.clone(), MAX_NAME_LEN)));
        // One byte more in the last label is too long to read, and too
        // long to write.
        let mut long = bytes[..MAX_NAME_LEN - 30].to_vec();
        long.push(29);
        long.extend_from_slice(&[b'D'; 29]);
        long.push(0);
        assert_eq!(long.len(), MAX_NAME_LEN + 1);
        assert_eq!(Name::parse(&long), None);
        let mut over = name;
        over.scope[3].push(b'D');
        assert_eq!(over.to_bytes(), Err(EncodeError::Name));
        // Two of the longest names make the longest request.
        let full = Name::parse(&bytes).unwrap().0;
        let req = Packet::Request { called: full.clone(), calling: full };
        let wire = req.to_bytes().unwrap();
        assert_eq!(wire.len(), HEADER_LEN + 2 * MAX_NAME_LEN);
        assert_eq!(Packet::parse(&wire), Ok(Some((req, wire.len()))));
    }

    #[test]
    fn named_codes_read_back_as_named() {
        // Other holding a named code would read back as the named variant,
        // so the writer refuses it.
        for c in [0x80, 0x81, 0x82, 0x83, 0x8f] {
            assert_eq!(Packet::Negative(NegativeCode::Other(c)).to_bytes(), Err(EncodeError::Code(c)));
        }
        // Every value from_code gives writes and reads back the same.
        for c in 0..=255u8 {
            let p = Packet::Negative(NegativeCode::from_code(c));
            assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(Some((p, 5))));
        }
        assert!(EncodeError::Code(0x80).to_string().contains("0x80"));
    }

    #[test]
    fn decoder_clones_mid_packet() {
        let bytes = request().to_bytes().unwrap();
        let mut d = Decoder::new();
        feed_all(&mut d, &bytes[..20]);
        assert_eq!(d.next_packet(), None);
        let mut e = d.clone();
        feed_all(&mut d, &bytes[20..]);
        feed_all(&mut e, &bytes[20..]);
        assert_eq!(d.next_packet(), Some(Ok(request())));
        assert_eq!(e.next_packet(), Some(Ok(request())));
        let mut set = std::collections::HashSet::new();
        set.insert(request());
        set.insert(Packet::KeepAlive);
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
    fn decoder_holds_at_most_max_buffered() {
        // Keepalives, all fed at once to a decoder whose limit is 0.
        let stream = [0x85, 0, 0, 0].repeat(1_000);
        let mut d = Decoder::with_limit(0);
        assert_eq!(d.max_buffered(), HEADER_LEN);
        assert_eq!(d.feed(&stream), HEADER_LEN);
        assert_eq!(d.feed(&stream[HEADER_LEN..]), 0);
        assert_eq!(d.buffered(), HEADER_LEN);
        // A full decoder always has a packet or an error, so a loop of
        // feeding and taking out reads the whole stream.
        let mut rest = &stream[HEADER_LEN..];
        let mut n = 0;
        while let Some(p) = d.next_packet() {
            assert_eq!(p, Ok(Packet::KeepAlive));
            n += 1;
            rest = &rest[d.feed(rest)..];
            assert!(d.buffered() <= d.max_buffered());
        }
        assert_eq!(n, 1_000);
        assert!(rest.is_empty());
        // The default decoder holds at most the longest packet, however
        // much it is fed.
        let mut d = Decoder::new();
        let big = vec![0u8; 3 * MAX_PACKET];
        assert_eq!(d.feed(&big), MAX_PACKET);
        assert_eq!(d.feed(&big), 0);
        assert_eq!(d.buffered(), MAX_PACKET);
        // After an error, every byte is taken and dropped.
        let mut d = Decoder::new();
        feed_all(&mut d, &[0x99]);
        assert_eq!(d.next_packet(), Some(Err(Error::Type(0x99))));
        assert_eq!(d.feed(&big), big.len());
        assert_eq!(d.buffered(), 0);
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
        assert_eq!(Name::parse(&b), None);
        // A compression pointer where a scope label would be.
        let mut b = good[..33].to_vec();
        b.extend_from_slice(&[0xc0, 0x0c]);
        assert_eq!(Name::parse(&b), None);
        // Scope labels that pass MAX_NAME_LEN.
        let mut b = good[..33].to_vec();
        for _ in 0..4 {
            b.push(63);
            b.extend_from_slice(&[b'X'; 63]);
        }
        b.push(0);
        assert_eq!(Name::parse(&b), None);
        assert_eq!(Name::parse(&[]), None);
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
            assert_eq!(name.to_bytes(), Err(EncodeError::Name));
            let req = Packet::Request { called: name.clone(), calling: fred() };
            assert_eq!(req.to_bytes(), Err(EncodeError::Name));
            let req = Packet::Request { called: fred(), calling: name };
            assert_eq!(req.to_bytes(), Err(EncodeError::Name));
        }
        // The longest label is fine.
        let name = Name { scope: vec![vec![b'A'; 63]], ..fred() };
        let bytes = name.to_bytes().unwrap();
        assert_eq!(Name::parse(&bytes), Some((name, bytes.len())));
        assert!(!EncodeError::Name.to_string().is_empty());
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
        assert_eq!(Packet::parse(&bytes), Ok(Some((request(), bytes.len()))));
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse(&bytes[..n]), Ok(None), "{n} bytes");
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
            assert_eq!(Packet::parse(&bytes), Ok(Some((p, bytes.len()))));
            for n in 0..bytes.len() {
                assert_eq!(Packet::parse(&bytes[..n]), Ok(None), "{n} bytes");
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
        assert_eq!(Packet::parse(&bytes), Ok(Some((long, bytes.len()))));
        assert_eq!(Packet::parse(&bytes[..bytes.len() - 1]), Ok(None));
        // The longest message, and one past it, which no packet holds.
        let longest = Packet::Message(vec![1; MAX_LENGTH]);
        let bytes = longest.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        assert_eq!(bytes[..4], [0, 1, 0xff, 0xff]);
        assert_eq!(Packet::parse(&bytes), Ok(Some((longest, MAX_PACKET))));
        let over = Packet::Message(vec![1; MAX_LENGTH + 1]);
        assert_eq!(over.to_bytes(), Err(EncodeError::TooLong(MAX_LENGTH + 1)));
        assert!(EncodeError::TooLong(9).to_string().contains('9'));
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
    fn decoder_limit() {
        let mut d = Decoder::with_limit(10);
        assert_eq!(d.limit(), 10);
        feed_all(&mut d, &Packet::Message(vec![1; 10]).to_bytes().unwrap());
        assert_eq!(d.next_packet(), Some(Ok(Packet::Message(vec![1; 10]))));
        // A header that promises 11 bytes is refused before they come.
        feed_all(&mut d, &[0, 0, 0, 11]);
        assert_eq!(d.next_packet(), Some(Err(Error::TooLong(11))));
        assert_eq!(d.buffered(), 0);
        // A request is longer than this limit allows.
        let mut d = Decoder::with_limit(10);
        feed_all(&mut d, &request().to_bytes().unwrap()[..4]);
        assert_eq!(d.next_packet(), Some(Err(Error::TooLong(68))));
        // Limits past MAX_LENGTH are MAX_LENGTH.
        assert_eq!(Decoder::with_limit(usize::MAX).limit(), MAX_LENGTH);
        assert_eq!(Decoder::default().limit(), MAX_LENGTH);
    }

    #[test]
    fn decoder_splits_a_stream() {
        let packets = [
            request(),
            Packet::Positive,
            Packet::Message(b"\xffSMBr".to_vec()),
            Packet::KeepAlive,
            Packet::Message(vec![9; 70_000]),
            Packet::Retarget { address: [192, 168, 1, 2], port: 1139 },
        ];
        let stream: Vec<u8> = packets.iter().flat_map(|p| p.to_bytes().unwrap()).collect();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            feed_all(&mut d, std::slice::from_ref(byte));
            while let Some(p) = d.next_packet() {
                got.push(p.unwrap());
            }
        }
        assert_eq!(got, packets);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        feed_all(&mut d, &[0x99, 0, 0, 0]);
        assert_eq!(d.next_packet(), Some(Err(Error::Type(0x99))));
        feed_all(&mut d, &Packet::Positive.to_bytes().unwrap());
        assert_eq!(d.next_packet(), Some(Err(Error::Type(0x99))));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_packets_in_linear_time() {
        let one = Packet::KeepAlive.to_bytes().unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        let mut rest = &stream[..];
        let mut n = 0;
        loop {
            rest = &rest[d.feed(rest)..];
            let mut any = false;
            while let Some(p) = d.next_packet() {
                p.unwrap();
                n += 1;
                any = true;
            }
            if !any {
                break;
            }
        }
        assert!(rest.is_empty());
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    /// A small deterministic generator, so the fuzz loop needs no crates.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u8
        }
    }

    /// Random bytes, often starting with a valid header so the fuzz loop
    /// reaches the bodies.
    fn buffer(rng: &mut Lcg) -> Vec<u8> {
        let len = usize::from(rng.next()) % 120;
        let mut b: Vec<u8> = (0..len).map(|_| rng.next()).collect();
        if rng.next().is_multiple_of(2) && b.len() >= 4 {
            let kinds = [0x00, 0x81, 0x82, 0x83, 0x84, 0x85];
            b[0] = kinds[usize::from(rng.next()) % kinds.len()];
            b[1] = rng.next() & flags::EXTEND & rng.next();
            b[2] = 0;
            if rng.next().is_multiple_of(2) {
                b[3] = (b.len() - 4) as u8;
            }
        }
        if rng.next().is_multiple_of(4) {
            // A real request, with a few bytes changed.
            b = request().to_bytes().unwrap();
            for _ in 0..usize::from(rng.next() % 3) {
                let i = usize::from(rng.next()) % b.len();
                b[i] = rng.next();
            }
        }
        b
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x5eed);
        for _ in 0..20_000 {
            let data = buffer(&mut rng);
            let mut whole = Decoder::new();
            feed_all(&mut whole, &data);
            let mut packets = Vec::new();
            let mut last = None;
            while let Some(p) = whole.next_packet() {
                match p {
                    Ok(p) => packets.push(p),
                    Err(e) => {
                        last = Some(e);
                        break;
                    }
                }
            }
            let mut bytewise = Decoder::new();
            let mut again = Vec::new();
            let mut last_again = None;
            for b in &data {
                feed_all(&mut bytewise, std::slice::from_ref(b));
                while last_again.is_none() {
                    match bytewise.next_packet() {
                        Some(Ok(p)) => again.push(p),
                        Some(Err(e)) => last_again = Some(e),
                        None => break,
                    }
                }
            }
            assert_eq!(packets, again);
            assert_eq!(last, last_again);
            for p in &packets {
                let bytes = p.to_bytes().unwrap();
                assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
            }
            let _ = Name::parse(&data);
            let _ = decode_first_level(&data);
            // Any name made of these bytes either writes bytes that read
            // back as the same name, or is refused for breaking a limit.
            let mut scope: Vec<Vec<u8>> = data.chunks(usize::from(rng.next() % 80) + 1).map(<[u8]>::to_vec).collect();
            if rng.next().is_multiple_of(8) {
                scope.push(Vec::new());
            }
            let name = Name { bytes: [rng.next(); NAME_LEN], scope };
            let fits = name.scope.iter().all(|l| (1..=MAX_LABEL).contains(&l.len()))
                && 1 + ENCODED_LEN + name.scope.iter().map(|l| 1 + l.len()).sum::<usize>() < MAX_NAME_LEN;
            match name.to_bytes() {
                Ok(bytes) => {
                    assert!(fits);
                    assert!(bytes.len() <= MAX_NAME_LEN);
                    assert_eq!(Name::parse(&bytes), Some((name.clone(), bytes.len())));
                    let req = Packet::Request { called: name.clone(), calling: name };
                    let wire = req.to_bytes().unwrap();
                    assert_eq!(Packet::parse(&wire), Ok(Some((req, wire.len()))));
                }
                Err(e) => {
                    assert_eq!(e, EncodeError::Name);
                    assert!(!fits);
                }
            }
            // Every negative code either round-trips or is refused.
            let code = NegativeCode::Other(rng.next());
            let p = Packet::Negative(code);
            match p.to_bytes() {
                Ok(bytes) => assert_eq!(Packet::parse(&bytes), Ok(Some((p, 5)))),
                Err(e) => assert_eq!(e, EncodeError::Code(code.code())),
            }
        }
    }
}
