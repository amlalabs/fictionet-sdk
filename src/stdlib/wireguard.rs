//! WireGuard: reading and writing the four message types, with no I/O and
//! no cryptography.
//!
//! WireGuard is a VPN that sends everything over UDP, usually on port
//! 51820. Peers trade a handshake initiation and a handshake response to
//! agree on keys. A peer under load may answer with a cookie reply instead.
//! After that, each IP packet travels inside a transport data message. This
//! module follows the WireGuard paper (Donenfeld, NDSS 2017, section 5.4)
//! and the protocol page at wireguard.com/protocol.
//!
//! Nothing here reads a socket or does any cryptography. A world that plays
//! a peer passes each UDP payload it gets to [`Message::parse`] and writes
//! the bytes of [`Message::to_bytes`] back. Encrypted fields, ephemeral
//! keys, nonces and MACs are kept as bytes. Checking a MAC, opening a
//! ciphertext or making keys is up to world code. So is which peers exist.
//!
//! Every message starts with a 4-byte little-endian type: one type byte,
//! then three reserved bytes that must be 0. The three handshake messages
//! have fixed sizes (148, 92 and 64 bytes). A transport data message is at
//! least 32 bytes: its 16-byte header and the 16-byte tag of an empty
//! plaintext, which is a keepalive. Its plaintext is padded with zeros to
//! a multiple of 16 bytes before encryption ([`padding`]). Its counter
//! must stay below [`REJECT_AFTER_MESSAGES`], and a receiver drops
//! counters it has seen or that fall too far behind ([`ReplayWindow`]).
//!
//! Every reader checks lengths and reserved bytes, because the agent can
//! send any bytes it likes. Bytes that break the layout give an [`Error`],
//! and a real peer drops the datagram without an answer.
//!
//! ```
//! use fictionet::stdlib::wireguard::{Data, Initiation, Message, ReplayWindow, INITIATION_LEN};
//!
//! // A handshake initiation from sender index 7, with stand-in crypto bytes.
//! let init = Initiation {
//!     sender: 7,
//!     ephemeral: [1; 32],
//!     encrypted_static: [2; 48],
//!     encrypted_timestamp: [3; 28],
//!     mac1: [4; 16],
//!     mac2: [0; 16],
//! };
//! let bytes = Message::Initiation(init.clone()).to_bytes();
//! assert_eq!(bytes.len(), INITIATION_LEN);
//! assert_eq!(bytes[..8], [1, 0, 0, 0, 7, 0, 0, 0]);
//! assert_eq!(Message::parse(&bytes), Ok(Message::Initiation(init)));
//!
//! // A keepalive: counter 0 and only a tag.
//! let keepalive = Data { receiver: 9, counter: 0, encrypted: vec![0xaa; 16] };
//! let bytes = Message::Data(keepalive.clone()).to_bytes();
//! assert_eq!(bytes.len(), 32);
//! assert_eq!(Message::parse(&bytes), Ok(Message::Data(keepalive)));
//!
//! // The same counter twice is a replay.
//! let mut window = ReplayWindow::new();
//! assert!(window.accept(0));
//! assert!(!window.accept(0));
//! ```

/// The UDP port WireGuard peers usually listen on.
pub const PORT: u16 = 51820;

/// Message type numbers, the first byte of every message.
pub mod message_type {
    /// A handshake initiation.
    pub const INITIATION: u8 = 1;
    /// A handshake response.
    pub const RESPONSE: u8 = 2;
    /// A cookie reply.
    pub const COOKIE_REPLY: u8 = 3;
    /// Transport data.
    pub const DATA: u8 = 4;
}

/// The length of a public key or an ephemeral key.
pub const KEY_LEN: usize = 32;
/// The length of an AEAD tag, added to every ciphertext.
pub const TAG_LEN: usize = 16;
/// The length of a MAC field (mac1 or mac2).
pub const MAC_LEN: usize = 16;
/// The length of a TAI64N timestamp, before encryption.
pub const TIMESTAMP_LEN: usize = 12;
/// The length of a cookie reply's random nonce (XChaCha20Poly1305).
pub const COOKIE_NONCE_LEN: usize = 24;
/// The length of a cookie, before encryption.
pub const COOKIE_LEN: usize = 16;
/// The length of the encrypted static key: the key and a tag.
pub const ENCRYPTED_STATIC_LEN: usize = KEY_LEN + TAG_LEN;
/// The length of the encrypted timestamp: the timestamp and a tag.
pub const ENCRYPTED_TIMESTAMP_LEN: usize = TIMESTAMP_LEN + TAG_LEN;
/// The length of the encrypted cookie: the cookie and a tag.
pub const ENCRYPTED_COOKIE_LEN: usize = COOKIE_LEN + TAG_LEN;
/// The length of a handshake initiation.
pub const INITIATION_LEN: usize = 4 + 4 + KEY_LEN + ENCRYPTED_STATIC_LEN + ENCRYPTED_TIMESTAMP_LEN + 2 * MAC_LEN;
/// The length of a handshake response.
pub const RESPONSE_LEN: usize = 4 + 4 + 4 + KEY_LEN + TAG_LEN + 2 * MAC_LEN;
/// The length of a cookie reply.
pub const COOKIE_REPLY_LEN: usize = 4 + 4 + COOKIE_NONCE_LEN + ENCRYPTED_COOKIE_LEN;
/// The length of a transport data message's header: type, receiver and
/// counter.
pub const DATA_HEADER_LEN: usize = 4 + 4 + 8;
/// The shortest transport data message: the header and a tag, which is a
/// keepalive.
pub const MIN_DATA_LEN: usize = DATA_HEADER_LEN + TAG_LEN;
/// The longest message: the largest UDP payload (65535 less the 8-byte UDP
/// header).
pub const MAX_MESSAGE: usize = 65_535 - 8;
/// The longest encrypted part a transport data message may carry.
pub const MAX_ENCRYPTED: usize = MAX_MESSAGE - DATA_HEADER_LEN;
/// Plaintexts are padded with zeros to a multiple of this many bytes.
pub const PADDING_MULTIPLE: usize = 16;
/// The longest plaintext [`pad`] takes. It leaves room for padding and a
/// tag within [`MAX_ENCRYPTED`].
pub const MAX_PLAINTEXT: usize = MAX_ENCRYPTED - TAG_LEN - PADDING_MULTIPLE;
/// A key pair may send counters below this, and no more: 2^64 - 2^13 - 1
/// (the paper's Reject-After-Messages).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
/// How many counters behind the highest one a [`ReplayWindow`] still
/// accepts, plus one.
pub const WINDOW_BITS: u64 = 2048;

/// A handshake initiation (type 1, 148 bytes), sent by the peer that
/// starts a handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Initiation {
    /// The index the initiator picked for this session. Replies name it as
    /// their receiver.
    pub sender: u32,
    /// The initiator's ephemeral public key, in the clear.
    pub ephemeral: [u8; KEY_LEN],
    /// The initiator's static public key, encrypted, with its tag.
    pub encrypted_static: [u8; ENCRYPTED_STATIC_LEN],
    /// A TAI64N timestamp, encrypted, with its tag.
    pub encrypted_timestamp: [u8; ENCRYPTED_TIMESTAMP_LEN],
    /// A MAC over the bytes before it, keyed by the responder's public key.
    pub mac1: [u8; MAC_LEN],
    /// A MAC over the bytes before it, keyed by a cookie, or all zeros.
    pub mac2: [u8; MAC_LEN],
}

/// A handshake response (type 2, 92 bytes), the answer to an initiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The index the responder picked for this session.
    pub sender: u32,
    /// The initiation's sender index.
    pub receiver: u32,
    /// The responder's ephemeral public key, in the clear.
    pub ephemeral: [u8; KEY_LEN],
    /// An empty plaintext, encrypted: only a tag.
    pub encrypted_nothing: [u8; TAG_LEN],
    /// A MAC over the bytes before it, keyed by the initiator's public key.
    pub mac1: [u8; MAC_LEN],
    /// A MAC over the bytes before it, keyed by a cookie, or all zeros.
    pub mac2: [u8; MAC_LEN],
}

/// A cookie reply (type 3, 64 bytes), sent instead of a response by a peer
/// under load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieReply {
    /// The sender index of the message this answers.
    pub receiver: u32,
    /// A random nonce for the cookie's encryption.
    pub nonce: [u8; COOKIE_NONCE_LEN],
    /// The cookie, encrypted, with its tag.
    pub encrypted_cookie: [u8; ENCRYPTED_COOKIE_LEN],
}

/// A transport data message (type 4): one encrypted, padded IP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    /// The session index the receiving peer picked.
    pub receiver: u32,
    /// The message counter, also the AEAD nonce. It counts up from 0 for
    /// each key pair.
    pub counter: u64,
    /// The padded packet, encrypted, with its tag. It holds at least a tag
    /// ([`TAG_LEN`] bytes) and at most [`MAX_ENCRYPTED`] bytes.
    pub encrypted: Vec<u8>,
}

/// Any WireGuard message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Type 1.
    Initiation(Initiation),
    /// Type 2.
    Response(Response),
    /// Type 3.
    CookieReply(CookieReply),
    /// Type 4.
    Data(Data),
}

/// Why bytes are not a WireGuard message. A real peer drops such a
/// datagram without an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer than 4 bytes, so there is no type field.
    Short(usize),
    /// The type byte is not 1 to 4.
    Type(u8),
    /// The type byte is a known type, but not the one a per-type reader
    /// such as [`Initiation::parse`] wants.
    Unexpected {
        /// The type the reader wants.
        want: u8,
        /// The type byte found.
        found: u8,
    },
    /// The three bytes after the type byte are not all 0.
    Reserved([u8; 3]),
    /// The message has the wrong length for its type: not the exact size
    /// of a handshake message, or a transport data message shorter than
    /// [`MIN_DATA_LEN`] or longer than [`MAX_MESSAGE`].
    Length {
        /// The type byte.
        kind: u8,
        /// The length of the bytes given.
        len: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Short(n) => write!(f, "{n} bytes, too short for a message type"),
            Error::Type(t) => write!(f, "message type {t}, not 1 to 4"),
            Error::Unexpected { want, found } => write!(f, "message type {found}, not the type {want} wanted here"),
            Error::Reserved(r) => write!(f, "reserved bytes {r:?}, not all 0"),
            Error::Length { kind, len } => write!(f, "{len} bytes, the wrong length for message type {kind}"),
        }
    }
}

impl std::error::Error for Error {}

impl Message {
    /// Reads one message from a whole UDP payload. The payload must be
    /// exactly one message: extra bytes after a handshake message are an
    /// error.
    pub fn parse(b: &[u8]) -> Result<Message, Error> {
        let kind = check_type(b)?;
        Ok(match kind {
            message_type::INITIATION => Message::Initiation(Initiation::parse(b)?),
            message_type::RESPONSE => Message::Response(Response::parse(b)?),
            message_type::COOKIE_REPLY => Message::CookieReply(CookieReply::parse(b)?),
            _ => Message::Data(Data::parse(b)?),
        })
    }

    /// The message's bytes, ready to send as one UDP payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::Initiation(m) => m.to_bytes(),
            Message::Response(m) => m.to_bytes(),
            Message::CookieReply(m) => m.to_bytes(),
            Message::Data(m) => m.to_bytes(),
        }
    }

    /// The message's type byte.
    pub fn kind(&self) -> u8 {
        match self {
            Message::Initiation(_) => message_type::INITIATION,
            Message::Response(_) => message_type::RESPONSE,
            Message::CookieReply(_) => message_type::COOKIE_REPLY,
            Message::Data(_) => message_type::DATA,
        }
    }

    /// The receiver index the message names, which tells a peer which
    /// session it belongs to. An initiation names none.
    pub fn receiver(&self) -> Option<u32> {
        match self {
            Message::Initiation(_) => None,
            Message::Response(m) => Some(m.receiver),
            Message::CookieReply(m) => Some(m.receiver),
            Message::Data(m) => Some(m.receiver),
        }
    }
}

impl Initiation {
    /// Reads a handshake initiation. `b` must be exactly
    /// [`INITIATION_LEN`] bytes with type 1.
    pub fn parse(b: &[u8]) -> Result<Initiation, Error> {
        let mut r = Reader::exact(b, message_type::INITIATION, INITIATION_LEN)?;
        Ok(Initiation {
            sender: r.u32()?,
            ephemeral: r.array()?,
            encrypted_static: r.array()?,
            encrypted_timestamp: r.array()?,
            mac1: r.array()?,
            mac2: r.array()?,
        })
    }

    /// The message's bytes, [`INITIATION_LEN`] of them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = header(message_type::INITIATION, INITIATION_LEN);
        out.extend_from_slice(&self.sender.to_le_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.encrypted_static);
        out.extend_from_slice(&self.encrypted_timestamp);
        out.extend_from_slice(&self.mac1);
        out.extend_from_slice(&self.mac2);
        out
    }

    /// The bytes mac1 is computed over: every byte before it.
    pub fn mac1_input(&self) -> Vec<u8> {
        let mut b = self.to_bytes();
        b.truncate(INITIATION_LEN - 2 * MAC_LEN);
        b
    }

    /// The bytes mac2 is computed over: every byte before it, mac1
    /// included.
    pub fn mac2_input(&self) -> Vec<u8> {
        let mut b = self.to_bytes();
        b.truncate(INITIATION_LEN - MAC_LEN);
        b
    }
}

impl Response {
    /// Reads a handshake response. `b` must be exactly [`RESPONSE_LEN`]
    /// bytes with type 2.
    pub fn parse(b: &[u8]) -> Result<Response, Error> {
        let mut r = Reader::exact(b, message_type::RESPONSE, RESPONSE_LEN)?;
        Ok(Response {
            sender: r.u32()?,
            receiver: r.u32()?,
            ephemeral: r.array()?,
            encrypted_nothing: r.array()?,
            mac1: r.array()?,
            mac2: r.array()?,
        })
    }

    /// The message's bytes, [`RESPONSE_LEN`] of them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = header(message_type::RESPONSE, RESPONSE_LEN);
        out.extend_from_slice(&self.sender.to_le_bytes());
        out.extend_from_slice(&self.receiver.to_le_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.encrypted_nothing);
        out.extend_from_slice(&self.mac1);
        out.extend_from_slice(&self.mac2);
        out
    }

    /// The bytes mac1 is computed over: every byte before it.
    pub fn mac1_input(&self) -> Vec<u8> {
        let mut b = self.to_bytes();
        b.truncate(RESPONSE_LEN - 2 * MAC_LEN);
        b
    }

    /// The bytes mac2 is computed over: every byte before it, mac1
    /// included.
    pub fn mac2_input(&self) -> Vec<u8> {
        let mut b = self.to_bytes();
        b.truncate(RESPONSE_LEN - MAC_LEN);
        b
    }
}

impl CookieReply {
    /// Reads a cookie reply. `b` must be exactly [`COOKIE_REPLY_LEN`]
    /// bytes with type 3.
    pub fn parse(b: &[u8]) -> Result<CookieReply, Error> {
        let mut r = Reader::exact(b, message_type::COOKIE_REPLY, COOKIE_REPLY_LEN)?;
        Ok(CookieReply { receiver: r.u32()?, nonce: r.array()?, encrypted_cookie: r.array()? })
    }

    /// The message's bytes, [`COOKIE_REPLY_LEN`] of them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = header(message_type::COOKIE_REPLY, COOKIE_REPLY_LEN);
        out.extend_from_slice(&self.receiver.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.encrypted_cookie);
        out
    }
}

impl Data {
    /// Reads a transport data message. `b` must have type 4 and be from
    /// [`MIN_DATA_LEN`] to [`MAX_MESSAGE`] bytes long. The encrypted part
    /// need not be a multiple of 16 bytes, since padding stops at the MTU.
    pub fn parse(b: &[u8]) -> Result<Data, Error> {
        let kind = check_type(b)?;
        if kind != message_type::DATA {
            return Err(Error::Unexpected { want: message_type::DATA, found: kind });
        }
        if b.len() < MIN_DATA_LEN || b.len() > MAX_MESSAGE {
            return Err(Error::Length { kind, len: b.len() });
        }
        let mut r = Reader { b, pos: 4, kind };
        let receiver = r.u32()?;
        let counter = u64::from_le_bytes(r.array()?);
        let encrypted = b.get(DATA_HEADER_LEN..).unwrap_or_default().to_vec();
        Ok(Data { receiver, counter, encrypted })
    }

    /// The message's bytes. An encrypted part longer than
    /// [`MAX_ENCRYPTED`] is cut to that length, and one shorter than a tag
    /// is filled out with zeros, since no message can be shorter.
    pub fn to_bytes(&self) -> Vec<u8> {
        let enc = &self.encrypted[..self.encrypted.len().min(MAX_ENCRYPTED)];
        let mut out = header(message_type::DATA, DATA_HEADER_LEN + enc.len().max(TAG_LEN));
        out.extend_from_slice(&self.receiver.to_le_bytes());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(enc);
        out.resize(out.len().max(MIN_DATA_LEN), 0);
        out
    }

    /// Whether this is a keepalive: an empty plaintext, so only a tag.
    pub fn is_keepalive(&self) -> bool {
        self.encrypted.len() == TAG_LEN
    }
}

/// How many zero bytes go after a plaintext of `len` bytes, sent on a
/// tunnel with the given `mtu`. The plaintext is padded to a multiple of
/// [`PADDING_MULTIPLE`], but never past the MTU. An `mtu` of 0 means no
/// MTU is known. A plaintext longer than the MTU is padded as if only its
/// last MTU-sized piece counted, as the Linux module does.
pub fn padding(len: usize, mtu: usize) -> usize {
    let last = if mtu != 0 && len > mtu { len % mtu } else { len };
    let rem = last % PADDING_MULTIPLE;
    let up = if rem == 0 { 0 } else { PADDING_MULTIPLE - rem };
    if mtu == 0 {
        return up;
    }
    match last.checked_add(up) {
        Some(padded) if padded <= mtu => up,
        _ => mtu.saturating_sub(last),
    }
}

/// A plaintext with its padding added, ready for encryption. A plaintext
/// longer than [`MAX_PLAINTEXT`] is cut to that length first, so the
/// encrypted result always fits in one message.
pub fn pad(plaintext: &[u8], mtu: usize) -> Vec<u8> {
    let p = &plaintext[..plaintext.len().min(MAX_PLAINTEXT)];
    let n = padding(p.len(), mtu);
    let mut out = Vec::with_capacity(p.len() + n);
    out.extend_from_slice(p);
    out.resize(p.len() + n, 0);
    out
}

/// Remembers which transport data counters a receiver has taken, so it
/// can drop replays. It accepts a counter once, and only if it is no more
/// than [`WINDOW_BITS`] - 1 behind the highest seen and below
/// [`REJECT_AFTER_MESSAGES`]. A receiver calls [`ReplayWindow::accept`]
/// only after the message decrypts, so forged counters cannot move the
/// window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayWindow {
    /// One bit per counter, at index `counter % WINDOW_BITS`.
    bits: [u64; (WINDOW_BITS / 64) as usize],
    /// The highest counter accepted so far.
    highest: Option<u64>,
}

impl Default for ReplayWindow {
    fn default() -> ReplayWindow {
        ReplayWindow::new()
    }
}

impl ReplayWindow {
    /// A window that has seen no counters.
    pub fn new() -> ReplayWindow {
        ReplayWindow { bits: [0; (WINDOW_BITS / 64) as usize], highest: None }
    }

    /// Takes `counter` and returns true if it is new and in range. It
    /// returns false, and changes nothing, for a replay, a counter too far
    /// behind, or one at or past [`REJECT_AFTER_MESSAGES`].
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        match self.highest {
            Some(h) if counter <= h => {
                if h - counter >= WINDOW_BITS || self.get(counter) {
                    return false;
                }
            }
            Some(h) => {
                let ahead = counter - h;
                if ahead >= WINDOW_BITS {
                    self.bits = [0; (WINDOW_BITS / 64) as usize];
                } else {
                    // Forget the counters the window slides past.
                    for c in h + 1..=counter {
                        self.clear(c);
                    }
                }
                self.highest = Some(counter);
            }
            None => self.highest = Some(counter),
        }
        self.set(counter);
        true
    }

    /// The highest counter accepted so far, if any.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    fn slot(counter: u64) -> (usize, u64) {
        let i = counter % WINDOW_BITS;
        ((i / 64) as usize, 1u64 << (i % 64))
    }

    fn get(&self, counter: u64) -> bool {
        let (w, m) = Self::slot(counter);
        self.bits.get(w).is_some_and(|x| x & m != 0)
    }

    fn set(&mut self, counter: u64) {
        let (w, m) = Self::slot(counter);
        if let Some(x) = self.bits.get_mut(w) {
            *x |= m;
        }
    }

    fn clear(&mut self, counter: u64) {
        let (w, m) = Self::slot(counter);
        if let Some(x) = self.bits.get_mut(w) {
            *x &= !m;
        }
    }
}

/// Checks the 4-byte type field and returns the type byte.
fn check_type(b: &[u8]) -> Result<u8, Error> {
    let [kind, r0, r1, r2, ..] = *b else { return Err(Error::Short(b.len())) };
    if !(message_type::INITIATION..=message_type::DATA).contains(&kind) {
        return Err(Error::Type(kind));
    }
    if [r0, r1, r2] != [0, 0, 0] {
        return Err(Error::Reserved([r0, r1, r2]));
    }
    Ok(kind)
}

/// The type field of a message, with room for `len` bytes in all.
fn header(kind: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&[kind, 0, 0, 0]);
    out
}

/// Reads fields in order after the type field. A field past the end is a
/// length error, though callers check lengths first.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    kind: u8,
}

impl<'a> Reader<'a> {
    /// A reader for a message of type `kind` that must be `len` bytes.
    fn exact(b: &'a [u8], kind: u8, len: usize) -> Result<Reader<'a>, Error> {
        let found = check_type(b)?;
        if found != kind {
            return Err(Error::Unexpected { want: kind, found });
        }
        if b.len() != len {
            return Err(Error::Length { kind, len: b.len() });
        }
        Ok(Reader { b, pos: 4, kind })
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let short = Error::Length { kind: self.kind, len: self.b.len() };
        let end = self.pos.checked_add(N).ok_or(short)?;
        let a = self.b.get(self.pos..end).and_then(|s| <[u8; N]>::try_from(s).ok()).ok_or(short)?;
        self.pos = end;
        Ok(a)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> Initiation {
        Initiation {
            sender: 0x0403_0201,
            ephemeral: [0x11; 32],
            encrypted_static: [0x22; 48],
            encrypted_timestamp: [0x33; 28],
            mac1: [0x44; 16],
            mac2: [0x55; 16],
        }
    }

    fn resp() -> Response {
        Response {
            sender: 0xdead_beef,
            receiver: 0x0403_0201,
            ephemeral: [0x66; 32],
            encrypted_nothing: [0x77; 16],
            mac1: [0x88; 16],
            mac2: [0; 16],
        }
    }

    fn cookie() -> CookieReply {
        CookieReply { receiver: 5, nonce: [0x99; 24], encrypted_cookie: [0xaa; 32] }
    }

    fn data() -> Data {
        Data { receiver: 0xdead_beef, counter: 0x0102_0304_0506_0708, encrypted: vec![0xbb; 48] }
    }

    fn all() -> Vec<Message> {
        vec![
            Message::Initiation(init()),
            Message::Response(resp()),
            Message::CookieReply(cookie()),
            Message::Data(data()),
        ]
    }

    // Sizes and offsets from the WireGuard paper, section 5.4.

    #[test]
    fn sizes_match_the_paper() {
        assert_eq!(INITIATION_LEN, 148);
        assert_eq!(RESPONSE_LEN, 92);
        assert_eq!(COOKIE_REPLY_LEN, 64);
        assert_eq!(MIN_DATA_LEN, 32);
        assert_eq!(REJECT_AFTER_MESSAGES, 18_446_744_073_709_543_423);
    }

    #[test]
    fn initiation_layout() {
        let b = init().to_bytes();
        assert_eq!(b.len(), 148);
        assert_eq!(b[..4], [1, 0, 0, 0]);
        assert_eq!(b[4..8], [1, 2, 3, 4]); // little-endian sender
        assert_eq!(b[8..40], [0x11; 32]);
        assert_eq!(b[40..88], [0x22; 48]);
        assert_eq!(b[88..116], [0x33; 28]);
        assert_eq!(b[116..132], [0x44; 16]);
        assert_eq!(b[132..148], [0x55; 16]);
        assert_eq!(init().mac1_input(), b[..116]);
        assert_eq!(init().mac2_input(), b[..132]);
    }

    #[test]
    fn response_layout() {
        let b = resp().to_bytes();
        assert_eq!(b.len(), 92);
        assert_eq!(b[..4], [2, 0, 0, 0]);
        assert_eq!(b[4..8], [0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(b[8..12], [1, 2, 3, 4]);
        assert_eq!(b[12..44], [0x66; 32]);
        assert_eq!(b[44..60], [0x77; 16]);
        assert_eq!(b[60..76], [0x88; 16]);
        assert_eq!(b[76..92], [0; 16]);
        assert_eq!(resp().mac1_input(), b[..60]);
        assert_eq!(resp().mac2_input(), b[..76]);
    }

    #[test]
    fn cookie_reply_layout() {
        let b = cookie().to_bytes();
        assert_eq!(b.len(), 64);
        assert_eq!(b[..8], [3, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(b[8..32], [0x99; 24]);
        assert_eq!(b[32..64], [0xaa; 32]);
    }

    #[test]
    fn data_layout() {
        let b = data().to_bytes();
        assert_eq!(b.len(), 16 + 48);
        assert_eq!(b[..8], [4, 0, 0, 0, 0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(b[8..16], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(b[16..], [0xbb; 48]);
        assert!(!data().is_keepalive());
        let k = Data { receiver: 1, counter: 0, encrypted: vec![0; 16] };
        assert!(k.is_keepalive());
        assert_eq!(k.to_bytes().len(), 32);
    }

    #[test]
    fn round_trips() {
        for m in all() {
            let b = m.to_bytes();
            assert_eq!(Message::parse(&b), Ok(m.clone()));
            assert_eq!(Message::parse(&b).unwrap().to_bytes(), b);
        }
        assert_eq!(Initiation::parse(&init().to_bytes()), Ok(init()));
        assert_eq!(Response::parse(&resp().to_bytes()), Ok(resp()));
        assert_eq!(CookieReply::parse(&cookie().to_bytes()), Ok(cookie()));
        assert_eq!(Data::parse(&data().to_bytes()), Ok(data()));
    }

    #[test]
    fn kinds_and_receivers() {
        let kinds: Vec<u8> = all().iter().map(Message::kind).collect();
        assert_eq!(kinds, [1, 2, 3, 4]);
        let receivers: Vec<Option<u32>> = all().iter().map(Message::receiver).collect();
        assert_eq!(receivers, [None, Some(0x0403_0201), Some(5), Some(0xdead_beef)]);
    }

    #[test]
    fn every_truncated_prefix_is_an_error() {
        for m in all() {
            let b = m.to_bytes();
            for n in 0..b.len() {
                let e = Message::parse(&b[..n]);
                if n < 4 {
                    assert_eq!(e, Err(Error::Short(n)));
                } else if m.kind() == message_type::DATA && n >= MIN_DATA_LEN {
                    // A shorter data message is still a data message.
                    assert!(e.is_ok());
                } else {
                    assert_eq!(e, Err(Error::Length { kind: m.kind(), len: n }), "{n} bytes of type {}", m.kind());
                }
            }
        }
    }

    #[test]
    fn errors() {
        assert_eq!(Message::parse(&[]), Err(Error::Short(0)));
        assert_eq!(Message::parse(&[1, 0, 0]), Err(Error::Short(3)));
        assert_eq!(Message::parse(&[0, 0, 0, 0]), Err(Error::Type(0)));
        assert_eq!(Message::parse(&[5, 0, 0, 0]), Err(Error::Type(5)));
        assert_eq!(Message::parse(&[0xff, 0, 0, 0]), Err(Error::Type(0xff)));
        let mut b = init().to_bytes();
        b[2] = 1;
        assert_eq!(Message::parse(&b), Err(Error::Reserved([0, 1, 0])));
        // One byte too many.
        let mut b = init().to_bytes();
        b.push(0);
        assert_eq!(Message::parse(&b), Err(Error::Length { kind: 1, len: 149 }));
        let mut b = cookie().to_bytes();
        b.push(0);
        assert_eq!(Message::parse(&b), Err(Error::Length { kind: 3, len: 65 }));
        // A data message too long for UDP.
        let mut b = vec![4, 0, 0, 0];
        b.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(Message::parse(&b), Err(Error::Length { kind: 4, len: MAX_MESSAGE + 1 }));
        b.pop();
        assert!(Message::parse(&b).is_ok());
        // The per-type readers check the type. A known type that is not the
        // one a reader wants is its own error, not an unknown type.
        assert_eq!(Initiation::parse(&resp().to_bytes()), Err(Error::Unexpected { want: 1, found: 2 }));
        assert_eq!(Response::parse(&init().to_bytes()), Err(Error::Unexpected { want: 2, found: 1 }));
        assert_eq!(CookieReply::parse(&data().to_bytes()), Err(Error::Unexpected { want: 3, found: 4 }));
        assert_eq!(Data::parse(&cookie().to_bytes()), Err(Error::Unexpected { want: 4, found: 3 }));
        assert_eq!(Data::parse(&[9, 0, 0, 0]), Err(Error::Type(9)));
        assert!(!Error::Unexpected { want: 1, found: 2 }.to_string().contains("not 1 to 4"));
        // Every error has a message.
        for e in [
            Error::Short(1),
            Error::Type(9),
            Error::Unexpected { want: 1, found: 2 },
            Error::Reserved([1, 2, 3]),
            Error::Length { kind: 1, len: 2 },
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn reserved_bytes_for_every_type_and_position() {
        for m in all() {
            for i in 1..4 {
                let mut b = m.to_bytes();
                b[i] = 0x80;
                let mut r = [0; 3];
                r[i - 1] = 0x80;
                let want: Result<(), Error> = Err(Error::Reserved(r));
                assert_eq!(Message::parse(&b).map(|_| ()), want);
                match &m {
                    Message::Initiation(_) => assert_eq!(Initiation::parse(&b).map(|_| ()), want),
                    Message::Response(_) => assert_eq!(Response::parse(&b).map(|_| ()), want),
                    Message::CookieReply(_) => assert_eq!(CookieReply::parse(&b).map(|_| ()), want),
                    Message::Data(_) => assert_eq!(Data::parse(&b).map(|_| ()), want),
                }
            }
        }
    }

    #[test]
    fn per_type_readers_on_every_prefix() {
        let b = init().to_bytes();
        for n in 0..b.len() {
            let want = if n < 4 { Error::Short(n) } else { Error::Length { kind: 1, len: n } };
            assert_eq!(Initiation::parse(&b[..n]), Err(want));
        }
        let b = resp().to_bytes();
        for n in 0..b.len() {
            let want = if n < 4 { Error::Short(n) } else { Error::Length { kind: 2, len: n } };
            assert_eq!(Response::parse(&b[..n]), Err(want));
        }
        let b = cookie().to_bytes();
        for n in 0..b.len() {
            let want = if n < 4 { Error::Short(n) } else { Error::Length { kind: 3, len: n } };
            assert_eq!(CookieReply::parse(&b[..n]), Err(want));
        }
        let b = data().to_bytes();
        for n in 0..=b.len() {
            let got = Data::parse(&b[..n]);
            if n < 4 {
                assert_eq!(got, Err(Error::Short(n)));
            } else if n < MIN_DATA_LEN {
                assert_eq!(got, Err(Error::Length { kind: 4, len: n }));
            } else {
                assert_eq!(got.map(|d| d.encrypted.len()), Ok(n - DATA_HEADER_LEN));
            }
        }
    }

    #[test]
    fn data_writer_output_always_parses() {
        let mut s = Lcg(0xda7a);
        let edges = [0, 1, 15, 16, 17, MAX_ENCRYPTED - 1, MAX_ENCRYPTED, MAX_ENCRYPTED + 1, MAX_MESSAGE];
        for i in 0..400 {
            let n = if i < edges.len() { edges[i] } else { (s.next() % 2000) as usize };
            let d = Data { receiver: s.next() as u32, counter: s.next() << 20, encrypted: vec![0x5a; n] };
            let b = d.to_bytes();
            assert!(b.len() >= MIN_DATA_LEN && b.len() <= MAX_MESSAGE, "{n}");
            let back = Data::parse(&b).unwrap();
            assert_eq!(back.receiver, d.receiver);
            assert_eq!(back.counter, d.counter);
            if (TAG_LEN..=MAX_ENCRYPTED).contains(&n) {
                assert_eq!(back, d);
            }
            assert_eq!(back.to_bytes(), b);
        }
    }

    #[test]
    fn writers_cap_what_they_write() {
        let short = Data { receiver: 1, counter: 2, encrypted: vec![7; 3] };
        let b = short.to_bytes();
        assert_eq!(b.len(), MIN_DATA_LEN);
        let back = Data::parse(&b).unwrap();
        assert_eq!(back.encrypted[..3], [7; 3]);
        assert_eq!(back.encrypted[3..], [0; 13]);
        let long = Data { receiver: 1, counter: 2, encrypted: vec![7; MAX_MESSAGE * 2] };
        let b = long.to_bytes();
        assert_eq!(b.len(), MAX_MESSAGE);
        assert!(Message::parse(&b).is_ok());
        let empty = Data { receiver: 0, counter: 0, encrypted: Vec::new() };
        assert!(Message::parse(&empty.to_bytes()).is_ok());
    }

    #[test]
    fn padding_rules() {
        // No MTU: up to a multiple of 16.
        assert_eq!(padding(0, 0), 0);
        assert_eq!(padding(1, 0), 15);
        assert_eq!(padding(16, 0), 0);
        assert_eq!(padding(17, 0), 15);
        // Never past the MTU.
        assert_eq!(padding(1415, 1420), 5);
        assert_eq!(padding(1418, 1420), 2);
        assert_eq!(padding(1420, 1420), 0);
        // Longer than the MTU: the last piece counts.
        assert_eq!(padding(1421, 1420), 15);
        assert_eq!(padding(usize::MAX, 0), 1);
        assert_eq!(padding(usize::MAX, usize::MAX), 0);
        assert_eq!(padding(usize::MAX - 3, usize::MAX), 3);
        assert_eq!(pad(&[1, 2, 3], 0), [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(pad(&[], 1420), Vec::<u8>::new());
        let big = pad(&vec![1; MAX_MESSAGE], 0);
        assert!(big.len() + TAG_LEN <= MAX_ENCRYPTED);
        assert_eq!(big.len() % 16, 0);
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert_eq!(w.highest(), None);
        assert!(w.accept(5));
        assert!(!w.accept(5));
        assert!(w.accept(3)); // late but new
        assert!(!w.accept(3));
        assert!(w.accept(100));
        assert!(w.accept(6));
        assert_eq!(w.highest(), Some(100));
        // Too far behind.
        assert!(w.accept(100 + WINDOW_BITS));
        assert!(!w.accept(100));
        assert!(w.accept(101));
        assert!(!w.accept(101));
        // The window slid past old bits, so a counter reusing a slot is new.
        assert!(w.accept(101 + WINDOW_BITS));
        assert!(!w.accept(101 + WINDOW_BITS));
        // A jump past the whole window clears it.
        assert!(w.accept(1 << 40));
        assert!(w.accept((1 << 40) - 1));
        assert!(!w.accept((1 << 40) - WINDOW_BITS));
        assert!(w.accept((1 << 40) - WINDOW_BITS + 1));
        // The counter limit.
        assert!(!w.accept(REJECT_AFTER_MESSAGES));
        assert!(!w.accept(u64::MAX));
        assert!(w.accept(REJECT_AFTER_MESSAGES - 1));
        assert!(!w.accept(REJECT_AFTER_MESSAGES - 1));
        // A rejected counter changes nothing.
        let before = w.clone();
        assert!(!w.accept(0));
        assert_eq!(w, before);
    }

    #[test]
    fn replay_window_matches_a_set() {
        // Against a plain list of what was taken, one counter at a time.
        let mut w = ReplayWindow::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut highest: Option<u64> = None;
        let mut s = Lcg(7);
        for _ in 0..20_000 {
            let base = highest.unwrap_or(0);
            let c = match s.next() % 4 {
                0 => base.saturating_sub(s.next() % (WINDOW_BITS + 10)),
                1 => base + s.next() % 70,
                2 => base + s.next() % (3 * WINDOW_BITS),
                _ => base.saturating_sub(s.next() % 16),
            };
            let expect = match highest {
                Some(h) if c <= h => h - c < WINDOW_BITS && !seen.contains(&c),
                _ => true,
            };
            assert_eq!(w.accept(c), expect, "counter {c}");
            if expect {
                seen.insert(c);
                highest = Some(highest.map_or(c, |h| h.max(c)));
            }
        }
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut s = Lcg(0x5eed);
        let sizes = [0, 3, 4, 31, 32, 63, 64, 65, 91, 92, 93, 147, 148, 149, 200, 1500];
        for i in 0..20_000 {
            let len =
                if i % 2 == 0 { sizes[(s.next() % sizes.len() as u64) as usize] } else { (s.next() % 300) as usize };
            let mut b: Vec<u8> = (0..len).map(|_| s.next() as u8).collect();
            if !b.is_empty() && !s.next().is_multiple_of(4) {
                b[0] = (s.next() % 5) as u8;
                for x in b.iter_mut().skip(1).take(3) {
                    if !s.next().is_multiple_of(8) {
                        *x = 0;
                    }
                }
            }
            check(&b);
            // The same bytes arriving one more byte at a time.
            if i % 50 == 0 {
                for n in 0..=b.len() {
                    check(&b[..n]);
                }
            }
        }
        // Random messages written, then read back.
        for _ in 0..5_000 {
            let mut bytes = |n: usize| -> Vec<u8> { (0..n).map(|_| s.next() as u8).collect() };
            let m = match bytes(1)[0] % 4 {
                0 => Message::Initiation(Initiation {
                    sender: u32::from_le_bytes(bytes(4).try_into().unwrap()),
                    ephemeral: bytes(32).try_into().unwrap(),
                    encrypted_static: bytes(48).try_into().unwrap(),
                    encrypted_timestamp: bytes(28).try_into().unwrap(),
                    mac1: bytes(16).try_into().unwrap(),
                    mac2: bytes(16).try_into().unwrap(),
                }),
                1 => Message::Response(Response {
                    sender: u32::from_le_bytes(bytes(4).try_into().unwrap()),
                    receiver: u32::from_le_bytes(bytes(4).try_into().unwrap()),
                    ephemeral: bytes(32).try_into().unwrap(),
                    encrypted_nothing: bytes(16).try_into().unwrap(),
                    mac1: bytes(16).try_into().unwrap(),
                    mac2: bytes(16).try_into().unwrap(),
                }),
                2 => Message::CookieReply(CookieReply {
                    receiver: u32::from_le_bytes(bytes(4).try_into().unwrap()),
                    nonce: bytes(24).try_into().unwrap(),
                    encrypted_cookie: bytes(32).try_into().unwrap(),
                }),
                _ => {
                    let n = 16 + usize::from(bytes(1)[0]);
                    Message::Data(Data {
                        receiver: u32::from_le_bytes(bytes(4).try_into().unwrap()),
                        counter: u64::from_le_bytes(bytes(8).try_into().unwrap()),
                        encrypted: bytes(n),
                    })
                }
            };
            let b = m.to_bytes();
            assert_eq!(Message::parse(&b), Ok(m));
        }
    }

    /// Any bytes: no panic, and what parses writes back the same.
    fn check(b: &[u8]) {
        if let Ok(m) = Message::parse(b) {
            assert_eq!(m.to_bytes(), b);
        }
        let _ = Initiation::parse(b);
        let _ = Response::parse(b);
        let _ = CookieReply::parse(b);
        let _ = Data::parse(b);
    }
}
