//! WireGuard: reading and writing the four message types, with no I/O and
//! no cryptography.
//!
//! A real client can send a handshake initiation whose fields this module
//! reads, but cannot establish a tunnel because the module cannot
//! authenticate or encrypt the handshake response.
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
//! the bytes of [`Message::write`] back. Encrypted fields, ephemeral
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
//! use fictionet::stdlib::codec::Wire;
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
//! let bytes = Message::Initiation(init.clone()).to_bytes().unwrap();
//! assert_eq!(bytes.len(), INITIATION_LEN);
//! assert_eq!(bytes[..8], [1, 0, 0, 0, 7, 0, 0, 0]);
//! assert_eq!(Message::parse(&bytes), Ok(Message::Initiation(init)));
//!
//! // A keepalive: counter 0 and only a tag.
//! let keepalive = Data { receiver: 9, counter: 0, encrypted: vec![0xaa; 16] };
//! let bytes = Message::Data(keepalive.clone()).to_bytes().unwrap();
//! assert_eq!(bytes.len(), 32);
//! assert_eq!(Message::parse(&bytes), Ok(Message::Data(keepalive)));
//!
//! // The same counter twice is a replay.
//! let mut window = ReplayWindow::new();
//! assert!(window.accept(0));
//! assert!(!window.accept(0));
//! ```

use fictionet::stdlib::codec::{Reader, Truncated};

use fictionet::stdlib::codec::Wire;

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
pub const INITIATION_LEN: usize =
    4 + 4 + KEY_LEN + ENCRYPTED_STATIC_LEN + ENCRYPTED_TIMESTAMP_LEN + 2 * MAC_LEN;
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
/// The longest padded plaintext that fits in one message once its tag is
/// added. [`Plaintext::padded`] refuses a plaintext whose padded length would pass it.
pub const MAX_PLAINTEXT: usize = MAX_ENCRYPTED - TAG_LEN;
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
    /// The value cannot be written without changing it.
    Unwritable,
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
    /// [`MIN_DATA_LEN`] or longer than [`MAX_MESSAGE`]. Also used for plaintext
    /// above [`MAX_PLAINTEXT`], with kind [`message_type::DATA`] and its plaintext length.
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
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Short(n) => write!(f, "{n} bytes, too short for a message type"),
            Error::Type(t) => write!(f, "message type {t}, not 1 to 4"),
            Error::Unexpected { want, found } => {
                write!(f, "message type {found}, not the type {want} wanted here")
            }
            Error::Reserved(r) => write!(f, "reserved bytes {r:?}, not all 0"),
            Error::Length { kind, len } => {
                write!(f, "{len} bytes, the wrong length for message type {kind}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl Message {
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
    /// The byte range covered by mac1 in the serialized initiation.
    pub const MAC1_INPUT: std::ops::Range<usize> = 0..INITIATION_LEN - 2 * MAC_LEN;
    /// The byte range covered by mac2, including mac1.
    pub const MAC2_INPUT: std::ops::Range<usize> = 0..INITIATION_LEN - MAC_LEN;
}

impl Response {
    /// The byte range covered by mac1 in the serialized response.
    pub const MAC1_INPUT: std::ops::Range<usize> = 0..RESPONSE_LEN - 2 * MAC_LEN;
    /// The byte range covered by mac2, including mac1.
    pub const MAC2_INPUT: std::ops::Range<usize> = 0..RESPONSE_LEN - MAC_LEN;
}

impl Data {
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
    let last = if mtu != 0 && len > mtu {
        len % mtu
    } else {
        len
    };
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

/// A plaintext ready for encryption, including any chosen padding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plaintext(
    /// The bytes to encrypt, including any selected padding.
    pub Vec<u8>,
);

impl Plaintext {
    /// Copies a plaintext and adds the zeros chosen by [padding].
    /// Refuses a padded length above [`MAX_PLAINTEXT`].
    pub fn padded(plaintext: &[u8], mtu: usize) -> Result<Self, Error> {
        let padded = plaintext
            .len()
            .checked_add(padding(plaintext.len(), mtu))
            .ok_or(Error::Unwritable)?;
        if padded > MAX_PLAINTEXT {
            return Err(Error::Unwritable);
        }
        let mut out = Vec::new();
        out.extend_from_slice(plaintext);
        out.resize(padded, 0);
        Ok(Self(out))
    }
}

impl Wire for Plaintext {
    type ParseError = Error;
    type WriteError = Error;

    /// Keeps every byte, including zeros. Refuses input above [`MAX_PLAINTEXT`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_PLAINTEXT {
            return Err(Error::Length {
                kind: message_type::DATA,
                len: b.len(),
            });
        }
        Ok(Self(b.to_vec()))
    }

    /// Appends the stored plaintext. Refuses oversized values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.len() > MAX_PLAINTEXT {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&self.0);
        Ok(())
    }
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
        ReplayWindow {
            bits: [0; (WINDOW_BITS / 64) as usize],
            highest: None,
        }
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
    let [kind, r0, r1, r2, ..] = *b else {
        return Err(Error::Short(b.len()));
    };
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

/// Checks a fixed message's type and length before reading its fields.
#[inline]
fn exact(b: &[u8], kind: u8, len: usize) -> Result<Reader<'_>, Error> {
    let found = check_type(b)?;
    if found != kind {
        return Err(Error::Unexpected { want: kind, found });
    }
    if b.len() != len {
        return Err(Error::Length { kind, len: b.len() });
    }
    let mut r = Reader::new(b);
    r.skip(4)
        .map_err(|_| Error::Length { kind, len: b.len() })?;
    Ok(r)
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one message from a whole UDP payload. The payload must be
    /// exactly one message: extra bytes after a handshake message are an
    /// error.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<Message, Error> {
        let kind = check_type(b)?;
        Ok(match kind {
            message_type::INITIATION => Message::Initiation(Initiation::parse(b)?),
            message_type::RESPONSE => Message::Response(Response::parse(b)?),
            message_type::COOKIE_REPLY => Message::CookieReply(CookieReply::parse(b)?),
            _ => Message::Data(Data::parse(b)?),
        })
    }

    /// Appends the complete wire form. Refuses values outside the wire limits.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Message::Initiation(m) => m.write(dst),
            Message::Response(m) => m.write(dst),
            Message::CookieReply(m) => m.write(dst),
            Message::Data(m) => m.write(dst),
        }
    }
}

impl Wire for Initiation {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a handshake initiation. `b` must be exactly
    /// [`INITIATION_LEN`] bytes with type 1.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<Initiation, Error> {
        let mut r = exact(b, message_type::INITIATION, INITIATION_LEN)?;
        let short = |_: Truncated| Error::Length {
            kind: message_type::INITIATION,
            len: b.len(),
        };
        Ok(Initiation {
            sender: r.u32_le().map_err(short)?,
            ephemeral: r.array().map_err(short)?,
            encrypted_static: r.array().map_err(short)?,
            encrypted_timestamp: r.array().map_err(short)?,
            mac1: r.array().map_err(short)?,
            mac2: r.array().map_err(short)?,
        })
    }

    /// Appends the complete 148-byte initiation. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = header(message_type::INITIATION, INITIATION_LEN);
        out.extend_from_slice(&self.sender.to_le_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.encrypted_static);
        out.extend_from_slice(&self.encrypted_timestamp);
        out.extend_from_slice(&self.mac1);
        out.extend_from_slice(&self.mac2);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Response {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a handshake response. `b` must be exactly [`RESPONSE_LEN`]
    /// bytes with type 2.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<Response, Error> {
        let mut r = exact(b, message_type::RESPONSE, RESPONSE_LEN)?;
        let short = |_: Truncated| Error::Length {
            kind: message_type::RESPONSE,
            len: b.len(),
        };
        Ok(Response {
            sender: r.u32_le().map_err(short)?,
            receiver: r.u32_le().map_err(short)?,
            ephemeral: r.array().map_err(short)?,
            encrypted_nothing: r.array().map_err(short)?,
            mac1: r.array().map_err(short)?,
            mac2: r.array().map_err(short)?,
        })
    }

    /// Appends the complete 92-byte response. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = header(message_type::RESPONSE, RESPONSE_LEN);
        out.extend_from_slice(&self.sender.to_le_bytes());
        out.extend_from_slice(&self.receiver.to_le_bytes());
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.encrypted_nothing);
        out.extend_from_slice(&self.mac1);
        out.extend_from_slice(&self.mac2);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for CookieReply {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a cookie reply. `b` must be exactly [`COOKIE_REPLY_LEN`]
    /// bytes with type 3.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<CookieReply, Error> {
        let mut r = exact(b, message_type::COOKIE_REPLY, COOKIE_REPLY_LEN)?;
        let short = |_: Truncated| Error::Length {
            kind: message_type::COOKIE_REPLY,
            len: b.len(),
        };
        Ok(CookieReply {
            receiver: r.u32_le().map_err(short)?,
            nonce: r.array().map_err(short)?,
            encrypted_cookie: r.array().map_err(short)?,
        })
    }

    /// Appends the complete 64-byte cookie reply. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = header(message_type::COOKIE_REPLY, COOKIE_REPLY_LEN);
        out.extend_from_slice(&self.receiver.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.encrypted_cookie);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Data {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a transport data message. `b` must have type 4 and be from
    /// [`MIN_DATA_LEN`] to [`MAX_MESSAGE`] bytes long. The encrypted part
    /// need not be a multiple of 16 bytes, since padding stops at the MTU.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<Data, Error> {
        let kind = check_type(b)?;
        if kind != message_type::DATA {
            return Err(Error::Unexpected {
                want: message_type::DATA,
                found: kind,
            });
        }
        if b.len() < MIN_DATA_LEN || b.len() > MAX_MESSAGE {
            return Err(Error::Length { kind, len: b.len() });
        }
        let mut r = Reader::new(b);
        let short = |_: Truncated| Error::Length { kind, len: b.len() };
        r.skip(4).map_err(short)?;
        let receiver = r.u32_le().map_err(short)?;
        let counter = r.u64_le().map_err(short)?;
        let encrypted = b.get(DATA_HEADER_LEN..).unwrap_or_default().to_vec();
        Ok(Data {
            receiver,
            counter,
            encrypted,
        })
    }

    /// Appends the complete transport message. Refuses ciphertext shorter than [`TAG_LEN`]
    /// or longer than [`MAX_ENCRYPTED`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let len = DATA_HEADER_LEN.saturating_add(self.encrypted.len());
        if !(TAG_LEN..=MAX_ENCRYPTED).contains(&self.encrypted.len()) {
            return Err(Error::Unwritable);
        }
        let mut out = header(message_type::DATA, len);
        out.extend_from_slice(&self.receiver.to_le_bytes());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.encrypted);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::rounds;

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
        CookieReply {
            receiver: 5,
            nonce: [0x99; 24],
            encrypted_cookie: [0xaa; 32],
        }
    }

    fn data() -> Data {
        Data {
            receiver: 0xdead_beef,
            counter: 0x0102_0304_0506_0708,
            encrypted: vec![0xbb; 48],
        }
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
        let b = init().to_bytes().unwrap();
        assert_eq!(b.len(), 148);
        assert_eq!(b[..4], [1, 0, 0, 0]);
        assert_eq!(b[4..8], [1, 2, 3, 4]); // little-endian sender
        assert_eq!(b[8..40], [0x11; 32]);
        assert_eq!(b[40..88], [0x22; 48]);
        assert_eq!(b[88..116], [0x33; 28]);
        assert_eq!(b[116..132], [0x44; 16]);
        assert_eq!(b[132..148], [0x55; 16]);
        assert_eq!(b[Initiation::MAC1_INPUT], b[..116]);
        assert_eq!(b[Initiation::MAC2_INPUT], b[..132]);
    }

    #[test]
    fn response_layout() {
        let b = resp().to_bytes().unwrap();
        assert_eq!(b.len(), 92);
        assert_eq!(b[..4], [2, 0, 0, 0]);
        assert_eq!(b[4..8], [0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(b[8..12], [1, 2, 3, 4]);
        assert_eq!(b[12..44], [0x66; 32]);
        assert_eq!(b[44..60], [0x77; 16]);
        assert_eq!(b[60..76], [0x88; 16]);
        assert_eq!(b[76..92], [0; 16]);
        assert_eq!(b[Response::MAC1_INPUT], b[..60]);
        assert_eq!(b[Response::MAC2_INPUT], b[..76]);
    }

    #[test]
    fn cookie_reply_layout() {
        let b = cookie().to_bytes().unwrap();
        assert_eq!(b.len(), 64);
        assert_eq!(b[..8], [3, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(b[8..32], [0x99; 24]);
        assert_eq!(b[32..64], [0xaa; 32]);
    }

    #[test]
    fn data_layout() {
        let b = data().to_bytes().unwrap();
        assert_eq!(b.len(), 16 + 48);
        assert_eq!(b[..8], [4, 0, 0, 0, 0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(b[8..16], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(b[16..], [0xbb; 48]);
        assert!(!data().is_keepalive());
        let k = Data {
            receiver: 1,
            counter: 0,
            encrypted: vec![0; 16],
        };
        assert!(k.is_keepalive());
        assert_eq!(k.to_bytes().unwrap().len(), 32);
    }

    #[test]
    fn round_trips() {
        for m in all() {
            let b = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&b), Ok(m.clone()));
            assert_eq!(Message::parse(&b).unwrap().to_bytes(), Ok(b));
        }
        assert_eq!(Initiation::parse(&init().to_bytes().unwrap()), Ok(init()));
        assert_eq!(Response::parse(&resp().to_bytes().unwrap()), Ok(resp()));
        assert_eq!(
            CookieReply::parse(&cookie().to_bytes().unwrap()),
            Ok(cookie())
        );
        assert_eq!(Data::parse(&data().to_bytes().unwrap()), Ok(data()));
    }

    #[test]
    fn kinds_and_receivers() {
        let kinds: Vec<u8> = all().iter().map(Message::kind).collect();
        assert_eq!(kinds, [1, 2, 3, 4]);
        let receivers: Vec<Option<u32>> = all().iter().map(Message::receiver).collect();
        assert_eq!(
            receivers,
            [None, Some(0x0403_0201), Some(5), Some(0xdead_beef)]
        );
    }

    #[test]
    fn every_truncated_prefix_is_an_error() {
        for m in all() {
            let b = m.to_bytes().unwrap();
            for n in 0..b.len() {
                let e = Message::parse(&b[..n]);
                if n < 4 {
                    assert_eq!(e, Err(Error::Short(n)));
                } else if m.kind() == message_type::DATA && n >= MIN_DATA_LEN {
                    // A shorter data message is still a data message.
                    assert!(e.is_ok());
                } else {
                    assert_eq!(
                        e,
                        Err(Error::Length {
                            kind: m.kind(),
                            len: n
                        }),
                        "{n} bytes of type {}",
                        m.kind()
                    );
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
        let mut b = init().to_bytes().unwrap();
        b[2] = 1;
        assert_eq!(Message::parse(&b), Err(Error::Reserved([0, 1, 0])));
        // One byte too many.
        let mut b = init().to_bytes().unwrap();
        b.push(0);
        assert_eq!(Message::parse(&b), Err(Error::Length { kind: 1, len: 149 }));
        let mut b = cookie().to_bytes().unwrap();
        b.push(0);
        assert_eq!(Message::parse(&b), Err(Error::Length { kind: 3, len: 65 }));
        // A data message too long for UDP.
        let mut b = vec![4, 0, 0, 0];
        b.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(
            Message::parse(&b),
            Err(Error::Length {
                kind: 4,
                len: MAX_MESSAGE + 1
            })
        );
        b.pop();
        assert!(Message::parse(&b).is_ok());
        // The per-type readers check the type. A known type that is not the
        // one a reader wants is its own error, not an unknown type.
        assert_eq!(
            Initiation::parse(&resp().to_bytes().unwrap()),
            Err(Error::Unexpected { want: 1, found: 2 })
        );
        assert_eq!(
            Response::parse(&init().to_bytes().unwrap()),
            Err(Error::Unexpected { want: 2, found: 1 })
        );
        assert_eq!(
            CookieReply::parse(&data().to_bytes().unwrap()),
            Err(Error::Unexpected { want: 3, found: 4 })
        );
        assert_eq!(
            Data::parse(&cookie().to_bytes().unwrap()),
            Err(Error::Unexpected { want: 4, found: 3 })
        );
        assert_eq!(Data::parse(&[9, 0, 0, 0]), Err(Error::Type(9)));
        assert!(
            !Error::Unexpected { want: 1, found: 2 }
                .to_string()
                .contains("not 1 to 4")
        );
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
                let mut b = m.to_bytes().unwrap();
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
        let b = init().to_bytes().unwrap();
        for n in 0..b.len() {
            let want = if n < 4 {
                Error::Short(n)
            } else {
                Error::Length { kind: 1, len: n }
            };
            assert_eq!(Initiation::parse(&b[..n]), Err(want));
        }
        let b = resp().to_bytes().unwrap();
        for n in 0..b.len() {
            let want = if n < 4 {
                Error::Short(n)
            } else {
                Error::Length { kind: 2, len: n }
            };
            assert_eq!(Response::parse(&b[..n]), Err(want));
        }
        let b = cookie().to_bytes().unwrap();
        for n in 0..b.len() {
            let want = if n < 4 {
                Error::Short(n)
            } else {
                Error::Length { kind: 3, len: n }
            };
            assert_eq!(CookieReply::parse(&b[..n]), Err(want));
        }
        let b = data().to_bytes().unwrap();
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
        // The writer takes exactly the encrypted lengths the reader takes,
        // writes them unchanged, and refuses the rest with Unwritable.
        let mut s = Lcg::new(0xda7a);
        let edges = [
            0,
            1,
            15,
            16,
            17,
            MAX_ENCRYPTED - 1,
            MAX_ENCRYPTED,
            MAX_ENCRYPTED + 1,
            MAX_MESSAGE,
        ];
        for i in 0..400 {
            let n = if i < edges.len() {
                edges[i]
            } else {
                s.index(2000)
            };
            let mut encrypted = vec![0; n];
            s.fill(&mut encrypted);
            let d = Data {
                receiver: s.next() as u32,
                counter: s.next() << 20,
                encrypted,
            };
            match d.to_bytes() {
                Ok(b) => {
                    assert!((TAG_LEN..=MAX_ENCRYPTED).contains(&n), "{n}");
                    assert_eq!(b.len(), DATA_HEADER_LEN + n);
                    assert_eq!(Data::parse(&b), Ok(d.clone()));
                    assert_eq!(Message::parse(&b), Ok(Message::Data(d.clone())));
                }
                Err(e) => {
                    assert!(!(TAG_LEN..=MAX_ENCRYPTED).contains(&n), "{n}");
                    assert_eq!(e, Error::Unwritable);
                    assert_eq!(Message::Data(d.clone()).to_bytes(), Err(e));
                }
            }
        }
    }

    #[test]
    fn data_writer_never_changes_the_ciphertext() {
        // A short or long encrypted part is refused, not padded or cut.
        for n in [0, 1, 3, 15, MAX_ENCRYPTED + 1, MAX_MESSAGE * 2] {
            let d = Data {
                receiver: 1,
                counter: 2,
                encrypted: vec![7; n],
            };
            assert_eq!(d.to_bytes(), Err(Error::Unwritable), "{n}");
        }
        // An empty encrypted part is not a keepalive, and does not become one.
        let empty = Data {
            receiver: 0,
            counter: 0,
            encrypted: Vec::new(),
        };
        assert!(!empty.is_keepalive());
        assert!(empty.to_bytes().is_err());
        // The longest one is written whole, its last byte (the tag's) kept.
        let mut long = vec![7; MAX_ENCRYPTED];
        long[MAX_ENCRYPTED - 1] = 0xee;
        let d = Data {
            receiver: 1,
            counter: 2,
            encrypted: long,
        };
        let b = d.to_bytes().unwrap();
        assert_eq!(b.len(), MAX_MESSAGE);
        assert_eq!(Data::parse(&b), Ok(d));
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
        assert_eq!(
            Plaintext::padded(&[1, 2, 3], 0).map(|v| v.0),
            Ok(vec![1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(Plaintext::padded(&[], 1420).map(|v| v.0), Ok(Vec::new()));
        // Too long for one message: refused, not cut.
        assert_eq!(
            Plaintext::padded(&vec![1; MAX_MESSAGE], 0).map(|v| v.0),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn padding_keeps_every_plaintext_byte() {
        assert_eq!(MAX_PLAINTEXT, 65_495);
        // 65,480 bytes pad to 65,488, a 65,520-byte message: it fits, whole.
        let mut p = vec![0x5a; 65_480];
        p[65_479] = 0xee;
        let out = Plaintext::padded(&p, 0).map(|v| v.0).unwrap();
        assert_eq!(out.len(), 65_488);
        assert_eq!(out[..p.len()], p[..]);
        assert!(out[p.len()..].iter().all(|&x| x == 0));
        // The limits with no MTU: 65,488 is the longest padded length.
        assert_eq!(
            Plaintext::padded(&vec![1; 65_488], 0)
                .map(|v| v.0)
                .map(|v| v.len()),
            Ok(65_488)
        );
        assert_eq!(
            Plaintext::padded(&vec![1; 65_489], 0).map(|v| v.0),
            Err(Error::Unwritable)
        );
        // With an MTU the padding can stop short of 16, so a longer one fits.
        assert_eq!(
            Plaintext::padded(&vec![1; MAX_PLAINTEXT], MAX_PLAINTEXT)
                .map(|v| v.0)
                .map(|v| v.len()),
            Ok(MAX_PLAINTEXT)
        );
        assert!(
            Plaintext::padded(&vec![1; MAX_PLAINTEXT + 1], MAX_PLAINTEXT + 1)
                .map(|v| v.0)
                .is_err()
        );
        // Any length and MTU: either every byte and zeros after, or refused
        // because the padded length passes the limit. Whatever it gives can
        // be sent once encrypted.
        let mut s = Lcg::new(0x9ad);
        for i in 0..3_000 {
            let len = if i % 2 == 0 {
                65_400 + s.index(200)
            } else {
                s.index(3000)
            };
            let mtu = match s.index(3) {
                0 => 0,
                1 => 1 + s.index(70_000),
                _ => 1280 + s.index(200),
            };
            let p: Vec<u8> = (0..len).map(|_| s.next() as u8 | 1).collect();
            let n = padding(len, mtu);
            match Plaintext::padded(&p, mtu).map(|v| v.0) {
                Ok(out) => {
                    assert_eq!(out.len(), len + n);
                    assert_eq!(out[..len], p[..]);
                    assert!(out[len..].iter().all(|&x| x == 0));
                    let d = Data {
                        receiver: 1,
                        counter: 0,
                        encrypted: vec![0; out.len() + TAG_LEN],
                    };
                    assert!(d.to_bytes().is_ok(), "{len} {mtu}");
                }
                Err(e) => {
                    assert!(len + n > MAX_PLAINTEXT, "{len} {mtu}");
                    assert_eq!(e, Error::Unwritable);
                }
            }
        }
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
        let mut s = Lcg::new(7);
        for _ in 0..rounds(20_000) {
            let base = highest.unwrap_or(0);
            let c = match s.index(4) {
                0 => base.saturating_sub(s.below(WINDOW_BITS + 10)),
                1 => base + s.below(70),
                2 => base + s.below(3 * WINDOW_BITS),
                _ => base.saturating_sub(s.below(16)),
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

    #[test]
    fn fuzz_loop() {
        let mut s = Lcg::new(0x5eed);
        let sizes = [
            0, 3, 4, 31, 32, 63, 64, 65, 91, 92, 93, 147, 148, 149, 200, 1500,
        ];
        for i in 0..rounds(20_000) {
            let len = if i % 2 == 0 {
                sizes[s.index(sizes.len())]
            } else {
                s.index(300)
            };
            let mut b = vec![0; len];
            s.fill(&mut b);
            if !b.is_empty() && s.index(4) != 0 {
                b[0] = s.index(5) as u8;
                for x in b.iter_mut().skip(1).take(3) {
                    if s.index(8) != 0 {
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
            let mut bytes = |n: usize| -> Vec<u8> {
                let mut out = vec![0; n];
                s.fill(&mut out);
                out
            };
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
            let b = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&b), Ok(m));
        }
    }

    /// Any bytes: no panic, and what parses writes back the same.
    fn check(b: &[u8]) {
        contract::check_wire::<Message>(b);
        contract::check_wire::<Initiation>(b);
        contract::check_wire::<Response>(b);
        contract::check_wire::<CookieReply>(b);
        contract::check_wire::<Data>(b);
        contract::check_wire::<Plaintext>(b);

        if let Ok(m) = Message::parse(b) {
            assert_eq!(m.to_bytes().as_deref(), Ok(b));
        }
        let _ = Initiation::parse(b);
        let _ = Response::parse(b);
        let _ = CookieReply::parse(b);
        let _ = Data::parse(b);
    }
}
