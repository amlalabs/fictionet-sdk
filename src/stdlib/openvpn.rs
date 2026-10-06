//! OpenVPN: reading and writing packets, over UDP and TCP, with no I/O.
//!
//! OpenVPN builds a VPN tunnel from two channels. The control channel
//! carries a TLS session in small, numbered, acknowledged packets, and
//! sets up the keys. The data channel carries the tunnel's IP packets,
//! encrypted with those keys. Both travel over UDP or TCP, usually on port
//! 1194. Over TCP each packet has a 2-byte length in front of it. This
//! module follows the packet layout in `doc/protocol` and `ssl_pkt.h` of
//! the OpenVPN source, and the tls-crypt notes in `doc/tls-crypt-v2.txt`.
//!
//! Every packet starts with one byte: the opcode in its top 5 bits and the
//! key ID in its low 3. A control packet then has the sender's session ID,
//! an array of packet IDs it acknowledges (with the peer's session ID if
//! the array is not empty), its own message packet ID, and a piece of the
//! TLS stream. A data packet has a peer ID (in version 2 only) and then its
//! payload, which this module keeps as bytes.
//!
//! There is no cryptography here. A server set up with tls-auth puts an
//! HMAC, a packet ID and a time after the session ID; one set up with
//! tls-crypt puts a packet ID, a time and a tag there, and encrypts the
//! rest. Nothing in the bytes says which is in use, so the caller says
//! with a [`Wrapping`] for [`Packet::parse_with`]. Writers use [`Packet`]
//! for plain control, [`Authenticated`] for tls-auth, and [`Encrypted`]
//! for tls-crypt. The module reads the wrapping's fields as they are. It
//! neither checks the HMAC nor decrypts.
//!
//! Nothing here reads a socket. A world that plays an OpenVPN server pushes
//! TCP bytes through [`Stream<Frames>`](super::codec::Stream), or takes each
//! UDP datagram whole, reads it with [`Packet::parse_with`], and writes
//! the reply's bytes back. What the TLS session says, and what the tunnel
//! carries, is up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A tls-crypt packet must have room in its ciphertext for the
//! fields encrypted there, and a tls-crypt-v2 packet must end with a
//! wrapped client key whose length field fits. The readers check layout
//! only. OpenVPN also drops a packet whose session ID is all zeros, and a
//! hard reset from a new client whose key ID is not 0. Those depend on the
//! session, so they are left to world code.
//!
//! A writer returns an [`EncodeError`] for a value its reader would not
//! give back as it is: a key ID or peer ID too large for its bits, too
//! many acknowledgements, a packet over [`MAX_PACKET`], and so on. What a
//! writer writes, the reader reads back as the same value.
//!
//! ```
//! use fictionet::stdlib::openvpn::{Ack, Control, ControlBody, ControlKind, Frames, Frame, Packet, Wrapping};
//!
//! use fictionet::stdlib::codec::{Stream, Wire};
//! let mut stream = Stream::new(Frames::new());
//! // A client's P_CONTROL_HARD_RESET_CLIENT_V2 over TCP: length 14,
//! // opcode 7 and key 0, session ID 1..8, no acks, message packet ID 0.
//! assert_eq!(stream.push(&[0, 14, 0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0]), 16);
//! let bytes = stream.next().unwrap().unwrap().0;
//! let packet = Packet::parse_with(&bytes, Wrapping::None).unwrap();
//! let Packet::Control { kind: ControlKind::HardResetClientV2, key_id: 0, body: ControlBody::Plain(hello) } = packet
//! else {
//!     panic!("not a client hard reset");
//! };
//! assert_eq!(hello.session_id, [1, 2, 3, 4, 5, 6, 7, 8]);
//!
//! // The server answers with its own session ID and acknowledges message 0.
//! let reply = Packet::Control {
//!     kind: ControlKind::HardResetServerV2,
//!     key_id: 0,
//!     body: ControlBody::Plain(Control {
//!         session_id: [9; 8],
//!         tls_auth: None,
//!         ack: Some(Ack { ids: vec![hello.message_id], remote_session_id: hello.session_id }),
//!         message_id: 0,
//!         payload: Vec::new(),
//!     }),
//! };
//! let wire = Frame::from_packet(&reply).unwrap().to_bytes().unwrap();
//! assert_eq!(wire[..3], [0, 26, 0x40]);
//! assert_eq!(Packet::parse_with(&wire[2..], Wrapping::None), Ok(reply));
//! ```

use super::codec::{Decode, Step, Wire};

/// The port OpenVPN servers listen on, over UDP and over TCP.
pub const PORT: u16 = 1194;
/// The longest packet, without the TCP length prefix. It is the most the
/// 2-byte prefix can say.
pub const MAX_PACKET: usize = 65535;
/// The length of the TCP length prefix.
pub const LENGTH_PREFIX_LEN: usize = 2;
/// The longest packet with its TCP length prefix.
pub const MAX_TCP_FRAME: usize = LENGTH_PREFIX_LEN + MAX_PACKET;
/// The length of a session ID.
pub const SESSION_ID_LEN: usize = 8;
/// The most packet IDs one control packet may acknowledge
/// (`RELIABLE_ACK_SIZE` in the OpenVPN source).
pub const MAX_ACKS: usize = 8;
/// The longest tls-auth HMAC a [`Wrapping`] may name: an HMAC-SHA512.
pub const MAX_HMAC_LEN: usize = 64;
/// The length of the tls-crypt tag, an HMAC-SHA256.
pub const TLS_CRYPT_TAG_LEN: usize = 32;
/// The shortest tls-crypt-v2 wrapped client key: its 32-byte tag, the
/// 256-byte client key and its 2-byte length (`tls_crypt.h`).
pub const MIN_WRAPPED_KEY_LEN: usize = TLS_CRYPT_TAG_LEN + 256 + 2;
/// The longest tls-crypt-v2 wrapped client key
/// (`TLS_CRYPT_V2_MAX_WKC_LEN` in the OpenVPN source).
pub const MAX_WRAPPED_KEY_LEN: usize = 1024;
/// The highest key ID: it has 3 bits.
pub const MAX_KEY_ID: u8 = 7;
/// The highest peer ID: it has 24 bits.
pub const MAX_PEER_ID: u32 = 0x00ff_ffff;
/// The peer ID a client sends before the server has given it one.
pub const NO_PEER_ID: u32 = MAX_PEER_ID;

/// Opcodes, the top 5 bits of a packet's first byte.
pub mod opcode {
    /// Client hard reset using key method 1.
    pub const P_CONTROL_HARD_RESET_CLIENT_V1: u8 = 1;
    /// Server hard reset using key method 1.
    pub const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
    /// Renegotiate keys within a session.
    pub const P_CONTROL_SOFT_RESET_V1: u8 = 3;
    /// A numbered control-channel payload.
    pub const P_CONTROL_V1: u8 = 4;
    /// Acknowledgements without a message ID.
    pub const P_ACK_V1: u8 = 5;
    /// Encrypted data without a peer ID.
    pub const P_DATA_V1: u8 = 6;
    /// Client hard reset using key method 2.
    pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
    /// Server hard reset using key method 2.
    pub const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
    /// Encrypted data with a 24-bit peer ID.
    pub const P_DATA_V2: u8 = 9;
    /// Client hard reset with a tls-crypt-v2 wrapped key.
    pub const P_CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;
    /// Control payload carrying a tls-crypt-v2 wrapped key.
    pub const P_CONTROL_WKC_V1: u8 = 11;
}

/// A session ID: 8 bytes each side picks at random when a session starts.
pub type SessionId = [u8; SESSION_ID_LEN];

/// The kinds of control channel packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ControlKind {
    /// A client starts a session with key method 1. OpenVPN 2.5 and later
    /// no longer support key method 1 and drop this opcode.
    HardResetClientV1,
    /// A server answers a version 1 hard reset. OpenVPN 2.5 and later drop
    /// this opcode too.
    HardResetServerV1,
    /// Either side starts a new key, keeping the session.
    SoftResetV1,
    /// A piece of the TLS stream.
    ControlV1,
    /// Only acknowledgements: no message packet ID. OpenVPN ignores any
    /// bytes after the acknowledgements.
    AckV1,
    /// A client starts a session.
    HardResetClientV2,
    /// A server answers a version 2 hard reset.
    HardResetServerV2,
    /// A client starts a session with tls-crypt-v2. Its wrapped client key
    /// follows the tls-crypt ciphertext.
    HardResetClientV3,
    /// A control packet that also carries the tls-crypt-v2 wrapped client
    /// key.
    ControlWkcV1,
}

impl ControlKind {
    /// Every kind, in opcode order.
    pub const ALL: [ControlKind; 9] = [
        ControlKind::HardResetClientV1,
        ControlKind::HardResetServerV1,
        ControlKind::SoftResetV1,
        ControlKind::ControlV1,
        ControlKind::AckV1,
        ControlKind::HardResetClientV2,
        ControlKind::HardResetServerV2,
        ControlKind::HardResetClientV3,
        ControlKind::ControlWkcV1,
    ];

    /// The kind's opcode.
    pub fn opcode(self) -> u8 {
        match self {
            ControlKind::HardResetClientV1 => opcode::P_CONTROL_HARD_RESET_CLIENT_V1,
            ControlKind::HardResetServerV1 => opcode::P_CONTROL_HARD_RESET_SERVER_V1,
            ControlKind::SoftResetV1 => opcode::P_CONTROL_SOFT_RESET_V1,
            ControlKind::ControlV1 => opcode::P_CONTROL_V1,
            ControlKind::AckV1 => opcode::P_ACK_V1,
            ControlKind::HardResetClientV2 => opcode::P_CONTROL_HARD_RESET_CLIENT_V2,
            ControlKind::HardResetServerV2 => opcode::P_CONTROL_HARD_RESET_SERVER_V2,
            ControlKind::HardResetClientV3 => opcode::P_CONTROL_HARD_RESET_CLIENT_V3,
            ControlKind::ControlWkcV1 => opcode::P_CONTROL_WKC_V1,
        }
    }

    /// The kind an opcode names, or `None` if it names a data packet or
    /// none at all.
    pub fn from_opcode(op: u8) -> Option<ControlKind> {
        ControlKind::ALL.into_iter().find(|k| k.opcode() == op)
    }

    /// Whether packets of this kind end with a tls-crypt-v2 wrapped client
    /// key: [`ControlKind::HardResetClientV3`] and
    /// [`ControlKind::ControlWkcV1`]. They are only sent with tls-crypt-v2,
    /// so they are read only with [`Wrapping::TlsCrypt`].
    pub fn carries_wrapped_key(self) -> bool {
        matches!(self, ControlKind::HardResetClientV3 | ControlKind::ControlWkcV1)
    }

    /// The fewest bytes the encrypted part of a tls-crypt packet of this
    /// kind can have. Encryption keeps the length, and the plaintext holds
    /// at least the acknowledgement count, plus the message packet ID for
    /// every kind but [`ControlKind::AckV1`].
    pub fn min_tls_crypt_body(self) -> usize {
        if self == ControlKind::AckV1 { 1 } else { 5 }
    }
}

/// How control packets are wrapped. Nothing in a packet says, so the
/// caller passes what the server is set up with. Data packets ignore it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Wrapping {
    /// No wrapping: the reliability fields follow the session ID.
    None,
    /// tls-auth: an HMAC of `hmac_len` bytes, a packet ID and a time
    /// follow the session ID. `hmac_len` is 20 for SHA1, the default.
    TlsAuth {
        /// The HMAC's length in bytes, at most [`MAX_HMAC_LEN`].
        hmac_len: usize,
    },
    /// tls-crypt or tls-crypt-v2: a packet ID, a time and a 32-byte tag
    /// follow the session ID, and the rest is encrypted.
    TlsCrypt,
}

/// The tls-auth fields of a control packet, as read. The HMAC is not
/// checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsAuth {
    /// The HMAC over the rest of the packet, at most [`MAX_HMAC_LEN`]
    /// bytes.
    pub hmac: Vec<u8>,
    /// The replay protection packet ID.
    pub packet_id: u32,
    /// The replay protection time, in seconds since 1970.
    pub net_time: u32,
}

/// The acknowledgements in a control packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    /// The message packet IDs acknowledged: 1 to [`MAX_ACKS`] of them. A
    /// packet with no acknowledgements has no `Ack`.
    pub ids: Vec<u32>,
    /// The session ID of the peer whose packets are acknowledged.
    pub remote_session_id: SessionId,
}

/// A control packet without tls-crypt: its fields can all be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    /// The sender's session ID.
    pub session_id: SessionId,
    /// The tls-auth fields, read when the [`Wrapping`] was
    /// [`Wrapping::TlsAuth`]. A writer writes them when they are here.
    pub tls_auth: Option<TlsAuth>,
    /// The acknowledgements, if any.
    pub ack: Option<Ack>,
    /// The packet's own message packet ID. A [`ControlKind::AckV1`]
    /// packet has none: a reader returns 0, and a writer refuses any
    /// other value.
    pub message_id: u32,
    /// A piece of the TLS stream. In a [`ControlKind::AckV1`] packet it is
    /// whatever bytes follow the acknowledgements, which OpenVPN sends
    /// none of and ignores. They are kept so the packet writes back the
    /// same.
    pub payload: Vec<u8>,
}

/// A control packet wrapped with tls-crypt. Only the header can be read.
/// The acknowledgements, message packet ID and payload are in the
/// ciphertext, which is not decrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCrypt {
    /// The sender's session ID.
    pub session_id: SessionId,
    /// The replay protection packet ID.
    pub packet_id: u32,
    /// The replay protection time, in seconds since 1970.
    pub net_time: u32,
    /// The authentication tag over the header and the plaintext.
    pub tag: [u8; TLS_CRYPT_TAG_LEN],
    /// Everything after the tag. For [`ControlKind::HardResetClientV3`]
    /// and [`ControlKind::ControlWkcV1`] it ends with the wrapped client
    /// key, which [`TlsCrypt::split_wrapped_key`] finds. The encrypted part
    /// has at least [`ControlKind::min_tls_crypt_body`] bytes.
    pub ciphertext: Vec<u8>,
}

impl TlsCrypt {
    /// For a [`ControlKind::HardResetClientV3`] or
    /// [`ControlKind::ControlWkcV1`] packet, splits the ciphertext into
    /// the encrypted control packet and the wrapped client key. The key
    /// ends with its own length in 2 bytes, which counts the whole key,
    /// [`MIN_WRAPPED_KEY_LEN`] to [`MAX_WRAPPED_KEY_LEN`]. It returns
    /// `None` if the ciphertext does not end with such a key.
    pub fn split_wrapped_key(&self) -> Option<(&[u8], &[u8])> {
        let len = wrapped_key_len(&self.ciphertext).ok()?;
        Some(self.ciphertext.split_at(self.ciphertext.len() - len))
    }
}

/// The length the last 2 bytes of `ct` give its wrapped client key, if it
/// is in range and fits in `ct`.
fn wrapped_key_len(ct: &[u8]) -> Result<usize, Error> {
    let [.., hi, lo] = *ct else {
        return Err(Error::Truncated);
    };
    let field = u16::from_be_bytes([hi, lo]);
    let len = usize::from(field);
    if !(MIN_WRAPPED_KEY_LEN..=MAX_WRAPPED_KEY_LEN).contains(&len) {
        return Err(Error::WrappedKeyLen(field));
    }
    if len > ct.len() {
        return Err(Error::Truncated);
    }
    Ok(len)
}

/// Checks that a tls-crypt ciphertext has room for what a packet of
/// `kind` encrypts, and the wrapped client key if the kind has one.
fn check_tls_crypt(kind: ControlKind, ct: &[u8]) -> Result<(), Error> {
    let body = if kind.carries_wrapped_key() { ct.len() - wrapped_key_len(ct)? } else { ct.len() };
    if body < kind.min_tls_crypt_body() {
        return Err(Error::Truncated);
    }
    Ok(())
}

/// The body of a control packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlBody {
    /// Read with [`Wrapping::None`] or [`Wrapping::TlsAuth`].
    Plain(Control),
    /// Read with [`Wrapping::TlsCrypt`].
    TlsCrypt(TlsCrypt),
}

impl ControlBody {
    /// The sender's session ID.
    pub fn session_id(&self) -> SessionId {
        match self {
            ControlBody::Plain(c) => c.session_id,
            ControlBody::TlsCrypt(c) => c.session_id,
        }
    }
}

/// One OpenVPN packet. The wire implementation uses unwrapped control fields.
/// Use [`Authenticated`] or [`Encrypted`] for protected control packets,
/// or [`Packet::parse_with`] to read with a runtime wrapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// A control channel packet.
    Control {
        /// Which control packet it is.
        kind: ControlKind,
        /// The key ID, 0 to [`MAX_KEY_ID`]. A writer refuses a larger value.
        key_id: u8,
        /// The packet's fields.
        body: ControlBody,
    },
    /// A P_DATA_V1 packet.
    DataV1 {
        /// The key ID, 0 to [`MAX_KEY_ID`]. A writer refuses a larger value.
        key_id: u8,
        /// The encrypted tunnel packet, as bytes.
        payload: Vec<u8>,
    },
    /// A P_DATA_V2 packet.
    DataV2 {
        /// The key ID, 0 to [`MAX_KEY_ID`]. A writer refuses a larger value.
        key_id: u8,
        /// The peer ID the server gave this client, 0 to [`MAX_PEER_ID`],
        /// or [`NO_PEER_ID`]. A writer refuses a larger value.
        peer_id: u32,
        /// The encrypted tunnel packet, as bytes.
        payload: Vec<u8>,
    },
}

/// Why bytes are not an OpenVPN packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// There were no bytes.
    Empty,
    /// The packet was longer than [`MAX_PACKET`].
    TooLong(usize),
    /// The opcode is not one OpenVPN defines.
    Opcode(u8),
    /// The packet ended before a field it must have.
    Truncated,
    /// The acknowledgement count was above [`MAX_ACKS`].
    TooManyAcks(u8),
    /// The [`Wrapping`] named an HMAC longer than [`MAX_HMAC_LEN`].
    HmacLen(usize),
    /// A tls-crypt-v2 packet was read with a [`Wrapping`] other than
    /// [`Wrapping::TlsCrypt`].
    NeedsTlsCrypt(ControlKind),
    /// A tls-crypt-v2 wrapped client key gave a length outside
    /// [`MIN_WRAPPED_KEY_LEN`] to [`MAX_WRAPPED_KEY_LEN`].
    WrappedKeyLen(u16),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Empty => write!(f, "empty packet"),
            Error::TooLong(n) => write!(f, "packet of {n} bytes, over {MAX_PACKET}"),
            Error::Opcode(op) => write!(f, "unknown opcode {op}"),
            Error::Truncated => write!(f, "packet ends inside a field"),
            Error::TooManyAcks(n) => write!(f, "{n} acknowledgements, over {MAX_ACKS}"),
            Error::HmacLen(n) => write!(f, "tls-auth HMAC of {n} bytes, over {MAX_HMAC_LEN}"),
            Error::NeedsTlsCrypt(kind) => write!(f, "{kind:?} needs tls-crypt-v2"),
            Error::WrappedKeyLen(n) => {
                write!(f, "wrapped client key of {n} bytes, outside {MIN_WRAPPED_KEY_LEN} to {MAX_WRAPPED_KEY_LEN}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Why a value cannot be written as it stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EncodeError {
    /// A field, wrapping, or packet length cannot be represented without change.
    Unwritable,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("value cannot be written without changing it")
    }
}

impl std::error::Error for EncodeError {}

/// Reads fields from the front of a slice.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.b.len() < n {
            return Err(Error::Truncated);
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn session_id(&mut self) -> Result<SessionId, Error> {
        let b = self.take(SESSION_ID_LEN)?;
        let mut id = [0; SESSION_ID_LEN];
        id.copy_from_slice(b);
        Ok(id)
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.b)
    }
}

/// The opcode and key ID packed in a packet's first byte.
pub fn split_first_byte(b: u8) -> (u8, u8) {
    (b >> 3, b & MAX_KEY_ID)
}

/// Packs a checked opcode and key ID.
fn first_byte(opcode: u8, key_id: u8) -> u8 {
    opcode << 3 | key_id
}

impl Packet {
    /// Reads one whole datagram or frame payload with explicit control wrapping.
    /// Refuses invalid fields, short input, and packets over [`MAX_PACKET`].
    pub fn parse_with(b: &[u8], wrapping: Wrapping) -> Result<Packet, Error> {
        if b.len() > MAX_PACKET {
            return Err(Error::TooLong(b.len()));
        }
        let mut r = Reader { b };
        let (op, key_id) = split_first_byte(r.u8().map_err(|_| Error::Empty)?);
        match op {
            opcode::P_DATA_V1 => return Ok(Packet::DataV1 { key_id, payload: r.rest().to_vec() }),
            opcode::P_DATA_V2 => {
                let p = r.take(3)?;
                let peer_id = u32::from_be_bytes([0, p[0], p[1], p[2]]);
                return Ok(Packet::DataV2 { key_id, peer_id, payload: r.rest().to_vec() });
            }
            _ => {}
        }
        let kind = ControlKind::from_opcode(op).ok_or(Error::Opcode(op))?;
        // A wrapping no packet can have is the caller's mistake, whatever
        // the bytes hold.
        if let Wrapping::TlsAuth { hmac_len } = wrapping
            && hmac_len > MAX_HMAC_LEN
        {
            return Err(Error::HmacLen(hmac_len));
        }
        if kind.carries_wrapped_key() && wrapping != Wrapping::TlsCrypt {
            return Err(Error::NeedsTlsCrypt(kind));
        }
        let session_id = r.session_id()?;
        let tls_auth = match wrapping {
            Wrapping::None => None,
            Wrapping::TlsAuth { hmac_len } => {
                let hmac = r.take(hmac_len)?.to_vec();
                Some(TlsAuth { hmac, packet_id: r.u32()?, net_time: r.u32()? })
            }
            Wrapping::TlsCrypt => {
                let packet_id = r.u32()?;
                let net_time = r.u32()?;
                let mut tag = [0; TLS_CRYPT_TAG_LEN];
                tag.copy_from_slice(r.take(TLS_CRYPT_TAG_LEN)?);
                let ciphertext = r.rest();
                check_tls_crypt(kind, ciphertext)?;
                let body = TlsCrypt { session_id, packet_id, net_time, tag, ciphertext: ciphertext.to_vec() };
                return Ok(Packet::Control { kind, key_id, body: ControlBody::TlsCrypt(body) });
            }
        };
        let count = r.u8()?;
        if usize::from(count) > MAX_ACKS {
            return Err(Error::TooManyAcks(count));
        }
        let ack = if count == 0 {
            None
        } else {
            let mut ids = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                ids.push(r.u32()?);
            }
            Some(Ack { ids, remote_session_id: r.session_id()? })
        };
        // OpenVPN reads no message ID from P_ACK_V1 and ignores the rest.
        let message_id = if kind == ControlKind::AckV1 { 0 } else { r.u32()? };
        let payload = r.rest().to_vec();
        let body = Control { session_id, tls_auth, ack, message_id, payload };
        Ok(Packet::Control { kind, key_id, body: ControlBody::Plain(body) })
    }

    /// The packet's opcode.
    pub fn opcode(&self) -> u8 {
        match self {
            Packet::Control { kind, .. } => kind.opcode(),
            Packet::DataV1 { .. } => opcode::P_DATA_V1,
            Packet::DataV2 { .. } => opcode::P_DATA_V2,
        }
    }

    /// The sender's session ID, for a control packet. Data packets carry
    /// none.
    pub fn session_id(&self) -> Option<SessionId> {
        match self {
            Packet::Control { body, .. } => Some(body.session_id()),
            Packet::DataV1 { .. } | Packet::DataV2 { .. } => None,
        }
    }

    /// The packet's key ID.
    pub fn key_id(&self) -> u8 {
        match self {
            Packet::Control { key_id, .. } | Packet::DataV1 { key_id, .. } | Packet::DataV2 { key_id, .. } => *key_id,
        }
    }

    /// The [`Wrapping`] that reads this packet's bytes back. Data packets
    /// give [`Wrapping::None`], since they ignore it.
    pub fn wrapping(&self) -> Wrapping {
        match self {
            Packet::Control { body: ControlBody::TlsCrypt(_), .. } => Wrapping::TlsCrypt,
            Packet::Control { body: ControlBody::Plain(Control { tls_auth: Some(a), .. }), .. } => {
                Wrapping::TlsAuth { hmac_len: a.hmac.len() }
            }
            _ => Wrapping::None,
        }
    }

    /// The packet's bytes, without a TCP length prefix. It returns an
    /// [`EncodeError`] for a packet [`Packet::parse_with`] would not read back
    /// as the same value.
    fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let key_id = self.key_id();
        if key_id > MAX_KEY_ID {
            return Err(EncodeError::Unwritable);
        }
        let mut out = vec![first_byte(self.opcode(), key_id)];
        let payload: &[u8] = match self {
            Packet::DataV1 { payload, .. } => payload,
            Packet::DataV2 { peer_id, payload, .. } => {
                if *peer_id > MAX_PEER_ID {
                    return Err(EncodeError::Unwritable);
                }
                out.extend_from_slice(&peer_id.to_be_bytes()[1..]);
                payload
            }
            Packet::Control { kind, body: ControlBody::TlsCrypt(c), .. } => {
                check_tls_crypt(*kind, &c.ciphertext).map_err(|_| EncodeError::Unwritable)?;
                out.extend_from_slice(&c.session_id);
                out.extend_from_slice(&c.packet_id.to_be_bytes());
                out.extend_from_slice(&c.net_time.to_be_bytes());
                out.extend_from_slice(&c.tag);
                &c.ciphertext
            }
            Packet::Control { kind, body: ControlBody::Plain(c), .. } => {
                if kind.carries_wrapped_key() {
                    return Err(EncodeError::Unwritable);
                }
                out.extend_from_slice(&c.session_id);
                if let Some(a) = &c.tls_auth {
                    if a.hmac.len() > MAX_HMAC_LEN {
                        return Err(EncodeError::Unwritable);
                    }
                    out.extend_from_slice(&a.hmac);
                    out.extend_from_slice(&a.packet_id.to_be_bytes());
                    out.extend_from_slice(&a.net_time.to_be_bytes());
                }
                match &c.ack {
                    Some(a) => {
                        if a.ids.is_empty() {
                            return Err(EncodeError::Unwritable);
                        }
                        let Ok(count) = u8::try_from(a.ids.len()) else {
                            return Err(EncodeError::Unwritable);
                        };
                        if usize::from(count) > MAX_ACKS {
                            return Err(EncodeError::Unwritable);
                        }
                        out.push(count);
                        for id in &a.ids {
                            out.extend_from_slice(&id.to_be_bytes());
                        }
                        out.extend_from_slice(&a.remote_session_id);
                    }
                    None => out.push(0),
                }
                if *kind == ControlKind::AckV1 {
                    if c.message_id != 0 {
                        return Err(EncodeError::Unwritable);
                    }
                } else {
                    out.extend_from_slice(&c.message_id.to_be_bytes());
                }
                &c.payload
            }
        };
        let len = out.len().saturating_add(payload.len());
        if len > MAX_PACKET {
            return Err(EncodeError::Unwritable);
        }
        out.extend_from_slice(payload);
        Ok(out)
    }
}

/// Finds the packet at the start of a TCP stream `b`. It returns
/// `Ok(None)` if `b` holds only part of one, and otherwise the packet's
/// bytes, without the prefix, and how many bytes of `b` it took.
fn split_tcp(b: &[u8]) -> Result<Option<(&[u8], usize)>, StreamError> {
    if b.len() < LENGTH_PREFIX_LEN {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if len == 0 {
        return Err(StreamError::ZeroLength);
    }
    let end = LENGTH_PREFIX_LEN + len;
    match b.get(LENGTH_PREFIX_LEN..end) {
        Some(packet) => Ok(Some((packet, end))),
        None => Ok(None),
    }
}

/// A TCP envelope containing one OpenVPN packet, without its length prefix.
///
/// [`Wire`] reads and writes the two-byte prefix and 1 to [`MAX_PACKET`]
/// payload bytes. The payload is opaque. Parse it with [`Packet::parse_with`]
/// and an explicit [`Wrapping`]; that context cannot be inferred from bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame(
    /// The packet bytes, excluding the TCP length prefix.
    pub Vec<u8>,
);

/// Why the bounded TCP framer refused an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The TCP length prefix is invalid.
    ZeroLength,
    /// The declared packet exceeds the configured payload limit.
    TooLong {
        /// The declared payload length.
        length: usize,
        /// The maximum accepted payload length.
        limit: usize,
    },
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroLength => f.write_str("OpenVPN TCP frame has zero length"),
            Self::TooLong { length, limit } => {
                write!(f, "OpenVPN packet of {length} bytes, over {limit}")
            }
        }
    }
}

impl core::error::Error for StreamError {}

/// Why an exact TCP envelope parse failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// The length prefix was refused.
    Frame(StreamError),
    /// The input ended before a complete envelope.
    Truncated,
    /// Bytes follow the first envelope.
    Trailing,
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete OpenVPN TCP envelope"),
            Self::Trailing => f.write_str("bytes follow the OpenVPN TCP envelope"),
        }
    }
}

impl core::error::Error for FrameParseError {}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = EncodeError;

    /// Reads one envelope. Refuses zero length, truncation, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, FrameParseError> {
        match Frames::new()
            .decode(bytes, true)
            .map_err(FrameParseError::Frame)?
        {
            Step::Item(frame, used) if used == bytes.len() => Ok(frame),
            Step::Item(_, _) => Err(FrameParseError::Trailing),
            _ => Err(FrameParseError::Truncated),
        }
    }

    /// Appends one envelope. Refuses empty payloads and lengths over [`MAX_PACKET`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let length = u16::try_from(self.0.len()).map_err(|_| EncodeError::Unwritable)?;
        if length == 0 {
            return Err(EncodeError::Unwritable);
        }
        out.try_reserve_exact(2 + self.0.len())
            .map_err(|_| EncodeError::Unwritable)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

/// A packet using tls-auth with a fixed HMAC length.
/// The HMAC is carried as bytes and is not verified.
/// Control packets require a matching HMAC length from 0 through [`MAX_HMAC_LEN`].
/// Select the wire type for the connection's configured length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticated<const HMAC_LEN: usize>(
    /// The packet whose control fields use this HMAC length.
    pub Packet,
);

/// A packet using tls-crypt. The ciphertext and tag are not verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encrypted(
    /// The packet whose control fields use tls-crypt.
    pub Packet,
);

fn write_packet(packet: &Packet, wrapping: Wrapping, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if matches!(packet, Packet::Control { .. }) && packet.wrapping() != wrapping {
        return Err(EncodeError::Unwritable);
    }
    let bytes = packet.encode()?;
    out.try_reserve_exact(bytes.len())
        .map_err(|_| EncodeError::Unwritable)?;
    out.extend_from_slice(&bytes);
    Ok(())
}

macro_rules! packet_wire {
    ($ty:ty, $wrapping:expr, $wrap:expr, |$packet:ident| $get:expr $(, $n:ident)?) => {
        impl $(<const $n: usize>)? Wire for $ty {
            type ParseError = Error;
            type WriteError = EncodeError;

            /// Reads one datagram with this type's wrapping. Refuses short input,
            /// invalid fields, and packets over [`MAX_PACKET`].
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                Packet::parse_with(bytes, $wrapping).map($wrap)
            }

            /// Appends one datagram. Refuses incompatible wrapping, invalid IDs,
            /// acknowledgements, ciphertext layout, or a length over [`MAX_PACKET`].
            fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
                let $packet = self;
                write_packet($get, $wrapping, out)
            }
        }
    };
}
packet_wire!(Packet, Wrapping::None, |p| p, |p| p);
packet_wire!(
    Authenticated<N>,
    Wrapping::TlsAuth { hmac_len: N },
    Self,
    |p| &p.0,
    N
);
packet_wire!(Encrypted, Wrapping::TlsCrypt, Self, |p| &p.0);

impl Frame {
    /// Places a packet in a TCP envelope. Refuses any value its writer refuses.
    pub fn from_packet<P: Wire<WriteError = EncodeError>>(packet: &P) -> Result<Self, EncodeError> {
        let bytes = packet.to_bytes()?;
        if bytes.is_empty() || bytes.len() > MAX_PACKET {
            return Err(EncodeError::Unwritable);
        }
        Ok(Self(bytes))
    }
}

/// Reads OpenVPN TCP envelopes without retaining input.
///
/// Capacity is the payload limit plus [`LENGTH_PREFIX_LEN`]. An oversized
/// packet is refused from its prefix. Partial envelopes return [`Step::Need`],
/// including at EOF, so [`super::codec::Stream`] reports truncation.
/// Map each frame through [`Packet::parse_with`] with the connection's wrapping
/// to receive packet errors as items while framing continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Creates a framer accepting payloads up to [`MAX_PACKET`] bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_PACKET)
    }

    /// Sets the payload limit, clamped to [`MAX_PACKET`]. Zero refuses
    /// every packet. The two-byte prefix is excluded from this limit.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_PACKET),
        }
    }

    /// The largest accepted packet, excluding its length prefix.
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
    type Item = Frame;
    type Error = StreamError;
    const NAME: &'static str = "OpenVPN/TCP";

    fn capacity(&self) -> usize {
        LENGTH_PREFIX_LEN.saturating_add(self.limit)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, StreamError> {
        if let Some(&[hi, lo]) = input.get(..LENGTH_PREFIX_LEN) {
            let length = usize::from(u16::from_be_bytes([hi, lo]));
            if length > self.limit {
                return Err(StreamError::TooLong {
                    length,
                    limit: self.limit,
                });
            }
        }
        Ok(match split_tcp(input)? {
            Some((packet, used)) => Step::Item(Frame(packet.to_vec()), used),
            None => Step::Need,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::codec::{
        contract, Stream, Fail,
        test_support::{decode_all, Lcg, mutate},
    };

    fn wire(packet: &Packet) -> Result<Vec<u8>, EncodeError> {
        match packet.wrapping() {
            Wrapping::None => packet.to_bytes(),
            Wrapping::TlsCrypt => Encrypted(packet.clone()).to_bytes(),
            Wrapping::TlsAuth { hmac_len } => {
                macro_rules! authenticated {
                    ($($n:literal),*) => {
                        match hmac_len {
                            $($n => Authenticated::<$n>(packet.clone()).to_bytes(),)*
                            _ => Err(EncodeError::Unwritable),
                        }
                    };
                }
                authenticated!(
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
                    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
                )
            },
        }
    }

    fn envelope(packet: &Packet) -> Result<Vec<u8>, EncodeError> {
        Frame(wire(packet)?).to_bytes()
    }

    const CLIENT_SID: SessionId = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    const SERVER_SID: SessionId = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];

    fn plain(kind: ControlKind, c: Control) -> Packet {
        Packet::Control { kind, key_id: 0, body: ControlBody::Plain(c) }
    }

    // Layouts from doc/protocol and ssl_pkt.h in the OpenVPN source.

    #[test]
    fn first_byte_packs_opcode_and_key_id() {
        assert_eq!(first_byte(opcode::P_CONTROL_HARD_RESET_CLIENT_V2, 0), 0x38);
        assert_eq!(first_byte(opcode::P_CONTROL_HARD_RESET_SERVER_V2, 0), 0x40);
        assert_eq!(first_byte(opcode::P_DATA_V2, 1), 0x49);
        assert_eq!(first_byte(opcode::P_CONTROL_V1, 7), 0x27);
        assert_eq!(split_first_byte(0x49), (9, 1));
        for b in 0..=255u8 {
            let (op, key) = split_first_byte(b);
            assert_eq!(first_byte(op, key), b);
        }
    }

    #[test]
    fn client_hard_reset_v2() {
        let mut bytes = vec![0x38];
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
        let p = Packet::parse_with(&bytes, Wrapping::None).unwrap();
        let want = plain(
            ControlKind::HardResetClientV2,
            Control { session_id: CLIENT_SID, tls_auth: None, ack: None, message_id: 0, payload: vec![] },
        );
        assert_eq!(p, want);
        assert_eq!(wire(&p).unwrap(), bytes);
        let mut tcp = vec![0, 14];
        tcp.extend_from_slice(&bytes);
        assert_eq!(envelope(&p).unwrap(), tcp);
    }

    #[test]
    fn server_hard_reset_v2_acks_the_client() {
        let mut bytes = vec![0x40];
        bytes.extend_from_slice(&SERVER_SID);
        bytes.extend_from_slice(&[1, 0, 0, 0, 0]);
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let p = Packet::parse_with(&bytes, Wrapping::None).unwrap();
        let ControlBody::Plain(c) = (match &p {
            Packet::Control { kind: ControlKind::HardResetServerV2, body, .. } => body.clone(),
            _ => panic!(),
        }) else {
            panic!()
        };
        assert_eq!(c.ack, Some(Ack { ids: vec![0], remote_session_id: CLIENT_SID }));
        assert_eq!(c.session_id, SERVER_SID);
        assert_eq!(wire(&p).unwrap(), bytes);
    }

    #[test]
    fn control_with_tls_payload_and_two_acks() {
        let c = Control {
            session_id: CLIENT_SID,
            tls_auth: None,
            ack: Some(Ack { ids: vec![1, 2], remote_session_id: SERVER_SID }),
            message_id: 3,
            payload: vec![0x16, 0x03, 0x01],
        };
        let p = Packet::Control { kind: ControlKind::ControlV1, key_id: 2, body: ControlBody::Plain(c) };
        let b = wire(&p).unwrap();
        assert_eq!(b[0], 0x22);
        assert_eq!(b.len(), 1 + 8 + 1 + 8 + 8 + 4 + 3);
        assert_eq!(&b[9..18], &[2, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(&b[b.len() - 7..], &[0, 0, 0, 3, 0x16, 0x03, 0x01]);
        assert_eq!(Packet::parse_with(&b, Wrapping::None), Ok(p));
    }

    #[test]
    fn ack_v1_has_no_message_id() {
        let mut bytes = vec![0x28];
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[1, 0, 0, 0, 5]);
        bytes.extend_from_slice(&SERVER_SID);
        let p = Packet::parse_with(&bytes, Wrapping::None).unwrap();
        assert_eq!(wire(&p).unwrap(), bytes);
        // The writer refuses a message ID set by mistake, which the reader
        // would not give back.
        let mut odd = p.clone();
        if let Packet::Control { body: ControlBody::Plain(c), .. } = &mut odd {
            c.message_id = 9;
        }
        assert_eq!(wire(&odd), Err(EncodeError::Unwritable));
        // OpenVPN ignores bytes after the acknowledgements (ssl.c reads no
        // message ID for P_ACK_V1 and stops), so they are kept as payload.
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let p = Packet::parse_with(&bytes, Wrapping::None).unwrap();
        let Packet::Control { body: ControlBody::Plain(c), .. } = &p else { panic!() };
        assert_eq!((c.message_id, &c.payload[..]), (0, &[0xaa, 0xbb][..]));
        assert_eq!(wire(&p).unwrap(), bytes);
    }

    #[test]
    fn data_packets() {
        let p = Packet::parse_with(&[0x30, 1, 2, 3], Wrapping::None).unwrap();
        assert_eq!(p, Packet::DataV1 { key_id: 0, payload: vec![1, 2, 3] });
        let p = Packet::parse_with(&[0x49, 0x00, 0x00, 0x05, 0xde, 0xad], Wrapping::TlsCrypt).unwrap();
        assert_eq!(p, Packet::DataV2 { key_id: 1, peer_id: 5, payload: vec![0xde, 0xad] });
        assert_eq!(wire(&p).unwrap(), [0x49, 0, 0, 5, 0xde, 0xad]);
        let p = Packet::DataV2 { key_id: 1, peer_id: NO_PEER_ID, payload: vec![] };
        assert_eq!(wire(&p).unwrap(), [0x49, 0xff, 0xff, 0xff]);
        assert_eq!(
            Packet::parse_with(&wire(&p).unwrap(), Wrapping::None),
            Ok(p)
        );
    }

    #[test]
    fn tls_auth_fields_are_read_not_checked() {
        let mut bytes = vec![0x38];
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[0xee; 20]);
        bytes.extend_from_slice(&[0, 0, 0, 1, 0x5f, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
        let p = Packet::parse_with(&bytes, Wrapping::TlsAuth { hmac_len: 20 }).unwrap();
        let Packet::Control { body: ControlBody::Plain(c), .. } = &p else { panic!() };
        assert_eq!(c.tls_auth, Some(TlsAuth { hmac: vec![0xee; 20], packet_id: 1, net_time: 0x5f00_0000 }));
        assert_eq!(p.wrapping(), Wrapping::TlsAuth { hmac_len: 20 });
        assert_eq!(wire(&p).unwrap(), bytes);
        assert_eq!(
            Packet::parse_with(&bytes, Wrapping::TlsAuth { hmac_len: 65 }),
            Err(Error::HmacLen(65))
        );
        // An HMAC length too long is refused before the bytes are read, so
        // even a packet cut short says so.
        assert_eq!(
            Packet::parse_with(&bytes[..3], Wrapping::TlsAuth { hmac_len: 65 }),
            Err(Error::HmacLen(65))
        );
        assert_eq!(
            Packet::parse_with(
                &bytes,
                Wrapping::TlsAuth {
                    hmac_len: usize::MAX
                }
            ),
            Err(Error::HmacLen(usize::MAX))
        );
        // Data packets ignore the wrapping, whatever it says.
        assert!(
            Packet::parse_with(
                &[0x30, 1],
                Wrapping::TlsAuth {
                    hmac_len: usize::MAX
                }
            )
            .is_ok()
        );
        assert_eq!(p.session_id(), Some(CLIENT_SID));
        assert_eq!(Packet::DataV1 { key_id: 0, payload: vec![] }.session_id(), None);
    }

    /// A wrapped client key of `len` bytes, ending with its length.
    fn wrapped_key(len: usize) -> Vec<u8> {
        let mut k = vec![0x5a; len - 2];
        k.extend_from_slice(&(len as u16).to_be_bytes());
        k
    }

    #[test]
    fn tls_crypt_header_is_read_and_the_rest_kept() {
        let mut ciphertext = vec![9, 8, 7, 6, 5];
        ciphertext.extend_from_slice(&wrapped_key(MIN_WRAPPED_KEY_LEN));
        let mut bytes = vec![0x50];
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
        bytes.extend_from_slice(&[0x77; 32]);
        bytes.extend_from_slice(&ciphertext);
        let p = Packet::parse_with(&bytes, Wrapping::TlsCrypt).unwrap();
        let want = TlsCrypt { session_id: CLIENT_SID, packet_id: 1, net_time: 2, tag: [0x77; 32], ciphertext };
        assert_eq!(want.split_wrapped_key(), Some((&[9, 8, 7, 6, 5][..], &want.ciphertext[5..])));
        assert_eq!(
            p,
            Packet::Control { kind: ControlKind::HardResetClientV3, key_id: 0, body: ControlBody::TlsCrypt(want) }
        );
        assert_eq!(p.wrapping(), Wrapping::TlsCrypt);
        assert_eq!(wire(&p).unwrap(), bytes);
    }

    /// The tls-crypt header of a packet of `first` byte, then `ct`.
    fn tls_crypt_bytes(first: u8, ct: &[u8]) -> Vec<u8> {
        let mut b = vec![first];
        b.extend_from_slice(&CLIENT_SID);
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&[0x77; 32]);
        b.extend_from_slice(ct);
        b
    }

    #[test]
    fn tls_crypt_v2_kinds_need_tls_crypt() {
        // A V3 hard reset or a WKC control packet is only sent with
        // tls-crypt-v2, so no other wrapping reads one.
        for (first, kind) in [(0x50, ControlKind::HardResetClientV3), (0x58, ControlKind::ControlWkcV1)] {
            let mut b = vec![first];
            b.extend_from_slice(&[1; 8]);
            b.extend_from_slice(&[0; 5]);
            assert_eq!(
                Packet::parse_with(&b, Wrapping::None),
                Err(Error::NeedsTlsCrypt(kind))
            );
            assert_eq!(
                Packet::parse_with(&b, Wrapping::TlsAuth { hmac_len: 0 }),
                Err(Error::NeedsTlsCrypt(kind))
            );
            let p = plain(
                kind,
                Control { session_id: CLIENT_SID, tls_auth: None, ack: None, message_id: 0, payload: vec![] },
            );
            assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        }
    }

    #[test]
    fn tls_crypt_v2_wrapped_key_is_checked() {
        // The old fixture: [9, 8, 7] names a 2055-byte key in 3 bytes.
        let b = tls_crypt_bytes(0x50, &[9, 8, 7]);
        assert_eq!(
            Packet::parse_with(&b, Wrapping::TlsCrypt),
            Err(Error::WrappedKeyLen(0x0807))
        );
        // No room for the length at all.
        assert_eq!(
            Packet::parse_with(&tls_crypt_bytes(0x58, &[9]), Wrapping::TlsCrypt),
            Err(Error::Truncated)
        );
        // A length in range but longer than the ciphertext.
        let mut ct = vec![1; 5];
        ct.extend_from_slice(&wrapped_key(MIN_WRAPPED_KEY_LEN));
        assert_eq!(
            Packet::parse_with(&tls_crypt_bytes(0x58, &ct[1..]), Wrapping::TlsCrypt),
            Err(Error::Truncated)
        );
        // Lengths at and past each end of the range.
        for (len, ok) in [
            (MIN_WRAPPED_KEY_LEN - 1, false),
            (MIN_WRAPPED_KEY_LEN, true),
            (MAX_WRAPPED_KEY_LEN, true),
            (MAX_WRAPPED_KEY_LEN + 1, false),
        ] {
            let mut ct = vec![1; 5];
            ct.extend_from_slice(&wrapped_key(len));
            let got = Packet::parse_with(&tls_crypt_bytes(0x58, &ct), Wrapping::TlsCrypt);
            if ok {
                assert!(got.is_ok(), "{len}");
            } else {
                assert_eq!(got, Err(Error::WrappedKeyLen(len as u16)));
            }
        }
        // The writer refuses what the reader refuses.
        let t = TlsCrypt { session_id: CLIENT_SID, packet_id: 0, net_time: 0, tag: [0; 32], ciphertext: vec![9, 8, 7] };
        assert_eq!(t.split_wrapped_key(), None);
        let p = Packet::Control { kind: ControlKind::HardResetClientV3, key_id: 0, body: ControlBody::TlsCrypt(t) };
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
    }

    #[test]
    fn tls_crypt_ciphertext_has_room_for_its_fields() {
        // A control packet encrypts at least an ack count and a message
        // packet ID, 5 bytes, and a P_ACK_V1 at least the count.
        for (first, kind) in [(0x20, ControlKind::ControlV1), (0x38, ControlKind::HardResetClientV2)] {
            assert_eq!(Packet::parse_with(&tls_crypt_bytes(first, &[]), Wrapping::TlsCrypt), Err(Error::Truncated));
            assert_eq!(Packet::parse_with(&tls_crypt_bytes(first, &[0; 4]), Wrapping::TlsCrypt), Err(Error::Truncated));
            assert!(Packet::parse_with(&tls_crypt_bytes(first, &[0; 5]), Wrapping::TlsCrypt).is_ok());
            let t = TlsCrypt { session_id: CLIENT_SID, packet_id: 0, net_time: 0, tag: [0; 32], ciphertext: vec![] };
            let p = Packet::Control { kind, key_id: 0, body: ControlBody::TlsCrypt(t) };
            assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        }
        assert_eq!(
            Packet::parse_with(&tls_crypt_bytes(0x28, &[]), Wrapping::TlsCrypt),
            Err(Error::Truncated)
        );
        assert!(Packet::parse_with(&tls_crypt_bytes(0x28, &[0]), Wrapping::TlsCrypt).is_ok());
        // With a wrapped key, the room is counted before the key.
        let mut ct = vec![0; 4];
        ct.extend_from_slice(&wrapped_key(MIN_WRAPPED_KEY_LEN));
        assert_eq!(
            Packet::parse_with(&tls_crypt_bytes(0x50, &ct), Wrapping::TlsCrypt),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn errors() {
        assert_eq!(Packet::parse_with(&[], Wrapping::None), Err(Error::Empty));
        assert_eq!(
            Packet::parse_with(&[0x00], Wrapping::None),
            Err(Error::Opcode(0))
        );
        assert_eq!(
            Packet::parse_with(&[12 << 3], Wrapping::None),
            Err(Error::Opcode(12))
        );
        assert_eq!(
            Packet::parse_with(&[0xff], Wrapping::None),
            Err(Error::Opcode(31))
        );
        assert_eq!(
            Packet::parse_with(&[0x38, 1, 2], Wrapping::None),
            Err(Error::Truncated)
        );
        assert_eq!(
            Packet::parse_with(&[0x48, 1, 2], Wrapping::None),
            Err(Error::Truncated)
        );
        let mut many = vec![0x20];
        many.extend_from_slice(&CLIENT_SID);
        many.push(9);
        assert_eq!(
            Packet::parse_with(&many, Wrapping::None),
            Err(Error::TooManyAcks(9))
        );
        let long = vec![0x30; MAX_PACKET + 1];
        assert_eq!(
            Packet::parse_with(&long, Wrapping::None),
            Err(Error::TooLong(MAX_PACKET + 1))
        );
        assert!(Packet::parse_with(&long[..MAX_PACKET], Wrapping::None).is_ok());
        for e in [
            Error::Empty,
            Error::TooLong(1),
            Error::Opcode(0),
            Error::Truncated,
            Error::TooManyAcks(9),
            Error::HmacLen(99),
            Error::NeedsTlsCrypt(ControlKind::ControlWkcV1),
            Error::WrappedKeyLen(3),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(!StreamError::ZeroLength.to_string().is_empty());
        assert_eq!(EncodeError::Unwritable.to_string(), "value cannot be written without changing it");
    }

    /// Every packet the tests build, with the wrapping that reads it.
    fn samples() -> Vec<Packet> {
        let ack = Some(Ack { ids: vec![4, 5, 6], remote_session_id: SERVER_SID });
        let tls_auth = Some(TlsAuth { hmac: vec![3; 20], packet_id: 7, net_time: 8 });
        let mut out = vec![
            Packet::DataV1 { key_id: 3, payload: vec![1, 2, 3] },
            Packet::DataV2 { key_id: 1, peer_id: 77, payload: vec![4, 5] },
        ];
        for kind in ControlKind::ALL {
            if kind.carries_wrapped_key() {
                // Only ever sent with tls-crypt-v2.
                let mut ciphertext = vec![6; 10];
                ciphertext.extend_from_slice(&wrapped_key(MIN_WRAPPED_KEY_LEN));
                let t = TlsCrypt { session_id: CLIENT_SID, packet_id: 1, net_time: 2, tag: [5; 32], ciphertext };
                out.push(Packet::Control { kind, key_id: 0, body: ControlBody::TlsCrypt(t) });
                continue;
            }
            for (tls_auth, ack) in [(None, None), (tls_auth.clone(), ack.clone()), (None, ack.clone())] {
                let payload = vec![0x16, 3, 3];
                let message_id = if kind == ControlKind::AckV1 { 0 } else { 42 };
                let c = Control { session_id: CLIENT_SID, tls_auth, ack, message_id, payload };
                out.push(Packet::Control { kind, key_id: 2, body: ControlBody::Plain(c) });
            }
            let mut ciphertext = vec![6; 10];
            if kind.carries_wrapped_key() {
                ciphertext.extend_from_slice(&wrapped_key(MIN_WRAPPED_KEY_LEN));
            }
            let t = TlsCrypt { session_id: CLIENT_SID, packet_id: 1, net_time: 2, tag: [5; 32], ciphertext };
            out.push(Packet::Control { kind, key_id: 0, body: ControlBody::TlsCrypt(t) });
        }
        out
    }

    #[test]
    fn round_trips() {
        for p in samples() {
            let b = wire(&p).unwrap();
            assert_eq!(Packet::parse_with(&b, p.wrapping()), Ok(p.clone()));
            let tcp = envelope(&p).unwrap();
            let (inner, used) = split_tcp(&tcp).unwrap().unwrap();
            assert_eq!(inner, &b[..]);
            assert_eq!(used, b.len() + 2);
        }
    }

    #[test]
    fn every_truncated_prefix() {
        for p in samples() {
            let b = wire(&p).unwrap();
            let w = p.wrapping();
            // Where the fixed fields end and the payload starts.
            let header = match &p {
                Packet::DataV1 { payload, .. } | Packet::DataV2 { payload, .. } => b.len() - payload.len(),
                Packet::Control { kind, body: ControlBody::TlsCrypt(t), .. } => {
                    if kind.carries_wrapped_key() {
                        // Cutting the end cuts the wrapped key's length, so
                        // no prefix reads.
                        b.len()
                    } else {
                        b.len() - t.ciphertext.len() + kind.min_tls_crypt_body()
                    }
                }
                Packet::Control { body: ControlBody::Plain(c), .. } => b.len() - c.payload.len(),
            };
            for n in 0..b.len() {
                let got = Packet::parse_with(&b[..n], w);
                if n == 0 {
                    assert_eq!(got, Err(Error::Empty));
                } else if n < header {
                    assert!(got.is_err(), "{p:?} cut to {n}");
                } else {
                    assert!(got.is_ok(), "{p:?} cut to {n}");
                }
            }
            let tcp = envelope(&p).unwrap();
            for n in 0..tcp.len() {
                assert_eq!(split_tcp(&tcp[..n]), Ok(None));
            }
        }
    }

    #[test]
    fn writers_refuse_what_the_reader_would_not_give_back() {
        // The longest packet is written whole, and one byte more is refused
        // rather than cut.
        let p = Packet::DataV1 { key_id: 0, payload: vec![7; MAX_PACKET - 1] };
        assert_eq!(Packet::parse_with(&wire(&p).unwrap(), Wrapping::None), Ok(p.clone()));
        assert_eq!(envelope(&p).unwrap().len(), MAX_TCP_FRAME);
        let p = Packet::DataV1 { key_id: 0, payload: vec![0; MAX_PACKET] };
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        assert_eq!(envelope(&p), Err(EncodeError::Unwritable));
        // A tls-crypt ciphertext is never cut, which would leave its tag
        // over bytes that are not there.
        let t =
            TlsCrypt { session_id: CLIENT_SID, packet_id: 0, net_time: 0, tag: [0; 32], ciphertext: vec![1; 65487] };
        let p = Packet::Control { kind: ControlKind::ControlV1, key_id: 0, body: ControlBody::TlsCrypt(t) };
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        // Key IDs and peer IDs too large for their bits.
        let p = Packet::DataV2 { key_id: 9, peer_id: 5, payload: vec![] };
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        let p = Packet::DataV2 { key_id: 1, peer_id: 0x0100_0005, payload: vec![] };
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        let control = |tls_auth, ack| Control { session_id: CLIENT_SID, tls_auth, ack, message_id: 1, payload: vec![] };
        let p =
            Packet::Control { kind: ControlKind::ControlV1, key_id: 8, body: ControlBody::Plain(control(None, None)) };
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        // An HMAC too long, too many acks, and an Ack with none.
        let p = plain(
            ControlKind::ControlV1,
            control(Some(TlsAuth { hmac: vec![1; MAX_HMAC_LEN + 1], packet_id: 0, net_time: 0 }), None),
        );
        assert_eq!(p.wrapping(), Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN + 1 });
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        let p = plain(
            ControlKind::ControlV1,
            control(Some(TlsAuth { hmac: vec![1; MAX_HMAC_LEN], packet_id: 0, net_time: 0 }), None),
        );
        assert_eq!(Packet::parse_with(&wire(&p).unwrap(), p.wrapping()), Ok(p));
        for (n, want) in [
            (MAX_ACKS, None),
            (MAX_ACKS + 1, Some(EncodeError::Unwritable)),
            (300, Some(EncodeError::Unwritable)),
        ] {
            let ack = Ack { ids: (0..n as u32).collect(), remote_session_id: SERVER_SID };
            let p = plain(ControlKind::ControlV1, control(None, Some(ack)));
            match want {
                None => assert_eq!(
                    Packet::parse_with(&wire(&p).unwrap(), Wrapping::None),
                    Ok(p)
                ),
                Some(e) => assert_eq!(wire(&p), Err(e)),
            }
        }
        let p = plain(ControlKind::ControlV1, control(None, Some(Ack { ids: vec![], remote_session_id: SERVER_SID })));
        assert_eq!(wire(&p), Err(EncodeError::Unwritable));
        assert_eq!(Frame(vec![]).to_bytes(), Err(EncodeError::Unwritable));
        assert_eq!(
            Frame(vec![0; MAX_PACKET + 1]).to_bytes(),
            Err(EncodeError::Unwritable)
        );
        assert_eq!(Frame(vec![0x30]).to_bytes(), Ok(vec![0, 1, 0x30]));
    }

    #[test]
    fn stream_splits_a_stream() {
        let a = envelope(&samples()[0]).unwrap();
        let b = envelope(&samples()[5]).unwrap();
        let bytes = [a.clone(), b.clone()].concat();
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_TCP_FRAME);
        assert_eq!(
            decode_all(Frames::new, &bytes),
            (vec![Frame(a[2..].to_vec()), Frame(b[2..].to_vec())], None)
        );
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&[0, 0, 0, 1, 0x30]), 5);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(StreamError::ZeroLength)))
        );
        assert!(stream.next().is_none());
        assert_eq!(stream.push(&a), a.len());
    }

    #[test]
    fn stream_holds_a_bounded_number_of_bytes() {
        let longest = Frame(vec![0x30; MAX_PACKET]).to_bytes().unwrap();
        contract::check_decode_with_alloc_limit(Frames::new, &longest, 2 * MAX_TCP_FRAME);
        assert_eq!(
            decode_all(Frames::new, &longest),
            (vec![Frame(longest[2..].to_vec())], None)
        );
    }

    #[test]
    fn stream_takes_many_small_packets_in_linear_time() {
        let bytes = Frame(vec![0x30, 1]).to_bytes().unwrap().repeat(200_000);
        let started = std::time::Instant::now();
        let (items, error) = decode_all(Frames::new, &bytes);
        // Allow slow test hosts while catching repeated scans or front removal.
        assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
        assert_eq!(error, None);
        assert_eq!(items.len(), 200_000);
        assert!(items.iter().all(|p| p.0 == [0x30, 1]));
    }

    #[test]
    fn authenticated_writes_every_supported_hmac_length() {
        for hmac_len in 0..=MAX_HMAC_LEN {
            let packet = plain(ControlKind::ControlV1, Control {
                session_id: CLIENT_SID,
                tls_auth: Some(TlsAuth {
                    hmac: vec![0x5a; hmac_len],
                    packet_id: 1,
                    net_time: 2,
                }),
                ack: None,
                message_id: 3,
                payload: vec![4],
            });
            let bytes = wire(&packet).unwrap();
            assert_eq!(Packet::parse_with(&bytes, packet.wrapping()), Ok(packet));
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x0b5e_1194);
        let wrappings = [
            Wrapping::None,
            Wrapping::TlsAuth { hmac_len: 0 },
            Wrapping::TlsAuth { hmac_len: 20 },
            Wrapping::TlsAuth { hmac_len: 32 },
            Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN },
            Wrapping::TlsCrypt,
        ];
        for i in 0..20_000 {
            let len = rng.index(120);
            let mut b = rng.bytes(len);
            // Mostly known opcodes and small ack counts, so parsing gets deep.
            if let Some(first) = b.first_mut() {
                *first = first_byte(rng.index(13) as u8, *first & 7);
            }
            if b.len() > 9 && i % 2 == 0 {
                b[9] %= 10;
            }
            for w in wrappings {
                if let Ok(p) = Packet::parse_with(&b, w) {
                    // Whatever is read is written back byte for byte.
                    assert_eq!(wire(&p), Ok(b.clone()), "{w:?}");
                    assert_eq!(Packet::parse_with(&b, p.wrapping()), Ok(p));
                }
            }
            // An HMAC too long is refused for any control packet, never
            // reported as a short packet.
            if let Some(&first) = b.first()
                && ControlKind::from_opcode(split_first_byte(first).0).is_some()
            {
                let too_long = Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN + 1 };
                assert_eq!(Packet::parse_with(&b, too_long), Err(Error::HmacLen(MAX_HMAC_LEN + 1)));
            }
            contract::check_decode_with_alloc_limit(Frames::new, &b, 2 * MAX_TCP_FRAME);
            contract::check_wire::<Frame>(&b);
            contract::check_wire::<Packet>(&b);
            contract::check_wire::<Authenticated<20>>(&b);
            contract::check_wire::<Encrypted>(&b);
            mutate(&mut rng, &mut b);
            contract::check_decode_with_alloc_limit(Frames::new, &b, 2 * MAX_TCP_FRAME);
        }
        // Built packets with random fields: each is written and read back
        // as the same value, or refused for the reason it breaks.
        for _ in 0..20_000 {
            let kind = ControlKind::ALL[rng.index(9)];
            let key_id = rng.index(10) as u8;
            let ids: Vec<u32> = (0..rng.index(11)).map(|_| rng.next() as u32).collect();
            let hmac_len = rng.index(MAX_HMAC_LEN + 2);
            let payload_len = rng.index(50);
            let message_id = if rng.coin() { 0 } else { rng.next() as u32 };
            let c = Control {
                session_id: [rng.next() as u8; 8],
                tls_auth: rng.coin().then(|| TlsAuth {
                    hmac: {
                        let mut hmac = vec![0; hmac_len];
                        rng.fill(&mut hmac);
                        hmac
                    },
                    packet_id: 1,
                    net_time: 2,
                }),
                ack: rng.coin().then_some(Ack {
                    ids,
                    remote_session_id: [3; 8],
                }),
                message_id,
                payload: rng.bytes(payload_len),
            };
            let want = (key_id > MAX_KEY_ID
                || kind.carries_wrapped_key()
                || c.tls_auth
                    .as_ref()
                    .is_some_and(|a| a.hmac.len() > MAX_HMAC_LEN)
                || c.ack
                    .as_ref()
                    .is_some_and(|a| a.ids.is_empty() || a.ids.len() > MAX_ACKS)
                || (kind == ControlKind::AckV1 && message_id != 0))
                .then_some(EncodeError::Unwritable);
            let p = Packet::Control { kind, key_id, body: ControlBody::Plain(c) };
            match want {
                Some(e) => assert_eq!(wire(&p), Err(e), "{p:?}"),
                None => {
                    let b = wire(&p).unwrap();
                    assert_eq!(Packet::parse_with(&b, p.wrapping()), Ok(p.clone()));
                    let bytes = Frame(b.clone()).to_bytes().unwrap();
                    assert_eq!(decode_all(Frames::new, &bytes), (vec![Frame(b)], None));
                }
            }
            // The same kind wrapped with tls-crypt, with a ciphertext that
            // may be too short or lack its wrapped key.
            let ct_len = rng.index(8);
            let mut ciphertext = rng.bytes(ct_len);
            let with_key = rng.coin();
            if with_key {
                ciphertext.extend_from_slice(&wrapped_key(MIN_WRAPPED_KEY_LEN + rng.index(4)));
            }
            let body_len = ciphertext.len() - if with_key { wrapped_key_len(&ciphertext).unwrap() } else { 0 };
            let fits = key_id <= MAX_KEY_ID
                && (!kind.carries_wrapped_key() || with_key)
                && if kind.carries_wrapped_key() { body_len } else { ciphertext.len() } >= kind.min_tls_crypt_body();
            let t = TlsCrypt { session_id: [4; 8], packet_id: 5, net_time: 6, tag: [7; 32], ciphertext };
            let p = Packet::Control { kind, key_id, body: ControlBody::TlsCrypt(t) };
            match wire(&p) {
                Ok(b) => {
                    assert!(fits, "{p:?}");
                    assert_eq!(Packet::parse_with(&b, Wrapping::TlsCrypt), Ok(p));
                }
                Err(e) => assert!(!fits, "{p:?}: {e}"),
            }
        }
        // Data packets, with key IDs and peer IDs in and out of range.
        for _ in 0..5_000 {
            let key_id = rng.index(10) as u8;
            let peer_id = (rng.next() as u32) >> rng.index(9);
            let payload_len = rng.index(20);
            let payload = rng.bytes(payload_len);
            for p in [
                Packet::DataV1 { key_id, payload: payload.clone() },
                Packet::DataV2 { key_id, peer_id, payload: payload.clone() },
            ] {
                match wire(&p) {
                    Ok(b) => assert_eq!(Packet::parse_with(&b, Wrapping::None), Ok(p)),
                    Err(e) => assert!(
                        e == EncodeError::Unwritable
                            && (key_id > MAX_KEY_ID || peer_id > MAX_PEER_ID),
                        "{p:?}: {e}"
                    ),
                }
            }
        }
    }
}
