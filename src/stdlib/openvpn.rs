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
//! with a [`Wrapping`]. The module reads the wrapping's fields and hands
//! them over as they are. It neither checks the HMAC nor decrypts.
//!
//! Nothing here reads a socket. A world that plays an OpenVPN server feeds
//! the bytes it reads from a TCP connection to a [`Decoder`], or takes each
//! UDP datagram whole, reads each packet with [`Packet::parse`], and writes
//! the reply's bytes back. What the TLS session says, and what the tunnel
//! carries, is up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes.
//!
//! ```
//! use fictionet::stdlib::openvpn::{Ack, Control, ControlBody, ControlKind, Decoder, Packet, Wrapping};
//!
//! let mut decoder = Decoder::new();
//! // A client's P_CONTROL_HARD_RESET_CLIENT_V2 over TCP: length 14,
//! // opcode 7 and key 0, session ID 1..8, no acks, message packet ID 0.
//! decoder.feed(&[0, 14, 0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0]);
//! let bytes = decoder.next_packet().unwrap().unwrap();
//! let packet = Packet::parse(&bytes, Wrapping::None).unwrap();
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
//! let wire = reply.to_tcp_bytes();
//! assert_eq!(wire[..3], [0, 26, 0x40]);
//! assert_eq!(Packet::parse(&wire[2..], Wrapping::None), Ok(reply));
//! ```

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
/// The highest key ID: it has 3 bits.
pub const MAX_KEY_ID: u8 = 7;
/// The highest peer ID: it has 24 bits.
pub const MAX_PEER_ID: u32 = 0x00ff_ffff;
/// The peer ID a client sends before the server has given it one.
pub const NO_PEER_ID: u32 = MAX_PEER_ID;

/// Opcodes, the top 5 bits of a packet's first byte.
pub mod opcode {
    #![allow(missing_docs)]
    pub const P_CONTROL_HARD_RESET_CLIENT_V1: u8 = 1;
    pub const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
    pub const P_CONTROL_SOFT_RESET_V1: u8 = 3;
    pub const P_CONTROL_V1: u8 = 4;
    pub const P_ACK_V1: u8 = 5;
    pub const P_DATA_V1: u8 = 6;
    pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
    pub const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
    pub const P_DATA_V2: u8 = 9;
    pub const P_CONTROL_HARD_RESET_CLIENT_V3: u8 = 10;
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
    /// The HMAC over the rest of the packet. A writer cuts it to
    /// [`MAX_HMAC_LEN`] bytes.
    pub hmac: Vec<u8>,
    /// The replay protection packet ID.
    pub packet_id: u32,
    /// The replay protection time, in seconds since 1970.
    pub net_time: u32,
}

/// The acknowledgements in a control packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    /// The message packet IDs acknowledged. A reader returns 1 to
    /// [`MAX_ACKS`] of them. A writer writes at most [`MAX_ACKS`], and
    /// writes an `Ack` with none as no acknowledgements at all.
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
    /// packet has none: a reader returns 0 and a writer leaves it out.
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
    /// key.
    pub ciphertext: Vec<u8>,
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

/// One OpenVPN packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// A control channel packet.
    Control {
        /// Which control packet it is.
        kind: ControlKind,
        /// The key ID, 0 to [`MAX_KEY_ID`]. A writer keeps its low 3 bits.
        key_id: u8,
        /// The packet's fields.
        body: ControlBody,
    },
    /// A P_DATA_V1 packet.
    DataV1 {
        /// The key ID, 0 to [`MAX_KEY_ID`]. A writer keeps its low 3 bits.
        key_id: u8,
        /// The encrypted tunnel packet, as bytes.
        payload: Vec<u8>,
    },
    /// A P_DATA_V2 packet.
    DataV2 {
        /// The key ID, 0 to [`MAX_KEY_ID`]. A writer keeps its low 3 bits.
        key_id: u8,
        /// The peer ID the server gave this client, 0 to [`MAX_PEER_ID`],
        /// or [`NO_PEER_ID`]. A writer keeps its low 24 bits.
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
        }
    }
}

impl std::error::Error for Error {}

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

/// A packet's first byte from its opcode and key ID. Only the low 5 bits
/// of the opcode and the low 3 of the key ID are kept.
pub fn first_byte(opcode: u8, key_id: u8) -> u8 {
    (opcode & 0x1f) << 3 | (key_id & MAX_KEY_ID)
}

impl Packet {
    /// Reads one whole packet: a UDP datagram, or what a [`Decoder`]
    /// returns. `wrapping` says how control packets are wrapped.
    pub fn parse(b: &[u8], wrapping: Wrapping) -> Result<Packet, Error> {
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
                let body = TlsCrypt { session_id, packet_id, net_time, tag, ciphertext: r.rest().to_vec() };
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

    /// The packet's key ID, as a writer writes it.
    pub fn key_id(&self) -> u8 {
        match self {
            Packet::Control { key_id, .. } | Packet::DataV1 { key_id, .. } | Packet::DataV2 { key_id, .. } => {
                key_id & MAX_KEY_ID
            }
        }
    }

    /// The [`Wrapping`] that reads this packet's bytes back. Data packets
    /// give [`Wrapping::None`], since they ignore it.
    pub fn wrapping(&self) -> Wrapping {
        match self {
            Packet::Control { body: ControlBody::TlsCrypt(_), .. } => Wrapping::TlsCrypt,
            Packet::Control { body: ControlBody::Plain(Control { tls_auth: Some(a), .. }), .. } => {
                Wrapping::TlsAuth { hmac_len: a.hmac.len().min(MAX_HMAC_LEN) }
            }
            _ => Wrapping::None,
        }
    }

    /// The packet's bytes, without a TCP length prefix. Payloads are cut
    /// so the packet is at most [`MAX_PACKET`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![first_byte(self.opcode(), self.key_id())];
        let payload: &[u8] = match self {
            Packet::DataV1 { payload, .. } => payload,
            Packet::DataV2 { peer_id, payload, .. } => {
                out.extend_from_slice(&(peer_id & MAX_PEER_ID).to_be_bytes()[1..]);
                payload
            }
            Packet::Control { body: ControlBody::TlsCrypt(c), .. } => {
                out.extend_from_slice(&c.session_id);
                out.extend_from_slice(&c.packet_id.to_be_bytes());
                out.extend_from_slice(&c.net_time.to_be_bytes());
                out.extend_from_slice(&c.tag);
                &c.ciphertext
            }
            Packet::Control { kind, body: ControlBody::Plain(c), .. } => {
                out.extend_from_slice(&c.session_id);
                if let Some(a) = &c.tls_auth {
                    out.extend_from_slice(&a.hmac[..a.hmac.len().min(MAX_HMAC_LEN)]);
                    out.extend_from_slice(&a.packet_id.to_be_bytes());
                    out.extend_from_slice(&a.net_time.to_be_bytes());
                }
                match &c.ack {
                    Some(a) if !a.ids.is_empty() => {
                        let ids = &a.ids[..a.ids.len().min(MAX_ACKS)];
                        // At most MAX_ACKS (8), so it fits a byte.
                        out.push(ids.len() as u8);
                        for id in ids {
                            out.extend_from_slice(&id.to_be_bytes());
                        }
                        out.extend_from_slice(&a.remote_session_id);
                    }
                    _ => out.push(0),
                }
                if *kind != ControlKind::AckV1 {
                    out.extend_from_slice(&c.message_id.to_be_bytes());
                }
                &c.payload
            }
        };
        // The header is under 200 bytes, far below MAX_PACKET.
        let room = MAX_PACKET.saturating_sub(out.len());
        out.extend_from_slice(&payload[..payload.len().min(room)]);
        out
    }

    /// The packet's bytes with the 2-byte length prefix TCP uses.
    pub fn to_tcp_bytes(&self) -> Vec<u8> {
        // A packet always has its first byte, and to_bytes caps the length.
        frame(&self.to_bytes()).unwrap_or_default()
    }
}

/// `packet` with the 2-byte length prefix TCP uses. It returns `None` for
/// an empty packet or one longer than [`MAX_PACKET`], which a reader would
/// refuse.
pub fn frame(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.is_empty() || packet.len() > MAX_PACKET {
        return None;
    }
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + packet.len());
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    Some(out)
}

/// Why a TCP stream cannot be split into packets. OpenVPN resets the
/// connection when it sees this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// A length prefix of 0: no packet is that short.
    ZeroLength,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::ZeroLength => write!(f, "packet length 0 in a TCP stream"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Finds the packet at the start of a TCP stream `b`. It returns
/// `Ok(None)` if `b` holds only part of one, and otherwise the packet's
/// bytes, without the prefix, and how many bytes of `b` it took.
pub fn split_tcp(b: &[u8]) -> Result<Option<(&[u8], usize)>, FrameError> {
    if b.len() < LENGTH_PREFIX_LEN {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if len == 0 {
        return Err(FrameError::ZeroLength);
    }
    let end = LENGTH_PREFIX_LEN + len;
    match b.get(LENGTH_PREFIX_LEN..end) {
        Some(packet) => Ok(Some((packet, end))),
        None => Ok(None),
    }
}

/// Splits an OpenVPN TCP stream into packets. Feed it the bytes a
/// connection reads, in order, and take packets out until it has none.
/// Each packet comes out as bytes, for [`Packet::parse`].
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small packets costs time in proportion to their bytes.
    start: usize,
    failed: Option<FrameError>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection. After a [`FrameError`] the
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

    /// The next whole packet, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A caller that takes packets out until this
    /// returns `None` after each `feed` keeps the decoder to at most
    /// [`MAX_TCP_FRAME`] bytes, plus what one `feed` added.
    pub fn next_packet(&mut self) -> Option<Result<Vec<u8>, FrameError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match split_tcp(&self.buf[self.start..]) {
            Ok(Some((packet, used))) => {
                let packet = packet.to_vec();
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
        let p = Packet::parse(&bytes, Wrapping::None).unwrap();
        let want = plain(
            ControlKind::HardResetClientV2,
            Control { session_id: CLIENT_SID, tls_auth: None, ack: None, message_id: 0, payload: vec![] },
        );
        assert_eq!(p, want);
        assert_eq!(p.to_bytes(), bytes);
        let mut tcp = vec![0, 14];
        tcp.extend_from_slice(&bytes);
        assert_eq!(p.to_tcp_bytes(), tcp);
    }

    #[test]
    fn server_hard_reset_v2_acks_the_client() {
        let mut bytes = vec![0x40];
        bytes.extend_from_slice(&SERVER_SID);
        bytes.extend_from_slice(&[1, 0, 0, 0, 0]);
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let p = Packet::parse(&bytes, Wrapping::None).unwrap();
        let ControlBody::Plain(c) = (match &p {
            Packet::Control { kind: ControlKind::HardResetServerV2, body, .. } => body.clone(),
            _ => panic!(),
        }) else {
            panic!()
        };
        assert_eq!(c.ack, Some(Ack { ids: vec![0], remote_session_id: CLIENT_SID }));
        assert_eq!(c.session_id, SERVER_SID);
        assert_eq!(p.to_bytes(), bytes);
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
        let b = p.to_bytes();
        assert_eq!(b[0], 0x22);
        assert_eq!(b.len(), 1 + 8 + 1 + 8 + 8 + 4 + 3);
        assert_eq!(&b[9..18], &[2, 0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(&b[b.len() - 7..], &[0, 0, 0, 3, 0x16, 0x03, 0x01]);
        assert_eq!(Packet::parse(&b, Wrapping::None), Ok(p));
    }

    #[test]
    fn ack_v1_has_no_message_id() {
        let mut bytes = vec![0x28];
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[1, 0, 0, 0, 5]);
        bytes.extend_from_slice(&SERVER_SID);
        let p = Packet::parse(&bytes, Wrapping::None).unwrap();
        assert_eq!(p.to_bytes(), bytes);
        // The writer leaves out a message ID set by mistake.
        let mut odd = p.clone();
        if let Packet::Control { body: ControlBody::Plain(c), .. } = &mut odd {
            c.message_id = 9;
        }
        assert_eq!(odd.to_bytes(), bytes);
        // OpenVPN ignores bytes after the acknowledgements (ssl.c reads no
        // message ID for P_ACK_V1 and stops), so they are kept as payload.
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let p = Packet::parse(&bytes, Wrapping::None).unwrap();
        let Packet::Control { body: ControlBody::Plain(c), .. } = &p else { panic!() };
        assert_eq!((c.message_id, &c.payload[..]), (0, &[0xaa, 0xbb][..]));
        assert_eq!(p.to_bytes(), bytes);
    }

    #[test]
    fn data_packets() {
        let p = Packet::parse(&[0x30, 1, 2, 3], Wrapping::None).unwrap();
        assert_eq!(p, Packet::DataV1 { key_id: 0, payload: vec![1, 2, 3] });
        let p = Packet::parse(&[0x49, 0x00, 0x00, 0x05, 0xde, 0xad], Wrapping::TlsCrypt).unwrap();
        assert_eq!(p, Packet::DataV2 { key_id: 1, peer_id: 5, payload: vec![0xde, 0xad] });
        assert_eq!(p.to_bytes(), [0x49, 0, 0, 5, 0xde, 0xad]);
        let p = Packet::DataV2 { key_id: 9, peer_id: 0xffff_ffff, payload: vec![] };
        assert_eq!(p.to_bytes(), [0x49, 0xff, 0xff, 0xff]);
        assert_eq!(
            Packet::parse(&p.to_bytes(), Wrapping::None),
            Ok(Packet::DataV2 { key_id: 1, peer_id: NO_PEER_ID, payload: vec![] })
        );
    }

    #[test]
    fn tls_auth_fields_are_read_not_checked() {
        let mut bytes = vec![0x38];
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[0xee; 20]);
        bytes.extend_from_slice(&[0, 0, 0, 1, 0x5f, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0]);
        let p = Packet::parse(&bytes, Wrapping::TlsAuth { hmac_len: 20 }).unwrap();
        let Packet::Control { body: ControlBody::Plain(c), .. } = &p else { panic!() };
        assert_eq!(c.tls_auth, Some(TlsAuth { hmac: vec![0xee; 20], packet_id: 1, net_time: 0x5f00_0000 }));
        assert_eq!(p.wrapping(), Wrapping::TlsAuth { hmac_len: 20 });
        assert_eq!(p.to_bytes(), bytes);
        assert_eq!(Packet::parse(&bytes, Wrapping::TlsAuth { hmac_len: 65 }), Err(Error::HmacLen(65)));
        // An HMAC length too long is refused before the bytes are read, so
        // even a packet cut short says so.
        assert_eq!(Packet::parse(&bytes[..3], Wrapping::TlsAuth { hmac_len: 65 }), Err(Error::HmacLen(65)));
        assert_eq!(Packet::parse(&bytes, Wrapping::TlsAuth { hmac_len: usize::MAX }), Err(Error::HmacLen(usize::MAX)));
        // Data packets ignore the wrapping, whatever it says.
        assert!(Packet::parse(&[0x30, 1], Wrapping::TlsAuth { hmac_len: usize::MAX }).is_ok());
        assert_eq!(p.session_id(), Some(CLIENT_SID));
        assert_eq!(Packet::DataV1 { key_id: 0, payload: vec![] }.session_id(), None);
    }

    #[test]
    fn tls_crypt_header_is_read_and_the_rest_kept() {
        let mut bytes = vec![0x50];
        bytes.extend_from_slice(&CLIENT_SID);
        bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
        bytes.extend_from_slice(&[0x77; 32]);
        bytes.extend_from_slice(&[9, 8, 7]);
        let p = Packet::parse(&bytes, Wrapping::TlsCrypt).unwrap();
        let want =
            TlsCrypt { session_id: CLIENT_SID, packet_id: 1, net_time: 2, tag: [0x77; 32], ciphertext: vec![9, 8, 7] };
        assert_eq!(
            p,
            Packet::Control { kind: ControlKind::HardResetClientV3, key_id: 0, body: ControlBody::TlsCrypt(want) }
        );
        assert_eq!(p.wrapping(), Wrapping::TlsCrypt);
        assert_eq!(p.to_bytes(), bytes);
    }

    #[test]
    fn errors() {
        assert_eq!(Packet::parse(&[], Wrapping::None), Err(Error::Empty));
        assert_eq!(Packet::parse(&[0x00], Wrapping::None), Err(Error::Opcode(0)));
        assert_eq!(Packet::parse(&[12 << 3], Wrapping::None), Err(Error::Opcode(12)));
        assert_eq!(Packet::parse(&[0xff], Wrapping::None), Err(Error::Opcode(31)));
        assert_eq!(Packet::parse(&[0x38, 1, 2], Wrapping::None), Err(Error::Truncated));
        assert_eq!(Packet::parse(&[0x48, 1, 2], Wrapping::None), Err(Error::Truncated));
        let mut many = vec![0x20];
        many.extend_from_slice(&CLIENT_SID);
        many.push(9);
        assert_eq!(Packet::parse(&many, Wrapping::None), Err(Error::TooManyAcks(9)));
        let long = vec![0x30; MAX_PACKET + 1];
        assert_eq!(Packet::parse(&long, Wrapping::None), Err(Error::TooLong(MAX_PACKET + 1)));
        assert!(Packet::parse(&long[..MAX_PACKET], Wrapping::None).is_ok());
        for e in [
            Error::Empty,
            Error::TooLong(1),
            Error::Opcode(0),
            Error::Truncated,
            Error::TooManyAcks(9),
            Error::HmacLen(99),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert!(!FrameError::ZeroLength.to_string().is_empty());
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
            for (tls_auth, ack) in [(None, None), (tls_auth.clone(), ack.clone()), (None, ack.clone())] {
                let payload = vec![0x16, 3, 3];
                let message_id = if kind == ControlKind::AckV1 { 0 } else { 42 };
                let c = Control { session_id: CLIENT_SID, tls_auth, ack, message_id, payload };
                out.push(Packet::Control { kind, key_id: 2, body: ControlBody::Plain(c) });
            }
            let t =
                TlsCrypt { session_id: CLIENT_SID, packet_id: 1, net_time: 2, tag: [5; 32], ciphertext: vec![6; 10] };
            out.push(Packet::Control { kind, key_id: 0, body: ControlBody::TlsCrypt(t) });
        }
        out
    }

    #[test]
    fn round_trips() {
        for p in samples() {
            let b = p.to_bytes();
            assert_eq!(Packet::parse(&b, p.wrapping()), Ok(p.clone()));
            let tcp = p.to_tcp_bytes();
            let (inner, used) = split_tcp(&tcp).unwrap().unwrap();
            assert_eq!(inner, &b[..]);
            assert_eq!(used, b.len() + 2);
        }
    }

    #[test]
    fn every_truncated_prefix() {
        for p in samples() {
            let b = p.to_bytes();
            let w = p.wrapping();
            // Where the fixed fields end and the payload starts.
            let header = match &p {
                Packet::DataV1 { payload, .. } | Packet::DataV2 { payload, .. } => b.len() - payload.len(),
                Packet::Control { body: ControlBody::TlsCrypt(t), .. } => b.len() - t.ciphertext.len(),
                Packet::Control { body: ControlBody::Plain(c), .. } => b.len() - c.payload.len(),
            };
            for n in 0..b.len() {
                let got = Packet::parse(&b[..n], w);
                if n == 0 {
                    assert_eq!(got, Err(Error::Empty));
                } else if n < header {
                    assert_eq!(got, Err(Error::Truncated), "{p:?} cut to {n}");
                } else {
                    assert!(got.is_ok(), "{p:?} cut to {n}");
                }
            }
            let tcp = p.to_tcp_bytes();
            for n in 0..tcp.len() {
                assert_eq!(split_tcp(&tcp[..n]), Ok(None));
            }
        }
    }

    #[test]
    fn writers_cap_what_they_write() {
        let p = Packet::DataV1 { key_id: 0, payload: vec![0; MAX_PACKET + 10] };
        assert_eq!(p.to_bytes().len(), MAX_PACKET);
        assert!(Packet::parse(&p.to_bytes(), Wrapping::None).is_ok());
        assert_eq!(p.to_tcp_bytes().len(), MAX_TCP_FRAME);
        let c = Control {
            session_id: CLIENT_SID,
            tls_auth: Some(TlsAuth { hmac: vec![1; 100], packet_id: 0, net_time: 0 }),
            ack: Some(Ack { ids: (0..20).collect(), remote_session_id: SERVER_SID }),
            message_id: 1,
            payload: vec![2; MAX_PACKET],
        };
        let p = plain(ControlKind::ControlV1, c);
        let b = p.to_bytes();
        assert_eq!(b.len(), MAX_PACKET);
        assert_eq!(p.wrapping(), Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN });
        let Packet::Control { body: ControlBody::Plain(back), .. } = Packet::parse(&b, p.wrapping()).unwrap() else {
            panic!()
        };
        assert_eq!(back.ack.unwrap().ids.len(), MAX_ACKS);
        assert_eq!(back.tls_auth.unwrap().hmac.len(), MAX_HMAC_LEN);
        // An Ack with no ids is written as none.
        let p = plain(
            ControlKind::ControlV1,
            Control {
                session_id: CLIENT_SID,
                tls_auth: None,
                ack: Some(Ack { ids: vec![], remote_session_id: SERVER_SID }),
                message_id: 0,
                payload: vec![],
            },
        );
        assert_eq!(p.to_bytes().len(), 14);
        assert!(Packet::parse(&p.to_bytes(), Wrapping::None).is_ok());
        assert_eq!(frame(&[]), None);
        assert_eq!(frame(&vec![0; MAX_PACKET + 1]), None);
        assert_eq!(frame(&[0x30]), Some(vec![0, 1, 0x30]));
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = samples()[0].to_tcp_bytes();
        let b = samples()[5].to_tcp_bytes();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(p) = d.next_packet() {
                got.push(p.unwrap());
            }
        }
        assert_eq!(got, [a[2..].to_vec(), b[2..].to_vec()]);
        assert_eq!(d.buffered(), 0);
        // A length of 0 breaks the stream for good.
        d.feed(&[0, 0, 0, 1, 0x30]);
        assert_eq!(d.next_packet(), Some(Err(FrameError::ZeroLength)));
        d.feed(&a);
        assert_eq!(d.next_packet(), Some(Err(FrameError::ZeroLength)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_packets_in_linear_time() {
        let one = frame(&[0x30, 1]).unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut n = 0;
        while let Some(p) = d.next_packet() {
            p.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x0b5e_1194);
        let wrappings = [
            Wrapping::None,
            Wrapping::TlsAuth { hmac_len: 0 },
            Wrapping::TlsAuth { hmac_len: 20 },
            Wrapping::TlsAuth { hmac_len: 32 },
            Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN },
            Wrapping::TlsCrypt,
        ];
        for i in 0..20_000 {
            let len = (rng.next() % 120) as usize;
            let mut b = rng.bytes(len);
            // Mostly known opcodes and small ack counts, so parsing gets deep.
            if let Some(first) = b.first_mut() {
                *first = first_byte((rng.next() % 13) as u8, *first);
            }
            if b.len() > 9 && i % 2 == 0 {
                b[9] %= 10;
            }
            for w in wrappings {
                if let Ok(p) = Packet::parse(&b, w) {
                    // Whatever is read is written back byte for byte.
                    assert_eq!(p.to_bytes(), b, "{w:?}");
                    assert_eq!(Packet::parse(&b, p.wrapping()), Ok(p));
                }
            }
            // An HMAC too long is refused for any control packet, never
            // reported as a short packet.
            if let Some(&first) = b.first()
                && ControlKind::from_opcode(split_first_byte(first).0).is_some()
            {
                let too_long = Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN + 1 };
                assert_eq!(Packet::parse(&b, too_long), Err(Error::HmacLen(MAX_HMAC_LEN + 1)));
            }
            // The same bytes as a TCP stream, whole and a byte at a time.
            let mut whole = Decoder::new();
            whole.feed(&b);
            let mut all = Vec::new();
            while let Some(Ok(p)) = whole.next_packet() {
                all.push(p);
            }
            let mut bytewise = Decoder::new();
            let mut again = Vec::new();
            for byte in &b {
                bytewise.feed(std::slice::from_ref(byte));
                while let Some(Ok(p)) = bytewise.next_packet() {
                    again.push(p);
                }
            }
            assert_eq!(all, again);
            for p in &all {
                let framed = frame(p).unwrap();
                let (inner, _) = split_tcp(&framed).unwrap().unwrap();
                assert_eq!(inner, &p[..]);
            }
        }
        // Built packets with random fields, written and read back.
        for _ in 0..5_000 {
            let kind = ControlKind::ALL[(rng.next() % 9) as usize];
            let ids: Vec<u32> = (0..rng.next() % 12).map(|_| rng.next() as u32).collect();
            let hmac_len = (rng.next() % 80) as usize;
            let payload_len = (rng.next() % 50) as usize;
            let c = Control {
                session_id: [rng.next() as u8; 8],
                tls_auth: rng.next().is_multiple_of(2).then(|| TlsAuth {
                    hmac: rng.bytes(hmac_len),
                    packet_id: 1,
                    net_time: 2,
                }),
                ack: rng.next().is_multiple_of(2).then_some(Ack { ids, remote_session_id: [3; 8] }),
                message_id: rng.next() as u32,
                payload: rng.bytes(payload_len),
            };
            let p = Packet::Control { kind, key_id: rng.next() as u8, body: ControlBody::Plain(c) };
            let b = p.to_bytes();
            let back = Packet::parse(&b, p.wrapping()).unwrap();
            assert_eq!(back.to_bytes(), b);
            let mut d = Decoder::new();
            for byte in p.to_tcp_bytes() {
                d.feed(&[byte]);
            }
            assert_eq!(d.next_packet(), Some(Ok(b)));
        }
    }
}
