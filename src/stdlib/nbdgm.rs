//! NetBIOS Datagram Service: reading and writing datagram packets, with
//! no I/O.
//!
//! On a Windows network, machines send each other short one-way messages
//! by NetBIOS name on UDP port 138. The best known are the browser
//! announcements: every few minutes a machine tells its workgroup that it
//! is there and what it serves, so it shows up in Network Neighborhood.
//! A datagram goes to one name (a direct unique datagram), to every
//! member of a group name such as a workgroup (a direct group datagram),
//! or to everyone (a broadcast datagram). Where a datagram is relayed by a
//! datagram distribution server (an NBDD), a node can ask it whether a
//! name can be reached (a query), and the server reports names it cannot
//! deliver to (an error packet). This module follows RFC 1001 and
//! RFC 1002, section 4.4.
//!
//! A NetBIOS name is 16 bytes: up to 15 characters, padded with spaces,
//! and a suffix byte that says what the name is for (`0x00` for a
//! workstation, `0x1D` for a workgroup's master browser). On the wire each
//! byte becomes two letters from `A` to `P`, one per half byte; see
//! [`Name`]. The 32 letters are the first label of a
//! DNS-style name, and an optional scope follows as more labels.
//!
//! A datagram too long for one packet is sent in fragments. The first has
//! the first flag set, each but the last has the more flag set, and each
//! says where its bytes start in the whole. A [`Reassembler`] puts them
//! back together, and [`Packet::split`] cuts a datagram into fragments.
//!
//! What a datagram carries is kept as raw bytes. Browser announcements
//! are SMB mailslot messages to `\MAILSLOT\BROWSE`; reading them is up to
//! world code ([`Packet::carries_smb`] says whether the bytes start with
//! an SMB header).
//!
//! Nothing here reads a socket. A world that plays the machines on a LAN
//! reads each datagram from its UDP socket, passes it to
//! [`Packet::parse`], and writes the bytes of [`Packet::write`] back.
//! The service runs over UDP, one packet per datagram, so there is no
//! stream decoder.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Writers refuse oversized or invalid values without changing the destination.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::nbdgm::{Body, DatagramKind, Name, Packet};
//! use std::net::Ipv4Addr;
//!
//! // The agent's machine tells the workgroup's master browser it exists.
//! let announcement = b"\xffSMB%rest of the announcement".to_vec();
//! let sent = Packet::datagram(
//!     DatagramKind::DirectGroup,
//!     0x8001,
//!     Ipv4Addr::new(10, 0, 0, 9),
//!     138,
//!     Name::new("laptop", 0x00),
//!     Name::new("WORKGROUP", 0x1d),
//!     announcement.clone(),
//! );
//! let bytes = sent.to_bytes().unwrap();
//! // A 14-byte header, two 34-byte names, then the data.
//! assert_eq!(bytes.len(), 14 + 34 + 34 + announcement.len());
//! // A direct group datagram, the first fragment, from a B node.
//! assert_eq!(bytes[..4], [0x11, 0x02, 0x80, 0x01]);
//! // The first-level encoding: L (0x4c) becomes "EM".
//! assert_eq!(&bytes[14..17], b"\x20EM");
//!
//! // The world reads it back, as the master browser would.
//! let got = Packet::parse(&bytes).unwrap();
//! assert!(got.carries_smb());
//! let Body::Datagram(d) = &got.body else { panic!("not a datagram") };
//! assert_eq!(d.destination, Name::new("WORKGROUP", 0x1d));
//! assert_eq!(d.source.to_string(), "LAPTOP<00>");
//! assert_eq!(d.data, announcement);
//! ```

use fictionet::stdlib::codec::Wire;

use std::net::Ipv4Addr;

/// The UDP port the datagram service listens on.
pub const PORT: u16 = 138;
/// The length of the header every packet starts with: type, flags, id,
/// source address and source port.
pub const HEADER_LEN: usize = 10;
/// The length of a datagram's header: the common header, then the length
/// and offset fields.
pub const DATAGRAM_HEADER_LEN: usize = HEADER_LEN + 4;
/// The length of an error packet: the common header and the error code.
pub const ERROR_LEN: usize = HEADER_LEN + 1;
/// The longest packet this module reads or writes: the most bytes one UDP
/// datagram over IPv4 can carry. A longer packet is refused.
pub const MAX_PACKET: usize = 65_507;
/// The length of a NetBIOS name: 15 characters and a suffix byte.
pub const NAME_LEN: usize = 16;
/// The length of a NetBIOS name in the first-level encoding.
pub const ENCODED_LEN: usize = 2 * NAME_LEN;
/// The longest label in a name's scope.
pub const MAX_LABEL: usize = 63;
/// The longest name on the wire: every label with its length byte, and
/// the zero byte that ends the name.
pub const MAX_NAME_LEN: usize = 255;
/// The most datagram bytes a [`Reassembler`] puts back together. The
/// offset field is 16 bits, so no whole datagram is meant to be longer.
pub const MAX_REASSEMBLED: usize = 65_535;
/// The most datagrams a [`Reassembler`] holds partly put together. When
/// one more starts, the oldest is dropped.
pub const MAX_PENDING: usize = 16;

/// Message types: the first byte of every packet.
pub mod msg_type {
    /// A datagram to a unique name.
    pub const DIRECT_UNIQUE: u8 = 0x10;
    /// A datagram to a group name.
    pub const DIRECT_GROUP: u8 = 0x11;
    /// A datagram to every name.
    pub const BROADCAST: u8 = 0x12;
    /// A datagram server could not deliver a datagram.
    pub const ERROR: u8 = 0x13;
    /// Asks a datagram server whether it can deliver to a name.
    pub const QUERY_REQUEST: u8 = 0x14;
    /// The server can deliver to the name.
    pub const POSITIVE_QUERY_RESPONSE: u8 = 0x15;
    /// The server cannot deliver to the name.
    pub const NEGATIVE_QUERY_RESPONSE: u8 = 0x16;
}

/// Bits of the flags byte.
pub mod flag {
    /// More fragments of this datagram follow.
    pub const MORE: u8 = 0x01;
    /// This is the first fragment, and maybe the only one.
    pub const FIRST: u8 = 0x02;
    /// The two bits that say what kind of node sent the packet.
    pub const NODE_TYPE: u8 = 0x0c;
    /// Bits the RFC reserves, which must be zero. Readers ignore them.
    pub const RESERVED: u8 = 0xf0;
}

/// The first-level encoding of a 16-byte NetBIOS name: each byte becomes
/// two letters, `A` plus its high half, then `A` plus its low half.
fn encode_first_level(name: &[u8; NAME_LEN]) -> [u8; ENCODED_LEN] {
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
    for (i, pair) in label.as_chunks::<2>().0.iter().enumerate() {
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
    /// The scope labels. Writers refuse empty labels, labels above [`MAX_LABEL`],
    /// and names above [`MAX_NAME_LEN`].
    pub scope: Vec<Vec<u8>>,
}

impl Name {
    /// The name `name` with suffix `suffix` and no scope. The name is put
    /// in uppercase, as Windows does, cut to 15 bytes, and padded with
    /// spaces.
    pub fn new(name: &str, suffix: u8) -> Name {
        let mut bytes = [b' '; NAME_LEN];
        for (slot, b) in bytes.iter_mut().zip(name.bytes().take(NAME_LEN - 1)) {
            *slot = b.to_ascii_uppercase();
        }
        bytes[NAME_LEN - 1] = suffix;
        Name { bytes, scope: Vec::new() }
    }

    /// The name `*` followed by zero bytes, which broadcast datagrams are
    /// sent to.
    pub fn wildcard() -> Name {
        let mut bytes = [0u8; NAME_LEN];
        bytes[0] = b'*';
        Name { bytes, scope: Vec::new() }
    }

    /// This name with the scope `scope`, given with dots between labels.
    /// Empty labels are skipped. Other labels are kept as given, so the
    /// writer refuses labels above [`MAX_LABEL`] and names above
    /// [`MAX_NAME_LEN`].
    pub fn with_scope(mut self, scope: &str) -> Name {
        self.scope = scope.split('.').filter(|l| !l.is_empty()).map(|l| l.as_bytes().to_vec()).collect();
        self
    }

    /// The name's characters, without the suffix or the padding spaces.
    pub fn name(&self) -> &[u8] {
        let chars = &self.bytes[..NAME_LEN - 1];
        let end = chars.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        &chars[..end]
    }

    /// The suffix: the last byte, which says what the name is for.
    pub fn suffix(&self) -> u8 {
        self.bytes[NAME_LEN - 1]
    }

    /// Reads the name at the start of `b`, and how many bytes it took.
    /// Names in datagram packets are written out in full, so a pointer to
    /// an earlier name, as DNS uses, is refused.
    fn parse_prefix(b: &[u8]) -> Result<(Name, usize), Error> {
        let first = *b.first().ok_or(Error::Truncated)?;
        if usize::from(first) != ENCODED_LEN {
            return Err(Error::Name);
        }
        let label = b.get(1..1 + ENCODED_LEN).ok_or(Error::Truncated)?;
        let bytes = decode_first_level(label).ok_or(Error::Name)?;
        let mut at = 1 + ENCODED_LEN;
        let mut scope = Vec::new();
        loop {
            let len = usize::from(*b.get(at).ok_or(Error::Truncated)?);
            if len == 0 {
                at += 1;
                break;
            }
            if len > MAX_LABEL {
                return Err(Error::Name);
            }
            // The label, its length byte, and the final zero must fit.
            if at + 1 + len + 1 > MAX_NAME_LEN {
                return Err(Error::Name);
            }
            let label = b.get(at + 1..at + 1 + len).ok_or(Error::Truncated)?;
            scope.push(label.to_vec());
            at += 1 + len;
        }
        Ok((Name { bytes, scope }, at))
    }
}

impl std::fmt::Display for Name {
    /// The name as Windows tools print it, such as `FILES<20>`, with the
    /// scope after a dot. Bytes that are not printable ASCII are written
    /// as `\xNN`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = |f: &mut std::fmt::Formatter<'_>, bytes: &[u8]| -> std::fmt::Result {
            for &b in bytes {
                if (0x20..0x7f).contains(&b) && b != b'\\' {
                    write!(f, "{}", b as char)?;
                } else {
                    write!(f, "\\x{b:02x}")?;
                }
            }
            Ok(())
        };
        text(f, self.name())?;
        write!(f, "<{:02X}>", self.suffix())?;
        for label in &self.scope {
            f.write_str(".")?;
            text(f, label)?;
        }
        Ok(())
    }
}

/// What kind of node sent a packet: the flags' SNT field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeType {
    /// A broadcast node, which finds names by asking the whole LAN.
    B,
    /// A point-to-point node, which asks a name server.
    P,
    /// A mixed node, which broadcasts first and then asks a name server.
    M,
    /// A datagram distribution server, relaying for another node.
    Nbdd,
}

impl NodeType {
    /// The node type the two bits `v` stand for. Higher bits are ignored.
    pub fn from_bits(v: u8) -> NodeType {
        match v & 3 {
            0 => NodeType::B,
            1 => NodeType::P,
            2 => NodeType::M,
            _ => NodeType::Nbdd,
        }
    }

    /// The two bits that stand for this node type.
    pub fn bits(self) -> u8 {
        match self {
            NodeType::B => 0,
            NodeType::P => 1,
            NodeType::M => 2,
            NodeType::Nbdd => 3,
        }
    }
}

/// The flags byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flags {
    /// More fragments of this datagram follow.
    pub more: bool,
    /// This is the first fragment, and maybe the only one.
    pub first: bool,
    /// What kind of node sent the packet.
    pub node_type: NodeType,
}

impl Flags {
    /// The flags of a datagram sent whole by a B node: first, no more.
    pub fn whole() -> Flags {
        Flags { more: false, first: true, node_type: NodeType::B }
    }

    /// The flags read from `v`. The reserved bits are ignored.
    pub fn from_byte(v: u8) -> Flags {
        Flags {
            more: v & flag::MORE != 0,
            first: v & flag::FIRST != 0,
            node_type: NodeType::from_bits((v & flag::NODE_TYPE) >> 2),
        }
    }

    /// The flags as a byte, with the reserved bits zero.
    pub fn to_byte(self) -> u8 {
        let mut v = self.node_type.bits() << 2;
        if self.first {
            v |= flag::FIRST;
        }
        if self.more {
            v |= flag::MORE;
        }
        v
    }
}

/// Who a datagram is for, from its message type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DatagramKind {
    /// One unique name.
    DirectUnique,
    /// Every member of a group name.
    DirectGroup,
    /// Every name.
    Broadcast,
}

impl DatagramKind {
    /// The message type byte for this kind.
    pub fn msg_type(self) -> u8 {
        match self {
            DatagramKind::DirectUnique => msg_type::DIRECT_UNIQUE,
            DatagramKind::DirectGroup => msg_type::DIRECT_GROUP,
            DatagramKind::Broadcast => msg_type::BROADCAST,
        }
    }
}

/// A datagram, or one fragment of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    /// Who it is for.
    pub kind: DatagramKind,
    /// Where this fragment's data starts in the whole datagram's data. It
    /// is 0 for a datagram sent whole.
    pub offset: u16,
    /// The name it is from.
    pub source: Name,
    /// The name it is for.
    pub destination: Name,
    /// The data, such as an SMB browser announcement, as raw bytes. A
    /// writer refuses data that does not fit in [`MAX_PACKET`] with the names.
    pub data: Vec<u8>,
}

/// Why a datagram server could not deliver a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The destination name is not registered anywhere (0x82).
    DestinationNameNotPresent,
    /// The source name was not well formed (0x83).
    InvalidSourceName,
    /// The destination name was not well formed (0x84).
    InvalidDestinationName,
    /// A code the RFC does not define, kept as it came.
    Other(u8),
}

impl ErrorCode {
    /// The error code `c` stands for.
    pub fn from_code(c: u8) -> ErrorCode {
        match c {
            0x82 => ErrorCode::DestinationNameNotPresent,
            0x83 => ErrorCode::InvalidSourceName,
            0x84 => ErrorCode::InvalidDestinationName,
            other => ErrorCode::Other(other),
        }
    }

    /// The code's byte.
    pub fn code(self) -> u8 {
        match self {
            ErrorCode::DestinationNameNotPresent => 0x82,
            ErrorCode::InvalidSourceName => 0x83,
            ErrorCode::InvalidDestinationName => 0x84,
            ErrorCode::Other(c) => c,
        }
    }
}

/// What a packet holds after the common header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// A direct unique, direct group or broadcast datagram.
    Datagram(Datagram),
    /// A datagram server could not deliver a datagram.
    Error(ErrorCode),
    /// Asks a datagram server whether it can deliver to this name.
    QueryRequest(Name),
    /// The server can deliver to this name.
    PositiveQueryResponse(Name),
    /// The server cannot deliver to this name.
    NegativeQueryResponse(Name),
}

impl Body {
    /// The message type byte for this body.
    pub fn msg_type(&self) -> u8 {
        match self {
            Body::Datagram(d) => d.kind.msg_type(),
            Body::Error(_) => msg_type::ERROR,
            Body::QueryRequest(_) => msg_type::QUERY_REQUEST,
            Body::PositiveQueryResponse(_) => msg_type::POSITIVE_QUERY_RESPONSE,
            Body::NegativeQueryResponse(_) => msg_type::NEGATIVE_QUERY_RESPONSE,
        }
    }
}

/// One datagram service packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The flags byte.
    pub flags: Flags,
    /// Chosen by the sender. Every fragment of one datagram has the same
    /// id, and a server's reply copies it.
    pub id: u16,
    /// The address of the node the datagram came from. A datagram server
    /// relaying it keeps the first sender's address here.
    pub source_ip: Ipv4Addr,
    /// The UDP port of the node the datagram came from.
    pub source_port: u16,
    /// What the packet holds.
    pub body: Body,
}

/// Why bytes are not a datagram service packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The packet ended before a field it needs.
    Truncated,
    /// The packet is longer than [`MAX_PACKET`].
    TooLong(usize),
    /// The message type is not one the RFC defines.
    MsgType(u8),
    /// A datagram's length field does not match the bytes after the
    /// offset field: it says `field`, and there are `actual` (more than
    /// `field`; fewer reads as [`Error::Truncated`]).
    Length {
        /// What the length field says.
        field: u16,
        /// How many bytes there are.
        actual: usize,
    },
    /// A name is not well formed: its first label is not 32 letters from
    /// `A` to `P`, a label is too long or a pointer, or it passes
    /// [`MAX_NAME_LEN`].
    Name,
    /// Bytes follow the end of an error, query or response packet.
    Trailing(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Truncated => f.write_str("packet ends early"),
            Error::TooLong(n) => write!(f, "packet of {n} bytes, over {MAX_PACKET}"),
            Error::MsgType(t) => write!(f, "unknown message type {t:#04x}"),
            Error::Length { field, actual } => {
                write!(f, "length field {field}, but {actual} bytes follow the offset")
            }
            Error::Name => f.write_str("malformed NetBIOS name"),
            Error::Trailing(n) => write!(f, "{n} bytes after the end of the packet"),
        }
    }
}

impl std::error::Error for Error {}

impl Packet {
    /// A datagram sent whole, from a B node.
    pub fn datagram(
        kind: DatagramKind,
        id: u16,
        source_ip: Ipv4Addr,
        source_port: u16,
        source: Name,
        destination: Name,
        data: Vec<u8>,
    ) -> Packet {
        Packet {
            flags: Flags::whole(),
            id,
            source_ip,
            source_port,
            body: Body::Datagram(Datagram { kind, offset: 0, source, destination, data }),
        }
    }

    /// The datagram this packet holds, or `None` for an error, query or
    /// response packet.
    pub fn as_datagram(&self) -> Option<&Datagram> {
        match &self.body {
            Body::Datagram(d) => Some(d),
            _ => None,
        }
    }

    /// Whether this is a datagram whose data starts with an SMB header
    /// (`0xFF` then `SMB`), as browser announcements and other mailslot
    /// messages do.
    pub fn carries_smb(&self) -> bool {
        matches!(&self.body, Body::Datagram(d) if d.data.starts_with(b"\xffSMB"))
    }

    /// The answer a datagram server at `ip` and `port` gives this query
    /// request: positive if it can deliver to the name (`present`), and
    /// negative if not. It has the request's id and name, and flags for a
    /// whole packet from a server. It returns `None` if this is not a
    /// query request.
    pub fn query_response(&self, ip: Ipv4Addr, port: u16, present: bool) -> Option<Packet> {
        let Body::QueryRequest(name) = &self.body else { return None };
        let body =
            if present { Body::PositiveQueryResponse(name.clone()) } else { Body::NegativeQueryResponse(name.clone()) };
        Some(Packet { flags: server_flags(), id: self.id, source_ip: ip, source_port: port, body })
    }

    /// The error packet a datagram server at `ip` and `port` sends when it
    /// cannot deliver this packet, with the packet's id.
    pub fn error(&self, ip: Ipv4Addr, port: u16, code: ErrorCode) -> Packet {
        Packet { flags: server_flags(), id: self.id, source_ip: ip, source_port: port, body: Body::Error(code) }
    }

    /// Splits this datagram into fragments of at most max_data bytes.
    /// The fragment size is limited to what fits with the names, and at least one.
    /// Offsets start at zero. Refuses data above [`MAX_REASSEMBLED`] or invalid names.
    /// Non-datagram packets come back as one packet.
    pub fn split(&self, max_data: usize) -> Result<Vec<Packet>, Error> {
        let Body::Datagram(d) = &self.body else { return Ok(vec![self.clone()]) };
        let (source, destination) = (d.source.to_bytes()?, d.destination.to_bytes()?);
        let names = source.len() + destination.len();
        let room = MAX_PACKET - DATAGRAM_HEADER_LEN - names;
        let size = max_data.clamp(1, room);
        if d.data.len() > MAX_REASSEMBLED {
            return Err(Error::Unwritable);
        }
        let data = &d.data;
        let chunks: Vec<&[u8]> = if data.is_empty() { vec![data] } else { data.chunks(size).collect() };
        let last = chunks.len() - 1;
        let mut out = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.into_iter().enumerate() {
            // Every chunk starts before MAX_REASSEMBLED, so its offset fits.
            let offset = (i * size) as u16;
            let flags = Flags { more: i < last, first: i == 0, node_type: self.flags.node_type };
            // Each fragment copies the names and its own bytes, never the
            // whole data, so cutting a long datagram finely stays linear.
            let fragment = Datagram {
                kind: d.kind,
                offset,
                source: d.source.clone(),
                destination: d.destination.clone(),
                data: chunk.to_vec(),
            };
            out.push(Packet {
                flags,
                id: self.id,
                source_ip: self.source_ip,
                source_port: self.source_port,
                body: Body::Datagram(fragment),
            });
        }
        Ok(out)
    }
}

/// The flags a datagram server sends a reply with.
fn server_flags() -> Flags {
    Flags { more: false, first: true, node_type: NodeType::Nbdd }
}

/// One datagram partly put back together.
#[derive(Debug)]
struct Pending {
    first: Packet,
    data: Vec<u8>,
}

/// Puts fragmented datagrams back together. Pass each datagram packet
/// as it comes; it hands back each datagram once its last fragment is in.
/// Fragments of one datagram share a source address, port and id, and
/// must come in order. A fragment out of order, or one whose names or
/// kind differ from the first, drops the datagram. It holds at most
/// [`MAX_PENDING`] datagrams, each at most [`MAX_REASSEMBLED`] bytes.
#[derive(Debug, Default)]
pub struct Reassembler {
    pending: Vec<Pending>,
}

impl Reassembler {
    /// A reassembler holding nothing.
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// Takes one packet. It returns the whole datagram, with offset 0 and
    /// the first flag set, once one is complete. A datagram sent whole
    /// comes straight back. Packets that are not datagrams are ignored.
    pub fn push(&mut self, mut packet: Packet) -> Option<Packet> {
        let Body::Datagram(d) = &mut packet.body else { return None };
        let key = (packet.source_ip, packet.source_port, packet.id);
        let at = self.pending.iter().position(|p| (p.first.source_ip, p.first.source_port, p.first.id) == key);
        if packet.flags.first {
            if let Some(i) = at {
                self.pending.remove(i);
            }
            if d.offset != 0 || d.data.len() > MAX_REASSEMBLED {
                return None;
            }
            if !packet.flags.more {
                return Some(packet);
            }
            if self.pending.len() >= MAX_PENDING {
                self.pending.remove(0);
            }
            // The data moves out of the first fragment, so it is held once.
            let data = std::mem::take(&mut d.data);
            self.pending.push(Pending { first: packet, data });
            return None;
        }
        let i = at?;
        let p = &mut self.pending[i];
        let Body::Datagram(start) = &p.first.body else { return None };
        let fits = p.data.len().checked_add(d.data.len()).is_some_and(|n| n <= MAX_REASSEMBLED);
        if usize::from(d.offset) != p.data.len()
            || !fits
            || d.kind != start.kind
            || d.source != start.source
            || d.destination != start.destination
        {
            self.pending.remove(i);
            return None;
        }
        p.data.extend_from_slice(&d.data);
        if packet.flags.more {
            return None;
        }
        let Pending { mut first, data } = self.pending.remove(i);
        first.flags.more = false;
        if let Body::Datagram(whole) = &mut first.body {
            whole.data = data;
        }
        Some(first)
    }

    /// How many datagrams are partly put together.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

impl Wire for Name {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one uncompressed NetBIOS name and scope. Refuses pointers, invalid
    /// first-level labels, oversized names and trailing bytes.
    fn parse(b: &[u8]) -> Result<Name, Error> {
        let (value, used) = Self::parse_prefix(b)?;
        if used != b.len() {
            return Err(Error::Trailing(b.len() - used));
        }
        Ok(value)
    }

    /// Appends the uncompressed name. Refuses empty or oversized scope labels and
    /// names above [`MAX_NAME_LEN`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::with_capacity(ENCODED_LEN + 2);
        out.push(ENCODED_LEN as u8);
        out.extend_from_slice(&encode_first_level(&self.bytes));
        for label in &self.scope {
            if label.len() > MAX_LABEL {
                return Err(Error::Unwritable);
            }
            if label.is_empty() {
                return Err(Error::Unwritable);
            }
            // The label, its length byte, and the final zero must fit.
            if out.len() + 1 + label.len() + 1 > MAX_NAME_LEN {
                return Err(Error::Unwritable);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);

        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the packet in `b`, which must be one whole UDP datagram.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Packet, Error> {
        if b.len() > MAX_PACKET {
            return Err(Error::TooLong(b.len()));
        }
        let ty = *b.first().ok_or(Error::Truncated)?;
        if !(msg_type::DIRECT_UNIQUE..=msg_type::NEGATIVE_QUERY_RESPONSE).contains(&ty) {
            return Err(Error::MsgType(ty));
        }
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let flags = Flags::from_byte(b[1]);
        let id = be16(b, 2);
        let source_ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
        let source_port = be16(b, 8);
        let rest = &b[HEADER_LEN..];
        let body = match ty {
            msg_type::DIRECT_UNIQUE | msg_type::DIRECT_GROUP | msg_type::BROADCAST => {
                let kind = match ty {
                    msg_type::DIRECT_UNIQUE => DatagramKind::DirectUnique,
                    msg_type::DIRECT_GROUP => DatagramKind::DirectGroup,
                    _ => DatagramKind::Broadcast,
                };
                if rest.len() < 4 {
                    return Err(Error::Truncated);
                }
                let field = be16(rest, 0);
                let offset = be16(rest, 2);
                let after = &rest[4..];
                let want = usize::from(field);
                if after.len() < want {
                    return Err(Error::Truncated);
                }
                if after.len() > want {
                    return Err(Error::Length { field, actual: after.len() });
                }
                let (source, used) = Name::parse_prefix(after)?;
                let (destination, used2) = Name::parse_prefix(&after[used..])?;
                let data = after[used + used2..].to_vec();
                Body::Datagram(Datagram { kind, offset, source, destination, data })
            }
            msg_type::ERROR => {
                let (&code, extra) = rest.split_first().ok_or(Error::Truncated)?;
                if !extra.is_empty() {
                    return Err(Error::Trailing(extra.len()));
                }
                Body::Error(ErrorCode::from_code(code))
            }
            _ => {
                let (name, used) = Name::parse_prefix(rest)?;
                if used < rest.len() {
                    return Err(Error::Trailing(rest.len() - used));
                }
                match ty {
                    msg_type::QUERY_REQUEST => Body::QueryRequest(name),
                    msg_type::POSITIVE_QUERY_RESPONSE => Body::PositiveQueryResponse(name),
                    _ => Body::NegativeQueryResponse(name),
                }
            }
        };
        Ok(Packet { flags, id, source_ip, source_port, body })
    }

    /// Appends the complete datagram. Refuses invalid names, oversized data and
    /// values that would change on reading. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::with_capacity(DATAGRAM_HEADER_LEN + 2 * (ENCODED_LEN + 2));
        out.push(self.body.msg_type());
        out.push(self.flags.to_byte());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.source_ip.octets());
        out.extend_from_slice(&self.source_port.to_be_bytes());
        match &self.body {
            Body::Datagram(d) => {
                let source = d.source.to_bytes()?;
                let destination = d.destination.to_bytes()?;
                // Names are at most 255 bytes each, so there is always room.
                let room = MAX_PACKET - DATAGRAM_HEADER_LEN - source.len() - destination.len();
                if d.data.len() > room {
                    return Err(Error::Unwritable);
                }
                let data = &d.data;
                let length = source.len() + destination.len() + data.len();
                // MAX_PACKET is under 65,536, so the length fits.
                out.extend_from_slice(&(length as u16).to_be_bytes());
                out.extend_from_slice(&d.offset.to_be_bytes());
                out.extend_from_slice(&source);
                out.extend_from_slice(&destination);
                out.extend_from_slice(data);
            }
            Body::Error(code) => out.push(code.code()),
            Body::QueryRequest(n) | Body::PositiveQueryResponse(n) | Body::NegativeQueryResponse(n) => {
                n.write(&mut out)?
            }
        }
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Lcg, contract, test_support::mutate};

    fn ip() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 9)
    }

    fn sample_datagram() -> Packet {
        Packet::datagram(
            DatagramKind::DirectGroup,
            0x1234,
            ip(),
            138,
            Name::new("HOST", 0),
            Name::new("WORKGROUP", 0x1d),
            b"\xffSMB%hello".to_vec(),
        )
    }

    fn samples() -> Vec<Vec<u8>> {
        let q = Packet {
            flags: Flags::whole(),
            id: 7,
            source_ip: ip(),
            source_port: 138,
            body: Body::QueryRequest(Name::new("FILES", 0x20).with_scope("corp.example")),
        };
        let mut b =
            Packet::datagram(DatagramKind::Broadcast, 9, ip(), 138, Name::new("A", 0), Name::wildcard(), vec![1, 2, 3]);
        b.flags = Flags { more: true, first: true, node_type: NodeType::M };
        vec![
            sample_datagram().to_bytes().unwrap(),
            b.to_bytes().unwrap(),
            q.to_bytes().unwrap(),
            q.query_response(ip(), 138, true).unwrap().to_bytes().unwrap(),
            q.query_response(ip(), 138, false).unwrap().to_bytes().unwrap(),
            q.error(ip(), 138, ErrorCode::DestinationNameNotPresent).to_bytes().unwrap(),
        ]
    }

    #[test]
    fn first_level_encoding_example() {
        // RFC 1001, section 14.1: "FRED" padded with spaces.
        let n = Name::new("Fred", b' ');
        let enc = n.to_bytes().unwrap()[1..1 + ENCODED_LEN].to_vec();
        assert_eq!(&enc, b"EGFCEFEECACACACACACACACACACACACA");
        assert_eq!(decode_first_level(&enc), Some(n.bytes));
        assert_eq!(decode_first_level(b"EG"), None);
        let mut bad = enc;
        bad[0] = b'Q';
        assert_eq!(decode_first_level(&bad), None);
        bad[0] = b'e';
        assert_eq!(decode_first_level(&bad), None);
    }

    #[test]
    fn datagram_layout() {
        let p = sample_datagram();
        let b = p.to_bytes().unwrap();
        assert_eq!(b[0], 0x11);
        assert_eq!(b[1], 0x02);
        assert_eq!(b[2..4], [0x12, 0x34]);
        assert_eq!(b[4..8], [10, 0, 0, 9]);
        assert_eq!(b[8..10], [0, 138]);
        // The length counts the names and the data.
        assert_eq!(usize::from(be16(&b, 10)), 34 + 34 + 10);
        assert_eq!(b[12..14], [0, 0]);
        assert_eq!(b[14], 32);
        assert_eq!(b[47], 0);
        assert_eq!(&b[b.len() - 10..], b"\xffSMB%hello");
        assert_eq!(Packet::parse(&b), Ok(p.clone()));
        assert!(p.carries_smb());
        assert_eq!(Packet::parse(&b).unwrap().to_bytes().unwrap(), b);
    }

    #[test]
    fn flags() {
        for v in 0..=255u8 {
            let f = Flags::from_byte(v);
            assert_eq!(f.to_byte(), v & !flag::RESERVED);
            assert_eq!(Flags::from_byte(f.to_byte()), f);
        }
        assert_eq!(Flags::from_byte(0x0e), Flags { more: false, first: true, node_type: NodeType::Nbdd });
        assert_eq!(Flags::from_byte(0x05), Flags { more: true, first: false, node_type: NodeType::P });
    }

    #[test]
    fn error_codes() {
        for c in 0..=255u8 {
            assert_eq!(ErrorCode::from_code(c).code(), c);
        }
        assert_eq!(ErrorCode::from_code(0x83), ErrorCode::InvalidSourceName);
        assert_eq!(ErrorCode::from_code(0x84), ErrorCode::InvalidDestinationName);
        let p = sample_datagram().error(ip(), 138, ErrorCode::DestinationNameNotPresent);
        let b = p.to_bytes().unwrap();
        assert_eq!(b, [0x13, 0x0e, 0x12, 0x34, 10, 0, 0, 9, 0, 138, 0x82]);
        assert_eq!(Packet::parse(&b), Ok(p));
    }

    #[test]
    fn queries() {
        let name = Name::new("FILES", 0x20).with_scope("corp.example");
        let q = Packet {
            flags: Flags::whole(),
            id: 5,
            source_ip: ip(),
            source_port: 138,
            body: Body::QueryRequest(name.clone()),
        };
        let b = q.to_bytes().unwrap();
        assert_eq!(b[0], 0x14);
        assert_eq!(b.len(), HEADER_LEN + 1 + 32 + 5 + 8 + 1);
        assert_eq!(Packet::parse(&b), Ok(q.clone()));
        let yes = q.query_response(ip(), 138, true).unwrap();
        assert_eq!(yes.body, Body::PositiveQueryResponse(name.clone()));
        assert_eq!(yes.to_bytes().unwrap()[0], 0x15);
        let no = q.query_response(ip(), 138, false).unwrap();
        assert_eq!(no.to_bytes().unwrap()[0], 0x16);
        assert_eq!(Packet::parse(&no.to_bytes().unwrap()), Ok(no.clone()));
        assert_eq!(no.query_response(ip(), 138, true), None);
        assert_eq!(sample_datagram().query_response(ip(), 138, true), None);
        assert_eq!(name.to_string(), "FILES<20>.corp.example");
    }

    #[test]
    fn errors() {
        let good = sample_datagram().to_bytes().unwrap();
        assert_eq!(Packet::parse(&[]), Err(Error::Truncated));
        assert_eq!(Packet::parse(&[0x17]), Err(Error::MsgType(0x17)));
        assert_eq!(Packet::parse(&[0x0f, 0, 0]), Err(Error::MsgType(0x0f)));
        assert_eq!(Packet::parse(&vec![0x10; MAX_PACKET + 1]), Err(Error::TooLong(MAX_PACKET + 1)));
        // Extra bytes after a datagram's length.
        let mut long = good.clone();
        long.push(0);
        assert_eq!(Packet::parse(&long), Err(Error::Length { field: 78, actual: 79 }));
        // A bad first label: wrong length, then a letter past P.
        let mut b = good.clone();
        b[14] = 31;
        assert_eq!(Packet::parse(&b), Err(Error::Name));
        let mut b = good.clone();
        b[15] = b'Z';
        assert_eq!(Packet::parse(&b), Err(Error::Name));
        // A pointer where the destination's scope would start.
        let mut b = good.clone();
        b[47 + 34] = 0xc0;
        assert_eq!(Packet::parse(&b), Err(Error::Name));
        // Trailing bytes after an error and a query.
        let e = sample_datagram().error(ip(), 1, ErrorCode::Other(9)).to_bytes().unwrap();
        let mut e2 = e.clone();
        e2.extend_from_slice(&[1, 2]);
        assert_eq!(Packet::parse(&e2), Err(Error::Trailing(2)));
        let q = Packet {
            flags: Flags::whole(),
            id: 1,
            source_ip: ip(),
            source_port: 1,
            body: Body::QueryRequest(Name::new("X", 0)),
        };
        let mut qb = q.to_bytes().unwrap();
        qb.push(0);
        assert_eq!(Packet::parse(&qb), Err(Error::Trailing(1)));
        // A name past MAX_NAME_LEN on the wire.
        let mut n = vec![32];
        n.extend_from_slice(&[b'A'; 32]);
        for _ in 0..4 {
            n.push(63);
            n.extend_from_slice(&[b'x'; 63]);
        }
        n.push(0);
        assert_eq!(Name::parse(&n), Err(Error::Name));
        // A label longer than 63 (and not a pointer).
        let mut n = vec![32];
        n.extend_from_slice(&[b'A'; 32]);
        n.push(64);
        assert_eq!(Name::parse(&n), Err(Error::Name));
        for e in [Error::Truncated, Error::Name, Error::Length { field: 1, actual: 2 }] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn spec_boundaries() {
        // The wildcard: "*" then 15 zero bytes, as "CK" and 30 "A"s.
        let w = Name::wildcard().to_bytes().unwrap();
        assert_eq!(&w[1..3], b"CK");
        assert!(w[3..33].iter().all(|&c| c == b'A'));
        // A name of exactly 255 bytes on the wire is read; 256 is not.
        let mut n = vec![32];
        n.extend_from_slice(&[b'A'; 32]);
        for _ in 0..3 {
            n.push(63);
            n.extend_from_slice(&[b'x'; 63]);
        }
        n.push(28);
        n.extend_from_slice(&[b'y'; 28]);
        n.push(0);
        assert_eq!(n.len(), MAX_NAME_LEN);
        assert_eq!(
            Name::parse(&n),
            Ok(Name {
                bytes: [0; NAME_LEN],
                scope: vec![
                    vec![b'x'; 63],
                    vec![b'x'; 63],
                    vec![b'x'; 63],
                    vec![b'y'; 28]
                ]
            })
        );
        let mut over = n.clone();
        over.insert(n.len() - 1, b'y');
        over[n.len() - 30] = 29;
        assert_eq!(Name::parse(&over), Err(Error::Name));
        // The flags bits: M is 0x01, F is 0x02, SNT is 0x0c.
        assert_eq!(Flags { more: true, first: false, node_type: NodeType::M }.to_byte(), 0x09);
        // A length field that ends inside the names refuses the packet.
        let mut b = sample_datagram().to_bytes().unwrap();
        b.truncate(DATAGRAM_HEADER_LEN + 34);
        b[10..12].copy_from_slice(&34u16.to_be_bytes());
        assert!(Packet::parse(&b).is_err());
    }

    #[test]
    fn every_prefix_is_truncated() {
        for s in samples() {
            assert!(Packet::parse(&s).is_ok());
            for n in 0..s.len() {
                assert_eq!(Packet::parse(&s[..n]), Err(Error::Truncated), "{n} of {}", s.len());
            }
        }
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        let name = Name { bytes: Name::new("A", 0).bytes, scope: vec![vec![b'x'; 100]; 10] };
        assert_eq!(name.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&name);
        let mut p = sample_datagram();
        if let Body::Datagram(d) = &mut p.body {
            d.data = vec![7; 70_000];
        }
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&p);
        let n = Name { bytes: [b'A'; 16], scope: vec![vec![], b"x".to_vec()] };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&n);
    }

    #[test]
    fn name_writer_refuses_each_limit_on_its_own() {
        // One label a byte past MAX_LABEL, in a short name.
        let wide = Name { bytes: [b'A'; 16], scope: vec![vec![b'x'; MAX_LABEL + 1]] };
        assert_eq!(wide.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&wide);
        // Five legal labels that make a 354-byte name.
        let long = Name { bytes: [b'A'; 16], scope: vec![vec![b'x'; MAX_LABEL]; 5] };
        assert_eq!(long.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&long);
        // A name of exactly MAX_NAME_LEN bytes is written and reads back.
        let mut scope = vec![vec![b'x'; MAX_LABEL]; 3];
        scope.push(vec![b'y'; 28]);
        let full = Name { bytes: [b'A'; 16], scope };
        let wire = full.to_bytes().unwrap();
        assert_eq!(wire.len(), MAX_NAME_LEN);
        assert_eq!(Name::parse(&wire), Ok(full.clone()));
        contract::check_wire_value(&full);
        // One more byte in the last label passes it.
        let mut over = full;
        over.scope[3].push(b'y');
        assert_eq!(over.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&over);
    }

    #[test]
    fn split_and_reassemble() {
        let mut p = sample_datagram();
        if let Body::Datagram(d) = &mut p.body {
            d.data = (0..1000u32).map(|i| i as u8).collect();
        }
        let parts = p.split(300).unwrap();
        assert_eq!(parts.len(), 4);
        assert!(parts[0].flags.first && parts[0].flags.more);
        assert!(!parts[3].flags.first && !parts[3].flags.more);
        let offsets: Vec<u16> =
            parts.iter().map(|f| if let Body::Datagram(d) = &f.body { d.offset } else { 0 }).collect();
        assert_eq!(offsets, [0, 300, 600, 900]);
        let mut r = Reassembler::new();
        // Each fragment goes through the wire, one at a time.
        let mut got = None;
        for f in &parts {
            assert!(got.is_none());
            got = r.push(Packet::parse(&f.to_bytes().unwrap()).unwrap());
        }
        assert_eq!(got, Some(p.clone()));
        assert_eq!(r.pending(), 0);
        // A whole datagram comes straight back; others are ignored.
        assert_eq!(r.push(sample_datagram()), Some(sample_datagram()));
        assert_eq!(r.push(sample_datagram().error(ip(), 1, ErrorCode::InvalidSourceName)), None);
        // Out of order drops it.
        assert_eq!(r.push(parts[0].clone()), None);
        assert_eq!(r.push(parts[2].clone()), None);
        assert_eq!(r.pending(), 0);
        assert_eq!(r.push(parts[3].clone()), None);
        // A first fragment with a nonzero offset is dropped.
        let mut odd = parts[1].clone();
        odd.flags.first = true;
        assert_eq!(r.push(odd), None);
        assert_eq!(r.pending(), 0);
        // A different destination drops it.
        r.push(parts[0].clone());
        let mut other = parts[1].clone();
        if let Body::Datagram(d) = &mut other.body {
            d.destination = Name::new("ELSE", 0);
        }
        assert_eq!(r.push(other), None);
        assert_eq!(r.pending(), 0);
        // Never more than MAX_PENDING at once.
        for id in 0..100u16 {
            let mut f = parts[0].clone();
            f.id = id;
            r.push(f);
            assert!(r.pending() <= MAX_PENDING);
        }
        assert_eq!(r.pending(), MAX_PENDING);
        // Small data, and non-datagrams, stay whole.
        assert_eq!(sample_datagram().split(1000).unwrap(), vec![sample_datagram()]);
        let e = sample_datagram().error(ip(), 1, ErrorCode::Other(1));
        assert_eq!(e.split(1).unwrap(), vec![e.clone()]);
        // Too long a whole is dropped.
        let mut big = parts[0].clone();
        big.id = 999;
        r.push(big.clone());
        let mut next = parts[1].clone();
        next.id = 999;
        if let Body::Datagram(d) = &mut next.body {
            d.data = vec![0; MAX_REASSEMBLED];
        }
        assert_eq!(r.push(next), None);
    }

    #[test]
    fn split_large_is_linear() {
        // The largest datagram cut into one-byte fragments: each fragment
        // copies only its own byte, so this stays fast.
        let mut p = sample_datagram();
        if let Body::Datagram(d) = &mut p.body {
            d.data = (0..MAX_REASSEMBLED).map(|i| i as u8).collect();
        }
        let parts = p.split(1).unwrap();
        assert_eq!(parts.len(), MAX_REASSEMBLED);
        let mut r = Reassembler::new();
        let mut got = None;
        for f in parts {
            got = r.push(f);
        }
        let Some(Packet { body: Body::Datagram(whole), .. }) = got else { panic!("not reassembled") };
        assert_eq!(whole.data.len(), MAX_REASSEMBLED);
        assert!(whole.data.iter().enumerate().all(|(i, &b)| b == i as u8));
        assert!(p.as_datagram().is_some());
        assert!(sample_datagram().error(ip(), 1, ErrorCode::Other(1)).as_datagram().is_none());
        if let Body::Datagram(d) = &mut p.body { d.data.push(0); }
        assert_eq!(p.split(1), Err(Error::Unwritable));
    }

    fn check(data: &[u8], r: &mut Reassembler) {
        contract::check_wire::<Name>(data);
        contract::check_wire::<Packet>(data);

        if let Ok(p) = Packet::parse(data) {
            let bytes = p.to_bytes().unwrap();
            let back = Packet::parse(&bytes).unwrap();
            assert_eq!(back, p);
            assert_eq!(back.to_bytes().unwrap(), bytes);
            for f in p.split(3).unwrap() {
                assert_eq!(Packet::parse(&f.to_bytes().unwrap()).unwrap(), f);
            }
            if let Some(q) = p.query_response(ip(), 138, true) {
                assert_eq!(Packet::parse(&q.to_bytes().unwrap()), Ok(q));
            }
            if let Some(whole) = r.push(p) {
                assert!(whole.flags.first && !whole.flags.more);
            }
            assert!(r.pending() <= MAX_PENDING);
        }
    }

    #[test]
    fn random_buffers() {
        let mut rng = Lcg::new(0x6e62_6467);
        let seeds = samples();
        let mut r = Reassembler::new();
        for round in 0..6000 {
            let mut buf = if round % 3 == 0 {
                let len = rng.index(120);
                let mut b = vec![0; len];
                rng.fill(&mut b);
                if let Some(t) = b.first_mut() {
                    *t = 0x10 + rng.index(8) as u8;
                }
                b
            } else {
                seeds[rng.index(seeds.len())].clone()
            };
            for _ in 0..rng.index(4) {
                mutate(&mut rng, &mut buf);
                let at = rng.index(buf.len());
                if let Some(byte) = buf.get_mut(at) {
                    *byte = match rng.index(4) {
                        0 => 0xc0,
                        1 => b'A' + rng.index(16) as u8,
                        2 => rng.index(64) as u8,
                        _ => b'Q',
                    };
                }
            }
            check(&buf, &mut r);
            // The datagram, one byte more at a time: every prefix is read
            // or refused, and never panics.
            for n in 0..buf.len() {
                check(&buf[..n], &mut r);
            }
        }
    }

    #[test]
    fn random_fragments() {
        // Fragments of a few datagrams, shuffled and sometimes lost, passed
        // one at a time: whatever comes out is a datagram that went in.
        let mut rng = Lcg::new(42);
        for _ in 0..500 {
            let mut r = Reassembler::new();
            let mut sent = Vec::new();
            let mut stream = Vec::new();
            for id in 0..(1 + rng.index(4)) as u16 {
                let mut p = sample_datagram();
                p.id = id;
                if let Body::Datagram(d) = &mut p.body {
                    d.data = rng.bytes(49);
                }
                stream.extend(p.split(1 + rng.index(10)).unwrap());
                sent.push(p);
            }
            for i in (1..stream.len()).rev() {
                if rng.index(4) == 0 {
                    let j = rng.index(i + 1);
                    stream.swap(i, j);
                }
            }
            for f in stream {
                if rng.index(10) == 0 {
                    continue;
                }
                if let Some(whole) = r.push(f) {
                    assert!(sent.contains(&whole));
                }
            }
        }
    }
}
