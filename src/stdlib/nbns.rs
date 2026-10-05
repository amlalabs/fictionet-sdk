//! NetBIOS Name Service: reading and answering name queries,
//! registrations and node status requests, with no I/O.
//!
//! On a Windows network, machines find each other by NetBIOS name as well
//! as by DNS. A machine that wants `FILES` broadcasts a name query to UDP
//! port 137, and whoever owns the name answers with its address. Machines
//! register their names the same way, and anyone can ask a machine for the
//! list of names it holds (a node status request). This module follows
//! RFC 1001 and RFC 1002.
//!
//! A NetBIOS name is 16 bytes: up to 15 characters, padded with spaces,
//! and a suffix byte that says what the name is for (`0x20` for a file
//! server, `0x00` for a workstation). On the wire each byte becomes two
//! letters from `A` to `P`, one per half byte. RFC 1001 calls this the
//! first-level encoding; see [`encode_first_level`]. The 32 letters are the
//! first label of a DNS-style name, and an optional scope follows it as
//! more labels. Packets are laid out like DNS messages, and may point back
//! to a name written earlier in the packet instead of repeating it.
//!
//! Nothing here reads a socket. A world that plays the machines on a LAN
//! reads each datagram from its UDP socket, passes it to
//! [`Packet::parse`], reads what it asks with [`Packet::request`], and
//! builds the answer with a method such as [`Packet::query_response`].
//! Which names exist, and who owns them, is up to world code. NBNS runs
//! over UDP, one packet per datagram, so there is no stream decoder.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Writers cut what does not fit, so their bytes always read back.
//!
//! ```
//! use fictionet::stdlib::nbns::{Name, NbEntry, NodeType, Packet, RData, Request};
//! use std::net::Ipv4Addr;
//!
//! // The agent's machine broadcasts a query for the file server FILES.
//! let query = Packet::name_query(0x1234, Name::new("files", 0x20), true);
//! let bytes = query.to_bytes();
//! assert_eq!(bytes.len(), 50);
//! assert_eq!(bytes[..4], [0x12, 0x34, 0x01, 0x10]);
//! // The first-level encoding: F (0x46) becomes "EG", and I (0x49) "EJ".
//! assert_eq!(&bytes[12..17], b"\x20EGEJ");
//!
//! // The world owns FILES at 10.0.0.5. Other names get no answer, as on a
//! // real LAN, where only the owner of a name answers a broadcast.
//! let owner = NbEntry { group: false, node_type: NodeType::B, address: Ipv4Addr::new(10, 0, 0, 5) };
//! let asked = Packet::parse(&bytes).unwrap();
//! let reply = match asked.request() {
//!     Ok(Request::NameQuery { name }) if name == Name::new("FILES", 0x20) => {
//!         Some(asked.query_response(name, 300_000, vec![owner]))
//!     }
//!     _ => None,
//! };
//!
//! let answer = Packet::parse(&reply.unwrap().to_bytes()).unwrap();
//! assert!(answer.response);
//! assert_eq!(answer.id, 0x1234);
//! assert_eq!(answer.answers[0].data, RData::Nb(vec![owner]));
//! ```

use std::net::Ipv4Addr;

/// The UDP port the name service listens on.
pub const PORT: u16 = 137;
/// The length of the header every packet starts with.
pub const HEADER_LEN: usize = 12;
/// The longest datagram this module reads or writes: the most bytes one
/// UDP datagram over IPv4 can carry. Most packets are under 100 bytes. A
/// longer datagram is refused.
pub const MAX_PACKET: usize = 65_507;
/// The most entries one section of a packet may hold here. Real packets
/// hold one or none. A packet whose header counts more is refused, and a
/// writer leaves out the rest.
pub const MAX_RECORDS: usize = 64;
/// The length of a NetBIOS name: 15 characters and a suffix byte.
pub const NAME_LEN: usize = 16;
/// The length of a NetBIOS name in the first-level encoding.
pub const ENCODED_LEN: usize = 2 * NAME_LEN;
/// The longest label in a name's scope.
pub const MAX_LABEL: usize = 63;
/// The longest name on the wire: every label with its length byte, and
/// the zero byte that ends the name.
pub const MAX_NAME_LEN: usize = 255;
/// The most pointers one name may follow before it ends.
pub const MAX_POINTERS: usize = 16;
/// The most bytes of data one record may carry: what its 16-bit length
/// field can count.
pub const MAX_RDATA: usize = 65_535;
/// The most addresses one NB record may carry.
pub const MAX_NB_ENTRIES: usize = MAX_RDATA / NB_ENTRY_LEN;
/// The length of one address in an NB record: flags and an IPv4 address.
pub const NB_ENTRY_LEN: usize = 6;
/// The most names one node status response may list: its count is a byte.
pub const MAX_NODE_NAMES: usize = 255;
/// The length of one name in a node status response: the 16-byte name
/// and its flags.
pub const NODE_NAME_LEN: usize = NAME_LEN + 2;
/// The length of the statistics block RFC 1002 puts after the names in a
/// node status response.
pub const STATISTICS_LEN: usize = 46;

/// Record and question types this module reads.
pub mod rr_type {
    /// An IPv4 address, in a redirect response.
    pub const A: u16 = 0x0001;
    /// A name server, in a redirect response.
    pub const NS: u16 = 0x0002;
    /// No data, in a negative query response.
    pub const NULL: u16 = 0x000a;
    /// A NetBIOS name and the addresses that own it.
    pub const NB: u16 = 0x0020;
    /// The names a node holds, for a node status request.
    pub const NBSTAT: u16 = 0x0021;
}

/// The Internet class, the only class NBNS uses.
pub const CLASS_IN: u16 = 0x0001;

/// Result codes a response carries.
pub mod rcode {
    /// The request worked.
    pub const OK: u8 = 0x0;
    /// The request was badly formed.
    pub const FMT_ERR: u8 = 0x1;
    /// The server failed.
    pub const SRV_ERR: u8 = 0x2;
    /// The name does not exist.
    pub const NAM_ERR: u8 = 0x3;
    /// The request is not supported.
    pub const IMP_ERR: u8 = 0x4;
    /// The server will not register this name for this host.
    pub const RFS_ERR: u8 = 0x5;
    /// Another node owns the name.
    pub const ACT_ERR: u8 = 0x6;
    /// The name is in conflict.
    pub const CFT_ERR: u8 = 0x7;
}

/// The bits of a name's flags in a node status response.
pub mod name_flags {
    /// The name is a group name, not a unique one.
    pub const GROUP: u16 = 0x8000;
    /// The two bits of the owner's node type, read as a `NodeType`.
    pub const NODE_TYPE: u16 = 0x6000;
    /// The name is being deleted.
    pub const DEREGISTER: u16 = 0x1000;
    /// The name is in conflict.
    pub const CONFLICT: u16 = 0x0800;
    /// The name is active. Every listed name has this set.
    pub const ACTIVE: u16 = 0x0400;
    /// The name is the node's permanent name.
    pub const PERMANENT: u16 = 0x0200;
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
    /// none. A writer leaves out empty labels, cuts labels to
    /// [`MAX_LABEL`] bytes, and stops adding labels once the name would
    /// pass [`MAX_NAME_LEN`].
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

    /// The name `*` followed by zero bytes, which node status requests
    /// ask about to mean "whoever you are".
    pub fn wildcard() -> Name {
        let mut bytes = [0u8; NAME_LEN];
        bytes[0] = b'*';
        Name { bytes, scope: Vec::new() }
    }

    /// This name with the scope `scope`, given with dots between labels.
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

    /// The name on the wire: the first-level label, the scope's labels,
    /// and a zero byte. It is never longer than [`MAX_NAME_LEN`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_LEN + 2);
        out.push(ENCODED_LEN as u8);
        out.extend_from_slice(&encode_first_level(&self.bytes));
        for label in &self.scope {
            let label = &label[..label.len().min(MAX_LABEL)];
            if label.is_empty() {
                continue;
            }
            // The label, its length byte, and the final zero must fit.
            if out.len() + 1 + label.len() + 1 > MAX_NAME_LEN {
                break;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out
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

/// What a packet does: the header's opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// 0: a name query or node status request.
    Query,
    /// 5: register a name.
    Registration,
    /// 6: release a name.
    Release,
    /// 7: wait for acknowledgement; a server needs more time.
    Wack,
    /// 8: refresh a registered name.
    Refresh,
    /// Any other opcode. Built with a value listed above, it reads back
    /// as that variant. 9 is also a refresh: RFC 1002 lists refresh as
    /// 8 but draws the refresh request with 9, and Windows sends 9.
    /// [`Packet::request`] reads both as [`Request::Refresh`]. 15 is a
    /// multi-homed registration, which this module does not answer.
    Other(u8),
}

impl Opcode {
    /// The opcode for the 4-bit value `v`. Only the low 4 bits are read.
    pub fn from_bits(v: u8) -> Opcode {
        match v & 0x0f {
            0 => Opcode::Query,
            5 => Opcode::Registration,
            6 => Opcode::Release,
            7 => Opcode::Wack,
            8 => Opcode::Refresh,
            v => Opcode::Other(v),
        }
    }

    /// The opcode's 4-bit value. Only the low 4 bits of
    /// [`Opcode::Other`] are kept.
    pub fn bits(self) -> u8 {
        match self {
            Opcode::Query => 0,
            Opcode::Registration => 5,
            Opcode::Release => 6,
            Opcode::Wack => 7,
            Opcode::Refresh => 8,
            Opcode::Other(v) => v & 0x0f,
        }
    }
}

/// The header's flags. The two reserved bits are not kept, and are
/// written as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Flags {
    /// AA: the responder owns the name or is the name server for it.
    pub authoritative: bool,
    /// TC: the packet was cut to fit a datagram.
    pub truncated: bool,
    /// RD: the requester wants a name server to do the work for it.
    pub recursion_desired: bool,
    /// RA: the name server can do the work for the requester.
    pub recursion_available: bool,
    /// B: the packet was broadcast.
    pub broadcast: bool,
}

impl Flags {
    fn from_bits(v: u16) -> Flags {
        Flags {
            authoritative: v & 0x40 != 0,
            truncated: v & 0x20 != 0,
            recursion_desired: v & 0x10 != 0,
            recursion_available: v & 0x08 != 0,
            broadcast: v & 0x01 != 0,
        }
    }

    fn bits(self) -> u16 {
        u16::from(self.authoritative) << 6
            | u16::from(self.truncated) << 5
            | u16::from(self.recursion_desired) << 4
            | u16::from(self.recursion_available) << 3
            | u16::from(self.broadcast)
    }
}

/// How a node finds names: the two-bit owner node type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeType {
    /// B node: by broadcast.
    B,
    /// P node: by asking a name server.
    P,
    /// M node: broadcast first, then a name server.
    M,
    /// H node: a name server first, then broadcast. RFC 1002 reserves
    /// this value. Windows uses it for H nodes.
    H,
}

impl NodeType {
    /// The node type for the two bits `v`. Only the low 2 bits are read.
    pub fn from_bits(v: u16) -> NodeType {
        match v & 3 {
            0 => NodeType::B,
            1 => NodeType::P,
            2 => NodeType::M,
            _ => NodeType::H,
        }
    }

    /// The node type's two bits.
    pub fn bits(self) -> u16 {
        match self {
            NodeType::B => 0,
            NodeType::P => 1,
            NodeType::M => 2,
            NodeType::H => 3,
        }
    }
}

/// One owner of a name in an NB record: who holds it, and at what
/// address. The flags' reserved bits are not kept, and are written as
/// zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NbEntry {
    /// The name is a group name, which many nodes can hold.
    pub group: bool,
    /// The owner's node type.
    pub node_type: NodeType,
    /// The owner's IPv4 address.
    pub address: Ipv4Addr,
}

impl NbEntry {
    fn parse(b: &[u8]) -> NbEntry {
        let flags = be16(b, 0);
        NbEntry {
            group: flags & 0x8000 != 0,
            node_type: NodeType::from_bits(flags >> 13),
            address: Ipv4Addr::new(b[2], b[3], b[4], b[5]),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        let flags = u16::from(self.group) << 15 | self.node_type.bits() << 13;
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&self.address.octets());
    }
}

/// One name in a node status response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeName {
    /// The 16-byte name, as in [`Name::bytes`]. It is not encoded, and
    /// carries no scope.
    pub bytes: [u8; NAME_LEN],
    /// The name's flags; see [`name_flags`].
    pub flags: u16,
}

impl NodeName {
    /// An active unique name owned by a B node.
    pub fn unique(name: &Name) -> NodeName {
        NodeName { bytes: name.bytes, flags: name_flags::ACTIVE }
    }

    /// An active group name owned by a B node.
    pub fn group(name: &Name) -> NodeName {
        NodeName { bytes: name.bytes, flags: name_flags::ACTIVE | name_flags::GROUP }
    }
}

/// The data of an NBSTAT record: the names a node holds, and its
/// statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NodeStatus {
    /// The names. A writer lists at most [`MAX_NODE_NAMES`].
    pub names: Vec<NodeName>,
    /// The statistics block, unread. RFC 1002 makes it
    /// [`STATISTICS_LEN`] bytes, starting with the node's 6-byte unit ID
    /// (its MAC address). Some senders write fewer or more. A writer cuts
    /// it so the record stays under [`MAX_RDATA`].
    pub statistics: Vec<u8>,
}

impl NodeStatus {
    /// The unit ID at the start of the statistics, if they hold one.
    pub fn unit_id(&self) -> Option<[u8; 6]> {
        self.statistics.get(..6)?.try_into().ok()
    }
}

/// A record's data, read by its type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RData {
    /// Type NB with a length that is a multiple of 6: the name's owners.
    /// A writer writes at most [`MAX_NB_ENTRIES`].
    Nb(Vec<NbEntry>),
    /// Type NBSTAT whose names fit its length: a node's names.
    NodeStatus(NodeStatus),
    /// Any other type, or an NB or NBSTAT record whose data does not
    /// read as one (such as the 2 bytes of a WACK), unread. Names inside
    /// it are not followed. A writer cuts it to [`MAX_RDATA`] bytes. If a
    /// world builds one of type NB or NBSTAT whose data does read as one,
    /// it reads back as [`RData::Nb`] or [`RData::NodeStatus`].
    Other {
        /// The record type; see [`rr_type`].
        rr_type: u16,
        /// The data.
        data: Vec<u8>,
    },
}

impl RData {
    /// The record type this data is written with.
    pub fn rr_type(&self) -> u16 {
        match self {
            RData::Nb(_) => rr_type::NB,
            RData::NodeStatus(_) => rr_type::NBSTAT,
            RData::Other { rr_type, .. } => *rr_type,
        }
    }

    fn parse(rr: u16, data: &[u8]) -> RData {
        if rr == rr_type::NB && data.len().is_multiple_of(NB_ENTRY_LEN) {
            return RData::Nb(data.chunks_exact(NB_ENTRY_LEN).map(NbEntry::parse).collect());
        }
        if rr == rr_type::NBSTAT
            && let Some((&n, rest)) = data.split_first()
            && let Some(names) = rest.get(..usize::from(n) * NODE_NAME_LEN)
        {
            let names = names
                .chunks_exact(NODE_NAME_LEN)
                .map(|c| {
                    let mut bytes = [0u8; NAME_LEN];
                    bytes.copy_from_slice(&c[..NAME_LEN]);
                    NodeName { bytes, flags: be16(c, NAME_LEN) }
                })
                .collect();
            let statistics = rest[usize::from(n) * NODE_NAME_LEN..].to_vec();
            return RData::NodeStatus(NodeStatus { names, statistics });
        }
        RData::Other { rr_type: rr, data: data.to_vec() }
    }

    /// The data's bytes, never longer than [`MAX_RDATA`].
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            RData::Nb(entries) => {
                for e in entries.iter().take(MAX_NB_ENTRIES) {
                    e.write(&mut out);
                }
            }
            RData::NodeStatus(s) => {
                let names = &s.names[..s.names.len().min(MAX_NODE_NAMES)];
                out.push(names.len() as u8);
                for n in names {
                    out.extend_from_slice(&n.bytes);
                    out.extend_from_slice(&n.flags.to_be_bytes());
                }
                let room = MAX_RDATA - out.len();
                out.extend_from_slice(&s.statistics[..s.statistics.len().min(room)]);
            }
            RData::Other { data, .. } => out.extend_from_slice(&data[..data.len().min(MAX_RDATA)]),
        }
        out
    }
}

/// One entry of the question section.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name asked about.
    pub name: Name,
    /// [`rr_type::NB`] for a name query or registration,
    /// [`rr_type::NBSTAT`] for a node status request.
    pub qtype: u16,
    /// The class: [`CLASS_IN`].
    pub class: u16,
}

/// One resource record, in the answer, authority or additional section.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record {
    /// The name the record is about.
    pub name: Name,
    /// The class: [`CLASS_IN`].
    pub class: u16,
    /// How long, in seconds, the name holds.
    pub ttl: u32,
    /// The data, which also gives the record's type.
    pub data: RData,
}

impl Record {
    /// Writes the record at the start of `out`, pointing to a name in
    /// `written` when it can. It returns the name's bytes if it wrote the
    /// name in full.
    fn write(&self, out: &mut Vec<u8>, written: &[(Vec<u8>, u16)]) -> Option<Vec<u8>> {
        let full = put_name(out, &self.name, written);
        out.extend_from_slice(&self.data.rr_type().to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let data = self.data.to_bytes();
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        full
    }
}

/// Writes `name` to `out`, the bytes of an entry that starts at the
/// beginning of `out`. A name written in full earlier, as listed in
/// `written`, becomes a two-byte pointer to it. It returns the name's
/// bytes if it wrote the name in full.
fn put_name(out: &mut Vec<u8>, name: &Name, written: &[(Vec<u8>, u16)]) -> Option<Vec<u8>> {
    let wire = name.to_bytes();
    if let Some((_, at)) = written.iter().find(|(w, _)| *w == wire) {
        out.extend_from_slice(&(0xc000 | at).to_be_bytes());
        return None;
    }
    out.extend_from_slice(&wire);
    Some(wire)
}

/// Notes that the name `full` was written in full at offset `at`, if a
/// pointer can reach it: pointers hold 14 bits.
fn remember(written: &mut Vec<(Vec<u8>, u16)>, full: Option<Vec<u8>>, at: usize) {
    if let (Some(wire), Ok(at)) = (full, u16::try_from(at))
        && at <= 0x3fff
    {
        written.push((wire, at));
    }
}

/// Why a datagram is not an NBNS packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The packet ends before its header, a name or a record does.
    Truncated,
    /// The datagram is longer than [`MAX_PACKET`].
    TooLong(usize),
    /// A section counts more entries than [`MAX_RECORDS`].
    TooManyRecords(u16),
    /// A label's length byte starts with the bits 01 or 10, which mark
    /// neither a label nor a pointer.
    BadLabel(u8),
    /// A pointer does not point back to an earlier byte, or a name
    /// follows more than [`MAX_POINTERS`] of them. The value is the
    /// pointer's offset.
    BadPointer(u16),
    /// A name's first label is not 32 letters from `A` to `P`, or the
    /// name is empty.
    BadFirstLevel,
    /// A name is longer than [`MAX_NAME_LEN`].
    NameTooLong,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated => f.write_str("packet ends early"),
            ParseError::TooLong(n) => write!(f, "datagram of {n} bytes, over {MAX_PACKET}"),
            ParseError::TooManyRecords(n) => write!(f, "section of {n} entries, over {MAX_RECORDS}"),
            ParseError::BadLabel(b) => write!(f, "label length byte {b:#04x}"),
            ParseError::BadPointer(p) => write!(f, "pointer to offset {p} goes forward or loops"),
            ParseError::BadFirstLevel => f.write_str("first label is not a first-level encoded name"),
            ParseError::NameTooLong => write!(f, "name longer than {MAX_NAME_LEN} bytes"),
        }
    }
}

impl std::error::Error for ParseError {}

/// One NBNS packet.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Packet {
    /// The transaction ID, chosen by the requester and copied into the
    /// response.
    pub id: u16,
    /// Whether this is a response, not a request.
    pub response: bool,
    /// What the packet does.
    pub opcode: Opcode,
    /// The header's flags.
    pub flags: Flags,
    /// The result code; see [`rcode`]. Only the low 4 bits are written.
    pub rcode: u8,
    /// The question section. A writer writes at most [`MAX_RECORDS`] of
    /// each section, and stops a section early if the packet would pass
    /// [`MAX_PACKET`].
    pub questions: Vec<Question>,
    /// The answer section.
    pub answers: Vec<Record>,
    /// The authority section.
    pub authority: Vec<Record>,
    /// The additional section.
    pub additional: Vec<Record>,
}

/// What a request asks, read by [`Packet::request`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Request {
    /// Who owns `name`, and at what address?
    NameQuery {
        /// The name asked about.
        name: Name,
    },
    /// Which names does the node holding `name` have? The name is often
    /// [`Name::wildcard`].
    NodeStatus {
        /// The name asked about.
        name: Name,
    },
    /// Register `name` for the owner in `entry`, for `ttl` seconds.
    Registration {
        /// The name to register.
        name: Name,
        /// How long the registration should last, in seconds.
        ttl: u32,
        /// The node claiming it.
        entry: NbEntry,
    },
    /// Refresh the registration of `name` for `ttl` seconds more. The
    /// opcode is 8 or 9. The answer is a registration response.
    Refresh {
        /// The name to refresh.
        name: Name,
        /// How long the registration should last, in seconds.
        ttl: u32,
        /// The node that holds it.
        entry: NbEntry,
    },
    /// Release `name`: the node in `entry` gives it up.
    Release {
        /// The name to release.
        name: Name,
        /// The node giving it up.
        entry: NbEntry,
    },
}

/// Why a packet is not a request [`Packet::request`] can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// The packet is a response. A server does not answer it.
    NotRequest,
    /// The packet lacks one question of the right type and class
    /// [`CLASS_IN`], or a registration, refresh or release lacks the NB
    /// record that says who asks. A server may answer
    /// [`rcode::FMT_ERR`].
    Malformed,
    /// The opcode is not one this module answers. A server may answer
    /// [`rcode::IMP_ERR`].
    Unsupported(Opcode),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::NotRequest => f.write_str("packet is a response"),
            RequestError::Malformed => f.write_str("request lacks its question or NB record"),
            RequestError::Unsupported(o) => write!(f, "opcode {} is not supported", o.bits()),
        }
    }
}

impl std::error::Error for RequestError {}

impl Request {
    /// The name the request is about: the question's name.
    pub fn name(&self) -> &Name {
        match self {
            Request::NameQuery { name }
            | Request::NodeStatus { name }
            | Request::Registration { name, .. }
            | Request::Refresh { name, .. }
            | Request::Release { name, .. } => name,
        }
    }
}

impl Packet {
    /// Reads one datagram. Bytes after the last record are ignored, as
    /// real stacks do.
    pub fn parse(b: &[u8]) -> Result<Packet, ParseError> {
        if b.len() > MAX_PACKET {
            return Err(ParseError::TooLong(b.len()));
        }
        if b.len() < HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let word = be16(b, 2);
        let mut counts = [0usize; 4];
        for (i, c) in counts.iter_mut().enumerate() {
            let n = be16(b, 4 + 2 * i);
            if usize::from(n) > MAX_RECORDS {
                return Err(ParseError::TooManyRecords(n));
            }
            *c = usize::from(n);
        }
        let mut pos = HEADER_LEN;
        let mut questions = Vec::with_capacity(counts[0]);
        for _ in 0..counts[0] {
            let (name, next) = read_name(b, pos)?;
            let fixed = b.get(next..next + 4).ok_or(ParseError::Truncated)?;
            questions.push(Question { name, qtype: be16(fixed, 0), class: be16(fixed, 2) });
            pos = next + 4;
        }
        let mut sections: [Vec<Record>; 3] = Default::default();
        for (section, &count) in sections.iter_mut().zip(&counts[1..]) {
            section.reserve(count);
            for _ in 0..count {
                let (name, next) = read_name(b, pos)?;
                let fixed = b.get(next..next + 10).ok_or(ParseError::Truncated)?;
                let len = usize::from(be16(fixed, 8));
                let start = next + 10;
                let data = b.get(start..start + len).ok_or(ParseError::Truncated)?;
                section.push(Record {
                    name,
                    class: be16(fixed, 2),
                    ttl: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
                    data: RData::parse(be16(fixed, 0), data),
                });
                pos = start + len;
            }
        }
        let [answers, authority, additional] = sections;
        Ok(Packet {
            id: be16(b, 0),
            response: word & 0x8000 != 0,
            opcode: Opcode::from_bits((word >> 11) as u8),
            flags: Flags::from_bits(word >> 4),
            rcode: (word & 0x0f) as u8,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// The packet's bytes. A name already written in full earlier in the
    /// packet is written as a pointer to it. RFC 1002 asks for this in
    /// registrations and releases, whose record repeats the question's
    /// name. The result is never longer than [`MAX_PACKET`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.header_word().to_be_bytes());
        out.extend_from_slice(&[0; 8]);
        let mut counts = [0u16; 4];
        // Each name written in full so far, and its offset. It holds at
        // most one per entry written, so 4 * MAX_RECORDS.
        let mut written: Vec<(Vec<u8>, u16)> = Vec::new();
        let mut entry = Vec::new();
        for q in self.questions.iter().take(MAX_RECORDS) {
            entry.clear();
            let full = put_name(&mut entry, &q.name, &written);
            entry.extend_from_slice(&q.qtype.to_be_bytes());
            entry.extend_from_slice(&q.class.to_be_bytes());
            if out.len() + entry.len() > MAX_PACKET {
                break;
            }
            remember(&mut written, full, out.len());
            out.extend_from_slice(&entry);
            counts[0] += 1;
        }
        for (i, section) in [&self.answers, &self.authority, &self.additional].into_iter().enumerate() {
            for r in section.iter().take(MAX_RECORDS) {
                entry.clear();
                let full = r.write(&mut entry, &written);
                if out.len() + entry.len() > MAX_PACKET {
                    break;
                }
                remember(&mut written, full, out.len());
                out.extend_from_slice(&entry);
                counts[i + 1] += 1;
            }
        }
        for (i, c) in counts.iter().enumerate() {
            out[4 + 2 * i..6 + 2 * i].copy_from_slice(&c.to_be_bytes());
        }
        out
    }

    /// The header's second 16 bits: the response bit, opcode, flags and
    /// result code.
    fn header_word(&self) -> u16 {
        u16::from(self.response) << 15
            | u16::from(self.opcode.bits()) << 11
            | self.flags.bits() << 4
            | u16::from(self.rcode & 0x0f)
    }

    /// What this packet asks, for a world that answers requests.
    pub fn request(&self) -> Result<Request, RequestError> {
        if self.response {
            return Err(RequestError::NotRequest);
        }
        let [q] = &self.questions[..] else { return Err(RequestError::Malformed) };
        if q.class != CLASS_IN {
            return Err(RequestError::Malformed);
        }
        let name = q.name.clone();
        let nb = || {
            if q.qtype != rr_type::NB {
                return Err(RequestError::Malformed);
            }
            self.additional
                .iter()
                .find_map(|r| match &r.data {
                    RData::Nb(e) => e.first().map(|e| (r.ttl, *e)),
                    _ => None,
                })
                .ok_or(RequestError::Malformed)
        };
        match self.opcode {
            Opcode::Query => match q.qtype {
                rr_type::NB => Ok(Request::NameQuery { name }),
                rr_type::NBSTAT => Ok(Request::NodeStatus { name }),
                _ => Err(RequestError::Malformed),
            },
            Opcode::Registration => nb().map(|(ttl, entry)| Request::Registration { name, ttl, entry }),
            Opcode::Refresh | Opcode::Other(9) => nb().map(|(ttl, entry)| Request::Refresh { name, ttl, entry }),
            Opcode::Release => nb().map(|(_, entry)| Request::Release { name, entry }),
            other => Err(RequestError::Unsupported(other)),
        }
    }

    /// A request with one question and nothing else.
    fn asking(id: u16, opcode: Opcode, flags: Flags, name: Name, qtype: u16) -> Packet {
        Packet {
            id,
            response: false,
            opcode,
            flags,
            rcode: rcode::OK,
            questions: vec![Question { name, qtype, class: CLASS_IN }],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// A name query for `name`, as RFC 1002 section 4.2.12 lays it out.
    /// It asks a name server to do the work (RD), and is marked broadcast
    /// if `broadcast` is set.
    pub fn name_query(id: u16, name: Name, broadcast: bool) -> Packet {
        let flags = Flags { recursion_desired: true, broadcast, ..Flags::default() };
        Packet::asking(id, Opcode::Query, flags, name, rr_type::NB)
    }

    /// A node status request about `name`, sent straight to one node.
    pub fn node_status_query(id: u16, name: Name) -> Packet {
        Packet::asking(id, Opcode::Query, Flags::default(), name, rr_type::NBSTAT)
    }

    /// A request to register `name` for `entry`, for `ttl` seconds: the
    /// question, and an NB record in the additional section.
    pub fn registration(id: u16, name: Name, ttl: u32, entry: NbEntry, broadcast: bool) -> Packet {
        let flags = Flags { recursion_desired: true, broadcast, ..Flags::default() };
        let mut p = Packet::asking(id, Opcode::Registration, flags, name.clone(), rr_type::NB);
        p.additional.push(Record { name, class: CLASS_IN, ttl, data: RData::Nb(vec![entry]) });
        p
    }

    /// A request to release `name`, held by `entry`.
    pub fn release(id: u16, name: Name, entry: NbEntry, broadcast: bool) -> Packet {
        let flags = Flags { broadcast, ..Flags::default() };
        let mut p = Packet::asking(id, Opcode::Release, flags, name.clone(), rr_type::NB);
        p.additional.push(Record { name, class: CLASS_IN, ttl: 0, data: RData::Nb(vec![entry]) });
        p
    }

    /// A response to this request with one answer record: the same ID,
    /// the response bit, AA and RD set, and the opcode and result code
    /// given. A world can change any field before writing it.
    fn reply(&self, opcode: Opcode, code: u8, record: Record) -> Packet {
        Packet {
            id: self.id,
            response: true,
            opcode,
            flags: Flags { authoritative: true, recursion_desired: true, ..Flags::default() },
            rcode: code,
            questions: Vec::new(),
            answers: vec![record],
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// The positive answer to a name query: `name` is held by `owners`
    /// for `ttl` seconds. AA and RD are set, whatever the query had
    /// (RFC 1002 section 4.2.13).
    pub fn query_response(&self, name: Name, ttl: u32, owners: Vec<NbEntry>) -> Packet {
        let record = Record { name, class: CLASS_IN, ttl, data: RData::Nb(owners) };
        self.reply(Opcode::Query, rcode::OK, record)
    }

    /// The negative answer to a name query, with result code `code`,
    /// usually [`rcode::NAM_ERR`]. AA and RD are set (RFC 1002 section
    /// 4.2.14). An end node sends none for a broadcast query. It stays
    /// silent.
    pub fn negative_query_response(&self, name: Name, code: u8) -> Packet {
        let record =
            Record { name, class: CLASS_IN, ttl: 0, data: RData::Other { rr_type: rr_type::NULL, data: Vec::new() } };
        self.reply(Opcode::Query, code, record)
    }

    /// The answer to a node status request: the node holds `names`, and
    /// its unit ID (MAC address) is `unit_id`. The other statistics are
    /// zero (RFC 1002 section 4.2.18). `name` is the name asked about.
    pub fn node_status_response(&self, name: Name, names: Vec<NodeName>, unit_id: [u8; 6]) -> Packet {
        let mut statistics = vec![0u8; STATISTICS_LEN];
        statistics[..6].copy_from_slice(&unit_id);
        let record =
            Record { name, class: CLASS_IN, ttl: 0, data: RData::NodeStatus(NodeStatus { names, statistics }) };
        let mut p = self.reply(Opcode::Query, rcode::OK, record);
        p.flags.recursion_desired = false;
        p
    }

    /// The answer to a registration or refresh. With [`rcode::OK`] the
    /// name is registered to `entry` for `ttl` seconds. With
    /// [`rcode::ACT_ERR`] another node owns it. RFC 1002 answers a refresh
    /// with a registration response too (section 5.1.4.1), so the opcode
    /// is always 5, with AA, RD and RA set (sections 4.2.5 and 4.2.6).
    pub fn registration_response(&self, name: Name, ttl: u32, entry: NbEntry, code: u8) -> Packet {
        let record = Record { name, class: CLASS_IN, ttl, data: RData::Nb(vec![entry]) };
        let mut p = self.reply(Opcode::Registration, code, record);
        p.flags.recursion_available = true;
        p
    }

    /// The answer to a release, with result code `code` and only AA set
    /// (RFC 1002 sections 4.2.10 and 4.2.11).
    pub fn release_response(&self, name: Name, entry: NbEntry, code: u8) -> Packet {
        let record = Record { name, class: CLASS_IN, ttl: 0, data: RData::Nb(vec![entry]) };
        let mut p = self.reply(Opcode::Release, code, record);
        p.flags.recursion_desired = false;
        p
    }

    /// A WACK: tells the requester to wait up to `ttl` seconds more for
    /// the answer to this request. Its data is this request's opcode and
    /// flags (RFC 1002 section 4.2.16).
    pub fn wack(&self, name: Name, ttl: u32) -> Packet {
        let data = (self.header_word() & 0xfff0).to_be_bytes().to_vec();
        let record = Record { name, class: CLASS_IN, ttl, data: RData::Other { rr_type: rr_type::NB, data } };
        let mut p = self.reply(Opcode::Wack, rcode::OK, record);
        p.flags.recursion_desired = false;
        p
    }
}

/// Reads the name at `start` in the packet `msg`, following pointers. It
/// returns the name and where the bytes after it begin.
fn read_name(msg: &[u8], start: usize) -> Result<(Name, usize), ParseError> {
    let mut pos = start;
    let mut after = None;
    let mut hops = 0;
    // The final zero byte counts toward the name's length.
    let mut total = 1usize;
    let mut first = None;
    let mut scope = Vec::new();
    loop {
        let len = *msg.get(pos).ok_or(ParseError::Truncated)?;
        match len & 0xc0 {
            0xc0 => {
                let low = *msg.get(pos + 1).ok_or(ParseError::Truncated)?;
                let target = u16::from(len & 0x3f) << 8 | u16::from(low);
                if usize::from(target) >= pos || hops >= MAX_POINTERS {
                    return Err(ParseError::BadPointer(target));
                }
                hops += 1;
                after.get_or_insert(pos + 2);
                pos = usize::from(target);
            }
            0x00 if len == 0 => break,
            0x00 => {
                let len = usize::from(len);
                if first.is_none() && len != ENCODED_LEN {
                    return Err(ParseError::BadFirstLevel);
                }
                total += 1 + len;
                if total > MAX_NAME_LEN {
                    return Err(ParseError::NameTooLong);
                }
                let label = msg.get(pos + 1..pos + 1 + len).ok_or(ParseError::Truncated)?;
                if first.is_none() {
                    first = Some(decode_first_level(label).ok_or(ParseError::BadFirstLevel)?);
                } else {
                    scope.push(label.to_vec());
                }
                pos += 1 + len;
            }
            _ => return Err(ParseError::BadLabel(len)),
        }
    }
    let bytes = first.ok_or(ParseError::BadFirstLevel)?;
    Ok((Name { bytes, scope }, after.unwrap_or(pos + 1)))
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRED: &[u8; 32] = b"EGFCEFEECACACACACACACACACACACACA";

    fn owner(last: u8) -> NbEntry {
        NbEntry { group: false, node_type: NodeType::B, address: Ipv4Addr::new(10, 0, 0, last) }
    }

    /// A name query for FRED<20>, written by hand.
    fn query_bytes() -> Vec<u8> {
        let mut b = vec![0x00, 0x2a, 0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
        b.extend_from_slice(FRED);
        b.extend_from_slice(&[0, 0, 0x20, 0, 1]);
        b
    }

    /// A broadcast registration of FRED<20> by 10.0.0.9, as Windows
    /// sends it: the additional record's name points back to the
    /// question's, at offset 12.
    fn registration_bytes() -> Vec<u8> {
        let mut b = vec![0x00, 0x07, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1, 0x20];
        b.extend_from_slice(FRED);
        b.extend_from_slice(&[0, 0, 0x20, 0, 1]);
        b.extend_from_slice(&[0xc0, 0x0c, 0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 6, 0x00, 0x00, 10, 0, 0, 9]);
        b
    }

    fn samples() -> Vec<Vec<u8>> {
        let req = Packet::parse(&query_bytes()).unwrap();
        let status = Packet::node_status_query(3, Name::wildcard());
        vec![
            query_bytes(),
            registration_bytes(),
            req.query_response(Name::new("FRED", 0x20), 60, vec![owner(1), owner(2)]).to_bytes(),
            req.negative_query_response(Name::new("FRED", 0x20), rcode::NAM_ERR).to_bytes(),
            status.to_bytes(),
            status
                .node_status_response(
                    Name::wildcard(),
                    vec![NodeName::unique(&Name::new("FRED", 0))],
                    [1, 2, 3, 4, 5, 6],
                )
                .to_bytes(),
            Packet::name_query(9, Name::new("FRED", 0x20).with_scope("NETBIOS.COM"), false).to_bytes(),
            req.wack(Name::new("FRED", 0x20), 5).to_bytes(),
        ]
    }

    #[test]
    fn first_level_encoding_example() {
        // RFC 1001 section 14.1: "FRED" padded with spaces.
        let fred = Name::new("Fred", 0x20);
        assert_eq!(&encode_first_level(&fred.bytes), FRED);
        assert_eq!(decode_first_level(FRED), Some(fred.bytes));
        assert_eq!(&encode_first_level(&Name::wildcard().bytes), b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        for b in 0..=255u8 {
            let name = [b; NAME_LEN];
            assert_eq!(decode_first_level(&encode_first_level(&name)), Some(name));
        }
        // Wrong lengths and letters outside A to P.
        assert_eq!(decode_first_level(&FRED[..31]), None);
        assert_eq!(decode_first_level(b"QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), None);
        assert_eq!(decode_first_level(b"aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), None);
    }

    #[test]
    fn scope_example() {
        // RFC 1002 section 4.1: FRED in the scope NETBIOS.COM.
        let name = Name::new("FRED", 0x20).with_scope("NETBIOS.COM");
        let mut want = vec![0x20];
        want.extend_from_slice(FRED);
        want.extend_from_slice(b"\x07NETBIOS\x03COM\x00");
        assert_eq!(name.to_bytes(), want);
        assert_eq!(read_name(&want, 0), Ok((name.clone(), want.len())));
        assert_eq!(name.to_string(), "FRED<20>.NETBIOS.COM");
    }

    #[test]
    fn names() {
        let n = Name::new("a very long name indeed", 0x03);
        assert_eq!(n.name(), b"A VERY LONG NAM");
        assert_eq!(n.suffix(), 3);
        assert_eq!(Name::new("", 0).name(), b"");
        assert_eq!(
            Name::wildcard().to_string(),
            "*\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00<00>"
        );
        assert_eq!(Name::new("ws\\1", 0).to_string(), "WS\\x5c1<00>");
    }

    #[test]
    fn name_query_request() {
        let p = Packet::name_query(0x2a, Name::new("fred", 0x20), true);
        assert_eq!(p.to_bytes(), query_bytes());
        let back = Packet::parse(&query_bytes()).unwrap();
        assert_eq!(back, p);
        assert!(!back.response);
        assert_eq!(back.opcode, Opcode::Query);
        assert!(back.flags.broadcast && back.flags.recursion_desired);
        assert_eq!(back.request(), Ok(Request::NameQuery { name: Name::new("FRED", 0x20) }));
    }

    #[test]
    fn positive_query_response() {
        let req = Packet::parse(&query_bytes()).unwrap();
        let owners =
            vec![owner(1), NbEntry { group: true, node_type: NodeType::H, address: Ipv4Addr::new(192, 0, 2, 7) }];
        let resp = req.query_response(Name::new("FRED", 0x20), 300_000, owners.clone());
        let bytes = resp.to_bytes();
        // R, opcode 0, AA and RD, result 0.
        assert_eq!(bytes[..4], [0x00, 0x2a, 0x85, 0x00]);
        assert_eq!(bytes[4..12], [0, 0, 0, 1, 0, 0, 0, 0]);
        let tail = &bytes[12 + 34..];
        assert_eq!(tail[..10], [0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 12]);
        assert_eq!(tail[10..], [0x00, 0x00, 10, 0, 0, 1, 0xe0, 0x00, 192, 0, 2, 7]);
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back, resp);
        assert_eq!(back.answers[0].data, RData::Nb(owners));
        assert_eq!(back.request(), Err(RequestError::NotRequest));
    }

    #[test]
    fn negative_query_response() {
        let req = Packet::parse(&query_bytes()).unwrap();
        let resp = req.negative_query_response(Name::new("FRED", 0x20), rcode::NAM_ERR);
        let bytes = resp.to_bytes();
        assert_eq!(bytes[2..4], [0x85, 0x03]);
        assert_eq!(bytes[12 + 34..], [0, 0x0a, 0, 1, 0, 0, 0, 0, 0, 0]);
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back.rcode, rcode::NAM_ERR);
        assert_eq!(back.answers[0].data, RData::Other { rr_type: rr_type::NULL, data: vec![] });
    }

    #[test]
    fn node_status() {
        let req = Packet::node_status_query(0x99, Name::wildcard());
        let bytes = req.to_bytes();
        assert_eq!(bytes[2..4], [0x00, 0x00]);
        assert_eq!(&bytes[12..15], b"\x20CK");
        assert_eq!(bytes[bytes.len() - 4..], [0, 0x21, 0, 1]);
        let asked = Packet::parse(&bytes).unwrap();
        let Ok(Request::NodeStatus { name }) = asked.request() else { panic!() };
        assert_eq!(name, Name::wildcard());

        let names = vec![NodeName::unique(&Name::new("FRED", 0x00)), NodeName::group(&Name::new("WORKGROUP", 0x00))];
        let resp = asked.node_status_response(name, names.clone(), [0, 0x50, 0x56, 1, 2, 3]);
        let bytes = resp.to_bytes();
        assert_eq!(bytes[2..4], [0x84, 0x00]);
        let rdata = &bytes[12 + 34 + 10..];
        assert_eq!(rdata.len(), 1 + 2 * NODE_NAME_LEN + STATISTICS_LEN);
        assert_eq!(rdata[0], 2);
        assert_eq!(&rdata[1..17], b"FRED           \x00");
        assert_eq!(rdata[17..19], [0x04, 0x00]);
        assert_eq!(rdata[35..37], [0x84, 0x00]);
        let back = Packet::parse(&bytes).unwrap();
        let RData::NodeStatus(s) = &back.answers[0].data else { panic!() };
        assert_eq!(s.names, names);
        assert_eq!(s.unit_id(), Some([0, 0x50, 0x56, 1, 2, 3]));
        assert_eq!(back.answers[0].ttl, 0);
        // A status block too short for its names is kept unread.
        let mut short = bytes.clone();
        let at = 12 + 34 + 10;
        short[at] = 200;
        let RData::Other { rr_type, data } = &Packet::parse(&short).unwrap().answers[0].data else { panic!() };
        assert_eq!((*rr_type, data.len()), (rr_type::NBSTAT, rdata.len()));
        assert_eq!(NodeStatus::default().unit_id(), None);
    }

    #[test]
    fn registration_with_a_pointer() {
        let bytes = registration_bytes();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.opcode, Opcode::Registration);
        assert_eq!(p.additional[0].name, Name::new("FRED", 0x20));
        let want = Request::Registration { name: Name::new("FRED", 0x20), ttl: 300_000, entry: owner(9) };
        assert_eq!(p.request(), Ok(want));
        // The writer spells the name out, and reads back the same.
        let built = Packet::registration(7, Name::new("FRED", 0x20), 300_000, owner(9), true);
        assert_eq!(built, p);
        assert_eq!(Packet::parse(&built.to_bytes()), Ok(p.clone()));

        let yes = p.registration_response(Name::new("FRED", 0x20), 300_000, owner(9), rcode::OK);
        let b = yes.to_bytes();
        // R, opcode 5, AA, RD and RA.
        assert_eq!(b[2..4], [0xad, 0x80]);
        let no = p.registration_response(Name::new("FRED", 0x20), 0, owner(4), rcode::ACT_ERR);
        let back = Packet::parse(&no.to_bytes()).unwrap();
        assert_eq!(back.rcode, rcode::ACT_ERR);
        assert_eq!(back.answers[0].data, RData::Nb(vec![owner(4)]));
    }

    #[test]
    fn refresh_and_release() {
        let mut p = Packet::registration(1, Name::new("FRED", 0x20), 60, owner(3), false);
        p.opcode = Opcode::Refresh;
        assert_eq!(p.request(), Ok(Request::Refresh { name: Name::new("FRED", 0x20), ttl: 60, entry: owner(3) }));
        let r = p.registration_response(Name::new("FRED", 0x20), 60, owner(3), rcode::OK);
        assert_eq!(Packet::parse(&r.to_bytes()).unwrap().opcode, Opcode::Registration);

        let rel = Packet::release(2, Name::new("FRED", 0x20), owner(3), true);
        let back = Packet::parse(&rel.to_bytes()).unwrap();
        assert_eq!(back.to_bytes()[2..4], [0x30, 0x10]);
        assert_eq!(back.request(), Ok(Request::Release { name: Name::new("FRED", 0x20), entry: owner(3) }));
        let resp = back.release_response(Name::new("FRED", 0x20), owner(3), rcode::OK);
        let b = resp.to_bytes();
        assert_eq!(b[2..4], [0xb4, 0x00]);
        assert_eq!(Packet::parse(&b), Ok(resp));
    }

    #[test]
    fn wack() {
        let p = Packet::parse(&registration_bytes()).unwrap();
        let w = p.wack(Name::new("FRED", 0x20), 30);
        let b = w.to_bytes();
        assert_eq!(b[2..4], [0xbc, 0x00]);
        // The data: the request's opcode and flags, result code 0.
        assert_eq!(b[b.len() - 4..], [0, 2, 0x29, 0x10]);
        let back = Packet::parse(&b).unwrap();
        assert_eq!(back.answers[0].data, RData::Other { rr_type: rr_type::NB, data: vec![0x29, 0x10] });
        assert_eq!(back, w);
    }

    #[test]
    fn rfc1001_name_with_scope_example() {
        // RFC 1001 section 14.1: "The NetBIOS name" in SCOPE.ID.COM. The
        // name keeps its case, so it is built from its bytes. The RFC
        // prints FEGHGFCAEOGFHEECEJEPFDCAHEGBGNGF, which has two letters
        // wrong: it decodes to "Tge NetBIOS tame".
        let name = Name { bytes: *b"The NetBIOS name", scope: Vec::new() }.with_scope("SCOPE.ID.COM");
        assert_eq!(&encode_first_level(&name.bytes), b"FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF");
        assert_eq!(decode_first_level(b"FEGHGFCAEOGFHEECEJEPFDCAHEGBGNGF"), Some(*b"Tge NetBIOS tame"));
        let wire = name.to_bytes();
        assert_eq!(&wire[33..], b"\x05SCOPE\x02ID\x03COM\x00");
        assert_eq!(read_name(&wire, 0), Ok((name, wire.len())));
    }

    #[test]
    fn record_name_points_to_the_question() {
        // RFC 1002 sections 4.2.2 and 4.2.9: the record's name must point
        // to the question's name.
        let built = Packet::registration(7, Name::new("FRED", 0x20), 300_000, owner(9), true);
        assert_eq!(built.to_bytes(), registration_bytes());
        let rel = Packet::release(2, Name::new("FRED", 0x20), owner(3), false).to_bytes();
        assert_eq!(rel[50..52], [0xc0, 0x0c]);
        // A different name is written in full.
        let mut p = built.clone();
        p.additional[0].name = Name::new("FRED", 0x00);
        let b = p.to_bytes();
        assert_eq!(b[50], 0x20);
        assert_eq!(Packet::parse(&b), Ok(p));
    }

    #[test]
    fn refresh_with_opcode_9() {
        // RFC 1002 lists refresh as opcode 8, but draws the refresh
        // request in section 4.2.4 with opcode 9. Both are refreshes.
        let mut p = Packet::registration(1, Name::new("FRED", 0x20), 60, owner(3), false);
        p.opcode = Opcode::Other(9);
        p.flags.recursion_desired = false;
        let back = Packet::parse(&p.to_bytes()).unwrap();
        assert_eq!(back.opcode, Opcode::Other(9));
        assert_eq!(back.request(), Ok(Request::Refresh { name: Name::new("FRED", 0x20), ttl: 60, entry: owner(3) }));
    }

    #[test]
    fn response_headers_follow_rfc_1002() {
        // A refresh is answered with a name registration response
        // (section 5.1.4.1): opcode 5, with AA, RD and RA (section 4.2.5),
        // even though a refresh request has RD clear (section 4.2.4).
        let mut refresh = Packet::registration(1, Name::new("FRED", 0x20), 60, owner(3), false);
        refresh.opcode = Opcode::Refresh;
        refresh.flags.recursion_desired = false;
        let r = refresh.registration_response(Name::new("FRED", 0x20), 60, owner(3), rcode::OK).to_bytes();
        assert_eq!(r[2..4], [0xad, 0x80]);
        // A release response has only AA (section 4.2.10), even when the
        // request set RD.
        let mut rel = Packet::release(2, Name::new("FRED", 0x20), owner(3), false);
        rel.flags.recursion_desired = true;
        let r = rel.release_response(Name::new("FRED", 0x20), owner(3), rcode::OK).to_bytes();
        assert_eq!(r[2..4], [0xb4, 0x00]);
    }

    #[test]
    fn query_responses_set_rd() {
        // RFC 1002 sections 4.2.13 and 4.2.14 draw both query responses
        // with RD set, even to a query that had it clear.
        let mut q = Packet::name_query(5, Name::new("FRED", 0x20), false);
        q.flags.recursion_desired = false;
        let yes = q.query_response(Name::new("FRED", 0x20), 60, vec![owner(1)]).to_bytes();
        assert_eq!(yes[2..4], [0x85, 0x00]);
        let no = q.negative_query_response(Name::new("FRED", 0x20), rcode::NAM_ERR).to_bytes();
        assert_eq!(no[2..4], [0x85, 0x03]);
        // Node status (4.2.18) and WACK (4.2.16) keep RD clear.
        assert_eq!(q.node_status_response(Name::wildcard(), vec![], [0; 6]).to_bytes()[2..4], [0x84, 0x00]);
        assert_eq!(q.wack(Name::new("FRED", 0x20), 1).to_bytes()[2..4], [0xbc, 0x00]);
    }

    #[test]
    fn request_names() {
        let fred = Name::new("FRED", 0x20);
        let reqs = [
            Request::NameQuery { name: fred.clone() },
            Request::NodeStatus { name: fred.clone() },
            Request::Registration { name: fred.clone(), ttl: 1, entry: owner(1) },
            Request::Refresh { name: fred.clone(), ttl: 1, entry: owner(1) },
            Request::Release { name: fred.clone(), entry: owner(1) },
        ];
        for r in &reqs {
            assert_eq!(r.name(), &fred);
        }
        assert_eq!(Packet::parse(&registration_bytes()).unwrap().request().unwrap().name(), &fred);
    }

    #[test]
    fn built_values_that_read_as_another_variant() {
        // Other data of type NB that holds whole entries reads back as Nb.
        let mut p = Packet::name_query(1, Name::new("FRED", 0x20), false);
        p.answers.push(Record {
            name: Name::new("FRED", 0x20),
            class: CLASS_IN,
            ttl: 0,
            data: RData::Other { rr_type: rr_type::NB, data: vec![0, 0, 10, 0, 0, 1] },
        });
        p.opcode = Opcode::Other(5);
        let back = Packet::parse(&p.to_bytes()).unwrap();
        assert_eq!(back.answers[0].data, RData::Nb(vec![owner(1)]));
        assert_eq!(back.opcode, Opcode::Registration);
        assert_eq!(back.to_bytes(), p.to_bytes());
    }

    #[test]
    fn question_class_must_be_in() {
        let mut p = Packet::parse(&query_bytes()).unwrap();
        p.questions[0].class = 3;
        assert_eq!(p.request(), Err(RequestError::Malformed));
        let mut reg = Packet::parse(&registration_bytes()).unwrap();
        reg.questions[0].class = 0;
        assert_eq!(reg.request(), Err(RequestError::Malformed));
    }

    #[test]
    fn opcodes_and_node_types() {
        for v in 0..16u8 {
            assert_eq!(Opcode::from_bits(v).bits(), v);
        }
        assert_eq!(Opcode::Other(0x15).bits(), 5);
        for v in 0..4u16 {
            assert_eq!(NodeType::from_bits(v).bits(), v);
        }
    }

    #[test]
    fn parse_errors() {
        assert_eq!(Packet::parse(&[]), Err(ParseError::Truncated));
        assert_eq!(Packet::parse(&[0; 11]), Err(ParseError::Truncated));
        assert!(Packet::parse(&[0; 12]).is_ok());
        assert_eq!(Packet::parse(&vec![0; MAX_PACKET + 1]), Err(ParseError::TooLong(MAX_PACKET + 1)));
        let mut many = vec![0; 12];
        many[10..12].copy_from_slice(&65u16.to_be_bytes());
        assert_eq!(Packet::parse(&many), Err(ParseError::TooManyRecords(65)));
        many[10..12].copy_from_slice(&64u16.to_be_bytes());
        assert_eq!(Packet::parse(&many), Err(ParseError::Truncated));

        let question = |name: &[u8]| {
            let mut b = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            b.extend_from_slice(name);
            b.extend_from_slice(&[0, 0x20, 0, 1]);
            Packet::parse(&b)
        };
        assert_eq!(question(&[0x40]), Err(ParseError::BadLabel(0x40)));
        assert_eq!(question(&[0x80]), Err(ParseError::BadLabel(0x80)));
        // A pointer to itself, and one forward.
        assert_eq!(question(&[0xc0, 12]), Err(ParseError::BadPointer(12)));
        assert_eq!(question(&[0xc0, 14, 0]), Err(ParseError::BadPointer(14)));
        // The null name, a short first label, and a bad letter.
        assert_eq!(question(&[0]), Err(ParseError::BadFirstLevel));
        assert_eq!(question(b"\x03ABC\x00"), Err(ParseError::BadFirstLevel));
        let mut bad = vec![0x20];
        bad.extend_from_slice(b"EGFCEFEECACACACACACACACACACACACZ\x00");
        assert_eq!(question(&bad), Err(ParseError::BadFirstLevel));
        // A scope that runs the name past 255 bytes.
        let mut long = vec![0x20];
        long.extend_from_slice(FRED);
        for _ in 0..4 {
            long.push(63);
            long.extend_from_slice(&[b'x'; 63]);
        }
        long.push(0);
        assert_eq!(question(&long), Err(ParseError::NameTooLong));

        // A chain of pointers, each to the one before, ending at a real
        // name at offset 12. Following MAX_POINTERS of them is fine; one
        // more is refused.
        let mut b = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20];
        b.extend_from_slice(FRED);
        b.push(0);
        let mut last = 12u8;
        for _ in 0..=MAX_POINTERS {
            let here = b.len() as u8;
            b.extend_from_slice(&[0xc0, last]);
            last = here;
        }
        let end = b.len();
        assert_eq!(read_name(&b, end - 4), Ok((Name::new("FRED", 0x20), end - 2)));
        assert_eq!(read_name(&b, end - 2), Err(ParseError::BadPointer(12)));
    }

    #[test]
    fn request_errors() {
        let mut p = Packet::parse(&query_bytes()).unwrap();
        p.questions[0].qtype = rr_type::A;
        assert_eq!(p.request(), Err(RequestError::Malformed));
        p.questions.clear();
        assert_eq!(p.request(), Err(RequestError::Malformed));
        let mut reg = Packet::parse(&registration_bytes()).unwrap();
        reg.additional[0].data = RData::Nb(vec![]);
        assert_eq!(reg.request(), Err(RequestError::Malformed));
        reg.additional.clear();
        assert_eq!(reg.request(), Err(RequestError::Malformed));
        let mut reg = Packet::parse(&registration_bytes()).unwrap();
        reg.questions[0].qtype = rr_type::NBSTAT;
        assert_eq!(reg.request(), Err(RequestError::Malformed));
        reg.opcode = Opcode::Wack;
        assert_eq!(reg.request(), Err(RequestError::Unsupported(Opcode::Wack)));
        assert!(!RequestError::Unsupported(Opcode::Other(9)).to_string().is_empty());
        assert!(!ParseError::BadPointer(3).to_string().is_empty());
    }

    #[test]
    fn every_truncated_prefix_is_refused() {
        for s in samples() {
            assert!(Packet::parse(&s).is_ok());
            for n in 0..s.len() {
                assert_eq!(Packet::parse(&s[..n]), Err(ParseError::Truncated), "{n} of {} bytes", s.len());
            }
        }
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut b = query_bytes();
        b.extend_from_slice(&[1, 2, 3]);
        assert_eq!(Packet::parse(&b), Packet::parse(&query_bytes()));
    }

    #[test]
    fn writers_cap_what_they_write() {
        // A scope with empty and long labels, past 255 bytes.
        let mut name = Name::new("FRED", 0x20);
        name.scope = vec![vec![], vec![b'a'; 100], vec![b'b'; 63], vec![b'c'; 63], vec![b'd'; 63]];
        let wire = name.to_bytes();
        assert!(wire.len() <= MAX_NAME_LEN);
        let (back, used) = read_name(&wire, 0).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(back.scope, vec![vec![b'a'; 63], vec![b'b'; 63], vec![b'c'; 63]]);

        // Too many node names, and statistics too long for the record.
        let names = vec![NodeName::unique(&Name::new("X", 0)); 300];
        let status = RData::NodeStatus(NodeStatus { names, statistics: vec![7; 70_000] });
        let data = status.to_bytes();
        assert_eq!(data.len(), MAX_RDATA);
        let RData::NodeStatus(s) = RData::parse(rr_type::NBSTAT, &data) else { panic!() };
        assert_eq!(s.names.len(), MAX_NODE_NAMES);
        assert_eq!(1 + MAX_NODE_NAMES * NODE_NAME_LEN + s.statistics.len(), MAX_RDATA);
        let nb = RData::Nb(vec![owner(1); 20_000]).to_bytes();
        assert_eq!(nb.len(), MAX_NB_ENTRIES * NB_ENTRY_LEN);

        // Too many questions, and answers past what a datagram holds.
        let mut p = Packet::name_query(1, name.clone(), false);
        p.questions = vec![p.questions[0].clone(); 100];
        let rec = Record { name: name.clone(), class: CLASS_IN, ttl: 0, data: RData::Nb(vec![owner(1); 5000]) };
        p.answers = vec![rec; 3];
        p.additional = vec![Record { name, class: CLASS_IN, ttl: 1, data: RData::Nb(vec![owner(2)]) }];
        p.rcode = 0xff;
        let bytes = p.to_bytes();
        assert!(bytes.len() <= MAX_PACKET);
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back.questions.len(), MAX_RECORDS);
        assert_eq!(back.rcode, 0x0f);
        // Repeated names are pointers, so two answers of 30,012 bytes
        // fit, and the third does not.
        assert_eq!(back.answers.len(), 2);
        assert_eq!(back.additional.len(), 1);
        assert_eq!(back.additional[0].name, back.questions[0].name);
        // An Other record cut to its length field.
        let other = RData::Other { rr_type: 0x99, data: vec![1; 70_000] };
        assert_eq!(other.to_bytes().len(), MAX_RDATA);
        // A record too big for any datagram is left out.
        let mut q = Packet::name_query(1, Name::new("Y", 0), false);
        q.answers = vec![Record { name: Name::new("Y", 0), class: 1, ttl: 0, data: other }];
        let back = Packet::parse(&q.to_bytes()).unwrap();
        assert!(back.answers.is_empty());
        assert_eq!(back.questions.len(), 1);
    }

    /// A fixed linear congruential generator, so failures repeat.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    fn check(data: &[u8]) {
        if let Ok(p) = Packet::parse(data) {
            let bytes = p.to_bytes();
            let back = Packet::parse(&bytes).unwrap();
            assert_eq!(back, p);
            assert_eq!(back.to_bytes(), bytes);
            if p.request().is_ok() {
                let name = Name::new("W", 0x20);
                for r in [
                    p.query_response(name.clone(), 1, vec![owner(1)]),
                    p.negative_query_response(name.clone(), rcode::NAM_ERR),
                    p.node_status_response(name.clone(), vec![NodeName::unique(&name)], [0; 6]),
                    p.wack(name, 2),
                ] {
                    assert_eq!(Packet::parse(&r.to_bytes()), Ok(r));
                }
            }
            for q in &p.questions {
                assert!(q.name.to_string().contains('<'));
            }
        }
    }

    #[test]
    fn random_buffers() {
        let mut rng = Lcg(0x6e62_6e73);
        let seeds = samples();
        for round in 0..6000 {
            let mut buf = if round % 2 == 0 {
                let len = (rng.next() % 120) as usize;
                let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                // Give most a plausible header, so names get read.
                if b.len() >= 12 {
                    for i in (4..12).step_by(2) {
                        b[i] = 0;
                        b[i + 1] = (rng.next() % 3) as u8;
                    }
                }
                b
            } else {
                seeds[(rng.next() as usize) % seeds.len()].clone()
            };
            // Flip a few bytes, often in the names and counts.
            for _ in 0..(rng.next() % 4) {
                if !buf.is_empty() {
                    let i = (rng.next() as usize) % buf.len();
                    buf[i] = match rng.next() % 4 {
                        0 => 0xc0,
                        1 => rng.next() as u8 & 0x3f,
                        _ => rng.next() as u8,
                    };
                }
            }
            check(&buf);
            // The datagram as it arrives, one byte more at a time: every
            // prefix is read or refused, and never panics.
            for n in 0..buf.len() {
                check(&buf[..n]);
            }
        }
    }
}
