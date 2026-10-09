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
//! first-level encoding; see [`Name`]. The 32 letters are the
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
//! Writers refuse oversized or invalid values without changing the destination.
//! Query and node-status reply constructors cut their owner or name lists
//! to fit [`MAX_DATAGRAM`] and set TC when they cut a list, as RFC 1002 asks.
//! Writers preserve the chosen records and TC flag, up to [`MAX_PACKET`].
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::nbns::{Name, NbEntry, NodeType, Packet, RData, Request};
//! use std::net::Ipv4Addr;
//!
//! // The agent's machine broadcasts a query for the file server FILES.
//! let query = Packet::name_query(0x1234, Name::new("files", 0x20), true);
//! let bytes = query.to_bytes().unwrap();
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
//! let answer = Packet::parse(&reply.unwrap().to_bytes().unwrap()).unwrap();
//! assert!(answer.response);
//! assert_eq!(answer.id, 0x1234);
//! assert_eq!(answer.answers[0].data, RData::Nb(vec![owner]));
//! ```

use fictionet::stdlib::codec::{Wire, be16};

use std::net::Ipv4Addr;

/// The UDP port the name service listens on.
pub const PORT: u16 = 137;
/// The length of the header every packet starts with.
pub const HEADER_LEN: usize = 12;
/// The largest packet read or written here: the IPv4 UDP payload limit.
pub const MAX_PACKET: usize = 65_507;
/// The 576-byte datagram budget from RFC 1002 section 4.2.1.1.
/// Query and node-status reply constructors cut their lists to this budget
/// and set TC. Writers preserve all fields and allow up to [`MAX_PACKET`].
pub const MAX_DATAGRAM: usize = 576;
/// The largest section allowed here. Readers and writers refuse larger counts.
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
#[inline]
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
#[inline]
pub fn decode_first_level(label: &[u8]) -> Option<[u8; NAME_LEN]> {
    if label.len() != ENCODED_LEN {
        return None;
    }
    let half = |c: u8| {
        if (b'A'..=b'P').contains(&c) {
            Some(c - b'A')
        } else {
            None
        }
    };
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
        Name {
            bytes,
            scope: Vec::new(),
        }
    }

    /// The name `*` followed by zero bytes, which node status requests
    /// ask about to mean "whoever you are".
    pub fn wildcard() -> Name {
        let mut bytes = [0u8; NAME_LEN];
        bytes[0] = b'*';
        Name {
            bytes,
            scope: Vec::new(),
        }
    }

    /// This name with the scope `scope`, given with dots between labels.
    /// Empty labels are skipped. Other labels are kept as given, so the
    /// writer refuses labels above [`MAX_LABEL`] and names above
    /// [`MAX_NAME_LEN`].
    pub fn with_scope(mut self, scope: &str) -> Name {
        self.scope = dotted_labels(scope);
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
}

/// The labels of `text`, given with dots between them. Empty labels are
/// skipped; the others are kept as given.
fn dotted_labels(text: &str) -> Vec<Vec<u8>> {
    text.split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.as_bytes().to_vec())
        .collect()
}

/// Appends valid labels and the final zero to a name. Refuses empty or
/// oversized labels and names above [`MAX_NAME_LEN`].
fn put_labels<'a>(out: &mut Vec<u8>, labels: impl Iterator<Item = &'a [u8]>) -> Result<(), Error> {
    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL || out.len() + label.len() + 2 > MAX_NAME_LEN
        {
            return Err(Error::Unwritable);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    Ok(())
}

/// Writes `bytes` as text, with bytes that are not printable ASCII, and
/// backslashes, as `\xNN`.
fn write_text(f: &mut std::fmt::Formatter<'_>, bytes: &[u8]) -> std::fmt::Result {
    for &b in bytes {
        if (0x20..0x7f).contains(&b) && b != b'\\' {
            write!(f, "{}", b as char)?;
        } else {
            write!(f, "\\x{b:02x}")?;
        }
    }
    Ok(())
}

impl std::fmt::Display for Name {
    /// The name as Windows tools print it, such as `FILES<20>`, with the
    /// scope after a dot. Bytes that are not printable ASCII are written
    /// as `\xNN`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_text(f, self.name())?;
        write!(f, "<{:02X}>", self.suffix())?;
        for label in &self.scope {
            f.write_str(".")?;
            write_text(f, label)?;
        }
        Ok(())
    }
}

/// The name a resource record is about. Most records are about a NetBIOS
/// name. RFC 1002 also has records about ordinary domain names: the
/// authority and additional records of a redirect (section 4.2.15) name
/// a domain and its name server, and a WACK about a request without a
/// name carries the null name, a single zero byte (section 4.2.16).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RrName {
    /// A NetBIOS name, whose first label is first-level encoded.
    NetBios(Name),
    /// Any other name, as its labels, such as `["NETBIOS", "COM"]`. No
    /// labels is the null name. A writer writes the labels by the rules
    /// of [`Name::scope`]. A first label of 32 letters from `A` to
    /// `P` is refused here; use [`RrName::NetBios`].
    Domain(Vec<Vec<u8>>),
}

impl RrName {
    /// The null name: a single zero byte.
    pub fn null() -> RrName {
        RrName::Domain(Vec::new())
    }

    /// The domain name `name`, given with dots between labels, split by
    /// the rules of [`Name::with_scope`].
    pub fn domain(name: &str) -> RrName {
        RrName::Domain(dotted_labels(name))
    }

    /// The NetBIOS name, if this is one.
    pub fn netbios(&self) -> Option<&Name> {
        match self {
            RrName::NetBios(n) => Some(n),
            RrName::Domain(_) => None,
        }
    }
}

impl From<Name> for RrName {
    fn from(name: Name) -> RrName {
        RrName::NetBios(name)
    }
}

impl PartialEq<Name> for RrName {
    fn eq(&self, other: &Name) -> bool {
        self.netbios() == Some(other)
    }
}

impl std::fmt::Display for RrName {
    /// A NetBIOS name as [`Name`] prints it. A domain name with dots
    /// between its labels, and the null name as `.`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RrName::NetBios(n) => n.fmt(f),
            RrName::Domain(labels) if labels.is_empty() => f.write_str("."),
            RrName::Domain(labels) => {
                for (i, label) in labels.iter().enumerate() {
                    if i > 0 {
                        f.write_str(".")?;
                    }
                    write_text(f, label)?;
                }
                Ok(())
            }
        }
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
    /// 7: wait for acknowledgment; a server needs more time.
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
    fn parse(b: &[u8]) -> Result<NbEntry, Error> {
        let flags = be16(b, 0).ok_or(Error::Truncated)?;
        Ok(NbEntry {
            group: flags & 0x8000 != 0,
            node_type: NodeType::from_bits(flags >> 13),
            address: Ipv4Addr::new(b[2], b[3], b[4], b[5]),
        })
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
        NodeName {
            bytes: name.bytes,
            flags: name_flags::ACTIVE,
        }
    }

    /// An active group name owned by a B node.
    pub fn group(name: &Name) -> NodeName {
        NodeName {
            bytes: name.bytes,
            flags: name_flags::ACTIVE | name_flags::GROUP,
        }
    }
}

/// The data of an NBSTAT record: the names a node holds, and its
/// statistics. The default has no names and [`STATISTICS_LEN`] zero
/// bytes of statistics.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeStatus {
    /// The node names. Writers refuse more than [`MAX_NODE_NAMES`].
    pub names: Vec<NodeName>,
    /// The statistics block, kept in full. RFC 1002 specifies
    /// [`STATISTICS_LEN`] bytes, starting with the node's six-byte unit ID
    /// (its MAC address). Some senders use fewer or more. Writers refuse
    /// an oversized packet.
    pub statistics: Vec<u8>,
}

impl Default for NodeStatus {
    fn default() -> NodeStatus {
        NodeStatus {
            names: Vec::new(),
            statistics: vec![0; STATISTICS_LEN],
        }
    }
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
    /// The writer refuses more than [`MAX_NB_ENTRIES`] entries.
    Nb(Vec<NbEntry>),
    /// Type NBSTAT whose names fit its length: a node's names.
    NodeStatus(NodeStatus),
    /// Type NS: the name of a name server, in a redirect (RFC 1002
    /// section 4.2.15), as its labels. A reader follows its pointers, so
    /// it does not depend on where it sits in the packet. A packet whose
    /// NS data is not one name is refused. A writer writes the labels by
    /// the rules of [`Name::scope`].
    Ns(Vec<Vec<u8>>),
    /// Other record data, including malformed NB or NBSTAT data such as WACK.
    /// Names within it are not followed. Writers refuse type NS, oversized data,
    /// and NB or NBSTAT bytes that would read as another variant.
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
            RData::Ns(_) => rr_type::NS,
            RData::Other { rr_type, .. } => *rr_type,
        }
    }

    fn parse(rr: u16, data: &[u8]) -> Result<RData, Error> {
        if rr == rr_type::NB && data.len().is_multiple_of(NB_ENTRY_LEN) {
            return Ok(RData::Nb(
                data.as_chunks::<NB_ENTRY_LEN>()
                    .0
                    .iter()
                    .map(|e| NbEntry::parse(e))
                    .collect::<Result<_, _>>()?,
            ));
        }
        if rr == rr_type::NBSTAT
            && let Some((&n, rest)) = data.split_first()
            && let Some(names) = rest.get(..usize::from(n) * NODE_NAME_LEN)
        {
            let names = names
                .as_chunks::<NODE_NAME_LEN>()
                .0
                .iter()
                .map(|c| {
                    let mut bytes = [0u8; NAME_LEN];
                    bytes.copy_from_slice(&c[..NAME_LEN]);
                    Ok(NodeName {
                        bytes,
                        flags: be16(c, NAME_LEN).ok_or(Error::Truncated)?,
                    })
                })
                .collect::<Result<_, Error>>()?;
            let statistics = rest[usize::from(n) * NODE_NAME_LEN..].to_vec();
            return Ok(RData::NodeStatus(NodeStatus { names, statistics }));
        }
        Ok(RData::Other {
            rr_type: rr,
            data: data.to_vec(),
        })
    }

    /// Appends complete record data. Refuses oversized or ambiguous values.
    fn write_data(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            RData::Nb(entries) => {
                if entries.len() > MAX_NB_ENTRIES {
                    return Err(Error::Unwritable);
                }
                for entry in entries {
                    entry.write(out);
                }
            }
            RData::NodeStatus(status) => {
                if status.names.len() > MAX_NODE_NAMES || status.statistics.len() > MAX_RDATA {
                    return Err(Error::Unwritable);
                }
                out.push(status.names.len() as u8);
                for name in &status.names {
                    out.extend_from_slice(&name.bytes);
                    out.extend_from_slice(&name.flags.to_be_bytes());
                }
                out.extend_from_slice(&status.statistics);
            }
            RData::Ns(labels) => put_labels(out, labels.iter().map(Vec::as_slice))?,
            RData::Other { rr_type, data } => {
                if *rr_type == rr_type::NS || data.len() > MAX_RDATA {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
            }
        }
        if out.len() > MAX_RDATA {
            return Err(Error::Unwritable);
        }
        Ok(())
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
    /// The name the record is about: almost always a NetBIOS name.
    pub name: RrName,
    /// The class: [`CLASS_IN`].
    pub class: u16,
    /// How long, in seconds, the name holds.
    pub ttl: u32,
    /// The data, which also gives the record's type.
    pub data: RData,
}

impl Record {
    /// Appends a complete record, using earlier names when possible.
    fn write_record(
        &self,
        out: &mut Vec<u8>,
        written: &std::collections::HashMap<Vec<u8>, u16>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let full = put_name(out, self.name.to_bytes()?, written);
        let mut data = Vec::new();
        self.data.write_data(&mut data)?;
        out.extend_from_slice(&self.data.rr_type().to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        Ok(full)
    }
}

/// Writes the name `wire` to `out`, the bytes of an entry that starts at
/// the beginning of `out`. A name written in full earlier, as listed in
/// `written`, becomes a two-byte pointer to it. It returns the name's
/// bytes if it wrote the name in full.
fn put_name(
    out: &mut Vec<u8>,
    wire: Vec<u8>,
    written: &std::collections::HashMap<Vec<u8>, u16>,
) -> Option<Vec<u8>> {
    if let Some(at) = written.get(&wire) {
        out.extend_from_slice(&(0xc000 | at).to_be_bytes());
        return None;
    }
    out.extend_from_slice(&wire);
    Some(wire)
}

/// Notes that the name `full` was written in full at offset `at`, if a
/// pointer can reach it: pointers hold 14 bits.
fn remember(
    written: &mut std::collections::HashMap<Vec<u8>, u16>,
    full: Option<Vec<u8>>,
    at: usize,
) {
    if let (Some(wire), Ok(at)) = (full, u16::try_from(at))
        && at <= 0x3fff
    {
        written.insert(wire, at);
    }
}

/// Why a datagram is not an NBNS packet, or why a packet is not a request
/// [`Packet::request`] can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Bytes follow a complete [`Name`] or [`RrName`].
    Trailing(usize),
    /// The value cannot be written without changing it.
    Unwritable,
    /// The packet ends before its header, a name or a record does.
    Truncated,
    /// The datagram is longer than [`MAX_PACKET`].
    TooLong(usize),
    /// Expanded names make the re-encoded packet exceed [`MAX_PACKET`].
    ExpansionTooLong,
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
    /// The data of an NS record is not exactly one name.
    BadNsData,
    /// The packet is a response. A server does not answer it.
    NotRequest,
    /// The packet lacks one question of the right type and class
    /// [`CLASS_IN`], or a registration, refresh or release lacks the one
    /// additional record that says who asks: an NB record for the
    /// question's name, of class [`CLASS_IN`], with one owner. A server
    /// may answer [`rcode::FMT_ERR`].
    BadRequest,
    /// The opcode is not one this module answers. A server may answer
    /// [`rcode::IMP_ERR`].
    Unsupported(Opcode),
}

fictionet::error_display!(Error, f, {
    Error::Trailing(n) => write!(f, "{n} bytes after the unit"),
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
    Error::Truncated => f.write_str("packet ends early"),
    Error::ExpansionTooLong => write!(f, "expanded packet exceeds {MAX_PACKET} bytes"),
    Error::TooLong(n) => write!(f, "datagram of {n} bytes, over {MAX_PACKET}"),
    Error::TooManyRecords(n) => write!(f, "section of {n} entries, over {MAX_RECORDS}"),
    Error::BadLabel(b) => write!(f, "label length byte {b:#04x}"),
    Error::BadPointer(p) => write!(f, "pointer to offset {p} goes forward or loops"),
    Error::BadFirstLevel => f.write_str("first label is not a first-level encoded name"),
    Error::NameTooLong => write!(f, "name longer than {MAX_NAME_LEN} bytes"),
    Error::BadNsData => f.write_str("NS record data is not one name"),
    Error::NotRequest => f.write_str("packet is a response"),
    Error::BadRequest => f.write_str("request lacks its question or NB record"),
    Error::Unsupported(o) => write!(f, "opcode {} is not supported", o.bits()),
});

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
    /// The result code; see [`rcode`]. Values above 15 are refused.
    pub rcode: u8,
    /// The question section. Writers refuse sections above [`MAX_RECORDS`]
    /// or packets above [`MAX_PACKET`]. The TC flag is preserved.
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
    /// Register `name` for the owner in `entry`, for `ttl` seconds. The
    /// request has RD set (RFC 1002 section 4.2.2).
    Registration {
        /// The name to register.
        name: Name,
        /// How long the registration should last, in seconds.
        ttl: u32,
        /// The node claiming it.
        entry: NbEntry,
    },
    /// A name overwrite request or demand (RFC 1002 section 4.2.3): a
    /// registration with RD clear. A B node sends it once it has
    /// registered `name` by broadcast without a challenge, to make the
    /// name its own. A node that owns the name may answer it as a
    /// conflicting registration.
    Overwrite {
        /// The name to take.
        name: Name,
        /// How long the registration should last, in seconds.
        ttl: u32,
        /// The node taking it.
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

impl Request {
    /// The name the request is about: the question's name.
    pub fn name(&self) -> &Name {
        match self {
            Request::NameQuery { name }
            | Request::NodeStatus { name }
            | Request::Registration { name, .. }
            | Request::Overwrite { name, .. }
            | Request::Refresh { name, .. }
            | Request::Release { name, .. } => name,
        }
    }
}

impl Packet {
    /// The header's second 16 bits: the response bit, opcode, flags and
    /// result code.
    fn header_word(&self) -> u16 {
        u16::from(self.response) << 15
            | u16::from(self.opcode.bits()) << 11
            | self.flags.bits() << 4
            | u16::from(self.rcode & 0x0f)
    }

    /// What this packet asks, for a world that answers requests.
    pub fn request(&self) -> Result<Request, Error> {
        if self.response {
            return Err(Error::NotRequest);
        }
        let [q] = &self.questions[..] else {
            return Err(Error::BadRequest);
        };
        if q.class != CLASS_IN {
            return Err(Error::BadRequest);
        }
        let name = q.name.clone();
        // RFC 1002 sections 4.2.2 to 4.2.4 and 4.2.9: one additional
        // record, for the question's name, of class IN, with one owner.
        let nb = || match &self.additional[..] {
            [r] if q.qtype == rr_type::NB && r.name == q.name && r.class == CLASS_IN => {
                match &r.data {
                    RData::Nb(e) => match &e[..] {
                        [e] => Ok((r.ttl, *e)),
                        _ => Err(Error::BadRequest),
                    },
                    _ => Err(Error::BadRequest),
                }
            }
            _ => Err(Error::BadRequest),
        };
        match self.opcode {
            Opcode::Query => match q.qtype {
                rr_type::NB => Ok(Request::NameQuery { name }),
                rr_type::NBSTAT => Ok(Request::NodeStatus { name }),
                _ => Err(Error::BadRequest),
            },
            Opcode::Registration if !self.flags.recursion_desired => {
                nb().map(|(ttl, entry)| Request::Overwrite { name, ttl, entry })
            }
            Opcode::Registration => {
                nb().map(|(ttl, entry)| Request::Registration { name, ttl, entry })
            }
            Opcode::Refresh | Opcode::Other(9) => {
                nb().map(|(ttl, entry)| Request::Refresh { name, ttl, entry })
            }
            Opcode::Release => nb().map(|(_, entry)| Request::Release { name, entry }),
            other => Err(Error::Unsupported(other)),
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
            questions: vec![Question {
                name,
                qtype,
                class: CLASS_IN,
            }],
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// A name query for `name`, as RFC 1002 section 4.2.12 lays it out.
    /// It asks a name server to do the work (RD), and is marked broadcast
    /// if `broadcast` is set.
    pub fn name_query(id: u16, name: Name, broadcast: bool) -> Packet {
        let flags = Flags {
            recursion_desired: true,
            broadcast,
            ..Flags::default()
        };
        Packet::asking(id, Opcode::Query, flags, name, rr_type::NB)
    }

    /// A node status request about `name`, sent straight to one node.
    pub fn node_status_query(id: u16, name: Name) -> Packet {
        Packet::asking(id, Opcode::Query, Flags::default(), name, rr_type::NBSTAT)
    }

    /// A request to register `name` for `entry`, for `ttl` seconds: the
    /// question, and an NB record in the additional section.
    pub fn registration(id: u16, name: Name, ttl: u32, entry: NbEntry, broadcast: bool) -> Packet {
        let flags = Flags {
            recursion_desired: true,
            broadcast,
            ..Flags::default()
        };
        let mut p = Packet::asking(id, Opcode::Registration, flags, name.clone(), rr_type::NB);
        p.additional.push(Record {
            name: name.into(),
            class: CLASS_IN,
            ttl,
            data: RData::Nb(vec![entry]),
        });
        p
    }

    /// A request to release `name`, held by `entry`.
    pub fn release(id: u16, name: Name, entry: NbEntry, broadcast: bool) -> Packet {
        let flags = Flags {
            broadcast,
            ..Flags::default()
        };
        let mut p = Packet::asking(id, Opcode::Release, flags, name.clone(), rr_type::NB);
        p.additional.push(Record {
            name: name.into(),
            class: CLASS_IN,
            ttl: 0,
            data: RData::Nb(vec![entry]),
        });
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
            flags: Flags {
                authoritative: true,
                recursion_desired: true,
                ..Flags::default()
            },
            rcode: code,
            questions: Vec::new(),
            answers: vec![record],
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// The positive answer to a name query: `name` is held by `owners`
    /// for `ttl` seconds. AA and RD are set, whatever the query had
    /// (RFC 1002 section 4.2.13). Cuts the owner list to fit [`MAX_DATAGRAM`]
    /// and sets TC when owners are omitted. An invalid name remains unwritable.
    pub fn query_response(&self, name: Name, ttl: u32, mut owners: Vec<NbEntry>) -> Packet {
        let limit = reply_list_limit(&name, 0, NB_ENTRY_LEN);
        let truncated = owners.len() > limit;
        owners.truncate(limit);
        let record = Record {
            name: name.into(),
            class: CLASS_IN,
            ttl,
            data: RData::Nb(owners),
        };
        let mut p = self.reply(Opcode::Query, rcode::OK, record);
        p.flags.truncated = truncated;
        p
    }

    /// The negative answer to a name query, with result code `code`,
    /// usually [`rcode::NAM_ERR`]. AA and RD are set (RFC 1002 section
    /// 4.2.14). An end node sends none for a broadcast query. It stays
    /// silent.
    pub fn negative_query_response(&self, name: Name, code: u8) -> Packet {
        let data = RData::Other {
            rr_type: rr_type::NULL,
            data: Vec::new(),
        };
        let record = Record {
            name: name.into(),
            class: CLASS_IN,
            ttl: 0,
            data,
        };
        self.reply(Opcode::Query, code, record)
    }

    /// The answer to a node status request: the node holds `names`, and
    /// its unit ID (MAC address) is `unit_id`. The other statistics are
    /// zero (RFC 1002 section 4.2.18). `name` is the name asked about.
    /// Cuts the name list to fit [`MAX_DATAGRAM`] and sets TC when names
    /// are omitted. An invalid name remains unwritable.
    pub fn node_status_response(
        &self,
        name: Name,
        mut names: Vec<NodeName>,
        unit_id: [u8; 6],
    ) -> Packet {
        let limit = reply_list_limit(&name, 1 + STATISTICS_LEN, NODE_NAME_LEN);
        let truncated = names.len() > limit;
        names.truncate(limit);
        let mut statistics = vec![0u8; STATISTICS_LEN];
        statistics[..6].copy_from_slice(&unit_id);
        let data = RData::NodeStatus(NodeStatus { names, statistics });
        let record = Record {
            name: name.into(),
            class: CLASS_IN,
            ttl: 0,
            data,
        };
        let mut p = self.reply(Opcode::Query, rcode::OK, record);
        p.flags.recursion_desired = false;
        p.flags.truncated = truncated;
        p
    }

    /// The answer to a registration or refresh. With [`rcode::OK`] the
    /// name is registered to `entry` for `ttl` seconds. With
    /// [`rcode::ACT_ERR`] another node owns it. RFC 1002 answers a refresh
    /// with a registration response too (section 5.1.4.1), so the opcode
    /// is always 5, with AA, RD and RA set (sections 4.2.5 and 4.2.6).
    pub fn registration_response(&self, name: Name, ttl: u32, entry: NbEntry, code: u8) -> Packet {
        let record = Record {
            name: name.into(),
            class: CLASS_IN,
            ttl,
            data: RData::Nb(vec![entry]),
        };
        let mut p = self.reply(Opcode::Registration, code, record);
        p.flags.recursion_available = true;
        p
    }

    /// The answer to a release, with result code `code` and only AA set
    /// (RFC 1002 sections 4.2.10 and 4.2.11).
    pub fn release_response(&self, name: Name, entry: NbEntry, code: u8) -> Packet {
        let record = Record {
            name: name.into(),
            class: CLASS_IN,
            ttl: 0,
            data: RData::Nb(vec![entry]),
        };
        let mut p = self.reply(Opcode::Release, code, record);
        p.flags.recursion_desired = false;
        p
    }

    /// A WACK: tells the requester to wait up to `ttl` seconds more for
    /// the answer to this request. Its data is this request's opcode and
    /// flags (RFC 1002 section 4.2.16). `name` is the request's name, or
    /// [`RrName::null`] if it has none.
    pub fn wack(&self, name: impl Into<RrName>, ttl: u32) -> Packet {
        let data = (self.header_word() & 0xfff0).to_be_bytes().to_vec();
        let record = Record {
            name: name.into(),
            class: CLASS_IN,
            ttl,
            data: RData::Other {
                rr_type: rr_type::NB,
                data,
            },
        };
        let mut p = self.reply(Opcode::Wack, rcode::OK, record);
        p.flags.recursion_desired = false;
        p
    }
}

/// Reads the NetBIOS name at `start` in the packet `msg`, following
/// pointers. It returns the name and where the bytes after it begin.
fn read_name(msg: &[u8], start: usize) -> Result<(Name, usize), Error> {
    let (mut labels, after) = read_labels(msg, start)?;
    let bytes = labels
        .first()
        .and_then(|l| decode_first_level(l))
        .ok_or(Error::BadFirstLevel)?;
    labels.remove(0);
    Ok((
        Name {
            bytes,
            scope: labels,
        },
        after,
    ))
}

/// Reads the name of a resource record at `start` in the packet `msg`:
/// a NetBIOS name if its first label is one, and a domain name if not.
fn read_rr_name(msg: &[u8], start: usize) -> Result<(RrName, usize), Error> {
    let (mut labels, after) = read_labels(msg, start)?;
    match labels.first().and_then(|l| decode_first_level(l)) {
        Some(bytes) => {
            labels.remove(0);
            Ok((
                RrName::NetBios(Name {
                    bytes,
                    scope: labels,
                }),
                after,
            ))
        }
        None => Ok((RrName::Domain(labels), after)),
    }
}

/// Reads the labels of the name at `start` in the packet `msg`, following
/// pointers. It returns them and where the bytes after the name begin.
fn read_labels(msg: &[u8], start: usize) -> Result<(Vec<Vec<u8>>, usize), Error> {
    let mut pos = start;
    let mut after = None;
    let mut hops = 0;
    // The final zero byte counts toward the name's length.
    let mut total = 1usize;
    let mut labels = Vec::new();
    loop {
        let len = *msg.get(pos).ok_or(Error::Truncated)?;
        match len & 0xc0 {
            0xc0 => {
                let low = *msg.get(pos + 1).ok_or(Error::Truncated)?;
                let target = u16::from(len & 0x3f) << 8 | u16::from(low);
                if usize::from(target) >= pos || hops >= MAX_POINTERS {
                    return Err(Error::BadPointer(target));
                }
                hops += 1;
                after.get_or_insert(pos + 2);
                pos = usize::from(target);
            }
            0x00 if len == 0 => break,
            0x00 => {
                let len = usize::from(len);
                total += 1 + len;
                if total > MAX_NAME_LEN {
                    return Err(Error::NameTooLong);
                }
                let label = msg.get(pos + 1..pos + 1 + len).ok_or(Error::Truncated)?;
                labels.push(label.to_vec());
                pos += 1 + len;
            }
            _ => return Err(Error::BadLabel(len)),
        }
    }
    Ok((labels, after.unwrap_or(pos + 1)))
}

/// Appends an uncompressed NetBIOS name and scope.
/// Refuses empty or oversized labels and names above [`MAX_NAME_LEN`].
/// Errors leave the destination unchanged.
pub fn write_name(
    dst: &mut Vec<u8>,
    bytes: &[u8; NAME_LEN],
    scope: &[Vec<u8>],
) -> Result<(), Error> {
    let mut out = Vec::with_capacity(ENCODED_LEN + 2);
    out.push(ENCODED_LEN as u8);
    out.extend_from_slice(&encode_first_level(bytes));
    put_labels(&mut out, scope.iter().map(Vec::as_slice))?;
    dst.extend_from_slice(&out);
    Ok(())
}

impl Wire for Name {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete name. Refuses invalid labels, pointers outside the input and trailing bytes.
    fn parse(b: &[u8]) -> Result<Name, Error> {
        let (value, used) = read_name(b, 0)?;
        if used != b.len() {
            return Err(Error::Trailing(b.len() - used));
        }
        Ok(value)
    }

    /// Appends the uncompressed name. Refuses empty or oversized scope labels and
    /// names above [`MAX_NAME_LEN`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        write_name(dst, &self.bytes, &self.scope)
    }
}

impl Wire for RrName {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete name. Refuses invalid labels, pointers outside the input and trailing bytes.
    fn parse(b: &[u8]) -> Result<RrName, Error> {
        let (value, used) = read_rr_name(b, 0)?;
        if used != b.len() {
            return Err(Error::Trailing(b.len() - used));
        }
        Ok(value)
    }

    /// Appends an uncompressed resource record name. Refuses invalid labels, oversized
    /// names and domain values that would read as NetBIOS names. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        match self {
            RrName::NetBios(n) => n.write(&mut out)?,
            RrName::Domain(labels) => put_labels(&mut out, labels.iter().map(Vec::as_slice))?,
        }
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a datagram with compressed names, ignoring bytes after its records.
    /// Refuses invalid records and packets whose expanded encoding exceeds [`MAX_PACKET`].
    fn parse(b: &[u8]) -> Result<Packet, Error> {
        if b.len() > MAX_PACKET {
            return Err(Error::TooLong(b.len()));
        }
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let word = be16(b, 2).ok_or(Error::Truncated)?;
        let mut counts = [0usize; 4];
        for (i, c) in counts.iter_mut().enumerate() {
            let n = be16(b, 4 + 2 * i).ok_or(Error::Truncated)?;
            if usize::from(n) > MAX_RECORDS {
                return Err(Error::TooManyRecords(n));
            }
            *c = usize::from(n);
        }
        let mut pos = HEADER_LEN;
        let mut questions = Vec::with_capacity(counts[0]);
        for _ in 0..counts[0] {
            let (name, next) = read_name(b, pos)?;
            let fixed = b.get(next..next + 4).ok_or(Error::Truncated)?;
            questions.push(Question {
                name,
                qtype: be16(fixed, 0).ok_or(Error::Truncated)?,
                class: be16(fixed, 2).ok_or(Error::Truncated)?,
            });
            pos = next + 4;
        }
        let mut sections: [Vec<Record>; 3] = Default::default();
        for (section, &count) in sections.iter_mut().zip(&counts[1..]) {
            section.reserve(count);
            for _ in 0..count {
                let (name, next) = read_rr_name(b, pos)?;
                let fixed = b.get(next..next + 10).ok_or(Error::Truncated)?;
                let len = usize::from(be16(fixed, 8).ok_or(Error::Truncated)?);
                let start = next + 10;
                let data = b.get(start..start + len).ok_or(Error::Truncated)?;
                let rr = be16(fixed, 0).ok_or(Error::Truncated)?;
                let data = if rr == rr_type::NS {
                    // The name server's name, whose pointers are followed
                    // now, since a writer may move what they point to.
                    match read_labels(b, start) {
                        Ok((labels, end)) if end == start + len => RData::Ns(labels),
                        _ => return Err(Error::BadNsData),
                    }
                } else {
                    RData::parse(rr, data)?
                };
                section.push(Record {
                    name,
                    class: be16(fixed, 2).ok_or(Error::Truncated)?,
                    ttl: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
                    data,
                });
                pos = start + len;
            }
        }
        let [answers, authority, additional] = sections;
        let packet = Packet {
            id: be16(b, 0).ok_or(Error::Truncated)?,
            response: word & 0x8000 != 0,
            opcode: Opcode::from_bits((word >> 11) as u8),
            flags: Flags::from_bits(word >> 4),
            rcode: (word & 0x0f) as u8,
            questions,
            answers,
            authority,
            additional,
        };
        packet.encode().map_err(|_| Error::ExpansionTooLong)?;
        Ok(packet)
    }

    /// Appends every section, compressing repeated names. Refuses oversized fields,
    /// sections or packets, and values that would read as another variant.
    /// Preserves the TC flag. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let out = self.encode()?;
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Packet {
    /// Stages the complete packet within its byte and record limits.
    fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.questions.len() > MAX_RECORDS
            || [&self.answers, &self.authority, &self.additional]
                .iter()
                .any(|s| s.len() > MAX_RECORDS)
        {
            return Err(Error::Unwritable);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.header_word().to_be_bytes());
        for count in [
            self.questions.len(),
            self.answers.len(),
            self.authority.len(),
            self.additional.len(),
        ] {
            out.extend_from_slice(&(count as u16).to_be_bytes());
        }
        let mut written = std::collections::HashMap::new();
        for q in &self.questions {
            let at = out.len();
            let full = put_name(&mut out, q.name.to_bytes()?, &written);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.class.to_be_bytes());
            remember(&mut written, full, at);
            if out.len() > MAX_PACKET {
                return Err(Error::Unwritable);
            }
        }
        for record in self
            .answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            let at = out.len();
            let full = record.write_record(&mut out, &written)?;
            remember(&mut written, full, at);
            if out.len() > MAX_PACKET {
                return Err(Error::Unwritable);
            }
        }
        Ok(out)
    }
}

/// The entries that fit a one-record reply, including its uncompressed name.
fn reply_list_limit(name: &Name, fixed_data: usize, entry_len: usize) -> usize {
    name.to_bytes().map_or(0, |bytes| {
        MAX_DATAGRAM.saturating_sub(HEADER_LEN + bytes.len() + 10 + fixed_data) / entry_len
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::hex;
    use fictionet::stdlib::test_support::mutate;
    use fictionet::stdlib::test_support::rounds;

    fn other_data(rr_type: u16, data: Vec<u8>) -> RData {
        RData::Other { rr_type, data }
    }

    const FRED: &[u8; 32] = b"EGFCEFEECACACACACACACACACACACACA";

    fn owner(last: u8) -> NbEntry {
        NbEntry {
            group: false,
            node_type: NodeType::B,
            address: Ipv4Addr::new(10, 0, 0, last),
        }
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
        b.extend_from_slice(&[
            0xc0, 0x0c, 0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 6, 0x00, 0x00, 10, 0, 0, 9,
        ]);
        b
    }

    fn samples() -> Vec<Vec<u8>> {
        let req = Packet::parse(&query_bytes()).unwrap();
        let status = Packet::node_status_query(3, Name::wildcard());
        vec![
            query_bytes(),
            registration_bytes(),
            req.query_response(Name::new("FRED", 0x20), 60, vec![owner(1), owner(2)])
                .to_bytes()
                .unwrap(),
            req.negative_query_response(Name::new("FRED", 0x20), rcode::NAM_ERR)
                .to_bytes()
                .unwrap(),
            status.to_bytes().unwrap(),
            status
                .node_status_response(
                    Name::wildcard(),
                    vec![NodeName::unique(&Name::new("FRED", 0))],
                    [1, 2, 3, 4, 5, 6],
                )
                .to_bytes()
                .unwrap(),
            Packet::name_query(9, Name::new("FRED", 0x20).with_scope("NETBIOS.COM"), false)
                .to_bytes()
                .unwrap(),
            req.wack(Name::new("FRED", 0x20), 5).to_bytes().unwrap(),
            req.wack(RrName::null(), 5).to_bytes().unwrap(),
            redirect_bytes(),
        ]
    }

    #[test]
    fn first_level_encoding_example() {
        // RFC 1001 section 14.1: "FRED" padded with spaces.
        let fred = Name::new("Fred", 0x20);
        assert_eq!(&fred.to_bytes().unwrap()[1..1 + ENCODED_LEN], FRED);
        assert_eq!(decode_first_level(FRED), Some(fred.bytes));
        assert_eq!(
            &Name::wildcard().to_bytes().unwrap()[1..1 + ENCODED_LEN],
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        for b in 0..=255u8 {
            let name = Name {
                bytes: [b; NAME_LEN],
                scope: Vec::new(),
            };
            assert_eq!(Name::parse(&name.to_bytes().unwrap()), Ok(name));
        }
        // Wrong lengths and letters outside A to P.
        assert_eq!(decode_first_level(&FRED[..31]), None);
        assert_eq!(
            decode_first_level(b"QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            None
        );
        assert_eq!(
            decode_first_level(b"aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            None
        );
    }

    #[test]
    fn scope_example() {
        // RFC 1002 section 4.1: FRED in the scope NETBIOS.COM.
        let name = Name::new("FRED", 0x20).with_scope("NETBIOS.COM");
        let mut want = vec![0x20];
        want.extend_from_slice(FRED);
        want.extend_from_slice(b"\x07NETBIOS\x03COM\x00");
        assert_eq!(name.to_bytes().unwrap(), want);
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
        assert_eq!(p.to_bytes().unwrap(), query_bytes());
        let back = Packet::parse(&query_bytes()).unwrap();
        assert_eq!(back, p);
        assert!(!back.response);
        assert_eq!(back.opcode, Opcode::Query);
        assert!(back.flags.broadcast && back.flags.recursion_desired);
        assert_eq!(
            back.request(),
            Ok(Request::NameQuery {
                name: Name::new("FRED", 0x20)
            })
        );
    }

    #[test]
    fn positive_query_response() {
        let req = Packet::parse(&query_bytes()).unwrap();
        let owners = vec![
            owner(1),
            NbEntry {
                group: true,
                node_type: NodeType::H,
                address: Ipv4Addr::new(192, 0, 2, 7),
            },
        ];
        let resp = req.query_response(Name::new("FRED", 0x20), 300_000, owners.clone());
        let bytes = resp.to_bytes().unwrap();
        // R, opcode 0, AA and RD, result 0.
        assert_eq!(bytes[..4], [0x00, 0x2a, 0x85, 0x00]);
        assert_eq!(bytes[4..12], [0, 0, 0, 1, 0, 0, 0, 0]);
        let tail = &bytes[12 + 34..];
        assert_eq!(tail[..10], [0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 12]);
        assert_eq!(
            tail[10..],
            [0x00, 0x00, 10, 0, 0, 1, 0xe0, 0x00, 192, 0, 2, 7]
        );
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back, resp);
        assert_eq!(back.answers[0].data, RData::Nb(owners));
        assert_eq!(back.request(), Err(Error::NotRequest));
    }

    #[test]
    fn negative_query_response() {
        let req = Packet::parse(&query_bytes()).unwrap();
        let resp = req.negative_query_response(Name::new("FRED", 0x20), rcode::NAM_ERR);
        let bytes = resp.to_bytes().unwrap();
        assert_eq!(bytes[2..4], [0x85, 0x03]);
        assert_eq!(bytes[12 + 34..], [0, 0x0a, 0, 1, 0, 0, 0, 0, 0, 0]);
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back.rcode, rcode::NAM_ERR);
        assert_eq!(back.answers[0].data, other_data(rr_type::NULL, vec![]));
    }

    #[test]
    fn node_status() {
        let req = Packet::node_status_query(0x99, Name::wildcard());
        let bytes = req.to_bytes().unwrap();
        assert_eq!(bytes[2..4], [0x00, 0x00]);
        assert_eq!(&bytes[12..15], b"\x20CK");
        assert_eq!(bytes[bytes.len() - 4..], [0, 0x21, 0, 1]);
        let asked = Packet::parse(&bytes).unwrap();
        let Ok(Request::NodeStatus { name }) = asked.request() else {
            panic!()
        };
        assert_eq!(name, Name::wildcard());

        let names = vec![
            NodeName::unique(&Name::new("FRED", 0x00)),
            NodeName::group(&Name::new("WORKGROUP", 0x00)),
        ];
        let resp = asked.node_status_response(name, names.clone(), [0, 0x50, 0x56, 1, 2, 3]);
        let bytes = resp.to_bytes().unwrap();
        assert_eq!(bytes[2..4], [0x84, 0x00]);
        let rdata = &bytes[12 + 34 + 10..];
        assert_eq!(rdata.len(), 1 + 2 * NODE_NAME_LEN + STATISTICS_LEN);
        assert_eq!(rdata[0], 2);
        assert_eq!(&rdata[1..17], b"FRED           \x00");
        assert_eq!(rdata[17..19], [0x04, 0x00]);
        assert_eq!(rdata[35..37], [0x84, 0x00]);
        let back = Packet::parse(&bytes).unwrap();
        let RData::NodeStatus(s) = &back.answers[0].data else {
            panic!()
        };
        assert_eq!(s.names, names);
        assert_eq!(s.unit_id(), Some([0, 0x50, 0x56, 1, 2, 3]));
        assert_eq!(back.answers[0].ttl, 0);
        // A status block too short for its names is kept unread.
        let mut short = bytes.clone();
        let at = 12 + 34 + 10;
        short[at] = 200;
        let RData::Other { rr_type, data } = &Packet::parse(&short).unwrap().answers[0].data else {
            panic!()
        };
        assert_eq!((*rr_type, data.len()), (rr_type::NBSTAT, rdata.len()));
        assert_eq!(NodeStatus::default().unit_id(), Some([0; 6]));
        assert_eq!(
            NodeStatus {
                names: vec![],
                statistics: vec![1, 2]
            }
            .unit_id(),
            None
        );
    }

    #[test]
    fn registration_with_a_pointer() {
        let bytes = registration_bytes();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.opcode, Opcode::Registration);
        assert_eq!(p.additional[0].name, Name::new("FRED", 0x20));
        let want = Request::Registration {
            name: Name::new("FRED", 0x20),
            ttl: 300_000,
            entry: owner(9),
        };
        assert_eq!(p.request(), Ok(want));
        // The writer spells the name out, and reads back the same.
        let built = Packet::registration(7, Name::new("FRED", 0x20), 300_000, owner(9), true);
        assert_eq!(built, p);
        assert_eq!(Packet::parse(&built.to_bytes().unwrap()), Ok(p.clone()));

        let yes = p.registration_response(Name::new("FRED", 0x20), 300_000, owner(9), rcode::OK);
        let b = yes.to_bytes().unwrap();
        // R, opcode 5, AA, RD and RA.
        assert_eq!(b[2..4], [0xad, 0x80]);
        let no = p.registration_response(Name::new("FRED", 0x20), 0, owner(4), rcode::ACT_ERR);
        let back = Packet::parse(&no.to_bytes().unwrap()).unwrap();
        assert_eq!(back.rcode, rcode::ACT_ERR);
        assert_eq!(back.answers[0].data, RData::Nb(vec![owner(4)]));
    }

    #[test]
    fn refresh_and_release() {
        let mut p = Packet::registration(1, Name::new("FRED", 0x20), 60, owner(3), false);
        p.opcode = Opcode::Refresh;
        assert_eq!(
            p.request(),
            Ok(Request::Refresh {
                name: Name::new("FRED", 0x20),
                ttl: 60,
                entry: owner(3)
            })
        );
        let r = p.registration_response(Name::new("FRED", 0x20), 60, owner(3), rcode::OK);
        assert_eq!(
            Packet::parse(&r.to_bytes().unwrap()).unwrap().opcode,
            Opcode::Registration
        );

        let rel = Packet::release(2, Name::new("FRED", 0x20), owner(3), true);
        let back = Packet::parse(&rel.to_bytes().unwrap()).unwrap();
        assert_eq!(back.to_bytes().unwrap()[2..4], [0x30, 0x10]);
        assert_eq!(
            back.request(),
            Ok(Request::Release {
                name: Name::new("FRED", 0x20),
                entry: owner(3)
            })
        );
        let resp = back.release_response(Name::new("FRED", 0x20), owner(3), rcode::OK);
        let b = resp.to_bytes().unwrap();
        assert_eq!(b[2..4], [0xb4, 0x00]);
        assert_eq!(Packet::parse(&b), Ok(resp));
    }

    #[test]
    fn wack() {
        let p = Packet::parse(&registration_bytes()).unwrap();
        let w = p.wack(Name::new("FRED", 0x20), 30);
        let b = w.to_bytes().unwrap();
        assert_eq!(b[2..4], [0xbc, 0x00]);
        // The data: the request's opcode and flags, result code 0.
        assert_eq!(b[b.len() - 4..], [0, 2, 0x29, 0x10]);
        let back = Packet::parse(&b).unwrap();
        assert_eq!(
            back.answers[0].data,
            other_data(rr_type::NB, vec![0x29, 0x10])
        );
        assert_eq!(back, w);
    }

    #[test]
    fn rfc1001_name_with_scope_example() {
        // RFC 1001 section 14.1: "The NetBIOS name" in SCOPE.ID.COM. The
        // name keeps its case, so it is built from its bytes. The RFC
        // prints FEGHGFCAEOGFHEECEJEPFDCAHEGBGNGF, which has two letters
        // wrong: it decodes to "Tge NetBIOS tame".
        let name = Name {
            bytes: *b"The NetBIOS name",
            scope: Vec::new(),
        }
        .with_scope("SCOPE.ID.COM");
        assert_eq!(
            &name.to_bytes().unwrap()[1..1 + ENCODED_LEN],
            b"FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF"
        );
        assert_eq!(
            decode_first_level(b"FEGHGFCAEOGFHEECEJEPFDCAHEGBGNGF"),
            Some(*b"Tge NetBIOS tame")
        );
        let wire = name.to_bytes().unwrap();
        assert_eq!(&wire[33..], b"\x05SCOPE\x02ID\x03COM\x00");
        assert_eq!(read_name(&wire, 0), Ok((name, wire.len())));
    }

    #[test]
    fn record_name_points_to_the_question() {
        // RFC 1002 sections 4.2.2 and 4.2.9: the record's name must point
        // to the question's name.
        let built = Packet::registration(7, Name::new("FRED", 0x20), 300_000, owner(9), true);
        assert_eq!(built.to_bytes().unwrap(), registration_bytes());
        let rel = Packet::release(2, Name::new("FRED", 0x20), owner(3), false)
            .to_bytes()
            .unwrap();
        assert_eq!(rel[50..52], [0xc0, 0x0c]);
        // A different name is written in full.
        let mut p = built.clone();
        p.additional[0].name = Name::new("FRED", 0x00).into();
        let b = p.to_bytes().unwrap();
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
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        assert_eq!(back.opcode, Opcode::Other(9));
        assert_eq!(
            back.request(),
            Ok(Request::Refresh {
                name: Name::new("FRED", 0x20),
                ttl: 60,
                entry: owner(3)
            })
        );
    }

    #[test]
    fn response_headers_follow_rfc_1002() {
        // A refresh is answered with a name registration response
        // (section 5.1.4.1): opcode 5, with AA, RD and RA (section 4.2.5),
        // even though a refresh request has RD clear (section 4.2.4).
        let mut refresh = Packet::registration(1, Name::new("FRED", 0x20), 60, owner(3), false);
        refresh.opcode = Opcode::Refresh;
        refresh.flags.recursion_desired = false;
        let r = refresh
            .registration_response(Name::new("FRED", 0x20), 60, owner(3), rcode::OK)
            .to_bytes()
            .unwrap();
        assert_eq!(r[2..4], [0xad, 0x80]);
        // A release response has only AA (section 4.2.10), even when the
        // request set RD.
        let mut rel = Packet::release(2, Name::new("FRED", 0x20), owner(3), false);
        rel.flags.recursion_desired = true;
        let r = rel
            .release_response(Name::new("FRED", 0x20), owner(3), rcode::OK)
            .to_bytes()
            .unwrap();
        assert_eq!(r[2..4], [0xb4, 0x00]);
    }

    #[test]
    fn query_responses_set_rd() {
        // RFC 1002 sections 4.2.13 and 4.2.14 draw both query responses
        // with RD set, even to a query that had it clear.
        let mut q = Packet::name_query(5, Name::new("FRED", 0x20), false);
        q.flags.recursion_desired = false;
        let yes = q
            .query_response(Name::new("FRED", 0x20), 60, vec![owner(1)])
            .to_bytes()
            .unwrap();
        assert_eq!(yes[2..4], [0x85, 0x00]);
        let no = q
            .negative_query_response(Name::new("FRED", 0x20), rcode::NAM_ERR)
            .to_bytes()
            .unwrap();
        assert_eq!(no[2..4], [0x85, 0x03]);
        // Node status (4.2.18) and WACK (4.2.16) keep RD clear.
        assert_eq!(
            q.node_status_response(Name::wildcard(), vec![], [0; 6])
                .to_bytes()
                .unwrap()[2..4],
            [0x84, 0x00]
        );
        assert_eq!(
            q.wack(Name::new("FRED", 0x20), 1).to_bytes().unwrap()[2..4],
            [0xbc, 0x00]
        );
    }

    #[test]
    fn request_names() {
        let fred = Name::new("FRED", 0x20);
        let reqs = [
            Request::NameQuery { name: fred.clone() },
            Request::NodeStatus { name: fred.clone() },
            Request::Registration {
                name: fred.clone(),
                ttl: 1,
                entry: owner(1),
            },
            Request::Refresh {
                name: fred.clone(),
                ttl: 1,
                entry: owner(1),
            },
            Request::Release {
                name: fred.clone(),
                entry: owner(1),
            },
        ];
        for r in &reqs {
            assert_eq!(r.name(), &fred);
        }
        assert_eq!(
            Packet::parse(&registration_bytes())
                .unwrap()
                .request()
                .unwrap()
                .name(),
            &fred
        );
    }

    #[test]
    fn built_values_that_read_as_another_variant() {
        // Other data of type NB that holds whole entries reads back as Nb.
        let mut p = Packet::name_query(1, Name::new("FRED", 0x20), false);
        p.answers.push(Record {
            name: Name::new("FRED", 0x20).into(),
            class: CLASS_IN,
            ttl: 0,
            data: other_data(rr_type::NB, vec![0, 0, 10, 0, 0, 1]),
        });
        p.opcode = Opcode::Other(5);
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&p);
        p.answers[0].data = RData::Nb(vec![owner(1)]);
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        p.opcode = Opcode::Registration;
        contract::check_wire_value(&p);
    }

    #[test]
    fn question_class_must_be_in() {
        let mut p = Packet::parse(&query_bytes()).unwrap();
        p.questions[0].class = 3;
        assert_eq!(p.request(), Err(Error::BadRequest));
        let mut reg = Packet::parse(&registration_bytes()).unwrap();
        reg.questions[0].class = 0;
        assert_eq!(reg.request(), Err(Error::BadRequest));
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
        assert_eq!(Packet::parse(&[]), Err(Error::Truncated));
        assert_eq!(Packet::parse(&[0; 11]), Err(Error::Truncated));
        assert!(Packet::parse(&[0; 12]).is_ok());
        assert_eq!(
            Packet::parse(&vec![0; MAX_PACKET + 1]),
            Err(Error::TooLong(MAX_PACKET + 1))
        );
        let mut many = vec![0; 12];
        many[10..12].copy_from_slice(&65u16.to_be_bytes());
        assert_eq!(Packet::parse(&many), Err(Error::TooManyRecords(65)));
        many[10..12].copy_from_slice(&64u16.to_be_bytes());
        assert_eq!(Packet::parse(&many), Err(Error::Truncated));

        let question = |name: &[u8]| {
            let mut b = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            b.extend_from_slice(name);
            b.extend_from_slice(&[0, 0x20, 0, 1]);
            Packet::parse(&b)
        };
        assert_eq!(question(&[0x40]), Err(Error::BadLabel(0x40)));
        assert_eq!(question(&[0x80]), Err(Error::BadLabel(0x80)));
        // A pointer to itself, and one forward.
        assert_eq!(question(&[0xc0, 12]), Err(Error::BadPointer(12)));
        assert_eq!(question(&[0xc0, 14, 0]), Err(Error::BadPointer(14)));
        // The null name, a short first label, and a bad letter.
        assert_eq!(question(&[0]), Err(Error::BadFirstLevel));
        assert_eq!(question(b"\x03ABC\x00"), Err(Error::BadFirstLevel));
        let mut bad = vec![0x20];
        bad.extend_from_slice(b"EGFCEFEECACACACACACACACACACACACZ\x00");
        assert_eq!(question(&bad), Err(Error::BadFirstLevel));
        // A scope that runs the name past 255 bytes.
        let mut long = vec![0x20];
        long.extend_from_slice(FRED);
        for _ in 0..4 {
            long.push(63);
            long.extend_from_slice(&[b'x'; 63]);
        }
        long.push(0);
        assert_eq!(question(&long), Err(Error::NameTooLong));

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
        assert_eq!(
            read_name(&b, end - 4),
            Ok((Name::new("FRED", 0x20), end - 2))
        );
        assert_eq!(read_name(&b, end - 2), Err(Error::BadPointer(12)));
    }

    #[test]
    fn request_errors() {
        let mut p = Packet::parse(&query_bytes()).unwrap();
        p.questions[0].qtype = rr_type::A;
        assert_eq!(p.request(), Err(Error::BadRequest));
        p.questions.clear();
        assert_eq!(p.request(), Err(Error::BadRequest));
        let mut reg = Packet::parse(&registration_bytes()).unwrap();
        reg.additional[0].data = RData::Nb(vec![]);
        assert_eq!(reg.request(), Err(Error::BadRequest));
        reg.additional.clear();
        assert_eq!(reg.request(), Err(Error::BadRequest));
        let mut reg = Packet::parse(&registration_bytes()).unwrap();
        reg.questions[0].qtype = rr_type::NBSTAT;
        assert_eq!(reg.request(), Err(Error::BadRequest));
        reg.opcode = Opcode::Wack;
        assert_eq!(reg.request(), Err(Error::Unsupported(Opcode::Wack)));
        assert!(!Error::Unsupported(Opcode::Other(9)).to_string().is_empty());
        assert!(!Error::BadPointer(3).to_string().is_empty());
    }

    #[test]
    fn every_truncated_prefix_is_refused() {
        for s in samples() {
            assert!(Packet::parse(&s).is_ok());
            for n in 0..s.len() {
                assert_eq!(
                    Packet::parse(&s[..n]),
                    Err(Error::Truncated),
                    "{n} of {} bytes",
                    s.len()
                );
            }
        }
    }

    #[test]
    fn expanded_packet_uses_a_reader_error() {
        // NS data points to a long earlier name. Re-encoding expands that
        // pointer; an opaque record fills the remaining packet space.
        let name = RrName::Domain(vec![vec![b'a'; 63]; 3]);
        let mut bytes = hex("0001 8000 0000 0002 0000 0000");
        name.write(&mut bytes).unwrap();
        bytes.extend_from_slice(&hex("0002 0001 00000000 0002 c00c"));
        bytes.push(0);
        let data_len = MAX_PACKET - bytes.len() - 10;
        bytes.extend_from_slice(&hex("0099 0001 00000000"));
        bytes.extend_from_slice(&(data_len as u16).to_be_bytes());
        bytes.resize(MAX_PACKET, 0);
        assert_eq!(Packet::parse(&bytes), Err(Error::ExpansionTooLong));
        contract::check_wire::<Packet>(&bytes);
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut b = query_bytes();
        b.extend_from_slice(&[1, 2, 3]);
        assert_eq!(Packet::parse(&b), Packet::parse(&query_bytes()));
        contract::check_wire::<Packet>(&b);
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        let mut name = Name::new("FRED", 0x20);
        for scope in [vec![vec![]], vec![vec![b'a'; 100]], vec![vec![b'b'; 63]; 4]] {
            name.scope = scope;
            contract::check_wire_value(&name);
            assert_eq!(name.to_bytes(), Err(Error::Unwritable));
        }
        let name = Name::new("X", 0);
        for data in [
            RData::NodeStatus(NodeStatus {
                names: vec![NodeName::unique(&name); 300],
                statistics: vec![],
            }),
            RData::NodeStatus(NodeStatus {
                names: vec![],
                statistics: vec![7; 70_000],
            }),
            RData::Nb(vec![owner(1); 20_000]),
            other_data(0x99, vec![1; 70_000]),
        ] {
            let mut packet = Packet::name_query(1, name.clone(), false);
            packet.answers.push(Record {
                name: name.clone().into(),
                class: CLASS_IN,
                ttl: 0,
                data,
            });
            contract::check_wire_value(&packet);
            assert_eq!(packet.to_bytes(), Err(Error::Unwritable));
        }
        let mut packet = Packet::name_query(1, name, false);
        packet.questions = vec![packet.questions[0].clone(); MAX_RECORDS + 1];
        contract::check_wire_value(&packet);
        assert_eq!(packet.to_bytes(), Err(Error::Unwritable));
        packet.questions.truncate(1);
        packet.rcode = 0xff;
        contract::check_wire_value(&packet);
        assert_eq!(packet.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn registration_needs_its_own_owner_record() {
        // RFC 1002 sections 4.2.2 and 4.2.9: one additional record, for
        // the question's name, of class IN, with one owner.
        let good = Packet::registration(7, Name::new("FRED", 0x20), 60, owner(9), true);
        assert!(good.request().is_ok());
        let mut other = good.clone();
        other.additional[0].name = Name::new("OTHER", 0x20).into();
        assert_eq!(other.request(), Err(Error::BadRequest));
        let mut class = good.clone();
        class.additional[0].class = 3;
        assert_eq!(class.request(), Err(Error::BadRequest));
        let mut two = good.clone();
        two.additional[0].data = RData::Nb(vec![owner(1), owner(2)]);
        assert_eq!(two.request(), Err(Error::BadRequest));
        let mut rel = Packet::release(2, Name::new("FRED", 0x20), owner(3), false);
        rel.additional[0].name = Name::new("FRED", 0x00).into();
        assert_eq!(rel.request(), Err(Error::BadRequest));
    }

    #[test]
    fn reply_constructors_keep_to_576_bytes_and_set_tc() {
        let req = Packet::parse(&query_bytes()).unwrap();
        for name in [
            Name::new("FRED", 0x20),
            Name::new("FRED", 0x20).with_scope(&"x.".repeat(110)),
        ] {
            let node = NodeName::unique(&name);
            for count in [0, 3, 100, 10_909] {
                for (reply, item_len, items) in [
                    (
                        req.query_response(name.clone(), 60, vec![owner(1); count]),
                        NB_ENTRY_LEN,
                        0,
                    ),
                    (
                        req.node_status_response(name.clone(), vec![node; count], [7; 6]),
                        NODE_NAME_LEN,
                        1,
                    ),
                ] {
                    contract::check_wire_value(&reply);
                    let bytes = reply.to_bytes().unwrap();
                    assert!(bytes.len() <= MAX_DATAGRAM);
                    assert_eq!(Packet::parse(&bytes), Ok(reply.clone()));
                    let retained = match &reply.answers[0].data {
                        RData::Nb(owners) => {
                            assert_eq!(items, 0);
                            assert_eq!(owners, &vec![owner(1); owners.len()]);
                            owners.len()
                        }
                        RData::NodeStatus(status) => {
                            assert_eq!(items, 1);
                            assert_eq!(status.names, vec![node; status.names.len()]);
                            assert_eq!(status.unit_id(), Some([7; 6]));
                            status.names.len()
                        }
                        _ => panic!("unexpected reply data"),
                    };
                    assert_eq!(reply.flags.truncated, retained < count);
                    if retained < count {
                        assert!(bytes.len() + item_len > MAX_DATAGRAM);
                    }
                }
            }
        }
        // Directly constructed packets retain all records and TC as supplied.
        let mut packet = req.query_response(Name::new("FRED", 0x20), 60, vec![]);
        packet.answers[0].data = RData::Nb(vec![owner(1); 100]);
        assert!(packet.to_bytes().unwrap().len() > MAX_DATAGRAM);
        assert!(!packet.flags.truncated);
        packet.answers[0].data = RData::Nb(vec![owner(1); MAX_NB_ENTRIES + 1]);
        assert_eq!(packet.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&packet);
        let mut many = Packet::name_query(1, Name::new("FRED", 0x20), false);
        many.questions = vec![many.questions[0].clone(); MAX_RECORDS + 1];
        assert_eq!(many.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&many);
    }

    #[test]
    fn with_scope_keeps_labels_and_write_refuses_long_ones() {
        // 110 two-byte labels fill the name to 254 bytes; one more passes
        // MAX_NAME_LEN.
        let name = Name::new("FRED", 0x20).with_scope(&"x.".repeat(110));
        assert_eq!(name.scope.len(), 110);
        let wire = name.to_bytes().unwrap();
        assert_eq!(wire.len(), MAX_NAME_LEN - 1);
        assert_eq!(read_name(&wire, 0).unwrap().0, name);
        let long = Name::new("FRED", 0x20).with_scope(&"x.".repeat(111));
        assert_eq!(long.scope.len(), 111);
        assert_eq!(long.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&long);
        let huge = Name::new("FRED", 0x20).with_scope(&"a.".repeat(rounds(100_000)));
        assert_eq!(huge.to_bytes(), Err(Error::Unwritable));
        // A label of MAX_LABEL bytes is written; one byte more is refused.
        let name = Name::new("FRED", 0x20).with_scope(&"x".repeat(MAX_LABEL));
        assert_eq!(read_name(&name.to_bytes().unwrap(), 0).unwrap().0, name);
        let wide = Name::new("FRED", 0x20).with_scope(&"x".repeat(MAX_LABEL + 1));
        assert_eq!(wide.scope, vec![vec![b'x'; MAX_LABEL + 1]]);
        assert_eq!(wide.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&wide);
        let domain = RrName::domain(&"x".repeat(MAX_LABEL + 1));
        assert_eq!(domain, RrName::Domain(vec![vec![b'x'; MAX_LABEL + 1]]));
        assert_eq!(domain.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&domain);
    }

    #[test]
    fn default_node_status_has_a_statistics_block() {
        // RFC 1002 section 4.2.18: the statistics follow the names.
        assert_eq!(NodeStatus::default().statistics, vec![0; STATISTICS_LEN]);
    }

    /// A redirect name query response (RFC 1002 section 4.2.15): the
    /// name server NS.NETBIOS.COM, at 10.0.0.1, has authority over
    /// NETBIOS.COM. The additional record's name points into the NS data.
    fn redirect_bytes() -> Vec<u8> {
        let mut b = hex("0005 8100 0000 0000 0001 0001");
        b.extend_from_slice(b"\x07NETBIOS\x03COM\x00");
        b.extend_from_slice(&hex("0002 0001 00000e10 0005"));
        b.extend_from_slice(b"\x02NS\xc0\x0c");
        b.extend_from_slice(&hex("c023 0001 0001 00000e10 0004 0a000001"));
        b
    }

    #[test]
    fn wack_with_the_null_name() {
        // RFC 1002 section 4.2.16: with no name from the request, the
        // WACK's name is the null name, a single zero byte.
        let b = hex("0001bc000000000100000000 00 00200001000000010002 2910");
        let p = Packet::parse(&b).unwrap();
        assert_eq!(p.answers[0].name, RrName::null());
        assert_eq!(p.answers[0].name.to_string(), ".");
        assert_eq!(p.to_bytes().unwrap(), b);
        let req = Packet::parse(&registration_bytes()).unwrap();
        let w = req.wack(RrName::null(), 1);
        assert_eq!(Packet::parse(&w.to_bytes().unwrap()), Ok(w));
        // Questions still need a NetBIOS name.
        let mut q = hex("0001 0000 0001 0000 0000 0000 00 0020 0001");
        assert_eq!(Packet::parse(&q), Err(Error::BadFirstLevel));
        q[5] = 0;
        assert_eq!(Packet::parse(&q), Packet::parse(&q[..HEADER_LEN]));
        assert!(Packet::parse(&q[..HEADER_LEN]).is_ok());
    }

    #[test]
    fn redirect_with_domain_names() {
        let b = redirect_bytes();
        let p = Packet::parse(&b).unwrap();
        assert_eq!(
            p.authority[0].name,
            RrName::domain("netbios.com".to_uppercase().as_str())
        );
        assert_eq!(p.authority[0].name.to_string(), "NETBIOS.COM");
        let ns = vec![b"NS".to_vec(), b"NETBIOS".to_vec(), b"COM".to_vec()];
        assert_eq!(p.authority[0].data, RData::Ns(ns.clone()));
        assert_eq!(p.additional[0].name, RrName::Domain(ns));
        assert_eq!(
            p.additional[0].data,
            other_data(rr_type::A, vec![10, 0, 0, 1])
        );
        assert!(p.authority[0].name.netbios().is_none());
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        assert_eq!(back, p);
        // NS data that is more than one name is refused.
        let mut bad = b.clone();
        bad[34] = 6;
        assert_eq!(Packet::parse(&bad), Err(Error::BadNsData));
    }

    #[test]
    fn ns_data_survives_rewriting() {
        // The authority record repeats the question's name in full, and
        // its NS data points at the scope inside it, at offset 95. The
        // writer turns the repeated name into a pointer, so the scope
        // moves; the NS data must still name NETBIOS.COM.
        let fred = Name::new("FRED", 0x20).with_scope("NETBIOS.COM");
        let mut b = hex("0009 8100 0001 0000 0001 0000");
        b.extend_from_slice(&fred.to_bytes().unwrap());
        b.extend_from_slice(&hex("0020 0001"));
        assert_eq!(b.len(), 62);
        b.extend_from_slice(&fred.to_bytes().unwrap());
        b.extend_from_slice(&hex("0002 0001 00000000 0002 c05f"));
        assert_eq!(b.len(), 120);
        let p = Packet::parse(&b).unwrap();
        let scope = vec![b"NETBIOS".to_vec(), b"COM".to_vec()];
        assert_eq!(p.authority[0].data, RData::Ns(scope.clone()));
        let out = p.to_bytes().unwrap();
        assert!(out.len() < b.len());
        let back = Packet::parse(&out).unwrap();
        assert_eq!(back.authority[0].data, RData::Ns(scope));
        assert_eq!(back, p);
        // Opaque NS data with a pointer is refused.
        let mut built = p.clone();
        built.authority[0].data = other_data(rr_type::NS, vec![0xc0, 0x5f]);
        assert_eq!(built.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&built);
        // Opaque NS data that would read as Ns is also refused.
        built.authority[0].data = other_data(rr_type::NS, b"\x03COM\x00".to_vec());
        assert_eq!(built.to_bytes(), Err(Error::Unwritable));
        built.authority[0].data = RData::Ns(vec![b"COM".to_vec()]);
        contract::check_wire_value(&built);
    }

    #[test]
    fn overwrite_is_not_a_registration() {
        // RFC 1002 sections 4.2.2 and 4.2.3: a registration has RD set,
        // an overwrite request or demand has it clear.
        let mut p = Packet::registration(7, Name::new("FRED", 0x20), 60, owner(9), true);
        let reg = p.request().unwrap();
        assert!(matches!(reg, Request::Registration { .. }));
        p.flags.recursion_desired = false;
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        let want = Request::Overwrite {
            name: Name::new("FRED", 0x20),
            ttl: 60,
            entry: owner(9),
        };
        assert_eq!(back.request(), Ok(want.clone()));
        assert_eq!(want.name(), reg.name());
    }

    fn check(data: &[u8]) {
        contract::check_wire::<Name>(data);
        contract::check_wire::<RrName>(data);
        contract::check_wire::<Packet>(data);

        if let Ok(p) = Packet::parse(data) {
            let bytes = p.to_bytes().unwrap();
            assert!(bytes.len() <= MAX_PACKET);
            let back = Packet::parse(&bytes).unwrap();
            assert_eq!(back, p);
            for r in back
                .answers
                .iter()
                .chain(&back.authority)
                .chain(&back.additional)
            {
                assert!(!r.name.to_string().is_empty());
            }
            if p.request().is_ok() {
                let name = Name::new("W", 0x20);
                for r in [
                    p.query_response(name.clone(), 1, vec![owner(1)]),
                    p.negative_query_response(name.clone(), rcode::NAM_ERR),
                    p.node_status_response(name.clone(), vec![NodeName::unique(&name)], [0; 6]),
                    p.wack(name, 2),
                ] {
                    assert_eq!(Packet::parse(&r.to_bytes().unwrap()), Ok(r));
                }
            }
            for q in &p.questions {
                assert!(q.name.to_string().contains('<'));
            }
        }
    }

    #[test]
    fn random_buffers() {
        let mut rng = Lcg::new(0x6e62_6e73);
        let seeds = samples();
        for round in 0..6000 {
            let mut buf = if round % 2 == 0 {
                let len = rng.index(120);
                let mut b = vec![0; len];
                rng.fill(&mut b);
                // Give most a plausible header, so names get read.
                if b.len() >= 12 {
                    for i in (4..12).step_by(2) {
                        b[i] = 0;
                        b[i + 1] = rng.index(3) as u8;
                    }
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
            check(&buf);
            // The datagram as it arrives, one byte more at a time: every
            // prefix is read or refused, and never panics.
            for n in 0..buf.len() {
                check(&buf[..n]);
            }
        }
    }
}
