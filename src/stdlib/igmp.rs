//! IGMP: reading and writing multicast group membership messages, with no
//! I/O.
//!
//! IGMP (the Internet Group Management Protocol, IP protocol 2) is how an
//! IPv4 host tells the routers on its link which multicast groups it wants
//! to hear. A router sends a query, every host answers with a report for
//! each group it has joined, and a host that leaves a group says so. IGMP
//! has three versions. Version 1 has queries and reports. Version 2 adds a
//! maximum response time to queries, group-specific queries and leave
//! messages. Version 3 adds sources: a host can ask for a group's traffic
//! from some senders only, or from every sender but some. This module
//! follows RFC 2236 (versions 1 and 2) and RFC 3376 (version 3).
//!
//! Nothing here reads a socket. A world that plays a host or a router
//! hands each IGMP payload (the bytes after the IPv4 header) to
//! [`Message::parse`], looks at the [`Message`], and sends the bytes
//! [`Message::to_bytes`] returns in an IPv4 packet with protocol
//! [`PROTOCOL`], a TTL of 1 and the Router Alert option, to the address
//! [`Message::destination`] gives. A [`Decoder`] reads a message that comes
//! in pieces and reports a bad type as soon as the first byte shows it.
//! Which groups a host has joined, and what a router does with a report,
//! is up to world code.
//!
//! Every reader checks lengths and the checksum, because the agent can send
//! any bytes it likes. Bytes past the end of a message are covered by the
//! checksum and otherwise ignored, as both RFCs ask. Reserved fields and
//! the unused field of version 1 reports are ignored when read and written
//! as zero. Writers check the same rules as readers, so bytes they return
//! always read back.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use fictionet::stdlib::igmp::{ALL_SYSTEMS, Message};
//!
//! /// The reports a host that joined `groups` sends for a query.
//! fn answer(groups: &[Ipv4Addr], query: &Message) -> Vec<Message> {
//!     match query {
//!         Message::Query { group, .. } => groups
//!             .iter()
//!             .filter(|g| group.is_unspecified() || *g == group)
//!             .map(|&group| Message::ReportV2 { group })
//!             .collect(),
//!         _ => Vec::new(),
//!     }
//! }
//!
//! // An IGMPv2 general query, with a maximum response time of 10 seconds.
//! let query = Message::parse(&[0x11, 0x64, 0xee, 0x9b, 0, 0, 0, 0]).unwrap();
//! assert_eq!(query, Message::Query { max_resp_time: 100, group: Ipv4Addr::UNSPECIFIED });
//! assert_eq!(query.destination(), ALL_SYSTEMS);
//! let reports = answer(&[Ipv4Addr::new(239, 1, 2, 3)], &query);
//! assert_eq!(reports.len(), 1);
//! assert_eq!(reports[0].to_bytes().unwrap(), [0x16, 0, 0xf8, 0xfa, 239, 1, 2, 3]);
//! assert_eq!(reports[0].destination(), Ipv4Addr::new(239, 1, 2, 3));
//! ```

use std::net::Ipv4Addr;

/// The IP protocol number of IGMP.
pub const PROTOCOL: u8 = 2;
/// The longest message this module reads or writes: the most an IPv4
/// packet can carry after a 20-byte header.
pub const MAX_MESSAGE: usize = 65_515;
/// The length of a version 1 or 2 message, and of a version 3 report's
/// header.
pub const HEADER_LEN: usize = 8;
/// The length of a version 3 query before its sources.
pub const V3_QUERY_LEN: usize = 12;
/// The length of a version 3 group record before its sources.
pub const RECORD_HEADER_LEN: usize = 8;
/// The most auxiliary data a group record can carry, in bytes: 255 words
/// of 4 bytes.
pub const MAX_AUX_LEN: usize = 255 * 4;
/// The largest value the maximum response code and QQIC encodings can
/// hold. See [`decode_code`].
pub const MAX_CODE_VALUE: u32 = 31_744;
/// The largest QRV a version 3 query can carry: the field has 3 bits.
pub const MAX_QRV: u8 = 7;

/// All systems on this subnet (224.0.0.1), where general queries go.
pub const ALL_SYSTEMS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
/// All routers on this subnet (224.0.0.2), where version 2 leave messages
/// go.
pub const ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);
/// All IGMPv3-capable routers (224.0.0.22), where version 3 reports go.
pub const ALL_IGMPV3_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);

/// Message types: the first byte of every message.
pub mod kind {
    /// A membership query, of any version.
    pub const MEMBERSHIP_QUERY: u8 = 0x11;
    /// A version 1 membership report.
    pub const V1_REPORT: u8 = 0x12;
    /// A version 2 membership report.
    pub const V2_REPORT: u8 = 0x16;
    /// A version 2 leave group message.
    pub const LEAVE_GROUP: u8 = 0x17;
    /// A version 3 membership report.
    pub const V3_REPORT: u8 = 0x22;
}

/// One IGMP message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Message {
    /// A version 1 or 2 query, 8 bytes long. A `max_resp_time` of 0 makes
    /// it a version 1 query; otherwise it is version 2. A group of 0.0.0.0
    /// makes it a general query; otherwise it asks only about that group.
    Query {
        /// How long hosts may wait before they answer, in tenths of a
        /// second.
        max_resp_time: u8,
        /// The group asked about, or 0.0.0.0 for every group.
        group: Ipv4Addr,
    },
    /// A version 3 query, 12 bytes long or more.
    QueryV3(QueryV3),
    /// A version 1 report: the sender is a member of `group`.
    ReportV1 {
        /// The group joined.
        group: Ipv4Addr,
    },
    /// A version 2 report: the sender is a member of `group`.
    ReportV2 {
        /// The group joined.
        group: Ipv4Addr,
    },
    /// A version 2 leave message: the sender has left `group`.
    Leave {
        /// The group left.
        group: Ipv4Addr,
    },
    /// A version 3 report: the sender's state for some groups, or changes
    /// to it.
    ReportV3 {
        /// The group records, in order.
        records: Vec<GroupRecord>,
    },
}

/// A version 3 query.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QueryV3 {
    /// The maximum response code: how long hosts may wait before they
    /// answer, in tenths of a second, in the encoding [`decode_code`]
    /// reads.
    pub max_resp_code: u8,
    /// The group asked about, or 0.0.0.0 for every group.
    pub group: Ipv4Addr,
    /// The S flag: routers that hear the query should not lower their
    /// timers for the group.
    pub suppress: bool,
    /// The QRV: how many times the querier sends each message, to ride
    /// out lost packets. It runs from 0 to [`MAX_QRV`]. 0 means the
    /// querier's value is above 7.
    pub qrv: u8,
    /// The querier's query interval code: seconds between general
    /// queries, in the encoding [`decode_code`] reads.
    pub qqic: u8,
    /// The sources asked about. Empty for a general or group-specific
    /// query.
    pub sources: Vec<Ipv4Addr>,
}

impl QueryV3 {
    /// The maximum response time, in tenths of a second.
    pub fn max_resp_time(&self) -> u32 {
        decode_code(self.max_resp_code)
    }

    /// The querier's query interval, in seconds.
    pub fn query_interval(&self) -> u32 {
        decode_code(self.qqic)
    }
}

/// The type of a version 3 group record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// MODE_IS_INCLUDE (1): the host hears the group from the listed
    /// sources only. Sent in answer to a query.
    ModeIsInclude,
    /// MODE_IS_EXCLUDE (2): the host hears the group from every source but
    /// the listed ones. Sent in answer to a query.
    ModeIsExclude,
    /// CHANGE_TO_INCLUDE_MODE (3): the host now hears the group from the
    /// listed sources only.
    ChangeToInclude,
    /// CHANGE_TO_EXCLUDE_MODE (4): the host now hears the group from every
    /// source but the listed ones.
    ChangeToExclude,
    /// ALLOW_NEW_SOURCES (5): the host now also hears the listed sources.
    AllowNewSources,
    /// BLOCK_OLD_SOURCES (6): the host no longer hears the listed sources.
    BlockOldSources,
    /// Any other code. RFC 3376 asks receivers to skip such records. The
    /// parser never gives a code from 1 to 6 here, and the writers refuse
    /// one, since it would read back as one of the types above.
    Other(u8),
}

impl RecordType {
    /// The record type's code on the wire.
    pub fn code(self) -> u8 {
        match self {
            RecordType::ModeIsInclude => 1,
            RecordType::ModeIsExclude => 2,
            RecordType::ChangeToInclude => 3,
            RecordType::ChangeToExclude => 4,
            RecordType::AllowNewSources => 5,
            RecordType::BlockOldSources => 6,
            RecordType::Other(c) => c,
        }
    }

    /// The record type a code stands for.
    pub fn from_code(c: u8) -> RecordType {
        match c {
            1 => RecordType::ModeIsInclude,
            2 => RecordType::ModeIsExclude,
            3 => RecordType::ChangeToInclude,
            4 => RecordType::ChangeToExclude,
            5 => RecordType::AllowNewSources,
            6 => RecordType::BlockOldSources,
            c => RecordType::Other(c),
        }
    }
}

/// One group record of a version 3 report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupRecord {
    /// What the record says about the group.
    pub kind: RecordType,
    /// The multicast group.
    pub group: Ipv4Addr,
    /// The sources the record lists.
    pub sources: Vec<Ipv4Addr>,
    /// Auxiliary data: a multiple of 4 bytes, at most [`MAX_AUX_LEN`].
    /// RFC 3376 defines none, so senders leave it empty.
    pub aux: Vec<u8>,
}

/// Why bytes are not an IGMP message, or a message cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IgmpError {
    /// The bytes end before the message does.
    Truncated,
    /// The message is longer than [`MAX_MESSAGE`].
    TooLong,
    /// The checksum over the message is wrong.
    Checksum,
    /// The first byte is not a message type this module knows.
    UnknownType(u8),
    /// A query was 9 to 11 bytes long: too long for version 2 and too short
    /// for version 3. RFC 3376 asks receivers to ignore such queries.
    QueryLength(usize),
    /// A version 3 query's QRV was above [`MAX_QRV`].
    Qrv(u8),
    /// A group record's auxiliary data was not a multiple of 4 bytes, or
    /// longer than [`MAX_AUX_LEN`].
    AuxData(usize),
    /// A group record to be written had [`RecordType::Other`] with a code
    /// from 1 to 6, which would read back as a different record type.
    RecordType(u8),
}

impl std::fmt::Display for IgmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IgmpError::Truncated => write!(f, "the message is cut short"),
            IgmpError::TooLong => write!(f, "the message is longer than {MAX_MESSAGE} bytes"),
            IgmpError::Checksum => write!(f, "the checksum is wrong"),
            IgmpError::UnknownType(t) => write!(f, "unknown message type {t:#04x}"),
            IgmpError::QueryLength(n) => write!(f, "a query of {n} bytes, neither 8 nor at least 12"),
            IgmpError::Qrv(q) => write!(f, "QRV {q}, above {MAX_QRV}"),
            IgmpError::AuxData(n) => {
                write!(f, "{n} bytes of auxiliary data, not a multiple of 4 up to {MAX_AUX_LEN}")
            }
            IgmpError::RecordType(c) => write!(f, "record type Other({c}), a code that has its own type"),
        }
    }
}

impl std::error::Error for IgmpError {}

/// The value a maximum response code or QQIC stands for. Codes below 128
/// are the value itself. A code of 128 or more is a float: 1, a 3-bit
/// exponent and a 4-bit mantissa, read as `(mantissa | 0x10) << (exponent
/// + 3)`, from 128 up to [`MAX_CODE_VALUE`].
pub fn decode_code(code: u8) -> u32 {
    if code < 128 {
        u32::from(code)
    } else {
        let exp = u32::from((code >> 4) & 0x07);
        let mant = u32::from(code & 0x0f);
        (mant | 0x10) << (exp + 3)
    }
}

/// The code for `value`, for a maximum response code or QQIC. Values below
/// 128 are exact. Larger values round down to the nearest value a code can
/// hold, and values above [`MAX_CODE_VALUE`] become the largest code.
pub fn encode_code(value: u32) -> u8 {
    if value < 128 {
        return value as u8;
    }
    if value >= MAX_CODE_VALUE {
        return 0xff;
    }
    for exp in 0..8u32 {
        let m = value >> (exp + 3);
        if (16..32).contains(&m) {
            return 0x80 | ((exp as u8) << 4) | ((m - 16) as u8);
        }
    }
    0xff
}

/// The Internet checksum of `b`: the ones' complement of the ones'
/// complement sum of its 16-bit words, with a zero byte added to an odd
/// length. A message with a correct checksum field sums to 0.
pub fn checksum(b: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut words = b.chunks_exact(2);
    for w in &mut words {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = words.remainder() {
        sum += u64::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn known_type(t: u8) -> bool {
    matches!(t, kind::MEMBERSHIP_QUERY | kind::V1_REPORT | kind::V2_REPORT | kind::LEAVE_GROUP | kind::V3_REPORT)
}

fn addr(b: &[u8], i: usize) -> Option<Ipv4Addr> {
    let s = b.get(i..i.checked_add(4)?)?;
    Some(Ipv4Addr::new(s[0], s[1], s[2], s[3]))
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    let s = b.get(i..i.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

/// `n` addresses starting at `at`, and where they end.
fn addrs(b: &[u8], at: usize, n: usize) -> Result<(Vec<Ipv4Addr>, usize), IgmpError> {
    let end = n.checked_mul(4).and_then(|l| l.checked_add(at)).ok_or(IgmpError::Truncated)?;
    let s = b.get(at..end).ok_or(IgmpError::Truncated)?;
    let out = s.chunks_exact(4).map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3])).collect();
    Ok((out, end))
}

impl Message {
    /// Reads the message in `b`, the whole IGMP payload of one IPv4
    /// packet. The checksum must be right. Bytes past the end of the
    /// message are ignored.
    pub fn parse(b: &[u8]) -> Result<Message, IgmpError> {
        let &t = b.first().ok_or(IgmpError::Truncated)?;
        if !known_type(t) {
            return Err(IgmpError::UnknownType(t));
        }
        if b.len() > MAX_MESSAGE {
            return Err(IgmpError::TooLong);
        }
        if b.len() < HEADER_LEN {
            return Err(IgmpError::Truncated);
        }
        if checksum(b) != 0 {
            return Err(IgmpError::Checksum);
        }
        let group = addr(b, 4).ok_or(IgmpError::Truncated)?;
        match t {
            kind::MEMBERSHIP_QUERY => match b.len() {
                HEADER_LEN => Ok(Message::Query { max_resp_time: b[1], group }),
                n if n < V3_QUERY_LEN => Err(IgmpError::QueryLength(n)),
                _ => {
                    let n = usize::from(be16(b, 10).ok_or(IgmpError::Truncated)?);
                    let (sources, _) = addrs(b, V3_QUERY_LEN, n)?;
                    Ok(Message::QueryV3(QueryV3 {
                        max_resp_code: b[1],
                        group,
                        suppress: b[8] & 0x08 != 0,
                        qrv: b[8] & 0x07,
                        qqic: b[9],
                        sources,
                    }))
                }
            },
            kind::V1_REPORT => Ok(Message::ReportV1 { group }),
            kind::V2_REPORT => Ok(Message::ReportV2 { group }),
            kind::LEAVE_GROUP => Ok(Message::Leave { group }),
            _ => {
                let m = usize::from(be16(b, 6).ok_or(IgmpError::Truncated)?);
                // Each record takes at least 8 bytes, so the bytes bound
                // what is allocated, whatever the count says.
                let mut records = Vec::with_capacity(m.min((b.len() - HEADER_LEN) / RECORD_HEADER_LEN));
                let mut at = HEADER_LEN;
                for _ in 0..m {
                    let head = b.get(at..at + RECORD_HEADER_LEN).ok_or(IgmpError::Truncated)?;
                    let aux_len = usize::from(head[1]) * 4;
                    let n = usize::from(u16::from_be_bytes([head[2], head[3]]));
                    let group = Ipv4Addr::new(head[4], head[5], head[6], head[7]);
                    let (sources, end) = addrs(b, at + RECORD_HEADER_LEN, n)?;
                    let aux_end = end.checked_add(aux_len).ok_or(IgmpError::Truncated)?;
                    let aux = b.get(end..aux_end).ok_or(IgmpError::Truncated)?.to_vec();
                    records.push(GroupRecord { kind: RecordType::from_code(head[0]), group, sources, aux });
                    at = aux_end;
                }
                Ok(Message::ReportV3 { records })
            }
        }
    }

    /// The message's type byte.
    pub fn kind(&self) -> u8 {
        match self {
            Message::Query { .. } | Message::QueryV3(_) => kind::MEMBERSHIP_QUERY,
            Message::ReportV1 { .. } => kind::V1_REPORT,
            Message::ReportV2 { .. } => kind::V2_REPORT,
            Message::Leave { .. } => kind::LEAVE_GROUP,
            Message::ReportV3 { .. } => kind::V3_REPORT,
        }
    }

    /// The IGMP version the message belongs to: 1, 2 or 3.
    pub fn version(&self) -> u8 {
        match self {
            Message::Query { max_resp_time: 0, .. } | Message::ReportV1 { .. } => 1,
            Message::Query { .. } | Message::ReportV2 { .. } | Message::Leave { .. } => 2,
            Message::QueryV3(_) | Message::ReportV3 { .. } => 3,
        }
    }

    /// Where the message is sent: a general query to [`ALL_SYSTEMS`], a
    /// group-specific query or a version 1 or 2 report to its group, a
    /// leave message to [`ALL_ROUTERS`], and a version 3 report to
    /// [`ALL_IGMPV3_ROUTERS`].
    pub fn destination(&self) -> Ipv4Addr {
        match self {
            Message::Query { group, .. } | Message::QueryV3(QueryV3 { group, .. }) => {
                if group.is_unspecified() {
                    ALL_SYSTEMS
                } else {
                    *group
                }
            }
            Message::ReportV1 { group } | Message::ReportV2 { group } => *group,
            Message::Leave { .. } => ALL_ROUTERS,
            Message::ReportV3 { .. } => ALL_IGMPV3_ROUTERS,
        }
    }

    /// How many bytes [`Message::to_bytes`] writes, or why it cannot write
    /// the message.
    pub fn encoded_len(&self) -> Result<usize, IgmpError> {
        let n = match self {
            Message::QueryV3(q) => {
                if q.qrv > MAX_QRV {
                    return Err(IgmpError::Qrv(q.qrv));
                }
                q.sources.len().checked_mul(4).and_then(|l| l.checked_add(V3_QUERY_LEN))
            }
            Message::ReportV3 { records } => {
                let mut n = Some(HEADER_LEN);
                for r in records {
                    if let RecordType::Other(c @ 1..=6) = r.kind {
                        return Err(IgmpError::RecordType(c));
                    }
                    if r.aux.len() % 4 != 0 || r.aux.len() > MAX_AUX_LEN {
                        return Err(IgmpError::AuxData(r.aux.len()));
                    }
                    n = n
                        .and_then(|n| n.checked_add(RECORD_HEADER_LEN))
                        .and_then(|n| n.checked_add(r.sources.len().checked_mul(4)?))
                        .and_then(|n| n.checked_add(r.aux.len()))
                        .filter(|&n| n <= MAX_MESSAGE);
                }
                n
            }
            _ => Some(HEADER_LEN),
        };
        // A count above 65535 needs more than MAX_MESSAGE bytes, so this
        // also keeps every count within its 16 bits.
        n.filter(|&n| n <= MAX_MESSAGE).ok_or(IgmpError::TooLong)
    }

    /// The message's bytes, with the checksum filled in. It fails if the
    /// message would be longer than [`MAX_MESSAGE`], a QRV is above
    /// [`MAX_QRV`], auxiliary data has a bad length, or a record type is
    /// [`RecordType::Other`] with a code from 1 to 6. Nothing is
    /// allocated before those checks pass.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IgmpError> {
        let len = self.encoded_len()?;
        let mut out = Vec::with_capacity(len);
        out.push(self.kind());
        let (code, group) = match self {
            Message::Query { max_resp_time, group } => (*max_resp_time, *group),
            Message::QueryV3(q) => (q.max_resp_code, q.group),
            Message::ReportV1 { group } | Message::ReportV2 { group } | Message::Leave { group } => (0, *group),
            Message::ReportV3 { .. } => (0, Ipv4Addr::UNSPECIFIED),
        };
        out.push(code);
        out.extend_from_slice(&[0, 0]);
        match self {
            Message::ReportV3 { records } => {
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&(records.len() as u16).to_be_bytes());
                for r in records {
                    out.push(r.kind.code());
                    out.push((r.aux.len() / 4) as u8);
                    out.extend_from_slice(&(r.sources.len() as u16).to_be_bytes());
                    out.extend_from_slice(&r.group.octets());
                    for s in &r.sources {
                        out.extend_from_slice(&s.octets());
                    }
                    out.extend_from_slice(&r.aux);
                }
            }
            Message::QueryV3(q) => {
                out.extend_from_slice(&group.octets());
                out.push(if q.suppress { 0x08 } else { 0 } | q.qrv);
                out.push(q.qqic);
                out.extend_from_slice(&(q.sources.len() as u16).to_be_bytes());
                for s in &q.sources {
                    out.extend_from_slice(&s.octets());
                }
            }
            _ => out.extend_from_slice(&group.octets()),
        }
        let c = checksum(&out);
        out[2..4].copy_from_slice(&c.to_be_bytes());
        Ok(out)
    }
}

/// Reads one message that comes in pieces. Feed it the bytes in order,
/// then call [`Decoder::finish`]. It fails as soon as the first byte shows
/// an unknown type, or the bytes run past [`MAX_MESSAGE`]. It holds at
/// most [`MAX_MESSAGE`] plus one bytes.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    failed: Option<IgmpError>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds the next bytes of the message. It returns the error once the
    /// bytes show one, and the same error on every later call; bytes fed
    /// after that are dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), IgmpError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        // One byte past the limit is enough to know the message is too long.
        let room = (MAX_MESSAGE + 1).saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        if let Some(&t) = self.buf.first()
            && !known_type(t) {
                return Err(self.fail(IgmpError::UnknownType(t)));
            }
        if self.buf.len() > MAX_MESSAGE {
            return Err(self.fail(IgmpError::TooLong));
        }
        Ok(())
    }

    fn fail(&mut self, e: IgmpError) -> IgmpError {
        self.failed = Some(e);
        self.buf = Vec::new();
        e
    }

    /// How many bytes are held.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The message, when no more bytes will come. It gives the same result
    /// as [`Message::parse`] on all the bytes fed.
    pub fn finish(self) -> Result<Message, IgmpError> {
        match self.failed {
            Some(e) => Err(e),
            None => Message::parse(&self.buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// `b` with its checksum field set right.
    fn fix(mut b: Vec<u8>) -> Vec<u8> {
        if b.len() >= 4 {
            b[2] = 0;
            b[3] = 0;
            let c = checksum(&b);
            b[2..4].copy_from_slice(&c.to_be_bytes());
        }
        b
    }

    fn decode_bytewise(b: &[u8]) -> Result<Message, IgmpError> {
        let mut d = Decoder::new();
        for x in b {
            if d.feed(std::slice::from_ref(x)).is_err() {
                break;
            }
        }
        d.finish()
    }

    fn decode_whole(b: &[u8]) -> Result<Message, IgmpError> {
        let mut d = Decoder::new();
        let _ = d.feed(b);
        d.finish()
    }

    fn decode_chunked(b: &[u8], size: usize) -> Result<Message, IgmpError> {
        let mut d = Decoder::new();
        for chunk in b.chunks(size) {
            if d.feed(chunk).is_err() {
                break;
            }
        }
        d.finish()
    }

    fn round_trip(m: &Message) -> Vec<u8> {
        let b = m.to_bytes().unwrap();
        assert_eq!(b.len(), m.encoded_len().unwrap());
        assert_eq!(checksum(&b), 0);
        assert_eq!(Message::parse(&b).as_ref(), Ok(m));
        assert_eq!(decode_bytewise(&b).as_ref(), Ok(m));
        b
    }

    // A general query as routers send it: version 2, 10 seconds.

    #[test]
    fn v2_general_query_example() {
        let b = [0x11, 0x64, 0xee, 0x9b, 0, 0, 0, 0];
        let m = Message::parse(&b).unwrap();
        assert_eq!(m, Message::Query { max_resp_time: 100, group: Ipv4Addr::UNSPECIFIED });
        assert_eq!(m.version(), 2);
        assert_eq!(m.destination(), ALL_SYSTEMS);
        assert_eq!(m.to_bytes().unwrap(), b);
    }

    #[test]
    fn v1_query_has_a_zero_code() {
        let m = Message::Query { max_resp_time: 0, group: Ipv4Addr::UNSPECIFIED };
        let b = round_trip(&m);
        assert_eq!(b, [0x11, 0, 0xee, 0xff, 0, 0, 0, 0]);
        assert_eq!(m.version(), 1);
    }

    #[test]
    fn group_specific_query_goes_to_the_group() {
        let m = Message::Query { max_resp_time: 10, group: ip(239, 1, 2, 3) };
        round_trip(&m);
        assert_eq!(m.destination(), ip(239, 1, 2, 3));
    }

    #[test]
    fn reports_and_leave() {
        let g = ip(239, 1, 2, 3);
        let b = round_trip(&Message::ReportV2 { group: g });
        assert_eq!(b, [0x16, 0, 0xf8, 0xfa, 239, 1, 2, 3]);
        let b = round_trip(&Message::ReportV1 { group: g });
        assert_eq!(&b[..2], [0x12, 0]);
        let leave = Message::Leave { group: g };
        let b = round_trip(&leave);
        assert_eq!(&b[..2], [0x17, 0]);
        assert_eq!(leave.destination(), ALL_ROUTERS);
        assert_eq!(leave.version(), 2);
        assert_eq!(Message::ReportV1 { group: g }.version(), 1);
        assert_eq!(Message::ReportV1 { group: g }.destination(), g);
    }

    #[test]
    fn unused_fields_are_ignored() {
        // A version 2 report with a nonzero max response time field, which
        // receivers ignore.
        let b = fix(vec![0x16, 0x55, 0, 0, 239, 1, 2, 3]);
        assert_eq!(Message::parse(&b), Ok(Message::ReportV2 { group: ip(239, 1, 2, 3) }));
        // A version 3 report with its reserved fields set.
        let b = fix(vec![0x22, 0xaa, 0, 0, 0xbb, 0xcc, 0, 0]);
        assert_eq!(Message::parse(&b), Ok(Message::ReportV3 { records: vec![] }));
    }

    #[test]
    fn v3_query_layout() {
        let q = QueryV3 {
            max_resp_code: 0x8a,
            group: ip(232, 1, 1, 1),
            suppress: true,
            qrv: 2,
            qqic: 125,
            sources: vec![ip(10, 0, 0, 1), ip(10, 0, 0, 2)],
        };
        let m = Message::QueryV3(q.clone());
        let b = round_trip(&m);
        assert_eq!(b.len(), 20);
        assert_eq!(&b[..2], [0x11, 0x8a]);
        assert_eq!(&b[4..12], [232, 1, 1, 1, 0x0a, 125, 0, 2]);
        assert_eq!(&b[12..], [10, 0, 0, 1, 10, 0, 0, 2]);
        assert_eq!(q.max_resp_time(), (0x1a) << 3);
        assert_eq!(q.query_interval(), 125);
        assert_eq!(m.version(), 3);
        assert_eq!(m.destination(), ip(232, 1, 1, 1));
    }

    #[test]
    fn v3_general_query_is_12_bytes() {
        let q = QueryV3 {
            max_resp_code: 100,
            group: Ipv4Addr::UNSPECIFIED,
            suppress: false,
            qrv: 7,
            qqic: 0xff,
            sources: vec![],
        };
        let m = Message::QueryV3(q);
        let b = round_trip(&m);
        assert_eq!(b.len(), V3_QUERY_LEN);
        assert_eq!(b[8], 7);
        assert_eq!(m.destination(), ALL_SYSTEMS);
    }

    #[test]
    fn v3_query_reserved_bits_are_ignored() {
        let b = fix(vec![0x11, 1, 0, 0, 0, 0, 0, 0, 0xf3, 9, 0, 0]);
        let Message::QueryV3(q) = Message::parse(&b).unwrap() else { panic!() };
        assert!(!q.suppress);
        assert_eq!(q.qrv, 3);
    }

    fn every_record_type() -> Vec<GroupRecord> {
        let kinds = [
            RecordType::ModeIsInclude,
            RecordType::ModeIsExclude,
            RecordType::ChangeToInclude,
            RecordType::ChangeToExclude,
            RecordType::AllowNewSources,
            RecordType::BlockOldSources,
            RecordType::Other(0),
            RecordType::Other(200),
        ];
        kinds
            .iter()
            .enumerate()
            .map(|(i, &kind)| GroupRecord {
                kind,
                group: ip(239, 0, 0, i as u8),
                sources: (0..i as u8).map(|s| ip(192, 0, 2, s)).collect(),
                aux: if i == 3 { vec![1, 2, 3, 4, 5, 6, 7, 8] } else { vec![] },
            })
            .collect()
    }

    #[test]
    fn v3_report_with_every_record_type() {
        let m = Message::ReportV3 { records: every_record_type() };
        let b = round_trip(&m);
        assert_eq!(&b[..2], [0x22, 0]);
        assert_eq!(&b[4..8], [0, 0, 0, 8]);
        // The first record: MODE_IS_INCLUDE, no aux data, no sources.
        assert_eq!(&b[8..16], [1, 0, 0, 0, 239, 0, 0, 0]);
        // The second: MODE_IS_EXCLUDE with one source.
        assert_eq!(&b[16..28], [2, 0, 0, 1, 239, 0, 0, 1, 192, 0, 2, 0]);
        assert_eq!(m.destination(), ALL_IGMPV3_ROUTERS);
        assert_eq!(m.version(), 3);
        for c in 0..=255u8 {
            assert_eq!(RecordType::from_code(c).code(), c);
        }
    }

    #[test]
    fn code_encoding() {
        assert_eq!(decode_code(0), 0);
        assert_eq!(decode_code(127), 127);
        assert_eq!(decode_code(0x80), 128);
        assert_eq!(decode_code(0x8f), 31 << 3);
        assert_eq!(decode_code(0x90), 16 << 4);
        assert_eq!(decode_code(0xff), MAX_CODE_VALUE);
        for c in 0..=255u8 {
            assert_eq!(encode_code(decode_code(c)), c);
        }
        for v in [0u32, 1, 127, 128, 129, 255, 256, 1000, 31_743, 31_744, 40_000, u32::MAX] {
            let d = decode_code(encode_code(v));
            assert!(d <= v);
            if v < 128 {
                assert_eq!(d, v);
            }
        }
        assert_eq!(encode_code(u32::MAX), 0xff);
        assert_eq!(encode_code(1000), 0xaf);
        assert_eq!(decode_code(0xaf), 31 << 5);
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let mut b = Message::ReportV2 { group: ip(239, 9, 9, 9) }.to_bytes().unwrap();
        b.extend_from_slice(&[1, 2, 3, 4, 5]);
        let b = fix(b);
        assert_eq!(Message::parse(&b), Ok(Message::ReportV2 { group: ip(239, 9, 9, 9) }));
        let q = QueryV3 { max_resp_code: 1, group: ip(0, 0, 0, 0), suppress: false, qrv: 1, qqic: 1, sources: vec![] };
        let mut b = Message::QueryV3(q.clone()).to_bytes().unwrap();
        b.extend_from_slice(&[9; 3]);
        assert_eq!(Message::parse(&fix(b)), Ok(Message::QueryV3(q)));
        // The extra bytes are in the checksum.
        let mut b = Message::Leave { group: ip(239, 1, 1, 1) }.to_bytes().unwrap();
        b.push(1);
        assert_eq!(Message::parse(&b), Err(IgmpError::Checksum));
    }

    #[test]
    fn error_paths() {
        assert_eq!(Message::parse(&[]), Err(IgmpError::Truncated));
        assert_eq!(Message::parse(&[0x11]), Err(IgmpError::Truncated));
        assert_eq!(Message::parse(&[0x11, 0, 0, 0, 0, 0, 0]), Err(IgmpError::Truncated));
        assert_eq!(Message::parse(&[0x13, 0, 0, 0, 0, 0, 0, 0]), Err(IgmpError::UnknownType(0x13)));
        assert_eq!(Message::parse(&[0x00]), Err(IgmpError::UnknownType(0)));
        assert_eq!(Message::parse(&vec![0x22; MAX_MESSAGE + 1]), Err(IgmpError::TooLong));
        assert_eq!(Message::parse(&[0x16, 0, 0, 0, 239, 1, 2, 3]), Err(IgmpError::Checksum));
        for n in 9..12 {
            let b = fix(vec![0x11; n]);
            assert_eq!(Message::parse(&b), Err(IgmpError::QueryLength(n)));
        }
        // A v3 query that says 2 sources and holds 1.
        let b = fix(vec![0x11, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 10, 0, 0, 1]);
        assert_eq!(Message::parse(&b), Err(IgmpError::Truncated));
        // A v3 report that says 1 record and holds none.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(Message::parse(&b), Err(IgmpError::Truncated));
        // A record that says 1 source and holds none.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 239, 0, 0, 1]);
        assert_eq!(Message::parse(&b), Err(IgmpError::Truncated));
        // A record that says 1 word of aux data and holds 2 bytes.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 239, 0, 0, 1, 0, 0]);
        assert_eq!(Message::parse(&b), Err(IgmpError::Truncated));
        // A record count of 65535 with no records.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(Message::parse(&b), Err(IgmpError::Truncated));
    }

    #[test]
    fn writer_errors() {
        let q = QueryV3 { max_resp_code: 0, group: ip(0, 0, 0, 0), suppress: false, qrv: 8, qqic: 0, sources: vec![] };
        assert_eq!(Message::QueryV3(q.clone()).to_bytes(), Err(IgmpError::Qrv(8)));
        let big = QueryV3 { qrv: 0, sources: vec![ip(1, 1, 1, 1); 20_000], ..q };
        assert_eq!(Message::QueryV3(big.clone()).to_bytes(), Err(IgmpError::TooLong));
        let fits = QueryV3 { sources: vec![ip(1, 1, 1, 1); (MAX_MESSAGE - V3_QUERY_LEN) / 4], ..big };
        let b = round_trip(&Message::QueryV3(fits));
        assert!(b.len() <= MAX_MESSAGE);
        let r = |aux: Vec<u8>| GroupRecord { kind: RecordType::ModeIsInclude, group: ip(239, 0, 0, 1), sources: vec![], aux };
        for aux in [vec![0; 3], vec![0; MAX_AUX_LEN + 4]] {
            let n = aux.len();
            assert_eq!(Message::ReportV3 { records: vec![r(aux)] }.to_bytes(), Err(IgmpError::AuxData(n)));
        }
        round_trip(&Message::ReportV3 { records: vec![r(vec![7; MAX_AUX_LEN])] });
        let many = Message::ReportV3 { records: vec![r(vec![]); 10_000] };
        assert_eq!(many.to_bytes(), Err(IgmpError::TooLong));
        let most = Message::ReportV3 { records: vec![r(vec![]); (MAX_MESSAGE - HEADER_LEN) / RECORD_HEADER_LEN] };
        round_trip(&most);
    }

    #[test]
    fn other_record_type_must_not_hide_a_known_code() {
        // Other(3) would be written as code 3 and read back as
        // ChangeToInclude, a different message.
        for c in 1..=6u8 {
            let r = GroupRecord { kind: RecordType::Other(c), group: ip(239, 0, 0, 1), sources: vec![], aux: vec![] };
            let m = Message::ReportV3 { records: vec![r] };
            assert_eq!(m.to_bytes(), Err(IgmpError::RecordType(c)));
            assert_eq!(m.encoded_len(), Err(IgmpError::RecordType(c)));
        }
    }

    #[test]
    fn largest_inputs_parse_in_one_pass() {
        // The most records a message can hold, each empty, read back.
        let n = (MAX_MESSAGE - HEADER_LEN) / RECORD_HEADER_LEN;
        let mut b = vec![0x22, 0, 0, 0, 0, 0];
        b.extend_from_slice(&(n as u16).to_be_bytes());
        for _ in 0..n {
            b.extend_from_slice(&[1, 0, 0, 0, 239, 0, 0, 1]);
        }
        let Message::ReportV3 { records } = Message::parse(&fix(b)).unwrap() else { panic!() };
        assert_eq!(records.len(), n);
        // A count and a source count that claim far more than the bytes
        // hold fail without a large allocation.
        let mut b = vec![0x22, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 0xff, 0xff, 0xff, 239, 0, 0, 1];
        b.resize(MAX_MESSAGE, 0);
        assert_eq!(Message::parse(&fix(b)), Err(IgmpError::Truncated));
        // A large chunk of unknown type fails on its type, as parse does.
        let big = vec![0x99; MAX_MESSAGE * 2];
        assert_eq!(Message::parse(&big), Err(IgmpError::UnknownType(0x99)));
        assert_eq!(decode_whole(&big), Err(IgmpError::UnknownType(0x99)));
        assert_eq!(decode_whole(&vec![0x11; MAX_MESSAGE * 2]), Err(IgmpError::TooLong));
    }

    #[test]
    fn messages_can_be_hashed() {
        let set: std::collections::HashSet<Message> = samples().into_iter().collect();
        assert_eq!(set.len(), samples().len());
        let kinds: std::collections::HashSet<RecordType> = (0..=255u8).map(RecordType::from_code).collect();
        assert_eq!(kinds.len(), 256);
    }

    #[test]
    fn errors_display() {
        let all = [
            IgmpError::Truncated,
            IgmpError::TooLong,
            IgmpError::Checksum,
            IgmpError::UnknownType(1),
            IgmpError::QueryLength(9),
            IgmpError::Qrv(9),
            IgmpError::AuxData(3),
            IgmpError::RecordType(1),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
    }

    fn samples() -> Vec<Message> {
        vec![
            Message::Query { max_resp_time: 100, group: Ipv4Addr::UNSPECIFIED },
            Message::Query { max_resp_time: 0, group: ip(239, 1, 1, 1) },
            Message::ReportV1 { group: ip(239, 1, 1, 1) },
            Message::ReportV2 { group: ip(239, 1, 1, 2) },
            Message::Leave { group: ip(239, 1, 1, 3) },
            Message::QueryV3(QueryV3 {
                max_resp_code: 0xc3,
                group: ip(232, 0, 0, 9),
                suppress: true,
                qrv: 5,
                qqic: 0x90,
                sources: vec![ip(10, 1, 1, 1), ip(10, 2, 2, 2), ip(10, 3, 3, 3)],
            }),
            Message::ReportV3 { records: every_record_type() },
        ]
    }

    #[test]
    fn every_truncated_prefix_fails() {
        for m in samples() {
            let b = m.to_bytes().unwrap();
            for n in 0..b.len() {
                let p = &b[..n];
                assert!(Message::parse(p).is_err(), "{m:?} prefix {n}");
                assert_eq!(decode_bytewise(p), Message::parse(p));
                // With the checksum fixed, a prefix still fails, unless it
                // happens to be a whole shorter message (a v3 query cut to
                // 8 bytes reads as a v2 query).
                let fixed = fix(p.to_vec());
                if let Ok(short) = Message::parse(&fixed) {
                    assert!(matches!(short, Message::Query { .. }) && n == HEADER_LEN, "{m:?} prefix {n}");
                }
            }
        }
    }

    #[test]
    fn decoder_matches_parse() {
        for m in samples() {
            let b = m.to_bytes().unwrap();
            assert_eq!(decode_whole(&b), Ok(m.clone()));
            for size in 1..6 {
                assert_eq!(decode_chunked(&b, size), Ok(m.clone()));
            }
        }
        // An unknown type fails at the first byte, and stays failed.
        let mut d = Decoder::new();
        assert_eq!(d.feed(&[0x99]), Err(IgmpError::UnknownType(0x99)));
        assert_eq!(d.feed(&[0x11]), Err(IgmpError::UnknownType(0x99)));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.finish(), Err(IgmpError::UnknownType(0x99)));
        // Too many bytes fail, and the decoder holds no more than allowed.
        let mut d = Decoder::new();
        assert_eq!(d.feed(&vec![0x22; MAX_MESSAGE]), Ok(()));
        assert_eq!(d.buffered(), MAX_MESSAGE);
        assert_eq!(d.feed(&[0; 100]), Err(IgmpError::TooLong));
        assert_eq!(d.finish(), Err(IgmpError::TooLong));
        assert_eq!(Decoder::new().finish(), Err(IgmpError::Truncated));
    }

    /// A deterministic pseudo-random generator for the fuzz loops.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
        fn addr(&mut self) -> Ipv4Addr {
            Ipv4Addr::from(self.next())
        }
        fn addrs(&mut self, n: usize) -> Vec<Ipv4Addr> {
            (0..self.below(n)).map(|_| self.addr()).collect()
        }
    }

    /// A random message the writer accepts.
    fn random_message(rng: &mut Lcg) -> Message {
        match rng.below(6) {
            0 => Message::Query { max_resp_time: rng.next() as u8, group: rng.addr() },
            1 => Message::ReportV1 { group: rng.addr() },
            2 => Message::ReportV2 { group: rng.addr() },
            3 => Message::Leave { group: rng.addr() },
            4 => Message::QueryV3(QueryV3 {
                max_resp_code: rng.next() as u8,
                group: rng.addr(),
                suppress: rng.below(2) == 0,
                qrv: rng.below(8) as u8,
                qqic: rng.next() as u8,
                sources: rng.addrs(8),
            }),
            _ => {
                let n = rng.below(5);
                let records = (0..n)
                    .map(|_| GroupRecord {
                        kind: RecordType::from_code(rng.below(9) as u8),
                        group: rng.addr(),
                        sources: rng.addrs(5),
                        aux: (0..rng.below(3) * 4).map(|_| rng.next() as u8).collect(),
                    })
                    .collect();
                Message::ReportV3 { records }
            }
        }
    }

    fn check_bytes(data: &[u8]) {
        let parsed = Message::parse(data);
        if let Ok(m) = &parsed {
            // A message read can be written, and reads back the same.
            let out = m.to_bytes().unwrap();
            assert!(out.len() <= data.len());
            assert_eq!(Message::parse(&out).as_ref(), Ok(m));
        }
        assert_eq!(decode_whole(data), parsed);
        assert_eq!(decode_bytewise(data), parsed);
        assert_eq!(decode_chunked(data, data.len() % 7 + 2), parsed);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x1906_2236_3376);
        for _ in 0..4000 {
            let m = random_message(&mut rng);
            let b = round_trip(&m);
            check_bytes(&b);
            // Flip some bytes, cut or extend, and fix the checksum most of
            // the time so the parser looks past it.
            let mut mutated = b.clone();
            for _ in 0..rng.below(4) {
                let i = rng.below(mutated.len());
                mutated[i] = rng.next() as u8;
            }
            match rng.below(4) {
                0 => mutated.truncate(rng.below(mutated.len() + 1)),
                1 => mutated.extend((0..rng.below(12)).map(|_| rng.next() as u8)),
                _ => {}
            }
            if rng.below(4) != 0 {
                mutated = fix(mutated);
            }
            check_bytes(&mutated);
            // Plain random bytes, with a known type and a right checksum.
            let n = rng.below(40);
            let mut raw: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            if let Some(t) = raw.first_mut() {
                *t = [0x11, 0x12, 0x16, 0x17, 0x22, rng.next() as u8][rng.below(6)];
            }
            check_bytes(&fix(raw));
        }
    }
}
