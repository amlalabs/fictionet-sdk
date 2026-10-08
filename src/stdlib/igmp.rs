//! IGMP: reading and writing multicast group membership messages, with no
//! I/O.
//!
//! `Message` reads and writes complete multicast membership messages through
//! `Wire`. There is no protocol stream decoder, membership state machine,
//! querier timer, or `Service`. The caller maintains groups and sends IP
//! packets.
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
//! [`Message::receive`], looks at the [`Message`], and sends the bytes
//! [`Message::to_bytes`] returns in an IPv4 packet with protocol
//! [`PROTOCOL`], a TTL of 1 and the Router Alert option, to the address
//! [`Message::destination`] gives. For pieces of one payload, use
//! [`Stream<Collect<Message>>`](fictionet::stdlib::codec::Stream)
//! and [`MAX_MESSAGE`] as the collection limit. Call `end` at the IPv4 boundary.
//! This collection uses the strict [`Message::parse`] reader.
//! Which groups a host has joined, and what a router does with a report,
//! is up to world code.
//!
//! Every reader checks lengths and the checksum, because the agent can send
//! any bytes it likes. Bytes past the message and its declared auxiliary
//! data are included in the checksum and ignored by [`Message::receive`].
//! [`Message::parse`] refuses them. Reserved fields and
//! the unused field of version 1 reports are ignored when read and written
//! as zero. So is the group field of a version 1 query, which RFC 1112
//! says is zero when sent and ignored when read. Auxiliary data in a
//! version 3 group record is skipped, since RFC 3376 defines none and says
//! receivers ignore it and senders never send it.
//!
//! Readers and writers also check what each address is for. A group in a
//! report, a leave message or a group record must be a multicast address.
//! A query's group must be multicast, or 0.0.0.0 for a general query. A
//! source must be a unicast address: not multicast, not 0.0.0.0 and not
//! 255.255.255.255. A version 3 general query lists no sources. Writers
//! check the same rules as readers, so bytes they return always read back.
//!
//! A host answers a query in the version the query came in: a version 1
//! query with version 1 reports, a version 2 query with version 2 reports,
//! and a version 3 query with one version 3 report. The example is a host
//! that has joined some groups from every source.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use std::net::Ipv4Addr;
//! use fictionet::stdlib::igmp::{ALL_SYSTEMS, GroupRecord, Message, QueryV3, RecordType};
//!
//! /// The reports a host that joined `groups`, from every source, sends
//! /// for a query.
//! fn answer(groups: &[Ipv4Addr], query: &Message) -> Vec<Message> {
//!     // The joined groups a query asks about.
//!     let asked = |asked: Ipv4Addr| -> Vec<Ipv4Addr> {
//!         groups.iter().copied().filter(|&g| asked.is_unspecified() || g == asked).collect()
//!     };
//!     match query {
//!         Message::Query { max_resp_time: 0, .. } => {
//!             asked(Ipv4Addr::UNSPECIFIED).into_iter().map(|group| Message::ReportV1 { group }).collect()
//!         }
//!         Message::Query { group, .. } => asked(*group).into_iter().map(|group| Message::ReportV2 { group }).collect(),
//!         Message::QueryV3(QueryV3 { group, sources, .. }) => {
//!             // Joined from every source is EXCLUDE mode with nothing
//!             // excluded. Asked about some sources, the host hears them
//!             // all (RFC 3376, section 5.2).
//!             let records: Vec<GroupRecord> = asked(*group)
//!                 .into_iter()
//!                 .map(|group| {
//!                     if sources.is_empty() {
//!                         GroupRecord { kind: RecordType::ModeIsExclude, group, sources: vec![] }
//!                     } else {
//!                         GroupRecord { kind: RecordType::ModeIsInclude, group, sources: sources.clone() }
//!                     }
//!                 })
//!                 .collect();
//!             if records.is_empty() { vec![] } else { vec![Message::ReportV3 { records }] }
//!         }
//!         _ => vec![],
//!     }
//! }
//!
//! let joined = [Ipv4Addr::new(239, 1, 2, 3)];
//! // An IGMPv2 general query, with a maximum response time of 10 seconds.
//! let query = Message::parse(&[0x11, 0x64, 0xee, 0x9b, 0, 0, 0, 0]).unwrap();
//! assert_eq!(query, Message::Query { max_resp_time: 100, group: Ipv4Addr::UNSPECIFIED });
//! assert_eq!(query.destination(), ALL_SYSTEMS);
//! let reports = answer(&joined, &query);
//! assert_eq!(reports.len(), 1);
//! assert_eq!(reports[0].to_bytes().unwrap(), [0x16, 0, 0xf8, 0xfa, 239, 1, 2, 3]);
//! assert_eq!(reports[0].destination(), Ipv4Addr::new(239, 1, 2, 3));
//! // An IGMPv1 query gets a version 1 report.
//! let query = Message::parse(&[0x11, 0, 0xee, 0xff, 0, 0, 0, 0]).unwrap();
//! assert_eq!(answer(&joined, &query), [Message::ReportV1 { group: joined[0] }]);
//! // An IGMPv3 general query gets one version 3 report.
//! let query = Message::parse(&[0x11, 0x64, 0xec, 0x1e, 0, 0, 0, 0, 0x02, 0x7d, 0, 0]).unwrap();
//! let reports = answer(&joined, &query);
//! assert_eq!(reports.len(), 1);
//! assert_eq!(reports[0].to_bytes().unwrap(), [0x22, 0, 0xea, 0xf9, 0, 0, 0, 1, 2, 0, 0, 0, 239, 1, 2, 3]);
//! ```

use fictionet::stdlib::codec::{be16, Wire};
use fictionet::stdlib::ip::checksum;

use std::net::Ipv4Addr;

/// The IP protocol number of IGMP.
pub const PROTOCOL: u8 = 2;
/// The longest message this module reads or writes: the most an IPv4
/// packet can carry after a 24-byte header, the 20-byte header plus the
/// Router Alert option every IGMPv2 and IGMPv3 message carries.
pub const MAX_MESSAGE: usize = 65_511;
/// The length of a version 1 or 2 message, and of a version 3 report's
/// header.
pub const HEADER_LEN: usize = 8;
/// The length of a version 3 query before its sources.
pub const V3_QUERY_LEN: usize = 12;
/// The length of a version 3 group record before its sources.
pub const RECORD_HEADER_LEN: usize = 8;
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
    /// A version 1 query is always general: its group reads as 0.0.0.0,
    /// and the writers refuse any other.
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
    /// query; a general query must have none.
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
}

/// Why bytes are not an IGMP message, or a message cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The bytes end before the message does.
    Truncated,
    /// Bytes follow the message and its declared auxiliary data.
    Trailing {
        /// Number of bytes after the message.
        remaining: usize,
    },
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
    /// A group was not a multicast address (or 0.0.0.0 in a query), or a
    /// source was not a unicast address.
    Address(Ipv4Addr),
    /// A version 3 general query listed this many sources. A general query
    /// lists none.
    GeneralQuerySources(usize),
    /// A value cannot be written without changing it. This includes an
    /// inexact response code or [`RecordType::Other`] with a known code.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Trailing { remaining } => write!(f, "{remaining} bytes after the IGMP message"),
            Error::Truncated => write!(f, "the message is cut short"),
            Error::TooLong => write!(f, "the message is longer than {MAX_MESSAGE} bytes"),
            Error::Checksum => write!(f, "the checksum is wrong"),
            Error::UnknownType(t) => write!(f, "unknown message type {t:#04x}"),
            Error::QueryLength(n) => write!(f, "a query of {n} bytes, neither 8 nor at least 12"),
            Error::Qrv(q) => write!(f, "QRV {q}, above {MAX_QRV}"),
            Error::Address(a) => write!(f, "address {a} cannot be used in that field"),
            Error::GeneralQuerySources(n) => write!(f, "a general query that lists {n} sources"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
        }
    }
}

impl std::error::Error for Error {}

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

/// A maximum response code or QQIC, stored as its decoded numeric value.
/// Values below 128 are exact. Larger values must fit the exponent and
/// mantissa described by [`decode_code`]. Serialization never rounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Code(
    /// Decoded response time or query interval, at most [`MAX_CODE_VALUE`].
    pub u32,
);

impl Wire for Code {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one response code or QQIC. Refuses an empty slice or trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            [code] => Ok(Self(decode_code(*code))),
            [] => Err(Error::Truncated),
            _ => Err(Error::Trailing { remaining: bytes.len() - 1 }),
        }
    }

    /// Appends one code. Refuses values that need rounding or exceed
    /// [`MAX_CODE_VALUE`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let code = if self.0 < 128 {
            self.0 as u8
        } else {
            (128..=255u8).find(|&code| decode_code(code) == self.0).ok_or(Error::Unwritable)?
        };
        out.push(code);
        Ok(())
    }
}

fn known_type(t: u8) -> bool {
    matches!(t, kind::MEMBERSHIP_QUERY | kind::V1_REPORT | kind::V2_REPORT | kind::LEAVE_GROUP | kind::V3_REPORT)
}

fn addr(b: &[u8], i: usize) -> Option<Ipv4Addr> {
    let s = b.get(i..i.checked_add(4)?)?;
    Some(Ipv4Addr::new(s[0], s[1], s[2], s[3]))
}

/// `n` source addresses starting at `at`, and where they end.
fn addrs(b: &[u8], at: usize, n: usize) -> Result<(Vec<Ipv4Addr>, usize), Error> {
    let end = n.checked_mul(4).and_then(|l| l.checked_add(at)).ok_or(Error::Truncated)?;
    let s = b.get(at..end).ok_or(Error::Truncated)?;
    let out: Vec<Ipv4Addr> = s.as_chunks::<4>().0.iter().map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3])).collect();
    check_sources(&out)?;
    Ok((out, end))
}

/// Whether `a` can be a source: a unicast address.
fn is_source(a: Ipv4Addr) -> bool {
    !(a.is_multicast() || a.is_unspecified() || a.is_broadcast())
}

fn check_sources(sources: &[Ipv4Addr]) -> Result<(), Error> {
    match sources.iter().find(|&&s| !is_source(s)) {
        Some(&s) => Err(Error::Address(s)),
        None => Ok(()),
    }
}

/// Checks a group that must be multicast, or also 0.0.0.0 when `general`
/// allows a general query.
fn check_group(group: Ipv4Addr, general: bool) -> Result<(), Error> {
    if group.is_multicast() || (general && group.is_unspecified()) {
        Ok(())
    } else {
        Err(Error::Address(group))
    }
}

/// Checks a version 3 query's group and sources.
fn check_query_v3(group: Ipv4Addr, sources: usize) -> Result<(), Error> {
    check_group(group, true)?;
    if group.is_unspecified() && sources != 0 {
        return Err(Error::GeneralQuerySources(sources));
    }
    Ok(())
}

impl Message {
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
    pub fn encoded_len(&self) -> Result<usize, Error> {
        let n = match self {
            Message::Query { max_resp_time: 0, group } => {
                // A version 1 query is sent with a zero group.
                if !group.is_unspecified() {
                    return Err(Error::Address(*group));
                }
                Some(HEADER_LEN)
            }
            Message::Query { group, .. } => {
                check_group(*group, true)?;
                Some(HEADER_LEN)
            }
            Message::ReportV1 { group } | Message::ReportV2 { group } | Message::Leave { group } => {
                check_group(*group, false)?;
                Some(HEADER_LEN)
            }
            Message::QueryV3(q) => {
                if q.qrv > MAX_QRV {
                    return Err(Error::Qrv(q.qrv));
                }
                check_query_v3(q.group, q.sources.len())?;
                check_sources(&q.sources)?;
                q.sources.len().checked_mul(4).and_then(|l| l.checked_add(V3_QUERY_LEN))
            }
            Message::ReportV3 { records } => {
                let mut n = Some(HEADER_LEN);
                for r in records {
                    if let RecordType::Other(1..=6) = r.kind {
                        return Err(Error::Unwritable);
                    }
                    check_group(r.group, false)?;
                    check_sources(&r.sources)?;
                    n = n
                        .and_then(|n| n.checked_add(RECORD_HEADER_LEN))
                        .and_then(|n| n.checked_add(r.sources.len().checked_mul(4)?))
                        .filter(|&n| n <= MAX_MESSAGE);
                }
                n
            }
        };
        // A count above 65535 needs more than MAX_MESSAGE bytes, so this
        // also keeps every count within its 16 bits.
        n.filter(|&n| n <= MAX_MESSAGE).ok_or(Error::TooLong)
    }

    /// Reads a complete IPv4 IGMP payload as a receiver does. Checks the
    /// checksum over all of `b`, then ignores bytes after the message and
    /// its declared auxiliary data (RFC 2236 2.5, RFC 3376 4.1.10 and 4.2.11).
    /// Refuses invalid lengths, types, checksums, addresses, and payloads
    /// above [`MAX_MESSAGE`], as [`Message::parse`] does.
    pub fn receive(b: &[u8]) -> Result<Message, Error> {
        Self::read(b, false)
    }

    /// Reads the message, optionally requiring it to fill the payload.
    fn read(b: &[u8], exact: bool) -> Result<Message, Error> {
        let &t = b.first().ok_or(Error::Truncated)?;
        if !known_type(t) {
            return Err(Error::UnknownType(t));
        }
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if checksum(b) != 0 {
            return Err(Error::Checksum);
        }
        let group = addr(b, 4).ok_or(Error::Truncated)?;
        let mut used = HEADER_LEN;
        let message = match t {
            kind::MEMBERSHIP_QUERY => match b.len() {
                // A version 1 query's group field is ignored when read.
                HEADER_LEN if b[1] == 0 => Ok(Message::Query { max_resp_time: 0, group: Ipv4Addr::UNSPECIFIED }),
                HEADER_LEN => {
                    check_group(group, true)?;
                    Ok(Message::Query { max_resp_time: b[1], group })
                }
                n if n < V3_QUERY_LEN => Err(Error::QueryLength(n)),
                _ => {
                    let n = usize::from(be16(b, 10).ok_or(Error::Truncated)?);
                    check_query_v3(group, n)?;
                    let (sources, end) = addrs(b, V3_QUERY_LEN, n)?;
                    used = end;
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
            kind::V1_REPORT => check_group(group, false).map(|()| Message::ReportV1 { group }),
            kind::V2_REPORT => check_group(group, false).map(|()| Message::ReportV2 { group }),
            kind::LEAVE_GROUP => check_group(group, false).map(|()| Message::Leave { group }),
            _ => {
                let m = usize::from(be16(b, 6).ok_or(Error::Truncated)?);
                // Each record takes at least 8 bytes, so the bytes bound
                // what is allocated, whatever the count says.
                let mut records = Vec::with_capacity(m.min((b.len() - HEADER_LEN) / RECORD_HEADER_LEN));
                let mut at = HEADER_LEN;
                for _ in 0..m {
                    let head = b.get(at..at + RECORD_HEADER_LEN).ok_or(Error::Truncated)?;
                    let aux_len = usize::from(head[1]) * 4;
                    let n = usize::from(u16::from_be_bytes([head[2], head[3]]));
                    let group = Ipv4Addr::new(head[4], head[5], head[6], head[7]);
                    check_group(group, false)?;
                    let (sources, end) = addrs(b, at + RECORD_HEADER_LEN, n)?;
                    // The auxiliary data must be there, but is skipped.
                    let aux_end = end.checked_add(aux_len).filter(|&e| e <= b.len()).ok_or(Error::Truncated)?;
                    records.push(GroupRecord { kind: RecordType::from_code(head[0]), group, sources });
                    at = aux_end;
                }
                used = at;
                Ok(Message::ReportV3 { records })
            }
        }?;
        if exact && used != b.len() {
            return Err(Error::Trailing { remaining: b.len() - used });
        }
        Ok(message)
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete IPv4 IGMP payload. Refuses invalid lengths,
    /// types, checksums, addresses, and trailing bytes. Reserved fields and
    /// version 1 query groups are ignored. Declared auxiliary data is skipped.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::read(b, true)
    }

    /// The message's bytes, with the checksum filled in. It fails if the
    /// message would be longer than [`MAX_MESSAGE`], a QRV is above
    /// [`MAX_QRV`], an address is wrong for its field (see the module
    /// docs), a version 3 general query lists sources, or a record type is
    /// [`RecordType::Other`] with a code from 1 to 6. Auxiliary data is
    /// never written. Nothing is allocated before those checks pass.
    /// Leaves the destination unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let len = self.encoded_len()?;
        let start = out.len();
        out.reserve(len);
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
                    out.push(0);
                    out.extend_from_slice(&(r.sources.len() as u16).to_be_bytes());
                    out.extend_from_slice(&r.group.octets());
                    for s in &r.sources {
                        out.extend_from_slice(&s.octets());
                    }
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
        let c = checksum(&out[start..]);
        out[start + 2..start + 4].copy_from_slice(&c.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Collect, CollectError, Fail, Lcg,
    };
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn collect(b: &[u8]) -> Result<Message, Error> {
        let make = || Collect::<Message>::new(MAX_MESSAGE);
        contract::check_decode_with_alloc_limit(make, b, 2 * (MAX_MESSAGE + 1));
        contract::check_wire::<Message>(b);
        let parsed = Message::parse(b);
        let (items, failure) = decode_all(make, b);
        if b.len() <= MAX_MESSAGE {
            assert_eq!(failure, parsed.clone().err().map(|e| Fail::Protocol(CollectError::Parse(e))));
            assert_eq!(items, parsed.clone().ok().into_iter().collect::<Vec<_>>());
        } else {
            assert_eq!(failure, Some(Fail::Protocol(CollectError::TooLong { limit: MAX_MESSAGE })));
        }
        parsed
    }

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

    fn round_trip(m: &Message) -> Vec<u8> {
        let b = m.to_bytes().unwrap();
        assert_eq!(b.len(), m.encoded_len().unwrap());
        assert_eq!(checksum(&b), 0);
        assert_eq!(Message::parse(&b).as_ref(), Ok(m));
        assert_eq!(collect(&b).as_ref(), Ok(m));
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
            assert_eq!(Code(decode_code(c)).to_bytes(), Ok(vec![c]));
            contract::check_wire::<Code>(&[c]);
        }
        for v in [129, 255, 1000, 31_743, 40_000, u32::MAX] {
            assert_eq!(Code(v).to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&Code(v));
        }
        assert_eq!(Code(992).to_bytes(), Ok(vec![0xaf]));
        assert_eq!(Code::parse(&[0xaf]), Ok(Code(992)));
        assert_eq!(Code::parse(&[]), Err(Error::Truncated));
        assert_eq!(Code::parse(&[0xaf, 0]), Err(Error::Trailing { remaining: 1 }));
        assert_eq!(decode_code(0xaf), 31 << 5);
    }

    #[test]
    fn trailing_bytes_are_ignored() {
        let messages = [
            Message::ReportV2 { group: ip(239, 9, 9, 9) },
            Message::Leave { group: ip(239, 1, 1, 1) },
            Message::QueryV3(QueryV3 {
                max_resp_code: 1, group: Ipv4Addr::UNSPECIFIED, suppress: false,
                qrv: 1, qqic: 1, sources: vec![],
            }),
            Message::QueryV3(QueryV3 {
                max_resp_code: 1, group: ip(239, 1, 1, 1), suppress: false,
                qrv: 1, qqic: 1, sources: vec![ip(192, 0, 2, 1)],
            }),
            Message::ReportV3 { records: vec![GroupRecord {
                kind: RecordType::ModeIsInclude, group: ip(239, 1, 1, 1),
                sources: vec![ip(192, 0, 2, 1)],
            }] },
        ];
        for m in messages {
            let mut b = m.to_bytes().unwrap();
            assert_eq!(Message::receive(&b).as_ref(), Ok(&m));
            // A report's declared auxiliary data is skipped before trailing bytes.
            if matches!(m, Message::ReportV3 { .. }) {
                b[9] = 1;
                b.extend_from_slice(&[6, 7, 8, 9]);
                b = fix(b);
                assert_eq!(Message::parse(&b).as_ref(), Ok(&m));
                assert_eq!(Message::receive(&b).as_ref(), Ok(&m));
                assert_eq!(Message::receive(&fix(b[..b.len() - 1].to_vec())), Err(Error::Truncated));
            }
            b.extend_from_slice(&[1, 2, 3, 4, 5]);
            // Trailing bytes still participate in the checksum.
            assert_eq!(Message::receive(&b), Err(Error::Checksum));
            assert_eq!(Message::parse(&b), Err(Error::Checksum));
            let b = fix(b);
            assert_eq!(Message::receive(&b), Ok(m));
            assert_eq!(collect(&b), Err(Error::Trailing { remaining: 5 }));
            check_bytes(&b);
        }
    }

    #[test]
    fn error_paths() {
        assert_eq!(Message::parse(&[]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x11]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x11, 0, 0, 0, 0, 0, 0]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x13, 0, 0, 0, 0, 0, 0, 0]), Err(Error::UnknownType(0x13)));
        assert_eq!(Message::parse(&[0x00]), Err(Error::UnknownType(0)));
        assert_eq!(Message::parse(&vec![0x22; MAX_MESSAGE + 1]), Err(Error::TooLong));
        assert_eq!(Message::parse(&[0x16, 0, 0, 0, 239, 1, 2, 3]), Err(Error::Checksum));
        for n in 9..12 {
            let b = fix(vec![0x11; n]);
            assert_eq!(Message::parse(&b), Err(Error::QueryLength(n)));
        }
        // A v3 query that says 2 sources and holds 1.
        let b = fix(vec![0x11, 1, 0, 0, 232, 0, 0, 1, 0, 0, 0, 2, 10, 0, 0, 1]);
        assert_eq!(Message::parse(&b), Err(Error::Truncated));
        // A v3 report that says 1 record and holds none.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(Message::parse(&b), Err(Error::Truncated));
        // A record that says 1 source and holds none.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 239, 0, 0, 1]);
        assert_eq!(Message::parse(&b), Err(Error::Truncated));
        // A record that says 1 word of aux data and holds 2 bytes.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 239, 0, 0, 1, 0, 0]);
        assert_eq!(Message::parse(&b), Err(Error::Truncated));
        // A record count of 65535 with no records.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(Message::parse(&b), Err(Error::Truncated));
    }

    #[test]
    fn writer_errors() {
        let q = QueryV3 { max_resp_code: 0, group: ip(232, 1, 1, 1), suppress: false, qrv: 8, qqic: 0, sources: vec![] };
        assert_eq!(Message::QueryV3(q.clone()).to_bytes(), Err(Error::Qrv(8)));
        let big = QueryV3 { qrv: 0, sources: vec![ip(1, 1, 1, 1); 20_000], ..q };
        assert_eq!(Message::QueryV3(big.clone()).to_bytes(), Err(Error::TooLong));
        let fits = QueryV3 { sources: vec![ip(1, 1, 1, 1); (MAX_MESSAGE - V3_QUERY_LEN) / 4], ..big };
        let b = round_trip(&Message::QueryV3(fits));
        assert!(b.len() <= MAX_MESSAGE);
        let r = GroupRecord { kind: RecordType::ModeIsInclude, group: ip(239, 0, 0, 1), sources: vec![] };
        let many = Message::ReportV3 { records: vec![r.clone(); 10_000] };
        assert_eq!(many.to_bytes(), Err(Error::TooLong));
        let most = Message::ReportV3 { records: vec![r; (MAX_MESSAGE - HEADER_LEN) / RECORD_HEADER_LEN] };
        round_trip(&most);
    }

    #[test]
    fn other_record_type_must_not_hide_a_known_code() {
        // Other(3) would be written as code 3 and read back as
        // ChangeToInclude, a different message.
        for c in 1..=6u8 {
            let r = GroupRecord { kind: RecordType::Other(c), group: ip(239, 0, 0, 1), sources: vec![] };
            let m = Message::ReportV3 { records: vec![r] };
            assert_eq!(m.to_bytes(), Err(Error::Unwritable));
            assert_eq!(m.encoded_len(), Err(Error::Unwritable));
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
        assert_eq!(Message::parse(&fix(b)), Err(Error::Truncated));
        // A large chunk of unknown type fails on its type, as parse does.
        let big = vec![0x99; MAX_MESSAGE * 2];
        assert_eq!(Message::parse(&big), Err(Error::UnknownType(0x99)));
        assert_eq!(collect(&big), Err(Error::UnknownType(0x99)));
        assert_eq!(collect(&vec![0x11; MAX_MESSAGE * 2]), Err(Error::TooLong));
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
            Error::Truncated,
            Error::TooLong,
            Error::Checksum,
            Error::UnknownType(1),
            Error::QueryLength(9),
            Error::Qrv(9),
            Error::Address(ip(10, 0, 0, 1)),
            Error::GeneralQuerySources(1),
            Error::Unwritable,
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn groups_must_be_multicast() {
        // RFC 2236, section 2.4, and RFC 3376, section 4.2.8.
        let u = ip(192, 0, 2, 1);
        for m in [Message::ReportV1 { group: u }, Message::ReportV2 { group: u }, Message::Leave { group: u }] {
            assert_eq!(m.to_bytes(), Err(Error::Address(u)));
            assert_eq!(m.encoded_len(), Err(Error::Address(u)));
        }
        for t in [0x12, 0x16, 0x17] {
            assert_eq!(Message::parse(&fix(vec![t, 0, 0, 0, 192, 0, 2, 1])), Err(Error::Address(u)));
        }
        assert_eq!(Message::Query { max_resp_time: 10, group: u }.to_bytes(), Err(Error::Address(u)));
        assert_eq!(Message::parse(&fix(vec![0x11, 10, 0, 0, 192, 0, 2, 1])), Err(Error::Address(u)));
        let q = QueryV3 { max_resp_code: 1, group: u, suppress: false, qrv: 2, qqic: 1, sources: vec![] };
        assert_eq!(Message::QueryV3(q).to_bytes(), Err(Error::Address(u)));
        assert_eq!(Message::parse(&fix(vec![0x11, 1, 0, 0, 192, 0, 2, 1, 2, 1, 0, 0])), Err(Error::Address(u)));
        let r = GroupRecord { kind: RecordType::ModeIsInclude, group: u, sources: vec![] };
        assert_eq!(Message::ReportV3 { records: vec![r] }.to_bytes(), Err(Error::Address(u)));
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 192, 0, 2, 1]);
        assert_eq!(Message::parse(&b), Err(Error::Address(u)));
    }

    #[test]
    fn sources_must_be_unicast() {
        // RFC 3376, sections 4.1.9 and 4.2.9.
        for bad in [ip(239, 1, 1, 1), Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST] {
            let q = QueryV3 { max_resp_code: 1, group: ip(232, 1, 1, 1), suppress: false, qrv: 2, qqic: 1, sources: vec![ip(10, 0, 0, 1), bad] };
            assert_eq!(Message::QueryV3(q).to_bytes(), Err(Error::Address(bad)));
            let o = bad.octets();
            let b = fix(vec![0x11, 1, 0, 0, 232, 1, 1, 1, 2, 1, 0, 1, o[0], o[1], o[2], o[3]]);
            assert_eq!(Message::parse(&b), Err(Error::Address(bad)));
            let r = GroupRecord { kind: RecordType::AllowNewSources, group: ip(239, 1, 1, 1), sources: vec![bad] };
            assert_eq!(Message::ReportV3 { records: vec![r] }.to_bytes(), Err(Error::Address(bad)));
            let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 1, 239, 1, 1, 1, o[0], o[1], o[2], o[3]]);
            assert_eq!(Message::parse(&b), Err(Error::Address(bad)));
        }
    }

    #[test]
    fn v3_general_query_lists_no_sources() {
        // RFC 3376, section 4.1.9: group 0.0.0.0 and one source, with a
        // right checksum. Linux drops it too.
        let b = [0x11, 0x64, 0x2a, 0x1c, 0, 0, 0, 0, 0x02, 0x7d, 0, 1, 192, 0, 2, 1];
        assert_eq!(checksum(&b), 0);
        assert_eq!(Message::parse(&b), Err(Error::GeneralQuerySources(1)));
        let q = QueryV3 { max_resp_code: 100, group: Ipv4Addr::UNSPECIFIED, suppress: false, qrv: 2, qqic: 125, sources: vec![ip(192, 0, 2, 1)] };
        assert_eq!(Message::QueryV3(q).to_bytes(), Err(Error::GeneralQuerySources(1)));
    }

    #[test]
    fn v1_query_group_is_ignored_and_never_sent() {
        // RFC 1112, appendix I: zero when sent, ignored when received.
        let m = Message::Query { max_resp_time: 0, group: ip(239, 1, 2, 3) };
        assert_eq!(m.to_bytes(), Err(Error::Address(ip(239, 1, 2, 3))));
        for g in [[239, 1, 2, 3], [192, 0, 2, 1]] {
            let b = fix(vec![0x11, 0, 0, 0, g[0], g[1], g[2], g[3]]);
            let m = Message::parse(&b).unwrap();
            assert_eq!(m, Message::Query { max_resp_time: 0, group: Ipv4Addr::UNSPECIFIED });
            assert_eq!(m.destination(), ALL_SYSTEMS);
            assert_eq!(m.version(), 1);
        }
    }

    #[test]
    fn aux_data_is_skipped_and_never_written() {
        // RFC 3376, section 4.2.10: a record with one word of aux data
        // reads as the record alone, and is written without it.
        let b = fix(vec![0x22, 0, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 239, 1, 2, 3, 1, 2, 3, 4]);
        let m = Message::parse(&b).unwrap();
        let r = GroupRecord { kind: RecordType::ModeIsExclude, group: ip(239, 1, 2, 3), sources: vec![] };
        assert_eq!(m, Message::ReportV3 { records: vec![r] });
        let out = m.to_bytes().unwrap();
        assert_eq!(out.len(), 16);
        assert_eq!(out[9], 0);
        // The most aux data a record can say it has, 255 words, before a
        // second record.
        let mut b = vec![0x22, 0, 0, 0, 0, 0, 0, 2, 1, 255, 0, 0, 239, 0, 0, 1];
        b.extend_from_slice(&[0xaa; 255 * 4]);
        b.extend_from_slice(&[2, 0, 0, 0, 239, 0, 0, 2]);
        let Message::ReportV3 { records } = Message::parse(&fix(b)).unwrap() else { panic!() };
        assert_eq!(records.iter().map(|r| r.group).collect::<Vec<_>>(), [ip(239, 0, 0, 1), ip(239, 0, 0, 2)]);
    }

    #[test]
    fn room_for_router_alert() {
        // RFC 3376, section 4: every message carries Router Alert, so the
        // IPv4 header is at least 24 bytes and a message at most 65511.
        assert_eq!(MAX_MESSAGE + 24, 65_535);
        let q = |n| QueryV3 { max_resp_code: 1, group: ip(232, 1, 1, 1), suppress: false, qrv: 2, qqic: 1, sources: vec![ip(10, 0, 0, 1); n] };
        assert_eq!(Message::QueryV3(q(16_375)).encoded_len(), Err(Error::TooLong));
        assert_eq!(round_trip(&Message::QueryV3(q(16_374))).len(), 65_508);
        // A received message that only fits a 20-byte header is too long.
        let mut b = vec![0x16, 0, 0, 0, 239, 1, 2, 3];
        b.resize(65_512, 0);
        assert_eq!(Message::parse(&fix(b)), Err(Error::TooLong));
    }

    #[test]
    fn checksum_folds_as_it_goes() {
        // A sum that carries out of 16 bits many times still folds right.
        assert_eq!(checksum(&[0xff; 4096]), 0);
        assert_eq!(checksum(&[0xff; 4097]), 0x00ff);
        assert_eq!(checksum(&[]), 0xffff);
        assert_eq!(checksum(&[0x80, 0, 0x80, 0]), 0xfffe);
    }

    fn samples() -> Vec<Message> {
        vec![
            Message::Query { max_resp_time: 100, group: Ipv4Addr::UNSPECIFIED },
            Message::Query { max_resp_time: 0, group: Ipv4Addr::UNSPECIFIED },
            Message::Query { max_resp_time: 10, group: ip(239, 1, 1, 1) },
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
                assert_eq!(collect(p), Message::parse(p));
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
    fn collection_matches_parse() {
        for m in samples() {
            assert_eq!(collect(&m.to_bytes().unwrap()), Ok(m));
        }
        assert_eq!(collect(&[0x99]), Err(Error::UnknownType(0x99)));
        assert_eq!(collect(&vec![0x22; MAX_MESSAGE + 100]), Err(Error::TooLong));
        assert_eq!(collect(&[]), Err(Error::Truncated));
    }

    trait Samples {
        fn addr(&mut self) -> Ipv4Addr;
        fn group(&mut self) -> Ipv4Addr;
        fn query_group(&mut self) -> Ipv4Addr;
        fn source(&mut self) -> Ipv4Addr;
        fn sources(&mut self, n: usize) -> Vec<Ipv4Addr>;
        fn addrs(&mut self, n: usize) -> Vec<Ipv4Addr>;
    }

    impl Samples for Lcg {
        /// Any address at all.
        fn addr(&mut self) -> Ipv4Addr {
            let mut bytes = [0; 4];
            self.fill(&mut bytes);
            Ipv4Addr::from(bytes)
        }
        /// A multicast address, 224.0.0.0 to 239.255.255.255.
        fn group(&mut self) -> Ipv4Addr {
            Ipv4Addr::from(0xe000_0000 | ((self.next() as u32) & 0x0fff_ffff))
        }
        /// A group for a query: multicast, or now and then 0.0.0.0.
        fn query_group(&mut self) -> Ipv4Addr {
            if self.index(3) == 0 { Ipv4Addr::UNSPECIFIED } else { self.group() }
        }
        /// A unicast address: first octet 1 to 223.
        fn source(&mut self) -> Ipv4Addr {
            let first = 1 + self.index(223) as u32;
            Ipv4Addr::from((first << 24) | ((self.next() as u32) & 0x00ff_ffff))
        }
        fn sources(&mut self, n: usize) -> Vec<Ipv4Addr> {
            (0..self.index(n)).map(|_| self.source()).collect()
        }
        /// Any addresses, valid or not.
        fn addrs(&mut self, n: usize) -> Vec<Ipv4Addr> {
            (0..self.index(n)).map(|_| self.addr()).collect()
        }
    }

    /// A random message the writer accepts.
    fn random_message(rng: &mut Lcg) -> Message {
        match rng.index(6) {
            0 => match rng.next() as u8 {
                0 => Message::Query { max_resp_time: 0, group: Ipv4Addr::UNSPECIFIED },
                t => Message::Query { max_resp_time: t, group: rng.query_group() },
            },
            1 => Message::ReportV1 { group: rng.group() },
            2 => Message::ReportV2 { group: rng.group() },
            3 => Message::Leave { group: rng.group() },
            4 => {
                let group = rng.query_group();
                let sources = if group.is_unspecified() { vec![] } else { rng.sources(8) };
                Message::QueryV3(QueryV3 {
                    max_resp_code: rng.next() as u8,
                    group,
                    suppress: !rng.coin(),
                    qrv: rng.index(8) as u8,
                    qqic: rng.next() as u8,
                    sources,
                })
            }
            _ => {
                let n = rng.index(5);
                let records = (0..n)
                    .map(|_| GroupRecord {
                        kind: match rng.index(9) as u8 {
                            c @ 1..=6 => RecordType::from_code(c),
                            _ => RecordType::Other([0, 7, 200, 255][rng.index(4)]),
                        },
                        group: rng.group(),
                        sources: rng.sources(5),
                    })
                    .collect();
                Message::ReportV3 { records }
            }
        }
    }

    /// A random message, valid or not: any addresses, QRV and record
    /// codes.
    fn random_any_message(rng: &mut Lcg) -> Message {
        match rng.index(6) {
            0 => Message::Query { max_resp_time: rng.next() as u8 % 3, group: rng.addr() },
            1 => Message::ReportV1 { group: rng.addr() },
            2 => Message::ReportV2 { group: rng.addr() },
            3 => Message::Leave { group: rng.addr() },
            4 => Message::QueryV3(QueryV3 {
                max_resp_code: rng.next() as u8,
                group: if !rng.coin() { Ipv4Addr::UNSPECIFIED } else { rng.addr() },
                suppress: !rng.coin(),
                qrv: rng.index(10) as u8,
                qqic: rng.next() as u8,
                sources: rng.addrs(3),
            }),
            _ => {
                let n = rng.index(3);
                let records = (0..n)
                    .map(|_| GroupRecord {
                        kind: RecordType::Other(rng.index(9) as u8),
                        group: if !rng.coin() { rng.group() } else { rng.addr() },
                        sources: rng.addrs(3),
                    })
                    .collect();
                Message::ReportV3 { records }
            }
        }
    }

    /// The rules of RFC 1112, RFC 2236 and RFC 3376 for a message sent,
    /// written out apart from the module's own checks.
    fn conforms(m: &Message) -> bool {
        let multicast = |a: &Ipv4Addr| (224..=239).contains(&a.octets()[0]);
        let zero = |a: &Ipv4Addr| a.octets() == [0; 4];
        let unicast = |a: &Ipv4Addr| !multicast(a) && !zero(a) && a.octets() != [255; 4];
        let len = match m {
            Message::Query { max_resp_time: 0, group } if !zero(group) => return false,
            Message::Query { group, .. } if !zero(group) && !multicast(group) => return false,
            Message::ReportV1 { group } | Message::ReportV2 { group } | Message::Leave { group } if !multicast(group) => {
                return false;
            }
            Message::QueryV3(q) => {
                if q.qrv > 7 || !(zero(&q.group) || multicast(&q.group)) || !q.sources.iter().all(unicast) {
                    return false;
                }
                if zero(&q.group) && !q.sources.is_empty() {
                    return false;
                }
                12 + 4 * q.sources.len()
            }
            Message::ReportV3 { records } => {
                let mut len = 8;
                for r in records {
                    if matches!(r.kind, RecordType::Other(1..=6)) || !multicast(&r.group) || !r.sources.iter().all(unicast) {
                        return false;
                    }
                    len += 8 + 4 * r.sources.len();
                }
                len
            }
            _ => 8,
        };
        // An IPv4 packet holds 65535 bytes, 24 of them the header with
        // Router Alert.
        len + 24 <= 65_535
    }

    fn check_bytes(data: &[u8]) {
        let parsed = Message::parse(data);
        if let Ok(m) = &parsed {
            assert_eq!(Message::receive(data).as_ref(), Ok(m));
        }
        if let Ok(m) = Message::receive(data) {
            // A message read follows the RFCs, can be written, and reads
            // back the same.
            assert!(conforms(&m), "{m:?}");
            let out = m.to_bytes().unwrap();
            assert!(out.len() <= data.len());
            assert_eq!(Message::parse(&out), Ok(m));
        }
        assert_eq!(collect(data), parsed);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x1906_2236_3376);
        for _ in 0..4000 {
            // Any message: the writer accepts exactly the ones that follow
            // the RFCs.
            let any = random_any_message(&mut rng);
            match any.to_bytes() {
                Ok(b) => {
                    assert!(conforms(&any), "{any:?}");
                    round_trip(&any);
                    check_bytes(&b);
                }
                Err(_) => assert!(!conforms(&any), "{any:?}"),
            }
            let m = random_message(&mut rng);
            assert!(conforms(&m), "{m:?}");
            let b = round_trip(&m);
            check_bytes(&b);
            // Flip some bytes, cut or extend, and fix the checksum most of
            // the time so the parser looks past it.
            let mut mutated = b.clone();
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut mutated);
            }
            if rng.index(4) != 0 {
                mutated = fix(mutated);
            }
            check_bytes(&mutated);
            // Plain random bytes, with a known type and a right checksum.
            let mut raw = rng.bytes(80);
            if let Some(t) = raw.first_mut() {
                *t = [0x11, 0x12, 0x16, 0x17, 0x22, rng.next() as u8][rng.index(6)];
            }
            check_bytes(&fix(raw));
        }
    }
}
