//! RIP and RIPng: reading and writing routing messages, with no I/O.
//!
//! RIP (the Routing Information Protocol) is the oldest routing protocol
//! still in use. Each router sends its neighbors the routes it knows, each
//! with a metric: the number of hops to the destination. A router that
//! hears a shorter route takes it. A metric of 16 means the destination
//! cannot be reached. RIP for IPv4 runs over UDP port 520. Version 1 (RFC
//! 1058, restated in RFC 2453) knows only classful networks. Version 2 (RFC
//! 2453) adds a subnet mask, a next hop and a route tag to each entry, and
//! an authentication entry at the start of a message. RFC 4822 defines the
//! cryptographic form of that entry, which puts a trailer of authentication
//! data after the routes. RIPng (RFC 2080) is the same protocol for IPv6,
//! over UDP port 521, with a prefix length in place of a mask and next hops
//! given by entries of their own.
//!
//! A message is a request or a response. A request asks a router for some
//! routes, or for its whole table: a request with one entry of family 0 and
//! metric 16 (in RIPng, the prefix `::/0` with metric 16). A response
//! carries routes, either as the answer to a request or as the update a
//! router sends every 30 seconds.
//!
//! Nothing here reads a socket. A world that plays a router hands each UDP
//! payload it reads on port [`PORT`] to [`Message::parse`], or on port
//! [`NG_PORT`] to [`NgMessage::parse`], looks at the routes, and sends the
//! bytes [`Message::to_bytes`] or [`NgMessage::to_bytes`] returns. A
//! [`Decoder`] or [`NgDecoder`] reads a payload that comes in pieces and
//! reports a bad field as soon as the bytes show it. Which routes exist,
//! what their metrics are, and whether a password or a digest is right are
//! up to world code. The authentication data is kept as bytes.
//!
//! Every reader checks the command, version, family, metric, mask, prefix
//! length, entry count and lengths, because the agent can send any bytes it
//! likes. A version 1 message whose must-be-zero fields are not zero is
//! rejected, as RFC 2453 says. In version 2 and RIPng, the header's unused
//! field and the reserved fields of the authentication and next hop entries
//! are ignored when read and written as zero. So are the fields of a
//! whole-table entry other than its family (or prefix and prefix length)
//! and metric. Writers check the same rules as readers, so bytes they
//! return always read back.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use fictionet::stdlib::rip::{Command, Entries, Message, RouteEntry, Version};
//!
//! // A version 2 request for the whole routing table.
//! let mut request = vec![1, 2, 0, 0];
//! request.extend_from_slice(&[0; 16]);
//! request.extend_from_slice(&[0, 0, 0, 16]);
//! let m = Message::parse(&request).unwrap();
//! assert_eq!(m.command, Command::Request);
//! assert_eq!(m.entries, Entries::WholeTable);
//!
//! // The router answers with its one route: 10.0.0.0/8, one hop away.
//! let route = RouteEntry {
//!     tag: 0,
//!     address: Ipv4Addr::new(10, 0, 0, 0),
//!     mask: Ipv4Addr::new(255, 0, 0, 0),
//!     next_hop: Ipv4Addr::UNSPECIFIED,
//!     metric: 1,
//! };
//! let reply = Message {
//!     command: Command::Response,
//!     version: Version::V2,
//!     auth: None,
//!     entries: Entries::Routes(vec![route]),
//! };
//! let bytes = reply.to_bytes().unwrap();
//! assert_eq!(
//!     bytes,
//!     [2, 2, 0, 0, 0, 2, 0, 0, 10, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
//! );
//! assert_eq!(Message::parse(&bytes), Ok(reply));
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

/// The UDP port RIP (versions 1 and 2) runs on.
pub const PORT: u16 = 520;
/// The UDP port RIPng runs on.
pub const NG_PORT: u16 = 521;
/// The IPv4 multicast group version 2 routers send updates to.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 9);
/// The IPv6 multicast group RIPng routers send updates to.
pub const NG_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 9);
/// The metric that means a destination cannot be reached.
pub const INFINITY: u8 = 16;
/// The length of a message header: command, version and two unused bytes.
pub const HEADER_LEN: usize = 4;
/// The length of one entry, in RIP and RIPng alike.
pub const ENTRY_LEN: usize = 20;
/// The most entries a RIP message holds, the authentication entry
/// included.
pub const MAX_ENTRIES: usize = 25;
/// The most bytes of authentication data a cryptographic trailer holds:
/// its length field is one byte.
pub const MAX_AUTH_DATA: usize = 255;
/// The length of the trailer header, `0xffff 0x0001`, before the
/// authentication data.
pub const TRAILER_HEADER_LEN: usize = 4;
/// The longest RIP message: the most entries, then the longest trailer.
pub const MAX_MESSAGE: usize = HEADER_LEN + MAX_ENTRIES * ENTRY_LEN + TRAILER_HEADER_LEN + MAX_AUTH_DATA;
/// The longest UDP payload, which bounds a RIPng message.
pub const MAX_UDP_PAYLOAD: usize = 65527;
/// The most entries a RIPng message holds: as many as fit in the longest
/// UDP payload.
pub const MAX_NG_ENTRIES: usize = (MAX_UDP_PAYLOAD - HEADER_LEN) / ENTRY_LEN;
/// The longest RIPng message.
pub const MAX_NG_MESSAGE: usize = HEADER_LEN + MAX_NG_ENTRIES * ENTRY_LEN;
/// The longest prefix length in a RIPng route.
pub const MAX_PREFIX_LEN: u8 = 128;
/// The metric that marks a RIPng entry as a next hop entry.
pub const NEXT_HOP_METRIC: u8 = 0xff;

/// Address family identifiers in RIP entries.
pub mod family {
    /// In a request, asks for the whole table.
    pub const WHOLE_TABLE: u16 = 0;
    /// An IPv4 route.
    pub const INET: u16 = 2;
    /// An authentication entry (version 2 only).
    pub const AUTH: u16 = 0xffff;
}

/// Authentication types in a version 2 authentication entry.
pub mod auth_type {
    /// A password of up to 16 bytes, padded with zeros (RFC 2453).
    pub const PASSWORD: u16 = 2;
    /// A keyed digest in a trailer after the routes (RFC 4822).
    pub const CRYPTO: u16 = 3;
}

/// What a message asks or tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    /// A request for routes (command 1).
    Request,
    /// Routes, sent in answer to a request or as an update (command 2).
    Response,
}

impl Command {
    /// The command's byte.
    pub fn code(self) -> u8 {
        match self {
            Command::Request => 1,
            Command::Response => 2,
        }
    }

    fn from_code(c: u8) -> Result<Command, RipError> {
        match c {
            1 => Ok(Command::Request),
            2 => Ok(Command::Response),
            _ => Err(RipError::Command(c)),
        }
    }

    /// Whether `metric` is allowed in an entry of a message with this
    /// command: 1 to 16 in a response, 0 to 16 in a request.
    pub fn allows_metric(self, metric: u32) -> bool {
        let low = match self {
            Command::Request => 0,
            Command::Response => 1,
        };
        (low..=u32::from(INFINITY)).contains(&metric)
    }
}

/// The RIP version of a message on port 520.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// Version 1: no masks, next hops, tags or authentication.
    V1,
    /// Version 2 (RFC 2453).
    V2,
}

impl Version {
    /// The version's byte.
    pub fn code(self) -> u8 {
        match self {
            Version::V1 => 1,
            Version::V2 => 2,
        }
    }
}

/// One IPv4 route. In version 1 the tag, mask and next hop are always
/// zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouteEntry {
    /// A value the router passes along unchanged, often the number of the
    /// system an external route came from.
    pub tag: u16,
    /// The destination network or host.
    pub address: Ipv4Addr,
    /// The destination's subnet mask: leading ones, then zeros. Zero means
    /// no mask was given.
    pub mask: Ipv4Addr,
    /// Where to send packets for the destination. Zero means the router
    /// that sent the message.
    pub next_hop: Ipv4Addr,
    /// Hops to the destination: 1 to 16 in a response, 0 to 16 in a
    /// request. [`INFINITY`] means unreachable.
    pub metric: u8,
}

/// The cryptographic authentication of RFC 4822. The digest itself is
/// kept as bytes for world code to check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Crypto {
    /// Which key was used.
    pub key_id: u8,
    /// The length of the authentication data as the sender gives it. RFC
    /// 4822 says it is the length of [`Crypto::data`]. Some routers count
    /// the 4-byte trailer header too, so both are read.
    pub data_len: u8,
    /// A number the sender never lets go down, to stop replays.
    pub sequence: u32,
    /// The authentication data from the trailer, at most
    /// [`MAX_AUTH_DATA`] bytes.
    pub data: Vec<u8>,
}

/// A version 2 authentication entry, the first entry of a message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Auth {
    /// A password ([`auth_type::PASSWORD`]), padded with zeros.
    Password([u8; 16]),
    /// A digest in a trailer ([`auth_type::CRYPTO`]).
    Crypto(Crypto),
    /// Any other type, with its 16 bytes as sent. The type is never
    /// [`auth_type::PASSWORD`] or [`auth_type::CRYPTO`].
    Other {
        /// The authentication type.
        kind: u16,
        /// The entry's last 16 bytes.
        data: [u8; 16],
    },
}

/// What a RIP message carries after any authentication entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Entries {
    /// A request for the whole table: one entry of family 0 and metric
    /// 16. Only a request carries it. The entry's other fields are
    /// ignored when read and written as zero.
    WholeTable,
    /// Routes. A message may have none only if it has an authentication
    /// entry.
    Routes(Vec<RouteEntry>),
}

/// A RIP message (versions 1 and 2), the payload of a UDP datagram on
/// port [`PORT`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    /// Request or response.
    pub command: Command,
    /// Version 1 or 2.
    pub version: Version,
    /// The authentication entry. Only version 2 has one.
    pub auth: Option<Auth>,
    /// The routes, or a request for all of them.
    pub entries: Entries,
}

/// Why bytes are not a RIP or RIPng message, or why a message cannot be
/// written. Entries are counted from 0 in the order they are sent, the
/// authentication entry included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RipError {
    /// The message ends before its header does, or part way through an
    /// entry or the trailer header.
    Truncated,
    /// The command is not 1 (request) or 2 (response).
    Command(u8),
    /// The version is not 1 or 2 (RIP) or not 1 (RIPng).
    Version(u8),
    /// A version 1 field that must be zero is not. `offset` is where it
    /// starts in the message.
    MustBeZero {
        /// The field's offset from the start of the message.
        offset: usize,
    },
    /// An entry's address family is not one this message may carry.
    Family {
        /// The entry.
        entry: usize,
        /// The family it gives.
        family: u16,
    },
    /// An authentication entry is not the first entry.
    AuthPlace {
        /// The entry.
        entry: usize,
    },
    /// A whole-table entry is in a response, is not the only route entry,
    /// or has a metric other than 16.
    WholeTable {
        /// The entry.
        entry: usize,
    },
    /// A metric is outside 1 to 16 in a response or 0 to 16 in a request.
    Metric {
        /// The entry.
        entry: usize,
        /// The metric it gives.
        metric: u32,
    },
    /// A subnet mask is not leading ones and then zeros.
    Mask {
        /// The entry.
        entry: usize,
    },
    /// A RIPng prefix length is above 128.
    PrefixLength {
        /// The entry.
        entry: usize,
        /// The length it gives.
        len: u8,
    },
    /// The packet length in a cryptographic authentication entry does not
    /// end on an entry within [`MAX_ENTRIES`], after the authentication
    /// entry.
    PacketLength(u16),
    /// The trailer does not start with `0xffff 0x0001`.
    Trailer,
    /// The trailer holds more than [`MAX_AUTH_DATA`] bytes of data.
    AuthDataTooLong,
    /// The trailer's data is not as long as the authentication entry says.
    AuthDataLen {
        /// The length the entry gives.
        declared: u8,
        /// The bytes in the trailer.
        actual: usize,
    },
    /// The message has no entries.
    NoEntries,
    /// The message has more than [`MAX_ENTRIES`] (RIP) or
    /// [`MAX_NG_ENTRIES`] (RIPng) entries.
    TooManyEntries,
    /// A message that would read back as a different message, such as an
    /// [`Auth::Other`] with a type this module reads as another variant.
    Unrepresentable,
}

impl std::fmt::Display for RipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RipError::Truncated => write!(f, "message cut short"),
            RipError::Command(c) => write!(f, "command {c}, not 1 or 2"),
            RipError::Version(v) => write!(f, "unknown version {v}"),
            RipError::MustBeZero { offset } => write!(f, "must-be-zero field at offset {offset} is not zero"),
            RipError::Family { entry, family } => write!(f, "entry {entry} has address family {family}"),
            RipError::AuthPlace { entry } => write!(f, "authentication entry {entry} is not the first"),
            RipError::WholeTable { entry } => write!(f, "entry {entry} is a malformed whole-table request"),
            RipError::Metric { entry, metric } => write!(f, "entry {entry} has metric {metric}"),
            RipError::Mask { entry } => write!(f, "entry {entry} has a mask that is not contiguous"),
            RipError::PrefixLength { entry, len } => write!(f, "entry {entry} has prefix length {len}"),
            RipError::PacketLength(n) => write!(f, "authentication packet length {n} is not valid"),
            RipError::Trailer => write!(f, "authentication trailer header is not 0xffff 0x0001"),
            RipError::AuthDataTooLong => write!(f, "authentication trailer is too long"),
            RipError::AuthDataLen { declared, actual } => {
                write!(f, "authentication data is {actual} bytes, entry says {declared}")
            }
            RipError::NoEntries => write!(f, "message has no entries"),
            RipError::TooManyEntries => write!(f, "message has too many entries"),
            RipError::Unrepresentable => write!(f, "message would not read back the same"),
        }
    }
}

impl std::error::Error for RipError {}

impl Message {
    /// A request for the whole table, with no authentication.
    pub fn whole_table_request(version: Version) -> Message {
        Message { command: Command::Request, version, auth: None, entries: Entries::WholeTable }
    }

    /// Reads a message: a whole UDP payload.
    pub fn parse(b: &[u8]) -> Result<Message, RipError> {
        match scan_rip(b, true)? {
            Some(m) => Ok(m),
            // A complete scan always gives a message.
            None => Err(RipError::Truncated),
        }
    }

    /// The message's bytes. It fails if the message breaks a rule the
    /// reader checks, with the error the reader would give, or if it would
    /// read back as a different message.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RipError> {
        let routes = match &self.entries {
            Entries::WholeTable => 1,
            Entries::Routes(r) => r.len(),
        };
        if routes.saturating_add(usize::from(self.auth.is_some())) > MAX_ENTRIES {
            return Err(RipError::TooManyEntries);
        }
        let mut out = Vec::with_capacity(MAX_MESSAGE);
        out.extend_from_slice(&[self.command.code(), self.version.code(), 0, 0]);
        let mut trailer: Option<&[u8]> = None;
        match &self.auth {
            None => {}
            Some(Auth::Password(p)) => {
                out.extend_from_slice(&family::AUTH.to_be_bytes());
                out.extend_from_slice(&auth_type::PASSWORD.to_be_bytes());
                out.extend_from_slice(p);
            }
            Some(Auth::Other { kind, data }) => {
                if *kind == auth_type::PASSWORD || *kind == auth_type::CRYPTO {
                    return Err(RipError::Unrepresentable);
                }
                out.extend_from_slice(&family::AUTH.to_be_bytes());
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(data);
            }
            Some(Auth::Crypto(c)) => {
                if c.data.len() > MAX_AUTH_DATA {
                    return Err(RipError::AuthDataTooLong);
                }
                // At most 25 entries, so this fits in 16 bits.
                let packet_len = (HEADER_LEN + (1 + routes) * ENTRY_LEN) as u16;
                out.extend_from_slice(&family::AUTH.to_be_bytes());
                out.extend_from_slice(&auth_type::CRYPTO.to_be_bytes());
                out.extend_from_slice(&packet_len.to_be_bytes());
                out.push(c.key_id);
                out.push(c.data_len);
                out.extend_from_slice(&c.sequence.to_be_bytes());
                out.extend_from_slice(&[0; 8]);
                trailer = Some(&c.data);
            }
        }
        match &self.entries {
            Entries::WholeTable => {
                out.extend_from_slice(&[0; 16]);
                out.extend_from_slice(&u32::from(INFINITY).to_be_bytes());
            }
            Entries::Routes(routes) => {
                for r in routes {
                    out.extend_from_slice(&family::INET.to_be_bytes());
                    out.extend_from_slice(&r.tag.to_be_bytes());
                    out.extend_from_slice(&r.address.octets());
                    out.extend_from_slice(&r.mask.octets());
                    out.extend_from_slice(&r.next_hop.octets());
                    out.extend_from_slice(&u32::from(r.metric).to_be_bytes());
                }
            }
        }
        if let Some(data) = trailer {
            out.extend_from_slice(&[0xff, 0xff, 0, 1]);
            out.extend_from_slice(data);
        }
        if Message::parse(&out)? != *self {
            return Err(RipError::Unrepresentable);
        }
        Ok(out)
    }
}

/// Whether `mask` is leading ones and then zeros. Zero passes.
fn contiguous(mask: u32) -> bool {
    let inv = !mask;
    inv & inv.wrapping_add(1) == 0
}

/// Reads a RIP message in byte order. With `complete` false, `b` may be
/// the start of a message: it returns `Ok(None)` unless the bytes so far
/// break a rule. Every check that fails on a prefix fails the same way on
/// any longer message, so a decoder can stop early.
fn scan_rip(b: &[u8], complete: bool) -> Result<Option<Message>, RipError> {
    let short = |complete: bool| if complete { Err(RipError::Truncated) } else { Ok(None) };
    let Some(&c) = b.first() else { return short(complete) };
    let command = Command::from_code(c)?;
    let Some(&v) = b.get(1) else { return short(complete) };
    let version = match v {
        1 => Version::V1,
        2 => Version::V2,
        _ => return Err(RipError::Version(v)),
    };
    if b.len() < HEADER_LEN {
        // Version 1's must-be-zero bytes are checked one at a time.
        if version == Version::V1 && b.get(2).is_some_and(|&x| x != 0) {
            return Err(RipError::MustBeZero { offset: 2 });
        }
        return short(complete);
    }
    if version == Version::V1 && (b[2] != 0 || b[3] != 0) {
        return Err(RipError::MustBeZero { offset: 2 });
    }
    let mut auth: Option<Auth> = None;
    let mut routes = Vec::new();
    let mut whole = false;
    // Where the entries end, when a cryptographic entry says so.
    let mut entries_end: Option<usize> = None;
    let mut entry = 0;
    let mut at = HEADER_LEN;
    loop {
        if entries_end.is_some_and(|end| at >= end) {
            break;
        }
        let Some(e) = b.get(at..at + ENTRY_LEN) else { break };
        if entry >= MAX_ENTRIES {
            return Err(RipError::TooManyEntries);
        }
        let fam = be16(e, 0);
        if version == Version::V1 && (fam == family::WHOLE_TABLE || fam == family::INET) {
            for (off, len) in [(2, 2), (8, 4), (12, 4)] {
                if e[off..off + len].iter().any(|&x| x != 0) {
                    return Err(RipError::MustBeZero { offset: at + off });
                }
            }
        }
        match fam {
            family::AUTH if version == Version::V2 => {
                if entry != 0 {
                    return Err(RipError::AuthPlace { entry });
                }
                let kind = be16(e, 2);
                let mut data = [0u8; 16];
                data.copy_from_slice(&e[4..20]);
                auth = Some(match kind {
                    auth_type::PASSWORD => Auth::Password(data),
                    auth_type::CRYPTO => {
                        let packet_len = be16(e, 4);
                        let n = usize::from(packet_len);
                        let ok = n >= HEADER_LEN + ENTRY_LEN
                            && (n - HEADER_LEN).is_multiple_of(ENTRY_LEN)
                            && n <= HEADER_LEN + MAX_ENTRIES * ENTRY_LEN;
                        if !ok {
                            return Err(RipError::PacketLength(packet_len));
                        }
                        entries_end = Some(n);
                        Auth::Crypto(Crypto { key_id: e[6], data_len: e[7], sequence: be32(e, 8), data: Vec::new() })
                    }
                    _ => Auth::Other { kind, data },
                });
            }
            family::WHOLE_TABLE => {
                // RFC 2453 names only the family and the metric, so the
                // other fields are ignored.
                if command != Command::Request || whole || !routes.is_empty() || be32(e, 16) != u32::from(INFINITY) {
                    return Err(RipError::WholeTable { entry });
                }
                whole = true;
            }
            family::INET => {
                if whole {
                    return Err(RipError::WholeTable { entry });
                }
                let tag = be16(e, 2);
                let mask = be32(e, 8);
                let next_hop = be32(e, 12);
                if !contiguous(mask) {
                    return Err(RipError::Mask { entry });
                }
                let metric = be32(e, 16);
                if !command.allows_metric(metric) {
                    return Err(RipError::Metric { entry, metric });
                }
                routes.push(RouteEntry {
                    tag,
                    address: Ipv4Addr::from(be32(e, 4)),
                    mask: Ipv4Addr::from(mask),
                    next_hop: Ipv4Addr::from(next_hop),
                    // Checked above to be at most 16.
                    metric: metric as u8,
                });
            }
            _ => return Err(RipError::Family { entry, family: fam }),
        }
        entry += 1;
        at += ENTRY_LEN;
    }
    if let Some(end) = entries_end {
        if let Some(h) = b.get(end..end + TRAILER_HEADER_LEN)
            && h != [0xff, 0xff, 0, 1] {
                return Err(RipError::Trailer);
            }
        let data = b.get(end + TRAILER_HEADER_LEN..).unwrap_or(&[]);
        if data.len() > MAX_AUTH_DATA {
            return Err(RipError::AuthDataTooLong);
        }
        if !complete {
            return Ok(None);
        }
        if b.len() < end + TRAILER_HEADER_LEN {
            return Err(RipError::Truncated);
        }
        if let Some(Auth::Crypto(c)) = &mut auth {
            let declared = usize::from(c.data_len);
            if declared != data.len() && declared != data.len() + TRAILER_HEADER_LEN {
                return Err(RipError::AuthDataLen { declared: c.data_len, actual: data.len() });
            }
            c.data = data.to_vec();
        }
    } else {
        if !complete {
            return Ok(None);
        }
        if at != b.len() {
            return Err(RipError::Truncated);
        }
    }
    if entry == 0 {
        return Err(RipError::NoEntries);
    }
    let entries = if whole { Entries::WholeTable } else { Entries::Routes(routes) };
    Ok(Some(Message { command, version, auth, entries }))
}

/// Reads one RIP message that comes in pieces. Feed it the bytes in order,
/// then call [`Decoder::finish`]. It fails as soon as the bytes show a bad
/// field or run past the longest message. It holds at most
/// [`MAX_MESSAGE`] plus one bytes.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    failed: Option<RipError>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds the next bytes of the message. It returns the error once the
    /// bytes show one, and the same error on every later call. Bytes fed
    /// after that are dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), RipError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        // Any message of MAX_MESSAGE + 1 bytes breaks a rule, so bytes
        // past that are never needed.
        let room = (MAX_MESSAGE + 1).saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        match scan_rip(&self.buf, false) {
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    }

    /// How many bytes are held.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The message, when no more bytes will come. It gives the same result
    /// as [`Message::parse`] on all the bytes fed.
    pub fn finish(self) -> Result<Message, RipError> {
        match self.failed {
            Some(e) => Err(e),
            None => Message::parse(&self.buf),
        }
    }
}

/// One RIPng route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NgRoute {
    /// The destination prefix.
    pub prefix: Ipv6Addr,
    /// A value the router passes along unchanged.
    pub tag: u16,
    /// How many leading bits of the prefix count: 0 to 128.
    pub prefix_len: u8,
    /// Hops to the destination: 1 to 16 in a response, 0 to 16 in a
    /// request.
    pub metric: u8,
}

/// One RIPng entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NgEntry {
    /// A route.
    Route(NgRoute),
    /// A next hop for the routes after it, up to the next next hop entry.
    /// `::` means the router that sent the message. On the wire its metric
    /// is [`NEXT_HOP_METRIC`] and its tag and prefix length are zero.
    NextHop(Ipv6Addr),
}

/// What a RIPng message carries.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NgEntries {
    /// A request for the whole table: one route `::/0` with metric 16.
    /// Only a request carries it. Its tag is ignored when read and written
    /// as zero.
    WholeTable,
    /// Routes and next hops, at least one. A request that holds only
    /// `::/0` with metric 16, whatever its tag, is
    /// [`NgEntries::WholeTable`] instead.
    Entries(Vec<NgEntry>),
}

/// A RIPng message, the payload of a UDP datagram on port [`NG_PORT`].
/// Its version is always 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NgMessage {
    /// Request or response.
    pub command: Command,
    /// The entries, or a request for all routes.
    pub entries: NgEntries,
}

const WHOLE_TABLE_NG: NgRoute = NgRoute { prefix: Ipv6Addr::UNSPECIFIED, tag: 0, prefix_len: 0, metric: INFINITY };

impl NgMessage {
    /// A request for the whole table.
    pub fn whole_table_request() -> NgMessage {
        NgMessage { command: Command::Request, entries: NgEntries::WholeTable }
    }

    /// Reads a message: a whole UDP payload.
    pub fn parse(b: &[u8]) -> Result<NgMessage, RipError> {
        scan_ng(b)
    }

    /// The message's bytes. It fails if the message breaks a rule the
    /// reader checks, with the error the reader would give, or if it would
    /// read back as a different message.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RipError> {
        let one = [NgEntry::Route(WHOLE_TABLE_NG)];
        let entries: &[NgEntry] = match &self.entries {
            NgEntries::WholeTable => &one,
            NgEntries::Entries(e) => e,
        };
        if entries.len() > MAX_NG_ENTRIES {
            return Err(RipError::TooManyEntries);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + entries.len() * ENTRY_LEN);
        out.extend_from_slice(&[self.command.code(), 1, 0, 0]);
        for e in entries {
            match e {
                NgEntry::Route(r) => {
                    out.extend_from_slice(&r.prefix.octets());
                    out.extend_from_slice(&r.tag.to_be_bytes());
                    out.push(r.prefix_len);
                    out.push(r.metric);
                }
                NgEntry::NextHop(a) => {
                    out.extend_from_slice(&a.octets());
                    out.extend_from_slice(&[0, 0, 0, NEXT_HOP_METRIC]);
                }
            }
        }
        if NgMessage::parse(&out)? != *self {
            return Err(RipError::Unrepresentable);
        }
        Ok(out)
    }
}

/// Reads the RIPng header at the start of `b`: the command, once the
/// version is known to be 1. It returns `Ok(None)` if `b` is shorter than
/// the header.
fn ng_header(b: &[u8]) -> Result<Option<Command>, RipError> {
    let Some(&c) = b.first() else { return Ok(None) };
    let command = Command::from_code(c)?;
    let Some(&v) = b.get(1) else { return Ok(None) };
    if v != 1 {
        return Err(RipError::Version(v));
    }
    if b.len() < HEADER_LEN {
        return Ok(None);
    }
    Ok(Some(command))
}

/// Reads RIPng entry number `entry`, the 20 bytes `e`.
fn ng_entry(command: Command, entry: usize, e: &[u8]) -> Result<NgEntry, RipError> {
    if entry >= MAX_NG_ENTRIES {
        return Err(RipError::TooManyEntries);
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&e[..16]);
    let prefix = Ipv6Addr::from(a);
    let metric = e[19];
    if metric == NEXT_HOP_METRIC {
        return Ok(NgEntry::NextHop(prefix));
    }
    let prefix_len = e[18];
    if prefix_len > MAX_PREFIX_LEN {
        return Err(RipError::PrefixLength { entry, len: prefix_len });
    }
    if !command.allows_metric(u32::from(metric)) {
        return Err(RipError::Metric { entry, metric: u32::from(metric) });
    }
    Ok(NgEntry::Route(NgRoute { prefix, tag: be16(e, 16), prefix_len, metric }))
}

/// Whether a route asks for the whole table when it is a request's only
/// entry: RFC 2080 names the prefix, prefix length and metric, not the tag.
fn is_whole_table_ng(r: NgRoute) -> bool {
    r.prefix == Ipv6Addr::UNSPECIFIED && r.prefix_len == 0 && r.metric == INFINITY
}

/// Reads a whole RIPng message, checking it in byte order, so the first
/// rule a prefix breaks is the first rule the whole message breaks.
fn scan_ng(b: &[u8]) -> Result<NgMessage, RipError> {
    let Some(command) = ng_header(b)? else { return Err(RipError::Truncated) };
    let mut entries = Vec::new();
    let mut at = HEADER_LEN;
    while let Some(e) = b.get(at..at + ENTRY_LEN) {
        entries.push(ng_entry(command, entries.len(), e)?);
        at += ENTRY_LEN;
    }
    if at != b.len() {
        return Err(RipError::Truncated);
    }
    if entries.is_empty() {
        return Err(RipError::NoEntries);
    }
    let whole = command == Command::Request && matches!(entries[..], [NgEntry::Route(r)] if is_whole_table_ng(r));
    let entries = if whole { NgEntries::WholeTable } else { NgEntries::Entries(entries) };
    Ok(NgMessage { command, entries })
}

/// Reads one RIPng message that comes in pieces, as [`Decoder`] does for
/// RIP. It checks each entry once, as its last byte comes. It holds at
/// most [`MAX_NG_MESSAGE`] plus [`ENTRY_LEN`] bytes.
#[derive(Clone, Debug, Default)]
pub struct NgDecoder {
    buf: Vec<u8>,
    /// How many entries have been checked.
    checked: usize,
    failed: Option<RipError>,
}

impl NgDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> NgDecoder {
        NgDecoder::default()
    }

    /// Adds the next bytes of the message. It returns the error once the
    /// bytes show one, and the same error on every later call. Bytes fed
    /// after that are dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), RipError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        // Any message of this many bytes has one entry too many.
        let room = (MAX_NG_MESSAGE + ENTRY_LEN).saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        match self.check() {
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                Err(e)
            }
            Ok(()) => Ok(()),
        }
    }

    fn check(&mut self) -> Result<(), RipError> {
        let Some(command) = ng_header(&self.buf)? else { return Ok(()) };
        loop {
            let at = HEADER_LEN + self.checked * ENTRY_LEN;
            let Some(e) = self.buf.get(at..at + ENTRY_LEN) else { return Ok(()) };
            ng_entry(command, self.checked, e)?;
            self.checked += 1;
        }
    }

    /// How many bytes are held.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The message, when no more bytes will come. It gives the same result
    /// as [`NgMessage::parse`] on all the bytes fed.
    pub fn finish(self) -> Result<NgMessage, RipError> {
        match self.failed {
            Some(e) => Err(e),
            None => NgMessage::parse(&self.buf),
        }
    }
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// A version 2 route entry's bytes.
    fn v2_entry(tag: u16, address: [u8; 4], mask: [u8; 4], next_hop: [u8; 4], metric: u32) -> Vec<u8> {
        let mut e = vec![0, 2];
        e.extend_from_slice(&tag.to_be_bytes());
        e.extend_from_slice(&address);
        e.extend_from_slice(&mask);
        e.extend_from_slice(&next_hop);
        e.extend_from_slice(&metric.to_be_bytes());
        e
    }

    fn whole_table_entry() -> Vec<u8> {
        let mut e = vec![0; 16];
        e.extend_from_slice(&[0, 0, 0, 16]);
        e
    }

    fn ng_entry_bytes(prefix: Ipv6Addr, tag: u16, len: u8, metric: u8) -> Vec<u8> {
        let mut e = prefix.octets().to_vec();
        e.extend_from_slice(&tag.to_be_bytes());
        e.push(len);
        e.push(metric);
        e
    }

    fn msg(command: u8, version: u8, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![command, version, 0, 0];
        for e in entries {
            b.extend_from_slice(e);
        }
        b
    }

    fn crypto_message(data_len: u8, data: &[u8]) -> Vec<u8> {
        let mut b = vec![2, 2, 0, 0, 0xff, 0xff, 0, 3, 0, 44, 1, data_len, 0, 0, 0, 7];
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&v2_entry(0, [10, 1, 0, 0], [255, 255, 0, 0], [0; 4], 3));
        b.extend_from_slice(&[0xff, 0xff, 0, 1]);
        b.extend_from_slice(data);
        b
    }

    fn decode_chunked(b: &[u8], size: usize) -> Result<Message, RipError> {
        let mut d = Decoder::new();
        for c in b.chunks(size.max(1)) {
            let _ = d.feed(c);
        }
        d.finish()
    }

    fn ng_decode_chunked(b: &[u8], size: usize) -> Result<NgMessage, RipError> {
        let mut d = NgDecoder::new();
        for c in b.chunks(size.max(1)) {
            let _ = d.feed(c);
        }
        d.finish()
    }

    fn check(b: &[u8]) -> Result<Message, RipError> {
        let p = Message::parse(b);
        assert_eq!(decode_chunked(b, b.len()), p);
        assert_eq!(decode_chunked(b, 1), p);
        assert_eq!(decode_chunked(b, 7), p);
        if let Ok(m) = &p {
            let out = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&out).as_ref(), Ok(m));
        }
        p
    }

    fn ng_check(b: &[u8]) -> Result<NgMessage, RipError> {
        let p = NgMessage::parse(b);
        assert_eq!(ng_decode_chunked(b, b.len()), p);
        assert_eq!(ng_decode_chunked(b, 1), p);
        assert_eq!(ng_decode_chunked(b, 13), p);
        if let Ok(m) = &p {
            let out = m.to_bytes().unwrap();
            assert_eq!(NgMessage::parse(&out).as_ref(), Ok(m));
        }
        p
    }

    fn samples() -> Vec<Vec<u8>> {
        let mut pw = vec![0xff, 0xff, 0, 2];
        pw.extend_from_slice(b"secret\0\0\0\0\0\0\0\0\0\0");
        vec![
            msg(2, 1, &[v2_entry(0, [192, 168, 1, 0], [0; 4], [0; 4], 2)]),
            msg(1, 1, &[whole_table_entry()]),
            msg(1, 2, &[whole_table_entry()]),
            msg(2, 2, &[pw.clone(), v2_entry(7, [10, 0, 0, 0], [255, 0, 0, 0], [10, 0, 0, 1], 16)]),
            msg(
                2,
                2,
                &[
                    pw,
                    v2_entry(0, [10, 0, 0, 0], [255, 0, 0, 0], [0; 4], 1),
                    v2_entry(0, [10, 1, 0, 0], [255, 255, 0, 0], [0; 4], 2),
                ],
            ),
            crypto_message(16, &[0xab; 16]),
            crypto_message(20, &[0xcd; 16]),
        ]
    }

    fn ng_samples() -> Vec<Vec<u8>> {
        let doc: Ipv6Addr = "2001:db8::".parse().unwrap();
        let hop: Ipv6Addr = "fe80::1".parse().unwrap();
        vec![
            msg(1, 1, &[ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 0, 0, 16)]),
            msg(2, 1, &[ng_entry_bytes(hop, 0, 0, 0xff), ng_entry_bytes(doc, 9, 32, 1)]),
            msg(1, 1, &[ng_entry_bytes(doc, 0, 32, 0)]),
        ]
    }

    #[test]
    fn module_example() {
        let mut request = vec![1, 2, 0, 0];
        request.extend_from_slice(&whole_table_entry());
        assert_eq!(check(&request), Ok(Message::whole_table_request(Version::V2)));
        let reply = Message {
            command: Command::Response,
            version: Version::V2,
            auth: None,
            entries: Entries::Routes(vec![RouteEntry {
                tag: 0,
                address: ip4(10, 0, 0, 0),
                mask: ip4(255, 0, 0, 0),
                next_hop: Ipv4Addr::UNSPECIFIED,
                metric: 1,
            }]),
        };
        let bytes = reply.to_bytes().unwrap();
        assert_eq!(bytes, [2, 2, 0, 0, 0, 2, 0, 0, 10, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(check(&bytes), Ok(reply));
    }

    #[test]
    fn version_1_response() {
        let b = msg(2, 1, &[v2_entry(0, [192, 168, 1, 0], [0; 4], [0; 4], 2)]);
        let m = check(&b).unwrap();
        assert_eq!(m.version, Version::V1);
        assert_eq!(
            m.entries,
            Entries::Routes(vec![RouteEntry {
                tag: 0,
                address: ip4(192, 168, 1, 0),
                mask: Ipv4Addr::UNSPECIFIED,
                next_hop: Ipv4Addr::UNSPECIFIED,
                metric: 2,
            }])
        );
        assert_eq!(m.to_bytes().unwrap(), b);
    }

    #[test]
    fn whole_table_requests() {
        let v1 = msg(1, 1, &[whole_table_entry()]);
        assert_eq!(check(&v1), Ok(Message::whole_table_request(Version::V1)));
        assert_eq!(Message::whole_table_request(Version::V1).to_bytes().unwrap(), v1);
        let ng = msg(1, 1, &[ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 0, 0, 16)]);
        assert_eq!(ng_check(&ng), Ok(NgMessage::whole_table_request()));
        assert_eq!(NgMessage::whole_table_request().to_bytes().unwrap(), ng);
        // In a response the same entry is a route to ::/0 that cannot be
        // reached.
        let ng_resp = msg(2, 1, &[ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 0, 0, 16)]);
        assert!(matches!(ng_check(&ng_resp).unwrap().entries, NgEntries::Entries(_)));
    }

    #[test]
    fn password_authentication() {
        let b = &samples()[3];
        let m = check(b).unwrap();
        let mut p = [0u8; 16];
        p[..6].copy_from_slice(b"secret");
        assert_eq!(m.auth, Some(Auth::Password(p)));
        assert_eq!(&m.to_bytes().unwrap(), b);
        // An unknown type keeps its bytes.
        let mut other = b.clone();
        other[7] = 9;
        let m = check(&other).unwrap();
        assert_eq!(m.auth, Some(Auth::Other { kind: 9, data: p }));
        assert_eq!(m.to_bytes().unwrap(), other);
        // An authentication entry with no routes after it.
        let alone = msg(2, 2, &[b[4..24].to_vec()]);
        assert_eq!(check(&alone).unwrap().entries, Entries::Routes(vec![]));
    }

    #[test]
    fn crypto_authentication() {
        let b = crypto_message(16, &[0xab; 16]);
        let m = check(&b).unwrap();
        assert_eq!(m.auth, Some(Auth::Crypto(Crypto { key_id: 1, data_len: 16, sequence: 7, data: vec![0xab; 16] })));
        assert_eq!(m.to_bytes().unwrap(), b);
        // The length that counts the trailer header is read too.
        let b20 = crypto_message(20, &[0xcd; 16]);
        assert_eq!(check(&b20).unwrap().to_bytes().unwrap(), b20);
        // The reserved fields are ignored, and written as zero.
        let mut r = b.clone();
        r[16] = 1;
        assert_eq!(check(&r).unwrap().to_bytes().unwrap(), b);
    }

    #[test]
    fn version_2_unused_header_is_ignored() {
        let mut b = samples()[2].clone();
        b[2] = 0x12;
        assert_eq!(check(&b).unwrap().to_bytes().unwrap(), samples()[2]);
    }

    #[test]
    fn ripng_next_hop() {
        let b = &ng_samples()[1];
        let m = ng_check(b).unwrap();
        assert_eq!(
            m.entries,
            NgEntries::Entries(vec![
                NgEntry::NextHop("fe80::1".parse().unwrap()),
                NgEntry::Route(NgRoute { prefix: "2001:db8::".parse().unwrap(), tag: 9, prefix_len: 32, metric: 1 }),
            ])
        );
        assert_eq!(&m.to_bytes().unwrap(), b);
        // A next hop's tag and prefix length are ignored.
        let mut odd = b.clone();
        odd[20] = 5;
        odd[22] = 64;
        assert_eq!(&ng_check(&odd).unwrap().to_bytes().unwrap(), b);
    }

    #[test]
    fn rip_errors() {
        let route = v2_entry(0, [10, 0, 0, 0], [255, 0, 0, 0], [0; 4], 1);
        let v1_route = v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 1);
        let mut pw = vec![0xff, 0xff, 0, 2];
        pw.extend_from_slice(&[0; 16]);
        let cases: Vec<(Vec<u8>, RipError)> = vec![
            (vec![], RipError::Truncated),
            (vec![2, 2, 0], RipError::Truncated),
            (msg(2, 2, &[route[..19].to_vec()]), RipError::Truncated),
            (msg(3, 2, std::slice::from_ref(&route)), RipError::Command(3)),
            (msg(0, 2, std::slice::from_ref(&route)), RipError::Command(0)),
            (msg(2, 0, std::slice::from_ref(&route)), RipError::Version(0)),
            (msg(2, 3, std::slice::from_ref(&route)), RipError::Version(3)),
            ([vec![2, 1, 0, 1], v1_route.clone()].concat(), RipError::MustBeZero { offset: 2 }),
            (vec![2, 1, 1], RipError::MustBeZero { offset: 2 }),
            (msg(2, 1, &[v2_entry(1, [10, 0, 0, 0], [0; 4], [0; 4], 1)]), RipError::MustBeZero { offset: 6 }),
            (msg(2, 1, std::slice::from_ref(&route)), RipError::MustBeZero { offset: 12 }),
            (msg(2, 1, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [1; 4], 1)]), RipError::MustBeZero { offset: 16 }),
            (msg(2, 1, &[pw.clone()]), RipError::Family { entry: 0, family: 0xffff }),
            (
                msg(2, 2, &[route.clone(), [vec![0, 7], route[2..].to_vec()].concat()]),
                RipError::Family { entry: 1, family: 7 },
            ),
            (msg(2, 2, &[route.clone(), pw.clone()]), RipError::AuthPlace { entry: 1 }),
            (msg(2, 2, &[whole_table_entry()]), RipError::WholeTable { entry: 0 }),
            (msg(1, 2, &[route.clone(), whole_table_entry()]), RipError::WholeTable { entry: 1 }),
            (msg(1, 2, &[whole_table_entry(), route.clone()]), RipError::WholeTable { entry: 1 }),
            (msg(1, 2, &[whole_table_entry(), whole_table_entry()]), RipError::WholeTable { entry: 1 }),
            (msg(1, 2, &[[&[0u8; 16][..], &[0, 0, 0, 15]].concat()]), RipError::WholeTable { entry: 0 }),
            (
                msg(1, 1, &[[&[0u8, 0, 0, 1][..], &[0; 12], &[0, 0, 0, 16]].concat()]),
                RipError::MustBeZero { offset: 6 },
            ),
            (msg(2, 2, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 0)]), RipError::Metric { entry: 0, metric: 0 }),
            (msg(2, 2, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 17)]), RipError::Metric { entry: 0, metric: 17 }),
            (
                msg(1, 2, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 0x100)]),
                RipError::Metric { entry: 0, metric: 0x100 },
            ),
            (msg(2, 2, &[v2_entry(0, [10, 0, 0, 0], [255, 0, 255, 0], [0; 4], 1)]), RipError::Mask { entry: 0 }),
            (vec![2, 2, 0, 0], RipError::NoEntries),
            (msg(2, 2, &vec![route.clone(); MAX_ENTRIES + 1]), RipError::TooManyEntries),
        ];
        for (b, e) in &cases {
            assert_eq!(check(b), Err(*e), "{b:?}");
        }
        // A request with metric 0 is fine; a response is not.
        assert!(check(&msg(1, 2, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 0)])).is_ok());
        // The most entries a message may hold.
        assert!(check(&msg(2, 2, &vec![route.clone(); MAX_ENTRIES])).is_ok());
    }

    #[test]
    fn crypto_errors() {
        let good = crypto_message(16, &[1; 16]);
        let with_len = |n: u16| {
            let mut b = good.clone();
            b[8..10].copy_from_slice(&n.to_be_bytes());
            b
        };
        for n in [0, 20, 30, 504 + 20, 0xffff] {
            assert_eq!(check(&with_len(n)), Err(RipError::PacketLength(n)));
        }
        // A packet length past the trailer reads the trailer as an entry.
        assert_eq!(check(&with_len(64)), Err(RipError::AuthPlace { entry: 2 }));
        assert_eq!(check(&good[..44]), Err(RipError::Truncated));
        let mut bad = good.clone();
        bad[47] = 2;
        assert_eq!(check(&bad), Err(RipError::Trailer));
        assert_eq!(check(&good[..46]), Err(RipError::Truncated));
        assert_eq!(check(&crypto_message(16, &[1; 15])), Err(RipError::AuthDataLen { declared: 16, actual: 15 }));
        assert_eq!(check(&crypto_message(255, &[1; 256])), Err(RipError::AuthDataTooLong));
        assert!(check(&crypto_message(255, &[1; 255])).is_ok());
        // Packet length 24 is the authentication entry alone.
        let mut alone = vec![2, 2, 0, 0, 0xff, 0xff, 0, 3, 0, 24, 1, 0, 0, 0, 0, 1];
        alone.extend_from_slice(&[0; 8]);
        alone.extend_from_slice(&[0xff, 0xff, 0, 1]);
        assert_eq!(check(&alone).unwrap().entries, Entries::Routes(vec![]));
    }

    #[test]
    fn ripng_errors() {
        let doc: Ipv6Addr = "2001:db8::".parse().unwrap();
        let route = ng_entry_bytes(doc, 0, 32, 1);
        let cases: Vec<(Vec<u8>, RipError)> = vec![
            (vec![], RipError::Truncated),
            (vec![2, 1, 0], RipError::Truncated),
            (msg(2, 1, &[route[..10].to_vec()]), RipError::Truncated),
            (msg(9, 1, std::slice::from_ref(&route)), RipError::Command(9)),
            (msg(2, 2, std::slice::from_ref(&route)), RipError::Version(2)),
            (msg(2, 0, std::slice::from_ref(&route)), RipError::Version(0)),
            (
                msg(2, 1, &[route.clone(), ng_entry_bytes(doc, 0, 129, 1)]),
                RipError::PrefixLength { entry: 1, len: 129 },
            ),
            (msg(2, 1, &[ng_entry_bytes(doc, 0, 32, 0)]), RipError::Metric { entry: 0, metric: 0 }),
            (msg(2, 1, &[ng_entry_bytes(doc, 0, 32, 17)]), RipError::Metric { entry: 0, metric: 17 }),
            (msg(1, 1, &[ng_entry_bytes(doc, 0, 32, 0xfe)]), RipError::Metric { entry: 0, metric: 0xfe }),
            (vec![2, 1, 0, 0], RipError::NoEntries),
        ];
        for (b, e) in &cases {
            assert_eq!(ng_check(b), Err(*e), "{b:?}");
        }
        // One entry too many, fed whole and a byte at a time.
        let mut big = vec![2, 1, 0, 0];
        for _ in 0..=MAX_NG_ENTRIES {
            big.extend_from_slice(&route);
        }
        assert_eq!(ng_check(&big), Err(RipError::TooManyEntries));
        let at_most = &big[..MAX_NG_MESSAGE];
        assert!(ng_check(at_most).is_ok());
        // The header's unused field is ignored.
        let mut b = msg(2, 1, std::slice::from_ref(&route));
        b[3] = 1;
        assert_eq!(ng_check(&b).unwrap().to_bytes().unwrap(), msg(2, 1, &[route]));
    }

    #[test]
    fn writer_errors() {
        let route = RouteEntry {
            tag: 0,
            address: ip4(10, 0, 0, 0),
            mask: ip4(255, 0, 0, 0),
            next_hop: Ipv4Addr::UNSPECIFIED,
            metric: 1,
        };
        let base = Message {
            command: Command::Response,
            version: Version::V2,
            auth: None,
            entries: Entries::Routes(vec![route]),
        };
        let mut m = base.clone();
        m.entries = Entries::Routes(vec![route; MAX_ENTRIES + 1]);
        assert_eq!(m.to_bytes(), Err(RipError::TooManyEntries));
        let mut m = base.clone();
        m.entries = Entries::Routes(vec![route; MAX_ENTRIES]);
        m.auth = Some(Auth::Password([0; 16]));
        assert_eq!(m.to_bytes(), Err(RipError::TooManyEntries));
        let mut m = base.clone();
        m.auth = Some(Auth::Crypto(Crypto { key_id: 1, data_len: 0, sequence: 0, data: vec![0; 256] }));
        assert_eq!(m.to_bytes(), Err(RipError::AuthDataTooLong));
        let mut m = base.clone();
        m.auth = Some(Auth::Crypto(Crypto { key_id: 1, data_len: 3, sequence: 0, data: vec![0; 16] }));
        assert_eq!(m.to_bytes(), Err(RipError::AuthDataLen { declared: 3, actual: 16 }));
        for kind in [auth_type::PASSWORD, auth_type::CRYPTO] {
            let mut m = base.clone();
            m.auth = Some(Auth::Other { kind, data: [0; 16] });
            assert_eq!(m.to_bytes(), Err(RipError::Unrepresentable));
        }
        let mut m = base.clone();
        m.version = Version::V1;
        assert_eq!(m.to_bytes(), Err(RipError::MustBeZero { offset: 12 }));
        let mut m = Message::whole_table_request(Version::V1);
        m.auth = Some(Auth::Password([0; 16]));
        assert_eq!(m.to_bytes(), Err(RipError::Family { entry: 0, family: 0xffff }));
        let mut m = Message::whole_table_request(Version::V2);
        m.command = Command::Response;
        assert_eq!(m.to_bytes(), Err(RipError::WholeTable { entry: 0 }));
        let mut m = base.clone();
        m.entries = Entries::Routes(vec![RouteEntry { metric: 17, ..route }]);
        assert_eq!(m.to_bytes(), Err(RipError::Metric { entry: 0, metric: 17 }));
        let mut m = base.clone();
        m.entries = Entries::Routes(vec![]);
        assert_eq!(m.to_bytes(), Err(RipError::NoEntries));

        let whole = NgRoute { prefix: Ipv6Addr::UNSPECIFIED, tag: 0, prefix_len: 0, metric: 16 };
        let m = NgMessage { command: Command::Request, entries: NgEntries::Entries(vec![NgEntry::Route(whole)]) };
        assert_eq!(m.to_bytes(), Err(RipError::Unrepresentable));
        let m = NgMessage { command: Command::Response, entries: NgEntries::WholeTable };
        assert_eq!(m.to_bytes(), Err(RipError::Unrepresentable));
        let m = NgMessage { command: Command::Response, entries: NgEntries::Entries(vec![]) };
        assert_eq!(m.to_bytes(), Err(RipError::NoEntries));
        let m = NgMessage {
            command: Command::Response,
            entries: NgEntries::Entries(vec![NgEntry::NextHop(Ipv6Addr::UNSPECIFIED); MAX_NG_ENTRIES + 1]),
        };
        assert_eq!(m.to_bytes(), Err(RipError::TooManyEntries));
        let m = NgMessage {
            command: Command::Response,
            entries: NgEntries::Entries(vec![NgEntry::Route(NgRoute { prefix_len: 200, metric: 1, ..whole })]),
        };
        assert_eq!(m.to_bytes(), Err(RipError::PrefixLength { entry: 0, len: 200 }));
    }

    #[test]
    fn every_truncated_prefix() {
        for b in samples() {
            let crypto = b.len() >= 8 && b[4..8] == [0xff, 0xff, 0, 3];
            for k in 0..b.len() {
                let p = &b[..k];
                let r = check(p);
                let boundary = k >= HEADER_LEN && (k - HEADER_LEN).is_multiple_of(ENTRY_LEN);
                match r {
                    // A crypto message cut 4 bytes into its data reads as
                    // one whose length counts the trailer header.
                    Ok(_) => assert!(if crypto { k + 4 == b.len() } else { boundary }, "{k} {b:?}"),
                    Err(e) => assert!(
                        matches!(e, RipError::Truncated | RipError::NoEntries | RipError::AuthDataLen { .. }),
                        "{k} {e:?}"
                    ),
                }
                // A decoder fed a prefix of a good message sees nothing wrong.
                let mut d = Decoder::new();
                for x in p {
                    assert_eq!(d.feed(std::slice::from_ref(x)), Ok(()));
                }
            }
        }
        for b in ng_samples() {
            for k in 0..b.len() {
                let p = &b[..k];
                let r = ng_check(p);
                let boundary = k >= HEADER_LEN && (k - HEADER_LEN).is_multiple_of(ENTRY_LEN);
                match r {
                    Ok(_) => assert!(boundary),
                    Err(e) => assert!(matches!(e, RipError::Truncated | RipError::NoEntries), "{k} {e:?}"),
                }
                let mut d = NgDecoder::new();
                for x in p {
                    assert_eq!(d.feed(std::slice::from_ref(x)), Ok(()));
                }
            }
        }
    }

    #[test]
    fn decoders_fail_early_and_stay_failed() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(&[7]), Err(RipError::Command(7)));
        assert_eq!(d.feed(&[1, 2, 3]), Err(RipError::Command(7)));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.finish(), Err(RipError::Command(7)));
        // A long stream is cut off once it breaks a rule.
        let mut d = Decoder::new();
        let mut errs = 0;
        for _ in 0..10_000 {
            if d.feed(&[2, 2, 0, 0, 0, 2]).is_err() {
                errs += 1;
            }
            assert!(d.buffered() <= MAX_MESSAGE + 1);
        }
        assert!(errs > 0);
        let mut n = NgDecoder::new();
        assert_eq!(n.feed(&[1, 2]), Err(RipError::Version(2)));
        assert_eq!(n.feed(&[1]), Err(RipError::Version(2)));
        assert_eq!(n.buffered(), 0);
        assert_eq!(n.finish(), Err(RipError::Version(2)));
    }

    #[test]
    fn whole_table_ignores_other_fields() {
        // RFC 2453: one entry of family 0 and metric 16 asks for the whole
        // table. The other fields do not matter in version 2.
        let mut e = whole_table_entry();
        e[2] = 1;
        e[4] = 10;
        e[8] = 255;
        assert_eq!(check(&msg(1, 2, &[e])), Ok(Message::whole_table_request(Version::V2)));
        // In version 1 the address is not a must-be-zero field.
        let mut e = whole_table_entry();
        e[4] = 10;
        assert_eq!(check(&msg(1, 1, &[e])), Ok(Message::whole_table_request(Version::V1)));
        // Its must-be-zero fields still are.
        let mut e = whole_table_entry();
        e[8] = 255;
        assert_eq!(check(&msg(1, 1, &[e])), Err(RipError::MustBeZero { offset: 12 }));
        // RFC 2080: the prefix, prefix length and metric decide; the tag
        // does not.
        let ng = msg(1, 1, &[ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 7, 0, 16)]);
        assert_eq!(ng_check(&ng), Ok(NgMessage::whole_table_request()));
        let tagged = NgRoute { tag: 7, ..WHOLE_TABLE_NG };
        let m = NgMessage { command: Command::Request, entries: NgEntries::Entries(vec![NgEntry::Route(tagged)]) };
        assert_eq!(m.to_bytes(), Err(RipError::Unrepresentable));
    }

    #[test]
    fn decoders_stay_bounded_on_long_input() {
        // A crypto message whose trailer never ends fails once the data
        // passes MAX_AUTH_DATA, fed whole or a byte at a time.
        let mut long = crypto_message(16, &[1; 16]);
        long.resize(10_000, 7);
        assert_eq!(check(&long), Err(RipError::AuthDataTooLong));
        let mut d = Decoder::new();
        let mut first = None;
        for x in &long {
            if let Err(e) = d.feed(std::slice::from_ref(x)) {
                first.get_or_insert(e);
            }
            assert!(d.buffered() <= MAX_MESSAGE + 1);
        }
        assert_eq!(first, Some(RipError::AuthDataTooLong));
        // A whole-table request with a crypto entry writes and reads back.
        let m = Message {
            command: Command::Request,
            version: Version::V2,
            auth: Some(Auth::Crypto(Crypto { key_id: 2, data_len: 4, sequence: 9, data: vec![5; 4] })),
            entries: Entries::WholeTable,
        };
        let b = m.to_bytes().unwrap();
        assert_eq!(b.len(), HEADER_LEN + 2 * ENTRY_LEN + TRAILER_HEADER_LEN + 4);
        assert_eq!(check(&b), Ok(m));
        // A RIPng stream far past the longest message is cut off.
        let route = ng_entry_bytes("2001:db8::".parse().unwrap(), 0, 32, 1);
        let mut n = NgDecoder::new();
        let _ = n.feed(&[2, 1, 0, 0]);
        let mut errs = 0;
        for _ in 0..(MAX_NG_ENTRIES + 50) {
            if n.feed(&route).is_err() {
                errs += 1;
            }
            assert!(n.buffered() <= MAX_NG_MESSAGE + ENTRY_LEN);
        }
        assert_eq!(errs, 50);
        assert_eq!(n.finish(), Err(RipError::TooManyEntries));
    }

    #[test]
    fn display_and_helpers() {
        assert_eq!(RipError::Command(3).to_string(), "command 3, not 1 or 2");
        assert_eq!(Command::Response.code(), 2);
        assert_eq!(Version::V2.code(), 2);
        assert!(Command::Request.allows_metric(0));
        assert!(!Command::Response.allows_metric(0));
        assert!(contiguous(0) && contiguous(u32::MAX) && contiguous(0xffff_ff00) && !contiguous(0x00ff_ffff));
        assert_eq!(MAX_MESSAGE, 763);
        assert_eq!(MAX_NG_ENTRIES, 3276);
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    /// Bytes shaped like a message: a sample with a few bytes changed, cut
    /// or added to, or bytes made up from a header.
    fn shaped(rng: &mut Lcg, pool: &[Vec<u8>]) -> Vec<u8> {
        let mut b = if rng.below(5) == 0 {
            let mut b = vec![1 + rng.below(2) as u8, 1 + rng.below(2) as u8, 0, 0];
            for _ in 0..rng.below(30) * 4 {
                // Mostly small bytes, so families and metrics are often
                // valid.
                b.push(if rng.below(2) == 0 { 0 } else { rng.byte() % 20 });
            }
            b
        } else {
            pool[rng.below(pool.len())].clone()
        };
        for _ in 0..rng.below(4) {
            let n = b.len();
            if n == 0 {
                break;
            }
            let i = rng.below(n);
            b[i] = match rng.below(3) {
                0 => rng.byte(),
                1 => b[i] ^ (1 << rng.below(8)),
                _ => [0, 1, 2, 3, 16, 17, 0xff][rng.below(7)],
            };
        }
        match rng.below(6) {
            0 => {
                let n = rng.below(b.len() + 1);
                b.truncate(n);
            }
            1 => {
                for _ in 0..rng.below(45) {
                    b.push(rng.byte());
                }
            }
            2 => {
                let e = b.get(4..24).map(|e| e.to_vec()).unwrap_or_default();
                for _ in 0..rng.below(30) {
                    b.extend_from_slice(&e);
                }
            }
            _ => {}
        }
        b
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg(0x5eed_0520);
        let pool = samples();
        let ng_pool = ng_samples();
        let (mut ok, mut ng_ok) = (0, 0);
        for _ in 0..6000 {
            let b = shaped(&mut rng, &pool);
            if check(&b).is_ok() {
                ok += 1;
            }
            let _ = ng_check(&b);
            let b = shaped(&mut rng, &ng_pool);
            if ng_check(&b).is_ok() {
                ng_ok += 1;
            }
            let _ = check(&b);
            // Any bytes at all.
            let raw: Vec<u8> = (0..rng.below(80)).map(|_| rng.byte()).collect();
            let _ = check(&raw);
            let _ = ng_check(&raw);
        }
        // The shapes reach the parsers' far ends, not only their headers.
        assert!(ok > 500, "{ok}");
        assert!(ng_ok > 500, "{ng_ok}");
    }

    #[test]
    fn lcg_fuzz_writers() {
        let mut rng = Lcg(42);
        for _ in 0..4000 {
            let command = if rng.below(2) == 0 { Command::Request } else { Command::Response };
            let version = if rng.below(2) == 0 { Version::V1 } else { Version::V2 };
            let small = |rng: &mut Lcg| if rng.below(3) == 0 { rng.byte() } else { 0 };
            let auth = match rng.below(5) {
                0 => Some(Auth::Password([rng.byte(); 16])),
                1 => {
                    let n = rng.below(40);
                    let data_len = if rng.below(4) == 0 { rng.byte() } else { n as u8 };
                    Some(Auth::Crypto(Crypto {
                        key_id: rng.byte(),
                        data_len,
                        sequence: rng.next(),
                        data: vec![rng.byte(); n],
                    }))
                }
                2 => Some(Auth::Other { kind: rng.below(5) as u16, data: [rng.byte(); 16] }),
                _ => None,
            };
            let entries = if rng.below(6) == 0 {
                Entries::WholeTable
            } else {
                let routes = (0..rng.below(28))
                    .map(|_| RouteEntry {
                        tag: u16::from(small(&mut rng)),
                        address: Ipv4Addr::from(rng.next()),
                        mask: Ipv4Addr::from(if rng.below(2) == 0 { 0 } else { u32::MAX << rng.below(32) }),
                        next_hop: Ipv4Addr::from(u32::from(small(&mut rng))),
                        metric: rng.below(19) as u8,
                    })
                    .collect();
                Entries::Routes(routes)
            };
            let m = Message { command, version, auth, entries };
            if let Ok(b) = m.to_bytes() {
                assert_eq!(check(&b), Ok(m));
            }
            let ng_entries = if rng.below(6) == 0 {
                NgEntries::WholeTable
            } else {
                NgEntries::Entries(
                    (0..rng.below(8))
                        .map(|_| {
                            if rng.below(4) == 0 {
                                NgEntry::NextHop(Ipv6Addr::from(u128::from(rng.next())))
                            } else {
                                NgEntry::Route(NgRoute {
                                    prefix: Ipv6Addr::from(u128::from(rng.next()) << 96),
                                    tag: u16::from(small(&mut rng)),
                                    prefix_len: rng.below(140) as u8,
                                    metric: rng.below(19) as u8,
                                })
                            }
                        })
                        .collect(),
                )
            };
            let n = NgMessage { command, entries: ng_entries };
            if let Ok(b) = n.to_bytes() {
                assert_eq!(ng_check(&b), Ok(n));
            }
        }
    }
}
