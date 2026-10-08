//! RIP and RIPng: reading and writing routing messages, with no I/O.
//!
//! `Message` and `NgMessage` read and write complete routing messages through
//! `Wire`. There is no protocol stream decoder, routing-table state machine,
//! update timer, authentication verification, or `Service`.
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
//! bytes [`Wire::to_bytes`] returns. Check [`Message::fits_datagram`] before
//! sending a RIP message. For pieces of one payload, use
//! [`Stream<Collect<Message>>`](fictionet::stdlib::codec::Stream)
//! and a limit of [`MAX_MESSAGE`], or `Collect<NgMessage>` with
//! [`MAX_NG_MESSAGE`]. Call `end` at the UDP boundary. Which routes exist,
//! what their metrics are, and whether a password or a digest is right
//! are up to world code. The authentication data is kept as bytes.
//!
//! [`Message::parse`] and [`NgMessage::parse`] fail on the first bad entry.
//! A router does not: it skips the entry and reads the rest (RFC 2453
//! 3.9.2, RFC 2080 2.4.2). [`Message::receive`] and [`NgMessage::receive`]
//! read that way, and say which entries they skipped.
//!
//! Every reader checks the command, version, family, metric, mask, prefix
//! length, entry count and lengths, because the agent can send any bytes it
//! likes. A version 1 message whose must-be-zero fields are not zero is
//! rejected, as RFC 2453 says. In version 2 and RIPng, the header's unused
//! field and the reserved fields of the authentication and next hop entries
//! are ignored when read and written as zero. So are the fields of a
//! whole-table entry other than its family (or prefix and prefix length)
//! and metric. A RIPng next hop that is not link-local is read as `::`, as
//! RFC 2080 says. Writers check the same rules as readers, so bytes they
//! return always read back, and keep a RIP message within
//! [`MAX_MESSAGE`] bytes.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
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

use fictionet::stdlib::codec::{Wire, be16, be32};

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
pub const MAX_MESSAGE: usize =
    HEADER_LEN + MAX_ENTRIES * ENTRY_LEN + TRAILER_HEADER_LEN + MAX_AUTH_DATA;
/// The longest RIP datagram to send: RFC 1058 3.1 limits a datagram to
/// 512 bytes. RFC 4822 does not say whether its trailer counts.
/// FRRouting counts it, and drops longer datagrams, so with a 16-byte
/// digest a message holds at most 23 routes. Readers and writers accept up
/// to [`MAX_MESSAGE`]. Check [`Message::fits_datagram`] before sending.
pub const MAX_DATAGRAM: usize = 512;
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

    fn from_code(c: u8) -> Result<Command, Error> {
        match c {
            1 => Ok(Command::Request),
            2 => Ok(Command::Response),
            _ => Err(Error::Command(c)),
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
    /// [`MAX_AUTH_DATA`] bytes. The digest covers the message as received,
    /// so check it against the payload from
    /// [`Stream::with_next`](fictionet::stdlib::codec::Stream::with_next), not against
    /// [`Message::to_bytes`], which writes ignored fields as zero.
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
pub enum Error {
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
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "message cut short"),
            Error::Command(c) => write!(f, "command {c}, not 1 or 2"),
            Error::Version(v) => write!(f, "unknown version {v}"),
            Error::MustBeZero { offset } => {
                write!(f, "must-be-zero field at offset {offset} is not zero")
            }
            Error::Family { entry, family } => {
                write!(f, "entry {entry} has address family {family}")
            }
            Error::AuthPlace { entry } => {
                write!(f, "authentication entry {entry} is not the first")
            }
            Error::WholeTable { entry } => {
                write!(f, "entry {entry} is a malformed whole-table request")
            }
            Error::Metric { entry, metric } => write!(f, "entry {entry} has metric {metric}"),
            Error::Mask { entry } => write!(f, "entry {entry} has a mask that is not contiguous"),
            Error::PrefixLength { entry, len } => {
                write!(f, "entry {entry} has prefix length {len}")
            }
            Error::PacketLength(n) => write!(f, "authentication packet length {n} is not valid"),
            Error::Trailer => write!(f, "authentication trailer header is not 0xffff 0x0001"),
            Error::AuthDataTooLong => write!(f, "authentication trailer is too long"),
            Error::AuthDataLen { declared, actual } => {
                write!(
                    f,
                    "authentication data is {actual} bytes, entry says {declared}"
                )
            }
            Error::NoEntries => write!(f, "message has no entries"),
            Error::TooManyEntries => write!(f, "message has too many entries"),
            Error::Unwritable => write!(f, "value cannot be written without changing it"),
        }
    }
}

impl std::error::Error for Error {}

impl Message {
    /// Whether the message fits the [`MAX_DATAGRAM`] sending limit,
    /// including its authentication trailer. This checks size only;
    /// [`Wire::write`] also checks the fields.
    pub fn fits_datagram(&self) -> bool {
        let routes = match &self.entries {
            Entries::WholeTable => 1,
            Entries::Routes(routes) => routes.len(),
        };
        let entries = routes.saturating_add(usize::from(self.auth.is_some()));
        let trailer = match &self.auth {
            Some(Auth::Crypto(c)) => TRAILER_HEADER_LEN.saturating_add(c.data.len()),
            _ => 0,
        };
        HEADER_LEN
            .saturating_add(entries.saturating_mul(ENTRY_LEN))
            .saturating_add(trailer)
            <= MAX_DATAGRAM
    }

    /// A request for the whole table, with no authentication.
    pub fn whole_table_request(version: Version) -> Message {
        Message {
            command: Command::Request,
            version,
            auth: None,
            entries: Entries::WholeTable,
        }
    }

    /// Reads a message as a receiving router does. An entry with an
    /// address family this module does not know, a mask that is not
    /// contiguous, or a metric out of range is skipped, and the rest of the
    /// message is read (RFC 1058 3.4 and 3.4.2, RFC 2453 3.9.2). A version
    /// above 2 is read as version 2, its unused fields ignored (RFC 1058
    /// 3.4, RFC 2453 5.1). Any other broken rule fails the whole message, as
    /// in [`Message::parse`], which this matches on every message that
    /// passes it. Whether a destination is one a router should accept
    /// (not 127/8 or multicast, say) is left to world code.
    pub fn receive(b: &[u8]) -> Result<Received<Message>, Error> {
        let scan = Routes {
            receive: true,
            ..Routes::default()
        };
        scan.read(b)
            .map(|(message, skipped)| Received { message, skipped })
    }
}

/// Whether `mask` is leading ones and then zeros. Zero passes.
fn contiguous(mask: u32) -> bool {
    let inv = !mask;
    inv & inv.wrapping_add(1) == 0
}

/// Entries and authentication collected during one complete RIP parse.
#[derive(Clone, Debug, Default)]
struct Routes {
    /// Whether to read as a receiving router does: skip bad entries and
    /// read a version above 2 as version 2.
    receive: bool,
    auth: Option<Auth>,
    routes: Vec<RouteEntry>,
    /// The entries skipped, in receive mode.
    skipped: Vec<Error>,
    whole: bool,
    /// Where the entries end, when a cryptographic entry says so.
    entries_end: Option<usize>,
    /// How many entries have been read.
    entry: usize,
}

impl Routes {
    /// Reads every entry once from a complete payload.
    fn read(mut self, b: &[u8]) -> Result<(Message, Vec<Error>), Error> {
        let command = Command::from_code(*b.first().ok_or(Error::Truncated)?)?;
        let v = *b.get(1).ok_or(Error::Truncated)?;
        let version = match v {
            1 => Version::V1,
            2 => Version::V2,
            3.. if self.receive => Version::V2,
            _ => return Err(Error::Version(v)),
        };
        if version == Version::V1
            && b.get(2..b.len().min(4))
                .is_some_and(|s| s.iter().any(|&x| x != 0))
        {
            return Err(Error::MustBeZero { offset: 2 });
        }
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        loop {
            let at = HEADER_LEN + self.entry * ENTRY_LEN;
            if self.entries_end.is_some_and(|end| at >= end) {
                break;
            }
            let Some(e) = b.get(at..at + ENTRY_LEN) else {
                break;
            };
            if self.entry >= MAX_ENTRIES {
                return Err(Error::TooManyEntries);
            }
            if let Err(err) = self.entry_at(command, version, at, e) {
                let skippable = matches!(
                    err,
                    Error::Family { .. } | Error::Mask { .. } | Error::Metric { .. }
                );
                if !(self.receive && skippable) {
                    return Err(err);
                }
                self.skipped.push(err);
            }
            self.entry += 1;
        }
        if let Some(end) = self.entries_end {
            if let Some(h) = b.get(end..end + TRAILER_HEADER_LEN)
                && h != [0xff, 0xff, 0, 1]
            {
                return Err(Error::Trailer);
            }
            if b.len().saturating_sub(end + TRAILER_HEADER_LEN) > MAX_AUTH_DATA {
                return Err(Error::AuthDataTooLong);
            }
        }
        let mut auth = self.auth;
        if let Some(end) = self.entries_end {
            if b.len() < end + TRAILER_HEADER_LEN {
                return Err(Error::Truncated);
            }
            let data = &b[end + TRAILER_HEADER_LEN..];
            if let Some(Auth::Crypto(c)) = &mut auth {
                let declared = usize::from(c.data_len);
                if declared != data.len() && declared != data.len() + TRAILER_HEADER_LEN {
                    return Err(Error::AuthDataLen {
                        declared: c.data_len,
                        actual: data.len(),
                    });
                }
                c.data = data.to_vec();
            }
        } else if HEADER_LEN + self.entry * ENTRY_LEN != b.len() {
            return Err(Error::Truncated);
        }
        if self.entry == 0 {
            return Err(Error::NoEntries);
        }
        let entries = if self.whole {
            Entries::WholeTable
        } else {
            Entries::Routes(self.routes)
        };
        Ok((
            Message {
                command,
                version,
                auth,
                entries,
            },
            self.skipped,
        ))
    }

    /// Reads entry number `self.entry`, the 20 bytes `e` at offset `at`.
    fn entry_at(
        &mut self,
        command: Command,
        version: Version,
        at: usize,
        e: &[u8],
    ) -> Result<(), Error> {
        let entry = self.entry;
        let fam = be16(e, 0).ok_or(Error::Truncated)?;
        if version == Version::V1 && (fam == family::WHOLE_TABLE || fam == family::INET) {
            for (off, len) in [(2, 2), (8, 4), (12, 4)] {
                if e[off..off + len].iter().any(|&x| x != 0) {
                    return Err(Error::MustBeZero { offset: at + off });
                }
            }
        }
        match fam {
            family::AUTH if version == Version::V2 => {
                if entry != 0 {
                    return Err(Error::AuthPlace { entry });
                }
                let kind = be16(e, 2).ok_or(Error::Truncated)?;
                let mut data = [0u8; 16];
                data.copy_from_slice(&e[4..20]);
                self.auth = Some(match kind {
                    auth_type::PASSWORD => Auth::Password(data),
                    auth_type::CRYPTO => {
                        let packet_len = be16(e, 4).ok_or(Error::Truncated)?;
                        let n = usize::from(packet_len);
                        let ok = n >= HEADER_LEN + ENTRY_LEN
                            && (n - HEADER_LEN).is_multiple_of(ENTRY_LEN)
                            && n <= HEADER_LEN + MAX_ENTRIES * ENTRY_LEN;
                        if !ok {
                            return Err(Error::PacketLength(packet_len));
                        }
                        self.entries_end = Some(n);
                        Auth::Crypto(Crypto {
                            key_id: e[6],
                            data_len: e[7],
                            sequence: be32(e, 8).ok_or(Error::Truncated)?,
                            data: Vec::new(),
                        })
                    }
                    _ => Auth::Other { kind, data },
                });
            }
            family::WHOLE_TABLE => {
                // RFC 2453 names only the family and the metric, so the
                // other fields are ignored. It must be the first entry
                // after any authentication entry.
                let first = entry == usize::from(self.auth.is_some());
                if command != Command::Request
                    || self.whole
                    || !first
                    || be32(e, 16).ok_or(Error::Truncated)? != u32::from(INFINITY)
                {
                    return Err(Error::WholeTable { entry });
                }
                self.whole = true;
            }
            family::INET => {
                if self.whole {
                    return Err(Error::WholeTable { entry });
                }
                let mask = be32(e, 8).ok_or(Error::Truncated)?;
                if !contiguous(mask) {
                    return Err(Error::Mask { entry });
                }
                let metric = be32(e, 16).ok_or(Error::Truncated)?;
                if !command.allows_metric(metric) {
                    return Err(Error::Metric { entry, metric });
                }
                self.routes.push(RouteEntry {
                    tag: be16(e, 2).ok_or(Error::Truncated)?,
                    address: Ipv4Addr::from(be32(e, 4).ok_or(Error::Truncated)?),
                    mask: Ipv4Addr::from(mask),
                    next_hop: Ipv4Addr::from(be32(e, 12).ok_or(Error::Truncated)?),
                    // Checked above to be at most 16.
                    metric: metric as u8,
                });
            }
            _ => return Err(Error::Family { entry, family: fam }),
        }
        Ok(())
    }
}

/// A message read as a receiving router reads it, with the entries it
/// skipped. See [`Message::receive`] and [`NgMessage::receive`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Received<M> {
    /// The message, without the entries skipped. Its routes may be empty
    /// even with no authentication entry, so [`Message::to_bytes`] or
    /// [`NgMessage::to_bytes`] may fail on it with [`Error::NoEntries`].
    pub message: M,
    /// Why each skipped entry was skipped, in order. Each error names its
    /// entry, counted as on the wire.
    pub skipped: Vec<Error>,
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
    /// `::` means the router that sent the message. It is always `::` or a
    /// link-local address (`fe80::/10`): RFC 2080 2.1.1 says a received
    /// next hop that is not link-local is read as `::`, and readers do so.
    /// A writer fails with [`Error::Unwritable`] on any other
    /// address. On the wire its metric is [`NEXT_HOP_METRIC`] and its tag
    /// and prefix length are zero.
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

const WHOLE_TABLE_NG: NgRoute = NgRoute {
    prefix: Ipv6Addr::UNSPECIFIED,
    tag: 0,
    prefix_len: 0,
    metric: INFINITY,
};

impl NgMessage {
    /// A request for the whole table.
    pub fn whole_table_request() -> NgMessage {
        NgMessage {
            command: Command::Request,
            entries: NgEntries::WholeTable,
        }
    }

    /// Reads a message as a receiving router does: a route with a prefix
    /// length above 128 or a metric out of range is skipped, and the rest
    /// of the message is read (RFC 2080 2.4.2). Any other broken rule fails
    /// the whole message, as in [`NgMessage::parse`], which this matches on
    /// every message that passes it. Whether a prefix is one a router
    /// should accept (not multicast or link-local, say) is left to world
    /// code.
    pub fn receive(b: &[u8]) -> Result<Received<NgMessage>, Error> {
        let mut skipped = Vec::new();
        let message = scan_ng(b, Some(&mut skipped))?;
        Ok(Received { message, skipped })
    }
}

/// Reads a complete RIPng header. Refuses an invalid command or version
/// and a header shorter than [`HEADER_LEN`].
fn ng_header(b: &[u8]) -> Result<Command, Error> {
    let &c = b.first().ok_or(Error::Truncated)?;
    let command = Command::from_code(c)?;
    let &v = b.get(1).ok_or(Error::Truncated)?;
    if v != 1 {
        return Err(Error::Version(v));
    }
    if b.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    Ok(command)
}

/// Reads RIPng entry number `entry`, the 20 bytes `e`.
fn ng_entry(command: Command, entry: usize, e: &[u8]) -> Result<NgEntry, Error> {
    if entry >= MAX_NG_ENTRIES {
        return Err(Error::TooManyEntries);
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&e[..16]);
    let prefix = Ipv6Addr::from(a);
    let metric = e[19];
    if metric == NEXT_HOP_METRIC {
        // RFC 2080 2.1.1: a next hop that is not link-local means the
        // sender, as :: does.
        let link_local = prefix.segments()[0] & 0xffc0 == 0xfe80;
        return Ok(NgEntry::NextHop(if link_local {
            prefix
        } else {
            Ipv6Addr::UNSPECIFIED
        }));
    }
    let prefix_len = e[18];
    if prefix_len > MAX_PREFIX_LEN {
        return Err(Error::PrefixLength {
            entry,
            len: prefix_len,
        });
    }
    if !command.allows_metric(u32::from(metric)) {
        return Err(Error::Metric {
            entry,
            metric: u32::from(metric),
        });
    }
    Ok(NgEntry::Route(NgRoute {
        prefix,
        tag: be16(e, 16).ok_or(Error::Truncated)?,
        prefix_len,
        metric,
    }))
}

/// Whether a route asks for the whole table when it is a request's only
/// entry: RFC 2080 names the prefix, prefix length and metric, not the tag.
fn is_whole_table_ng(r: NgRoute) -> bool {
    r.prefix == Ipv6Addr::UNSPECIFIED && r.prefix_len == 0 && r.metric == INFINITY
}

/// Reads a whole RIPng message, checking it in byte order, so the first
/// rule a prefix breaks is the first rule the whole message breaks. With
/// `skip`, a route with a bad prefix length or metric is left out and its
/// error added there instead.
fn scan_ng(b: &[u8], mut skip: Option<&mut Vec<Error>>) -> Result<NgMessage, Error> {
    let command = ng_header(b)?;
    let mut entries = Vec::new();
    let mut count = 0;
    let mut at = HEADER_LEN;
    while let Some(e) = b.get(at..at + ENTRY_LEN) {
        match ng_entry(command, count, e) {
            Ok(entry) => entries.push(entry),
            Err(err @ (Error::PrefixLength { .. } | Error::Metric { .. })) if skip.is_some() => {
                if let Some(s) = skip.as_mut() {
                    s.push(err);
                }
            }
            Err(err) => return Err(err),
        }
        count += 1;
        at += ENTRY_LEN;
    }
    if at != b.len() {
        return Err(Error::Truncated);
    }
    if count == 0 {
        return Err(Error::NoEntries);
    }
    let whole = command == Command::Request
        && count == 1
        && matches!(entries[..], [NgEntry::Route(r)] if is_whole_table_ng(r));
    let entries = if whole {
        NgEntries::WholeTable
    } else {
        NgEntries::Entries(entries)
    };
    Ok(NgMessage { command, entries })
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete UDP payload. Refuses invalid header, route,
    /// authentication, and length fields.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        Routes::default().read(b).map(|(m, _)| m)
    }

    /// Appends a message. Refuses invalid fields, excessive route or digest
    /// lengths, and values that would read back differently. Preserves all
    /// parsed messages. Leaves the destination unchanged on error.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        let routes = match &self.entries {
            Entries::WholeTable => 1,
            Entries::Routes(r) => r.len(),
        };
        if routes.saturating_add(usize::from(self.auth.is_some())) > MAX_ENTRIES {
            return Err(Error::TooManyEntries);
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
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&family::AUTH.to_be_bytes());
                out.extend_from_slice(&kind.to_be_bytes());
                out.extend_from_slice(data);
            }
            Some(Auth::Crypto(c)) => {
                if c.data.len() > MAX_AUTH_DATA {
                    return Err(Error::AuthDataTooLong);
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
            return Err(Error::Unwritable);
        }
        if out.len() > MAX_MESSAGE {
            return Err(Error::TooManyEntries);
        }
        destination.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for NgMessage {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete RIPng UDP payload. Refuses an invalid command or
    /// version, missing or partial entries, excessive entry counts, invalid
    /// prefix lengths, and metrics outside the command's range.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        scan_ng(b, None)
    }

    /// Appends a RIPng message. Refuses missing or excessive entries, invalid
    /// prefix lengths or metrics, and next hops or whole-table forms that
    /// would read back differently. Leaves the destination unchanged on error.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        let one = [NgEntry::Route(WHOLE_TABLE_NG)];
        let entries: &[NgEntry] = match &self.entries {
            NgEntries::WholeTable => &one,
            NgEntries::Entries(e) => e,
        };
        if entries.len() > MAX_NG_ENTRIES {
            return Err(Error::TooManyEntries);
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
            return Err(Error::Unwritable);
        }
        destination.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Collect, CollectError, Fail, Lcg, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::rounds;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn collect(b: &[u8]) -> Result<Message, Error> {
        let make = || Collect::<Message>::new(MAX_MESSAGE);
        contract::check_decode_with_alloc_limit(make, b, 2 * (MAX_MESSAGE + 1));
        contract::check_wire::<Message>(b);
        let parsed = Message::parse(b);
        let (items, failure) = decode_all(make, b);
        if b.len() <= MAX_MESSAGE {
            assert_eq!(
                failure,
                parsed
                    .clone()
                    .err()
                    .map(|e| Fail::Protocol(CollectError::Parse(e)))
            );
            assert_eq!(items, parsed.clone().ok().into_iter().collect::<Vec<_>>());
        } else {
            assert_eq!(
                failure,
                Some(Fail::Protocol(CollectError::TooLong { limit: MAX_MESSAGE }))
            );
        }
        parsed
    }

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// A version 2 route entry's bytes.
    fn v2_entry(
        tag: u16,
        address: [u8; 4],
        mask: [u8; 4],
        next_hop: [u8; 4],
        metric: u32,
    ) -> Vec<u8> {
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

    fn ng_collect(b: &[u8]) -> Result<NgMessage, Error> {
        let make = || Collect::<NgMessage>::new(MAX_NG_MESSAGE);
        contract::check_decode_with_alloc_limit(make, b, 2 * (MAX_NG_MESSAGE + 1));
        contract::check_wire::<NgMessage>(b);
        let parsed = NgMessage::parse(b);
        let (items, failure) = decode_all(make, b);
        if b.len() <= MAX_NG_MESSAGE {
            assert_eq!(
                failure,
                parsed
                    .clone()
                    .err()
                    .map(|e| Fail::Protocol(CollectError::Parse(e)))
            );
            assert_eq!(items, parsed.clone().ok().into_iter().collect::<Vec<_>>());
        } else {
            assert!(items.is_empty());
            assert_eq!(
                failure,
                Some(Fail::Protocol(CollectError::TooLong {
                    limit: MAX_NG_MESSAGE
                }))
            );
        }
        parsed
    }

    fn check(b: &[u8]) -> Result<Message, Error> {
        let p = Message::parse(b);
        assert_eq!(collect(b), p);
        if let Ok(m) = &p {
            // Reading as a router does agrees on every message parse takes.
            assert_eq!(
                Message::receive(b),
                Ok(Received {
                    message: m.clone(),
                    skipped: vec![]
                })
            );
            let out = m.to_bytes().unwrap();
            assert_eq!(out.len(), b.len());
            assert_eq!(Message::parse(&out).as_ref(), Ok(m));
        }
        if let Ok(r) = Message::receive(b) {
            assert!(r.skipped.len() <= MAX_ENTRIES);
            if let Entries::Routes(routes) = &r.message.entries {
                for x in routes {
                    assert!(
                        r.message.command.allows_metric(u32::from(x.metric))
                            && contiguous(u32::from(x.mask))
                    );
                }
            }
        }
        p
    }

    fn ng_check(b: &[u8]) -> Result<NgMessage, Error> {
        let p = NgMessage::parse(b);
        assert_eq!(ng_collect(b), p);
        if let Ok(m) = &p {
            assert_eq!(
                NgMessage::receive(b),
                Ok(Received {
                    message: m.clone(),
                    skipped: vec![]
                })
            );
            let out = m.to_bytes().unwrap();
            assert_eq!(out.len(), b.len());
            assert_eq!(NgMessage::parse(&out).as_ref(), Ok(m));
        }
        if let Ok(r) = NgMessage::receive(b)
            && let NgEntries::Entries(es) = &r.message.entries
        {
            for e in es {
                match e {
                    NgEntry::NextHop(a) => {
                        assert!(a.is_unspecified() || a.segments()[0] & 0xffc0 == 0xfe80)
                    }
                    NgEntry::Route(x) => {
                        assert!(
                            x.prefix_len <= MAX_PREFIX_LEN
                                && r.message.command.allows_metric(u32::from(x.metric))
                        )
                    }
                }
            }
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
            msg(
                2,
                2,
                &[
                    pw.clone(),
                    v2_entry(7, [10, 0, 0, 0], [255, 0, 0, 0], [10, 0, 0, 1], 16),
                ],
            ),
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
            msg(
                2,
                1,
                &[
                    ng_entry_bytes(hop, 0, 0, 0xff),
                    ng_entry_bytes(doc, 9, 32, 1),
                ],
            ),
            msg(1, 1, &[ng_entry_bytes(doc, 0, 32, 0)]),
        ]
    }

    #[test]
    fn module_example() {
        let mut request = vec![1, 2, 0, 0];
        request.extend_from_slice(&whole_table_entry());
        assert_eq!(
            check(&request),
            Ok(Message::whole_table_request(Version::V2))
        );
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
        assert_eq!(
            bytes,
            [
                2, 2, 0, 0, 0, 2, 0, 0, 10, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ]
        );
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
        assert_eq!(
            Message::whole_table_request(Version::V1)
                .to_bytes()
                .unwrap(),
            v1
        );
        let ng = msg(1, 1, &[ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 0, 0, 16)]);
        assert_eq!(ng_check(&ng), Ok(NgMessage::whole_table_request()));
        assert_eq!(NgMessage::whole_table_request().to_bytes().unwrap(), ng);
        // In a response the same entry is a route to ::/0 that cannot be
        // reached.
        let ng_resp = msg(2, 1, &[ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 0, 0, 16)]);
        assert!(matches!(
            ng_check(&ng_resp).unwrap().entries,
            NgEntries::Entries(_)
        ));
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
        assert_eq!(
            m.auth,
            Some(Auth::Crypto(Crypto {
                key_id: 1,
                data_len: 16,
                sequence: 7,
                data: vec![0xab; 16]
            }))
        );
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
                NgEntry::Route(NgRoute {
                    prefix: "2001:db8::".parse().unwrap(),
                    tag: 9,
                    prefix_len: 32,
                    metric: 1
                }),
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
        let cases: Vec<(Vec<u8>, Error)> = vec![
            (vec![], Error::Truncated),
            (vec![2, 2, 0], Error::Truncated),
            (msg(2, 2, &[route[..19].to_vec()]), Error::Truncated),
            (msg(3, 2, std::slice::from_ref(&route)), Error::Command(3)),
            (msg(0, 2, std::slice::from_ref(&route)), Error::Command(0)),
            (msg(2, 0, std::slice::from_ref(&route)), Error::Version(0)),
            (msg(2, 3, std::slice::from_ref(&route)), Error::Version(3)),
            (
                [vec![2, 1, 0, 1], v1_route.clone()].concat(),
                Error::MustBeZero { offset: 2 },
            ),
            (vec![2, 1, 1], Error::MustBeZero { offset: 2 }),
            (
                msg(2, 1, &[v2_entry(1, [10, 0, 0, 0], [0; 4], [0; 4], 1)]),
                Error::MustBeZero { offset: 6 },
            ),
            (
                msg(2, 1, std::slice::from_ref(&route)),
                Error::MustBeZero { offset: 12 },
            ),
            (
                msg(2, 1, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [1; 4], 1)]),
                Error::MustBeZero { offset: 16 },
            ),
            (
                msg(2, 1, &[pw.clone()]),
                Error::Family {
                    entry: 0,
                    family: 0xffff,
                },
            ),
            (
                msg(
                    2,
                    2,
                    &[route.clone(), [vec![0, 7], route[2..].to_vec()].concat()],
                ),
                Error::Family {
                    entry: 1,
                    family: 7,
                },
            ),
            (
                msg(2, 2, &[route.clone(), pw.clone()]),
                Error::AuthPlace { entry: 1 },
            ),
            (
                msg(2, 2, &[whole_table_entry()]),
                Error::WholeTable { entry: 0 },
            ),
            (
                msg(1, 2, &[route.clone(), whole_table_entry()]),
                Error::WholeTable { entry: 1 },
            ),
            (
                msg(1, 2, &[whole_table_entry(), route.clone()]),
                Error::WholeTable { entry: 1 },
            ),
            (
                msg(1, 2, &[whole_table_entry(), whole_table_entry()]),
                Error::WholeTable { entry: 1 },
            ),
            (
                msg(1, 2, &[[&[0u8; 16][..], &[0, 0, 0, 15]].concat()]),
                Error::WholeTable { entry: 0 },
            ),
            (
                msg(
                    1,
                    1,
                    &[[&[0u8, 0, 0, 1][..], &[0; 12], &[0, 0, 0, 16]].concat()],
                ),
                Error::MustBeZero { offset: 6 },
            ),
            (
                msg(2, 2, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 0)]),
                Error::Metric {
                    entry: 0,
                    metric: 0,
                },
            ),
            (
                msg(2, 2, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 17)]),
                Error::Metric {
                    entry: 0,
                    metric: 17,
                },
            ),
            (
                msg(1, 2, &[v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 0x100)]),
                Error::Metric {
                    entry: 0,
                    metric: 0x100,
                },
            ),
            (
                msg(
                    2,
                    2,
                    &[v2_entry(0, [10, 0, 0, 0], [255, 0, 255, 0], [0; 4], 1)],
                ),
                Error::Mask { entry: 0 },
            ),
            (vec![2, 2, 0, 0], Error::NoEntries),
            (
                msg(2, 2, &vec![route.clone(); MAX_ENTRIES + 1]),
                Error::TooManyEntries,
            ),
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
            assert_eq!(check(&with_len(n)), Err(Error::PacketLength(n)));
        }
        // A packet length past the trailer reads the trailer as an entry.
        assert_eq!(check(&with_len(64)), Err(Error::AuthPlace { entry: 2 }));
        assert_eq!(check(&good[..44]), Err(Error::Truncated));
        let mut bad = good.clone();
        bad[47] = 2;
        assert_eq!(check(&bad), Err(Error::Trailer));
        assert_eq!(check(&good[..46]), Err(Error::Truncated));
        assert_eq!(
            check(&crypto_message(16, &[1; 15])),
            Err(Error::AuthDataLen {
                declared: 16,
                actual: 15
            })
        );
        assert_eq!(
            check(&crypto_message(255, &[1; 256])),
            Err(Error::AuthDataTooLong)
        );
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
        let cases: Vec<(Vec<u8>, Error)> = vec![
            (vec![], Error::Truncated),
            (vec![2, 1, 0], Error::Truncated),
            (msg(2, 1, &[route[..10].to_vec()]), Error::Truncated),
            (msg(9, 1, std::slice::from_ref(&route)), Error::Command(9)),
            (msg(2, 2, std::slice::from_ref(&route)), Error::Version(2)),
            (msg(2, 0, std::slice::from_ref(&route)), Error::Version(0)),
            (
                msg(2, 1, &[route.clone(), ng_entry_bytes(doc, 0, 129, 1)]),
                Error::PrefixLength { entry: 1, len: 129 },
            ),
            (
                msg(2, 1, &[ng_entry_bytes(doc, 0, 32, 0)]),
                Error::Metric {
                    entry: 0,
                    metric: 0,
                },
            ),
            (
                msg(2, 1, &[ng_entry_bytes(doc, 0, 32, 17)]),
                Error::Metric {
                    entry: 0,
                    metric: 17,
                },
            ),
            (
                msg(1, 1, &[ng_entry_bytes(doc, 0, 32, 0xfe)]),
                Error::Metric {
                    entry: 0,
                    metric: 0xfe,
                },
            ),
            (vec![2, 1, 0, 0], Error::NoEntries),
        ];
        for (b, e) in &cases {
            assert_eq!(ng_check(b), Err(*e), "{b:?}");
        }
        // One entry too many, through the collection contract.
        let mut big = vec![2, 1, 0, 0];
        for _ in 0..=MAX_NG_ENTRIES {
            big.extend_from_slice(&route);
        }
        assert_eq!(ng_check(&big), Err(Error::TooManyEntries));
        let at_most = &big[..MAX_NG_MESSAGE];
        assert!(ng_check(at_most).is_ok());
        // The header's unused field is ignored.
        let mut b = msg(2, 1, std::slice::from_ref(&route));
        b[3] = 1;
        assert_eq!(
            ng_check(&b).unwrap().to_bytes().unwrap(),
            msg(2, 1, &[route])
        );
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
        assert_eq!(m.to_bytes(), Err(Error::TooManyEntries));
        let mut m = base.clone();
        m.entries = Entries::Routes(vec![route; MAX_ENTRIES]);
        m.auth = Some(Auth::Password([0; 16]));
        assert_eq!(m.to_bytes(), Err(Error::TooManyEntries));
        let mut m = base.clone();
        m.auth = Some(Auth::Crypto(Crypto {
            key_id: 1,
            data_len: 0,
            sequence: 0,
            data: vec![0; 256],
        }));
        assert_eq!(m.to_bytes(), Err(Error::AuthDataTooLong));
        let mut m = base.clone();
        m.auth = Some(Auth::Crypto(Crypto {
            key_id: 1,
            data_len: 3,
            sequence: 0,
            data: vec![0; 16],
        }));
        assert_eq!(
            m.to_bytes(),
            Err(Error::AuthDataLen {
                declared: 3,
                actual: 16
            })
        );
        for kind in [auth_type::PASSWORD, auth_type::CRYPTO] {
            let mut m = base.clone();
            m.auth = Some(Auth::Other {
                kind,
                data: [0; 16],
            });
            assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        }
        let mut m = base.clone();
        m.version = Version::V1;
        assert_eq!(m.to_bytes(), Err(Error::MustBeZero { offset: 12 }));
        let mut m = Message::whole_table_request(Version::V1);
        m.auth = Some(Auth::Password([0; 16]));
        assert_eq!(
            m.to_bytes(),
            Err(Error::Family {
                entry: 0,
                family: 0xffff
            })
        );
        let mut m = Message::whole_table_request(Version::V2);
        m.command = Command::Response;
        assert_eq!(m.to_bytes(), Err(Error::WholeTable { entry: 0 }));
        let mut m = base.clone();
        m.entries = Entries::Routes(vec![RouteEntry {
            metric: 17,
            ..route
        }]);
        assert_eq!(
            m.to_bytes(),
            Err(Error::Metric {
                entry: 0,
                metric: 17
            })
        );
        let mut m = base.clone();
        m.entries = Entries::Routes(vec![]);
        assert_eq!(m.to_bytes(), Err(Error::NoEntries));

        let whole = NgRoute {
            prefix: Ipv6Addr::UNSPECIFIED,
            tag: 0,
            prefix_len: 0,
            metric: 16,
        };
        let m = NgMessage {
            command: Command::Request,
            entries: NgEntries::Entries(vec![NgEntry::Route(whole)]),
        };
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        let m = NgMessage {
            command: Command::Response,
            entries: NgEntries::WholeTable,
        };
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        let m = NgMessage {
            command: Command::Response,
            entries: NgEntries::Entries(vec![]),
        };
        assert_eq!(m.to_bytes(), Err(Error::NoEntries));
        let m = NgMessage {
            command: Command::Response,
            entries: NgEntries::Entries(vec![
                NgEntry::NextHop(Ipv6Addr::UNSPECIFIED);
                MAX_NG_ENTRIES + 1
            ]),
        };
        assert_eq!(m.to_bytes(), Err(Error::TooManyEntries));
        let m = NgMessage {
            command: Command::Response,
            entries: NgEntries::Entries(vec![NgEntry::Route(NgRoute {
                prefix_len: 200,
                metric: 1,
                ..whole
            })]),
        };
        assert_eq!(
            m.to_bytes(),
            Err(Error::PrefixLength { entry: 0, len: 200 })
        );
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
                    Ok(_) => assert!(
                        if crypto { k + 4 == b.len() } else { boundary },
                        "{k} {b:?}"
                    ),
                    Err(e) => assert!(
                        matches!(
                            e,
                            Error::Truncated | Error::NoEntries | Error::AuthDataLen { .. }
                        ),
                        "{k} {e:?}"
                    ),
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
                    Err(e) => assert!(
                        matches!(e, Error::Truncated | Error::NoEntries),
                        "{k} {e:?}"
                    ),
                }
            }
        }
    }

    #[test]
    fn streams_report_parse_errors_once() {
        assert_eq!(collect(&[7]), Err(Error::Command(7)));
        assert_eq!(ng_collect(&[1, 2]), Err(Error::Version(2)));
        let b = [2, 2, 0, 0, 0, 2].repeat(rounds(10_000));
        contract::check_decode_with_alloc_limit(
            || Collect::<Message>::new(MAX_MESSAGE),
            &b,
            2 * (MAX_MESSAGE + 1),
        );
    }

    #[test]
    fn whole_table_ignores_other_fields() {
        // RFC 2453: one entry of family 0 and metric 16 asks for the whole
        // table. The other fields do not matter in version 2.
        let mut e = whole_table_entry();
        e[2] = 1;
        e[4] = 10;
        e[8] = 255;
        assert_eq!(
            check(&msg(1, 2, &[e])),
            Ok(Message::whole_table_request(Version::V2))
        );
        // In version 1 the address is not a must-be-zero field.
        let mut e = whole_table_entry();
        e[4] = 10;
        assert_eq!(
            check(&msg(1, 1, &[e])),
            Ok(Message::whole_table_request(Version::V1))
        );
        // Its must-be-zero fields still are.
        let mut e = whole_table_entry();
        e[8] = 255;
        assert_eq!(
            check(&msg(1, 1, &[e])),
            Err(Error::MustBeZero { offset: 12 })
        );
        // RFC 2080: the prefix, prefix length and metric decide; the tag
        // does not.
        let ng = msg(1, 1, &[ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 7, 0, 16)]);
        assert_eq!(ng_check(&ng), Ok(NgMessage::whole_table_request()));
        let tagged = NgRoute {
            tag: 7,
            ..WHOLE_TABLE_NG
        };
        let m = NgMessage {
            command: Command::Request,
            entries: NgEntries::Entries(vec![NgEntry::Route(tagged)]),
        };
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn collections_stay_bounded_on_long_input() {
        // A crypto message whose trailer never ends fails once the data
        // passes MAX_AUTH_DATA, through the collection contract.
        let mut long = crypto_message(16, &[1; 16]);
        long.resize(10_000, 7);
        assert_eq!(check(&long), Err(Error::AuthDataTooLong));
        // A whole-table request with a crypto entry writes and reads back.
        let m = Message {
            command: Command::Request,
            version: Version::V2,
            auth: Some(Auth::Crypto(Crypto {
                key_id: 2,
                data_len: 4,
                sequence: 9,
                data: vec![5; 4],
            })),
            entries: Entries::WholeTable,
        };
        let b = m.to_bytes().unwrap();
        assert_eq!(b.len(), HEADER_LEN + 2 * ENTRY_LEN + TRAILER_HEADER_LEN + 4);
        assert_eq!(check(&b), Ok(m));
        // A RIPng stream far past the longest message is cut off.
        let route = ng_entry_bytes("2001:db8::".parse().unwrap(), 0, 32, 1);
        let mut long = vec![2, 1, 0, 0];
        long.extend(route.repeat(MAX_NG_ENTRIES + 50));
        assert_eq!(ng_collect(&long), Err(Error::TooManyEntries));
    }

    #[test]
    fn display_and_helpers() {
        assert_eq!(Error::Command(3).to_string(), "command 3, not 1 or 2");
        assert_eq!(Command::Response.code(), 2);
        assert_eq!(Version::V2.code(), 2);
        assert!(Command::Request.allows_metric(0));
        assert!(!Command::Response.allows_metric(0));
        assert!(
            contiguous(0)
                && contiguous(u32::MAX)
                && contiguous(0xffff_ff00)
                && !contiguous(0x00ff_ffff)
        );
        assert_eq!(MAX_MESSAGE, 763);
        assert_eq!(MAX_NG_ENTRIES, 3276);
    }

    fn route_bytes(metric: u32) -> Vec<u8> {
        v2_entry(0, [10, 0, 0, 0], [255, 0, 0, 0], [0; 4], metric)
    }

    #[test]
    fn receive_skips_bad_entries() {
        // RFC 2453 3.9.2: a bad entry is skipped, and the rest are read.
        let a = route_bytes(1);
        let bad_metric = route_bytes(17);
        let bad_family = [vec![0, 7], a[2..].to_vec()].concat();
        let bad_mask = v2_entry(0, [10, 0, 0, 0], [255, 0, 255, 0], [0; 4], 1);
        let b2 = v2_entry(0, [10, 2, 0, 0], [255, 255, 0, 0], [0; 4], 2);
        let b = msg(
            2,
            2,
            &[a.clone(), bad_metric, bad_family, bad_mask, b2.clone()],
        );
        assert_eq!(
            check(&b),
            Err(Error::Metric {
                entry: 1,
                metric: 17
            })
        );
        let r = Message::receive(&b).unwrap();
        assert_eq!(
            r.skipped,
            vec![
                Error::Metric {
                    entry: 1,
                    metric: 17
                },
                Error::Family {
                    entry: 2,
                    family: 7
                },
                Error::Mask { entry: 3 },
            ]
        );
        let good = Message::parse(&msg(2, 2, &[a.clone(), b2])).unwrap();
        assert_eq!(r.message, good);
        // A version 1 message skips an authentication entry, a family it
        // does not know.
        let v1 = v2_entry(0, [10, 0, 0, 0], [0; 4], [0; 4], 1);
        let mut pw = vec![0xff, 0xff, 0, 2];
        pw.extend_from_slice(&[0; 16]);
        let r = Message::receive(&msg(2, 1, &[pw, v1.clone()])).unwrap();
        assert_eq!(
            r.skipped,
            vec![Error::Family {
                entry: 0,
                family: 0xffff
            }]
        );
        assert_eq!(r.message, Message::parse(&msg(2, 1, &[v1])).unwrap());
        // Every entry skipped leaves no routes.
        let r = Message::receive(&msg(2, 2, &[route_bytes(0)])).unwrap();
        assert_eq!(r.message.entries, Entries::Routes(vec![]));
        assert_eq!(r.message.to_bytes(), Err(Error::NoEntries));
        // Rules about the message as a whole still fail it.
        assert_eq!(
            Message::receive(&msg(2, 2, &[a.clone(), a[..10].to_vec()])),
            Err(Error::Truncated)
        );
        assert_eq!(
            Message::receive(&msg(2, 2, &[whole_table_entry()])),
            Err(Error::WholeTable { entry: 0 })
        );
        assert_eq!(
            Message::receive(&msg(2, 1, &[route_bytes(1)])),
            Err(Error::MustBeZero { offset: 12 })
        );
        // RFC 2080 2.4.2: the same for RIPng.
        let doc: Ipv6Addr = "2001:db8::".parse().unwrap();
        let ok = ng_entry_bytes(doc, 0, 32, 1);
        let b = msg(
            2,
            1,
            &[
                ok.clone(),
                ng_entry_bytes(doc, 0, 129, 1),
                ng_entry_bytes(doc, 0, 32, 17),
                ok.clone(),
            ],
        );
        assert_eq!(
            ng_check(&b),
            Err(Error::PrefixLength { entry: 1, len: 129 })
        );
        let r = NgMessage::receive(&b).unwrap();
        assert_eq!(
            r.skipped,
            vec![
                Error::PrefixLength { entry: 1, len: 129 },
                Error::Metric {
                    entry: 2,
                    metric: 17
                }
            ]
        );
        assert_eq!(
            r.message,
            NgMessage::parse(&msg(2, 1, &[ok.clone(), ok])).unwrap()
        );
        // A request whose only good entry is ::/0 with metric 16, after one
        // that was skipped, is not a whole-table request.
        let wt = ng_entry_bytes(Ipv6Addr::UNSPECIFIED, 0, 0, 16);
        let r = NgMessage::receive(&msg(1, 1, &[ng_entry_bytes(doc, 0, 200, 1), wt])).unwrap();
        assert!(matches!(r.message.entries, NgEntries::Entries(_)));
    }

    #[test]
    fn receive_reads_later_versions_as_2() {
        // RFC 1058 3.4 and RFC 2453 5.1: a version above 1 is read for the
        // fields known; version 0 is not.
        let mut b = samples()[4].clone();
        b[1] = 3;
        b[2] = 9;
        assert_eq!(check(&b), Err(Error::Version(3)));
        let r = Message::receive(&b).unwrap();
        assert_eq!(r.message, Message::parse(&samples()[4]).unwrap());
        b[1] = 0;
        assert_eq!(Message::receive(&b), Err(Error::Version(0)));
    }

    #[test]
    fn ripng_next_hop_must_be_link_local() {
        // RFC 2080 2.1.1: a next hop that is not link-local is read as ::.
        let doc: Ipv6Addr = "2001:db8::".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let route = NgRoute {
            prefix: doc,
            tag: 0,
            prefix_len: 32,
            metric: 1,
        };
        let b = msg(
            2,
            1,
            &[
                ng_entry_bytes(global, 0, 0, 0xff),
                ng_entry_bytes(doc, 0, 32, 1),
            ],
        );
        let m = ng_check(&b).unwrap();
        assert_eq!(
            m.entries,
            NgEntries::Entries(vec![
                NgEntry::NextHop(Ipv6Addr::UNSPECIFIED),
                NgEntry::Route(route)
            ])
        );
        // A writer does not send one.
        let w = NgMessage {
            command: Command::Response,
            entries: NgEntries::Entries(vec![NgEntry::NextHop(global), NgEntry::Route(route)]),
        };
        assert_eq!(w.to_bytes(), Err(Error::Unwritable));
        // The edges of fe80::/10.
        for (a, kept) in [
            ("fe80::1", true),
            ("febf:ffff::1", true),
            ("fec0::1", false),
            ("ff02::9", false),
        ] {
            let a: Ipv6Addr = a.parse().unwrap();
            let m = ng_check(&msg(
                2,
                1,
                &[ng_entry_bytes(a, 0, 0, 0xff), ng_entry_bytes(doc, 0, 32, 1)],
            ))
            .unwrap();
            let want = if kept { a } else { Ipv6Addr::UNSPECIFIED };
            assert_eq!(
                m.entries,
                NgEntries::Entries(vec![NgEntry::NextHop(want), NgEntry::Route(route)]),
                "{a}"
            );
        }
    }

    #[test]
    fn messages_fit_the_512_byte_sending_limit() {
        // With a 16-byte digest, 23 routes fit the sending limit and 24 do not.
        // Both messages still write without losing routes.
        let route = RouteEntry {
            tag: 0,
            address: ip4(10, 0, 0, 0),
            mask: ip4(255, 0, 0, 0),
            next_hop: Ipv4Addr::UNSPECIFIED,
            metric: 1,
        };
        let crypto = |n: usize| Message {
            command: Command::Response,
            version: Version::V2,
            auth: Some(Auth::Crypto(Crypto {
                key_id: 1,
                data_len: 16,
                sequence: 1,
                data: vec![9; 16],
            })),
            entries: Entries::Routes(vec![route; n]),
        };
        assert!(crypto(23).fits_datagram());
        assert!(!crypto(24).fits_datagram());
        let b = crypto(23).to_bytes().unwrap();
        assert_eq!(b.len(), 504);
        assert_eq!(check(&b), Ok(crypto(23)));
        assert_eq!(crypto(24).to_bytes().unwrap().len(), 524);
        // A 524-byte message reads and writes back.
        let mut wire = vec![2, 2, 0, 0, 0xff, 0xff, 0, 3];
        wire.extend_from_slice(&504u16.to_be_bytes());
        wire.extend_from_slice(&[1, 16, 0, 0, 0, 1]);
        wire.extend_from_slice(&[0; 8]);
        for _ in 0..24 {
            wire.extend_from_slice(&route_bytes(1));
        }
        wire.extend_from_slice(&[0xff, 0xff, 0, 1]);
        wire.extend_from_slice(&[9; 16]);
        assert_eq!(wire.len(), 524);
        assert_eq!(check(&wire), Ok(crypto(24)));
        // Without a trailer, 25 entries are 504 bytes.
        let plain = Message {
            auth: Some(Auth::Password([0; 16])),
            ..crypto(24)
        };
        assert_eq!(plain.to_bytes().unwrap().len(), 504);
        assert!(plain.fits_datagram());
        // Include the exact boundary and the first byte above it.
        for size in [MAX_DATAGRAM, MAX_DATAGRAM + 1] {
            let digest = size - 488; // Header, authentication, 23 routes, trailer header.
            let m = Message {
                auth: Some(Auth::Crypto(Crypto {
                    key_id: 1,
                    data_len: digest as u8,
                    sequence: 1,
                    data: vec![9; digest],
                })),
                ..crypto(23)
            };
            assert_eq!(m.to_bytes().unwrap().len(), size);
            assert_eq!(m.fits_datagram(), size <= MAX_DATAGRAM);
        }
    }

    #[test]
    fn stream_keeps_the_bytes_as_received() {
        let mut b = crypto_message(16, &[0xab; 16]);
        b[2] = 0x55;
        b[16] = 1;
        let mut stream = Stream::new(Collect::<Message>::new(MAX_MESSAGE));
        assert_eq!(stream.push(&b), b.len());
        stream.end();
        let m = stream
            .with_next(|message, raw, _| {
                assert_eq!(raw, b);
                message
            })
            .unwrap()
            .unwrap();
        assert_ne!(m.to_bytes().unwrap(), b);
    }

    #[test]
    fn collection_reads_all_routes() {
        let b = msg(2, 2, &vec![route_bytes(1); MAX_ENTRIES]);
        let m = collect(&b).unwrap();
        let Entries::Routes(routes) = m.entries else {
            panic!()
        };
        assert_eq!(routes.len(), MAX_ENTRIES);
    }

    /// Bytes shaped like a message: a sample with a few bytes changed, cut
    /// or added to, or bytes made up from a header.
    fn shaped(rng: &mut Lcg, pool: &[Vec<u8>]) -> Vec<u8> {
        let mut b = if rng.index(5) == 0 {
            let mut b = vec![1 + rng.index(2) as u8, 1 + rng.index(2) as u8, 0, 0];
            for _ in 0..rng.index(30) * 4 {
                // Mostly small bytes, so families and metrics are often
                // valid.
                b.push(if !rng.coin() {
                    0
                } else {
                    rng.next() as u8 % 20
                });
            }
            b
        } else {
            pool[rng.index(pool.len())].clone()
        };
        for _ in 0..1 + rng.index(4) {
            mutate(rng, &mut b);
        }
        b
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x5eed_0520);
        let pool = samples();
        let ng_pool = ng_samples();
        let mut repeated = msg(2, 2, &[route_bytes(1)]);
        for _ in 0..MAX_ENTRIES {
            repeated.extend_from_within(HEADER_LEN..HEADER_LEN + ENTRY_LEN);
        }
        assert_eq!(check(&repeated), Err(Error::TooManyEntries));
        let (mut ok, mut ng_ok) = (0, 0);
        // Deeper mutations need more trials to keep reaching valid messages.
        for _ in 0..rounds(12_000) {
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
            let raw: Vec<u8> = rng.bytes(79);
            let _ = check(&raw);
            let _ = ng_check(&raw);
        }
        // The shapes reach the parsers' far ends, not only their headers.
        assert!(ok > 500, "{ok}");
        assert!(ng_ok > 500, "{ng_ok}");
    }

    #[test]
    fn lcg_fuzz_writers() {
        let mut rng = Lcg::new(42);
        for _ in 0..4000 {
            let command = if !rng.coin() {
                Command::Request
            } else {
                Command::Response
            };
            let version = if !rng.coin() {
                Version::V1
            } else {
                Version::V2
            };
            let small = |rng: &mut Lcg| {
                if rng.index(3) == 0 {
                    rng.next() as u8
                } else {
                    0
                }
            };
            let auth = match rng.index(5) {
                0 => Some(Auth::Password([rng.next() as u8; 16])),
                1 => {
                    let n = rng.index(40);
                    let data_len = if rng.index(4) == 0 {
                        rng.next() as u8
                    } else {
                        n as u8
                    };
                    Some(Auth::Crypto(Crypto {
                        key_id: rng.next() as u8,
                        data_len,
                        sequence: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                        data: vec![rng.next() as u8; n],
                    }))
                }
                2 => Some(Auth::Other {
                    kind: rng.index(5) as u16,
                    data: [rng.next() as u8; 16],
                }),
                _ => None,
            };
            let entries = if rng.index(6) == 0 {
                Entries::WholeTable
            } else {
                let routes = (0..rng.index(28))
                    .map(|_| RouteEntry {
                        tag: u16::from(small(&mut rng)),
                        address: Ipv4Addr::from(u32::from_be_bytes(std::array::from_fn(|_| {
                            rng.next() as u8
                        }))),
                        mask: Ipv4Addr::from(if !rng.coin() {
                            0
                        } else {
                            u32::MAX << rng.index(32)
                        }),
                        next_hop: Ipv4Addr::from(u32::from(small(&mut rng))),
                        metric: rng.index(19) as u8,
                    })
                    .collect();
                Entries::Routes(routes)
            };
            let m = Message {
                command,
                version,
                auth,
                entries,
            };
            if let Ok(b) = m.to_bytes() {
                assert!(b.len() <= MAX_MESSAGE);
                assert_eq!(check(&b), Ok(m));
            }
            let ng_entries = if rng.index(6) == 0 {
                NgEntries::WholeTable
            } else {
                NgEntries::Entries(
                    (0..rng.index(8))
                        .map(|_| {
                            if rng.index(4) == 0 {
                                NgEntry::NextHop(Ipv6Addr::from(u128::from(u32::from_be_bytes(
                                    std::array::from_fn(|_| rng.next() as u8),
                                ))))
                            } else {
                                NgEntry::Route(NgRoute {
                                    prefix: Ipv6Addr::from(
                                        u128::from(u32::from_be_bytes(std::array::from_fn(|_| {
                                            rng.next() as u8
                                        }))) << 96,
                                    ),
                                    tag: u16::from(small(&mut rng)),
                                    prefix_len: rng.index(140) as u8,
                                    metric: rng.index(19) as u8,
                                })
                            }
                        })
                        .collect(),
                )
            };
            let n = NgMessage {
                command,
                entries: ng_entries,
            };
            if let Ok(b) = n.to_bytes() {
                assert_eq!(ng_check(&b), Ok(n));
            }
        }
    }
}
