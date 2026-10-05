//! PIM: reading and writing Protocol Independent Multicast version 2
//! messages, with no I/O.
//!
//! PIM (IP protocol 103) is how routers build the trees that carry
//! multicast traffic. Neighbors find each other with Hello messages. A
//! router that wants a group's traffic sends a Join/Prune message upstream,
//! toward the group's rendezvous point (RP) or toward a source. The router
//! next to a source wraps its first packets in Register messages and sends
//! them to the RP, which answers with Register-Stop once it gets them
//! natively. On a LAN where two routers forward the same traffic, Assert
//! messages pick one. The bootstrap router (BSR) floods Bootstrap messages
//! that list the RPs, and routers that want to be an RP send it
//! Candidate-RP-Advertisement messages. This module follows RFC 7761
//! (PIM Sparse Mode) and RFC 5059 (the Bootstrap mechanism).
//!
//! Every message starts with a 4-byte header: the version (2) and type,
//! a reserved byte, and a checksum. The checksum covers the whole message,
//! except in a Register, where it covers only the first 8 bytes. Over IPv6
//! it also covers a pseudo-header made from the IP header, so the source
//! and destination addresses must be known to read or write a message.
//! Addresses inside messages use three encodings, each led by an address
//! family: a unicast address, a group with a mask length and flags, and a
//! source with a mask length and flags.
//!
//! Nothing here reads a socket. A world that plays a router hands each PIM
//! payload (the bytes after the IP header) to [`Message::parse`] with the
//! packet's [`Endpoints`], looks at the [`Message`], and sends the bytes
//! [`Message::to_bytes`] returns in an IP packet with protocol
//! [`PROTOCOL`]. Hello, Join/Prune, Assert and Bootstrap messages go to
//! [`ALL_PIM_ROUTERS_V4`] or [`ALL_PIM_ROUTERS_V6`] with a TTL of 1. A
//! [`Decoder`] reads a payload that comes in pieces. Which routers are
//! neighbors, what trees exist and who wins an assert are up to world code.
//!
//! Every reader checks the version, the checksum, the address families,
//! the mask lengths and every count and length, because the agent can send
//! any bytes it likes. Every encoded address in a message must have the
//! family of the IP packet that carries it, so IPv4 and IPv6 never mix in
//! one message. Reserved bits, and the deprecated Border bit of a
//! Register, are ignored when read and written as zero. The Z (admin
//! scope zone) bit of a group is read only where RFC 5059 gives it a
//! meaning: in a Candidate-RP-Advertisement and in the first group of a
//! Bootstrap. Elsewhere it is ignored when read, and a writer refuses it.
//! Readers also check the rules RFC 7761 and RFC 5059 set on the parts of
//! a message: a Join/Prune names single multicast groups and never joins
//! and prunes one entry at once, a Register carries an IP header of the
//! packet's family, a Bootstrap fragment lists no more RPs for a range
//! than its RP count. Types this module does not read, such as the Graft
//! messages of PIM Dense Mode, are kept as bytes. Writers check the same
//! rules as readers, so bytes they return always read back. The one
//! exception goes the other way: a Candidate-RP-Advertisement with no
//! groups is read, since a BSR treats one from an older router as every
//! group, but RFC 5059 forbids sending one, so it is not written.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use fictionet::stdlib::pim::{ALL_PIM_ROUTERS_V4, Endpoints, HelloOption, Message};
//!
//! /// The holdtime a neighbor's Hello asks for, if it gives one.
//! fn holdtime(m: &Message) -> Option<u16> {
//!     let Message::Hello(options) = m else { return None };
//!     options.iter().find_map(|o| match o {
//!         HelloOption::Holdtime(t) => Some(*t),
//!         _ => None,
//!     })
//! }
//!
//! // A Hello from 10.0.0.2 that asks to be kept as a neighbor for 105
//! // seconds.
//! let ends = Endpoints::V4 { source: Ipv4Addr::new(10, 0, 0, 2), destination: ALL_PIM_ROUTERS_V4 };
//! let bytes = [0x20, 0x00, 0xdf, 0x93, 0x00, 0x01, 0x00, 0x02, 0x00, 0x69];
//! let hello = Message::parse(&bytes, &ends).unwrap();
//! assert_eq!(hello, Message::Hello(vec![HelloOption::Holdtime(105)]));
//! assert_eq!(holdtime(&hello), Some(105));
//! // Written back, the Hello is the same bytes.
//! assert_eq!(hello.to_bytes(&ends).unwrap(), bytes);
//! ```
//!
//! [`Datagram`] implements [`Wire`](super::codec::Wire) for a bounded,
//! byte-preserving payload. Collect chunks with `Collect<Datagram>` and
//! map each payload through [`Message::parse`] with [`Endpoints`]. End the
//! stream at the IP packet boundary. Collection errors end the stream;
//! message and checksum failures are mapped item errors. [`Message`] stays
//! outside `Wire` because the payload does not carry its endpoints.
//! [`Decoder`] keeps its context, constructor, early checks, and feed errors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The IP protocol number of PIM.
pub const PROTOCOL: u8 = 103;
/// The PIM version this module reads and writes.
pub const VERSION: u8 = 2;
/// The IPv4 multicast group link-local messages are sent to.
pub const ALL_PIM_ROUTERS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);
/// The IPv6 multicast group link-local messages are sent to.
pub const ALL_PIM_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0d);
/// The length of the header every message starts with.
pub const HEADER_LEN: usize = 4;
/// The bytes of a Register message its checksum covers: the header and
/// the flags word.
pub const REGISTER_HEADER_LEN: usize = 8;
/// The longest message read or written: the most an IPv6 packet without
/// jumbograms can carry.
pub const MAX_MESSAGE: usize = 65535;
/// The longest message read or written over IPv4: the 65535 bytes of an
/// IPv4 packet less its 20-byte header.
pub const MAX_MESSAGE_V4: usize = 65515;
/// The Hello holdtime RFC 7761 suggests, in seconds: 3.5 times the
/// 30-second Hello period.
pub const DEFAULT_HELLO_HOLDTIME: u16 = 105;
/// A holdtime that never runs out, in a Hello or a Join/Prune.
pub const HOLDTIME_FOREVER: u16 = 0xffff;
/// The largest Assert metric preference: it has 31 bits.
pub const MAX_METRIC_PREFERENCE: u32 = 0x7fff_ffff;
/// The largest LAN Prune Delay propagation delay: it has 15 bits.
pub const MAX_PROPAGATION_DELAY: u16 = 0x7fff;
/// The largest type a header can hold: it has 4 bits.
pub const MAX_TYPE: u8 = 15;

/// Message types.
pub mod kind {
    /// Hello: sent by every PIM router on each link.
    pub const HELLO: u8 = 0;
    /// Register: a data packet sent to the RP inside PIM.
    pub const REGISTER: u8 = 1;
    /// Register-Stop: the RP asks a router to stop registering.
    pub const REGISTER_STOP: u8 = 2;
    /// Join/Prune: join or leave trees, sent upstream.
    pub const JOIN_PRUNE: u8 = 3;
    /// Bootstrap: the BSR's list of RPs.
    pub const BOOTSTRAP: u8 = 4;
    /// Assert: picks one forwarder on a LAN.
    pub const ASSERT: u8 = 5;
    /// Graft, from PIM Dense Mode. Kept as bytes.
    pub const GRAFT: u8 = 6;
    /// Graft-Ack, from PIM Dense Mode. Kept as bytes.
    pub const GRAFT_ACK: u8 = 7;
    /// Candidate-RP-Advertisement: offers to be an RP, sent to the BSR.
    pub const CANDIDATE_RP_ADVERTISEMENT: u8 = 8;
}

/// Hello option types.
pub mod option {
    /// How long to keep the sender as a neighbor, in seconds.
    pub const HOLDTIME: u16 = 1;
    /// The LAN Prune Delay: propagation delay and override interval.
    pub const LAN_PRUNE_DELAY: u16 = 2;
    /// The sender's priority to be the designated router (DR).
    pub const DR_PRIORITY: u16 = 19;
    /// A number the sender picks when it starts, to show it restarted.
    pub const GENERATION_ID: u16 = 20;
    /// The sender's other addresses on the link.
    pub const ADDRESS_LIST: u16 = 24;
}

/// Address families in encoded addresses (the IANA numbers).
pub mod family {
    /// IPv4: 4-byte addresses.
    pub const IPV4: u8 = 1;
    /// IPv6: 16-byte addresses.
    pub const IPV6: u8 = 2;
}

/// The IP source and destination of the packet that carries a message.
/// IPv6 checksums cover them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Endpoints {
    /// An IPv4 packet.
    V4 {
        /// The sending router's address.
        source: Ipv4Addr,
        /// A router's address or [`ALL_PIM_ROUTERS_V4`].
        destination: Ipv4Addr,
    },
    /// An IPv6 packet.
    V6 {
        /// The sending router's address, link-local for link-local
        /// messages.
        source: Ipv6Addr,
        /// A router's address or [`ALL_PIM_ROUTERS_V6`].
        destination: Ipv6Addr,
    },
}

/// An Encoded-Group address: a multicast group or range of groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Group {
    /// The group, or the first group of the range.
    pub address: IpAddr,
    /// How many leading bits of `address` the range fixes: at most 32 for
    /// IPv4 and 128 for IPv6. A single group has 32 or 128.
    pub mask_len: u8,
    /// The B bit: the range is for Bidirectional PIM.
    pub bidirectional: bool,
    /// The Z bit: the range is an administrative scope zone.
    pub zone: bool,
}

impl Group {
    /// One group, with a full mask and no flags.
    pub fn single(address: IpAddr) -> Group {
        Group { address, mask_len: full_mask(address), bidirectional: false, zone: false }
    }

    /// A range of groups: `address` with its first `mask_len` bits fixed,
    /// and no flags. A mask longer than the address is a
    /// [`PimError::MaskLen`] when written.
    pub fn range(address: IpAddr, mask_len: u8) -> Group {
        Group { address, mask_len, bidirectional: false, zone: false }
    }
}

/// An Encoded-Source address: a source in a Join/Prune message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Source {
    /// The source address, or the RP's address for a shared-tree entry.
    pub address: IpAddr,
    /// How many leading bits of `address` count. RFC 7761 requires the
    /// full length, 32 for IPv4 and 128 for IPv6, and any other value is
    /// a [`PimError::MaskLen`].
    pub mask_len: u8,
    /// The S bit: the sender is in Sparse Mode. Always set in Sparse Mode.
    pub sparse: bool,
    /// The W bit: a wildcard entry, (*,G), joining the shared tree. It
    /// needs the R bit too, or the source is a [`PimError::SourceFlags`].
    pub wildcard: bool,
    /// The R bit: the entry is sent toward the RP.
    pub rpt: bool,
}

impl Source {
    /// One source of a (S,G) join or prune: a full mask and the S bit set.
    pub fn single(address: IpAddr) -> Source {
        Source { address, mask_len: full_mask(address), sparse: true, wildcard: false, rpt: false }
    }

    /// The entry of a (*,G) join or prune on the shared tree: the RP's
    /// address with a full mask and the S, W and R bits set.
    pub fn shared_tree(rp: IpAddr) -> Source {
        Source { address: rp, mask_len: full_mask(rp), sparse: true, wildcard: true, rpt: true }
    }
}

/// One option of a Hello message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HelloOption {
    /// How long to keep the sender as a neighbor, in seconds. 0 means drop
    /// it now, and [`HOLDTIME_FOREVER`] means never time it out.
    Holdtime(u16),
    /// The LAN Prune Delay option.
    LanPruneDelay {
        /// The T bit: the sender can turn off join suppression.
        tracking: bool,
        /// The link's propagation delay in milliseconds, up to
        /// [`MAX_PROPAGATION_DELAY`].
        propagation_delay: u16,
        /// The override interval in milliseconds.
        override_interval: u16,
    },
    /// The sender's priority to be the DR. The highest wins.
    DrPriority(u32),
    /// The sender's generation ID. A new one means it restarted.
    GenerationId(u32),
    /// The sender's secondary addresses on the link, all in the family of
    /// the packet.
    AddressList(Vec<IpAddr>),
    /// Any other option, with its value unread.
    Other {
        /// The option type. Not one of the types in [`option`].
        kind: u16,
        /// The value, at most 65535 bytes.
        value: Vec<u8>,
    },
}

impl HelloOption {
    /// The option's type.
    pub fn kind(&self) -> u16 {
        match self {
            HelloOption::Holdtime(_) => option::HOLDTIME,
            HelloOption::LanPruneDelay { .. } => option::LAN_PRUNE_DELAY,
            HelloOption::DrPriority(_) => option::DR_PRIORITY,
            HelloOption::GenerationId(_) => option::GENERATION_ID,
            HelloOption::AddressList(_) => option::ADDRESS_LIST,
            HelloOption::Other { kind, .. } => *kind,
        }
    }
}

/// A Register message: a data packet the router next to a source sends
/// to the RP. RFC 7761 deprecates the B (Border) bit, so it is ignored
/// when read and written as zero.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Register {
    /// The N bit: a Null-Register, which carries only the inner IP header
    /// and asks whether to start registering again.
    pub null: bool,
    /// The multicast data packet, from its IP header on. Only the start of
    /// the header is checked: it must be an IP header of the packet's
    /// family, at least 20 bytes with a header length that fits for IPv4,
    /// or at least 40 bytes for IPv6. The rest is unread.
    pub packet: Vec<u8>,
}

/// One group of a Join/Prune message, with the sources joined and pruned.
/// RFC 7761 section 4.9.5.1 sets the rules both readers and writers
/// check: the group is one multicast group with a full mask, there is at
/// most one (*,G) entry across both lists, and no (S,G) or (S,G,rpt)
/// entry is both joined and pruned.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JoinPruneGroup {
    /// The group: a multicast address with a mask of 32 or 128 bits, and
    /// no Z bit.
    pub group: Group,
    /// The sources joined. At most 65535.
    pub joins: Vec<Source>,
    /// The sources pruned. At most 65535.
    pub prunes: Vec<Source>,
}

/// A Join/Prune message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JoinPrune {
    /// The upstream neighbor the message is for. Other routers on the
    /// link read it too.
    pub upstream: IpAddr,
    /// How long the joins and prunes last, in seconds.
    pub holdtime: u16,
    /// The groups. At most 255.
    pub groups: Vec<JoinPruneGroup>,
}

/// One RP in a Bootstrap message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BootstrapRp {
    /// The RP's address.
    pub address: IpAddr,
    /// How long the RP stays valid, in seconds.
    pub holdtime: u16,
    /// The RP's priority. The lowest wins.
    pub priority: u8,
}

/// One group range of a Bootstrap message and its RPs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BootstrapGroup {
    /// The group range. Only the first group of a fragment may have the
    /// Z bit; in later groups it is ignored when read.
    pub group: Group,
    /// How many RPs the range has in all the fragments of the message.
    pub rp_count: u8,
    /// The RPs in this fragment. At most `rp_count`.
    pub rps: Vec<BootstrapRp>,
}

/// A Bootstrap message, or one fragment of one. When the first group has
/// the Z bit, the fragment is for an admin scope zone, and over IPv6 every
/// group must then have a mask of at least 16 bits and the first group's
/// scope (the low 4 bits of its second byte), as RFC 5059 section 4.1
/// requires.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Bootstrap {
    /// The N (No-Forward) bit of the header: routers that get the
    /// fragment do not forward it. RFC 5059 section 3.5.1 uses it for the
    /// Bootstrap a router sends a new neighbor.
    pub no_forward: bool,
    /// A number shared by all fragments of one message.
    pub fragment_tag: u16,
    /// The hash mask length, for spreading groups across RPs: at most 32
    /// for IPv4 and 128 for IPv6.
    pub hash_mask_len: u8,
    /// The BSR's priority. The highest wins.
    pub priority: u8,
    /// The BSR's address.
    pub bsr: IpAddr,
    /// The group ranges. Any number that fits in the message.
    pub groups: Vec<BootstrapGroup>,
}

/// An Assert message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Assert {
    /// The group the assert is for.
    pub group: Group,
    /// The source, or zero for a (*,G) assert.
    pub source: IpAddr,
    /// The R bit: the sender forwards on the shared tree.
    pub rpt: bool,
    /// The routing protocol's preference, up to [`MAX_METRIC_PREFERENCE`].
    /// The lowest wins.
    pub metric_preference: u32,
    /// The route's metric. The lowest wins.
    pub metric: u32,
}

/// A Candidate-RP-Advertisement message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CandidateRp {
    /// The candidate's priority. The lowest wins.
    pub priority: u8,
    /// How long the advertisement is valid, in seconds.
    pub holdtime: u16,
    /// The candidate RP's address.
    pub rp: IpAddr,
    /// The group ranges it offers to serve. At most 255. RFC 5059 says not
    /// to send an empty list, so writing one is a [`PimError::Count`], but
    /// one is read, since a BSR treats one from an older router as every
    /// group: 224.0.0.0/4 or ff00::/8.
    pub groups: Vec<Group>,
}

/// One PIM version 2 message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Message {
    /// Type 0, with its options in order.
    Hello(Vec<HelloOption>),
    /// Type 1.
    Register(Register),
    /// Type 2: stop registering the packets of a source to a group.
    RegisterStop {
        /// The group.
        group: Group,
        /// The source, or zero for every source.
        source: IpAddr,
    },
    /// Type 3.
    JoinPrune(JoinPrune),
    /// Type 4.
    Bootstrap(Bootstrap),
    /// Type 5.
    Assert(Assert),
    /// Type 8.
    CandidateRp(CandidateRp),
    /// Any other type, with the bytes after the header unread.
    Other {
        /// The type: up to [`MAX_TYPE`], and not one of the types above.
        kind: u8,
        /// The bytes after the header.
        body: Vec<u8>,
    },
}

/// Why bytes are not a PIM message, or a message cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PimError {
    /// The bytes end before the message does.
    Truncated,
    /// Bytes follow the end of the message.
    Trailing,
    /// The message is longer than [`MAX_MESSAGE`], or than
    /// [`MAX_MESSAGE_V4`] over IPv4.
    TooLong,
    /// The version was not 2.
    Version(u8),
    /// The checksum was wrong.
    Checksum,
    /// An encoded address had a family other than IPv4 (1) or IPv6 (2).
    Family(u8),
    /// An encoded address had an encoding type other than 0.
    Encoding(u8),
    /// An encoded address had a family other than the IP packet's. The
    /// value is the family it had.
    FamilyMismatch(u8),
    /// A group's mask length was longer than its address, a source's was
    /// not the full length of its address, or a Bootstrap's hash mask
    /// length was longer than its BSR's address.
    MaskLen(u8),
    /// A source had the W bit set without the R bit.
    SourceFlags,
    /// A Join/Prune group was not one multicast group with a full mask.
    JoinPruneGroup,
    /// A Join/Prune group listed more than one (*,G) entry, or joined and
    /// pruned the same (S,G) or (S,G,rpt) entry.
    SourceList,
    /// A Register's packet did not start with an IP header of the
    /// packet's family.
    Inner,
    /// A group to be written had the Z bit where it has no meaning, or a
    /// scoped IPv6 Bootstrap had a group with a mask under 16 bits or a
    /// scope other than the first group's.
    Zone,
    /// A Hello option this module knows had a value of the wrong length.
    OptionLength {
        /// The option type.
        kind: u16,
        /// The value's length.
        len: u16,
    },
    /// A message to be written had a type above [`MAX_TYPE`], or kept as
    /// [`Message::Other`] a type this module reads.
    Type(u8),
    /// A Hello option to be written as [`HelloOption::Other`] had a type
    /// this module reads.
    OptionKind(u16),
    /// A list to be written had more entries than its count field holds,
    /// a Hello option value was longer than 65535 bytes, a Bootstrap
    /// fragment listed more RPs for a range than its RP count, or a
    /// Candidate-RP-Advertisement to be written had no groups.
    Count,
    /// A field to be written was above its largest value.
    Value,
}

impl Endpoints {
    /// The endpoints of a packet from `source` to `destination`, or `None`
    /// if the two are not in the same family.
    pub fn new(source: IpAddr, destination: IpAddr) -> Option<Endpoints> {
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => Some(Endpoints::V4 { source, destination }),
            (IpAddr::V6(source), IpAddr::V6(destination)) => Some(Endpoints::V6 { source, destination }),
            _ => None,
        }
    }

    /// The packet's source address.
    pub fn source(&self) -> IpAddr {
        match *self {
            Endpoints::V4 { source, .. } => IpAddr::V4(source),
            Endpoints::V6 { source, .. } => IpAddr::V6(source),
        }
    }

    /// The packet's destination address.
    pub fn destination(&self) -> IpAddr {
        match *self {
            Endpoints::V4 { destination, .. } => IpAddr::V4(destination),
            Endpoints::V6 { destination, .. } => IpAddr::V6(destination),
        }
    }

    /// The packet's address family: [`family::IPV4`] or [`family::IPV6`].
    /// Every encoded address in the message must have it.
    pub fn family(&self) -> u8 {
        match self {
            Endpoints::V4 { .. } => family::IPV4,
            Endpoints::V6 { .. } => family::IPV6,
        }
    }

    /// The longest message the packet can carry: [`MAX_MESSAGE_V4`] for
    /// IPv4 and [`MAX_MESSAGE`] for IPv6.
    pub fn max_message(&self) -> usize {
        match self {
            Endpoints::V4 { .. } => MAX_MESSAGE_V4,
            Endpoints::V6 { .. } => MAX_MESSAGE,
        }
    }

    /// The length of an address in the packet's family: 4 or 16.
    fn address_len(&self) -> usize {
        match self {
            Endpoints::V4 { .. } => 4,
            Endpoints::V6 { .. } => 16,
        }
    }
}

impl std::fmt::Display for PimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PimError::Truncated => write!(f, "the message is cut short"),
            PimError::Trailing => write!(f, "bytes follow the end of the message"),
            PimError::TooLong => write!(f, "the message is longer than its IP packet can carry"),
            PimError::Version(v) => write!(f, "version {v}, not 2"),
            PimError::Checksum => write!(f, "the checksum is wrong"),
            PimError::Family(a) => write!(f, "address family {a}, not 1 (IPv4) or 2 (IPv6)"),
            PimError::Encoding(e) => write!(f, "address encoding type {e}, not 0"),
            PimError::FamilyMismatch(a) => write!(f, "address family {a}, not the family of the packet"),
            PimError::MaskLen(m) => write!(f, "mask length {m} does not fit the address"),
            PimError::SourceFlags => write!(f, "a source with the W bit but not the R bit"),
            PimError::JoinPruneGroup => write!(f, "a Join/Prune group that is not one multicast group"),
            PimError::SourceList => {
                write!(f, "a Join/Prune group with two (*,G) entries or a source joined and pruned")
            }
            PimError::Inner => write!(f, "a Register packet without an IP header of the packet's family"),
            PimError::Zone => write!(f, "an admin scope zone bit or scoped range that breaks RFC 5059"),
            PimError::OptionLength { kind, len } => write!(f, "Hello option {kind} with a {len}-byte value"),
            PimError::Type(t) => write!(f, "message type {t} cannot be written as other bytes"),
            PimError::OptionKind(k) => write!(f, "Hello option {k} cannot be written as other bytes"),
            PimError::Count => write!(f, "a list is longer than its count allows, or empty where it must not be"),
            PimError::Value => write!(f, "a field is above its largest value"),
        }
    }
}

impl std::error::Error for PimError {}

fn full_mask(a: IpAddr) -> u8 {
    match a {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Adds `b` to a ones' complement sum, as 16-bit words with a zero byte
/// added to an odd length.
fn sum_words(mut sum: u64, b: &[u8]) -> u64 {
    let mut words = b.chunks_exact(2);
    for w in &mut words {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = words.remainder() {
        sum += u64::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u64) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// The checksum of `covered`, with bytes 2 and 3 taken as zero, plus the
/// IPv6 pseudo-header for a length of `len`. `covered` is at least
/// [`HEADER_LEN`] and at most [`MAX_MESSAGE`] bytes, and so is `len`.
fn checksum_over(covered: &[u8], len: usize, endpoints: &Endpoints) -> u16 {
    let mut sum = sum_words(0, &covered[..2]);
    sum = sum_words(sum, &covered[HEADER_LEN..]);
    if let Endpoints::V6 { source, destination } = endpoints {
        // At most MAX_MESSAGE, so it fits in 32 bits.
        let len = len as u32;
        sum = sum_words(sum, &source.octets());
        sum = sum_words(sum, &destination.octets());
        sum = sum_words(sum, &len.to_be_bytes());
        sum = sum_words(sum, &[0, 0, 0, PROTOCOL]);
    }
    !fold(sum)
}

/// The checksum the message in `b` should carry, worked out with its
/// checksum field (bytes 2 and 3) taken as zero. It covers the whole
/// message, or only the first [`REGISTER_HEADER_LEN`] bytes of a Register.
/// Over IPv6 it also covers the pseudo-header of RFC 8200 section 8.1,
/// with protocol [`PROTOCOL`] and the length of the bytes covered. It
/// returns `None` if `b` is shorter than [`HEADER_LEN`] (or
/// [`REGISTER_HEADER_LEN`] for a Register) or longer than [`MAX_MESSAGE`].
pub fn checksum(b: &[u8], endpoints: &Endpoints) -> Option<u16> {
    if b.len() < HEADER_LEN || b.len() > MAX_MESSAGE {
        return None;
    }
    if b[0] & 0x0f == kind::REGISTER {
        return b.get(..REGISTER_HEADER_LEN).map(|c| checksum_over(c, REGISTER_HEADER_LEN, endpoints));
    }
    Some(checksum_over(b, b.len(), endpoints))
}

/// Whether a checksum field holds `want`. In ones' complement 0xffff and
/// 0x0000 are both zero, so either passes where 0x0000 is due.
fn checksum_matches(got: u16, want: u16) -> bool {
    got == want || (want == 0 && got == 0xffff)
}

/// Checks what the bytes so far show about the header. Every error it
/// gives holds for any bytes that could follow, which lets [`Decoder`]
/// stop early and still agree with [`Message::parse`]. `max` is the
/// longest message the packet can carry.
fn check_header(b: &[u8], max: usize) -> Result<(), PimError> {
    if let Some(&first) = b.first() {
        let version = first >> 4;
        if version != VERSION {
            return Err(PimError::Version(version));
        }
    }
    if b.len() > max {
        return Err(PimError::TooLong);
    }
    Ok(())
}

/// Checks that a Register's packet starts with an IP header of the
/// family whose addresses are `addr_len` bytes: version 4, at least 20
/// bytes and a header length from 5 words to the packet's length, or
/// version 6 and at least 40 bytes.
fn check_inner(p: &[u8], addr_len: usize) -> Result<(), PimError> {
    let ok = match (p.first(), addr_len) {
        (Some(&b), 4) => b >> 4 == 4 && p.len() >= 20 && (5..=p.len() / 4).contains(&usize::from(b & 0x0f)),
        (Some(&b), _) => b >> 4 == 6 && p.len() >= 40,
        (None, _) => false,
    };
    if ok { Ok(()) } else { Err(PimError::Inner) }
}

/// Checks a Join/Prune group set: one multicast group with a full mask,
/// at most one (*,G) entry across both lists, and no (S,G) or (S,G,rpt)
/// entry both joined and pruned. It sorts a copy of the entries, so it
/// takes time in proportion to n log n, not n squared.
fn check_join_prune_group(g: &JoinPruneGroup) -> Result<(), PimError> {
    if !g.group.address.is_multicast() || g.group.mask_len != full_mask(g.group.address) {
        return Err(PimError::JoinPruneGroup);
    }
    let mut wildcards = 0usize;
    let mut entries = Vec::with_capacity(g.joins.len() + g.prunes.len());
    for (pruned, list) in [(false, &g.joins), (true, &g.prunes)] {
        for s in list {
            if s.wildcard {
                wildcards += 1;
            } else {
                entries.push((s.address, s.rpt, pruned));
            }
        }
    }
    if wildcards > 1 {
        return Err(PimError::SourceList);
    }
    // Sorted by address, then tree, then list: a joined entry and a pruned
    // one for the same address and tree end up next to each other.
    entries.sort_unstable();
    if entries.windows(2).any(|w| w[0].0 == w[1].0 && w[0].1 == w[1].1 && w[0].2 != w[1].2) {
        return Err(PimError::SourceList);
    }
    Ok(())
}

/// Checks the admin scope rules of RFC 5059 section 4.1 on a Bootstrap's
/// groups. Only the first group may have the Z bit. If it does and it is
/// IPv6, every group needs a mask of at least 16 bits and the first
/// group's scope, the low 4 bits of the address's second byte.
fn check_scope(groups: &[BootstrapGroup]) -> Result<(), PimError> {
    if groups.iter().skip(1).any(|g| g.group.zone) {
        return Err(PimError::Zone);
    }
    if let Some(first) = groups.first()
        && first.group.zone
        && let IpAddr::V6(a) = first.group.address
    {
        let scope = a.octets()[1] & 0x0f;
        for g in groups {
            match g.group.address {
                IpAddr::V6(b) if g.group.mask_len >= 16 && b.octets()[1] & 0x0f == scope => {}
                _ => return Err(PimError::Zone),
            }
        }
    }
    Ok(())
}

/// Reads fields from the front of a byte slice. Every read checks the
/// length first.
struct Reader<'a> {
    b: &'a [u8],
    /// The length of an address in the packet's family: 4 or 16.
    addr_len: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PimError> {
        if self.b.len() < n {
            return Err(PimError::Truncated);
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, PimError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PimError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, PimError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn is_empty(&self) -> bool {
        self.b.is_empty()
    }

    fn end(&self) -> Result<(), PimError> {
        if self.b.is_empty() { Ok(()) } else { Err(PimError::Trailing) }
    }

    /// The family and encoding type bytes, checked, and the address
    /// length they give. The family must be the packet's.
    fn family(&mut self) -> Result<usize, PimError> {
        let fam = self.u8()?;
        let len = match fam {
            family::IPV4 => 4,
            family::IPV6 => 16,
            f => return Err(PimError::Family(f)),
        };
        if len != self.addr_len {
            return Err(PimError::FamilyMismatch(fam));
        }
        let enc = self.u8()?;
        if enc != 0 {
            return Err(PimError::Encoding(enc));
        }
        Ok(len)
    }

    fn address(&mut self, len: usize) -> Result<IpAddr, PimError> {
        let b = self.take(len)?;
        Ok(if len == 4 {
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        } else {
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            IpAddr::V6(Ipv6Addr::from(o))
        })
    }

    fn unicast(&mut self) -> Result<IpAddr, PimError> {
        let len = self.family()?;
        self.address(len)
    }

    /// A group: its mask length is at most the address length.
    fn group(&mut self) -> Result<Group, PimError> {
        let len = self.family()?;
        let flags = self.u8()?;
        let mask_len = self.u8()?;
        if usize::from(mask_len) > len * 8 {
            return Err(PimError::MaskLen(mask_len));
        }
        let address = self.address(len)?;
        Ok(Group { address, mask_len, bidirectional: flags & 0x80 != 0, zone: flags & 0x01 != 0 })
    }

    /// A source: its mask length is the full address length, and the W
    /// bit comes with the R bit.
    fn source(&mut self) -> Result<Source, PimError> {
        let len = self.family()?;
        let flags = self.u8()?;
        let mask_len = self.u8()?;
        if usize::from(mask_len) != len * 8 {
            return Err(PimError::MaskLen(mask_len));
        }
        let (wildcard, rpt) = (flags & 0x02 != 0, flags & 0x01 != 0);
        if wildcard && !rpt {
            return Err(PimError::SourceFlags);
        }
        let address = self.address(len)?;
        Ok(Source { address, mask_len, sparse: flags & 0x04 != 0, wildcard, rpt })
    }
}

fn parse_hello_option(kind: u16, value: &[u8], addr_len: usize) -> Result<HelloOption, PimError> {
    // The value came from a 16-bit length, so its length fits.
    let bad = || PimError::OptionLength { kind, len: value.len() as u16 };
    let mut r = Reader { b: value, addr_len };
    let fixed = |n: usize| if value.len() == n { Ok(()) } else { Err(bad()) };
    Ok(match kind {
        option::HOLDTIME => {
            fixed(2)?;
            HelloOption::Holdtime(r.u16()?)
        }
        option::LAN_PRUNE_DELAY => {
            fixed(4)?;
            let delay = r.u16()?;
            HelloOption::LanPruneDelay {
                tracking: delay & 0x8000 != 0,
                propagation_delay: delay & 0x7fff,
                override_interval: r.u16()?,
            }
        }
        option::DR_PRIORITY => {
            fixed(4)?;
            HelloOption::DrPriority(r.u32()?)
        }
        option::GENERATION_ID => {
            fixed(4)?;
            HelloOption::GenerationId(r.u32()?)
        }
        option::ADDRESS_LIST => {
            let mut list = Vec::new();
            while !r.is_empty() {
                list.push(r.unicast()?);
            }
            HelloOption::AddressList(list)
        }
        _ => HelloOption::Other { kind, value: value.to_vec() },
    })
}

fn is_known_option(kind: u16) -> bool {
    matches!(
        kind,
        option::HOLDTIME | option::LAN_PRUNE_DELAY | option::DR_PRIORITY | option::GENERATION_ID | option::ADDRESS_LIST
    )
}

fn is_known_type(kind: u8) -> bool {
    matches!(
        kind,
        kind::HELLO
            | kind::REGISTER
            | kind::REGISTER_STOP
            | kind::JOIN_PRUNE
            | kind::BOOTSTRAP
            | kind::ASSERT
            | kind::CANDIDATE_RP_ADVERTISEMENT
    )
}

impl Message {
    /// Reads the message in `b`, the whole PIM payload of one IP packet,
    /// sent from and to `endpoints`. The version must be 2 and the
    /// checksum right. A Register whose checksum covers the whole message
    /// is accepted too, as RFC 7761 asks. Every encoded address must have
    /// the family of `endpoints`. Every source must have a full mask, and
    /// the W bit only with the R bit. Every count must match the bytes
    /// that follow, and `b` must end where the message does, except for a
    /// Register or a type kept as [`Message::Other`], which run to the end.
    /// The rules on Join/Prune groups, Register packets and Bootstrap
    /// fragments in the module docs are checked too, and a Z bit where it
    /// has no meaning is read as clear.
    pub fn parse(b: &[u8], endpoints: &Endpoints) -> Result<Message, PimError> {
        check_header(b, endpoints.max_message())?;
        if b.len() < HEADER_LEN {
            return Err(PimError::Truncated);
        }
        let want = checksum(b, endpoints).ok_or(PimError::Truncated)?;
        let got = u16::from_be_bytes([b[2], b[3]]);
        // RFC 7761 sets the IPv6 pseudo-header length of a Register to 8
        // even when the checksum covers the whole message. Some senders
        // use the whole length, so both are accepted. Over IPv4 there is no
        // pseudo-header, so one sum covers both.
        let whole_register = || {
            b[0] & 0x0f == kind::REGISTER
                && (checksum_matches(got, checksum_over(b, REGISTER_HEADER_LEN, endpoints))
                    || (matches!(endpoints, Endpoints::V6 { .. })
                        && checksum_matches(got, checksum_over(b, b.len(), endpoints))))
        };
        if !checksum_matches(got, want) && !whole_register() {
            return Err(PimError::Checksum);
        }
        let mut r = Reader { b: &b[HEADER_LEN..], addr_len: endpoints.address_len() };
        let message = match b[0] & 0x0f {
            kind::HELLO => {
                let mut options = Vec::new();
                while !r.is_empty() {
                    let kind = r.u16()?;
                    let len = r.u16()?;
                    let value = r.take(usize::from(len))?;
                    options.push(parse_hello_option(kind, value, r.addr_len)?);
                }
                Message::Hello(options)
            }
            kind::REGISTER => {
                let flags = r.u32()?;
                let packet = r.take(r.b.len())?;
                check_inner(packet, r.addr_len)?;
                Message::Register(Register { null: flags & 0x4000_0000 != 0, packet: packet.to_vec() })
            }
            kind::REGISTER_STOP => {
                let group = Group { zone: false, ..r.group()? };
                let source = r.unicast()?;
                Message::RegisterStop { group, source }
            }
            kind::JOIN_PRUNE => {
                let upstream = r.unicast()?;
                let _reserved = r.u8()?;
                let count = r.u8()?;
                let holdtime = r.u16()?;
                let mut groups = Vec::new();
                for _ in 0..count {
                    let group = Group { zone: false, ..r.group()? };
                    let joined = r.u16()?;
                    let pruned = r.u16()?;
                    // Each source takes at least 8 bytes, so the lists
                    // grow only as the bytes allow.
                    let mut joins = Vec::new();
                    for _ in 0..joined {
                        joins.push(r.source()?);
                    }
                    let mut prunes = Vec::new();
                    for _ in 0..pruned {
                        prunes.push(r.source()?);
                    }
                    let g = JoinPruneGroup { group, joins, prunes };
                    check_join_prune_group(&g)?;
                    groups.push(g);
                }
                Message::JoinPrune(JoinPrune { upstream, holdtime, groups })
            }
            kind::BOOTSTRAP => {
                let fragment_tag = r.u16()?;
                let hash_mask_len = r.u8()?;
                let priority = r.u8()?;
                let bsr = r.unicast()?;
                if hash_mask_len > full_mask(bsr) {
                    return Err(PimError::MaskLen(hash_mask_len));
                }
                let mut groups: Vec<BootstrapGroup> = Vec::new();
                while !r.is_empty() {
                    let mut group = r.group()?;
                    // RFC 5059 section 4.1: the Z bit of every group but
                    // the first is ignored on receipt.
                    group.zone &= groups.is_empty();
                    let rp_count = r.u8()?;
                    let fragment_count = r.u8()?;
                    let _reserved = r.u16()?;
                    if fragment_count > rp_count {
                        return Err(PimError::Count);
                    }
                    let mut rps = Vec::new();
                    for _ in 0..fragment_count {
                        let address = r.unicast()?;
                        let holdtime = r.u16()?;
                        let priority = r.u8()?;
                        let _reserved = r.u8()?;
                        rps.push(BootstrapRp { address, holdtime, priority });
                    }
                    groups.push(BootstrapGroup { group, rp_count, rps });
                }
                check_scope(&groups)?;
                let no_forward = b[1] & 0x80 != 0;
                Message::Bootstrap(Bootstrap { no_forward, fragment_tag, hash_mask_len, priority, bsr, groups })
            }
            kind::ASSERT => {
                let group = Group { zone: false, ..r.group()? };
                let source = r.unicast()?;
                let pref = r.u32()?;
                let metric = r.u32()?;
                Message::Assert(Assert {
                    group,
                    source,
                    rpt: pref & 0x8000_0000 != 0,
                    metric_preference: pref & MAX_METRIC_PREFERENCE,
                    metric,
                })
            }
            kind::CANDIDATE_RP_ADVERTISEMENT => {
                let count = r.u8()?;
                let priority = r.u8()?;
                let holdtime = r.u16()?;
                let rp = r.unicast()?;
                let mut groups = Vec::new();
                for _ in 0..count {
                    groups.push(r.group()?);
                }
                Message::CandidateRp(CandidateRp { priority, holdtime, rp, groups })
            }
            kind => Message::Other { kind, body: r.take(r.b.len())?.to_vec() },
        };
        r.end()?;
        Ok(message)
    }

    /// The message's type.
    pub fn kind(&self) -> u8 {
        match self {
            Message::Hello(_) => kind::HELLO,
            Message::Register(_) => kind::REGISTER,
            Message::RegisterStop { .. } => kind::REGISTER_STOP,
            Message::JoinPrune(_) => kind::JOIN_PRUNE,
            Message::Bootstrap(_) => kind::BOOTSTRAP,
            Message::Assert(_) => kind::ASSERT,
            Message::CandidateRp(_) => kind::CANDIDATE_RP_ADVERTISEMENT,
            Message::Other { kind, .. } => *kind,
        }
    }

    /// Whether the message is sent to all PIM routers on the link, with a
    /// TTL of 1: Hello, Join/Prune, Bootstrap and Assert. The others go to
    /// one router's unicast address.
    pub fn is_link_local(&self) -> bool {
        matches!(self, Message::Hello(_) | Message::JoinPrune(_) | Message::Bootstrap(_) | Message::Assert(_))
    }

    /// How many bytes [`Message::to_bytes`] writes, or why it cannot write
    /// the message. It does not know the packet, so it does not check
    /// address families, a Register's packet or the IPv4 length limit;
    /// [`Message::to_bytes`] does.
    pub fn encoded_len(&self) -> Result<usize, PimError> {
        let mut n = Len(HEADER_LEN);
        match self {
            Message::Hello(options) => {
                for o in options {
                    let value = match o {
                        HelloOption::Holdtime(_) => 2,
                        HelloOption::LanPruneDelay { propagation_delay, .. } => {
                            if *propagation_delay > MAX_PROPAGATION_DELAY {
                                return Err(PimError::Value);
                            }
                            4
                        }
                        HelloOption::DrPriority(_) | HelloOption::GenerationId(_) => 4,
                        HelloOption::AddressList(list) => {
                            let mut v = Len(0);
                            for a in list {
                                v.add(unicast_len(*a))?;
                            }
                            v.0
                        }
                        HelloOption::Other { kind, value } => {
                            if is_known_option(*kind) {
                                return Err(PimError::OptionKind(*kind));
                            }
                            value.len()
                        }
                    };
                    if value > usize::from(u16::MAX) {
                        return Err(PimError::Count);
                    }
                    n.add(4)?;
                    n.add(value)?;
                }
            }
            Message::Register(reg) => {
                n.add(4)?;
                n.add(reg.packet.len())?;
            }
            Message::RegisterStop { group, source } => {
                n.add(group_len(group)?)?;
                no_zone(group)?;
                n.add(unicast_len(*source))?;
            }
            Message::JoinPrune(jp) => {
                if jp.groups.len() > usize::from(u8::MAX) {
                    return Err(PimError::Count);
                }
                n.add(unicast_len(jp.upstream))?;
                n.add(4)?;
                for g in &jp.groups {
                    if g.joins.len() > usize::from(u16::MAX) || g.prunes.len() > usize::from(u16::MAX) {
                        return Err(PimError::Count);
                    }
                    n.add(group_len(&g.group)?)?;
                    no_zone(&g.group)?;
                    n.add(4)?;
                    for s in g.joins.iter().chain(&g.prunes) {
                        n.add(source_len(s)?)?;
                    }
                    check_join_prune_group(g)?;
                }
            }
            Message::Bootstrap(bs) => {
                if bs.hash_mask_len > full_mask(bs.bsr) {
                    return Err(PimError::MaskLen(bs.hash_mask_len));
                }
                n.add(4)?;
                n.add(unicast_len(bs.bsr))?;
                for g in &bs.groups {
                    if g.rps.len() > usize::from(g.rp_count) {
                        return Err(PimError::Count);
                    }
                    n.add(group_len(&g.group)?)?;
                    n.add(4)?;
                    for rp in &g.rps {
                        n.add(unicast_len(rp.address))?;
                        n.add(4)?;
                    }
                }
                check_scope(&bs.groups)?;
            }
            Message::Assert(a) => {
                if a.metric_preference > MAX_METRIC_PREFERENCE {
                    return Err(PimError::Value);
                }
                n.add(group_len(&a.group)?)?;
                no_zone(&a.group)?;
                n.add(unicast_len(a.source))?;
                n.add(8)?;
            }
            Message::CandidateRp(c) => {
                // RFC 5059 section 4.2: a C-RP-Adv is never sent with no
                // groups.
                if c.groups.is_empty() || c.groups.len() > usize::from(u8::MAX) {
                    return Err(PimError::Count);
                }
                n.add(4)?;
                n.add(unicast_len(c.rp))?;
                for g in &c.groups {
                    n.add(group_len(g)?)?;
                }
            }
            Message::Other { kind, body } => {
                if *kind > MAX_TYPE || is_known_type(*kind) {
                    return Err(PimError::Type(*kind));
                }
                n.add(body.len())?;
            }
        }
        Ok(n.0)
    }

    /// Checks that every encoded address in the message has the family of
    /// the packet, whose addresses are `addr_len` bytes, and that a
    /// Register carries a packet of that family.
    fn check_families(&self, addr_len: usize) -> Result<(), PimError> {
        let f = |a: IpAddr| check_family(a, addr_len);
        match self {
            Message::Register(reg) => check_inner(&reg.packet, addr_len)?,
            Message::Hello(options) => {
                for o in options {
                    if let HelloOption::AddressList(list) = o {
                        list.iter().try_for_each(|a| f(*a))?;
                    }
                }
            }
            Message::Other { .. } => {}
            Message::RegisterStop { group, source } => {
                f(group.address)?;
                f(*source)?;
            }
            Message::JoinPrune(jp) => {
                f(jp.upstream)?;
                for g in &jp.groups {
                    f(g.group.address)?;
                    g.joins.iter().chain(&g.prunes).try_for_each(|s| f(s.address))?;
                }
            }
            Message::Bootstrap(bs) => {
                f(bs.bsr)?;
                for g in &bs.groups {
                    f(g.group.address)?;
                    g.rps.iter().try_for_each(|rp| f(rp.address))?;
                }
            }
            Message::Assert(a) => {
                f(a.group.address)?;
                f(a.source)?;
            }
            Message::CandidateRp(c) => {
                f(c.rp)?;
                c.groups.iter().try_for_each(|g| f(g.address))?;
            }
        }
        Ok(())
    }

    /// The message's bytes, to go from and to `endpoints`, with the
    /// checksum filled in. It fails if a list has more entries than its
    /// count field holds, a group's mask length is longer than its
    /// address, a source's is not the full length, a source has the W bit
    /// without the R bit, an address is not in the family of `endpoints`,
    /// a field is above its largest value, an [`Message::Other`] or
    /// [`HelloOption::Other`] has a type this module reads, a rule of the
    /// module docs on Join/Prune groups, Register packets, Bootstrap
    /// fragments or Z bits is broken, a Candidate-RP-Advertisement has no
    /// groups, or the message would be longer than
    /// [`Endpoints::max_message`]. The output is not allocated before
    /// those checks pass.
    pub fn to_bytes(&self, endpoints: &Endpoints) -> Result<Vec<u8>, PimError> {
        let len = self.encoded_len()?;
        if len > endpoints.max_message() {
            return Err(PimError::TooLong);
        }
        self.check_families(endpoints.address_len())?;
        let mut out = Vec::with_capacity(len);
        let no_forward = matches!(self, Message::Bootstrap(Bootstrap { no_forward: true, .. }));
        out.extend_from_slice(&[(VERSION << 4) | self.kind(), if no_forward { 0x80 } else { 0 }, 0, 0]);
        match self {
            Message::Hello(options) => {
                for o in options {
                    out.extend_from_slice(&o.kind().to_be_bytes());
                    let at = out.len();
                    out.extend_from_slice(&[0, 0]);
                    match o {
                        HelloOption::Holdtime(t) => out.extend_from_slice(&t.to_be_bytes()),
                        HelloOption::LanPruneDelay { tracking, propagation_delay, override_interval } => {
                            let d = propagation_delay | if *tracking { 0x8000 } else { 0 };
                            out.extend_from_slice(&d.to_be_bytes());
                            out.extend_from_slice(&override_interval.to_be_bytes());
                        }
                        HelloOption::DrPriority(v) | HelloOption::GenerationId(v) => {
                            out.extend_from_slice(&v.to_be_bytes())
                        }
                        HelloOption::AddressList(list) => list.iter().for_each(|a| put_unicast(&mut out, *a)),
                        HelloOption::Other { value, .. } => out.extend_from_slice(value),
                    }
                    // Checked in encoded_len to fit in 16 bits.
                    let value_len = (out.len() - at - 2) as u16;
                    out[at..at + 2].copy_from_slice(&value_len.to_be_bytes());
                }
            }
            Message::Register(reg) => {
                let flags: u32 = if reg.null { 0x4000_0000 } else { 0 };
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&reg.packet);
            }
            Message::RegisterStop { group, source } => {
                put_group(&mut out, group);
                put_unicast(&mut out, *source);
            }
            Message::JoinPrune(jp) => {
                put_unicast(&mut out, jp.upstream);
                out.extend_from_slice(&[0, jp.groups.len() as u8]);
                out.extend_from_slice(&jp.holdtime.to_be_bytes());
                for g in &jp.groups {
                    put_group(&mut out, &g.group);
                    out.extend_from_slice(&(g.joins.len() as u16).to_be_bytes());
                    out.extend_from_slice(&(g.prunes.len() as u16).to_be_bytes());
                    for s in g.joins.iter().chain(&g.prunes) {
                        put_source(&mut out, s);
                    }
                }
            }
            Message::Bootstrap(bs) => {
                out.extend_from_slice(&bs.fragment_tag.to_be_bytes());
                out.extend_from_slice(&[bs.hash_mask_len, bs.priority]);
                put_unicast(&mut out, bs.bsr);
                for g in &bs.groups {
                    put_group(&mut out, &g.group);
                    out.extend_from_slice(&[g.rp_count, g.rps.len() as u8, 0, 0]);
                    for rp in &g.rps {
                        put_unicast(&mut out, rp.address);
                        out.extend_from_slice(&rp.holdtime.to_be_bytes());
                        out.extend_from_slice(&[rp.priority, 0]);
                    }
                }
            }
            Message::Assert(a) => {
                put_group(&mut out, &a.group);
                put_unicast(&mut out, a.source);
                let pref = a.metric_preference | if a.rpt { 0x8000_0000 } else { 0 };
                out.extend_from_slice(&pref.to_be_bytes());
                out.extend_from_slice(&a.metric.to_be_bytes());
            }
            Message::CandidateRp(c) => {
                out.extend_from_slice(&[c.groups.len() as u8, c.priority]);
                out.extend_from_slice(&c.holdtime.to_be_bytes());
                put_unicast(&mut out, c.rp);
                for g in &c.groups {
                    put_group(&mut out, g);
                }
            }
            Message::Other { body, .. } => out.extend_from_slice(body),
        }
        // The length was checked above, so the checksum is always there.
        let c = checksum(&out, endpoints).unwrap_or(0);
        out[2..4].copy_from_slice(&c.to_be_bytes());
        Ok(out)
    }
}

/// A running message length that fails once it passes [`MAX_MESSAGE`].
struct Len(usize);

impl Len {
    fn add(&mut self, n: usize) -> Result<(), PimError> {
        self.0 = self.0.checked_add(n).filter(|&t| t <= MAX_MESSAGE).ok_or(PimError::TooLong)?;
        Ok(())
    }
}

fn address_len(a: IpAddr) -> usize {
    match a {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 16,
    }
}

fn unicast_len(a: IpAddr) -> usize {
    2 + address_len(a)
}

fn check_mask(a: IpAddr, mask_len: u8) -> Result<usize, PimError> {
    if mask_len > full_mask(a) {
        return Err(PimError::MaskLen(mask_len));
    }
    Ok(4 + address_len(a))
}

fn group_len(g: &Group) -> Result<usize, PimError> {
    check_mask(g.address, g.mask_len)
}

/// Checks that a group outside the Bootstrap mechanism has no Z bit: RFC
/// 7761 section 4.9.1 says to send it as zero there.
fn no_zone(g: &Group) -> Result<(), PimError> {
    if g.zone { Err(PimError::Zone) } else { Ok(()) }
}

fn source_len(s: &Source) -> Result<usize, PimError> {
    if s.mask_len != full_mask(s.address) {
        return Err(PimError::MaskLen(s.mask_len));
    }
    if s.wildcard && !s.rpt {
        return Err(PimError::SourceFlags);
    }
    Ok(4 + address_len(s.address))
}

fn family_of(a: IpAddr) -> u8 {
    match a {
        IpAddr::V4(_) => family::IPV4,
        IpAddr::V6(_) => family::IPV6,
    }
}

/// Checks that `a` is in the family whose addresses are `addr_len` bytes.
fn check_family(a: IpAddr, addr_len: usize) -> Result<(), PimError> {
    if address_len(a) == addr_len { Ok(()) } else { Err(PimError::FamilyMismatch(family_of(a))) }
}

fn put_family(out: &mut Vec<u8>, a: IpAddr) {
    out.extend_from_slice(&[family_of(a), 0]);
}

fn put_address(out: &mut Vec<u8>, a: IpAddr) {
    match a {
        IpAddr::V4(v) => out.extend_from_slice(&v.octets()),
        IpAddr::V6(v) => out.extend_from_slice(&v.octets()),
    }
}

fn put_unicast(out: &mut Vec<u8>, a: IpAddr) {
    put_family(out, a);
    put_address(out, a);
}

fn put_group(out: &mut Vec<u8>, g: &Group) {
    put_family(out, g.address);
    let flags = if g.bidirectional { 0x80 } else { 0 } | if g.zone { 0x01 } else { 0 };
    out.extend_from_slice(&[flags, g.mask_len]);
    put_address(out, g.address);
}

fn put_source(out: &mut Vec<u8>, s: &Source) {
    put_family(out, s.address);
    let flags = if s.sparse { 0x04 } else { 0 } | if s.wildcard { 0x02 } else { 0 } | if s.rpt { 0x01 } else { 0 };
    out.extend_from_slice(&[flags, s.mask_len]);
    put_address(out, s.address);
}

/// One bounded IP payload, with every received byte preserved.
///
/// [`Wire`](super::codec::Wire) reads the entire payload and checks only
/// [`MAX_MESSAGE`]. It does not validate a PIM message or its checksum.
/// Use [`Message::parse`] with the packet's [`Endpoints`] for that check.
/// The endpoints are not encoded in this payload.
///
/// ```
/// use fictionet::stdlib::{codec::{Collect, Decode, Stream}, pim};
/// # let endpoints = pim::Endpoints::V4 {
/// #     source: "192.0.2.1".parse().unwrap(),
/// #     destination: "224.0.0.1".parse().unwrap(),
/// # };
/// let messages = Collect::<pim::Datagram>::new(pim::MAX_MESSAGE)
///     .map(move |datagram| pim::Message::parse(&datagram.0, &endpoints));
/// let mut stream = Stream::new(messages);
/// // Push chunks of one IP payload, then call stream.end().
/// # stream.end();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram(
    /// Complete payload bytes, including the received checksum.
    /// Parsing and writing refuse more than [`MAX_MESSAGE`] bytes.
    pub Vec<u8>,
);

impl super::codec::Wire for Datagram {
    type ParseError = PimError;
    type WriteError = PimError;

    /// Copies the entire payload after checking [`MAX_MESSAGE`].
    /// Message and checksum validation need [`Endpoints`] separately.
    fn parse(bytes: &[u8]) -> Result<Self, PimError> {
        if bytes.len() > MAX_MESSAGE {
            return Err(PimError::TooLong);
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Appends the original payload. Leaves `out` unchanged on error.
    /// No checksum is computed or validated.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), PimError> {
        if self.0.len() > MAX_MESSAGE {
            return Err(PimError::TooLong);
        }
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

/// Reads one message that comes in pieces. Feed it the bytes in order,
/// then call [`Decoder::finish`]. It fails as soon as the bytes show a
/// version other than 2 or run past [`Endpoints::max_message`]. It holds
/// at most [`MAX_MESSAGE`] plus one bytes.
#[derive(Clone, Debug)]
pub struct Decoder {
    endpoints: Endpoints,
    buf: Vec<u8>,
    failed: Option<PimError>,
}

impl Decoder {
    /// A decoder for a message sent from and to `endpoints`, holding no
    /// bytes.
    pub fn new(endpoints: Endpoints) -> Decoder {
        Decoder { endpoints, buf: Vec::new(), failed: None }
    }

    /// Adds the next bytes of the message. It returns the error once the
    /// bytes show one, and the same error on every later call. Bytes fed
    /// after that are dropped.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), PimError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        // One byte past the longest message is enough to know it is too
        // long.
        let max = self.endpoints.max_message();
        let room = (max + 1).saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
        check_header(&self.buf, max).inspect_err(|&e| {
            self.failed = Some(e);
            self.buf = Vec::new();
        })
    }

    /// How many bytes are held.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The message, when no more bytes will come. It gives the same result
    /// as [`Message::parse`] on all the bytes fed.
    pub fn finish(self) -> Result<Message, PimError> {
        match self.failed {
            Some(e) => Err(e),
            None => Message::parse(&self.buf, &self.endpoints),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    fn v4_ends() -> Endpoints {
        Endpoints::V4 { source: Ipv4Addr::new(10, 0, 0, 2), destination: ALL_PIM_ROUTERS_V4 }
    }

    fn v6_ends() -> Endpoints {
        Endpoints::V6 { source: "fe80::2".parse().unwrap(), destination: ALL_PIM_ROUTERS_V6 }
    }

    /// `b` with its checksum field set right.
    fn fix(mut b: Vec<u8>, e: &Endpoints) -> Vec<u8> {
        if let Some(c) = checksum(&b, e) {
            b[2..4].copy_from_slice(&c.to_be_bytes());
        }
        b
    }

    fn round_trip(m: &Message, e: &Endpoints) -> Vec<u8> {
        let b = m.to_bytes(e).unwrap();
        assert_eq!(b.len(), m.encoded_len().unwrap());
        assert_eq!(Message::parse(&b, e).as_ref(), Ok(m));
        b
    }

    fn decode_chunked(b: &[u8], e: &Endpoints, size: usize) -> Result<Message, PimError> {
        let mut d = Decoder::new(*e);
        for c in b.chunks(size.max(1)) {
            let _ = d.feed(c);
        }
        d.finish()
    }

    #[test]
    fn module_example() {
        // The words are 0x2000 + 0x0001 + 0x0002 + 0x0069 = 0x206c, and
        // its complement is 0xdf93.
        let bytes = [0x20, 0x00, 0xdf, 0x93, 0x00, 0x01, 0x00, 0x02, 0x00, 0x69];
        let m = Message::parse(&bytes, &v4_ends()).unwrap();
        assert_eq!(m, Message::Hello(vec![HelloOption::Holdtime(DEFAULT_HELLO_HOLDTIME)]));
        assert_eq!(m.to_bytes(&v4_ends()).unwrap(), bytes);
        assert!(m.is_link_local());
    }

    #[test]
    fn hello_with_every_option() {
        // RFC 7761 section 4.9.2: Holdtime, LAN Prune Delay, DR Priority,
        // Generation ID and Address List.
        let m = Message::Hello(vec![
            HelloOption::Holdtime(105),
            HelloOption::LanPruneDelay { tracking: true, propagation_delay: 500, override_interval: 2500 },
            HelloOption::DrPriority(1),
            HelloOption::GenerationId(0xdead_beef),
            HelloOption::AddressList(vec![v4(10, 0, 0, 9), v4(10, 0, 0, 10)]),
            HelloOption::Other { kind: 21, value: vec![] },
        ]);
        let b = round_trip(&m, &v4_ends());
        // The LAN Prune Delay: type 2, length 4, T bit and 500, then 2500.
        assert_eq!(&b[10..18], &[0, 2, 0, 4, 0x81, 0xf4, 0x09, 0xc4]);
        // The address list: type 24, length 6 + 6.
        let at = 10 + 8 + 8 + 8;
        assert_eq!(&b[at..at + 16], &[0, 24, 0, 12, 1, 0, 10, 0, 0, 9, 1, 0, 10, 0, 0, 10]);
        let m6 = Message::Hello(vec![HelloOption::AddressList(vec![v6("2001:db8::1")])]);
        let b6 = round_trip(&m6, &v6_ends());
        assert_eq!(&b6[4..10], &[0, 24, 0, 18, 2, 0]);
    }

    #[test]
    fn address_families_match_the_packet() {
        // RFC 7761 section 4.3.4: one Address List holds one family, and
        // section 4.9.5: one Join/Prune does not mix families. RFC 5059
        // section 4: Bootstrap and C-RP-Adv addresses have the packet's
        // family. Here, an IPv6 address in an IPv4 packet.
        let e = v4_ends();
        let mixed = Message::Hello(vec![HelloOption::AddressList(vec![v4(10, 0, 0, 9), v6("2001:db8::1")])]);
        assert_eq!(mixed.to_bytes(&e), Err(PimError::FamilyMismatch(2)));
        let b = fix([&[0x20u8, 0, 0, 0, 0, 24, 0, 18, 2, 0][..], &[0; 16]].concat(), &e);
        assert_eq!(Message::parse(&b, &e), Err(PimError::FamilyMismatch(2)));
        // Every message type, written for one family, fails for the other.
        for (ok, bad) in [(v4_ends(), v6_ends()), (v6_ends(), v4_ends())] {
            for m in samples(&ok) {
                let b = m.to_bytes(&ok).unwrap();
                let has_addresses = !matches!(m, Message::Register(_) | Message::Other { .. });
                if has_addresses {
                    assert!(matches!(m.to_bytes(&bad), Err(PimError::FamilyMismatch(_))), "{m:?}");
                    let b = fix(b, &bad);
                    assert!(matches!(Message::parse(&b, &bad), Err(PimError::FamilyMismatch(_))), "{m:?}");
                }
            }
        }
        // A Join/Prune with an IPv4 upstream and an IPv6 source.
        let jp = Message::JoinPrune(JoinPrune {
            upstream: v4(10, 0, 0, 1),
            holdtime: 210,
            groups: vec![JoinPruneGroup {
                group: Group::single(v4(239, 1, 1, 1)),
                joins: vec![Source::single(v6("2001:db8::1"))],
                prunes: vec![],
            }],
        });
        assert_eq!(jp.to_bytes(&e), Err(PimError::FamilyMismatch(2)));
    }

    #[test]
    fn source_mask_and_flags() {
        // RFC 7761 section 4.9.1: a source's mask length must be the full
        // length, and the W bit needs the R bit.
        let e = v4_ends();
        let jp = |flags: u8, mask: u8| {
            fix(
                vec![
                    0x23, 0, 0, 0, 1, 0, 10, 0, 0, 1, 0, 1, 0, 10, 1, 0, 0, 32, 239, 1, 1, 1, 0, 1, 0, 0, 1, 0, flags,
                    mask, 10, 1, 1, 1,
                ],
                &e,
            )
        };
        assert!(Message::parse(&jp(4, 32), &e).is_ok());
        assert!(Message::parse(&jp(7, 32), &e).is_ok());
        assert_eq!(Message::parse(&jp(4, 24), &e), Err(PimError::MaskLen(24)));
        assert_eq!(Message::parse(&jp(4, 0), &e), Err(PimError::MaskLen(0)));
        assert_eq!(Message::parse(&jp(6, 32), &e), Err(PimError::SourceFlags));
        let write = |s: Source| {
            Message::JoinPrune(JoinPrune {
                upstream: v4(10, 0, 0, 1),
                holdtime: 1,
                groups: vec![JoinPruneGroup { group: Group::single(v4(239, 1, 1, 1)), joins: vec![s], prunes: vec![] }],
            })
            .to_bytes(&e)
        };
        assert_eq!(write(Source { mask_len: 24, ..Source::single(v4(10, 1, 1, 0)) }), Err(PimError::MaskLen(24)));
        assert_eq!(write(Source { wildcard: true, ..Source::single(v4(10, 1, 1, 1)) }), Err(PimError::SourceFlags));
    }

    #[test]
    fn register_checksum_covers_eight_bytes() {
        let inner = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 239, 1, 1, 1];
        let m = Message::Register(Register { null: true, packet: inner.clone() });
        let b = round_trip(&m, &v4_ends());
        // Header 0x2100, flags 0x4000 0x0000: sum 0x6100, complement 0x9eff.
        assert_eq!(&b[..8], &[0x21, 0, 0x9e, 0xff, 0x40, 0, 0, 0]);
        assert_eq!(&b[8..], &inner[..]);
        // Changing the inner packet keeps the checksum right.
        let mut other = b.clone();
        other[10] = 0x77;
        assert!(Message::parse(&other, &v4_ends()).is_ok());
        // A checksum over the whole message is accepted too.
        let whole = checksum_over(&b, b.len(), &v4_ends());
        let mut w = b.clone();
        w[2..4].copy_from_slice(&whole.to_be_bytes());
        assert_eq!(Message::parse(&w, &v4_ends()), Ok(m.clone()));
        // Any other checksum is not.
        let mut bad = b.clone();
        bad[3] ^= 1;
        assert_eq!(Message::parse(&bad, &v4_ends()), Err(PimError::Checksum));
        // The B bit is deprecated: ignored when read, written as zero.
        let mut border = b.clone();
        border[4] |= 0x80;
        assert_eq!(Message::parse(&fix(border, &v4_ends()), &v4_ends()), Ok(m.clone()));
        // Over IPv6 a checksum of the whole message uses a pseudo-header
        // length of 8, as RFC 7761 section 4.9.3 says. The whole length is
        // accepted too.
        let e6 = v6_ends();
        let m = Message::Register(Register { null: true, packet: inner_header(true) });
        let b6 = round_trip(&m, &e6);
        for len in [REGISTER_HEADER_LEN, b6.len()] {
            let mut w = b6.clone();
            w[2..4].copy_from_slice(&checksum_over(&b6, len, &e6).to_be_bytes());
            assert_eq!(Message::parse(&w, &e6), Ok(m.clone()));
        }
    }

    #[test]
    fn register_stop_bytes() {
        let m = Message::RegisterStop { group: Group::single(v4(239, 1, 2, 3)), source: v4(10, 1, 1, 1) };
        let b = round_trip(&m, &v4_ends());
        assert_eq!(&b[4..], &[1, 0, 0, 32, 239, 1, 2, 3, 1, 0, 10, 1, 1, 1]);
        assert!(!m.is_link_local());
    }

    #[test]
    fn join_prune_bytes() {
        let rp = v4(10, 9, 9, 9);
        let m = Message::JoinPrune(JoinPrune {
            upstream: v4(10, 0, 0, 1),
            holdtime: 210,
            groups: vec![
                JoinPruneGroup {
                    group: Group::single(v4(239, 1, 1, 1)),
                    joins: vec![Source { address: rp, mask_len: 32, sparse: true, wildcard: true, rpt: true }],
                    prunes: vec![Source { rpt: true, ..Source::single(v4(10, 1, 1, 1)) }],
                },
                JoinPruneGroup {
                    group: Group::single(v4(232, 1, 1, 1)),
                    joins: vec![Source::single(v4(10, 2, 2, 2))],
                    prunes: vec![],
                },
            ],
        });
        let b = round_trip(&m, &v4_ends());
        // Upstream, reserved, 2 groups, holdtime 210.
        assert_eq!(&b[4..14], &[1, 0, 10, 0, 0, 1, 0, 2, 0, 210]);
        // Group 1, 1 join and 1 prune, the (*,G) join with S, W and R set.
        assert_eq!(&b[14..30], &[1, 0, 0, 32, 239, 1, 1, 1, 0, 1, 0, 1, 1, 0, 7, 32]);
        // The same over IPv6, with IPv6 addresses.
        let m6 = Message::JoinPrune(JoinPrune {
            upstream: v6("fe80::1"),
            holdtime: 210,
            groups: vec![JoinPruneGroup {
                group: Group::single(v6("ff3e::1")),
                joins: vec![Source {
                    address: v6("2001:db8::9"),
                    mask_len: 128,
                    sparse: true,
                    wildcard: true,
                    rpt: true,
                }],
                prunes: vec![],
            }],
        });
        let b6 = round_trip(&m6, &v6_ends());
        assert_eq!(&b6[50..54], &[2, 0, 7, 128]);
    }

    #[test]
    fn bootstrap_bytes() {
        let m = Message::Bootstrap(Bootstrap {
            no_forward: false,
            fragment_tag: 0x1234,
            hash_mask_len: 30,
            priority: 64,
            bsr: v4(10, 0, 0, 5),
            groups: vec![BootstrapGroup {
                group: Group { address: v4(224, 0, 0, 0), mask_len: 4, bidirectional: false, zone: false },
                rp_count: 2,
                rps: vec![BootstrapRp { address: v4(10, 0, 0, 7), holdtime: 150, priority: 192 }],
            }],
        });
        let b = round_trip(&m, &v4_ends());
        assert_eq!(&b[4..16], &[0x12, 0x34, 30, 64, 1, 0, 10, 0, 0, 5, 1, 0]);
        assert_eq!(&b[16..34], &[0, 4, 224, 0, 0, 0, 2, 1, 0, 0, 1, 0, 10, 0, 0, 7, 0, 150]);
        assert_eq!(&b[34..], &[192, 0]);
        // No groups at all is a valid fragment.
        round_trip(
            &Message::Bootstrap(Bootstrap {
                groups: vec![],
                ..match m {
                    Message::Bootstrap(b) => b,
                    _ => unreachable!(),
                }
            }),
            &v4_ends(),
        );
    }

    #[test]
    fn assert_bytes() {
        let m = Message::Assert(Assert {
            group: Group::single(v6("ff3e::1")),
            source: v6("2001:db8::5"),
            rpt: true,
            metric_preference: 110,
            metric: 20,
        });
        let b = round_trip(&m, &v6_ends());
        assert_eq!(&b[b.len() - 8..], &[0x80, 0, 0, 110, 0, 0, 0, 20]);
    }

    #[test]
    fn candidate_rp_bytes() {
        let m = Message::CandidateRp(CandidateRp {
            priority: 192,
            holdtime: 150,
            rp: v4(10, 0, 0, 7),
            groups: vec![Group { address: v4(239, 0, 0, 0), mask_len: 8, bidirectional: true, zone: true }],
        });
        let b = round_trip(&m, &v4_ends());
        assert_eq!(&b[4..], &[1, 192, 0, 150, 1, 0, 10, 0, 0, 7, 1, 0, 0x81, 8, 239, 0, 0, 0]);
        // RFC 5059 section 4.2: no groups is never sent, but is read, as
        // a BSR reads one from an older router as every group.
        let empty = Message::CandidateRp(CandidateRp { priority: 0, holdtime: 0, rp: v4(1, 2, 3, 4), groups: vec![] });
        assert_eq!(empty.to_bytes(&v4_ends()), Err(PimError::Count));
        let b = fix(vec![0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 3, 4], &v4_ends());
        assert_eq!(Message::parse(&b, &v4_ends()), Ok(empty));
    }

    #[test]
    fn constructors_and_accessors() {
        let e = Endpoints::new(v4(10, 0, 0, 2), IpAddr::V4(ALL_PIM_ROUTERS_V4)).unwrap();
        assert_eq!(e, v4_ends());
        assert_eq!((e.source(), e.destination(), e.family()), (v4(10, 0, 0, 2), v4(224, 0, 0, 13), family::IPV4));
        let e6 = Endpoints::new(v6("fe80::2"), IpAddr::V6(ALL_PIM_ROUTERS_V6)).unwrap();
        assert_eq!(e6, v6_ends());
        assert_eq!(e6.family(), family::IPV6);
        assert_eq!(e6.destination(), v6("ff02::d"));
        assert_eq!(Endpoints::new(v4(10, 0, 0, 2), v6("ff02::d")), None);
        let s = Source::shared_tree(v6("2001:db8::9"));
        assert_eq!(s, Source { address: v6("2001:db8::9"), mask_len: 128, sparse: true, wildcard: true, rpt: true });
        let g = Group::range(v4(239, 0, 0, 0), 8);
        assert_eq!(g, Group { address: v4(239, 0, 0, 0), mask_len: 8, bidirectional: false, zone: false });
        let jp = Message::JoinPrune(JoinPrune {
            upstream: v4(10, 0, 0, 1),
            holdtime: 210,
            groups: vec![JoinPruneGroup {
                group: Group::single(v4(239, 0, 0, 1)),
                joins: vec![Source::shared_tree(v4(10, 9, 9, 9))],
                prunes: vec![],
            }],
        });
        round_trip(&jp, &e);
        assert_eq!(
            Message::RegisterStop { group: Group::range(v4(239, 0, 0, 0), 33), source: v4(1, 1, 1, 1) }.to_bytes(&e),
            Err(PimError::MaskLen(33))
        );
    }

    #[test]
    fn largest_messages() {
        // The longest Hello: 16382 options with empty values fill the
        // message, and read back in one linear pass.
        let e = v6_ends();
        let n = (MAX_MESSAGE - HEADER_LEN) / 4;
        let m = Message::Hello(vec![HelloOption::Other { kind: 9999, value: vec![] }; n]);
        let b = round_trip(&m, &e);
        assert_eq!(decode_chunked(&b, &e, 4096), Ok(m.clone()));
        // One more option is too long.
        let Message::Hello(mut more) = m else { unreachable!() };
        more.push(HelloOption::Holdtime(1));
        assert_eq!(Message::Hello(more).to_bytes(&e), Err(PimError::TooLong));
        // The most sources a Join/Prune can hold, over IPv6.
        let e6 = v6_ends();
        let room = MAX_MESSAGE - HEADER_LEN - 18 - 4 - 20 - 4;
        let joins = vec![Source::single(v6("2001:db8::1")); room / 20];
        let jp = Message::JoinPrune(JoinPrune {
            upstream: v6("fe80::1"),
            holdtime: 1,
            groups: vec![JoinPruneGroup { group: Group::single(v6("ff3e::1")), joins, prunes: vec![] }],
        });
        let b = round_trip(&jp, &e6);
        assert!(b.len() <= MAX_MESSAGE && b.len() + 20 > MAX_MESSAGE);
        // A largest Register over IPv6, with each checksum length.
        let reg = Message::Register(Register { null: false, packet: vec![0x60; MAX_MESSAGE - REGISTER_HEADER_LEN] });
        let b = round_trip(&reg, &e6);
        let mut w = b.clone();
        w[2..4].copy_from_slice(&checksum_over(&b, b.len(), &e6).to_be_bytes());
        assert_eq!(Message::parse(&w, &e6), Ok(reg));
    }

    #[test]
    fn other_types_kept() {
        let m = Message::Other { kind: kind::GRAFT, body: vec![1, 2, 3] };
        let b = round_trip(&m, &v4_ends());
        assert_eq!(b[0], 0x26);
        assert_eq!(m.kind(), 6);
    }

    #[test]
    fn reserved_bits_ignored() {
        let m = Message::RegisterStop { group: Group::single(v4(239, 1, 2, 3)), source: v4(10, 1, 1, 1) };
        let mut b = m.to_bytes(&v4_ends()).unwrap();
        // The header's reserved byte and the group's reserved flag bits.
        b[1] = 0xff;
        b[6] |= 0x7e;
        let b = fix(b, &v4_ends());
        assert_eq!(Message::parse(&b, &v4_ends()), Ok(m));
    }

    #[test]
    fn negative_zero_checksum() {
        // Find a Hello option whose checksum comes to 0, then send 0xffff.
        for g in 0..=u32::from(u16::MAX) {
            let m = Message::Hello(vec![HelloOption::GenerationId(g)]);
            let b = m.to_bytes(&v4_ends()).unwrap();
            if b[2..4] == [0, 0] {
                let mut n = b.clone();
                n[2..4].copy_from_slice(&[0xff, 0xff]);
                assert_eq!(Message::parse(&n, &v4_ends()), Ok(m));
                return;
            }
        }
        panic!("no message with a zero checksum");
    }

    #[test]
    fn parse_errors() {
        let e = v4_ends();
        assert_eq!(Message::parse(&[], &e), Err(PimError::Truncated));
        assert_eq!(Message::parse(&[0x10], &e), Err(PimError::Version(1)));
        assert_eq!(Message::parse(&[0x20, 0, 0], &e), Err(PimError::Truncated));
        assert_eq!(Message::parse(&[0x20, 0, 0, 0], &e), Err(PimError::Checksum));
        assert_eq!(Message::parse(&fix(vec![0x20, 0, 0, 0], &e), &e), Ok(Message::Hello(vec![])));
        // A Register needs its flags word.
        assert_eq!(Message::parse(&[0x21, 0, 0, 0, 0], &e), Err(PimError::Truncated));
        let mut long = vec![0x26, 0, 0, 0];
        long.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(Message::parse(&long, &e), Err(PimError::TooLong));
        // Address family and encoding.
        let stop = |rest: &[u8]| fix([&[0x22, 0, 0, 0][..], rest].concat(), &e);
        assert_eq!(Message::parse(&stop(&[3, 0, 0, 32, 1, 1, 1, 1]), &e), Err(PimError::Family(3)));
        assert_eq!(Message::parse(&stop(&[1, 1, 0, 32, 1, 1, 1, 1]), &e), Err(PimError::Encoding(1)));
        assert_eq!(Message::parse(&stop(&[1, 0, 0, 33, 1, 1, 1, 1]), &e), Err(PimError::MaskLen(33)));
        assert_eq!(Message::parse(&stop(&[1, 0, 0, 32, 1, 1, 1, 1, 1, 0, 1, 1, 1]), &e), Err(PimError::Truncated));
        assert_eq!(Message::parse(&stop(&[1, 0, 0, 32, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 9]), &e), Err(PimError::Trailing));
        // An IPv6 group may have a 128-bit mask, but no more.
        let e6 = v6_ends();
        let stop6 = |rest: &[u8]| fix([&[0x22, 0, 0, 0][..], rest].concat(), &e6);
        let g6 = [&[2u8, 0, 0, 128][..], &[0xff; 16], &[2, 0], &[1; 16]].concat();
        assert!(Message::parse(&stop6(&g6), &e6).is_ok());
        let g6 = [&[2u8, 0, 0, 129][..], &[0xff; 16], &[2, 0], &[1; 16]].concat();
        assert_eq!(Message::parse(&stop6(&g6), &e6), Err(PimError::MaskLen(129)));
        // Hello option lengths.
        let hello = |rest: &[u8]| fix([&[0x20, 0, 0, 0][..], rest].concat(), &e);
        assert_eq!(Message::parse(&hello(&[0, 1, 0, 3, 0, 0, 0]), &e), Err(PimError::OptionLength { kind: 1, len: 3 }));
        assert_eq!(Message::parse(&hello(&[0, 19, 0, 2, 0, 0]), &e), Err(PimError::OptionLength { kind: 19, len: 2 }));
        assert_eq!(Message::parse(&hello(&[0, 1, 0, 3, 0, 0]), &e), Err(PimError::Truncated));
        assert_eq!(Message::parse(&hello(&[0, 1, 0]), &e), Err(PimError::Truncated));
        // An address list that ends inside an address.
        assert_eq!(Message::parse(&hello(&[0, 24, 0, 3, 1, 0, 9]), &e), Err(PimError::Truncated));
        // A Join/Prune whose group count promises more than comes.
        let jp = fix(vec![0x23, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 200, 0, 10], &e);
        assert_eq!(Message::parse(&jp, &e), Err(PimError::Truncated));
        // A source count of 65535 with no sources.
        let jp =
            fix(vec![0x23, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 10, 1, 0, 0, 32, 239, 1, 1, 1, 0xff, 0xff, 0, 0], &e);
        assert_eq!(Message::parse(&jp, &e), Err(PimError::Truncated));
        // An Assert with bytes after it.
        let a = Message::Assert(Assert {
            group: Group::single(v4(239, 1, 1, 1)),
            source: v4(1, 1, 1, 1),
            rpt: false,
            metric_preference: 1,
            metric: 1,
        });
        let mut b = a.to_bytes(&e).unwrap();
        b.push(0);
        assert_eq!(Message::parse(&fix(b, &e), &e), Err(PimError::Trailing));
        // The IPv6 checksum covers the pseudo-header, so the endpoints
        // must match.
        let b = samples(&v6_ends())[5].to_bytes(&v6_ends()).unwrap();
        let other = Endpoints::V6 { source: "fe80::3".parse().unwrap(), destination: ALL_PIM_ROUTERS_V6 };
        assert_eq!(Message::parse(&b, &other), Err(PimError::Checksum));
        assert!(Message::parse(&b, &v6_ends()).is_ok());
    }

    #[test]
    fn write_errors() {
        let e = v4_ends();
        let bad_group = Group { address: v4(239, 0, 0, 0), mask_len: 33, bidirectional: false, zone: false };
        assert_eq!(
            Message::RegisterStop { group: bad_group, source: v4(1, 1, 1, 1) }.to_bytes(&e),
            Err(PimError::MaskLen(33))
        );
        let bad_source = Source { mask_len: 129, ..Source::single(v6("::1")) };
        let jp = |groups| Message::JoinPrune(JoinPrune { upstream: v4(1, 1, 1, 1), holdtime: 1, groups });
        let g = Group::single(v4(239, 1, 1, 1));
        assert_eq!(
            jp(vec![JoinPruneGroup { group: g, joins: vec![bad_source], prunes: vec![] }]).to_bytes(&e),
            Err(PimError::MaskLen(129))
        );
        let many = vec![JoinPruneGroup { group: g, joins: vec![], prunes: vec![] }; 256];
        assert_eq!(jp(many).to_bytes(&e), Err(PimError::Count));
        let lots = vec![Source::single(v4(1, 1, 1, 1)); 65536];
        assert_eq!(
            jp(vec![JoinPruneGroup { group: g, joins: lots, prunes: vec![] }]).to_bytes(&e),
            Err(PimError::Count)
        );
        let lots = vec![Source::single(v4(1, 1, 1, 1)); 9000];
        assert_eq!(
            jp(vec![JoinPruneGroup { group: g, joins: lots, prunes: vec![] }]).to_bytes(&e),
            Err(PimError::TooLong)
        );
        let a = Assert { group: g, source: v4(1, 1, 1, 1), rpt: false, metric_preference: 0x8000_0000, metric: 0 };
        assert_eq!(Message::Assert(a).to_bytes(&e), Err(PimError::Value));
        let lpd = HelloOption::LanPruneDelay { tracking: false, propagation_delay: 0x8000, override_interval: 0 };
        assert_eq!(Message::Hello(vec![lpd]).to_bytes(&e), Err(PimError::Value));
        let other = HelloOption::Other { kind: option::HOLDTIME, value: vec![0, 1] };
        assert_eq!(Message::Hello(vec![other]).to_bytes(&e), Err(PimError::OptionKind(1)));
        let big = HelloOption::Other { kind: 65000, value: vec![0; 65536] };
        assert_eq!(Message::Hello(vec![big]).to_bytes(&e), Err(PimError::Count));
        assert_eq!(Message::Other { kind: kind::ASSERT, body: vec![] }.to_bytes(&e), Err(PimError::Type(5)));
        assert_eq!(Message::Other { kind: 16, body: vec![] }.to_bytes(&e), Err(PimError::Type(16)));
        let reg = Message::Register(Register { null: false, packet: vec![0x45; MAX_MESSAGE] });
        assert_eq!(reg.to_bytes(&e), Err(PimError::TooLong));
        let reg = Message::Register(Register { null: false, packet: vec![0x45; MAX_MESSAGE_V4 - 8] });
        assert_eq!(reg.to_bytes(&e).unwrap().len(), MAX_MESSAGE_V4);
        let bs = |rps| Bootstrap {
            no_forward: false,
            fragment_tag: 0,
            hash_mask_len: 0,
            priority: 0,
            bsr: v4(1, 1, 1, 1),
            groups: vec![BootstrapGroup { group: g, rp_count: 0, rps }],
        };
        let rp = BootstrapRp { address: v4(1, 1, 1, 1), holdtime: 0, priority: 0 };
        assert_eq!(Message::Bootstrap(bs(vec![rp; 256])).to_bytes(&e), Err(PimError::Count));
        let crp = CandidateRp { priority: 0, holdtime: 0, rp: v4(1, 1, 1, 1), groups: vec![g; 256] };
        assert_eq!(Message::CandidateRp(crp).to_bytes(&e), Err(PimError::Count));
        // Every error has a message.
        for err in [
            PimError::Truncated,
            PimError::OptionLength { kind: 1, len: 3 },
            PimError::Value,
            PimError::FamilyMismatch(2),
            PimError::SourceFlags,
        ] {
            assert!(!err.to_string().is_empty());
        }
    }

    /// Bytes written as hex pairs separated by spaces.
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).unwrap()).collect()
    }

    #[test]
    fn bootstrap_no_forward_bit() {
        // RFC 5059 section 4.1: the N bit is the top bit of header byte 1.
        // A No-Forward Bootstrap from 10.0.0.5 with no groups, checksum
        // worked out by hand.
        let e = v4_ends();
        let b = hex("24 80 b2 39 00 01 1e 40 01 00 0a 00 00 05");
        let m = Message::Bootstrap(Bootstrap {
            no_forward: true,
            fragment_tag: 1,
            hash_mask_len: 30,
            priority: 64,
            bsr: v4(10, 0, 0, 5),
            groups: vec![],
        });
        assert_eq!(Message::parse(&b, &e), Ok(m.clone()));
        assert_eq!(m.to_bytes(&e).unwrap(), b);
        // Without the bit; the other reserved bits are still ignored.
        let mut clear = b.clone();
        clear[1] = 0x7f;
        let Message::Bootstrap(inner) = m else { unreachable!() };
        let forward = Message::Bootstrap(Bootstrap { no_forward: false, ..inner });
        assert_eq!(Message::parse(&fix(clear, &e), &e), Ok(forward.clone()));
        assert_eq!(forward.to_bytes(&e).unwrap()[1], 0);
        // The bit means nothing in other types, so it is not read there.
        let mut hello = Message::Hello(vec![]).to_bytes(&e).unwrap();
        hello[1] = 0x80;
        assert_eq!(Message::parse(&fix(hello, &e), &e), Ok(Message::Hello(vec![])));
    }

    #[test]
    fn join_prune_groups_are_single_multicast_groups() {
        // RFC 7761 section 4.9.5.1: the one valid group set is a multicast
        // group with a full mask. This one is 239.0.0.0/8.
        let e = v4_ends();
        let b = hex(
            "23 00 d0 ff 01 00 0a 00 00 01 00 01 00 d2 01 00 00 08 ef 00 00 00 00 01 00 00 01 00 04 20 0a 01 01 01",
        );
        assert_eq!(Message::parse(&b, &e), Err(PimError::JoinPruneGroup));
        let jp = |group: Group| {
            Message::JoinPrune(JoinPrune {
                upstream: v4(10, 0, 0, 1),
                holdtime: 210,
                groups: vec![JoinPruneGroup { group, joins: vec![Source::single(v4(10, 1, 1, 1))], prunes: vec![] }],
            })
        };
        assert_eq!(jp(Group::range(v4(239, 0, 0, 0), 8)).to_bytes(&e), Err(PimError::JoinPruneGroup));
        assert_eq!(jp(Group::single(v4(10, 0, 0, 1))).to_bytes(&e), Err(PimError::JoinPruneGroup));
        let b = round_trip(&jp(Group::single(v4(239, 0, 0, 1))), &e);
        // The unicast group 10.0.0.1, written by hand.
        let mut unicast = b.clone();
        unicast[18] = 10;
        assert_eq!(Message::parse(&fix(unicast, &e), &e), Err(PimError::JoinPruneGroup));
        let e6 = v6_ends();
        let jp6 = |group: Group| {
            Message::JoinPrune(JoinPrune {
                upstream: v6("fe80::1"),
                holdtime: 210,
                groups: vec![JoinPruneGroup { group, joins: vec![Source::single(v6("2001:db8::1"))], prunes: vec![] }],
            })
        };
        assert_eq!(jp6(Group::range(v6("ff3e::"), 64)).to_bytes(&e6), Err(PimError::JoinPruneGroup));
        round_trip(&jp6(Group::single(v6("ff3e::1"))), &e6);
    }

    #[test]
    fn join_prune_source_lists() {
        // RFC 7761 section 4.9.5.1: one (*,G) entry at most, and no (S,G)
        // or (S,G,rpt) entry both joined and pruned. These bytes join and
        // prune (10.1.1.1, 239.1.1.1).
        let e = v4_ends();
        let b = hex(
            "23 00 bf c2 01 00 0a 00 00 01 00 01 00 d2 01 00 00 20 ef 01 01 01 00 01 00 01 01 00 04 20 0a 01 01 01 01 00 04 20 0a 01 01 01",
        );
        assert_eq!(Message::parse(&b, &e), Err(PimError::SourceList));
        let jp = |joins: Vec<Source>, prunes: Vec<Source>| {
            Message::JoinPrune(JoinPrune {
                upstream: v4(10, 0, 0, 1),
                holdtime: 210,
                groups: vec![JoinPruneGroup { group: Group::single(v4(239, 1, 1, 1)), joins, prunes }],
            })
        };
        let s = Source::single(v4(10, 1, 1, 1));
        let rpt = Source { rpt: true, ..s };
        let star = Source::shared_tree(v4(10, 9, 9, 9));
        assert_eq!(jp(vec![s], vec![s]).to_bytes(&e), Err(PimError::SourceList));
        assert_eq!(jp(vec![rpt], vec![rpt]).to_bytes(&e), Err(PimError::SourceList));
        assert_eq!(jp(vec![star], vec![star]).to_bytes(&e), Err(PimError::SourceList));
        assert_eq!(jp(vec![star, star], vec![]).to_bytes(&e), Err(PimError::SourceList));
        // Allowed: an (S,G) join with an (S,G,rpt) prune of the same
        // source, a (*,G) join with an (S,G,rpt) prune, and the same entry
        // twice in one list.
        round_trip(&jp(vec![s], vec![rpt]), &e);
        round_trip(&jp(vec![star], vec![rpt, s]), &e);
        round_trip(&jp(vec![s, s], vec![]), &e);
        // A conflict among many entries is still found.
        let many: Vec<Source> =
            (0..500u32).map(|i| Source::single(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)))).collect();
        round_trip(&jp(many.clone(), vec![]), &e);
        assert_eq!(jp(many, vec![Source::single(v4(10, 0, 1, 0))]).to_bytes(&e), Err(PimError::SourceList));
    }

    #[test]
    fn register_packet_is_an_ip_header_of_the_family() {
        // RFC 7761 section 4.9.3: the packet has the family of the PIM
        // packet. An empty Register, checksum worked out by hand.
        let e = v4_ends();
        assert_eq!(Message::parse(&hex("21 00 de ff 00 00 00 00"), &e), Err(PimError::Inner));
        let reg = |packet: Vec<u8>| Message::Register(Register { null: false, packet });
        assert_eq!(reg(vec![]).to_bytes(&e), Err(PimError::Inner));
        let v4h = inner_header(false);
        let v6h = inner_header(true);
        round_trip(&reg(v4h.clone()), &e);
        round_trip(&reg(v6h.clone()), &v6_ends());
        // The wrong family, both ways.
        assert_eq!(reg(v4h.clone()).to_bytes(&v6_ends()), Err(PimError::Inner));
        assert_eq!(reg(v6h.clone()).to_bytes(&e), Err(PimError::Inner));
        let wrong = fix([&[0x21u8, 0, 0, 0, 0, 0, 0, 0][..], &v6h].concat(), &e);
        assert_eq!(Message::parse(&wrong, &e), Err(PimError::Inner));
        // Too short, or an IPv4 header length out of range.
        assert_eq!(reg(v4h[..19].to_vec()).to_bytes(&e), Err(PimError::Inner));
        assert_eq!(reg(v6h[..39].to_vec()).to_bytes(&v6_ends()), Err(PimError::Inner));
        let ihl = |b: u8| {
            let mut p = v4h.clone();
            p[0] = b;
            reg(p).to_bytes(&e)
        };
        assert_eq!(ihl(0x44), Err(PimError::Inner));
        assert_eq!(ihl(0x46), Err(PimError::Inner));
        let mut options = v4h.clone();
        options[0] = 0x46;
        options.extend_from_slice(&[1, 1, 1, 0]);
        round_trip(&reg(options), &e);
    }

    #[test]
    fn bootstrap_counts_and_hash_mask() {
        let e = v4_ends();
        // RFC 5059 section 4.1: a fragment holds no more RPs for a range
        // than the range has in all. RP count 0 with one RP here.
        let b = hex(
            "24 00 f5 f7 00 01 1e 40 01 00 0a 00 00 05 01 00 00 20 ef 01 01 01 00 01 00 00 01 00 0a 00 00 07 00 96 c0 00",
        );
        assert_eq!(Message::parse(&b, &e), Err(PimError::Count));
        let rp = BootstrapRp { address: v4(10, 0, 0, 7), holdtime: 150, priority: 192 };
        let bs = |hash_mask_len: u8, bsr: IpAddr, groups: Vec<BootstrapGroup>| {
            Message::Bootstrap(Bootstrap {
                no_forward: false,
                fragment_tag: 1,
                hash_mask_len,
                priority: 64,
                bsr,
                groups,
            })
        };
        let g = |rp_count: u8, rps: Vec<BootstrapRp>| BootstrapGroup {
            group: Group::range(v4(239, 0, 0, 0), 8),
            rp_count,
            rps,
        };
        assert_eq!(bs(30, v4(10, 0, 0, 5), vec![g(0, vec![rp])]).to_bytes(&e), Err(PimError::Count));
        assert_eq!(bs(30, v4(10, 0, 0, 5), vec![g(1, vec![rp, rp])]).to_bytes(&e), Err(PimError::Count));
        round_trip(&bs(30, v4(10, 0, 0, 5), vec![g(2, vec![rp, rp]), g(0, vec![])]), &e);
        // RFC 5059 section 4.1 and RFC 7761 section 4.7.2: the hash mask
        // is a mask of the family, so at most 32 or 128 bits.
        round_trip(&bs(32, v4(10, 0, 0, 5), vec![]), &e);
        assert_eq!(bs(33, v4(10, 0, 0, 5), vec![]).to_bytes(&e), Err(PimError::MaskLen(33)));
        assert_eq!(bs(255, v4(10, 0, 0, 5), vec![]).to_bytes(&e), Err(PimError::MaskLen(255)));
        let b = fix(hex("24 00 00 00 00 01 21 40 01 00 0a 00 00 05"), &e);
        assert_eq!(Message::parse(&b, &e), Err(PimError::MaskLen(33)));
        let e6 = v6_ends();
        round_trip(&bs(128, v6("2001:db8::5"), vec![]), &e6);
        assert_eq!(bs(129, v6("2001:db8::5"), vec![]).to_bytes(&e6), Err(PimError::MaskLen(129)));
    }

    #[test]
    fn scoped_bootstrap_fragments() {
        // RFC 5059 section 4.1: only the first group may have the Z bit.
        // In a scoped IPv6 fragment every group has a mask of at least 16
        // bits and the first group's scope.
        let e6 = v6_ends();
        let group = |a: &str, mask_len: u8, zone: bool| BootstrapGroup {
            group: Group { address: v6(a), mask_len, bidirectional: false, zone },
            rp_count: 0,
            rps: vec![],
        };
        let bs = |groups| {
            Message::Bootstrap(Bootstrap {
                no_forward: false,
                fragment_tag: 1,
                hash_mask_len: 126,
                priority: 64,
                bsr: v6("2001:db8::5"),
                groups,
            })
        };
        let scoped = bs(vec![group("ff05::", 16, true), group("ff15:1::", 32, false)]);
        let b = round_trip(&scoped, &e6);
        assert_eq!(bs(vec![group("ff05::", 8, true)]).to_bytes(&e6), Err(PimError::Zone));
        assert_eq!(bs(vec![group("ff05::", 16, true), group("ff08::", 16, false)]).to_bytes(&e6), Err(PimError::Zone));
        assert_eq!(bs(vec![group("ff05::", 16, true), group("ff05::", 12, false)]).to_bytes(&e6), Err(PimError::Zone));
        // Unscoped fragments have no such rule.
        round_trip(&bs(vec![group("ff00::", 8, false), group("ff05::", 12, false)]), &e6);
        // The first group's mask, cut to 8 bits by hand.
        let mut short = b.clone();
        short[4 + 4 + 18 + 3] = 8;
        assert_eq!(Message::parse(&fix(short, &e6), &e6), Err(PimError::Zone));
        // A Z bit on a later group is refused when written and ignored
        // when read.
        assert_eq!(bs(vec![group("ff00::", 8, false), group("ff05::", 16, true)]).to_bytes(&e6), Err(PimError::Zone));
        let plain = bs(vec![group("ff00::", 8, false), group("ff05::", 16, false)]);
        let mut b = plain.to_bytes(&e6).unwrap();
        let second = 4 + 4 + 18 + 20 + 4;
        b[second + 2] |= 0x01;
        assert_eq!(Message::parse(&fix(b, &e6), &e6), Ok(plain));
    }

    #[test]
    fn candidate_rp_with_no_groups() {
        // RFC 5059 section 4.2: a C-RP-Adv is never sent with Prefix Count
        // 0, but one from an older router is read. Checksum worked out by
        // hand.
        let e = v4_ends();
        let m = Message::CandidateRp(CandidateRp { priority: 192, holdtime: 150, rp: v4(10, 0, 0, 7), groups: vec![] });
        assert_eq!(Message::parse(&hex("28 00 cb a2 00 c0 00 96 01 00 0a 00 00 07"), &e), Ok(m.clone()));
        assert_eq!(m.to_bytes(&e), Err(PimError::Count));
        assert_eq!(m.encoded_len(), Err(PimError::Count));
    }

    #[test]
    fn zone_bit_only_in_the_bootstrap_mechanism() {
        // RFC 7761 section 4.9.1: outside the BSR mechanism the Z bit is
        // sent as zero and ignored on receipt.
        let e = v4_ends();
        let zoned = Group { zone: true, ..Group::single(v4(239, 1, 2, 3)) };
        let stop = Message::RegisterStop { group: zoned, source: v4(10, 1, 1, 1) };
        assert_eq!(stop.to_bytes(&e), Err(PimError::Zone));
        let plain = Message::RegisterStop { group: Group::single(v4(239, 1, 2, 3)), source: v4(10, 1, 1, 1) };
        let mut b = plain.to_bytes(&e).unwrap();
        b[6] |= 0x01;
        assert_eq!(Message::parse(&fix(b, &e), &e), Ok(plain));
        let assert = Assert { group: zoned, source: v4(10, 1, 1, 1), rpt: false, metric_preference: 1, metric: 1 };
        assert_eq!(Message::Assert(assert).to_bytes(&e), Err(PimError::Zone));
        let plain = Message::Assert(Assert { group: Group::single(v4(239, 1, 2, 3)), ..assert });
        let mut b = plain.to_bytes(&e).unwrap();
        b[6] |= 0x01;
        assert_eq!(Message::parse(&fix(b, &e), &e), Ok(plain));
        let jp = |group| {
            Message::JoinPrune(JoinPrune {
                upstream: v4(10, 0, 0, 1),
                holdtime: 210,
                groups: vec![JoinPruneGroup { group, joins: vec![Source::single(v4(10, 1, 1, 1))], prunes: vec![] }],
            })
        };
        assert_eq!(jp(zoned).to_bytes(&e), Err(PimError::Zone));
        let plain = jp(Group::single(v4(239, 1, 2, 3)));
        let mut b = plain.to_bytes(&e).unwrap();
        b[16] |= 0x01;
        assert_eq!(Message::parse(&fix(b, &e), &e), Ok(plain));
        // A C-RP-Adv keeps it: a ZBR sets it there.
        round_trip(
            &Message::CandidateRp(CandidateRp { priority: 0, holdtime: 150, rp: v4(10, 0, 0, 7), groups: vec![zoned] }),
            &e,
        );
    }

    #[test]
    fn ipv4_length_limit() {
        // RFC 791: an IPv4 packet is at most 65535 bytes with its 20-byte
        // header, so the PIM payload is at most 65515.
        let e = v4_ends();
        let hello = |n: usize| Message::Hello(vec![HelloOption::Other { kind: 9999, value: vec![0; n] }]);
        assert_eq!(hello(MAX_MESSAGE - 8).encoded_len(), Ok(MAX_MESSAGE));
        assert_eq!(hello(MAX_MESSAGE - 8).to_bytes(&e), Err(PimError::TooLong));
        round_trip(&hello(MAX_MESSAGE - 8), &v6_ends());
        let b = round_trip(&hello(MAX_MESSAGE_V4 - 8), &e);
        assert_eq!(b.len(), MAX_MESSAGE_V4);
        let mut long = vec![0x26, 0, 0, 0];
        long.resize(MAX_MESSAGE_V4 + 1, 0);
        let long = fix(long, &e);
        assert_eq!(Message::parse(&long, &e), Err(PimError::TooLong));
        assert_eq!(decode_chunked(&long, &e, 1000), Err(PimError::TooLong));
        assert!(Message::parse(&fix(long, &v6_ends()), &v6_ends()).is_ok());
        assert_eq!(e.max_message(), MAX_MESSAGE_V4);
        assert_eq!(v6_ends().max_message(), MAX_MESSAGE);
    }

    /// The smallest IP header a Register can carry: IPv4 or IPv6.
    fn inner_header(six: bool) -> Vec<u8> {
        if six {
            let mut h = vec![0x60, 0, 0, 0, 0, 4, 103, 1];
            h.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            h.extend_from_slice(&[0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            h
        } else {
            vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 103, 0, 0, 10, 0, 0, 1, 239, 1, 1, 1]
        }
    }

    /// One message of each type, with addresses in the family of `e`.
    fn samples(e: &Endpoints) -> Vec<Message> {
        let six = matches!(e, Endpoints::V6 { .. });
        let a = |n: u8| if six { v6(&format!("2001:db8::{n}")) } else { v4(10, 0, 0, n) };
        let g = Group::single(if six { v6("ff3e::8") } else { v4(239, 1, 1, 1) });
        vec![
            Message::Hello(vec![
                HelloOption::Holdtime(105),
                HelloOption::DrPriority(7),
                HelloOption::AddressList(vec![a(9)]),
            ]),
            Message::Register(Register { null: false, packet: inner_header(six) }),
            Message::RegisterStop { group: g, source: a(0) },
            Message::JoinPrune(JoinPrune {
                upstream: a(1),
                holdtime: 210,
                groups: vec![JoinPruneGroup {
                    group: g,
                    joins: vec![Source::single(a(2))],
                    prunes: vec![Source::single(a(3))],
                }],
            }),
            Message::Bootstrap(Bootstrap {
                no_forward: false,
                fragment_tag: 1,
                hash_mask_len: 30,
                priority: 1,
                bsr: a(5),
                groups: vec![BootstrapGroup {
                    group: g,
                    rp_count: 1,
                    rps: vec![BootstrapRp { address: a(7), holdtime: 150, priority: 1 }],
                }],
            }),
            Message::Assert(Assert { group: g, source: a(4), rpt: false, metric_preference: 1, metric: 2 }),
            Message::CandidateRp(CandidateRp { priority: 1, holdtime: 150, rp: a(7), groups: vec![g] }),
            Message::Other { kind: 9, body: vec![1, 2] },
        ]
    }

    #[test]
    fn every_truncated_prefix_fails() {
        for e in [v4_ends(), v6_ends()] {
            for m in samples(&e) {
                let b = m.to_bytes(&e).unwrap();
                for n in 0..b.len() {
                    // With the checksum set right for the prefix, so the
                    // parser reads the body.
                    let prefix = fix(b[..n].to_vec(), &e);
                    let got = Message::parse(&prefix, &e);
                    // Messages that run to the end of the bytes read a
                    // prefix as a shorter message. The rest must fail.
                    let open_ended = matches!(
                        m,
                        Message::Hello(_) | Message::Register(_) | Message::Bootstrap(_) | Message::Other { .. }
                    );
                    if let Ok(p) = &got {
                        assert!(open_ended && *p != m, "{m:?} at {n}");
                    }
                    assert_eq!(decode_chunked(&prefix, &e, 1), got);
                }
            }
        }
    }

    #[test]
    fn decoder_matches_parse() {
        let e = v4_ends();
        for m in samples(&e) {
            let b = m.to_bytes(&e).unwrap();
            for size in [1, 2, 3, 7, 1000] {
                assert_eq!(decode_chunked(&b, &e, size), Ok(m.clone()));
            }
        }
        // A bad version fails on the first byte, and stays failed.
        let mut d = Decoder::new(e);
        assert_eq!(d.feed(&[0x30]), Err(PimError::Version(3)));
        assert_eq!(d.feed(&[0x20]), Err(PimError::Version(3)));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.finish(), Err(PimError::Version(3)));
        // Too many bytes fail once past the limit, and the buffer stays
        // bounded. The limit is the packet's: smaller over IPv4.
        for (e, max) in [(e, MAX_MESSAGE_V4), (v6_ends(), MAX_MESSAGE)] {
            let mut d = Decoder::new(e);
            assert!(d.feed(&[0x26]).is_ok());
            assert!(d.feed(&vec![0; max - 1]).is_ok());
            assert_eq!(d.buffered(), max);
            assert_eq!(d.feed(&[0, 0]), Err(PimError::TooLong));
            assert_eq!(d.buffered(), 0);
        }
    }

    /// A random number source that also knows the packet's family.
    struct Lcg(u64, bool);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn coin(&mut self) -> bool {
            self.next() & 1 == 0
        }

        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }

        /// An address in the family of the packet.
        fn addr(&mut self) -> IpAddr {
            if !self.1 {
                IpAddr::V4(Ipv4Addr::from(self.next()))
            } else {
                let o: [u8; 16] = std::array::from_fn(|_| self.next() as u8);
                IpAddr::V6(Ipv6Addr::from(o))
            }
        }

        fn group(&mut self) -> Group {
            let address = self.addr();
            let mask_len = self.below(usize::from(full_mask(address)) + 1) as u8;
            Group { address, mask_len, bidirectional: self.coin(), zone: self.coin() }
        }

        /// A group with no Z bit, for messages outside the Bootstrap
        /// mechanism.
        fn plain_group(&mut self) -> Group {
            Group { zone: false, ..self.group() }
        }

        /// One multicast group with a full mask, for a Join/Prune.
        fn multicast_group(&mut self) -> Group {
            let address = match self.addr() {
                IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & 0x0fff_ffff | 0xe000_0000)),
                IpAddr::V6(a) => {
                    let mut o = a.octets();
                    o[0] = 0xff;
                    IpAddr::V6(Ipv6Addr::from(o))
                }
            };
            Group { address, mask_len: full_mask(address), bidirectional: self.coin(), zone: false }
        }

        /// A Bootstrap's groups: the first may have the Z bit, and in a
        /// scoped IPv6 fragment every group has a mask of at least 16 bits
        /// and the first group's scope.
        fn bootstrap_groups(&mut self) -> Vec<BootstrapGroup> {
            let mut groups: Vec<BootstrapGroup> = Vec::new();
            for i in 0..self.below(3) {
                let mut group = self.group();
                group.zone &= i == 0;
                if let Some(first) = groups.first()
                    && first.group.zone
                    && let (IpAddr::V6(f), IpAddr::V6(a)) = (first.group.address, group.address)
                {
                    let mut o = a.octets();
                    o[1] = (o[1] & 0xf0) | (f.octets()[1] & 0x0f);
                    group.address = IpAddr::V6(Ipv6Addr::from(o));
                }
                if group.address.is_ipv6() && (group.zone || groups.first().is_some_and(|f| f.group.zone)) {
                    group.mask_len = group.mask_len.max(16);
                }
                let rps: Vec<BootstrapRp> = (0..self.below(3))
                    .map(|_| BootstrapRp {
                        address: self.addr(),
                        holdtime: self.next() as u16,
                        priority: self.next() as u8,
                    })
                    .collect();
                let rp_count = (rps.len() + self.below(250)) as u8;
                groups.push(BootstrapGroup { group, rp_count, rps });
            }
            groups
        }

        fn source(&mut self) -> Source {
            let address = self.addr();
            let f = self.next();
            let wildcard = f & 2 != 0;
            Source { address, mask_len: full_mask(address), sparse: f & 1 != 0, wildcard, rpt: wildcard || f & 4 != 0 }
        }
    }

    fn random_message(rng: &mut Lcg) -> Message {
        match rng.below(8) {
            0 => {
                let options = (0..rng.below(5))
                    .map(|_| match rng.below(6) {
                        0 => HelloOption::Holdtime(rng.next() as u16),
                        1 => HelloOption::LanPruneDelay {
                            tracking: rng.coin(),
                            propagation_delay: rng.next() as u16 & 0x7fff,
                            override_interval: rng.next() as u16,
                        },
                        2 => HelloOption::DrPriority(rng.next()),
                        3 => HelloOption::GenerationId(rng.next()),
                        4 => HelloOption::AddressList((0..rng.below(4)).map(|_| rng.addr()).collect()),
                        _ => HelloOption::Other { kind: 100 + rng.next() as u16 % 100, value: vec![7; rng.below(9)] },
                    })
                    .collect();
                Message::Hello(options)
            }
            1 => Message::Register(Register {
                null: rng.coin(),
                packet: {
                    let mut p = inner_header(rng.1);
                    p.extend((0..rng.below(40)).map(|_| rng.next() as u8));
                    p
                },
            }),
            2 => Message::RegisterStop { group: rng.plain_group(), source: rng.addr() },
            3 => Message::JoinPrune(JoinPrune {
                upstream: rng.addr(),
                holdtime: rng.next() as u16,
                groups: (0..rng.below(4))
                    .map(|_| {
                        let group = rng.multicast_group();
                        let mut joins: Vec<Source> = (0..rng.below(3)).map(|_| rng.source()).collect();
                        let mut prunes: Vec<Source> = (0..rng.below(3)).map(|_| rng.source()).collect();
                        // At most one (*,G) entry across both lists.
                        let mut seen = false;
                        for s in joins.iter_mut().chain(prunes.iter_mut()) {
                            s.wildcard &= !seen;
                            seen |= s.wildcard;
                        }
                        JoinPruneGroup { group, joins, prunes }
                    })
                    .collect(),
            }),
            4 => {
                let bsr = rng.addr();
                Message::Bootstrap(Bootstrap {
                    no_forward: rng.coin(),
                    fragment_tag: rng.next() as u16,
                    hash_mask_len: rng.below(usize::from(full_mask(bsr)) + 1) as u8,
                    priority: rng.next() as u8,
                    bsr,
                    groups: rng.bootstrap_groups(),
                })
            }
            5 => Message::Assert(Assert {
                group: rng.plain_group(),
                source: rng.addr(),
                rpt: rng.coin(),
                metric_preference: rng.next() & MAX_METRIC_PREFERENCE,
                metric: rng.next(),
            }),
            6 => Message::CandidateRp(CandidateRp {
                priority: rng.next() as u8,
                holdtime: rng.next() as u16,
                rp: rng.addr(),
                groups: (0..1 + rng.below(4)).map(|_| rng.group()).collect(),
            }),
            _ => Message::Other { kind: [6, 7, 9, 15][rng.below(4)], body: vec![1; rng.below(10)] },
        }
    }

    /// What the fuzz target checks: parse and the decoder agree, whole and
    /// a byte at a time, and whatever parses, except a C-RP-Adv with no
    /// groups, writes back to bytes that read the same.
    fn check_bytes(data: &[u8], e: &Endpoints) {
        let parsed = Message::parse(data, e);
        assert_eq!(decode_chunked(data, e, data.len()), parsed);
        assert_eq!(decode_chunked(data, e, 1), parsed);
        if let Ok(m) = &parsed {
            assert!(data.len() <= e.max_message());
            if let Message::Bootstrap(b) = m {
                assert_eq!(b.no_forward, data[1] & 0x80 != 0);
            }
            // A C-RP-Adv with no groups is read but never written.
            if let Message::CandidateRp(CandidateRp { groups, .. }) = m
                && groups.is_empty()
            {
                assert_eq!(m.to_bytes(e), Err(PimError::Count));
                return;
            }
            let b = m.to_bytes(e).unwrap();
            assert_eq!(b.len(), data.len());
            assert_eq!(Message::parse(&b, e).as_ref(), Ok(m));
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x7761_0103_5059, false);
        let mut parsed = 0;
        for i in 0..6000 {
            rng.1 = i % 2 == 1;
            let e = if rng.1 { v6_ends() } else { v4_ends() };
            // Random messages round trip.
            let m = random_message(&mut rng);
            let b = round_trip(&m, &e);
            // Mutated, with the checksum set right so the body is read.
            let mut data = b.clone();
            for _ in 0..1 + rng.below(4) {
                match rng.below(3) {
                    0 if !data.is_empty() => {
                        let at = rng.below(data.len());
                        data[at] = rng.next() as u8;
                    }
                    1 if !data.is_empty() => data.truncate(rng.below(data.len())),
                    _ => data.push(rng.next() as u8),
                }
            }
            if !data.is_empty() {
                data[0] = (data[0] & 0x0f) | 0x20;
            }
            let data = fix(data, &e);
            check_bytes(&data, &e);
            parsed += usize::from(Message::parse(&data, &e).is_ok());
            // Pure noise, with and without a good checksum.
            let noise: Vec<u8> = (0..rng.below(64)).map(|_| rng.next() as u8).collect();
            check_bytes(&noise, &e);
            let mut noise = noise;
            if !noise.is_empty() {
                noise[0] = (noise[0] & 0x0f) | 0x20;
            }
            check_bytes(&fix(noise, &e), &e);
        }
        // The mutations leave enough messages whole to test the writers.
        assert!(parsed > 500, "{parsed}");
    }
}
