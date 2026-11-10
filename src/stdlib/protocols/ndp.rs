//! IPv6 neighbor discovery: reading and writing its five ICMPv6 messages
//! and their options, with no I/O.
//!
//! IPv6 has no ARP. Hosts and routers on a link find each other with five
//! ICMPv6 messages instead ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861)):
//!
//! - a router solicitation asks the routers on the link to announce
//!   themselves;
//! - a router advertisement is a router announcing itself, with the
//!   prefixes on the link, the link's MTU, and how long hosts may use it as
//!   their default router;
//! - a neighbor solicitation asks for the link-layer address of an IPv6
//!   address, or checks that the address is still reachable, or, from the
//!   unspecified address, checks that no other node uses an address before
//!   a host takes it (duplicate address detection, RFC 4862);
//! - a neighbor advertisement answers a solicitation, or announces a change
//!   of link-layer address;
//! - a redirect tells a host a better first hop for a destination.
//!
//! [`Message`] is one of them, read from the ICMPv6 message: the bytes
//! after the IPv6 header and any extension headers. Each message carries
//! [`NdOption`]s. Options this module does not know, such as the
//! recursive DNS server option of RFC 8106, are kept as their type and
//! bytes. Link-layer addresses are read as Ethernet MACs, the only layout
//! [RFC 2464](https://www.rfc-editor.org/rfc/rfc2464) section 8 defines for
//! Ethernet.
//!
//! Reading has two steps, as RFC 4861 lays out the checks a receiver makes
//! (sections 6.1.1, 6.1.2, 7.1.1, 7.1.2 and 8.1):
//!
//! - [`Message::parse`] checks what the message alone shows: a known type,
//!   code 0, the minimum length for the type, and options that each have a
//!   length that is not zero and fits. It does not check the checksum.
//! - [`Message::validate`] checks what needs the IPv6 header, given as an
//!   [`Envelope`]: hop limit 255, which shows the packet was not
//!   forwarded from another link, and the rules about addresses each type
//!   has.
//!
//! [`Message::receive`] checks the ICMPv6 checksum (RFC 4443 section 2.3)
//! and then does both steps. A reader that takes frames from a virtual
//! network card whose checksum the card was to fill in later can call
//! `parse` and `validate` and leave the checksum out.
//!
//! [`Message::emit`] writes the ICMPv6 message with its checksum, and
//! [`Message::packet`] the whole IPv6 packet with hop limit 255. Both
//! first check the message as `validate` would, so what they write reads
//! back. Reserved fields and flags this module does not name are ignored
//! when read and written as zero.
//!
//! ```
//! use std::net::Ipv6Addr;
//! use fictionet::stdlib::protocols::ndp::{
//!     Envelope, Message, NdOption, NeighborAdvertisement, NeighborSolicitation, solicited_node,
//! };
//!
//! // A host at fe80::2 asks who has fe80::1, from its MAC.
//! let host: Ipv6Addr = "fe80::2".parse().unwrap();
//! let router: Ipv6Addr = "fe80::1".parse().unwrap();
//! let ns = Message::NeighborSolicitation(NeighborSolicitation {
//!     target: router,
//!     options: vec![NdOption::SourceLinkLayer([0x52, 0x54, 0, 0, 0, 2])],
//! });
//! let to = solicited_node(router);
//! assert_eq!(to, "ff02::1:ff00:1".parse::<Ipv6Addr>().unwrap());
//! let bytes = ns.emit(host, to).unwrap();
//!
//! // The router reads it, and answers with its own MAC.
//! let envelope = Envelope { source: host, destination: to, hop_limit: 255 };
//! let Message::NeighborSolicitation(asked) = Message::receive(&envelope, &bytes).unwrap() else {
//!     unreachable!()
//! };
//! assert_eq!(asked.target, router);
//! let na = Message::NeighborAdvertisement(NeighborAdvertisement {
//!     router: true,
//!     solicited: true,
//!     overrides: true,
//!     target: asked.target,
//!     options: vec![NdOption::TargetLinkLayer([0x02, 0, 0, 0, 0, 1])],
//! });
//! let packet = na.packet(router, host).unwrap();
//! assert_eq!(packet[7], 255, "hop limit");
//! assert_eq!(Message::parse(&packet[40..]).unwrap(), na);
//! ```

use std::net::{IpAddr, Ipv6Addr};

use fictionet::stdlib::network::ethernet::frame::Mac;
use fictionet::stdlib::network::ip::{self, Fields, protocol};

/// The hop limit every neighbor discovery message is sent with, and the
/// only one a receiver accepts (RFC 4861, sections 6.1 to 8.1). A router
/// forwarding a packet lowers it, so a message with 255 came from the link.
pub const HOP_LIMIT: u8 = 255;
/// The all-nodes multicast address, ff02::1 (RFC 4291, section 2.7.1),
/// where unsolicited router advertisements go.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// The all-routers multicast address, ff02::2 (RFC 4291, section 2.7.1),
/// where router solicitations go.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// The longest message this module reads or writes: the most an IPv6
/// packet's 16-bit payload length can describe (RFC 8200, section 3).
pub const MAX_MESSAGE: usize = 65_535;

/// The ICMPv6 types of neighbor discovery (RFC 4861, section 4).
pub mod kind {
    /// Router solicitation.
    pub const ROUTER_SOLICITATION: u8 = 133;
    /// Router advertisement.
    pub const ROUTER_ADVERTISEMENT: u8 = 134;
    /// Neighbor solicitation.
    pub const NEIGHBOR_SOLICITATION: u8 = 135;
    /// Neighbor advertisement.
    pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
    /// Redirect.
    pub const REDIRECT: u8 = 137;
}

/// The option types RFC 4861 defines (section 4.6).
pub mod option {
    /// Source link-layer address.
    pub const SOURCE_LINK_LAYER: u8 = 1;
    /// Target link-layer address.
    pub const TARGET_LINK_LAYER: u8 = 2;
    /// Prefix information.
    pub const PREFIX_INFORMATION: u8 = 3;
    /// Redirected header.
    pub const REDIRECTED_HEADER: u8 = 4;
    /// MTU.
    pub const MTU: u8 = 5;
}

/// The solicited-node multicast address of `addr`: ff02::1:ff00:0/104
/// with the low 24 bits of `addr` (RFC 4291, section 2.7.1). A node joins
/// it for each of its addresses, and a neighbor solicitation for an address
/// goes there, so only the few nodes that share those 24 bits hear it.
pub fn solicited_node(addr: Ipv6Addr) -> Ipv6Addr {
    let a = addr.octets();
    Ipv6Addr::from([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, a[13], a[14], a[15],
    ])
}

/// One neighbor discovery message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Message {
    /// A router solicitation (RFC 4861, section 4.1).
    RouterSolicitation(RouterSolicitation),
    /// A router advertisement (RFC 4861, section 4.2).
    RouterAdvertisement(RouterAdvertisement),
    /// A neighbor solicitation (RFC 4861, section 4.3).
    NeighborSolicitation(NeighborSolicitation),
    /// A neighbor advertisement (RFC 4861, section 4.4).
    NeighborAdvertisement(NeighborAdvertisement),
    /// A redirect (RFC 4861, section 4.5).
    Redirect(Redirect),
}

/// A router solicitation: a host asking the routers on the link to send a
/// router advertisement now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouterSolicitation {
    /// The options: usually the host's source link-layer address, which
    /// must be left out when the host sends from the unspecified address.
    pub options: Vec<NdOption>,
}

/// A router advertisement: a router announcing itself and the link.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RouterAdvertisement {
    /// The hop limit hosts should put on the packets they send, or 0 for
    /// no advice.
    pub cur_hop_limit: u8,
    /// The M flag: addresses come from DHCPv6.
    pub managed: bool,
    /// The O flag: other configuration, such as DNS servers, comes from
    /// DHCPv6.
    pub other: bool,
    /// How long, in seconds, hosts may use the router as a default router.
    /// 0 means it is not a default router.
    pub router_lifetime: u16,
    /// How long, in milliseconds, a neighbor counts as reachable after
    /// a sign that it is, or 0 for no advice.
    pub reachable_time: u32,
    /// How long, in milliseconds, to wait between neighbor solicitations
    /// that get no answer, or 0 for no advice.
    pub retrans_timer: u32,
    /// The options: the router's source link-layer address, the link's
    /// MTU, and prefix information, for example.
    pub options: Vec<NdOption>,
}

/// A neighbor solicitation: a node asking for the link-layer address of
/// `target`, or checking that it is still reachable.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NeighborSolicitation {
    /// The address asked about. Never multicast.
    pub target: Ipv6Addr,
    /// The options: usually the sender's source link-layer address, which
    /// must be left out in duplicate address detection.
    pub options: Vec<NdOption>,
}

/// A neighbor advertisement: the link-layer address of `target`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NeighborAdvertisement {
    /// The R flag: the sender is a router.
    pub router: bool,
    /// The S flag: this answers a solicitation. Never set when sent to a
    /// multicast address.
    pub solicited: bool,
    /// The O flag: the receiver should replace a link-layer address it
    /// already has for `target` with this one.
    pub overrides: bool,
    /// The address advertised: the target of the solicitation this
    /// answers, or the address whose link-layer address changed. Never
    /// multicast.
    pub target: Ipv6Addr,
    /// The options: usually the target link-layer address.
    pub options: Vec<NdOption>,
}

/// A redirect: a router telling a host that `target` is a better first
/// hop for `destination`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Redirect {
    /// The better first hop: a link-local address of a router, or
    /// `destination` itself when the destination is on the link.
    pub target: Ipv6Addr,
    /// The destination the redirect is about. Never multicast.
    pub destination: Ipv6Addr,
    /// The options: usually the target link-layer address and the
    /// redirected header.
    pub options: Vec<NdOption>,
}

/// One neighbor discovery option (RFC 4861, section 4.6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NdOption {
    /// The sender's link-layer address (type 1).
    SourceLinkLayer(Mac),
    /// The target's link-layer address (type 2).
    TargetLinkLayer(Mac),
    /// A prefix on the link, or one to make addresses from (type 3).
    PrefixInformation(PrefixInformation),
    /// The start of the packet a redirect is about (type 4): its IPv6
    /// header and as much of the rest as fits. Read with the zero bytes
    /// that pad the option to a multiple of 8, and padded so when written.
    RedirectedHeader(Vec<u8>),
    /// The link's MTU, in bytes (type 5).
    Mtu(u32),
    /// An option of a type this module does not read: its type, and the
    /// bytes after its type and length fields. A writer refuses one of the
    /// types above, which would read back as that type, and one whose
    /// bytes plus 2 are not a multiple of 8.
    Unknown {
        /// The option type.
        kind: u8,
        /// The bytes after the type and length fields.
        data: Vec<u8>,
    },
}

/// The prefix information option (RFC 4861, section 4.6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrefixInformation {
    /// How many leading bits of `prefix` count. RFC 4861 allows 0 to 128;
    /// a larger value is kept as read, for the receiver to ignore the
    /// option as RFC 4862 section 5.5.3 says.
    pub prefix_len: u8,
    /// The L flag: addresses in the prefix are on the link.
    pub on_link: bool,
    /// The A flag: hosts may make addresses in the prefix themselves
    /// (RFC 4862).
    pub autonomous: bool,
    /// How long, in seconds, the prefix counts as on the link.
    /// `u32::MAX` is forever.
    pub valid_lifetime: u32,
    /// How long, in seconds, addresses made in the prefix stay preferred.
    /// `u32::MAX` is forever.
    pub preferred_lifetime: u32,
    /// The prefix. Bits past `prefix_len` should be zero.
    pub prefix: Ipv6Addr,
}

/// The fields of the IPv6 header that carried a message, which
/// [`Message::validate`] checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Envelope {
    /// The IPv6 source address.
    pub source: Ipv6Addr,
    /// The IPv6 destination address.
    pub destination: Ipv6Addr,
    /// The IPv6 hop limit.
    pub hop_limit: u8,
}

impl Envelope {
    /// The envelope in an IPv6 header: `None` if `packet` is shorter than
    /// a header or is not IPv6.
    pub fn of(packet: &[u8]) -> Option<Envelope> {
        if packet.len() < 40 || packet[0] >> 4 != 6 {
            return None;
        }
        let addr = |at: usize| Ipv6Addr::from(<[u8; 16]>::try_from(&packet[at..at + 16]).unwrap());
        Some(Envelope {
            source: addr(8),
            destination: addr(24),
            hop_limit: packet[7],
        })
    }
}

/// Why bytes are not a valid neighbor discovery message, or why a message
/// cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The bytes end before the message's fixed fields, or an option runs
    /// past the end.
    Truncated,
    /// The message is longer than [`MAX_MESSAGE`].
    TooLong,
    /// The ICMPv6 type is not one of neighbor discovery's.
    UnknownType(u8),
    /// The ICMPv6 code is not 0.
    Code(u8),
    /// The ICMPv6 checksum is wrong.
    Checksum,
    /// An option has length 0, which RFC 4861 section 4.6 says makes a
    /// receiver discard the whole message.
    ZeroLengthOption,
    /// A known option has a length its layout does not allow.
    OptionLength {
        /// The option type.
        kind: u8,
        /// The option's length field, in units of 8 bytes.
        units: u8,
    },
    /// The hop limit is not [`HOP_LIMIT`].
    HopLimit(u8),
    /// The source address is wrong for the message: not link-local for a
    /// router advertisement or a redirect.
    Source(Ipv6Addr),
    /// A message from the unspecified address carries a source link-layer
    /// address option.
    SourceLinkLayerFromUnspecified,
    /// The destination address is wrong for the message: not a
    /// solicited-node address for a neighbor solicitation from the
    /// unspecified address, or multicast in a redirect's destination field.
    Destination(Ipv6Addr),
    /// The target address is wrong for the message: multicast in a neighbor
    /// solicitation or advertisement, or, in a redirect, neither link-local
    /// nor the redirect's destination.
    Target(Ipv6Addr),
    /// A neighbor advertisement to a multicast address has the solicited
    /// flag set.
    SolicitedToMulticast,
    /// A value cannot be written without changing it: an unknown option
    /// of a known type or with a length that is not a multiple of 8, or an
    /// option longer than its 8-bit length field can describe.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("neighbor discovery message cut short"),
            Error::TooLong => write!(f, "neighbor discovery message over {MAX_MESSAGE} bytes"),
            Error::UnknownType(t) => write!(f, "ICMPv6 type {t} is not neighbor discovery"),
            Error::Code(c) => write!(f, "neighbor discovery message with code {c}"),
            Error::Checksum => f.write_str("wrong ICMPv6 checksum"),
            Error::ZeroLengthOption => f.write_str("neighbor discovery option of length 0"),
            Error::OptionLength { kind, units } => write!(
                f,
                "neighbor discovery option {kind} cannot be {units} units of 8 bytes"
            ),
            Error::HopLimit(h) => write!(f, "neighbor discovery message with hop limit {h}"),
            Error::Source(a) => write!(f, "neighbor discovery message from {a}"),
            Error::SourceLinkLayerFromUnspecified => {
                f.write_str("source link-layer address option from the unspecified address")
            }
            Error::Destination(a) => write!(f, "neighbor discovery message to {a}"),
            Error::Target(a) => write!(f, "neighbor discovery target {a}"),
            Error::SolicitedToMulticast => {
                f.write_str("solicited neighbor advertisement to a multicast address")
            }
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
        }
    }
}

impl std::error::Error for Error {}

impl Message {
    /// The message's ICMPv6 type, one of the [`kind`] values.
    pub fn kind(&self) -> u8 {
        match self {
            Message::RouterSolicitation(_) => kind::ROUTER_SOLICITATION,
            Message::RouterAdvertisement(_) => kind::ROUTER_ADVERTISEMENT,
            Message::NeighborSolicitation(_) => kind::NEIGHBOR_SOLICITATION,
            Message::NeighborAdvertisement(_) => kind::NEIGHBOR_ADVERTISEMENT,
            Message::Redirect(_) => kind::REDIRECT,
        }
    }

    /// The message's options.
    pub fn options(&self) -> &[NdOption] {
        match self {
            Message::RouterSolicitation(m) => &m.options,
            Message::RouterAdvertisement(m) => &m.options,
            Message::NeighborSolicitation(m) => &m.options,
            Message::NeighborAdvertisement(m) => &m.options,
            Message::Redirect(m) => &m.options,
        }
    }

    /// The first source link-layer address option, if there is one.
    pub fn source_link_layer(&self) -> Option<Mac> {
        self.options().iter().find_map(|o| match o {
            NdOption::SourceLinkLayer(mac) => Some(*mac),
            _ => None,
        })
    }

    /// The first target link-layer address option, if there is one.
    pub fn target_link_layer(&self) -> Option<Mac> {
        self.options().iter().find_map(|o| match o {
            NdOption::TargetLinkLayer(mac) => Some(*mac),
            _ => None,
        })
    }

    /// Reads a message from the ICMPv6 bytes alone. Checks the type, code
    /// 0, the type's minimum length, and every option's length; leaves the
    /// checksum and the IPv6 header to [`Message::receive`] and
    /// [`Message::validate`].
    pub fn parse(msg: &[u8]) -> Result<Message, Error> {
        if msg.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let &t = msg.first().ok_or(Error::Truncated)?;
        let fixed = match t {
            kind::ROUTER_SOLICITATION => 8,
            kind::ROUTER_ADVERTISEMENT => 16,
            kind::NEIGHBOR_SOLICITATION | kind::NEIGHBOR_ADVERTISEMENT => 24,
            kind::REDIRECT => 40,
            t => return Err(Error::UnknownType(t)),
        };
        if msg.len() < fixed {
            return Err(Error::Truncated);
        }
        if msg[1] != 0 {
            return Err(Error::Code(msg[1]));
        }
        let options = parse_options(&msg[fixed..])?;
        let addr = |at: usize| Ipv6Addr::from(<[u8; 16]>::try_from(&msg[at..at + 16]).unwrap());
        let be32 = |at: usize| u32::from_be_bytes(msg[at..at + 4].try_into().unwrap());
        Ok(match t {
            kind::ROUTER_SOLICITATION => {
                Message::RouterSolicitation(RouterSolicitation { options })
            }
            kind::ROUTER_ADVERTISEMENT => Message::RouterAdvertisement(RouterAdvertisement {
                cur_hop_limit: msg[4],
                managed: msg[5] & 0x80 != 0,
                other: msg[5] & 0x40 != 0,
                router_lifetime: u16::from_be_bytes([msg[6], msg[7]]),
                reachable_time: be32(8),
                retrans_timer: be32(12),
                options,
            }),
            kind::NEIGHBOR_SOLICITATION => Message::NeighborSolicitation(NeighborSolicitation {
                target: addr(8),
                options,
            }),
            kind::NEIGHBOR_ADVERTISEMENT => Message::NeighborAdvertisement(NeighborAdvertisement {
                router: msg[4] & 0x80 != 0,
                solicited: msg[4] & 0x40 != 0,
                overrides: msg[4] & 0x20 != 0,
                target: addr(8),
                options,
            }),
            _ => Message::Redirect(Redirect {
                target: addr(8),
                destination: addr(24),
                options,
            }),
        })
    }

    /// Checks the rules RFC 4861 gives a receiver that need the IPv6
    /// header: hop limit 255 for every message, and for each type:
    ///
    /// - a router or neighbor solicitation from the unspecified address
    ///   carries no source link-layer address option (sections 6.1.1 and
    ///   7.1.1), and a neighbor solicitation from it goes to a
    ///   solicited-node address (section 7.1.1);
    /// - a router advertisement comes from a link-local address (section
    ///   6.1.2);
    /// - a neighbor solicitation's or advertisement's target is not
    ///   multicast, and an advertisement to a multicast address does not
    ///   have the solicited flag (section 7.1.2);
    /// - a redirect comes from a link-local address, its destination is not
    ///   multicast, and its target is link-local or the destination
    ///   (section 8.1).
    ///
    /// Whether a redirect came from the host's current first hop is up to
    /// the caller, which knows it.
    pub fn validate(&self, envelope: &Envelope) -> Result<(), Error> {
        if envelope.hop_limit != HOP_LIMIT {
            return Err(Error::HopLimit(envelope.hop_limit));
        }
        let from_unspecified = envelope.source.is_unspecified();
        let link_local_source = || {
            if envelope.source.is_unicast_link_local() {
                Ok(())
            } else {
                Err(Error::Source(envelope.source))
            }
        };
        let no_source_link_layer = || {
            if from_unspecified && self.source_link_layer().is_some() {
                Err(Error::SourceLinkLayerFromUnspecified)
            } else {
                Ok(())
            }
        };
        match self {
            Message::RouterSolicitation(_) => no_source_link_layer(),
            Message::RouterAdvertisement(_) => link_local_source(),
            Message::NeighborSolicitation(ns) => {
                if ns.target.is_multicast() {
                    return Err(Error::Target(ns.target));
                }
                if from_unspecified && envelope.destination != solicited_node(envelope.destination)
                {
                    return Err(Error::Destination(envelope.destination));
                }
                no_source_link_layer()
            }
            Message::NeighborAdvertisement(na) => {
                if na.target.is_multicast() {
                    return Err(Error::Target(na.target));
                }
                if na.solicited && envelope.destination.is_multicast() {
                    return Err(Error::SolicitedToMulticast);
                }
                Ok(())
            }
            Message::Redirect(r) => {
                link_local_source()?;
                if r.destination.is_multicast() {
                    return Err(Error::Destination(r.destination));
                }
                if !r.target.is_unicast_link_local() && r.target != r.destination {
                    return Err(Error::Target(r.target));
                }
                Ok(())
            }
        }
    }

    /// Reads a message as a receiver must: checks the ICMPv6 checksum over
    /// the pseudo-header of `envelope` (RFC 4443, section 2.3), then
    /// [`parse`](Message::parse)s and [`validate`](Message::validate)s it.
    pub fn receive(envelope: &Envelope, msg: &[u8]) -> Result<Message, Error> {
        if msg.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let sum = ip::transport_checksum(
            envelope.source.into(),
            envelope.destination.into(),
            protocol::ICMPV6,
            msg,
        );
        if sum != 0 {
            return Err(Error::Checksum);
        }
        let message = Message::parse(msg)?;
        message.validate(envelope)?;
        Ok(message)
    }

    /// The ICMPv6 message from `source` to `destination`, with its
    /// checksum filled in. Fails if the message breaks a rule
    /// [`validate`](Message::validate) checks, an option cannot be written,
    /// or the message is longer than [`MAX_MESSAGE`].
    pub fn emit(&self, source: Ipv6Addr, destination: Ipv6Addr) -> Result<Vec<u8>, Error> {
        self.validate(&Envelope {
            source,
            destination,
            hop_limit: HOP_LIMIT,
        })?;
        let mut out = Vec::new();
        out.extend_from_slice(&[self.kind(), 0, 0, 0]);
        match self {
            Message::RouterSolicitation(_) => out.extend_from_slice(&[0; 4]),
            Message::RouterAdvertisement(ra) => {
                out.push(ra.cur_hop_limit);
                out.push(if ra.managed { 0x80 } else { 0 } | if ra.other { 0x40 } else { 0 });
                out.extend_from_slice(&ra.router_lifetime.to_be_bytes());
                out.extend_from_slice(&ra.reachable_time.to_be_bytes());
                out.extend_from_slice(&ra.retrans_timer.to_be_bytes());
            }
            Message::NeighborSolicitation(ns) => {
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&ns.target.octets());
            }
            Message::NeighborAdvertisement(na) => {
                out.push(
                    if na.router { 0x80 } else { 0 }
                        | if na.solicited { 0x40 } else { 0 }
                        | if na.overrides { 0x20 } else { 0 },
                );
                out.extend_from_slice(&[0; 3]);
                out.extend_from_slice(&na.target.octets());
            }
            Message::Redirect(r) => {
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&r.target.octets());
                out.extend_from_slice(&r.destination.octets());
            }
        }
        for o in self.options() {
            o.write(&mut out)?;
            if out.len() > MAX_MESSAGE {
                return Err(Error::TooLong);
            }
        }
        let sum = ip::transport_checksum(
            IpAddr::V6(source),
            IpAddr::V6(destination),
            protocol::ICMPV6,
            &out,
        );
        out[2..4].copy_from_slice(&sum.to_be_bytes());
        Ok(out)
    }

    /// The whole IPv6 packet from `source` to `destination`, with hop
    /// limit 255, carrying [`emit`](Message::emit)'s bytes.
    pub fn packet(&self, source: Ipv6Addr, destination: Ipv6Addr) -> Result<Vec<u8>, Error> {
        let msg = self.emit(source, destination)?;
        Ok(ip::packet_with(
            source.into(),
            destination.into(),
            protocol::ICMPV6,
            Fields {
                ttl: HOP_LIMIT,
                ..Fields::default()
            },
            &msg,
        )
        .into_vec())
    }
}

/// Reads the options that fill `b`.
fn parse_options(mut b: &[u8]) -> Result<Vec<NdOption>, Error> {
    let mut options = Vec::new();
    while !b.is_empty() {
        if b.len() < 2 {
            return Err(Error::Truncated);
        }
        let (kind, units) = (b[0], b[1]);
        if units == 0 {
            return Err(Error::ZeroLengthOption);
        }
        let len = usize::from(units) * 8;
        let o = b.get(..len).ok_or(Error::Truncated)?;
        let length = Error::OptionLength { kind, units };
        options.push(match kind {
            option::SOURCE_LINK_LAYER | option::TARGET_LINK_LAYER => {
                if units != 1 {
                    return Err(length);
                }
                let mac: Mac = o[2..8].try_into().unwrap();
                if kind == option::SOURCE_LINK_LAYER {
                    NdOption::SourceLinkLayer(mac)
                } else {
                    NdOption::TargetLinkLayer(mac)
                }
            }
            option::PREFIX_INFORMATION => {
                if units != 4 {
                    return Err(length);
                }
                let be32 = |at: usize| u32::from_be_bytes(o[at..at + 4].try_into().unwrap());
                NdOption::PrefixInformation(PrefixInformation {
                    prefix_len: o[2],
                    on_link: o[3] & 0x80 != 0,
                    autonomous: o[3] & 0x40 != 0,
                    valid_lifetime: be32(4),
                    preferred_lifetime: be32(8),
                    prefix: Ipv6Addr::from(<[u8; 16]>::try_from(&o[16..32]).unwrap()),
                })
            }
            // Six reserved bytes, then the start of the redirected packet.
            option::REDIRECTED_HEADER => NdOption::RedirectedHeader(o[8..].to_vec()),
            option::MTU => {
                if units != 1 {
                    return Err(length);
                }
                NdOption::Mtu(u32::from_be_bytes(o[4..8].try_into().unwrap()))
            }
            kind => NdOption::Unknown {
                kind,
                data: o[2..].to_vec(),
            },
        });
        b = &b[len..];
    }
    Ok(options)
}

impl NdOption {
    /// The option's type, one of the [`option`] values for a known option.
    pub fn kind(&self) -> u8 {
        match self {
            NdOption::SourceLinkLayer(_) => option::SOURCE_LINK_LAYER,
            NdOption::TargetLinkLayer(_) => option::TARGET_LINK_LAYER,
            NdOption::PrefixInformation(_) => option::PREFIX_INFORMATION,
            NdOption::RedirectedHeader(_) => option::REDIRECTED_HEADER,
            NdOption::Mtu(_) => option::MTU,
            NdOption::Unknown { kind, .. } => *kind,
        }
    }

    /// Appends the option, type and length fields included. Leaves `out`
    /// unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        // The option's whole length in bytes, a multiple of 8.
        let len = match self {
            NdOption::SourceLinkLayer(_) | NdOption::TargetLinkLayer(_) | NdOption::Mtu(_) => 8,
            NdOption::PrefixInformation(_) => 32,
            NdOption::RedirectedHeader(data) => 8 + data.len().div_ceil(8) * 8,
            NdOption::Unknown { kind, data } => {
                if (option::SOURCE_LINK_LAYER..=option::MTU).contains(kind)
                    || (data.len() + 2) % 8 != 0
                {
                    return Err(Error::Unwritable);
                }
                data.len() + 2
            }
        };
        let units = u8::try_from(len / 8).map_err(|_| Error::Unwritable)?;
        out.push(self.kind());
        out.push(units);
        match self {
            NdOption::SourceLinkLayer(mac) | NdOption::TargetLinkLayer(mac) => {
                out.extend_from_slice(mac)
            }
            NdOption::PrefixInformation(p) => {
                out.push(p.prefix_len);
                out.push(if p.on_link { 0x80 } else { 0 } | if p.autonomous { 0x40 } else { 0 });
                out.extend_from_slice(&p.valid_lifetime.to_be_bytes());
                out.extend_from_slice(&p.preferred_lifetime.to_be_bytes());
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&p.prefix.octets());
            }
            NdOption::RedirectedHeader(data) => {
                out.extend_from_slice(&[0; 6]);
                out.extend_from_slice(data);
                out.resize(out.len() + (len - 8 - data.len()), 0);
            }
            NdOption::Mtu(mtu) => {
                out.extend_from_slice(&[0; 2]);
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            NdOption::Unknown { data, .. } => out.extend_from_slice(data),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_MAC: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const ROUTER_MAC: Mac = [0x74, 0x83, 0xc2, 0x9a, 0x47, 0xd1];

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn envelope(source: &str, destination: &str) -> Envelope {
        Envelope {
            source: addr(source),
            destination: addr(destination),
            hop_limit: 255,
        }
    }

    /// Fills in the checksum of a message laid out by hand.
    fn checksummed(env: &Envelope, mut msg: Vec<u8>) -> Vec<u8> {
        let sum = ip::transport_checksum(
            env.source.into(),
            env.destination.into(),
            protocol::ICMPV6,
            &msg,
        );
        msg[2..4].copy_from_slice(&sum.to_be_bytes());
        msg
    }

    /// One message of each type, with every option type, and the envelope
    /// it is valid in.
    fn samples() -> Vec<(Envelope, Message)> {
        vec![
            (
                envelope("fe80::2", "ff02::2"),
                Message::RouterSolicitation(RouterSolicitation {
                    options: vec![NdOption::SourceLinkLayer(HOST_MAC)],
                }),
            ),
            (
                envelope("::", "ff02::2"),
                Message::RouterSolicitation(RouterSolicitation { options: vec![] }),
            ),
            (
                envelope("fe80::1", "ff02::1"),
                Message::RouterAdvertisement(RouterAdvertisement {
                    cur_hop_limit: 64,
                    managed: true,
                    other: false,
                    router_lifetime: 1800,
                    reachable_time: 30_000,
                    retrans_timer: 1000,
                    options: vec![
                        NdOption::SourceLinkLayer(ROUTER_MAC),
                        NdOption::Mtu(1500),
                        NdOption::PrefixInformation(PrefixInformation {
                            prefix_len: 64,
                            on_link: true,
                            autonomous: true,
                            valid_lifetime: 2_592_000,
                            preferred_lifetime: 604_800,
                            prefix: addr("2001:db8:1::"),
                        }),
                        NdOption::Unknown {
                            kind: 25,
                            data: [
                                vec![0, 0, 0, 0, 0x0e, 0x10],
                                addr("2001:db8::53").octets().to_vec(),
                            ]
                            .concat(),
                        },
                    ],
                }),
            ),
            (
                envelope("fe80::2", "ff02::1:ff00:1"),
                Message::NeighborSolicitation(NeighborSolicitation {
                    target: addr("fe80::1"),
                    options: vec![NdOption::SourceLinkLayer(HOST_MAC)],
                }),
            ),
            (
                envelope("::", "ff02::1:ff00:2"),
                Message::NeighborSolicitation(NeighborSolicitation {
                    target: addr("2001:db8::2"),
                    options: vec![],
                }),
            ),
            (
                envelope("fe80::1", "fe80::2"),
                Message::NeighborAdvertisement(NeighborAdvertisement {
                    router: true,
                    solicited: true,
                    overrides: false,
                    target: addr("fe80::1"),
                    options: vec![NdOption::TargetLinkLayer(ROUTER_MAC)],
                }),
            ),
            (
                envelope("fe80::1", "fe80::2"),
                Message::Redirect(Redirect {
                    target: addr("fe80::3"),
                    destination: addr("2001:db8::99"),
                    options: vec![
                        NdOption::TargetLinkLayer([2, 0, 0, 0, 0, 3]),
                        NdOption::RedirectedHeader(vec![0x60; 48]),
                    ],
                }),
            ),
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for (env, m) in samples() {
            let bytes = m.emit(env.source, env.destination).unwrap();
            assert_eq!(Message::parse(&bytes), Ok(m.clone()));
            assert_eq!(Message::receive(&env, &bytes), Ok(m.clone()));
            let packet = m.packet(env.source, env.destination).unwrap();
            assert_eq!(Envelope::of(&packet), Some(env));
            assert_eq!(packet[6], protocol::ICMPV6);
            assert_eq!(&packet[40..], &bytes[..]);
        }
    }

    #[test]
    fn a_neighbor_solicitation_from_its_layout() {
        // RFC 4861 section 4.3: type, code, checksum, reserved, target,
        // then a source link-layer address option (section 4.6.1).
        let env = envelope("fe80::2", "ff02::1:ff00:1");
        let mut msg = vec![135, 0, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(&addr("fe80::1").octets());
        msg.extend_from_slice(&[1, 1]);
        msg.extend_from_slice(&HOST_MAC);
        let msg = checksummed(&env, msg);
        let expected = Message::NeighborSolicitation(NeighborSolicitation {
            target: addr("fe80::1"),
            options: vec![NdOption::SourceLinkLayer(HOST_MAC)],
        });
        assert_eq!(Message::receive(&env, &msg), Ok(expected.clone()));
        assert_eq!(expected.emit(env.source, env.destination).unwrap(), msg);
    }

    #[test]
    fn a_neighbor_advertisement_from_its_layout() {
        // RFC 4861 section 4.4: flags R, S and O are the top three bits of
        // the first word after the checksum.
        let env = envelope("fe80::1", "fe80::2");
        let mut msg = vec![136, 0, 0, 0, 0xe0, 0, 0, 0];
        msg.extend_from_slice(&addr("fe80::1").octets());
        msg.extend_from_slice(&[2, 1]);
        msg.extend_from_slice(&ROUTER_MAC);
        let msg = checksummed(&env, msg);
        let expected = Message::NeighborAdvertisement(NeighborAdvertisement {
            router: true,
            solicited: true,
            overrides: true,
            target: addr("fe80::1"),
            options: vec![NdOption::TargetLinkLayer(ROUTER_MAC)],
        });
        assert_eq!(Message::receive(&env, &msg), Ok(expected.clone()));
        assert_eq!(expected.emit(env.source, env.destination).unwrap(), msg);
    }

    #[test]
    fn a_router_advertisement_from_its_layout() {
        // RFC 4861 section 4.2, with an MTU option (4.6.4) and prefix
        // information (4.6.2).
        let env = envelope("fe80::1", "ff02::1");
        let mut msg = vec![134, 0, 0, 0, 64, 0x40, 0x07, 0x08];
        msg.extend_from_slice(&30_000u32.to_be_bytes());
        msg.extend_from_slice(&1_000u32.to_be_bytes());
        msg.extend_from_slice(&[5, 1, 0, 0]);
        msg.extend_from_slice(&1500u32.to_be_bytes());
        msg.extend_from_slice(&[3, 4, 64, 0xc0]);
        msg.extend_from_slice(&86_400u32.to_be_bytes());
        msg.extend_from_slice(&14_400u32.to_be_bytes());
        msg.extend_from_slice(&[0; 4]);
        msg.extend_from_slice(&addr("2001:db8::").octets());
        let msg = checksummed(&env, msg);
        let expected = Message::RouterAdvertisement(RouterAdvertisement {
            cur_hop_limit: 64,
            managed: false,
            other: true,
            router_lifetime: 1800,
            reachable_time: 30_000,
            retrans_timer: 1000,
            options: vec![
                NdOption::Mtu(1500),
                NdOption::PrefixInformation(PrefixInformation {
                    prefix_len: 64,
                    on_link: true,
                    autonomous: true,
                    valid_lifetime: 86_400,
                    preferred_lifetime: 14_400,
                    prefix: addr("2001:db8::"),
                }),
            ],
        });
        assert_eq!(Message::receive(&env, &msg), Ok(expected.clone()));
        assert_eq!(expected.emit(env.source, env.destination).unwrap(), msg);
    }

    #[test]
    fn a_router_solicitation_and_a_redirect_from_their_layouts() {
        // RFC 4861 section 4.1: four reserved bytes, then options.
        let env = envelope("fe80::2", "ff02::2");
        let mut rs = vec![133, 0, 0, 0, 0, 0, 0, 0, 1, 1];
        rs.extend_from_slice(&HOST_MAC);
        let rs = checksummed(&env, rs);
        assert_eq!(
            Message::receive(&env, &rs),
            Ok(Message::RouterSolicitation(RouterSolicitation {
                options: vec![NdOption::SourceLinkLayer(HOST_MAC)],
            }))
        );
        // Section 4.5, with a redirected header option (4.6.3): type,
        // length, six reserved bytes, then the packet.
        let env = envelope("fe80::1", "fe80::2");
        let mut redirect = vec![137, 0, 0, 0, 0, 0, 0, 0];
        redirect.extend_from_slice(&addr("fe80::3").octets());
        redirect.extend_from_slice(&addr("2001:db8::99").octets());
        redirect.extend_from_slice(&[4, 2, 0, 0, 0, 0, 0, 0]);
        redirect.extend_from_slice(&[0x60, 0, 0, 0, 0, 0, 59, 64]);
        let redirect = checksummed(&env, redirect);
        let expected = Message::Redirect(Redirect {
            target: addr("fe80::3"),
            destination: addr("2001:db8::99"),
            options: vec![NdOption::RedirectedHeader(vec![
                0x60, 0, 0, 0, 0, 0, 59, 64,
            ])],
        });
        assert_eq!(Message::receive(&env, &redirect), Ok(expected.clone()));
        assert_eq!(
            expected.emit(env.source, env.destination).unwrap(),
            redirect
        );
    }

    #[test]
    fn reserved_bits_are_ignored_and_written_as_zero() {
        let env = envelope("fe80::1", "fe80::2");
        let mut msg = vec![136, 0, 0, 0, 0x1f, 0xff, 0xff, 0xff];
        msg.extend_from_slice(&addr("fe80::1").octets());
        let msg = checksummed(&env, msg);
        let m = Message::receive(&env, &msg).unwrap();
        assert_eq!(
            m,
            Message::NeighborAdvertisement(NeighborAdvertisement {
                router: false,
                solicited: false,
                overrides: false,
                target: addr("fe80::1"),
                options: vec![],
            })
        );
        assert_eq!(&m.emit(env.source, env.destination).unwrap()[4..8], &[0; 4]);
    }

    #[test]
    fn every_truncation_fails_without_panicking() {
        for (env, m) in samples() {
            let bytes = m.emit(env.source, env.destination).unwrap();
            let fixed = match m.kind() {
                kind::ROUTER_SOLICITATION => 8,
                kind::ROUTER_ADVERTISEMENT => 16,
                kind::REDIRECT => 40,
                _ => 24,
            };
            for len in 0..bytes.len() {
                let cut = &bytes[..len];
                match Message::parse(cut) {
                    // Cut between options, the message reads with fewer.
                    Ok(read) => {
                        assert!(len >= fixed, "{m:?} cut to {len}");
                        assert!(read.options().len() < m.options().len());
                        let again = read.emit(env.source, env.destination).unwrap();
                        assert_eq!(&again[4..], &cut[4..]);
                    }
                    Err(e) if len < fixed => assert_eq!(e, Error::Truncated),
                    Err(_) => {}
                }
                assert!(Message::receive(&env, cut).is_err());
            }
            assert!(Envelope::of(&m.packet(env.source, env.destination).unwrap()[..39]).is_none());
        }
    }

    #[test]
    fn every_byte_value_at_every_position_reads_or_fails_cleanly() {
        for (env, m) in samples() {
            let bytes = m.emit(env.source, env.destination).unwrap();
            for at in 0..bytes.len() {
                for value in [0, 1, 2, 3, 4, 5, 0x7f, 0x80, 0xff] {
                    let mut b = bytes.clone();
                    b[at] = value;
                    if let Ok(read) = Message::parse(&b) {
                        // Whatever reads must write again, unless it now
                        // breaks an address rule.
                        if read.validate(&env).is_ok() {
                            let again = read.emit(env.source, env.destination).unwrap();
                            assert_eq!(Message::parse(&again), Ok(read));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_message_alone_is_checked_by_parse() {
        let ns = |rest: &[u8]| {
            let mut m = vec![135, 0, 0, 0, 0, 0, 0, 0];
            m.extend_from_slice(&addr("fe80::1").octets());
            m.extend_from_slice(rest);
            m
        };
        assert_eq!(
            Message::parse(&[128, 0, 0, 0]),
            Err(Error::UnknownType(128))
        );
        assert_eq!(Message::parse(&[]), Err(Error::Truncated));
        let mut code = ns(&[]);
        code[1] = 1;
        assert_eq!(Message::parse(&code), Err(Error::Code(1)));
        assert_eq!(Message::parse(&ns(&[1, 0])), Err(Error::ZeroLengthOption));
        assert_eq!(
            Message::parse(&ns(&[99, 0, 0, 0])),
            Err(Error::ZeroLengthOption)
        );
        assert_eq!(Message::parse(&ns(&[1])), Err(Error::Truncated));
        assert_eq!(Message::parse(&ns(&[1, 2, 0])), Err(Error::Truncated));
        assert_eq!(
            Message::parse(&ns(&[1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
            Err(Error::OptionLength { kind: 1, units: 2 })
        );
        assert_eq!(
            Message::parse(&ns(&[3, 1, 0, 0, 0, 0, 0, 0])),
            Err(Error::OptionLength { kind: 3, units: 1 })
        );
        assert_eq!(
            Message::parse(&ns(&[5, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
            Err(Error::OptionLength { kind: 5, units: 2 })
        );
        // An unknown option is kept, its bytes after type and length.
        assert_eq!(
            Message::parse(&ns(&[99, 1, 1, 2, 3, 4, 5, 6])),
            Ok(Message::NeighborSolicitation(NeighborSolicitation {
                target: addr("fe80::1"),
                options: vec![NdOption::Unknown {
                    kind: 99,
                    data: vec![1, 2, 3, 4, 5, 6]
                }],
            }))
        );
        // The checksum is left to receive.
        assert!(Message::parse(&ns(&[])).is_ok());
        assert_eq!(
            Message::receive(&envelope("fe80::2", "fe80::1"), &ns(&[])),
            Err(Error::Checksum)
        );
        assert_eq!(
            Message::parse(&vec![133; MAX_MESSAGE + 1]),
            Err(Error::TooLong)
        );
    }

    #[test]
    fn the_rules_on_addresses_are_checked_by_validate() {
        let ns = |target: &str, options: Vec<NdOption>| {
            Message::NeighborSolicitation(NeighborSolicitation {
                target: addr(target),
                options,
            })
        };
        let na = |solicited: bool, target: &str| {
            Message::NeighborAdvertisement(NeighborAdvertisement {
                router: false,
                solicited,
                overrides: false,
                target: addr(target),
                options: vec![],
            })
        };
        let ra = Message::RouterAdvertisement(RouterAdvertisement {
            cur_hop_limit: 0,
            managed: false,
            other: false,
            router_lifetime: 0,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![],
        });
        let redirect = |target: &str, destination: &str| {
            Message::Redirect(Redirect {
                target: addr(target),
                destination: addr(destination),
                options: vec![],
            })
        };
        let rs = Message::RouterSolicitation(RouterSolicitation {
            options: vec![NdOption::SourceLinkLayer(HOST_MAC)],
        });
        let mut forwarded = envelope("fe80::2", "ff02::2");
        forwarded.hop_limit = 254;
        for (m, env, expected) in [
            (rs.clone(), forwarded, Err(Error::HopLimit(254))),
            (
                rs.clone(),
                envelope("::", "ff02::2"),
                Err(Error::SourceLinkLayerFromUnspecified),
            ),
            (rs, envelope("fe80::2", "ff02::2"), Ok(())),
            (
                ns("ff02::1", vec![]),
                envelope("fe80::2", "ff02::1:ff00:1"),
                Err(Error::Target(addr("ff02::1"))),
            ),
            (
                ns("2001:db8::1", vec![]),
                envelope("::", "2001:db8::1"),
                Err(Error::Destination(addr("2001:db8::1"))),
            ),
            (
                ns("2001:db8::1", vec![NdOption::SourceLinkLayer(HOST_MAC)]),
                envelope("::", "ff02::1:ff00:1"),
                Err(Error::SourceLinkLayerFromUnspecified),
            ),
            (
                ns("2001:db8::1", vec![]),
                envelope("2001:db8::2", "2001:db8::1"),
                Ok(()),
            ),
            (
                na(true, "fe80::1"),
                envelope("fe80::1", "ff02::1"),
                Err(Error::SolicitedToMulticast),
            ),
            (na(false, "fe80::1"), envelope("fe80::1", "ff02::1"), Ok(())),
            (
                na(false, "ff02::1"),
                envelope("fe80::1", "fe80::2"),
                Err(Error::Target(addr("ff02::1"))),
            ),
            (
                ra.clone(),
                envelope("2001:db8::1", "ff02::1"),
                Err(Error::Source(addr("2001:db8::1"))),
            ),
            (ra, envelope("fe80::1", "ff02::1"), Ok(())),
            (
                redirect("fe80::3", "2001:db8::9"),
                envelope("2001:db8::1", "fe80::2"),
                Err(Error::Source(addr("2001:db8::1"))),
            ),
            (
                redirect("fe80::3", "ff0e::1"),
                envelope("fe80::1", "fe80::2"),
                Err(Error::Destination(addr("ff0e::1"))),
            ),
            (
                redirect("2001:db8::3", "2001:db8::9"),
                envelope("fe80::1", "fe80::2"),
                Err(Error::Target(addr("2001:db8::3"))),
            ),
            (
                redirect("2001:db8::9", "2001:db8::9"),
                envelope("fe80::1", "fe80::2"),
                Ok(()),
            ),
        ] {
            assert_eq!(m.validate(&env), expected, "{m:?} in {env:?}");
            // Writers refuse what readers refuse.
            assert_eq!(
                m.emit(env.source, env.destination).map(|_| ()),
                if env.hop_limit == 255 {
                    expected
                } else {
                    Ok(())
                }
            );
        }
    }

    #[test]
    fn options_that_would_not_read_back_are_refused() {
        let with = |o: NdOption| {
            Message::RouterSolicitation(RouterSolicitation { options: vec![o] })
                .emit(addr("fe80::2"), ALL_ROUTERS)
        };
        for o in [
            NdOption::Unknown {
                kind: 1,
                data: vec![0; 6],
            },
            NdOption::Unknown {
                kind: 5,
                data: vec![0; 6],
            },
            NdOption::Unknown {
                kind: 99,
                data: vec![0; 5],
            },
            NdOption::Unknown {
                kind: 99,
                data: vec![0; 255 * 8 + 6],
            },
            NdOption::RedirectedHeader(vec![0; 255 * 8]),
        ] {
            assert_eq!(with(o), Err(Error::Unwritable));
        }
        // A redirected header is padded to a multiple of 8.
        let bytes = with(NdOption::RedirectedHeader(vec![0x60; 3])).unwrap();
        assert_eq!(
            &bytes[8..],
            &[4, 2, 0, 0, 0, 0, 0, 0, 0x60, 0x60, 0x60, 0, 0, 0, 0, 0]
        );
        // The largest redirected header fits.
        assert!(with(NdOption::RedirectedHeader(vec![0; 254 * 8])).is_ok());
    }

    #[test]
    fn solicited_node_addresses() {
        // RFC 4291 section 2.7.1: FF02:0:0:0:0:1:FFXX:XXXX.
        assert_eq!(
            solicited_node(addr("2001:db8::1:2345:6789")),
            addr("ff02::1:ff45:6789")
        );
        assert_eq!(
            solicited_node(addr("fe80::5054:ff:fe12:3456")),
            addr("ff02::1:ff12:3456")
        );
        let sn = solicited_node(addr("::"));
        assert_eq!(solicited_node(sn), sn);
    }
}
