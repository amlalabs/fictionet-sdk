//! OSPF: reading and writing OSPFv2 and OSPFv3 packets and LSAs, with no
//! I/O.
//!
//! Packet and LSA readers and writers handle complete values. `Datagram`
//! carries packet bytes through `Wire`. There is no protocol stream decoder,
//! neighbor state machine, routing database, route calculation, or `Service`.
//!
//! OSPF (Open Shortest Path First, IP protocol 89) is a link-state routing
//! protocol that many enterprise and campus networks run inside. Routers on
//! a link find each other with Hello packets and elect a designated router.
//! Each router then describes its links in link state advertisements (LSAs).
//! Neighbors swap summaries of the LSAs they hold (Database Description),
//! ask for the ones they lack (Link State Request), send them (Link State
//! Update) and confirm them (Link State Acknowledgment). Every router
//! builds the same map from the LSAs and works out its routes from it.
//!
//! Two versions are in use. Version 2 (RFC 2328) runs over IPv4 and
//! carries IPv4 routes. It has an authentication field in every header,
//! and its checksum covers the packet without that field. Version 3 (RFC
//! 5340) runs over IPv6 and carries IPv6 prefixes. It has no
//! authentication field, and its checksum covers an IPv6 pseudo-header as
//! well. Both versions have the same five packet types, and both protect
//! each LSA with a Fletcher checksum (RFC 905, annex B) that every router
//! checks before it accepts the LSA.
//!
//! Nothing here reads a socket. A world that plays a router hands each
//! OSPF payload (the bytes after the IP header) to [`Packet::parse`] with
//! the packet's [`Endpoints`], and prepares a reply with [`Packet::frame`].
//! Write that frame with [`Wire::write`] in an IP packet with protocol
//! [`PROTOCOL`], usually to [`ALL_SPF_ROUTERS_V4`] or [`ALL_SPF_ROUTERS_V6`].
//! For pieces of one payload, use [`Stream<Collect<Datagram>>`](fictionet::stdlib::codec::Stream)
//! with a limit of [`MAX_MESSAGE`].
//! Map the payload through [`Packet::parse`], and call `end` at the IP
//! packet boundary. Which routers and links exist, when Hellos go out,
//! and how routes are worked out are up to world code.
//!
//! Every reader checks the version, packet type, lengths, counts and both
//! checksums, because the agent can send any bytes it likes. A payload
//! must end where its length says, except for a link-local signaling
//! block (RFC 5613) after a Hello or Database Description that sets the L
//! bit. An LSA body must fill its LSA exactly. Reserved fields in packets
//! are ignored when read and written as zero. In LSAs they must be zero,
//! and so must the bits of a prefix past its length: the checksum covers
//! them, and an LSA read here writes back to the same bytes, so its
//! header and checksum match the one received. Writers check the same
//! rules as readers, so bytes they return always read back.
//!
//! A Link State Update leaves out each LSA whose checksum is wrong or
//! whose body does not read, and keeps the rest (RFC 2328 section 13,
//! step 1). The packet still fails if an LSA's length does not fit.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use std::net::Ipv4Addr;
//! use fictionet::stdlib::ospf::{ALL_SPF_ROUTERS_V4, Auth, Body, Endpoints, Header, HelloV2, Packet};
//!
//! /// A Hello from router `me` on a /24 link, listing the routers it has
//! /// heard on the link.
//! fn hello(me: Ipv4Addr, heard: Vec<Ipv4Addr>) -> Packet {
//!     Packet {
//!         router_id: me,
//!         area_id: Ipv4Addr::UNSPECIFIED,
//!         header: Header::V2 { auth: Auth::Null },
//!         lls: None,
//!         body: Body::HelloV2(HelloV2 {
//!             network_mask: Ipv4Addr::new(255, 255, 255, 0),
//!             hello_interval: 10,
//!             options: 0x02,
//!             priority: 1,
//!             dead_interval: 40,
//!             designated_router: Ipv4Addr::UNSPECIFIED,
//!             backup_designated_router: Ipv4Addr::UNSPECIFIED,
//!             neighbors: heard,
//!         }),
//!     }
//! }
//!
//! // The agent's router, 1.1.1.1 at 10.0.0.1, says hello to the link. It
//! // has heard no one yet.
//! let link = Endpoints::V4 { source: Ipv4Addr::new(10, 0, 0, 1), destination: ALL_SPF_ROUTERS_V4 };
//! let bytes = [
//!     2, 1, 0, 44, 1, 1, 1, 1, 0, 0, 0, 0, 0xfa, 0x9c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // header
//!     255, 255, 255, 0, 0, 10, 0x02, 1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, // Hello
//! ];
//! let packet = Packet::parse(&bytes, &link).unwrap();
//! assert_eq!(packet, hello(Ipv4Addr::new(1, 1, 1, 1), vec![]));
//! assert_eq!(packet.frame(&link).and_then(|frame| frame.to_bytes()).unwrap(), bytes);
//!
//! // The world's router, 2.2.2.2, answers. Listing 1.1.1.1 tells the
//! // agent's router that the two can hear each other.
//! let reply = hello(Ipv4Addr::new(2, 2, 2, 2), vec![packet.router_id]);
//! let sent = reply.frame(&link).and_then(|frame| frame.to_bytes()).unwrap();
//! assert_eq!(sent.len(), 48);
//! assert_eq!(Packet::parse(&sent, &link), Ok(reply));
//!
//! // One flipped bit and the checksum no longer holds.
//! let mut bad = bytes;
//! bad[30] ^= 1;
//! assert!(Packet::parse(&bad, &link).is_err());
//! ```

use fictionet::stdlib::codec::{be16, be32};
use fictionet::stdlib::codec::Reader as ByteReader;

use fictionet::stdlib::codec::Wire;

use std::net::{Ipv4Addr, Ipv6Addr};

/// The IP protocol number of OSPF.
pub const PROTOCOL: u8 = 89;
/// The IPv4 group every OSPFv2 router on a link listens to.
pub const ALL_SPF_ROUTERS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
/// The IPv4 group the designated routers of a link listen to.
pub const ALL_D_ROUTERS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);
/// The IPv6 group every OSPFv3 router on a link listens to.
pub const ALL_SPF_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);
/// The IPv6 group the designated routers of a link listen to.
pub const ALL_D_ROUTERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);
/// The length of the OSPFv2 packet header.
pub const HEADER_LEN_V2: usize = 24;
/// The length of the OSPFv3 packet header.
pub const HEADER_LEN_V3: usize = 16;
/// The length of an LSA header, in either version.
pub const LSA_HEADER_LEN: usize = 20;
/// The longest packet: its 16-bit length field caps it.
pub const MAX_PACKET: usize = 65535;
/// The longest message digest an OSPFv2 packet with cryptographic
/// authentication carries after the packet. Its length is one byte.
pub const MAX_DIGEST: usize = 255;
/// The longest payload a reader takes: the longest packet and the longest
/// digest. A link-local signaling block must end within it too.
pub const MAX_MESSAGE: usize = MAX_PACKET + MAX_DIGEST;
/// The L bit in OSPFv2 Hello and Database Description options: a
/// link-local signaling block follows the packet (RFC 5613).
pub const OPTION_L_V2: u8 = 0x10;
/// The L bit in OSPFv3 Hello and Database Description options.
pub const OPTION_L_V3: u32 = 0x0200;
/// The DoNotAge bit of an LSA's age (RFC 1793). The rest of the age is at
/// most [`MAX_AGE`].
pub const DO_NOT_AGE: u16 = 0x8000;
/// The LSA sequence number the protocol reserves and never sends.
pub const RESERVED_SEQUENCE: u32 = 0x8000_0000;
/// The longest LSA: its 16-bit length field caps it.
pub const MAX_LSA: usize = 65535;
/// The longest IPv6 prefix, in bits.
pub const MAX_PREFIX_LEN: u8 = 128;
/// The largest value of a 24-bit field: OSPFv3 options and most metrics.
pub const MAX_U24: u32 = 0x00ff_ffff;
/// The age, in seconds, at which an LSA is flushed from every database.
pub const MAX_AGE: u16 = 3600;
/// The sequence number a router gives the first instance of an LSA.
pub const INITIAL_SEQUENCE: u32 = 0x8000_0001;

/// Packet type numbers.
pub mod packet_type {
    /// Hello: finds neighbors and elects the designated router.
    pub const HELLO: u8 = 1;
    /// Database Description: a summary of the LSAs a router holds.
    pub const DATABASE_DESCRIPTION: u8 = 2;
    /// Link State Request: asks a neighbor for LSAs.
    pub const LINK_STATE_REQUEST: u8 = 3;
    /// Link State Update: carries LSAs.
    pub const LINK_STATE_UPDATE: u8 = 4;
    /// Link State Acknowledgment: confirms LSAs arrived.
    pub const LINK_STATE_ACK: u8 = 5;
}

/// OSPFv2 authentication types.
pub mod auth_type {
    /// No authentication.
    pub const NULL: u16 = 0;
    /// A plain-text password in the header.
    pub const SIMPLE: u16 = 1;
    /// A keyed digest after the packet (RFC 2328 appendix D, RFC 5709).
    pub const CRYPTOGRAPHIC: u16 = 2;
}

/// Database Description flag bits.
pub mod dd_flags {
    /// Master/slave: set by the master of the exchange.
    pub const MS: u8 = 0x01;
    /// More: more Database Description packets follow.
    pub const MORE: u8 = 0x02;
    /// Init: the first packet of the exchange.
    pub const INIT: u8 = 0x04;
}

/// OSPFv2 LS types.
pub mod lsa_type_v2 {
    /// Router-LSA: a router's links in one area.
    pub const ROUTER: u16 = 1;
    /// Network-LSA: the routers on a transit network.
    pub const NETWORK: u16 = 2;
    /// Summary-LSA for a network in another area.
    pub const SUMMARY_NETWORK: u16 = 3;
    /// Summary-LSA for an AS boundary router in another area.
    pub const SUMMARY_ASBR: u16 = 4;
    /// AS-external-LSA: a route from outside the OSPF domain.
    pub const AS_EXTERNAL: u16 = 5;
    /// NSSA-LSA (RFC 3101): an external route inside a not-so-stubby
    /// area. It has the AS-external-LSA's format.
    pub const NSSA: u16 = 7;
}

/// OSPFv3 LS types, scope bits included.
pub mod lsa_type_v3 {
    /// Router-LSA.
    pub const ROUTER: u16 = 0x2001;
    /// Network-LSA.
    pub const NETWORK: u16 = 0x2002;
    /// Inter-Area-Prefix-LSA: a prefix in another area.
    pub const INTER_AREA_PREFIX: u16 = 0x2003;
    /// Inter-Area-Router-LSA: an AS boundary router in another area.
    pub const INTER_AREA_ROUTER: u16 = 0x2004;
    /// AS-External-LSA.
    pub const AS_EXTERNAL: u16 = 0x4005;
    /// NSSA-LSA (RFC 3101). It has the AS-External-LSA's format.
    pub const NSSA: u16 = 0x2007;
    /// Link-LSA: a router's link-local address and prefixes on one link.
    pub const LINK: u16 = 0x0008;
    /// Intra-Area-Prefix-LSA: the prefixes of a router or transit network.
    pub const INTRA_AREA_PREFIX: u16 = 0x2009;
}

/// The OSPF version: 2 for IPv4, 3 for IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// OSPFv2, RFC 2328.
    V2,
    /// OSPFv3, RFC 5340.
    V3,
}

impl Version {
    /// The version number in the header.
    pub fn number(self) -> u8 {
        match self {
            Version::V2 => 2,
            Version::V3 => 3,
        }
    }

    /// The length of this version's packet header.
    pub fn header_len(self) -> usize {
        match self {
            Version::V2 => HEADER_LEN_V2,
            Version::V3 => HEADER_LEN_V3,
        }
    }
}

/// The IP source and destination of the packet that carries an OSPF
/// payload. An IPv4 packet carries OSPFv2 and an IPv6 packet carries
/// OSPFv3. OSPFv3 checksums cover the IPv6 addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Endpoints {
    /// An IPv4 packet.
    V4 {
        /// The sending router's address on the link.
        source: Ipv4Addr,
        /// A neighbor or one of the OSPF groups.
        destination: Ipv4Addr,
    },
    /// An IPv6 packet.
    V6 {
        /// The sending router's link-local address.
        source: Ipv6Addr,
        /// A neighbor or one of the OSPF groups.
        destination: Ipv6Addr,
    },
}

impl Endpoints {
    /// The OSPF version this IP family carries.
    pub fn version(&self) -> Version {
        match self {
            Endpoints::V4 { .. } => Version::V2,
            Endpoints::V6 { .. } => Version::V3,
        }
    }
}

/// OSPFv2 authentication, from the header's type and 8-byte field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    /// Type 0. The field is ignored when read and written as zero.
    Null,
    /// Type 1: an 8-byte password, padded with zeros.
    Simple([u8; 8]),
    /// Type 2. The packet checksum is not computed: it is written as zero
    /// and not checked. The digest follows the packet, and its length is
    /// in the field. This module does not compute or check the digest.
    Cryptographic {
        /// Which shared key made the digest.
        key_id: u8,
        /// A number the sender never lets go down, against replays.
        sequence: u32,
        /// The digest, at most [`MAX_DIGEST`] bytes.
        digest: Vec<u8>,
    },
    /// Any other type, with its field kept as it was.
    Other {
        /// The type, not 0, 1 or 2.
        kind: u16,
        /// The 8-byte field.
        data: [u8; 8],
    },
}

impl Auth {
    /// The authentication type number.
    pub fn kind(&self) -> u16 {
        match self {
            Auth::Null => auth_type::NULL,
            Auth::Simple(_) => auth_type::SIMPLE,
            Auth::Cryptographic { .. } => auth_type::CRYPTOGRAPHIC,
            Auth::Other { kind, .. } => *kind,
        }
    }
}

/// The header fields that differ between the versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Header {
    /// OSPFv2: the authentication.
    V2 {
        /// How the packet is authenticated.
        auth: Auth,
    },
    /// OSPFv3: the instance ID, which lets several OSPF instances share a
    /// link.
    V3 {
        /// The instance ID.
        instance_id: u8,
    },
}

/// One OSPF packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The sending router's ID.
    pub router_id: Ipv4Addr,
    /// The area the packet belongs to. The backbone is 0.0.0.0.
    pub area_id: Ipv4Addr,
    /// The fields that differ between the versions.
    pub header: Header,
    /// The TLVs of the link-local signaling block (RFC 5613) after the
    /// packet and its digest, without the block's 4-byte header, which
    /// writers work out. Only a Hello or Database Description whose
    /// options set the L bit ([`OPTION_L_V2`], [`OPTION_L_V3`]) carries
    /// one, and its length is a multiple of 4. Readers give `None` when
    /// the L bit is clear, when no block follows, or when the block's
    /// checksum is wrong, since the RFC says to drop the block then and
    /// keep the packet.
    pub lls: Option<Vec<u8>>,
    /// What the packet carries. Its variant gives the packet type.
    pub body: Body,
}

/// What a packet carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// Type 1 in OSPFv2.
    HelloV2(HelloV2),
    /// Type 1 in OSPFv3.
    HelloV3(HelloV3),
    /// Type 2.
    DatabaseDescription(DatabaseDescription),
    /// Type 3: the LSAs asked for.
    LinkStateRequest(Vec<LsaKey>),
    /// Type 4: the LSAs sent.
    LinkStateUpdate(Vec<Lsa>),
    /// Type 5: the headers of the LSAs acknowledged.
    LinkStateAck(Vec<LsaHeader>),
}

impl Body {
    /// The packet type number.
    pub fn packet_type(&self) -> u8 {
        match self {
            Body::HelloV2(_) | Body::HelloV3(_) => packet_type::HELLO,
            Body::DatabaseDescription(_) => packet_type::DATABASE_DESCRIPTION,
            Body::LinkStateRequest(_) => packet_type::LINK_STATE_REQUEST,
            Body::LinkStateUpdate(_) => packet_type::LINK_STATE_UPDATE,
            Body::LinkStateAck(_) => packet_type::LINK_STATE_ACK,
        }
    }
}

/// An OSPFv2 Hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloV2 {
    /// The network mask of the sending interface.
    pub network_mask: Ipv4Addr,
    /// Seconds between Hellos.
    pub hello_interval: u16,
    /// The options the router supports.
    pub options: u8,
    /// The router's priority in the designated router election. 0 means
    /// it never stands.
    pub priority: u8,
    /// Seconds of silence after which a neighbor is taken as down.
    pub dead_interval: u32,
    /// The designated router's interface address, or 0.0.0.0.
    pub designated_router: Ipv4Addr,
    /// The backup designated router's interface address, or 0.0.0.0.
    pub backup_designated_router: Ipv4Addr,
    /// The router IDs heard on the link recently.
    pub neighbors: Vec<Ipv4Addr>,
}

/// An OSPFv3 Hello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloV3 {
    /// A number that names the sending interface within its router.
    pub interface_id: u32,
    /// The router's priority in the designated router election.
    pub priority: u8,
    /// The options the router supports, at most [`MAX_U24`].
    pub options: u32,
    /// Seconds between Hellos.
    pub hello_interval: u16,
    /// Seconds of silence after which a neighbor is taken as down.
    pub dead_interval: u16,
    /// The designated router's router ID, or 0.0.0.0.
    pub designated_router: Ipv4Addr,
    /// The backup designated router's router ID, or 0.0.0.0.
    pub backup_designated_router: Ipv4Addr,
    /// The router IDs heard on the link recently.
    pub neighbors: Vec<Ipv4Addr>,
}

/// A Database Description packet, in either version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseDescription {
    /// The largest IP packet the interface sends without fragmenting.
    pub mtu: u16,
    /// The options the router supports: at most 0xff in OSPFv2 and
    /// [`MAX_U24`] in OSPFv3.
    pub options: u32,
    /// The flags byte; see [`dd_flags`].
    pub flags: u8,
    /// The exchange's sequence number, set by the master.
    pub sequence: u32,
    /// Headers of the LSAs the sender holds.
    pub headers: Vec<LsaHeader>,
}

/// Which LSA a Link State Request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LsaKey {
    /// The LS type. It is 32 bits in OSPFv2 and at most 0xffff in OSPFv3.
    pub ls_type: u32,
    /// The Link State ID.
    pub link_state_id: Ipv4Addr,
    /// The router that made the LSA.
    pub advertising_router: Ipv4Addr,
}

/// An LSA header, as Database Description and Link State Acknowledgment
/// packets carry it. Its checksum and length describe an LSA and are kept
/// as sent. Readers and writers check that it could describe one: the
/// length is at least [`LSA_HEADER_LEN`], neither checksum byte is zero,
/// the sequence number is not [`RESERVED_SEQUENCE`], and the age past
/// [`DO_NOT_AGE`] is at most [`MAX_AGE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LsaHeader {
    /// Seconds since the LSA was made.
    pub age: u16,
    /// OSPFv2 options. OSPFv3 headers have none, so this must be 0 there.
    pub options: u8,
    /// The LS type: at most 0xff in OSPFv2, which gives it one byte.
    pub ls_type: u16,
    /// The Link State ID.
    pub link_state_id: Ipv4Addr,
    /// The router that made the LSA.
    pub advertising_router: Ipv4Addr,
    /// The instance's sequence number.
    pub sequence: u32,
    /// The LSA's Fletcher checksum.
    pub checksum: u16,
    /// The LSA's length, header included.
    pub length: u16,
}

impl LsaHeader {
    /// Which LSA this header names, as a Link State Request asks for it.
    pub fn key(&self) -> LsaKey {
        LsaKey {
            ls_type: u32::from(self.ls_type),
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }
}

/// A whole LSA. Its checksum and length are worked out when it is written
/// and checked when it is read, so they are not kept. An LSA read with
/// [`Lsa::parse`] writes back to the same bytes, so [`Lsa::header`] gives
/// the header it was received with. The age and sequence number follow
/// the rules of [`LsaHeader`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lsa {
    /// Seconds since the LSA was made, at most [`MAX_AGE`], with
    /// [`DO_NOT_AGE`] possibly set.
    pub age: u16,
    /// OSPFv2 options. OSPFv3 LSA headers have none, so this must be 0
    /// there.
    pub options: u8,
    /// The LS type: at most 0xff in OSPFv2.
    pub ls_type: u16,
    /// The Link State ID.
    pub link_state_id: Ipv4Addr,
    /// The router that made the LSA.
    pub advertising_router: Ipv4Addr,
    /// The instance's sequence number.
    pub sequence: u32,
    /// The body. Its variant must be the one the version and LS type call
    /// for, or [`LsaBody::Other`] for a type this module does not read.
    pub body: LsaBody,
}

/// The body of an LSA, by type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LsaBody {
    /// OSPFv2 type 1.
    Router(RouterLsa),
    /// OSPFv2 type 2.
    Network(NetworkLsa),
    /// OSPFv2 types 3 and 4.
    Summary(SummaryLsa),
    /// OSPFv2 types 5 and 7.
    AsExternal(AsExternalLsa),
    /// OSPFv3 type 0x2001.
    RouterV3(RouterLsaV3),
    /// OSPFv3 type 0x2002.
    NetworkV3(NetworkLsaV3),
    /// OSPFv3 type 0x2003.
    InterAreaPrefix(InterAreaPrefixLsa),
    /// OSPFv3 type 0x2004.
    InterAreaRouter(InterAreaRouterLsa),
    /// OSPFv3 types 0x4005 and 0x2007.
    AsExternalV3(AsExternalLsaV3),
    /// OSPFv3 type 0x0008.
    Link(LinkLsa),
    /// OSPFv3 type 0x2009.
    IntraAreaPrefix(IntraAreaPrefixLsa),
    /// Any other type, with its body unread.
    Other(Vec<u8>),
}

/// An OSPFv2 Router-LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterLsa {
    /// The flags byte: 0x04 virtual link endpoint (V), 0x02 AS boundary
    /// router (E), 0x01 area border router (B).
    pub flags: u8,
    /// The router's links, at most 65535.
    pub links: Vec<RouterLink>,
}

/// One link of an OSPFv2 Router-LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterLink {
    /// What the link connects to; its meaning depends on `kind`.
    pub id: Ipv4Addr,
    /// More about the link; its meaning depends on `kind`.
    pub data: Ipv4Addr,
    /// 1 point-to-point, 2 transit network, 3 stub network, 4 virtual
    /// link. No other value is read or written.
    pub kind: u8,
    /// The cost of sending over the link.
    pub metric: u16,
    /// Costs for other types of service, at most 255. Most routers send
    /// none.
    pub tos: Vec<TosMetric>,
}

/// A cost for one type of service, in an OSPFv2 Router-LSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TosMetric {
    /// The type of service.
    pub tos: u8,
    /// Its cost.
    pub metric: u16,
}

/// An OSPFv2 Network-LSA, made by a network's designated router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkLsa {
    /// The network's mask.
    pub network_mask: Ipv4Addr,
    /// The router IDs of the routers on the network. There is at least
    /// one, and a whole LSA lists its advertising router, the designated
    /// router, among them.
    pub attached_routers: Vec<Ipv4Addr>,
}

/// An OSPFv2 Summary-LSA, made by an area border router.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryLsa {
    /// The destination's mask. Type 4 LSAs must set it to 0.0.0.0.
    pub network_mask: Ipv4Addr,
    /// The cost to the destination, at most [`MAX_U24`].
    pub metric: u32,
    /// Costs for other types of service, each at most [`MAX_U24`].
    pub tos: Vec<(u8, u32)>,
}

/// An OSPFv2 AS-external-LSA or NSSA-LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsExternalLsa {
    /// The destination's mask.
    pub network_mask: Ipv4Addr,
    /// One route per type of service. There is at least one, and the
    /// first is for type of service 0.
    pub routes: Vec<ExternalRoute>,
}

/// One route of an OSPFv2 AS-external-LSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExternalRoute {
    /// The E bit: the metric is of type 2, larger than any internal cost.
    pub type2: bool,
    /// The type of service, at most 127.
    pub tos: u8,
    /// The cost, at most [`MAX_U24`].
    pub metric: u32,
    /// Where to send the traffic, or 0.0.0.0 for the advertising router.
    pub forwarding_address: Ipv4Addr,
    /// A tag routers pass along unread.
    pub route_tag: u32,
}

/// An OSPFv3 Router-LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterLsaV3 {
    /// The flags byte: 0x10 NSSA translator (Nt), 0x04 V, 0x02 E, 0x01 B.
    pub flags: u8,
    /// The options, at most [`MAX_U24`].
    pub options: u32,
    /// The router's interfaces.
    pub interfaces: Vec<RouterInterface>,
}

/// One interface of an OSPFv3 Router-LSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouterInterface {
    /// 1 point-to-point, 2 transit network, 4 virtual link. No other value
    /// is read or written.
    pub kind: u8,
    /// The cost of sending over the interface.
    pub metric: u16,
    /// The interface's ID.
    pub interface_id: u32,
    /// The neighbor's interface ID, or the designated router's on a
    /// transit network.
    pub neighbor_interface_id: u32,
    /// The neighbor's router ID, or the designated router's.
    pub neighbor_router_id: Ipv4Addr,
}

/// An OSPFv3 Network-LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkLsaV3 {
    /// The options, at most [`MAX_U24`].
    pub options: u32,
    /// The router IDs of the routers on the network, with the same rules
    /// as in [`NetworkLsa`].
    pub attached_routers: Vec<Ipv4Addr>,
}

/// An IPv6 prefix as OSPFv3 carries it: only the 32-bit words the length
/// needs are sent. Every bit of `address` past the length must be zero
/// (RFC 5340 appendix A.4.1): readers reject a prefix with one set, and
/// writers refuse one. Build one with [`Prefix::new`] to clear them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    /// The prefix length in bits, at most [`MAX_PREFIX_LEN`].
    pub length: u8,
    /// The prefix options: 0x01 NU, 0x02 LA, 0x08 P, 0x10 DN.
    pub options: u8,
    /// The prefix.
    pub address: Ipv6Addr,
}

impl Prefix {
    /// A prefix of `length` bits with every bit of `address` past the
    /// length cleared. For example, 2001:db8::1 with length 64 gives
    /// 2001:db8::. A length over [`MAX_PREFIX_LEN`] is kept as it is, and
    /// writers reject it.
    pub fn new(length: u8, options: u8, address: Ipv6Addr) -> Prefix {
        Prefix { length, options, address: Ipv6Addr::from(u128::from(address) & prefix_mask(length)) }
    }
}

/// The bits of an address a prefix of `length` bits keeps.
fn prefix_mask(length: u8) -> u128 {
    let bits = u32::from(length.min(MAX_PREFIX_LEN));
    if bits == 0 { 0 } else { u128::MAX << (128 - bits) }
}

/// An OSPFv3 Inter-Area-Prefix-LSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterAreaPrefixLsa {
    /// The cost to the prefix, at most [`MAX_U24`].
    pub metric: u32,
    /// The prefix.
    pub prefix: Prefix,
}

/// An OSPFv3 Inter-Area-Router-LSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterAreaRouterLsa {
    /// The destination router's options, at most [`MAX_U24`].
    pub options: u32,
    /// The cost to it, at most [`MAX_U24`].
    pub metric: u32,
    /// Its router ID.
    pub destination: Ipv4Addr,
}

/// An OSPFv3 AS-External-LSA or NSSA-LSA. Its F and T flags are set when
/// the forwarding address and the tag are present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AsExternalLsaV3 {
    /// The E flag: the metric is of type 2.
    pub type2: bool,
    /// The cost, at most [`MAX_U24`].
    pub metric: u32,
    /// The prefix.
    pub prefix: Prefix,
    /// Where to send the traffic, if not to the advertising router. It is
    /// never the unspecified address or a link-local one (RFC 5340
    /// appendix A.4.7).
    pub forwarding_address: Option<Ipv6Addr>,
    /// A tag routers pass along unread.
    pub route_tag: Option<u32>,
    /// Another LSA with more about the route: its nonzero LS type and its
    /// Link State ID.
    pub referenced: Option<(u16, Ipv4Addr)>,
}

/// An OSPFv3 Link-LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkLsa {
    /// The router's priority on the link.
    pub priority: u8,
    /// The options, at most [`MAX_U24`].
    pub options: u32,
    /// The router's link-local address on the link.
    pub link_local_address: Ipv6Addr,
    /// The prefixes on the link.
    pub prefixes: Vec<Prefix>,
}

/// An OSPFv3 Intra-Area-Prefix-LSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntraAreaPrefixLsa {
    /// The LS type of the Router-LSA or Network-LSA the prefixes belong to.
    pub referenced_ls_type: u16,
    /// Its Link State ID.
    pub referenced_link_state_id: Ipv4Addr,
    /// Its advertising router.
    pub referenced_advertising_router: Ipv4Addr,
    /// The prefixes and their costs, at most 65535.
    pub prefixes: Vec<(Prefix, u16)>,
}

/// Why bytes are not an OSPF packet or LSA, or why a value cannot be
/// written as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes end before the packet or LSA does.
    Truncated,
    /// Bytes follow the end the length gives.
    Trailing {
        /// Number of bytes after the OSPF packet.
        remaining: usize,
    },
    /// The version is not 2 or 3.
    Version(u8),
    /// The version does not match the IP family: OSPFv2 over IPv6 or
    /// OSPFv3 over IPv4.
    Family,
    /// The packet type is not 1 to 5.
    Type(u8),
    /// The packet length is shorter than the header.
    Length(u16),
    /// The packet checksum is wrong.
    Checksum,
    /// The packet body does not fit its type: fixed fields are missing or
    /// a list does not divide evenly.
    BodyLength,
    /// An LSA's length is shorter than its header or longer than the bytes
    /// left.
    LsaLength(u16),
    /// An LSA's Fletcher checksum is wrong.
    LsaChecksum,
    /// A Link State Update's LSA count does not match the LSAs it holds.
    LsaCount,
    /// An LSA body does not fit its type.
    LsaBody,
    /// A prefix length is over [`MAX_PREFIX_LEN`].
    PrefixLength(u8),
    /// The packet or LSA would be longer than its length field allows.
    TooLong,
    /// A field is out of range for what holds it, such as an OSPFv3
    /// option above [`MAX_U24`], or holds a value the protocol never
    /// sends, such as LSA sequence number [`RESERVED_SEQUENCE`].
    Field,
    /// The value cannot be written without changing it.
    Unwritable,
    /// A link-local signaling block's length is shorter than its header
    /// or runs past [`MAX_MESSAGE`], or a block is set on a packet that
    /// cannot carry one.
    Lls,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("OSPF packet or LSA cut short"),
            Error::Trailing { remaining } => {
                write!(f, "{remaining} bytes after the OSPF packet")
            }
            Error::Version(v) => write!(f, "OSPF version {v}, not 2 or 3"),
            Error::Family => f.write_str("OSPF version does not match the IP family"),
            Error::Type(t) => write!(f, "OSPF packet type {t}, not 1 to 5"),
            Error::Length(n) => write!(f, "OSPF packet length {n}, shorter than the header"),
            Error::Checksum => f.write_str("wrong OSPF packet checksum"),
            Error::BodyLength => f.write_str("OSPF packet body does not fit its type"),
            Error::LsaLength(n) => write!(f, "LSA length {n} does not fit"),
            Error::LsaChecksum => f.write_str("wrong LSA checksum"),
            Error::LsaCount => f.write_str("LSA count does not match the LSAs sent"),
            Error::LsaBody => f.write_str("LSA body does not fit its type"),
            Error::PrefixLength(n) => write!(f, "prefix length {n}, over 128"),
            Error::TooLong => f.write_str("too long for its length field"),
            Error::Field => f.write_str("field out of range"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Lls => f.write_str("bad link-local signaling block"),
        }
    }
}

impl std::error::Error for Error {}

// Checksums.

fn sum_words(mut sum: u64, b: &[u8]) -> u64 {
    let (chunks, rest) = b.as_chunks::<2>();
    for c in chunks {
        sum += u64::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = rest {
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

/// The packet checksum the OSPF payload in `b` should carry, worked out
/// with its checksum field (bytes 12 and 13) taken as zero, over the bytes
/// the packet length gives. For OSPFv2 (IPv4 endpoints) it skips the
/// 8-byte authentication field. For OSPFv3 (IPv6 endpoints) it includes
/// the IPv6 pseudo-header of RFC 8200 section 8.1. It returns `None` if
/// `b` is shorter than the header, or the length field is shorter than the
/// header or longer than `b`. A packet with cryptographic authentication
/// carries zero instead.
pub fn checksum(b: &[u8], endpoints: &Endpoints) -> Option<u16> {
    let hl = endpoints.version().header_len();
    if b.len() < hl {
        return None;
    }
    let len = usize::from(be16(b, 2)?);
    if len < hl || len > b.len() {
        return None;
    }
    let mut sum = sum_words(0, &b[..12]);
    match endpoints {
        Endpoints::V4 { .. } => {
            sum = sum_words(sum, &b[14..16]);
            sum = sum_words(sum, &b[HEADER_LEN_V2..len]);
        }
        Endpoints::V6 { source, destination } => {
            sum = sum_words(sum, &b[14..len]);
            sum = sum_words(sum, &source.octets());
            sum = sum_words(sum, &destination.octets());
            // At most MAX_PACKET, so it fits in 32 bits.
            sum = sum_words(sum, &(len as u32).to_be_bytes());
            sum = sum_words(sum, &[0, 0, 0, PROTOCOL]);
        }
    }
    Some(!fold(sum))
}

/// Whether two ones' complement checksums are equal: 0x0000 and 0xffff
/// are both zero.
fn same_checksum(a: u16, b: u16) -> bool {
    a == b || (a | b == 0xffff && (a == 0 || b == 0))
}

/// The Fletcher sums of `data` modulo 255, with the bytes at `skip` and
/// `skip + 1` taken as zero.
fn fletcher_sums(data: &[u8], skip: Option<usize>) -> (i64, i64) {
    let (mut c0, mut c1) = (0i64, 0i64);
    for (i, &byte) in data.iter().enumerate() {
        let byte = match skip {
            Some(s) if i == s || i == s + 1 => 0,
            _ => byte,
        };
        c0 = (c0 + i64::from(byte)) % 255;
        c1 = (c1 + c0) % 255;
    }
    (c0, c1)
}

/// The Fletcher checksum the LSA at the start of `lsa` should carry
/// (RFC 2328 section 12.1.7, using RFC 905 annex B). It covers the LSA from
/// the byte after the age to the end its length field gives, with the
/// checksum field (bytes 16 and 17) taken as zero. Neither byte of the
/// result is ever zero. It returns `None` if `lsa` is shorter than an LSA
/// header, or the length field is shorter than the header or longer than
/// `lsa`.
pub fn lsa_checksum(lsa: &[u8]) -> Option<u16> {
    let data = lsa_data(lsa)?;
    // The checksum's first byte is at offset 14 of the data, position 15
    // counting from 1.
    let (c0, c1) = fletcher_sums(data, Some(14));
    // At most MAX_LSA, so this cannot overflow.
    let after = data.len() as i64 - 15;
    let mut x = (after * c0 - c1).rem_euclid(255);
    let mut y = (c1 - (after + 1) * c0).rem_euclid(255);
    if x == 0 {
        x = 255;
    }
    if y == 0 {
        y = 255;
    }
    Some(((x as u16) << 8) | y as u16)
}

/// Whether the LSA at the start of `lsa` carries a right Fletcher
/// checksum: both sums over the checked bytes are zero modulo 255, and
/// neither byte of the field is zero. A zero byte is never made (255 is
/// written instead), and an LSA with one would get a different checksum
/// if it were written again.
pub fn lsa_checksum_ok(lsa: &[u8]) -> bool {
    match lsa_data(lsa) {
        Some(data) => lsa[16] != 0 && lsa[17] != 0 && fletcher_sums(data, None) == (0, 0),
        None => false,
    }
}

fn lsa_data(lsa: &[u8]) -> Option<&[u8]> {
    if lsa.len() < LSA_HEADER_LEN {
        return None;
    }
    let len = usize::from(be16(lsa, 18)?);
    if !(LSA_HEADER_LEN..=lsa.len()).contains(&len) {
        return None;
    }
    Some(&lsa[2..len])
}

// Reading.

/// Reads OSPF fields with the enclosing packet or LSA error.
struct Fields<'a> {
    cursor: ByteReader<'a>,
    err: Error,
}

impl<'a> Fields<'a> {
    fn new(b: &'a [u8], err: Error) -> Fields<'a> {
        Fields { cursor: ByteReader::new(b), err }
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.cursor.take(n).map_err(|_| self.err)
    }

    #[inline]
    fn u8(&mut self) -> Result<u8, Error> {
        self.cursor.u8().map_err(|_| self.err)
    }

    #[inline]
    fn u16(&mut self) -> Result<u16, Error> {
        self.cursor.u16_be().map_err(|_| self.err)
    }

    #[inline]
    fn u24(&mut self) -> Result<u32, Error> {
        self.cursor.u24_be().map_err(|_| self.err)
    }

    #[inline]
    fn u32(&mut self) -> Result<u32, Error> {
        self.cursor.u32_be().map_err(|_| self.err)
    }

    fn ip4(&mut self) -> Result<Ipv4Addr, Error> {
        Ok(Ipv4Addr::from(self.u32()?))
    }

    fn ip6(&mut self) -> Result<Ipv6Addr, Error> {
        let s = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(Ipv6Addr::from(a))
    }

    #[inline]
    fn left(&self) -> usize {
        self.cursor.remaining()
    }

    #[inline]
    fn end(&self) -> Result<(), Error> {
        self.cursor.finish().map_err(|_| self.err)
    }

    /// `n` reserved bytes, which must be zero.
    fn zero(&mut self, n: usize) -> Result<(), Error> {
        if self.take(n)?.iter().all(|&x| x == 0) { Ok(()) } else { Err(self.err) }
    }

    /// The rest as addresses, which must divide evenly.
    fn ip4_list(&mut self) -> Result<Vec<Ipv4Addr>, Error> {
        if !self.left().is_multiple_of(4) {
            return Err(self.err);
        }
        let mut out = Vec::with_capacity(self.left() / 4);
        while self.left() > 0 {
            out.push(self.ip4()?);
        }
        Ok(out)
    }

    /// The rest as LSA headers, which must divide evenly.
    fn header_list(&mut self, v: Version) -> Result<Vec<LsaHeader>, Error> {
        if !self.left().is_multiple_of(LSA_HEADER_LEN) {
            return Err(self.err);
        }
        let mut out = Vec::with_capacity(self.left() / LSA_HEADER_LEN);
        while self.left() > 0 {
            let h = read_lsa_header(self, v)?;
            check_lsa_header(&h)?;
            out.push(h);
        }
        Ok(out)
    }
}

/// The age and sequence number rules every LSA follows: the age past the
/// DoNotAge bit is at most MaxAge (RFC 2328 section 12.1.1), and the
/// sequence number is not the reserved one (section 12.1.6).
fn check_age_sequence(age: u16, sequence: u32) -> Result<(), Error> {
    if age & !DO_NOT_AGE > MAX_AGE || sequence == RESERVED_SEQUENCE { Err(Error::Field) } else { Ok(()) }
}

/// Whether a header could describe an LSA that reads.
fn check_lsa_header(h: &LsaHeader) -> Result<(), Error> {
    if usize::from(h.length) < LSA_HEADER_LEN {
        return Err(Error::LsaLength(h.length));
    }
    if h.checksum >> 8 == 0 || h.checksum & 0xff == 0 {
        return Err(Error::Field);
    }
    check_age_sequence(h.age, h.sequence)
}

fn read_lsa_header(r: &mut Fields, v: Version) -> Result<LsaHeader, Error> {
    let age = r.u16()?;
    let (options, ls_type) = match v {
        Version::V2 => (r.u8()?, u16::from(r.u8()?)),
        Version::V3 => (0, r.u16()?),
    };
    Ok(LsaHeader {
        age,
        options,
        ls_type,
        link_state_id: r.ip4()?,
        advertising_router: r.ip4()?,
        sequence: r.u32()?,
        checksum: r.u16()?,
        length: r.u16()?,
    })
}

fn prefix_bytes(length: u8) -> usize {
    usize::from(length).div_ceil(32) * 4
}

/// A prefix and the 16-bit field between its options and its address.
fn read_prefix(r: &mut Fields) -> Result<(Prefix, u16), Error> {
    let length = r.u8()?;
    let options = r.u8()?;
    let middle = r.u16()?;
    if length > MAX_PREFIX_LEN {
        return Err(Error::PrefixLength(length));
    }
    let raw = r.take(prefix_bytes(length))?;
    let mut a = [0u8; 16];
    a[..raw.len()].copy_from_slice(raw);
    let address = u128::from_be_bytes(a);
    // The padding past the length is zero (RFC 5340 appendix A.4.1).
    if address & !prefix_mask(length) != 0 {
        return Err(r.err);
    }
    Ok((Prefix { length, options, address: Ipv6Addr::from(address) }, middle))
}

/// Whether an address may be an OSPFv3 external forwarding address: not
/// unspecified and not link-local (RFC 5340 appendix A.4.7).
fn forwarding_ok(a: Ipv6Addr) -> bool {
    !a.is_unspecified() && !a.is_unicast_link_local()
}

/// Whether a Router-LSA link or interface type is one the version defines
/// (RFC 2328 appendix A.4.2, RFC 5340 appendix A.4.3).
fn link_kind_ok(v: Version, kind: u8) -> bool {
    match v {
        Version::V2 => (1..=4).contains(&kind),
        Version::V3 => matches!(kind, 1 | 2 | 4),
    }
}

/// Which body an LSA of a version and type has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Router,
    Network,
    Summary,
    AsExternal,
    RouterV3,
    NetworkV3,
    InterAreaPrefix,
    InterAreaRouter,
    AsExternalV3,
    Link,
    IntraAreaPrefix,
    Other,
}

fn kind_for(v: Version, t: u16) -> Kind {
    match (v, t) {
        (Version::V2, lsa_type_v2::ROUTER) => Kind::Router,
        (Version::V2, lsa_type_v2::NETWORK) => Kind::Network,
        (Version::V2, lsa_type_v2::SUMMARY_NETWORK | lsa_type_v2::SUMMARY_ASBR) => Kind::Summary,
        (Version::V2, lsa_type_v2::AS_EXTERNAL | lsa_type_v2::NSSA) => Kind::AsExternal,
        (Version::V3, lsa_type_v3::ROUTER) => Kind::RouterV3,
        (Version::V3, lsa_type_v3::NETWORK) => Kind::NetworkV3,
        (Version::V3, lsa_type_v3::INTER_AREA_PREFIX) => Kind::InterAreaPrefix,
        (Version::V3, lsa_type_v3::INTER_AREA_ROUTER) => Kind::InterAreaRouter,
        (Version::V3, lsa_type_v3::AS_EXTERNAL | lsa_type_v3::NSSA) => Kind::AsExternalV3,
        (Version::V3, lsa_type_v3::LINK) => Kind::Link,
        (Version::V3, lsa_type_v3::INTRA_AREA_PREFIX) => Kind::IntraAreaPrefix,
        _ => Kind::Other,
    }
}

impl LsaBody {
    fn kind(&self) -> Kind {
        match self {
            LsaBody::Router(_) => Kind::Router,
            LsaBody::Network(_) => Kind::Network,
            LsaBody::Summary(_) => Kind::Summary,
            LsaBody::AsExternal(_) => Kind::AsExternal,
            LsaBody::RouterV3(_) => Kind::RouterV3,
            LsaBody::NetworkV3(_) => Kind::NetworkV3,
            LsaBody::InterAreaPrefix(_) => Kind::InterAreaPrefix,
            LsaBody::InterAreaRouter(_) => Kind::InterAreaRouter,
            LsaBody::AsExternalV3(_) => Kind::AsExternalV3,
            LsaBody::Link(_) => Kind::Link,
            LsaBody::IntraAreaPrefix(_) => Kind::IntraAreaPrefix,
            LsaBody::Other(_) => Kind::Other,
        }
    }

    /// Reads the body of an LSA of version `v` and LS type `ls_type`. The
    /// body must fill `b` exactly, and be no longer than an LSA can hold
    /// ([`Error::TooLong`] otherwise). Reserved bytes must be zero.
    pub fn parse(b: &[u8], v: Version, ls_type: u16) -> Result<LsaBody, Error> {
        if b.len() > MAX_LSA - LSA_HEADER_LEN {
            return Err(Error::TooLong);
        }
        let r = &mut Fields::new(b, Error::LsaBody);
        let body = match kind_for(v, ls_type) {
            Kind::Router => {
                let flags = r.u8()?;
                r.zero(1)?;
                let count = r.u16()?;
                let mut links = Vec::new();
                for _ in 0..count {
                    let id = r.ip4()?;
                    let data = r.ip4()?;
                    let kind = r.u8()?;
                    if !link_kind_ok(v, kind) {
                        return Err(Error::LsaBody);
                    }
                    let n = r.u8()?;
                    let metric = r.u16()?;
                    let mut tos = Vec::new();
                    for _ in 0..n {
                        let t = r.u8()?;
                        r.zero(1)?;
                        tos.push(TosMetric { tos: t, metric: r.u16()? });
                    }
                    links.push(RouterLink { id, data, kind, metric, tos });
                }
                LsaBody::Router(RouterLsa { flags, links })
            }
            Kind::Network => {
                let network_mask = r.ip4()?;
                let attached_routers = r.ip4_list()?;
                if attached_routers.is_empty() {
                    return Err(Error::LsaBody);
                }
                LsaBody::Network(NetworkLsa { network_mask, attached_routers })
            }
            Kind::Summary => {
                let network_mask = r.ip4()?;
                // Type 4 names a router, so its mask is zero (RFC 2328
                // appendix A.4.4).
                if ls_type == lsa_type_v2::SUMMARY_ASBR && !network_mask.is_unspecified() {
                    return Err(Error::LsaBody);
                }
                r.zero(1)?;
                let metric = r.u24()?;
                if !r.left().is_multiple_of(4) {
                    return Err(Error::LsaBody);
                }
                let mut tos = Vec::with_capacity(r.left() / 4);
                while r.left() > 0 {
                    tos.push((r.u8()?, r.u24()?));
                }
                LsaBody::Summary(SummaryLsa { network_mask, metric, tos })
            }
            Kind::AsExternal => {
                let network_mask = r.ip4()?;
                if !r.left().is_multiple_of(12) {
                    return Err(Error::LsaBody);
                }
                let mut routes = Vec::with_capacity(r.left() / 12);
                while r.left() > 0 {
                    let e = r.u8()?;
                    routes.push(ExternalRoute {
                        type2: e & 0x80 != 0,
                        tos: e & 0x7f,
                        metric: r.u24()?,
                        forwarding_address: r.ip4()?,
                        route_tag: r.u32()?,
                    });
                }
                // The TOS 0 route always comes first (RFC 2328 A.4.5).
                if routes.first().map(|x| x.tos) != Some(0) {
                    return Err(Error::LsaBody);
                }
                LsaBody::AsExternal(AsExternalLsa { network_mask, routes })
            }
            Kind::RouterV3 => {
                let flags = r.u8()?;
                let options = r.u24()?;
                if !r.left().is_multiple_of(16) {
                    return Err(Error::LsaBody);
                }
                let mut interfaces = Vec::with_capacity(r.left() / 16);
                while r.left() > 0 {
                    let kind = r.u8()?;
                    if !link_kind_ok(v, kind) {
                        return Err(Error::LsaBody);
                    }
                    r.zero(1)?;
                    interfaces.push(RouterInterface {
                        kind,
                        metric: r.u16()?,
                        interface_id: r.u32()?,
                        neighbor_interface_id: r.u32()?,
                        neighbor_router_id: r.ip4()?,
                    });
                }
                LsaBody::RouterV3(RouterLsaV3 { flags, options, interfaces })
            }
            Kind::NetworkV3 => {
                r.zero(1)?;
                let options = r.u24()?;
                let attached_routers = r.ip4_list()?;
                if attached_routers.is_empty() {
                    return Err(Error::LsaBody);
                }
                LsaBody::NetworkV3(NetworkLsaV3 { options, attached_routers })
            }
            Kind::InterAreaPrefix => {
                r.zero(1)?;
                let metric = r.u24()?;
                let (prefix, middle) = read_prefix(r)?;
                if middle != 0 {
                    return Err(Error::LsaBody);
                }
                LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric, prefix })
            }
            Kind::InterAreaRouter => {
                r.zero(1)?;
                let options = r.u24()?;
                r.zero(1)?;
                let metric = r.u24()?;
                LsaBody::InterAreaRouter(InterAreaRouterLsa { options, metric, destination: r.ip4()? })
            }
            Kind::AsExternalV3 => {
                let flags = r.u8()?;
                // Only E, F and T are defined.
                if flags & !0x07 != 0 {
                    return Err(Error::LsaBody);
                }
                let metric = r.u24()?;
                let (prefix, referenced_type) = read_prefix(r)?;
                let forwarding_address = if flags & 0x02 != 0 { Some(r.ip6()?) } else { None };
                if forwarding_address.is_some_and(|a| !forwarding_ok(a)) {
                    return Err(Error::LsaBody);
                }
                let route_tag = if flags & 0x01 != 0 { Some(r.u32()?) } else { None };
                let referenced = if referenced_type != 0 { Some((referenced_type, r.ip4()?)) } else { None };
                LsaBody::AsExternalV3(AsExternalLsaV3 {
                    type2: flags & 0x04 != 0,
                    metric,
                    prefix,
                    forwarding_address,
                    route_tag,
                    referenced,
                })
            }
            Kind::Link => {
                let priority = r.u8()?;
                let options = r.u24()?;
                let link_local_address = r.ip6()?;
                let count = r.u32()?;
                // Each prefix takes at least 4 bytes, so this loop stops
                // within the body's length.
                let mut prefixes = Vec::new();
                for _ in 0..count {
                    let (prefix, middle) = read_prefix(r)?;
                    if middle != 0 {
                        return Err(Error::LsaBody);
                    }
                    prefixes.push(prefix);
                }
                LsaBody::Link(LinkLsa { priority, options, link_local_address, prefixes })
            }
            Kind::IntraAreaPrefix => {
                let count = r.u16()?;
                let referenced_ls_type = r.u16()?;
                let referenced_link_state_id = r.ip4()?;
                let referenced_advertising_router = r.ip4()?;
                let mut prefixes = Vec::new();
                for _ in 0..count {
                    prefixes.push(read_prefix(r)?);
                }
                LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                    referenced_ls_type,
                    referenced_link_state_id,
                    referenced_advertising_router,
                    prefixes,
                })
            }
            Kind::Other => {
                r.cursor.rest();
                LsaBody::Other(b.to_vec())
            }
        };
        r.end()?;
        Ok(body)
    }

    /// Prepares an LSA body frame, for an LSA of version `v` and LS type `ls_type`.
    /// It fails with [`Error::Unwritable`] if the variant is not the one
    /// they call for, [`Error::Field`] if a value does not fit its
    /// field, and [`Error::TooLong`] past what an LSA can hold.
    pub fn frame(&self, v: Version, ls_type: u16) -> Result<LsaBodyFrame, Error> {
        if self.kind() != kind_for(v, ls_type) {
            return Err(Error::Unwritable);
        }
        let room = MAX_LSA - LSA_HEADER_LEN;
        let mut out = Vec::new();
        match self {
            LsaBody::Router(l) => {
                let count = u16::try_from(l.links.len()).map_err(|_| Error::Field)?;
                out.push(l.flags);
                out.push(0);
                out.extend_from_slice(&count.to_be_bytes());
                for link in &l.links {
                    let n = u8::try_from(link.tos.len()).map_err(|_| Error::Field)?;
                    if !link_kind_ok(v, link.kind) {
                        return Err(Error::Field);
                    }
                    out.extend_from_slice(&link.id.octets());
                    out.extend_from_slice(&link.data.octets());
                    out.push(link.kind);
                    out.push(n);
                    out.extend_from_slice(&link.metric.to_be_bytes());
                    for t in &link.tos {
                        out.extend_from_slice(&[t.tos, 0]);
                        out.extend_from_slice(&t.metric.to_be_bytes());
                    }
                    fits(&out, room)?;
                }
            }
            LsaBody::Network(n) => {
                if n.attached_routers.is_empty() {
                    return Err(Error::Field);
                }
                out.extend_from_slice(&n.network_mask.octets());
                put_ip4s(&mut out, &n.attached_routers, room)?;
            }
            LsaBody::Summary(s) => {
                if ls_type == lsa_type_v2::SUMMARY_ASBR && !s.network_mask.is_unspecified() {
                    return Err(Error::Field);
                }
                out.extend_from_slice(&s.network_mask.octets());
                out.push(0);
                put24(&mut out, s.metric)?;
                for &(tos, metric) in &s.tos {
                    out.push(tos);
                    put24(&mut out, metric)?;
                    fits(&out, room)?;
                }
            }
            LsaBody::AsExternal(e) => {
                if e.routes.first().map(|x| x.tos) != Some(0) {
                    return Err(Error::Field);
                }
                out.extend_from_slice(&e.network_mask.octets());
                for route in &e.routes {
                    if route.tos > 0x7f {
                        return Err(Error::Field);
                    }
                    out.push(route.tos | if route.type2 { 0x80 } else { 0 });
                    put24(&mut out, route.metric)?;
                    out.extend_from_slice(&route.forwarding_address.octets());
                    out.extend_from_slice(&route.route_tag.to_be_bytes());
                    fits(&out, room)?;
                }
            }
            LsaBody::RouterV3(l) => {
                out.push(l.flags);
                put24(&mut out, l.options)?;
                for i in &l.interfaces {
                    if !link_kind_ok(v, i.kind) {
                        return Err(Error::Field);
                    }
                    out.extend_from_slice(&[i.kind, 0]);
                    out.extend_from_slice(&i.metric.to_be_bytes());
                    out.extend_from_slice(&i.interface_id.to_be_bytes());
                    out.extend_from_slice(&i.neighbor_interface_id.to_be_bytes());
                    out.extend_from_slice(&i.neighbor_router_id.octets());
                    fits(&out, room)?;
                }
            }
            LsaBody::NetworkV3(n) => {
                if n.attached_routers.is_empty() {
                    return Err(Error::Field);
                }
                out.push(0);
                put24(&mut out, n.options)?;
                put_ip4s(&mut out, &n.attached_routers, room)?;
            }
            LsaBody::InterAreaPrefix(p) => {
                out.push(0);
                put24(&mut out, p.metric)?;
                put_prefix(&mut out, &p.prefix, 0)?;
            }
            LsaBody::InterAreaRouter(r) => {
                out.push(0);
                put24(&mut out, r.options)?;
                out.push(0);
                put24(&mut out, r.metric)?;
                out.extend_from_slice(&r.destination.octets());
            }
            LsaBody::AsExternalV3(e) => {
                let mut flags = 0;
                if e.type2 {
                    flags |= 0x04;
                }
                if e.forwarding_address.is_some() {
                    flags |= 0x02;
                }
                if e.route_tag.is_some() {
                    flags |= 0x01;
                }
                if e.forwarding_address.is_some_and(|a| !forwarding_ok(a)) {
                    return Err(Error::Field);
                }
                let referenced_type = match e.referenced {
                    Some((0, _)) => return Err(Error::Field),
                    Some((t, _)) => t,
                    None => 0,
                };
                out.push(flags);
                put24(&mut out, e.metric)?;
                put_prefix(&mut out, &e.prefix, referenced_type)?;
                if let Some(a) = e.forwarding_address {
                    out.extend_from_slice(&a.octets());
                }
                if let Some(t) = e.route_tag {
                    out.extend_from_slice(&t.to_be_bytes());
                }
                if let Some((_, id)) = e.referenced {
                    out.extend_from_slice(&id.octets());
                }
            }
            LsaBody::Link(l) => {
                out.push(l.priority);
                put24(&mut out, l.options)?;
                out.extend_from_slice(&l.link_local_address.octets());
                let count = u32::try_from(l.prefixes.len()).map_err(|_| Error::TooLong)?;
                out.extend_from_slice(&count.to_be_bytes());
                for p in &l.prefixes {
                    put_prefix(&mut out, p, 0)?;
                    fits(&out, room)?;
                }
            }
            LsaBody::IntraAreaPrefix(l) => {
                let count = u16::try_from(l.prefixes.len()).map_err(|_| Error::Field)?;
                out.extend_from_slice(&count.to_be_bytes());
                out.extend_from_slice(&l.referenced_ls_type.to_be_bytes());
                out.extend_from_slice(&l.referenced_link_state_id.octets());
                out.extend_from_slice(&l.referenced_advertising_router.octets());
                for (p, metric) in &l.prefixes {
                    put_prefix(&mut out, p, *metric)?;
                    fits(&out, room)?;
                }
            }
            LsaBody::Other(data) => {
                fits(data, room)?;
                out.extend_from_slice(data);
            }
        }
        fits(&out, room)?;
        Ok(LsaBodyFrame(out))
    }
}

impl Lsa {
    /// Reads the LSA at the start of `b`, and returns it with its length.
    /// The length field must fit in `b`, the Fletcher checksum must be
    /// right, and the body must fit its type exactly. A Network-LSA must
    /// list its advertising router. Bytes after the LSA are left alone.
    pub fn parse(b: &[u8], v: Version) -> Result<(Lsa, usize), Error> {
        if b.len() < LSA_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let length = be16(b, 18).ok_or(Error::Truncated)?;
        let n = usize::from(length);
        if !(LSA_HEADER_LEN..=b.len()).contains(&n) {
            return Err(Error::LsaLength(length));
        }
        let b = &b[..n];
        if !lsa_checksum_ok(b) {
            return Err(Error::LsaChecksum);
        }
        let h = read_lsa_header(&mut Fields::new(b, Error::Truncated), v)?;
        check_age_sequence(h.age, h.sequence)?;
        let body = LsaBody::parse(&b[LSA_HEADER_LEN..], v, h.ls_type)?;
        check_designated(&body, h.advertising_router)?;
        let lsa = Lsa {
            age: h.age,
            options: h.options,
            ls_type: h.ls_type,
            link_state_id: h.link_state_id,
            advertising_router: h.advertising_router,
            sequence: h.sequence,
            body,
        };
        Ok((lsa, n))
    }

    /// Prepares an LSA frame in version `v`, with its length and Fletcher
    /// checksum worked out.
    pub fn frame(&self, v: Version) -> Result<LsaFrame, Error> {
        check_age_sequence(self.age, self.sequence)?;
        let body = self.body.frame(v, self.ls_type).and_then(|frame| frame.to_bytes())?;
        check_designated(&self.body, self.advertising_router).map_err(|_| Error::Field)?;
        let mut out = Vec::with_capacity(LSA_HEADER_LEN + body.len());
        let header = LsaHeader {
            age: self.age,
            options: self.options,
            ls_type: self.ls_type,
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
            sequence: self.sequence,
            checksum: 0,
            // The body is at most MAX_LSA - LSA_HEADER_LEN bytes.
            length: (LSA_HEADER_LEN + body.len()) as u16,
        };
        put_lsa_header(&mut out, &header, v)?;
        out.extend_from_slice(&body);
        let c = lsa_checksum(&out).ok_or(Error::TooLong)?;
        out[16..18].copy_from_slice(&c.to_be_bytes());
        Ok(LsaFrame(out))
    }

    /// The LSA's header in version `v`, with the checksum and length its
    /// bytes have, as an acknowledgment or a database summary carries it.
    /// For an LSA read with [`Lsa::parse`] it is the header received.
    pub fn header(&self, v: Version) -> Result<LsaHeader, Error> {
        let bytes = self.frame(v).and_then(|frame| frame.to_bytes())?;
        read_lsa_header(&mut Fields::new(&bytes, Error::Truncated), v)
    }

    /// Which LSA this is, as a Link State Request asks for it.
    pub fn key(&self) -> LsaKey {
        LsaKey {
            ls_type: u32::from(self.ls_type),
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }
}

/// A Network-LSA comes from the network's designated router, which lists
/// itself among the attached routers (RFC 2328 appendix A.4.3, RFC 5340
/// appendix A.4.4).
fn check_designated(body: &LsaBody, advertising_router: Ipv4Addr) -> Result<(), Error> {
    let list = match body {
        LsaBody::Network(n) => &n.attached_routers,
        LsaBody::NetworkV3(n) => &n.attached_routers,
        _ => return Ok(()),
    };
    if list.contains(&advertising_router) { Ok(()) } else { Err(Error::LsaBody) }
}

/// The boundaries declared by a complete payload's headers.
struct Layout {
    /// Where the packet and its digest end.
    base: usize,
    /// Where the payload ends, including any signaling block.
    end: usize,
}

/// The ones' complement checksum of a link-local signaling block, with
/// its checksum field taken as zero.
fn lls_checksum(block: &[u8]) -> u16 {
    !fold(sum_words(0, &block[2..]))
}

/// Checks a complete payload's header and returns its declared end,
/// including any digest and link-local signaling block.
fn check_header(b: &[u8], endpoints: &Endpoints) -> Result<Layout, Error> {
    let base = check_base(b, endpoints)?;
    let v = endpoints.version();
    let len = usize::from(be16(b, 2).ok_or(Error::Truncated)?);
    // Where the options byte holding the L bit sits, and the bit.
    let l_at = match (v, b[1]) {
        (Version::V2, packet_type::HELLO) => Some((HEADER_LEN_V2 + 6, OPTION_L_V2)),
        (Version::V2, packet_type::DATABASE_DESCRIPTION) => Some((HEADER_LEN_V2 + 2, OPTION_L_V2)),
        (Version::V3, packet_type::HELLO) => Some((HEADER_LEN_V3 + 6, (OPTION_L_V3 >> 8) as u8)),
        (Version::V3, packet_type::DATABASE_DESCRIPTION) => Some((HEADER_LEN_V3 + 2, (OPTION_L_V3 >> 8) as u8)),
        _ => None,
    };
    // A packet too short to hold its options fails as a body anyway.
    let lls = match l_at {
        Some((at, bit)) if at < len => b.get(at).ok_or(Error::Truncated)? & bit != 0,
        _ => false,
    };
    // The L bit may be set without a block following the packet.
    if !lls || b.len() == base {
        return Ok(Layout { base, end: base });
    }
    if b.len() < base + 4 {
        return Err(Error::Truncated);
    }
    let words = usize::from(be16(b, base + 2).ok_or(Error::Truncated)?);
    let end = base + words * 4;
    if words == 0 || end > MAX_MESSAGE {
        return Err(Error::Lls);
    }
    Ok(Layout { base, end })
}

/// Checks the header through its length and authentication fields, then
/// returns where the packet and its digest end. Refuses missing fields.
fn check_base(b: &[u8], endpoints: &Endpoints) -> Result<usize, Error> {
    let &version = b.first().ok_or(Error::Truncated)?;
    if version != 2 && version != 3 {
        return Err(Error::Version(version));
    }
    let v = endpoints.version();
    if version != v.number() {
        return Err(Error::Family);
    }
    let &t = b.get(1).ok_or(Error::Truncated)?;
    if !(packet_type::HELLO..=packet_type::LINK_STATE_ACK).contains(&t) {
        return Err(Error::Type(t));
    }
    if b.len() < 4 {
        return Err(Error::Truncated);
    }
    let length = be16(b, 2).ok_or(Error::Truncated)?;
    if usize::from(length) < v.header_len() {
        return Err(Error::Length(length));
    }
    if v == Version::V3 {
        return Ok(usize::from(length));
    }
    if b.len() < 16 {
        return Err(Error::Truncated);
    }
    if be16(b, 14).ok_or(Error::Truncated)? != auth_type::CRYPTOGRAPHIC {
        return Ok(usize::from(length));
    }
    let &n = b.get(19).ok_or(Error::Truncated)?;
    Ok(usize::from(length) + usize::from(n))
}

impl Packet {
    /// Reads the packet in `b`, the whole OSPF payload of one IP packet
    /// sent from and to `endpoints`. The version must match the IP family,
    /// `b` must end where the length says (after the digest, with
    /// cryptographic authentication, and after the signaling block, if
    /// the L bit is set and one follows), the checksum must be right, the
    /// body must fit its type, and every LSA in an update must be framed
    /// by its length. A checksum of 0xffff is taken where 0x0000 is due,
    /// since the two are equal in ones' complement.
    pub fn parse(b: &[u8], endpoints: &Endpoints) -> Result<Packet, Error> {
        let layout = check_header(b, endpoints)?;
        let end = layout.end;
        if b.len() < end {
            return Err(Error::Truncated);
        }
        if b.len() > end {
            return Err(Error::Trailing { remaining: b.len() - end });
        }
        let v = endpoints.version();
        let len = usize::from(be16(b, 2).ok_or(Error::Truncated)?);
        let auth_kind = if v == Version::V2 { be16(b, 14).ok_or(Error::Truncated)? } else { 0 };
        if v == Version::V3 || auth_kind != auth_type::CRYPTOGRAPHIC {
            // The header check made sure the length fits in `b`.
            let want = checksum(b, endpoints).ok_or(Error::Truncated)?;
            if !same_checksum(want, be16(b, 12).ok_or(Error::Truncated)?) {
                return Err(Error::Checksum);
            }
        }
        let header = match v {
            Version::V2 => {
                let mut data = [0u8; 8];
                data.copy_from_slice(&b[16..24]);
                let auth = match auth_kind {
                    auth_type::NULL => Auth::Null,
                    auth_type::SIMPLE => Auth::Simple(data),
                    auth_type::CRYPTOGRAPHIC => Auth::Cryptographic {
                        key_id: b[18],
                        sequence: be32(b, 20).ok_or(Error::Truncated)?,
                        digest: b[len..layout.base].to_vec(),
                    },
                    kind => Auth::Other { kind, data },
                };
                Header::V2 { auth }
            }
            Version::V3 => Header::V3 { instance_id: b[14] },
        };
        let body = parse_body(&b[v.header_len()..len], v, b[1])?;
        // A block with a wrong checksum is dropped and the packet kept
        // (RFC 5613 section 2.2). With cryptographic authentication the
        // checksum is zero and not checked.
        let block = &b[layout.base..end];
        let lls = if block.is_empty() {
            None
        } else if auth_kind == auth_type::CRYPTOGRAPHIC || same_checksum(lls_checksum(block), be16(block, 0).ok_or(Error::Truncated)?) {
            Some(block[4..].to_vec())
        } else {
            None
        };
        Ok(Packet { router_id: Ipv4Addr::from(be32(b, 4).ok_or(Error::Truncated)?), area_id: Ipv4Addr::from(be32(b, 8).ok_or(Error::Truncated)?), header, lls, body })
    }

    /// The packet's version, from its header.
    pub fn version(&self) -> Version {
        match self.header {
            Header::V2 { .. } => Version::V2,
            Header::V3 { .. } => Version::V3,
        }
    }

    /// Prepares a packet frame, to send from and to `endpoints`, with the
    /// length and checksum worked out. It fails with
    /// [`Error::Family`] if the header's version does not match the
    /// IP family, [`Error::Unwritable`] if the body is not for this
    /// version, [`Error::Field`] if a value does not fit its field,
    /// [`Error::TooLong`] past [`MAX_PACKET`] (or [`MAX_MESSAGE`] with
    /// the digest and signaling block), and [`Error::Lls`] if `lls` is
    /// set on a packet other than a Hello or Database Description whose
    /// options set the L bit, or is not a multiple of 4 bytes.
    pub fn frame(&self, endpoints: &Endpoints) -> Result<Datagram, Error> {
        let v = self.version();
        if v != endpoints.version() {
            return Err(Error::Family);
        }
        let mut out = vec![0u8; v.header_len()];
        write_body(&mut out, &self.body, v)?;
        let len = u16::try_from(out.len()).map_err(|_| Error::TooLong)?;
        out[0] = v.number();
        out[1] = self.body.packet_type();
        out[2..4].copy_from_slice(&len.to_be_bytes());
        out[4..8].copy_from_slice(&self.router_id.octets());
        out[8..12].copy_from_slice(&self.area_id.octets());
        let mut digest: &[u8] = &[];
        match &self.header {
            Header::V2 { auth } => {
                out[14..16].copy_from_slice(&auth.kind().to_be_bytes());
                match auth {
                    Auth::Null => {}
                    Auth::Simple(p) => out[16..24].copy_from_slice(p),
                    Auth::Cryptographic { key_id, sequence, digest: d } => {
                        let n = u8::try_from(d.len()).map_err(|_| Error::Field)?;
                        out[18] = *key_id;
                        out[19] = n;
                        out[20..24].copy_from_slice(&sequence.to_be_bytes());
                        digest = d;
                    }
                    Auth::Other { kind, data } => {
                        if *kind <= auth_type::CRYPTOGRAPHIC {
                            return Err(Error::Unwritable);
                        }
                        out[16..24].copy_from_slice(data);
                    }
                }
            }
            Header::V3 { instance_id } => out[14] = *instance_id,
        }
        if !matches!(self.header, Header::V2 { auth: Auth::Cryptographic { .. } }) {
            let c = checksum(&out, endpoints).ok_or(Error::TooLong)?;
            out[12..14].copy_from_slice(&c.to_be_bytes());
        }
        out.extend_from_slice(digest);
        if let Some(tlvs) = &self.lls {
            let l_set = match &self.body {
                Body::HelloV2(h) => h.options & OPTION_L_V2 != 0,
                Body::HelloV3(h) => h.options & OPTION_L_V3 != 0,
                Body::DatabaseDescription(d) => match v {
                    Version::V2 => d.options & u32::from(OPTION_L_V2) != 0,
                    Version::V3 => d.options & OPTION_L_V3 != 0,
                },
                _ => false,
            };
            if !l_set || !tlvs.len().is_multiple_of(4) {
                return Err(Error::Lls);
            }
            if out.len().checked_add(4).and_then(|n| n.checked_add(tlvs.len())).is_none_or(|n| n > MAX_MESSAGE) {
                return Err(Error::TooLong);
            }
            let start = out.len();
            // At most MAX_MESSAGE / 4 words, so it fits in 16 bits.
            let words = ((4 + tlvs.len()) / 4) as u16;
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&words.to_be_bytes());
            out.extend_from_slice(tlvs);
            if !matches!(self.header, Header::V2 { auth: Auth::Cryptographic { .. } }) {
                let c = lls_checksum(&out[start..]);
                out[start..start + 2].copy_from_slice(&c.to_be_bytes());
            }
        }
        Ok(Datagram(out))
    }
}

fn parse_body(b: &[u8], v: Version, t: u8) -> Result<Body, Error> {
    let r = &mut Fields::new(b, Error::BodyLength);
    let body = match (t, v) {
        (packet_type::HELLO, Version::V2) => Body::HelloV2(HelloV2 {
            network_mask: r.ip4()?,
            hello_interval: r.u16()?,
            options: r.u8()?,
            priority: r.u8()?,
            dead_interval: r.u32()?,
            designated_router: r.ip4()?,
            backup_designated_router: r.ip4()?,
            neighbors: r.ip4_list()?,
        }),
        (packet_type::HELLO, Version::V3) => Body::HelloV3(HelloV3 {
            interface_id: r.u32()?,
            priority: r.u8()?,
            options: r.u24()?,
            hello_interval: r.u16()?,
            dead_interval: r.u16()?,
            designated_router: r.ip4()?,
            backup_designated_router: r.ip4()?,
            neighbors: r.ip4_list()?,
        }),
        (packet_type::DATABASE_DESCRIPTION, _) => {
            let (mtu, options, flags) = match v {
                Version::V2 => (r.u16()?, u32::from(r.u8()?), r.u8()?),
                Version::V3 => {
                    r.u8()?;
                    let options = r.u24()?;
                    let mtu = r.u16()?;
                    r.u8()?;
                    (mtu, options, r.u8()?)
                }
            };
            let sequence = r.u32()?;
            Body::DatabaseDescription(DatabaseDescription { mtu, options, flags, sequence, headers: r.header_list(v)? })
        }
        (packet_type::LINK_STATE_REQUEST, _) => {
            if !r.left().is_multiple_of(12) {
                return Err(Error::BodyLength);
            }
            let mut keys = Vec::with_capacity(r.left() / 12);
            while r.left() > 0 {
                let ls_type = match v {
                    Version::V2 => r.u32()?,
                    Version::V3 => {
                        r.u16()?;
                        u32::from(r.u16()?)
                    }
                };
                keys.push(LsaKey { ls_type, link_state_id: r.ip4()?, advertising_router: r.ip4()? });
            }
            Body::LinkStateRequest(keys)
        }
        (packet_type::LINK_STATE_UPDATE, _) => {
            let count = r.u32()?;
            let mut lsas = Vec::new();
            let mut framed: u64 = 0;
            while r.left() > 0 {
                if r.left() < LSA_HEADER_LEN {
                    return Err(Error::BodyLength);
                }
                let rest = &b[r.cursor.position()..];
                let length = be16(rest, 18).ok_or(Error::BodyLength)?;
                let n = usize::from(length);
                if !(LSA_HEADER_LEN..=rest.len()).contains(&n) {
                    return Err(Error::LsaLength(length));
                }
                // An LSA with a wrong checksum or a body that does not
                // read is dropped, and the next one read (RFC 2328
                // section 13, step 1).
                if let Ok((lsa, _)) = Lsa::parse(&rest[..n], v) {
                    lsas.push(lsa);
                }
                r.cursor.skip(n).map_err(|_| r.err)?;
                framed += 1;
            }
            if u64::from(count) != framed {
                return Err(Error::LsaCount);
            }
            Body::LinkStateUpdate(lsas)
        }
        (packet_type::LINK_STATE_ACK, _) => Body::LinkStateAck(r.header_list(v)?),
        // The header check allows only types 1 to 5.
        _ => return Err(Error::Type(t)),
    };
    r.end()?;
    Ok(body)
}

fn write_body(out: &mut Vec<u8>, body: &Body, v: Version) -> Result<(), Error> {
    match (body, v) {
        (Body::HelloV2(h), Version::V2) => {
            out.extend_from_slice(&h.network_mask.octets());
            out.extend_from_slice(&h.hello_interval.to_be_bytes());
            out.extend_from_slice(&[h.options, h.priority]);
            out.extend_from_slice(&h.dead_interval.to_be_bytes());
            out.extend_from_slice(&h.designated_router.octets());
            out.extend_from_slice(&h.backup_designated_router.octets());
            put_ip4s(out, &h.neighbors, MAX_PACKET)?;
        }
        (Body::HelloV3(h), Version::V3) => {
            out.extend_from_slice(&h.interface_id.to_be_bytes());
            out.push(h.priority);
            put24(out, h.options)?;
            out.extend_from_slice(&h.hello_interval.to_be_bytes());
            out.extend_from_slice(&h.dead_interval.to_be_bytes());
            out.extend_from_slice(&h.designated_router.octets());
            out.extend_from_slice(&h.backup_designated_router.octets());
            put_ip4s(out, &h.neighbors, MAX_PACKET)?;
        }
        (Body::HelloV2(_) | Body::HelloV3(_), _) => return Err(Error::Unwritable),
        (Body::DatabaseDescription(d), _) => {
            match v {
                Version::V2 => {
                    let options = u8::try_from(d.options).map_err(|_| Error::Field)?;
                    out.extend_from_slice(&d.mtu.to_be_bytes());
                    out.extend_from_slice(&[options, d.flags]);
                }
                Version::V3 => {
                    out.push(0);
                    put24(out, d.options)?;
                    out.extend_from_slice(&d.mtu.to_be_bytes());
                    out.extend_from_slice(&[0, d.flags]);
                }
            }
            out.extend_from_slice(&d.sequence.to_be_bytes());
            for h in &d.headers {
                check_lsa_header(h)?;
                put_lsa_header(out, h, v)?;
                fits(out, MAX_PACKET)?;
            }
        }
        (Body::LinkStateRequest(keys), _) => {
            for k in keys {
                match v {
                    Version::V2 => out.extend_from_slice(&k.ls_type.to_be_bytes()),
                    Version::V3 => {
                        let t = u16::try_from(k.ls_type).map_err(|_| Error::Field)?;
                        out.extend_from_slice(&[0, 0]);
                        out.extend_from_slice(&t.to_be_bytes());
                    }
                }
                out.extend_from_slice(&k.link_state_id.octets());
                out.extend_from_slice(&k.advertising_router.octets());
                fits(out, MAX_PACKET)?;
            }
        }
        (Body::LinkStateUpdate(lsas), _) => {
            let count = u32::try_from(lsas.len()).map_err(|_| Error::TooLong)?;
            out.extend_from_slice(&count.to_be_bytes());
            for lsa in lsas {
                out.extend_from_slice(&lsa.frame(v).and_then(|frame| frame.to_bytes())?);
                fits(out, MAX_PACKET)?;
            }
        }
        (Body::LinkStateAck(headers), _) => {
            for h in headers {
                check_lsa_header(h)?;
                put_lsa_header(out, h, v)?;
                fits(out, MAX_PACKET)?;
            }
        }
    }
    fits(out, MAX_PACKET)
}

// Writing.

fn fits(out: &[u8], max: usize) -> Result<(), Error> {
    if out.len() > max { Err(Error::TooLong) } else { Ok(()) }
}

fn put24(out: &mut Vec<u8>, v: u32) -> Result<(), Error> {
    if v > MAX_U24 {
        return Err(Error::Field);
    }
    out.extend_from_slice(&v.to_be_bytes()[1..]);
    Ok(())
}

fn put_ip4s(out: &mut Vec<u8>, list: &[Ipv4Addr], max: usize) -> Result<(), Error> {
    for a in list {
        out.extend_from_slice(&a.octets());
        fits(out, max)?;
    }
    Ok(())
}

fn put_prefix(out: &mut Vec<u8>, p: &Prefix, middle: u16) -> Result<(), Error> {
    if p.length > MAX_PREFIX_LEN || u128::from(p.address) & !prefix_mask(p.length) != 0 {
        return Err(Error::Field);
    }
    out.extend_from_slice(&[p.length, p.options]);
    out.extend_from_slice(&middle.to_be_bytes());
    out.extend_from_slice(&p.address.octets()[..prefix_bytes(p.length)]);
    Ok(())
}

fn put_lsa_header(out: &mut Vec<u8>, h: &LsaHeader, v: Version) -> Result<(), Error> {
    out.extend_from_slice(&h.age.to_be_bytes());
    match v {
        Version::V2 => {
            let t = u8::try_from(h.ls_type).map_err(|_| Error::Field)?;
            out.extend_from_slice(&[h.options, t]);
        }
        Version::V3 => {
            if h.options != 0 {
                return Err(Error::Field);
            }
            out.extend_from_slice(&h.ls_type.to_be_bytes());
        }
    }
    out.extend_from_slice(&h.link_state_id.octets());
    out.extend_from_slice(&h.advertising_router.octets());
    out.extend_from_slice(&h.sequence.to_be_bytes());
    out.extend_from_slice(&h.checksum.to_be_bytes());
    out.extend_from_slice(&h.length.to_be_bytes());
    Ok(())
}

/// Implements byte-preserving [`Wire`] for a named tuple payload with a byte limit.
/// The payload stores a `Vec<u8>` in its first field. Its OSPF parser
/// supplies any context that is absent from the bytes.
macro_rules! bounded_datagram_wire {
    ($unit:ty, $error:ty, $too_long:expr, $limit:expr) => {
        impl Wire for $unit {
            type ParseError = $error;
            type WriteError = $error;

            /// Copies a complete payload. Refuses bytes above this unit's
            /// documented limit. Protocol and checksum checks require its
            /// contextual parser.
            fn parse(bytes: &[u8]) -> Result<Self, $error> {
                if bytes.len() > $limit { return Err($too_long); }
                Ok(Self(bytes.to_vec()))
            }

            /// Appends the payload unchanged. Refuses values above this
            /// unit's documented limit. Leaves `out` unchanged on error.
            /// Does not compute or validate a checksum.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), $error> {
                if self.0.len() > $limit { return Err($too_long); }
                out.extend_from_slice(&self.0);
                Ok(())
            }
        }
    };
}

/// One bounded IP payload, with every received byte preserved.
///
/// [`Wire`] reads the entire payload and checks only
/// [`MAX_MESSAGE`]. It does not validate an OSPF message or its checksum.
/// Use [`Packet::parse`] with the packet's [`Endpoints`] for that check.
/// The endpoints are not encoded in this payload.
///
/// ```
/// use fictionet::stdlib::{codec::{Collect, Decode, Stream}, ospf};
/// # let endpoints = ospf::Endpoints::V4 {
/// #     source: "192.0.2.1".parse().unwrap(),
/// #     destination: "224.0.0.1".parse().unwrap(),
/// # };
/// let messages = Collect::<ospf::Datagram>::new(ospf::MAX_MESSAGE)
///     .map(move |datagram| ospf::Packet::parse(&datagram.0, &endpoints));
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

bounded_datagram_wire!(Datagram, Error, Error::TooLong, MAX_MESSAGE);

/// An LSA's bytes, interpreted with a separate [`Version`].
/// Construct with [`Lsa::frame`] or copy a bounded payload with [`Wire::parse`].
/// Use [`Lsa::parse`] to validate its fields and Fletcher checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LsaFrame(
    /// Complete LSA bytes, at most [`MAX_LSA`].
    pub Vec<u8>,
);
bounded_datagram_wire!(LsaFrame, Error, Error::TooLong, MAX_LSA);

/// An LSA body's bytes, interpreted with a separate version and LS type.
/// Construct with [`LsaBody::frame`] or copy a bounded payload with [`Wire::parse`].
/// Use [`LsaBody::parse`] to validate its fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LsaBodyFrame(
    /// Body bytes, at most [`MAX_LSA`] minus [`LSA_HEADER_LEN`].
    pub Vec<u8>,
);
bounded_datagram_wire!(LsaBodyFrame, Error, Error::TooLong, MAX_LSA - LSA_HEADER_LEN);

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Collect, CollectError, Fail, Lcg,
    };
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn collect(b: &[u8], e: &Endpoints) -> Result<Packet, Error> {
        use fictionet::stdlib::codec::Decode;
        let make = || Collect::<Datagram>::new(MAX_MESSAGE).map(|d| Packet::parse(&d.0, e));
        contract::check_decode_with_alloc_limit(make, b, 2 * (MAX_MESSAGE + 1));
        contract::check_wire::<Datagram>(b);
        let parsed = Packet::parse(b, e);
        let (items, failure) = decode_all(make, b);
        if b.len() <= MAX_MESSAGE {
            assert_eq!(failure, None);
            assert_eq!(items, vec![parsed.clone()]);
        } else {
            assert_eq!(failure, Some(Fail::Protocol(CollectError::TooLong { limit: MAX_MESSAGE })));
        }
        parsed
    }

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn v4_ends() -> Endpoints {
        Endpoints::V4 { source: ip4(10, 0, 0, 1), destination: ALL_SPF_ROUTERS_V4 }
    }

    fn v6_ends() -> Endpoints {
        Endpoints::V6 { source: "fe80::1".parse().unwrap(), destination: ALL_SPF_ROUTERS_V6 }
    }

    /// `b` with its packet checksum set right.
    fn fix(mut b: Vec<u8>, e: &Endpoints) -> Vec<u8> {
        if let Some(c) = checksum(&b, e) {
            b[12..14].copy_from_slice(&c.to_be_bytes());
        }
        b
    }

    /// `b` with its LSA checksum set right.
    fn fix_lsa(mut b: Vec<u8>) -> Vec<u8> {
        if let Some(c) = lsa_checksum(&b) {
            b[16..18].copy_from_slice(&c.to_be_bytes());
        }
        b
    }

    fn hello_v2(me: Ipv4Addr, heard: Vec<Ipv4Addr>) -> Packet {
        Packet {
            router_id: me,
            area_id: Ipv4Addr::UNSPECIFIED,
            header: Header::V2 { auth: Auth::Null },
            lls: None,
            body: Body::HelloV2(HelloV2 {
                network_mask: ip4(255, 255, 255, 0),
                hello_interval: 10,
                options: 0x02,
                priority: 1,
                dead_interval: 40,
                designated_router: Ipv4Addr::UNSPECIFIED,
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: heard,
            }),
        }
    }

    #[test]
    fn module_example() {
        let link = v4_ends();
        let bytes = [
            2, 1, 0, 44, 1, 1, 1, 1, 0, 0, 0, 0, 0xfa, 0x9c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            255, 255, 255, 0, 0, 10, 0x02, 1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let packet = Packet::parse(&bytes, &link).unwrap();
        assert_eq!(packet, hello_v2(ip4(1, 1, 1, 1), vec![]));
        assert_eq!(packet.frame(&link).and_then(|frame| frame.to_bytes()).unwrap(), bytes);
        let reply = hello_v2(ip4(2, 2, 2, 2), vec![packet.router_id]);
        let sent = reply.frame(&link).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(sent.len(), 48);
        assert_eq!(Packet::parse(&sent, &link), Ok(reply));
        let mut bad = bytes;
        bad[30] ^= 1;
        assert_eq!(Packet::parse(&bad, &link), Err(Error::Checksum));
    }

    #[test]
    fn v2_hello_with_neighbors_and_password() {
        // A Hello from 192.168.1.1 in area 0.0.0.1, with password "secret",
        // naming 192.168.1.2 as DR and listing two neighbors. The checksum
        // skips the password.
        let p = Packet {
            router_id: ip4(192, 168, 1, 1),
            area_id: ip4(0, 0, 0, 1),
            header: Header::V2 { auth: Auth::Simple(*b"secret\0\0") },
            lls: None,
            body: Body::HelloV2(HelloV2 {
                network_mask: ip4(255, 255, 255, 0),
                hello_interval: 10,
                options: 0x12,
                priority: 1,
                dead_interval: 40,
                designated_router: ip4(192, 168, 1, 2),
                backup_designated_router: ip4(192, 168, 1, 1),
                neighbors: vec![ip4(2, 2, 2, 2), ip4(3, 3, 3, 3)],
            }),
        };
        let b = p.frame(&v4_ends()).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(&b[..4], &[2, 1, 0, 52]);
        assert_eq!(&b[14..24], b"\0\x01secret\0\0");
        assert_eq!(&b[12..14], &[0x9d, 0x8c]);
        assert_eq!(Packet::parse(&b, &v4_ends()), Ok(p));
        // The password is outside the checksum.
        let mut other = b.clone();
        other[16] = b'S';
        assert!(Packet::parse(&other, &v4_ends()).is_ok());
    }

    #[test]
    fn v3_hello_example() {
        // An OSPFv3 Hello from fe80::1, router 1.1.1.1, interface 5. The
        // checksum covers the IPv6 pseudo-header.
        let bytes = [
            3, 1, 0, 36, 1, 1, 1, 1, 0, 0, 0, 0, 0xfb, 0x87, 0, 0, // header
            0, 0, 0, 5, 1, 0, 0, 0x13, 0, 10, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, // Hello
        ];
        let p = Packet::parse(&bytes, &v6_ends()).unwrap();
        assert_eq!(
            p,
            Packet {
                router_id: ip4(1, 1, 1, 1),
                area_id: Ipv4Addr::UNSPECIFIED,
                header: Header::V3 { instance_id: 0 },
                lls: None,
                body: Body::HelloV3(HelloV3 {
                    interface_id: 5,
                    priority: 1,
                    options: 0x13,
                    hello_interval: 10,
                    dead_interval: 40,
                    designated_router: Ipv4Addr::UNSPECIFIED,
                    backup_designated_router: Ipv4Addr::UNSPECIFIED,
                    neighbors: vec![],
                }),
            }
        );
        assert_eq!(p.frame(&v6_ends()).and_then(|frame| frame.to_bytes()).unwrap(), bytes);
        // Another source address changes the pseudo-header.
        let elsewhere = Endpoints::V6 { source: "fe80::2".parse().unwrap(), destination: ALL_SPF_ROUTERS_V6 };
        assert_eq!(Packet::parse(&bytes, &elsewhere), Err(Error::Checksum));
    }

    #[test]
    fn router_lsa_fletcher_example() {
        // A Router-LSA from 1.1.1.1 with one stub link to 10.0.0.0/24 at
        // cost 10. Its checksum was worked out separately, with the RFC
        // 905 annex B formulas.
        let bytes = [
            0, 1, 0x22, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x80, 0, 0, 1, 0x97, 0x7f, 0, 36, // header
            0, 0, 0, 1, 10, 0, 0, 0, 255, 255, 255, 0, 3, 0, 0, 10,
        ];
        assert_eq!(lsa_checksum(&bytes), Some(0x977f));
        assert!(lsa_checksum_ok(&bytes));
        let (lsa, n) = Lsa::parse(&bytes, Version::V2).unwrap();
        assert_eq!(n, 36);
        assert_eq!(
            lsa,
            Lsa {
                age: 1,
                options: 0x22,
                ls_type: 1,
                link_state_id: ip4(1, 1, 1, 1),
                advertising_router: ip4(1, 1, 1, 1),
                sequence: INITIAL_SEQUENCE,
                body: LsaBody::Router(RouterLsa {
                    flags: 0,
                    links: vec![RouterLink {
                        id: ip4(10, 0, 0, 0),
                        data: ip4(255, 255, 255, 0),
                        kind: 3,
                        metric: 10,
                        tos: vec![],
                    }],
                }),
            }
        );
        assert_eq!(lsa.frame(Version::V2).and_then(|frame| frame.to_bytes()).unwrap(), bytes);
        // The age is outside the checksum, so routers can age LSAs.
        let mut older = bytes;
        older[1] = 200;
        assert!(lsa_checksum_ok(&older));
        let mut bad = bytes;
        bad[30] ^= 1;
        assert_eq!(Lsa::parse(&bad, Version::V2), Err(Error::LsaChecksum));
        let h = lsa.header(Version::V2).unwrap();
        assert_eq!((h.checksum, h.length), (0x977f, 36));
    }

    #[test]
    fn fletcher_holds_for_all_lengths() {
        let mut rng = Lcg::new(7);
        for len in LSA_HEADER_LEN..300 {
            let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            b[18..20].copy_from_slice(&(len as u16).to_be_bytes());
            let b = fix_lsa(b);
            assert!(lsa_checksum_ok(&b), "{len}");
            assert_ne!(b[16], 0);
            assert_ne!(b[17], 0);
        }
        // A zero checksum is never right.
        let mut zero = vec![0u8; 20];
        zero[19] = 20;
        assert!(!lsa_checksum_ok(&zero));
        assert_eq!(lsa_checksum(&zero[..19]), None);
        zero[19] = 19;
        assert_eq!(lsa_checksum(&zero), None);
        zero[19] = 21;
        assert_eq!(lsa_checksum(&zero), None);
    }

    fn pfx(len: u8, a: &str) -> Prefix {
        Prefix { length: len, options: 0, address: a.parse().unwrap() }
    }

    fn lsa(ls_type: u16, body: LsaBody) -> Lsa {
        Lsa {
            age: 3,
            options: 0,
            ls_type,
            link_state_id: ip4(0, 0, 0, 1),
            advertising_router: ip4(1, 1, 1, 1),
            sequence: INITIAL_SEQUENCE + 4,
            body,
        }
    }

    fn v2_lsas() -> Vec<Lsa> {
        let mut router = lsa(
            lsa_type_v2::ROUTER,
            LsaBody::Router(RouterLsa {
                flags: 0x01,
                links: vec![
                    RouterLink {
                        id: ip4(2, 2, 2, 2),
                        data: ip4(10, 0, 0, 1),
                        kind: 1,
                        metric: 10,
                        tos: vec![TosMetric { tos: 2, metric: 7 }],
                    },
                    RouterLink {
                        id: ip4(10, 0, 0, 0),
                        data: ip4(255, 255, 255, 252),
                        kind: 3,
                        metric: 10,
                        tos: vec![],
                    },
                ],
            }),
        );
        router.options = 0x22;
        vec![
            router,
            lsa(
                lsa_type_v2::NETWORK,
                LsaBody::Network(NetworkLsa {
                    network_mask: ip4(255, 255, 255, 0),
                    attached_routers: vec![ip4(1, 1, 1, 1), ip4(2, 2, 2, 2)],
                }),
            ),
            lsa(
                lsa_type_v2::SUMMARY_NETWORK,
                LsaBody::Summary(SummaryLsa {
                    network_mask: ip4(255, 255, 0, 0),
                    metric: 0x0f_0000,
                    tos: vec![(4, 9)],
                }),
            ),
            lsa(
                lsa_type_v2::SUMMARY_ASBR,
                LsaBody::Summary(SummaryLsa { network_mask: Ipv4Addr::UNSPECIFIED, metric: 20, tos: vec![] }),
            ),
            lsa(
                lsa_type_v2::AS_EXTERNAL,
                LsaBody::AsExternal(AsExternalLsa {
                    network_mask: ip4(255, 255, 255, 0),
                    routes: vec![ExternalRoute {
                        type2: true,
                        tos: 0,
                        metric: 20,
                        forwarding_address: Ipv4Addr::UNSPECIFIED,
                        route_tag: 42,
                    }],
                }),
            ),
            lsa(
                lsa_type_v2::NSSA,
                LsaBody::AsExternal(AsExternalLsa {
                    network_mask: ip4(255, 0, 0, 0),
                    routes: vec![ExternalRoute {
                        type2: false,
                        tos: 0,
                        metric: 1,
                        forwarding_address: ip4(10, 0, 0, 9),
                        route_tag: 0,
                    }],
                }),
            ),
            lsa(10, LsaBody::Other(vec![1, 2, 3, 4, 5])),
        ]
    }

    fn v3_lsas() -> Vec<Lsa> {
        vec![
            lsa(
                lsa_type_v3::ROUTER,
                LsaBody::RouterV3(RouterLsaV3 {
                    flags: 0x02,
                    options: 0x13,
                    interfaces: vec![RouterInterface {
                        kind: 2,
                        metric: 1,
                        interface_id: 5,
                        neighbor_interface_id: 6,
                        neighbor_router_id: ip4(2, 2, 2, 2),
                    }],
                }),
            ),
            lsa(
                lsa_type_v3::NETWORK,
                LsaBody::NetworkV3(NetworkLsaV3 { options: 0x13, attached_routers: vec![ip4(1, 1, 1, 1)] }),
            ),
            lsa(
                lsa_type_v3::INTER_AREA_PREFIX,
                LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric: 30, prefix: pfx(64, "2001:db8:1::") }),
            ),
            lsa(
                lsa_type_v3::INTER_AREA_ROUTER,
                LsaBody::InterAreaRouter(InterAreaRouterLsa { options: 0x13, metric: 5, destination: ip4(9, 9, 9, 9) }),
            ),
            lsa(
                lsa_type_v3::AS_EXTERNAL,
                LsaBody::AsExternalV3(AsExternalLsaV3 {
                    type2: true,
                    metric: 20,
                    prefix: pfx(48, "2001:db8:2::"),
                    forwarding_address: Some("2001:db8::9".parse().unwrap()),
                    route_tag: Some(7),
                    referenced: Some((0x2001, ip4(0, 0, 0, 3))),
                }),
            ),
            lsa(
                lsa_type_v3::NSSA,
                LsaBody::AsExternalV3(AsExternalLsaV3 {
                    type2: false,
                    metric: 1,
                    prefix: pfx(0, "::"),
                    forwarding_address: None,
                    route_tag: None,
                    referenced: None,
                }),
            ),
            lsa(
                lsa_type_v3::LINK,
                LsaBody::Link(LinkLsa {
                    priority: 1,
                    options: 0x13,
                    link_local_address: "fe80::1".parse().unwrap(),
                    prefixes: vec![pfx(64, "2001:db8:3::"), pfx(128, "2001:db8::1")],
                }),
            ),
            lsa(
                lsa_type_v3::INTRA_AREA_PREFIX,
                LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                    referenced_ls_type: lsa_type_v3::ROUTER,
                    referenced_link_state_id: Ipv4Addr::UNSPECIFIED,
                    referenced_advertising_router: ip4(1, 1, 1, 1),
                    prefixes: vec![(pfx(96, "2001:db8:4::"), 10), (pfx(33, "2001:db8:8000::"), 1)],
                }),
            ),
            lsa(0x0010, LsaBody::Other(vec![])),
        ]
    }

    fn header_of(l: &Lsa, v: Version) -> LsaHeader {
        l.header(v).unwrap()
    }

    fn packets(v: Version) -> Vec<Packet> {
        let lsas = match v {
            Version::V2 => v2_lsas(),
            Version::V3 => v3_lsas(),
        };
        let headers: Vec<LsaHeader> = lsas.iter().map(|l| header_of(l, v)).collect();
        let header = match v {
            Version::V2 => Header::V2 { auth: Auth::Null },
            Version::V3 => Header::V3 { instance_id: 0 },
        };
        let hello = match v {
            Version::V2 => hello_v2(ip4(1, 1, 1, 1), vec![ip4(2, 2, 2, 2)]).body,
            Version::V3 => Body::HelloV3(HelloV3 {
                interface_id: 1,
                priority: 1,
                options: 0x13,
                hello_interval: 10,
                dead_interval: 40,
                designated_router: ip4(1, 1, 1, 1),
                backup_designated_router: Ipv4Addr::UNSPECIFIED,
                neighbors: vec![ip4(2, 2, 2, 2)],
            }),
        };
        let bodies = vec![
            hello,
            Body::DatabaseDescription(DatabaseDescription {
                mtu: 1500,
                options: 0x02,
                flags: dd_flags::INIT | dd_flags::MORE | dd_flags::MS,
                sequence: 0x1234,
                headers: vec![],
            }),
            Body::DatabaseDescription(DatabaseDescription {
                mtu: 1500,
                options: 0x02,
                flags: dd_flags::MORE,
                sequence: 0x1235,
                headers: headers.clone(),
            }),
            Body::LinkStateRequest(lsas.iter().map(|l| l.key()).collect()),
            Body::LinkStateUpdate(lsas.clone()),
            Body::LinkStateUpdate(vec![]),
            Body::LinkStateAck(headers),
        ];
        let mut out: Vec<Packet> = bodies
            .into_iter()
            .map(|body| Packet {
                router_id: ip4(1, 1, 1, 1),
                area_id: ip4(0, 0, 0, 0),
                header: header.clone(),
                lls: None,
                body,
            })
            .collect();
        if v == Version::V2 {
            let mut auths = vec![
                Auth::Simple(*b"password"),
                Auth::Cryptographic { key_id: 1, sequence: 99, digest: vec![0xaa; 16] },
                Auth::Cryptographic { key_id: 2, sequence: 1, digest: vec![] },
                Auth::Other { kind: 9, data: [1; 8] },
            ];
            for a in auths.drain(..) {
                let mut p = out[0].clone();
                p.header = Header::V2 { auth: a };
                out.push(p);
            }
        } else {
            let mut p = out[0].clone();
            p.header = Header::V3 { instance_id: 7 };
            out.push(p);
        }
        out
    }

    fn samples() -> Vec<(Packet, Endpoints)> {
        let mut out = Vec::new();
        for p in packets(Version::V2) {
            out.push((p, v4_ends()));
        }
        for p in packets(Version::V3) {
            out.push((p, v6_ends()));
        }
        out
    }

    #[test]
    fn round_trips() {
        for (p, e) in samples() {
            let b = p.frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
            assert_eq!(Packet::parse(&b, &e).as_ref(), Ok(&p), "{p:?}");
            assert_eq!(collect(&b, &e).as_ref(), Ok(&p));
            assert_eq!(Packet::parse(&b, &e).unwrap().frame(&e).and_then(|frame| frame.to_bytes()).unwrap(), b);
        }
        for (lsas, v) in [(v2_lsas(), Version::V2), (v3_lsas(), Version::V3)] {
            for l in lsas {
                let b = l.frame(v).and_then(|frame| frame.to_bytes()).unwrap();
                assert!(lsa_checksum_ok(&b));
                assert_eq!(Lsa::parse(&b, v), Ok((l, b.len())));
            }
        }
    }

    #[test]
    fn prefixes_send_only_the_words_they_need() {
        let l = &v3_lsas()[7];
        let b = l.frame(Version::V3).and_then(|frame| frame.to_bytes()).unwrap();
        // Header, 12 fixed bytes, then 4 + 12 and 4 + 8 bytes of prefixes.
        assert_eq!(b.len(), 20 + 12 + 16 + 12);
        let p = Prefix::new(1, 0, "ffff::1".parse().unwrap());
        let ia =
            lsa(lsa_type_v3::INTER_AREA_PREFIX, LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric: 0, prefix: p }));
        let b = ia.frame(Version::V3).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(b.len(), 20 + 4 + 4 + 4);
        assert_eq!(&b[24..32], &[1, 0, 0, 0, 0x80, 0, 0, 0]);
        assert_eq!(Lsa::parse(&b, Version::V3), Ok((ia, b.len())));
    }

    #[test]
    fn prefix_bits_past_the_length_are_zero() {
        // RFC 5340 appendix A.4.1: the padding is zero. A writer refuses an
        // address with bits past the length instead of dropping them.
        for (length, a) in [(1, "ffff::1"), (64, "2001:db8::1"), (0, "::1"), (33, "2001:db8:c000::")] {
            let p = Prefix { length, options: 0, address: a.parse().unwrap() };
            let ia = lsa(
                lsa_type_v3::INTER_AREA_PREFIX,
                LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric: 0, prefix: p }),
            );
            assert_eq!(ia.frame(Version::V3).and_then(|frame| frame.to_bytes()), Err(Error::Field), "{a}/{length}");
        }
        // A reader rejects one: ffff::/1 sent as ff ff 00 00.
        let body = [0, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0, 0];
        assert_eq!(LsaBody::parse(&body, Version::V3, lsa_type_v3::INTER_AREA_PREFIX), Err(Error::LsaBody));
        let body = [0, 0, 0, 0, 1, 0, 0, 0, 0x80, 0, 0, 0];
        assert!(LsaBody::parse(&body, Version::V3, lsa_type_v3::INTER_AREA_PREFIX).is_ok());
    }

    #[test]
    fn prefix_new_clears_the_host_bits() {
        let a: Ipv6Addr = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(Prefix::new(64, 0, a), pfx(64, "2001:db8:ffff:ffff::"));
        assert_eq!(Prefix::new(0, 0, a).address, Ipv6Addr::UNSPECIFIED);
        assert_eq!(Prefix::new(128, 0, a).address, a);
        assert_eq!(Prefix::new(33, 0, a).address, "2001:db8:8000::".parse::<Ipv6Addr>().unwrap());
        // A length past 128 is kept, for the writer to reject.
        assert_eq!(Prefix::new(200, 0, a), Prefix { length: 200, options: 0, address: a });
        // A prefix made with new reads back equal for every length, even
        // from an address with every bit set.
        for length in 0..=MAX_PREFIX_LEN {
            let p = Prefix::new(length, 0x10, Ipv6Addr::from(u128::MAX));
            let l = lsa(
                lsa_type_v3::INTER_AREA_PREFIX,
                LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric: 1, prefix: p }),
            );
            let b = l.frame(Version::V3).and_then(|frame| frame.to_bytes()).unwrap();
            assert_eq!(Lsa::parse(&b, Version::V3), Ok((l, b.len())), "{length}");
        }
    }

    #[test]
    fn header_errors() {
        let e4 = v4_ends();
        let e6 = v6_ends();
        let good = hello_v2(ip4(1, 1, 1, 1), vec![]).frame(&e4).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(Packet::parse(&[], &e4), Err(Error::Truncated));
        let mut b = good.clone();
        b[0] = 4;
        assert_eq!(Packet::parse(&b, &e4), Err(Error::Version(4)));
        assert_eq!(Packet::parse(&good, &e6), Err(Error::Family));
        b = good.clone();
        b[1] = 6;
        assert_eq!(Packet::parse(&b, &e4), Err(Error::Type(6)));
        b[1] = 0;
        assert_eq!(Packet::parse(&b, &e4), Err(Error::Type(0)));
        b = good.clone();
        b[2..4].copy_from_slice(&23u16.to_be_bytes());
        assert_eq!(Packet::parse(&b, &e4), Err(Error::Length(23)));
        b[2..4].copy_from_slice(&45u16.to_be_bytes());
        assert_eq!(Packet::parse(&b, &e4), Err(Error::Truncated));
        b = good.clone();
        b.push(0);
        assert_eq!(
            Packet::parse(&b, &e4),
            Err(Error::Trailing { remaining: 1 })
        );
        b = good.clone();
        b[12] ^= 0x10;
        assert_eq!(Packet::parse(&b, &e4), Err(Error::Checksum));
        // A v3 header shorter than 16.
        let mut v3 = vec![3, 1, 0, 15];
        v3.resize(15, 0);
        assert_eq!(Packet::parse(&v3, &e6), Err(Error::Length(15)));
        assert_eq!(Packet::parse(&[3], &e4), Err(Error::Family));
    }

    #[test]
    fn negative_zero_checksum() {
        // Search for a packet whose checksum is 0x0000 or 0xffff, and check
        // the other form is taken too.
        let e = v4_ends();
        let mut found = 0;
        for id in 0..=0xffffu32 {
            let p = Packet { router_id: Ipv4Addr::from(id), ..hello_v2(ip4(0, 0, 0, 0), vec![]) };
            let mut b = p.frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
            let c = be16(&b, 12).unwrap();
            if c == 0 || c == 0xffff {
                b[12..14].copy_from_slice(&(!c).to_be_bytes());
                assert_eq!(Packet::parse(&b, &e), Ok(p));
                found += 1;
            }
        }
        assert!(found > 0);
        assert!(same_checksum(0, 0xffff));
        assert!(!same_checksum(0x00ff, 0xff00));
    }

    #[test]
    fn crypto_auth_skips_the_checksum() {
        let e = v4_ends();
        let mut p = hello_v2(ip4(1, 1, 1, 1), vec![]);
        p.header = Header::V2 { auth: Auth::Cryptographic { key_id: 3, sequence: 77, digest: vec![9; 16] } };
        let b = p.frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(b.len(), 44 + 16);
        assert_eq!(&b[12..24], &[0, 0, 0, 2, 0, 0, 3, 16, 0, 0, 0, 77]);
        assert_eq!(Packet::parse(&b, &e), Ok(p.clone()));
        // The digest's length is in the header, so a short or long one fails.
        assert_eq!(Packet::parse(&b[..b.len() - 1], &e), Err(Error::Truncated));
        let mut long = b.clone();
        long.push(0);
        assert_eq!(
            Packet::parse(&long, &e),
            Err(Error::Trailing { remaining: 1 })
        );
        // A digest over 255 bytes cannot be written.
        p.header = Header::V2 { auth: Auth::Cryptographic { key_id: 3, sequence: 77, digest: vec![9; 256] } };
        assert_eq!(p.frame(&e).and_then(|frame| frame.to_bytes()), Err(Error::Field));
    }

    #[test]
    fn body_errors() {
        let e4 = v4_ends();
        let e6 = v6_ends();
        let raw = |v: u8, t: u8, body: &[u8], e: &Endpoints| -> Result<Packet, Error> {
            let hl = if v == 2 { HEADER_LEN_V2 } else { HEADER_LEN_V3 };
            let mut b = vec![0u8; hl];
            b[0] = v;
            b[1] = t;
            b.extend_from_slice(body);
            let len = b.len() as u16;
            b[2..4].copy_from_slice(&len.to_be_bytes());
            Packet::parse(&fix(b, e), e)
        };
        // A Hello short of its fixed fields, and one with a partial neighbor.
        assert_eq!(raw(2, 1, &[0; 19], &e4), Err(Error::BodyLength));
        assert_eq!(raw(2, 1, &[0; 22], &e4), Err(Error::BodyLength));
        assert!(raw(2, 1, &[0; 24], &e4).is_ok());
        assert_eq!(raw(3, 1, &[0; 21], &e6), Err(Error::BodyLength));
        // Database Description: fixed fields, then whole headers.
        assert_eq!(raw(2, 2, &[0; 7], &e4), Err(Error::BodyLength));
        assert_eq!(raw(2, 2, &[0; 9], &e4), Err(Error::BodyLength));
        // An all-zero header describes no LSA.
        assert_eq!(raw(2, 2, &[0; 28], &e4), Err(Error::LsaLength(0)));
        let mut dd = vec![0u8; 8];
        dd.extend_from_slice(&[0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x80, 0, 0, 1, 0x97, 0x7f, 0, 36]);
        assert!(raw(2, 2, &dd, &e4).is_ok());
        assert_eq!(raw(3, 2, &[0; 11], &e6), Err(Error::BodyLength));
        assert!(raw(3, 2, &[0; 12], &e6).is_ok());
        // Requests come in 12s.
        assert_eq!(raw(2, 3, &[0; 13], &e4), Err(Error::BodyLength));
        assert!(raw(3, 3, &[0; 24], &e6).is_ok());
        // Acknowledgments come in 20s.
        assert_eq!(raw(2, 5, &[0; 19], &e4), Err(Error::BodyLength));
        // Updates: the count, then LSAs that must match it.
        assert_eq!(raw(2, 4, &[0; 3], &e4), Err(Error::BodyLength));
        assert_eq!(raw(2, 4, &[0, 0, 0, 1], &e4), Err(Error::LsaCount));
        let l = v2_lsas()[1].frame(Version::V2).and_then(|frame| frame.to_bytes()).unwrap();
        let mut body = vec![0, 0, 0, 2];
        body.extend_from_slice(&l);
        assert_eq!(raw(2, 4, &body, &e4), Err(Error::LsaCount));
        body[3] = 1;
        assert!(raw(2, 4, &body, &e4).is_ok());
        body.extend_from_slice(&[0; 19]);
        assert_eq!(raw(2, 4, &body, &e4), Err(Error::BodyLength));
        // An LSA in an update with a bad checksum is left out, and still
        // counts; a bad length fails the packet.
        let mut body = vec![0, 0, 0, 1];
        body.extend_from_slice(&l);
        body[4 + 20] ^= 1;
        assert_eq!(raw(2, 4, &body, &e4).map(|p| p.body), Ok(Body::LinkStateUpdate(vec![])));
        body[4 + 19] = 19;
        assert_eq!(raw(2, 4, &body, &e4), Err(Error::LsaLength(19)));
        body[4 + 19] = 200;
        assert_eq!(raw(2, 4, &body, &e4), Err(Error::LsaLength(200)));
    }

    #[test]
    fn lsa_errors() {
        let v2 = Version::V2;
        let v3 = Version::V3;
        let raw = |v: Version, t: u16, body: &[u8]| -> Result<(Lsa, usize), Error> {
            let mut b = vec![0u8; LSA_HEADER_LEN];
            match v {
                Version::V2 => b[3] = t as u8,
                Version::V3 => b[2..4].copy_from_slice(&t.to_be_bytes()),
            }
            b.extend_from_slice(body);
            let len = b.len() as u16;
            b[18..20].copy_from_slice(&len.to_be_bytes());
            Lsa::parse(&fix_lsa(b), v)
        };
        assert_eq!(Lsa::parse(&[0; 19], v2), Err(Error::Truncated));
        // Router-LSA: a link count past the bytes, a TOS count past them,
        // bytes after the links.
        assert_eq!(raw(v2, 1, &[0, 0, 0, 1]), Err(Error::LsaBody));
        assert_eq!(raw(v2, 1, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 0, 1]), Err(Error::LsaBody));
        assert_eq!(raw(v2, 1, &[0, 0, 0, 0, 9]), Err(Error::LsaBody));
        assert!(raw(v2, 1, &[0, 0, 0, 0]).is_ok());
        assert_eq!(raw(v2, 2, &[0; 6]), Err(Error::LsaBody));
        assert_eq!(raw(v2, 3, &[0; 9]), Err(Error::LsaBody));
        assert_eq!(raw(v2, 3, &[0; 7]), Err(Error::LsaBody));
        assert_eq!(raw(v2, 5, &[0; 10]), Err(Error::LsaBody));
        assert_eq!(raw(v3, 0x2001, &[0; 5]), Err(Error::LsaBody));
        assert_eq!(raw(v3, 0x2002, &[0; 6]), Err(Error::LsaBody));
        assert_eq!(raw(v3, 0x2004, &[0; 11]), Err(Error::LsaBody));
        assert_eq!(raw(v3, 0x2004, &[0; 13]), Err(Error::LsaBody));
        // Prefixes: too long, or missing words.
        assert_eq!(raw(v3, 0x2003, &[0, 0, 0, 0, 129, 0, 0, 0]), Err(Error::PrefixLength(129)));
        assert_eq!(raw(v3, 0x2003, &[0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0]), Err(Error::LsaBody));
        assert!(raw(v3, 0x2003, &[0, 0, 0, 0, 0, 0, 0, 0]).is_ok());
        // AS-External: F set without the forwarding address; a reference
        // without its ID.
        assert_eq!(raw(v3, 0x4005, &[0x02, 0, 0, 0, 0, 0, 0, 0]), Err(Error::LsaBody));
        assert_eq!(raw(v3, 0x4005, &[0, 0, 0, 0, 0, 0, 0x20, 0x01]), Err(Error::LsaBody));
        // Link-LSA and Intra-Area-Prefix-LSA counts past the prefixes.
        let mut link = vec![0u8; 20];
        link.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(raw(v3, 0x0008, &link), Err(Error::LsaBody));
        assert_eq!(raw(v3, 0x2009, &[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::LsaBody));
        assert_eq!(raw(v3, 0x2009, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), Err(Error::LsaBody));
        // Bytes past the LSA's length are left for the caller.
        let mut b = v2_lsas()[1].frame(v2).and_then(|frame| frame.to_bytes()).unwrap();
        let n = b.len();
        b.extend_from_slice(&[1, 2, 3]);
        assert_eq!(Lsa::parse(&b, v2).unwrap().1, n);
    }

    #[test]
    fn as_external_needs_its_tos_0_route() {
        // RFC 2328 A.4.5: the E bit, metric, forwarding address and tag of
        // TOS 0 always follow the mask. A mask alone is not an LSA.
        let raw = |t: u16, body: &[u8]| {
            let mut b = vec![0u8; LSA_HEADER_LEN];
            b[3] = t as u8;
            b.extend_from_slice(body);
            let len = b.len() as u16;
            b[18..20].copy_from_slice(&len.to_be_bytes());
            Lsa::parse(&fix_lsa(b), Version::V2)
        };
        for t in [lsa_type_v2::AS_EXTERNAL, lsa_type_v2::NSSA] {
            assert_eq!(raw(t, &[255, 255, 255, 0]), Err(Error::LsaBody));
            let mut one = vec![255, 255, 255, 0, 0x80, 0, 0, 20];
            one.extend_from_slice(&[0; 8]);
            assert!(raw(t, &one).is_ok());
            // The first route's TOS field is 0.
            one[4] = 0x81;
            assert_eq!(raw(t, &one), Err(Error::LsaBody));
        }
        let route =
            ExternalRoute { type2: false, tos: 0, metric: 1, forwarding_address: Ipv4Addr::UNSPECIFIED, route_tag: 0 };
        let ext = |routes: Vec<ExternalRoute>| {
            lsa(lsa_type_v2::AS_EXTERNAL, LsaBody::AsExternal(AsExternalLsa { network_mask: ip4(0, 0, 0, 0), routes }))
        };
        assert_eq!(ext(vec![]).frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        assert_eq!(ext(vec![ExternalRoute { tos: 4, ..route }]).frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        assert!(ext(vec![route, ExternalRoute { tos: 4, ..route }]).frame(Version::V2).and_then(|frame| frame.to_bytes()).is_ok());
    }

    #[test]
    fn writer_errors() {
        let e4 = v4_ends();
        let e6 = v6_ends();
        let mut p = hello_v2(ip4(1, 1, 1, 1), vec![]);
        assert_eq!(p.frame(&e6).and_then(|frame| frame.to_bytes()), Err(Error::Family));
        p.header = Header::V3 { instance_id: 0 };
        assert_eq!(p.frame(&e6).and_then(|frame| frame.to_bytes()), Err(Error::Unwritable));
        p.header = Header::V2 { auth: Auth::Other { kind: 1, data: [0; 8] } };
        assert_eq!(p.frame(&e4).and_then(|frame| frame.to_bytes()), Err(Error::Unwritable));
        // Too many neighbors for a 16-bit length.
        p.header = Header::V2 { auth: Auth::Null };
        let Body::HelloV2(h) = &mut p.body else { panic!() };
        h.neighbors = vec![ip4(1, 2, 3, 4); 20_000];
        assert_eq!(p.frame(&e4).and_then(|frame| frame.to_bytes()), Err(Error::TooLong));
        let Body::HelloV2(h) = &mut p.body else { panic!() };
        h.neighbors = vec![ip4(1, 2, 3, 4); (MAX_PACKET - 44) / 4];
        let b = p.frame(&e4).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(Packet::parse(&b, &e4), Ok(p));
        // Out-of-range fields.
        let mut q = packets(Version::V3).remove(0);
        let Body::HelloV3(h) = &mut q.body else { panic!() };
        h.options = 0x0100_0000;
        assert_eq!(q.frame(&e6).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let dd = |options: u32, headers: Vec<LsaHeader>| Packet {
            router_id: ip4(1, 1, 1, 1),
            area_id: ip4(0, 0, 0, 0),
            header: Header::V2 { auth: Auth::Null },
            lls: None,
            body: Body::DatabaseDescription(DatabaseDescription { mtu: 1500, options, flags: 0, sequence: 1, headers }),
        };
        assert_eq!(dd(0x100, vec![]).frame(&e4).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let mut h = header_of(&v2_lsas()[0], Version::V2);
        h.ls_type = 0x100;
        assert_eq!(dd(0, vec![h]).frame(&e4).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let req = Packet {
            router_id: ip4(1, 1, 1, 1),
            area_id: ip4(0, 0, 0, 0),
            header: Header::V3 { instance_id: 0 },
            lls: None,
            body: Body::LinkStateRequest(vec![LsaKey {
                ls_type: 0x1_0000,
                link_state_id: ip4(0, 0, 0, 0),
                advertising_router: ip4(0, 0, 0, 0),
            }]),
        };
        assert_eq!(req.frame(&e6).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        // LSAs: a body for another type, a v2 type over 255, v3 options.
        let mut l = v2_lsas().remove(0);
        l.ls_type = 2;
        assert_eq!(l.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Unwritable));
        assert_eq!(v2_lsas()[0].frame(Version::V3).and_then(|frame| frame.to_bytes()), Err(Error::Unwritable));
        let mut l = v2_lsas().remove(6);
        l.ls_type = 0x100;
        assert_eq!(l.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let mut l = v3_lsas().remove(8);
        l.options = 1;
        assert_eq!(l.frame(Version::V3).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let summary =
            lsa(3, LsaBody::Summary(SummaryLsa { network_mask: ip4(0, 0, 0, 0), metric: 1 << 24, tos: vec![] }));
        assert_eq!(summary.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let ext = lsa(
            5,
            LsaBody::AsExternal(AsExternalLsa {
                network_mask: ip4(0, 0, 0, 0),
                routes: vec![
                    ExternalRoute {
                        type2: false,
                        tos: 0,
                        metric: 0,
                        forwarding_address: ip4(0, 0, 0, 0),
                        route_tag: 0,
                    },
                    ExternalRoute {
                        type2: false,
                        tos: 128,
                        metric: 0,
                        forwarding_address: ip4(0, 0, 0, 0),
                        route_tag: 0,
                    },
                ],
            }),
        );
        assert_eq!(ext.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let ia = lsa(0x2003, LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric: 0, prefix: pfx(0, "::") }));
        let mut bad = ia.clone();
        let LsaBody::InterAreaPrefix(x) = &mut bad.body else { panic!() };
        x.prefix.length = 129;
        assert_eq!(bad.frame(Version::V3).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let mut bad = v3_lsas().remove(4);
        let LsaBody::AsExternalV3(x) = &mut bad.body else { panic!() };
        x.referenced = Some((0, ip4(0, 0, 0, 1)));
        assert_eq!(bad.frame(Version::V3).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let router = lsa(
            1,
            LsaBody::Router(RouterLsa {
                flags: 0,
                links: vec![RouterLink {
                    id: ip4(0, 0, 0, 0),
                    data: ip4(0, 0, 0, 0),
                    kind: 1,
                    metric: 1,
                    tos: vec![TosMetric { tos: 0, metric: 0 }; 256],
                }],
            }),
        );
        assert_eq!(router.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let big = lsa(10, LsaBody::Other(vec![0; MAX_LSA - LSA_HEADER_LEN + 1]));
        assert_eq!(big.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::TooLong));
        let fits = lsa(10, LsaBody::Other(vec![0; MAX_LSA - LSA_HEADER_LEN]));
        let b = fits.frame(Version::V2).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(Lsa::parse(&b, Version::V2), Ok((fits, MAX_LSA)));
    }

    /// The module example's Hello with the L bit set, and the LLS block
    /// that follows it: one Extended Options TLV with LR set.
    fn hello_with_lls() -> (Vec<u8>, Packet) {
        let mut b = vec![
            2, 1, 0, 44, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            255, 255, 255, 0, 0, 10, 0x12, 1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        b = fix(b, &v4_ends());
        assert_eq!(&b[12..14], &[0xea, 0x9c]);
        b.extend_from_slice(&[0xff, 0xf6, 0, 3, 0, 1, 0, 4, 0, 0, 0, 1]);
        let mut p = hello_v2(ip4(1, 1, 1, 1), vec![]);
        let Body::HelloV2(h) = &mut p.body else { panic!() };
        h.options = 0x12;
        p.lls = Some(vec![0, 1, 0, 4, 0, 0, 0, 1]);
        (b, p)
    }

    #[test]
    fn link_local_signaling_follows_the_packet() {
        // RFC 5613 section 2: the block follows the packet, outside its
        // length, when the L bit is set.
        let e = v4_ends();
        let (b, p) = hello_with_lls();
        assert_eq!(Packet::parse(&b, &e).as_ref(), Ok(&p));
        assert_eq!(p.frame(&e).and_then(|frame| frame.to_bytes()).unwrap(), b);
        assert_eq!(collect(&b, &e).as_ref(), Ok(&p));
        // Cut inside the block, or with bytes past it.
        assert_eq!(Packet::parse(&b[..50], &e), Err(Error::Truncated));
        assert_eq!(Packet::parse(&b[..46], &e), Err(Error::Truncated));
        let mut long = b.clone();
        long.extend_from_slice(&[0; 4]);
        assert_eq!(
            Packet::parse(&long, &e),
            Err(Error::Trailing { remaining: 4 })
        );
        assert_eq!(
            collect(&long, &e),
            Err(Error::Trailing { remaining: 4 })
        );
        // The L bit set and no block: the packet reads, with none.
        let mut alone = p.clone();
        alone.lls = None;
        assert_eq!(Packet::parse(&b[..44], &e), Ok(alone.clone()));
        assert_eq!(alone.frame(&e).and_then(|frame| frame.to_bytes()).unwrap(), b[..44]);
        // A wrong block checksum drops the block and keeps the packet.
        let mut bad = b.clone();
        bad[44] ^= 1;
        assert_eq!(Packet::parse(&bad, &e), Ok(alone));
        // A block length of zero words, or one past the payload's cap.
        let mut zero = b.clone();
        zero[46..48].copy_from_slice(&[0, 0]);
        assert_eq!(Packet::parse(&zero, &e), Err(Error::Lls));
        assert_eq!(collect(&zero[..48], &e), Err(Error::Lls));
        let mut huge = b.clone();
        huge[46..48].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(Packet::parse(&huge, &e), Err(Error::Lls));
        // Without the L bit, bytes after the packet are still trailing.
        let mut clear = b.clone();
        clear[30] = 0x02;
        let clear = fix(clear, &e);
        assert_eq!(
            Packet::parse(&clear, &e),
            Err(Error::Trailing { remaining: 12 })
        );
        // Writers: a block needs the L bit, a Hello or DD, and whole words.
        let mut q = p.clone();
        let Body::HelloV2(h) = &mut q.body else { panic!() };
        h.options = 0x02;
        assert_eq!(q.frame(&e).and_then(|frame| frame.to_bytes()), Err(Error::Lls));
        let mut q = p.clone();
        q.lls = Some(vec![1, 2, 3]);
        assert_eq!(q.frame(&e).and_then(|frame| frame.to_bytes()), Err(Error::Lls));
        let mut q = p.clone();
        q.lls = Some(vec![0; MAX_MESSAGE & !3]);
        assert_eq!(q.frame(&e).and_then(|frame| frame.to_bytes()), Err(Error::TooLong));
        let mut q = packets(Version::V2).remove(5);
        q.lls = Some(vec![]);
        assert_eq!(q.frame(&e).and_then(|frame| frame.to_bytes()), Err(Error::Lls));
        // After a digest, with its checksum zero and not checked.
        let mut q = p.clone();
        q.header = Header::V2 { auth: Auth::Cryptographic { key_id: 1, sequence: 5, digest: vec![7; 16] } };
        let c = q.frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(c.len(), 44 + 16 + 12);
        assert_eq!(&c[60..64], &[0, 0, 0, 3]);
        assert_eq!(Packet::parse(&c, &e), Ok(q));
    }

    #[test]
    fn link_local_signaling_in_v3_and_database_description() {
        let e6 = v6_ends();
        let mut hello = packets(Version::V3).remove(0);
        let Body::HelloV3(h) = &mut hello.body else { panic!() };
        h.options |= OPTION_L_V3;
        hello.lls = Some(vec![0, 1, 0, 4, 0, 0, 0, 1]);
        let b = hello.frame(&e6).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(usize::from(be16(&b, 2).unwrap()), b.len() - 12);
        assert_eq!(Packet::parse(&b, &e6), Ok(hello.clone()));
        for (v, e, l) in [(Version::V2, v4_ends(), u32::from(OPTION_L_V2)), (Version::V3, e6, OPTION_L_V3)] {
            let mut dd = packets(v).remove(2);
            let Body::DatabaseDescription(d) = &mut dd.body else { panic!() };
            d.options |= l;
            dd.lls = Some(vec![9; 16]);
            let b = dd.frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
            assert_eq!(Packet::parse(&b, &e), Ok(dd.clone()));
            assert_eq!(collect(&b, &e), Ok(dd));
        }
    }

    #[test]
    fn received_lsas_write_back_to_the_same_bytes() {
        // RFC 2328 sections 13.1 and 13.7: the checksum names the
        // instance, so an LSA read must give back its own header. A
        // reserved byte that is not zero would be lost, so it is refused.
        let good: [u8; 36] = [
            0, 1, 0x22, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x80, 0, 0, 1, 0x97, 0x7f, 0, 36, //
            0, 0, 0, 1, 10, 0, 0, 0, 255, 255, 255, 0, 3, 0, 0, 10,
        ];
        let mut b = good.to_vec();
        b[21] = 1;
        let b = fix_lsa(b);
        assert_eq!(be16(&b, 16).unwrap(), 0x9b7a);
        assert_eq!(Lsa::parse(&b, Version::V2), Err(Error::LsaBody));
        // A checksum byte of 0 stands for 255 in the sums, but writing the
        // LSA again would give 255, so it is refused.
        let mut found = false;
        for id in 0..=0xffffu16 {
            let mut c = good.to_vec();
            c[6..8].copy_from_slice(&id.to_be_bytes());
            let c = fix_lsa(c);
            if c[16] == 255 || c[17] == 255 {
                let mut zeroed = c.clone();
                if zeroed[16] == 255 {
                    zeroed[16] = 0;
                } else {
                    zeroed[17] = 0;
                }
                assert!(!lsa_checksum_ok(&zeroed));
                assert_eq!(Lsa::parse(&zeroed, Version::V2), Err(Error::LsaChecksum));
                found = true;
            }
        }
        assert!(found);
        // Reserved bytes in every body type are refused.
        let refused = [
            (Version::V2, lsa_type_v2::ROUTER, vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 9, 0, 1]),
            (Version::V2, lsa_type_v2::SUMMARY_NETWORK, vec![255, 0, 0, 0, 1, 0, 0, 1]),
            (Version::V3, lsa_type_v3::ROUTER, vec![0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 2, 2, 2, 2]),
            (Version::V3, lsa_type_v3::NETWORK, vec![1, 0, 0, 0, 1, 1, 1, 1]),
            (Version::V3, lsa_type_v3::INTER_AREA_PREFIX, vec![1, 0, 0, 1, 0, 0, 0, 0]),
            (Version::V3, lsa_type_v3::INTER_AREA_PREFIX, vec![0, 0, 0, 1, 0, 0, 0, 1]),
            (Version::V3, lsa_type_v3::INTER_AREA_ROUTER, vec![1, 0, 0, 0, 0, 0, 0, 1, 9, 9, 9, 9]),
            (Version::V3, lsa_type_v3::INTER_AREA_ROUTER, vec![0, 0, 0, 0, 1, 0, 0, 1, 9, 9, 9, 9]),
            (Version::V3, lsa_type_v3::AS_EXTERNAL, vec![0x08, 0, 0, 1, 0, 0, 0, 0]),
        ];
        for (v, t, body) in refused {
            assert_eq!(LsaBody::parse(&body, v, t), Err(Error::LsaBody), "{t:#x} {body:?}");
        }
        let mut link = vec![1, 0, 0, 0];
        link.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        link.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
        assert_eq!(LsaBody::parse(&link, Version::V3, lsa_type_v3::LINK), Err(Error::LsaBody));
        // Every sample's header, worked out from the value, is the one in
        // its bytes.
        for (lsas, v) in [(v2_lsas(), Version::V2), (v3_lsas(), Version::V3)] {
            for l in lsas {
                let b = l.frame(v).and_then(|frame| frame.to_bytes()).unwrap();
                let (back, _) = Lsa::parse(&b, v).unwrap();
                assert_eq!(back.frame(v).and_then(|frame| frame.to_bytes()).unwrap(), b);
                assert_eq!(back.header(v).unwrap().checksum, be16(&b, 16).unwrap());
            }
        }
    }

    #[test]
    fn lsa_body_parse_is_capped() {
        let most = MAX_LSA - LSA_HEADER_LEN;
        assert!(LsaBody::parse(&vec![0; most], Version::V2, 10).is_ok());
        assert_eq!(LsaBody::parse(&vec![0; most + 1], Version::V2, 10), Err(Error::TooLong));
        assert_eq!(LsaBody::parse(&vec![0; 1 << 20], Version::V3, lsa_type_v3::NETWORK), Err(Error::TooLong));
    }

    #[test]
    fn update_keeps_the_lsas_around_a_bad_one() {
        // RFC 2328 section 13, step 1: discard the bad LSA and go on.
        let e = v4_ends();
        let l = v2_lsas()[1].frame(Version::V2).and_then(|frame| frame.to_bytes()).unwrap();
        let mut bad = l.clone();
        bad[21] ^= 1;
        let mut wrong_body = v2_lsas()[1].frame(Version::V2).and_then(|frame| frame.to_bytes()).unwrap();
        wrong_body[24..28].copy_from_slice(&[9, 9, 9, 9]);
        let wrong_body = fix_lsa(wrong_body);
        let mut b = vec![0u8; 24];
        b[0] = 2;
        b[1] = 4;
        b.extend_from_slice(&[0, 0, 0, 4]);
        for x in [&l, &bad, &wrong_body, &l] {
            b.extend_from_slice(x);
        }
        let n = b.len() as u16;
        b[2..4].copy_from_slice(&n.to_be_bytes());
        let b = fix(b, &e);
        let p = Packet::parse(&b, &e).unwrap();
        assert_eq!(p.body, Body::LinkStateUpdate(vec![v2_lsas().remove(1), v2_lsas().remove(1)]));
        assert_eq!(collect(&b, &e), Ok(p));
        // The count still covers the dropped ones.
        let mut short = b.clone();
        short[27] = 2;
        assert_eq!(Packet::parse(&fix(short, &e), &e), Err(Error::LsaCount));
    }

    #[test]
    fn lsa_headers_describe_possible_lsas() {
        // RFC 2328 A.4.1, 12.1.1, 12.1.6 and 12.1.7.
        let e = v4_ends();
        let good = header_of(&v2_lsas()[0], Version::V2);
        let ack = |h: LsaHeader| Packet {
            router_id: ip4(1, 1, 1, 1),
            area_id: ip4(0, 0, 0, 0),
            header: Header::V2 { auth: Auth::Null },
            lls: None,
            body: Body::LinkStateAck(vec![h]),
        };
        let b = ack(good).frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(Packet::parse(&b, &e), Ok(ack(good)));
        let cases = [
            (LsaHeader { length: 0, ..good }, Error::LsaLength(0)),
            (LsaHeader { length: 19, ..good }, Error::LsaLength(19)),
            (LsaHeader { checksum: 0, ..good }, Error::Field),
            (LsaHeader { checksum: 0x9700, ..good }, Error::Field),
            (LsaHeader { sequence: RESERVED_SEQUENCE, ..good }, Error::Field),
            (LsaHeader { age: MAX_AGE + 1, ..good }, Error::Field),
            (LsaHeader { age: DO_NOT_AGE | (MAX_AGE + 1), ..good }, Error::Field),
        ];
        for (h, err) in cases {
            assert_eq!(ack(h).frame(&e).and_then(|frame| frame.to_bytes()), Err(err), "{h:?}");
            // The same header read from bytes.
            let mut raw = b.clone();
            let mut hb = Vec::new();
            put_lsa_header(&mut hb, &h, Version::V2).unwrap();
            raw[24..44].copy_from_slice(&hb);
            assert_eq!(Packet::parse(&fix(raw, &e), &e), Err(err), "{h:?}");
        }
        assert!(ack(LsaHeader { age: DO_NOT_AGE | MAX_AGE, ..good }).frame(&e).and_then(|frame| frame.to_bytes()).is_ok());
        // Whole LSAs follow the same age and sequence rules.
        for (age, sequence) in [(MAX_AGE + 1, INITIAL_SEQUENCE), (3, RESERVED_SEQUENCE)] {
            let l = Lsa { age, sequence, ..v2_lsas().remove(0) };
            assert_eq!(l.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
            let mut b = Lsa { age: 3, sequence: INITIAL_SEQUENCE, ..l }.frame(Version::V2).and_then(|frame| frame.to_bytes()).unwrap();
            b[0..2].copy_from_slice(&age.to_be_bytes());
            b[12..16].copy_from_slice(&sequence.to_be_bytes());
            assert_eq!(Lsa::parse(&fix_lsa(b), Version::V2), Err(Error::Field));
        }
    }

    #[test]
    fn external_forwarding_addresses_are_global() {
        // RFC 5340 A.4.7: not the unspecified address, not link-local.
        for a in ["::", "fe80::1", "febf::9"] {
            let mut l = v3_lsas().remove(4);
            let LsaBody::AsExternalV3(x) = &mut l.body else { panic!() };
            x.forwarding_address = Some(a.parse().unwrap());
            assert_eq!(l.frame(Version::V3).and_then(|frame| frame.to_bytes()), Err(Error::Field), "{a}");
            let LsaBody::AsExternalV3(x) = &mut l.body else { panic!() };
            x.forwarding_address = Some("2001:db8::9".parse().unwrap());
            let mut b = l.frame(Version::V3).and_then(|frame| frame.to_bytes()).unwrap();
            let at = 20 + 4 + 4 + 8;
            b[at..at + 16].copy_from_slice(&a.parse::<Ipv6Addr>().unwrap().octets());
            assert_eq!(Lsa::parse(&fix_lsa(b), Version::V3), Err(Error::LsaBody), "{a}");
        }
    }

    #[test]
    fn router_link_types_are_the_defined_ones() {
        // RFC 2328 A.4.2 (1 to 4) and RFC 5340 A.4.3 (1, 2 and 4).
        for kind in 0..=255u8 {
            let mut l = v2_lsas().remove(0);
            let LsaBody::Router(r) = &mut l.body else { panic!() };
            r.links[0].kind = kind;
            assert_eq!(l.frame(Version::V2).and_then(|frame| frame.to_bytes()).is_ok(), (1..=4).contains(&kind), "{kind}");
            let mut l = v3_lsas().remove(0);
            let LsaBody::RouterV3(r) = &mut l.body else { panic!() };
            r.interfaces[0].kind = kind;
            assert_eq!(l.frame(Version::V3).and_then(|frame| frame.to_bytes()).is_ok(), matches!(kind, 1 | 2 | 4), "{kind}");
        }
        let mut b = vec![0, 0, 0, 1, 10, 0, 0, 0, 255, 255, 255, 0, 3, 0, 0, 10];
        assert!(LsaBody::parse(&b, Version::V2, lsa_type_v2::ROUTER).is_ok());
        b[12] = 0;
        assert_eq!(LsaBody::parse(&b, Version::V2, lsa_type_v2::ROUTER), Err(Error::LsaBody));
        let mut b = vec![0, 0, 0, 0x13, 3, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 6, 2, 2, 2, 2];
        assert_eq!(LsaBody::parse(&b, Version::V3, lsa_type_v3::ROUTER), Err(Error::LsaBody));
        b[4] = 4;
        assert!(LsaBody::parse(&b, Version::V3, lsa_type_v3::ROUTER).is_ok());
    }

    #[test]
    fn network_lsas_list_the_designated_router() {
        // RFC 2328 A.4.3 and RFC 5340 A.4.4: the designated router, which
        // advertises the LSA, lists itself.
        let mut l = v2_lsas().remove(1);
        let LsaBody::Network(n) = &mut l.body else { panic!() };
        n.attached_routers = vec![];
        assert_eq!(l.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        assert_eq!(LsaBody::parse(&[255, 255, 255, 0], Version::V2, lsa_type_v2::NETWORK), Err(Error::LsaBody));
        let LsaBody::Network(n) = &mut l.body else { panic!() };
        n.attached_routers = vec![ip4(2, 2, 2, 2)];
        assert_eq!(l.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        let mut b = v2_lsas()[1].frame(Version::V2).and_then(|frame| frame.to_bytes()).unwrap();
        b[24..28].copy_from_slice(&[3, 3, 3, 3]);
        assert_eq!(Lsa::parse(&fix_lsa(b), Version::V2), Err(Error::LsaBody));
        let mut l = v3_lsas().remove(1);
        let LsaBody::NetworkV3(n) = &mut l.body else { panic!() };
        n.attached_routers = vec![ip4(2, 2, 2, 2)];
        assert_eq!(l.frame(Version::V3).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        assert_eq!(LsaBody::parse(&[0, 0, 0, 0x13], Version::V3, lsa_type_v3::NETWORK), Err(Error::LsaBody));
    }

    #[test]
    fn asbr_summaries_have_no_mask() {
        // RFC 2328 A.4.4: for type 4 the mask must be zero.
        let mask = ip4(255, 255, 255, 0);
        let l = lsa(4, LsaBody::Summary(SummaryLsa { network_mask: mask, metric: 1, tos: vec![] }));
        assert_eq!(l.frame(Version::V2).and_then(|frame| frame.to_bytes()), Err(Error::Field));
        assert!(lsa(3, l.body.clone()).frame(Version::V2).and_then(|frame| frame.to_bytes()).is_ok());
        let body = [255, 255, 255, 0, 0, 0, 0, 1];
        assert_eq!(LsaBody::parse(&body, Version::V2, 4), Err(Error::LsaBody));
        assert!(LsaBody::parse(&body, Version::V2, 3).is_ok());
    }

    #[test]
    fn checksum_bounds() {
        assert_eq!(checksum(&[2; 23], &v4_ends()), None);
        let mut b = vec![0u8; 24];
        b[3] = 25;
        assert_eq!(checksum(&b, &v4_ends()), None);
        b[3] = 23;
        assert_eq!(checksum(&b, &v4_ends()), None);
        b[3] = 24;
        assert!(checksum(&b, &v4_ends()).is_some());
        assert_eq!(checksum(&b[..15], &v6_ends()), None);
    }

    #[test]
    fn every_truncated_prefix_fails() {
        for (p, e) in samples() {
            let b = p.frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
            for n in 0..b.len() {
                assert!(Packet::parse(&b[..n], &e).is_err(), "{n} of {p:?}");
                assert!(collect(&b[..n], &e).is_err());
            }
        }
        for (lsas, v) in [(v2_lsas(), Version::V2), (v3_lsas(), Version::V3)] {
            for l in lsas {
                let b = l.frame(v).and_then(|frame| frame.to_bytes()).unwrap();
                for n in 0..b.len() {
                    assert!(Lsa::parse(&b[..n], v).is_err());
                }
            }
        }
    }

    #[test]
    fn collection_matches_parse() {
        for (p, e) in samples() {
            assert_eq!(collect(&p.frame(&e).and_then(|f| f.to_bytes()).unwrap(), &e), Ok(p));
        }
        assert_eq!(collect(&[2, 9], &v4_ends()), Err(Error::Type(9)));
        assert_eq!(collect(&[2], &v6_ends()), Err(Error::Family));
        let mut b = hello_v2(ip4(1, 1, 1, 1), vec![]).frame(&v4_ends()).unwrap().to_bytes().unwrap();
        b.push(0);
        assert_eq!(
            collect(&b, &v4_ends()),
            Err(Error::Trailing { remaining: 1 })
        );
        b.resize(MAX_MESSAGE + 100, 0);
        assert_eq!(
            collect(&b, &v4_ends()),
            Err(Error::Trailing {
                remaining: MAX_MESSAGE + 100 - 44
            })
        );
        assert_eq!(collect(&[], &v4_ends()), Err(Error::Truncated));
    }

    #[test]
    fn errors_display() {
        for e in [Error::Version(9), Error::LsaLength(3), Error::PrefixLength(200), Error::Unwritable] {
            assert!(!e.to_string().is_empty());
        }
    }


    trait Samples {
        fn ip4(&mut self) -> Ipv4Addr;
        fn ip6(&mut self) -> Ipv6Addr;
        fn u24(&mut self) -> u32;
        fn prefix(&mut self) -> Prefix;
        fn age(&mut self) -> u16;
        fn sequence(&mut self) -> u32;
    }

    impl Samples for Lcg {
        fn ip4(&mut self) -> Ipv4Addr {
            Ipv4Addr::from(u32::from_be_bytes(std::array::from_fn(|_| self.next() as u8)))
        }
        fn ip6(&mut self) -> Ipv6Addr {
            let mut a = [0u8; 16];
            self.fill(&mut a);
            Ipv6Addr::from(a)
        }
        fn u24(&mut self) -> u32 {
            u32::from_be_bytes(std::array::from_fn(|_| self.next() as u8)) & MAX_U24
        }
        fn prefix(&mut self) -> Prefix {
            let length = self.index(129) as u8;
            Prefix::new(length, self.next() as u8, self.ip6())
        }
        /// An age a router may send: at most MaxAge, sometimes DoNotAge.
        fn age(&mut self) -> u16 {
            let age = self.index(usize::from(MAX_AGE) + 1) as u16;
            if self.index(4) == 0 { age | DO_NOT_AGE } else { age }
        }
        /// A sequence number other than the reserved one.
        fn sequence(&mut self) -> u32 {
            match u32::from_be_bytes(std::array::from_fn(|_| self.next() as u8)) {
                RESERVED_SEQUENCE => INITIAL_SEQUENCE,
                s => s,
            }
        }
    }

    fn random_lsa(rng: &mut Lcg, v: Version) -> Lsa {
        let n = rng.index(4);
        let advertising_router = rng.ip4();
        // A Network-LSA lists its advertising router, the designated router.
        let attached = |rng: &mut Lcg| {
            let mut list: Vec<Ipv4Addr> = (0..n).map(|_| rng.ip4()).collect();
            list.insert(rng.index(n + 1), advertising_router);
            list
        };
        let (ls_type, body) = match v {
            Version::V2 => match rng.index(6) {
                0 => (
                    1,
                    LsaBody::Router(RouterLsa {
                        flags: rng.next() as u8,
                        links: (0..n)
                            .map(|_| RouterLink {
                                id: rng.ip4(),
                                data: rng.ip4(),
                                kind: 1 + rng.index(4) as u8,
                                metric: rng.next() as u16,
                                tos: (0..rng.index(3))
                                    .map(|_| TosMetric { tos: rng.next() as u8, metric: rng.next() as u16 })
                                    .collect(),
                            })
                            .collect(),
                    }),
                ),
                1 => (2, LsaBody::Network(NetworkLsa { network_mask: rng.ip4(), attached_routers: attached(rng) })),
                2 => {
                    let t = 3 + rng.index(2) as u16;
                    (
                        t,
                        LsaBody::Summary(SummaryLsa {
                            network_mask: if t == 4 { Ipv4Addr::UNSPECIFIED } else { rng.ip4() },
                            metric: rng.u24(),
                            tos: (0..n).map(|_| (rng.next() as u8, rng.u24())).collect(),
                        }),
                    )
                }
                3 => (
                    if !rng.coin() { 5 } else { 7 },
                    LsaBody::AsExternal(AsExternalLsa {
                        network_mask: rng.ip4(),
                        routes: (0..=n)
                            .map(|i| ExternalRoute {
                                type2: !rng.coin(),
                                tos: if i == 0 { 0 } else { rng.next() as u8 & 0x7f },
                                metric: rng.u24(),
                                forwarding_address: rng.ip4(),
                                route_tag: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                            })
                            .collect(),
                    }),
                ),
                _ => (
                    100 + rng.index(100) as u16,
                    LsaBody::Other(rng.bytes(11)),
                ),
            },
            Version::V3 => match rng.index(9) {
                0 => (
                    lsa_type_v3::ROUTER,
                    LsaBody::RouterV3(RouterLsaV3 {
                        flags: rng.next() as u8,
                        options: rng.u24(),
                        interfaces: (0..n)
                            .map(|_| RouterInterface {
                                kind: [1, 2, 4][rng.index(3)],
                                metric: rng.next() as u16,
                                interface_id: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                                neighbor_interface_id: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                                neighbor_router_id: rng.ip4(),
                            })
                            .collect(),
                    }),
                ),
                1 => (
                    lsa_type_v3::NETWORK,
                    LsaBody::NetworkV3(NetworkLsaV3 { options: rng.u24(), attached_routers: attached(rng) }),
                ),
                2 => (
                    lsa_type_v3::INTER_AREA_PREFIX,
                    LsaBody::InterAreaPrefix(InterAreaPrefixLsa { metric: rng.u24(), prefix: rng.prefix() }),
                ),
                3 => (
                    lsa_type_v3::INTER_AREA_ROUTER,
                    LsaBody::InterAreaRouter(InterAreaRouterLsa {
                        options: rng.u24(),
                        metric: rng.u24(),
                        destination: rng.ip4(),
                    }),
                ),
                4 => (
                    if !rng.coin() { lsa_type_v3::AS_EXTERNAL } else { lsa_type_v3::NSSA },
                    LsaBody::AsExternalV3(AsExternalLsaV3 {
                        type2: !rng.coin(),
                        metric: rng.u24(),
                        prefix: rng.prefix(),
                        // A global address: 2000::/3.
                        forwarding_address: if !rng.coin() {
                            Some(Ipv6Addr::from((u128::from(rng.ip6()) >> 3) | (1 << 125)))
                        } else {
                            None
                        },
                        route_tag: if !rng.coin() { Some(u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8))) } else { None },
                        referenced: if !rng.coin() {
                            Some((1 + rng.index(0xfffe) as u16, rng.ip4()))
                        } else {
                            None
                        },
                    }),
                ),
                5 => (
                    lsa_type_v3::LINK,
                    LsaBody::Link(LinkLsa {
                        priority: rng.next() as u8,
                        options: rng.u24(),
                        link_local_address: rng.ip6(),
                        prefixes: (0..n).map(|_| rng.prefix()).collect(),
                    }),
                ),
                6 => (
                    lsa_type_v3::INTRA_AREA_PREFIX,
                    LsaBody::IntraAreaPrefix(IntraAreaPrefixLsa {
                        referenced_ls_type: rng.next() as u16,
                        referenced_link_state_id: rng.ip4(),
                        referenced_advertising_router: rng.ip4(),
                        prefixes: (0..n).map(|_| (rng.prefix(), rng.next() as u16)).collect(),
                    }),
                ),
                _ => (
                    0x0100 + rng.index(100) as u16,
                    LsaBody::Other(rng.bytes(11)),
                ),
            },
        };
        Lsa {
            age: rng.age(),
            options: if v == Version::V2 { rng.next() as u8 } else { 0 },
            ls_type,
            link_state_id: rng.ip4(),
            advertising_router,
            sequence: rng.sequence(),
            body,
        }
    }

    fn random_header(rng: &mut Lcg, v: Version) -> LsaHeader {
        LsaHeader {
            age: rng.age(),
            options: if v == Version::V2 { rng.next() as u8 } else { 0 },
            ls_type: if v == Version::V2 { rng.next() as u8 as u16 } else { rng.next() as u16 },
            link_state_id: rng.ip4(),
            advertising_router: rng.ip4(),
            sequence: rng.sequence(),
            checksum: ((1 + rng.index(255) as u16) << 8) | (1 + rng.index(255) as u16),
            length: (LSA_HEADER_LEN + rng.index(MAX_LSA - LSA_HEADER_LEN + 1)) as u16,
        }
    }

    fn random_packet(rng: &mut Lcg, v: Version) -> Packet {
        let n = rng.index(4);
        let body = match rng.index(5) {
            0 => match v {
                Version::V2 => Body::HelloV2(HelloV2 {
                    network_mask: rng.ip4(),
                    hello_interval: rng.next() as u16,
                    options: rng.next() as u8,
                    priority: rng.next() as u8,
                    dead_interval: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                    designated_router: rng.ip4(),
                    backup_designated_router: rng.ip4(),
                    neighbors: (0..n).map(|_| rng.ip4()).collect(),
                }),
                Version::V3 => Body::HelloV3(HelloV3 {
                    interface_id: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                    priority: rng.next() as u8,
                    options: rng.u24(),
                    hello_interval: rng.next() as u16,
                    dead_interval: rng.next() as u16,
                    designated_router: rng.ip4(),
                    backup_designated_router: rng.ip4(),
                    neighbors: (0..n).map(|_| rng.ip4()).collect(),
                }),
            },
            1 => Body::DatabaseDescription(DatabaseDescription {
                mtu: rng.next() as u16,
                options: if v == Version::V2 { u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)) & 0xff } else { rng.u24() },
                flags: rng.next() as u8,
                sequence: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                headers: (0..n).map(|_| random_header(rng, v)).collect(),
            }),
            2 => Body::LinkStateRequest(
                (0..n)
                    .map(|_| LsaKey {
                        ls_type: if v == Version::V2 { u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)) } else { u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)) & 0xffff },
                        link_state_id: rng.ip4(),
                        advertising_router: rng.ip4(),
                    })
                    .collect(),
            ),
            3 => Body::LinkStateUpdate((0..n).map(|_| random_lsa(rng, v)).collect()),
            _ => Body::LinkStateAck((0..n).map(|_| random_header(rng, v)).collect()),
        };
        let header = match v {
            Version::V2 => Header::V2 {
                auth: match rng.index(4) {
                    0 => Auth::Null,
                    1 => Auth::Simple([rng.next() as u8; 8]),
                    2 => Auth::Cryptographic {
                        key_id: rng.next() as u8,
                        sequence: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                        digest: rng.bytes(32),
                    },
                    _ => Auth::Other { kind: 3 + rng.index(100) as u16, data: [rng.next() as u8; 8] },
                },
            },
            Version::V3 => Header::V3 { instance_id: rng.next() as u8 },
        };
        let mut body = body;
        // Sometimes a signaling block, with the L bit set.
        let lls = if rng.index(3) == 0 {
            let l_set = match &mut body {
                Body::HelloV2(h) => {
                    h.options |= OPTION_L_V2;
                    true
                }
                Body::HelloV3(h) => {
                    h.options |= OPTION_L_V3;
                    true
                }
                Body::DatabaseDescription(d) => {
                    d.options |= if v == Version::V2 { u32::from(OPTION_L_V2) } else { OPTION_L_V3 };
                    true
                }
                _ => false,
            };
            l_set.then(|| {
                let mut bytes = vec![0; 4 * rng.index(4)];
                rng.fill(&mut bytes);
                bytes
            })
        } else {
            None
        };
        Packet { router_id: rng.ip4(), area_id: rng.ip4(), header, lls, body }
    }

    /// What the fuzz target checks, for one buffer.
    fn check_bytes(data: &[u8], e: &Endpoints) {
        let parsed = Packet::parse(data, e);
        assert_eq!(collect(data, e), parsed);
        if let Ok(p) = &parsed {
            // Dropped LSAs and signaling blocks make it shorter.
            let b = p.frame(e).and_then(|frame| frame.to_bytes()).unwrap();
            assert!(b.len() <= data.len());
            assert_eq!(Packet::parse(&b, e).as_ref(), Ok(p));
        }
        for v in [Version::V2, Version::V3] {
            if let Ok((l, n)) = Lsa::parse(data, v) {
                // An LSA read writes back to the same bytes, so its header
                // and checksum are the ones received.
                assert!(n <= data.len());
                let b = l.frame(v).and_then(|frame| frame.to_bytes()).unwrap();
                assert_eq!(b, data[..n]);
                assert_eq!(l.header(v).map(|h| (h.checksum, h.length)), Ok((be16(data, 16).unwrap(), n as u16)));
            }
            if data.len() >= LSA_HEADER_LEN {
                let t = if v == Version::V2 { u16::from(data[3]) } else { be16(data, 2).unwrap() };
                if let Ok(body) = LsaBody::parse(&data[LSA_HEADER_LEN..], v, t) {
                    assert_eq!(body.frame(v, t).and_then(|frame| frame.to_bytes()).as_deref(), Ok(&data[LSA_HEADER_LEN..]));
                }
            }
        }
    }

    /// A prefix with a length that may be out of range, built with
    /// [`Prefix::new`] or directly, with bits past the length.
    fn wild_prefix(rng: &mut Lcg) -> Prefix {
        if !rng.coin() {
            Prefix::new(rng.next() as u8, rng.next() as u8, rng.ip6())
        } else {
            Prefix { length: rng.index(140) as u8, options: rng.next() as u8, address: rng.ip6() }
        }
    }

    /// Sets one field of `l` to a value that may not fit, as a careless
    /// world might.
    fn perturb_lsa(rng: &mut Lcg, l: &mut Lsa) {
        match rng.index(6) {
            0 => l.ls_type = rng.next() as u16,
            1 => l.options = rng.next() as u8,
            2 => l.age = rng.next() as u16,
            3 => l.sequence = if !rng.coin() { RESERVED_SEQUENCE } else { u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)) },
            4 => match &mut l.body {
                LsaBody::Router(r) => {
                    if let Some(link) = r.links.first_mut() {
                        if !rng.coin() {
                            link.tos = vec![TosMetric { tos: 1, metric: 1 }; rng.index(300)];
                        } else {
                            link.kind = rng.next() as u8;
                        }
                    }
                }
                LsaBody::Network(n) => n.attached_routers.truncate(rng.index(2)),
                LsaBody::NetworkV3(n) => {
                    if !rng.coin() {
                        n.options = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8));
                    } else {
                        n.attached_routers.truncate(rng.index(2));
                    }
                }
                LsaBody::Summary(s) => {
                    if !rng.coin() {
                        s.metric = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8));
                    } else {
                        s.network_mask = rng.ip4();
                    }
                }
                LsaBody::AsExternal(e) => match rng.index(3) {
                    0 => e.routes.clear(),
                    1 => e.routes[0].tos = rng.next() as u8,
                    _ => e.routes[0].metric = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                },
                LsaBody::RouterV3(r) => match r.interfaces.first_mut() {
                    Some(i) if !rng.coin() => i.kind = rng.next() as u8,
                    _ => r.options = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                },
                LsaBody::InterAreaPrefix(p) => p.prefix = wild_prefix(rng),
                LsaBody::InterAreaRouter(r) => r.metric = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)),
                LsaBody::AsExternalV3(e) => match rng.index(3) {
                    0 => e.prefix = wild_prefix(rng),
                    1 => e.referenced = Some((rng.index(3) as u16, rng.ip4())),
                    _ => {
                        let a = ["::", "fe80::1", "fe80::", "2001:db8::1"][rng.index(4)];
                        e.forwarding_address = Some(a.parse().unwrap());
                    }
                },
                LsaBody::Link(k) => k.prefixes.push(wild_prefix(rng)),
                LsaBody::IntraAreaPrefix(k) => k.prefixes.push((wild_prefix(rng), 1)),
                LsaBody::Other(_) => {}
            },
            _ => {}
        }
    }

    #[test]
    fn writers_never_write_what_readers_reject() {
        // Values with fields set out of range: each write either fails or
        // gives bytes that read back as the same value.
        let mut rng = Lcg::new(0x77);
        let ends = [v4_ends(), v6_ends()];
        let mut written = 0;
        for round in 0..6000 {
            let e = ends[round % 2];
            let v = e.version();
            let mut p = random_packet(&mut rng, v);
            match &mut p.body {
                Body::LinkStateUpdate(lsas) => {
                    for l in lsas {
                        perturb_lsa(&mut rng, l);
                    }
                }
                Body::DatabaseDescription(d) => {
                    d.options = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)) >> rng.index(32);
                    if let Some(h) = d.headers.first_mut() {
                        h.options = rng.next() as u8;
                        h.ls_type = rng.next() as u16;
                    }
                }
                Body::LinkStateAck(hs) => {
                    if let Some(h) = hs.first_mut() {
                        match rng.index(4) {
                            0 => h.length = rng.index(40) as u16,
                            1 => h.checksum = rng.next() as u16 & 0xff00,
                            2 => h.age = rng.next() as u16,
                            _ => {
                                h.options = rng.next() as u8;
                                h.ls_type = rng.next() as u16;
                            }
                        }
                    }
                }
                Body::LinkStateRequest(keys) => {
                    if let Some(k) = keys.first_mut() {
                        k.ls_type = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8));
                    }
                }
                Body::HelloV3(h) => h.options = u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)) >> rng.index(32),
                Body::HelloV2(h) => h.options = rng.next() as u8,
            }
            if rng.index(4) == 0 {
                p.lls = Some(rng.bytes(9));
            }
            match rng.index(4) {
                0 => p.header = Header::V2 { auth: Auth::Other { kind: rng.index(5) as u16, data: [7; 8] } },
                1 => p.header = Header::V3 { instance_id: 1 },
                _ => {}
            }
            let end = if rng.index(8) == 0 { ends[(round + 1) % 2] } else { e };
            if let Ok(b) = p.frame(&end).and_then(|frame| frame.to_bytes()) {
                assert_eq!(Packet::parse(&b, &end).as_ref(), Ok(&p), "round {round}");
                written += 1;
            }
            let mut l = random_lsa(&mut rng, v);
            perturb_lsa(&mut rng, &mut l);
            if let Ok(b) = l.frame(v).and_then(|frame| frame.to_bytes()) {
                assert_eq!(Lsa::parse(&b, v), Ok((l, b.len())), "round {round}");
            }
        }
        // Many values still fit, so the check has teeth.
        assert!(written > 1000, "{written}");
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x05f5);
        let ends = [v4_ends(), v6_ends()];
        for round in 0..6000 {
            let e = ends[round % 2];
            let p = random_packet(&mut rng, e.version());
            let good = p.frame(&e).and_then(|frame| frame.to_bytes()).unwrap();
            assert_eq!(Packet::parse(&good, &e).as_ref(), Ok(&p), "round {round}");
            check_bytes(&good, &e);
            // Mutations, with the checksums fixed again so the parser
            // looks past them.
            let mut bad = good.clone();
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut bad);
            }
            check_bytes(&bad, &e);
            check_bytes(&fix(bad.clone(), &e), &e);
            // An LSA, with its checksum set right after mutating it.
            let l = random_lsa(&mut rng, e.version());
            let mut lb = l.frame(e.version()).and_then(|frame| frame.to_bytes()).unwrap();
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut lb);
            }
            check_bytes(&fix_lsa(lb), &e);
            // Random bytes behind a plausible header.
            let mut raw = rng.bytes(80);
            if raw.len() >= 4 {
                raw[0] = e.version().number();
                raw[1] = 1 + rng.index(5) as u8;
                let len = raw.len() as u16;
                raw[2..4].copy_from_slice(&len.to_be_bytes());
            }
            check_bytes(&fix(raw, &e), &e);
        }
    }
}
