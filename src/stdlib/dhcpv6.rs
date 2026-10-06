//! DHCPv6: reading and writing client, server and relay messages and their
//! options, with no I/O.
//!
//! DHCPv6 is how a host on an IPv6 network gets addresses, delegated
//! prefixes and settings such as DNS servers. A client sends to UDP port
//! 547 on the multicast address `ff02::1:2`, and servers and relay agents
//! answer to port 546. A client asks with a Solicit, a server offers with an
//! Advertise, the client takes the offer with a Request, and the server
//! confirms it with a Reply. Renew, Rebind, Release and the other messages
//! keep the lease going. A relay agent wraps a client's message in a
//! Relay-forward message to reach a server on another link, and the server
//! answers inside a Relay-reply. This module follows RFC 8415, and reads
//! the DNS options of RFC 3646 too.
//!
//! A client or server message is a type, a 24-bit transaction ID and
//! options. A relay message is a type, a hop count, two addresses and
//! options; the message it carries is the bytes of its Relay Message
//! option, read with [`Message::relayed`]. Each option is a code, a length
//! and a body. Identity associations (IA_NA for addresses, IA_PD for
//! prefixes) hold further options inside their bodies, so options nest.
//!
//! Nothing here reads a socket. A world that plays a DHCPv6 server reads
//! each UDP datagram with [`Message::parse`], starts its reply with
//! [`Message::answer`], adds the addresses and prefixes it hands out, and
//! sends [`Message::to_bytes`] back. Which addresses exist and who gets them
//! is up to world code. For DHCPv6 over TCP, as leasequery uses, a
//! [`Stream<Frames>`](super::codec::Stream) splits the stream into messages.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. Options nest at most [`MAX_DEPTH`] deep; deeper ones are
//! kept as raw bytes. Writers refuse fields that cannot be written unchanged.
//! A message that parses writes back to the same bytes.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use std::net::Ipv6Addr;
//! use fictionet::stdlib::dhcpv6::{msg, opt, DhcpOption, Duid, IaAddr, IaNa, Message};
//!
//! // A client asks for an address: a Solicit with its DUID and one IA_NA.
//! let client = Duid::ll(1, &[0x02, 0, 0, 0, 0, 0x01]);
//! let mut solicit = Message::new(msg::SOLICIT, 0x00ab_cdef);
//! solicit.options.push(DhcpOption::ClientId(client.clone()));
//! solicit.options.push(DhcpOption::ElapsedTime(0));
//! solicit.options.push(DhcpOption::IaNa(IaNa { iaid: 1, t1: 0, t2: 0, options: vec![] }));
//! solicit.options.push(DhcpOption::Oro(vec![opt::DNS_SERVERS]));
//! let datagram = solicit.to_bytes().unwrap();
//!
//! // The server reads it and offers 2001:db8::10 in an Advertise.
//! let server = Duid::en(32473, b"world");
//! let request = Message::parse(&datagram).unwrap();
//! let mut advertise = request.answer(msg::ADVERTISE, &server);
//! for ia in request.ia_na() {
//!     let address = IaAddr { address: "2001:db8::10".parse().unwrap(), preferred: 3600, valid: 7200, options: vec![] };
//!     let options = vec![DhcpOption::IaAddr(address)];
//!     advertise.options.push(DhcpOption::IaNa(IaNa { iaid: ia.iaid, t1: 1800, t2: 2880, options }));
//! }
//! advertise.options.push(DhcpOption::DnsServers(vec!["2001:db8::53".parse().unwrap()]));
//!
//! // The client reads the offer.
//! let offer = Message::parse(&advertise.to_bytes().unwrap()).unwrap();
//! assert_eq!(offer.msg_type, msg::ADVERTISE);
//! assert_eq!(offer.transaction, 0x00ab_cdef);
//! assert_eq!(offer.client_id(), Some(&client));
//! assert_eq!(offer.server_id(), Some(&server));
//! let ia = offer.ia_na().next().unwrap();
//! assert_eq!(ia.iaid, 1);
//! let lease = ia.addresses().next().unwrap();
//! assert_eq!(lease.address, "2001:db8::10".parse::<Ipv6Addr>().unwrap());
//! assert_eq!(lease.valid, 7200);
//! ```

use core::convert::Infallible;
use std::net::Ipv6Addr;

use super::codec::{Decode, Step, Wire};

/// The UDP port DHCPv6 clients listen on.
pub const CLIENT_PORT: u16 = 546;
/// The UDP port DHCPv6 servers and relay agents listen on.
pub const SERVER_PORT: u16 = 547;
/// The link-scoped multicast address of every relay agent and server,
/// `ff02::1:2`. Clients send here.
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
/// The site-scoped multicast address of every server, `ff05::1:3`.
pub const ALL_DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);

/// The longest message: the most a UDP datagram over IPv6 can carry
/// without jumbograms. Longer bytes are refused, and writers stay within
/// it.
pub const MAX_MESSAGE: usize = 65_527;
/// The longest message over TCP, where a 2-byte length comes before each
/// message (RFC 5460, section 5.1). [`Stream<Frames>`](super::codec::Stream) reads messages this long,
/// and [`Frame`] writes them.
pub const MAX_TCP_MESSAGE: usize = 65_535;
/// The most bytes a [`Stream<Frames>`](super::codec::Stream) holds that have not been taken out: one
/// whole message over TCP and its length.
pub const MAX_BUFFERED: usize = 2 + MAX_TCP_MESSAGE;
/// The length of a client or server message's header: the type and the
/// transaction ID.
pub const CLIENT_HEADER_LEN: usize = 4;
/// The length of a relay message's header: the type, the hop count, the
/// link address and the peer address.
pub const RELAY_HEADER_LEN: usize = 34;
/// How many option lists deep options are read. The options of a message
/// are at depth 0; the options inside an IA_NA are at depth 1, and those
/// inside one of its addresses at depth 2. An option that holds options
/// and sits at this depth or deeper is kept as [`DhcpOption::Other`].
pub const MAX_DEPTH: usize = 8;
/// The shortest DUID read: a 2-byte type and at least one byte of
/// identifier.
pub const MIN_DUID: usize = 3;
/// The longest DUID: a 2-byte type and at most 128 bytes of identifier.
pub const MAX_DUID: usize = 130;
/// The longest domain name in a Domain Search List, in its wire form.
pub const MAX_NAME: usize = 255;
/// The longest label of a domain name.
pub const MAX_LABEL: usize = 63;
/// The hop count past which a relay agent drops a Relay-forward message
/// instead of passing it on.
pub const HOP_COUNT_LIMIT: u8 = 8;
/// A lifetime or time value that means forever.
pub const INFINITY: u32 = 0xffff_ffff;

/// Message types.
pub mod msg {
    /// A client looks for servers.
    pub const SOLICIT: u8 = 1;
    /// A server offers itself, in answer to a Solicit.
    pub const ADVERTISE: u8 = 2;
    /// A client asks one server for addresses and settings.
    pub const REQUEST: u8 = 3;
    /// A client asks whether its addresses still suit the link it is on.
    pub const CONFIRM: u8 = 4;
    /// A client asks the server that gave its leases to extend them.
    pub const RENEW: u8 = 5;
    /// A client asks any server to extend its leases.
    pub const REBIND: u8 = 6;
    /// A server answers a Request, Renew, Rebind, Release, Decline,
    /// Confirm or Information-request, or a Solicit with Rapid Commit.
    pub const REPLY: u8 = 7;
    /// A client gives leases back.
    pub const RELEASE: u8 = 8;
    /// A client says an address it was given is already in use.
    pub const DECLINE: u8 = 9;
    /// A server tells a client to renew or ask for settings again.
    pub const RECONFIGURE: u8 = 10;
    /// A client asks for settings and no addresses.
    pub const INFORMATION_REQUEST: u8 = 11;
    /// A relay agent passes a message on toward the servers.
    pub const RELAY_FORW: u8 = 12;
    /// A server sends a message back through a relay agent.
    pub const RELAY_REPL: u8 = 13;
}

/// Option codes this module reads into typed options.
pub mod opt {
    /// The client's DUID.
    pub const CLIENTID: u16 = 1;
    /// The server's DUID.
    pub const SERVERID: u16 = 2;
    /// An identity association for non-temporary addresses.
    pub const IA_NA: u16 = 3;
    /// An identity association for temporary addresses.
    pub const IA_TA: u16 = 4;
    /// An address inside an IA_NA or IA_TA.
    pub const IAADDR: u16 = 5;
    /// The option codes a client asks for.
    pub const ORO: u16 = 6;
    /// A server's preference, 0 to 255.
    pub const PREFERENCE: u16 = 7;
    /// How long the client has been trying, in hundredths of a second.
    pub const ELAPSED_TIME: u16 = 8;
    /// The message a relay agent carries.
    pub const RELAY_MSG: u16 = 9;
    /// Authentication.
    pub const AUTH: u16 = 11;
    /// A unicast address the client may send to.
    pub const UNICAST: u16 = 12;
    /// A status code and message.
    pub const STATUS_CODE: u16 = 13;
    /// The client takes a Reply to its Solicit at once.
    pub const RAPID_COMMIT: u16 = 14;
    /// The client's user classes.
    pub const USER_CLASS: u16 = 15;
    /// The client's vendor and vendor classes.
    pub const VENDOR_CLASS: u16 = 16;
    /// Vendor-specific information.
    pub const VENDOR_OPTS: u16 = 17;
    /// The relay agent's name for the interface a message came in on.
    pub const INTERFACE_ID: u16 = 18;
    /// The message type a Reconfigure asks the client to send.
    pub const RECONF_MSG: u16 = 19;
    /// The client takes Reconfigure messages.
    pub const RECONF_ACCEPT: u16 = 20;
    /// Recursive DNS servers (RFC 3646).
    pub const DNS_SERVERS: u16 = 23;
    /// The domain search list (RFC 3646).
    pub const DOMAIN_LIST: u16 = 24;
    /// An identity association for prefix delegation.
    pub const IA_PD: u16 = 25;
    /// A prefix inside an IA_PD.
    pub const IAPREFIX: u16 = 26;
    /// How long a client waits before asking for settings again.
    pub const INFORMATION_REFRESH_TIME: u16 = 32;
    /// The longest wait between Solicit retransmissions.
    pub const SOL_MAX_RT: u16 = 82;
    /// The longest wait between Information-request retransmissions.
    pub const INF_MAX_RT: u16 = 83;
}

/// Status codes, carried in a Status Code option.
pub mod status {
    /// It worked.
    pub const SUCCESS: u16 = 0;
    /// It failed for a reason no other code names.
    pub const UNSPEC_FAIL: u16 = 1;
    /// The server has no addresses for this IA.
    pub const NO_ADDRS_AVAIL: u16 = 2;
    /// The server has no lease for this IA.
    pub const NO_BINDING: u16 = 3;
    /// The prefix of the address does not suit the client's link.
    pub const NOT_ON_LINK: u16 = 4;
    /// The client sent by unicast and must use multicast.
    pub const USE_MULTICAST: u16 = 5;
    /// The server has no prefixes for this IA.
    pub const NO_PREFIX_AVAIL: u16 = 6;
}

/// DUID types: the first two bytes of a [`Duid`].
pub mod duid_type {
    /// A link-layer address and a time.
    pub const LLT: u16 = 1;
    /// An enterprise number and an identifier the vendor assigns.
    pub const EN: u16 = 2;
    /// A link-layer address.
    pub const LL: u16 = 3;
    /// A UUID.
    pub const UUID: u16 = 4;
}

/// Hardware types used in DUIDs, from the ARP parameters registry.
pub mod hardware {
    /// Ethernet.
    pub const ETHERNET: u16 = 1;
}

/// A DHCP Unique Identifier: the bytes that name a client or a server,
/// starting with a 2-byte type. A DUID is read only if it is
/// [`MIN_DUID`] to [`MAX_DUID`] bytes long; writers refuse any other.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Duid(
    /// The DUID type and identifier bytes.
    pub Vec<u8>,
);

impl Duid {
    /// A DUID-LLT: a hardware type, a time in seconds since midnight UTC on
    /// 2000-01-01, and a link-layer address.
    pub fn llt(hardware: u16, time: u32, link_layer: &[u8]) -> Duid {
        let mut b = Vec::with_capacity(8 + link_layer.len());
        b.extend_from_slice(&duid_type::LLT.to_be_bytes());
        b.extend_from_slice(&hardware.to_be_bytes());
        b.extend_from_slice(&time.to_be_bytes());
        b.extend_from_slice(link_layer);
        Duid(b)
    }

    /// A DUID-EN: an IANA enterprise number and an identifier.
    pub fn en(enterprise: u32, id: &[u8]) -> Duid {
        let mut b = Vec::with_capacity(6 + id.len());
        b.extend_from_slice(&duid_type::EN.to_be_bytes());
        b.extend_from_slice(&enterprise.to_be_bytes());
        b.extend_from_slice(id);
        Duid(b)
    }

    /// A DUID-LL: a hardware type and a link-layer address.
    pub fn ll(hardware: u16, link_layer: &[u8]) -> Duid {
        let mut b = Vec::with_capacity(4 + link_layer.len());
        b.extend_from_slice(&duid_type::LL.to_be_bytes());
        b.extend_from_slice(&hardware.to_be_bytes());
        b.extend_from_slice(link_layer);
        Duid(b)
    }

    /// A DUID-UUID (RFC 6355).
    pub fn uuid(uuid: [u8; 16]) -> Duid {
        let mut b = Vec::with_capacity(18);
        b.extend_from_slice(&duid_type::UUID.to_be_bytes());
        b.extend_from_slice(&uuid);
        Duid(b)
    }

    /// The DUID's type, if it has two bytes for one.
    pub fn kind(&self) -> Option<u16> {
        match self.0.as_slice() {
            [a, b, ..] => Some(u16::from_be_bytes([*a, *b])),
            _ => None,
        }
    }

    /// Whether the DUID's length is one a message may carry.
    pub fn is_valid(&self) -> bool {
        (MIN_DUID..=MAX_DUID).contains(&self.0.len())
    }
}

impl Wire for Duid {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads a DUID. Refuses lengths outside [`MIN_DUID`] through [`MAX_DUID`].
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if !(MIN_DUID..=MAX_DUID).contains(&bytes.len()) {
            return Err(ParseError::BadOption(opt::CLIENTID));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Appends a DUID. Refuses invalid lengths. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if !self.is_valid() {
            return Err(WriteError::Unwritable);
        }
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

/// An identity association for non-temporary addresses (IA_NA): the
/// addresses a server gives a client, under an ID the client picks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IaNa {
    /// The identity association's ID, picked by the client.
    pub iaid: u32,
    /// Seconds until the client should renew with the same server.
    pub t1: u32,
    /// Seconds until the client should rebind with any server.
    pub t2: u32,
    /// The options inside: [`IaAddr`]s and a status code, usually.
    pub options: Vec<DhcpOption>,
}

/// An identity association for temporary addresses (IA_TA).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IaTa {
    /// The identity association's ID, picked by the client.
    pub iaid: u32,
    /// The options inside: [`IaAddr`]s and a status code, usually.
    pub options: Vec<DhcpOption>,
}

/// An address inside an IA_NA or IA_TA (IAADDR), with its lifetimes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaAddr {
    /// The address.
    pub address: Ipv6Addr,
    /// Seconds the address stays preferred.
    pub preferred: u32,
    /// Seconds the address stays valid.
    pub valid: u32,
    /// The options inside: a status code, usually.
    pub options: Vec<DhcpOption>,
}

/// An identity association for prefix delegation (IA_PD): the prefixes a
/// server delegates to a router, under an ID the router picks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IaPd {
    /// The identity association's ID, picked by the client.
    pub iaid: u32,
    /// Seconds until the client should renew with the same server.
    pub t1: u32,
    /// Seconds until the client should rebind with any server.
    pub t2: u32,
    /// The options inside: [`IaPrefix`]es and a status code, usually.
    pub options: Vec<DhcpOption>,
}

/// A prefix inside an IA_PD (IAPREFIX), with its lifetimes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaPrefix {
    /// Seconds the prefix stays preferred.
    pub preferred: u32,
    /// Seconds the prefix stays valid.
    pub valid: u32,
    /// The prefix length in bits, 0 to 128.
    pub prefix_len: u8,
    /// The prefix.
    pub prefix: Ipv6Addr,
    /// The options inside: a status code, usually.
    pub options: Vec<DhcpOption>,
}

/// A status code and a message for people to read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusCode {
    /// The code, one of [`status`].
    pub code: u16,
    /// The message, in UTF-8. It may be empty. A message that ends in a
    /// NUL byte is refused, as RFC 8415 does not allow one.
    pub message: String,
}

/// The Authentication option's fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Auth {
    /// The authentication protocol: 3 is reconfigure key.
    pub protocol: u8,
    /// The algorithm the protocol uses.
    pub algorithm: u8,
    /// The replay detection method: 0 is a counter.
    pub rdm: u8,
    /// The replay detection value.
    pub replay_detection: u64,
    /// The protocol's own bytes, unread.
    pub info: Vec<u8>,
}

/// One option. Options this module knows are read into their fields;
/// any other is kept as its code and body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DhcpOption {
    /// Option 1: the client's DUID.
    ClientId(Duid),
    /// Option 2: the server's DUID.
    ServerId(Duid),
    /// Option 3: an identity association for non-temporary addresses.
    IaNa(IaNa),
    /// Option 4: an identity association for temporary addresses.
    IaTa(IaTa),
    /// Option 5: an address and its lifetimes.
    IaAddr(IaAddr),
    /// Option 6: the option codes a client asks for.
    Oro(Vec<u16>),
    /// Option 7: a server's preference. 255 tells the client to take this
    /// server at once.
    Preference(u8),
    /// Option 8: how long the client has been trying, in hundredths of a
    /// second.
    ElapsedTime(u16),
    /// Option 9: the message a relay agent carries, as bytes. Read it with
    /// [`Message::parse`] or [`Message::relayed`].
    RelayMessage(Vec<u8>),
    /// Option 11: authentication.
    Auth(Auth),
    /// Option 12: the server's address, which the client may send to
    /// directly.
    Unicast(Ipv6Addr),
    /// Option 13: a status code and message.
    StatusCode(StatusCode),
    /// Option 14: the client takes a Reply to its Solicit at once.
    RapidCommit,
    /// Option 15: the client's user classes, each as bytes. It holds at
    /// least one; readers and writers refuse an empty list.
    UserClass(Vec<Vec<u8>>),
    /// Option 16: the client's vendor and its vendor classes.
    VendorClass {
        /// The vendor's IANA enterprise number.
        enterprise: u32,
        /// The vendor classes, each as bytes. It holds at least one; an
        /// empty list is refused by readers and writers.
        classes: Vec<Vec<u8>>,
    },
    /// Option 17: vendor-specific information.
    VendorOpts {
        /// The vendor's IANA enterprise number.
        enterprise: u32,
        /// The vendor's options, unread. They must be a run of options, each
        /// a 2-byte code, a 2-byte length and that many bytes; other bytes
        /// are refused by readers and writers.
        data: Vec<u8>,
    },
    /// Option 18: the relay agent's name for an interface, as bytes.
    InterfaceId(Vec<u8>),
    /// Option 19: the message type a Reconfigure asks for: Renew, Rebind
    /// or Information-request.
    ReconfigureMessage(u8),
    /// Option 20: the client takes Reconfigure messages.
    ReconfigureAccept,
    /// Option 23: recursive DNS servers. It holds at least one; an empty
    /// list is refused by readers and writers.
    DnsServers(Vec<Ipv6Addr>),
    /// Option 24: the domain search list, each name with dots between its
    /// labels and no dot at the end. The root is the empty string. Labels
    /// hold letters, digits, hyphens and underscores. A list in the right
    /// form with any other byte in a label is kept as
    /// [`DhcpOption::Other`], since a dot inside a label could not be told
    /// apart from one between labels.
    DomainList(Vec<String>),
    /// Option 25: an identity association for prefix delegation.
    IaPd(IaPd),
    /// Option 26: a prefix and its lifetimes.
    IaPrefix(IaPrefix),
    /// Option 32: how long a client waits before asking for settings
    /// again, in seconds.
    InformationRefreshTime(u32),
    /// Option 82: the longest wait between Solicits, in seconds.
    SolMaxRt(u32),
    /// Option 83: the longest wait between Information-requests, in
    /// seconds.
    InfMaxRt(u32),
    /// Any other option, with its body unread.
    Other {
        /// The option code.
        code: u16,
        /// The option body.
        data: Vec<u8>,
    },
}

impl DhcpOption {
    /// The option's code.
    pub fn code(&self) -> u16 {
        match self {
            DhcpOption::ClientId(_) => opt::CLIENTID,
            DhcpOption::ServerId(_) => opt::SERVERID,
            DhcpOption::IaNa(_) => opt::IA_NA,
            DhcpOption::IaTa(_) => opt::IA_TA,
            DhcpOption::IaAddr(_) => opt::IAADDR,
            DhcpOption::Oro(_) => opt::ORO,
            DhcpOption::Preference(_) => opt::PREFERENCE,
            DhcpOption::ElapsedTime(_) => opt::ELAPSED_TIME,
            DhcpOption::RelayMessage(_) => opt::RELAY_MSG,
            DhcpOption::Auth(_) => opt::AUTH,
            DhcpOption::Unicast(_) => opt::UNICAST,
            DhcpOption::StatusCode(_) => opt::STATUS_CODE,
            DhcpOption::RapidCommit => opt::RAPID_COMMIT,
            DhcpOption::UserClass(_) => opt::USER_CLASS,
            DhcpOption::VendorClass { .. } => opt::VENDOR_CLASS,
            DhcpOption::VendorOpts { .. } => opt::VENDOR_OPTS,
            DhcpOption::InterfaceId(_) => opt::INTERFACE_ID,
            DhcpOption::ReconfigureMessage(_) => opt::RECONF_MSG,
            DhcpOption::ReconfigureAccept => opt::RECONF_ACCEPT,
            DhcpOption::DnsServers(_) => opt::DNS_SERVERS,
            DhcpOption::DomainList(_) => opt::DOMAIN_LIST,
            DhcpOption::IaPd(_) => opt::IA_PD,
            DhcpOption::IaPrefix(_) => opt::IAPREFIX,
            DhcpOption::InformationRefreshTime(_) => opt::INFORMATION_REFRESH_TIME,
            DhcpOption::SolMaxRt(_) => opt::SOL_MAX_RT,
            DhcpOption::InfMaxRt(_) => opt::INF_MAX_RT,
            DhcpOption::Other { code, .. } => *code,
        }
    }
}

macro_rules! association_status {
    ($($type:ty),+ $(,)?) => {$(
        impl $type {
            /// The status code inside this association, if present.
            pub fn status(&self) -> Option<&StatusCode> {
                find_status(&self.options)
            }
        }
    )+};
}

association_status!(IaNa, IaTa, IaAddr, IaPd, IaPrefix);

impl IaNa {
    /// The addresses inside.
    pub fn addresses(&self) -> impl Iterator<Item = &IaAddr> {
        self.options.iter().filter_map(|o| if let DhcpOption::IaAddr(a) = o { Some(a) } else { None })
    }
}

impl IaTa {
    /// The addresses inside.
    pub fn addresses(&self) -> impl Iterator<Item = &IaAddr> {
        self.options.iter().filter_map(|o| if let DhcpOption::IaAddr(a) = o { Some(a) } else { None })
    }
}

impl IaPd {
    /// The prefixes inside.
    pub fn prefixes(&self) -> impl Iterator<Item = &IaPrefix> {
        self.options.iter().filter_map(|o| if let DhcpOption::IaPrefix(p) = o { Some(p) } else { None })
    }
}

/// Why bytes are not a DHCPv6 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The bytes are shorter than the message's header.
    Short,
    /// The bytes are longer than [`MAX_MESSAGE`]; the length is given.
    TooLong(usize),
    /// An option's header or body runs past the end of the bytes that hold
    /// it.
    Truncated,
    /// The option with this code has a body its definition does not
    /// allow, such as the wrong length.
    BadOption(u16),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Short => f.write_str("shorter than a DHCPv6 header"),
            ParseError::TooLong(n) => write!(f, "{n} bytes, longer than a DHCPv6 message may be"),
            ParseError::Truncated => f.write_str("an option runs past the end of the message"),
            ParseError::BadOption(c) => write!(f, "option {c} is malformed"),
        }
    }
}

impl std::error::Error for ParseError {}

/// One DHCPv6 message. Client and server messages use `transaction`;
/// relay messages ([`msg::RELAY_FORW`] and [`msg::RELAY_REPL`]) use
/// `hop_count`, `link_address` and `peer_address` instead. Which fields
/// are written depends on `msg_type`, and the fields a message does not
/// use read back as zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The message type, one of [`msg`] or any other value.
    pub msg_type: u8,
    /// The 24-bit transaction ID the client picks. Only its low 24 bits
    /// are written.
    pub transaction: u32,
    /// How many relay agents have passed the message on before this one.
    pub hop_count: u8,
    /// An address the server can use to tell which link the client is on,
    /// or zero.
    pub link_address: Ipv6Addr,
    /// The address of the client or relay agent the message came from, or
    /// goes to.
    pub peer_address: Ipv6Addr,
    /// The options, in order.
    pub options: Vec<DhcpOption>,
}

impl Message {
    /// A client or server message of type `msg_type`, with no options.
    pub fn new(msg_type: u8, transaction: u32) -> Message {
        Message {
            msg_type,
            transaction: transaction & 0x00ff_ffff,
            hop_count: 0,
            link_address: Ipv6Addr::UNSPECIFIED,
            peer_address: Ipv6Addr::UNSPECIFIED,
            options: Vec::new(),
        }
    }

    /// Wraps a message for relay transport. Refuses an unwritable inner
    /// message. The outer message must also fit when written.
    pub fn relay_forward(
        inner: &Message,
        hop_count: u8,
        link_address: Ipv6Addr,
        peer_address: Ipv6Addr,
    ) -> Result<Message, WriteError> {
        Ok(Message {
            msg_type: msg::RELAY_FORW,
            transaction: 0,
            hop_count,
            link_address,
            peer_address,
            options: vec![DhcpOption::RelayMessage(inner.to_bytes()?)],
        })
    }

    /// Reads the message in `b`, refusing more than `limit` bytes.
    fn parse_within(b: &[u8], limit: usize) -> Result<Message, ParseError> {
        if b.len() > limit {
            return Err(ParseError::TooLong(b.len()));
        }
        let &msg_type = b.first().ok_or(ParseError::Short)?;
        let mut m = Message::new(msg_type, 0);
        let rest = if m.is_relay() {
            if b.len() < RELAY_HEADER_LEN {
                return Err(ParseError::Short);
            }
            m.hop_count = b[1];
            m.link_address = addr(b, 2);
            m.peer_address = addr(b, 18);
            &b[RELAY_HEADER_LEN..]
        } else {
            if b.len() < CLIENT_HEADER_LEN {
                return Err(ParseError::Short);
            }
            m.transaction = u32::from_be_bytes([0, b[1], b[2], b[3]]);
            &b[CLIENT_HEADER_LEN..]
        };
        m.options = parse_options(rest, 0)?;
        Ok(m)
    }

    /// The message's bytes, in at most `limit` bytes.
    fn write_within(&self, limit: usize) -> Result<Vec<u8>, WriteError> {
        if (self.is_relay() && self.transaction != 0)
            || (!self.is_relay()
                && (self.transaction > 0x00ff_ffff
                    || self.hop_count != 0
                    || self.link_address != Ipv6Addr::UNSPECIFIED
                    || self.peer_address != Ipv6Addr::UNSPECIFIED))
        {
            return Err(WriteError::Unwritable);
        }
        let mut out = Vec::new();
        out.push(self.msg_type);
        if self.is_relay() {
            out.push(self.hop_count);
            out.extend_from_slice(&self.link_address.octets());
            out.extend_from_slice(&self.peer_address.octets());
        } else {
            out.extend_from_slice(&self.transaction.to_be_bytes()[1..]);
        }
        let budget = limit - out.len();
        out.extend_from_slice(&encode_options(&self.options, 0, budget).ok_or(WriteError::Unwritable)?);
        Ok(out)
    }

    /// Whether this is a relay message: Relay-forward or Relay-reply.
    pub fn is_relay(&self) -> bool {
        self.msg_type == msg::RELAY_FORW || self.msg_type == msg::RELAY_REPL
    }

    /// The first option with code `code`.
    pub fn option(&self, code: u16) -> Option<&DhcpOption> {
        self.options.iter().find(|o| o.code() == code)
    }

    /// The client's DUID, from the Client Identifier option.
    pub fn client_id(&self) -> Option<&Duid> {
        self.options.iter().find_map(|o| if let DhcpOption::ClientId(d) = o { Some(d) } else { None })
    }

    /// The server's DUID, from the Server Identifier option.
    pub fn server_id(&self) -> Option<&Duid> {
        self.options.iter().find_map(|o| if let DhcpOption::ServerId(d) = o { Some(d) } else { None })
    }

    /// The message's own status code, if it has one. Status codes inside
    /// identity associations are read from those.
    pub fn status(&self) -> Option<&StatusCode> {
        find_status(&self.options)
    }

    /// The identity associations for non-temporary addresses.
    pub fn ia_na(&self) -> impl Iterator<Item = &IaNa> {
        self.options.iter().filter_map(|o| if let DhcpOption::IaNa(ia) = o { Some(ia) } else { None })
    }

    /// The identity associations for temporary addresses.
    pub fn ia_ta(&self) -> impl Iterator<Item = &IaTa> {
        self.options.iter().filter_map(|o| if let DhcpOption::IaTa(ia) = o { Some(ia) } else { None })
    }

    /// The identity associations for prefix delegation.
    pub fn ia_pd(&self) -> impl Iterator<Item = &IaPd> {
        self.options.iter().filter_map(|o| if let DhcpOption::IaPd(ia) = o { Some(ia) } else { None })
    }

    /// The option codes the client asks for, from the Option Request
    /// option. It is empty if there is no such option.
    pub fn requested_options(&self) -> &[u16] {
        self.options
            .iter()
            .find_map(|o| if let DhcpOption::Oro(c) = o { Some(c.as_slice()) } else { None })
            .unwrap_or(&[])
    }

    /// The relay agent's name for the interface the message came in on,
    /// from the Interface-Id option.
    pub fn interface_id(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| if let DhcpOption::InterfaceId(b) = o { Some(b.as_slice()) } else { None })
    }

    /// The message a relay message carries, read from its Relay Message
    /// option. It returns `None` if there is no such option, or if this is
    /// not a relay message, since RFC 8415 (section 21.10) puts the option
    /// only in those. That message may be a relay message too; call this
    /// again to unwrap it. Each call reads the inner bytes afresh, so a
    /// server should stop after [`HOP_COUNT_LIMIT`] + 1 layers, the most
    /// that relay agents pass on.
    pub fn relayed(&self) -> Option<Result<Message, ParseError>> {
        if !self.is_relay() {
            return None;
        }
        self.options
            .iter()
            .find_map(|o| if let DhcpOption::RelayMessage(b) = o { Some(Message::parse(b)) } else { None })
    }

    /// The start of a server's answer to this client message: a message of
    /// type `msg_type` (usually [`msg::ADVERTISE`] or [`msg::REPLY`]) with
    /// the same transaction ID, the server's DUID, and the client's DUID
    /// copied if this message has one. The caller adds the rest.
    pub fn answer(&self, msg_type: u8, server_id: &Duid) -> Message {
        let mut m = Message::new(msg_type, self.transaction);
        m.options.push(DhcpOption::ServerId(server_id.clone()));
        if let Some(c) = self.client_id() {
            m.options.push(DhcpOption::ClientId(c.clone()));
        }
        m
    }

    /// Wraps a message for relay transport. Refuses an unwritable inner
    /// message. The outer message must also fit when written.
    pub fn relay_reply(&self, inner: &Message) -> Result<Message, WriteError> {
        let mut options = Vec::new();
        if let Some(id) = self.interface_id() {
            options.push(DhcpOption::InterfaceId(id.to_vec()));
        }
        options.push(DhcpOption::RelayMessage(inner.to_bytes()?));
        Ok(Message {
            msg_type: msg::RELAY_REPL,
            transaction: 0,
            hop_count: self.hop_count,
            link_address: self.link_address,
            peer_address: self.peer_address,
            options,
        })
    }
}

/// A DHCPv6 value cannot be written without changing it.
///
/// A field or option exceeds its limit, an option changes form when read,
/// or a field unused by the message type is nonzero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The value cannot be written without changing it.
    Unwritable,
}

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DHCPv6 value cannot be written without changing it")
    }
}

impl core::error::Error for WriteError {}

impl Wire for Message {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads one UDP message. Refuses short headers, malformed options, and messages above [`MAX_MESSAGE`].
    fn parse(b: &[u8]) -> Result<Message, ParseError> {
        Message::parse_within(b, MAX_MESSAGE)
    }

    /// Appends a UDP message. Refuses unused nonzero fields, invalid options,
    /// excess nesting, and size limits. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        out.extend_from_slice(&self.write_within(MAX_MESSAGE)?);
        Ok(())
    }
}

/// One DHCPv6 TCP message with its two-byte length prefix.
///
/// [`Wire`] permits up to [`MAX_TCP_MESSAGE`] payload bytes. Use
/// [`Message`]'s [`Wire`] implementation for the smaller UDP limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame(
    /// The message carried by this frame.
    pub Message,
);

/// Why bytes do not contain exactly one DHCPv6 TCP message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// The message body was refused.
    Message(ParseError),
    /// The length prefix or message ended early.
    Truncated,
    /// Bytes followed the message.
    Trailing,
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Message(e) => e.fmt(f),
            Self::Truncated => f.write_str("DHCPv6 TCP message ended early"),
            Self::Trailing => f.write_str("bytes after the DHCPv6 TCP message"),
        }
    }
}

impl core::error::Error for FrameParseError {}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = WriteError;

    /// Reads exactly one length-prefixed TCP message.
    /// Refuses malformed messages, short prefixes or bodies, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, FrameParseError> {
        let step = match Frames.decode(bytes, true) {
            Ok(step) => step,
            Err(never) => match never {},
        };
        match step {
            Step::Item(message, used) if used == bytes.len() => message.map(Self).map_err(FrameParseError::Message),
            Step::Item(_, _) => Err(FrameParseError::Trailing),
            _ => Err(FrameParseError::Truncated),
        }
    }

    /// Appends a TCP message. Refuses unused nonzero fields, invalid options,
    /// excess nesting, and size limits. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let bytes = self.0.write_within(MAX_TCP_MESSAGE)?;
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Reads DHCPv6 TCP messages without retaining input bytes.
///
/// Use with [`Stream<Frames>`](super::codec::Stream) for at most [`MAX_BUFFERED`] unread bytes. Each
/// two-byte length delimits one item. Malformed messages are error items,
/// so the next message can still be read. Framing has no protocol errors.
/// Partial prefixes and bodies return [`Step::Need`], including at EOF;
/// the driver reports [`Fail::Truncated`](super::codec::Fail::Truncated). UDP uses [`Wire`] on [`Message`].
///
/// ```
/// use fictionet::stdlib::{dhcpv6::{Frame, Frames, Message, msg}, codec::{Stream, Wire}};
///
/// let message = Message::new(msg::SOLICIT, 7);
/// let bytes = Wire::to_bytes(&Frame(message.clone()))?;
/// let mut stream = Stream::new(Frames::new());
/// assert_eq!(stream.push(&bytes), bytes.len());
/// assert_eq!(stream.next(), Some(Ok(Ok(message))));
/// stream.end();
/// assert_eq!(stream.next(), None);
/// # Ok::<(), fictionet::stdlib::dhcpv6::WriteError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;

impl Frames {
    /// Creates a TCP message decoder with no retained state.
    pub fn new() -> Self {
        Self
    }
}

impl Decode for Frames {
    type Item = Result<Message, ParseError>;
    type Error = Infallible;
    const NAME: &'static str = "DHCPv6 over TCP";

    fn capacity(&self) -> usize {
        MAX_BUFFERED
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Infallible> {
        let Some(&[a, b]) = input.get(..2) else { return Ok(Step::Need) };
        // The two-byte length is at most MAX_TCP_MESSAGE.
        let used = 2usize.saturating_add(usize::from(u16::from_be_bytes([a, b])));
        let Some(body) = input.get(2..used) else { return Ok(Step::Need) };
        Ok(Step::Item(Message::parse_within(body, MAX_TCP_MESSAGE), used))
    }
}

fn find_status(options: &[DhcpOption]) -> Option<&StatusCode> {
    options.iter().find_map(|o| if let DhcpOption::StatusCode(s) = o { Some(s) } else { None })
}

/// Reads an option list at `depth`.
fn parse_options(b: &[u8], depth: usize) -> Result<Vec<DhcpOption>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let head = b.get(i..i + 4).ok_or(ParseError::Truncated)?;
        let code = u16::from_be_bytes([head[0], head[1]]);
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let start = i + 4;
        let body = b.get(start..start + len).ok_or(ParseError::Truncated)?;
        out.push(parse_option(code, body, depth)?);
        i = start + len;
    }
    Ok(out)
}

/// Reads one option's body. Options that hold options are read only above
/// [`MAX_DEPTH`]; at it, they are kept as [`DhcpOption::Other`].
fn parse_option(code: u16, b: &[u8], depth: usize) -> Result<DhcpOption, ParseError> {
    let bad = ParseError::BadOption(code);
    let fixed = |n: usize| if b.len() == n { Ok(()) } else { Err(bad) };
    let at_least = |n: usize| if b.len() >= n { Ok(()) } else { Err(bad) };
    let nest = depth < MAX_DEPTH;
    Ok(match code {
        opt::CLIENTID | opt::SERVERID => {
            if !(MIN_DUID..=MAX_DUID).contains(&b.len()) {
                return Err(bad);
            }
            let d = Duid(b.to_vec());
            if code == opt::CLIENTID { DhcpOption::ClientId(d) } else { DhcpOption::ServerId(d) }
        }
        opt::IA_NA if nest => {
            at_least(12)?;
            let options = parse_options(&b[12..], depth + 1)?;
            DhcpOption::IaNa(IaNa { iaid: be32(b, 0), t1: be32(b, 4), t2: be32(b, 8), options })
        }
        opt::IA_TA if nest => {
            at_least(4)?;
            DhcpOption::IaTa(IaTa { iaid: be32(b, 0), options: parse_options(&b[4..], depth + 1)? })
        }
        opt::IAADDR if nest => {
            at_least(24)?;
            let options = parse_options(&b[24..], depth + 1)?;
            DhcpOption::IaAddr(IaAddr { address: addr(b, 0), preferred: be32(b, 16), valid: be32(b, 20), options })
        }
        opt::IA_PD if nest => {
            at_least(12)?;
            let options = parse_options(&b[12..], depth + 1)?;
            DhcpOption::IaPd(IaPd { iaid: be32(b, 0), t1: be32(b, 4), t2: be32(b, 8), options })
        }
        opt::IAPREFIX if nest => {
            at_least(25)?;
            if b[8] > 128 {
                return Err(bad);
            }
            let options = parse_options(&b[25..], depth + 1)?;
            DhcpOption::IaPrefix(IaPrefix {
                preferred: be32(b, 0),
                valid: be32(b, 4),
                prefix_len: b[8],
                prefix: addr(b, 9),
                options,
            })
        }
        opt::ORO => {
            if !b.len().is_multiple_of(2) {
                return Err(bad);
            }
            DhcpOption::Oro(b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
        }
        opt::PREFERENCE => {
            fixed(1)?;
            DhcpOption::Preference(b[0])
        }
        opt::ELAPSED_TIME => {
            fixed(2)?;
            DhcpOption::ElapsedTime(u16::from_be_bytes([b[0], b[1]]))
        }
        opt::RELAY_MSG => DhcpOption::RelayMessage(b.to_vec()),
        opt::AUTH => {
            at_least(11)?;
            let mut replay = [0u8; 8];
            replay.copy_from_slice(&b[3..11]);
            DhcpOption::Auth(Auth {
                protocol: b[0],
                algorithm: b[1],
                rdm: b[2],
                replay_detection: u64::from_be_bytes(replay),
                info: b[11..].to_vec(),
            })
        }
        opt::UNICAST => {
            fixed(16)?;
            DhcpOption::Unicast(addr(b, 0))
        }
        opt::STATUS_CODE => {
            at_least(2)?;
            // RFC 8415, section 21.13: the message is not null-terminated.
            if b.len() > 2 && b[b.len() - 1] == 0 {
                return Err(bad);
            }
            let message = std::str::from_utf8(&b[2..]).map_err(|_| bad)?.to_string();
            DhcpOption::StatusCode(StatusCode { code: u16::from_be_bytes([b[0], b[1]]), message })
        }
        opt::RAPID_COMMIT => {
            fixed(0)?;
            DhcpOption::RapidCommit
        }
        opt::USER_CLASS => {
            // RFC 8415, section 21.15: one or more user classes.
            at_least(2)?;
            DhcpOption::UserClass(parse_counted(b).ok_or(bad)?)
        }
        opt::VENDOR_CLASS => {
            // RFC 8415, section 21.16: one or more vendor classes.
            at_least(6)?;
            DhcpOption::VendorClass { enterprise: be32(b, 0), classes: parse_counted(&b[4..]).ok_or(bad)? }
        }
        opt::VENDOR_OPTS => {
            at_least(4)?;
            // Section 21.17: the vendor's options are code, length, value.
            if !options_in_form(&b[4..]) {
                return Err(bad);
            }
            DhcpOption::VendorOpts { enterprise: be32(b, 0), data: b[4..].to_vec() }
        }
        opt::INTERFACE_ID => DhcpOption::InterfaceId(b.to_vec()),
        opt::RECONF_MSG => {
            fixed(1)?;
            DhcpOption::ReconfigureMessage(b[0])
        }
        opt::RECONF_ACCEPT => {
            fixed(0)?;
            DhcpOption::ReconfigureAccept
        }
        opt::DNS_SERVERS => {
            // RFC 3646, section 3: one or more servers.
            if b.is_empty() || !b.len().is_multiple_of(16) {
                return Err(bad);
            }
            DhcpOption::DnsServers(b.chunks_exact(16).map(|c| addr(c, 0)).collect())
        }
        opt::DOMAIN_LIST => match parse_names(b).ok_or(bad)? {
            Names::Hosts(names) => DhcpOption::DomainList(names),
            Names::Other => DhcpOption::Other { code, data: b.to_vec() },
        },
        opt::INFORMATION_REFRESH_TIME | opt::SOL_MAX_RT | opt::INF_MAX_RT => {
            fixed(4)?;
            let v = be32(b, 0);
            match code {
                opt::INFORMATION_REFRESH_TIME => DhcpOption::InformationRefreshTime(v),
                opt::SOL_MAX_RT => DhcpOption::SolMaxRt(v),
                _ => DhcpOption::InfMaxRt(v),
            }
        }
        _ => DhcpOption::Other { code, data: b.to_vec() },
    })
}

/// Items that each follow a 2-byte length, as User Class and Vendor Class
/// carry them. `None` if the last one runs past the end.
fn parse_counted(b: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let head = b.get(i..i + 2)?;
        let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
        out.push(b.get(i + 2..i + 2 + len)?.to_vec());
        i += 2 + len;
    }
    Some(out)
}

/// Whether `b` is a run of options, each a 2-byte code, a 2-byte length
/// and that many bytes, as vendor options are.
fn options_in_form(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        let Some(head) = b.get(i..i + 4) else { return false };
        i += 4 + usize::from(u16::from_be_bytes([head[2], head[3]]));
    }
    i == b.len()
}

/// A domain name list in its wire form, read.
enum Names {
    /// Every label holds only the bytes [`label_byte`] allows.
    Hosts(Vec<String>),
    /// A label holds some other byte.
    Other,
}

/// Whether a domain name label may hold this byte. Names here are host
/// names: letters, digits, hyphens and underscores.
fn label_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// Domain names in DNS wire form, uncompressed, one after another, or
/// `None` if the bytes are not in that form.
fn parse_names(b: &[u8]) -> Option<Names> {
    let mut names = Vec::new();
    let mut hosts = true;
    let mut i = 0;
    while i < b.len() {
        let start = i;
        let mut name = String::new();
        loop {
            let len = usize::from(*b.get(i)?);
            i += 1;
            if len == 0 {
                break;
            }
            if len > MAX_LABEL {
                return None;
            }
            let label = b.get(i..i + len)?;
            if hosts && label.iter().all(|&c| label_byte(c)) {
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(std::str::from_utf8(label).ok()?);
            } else {
                hosts = false;
            }
            i += len;
            if i - start > MAX_NAME {
                return None;
            }
        }
        if i - start > MAX_NAME {
            return None;
        }
        if hosts {
            names.push(name);
        }
    }
    Some(if hosts { Names::Hosts(names) } else { Names::Other })
}

/// A domain name in DNS wire form, or `None` if it cannot be one.
fn encode_name(name: &str) -> Option<Vec<u8>> {
    // A name of n bytes takes n + 2 bytes in wire form.
    let size = name.len().checked_add(2)?;
    if size > MAX_NAME + usize::from(name.is_empty()) {
        return None;
    }
    let mut out = Vec::with_capacity(size);
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL || !label.bytes().all(label_byte) {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    if out.len() > MAX_NAME { None } else { Some(out) }
}

/// An option list at `depth`, in at most `budget` bytes. Options that are
/// malformed or do not fit are refused.
fn encode_options(options: &[DhcpOption], depth: usize, budget: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for o in options {
        let bytes = encode_option(o, depth, budget.checked_sub(out.len())?)?;
        out.extend_from_slice(&bytes);
    }
    Some(out)
}

/// One option, header and body, in at most `budget` bytes, or `None` if it
/// does not fit or would not read back.
fn encode_option(o: &DhcpOption, depth: usize, budget: usize) -> Option<Vec<u8>> {
    let max = budget.checked_sub(4)?.min(usize::from(u16::MAX));
    let body = encode_body(o, depth, max)?;
    if body.len() > max {
        return None;
    }
    let code = o.code();
    // A last check, so nothing written fails to read.
    if parse_option(code, &body, depth).ok().as_ref() != Some(o) {
        return None;
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

/// An option's body, or `None` if it is invalid or cannot fit in `max` bytes.
fn encode_body(o: &DhcpOption, depth: usize, max: usize) -> Option<Vec<u8>> {
    let nested = |options: &[DhcpOption], fixed: usize| {
        if depth < MAX_DEPTH { encode_options(options, depth + 1, max.checked_sub(fixed)?) } else { None }
    };
    let mut out = Vec::new();
    match o {
        DhcpOption::ClientId(d) | DhcpOption::ServerId(d) => {
            if !d.is_valid() {
                return None;
            }
            out.extend_from_slice(&d.0)
        }
        DhcpOption::IaNa(ia) => {
            out.extend_from_slice(&ia.iaid.to_be_bytes());
            out.extend_from_slice(&ia.t1.to_be_bytes());
            out.extend_from_slice(&ia.t2.to_be_bytes());
            out.extend_from_slice(&nested(&ia.options, 12)?);
        }
        DhcpOption::IaTa(ia) => {
            out.extend_from_slice(&ia.iaid.to_be_bytes());
            out.extend_from_slice(&nested(&ia.options, 4)?);
        }
        DhcpOption::IaAddr(a) => {
            out.extend_from_slice(&a.address.octets());
            out.extend_from_slice(&a.preferred.to_be_bytes());
            out.extend_from_slice(&a.valid.to_be_bytes());
            out.extend_from_slice(&nested(&a.options, 24)?);
        }
        DhcpOption::IaPd(ia) => {
            out.extend_from_slice(&ia.iaid.to_be_bytes());
            out.extend_from_slice(&ia.t1.to_be_bytes());
            out.extend_from_slice(&ia.t2.to_be_bytes());
            out.extend_from_slice(&nested(&ia.options, 12)?);
        }
        DhcpOption::IaPrefix(p) => {
            out.extend_from_slice(&p.preferred.to_be_bytes());
            out.extend_from_slice(&p.valid.to_be_bytes());
            out.push(p.prefix_len);
            out.extend_from_slice(&p.prefix.octets());
            out.extend_from_slice(&nested(&p.options, 25)?);
        }
        DhcpOption::Oro(codes) => {
            if codes.len() > max / 2 {
                return None;
            }
            for c in codes {
                out.extend_from_slice(&c.to_be_bytes());
            }
        }
        DhcpOption::Preference(p) => out.push(*p),
        DhcpOption::ElapsedTime(t) => out.extend_from_slice(&t.to_be_bytes()),
        DhcpOption::RelayMessage(b) | DhcpOption::InterfaceId(b) => push_fitting(&mut out, b, max)?,
        DhcpOption::Auth(a) => {
            out.extend_from_slice(&[a.protocol, a.algorithm, a.rdm]);
            out.extend_from_slice(&a.replay_detection.to_be_bytes());
            push_fitting(&mut out, &a.info, max)?;
        }
        DhcpOption::Unicast(a) => out.extend_from_slice(&a.octets()),
        DhcpOption::StatusCode(s) => {
            out.extend_from_slice(&s.code.to_be_bytes());
            push_fitting(&mut out, s.message.as_bytes(), max)?;
        }
        DhcpOption::RapidCommit | DhcpOption::ReconfigureAccept => {}
        DhcpOption::UserClass(items) => push_counted(&mut out, items, max)?,
        DhcpOption::VendorClass { enterprise, classes } => {
            out.extend_from_slice(&enterprise.to_be_bytes());
            push_counted(&mut out, classes, max)?;
        }
        DhcpOption::VendorOpts { enterprise, data } => {
            out.extend_from_slice(&enterprise.to_be_bytes());
            push_fitting(&mut out, data, max)?;
        }
        DhcpOption::ReconfigureMessage(m) => out.push(*m),
        DhcpOption::DnsServers(addrs) => {
            if addrs.len() > max / 16 {
                return None;
            }
            for a in addrs {
                out.extend_from_slice(&a.octets());
            }
        }
        DhcpOption::DomainList(names) => {
            for name in names {
                push_fitting(&mut out, &encode_name(name)?, max)?;
            }
        }
        DhcpOption::InformationRefreshTime(v) | DhcpOption::SolMaxRt(v) | DhcpOption::InfMaxRt(v) => {
            out.extend_from_slice(&v.to_be_bytes())
        }
        DhcpOption::Other { data, .. } => push_fitting(&mut out, data, max)?,
    }
    Some(out)
}

/// Appends `data` if the body stays within `max` bytes, and otherwise
/// returns `None`.
fn push_fitting(out: &mut Vec<u8>, data: &[u8], max: usize) -> Option<()> {
    if out.len().checked_add(data.len())? > max {
        return None;
    }
    out.extend_from_slice(data);
    Some(())
}

/// Appends counted items, refusing invalid lengths or a body over `max`.
fn push_counted(out: &mut Vec<u8>, items: &[Vec<u8>], max: usize) -> Option<()> {
    for item in items {
        let len = u16::try_from(item.len()).ok()?;
        push_fitting(out, &len.to_be_bytes(), max)?;
        push_fitting(out, item, max)?;
    }
    Some(())
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn addr(b: &[u8], i: usize) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&b[i..i + 16]);
    Ipv6Addr::from(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{
        Stream, contract, pump,
        test_support::{Lcg, decode_all, mutate},
    };

    fn a(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// A Solicit laid out by hand from RFC 8415, sections 8 and 21: a
    /// DUID-LL Client Identifier, Elapsed Time 0, one IA_NA with IAID 1
    /// and no times, and an Option Request for DNS servers and the domain
    /// list.
    const SOLICIT: [u8; 48] = [
        1, 0x12, 0x34, 0x56, // Solicit, transaction 0x123456
        0, 1, 0, 10, 0, 3, 0, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Client ID: DUID-LL, Ethernet
        0, 8, 0, 2, 0, 0, // Elapsed Time 0
        0, 3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, // IA_NA 1, T1 0, T2 0
        0, 6, 0, 4, 0, 23, 0, 24, // ORO: DNS servers, domain list
    ];

    fn client_duid() -> Duid {
        Duid::ll(hardware::ETHERNET, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    }

    #[test]
    fn duid_wire_lengths() {
        for len in [0, MIN_DUID - 1, MIN_DUID, MAX_DUID, MAX_DUID + 1] {
            let bytes = vec![0; len];
            let valid = (MIN_DUID..=MAX_DUID).contains(&len);
            let expected = if valid { Ok(Duid(bytes.clone())) } else { Err(ParseError::BadOption(opt::CLIENTID)) };
            assert_eq!(Duid::parse(&bytes), expected);
            assert_eq!(Duid(bytes.clone()).to_bytes().is_ok(), valid);
            contract::check_wire::<Duid>(&bytes);
            contract::check_wire_value(&Duid(bytes));
        }
    }

    #[test]
    fn solicit_example() {
        let m = Message::parse(&SOLICIT).unwrap();
        assert_eq!(m.msg_type, msg::SOLICIT);
        assert_eq!(m.transaction, 0x123456);
        assert!(!m.is_relay());
        assert_eq!(m.client_id(), Some(&client_duid()));
        assert_eq!(m.client_id().unwrap().kind(), Some(duid_type::LL));
        assert_eq!(
            m.options,
            [
                DhcpOption::ClientId(client_duid()),
                DhcpOption::ElapsedTime(0),
                DhcpOption::IaNa(IaNa { iaid: 1, t1: 0, t2: 0, options: vec![] }),
                DhcpOption::Oro(vec![opt::DNS_SERVERS, opt::DOMAIN_LIST]),
            ]
        );
        assert_eq!(m.to_bytes().unwrap(), SOLICIT);
        // Built from fields, it makes the same bytes.
        let mut built = Message::new(msg::SOLICIT, 0x123456);
        built.options = m.options.clone();
        assert_eq!(built.to_bytes().unwrap(), SOLICIT);
    }

    #[test]
    fn reply_with_an_address_and_a_prefix() {
        let request = Message::parse(&SOLICIT).unwrap();
        let server = Duid::llt(hardware::ETHERNET, 0x2a2b_2c2d, &[2, 0, 0, 0, 0, 9]);
        let mut reply = request.answer(msg::REPLY, &server);
        let address = IaAddr { address: a("2001:db8::1"), preferred: 3600, valid: 7200, options: vec![] };
        reply.options.push(DhcpOption::IaNa(IaNa {
            iaid: 1,
            t1: 1800,
            t2: 2880,
            options: vec![
                DhcpOption::IaAddr(address),
                DhcpOption::StatusCode(StatusCode { code: status::SUCCESS, message: "ok".into() }),
            ],
        }));
        let prefix =
            IaPrefix { preferred: 3600, valid: INFINITY, prefix_len: 48, prefix: a("2001:db8:1::"), options: vec![] };
        reply.options.push(DhcpOption::IaPd(IaPd {
            iaid: 2,
            t1: 0,
            t2: 0,
            options: vec![DhcpOption::IaPrefix(prefix)],
        }));
        reply.options.push(DhcpOption::RapidCommit);
        let bytes = reply.to_bytes().unwrap();
        // The header, then Server ID (4 + 14), Client ID (4 + 10), IA_NA
        // (4 + 12 + IAADDR 28 + status 8), IA_PD (4 + 12 + IAPREFIX 29) and
        // Rapid Commit (4).
        assert_eq!(bytes.len(), 4 + 18 + 14 + 52 + 45 + 4);
        assert_eq!(&bytes[..4], [7, 0x12, 0x34, 0x56]);
        assert_eq!(&bytes[4..8], [0, 2, 0, 14]);
        // The IAPREFIX option, laid out by hand.
        let iaprefix = [
            0, 26, 0, 25, 0, 0, 0x0e, 0x10, 0xff, 0xff, 0xff, 0xff, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert!(bytes.windows(iaprefix.len()).any(|w| w == iaprefix));
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back, reply);
        assert_eq!(back.to_bytes().unwrap(), bytes);
        let ia = back.ia_na().next().unwrap();
        assert_eq!(ia.addresses().next().unwrap().address, a("2001:db8::1"));
        assert_eq!(ia.status().unwrap().message, "ok");
        let pd = back.ia_pd().next().unwrap();
        let p = pd.prefixes().next().unwrap();
        assert_eq!((p.prefix, p.prefix_len, p.valid), (a("2001:db8:1::"), 48, INFINITY));
        assert_eq!(back.server_id(), Some(&server));
        assert_eq!(back.option(opt::RAPID_COMMIT), Some(&DhcpOption::RapidCommit));
        assert_eq!(back.status(), None);
        assert_eq!(back.ia_ta().count(), 0);
    }

    #[test]
    fn relay_example() {
        let solicit = Message::parse(&SOLICIT).unwrap();
        let mut forw =
            Message::relay_forward(&solicit, 0, a("2001:db8:0:1::1"), a("fe80::211:22ff:fe33:4455")).unwrap();
        forw.options.insert(0, DhcpOption::InterfaceId(b"eth0".to_vec()));
        let bytes = forw.to_bytes().unwrap();
        // RFC 8415, section 9: type, hop count, link address, peer address.
        assert_eq!(bytes[0], msg::RELAY_FORW);
        assert_eq!(bytes[1], 0);
        assert_eq!(&bytes[2..18], &a("2001:db8:0:1::1").octets());
        assert_eq!(&bytes[18..34], &a("fe80::211:22ff:fe33:4455").octets());
        assert_eq!(&bytes[34..42], [0, 18, 0, 4, b'e', b't', b'h', b'0']);
        assert_eq!(&bytes[42..46], [0, 9, 0, SOLICIT.len() as u8]);
        assert_eq!(&bytes[46..], SOLICIT);
        assert_eq!(bytes.len(), RELAY_HEADER_LEN + 8 + 4 + SOLICIT.len());

        let read = Message::parse(&bytes).unwrap();
        assert!(read.is_relay());
        assert_eq!(read.transaction, 0);
        assert_eq!(read.relayed(), Some(Ok(solicit.clone())));

        // A second relay agent wraps it again.
        let outer = Message::relay_forward(&read, 1, Ipv6Addr::UNSPECIFIED, a("2001:db8:0:1::1")).unwrap();
        let outer = Message::parse(&outer.to_bytes().unwrap()).unwrap();
        assert_eq!(outer.hop_count, 1);
        assert_eq!(outer.relayed().unwrap().unwrap().relayed().unwrap().unwrap(), solicit);

        // The server answers through the first relay agent.
        let advertise = solicit.answer(msg::ADVERTISE, &Duid::en(9, b"srv"));
        let repl = read.relay_reply(&advertise).unwrap();
        assert_eq!(repl.msg_type, msg::RELAY_REPL);
        assert_eq!((repl.hop_count, repl.link_address, repl.peer_address), (0, read.link_address, read.peer_address));
        assert_eq!(repl.option(opt::INTERFACE_ID), Some(&DhcpOption::InterfaceId(b"eth0".to_vec())));
        let back = Message::parse(&repl.to_bytes().unwrap()).unwrap();
        assert_eq!(back.relayed(), Some(Ok(advertise)));
        assert_eq!(solicit.relayed(), None);
    }

    #[test]
    fn every_known_option_round_trips() {
        let options = vec![
            DhcpOption::ClientId(Duid::uuid([7; 16])),
            DhcpOption::ServerId(Duid::en(311, &[1, 2, 3])),
            DhcpOption::IaTa(IaTa {
                iaid: 5,
                options: vec![DhcpOption::IaAddr(IaAddr {
                    address: a("fd00::5"),
                    preferred: 1,
                    valid: 2,
                    options: vec![DhcpOption::StatusCode(StatusCode { code: 0, message: String::new() })],
                })],
            }),
            DhcpOption::Preference(255),
            DhcpOption::Auth(Auth { protocol: 3, algorithm: 1, rdm: 0, replay_detection: 42, info: vec![1; 17] }),
            DhcpOption::Unicast(a("2001:db8::547")),
            DhcpOption::StatusCode(StatusCode { code: status::NO_ADDRS_AVAIL, message: "épuisé".into() }),
            DhcpOption::UserClass(vec![b"lab".to_vec(), vec![]]),
            DhcpOption::VendorClass { enterprise: 4491, classes: vec![b"docsis3.0".to_vec()] },
            DhcpOption::VendorOpts { enterprise: 4491, data: vec![0, 1, 0, 0] },
            DhcpOption::ReconfigureMessage(msg::RENEW),
            DhcpOption::ReconfigureAccept,
            DhcpOption::DnsServers(vec![a("2001:4860:4860::8888"), a("2001:4860:4860::8844")]),
            DhcpOption::DomainList(vec!["example.com".into(), "lab.example.org".into(), String::new()]),
            DhcpOption::InformationRefreshTime(86400),
            DhcpOption::SolMaxRt(3600),
            DhcpOption::InfMaxRt(3600),
            DhcpOption::Other { code: 39, data: vec![0, 4, b'h', b'o', b's', b't'] },
        ];
        let mut m = Message::new(msg::REPLY, 0xffffff);
        m.options = options;
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        // The domain list in wire form (RFC 1035, section 3.1).
        let mut list = vec![0, 24, 0, 31, 7];
        list.extend_from_slice(b"example");
        list.push(3);
        list.extend_from_slice(b"com");
        list.extend_from_slice(&[0, 3, b'l', b'a', b'b', 7]);
        list.extend_from_slice(b"example");
        list.push(3);
        list.extend_from_slice(b"org");
        list.extend_from_slice(&[0, 0]);
        assert!(bytes.windows(list.len()).any(|w| w == list));
        // Every DUID constructor makes a DUID a message may carry.
        for d in [Duid::llt(1, 0, &[1; 6]), Duid::en(1, b"x"), Duid::ll(1, &[1; 6]), Duid::uuid([0; 16])] {
            assert!(d.is_valid());
        }
        assert_eq!(Duid(vec![0]).kind(), None);
        assert!(!Duid(vec![0, 1]).is_valid());
    }

    #[test]
    fn short_and_long_messages() {
        assert_eq!(Message::parse(&[]), Err(ParseError::Short));
        assert_eq!(Message::parse(&[1, 0, 0]), Err(ParseError::Short));
        assert_eq!(Message::parse(&[12; 33]), Err(ParseError::Short));
        assert_eq!(Message::parse(&[13; 33]), Err(ParseError::Short));
        assert!(Message::parse(&[1, 0, 0, 0]).is_ok());
        assert!(Message::parse(&[12; 34]).is_ok());
        // Message types past 13 are read as client and server messages.
        assert!(Message::parse(&[200, 0, 0, 0]).is_ok());
        let mut long = vec![1, 0, 0, 0];
        long.resize(MAX_MESSAGE + 1, 0);
        assert_eq!(Message::parse(&long), Err(ParseError::TooLong(MAX_MESSAGE + 1)));
        // An Other option fills the rest exactly.
        long.truncate(MAX_MESSAGE);
        long[4..8].copy_from_slice(&[0, 99, 0xff, 0xef]);
        assert_eq!(usize::from(u16::from_be_bytes([0xff, 0xef])), MAX_MESSAGE - 8);
        let m = Message::parse(&long).unwrap();
        assert_eq!(m.to_bytes().unwrap(), long);
    }

    #[test]
    fn truncated_options() {
        // A header cut short, and a body that runs past the end.
        assert_eq!(Message::parse(&[1, 0, 0, 0, 0]), Err(ParseError::Truncated));
        assert_eq!(Message::parse(&[1, 0, 0, 0, 0, 8, 0]), Err(ParseError::Truncated));
        assert_eq!(Message::parse(&[1, 0, 0, 0, 0, 8, 0, 2, 0]), Err(ParseError::Truncated));
        // Inside an IA_NA, too.
        let ia = [1, 0, 0, 0, 0, 3, 0, 14, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        assert_eq!(Message::parse(&ia), Err(ParseError::Truncated));
    }

    /// A client message with one option, `code`, holding `body`.
    fn with_option(code: u16, body: &[u8]) -> Vec<u8> {
        let mut b = vec![1, 0, 0, 0];
        b.extend_from_slice(&code.to_be_bytes());
        b.extend_from_slice(&(body.len() as u16).to_be_bytes());
        b.extend_from_slice(body);
        b
    }

    #[test]
    fn malformed_options() {
        let bad = |code: u16, body: &[u8]| {
            assert_eq!(Message::parse(&with_option(code, body)), Err(ParseError::BadOption(code)), "{code} {body:?}");
        };
        bad(opt::CLIENTID, &[0, 3]);
        bad(opt::SERVERID, &[0; 131]);
        bad(opt::IA_NA, &[0; 11]);
        bad(opt::IA_TA, &[0; 3]);
        bad(opt::IAADDR, &[0; 23]);
        bad(opt::IA_PD, &[0; 11]);
        bad(opt::IAPREFIX, &[0; 24]);
        let mut prefix = [0u8; 25];
        prefix[8] = 129;
        bad(opt::IAPREFIX, &prefix);
        bad(opt::ORO, &[0, 1, 0]);
        bad(opt::PREFERENCE, &[]);
        bad(opt::PREFERENCE, &[1, 2]);
        bad(opt::ELAPSED_TIME, &[0]);
        bad(opt::AUTH, &[0; 10]);
        bad(opt::UNICAST, &[0; 15]);
        bad(opt::STATUS_CODE, &[0]);
        bad(opt::STATUS_CODE, &[0, 0, 0xff]);
        bad(opt::RAPID_COMMIT, &[0]);
        bad(opt::USER_CLASS, &[0, 3, 1, 2]);
        bad(opt::USER_CLASS, &[0]);
        bad(opt::VENDOR_CLASS, &[0, 0, 0]);
        bad(opt::VENDOR_CLASS, &[0, 0, 0, 1]);
        bad(opt::VENDOR_CLASS, &[0, 0, 0, 1, 0, 1]);
        bad(opt::VENDOR_OPTS, &[0, 0, 0]);
        bad(opt::RECONF_MSG, &[]);
        bad(opt::RECONF_ACCEPT, &[1]);
        bad(opt::DNS_SERVERS, &[0; 17]);
        bad(opt::INFORMATION_REFRESH_TIME, &[0; 3]);
        bad(opt::SOL_MAX_RT, &[0; 5]);
        bad(opt::INF_MAX_RT, &[]);
        // Domain names: no end, a label too long, a compression pointer,
        // and a name too long.
        bad(opt::DOMAIN_LIST, &[3, b'c', b'o', b'm']);
        let mut long_label = vec![64];
        long_label.extend_from_slice(&[b'a'; 64]);
        long_label.push(0);
        bad(opt::DOMAIN_LIST, &long_label);
        bad(opt::DOMAIN_LIST, &[0xc0, 0x0c]);
        let mut long_name = Vec::new();
        for _ in 0..5 {
            long_name.push(63);
            long_name.extend_from_slice(&[b'a'; 63]);
        }
        long_name.push(0);
        bad(opt::DOMAIN_LIST, &long_name);
        // A bad option inside an IA_NA names the inner option.
        let mut ia = vec![0u8; 12];
        ia.extend_from_slice(&[0, 13, 0, 1, 0]);
        assert_eq!(Message::parse(&with_option(opt::IA_NA, &ia)), Err(ParseError::BadOption(opt::STATUS_CODE)));
        // Bodies just long enough read.
        for (code, n) in [(opt::IA_NA, 12), (opt::IA_TA, 4), (opt::IAADDR, 24), (opt::IA_PD, 12), (opt::IAPREFIX, 25)] {
            assert!(Message::parse(&with_option(code, &vec![0; n])).is_ok(), "{code}");
        }
        assert!(Message::parse(&with_option(opt::CLIENTID, &[0, 3, 0])).is_ok());
        assert!(Message::parse(&with_option(opt::CLIENTID, &[0; 130])).is_ok());
        // The longest name, 255 bytes, reads.
        let mut max_name = Vec::new();
        for _ in 0..3 {
            max_name.push(63);
            max_name.extend_from_slice(&[b'a'; 63]);
        }
        max_name.push(61);
        max_name.extend_from_slice(&[b'b'; 61]);
        max_name.push(0);
        assert_eq!(max_name.len(), MAX_NAME);
        let m = Message::parse(&with_option(opt::DOMAIN_LIST, &max_name)).unwrap();
        assert_eq!(m.to_bytes().unwrap(), with_option(opt::DOMAIN_LIST, &max_name));
    }

    #[test]
    fn spec_review_cases() {
        // RFC 8415, section 21.15: a User Class option holds one or more
        // instances, so readers and writers refuse a list with no items.
        assert_eq!(Message::parse(&with_option(opt::USER_CLASS, &[])), Err(ParseError::BadOption(opt::USER_CLASS)));
        assert!(Message::parse(&with_option(opt::USER_CLASS, &[0, 0])).is_ok());
        let mut m = Message::new(msg::SOLICIT, 1);
        m.options.push(DhcpOption::UserClass(vec![]));
        m.options.push(DhcpOption::UserClass(vec![vec![0; 70000]]));
        for option in m.options {
            let value = Message { options: vec![option], ..Message::new(msg::SOLICIT, 1) };
            assert!(value.to_bytes().is_err());
            contract::check_wire_value(&value);
        }
        // Section 21.13: a status message is not null-terminated.
        let nul = with_option(opt::STATUS_CODE, &[0, 0, b'o', b'k', 0]);
        assert_eq!(Message::parse(&nul), Err(ParseError::BadOption(opt::STATUS_CODE)));
        assert!(Message::parse(&with_option(opt::STATUS_CODE, &[0, 0, 0, b'k'])).is_ok());
        let mut m = Message::new(msg::REPLY, 1);
        m.options.push(DhcpOption::StatusCode(StatusCode { code: 0, message: "ok\0".into() }));
        for option in m.options {
            let value = Message { options: vec![option], ..Message::new(msg::REPLY, 1) };
            assert!(value.to_bytes().is_err());
            contract::check_wire_value(&value);
        }
    }

    #[test]
    fn relay_reply_with_a_long_interface_id() {
        // A Relay-forward whose Interface-Id leaves no room for the answer:
        // writing the Relay-reply must fail without dropping its message.
        let mut forw = Message::relay_forward(&Message::new(msg::SOLICIT, 1), 0, a("::1"), a("::2")).unwrap();
        forw.options = vec![DhcpOption::InterfaceId(vec![7; MAX_MESSAGE - RELAY_HEADER_LEN - 4])];
        let bytes = forw.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        let read = Message::parse(&bytes).unwrap();
        let answer = Message::parse(&SOLICIT).unwrap().answer(msg::REPLY, &Duid::en(1, b"s"));
        let repl = read.relay_reply(&answer).unwrap();
        assert!(repl.to_bytes().is_err());
        contract::check_wire_value(&repl);
    }

    #[test]
    fn accessors_and_defaults() {
        // A server answers the options a client asks for in its ORO.
        let solicit = Message::parse(&SOLICIT).unwrap();
        assert_eq!(solicit.requested_options(), [opt::DNS_SERVERS, opt::DOMAIN_LIST]);
        assert_eq!(Message::new(msg::SOLICIT, 1).requested_options(), [] as [u16; 0]);
        // A relay's Interface-Id, as bytes.
        let mut forw = Message::relay_forward(&solicit, 0, a("::1"), a("::2")).unwrap();
        assert_eq!(forw.interface_id(), None);
        forw.options.push(DhcpOption::InterfaceId(b"eth1".to_vec()));
        assert_eq!(forw.interface_id(), Some(&b"eth1"[..]));
        // The IA, status and auth types build from defaults.
        let ia = IaNa { iaid: 3, ..Default::default() };
        assert_eq!((ia.t1, ia.t2, ia.options.len()), (0, 0, 0));
        assert_eq!(IaTa::default().iaid, 0);
        assert_eq!(IaPd { iaid: 4, ..Default::default() }.iaid, 4);
        assert_eq!(StatusCode::default().code, status::SUCCESS);
        assert_eq!(Auth::default().info, Vec::<u8>::new());
    }

    #[test]
    fn stream_takes_many_small_messages_in_linear_time() {
        let n = 1_000_000;
        let mut stream = Stream::new(Frames::new());
        let mut count = 0;
        pump(&mut stream, &vec![0; 2 * n], |m| {
            assert_eq!(m, Err(ParseError::Short));
            count += 1;
        })
        .unwrap();
        assert_eq!(count, n);
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.push(&[0, 4, 1, 0, 0, 7]), 6);
        assert_eq!(stream.next().unwrap().unwrap().unwrap().transaction, 7);
    }

    #[test]
    fn errors_display() {
        for e in [ParseError::Short, ParseError::TooLong(70000), ParseError::Truncated, ParseError::BadOption(3)] {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(ParseError::BadOption(3).to_string(), "option 3 is malformed");
    }

    #[test]
    fn every_truncated_prefix() {
        let relay =
            Message::relay_forward(&Message::parse(&SOLICIT).unwrap(), 0, a("2001:db8::1"), a("fe80::1")).unwrap();
        for full in [SOLICIT.to_vec(), relay.to_bytes().unwrap()] {
            let header = if full[0] == msg::RELAY_FORW { RELAY_HEADER_LEN } else { CLIENT_HEADER_LEN };
            // Where each top-level option ends.
            let mut ends = vec![header];
            let mut i = header;
            while i < full.len() {
                i += 4 + usize::from(u16::from_be_bytes([full[i + 2], full[i + 3]]));
                ends.push(i);
            }
            for n in 0..full.len() {
                let r = Message::parse(&full[..n]);
                if n < header {
                    assert_eq!(r, Err(ParseError::Short), "{n}");
                } else if ends.contains(&n) {
                    // Cut between options: a shorter message.
                    assert_eq!(r.unwrap().to_bytes().unwrap(), full[..n], "{n}");
                } else {
                    assert_eq!(r, Err(ParseError::Truncated), "{n}");
                }
            }
            // Over TCP, every prefix waits for more.
            let framed = Frame(Message::parse(&full).unwrap().clone()).to_bytes().unwrap();
            contract::check_decode_with_alloc_limit(Frames::new, &framed, 2 * MAX_BUFFERED);
            for n in 0..framed.len() {
                assert_eq!(Frames::new().decode(&framed[..n], false), Ok(Step::Need));
            }
        }
    }

    #[test]
    fn stream_splits_a_stream() {
        let first = Message::parse(&SOLICIT).unwrap();
        let second = first.answer(msg::REPLY, &Duid::en(1, b"s"));
        let mut bytes = Frame(first.clone()).to_bytes().unwrap();
        bytes.extend_from_slice(&[0, 3, 1, 0, 0]);
        bytes.extend_from_slice(&Frame(second.clone()).to_bytes().unwrap());
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_BUFFERED);
        assert_eq!(decode_all(Frames::new, &bytes), (vec![Ok(first), Err(ParseError::Short), Ok(second)], None));
        let (messages, error) = decode_all(Frames::new, &[0, 0, 0, 4, 2, 0, 0, 1]);
        assert_eq!(messages, [Err(ParseError::Short), Ok(Message::new(2, 1))]);
        assert_eq!(error, None);
    }

    #[test]
    fn depth_limit() {
        // IA_NAs nested deeper than MAX_DEPTH.
        let mut body: Vec<u8> = Vec::new();
        for _ in 0..MAX_DEPTH + 4 {
            let mut outer = vec![0u8; 12];
            outer.extend_from_slice(&opt::IA_NA.to_be_bytes());
            outer.extend_from_slice(&(body.len() as u16).to_be_bytes());
            outer.extend_from_slice(&body);
            body = outer;
        }
        let bytes = with_option(opt::IA_NA, &body);
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.to_bytes().unwrap(), bytes);
        let mut depth = 0;
        let mut options = &m.options;
        while let Some(DhcpOption::IaNa(ia)) = options.first() {
            depth += 1;
            options = &ia.options;
        }
        assert_eq!(depth, MAX_DEPTH);
        assert!(matches!(options.first(), Some(DhcpOption::Other { code: opt::IA_NA, .. })));

        // A constructed value past the depth limit is refused.
        let mut o = DhcpOption::RapidCommit;
        for _ in 0..MAX_DEPTH * 3 {
            o = DhcpOption::IaNa(IaNa { iaid: 0, t1: 0, t2: 0, options: vec![o] });
        }
        let mut m = Message::new(msg::REPLY, 1);
        m.options.push(o);
        assert!(m.to_bytes().is_err());
        contract::check_wire_value(&m);
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        let mut m = Message::new(msg::REPLY, 0x0100_0001);
        // The transaction ID keeps its low 24 bits.
        assert_eq!(m.transaction, 1);
        m.transaction = 0xff12_3456;
        m.options = vec![
            DhcpOption::ClientId(Duid(vec![1])),
            DhcpOption::ServerId(Duid(vec![0; 200])),
            DhcpOption::IaPrefix(IaPrefix {
                preferred: 0,
                valid: 0,
                prefix_len: 200,
                prefix: Ipv6Addr::UNSPECIFIED,
                options: vec![],
            }),
            DhcpOption::Other { code: opt::PREFERENCE, data: vec![1, 2, 3] },
            DhcpOption::Other { code: opt::ELAPSED_TIME, data: vec![0, 5] },
            DhcpOption::DomainList(vec!["ok.example".into(), "bad..name".into(), "sp ace".into(), "a.".into()]),
            DhcpOption::UserClass(vec![vec![0; 70000], b"kept".to_vec()]),
            DhcpOption::Other { code: 1000, data: vec![0; 70000] },
            DhcpOption::RelayMessage(vec![0; MAX_MESSAGE]),
        ];
        assert!(m.to_bytes().is_err());
        for option in std::mem::take(&mut m.options) {
            let value = Message { options: vec![option], ..Message::new(msg::REPLY, 1) };
            assert!(value.to_bytes().is_err(), "{:?}", value.options);
            contract::check_wire_value(&value);
        }
        for option in [
            DhcpOption::DnsServers(vec![Ipv6Addr::LOCALHOST; 5000]),
            DhcpOption::Oro(vec![23; 40000]),
            DhcpOption::StatusCode(StatusCode { code: 0, message: "x".repeat(70000) }),
        ] {
            let value = Message { options: vec![option], ..Message::new(msg::REPLY, 1) };
            assert!(value.to_bytes().is_err());
            contract::check_wire_value(&value);
        }

        // A relay whose inner message does not fit is refused.
        let mut huge = Message::new(msg::SOLICIT, 0);
        huge.options.push(DhcpOption::Other { code: 1000, data: vec![0; MAX_MESSAGE - 8] });
        assert_eq!(huge.to_bytes().unwrap().len(), MAX_MESSAGE);
        let forw = Message::relay_forward(&huge, 0, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED).unwrap();
        assert!(forw.to_bytes().is_err());
        assert!(Frame(forw).to_bytes().is_err());
    }

    /// A random option, sometimes malformed, nested up to `depth` more.
    fn random_option(r: &mut Lcg, depth: usize) -> DhcpOption {
        let nested = |r: &mut Lcg| {
            if depth == 0 { Vec::new() } else { (0..r.index(3)).map(|_| random_option(r, depth - 1)).collect() }
        };
        let addr = |r: &mut Lcg| Ipv6Addr::from(u128::from(r.next() as u32) << 96 | u128::from(r.next() as u32));
        match r.index(30) {
            0 => DhcpOption::ClientId(Duid(r.bytes(140))),
            1 => DhcpOption::ServerId(Duid::en(r.next() as u32, &[1, 2])),
            2 => DhcpOption::IaNa(IaNa {
                iaid: r.next() as u32,
                t1: r.next() as u32,
                t2: r.next() as u32,
                options: nested(r),
            }),
            3 => DhcpOption::IaTa(IaTa { iaid: r.next() as u32, options: nested(r) }),
            4 => DhcpOption::IaAddr(IaAddr { address: addr(r), preferred: 1, valid: 2, options: nested(r) }),
            5 => DhcpOption::IaPd(IaPd { iaid: r.next() as u32, t1: 0, t2: 0, options: nested(r) }),
            6 => DhcpOption::IaPrefix(IaPrefix {
                preferred: 1,
                valid: 2,
                prefix_len: r.index(140) as u8,
                prefix: addr(r),
                options: nested(r),
            }),
            7 => DhcpOption::Oro((0..r.index(10)).map(|_| r.next() as u16).collect()),
            8 => DhcpOption::Preference(r.next() as u8),
            9 => DhcpOption::ElapsedTime(r.next() as u16),
            10 => DhcpOption::RelayMessage(r.bytes(40)),
            11 => DhcpOption::Auth(Auth {
                protocol: 3,
                algorithm: 1,
                rdm: 0,
                replay_detection: u64::from(r.next() as u32),
                info: r.bytes(20),
            }),
            12 => DhcpOption::Unicast(addr(r)),
            13 => {
                DhcpOption::StatusCode(StatusCode { code: r.next() as u16, message: "nö".repeat(r.index(4)) })
            }
            14 => DhcpOption::RapidCommit,
            15 => DhcpOption::UserClass((0..r.index(4)).map(|_| r.bytes(6)).collect()),
            16 => DhcpOption::VendorClass { enterprise: r.next() as u32, classes: vec![r.bytes(5)] },
            17 => DhcpOption::VendorOpts { enterprise: r.next() as u32, data: r.bytes(9) },
            18 => DhcpOption::InterfaceId(r.bytes(9)),
            19 => DhcpOption::ReconfigureMessage(r.next() as u8),
            20 => DhcpOption::ReconfigureAccept,
            21 => DhcpOption::DnsServers((0..r.index(4)).map(|_| addr(r)).collect()),
            22 => {
                let names = ["a.b", "", "x..y", "-", "ä.com", "host_1.lab"];
                DhcpOption::DomainList((0..r.index(4)).map(|_| names[r.index(names.len())].to_string()).collect())
            }
            23 => DhcpOption::InformationRefreshTime(r.next() as u32),
            24 => DhcpOption::SolMaxRt(r.next() as u32),
            25 => DhcpOption::InfMaxRt(r.next() as u32),
            // Other options, some with known codes and any body.
            _ => DhcpOption::Other { code: r.index(30) as u16, data: r.bytes(30) },
        }
    }

    fn random_message(r: &mut Lcg) -> Message {
        let mut m = Message::new(r.index(16) as u8, r.next() as u32);
        m.transaction = r.next() as u32;
        m.hop_count = r.next() as u8;
        m.link_address = Ipv6Addr::from(u128::from(r.next() as u32));
        m.options = (0..r.index(6)).map(|_| random_option(r, MAX_DEPTH + 2)).collect();
        m
    }

    #[test]
    fn fuzz_built_messages_read_back() {
        let mut r = Lcg::new(0x5eed);
        for _ in 0..3000 {
            let mut m = random_message(&mut r);
            contract::check_wire_value(&m);
            if r.coin() {
                if m.is_relay() {
                    m.transaction = 0;
                } else {
                    m.transaction &= 0xffffff;
                    m.hop_count = 0;
                    m.link_address = Ipv6Addr::UNSPECIFIED;
                }
            }
            contract::check_wire_value(&m);
            if let Ok(bytes) = m.to_bytes() {
                let back = Message::parse(&bytes).unwrap();
                assert_eq!(back, m);
                if m.is_relay() {
                    contract::check_wire_value(&back.relay_reply(&m).unwrap());
                } else {
                    contract::check_wire_value(&back.answer(msg::REPLY, &Duid::en(1, b"x")));
                }
            }
            contract::check_wire_value(&Frame(m));
        }
    }

    #[test]
    fn fuzz_random_bytes() {
        let mut r = Lcg::new(42);
        let mut seeds = vec![SOLICIT.to_vec()];
        for _ in 0..100 {
            let mut message = random_message(&mut r);
            if message.is_relay() {
                message.transaction = 0;
            } else {
                message.transaction &= 0xffffff;
                message.hop_count = 0;
                message.link_address = Ipv6Addr::UNSPECIFIED;
                message.peer_address = Ipv6Addr::UNSPECIFIED;
            }
            if let Ok(bytes) = message.to_bytes() {
                seeds.push(bytes);
                if seeds.len() == 21 {
                    break;
                }
            }
        }
        assert_eq!(seeds.len(), 21);
        assert!(seeds.iter().any(|bytes| Message::parse(bytes).unwrap().is_relay()));
        let mut accepted = 0;
        for round in 0..6000 {
            let mut data = if round % 4 == 0 { r.bytes(80) } else { seeds[r.index(seeds.len())].clone() };
            for _ in 0..1 + r.index(4) {
                mutate(&mut r, &mut data);
            }
            contract::check_wire::<Message>(&data);
            contract::check_wire::<Frame>(&data);
            if let Ok(m) = Message::parse(&data) {
                accepted += 1;
                assert_eq!(m.to_bytes().unwrap(), data);
                if let Some(Ok(inner)) = m.relayed() {
                    contract::check_wire_value(&inner);
                }
            }
            contract::check_decode_with_alloc_limit(Frames::new, &data, 2 * MAX_BUFFERED);
        }
        assert!(accepted > 500, "{accepted}");
    }

    #[test]
    fn review_tcp_frames_up_to_65535_bytes_read() {
        // RFC 5460, section 5.1: the 2-byte length allows 65,535 bytes.
        let mut body = vec![0u8; 65_535 - 8];
        body[0] = 1;
        let mut frame = vec![0xff, 0xff, 1, 0, 0, 1, 0x03, 0xe8, 0xff, 0xf7];
        frame.extend_from_slice(&body);
        assert_eq!(frame.len(), 2 + 65_535);
        let value = Frame::parse(&frame).unwrap();
        assert_eq!(value.to_bytes().unwrap(), frame);
        assert!(value.0.to_bytes().is_err());
        contract::check_decode_with_alloc_limit(Frames::new, &frame, 2 * MAX_BUFFERED);
    }

    #[test]
    fn review_odd_label_bytes_keep_the_message() {
        // RFC 1035, section 3.1 allows any byte in a label. The message
        // still reads, with the list kept as its bytes.
        let bytes = with_option(opt::DOMAIN_LIST, &[1, b'.', 0]);
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.options, [DhcpOption::Other { code: opt::DOMAIN_LIST, data: vec![1, b'.', 0] }]);
        assert_eq!(m.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn review_vendor_and_dns_bodies() {
        let bad = |code: u16, body: &[u8]| {
            assert_eq!(Message::parse(&with_option(code, body)), Err(ParseError::BadOption(code)), "{code} {body:?}");
        };
        // RFC 8415, section 21.16: one or more vendor classes.
        bad(opt::VENDOR_CLASS, &[0, 0, 0, 1]);
        // Section 21.17: vendor options are code, length and value.
        bad(opt::VENDOR_OPTS, &[0, 0, 0, 1, 0]);
        bad(opt::VENDOR_OPTS, &[0, 0, 0, 1, 0, 1, 0, 2, 9]);
        assert!(Message::parse(&with_option(opt::VENDOR_OPTS, &[0, 0, 0, 1])).is_ok());
        // RFC 3646, section 3: one or more servers.
        bad(opt::DNS_SERVERS, &[]);
        let mut m = Message::new(msg::REPLY, 1);
        m.options = vec![
            DhcpOption::VendorClass { enterprise: 1, classes: vec![] },
            DhcpOption::VendorOpts { enterprise: 1, data: vec![0] },
            DhcpOption::DnsServers(vec![]),
        ];
        for option in m.options {
            let value = Message { options: vec![option], ..Message::new(msg::REPLY, 1) };
            assert!(value.to_bytes().is_err());
            contract::check_wire_value(&value);
        }
    }

    #[test]
    fn review_relayed_reads_only_relay_messages() {
        // RFC 8415, section 21.10: the Relay Message option is carried by
        // Relay-forward and Relay-reply messages only.
        let mut m = Message::new(msg::SOLICIT, 1);
        m.options.push(DhcpOption::RelayMessage(SOLICIT.to_vec()));
        assert_eq!(m.relayed(), None);
    }

    #[test]
    fn review_stream_holds_a_bounded_number_of_bytes() {
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&vec![0; 2 * MAX_BUFFERED]), MAX_BUFFERED);
        assert_eq!(stream.buffered(), MAX_BUFFERED);
        assert_eq!(stream.next(), Some(Ok(Err(ParseError::Short))));
        assert_eq!(stream.push(&[0; 4096]), 2);
        contract::check_decode_with_alloc_limit(Frames::new, &[0; 4096], 2 * MAX_BUFFERED);
    }

    #[test]
    fn writer_refuses_relays_that_do_not_fit() {
        let mut huge = Message::new(msg::SOLICIT, 0);
        huge.options.push(DhcpOption::Other { code: 1000, data: vec![0; MAX_MESSAGE - 8] });
        assert!(huge.to_bytes().is_ok());
        let forw = Message::relay_forward(&huge, 0, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED).unwrap();
        assert!(forw.to_bytes().is_err());
        let small =
            Message::relay_forward(&Message::new(msg::SOLICIT, 1), 0, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
                .unwrap();
        assert!(small.to_bytes().is_ok());
    }
}
