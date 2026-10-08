//! PCP and NAT-PMP: reading and writing port mapping requests and
//! responses, and the version negotiation between them, with no I/O.
//!
//! Requests and responses implement `Wire`, and `receive` supplies stateless
//! validation and reply decisions. There is no stream decoder, mapping-lifetime
//! state machine, NAT implementation, `Service`, or live transport.
//!
//! A host behind a NAT asks the gateway to open a port with one of two
//! protocols, both on UDP port 5351. NAT-PMP (RFC 6886, version 0) came
//! first. It can ask for the gateway's external IPv4 address and map a
//! UDP or TCP port. PCP (the Port Control Protocol, RFC 6887, version 2)
//! replaced it. PCP carries IPv6 as well, and has three opcodes: MAP opens
//! an inbound mapping, PEER creates or extends an outbound one, and
//! ANNOUNCE asks whether a server is there and what its epoch is. PCP
//! options extend a request: THIRD_PARTY asks for a mapping on behalf of
//! another host, PREFER_FAILURE refuses any port but the one suggested,
//! and FILTER limits which remote peers may use a mapping. The first byte
//! of every message is its version, and a server that does not speak a
//! version says so, which is how clients fall back from PCP to NAT-PMP.
//!
//! Nothing here reads a socket or a clock. A world that plays a gateway
//! reads each datagram itself and gives it to [`receive`], with the
//! address it came from and the gateway's epoch (the seconds since its
//! mapping table was last reset). [`receive`] drops what a server drops,
//! answers what it can answer alone (version mismatches, malformed
//! requests, unknown opcodes and options), and hands back the rest as a
//! [`NatPmpRequest`] or a PCP [`Request`]. Which mappings exist, which
//! ports are free, and whether a request is allowed are up to world code.
//! A world that plays a client builds a [`Request`], writes it with
//! [`Request::write`], and reads the answer with [`Response::parse`] or
//! [`unsupported_version`].
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. No message is longer than [`MAX_MESSAGE`], and the writers refuse
//! values above that limit without changing the destination.
//! PCP addresses are 16 bytes. An IPv4 address is carried as an
//! IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), as RFC 6887 section 5
//! says.
//!
//! ```
//! use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::pcp::{receive, Incoming, Map, Operation, Request, Response, ResultCode, Speaks};
//!
//! let laptop = Ipv4Addr::new(192, 168, 1, 20);
//! // The laptop asks for TCP port 8080 to be reachable from outside, for two hours.
//! let ask = Request {
//!     lifetime: 7200,
//!     client: laptop.to_ipv6_mapped(),
//!     operation: Operation::Map(Map {
//!         nonce: [7; 12],
//!         protocol: 6,
//!         internal_port: 8080,
//!         external_port: 0,
//!         external_address: Ipv6Addr::UNSPECIFIED,
//!     }),
//!     options: vec![],
//! };
//! let datagram = ask.to_bytes().unwrap();
//! assert_eq!(datagram.len(), 60);
//!
//! // The gateway, at epoch 1000, grants external port 40000 for an hour.
//! let Incoming::Pcp(request) = receive(&datagram, Speaks::Both, IpAddr::V4(laptop), 1000) else {
//!     panic!("expected a PCP request")
//! };
//! let Operation::Map(mut map) = request.operation.clone() else { panic!("expected MAP") };
//! map.external_port = 40000;
//! map.external_address = Ipv4Addr::new(203, 0, 113, 5).to_ipv6_mapped();
//! let mut reply = request.reply(ResultCode::Success, 3600, 1000);
//! reply.operation = Operation::Map(map);
//! let bytes = reply.to_bytes().unwrap();
//! assert_eq!(&bytes[..4], &[2, 0x81, 0, 0]);
//! assert_eq!(Response::parse(&bytes), Ok(reply));
//!
//! // The same datagram from another address passed through a NAT the
//! // laptop did not know about, and the gateway says so on its own.
//! let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
//! let Incoming::Reply(error) = receive(&datagram, Speaks::Both, other, 1000) else {
//!     panic!("expected an error reply")
//! };
//! assert_eq!(Response::parse(&error.to_bytes().unwrap()).unwrap().result, ResultCode::AddressMismatch);
//! ```

use fictionet::stdlib::codec::{Wire, be16, be32};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The UDP port PCP and NAT-PMP servers listen on.
pub const PORT: u16 = 5351;
/// The UDP port clients listen on for unsolicited ANNOUNCE responses.
pub const CLIENT_PORT: u16 = 5350;
/// The PCP version this module reads and writes (RFC 6887).
pub const VERSION: u8 = 2;
/// The version byte of NAT-PMP (RFC 6886).
pub const NAT_PMP_VERSION: u8 = 0;
/// The longest message, PCP or NAT-PMP. RFC 6887 sets it for PCP. RFC
/// 6886 sets none for NAT-PMP, whose messages are at most 16 bytes, so
/// this module uses the same limit for both.
pub const MAX_MESSAGE: usize = 1100;
/// The length of the PCP request and response headers.
pub const HEADER_LEN: usize = 24;
/// The length of the MAP opcode's data, in requests and responses.
pub const MAP_LEN: usize = 36;
/// The length of the PEER opcode's data, in requests and responses.
pub const PEER_LEN: usize = 56;
/// The length of a PCP option's header, before its data.
pub const OPTION_HEADER_LEN: usize = 4;
/// The most options one PCP message can hold: every option takes at
/// least its 4-byte header.
pub const MAX_OPTIONS: usize = (MAX_MESSAGE - HEADER_LEN) / OPTION_HEADER_LEN;
/// The lifetime RFC 6887 recommends for a long lifetime error, in seconds.
pub const LONG_ERROR_LIFETIME: u32 = 1800;
/// The lifetime RFC 6887 recommends for a short lifetime error, in
/// seconds.
pub const SHORT_ERROR_LIFETIME: u32 = 30;
/// The bit of the second byte that marks a response, in PCP (the R bit)
/// and NAT-PMP (128 added to the opcode).
pub const RESPONSE_FLAG: u8 = 0x80;

/// PCP opcodes this module reads and writes.
pub mod opcode {
    #![allow(missing_docs)]
    pub const ANNOUNCE: u8 = 0;
    pub const MAP: u8 = 1;
    pub const PEER: u8 = 2;
    /// Reserved by RFC 6887.
    pub const RESERVED: u8 = 127;
}

/// PCP option codes this module reads and writes.
pub mod option_code {
    #![allow(missing_docs)]
    pub const THIRD_PARTY: u8 = 1;
    pub const PREFER_FAILURE: u8 = 2;
    pub const FILTER: u8 = 3;
    /// Set in the code of an option a server may ignore. Without it, a
    /// server must process the option or refuse the request.
    pub const OPTIONAL_FLAG: u8 = 0x80;
}

/// NAT-PMP opcodes this module reads and writes.
pub mod nat_pmp_opcode {
    #![allow(missing_docs)]
    pub const EXTERNAL_ADDRESS: u8 = 0;
    pub const MAP_UDP: u8 = 1;
    pub const MAP_TCP: u8 = 2;
}

// ---------------------------------------------------------------------
// PCP
// ---------------------------------------------------------------------

/// A PCP result code (RFC 6887 section 7.4). Only [`ResultCode::Success`]
/// means success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResultCode {
    /// 0: the request succeeded.
    Success,
    /// 1: the server does not speak the request's version.
    UnsuppVersion,
    /// 2: the client may not do this.
    NotAuthorized,
    /// 3: the request could not be parsed.
    MalformedRequest,
    /// 4: the server does not know the opcode.
    UnsuppOpcode,
    /// 5: the server does not know or allow a mandatory option.
    UnsuppOption,
    /// 6: an option is malformed, repeated, or makes no sense here.
    MalformedOption,
    /// 7: the server or its device has a network failure.
    NetworkFailure,
    /// 8: the server is out of resources for now.
    NoResources,
    /// 9: the server does not map this transport protocol.
    UnsuppProtocol,
    /// 10: the mapping would exceed the subscriber's port quota.
    UserExQuota,
    /// 11: the suggested external address or port cannot be given.
    CannotProvideExternal,
    /// 12: the packet's source address is not the client address it
    /// carries, so a NAT sits between client and server.
    AddressMismatch,
    /// 13: the server could not create the filters asked for.
    ExcessiveRemotePeers,
    /// Any other code, 14 to 255.
    Other(u8),
}

impl ResultCode {
    /// The code for byte `c`.
    pub fn from_code(c: u8) -> ResultCode {
        match c {
            0 => ResultCode::Success,
            1 => ResultCode::UnsuppVersion,
            2 => ResultCode::NotAuthorized,
            3 => ResultCode::MalformedRequest,
            4 => ResultCode::UnsuppOpcode,
            5 => ResultCode::UnsuppOption,
            6 => ResultCode::MalformedOption,
            7 => ResultCode::NetworkFailure,
            8 => ResultCode::NoResources,
            9 => ResultCode::UnsuppProtocol,
            10 => ResultCode::UserExQuota,
            11 => ResultCode::CannotProvideExternal,
            12 => ResultCode::AddressMismatch,
            13 => ResultCode::ExcessiveRemotePeers,
            other => ResultCode::Other(other),
        }
    }

    /// The code's byte.
    pub fn code(self) -> u8 {
        match self {
            ResultCode::Success => 0,
            ResultCode::UnsuppVersion => 1,
            ResultCode::NotAuthorized => 2,
            ResultCode::MalformedRequest => 3,
            ResultCode::UnsuppOpcode => 4,
            ResultCode::UnsuppOption => 5,
            ResultCode::MalformedOption => 6,
            ResultCode::NetworkFailure => 7,
            ResultCode::NoResources => 8,
            ResultCode::UnsuppProtocol => 9,
            ResultCode::UserExQuota => 10,
            ResultCode::CannotProvideExternal => 11,
            ResultCode::AddressMismatch => 12,
            ResultCode::ExcessiveRemotePeers => 13,
            ResultCode::Other(c) => c,
        }
    }

    /// The lifetime RFC 6887 recommends for this error: 30 seconds for a
    /// short lifetime error, 30 minutes for the rest, and 0 for success.
    /// RFC 6887 leaves CANNOT_PROVIDE_EXTERNAL to the server, and this
    /// gives it the short one.
    pub fn error_lifetime(self) -> u32 {
        match self {
            ResultCode::Success => 0,
            ResultCode::NetworkFailure
            | ResultCode::NoResources
            | ResultCode::UserExQuota
            | ResultCode::CannotProvideExternal => SHORT_ERROR_LIFETIME,
            _ => LONG_ERROR_LIFETIME,
        }
    }
}

/// The MAP opcode's data (RFC 6887 section 11.1). A request carries the
/// suggested external port and address, and a response the assigned
/// ones, in the same places.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Map {
    /// Chosen at random by the client, and copied into the response.
    pub nonce: [u8; 12],
    /// The IANA protocol number: 6 for TCP, 17 for UDP, 0 for all.
    pub protocol: u8,
    /// The port on the internal host. 0 means all ports.
    pub internal_port: u16,
    /// The suggested (request) or assigned (response) external port.
    pub external_port: u16,
    /// The suggested (request) or assigned (response) external address.
    pub external_address: Ipv6Addr,
}

/// The PEER opcode's data (RFC 6887 section 12.1): a MAP's fields, and
/// the remote peer the outbound mapping talks to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Peer {
    /// Chosen at random by the client, and copied into the response.
    pub nonce: [u8; 12],
    /// The IANA protocol number. A request may not use 0.
    pub protocol: u8,
    /// The port on the internal host. A request may not use 0.
    pub internal_port: u16,
    /// The suggested (request) or assigned (response) external port.
    pub external_port: u16,
    /// The suggested (request) or assigned (response) external address.
    pub external_address: Ipv6Addr,
    /// The remote peer's port. A request may not use 0.
    pub remote_port: u16,
    /// The remote peer's address, as the client sees it.
    pub remote_address: Ipv6Addr,
}

/// What a PCP message asks for or answers: its opcode and the opcode's
/// data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// ANNOUNCE (opcode 0), which has no data.
    Announce,
    /// MAP (opcode 1).
    Map(Map),
    /// PEER (opcode 2).
    Peer(Peer),
    /// Any other opcode, with every byte after the header unread, options
    /// included. A response whose MAP or PEER data or options cannot be
    /// read is kept this way too.
    Other {
        /// The 7-bit opcode.
        opcode: u8,
        /// The bytes after the header.
        data: Vec<u8>,
    },
}

impl Operation {
    /// The operation's opcode, without the R bit.
    pub fn opcode(&self) -> u8 {
        match self {
            Operation::Announce => opcode::ANNOUNCE,
            Operation::Map(_) => opcode::MAP,
            Operation::Peer(_) => opcode::PEER,
            Operation::Other { opcode, .. } => opcode & !RESPONSE_FLAG,
        }
    }
}

/// A PCP option (RFC 6887 sections 7.3 and 13).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PcpOption {
    /// THIRD_PARTY (1): the mapping is for this internal address, not the
    /// sender's. MAP and PEER only, at most once.
    ThirdParty(Ipv6Addr),
    /// PREFER_FAILURE (2): fail rather than map another port or address.
    /// MAP only, at most once.
    PreferFailure,
    /// FILTER (3): only this remote peer may use the mapping. MAP only,
    /// any number of times.
    Filter {
        /// How many leading bits of `remote_address` count. 0 removes
        /// every filter. For an IPv4-mapped address it is 96 more than
        /// the IPv4 prefix length.
        prefix_length: u8,
        /// The remote peer's port. 0 means all ports.
        remote_port: u16,
        /// The remote peer's address.
        remote_address: Ipv6Addr,
    },
    /// Any other option, or, in a response, a known option with the
    /// wrong length.
    Other {
        /// The option code. Codes below 128 are mandatory to process.
        code: u8,
        /// The option's data, without padding.
        data: Vec<u8>,
    },
}

impl PcpOption {
    /// The option's code.
    pub fn code(&self) -> u8 {
        match self {
            PcpOption::ThirdParty(_) => option_code::THIRD_PARTY,
            PcpOption::PreferFailure => option_code::PREFER_FAILURE,
            PcpOption::Filter { .. } => option_code::FILTER,
            PcpOption::Other { code, .. } => *code,
        }
    }

    /// Whether a server may ignore the option: its code is 128 or more.
    pub fn is_optional(&self) -> bool {
        self.code() & option_code::OPTIONAL_FLAG != 0
    }

    /// The option's data, without its header or padding.
    fn data(&self) -> Vec<u8> {
        match self {
            PcpOption::ThirdParty(a) => a.octets().to_vec(),
            PcpOption::PreferFailure => Vec::new(),
            PcpOption::Filter {
                prefix_length,
                remote_port,
                remote_address,
            } => {
                let mut d = vec![0, *prefix_length];
                d.extend_from_slice(&remote_port.to_be_bytes());
                d.extend_from_slice(&remote_address.octets());
                d
            }
            PcpOption::Other { data, .. } => data.clone(),
        }
    }
}

/// Why bytes are not a PCP or NAT-PMP request or response this module
/// reads, or a value cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// Too few bytes: under 2 (requests) or 4 (responses) to know the
    /// version, or under the 24-byte header. The value is the length.
    Short(usize),
    /// A request with the R bit set, or a response without it.
    WrongDirection,
    /// A version other than 2. The value is the version byte.
    Version(u8),
    /// Longer than [`MAX_MESSAGE`]. The value is the length.
    TooLong(usize),
    /// A length that is not a multiple of 4. The value is the length.
    Unaligned(usize),
    /// Too short for the opcode's data.
    OpcodeData {
        /// The opcode.
        opcode: u8,
        /// The bytes after the header.
        len: usize,
    },
    /// An option runs past the end of the message, or a known option has
    /// the wrong length.
    MalformedOption,
    /// An option that may appear once appears again. The value is its
    /// code.
    DuplicateOption(u8),
    /// NAT-PMP: bytes follow a fixed-size message.
    NatPmpTrailing,
    /// NAT-PMP: too few bytes for the opcode. The value is the length.
    NatPmpShort(usize),
    /// NAT-PMP: longer than [`MAX_MESSAGE`]. The value is the length.
    NatPmpTooLong(usize),
    /// NAT-PMP: a version other than 0. The value is the version byte.
    NatPmpVersion(u8),
    /// NAT-PMP: a request with an opcode of 128 or more, or a response
    /// without.
    NatPmpWrongDirection,
}

impl Error {
    /// The result code a server answers this error with, or `None` if
    /// RFC 6887 says to drop the message without a word.
    pub fn result_code(self) -> Option<ResultCode> {
        match self {
            Error::Short(_)
            | Error::WrongDirection
            | Error::Unwritable
            | Error::NatPmpTrailing
            | Error::NatPmpShort(_)
            | Error::NatPmpTooLong(_)
            | Error::NatPmpVersion(_)
            | Error::NatPmpWrongDirection => None,
            Error::Version(_) => Some(ResultCode::UnsuppVersion),
            Error::TooLong(_) | Error::Unaligned(_) | Error::OpcodeData { .. } => {
                Some(ResultCode::MalformedRequest)
            }
            Error::MalformedOption | Error::DuplicateOption(_) => Some(ResultCode::MalformedOption),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Short(n) => write!(f, "{n} bytes, too short for a PCP message"),
            Error::WrongDirection => f.write_str("R bit says the message goes the other way"),
            Error::Version(v) => write!(f, "version {v}, not 2 (PCP)"),
            Error::TooLong(n) => write!(f, "{n} bytes, longer than {MAX_MESSAGE}"),
            Error::Unaligned(n) => write!(f, "{n} bytes, not a multiple of 4"),
            Error::OpcodeData { opcode, len } => {
                write!(f, "{len} bytes of data, too short for opcode {opcode}")
            }
            Error::MalformedOption => f.write_str("malformed option"),
            Error::DuplicateOption(c) => write!(f, "option {c} repeated"),
            Error::NatPmpTrailing => f.write_str("bytes after the message"),
            Error::NatPmpShort(n) => write!(f, "{n} bytes, too short for the NAT-PMP opcode"),
            Error::NatPmpTooLong(n) => write!(f, "{n} bytes, longer than {MAX_MESSAGE} (NAT-PMP)"),
            Error::NatPmpVersion(v) => write!(f, "version {v}, not 0 (NAT-PMP)"),
            Error::NatPmpWrongDirection => {
                f.write_str("opcode says the message goes the other way")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A PCP request (RFC 6887 section 7.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The requested lifetime, in seconds. 0 asks MAP to delete.
    pub lifetime: u32,
    /// The client's own address, as it believes it to be. IPv4 is
    /// IPv4-mapped.
    pub client: Ipv6Addr,
    /// The opcode and its data.
    pub operation: Operation,
    /// The options, in order.
    pub options: Vec<PcpOption>,
}

impl Request {
    /// Checks what a server checks once a request reads, in the order of
    /// RFC 6887 sections 8.2, 11.3 and 12.3. First the client address
    /// against `source` (ADDRESS_MISMATCH). Then the opcode: an unknown
    /// one is UNSUPP_OPCODE. Then the MAP and PEER fields RFC 6887 forbids
    /// (MALFORMED_REQUEST). A MAP with protocol 0 and a nonzero internal
    /// port is malformed only when its lifetime is not 0, since a delete
    /// is allowed any port. Last, each option against the opcode
    /// (MALFORMED_REQUEST, MALFORMED_OPTION, or UNSUPP_OPTION for an
    /// unknown mandatory option). Whether to allow THIRD_PARTY at all is
    /// left to the world.
    pub fn check(&self, source: IpAddr) -> Result<(), ResultCode> {
        let source = mapped(source);
        if self.client != source {
            return Err(ResultCode::AddressMismatch);
        }
        match &self.operation {
            Operation::Other { .. } => return Err(ResultCode::UnsuppOpcode),
            Operation::Map(m) if self.lifetime != 0 && m.protocol == 0 && m.internal_port != 0 => {
                return Err(ResultCode::MalformedRequest);
            }
            Operation::Peer(p) => {
                if p.protocol == 0 || p.internal_port == 0 || p.remote_port == 0 {
                    return Err(ResultCode::MalformedRequest);
                }
                if self
                    .options
                    .iter()
                    .any(|o| matches!(o, PcpOption::PreferFailure))
                {
                    return Err(ResultCode::MalformedRequest);
                }
            }
            _ => {}
        }
        for o in &self.options {
            match (o, &self.operation) {
                (PcpOption::ThirdParty(a), Operation::Map(_) | Operation::Peer(_)) => {
                    if *a == source {
                        return Err(ResultCode::MalformedRequest);
                    }
                }
                (PcpOption::PreferFailure, Operation::Map(m)) => {
                    if self.lifetime == 0 || m.external_port == 0 {
                        return Err(ResultCode::MalformedOption);
                    }
                }
                (
                    PcpOption::Filter {
                        prefix_length,
                        remote_address,
                        ..
                    },
                    Operation::Map(_),
                ) => {
                    if self.lifetime == 0 || !filter_prefix_ok(*prefix_length, remote_address) {
                        return Err(ResultCode::MalformedOption);
                    }
                }
                (
                    PcpOption::ThirdParty(_) | PcpOption::PreferFailure | PcpOption::Filter { .. },
                    _,
                ) => {
                    return Err(ResultCode::MalformedOption);
                }
                (PcpOption::Other { code, .. }, _) => {
                    if code & option_code::OPTIONAL_FLAG == 0 {
                        return Err(ResultCode::UnsuppOption);
                    }
                }
            }
        }
        Ok(())
    }

    /// A response to this request with `result`, `lifetime` and `epoch`.
    /// It copies the opcode, its data and every option, as an error
    /// response must. For a success, the world sets the assigned port and
    /// address, and removes any option it did not process.
    pub fn reply(&self, result: ResultCode, lifetime: u32, epoch: u32) -> Response {
        Response {
            result,
            lifetime,
            epoch,
            reserved: [0; 12],
            operation: self.operation.clone(),
            options: self.options.clone(),
        }
    }
}

/// A PCP response (RFC 6887 section 7.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Response {
    /// The result.
    pub result: ResultCode,
    /// On success, the mapping's lifetime in seconds. On an error, how
    /// long the same request will get the same error.
    pub lifetime: u32,
    /// The server's epoch: seconds since its mapping state was reset.
    pub epoch: u32,
    /// The 96 reserved bits. Zero, except in an error response to a
    /// request that did not parse, where they are the last 12 bytes of
    /// the request's client address.
    pub reserved: [u8; 12],
    /// The opcode and its data.
    pub operation: Operation,
    /// The options, in order.
    pub options: Vec<PcpOption>,
}

impl Response {
    /// An unsolicited ANNOUNCE response, which a server that lost its
    /// state sends to [`CLIENT_PORT`] with its reset epoch.
    pub fn announce(epoch: u32) -> Response {
        Response {
            result: ResultCode::Success,
            lifetime: 0,
            epoch,
            reserved: [0; 12],
            operation: Operation::Announce,
            options: vec![],
        }
    }
}

/// The error response to a PCP request that did not parse, built from its
/// bytes as RFC 6887 section 8.2 says: the first [`MAX_MESSAGE`] bytes,
/// padded with zeros to a multiple of 4, with the version set to 2, the R
/// bit set, and the result, lifetime and epoch filled in. The reserved
/// bits keep the last 12 bytes of the request's client address. A request
/// shorter than the header is padded to [`HEADER_LEN`], so the reply always
/// reads as a [`Response`].
pub fn error_reply(request: &[u8], result: ResultCode, lifetime: u32, epoch: u32) -> Response {
    let opcode = request.get(1).copied().unwrap_or(0) & !RESPONSE_FLAG;
    let mut reserved = [0; 12];
    for (slot, value) in reserved
        .iter_mut()
        .zip(request.get(12..request.len().min(24)).unwrap_or_default())
    {
        *slot = *value;
    }
    let mut body = request
        .get(HEADER_LEN..request.len().min(MAX_MESSAGE))
        .unwrap_or_default()
        .to_vec();
    body.resize(body.len().next_multiple_of(4), 0);
    let (operation, options) = response_body(opcode, &body);
    Response {
        result,
        lifetime,
        epoch,
        reserved,
        operation,
        options,
    }
}

// ---------------------------------------------------------------------
// NAT-PMP
// ---------------------------------------------------------------------

/// A NAT-PMP result code (RFC 6886 section 3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NatPmpResult {
    /// 0: the request succeeded.
    Success,
    /// 1: the server does not speak the request's version.
    UnsupportedVersion,
    /// 2: the gateway can map ports, but not for this client.
    NotAuthorized,
    /// 3: the gateway has a network failure, such as no DHCP lease.
    NetworkFailure,
    /// 4: the gateway cannot create more mappings now.
    OutOfResources,
    /// 5: the server does not know the opcode.
    UnsupportedOpcode,
    /// Any other code.
    Other(u16),
}

impl NatPmpResult {
    /// The result for code `c`.
    pub fn from_code(c: u16) -> NatPmpResult {
        match c {
            0 => NatPmpResult::Success,
            1 => NatPmpResult::UnsupportedVersion,
            2 => NatPmpResult::NotAuthorized,
            3 => NatPmpResult::NetworkFailure,
            4 => NatPmpResult::OutOfResources,
            5 => NatPmpResult::UnsupportedOpcode,
            other => NatPmpResult::Other(other),
        }
    }

    /// The result's code.
    pub fn code(self) -> u16 {
        match self {
            NatPmpResult::Success => 0,
            NatPmpResult::UnsupportedVersion => 1,
            NatPmpResult::NotAuthorized => 2,
            NatPmpResult::NetworkFailure => 3,
            NatPmpResult::OutOfResources => 4,
            NatPmpResult::UnsupportedOpcode => 5,
            NatPmpResult::Other(c) => c,
        }
    }
}

/// The transport protocol of a NAT-PMP mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NatPmpProtocol {
    /// Opcode 1.
    Udp,
    /// Opcode 2.
    Tcp,
}

impl NatPmpProtocol {
    /// The opcode that maps this protocol.
    pub fn opcode(self) -> u8 {
        match self {
            NatPmpProtocol::Udp => nat_pmp_opcode::MAP_UDP,
            NatPmpProtocol::Tcp => nat_pmp_opcode::MAP_TCP,
        }
    }
}

/// A NAT-PMP request (RFC 6886 sections 3.2 and 3.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NatPmpRequest {
    /// Opcode 0: what is the gateway's external IPv4 address?
    ExternalAddress,
    /// Opcode 1 or 2: map a port. Lifetime 0 deletes the mapping, and
    /// internal port 0 with lifetime 0 deletes all of the client's
    /// mappings for the protocol.
    Map {
        /// UDP or TCP.
        protocol: NatPmpProtocol,
        /// The client's port.
        internal_port: u16,
        /// The external port the client would like. 0 means any.
        external_port: u16,
        /// The requested lifetime, in seconds.
        lifetime: u32,
    },
    /// Any other opcode below 128, which a server answers with
    /// [`NatPmpResult::UnsupportedOpcode`].
    Unsupported {
        /// The opcode.
        opcode: u8,
        /// The bytes after the opcode.
        data: Vec<u8>,
    },
}

impl NatPmpRequest {
    /// The response that refuses this request with `result`, as RFC 6886
    /// section 3.5 says: the internal port copied, the external address,
    /// port and lifetime zero. A failed delete is the exception: RFC 6886
    /// section 3.4 wants the mapping that still exists, so the world sets
    /// its external port. For an unsupported opcode, the whole
    /// request comes back with the top bit of the opcode set and the
    /// result over its third and fourth bytes.
    pub fn refuse(&self, result: NatPmpResult, epoch: u32) -> NatPmpResponse {
        match self {
            NatPmpRequest::ExternalAddress => NatPmpResponse::ExternalAddress {
                result,
                epoch,
                address: Ipv4Addr::UNSPECIFIED,
            },
            NatPmpRequest::Map {
                protocol,
                internal_port,
                ..
            } => NatPmpResponse::Map {
                protocol: *protocol,
                result,
                epoch,
                internal_port: *internal_port,
                external_port: 0,
                lifetime: 0,
            },
            NatPmpRequest::Unsupported { opcode, data } => NatPmpResponse::Other {
                opcode: *opcode,
                result,
                data: data.get(2..).unwrap_or(&[]).to_vec(),
            },
        }
    }
}

/// A NAT-PMP response (RFC 6886 sections 3.2, 3.3 and 3.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NatPmpResponse {
    /// Opcode 128: the gateway's external IPv4 address.
    ExternalAddress {
        /// The result.
        result: NatPmpResult,
        /// Seconds since the gateway's mapping table was reset.
        epoch: u32,
        /// The external address. 0.0.0.0 on an error.
        address: Ipv4Addr,
    },
    /// Opcode 129 or 130: the mapping made.
    Map {
        /// UDP or TCP.
        protocol: NatPmpProtocol,
        /// The result.
        result: NatPmpResult,
        /// Seconds since the gateway's mapping table was reset.
        epoch: u32,
        /// The client's port, copied from the request.
        internal_port: u16,
        /// The external port mapped. 0 on an error.
        external_port: u16,
        /// The mapping's lifetime, in seconds. 0 on an error.
        lifetime: u32,
    },
    /// The server does not speak the request's version. RFC 6886 gives it
    /// opcode 0 and result 1, eight bytes long.
    UnsupportedVersion {
        /// Seconds since the gateway's mapping table was reset.
        epoch: u32,
    },
    /// The response to any other opcode, usually
    /// [`NatPmpResult::UnsupportedOpcode`].
    Other {
        /// The request's opcode, without the top bit.
        opcode: u8,
        /// The result.
        result: NatPmpResult,
        /// The bytes after the result.
        data: Vec<u8>,
    },
}

// ---------------------------------------------------------------------
// Serving and version negotiation
// ---------------------------------------------------------------------

/// Which protocols a server speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Speaks {
    /// PCP only. NAT-PMP requests get a PCP UNSUPP_VERSION reply, whose
    /// first four bytes a NAT-PMP client reads as result 1 (RFC 6887
    /// appendix A).
    Pcp,
    /// NAT-PMP only. PCP requests get the NAT-PMP Unsupported Version
    /// reply.
    NatPmp,
    /// Both, told apart by the first byte.
    Both,
}

/// What a server does with one datagram, as [`receive`] decides it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Incoming {
    /// Drop it without a reply.
    Ignore,
    /// Send these bytes back to the sender. Nothing else changes.
    Reply(Reply),
    /// A NAT-PMP request for the world to answer.
    NatPmp(NatPmpRequest),
    /// A PCP request that passed [`Request::check`], for the world to
    /// answer with [`Request::reply`].
    Pcp(Request),
}

/// Reads one datagram the way a server does, and says what to do with
/// it. `source` is the address it came from, and `epoch` the server's
/// epoch, which error replies carry.
///
/// For PCP, the steps are those of RFC 6887 section 8.2: messages under 2
/// bytes and responses are dropped; an unsupported version gets
/// UNSUPP_VERSION with version 2; a version 2 message under 24 bytes is
/// dropped; malformed requests get MALFORMED_REQUEST; then a request from
/// an address other than its client address gets ADDRESS_MISMATCH, before
/// its options are judged; malformed options, unknown opcodes, and the
/// other failures [`Request::check`] finds get their error replies. For NAT-PMP
/// (RFC 6886 section 3.5), responses and short requests are dropped, an
/// unknown opcode gets Unsupported Opcode, and a server that speaks only
/// NAT-PMP answers any other version with Unsupported Version. Responses
/// are never answered, so two servers cannot keep replying to each other.
pub fn receive(datagram: &[u8], speaks: Speaks, source: IpAddr, epoch: u32) -> Incoming {
    let b = datagram;
    if b.len() < 2 || b[1] & RESPONSE_FLAG != 0 {
        return Incoming::Ignore;
    }
    if b[0] == NAT_PMP_VERSION && speaks != Speaks::Pcp {
        return match NatPmpRequest::parse(b) {
            Ok(r @ NatPmpRequest::Unsupported { .. }) => Incoming::Reply(Reply::NatPmp(
                r.refuse(NatPmpResult::UnsupportedOpcode, epoch),
            )),
            Ok(r) => Incoming::NatPmp(r),
            Err(_) => Incoming::Ignore,
        };
    }
    if speaks == Speaks::NatPmp {
        return Incoming::Reply(Reply::NatPmp(NatPmpResponse::UnsupportedVersion { epoch }));
    }
    let request = match Request::parse(b) {
        Ok(r) => r,
        Err(e) => {
            let code = match e.result_code() {
                // Options are read after the address check (RFC 6887
                // section 8.2), so a request from the wrong address hears
                // that first. The header has been read by now.
                Some(ResultCode::MalformedOption)
                    if b.get(8..HEADER_LEN).map(ip6) != Some(mapped(source)) =>
                {
                    ResultCode::AddressMismatch
                }
                Some(code) => code,
                None => return Incoming::Ignore,
            };
            return Incoming::Reply(Reply::Pcp(error_reply(
                b,
                code,
                code.error_lifetime(),
                epoch,
            )));
        }
    };
    if let Err(code) = request.check(source) {
        return Incoming::Reply(Reply::Pcp(request.reply(
            code,
            code.error_lifetime(),
            epoch,
        )));
    }
    Incoming::Pcp(request)
}

/// An UNSUPP_VERSION reply, in PCP or NAT-PMP form, as a client reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnsupportedVersion {
    /// The version the server offers instead. 0 means NAT-PMP.
    pub version: u8,
    /// How long the server says the error lasts, in seconds. NAT-PMP
    /// replies do not say.
    pub lifetime: Option<u32>,
}

/// What a client does after an UNSUPP_VERSION reply (RFC 6887 section 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersionChoice {
    /// Send the request again as PCP version 2.
    Pcp,
    /// Send the request again as NAT-PMP.
    NatPmp,
    /// Stop, and try PCP again after this many seconds.
    GiveUp {
        /// The smaller of 30 minutes and the reply's lifetime.
        retry_after: u32,
    },
}

/// Reads a reply that says the server does not speak the version a client
/// sent, in either form: a PCP response with result UNSUPP_VERSION, or a
/// NAT-PMP message with version 0 and result 1. RFC 6886 gives the
/// NAT-PMP form opcode 0, and some gateways send 128 plus the request's
/// opcode, so both are read. Anything else is `None`.
pub fn unsupported_version(datagram: &[u8]) -> Option<UnsupportedVersion> {
    let b = datagram;
    if b.len() < 4 || b.len() > MAX_MESSAGE {
        return None;
    }
    if b[0] == NAT_PMP_VERSION {
        let op_ok = b[1] == 0 || b[1] & RESPONSE_FLAG != 0;
        return (op_ok && be16(b, 2)? == 1).then_some(UnsupportedVersion {
            version: 0,
            lifetime: None,
        });
    }
    if b[1] & RESPONSE_FLAG == 0 || b[3] != ResultCode::UnsuppVersion.code() {
        return None;
    }
    let lifetime = be32(b, 4);
    Some(UnsupportedVersion {
        version: b[0],
        lifetime,
    })
}

impl UnsupportedVersion {
    /// The next step for a client that sent version `sent` (0 for NAT-PMP,
    /// 2 for PCP) and speaks both. A server offering 0 means NAT-PMP, and
    /// a server offering 2 means PCP, unless that is what the client sent.
    /// A server offering any other version means the client tries the
    /// next version it speaks below the one it sent (RFC 6887 section 9).
    /// Only a client that sent a version above 2 has one. Any other client
    /// gives up and retries after 30 minutes, or the reply's lifetime if
    /// that is shorter.
    pub fn next_step(&self, sent: u8) -> VersionChoice {
        let give_up = VersionChoice::GiveUp {
            retry_after: self
                .lifetime
                .unwrap_or(LONG_ERROR_LIFETIME)
                .min(LONG_ERROR_LIFETIME),
        };
        match (self.version, sent) {
            (NAT_PMP_VERSION, s) if s != NAT_PMP_VERSION => VersionChoice::NatPmp,
            (VERSION, s) if s != VERSION => VersionChoice::Pcp,
            (v, s) if v != NAT_PMP_VERSION && v != VERSION && s > VERSION => VersionChoice::Pcp,
            _ => give_up,
        }
    }
}

/// An address as PCP carries it: IPv6 as is, IPv4 as IPv4-mapped.
pub fn mapped(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V4(a) => a.to_ipv6_mapped(),
        IpAddr::V6(a) => a,
    }
}

/// An address PCP carries, as IPv4 if it is IPv4-mapped and as IPv6 if
/// not.
pub fn unmapped(address: Ipv6Addr) -> IpAddr {
    match address.to_ipv4_mapped() {
        Some(a) => IpAddr::V4(a),
        None => IpAddr::V6(address),
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// The PCP length rules, once the header is known to be version 2:
/// at least the header, at most [`MAX_MESSAGE`], a multiple of 4.
fn check_length(b: &[u8]) -> Result<(), Error> {
    if b.len() < HEADER_LEN {
        return Err(Error::Short(b.len()));
    }
    if b.len() > MAX_MESSAGE {
        return Err(Error::TooLong(b.len()));
    }
    if !b.len().is_multiple_of(4) {
        return Err(Error::Unaligned(b.len()));
    }
    Ok(())
}

/// Whether a FILTER prefix length fits its address (RFC 6887 section
/// 13.3). 0 always does, since it removes every filter.
fn filter_prefix_ok(prefix: u8, address: &Ipv6Addr) -> bool {
    match address.to_ipv4_mapped() {
        _ if prefix == 0 => true,
        Some(_) => (96..=128).contains(&prefix),
        None => prefix <= 128,
    }
}

/// Reads the opcode's data and options after the header. `strict` is for
/// requests: known options must have their lengths and appear no more
/// often than allowed.
fn read_body(op: u8, body: &[u8], strict: bool) -> Result<(Operation, Vec<PcpOption>), Error> {
    let short = || Error::OpcodeData {
        opcode: op,
        len: body.len(),
    };
    match op {
        opcode::ANNOUNCE => Ok((Operation::Announce, read_options(body, strict)?)),
        opcode::MAP => {
            let d = body.get(..MAP_LEN).ok_or_else(short)?;
            Ok((
                Operation::Map(read_map(d).ok_or_else(short)?),
                read_options(&body[MAP_LEN..], strict)?,
            ))
        }
        opcode::PEER => {
            let d = body.get(..PEER_LEN).ok_or_else(short)?;
            let m = read_map(&d[..MAP_LEN]).ok_or_else(short)?;
            let peer = Peer {
                nonce: m.nonce,
                protocol: m.protocol,
                internal_port: m.internal_port,
                external_port: m.external_port,
                external_address: m.external_address,
                remote_port: be16(d, 36).ok_or_else(short)?,
                remote_address: ip6(&d[40..56]),
            };
            Ok((
                Operation::Peer(peer),
                read_options(&body[PEER_LEN..], strict)?,
            ))
        }
        _ => Ok((
            Operation::Other {
                opcode: op,
                data: body.to_vec(),
            },
            vec![],
        )),
    }
}

/// Keeps response bytes opaque when decoding would discard reserved bytes
/// or option padding. This also preserves the request body in error replies.
fn response_body(opcode: u8, body: &[u8]) -> (Operation, Vec<PcpOption>) {
    if let Ok((operation, options)) = read_body(opcode, body, false) {
        let mut encoded = Vec::new();
        if write_operation(&mut encoded, &operation).is_ok()
            && write_options(&mut encoded, &options, false).is_ok()
            && encoded == body
        {
            return (operation, options);
        }
    }
    (
        Operation::Other {
            opcode,
            data: body.to_vec(),
        },
        vec![],
    )
}

/// Reads MAP data from exactly [`MAP_LEN`] bytes.
fn read_map(d: &[u8]) -> Option<Map> {
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&d[..12]);
    Some(Map {
        nonce,
        protocol: d[12],
        internal_port: be16(d, 16)?,
        external_port: be16(d, 18)?,
        external_address: ip6(&d[20..36]),
    })
}

/// Reads options until `b` ends.
fn read_options(b: &[u8], strict: bool) -> Result<Vec<PcpOption>, Error> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let (mut third_party, mut prefer_failure) = (false, false);
    while i < b.len() {
        if out.len() >= MAX_OPTIONS {
            return Err(Error::MalformedOption);
        }
        let h = b
            .get(i..i + OPTION_HEADER_LEN)
            .ok_or(Error::MalformedOption)?;
        let (code, len) = (h[0], usize::from(be16(h, 2).ok_or(Error::MalformedOption)?));
        let start = i + OPTION_HEADER_LEN;
        let end = start.checked_add(len).ok_or(Error::MalformedOption)?;
        let padded = end.next_multiple_of(4);
        if padded > b.len() {
            return Err(Error::MalformedOption);
        }
        let data = &b[start..end];
        let option = match (code, len) {
            (option_code::THIRD_PARTY, 16) => PcpOption::ThirdParty(ip6(data)),
            (option_code::PREFER_FAILURE, 0) => PcpOption::PreferFailure,
            (option_code::FILTER, 20) => PcpOption::Filter {
                prefix_length: data[1],
                remote_port: be16(data, 2).ok_or(Error::MalformedOption)?,
                remote_address: ip6(&data[4..20]),
            },
            (option_code::THIRD_PARTY | option_code::PREFER_FAILURE | option_code::FILTER, _)
                if strict =>
            {
                return Err(Error::MalformedOption);
            }
            _ => PcpOption::Other {
                code,
                data: data.to_vec(),
            },
        };
        if strict {
            let seen = match option {
                PcpOption::ThirdParty(_) => Some(&mut third_party),
                PcpOption::PreferFailure => Some(&mut prefer_failure),
                _ => None,
            };
            if let Some(seen) = seen {
                if *seen {
                    return Err(Error::DuplicateOption(code));
                }
                *seen = true;
            }
        }
        out.push(option);
        i = padded;
    }
    Ok(out)
}

/// Writes opcode data. Refuses oversized or unaligned opaque data.
fn write_operation(out: &mut Vec<u8>, op: &Operation) -> Result<(), Error> {
    let write_map = |out: &mut Vec<u8>,
                     nonce: &[u8; 12],
                     protocol: u8,
                     internal: u16,
                     external: u16,
                     addr: &Ipv6Addr| {
        out.extend_from_slice(nonce);
        out.extend_from_slice(&[protocol, 0, 0, 0]);
        out.extend_from_slice(&internal.to_be_bytes());
        out.extend_from_slice(&external.to_be_bytes());
        out.extend_from_slice(&addr.octets());
    };
    match op {
        Operation::Announce => {}
        Operation::Map(m) => write_map(
            out,
            &m.nonce,
            m.protocol,
            m.internal_port,
            m.external_port,
            &m.external_address,
        ),
        Operation::Peer(p) => {
            write_map(
                out,
                &p.nonce,
                p.protocol,
                p.internal_port,
                p.external_port,
                &p.external_address,
            );
            out.extend_from_slice(&p.remote_port.to_be_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&p.remote_address.octets());
        }
        Operation::Other { data, .. } => {
            let room = MAX_MESSAGE.saturating_sub(out.len());
            if data.len() > room || !data.len().is_multiple_of(4) {
                return Err(Error::Unwritable);
            }
            out.extend_from_slice(data);
        }
    }
    Ok(())
}

/// Writes every option. Refuses oversized options, duplicate request singletons
/// and opaque request options that name a defined code.
fn write_options(out: &mut Vec<u8>, options: &[PcpOption], request: bool) -> Result<(), Error> {
    if options.len() > MAX_OPTIONS {
        return Err(Error::Unwritable);
    }
    let (mut third_party, mut prefer_failure) = (false, false);
    for o in options {
        if request {
            let seen = match o {
                PcpOption::ThirdParty(_) => Some(&mut third_party),
                PcpOption::PreferFailure => Some(&mut prefer_failure),
                PcpOption::Other { code: 1..=3, .. } => return Err(Error::Unwritable),
                _ => None,
            };
            if let Some(seen) = seen {
                if *seen {
                    return Err(Error::Unwritable);
                }
                *seen = true;
            }
        }
        if matches!(o, PcpOption::Other { data, .. } if data.len() > MAX_MESSAGE) {
            return Err(Error::Unwritable);
        }
        let data = o.data();
        let size = OPTION_HEADER_LEN.saturating_add(data.len().next_multiple_of(4));
        if out.len().saturating_add(size) > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&[o.code(), 0]);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        out.resize(out.len().next_multiple_of(4), 0);
    }
    Ok(())
}

/// An IPv6 address from the first 16 bytes of `b`.
fn ip6(b: &[u8]) -> Ipv6Addr {
    let mut a = [0; 16];
    a.copy_from_slice(&b[..16]);
    Ipv6Addr::from(a)
}

/// An IPv4 address from the first 4 bytes of `b`.
fn ip4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

impl Wire for Request {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a request. The checks run in the order of RFC 6887 section
    /// 8.2, so the first error found is the one a server reports. Known
    /// options must have their exact lengths, and THIRD_PARTY and
    /// PREFER_FAILURE may each appear once.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Request, Error> {
        if b.len() < 2 {
            return Err(Error::Short(b.len()));
        }
        if b[1] & RESPONSE_FLAG != 0 {
            return Err(Error::WrongDirection);
        }
        if b[0] != VERSION {
            return Err(Error::Version(b[0]));
        }
        check_length(b)?;
        let op = b[1];
        let (operation, options) = read_body(op, &b[HEADER_LEN..], true)?;
        Ok(Request {
            lifetime: be32(b, 4).ok_or(Error::Short(b.len()))?,
            client: ip6(&b[8..24]),
            operation,
            options,
        })
    }

    /// Appends the request. Refuses oversized fields, unaligned opaque data, duplicate
    /// singleton options, and variants that would change. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let op = self.operation.opcode();
        let mut out = Vec::with_capacity(HEADER_LEN + PEER_LEN);
        out.extend_from_slice(&[VERSION, op, 0, 0]);
        out.extend_from_slice(&self.lifetime.to_be_bytes());
        out.extend_from_slice(&self.client.octets());
        write_operation(&mut out, &self.operation)?;
        write_options(&mut out, &self.options, true)?;
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Response {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a response. The checks run in the order of RFC 6887 section
    /// 8.3. A reply whose version is not 2 is [`Error::Version`], and
    /// [`unsupported_version`] reads it. Clients must ignore options they
    /// do not understand, so a known option with the wrong length becomes
    /// [`PcpOption::Other`], repeats are kept, and MAP or PEER data or
    /// options that do not read leave the operation as
    /// [`Operation::Other`]. Nonzero body reserved bytes or option padding
    /// also use that variant so error replies can copy the request body.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Response, Error> {
        if b.len() < 4 {
            return Err(Error::Short(b.len()));
        }
        if b[1] & RESPONSE_FLAG == 0 {
            return Err(Error::WrongDirection);
        }
        if b[0] != VERSION {
            return Err(Error::Version(b[0]));
        }
        check_length(b)?;
        let op = b[1] & !RESPONSE_FLAG;
        let body = &b[HEADER_LEN..];
        let (operation, options) = response_body(op, body);
        let mut reserved = [0; 12];
        reserved.copy_from_slice(&b[12..24]);
        Ok(Response {
            result: ResultCode::from_code(b[3]),
            lifetime: be32(b, 4).ok_or(Error::Short(b.len()))?,
            epoch: be32(b, 8).ok_or(Error::Short(b.len()))?,
            reserved,
            operation,
            options,
        })
    }

    /// Appends the response. Refuses oversized fields, unaligned opaque data and
    /// variants that would change. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::with_capacity(HEADER_LEN + PEER_LEN);
        out.extend_from_slice(&[
            VERSION,
            self.operation.opcode() | RESPONSE_FLAG,
            0,
            self.result.code(),
        ]);
        out.extend_from_slice(&self.lifetime.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.reserved);
        write_operation(&mut out, &self.operation)?;
        write_options(&mut out, &self.options, false)?;
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for NatPmpRequest {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one request, refusing bytes past a fixed opcode body.
    /// Refuses incomplete headers or bodies, responses and oversized input.
    fn parse(b: &[u8]) -> Result<NatPmpRequest, Error> {
        if b.len() < 2 {
            return Err(Error::NatPmpShort(b.len()));
        }
        if b.len() > MAX_MESSAGE {
            return Err(Error::NatPmpTooLong(b.len()));
        }
        if b[0] != NAT_PMP_VERSION {
            return Err(Error::NatPmpVersion(b[0]));
        }
        let op = b[1];
        if op & RESPONSE_FLAG != 0 {
            return Err(Error::NatPmpWrongDirection);
        }
        Ok(match op {
            nat_pmp_opcode::EXTERNAL_ADDRESS => {
                if b.len() > 2 {
                    return Err(Error::NatPmpTrailing);
                }
                NatPmpRequest::ExternalAddress
            }
            nat_pmp_opcode::MAP_UDP | nat_pmp_opcode::MAP_TCP => {
                if b.len() < 12 {
                    return Err(Error::NatPmpShort(b.len()));
                }
                if b.len() > 12 {
                    return Err(Error::NatPmpTrailing);
                }
                let protocol = if op == nat_pmp_opcode::MAP_UDP {
                    NatPmpProtocol::Udp
                } else {
                    NatPmpProtocol::Tcp
                };
                NatPmpRequest::Map {
                    protocol,
                    internal_port: be16(b, 4).ok_or(Error::NatPmpShort(b.len()))?,
                    external_port: be16(b, 6).ok_or(Error::NatPmpShort(b.len()))?,
                    lifetime: be32(b, 8).ok_or(Error::NatPmpShort(b.len()))?,
                }
            }
            _ => NatPmpRequest::Unsupported {
                opcode: op,
                data: b[2..].to_vec(),
            },
        })
    }

    /// Appends the request. Refuses oversized opaque data and unsupported opcode
    /// values that name defined requests or set the response bit. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let out = match self {
            NatPmpRequest::ExternalAddress => {
                vec![NAT_PMP_VERSION, nat_pmp_opcode::EXTERNAL_ADDRESS]
            }
            NatPmpRequest::Map {
                protocol,
                internal_port,
                external_port,
                lifetime,
            } => {
                let mut out = vec![NAT_PMP_VERSION, protocol.opcode(), 0, 0];
                out.extend_from_slice(&internal_port.to_be_bytes());
                out.extend_from_slice(&external_port.to_be_bytes());
                out.extend_from_slice(&lifetime.to_be_bytes());
                out
            }
            NatPmpRequest::Unsupported { opcode, data } => {
                if *opcode <= nat_pmp_opcode::MAP_TCP || *opcode >= RESPONSE_FLAG {
                    return Err(Error::Unwritable);
                }
                let o = *opcode;
                let mut out = vec![NAT_PMP_VERSION, o];
                if data.len() > MAX_MESSAGE - 2 {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
                out
            }
        };
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for NatPmpResponse {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a response. Bytes past a fixed opcode body are refused.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<NatPmpResponse, Error> {
        if b.len() < 4 {
            return Err(Error::NatPmpShort(b.len()));
        }
        if b.len() > MAX_MESSAGE {
            return Err(Error::NatPmpTooLong(b.len()));
        }
        if b[0] != NAT_PMP_VERSION {
            return Err(Error::NatPmpVersion(b[0]));
        }
        let (op, result) = (
            b[1],
            NatPmpResult::from_code(be16(b, 2).ok_or(Error::NatPmpShort(b.len()))?),
        );
        let need = |n: usize| {
            if b.len() < n {
                Err(Error::NatPmpShort(b.len()))
            } else if b.len() > n {
                Err(Error::NatPmpTrailing)
            } else {
                Ok(())
            }
        };
        Ok(match op {
            0 if result == NatPmpResult::UnsupportedVersion => {
                need(8)?;
                NatPmpResponse::UnsupportedVersion {
                    epoch: be32(b, 4).ok_or(Error::NatPmpShort(b.len()))?,
                }
            }
            0..=127 => return Err(Error::NatPmpWrongDirection),
            128 => {
                need(12)?;
                NatPmpResponse::ExternalAddress {
                    result,
                    epoch: be32(b, 4).ok_or(Error::NatPmpShort(b.len()))?,
                    address: ip4(&b[8..12]),
                }
            }
            129 | 130 => {
                need(16)?;
                let protocol = if op == 129 {
                    NatPmpProtocol::Udp
                } else {
                    NatPmpProtocol::Tcp
                };
                NatPmpResponse::Map {
                    protocol,
                    result,
                    epoch: be32(b, 4).ok_or(Error::NatPmpShort(b.len()))?,
                    internal_port: be16(b, 8).ok_or(Error::NatPmpShort(b.len()))?,
                    external_port: be16(b, 10).ok_or(Error::NatPmpShort(b.len()))?,
                    lifetime: be32(b, 12).ok_or(Error::NatPmpShort(b.len()))?,
                }
            }
            _ => NatPmpResponse::Other {
                opcode: op & !RESPONSE_FLAG,
                result,
                data: b[4..].to_vec(),
            },
        })
    }

    /// Appends the response. Refuses oversized opaque data and variants that would
    /// read as a different response. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let out = match self {
            NatPmpResponse::ExternalAddress {
                result,
                epoch,
                address,
            } => {
                let mut out = vec![NAT_PMP_VERSION, 128];
                out.extend_from_slice(&result.code().to_be_bytes());
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&address.octets());
                out
            }
            NatPmpResponse::Map {
                protocol,
                result,
                epoch,
                internal_port,
                external_port,
                lifetime,
            } => {
                let mut out = vec![NAT_PMP_VERSION, protocol.opcode() | RESPONSE_FLAG];
                out.extend_from_slice(&result.code().to_be_bytes());
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&internal_port.to_be_bytes());
                out.extend_from_slice(&external_port.to_be_bytes());
                out.extend_from_slice(&lifetime.to_be_bytes());
                out
            }
            NatPmpResponse::UnsupportedVersion { epoch } => {
                let mut out = vec![NAT_PMP_VERSION, 0, 0, 1];
                out.extend_from_slice(&epoch.to_be_bytes());
                out
            }
            NatPmpResponse::Other {
                opcode,
                result,
                data,
            } => {
                if *opcode <= 2 || *opcode >= RESPONSE_FLAG {
                    return Err(Error::Unwritable);
                }
                let op = opcode | RESPONSE_FLAG;
                let mut out = vec![NAT_PMP_VERSION, op];
                out.extend_from_slice(&result.code().to_be_bytes());
                if data.len() > MAX_MESSAGE - 4 {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
                out
            }
        };
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

/// A complete gateway response in either supported protocol.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Reply {
    /// A PCP response.
    Pcp(Response),
    /// A NAT-PMP response.
    NatPmp(NatPmpResponse),
}

impl Wire for Reply {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one response. Refuses malformed lengths, versions and directions.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.first() == Some(&NAT_PMP_VERSION) {
            NatPmpResponse::parse(b).map(Self::NatPmp)
        } else {
            Response::parse(b).map(Self::Pcp)
        }
    }

    /// Appends the complete response. Refuses values the selected protocol cannot preserve.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Pcp(value) => value.write(out),
            Self::NatPmp(value) => value.write(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::mutate;

    const LAPTOP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

    fn laptop() -> IpAddr {
        IpAddr::V4(LAPTOP)
    }

    fn map_request() -> Request {
        Request {
            lifetime: 7200,
            client: LAPTOP.to_ipv6_mapped(),
            operation: Operation::Map(Map {
                nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                protocol: 6,
                internal_port: 8080,
                external_port: 8080,
                external_address: Ipv6Addr::UNSPECIFIED,
            }),
            options: vec![],
        }
    }

    fn peer_request() -> Request {
        Request {
            lifetime: 600,
            client: LAPTOP.to_ipv6_mapped(),
            operation: Operation::Peer(Peer {
                nonce: [9; 12],
                protocol: 17,
                internal_port: 5000,
                external_port: 0,
                external_address: Ipv6Addr::UNSPECIFIED,
                remote_port: 443,
                remote_address: Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped(),
            }),
            options: vec![],
        }
    }

    fn filter(prefix_length: u8) -> PcpOption {
        PcpOption::Filter {
            prefix_length,
            remote_port: 0,
            remote_address: Ipv4Addr::new(198, 51, 100, 0).to_ipv6_mapped(),
        }
    }

    /// The request with these options.
    fn with(mut r: Request, options: Vec<PcpOption>) -> Request {
        r.options = options;
        r
    }

    // RFC 6887 figures 2, 9 and 13: a MAP request, byte by byte.
    #[test]
    fn review_nat_pmp_request_trailing() {
        for mut bytes in [
            vec![0, 0],
            vec![0, 1, 0, 0, 0, 1, 0, 2, 0, 0, 0, 3],
            vec![0, 2, 0, 0, 0, 1, 0, 2, 0, 0, 0, 3],
        ] {
            assert!(NatPmpRequest::parse(&bytes).is_ok());
            bytes.push(0);
            assert_eq!(NatPmpRequest::parse(&bytes), Err(Error::NatPmpTrailing));
        }
    }

    #[test]
    fn map_request_layout() {
        let mut r = map_request();
        r.options = vec![PcpOption::ThirdParty(
            Ipv4Addr::new(192, 168, 1, 30).to_ipv6_mapped(),
        )];
        let b = r.to_bytes().unwrap();
        let mut want = vec![2, 1, 0, 0, 0, 0, 0x1c, 0x20];
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 20]);
        want.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        want.extend_from_slice(&[6, 0, 0, 0, 0x1f, 0x90, 0x1f, 0x90]);
        want.extend_from_slice(&[0; 16]);
        want.extend_from_slice(&[
            1, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 30,
        ]);
        assert_eq!(b, want);
        assert_eq!(b.len(), HEADER_LEN + MAP_LEN + 20);
        assert_eq!(Request::parse(&b), Ok(r));
    }

    // RFC 6887 figures 3 and 10: a MAP response.
    #[test]
    fn map_response_layout() {
        let req = map_request();
        let mut resp = req.reply(ResultCode::Success, 3600, 77);
        let Operation::Map(m) = &mut resp.operation else {
            panic!()
        };
        m.external_address = Ipv4Addr::new(203, 0, 113, 5).to_ipv6_mapped();
        let b = resp.to_bytes().unwrap();
        assert_eq!(&b[..12], &[2, 0x81, 0, 0, 0, 0, 0x0e, 0x10, 0, 0, 0, 77]);
        assert_eq!(&b[12..24], &[0; 12]);
        assert_eq!(&b[24 + 32..24 + 36], &[203, 0, 113, 5]);
        assert_eq!(Response::parse(&b), Ok(resp));
    }

    // RFC 6887 figure 11: a PEER request.
    #[test]
    fn peer_round_trip() {
        let r = peer_request();
        let b = r.to_bytes().unwrap();
        assert_eq!(b.len(), HEADER_LEN + PEER_LEN);
        assert_eq!(b[1], opcode::PEER);
        assert_eq!(&b[24 + 36..24 + 40], &[0x01, 0xbb, 0, 0]);
        assert_eq!(&b[24 + 52..24 + 56], &[198, 51, 100, 7]);
        assert_eq!(Request::parse(&b), Ok(r.clone()));
        let resp = r.reply(ResultCode::Success, 600, 5);
        assert_eq!(Response::parse(&resp.to_bytes().unwrap()), Ok(resp));
        assert_eq!(r.check(laptop()), Ok(()));
    }

    // RFC 6887 section 14.1: ANNOUNCE has no data.
    #[test]
    fn announce() {
        let r = Request {
            lifetime: 0,
            client: LAPTOP.to_ipv6_mapped(),
            operation: Operation::Announce,
            options: vec![],
        };
        let b = r.to_bytes().unwrap();
        assert_eq!(b.len(), HEADER_LEN);
        assert_eq!(&b[..4], &[2, 0, 0, 0]);
        let Incoming::Pcp(got) = receive(&b, Speaks::Pcp, laptop(), 3) else {
            panic!()
        };
        assert_eq!(got, r);
        let a = Response::announce(0).to_bytes().unwrap();
        assert_eq!(a.len(), HEADER_LEN);
        assert_eq!(&a[..4], &[2, 0x80, 0, 0]);
        assert_eq!(Response::parse(&a), Ok(Response::announce(0)));
        // Options may follow ANNOUNCE in future, so they are read.
        let r = with(
            r,
            vec![PcpOption::Other {
                code: 200,
                data: vec![1, 2, 3],
            }],
        );
        assert_eq!(Request::parse(&r.to_bytes().unwrap()), Ok(r));
    }

    // RFC 6887 sections 13.2 and 13.3.
    #[test]
    fn options_layout() {
        let r = with(map_request(), vec![PcpOption::PreferFailure, filter(120)]);
        let b = r.to_bytes().unwrap();
        let opts = &b[HEADER_LEN + MAP_LEN..];
        assert_eq!(&opts[..4], &[2, 0, 0, 0]);
        assert_eq!(&opts[4..12], &[3, 0, 0, 20, 0, 120, 0, 0]);
        assert_eq!(opts.len(), 4 + 24);
        assert_eq!(Request::parse(&b), Ok(r.clone()));
        assert_eq!(r.check(laptop()), Ok(()));
        // An odd-length option is padded, and its length is the real one.
        let r = with(
            map_request(),
            vec![PcpOption::Other {
                code: 130,
                data: vec![7; 5],
            }],
        );
        let b = r.to_bytes().unwrap();
        assert_eq!(
            &b[HEADER_LEN + MAP_LEN..],
            &[130, 0, 0, 5, 7, 7, 7, 7, 7, 0, 0, 0]
        );
        assert_eq!(Request::parse(&b), Ok(r));
    }

    #[test]
    fn request_errors() {
        let good = map_request().to_bytes().unwrap();
        assert_eq!(Request::parse(&[2]), Err(Error::Short(1)));
        let mut b = good.clone();
        b[1] |= 0x80;
        assert_eq!(Request::parse(&b), Err(Error::WrongDirection));
        let mut b = good.clone();
        b[0] = 3;
        assert_eq!(Request::parse(&b), Err(Error::Version(3)));
        assert_eq!(Request::parse(&[0, 0]), Err(Error::Version(0)));
        assert_eq!(Request::parse(&good[..20]), Err(Error::Short(20)));
        let mut b = good.clone();
        b.resize(1104, 0);
        assert_eq!(Request::parse(&b), Err(Error::TooLong(1104)));
        assert_eq!(Request::parse(&good[..58]), Err(Error::Unaligned(58)));
        assert_eq!(
            Request::parse(&good[..56]),
            Err(Error::OpcodeData { opcode: 1, len: 32 })
        );
        let peer = peer_request().to_bytes().unwrap();
        assert_eq!(
            Request::parse(&peer[..60]),
            Err(Error::OpcodeData { opcode: 2, len: 36 })
        );
        // An option header with no room for its data.
        let mut b = good.clone();
        b.extend_from_slice(&[1, 0, 0, 16]);
        assert_eq!(Request::parse(&b), Err(Error::MalformedOption));
        // A known option with the wrong length.
        let mut b = good.clone();
        b.extend_from_slice(&[2, 0, 0, 4, 0, 0, 0, 0]);
        assert_eq!(Request::parse(&b), Err(Error::MalformedOption));
        // A length that needs padding past the end.
        let mut b = good.clone();
        b.extend_from_slice(&[200, 0, 0, 5, 0, 0, 0, 0]);
        assert_eq!(Request::parse(&b), Err(Error::MalformedOption));
        // PREFER_FAILURE twice.
        let mut b = good.clone();
        b.extend_from_slice(&[2, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(Request::parse(&b), Err(Error::DuplicateOption(2)));
        let mut b = good.clone();
        let third = [1, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        b.extend_from_slice(&third);
        b.extend_from_slice(&third);
        assert_eq!(Request::parse(&b), Err(Error::DuplicateOption(1)));
        // FILTER may repeat.
        let r = with(map_request(), vec![filter(0), filter(120)]);
        assert_eq!(Request::parse(&r.to_bytes().unwrap()), Ok(r));
        // Each error's result code.
        assert_eq!(Error::Short(3).result_code(), None);
        assert_eq!(Error::WrongDirection.result_code(), None);
        assert_eq!(
            Error::Version(1).result_code(),
            Some(ResultCode::UnsuppVersion)
        );
        assert_eq!(
            Error::Unaligned(25).result_code(),
            Some(ResultCode::MalformedRequest)
        );
        assert_eq!(
            Error::DuplicateOption(1).result_code(),
            Some(ResultCode::MalformedOption)
        );
        for e in [
            Error::Short(1),
            Error::OpcodeData { opcode: 1, len: 0 },
            Error::MalformedOption,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn response_errors() {
        let good = map_request()
            .reply(ResultCode::Success, 1, 2)
            .to_bytes()
            .unwrap();
        assert_eq!(Response::parse(&good[..3]), Err(Error::Short(3)));
        assert_eq!(
            Response::parse(&map_request().to_bytes().unwrap()),
            Err(Error::WrongDirection)
        );
        let mut b = good.clone();
        b[0] = 1;
        assert_eq!(Response::parse(&b), Err(Error::Version(1)));
        assert_eq!(Response::parse(&good[..20]), Err(Error::Short(20)));
        assert_eq!(Response::parse(&good[..30]), Err(Error::Unaligned(30)));
        let mut b = good.clone();
        b.resize(1200, 0);
        assert_eq!(Response::parse(&b), Err(Error::TooLong(1200)));
        // Short MAP data in a response is kept, not refused.
        let r = Response::parse(&good[..32]).unwrap();
        assert_eq!(
            r.operation,
            Operation::Other {
                opcode: 1,
                data: good[24..32].to_vec()
            }
        );
        assert_eq!(Response::parse(&r.to_bytes().unwrap()), Ok(r));
        // A known option with a wrong length becomes Other, and repeats stay.
        let mut b = good.clone();
        b.extend_from_slice(&[2, 0, 0, 4, 9, 9, 9, 9, 2, 0, 0, 0, 2, 0, 0, 0]);
        let r = Response::parse(&b).unwrap();
        assert_eq!(
            r.options,
            [
                PcpOption::Other {
                    code: 2,
                    data: vec![9; 4]
                },
                PcpOption::PreferFailure,
                PcpOption::PreferFailure
            ]
        );
        assert_eq!(r.to_bytes().unwrap(), b);
    }

    #[test]
    fn checks() {
        let ok = |r: &Request| r.check(laptop());
        assert_eq!(ok(&map_request()), Ok(()));
        // ADDRESS_MISMATCH.
        assert_eq!(
            map_request().check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Err(ResultCode::AddressMismatch)
        );
        // IPv6 sources compare directly.
        let v6: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut r = map_request();
        r.client = v6;
        assert_eq!(r.check(IpAddr::V6(v6)), Ok(()));
        // MAP with protocol 0 and a port.
        let mut r = map_request();
        let Operation::Map(m) = &mut r.operation else {
            panic!()
        };
        m.protocol = 0;
        assert_eq!(ok(&r), Err(ResultCode::MalformedRequest));
        // PEER with zeros it may not have.
        let zero: [fn(&mut Peer); 3] = [
            |p| p.protocol = 0,
            |p| p.internal_port = 0,
            |p| p.remote_port = 0,
        ];
        for f in zero {
            let mut r = peer_request();
            let Operation::Peer(p) = &mut r.operation else {
                panic!()
            };
            f(p);
            assert_eq!(ok(&r), Err(ResultCode::MalformedRequest));
        }
        // PREFER_FAILURE with PEER.
        assert_eq!(
            ok(&with(peer_request(), vec![PcpOption::PreferFailure])),
            Err(ResultCode::MalformedRequest)
        );
        // THIRD_PARTY naming the sender.
        let me = PcpOption::ThirdParty(LAPTOP.to_ipv6_mapped());
        assert_eq!(
            ok(&with(map_request(), vec![me])),
            Err(ResultCode::MalformedRequest)
        );
        let other = PcpOption::ThirdParty(Ipv4Addr::new(192, 168, 1, 2).to_ipv6_mapped());
        assert_eq!(ok(&with(peer_request(), vec![other.clone()])), Ok(()));
        // PREFER_FAILURE with no suggested port, or on a delete.
        let mut r = with(map_request(), vec![PcpOption::PreferFailure]);
        assert_eq!(ok(&r), Ok(()));
        r.lifetime = 0;
        assert_eq!(ok(&r), Err(ResultCode::MalformedOption));
        let mut r = with(map_request(), vec![PcpOption::PreferFailure]);
        let Operation::Map(m) = &mut r.operation else {
            panic!()
        };
        m.external_port = 0;
        assert_eq!(ok(&r), Err(ResultCode::MalformedOption));
        // FILTER prefixes: IPv4-mapped needs 96..=128, or 0.
        assert_eq!(ok(&with(map_request(), vec![filter(0)])), Ok(()));
        assert_eq!(
            ok(&with(map_request(), vec![filter(95)])),
            Err(ResultCode::MalformedOption)
        );
        assert_eq!(
            ok(&with(map_request(), vec![filter(129)])),
            Err(ResultCode::MalformedOption)
        );
        let v6_filter = PcpOption::Filter {
            prefix_length: 48,
            remote_port: 1,
            remote_address: v6,
        };
        assert_eq!(ok(&with(map_request(), vec![v6_filter])), Ok(()));
        let mut r = with(map_request(), vec![filter(120)]);
        r.lifetime = 0;
        assert_eq!(ok(&r), Err(ResultCode::MalformedOption));
        // FILTER with PEER, and MAP options with ANNOUNCE.
        assert_eq!(
            ok(&with(peer_request(), vec![filter(120)])),
            Err(ResultCode::MalformedOption)
        );
        let announce = Request {
            lifetime: 0,
            client: LAPTOP.to_ipv6_mapped(),
            operation: Operation::Announce,
            options: vec![other],
        };
        assert_eq!(ok(&announce), Err(ResultCode::MalformedOption));
        // Unknown options: mandatory ones refuse, optional ones do not.
        let mandatory = PcpOption::Other {
            code: 4,
            data: vec![],
        };
        assert_eq!(
            ok(&with(map_request(), vec![mandatory])),
            Err(ResultCode::UnsuppOption)
        );
        let optional = PcpOption::Other {
            code: 129,
            data: vec![],
        };
        assert!(optional.is_optional());
        assert_eq!(ok(&with(map_request(), vec![optional])), Ok(()));
    }

    // RFC 6887 section 11.3: protocol 0 with a port is malformed only when
    // the lifetime is not zero. A delete may carry any internal port.
    #[test]
    fn map_delete_with_protocol_zero() {
        let mut r = map_request();
        r.lifetime = 0;
        let Operation::Map(m) = &mut r.operation else {
            panic!()
        };
        m.protocol = 0;
        assert_eq!(r.check(laptop()), Ok(()));
    }

    // RFC 6887 section 8.2: the address check comes before the opcode and
    // its options are processed.
    #[test]
    fn address_mismatch_comes_first() {
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut r = map_request();
        let Operation::Map(m) = &mut r.operation else {
            panic!()
        };
        m.protocol = 0;
        assert_eq!(r.check(other), Err(ResultCode::AddressMismatch));
        let r = with(peer_request(), vec![PcpOption::PreferFailure]);
        assert_eq!(r.check(other), Err(ResultCode::AddressMismatch));
        // An unknown opcode from the wrong address.
        let r = Request {
            lifetime: 5,
            client: LAPTOP.to_ipv6_mapped(),
            operation: Operation::Other {
                opcode: 99,
                data: vec![],
            },
            options: vec![],
        };
        assert_eq!(r.check(laptop()), Err(ResultCode::UnsuppOpcode));
        assert_eq!(r.check(other), Err(ResultCode::AddressMismatch));
        let Incoming::Reply(reply) = receive(&r.to_bytes().unwrap(), Speaks::Both, other, 9) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(
            Response::parse(&reply).unwrap().result,
            ResultCode::AddressMismatch
        );
        // A malformed option from the wrong address.
        let mut b = map_request().to_bytes().unwrap();
        b.extend_from_slice(&[3, 0, 0, 4, 0, 0, 0, 0]);
        let Incoming::Reply(reply) = receive(&b, Speaks::Both, other, 9) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        let resp = Response::parse(&reply).unwrap();
        assert_eq!(resp.result, ResultCode::AddressMismatch);
        assert_eq!(&reply[12..24], &b[12..24]);
        // From the right address it is still MALFORMED_OPTION.
        let Incoming::Reply(reply) = receive(&b, Speaks::Both, laptop(), 9) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(
            Response::parse(&reply).unwrap().result,
            ResultCode::MalformedOption
        );
    }

    // RFC 6887 section 9, step 5: a version the client does not speak
    // sends it to the next lower one it does, and below NAT-PMP there is
    // none.
    #[test]
    fn nat_pmp_client_offered_unknown_version_gives_up() {
        let u = UnsupportedVersion {
            version: 5,
            lifetime: Some(60),
        };
        assert_eq!(
            u.next_step(NAT_PMP_VERSION),
            VersionChoice::GiveUp { retry_after: 60 }
        );
        assert_eq!(u.next_step(3), VersionChoice::Pcp);
        let u = UnsupportedVersion {
            version: VERSION,
            lifetime: Some(60),
        };
        assert_eq!(u.next_step(NAT_PMP_VERSION), VersionChoice::Pcp);
    }

    #[test]
    fn result_codes() {
        for c in 0..=255u8 {
            assert_eq!(ResultCode::from_code(c).code(), c);
        }
        for c in [0u16, 1, 2, 3, 4, 5, 6, 999, 65535] {
            assert_eq!(NatPmpResult::from_code(c).code(), c);
        }
        assert_eq!(ResultCode::NoResources.error_lifetime(), 30);
        assert_eq!(ResultCode::NotAuthorized.error_lifetime(), 1800);
        assert_eq!(ResultCode::Success.error_lifetime(), 0);
    }

    #[test]
    fn error_reply_copies_map_and_option_reserved_bytes() {
        let mut request = map_request().to_bytes().unwrap();
        request[HEADER_LEN + 13..HEADER_LEN + 16].copy_from_slice(&[1, 2, 3]);
        request.extend_from_slice(&[2, 0x7f, 0, 0]);
        let reply = error_reply(&request, ResultCode::MalformedRequest, 60, 9);
        assert_eq!(
            reply.to_bytes().unwrap()[HEADER_LEN..],
            request[HEADER_LEN..]
        );
        contract::check_wire_value(&reply);
        contract::check_wire::<Response>(&reply.to_bytes().unwrap());
    }

    #[test]
    fn server_replies() {
        // A short header keeps the address bytes that arrived and pads the rest.
        let short = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7];
        let reply = error_reply(&short, ResultCode::UnsuppVersion, 1800, 9);
        assert_eq!(reply.reserved, [9, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        contract::check_wire_value(&reply);
        // Under 2 bytes, and responses: dropped.
        assert_eq!(receive(&[2], Speaks::Both, laptop(), 0), Incoming::Ignore);
        let resp = map_request()
            .reply(ResultCode::Success, 0, 0)
            .to_bytes()
            .unwrap();
        assert_eq!(receive(&resp, Speaks::Both, laptop(), 0), Incoming::Ignore);
        // A version 2 message under 24 bytes: dropped.
        assert_eq!(
            receive(&[2, 1, 0, 0], Speaks::Both, laptop(), 0),
            Incoming::Ignore
        );
        // A version this server does not speak, with the client address
        // tail in the reserved bits.
        let mut b = map_request().to_bytes().unwrap();
        b[0] = 3;
        let Incoming::Reply(reply) = receive(&b, Speaks::Pcp, laptop(), 9) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(reply.len(), b.len());
        assert_eq!(&reply[..4], &[2, 0x81, 0, 1]);
        assert_eq!(&reply[12..24], &b[12..24]);
        let r = Response::parse(&reply).unwrap();
        assert_eq!(
            (r.result, r.lifetime, r.epoch),
            (ResultCode::UnsuppVersion, 1800, 9)
        );
        // Malformed: unaligned.
        let mut b = map_request().to_bytes().unwrap();
        b.push(0);
        let Incoming::Reply(reply) = receive(&b, Speaks::Both, laptop(), 9) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(reply.len(), 64);
        assert_eq!(
            Response::parse(&reply).unwrap().result,
            ResultCode::MalformedRequest
        );
        // Too long: the reply is cut to 1100 bytes.
        let mut b = map_request().to_bytes().unwrap();
        b.resize(1500, 0);
        let Incoming::Reply(reply) = receive(&b, Speaks::Both, laptop(), 9) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(reply.len(), MAX_MESSAGE);
        assert!(Response::parse(&reply).is_ok());
        // Malformed option.
        let mut b = map_request().to_bytes().unwrap();
        b.extend_from_slice(&[3, 0, 0, 4, 0, 0, 0, 0]);
        let Incoming::Reply(reply) = receive(&b, Speaks::Both, laptop(), 9) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(
            Response::parse(&reply).unwrap().result,
            ResultCode::MalformedOption
        );
        // Unknown opcode: the payload comes back as is.
        let r = Request {
            lifetime: 5,
            client: LAPTOP.to_ipv6_mapped(),
            operation: Operation::Other {
                opcode: 99,
                data: vec![1, 2, 3, 4],
            },
            options: vec![],
        };
        let Incoming::Reply(reply) = receive(&r.to_bytes().unwrap(), Speaks::Both, laptop(), 9)
        else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        let resp = Response::parse(&reply).unwrap();
        assert_eq!(resp.result, ResultCode::UnsuppOpcode);
        assert_eq!(resp.operation, r.operation);
        // A failed check.
        let r = with(
            map_request(),
            vec![PcpOption::Other {
                code: 50,
                data: vec![],
            }],
        );
        let Incoming::Reply(reply) = receive(&r.to_bytes().unwrap(), Speaks::Both, laptop(), 9)
        else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        let resp = Response::parse(&reply).unwrap();
        assert_eq!(resp.result, ResultCode::UnsuppOption);
        assert_eq!(resp.options, r.options);
    }

    // RFC 6886 section 3.2 and 3.3 examples, and RFC 6887 appendix A.
    #[test]
    fn nat_pmp() {
        assert_eq!(
            NatPmpRequest::parse(&[0, 0]),
            Ok(NatPmpRequest::ExternalAddress)
        );
        let resp = NatPmpResponse::ExternalAddress {
            result: NatPmpResult::Success,
            epoch: 300,
            address: Ipv4Addr::new(203, 0, 113, 5),
        };
        let b = resp.to_bytes().unwrap();
        assert_eq!(b, [0, 128, 0, 0, 0, 0, 1, 44, 203, 0, 113, 5]);
        assert_eq!(NatPmpResponse::parse(&b), Ok(resp));
        let req = [0, 2, 0, 0, 0x1f, 0x90, 0, 80, 0, 0, 0x1c, 0x20];
        let map = NatPmpRequest::Map {
            protocol: NatPmpProtocol::Tcp,
            internal_port: 8080,
            external_port: 80,
            lifetime: 7200,
        };
        assert_eq!(NatPmpRequest::parse(&req), Ok(map.clone()));
        assert_eq!(map.to_bytes().unwrap(), req);
        let resp = NatPmpResponse::Map {
            protocol: NatPmpProtocol::Tcp,
            result: NatPmpResult::Success,
            epoch: 300,
            internal_port: 8080,
            external_port: 80,
            lifetime: 7200,
        };
        let b = resp.to_bytes().unwrap();
        assert_eq!(
            b,
            [
                0, 130, 0, 0, 0, 0, 1, 44, 0x1f, 0x90, 0, 80, 0, 0, 0x1c, 0x20
            ]
        );
        assert_eq!(NatPmpResponse::parse(&b), Ok(resp));
        // Refusals keep the internal port and zero the rest.
        let refused = map.refuse(NatPmpResult::OutOfResources, 1);
        assert_eq!(
            refused.to_bytes().unwrap(),
            [0, 130, 0, 4, 0, 0, 0, 1, 0x1f, 0x90, 0, 0, 0, 0, 0, 0]
        );
        let refused = NatPmpRequest::ExternalAddress.refuse(NatPmpResult::NetworkFailure, 1);
        assert_eq!(
            refused.to_bytes().unwrap(),
            [0, 128, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        // Through the server.
        assert_eq!(
            receive(&req, Speaks::Both, laptop(), 0),
            Incoming::NatPmp(map.clone())
        );
        assert_eq!(
            receive(&req, Speaks::NatPmp, laptop(), 0),
            Incoming::NatPmp(map)
        );
        assert_eq!(
            receive(&[0, 128, 0, 0], Speaks::NatPmp, laptop(), 0),
            Incoming::Ignore
        );
        assert_eq!(
            receive(&[0, 1, 0, 0], Speaks::Both, laptop(), 0),
            Incoming::Ignore
        );
        // Unsupported opcode: the request comes back, top bit set, result 5.
        let Incoming::Reply(reply) = receive(&[0, 9, 0xaa, 0xbb, 1, 2], Speaks::Both, laptop(), 0)
        else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(reply, [0, 0x89, 0, 5, 1, 2]);
        assert_eq!(
            NatPmpResponse::parse(&reply),
            Ok(NatPmpResponse::Other {
                opcode: 9,
                result: NatPmpResult::UnsupportedOpcode,
                data: vec![1, 2]
            })
        );
        let Incoming::Reply(reply) = receive(&[0, 9], Speaks::Both, laptop(), 0) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(reply, [0, 0x89, 0, 5]);
        // A NAT-PMP-only server answers PCP with Unsupported Version.
        let Incoming::Reply(reply) = receive(
            &map_request().to_bytes().unwrap(),
            Speaks::NatPmp,
            laptop(),
            7,
        ) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(reply, [0, 0, 0, 1, 0, 0, 0, 7]);
        assert_eq!(
            NatPmpResponse::parse(&reply),
            Ok(NatPmpResponse::UnsupportedVersion { epoch: 7 })
        );
        // A PCP-only server answers NAT-PMP with a PCP UNSUPP_VERSION whose
        // first four bytes read as result 1 to NAT-PMP.
        let Incoming::Reply(reply) = receive(&[0, 0], Speaks::Pcp, laptop(), 7) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(&reply[..4], &[2, 0x80, 0, 1]);
        assert_eq!(reply.len(), HEADER_LEN);
        assert_eq!(
            Response::parse(&reply).unwrap().result,
            ResultCode::UnsuppVersion
        );
    }

    #[test]
    fn nat_pmp_errors() {
        assert_eq!(NatPmpRequest::parse(&[0]), Err(Error::NatPmpShort(1)));
        assert_eq!(NatPmpRequest::parse(&[2, 1]), Err(Error::NatPmpVersion(2)));
        assert_eq!(
            NatPmpRequest::parse(&[0, 128]),
            Err(Error::NatPmpWrongDirection)
        );
        assert_eq!(
            NatPmpRequest::parse(&[0, 1, 0, 0]),
            Err(Error::NatPmpShort(4))
        );
        assert_eq!(
            NatPmpRequest::parse(&[0; 1101]),
            Err(Error::NatPmpTooLong(1101))
        );
        assert_eq!(
            NatPmpResponse::parse(&[0, 128, 0]),
            Err(Error::NatPmpShort(3))
        );
        assert_eq!(
            NatPmpResponse::parse(&[0; 1101]),
            Err(Error::NatPmpTooLong(1101))
        );
        assert_eq!(
            NatPmpResponse::parse(&[2, 128, 0, 0]),
            Err(Error::NatPmpVersion(2))
        );
        assert_eq!(
            NatPmpResponse::parse(&[0, 1, 0, 0]),
            Err(Error::NatPmpWrongDirection)
        );
        assert_eq!(
            NatPmpResponse::parse(&[0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::NatPmpWrongDirection)
        );
        assert_eq!(
            NatPmpResponse::parse(&[0, 0, 0, 1, 0, 0]),
            Err(Error::NatPmpShort(6))
        );
        assert_eq!(
            NatPmpResponse::parse(&[0, 128, 0, 0, 0, 0, 0, 0]),
            Err(Error::NatPmpShort(8))
        );
        assert_eq!(
            NatPmpResponse::parse(&[0, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::NatPmpShort(12))
        );
        for e in [
            Error::NatPmpShort(1),
            Error::NatPmpTooLong(2),
            Error::NatPmpVersion(3),
            Error::NatPmpWrongDirection,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn version_negotiation() {
        // A PCP server that does not speak version 3 offers 2.
        let mut b = map_request().to_bytes().unwrap();
        b[0] = 3;
        let Incoming::Reply(reply) = receive(&b, Speaks::Pcp, laptop(), 0) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        let u = unsupported_version(&reply).unwrap();
        assert_eq!(
            u,
            UnsupportedVersion {
                version: 2,
                lifetime: Some(1800)
            }
        );
        assert_eq!(u.next_step(3), VersionChoice::Pcp);
        // A NAT-PMP server answers a PCP client, which falls back.
        let Incoming::Reply(reply) = receive(
            &map_request().to_bytes().unwrap(),
            Speaks::NatPmp,
            laptop(),
            0,
        ) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        let u = unsupported_version(&reply).unwrap();
        assert_eq!(
            u,
            UnsupportedVersion {
                version: 0,
                lifetime: None
            }
        );
        assert_eq!(u.next_step(VERSION), VersionChoice::NatPmp);
        // The form some gateways send: 128 plus the opcode.
        assert_eq!(
            unsupported_version(&[0, 129, 0, 1, 0, 0, 0, 0]).map(|u| u.version),
            Some(0)
        );
        // A PCP server answers a NAT-PMP client, which moves up to PCP.
        let Incoming::Reply(reply) = receive(&[0, 0], Speaks::Pcp, laptop(), 0) else {
            panic!()
        };
        let reply = reply.to_bytes().unwrap();
        assert_eq!(
            unsupported_version(&reply)
                .unwrap()
                .next_step(NAT_PMP_VERSION),
            VersionChoice::Pcp
        );
        // A server offering a version the client cannot use: give up.
        let u = UnsupportedVersion {
            version: 5,
            lifetime: Some(60),
        };
        assert_eq!(
            u.next_step(VERSION),
            VersionChoice::GiveUp { retry_after: 60 }
        );
        let u = UnsupportedVersion {
            version: 5,
            lifetime: Some(99999),
        };
        assert_eq!(
            u.next_step(VERSION),
            VersionChoice::GiveUp { retry_after: 1800 }
        );
        let u = UnsupportedVersion {
            version: 0,
            lifetime: None,
        };
        assert_eq!(
            u.next_step(NAT_PMP_VERSION),
            VersionChoice::GiveUp { retry_after: 1800 }
        );
        // Not an UNSUPP_VERSION reply.
        assert_eq!(unsupported_version(&[0, 0]), None);
        assert_eq!(unsupported_version(&[0, 1, 0, 1]), None);
        assert_eq!(unsupported_version(&[2, 1, 0, 1]), None);
        assert_eq!(unsupported_version(&[2, 0x81, 0, 2]), None);
        assert_eq!(
            unsupported_version(&[2, 0x81, 0, 1]),
            Some(UnsupportedVersion {
                version: 2,
                lifetime: None
            })
        );
        assert_eq!(unsupported_version(&[0u8, 0, 0, 1].repeat(300)), None);
    }

    #[test]
    fn addresses() {
        let a = IpAddr::V4(LAPTOP);
        assert_eq!(unmapped(mapped(a)), a);
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(unmapped(mapped(b)), b);
    }

    #[test]
    fn every_truncated_prefix() {
        let requests = [
            map_request(),
            peer_request(),
            with(map_request(), vec![PcpOption::PreferFailure, filter(120)]),
            with(
                peer_request(),
                vec![PcpOption::ThirdParty(Ipv6Addr::LOCALHOST)],
            ),
        ];
        for r in &requests {
            let b = r.to_bytes().unwrap();
            for n in 0..b.len() {
                // Cut at an option boundary, a request reads with fewer
                // options. Cut anywhere else, it does not read.
                let got = Request::parse(&b[..n]);
                assert_ne!(got, Ok(r.clone()));
                if r.options.is_empty() || n < HEADER_LEN + MAP_LEN {
                    assert!(got.is_err(), "{n} of {}", b.len());
                }
            }
            let resp = r.reply(ResultCode::Success, 1, 1);
            let b = resp.to_bytes().unwrap();
            for n in 0..b.len() {
                // A response never reads back the same once cut.
                assert_ne!(Response::parse(&b[..n]), Ok(resp.clone()));
                if n < HEADER_LEN || n % 4 != 0 {
                    assert!(Response::parse(&b[..n]).is_err());
                }
            }
        }
        let nat = [NatPmpRequest::Map {
            protocol: NatPmpProtocol::Udp,
            internal_port: 1,
            external_port: 2,
            lifetime: 3,
        }
        .to_bytes()
        .unwrap()];
        for b in &nat {
            for n in 0..b.len() {
                assert!(NatPmpRequest::parse(&b[..n]).is_err());
            }
        }
        let responses = [
            NatPmpResponse::ExternalAddress {
                result: NatPmpResult::Success,
                epoch: 1,
                address: LAPTOP,
            },
            NatPmpResponse::Map {
                protocol: NatPmpProtocol::Udp,
                result: NatPmpResult::Success,
                epoch: 1,
                internal_port: 1,
                external_port: 2,
                lifetime: 3,
            },
            NatPmpResponse::UnsupportedVersion { epoch: 1 },
        ];
        for r in &responses {
            let b = r.to_bytes().unwrap();
            for n in 0..b.len() {
                assert!(NatPmpResponse::parse(&b[..n]).is_err(), "{r:?} cut to {n}");
            }
        }
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        // Too many options are refused.
        let many = vec![
            PcpOption::Other {
                code: 200,
                data: vec![1; 40]
            };
            100
        ];
        let r = with(map_request(), many.clone());
        assert_eq!(r.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&r);
        let resp = Response {
            options: many,
            ..map_request().reply(ResultCode::Success, 0, 0)
        };
        assert_eq!(resp.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&resp);
        // An oversized option refuses the whole value.
        let r = with(
            map_request(),
            vec![
                PcpOption::Other {
                    code: 200,
                    data: vec![0; 70000],
                },
                filter(0),
            ],
        );
        assert_eq!(r.to_bytes(), Err(Error::Unwritable));
        // Repeated singleton options and opaque known options are refused.
        let r = with(
            map_request(),
            vec![
                PcpOption::PreferFailure,
                PcpOption::PreferFailure,
                PcpOption::ThirdParty(Ipv6Addr::LOCALHOST),
                PcpOption::ThirdParty(Ipv6Addr::LOCALHOST),
                PcpOption::Other {
                    code: 3,
                    data: vec![1],
                },
            ],
        );
        assert_eq!(r.to_bytes(), Err(Error::Unwritable));
        // An unknown opcode that looks known is refused.
        let r = Request {
            lifetime: 0,
            client: Ipv6Addr::LOCALHOST,
            operation: Operation::Other {
                opcode: 0x81,
                data: vec![0; 5000],
            },
            options: vec![],
        };
        assert_eq!(r.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&r);
        let resp = Response {
            operation: Operation::Other {
                opcode: 1,
                data: vec![],
            },
            ..Response::announce(0)
        };
        contract::check_wire_value(&resp);
        // NAT-PMP.
        let r = NatPmpRequest::Unsupported {
            opcode: 1,
            data: vec![0; 5000],
        };
        assert_eq!(r.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&r);
        for opcode in [0, 1, 2, 0x80, 0x81, 3, 77] {
            let r = NatPmpResponse::Other {
                opcode,
                result: NatPmpResult::Success,
                data: vec![],
            };
            contract::check_wire_value(&r);
            assert_eq!(r.to_bytes().is_ok(), matches!(opcode, 3 | 77));
        }
        let r = NatPmpResponse::Other {
            opcode: 9,
            result: NatPmpResult::Success,
            data: vec![0; 5000],
        };
        assert_eq!(r.to_bytes(), Err(Error::Unwritable));
        // Error replies to tiny or huge requests still read.
        assert!(
            Response::parse(
                &error_reply(&[], ResultCode::UnsuppVersion, 1, 1)
                    .to_bytes()
                    .unwrap()
            )
            .is_ok()
        );
        assert!(
            Response::parse(
                &error_reply(&[7; 3000], ResultCode::MalformedRequest, 1, 1)
                    .to_bytes()
                    .unwrap()
            )
            .is_ok()
        );
    }

    /// Everything a reader of `b` must hold to.
    fn exercise(b: &[u8]) {
        contract::check_wire::<Request>(b);
        contract::check_wire::<Response>(b);
        contract::check_wire::<NatPmpRequest>(b);
        contract::check_wire::<NatPmpResponse>(b);
        contract::check_wire::<Reply>(b);

        if let Ok(r) = Request::parse(b) {
            let bytes = r.to_bytes().unwrap();
            assert!(bytes.len() <= MAX_MESSAGE);
            assert_eq!(Request::parse(&bytes), Ok(r.clone()));
            let _ = r.check(laptop());
            let resp = r.reply(ResultCode::NoResources, 30, 1);
            assert_eq!(Response::parse(&resp.to_bytes().unwrap()), Ok(resp));
        }
        if let Ok(r) = Response::parse(b) {
            let bytes = r.to_bytes().unwrap();
            assert!(bytes.len() <= MAX_MESSAGE);
            assert_eq!(Response::parse(&bytes), Ok(r));
        }
        if let Ok(r) = NatPmpRequest::parse(b) {
            assert_eq!(NatPmpRequest::parse(&r.to_bytes().unwrap()), Ok(r.clone()));
            let resp = r.refuse(NatPmpResult::NotAuthorized, 4);
            assert!(NatPmpResponse::parse(&resp.to_bytes().unwrap()).is_ok());
        }
        if let Ok(r) = NatPmpResponse::parse(b) {
            assert_eq!(NatPmpResponse::parse(&r.to_bytes().unwrap()), Ok(r));
        }
        for speaks in [Speaks::Pcp, Speaks::NatPmp, Speaks::Both] {
            if let Incoming::Reply(reply) = receive(b, speaks, laptop(), 11) {
                let reply = reply.to_bytes().unwrap();
                assert!(reply.len() <= MAX_MESSAGE);
                if reply[0] == NAT_PMP_VERSION {
                    assert!(NatPmpResponse::parse(&reply).is_ok());
                } else {
                    assert!(Response::parse(&reply).is_ok());
                    assert!(receive(&reply, speaks, laptop(), 11) == Incoming::Ignore);
                }
            }
        }
        if let Some(u) = unsupported_version(b) {
            let _ = u.next_step(VERSION);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x5351);
        let seeds: Vec<Vec<u8>> = vec![
            map_request().to_bytes().unwrap(),
            peer_request().to_bytes().unwrap(),
            with(
                map_request(),
                vec![
                    PcpOption::PreferFailure,
                    filter(120),
                    PcpOption::ThirdParty(Ipv6Addr::LOCALHOST),
                ],
            )
            .to_bytes()
            .unwrap(),
            map_request()
                .reply(ResultCode::Success, 1, 2)
                .to_bytes()
                .unwrap(),
            Response::announce(3).to_bytes().unwrap(),
            NatPmpRequest::ExternalAddress.to_bytes().unwrap(),
            NatPmpRequest::Map {
                protocol: NatPmpProtocol::Tcp,
                internal_port: 1,
                external_port: 2,
                lifetime: 3,
            }
            .to_bytes()
            .unwrap(),
            NatPmpResponse::UnsupportedVersion { epoch: 1 }
                .to_bytes()
                .unwrap(),
        ];
        for round in 0..4000 {
            let mut b = if round % 4 == 0 {
                (0..rng.index(120)).map(|_| rng.next() as u8).collect()
            } else {
                seeds[rng.index(seeds.len())].clone()
            };
            for _ in 0..rng.index(4) {
                mutate(&mut rng, &mut b);
            }
            // The whole buffer, and every prefix, as if it arrived a byte
            // at a time.
            for n in 0..=b.len() {
                exercise(&b[..n]);
            }
        }
    }

    /// Any value a world builds, not only one read from bytes, writes
    /// bytes that read back.
    #[test]
    fn built_values_always_read_back() {
        let mut rng = Lcg::new(6887);
        let addr = |rng: &mut Lcg| {
            if rng.coin() {
                Ipv4Addr::from(rng.next() as u32).to_ipv6_mapped()
            } else {
                Ipv6Addr::from([rng.next() as u8; 16])
            }
        };
        let bytes = |rng: &mut Lcg, sizes: &[usize]| -> Vec<u8> {
            let n = sizes[rng.index(sizes.len())];
            (0..n).map(|_| rng.next() as u8).collect()
        };
        for _ in 0..3000 {
            let operation = match rng.index(4) {
                0 => Operation::Announce,
                1 => Operation::Map(Map {
                    nonce: [rng.next() as u8; 12],
                    protocol: rng.next() as u8,
                    internal_port: rng.next() as u16,
                    external_port: rng.next() as u16,
                    external_address: addr(&mut rng),
                }),
                2 => Operation::Peer(Peer {
                    nonce: [rng.next() as u8; 12],
                    protocol: rng.next() as u8,
                    internal_port: rng.next() as u16,
                    external_port: rng.next() as u16,
                    external_address: addr(&mut rng),
                    remote_port: rng.next() as u16,
                    remote_address: addr(&mut rng),
                }),
                _ => Operation::Other {
                    opcode: rng.next() as u8,
                    data: bytes(&mut rng, &[0, 1, 3, 36, 56, 2000]),
                },
            };
            let count = [0, 1, 3, 60, 300][rng.index(5)];
            let options = (0..count)
                .map(|_| match rng.index(4) {
                    0 => PcpOption::ThirdParty(addr(&mut rng)),
                    1 => PcpOption::PreferFailure,
                    2 => PcpOption::Filter {
                        prefix_length: rng.next() as u8,
                        remote_port: rng.next() as u16,
                        remote_address: addr(&mut rng),
                    },
                    _ => PcpOption::Other {
                        code: rng.next() as u8,
                        data: bytes(&mut rng, &[0, 1, 5, 16, 20, 1200]),
                    },
                })
                .collect::<Vec<_>>();
            let r = Request {
                lifetime: (rng.next() as u32),
                client: addr(&mut rng),
                operation,
                options,
            };
            contract::check_wire_value(&r);
            if let Ok(b) = r.to_bytes() {
                let source = unmapped(r.client);
                if let Incoming::Reply(reply) = receive(&b, Speaks::Both, source, 9) {
                    contract::check_wire_value(&reply);
                }
            }
            let resp = Response {
                reserved: [rng.next() as u8; 12],
                ..r.reply(ResultCode::from_code(rng.next() as u8), 1, 2)
            };
            contract::check_wire_value(&resp);
            let n = NatPmpResponse::Other {
                opcode: rng.next() as u8,
                result: NatPmpResult::from_code(rng.next() as u16),
                data: bytes(&mut rng, &[0, 1, 3, 20, 2000]),
            };
            contract::check_wire_value(&n);
            let n = NatPmpRequest::Unsupported {
                opcode: rng.next() as u8,
                data: bytes(&mut rng, &[0, 1, 2, 3, 2000]),
            };
            contract::check_wire_value(&n);
            if let Ok(b) = n.to_bytes() {
                let read = NatPmpRequest::parse(&b).unwrap();
                contract::check_wire_value(&read.refuse(NatPmpResult::UnsupportedOpcode, 1));
            }
        }
    }

    /// Worlds key mapping tables by these types.
    #[test]
    fn types_hash() {
        let mut table = std::collections::HashMap::new();
        let Operation::Map(m) = map_request().operation else {
            panic!()
        };
        table.insert(m, ResultCode::Success);
        table.insert(m, ResultCode::NoResources);
        assert_eq!(table.len(), 1);
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(map_request()));
        assert!(!seen.insert(map_request()));
    }
}
