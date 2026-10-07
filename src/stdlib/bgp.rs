//! BGP-4: reading and writing messages, from OPEN to ROUTE-REFRESH, with
//! no I/O.
//!
//! BGP is how networks on the Internet tell each other which addresses
//! they can reach. Two routers (speakers) hold a TCP connection, usually
//! on port 179, and send each other messages: an OPEN to start, then
//! UPDATEs that announce and withdraw routes, KEEPALIVEs to show they are
//! still there, and a NOTIFICATION just before one of them closes the
//! connection because something went wrong. Every message starts with a
//! 19-byte header: 16 bytes of 0xFF, a length and a type. This module
//! follows RFC 4271 (BGP-4), RFC 4760 (multiprotocol routes), RFC 6793
//! (four-octet AS numbers), RFC 5492 (capabilities), RFC 2918 (route
//! refresh), RFC 4724 (the graceful restart capability), RFC 7606 (revised
//! UPDATE error handling), RFC 7607 (AS 0), RFC 7313 (enhanced route
//! refresh errors) and RFC 9072 (long OPEN optional parameters).
//!
//! Nothing here reads a socket. A world that plays a router passes the
//! bytes it reads from a TCP connection to [`Stream<Frames>`](fictionet::stdlib::codec::Stream),
//! gets [`Frame`]s back, and reads each one with [`Message::decode`].
//! It builds a reply with [`Message::to_frame`] and writes its bytes
//! back to the connection. Which routes exist,
//! which peers are welcome and when timers fire is up to world code.
//!
//! How an UPDATE reads depends on the session: once both speakers have
//! sent the four-octet AS capability, AS numbers in AS_PATH and
//! AGGREGATOR take four bytes instead of two. A [`Context`] says which,
//! and [`Context::negotiated`] works it out from the two OPEN messages.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A message that breaks the specification gives an [`Error`]
//! whose [`Error::notification`] is the NOTIFICATION RFC 4271 sends before
//! it closes the connection. RFC 7606 closes the connection for fewer
//! UPDATE errors: most of them withdraw the UPDATE's routes or drop one
//! attribute instead. [`Update::receive`] reads an UPDATE that way.
//! Writers check the same rules and return an [`Error`] instead of
//! bytes a reader would refuse.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
//! use core::net::Ipv4Addr;
//! use fictionet::stdlib::bgp::{
//!     afi, safi, Attribute, Capability, Context, Frames, Message, Open, Origin, Prefix, Segment, SegmentKind,
//!     Update, AS_TRANS,
//! };
//!
//! // The agent's router opens a session as AS 65001.
//! let theirs = Open::new(65001, 90, Ipv4Addr::new(192, 0, 2, 1), vec![Capability::Multiprotocol {
//!     afi: afi::IPV4,
//!     safi: safi::UNICAST,
//! }]);
//! let mut stream = Stream::new(Frames);
//! let mut frames = Vec::new();
//! let bytes = Message::Open(theirs).to_frame(&Context::default()).and_then(|frame| frame.to_bytes()).unwrap();
//! pump(&mut stream, &bytes, |frame| frames.push(frame)).unwrap();
//! let frame = frames.pop().unwrap();
//! let Message::Open(open) = Message::decode(&frame, &Context::default()).unwrap() else {
//!     panic!("not an OPEN");
//! };
//! assert_eq!(open.asn(), 65001);
//!
//! // The world answers as AS 4200000000, which needs four octets.
//! let ours = Open::new(4_200_000_000, 90, Ipv4Addr::new(198, 51, 100, 1), vec![]);
//! assert_eq!(ours.my_as, AS_TRANS);
//! let negotiated = Context::negotiated(&ours, &open);
//! assert!(negotiated.four_octet_as);
//! let keepalive = Message::Keepalive.to_frame(&negotiated).and_then(|frame| frame.to_bytes()).unwrap();
//! assert_eq!(keepalive[16..], [0, 19, 4]);
//!
//! // Announce 203.0.113.0/24 with the world's AS as the whole path.
//! let update = Update {
//!     withdrawn: vec![],
//!     attributes: vec![
//!         Attribute::Origin(Origin::Igp),
//!         Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns: vec![4_200_000_000] }]),
//!         Attribute::NextHop(Ipv4Addr::new(198, 51, 100, 1)),
//!     ],
//!     nlri: vec![Prefix::new(Ipv4Addr::new(203, 0, 113, 0).into(), 24).unwrap()],
//! };
//! let bytes = Message::Update(update.clone()).to_frame(&negotiated).and_then(|frame| frame.to_bytes()).unwrap();
//! // No withdrawn routes, then 20 bytes of attributes.
//! assert_eq!(bytes[19..23], [0, 0, 0, 20]);
//! // The prefix comes last: its length in bits, then 3 bytes.
//! assert_eq!(bytes[43..], [24, 203, 0, 113]);
//!
//! pump(&mut stream, &bytes, |frame| frames.push(frame)).unwrap();
//! let frame = frames.pop().unwrap();
//! assert_eq!(Message::decode(&frame, &negotiated), Ok(Message::Update(update)));
//! finish(&mut stream, |_| unreachable!()).unwrap();
//! ```

extern crate alloc;

use fictionet::stdlib::codec::{Decode, Step, Wire};
use alloc::{vec, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The TCP port BGP speakers listen on.
pub const PORT: u16 = 179;
/// The BGP version this module reads and writes.
pub const VERSION: u8 = 4;
/// The length of the marker that starts every message: 16 bytes of 0xFF.
pub const MARKER_LEN: usize = 16;
/// The length of the message header: the marker, a 2-byte length and a
/// 1-byte type.
pub const HEADER_LEN: usize = 19;
/// The longest message RFC 4271 allows, header included.
pub const MAX_MESSAGE_LEN: usize = 4096;
/// The longest body a message may carry after its header.
pub const MAX_BODY_LEN: usize = MAX_MESSAGE_LEN - HEADER_LEN;
/// The most bytes of optional parameters an OPEN carries in the format of
/// RFC 4271, and the most bytes one capability may hold: each length is
/// one byte. Longer parameters are written in the extended format of RFC
/// 9072, with two-byte lengths.
pub const MAX_PARAMETERS_LEN: usize = 255;
/// The most AS numbers one AS_PATH segment may hold: its count is one
/// byte.
pub const MAX_SEGMENT_ASNS: usize = 255;
/// The longest restart time the graceful restart capability can carry, in
/// seconds: the field is 12 bits.
pub const MAX_RESTART_TIME: u16 = 0x0fff;
/// The AS number a four-octet speaker puts in two-octet fields when its
/// real number does not fit (RFC 6793).
pub const AS_TRANS: u16 = 23456;

/// Message type codes.
pub mod kind {
    /// The first message each side sends.
    pub const OPEN: u8 = 1;
    /// Announces and withdraws routes.
    pub const UPDATE: u8 = 2;
    /// Reports an error just before the connection closes.
    pub const NOTIFICATION: u8 = 3;
    /// Shows the sender is still there.
    pub const KEEPALIVE: u8 = 4;
    /// Asks the peer to send its routes again (RFC 2918).
    pub const ROUTE_REFRESH: u8 = 5;
}

/// Address family identifiers this module reads prefixes for.
pub mod afi {
    /// IPv4.
    pub const IPV4: u16 = 1;
    /// IPv6.
    pub const IPV6: u16 = 2;
}

/// Subsequent address family identifiers this module reads prefixes for.
pub mod safi {
    /// Routes for unicast forwarding.
    pub const UNICAST: u8 = 1;
    /// Routes for multicast forwarding.
    pub const MULTICAST: u8 = 2;
}

/// Path attribute type codes.
pub mod attr {
    /// Where the route came from: IGP, EGP or incomplete.
    pub const ORIGIN: u8 = 1;
    /// The AS numbers the route passed through.
    pub const AS_PATH: u8 = 2;
    /// The IPv4 address to forward to.
    pub const NEXT_HOP: u8 = 3;
    /// The MULTI_EXIT_DISC: which of several links into an AS to prefer.
    pub const MED: u8 = 4;
    /// How much the sender's own AS prefers the route.
    pub const LOCAL_PREF: u8 = 5;
    /// Says a less specific route was chosen over more specific ones.
    pub const ATOMIC_AGGREGATE: u8 = 6;
    /// The AS and router that aggregated the route.
    pub const AGGREGATOR: u8 = 7;
    /// Community tags (RFC 1997).
    pub const COMMUNITIES: u8 = 8;
    /// Routes of other address families, with their next hop (RFC 4760).
    pub const MP_REACH_NLRI: u8 = 14;
    /// Withdrawn routes of other address families (RFC 4760).
    pub const MP_UNREACH_NLRI: u8 = 15;
    /// The four-octet AS path a two-octet session carries (RFC 6793).
    /// This module keeps it as an `Attribute::Unknown`, and checks it: it
    /// is dropped in a four-octet session or when it is malformed, as RFC
    /// 6793 section 6 says.
    pub const AS4_PATH: u8 = 17;
    /// The four-octet aggregator a two-octet session carries (RFC 6793).
    /// It is kept and checked like `AS4_PATH`.
    pub const AS4_AGGREGATOR: u8 = 18;
}

/// Path attribute flag bits.
pub mod flag {
    /// The attribute is optional, not well known.
    pub const OPTIONAL: u8 = 0x80;
    /// The attribute is passed on to other peers.
    pub const TRANSITIVE: u8 = 0x40;
    /// A router on the way did not recognize the optional transitive
    /// attribute.
    pub const PARTIAL: u8 = 0x20;
    /// The length field takes two bytes instead of one.
    pub const EXTENDED_LENGTH: u8 = 0x10;
}

/// Capability codes this module reads (RFC 5492 and the RFCs it names).
pub mod capability {
    /// Multiprotocol extensions (RFC 4760).
    pub const MULTIPROTOCOL: u8 = 1;
    /// Route refresh (RFC 2918).
    pub const ROUTE_REFRESH: u8 = 2;
    /// Graceful restart (RFC 4724).
    pub const GRACEFUL_RESTART: u8 = 64;
    /// Four-octet AS numbers (RFC 6793).
    pub const FOUR_OCTET_AS: u8 = 65;
    /// Enhanced route refresh (RFC 7313). This module keeps it as a
    /// `Capability::Other` with no value.
    pub const ENHANCED_ROUTE_REFRESH: u8 = 70;
}

/// The optional parameter type that holds capabilities (RFC 5492).
pub const PARAMETER_CAPABILITIES: u8 = 2;
/// The optional parameter type RFC 9072 reserves to mark the extended
/// format. No parameter has it.
pub const PARAMETER_EXTENDED: u8 = 255;

/// NOTIFICATION error codes.
pub mod code {
    /// Something is wrong with a message header.
    pub const MESSAGE_HEADER: u8 = 1;
    /// Something is wrong with an OPEN.
    pub const OPEN_MESSAGE: u8 = 2;
    /// Something is wrong with an UPDATE.
    pub const UPDATE_MESSAGE: u8 = 3;
    /// No message came before the hold timer ran out.
    pub const HOLD_TIMER_EXPIRED: u8 = 4;
    /// A message came that the session's state does not allow.
    pub const FSM: u8 = 5;
    /// The speaker is closing the session for another reason.
    pub const CEASE: u8 = 6;
    /// Something is wrong with a ROUTE-REFRESH (RFC 7313).
    pub const ROUTE_REFRESH_MESSAGE: u8 = 7;
}

/// NOTIFICATION error subcodes, grouped by error code.
pub mod subcode {
    /// The subcode that names no particular error.
    pub const UNSPECIFIC: u8 = 0;

    /// Subcodes for `code::MESSAGE_HEADER`.
    pub mod header {
        /// The marker was not all ones.
        pub const CONNECTION_NOT_SYNCHRONIZED: u8 = 1;
        /// The length field was out of range for the message.
        pub const BAD_MESSAGE_LENGTH: u8 = 2;
        /// The type was not one the receiver knows.
        pub const BAD_MESSAGE_TYPE: u8 = 3;
    }

    /// Subcodes for `code::OPEN_MESSAGE`.
    pub mod open {
        /// The version is not one the receiver speaks.
        pub const UNSUPPORTED_VERSION_NUMBER: u8 = 1;
        /// The peer's AS is not the one expected.
        pub const BAD_PEER_AS: u8 = 2;
        /// The BGP identifier is not valid.
        pub const BAD_BGP_IDENTIFIER: u8 = 3;
        /// An optional parameter is not one the receiver knows.
        pub const UNSUPPORTED_OPTIONAL_PARAMETER: u8 = 4;
        /// The hold time is 1 or 2 seconds, or not one the receiver
        /// accepts.
        pub const UNACCEPTABLE_HOLD_TIME: u8 = 6;
        /// A capability the receiver needs is missing (RFC 5492).
        pub const UNSUPPORTED_CAPABILITY: u8 = 7;
    }

    /// Subcodes for `code::UPDATE_MESSAGE`.
    pub mod update {
        /// The lengths of the parts do not add up, or an attribute appears
        /// twice.
        pub const MALFORMED_ATTRIBUTE_LIST: u8 = 1;
        /// A well-known attribute the receiver does not know.
        pub const UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE: u8 = 2;
        /// A well-known attribute the routes need is missing.
        pub const MISSING_WELL_KNOWN_ATTRIBUTE: u8 = 3;
        /// An attribute's flags do not match its type.
        pub const ATTRIBUTE_FLAGS_ERROR: u8 = 4;
        /// An attribute's length does not match its type.
        pub const ATTRIBUTE_LENGTH_ERROR: u8 = 5;
        /// The ORIGIN value is not 0, 1 or 2.
        pub const INVALID_ORIGIN_ATTRIBUTE: u8 = 6;
        /// The NEXT_HOP is not a usable address.
        pub const INVALID_NEXT_HOP_ATTRIBUTE: u8 = 8;
        /// An optional attribute's value cannot be read.
        pub const OPTIONAL_ATTRIBUTE_ERROR: u8 = 9;
        /// A prefix cannot be read.
        pub const INVALID_NETWORK_FIELD: u8 = 10;
        /// The AS_PATH cannot be read.
        pub const MALFORMED_AS_PATH: u8 = 11;
    }

    /// Subcodes for `code::ROUTE_REFRESH_MESSAGE` (RFC 7313).
    pub mod route_refresh {
        /// A ROUTE-REFRESH that starts or ends a refresh is not 4 bytes
        /// after its header.
        pub const INVALID_MESSAGE_LENGTH: u8 = 1;
    }
}

/// What the two speakers agreed in their OPEN messages that changes how an
/// UPDATE reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Context {
    /// Both sent the four-octet AS capability, so AS numbers in AS_PATH and
    /// AGGREGATOR take four bytes.
    pub four_octet_as: bool,
    /// The peer sent the enhanced route refresh capability (RFC 7313), so
    /// a ROUTE-REFRESH that starts or ends a refresh with the wrong length
    /// is a ROUTE-REFRESH Message Error, not a header error.
    pub enhanced_route_refresh: bool,
}

impl Context {
    /// The context once `local` and `remote` have been exchanged.
    pub fn negotiated(local: &Open, remote: &Open) -> Context {
        let enhanced = |o: &Open| {
            o.capabilities().any(|c| matches!(c, Capability::Other { code: capability::ENHANCED_ROUTE_REFRESH, .. }))
        };
        Context {
            four_octet_as: local.four_octet_as().is_some() && remote.four_octet_as().is_some(),
            enhanced_route_refresh: enhanced(local) && enhanced(remote),
        }
    }
}

/// Why bytes are not a BGP message this module can read, or a message
/// cannot be written. Each fault in what the peer sent maps to the
/// NOTIFICATION a real speaker sends before it closes the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The marker was not 16 bytes of 0xFF.
    ConnectionNotSynchronized,
    /// The length field, given here, was below 19, above 4096, or wrong for
    /// the message type.
    BadMessageLength(u16),
    /// The message type, given here, is not one this module knows.
    BadMessageType(u8),
    /// An OPEN's optional parameters or capabilities do not fit together.
    MalformedOpen,
    /// The OPEN's version, given here, is not 4.
    UnsupportedVersion(u8),
    /// The OPEN's AS number, or its four-octet AS capability, is 0, which
    /// RFC 7607 forbids.
    BadPeerAs,
    /// The OPEN's BGP identifier is 0. RFC 6286 allows any other value.
    BadBgpIdentifier,
    /// The OPEN's hold time is 1 or 2 seconds.
    UnacceptableHoldTime,
    /// An UPDATE's lengths do not add up, an attribute is cut short, or an
    /// attribute appears twice.
    MalformedAttributeList,
    /// An attribute this module does not know arrived without the optional
    /// bit. It holds the whole attribute.
    UnrecognizedWellKnownAttribute(Vec<u8>),
    /// The UPDATE carries routes without this well-known attribute.
    MissingWellKnownAttribute(u8),
    /// An attribute's flags do not match its type. It holds the whole
    /// attribute.
    AttributeFlags(Vec<u8>),
    /// An attribute's length does not match its type. It holds the whole
    /// attribute.
    AttributeLength(Vec<u8>),
    /// The ORIGIN value is not 0, 1 or 2. It holds the whole attribute.
    InvalidOrigin(Vec<u8>),
    /// The NEXT_HOP is not an IPv4 host address: it is in 0.0.0.0/8,
    /// 127.0.0.0/8, 224.0.0.0/4 or 240.0.0.0/4. It holds the whole
    /// attribute.
    InvalidNextHop(Vec<u8>),
    /// An optional attribute's value is wrong: an MP_REACH_NLRI or
    /// MP_UNREACH_NLRI cannot be read or has a next hop of the wrong
    /// length, an AGGREGATOR names AS 0, or an AS4_PATH or AS4_AGGREGATOR
    /// is malformed. It holds the whole attribute.
    OptionalAttribute(Vec<u8>),
    /// A withdrawn route or NLRI prefix cannot be read.
    InvalidNetworkField,
    /// The AS_PATH cannot be read, or holds AS 0.
    MalformedAsPath,
    /// With enhanced route refresh, a ROUTE-REFRESH of subtype 1 or 2 is
    /// not 4 bytes after its header (RFC 7313 section 5). It holds the
    /// whole message, header included, cut to what a NOTIFICATION holds.
    RouteRefreshLength(Vec<u8>),
    /// An exact [`Wire`] parse of a [`Frame`] ended before a complete
    /// frame, including empty input.
    Truncated,
    /// Bytes follow the first complete frame in an exact [`Wire`] parse.
    Trailing,
    /// A value cannot be written without changing it: its fields break a
    /// rule the reader checks, or it does not fit in [`MAX_MESSAGE_LEN`]
    /// bytes.
    Unwritable,
}

impl Error {
    /// The NOTIFICATION a speaker sends for this error, with the data RFC
    /// 4271 asks for. Preserves the stored data. Caller-built errors with
    /// excess data produce a notification that writing refuses. It is
    /// `None` for [`Error::Truncated`], [`Error::Trailing`] and
    /// [`Error::Unwritable`], which are not faults a peer sent.
    pub fn notification(&self) -> Option<Notification> {
        use subcode::{header as h, open as o, update as u};
        let (code, subcode, data) = match self {
            Error::ConnectionNotSynchronized => (code::MESSAGE_HEADER, h::CONNECTION_NOT_SYNCHRONIZED, vec![]),
            Error::BadMessageLength(n) => (code::MESSAGE_HEADER, h::BAD_MESSAGE_LENGTH, n.to_be_bytes().to_vec()),
            Error::BadMessageType(t) => (code::MESSAGE_HEADER, h::BAD_MESSAGE_TYPE, vec![*t]),
            Error::MalformedOpen => (code::OPEN_MESSAGE, subcode::UNSPECIFIC, vec![]),
            // The data is the largest version the speaker supports.
            Error::UnsupportedVersion(_) => (code::OPEN_MESSAGE, o::UNSUPPORTED_VERSION_NUMBER, vec![0, VERSION]),
            Error::BadPeerAs => (code::OPEN_MESSAGE, o::BAD_PEER_AS, vec![]),
            Error::BadBgpIdentifier => (code::OPEN_MESSAGE, o::BAD_BGP_IDENTIFIER, vec![]),
            Error::UnacceptableHoldTime => (code::OPEN_MESSAGE, o::UNACCEPTABLE_HOLD_TIME, vec![]),
            Error::MalformedAttributeList => (code::UPDATE_MESSAGE, u::MALFORMED_ATTRIBUTE_LIST, vec![]),
            Error::UnrecognizedWellKnownAttribute(a) => {
                (code::UPDATE_MESSAGE, u::UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE, a.clone())
            }
            Error::MissingWellKnownAttribute(t) => (code::UPDATE_MESSAGE, u::MISSING_WELL_KNOWN_ATTRIBUTE, vec![*t]),
            Error::AttributeFlags(a) => (code::UPDATE_MESSAGE, u::ATTRIBUTE_FLAGS_ERROR, a.clone()),
            Error::AttributeLength(a) => (code::UPDATE_MESSAGE, u::ATTRIBUTE_LENGTH_ERROR, a.clone()),
            Error::InvalidOrigin(a) => (code::UPDATE_MESSAGE, u::INVALID_ORIGIN_ATTRIBUTE, a.clone()),
            Error::InvalidNextHop(a) => (code::UPDATE_MESSAGE, u::INVALID_NEXT_HOP_ATTRIBUTE, a.clone()),
            Error::OptionalAttribute(a) => (code::UPDATE_MESSAGE, u::OPTIONAL_ATTRIBUTE_ERROR, a.clone()),
            Error::InvalidNetworkField => (code::UPDATE_MESSAGE, u::INVALID_NETWORK_FIELD, vec![]),
            Error::MalformedAsPath => (code::UPDATE_MESSAGE, u::MALFORMED_AS_PATH, vec![]),
            Error::RouteRefreshLength(m) => (
                code::ROUTE_REFRESH_MESSAGE,
                subcode::route_refresh::INVALID_MESSAGE_LENGTH,
                m.clone(),
            ),
            Error::Truncated | Error::Trailing | Error::Unwritable => return None,
        };
        Some(Notification { code, subcode, data })
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ConnectionNotSynchronized => f.write_str("marker is not all ones"),
            Error::BadMessageLength(n) => write!(f, "bad message length {n}"),
            Error::BadMessageType(t) => write!(f, "bad message type {t}"),
            Error::MalformedOpen => f.write_str("malformed OPEN optional parameters"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported BGP version {v}"),
            Error::BadPeerAs => f.write_str("peer AS is 0"),
            Error::BadBgpIdentifier => f.write_str("BGP identifier is 0"),
            Error::UnacceptableHoldTime => f.write_str("hold time of 1 or 2 seconds"),
            Error::MalformedAttributeList => f.write_str("malformed attribute list"),
            Error::UnrecognizedWellKnownAttribute(a) => {
                write!(f, "unrecognized well-known attribute {}", a.get(1).copied().unwrap_or(0))
            }
            Error::MissingWellKnownAttribute(t) => write!(f, "missing well-known attribute {t}"),
            Error::AttributeFlags(a) => write!(f, "bad flags on attribute {}", a.get(1).copied().unwrap_or(0)),
            Error::AttributeLength(a) => write!(f, "bad length of attribute {}", a.get(1).copied().unwrap_or(0)),
            Error::InvalidOrigin(_) => f.write_str("invalid ORIGIN"),
            Error::InvalidNextHop(_) => f.write_str("NEXT_HOP is not a host address"),
            Error::OptionalAttribute(a) => write!(f, "cannot read attribute {}", a.get(1).copied().unwrap_or(0)),
            Error::InvalidNetworkField => f.write_str("invalid prefix"),
            Error::MalformedAsPath => f.write_str("malformed AS_PATH"),
            Error::RouteRefreshLength(_) => f.write_str("ROUTE-REFRESH of the wrong length"),
            Error::Truncated => f.write_str("input ended before a complete BGP frame"),
            Error::Trailing => f.write_str("bytes follow the BGP frame"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
        }
    }
}

impl core::error::Error for Error {}

/// One BGP message as the header splits it: its type and the bytes after
/// the header. The marker is always all ones and the length is worked out
/// from the body, so neither is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The message type, one of [`kind`]'s codes for messages this module
    /// reads.
    pub kind: u8,
    /// The bytes after the header.
    pub body: Vec<u8>,
}

impl Frame {
    /// Reads the frame at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the frame and how many bytes
    /// of `b` it took. A marker byte that is not 0xFF is reported as soon
    /// as it arrives.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
        if b.iter().take(MARKER_LEN).any(|&x| x != 0xff) {
            return Err(Error::ConnectionNotSynchronized);
        }
        if b.len() < MARKER_LEN + 2 {
            return Ok(None);
        }
        let length = be16(b, MARKER_LEN);
        let end = usize::from(length);
        if !(HEADER_LEN..=MAX_MESSAGE_LEN).contains(&end) {
            return Err(Error::BadMessageLength(length));
        }
        if b.len() < end {
            return Ok(None);
        }
        Ok(Some((Frame { kind: b[MARKER_LEN + 2], body: b[HEADER_LEN..end].to_vec() }, end)))
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one frame. Refuses a marker byte other than 0xFF,
    /// a length outside [`HEADER_LEN`] through [`MAX_MESSAGE_LEN`],
    /// incomplete input, and trailing bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match Self::parse_prefix(b)? {
            Some((frame, used)) if used == b.len() => Ok(frame),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Truncated),
        }
    }

    /// Appends the header and body. Refuses a body longer than
    /// [`MAX_BODY_LEN`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.body.len() > MAX_BODY_LEN {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&[0xff; MARKER_LEN]);
        out.extend_from_slice(&((HEADER_LEN + self.body.len()) as u16).to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

/// Reads BGP frames without holding input bytes.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for input bounded by [`MAX_MESSAGE_LEN`].
/// Partial frames return [`Step::Need`], including at EOF. The stream reports
/// truncation at EOF and framing errors once. Map frames through
/// [`Message::decode`] with the session's [`Context`] to read their bodies.
///
/// ```
/// use fictionet::stdlib::codec::{Decode, Stream, Wire, finish, pump};
/// use fictionet::stdlib::bgp::{Context, Frames, Message};
///
/// let context = Context::default();
/// let bytes = Message::Keepalive.to_frame(&context).and_then(|frame| frame.to_bytes())?;
/// let mut stream = Stream::new(Frames.map(|frame| Message::decode(&frame, &context)));
/// let mut messages = Vec::new();
/// pump(&mut stream, &bytes, |message| messages.push(message))?;
/// finish(&mut stream, |message| messages.push(message))?;
/// assert_eq!(messages, [Ok(Message::Keepalive)]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;

impl Decode for Frames {
    type Item = Frame;
    type Error = Error;
    const NAME: &'static str = "BGP";

    fn capacity(&self) -> usize {
        MAX_MESSAGE_LEN
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, Error> {
        Ok(match Frame::parse_prefix(input)? {
            Some((frame, used)) => Step::Item(frame, used),
            None => Step::Need,
        })
    }
}

/// A BGP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// The first message each side sends.
    Open(Open),
    /// Routes announced and withdrawn.
    Update(Update),
    /// An error, sent just before the connection closes.
    Notification(Notification),
    /// The sender is still there.
    Keepalive,
    /// A request to send the routes of one address family again.
    RouteRefresh(RouteRefresh),
}

impl Message {
    /// Reads the message in `frame`. `negotiated` says how AS numbers in an
    /// UPDATE read and how a ROUTE-REFRESH of the wrong length is
    /// reported. An UPDATE is read as [`Update::parse`] reads it: every
    /// error is one that closes the connection. Pass the body of an UPDATE
    /// frame to [`Update::receive`] for the error handling of RFC 7606.
    pub fn decode(frame: &Frame, negotiated: &Context) -> Result<Message, Error> {
        let len = frame.body.len().saturating_add(HEADER_LEN);
        let field = length_field(&frame.body);
        // RFC 7313 section 5: with enhanced route refresh, a refresh start
        // or end of the wrong length has its own error, with the message.
        if frame.kind == kind::ROUTE_REFRESH
            && negotiated.enhanced_route_refresh
            && len <= MAX_MESSAGE_LEN
            && frame.body.len() != 4
            && matches!(frame.body.get(2), Some(1 | 2))
        {
            let mut whole = vec![0xff; MARKER_LEN];
            whole.extend_from_slice(&field.to_be_bytes());
            whole.push(frame.kind);
            whole.extend_from_slice(&frame.body[..frame.body.len().min(MAX_BODY_LEN - 2 - HEADER_LEN)]);
            return Err(Error::RouteRefreshLength(whole));
        }
        let (min, exact) = match frame.kind {
            kind::OPEN => (29, false),
            kind::UPDATE => (23, false),
            kind::NOTIFICATION => (21, false),
            kind::KEEPALIVE => (19, true),
            kind::ROUTE_REFRESH => (23, true),
            other => return Err(Error::BadMessageType(other)),
        };
        if len > MAX_MESSAGE_LEN || len < min || (exact && len != min) {
            return Err(Error::BadMessageLength(field));
        }
        let b = &frame.body[..];
        Ok(match frame.kind {
            kind::OPEN => Message::Open(Open::parse(b)?),
            kind::UPDATE => Message::Update(Update::parse(b, negotiated)?),
            kind::NOTIFICATION => Message::Notification(Notification::parse(b).ok_or(Error::BadMessageLength(field))?),
            kind::KEEPALIVE => Message::Keepalive,
            _ => Message::RouteRefresh(RouteRefresh::parse(b).ok_or(Error::BadMessageLength(field))?),
        })
    }

    /// The message's type code.
    pub fn kind(&self) -> u8 {
        match self {
            Message::Open(_) => kind::OPEN,
            Message::Update(_) => kind::UPDATE,
            Message::Notification(_) => kind::NOTIFICATION,
            Message::Keepalive => kind::KEEPALIVE,
            Message::RouteRefresh(_) => kind::ROUTE_REFRESH,
        }
    }

    /// The message as a frame, checked so that [`Message::decode`] reads
    /// it back with the same `negotiated`.
    pub fn to_frame(&self, negotiated: &Context) -> Result<Frame, Error> {
        let body = match self {
            Message::Open(o) => o.to_body()?,
            Message::Update(u) => u.to_body(negotiated)?,
            Message::Notification(n) => n.to_body()?,
            Message::Keepalive => Vec::new(),
            Message::RouteRefresh(r) => r.to_body(),
        };
        bound(&body)?;
        Ok(Frame { kind: self.kind(), body })
    }
}

/// An OPEN message. The version is always 4, so it is not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    /// The sender's AS number, or [`AS_TRANS`] if it needs four octets.
    pub my_as: u16,
    /// The most seconds the sender waits between messages before it gives
    /// up: 0, or at least 3.
    pub hold_time: u16,
    /// The sender's BGP identifier, usually one of its IPv4 addresses. It
    /// is never 0.
    pub bgp_id: Ipv4Addr,
    /// The optional parameters, in order.
    pub parameters: Vec<Parameter>,
}

/// An OPEN optional parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parameter {
    /// Type 2: capabilities the sender supports (RFC 5492).
    Capabilities(Vec<Capability>),
    /// Any other type, with its value unread. Its kind is never 2 or
    /// [`PARAMETER_EXTENDED`].
    Other {
        /// The parameter type.
        kind: u8,
        /// The parameter value. More than 255 bytes needs the extended
        /// format, which the writer picks when it must.
        value: Vec<u8>,
    },
}

/// A capability advertised in an OPEN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Code 1: the sender takes routes of this address family (RFC 4760).
    Multiprotocol {
        /// The address family, such as [`afi::IPV6`].
        afi: u16,
        /// The subsequent address family, such as [`safi::UNICAST`].
        safi: u8,
    },
    /// Code 2: the sender answers ROUTE-REFRESH messages (RFC 2918).
    RouteRefresh,
    /// Code 64: the sender keeps forwarding through a restart (RFC 4724).
    GracefulRestart(GracefulRestart),
    /// Code 65: the sender's four-octet AS number (RFC 6793).
    FourOctetAs(u32),
    /// Any other capability, with its value unread. Its code is never one
    /// of the four above.
    Other {
        /// The capability code.
        code: u8,
        /// The capability value, at most 255 bytes.
        value: Vec<u8>,
    },
}

/// The graceful restart capability's value (RFC 4724).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GracefulRestart {
    /// The 4 restart flag bits, 0 to 15. The top one (8) says the sender
    /// has restarted.
    pub flags: u8,
    /// How many seconds the sender expects a restart to take, at most
    /// [`MAX_RESTART_TIME`].
    pub time: u16,
    /// The address families whose forwarding state the sender keeps.
    pub families: Vec<RestartFamily>,
}

/// One address family in a graceful restart capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestartFamily {
    /// The address family.
    pub afi: u16,
    /// The subsequent address family.
    pub safi: u8,
    /// The family's flags. The top bit (0x80) says forwarding state was
    /// kept.
    pub flags: u8,
}

impl Open {
    /// An OPEN for AS `asn` that advertises `capabilities` and then the
    /// four-octet AS capability for `asn`. A four-octet AS capability in
    /// `capabilities` is left out, so the OPEN names one AS. If `asn` does
    /// not fit in two octets, `my_as` is [`AS_TRANS`].
    pub fn new(asn: u32, hold_time: u16, bgp_id: Ipv4Addr, mut capabilities: Vec<Capability>) -> Open {
        capabilities.retain(|c| !matches!(c, Capability::FourOctetAs(_)));
        capabilities.push(Capability::FourOctetAs(asn));
        Open {
            my_as: u16::try_from(asn).unwrap_or(AS_TRANS),
            hold_time,
            bgp_id,
            parameters: vec![Parameter::Capabilities(capabilities)],
        }
    }

    /// Every capability, from every capabilities parameter, in order.
    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.parameters.iter().flat_map(|p| match p {
            Parameter::Capabilities(c) => c.as_slice(),
            Parameter::Other { .. } => &[],
        })
    }

    /// The AS number from the four-octet AS capability, if there is one.
    pub fn four_octet_as(&self) -> Option<u32> {
        self.capabilities().find_map(|c| match c {
            Capability::FourOctetAs(a) => Some(*a),
            _ => None,
        })
    }

    /// The sender's AS number: the four-octet one if it sent one, and
    /// `my_as` otherwise.
    pub fn asn(&self) -> u32 {
        self.four_octet_as().unwrap_or(u32::from(self.my_as))
    }

    fn to_body(&self) -> Result<Vec<u8>, Error> {
        if self.my_as == 0 || self.capabilities().any(|c| *c == Capability::FourOctetAs(0)) {
            return Err(Error::Unwritable);
        }
        if self.hold_time == 1 || self.hold_time == 2 {
            return Err(Error::Unwritable);
        }
        if self.bgp_id.is_unspecified() {
            return Err(Error::Unwritable);
        }
        let mut params = Vec::new();
        let mut size = 0;
        for p in &self.parameters {
            let (kind, value) = match p {
                Parameter::Capabilities(caps) => (PARAMETER_CAPABILITIES, capabilities_bytes(caps)?),
                Parameter::Other { kind, value } => {
                    if *kind == PARAMETER_CAPABILITIES {
                        return Err(Error::Unwritable);
                    }
                    if *kind == PARAMETER_EXTENDED {
                        return Err(Error::Unwritable);
                    }
                    bound(value)?;
                    (*kind, value.clone())
                }
            };
            size += 3 + value.len();
            if size > MAX_BODY_LEN {
                return Err(Error::Unwritable);
            }
            params.push((kind, value));
        }
        let mut out = vec![VERSION];
        out.extend_from_slice(&self.my_as.to_be_bytes());
        out.extend_from_slice(&self.hold_time.to_be_bytes());
        out.extend_from_slice(&self.bgp_id.octets());
        let short: usize = params.iter().map(|(_, v)| 2 + v.len()).sum();
        if short <= MAX_PARAMETERS_LEN && params.iter().all(|(_, v)| v.len() <= 255) {
            out.push(short as u8);
            for (kind, value) in &params {
                out.push(*kind);
                out.push(value.len() as u8);
                out.extend_from_slice(value);
            }
        } else {
            // RFC 9072: the extended format, needed when the parameters do
            // not fit in 255 bytes or one of them is longer than 255.
            out.extend_from_slice(&[0xff, PARAMETER_EXTENDED]);
            out.extend_from_slice(&(size as u16).to_be_bytes());
            for (kind, value) in &params {
                out.push(*kind);
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                out.extend_from_slice(value);
            }
        }
        bound(&out)?;
        Ok(out)
    }
}

impl Wire for Open {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an OPEN's body, the bytes after the header. A body shorter
    /// than 10 bytes or longer than [`MAX_BODY_LEN`] is a bad length.
    /// Refuses malformed fields, invalid AS numbers or timers, and excess lengths.
    fn parse(b: &[u8]) -> Result<Open, Error> {
        if b.len() > MAX_BODY_LEN {
            return Err(Error::BadMessageLength(length_field(b)));
        }
        let mut r = b;
        let (Some(version), Some(my_as), Some(hold_time), Some(id), Some(params_len)) =
            (take_u8(&mut r), take_u16(&mut r), take_u16(&mut r), take_u32(&mut r), take_u8(&mut r))
        else {
            return Err(Error::BadMessageLength(length_field(b)));
        };
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if my_as == 0 {
            return Err(Error::BadPeerAs);
        }
        if hold_time == 1 || hold_time == 2 {
            return Err(Error::UnacceptableHoldTime);
        }
        if id == 0 {
            return Err(Error::BadBgpIdentifier);
        }
        // RFC 9072: a nonzero length followed by type 255 marks the
        // extended format, with two-byte lengths.
        let extended = params_len != 0 && r.first() == Some(&PARAMETER_EXTENDED);
        let total = if extended {
            r = &r[1..];
            usize::from(take_u16(&mut r).ok_or(Error::MalformedOpen)?)
        } else {
            usize::from(params_len)
        };
        if r.len() != total {
            return Err(Error::MalformedOpen);
        }
        let mut parameters = Vec::new();
        while !r.is_empty() {
            let kind = take_u8(&mut r).ok_or(Error::MalformedOpen)?;
            let n = if extended { take_u16(&mut r).map(usize::from) } else { take_u8(&mut r).map(usize::from) };
            let value = take(&mut r, n.ok_or(Error::MalformedOpen)?).ok_or(Error::MalformedOpen)?;
            parameters.push(match kind {
                PARAMETER_CAPABILITIES => Parameter::Capabilities(parse_capabilities(value)?),
                PARAMETER_EXTENDED => return Err(Error::MalformedOpen),
                _ => Parameter::Other { kind, value: value.to_vec() },
            });
        }
        let open = Open { my_as, hold_time, bgp_id: Ipv4Addr::from(id), parameters };
        if open.capabilities().any(|c| *c == Capability::FourOctetAs(0)) {
            return Err(Error::BadPeerAs);
        }
        Ok(open)
    }

    /// Appends an OPEN body. Refuses invalid fields, capabilities, or
    /// lengths without changing `out`. Uses RFC 9072 for long parameters.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.to_body()?);
        Ok(())
    }
}

fn parse_capabilities(mut r: &[u8]) -> Result<Vec<Capability>, Error> {
    let mut out = Vec::new();
    while !r.is_empty() {
        let (Some(code), Some(n)) = (take_u8(&mut r), take_u8(&mut r)) else { return Err(Error::MalformedOpen) };
        let v = take(&mut r, usize::from(n)).ok_or(Error::MalformedOpen)?;
        out.push(match code {
            capability::MULTIPROTOCOL => {
                let [a0, a1, _reserved, safi] = v else { return Err(Error::MalformedOpen) };
                Capability::Multiprotocol { afi: u16::from_be_bytes([*a0, *a1]), safi: *safi }
            }
            capability::ROUTE_REFRESH if v.is_empty() => Capability::RouteRefresh,
            capability::FOUR_OCTET_AS => {
                let [a, b, c, d] = v else { return Err(Error::MalformedOpen) };
                Capability::FourOctetAs(u32::from_be_bytes([*a, *b, *c, *d]))
            }
            capability::GRACEFUL_RESTART if v.len() >= 2 && (v.len() - 2).is_multiple_of(4) => {
                let families = v[2..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| RestartFamily { afi: u16::from_be_bytes([c[0], c[1]]), safi: c[2], flags: c[3] })
                    .collect();
                Capability::GracefulRestart(GracefulRestart {
                    flags: v[0] >> 4,
                    time: u16::from_be_bytes([v[0], v[1]]) & MAX_RESTART_TIME,
                    families,
                })
            }
            capability::ROUTE_REFRESH | capability::GRACEFUL_RESTART => return Err(Error::MalformedOpen),
            code => Capability::Other { code, value: v.to_vec() },
        });
    }
    Ok(out)
}

fn capabilities_bytes(caps: &[Capability]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for c in caps {
        let (code, value) = match c {
            Capability::Multiprotocol { afi, safi } => {
                let [a0, a1] = afi.to_be_bytes();
                (capability::MULTIPROTOCOL, vec![a0, a1, 0, *safi])
            }
            Capability::RouteRefresh => (capability::ROUTE_REFRESH, vec![]),
            Capability::FourOctetAs(a) => (capability::FOUR_OCTET_AS, a.to_be_bytes().to_vec()),
            Capability::GracefulRestart(g) => {
                if g.flags > 0x0f {
                    return Err(Error::Unwritable);
                }
                if g.time > MAX_RESTART_TIME {
                    return Err(Error::Unwritable);
                }
                if g.families.len() > (MAX_PARAMETERS_LEN - 2) / 4 {
                    return Err(Error::Unwritable);
                }
                let mut v = vec![(g.flags << 4) | (g.time >> 8) as u8, g.time as u8];
                for f in &g.families {
                    v.extend_from_slice(&f.afi.to_be_bytes());
                    v.push(f.safi);
                    v.push(f.flags);
                }
                (capability::GRACEFUL_RESTART, v)
            }
            Capability::Other { code, value } => {
                if matches!(
                    *code,
                    capability::MULTIPROTOCOL
                        | capability::ROUTE_REFRESH
                        | capability::GRACEFUL_RESTART
                        | capability::FOUR_OCTET_AS
                ) {
                    return Err(Error::Unwritable);
                }
                if value.len() > MAX_PARAMETERS_LEN {
                    return Err(Error::Unwritable);
                }
                (*code, value.clone())
            }
        };
        out.push(code);
        out.push(value.len() as u8);
        out.extend_from_slice(&value);
        bound(&out)?;
    }
    Ok(out)
}

/// An IP prefix: an address and how many of its leading bits count.
/// The bits past the length are always 0: readers clear them, since they
/// mean nothing on the wire, and writers refuse a prefix that has any set.
/// [`Prefix::new`] clears them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    /// The address.
    pub addr: IpAddr,
    /// The prefix length in bits: at most 32 for IPv4 and 128 for IPv6.
    pub length: u8,
}

impl Prefix {
    /// The prefix of `length` bits of `addr`, with the bits after them
    /// cleared. It returns `None` if `length` is too long for the address.
    pub fn new(addr: IpAddr, length: u8) -> Option<Prefix> {
        match addr {
            IpAddr::V4(a) if length <= 32 => {
                let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
                Some(Prefix { addr: IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask)), length })
            }
            IpAddr::V6(a) if length <= 128 => {
                let mask = u128::MAX.checked_shl(128 - u32::from(length)).unwrap_or(0);
                Some(Prefix { addr: IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask)), length })
            }
            _ => None,
        }
    }
}

impl core::fmt::Display for Prefix {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.addr, self.length)
    }
}

/// Reads a run of prefixes of one family, each a length in bits and just
/// enough bytes to hold them.
fn read_prefixes(mut r: &[u8], v6: bool) -> Option<Vec<Prefix>> {
    let max = if v6 { 128 } else { 32 };
    let mut out = Vec::new();
    while !r.is_empty() {
        let length = take_u8(&mut r)?;
        if length > max {
            return None;
        }
        let bytes = take(&mut r, usize::from(length).div_ceil(8))?;
        let mut octets = [0u8; 16];
        octets[..bytes.len()].copy_from_slice(bytes);
        let addr = if v6 {
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        };
        out.push(Prefix::new(addr, length)?);
    }
    Some(out)
}

fn write_prefixes(out: &mut Vec<u8>, prefixes: &[Prefix], v6: bool) -> Result<(), Error> {
    for p in prefixes {
        let octets = match (p.addr, v6) {
            (IpAddr::V4(a), false) if p.length <= 32 => a.octets().to_vec(),
            (IpAddr::V6(a), true) if p.length <= 128 => a.octets().to_vec(),
            _ => return Err(Error::Unwritable),
        };
        if Prefix::new(p.addr, p.length) != Some(*p) {
            return Err(Error::Unwritable);
        }
        out.push(p.length);
        out.extend_from_slice(&octets[..usize::from(p.length).div_ceil(8)]);
        bound(out)?;
    }
    Ok(())
}

/// An UPDATE message.
///
/// Readers take any layout, but writers follow RFC 7606 section 5.1: an
/// UPDATE carries only one of withdrawn routes, NLRI, an MP_REACH_NLRI and
/// an MP_UNREACH_NLRI, and an MP attribute comes first. An UPDATE read
/// from an older speaker that mixes them is refused by the writer; send
/// its parts as separate UPDATEs.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Update {
    /// IPv4 prefixes the sender no longer reaches.
    pub withdrawn: Vec<Prefix>,
    /// The path attributes, in order. Each type appears at most once.
    pub attributes: Vec<Attribute>,
    /// IPv4 prefixes the sender reaches by the path the attributes give.
    pub nlri: Vec<Prefix>,
}

/// The value of an ORIGIN attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    /// 0: learned from an interior protocol in the origin AS.
    Igp,
    /// 1: learned from the older EGP protocol.
    Egp,
    /// 2: learned some other way.
    Incomplete,
}

impl Origin {
    /// The value's code.
    pub fn code(self) -> u8 {
        match self {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }

    /// The value with code `c`, if there is one.
    pub fn from_code(c: u8) -> Option<Origin> {
        match c {
            0 => Some(Origin::Igp),
            1 => Some(Origin::Egp),
            2 => Some(Origin::Incomplete),
            _ => None,
        }
    }
}

/// The kind of an AS_PATH segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SegmentKind {
    /// 1: AS_SET, ASes in no particular order, left by aggregation.
    Set,
    /// 2: AS_SEQUENCE, ASes in the order the route passed them, newest
    /// first.
    Sequence,
    /// 3: AS_CONFED_SEQUENCE, inside a confederation (RFC 5065).
    ConfedSequence,
    /// 4: AS_CONFED_SET, inside a confederation (RFC 5065).
    ConfedSet,
}

impl SegmentKind {
    /// The segment type's code.
    pub fn code(self) -> u8 {
        match self {
            SegmentKind::Set => 1,
            SegmentKind::Sequence => 2,
            SegmentKind::ConfedSequence => 3,
            SegmentKind::ConfedSet => 4,
        }
    }

    /// The segment kind with code `c`, if there is one.
    pub fn from_code(c: u8) -> Option<SegmentKind> {
        match c {
            1 => Some(SegmentKind::Set),
            2 => Some(SegmentKind::Sequence),
            3 => Some(SegmentKind::ConfedSequence),
            4 => Some(SegmentKind::ConfedSet),
            _ => None,
        }
    }
}

/// One AS_PATH segment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Segment {
    /// What kind of segment it is.
    pub kind: SegmentKind,
    /// Its AS numbers: 1 to [`MAX_SEGMENT_ASNS`] of them.
    pub asns: Vec<u32>,
}

/// Prefixes in an MP_REACH_NLRI or MP_UNREACH_NLRI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nlri {
    /// IPv4 or IPv6 unicast or multicast prefixes, read.
    Prefixes(Vec<Prefix>),
    /// Any other family's routes, unread.
    Raw(Vec<u8>),
}

/// Whether this module reads the routes of a family as prefixes.
fn prefix_family(afi: u16, safi: u8) -> bool {
    matches!(afi, afi::IPV4 | afi::IPV6) && matches!(safi, safi::UNICAST | safi::MULTICAST)
}

/// The value of an MP_REACH_NLRI attribute (RFC 4760).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpReach {
    /// The address family.
    pub afi: u16,
    /// The subsequent address family.
    pub safi: u8,
    /// The next hop's bytes: 16 or 32 for IPv6 (a global address, then
    /// maybe a link-local one, RFC 2545), and 4, 16 or 32 for IPv4 (RFC
    /// 4760, and RFC 8950 for an IPv6 next hop). For families read as
    /// [`Nlri::Raw`] any length up to 255 bytes.
    pub next_hop: Vec<u8>,
    /// The routes. [`Nlri::Prefixes`] for IPv4 and IPv6 unicast and
    /// multicast, [`Nlri::Raw`] otherwise.
    pub nlri: Nlri,
}

/// The value of an MP_UNREACH_NLRI attribute (RFC 4760).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MpUnreach {
    /// The address family.
    pub afi: u16,
    /// The subsequent address family.
    pub safi: u8,
    /// The withdrawn routes, in the same form as [`MpReach::nlri`].
    pub withdrawn: Nlri,
}

/// A path attribute. Known attributes are written with the flags RFC 4271
/// gives their type. The two optional transitive ones, AGGREGATOR and
/// COMMUNITIES, keep a PARTIAL bit: RFC 4271 section 5 forbids clearing it
/// when the route is passed on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribute {
    /// Type 1: where the route came from.
    Origin(Origin),
    /// Type 2: the ASes the route passed through. It may be empty.
    AsPath(Vec<Segment>),
    /// Type 3: the IPv4 address to forward to. It is a host address: not
    /// in 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4 or 240.0.0.0/4.
    NextHop(Ipv4Addr),
    /// Type 4: the MULTI_EXIT_DISC; lower is preferred.
    Med(u32),
    /// Type 5: the LOCAL_PREF; higher is preferred.
    LocalPref(u32),
    /// Type 6: ATOMIC_AGGREGATE, which has no value.
    AtomicAggregate,
    /// Type 7: who aggregated the route.
    Aggregator {
        /// The aggregating AS. It takes two octets unless the context says
        /// four.
        asn: u32,
        /// The aggregating router's address.
        address: Ipv4Addr,
        /// The PARTIAL flag: a router on the way did not know the
        /// attribute.
        partial: bool,
    },
    /// Type 8: community tags (RFC 1997).
    Communities {
        /// The tags, at least one, each the AS in the top 16 bits and a
        /// value in the bottom 16.
        values: Vec<u32>,
        /// The PARTIAL flag: a router on the way did not know the
        /// attribute.
        partial: bool,
    },
    /// Type 14: routes of another address family.
    MpReach(MpReach),
    /// Type 15: withdrawn routes of another address family.
    MpUnreach(MpUnreach),
    /// Any other type, with its value unread, except that an AS4_PATH or
    /// AS4_AGGREGATOR is checked against RFC 6793.
    Unknown {
        /// The flags: only the optional, transitive and partial bits, which
        /// is all a reader keeps and all a writer takes. The optional bit
        /// is always set: an unknown attribute without it is an error. The
        /// partial bit is set only with the transitive bit (RFC 4271
        /// section 4.3); a reader clears it on a non-transitive attribute.
        flags: u8,
        /// The type code. It is never one of the types above.
        kind: u8,
        /// The value.
        value: Vec<u8>,
    },
}

/// The optional and transitive bits a known attribute type must carry.
fn known_flags(kind: u8) -> Option<u8> {
    match kind {
        attr::ORIGIN | attr::AS_PATH | attr::NEXT_HOP | attr::LOCAL_PREF | attr::ATOMIC_AGGREGATE => {
            Some(flag::TRANSITIVE)
        }
        attr::MED | attr::MP_REACH_NLRI | attr::MP_UNREACH_NLRI => Some(flag::OPTIONAL),
        attr::AGGREGATOR | attr::COMMUNITIES => Some(flag::OPTIONAL | flag::TRANSITIVE),
        _ => None,
    }
}

impl Attribute {
    /// The attribute's type code.
    pub fn kind(&self) -> u8 {
        match self {
            Attribute::Origin(_) => attr::ORIGIN,
            Attribute::AsPath(_) => attr::AS_PATH,
            Attribute::NextHop(_) => attr::NEXT_HOP,
            Attribute::Med(_) => attr::MED,
            Attribute::LocalPref(_) => attr::LOCAL_PREF,
            Attribute::AtomicAggregate => attr::ATOMIC_AGGREGATE,
            Attribute::Aggregator { .. } => attr::AGGREGATOR,
            Attribute::Communities { .. } => attr::COMMUNITIES,
            Attribute::MpReach(_) => attr::MP_REACH_NLRI,
            Attribute::MpUnreach(_) => attr::MP_UNREACH_NLRI,
            Attribute::Unknown { kind, .. } => *kind,
        }
    }

    /// Reads one attribute's value. `raw` is the whole attribute, for the
    /// error. It returns `None` for an attribute RFC 6793 drops without an
    /// error: an AS4_PATH or AS4_AGGREGATOR in a four-octet session, or an
    /// AS4_PATH with no segments left once its confederation segments are
    /// dropped.
    fn parse(flags: u8, kind: u8, v: &[u8], raw: &[u8], negotiated: &Context) -> Result<Option<Attribute>, Error> {
        if kind == attr::AS4_PATH || kind == attr::AS4_AGGREGATOR {
            return parse_as4(flags, kind, v, raw, negotiated);
        }
        let Some(expected) = known_flags(kind) else {
            if flags & flag::OPTIONAL == 0 {
                return Err(Error::UnrecognizedWellKnownAttribute(raw.to_vec()));
            }
            let mut flags = flags & (flag::OPTIONAL | flag::TRANSITIVE | flag::PARTIAL);
            // RFC 4271 section 4.3: PARTIAL is 0 on a non-transitive
            // attribute.
            if flags & flag::TRANSITIVE == 0 {
                flags &= !flag::PARTIAL;
            }
            return Ok(Some(Attribute::Unknown { flags, kind, value: v.to_vec() }));
        };
        let partial_ok = expected == flag::OPTIONAL | flag::TRANSITIVE;
        if flags & (flag::OPTIONAL | flag::TRANSITIVE) != expected || (flags & flag::PARTIAL != 0 && !partial_ok) {
            return Err(Error::AttributeFlags(raw.to_vec()));
        }
        let partial = flags & flag::PARTIAL != 0;
        let length = || Error::AttributeLength(raw.to_vec());
        let u32_value = || -> Result<u32, Error> {
            let [a, b, c, d] = v else { return Err(length()) };
            Ok(u32::from_be_bytes([*a, *b, *c, *d]))
        };
        Ok(Some(match kind {
            attr::ORIGIN => match v {
                [c] => Attribute::Origin(Origin::from_code(*c).ok_or_else(|| Error::InvalidOrigin(raw.to_vec()))?),
                _ => return Err(length()),
            },
            attr::AS_PATH => Attribute::AsPath(parse_as_path(v, negotiated.four_octet_as).ok_or(Error::MalformedAsPath)?),
            attr::NEXT_HOP => {
                let a = Ipv4Addr::from(u32_value()?);
                if !host_address(a) {
                    return Err(Error::InvalidNextHop(raw.to_vec()));
                }
                Attribute::NextHop(a)
            }
            attr::MED => Attribute::Med(u32_value()?),
            attr::LOCAL_PREF => Attribute::LocalPref(u32_value()?),
            attr::ATOMIC_AGGREGATE if v.is_empty() => Attribute::AtomicAggregate,
            attr::ATOMIC_AGGREGATE => return Err(length()),
            attr::AGGREGATOR => {
                let (asn, address) = match (v, negotiated.four_octet_as) {
                    ([a, b, x @ ..], false) if x.len() == 4 => (u32::from(u16::from_be_bytes([*a, *b])), x),
                    ([a, b, c, d, x @ ..], true) if x.len() == 4 => (u32::from_be_bytes([*a, *b, *c, *d]), x),
                    _ => return Err(length()),
                };
                // RFC 7607: AS 0 makes the attribute malformed.
                if asn == 0 {
                    return Err(Error::OptionalAttribute(raw.to_vec()));
                }
                let address = Ipv4Addr::new(address[0], address[1], address[2], address[3]);
                Attribute::Aggregator { asn, address, partial }
            }
            // RFC 7606 section 7.8: a nonzero multiple of 4 bytes.
            attr::COMMUNITIES if !v.is_empty() && v.len().is_multiple_of(4) => Attribute::Communities {
                values: v.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect(),
                partial,
            },
            attr::COMMUNITIES => return Err(length()),
            attr::MP_REACH_NLRI => {
                Attribute::MpReach(parse_mp_reach(v).ok_or_else(|| Error::OptionalAttribute(raw.to_vec()))?)
            }
            _ => Attribute::MpUnreach(parse_mp_unreach(v).ok_or_else(|| Error::OptionalAttribute(raw.to_vec()))?),
        }))
    }

    /// Writes the attribute, header and value, onto `out`.
    fn write(&self, out: &mut Vec<u8>, negotiated: &Context) -> Result<(), Error> {
        let kind = self.kind();
        let mut v = Vec::new();
        let mut partial = false;
        match self {
            Attribute::Origin(o) => v.push(o.code()),
            Attribute::AsPath(segments) => put_segments(&mut v, segments, negotiated.four_octet_as)?,
            Attribute::NextHop(a) => {
                if !host_address(*a) {
                    return Err(Error::Unwritable);
                }
                v.extend_from_slice(&a.octets())
            }
            Attribute::Med(n) | Attribute::LocalPref(n) => v.extend_from_slice(&n.to_be_bytes()),
            Attribute::AtomicAggregate => {}
            Attribute::Aggregator { asn, address, partial: p } => {
                if *asn == 0 {
                    return Err(Error::Unwritable);
                }
                put_asn(&mut v, *asn, negotiated.four_octet_as)?;
                v.extend_from_slice(&address.octets());
                partial = *p;
            }
            Attribute::Communities { values, partial: p } => {
                if values.is_empty() {
                    return Err(Error::Unwritable);
                }
                for n in values {
                    v.extend_from_slice(&n.to_be_bytes());
                    bound(&v)?;
                }
                partial = *p;
            }
            Attribute::MpReach(m) => {
                if m.next_hop.len() > 255 {
                    return Err(Error::Unwritable);
                }
                if !next_hop_length(m.afi, m.safi, m.next_hop.len()) {
                    return Err(Error::Unwritable);
                }
                v.extend_from_slice(&m.afi.to_be_bytes());
                v.push(m.safi);
                v.push(m.next_hop.len() as u8);
                v.extend_from_slice(&m.next_hop);
                v.push(0);
                write_nlri(&mut v, m.afi, m.safi, &m.nlri)?;
            }
            Attribute::MpUnreach(m) => {
                v.extend_from_slice(&m.afi.to_be_bytes());
                v.push(m.safi);
                write_nlri(&mut v, m.afi, m.safi, &m.withdrawn)?;
            }
            Attribute::Unknown { flags, kind, value } => {
                if known_flags(*kind).is_some() {
                    return Err(Error::Unwritable);
                }
                if flags & flag::OPTIONAL == 0 {
                    return Err(Error::Unwritable);
                }
                if flags & !(flag::OPTIONAL | flag::TRANSITIVE | flag::PARTIAL) != 0 {
                    return Err(Error::Unwritable);
                }
                if flags & flag::PARTIAL != 0 && flags & flag::TRANSITIVE == 0 {
                    return Err(Error::Unwritable);
                }
                if value.len() > MAX_BODY_LEN {
                    return Err(Error::Unwritable);
                }
                let flags = *flags;
                if *kind == attr::AS4_PATH || *kind == attr::AS4_AGGREGATOR {
                    if negotiated.four_octet_as {
                        return Err(Error::Unwritable);
                    }
                    // A reader keeps the attribute as it is only if it is
                    // well formed.
                    match parse_as4(flags, *kind, value, &[], negotiated) {
                        Ok(Some(Attribute::Unknown { value: read, .. })) if read == *value => {}
                        _ => return Err(Error::Unwritable),
                    }
                }
                return put_attribute(out, flags, *kind, value);
            }
        }
        // Every known type has flags; the match above returned for the rest.
        let flags = known_flags(kind).unwrap_or(flag::OPTIONAL) | if partial { flag::PARTIAL } else { 0 };
        put_attribute(out, flags, kind, &v)
    }
}

/// Reads an AS4_PATH or AS4_AGGREGATOR (RFC 6793 section 6). Between two
/// four-octet speakers it is dropped. One that is not optional transitive
/// is an `AttributeFlags` error, and a malformed one, or one naming AS 0
/// (RFC 7607), an `OptionalAttribute` error; RFC 6793 drops the attribute
/// for both. Confederation segments in an AS4_PATH are dropped.
fn parse_as4(flags: u8, kind: u8, v: &[u8], raw: &[u8], negotiated: &Context) -> Result<Option<Attribute>, Error> {
    if negotiated.four_octet_as {
        return Ok(None);
    }
    if flags & (flag::OPTIONAL | flag::TRANSITIVE) != flag::OPTIONAL | flag::TRANSITIVE {
        return Err(Error::AttributeFlags(raw.to_vec()));
    }
    let malformed = || Error::OptionalAttribute(raw.to_vec());
    let value = if kind == attr::AS4_PATH {
        let segments = parse_as_path(v, true).filter(|s| !s.is_empty()).ok_or_else(malformed)?;
        let kept: Vec<Segment> =
            segments.into_iter().filter(|s| matches!(s.kind, SegmentKind::Set | SegmentKind::Sequence)).collect();
        if kept.is_empty() {
            return Ok(None);
        }
        let mut value = Vec::new();
        put_segments(&mut value, &kept, true).map_err(|_| malformed())?;
        value
    } else {
        let [a, b, c, d, _, _, _, _] = v else { return Err(malformed()) };
        if u32::from_be_bytes([*a, *b, *c, *d]) == 0 {
            return Err(malformed());
        }
        v.to_vec()
    };
    Ok(Some(Attribute::Unknown { flags: flags & (flag::OPTIONAL | flag::TRANSITIVE | flag::PARTIAL), kind, value }))
}

/// Whether an MP_REACH_NLRI next hop of `len` bytes fits the family: RFC
/// 2545 for IPv6, RFC 4760 and RFC 8950 for IPv4. Families this module
/// does not read as prefixes are not checked.
fn next_hop_length(afi: u16, safi: u8, len: usize) -> bool {
    match afi {
        _ if !prefix_family(afi, safi) => true,
        afi::IPV4 => matches!(len, 4 | 16 | 32),
        _ => matches!(len, 16 | 32),
    }
}

/// Writes AS_PATH segments: each 1 to 255 AS numbers, none of them 0.
fn put_segments(v: &mut Vec<u8>, segments: &[Segment], four: bool) -> Result<(), Error> {
    for s in segments {
        if s.asns.is_empty() || s.asns.len() > MAX_SEGMENT_ASNS {
            return Err(Error::Unwritable);
        }
        if s.asns.contains(&0) {
            return Err(Error::Unwritable);
        }
        v.push(s.kind.code());
        v.push(s.asns.len() as u8);
        for &a in &s.asns {
            put_asn(v, a, four)?;
        }
        bound(v)?;
    }
    Ok(())
}

/// Whether `a` can be a NEXT_HOP: RFC 4271 section 6.3 asks for a valid
/// IP host address. Addresses in 0.0.0.0/8 (this network), 127.0.0.0/8
/// (loopback), 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved, with
/// the broadcast address) are not.
fn host_address(a: Ipv4Addr) -> bool {
    !matches!(a.octets()[0], 0 | 127 | 224..=255)
}

fn put_asn(v: &mut Vec<u8>, asn: u32, four: bool) -> Result<(), Error> {
    if four {
        v.extend_from_slice(&asn.to_be_bytes());
    } else {
        let a = u16::try_from(asn).map_err(|_| Error::Unwritable)?;
        v.extend_from_slice(&a.to_be_bytes());
    }
    Ok(())
}

fn put_attribute(out: &mut Vec<u8>, flags: u8, kind: u8, value: &[u8]) -> Result<(), Error> {
    if value.len() > MAX_BODY_LEN {
        return Err(Error::Unwritable);
    }
    if value.len() > 255 {
        out.push(flags | flag::EXTENDED_LENGTH);
        out.push(kind);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    } else {
        out.push(flags);
        out.push(kind);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
    bound(out)
}

fn write_nlri(v: &mut Vec<u8>, afi: u16, safi: u8, nlri: &Nlri) -> Result<(), Error> {
    match (nlri, prefix_family(afi, safi)) {
        (Nlri::Prefixes(p), true) => write_prefixes(v, p, afi == afi::IPV6),
        (Nlri::Raw(r), false) => {
            if r.len() > MAX_BODY_LEN {
                return Err(Error::Unwritable);
            }
            v.extend_from_slice(r);
            bound(v)
        }
        _ => Err(Error::Unwritable),
    }
}

/// Reads AS_PATH segments. A segment with no AS numbers, or with AS 0
/// (RFC 7607), makes the path malformed.
fn parse_as_path(mut r: &[u8], four: bool) -> Option<Vec<Segment>> {
    let size = if four { 4 } else { 2 };
    let mut out = Vec::new();
    while !r.is_empty() {
        let kind = SegmentKind::from_code(take_u8(&mut r)?)?;
        let count = usize::from(take_u8(&mut r)?);
        if count == 0 {
            return None;
        }
        let bytes = take(&mut r, count * size)?;
        let asns: Vec<u32> = bytes
            .chunks_exact(size)
            .map(|c| if four { u32::from_be_bytes([c[0], c[1], c[2], c[3]]) } else { u32::from(be16(c, 0)) })
            .collect();
        if asns.contains(&0) {
            return None;
        }
        out.push(Segment { kind, asns });
    }
    Some(out)
}

fn parse_nlri(r: &[u8], afi: u16, safi: u8) -> Option<Nlri> {
    if prefix_family(afi, safi) {
        Some(Nlri::Prefixes(read_prefixes(r, afi == afi::IPV6)?))
    } else {
        Some(Nlri::Raw(r.to_vec()))
    }
}

fn parse_mp_reach(mut r: &[u8]) -> Option<MpReach> {
    let afi = take_u16(&mut r)?;
    let safi = take_u8(&mut r)?;
    let n = take_u8(&mut r)?;
    if !next_hop_length(afi, safi, usize::from(n)) {
        return None;
    }
    let next_hop = take(&mut r, usize::from(n))?.to_vec();
    let _reserved = take_u8(&mut r)?;
    Some(MpReach { afi, safi, next_hop, nlri: parse_nlri(r, afi, safi)? })
}

fn parse_mp_unreach(mut r: &[u8]) -> Option<MpUnreach> {
    let afi = take_u16(&mut r)?;
    let safi = take_u8(&mut r)?;
    Some(MpUnreach { afi, safi, withdrawn: parse_nlri(r, afi, safi)? })
}

/// The well-known attributes an UPDATE needs, given whether it carries
/// IPv4 NLRI and whether it has an MP_REACH_NLRI. It returns the first
/// one missing.
fn missing(seen: &[bool; 256], nlri: bool) -> Option<u8> {
    let reach = seen[usize::from(attr::MP_REACH_NLRI)];
    if !nlri && !reach {
        return None;
    }
    let need: &[u8] =
        if nlri { &[attr::ORIGIN, attr::AS_PATH, attr::NEXT_HOP] } else { &[attr::ORIGIN, attr::AS_PATH] };
    need.iter().copied().find(|&k| !seen[usize::from(k)])
}

impl Update {
    /// Reads an UPDATE's body, the bytes after the header, as RFC 4271
    /// does: every error is one that closes the connection. `negotiated` says how
    /// many octets an AS number takes. A body longer than
    /// [`MAX_BODY_LEN`] is a bad length. Two things RFC 6793 drops without
    /// an error are dropped here too: AS4_PATH and AS4_AGGREGATOR in a
    /// four-octet session, and malformed ones in a two-octet session.
    /// MP_REACH_NLRI and MP_UNREACH_NLRI come first in the attributes
    /// read, wherever they were in the message.
    pub fn parse(b: &[u8], negotiated: &Context) -> Result<Update, Error> {
        read_update(b, negotiated, true).map(|r| r.update)
    }

    /// Reads an UPDATE's body with the error handling of RFC 7606, which
    /// closes the connection only when the routes cannot be told apart.
    /// The error it returns is one of those, and its NOTIFICATION is sent.
    /// For other errors it returns what it read and says what to do with
    /// it. LOCAL_PREF is handled as from an internal peer; a world peering
    /// with an external one drops it itself.
    pub fn receive(b: &[u8], negotiated: &Context) -> Result<Received, Error> {
        read_update(b, negotiated, false)
    }

    /// The attribute of type `kind`, if the UPDATE has one.
    pub fn attribute(&self, kind: u8) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.kind() == kind)
    }

    fn to_body(&self, negotiated: &Context) -> Result<Vec<u8>, Error> {
        // RFC 7606 section 5.1: one kind of routes per UPDATE, and an
        // MP_REACH_NLRI or MP_UNREACH_NLRI first.
        let is_mp = |a: &Attribute| matches!(a, Attribute::MpReach(_) | Attribute::MpUnreach(_));
        let mp = self.attributes.iter().filter(|a| is_mp(a)).count();
        if usize::from(!self.withdrawn.is_empty()) + usize::from(!self.nlri.is_empty()) + mp > 1 {
            return Err(Error::Unwritable);
        }
        if mp == 1 && !self.attributes.first().is_some_and(is_mp) {
            return Err(Error::Unwritable);
        }
        let mut out = vec![0, 0];
        write_prefixes(&mut out, &self.withdrawn, false)?;
        let wlen = (out.len() - 2) as u16;
        out[..2].copy_from_slice(&wlen.to_be_bytes());
        let at = out.len();
        out.extend_from_slice(&[0, 0]);
        let mut seen = [false; 256];
        for a in &self.attributes {
            if core::mem::replace(&mut seen[usize::from(a.kind())], true) {
                return Err(Error::Unwritable);
            }
            a.write(&mut out, negotiated)?;
        }
        let alen = (out.len() - at - 2) as u16;
        out[at..at + 2].copy_from_slice(&alen.to_be_bytes());
        write_prefixes(&mut out, &self.nlri, false)?;
        if missing(&seen, !self.nlri.is_empty()).is_some() {
            return Err(Error::Unwritable);
        }
        bound(&out)?;
        Ok(out)
    }
}

/// An UPDATE read with the error handling of RFC 7606, by
/// [`Update::receive`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Received {
    /// What was read. Attributes dropped are left out. The routes are kept
    /// even when `withdraw` is set, so the caller knows which to withdraw.
    pub update: Update,
    /// Set when the routes the UPDATE announces, in `nlri` and in an
    /// MP_REACH_NLRI, are to be handled as withdrawn ("treat-as-withdraw").
    /// It holds the first error that asked for it, for the log; no
    /// NOTIFICATION is sent.
    pub withdraw: Option<Error>,
    /// Attributes dropped, one error each, and the UPDATE read on without
    /// them: a malformed ATOMIC_AGGREGATE, AGGREGATOR, AS4_PATH or
    /// AS4_AGGREGATOR, and `MalformedAttributeList` for each attribute of a
    /// type already read.
    pub discarded: Vec<Error>,
}

/// What RFC 7606 does about an error in an UPDATE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handling {
    /// Drop the attribute and read on.
    AttributeDiscard,
    /// Handle the UPDATE's routes as withdrawn.
    TreatAsWithdraw,
    /// Send the NOTIFICATION and close the connection.
    SessionReset,
}

/// How RFC 7606 sections 3 and 7, and RFC 6793 section 6, handle an error
/// in an attribute of type `kind`.
fn handling(kind: u8, e: &Error) -> Handling {
    match (kind, e) {
        (_, Error::UnrecognizedWellKnownAttribute(_)) => Handling::SessionReset,
        (attr::MP_REACH_NLRI | attr::MP_UNREACH_NLRI, _) => Handling::SessionReset,
        (attr::ATOMIC_AGGREGATE | attr::AGGREGATOR | attr::AS4_PATH | attr::AS4_AGGREGATOR, _) => {
            Handling::AttributeDiscard
        }
        _ => Handling::TreatAsWithdraw,
    }
}

/// Reads an UPDATE's body. `strict` returns the first error, as RFC 4271
/// does; otherwise errors are handled as RFC 7606 says.
fn read_update(b: &[u8], negotiated: &Context, strict: bool) -> Result<Received, Error> {
    if b.len() > MAX_BODY_LEN {
        return Err(Error::BadMessageLength(length_field(b)));
    }
    let mut r = b;
    let wlen = take_u16(&mut r).ok_or(Error::MalformedAttributeList)?;
    let withdrawn = take(&mut r, usize::from(wlen)).ok_or(Error::MalformedAttributeList)?;
    let alen = take_u16(&mut r).ok_or(Error::MalformedAttributeList)?;
    let mut attrs = take(&mut r, usize::from(alen)).ok_or(Error::MalformedAttributeList)?;
    let withdrawn = read_prefixes(withdrawn, false).ok_or(Error::InvalidNetworkField)?;
    // RFC 7606 reads the NLRI first: an error in it closes the connection
    // whatever the attributes hold.
    let early = if strict { None } else { Some(read_prefixes(r, false).ok_or(Error::InvalidNetworkField)?) };

    // Types met, whether read or not, and types read and kept.
    let mut seen = [false; 256];
    let mut have = [false; 256];
    let mut broken = false;
    let mut attributes = Vec::new();
    let mut withdraw = None;
    let mut discarded = Vec::new();
    while !attrs.is_empty() {
        let all = attrs;
        let header = (|| {
            let (flags, kind) = (take_u8(&mut attrs)?, take_u8(&mut attrs)?);
            let n = if flags & flag::EXTENDED_LENGTH != 0 {
                usize::from(take_u16(&mut attrs)?)
            } else {
                usize::from(take_u8(&mut attrs)?)
            };
            Some((flags, kind, take(&mut attrs, n)?))
        })();
        let Some((flags, kind, value)) = header else {
            // RFC 7606 section 4: an attribute that runs past the total
            // attribute length, which still says where the NLRI starts.
            if strict {
                return Err(Error::MalformedAttributeList);
            }
            withdraw.get_or_insert(Error::MalformedAttributeList);
            broken = true;
            break;
        };
        let raw = &all[..all.len() - attrs.len()];
        if core::mem::replace(&mut seen[usize::from(kind)], true) {
            // RFC 7606 section 3 (g): a repeated MP attribute closes the
            // connection; other repeats are dropped.
            if strict || kind == attr::MP_REACH_NLRI || kind == attr::MP_UNREACH_NLRI {
                return Err(Error::MalformedAttributeList);
            }
            discarded.push(Error::MalformedAttributeList);
            continue;
        }
        match Attribute::parse(flags, kind, value, raw, negotiated) {
            Ok(Some(a)) => {
                have[usize::from(kind)] = true;
                attributes.push(a);
            }
            Ok(None) => {}
            Err(e) => {
                let h = handling(kind, &e);
                let as4 = kind == attr::AS4_PATH || kind == attr::AS4_AGGREGATOR;
                if h == Handling::SessionReset || (strict && !as4) {
                    return Err(e);
                }
                if h == Handling::TreatAsWithdraw {
                    withdraw.get_or_insert(e);
                } else if !strict {
                    discarded.push(e);
                }
            }
        }
    }
    let nlri = match early {
        Some(n) => n,
        None => read_prefixes(r, false).ok_or(Error::InvalidNetworkField)?,
    };
    if let Some(k) = missing(&have, !nlri.is_empty()) {
        // RFC 7606 section 3 (d).
        if strict {
            return Err(Error::MissingWellKnownAttribute(k));
        }
        withdraw.get_or_insert(Error::MissingWellKnownAttribute(k));
    }
    // RFC 7606 section 5.2: an UPDATE that announces nothing but carries
    // attributes other than MP_UNREACH_NLRI cannot be trusted to have been
    // read, so an error stronger than a discard closes the connection.
    if let Some(e) = &withdraw {
        let announces = !nlri.is_empty() || have[usize::from(attr::MP_REACH_NLRI)];
        let others = broken || seen.iter().enumerate().any(|(k, &s)| s && k != usize::from(attr::MP_UNREACH_NLRI));
        if !announces && others {
            return Err(e.clone());
        }
    }
    // RFC 7606 section 5.1 puts MP_REACH_NLRI and MP_UNREACH_NLRI first.
    attributes.sort_by_key(|a| !matches!(a, Attribute::MpReach(_) | Attribute::MpUnreach(_)));
    Ok(Received { update: Update { withdrawn, attributes, nlri }, withdraw, discarded })
}

/// A NOTIFICATION message: an error code, a subcode and data that depends
/// on them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    /// The error code, one of [`code`]'s.
    pub code: u8,
    /// The subcode, one of [`subcode`]'s for the code, or 0.
    pub subcode: u8,
    /// The data, at most [`MAX_BODY_LEN`] less 2 bytes.
    pub data: Vec<u8>,
}

impl Notification {
    fn parse(b: &[u8]) -> Option<Notification> {
        let [code, subcode, data @ ..] = b else { return None };
        Some(Notification { code: *code, subcode: *subcode, data: data.to_vec() })
    }

    fn to_body(&self) -> Result<Vec<u8>, Error> {
        if self.data.len() > MAX_BODY_LEN - 2 {
            return Err(Error::Unwritable);
        }
        let mut out = vec![self.code, self.subcode];
        out.extend_from_slice(&self.data);
        Ok(out)
    }
}

impl core::fmt::Display for Notification {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self.code {
            code::MESSAGE_HEADER => "message header error",
            code::OPEN_MESSAGE => "OPEN message error",
            code::UPDATE_MESSAGE => "UPDATE message error",
            code::HOLD_TIMER_EXPIRED => "hold timer expired",
            code::FSM => "finite state machine error",
            code::CEASE => "cease",
            code::ROUTE_REFRESH_MESSAGE => "ROUTE-REFRESH message error",
            _ => "error",
        };
        write!(f, "{name} (code {}, subcode {})", self.code, self.subcode)
    }
}

/// A ROUTE-REFRESH message (RFC 2918): a request to send the routes of one
/// address family again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRefresh {
    /// The address family.
    pub afi: u16,
    /// The byte RFC 2918 reserves. RFC 7313 uses it as a subtype: 0 for a
    /// plain request, 1 and 2 for the start and end of a refresh.
    pub subtype: u8,
    /// The subsequent address family.
    pub safi: u8,
}

impl RouteRefresh {
    fn parse(b: &[u8]) -> Option<RouteRefresh> {
        let [a0, a1, subtype, safi] = b else { return None };
        Some(RouteRefresh { afi: u16::from_be_bytes([*a0, *a1]), subtype: *subtype, safi: *safi })
    }

    fn to_body(self) -> Vec<u8> {
        let [a0, a1] = self.afi.to_be_bytes();
        vec![a0, a1, self.subtype, self.safi]
    }
}

/// The length field a message with body `b` would carry, or `u16::MAX`
/// if it does not fit.
fn length_field(b: &[u8]) -> u16 {
    u16::try_from(b.len().saturating_add(HEADER_LEN)).unwrap_or(u16::MAX)
}

/// Fails once a body being written has passed what a message can hold.
fn bound(out: &[u8]) -> Result<(), Error> {
    if out.len() > MAX_BODY_LEN { Err(Error::Unwritable) } else { Ok(()) }
}

fn take<'a>(r: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if r.len() < n {
        return None;
    }
    let (head, tail) = r.split_at(n);
    *r = tail;
    Some(head)
}

fn take_u8(r: &mut &[u8]) -> Option<u8> {
    take(r, 1).map(|b| b[0])
}

fn take_u16(r: &mut &[u8]) -> Option<u16> {
    take(r, 2).map(|b| be16(b, 0))
}

fn take_u32(r: &mut &[u8]) -> Option<u32> {
    take(r, 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream, contract, finish, pump,
        test_support::{decode_all, mutate},
    };

    fn encode(message: &Message, context: &Context) -> Result<Vec<u8>, Error> {
        message.to_frame(context)?.to_bytes()
    }

    const TWO: Context = Context { four_octet_as: false, enhanced_route_refresh: false };
    const FOUR: Context = Context { four_octet_as: true, enhanced_route_refresh: false };

    fn header(len: u16, kind: u8) -> Vec<u8> {
        let mut out = vec![0xff; 16];
        out.extend_from_slice(&len.to_be_bytes());
        out.push(kind);
        out
    }

    fn decode(bytes: &[u8], negotiated: &Context) -> Result<Message, Error> {
        let Step::Item(frame, used) = Frames.decode(bytes, true)? else { panic!("a whole frame") };
        assert_eq!(used, bytes.len());
        Message::decode(&frame, negotiated)
    }

    fn update_body(body: &[u8], negotiated: &Context) -> Result<Message, Error> {
        Message::decode(&Frame { kind: kind::UPDATE, body: body.to_vec() }, negotiated)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix {
        Prefix { addr: IpAddr::V4(Ipv4Addr::new(a, b, c, d)), length: len }
    }

    /// An OPEN for AS 65001, hold time 180, identifier 192.0.2.1, with
    /// capabilities for IPv4 unicast, route refresh and four-octet AS
    /// 65001, written out by hand from RFC 4271 section 4.2 and RFC 5492.
    fn open_bytes() -> Vec<u8> {
        let mut b = header(45, 1);
        b.extend_from_slice(&[4, 0xfd, 0xe9, 0, 180, 192, 0, 2, 1, 16]);
        b.extend_from_slice(&[2, 14, 1, 4, 0, 1, 0, 1, 2, 0, 65, 4, 0, 0, 0xfd, 0xe9]);
        b
    }

    /// An UPDATE that announces 10.0.0.0/8 from AS 65001 with next hop
    /// 192.0.2.1, two-octet AS numbers.
    fn update_bytes() -> Vec<u8> {
        let mut b = header(19 + 4 + 18 + 2, 2);
        b.extend_from_slice(&[0, 0, 0, 18]);
        b.extend_from_slice(&[0x40, 1, 1, 0]);
        b.extend_from_slice(&[0x40, 2, 4, 2, 1, 0xfd, 0xe9]);
        b.extend_from_slice(&[0x40, 3, 4, 192, 0, 2, 1]);
        b.extend_from_slice(&[8, 10]);
        b
    }

    fn samples() -> Vec<(Vec<u8>, Context)> {
        let keep = {
            let mut b = header(19, 4);
            b.truncate(19);
            b
        };
        let mut refresh = header(23, 5);
        refresh.extend_from_slice(&[0, 2, 0, 1]);
        let mut note = header(23, 3);
        note.extend_from_slice(&[6, 2, 0xaa, 0xbb]);
        let mp = encode(&Message::Update(Update {
            withdrawn: vec![],
            attributes: vec![
                Attribute::MpReach(MpReach {
                    afi: afi::IPV6,
                    safi: safi::UNICAST,
                    next_hop: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    nlri: Nlri::Prefixes(vec![Prefix::new("2001:db8:1::".parse().unwrap(), 48).unwrap()]),
                }),
                Attribute::Origin(Origin::Egp),
                Attribute::AsPath(vec![
                    Segment { kind: SegmentKind::Sequence, asns: vec![4_200_000_000, 65001] },
                    Segment { kind: SegmentKind::Set, asns: vec![1, 2, 3] },
                ]),
                Attribute::Med(7),
                Attribute::LocalPref(100),
                Attribute::AtomicAggregate,
                Attribute::Aggregator { asn: 4_200_000_000, address: Ipv4Addr::new(10, 0, 0, 1), partial: false },
                Attribute::Communities { values: vec![0xfde9_0001, 0xffff_ff01], partial: true },
                Attribute::Unknown { flags: 0xc0, kind: 32, value: vec![0; 300] },
            ],
            nlri: vec![],
        }), &FOUR)
        .unwrap();
        let unreach = encode(&Message::Update(Update {
            attributes: vec![Attribute::MpUnreach(MpUnreach {
                afi: 25,
                safi: 65,
                withdrawn: Nlri::Raw(vec![1, 2, 3]),
            })],
            ..Update::default()
        }), &FOUR)
        .unwrap();
        // A two-octet session that carries the four-octet path and
        // aggregator beside AS_TRANS.
        let as4 = encode(&Message::Update(Update {
            withdrawn: vec![],
            attributes: vec![
                Attribute::Origin(Origin::Igp),
                Attribute::AsPath(vec![Segment {
                    kind: SegmentKind::Sequence,
                    asns: vec![u32::from(AS_TRANS), 65001],
                }]),
                Attribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
                Attribute::Aggregator { asn: u32::from(AS_TRANS), address: Ipv4Addr::new(10, 0, 0, 1), partial: true },
                Attribute::Unknown {
                    flags: 0xe0,
                    kind: attr::AS4_PATH,
                    value: vec![2, 2, 0xfa, 0x56, 0xea, 0, 0, 0, 0xfd, 0xe9],
                },
                Attribute::Unknown {
                    flags: 0xc0,
                    kind: attr::AS4_AGGREGATOR,
                    value: vec![0xfa, 0x56, 0xea, 0, 10, 0, 0, 1],
                },
            ],
            nlri: vec![v4(198, 51, 100, 0, 24)],
        }), &TWO)
        .unwrap();
        vec![
            (open_bytes(), TWO),
            (update_bytes(), TWO),
            (keep, TWO),
            (refresh, TWO),
            (note, TWO),
            (mp, FOUR),
            (unreach, FOUR),
            (as4, TWO),
        ]
    }

    #[test]
    fn keepalive_example() {
        // RFC 4271 section 4.4: a KEEPALIVE is the header alone, 19 bytes.
        let b = encode(&Message::Keepalive, &TWO).unwrap();
        let mut want = vec![0xff; 16];
        want.extend_from_slice(&[0, 19, 4]);
        assert_eq!(b, want);
        assert_eq!(decode(&b, &TWO), Ok(Message::Keepalive));
    }

    #[test]
    fn open_example() {
        let b = open_bytes();
        let Message::Open(open) = decode(&b, &TWO).unwrap() else { panic!() };
        assert_eq!(open.my_as, 65001);
        assert_eq!(open.hold_time, 180);
        assert_eq!(open.bgp_id, Ipv4Addr::new(192, 0, 2, 1));
        let caps: Vec<_> = open.capabilities().cloned().collect();
        assert_eq!(
            caps,
            [
                Capability::Multiprotocol { afi: afi::IPV4, safi: safi::UNICAST },
                Capability::RouteRefresh,
                Capability::FourOctetAs(65001),
            ]
        );
        assert_eq!(open.asn(), 65001);
        assert_eq!(encode(&Message::Open(open.clone()), &TWO).unwrap(), b);
        // Open::new builds the same message.
        let built = Open::new(
            65001,
            180,
            Ipv4Addr::new(192, 0, 2, 1),
            vec![Capability::Multiprotocol { afi: afi::IPV4, safi: safi::UNICAST }, Capability::RouteRefresh],
        );
        assert_eq!(built, open);
    }

    #[test]
    fn open_with_other_parameters_and_capabilities() {
        let open = Open {
            my_as: AS_TRANS,
            hold_time: 0,
            bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            parameters: vec![
                Parameter::Other { kind: 1, value: vec![0, 1, 2] },
                Parameter::Capabilities(vec![
                    Capability::GracefulRestart(GracefulRestart {
                        flags: 8,
                        time: 120,
                        families: vec![RestartFamily { afi: 1, safi: 1, flags: 0x80 }],
                    }),
                    Capability::Other { code: 70, value: vec![] },
                    Capability::Other { code: 128, value: vec![9, 9] },
                    Capability::FourOctetAs(4_200_000_000),
                ]),
                Parameter::Capabilities(vec![]),
            ],
        };
        let b = encode(&Message::Open(open.clone()), &TWO).unwrap();
        // The graceful restart value: flags 8 in the top bits, time 120.
        let at = b.windows(2).position(|w| w == [64, 6]).unwrap();
        assert_eq!(b[at + 2..at + 8], [0x80, 120, 0, 1, 1, 0x80]);
        assert_eq!(decode(&b, &TWO), Ok(Message::Open(open.clone())));
        assert_eq!(open.asn(), 4_200_000_000);
        let plain = Open { parameters: vec![], ..open.clone() };
        assert_eq!(plain.asn(), u32::from(AS_TRANS));
        assert_eq!(Context::negotiated(&open, &plain), TWO);
        // Both sent capability 70, enhanced route refresh, too.
        assert_eq!(Context::negotiated(&open, &open), Context { enhanced_route_refresh: true, ..FOUR });
    }

    #[test]
    fn update_example() {
        let b = update_bytes();
        let Message::Update(u) = decode(&b, &TWO).unwrap() else { panic!() };
        assert_eq!(u.withdrawn, []);
        assert_eq!(
            u.attributes,
            [
                Attribute::Origin(Origin::Igp),
                Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns: vec![65001] }]),
                Attribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
            ]
        );
        assert_eq!(u.nlri, [v4(10, 0, 0, 0, 8)]);
        assert_eq!(u.attribute(attr::NEXT_HOP), Some(&Attribute::NextHop(Ipv4Addr::new(192, 0, 2, 1))));
        assert_eq!(u.attribute(attr::MED), None);
        assert_eq!(encode(&Message::Update(u.clone()), &TWO).unwrap(), b);
        // With four-octet AS numbers the AS_PATH reads differently: 1 AS
        // of 4 bytes needs 6 bytes of value, and 4 is too short.
        assert_eq!(decode(&b, &FOUR), Err(Error::MalformedAsPath));
        let four = encode(&Message::Update(u), &FOUR).unwrap();
        assert_eq!(four.len(), b.len() + 2);
        assert_eq!(four[19 + 4 + 4..19 + 4 + 4 + 9], [0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe9]);
    }

    #[test]
    fn withdraw_only_update_and_end_of_rib() {
        // An UPDATE with nothing in it is the IPv4 End-of-RIB marker
        // (RFC 4724).
        let mut b = header(23, 2);
        b.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(decode(&b, &TWO), Ok(Message::Update(Update::default())));
        let u = Update { withdrawn: vec![v4(192, 168, 0, 0, 16), v4(0, 0, 0, 0, 0)], ..Update::default() };
        let b = encode(&Message::Update(u.clone()), &TWO).unwrap();
        assert_eq!(b[19..], [0, 4, 16, 192, 168, 0, 0, 0]);
        assert_eq!(decode(&b, &TWO), Ok(Message::Update(u)));
    }

    #[test]
    fn mp_reach_ipv6_example() {
        // MP_REACH_NLRI for 2001:db8::/32 via 2001:db8::1 (RFC 4760
        // section 3), with ORIGIN and an empty AS_PATH.
        let mut body = vec![0, 0, 0, 36];
        body.extend_from_slice(&[0x40, 1, 1, 2, 0x40, 2, 0]);
        body.extend_from_slice(&[0x80, 14, 26, 0, 2, 1, 16]);
        body.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        body.extend_from_slice(&[0, 32, 0x20, 0x01, 0x0d, 0xb8]);
        let Message::Update(u) = update_body(&body, &TWO).unwrap() else { panic!() };
        let Some(Attribute::MpReach(m)) = u.attribute(attr::MP_REACH_NLRI) else { panic!() };
        assert_eq!(m.afi, afi::IPV6);
        assert_eq!(m.next_hop.len(), 16);
        assert_eq!(m.nlri, Nlri::Prefixes(vec![Prefix::new("2001:db8::".parse().unwrap(), 32).unwrap()]));
        assert_eq!(u.attribute(attr::AS_PATH), Some(&Attribute::AsPath(vec![])));
        // The reader puts MP_REACH_NLRI first, where RFC 7606 section 5.1
        // has a writer put it.
        assert_eq!(u.attributes[0].kind(), attr::MP_REACH_NLRI);
        let mut moved = body[..4].to_vec();
        moved.extend_from_slice(&body[11..]);
        moved.extend_from_slice(&body[4..11]);
        assert_eq!(Message::Update(u).to_frame(&TWO).unwrap().body, moved);
        // Without ORIGIN the routes are refused.
        let mut b = vec![0, 0, 0, 32];
        b.extend_from_slice(&body[8..]);
        assert_eq!(update_body(&b, &TWO), Err(Error::MissingWellKnownAttribute(attr::ORIGIN)));
    }

    #[test]
    fn notification_and_route_refresh_examples() {
        let n = Notification { code: code::CEASE, subcode: 2, data: b"bye".to_vec() };
        let b = encode(&Message::Notification(n.clone()), &TWO).unwrap();
        assert_eq!(b[16..], [0, 24, 3, 6, 2, b'b', b'y', b'e']);
        assert_eq!(decode(&b, &TWO), Ok(Message::Notification(n.clone())));
        assert_eq!(n.to_string(), "cease (code 6, subcode 2)");
        let r = RouteRefresh { afi: afi::IPV6, subtype: 0, safi: safi::UNICAST };
        let b = encode(&Message::RouteRefresh(r), &TWO).unwrap();
        assert_eq!(b[16..], [0, 23, 5, 0, 2, 0, 1]);
        assert_eq!(decode(&b, &TWO), Ok(Message::RouteRefresh(r)));
    }

    #[test]
    fn prefixes() {
        let p = Prefix::new(Ipv4Addr::new(10, 1, 2, 3).into(), 12).unwrap();
        assert_eq!(p, v4(10, 0, 0, 0, 12));
        assert_eq!(p.to_string(), "10.0.0.0/12");
        assert_eq!(Prefix::new(Ipv4Addr::new(1, 2, 3, 4).into(), 0).unwrap(), v4(0, 0, 0, 0, 0));
        assert_eq!(Prefix::new(Ipv4Addr::new(1, 2, 3, 4).into(), 32).unwrap(), v4(1, 2, 3, 4, 32));
        assert_eq!(Prefix::new(Ipv4Addr::new(1, 2, 3, 4).into(), 33), None);
        assert!(Prefix::new(Ipv6Addr::LOCALHOST.into(), 128).is_some());
        assert_eq!(Prefix::new(Ipv6Addr::LOCALHOST.into(), 129), None);
        // Bits past the length are cleared, and written as 0.
        let b = vec![0, 2, 7, 0xff, 0, 0];
        let Message::Update(u) = update_body(&b, &TWO).unwrap() else { panic!() };
        assert_eq!(u.withdrawn, [v4(254, 0, 0, 0, 7)]);
        assert_eq!(Message::Update(u).to_frame(&TWO).unwrap().body, [0, 2, 7, 0xfe, 0, 0]);
    }

    #[test]
    fn header_errors() {
        assert_eq!(Frames.decode(&[0xff, 0xff, 0xfe], false), Err(Error::ConnectionNotSynchronized));
        let mut b = header(18, 4);
        assert_eq!(Frames.decode(&b, false), Err(Error::BadMessageLength(18)));
        b = header(4097, 4);
        assert_eq!(Frames.decode(&b, false), Err(Error::BadMessageLength(4097)));
        assert_eq!(Frames.decode(&header(4096, 4), false), Ok(Step::Need));
        b = header(19, 9);
        assert_eq!(decode(&b, &TWO), Err(Error::BadMessageType(9)));
        b = header(19, 0);
        assert_eq!(decode(&b, &TWO), Err(Error::BadMessageType(0)));
        // Lengths wrong for the type.
        let mut k = header(20, 4);
        k.push(0);
        assert_eq!(decode(&k, &TWO), Err(Error::BadMessageLength(20)));
        let mut r = header(22, 5);
        r.extend_from_slice(&[0, 1, 0]);
        assert_eq!(decode(&r, &TWO), Err(Error::BadMessageLength(22)));
        let mut n = header(20, 3);
        n.push(6);
        assert_eq!(decode(&n, &TWO), Err(Error::BadMessageLength(20)));
        let mut o = header(28, 1);
        o.extend_from_slice(&[4, 0, 1, 0, 0, 1, 1, 1, 1]);
        assert_eq!(decode(&o, &TWO), Err(Error::BadMessageLength(28)));
        let mut u = header(22, 2);
        u.extend_from_slice(&[0, 0, 0]);
        assert_eq!(decode(&u, &TWO), Err(Error::BadMessageLength(22)));
        // A frame built by hand with a body too long for any message.
        let big = Frame { kind: kind::NOTIFICATION, body: vec![0; MAX_BODY_LEN + 1] };
        assert_eq!(Message::decode(&big, &TWO), Err(Error::BadMessageLength(4097)));
        assert_eq!(big.to_bytes(), Err(Error::Unwritable));
        // Bodies passed straight to the readers, too short.
        assert_eq!(Open::parse(&[4, 0]), Err(Error::BadMessageLength(21)));
        assert_eq!(Update::parse(&[0], &TWO), Err(Error::MalformedAttributeList));
    }

    #[test]
    fn open_errors() {
        let base = open_bytes();
        let with = |at: usize, v: u8| {
            let mut b = base.clone();
            b[at] = v;
            decode(&b, &TWO)
        };
        assert_eq!(with(19, 3), Err(Error::UnsupportedVersion(3)));
        assert_eq!(with(23, 1), Err(Error::UnacceptableHoldTime));
        assert_eq!(with(23, 2), Err(Error::UnacceptableHoldTime));
        assert!(with(23, 0).is_ok());
        assert!(with(23, 3).is_ok());
        let mut zero = base.clone();
        zero[24..28].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(decode(&zero, &TWO), Err(Error::BadBgpIdentifier));
        // Optional parameters length that does not match.
        assert_eq!(with(28, 15), Err(Error::MalformedOpen));
        assert_eq!(with(28, 17), Err(Error::MalformedOpen));
        // A parameter that runs past the end.
        assert_eq!(with(30, 15), Err(Error::MalformedOpen));
        // A capability that runs past its parameter.
        assert_eq!(with(40, 5), Err(Error::MalformedOpen));
        // Known capabilities of the wrong length.
        assert_eq!(with(32, 3), Err(Error::MalformedOpen));
        assert_eq!(with(38, 1), Err(Error::MalformedOpen));
        let mut gr = header(19 + 10 + 2 + 2 + 1, 1);
        gr.extend_from_slice(&[4, 0, 1, 0, 0, 1, 1, 1, 1, 5, 2, 3, 64, 1, 0]);
        assert_eq!(decode(&gr, &TWO), Err(Error::MalformedOpen));
        // A parameter header cut in half.
        let mut half = header(19 + 11, 1);
        half.extend_from_slice(&[4, 0, 1, 0, 0, 1, 1, 1, 1, 1, 2]);
        assert_eq!(decode(&half, &TWO), Err(Error::MalformedOpen));
        let mut cap_half = header(19 + 13, 1);
        cap_half.extend_from_slice(&[4, 0, 1, 0, 0, 1, 1, 1, 1, 3, 2, 1, 65]);
        assert_eq!(decode(&cap_half, &TWO), Err(Error::MalformedOpen));
    }

    #[test]
    fn update_errors() {
        let e = |b: &[u8]| update_body(b, &TWO);
        // Lengths that run past the body.
        assert_eq!(e(&[0, 5, 0, 0]), Err(Error::MalformedAttributeList));
        assert_eq!(e(&[0, 0, 0, 5]), Err(Error::MalformedAttributeList));
        assert_eq!(e(&[0, 1, 8, 0]), Err(Error::MalformedAttributeList));
        // Bad withdrawn prefixes and NLRI.
        assert_eq!(e(&[0, 1, 33, 0, 0]), Err(Error::InvalidNetworkField));
        assert_eq!(e(&[0, 1, 9, 0, 0]), Err(Error::InvalidNetworkField));
        assert_eq!(e(&[0, 0, 0, 0, 24, 1, 2]), Err(Error::InvalidNetworkField));
        // An attribute cut short: header, extended length, value.
        assert_eq!(e(&[0, 0, 0, 2, 0x40, 1]), Err(Error::MalformedAttributeList));
        assert_eq!(e(&[0, 0, 0, 3, 0x50, 1, 0]), Err(Error::MalformedAttributeList));
        assert_eq!(e(&[0, 0, 0, 3, 0x40, 1, 1]), Err(Error::MalformedAttributeList));
        // The same attribute twice.
        assert_eq!(e(&[0, 0, 0, 8, 0x40, 1, 1, 0, 0x40, 1, 1, 0]), Err(Error::MalformedAttributeList));
        // An unknown attribute without the optional bit.
        assert_eq!(e(&[0, 0, 0, 4, 0x40, 99, 1, 7]), Err(Error::UnrecognizedWellKnownAttribute(vec![0x40, 99, 1, 7])));
        // Flags that do not match the type.
        assert_eq!(e(&[0, 0, 0, 4, 0xc0, 1, 1, 0]), Err(Error::AttributeFlags(vec![0xc0, 1, 1, 0])));
        assert_eq!(e(&[0, 0, 0, 4, 0x60, 1, 1, 0]), Err(Error::AttributeFlags(vec![0x60, 1, 1, 0])));
        assert_eq!(e(&[0, 0, 0, 7, 0xa0, 4, 4, 0, 0, 0, 1]), Err(Error::AttributeFlags(vec![0xa0, 4, 4, 0, 0, 0, 1])));
        assert_eq!(e(&[0, 0, 0, 3, 0x80, 8, 0]), Err(Error::AttributeFlags(vec![0x80, 8, 0])));
        // Lengths that do not match the type.
        let len_err = |raw: &[u8]| {
            let mut b = vec![0, 0, 0, raw.len() as u8];
            b.extend_from_slice(raw);
            assert_eq!(e(&b), Err(Error::AttributeLength(raw.to_vec())), "{raw:?}");
        };
        len_err(&[0x40, 1, 2, 0, 0]);
        len_err(&[0x40, 1, 0]);
        len_err(&[0x40, 3, 3, 1, 2, 3]);
        len_err(&[0x80, 4, 5, 0, 0, 0, 0, 0]);
        len_err(&[0x40, 5, 2, 0, 0]);
        len_err(&[0x40, 6, 1, 0]);
        len_err(&[0xc0, 7, 8, 0, 0, 0, 1, 10, 0, 0, 1]);
        len_err(&[0xc0, 8, 3, 0, 0, 0]);
        // In a four-octet session an AGGREGATOR takes 8 bytes, not 6.
        let mut b = vec![0, 0, 0, 9, 0xc0, 7, 6, 0, 1, 10, 0, 0, 1];
        assert!(e(&b).is_ok());
        assert_eq!(update_body(&b, &FOUR), Err(Error::AttributeLength(b[4..].to_vec())));
        b = vec![0, 0, 0, 11, 0xc0, 7, 8, 0, 0, 0, 1, 10, 0, 0, 1];
        assert!(update_body(&b, &FOUR).is_ok());
        // An ORIGIN of 3.
        assert_eq!(e(&[0, 0, 0, 4, 0x40, 1, 1, 3]), Err(Error::InvalidOrigin(vec![0x40, 1, 1, 3])));
        // AS_PATHs that cannot be read: segment type 0 and 5, a count of 0,
        // too few AS numbers, a header cut in half.
        for path in [&[0u8, 1, 0, 1][..], &[5, 1, 0, 1], &[2, 0], &[2, 2, 0, 1], &[2]] {
            let mut b = vec![0, 0, 0, 3 + path.len() as u8, 0x40, 2, path.len() as u8];
            b.extend_from_slice(path);
            assert_eq!(e(&b), Err(Error::MalformedAsPath), "{path:?}");
        }
        // MP_REACH_NLRI and MP_UNREACH_NLRI that cannot be read.
        for v in [&[0u8, 2, 1][..], &[0, 2, 1, 4, 0, 0], &[0, 2, 1, 0, 0, 129, 0], &[0, 1, 1, 0, 0, 8]] {
            let mut raw = vec![0x80, 14, v.len() as u8];
            raw.extend_from_slice(v);
            let mut b = vec![0, 0, 0, raw.len() as u8];
            b.extend_from_slice(&raw);
            assert_eq!(e(&b), Err(Error::OptionalAttribute(raw)), "{v:?}");
        }
        for v in [&[0u8, 2][..], &[0, 1, 2, 33]] {
            let mut raw = vec![0x80, 15, v.len() as u8];
            raw.extend_from_slice(v);
            let mut b = vec![0, 0, 0, raw.len() as u8];
            b.extend_from_slice(&raw);
            assert_eq!(e(&b), Err(Error::OptionalAttribute(raw)), "{v:?}");
        }
        // Routes without the attributes they need.
        assert_eq!(e(&[0, 0, 0, 0, 8, 10]), Err(Error::MissingWellKnownAttribute(attr::ORIGIN)));
        assert_eq!(e(&[0, 0, 0, 4, 0x40, 1, 1, 0, 8, 10]), Err(Error::MissingWellKnownAttribute(attr::AS_PATH)));
        assert_eq!(
            e(&[0, 0, 0, 7, 0x40, 1, 1, 0, 0x40, 2, 0, 8, 10]),
            Err(Error::MissingWellKnownAttribute(attr::NEXT_HOP))
        );
        // Unknown optional attributes are kept, with the extended length
        // bit and the low bits dropped from their flags.
        let Ok(Message::Update(u)) = e(&[0, 0, 0, 5, 0xff, 99, 0, 1, 7]) else { panic!() };
        assert_eq!(u.attributes, [Attribute::Unknown { flags: 0xe0, kind: 99, value: vec![7] }]);
    }

    #[test]
    fn next_hop_must_be_a_host_address() {
        // RFC 4271 section 6.3: a NEXT_HOP that is not a valid IP host
        // address is an Invalid NEXT_HOP Attribute error, with the
        // attribute as data.
        let body = |a: [u8; 4]| {
            let mut b = vec![0, 0, 0, 18, 0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0, 1, 0x40, 3, 4];
            b.extend_from_slice(&a);
            b.extend_from_slice(&[8, 10]);
            b
        };
        for bad in
            [[0, 0, 0, 0], [0, 1, 2, 3], [127, 0, 0, 1], [224, 0, 0, 5], [239, 1, 1, 1], [240, 0, 0, 1], [255; 4]]
        {
            let mut raw = vec![0x40, 3, 4];
            raw.extend_from_slice(&bad);
            assert_eq!(update_body(&body(bad), &TWO), Err(Error::InvalidNextHop(raw.clone())), "{bad:?}");
            let n = Error::InvalidNextHop(raw.clone()).notification().unwrap();
            assert_eq!((n.code, n.subcode, n.data), (3, 8, raw));
            let u = Update {
                attributes: vec![
                    Attribute::Origin(Origin::Igp),
                    Attribute::AsPath(vec![]),
                    Attribute::NextHop(Ipv4Addr::from(bad)),
                ],
                nlri: vec![v4(10, 0, 0, 0, 8)],
                ..Update::default()
            };
            assert!(matches!(encode(&Message::Update(u), &TWO), Err(Error::Unwritable)));
        }
        for good in [[1, 0, 0, 0], [10, 0, 0, 1], [126, 255, 255, 255], [128, 0, 0, 1], [223, 255, 255, 254]] {
            assert!(update_body(&body(good), &TWO).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn body_readers_refuse_bodies_too_long_for_a_message() {
        // Open::parse and Update::parse are public, so world code can hand
        // them a body of any length. One longer than a message can carry
        // is refused as a bad length, so every error's NOTIFICATION can
        // still be sent and every message read can be written.
        let mut b = vec![0, 0, 0xff, 0xff, 0x50, 99, 0xff, 0xfb];
        b.extend(vec![0u8; 0xfffb]);
        let e = Update::parse(&b, &FOUR).unwrap_err();
        assert_eq!(e, Error::BadMessageLength(u16::MAX));
        assert!(encode(&Message::Notification(e.notification().unwrap()), &FOUR).is_ok());
        // 4200 withdrawn /0 routes, one byte each: well formed, but too
        // many for one message.
        let mut withdrawn = vec![0x10, 0x68];
        withdrawn.extend(vec![0u8; 0x1068]);
        withdrawn.extend_from_slice(&[0, 0]);
        assert_eq!(Update::parse(&withdrawn, &TWO), Err(Error::BadMessageLength(4204 + 19)));
        let mut open = vec![4, 0, 1, 0, 0, 1, 1, 1, 1, 0];
        open.extend(vec![0u8; MAX_BODY_LEN]);
        assert!(matches!(Open::parse(&open), Err(Error::BadMessageLength(_))));
        // The longest body still reads.
        let mut longest = ((MAX_BODY_LEN - 4) as u16).to_be_bytes().to_vec();
        longest.extend(vec![0u8; MAX_BODY_LEN - 4]);
        longest.extend_from_slice(&[0, 0]);
        assert_eq!(longest.len(), MAX_BODY_LEN);
        let u = Update::parse(&longest, &TWO).unwrap();
        assert_eq!(u.withdrawn.len(), MAX_BODY_LEN - 4);
        assert!(encode(&Message::Update(u), &TWO).is_ok());
    }

    #[test]
    fn origin_codes() {
        for o in [Origin::Igp, Origin::Egp, Origin::Incomplete] {
            assert_eq!(Origin::from_code(o.code()), Some(o));
        }
        assert_eq!(Origin::from_code(3), None);
        for c in 0..=255 {
            if let Some(k) = SegmentKind::from_code(c) {
                assert_eq!(k.code(), c);
            }
        }
    }

    #[test]
    fn notifications_for_errors() {
        let n = Error::BadMessageLength(5000).notification().unwrap();
        assert_eq!((n.code, n.subcode, &n.data[..]), (1, 2, &[0x13, 0x88][..]));
        let n = Error::UnsupportedVersion(3).notification().unwrap();
        assert_eq!((n.code, n.subcode, &n.data[..]), (2, 1, &[0, 4][..]));
        let n = Error::MissingWellKnownAttribute(3).notification().unwrap();
        assert_eq!((n.code, n.subcode, &n.data[..]), (3, 3, &[3][..]));
        let all = [
            Error::ConnectionNotSynchronized,
            Error::BadMessageLength(1),
            Error::BadMessageType(9),
            Error::MalformedOpen,
            Error::UnsupportedVersion(3),
            Error::BadBgpIdentifier,
            Error::UnacceptableHoldTime,
            Error::MalformedAttributeList,
            Error::UnrecognizedWellKnownAttribute(vec![0x40, 99, 0]),
            Error::MissingWellKnownAttribute(1),
            Error::AttributeFlags(vec![0, 1, 0]),
            Error::AttributeLength(vec![0x40, 1, 0]),
            Error::InvalidOrigin(vec![0x40, 1, 1, 9]),
            Error::InvalidNextHop(vec![0x40, 3, 4, 0, 0, 0, 0]),
            Error::OptionalAttribute(vec![0x80, 14, 0]),
            Error::InvalidNetworkField,
            Error::MalformedAsPath,
        ];
        let want = [
            (1, 1),
            (1, 2),
            (1, 3),
            (2, 0),
            (2, 1),
            (2, 3),
            (2, 6),
            (3, 1),
            (3, 2),
            (3, 3),
            (3, 4),
            (3, 5),
            (3, 6),
            (3, 8),
            (3, 9),
            (3, 10),
            (3, 11),
        ];
        for (e, (c, s)) in all.iter().zip(want) {
            let n = e.notification().unwrap();
            assert_eq!((n.code, n.subcode), (c, s), "{e}");
            // Every notification can be sent.
            let b = encode(&Message::Notification(n.clone()), &TWO).unwrap();
            assert_eq!(decode(&b, &TWO), Ok(Message::Notification(n)));
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn notifications_preserve_caller_supplied_data() {
        for len in [MAX_BODY_LEN - 2, MAX_BODY_LEN - 1] {
            let data = vec![7; len];
            for error in [
                Error::UnrecognizedWellKnownAttribute(data.clone()),
                Error::AttributeFlags(data.clone()),
                Error::AttributeLength(data.clone()),
                Error::InvalidOrigin(data.clone()),
                Error::InvalidNextHop(data.clone()),
                Error::OptionalAttribute(data.clone()),
                Error::RouteRefreshLength(data.clone()),
            ] {
                let notification = error.notification().unwrap();
                assert_eq!(notification.data, data);
                let message = Message::Notification(notification);
                if len == MAX_BODY_LEN - 2 {
                    let bytes = encode(&message, &TWO).unwrap();
                    assert_eq!(decode(&bytes, &TWO), Ok(message));
                } else {
                    assert_eq!(message.to_frame(&TWO), Err(Error::Unwritable));
                }
            }
        }
    }

    #[test]
    fn writers_refuse_what_readers_refuse() {
        let id = Ipv4Addr::new(10, 0, 0, 1);
        let open = |p: Vec<Parameter>| Message::Open(Open { my_as: 1, hold_time: 90, bgp_id: id, parameters: p });
        let bad = |m: Message, negotiated: &Context| encode(&m, negotiated).unwrap_err();
        let invalid = |m: Message, negotiated: &Context| matches!(bad(m, negotiated), Error::Unwritable);
        assert!(invalid(Message::Open(Open { hold_time: 2, ..Open::new(1, 0, id, vec![]) }), &TWO));
        assert!(invalid(Message::Open(Open::new(1, 0, Ipv4Addr::UNSPECIFIED, vec![])), &TWO));
        assert!(invalid(open(vec![Parameter::Other { kind: 2, value: vec![] }]), &TWO));
        assert!(invalid(open(vec![Parameter::Other { kind: 255, value: vec![] }]), &TWO));
        assert!(invalid(Message::Open(Open { my_as: 0, ..Open::new(1, 0, id, vec![]) }), &TWO));
        assert!(invalid(Message::Open(Open::new(0, 0, id, vec![])), &TWO));
        assert_eq!(
            bad(open(vec![Parameter::Other { kind: 1, value: vec![0; MAX_BODY_LEN] }]), &TWO),
            Error::Unwritable
        );
        let caps = |c: Vec<Capability>| open(vec![Parameter::Capabilities(c)]);
        assert!(invalid(caps(vec![Capability::Other { code: 65, value: vec![0; 4] }]), &TWO));
        assert!(invalid(caps(vec![Capability::Other { code: 9, value: vec![0; 256] }]), &TWO));
        // More than 255 bytes of capabilities take the extended format.
        assert!(encode(&caps(vec![Capability::RouteRefresh; 128]), &TWO).is_ok());
        let gr = |flags, time, n| {
            caps(vec![Capability::GracefulRestart(GracefulRestart {
                flags,
                time,
                families: vec![RestartFamily { afi: 1, safi: 1, flags: 0 }; n],
            })])
        };
        assert!(invalid(gr(16, 0, 0), &TWO));
        assert!(invalid(gr(0, 4096, 0), &TWO));
        assert!(invalid(gr(0, 0, 64), &TWO));
        assert!(encode(&gr(15, 4095, 60), &TWO).is_ok());

        let path = |asns: Vec<u32>| Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns }]);
        let route = |attributes: Vec<Attribute>| {
            Message::Update(Update { withdrawn: vec![], attributes, nlri: vec![v4(10, 0, 0, 0, 8)] })
        };
        let well_known =
            || vec![Attribute::Origin(Origin::Igp), path(vec![1]), Attribute::NextHop(Ipv4Addr::new(1, 2, 3, 4))];
        assert!(encode(&route(well_known()), &TWO).is_ok());
        // Missing attributes, and one twice.
        assert!(invalid(route(well_known()[..2].to_vec()), &TWO));
        let mut twice = well_known();
        twice.push(Attribute::Med(1));
        twice.push(Attribute::Med(2));
        assert!(invalid(route(twice), &TWO));
        // AS_PATH segments with no AS numbers, too many, or ones too big.
        let with = |a: Attribute| {
            let mut v = well_known();
            v[1] = a;
            route(v)
        };
        assert!(invalid(with(path(vec![])), &TWO));
        assert!(invalid(with(path(vec![1; 256])), &TWO));
        assert!(invalid(with(path(vec![70000])), &TWO));
        assert!(encode(&with(path(vec![70000])), &FOUR).is_ok());
        let mut agg = well_known();
        agg.push(Attribute::Aggregator { asn: 70000, address: id, partial: false });
        assert!(invalid(route(agg.clone()), &TWO));
        assert!(encode(&route(agg), &FOUR).is_ok());
        // Unknown attributes that would read as something else.
        let mut u = well_known();
        u.push(Attribute::Unknown { flags: 0xc0, kind: 8, value: vec![] });
        assert!(invalid(route(u), &TWO));
        let mut u = well_known();
        u.push(Attribute::Unknown { flags: 0x40, kind: 99, value: vec![] });
        assert!(invalid(route(u), &TWO));
        // Prefixes of the wrong family or length.
        let mut m = Update { attributes: well_known(), ..Update::default() };
        m.nlri = vec![Prefix { addr: Ipv6Addr::LOCALHOST.into(), length: 128 }];
        assert!(invalid(Message::Update(m.clone()), &TWO));
        m.nlri = vec![v4(1, 2, 3, 4, 33)];
        assert!(invalid(Message::Update(m.clone()), &TWO));
        m.nlri = vec![];
        m.withdrawn = vec![v4(1, 2, 3, 4, 40)];
        assert!(invalid(Message::Update(m), &TWO));
        // MP_REACH_NLRI: a long next hop, and NLRI in the wrong form.
        let reach = |next_hop: Vec<u8>, afi: u16, nlri: Nlri| {
            Message::Update(Update {
                attributes: vec![
                    Attribute::MpReach(MpReach { afi, safi: 1, next_hop, nlri }),
                    Attribute::Origin(Origin::Igp),
                    path(vec![1]),
                ],
                ..Update::default()
            })
        };
        assert!(invalid(reach(vec![0; 256], 2, Nlri::Prefixes(vec![])), &TWO));
        assert!(invalid(reach(vec![0; 16], 2, Nlri::Raw(vec![])), &TWO));
        assert!(invalid(reach(vec![0; 16], 9, Nlri::Prefixes(vec![])), &TWO));
        assert!(invalid(reach(vec![0; 4], 2, Nlri::Prefixes(vec![v4(1, 0, 0, 0, 8)])), &TWO));
        assert!(encode(&reach(vec![0; 4], 9, Nlri::Raw(vec![1, 2, 3])), &TWO).is_ok());
        // Too much for one message.
        let mut many = well_known();
        many.push(Attribute::Communities { values: vec![1; 1100], partial: false });
        assert_eq!(bad(route(many), &TWO), Error::Unwritable);
        let mut huge = well_known();
        huge.push(Attribute::Communities { values: vec![1; 10_000_000], partial: false });
        assert_eq!(bad(route(huge), &TWO), Error::Unwritable);
        let mut unknown = well_known();
        unknown.push(Attribute::Unknown { flags: 0x80, kind: 99, value: vec![0; 5000] });
        assert_eq!(bad(route(unknown), &TWO), Error::Unwritable);
        assert_eq!(bad(reach(vec![0; 4], 9, Nlri::Raw(vec![0; 5000])), &TWO), Error::Unwritable);
        let note = Notification { code: 6, subcode: 0, data: vec![0; MAX_BODY_LEN - 1] };
        assert_eq!(bad(Message::Notification(note), &TWO), Error::Unwritable);
        let note = Notification { code: 6, subcode: 0, data: vec![0; MAX_BODY_LEN - 2] };
        let b = encode(&Message::Notification(note), &TWO).unwrap();
        assert_eq!(b.len(), MAX_MESSAGE_LEN);
        assert!(decode(&b, &TWO).is_ok());
        assert!(!Error::Unwritable.to_string().is_empty());
    }

    #[test]
    fn samples_round_trip() {
        for (b, negotiated) in samples() {
            let m = decode(&b, &negotiated).unwrap();
            if let Message::Open(open) = &m { contract::check_wire_value(open); }
            assert_eq!(encode(&m, &negotiated).unwrap(), b, "{m:?}");
        }
    }

    #[test]
    fn every_truncated_prefix_waits_for_more() {
        for (b, negotiated) in samples() {
            for n in 0..b.len() {
                assert_eq!(Frames.decode(&b[..n], false), Ok(Step::Need), "{n} of {} bytes", b.len());
            }
            // Bodies cut short never read as the whole message, and never
            // panic.
            let frame = Frame::parse(&b).unwrap();
            let whole = Message::decode(&frame, &negotiated).unwrap();
            for n in 0..frame.body.len() {
                let cut = Frame { kind: frame.kind, body: frame.body[..n].to_vec() };
                if let Ok(m) = Message::decode(&cut, &negotiated) {
                    assert_ne!(m, whole);
                }
            }
        }
    }

    #[test]
    fn stream_splits_frames() {
        let all = samples();
        let bytes: Vec<u8> = all.iter().filter(|(_, c)| *c == TWO).flat_map(|(b, _)| b.clone()).collect();
        contract::check_decode_with_alloc_limit(|| Frames, &bytes, 2 * MAX_MESSAGE_LEN);
        let (frames, error) = decode_all(|| Frames, &bytes);
        assert_eq!(error, None);
        assert_eq!(frames.iter().map(|f| f.kind).collect::<Vec<_>>(), [1, 2, 4, 5, 3, 2]);
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&[0xff, 0xff, 0]), 3);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::ConnectionNotSynchronized))));
        assert_eq!(stream.push(&bytes), bytes.len());
        assert!(stream.next().is_none());
        assert_eq!(stream.buffered(), 3);
    }

    #[test]
    fn stream_reads_many_small_frames_in_linear_time() {
        let one = Message::Keepalive.to_frame(&TWO).unwrap().to_bytes().unwrap();
        let bytes = one.repeat(200_000);
        let started = std::time::Instant::now();
        let mut stream = Stream::new(Frames);
        let mut count = 0;
        pump(&mut stream, &bytes, |_| count += 1).unwrap();
        finish(&mut stream, |_| count += 1).unwrap();
        assert_eq!(count, 200_000);
        assert_eq!(stream.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    /// Whether an UPDATE mixes kinds of routes, which a reader takes from
    /// older speakers but a writer refuses (RFC 7606 section 5.1).
    fn mixes(m: &Message) -> bool {
        let Message::Update(u) = m else { return false };
        let mp = u.attributes.iter().filter(|a| matches!(a, Attribute::MpReach(_) | Attribute::MpUnreach(_))).count();
        usize::from(!u.withdrawn.is_empty()) + usize::from(!u.nlri.is_empty()) + mp > 1
    }

    /// Checks what the fuzz target checks: a message read can be written,
    /// unless it mixes kinds of routes, and reads back the same. The
    /// error handling of RFC 7606 closes the connection only for errors
    /// the strict reader has too.
    fn check_frame(frame: &Frame) {
        for negotiated in [TWO, FOUR] {
            if frame.kind == kind::UPDATE {
                let strict = Message::decode(frame, &negotiated);
                match Update::receive(&frame.body, &negotiated) {
                    Ok(r) => {
                        if r.withdraw.is_some() {
                            assert!(strict.is_err());
                        }
                        if let Ok(m) = strict {
                            assert_eq!(m, Message::Update(r.update));
                        }
                    }
                    Err(e) => {
                        assert!(strict.is_err());
                        assert!(encode(&Message::Notification(e.notification().unwrap()), &negotiated).is_ok());
                    }
                }
            }
            if let Ok(m) = Message::decode(frame, &negotiated) {
                if mixes(&m) {
                    assert!(matches!(encode(&m, &negotiated), Err(Error::Unwritable)));
                    continue;
                }
                let bytes = encode(&m, &negotiated).unwrap_or_else(|e| panic!("{m:?} cannot be written: {e}"));
                assert!(bytes.len() <= MAX_MESSAGE_LEN);
                let back = Frame::parse(&bytes).unwrap();
                assert_eq!(Message::decode(&back, &negotiated), Ok(m));
            } else if let Err(e) = Message::decode(frame, &negotiated) {
                let n = e.notification().unwrap();
                assert!(encode(&Message::Notification(n), &negotiated).is_ok());
            }
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg::new(0x2545_f491_4f6c_dd1d);
        let bases: Vec<Vec<u8>> = samples().into_iter().map(|(b, _)| b).collect();
        for round in 0..6000 {
            let mut b = bases[r.index(bases.len())].clone();
            match round % 4 {
                // Mutate only the body, preserving the header and fixing its length.
                0 | 1 => {
                    let mut body = b.split_off(HEADER_LEN);
                    mutate(&mut r, &mut body);
                    b.extend_from_slice(&body);
                    let length = u16::try_from(b.len()).unwrap();
                    b[16..18].copy_from_slice(&length.to_be_bytes());
                }
                // Cut the body short or grow it, and fix the length field.
                2 => {
                    let n = HEADER_LEN + r.index(b.len() + 8 - HEADER_LEN);
                    b.resize(n, r.next() as u8);
                    b[16..18].copy_from_slice(&(n as u16).to_be_bytes());
                }
                // Any bytes at all, behind a good marker half the time.
                _ => {
                    b = r.bytes(63);
                    if r.coin() && b.len() >= MARKER_LEN {
                        b[..MARKER_LEN].fill(0xff);
                    }
                }
            }
            contract::check_decode_with_alloc_limit(|| Frames, &b, 2 * MAX_MESSAGE_LEN);
            contract::check_wire::<Frame>(&b);
            for frame in decode_all(|| Frames, &b).0 {
                check_frame(&frame);
            }
            // The body alone, as each message type.
            let body = b.get(HEADER_LEN..).unwrap_or(&[]).to_vec();
            for kind in 1..=6 {
                check_frame(&Frame { kind, body: body.clone() });
            }
        }
    }

    #[test]
    fn lcg_fuzz_update_attributes() {
        // Random attribute lists behind good UPDATE lengths, so the
        // attribute readers see most of the inputs.
        let mut r = Lcg::new(7);
        let mut read = 0;
        for _ in 0..20_000 {
            let mut attrs = Vec::new();
            for _ in 0..r.index(4) {
                let kind = [1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 99][r.index(11)];
                let flags = match r.index(3) {
                    0 => known_flags(kind).unwrap_or(0x80),
                    1 => known_flags(kind).unwrap_or(0xc0) | flag::EXTENDED_LENGTH,
                    _ => r.next() as u8,
                };
                let n = r.index(12);
                let mut v: Vec<u8> = (0..n).map(|_| r.index(6) as u8).collect();
                if kind == 14 || kind == 15 {
                    v.splice(0..0, [0, 1 + r.index(2) as u8, 1, 0]);
                }
                attrs.push(flags);
                attrs.push(kind);
                if flags & flag::EXTENDED_LENGTH != 0 {
                    attrs.extend_from_slice(&(v.len() as u16).to_be_bytes());
                } else {
                    attrs.push(v.len() as u8);
                }
                attrs.extend_from_slice(&v);
            }
            let mut body = vec![0, 0];
            body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
            body.extend_from_slice(&attrs);
            if r.coin() {
                body.extend_from_slice(&[8, 10]);
            }
            let frame = Frame { kind: kind::UPDATE, body };
            if Message::decode(&frame, &TWO).is_ok() {
                read += 1;
            }
            check_frame(&frame);
        }
        assert!(read > 100, "only {read} read");
    }

    #[test]
    fn review_to_frame_checks_the_whole_body() {
        // 4074 withdrawn /0 routes: 4076 bytes of withdrawn routes, then
        // the attribute length makes the body 4078, too long.
        let u = Update { withdrawn: vec![v4(0, 0, 0, 0, 0); 4074], ..Update::default() };
        assert_eq!(Message::Update(u).to_frame(&TWO), Err(Error::Unwritable));
        let u = Update { withdrawn: vec![v4(0, 0, 0, 0, 0); 4073], ..Update::default() };
        let f = Message::Update(u).to_frame(&TWO).unwrap();
        assert_eq!(f.body.len(), MAX_BODY_LEN);
        assert!(Message::decode(&f, &TWO).is_ok());
    }

    #[test]
    fn review_open_new_carries_one_four_octet_as() {
        let o = Open::new(65001, 90, Ipv4Addr::new(192, 0, 2, 1), vec![Capability::FourOctetAs(65002)]);
        assert_eq!(o.asn(), 65001);
        assert_eq!(o.capabilities().filter(|c| matches!(c, Capability::FourOctetAs(_))).count(), 1);
    }

    #[test]
    fn review_empty_communities_are_malformed() {
        assert_eq!(update_body(&[0, 0, 0, 3, 0xc0, 8, 0], &TWO), Err(Error::AttributeLength(vec![0xc0, 8, 0])));
    }

    #[test]
    fn review_unknown_non_transitive_attributes_drop_partial() {
        let Ok(Message::Update(u)) = update_body(&[0, 0, 0, 3, 0xa0, 99, 0], &TWO) else { panic!() };
        assert_eq!(u.attributes, [Attribute::Unknown { flags: 0x80, kind: 99, value: vec![] }]);
        let bad = Update {
            attributes: vec![Attribute::Unknown { flags: 0xa0, kind: 99, value: vec![] }],
            ..Update::default()
        };
        assert!(matches!(encode(&Message::Update(bad), &TWO), Err(Error::Unwritable)));
    }

    #[test]
    fn review_prefixes_are_canonical() {
        // 10.128.0.0/9 with the padding bit clear and set reads the same.
        let a = update_body(&[0, 3, 9, 10, 0x80, 0, 0], &TWO).unwrap();
        let b = update_body(&[0, 3, 9, 10, 0xff, 0, 0], &TWO).unwrap();
        assert_eq!(a, b);
        let Message::Update(u) = a else { panic!() };
        assert_eq!(u.withdrawn, [v4(10, 128, 0, 0, 9)]);
        // A prefix with bits set past its length is not written.
        let u = Update { withdrawn: vec![v4(192, 0, 2, 9, 24)], ..Update::default() };
        assert!(matches!(encode(&Message::Update(u), &TWO), Err(Error::Unwritable)));
    }

    #[test]
    fn review_mp_reach_next_hop_lengths() {
        let reach = |afi: u16, next_hop: Vec<u8>| {
            let mut v = afi.to_be_bytes().to_vec();
            v.push(1);
            v.push(next_hop.len() as u8);
            v.extend_from_slice(&next_hop);
            v.push(0);
            let mut raw = vec![0x80, 14, v.len() as u8];
            raw.extend_from_slice(&v);
            let mut b = vec![0, 0, 0, 7 + raw.len() as u8, 0x40, 1, 1, 0, 0x40, 2, 0];
            b.extend_from_slice(&raw);
            (b, raw)
        };
        for (afi, n) in [(2, 0), (2, 4), (2, 15), (1, 0), (1, 8)] {
            let (b, raw) = reach(afi, vec![1; n]);
            assert_eq!(update_body(&b, &TWO), Err(Error::OptionalAttribute(raw)), "{afi} {n}");
        }
        for (afi, n) in [(2, 16), (2, 32), (1, 4), (1, 16), (1, 32), (25, 0)] {
            let (b, _) = reach(afi, vec![1; n]);
            assert!(update_body(&b, &TWO).is_ok(), "{afi} {n}");
        }
        let u = Update {
            attributes: vec![
                Attribute::MpReach(MpReach {
                    afi: afi::IPV6,
                    safi: safi::UNICAST,
                    next_hop: vec![],
                    nlri: Nlri::Prefixes(vec![Prefix::new(Ipv6Addr::UNSPECIFIED.into(), 0).unwrap()]),
                }),
                Attribute::Origin(Origin::Igp),
                Attribute::AsPath(vec![]),
            ],
            ..Update::default()
        };
        assert!(matches!(encode(&Message::Update(u), &TWO), Err(Error::Unwritable)));
    }

    #[test]
    fn review_as_zero_is_refused() {
        // RFC 7607: an OPEN from AS 0 is Bad Peer AS.
        let mut b = open_bytes();
        b[20..22].copy_from_slice(&[0, 0]);
        assert_eq!(decode(&b, &TWO), Err(Error::BadPeerAs));
        let mut b = open_bytes();
        let n = b.len();
        b[n - 4..].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(decode(&b, &TWO), Err(Error::BadPeerAs));
        let n = Error::BadPeerAs.notification().unwrap();
        assert_eq!((n.code, n.subcode), (2, 2));
        let id = Ipv4Addr::new(10, 0, 0, 1);
        assert!(matches!(encode(&Message::Open(Open::new(0, 90, id, vec![])), &TWO), Err(Error::Unwritable)));
        // An AS_PATH or AGGREGATOR with AS 0 is malformed.
        assert_eq!(update_body(&[0, 0, 0, 7, 0x40, 2, 4, 2, 1, 0, 0], &TWO), Err(Error::MalformedAsPath));
        let raw = vec![0xc0, 7, 6, 0, 0, 10, 0, 0, 1];
        let mut b = vec![0, 0, 0, raw.len() as u8];
        b.extend_from_slice(&raw);
        assert_eq!(update_body(&b, &TWO), Err(Error::OptionalAttribute(raw)));
    }

    #[test]
    fn review_extended_open_parameters() {
        // RFC 9072: an OPEN in the extended format, with no parameters.
        let body = [4, 0xfd, 0xe9, 0, 0x5a, 0xc0, 0, 2, 1, 0xff, 0xff, 0, 0];
        let Message::Open(o) = Message::decode(&Frame { kind: kind::OPEN, body: body.to_vec() }, &TWO).unwrap() else {
            panic!()
        };
        assert_eq!((o.my_as, o.hold_time, o.parameters.len()), (65001, 90, 0));
        // With a capabilities parameter of two capabilities.
        let mut body = vec![4, 0xfd, 0xe9, 0, 0x5a, 0xc0, 0, 2, 1, 0xff, 0xff, 0, 11];
        body.extend_from_slice(&[2, 0, 8, 2, 0, 65, 4, 0, 0, 0xfd, 0xe9]);
        let Message::Open(o) = Message::decode(&Frame { kind: kind::OPEN, body }, &TWO).unwrap() else { panic!() };
        assert_eq!(o.capabilities().count(), 2);
        assert_eq!(o.asn(), 65001);
    }

    #[test]
    fn review_update_writer_follows_rfc_7606_layout() {
        let path = Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns: vec![1] }]);
        let reach = Attribute::MpReach(MpReach {
            afi: afi::IPV6,
            safi: safi::UNICAST,
            next_hop: vec![0x20; 16],
            nlri: Nlri::Prefixes(vec![]),
        });
        // MP_REACH_NLRI after other attributes is not written.
        let late = Update {
            attributes: vec![Attribute::Origin(Origin::Igp), path.clone(), reach.clone()],
            ..Update::default()
        };
        assert!(matches!(encode(&Message::Update(late), &TWO), Err(Error::Unwritable)));
        // Withdrawn routes with MP_REACH_NLRI are not written.
        let mixed = Update {
            withdrawn: vec![v4(10, 0, 0, 0, 8)],
            attributes: vec![reach.clone(), Attribute::Origin(Origin::Igp), path.clone()],
            ..Update::default()
        };
        assert!(matches!(encode(&Message::Update(mixed), &TWO), Err(Error::Unwritable)));
        // A reader still takes the old layout, and puts MP_REACH_NLRI first.
        let mut body = vec![0, 0, 0, 31, 0x40, 1, 1, 0, 0x40, 2, 0, 0x80, 14, 21, 0, 2, 1, 16];
        body.extend_from_slice(&[0x20; 16]);
        body.push(0);
        let Message::Update(u) = update_body(&body, &TWO).unwrap() else { panic!() };
        assert_eq!(u.attributes[0].kind(), attr::MP_REACH_NLRI);
        assert!(encode(&Message::Update(u), &TWO).is_ok());
    }

    #[test]
    fn stream_holds_at_most_one_message() {
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&vec![0xff; 1 << 20]), MAX_MESSAGE_LEN);
        assert_eq!(stream.buffered(), MAX_MESSAGE_LEN);
        assert_eq!(stream.push(&[0xff]), 0);
        let note = Message::Notification(Notification { code: 6, subcode: 0, data: vec![0; MAX_BODY_LEN - 2] });
        let frame = note.to_frame(&TWO).unwrap();
        let bytes = frame.to_bytes().unwrap();
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Ok(frame.clone())));
        let (frames, error) = decode_all(|| Frames, &bytes.repeat(50));
        assert_eq!(error, None);
        assert_eq!(frames, vec![frame; 50]);
    }

    /// An UPDATE body announcing 10.0.0.0/8, with `extra` added to the
    /// attributes after ORIGIN, AS_PATH (AS 1) and NEXT_HOP.
    fn route_with(extra: &[u8]) -> Vec<u8> {
        let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0, 1, 0x40, 3, 4, 192, 0, 2, 1];
        attrs.extend_from_slice(extra);
        let mut b = vec![0, 0];
        b.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        b.extend_from_slice(&attrs);
        b.extend_from_slice(&[8, 10]);
        b
    }

    #[test]
    fn review_receive_follows_rfc_7606() {
        // A good UPDATE reads the same both ways.
        let good = route_with(&[]);
        let r = Update::receive(&good, &TWO).unwrap();
        assert_eq!((r.withdraw.as_ref(), r.discarded.len()), (None, 0));
        assert_eq!(r.update, Update::parse(&good, &TWO).unwrap());
        // An ORIGIN of 3 withdraws the route instead of closing.
        let mut b = good.clone();
        b[7] = 3;
        assert_eq!(Update::parse(&b, &TWO), Err(Error::InvalidOrigin(vec![0x40, 1, 1, 3])));
        let r = Update::receive(&b, &TWO).unwrap();
        assert_eq!(r.withdraw, Some(Error::InvalidOrigin(vec![0x40, 1, 1, 3])));
        assert_eq!(r.update.nlri, [v4(10, 0, 0, 0, 8)]);
        // A second MED is dropped and the first kept.
        let b = route_with(&[0x80, 4, 4, 0, 0, 0, 1, 0x80, 4, 4, 0, 0, 0, 2]);
        assert_eq!(Update::parse(&b, &TWO), Err(Error::MalformedAttributeList));
        let r = Update::receive(&b, &TWO).unwrap();
        assert_eq!(r.withdraw, None);
        assert_eq!(r.discarded, [Error::MalformedAttributeList]);
        assert_eq!(r.update.attribute(attr::MED), Some(&Attribute::Med(1)));
        // A malformed AGGREGATOR or ATOMIC_AGGREGATE is dropped.
        let b = route_with(&[0xc0, 7, 5, 0, 1, 10, 0, 0, 0x40, 6, 1, 0]);
        let r = Update::receive(&b, &TWO).unwrap();
        assert_eq!(r.withdraw, None);
        assert_eq!(r.discarded.len(), 2);
        assert_eq!(r.update.attributes.len(), 3);
        // Empty COMMUNITIES, a NEXT_HOP that is no host, AS 0 in the path
        // and a missing NEXT_HOP each withdraw.
        for b in [
            route_with(&[0xc0, 8, 0]),
            {
                let mut b = route_with(&[]);
                b[18] = 127;
                b
            },
            {
                let mut b = route_with(&[]);
                b[14] = 0;
                b
            },
            vec![0, 0, 0, 11, 0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0, 1, 8, 10],
        ] {
            let r = Update::receive(&b, &TWO).unwrap();
            assert!(r.withdraw.is_some(), "{b:?}");
            assert_eq!(r.update.nlri, [v4(10, 0, 0, 0, 8)]);
        }
        // An attribute running past the attribute length withdraws; the
        // NLRI is found from the length.
        let mut b = vec![0, 0, 0, 7, 0x40, 1, 1, 0, 0x80, 4, 9, 8, 10];
        let r = Update::receive(&b, &TWO).unwrap();
        assert_eq!(r.withdraw, Some(Error::MalformedAttributeList));
        assert_eq!(r.update.nlri, [v4(10, 0, 0, 0, 8)]);
        // The same with no routes announced closes (section 5.2).
        b.truncate(11);
        assert_eq!(Update::receive(&b, &TWO), Err(Error::MalformedAttributeList));
        // Errors that still close: NLRI that cannot be read, a repeated
        // MP_REACH_NLRI, an unknown well-known attribute.
        let mut b = route_with(&[]);
        b.push(33);
        assert_eq!(Update::receive(&b, &TWO), Err(Error::InvalidNetworkField));
        let mp = [0x80, 15, 3, 0, 1, 1];
        let b = [&[0, 0, 0, 12][..], &mp, &mp].concat();
        assert_eq!(Update::receive(&b, &TWO), Err(Error::MalformedAttributeList));
        let b = route_with(&[0x40, 99, 0]);
        assert_eq!(Update::receive(&b, &TWO), Err(Error::UnrecognizedWellKnownAttribute(vec![0x40, 99, 0])));
        // Withdrawn routes with a bad ORIGIN and nothing announced close.
        let b = [0, 2, 8, 10, 0, 4, 0x40, 1, 1, 3];
        assert_eq!(Update::receive(&b, &TWO), Err(Error::InvalidOrigin(vec![0x40, 1, 1, 3])));
    }

    #[test]
    fn review_partial_is_kept_on_known_attributes() {
        let b = [0, 0, 0, 7, 0xe0, 8, 4, 0xfd, 0xe9, 0, 1];
        let Message::Update(u) = update_body(&b, &TWO).unwrap() else { panic!() };
        assert_eq!(u.attributes, [Attribute::Communities { values: vec![0xfde9_0001], partial: true }]);
        assert_eq!(Message::Update(u).to_frame(&TWO).unwrap().body, b);
        let b = [0, 0, 0, 9, 0xe0, 7, 6, 0, 1, 10, 0, 0, 1];
        let Message::Update(u) = update_body(&b, &TWO).unwrap() else { panic!() };
        assert_eq!(Message::Update(u).to_frame(&TWO).unwrap().body, b);
    }

    #[test]
    fn review_as4_attributes_are_checked() {
        let with = |raw: &[u8], negotiated: &Context| {
            let Ok(Message::Update(u)) = update_body(&route_with(raw), negotiated) else { panic!("{raw:?}") };
            u.attributes.len()
        };
        let path = [0xc0, 17, 6, 2, 1, 0, 1, 0, 0];
        let agg = [0xc0, 18, 8, 0, 1, 0, 0, 10, 0, 0, 1];
        // Kept in a two-octet session, dropped between four-octet ones.
        assert_eq!(with(&path, &TWO), 4);
        assert_eq!(with(&agg, &TWO), 4);
        let four = |raw: &[u8]| {
            let mut b = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0, 1, 0x40, 3, 4, 192, 0, 2, 1];
            b.extend_from_slice(raw);
            let mut body = vec![0, 0, 0, b.len() as u8];
            body.extend_from_slice(&b);
            body.extend_from_slice(&[8, 10]);
            let Ok(Message::Update(u)) = update_body(&body, &FOUR) else { panic!() };
            u.attributes.len()
        };
        assert_eq!(four(&path), 3);
        assert_eq!(four(&agg), 3);
        // Malformed ones are dropped: empty, AS 0, the wrong length, not
        // transitive.
        for raw in [
            &[0xc0, 17, 0][..],
            &[0xc0, 17, 6, 2, 1, 0, 0, 0, 0],
            &[0xc0, 17, 4, 2, 1, 0, 1],
            &[0x80, 17, 6, 2, 1, 0, 1, 0, 0],
            &[0xc0, 18, 6, 0, 1, 10, 0, 0, 1],
            &[0xc0, 18, 8, 0, 0, 0, 0, 10, 0, 0, 1],
        ] {
            assert_eq!(with(raw, &TWO), 3, "{raw:?}");
            assert_eq!(Update::receive(&route_with(raw), &TWO).unwrap().discarded.len(), 1, "{raw:?}");
        }
        // Confederation segments are dropped from an AS4_PATH.
        let Ok(Message::Update(u)) =
            update_body(&route_with(&[0xc0, 17, 12, 3, 1, 0, 0, 0, 9, 2, 1, 0, 1, 0, 0]), &TWO)
        else {
            panic!()
        };
        assert_eq!(u.attributes[3], Attribute::Unknown { flags: 0xc0, kind: 17, value: vec![2, 1, 0, 1, 0, 0] });
        // Writers refuse what readers drop.
        let route = |a: Attribute, negotiated: &Context| {
            let mut u = Update::parse(&route_with(&[]), &TWO).unwrap();
            u.attributes.push(a);
            encode(&Message::Update(u), negotiated)
        };
        let unknown = |flags, kind, value: &[u8]| Attribute::Unknown { flags, kind, value: value.to_vec() };
        assert!(route(unknown(0xc0, 17, &path[3..]), &TWO).is_ok());
        assert!(route(unknown(0xc0, 17, &path[3..]), &FOUR).is_err());
        assert!(route(unknown(0xc0, 17, &[]), &TWO).is_err());
        assert!(route(unknown(0x80, 17, &path[3..]), &TWO).is_err());
        assert!(route(unknown(0xc0, 17, &[3, 1, 0, 0, 0, 9]), &TWO).is_err());
        assert!(route(unknown(0xc0, 18, &[0, 0, 0, 0, 10, 0, 0, 1]), &TWO).is_err());
        assert!(route(unknown(0xc0, 18, &agg[3..]), &TWO).is_ok());
    }

    #[test]
    fn review_enhanced_route_refresh_length() {
        let negotiated = Context { enhanced_route_refresh: true, ..TWO };
        let frame = Frame { kind: kind::ROUTE_REFRESH, body: vec![0, 2, 1, 1, 0] };
        let Err(e) = Message::decode(&frame, &negotiated) else { panic!() };
        let mut whole = header(24, 5);
        whole.extend_from_slice(&frame.body);
        assert_eq!(e, Error::RouteRefreshLength(whole.clone()));
        let n = e.notification().unwrap();
        assert_eq!((n.code, n.subcode, n.data), (7, 1, whole));
        // Without the capability, or for a plain request, it is a header
        // error.
        assert_eq!(Message::decode(&frame, &TWO), Err(Error::BadMessageLength(24)));
        let plain = Frame { kind: kind::ROUTE_REFRESH, body: vec![0, 2, 0, 1, 0] };
        assert_eq!(Message::decode(&plain, &negotiated), Err(Error::BadMessageLength(24)));
        // The longest such message still fits in a NOTIFICATION.
        let long = Frame { kind: kind::ROUTE_REFRESH, body: [&[0, 2, 2, 1][..], &[0; MAX_BODY_LEN - 4]].concat() };
        let e = Message::decode(&long, &negotiated).unwrap_err();
        assert!(encode(&Message::Notification(e.notification().unwrap()), &negotiated).is_ok());
        // The capability is negotiated when both sides send it.
        let id = Ipv4Addr::new(10, 0, 0, 1);
        let err =
            Open::new(1, 90, id, vec![Capability::Other { code: capability::ENHANCED_ROUTE_REFRESH, value: vec![] }]);
        let plain = Open::new(2, 90, id, vec![]);
        assert!(Context::negotiated(&err, &err).enhanced_route_refresh);
        assert!(!Context::negotiated(&err, &plain).enhanced_route_refresh);
    }

    #[test]
    fn lcg_public_values_round_trip() {
        // Updates built from public fields, the way world code builds
        // them: whatever a writer takes reads back the same.
        let mut r = Lcg::new(99);
        let mut written = 0;
        for _ in 0..3000 {
            let prefix = |r: &mut Lcg| {
                let addr = Ipv4Addr::from(if r.coin() { r.next() as u32 } else { (r.next() as u32) & 0xffff_0000 });
                let length = r.index(34) as u8;
                if r.index(3) == 0 {
                    Prefix::new(addr.into(), length.min(32)).unwrap()
                } else {
                    Prefix { addr: addr.into(), length }
                }
            };
            let count = [0, 1, 3, 4073, 4074, 5000][r.index(6)];
            let withdrawn: Vec<Prefix> = (0..count).map(|_| prefix(&mut r)).collect();
            let mut attributes = vec![];
            if r.coin() {
                attributes.push(Attribute::Origin(Origin::Igp));
                attributes
                    .push(Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns: vec![r.index(3) as u32] }]));
                attributes.push(Attribute::NextHop(Ipv4Addr::from(r.next() as u32)));
            }
            if r.coin() {
                let values = (0..r.index(3)).map(|_| r.next() as u32).collect();
                attributes.push(Attribute::Communities { values, partial: r.coin() });
            }
            if r.index(4) == 0 {
                attributes.push(Attribute::Unknown {
                    flags: r.next() as u8,
                    kind: 17 + r.index(3) as u8,
                    value: vec![2, 1, 0, 0, 0, r.index(2) as u8],
                });
            }
            let nlri = if r.coin() { vec![prefix(&mut r)] } else { vec![] };
            let u = Update { withdrawn, attributes, nlri };
            for negotiated in [TWO, FOUR] {
                let m = Message::Update(u.clone());
                if let Ok(frame) = m.to_frame(&negotiated) {
                    written += 1;
                    assert!(frame.body.len() <= MAX_BODY_LEN);
                    assert_eq!(Message::decode(&frame, &negotiated).as_ref(), Ok(&m));
                    assert_eq!(frame.to_bytes().map(|b| b.len()), Ok(HEADER_LEN + frame.body.len()));
                }
            }
        }
        assert!(written > 100, "only {written} written");
    }
}
