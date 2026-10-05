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
//! refresh) and RFC 4724 (the graceful restart capability).
//!
//! Nothing here reads a socket. A world that plays a router feeds the
//! bytes it reads from a TCP connection to a [`Decoder`], gets [`Frame`]s
//! back, and reads each one with [`Message::decode`]. It writes the bytes
//! of [`Message::to_bytes`] back to the connection. Which routes exist,
//! which peers are welcome and when timers fire is up to world code.
//!
//! How an UPDATE reads depends on the session: once both speakers have
//! sent the four-octet AS capability, AS numbers in AS_PATH and
//! AGGREGATOR take four bytes instead of two. A [`Context`] says which,
//! and [`Context::negotiated`] works it out from the two OPEN messages.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A message that breaks the specification gives an [`Error`]
//! whose [`Error::notification`] is the NOTIFICATION a real router would
//! send before it closes the connection. Writers check the same rules and
//! return an [`EncodeError`] instead of bytes a reader would refuse.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use fictionet::stdlib::bgp::{
//!     afi, safi, Attribute, Capability, Context, Decoder, Message, Open, Origin, Prefix, Segment, SegmentKind,
//!     Update, AS_TRANS,
//! };
//!
//! // The agent's router opens a session as AS 65001.
//! let theirs = Open::new(65001, 90, Ipv4Addr::new(192, 0, 2, 1), vec![Capability::Multiprotocol {
//!     afi: afi::IPV4,
//!     safi: safi::UNICAST,
//! }]);
//! let mut decoder = Decoder::new();
//! decoder.feed(&Message::Open(theirs).to_bytes(&Context::default()).unwrap());
//! let frame = decoder.next_frame().unwrap().unwrap();
//! let Message::Open(open) = Message::decode(&frame, &Context::default()).unwrap() else {
//!     panic!("not an OPEN");
//! };
//! assert_eq!(open.asn(), 65001);
//!
//! // The world answers as AS 4200000000, which needs four octets.
//! let ours = Open::new(4_200_000_000, 90, Ipv4Addr::new(198, 51, 100, 1), vec![]);
//! assert_eq!(ours.my_as, AS_TRANS);
//! let ctx = Context::negotiated(&ours, &open);
//! assert!(ctx.four_octet_as);
//! let keepalive = Message::Keepalive.to_bytes(&ctx).unwrap();
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
//! let bytes = Message::Update(update.clone()).to_bytes(&ctx).unwrap();
//! // No withdrawn routes, then 20 bytes of attributes.
//! assert_eq!(bytes[19..23], [0, 0, 0, 20]);
//! // The prefix comes last: its length in bits, then 3 bytes.
//! assert_eq!(bytes[43..], [24, 203, 0, 113]);
//!
//! decoder.feed(&bytes);
//! let frame = decoder.next_frame().unwrap().unwrap();
//! assert_eq!(Message::decode(&frame, &ctx), Ok(Message::Update(update)));
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
/// The most bytes of optional parameters an OPEN may carry, and the most
/// bytes one parameter or one capability may hold: each length is one
/// byte.
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
    /// This module keeps it as an `Attribute::Unknown`.
    pub const AS4_PATH: u8 = 17;
    /// The four-octet aggregator a two-octet session carries (RFC 6793).
    /// This module keeps it as an `Attribute::Unknown`.
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
}

/// The optional parameter type that holds capabilities (RFC 5492).
pub const PARAMETER_CAPABILITIES: u8 = 2;

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
}

/// What the two speakers agreed in their OPEN messages that changes how an
/// UPDATE reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Context {
    /// Both sent the four-octet AS capability, so AS numbers in AS_PATH and
    /// AGGREGATOR take four bytes.
    pub four_octet_as: bool,
}

impl Context {
    /// The context once `local` and `remote` have been exchanged.
    pub fn negotiated(local: &Open, remote: &Open) -> Context {
        Context { four_octet_as: local.four_octet_as().is_some() && remote.four_octet_as().is_some() }
    }
}

/// Why bytes are not a BGP message this module can read. Each one maps to
/// the NOTIFICATION a real speaker sends before it closes the connection.
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
    /// An MP_REACH_NLRI or MP_UNREACH_NLRI cannot be read. It holds the
    /// whole attribute.
    OptionalAttribute(Vec<u8>),
    /// A withdrawn route or NLRI prefix cannot be read.
    InvalidNetworkField,
    /// The AS_PATH cannot be read.
    MalformedAsPath,
}

impl Error {
    /// The NOTIFICATION a speaker sends for this error, with the data RFC
    /// 4271 asks for.
    pub fn notification(&self) -> Notification {
        use subcode::{header as h, open as o, update as u};
        let (code, subcode, data) = match self {
            Error::ConnectionNotSynchronized => (code::MESSAGE_HEADER, h::CONNECTION_NOT_SYNCHRONIZED, vec![]),
            Error::BadMessageLength(n) => (code::MESSAGE_HEADER, h::BAD_MESSAGE_LENGTH, n.to_be_bytes().to_vec()),
            Error::BadMessageType(t) => (code::MESSAGE_HEADER, h::BAD_MESSAGE_TYPE, vec![*t]),
            Error::MalformedOpen => (code::OPEN_MESSAGE, subcode::UNSPECIFIC, vec![]),
            // The data is the largest version the speaker supports.
            Error::UnsupportedVersion(_) => (code::OPEN_MESSAGE, o::UNSUPPORTED_VERSION_NUMBER, vec![0, VERSION]),
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
        };
        Notification { code, subcode, data }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConnectionNotSynchronized => f.write_str("marker is not all ones"),
            Error::BadMessageLength(n) => write!(f, "bad message length {n}"),
            Error::BadMessageType(t) => write!(f, "bad message type {t}"),
            Error::MalformedOpen => f.write_str("malformed OPEN optional parameters"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported BGP version {v}"),
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
        }
    }
}

impl std::error::Error for Error {}

/// Why a message cannot be written: its fields break a rule the reader
/// checks, or it does not fit in [`MAX_MESSAGE_LEN`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The message would be longer than [`MAX_MESSAGE_LEN`] bytes.
    TooLong,
    /// A field breaks a rule. The text says which.
    Invalid(&'static str),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooLong => write!(f, "message longer than {MAX_MESSAGE_LEN} bytes"),
            EncodeError::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for EncodeError {}

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
    pub fn parse(b: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
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

    /// The frame's bytes: the header, then the body. A body longer than
    /// [`MAX_BODY_LEN`] cannot be written.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if self.body.len() > MAX_BODY_LEN {
            return Err(EncodeError::TooLong);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.extend_from_slice(&[0xff; MARKER_LEN]);
        out.extend_from_slice(&((HEADER_LEN + self.body.len()) as u16).to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

/// Splits a BGP byte stream into frames. Feed it the bytes a connection
/// reads, in order, and take frames out until it has none.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small frames costs time in proportion to their bytes.
    start: usize,
    failed: Option<Error>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection. After an [`Error`] the stream
    /// cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next whole frame, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A decoder never holds more than one message's
    /// bytes beyond what has been taken out, plus what one `feed` added.
    pub fn next_frame(&mut self) -> Option<Result<Frame, Error>> {
        if let Some(e) = &self.failed {
            return Some(Err(e.clone()));
        }
        match Frame::parse(&self.buf[self.start..]) {
            Ok(Some((frame, used))) => {
                self.start += used;
                Some(Ok(frame))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e.clone());
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
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
    /// Reads the message in `frame`. `ctx` says how AS numbers in an
    /// UPDATE read; the other messages ignore it.
    pub fn decode(frame: &Frame, ctx: &Context) -> Result<Message, Error> {
        let len = frame.body.len().saturating_add(HEADER_LEN);
        let field = length_field(&frame.body);
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
            kind::UPDATE => Message::Update(Update::parse(b, ctx)?),
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
    /// it back with the same `ctx`.
    pub fn to_frame(&self, ctx: &Context) -> Result<Frame, EncodeError> {
        let body = match self {
            Message::Open(o) => o.to_body()?,
            Message::Update(u) => u.to_body(ctx)?,
            Message::Notification(n) => n.to_body()?,
            Message::Keepalive => Vec::new(),
            Message::RouteRefresh(r) => r.to_body(),
        };
        Ok(Frame { kind: self.kind(), body })
    }

    /// The message's bytes, header and all.
    pub fn to_bytes(&self, ctx: &Context) -> Result<Vec<u8>, EncodeError> {
        self.to_frame(ctx)?.to_bytes()
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
    /// Any other type, with its value unread. Its kind is never 2.
    Other {
        /// The parameter type.
        kind: u8,
        /// The parameter value, at most 255 bytes.
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
    /// four-octet AS capability for `asn`. If `asn` does not fit in two
    /// octets, `my_as` is [`AS_TRANS`].
    pub fn new(asn: u32, hold_time: u16, bgp_id: Ipv4Addr, mut capabilities: Vec<Capability>) -> Open {
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

    /// Reads an OPEN's body, the bytes after the header. A body shorter
    /// than 10 bytes or longer than [`MAX_BODY_LEN`] is a bad length.
    pub fn parse(b: &[u8]) -> Result<Open, Error> {
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
        if hold_time == 1 || hold_time == 2 {
            return Err(Error::UnacceptableHoldTime);
        }
        if id == 0 {
            return Err(Error::BadBgpIdentifier);
        }
        if r.len() != usize::from(params_len) {
            return Err(Error::MalformedOpen);
        }
        let mut parameters = Vec::new();
        while !r.is_empty() {
            let (Some(kind), Some(n)) = (take_u8(&mut r), take_u8(&mut r)) else { return Err(Error::MalformedOpen) };
            let value = take(&mut r, usize::from(n)).ok_or(Error::MalformedOpen)?;
            parameters.push(if kind == PARAMETER_CAPABILITIES {
                Parameter::Capabilities(parse_capabilities(value)?)
            } else {
                Parameter::Other { kind, value: value.to_vec() }
            });
        }
        Ok(Open { my_as, hold_time, bgp_id: Ipv4Addr::from(id), parameters })
    }

    fn to_body(&self) -> Result<Vec<u8>, EncodeError> {
        if self.hold_time == 1 || self.hold_time == 2 {
            return Err(EncodeError::Invalid("hold time is 1 or 2 seconds"));
        }
        if self.bgp_id.is_unspecified() {
            return Err(EncodeError::Invalid("BGP identifier is 0"));
        }
        let mut params = Vec::new();
        for p in &self.parameters {
            let (kind, value) = match p {
                Parameter::Capabilities(caps) => (PARAMETER_CAPABILITIES, capabilities_bytes(caps)?),
                Parameter::Other { kind, value } => {
                    if *kind == PARAMETER_CAPABILITIES {
                        return Err(EncodeError::Invalid("other parameter with the capabilities type"));
                    }
                    if value.len() > MAX_PARAMETERS_LEN {
                        return Err(EncodeError::Invalid("optional parameter longer than 255 bytes"));
                    }
                    (*kind, value.clone())
                }
            };
            if value.len() > MAX_PARAMETERS_LEN {
                return Err(EncodeError::Invalid("optional parameter longer than 255 bytes"));
            }
            params.push(kind);
            params.push(value.len() as u8);
            params.extend_from_slice(&value);
            if params.len() > MAX_PARAMETERS_LEN {
                return Err(EncodeError::Invalid("optional parameters longer than 255 bytes"));
            }
        }
        let mut out = vec![VERSION];
        out.extend_from_slice(&self.my_as.to_be_bytes());
        out.extend_from_slice(&self.hold_time.to_be_bytes());
        out.extend_from_slice(&self.bgp_id.octets());
        out.push(params.len() as u8);
        out.extend_from_slice(&params);
        Ok(out)
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
                    .chunks_exact(4)
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

fn capabilities_bytes(caps: &[Capability]) -> Result<Vec<u8>, EncodeError> {
    let too_long = EncodeError::Invalid("optional parameter longer than 255 bytes");
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
                    return Err(EncodeError::Invalid("graceful restart flags above 15"));
                }
                if g.time > MAX_RESTART_TIME {
                    return Err(EncodeError::Invalid("graceful restart time above 4095 seconds"));
                }
                if g.families.len() > (MAX_PARAMETERS_LEN - 2) / 4 {
                    return Err(too_long);
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
                    return Err(EncodeError::Invalid("other capability with a known code"));
                }
                if value.len() > MAX_PARAMETERS_LEN {
                    return Err(too_long);
                }
                (*code, value.clone())
            }
        };
        out.push(code);
        out.push(value.len() as u8);
        out.extend_from_slice(&value);
        if out.len() > MAX_PARAMETERS_LEN {
            return Err(too_long);
        }
    }
    Ok(out)
}

/// An IP prefix: an address and how many of its leading bits count.
/// Bits past the length are kept as they arrived, though they mean
/// nothing; [`Prefix::new`] clears them.
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

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        out.push(Prefix { addr, length });
    }
    Some(out)
}

fn write_prefixes(out: &mut Vec<u8>, prefixes: &[Prefix], v6: bool) -> Result<(), EncodeError> {
    for p in prefixes {
        let octets = match (p.addr, v6) {
            (IpAddr::V4(a), false) if p.length <= 32 => a.octets().to_vec(),
            (IpAddr::V6(a), true) if p.length <= 128 => a.octets().to_vec(),
            _ => return Err(EncodeError::Invalid("prefix of the wrong family, or too long")),
        };
        out.push(p.length);
        out.extend_from_slice(&octets[..usize::from(p.length).div_ceil(8)]);
        bound(out)?;
    }
    Ok(())
}

/// An UPDATE message.
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
    /// The next hop's bytes: 4 for IPv4, and 16 or 32 for IPv6 (a global
    /// address, then maybe a link-local one). At most 255 bytes.
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
/// gives their type, so a PARTIAL bit read on one is not kept.
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
    },
    /// Type 8: community tags, each the AS in the top 16 bits and a value
    /// in the bottom 16 (RFC 1997).
    Communities(Vec<u32>),
    /// Type 14: routes of another address family.
    MpReach(MpReach),
    /// Type 15: withdrawn routes of another address family.
    MpUnreach(MpUnreach),
    /// Any other type, with its value unread.
    Unknown {
        /// The flags, with only the optional, transitive and partial bits
        /// kept. The optional bit is always set: an unknown attribute
        /// without it is an error.
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
            Attribute::Communities(_) => attr::COMMUNITIES,
            Attribute::MpReach(_) => attr::MP_REACH_NLRI,
            Attribute::MpUnreach(_) => attr::MP_UNREACH_NLRI,
            Attribute::Unknown { kind, .. } => *kind,
        }
    }

    /// Reads one attribute's value. `raw` is the whole attribute, for the
    /// error.
    fn parse(flags: u8, kind: u8, v: &[u8], raw: &[u8], ctx: &Context) -> Result<Attribute, Error> {
        let Some(expected) = known_flags(kind) else {
            if flags & flag::OPTIONAL == 0 {
                return Err(Error::UnrecognizedWellKnownAttribute(raw.to_vec()));
            }
            let flags = flags & (flag::OPTIONAL | flag::TRANSITIVE | flag::PARTIAL);
            return Ok(Attribute::Unknown { flags, kind, value: v.to_vec() });
        };
        let partial_ok = expected == flag::OPTIONAL | flag::TRANSITIVE;
        if flags & (flag::OPTIONAL | flag::TRANSITIVE) != expected || (flags & flag::PARTIAL != 0 && !partial_ok) {
            return Err(Error::AttributeFlags(raw.to_vec()));
        }
        let length = || Error::AttributeLength(raw.to_vec());
        let u32_value = || -> Result<u32, Error> {
            let [a, b, c, d] = v else { return Err(length()) };
            Ok(u32::from_be_bytes([*a, *b, *c, *d]))
        };
        Ok(match kind {
            attr::ORIGIN => match v {
                [c] => Attribute::Origin(Origin::from_code(*c).ok_or_else(|| Error::InvalidOrigin(raw.to_vec()))?),
                _ => return Err(length()),
            },
            attr::AS_PATH => Attribute::AsPath(parse_as_path(v, ctx.four_octet_as).ok_or(Error::MalformedAsPath)?),
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
                let (asn, address) = match (v, ctx.four_octet_as) {
                    ([a, b, x @ ..], false) if x.len() == 4 => (u32::from(u16::from_be_bytes([*a, *b])), x),
                    ([a, b, c, d, x @ ..], true) if x.len() == 4 => (u32::from_be_bytes([*a, *b, *c, *d]), x),
                    _ => return Err(length()),
                };
                Attribute::Aggregator { asn, address: Ipv4Addr::new(address[0], address[1], address[2], address[3]) }
            }
            attr::COMMUNITIES if v.len().is_multiple_of(4) => Attribute::Communities(
                v.chunks_exact(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect(),
            ),
            attr::COMMUNITIES => return Err(length()),
            attr::MP_REACH_NLRI => {
                Attribute::MpReach(parse_mp_reach(v).ok_or_else(|| Error::OptionalAttribute(raw.to_vec()))?)
            }
            _ => Attribute::MpUnreach(parse_mp_unreach(v).ok_or_else(|| Error::OptionalAttribute(raw.to_vec()))?),
        })
    }

    /// Writes the attribute, header and value, onto `out`.
    fn write(&self, out: &mut Vec<u8>, ctx: &Context) -> Result<(), EncodeError> {
        let kind = self.kind();
        let mut v = Vec::new();
        match self {
            Attribute::Origin(o) => v.push(o.code()),
            Attribute::AsPath(segments) => {
                for s in segments {
                    if s.asns.is_empty() || s.asns.len() > MAX_SEGMENT_ASNS {
                        return Err(EncodeError::Invalid("AS_PATH segment with no AS numbers or more than 255"));
                    }
                    v.push(s.kind.code());
                    v.push(s.asns.len() as u8);
                    for &a in &s.asns {
                        put_asn(&mut v, a, ctx)?;
                    }
                    bound(&v)?;
                }
            }
            Attribute::NextHop(a) => {
                if !host_address(*a) {
                    return Err(EncodeError::Invalid("NEXT_HOP is not a host address"));
                }
                v.extend_from_slice(&a.octets())
            }
            Attribute::Med(n) | Attribute::LocalPref(n) => v.extend_from_slice(&n.to_be_bytes()),
            Attribute::AtomicAggregate => {}
            Attribute::Aggregator { asn, address } => {
                put_asn(&mut v, *asn, ctx)?;
                v.extend_from_slice(&address.octets());
            }
            Attribute::Communities(c) => {
                for n in c {
                    v.extend_from_slice(&n.to_be_bytes());
                    bound(&v)?;
                }
            }
            Attribute::MpReach(m) => {
                if m.next_hop.len() > 255 {
                    return Err(EncodeError::Invalid("MP_REACH_NLRI next hop longer than 255 bytes"));
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
                    return Err(EncodeError::Invalid("unknown attribute with a known type code"));
                }
                if flags & flag::OPTIONAL == 0 {
                    return Err(EncodeError::Invalid("unknown attribute without the optional bit"));
                }
                if value.len() > MAX_BODY_LEN {
                    return Err(EncodeError::TooLong);
                }
                let flags = flags & (flag::OPTIONAL | flag::TRANSITIVE | flag::PARTIAL);
                return put_attribute(out, flags, *kind, value);
            }
        }
        // Every known type has flags; the match above returned for the rest.
        put_attribute(out, known_flags(kind).unwrap_or(flag::OPTIONAL), kind, &v)
    }
}

/// Whether `a` can be a NEXT_HOP: RFC 4271 section 6.3 asks for a valid
/// IP host address. Addresses in 0.0.0.0/8 (this network), 127.0.0.0/8
/// (loopback), 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved, with
/// the broadcast address) are not.
fn host_address(a: Ipv4Addr) -> bool {
    !matches!(a.octets()[0], 0 | 127 | 224..=255)
}

fn put_asn(v: &mut Vec<u8>, asn: u32, ctx: &Context) -> Result<(), EncodeError> {
    if ctx.four_octet_as {
        v.extend_from_slice(&asn.to_be_bytes());
    } else {
        let a = u16::try_from(asn).map_err(|_| EncodeError::Invalid("AS number needs four octets"))?;
        v.extend_from_slice(&a.to_be_bytes());
    }
    Ok(())
}

fn put_attribute(out: &mut Vec<u8>, flags: u8, kind: u8, value: &[u8]) -> Result<(), EncodeError> {
    if value.len() > MAX_BODY_LEN {
        return Err(EncodeError::TooLong);
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

fn write_nlri(v: &mut Vec<u8>, afi: u16, safi: u8, nlri: &Nlri) -> Result<(), EncodeError> {
    match (nlri, prefix_family(afi, safi)) {
        (Nlri::Prefixes(p), true) => write_prefixes(v, p, afi == afi::IPV6),
        (Nlri::Raw(r), false) => {
            if r.len() > MAX_BODY_LEN {
                return Err(EncodeError::TooLong);
            }
            v.extend_from_slice(r);
            bound(v)
        }
        _ => Err(EncodeError::Invalid("NLRI form does not match the address family")),
    }
}

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
        let asns = bytes
            .chunks_exact(size)
            .map(|c| if four { u32::from_be_bytes([c[0], c[1], c[2], c[3]]) } else { u32::from(be16(c, 0)) })
            .collect();
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
    /// Reads an UPDATE's body, the bytes after the header. `ctx` says how
    /// many octets an AS number takes. A body longer than
    /// [`MAX_BODY_LEN`] is a bad length.
    pub fn parse(b: &[u8], ctx: &Context) -> Result<Update, Error> {
        if b.len() > MAX_BODY_LEN {
            return Err(Error::BadMessageLength(length_field(b)));
        }
        let mut r = b;
        let wlen = take_u16(&mut r).ok_or(Error::MalformedAttributeList)?;
        let withdrawn = take(&mut r, usize::from(wlen)).ok_or(Error::MalformedAttributeList)?;
        let alen = take_u16(&mut r).ok_or(Error::MalformedAttributeList)?;
        let mut attrs = take(&mut r, usize::from(alen)).ok_or(Error::MalformedAttributeList)?;
        let withdrawn = read_prefixes(withdrawn, false).ok_or(Error::InvalidNetworkField)?;

        let mut seen = [false; 256];
        let mut attributes = Vec::new();
        while !attrs.is_empty() {
            let all = attrs;
            let (Some(flags), Some(kind)) = (take_u8(&mut attrs), take_u8(&mut attrs)) else {
                return Err(Error::MalformedAttributeList);
            };
            let n = if flags & flag::EXTENDED_LENGTH != 0 {
                take_u16(&mut attrs).map(usize::from)
            } else {
                take_u8(&mut attrs).map(usize::from)
            };
            let n = n.ok_or(Error::MalformedAttributeList)?;
            let value = take(&mut attrs, n).ok_or(Error::MalformedAttributeList)?;
            let raw = &all[..all.len() - attrs.len()];
            if std::mem::replace(&mut seen[usize::from(kind)], true) {
                return Err(Error::MalformedAttributeList);
            }
            attributes.push(Attribute::parse(flags, kind, value, raw, ctx)?);
        }
        let nlri = read_prefixes(r, false).ok_or(Error::InvalidNetworkField)?;
        if let Some(k) = missing(&seen, !nlri.is_empty()) {
            return Err(Error::MissingWellKnownAttribute(k));
        }
        Ok(Update { withdrawn, attributes, nlri })
    }

    /// The attribute of type `kind`, if the UPDATE has one.
    pub fn attribute(&self, kind: u8) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.kind() == kind)
    }

    fn to_body(&self, ctx: &Context) -> Result<Vec<u8>, EncodeError> {
        let mut out = vec![0, 0];
        write_prefixes(&mut out, &self.withdrawn, false)?;
        let wlen = (out.len() - 2) as u16;
        out[..2].copy_from_slice(&wlen.to_be_bytes());
        let at = out.len();
        out.extend_from_slice(&[0, 0]);
        let mut seen = [false; 256];
        for a in &self.attributes {
            if std::mem::replace(&mut seen[usize::from(a.kind())], true) {
                return Err(EncodeError::Invalid("attribute type appears twice"));
            }
            a.write(&mut out, ctx)?;
        }
        let alen = (out.len() - at - 2) as u16;
        out[at..at + 2].copy_from_slice(&alen.to_be_bytes());
        write_prefixes(&mut out, &self.nlri, false)?;
        if missing(&seen, !self.nlri.is_empty()).is_some() {
            return Err(EncodeError::Invalid("routes without ORIGIN, AS_PATH or NEXT_HOP"));
        }
        Ok(out)
    }
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

    fn to_body(&self) -> Result<Vec<u8>, EncodeError> {
        if self.data.len() > MAX_BODY_LEN - 2 {
            return Err(EncodeError::TooLong);
        }
        let mut out = vec![self.code, self.subcode];
        out.extend_from_slice(&self.data);
        Ok(out)
    }
}

impl std::fmt::Display for Notification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
fn bound(out: &[u8]) -> Result<(), EncodeError> {
    if out.len() > MAX_BODY_LEN { Err(EncodeError::TooLong) } else { Ok(()) }
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

    const TWO: Context = Context { four_octet_as: false };
    const FOUR: Context = Context { four_octet_as: true };

    fn header(len: u16, kind: u8) -> Vec<u8> {
        let mut out = vec![0xff; 16];
        out.extend_from_slice(&len.to_be_bytes());
        out.push(kind);
        out
    }

    fn decode(bytes: &[u8], ctx: &Context) -> Result<Message, Error> {
        let (frame, used) = Frame::parse(bytes)?.expect("a whole frame");
        assert_eq!(used, bytes.len());
        Message::decode(&frame, ctx)
    }

    fn update_body(body: &[u8], ctx: &Context) -> Result<Message, Error> {
        Message::decode(&Frame { kind: kind::UPDATE, body: body.to_vec() }, ctx)
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
        let mp = Message::Update(Update {
            withdrawn: vec![v4(10, 1, 0, 0, 16)],
            attributes: vec![
                Attribute::Origin(Origin::Egp),
                Attribute::AsPath(vec![
                    Segment { kind: SegmentKind::Sequence, asns: vec![4_200_000_000, 65001] },
                    Segment { kind: SegmentKind::Set, asns: vec![1, 2, 3] },
                ]),
                Attribute::Med(7),
                Attribute::LocalPref(100),
                Attribute::AtomicAggregate,
                Attribute::Aggregator { asn: 4_200_000_000, address: Ipv4Addr::new(10, 0, 0, 1) },
                Attribute::Communities(vec![0xfde9_0001, 0xffff_ff01]),
                Attribute::MpReach(MpReach {
                    afi: afi::IPV6,
                    safi: safi::UNICAST,
                    next_hop: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    nlri: Nlri::Prefixes(vec![Prefix::new("2001:db8:1::".parse().unwrap(), 48).unwrap()]),
                }),
                Attribute::MpUnreach(MpUnreach { afi: 25, safi: 65, withdrawn: Nlri::Raw(vec![1, 2, 3]) }),
                Attribute::Unknown { flags: 0xc0, kind: 32, value: vec![0; 300] },
            ],
            nlri: vec![],
        })
        .to_bytes(&FOUR)
        .unwrap();
        vec![(open_bytes(), TWO), (update_bytes(), TWO), (keep, TWO), (refresh, TWO), (note, TWO), (mp, FOUR)]
    }

    #[test]
    fn keepalive_example() {
        // RFC 4271 section 4.4: a KEEPALIVE is the header alone, 19 bytes.
        let b = Message::Keepalive.to_bytes(&TWO).unwrap();
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
        assert_eq!(Message::Open(open.clone()).to_bytes(&TWO).unwrap(), b);
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
        let b = Message::Open(open.clone()).to_bytes(&TWO).unwrap();
        // The graceful restart value: flags 8 in the top bits, time 120.
        let at = b.windows(2).position(|w| w == [64, 6]).unwrap();
        assert_eq!(b[at + 2..at + 8], [0x80, 120, 0, 1, 1, 0x80]);
        assert_eq!(decode(&b, &TWO), Ok(Message::Open(open.clone())));
        assert_eq!(open.asn(), 4_200_000_000);
        let plain = Open { parameters: vec![], ..open.clone() };
        assert_eq!(plain.asn(), u32::from(AS_TRANS));
        assert_eq!(Context::negotiated(&open, &plain), TWO);
        assert_eq!(Context::negotiated(&open, &open), FOUR);
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
        assert_eq!(Message::Update(u.clone()).to_bytes(&TWO).unwrap(), b);
        // With four-octet AS numbers the AS_PATH reads differently: 1 AS
        // of 4 bytes needs 6 bytes of value, and 4 is too short.
        assert_eq!(decode(&b, &FOUR), Err(Error::MalformedAsPath));
        let four = Message::Update(u).to_bytes(&FOUR).unwrap();
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
        let b = Message::Update(u.clone()).to_bytes(&TWO).unwrap();
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
        assert_eq!(Message::Update(u).to_frame(&TWO).unwrap().body, body);
        // Without ORIGIN the routes are refused.
        let mut b = vec![0, 0, 0, 32];
        b.extend_from_slice(&body[8..]);
        assert_eq!(update_body(&b, &TWO), Err(Error::MissingWellKnownAttribute(attr::ORIGIN)));
    }

    #[test]
    fn notification_and_route_refresh_examples() {
        let n = Notification { code: code::CEASE, subcode: 2, data: b"bye".to_vec() };
        let b = Message::Notification(n.clone()).to_bytes(&TWO).unwrap();
        assert_eq!(b[16..], [0, 24, 3, 6, 2, b'b', b'y', b'e']);
        assert_eq!(decode(&b, &TWO), Ok(Message::Notification(n.clone())));
        assert_eq!(n.to_string(), "cease (code 6, subcode 2)");
        let r = RouteRefresh { afi: afi::IPV6, subtype: 0, safi: safi::UNICAST };
        let b = Message::RouteRefresh(r).to_bytes(&TWO).unwrap();
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
        // Bits past the length are kept as they came, and written back.
        let b = vec![0, 2, 7, 0xff, 0, 0];
        let Message::Update(u) = update_body(&b, &TWO).unwrap() else { panic!() };
        assert_eq!(u.withdrawn, [v4(255, 0, 0, 0, 7)]);
        assert_eq!(Message::Update(u).to_frame(&TWO).unwrap().body, b);
    }

    #[test]
    fn header_errors() {
        assert_eq!(Frame::parse(&[0xff, 0xff, 0xfe]), Err(Error::ConnectionNotSynchronized));
        let mut b = header(18, 4);
        assert_eq!(Frame::parse(&b), Err(Error::BadMessageLength(18)));
        b = header(4097, 4);
        assert_eq!(Frame::parse(&b), Err(Error::BadMessageLength(4097)));
        assert_eq!(Frame::parse(&header(4096, 4)), Ok(None));
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
        assert_eq!(big.to_bytes(), Err(EncodeError::TooLong));
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
            let n = Error::InvalidNextHop(raw.clone()).notification();
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
            assert!(matches!(Message::Update(u).to_bytes(&TWO), Err(EncodeError::Invalid(_))));
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
        assert!(Message::Notification(e.notification()).to_bytes(&FOUR).is_ok());
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
        assert!(Message::Update(u).to_bytes(&TWO).is_ok());
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
        let n = Error::BadMessageLength(5000).notification();
        assert_eq!((n.code, n.subcode, &n.data[..]), (1, 2, &[0x13, 0x88][..]));
        let n = Error::UnsupportedVersion(3).notification();
        assert_eq!((n.code, n.subcode, &n.data[..]), (2, 1, &[0, 4][..]));
        let n = Error::MissingWellKnownAttribute(3).notification();
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
            let n = e.notification();
            assert_eq!((n.code, n.subcode), (c, s), "{e}");
            // Every notification can be sent.
            let b = Message::Notification(n.clone()).to_bytes(&TWO).unwrap();
            assert_eq!(decode(&b, &TWO), Ok(Message::Notification(n)));
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_refuse_what_readers_refuse() {
        let id = Ipv4Addr::new(10, 0, 0, 1);
        let open = |p: Vec<Parameter>| Message::Open(Open { my_as: 1, hold_time: 90, bgp_id: id, parameters: p });
        let bad = |m: Message, ctx: &Context| m.to_bytes(ctx).unwrap_err();
        let invalid = |m: Message, ctx: &Context| matches!(bad(m, ctx), EncodeError::Invalid(_));
        assert!(invalid(Message::Open(Open { hold_time: 2, ..Open::new(1, 0, id, vec![]) }), &TWO));
        assert!(invalid(Message::Open(Open::new(1, 0, Ipv4Addr::UNSPECIFIED, vec![])), &TWO));
        assert!(invalid(open(vec![Parameter::Other { kind: 2, value: vec![] }]), &TWO));
        assert!(invalid(open(vec![Parameter::Other { kind: 1, value: vec![0; 256] }]), &TWO));
        assert!(invalid(open(vec![Parameter::Other { kind: 1, value: vec![0; 200] }; 2]), &TWO));
        let caps = |c: Vec<Capability>| open(vec![Parameter::Capabilities(c)]);
        assert!(invalid(caps(vec![Capability::Other { code: 65, value: vec![0; 4] }]), &TWO));
        assert!(invalid(caps(vec![Capability::Other { code: 9, value: vec![0; 256] }]), &TWO));
        assert!(invalid(caps(vec![Capability::RouteRefresh; 128]), &TWO));
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
        assert!(gr(15, 4095, 60).to_bytes(&TWO).is_ok());

        let path = |asns: Vec<u32>| Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns }]);
        let route = |attributes: Vec<Attribute>| {
            Message::Update(Update { withdrawn: vec![], attributes, nlri: vec![v4(10, 0, 0, 0, 8)] })
        };
        let well_known =
            || vec![Attribute::Origin(Origin::Igp), path(vec![1]), Attribute::NextHop(Ipv4Addr::new(1, 2, 3, 4))];
        assert!(route(well_known()).to_bytes(&TWO).is_ok());
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
        assert!(with(path(vec![70000])).to_bytes(&FOUR).is_ok());
        let mut agg = well_known();
        agg.push(Attribute::Aggregator { asn: 70000, address: id });
        assert!(invalid(route(agg.clone()), &TWO));
        assert!(route(agg).to_bytes(&FOUR).is_ok());
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
                    Attribute::Origin(Origin::Igp),
                    path(vec![1]),
                    Attribute::MpReach(MpReach { afi, safi: 1, next_hop, nlri }),
                ],
                ..Update::default()
            })
        };
        assert!(invalid(reach(vec![0; 256], 2, Nlri::Prefixes(vec![])), &TWO));
        assert!(invalid(reach(vec![0; 16], 2, Nlri::Raw(vec![])), &TWO));
        assert!(invalid(reach(vec![0; 16], 9, Nlri::Prefixes(vec![])), &TWO));
        assert!(invalid(reach(vec![0; 4], 2, Nlri::Prefixes(vec![v4(1, 0, 0, 0, 8)])), &TWO));
        assert!(reach(vec![0; 4], 9, Nlri::Raw(vec![1, 2, 3])).to_bytes(&TWO).is_ok());
        // Too much for one message.
        let mut many = well_known();
        many.push(Attribute::Communities(vec![1; 1100]));
        assert_eq!(bad(route(many), &TWO), EncodeError::TooLong);
        let mut huge = well_known();
        huge.push(Attribute::Communities(vec![1; 10_000_000]));
        assert_eq!(bad(route(huge), &TWO), EncodeError::TooLong);
        let mut unknown = well_known();
        unknown.push(Attribute::Unknown { flags: 0x80, kind: 99, value: vec![0; 5000] });
        assert_eq!(bad(route(unknown), &TWO), EncodeError::TooLong);
        assert_eq!(bad(reach(vec![0; 4], 9, Nlri::Raw(vec![0; 5000])), &TWO), EncodeError::TooLong);
        let note = Notification { code: 6, subcode: 0, data: vec![0; MAX_BODY_LEN - 1] };
        assert_eq!(bad(Message::Notification(note), &TWO), EncodeError::TooLong);
        let note = Notification { code: 6, subcode: 0, data: vec![0; MAX_BODY_LEN - 2] };
        let b = Message::Notification(note).to_bytes(&TWO).unwrap();
        assert_eq!(b.len(), MAX_MESSAGE_LEN);
        assert!(decode(&b, &TWO).is_ok());
        assert!(!EncodeError::TooLong.to_string().is_empty());
    }

    #[test]
    fn samples_round_trip() {
        for (b, ctx) in samples() {
            let m = decode(&b, &ctx).unwrap();
            assert_eq!(m.to_bytes(&ctx).unwrap(), b, "{m:?}");
        }
    }

    #[test]
    fn every_truncated_prefix_waits_for_more() {
        for (b, ctx) in samples() {
            for n in 0..b.len() {
                assert_eq!(Frame::parse(&b[..n]), Ok(None), "{n} of {} bytes", b.len());
            }
            // Bodies cut short never read as the whole message, and never
            // panic.
            let (frame, _) = Frame::parse(&b).unwrap().unwrap();
            let whole = Message::decode(&frame, &ctx).unwrap();
            for n in 0..frame.body.len() {
                let cut = Frame { kind: frame.kind, body: frame.body[..n].to_vec() };
                if let Ok(m) = Message::decode(&cut, &ctx) {
                    assert_ne!(m, whole);
                }
            }
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let all = samples();
        let stream: Vec<u8> = all.iter().filter(|(_, c)| *c == TWO).flat_map(|(b, _)| b.clone()).collect();
        let mut d = Decoder::new();
        let mut kinds = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(f) = d.next_frame() {
                kinds.push(f.unwrap().kind);
            }
        }
        assert_eq!(kinds, [1, 2, 4, 5, 3]);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        d.feed(&[0xff, 0xff, 0]);
        assert_eq!(d.next_frame(), Some(Err(Error::ConnectionNotSynchronized)));
        d.feed(&stream);
        assert_eq!(d.next_frame(), Some(Err(Error::ConnectionNotSynchronized)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_frames_in_linear_time() {
        let one = Message::Keepalive.to_bytes(&TWO).unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut n = 0;
        while let Some(f) = d.next_frame() {
            f.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    /// Checks what the fuzz target checks: a message read can be written,
    /// and reads back the same.
    fn check_frame(frame: &Frame) {
        for ctx in [TWO, FOUR] {
            if let Ok(m) = Message::decode(frame, &ctx) {
                let bytes = m.to_bytes(&ctx).unwrap_or_else(|e| panic!("{m:?} cannot be written: {e}"));
                assert!(bytes.len() <= MAX_MESSAGE_LEN);
                let (back, used) = Frame::parse(&bytes).unwrap().unwrap();
                assert_eq!(used, bytes.len());
                assert_eq!(Message::decode(&back, &ctx), Ok(m));
            } else if let Err(e) = Message::decode(frame, &ctx) {
                let n = e.notification();
                assert!(Message::Notification(n).to_bytes(&ctx).is_ok());
            }
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        let bases: Vec<Vec<u8>> = samples().into_iter().map(|(b, _)| b).collect();
        for round in 0..6000 {
            let mut b = bases[next() as usize % bases.len()].clone();
            match round % 4 {
                // Flip a few bytes after the marker.
                0 | 1 => {
                    for _ in 0..1 + next() % 4 {
                        let i = HEADER_LEN + next() as usize % b.len().saturating_sub(HEADER_LEN).max(1);
                        if i < b.len() {
                            b[i] = next() as u8;
                        }
                    }
                }
                // Cut the body short or grow it, and fix the length field.
                2 => {
                    let n = HEADER_LEN + next() as usize % (b.len() + 8 - HEADER_LEN);
                    b.resize(n, next() as u8);
                    b[16..18].copy_from_slice(&(n as u16).to_be_bytes());
                }
                // Any bytes at all, behind a good marker half the time.
                _ => {
                    let n = next() as usize % 64;
                    b = (0..n).map(|_| next() as u8).collect();
                    if next() % 2 == 0 && b.len() >= MARKER_LEN {
                        b[..MARKER_LEN].fill(0xff);
                    }
                }
            }
            let mut whole = Decoder::new();
            whole.feed(&b);
            let mut frames = Vec::new();
            while let Some(Ok(f)) = whole.next_frame() {
                frames.push(f);
            }
            let mut bytewise = Decoder::new();
            let mut again = Vec::new();
            for byte in &b {
                bytewise.feed(std::slice::from_ref(byte));
                while let Some(Ok(f)) = bytewise.next_frame() {
                    again.push(f);
                }
            }
            assert_eq!(frames, again);
            for f in &frames {
                check_frame(f);
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
        let mut seed: u64 = 7;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        let mut read = 0;
        for _ in 0..20_000 {
            let mut attrs = Vec::new();
            for _ in 0..next() % 4 {
                let kind = [1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 99][next() as usize % 11];
                let flags = match next() % 3 {
                    0 => known_flags(kind).unwrap_or(0x80),
                    1 => known_flags(kind).unwrap_or(0xc0) | flag::EXTENDED_LENGTH,
                    _ => next() as u8,
                };
                let n = next() as usize % 12;
                let mut v: Vec<u8> = (0..n).map(|_| next() as u8 % 6).collect();
                if kind == 14 || kind == 15 {
                    v.splice(0..0, [0, 1 + next() as u8 % 2, 1, 0]);
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
            if next() % 2 == 0 {
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
}
