//! STUN: reading and writing Session Traversal Utilities for NAT messages,
//! with no I/O.
//!
//! STUN is how a host behind a NAT learns the public address and port its
//! packets leave from. A client sends a Binding request, usually over UDP to
//! port 3478, and the server answers with the source address it saw, in an
//! XOR-MAPPED-ADDRESS attribute. ICE, WebRTC and TURN are all built on it.
//! This module follows RFC 8489.
//!
//! Every message starts with a 20-byte header: a message type that packs a
//! method and a class, a body length, the magic cookie `0x2112A442` and a
//! 96-bit transaction ID the client picks. Attributes follow, each a type, a
//! length and a value padded to a multiple of 4 bytes. Attribute types
//! below `0x8000` are comprehension-required: a server that does not know
//! one must refuse the request with error 420 and list it in
//! UNKNOWN-ATTRIBUTES. [`Message::unknown_comprehension_required`] finds
//! them, and [`answer_binding`] does all of this for a Binding request.
//!
//! Nothing here reads a socket. A world that plays a STUN server takes each
//! UDP datagram it receives, reads it with [`Message::parse`], passes it and
//! the datagram's source address to [`answer_binding`], and sends the
//! reply's bytes back. Over TCP, [`Frames`] and [`codec::Stream`] split the
//! byte stream into messages. Use [`codec::Stream::with_next`] for each
//! frame's exact bytes. Integrity values stay as raw bytes. World code
//! computes HMACs over those original bytes, including their padding.
//! [`codec::Wire::write`] uses zero padding and recomputes FINGERPRINT.
//! It rejects invalid fields and leaves the destination unchanged.
//!
//! ```
//! use std::net::SocketAddr;
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::stun::{answer_binding, Class, Message, method};
//!
//! // The client asks for its public address, with a FINGERPRINT.
//! let tid = [7u8; 12];
//! let mut request = Message::binding_request(tid);
//! request.fingerprint = true;
//! let datagram = request.to_bytes().unwrap();
//! assert_eq!(datagram.len(), 20 + 8);
//!
//! // The server reads it and answers with the source address it saw.
//! let seen: SocketAddr = "192.0.2.1:32853".parse().unwrap();
//! let received = Message::parse(&datagram).unwrap();
//! assert_eq!((received.method, received.class), (method::BINDING, Class::Request));
//! let reply = answer_binding(&received, seen).unwrap().to_bytes().unwrap();
//!
//! // The client reads its address back.
//! let response = Message::parse(&reply).unwrap();
//! assert_eq!(response.class, Class::SuccessResponse);
//! assert_eq!(response.transaction, tid);
//! assert_eq!(response.xor_mapped_address(), Some(seen));
//! assert!(response.fingerprint);
//! ```

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::codec::{self, Decode, Step};

/// The UDP and TCP port STUN servers listen on.
pub const PORT: u16 = 3478;
/// The port STUN servers listen on for TLS and DTLS.
pub const TLS_PORT: u16 = 5349;
/// The fixed value in bytes 4 to 7 of every message.
pub const MAGIC_COOKIE: u32 = 0x2112_a442;
/// The length of the message header, before the attributes.
pub const HEADER_LEN: usize = 20;
/// The longest body (all attributes) a message may have: the largest
/// 16-bit length that is a multiple of 4.
pub const MAX_BODY: usize = 65532;
/// The longest message: the header and the longest body.
pub const MAX_MESSAGE: usize = HEADER_LEN + MAX_BODY;
/// The most attributes one message may hold, FINGERPRINT included. A parser
/// refuses messages with more, so a reader never builds a huge list.
pub const MAX_ATTRIBUTES: usize = 256;
/// The longest value an [`Attribute::Other`] or UNKNOWN-ATTRIBUTES list may
/// have: the longest body, less one attribute header.
pub const MAX_VALUE: usize = MAX_BODY - 4;
/// The most bytes of UTF-8 a reader takes in USERNAME, SOFTWARE, REALM,
/// NONCE and an ERROR-CODE reason. RFC 8489 asks readers to take up to 763
/// bytes, for senders that follow the older RFC 5389.
pub const MAX_TEXT: usize = 763;
/// XORed into the CRC-32 of a message to make its FINGERPRINT value. It is
/// "STUN" in ASCII.
pub const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// Methods, the 12-bit numbers that say what a message is about.
pub mod method {
    /// Binding: learn the address a server sees packets come from.
    pub const BINDING: u16 = 0x001;
}

/// Attribute types from RFC 8489. Types below `0x8000` are
/// comprehension-required.
pub mod attr {
    #![allow(missing_docs)]
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000a;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001c;
    pub const PASSWORD_ALGORITHM: u16 = 0x001d;
    pub const USERHASH: u16 = 0x001e;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const PASSWORD_ALGORITHMS: u16 = 0x8002;
    pub const ALTERNATE_DOMAIN: u16 = 0x8003;
    pub const SOFTWARE: u16 = 0x8022;
    pub const ALTERNATE_SERVER: u16 = 0x8023;
    pub const FINGERPRINT: u16 = 0x8028;
    /// The lowest comprehension-optional type. Types below it are
    /// comprehension-required.
    pub const OPTIONAL_START: u16 = 0x8000;
}

/// Error codes from RFC 8489, for ERROR-CODE.
pub mod code {
    #![allow(missing_docs)]
    pub const TRY_ALTERNATE: u16 = 300;
    pub const BAD_REQUEST: u16 = 400;
    pub const UNAUTHENTICATED: u16 = 401;
    pub const FORBIDDEN: u16 = 403;
    pub const UNKNOWN_ATTRIBUTE: u16 = 420;
    pub const STALE_NONCE: u16 = 438;
    pub const SERVER_ERROR: u16 = 500;
}

/// The reason phrase RFC 8489 suggests for an error code, or "Error" for a
/// code it does not name.
pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        code::TRY_ALTERNATE => "Try Alternate",
        code::BAD_REQUEST => "Bad Request",
        code::UNAUTHENTICATED => "Unauthenticated",
        code::FORBIDDEN => "Forbidden",
        code::UNKNOWN_ATTRIBUTE => "Unknown Attribute",
        code::STALE_NONCE => "Stale Nonce",
        code::SERVER_ERROR => "Server Error",
        _ => "Error",
    }
}

/// A message's class: what role it plays in an exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Asks for an answer.
    Request,
    /// Says something and expects no answer.
    Indication,
    /// Answers a request that succeeded.
    SuccessResponse,
    /// Answers a request that failed. It carries an ERROR-CODE.
    ErrorResponse,
}

impl Class {
    /// The class's two bits, C1 and C0.
    pub fn bits(self) -> u16 {
        match self {
            Class::Request => 0b00,
            Class::Indication => 0b01,
            Class::SuccessResponse => 0b10,
            Class::ErrorResponse => 0b11,
        }
    }

    /// The class for two bits. Only the low two bits of `b` are read.
    pub fn from_bits(b: u16) -> Class {
        match b & 0b11 {
            0b00 => Class::Request,
            0b01 => Class::Indication,
            0b10 => Class::SuccessResponse,
            _ => Class::ErrorResponse,
        }
    }
}

/// The 14-bit message type for a method and a class. The method's 12 bits
/// are split around the class bits: `M11..M7 C1 M6..M4 C0 M3..M0`. Bits of
/// `method` above the low 12 are dropped.
pub fn message_type(method: u16, class: Class) -> u16 {
    let m = method & 0x0fff;
    let c = class.bits();
    (m & 0x000f) | ((m & 0x0070) << 1) | ((m & 0x0f80) << 2) | ((c & 1) << 4) | ((c & 2) << 7)
}

/// Splits a message type into its method and class. Bits above the low 14
/// are ignored.
pub fn split_type(t: u16) -> (u16, Class) {
    let m = (t & 0x000f) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0f80);
    let c = ((t >> 4) & 1) | ((t >> 7) & 2);
    (m, Class::from_bits(c))
}

/// Whether `b` starts like a STUN message: the top two bits are zero and
/// the magic cookie is in place. Use it to tell STUN apart from other
/// traffic on the same port. It reads at most 8 bytes and needs at least 8.
pub fn is_stun(b: &[u8]) -> bool {
    b.first().is_some_and(|first| first & 0xc0 == 0) && be32(b, 4) == Some(MAGIC_COOKIE)
}

/// One attribute. Types this module reads become their own variant. Every
/// other type stays as raw bytes in [`Attribute::Other`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribute {
    /// MAPPED-ADDRESS: an address in the clear. Old servers sent it in
    /// place of XOR-MAPPED-ADDRESS. On the wire an address is only an IP
    /// and a port. The writer refuses nonzero IPv6 flow labels and scope
    /// IDs. A reader sets both
    /// to zero. The same holds for the other address variants.
    MappedAddress(SocketAddr),
    /// XOR-MAPPED-ADDRESS: the address the server saw the request come
    /// from. On the wire it is XORed with the magic cookie and transaction
    /// ID, so NATs that rewrite addresses in packets leave it alone. Here
    /// it is the plain address.
    XorMappedAddress(SocketAddr),
    /// ALTERNATE-SERVER: another server to try, sent with error 300.
    AlternateServer(SocketAddr),
    /// USERNAME. The parser and strict writer accept [`MAX_TEXT`] bytes.
    /// The writer accepts up to [`MAX_TEXT`] bytes.
    Username(String),
    /// REALM. The parser and strict writer accept [`MAX_TEXT`] bytes.
    /// The writer accepts up to [`MAX_TEXT`] bytes.
    Realm(String),
    /// NONCE, with the same limits as REALM.
    Nonce(String),
    /// SOFTWARE: the sender's name and version, with the same limits as
    /// REALM.
    Software(String),
    /// ERROR-CODE: a code from 300 to 699 and a reason phrase with the same
    /// limits as REALM.
    ErrorCode {
        /// The code: the hundreds digit is its class, 3 to 6.
        code: u16,
        /// Words for people to read.
        reason: String,
    },
    /// UNKNOWN-ATTRIBUTES: the comprehension-required types a server did
    /// not know, sent with error 420.
    UnknownAttributes(Vec<u16>),
    /// Any other attribute, such as MESSAGE-INTEGRITY, kept as it came
    /// without its padding.
    Other {
        /// The attribute type. A parser never puts a type with its own
        /// variant here, nor FINGERPRINT.
        typ: u16,
        /// The value, without padding.
        value: Vec<u8>,
    },
}

impl Attribute {
    /// The attribute's type number.
    pub fn typ(&self) -> u16 {
        match self {
            Attribute::MappedAddress(_) => attr::MAPPED_ADDRESS,
            Attribute::XorMappedAddress(_) => attr::XOR_MAPPED_ADDRESS,
            Attribute::AlternateServer(_) => attr::ALTERNATE_SERVER,
            Attribute::Username(_) => attr::USERNAME,
            Attribute::Realm(_) => attr::REALM,
            Attribute::Nonce(_) => attr::NONCE,
            Attribute::Software(_) => attr::SOFTWARE,
            Attribute::ErrorCode { .. } => attr::ERROR_CODE,
            Attribute::UnknownAttributes(_) => attr::UNKNOWN_ATTRIBUTES,
            Attribute::Other { typ, .. } => *typ,
        }
    }

    /// Whether a receiver must understand this attribute to process the
    /// message: its type is below `0x8000`.
    pub fn comprehension_required(&self) -> bool {
        self.typ() < attr::OPTIONAL_START
    }

    /// Reads one attribute's value. `transaction` is the message's, needed
    /// to undo the XOR in XOR-MAPPED-ADDRESS. FINGERPRINT is not read here,
    /// since it depends on the bytes before it; it comes back as an error.
    /// A value longer than [`MAX_VALUE`], which no message can hold, is
    /// refused before anything is copied.
    pub fn parse(typ: u16, value: &[u8], transaction: &[u8; 12]) -> Result<Attribute, ParseError> {
        let bad = || ParseError::AttributeValue { typ, len: value.len() };
        if value.len() > MAX_VALUE {
            return Err(bad());
        }
        match typ {
            attr::MAPPED_ADDRESS => Ok(Attribute::MappedAddress(read_address(typ, value, None)?)),
            attr::ALTERNATE_SERVER => Ok(Attribute::AlternateServer(read_address(typ, value, None)?)),
            attr::XOR_MAPPED_ADDRESS => {
                Ok(Attribute::XorMappedAddress(read_address(typ, value, Some(transaction))?))
            }
            attr::USERNAME => Ok(Attribute::Username(read_text(typ, value, MAX_TEXT)?)),
            attr::REALM => Ok(Attribute::Realm(read_text(typ, value, MAX_TEXT)?)),
            attr::NONCE => Ok(Attribute::Nonce(read_text(typ, value, MAX_TEXT)?)),
            attr::SOFTWARE => Ok(Attribute::Software(read_text(typ, value, MAX_TEXT)?)),
            attr::ERROR_CODE => {
                let [_, _, class_byte, number_byte, reason @ ..] = value else { return Err(bad()) };
                let class = u16::from(class_byte & 0x07);
                let number = u16::from(*number_byte);
                if !(3..=6).contains(&class) || number > 99 {
                    return Err(ParseError::ErrorCode { class: class_byte & 0x07, number: *number_byte });
                }
                let reason = read_text(typ, reason, MAX_TEXT)?;
                Ok(Attribute::ErrorCode { code: class * 100 + number, reason })
            }
            attr::UNKNOWN_ATTRIBUTES => {
                if !value.len().is_multiple_of(2) {
                    return Err(bad());
                }
                Ok(Attribute::UnknownAttributes(value.chunks_exact(2).filter_map(|c| be16(c, 0)).collect()))
            }
            attr::FINGERPRINT => Err(ParseError::FingerprintNotLast),
            _ if !integrity_length_ok(typ, value.len()) => Err(bad()),
            _ => Ok(Attribute::Other { typ, value: value.to_vec() }),
        }
    }

    // Each allocation is bounded by MAX_VALUE. Text uses the parser's
    // limit so every parsed message can be written without changing it.
    fn strict_value(&self, transaction: &[u8; 12]) -> Result<Vec<u8>, WriteError> {
        let bad = WriteError::Attribute { typ: self.typ() };
        match self {
            Attribute::MappedAddress(a) | Attribute::XorMappedAddress(a) | Attribute::AlternateServer(a) => {
                if let SocketAddr::V6(a) = a
                    && (a.flowinfo() != 0 || a.scope_id() != 0)
                {
                    return Err(bad);
                }
            }
            Attribute::Username(s) | Attribute::Realm(s) | Attribute::Nonce(s) | Attribute::Software(s) => {
                return if s.len() <= MAX_TEXT { Ok(s.as_bytes().to_vec()) } else { Err(bad) };
            }
            Attribute::ErrorCode { code, reason } => {
                if !(300..=699).contains(code) || reason.len() > MAX_TEXT {
                    return Err(bad);
                }
                let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
                value.extend_from_slice(reason.as_bytes());
                return Ok(value);
            }
            Attribute::UnknownAttributes(types) if types.len() > MAX_VALUE / 2 => return Err(bad),
            Attribute::Other { value, .. } if value.len() > MAX_VALUE => return Err(bad),
            _ => {}
        }
        Ok(match self {
            Attribute::MappedAddress(a) | Attribute::AlternateServer(a) => write_address(*a, None),
            Attribute::XorMappedAddress(a) => write_address(*a, Some(transaction)),
            Attribute::UnknownAttributes(types) => types.iter().flat_map(|t| t.to_be_bytes()).collect(),
            Attribute::Other { typ, value } => {
                if is_known(*typ) || !integrity_length_ok(*typ, value.len()) {
                    return Err(bad);
                }
                value.clone()
            }
            _ => return Err(bad),
        })
    }
}

/// One STUN message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The method, 12 bits. Higher bits are refused by the writer.
    /// The strict writer refuses them.
    pub method: u16,
    /// The class.
    pub class: Class,
    /// The 96-bit transaction ID. A request's ID is copied into its
    /// response, so the client can match them.
    pub transaction: [u8; 12],
    /// The attributes in order, without FINGERPRINT.
    pub attributes: Vec<Attribute>,
    /// Whether the message ends with a FINGERPRINT. A parser sets it only
    /// when the fingerprint was correct. A writer computes the value.
    pub fingerprint: bool,
}

/// Why bytes are not a STUN message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the header, or than the header's length says.
    Truncated,
    /// More bytes than the header's length says. A UDP datagram holds
    /// exactly one message.
    TrailingBytes(usize),
    /// The first byte's top two bits were not zero, so this is not STUN.
    TopBits(u8),
    /// The length field was not a multiple of 4.
    Length(u16),
    /// Bytes 4 to 7 were not the magic cookie.
    MagicCookie(u32),
    /// An attribute's header or value ran past the end of the message.
    AttributeTruncated {
        /// The attribute's type.
        typ: u16,
    },
    /// The message held more than [`MAX_ATTRIBUTES`] attributes.
    TooManyAttributes,
    /// An attribute's value had a length its type does not allow.
    AttributeValue {
        /// The attribute's type.
        typ: u16,
        /// The value's length.
        len: usize,
    },
    /// An address attribute named a family other than IPv4 (1) or IPv6 (2).
    /// Only [`Attribute::parse`] returns it: [`Message::parse`] skips such
    /// an attribute, since RFC 8489 says to ignore it.
    AddressFamily(u8),
    /// Text that was not UTF-8, or longer than [`MAX_TEXT`] bytes.
    Text {
        /// The attribute's type.
        typ: u16,
    },
    /// An ERROR-CODE whose class was not 3 to 6, or whose number was over
    /// 99.
    ErrorCode {
        /// The class field, the hundreds digit.
        class: u8,
        /// The number field, the last two digits.
        number: u8,
    },
    /// A FINGERPRINT that was not the last attribute.
    FingerprintNotLast,
    /// A FINGERPRINT whose value did not match the message.
    Fingerprint {
        /// The value the message's bytes give.
        expected: u32,
        /// The value the message carried.
        found: u32,
    },
}

impl ParseError {
    /// Whether the error is in the header, so a byte stream holding it
    /// cannot be split into messages any further. Other errors are in one
    /// message's attributes, and the messages after it can still be read.
    pub fn is_framing(&self) -> bool {
        matches!(self, ParseError::TopBits(_) | ParseError::Length(_) | ParseError::MagicCookie(_))
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => f.write_str("message cut short"),
            ParseError::TrailingBytes(n) => write!(f, "{n} bytes after the message"),
            ParseError::TopBits(b) => write!(f, "first byte {b:#04x} has its top bits set, not STUN"),
            ParseError::Length(n) => write!(f, "message length {n} is not a multiple of 4"),
            ParseError::MagicCookie(c) => write!(f, "magic cookie {c:#010x}, not 0x2112a442"),
            ParseError::AttributeTruncated { typ } => write!(f, "attribute {typ:#06x} runs past the message"),
            ParseError::TooManyAttributes => write!(f, "more than {MAX_ATTRIBUTES} attributes"),
            ParseError::AttributeValue { typ, len } => {
                write!(f, "attribute {typ:#06x} has a bad length {len}")
            }
            ParseError::AddressFamily(fam) => write!(f, "address family {fam}, not 1 or 2"),
            ParseError::Text { typ } => write!(f, "attribute {typ:#06x} is not UTF-8 or is too long"),
            ParseError::ErrorCode { class, number } => write!(f, "error code class {class} number {number}"),
            ParseError::FingerprintNotLast => f.write_str("FINGERPRINT is not the last attribute"),
            ParseError::Fingerprint { expected, found } => {
                write!(f, "FINGERPRINT {found:#010x}, the message gives {expected:#010x}")
            }
        }
    }
}

impl core::error::Error for ParseError {}

/// Why a message cannot be written without changing its fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The method has bits outside the 12-bit field.
    Method(u16),
    /// The attribute count, including FINGERPRINT, exceeds [`MAX_ATTRIBUTES`].
    TooManyAttributes,
    /// The encoded attributes, including FINGERPRINT, exceed [`MAX_BODY`].
    BodyTooLong,
    /// An attribute cannot be read back as the same value.
    ///
    /// This includes invalid lengths, text over [`MAX_TEXT`], invalid error
    /// codes, and nonzero IPv6 flow labels or scope IDs. It also includes
    /// known types stored in [`Attribute::Other`] and attributes the parser
    /// would ignore after an integrity attribute.
    Attribute {
        /// The attribute's type.
        typ: u16,
    },
}

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Method(method) => write!(f, "method {method:#06x} exceeds 12 bits"),
            Self::TooManyAttributes => write!(f, "more than {MAX_ATTRIBUTES} attributes"),
            Self::BodyTooLong => write!(f, "message body exceeds {MAX_BODY} bytes"),
            Self::Attribute { typ } => write!(f, "attribute {typ:#06x} cannot be written unchanged"),
        }
    }
}

impl core::error::Error for WriteError {}

impl Message {
    /// A message with no attributes and no FINGERPRINT.
    pub fn new(method: u16, class: Class, transaction: [u8; 12]) -> Message {
        Message { method: method & 0x0fff, class, transaction, attributes: Vec::new(), fingerprint: false }
    }

    /// A Binding request with no attributes.
    pub fn binding_request(transaction: [u8; 12]) -> Message {
        Message::new(method::BINDING, Class::Request, transaction)
    }

    /// Reads one whole message, such as a UDP datagram. `b` must hold
    /// exactly the message.
    ///
    /// Some attributes are skipped, as RFC 8489 says a receiver ignores
    /// them, and do not appear in [`Message::attributes`]: an address
    /// attribute with a family other than IPv4 or IPv6, and everything
    /// after MESSAGE-INTEGRITY except MESSAGE-INTEGRITY-SHA256 and
    /// FINGERPRINT, and everything but FINGERPRINT after a
    /// MESSAGE-INTEGRITY-SHA256.
    pub fn parse(b: &[u8]) -> Result<Message, ParseError> {
        let total = match header(b)? {
            Some(n) => n,
            None => return Err(ParseError::Truncated),
        };
        if b.len() > total {
            return Err(ParseError::TrailingBytes(b.len() - total));
        }
        let (method, class) = split_type(be16(b, 0).ok_or(ParseError::Truncated)?);
        let mut transaction = [0u8; 12];
        transaction.copy_from_slice(b.get(8..HEADER_LEN).ok_or(ParseError::Truncated)?);
        let mut attributes = Vec::new();
        let mut fingerprint = false;
        let mut integrity = Integrity::None;
        let mut at = HEADER_LEN;
        let mut count = 0usize;
        while at < total {
            let tail = b.get(at..total).ok_or(ParseError::AttributeTruncated { typ: 0 })?;
            let [hi, lo, len_hi, len_lo, rest @ ..] = tail else {
                return Err(ParseError::AttributeTruncated { typ: 0 });
            };
            let typ = u16::from_be_bytes([*hi, *lo]);
            let len = usize::from(u16::from_be_bytes([*len_hi, *len_lo]));
            let value = rest.get(..len).ok_or(ParseError::AttributeTruncated { typ })?;
            count += 1;
            if count > MAX_ATTRIBUTES {
                return Err(ParseError::TooManyAttributes);
            }
            // Offsets stay multiples of 4 and the body is one, so the
            // padding always fits once the value does.
            let next = at
                .checked_add(4)
                .and_then(|n| n.checked_add(padded(len)))
                .filter(|&n| n <= total)
                .ok_or(ParseError::AttributeTruncated { typ })?;
            if typ == attr::FINGERPRINT {
                if next != total {
                    return Err(ParseError::FingerprintNotLast);
                }
                if len != 4 {
                    return Err(ParseError::AttributeValue { typ, len });
                }
                let expected = crc32(b.get(..at).ok_or(ParseError::Truncated)?) ^ FINGERPRINT_XOR;
                let found = be32(value, 0).ok_or(ParseError::AttributeValue { typ, len })?;
                if expected != found {
                    return Err(ParseError::Fingerprint { expected, found });
                }
                fingerprint = true;
            } else if integrity_keeps(&mut integrity, typ) {
                match Attribute::parse(typ, value, &transaction) {
                    Ok(a) => attributes.push(a),
                    // An address family this module does not know is
                    // ignored (RFC 8489, section 6.3.3).
                    Err(ParseError::AddressFamily(_)) => {}
                    Err(e) => return Err(e),
                }
            }
            at = next;
        }
        Ok(Message { method, class, transaction, attributes, fingerprint })
    }

    /// The first attribute of type `typ`. RFC 8489 says a receiver reads
    /// only the first of each type.
    pub fn get(&self, typ: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.typ() == typ)
    }

    /// The first XOR-MAPPED-ADDRESS.
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        match self.get(attr::XOR_MAPPED_ADDRESS) {
            Some(Attribute::XorMappedAddress(a)) => Some(*a),
            _ => None,
        }
    }

    /// The first MAPPED-ADDRESS.
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        match self.get(attr::MAPPED_ADDRESS) {
            Some(Attribute::MappedAddress(a)) => Some(*a),
            _ => None,
        }
    }

    /// The first ERROR-CODE: the code and its reason phrase.
    pub fn error_code(&self) -> Option<(u16, &str)> {
        match self.get(attr::ERROR_CODE) {
            Some(Attribute::ErrorCode { code, reason }) => Some((*code, reason)),
            _ => None,
        }
    }

    /// The first SOFTWARE.
    pub fn software(&self) -> Option<&str> {
        match self.get(attr::SOFTWARE) {
            Some(Attribute::Software(s)) => Some(s),
            _ => None,
        }
    }

    /// The first USERNAME.
    pub fn username(&self) -> Option<&str> {
        match self.get(attr::USERNAME) {
            Some(Attribute::Username(s)) => Some(s),
            _ => None,
        }
    }

    /// The first REALM.
    pub fn realm(&self) -> Option<&str> {
        match self.get(attr::REALM) {
            Some(Attribute::Realm(s)) => Some(s),
            _ => None,
        }
    }

    /// The first NONCE.
    pub fn nonce(&self) -> Option<&str> {
        match self.get(attr::NONCE) {
            Some(Attribute::Nonce(s)) => Some(s),
            _ => None,
        }
    }

    /// The first ALTERNATE-SERVER.
    pub fn alternate_server(&self) -> Option<SocketAddr> {
        match self.get(attr::ALTERNATE_SERVER) {
            Some(Attribute::AlternateServer(a)) => Some(*a),
            _ => None,
        }
    }

    /// The types in the first UNKNOWN-ATTRIBUTES, as a server listed them
    /// in a 420 error response.
    pub fn unknown_attributes(&self) -> Option<&[u16]> {
        match self.get(attr::UNKNOWN_ATTRIBUTES) {
            Some(Attribute::UnknownAttributes(t)) => Some(t),
            _ => None,
        }
    }

    /// The comprehension-required types (below `0x8000`) this module does
    /// not read, in the order they first appear, each once. These are the
    /// [`Attribute::Other`] types below `0x8000`, and they include
    /// MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256: world code that
    /// checks them should drop those types from the list.
    pub fn unknown_comprehension_required(&self) -> Vec<u16> {
        let mut out: Vec<u16> = Vec::new();
        for a in &self.attributes {
            if let Attribute::Other { typ, .. } = a
                && *typ < attr::OPTIONAL_START
                && !out.contains(typ)
            {
                out.push(*typ);
            }
        }
        out
    }

    /// A success response to this message, with the same method and
    /// transaction ID, holding `source` in an XOR-MAPPED-ADDRESS. It has a
    /// FINGERPRINT if this message had one.
    pub fn success_response(&self, source: SocketAddr) -> Message {
        let mut m = Message::new(self.method, Class::SuccessResponse, self.transaction);
        m.attributes.push(Attribute::XorMappedAddress(source));
        m.fingerprint = self.fingerprint;
        m
    }

    /// An error response to this message, with the same method and
    /// transaction ID, holding an ERROR-CODE with `code` and its
    /// [`reason_phrase`]. It has a FINGERPRINT if this message had one.
    pub fn error_response(&self, code: u16) -> Message {
        let mut m = Message::new(self.method, Class::ErrorResponse, self.transaction);
        m.attributes.push(Attribute::ErrorCode { code, reason: reason_phrase(code).to_string() });
        m.fingerprint = self.fingerprint;
        m
    }
}

impl codec::Wire for Message {
    type ParseError = ParseError;
    type WriteError = WriteError;

    fn parse(bytes: &[u8]) -> Result<Self, Self::ParseError> {
        Message::parse(bytes)
    }

    /// Appends a strict message. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if self.method > 0x0fff {
            return Err(WriteError::Method(self.method));
        }
        let reserve = if self.fingerprint { 8 } else { 0 };
        if self.attributes.len() > MAX_ATTRIBUTES - usize::from(self.fingerprint) {
            return Err(WriteError::TooManyAttributes);
        }
        let mut body = Vec::new();
        let mut integrity = Integrity::None;
        for attribute in &self.attributes {
            let typ = attribute.typ();
            if !integrity_keeps(&mut integrity, typ) {
                return Err(WriteError::Attribute { typ });
            }
            let value = attribute.strict_value(&self.transaction)?;
            let end = body
                .len()
                .checked_add(4)
                .and_then(|n| n.checked_add(padded(value.len())))
                .filter(|&n| n <= MAX_BODY - reserve)
                .ok_or(WriteError::BodyTooLong)?;
            let len = u16::try_from(value.len()).map_err(|_| WriteError::Attribute { typ })?;
            body.extend_from_slice(&typ.to_be_bytes());
            body.extend_from_slice(&len.to_be_bytes());
            body.extend_from_slice(&value);
            body.resize(end, 0);
        }
        let body_len = body.len().checked_add(reserve).ok_or(WriteError::BodyTooLong)?;
        let total =
            HEADER_LEN.checked_add(body_len).filter(|&n| n <= MAX_MESSAGE).ok_or(WriteError::BodyTooLong)?;
        let length = u16::try_from(body_len).map_err(|_| WriteError::BodyTooLong)?;
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&message_type(self.method, self.class).to_be_bytes());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        frame.extend_from_slice(&self.transaction);
        frame.extend_from_slice(&body);
        if self.fingerprint {
            let crc = crc32(&frame) ^ FINGERPRINT_XOR;
            frame.extend_from_slice(&attr::FINGERPRINT.to_be_bytes());
            frame.extend_from_slice(&4u16.to_be_bytes());
            frame.extend_from_slice(&crc.to_be_bytes());
        }
        out.extend_from_slice(&frame);
        Ok(())
    }
}

/// Answers a request the way a plain STUN server does. `source` is the
/// address the request came from, as the world's socket saw it.
///
/// It returns `None` for indications and responses, which get no answer,
/// and for a request for any method but Binding, which RFC 8489 (section
/// 6.3) says a server silently discards. A Binding request with
/// comprehension-required attributes this module does not read gets error
/// 420 with UNKNOWN-ATTRIBUTES. Any other Binding request gets a success
/// response with `source` in an XOR-MAPPED-ADDRESS.
pub fn answer_binding(request: &Message, source: SocketAddr) -> Option<Message> {
    if request.class != Class::Request || request.method != method::BINDING {
        return None;
    }
    let unknown = request.unknown_comprehension_required();
    if !unknown.is_empty() {
        let mut m = request.error_response(code::UNKNOWN_ATTRIBUTE);
        m.attributes.push(Attribute::UnknownAttributes(unknown));
        return Some(m);
    }
    Some(request.success_response(source))
}

/// Reads complete STUN frames from a byte slice.
///
/// Only headers are checked. Invalid top bits, lengths, or magic cookies
/// return a stream error. Map frames through [`Message::parse`] to receive
/// attribute errors as items and continue with the next message.
///
/// This decoder owns no input. Its capacity is [`MAX_MESSAGE`]. An
/// incomplete frame returns [`Step::Need`], including at EOF, so
/// [`codec::Stream`] reports truncation. [`codec::Stream::with_next`] gives
/// access to each item's exact bytes, including padding.
///
/// ```
/// use fictionet::stdlib::{codec::{Decode, Stream, Wire}, stun::{Frames, Message}};
///
/// let message = Message::binding_request([7; 12]);
/// let bytes = Wire::to_bytes(&message)?;
/// let mut stream = Stream::new(Frames::new().map(|frame| Message::parse(&frame)));
/// assert_eq!(stream.push(&bytes), bytes.len());
/// let item = stream.with_next(|item, raw, span| {
///     assert_eq!(raw, bytes);
///     assert_eq!(span, 0..bytes.len() as u64);
///     item
/// });
/// assert_eq!(item, Some(Ok(Ok(message))));
/// stream.end();
/// assert_eq!(stream.next(), None);
/// # Ok::<(), fictionet::stdlib::stun::WriteError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;

impl Frames {
    /// Creates a frame decoder with no retained state.
    pub fn new() -> Self {
        Self
    }
}

impl Decode for Frames {
    type Item = Vec<u8>;
    type Error = ParseError;

    const NAME: &'static str = "STUN";

    fn capacity(&self) -> usize {
        MAX_MESSAGE
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let Some(total) = header(input)? else { return Ok(Step::Need) };
        let frame = input.get(..total).ok_or(ParseError::Truncated)?;
        Ok(Step::Item(frame.to_vec(), total))
    }
}

/// The CRC-32 of `data`, as used by FINGERPRINT: the IEEE 802.3
/// polynomial, reflected, starting from all ones and inverted at the end.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = CRC_TABLE.get(usize::from((crc as u8) ^ byte)).copied().unwrap_or_default() ^ (crc >> 8);
    }
    !crc
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Checks as much of a header as `b` holds, in byte order: the top bits,
/// the length, then the cookie. It returns the whole message's length once
/// the header is there, and `None` while it is not.
fn header(b: &[u8]) -> Result<Option<usize>, ParseError> {
    if let Some(&first) = b.first()
        && first & 0xc0 != 0
    {
        return Err(ParseError::TopBits(first));
    }
    let Some(length) = be16(b, 2) else { return Ok(None) };
    if !length.is_multiple_of(4) {
        return Err(ParseError::Length(length));
    }
    let Some(cookie) = be32(b, 4) else { return Ok(None) };
    if cookie != MAGIC_COOKIE {
        return Err(ParseError::MagicCookie(cookie));
    }
    let total = HEADER_LEN.checked_add(usize::from(length)).ok_or(ParseError::Length(length))?;
    if b.len() < total {
        return Ok(None);
    }
    Ok(Some(total))
}

/// Whether the parser gives `typ` its own variant or handles it itself.
fn is_known(typ: u16) -> bool {
    matches!(
        typ,
        attr::MAPPED_ADDRESS
            | attr::XOR_MAPPED_ADDRESS
            | attr::ALTERNATE_SERVER
            | attr::USERNAME
            | attr::REALM
            | attr::NONCE
            | attr::SOFTWARE
            | attr::ERROR_CODE
            | attr::UNKNOWN_ATTRIBUTES
            | attr::FINGERPRINT
    )
}

/// The XOR key for an address: the cookie, then the transaction ID.
fn xor_key(transaction: &[u8; 12]) -> [u8; 16] {
    let mut key = [0u8; 16];
    for (out, byte) in key.iter_mut().zip(MAGIC_COOKIE.to_be_bytes().iter().chain(transaction)) {
        *out = *byte;
    }
    key
}

fn read_address(typ: u16, v: &[u8], xor: Option<&[u8; 12]>) -> Result<SocketAddr, ParseError> {
    let bad = || ParseError::AttributeValue { typ, len: v.len() };
    let [_, family, hi, lo, address @ ..] = v else { return Err(bad()) };
    let key = xor.map(xor_key).unwrap_or([0; 16]);
    let port = u16::from_be_bytes([*hi, *lo]) ^ be16(&key, 0).ok_or_else(bad)?;
    match *family {
        1 => {
            if v.len() != 8 {
                return Err(ParseError::AttributeValue { typ, len: v.len() });
            }
            let mut ip = [0u8; 4];
            for ((out, byte), mask) in ip.iter_mut().zip(address).zip(key) {
                *out = byte ^ mask;
            }
            Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
        }
        2 => {
            if v.len() != 20 {
                return Err(ParseError::AttributeValue { typ, len: v.len() });
            }
            let mut ip = [0u8; 16];
            for ((out, byte), mask) in ip.iter_mut().zip(address).zip(key) {
                *out = byte ^ mask;
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0)))
        }
        f => Err(ParseError::AddressFamily(f)),
    }
}

/// An address value. The IPv6 flow label and scope are not sent.
fn write_address(a: SocketAddr, xor: Option<&[u8; 12]>) -> Vec<u8> {
    let key = xor.map(xor_key).unwrap_or([0; 16]);
    let port = a.port() ^ be16(&key, 0).unwrap_or_default();
    let (family, ip): (u8, Vec<u8>) = match a.ip() {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    let mut v = vec![0, family];
    v.extend_from_slice(&port.to_be_bytes());
    v.extend(ip.iter().zip(key.iter()).map(|(b, k)| b ^ k));
    v
}

fn read_text(typ: u16, v: &[u8], max: usize) -> Result<String, ParseError> {
    if v.len() > max {
        return Err(ParseError::Text { typ });
    }
    match core::str::from_utf8(v) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(ParseError::Text { typ }),
    }
}

/// Whether a value of `len` bytes is allowed for `typ`, as far as the
/// integrity attributes go: MESSAGE-INTEGRITY is an HMAC-SHA1, 20 bytes,
/// and MESSAGE-INTEGRITY-SHA256 is 16 to 32 bytes, a multiple of 4.
fn integrity_length_ok(typ: u16, len: usize) -> bool {
    match typ {
        attr::MESSAGE_INTEGRITY => len == 20,
        attr::MESSAGE_INTEGRITY_SHA256 => (16..=32).contains(&len) && len.is_multiple_of(4),
        _ => true,
    }
}

/// Whether an attribute of type `typ` is read, given what came before it.
/// RFC 8489, sections 14.5 and 14.6: after MESSAGE-INTEGRITY only
/// MESSAGE-INTEGRITY-SHA256 (and FINGERPRINT) are read, and after any
/// MESSAGE-INTEGRITY-SHA256 only FINGERPRINT is. `state` tracks the last
/// of the two that was read.
fn integrity_keeps(state: &mut Integrity, typ: u16) -> bool {
    let keep = match *state {
        Integrity::None => true,
        Integrity::Sha1 => typ == attr::MESSAGE_INTEGRITY_SHA256,
        Integrity::Sha256 => false,
    };
    if keep {
        match typ {
            attr::MESSAGE_INTEGRITY => *state = Integrity::Sha1,
            attr::MESSAGE_INTEGRITY_SHA256 => *state = Integrity::Sha256,
            _ => {}
        }
    }
    keep
}

/// Which integrity attribute a message has shown so far.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Integrity {
    None,
    Sha1,
    Sha256,
}

fn padded(len: usize) -> usize {
    len.div_ceil(4) * 4
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(*b.get(i..)?.first_chunk::<2>()?))
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*b.get(i..)?.first_chunk::<4>()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::test_support::Lcg;
    use crate::stdlib::codec::{Fail, Stream, Wire, contract, finish, pump, test_support};

    const TID: [u8; 12] = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

    // Test vectors from RFC 5769, section 2.

    const SAMPLE_REQUEST: [u8; 108] = [
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa,
        0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20,
        0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00,
        0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a,
        0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf,
        0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28,
        0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
    ];

    const SAMPLE_IPV4_RESPONSE: [u8; 80] = [
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa,
        0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f,
        0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00,
        0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53,
        0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
    ];

    const SAMPLE_IPV6_RESPONSE: [u8; 92] = [
        0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa,
        0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f,
        0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1,
        0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e,
        0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41, 0x80,
        0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c,
    ];

    fn samples() -> [&'static [u8]; 3] {
        [&SAMPLE_REQUEST, &SAMPLE_IPV4_RESPONSE, &SAMPLE_IPV6_RESPONSE]
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn message_types() {
        assert_eq!(message_type(method::BINDING, Class::Request), 0x0001);
        assert_eq!(message_type(method::BINDING, Class::Indication), 0x0011);
        assert_eq!(message_type(method::BINDING, Class::SuccessResponse), 0x0101);
        assert_eq!(message_type(method::BINDING, Class::ErrorResponse), 0x0111);
        assert_eq!(message_type(0xfff, Class::ErrorResponse), 0x3fff);
        for t in 0..0x4000u16 {
            let (m, c) = split_type(t);
            assert_eq!(message_type(m, c), t);
        }
    }

    #[test]
    fn rfc5769_sample_request() {
        let m = Message::parse(&SAMPLE_REQUEST).unwrap();
        assert_eq!((m.method, m.class, m.transaction), (method::BINDING, Class::Request, TID));
        assert!(m.fingerprint);
        assert_eq!(m.software(), Some("STUN test client"));
        assert_eq!(m.get(attr::USERNAME), Some(&Attribute::Username("evtj:h6vY".into())));
        assert_eq!(m.attributes.len(), 5);
        // PRIORITY (0x0024) and MESSAGE-INTEGRITY are not read here; the
        // ICE-CONTROLLED attribute (0x8029) is optional.
        assert_eq!(m.unknown_comprehension_required(), [0x0024, attr::MESSAGE_INTEGRITY]);
        let reply = answer_binding(&m, "192.0.2.1:32853".parse().unwrap()).unwrap();
        assert_eq!(reply.class, Class::ErrorResponse);
        assert_eq!(reply.error_code(), Some((420, "Unknown Attribute")));
        assert_eq!(
            reply.get(attr::UNKNOWN_ATTRIBUTES),
            Some(&Attribute::UnknownAttributes(vec![0x0024, 0x0008]))
        );
    }

    #[test]
    fn rfc5769_sample_ipv4_response() {
        let m = Message::parse(&SAMPLE_IPV4_RESPONSE).unwrap();
        assert_eq!((m.method, m.class), (method::BINDING, Class::SuccessResponse));
        assert_eq!(m.software(), Some("test vector"));
        assert_eq!(m.xor_mapped_address(), Some("192.0.2.1:32853".parse().unwrap()));
        assert!(m.fingerprint);
    }

    #[test]
    fn rfc5769_sample_ipv6_response() {
        let m = Message::parse(&SAMPLE_IPV6_RESPONSE).unwrap();
        assert_eq!(
            m.xor_mapped_address(),
            Some("[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap())
        );
        assert!(m.fingerprint);
    }

    #[test]
    fn samples_round_trip() {
        for s in samples() {
            let m = Message::parse(s).unwrap();
            let bytes = m.to_bytes().unwrap();
            // Padding is zeroed, so the bytes may differ, but not the length.
            assert_eq!(bytes.len(), s.len());
            assert_eq!(Message::parse(&bytes).unwrap(), m);
        }
        // With zero padding in the original, the bytes match exactly.
        let mut v6 = SAMPLE_IPV6_RESPONSE;
        v6[35] = 0;
        let fp = crc32(&v6[..84]) ^ FINGERPRINT_XOR;
        v6[88..].copy_from_slice(&fp.to_be_bytes());
        assert_eq!(Message::parse(&v6).unwrap().to_bytes().unwrap(), v6);
    }

    #[test]
    fn binding_success_response() {
        let mut req = Message::binding_request([1; 12]);
        req.attributes.push(Attribute::Software("client".into()));
        let source: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        let reply = answer_binding(&Message::parse(&req.to_bytes().unwrap()).unwrap(), source).unwrap();
        assert_eq!(reply.class, Class::SuccessResponse);
        assert_eq!(reply.transaction, [1; 12]);
        assert!(!reply.fingerprint);
        let back = Message::parse(&reply.to_bytes().unwrap()).unwrap();
        assert_eq!(back.xor_mapped_address(), Some(source));
        // Known bytes: binding success, length 12, family 1, port and
        // address XORed with the cookie.
        let reply = Message::binding_request([0; 12]).success_response("192.0.2.1:32853".parse().unwrap());
        assert_eq!(
            reply.to_bytes().unwrap()[..],
            [
                0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00,
                0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43
            ]
        );
    }

    #[test]
    fn answers_to_other_messages() {
        let src: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let ind = Message::new(method::BINDING, Class::Indication, [0; 12]);
        assert_eq!(answer_binding(&ind, src), None);
        let resp = Message::new(method::BINDING, Class::SuccessResponse, [0; 12]);
        assert_eq!(answer_binding(&resp, src), None);
        let mut unknown = Message::binding_request([5; 12]);
        unknown.attributes.push(Attribute::Other { typ: 0x7fff, value: vec![] });
        let reply = answer_binding(&unknown, src).unwrap();
        assert_eq!((reply.method, reply.transaction), (method::BINDING, [5; 12]));
        assert_eq!(reply.error_code(), Some((420, "Unknown Attribute")));
        let reply = Message::binding_request([0; 12]).error_response(code::BAD_REQUEST);
        assert_eq!(reply.error_code(), Some((400, "Bad Request")));
    }

    #[test]
    fn mapped_address_and_error_code() {
        let mut m = Message::new(method::BINDING, Class::ErrorResponse, [9; 12]);
        m.attributes.push(Attribute::MappedAddress("1.2.3.4:5".parse().unwrap()));
        m.attributes.push(Attribute::ErrorCode { code: 438, reason: "Stale Nonce".into() });
        m.attributes.push(Attribute::AlternateServer("[::1]:3478".parse().unwrap()));
        m.attributes.push(Attribute::Realm("example.org".into()));
        m.attributes.push(Attribute::Nonce("abc".into()));
        let bytes = m.to_bytes().unwrap();
        // MAPPED-ADDRESS is in the clear.
        assert_eq!(bytes[20..32], [0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x05, 1, 2, 3, 4]);
        // ERROR-CODE: class 4, number 38.
        assert_eq!(bytes[32..40], [0x00, 0x09, 0x00, 0x0f, 0, 0, 4, 38]);
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.mapped_address(), Some("1.2.3.4:5".parse().unwrap()));
        assert_eq!(back.error_code(), Some((438, "Stale Nonce")));
    }

    #[test]
    fn header_errors() {
        let good = Message::binding_request([0; 12]).to_bytes().unwrap();
        assert_eq!(Message::parse(&[]), Err(ParseError::Truncated));
        let mut b = good.clone();
        b[0] = 0x40;
        assert_eq!(Message::parse(&b), Err(ParseError::TopBits(0x40)));
        assert_eq!(Message::parse(&[0x80]), Err(ParseError::TopBits(0x80)));
        let mut b = good.clone();
        b[3] = 2;
        assert_eq!(Message::parse(&b), Err(ParseError::Length(2)));
        let mut b = good.clone();
        b[4] = 0;
        assert_eq!(Message::parse(&b), Err(ParseError::MagicCookie(0x0012_a442)));
        let mut b = good.clone();
        b.push(0);
        assert_eq!(Message::parse(&b), Err(ParseError::TrailingBytes(1)));
        assert!(ParseError::Length(2).is_framing());
        assert!(!ParseError::Truncated.is_framing());
        assert!(is_stun(&good));
        assert!(!is_stun(&good[..7]));
        assert!(!is_stun(&b"GET / HTTP/1.1"[..]));
    }

    /// A message with the header for `body` and that body.
    fn with_body(body: &[u8]) -> Vec<u8> {
        let mut b = vec![0x00, 0x01];
        b.extend_from_slice(&(body.len() as u16).to_be_bytes());
        b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        b.extend_from_slice(&[0; 12]);
        b.extend_from_slice(body);
        b
    }

    #[test]
    fn attribute_errors() {
        let p = |body: &[u8]| Message::parse(&with_body(body));
        // A value running past the end.
        assert_eq!(
            p(&[0x80, 0x22, 0x00, 0x08, 0, 0, 0, 0]),
            Err(ParseError::AttributeTruncated { typ: 0x8022 })
        );
        // Address: too short, wrong length, bad family.
        assert_eq!(p(&[0, 1, 0, 0]), Err(ParseError::AttributeValue { typ: 1, len: 0 }));
        assert_eq!(p(&[0, 1, 0, 4, 0, 1, 0, 0]), Err(ParseError::AttributeValue { typ: 1, len: 4 }));
        assert_eq!(
            p(&[0, 1, 0, 8, 0, 2, 0, 0, 1, 2, 3, 4]),
            Err(ParseError::AttributeValue { typ: 1, len: 8 })
        );
        assert_eq!(
            Attribute::parse(0x20, &[0, 3, 0, 0, 1, 2, 3, 4], &[0; 12]),
            Err(ParseError::AddressFamily(3))
        );
        // Error code: too short, class 7, number 100.
        assert_eq!(p(&[0, 9, 0, 0]), Err(ParseError::AttributeValue { typ: 9, len: 0 }));
        assert_eq!(p(&[0, 9, 0, 4, 0, 0, 7, 0]), Err(ParseError::ErrorCode { class: 7, number: 0 }));
        assert_eq!(p(&[0, 9, 0, 4, 0, 0, 4, 100]), Err(ParseError::ErrorCode { class: 4, number: 100 }));
        // Bad UTF-8, and text that is too long.
        assert_eq!(p(&[0x80, 0x22, 0, 1, 0xff, 0, 0, 0]), Err(ParseError::Text { typ: 0x8022 }));
        let mut long = vec![0x80, 0x22, 0x02, 0xfc];
        long.resize(4 + 764, b'a');
        assert_eq!(p(&long), Err(ParseError::Text { typ: 0x8022 }));
        // An odd unknown-attribute list.
        assert_eq!(p(&[0, 0x0a, 0, 3, 0, 1, 0, 0]), Err(ParseError::AttributeValue { typ: 0x0a, len: 3 }));
        // FINGERPRINT: not last, wrong length, wrong value.
        assert_eq!(p(&[0x80, 0x28, 0, 4, 0, 0, 0, 0, 0x80, 0x22, 0, 0]), Err(ParseError::FingerprintNotLast));
        assert_eq!(p(&[0x80, 0x28, 0, 0]), Err(ParseError::AttributeValue { typ: 0x8028, len: 0 }));
        let mut b = SAMPLE_IPV4_RESPONSE;
        b[79] ^= 1;
        assert!(matches!(Message::parse(&b), Err(ParseError::Fingerprint { found: 0xc07d_4c97, .. })));
        // A changed byte before the fingerprint is caught too.
        let mut b = SAMPLE_IPV4_RESPONSE;
        b[24] = b'T';
        assert!(matches!(Message::parse(&b), Err(ParseError::Fingerprint { .. })));
        // Too many attributes.
        let many: Vec<u8> = std::iter::repeat_n([0x80u8, 0x99, 0, 0], MAX_ATTRIBUTES + 1).flatten().collect();
        assert_eq!(p(&many), Err(ParseError::TooManyAttributes));
        assert!(p(&many[4..]).is_ok());
        // Each error has words.
        assert!(!ParseError::Fingerprint { expected: 1, found: 2 }.to_string().is_empty());
    }

    #[test]
    fn every_prefix_is_truncated() {
        for s in samples() {
            for n in 0..s.len() {
                assert_eq!(Message::parse(&s[..n]), Err(ParseError::Truncated), "{n} bytes");
                let mut d = Stream::new(Frames);
                put(&mut d, &s[..n]);
                assert_eq!(d.next().map(|r| r.map(|frame| Message::parse(&frame))), None);
            }
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let mut stream = Vec::new();
        for s in samples() {
            stream.extend_from_slice(s);
        }
        // A message with a bad attribute in the middle is skipped.
        stream.extend_from_slice(&with_body(&[0, 1, 0, 0]));
        stream.extend_from_slice(&SAMPLE_IPV4_RESPONSE);
        let mut d = Stream::new(Frames);
        let mut got = Vec::new();
        for byte in codec::test_support::chunks(&stream, &[1]) {
            put(&mut d, byte);
            while let Some(m) = d.next().map(|r| r.map(|frame| Message::parse(&frame))) {
                got.push(m.unwrap().map(|m| m.class));
            }
        }
        use Class::*;
        let bad = Err(ParseError::AttributeValue { typ: 1, len: 0 });
        assert_eq!(got, [Ok(Request), Ok(SuccessResponse), Ok(SuccessResponse), bad, Ok(SuccessResponse)]);
        assert_eq!(d.buffered(), 0);
        assert!(d.failed().is_none());
        // A broken stream stays broken. The error is returned once, and
        // the decoder drops what it is fed after it.
        put(&mut d, &[0x00, 0x01, 0x00, 0x00, 1, 2, 3, 4]);
        assert_eq!(
            d.next().map(|r| r.map(|frame| Message::parse(&frame))),
            Some(Err(codec::Fail::Protocol(ParseError::MagicCookie(0x0102_0304))))
        );
        put(&mut d, &SAMPLE_REQUEST);
        assert_eq!(d.next().map(|r| r.map(|frame| Message::parse(&frame))), None);
        assert!(d.failed().is_some());
        assert_eq!(d.failed(), Some(&codec::Fail::Protocol(ParseError::MagicCookie(0x0102_0304))));
    }

    #[test]
    fn writers_refuse_invalid_fields() {
        let mut message = Message::binding_request([3; 12]);
        message.method = 0xffff;
        assert_write_error(&message, WriteError::Method(0xffff));
        message.method = 1;
        for attribute in [
            Attribute::Software("é".repeat(500)),
            Attribute::Username("x".repeat(1000)),
            Attribute::ErrorCode { code: 99, reason: String::new() },
            Attribute::ErrorCode { code: 1000, reason: String::new() },
            Attribute::Other { typ: attr::FINGERPRINT, value: vec![0; 4] },
            Attribute::Other { typ: attr::SOFTWARE, value: vec![0xff] },
            Attribute::UnknownAttributes(vec![0x1234; 40000]),
            Attribute::Other { typ: 0x8099, value: vec![1; 70000] },
        ] {
            let typ = attribute.typ();
            message.attributes = vec![attribute];
            assert_write_error(&message, WriteError::Attribute { typ });
        }
        message.fingerprint = true;
        message.attributes = vec![Attribute::Other { typ: 0x8099, value: vec![] }; MAX_ATTRIBUTES + 10];
        assert_write_error(&message, WriteError::TooManyAttributes);
    }

    // RFC 8489, section 14.3: a reader must take a USERNAME of up to 763
    // bytes, though a sender keeps it under 509.
    #[test]
    fn long_username_reads() {
        let mut body = vec![0x00, 0x06, 0x02, 0x58];
        body.resize(4 + 600, b'u');
        let m = Message::parse(&with_body(&body)).unwrap();
        assert_eq!(m.get(attr::USERNAME), Some(&Attribute::Username("u".repeat(600))));
        let mut body = vec![0x00, 0x06, 0x02, 0xfb];
        body.resize(4 + 763, b'u');
        body.push(0);
        assert!(Message::parse(&with_body(&body)).is_ok());
    }

    #[test]
    fn writer_preserves_parser_text_limits() {
        let mut message = Message::binding_request([0; 12]);
        message.attributes = vec![
            Attribute::Software("é".repeat(200)),
            Attribute::Realm("r".repeat(300)),
            Attribute::Nonce("n".repeat(128)),
            Attribute::ErrorCode { code: 400, reason: "w".repeat(200) },
            Attribute::Username("x".repeat(MAX_TEXT)),
        ];
        contract::check_wire_value(&message);
        assert_eq!(Message::parse(&message.to_bytes().unwrap()), Ok(message));
    }

    // Section 6.3: a message whose method is not supported is silently
    // discarded, before unknown attributes are looked at.
    #[test]
    fn unsupported_method_is_discarded() {
        let src: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let mut other = Message::new(0x003, Class::Request, [0; 12]);
        assert_eq!(answer_binding(&other, src), None);
        other.attributes.push(Attribute::Other { typ: 0x0024, value: vec![0; 4] });
        assert_eq!(answer_binding(&other, src), None);
    }

    // Sections 6.3.3 and 14.1: an address family that is not supported is
    // ignored, not an error for the whole message.
    #[test]
    fn unknown_address_family_is_ignored() {
        let m = Message::parse(&with_body(&[
            0, 0x20, 0, 8, 0, 3, 0, 0, 1, 2, 3, 4, 0x80, 0x22, 0, 1, b'a', 0, 0, 0,
        ]))
        .unwrap();
        assert_eq!(m.attributes, [Attribute::Software("a".into())]);
        let m = Message::parse(&with_body(&[0, 1, 0, 4, 0, 9, 0, 0])).unwrap();
        assert!(m.attributes.is_empty());
        assert_eq!(Attribute::parse(1, &[0, 9, 0, 0], &[0; 12]), Err(ParseError::AddressFamily(9)));
    }

    // Section 9: attributes after MESSAGE-INTEGRITY are ignored, except
    // MESSAGE-INTEGRITY-SHA256 and FINGERPRINT; after a
    // MESSAGE-INTEGRITY-SHA256 with no MESSAGE-INTEGRITY, all but
    // FINGERPRINT are.
    #[test]
    fn attributes_after_integrity_are_ignored() {
        let mi = |b: &mut Vec<u8>| {
            b.extend_from_slice(&[0, 8, 0, 20]);
            b.extend_from_slice(&[0xaa; 20]);
        };
        let sha = |b: &mut Vec<u8>| {
            b.extend_from_slice(&[0, 0x1c, 0, 32]);
            b.extend_from_slice(&[0xbb; 32]);
        };
        // MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256, then an unknown
        // comprehension-required type and a bad MAPPED-ADDRESS.
        let mut body = Vec::new();
        mi(&mut body);
        sha(&mut body);
        body.extend_from_slice(&[0, 0x24, 0, 4, 1, 2, 3, 4, 0, 1, 0, 0]);
        let m = Message::parse(&with_body(&body)).unwrap();
        assert_eq!(m.attributes.iter().map(Attribute::typ).collect::<Vec<_>>(), [0x0008, 0x001c]);
        assert_eq!(m.unknown_comprehension_required(), [0x0008, 0x001c]);
        // MESSAGE-INTEGRITY-SHA256 alone: what follows is ignored.
        let mut body = Vec::new();
        sha(&mut body);
        body.extend_from_slice(&[0, 0x24, 0, 4, 1, 2, 3, 4]);
        let m = Message::parse(&with_body(&body)).unwrap();
        assert_eq!(m.attributes.len(), 1);
        // A writer refuses attributes the reader would ignore.
        let mut w = Message::binding_request([0; 12]);
        w.attributes.push(Attribute::Other { typ: 0x0008, value: vec![0; 20] });
        w.attributes.push(Attribute::Software("late".into()));
        w.fingerprint = true;
        assert_eq!(w.to_bytes(), Err(WriteError::Attribute { typ: attr::SOFTWARE }));
    }

    // Sections 14.5 and 14.6: MESSAGE-INTEGRITY is 20 bytes;
    // MESSAGE-INTEGRITY-SHA256 is 16 to 32 bytes, a multiple of 4.
    #[test]
    fn integrity_lengths() {
        let p = |body: &[u8]| Message::parse(&with_body(body));
        assert_eq!(p(&[0, 8, 0, 4, 0, 0, 0, 0]), Err(ParseError::AttributeValue { typ: 8, len: 4 }));
        let mut b = vec![0, 0x1c, 0, 18];
        b.resize(4 + 20, 0);
        assert_eq!(p(&b), Err(ParseError::AttributeValue { typ: 0x1c, len: 18 }));
        let mut b = vec![0, 0x1c, 0, 16];
        b.resize(4 + 16, 0);
        assert!(p(&b).is_ok());
        // A writer refuses an integrity value of the wrong length.
        let mut w = Message::binding_request([0; 12]);
        w.attributes.push(Attribute::Other { typ: 0x0008, value: vec![0; 4] });
        w.attributes.push(Attribute::Other { typ: 0x001c, value: vec![0; 12] });
        assert_eq!(w.to_bytes(), Err(WriteError::Attribute { typ: attr::MESSAGE_INTEGRITY }));
        w.attributes.remove(0);
        assert_eq!(w.to_bytes(), Err(WriteError::Attribute { typ: attr::MESSAGE_INTEGRITY_SHA256 }));
    }

    // Section 14.6: after any MESSAGE-INTEGRITY-SHA256, only FINGERPRINT
    // is read, so a second one after MESSAGE-INTEGRITY is ignored too.
    #[test]
    fn second_sha256_is_ignored() {
        let mut body = vec![0, 8, 0, 20];
        body.extend_from_slice(&[0xaa; 20]);
        for fill in [0xbb, 0xcc] {
            body.extend_from_slice(&[0, 0x1c, 0, 16]);
            body.extend_from_slice(&[fill; 16]);
        }
        let m = Message::parse(&with_body(&body)).unwrap();
        assert_eq!(m.attributes.iter().map(Attribute::typ).collect::<Vec<_>>(), [0x0008, 0x001c]);
        assert_eq!(m.attributes[1], Attribute::Other { typ: 0x001c, value: vec![0xbb; 16] });
        // The writer refuses a second SHA256 attribute.
        let mut w = m.clone();
        w.attributes.push(Attribute::Other { typ: 0x001c, value: vec![0xcc; 16] });
        assert_eq!(w.to_bytes(), Err(WriteError::Attribute { typ: attr::MESSAGE_INTEGRITY_SHA256 }));
    }

    // A stream of many small messages fed at once is split in linear time:
    // taking one message out does not move the bytes after it.
    #[test]
    fn decoder_is_linear() {
        let one = Message::binding_request([1; 12]).to_bytes().unwrap();
        let n = 1_000_000;
        let mut stream = Vec::with_capacity(one.len() * n);
        for _ in 0..n {
            stream.extend_from_slice(&one);
        }
        let mut d = Stream::new(Frames);
        let start = std::time::Instant::now();
        let mut count = 0;
        let mut rest = &stream[..];
        while !rest.is_empty() {
            let took = d.push(rest);
            assert!(took > 0 || d.buffered() == MAX_MESSAGE);
            rest = &rest[took..];
            while let Some(m) = d.next().map(|r| r.map(|frame| Message::parse(&frame))) {
                assert!(m.is_ok());
                count += 1;
            }
        }
        assert_eq!(count, n);
        assert_eq!(d.buffered(), 0);
        assert!(start.elapsed() < std::time::Duration::from_secs(10), "{:?}", start.elapsed());
        // Interleaved feeds keep working once part of the buffer is read.
        put(&mut d, &one[..5]);
        assert_eq!(d.next().map(|r| r.map(|frame| Message::parse(&frame))), None);
        assert_eq!(d.buffered(), 5);
        put(&mut d, &one[5..]);
        put(&mut d, &one);
        assert!(d.next().map(|r| r.map(|frame| Message::parse(&frame))).unwrap().is_ok());
        assert_eq!(d.buffered(), one.len());
        put(&mut d, &one[..3]);
        assert!(d.next().map(|r| r.map(|frame| Message::parse(&frame))).unwrap().is_ok());
        assert_eq!(d.next().map(|r| r.map(|frame| Message::parse(&frame))), None);
        assert_eq!(d.buffered(), 3);
        assert_eq!(d.into_parts().0.len(), 3);
    }

    #[test]
    fn stream_is_bounded() {
        let one = Message::binding_request([1; 12]).to_bytes().unwrap();
        let bytes = one.repeat(100_000);
        let mut stream = Stream::new(Frames);
        let took = stream.push(&bytes);
        assert_eq!(took, MAX_MESSAGE);
        assert_eq!(stream.push(&bytes[took..]), 0);
        let mut count = 0;
        codec::pump(&mut stream, &bytes[took..], |_| count += 1).unwrap();
        codec::finish(&mut stream, |_| count += 1).unwrap();
        assert_eq!(count, 100_000);
        assert_eq!(stream.buffered(), 0);
    }

    #[test]
    fn framing_error_ends_the_drain_loop() {
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&[0xc0]), 1);
        let error = codec::Fail::Protocol(ParseError::TopBits(0xc0));
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
    }

    // Attribute::parse refuses a value no message can hold before copying
    // it.
    #[test]
    fn attribute_parse_refuses_huge_values() {
        let big = vec![0u8; MAX_VALUE + 2];
        for typ in [0x8099, attr::UNKNOWN_ATTRIBUTES, attr::USERNAME] {
            assert_eq!(
                Attribute::parse(typ, &big, &[0; 12]),
                Err(ParseError::AttributeValue { typ, len: MAX_VALUE + 2 })
            );
        }
        assert!(Attribute::parse(0x8099, &big[..MAX_VALUE], &[0; 12]).is_ok());
    }

    // RFC 8489, section 14.5: MESSAGE-INTEGRITY covers the bytes as sent,
    // padding included. The RFC 5769 request pads USERNAME with spaces,
    // which a writer would zero, so the decoder hands out each frame's
    // bytes as they came.
    #[test]
    fn decoder_frames_keep_the_bytes_sent() {
        let mut stream = Vec::new();
        for s in samples() {
            stream.extend_from_slice(s);
        }
        let mut d = Stream::new(Frames);
        put(&mut d, &stream);
        for s in samples() {
            let frame = d.next().unwrap().unwrap();
            assert_eq!(frame, s);
            assert!(Message::parse(&frame).is_ok());
        }
        assert_eq!(d.next(), None);
        assert_ne!(Message::parse(&SAMPLE_REQUEST).unwrap().to_bytes().unwrap(), SAMPLE_REQUEST);
    }

    #[test]
    fn accessors() {
        let mut m = Message::new(method::BINDING, Class::ErrorResponse, [2; 12]);
        assert_eq!((m.username(), m.realm(), m.nonce()), (None, None, None));
        assert_eq!((m.alternate_server(), m.unknown_attributes()), (None, None));
        m.attributes.push(Attribute::Username("alice".into()));
        m.attributes.push(Attribute::Realm("example.org".into()));
        m.attributes.push(Attribute::Nonce("n0".into()));
        m.attributes.push(Attribute::AlternateServer("192.0.2.9:3478".parse().unwrap()));
        m.attributes.push(Attribute::UnknownAttributes(vec![0x0024, 0x7000]));
        let m = Message::parse(&m.to_bytes().unwrap()).unwrap();
        assert_eq!(m.username(), Some("alice"));
        assert_eq!(m.realm(), Some("example.org"));
        assert_eq!(m.nonce(), Some("n0"));
        assert_eq!(m.alternate_server(), Some("192.0.2.9:3478".parse().unwrap()));
        assert_eq!(m.unknown_attributes(), Some(&[0x0024, 0x7000][..]));
    }

    #[test]
    fn codec_stack_end_to_end() {
        let request = Message::binding_request([8; 12]);
        let bad_attribute = with_body(&[0, 1, 0, 0]);
        let attribute_error = ParseError::AttributeValue { typ: attr::MAPPED_ADDRESS, len: 0 };
        let header_error = ParseError::TopBits(0xc0);
        let mut bytes = SAMPLE_REQUEST.to_vec();
        bytes.extend_from_slice(&bad_attribute);
        request.write(&mut bytes).unwrap();
        let consumed = bytes.len();
        bytes.push(0xc0);
        request.write(&mut bytes).unwrap();

        let expected = vec![
            Ok(Message::parse(&SAMPLE_REQUEST)),
            Ok(Err(attribute_error)),
            Ok(Ok(request.clone())),
            Err(Fail::Protocol(header_error)),
        ];
        let source = "192.0.2.1:32853".parse().unwrap();
        for pattern in [&[][..], &[1], &[3, 1, 17]] {
            let mut stream = Stream::new(Frames::new().map(|frame| Message::parse(&frame)));
            let mut results = Vec::new();
            let mut replies = Vec::new();
            let mut expected_replies = Vec::new();
            let mut at = 0;
            for chunk in test_support::chunks(&bytes, pattern) {
                assert_eq!(stream.push(chunk), chunk.len());
                while let Some(result) = stream.with_next(|item, raw, span| {
                    let end = at + raw.len();
                    assert_eq!(raw, bytes.get(at..end).unwrap());
                    assert_eq!(span, at as u64..end as u64);
                    at = end;
                    if let Ok(message) = &item {
                        let reply = answer_binding(message, source).unwrap();
                        Wire::write(&reply, &mut replies).unwrap();
                        expected_replies.push(Ok(reply));
                    }
                    item
                }) {
                    results.push(result);
                }
                assert!(stream.buffered() <= MAX_MESSAGE);
            }
            assert_eq!(results, expected);
            assert_eq!(at, consumed);
            assert_eq!(stream.offset(), consumed as u64);
            assert_eq!(stream.failed(), Some(&Fail::Protocol(header_error)));
            assert!(stream.is_done());
            stream.end();
            assert_eq!(stream.next(), None);
            assert_eq!(stream.push(&request.to_bytes().unwrap()), HEADER_LEN);
            assert_eq!(stream.next(), None);

            let mut response_stream = Stream::new(Frames::new().map(|frame| Message::parse(&frame)));
            let mut responses = Vec::new();
            for byte in &replies {
                assert_eq!(
                    pump(&mut response_stream, core::slice::from_ref(byte), |item| responses.push(item)),
                    Ok(1)
                );
            }
            finish(&mut response_stream, |item| responses.push(item)).unwrap();
            assert_eq!(responses, expected_replies);
            assert!(response_stream.is_done());
            assert_eq!(response_stream.failed(), None);
        }

        // The existing borrowed API still reports the same flattened results.
    }

    #[test]
    fn codec_eof_and_early_header_errors() {
        for sample in samples() {
            for cut in 0..sample.len() {
                let mut stream = Stream::new(Frames::new());
                assert_eq!(stream.push(sample.get(..cut).unwrap()), cut);
                assert_eq!(stream.next(), None);
                stream.end();
                let expected = if cut == 0 { None } else { Some(Err(Fail::Truncated { unread: cut })) };
                assert_eq!(stream.next(), expected);
                assert!(stream.is_done());
                assert_eq!(stream.next(), None);
            }
        }
        for (bytes, error) in [
            (&[0x80][..], ParseError::TopBits(0x80)),
            (&[0, 1, 0, 2][..], ParseError::Length(2)),
            (&[0, 1, 0xff, 0xfc, 1, 2, 3, 4][..], ParseError::MagicCookie(0x0102_0304)),
        ] {
            let mut stream = Stream::new(Frames::new());
            assert_eq!(stream.push(bytes), bytes.len());
            assert_eq!(stream.next(), Some(Err(Fail::Protocol(error))));
            assert_eq!(stream.failed(), Some(&Fail::Protocol(error)));
            assert_eq!(stream.next(), None);
        }
    }

    #[test]
    fn codec_contracts_and_capacity() {
        for sample in samples() {
            contract::check_decode(Frames::new, sample);
            contract::check_decode(|| Frames::new().map(|frame| Message::parse(&frame)), sample);
            contract::check_wire::<Message>(sample);
        }
        let mut message = Message::binding_request([1; 12]);
        message.attributes.push(Attribute::Other { typ: 0x8099, value: vec![0x5a; MAX_VALUE] });
        let bytes = Wire::to_bytes(&message).unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        assert_eq!(Frames::new().capacity(), MAX_MESSAGE);
        assert_eq!(Frames::new().held(), 0);
        contract::check_decode(Frames::new, &bytes);
        contract::check_decode(|| Frames::new().map(|frame| Message::parse(&frame)), &bytes);
        contract::check_wire::<Message>(&bytes);

        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&bytes), MAX_MESSAGE);
        assert_eq!(stream.push(&bytes), 0);
        assert_eq!(stream.next(), Some(Ok(bytes.clone())));
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.push(&bytes), MAX_MESSAGE);
        stream.end();
        assert_eq!(stream.next(), Some(Ok(bytes)));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), None);
    }

    #[test]
    fn strict_writer_preserves_long_text() {
        let text = format!("{}a", "é".repeat(MAX_TEXT / 2));
        assert_eq!(text.len(), MAX_TEXT);
        let mut message = Message::binding_request([4; 12]);
        message.attributes = vec![
            Attribute::Username(text.clone()),
            Attribute::Realm(text.clone()),
            Attribute::Nonce(text.clone()),
            Attribute::Software(text.clone()),
            Attribute::ErrorCode { code: 699, reason: text },
        ];
        message.fingerprint = true;
        let bytes = Wire::to_bytes(&message).unwrap();
        assert_eq!(Message::parse(&bytes), Ok(message.clone()));
        contract::check_wire::<Message>(&bytes);

        let mut appended = SAMPLE_REQUEST.to_vec();
        message.write(&mut appended).unwrap();
        assert_eq!(appended.get(..SAMPLE_REQUEST.len()).unwrap(), SAMPLE_REQUEST);
        assert_eq!(Message::parse(appended.get(SAMPLE_REQUEST.len()..).unwrap()), Ok(message));
        assert!(matches!(<Message as Wire>::parse(&appended), Err(ParseError::TrailingBytes(_))));
    }

    fn assert_write_error(message: &Message, error: WriteError) {
        let mut out = vec![0x5a, 0xa5];
        assert_eq!(message.write(&mut out), Err(error));
        assert_eq!(out, [0x5a, 0xa5]);
        contract::check_wire_value(message);
        assert_eq!(message.to_bytes(), Err(error));
    }

    #[test]
    fn strict_writer_refuses_changed_attributes_transactionally() {
        let long = "x".repeat(MAX_TEXT + 1);
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3478, 0, 1));
        let flow = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3478, 1, 0));
        let mut attributes = vec![
            Attribute::Username(long.clone()),
            Attribute::Realm(long.clone()),
            Attribute::Nonce(long.clone()),
            Attribute::Software(long.clone()),
            Attribute::ErrorCode { code: 400, reason: long },
            Attribute::ErrorCode { code: 299, reason: String::new() },
            Attribute::ErrorCode { code: 700, reason: String::new() },
            Attribute::UnknownAttributes(vec![1; MAX_VALUE / 2 + 1]),
            Attribute::Other { typ: 0x8099, value: vec![0; MAX_VALUE + 1] },
            Attribute::Other { typ: attr::MESSAGE_INTEGRITY, value: vec![0; 19] },
            Attribute::Other { typ: attr::MESSAGE_INTEGRITY_SHA256, value: vec![0; 18] },
            Attribute::MappedAddress(scoped),
            Attribute::XorMappedAddress(flow),
            Attribute::AlternateServer(scoped),
        ];
        for typ in [
            attr::MAPPED_ADDRESS,
            attr::XOR_MAPPED_ADDRESS,
            attr::ALTERNATE_SERVER,
            attr::USERNAME,
            attr::REALM,
            attr::NONCE,
            attr::SOFTWARE,
            attr::ERROR_CODE,
            attr::UNKNOWN_ATTRIBUTES,
            attr::FINGERPRINT,
        ] {
            attributes.push(Attribute::Other { typ, value: vec![] });
        }
        for attribute in attributes {
            let error = WriteError::Attribute { typ: attribute.typ() };
            let mut message = Message::binding_request([0; 12]);
            message.attributes = vec![Attribute::Software("valid prefix".into()), attribute];
            message.fingerprint = true;
            assert_write_error(&message, error);
        }
        let mut message = Message::binding_request([0; 12]);
        message.method = 0x1001;
        assert_write_error(&message, WriteError::Method(0x1001));
    }

    #[test]
    fn strict_writer_checks_integrity_order() {
        let sha1 = Attribute::Other { typ: attr::MESSAGE_INTEGRITY, value: vec![1; 20] };
        let sha256 = Attribute::Other { typ: attr::MESSAGE_INTEGRITY_SHA256, value: vec![2; 16] };
        let mut message = Message::binding_request([0; 12]);
        message.fingerprint = true;
        message.attributes = vec![Attribute::Software("sdk".into()), sha1.clone(), sha256.clone()];
        let bytes = Wire::to_bytes(&message).unwrap();
        contract::check_wire::<Message>(&bytes);
        for (first, second) in [
            (sha1.clone(), Attribute::Software("ignored".into())),
            (sha1.clone(), sha1.clone()),
            (sha256.clone(), sha1),
            (sha256.clone(), sha256),
        ] {
            let error = WriteError::Attribute { typ: second.typ() };
            message.attributes = vec![first, second];
            assert_write_error(&message, error);
        }
    }

    #[test]
    fn strict_writer_checks_body_and_attribute_limits() {
        let mut message = Message::binding_request([0; 12]);
        message.attributes = vec![Attribute::Other { typ: 0x8099, value: vec![] }; MAX_ATTRIBUTES];
        contract::check_wire::<Message>(&Wire::to_bytes(&message).unwrap());
        message.fingerprint = true;
        assert_write_error(&message, WriteError::TooManyAttributes);
        message.attributes.pop();
        contract::check_wire::<Message>(&Wire::to_bytes(&message).unwrap());
        message.fingerprint = false;
        message.attributes = vec![Attribute::Other { typ: 0x8099, value: vec![0; MAX_VALUE] }];
        assert_eq!(Wire::to_bytes(&message).unwrap().len(), MAX_MESSAGE);
        message.fingerprint = true;
        assert_write_error(&message, WriteError::BodyTooLong);
        message.attributes = vec![Attribute::Other { typ: 0x8099, value: vec![0; MAX_VALUE - 8] }];
        let bytes = Wire::to_bytes(&message).unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        contract::check_wire::<Message>(&bytes);
        message.fingerprint = false;
        message.attributes.push(Attribute::Other { typ: 0x8099, value: vec![0; 5] });
        assert_write_error(&message, WriteError::BodyTooLong);
    }

    fn check_round_trip(bytes: &[u8]) {
        contract::check_wire::<Message>(bytes);
        if let Ok(message) = Message::parse(bytes) {
            assert_eq!(Message::parse(&message.to_bytes().unwrap()), Ok(message.clone()));
            if let Some(reply) = answer_binding(&message, "10.0.0.1:9".parse().unwrap()) {
                contract::check_wire_value(&reply);
            }
        }
    }

    fn put(stream: &mut Stream<Frames>, bytes: &[u8]) {
        assert_eq!(stream.push(bytes), bytes.len());
    }

    fn check_decoder(bytes: &[u8]) -> usize {
        contract::check_decode(|| Frames.map(|frame| Message::parse(&frame)), bytes);
        let mut stream = Stream::new(Frames);
        let mut count = 0;
        let _ = codec::pump(&mut stream, bytes, |frame| {
            if let Ok(message) = Message::parse(&frame) {
                contract::check_wire_value(&message);
                count += 1;
            }
        });
        count
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5354_554e);
        let mut parsed = 0;
        let mut stream = Vec::new();
        let mut streamed = 0;
        for i in 0..4000 {
            let len = (rng.next() % 200) as usize;
            let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            match i % 4 {
                // Random bytes.
                0 => {}
                // A valid header over random attributes.
                1 | 2 => {
                    let body = (len / 4) * 4;
                    b.truncate(body);
                    let mut msg = with_body(&b);
                    msg[1] = rng.next() as u8;
                    // Make most attribute lengths fit, and types known.
                    let mut at = HEADER_LEN;
                    while at + 4 <= msg.len() {
                        let room = msg.len() - at - 4;
                        let len = (rng.next() as usize % (room + 1)).min(24);
                        let known = [
                            0x0001, 0x0020, 0x0009, 0x000a, 0x8022, 0x0006, 0x8023, 0x8099, 0x0024, 0x0008,
                            0x001c,
                        ];
                        let typ: u16 = known[rng.next() as usize % known.len()];
                        msg[at..at + 2].copy_from_slice(&typ.to_be_bytes());
                        msg[at + 2..at + 4].copy_from_slice(&(len as u16).to_be_bytes());
                        at += 4 + padded(len);
                    }
                    if i % 4 == 2 && msg.len() + 8 <= MAX_MESSAGE {
                        let n = msg.len() - HEADER_LEN + 8;
                        msg[2..4].copy_from_slice(&(n as u16).to_be_bytes());
                        let fp = crc32(&msg) ^ FINGERPRINT_XOR;
                        msg.extend_from_slice(&[0x80, 0x28, 0, 4]);
                        msg.extend_from_slice(&fp.to_be_bytes());
                    }
                    b = msg;
                }
                // A sample with a few bytes changed.
                _ => {
                    let s = samples()[rng.next() as usize % 3];
                    b = s.to_vec();
                    for _ in 0..1 + rng.next() % 3 {
                        let at = rng.next() as usize % b.len();
                        b[at] = rng.next() as u8;
                    }
                }
            }
            if Message::parse(&b).is_ok() {
                parsed += 1;
            }
            check_round_trip(&b);
            // The decoder gives the same messages fed whole, in pieces, or
            // a byte at a time, and over a stream of several messages.
            check_decoder(&b);
            // Random bytes would break most streams at once, so streams
            // are built from the other inputs.
            if i % 4 != 0 {
                stream.extend_from_slice(&b);
            }
            if i % 16 == 15 {
                streamed += check_decoder(&stream);
                stream.clear();
            }
        }
        // The loop reaches the attribute readers, not only header errors.
        assert!(parsed > 100, "{parsed} parsed");
        assert!(streamed > 200, "{streamed} messages from streams");
    }
}
