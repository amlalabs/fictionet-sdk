//! IKEv2: reading and writing message structure, with no I/O and no
//! cryptography.
//!
//! IKEv2 is how two IPsec peers agree on keys and on what traffic to
//! protect. Peers send it over UDP, on port 500, or on port 4500 once
//! they have found a NAT between them. Each exchange is a request and a
//! response. The first, IKE_SA_INIT, trades proposals, Diffie-Hellman
//! values and nonces in the clear. Everything after it travels inside an
//! encrypted payload. This module follows RFC 7296.
//!
//! A message is a 28-byte header, then a chain of payloads. The header
//! holds the two peers' SPIs, the exchange type, flags and a message ID.
//! Each payload starts with a 4-byte generic header: the type of the
//! payload after it, a critical bit, and its length. This module reads
//! the bodies of the security association (SA), key exchange (KE), nonce,
//! notify, delete, vendor ID, traffic selector (TSi and TSr) and
//! identification (IDi and IDr) payloads. The encrypted payload (SK) and
//! the encrypted fragment (SKF, RFC 7383) are kept as bytes, and so is
//! any other payload. On port 4500 an IKE message follows four zero bytes,
//! the non-ESP marker, so a receiver can tell it from ESP ([`NatT`]).
//!
//! Nothing here reads a socket or does any cryptography. A world that
//! plays a VPN gateway passes each UDP payload it gets to
//! [`Message::parse`] and sends the bytes of [`Message::write`] back.
//! Choosing a proposal, making keys, opening an SK payload and checking
//! AUTH are up to world code. After it decrypts an SK payload, it can read
//! the inner payloads with [`parse_payloads`].
//!
//! Every reader checks lengths, counts and limits, because the agent can
//! send any bytes it likes. Bytes that break the layout give an [`Error`].
//! A real gateway drops such a request, or answers with an INVALID_SYNTAX
//! notify once the SA is up.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::ike::{
//!     Body, KeyExchange, Message, Notify, Payload, Proposal, Transform, exchange, flags, notify, payload, protocol,
//!     transform,
//! };
//!
//! // An IKE_SA_INIT request offering Diffie-Hellman group 14.
//! let request = Message {
//!     initiator_spi: 0x0102_0304_0506_0708,
//!     responder_spi: 0,
//!     minor_version: 0,
//!     exchange: exchange::IKE_SA_INIT,
//!     flags: flags::INITIATOR,
//!     message_id: 0,
//!     payloads: vec![
//!         Payload::new(Body::SecurityAssociation(vec![Proposal {
//!             number: 1,
//!             protocol: protocol::IKE,
//!             spi: vec![],
//!             transforms: vec![Transform { kind: transform::DH, id: 14, attributes: vec![] }],
//!         }])),
//!         Payload::new(Body::KeyExchange(KeyExchange { group: 14, data: vec![7; 256] })),
//!         Payload::new(Body::Nonce(vec![9; 32])),
//!     ],
//! };
//! let bytes = request.to_bytes().unwrap();
//! // The header, then SA (4 + 16 bytes), KE (4 + 4 + 256) and nonce (4 + 32).
//! assert_eq!(bytes.len(), 28 + 20 + 264 + 36);
//! assert_eq!(bytes[16], payload::SA);
//! assert_eq!(bytes[17], 0x20);
//! assert_eq!(Message::parse(&bytes), Ok(request.clone()));
//!
//! // A gateway that wants group 19 says so, with the same SPIs and
//! // message ID.
//! let wanted = 19u16.to_be_bytes().to_vec();
//! let reply = request.response(vec![Payload::new(Body::Notify(Notify {
//!     protocol: 0,
//!     spi: vec![],
//!     kind: notify::INVALID_KE_PAYLOAD,
//!     data: wanted,
//! }))]);
//! let bytes = reply.to_bytes().unwrap();
//! assert_eq!(bytes.len(), 28 + 4 + 4 + 2);
//! assert_eq!(bytes[19], flags::RESPONSE);
//! let back = Message::parse(&bytes).unwrap();
//! assert!(back.is_response());
//! assert_eq!(back.notify(notify::INVALID_KE_PAYLOAD).unwrap().data, [0, 19]);
//! ```

use fictionet::stdlib::codec::{be16, Reader, Truncated};

use fictionet::stdlib::codec::Wire;

use std::net::{Ipv4Addr, Ipv6Addr};

/// The UDP port IKE peers listen on.
pub const PORT: u16 = 500;
/// The UDP port IKE moves to when there is a NAT between the peers. IKE
/// messages on it follow the [`NON_ESP_MARKER`].
pub const NAT_T_PORT: u16 = 4500;
/// The length of the IKE header.
pub const HEADER_LEN: usize = 28;
/// The length of the generic payload header.
pub const PAYLOAD_HEADER_LEN: usize = 4;
/// The longest message this module reads or writes. It bounds memory, and
/// matches the largest length a payload header can hold. A UDP
/// datagram over IPv4 carries at most 65507 bytes, so a world that sends
/// a message this long must check that it fits.
pub const MAX_MESSAGE: usize = 65535;
/// The longest payload body a writer produces: what fits in the longest
/// message after its header and one payload header.
pub const MAX_BODY: usize = MAX_MESSAGE - HEADER_LEN - PAYLOAD_HEADER_LEN;
/// The longest payload chain this module reads or writes: what fits in
/// the longest message after its header.
pub const MAX_CHAIN: usize = MAX_MESSAGE - HEADER_LEN;
/// The most payloads one chain may hold.
pub const MAX_PAYLOADS: usize = 128;
/// The most proposals one SA payload may hold.
pub const MAX_PROPOSALS: usize = 64;
/// The most transforms one proposal may hold.
pub const MAX_TRANSFORMS: usize = 64;
/// The most attributes one transform may hold.
pub const MAX_ATTRIBUTES: usize = 16;
/// The most traffic selectors one TS payload may hold.
pub const MAX_SELECTORS: usize = 64;
/// The most SPIs one delete payload may hold.
pub const MAX_DELETE_SPIS: usize = 4096;
/// The longest SPI a proposal, notify or delete payload can carry: its
/// size field is one byte.
pub const MAX_SPI: usize = 255;
/// The major version this module reads: IKEv2.
pub const MAJOR_VERSION: u8 = 2;
/// The four zero bytes before an IKE message on port 4500. ESP packets
/// start with a nonzero SPI there instead.
pub const NON_ESP_MARKER: [u8; 4] = [0; 4];
/// The single byte a peer behind a NAT sends on port 4500 to keep the
/// NAT's mapping open (RFC 3948).
pub const NAT_KEEPALIVE: u8 = 0xff;

/// Exchange types, from the header.
pub mod exchange {
    #![allow(missing_docs)]
    pub const IKE_SA_INIT: u8 = 34;
    pub const IKE_AUTH: u8 = 35;
    pub const CREATE_CHILD_SA: u8 = 36;
    pub const INFORMATIONAL: u8 = 37;
}

/// Header flags. The other bits are reserved. The message reader ignores
/// them, and the message writer refuses them. A raw [`Header`] keeps them.
pub mod flags {
    /// Set in every message the original initiator of the IKE SA sends.
    pub const INITIATOR: u8 = 0x08;
    /// Set when the sender can speak a higher major version.
    pub const VERSION: u8 = 0x10;
    /// Set in a response, clear in a request.
    pub const RESPONSE: u8 = 0x20;
    /// All three flags.
    pub const ALL: u8 = INITIATOR | VERSION | RESPONSE;
}

/// Payload types, from the header's or a payload's next payload field.
pub mod payload {
    #![allow(missing_docs)]
    /// No next payload: the chain ends.
    pub const NONE: u8 = 0;
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const CERT: u8 = 37;
    pub const CERTREQ: u8 = 38;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const VENDOR_ID: u8 = 43;
    pub const TSI: u8 = 44;
    pub const TSR: u8 = 45;
    pub const SK: u8 = 46;
    pub const CP: u8 = 47;
    pub const EAP: u8 = 48;
    /// The encrypted fragment payload, from RFC 7383.
    pub const SKF: u8 = 53;
}

/// Protocol IDs, in proposals, notify and delete payloads.
pub mod protocol {
    #![allow(missing_docs)]
    pub const IKE: u8 = 1;
    pub const AH: u8 = 2;
    pub const ESP: u8 = 3;
}

/// Transform types and a few transform IDs.
pub mod transform {
    #![allow(missing_docs)]
    /// Encryption algorithm.
    pub const ENCR: u8 = 1;
    /// Pseudorandom function.
    pub const PRF: u8 = 2;
    /// Integrity algorithm.
    pub const INTEG: u8 = 3;
    /// Diffie-Hellman group.
    pub const DH: u8 = 4;
    /// Extended sequence numbers.
    pub const ESN: u8 = 5;
    /// The key length attribute, in bits. It is always a short attribute.
    pub const KEY_LENGTH: u16 = 14;
    pub const ENCR_3DES: u16 = 3;
    pub const ENCR_AES_CBC: u16 = 12;
    pub const ENCR_AES_CTR: u16 = 13;
    /// AES-GCM with a 16-byte tag (RFC 5282).
    pub const ENCR_AES_GCM_16: u16 = 20;
    pub const PRF_HMAC_SHA1: u16 = 2;
    /// RFC 4868.
    pub const PRF_HMAC_SHA2_256: u16 = 5;
    pub const AUTH_HMAC_SHA1_96: u16 = 2;
    /// RFC 4868.
    pub const AUTH_HMAC_SHA2_256_128: u16 = 12;
    /// The 2048-bit MODP group.
    pub const DH_MODP_2048: u16 = 14;
    /// The 256-bit random ECP group (RFC 5903).
    pub const DH_ECP_256: u16 = 19;
    /// Curve25519 (RFC 8031).
    pub const DH_CURVE25519: u16 = 31;
    pub const ESN_NO: u16 = 0;
    pub const ESN_YES: u16 = 1;
}

/// Identification types, in IDi and IDr payloads.
pub mod id {
    #![allow(missing_docs)]
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const RFC822_ADDR: u8 = 3;
    pub const IPV6_ADDR: u8 = 5;
    pub const DER_ASN1_DN: u8 = 9;
    pub const DER_ASN1_GN: u8 = 10;
    pub const KEY_ID: u8 = 11;
}

/// Traffic selector types.
pub mod ts {
    #![allow(missing_docs)]
    pub const IPV4_ADDR_RANGE: u8 = 7;
    pub const IPV6_ADDR_RANGE: u8 = 8;
}

/// Notify message types from RFC 7296. Types below 16384 report errors,
/// and the rest report status.
pub mod notify {
    #![allow(missing_docs)]
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
    pub const INVALID_IKE_SPI: u16 = 4;
    pub const INVALID_MAJOR_VERSION: u16 = 5;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const INVALID_MESSAGE_ID: u16 = 9;
    pub const INVALID_SPI: u16 = 11;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const SINGLE_PAIR_REQUIRED: u16 = 34;
    pub const NO_ADDITIONAL_SAS: u16 = 35;
    pub const INTERNAL_ADDRESS_FAILURE: u16 = 36;
    pub const FAILED_CP_REQUIRED: u16 = 37;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const INVALID_SELECTORS: u16 = 39;
    pub const TEMPORARY_FAILURE: u16 = 43;
    pub const CHILD_SA_NOT_FOUND: u16 = 44;
    pub const INITIAL_CONTACT: u16 = 16384;
    pub const SET_WINDOW_SIZE: u16 = 16385;
    pub const ADDITIONAL_TS_POSSIBLE: u16 = 16386;
    pub const IPCOMP_SUPPORTED: u16 = 16387;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const USE_TRANSPORT_MODE: u16 = 16391;
    pub const HTTP_CERT_LOOKUP_SUPPORTED: u16 = 16392;
    pub const REKEY_SA: u16 = 16393;
    pub const ESP_TFC_PADDING_NOT_SUPPORTED: u16 = 16394;
    pub const NON_FIRST_FRAGMENTS_ALSO: u16 = 16395;

    /// Whether a notify type reports an error.
    pub fn is_error(kind: u16) -> bool {
        kind < 16384
    }

    /// The name RFC 7296 gives a notify type, if it gives one.
    pub fn name(kind: u16) -> Option<&'static str> {
        Some(match kind {
            UNSUPPORTED_CRITICAL_PAYLOAD => "UNSUPPORTED_CRITICAL_PAYLOAD",
            INVALID_IKE_SPI => "INVALID_IKE_SPI",
            INVALID_MAJOR_VERSION => "INVALID_MAJOR_VERSION",
            INVALID_SYNTAX => "INVALID_SYNTAX",
            INVALID_MESSAGE_ID => "INVALID_MESSAGE_ID",
            INVALID_SPI => "INVALID_SPI",
            NO_PROPOSAL_CHOSEN => "NO_PROPOSAL_CHOSEN",
            INVALID_KE_PAYLOAD => "INVALID_KE_PAYLOAD",
            AUTHENTICATION_FAILED => "AUTHENTICATION_FAILED",
            SINGLE_PAIR_REQUIRED => "SINGLE_PAIR_REQUIRED",
            NO_ADDITIONAL_SAS => "NO_ADDITIONAL_SAS",
            INTERNAL_ADDRESS_FAILURE => "INTERNAL_ADDRESS_FAILURE",
            FAILED_CP_REQUIRED => "FAILED_CP_REQUIRED",
            TS_UNACCEPTABLE => "TS_UNACCEPTABLE",
            INVALID_SELECTORS => "INVALID_SELECTORS",
            TEMPORARY_FAILURE => "TEMPORARY_FAILURE",
            CHILD_SA_NOT_FOUND => "CHILD_SA_NOT_FOUND",
            INITIAL_CONTACT => "INITIAL_CONTACT",
            SET_WINDOW_SIZE => "SET_WINDOW_SIZE",
            ADDITIONAL_TS_POSSIBLE => "ADDITIONAL_TS_POSSIBLE",
            IPCOMP_SUPPORTED => "IPCOMP_SUPPORTED",
            NAT_DETECTION_SOURCE_IP => "NAT_DETECTION_SOURCE_IP",
            NAT_DETECTION_DESTINATION_IP => "NAT_DETECTION_DESTINATION_IP",
            COOKIE => "COOKIE",
            USE_TRANSPORT_MODE => "USE_TRANSPORT_MODE",
            HTTP_CERT_LOOKUP_SUPPORTED => "HTTP_CERT_LOOKUP_SUPPORTED",
            REKEY_SA => "REKEY_SA",
            ESP_TFC_PADDING_NOT_SUPPORTED => "ESP_TFC_PADDING_NOT_SUPPORTED",
            NON_FIRST_FRAGMENTS_ALSO => "NON_FIRST_FRAGMENTS_ALSO",
            _ => return None,
        })
    }
}

/// Why bytes are not an IKEv2 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The bytes end before the header does, or before the length the
    /// header gives.
    Short,
    /// The header's version byte has a major version other than 2. A
    /// gateway answers with an INVALID_MAJOR_VERSION notify.
    Version(u8),
    /// The header's length is below [`HEADER_LEN`] or above
    /// [`MAX_MESSAGE`].
    MessageLength(u32),
    /// Bytes are left over: after the length the header gives, after the
    /// last payload, or after an encrypted payload, which must come last.
    Trailing,
    /// A payload of this type has a length below 4 or past the end of the
    /// message, or the chain names it and the message has ended.
    PayloadLength(u8),
    /// The body of a payload of this type does not follow its layout.
    Body {
        /// The payload type.
        kind: u8,
        /// What is wrong, in a few words.
        reason: &'static str,
    },
    /// A count is above one of this module's limits, named here.
    Limit(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Short => f.write_str("message cut short"),
            Error::Version(v) => write!(f, "version byte {v:#04x}, not IKEv2"),
            Error::MessageLength(n) => write!(f, "message length {n}, outside {HEADER_LEN}..={MAX_MESSAGE}"),
            Error::Trailing => f.write_str("bytes left after the last payload"),
            Error::PayloadLength(k) => write!(f, "payload type {k} has a bad length"),
            Error::Body { kind, reason } => write!(f, "payload type {kind}: {reason}"),
            Error::Limit(what) => write!(f, "too many {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// The IKE header as it is on the wire, read without checking the version
/// or length. A gateway reads it to answer a message it cannot parse, for
/// example with INVALID_MAJOR_VERSION.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The SPI the initiator chose for the IKE SA.
    pub initiator_spi: u64,
    /// The SPI the responder chose, or 0 in the first request.
    pub responder_spi: u64,
    /// The type of the first payload, or 0 for none.
    pub next_payload: u8,
    /// The major version in the high four bits, the minor in the low four.
    pub version: u8,
    /// The exchange type: see [`exchange`].
    pub exchange: u8,
    /// The flags byte, reserved bits and all: see [`flags`].
    pub flags: u8,
    /// Counts the requests in each direction. A response carries its
    /// request's ID.
    pub message_id: u32,
    /// The length of the whole message, header included.
    pub length: u32,
}

impl Header {
    /// The major version.
    pub fn major(&self) -> u8 {
        self.version >> 4
    }

    /// The minor version.
    pub fn minor(&self) -> u8 {
        self.version & 0x0f
    }
}

/// One IKEv2 message: the header's fields and the payloads. The header's
/// next payload and length are worked out from the payloads, so neither
/// is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The SPI the initiator chose for the IKE SA.
    pub initiator_spi: u64,
    /// The SPI the responder chose, or 0 in the first request.
    pub responder_spi: u64,
    /// The minor version, 0 for RFC 7296. The writer refuses values above 15.
    pub minor_version: u8,
    /// The exchange type: see [`exchange`].
    pub exchange: u8,
    /// The flags: see [`flags`]. The reader keeps only the three defined
    /// bits. The writer refuses any other bits.
    pub flags: u8,
    /// Counts the requests in each direction. A response carries its
    /// request's ID.
    pub message_id: u32,
    /// The payloads, in order.
    pub payloads: Vec<Payload>,
}

impl Message {
    /// Whether the message is a response.
    pub fn is_response(&self) -> bool {
        self.flags & flags::RESPONSE != 0
    }

    /// Whether the original initiator of the IKE SA sent the message.
    pub fn is_initiator(&self) -> bool {
        self.flags & flags::INITIATOR != 0
    }

    /// A response to this request, carrying `payloads`. It has the same
    /// SPIs, exchange and message ID, and the response flag. The other
    /// peer sends it, so it has the initiator flag only when the request
    /// does not.
    pub fn response(&self, payloads: Vec<Payload>) -> Message {
        let initiator = if self.is_initiator() { 0 } else { flags::INITIATOR };
        Message {
            initiator_spi: self.initiator_spi,
            responder_spi: self.responder_spi,
            minor_version: 0,
            exchange: self.exchange,
            flags: flags::RESPONSE | initiator,
            message_id: self.message_id,
            payloads,
        }
    }

    /// The first payload of type `kind`, if there is one: for example
    /// `payload::KE` for the key exchange.
    pub fn payload(&self, kind: u8) -> Option<&Payload> {
        self.payloads.iter().find(|p| p.kind() == kind)
    }

    /// The first notify payload of type `kind`, if there is one.
    pub fn notify(&self, kind: u16) -> Option<&Notify> {
        self.payloads.iter().find_map(|p| match &p.body {
            Body::Notify(n) if n.kind == kind => Some(n),
            _ => None,
        })
    }

    /// The type of the first payload marked critical whose type RFC 7296
    /// and RFC 7383 do not define. RFC 7296 says to reject such a message
    /// with an UNSUPPORTED_CRITICAL_PAYLOAD notify that carries this type.
    pub fn unsupported_critical(&self) -> Option<u8> {
        self.payloads.iter().find_map(|p| match p.body {
            Body::Other { kind, .. } if p.critical && !is_defined(kind) => Some(kind),
            _ => None,
        })
    }
}

/// What a UDP datagram on port 4500 holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NatT {
    /// An IKE message, after the non-ESP marker.
    Ike(Message),
    /// An ESP packet, all of it, starting with its nonzero SPI.
    Esp(Vec<u8>),
    /// A NAT keepalive: the single byte [`NAT_KEEPALIVE`].
    Keepalive,
}

/// One payload: the critical bit from its generic header, and its body.
/// The next payload field and the length are worked out when it is
/// written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// Set when a receiver that does not know this payload type must
    /// reject the message. RFC 7296 has senders set it only for types
    /// outside its own.
    pub critical: bool,
    /// The payload's type and contents.
    pub body: Body,
}

impl Payload {
    /// A payload that is not marked critical.
    pub fn new(body: Body) -> Payload {
        Payload { critical: false, body }
    }

    /// The payload type.
    pub fn kind(&self) -> u8 {
        self.body.kind()
    }
}

/// A payload's body, by type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// SA: the proposals, in order of preference. A response holds one.
    SecurityAssociation(Vec<Proposal>),
    /// KE: a Diffie-Hellman public value.
    KeyExchange(KeyExchange),
    /// IDi: the initiator's identity.
    IdInitiator(Identification),
    /// IDr: the responder's identity.
    IdResponder(Identification),
    /// Ni or Nr: a nonce. RFC 7296 asks for 16 to 256 bytes, and leaves
    /// the check to the receiver.
    Nonce(Vec<u8>),
    /// N: a notify message.
    Notify(Notify),
    /// D: SAs to delete.
    Delete(Delete),
    /// V: a vendor ID, opaque bytes.
    VendorId(Vec<u8>),
    /// TSi: the initiator's traffic selectors.
    TsInitiator(Vec<TrafficSelector>),
    /// TSr: the responder's traffic selectors.
    TsResponder(Vec<TrafficSelector>),
    /// SK: encrypted and authenticated payloads, kept as bytes.
    Encrypted(Encrypted),
    /// SKF: one fragment of an SK payload (RFC 7383), kept as bytes.
    EncryptedFragment(EncryptedFragment),
    /// Any other payload type, such as CERT, AUTH, CP or EAP, with its
    /// body unread. The writer refuses one whose `kind` is 0 or a type
    /// another variant covers.
    Other {
        /// The payload type.
        kind: u8,
        /// The body.
        data: Vec<u8>,
    },
}

impl Body {
    /// The payload type.
    pub fn kind(&self) -> u8 {
        match self {
            Body::SecurityAssociation(_) => payload::SA,
            Body::KeyExchange(_) => payload::KE,
            Body::IdInitiator(_) => payload::IDI,
            Body::IdResponder(_) => payload::IDR,
            Body::Nonce(_) => payload::NONCE,
            Body::Notify(_) => payload::NOTIFY,
            Body::Delete(_) => payload::DELETE,
            Body::VendorId(_) => payload::VENDOR_ID,
            Body::TsInitiator(_) => payload::TSI,
            Body::TsResponder(_) => payload::TSR,
            Body::Encrypted(_) => payload::SK,
            Body::EncryptedFragment(_) => payload::SKF,
            Body::Other { kind, .. } => *kind,
        }
    }
}

/// One proposal in an SA payload: a protocol and the transforms offered
/// for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The proposal number. The first is 1, and each one after it is one
    /// more. A response echoes the number it chose.
    pub number: u8,
    /// The protocol: see [`protocol`].
    pub protocol: u8,
    /// The sender's SPI: empty for IKE in IKE_SA_INIT, 4 bytes for ESP
    /// and AH, 8 for IKE when rekeying. The writer refuses more than [`MAX_SPI`] bytes.
    pub spi: Vec<u8>,
    /// The transforms. Several of one type are alternatives.
    pub transforms: Vec<Transform>,
}

/// One transform in a proposal: an algorithm of some type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transform {
    /// The transform type: see [`transform`].
    pub kind: u8,
    /// The algorithm's ID within its type.
    pub id: u16,
    /// The attributes, such as the key length.
    pub attributes: Vec<Attribute>,
}

/// One transform attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute type, 15 bits. The writer refuses values above 0x7FFF.
    pub kind: u16,
    /// The value.
    pub value: AttributeValue,
}

/// A transform attribute's value, short or long.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttributeValue {
    /// A two-byte value in the attribute itself (the TV form).
    Short(u16),
    /// A value with its own length (the TLV form). The writer refuses more than 65535 bytes.
    Long(Vec<u8>),
}

/// The body of a KE payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyExchange {
    /// The Diffie-Hellman group: one of the DH transform IDs.
    pub group: u16,
    /// The public value.
    pub data: Vec<u8>,
}

/// The body of an IDi or IDr payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identification {
    /// The identification type: see [`id`].
    pub kind: u8,
    /// The identity: four bytes of address for IPV4_ADDR, the name for
    /// FQDN, and so on.
    pub data: Vec<u8>,
}

/// The body of a notify payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notify {
    /// The protocol the SPI belongs to, or 0 with no SPI.
    pub protocol: u8,
    /// The SPI of the SA the notify is about, often empty. The writer refuses
    /// more than [`MAX_SPI`] bytes.
    pub spi: Vec<u8>,
    /// The notify message type: see [`notify`].
    pub kind: u16,
    /// The notification data.
    pub data: Vec<u8>,
}

/// The body of a delete payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delete {
    /// The protocol of the SAs: [`protocol::IKE`] for the IKE SA itself,
    /// or ESP or AH.
    pub protocol: u8,
    /// The length of each SPI: 0 for IKE, 4 for ESP and AH.
    pub spi_size: u8,
    /// The SPIs of the SAs to delete. The writer refuses any whose
    /// length is not `spi_size`, and any past [`MAX_DELETE_SPIS`].
    pub spis: Vec<Vec<u8>>,
}

/// One traffic selector: a range of addresses, ports and an IP protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrafficSelector {
    /// TS_IPV4_ADDR_RANGE.
    Ipv4 {
        /// The IP protocol, or 0 for any.
        protocol: u8,
        /// The first port.
        start_port: u16,
        /// The last port.
        end_port: u16,
        /// The first address.
        start: Ipv4Addr,
        /// The last address.
        end: Ipv4Addr,
    },
    /// TS_IPV6_ADDR_RANGE.
    Ipv6 {
        /// The IP protocol, or 0 for any.
        protocol: u8,
        /// The first port.
        start_port: u16,
        /// The last port.
        end_port: u16,
        /// The first address.
        start: Ipv6Addr,
        /// The last address.
        end: Ipv6Addr,
    },
    /// Any other selector type, unread. The writer refuses one whose
    /// `kind` is one of the two above.
    Other {
        /// The selector type.
        kind: u8,
        /// The byte after the type, which is the IP protocol for the
        /// address range types.
        protocol: u8,
        /// The bytes after the selector's length field.
        data: Vec<u8>,
    },
}

/// The body of an SK payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encrypted {
    /// The type of the first payload inside, from the SK payload's next
    /// payload field.
    pub first_payload: u8,
    /// The IV, the ciphertext and the integrity checksum, as sent.
    pub data: Vec<u8>,
}

/// The body of an SKF payload. RFC 7383 has a receiver discard a fragment
/// that breaks the rules in [`EncryptedFragment::is_valid`], so the reader
/// and writer refuse one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedFragment {
    /// The type of the first payload inside, in the first fragment. In
    /// every other fragment it must be 0.
    pub first_payload: u8,
    /// This fragment's number, from 1 up to `total`.
    pub number: u16,
    /// How many fragments there are, at least 1.
    pub total: u16,
    /// The IV, the ciphertext and the integrity checksum, as sent.
    pub data: Vec<u8>,
}

impl EncryptedFragment {
    /// Whether the fields follow RFC 7383 section 2.5: the number and the
    /// total are not 0, the number is at most the total, and only the
    /// first fragment names a first payload.
    pub fn is_valid(&self) -> bool {
        self.number != 0 && self.number <= self.total && (self.number == 1 || self.first_payload == payload::NONE)
    }
}

/// Reads a payload chain: `first` is the type of the first payload, and
/// `b` holds the payloads and nothing else. A message's payloads come
/// after its header. Inside an SK payload, `first` is
/// [`Encrypted::first_payload`] and `b` is the plaintext with its padding
/// and pad length taken off. An SK or SKF payload ends the chain, and must
/// end the bytes too. More than [`MAX_CHAIN`] bytes is
/// [`Error::Limit`].
///
/// To write a payload chain, put the payloads in a [`Message`]
/// and write it. Byte 16 gives the first type; bytes from [`HEADER_LEN`] onward
/// are the inner chain. The temporary header is excluded from the plaintext
/// encrypted for an SK payload.
///
/// ```
/// use fictionet::stdlib::codec::Wire;
/// use fictionet::stdlib::ike::{Body, Message, Payload, HEADER_LEN, exchange, parse_payloads};
/// let payloads = vec![Payload::new(Body::Nonce(vec![7; 32]))];
/// let envelope = Message {
///     initiator_spi: 0, responder_spi: 0, minor_version: 0,
///     exchange: exchange::INFORMATIONAL, flags: 0, message_id: 0,
///     payloads: payloads.clone(),
/// };
/// let bytes = envelope.to_bytes().unwrap();
/// let (first, chain) = (bytes[16], &bytes[HEADER_LEN..]);
/// assert_eq!(parse_payloads(first, chain).unwrap(), payloads);
/// ```
pub fn parse_payloads(first: u8, b: &[u8]) -> Result<Vec<Payload>, Error> {
    if b.len() > MAX_CHAIN {
        return Err(Error::Limit("chain bytes"));
    }
    let mut out = Vec::new();
    let mut kind = first;
    let mut pos = 0;
    while kind != payload::NONE {
        if out.len() == MAX_PAYLOADS {
            return Err(Error::Limit("payloads"));
        }
        let rest = &b[pos..];
        if rest.len() < PAYLOAD_HEADER_LEN {
            return Err(Error::PayloadLength(kind));
        }
        let next = rest[0];
        let critical = rest[1] & 0x80 != 0;
        let len = usize::from(be16(rest, 2).ok_or(Error::PayloadLength(kind))?);
        if len < PAYLOAD_HEADER_LEN || len > rest.len() {
            return Err(Error::PayloadLength(kind));
        }
        let body = parse_body(kind, next, &rest[PAYLOAD_HEADER_LEN..len])?;
        pos += len;
        let ends = matches!(body, Body::Encrypted(_) | Body::EncryptedFragment(_));
        out.push(Payload { critical, body });
        if ends {
            break;
        }
        kind = next;
    }
    if pos != b.len() {
        return Err(Error::Trailing);
    }
    Ok(out)
}

/// Whether RFC 7296 or RFC 7383 defines payload type `kind`.
fn is_defined(kind: u8) -> bool {
    (payload::SA..=payload::EAP).contains(&kind) || kind == payload::SKF
}

/// Whether a [`Body`] variant other than `Other` covers payload type
/// `kind`.
fn is_typed(kind: u8) -> bool {
    matches!(
        kind,
        payload::SA
            | payload::KE
            | payload::IDI
            | payload::IDR
            | payload::NONCE
            | payload::NOTIFY
            | payload::DELETE
            | payload::VENDOR_ID
            | payload::TSI
            | payload::TSR
            | payload::SK
            | payload::SKF
    )
}

fn bad(kind: u8, reason: &'static str) -> Error {
    Error::Body { kind, reason }
}

fn parse_body(kind: u8, next: u8, b: &[u8]) -> Result<Body, Error> {
    let short = || bad(kind, "body shorter than its fixed fields");
    Ok(match kind {
        payload::SA => Body::SecurityAssociation(parse_sa(b)?),
        payload::KE => {
            let rest = b.get(4..).ok_or_else(short)?;
            Body::KeyExchange(KeyExchange { group: be16(b, 0).ok_or(short())?, data: rest.to_vec() })
        }
        payload::IDI | payload::IDR => {
            let rest = b.get(4..).ok_or_else(short)?;
            let ident = Identification { kind: b[0], data: rest.to_vec() };
            if kind == payload::IDI { Body::IdInitiator(ident) } else { Body::IdResponder(ident) }
        }
        payload::NONCE => Body::Nonce(b.to_vec()),
        payload::NOTIFY => {
            if b.len() < 4 {
                return Err(short());
            }
            let spi_size = usize::from(b[1]);
            let spi = b.get(4..4 + spi_size).ok_or(bad(kind, "SPI longer than the payload"))?;
            Body::Notify(Notify {
                protocol: b[0],
                spi: spi.to_vec(),
                kind: be16(b, 2).ok_or(short())?,
                data: b[4 + spi_size..].to_vec(),
            })
        }
        payload::DELETE => {
            if b.len() < 4 {
                return Err(short());
            }
            let (spi_size, count) = (usize::from(b[1]), usize::from(be16(b, 2).ok_or(short())?));
            if count > MAX_DELETE_SPIS {
                return Err(Error::Limit("SPIs to delete"));
            }
            let rest = &b[4..];
            // count is at most MAX_DELETE_SPIS, so this cannot overflow.
            if count * spi_size != rest.len() {
                return Err(bad(kind, "SPI count and size do not match the length"));
            }
            let spis = if spi_size == 0 {
                vec![Vec::new(); count]
            } else {
                rest.chunks_exact(spi_size).map(<[u8]>::to_vec).collect()
            };
            Body::Delete(Delete { protocol: b[0], spi_size: b[1], spis })
        }
        payload::VENDOR_ID => Body::VendorId(b.to_vec()),
        payload::TSI => Body::TsInitiator(parse_selectors(kind, b)?),
        payload::TSR => Body::TsResponder(parse_selectors(kind, b)?),
        payload::SK => Body::Encrypted(Encrypted { first_payload: next, data: b.to_vec() }),
        payload::SKF => {
            let rest = b.get(4..).ok_or_else(short)?;
            let f =
                EncryptedFragment { first_payload: next, number: be16(b, 0).ok_or(short())?, total: be16(b, 2).ok_or(short())?, data: rest.to_vec() };
            if !f.is_valid() {
                return Err(bad(kind, "fragment number, total or next payload breaks RFC 7383"));
            }
            Body::EncryptedFragment(f)
        }
        _ => Body::Other { kind, data: b.to_vec() },
    })
}

/// Checks the last-substructure byte of an item: `more` while items
/// follow, 0 on the last.
fn last_flag(byte: u8, is_last: bool, more: u8) -> bool {
    if is_last { byte == 0 } else { byte == more }
}

fn parse_sa(b: &[u8]) -> Result<Vec<Proposal>, Error> {
    let k = payload::SA;
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        if out.len() == MAX_PROPOSALS {
            return Err(Error::Limit("proposals"));
        }
        let rest = &b[pos..];
        if rest.len() < 8 {
            return Err(bad(k, "proposal header cut short"));
        }
        let len = usize::from(be16(rest, 2).ok_or(bad(k, "proposal header cut short"))?);
        if len < 8 || len > rest.len() {
            return Err(bad(k, "proposal length out of range"));
        }
        let p = &rest[..len];
        let spi_size = usize::from(p[6]);
        let spi = p.get(8..8 + spi_size).ok_or(bad(k, "SPI longer than its proposal"))?;
        let transforms = parse_transforms(&p[8 + spi_size..], usize::from(p[7]))?;
        pos += len;
        if !last_flag(rest[0], pos == b.len(), 2) {
            return Err(bad(k, "proposal's last-substructure byte is wrong"));
        }
        out.push(Proposal { number: p[4], protocol: p[5], spi: spi.to_vec(), transforms });
    }
    Ok(out)
}

fn parse_transforms(b: &[u8], count: usize) -> Result<Vec<Transform>, Error> {
    let k = payload::SA;
    if count > MAX_TRANSFORMS {
        return Err(Error::Limit("transforms"));
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        if out.len() == count {
            return Err(bad(k, "more transforms than the proposal counts"));
        }
        let rest = &b[pos..];
        if rest.len() < 8 {
            return Err(bad(k, "transform header cut short"));
        }
        let len = usize::from(be16(rest, 2).ok_or(bad(k, "transform header cut short"))?);
        if len < 8 || len > rest.len() {
            return Err(bad(k, "transform length out of range"));
        }
        let attributes = parse_attributes(&rest[8..len])?;
        pos += len;
        if !last_flag(rest[0], pos == b.len(), 3) {
            return Err(bad(k, "transform's last-substructure byte is wrong"));
        }
        out.push(Transform { kind: rest[4], id: be16(rest, 6).ok_or(bad(k, "transform header cut short"))?, attributes });
    }
    if out.len() != count {
        return Err(bad(k, "fewer transforms than the proposal counts"));
    }
    Ok(out)
}

fn parse_attributes(b: &[u8]) -> Result<Vec<Attribute>, Error> {
    let k = payload::SA;
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < b.len() {
        if out.len() == MAX_ATTRIBUTES {
            return Err(Error::Limit("attributes"));
        }
        let rest = &b[pos..];
        if rest.len() < 4 {
            return Err(bad(k, "attribute cut short"));
        }
        let t = be16(rest, 0).ok_or(bad(k, "attribute cut short"))?;
        let kind = t & 0x7fff;
        if t & 0x8000 != 0 {
            out.push(Attribute { kind, value: AttributeValue::Short(be16(rest, 2).ok_or(bad(k, "attribute cut short"))?) });
            pos += 4;
        } else {
            let len = usize::from(be16(rest, 2).ok_or(bad(k, "attribute cut short"))?);
            let v = rest.get(4..4 + len).ok_or(bad(k, "attribute value cut short"))?;
            out.push(Attribute { kind, value: AttributeValue::Long(v.to_vec()) });
            pos += 4 + len;
        }
    }
    Ok(out)
}

fn parse_selectors(k: u8, b: &[u8]) -> Result<Vec<TrafficSelector>, Error> {
    if b.len() < 4 {
        return Err(bad(k, "body shorter than its fixed fields"));
    }
    let count = usize::from(b[0]);
    if count > MAX_SELECTORS {
        return Err(Error::Limit("traffic selectors"));
    }
    let mut out = Vec::new();
    let mut pos = 4;
    while pos < b.len() {
        if out.len() == count {
            return Err(bad(k, "more selectors than the payload counts"));
        }
        let rest = &b[pos..];
        if rest.len() < 4 {
            return Err(bad(k, "selector header cut short"));
        }
        let (kind, protocol, len) = (rest[0], rest[1], usize::from(be16(rest, 2).ok_or(bad(k, "selector header cut short"))?));
        if len < 4 || len > rest.len() {
            return Err(bad(k, "selector length out of range"));
        }
        let s = &rest[..len];
        let ts = match kind {
            ts::IPV4_ADDR_RANGE | ts::IPV6_ADDR_RANGE => {
                let n = if kind == ts::IPV4_ADDR_RANGE { 4 } else { 16 };
                if len != 8 + 2 * n {
                    return Err(bad(k, "address range selector has the wrong length"));
                }
                let (start_port, end_port) = (be16(s, 4).ok_or(bad(k, "selector header cut short"))?, be16(s, 6).ok_or(bad(k, "selector header cut short"))?);
                if n == 4 {
                    let a = |i: usize| Ipv4Addr::new(s[i], s[i + 1], s[i + 2], s[i + 3]);
                    TrafficSelector::Ipv4 { protocol, start_port, end_port, start: a(8), end: a(12) }
                } else {
                    let a = |i: usize| {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(&s[i..i + 16]);
                        Ipv6Addr::from(o)
                    };
                    TrafficSelector::Ipv6 { protocol, start_port, end_port, start: a(8), end: a(24) }
                }
            }
            _ => TrafficSelector::Other { kind, protocol, data: s[4..].to_vec() },
        };
        out.push(ts);
        pos += len;
    }
    if out.len() != count {
        return Err(bad(k, "fewer selectors than the payload counts"));
    }
    Ok(out)
}

/// Writes a complete payload chain, refusing values that exceed `cap`.
fn write_chain(payloads: &[Payload], cap: usize) -> Option<(u8, Vec<u8>)> {
    // Each part: its type, the next payload field it would give an SK or
    // SKF payload, its critical bit and its body.
    let mut parts: Vec<(u8, Option<u8>, bool, Vec<u8>)> = Vec::new();
    let mut used = 0usize;
    for (i, p) in payloads.iter().enumerate() {
        if parts.len() == MAX_PAYLOADS {
            return None;
        }
        let unreadable = match &p.body {
            Body::Other { kind, .. } => *kind == payload::NONE || is_typed(*kind),
            Body::EncryptedFragment(f) => !f.is_valid(),
            _ => false,
        };
        if unreadable {
            return None;
        }
        let room = cap.saturating_sub(used);
        if room < PAYLOAD_HEADER_LEN {
            return None;
        }
        let room = (room - PAYLOAD_HEADER_LEN).min(MAX_BODY);
        let body = write_body(&p.body, room)?;
        used += PAYLOAD_HEADER_LEN + body.len();
        let inner = match &p.body {
            Body::Encrypted(e) => Some(e.first_payload),
            Body::EncryptedFragment(f) => Some(f.first_payload),
            _ => None,
        };
        parts.push((p.kind(), inner, p.critical, body));
        if inner.is_some() && i + 1 != payloads.len() {
            return None;
        }
    }
    let first = parts.first().map_or(payload::NONE, |p| p.0);
    let mut out = Vec::with_capacity(used);
    for (i, (_, inner, critical, body)) in parts.iter().enumerate() {
        let next = match inner {
            Some(n) => *n,
            None => parts.get(i + 1).map_or(payload::NONE, |p| p.0),
        };
        out.push(next);
        out.push(if *critical { 0x80 } else { 0 });
        out.extend_from_slice(&((PAYLOAD_HEADER_LEN + body.len()) as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
    Some((first, out))
}

/// The whole slice if it fits in `room`.
fn fit(data: &[u8], room: usize) -> Option<&[u8]> {
    (data.len() <= room).then_some(data)
}

/// A body in at most `room` bytes, or `None` if its fixed fields do not
/// fit.
fn write_body(body: &Body, room: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let fixed = |n: usize| if room >= n { Some(()) } else { None };
    match body {
        Body::SecurityAssociation(props) => write_sa(props, room, &mut out)?,
        Body::KeyExchange(ke) => {
            fixed(4)?;
            out.extend_from_slice(&ke.group.to_be_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(fit(&ke.data, room - 4)?);
        }
        Body::IdInitiator(ident) | Body::IdResponder(ident) => {
            fixed(4)?;
            out.extend_from_slice(&[ident.kind, 0, 0, 0]);
            out.extend_from_slice(fit(&ident.data, room - 4)?);
        }
        Body::Nonce(data) | Body::VendorId(data) | Body::Other { data, .. } => {
            out.extend_from_slice(fit(data, room)?);
        }
        Body::Notify(n) => {
            let spi = fit(&n.spi, MAX_SPI)?;
            fixed(4 + spi.len())?;
            out.extend_from_slice(&[n.protocol, spi.len() as u8]);
            out.extend_from_slice(&n.kind.to_be_bytes());
            out.extend_from_slice(spi);
            out.extend_from_slice(fit(&n.data, room - 4 - spi.len())?);
        }
        Body::Delete(d) => {
            fixed(4)?;
            let size = usize::from(d.spi_size);
            let fits = (room - 4).checked_div(size).unwrap_or(MAX_DELETE_SPIS);
            if d.spis.len() > MAX_DELETE_SPIS.min(fits) || d.spis.iter().any(|s| s.len() != size) {
                return None;
            }
            let spis = &d.spis;
            out.extend_from_slice(&[d.protocol, d.spi_size]);
            out.extend_from_slice(&(spis.len() as u16).to_be_bytes());
            for s in spis {
                out.extend_from_slice(s);
            }
        }
        Body::TsInitiator(sel) | Body::TsResponder(sel) => {
            fixed(4)?;
            write_selectors(sel, room, &mut out)?;
        }
        Body::Encrypted(e) => out.extend_from_slice(fit(&e.data, room)?),
        Body::EncryptedFragment(f) => {
            fixed(4)?;
            out.extend_from_slice(&f.number.to_be_bytes());
            out.extend_from_slice(&f.total.to_be_bytes());
            out.extend_from_slice(fit(&f.data, room - 4)?);
        }
    }
    Some(out)
}

fn write_sa(props: &[Proposal], room: usize, out: &mut Vec<u8>) -> Option<()> {
    if props.len() > MAX_PROPOSALS {
        return None;
    }
    let mut last = None;
    for p in props {
        let bytes = write_proposal(p, room.checked_sub(out.len())?)?;
        last = Some(out.len());
        out.extend_from_slice(&bytes);
    }
    if let Some(i) = last {
        out[i] = 0;
    }
    Some(())
}

fn write_proposal(p: &Proposal, room: usize) -> Option<Vec<u8>> {
    let spi = fit(&p.spi, MAX_SPI)?;
    if 8 + spi.len() > room {
        return None;
    }
    let mut out = vec![2, 0, 0, 0, p.number, p.protocol, spi.len() as u8, 0];
    out.extend_from_slice(spi);
    let (mut n, mut last) = (0u8, None);
    if p.transforms.len() > MAX_TRANSFORMS {
        return None;
    }
    for t in &p.transforms {
        let bytes = write_transform(t, room.checked_sub(out.len())?)?;
        last = Some(out.len());
        out.extend_from_slice(&bytes);
        n += 1;
    }
    if let Some(i) = last {
        out[i] = 0;
    }
    out[7] = n;
    // room is at most MAX_BODY, so the length fits in 16 bits.
    let len = (out.len() as u16).to_be_bytes();
    out[2..4].copy_from_slice(&len);
    Some(out)
}

fn write_transform(t: &Transform, room: usize) -> Option<Vec<u8>> {
    if room < 8 {
        return None;
    }
    let mut out = vec![3, 0, 0, 0, t.kind, 0];
    out.extend_from_slice(&t.id.to_be_bytes());
    if t.attributes.len() > MAX_ATTRIBUTES {
        return None;
    }
    for a in &t.attributes {
        if a.kind > 0x7fff {
            return None;
        }
        let kind = a.kind & 0x7fff;
        let mut bytes = Vec::new();
        match &a.value {
            AttributeValue::Short(v) => {
                bytes.extend_from_slice(&(kind | 0x8000).to_be_bytes());
                bytes.extend_from_slice(&v.to_be_bytes());
            }
            AttributeValue::Long(v) => {
                let v = fit(v, usize::from(u16::MAX))?;
                bytes.extend_from_slice(&kind.to_be_bytes());
                bytes.extend_from_slice(&(v.len() as u16).to_be_bytes());
                bytes.extend_from_slice(v);
            }
        }
        if out.len() + bytes.len() > room {
            return None;
        }
        out.extend_from_slice(&bytes);
    }
    let len = (out.len() as u16).to_be_bytes();
    out[2..4].copy_from_slice(&len);
    Some(out)
}

fn write_selectors(sel: &[TrafficSelector], room: usize, out: &mut Vec<u8>) -> Option<()> {
    out.extend_from_slice(&[0, 0, 0, 0]);
    let mut n = 0u8;
    for s in sel {
        if usize::from(n) == MAX_SELECTORS {
            return None;
        }
        let mut bytes = Vec::new();
        match s {
            TrafficSelector::Ipv4 { protocol, start_port, end_port, start, end } => {
                bytes.extend_from_slice(&[ts::IPV4_ADDR_RANGE, *protocol, 0, 16]);
                bytes.extend_from_slice(&start_port.to_be_bytes());
                bytes.extend_from_slice(&end_port.to_be_bytes());
                bytes.extend_from_slice(&start.octets());
                bytes.extend_from_slice(&end.octets());
            }
            TrafficSelector::Ipv6 { protocol, start_port, end_port, start, end } => {
                bytes.extend_from_slice(&[ts::IPV6_ADDR_RANGE, *protocol, 0, 40]);
                bytes.extend_from_slice(&start_port.to_be_bytes());
                bytes.extend_from_slice(&end_port.to_be_bytes());
                bytes.extend_from_slice(&start.octets());
                bytes.extend_from_slice(&end.octets());
            }
            TrafficSelector::Other { kind, protocol, data } => {
                if *kind == ts::IPV4_ADDR_RANGE || *kind == ts::IPV6_ADDR_RANGE {
                    return None;
                }
                let room_left = room.saturating_sub(out.len()).saturating_sub(4);
                let data = fit(data, room_left.min(usize::from(u16::MAX) - 4))?;
                bytes.extend_from_slice(&[*kind, *protocol]);
                bytes.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
                bytes.extend_from_slice(data);
            }
        }
        if out.len() + bytes.len() > room {
            return None;
        }
        out.extend_from_slice(&bytes);
        n += 1;
    }
    out[0] = n;
    Some(())
}

impl Wire for Header {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly the 28-byte header. Refuses short or trailing input.
    /// The version and flag bytes are kept without validation.
    fn parse(b: &[u8]) -> Result<Header, Error> {
        if b.len() != HEADER_LEN {
            return Err(if b.len() < HEADER_LEN { Error::Short } else { Error::Trailing });
        }

        let mut r = Reader::new(b);
        Ok(Header {
            initiator_spi: r.u64_be()?,
            responder_spi: r.u64_be()?,
            next_payload: r.u8()?,
            version: r.u8()?,
            exchange: r.u8()?,
            flags: r.u8()?,
            message_id: r.u32_be()?,
            length: r.u32_be()?,
        })
    }

    /// Appends all header fields unchanged. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = [0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&self.initiator_spi.to_be_bytes());
        out[8..16].copy_from_slice(&self.responder_spi.to_be_bytes());
        out[16] = self.next_payload;
        out[17] = self.version;
        out[18] = self.exchange;
        out[19] = self.flags;
        out[20..24].copy_from_slice(&self.message_id.to_be_bytes());
        out[24..28].copy_from_slice(&self.length.to_be_bytes());
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the message in `b`, which must be exactly one message, as a
    /// UDP datagram on port 500 carries it.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Message, Error> {
        let h = Header::parse(b.get(..HEADER_LEN).ok_or(Error::Short)?)?;
        if h.major() != MAJOR_VERSION {
            return Err(Error::Version(h.version));
        }
        let length = h.length as usize;
        if !(HEADER_LEN..=MAX_MESSAGE).contains(&length) {
            return Err(Error::MessageLength(h.length));
        }
        if b.len() < length {
            return Err(Error::Short);
        }
        if b.len() > length {
            return Err(Error::Trailing);
        }
        let payloads = parse_payloads(h.next_payload, &b[HEADER_LEN..])?;
        Ok(Message {
            initiator_spi: h.initiator_spi,
            responder_spi: h.responder_spi,
            minor_version: h.minor(),
            exchange: h.exchange,
            flags: h.flags & flags::ALL,
            message_id: h.message_id,
            payloads,
        })
    }

    /// Appends the full payload chain. Refuses oversized fields or counts, values outside
    /// field widths, typed payloads represented as Other, inconsistent SPI lengths and
    /// payloads after SK or SKF. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let (first, chain) = write_chain(&self.payloads, MAX_CHAIN).ok_or(Error::Unwritable)?;
        let header = Header {
            initiator_spi: self.initiator_spi,
            responder_spi: self.responder_spi,
            next_payload: first,
            version: MAJOR_VERSION << 4 | (self.minor_version & 0x0f),
            exchange: self.exchange,
            flags: self.flags & flags::ALL,
            message_id: self.message_id,
            length: (HEADER_LEN + chain.len()) as u32,
        };
        let mut out = Vec::with_capacity(HEADER_LEN + chain.len());
        header.write(&mut out)?;
        out.extend_from_slice(&chain);
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for NatT {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a datagram that came to port 4500. Fewer than four bytes,
    /// other than a keepalive, is [`Error::Short`].
    /// Refuses input above [`MAX_MESSAGE`] + 4 and malformed or trailing IKE bytes.
    fn parse(b: &[u8]) -> Result<NatT, Error> {
        if b.len() > MAX_MESSAGE + NON_ESP_MARKER.len() {
            return Err(Error::Limit("datagram bytes"));
        }

        if b == [NAT_KEEPALIVE] {
            return Ok(NatT::Keepalive);
        }
        match b.get(..4) {
            None => Err(Error::Short),
            Some(m) if m == NON_ESP_MARKER => Message::parse(&b[4..]).map(NatT::Ike),
            Some(_) => Ok(NatT::Esp(b.to_vec())),
        }
    }

    /// Appends the UDP payload. Refuses unwritable IKE messages and ESP data shorter
    /// than four bytes, above [`MAX_MESSAGE`] + 4, or beginning with the non-ESP marker.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        match self {
            NatT::Keepalive => out.push(NAT_KEEPALIVE),
            NatT::Ike(message) => { out.extend_from_slice(&NON_ESP_MARKER); message.write(&mut out)?; }
            NatT::Esp(data) => {
                if data.len() < 4 || data.len() > MAX_MESSAGE + 4 || data[..4] == NON_ESP_MARKER {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
            }
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl From<Truncated> for Error {
    #[inline]
    fn from(_: Truncated) -> Self { Error::Short }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::mutate;

    /// An IKE_SA_INIT request laid out by hand from the figures in RFC
    /// 7296 sections 3.1 to 3.10: header, SA, KE, Ni, and two notifies.
    fn sa_init_bytes() -> Vec<u8> {
        // Kept by hand, one field group per line, so each comment sits on
        // the bytes it describes.
        #[rustfmt::skip]
        let mut b = vec![
            // Initiator SPI, responder SPI 0.
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0, 0, 0, 0,
            // Next payload SA, version 2.0, IKE_SA_INIT, flags I, message ID 0.
            33, 0x20, 34, 0x08, 0, 0, 0, 0,
            // Length, filled in below.
            0, 0, 0, 0,
            // SA payload: next KE, length 4 + 44.
            34, 0, 0, 48,
            // Proposal 1, last, length 44, IKE, no SPI, 4 transforms.
            0, 0, 0, 44, 1, 1, 0, 4,
            // ENCR_AES_CBC with a 256-bit key length attribute.
            3, 0, 0, 12, 1, 0, 0, 12, 0x80, 14, 0x01, 0x00,
            // PRF_HMAC_SHA2_256.
            3, 0, 0, 8, 2, 0, 0, 5,
            // AUTH_HMAC_SHA2_256_128.
            3, 0, 0, 8, 3, 0, 0, 12,
            // DH group 19, last.
            0, 0, 0, 8, 4, 0, 0, 19,
            // KE payload: next nonce, length 4 + 4 + 8, group 19.
            40, 0, 0, 16, 0, 19, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            // Nonce payload: next notify, 16 bytes.
            41, 0, 0, 20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
            0xaf,
            // Notify NAT_DETECTION_SOURCE_IP with 4 bytes of data, next notify.
            41, 0, 0, 12, 0, 0, 0x40, 0x04, 0xde, 0xad, 0xbe, 0xef,
            // Notify COOKIE with 2 bytes of data, last.
            0, 0, 0, 10, 0, 0, 0x40, 0x06, 0xc0, 0x0c,
        ];
        let len = (b.len() as u32).to_be_bytes();
        b[24..28].copy_from_slice(&len);
        b
    }

    #[test]
    fn sa_init_example() {
        let bytes = sa_init_bytes();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.initiator_spi, 0x1122_3344_5566_7788);
        assert_eq!(m.responder_spi, 0);
        assert_eq!(m.exchange, exchange::IKE_SA_INIT);
        assert!(m.is_initiator() && !m.is_response());
        assert_eq!(m.payloads.len(), 5);
        let Body::SecurityAssociation(props) = &m.payloads[0].body else { panic!() };
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].protocol, protocol::IKE);
        let t = &props[0].transforms;
        assert_eq!(t.len(), 4);
        assert_eq!((t[0].kind, t[0].id), (transform::ENCR, transform::ENCR_AES_CBC));
        assert_eq!(t[0].attributes, [Attribute { kind: transform::KEY_LENGTH, value: AttributeValue::Short(256) }]);
        assert_eq!((t[3].kind, t[3].id), (transform::DH, transform::DH_ECP_256));
        assert_eq!(
            m.payloads[1].body,
            Body::KeyExchange(KeyExchange { group: 19, data: vec![1, 2, 3, 4, 5, 6, 7, 8] })
        );
        assert_eq!(m.payloads[2].body, Body::Nonce((0xa0..=0xaf).collect()));
        assert_eq!(m.notify(notify::COOKIE).unwrap().data, [0xc0, 0x0c]);
        assert_eq!(m.notify(notify::NAT_DETECTION_SOURCE_IP).unwrap().data, [0xde, 0xad, 0xbe, 0xef]);
        assert!(m.notify(notify::INITIAL_CONTACT).is_none());
        // Written back, the bytes are the same.
        assert_eq!(m.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn every_prefix_is_short() {
        let bytes = sa_init_bytes();
        for n in 0..bytes.len() {
            assert_eq!(Message::parse(&bytes[..n]), Err(Error::Short), "{n} bytes");
        }
        let mut more = bytes.clone();
        more.push(0);
        assert_eq!(Message::parse(&more), Err(Error::Trailing));
    }

    #[test]
    fn header_and_version() {
        let mut bytes = sa_init_bytes();
        let h = Header::parse(&bytes[..HEADER_LEN]).unwrap();
        assert_eq!((h.major(), h.minor()), (2, 0));
        assert_eq!(h.length as usize, bytes.len());
        assert_eq!(h.to_bytes().unwrap(), bytes[..28]);
        assert_eq!(Header::parse(&bytes[..27]), Err(Error::Short));
        // IKEv1's version byte, 0x10, is not read, but the header still is.
        bytes[17] = 0x10;
        assert_eq!(Message::parse(&bytes), Err(Error::Version(0x10)));
        assert_eq!(Header::parse(&bytes[..HEADER_LEN]).unwrap().major(), 1);
        // A higher minor version is read and kept.
        bytes[17] = 0x21;
        assert_eq!(Message::parse(&bytes).unwrap().minor_version, 1);
        // Reserved flag bits are dropped.
        bytes[19] = 0xff;
        assert_eq!(Message::parse(&bytes).unwrap().flags, flags::ALL);
    }

    #[test]
    fn message_length_errors() {
        let mut bytes = sa_init_bytes();
        bytes[24..28].copy_from_slice(&27u32.to_be_bytes());
        assert_eq!(Message::parse(&bytes), Err(Error::MessageLength(27)));
        bytes[24..28].copy_from_slice(&70000u32.to_be_bytes());
        assert_eq!(Message::parse(&bytes), Err(Error::MessageLength(70000)));
        // A length shorter than the bytes.
        let mut bytes = sa_init_bytes();
        let n = bytes.len() as u32 - 1;
        bytes[24..28].copy_from_slice(&n.to_be_bytes());
        assert_eq!(Message::parse(&bytes), Err(Error::Trailing));
    }

    fn message(payloads: Vec<Payload>) -> Message {
        Message {
            initiator_spi: 1,
            responder_spi: 2,
            minor_version: 0,
            exchange: exchange::INFORMATIONAL,
            flags: 0,
            message_id: 5,
            payloads,
        }
    }

    /// A header with `chain` after it and `first` as its next payload.
    fn raw(first: u8, chain: &[u8]) -> Vec<u8> {
        let mut b = message(vec![]).to_bytes().unwrap();
        b[16] = first;
        b.extend_from_slice(chain);
        let len = (b.len() as u32).to_be_bytes();
        b[24..28].copy_from_slice(&len);
        b
    }

    #[test]
    fn payload_chain_errors() {
        // The header names a payload, and there is none.
        assert_eq!(Message::parse(&raw(payload::NONCE, &[])), Err(Error::PayloadLength(payload::NONCE)));
        // A payload length below 4, and past the end.
        assert_eq!(Message::parse(&raw(payload::NONCE, &[0, 0, 0, 3])), Err(Error::PayloadLength(payload::NONCE)));
        assert_eq!(Message::parse(&raw(payload::NONCE, &[0, 0, 0, 9, 1])), Err(Error::PayloadLength(payload::NONCE)));
        // Bytes after the last payload.
        assert_eq!(Message::parse(&raw(payload::NONCE, &[0, 0, 0, 5, 1, 9])), Err(Error::Trailing));
        // Bytes after an SK payload, whose next field names what is inside.
        assert_eq!(Message::parse(&raw(payload::SK, &[payload::IDI, 0, 0, 5, 1, 9])), Err(Error::Trailing));
        // Too many payloads.
        let chain: Vec<u8> = (0..=MAX_PAYLOADS).flat_map(|_| [payload::VENDOR_ID, 0, 0, 4]).collect();
        assert_eq!(Message::parse(&raw(payload::VENDOR_ID, &chain)), Err(Error::Limit("payloads")));
        let chain: Vec<u8> =
            (0..MAX_PAYLOADS).flat_map(|i| [if i + 1 == MAX_PAYLOADS { 0 } else { 43 }, 0, 0, 4]).collect();
        assert_eq!(Message::parse(&raw(payload::VENDOR_ID, &chain)).unwrap().payloads.len(), MAX_PAYLOADS);
    }

    fn body_err(kind: u8, body: &[u8]) -> Error {
        let mut chain = vec![0, 0];
        chain.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        chain.extend_from_slice(body);
        Message::parse(&raw(kind, &chain)).unwrap_err()
    }

    fn body_ok(kind: u8, body: &[u8]) -> Body {
        let mut chain = vec![0, 0];
        chain.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        chain.extend_from_slice(body);
        Message::parse(&raw(kind, &chain)).unwrap().payloads.remove(0).body
    }

    fn is_body(e: Error, k: u8) -> bool {
        matches!(e, Error::Body { kind, .. } if kind == k)
    }

    #[test]
    fn body_errors() {
        // Fixed fields cut short.
        for k in [
            payload::KE,
            payload::IDI,
            payload::IDR,
            payload::NOTIFY,
            payload::DELETE,
            payload::TSI,
            payload::TSR,
            payload::SKF,
        ] {
            assert!(is_body(body_err(k, &[0, 0, 0]), k), "type {k}");
        }
        // A notify SPI longer than the payload.
        assert!(is_body(body_err(payload::NOTIFY, &[3, 4, 0, 1, 0, 0, 0]), payload::NOTIFY));
        // Delete: count times size must fill the body.
        assert!(is_body(body_err(payload::DELETE, &[3, 4, 0, 2, 1, 2, 3, 4]), payload::DELETE));
        assert_eq!(body_err(payload::DELETE, &[3, 0, 0x10, 0x01]), Error::Limit("SPIs to delete"));
        // Proposals.
        let sa = payload::SA;
        assert!(is_body(body_err(sa, &[0, 0, 0, 8, 1, 1, 0]), sa));
        assert!(is_body(body_err(sa, &[0, 0, 0, 7, 1, 1, 0, 0]), sa));
        assert!(is_body(body_err(sa, &[0, 0, 0, 9, 1, 1, 0, 0]), sa));
        assert!(is_body(body_err(sa, &[0, 0, 0, 8, 1, 1, 1, 0]), sa));
        assert!(is_body(body_err(sa, &[2, 0, 0, 8, 1, 1, 0, 0]), sa), "last proposal marked as not last");
        assert!(is_body(body_err(sa, &[0, 0, 0, 8, 1, 1, 0, 0, 0, 0, 0, 8, 2, 1, 0, 0]), sa));
        assert_eq!(body_err(sa, &[0, 0, 0, 8, 1, 1, 0, 65]), Error::Limit("transforms"));
        let many: Vec<u8> = (0..=MAX_PROPOSALS).flat_map(|_| [2, 0, 0, 8, 1, 1, 0, 0]).collect();
        assert_eq!(body_err(sa, &many), Error::Limit("proposals"));
        // Transforms.
        let prop = |count: u8, t: &[u8]| {
            let mut p = vec![0, 0, 0, 8 + t.len() as u8, 1, 1, 0, count];
            p.extend_from_slice(t);
            p
        };
        assert!(body_ok(sa, &prop(1, &[0, 0, 0, 8, 1, 0, 0, 12])) != Body::Nonce(vec![]));
        assert!(is_body(body_err(sa, &prop(1, &[0, 0, 0, 8, 1, 0, 0])), sa));
        assert!(is_body(body_err(sa, &prop(1, &[0, 0, 0, 7, 1, 0, 0, 12])), sa));
        assert!(is_body(body_err(sa, &prop(1, &[0, 0, 0, 9, 1, 0, 0, 12])), sa));
        assert!(is_body(body_err(sa, &prop(1, &[3, 0, 0, 8, 1, 0, 0, 12])), sa));
        assert!(is_body(body_err(sa, &prop(2, &[0, 0, 0, 8, 1, 0, 0, 12])), sa));
        assert!(is_body(body_err(sa, &prop(0, &[0, 0, 0, 8, 1, 0, 0, 12])), sa));
        // Attributes.
        assert!(is_body(body_err(sa, &prop(1, &[0, 0, 0, 11, 1, 0, 0, 12, 0x80, 14, 1])), sa));
        assert!(is_body(body_err(sa, &prop(1, &[0, 0, 0, 13, 1, 0, 0, 12, 0, 1, 0, 2, 9])), sa));
        let attrs: Vec<u8> = (0..=MAX_ATTRIBUTES).flat_map(|_| [0x80, 14, 0, 128]).collect();
        let mut t = vec![0, 0, 0, 8 + attrs.len() as u8, 1, 0, 0, 12];
        t.extend_from_slice(&attrs);
        assert_eq!(body_err(sa, &prop(1, &t)), Error::Limit("attributes"));
        // Traffic selectors.
        let tsi = payload::TSI;
        assert_eq!(body_err(tsi, &[65, 0, 0, 0]), Error::Limit("traffic selectors"));
        assert!(is_body(body_err(tsi, &[1, 0, 0, 0]), tsi));
        assert!(is_body(body_err(tsi, &[0, 0, 0, 0, 9, 0, 0, 4]), tsi));
        assert!(is_body(body_err(tsi, &[1, 0, 0, 0, 9, 0, 0]), tsi));
        assert!(is_body(body_err(tsi, &[1, 0, 0, 0, 9, 0, 0, 3]), tsi));
        assert!(is_body(body_err(tsi, &[1, 0, 0, 0, 9, 0, 0, 5]), tsi));
        assert!(is_body(body_err(tsi, &[1, 0, 0, 0, 7, 0, 0, 8, 0, 0, 0, 0]), tsi));
        assert_eq!(
            body_ok(tsi, &[1, 0, 0, 0, 9, 6, 0, 5, 1]),
            Body::TsInitiator(vec![TrafficSelector::Other { kind: 9, protocol: 6, data: vec![1] }])
        );
    }

    #[test]
    fn display() {
        for e in [
            Error::Short,
            Error::Version(0x10),
            Error::MessageLength(3),
            Error::Trailing,
            Error::PayloadLength(40),
            Error::Body { kind: 33, reason: "x" },
            Error::Limit("payloads"),
        ] {
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(notify::name(notify::COOKIE), Some("COOKIE"));
        assert_eq!(notify::name(2), None);
        assert!(notify::is_error(notify::NO_PROPOSAL_CHOSEN));
        assert!(!notify::is_error(notify::INITIAL_CONTACT));
    }

    fn every_body() -> Vec<Payload> {
        vec![
            Payload::new(Body::SecurityAssociation(vec![
                Proposal {
                    number: 1,
                    protocol: protocol::ESP,
                    spi: vec![1, 2, 3, 4],
                    transforms: vec![
                        Transform {
                            kind: transform::ENCR,
                            id: transform::ENCR_AES_GCM_16,
                            attributes: vec![
                                Attribute { kind: transform::KEY_LENGTH, value: AttributeValue::Short(128) },
                                Attribute { kind: 99, value: AttributeValue::Long(vec![5, 6, 7]) },
                            ],
                        },
                        Transform { kind: transform::ESN, id: transform::ESN_NO, attributes: vec![] },
                    ],
                },
                Proposal { number: 2, protocol: protocol::AH, spi: vec![9; 4], transforms: vec![] },
            ])),
            Payload::new(Body::KeyExchange(KeyExchange { group: 31, data: vec![3; 32] })),
            Payload::new(Body::IdInitiator(Identification { kind: id::FQDN, data: b"vpn.example".to_vec() })),
            Payload::new(Body::IdResponder(Identification { kind: id::IPV4_ADDR, data: vec![192, 0, 2, 1] })),
            Payload::new(Body::Nonce(vec![4; 16])),
            Payload::new(Body::Notify(Notify {
                protocol: protocol::ESP,
                spi: vec![1, 2, 3, 4],
                kind: notify::REKEY_SA,
                data: vec![],
            })),
            Payload::new(Body::Delete(Delete {
                protocol: protocol::ESP,
                spi_size: 4,
                spis: vec![vec![1; 4], vec![2; 4]],
            })),
            Payload::new(Body::Delete(Delete { protocol: protocol::IKE, spi_size: 0, spis: vec![] })),
            Payload::new(Body::VendorId(b"fictionet".to_vec())),
            Payload::new(Body::TsInitiator(vec![TrafficSelector::Ipv4 {
                protocol: 0,
                start_port: 0,
                end_port: 65535,
                start: Ipv4Addr::new(10, 0, 0, 0),
                end: Ipv4Addr::new(10, 0, 0, 255),
            }])),
            Payload::new(Body::TsResponder(vec![
                TrafficSelector::Ipv6 {
                    protocol: 6,
                    start_port: 443,
                    end_port: 443,
                    start: Ipv6Addr::LOCALHOST,
                    end: Ipv6Addr::LOCALHOST,
                },
                TrafficSelector::Other { kind: 9, protocol: 0, data: vec![1, 2] },
            ])),
            Payload { critical: true, body: Body::Other { kind: 200, data: vec![7] } },
            Payload::new(Body::Other { kind: payload::AUTH, data: vec![2, 0, 0, 0, 0xaa] }),
            Payload::new(Body::Encrypted(Encrypted { first_payload: payload::IDI, data: vec![0x55; 40] })),
        ]
    }

    #[test]
    fn every_body_round_trips() {
        let m = message(every_body());
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        assert_eq!(m.unsupported_critical(), Some(200));
        // Every prefix is short, and every cut chain is an error.
        for n in 0..bytes.len() {
            assert_eq!(Message::parse(&bytes[..n]), Err(Error::Short));
            let mut cut = bytes[..n.max(HEADER_LEN)].to_vec();
            let len = (cut.len() as u32).to_be_bytes();
            cut[24..28].copy_from_slice(&len);
            if cut.len() < bytes.len() {
                assert!(Message::parse(&cut).is_err(), "{n} bytes");
            }
        }
        // The chain on its own, as inside an SK payload.
        let bytes = m.to_bytes().unwrap();
        let first = bytes[16];
        let chain = &bytes[HEADER_LEN..];
        assert_eq!(first, payload::SA);
        assert_eq!(chain, &bytes[HEADER_LEN..]);
        assert_eq!(parse_payloads(first, chain), Ok(m.payloads));
        assert_eq!(parse_payloads(0, &[]), Ok(vec![]));
    }

    #[test]
    fn payload_chains_round_trip_and_refuse_a_different_first_type() {
        fn chain_bytes(first: u8, payloads: Vec<Payload>) -> Result<Vec<u8>, Error> {
            let bytes = message(payloads).to_bytes()?;
            if bytes[16] != first { return Err(Error::Unwritable); }
            Ok(bytes[HEADER_LEN..].to_vec())
        }
        let payloads = every_body();
        let chain = message(payloads.clone());
        let bytes = chain_bytes(payload::SA, payloads.clone()).unwrap();
        assert_eq!(parse_payloads(payload::SA, &bytes), Ok(chain.payloads.clone()));
        contract::check_wire_value(&chain);
        assert_eq!(chain_bytes(payload::NONCE, payloads.clone()), Err(Error::Unwritable));
        contract::check_wire_value(&message(payloads));
        contract::check_wire_value(&message(vec![]));
    }

    #[test]
    fn fragments() {
        let f = Payload::new(Body::EncryptedFragment(EncryptedFragment {
            first_payload: payload::IDI,
            number: 1,
            total: 3,
            data: vec![1, 2, 3],
        }));
        let m = message(vec![f.clone()]);
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes[HEADER_LEN..], [payload::IDI, 0, 0, 11, 0, 1, 0, 3, 1, 2, 3]);
        assert_eq!(Message::parse(&bytes), Ok(m));
    }

    /// RFC 7383 section 2.6: both counts nonzero, the number at most the
    /// total, and a next payload of 0 after the first fragment.
    #[test]
    fn fragment_fields_are_checked() {
        let skf = payload::SKF;
        let chain = |next: u8, number: u16, total: u16| {
            let mut c = vec![next, 0, 0, 9];
            c.extend_from_slice(&number.to_be_bytes());
            c.extend_from_slice(&total.to_be_bytes());
            c.push(0xaa);
            c
        };
        assert!(Message::parse(&raw(skf, &chain(payload::IDI, 1, 2))).is_ok());
        assert!(Message::parse(&raw(skf, &chain(0, 2, 2))).is_ok());
        for (next, number, total) in [(0, 0, 2), (0, 1, 0), (0, 3, 2), (payload::IDI, 2, 2)] {
            let e = Message::parse(&raw(skf, &chain(next, number, total))).unwrap_err();
            assert!(is_body(e, skf), "{next} {number} {total}");
        }
        // The writer refuses invalid fragment fields.
        let frag = |first_payload, number, total| {
            Payload::new(Body::EncryptedFragment(EncryptedFragment { first_payload, number, total, data: vec![1] }))
        };
        let nonce = Payload::new(Body::Nonce(vec![1; 16]));
        for bad in [frag(0, 0, 1), frag(0, 2, 1), frag(0, 1, 0), frag(payload::IDI, 2, 3)] {
            let m = message(vec![bad, nonce.clone()]);
            assert_eq!(m.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&m);
        }
    }

    #[test]
    fn writers_refuse_invalid_values() {
        let m = message(vec![
            Payload::new(Body::Other { kind: payload::SA, data: vec![1] }),
            Payload::new(Body::Other { kind: 0, data: vec![1] }),
            Payload::new(Body::Nonce(vec![1; 16])),
            Payload::new(Body::Encrypted(Encrypted { first_payload: 0, data: vec![] })),
            Payload::new(Body::Nonce(vec![2; 16])),
        ]);
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&m);
        // Delete SPIs of the wrong size, and selectors typed as Other.
        let m = message(vec![
            Payload::new(Body::Delete(Delete { protocol: 3, spi_size: 4, spis: vec![vec![1; 4], vec![1; 3]] })),
            Payload::new(Body::TsInitiator(vec![TrafficSelector::Other { kind: 7, protocol: 0, data: vec![0; 12] }])),
        ]);
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        for payload in &m.payloads {
            let one = message(vec![payload.clone()]);
            assert_eq!(one.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&one);
        }
        // Reserved flag bits and high minor-version bits.
        let mut m = message(vec![]);
        m.flags = 0xff;
        m.minor_version = 0xf3;
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&m);
    }

    #[test]
    fn writers_refuse_oversized_values() {
        let huge = vec![0xab; 100_000];
        let m = message(vec![Payload::new(Body::Nonce(huge.clone())), Payload::new(Body::VendorId(huge.clone()))]);
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&m);
        // A long chain of every kind of oversized body.
        // Each attribute value is too long on its own, and the counts are
        // past the limits.
        let big = vec![0xcd; 70_000];
        let mut attributes = vec![Attribute { kind: 0xffff, value: AttributeValue::Long(big) }];
        attributes.extend(vec![Attribute { kind: 1, value: AttributeValue::Long(vec![1; 3000]) }; 30]);
        let t = Transform { kind: 1, id: 12, attributes };
        let p = Proposal { number: 1, protocol: 3, spi: vec![1; 300], transforms: vec![t; 100] };
        let bodies = vec![
            Body::SecurityAssociation(vec![p; 3]),
            Body::SecurityAssociation(vec![Proposal { number: 1, protocol: 1, spi: vec![], transforms: vec![] }; 100]),
            Body::KeyExchange(KeyExchange { group: 1, data: huge.clone() }),
            Body::IdInitiator(Identification { kind: 2, data: huge.clone() }),
            Body::Notify(Notify { protocol: 3, spi: vec![1; 300], kind: 1, data: huge.clone() }),
            Body::Delete(Delete { protocol: 3, spi_size: 4, spis: vec![vec![1; 4]; 20_000] }),
            Body::Delete(Delete { protocol: 1, spi_size: 0, spis: vec![vec![]; 20_000] }),
            Body::TsInitiator(vec![TrafficSelector::Other { kind: 9, protocol: 0, data: huge.clone() }; 100]),
            Body::TsResponder(vec![
                TrafficSelector::Ipv4 {
                    protocol: 0,
                    start_port: 0,
                    end_port: 0,
                    start: Ipv4Addr::UNSPECIFIED,
                    end: Ipv4Addr::BROADCAST,
                };
                100
            ]),
            Body::EncryptedFragment(EncryptedFragment { first_payload: 0, number: 1, total: 1, data: huge.clone() }),
            Body::Encrypted(Encrypted { first_payload: 0, data: huge.clone() }),
        ];
        for b in &bodies {
            let m = message(vec![Payload::new(b.clone())]);
            assert_eq!(m.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&m);
            // Behind a full nonce, there is little room left.
            let m = message(vec![Payload::new(Body::Nonce(vec![0; MAX_BODY - 10])), Payload::new(b.clone())]);
            assert_eq!(m.to_bytes(), Err(Error::Unwritable));
        }
        // More payloads than allowed.
        let m = message(vec![Payload::new(Body::Nonce(vec![])); 500]);
        assert_eq!(m.to_bytes(), Err(Error::Unwritable));
    }

    /// A message can hold a chain a few bytes longer than one payload body.
    /// The chain on its own must still write back in full, and a longer
    /// chain is refused.
    #[test]
    fn longest_chain() {
        let a = Payload::new(Body::VendorId(vec![1; 40_000]));
        let b = Payload::new(Body::Nonce(vec![2; MAX_CHAIN - 8 - 40_000]));
        let m = message(vec![a, b]);
        let bytes = m.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back, m);
        let bytes = back.to_bytes().unwrap();
        let first = bytes[16];
        let chain = &bytes[HEADER_LEN..];
        assert_eq!(chain, &bytes[HEADER_LEN..]);
        assert_eq!(parse_payloads(first, chain), Ok(back.payloads));
        // One byte more than a message can hold.
        let long = vec![0; MAX_CHAIN + 1];
        assert_eq!(parse_payloads(payload::VENDOR_ID, &long), Err(Error::Limit("chain bytes")));
    }

    #[test]
    fn find_payload() {
        let m = message(every_body());
        assert_eq!(m.payload(payload::NONCE).map(|p| &p.body), Some(&Body::Nonce(vec![4; 16])));
        assert_eq!(m.payload(payload::AUTH).map(Payload::kind), Some(payload::AUTH));
        assert_eq!(m.payload(payload::EAP), None);
    }

    #[test]
    fn nat_t() {
        let m = message(every_body());
        let bytes = NatT::Ike(m.clone()).to_bytes().unwrap();
        assert_eq!(bytes[..4], NON_ESP_MARKER);
        assert_eq!(NatT::parse(&bytes), Ok(NatT::Ike(m)));
        assert_eq!(NatT::parse(&[0xff]), Ok(NatT::Keepalive));
        let esp = [0, 0, 1, 0, 0, 0, 0, 1, 0xaa];
        assert_eq!(NatT::parse(&esp), Ok(NatT::Esp(esp.to_vec())));
        assert_eq!(NatT::parse(&[]), Err(Error::Short));
        assert_eq!(NatT::parse(&[0, 0, 0]), Err(Error::Short));
        assert_eq!(NatT::parse(&[0, 0, 0, 0]), Err(Error::Short));
        let mut largest = vec![1; MAX_MESSAGE + NON_ESP_MARKER.len()];
        contract::check_wire::<NatT>(&largest);
        assert!(matches!(NatT::parse(&largest), Ok(NatT::Esp(_))));
        largest.push(1);
        assert_eq!(NatT::parse(&largest), Err(Error::Limit("datagram bytes")));
        contract::check_wire_value(&NatT::Esp(largest));
        for n in 0..bytes.len() {
            assert!(NatT::parse(&bytes[..n]).is_err() || bytes[..n] == [0xff]);
        }
    }

    #[test]
    fn response_and_critical() {
        let req = Message::parse(&sa_init_bytes()).unwrap();
        let resp = req.response(vec![]);
        assert_eq!(resp.flags, flags::RESPONSE);
        assert_eq!((resp.initiator_spi, resp.message_id, resp.exchange), (req.initiator_spi, 0, req.exchange));
        assert!(resp.is_response() && !resp.is_initiator());
        // A request from the original responder is answered by the
        // original initiator, which sets the initiator flag (RFC 7296
        // section 3.1).
        let mut req = message(vec![]);
        req.flags = 0;
        assert_eq!(req.response(vec![]).flags, flags::RESPONSE | flags::INITIATOR);
        // A known type marked critical is not unsupported.
        let m = message(vec![Payload { critical: true, body: Body::Other { kind: payload::CP, data: vec![] } }]);
        assert_eq!(m.unsupported_critical(), None);
        let m = message(vec![Payload { critical: false, body: Body::Other { kind: 100, data: vec![] } }]);
        assert_eq!(m.unsupported_critical(), None);
    }

    fn check_chain(first: u8, data: &[u8]) {
        if let Ok(payloads) = parse_payloads(first, data) {
            let value = message(payloads.clone());
            contract::check_wire_value(&value);
            let bytes = value.to_bytes().unwrap();
            assert_eq!(bytes[16], first);
            assert_eq!(parse_payloads(first, &bytes[HEADER_LEN..]), Ok(payloads));
        }
    }

    /// What the fuzz target checks: whatever reads, writes and reads back
    /// the same, and every prefix and chain reader runs without a panic.
    fn check(data: &[u8]) {
        contract::check_wire::<Header>(data);
        contract::check_wire::<Message>(data);
        contract::check_wire::<NatT>(data);
        check_chain(0, data);
        check_chain(33, data);
        check_chain(40, data);
        check_chain(46, data);

        if let Ok(m) = Message::parse(data) {
            let bytes = m.to_bytes().unwrap();
            assert!(bytes.len() <= data.len());
            assert_eq!(Message::parse(&bytes).as_ref(), Ok(&m));
            for n in 0..bytes.len() {
                assert_eq!(Message::parse(&bytes[..n]), Err(Error::Short));
            }
            let bytes = m.to_bytes().unwrap();
        let first = bytes[16];
        let chain = &bytes[HEADER_LEN..];
            assert_eq!(parse_payloads(first, chain).as_ref(), Ok(&m.payloads));
        }
        if let Ok(NatT::Ike(m)) = NatT::parse(data) {
            assert_eq!(NatT::parse(&NatT::Ike(m.clone()).to_bytes().unwrap()), Ok(NatT::Ike(m)));
        }
        let _ = Header::parse(data);
        if let Some((&first, rest)) = data.split_first()
            && let Ok(p) = parse_payloads(first, rest)
        {
            let bytes = message(p.clone()).to_bytes().unwrap();
            assert_eq!(parse_payloads(bytes[16], &bytes[HEADER_LEN..]), Ok(p));
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut s = Lcg::new(0x1e2f);
        let seeds = [sa_init_bytes(), message(every_body()).to_bytes().unwrap()];
        let mut parsed = 0;
        for i in 0..6000 {
            let mut data = seeds[i % 2].clone();
            match i % 3 {
                // Flip a few bytes past the header's length.
                0 => {
                    let mut chain = data.split_off(HEADER_LEN);
                    for _ in 0..1 + s.index(4) { mutate(&mut s, &mut chain); }
                    data.extend(chain);
                    let len = (data.len() as u32).to_be_bytes();
                    data[24..28].copy_from_slice(&len);
                }
                // Cut it and fix the length.
                1 => {
                    let n =
                        HEADER_LEN + s.index(data.len() - HEADER_LEN);
                    data.truncate(n);
                    let len = (n as u32).to_be_bytes();
                    data[24..28].copy_from_slice(&len);
                }
                // Random bytes behind a valid header.
                _ => {
                    let n = usize::from(s.next() as u8) + usize::from(s.next() as u8);
                    data.truncate(HEADER_LEN);
                    data[16] = [33, 34, 40, 41, 42, 44, 46, 53, 0, 99][s.index(10)];
                    data.extend((0..n).map(|_| s.next() as u8));
                    let len = (data.len() as u32).to_be_bytes();
                    data[24..28].copy_from_slice(&len);
                }
            }
            if Message::parse(&data).is_ok() {
                parsed += 1;
            }
            check(&data);
            // The same bytes one at a time: each prefix on its own.
            for n in 0..data.len().min(64) {
                let _ = Message::parse(&data[..n]);
                let _ = NatT::parse(&data[..n]);
            }
        }
        assert!(parsed > 100, "only {parsed} parsed");
        // Plain random buffers.
        for _ in 0..4000 {
            let n = usize::from(s.next() as u8);
            let mut data = vec![0; n];
            s.fill(&mut data);
            check(&data);
        }
    }
}
