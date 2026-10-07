//! Diameter: reading and writing messages and AVPs, with no I/O.
//!
//! Diameter is the authentication, authorization and accounting protocol
//! of mobile and carrier networks. An MME asks an HSS whether a subscriber
//! may attach, and a gateway asks a charging server how much credit is
//! left. Each such question is a Diameter request, and each has an answer.
//! Two peers hold a TCP or SCTP connection, usually on port 3868. They open
//! it with a Capabilities-Exchange and keep it alive with Device-Watchdog
//! messages. This module follows RFC 6733.
//!
//! A message is a 20-byte header and a list of AVPs (attribute-value
//! pairs). The header names the command, the application, and two
//! identifiers that tie an answer to its request. Each AVP has a code,
//! flags, an optional vendor ID and data, padded to a multiple of 4 bytes.
//! The data's format (an integer, a string, an address, a list of more
//! AVPs) is not on the wire. It comes from a dictionary, so [`Avp`] keeps
//! the raw bytes and [`Avp::value`] reads them in the [`Format`] the caller
//! names. [`base_format`] is the dictionary of RFC 6733's own AVPs, and
//! [`check`] reads every AVP of a message against a dictionary, grouped
//! AVPs included, down to [`MAX_DEPTH`] levels.
//!
//! A world that plays a Diameter server pushes connection bytes into a
//! [`Stream<Messages>`](fictionet::stdlib::codec::Stream), gets [`Message`]s back,
//! and writes each answer's bytes to the connection. Which applications,
//! subscribers and sessions exist is up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Each [`FrameError`] names the Result-Code a real server answers it
//! with.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::diameter::{avp, command, result, Avp, Identity, Message, Messages, Value};
//!
//! /// Answers a Device-Watchdog-Request, as the HSS of a pretend network.
//! fn answer(request: &Message, host: &Identity, realm: &Identity) -> Option<Message> {
//!     if !request.request || request.command != command::DEVICE_WATCHDOG {
//!         return None;
//!     }
//!     let mut reply = request.answer();
//!     reply.avps.push(Avp::new(avp::RESULT_CODE, &Value::Unsigned32(result::SUCCESS)).unwrap());
//!     reply.avps.push(Avp::new(avp::ORIGIN_HOST, &Value::DiameterIdentity(host.clone())).unwrap());
//!     reply.avps.push(Avp::new(avp::ORIGIN_REALM, &Value::DiameterIdentity(realm.clone())).unwrap());
//!     Some(reply)
//! }
//!
//! let host = Identity::new("hss.example.net").unwrap();
//! let realm = Identity::new("example.net").unwrap();
//!
//! // A peer's watchdog request: hop-by-hop 7, end-to-end 9.
//! let mut dwr = Message::request(command::DEVICE_WATCHDOG, 0, 7, 9);
//! let peer = Identity::new("mme.example.net").unwrap();
//! dwr.avps.push(Avp::new(avp::ORIGIN_HOST, &Value::DiameterIdentity(peer)).unwrap());
//! dwr.avps.push(Avp::new(avp::ORIGIN_REALM, &Value::DiameterIdentity(realm.clone())).unwrap());
//! let bytes = dwr.to_bytes().unwrap();
//! // The header, then AVPs of 8 + 15 and 8 + 11 bytes, padded to 24 and 20.
//! assert_eq!(bytes.len(), 20 + 24 + 20);
//!
//! let mut decoder = Stream::new(Messages::new());
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! let got = decoder.next().unwrap().unwrap().unwrap();
//! assert_eq!(got, dwr);
//! let reply = answer(&got, &host, &realm).unwrap();
//! let back = Message::parse(&reply.to_bytes().unwrap()).unwrap();
//! assert!(!back.request);
//! assert_eq!((back.hop_by_hop, back.end_to_end), (7, 9));
//! assert_eq!(back.avp(avp::RESULT_CODE).and_then(Avp::as_u32), Some(result::SUCCESS));
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The port Diameter peers listen on, over TCP or SCTP.
pub const PORT: u16 = 3868;
/// The port Diameter peers listen on with TLS or DTLS.
pub const TLS_PORT: u16 = 5658;
/// The protocol version in every message header.
pub const VERSION: u8 = 1;
/// The length of a message header.
pub const HEADER_LEN: usize = 20;
/// The length of an AVP header without a vendor ID.
pub const AVP_HEADER_LEN: usize = 8;
/// The length of an AVP header with a vendor ID.
pub const VENDOR_AVP_HEADER_LEN: usize = 12;
/// The longest message: the largest multiple of 4 the 24-bit length field
/// can hold.
pub const MAX_MESSAGE: usize = 0x00ff_fffc;
/// The largest message accepted by [`Messages::new`].
pub const DEFAULT_LIMIT: usize = 65_536;
/// The most data one AVP with a vendor ID can carry in a message. One
/// without a vendor ID can carry 4 bytes more. Writers refuse data that
/// exceeds the applicable limit.
pub const MAX_AVP_DATA: usize = MAX_MESSAGE - HEADER_LEN - VENDOR_AVP_HEADER_LEN;
/// The most AVPs in one list: a message's, or one grouped AVP's.
pub const MAX_AVPS: usize = 4096;
/// The most levels of grouped AVPs [`check`] reads into.
pub const MAX_DEPTH: usize = 8;
/// The longest [`Identity`]: the longest DNS name, written as text.
pub const MAX_IDENTITY: usize = 253;
/// The longest label, the part of an [`Identity`] between dots.
pub const MAX_LABEL: usize = 63;

/// Bits of the command flags in the message header.
pub mod flags {
    /// The message is a request. Clear in an answer.
    pub const REQUEST: u8 = 0x80;
    /// The message may be proxied, relayed or redirected.
    pub const PROXIABLE: u8 = 0x40;
    /// The answer reports a protocol error. Never set in a request.
    pub const ERROR: u8 = 0x20;
    /// The request may be a retransmission.
    pub const RETRANSMIT: u8 = 0x10;
}

/// Bits of the flags in an AVP header.
pub mod avp_flags {
    /// A vendor ID follows the length.
    pub const VENDOR: u8 = 0x80;
    /// The receiver must understand the AVP or reject the message.
    pub const MANDATORY: u8 = 0x40;
    /// Reserved for end-to-end security. RFC 6733 deprecates it.
    pub const PROTECTED: u8 = 0x20;
}

/// The command codes of the base protocol. Each names a request and its
/// answer, told apart by the request flag.
pub mod command {
    /// Capabilities-Exchange-Request and Answer (CER and CEA).
    pub const CAPABILITIES_EXCHANGE: u32 = 257;
    /// Re-Auth-Request and Answer (RAR and RAA).
    pub const RE_AUTH: u32 = 258;
    /// Accounting-Request and Answer (ACR and ACA).
    pub const ACCOUNTING: u32 = 271;
    /// Abort-Session-Request and Answer (ASR and ASA).
    pub const ABORT_SESSION: u32 = 274;
    /// Session-Termination-Request and Answer (STR and STA).
    pub const SESSION_TERMINATION: u32 = 275;
    /// Device-Watchdog-Request and Answer (DWR and DWA).
    pub const DEVICE_WATCHDOG: u32 = 280;
    /// Disconnect-Peer-Request and Answer (DPR and DPA).
    pub const DISCONNECT_PEER: u32 = 282;
}

/// Application IDs with a meaning of their own.
pub mod application {
    /// The base protocol's own messages, such as CER and DWR.
    pub const COMMON: u32 = 0;
    /// Base accounting.
    pub const BASE_ACCOUNTING: u32 = 3;
    /// A relay agent: it forwards every application.
    pub const RELAY: u32 = 0xffff_ffff;
}

/// The codes of the base protocol's AVPs (RFC 6733, section 4.5).
/// The function `base_format` gives each one's format.
pub mod avp {
    /// The USER-NAME AVP code.
    pub const USER_NAME: u32 = 1;
    /// The CLASS AVP code.
    pub const CLASS: u32 = 25;
    /// The SESSION-TIMEOUT AVP code.
    pub const SESSION_TIMEOUT: u32 = 27;
    /// The PROXY-STATE AVP code.
    pub const PROXY_STATE: u32 = 33;
    /// The ACCT-SESSION-ID AVP code.
    pub const ACCT_SESSION_ID: u32 = 44;
    /// The ACCT-MULTI-SESSION-ID AVP code.
    pub const ACCT_MULTI_SESSION_ID: u32 = 50;
    /// The EVENT-TIMESTAMP AVP code.
    pub const EVENT_TIMESTAMP: u32 = 55;
    /// The ACCT-INTERIM-INTERVAL AVP code.
    pub const ACCT_INTERIM_INTERVAL: u32 = 85;
    /// The HOST-IP-ADDRESS AVP code.
    pub const HOST_IP_ADDRESS: u32 = 257;
    /// The AUTH-APPLICATION-ID AVP code.
    pub const AUTH_APPLICATION_ID: u32 = 258;
    /// The ACCT-APPLICATION-ID AVP code.
    pub const ACCT_APPLICATION_ID: u32 = 259;
    /// The VENDOR-SPECIFIC-APPLICATION-ID AVP code.
    pub const VENDOR_SPECIFIC_APPLICATION_ID: u32 = 260;
    /// The REDIRECT-HOST-USAGE AVP code.
    pub const REDIRECT_HOST_USAGE: u32 = 261;
    /// The REDIRECT-MAX-CACHE-TIME AVP code.
    pub const REDIRECT_MAX_CACHE_TIME: u32 = 262;
    /// The SESSION-ID AVP code.
    pub const SESSION_ID: u32 = 263;
    /// The ORIGIN-HOST AVP code.
    pub const ORIGIN_HOST: u32 = 264;
    /// The SUPPORTED-VENDOR-ID AVP code.
    pub const SUPPORTED_VENDOR_ID: u32 = 265;
    /// The VENDOR-ID AVP code.
    pub const VENDOR_ID: u32 = 266;
    /// The FIRMWARE-REVISION AVP code.
    pub const FIRMWARE_REVISION: u32 = 267;
    /// The RESULT-CODE AVP code.
    pub const RESULT_CODE: u32 = 268;
    /// The PRODUCT-NAME AVP code.
    pub const PRODUCT_NAME: u32 = 269;
    /// The SESSION-BINDING AVP code.
    pub const SESSION_BINDING: u32 = 270;
    /// The SESSION-SERVER-FAILOVER AVP code.
    pub const SESSION_SERVER_FAILOVER: u32 = 271;
    /// The MULTI-ROUND-TIME-OUT AVP code.
    pub const MULTI_ROUND_TIME_OUT: u32 = 272;
    /// The DISCONNECT-CAUSE AVP code.
    pub const DISCONNECT_CAUSE: u32 = 273;
    /// The AUTH-REQUEST-TYPE AVP code.
    pub const AUTH_REQUEST_TYPE: u32 = 274;
    /// The AUTH-GRACE-PERIOD AVP code.
    pub const AUTH_GRACE_PERIOD: u32 = 276;
    /// The AUTH-SESSION-STATE AVP code.
    pub const AUTH_SESSION_STATE: u32 = 277;
    /// The ORIGIN-STATE-ID AVP code.
    pub const ORIGIN_STATE_ID: u32 = 278;
    /// The FAILED-AVP AVP code.
    pub const FAILED_AVP: u32 = 279;
    /// The PROXY-HOST AVP code.
    pub const PROXY_HOST: u32 = 280;
    /// The ERROR-MESSAGE AVP code.
    pub const ERROR_MESSAGE: u32 = 281;
    /// The ROUTE-RECORD AVP code.
    pub const ROUTE_RECORD: u32 = 282;
    /// The DESTINATION-REALM AVP code.
    pub const DESTINATION_REALM: u32 = 283;
    /// The PROXY-INFO AVP code.
    pub const PROXY_INFO: u32 = 284;
    /// The RE-AUTH-REQUEST-TYPE AVP code.
    pub const RE_AUTH_REQUEST_TYPE: u32 = 285;
    /// The ACCOUNTING-SUB-SESSION-ID AVP code.
    pub const ACCOUNTING_SUB_SESSION_ID: u32 = 287;
    /// The AUTHORIZATION-LIFETIME AVP code.
    pub const AUTHORIZATION_LIFETIME: u32 = 291;
    /// The REDIRECT-HOST AVP code.
    pub const REDIRECT_HOST: u32 = 292;
    /// The DESTINATION-HOST AVP code.
    pub const DESTINATION_HOST: u32 = 293;
    /// The ERROR-REPORTING-HOST AVP code.
    pub const ERROR_REPORTING_HOST: u32 = 294;
    /// The TERMINATION-CAUSE AVP code.
    pub const TERMINATION_CAUSE: u32 = 295;
    /// The ORIGIN-REALM AVP code.
    pub const ORIGIN_REALM: u32 = 296;
    /// The EXPERIMENTAL-RESULT AVP code.
    pub const EXPERIMENTAL_RESULT: u32 = 297;
    /// The EXPERIMENTAL-RESULT-CODE AVP code.
    pub const EXPERIMENTAL_RESULT_CODE: u32 = 298;
    /// The INBAND-SECURITY-ID AVP code.
    pub const INBAND_SECURITY_ID: u32 = 299;
    /// The ACCOUNTING-RECORD-TYPE AVP code.
    pub const ACCOUNTING_RECORD_TYPE: u32 = 480;
    /// The ACCOUNTING-REALTIME-REQUIRED AVP code.
    pub const ACCOUNTING_REALTIME_REQUIRED: u32 = 483;
    /// The ACCOUNTING-RECORD-NUMBER AVP code.
    pub const ACCOUNTING_RECORD_NUMBER: u32 = 485;
}

/// Values of the Result-Code AVP (RFC 6733, section 7.1). The thousands
/// digit is the class: 1 informational, 2 success, 3 protocol error, 4
/// transient failure, 5 permanent failure.
pub mod result {
    /// The MULTI-ROUND-AUTH Result-Code.
    pub const MULTI_ROUND_AUTH: u32 = 1001;
    /// The SUCCESS Result-Code.
    pub const SUCCESS: u32 = 2001;
    /// The LIMITED-SUCCESS Result-Code.
    pub const LIMITED_SUCCESS: u32 = 2002;
    /// The COMMAND-UNSUPPORTED Result-Code.
    pub const COMMAND_UNSUPPORTED: u32 = 3001;
    /// The UNABLE-TO-DELIVER Result-Code.
    pub const UNABLE_TO_DELIVER: u32 = 3002;
    /// The REALM-NOT-SERVED Result-Code.
    pub const REALM_NOT_SERVED: u32 = 3003;
    /// The TOO-BUSY Result-Code.
    pub const TOO_BUSY: u32 = 3004;
    /// The LOOP-DETECTED Result-Code.
    pub const LOOP_DETECTED: u32 = 3005;
    /// The REDIRECT-INDICATION Result-Code.
    pub const REDIRECT_INDICATION: u32 = 3006;
    /// The APPLICATION-UNSUPPORTED Result-Code.
    pub const APPLICATION_UNSUPPORTED: u32 = 3007;
    /// The INVALID-HDR-BITS Result-Code.
    pub const INVALID_HDR_BITS: u32 = 3008;
    /// The INVALID-AVP-BITS Result-Code.
    pub const INVALID_AVP_BITS: u32 = 3009;
    /// The UNKNOWN-PEER Result-Code.
    pub const UNKNOWN_PEER: u32 = 3010;
    /// The AUTHENTICATION-REJECTED Result-Code.
    pub const AUTHENTICATION_REJECTED: u32 = 4001;
    /// The OUT-OF-SPACE Result-Code.
    pub const OUT_OF_SPACE: u32 = 4002;
    /// The ELECTION-LOST Result-Code.
    pub const ELECTION_LOST: u32 = 4003;
    /// The AVP-UNSUPPORTED Result-Code.
    pub const AVP_UNSUPPORTED: u32 = 5001;
    /// The UNKNOWN-SESSION-ID Result-Code.
    pub const UNKNOWN_SESSION_ID: u32 = 5002;
    /// The AUTHORIZATION-REJECTED Result-Code.
    pub const AUTHORIZATION_REJECTED: u32 = 5003;
    /// The INVALID-AVP-VALUE Result-Code.
    pub const INVALID_AVP_VALUE: u32 = 5004;
    /// The MISSING-AVP Result-Code.
    pub const MISSING_AVP: u32 = 5005;
    /// The RESOURCES-EXCEEDED Result-Code.
    pub const RESOURCES_EXCEEDED: u32 = 5006;
    /// The CONTRADICTING-AVPS Result-Code.
    pub const CONTRADICTING_AVPS: u32 = 5007;
    /// The AVP-NOT-ALLOWED Result-Code.
    pub const AVP_NOT_ALLOWED: u32 = 5008;
    /// The AVP-OCCURS-TOO-MANY-TIMES Result-Code.
    pub const AVP_OCCURS_TOO_MANY_TIMES: u32 = 5009;
    /// The NO-COMMON-APPLICATION Result-Code.
    pub const NO_COMMON_APPLICATION: u32 = 5010;
    /// The UNSUPPORTED-VERSION Result-Code.
    pub const UNSUPPORTED_VERSION: u32 = 5011;
    /// The UNABLE-TO-COMPLY Result-Code.
    pub const UNABLE_TO_COMPLY: u32 = 5012;
    /// The INVALID-BIT-IN-HEADER Result-Code.
    pub const INVALID_BIT_IN_HEADER: u32 = 5013;
    /// The INVALID-AVP-LENGTH Result-Code.
    pub const INVALID_AVP_LENGTH: u32 = 5014;
    /// The INVALID-MESSAGE-LENGTH Result-Code.
    pub const INVALID_MESSAGE_LENGTH: u32 = 5015;
    /// The INVALID-AVP-BIT-COMBO Result-Code.
    pub const INVALID_AVP_BIT_COMBO: u32 = 5016;
    /// The NO-COMMON-SECURITY Result-Code.
    pub const NO_COMMON_SECURITY: u32 = 5017;
}

/// Values of the Disconnect-Cause AVP, sent in a Disconnect-Peer-Request.
pub mod disconnect_cause {
    /// The peer is going down and will come back.
    pub const REBOOTING: i32 = 0;
    /// The peer has too many connections.
    pub const BUSY: i32 = 1;
    /// The peer has no use for this connection.
    pub const DO_NOT_WANT_TO_TALK_TO_YOU: i32 = 2;
}

/// The name of a base protocol command, such as "Device-Watchdog" for 280.
pub fn command_name(code: u32) -> Option<&'static str> {
    Some(match code {
        command::CAPABILITIES_EXCHANGE => "Capabilities-Exchange",
        command::RE_AUTH => "Re-Auth",
        command::ACCOUNTING => "Accounting",
        command::ABORT_SESSION => "Abort-Session",
        command::SESSION_TERMINATION => "Session-Termination",
        command::DEVICE_WATCHDOG => "Device-Watchdog",
        command::DISCONNECT_PEER => "Disconnect-Peer",
        _ => return None,
    })
}

/// Why bytes are not a Diameter message, or an AVP is not what its
/// dictionary says. It is the [`Decode::Error`] of [`Messages`], and the
/// reason inside an [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// The version byte was not 1.
    Version(u8),
    /// The message length was below the header's 20 bytes or not a
    /// multiple of 4.
    MessageLength(u32),
    /// The message length was above the reader's limit.
    TooBig(u32),
    /// An AVP's length was shorter than its header, ran past the bytes
    /// that hold it, left out the padding an AVP in a list needs, or did
    /// not match its format's fixed size. Also an AVP too large to fit in
    /// one message.
    AvpLength {
        /// The AVP's code, or 0 if fewer than 4 bytes were left.
        code: u32,
        /// The AVP's length field, or how many bytes were left if the
        /// header itself did not fit.
        length: u32,
    },
    /// One list held more than [`MAX_AVPS`] AVPs.
    TooManyAvps,
    /// Grouped AVPs nested deeper than [`MAX_DEPTH`]. It holds the code of
    /// the grouped AVP that went too deep.
    TooDeep(u32),
    /// An AVP's data was not a valid value of its format.
    Value {
        /// The AVP's code.
        code: u32,
        /// The format its data was read as.
        format: Format,
    },
    /// The header's flags were a combination RFC 6733 forbids: the E flag
    /// on a request, or the T flag on an answer. It holds the flags byte.
    /// [`Message::check_header`] reports it.
    HeaderBits(u8),
    /// An AVP's flags were a combination RFC 6733 forbids: the V flag with
    /// vendor ID 0. [`check`] reports it.
    AvpBits {
        /// The AVP's code.
        code: u32,
    },
    /// The input ends before a complete message.
    Incomplete,
    /// Bytes follow a complete wire value.
    Trailing {
        /// Number of trailing bytes.
        remaining: usize,
    },
    /// The value cannot be written without changing it.
    Unwritable,
}

impl FrameError {
    /// The Result-Code a server answers a read error with.
    /// [`FrameError::Unwritable`] is a write-side error and must never produce
    /// a reply. Its fallback code here is not a response to a peer.
    pub fn result_code(self) -> u32 {
        match self {
            FrameError::Incomplete | FrameError::Trailing { .. } | FrameError::Unwritable => result::INVALID_MESSAGE_LENGTH,
            FrameError::HeaderBits(_) => result::INVALID_HDR_BITS,
            FrameError::AvpBits { .. } => result::INVALID_AVP_BITS,
            FrameError::Version(_) => result::UNSUPPORTED_VERSION,
            FrameError::MessageLength(_) => result::INVALID_MESSAGE_LENGTH,
            FrameError::TooBig(_) | FrameError::TooManyAvps | FrameError::TooDeep(_) => result::RESOURCES_EXCEEDED,
            FrameError::AvpLength { .. } => result::INVALID_AVP_LENGTH,
            FrameError::Value { .. } => result::INVALID_AVP_VALUE,
        }
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Incomplete => f.write_str("incomplete Diameter message"),
            FrameError::Trailing { remaining } => write!(f, "{remaining} bytes after Diameter value"),
            FrameError::Unwritable => f.write_str("Diameter value cannot be written without changing it"),
            FrameError::Version(v) => write!(f, "Diameter version {v}, not 1"),
            FrameError::MessageLength(n) => write!(f, "message length {n}, below 20 or not a multiple of 4"),
            FrameError::TooBig(n) => write!(f, "message length {n}, above the limit"),
            FrameError::AvpLength { code, length } => write!(f, "AVP {code} has length {length}, which does not fit"),
            FrameError::TooManyAvps => write!(f, "more than {MAX_AVPS} AVPs in one list"),
            FrameError::TooDeep(code) => write!(f, "grouped AVP {code} nests deeper than {MAX_DEPTH} levels"),
            FrameError::Value { code, format } => write!(f, "AVP {code} is not a valid {}", format.name()),
            FrameError::HeaderBits(flags) => write!(f, "header flags {flags:#04x} are a forbidden combination"),
            FrameError::AvpBits { code } => write!(f, "AVP {code} has the vendor flag with vendor ID 0"),
        }
    }
}

impl std::error::Error for FrameError {}

/// One Diameter message: the header's fields and the AVPs it carries. The
/// version is always 1 and the length is worked out from the AVPs, so
/// neither is kept. The header's reserved flag bits are ignored on read
/// and written as 0, as RFC 6733 asks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    /// The R flag: a request, not an answer.
    pub request: bool,
    /// The P flag: agents may proxy, relay or redirect it.
    pub proxiable: bool,
    /// The E flag: an answer that reports a protocol error. RFC 6733
    /// forbids it in a request. Readers accept it there, and
    /// [`Message::check_header`] reports it.
    pub error: bool,
    /// The T flag: a request sent again after a link failed. RFC 6733
    /// forbids it in an answer, which [`Message::check_header`] reports.
    pub retransmit: bool,
    /// The command code. Only its low 24 bits go on the wire, so
    /// [`Wire::write`] refuses a larger one.
    pub command: u32,
    /// The application the message belongs to, 0 for the base protocol.
    pub application: u32,
    /// Chosen by the sender of a request, and copied into the answer, so
    /// it can match answers to requests on one connection.
    pub hop_by_hop: u32,
    /// Chosen by the request's origin and kept through every agent, so it
    /// can spot duplicates.
    pub end_to_end: u32,
    /// The AVPs, in order.
    pub avps: Vec<Avp>,
}

impl Message {
    /// A request with no AVPs and only the request flag set.
    pub fn request(command: u32, application: u32, hop_by_hop: u32, end_to_end: u32) -> Message {
        Message {
            request: true,
            proxiable: false,
            error: false,
            retransmit: false,
            command,
            application,
            hop_by_hop,
            end_to_end,
            avps: Vec::new(),
        }
    }

    /// An answer to this message: the same command, application,
    /// identifiers and proxiable flag, with the other flags clear. As RFC
    /// 6733 asks (section 6.2), it carries the request's first Session-Id
    /// and all its Proxy-Info AVPs, in order, and no others yet. Add the
    /// Result-Code, Origin-Host and Origin-Realm after them. A protocol
    /// error answer also sets [`Message::error`].
    pub fn answer(&self) -> Message {
        let base = |code| move |a: &&Avp| a.code == code && a.vendor.is_none();
        let session = self.avps.iter().find(base(avp::SESSION_ID));
        let proxies = self.avps.iter().filter(base(avp::PROXY_INFO));
        Message {
            request: false,
            proxiable: self.proxiable,
            error: false,
            retransmit: false,
            command: self.command,
            application: self.application,
            hop_by_hop: self.hop_by_hop,
            end_to_end: self.end_to_end,
            avps: session.into_iter().chain(proxies).cloned().collect(),
        }
    }

    /// The header's flags byte.
    pub fn flags(&self) -> u8 {
        let mut f = 0;
        for (on, bit) in [
            (self.request, flags::REQUEST),
            (self.proxiable, flags::PROXIABLE),
            (self.error, flags::ERROR),
            (self.retransmit, flags::RETRANSMIT),
        ] {
            if on {
                f |= bit;
            }
        }
        f
    }

    /// The first AVP with code `code` and no vendor ID.
    pub fn avp(&self, code: u32) -> Option<&Avp> {
        self.avps.iter().find(|a| a.code == code && a.vendor.is_none())
    }

    /// The first AVP with code `code` in vendor `vendor`'s space, such as
    /// 3GPP's (10415).
    pub fn vendor_avp(&self, code: u32, vendor: u32) -> Option<&Avp> {
        self.avps.iter().find(|a| a.code == code && a.vendor == Some(vendor))
    }

    // Validate framing before either parser interprets the AVPs.
    fn frame_length(b: &[u8], limit: usize) -> Result<Option<usize>, FrameError> {
        let limit = limit.clamp(HEADER_LEN, MAX_MESSAGE);
        let Some(&version) = b.first() else { return Ok(None) };
        if version != VERSION {
            return Err(FrameError::Version(version));
        }
        if b.len() < 4 {
            return Ok(None);
        }
        let length = be24(b, 1);
        let len = length as usize;
        if len < HEADER_LEN || !len.is_multiple_of(4) {
            return Err(FrameError::MessageLength(length));
        }
        if len > limit {
            return Err(FrameError::TooBig(length));
        }
        Ok(Some(len))
    }

    /// The header fields of the at least [`HEADER_LEN`] bytes `h`, with
    /// no AVPs.
    fn header(h: &[u8]) -> Message {
        let f = h[4];
        Message {
            request: f & flags::REQUEST != 0,
            proxiable: f & flags::PROXIABLE != 0,
            error: f & flags::ERROR != 0,
            retransmit: f & flags::RETRANSMIT != 0,
            command: be24(h, 5),
            application: be32(h, 8),
            hop_by_hop: be32(h, 12),
            end_to_end: be32(h, 16),
            avps: Vec::new(),
        }
    }

    /// Checks the header's flags against RFC 6733, section 3: the E flag
    /// is never set in a request, and the T flag never in an answer.
    /// Readers accept either, since the answer to them is
    /// [`result::INVALID_HDR_BITS`] and the connection stays up.
    pub fn check_header(&self) -> Result<(), FrameError> {
        if (self.request && self.error) || (!self.request && self.retransmit) {
            return Err(FrameError::HeaderBits(self.flags()));
        }
        Ok(())
    }
}

impl Wire for Message {
    type ParseError = FrameError;
    type WriteError = FrameError;

    /// Reads one message. Refuses invalid versions or lengths, truncated
    /// messages, malformed AVPs, excessive AVP counts, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        let length = Self::frame_length(bytes, MAX_MESSAGE)?.ok_or(FrameError::Incomplete)?;
        let body = bytes.get(HEADER_LEN..length).ok_or(FrameError::Incomplete)?;
        if bytes.len() != length {
            return Err(FrameError::Trailing { remaining: bytes.len() - length });
        }
        Ok(Self { avps: Avp::parse_list(body)?, ..Self::header(bytes) })
    }

    /// Appends one message. Refuses commands above 24 bits, more than
    /// [`MAX_AVPS`] AVPs, or messages exceeding [`MAX_MESSAGE`].
    /// Leaves `out` unchanged on error. Keeps forbidden flag combinations
    /// and vendor ID zero; use [`Message::check_header`] and [`check`] to
    /// validate those semantic rules.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        if self.command > 0x00ff_ffff {
            return Err(FrameError::Unwritable);
        }
        let length = HEADER_LEN + list_length(&self.avps, MAX_MESSAGE - HEADER_LEN)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.push(VERSION);
        bytes.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
        bytes.push(self.flags());
        bytes.extend_from_slice(&self.command.to_be_bytes()[1..]);
        bytes.extend_from_slice(&self.application.to_be_bytes());
        bytes.extend_from_slice(&self.hop_by_hop.to_be_bytes());
        bytes.extend_from_slice(&self.end_to_end.to_be_bytes());
        for avp in &self.avps {
            avp.write(&mut bytes)?;
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// A framed message whose AVPs could not be read.
///
/// [`Messages`] consumes the complete message and returns this as an item,
/// so the caller can answer using the header and then read the next message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The command, application, flags and identifiers, with no AVPs.
    pub header: Message,
    /// The AVP error that caused this message to be refused.
    pub error: FrameError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.error.fmt(f)
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Reads Diameter messages without retaining input.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for bounded buffering. The first four
/// bytes suffice to refuse a message above [`limit`](Self::limit). Partial
/// messages return [`Step::Need`], including at EOF. The driver reports
/// truncation and reports header errors once. Only [`FrameError::Version`],
/// [`FrameError::MessageLength`] and [`FrameError::TooBig`] end the stream. AVP errors
/// yield [`Error`] items with the header and no AVPs, then decoding
/// continues at the next message. Use that header to construct an answer.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire, finish, pump}, diameter::{command, Message, Messages}};
/// let message = Message::request(command::DEVICE_WATCHDOG, 0, 7, 9);
/// let bytes = Wire::to_bytes(&message)?;
/// let mut stream = Stream::new(Messages::new());
/// let mut messages = Vec::new();
/// for chunk in bytes.chunks(3) {
///     pump(&mut stream, chunk, |item| messages.push(item))?;
/// }
/// finish(&mut stream, |item| messages.push(item))?;
/// assert_eq!(messages, vec![Ok(message)]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Messages {
    limit: usize,
}

impl Messages {
    /// Creates a decoder with [`DEFAULT_LIMIT`] as its message limit.
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_LIMIT)
    }

    /// Sets the whole-message limit, clamped to [`HEADER_LEN`] through [`MAX_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.clamp(HEADER_LEN, MAX_MESSAGE) }
    }

    /// The largest accepted message, including its header.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for Messages {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Messages {
    type Item = Result<Message, Error>;
    type Error = FrameError;
    const NAME: &'static str = "Diameter";

    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, FrameError> {
        let Some(used) = Message::frame_length(input, self.limit)? else {
            return Ok(Step::Need);
        };
        let Some(body) = input.get(HEADER_LEN..used) else {
            return Ok(Step::Need);
        };
        let header = Message::header(input);
        let message = match Avp::parse_list(body) {
            Ok(avps) => Ok(Message { avps, ..header }),
            Err(error) => Err(Error { header, error }),
        };
        Ok(Step::Item(message, used))
    }
}

/// Checks the count and padded byte length before a list is copied.
fn list_length(avps: &[Avp], limit: usize) -> Result<usize, FrameError> {
    if avps.len() > MAX_AVPS {
        return Err(FrameError::Unwritable);
    }
    let mut length = 0usize;
    for avp in avps {
        let size = avp.header_len().checked_add(avp.data.len()).ok_or(FrameError::Unwritable)?;
        let size = size.checked_add(3).ok_or(FrameError::Unwritable)? & !3;
        length = length.checked_add(size).filter(|n| *n <= limit).ok_or(FrameError::Unwritable)?;
    }
    Ok(length)
}

/// One AVP: its header's fields and its data, unread. The data's format
/// comes from a dictionary; [`Avp::value`] reads it. The header's
/// reserved flag bits are ignored on read and written as 0.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Avp {
    /// The AVP code. With no vendor ID, codes are assigned by IANA.
    pub code: u32,
    /// The vendor ID, which puts the code in that vendor's space. Its
    /// presence sets the V flag. RFC 6733 forbids vendor ID 0, which
    /// [`check`] reports.
    pub vendor: Option<u32>,
    /// The M flag: the receiver must understand this AVP, or reject the
    /// message with [`result::AVP_UNSUPPORTED`].
    pub mandatory: bool,
    /// The P flag, kept for older peers.
    pub protected: bool,
    /// The data, without padding.
    pub data: Vec<u8>,
}

impl Wire for Avp {
    type ParseError = FrameError;
    type WriteError = FrameError;

    /// Reads one AVP. Refuses invalid lengths, incomplete headers or data,
    /// values too large for one message, and trailing bytes. A final AVP
    /// may omit padding; [`Avp::parse_list`] requires it.
    fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        let (avp, used) = Self::read_prefix(bytes)?;
        if used != bytes.len() {
            return Err(FrameError::Trailing { remaining: bytes.len() - used });
        }
        Ok(avp)
    }

    /// Appends one AVP and its four-byte alignment padding. Refuses data
    /// that cannot fit in one message. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let header = self.header_len();
        if self.data.len() > MAX_MESSAGE - HEADER_LEN - header {
            return Err(FrameError::Unwritable);
        }
        let data = &self.data;
        let mut f = 0;
        if self.vendor.is_some() {
            f |= avp_flags::VENDOR;
        }
        if self.mandatory {
            f |= avp_flags::MANDATORY;
        }
        if self.protected {
            f |= avp_flags::PROTECTED;
        }
        let len = header + data.len();
        out.extend_from_slice(&self.code.to_be_bytes());
        out.push(f);
        out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
        if let Some(v) = self.vendor {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out.extend_from_slice(data);
        out.resize(out.len() + (padded(len) - len), 0);
        Ok(())
    }
}

impl Avp {
    /// An AVP with code `code` holding `value`, with no vendor ID. The
    /// mandatory flag follows RFC 6733, section 4.5: clear for
    /// Product-Name, Firmware-Revision, Error-Message and
    /// Error-Reporting-Host, and set for every other code. Refuses values
    /// that exceed length or AVP count limits, text containing NUL, UDP
    /// Diameter URIs, and [`Address::Other`] with an IPv4 or IPv6 family.
    pub fn new(code: u32, value: &Value) -> Result<Avp, FrameError> {
        let mandatory = !matches!(
            code,
            avp::PRODUCT_NAME | avp::FIRMWARE_REVISION | avp::ERROR_MESSAGE | avp::ERROR_REPORTING_HOST
        );
        Ok(Avp { code, vendor: None, mandatory, protected: false, data: value.encode()? })
    }

    /// The length of this AVP's header: 12 with a vendor ID, 8 without.
    fn header_len(&self) -> usize {
        if self.vendor.is_some() { VENDOR_AVP_HEADER_LEN } else { AVP_HEADER_LEN }
    }

    /// Reads the AVP at the start of `b`. It returns the AVP and how many
    /// bytes it took, padding included. An AVP that ends `b` may leave out
    /// its padding, as some peers do; [`Avp::parse_list`] does not allow
    /// that.
    fn read_prefix(b: &[u8]) -> Result<(Avp, usize), FrameError> {
        if b.len() < AVP_HEADER_LEN {
            let code = if b.len() >= 4 { be32(b, 0) } else { 0 };
            return Err(FrameError::AvpLength { code, length: b.len() as u32 });
        }
        let code = be32(b, 0);
        let f = b[4];
        let length = be24(b, 5);
        let len = length as usize;
        let has_vendor = f & avp_flags::VENDOR != 0;
        let header = if has_vendor { VENDOR_AVP_HEADER_LEN } else { AVP_HEADER_LEN };
        if len < header || len > b.len() || padded(len) > MAX_MESSAGE - HEADER_LEN {
            return Err(FrameError::AvpLength { code, length });
        }
        let avp = Avp {
            code,
            vendor: if has_vendor { Some(be32(b, 8)) } else { None },
            mandatory: f & avp_flags::MANDATORY != 0,
            protected: f & avp_flags::PROTECTED != 0,
            data: b[header..len].to_vec(),
        };
        Ok((avp, padded(len).min(b.len())))
    }

    /// Reads a list of AVPs that fills `b`: a message's body, or a
    /// grouped AVP's data. Refuses more than [`MAX_AVPS`] entries or more
    /// than [`MAX_MESSAGE`] minus [`HEADER_LEN`] bytes. Each AVP, the last included, must have its
    /// padding, since RFC 6733 (section 4.2) counts it in the list.
    pub fn parse_list(b: &[u8]) -> Result<Vec<Avp>, FrameError> {
        if b.len() > MAX_MESSAGE - HEADER_LEN {
            return Err(FrameError::TooBig(b.len().min(u32::MAX as usize) as u32));
        }
        let mut avps = Vec::new();
        let mut at = 0;
        while let Some(rest) = b.get(at..).filter(|r| !r.is_empty()) {
            if avps.len() == MAX_AVPS {
                return Err(FrameError::TooManyAvps);
            }
            let (avp, used) = Avp::read_prefix(rest)?;
            let len = avp.header_len() + avp.data.len();
            if used < padded(len) {
                return Err(FrameError::AvpLength { code: avp.code, length: len as u32 });
            }
            avps.push(avp);
            at += used;
        }
        Ok(avps)
    }

    /// Reads the data as `format`. Data of the wrong size for a
    /// fixed-size format, such as 3 bytes for an Unsigned32, is an
    /// [`FrameError::AvpLength`], as RFC 6733 (section 7.1.5) answers it.
    pub fn value(&self, format: Format) -> Result<Value, FrameError> {
        let bad = FrameError::Value { code: self.code, format };
        let d = &self.data[..];
        let length = (self.header_len() + d.len()).min(u32::MAX as usize) as u32;
        let size = FrameError::AvpLength { code: self.code, length };
        Ok(match format {
            Format::OctetString => Value::OctetString(d.to_vec()),
            Format::Integer32 => Value::Integer32(i32::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Integer64 => Value::Integer64(i64::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Unsigned32 => Value::Unsigned32(u32::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Unsigned64 => Value::Unsigned64(u64::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Float32 => Value::Float32(f32::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Float64 => Value::Float64(f64::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Enumerated => Value::Enumerated(i32::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Time => Value::Time(u32::from_be_bytes(d.try_into().map_err(|_| size)?)),
            Format::Grouped => Value::Grouped(Avp::parse_list(d)?),
            Format::Address => Value::Address(Address::parse(d).map_err(|_| bad)?),
            Format::Utf8String => {
                // RFC 6733 allows code points from 1 up, so no NUL.
                if d.contains(&0) {
                    return Err(bad);
                }
                Value::Utf8String(String::from_utf8(d.to_vec()).map_err(|_| bad)?)
            }
            Format::DiameterIdentity => {
                let s = std::str::from_utf8(d).map_err(|_| bad)?;
                Value::DiameterIdentity(Identity::new(s).ok_or(bad)?)
            }
            Format::DiameterUri => {
                let s = std::str::from_utf8(d).map_err(|_| bad)?;
                Value::DiameterUri(Uri::parse(s).ok_or(bad)?)
            }
        })
    }

    /// The data as an Unsigned32, if it is 4 bytes long.
    pub fn as_u32(&self) -> Option<u32> {
        Some(u32::from_be_bytes(self.data[..].try_into().ok()?))
    }

    /// The data as an Integer32 or Enumerated, if it is 4 bytes long.
    pub fn as_i32(&self) -> Option<i32> {
        Some(i32::from_be_bytes(self.data[..].try_into().ok()?))
    }

    /// The data as an Unsigned64, if it is 8 bytes long.
    pub fn as_u64(&self) -> Option<u64> {
        Some(u64::from_be_bytes(self.data[..].try_into().ok()?))
    }

    /// The data as text, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }
}

/// The data formats of RFC 6733, section 4.2 and 4.3. Enumerated is
/// stored as an Integer32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// Any bytes.
    OctetString,
    /// A signed 32-bit integer.
    Integer32,
    /// A signed 64-bit integer.
    Integer64,
    /// An unsigned 32-bit integer.
    Unsigned32,
    /// An unsigned 64-bit integer.
    Unsigned64,
    /// An IEEE 754 single-precision number.
    Float32,
    /// An IEEE 754 double-precision number.
    Float64,
    /// A list of more AVPs.
    Grouped,
    /// An address family (2 bytes) and an address.
    Address,
    /// Seconds since 1900, as the first 4 bytes of an NTP timestamp.
    Time,
    /// UTF-8 text with no NUL character.
    Utf8String,
    /// The name of a Diameter node or realm.
    DiameterIdentity,
    /// An aaa:// or aaas:// URI naming a Diameter node.
    DiameterUri,
    /// A named value, stored as an Integer32.
    Enumerated,
}

impl Format {
    /// The format's name, as RFC 6733 spells it.
    pub fn name(self) -> &'static str {
        match self {
            Format::OctetString => "OctetString",
            Format::Integer32 => "Integer32",
            Format::Integer64 => "Integer64",
            Format::Unsigned32 => "Unsigned32",
            Format::Unsigned64 => "Unsigned64",
            Format::Float32 => "Float32",
            Format::Float64 => "Float64",
            Format::Grouped => "Grouped",
            Format::Address => "Address",
            Format::Time => "Time",
            Format::Utf8String => "UTF8String",
            Format::DiameterIdentity => "DiameterIdentity",
            Format::DiameterUri => "DiameterURI",
            Format::Enumerated => "Enumerated",
        }
    }
}

/// The format of a base protocol AVP with no vendor ID, or `None` for a
/// code RFC 6733 does not define.
pub fn base_format(code: u32) -> Option<Format> {
    use Format::*;
    Some(match code {
        avp::USER_NAME => Utf8String,
        avp::CLASS | avp::PROXY_STATE | avp::ACCT_SESSION_ID => OctetString,
        avp::SESSION_TIMEOUT
        | avp::ACCT_INTERIM_INTERVAL
        | avp::AUTH_APPLICATION_ID
        | avp::ACCT_APPLICATION_ID
        | avp::REDIRECT_MAX_CACHE_TIME
        | avp::SUPPORTED_VENDOR_ID
        | avp::VENDOR_ID
        | avp::FIRMWARE_REVISION
        | avp::RESULT_CODE
        | avp::SESSION_BINDING
        | avp::MULTI_ROUND_TIME_OUT
        | avp::AUTH_GRACE_PERIOD
        | avp::ORIGIN_STATE_ID
        | avp::AUTHORIZATION_LIFETIME
        | avp::EXPERIMENTAL_RESULT_CODE
        | avp::INBAND_SECURITY_ID
        | avp::ACCOUNTING_RECORD_NUMBER => Unsigned32,
        avp::ACCOUNTING_SUB_SESSION_ID => Unsigned64,
        avp::ACCT_MULTI_SESSION_ID | avp::SESSION_ID | avp::PRODUCT_NAME | avp::ERROR_MESSAGE => Utf8String,
        avp::EVENT_TIMESTAMP => Time,
        avp::HOST_IP_ADDRESS => Address,
        avp::VENDOR_SPECIFIC_APPLICATION_ID | avp::FAILED_AVP | avp::PROXY_INFO | avp::EXPERIMENTAL_RESULT => Grouped,
        avp::REDIRECT_HOST_USAGE
        | avp::SESSION_SERVER_FAILOVER
        | avp::DISCONNECT_CAUSE
        | avp::AUTH_REQUEST_TYPE
        | avp::AUTH_SESSION_STATE
        | avp::RE_AUTH_REQUEST_TYPE
        | avp::TERMINATION_CAUSE
        | avp::ACCOUNTING_RECORD_TYPE
        | avp::ACCOUNTING_REALTIME_REQUIRED => Enumerated,
        avp::ORIGIN_HOST
        | avp::PROXY_HOST
        | avp::ROUTE_RECORD
        | avp::DESTINATION_REALM
        | avp::DESTINATION_HOST
        | avp::ERROR_REPORTING_HOST
        | avp::ORIGIN_REALM => DiameterIdentity,
        avp::REDIRECT_HOST => DiameterUri,
        _ => return None,
    })
}

/// Reads every AVP in `avps` as the format `dictionary` gives for its code
/// and vendor ID, and reads into grouped AVPs down to [`MAX_DEPTH`]
/// levels. An AVP with vendor ID 0, which RFC 6733 (section 4.1.1)
/// forbids, is a [`FrameError::AvpBits`]. AVPs the dictionary does not know
/// are otherwise skipped. Whether one
/// with the mandatory flag is an error is the caller's call. The data of a
/// base Failed-AVP is not read at all: it holds the AVP that failed, which
/// RFC 6733 (section 7.5) lets be malformed. For the base
/// protocol alone, pass `|code, vendor| vendor.map_or_else(|| base_format(code), |_| None)`.
pub fn check(avps: &[Avp], dictionary: impl Fn(u32, Option<u32>) -> Option<Format>) -> Result<(), FrameError> {
    check_at(avps, &dictionary, 0)
}

/// [`check`] for a list `depth` grouped AVPs down. The depth is at most
/// [`MAX_DEPTH`], which bounds the recursion.
fn check_at(avps: &[Avp], dictionary: &dyn Fn(u32, Option<u32>) -> Option<Format>, depth: usize) -> Result<(), FrameError> {
    for a in avps {
        if a.vendor == Some(0) {
            return Err(FrameError::AvpBits { code: a.code });
        }
        if a.code == avp::FAILED_AVP && a.vendor.is_none() {
            continue;
        }
        match dictionary(a.code, a.vendor) {
            None => {}
            Some(Format::Grouped) => {
                if depth >= MAX_DEPTH {
                    return Err(FrameError::TooDeep(a.code));
                }
                check_at(&Avp::parse_list(&a.data)?, dictionary, depth + 1)?;
            }
            Some(format) => {
                a.value(format)?;
            }
        }
    }
    Ok(())
}

/// An AVP's data, read in its format.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// A value in the [`Format::OctetString`] format.
    OctetString(Vec<u8>),
    /// A value in the [`Format::Integer32`] format.
    Integer32(i32),
    /// A value in the [`Format::Integer64`] format.
    Integer64(i64),
    /// A value in the [`Format::Unsigned32`] format.
    Unsigned32(u32),
    /// A value in the [`Format::Unsigned64`] format.
    Unsigned64(u64),
    /// A value in the [`Format::Float32`] format.
    Float32(f32),
    /// A value in the [`Format::Float64`] format.
    Float64(f64),
    /// The AVPs inside, with their data unread.
    Grouped(Vec<Avp>),
    /// A value in the [`Format::Address`] format.
    Address(Address),
    /// Seconds since 1900; see [`time_to_unix`].
    Time(u32),
    /// A value in the [`Format::Utf8String`] format.
    Utf8String(String),
    /// A value in the [`Format::DiameterIdentity`] format.
    DiameterIdentity(Identity),
    /// A value in the [`Format::DiameterUri`] format.
    DiameterUri(Uri),
    /// A value in the [`Format::Enumerated`] format.
    Enumerated(i32),
}

impl Value {
    /// The format the value is in.
    pub fn format(&self) -> Format {
        match self {
            Value::OctetString(_) => Format::OctetString,
            Value::Integer32(_) => Format::Integer32,
            Value::Integer64(_) => Format::Integer64,
            Value::Unsigned32(_) => Format::Unsigned32,
            Value::Unsigned64(_) => Format::Unsigned64,
            Value::Float32(_) => Format::Float32,
            Value::Float64(_) => Format::Float64,
            Value::Grouped(_) => Format::Grouped,
            Value::Address(_) => Format::Address,
            Value::Time(_) => Format::Time,
            Value::Utf8String(_) => Format::Utf8String,
            Value::DiameterIdentity(_) => Format::DiameterIdentity,
            Value::DiameterUri(_) => Format::DiameterUri,
            Value::Enumerated(_) => Format::Enumerated,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let limit = MAX_MESSAGE - HEADER_LEN - AVP_HEADER_LEN;
        Ok(match self {
            Value::OctetString(b) => {
                if b.len() > limit {
                    return Err(FrameError::Unwritable);
                }
                b.clone()
            }
            Value::Integer32(v) | Value::Enumerated(v) => v.to_be_bytes().to_vec(),
            Value::Integer64(v) => v.to_be_bytes().to_vec(),
            Value::Unsigned32(v) | Value::Time(v) => v.to_be_bytes().to_vec(),
            Value::Unsigned64(v) => v.to_be_bytes().to_vec(),
            Value::Float32(v) => v.to_be_bytes().to_vec(),
            Value::Float64(v) => v.to_be_bytes().to_vec(),
            Value::Grouped(avps) => {
                let length = list_length(avps, limit)?;
                let mut out = Vec::with_capacity(length);
                for avp in avps { avp.write(&mut out)?; }
                out
            }
            Value::Address(a) => a.to_bytes()?,
            Value::Utf8String(s) => {
                if s.len() > limit || s.contains('\0') {
                    return Err(FrameError::Unwritable);
                }
                s.as_bytes().to_vec()
            }
            Value::DiameterIdentity(id) => id.as_str().as_bytes().to_vec(),
            Value::DiameterUri(uri) => {
                if uri.udp_diameter() {
                    return Err(FrameError::Unwritable);
                }
                uri.to_string().into_bytes()
            }
        })
    }
}

/// An Address value: an IANA address family and the address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// Family 1, with 4 bytes.
    V4(Ipv4Addr),
    /// Family 2, with 16 bytes.
    V6(Ipv6Addr),
    /// Any other family. The reader never makes one with family 1 or 2.
    /// The writer refuses `Other` with family 1 or 2.
    Other {
        /// The address family number.
        family: u16,
        /// The address bytes.
        bytes: Vec<u8>,
    },
}

impl Wire for Address {
    type ParseError = FrameError;
    type WriteError = FrameError;

    /// Reads an address family and data. Refuses missing families, incorrect
    /// IPv4 or IPv6 lengths, and values over [`MAX_AVP_DATA`].
    fn parse(d: &[u8]) -> Result<Self, FrameError> {
        let bad = FrameError::Value { code: 0, format: Format::Address };
        if d.len() > MAX_AVP_DATA {
            return Err(bad);
        }
        let (family, rest) = d.split_first_chunk::<2>().ok_or(bad)?;
        let family = u16::from_be_bytes(*family);
        Ok(match (family, rest.len()) {
            (Address::IPV4, 4) => Address::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3])),
            (Address::IPV6, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rest);
                Address::V6(Ipv6Addr::from(a))
            }
            (Address::IPV4 | Address::IPV6, _) => return Err(bad),
            _ => Address::Other { family, bytes: rest.to_vec() },
        })
    }

    /// Appends the family and address. Refuses `Other` with family 1 or 2
    /// and values over [`MAX_AVP_DATA`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        match self {
            Address::V4(a) => {
                out.extend_from_slice(&Address::IPV4.to_be_bytes());
                out.extend_from_slice(&a.octets());
            }
            Address::V6(a) => {
                out.extend_from_slice(&Address::IPV6.to_be_bytes());
                out.extend_from_slice(&a.octets());
            }
            Address::Other { family, bytes } => {
                if matches!(*family, Address::IPV4 | Address::IPV6) || bytes.len() > MAX_AVP_DATA - 2 {
                    return Err(FrameError::Unwritable);
                }
                out.extend_from_slice(&family.to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }
        Ok(())
    }
}

impl Address {
    /// IANA's address family number for IPv4.
    pub const IPV4: u16 = 1;
    /// IANA's address family number for IPv6.
    pub const IPV6: u16 = 2;
}

/// Seconds from 1900, the NTP epoch, to 1970, the Unix epoch.
pub const NTP_TO_UNIX: i64 = 2_208_988_800;

/// The Unix time a Time value names. Time wraps in February 2036, so a
/// value with its top bit clear counts from then, as RFC 4330 describes.
/// That covers 1968 to 2104.
pub fn time_to_unix(t: u32) -> i64 {
    let since_1900 = if t & 0x8000_0000 != 0 { i64::from(t) } else { i64::from(t) + (1 << 32) };
    since_1900 - NTP_TO_UNIX
}

/// The Time value for a Unix time, or `None` outside 1968 to 2104.
pub fn time_from_unix(secs: i64) -> Option<u32> {
    let since_1900 = secs.checked_add(NTP_TO_UNIX)?;
    if (1 << 31..1 << 32).contains(&since_1900) {
        u32::try_from(since_1900).ok()
    } else if (1 << 32..(1 << 32) + (1 << 31)).contains(&since_1900) {
        u32::try_from(since_1900 - (1 << 32)).ok()
    } else {
        None
    }
}

/// A DiameterIdentity: the name of a node (an FQDN) or a realm. It holds
/// up to [`MAX_IDENTITY`] ASCII letters, digits, hyphens, dots and
/// underscores. Dots split it into labels of 1 to [`MAX_LABEL`]
/// characters, so it has no leading, trailing or double dot. Any valid
/// one can be written and read back.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity(String);

impl Identity {
    /// The identity `s`, if it is a valid one.
    pub fn new(s: &str) -> Option<Identity> {
        let ok = s.len() <= MAX_IDENTITY
            && s.split('.').all(|label| {
                (1..=MAX_LABEL).contains(&label.len())
                    && label.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            });
        ok.then(|| Identity(s.to_string()))
    }

    /// The identity as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether two identities name the same node or realm. DNS names do
    /// not depend on ASCII case, though `==` does.
    pub fn eq_ignore_case(&self, other: &Identity) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The transport a DiameterURI names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP, the default when the URI names none.
    Tcp,
    /// SCTP.
    Sctp,
    /// UDP, which RFC 6733 forbids for Diameter.
    Udp,
}

/// The AAA protocol a DiameterURI names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AaaProtocol {
    /// Diameter, the default when the URI names none.
    Diameter,
    /// RADIUS.
    Radius,
    /// TACACS+.
    TacacsPlus,
}

/// A DiameterURI, such as `aaa://host.example.com:6666;transport=tcp`.
/// Its parts come in this order: the scheme, the FQDN, then an optional
/// port, transport and protocol. Scheme and parameter names are read
/// without regard to case and written in lower case. RFC 6733 forbids UDP
/// with Diameter, the default protocol. The reader and the AVP writer
/// refuse that pair. Display still prints `transport=udp` for it, producing
/// text that [`Uri::parse`] refuses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Uri {
    /// The `aaas` scheme: the connection uses TLS or DTLS.
    pub secure: bool,
    /// The node's name.
    pub fqdn: Identity,
    /// The port, if given. See [`Uri::port_or_default`].
    pub port: Option<u16>,
    /// The `transport` parameter, if given.
    pub transport: Option<Transport>,
    /// The `protocol` parameter, if given.
    pub protocol: Option<AaaProtocol>,
}

impl Uri {
    /// Reads a DiameterURI, or `None` if `s` is not one.
    pub fn parse(s: &str) -> Option<Uri> {
        let (secure, rest) = if let Some(r) = strip_prefix_ci(s, "aaas://") {
            (true, r)
        } else {
            (false, strip_prefix_ci(s, "aaa://")?)
        };
        let end = rest.find([':', ';']).unwrap_or(rest.len());
        let fqdn = Identity::new(&rest[..end])?;
        let mut rest = &rest[end..];
        let mut port = None;
        if let Some(r) = rest.strip_prefix(':') {
            let e = r.find(';').unwrap_or(r.len());
            let digits = &r[..e];
            if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            port = Some(digits.parse::<u16>().ok()?);
            rest = &r[e..];
        }
        let mut transport = None;
        if let Some(r) = strip_prefix_ci(rest, ";transport=") {
            let e = r.find(';').unwrap_or(r.len());
            let t = &r[..e];
            transport = Some(if t.eq_ignore_ascii_case("tcp") {
                Transport::Tcp
            } else if t.eq_ignore_ascii_case("sctp") {
                Transport::Sctp
            } else if t.eq_ignore_ascii_case("udp") {
                Transport::Udp
            } else {
                return None;
            });
            rest = &r[e..];
        }
        let mut protocol = None;
        if let Some(r) = strip_prefix_ci(rest, ";protocol=") {
            protocol = Some(if r.eq_ignore_ascii_case("diameter") {
                AaaProtocol::Diameter
            } else if r.eq_ignore_ascii_case("radius") {
                AaaProtocol::Radius
            } else if r.eq_ignore_ascii_case("tacacs+") {
                AaaProtocol::TacacsPlus
            } else {
                return None;
            });
            rest = "";
        }
        let uri = Uri { secure, fqdn, port, transport, protocol };
        (rest.is_empty() && !uri.udp_diameter()).then_some(uri)
    }

    /// Whether the URI names UDP for Diameter, given or by default, which
    /// RFC 6733 (section 4.3.1) forbids.
    fn udp_diameter(&self) -> bool {
        self.transport == Some(Transport::Udp) && matches!(self.protocol, None | Some(AaaProtocol::Diameter))
    }

    /// The port, or the default when none is given: [`PORT`], or
    /// [`TLS_PORT`] for `aaas`.
    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(if self.secure { TLS_PORT } else { PORT })
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", if self.secure { "aaas" } else { "aaa" }, self.fqdn)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        if let Some(t) = self.transport {
            let t = match t {
                Transport::Tcp => "tcp",
                Transport::Sctp => "sctp",
                Transport::Udp => "udp",
            };
            write!(f, ";transport={t}")?;
        }
        if let Some(p) = self.protocol {
            let p = match p {
                AaaProtocol::Diameter => "diameter",
                AaaProtocol::Radius => "radius",
                AaaProtocol::TacacsPlus => "tacacs+",
            };
            write!(f, ";protocol={p}")?;
        }
        Ok(())
    }
}

/// `s` without `prefix`, matched without regard to ASCII case.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) { s.get(prefix.len()..) } else { None }
}

/// `len` rounded up to a multiple of 4. `len` is below 2^24 wherever it
/// is called, so this cannot overflow.
fn padded(len: usize) -> usize {
    (len + 3) & !3
}

fn be24(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([0, b[i], b[i + 1], b[i + 2]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream, contract,
        test_support::{decode_all, mutate},
    };

    fn id(s: &str) -> Identity {
        Identity::new(s).unwrap()
    }

    fn base(code: u32, vendor: Option<u32>) -> Option<Format> {
        if vendor.is_none() { base_format(code) } else { None }
    }

    /// A Device-Watchdog-Request built byte by byte from the layout in
    /// RFC 6733, sections 3 and 4.1.
    fn dwr_bytes() -> Vec<u8> {
        let mut b = vec![
            0x01, 0x00, 0x00, 0x40, // version 1, length 64
            0x80, 0x00, 0x01, 0x18, // R flag, command 280
            0x00, 0x00, 0x00, 0x00, // application 0
            0x12, 0x34, 0x56, 0x78, // hop-by-hop
            0x9a, 0xbc, 0xde, 0xf0, // end-to-end
            0x00, 0x00, 0x01, 0x08, 0x40, 0x00, 0x00, 0x17, // Origin-Host, M, length 23
        ];
        b.extend_from_slice(b"mme.example.net");
        b.push(0); // padding
        b.extend_from_slice(&[0x00, 0x00, 0x01, 0x28, 0x40, 0x00, 0x00, 0x13]); // Origin-Realm, length 19
        b.extend_from_slice(b"example.net");
        b.push(0);
        assert_eq!(b.len(), 64);
        b
    }

    fn dwr() -> Message {
        let mut m = Message::request(command::DEVICE_WATCHDOG, 0, 0x1234_5678, 0x9abc_def0);
        m.avps.push(Avp::new(avp::ORIGIN_HOST, &Value::DiameterIdentity(id("mme.example.net"))).unwrap());
        m.avps.push(Avp::new(avp::ORIGIN_REALM, &Value::DiameterIdentity(id("example.net"))).unwrap());
        m
    }

    #[test]
    fn header_and_avp_layout() {
        let bytes = dwr_bytes();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m, dwr());
        assert_eq!(m.to_bytes().unwrap(), bytes);
        assert_eq!(m.flags(), flags::REQUEST);
        assert_eq!(m.avp(avp::ORIGIN_HOST).and_then(Avp::as_str), Some("mme.example.net"));
        assert_eq!(command_name(m.command), Some("Device-Watchdog"));
        assert_eq!(command_name(9999), None);
        check(&m.avps, base).unwrap();
    }

    #[test]
    fn answer_keeps_identifiers() {
        let mut req = dwr();
        req.proxiable = true;
        req.retransmit = true;
        let a = req.answer();
        assert!(!a.request && a.proxiable && !a.retransmit && !a.error);
        assert_eq!((a.command, a.application, a.hop_by_hop, a.end_to_end), (280, 0, 0x1234_5678, 0x9abc_def0));
        let mut a = a;
        a.error = true;
        assert_eq!(a.to_bytes().unwrap()[4], flags::PROXIABLE | flags::ERROR);
    }

    #[test]
    fn reserved_bits_are_ignored() {
        let mut b = dwr_bytes();
        b[4] |= 0x0f;
        b[24] |= 0x1f; // the first AVP's reserved flags
        let m = Message::parse(&b).unwrap();
        assert_eq!(m, dwr());
        assert_eq!(m.to_bytes().unwrap(), dwr_bytes());
    }

    #[test]
    fn vendor_avp_layout() {
        // 3GPP (vendor 10415) AVP 1032 RAT-Type, V and M set, value 1004.
        let b = [0x00, 0x00, 0x04, 0x08, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28, 0xaf, 0, 0, 0x03, 0xec];
        let a = Avp::parse(&b).unwrap();
        assert_eq!(
            a,
            Avp { code: 1032, vendor: Some(10415), mandatory: true, protected: false, data: vec![0, 0, 3, 0xec] }
        );
        assert_eq!(a.value(Format::Enumerated), Ok(Value::Enumerated(1004)));
        assert_eq!(a.to_bytes().unwrap(), b);
        // The protected flag.
        let p = Avp { protected: true, mandatory: false, ..a };
        assert_eq!(p.to_bytes().unwrap()[4], avp_flags::VENDOR | avp_flags::PROTECTED);
        assert_eq!(Avp::parse(&p.to_bytes().unwrap()).unwrap(), p);
    }

    #[test]
    fn padding() {
        for n in 0..9 {
            let a = Avp { code: 7, vendor: None, mandatory: false, protected: false, data: vec![0xaa; n] };
            let b = a.to_bytes().unwrap();
            assert_eq!(b.len(), (8 + n).div_ceil(4) * 4);
            assert_eq!(u32::from_be_bytes([0, b[5], b[6], b[7]]) as usize, 8 + n);
            assert_eq!(Avp::parse(&b), Ok(a.clone()));
            // An AVP on its own may leave its padding out, one in a list
            // may not.
            assert_eq!(Avp::parse(&b[..8 + n]), Ok(a.clone()));
            let listed = if n % 4 == 0 { Ok(vec![a]) } else { Err(FrameError::AvpLength { code: 7, length: 8 + n as u32 }) };
            assert_eq!(Avp::parse_list(&b[..8 + n]), listed);
        }
    }

    #[test]
    fn data_formats() {
        let cases: Vec<(Value, Vec<u8>)> = vec![
            (Value::OctetString(vec![1, 2, 3]), vec![1, 2, 3]),
            (Value::Integer32(-2), vec![0xff, 0xff, 0xff, 0xfe]),
            (Value::Integer64(-1), vec![0xff; 8]),
            (Value::Unsigned32(2001), vec![0, 0, 0x07, 0xd1]),
            (Value::Unsigned64(1 << 40), vec![0, 0, 1, 0, 0, 0, 0, 0]),
            (Value::Float32(1.5), vec![0x3f, 0xc0, 0, 0]),
            (Value::Float64(-2.0), vec![0xc0, 0, 0, 0, 0, 0, 0, 0]),
            (Value::Address(Address::V4(Ipv4Addr::new(192, 0, 2, 1))), vec![0, 1, 192, 0, 2, 1]),
            (Value::Time(0xe0a3_b2c0), vec![0xe0, 0xa3, 0xb2, 0xc0]),
            (Value::Utf8String("héllo".into()), "héllo".as_bytes().to_vec()),
            (Value::DiameterIdentity(id("example.net")), b"example.net".to_vec()),
            (Value::Enumerated(2), vec![0, 0, 0, 2]),
            (
                Value::DiameterUri(Uri::parse("aaa://h.example.com:6666;transport=tcp").unwrap()),
                b"aaa://h.example.com:6666;transport=tcp".to_vec(),
            ),
        ];
        for (v, bytes) in cases {
            assert_eq!(Avp::new(1, &v).unwrap().data, bytes, "{v:?}");
            let a = Avp::new(1, &v).unwrap();
            assert_eq!(a.value(v.format()), Ok(v));
        }
        let v6 = Address::V6("2001:db8::1".parse().unwrap());
        let b = v6.to_bytes().unwrap();
        assert_eq!(&b[..2], &[0, 2]);
        assert_eq!(b.len(), 18);
        assert_eq!(Address::parse(&b), Ok(v6));
        // Grouped: an Experimental-Result holding a vendor and a code.
        let inner = vec![
            Avp::new(avp::VENDOR_ID, &Value::Unsigned32(10415)).unwrap(),
            Avp::new(avp::EXPERIMENTAL_RESULT_CODE, &Value::Unsigned32(5001)).unwrap(),
        ];
        let g = Avp::new(avp::EXPERIMENTAL_RESULT, &Value::Grouped(inner.clone())).unwrap();
        assert_eq!(g.data.len(), 24);
        assert_eq!(g.value(Format::Grouped), Ok(Value::Grouped(inner)));
        check(&[g], base).unwrap();
    }

    #[test]
    fn addresses_of_other_families() {
        assert!(Address::parse(&[0]).is_err());
        assert_eq!(Address::parse(&[0, 8, 9]), Ok(Address::Other { family: 8, bytes: vec![9] }));
        let other = Address::Other { family: 1, bytes: vec![10, 0, 0, 1] };
        assert_eq!(other.to_bytes(), Err(FrameError::Unwritable));
    }

    #[test]
    fn times() {
        // 2026-01-01T00:00:00Z.
        let unix = 1_767_225_600;
        let t = time_from_unix(unix).unwrap();
        assert_eq!(u64::from(t), 1_767_225_600 + 2_208_988_800);
        assert_eq!(time_to_unix(t), unix);
        // After the 2036 wrap, the top bit is clear.
        let late = (1i64 << 32) + 100 - NTP_TO_UNIX; // 2036 plus 100 s
        let t = time_from_unix(late).unwrap();
        assert_eq!(t, 100);
        assert_eq!(time_to_unix(t), late);
        assert_eq!(time_from_unix(i64::MAX), None);
        assert_eq!(time_from_unix(i64::MIN), None);
        assert_eq!(time_from_unix(-NTP_TO_UNIX), None); // 1900 is out of range
        for t in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            assert_eq!(time_from_unix(time_to_unix(t)), Some(t));
        }
    }

    #[test]
    fn uris() {
        // The examples in RFC 6733, section 4.3.1.
        for s in [
            "aaa://host.example.com;transport=tcp",
            "aaa://host.example.com:6666;transport=tcp",
            "aaa://host.example.com;protocol=diameter",
            "aaa://host.example.com:6666;protocol=diameter",
            "aaa://host.example.com:6666;transport=tcp;protocol=diameter",
            "aaa://host.example.com:1813;transport=udp;protocol=radius",
        ] {
            let u = Uri::parse(s).unwrap();
            assert_eq!(u.to_string(), s);
        }
        let u = Uri::parse("aaa://host.example.com:6666;transport=tcp;protocol=diameter").unwrap();
        assert_eq!(u.port, Some(6666));
        assert_eq!(u.transport, Some(Transport::Tcp));
        assert_eq!(u.protocol, Some(AaaProtocol::Diameter));
        let s = Uri::parse("AAAS://peer.example.net;Transport=SCTP;protocol=tacacs+").unwrap();
        assert!(s.secure);
        assert_eq!(s.port_or_default(), TLS_PORT);
        assert_eq!(s.to_string(), "aaas://peer.example.net;transport=sctp;protocol=tacacs+");
        assert_eq!(Uri::parse("aaa://a").unwrap().port_or_default(), PORT);
        for bad in [
            "",
            "aaa://",
            "http://host",
            "aaa://host:",
            "aaa://host:x1",
            "aaa://host:70000",
            "aaa://host;transport=quic",
            "aaa://host;protocol=ldap",
            "aaa://host;protocol=diameter;transport=tcp",
            "aaa://host;foo=bar",
            "aaa://ho st",
            "aaa://hé",
            "aaé://host",
        ] {
            assert_eq!(Uri::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn identities() {
        assert!(Identity::new("a").is_some());
        assert!(Identity::new(&"a".repeat(MAX_LABEL)).is_some());
        assert!(Identity::new(&"a".repeat(MAX_LABEL + 1)).is_none());
        assert!(Identity::new("").is_none());
        assert!(Identity::new("a b").is_none());
        assert!(Identity::new("a:1").is_none());
        let a =
            Avp { code: avp::ORIGIN_HOST, vendor: None, mandatory: true, protected: false, data: b"bad host".to_vec() };
        assert_eq!(
            a.value(Format::DiameterIdentity),
            Err(FrameError::Value { code: 264, format: Format::DiameterIdentity })
        );
        assert_eq!(check(&[a], base), Err(FrameError::Value { code: 264, format: Format::DiameterIdentity }));
    }

    #[test]
    fn value_errors() {
        let raw = |data: &[u8]| Avp { code: 9, vendor: None, mandatory: false, protected: false, data: data.to_vec() };
        // Fixed-size formats given the wrong size: a length error.
        for (format, bad) in [
            (Format::Integer32, &[0u8; 3][..]),
            (Format::Integer64, &[0; 7]),
            (Format::Unsigned32, &[0; 5]),
            (Format::Unsigned64, &[0; 9]),
            (Format::Float32, &[0; 2]),
            (Format::Float64, &[0; 4]),
            (Format::Time, &[]),
            (Format::Enumerated, &[1]),
        ] {
            let e = raw(bad).value(format).unwrap_err();
            assert_eq!(e, FrameError::AvpLength { code: 9, length: 8 + bad.len() as u32 });
            assert_eq!(e.result_code(), result::INVALID_AVP_LENGTH);
        }
        for (format, bad) in [
            (Format::Address, &[1u8][..]),
            (Format::Utf8String, &[0xff]),
            (Format::DiameterIdentity, &[]),
            (Format::DiameterIdentity, &[0xff]),
            (Format::DiameterUri, b"aaa:/x"),
            (Format::DiameterUri, &[0xff]),
        ] {
            let e = raw(bad).value(format).unwrap_err();
            assert_eq!(e, FrameError::Value { code: 9, format });
            assert_eq!(e.result_code(), result::INVALID_AVP_VALUE);
            assert!(e.to_string().contains(format.name()));
        }
        // A grouped AVP whose data is not AVPs.
        assert_eq!(raw(&[0, 0, 0, 5, 0]).value(Format::Grouped), Err(FrameError::AvpLength { code: 5, length: 5 }));
        assert_eq!(raw(&[0, 0]).value(Format::Grouped), Err(FrameError::AvpLength { code: 0, length: 2 }));
        assert_eq!(raw(&[]).value(Format::Grouped), Ok(Value::Grouped(vec![])));
        assert_eq!(raw(&[]).as_u32(), None);
        assert_eq!(raw(&[0, 0, 0, 0, 0, 0, 0, 1]).as_u64(), Some(1));
        assert_eq!(raw(&[0xff; 4]).as_i32(), Some(-1));
    }

    #[test]
    fn message_errors() {
        let ok = dwr_bytes();
        let with = |i: usize, v: u8| {
            let mut b = ok.clone();
            b[i] = v;
            b
        };
        assert_eq!(Message::parse(&[2]), Err(FrameError::Version(2)));
        assert_eq!(Message::parse(&with(0, 0)), Err(FrameError::Version(0)));
        assert_eq!(Message::parse(&[1, 0, 0, 16]), Err(FrameError::MessageLength(16)));
        assert_eq!(Message::parse(&[1, 0, 0, 22]), Err(FrameError::MessageLength(22)));
        assert_eq!(Messages::with_limit(64).decode(&[1, 0, 0, 0x44], false), Err(FrameError::TooBig(0x44)));
        assert_eq!(Messages::with_limit(64).decode(&ok, false), Ok(Step::Item(Ok(dwr()), 64)));
        // An AVP length shorter than its header.
        assert_eq!(Message::parse(&with(27, 7)), Err(FrameError::AvpLength { code: 264, length: 7 }));
        // A vendor flag on an AVP too short to hold the vendor ID.
        let mut b = ok.clone();
        b[24] = 0xc0;
        b[27] = 11;
        assert_eq!(Message::parse(&b), Err(FrameError::AvpLength { code: 264, length: 11 }));
        // An AVP that runs past the message.
        assert_eq!(Message::parse(&with(27, 0x30)), Err(FrameError::AvpLength { code: 264, length: 0x30 }));
        // A message length that cuts an AVP header short.
        let mut b = ok[..24].to_vec();
        b[3] = 24;
        assert_eq!(Message::parse(&b), Err(FrameError::AvpLength { code: 264, length: 4 }));
        // Result-Codes.
        assert_eq!(FrameError::Version(2).result_code(), result::UNSUPPORTED_VERSION);
        assert_eq!(FrameError::MessageLength(3).result_code(), result::INVALID_MESSAGE_LENGTH);
        assert_eq!(FrameError::AvpLength { code: 1, length: 1 }.result_code(), result::INVALID_AVP_LENGTH);
        assert_eq!(FrameError::TooBig(1).result_code(), result::RESOURCES_EXCEEDED);
        assert_eq!(FrameError::TooManyAvps.result_code(), result::RESOURCES_EXCEEDED);
        assert_eq!(FrameError::TooDeep(1).result_code(), result::RESOURCES_EXCEEDED);
        for e in [FrameError::Version(2), FrameError::MessageLength(3), FrameError::TooBig(1), FrameError::TooManyAvps, FrameError::TooDeep(1)] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn too_many_avps() {
        let one = Avp { code: 1, vendor: None, mandatory: false, protected: false, data: vec![] };
        let list: Vec<u8> = one.to_bytes().unwrap().repeat(MAX_AVPS);
        assert_eq!(Avp::parse_list(&list).unwrap().len(), MAX_AVPS);
        let more: Vec<u8> = one.to_bytes().unwrap().repeat(MAX_AVPS + 1);
        assert_eq!(Avp::parse_list(&more), Err(FrameError::TooManyAvps));
        let mut message = Message::request(1, 0, 0, 0);
        message.avps = vec![one.clone(); MAX_AVPS + 5];
        assert_eq!(message.to_bytes(), Err(FrameError::Unwritable));
        assert_eq!(Avp::new(1, &Value::Grouped(vec![one; MAX_AVPS + 5])), Err(FrameError::Unwritable));
    }

    #[test]
    fn depth_limit() {
        const NEST: u32 = 999;
        let dict = |code: u32, _: Option<u32>| if code == NEST { Some(Format::Grouped) } else { base_format(code) };
        let leaf = Avp::new(avp::RESULT_CODE, &Value::Unsigned32(2001)).unwrap();
        let mut a = leaf.clone();
        for _ in 0..MAX_DEPTH {
            a = Avp::new(NEST, &Value::Grouped(vec![a])).unwrap();
        }
        check(std::slice::from_ref(&a), dict).unwrap();
        let deeper = Avp::new(NEST, &Value::Grouped(vec![a.clone()])).unwrap();
        assert_eq!(check(&[deeper], dict), Err(FrameError::TooDeep(NEST)));
        // A bad value deep inside is found.
        let mut b = Avp { data: vec![1], ..leaf };
        for _ in 0..3 {
            b = Avp::new(NEST, &Value::Grouped(vec![b])).unwrap();
        }
        assert_eq!(check(&[b], dict), Err(FrameError::AvpLength { code: avp::RESULT_CODE, length: 9 }));
        // Unknown AVPs are skipped, whatever they hold.
        let unknown = Avp { code: 77, vendor: Some(1), mandatory: true, protected: false, data: vec![9] };
        check(&[unknown], dict).unwrap();
    }

    #[test]
    fn every_truncated_prefix() {
        let bytes = dwr_bytes();
        for n in 0..bytes.len() {
            assert_eq!(Message::parse(&bytes[..n]), Err(FrameError::Incomplete), "{n} bytes");
        }
        // AVPs cut short read as errors, never as a shorter AVP.
        let a = Avp { code: 5, vendor: Some(3), mandatory: true, protected: false, data: vec![1, 2, 3, 4, 5] };
        let b = a.to_bytes().unwrap();
        for n in 0..17 {
            assert!(Avp::parse(&b[..n]).is_err(), "{n} bytes");
        }
        for n in 17..=b.len() {
            assert_eq!(Avp::parse(&b[..n]).unwrap(), a);
        }
        // Each fixed-size value cut short is refused.
        for v in [Value::Integer64(5), Value::Unsigned64(5), Value::Float64(5.0), Value::Unsigned32(5)] {
            let full = Avp::new(1, &v).unwrap();
            for n in 0..full.data.len() {
                let cut = Avp { data: full.data[..n].to_vec(), ..full.clone() };
                assert!(cut.value(v.format()).is_err());
            }
        }
    }

    #[test]
    fn stream_splits_messages() {
        let mut second = dwr().answer();
        second.avps.push(Avp::new(avp::RESULT_CODE, &Value::Unsigned32(2001)).unwrap());
        let data = [dwr_bytes(), second.to_bytes().unwrap()].concat();
        contract::check_decode_with_alloc_limit(Messages::new, &data, 2 * DEFAULT_LIMIT);
        assert_eq!(decode_all(Messages::new, &data), (vec![Ok(dwr()), Ok(second)], None));
        assert_eq!(decode_all(Messages::new, &[2, 0, 0, 20]).1, Some(Fail::Protocol(FrameError::Version(2))));
    }

    #[test]
    fn stream_limit() {
        let mut d = Stream::new(Messages::with_limit(63));
        assert_eq!(d.push(&dwr_bytes()[..4]), 4);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(FrameError::TooBig(64)))));
        let mut d = Stream::new(Messages::with_limit(64));
        assert_eq!(d.push(&dwr_bytes()), 64);
        assert_eq!(d.next(), Some(Ok(Ok(dwr()))));
        // A tiny limit is raised to the header length.
        let mut d = Stream::new(Messages::with_limit(0));
        assert_eq!(d.push(&[1, 0, 0, 20, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 20);
        assert!(matches!(d.next(), Some(Ok(_))));
        // The default limit.
        let mut d = Stream::new(Messages::new());
        let big = (DEFAULT_LIMIT + 4) as u32;
        assert_eq!(d.push(&[1, (big >> 16) as u8, (big >> 8) as u8, big as u8]), 4);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(FrameError::TooBig(big)))));
    }

    #[test]
    fn stream_takes_many_small_messages_in_linear_time() {
        let data = Message::request(command::DEVICE_WATCHDOG, 0, 1, 1).to_bytes().unwrap().repeat(200_000);
        let started = std::time::Instant::now();
        let (messages, error) = decode_all(Messages::new, &data);
        assert_eq!(error, None);
        assert_eq!(messages.len(), 200_000);
        assert!(messages.iter().all(Result::is_ok));
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn writers_refuse_what_does_not_fit() {
        let huge = Avp { code: 1, vendor: Some(1), mandatory: false, protected: false, data: vec![7; MAX_AVP_DATA + 100] };
        contract::check_wire_value(&huge);
        assert_eq!(huge.to_bytes(), Err(FrameError::Unwritable));
        let mut message = Message::request(1, 2, 3, 4);
        message.avps = vec![huge.clone(), huge];
        contract::check_wire_value(&message);
        assert_eq!(message.to_bytes(), Err(FrameError::Unwritable));
        let text = "é".repeat(MAX_AVP_DATA / 2 + 4);
        assert_eq!(Avp::new(1, &Value::Utf8String(text)), Err(FrameError::Unwritable));
        let address = Address::Other { family: 9, bytes: vec![0; MAX_AVP_DATA] };
        assert_eq!(address.to_bytes(), Err(FrameError::Unwritable));
        contract::check_wire_value(&address);
        assert_eq!(Message::request(0xff00_0101, 0, 0, 0).to_bytes(), Err(FrameError::Unwritable));
    }

    #[test]
    fn utf8_string_refuses_code_point_zero() {
        // RFC 6733, section 4.3.1: code points 0x00000001 and up only.
        let a = Avp { code: avp::USER_NAME, vendor: None, mandatory: true, protected: false, data: b"a\0b".to_vec() };
        assert_eq!(a.value(Format::Utf8String), Err(FrameError::Value { code: 1, format: Format::Utf8String }));
        assert_eq!(check(&[a], base), Err(FrameError::Value { code: 1, format: Format::Utf8String }));
        assert_eq!(Avp::new(avp::USER_NAME, &Value::Utf8String("a\0b\0".into())), Err(FrameError::Unwritable));
    }

    #[test]
    fn failed_avp_holds_the_bad_avp_unchecked() {
        // RFC 6733, section 7.5: Failed-AVP carries the AVP that failed,
        // even one with a bad value or a bad length.
        let bad_value =
            Avp { code: avp::ORIGIN_HOST, vendor: None, mandatory: true, protected: false, data: b"no good".to_vec() };
        let f = Avp::new(avp::FAILED_AVP, &Value::Grouped(vec![bad_value])).unwrap();
        let rc = Avp::new(avp::RESULT_CODE, &Value::Unsigned32(result::INVALID_AVP_VALUE)).unwrap();
        check(&[rc.clone(), f], base).unwrap();
        // A copy of a header whose length is below 8, and a zero payload.
        let bad_length = Avp { data: vec![0, 0, 1, 8, 0x40, 0, 0, 5, 0, 0, 0, 0], ..rc.clone() };
        let f = Avp { code: avp::FAILED_AVP, ..bad_length };
        check(&[f], base).unwrap();
        // Another grouped AVP is still read.
        let g = Avp { code: avp::PROXY_INFO, data: vec![0, 0, 1, 8, 0x40, 0, 0, 5], ..rc };
        assert_eq!(check(&[g], base), Err(FrameError::AvpLength { code: 264, length: 5 }));
    }

    #[test]
    fn ip_address_families_need_their_lengths() {
        assert!(Address::parse(&[0, 1, 1, 2, 3]).is_err());
        assert!(Address::parse(&[0, 1, 1, 2, 3, 4, 5]).is_err());
        assert!(Address::parse(&[0, 2]).is_err());
        assert!(Address::parse(&[0, 2, 0, 0, 0, 0]).is_err());
        let a =
            Avp { code: avp::HOST_IP_ADDRESS, vendor: None, mandatory: true, protected: false, data: vec![0, 1, 9] };
        assert_eq!(check(&[a], base), Err(FrameError::Value { code: 257, format: Format::Address }));
        for address in [Address::Other { family: 1, bytes: vec![10, 0, 0] },
            Address::Other { family: 2, bytes: vec![0xff; 20] }] {
            assert_eq!(address.to_bytes(), Err(FrameError::Unwritable));
            contract::check_wire_value(&address);
        }
    }

    #[test]
    fn identity_labels() {
        // A DiameterIdentity is an FQDN or realm: dot-separated labels of
        // 1 to 63 characters.
        for bad in [".", "a..b", ".example", "example.", "a.b..", &format!("{}.net", "x".repeat(64))] {
            assert!(Identity::new(bad).is_none(), "{bad}");
        }
        assert!(Identity::new(&format!("{}.net", "x".repeat(63))).is_some());
        assert!(Uri::parse("aaa://host..example").is_none());
        let labels = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
        assert_eq!(labels.len(), MAX_IDENTITY);
        assert!(Identity::new(&labels).is_some());
        assert!(Identity::new(&format!("{labels}e")).is_none());
    }

    #[test]
    fn stream_holds_at_most_its_limit() {
        let data = dwr_bytes().repeat(100);
        contract::check_decode_with_alloc_limit(|| Messages::with_limit(64), &data, 128);
        assert_eq!(decode_all(|| Messages::with_limit(64), &data), (vec![Ok(dwr()); 100], None));
        let mut stream = Stream::new(Messages::with_limit(64));
        assert_eq!(stream.push(&data), 64);
        assert_eq!(stream.push(&data), 0);
        assert_eq!(stream.next(), Some(Ok(Ok(dwr()))));
    }

    #[test]
    fn answer_carries_session_id_and_proxy_info() {
        // RFC 6733, section 6.2: the answer includes the request's
        // Session-Id and its Proxy-Info AVPs, in the same order.
        let mut req = Message::request(command::RE_AUTH, 4, 1, 2);
        req.proxiable = true;
        let sid = Avp::new(avp::SESSION_ID, &Value::Utf8String("mme.example.net;1;2".into())).unwrap();
        let state = |s: &[u8]| Avp::new(avp::PROXY_STATE, &Value::OctetString(s.to_vec())).unwrap();
        let p1 = Avp::new(avp::PROXY_INFO, &Value::Grouped(vec![state(b"one")])).unwrap();
        let p2 = Avp::new(avp::PROXY_INFO, &Value::Grouped(vec![state(b"two")])).unwrap();
        req.avps = vec![
            sid.clone(),
            p1.clone(),
            Avp::new(avp::ORIGIN_HOST, &Value::DiameterIdentity(id("mme.example.net"))).unwrap(),
            p2.clone(),
            Avp { vendor: Some(10415), ..p1.clone() },
        ];
        let a = req.answer();
        assert_eq!(a.avps, [sid, p1, p2]);
        assert!(a.proxiable && !a.request);
    }

    #[test]
    fn lookups_and_traits() {
        let mut m = dwr();
        let v = Avp { vendor: Some(10415), ..Avp::new(1032, &Value::Enumerated(1004)).unwrap() };
        m.avps.push(v.clone());
        assert_eq!(m.vendor_avp(1032, 10415), Some(&v));
        assert_eq!(m.vendor_avp(1032, 1), None);
        assert_eq!(m.avp(1032), None);
        assert!(id("Example.NET").eq_ignore_case(&id("example.net")));
        assert!(!id("example.org").eq_ignore_case(&id("example.net")));
        let mut set = std::collections::HashSet::new();
        set.insert(m.clone());
        assert!(set.contains(&m));
        let formats: std::collections::HashSet<Format> = [Format::Grouped, Format::Time].into();
        assert_eq!(formats.len(), 2);
        let d = Stream::new(Messages::new());
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn largest_base_avp_writes_back_whole() {
        // An AVP with no vendor ID has a 4-byte shorter header, so it can
        // carry 4 more bytes than one with. A message holding the largest
        // such AVP reads and writes back unchanged.
        let data = vec![0x5a; MAX_MESSAGE - HEADER_LEN - AVP_HEADER_LEN];
        let mut m = Message::request(1, 0, 0, 0);
        m.avps.push(Avp { code: 1, vendor: None, mandatory: false, protected: false, data });
        let b = m.to_bytes().unwrap();
        assert_eq!(b.len(), MAX_MESSAGE);
        assert_eq!(Message::parse(&b), Ok(m));
    }

    #[test]
    fn new_avps_follow_the_base_flag_rules() {
        // RFC 6733, section 4.5: these four must not have the M flag.
        for code in [avp::PRODUCT_NAME, avp::FIRMWARE_REVISION, avp::ERROR_MESSAGE, avp::ERROR_REPORTING_HOST] {
            assert!(!Avp::new(code, &Value::Unsigned32(1)).unwrap().mandatory, "{code}");
        }
        for code in [avp::ORIGIN_HOST, avp::RESULT_CODE, avp::FAILED_AVP, 9999] {
            assert!(Avp::new(code, &Value::Unsigned32(1)).unwrap().mandatory, "{code}");
        }
    }

    #[test]
    fn diameter_uris_never_name_udp() {
        // RFC 6733, section 4.3.1: UDP must not be used with Diameter,
        // which is the default protocol.
        for bad in ["aaa://h.example;transport=udp", "aaa://h.example;transport=udp;protocol=diameter"] {
            assert_eq!(Uri::parse(bad), None, "{bad}");
        }
        assert!(Uri::parse("aaa://h.example;transport=udp;protocol=radius").is_some());
        // A constructed URI with forbidden UDP transport is refused.
        let u = Uri {
            secure: false,
            fqdn: id("h.example"),
            port: None,
            transport: Some(Transport::Udp),
            protocol: Some(AaaProtocol::Diameter),
        };
        assert_eq!(u.to_string(), "aaa://h.example;transport=udp;protocol=diameter");
        assert_eq!(Avp::new(avp::REDIRECT_HOST, &Value::DiameterUri(u)), Err(FrameError::Unwritable));
    }

    #[test]
    fn grouped_children_need_their_padding() {
        // RFC 6733, section 4.2: a grouped AVP's data holds its AVPs with
        // their padding. Proxy-State "x" with its 3 padding bytes left out:
        let short = [0, 0, 0, 0x21, 0x40, 0, 0, 9, b'x'];
        let g = Avp { code: avp::PROXY_INFO, vendor: None, mandatory: true, protected: false, data: short.to_vec() };
        let e = FrameError::AvpLength { code: avp::PROXY_STATE, length: 9 };
        assert_eq!(g.value(Format::Grouped), Err(e));
        assert_eq!(check(&[g], base), Err(e));
        assert_eq!(Avp::parse_list(&short), Err(e));
        let mut padded = short.to_vec();
        padded.extend_from_slice(&[0, 0, 0]);
        assert_eq!(Avp::parse_list(&padded).unwrap().len(), 1);
    }

    #[test]
    fn fixed_width_values_of_the_wrong_size_are_length_errors() {
        // RFC 6733, section 7.1.5: DIAMETER_INVALID_AVP_LENGTH.
        let a = Avp { code: avp::SESSION_TIMEOUT, vendor: None, mandatory: true, protected: false, data: vec![0; 3] };
        let e = check(std::slice::from_ref(&a), base).unwrap_err();
        assert_eq!(e, FrameError::AvpLength { code: avp::SESSION_TIMEOUT, length: 11 });
        assert_eq!(e.result_code(), result::INVALID_AVP_LENGTH);
        let v = Avp { vendor: Some(10415), ..a };
        assert_eq!(v.value(Format::Unsigned32), Err(FrameError::AvpLength { code: avp::SESSION_TIMEOUT, length: 15 }));
    }

    #[test]
    fn forbidden_header_flags_are_reported() {
        // RFC 6733, section 3: no E flag on a request, no T flag on an
        // answer. Both read, and check_header reports them.
        let mut b = dwr_bytes();
        b[4] |= flags::ERROR;
        let m = Message::parse(&b).unwrap();
        let e = m.check_header().unwrap_err();
        assert_eq!(e, FrameError::HeaderBits(flags::REQUEST | flags::ERROR));
        assert_eq!(e.result_code(), result::INVALID_HDR_BITS);
        assert!(!e.to_string().is_empty());
        contract::check_wire_value(&m);
        assert_eq!(m.to_bytes().unwrap(), b);
        let mut a = dwr().answer();
        a.retransmit = true;
        assert_eq!(a.check_header(), Err(FrameError::HeaderBits(flags::RETRANSMIT)));
        contract::check_wire_value(&a);
        // An error answer and a retransmitted request are fine.
        let mut a = dwr().answer();
        a.error = true;
        a.check_header().unwrap();
        let mut r = dwr();
        r.retransmit = true;
        r.check_header().unwrap();
        contract::check_wire_value(&r);
    }

    #[test]
    fn vendor_id_zero_is_reported() {
        // RFC 6733, section 4.1.1: implementations must not use vendor
        // ID 0. Origin-Host with V set and vendor 0:
        let b = [0, 0, 1, 8, 0xc0, 0, 0, 0x0d, 0, 0, 0, 0, b'h', 0, 0, 0];
        let a = Avp::parse(&b).unwrap();
        assert_eq!(a.vendor, Some(0));
        let e = check(std::slice::from_ref(&a), base).unwrap_err();
        assert_eq!(e, FrameError::AvpBits { code: avp::ORIGIN_HOST });
        assert_eq!(e.result_code(), result::INVALID_AVP_BITS);
        assert!(!e.to_string().is_empty());
        // Inside a grouped AVP too.
        let g = Avp::new(avp::PROXY_INFO, &Value::Grouped(vec![a.clone()])).unwrap();
        assert_eq!(check(&[g], base), Err(e));
        let mut m = dwr();
        m.avps.push(a);
        contract::check_wire_value(&m);
    }

    #[test]
    fn checked_writer_refuses_what_it_would_change() {
        assert_eq!(dwr().to_bytes(), Ok(dwr_bytes()));
        assert_eq!(Message::request(0x0100_0101, 0, 0, 0).to_bytes(), Err(FrameError::Unwritable));
        let one = Avp { code: 1, vendor: None, mandatory: false, protected: false, data: vec![] };
        let mut m = Message::request(1, 0, 0, 0);
        m.avps = vec![one; MAX_AVPS];
        contract::check_wire_value(&m);
        m.avps.push(m.avps[0].clone());
        assert_eq!(m.to_bytes(), Err(FrameError::Unwritable));
        // The largest AVP fits on its own, but not with another after it.
        let big = vec![0; MAX_MESSAGE - HEADER_LEN - AVP_HEADER_LEN];
        let mut m = Message::request(1, 0, 0, 0);
        m.avps.push(Avp { code: 1, vendor: None, mandatory: false, protected: false, data: big.clone() });
        assert!(m.to_bytes().is_ok());
        m.avps.push(Avp::new(avp::RESULT_CODE, &Value::Unsigned32(2001)).unwrap());
        assert_eq!(m.to_bytes(), Err(FrameError::Unwritable));
        // With a vendor ID the same data is 4 bytes too long.
        let mut m = Message::request(1, 0, 0, 0);
        m.avps.push(Avp { code: 1, vendor: Some(1), mandatory: false, protected: false, data: big });
        assert_eq!(m.to_bytes(), Err(FrameError::Unwritable));
    }

    #[test]
    fn malformed_item_keeps_its_header() {
        let mut data = dwr_bytes();
        data[27] = 7;
        data.extend_from_slice(&dwr_bytes());
        let (messages, error) = decode_all(Messages::new, &data);
        assert_eq!(error, None);
        let malformed = messages[0].as_ref().unwrap_err();
        assert_eq!(malformed.error, FrameError::AvpLength { code: avp::ORIGIN_HOST, length: 7 });
        assert_eq!(malformed.header, Message { avps: vec![], ..dwr() });
        let reply = malformed.header.answer();
        assert_eq!((reply.hop_by_hop, reply.end_to_end), (0x1234_5678, 0x9abc_def0));
        assert_eq!(messages[1], Ok(dwr()));
        contract::check_decode_with_alloc_limit(Messages::new, &data, 2 * DEFAULT_LIMIT);
    }

    const FORMATS: [Format; 14] = [
        Format::OctetString,
        Format::Integer32,
        Format::Integer64,
        Format::Unsigned32,
        Format::Unsigned64,
        Format::Float32,
        Format::Float64,
        Format::Grouped,
        Format::Address,
        Format::Time,
        Format::Utf8String,
        Format::DiameterIdentity,
        Format::DiameterUri,
        Format::Enumerated,
    ];

    fn random_value(r: &mut Lcg, depth: u32) -> Value {
        match r.index(if depth > 2 { 13 } else { 14 }) {
            0 => Value::OctetString(r.bytes(12)),
            1 => Value::Integer32(r.next() as i32),
            2 => Value::Integer64((r.next() << 32 | r.next()) as i64),
            3 => Value::Unsigned32(r.next() as u32),
            4 => Value::Unsigned64(r.next() << 32 | r.next()),
            5 => Value::Float32(f32::from_bits(r.next() as u32)),
            6 => Value::Float64(f64::from_bits(r.next() << 32)),
            7 => Value::Address(Address::V4(Ipv4Addr::from(r.next() as u32))),
            8 => Value::Time(r.next() as u32),
            9 => Value::Utf8String(["", "x", "héllo", "日本"][r.index(4)].to_string()),
            10 => Value::DiameterIdentity(id(["a", "realm.example", "h-1_2.x"][r.index(3)])),
            11 => Value::DiameterUri(Uri {
                secure: r.coin(),
                fqdn: id("peer.example"),
                port: r.coin().then(|| r.next() as u16),
                transport: [None, Some(Transport::Tcp), Some(Transport::Sctp), Some(Transport::Udp)]
                    [r.index(4)],
                protocol: [None, Some(AaaProtocol::Diameter), Some(AaaProtocol::Radius), Some(AaaProtocol::TacacsPlus)]
                    [r.index(4)],
            }),
            12 => Value::Enumerated(r.next() as i32),
            _ => Value::Grouped((0..r.index(4)).map(|_| random_avp(r, depth + 1).0).collect()),
        }
    }

    fn random_avp(r: &mut Lcg, depth: u32) -> (Avp, Value) {
        let mut v = random_value(r, depth);
        if let Value::DiameterUri(uri) = &mut v
            && uri.udp_diameter()
        {
            uri.protocol = Some(AaaProtocol::Radius);
        }
        let mut a = Avp::new(r.index(400) as u32, &v).unwrap();
        a.vendor = (r.index(3) == 0).then(|| r.next() as u32);
        a.mandatory = r.coin();
        a.protected = r.index(5) == 0;
        (a, v)
    }

    fn random_message(r: &mut Lcg) -> Message {
        let f = r.index(16);
        Message {
            request: f & 1 != 0,
            proxiable: f & 2 != 0,
            error: f & 4 != 0,
            retransmit: f & 8 != 0,
            command: (r.next() as u32) & 0xff_ffff,
            application: (r.next() as u32),
            hop_by_hop: (r.next() as u32),
            end_to_end: (r.next() as u32),
            avps: (0..r.index(6)).map(|_| random_avp(r, 0).0).collect(),
        }
    }

    /// Exercises framing, semantic checks, and every named wire unit.
    fn exercise(data: &[u8]) {
        contract::check_decode_with_alloc_limit(Messages::new, data, 2 * DEFAULT_LIMIT);
        contract::check_wire::<Message>(data);
        contract::check_wire::<Avp>(data);
        contract::check_wire::<Address>(data);
        if let Ok(address) = Address::parse(data) {
            assert_eq!(address.to_bytes().unwrap(), data);
        }
        for message in decode_all(Messages::new, data).0.into_iter().flatten() {
            contract::check_wire_value(&message);
            let _ = check(&message.avps, base);
            let _ = check(&message.avps, |_, _| Some(Format::Grouped));
            contract::check_wire_value(&message.answer());
            for avp in &message.avps {
                for format in FORMATS {
                    if let Ok(value) = avp.value(format) {
                        let rebuilt = Avp::new(avp.code, &value).unwrap();
                        if !matches!(format, Format::Grouped | Format::DiameterUri) {
                            assert_eq!(rebuilt.data, avp.data);
                        }
                        let reread = rebuilt.value(format).unwrap();
                        assert_eq!(Avp::new(avp.code, &reread).unwrap().data, rebuilt.data);
                    }
                }
            }
        }
        if let Ok(list) = Avp::parse_list(data)
            && let Ok(avp) = Avp::new(1, &Value::Grouped(list.clone()))
        {
            assert_eq!(avp.value(Format::Grouped), Ok(Value::Grouped(list)));
        }
        if let Ok(text) = std::str::from_utf8(data) {
            if let Some(uri) = Uri::parse(text) { assert_eq!(Uri::parse(&uri.to_string()), Some(uri)); }
            if let Some(identity) = Identity::new(text) { assert_eq!(identity.as_str(), text); }
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg::new(0x5eed_d1a3);
        for round in 0..fictionet::stdlib::codec::test_support::rounds(9500) {
            let data = match round % 3 {
                // Random bytes behind a plausible header.
                0 => {
                    let mut d = r.bytes(120);
                    if d.len() >= 4 && r.coin() {
                        d[0] = 1;
                        d[1] = 0;
                        d[2] = 0;
                        d[3] = (r.index(30) * 4) as u8;
                    }
                    d
                }
                // A valid message, mutated.
                1 => {
                    let mut d = random_message(&mut r).to_bytes().unwrap();
                    mutate(&mut r, &mut d);
                    d
                }
                // Valid messages back to back, which must read back exactly.
                _ => {
                    let ms: Vec<Message> = (0..1 + r.index(3)).map(|_| random_message(&mut r)).collect();
                    let d: Vec<u8> = ms.iter().flat_map(|m| m.to_bytes().unwrap()).collect();
                    assert_eq!(decode_all(Messages::new, &d), (ms.into_iter().map(Ok).collect(), None));
                    d
                }
            };
            exercise(&data);
        }
        // Random AVPs: each value reads back in its own format, to the same bytes.
        for _ in 0..fictionet::stdlib::codec::test_support::rounds(9500) {
            let (a, v) = random_avp(&mut r, 0);
            let back = Avp::parse(&a.to_bytes().unwrap()).unwrap();
            assert_eq!(back, a);
            assert_eq!(Avp::new(a.code, &a.value(v.format()).unwrap()).unwrap().data, Avp::new(a.code, &v).unwrap().data);
        }
        // Random strings as URIs.
        let alphabet = b"aAs:/;=0123456789.tcpransportoldiemu+x";
        for _ in 0..fictionet::stdlib::codec::test_support::rounds(9500) {
            let mut s = String::from(["aaa://", "aaas://", "AaA://", ""][r.index(4)]);
            for byte in r.bytes(30) {
                s.push(alphabet[usize::from(byte) % alphabet.len()] as char);
            }
            if let Some(u) = Uri::parse(&s) {
                assert_eq!(Uri::parse(&u.to_string()), Some(u));
            }
        }
    }
}
