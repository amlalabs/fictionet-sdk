//! CoAP: reading and writing messages over UDP and frames over TCP, with
//! no I/O.
//!
//! CoAP, the Constrained Application Protocol, is a small web protocol for
//! sensors, meters and other small devices. A client sends a request with
//! a method (GET, POST, PUT, DELETE) and a path, and the device answers
//! with a response code and a payload, much as in HTTP. Over UDP each
//! message is one datagram, usually to port 5683, behind a 4-byte header.
//! This module follows RFC 7252 (CoAP), RFC 7959 (block-wise transfer),
//! RFC 7641 (Observe) and RFC 8323 (CoAP over TCP).
//!
//! Nothing here reads a socket. A world that plays a device reads each
//! datagram it gets with [`Message::parse`], looks at its code, path and
//! options, and sends back the bytes of [`Message::to_bytes`] for the
//! reply. Over TCP it pushes the bytes it reads to a [`Stream<codec::Frames<Frame>>`](fictionet::stdlib::codec::Stream) and gets
//! [`Frame`]s back. Which resources exist, and what they hold, is up to
//! world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A datagram that breaks the message format is an [`Error`]; a
//! real device answers a confirmable one with a Reset (see
//! [`peek_header`]) and drops the rest. Options are read as bytes and
//! checked against the registry only when asked, with
//! [`Message::bad_option`], as RFC 7252 section 5.4 describes.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::coap::{Code, Message, Type, content_format};
//!
//! /// A pretend thermometer with one resource, /temp.
//! fn answer(request: &Message) -> Message {
//!     if request.code != Code::GET {
//!         return request.reply(Code::METHOD_NOT_ALLOWED, 0);
//!     }
//!     match request.options.uri_path().as_deref() {
//!         Some("/temp") => {
//!             let mut reply = request.reply(Code::CONTENT, 0);
//!             reply.options.set_content_format(content_format::TEXT_PLAIN);
//!             reply.payload = b"21.5".to_vec();
//!             reply
//!         }
//!         _ => request.reply(Code::NOT_FOUND, 0),
//!     }
//! }
//!
//! // A confirmable GET /temp, message ID 0x1234, token 0x77.
//! let datagram = [0x41, 0x01, 0x12, 0x34, 0x77, 0xb4, b't', b'e', b'm', b'p'];
//! let request = Message::parse(&datagram).unwrap();
//! assert_eq!(request.kind, Type::Confirmable);
//! let reply = answer(&request);
//! // A piggybacked acknowledgement: 2.05 Content, the same ID and token,
//! // Content-Format 0 (an empty value), then the payload.
//! assert_eq!(reply.to_bytes().unwrap(), [0x61, 0x45, 0x12, 0x34, 0x77, 0xc0, 0xff, b'2', b'1', b'.', b'5']);
//! ```

use fictionet::stdlib::codec::Prefixed;
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::ascii::{self, hex_upper};
use fictionet::stdlib::codec::{Wire};

/// The UDP and TCP port CoAP servers listen on.
pub const PORT: u16 = 5683;
/// The port for CoAP over DTLS or TLS.
pub const SECURE_PORT: u16 = 5684;
/// The protocol version every UDP message carries.
pub const VERSION: u8 = 1;
/// The length of a UDP message's fixed header.
pub const HEADER_LEN: usize = 4;
/// The longest token a message may carry.
pub const MAX_TOKEN: usize = 8;
/// The most options one message may carry here. RFC 7252 sets no limit;
/// this bounds what a reader keeps.
pub const MAX_OPTIONS: usize = 64;
/// The longest option value read or written: the longest registered
/// option, Proxy-Uri.
pub const MAX_OPTION_VALUE: usize = 1034;
/// The longest UDP datagram read or written: the largest UDP payload
/// over IPv4, so a message written fits a datagram over either IP
/// version (RFC 7252 section 4.6).
pub const MAX_DATAGRAM: usize = 65_507;
/// The longest TCP frame body (options, payload marker and payload) read
/// or written.
pub const MAX_FRAME_BODY: usize = 1 << 20;
/// The longest TCP frame header: the length and token-length byte, a
/// 4-byte extended length, and the code.
pub const MAX_FRAME_HEADER: usize = 6;
/// The most bytes a [`Stream<codec::Frames<Frame>>`](fictionet::stdlib::codec::Stream) holds: one whole frame of the largest
/// size.
pub const MAX_BUFFERED: usize = MAX_FRAME_HEADER + MAX_TOKEN + MAX_FRAME_BODY;
/// The longest body a [`Reassembler`] collects.
pub const MAX_BODY: usize = 1 << 24;
/// The byte that ends the options and starts the payload.
pub const PAYLOAD_MARKER: u8 = 0xff;

/// A UDP message's type: whether it wants an acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    /// CON: the sender retransmits it until it gets an ACK or a Reset.
    Confirmable,
    /// NON: sent once, with no acknowledgement.
    NonConfirmable,
    /// ACK: says a confirmable message arrived, and may carry the
    /// response.
    Acknowledgement,
    /// RST: says a message arrived that the receiver cannot process.
    Reset,
}

impl Type {
    /// The type for the header's 2-bit field. Only the low two bits of
    /// `bits` count.
    pub fn from_bits(bits: u8) -> Type {
        match bits & 3 {
            0 => Type::Confirmable,
            1 => Type::NonConfirmable,
            2 => Type::Acknowledgement,
            _ => Type::Reset,
        }
    }

    /// The header's 2-bit field for this type.
    pub fn bits(self) -> u8 {
        match self {
            Type::Confirmable => 0,
            Type::NonConfirmable => 1,
            Type::Acknowledgement => 2,
            Type::Reset => 3,
        }
    }
}

/// A message code: a 3-bit class and a 5-bit detail, written `c.dd`.
/// Class 0 holds the methods, classes 2, 4 and 5 the responses, and
/// class 7 the signals of CoAP over TCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Code(pub u8);

#[allow(missing_docs)] // each name is the code's name in the registry
impl Code {
    /// 0.00: an empty message, such as a bare ACK, a Reset or a ping.
    pub const EMPTY: Code = Code(0x00);
    pub const GET: Code = Code(0x01);
    pub const POST: Code = Code(0x02);
    pub const PUT: Code = Code(0x03);
    pub const DELETE: Code = Code(0x04);
    pub const FETCH: Code = Code(0x05);
    pub const PATCH: Code = Code(0x06);
    pub const IPATCH: Code = Code(0x07);
    pub const CREATED: Code = Code(0x41);
    pub const DELETED: Code = Code(0x42);
    pub const VALID: Code = Code(0x43);
    pub const CHANGED: Code = Code(0x44);
    pub const CONTENT: Code = Code(0x45);
    /// 2.31: the server took a Block1 block and wants the next one.
    pub const CONTINUE: Code = Code(0x5f);
    pub const BAD_REQUEST: Code = Code(0x80);
    pub const UNAUTHORIZED: Code = Code(0x81);
    pub const BAD_OPTION: Code = Code(0x82);
    pub const FORBIDDEN: Code = Code(0x83);
    pub const NOT_FOUND: Code = Code(0x84);
    pub const METHOD_NOT_ALLOWED: Code = Code(0x85);
    pub const NOT_ACCEPTABLE: Code = Code(0x86);
    pub const REQUEST_ENTITY_INCOMPLETE: Code = Code(0x88);
    pub const CONFLICT: Code = Code(0x89);
    pub const PRECONDITION_FAILED: Code = Code(0x8c);
    pub const REQUEST_ENTITY_TOO_LARGE: Code = Code(0x8d);
    pub const UNSUPPORTED_CONTENT_FORMAT: Code = Code(0x8f);
    pub const UNPROCESSABLE_ENTITY: Code = Code(0x96);
    pub const TOO_MANY_REQUESTS: Code = Code(0x9d);
    pub const INTERNAL_SERVER_ERROR: Code = Code(0xa0);
    pub const NOT_IMPLEMENTED: Code = Code(0xa1);
    pub const BAD_GATEWAY: Code = Code(0xa2);
    pub const SERVICE_UNAVAILABLE: Code = Code(0xa3);
    pub const GATEWAY_TIMEOUT: Code = Code(0xa4);
    pub const PROXYING_NOT_SUPPORTED: Code = Code(0xa5);
    pub const HOP_LIMIT_REACHED: Code = Code(0xa8);
    /// 7.01: Capabilities and Settings, the first frame each side of a
    /// TCP connection sends.
    pub const CSM: Code = Code(0xe1);
    pub const PING: Code = Code(0xe2);
    pub const PONG: Code = Code(0xe3);
    pub const RELEASE: Code = Code(0xe4);
    pub const ABORT: Code = Code(0xe5);
}

impl Code {
    /// The code `class.detail`, or `None` if the class is over 7 or the
    /// detail over 31.
    pub fn new(class: u8, detail: u8) -> Option<Code> {
        if class > 7 || detail > 31 { None } else { Some(Code(class << 5 | detail)) }
    }

    /// The class: the code's top 3 bits.
    pub fn class(self) -> u8 {
        self.0 >> 5
    }

    /// The detail: the code's low 5 bits.
    pub fn detail(self) -> u8 {
        self.0 & 0x1f
    }

    /// Whether this is 0.00, the code of an empty message.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether this is a method: class 0, other than 0.00.
    pub fn is_request(self) -> bool {
        self.class() == 0 && self.0 != 0
    }

    /// Whether this is a response: class 2, 4 or 5.
    pub fn is_response(self) -> bool {
        matches!(self.class(), 2 | 4 | 5)
    }

    /// Whether this is a signal of CoAP over TCP: class 7.
    pub fn is_signal(self) -> bool {
        self.class() == 7
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:02}", self.class(), self.detail())
    }
}

/// Option numbers in the CoAP Option Numbers registry. Over TCP, signal
/// frames (class 7) number their options apart; see [`signal`].
pub mod option {
    /// Opaque, 0 to 8 bytes, repeatable: act only if the resource's
    /// ETag matches one of these.
    pub const IF_MATCH: u16 = 1;
    /// String, 1 to 255 bytes: the host the request is for.
    pub const URI_HOST: u16 = 3;
    /// Opaque, 1 to 8 bytes, repeatable: a tag for one version of a
    /// resource.
    pub const ETAG: u16 = 4;
    /// Empty: act only if the resource does not exist.
    pub const IF_NONE_MATCH: u16 = 5;
    /// Uint, 0 to 3 bytes: register for or carry notifications (RFC 7641).
    pub const OBSERVE: u16 = 6;
    /// Uint, 0 to 2 bytes: the port the request is for.
    pub const URI_PORT: u16 = 7;
    /// String, 0 to 255 bytes, repeatable: one segment of a created
    /// resource's path.
    pub const LOCATION_PATH: u16 = 8;
    /// Opaque, 0 to 255 bytes: OSCORE protection (RFC 8613).
    pub const OSCORE: u16 = 9;
    /// String, 0 to 255 bytes, repeatable: one segment of the path.
    pub const URI_PATH: u16 = 11;
    /// Uint, 0 to 2 bytes: the payload's format.
    pub const CONTENT_FORMAT: u16 = 12;
    /// Uint, 0 to 4 bytes: how many seconds a response stays fresh.
    pub const MAX_AGE: u16 = 14;
    /// String, 0 to 255 bytes, repeatable: one `key=value` of the query.
    pub const URI_QUERY: u16 = 15;
    /// Uint, 1 byte: how many proxies a request may still pass
    /// (RFC 8768).
    pub const HOP_LIMIT: u16 = 16;
    /// Uint, 0 to 2 bytes: the payload format the client wants.
    pub const ACCEPT: u16 = 17;
    /// Uint, 0 to 3 bytes: a quick Block1 block (RFC 9177).
    pub const Q_BLOCK1: u16 = 19;
    /// String, 0 to 255 bytes, repeatable: one `key=value` of a created
    /// resource's query.
    pub const LOCATION_QUERY: u16 = 20;
    /// Empty: the request also carries EDHOC (RFC 9668).
    pub const EDHOC: u16 = 21;
    /// Uint, 0 to 3 bytes: which block of the response this is, or which
    /// the client wants (RFC 7959).
    pub const BLOCK2: u16 = 23;
    /// Uint, 0 to 3 bytes: which block of the request body this is
    /// (RFC 7959).
    pub const BLOCK1: u16 = 27;
    /// Uint, 0 to 4 bytes: the size of the whole response body
    /// (RFC 7959).
    pub const SIZE2: u16 = 28;
    /// Uint, 0 to 3 bytes, repeatable when asking for missing blocks: a
    /// quick Block2 block (RFC 9177).
    pub const Q_BLOCK2: u16 = 31;
    /// String, 1 to 1034 bytes: the whole URI, for a forward proxy.
    pub const PROXY_URI: u16 = 35;
    /// String, 1 to 255 bytes: the URI scheme, for a forward proxy.
    pub const PROXY_SCHEME: u16 = 39;
    /// Uint, 0 to 4 bytes: the size of the whole request body.
    pub const SIZE1: u16 = 60;
    /// Opaque, 1 to 40 bytes: a value the server wants echoed (RFC 9175).
    pub const ECHO: u16 = 252;
    /// Uint, 0 to 1 byte: which responses the client does not want
    /// (RFC 7967).
    pub const NO_RESPONSE: u16 = 258;
    /// Opaque, 0 to 8 bytes, repeatable: tells block-wise requests apart
    /// (RFC 9175).
    pub const REQUEST_TAG: u16 = 292;
    /// Uint, 0 to 2 bytes: the OCF content format version the client
    /// accepts.
    pub const OCF_ACCEPT_CONTENT_FORMAT_VERSION: u16 = 2049;
    /// Uint, 0 to 2 bytes: the OCF content format version of the payload.
    pub const OCF_CONTENT_FORMAT_VERSION: u16 = 2053;

    /// Whether option `number` is critical: a receiver that does not
    /// understand it must reject the message.
    pub fn is_critical(number: u16) -> bool {
        number & 1 == 1
    }

    /// Whether option `number` is unsafe to forward: a proxy that does
    /// not understand it must not pass the message on.
    pub fn is_unsafe(number: u16) -> bool {
        number & 2 != 0
    }

    /// Whether option `number` is left out of a cache key. Only safe
    /// options can be.
    pub fn is_no_cache_key(number: u16) -> bool {
        number & 0x1e == 0x1c
    }
}

/// Option numbers of the signals of CoAP over TCP (RFC 8323 section 5).
/// The same number means a different option for each signal code.
pub mod signal {
    /// CSM, uint 0 to 4 bytes: the largest message the sender accepts.
    pub const MAX_MESSAGE_SIZE: u16 = 2;
    /// CSM, empty: the sender accepts BERT block-wise transfer.
    pub const BLOCK_WISE_TRANSFER: u16 = 4;
    /// Ping and Pong, empty: answer only once the queue is flushed.
    pub const CUSTODY: u16 = 2;
    /// Release, string 1 to 255 bytes, repeatable: where to reconnect.
    pub const ALTERNATIVE_ADDRESS: u16 = 2;
    /// Release, uint 0 to 3 bytes: seconds to wait before reconnecting.
    pub const HOLD_OFF: u16 = 4;
    /// Abort, uint 0 to 2 bytes: the CSM option that caused the abort.
    pub const BAD_CSM_OPTION: u16 = 2;
    /// The Max-Message-Size a peer assumes until it reads a CSM.
    pub const DEFAULT_MAX_MESSAGE_SIZE: u32 = 1152;
}

/// Content-Format numbers in the registry, for the Content-Format and
/// Accept options.
pub mod content_format {
    /// `text/plain; charset=utf-8`
    pub const TEXT_PLAIN: u16 = 0;
    /// `application/link-format`, the format of `/.well-known/core`.
    pub const LINK_FORMAT: u16 = 40;
    /// `application/xml`
    pub const XML: u16 = 41;
    /// `application/octet-stream`
    pub const OCTET_STREAM: u16 = 42;
    /// `application/exi`
    pub const EXI: u16 = 47;
    /// `application/json`
    pub const JSON: u16 = 50;
    /// `application/cbor`
    pub const CBOR: u16 = 60;
    /// `application/senml+json`
    pub const SENML_JSON: u16 = 110;
    /// `application/senml+cbor`
    pub const SENML_CBOR: u16 = 112;
}

/// Observe option values a client sends (RFC 7641).
pub mod observe {
    /// Asks to be told each time the resource changes.
    pub const REGISTER: u32 = 0;
    /// Asks to stop being told.
    pub const DEREGISTER: u32 = 1;
    /// The largest Observe value: it is 24 bits.
    pub const MAX: u32 = 0xff_ffff;
}

/// How an option's value is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueFormat {
    /// No value at all.
    Empty,
    /// Bytes with no meaning to CoAP.
    Opaque,
    /// A big-endian unsigned integer with no leading zero bytes.
    Uint,
    /// UTF-8 text.
    String,
}

/// What the registry says about one option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionFormat {
    /// The option's name in the registry.
    pub name: &'static str,
    /// How its value is written.
    pub value: ValueFormat,
    /// The shortest value allowed, in bytes.
    pub min: usize,
    /// The longest value allowed, in bytes.
    pub max: usize,
    /// Whether it may appear more than once.
    pub repeatable: bool,
}

/// The registry entry for option `number` in a request or response, or
/// `None` for a number not registered.
pub fn option_format(number: u16) -> Option<OptionFormat> {
    use ValueFormat::{Empty, Opaque, String, Uint};
    let (name, value, min, max, repeatable) = match number {
        option::IF_MATCH => ("If-Match", Opaque, 0, 8, true),
        option::URI_HOST => ("Uri-Host", String, 1, 255, false),
        option::ETAG => ("ETag", Opaque, 1, 8, true),
        option::IF_NONE_MATCH => ("If-None-Match", Empty, 0, 0, false),
        option::OBSERVE => ("Observe", Uint, 0, 3, false),
        option::URI_PORT => ("Uri-Port", Uint, 0, 2, false),
        option::LOCATION_PATH => ("Location-Path", String, 0, 255, true),
        option::OSCORE => ("OSCORE", Opaque, 0, 255, false),
        option::URI_PATH => ("Uri-Path", String, 0, 255, true),
        option::CONTENT_FORMAT => ("Content-Format", Uint, 0, 2, false),
        option::MAX_AGE => ("Max-Age", Uint, 0, 4, false),
        option::URI_QUERY => ("Uri-Query", String, 0, 255, true),
        option::HOP_LIMIT => ("Hop-Limit", Uint, 1, 1, false),
        option::ACCEPT => ("Accept", Uint, 0, 2, false),
        option::Q_BLOCK1 => ("Q-Block1", Uint, 0, 3, false),
        option::LOCATION_QUERY => ("Location-Query", String, 0, 255, true),
        option::EDHOC => ("EDHOC", Empty, 0, 0, false),
        option::BLOCK2 => ("Block2", Uint, 0, 3, false),
        option::BLOCK1 => ("Block1", Uint, 0, 3, false),
        option::SIZE2 => ("Size2", Uint, 0, 4, false),
        option::Q_BLOCK2 => ("Q-Block2", Uint, 0, 3, true),
        option::PROXY_URI => ("Proxy-Uri", String, 1, 1034, false),
        option::PROXY_SCHEME => ("Proxy-Scheme", String, 1, 255, false),
        option::SIZE1 => ("Size1", Uint, 0, 4, false),
        option::ECHO => ("Echo", Opaque, 1, 40, false),
        option::NO_RESPONSE => ("No-Response", Uint, 0, 1, false),
        option::REQUEST_TAG => ("Request-Tag", Opaque, 0, 8, true),
        option::OCF_ACCEPT_CONTENT_FORMAT_VERSION => ("OCF-Accept-Content-Format-Version", Uint, 0, 2, false),
        option::OCF_CONTENT_FORMAT_VERSION => ("OCF-Content-Format-Version", Uint, 0, 2, false),
        _ => return None,
    };
    Some(OptionFormat { name, value, min, max, repeatable })
}

/// The registry entry for option `number` in a signal frame with `code`,
/// or `None` if that signal has no such option.
pub fn signal_option_format(code: Code, number: u16) -> Option<OptionFormat> {
    use ValueFormat::{Empty, String, Uint};
    let (name, value, min, max, repeatable) = match (code, number) {
        (Code::CSM, signal::MAX_MESSAGE_SIZE) => ("Max-Message-Size", Uint, 0, 4, false),
        (Code::CSM, signal::BLOCK_WISE_TRANSFER) => ("Block-Wise-Transfer", Empty, 0, 0, false),
        (Code::PING | Code::PONG, signal::CUSTODY) => ("Custody", Empty, 0, 0, false),
        (Code::RELEASE, signal::ALTERNATIVE_ADDRESS) => ("Alternative-Address", String, 1, 255, true),
        (Code::RELEASE, signal::HOLD_OFF) => ("Hold-Off", Uint, 0, 3, false),
        (Code::ABORT, signal::BAD_CSM_OPTION) => ("Bad-CSM-Option", Uint, 0, 2, false),
        _ => return None,
    };
    Some(OptionFormat { name, value, min, max, repeatable })
}

/// An unsigned CoAP option value, encoded in zero to four bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uint(
    /// The option's numeric value.
    pub u32,
);

impl Wire for Uint {
    type ParseError = Error;
    type WriteError = core::convert::Infallible;

    /// Reads one unsigned value. Refuses more than four bytes; leading zeros are accepted.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 4 {
            return Err(Error::TooLong(bytes.len() as u64));
        }
        Ok(Self(bytes.iter().fold(0, |n, &byte| (n << 8) | u32::from(byte))))
    }

    /// Appends the shortest encoding. Every `u32` is writable; no value is refused.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        let bytes = self.0.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        out.extend_from_slice(&bytes[start..]);
        Ok(())
    }
}

/// One option: its number and its value's bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoapOption {
    /// The option number, such as [`option::URI_PATH`].
    pub number: u16,
    /// The value, as the message carries it.
    pub value: Vec<u8>,
}

impl CoapOption {
    /// An option carrying an unsigned value in its shortest encoding.
    pub fn uint(number: u16, value: u32) -> Self {
        let mut bytes = Vec::new();
        match Uint(value).write(&mut bytes) {
            Ok(()) => {}
            Err(never) => match never {},
        }
        Self { number, value: bytes }
    }
}

/// A message's options, sorted by number, with repeats in insertion order.
/// Readers and setters preserve this order. Writers refuse decreasing numbers.
/// Callers that change the public list must keep it sorted before writing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Options(pub Vec<CoapOption>);

impl Options {
    /// No options.
    pub fn new() -> Options {
        Options::default()
    }

    /// The options, in order.
    pub fn iter(&self) -> std::slice::Iter<'_, CoapOption> {
        self.0.iter()
    }

    /// How many options there are.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The first value of option `number`.
    pub fn get(&self, number: u16) -> Option<&[u8]> {
        self.0.iter().find(|o| o.number == number).map(|o| &o.value[..])
    }

    /// Every value of option `number`, in order.
    pub fn get_all(&self, number: u16) -> impl Iterator<Item = &[u8]> {
        self.0.iter().filter(move |o| o.number == number).map(|o| &o.value[..])
    }

    /// Whether option `number` is present.
    pub fn has(&self, number: u16) -> bool {
        self.get(number).is_some()
    }

    /// Inserts option `number` with `value` after all options with the same
    /// or a lower number. Keeps repeated values in insertion order.
    pub fn add(&mut self, number: u16, value: impl Into<Vec<u8>>) {
        let at = self.0.partition_point(|o| o.number <= number);
        self.0.insert(at, CoapOption { number, value: value.into() });
    }

    /// Removes every option `number`.
    pub fn remove(&mut self, number: u16) {
        self.0.retain(|o| o.number != number);
    }

    /// Sets option `number` to `value`, removing any others of it.
    pub fn set(&mut self, number: u16, value: impl Into<Vec<u8>>) {
        self.remove(number);
        self.add(number, value);
    }

    /// The first value of option `number` read as an unsigned integer, or
    /// `None` if it is absent or longer than 4 bytes.
    pub fn uint(&self, number: u16) -> Option<u32> {
        Uint::parse(self.get(number)?).ok().map(|v| v.0)
    }

    /// The first value of registered option `number` read as an unsigned
    /// integer, or `None` if it is absent or its length is outside the
    /// registry's range. RFC 7252 section 5.4.3 treats such a value like
    /// an unrecognized option.
    fn registered_uint(&self, number: u16) -> Option<u32> {
        let value = self.get(number)?;
        let f = option_format(number)?;
        if value.len() < f.min || value.len() > f.max {
            return None;
        }
        Uint::parse(value).ok().map(|v| v.0)
    }

    /// Sets option `number` to the shortest bytes for `n`.
    pub fn set_uint(&mut self, number: u16, n: u32) {
        self.set(number, CoapOption::uint(number, n).value);
    }

    /// Every value of option `number` as text, or `None` if one is not
    /// UTF-8.
    pub fn strings(&self, number: u16) -> Option<Vec<&str>> {
        self.get_all(number).map(|v| std::str::from_utf8(v).ok()).collect()
    }

    /// The path the Uri-Path options spell, such as `/sensors/temp`, or
    /// `/` if there are none. As in RFC 7252 section 6.5, each byte of a
    /// segment that may not appear in a URI path segment is
    /// percent-encoded, so a segment holding `a/b` reads as `/a%2Fb`.
    /// `None` if a segment is not UTF-8, or is `.` or `..`, which RFC 7252
    /// section 5.10.1 forbids.
    pub fn uri_path(&self) -> Option<String> {
        self.path(option::URI_PATH)
    }

    /// Sets the Uri-Path options from `path`, as RFC 7252 section 6.4
    /// does: `/` or an empty path gives none, and otherwise each segment
    /// between slashes, empty ones included, gives one option, with
    /// percent-encodings turned back into bytes. A `%` not followed by
    /// two hex digits is kept as it is. Segments `.` and `..`, written
    /// plainly or as `%2E`, are resolved as RFC 3986 section 5.2.4 does,
    /// since RFC 7252 section 5.10.1 forbids them as option values: so
    /// `/a/../b` gives one option, `b`. A segment over 255 bytes is
    /// written as it is, and [`Message::bad_option`] then reports it.
    pub fn set_uri_path(&mut self, path: &str) {
        self.set_path(option::URI_PATH, path);
    }

    /// The path the Location-Path options of a 2.01 Created response
    /// spell, read like [`Options::uri_path`].
    pub fn location_path(&self) -> Option<String> {
        self.path(option::LOCATION_PATH)
    }

    /// Sets the Location-Path options from `path`, as
    /// [`Options::set_uri_path`] does.
    pub fn set_location_path(&mut self, path: &str) {
        self.set_path(option::LOCATION_PATH, path);
    }

    /// The path that the options numbered `number` spell.
    fn path(&self, number: u16) -> Option<String> {
        let segments = self.strings(number)?;
        if segments.iter().any(|s| is_dot_segment(s.as_bytes())) {
            return None;
        }
        if segments.is_empty() {
            return Some("/".to_string());
        }
        let mut path = String::new();
        for segment in segments {
            path.push('/');
            for &b in segment.as_bytes() {
                if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b) {
                    path.push(char::from(b));
                } else {
                    path.push('%');
                    path.push(char::from(hex_upper(b >> 4)));
                    path.push(char::from(hex_upper(b)));
                }
            }
        }
        Some(path)
    }

    /// Sets the options numbered `number` to the segments of `path`.
    fn set_path(&mut self, number: u16, path: &str) {
        self.remove(number);
        let path = path.strip_prefix('/').unwrap_or(path);
        if path.is_empty() {
            return;
        }
        let parts: Vec<&str> = path.split('/').collect();
        let mut segments: Vec<Vec<u8>> = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let segment = percent_decode(part.as_bytes());
            let last = i + 1 == parts.len();
            if is_dot_segment(&segment) {
                if segment.len() == 2 {
                    segments.pop();
                }
                // A path ending in a dot segment ends in a slash.
                if last {
                    segments.push(Vec::new());
                }
            } else {
                segments.push(segment);
            }
        }
        // Only dot segments can leave the path `/`, which has no options.
        if segments.len() == 1 && segments[0].is_empty() {
            return;
        }
        for segment in segments {
            self.add(number, segment);
        }
    }

    /// The first Uri-Host, if it is UTF-8 and 1 to 255 bytes long.
    pub fn uri_host(&self) -> Option<&str> {
        let value = self.get(option::URI_HOST)?;
        if value.is_empty() || value.len() > 255 {
            return None;
        }
        std::str::from_utf8(value).ok()
    }

    /// The Uri-Port, if one is given in 2 bytes or fewer.
    pub fn uri_port(&self) -> Option<u16> {
        self.registered_uint(option::URI_PORT).and_then(|n| u16::try_from(n).ok())
    }

    /// The Uri-Query options, each a `key=value` or a bare key, or `None`
    /// if one is not UTF-8.
    pub fn uri_query(&self) -> Option<Vec<&str>> {
        self.strings(option::URI_QUERY)
    }

    /// Sets the Uri-Query options, one for each item of `query`, in order.
    pub fn set_uri_query(&mut self, query: &[&str]) {
        self.remove(option::URI_QUERY);
        for item in query {
            self.add(option::URI_QUERY, item.as_bytes());
        }
    }

    /// The Content-Format, if one is given in 2 bytes or fewer.
    pub fn content_format(&self) -> Option<u16> {
        self.registered_uint(option::CONTENT_FORMAT).and_then(|n| u16::try_from(n).ok())
    }

    /// Sets the Content-Format.
    pub fn set_content_format(&mut self, format: u16) {
        self.set_uint(option::CONTENT_FORMAT, u32::from(format));
    }

    /// The Accept option, if one is given in 2 bytes or fewer.
    pub fn accept(&self) -> Option<u16> {
        self.registered_uint(option::ACCEPT).and_then(|n| u16::try_from(n).ok())
    }

    /// Sets the Accept option.
    pub fn set_accept(&mut self, format: u16) {
        self.set_uint(option::ACCEPT, u32::from(format));
    }

    /// The Max-Age in seconds: the option's value, or 60 if it is absent
    /// or longer than 4 bytes.
    pub fn max_age(&self) -> u32 {
        self.registered_uint(option::MAX_AGE).unwrap_or(60)
    }

    /// Sets the Max-Age in seconds.
    pub fn set_max_age(&mut self, seconds: u32) {
        self.set_uint(option::MAX_AGE, seconds);
    }

    /// The Observe value, if one is given in 3 bytes or fewer.
    pub fn observe(&self) -> Option<u32> {
        self.registered_uint(option::OBSERVE)
    }

    /// Sets the Observe value. Only its low 24 bits are kept.
    pub fn set_observe(&mut self, n: u32) {
        self.set_uint(option::OBSERVE, n & observe::MAX);
    }

    /// The Block1 option, if it is present in 3 bytes or fewer.
    pub fn block1(&self) -> Option<Block> {
        Block::from_uint(self.registered_uint(option::BLOCK1)?)
    }

    /// Sets the Block1 option.
    pub fn set_block1(&mut self, block: Block) {
        self.set_uint(option::BLOCK1, block.to_uint());
    }

    /// The Block2 option, if it is present in 3 bytes or fewer.
    pub fn block2(&self) -> Option<Block> {
        Block::from_uint(self.registered_uint(option::BLOCK2)?)
    }

    /// Sets the Block2 option.
    pub fn set_block2(&mut self, block: Block) {
        self.set_uint(option::BLOCK2, block.to_uint());
    }

    /// The Size1 option: the whole request body's size, if it is given
    /// in 4 bytes or fewer.
    pub fn size1(&self) -> Option<u32> {
        self.registered_uint(option::SIZE1)
    }

    /// Sets the Size1 option.
    pub fn set_size1(&mut self, size: u32) {
        self.set_uint(option::SIZE1, size);
    }

    /// The Size2 option: the whole response body's size, if it is given
    /// in 4 bytes or fewer.
    pub fn size2(&self) -> Option<u32> {
        self.registered_uint(option::SIZE2)
    }

    /// Sets the Size2 option.
    pub fn set_size2(&mut self, size: u32) {
        self.set_uint(option::SIZE2, size);
    }

    /// The first critical option that `format` does not know, whose value
    /// has a length outside its range or a string value that is not
    /// UTF-8, that repeats when it may not, or that is a Uri-Path of `.`
    /// or `..`. It takes time in proportion to the number of options.
    fn first_bad(&self, format: impl Fn(u16) -> Option<OptionFormat>) -> Option<u16> {
        let mut seen = std::collections::HashSet::new();
        for o in &self.0 {
            if !option::is_critical(o.number) {
                continue;
            }
            let repeated = !seen.insert(o.number);
            let bad = match format(o.number) {
                None => true,
                Some(f) => {
                    o.value.len() < f.min
                        || o.value.len() > f.max
                        || (repeated && !f.repeatable)
                        || (f.value == ValueFormat::String && std::str::from_utf8(&o.value).is_err())
                        || (o.number == option::URI_PATH && is_dot_segment(&o.value))
                }
            };
            if bad {
                return Some(o.number);
            }
        }
        None
    }
}

impl<'a> IntoIterator for &'a Options {
    type Item = &'a CoapOption;
    type IntoIter = std::slice::Iter<'a, CoapOption>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Why bytes are not a CoAP message or frame, why a value cannot be
/// written, or why a [`Reassembler`] refused a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The bytes end before the header, token or an option does, or
    /// before a complete frame arrived.
    Truncated,
    /// The UDP version field was not 1.
    Version(u8),
    /// The token length was over 8.
    TokenLength(u8),
    /// A UDP message with code 0.00 carried a token or bytes after its
    /// header.
    EmptyWithContent,
    /// A UDP message's type does not allow its code: an ACK with a code
    /// that is not 0.00 or a response, a Reset that is not empty, or an
    /// empty NON (RFC 7252 sections 4.2 and 4.3). A receiver ignores it.
    TypeAndCode(Type, Code),
    /// An option's delta or length field was 15, which is reserved.
    ReservedNibble,
    /// An option number went past 65535.
    OptionNumber,
    /// An option value was longer than [`MAX_OPTION_VALUE`].
    OptionTooLong(usize),
    /// There were more than [`MAX_OPTIONS`] options.
    TooManyOptions,
    /// The payload marker came with no payload after it.
    EmptyPayload,
    /// A datagram over [`MAX_DATAGRAM`] bytes, or a frame body over
    /// [`MAX_FRAME_BODY`].
    TooLong(u64),
    /// Bytes followed the frame.
    Trailing,
    /// The value cannot be written without changing it: a field exceeds
    /// its limit, options are out of order, or the message type does not
    /// allow its contents.
    Unwritable,
    /// The block does not start where the body so far ends.
    OutOfOrder {
        /// Where the next block should start.
        expected: usize,
        /// Where this one starts.
        got: usize,
    },
    /// A block with more after it was not the full block size, or a BERT
    /// block came to a reassembler that does not take them.
    BlockSize,
    /// The body would grow past the reassembler's limit.
    BodyTooLarge,
    /// The last block has already come.
    AfterLastBlock,
}

impl Error {
    /// The response code a server answers a request with when it refuses
    /// it: 4.08 Request Entity Incomplete for a block out of order, 4.13
    /// Request Entity Too Large for a body over the limit, and 4.00 Bad
    /// Request for the rest.
    pub fn code(self) -> Code {
        match self {
            Error::OutOfOrder { .. } => Code::REQUEST_ENTITY_INCOMPLETE,
            Error::BodyTooLarge => Code::REQUEST_ENTITY_TOO_LARGE,
            _ => Code::BAD_REQUEST,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("message ends early"),
            Error::Version(v) => write!(f, "version {v}, not 1"),
            Error::TokenLength(n) => write!(f, "token length {n}, over 8"),
            Error::EmptyWithContent => f.write_str("empty message (0.00) with a token or more bytes"),
            Error::TypeAndCode(t, c) => write!(f, "a {t:?} message may not carry code {c}"),
            Error::ReservedNibble => f.write_str("option delta or length 15"),
            Error::OptionNumber => f.write_str("option number past 65535"),
            Error::OptionTooLong(n) => write!(f, "option value of {n} bytes, over {MAX_OPTION_VALUE}"),
            Error::TooManyOptions => write!(f, "more than {MAX_OPTIONS} options"),
            Error::EmptyPayload => f.write_str("payload marker with no payload"),
            Error::TooLong(n) => write!(f, "{n} bytes, over the limit"),
            Error::Trailing => f.write_str("bytes after the CoAP frame"),
            Error::Unwritable => f.write_str("CoAP value cannot be written without changing it"),
            Error::OutOfOrder { expected, got } => write!(f, "block at offset {got}, expected {expected}"),
            Error::BlockSize => f.write_str("block payload is the wrong size"),
            Error::BodyTooLarge => f.write_str("body too large"),
            Error::AfterLastBlock => f.write_str("the last block has already come"),
        }
    }
}

impl std::error::Error for Error {}

/// One CoAP message over UDP.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    /// Confirmable, non-confirmable, acknowledgement or reset.
    pub kind: Type,
    /// The method or response code.
    pub code: Code,
    /// Matches an ACK or Reset to its message, and spots duplicates.
    pub message_id: u16,
    /// Matches a response to its request. Up to 8 bytes.
    pub token: Vec<u8>,
    /// The options.
    pub options: Options,
    /// The payload. Empty if the message has none.
    pub payload: Vec<u8>,
}

/// The type, code and message ID at the start of a datagram, if it has a
/// header with version 1. A world uses it to answer a confirmable
/// datagram that [`Message::parse`] refuses with [`Message::reset`].
pub fn peek_header(b: &[u8]) -> Option<(Type, Code, u16)> {
    if b.len() < HEADER_LEN || b[0] >> 6 != VERSION {
        return None;
    }
    Some((Type::from_bits(b[0] >> 4), Code(b[1]), u16::from_be_bytes([b[2], b[3]])))
}

impl Message {
    /// A message with no token, options or payload.
    pub fn new(kind: Type, code: Code, message_id: u16) -> Message {
        Message { kind, code, message_id, token: Vec::new(), options: Options::new(), payload: Vec::new() }
    }

    /// An empty ACK for message `message_id`: it arrived, and the response
    /// will come separately.
    pub fn empty_ack(message_id: u16) -> Message {
        Message::new(Type::Acknowledgement, Code::EMPTY, message_id)
    }

    /// A Reset for message `message_id`: it could not be processed.
    pub fn reset(message_id: u16) -> Message {
        Message::new(Type::Reset, Code::EMPTY, message_id)
    }

    /// An empty confirmable message, which a peer answers with a Reset:
    /// the CoAP ping.
    pub fn ping(message_id: u16) -> Message {
        Message::new(Type::Confirmable, Code::EMPTY, message_id)
    }

    /// A response to this request with `code` and the same token. A
    /// confirmable request gets a piggybacked ACK with its own message ID;
    /// any other gets a non-confirmable response with `message_id`.
    pub fn reply(&self, code: Code, message_id: u16) -> Message {
        let (kind, id) = match self.kind {
            Type::Confirmable => (Type::Acknowledgement, self.message_id),
            _ => (Type::NonConfirmable, message_id),
        };
        Message { token: self.token.clone(), ..Message::new(kind, code, id) }
    }

    /// The Block1 or Block2 option, if either has SZX 7. RFC 7959 section
    /// 2.2 reserves that size over UDP: a server answers a request that
    /// carries one with 4.00 Bad Request.
    pub fn bad_block(&self) -> Option<u16> {
        [option::BLOCK1, option::BLOCK2].into_iter().find(|&n| {
            let block = self.options.registered_uint(n).and_then(Block::from_uint);
            block.is_some_and(Block::is_bert)
        })
    }

    /// The first critical option this message carries that the registry
    /// does not list, whose value has a length outside the registry's
    /// range or is a string that is not UTF-8, that repeats when it may
    /// not, or that is a Uri-Path of `.` or `..` (RFC 7252 section
    /// 5.10.1). A server answers a request
    /// that has one with 4.02 Bad Option, and a client rejects such a
    /// response. Elective options with these faults are ignored, so they
    /// are not reported. A world that does not act on a critical option
    /// in the registry should answer 4.02 itself.
    pub fn bad_option(&self) -> Option<u16> {
        self.options.first_bad(option_format)
    }
}

/// One CoAP message over TCP (RFC 8323): no type or message ID, since TCP
/// is already reliable, and a length up front.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Frame {
    /// The method, response or signal code.
    pub code: Code,
    /// Matches a response to its request. Up to 8 bytes.
    pub token: Vec<u8>,
    /// The options. In a signal frame (class 7) they are numbered as in
    /// [`signal`].
    pub options: Options,
    /// The payload. Empty if the frame has none.
    pub payload: Vec<u8>,
}

impl Frame {
    /// A frame with no token, options or payload.
    pub fn new(code: Code) -> Frame {
        Frame { code, token: Vec::new(), options: Options::new(), payload: Vec::new() }
    }

    /// A CSM frame saying the largest message this side accepts, and
    /// whether it accepts BERT block-wise transfer.
    pub fn csm(max_message_size: u32, block_wise: bool) -> Frame {
        let mut f = Frame::new(Code::CSM);
        f.options.set_uint(signal::MAX_MESSAGE_SIZE, max_message_size);
        if block_wise {
            f.options.set(signal::BLOCK_WISE_TRANSFER, Vec::new());
        }
        f
    }

    /// The Max-Message-Size of a CSM frame, if it gives one.
    pub fn max_message_size(&self) -> Option<u32> {
        if self.code == Code::CSM { self.options.uint(signal::MAX_MESSAGE_SIZE) } else { None }
    }

    /// The Pong that answers this Ping, with the same token.
    pub fn pong(&self) -> Frame {
        Frame { token: self.token.clone(), ..Frame::new(Code::PONG) }
    }

    /// A response to this request with `code` and the same token.
    pub fn reply(&self, code: Code) -> Frame {
        Frame { token: self.token.clone(), ..Frame::new(code) }
    }

    /// Reads the frame at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the frame and how many bytes
    /// of `b` it took.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
        let Some(&first) = b.first() else { return Ok(None) };
        let (nibble, tkl) = (first >> 4, first & 0x0f);
        if usize::from(tkl) > MAX_TOKEN {
            return Err(Error::TokenLength(tkl));
        }
        let ext = match nibble {
            13 => 1,
            14 => 2,
            15 => 4,
            _ => 0,
        };
        if b.len() < 1 + ext {
            return Ok(None);
        }
        let len: u64 = match nibble {
            13 => 13 + u64::from(b[1]),
            14 => 269 + u64::from(u16::from_be_bytes([b[1], b[2]])),
            15 => 65_805 + u64::from(u32::from_be_bytes([b[1], b[2], b[3], b[4]])),
            n => u64::from(n),
        };
        if len > MAX_FRAME_BODY as u64 {
            return Err(Error::TooLong(len));
        }
        // At most 6 + 8 + MAX_FRAME_BODY, so this cannot overflow.
        let start = 2 + ext + usize::from(tkl);
        let total = start + len as usize;
        if b.len() < total {
            return Ok(None);
        }
        let code = Code(b[1 + ext]);
        let token = b[2 + ext..start].to_vec();
        let (options, payload) = read_body(&b[start..total])?;
        Ok(Some((Frame { code, token, options, payload }, total)))
    }

    /// Like [`Message::bad_option`]. In a signal frame, options are
    /// checked against the signal's own options.
    pub fn bad_option(&self) -> Option<u16> {
        if self.code.is_signal() {
            self.options.first_bad(|n| signal_option_format(self.code, n))
        } else {
            self.options.first_bad(option_format)
        }
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one UDP datagram. Refuses bad versions, token lengths, type/code pairs, empty content, malformed options, and size limits.
    fn parse(b: &[u8]) -> Result<Message, Error> {
        if b.len() > MAX_DATAGRAM {
            return Err(Error::TooLong(b.len() as u64));
        }
        let (kind, code, message_id) = match peek_header(b) {
            Some(h) => h,
            None if b.len() < HEADER_LEN => return Err(Error::Truncated),
            None => return Err(Error::Version(b[0] >> 6)),
        };
        let tkl = b[0] & 0x0f;
        if usize::from(tkl) > MAX_TOKEN {
            return Err(Error::TokenLength(tkl));
        }
        if code.is_empty() && (tkl != 0 || b.len() != HEADER_LEN) {
            return Err(Error::EmptyWithContent);
        }
        if !valid_type_code(kind, code) {
            return Err(Error::TypeAndCode(kind, code));
        }
        if code.is_empty() {
            return Ok(Message::new(kind, code, message_id));
        }
        let end = HEADER_LEN + usize::from(tkl);
        let token = b.get(HEADER_LEN..end).ok_or(Error::Truncated)?.to_vec();
        let (options, payload) = read_body(&b[end..])?;
        Ok(Message { kind, code, message_id, token, options, payload })
    }

    /// Appends a datagram. Refuses invalid type/code pairs, empty content,
    /// long tokens, unsorted options, and size limits. Leaves `out` unchanged
    /// on error. [`Message::bad_block`] remains a separate UDP check.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !valid_type_code(self.kind, self.code)
            || self.token.len() > MAX_TOKEN
            || (self.code.is_empty()
                && (!self.token.is_empty() || !self.options.is_empty() || !self.payload.is_empty()))
        {
            return Err(Error::Unwritable);
        }
        let mut bytes = vec![VERSION << 6 | self.kind.bits() << 4 | self.token.len() as u8, self.code.0];
        bytes.extend_from_slice(&self.message_id.to_be_bytes());
        bytes.extend_from_slice(&self.token);
        write_body(&mut bytes, &self.options, &self.payload, MAX_DATAGRAM - HEADER_LEN - self.token.len())?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one TCP frame, with at most [`MAX_FRAME_BODY`] body bytes.
    /// Refuses long tokens, malformed options, incomplete frames, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Self::parse_prefix(bytes)? {
            Some((frame, used)) if used == bytes.len() => Ok(frame),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Truncated),
        }
    }

    /// Appends a TCP frame. Refuses long tokens, unsorted options, and size
    /// limits. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.token.len() > MAX_TOKEN {
            return Err(Error::Unwritable);
        }
        let mut body = Vec::new();
        write_body(&mut body, &self.options, &self.payload, MAX_FRAME_BODY)?;
        let len = body.len();
        let tkl = self.token.len() as u8;
        if len < 13 {
            out.push((len as u8) << 4 | tkl);
        } else if len < 269 {
            out.push(13 << 4 | tkl);
            out.push((len - 13) as u8);
        } else if len < 65_805 {
            out.push(14 << 4 | tkl);
            out.extend_from_slice(&((len - 269) as u16).to_be_bytes());
        } else {
            out.push(15 << 4 | tkl);
            out.extend_from_slice(&((len - 65_805) as u32).to_be_bytes());
        }
        out.push(self.code.0);
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&body);
        Ok(())
    }
}

/// Reads CoAP over TCP frames without retaining input bytes.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for at most [`MAX_BUFFERED`] unread
/// bytes. Header and body errors end the stream.
/// Partial frames return [`fictionet::stdlib::codec::Step::Need`], including at EOF. The driver
/// reports truncation. UDP datagrams use [`Wire`] on [`Message`] directly.
///
/// ```
/// use fictionet::stdlib::codec::Frames;
/// use fictionet::stdlib::coap::Frame;
/// use fictionet::stdlib::codec::{Stream, Wire};
///
/// let frame = Frame::csm(4096, true);
/// let bytes = Wire::to_bytes(&frame)?;
/// let mut stream = Stream::new(Frames::<Frame>::new());
/// assert_eq!(stream.push(&bytes), bytes.len());
/// assert_eq!(stream.next(), Some(Ok(frame)));
/// stream.end();
/// assert_eq!(stream.next(), None);
/// # Ok::<(), fictionet::stdlib::coap::Error>(())
/// ```
impl Prefixed for Frame {
    type Item = Frame;
    type Error = Error;
    type Limit = ();
    const NAME: &'static str = "CoAP over TCP";

    #[inline]
    fn default_limit() -> Self::Limit {}

    #[inline]
    fn capacity(_limit: &Self::Limit) -> usize {
        MAX_BUFFERED
    }

    #[inline]
    fn parse_prefix(input: &[u8], _limit: &Self::Limit) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        Frame::parse_prefix(input)
    }
}


/// A Block1 or Block2 option (RFC 7959): which block of a body this is,
/// whether more follow, and the block size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    /// The block number, from 0. At most [`Block::MAX_NUM`].
    pub num: u32,
    /// Whether more blocks follow. In a Block1 response, or a Block2
    /// request, it has other meanings; see RFC 7959 section 2.3.
    pub more: bool,
    /// The size exponent: blocks are `16 << szx` bytes. 0 to 6. 7 is
    /// reserved over UDP; over TCP it means BERT, blocks of one or more
    /// 1024-byte units (RFC 8323 section 6).
    pub szx: u8,
}

impl Block {
    /// The largest block number: it is 20 bits.
    pub const MAX_NUM: u32 = (1 << 20) - 1;
    /// The szx value that means BERT over TCP.
    pub const BERT: u8 = 7;

    /// The block an option value holds, or `None` if it is over 24 bits.
    pub fn from_uint(n: u32) -> Option<Block> {
        if n > 0xff_ffff {
            return None;
        }
        Some(Block { num: n >> 4, more: n & 8 != 0, szx: (n & 7) as u8 })
    }

    /// The option value for this block. Only the low 20 bits of `num` and
    /// the low 3 bits of `szx` are kept.
    pub fn to_uint(self) -> u32 {
        (self.num & Block::MAX_NUM) << 4 | u32::from(self.more) << 3 | u32::from(self.szx & 7)
    }

    /// The size exponent for a block size of `size` bytes, if it is a
    /// power of two from 16 to 1024.
    pub fn szx_for(size: usize) -> Option<u8> {
        (0..=6u8).find(|&s| 16usize << s == size)
    }

    /// The block size in bytes: `16 << szx`, or 1024 for BERT.
    pub fn size(self) -> usize {
        16 << (self.szx & 7).min(6)
    }

    /// Whether this is a BERT block.
    pub fn is_bert(self) -> bool {
        self.szx & 7 == Block::BERT
    }

    /// Where the block starts in the body: `num` times the size.
    pub fn offset(self) -> usize {
        (self.num & Block::MAX_NUM) as usize * self.size()
    }

    /// Block `num` of `body` in blocks of `16 << szx` bytes, with `more`
    /// set unless it is the last. `None` if `szx` is over 6, `num` is past
    /// [`Block::MAX_NUM`], or the body has no such block. An empty body
    /// has one empty block, block 0.
    pub fn take(body: &[u8], num: u32, szx: u8) -> Option<(Block, &[u8])> {
        if szx > 6 || num > Block::MAX_NUM {
            return None;
        }
        let block = Block { num, more: false, szx };
        let offset = block.offset();
        if offset > body.len() || (offset == body.len() && num > 0) {
            return None;
        }
        let end = body.len().min(offset + block.size());
        Some((Block { more: end < body.len(), ..block }, &body[offset..end]))
    }
}

/// Puts a body back together from its blocks, as they come in order. A
/// server uses it for a Block1 request body, a client for a Block2
/// response. The block size may shrink partway, as RFC 7959 allows.
/// There is no default: the largest body is always chosen with
/// [`Reassembler::new`] or [`Reassembler::with_bert`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reassembler {
    body: Vec<u8>,
    max: usize,
    done: bool,
    bert: bool,
}

impl Reassembler {
    /// A reassembler that takes bodies of up to `max` bytes, and never more
    /// than [`MAX_BODY`]. It refuses BERT blocks (SZX 7) with
    /// [`Error::BlockSize`], whose code is 4.00 Bad Request, as RFC 7959
    /// section 2.2 asks over UDP.
    pub fn new(max: usize) -> Reassembler {
        Reassembler { body: Vec::new(), max: max.min(MAX_BODY), done: false, bert: false }
    }

    /// Like [`Reassembler::new`], but it also takes BERT blocks, for CoAP
    /// over TCP once the peer's CSM offered Block-Wise-Transfer (RFC 8323
    /// section 6).
    pub fn with_bert(max: usize) -> Reassembler {
        Reassembler { bert: true, ..Reassembler::new(max) }
    }

    /// Adds the next block and its payload. It returns whether the body
    /// is now whole. A refused block changes nothing.
    pub fn push(&mut self, block: Block, payload: &[u8]) -> Result<bool, Error> {
        if self.done {
            return Err(Error::AfterLastBlock);
        }
        let got = block.offset();
        if got != self.body.len() {
            return Err(Error::OutOfOrder { expected: self.body.len(), got });
        }
        // RFC 7959 section 2.3: SZX does not govern the payload size of
        // the last block.
        let size_ok = match (block.is_bert(), block.more) {
            (true, _) if !self.bert => false,
            (false, true) => payload.len() == block.size(),
            (true, true) => !payload.is_empty() && payload.len().is_multiple_of(1024),
            (_, false) => true,
        };
        if !size_ok {
            return Err(Error::BlockSize);
        }
        if payload.len() > self.max - self.body.len() {
            return Err(Error::BodyTooLarge);
        }
        self.body.extend_from_slice(payload);
        self.done = !block.more;
        Ok(self.done)
    }

    /// Whether the last block has come.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The body so far.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The body, taken out.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// Whether Observe value `new` is fresher than `old`, which came
/// `seconds_between` seconds before it (RFC 7641 section 3.4). The values
/// wrap around at 24 bits; after 128 seconds a notification counts as
/// fresher whatever its number.
pub fn observe_is_newer(old: u32, new: u32, seconds_between: u64) -> bool {
    let (v1, v2) = (old & observe::MAX, new & observe::MAX);
    let half = 1 << 23;
    (v1 < v2 && v2 - v1 < half) || (v1 > v2 && v1 - v2 > half) || seconds_between > 128
}

/// Whether RFC 7252 sections 4.2 and 4.3 allow this type and code together.
fn valid_type_code(kind: Type, code: Code) -> bool {
    match kind {
        Type::Reset => code.is_empty(),
        Type::Acknowledgement => code.is_empty() || code.is_response(),
        Type::NonConfirmable => !code.is_empty(),
        Type::Confirmable => true,
    }
}

/// Whether a path segment is `.` or `..`.
fn is_dot_segment(s: &[u8]) -> bool {
    s == b"." || s == b".."
}

/// `s` with each `%` and two hex digits turned into the byte they spell.
fn percent_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    ascii::percent_decode_into(s, false, &mut out, usize::MAX);
    out
}

/// Reads options and a payload: what follows the token in a message or a
/// frame.
fn read_body(b: &[u8]) -> Result<(Options, Vec<u8>), Error> {
    let mut options = Vec::new();
    let mut number: u32 = 0;
    let mut i = 0;
    while let Some(&first) = b.get(i) {
        i += 1;
        if first == PAYLOAD_MARKER {
            if i == b.len() {
                return Err(Error::EmptyPayload);
            }
            return Ok((Options(options), b[i..].to_vec()));
        }
        let delta = read_ext(b, &mut i, first >> 4)?;
        let length = read_ext(b, &mut i, first & 0x0f)? as usize;
        number += delta;
        let Ok(n) = u16::try_from(number) else { return Err(Error::OptionNumber) };
        if length > MAX_OPTION_VALUE {
            return Err(Error::OptionTooLong(length));
        }
        if options.len() == MAX_OPTIONS {
            return Err(Error::TooManyOptions);
        }
        let value = b.get(i..i + length).ok_or(Error::Truncated)?;
        i += length;
        options.push(CoapOption { number: n, value: value.to_vec() });
    }
    Ok((Options(options), Vec::new()))
}

/// Reads an option delta or length from its 4-bit field and any extended
/// bytes after `*i`.
fn read_ext(b: &[u8], i: &mut usize, nibble: u8) -> Result<u32, Error> {
    match nibble {
        13 => {
            let &x = b.get(*i).ok_or(Error::Truncated)?;
            *i += 1;
            Ok(13 + u32::from(x))
        }
        14 => {
            let x = b.get(*i..*i + 2).ok_or(Error::Truncated)?;
            *i += 2;
            Ok(269 + u32::from(u16::from_be_bytes([x[0], x[1]])))
        }
        15 => Err(Error::ReservedNibble),
        n => Ok(u32::from(n)),
    }
}

/// The 4-bit field and extended bytes for an option delta or length.
fn ext(v: usize) -> (u8, Vec<u8>) {
    if v < 13 {
        (v as u8, Vec::new())
    } else if v < 269 {
        (13, vec![(v - 13) as u8])
    } else {
        (14, ((v - 269) as u16).to_be_bytes().to_vec())
    }
}

fn write_body(out: &mut Vec<u8>, options: &Options, payload: &[u8], budget: usize) -> Result<(), Error> {
    if options.0.len() > MAX_OPTIONS {
        return Err(Error::Unwritable);
    }
    let mut used = 0usize;
    let mut prev = 0u16;
    for o in &options.0 {
        if o.value.len() > MAX_OPTION_VALUE {
            return Err(Error::Unwritable);
        }
        let delta = o.number.checked_sub(prev).ok_or(Error::Unwritable)?;
        let (dn, dx) = ext(usize::from(delta));
        let (ln, lx) = ext(o.value.len());
        let size = 1 + dx.len() + lx.len() + o.value.len();
        used = used.checked_add(size).filter(|&n| n <= budget).ok_or(Error::Unwritable)?;
        out.push(dn << 4 | ln);
        out.extend_from_slice(&dx);
        out.extend_from_slice(&lx);
        out.extend_from_slice(&o.value);
        prev = o.number;
    }
    if !payload.is_empty() {
        if payload.len().checked_add(1).filter(|&n| n <= budget - used).is_none() {
            return Err(Error::Unwritable);
        }
        out.push(PAYLOAD_MARKER);
        out.extend_from_slice(payload);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::codec::{Step, Decode};
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream, contract, pump,
        test_support::{decode_all, mutate},
    };

    fn get(path: &str, id: u16, token: &[u8]) -> Message {
        let mut m = Message::new(Type::Confirmable, Code::GET, id);
        m.token = token.to_vec();
        m.options.set_uri_path(path);
        m
    }

    // RFC 7252 section 3 and appendix A: the header, and a GET with its
    // piggybacked response.

    #[test]
    fn header_layout() {
        let m = get("/temperature", 0x7d34, &[]);
        let bytes = m.to_bytes().unwrap();
        // Ver 1, CON, TKL 0; GET; message ID; Uri-Path (delta 11, length 11).
        assert_eq!(&bytes[..5], &[0x40, 0x01, 0x7d, 0x34, 0xbb]);
        assert_eq!(&bytes[5..], b"temperature");
        assert_eq!(Message::parse(&bytes), Ok(m));
        assert_eq!(peek_header(&bytes), Some((Type::Confirmable, Code::GET, 0x7d34)));
    }

    #[test]
    fn piggybacked_response() {
        let req = get("/temperature", 0x7d34, &[]);
        let mut resp = req.reply(Code::CONTENT, 99);
        resp.payload = b"22.3 C".to_vec();
        assert_eq!(resp.kind, Type::Acknowledgement);
        assert_eq!(resp.message_id, 0x7d34);
        assert_eq!(resp.to_bytes().unwrap(), [&[0x60, 0x45, 0x7d, 0x34, 0xff][..], b"22.3 C"].concat());
        // A non-confirmable request gets a non-confirmable answer with the new ID.
        let non = Message { kind: Type::NonConfirmable, ..req };
        let r = non.reply(Code::CONTENT, 99);
        assert_eq!((r.kind, r.message_id), (Type::NonConfirmable, 99));
    }

    #[test]
    fn empty_messages() {
        assert_eq!(Message::empty_ack(5).to_bytes().unwrap(), [0x60, 0, 0, 5]);
        assert_eq!(Message::reset(5).to_bytes().unwrap(), [0x70, 0, 0, 5]);
        assert_eq!(Message::ping(5).to_bytes().unwrap(), [0x40, 0, 0, 5]);
        assert_eq!(Message::parse(&[0x70, 0, 0, 5]), Ok(Message::reset(5)));
        // An empty message with a token or bytes after the header.
        assert_eq!(Message::parse(&[0x41, 0, 0, 5, 1]), Err(Error::EmptyWithContent));
        assert_eq!(Message::parse(&[0x40, 0, 0, 5, 0xff]), Err(Error::EmptyWithContent));
        // A writer refuses the invalid content.
        let mut m = Message::reset(5);
        m.token = vec![1, 2];
        m.payload = vec![3];
        assert!(m.to_bytes().is_err());
    }

    #[test]
    fn codes() {
        assert_eq!(Code::CONTENT.to_string(), "2.05");
        assert_eq!(Code::NOT_FOUND.to_string(), "4.04");
        assert_eq!(Code::CSM.to_string(), "7.01");
        assert_eq!(Code::new(2, 31), Some(Code::CONTINUE));
        assert_eq!(Code::new(8, 0), None);
        assert_eq!(Code::new(0, 32), None);
        assert!(Code::GET.is_request() && !Code::EMPTY.is_request());
        assert!(Code::GATEWAY_TIMEOUT.is_response() && !Code::GET.is_response());
        assert!(Code::PING.is_signal());
        for b in 0..=3 {
            assert_eq!(Type::from_bits(b).bits(), b);
        }
    }

    #[test]
    fn option_extended_forms() {
        // Deltas and lengths at each boundary: 12, 13, 268, 269.
        for (number, len) in [(12u16, 12usize), (13, 13), (268, 268), (269, 269), (65535, 1034)] {
            let mut m = Message::new(Type::NonConfirmable, Code::POST, 1);
            m.options.add(number, vec![0xaa; len]);
            let bytes = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes), Ok(m), "{number} {len}");
        }
        // Delta 13 is nibble 13 and one byte of 0.
        let mut m = Message::new(Type::Confirmable, Code::GET, 0);
        m.options.add(13, Vec::new());
        assert_eq!(&m.to_bytes().unwrap()[4..], [0xd0, 0x00]);
        // Delta 269 is nibble 14 and two bytes of 0.
        let mut m = Message::new(Type::Confirmable, Code::GET, 0);
        m.options.add(269, Vec::new());
        assert_eq!(&m.to_bytes().unwrap()[4..], [0xe0, 0x00, 0x00]);
        // The largest delta reaches 65535 exactly once.
        let mut m = Message::new(Type::Confirmable, Code::GET, 0);
        m.options.add(65535, Vec::new());
        assert_eq!(&m.to_bytes().unwrap()[4..], [0xe0, 0xfe, 0xf2]);
    }

    #[test]
    fn option_errors() {
        let head = [0x40, 0x01, 0, 1];
        let with = |rest: &[u8]| Message::parse(&[&head[..], rest].concat());
        assert_eq!(with(&[0xf0]), Err(Error::ReservedNibble));
        assert_eq!(with(&[0x0f]), Err(Error::ReservedNibble));
        assert_eq!(with(&[0xff]), Err(Error::EmptyPayload));
        assert_eq!(with(&[0xd0]), Err(Error::Truncated));
        assert_eq!(with(&[0xe0, 0]), Err(Error::Truncated));
        assert_eq!(with(&[0x03, 1, 2]), Err(Error::Truncated));
        // 65535 then one more.
        assert_eq!(with(&[0xe0, 0xfe, 0xf2, 0x10]), Err(Error::OptionNumber));
        assert_eq!(with(&[0xe0, 0xff, 0xff]), Err(Error::OptionNumber));
        assert_eq!(with(&[0x0e, 0x03, 0x00]), Err(Error::OptionTooLong(1037)));
        let many = vec![0x10; MAX_OPTIONS + 1];
        assert_eq!(with(&many), Err(Error::TooManyOptions));
        assert!(with(&many[..MAX_OPTIONS]).is_ok());
        assert_eq!(Message::parse(&[0x80, 1, 0, 0]), Err(Error::Version(2)));
        assert_eq!(Message::parse(&[0x49, 1, 0, 0]), Err(Error::TokenLength(9)));
        assert_eq!(Message::parse(&[0x40, 1, 0]), Err(Error::Truncated));
        assert_eq!(Message::parse(&[0x42, 1, 0, 0, 7]), Err(Error::Truncated));
        let big = vec![0x40; MAX_DATAGRAM + 1];
        assert_eq!(Message::parse(&big), Err(Error::TooLong(MAX_DATAGRAM as u64 + 1)));
        assert_eq!(peek_header(&[0x80, 1, 0, 0]), None);
    }

    #[test]
    fn every_truncated_prefix_fails() {
        let mut m = get("/a/very/long/path/segment", 0x1234, &[1, 2, 3, 4]);
        m.options.add(option::URI_QUERY, b"x=1".to_vec());
        m.options.add(option::PROXY_URI, vec![b'a'; 300]);
        m.payload = b"hello".to_vec();
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes), Ok(m));
        // A prefix ending at an option boundary is a whole shorter
        // message; one ending at the marker has no payload. Every other
        // prefix fails.
        for n in 0..bytes.len() {
            match Message::parse(&bytes[..n]) {
                Ok(short) => assert_eq!(short.to_bytes().unwrap(), &bytes[..n]),
                Err(e) => assert!(matches!(e, Error::Truncated | Error::EmptyPayload), "{n}: {e}"),
            }
        }
        // A frame's prefixes all need more bytes.
        let f = Frame { code: Code::POST, token: vec![9; 8], options: m_options(), payload: vec![7; 400] };
        let bytes = f.to_bytes().unwrap();
        for n in 0..bytes.len() {
            assert_eq!(Frame::parse(&bytes[..n]), Err(Error::Truncated), "{n}");
        }
        assert_eq!(Frame::parse(&bytes), Ok(f));
    }

    fn m_options() -> Options {
        let mut o = Options::new();
        o.set_uri_path("/fw/image");
        o.set_block1(Block { num: 3, more: true, szx: 6 });
        o.set_size1(20_000);
        o
    }

    #[test]
    fn setters_keep_options_in_number_order() {
        let mut observe = get("/temp", 1, &[]);
        observe.options.set_observe(0);
        let mut block = Message::new(Type::Confirmable, Code::GET, 2);
        block.options.set_block2(Block { num: 0, more: false, szx: 4 });
        block.options.set_uri_path("/a/b");
        let mut reply = observe.reply(Code::CONTENT, 3);
        reply.options.set_max_age(10);
        reply.options.set_content_format(0);
        for message in [observe, block, reply] {
            let bytes = message.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes), Ok(message.clone()));
            contract::check_wire_value(&message);
        }
        let mut options = Options::new();
        options.add(option::URI_PATH, b"a".to_vec());
        options.add(option::URI_QUERY, b"q=1".to_vec());
        options.add(option::URI_PATH, b"b".to_vec());
        options.set_uint(option::OBSERVE, 1);
        assert_eq!(options.iter().map(|o| o.number).collect::<Vec<_>>(), [6, 11, 11, 15]);
        assert_eq!(options.get_all(option::URI_PATH).collect::<Vec<_>>(), [b"a", b"b"]);
    }

    #[test]
    fn options_sort_and_typed_values() {
        let mut m = Message::new(Type::Confirmable, Code::PUT, 1);
        m.options.set_content_format(content_format::JSON);
        m.options.set_uri_path("/a/b");
        m.options.add(option::URI_QUERY, b"k=v".to_vec());
        m.options.set_uri_path("/x//y/");
        m.options.set_observe(0x0100_0005);
        m.options.set_uint(option::MAX_AGE, 0);
        let back = Message::parse(&m.to_bytes().unwrap()).unwrap();
        let numbers: Vec<u16> = back.options.iter().map(|o| o.number).collect();
        assert_eq!(numbers, [6, 11, 11, 11, 11, 12, 14, 15]);
        assert_eq!(back.options.uri_path().as_deref(), Some("/x//y/"));
        assert_eq!(back.options.uri_query(), Some(vec!["k=v"]));
        assert_eq!(back.options.content_format(), Some(50));
        assert_eq!(back.options.observe(), Some(5));
        assert_eq!(back.options.max_age(), 0);
        assert_eq!(back.options.get(option::MAX_AGE), Some(&[][..]));
        assert_eq!(Message::new(Type::Confirmable, Code::GET, 0).options.uri_path().as_deref(), Some("/"));
        assert_eq!(Options::new().max_age(), 60);
        assert_eq!(Uint(0).to_bytes().unwrap(), Vec::<u8>::new());
        assert_eq!(Uint(0x1234).to_bytes().unwrap(), [0x12, 0x34]);
        assert_eq!(Uint::parse(&[0, 0, 1]).ok().map(|v| v.0), Some(1));
        assert_eq!(Uint::parse(&[1, 0, 0, 0, 0]).ok().map(|v| v.0), None);
        let mut o = Options::new();
        o.add(option::URI_PATH, vec![0xff]);
        assert_eq!(o.uri_path(), None);
        o.add(option::ACCEPT, vec![1, 0, 0]);
        assert_eq!(o.accept(), None);
        assert!(o.has(option::ACCEPT) && o.len() == 2 && !o.is_empty());
        o.remove(option::ACCEPT);
        assert!(!o.has(option::ACCEPT));
    }

    #[test]
    fn critical_and_bad_options() {
        assert!(option::is_critical(option::URI_PATH) && !option::is_critical(option::ETAG));
        assert!(option::is_unsafe(option::URI_HOST) && !option::is_unsafe(option::ETAG));
        assert!(option::is_no_cache_key(option::SIZE1) && !option::is_no_cache_key(option::URI_PATH));
        let mut m = get("/x", 1, &[]);
        assert_eq!(m.bad_option(), None);
        // An unknown elective option is ignored; an unknown critical one is not.
        m.options.add(2000, Vec::new());
        assert_eq!(m.bad_option(), None);
        m.options.add(2001, Vec::new());
        assert_eq!(m.bad_option(), Some(2001));
        // A critical option of the wrong length, or repeated.
        let mut m = get("/x", 1, &[]);
        m.options.add(option::URI_HOST, Vec::new());
        assert_eq!(m.bad_option(), Some(option::URI_HOST));
        let mut m = get("/x", 1, &[]);
        m.options.set_size2(10);
        m.options.add(option::SIZE2, vec![1]);
        assert_eq!(m.bad_option(), None, "Size2 is elective");
        m.options.set_block2(Block { num: 0, more: false, szx: 2 });
        m.options.add(option::BLOCK2, vec![1]);
        assert_eq!(m.bad_option(), Some(option::BLOCK2));
        assert_eq!(option_format(option::PROXY_URI).unwrap().max, MAX_OPTION_VALUE);
        assert_eq!(option_format(999), None);
        // Signal options are numbered apart.
        let csm = Frame::csm(1152, true);
        assert_eq!(csm.bad_option(), None);
        assert_eq!(csm.max_message_size(), Some(1152));
        let mut ping = Frame::new(Code::PING);
        ping.options.add(signal::CUSTODY, Vec::new());
        assert_eq!(ping.bad_option(), None);
        ping.options.add(3, Vec::new());
        assert_eq!(ping.bad_option(), Some(3));
        assert_eq!(Frame::new(Code::PING).max_message_size(), None);
    }

    // Problems found in review, one test each.

    #[test]
    fn q_block2_may_repeat() {
        // RFC 9177 section 4.1: Q-Block2 repeats when asking for missing
        // blocks; Q-Block1 does not.
        assert!(option_format(option::Q_BLOCK2).unwrap().repeatable);
        assert!(!option_format(option::Q_BLOCK1).unwrap().repeatable);
        let mut m = get("/x", 1, &[]);
        m.options.add(option::Q_BLOCK2, vec![0x16]);
        m.options.add(option::Q_BLOCK2, vec![0x36]);
        assert_eq!(m.bad_option(), None);
    }

    #[test]
    fn typed_values_outside_the_registry_length_are_ignored() {
        // RFC 7252 section 5.4.3: a value of the wrong length is treated
        // like an unrecognized option, even with leading zero bytes.
        let mut o = Options::new();
        o.add(option::OBSERVE, vec![0, 0, 0, 5]);
        o.add(option::CONTENT_FORMAT, vec![0, 0, 50]);
        o.add(option::ACCEPT, vec![0, 0, 0, 50]);
        o.add(option::BLOCK1, vec![0, 0, 0, 0x1e]);
        o.add(option::BLOCK2, vec![0, 0, 0, 0x1e]);
        o.add(option::MAX_AGE, vec![0, 0, 0, 0, 9]);
        o.add(option::SIZE1, vec![0, 0, 0, 0, 9]);
        o.add(option::SIZE2, vec![0, 0, 0, 0, 9]);
        assert_eq!(o.observe(), None);
        assert_eq!(o.content_format(), None);
        assert_eq!(o.accept(), None);
        assert_eq!(o.block1(), None);
        assert_eq!(o.block2(), None);
        assert_eq!(o.max_age(), 60);
        assert_eq!((o.size1(), o.size2()), (None, None));
        // Leading zeros within the range still read.
        let mut o = Options::new();
        o.add(option::OBSERVE, vec![0, 0, 5]);
        o.add(option::CONTENT_FORMAT, vec![0, 50]);
        o.add(option::BLOCK2, vec![0, 0, 0x1e]);
        assert_eq!(o.observe(), Some(5));
        assert_eq!(o.content_format(), Some(50));
        assert_eq!(o.block2().map(|b| b.num), Some(1));
    }

    #[test]
    fn uri_path_percent_encodes_segments() {
        // RFC 7252 section 6.5 step 8: a slash inside a segment is
        // percent-encoded, so one segment never reads as two.
        let mut o = Options::new();
        o.add(option::URI_PATH, b"admin/secret".to_vec());
        assert_eq!(o.uri_path().as_deref(), Some("/admin%2Fsecret"));
        o.set_uri_path("/a b/%2F/caf\u{e9}");
        let segments: Vec<&[u8]> = o.get_all(option::URI_PATH).collect();
        assert_eq!(segments, [&b"a b"[..], b"/", "caf\u{e9}".as_bytes()]);
        assert_eq!(o.uri_path().as_deref(), Some("/a%20b/%2F/caf%C3%A9"));
        // Section 6.4 step 8: "/" means no options, and empty segments
        // inside a longer path are kept.
        o.set_uri_path("/");
        assert!(o.is_empty());
        o.set_uri_path("/x//y/");
        assert_eq!(o.get_all(option::URI_PATH).count(), 4);
        assert_eq!(o.uri_path().as_deref(), Some("/x//y/"));
        // A bad percent-encoding is kept as it is written.
        o.set_uri_path("/50%/%zz");
        assert_eq!(o.uri_path().as_deref(), Some("/50%25/%25zz"));
        for p in ["/temp", "/a/b:c@d", "/~u/-._!$&'()*+,;="] {
            o.set_uri_path(p);
            assert_eq!(o.uri_path().as_deref(), Some(p));
        }
    }

    #[test]
    fn more_accessors_for_world_authors() {
        // A 2.01 Created reply names the new resource with Location-Path.
        let mut o = Options::new();
        o.set_location_path("/logs/17");
        assert_eq!(o.get_all(option::LOCATION_PATH).count(), 2);
        assert_eq!(o.location_path().as_deref(), Some("/logs/17"));
        assert_eq!(o.uri_path().as_deref(), Some("/"));
        o.set_uri_query(&["a=1", "b"]);
        assert_eq!(o.uri_query(), Some(vec!["a=1", "b"]));
        o.set_uri_query(&[]);
        assert_eq!(o.uri_query(), Some(vec![]));
        o.set_accept(content_format::CBOR);
        o.set_max_age(0);
        assert_eq!((o.accept(), o.max_age()), (Some(60), 0));
        assert_eq!(o.uri_host(), None);
        o.add(option::URI_HOST, b"example.net".to_vec());
        o.add(option::URI_PORT, vec![0x16, 0x33]);
        assert_eq!((o.uri_host(), o.uri_port()), (Some("example.net"), Some(5683)));
        o.set(option::URI_HOST, Vec::new());
        o.set(option::URI_PORT, vec![0, 0, 1]);
        assert_eq!((o.uri_host(), o.uri_port()), (None, None));
        o.set(option::URI_HOST, vec![0xff]);
        assert_eq!(o.uri_host(), None);
        // Through a message and back.
        let mut m = Message::new(Type::Confirmable, Code::CREATED, 1);
        m.options = o.clone();
        let back = Message::parse(&m.to_bytes().unwrap()).unwrap();
        assert_eq!(back.options.location_path().as_deref(), Some("/logs/17"));
        assert_eq!(back.options.accept(), Some(60));
        assert_eq!((&o).into_iter().count(), o.len());
        let mut frames = Frames::<Frame>::new();
        assert_eq!(frames.decode(&[0x01, 0xe2], false), Ok(Step::Need));
        assert!(matches!(frames.clone().decode(&[0x01, 0xe2, 0x42], false), Ok(Step::Item(_, 3))));
    }

    #[test]
    fn writers_preserve_conditions_and_refuse_changes() {
        let mut m = Message::new(Type::Confirmable, Code::PUT, 1);
        m.options.add(option::IF_NONE_MATCH, Vec::new());
        for i in 0..MAX_OPTIONS {
            m.options.add(option::URI_QUERY, format!("k{i}").into_bytes());
        }
        m.payload = b"new".to_vec();
        assert!(m.to_bytes().is_err());
        contract::check_wire_value(&m);
        m.options.remove(option::URI_QUERY);
        m.options.add(option::URI_QUERY, b"k".to_vec());
        let back = Message::parse(&m.to_bytes().unwrap()).unwrap();
        assert!(back.options.has(option::IF_NONE_MATCH));
        let mut invalid = vec![];
        let mut t = m.clone();
        t.token = vec![1; 9];
        invalid.push(t);
        let mut v = m.clone();
        v.options.add(option::PROXY_URI, vec![b'u'; MAX_OPTION_VALUE + 1]);
        invalid.push(v);
        let mut p = m.clone();
        p.payload = vec![0; MAX_DATAGRAM];
        invalid.push(p);
        let mut e = Message::reset(1);
        e.payload = vec![1];
        invalid.push(e);
        let mut e = Message::reset(1);
        e.token = vec![1];
        invalid.push(e);
        let mut e = Message::reset(1);
        e.options.add(1, vec![]);
        invalid.push(e);
        let mut unsorted = m.clone();
        unsorted.options.0.reverse();
        invalid.push(unsorted);
        for value in invalid {
            assert!(value.to_bytes().is_err());
            contract::check_wire_value(&value);
        }
        assert_eq!(Message::reset(1).to_bytes().unwrap(), [0x70, 0, 0, 1]);
        let f = Frame { code: Code::PUT, token: vec![1; 9], options: Options::new(), payload: Vec::new() };
        assert!(f.to_bytes().is_err());
        contract::check_wire_value(&f);
        let f = Frame { token: vec![1; 8], ..f };
        contract::check_wire_value(&f);
        let f = Frame { payload: vec![0; MAX_FRAME_BODY], ..f };
        assert!(f.to_bytes().is_err());
        contract::check_wire_value(&f);
    }

    #[test]
    fn stream_holds_at_most_max_buffered() {
        let mut junk = vec![0; MAX_BUFFERED + 100];
        junk[0] = 9;
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &junk, 2 * MAX_BUFFERED);
        assert_eq!(decode_all(Frames::<Frame>::new, &junk).1, Some(Fail::Protocol(Error::TokenLength(9))));
        let big = Frame {
            code: Code::CONTENT,
            token: vec![1; MAX_TOKEN],
            options: Options::new(),
            payload: vec![7; MAX_FRAME_BODY - 1],
        };
        let one = big.to_bytes().unwrap();
        assert_eq!(one.len(), MAX_BUFFERED);
        let bytes = one.repeat(3);
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_BUFFERED);
        assert_eq!(decode_all(Frames::<Frame>::new, &bytes), (vec![big; 3], None));
    }

    #[test]
    fn datagrams_fit_either_ip_version() {
        // RFC 7252 section 4.6: a message fits one datagram. The largest
        // UDP payload is 65,507 bytes over IPv4 and 65,527 over IPv6.
        assert_eq!(MAX_DATAGRAM, 65_507);
        let mut m = Message::new(Type::NonConfirmable, Code::POST, 1);
        m.payload = vec![0; 65_530];
        assert!(m.to_bytes().is_err());
        assert!(m.to_bytes().is_err());
        m.payload.truncate(65_507 - HEADER_LEN - 1);
        assert_eq!(m.to_bytes().map(|b| b.len()), Ok(65_507));
    }

    #[test]
    fn types_and_codes_go_together() {
        // RFC 7252 section 4.2: an ACK carries a response or is empty, and
        // a Reset is empty. Section 4.3: a NON is never empty.
        assert_eq!(Message::parse(&[0x60, 0x01, 0, 1]), Err(Error::TypeAndCode(Type::Acknowledgement, Code::GET)));
        assert_eq!(Message::parse(&[0x60, 0xe1, 0, 1]), Err(Error::TypeAndCode(Type::Acknowledgement, Code::CSM)));
        assert_eq!(Message::parse(&[0x70, 0x45, 0, 1]), Err(Error::TypeAndCode(Type::Reset, Code::CONTENT)));
        assert_eq!(Message::parse(&[0x50, 0x00, 0, 1]), Err(Error::TypeAndCode(Type::NonConfirmable, Code::EMPTY)));
        assert_eq!(peek_header(&[0x50, 0x00, 0, 1]), Some((Type::NonConfirmable, Code::EMPTY, 1)));
        for ok in [[0x60, 0x45, 0, 1], [0x60, 0, 0, 1], [0x70, 0, 0, 1], [0x40, 0, 0, 1], [0x50, 0x01, 0, 1], [0x40, 0xe1, 0, 1]] {
            assert!(Message::parse(&ok).is_ok(), "{ok:?}");
        }
        for (kind, code) in
            [(Type::Acknowledgement, Code::GET), (Type::Reset, Code::CONTENT), (Type::NonConfirmable, Code::EMPTY)]
        {
            let m = Message::new(kind, code, 1);
            assert!(m.to_bytes().is_err());
            contract::check_wire_value(&m);
        }
    }

    #[test]
    fn path_setters_resolve_dot_segments() {
        // RFC 7252 sections 5.10.1 and 5.10.7: Uri-Path and Location-Path
        // are never `.` or `..`. Setters resolve them as RFC 3986 does.
        let segments = |path: &str| {
            let mut o = Options::new();
            o.set_uri_path(path);
            let uri: Vec<Vec<u8>> = o.get_all(option::URI_PATH).map(<[u8]>::to_vec).collect();
            o.set_location_path(path);
            let location: Vec<Vec<u8>> = o.get_all(option::LOCATION_PATH).map(<[u8]>::to_vec).collect();
            assert_eq!(uri, location);
            uri
        };
        let v = |s: &[&str]| s.iter().map(|x| x.as_bytes().to_vec()).collect::<Vec<_>>();
        assert_eq!(segments("/a/../b"), v(&["b"]));
        assert_eq!(segments("/%2e"), v(&[]));
        assert_eq!(segments("/%2E%2E/x"), v(&["x"]));
        assert_eq!(segments("/.."), v(&[]));
        assert_eq!(segments("/../../x"), v(&["x"]));
        assert_eq!(segments("/a/./b/."), v(&["a", "b", ""]));
        assert_eq!(segments("/a/b/.."), v(&["a", ""]));
        assert_eq!(segments("/a/.b/..c"), v(&["a", ".b", "..c"]));
        // Received dot segments: no path reads, and a Uri-Path is bad.
        let mut m = get("/x", 1, &[]);
        m.options.add(option::URI_PATH, b"..".to_vec());
        assert_eq!(m.options.uri_path(), None);
        assert_eq!(m.bad_option(), Some(option::URI_PATH));
        let mut o = Options::new();
        o.add(option::LOCATION_PATH, b".".to_vec());
        assert_eq!(o.location_path(), None);
    }

    #[test]
    fn string_options_must_be_utf8() {
        // RFC 7252 section 3.2: a string value is UTF-8. A critical one
        // that is not is reported like a value of the wrong length.
        let m = Message::parse(&[0x40, 0x01, 0x00, 0x01, 0x31, 0xff]).unwrap();
        assert_eq!(m.bad_option(), Some(option::URI_HOST));
        let mut ok = get("/caf\u{e9}", 1, &[]);
        assert_eq!(ok.bad_option(), None);
        ok.options.add(option::PROXY_SCHEME, vec![0xc3]);
        assert_eq!(ok.bad_option(), Some(option::PROXY_SCHEME));
    }

    #[test]
    fn bad_option_takes_linear_time() {
        // Many elective options, then many repeatable critical ones.
        let message = |n: usize| {
            let mut o = Options::new();
            for i in 0..n {
                o.add(2 + 2 * (i % 2000) as u16 + 2000, Vec::new());
            }
            for _ in 0..n {
                o.add(option::URI_PATH, b"p".to_vec());
            }
            Message { options: o, ..Message::new(Type::Confirmable, Code::GET, 1) }
        };
        // Only bad_option is timed, after the first call at each size
        // builds the message. The larger size is 60,000 of each kind.
        let mut messages = std::collections::HashMap::new();
        fictionet::stdlib::codec::test_support::assert_linear("CoAP bad_option", 15_000, |n| {
            let m = messages.entry(n).or_insert_with(|| message(n));
            assert_eq!(m.bad_option(), None);
        });
    }

    #[test]
    fn szx_7_is_reserved_over_udp() {
        // RFC 7959 section 2.2: SZX 7 is never sent, and a request with it
        // gets 4.00 Bad Request.
        let m = Message::parse(&[0x40, 0x03, 0x00, 0x01, 0xd1, 0x0e, 0x07, 0xff, b'x']).unwrap();
        let block = m.options.block1().unwrap();
        assert!(block.is_bert());
        assert_eq!(m.bad_block(), Some(option::BLOCK1));
        contract::check_wire_value(&m);
        assert!(m.to_bytes().is_ok());
        let err = Reassembler::new(100).push(block, &m.payload).unwrap_err();
        assert_eq!((err, err.code()), (Error::BlockSize, Code::BAD_REQUEST));
        // Over TCP, after a CSM offering it, BERT is fine.
        assert_eq!(Reassembler::with_bert(100).push(block, &m.payload), Ok(true));
        assert_eq!(get("/x", 1, &[]).bad_block(), None);
        let mut b2 = get("/x", 1, &[]);
        b2.options.set_block2(Block { num: 1, more: false, szx: 7 });
        assert_eq!(b2.bad_block(), Some(option::BLOCK2));
    }

    #[test]
    fn last_block_may_be_any_size() {
        // RFC 7959 section 2.3: SZX does not govern the payload size of a
        // block whose M bit is unset.
        let mut a = Reassembler::new(100);
        assert_eq!(a.push(Block { num: 0, more: false, szx: 0 }, &[0; 17]), Ok(true));
        let mut a = Reassembler::new(100);
        assert_eq!(a.push(Block { num: 0, more: true, szx: 0 }, &[0; 16]), Ok(false));
        assert_eq!(a.push(Block { num: 1, more: false, szx: 0 }, &[1; 40]), Ok(true));
        assert_eq!(a.body().len(), 56);
        // The body limit still holds.
        let mut a = Reassembler::new(10);
        assert_eq!(a.push(Block { num: 0, more: false, szx: 0 }, &[0; 11]), Err(Error::BodyTooLarge));
    }

    // RFC 7959: Block options and transfers.

    #[test]
    fn block_values() {
        // RFC 7959 figure 2: block 0, more, 128 bytes is 0x0b.
        let b = Block { num: 0, more: true, szx: 3 };
        assert_eq!(b.to_uint(), 0x0b);
        assert_eq!(b.size(), 128);
        let b = Block::from_uint(0x1e).unwrap();
        assert_eq!(b, Block { num: 1, more: true, szx: 6 });
        assert_eq!(b.offset(), 1024);
        let max = Block { num: Block::MAX_NUM, more: true, szx: 6 };
        assert_eq!(Block::from_uint(max.to_uint()), Some(max));
        assert_eq!(Block::from_uint(0x100_0000), None);
        let bert = Block::from_uint(0x27).unwrap();
        assert!(bert.is_bert() && bert.size() == 1024 && bert.offset() == 2048);
        assert_eq!(Block::szx_for(16), Some(0));
        assert_eq!(Block::szx_for(1024), Some(6));
        assert_eq!(Block::szx_for(100), None);
        let mut m = Message::new(Type::Confirmable, Code::GET, 0);
        m.options.set_block2(Block { num: 0, more: false, szx: 0 });
        assert_eq!(m.options.get(option::BLOCK2), Some(&[][..]));
        assert_eq!(m.options.block2(), Some(Block { num: 0, more: false, szx: 0 }));
        m.options.set(option::BLOCK2, vec![1, 2, 3, 4]);
        assert_eq!(m.options.block2(), None);
    }

    #[test]
    fn block_transfer_round_trip() {
        let body: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        for szx in 0..=6 {
            let mut a = Reassembler::new(4096);
            let mut num = 0;
            loop {
                let (block, chunk) = Block::take(&body, num, szx).unwrap();
                // Through a message and back, as Block1 would travel.
                let mut m = Message::new(Type::Confirmable, Code::PUT, num as u16);
                m.options.set_block1(block);
                m.options.set_size1(body.len() as u32);
                m.payload = chunk.to_vec();
                let back = Message::parse(&m.to_bytes().unwrap()).unwrap();
                let done = a.push(back.options.block1().unwrap(), &back.payload).unwrap();
                if done {
                    break;
                }
                num += 1;
            }
            assert!(a.is_done());
            assert_eq!(a.body(), &body[..]);
            assert_eq!(a.push(Block { num: 99, more: false, szx }, &[]), Err(Error::AfterLastBlock));
        }
        assert_eq!(Block::take(&body, 1, 6), None);
        assert_eq!(Block::take(&body, 0, 7), None);
        assert_eq!(Block::take(&[], 0, 2), Some((Block { num: 0, more: false, szx: 2 }, &[][..])));
        assert_eq!(Block::take(&[0; 32], 2, 0), None);
        assert!(!Block::take(&[0; 32], 1, 0).unwrap().0.more);
        assert_eq!(Block::take(&body, Block::MAX_NUM + 1, 0), None);
    }

    #[test]
    fn assembler_errors() {
        let mut a = Reassembler::new(100);
        assert_eq!(
            a.push(Block { num: 1, more: true, szx: 0 }, &[0; 16]),
            Err(Error::OutOfOrder { expected: 0, got: 16 })
        );
        assert_eq!(a.push(Block { num: 0, more: true, szx: 0 }, &[0; 15]), Err(Error::BlockSize));
        // A smaller block size partway: 64 bytes, then 32-byte block 2.
        assert_eq!(a.push(Block { num: 0, more: true, szx: 2 }, &[1; 64]), Ok(false));
        assert_eq!(a.push(Block { num: 2, more: true, szx: 1 }, &[2; 32]), Ok(false));
        assert_eq!(a.push(Block { num: 6, more: true, szx: 0 }, &[3; 16]), Err(Error::BodyTooLarge));
        assert_eq!(a.push(Block { num: 6, more: false, szx: 0 }, &[3; 4]), Ok(true));
        assert_eq!(a.clone().into_body().len(), 100);
        assert_eq!(Error::OutOfOrder { expected: 0, got: 1 }.code(), Code::REQUEST_ENTITY_INCOMPLETE);
        assert_eq!(Error::BodyTooLarge.code(), Code::REQUEST_ENTITY_TOO_LARGE);
        assert_eq!(Error::BlockSize.code(), Code::BAD_REQUEST);
        // BERT: whole 1024-byte units while more follow.
        let mut a = Reassembler::with_bert(MAX_BODY + 1);
        assert_eq!(a.push(Block { num: 0, more: true, szx: 7 }, &[0; 1000]), Err(Error::BlockSize));
        assert_eq!(a.push(Block { num: 0, more: true, szx: 7 }, &[]), Err(Error::BlockSize));
        assert_eq!(a.push(Block { num: 0, more: true, szx: 7 }, &[0; 2048]), Ok(false));
        assert_eq!(a.push(Block { num: 2, more: false, szx: 7 }, &[0; 3000]), Ok(true));
        assert_eq!(a.body().len(), 5048);
    }

    // RFC 7641: Observe.

    #[test]
    fn observe_freshness() {
        assert!(observe_is_newer(1, 2, 0));
        assert!(!observe_is_newer(2, 1, 0));
        assert!(!observe_is_newer(5, 5, 0));
        // Wrapping around 2^24.
        assert!(observe_is_newer(observe::MAX, 0, 0));
        assert!(!observe_is_newer(0, observe::MAX, 0));
        assert!(!observe_is_newer(0, 1 << 23, 0));
        assert!(observe_is_newer(2, 1, 129));
        let mut m = get("/temp", 1, &[1]);
        m.options.set_uint(option::OBSERVE, observe::REGISTER);
        let back = Message::parse(&m.to_bytes().unwrap()).unwrap();
        assert_eq!(back.options.observe(), Some(observe::REGISTER));
        m.options.set(option::OBSERVE, vec![1, 0, 0, 0]);
        assert_eq!(m.options.observe(), None);
    }

    // RFC 8323: CoAP over TCP.

    #[test]
    fn tcp_length_forms() {
        // Body lengths at each boundary of the Len field.
        for (payload, first, ext_len) in
            [(11usize, 0xc0u8, 0usize), (12, 0xd0, 1), (267, 0xd0, 1), (268, 0xe0, 2), (65_803, 0xe0, 2), (65_804, 0xf0, 4)]
        {
            let f = Frame { code: Code::POST, token: Vec::new(), options: Options::new(), payload: vec![1; payload] };
            let bytes = f.to_bytes().unwrap();
            assert_eq!(bytes[0], first, "{payload}");
            assert_eq!(bytes.len(), 1 + ext_len + 1 + 1 + payload);
            assert_eq!(Frame::parse(&bytes), Ok(f));
        }
        // RFC 8323 figure 7: a CSM with Max-Message-Size 1152.
        let csm = Frame::csm(1152, false);
        assert_eq!(csm.to_bytes().unwrap(), [0x30, 0xe1, 0x22, 0x04, 0x80]);
        let ping = Frame { token: vec![0x42], ..Frame::new(Code::PING) };
        assert_eq!(ping.to_bytes().unwrap(), [0x01, 0xe2, 0x42]);
        assert_eq!(ping.pong().to_bytes().unwrap(), [0x01, 0xe3, 0x42]);
        let req = Frame { token: vec![1, 2], ..Frame::new(Code::GET) };
        assert_eq!(req.reply(Code::CONTENT).token, vec![1, 2]);
    }

    #[test]
    fn tcp_errors() {
        assert_eq!(Frame::parse(&[0x09]), Err(Error::TokenLength(9)));
        assert_eq!(Frame::parse(&[0xf0, 0, 0x10]), Err(Error::Truncated));
        assert_eq!(
            Frame::parse(&[0xf0, 0, 0x10, 0, 0]),
            Err(Error::TooLong(65_805 + 0x10_0000))
        );
        assert_eq!(
            Frame::parse(&[0xf0, 0xff, 0xff, 0xff, 0xff]),
            Err(Error::TooLong(65_805 + 0xffff_ffff))
        );
        assert_eq!(Frame::parse(&[0x10, 0x45, 0xff]), Err(Error::EmptyPayload));
        assert_eq!(Frame::parse(&[0x10, 0x45, 0xf1]), Err(Error::ReservedNibble));
        assert_eq!(Frame::parse(&[0x10, 0x45, 0x01]), Err(Error::Truncated));
        // An empty frame is allowed over TCP.
        assert_eq!(Frame::parse(&[0x00, 0x00]), Ok(Frame::new(Code::EMPTY)));
        let mut largest = Frame {
            code: Code::CONTENT,
            token: Vec::new(),
            options: Options::new(),
            payload: vec![0; 2 * MAX_FRAME_BODY],
        };
        assert!(largest.to_bytes().is_err());
        largest.payload.truncate(MAX_FRAME_BODY - 1);
        let bytes = largest.to_bytes().unwrap();
        assert_eq!(bytes.len(), 1 + 4 + 1 + MAX_FRAME_BODY);
        assert_eq!(Frame::parse(&bytes), Ok(largest));
    }

    #[test]
    fn stream_splits_a_stream() {
        let a = Frame::csm(1152, true);
        let b = Frame { token: vec![7; 8], options: m_options(), payload: vec![5; 300], ..Frame::new(Code::GET) };
        let bytes = [a.to_bytes().unwrap(), b.to_bytes().unwrap(), a.to_bytes().unwrap()].concat();
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_BUFFERED);
        assert_eq!(decode_all(Frames::<Frame>::new, &bytes), (vec![a, b, Frame::csm(1152, true)], None));
        let mut stream = Stream::new(Frames::<Frame>::new());
        assert_eq!(stream.push(&[0x0c, 0xe2]), 2);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TokenLength(12)))));
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn stream_takes_many_small_frames_in_linear_time() {
        let bytes = Frame { token: vec![1], ..Frame::new(Code::PING) }.to_bytes().unwrap().repeat(200_000);
        let started = std::time::Instant::now();
        let mut stream = Stream::new(Frames::<Frame>::new());
        let mut n = 0;
        pump(&mut stream, &bytes, |_| n += 1).unwrap();
        assert_eq!(n, 200_000);
        assert!(started.elapsed().as_secs() < 5);
    }

    #[test]
    fn writers_refuse_oversized_values() {
        let mut m = Message::new(Type::Confirmable, Code::POST, 1);
        for _ in 0..MAX_OPTIONS {
            m.options.add(option::URI_PATH, vec![b'y'; MAX_OPTION_VALUE]);
        }
        m.payload = vec![1; 1000];
        assert!(m.to_bytes().is_err());
        contract::check_wire_value(&m);
        for f in [
            Frame { token: vec![2; 9], ..Frame::new(Code::POST) },
            Frame {
                options: Options(vec![CoapOption { number: 1, value: vec![0; MAX_OPTION_VALUE + 1] }]),
                ..Frame::new(Code::POST)
            },
            Frame {
                options: Options(vec![CoapOption { number: 1, value: vec![] }; MAX_OPTIONS + 1]),
                ..Frame::new(Code::POST)
            },
            Frame { payload: vec![3; 2 * MAX_FRAME_BODY], ..Frame::new(Code::POST) },
        ] {
            assert!(f.to_bytes().is_err());
            contract::check_wire_value(&f);
        }
    }

    #[test]
    fn errors_display() {
        for e in [
            Error::Truncated,
            Error::Version(0),
            Error::TokenLength(9),
            Error::EmptyWithContent,
            Error::TypeAndCode(Type::Reset, Code::GET),
            Error::ReservedNibble,
            Error::OptionNumber,
            Error::OptionTooLong(2000),
            Error::TooManyOptions,
            Error::EmptyPayload,
            Error::TooLong(1),
        ] {
            assert!(!e.to_string().is_empty());
        }
        for e in [Error::OutOfOrder { expected: 0, got: 1 }, Error::BlockSize, Error::BodyTooLarge, Error::AfterLastBlock] {
            assert!(!e.to_string().is_empty());
        }
    }

    /// Reads `b` every way this module can, checking what holds for any
    /// bytes.
    fn check_bytes(b: &[u8]) {
        if let Ok(m) = Message::parse(b) {
            // Encoding is canonical, so writing gives the same bytes.
            assert_eq!(m.to_bytes().unwrap(), b);
            let o = &m.options;
            let _ = (m.bad_option(), o.uri_path(), o.uri_query(), o.content_format(), o.accept(), o.max_age());
            let _ = (o.observe(), o.block1(), o.block2(), o.size1(), o.size2());
            let _ = (o.uri_host(), o.uri_port());
            if let Some(path) = o.location_path() {
                let mut again = Options::new();
                again.set_location_path(&path);
                let segments: Vec<&[u8]> = o.get_all(option::LOCATION_PATH).collect();
                let back: Vec<&[u8]> = again.get_all(option::LOCATION_PATH).collect();
                assert!(back == segments || (segments == [&b""[..]] && back.is_empty()), "{path}");
            }
            let _ = m.reply(Code::CONTENT, 0).to_bytes().unwrap();
            // A path read writes back as the same segments, except one
            // empty segment, which reads as `/` like no segment at all.
            if let Some(path) = o.uri_path() {
                let mut again = Options::new();
                again.set_uri_path(&path);
                let segments: Vec<&[u8]> = o.get_all(option::URI_PATH).collect();
                let back: Vec<&[u8]> = again.get_all(option::URI_PATH).collect();
                assert!(back == segments || (segments == [&b""[..]] && back.is_empty()), "{path}");
            }
        }
        let _ = peek_header(b);
        contract::check_wire::<Message>(b);
        contract::check_wire::<Frame>(b);
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, b, 2 * MAX_BUFFERED);
        for f in decode_all(Frames::<Frame>::new, b).0 {
            contract::check_wire_value(&f);
            let _ = (f.bad_option(), f.max_message_size(), f.pong());
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0xc0a9);
        let mut seeds = Vec::new();
        let mut m = get("/sensors/temp", 0x1234, &[1, 2, 3]);
        m.options.set_block2(Block { num: 2, more: true, szx: 4 });
        m.options.set_observe(7);
        m.options.add(option::PROXY_URI, vec![b'p'; 300]);
        m.payload = b"payload".to_vec();
        seeds.push(m.to_bytes().unwrap());
        seeds.push(Message::reset(9).to_bytes().unwrap());
        let mut f = Frame { token: vec![4; 4], ..Frame::new(Code::PUT) };
        f.options = m_options();
        f.payload = vec![1; 20];
        seeds.push(
            [
                Frame::csm(1152, true).to_bytes().unwrap(),
                f.to_bytes().unwrap(),
                Frame::new(Code::PING).to_bytes().unwrap(),
            ]
            .concat(),
        );
        for i in 0..6000 {
            let b: Vec<u8> = if i % 3 == 0 {
                rng.bytes(64)
            } else {
                let mut b = seeds[rng.index(seeds.len())].clone();
                for _ in 0..1 + rng.index(4) {
                    mutate(&mut rng, &mut b);
                }
                b
            };
            check_bytes(&b);
        }
        // Random messages built from parts round trip exactly.
        for _ in 0..3000 {
            let mut m =
                Message::new(Type::from_bits(rng.next() as u8), Code(1 + rng.index(255) as u8), rng.next() as u16);
            if !valid_type_code(m.kind, m.code) {
                m.kind = Type::Confirmable;
            }
            m.token = rng.bytes(8);
            for _ in 0..rng.index(8) {
                let len = [0, 1, 12, 13, 268, 269, 400][rng.index(7)];
                m.options.add(rng.next() as u16 >> rng.index(16), vec![rng.next() as u8; len]);
            }
            m.payload = rng.bytes(39);
            contract::check_wire_value(&m);
            let bytes = m.to_bytes().unwrap();
            let back = Message::parse(&bytes).unwrap();
            assert_eq!((back.kind, back.code, back.message_id), (m.kind, m.code, m.message_id));
            assert_eq!((&back.token, &back.options, &back.payload), (&m.token, &m.options, &m.payload));
            let f = Frame { code: m.code, token: m.token, options: m.options, payload: m.payload };
            contract::check_wire_value(&f);
            let bytes = f.to_bytes().unwrap();
            assert_eq!(Frame::parse(&bytes), Ok(f));
            check_bytes(&bytes);
        }
    }
}
