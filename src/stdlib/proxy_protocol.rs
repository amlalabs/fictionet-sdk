//! The PROXY protocol: reading and writing the header a proxy puts in
//! front of a TCP connection, with no I/O.
//!
//! A load balancer or TLS terminator that passes a connection on loses the
//! client's address: the server sees the proxy's. The PROXY protocol fixes
//! that. Before any of the client's bytes, the proxy sends one header that
//! names the original source and destination. Version 1 is a line of text,
//! such as `PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n`. Version 2 is
//! binary: a 16-byte header, an address block, and TLVs (type, length,
//! value) that carry extras such as the TLS server name, the ALPN protocol
//! and details of the client's certificate. This module follows the HAProxy
//! "PROXY protocol" specification, versions 1 and 2.
//!
//! Nothing here reads a socket. A world that plays a server behind a proxy
//! feeds the first bytes of a connection to a [`Decoder`]. It gets back
//! [`Step::NeedMore`] until the header is whole, then the [`Header`] and the
//! bytes that came after it, which belong to the protocol the connection
//! carries. A world that plays the proxy writes [`Header::to_bytes`] before
//! the client's bytes.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. A version 2 header with a CRC32C TLV is checked against
//! its checksum. The specification says a receiver accepts a version 2
//! LOCAL header and discards its address block, so a LOCAL header whose
//! family, addresses or TLVs cannot be read gives no addresses and no TLVs
//! instead of an error. A CRC32C TLV that the reader can find in a LOCAL
//! header is still checked, even when a later TLV cannot be read.
//!
//! New code uses [`Headers`] with [`codec::Stream`]. The decoder returns
//! one header result and then `End`. `swap` or `into_parts` preserves the
//! unread suffix. [`Wire`] adds exact parsing and strict writing for
//! [`Header`], with [`HeaderParseError`] for parsing and [`EncodeError`]
//! for writing. [`HeaderError`] covers terminal framing errors. The legacy
//! `Decoder`, `Step`, prefix parser and writer keep their old behavior.
//!
//! ```
//! use fictionet::stdlib::proxy_protocol::{Addresses, Command, Decoder, Header, Step, Tlv, Transport, V2};
//! use std::net::Ipv4Addr;
//!
//! // A version 1 header that arrives in two reads, with the client's
//! // request right behind it.
//! let mut decoder = Decoder::new();
//! assert_eq!(decoder.feed(b"PROXY TCP4 192.0.2.1 "), Step::NeedMore);
//! let Step::Header { header, rest } = decoder.feed(b"198.51.100.2 56324 443\r\nGET / HTTP/1.1\r\n") else {
//!     panic!("expected a header");
//! };
//! let (source, destination) = header.addresses().unwrap();
//! assert_eq!(source.to_string(), "192.0.2.1:56324");
//! assert_eq!(destination.port(), 443);
//! assert_eq!(rest, b"GET / HTTP/1.1\r\n");
//!
//! // A version 2 header, as a TLS terminator would send it, reads back the same.
//! let header = Header::V2(V2 {
//!     command: Command::Proxy,
//!     addresses: Addresses::Inet {
//!         transport: Transport::Stream,
//!         src: Ipv4Addr::new(192, 0, 2, 1),
//!         dst: Ipv4Addr::new(198, 51, 100, 2),
//!         src_port: 56324,
//!         dst_port: 443,
//!     },
//!     tlvs: vec![Tlv::Authority(b"example.com".to_vec())],
//! });
//! let bytes = header.to_bytes();
//! assert_eq!(Header::parse(&bytes), Ok(Some((header, bytes.len()))));
//! ```

use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::codec::{self, Decode, Wire};

/// Why the next PROXY header cannot be framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// A signature or fixed header is invalid, or a v1 line exceeds [`V1_MAX_LEN`].
    Protocol(Error),
    /// The declared header exceeds the configured whole-header limit.
    TooLong,
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::TooLong => f.write_str("PROXY header exceeds its limit"),
        }
    }
}
impl core::error::Error for HeaderError {}

/// Why an exact [`Wire`] parse cannot read one PROXY header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderParseError {
    /// The header is malformed.
    Protocol(Error),
    /// The input ends inside a header.
    Truncated,
    /// Bytes follow the header.
    Trailing,
    /// Re-encoding would change the value, including its checksum.
    Unrepresentable,
}

impl core::fmt::Display for HeaderParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete PROXY header"),
            Self::Trailing => f.write_str("bytes after the PROXY header"),
            Self::Unrepresentable => f.write_str("PROXY header cannot be written unchanged"),
        }
    }
}
impl core::error::Error for HeaderParseError {}

/// Why a strict writer cannot preserve a PROXY header's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Encoding would clip a field, normalize a variant or change a checksum.
    Unrepresentable,
}
impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unrepresentable => f.write_str("PROXY header cannot be written unchanged"),
        }
    }
}
impl core::error::Error for EncodeError {}

impl Wire for Header {
    type ParseError = HeaderParseError;
    type WriteError = EncodeError;

    /// Reads exactly one header. Refuses values whose canonical encoding
    /// changes their checksum. The inherent prefix parser is unchanged.
    fn parse(bytes: &[u8]) -> Result<Self, HeaderParseError> {
        let (header, used) = Header::parse(bytes)
            .map_err(HeaderParseError::Protocol)?
            .ok_or(HeaderParseError::Truncated)?;
        if used != bytes.len() {
            return Err(HeaderParseError::Trailing);
        }
        strict_header(&header).map_err(|_| HeaderParseError::Unrepresentable)?;
        Ok(header)
    }

    /// Appends at most [`MAX_HEADER_LEN`] bytes. Refuses clipping, variant
    /// normalization and checksum changes without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.extend_from_slice(&strict_header(self)?);
        Ok(())
    }
}

fn strict_header(header: &Header) -> Result<Vec<u8>, EncodeError> {
    let bytes = header.to_bytes();
    match Header::parse(&bytes) {
        Ok(Some((ref back, used))) if back == header && used == bytes.len() => Ok(bytes),
        _ => Err(EncodeError::Unrepresentable),
    }
}

/// Reads one PROXY header, then returns [`codec::Step::End`].
///
/// Use with [`codec::Stream`]. Items are `Result<Header, Error>`: a bad
/// complete line or v2 body is one refused item, followed by `End`.
/// Bad signatures, fixed headers and limits are terminal errors.
/// A v1 line without a newline within [`V1_MAX_LEN`] fails with
/// [`Error::V1TooLong`]; a smaller configured limit gives [`HeaderError::TooLong`].
/// In particular, [`Error::NotProxy`] is a terminal `Protocol` error with
/// no consumption. Use [`codec::Stream::swap`] or
/// [`codec::Stream::into_parts`] to give every unread byte to the plain
/// protocol. After a header item, only its bytes have been consumed.
/// After `End`, [`codec::Stream::push`] takes and drops further input.
/// Give any unaccepted input to the next decoder along with the unread
/// suffix. Partial headers return `Need`, including at EOF.
#[derive(Clone, Debug)]
pub struct Headers {
    limit: usize,
    scanned: usize,
    done: bool,
}

impl Headers {
    /// Accepts headers up to [`MAX_HEADER_LEN`] bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_HEADER_LEN)
    }

    /// Sets the whole-header limit, clamped to [`V2_HEADER_LEN`] through
    /// [`MAX_HEADER_LEN`]. A v2 length is checked before its body arrives.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.clamp(V2_HEADER_LEN, MAX_HEADER_LEN), scanned: 0, done: false }
    }

    /// The largest accepted header, including its fixed part.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Headers {
    type Item = Result<Header, Error>;
    type Error = HeaderError;
    const NAME: &'static str = "PROXY protocol";

    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, input: &[u8], _: bool) -> Result<codec::Step<Self::Item>, HeaderError> {
        if self.done {
            return Ok(codec::Step::End);
        }
        let used = match detect(input) {
            Detection::NeedMore => return Ok(codec::Step::Need),
            Detection::NotProxy => return Err(HeaderError::Protocol(Error::NotProxy)),
            Detection::V1 => {
                let cap = self.limit.min(V1_MAX_LEN);
                let end = input.len().min(cap);
                let window = input.get(self.scanned..end).unwrap_or_default();
                match window.iter().position(|&b| b == b'\n') {
                    Some(n) => self
                        .scanned
                        .checked_add(n)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(HeaderError::TooLong)?,
                    None => {
                        self.scanned = end;
                        return if end == V1_MAX_LEN {
                            Err(HeaderError::Protocol(Error::V1TooLong))
                        } else if end == cap {
                            Err(HeaderError::TooLong)
                        } else {
                            Ok(codec::Step::Need)
                        };
                    }
                }
            }
            Detection::V2 => {
                // Validate just the fixed prefix even when a whole body is
                // available, so header faults always have the same priority.
                let fixed = input.get(..input.len().min(V2_HEADER_LEN)).unwrap_or_default();
                Header::parse(fixed).map_err(HeaderError::Protocol)?;
                let Some(&[hi, lo]) = input.get(14..16) else {
                    return Ok(codec::Step::Need);
                };
                let used = V2_HEADER_LEN
                    .checked_add(usize::from(u16::from_be_bytes([hi, lo])))
                    .ok_or(HeaderError::TooLong)?;
                if used > self.limit {
                    return Err(HeaderError::TooLong);
                }
                used
            }
        };
        let Some(bytes) = input.get(..used) else { return Ok(codec::Step::Need) };
        let item = Header::parse(bytes).and_then(|m| m.map(|(h, _)| h).ok_or(Error::V1Syntax));
        self.done = true;
        Ok(codec::Step::Item(item, used))
    }
}

/// What every version 1 header starts with.
pub const V1_PREFIX: &[u8; 6] = b"PROXY ";
/// The longest version 1 header, counting the CR and LF at its end.
pub const V1_MAX_LEN: usize = 107;
/// The longest text a version 1 `UNKNOWN` header can carry after the word
/// `UNKNOWN` and still fit in [`V1_MAX_LEN`].
pub const V1_MAX_UNKNOWN_REST: usize = V1_MAX_LEN - b"PROXY UNKNOWN\r\n".len();
/// The 12 bytes every version 2 header starts with.
pub const V2_SIGNATURE: [u8; 12] = [0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a];
/// The length of the fixed part of a version 2 header: the signature, the
/// version and command, the family and transport, and the length.
pub const V2_HEADER_LEN: usize = 16;
/// The most bytes a version 2 header may carry after its fixed part: the
/// address block and the TLVs. The length field is 16 bits.
pub const V2_MAX_BODY: usize = 0xffff;
/// The longest version 2 header.
pub const V2_MAX_LEN: usize = V2_HEADER_LEN + V2_MAX_BODY;
/// The longest header of either version. A [`Decoder`] never holds more.
pub const MAX_HEADER_LEN: usize = V2_MAX_LEN;
/// The length of an IPv4 address block: two addresses and two ports.
pub const INET_BLOCK_LEN: usize = 12;
/// The length of an IPv6 address block: two addresses and two ports.
pub const INET6_BLOCK_LEN: usize = 36;
/// The length of one Unix socket address in a version 2 header.
pub const UNIX_ADDR_LEN: usize = 108;
/// The length of a Unix address block: two socket addresses.
pub const UNIX_BLOCK_LEN: usize = 2 * UNIX_ADDR_LEN;
/// The longest value a `UNIQUE_ID` TLV may hold.
pub const MAX_UNIQUE_ID: usize = 128;
/// The length of the fixed part of an `SSL` TLV's value: the client flags
/// and the verify result.
pub const SSL_FIXED_LEN: usize = 5;
/// The longest value any TLV can hold inside a header: the whole body less
/// the TLV's own type and length. [`Tlv::from_raw`] and [`Ssl::parse`]
/// refuse longer values.
pub const MAX_TLV_VALUE: usize = V2_MAX_BODY - 3;

/// The TLV types this module names. Others are kept as [`Tlv::Other`].
pub mod tlv_type {
    #![allow(missing_docs)]
    pub const ALPN: u8 = 0x01;
    pub const AUTHORITY: u8 = 0x02;
    pub const CRC32C: u8 = 0x03;
    pub const NOOP: u8 = 0x04;
    pub const UNIQUE_ID: u8 = 0x05;
    pub const SSL: u8 = 0x20;
    pub const NETNS: u8 = 0x30;
    // Sub-TLVs, found only inside an `SSL` TLV.
    pub const SSL_VERSION: u8 = 0x21;
    pub const SSL_CN: u8 = 0x22;
    pub const SSL_CIPHER: u8 = 0x23;
    pub const SSL_SIG_ALG: u8 = 0x24;
    pub const SSL_KEY_ALG: u8 = 0x25;
}

/// The bits of an `SSL` TLV's client field.
pub mod client {
    /// The client connected over SSL or TLS.
    pub const SSL: u8 = 0x01;
    /// The client sent a certificate on this connection.
    pub const CERT_CONN: u8 = 0x02;
    /// The client sent a certificate at least once in this TLS session.
    pub const CERT_SESS: u8 = 0x04;
}

/// A PROXY protocol header of either version.
#[derive(Clone, Debug, PartialEq, Eq)]
// A connection has one header, so the size of the v2 variant (its Unix
// paths) costs nothing worth boxing it for.
#[allow(clippy::large_enum_variant)]
pub enum Header {
    /// A version 1 text header.
    V1(V1),
    /// A version 2 binary header.
    V2(V2),
}

/// A version 1 header: one line of text.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum V1 {
    /// `PROXY TCP4`: a TCP connection over IPv4, from `src:src_port` to
    /// `dst:dst_port`.
    Tcp4 { src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16 },
    /// `PROXY TCP6`: a TCP connection over IPv6.
    Tcp6 { src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16 },
    /// `PROXY UNKNOWN`: the proxy does not say where the connection came
    /// from. The bytes are whatever followed the word `UNKNOWN` on the line,
    /// before the CR and LF. They are empty or start with a space. A
    /// receiver ignores them.
    Unknown(Vec<u8>),
}

/// A version 2 header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2 {
    /// Whether the connection is proxied or made by the proxy itself.
    pub command: Command,
    /// The address family, the transport and the addresses.
    pub addresses: Addresses,
    /// The TLVs after the address block, in order.
    pub tlvs: Vec<Tlv>,
}

/// A version 2 command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// The proxy made the connection itself, such as for a health check.
    /// The receiver uses the connection's real endpoints.
    Local,
    /// The connection is relayed for a client. The receiver uses the
    /// addresses in the header.
    Proxy,
}

/// A version 2 transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// A stream: TCP, or a Unix stream socket.
    Stream,
    /// Datagrams: UDP, or a Unix datagram socket.
    Dgram,
}

/// A version 2 address block, with the family and transport it belongs to.
/// Only these combinations are allowed by the specification.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Addresses {
    /// No addresses: the family and transport are both unspecified.
    Unspec,
    /// IPv4 source and destination, with ports.
    Inet { transport: Transport, src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16 },
    /// IPv6 source and destination, with ports.
    Inet6 { transport: Transport, src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16 },
    /// Unix socket paths, each padded with zero bytes to
    /// [`UNIX_ADDR_LEN`]. [`unix_path`] cuts the padding off, and
    /// [`unix_addr`] adds it.
    Unix { transport: Transport, src: [u8; UNIX_ADDR_LEN], dst: [u8; UNIX_ADDR_LEN] },
}

/// One TLV of a version 2 header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Tlv {
    /// `ALPN`: the protocol the client chose with TLS ALPN, such as `h2`.
    Alpn(Vec<u8>),
    /// `AUTHORITY`: the host name the client asked for, such as the TLS
    /// server name, in UTF-8.
    Authority(Vec<u8>),
    /// `CRC32C`: a checksum of the whole header. A reader checks it. A
    /// writer works out the right value itself and ignores this one.
    Crc32c(u32),
    /// `NOOP`: padding a receiver skips.
    Noop(Vec<u8>),
    /// `UNIQUE_ID`: an opaque ID for the connection, at most
    /// [`MAX_UNIQUE_ID`] bytes.
    UniqueId(Vec<u8>),
    /// `SSL`: how the client connected over TLS.
    Ssl(Ssl),
    /// `NETNS`: the name of the network namespace the connection came in on.
    NetNs(Vec<u8>),
    /// Any other type, such as one in the custom range 0xE0 to 0xEF. The
    /// parser never makes an `Other` of a type named above. One built by
    /// hand is written with its type and reads back as that type's variant.
    Other { kind: u8, value: Vec<u8> },
}

/// The value of an `SSL` TLV.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssl {
    /// The bits in [`client`]: TLS was used, and whether a client
    /// certificate was sent.
    pub client: u8,
    /// Zero if the client's certificate was verified, and otherwise not.
    pub verify: u32,
    /// The sub-TLVs, in order.
    pub tlvs: Vec<SslTlv>,
}

/// One sub-TLV inside an `SSL` TLV. Every value is text, as the proxy
/// wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum SslTlv {
    /// `SSL_VERSION`: the TLS version, such as `TLSv1.3`.
    Version(Vec<u8>),
    /// `SSL_CN`: the common name of the client certificate's subject.
    CommonName(Vec<u8>),
    /// `SSL_CIPHER`: the cipher, such as `ECDHE-RSA-AES128-GCM-SHA256`.
    Cipher(Vec<u8>),
    /// `SSL_SIG_ALG`: the algorithm that signed the certificate the proxy
    /// itself presented to the client (the frontend's certificate, not the
    /// client's), such as `SHA256`.
    SigAlg(Vec<u8>),
    /// `SSL_KEY_ALG`: the algorithm of the key of the certificate the proxy
    /// itself presented to the client (the frontend's certificate, not the
    /// client's), such as `RSA2048`.
    KeyAlg(Vec<u8>),
    /// Any other sub-type. One built by hand with a type named above reads
    /// back as that type's variant.
    Other { kind: u8, value: Vec<u8> },
}

/// Why bytes are not a PROXY protocol header. A real server closes the
/// connection, unless the error is [`Error::NotProxy`] and it also accepts
/// connections with no header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes start with neither `PROXY ` nor the version 2 signature.
    NotProxy,
    /// A version 1 line ran past [`V1_MAX_LEN`] bytes with no line feed.
    V1TooLong,
    /// A version 1 line is not shaped right: an LF with no CR before it,
    /// an unknown protocol word, or the wrong number of fields.
    V1Syntax,
    /// A version 1 address is not an address of the line's family.
    V1Address,
    /// A version 1 port is not a number from 0 to 65535 written without
    /// leading zeros.
    V1Port,
    /// The version 2 version field (the high 4 bits of byte 13) was not 2.
    Version(u8),
    /// The version 2 command (the low 4 bits of byte 13) was neither LOCAL
    /// (0) nor PROXY (1).
    Command(u8),
    /// The family and transport byte of a version 2 PROXY header was not
    /// one of the seven the specification allows. A LOCAL header ignores it.
    Family(u8),
    /// The length of a version 2 PROXY header was too short to hold the
    /// address block.
    Length(u16),
    /// A TLV or SSL sub-TLV ran past the end of what holds it.
    TlvTruncated,
    /// A TLV of this type had a value of the wrong length: a CRC32C not 4
    /// bytes, a UNIQUE_ID over [`MAX_UNIQUE_ID`], an SSL value shorter
    /// than [`SSL_FIXED_LEN`], or any value over [`MAX_TLV_VALUE`]. A LOCAL
    /// header gives this error only for a CRC32C TLV.
    TlvLength(u8),
    /// The CRC32C TLV did not match the header, or there was more than one.
    Checksum,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotProxy => f.write_str("not a PROXY protocol header"),
            Error::V1TooLong => write!(f, "PROXY v1 line longer than {V1_MAX_LEN} bytes"),
            Error::V1Syntax => f.write_str("malformed PROXY v1 line"),
            Error::V1Address => f.write_str("bad address in PROXY v1 line"),
            Error::V1Port => f.write_str("bad port in PROXY v1 line"),
            Error::Version(v) => write!(f, "PROXY header version {v}, not 2"),
            Error::Command(c) => write!(f, "PROXY v2 command {c}, not LOCAL or PROXY"),
            Error::Family(b) => write!(f, "PROXY v2 family and transport byte {b:#04x} not allowed"),
            Error::Length(n) => write!(f, "PROXY v2 length {n} too short for the address block"),
            Error::TlvTruncated => f.write_str("PROXY v2 TLV runs past its end"),
            Error::TlvLength(k) => write!(f, "PROXY v2 TLV type {k:#04x} has a value of the wrong length"),
            Error::Checksum => f.write_str("PROXY v2 CRC32C checksum does not match"),
        }
    }
}

impl std::error::Error for Error {}

/// What the start of a connection looks like, from its first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detection {
    /// The bytes so far could start a header of either version.
    NeedMore,
    /// The bytes start with `PROXY `.
    V1,
    /// The bytes start with the version 2 signature.
    V2,
    /// The bytes cannot start a header.
    NotProxy,
}

/// Says which version of header `b` starts with, if any, looking only at
/// the prefix. It does not check the rest of the header.
pub fn detect(b: &[u8]) -> Detection {
    if let Some(d) = match_prefix(b, V1_PREFIX, Detection::V1) {
        return d;
    }
    if let Some(d) = match_prefix(b, &V2_SIGNATURE, Detection::V2) {
        return d;
    }
    Detection::NotProxy
}

fn match_prefix(b: &[u8], prefix: &[u8], whole: Detection) -> Option<Detection> {
    let n = b.len().min(prefix.len());
    if b[..n] != prefix[..n] {
        None
    } else if n == prefix.len() {
        Some(whole)
    } else {
        Some(Detection::NeedMore)
    }
}

impl Header {
    /// Reads the header at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the header and how many bytes
    /// of `b` it took. An error found in a part is the same error the whole
    /// header gives.
    pub fn parse(b: &[u8]) -> Result<Option<(Header, usize)>, Error> {
        match detect(b) {
            Detection::NeedMore => Ok(None),
            Detection::NotProxy => Err(Error::NotProxy),
            Detection::V1 => Ok(parse_v1(b)?.map(|(h, n)| (Header::V1(h), n))),
            Detection::V2 => Ok(parse_v2(b)?.map(|(h, n)| (Header::V2(h), n))),
        }
    }

    /// The header's bytes. Whatever the header holds, [`Header::parse`]
    /// reads them back; see [`V1::to_bytes`] and [`V2::to_bytes`] for what
    /// is cut to make that so.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Header::V1(h) => h.to_bytes(),
            Header::V2(h) => h.to_bytes(),
        }
    }

    /// The client's address and the address it connected to, when the
    /// header gives IP addresses for a relayed connection. It is `None`
    /// for `UNKNOWN`, `LOCAL`, an unspecified family and Unix sockets, where
    /// a receiver uses the connection's real endpoints.
    pub fn addresses(&self) -> Option<(SocketAddr, SocketAddr)> {
        match self {
            Header::V1(V1::Tcp4 { src, dst, src_port, dst_port }) => {
                Some((SocketAddr::from((*src, *src_port)), SocketAddr::from((*dst, *dst_port))))
            }
            Header::V1(V1::Tcp6 { src, dst, src_port, dst_port }) => {
                Some((SocketAddr::from((*src, *src_port)), SocketAddr::from((*dst, *dst_port))))
            }
            Header::V1(V1::Unknown(_)) => None,
            Header::V2(h) if h.command == Command::Local => None,
            Header::V2(h) => match &h.addresses {
                Addresses::Inet { src, dst, src_port, dst_port, .. } => {
                    Some((SocketAddr::from((*src, *src_port)), SocketAddr::from((*dst, *dst_port))))
                }
                Addresses::Inet6 { src, dst, src_port, dst_port, .. } => {
                    Some((SocketAddr::from((*src, *src_port)), SocketAddr::from((*dst, *dst_port))))
                }
                Addresses::Unspec | Addresses::Unix { .. } => None,
            },
        }
    }
}

fn parse_v1(b: &[u8]) -> Result<Option<(V1, usize)>, Error> {
    let window = &b[..b.len().min(V1_MAX_LEN)];
    let Some(lf) = window.iter().position(|&c| c == b'\n') else {
        return if b.len() >= V1_MAX_LEN { Err(Error::V1TooLong) } else { Ok(None) };
    };
    // The prefix holds no LF, so `lf` is at least 6.
    let cr = lf.checked_sub(1).ok_or(Error::V1Syntax)?;
    if window.get(cr) != Some(&b'\r') || cr < V1_PREFIX.len() {
        return Err(Error::V1Syntax);
    }
    let line = window.get(V1_PREFIX.len()..cr).ok_or(Error::V1Syntax)?;
    let used = lf + 1;
    if let Some(rest) = line.strip_prefix(b"UNKNOWN") {
        // The word ends at the CR or at a space.
        if rest.first().is_some_and(|&c| c != b' ') {
            return Err(Error::V1Syntax);
        }
        return Ok(Some((V1::Unknown(rest.to_vec()), used)));
    }
    let mut fields = line.split(|&c| c == b' ');
    let (Some(proto), Some(src), Some(dst), Some(sport), Some(dport), None) =
        (fields.next(), fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(Error::V1Syntax);
    };
    let header = match proto {
        b"TCP4" => {
            let (src, dst) = (v1_addr::<Ipv4Addr>(src)?, v1_addr::<Ipv4Addr>(dst)?);
            V1::Tcp4 { src, dst, src_port: v1_port(sport)?, dst_port: v1_port(dport)? }
        }
        b"TCP6" => {
            let (src, dst) = (v1_addr::<Ipv6Addr>(src)?, v1_addr::<Ipv6Addr>(dst)?);
            V1::Tcp6 { src, dst, src_port: v1_port(sport)?, dst_port: v1_port(dport)? }
        }
        _ => return Err(Error::V1Syntax),
    };
    Ok(Some((header, used)))
}

fn v1_addr<A: std::str::FromStr>(field: &[u8]) -> Result<A, Error> {
    std::str::from_utf8(field).ok().and_then(|s| s.parse().ok()).ok_or(Error::V1Address)
}

fn v1_port(field: &[u8]) -> Result<u16, Error> {
    let ok = !field.is_empty()
        && field.len() <= 5
        && field.iter().all(u8::is_ascii_digit)
        && (field[0] != b'0' || field.len() == 1);
    if !ok {
        return Err(Error::V1Port);
    }
    let mut n: u32 = 0;
    for &d in field {
        n = n * 10 + u32::from(d - b'0');
    }
    u16::try_from(n).map_err(|_| Error::V1Port)
}

/// Two socket addresses as IP addresses of one family. If they differ, the
/// IPv4 one becomes an IPv4-mapped IPv6 address.
enum SamePair {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

fn same_family(src: SocketAddr, dst: SocketAddr) -> SamePair {
    let v6 = |a: SocketAddr| match a {
        SocketAddr::V4(a) => a.ip().to_ipv6_mapped(),
        SocketAddr::V6(a) => *a.ip(),
    };
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => SamePair::V4(*s.ip(), *d.ip()),
        _ => SamePair::V6(v6(src), v6(dst)),
    }
}

impl V1 {
    /// A `TCP4` or `TCP6` line for a connection from `src` to `dst`, as a
    /// proxy writes it. If one address is IPv4 and the other IPv6, both
    /// are written as IPv6, the IPv4 one as an IPv4-mapped address. IPv6
    /// scope IDs and flow labels are not carried.
    pub fn from_addrs(src: SocketAddr, dst: SocketAddr) -> V1 {
        let (src_port, dst_port) = (src.port(), dst.port());
        match same_family(src, dst) {
            SamePair::V4(src, dst) => V1::Tcp4 { src, dst, src_port, dst_port },
            SamePair::V6(src, dst) => V1::Tcp6 { src, dst, src_port, dst_port },
        }
    }

    /// The line's bytes, CR and LF included. The text of an `UNKNOWN`
    /// header is cut at its first LF, and to [`V1_MAX_UNKNOWN_REST`] bytes,
    /// so the line stays one line that fits in [`V1_MAX_LEN`]. Text that
    /// does not start with a space is left out, since it would join the
    /// word `UNKNOWN`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = V1_PREFIX.to_vec();
        match self {
            V1::Tcp4 { src, dst, src_port, dst_port } => {
                out.extend_from_slice(format!("TCP4 {src} {dst} {src_port} {dst_port}").as_bytes());
            }
            V1::Tcp6 { src, dst, src_port, dst_port } => {
                out.extend_from_slice(format!("TCP6 {src} {dst} {src_port} {dst_port}").as_bytes());
            }
            V1::Unknown(rest) => {
                let rest = &rest[..rest.len().min(V1_MAX_UNKNOWN_REST)];
                let end = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());
                out.extend_from_slice(b"UNKNOWN");
                if rest.first() == Some(&b' ') {
                    out.extend_from_slice(&rest[..end]);
                }
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

impl Addresses {
    /// An `Inet` or `Inet6` block for a connection from `src` to `dst` over
    /// `transport`. If one address is IPv4 and the other IPv6, both are
    /// written as IPv6, the IPv4 one as an IPv4-mapped address. IPv6 scope
    /// IDs and flow labels are not carried.
    pub fn from_addrs(transport: Transport, src: SocketAddr, dst: SocketAddr) -> Addresses {
        let (src_port, dst_port) = (src.port(), dst.port());
        match same_family(src, dst) {
            SamePair::V4(src, dst) => Addresses::Inet { transport, src, dst, src_port, dst_port },
            SamePair::V6(src, dst) => Addresses::Inet6 { transport, src, dst, src_port, dst_port },
        }
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The address block length and transport for a family and transport
/// byte, or `None` if the specification does not allow the byte.
fn family(fam: u8) -> Option<(usize, Transport)> {
    Some(match fam {
        0x00 => (0, Transport::Stream),
        0x11 => (INET_BLOCK_LEN, Transport::Stream),
        0x12 => (INET_BLOCK_LEN, Transport::Dgram),
        0x21 => (INET6_BLOCK_LEN, Transport::Stream),
        0x22 => (INET6_BLOCK_LEN, Transport::Dgram),
        0x31 => (UNIX_BLOCK_LEN, Transport::Stream),
        0x32 => (UNIX_BLOCK_LEN, Transport::Dgram),
        _ => return None,
    })
}

fn parse_v2(b: &[u8]) -> Result<Option<(V2, usize)>, Error> {
    let Some(&ver_cmd) = b.get(12) else { return Ok(None) };
    if ver_cmd >> 4 != 2 {
        return Err(Error::Version(ver_cmd >> 4));
    }
    let command = match ver_cmd & 0x0f {
        0 => Command::Local,
        1 => Command::Proxy,
        c => return Err(Error::Command(c)),
    };
    let Some(&fam) = b.get(13) else { return Ok(None) };
    // A LOCAL header's block is discarded, so only PROXY fails early.
    let proxy = command == Command::Proxy;
    if proxy && family(fam).is_none() {
        return Err(Error::Family(fam));
    }
    if b.len() < V2_HEADER_LEN {
        return Ok(None);
    }
    let len = be16(b, 14);
    if let (true, Some((block, _))) = (proxy, family(fam))
        && usize::from(len) < block {
            return Err(Error::Length(len));
        }
    let total = V2_HEADER_LEN + usize::from(len);
    if b.len() < total {
        return Ok(None);
    }
    match parse_v2_body(b, fam, total) {
        Ok((addresses, tlvs)) => Ok(Some((V2 { command, addresses, tlvs }, total))),
        // The specification says a receiver accepts a LOCAL header and
        // discards its address block, family included. A wrong checksum,
        // or a CRC32C TLV that cannot be checked, still makes the header
        // invalid.
        Err(e) if !proxy && e != Error::Checksum && e != Error::TlvLength(tlv_type::CRC32C) => {
            Ok(Some((V2 { command, addresses: Addresses::Unspec, tlvs: Vec::new() }, total)))
        }
        Err(e) => Err(e),
    }
}

/// Reads the address block and TLVs of the whole version 2 header
/// `b[..total]`, whose family and transport byte is `fam`.
fn parse_v2_body(b: &[u8], fam: u8, total: usize) -> Result<(Addresses, Vec<Tlv>), Error> {
    let (block, transport) = family(fam).ok_or(Error::Family(fam))?;
    let len = be16(b, 14);
    if usize::from(len) < block {
        return Err(Error::Length(len));
    }
    let a = &b[V2_HEADER_LEN..V2_HEADER_LEN + block];
    let addresses = match fam >> 4 {
        1 => Addresses::Inet {
            transport,
            src: Ipv4Addr::new(a[0], a[1], a[2], a[3]),
            dst: Ipv4Addr::new(a[4], a[5], a[6], a[7]),
            src_port: be16(a, 8),
            dst_port: be16(a, 10),
        },
        2 => {
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&a[..16]);
            dst.copy_from_slice(&a[16..32]);
            Addresses::Inet6 {
                transport,
                src: Ipv6Addr::from(src),
                dst: Ipv6Addr::from(dst),
                src_port: be16(a, 32),
                dst_port: be16(a, 34),
            }
        }
        3 => {
            let mut src = [0u8; UNIX_ADDR_LEN];
            let mut dst = [0u8; UNIX_ADDR_LEN];
            src.copy_from_slice(&a[..UNIX_ADDR_LEN]);
            dst.copy_from_slice(&a[UNIX_ADDR_LEN..]);
            Addresses::Unix { transport, src, dst }
        }
        _ => Addresses::Unspec,
    };
    // First the framing and the checksum, so that a TLV that cannot be
    // read never hides a wrong checksum before it.
    let start = V2_HEADER_LEN + block;
    let mut crc_at = None;
    let mut framing = Ok(());
    let mut i = start;
    while i < total {
        match next_tlv(b, i, total) {
            Ok((kind, value, value_at, next)) => {
                if kind == tlv_type::CRC32C {
                    if value.len() != 4 {
                        return Err(Error::TlvLength(kind));
                    }
                    if crc_at.is_some() {
                        return Err(Error::Checksum);
                    }
                    crc_at = Some(value_at);
                }
                i = next;
            }
            Err(e) => {
                framing = Err(e);
                break;
            }
        }
    }
    if let Some(at) = crc_at {
        let expected = u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let mut crc = crc32c_update(!0, &b[..at]);
        crc = crc32c_update(crc, &[0; 4]);
        crc = crc32c_update(crc, &b[at + 4..total]) ^ !0;
        if crc != expected {
            return Err(Error::Checksum);
        }
    }
    framing?;
    let mut tlvs = Vec::new();
    let mut i = start;
    while i < total {
        let (kind, value, _, next) = next_tlv(b, i, total)?;
        tlvs.push(Tlv::from_raw(kind, value)?);
        i = next;
    }
    Ok((addresses, tlvs))
}

/// Reads the TLV at `b[i..end]`: its type, its value, where the value
/// starts, and where the next TLV starts.
fn next_tlv(b: &[u8], i: usize, end: usize) -> Result<(u8, &[u8], usize, usize), Error> {
    if end.saturating_sub(i) < 3 {
        return Err(Error::TlvTruncated);
    }
    let kind = b[i];
    let value_at = i + 3;
    let next = value_at + usize::from(be16(b, i + 1));
    if next > end {
        return Err(Error::TlvTruncated);
    }
    Ok((kind, &b[value_at..next], value_at, next))
}

/// Checks that `value` is valid for a TLV of type `kind`, as
/// [`Tlv::from_raw`] does, without copying it.
fn check_raw(kind: u8, value: &[u8]) -> Result<(), Error> {
    let ok = match kind {
        _ if value.len() > MAX_TLV_VALUE => false,
        tlv_type::CRC32C => value.len() == 4,
        tlv_type::UNIQUE_ID => value.len() <= MAX_UNIQUE_ID,
        tlv_type::SSL => {
            check_ssl(value)?;
            true
        }
        _ => true,
    };
    if ok { Ok(()) } else { Err(Error::TlvLength(kind)) }
}

/// Checks an `SSL` TLV's value, as [`Ssl::parse`] does, without copying it.
fn check_ssl(value: &[u8]) -> Result<(), Error> {
    if value.len() < SSL_FIXED_LEN || value.len() > MAX_TLV_VALUE {
        return Err(Error::TlvLength(tlv_type::SSL));
    }
    let mut i = SSL_FIXED_LEN;
    while i < value.len() {
        i = next_tlv(value, i, value.len())?.3;
    }
    Ok(())
}

impl Tlv {
    /// Reads a TLV of type `kind` from its value. A value longer than
    /// [`MAX_TLV_VALUE`], which no header can hold, is refused.
    pub fn from_raw(kind: u8, value: &[u8]) -> Result<Tlv, Error> {
        check_raw(kind, value)?;
        Ok(match kind {
            tlv_type::ALPN => Tlv::Alpn(value.to_vec()),
            tlv_type::AUTHORITY => Tlv::Authority(value.to_vec()),
            tlv_type::CRC32C => match <[u8; 4]>::try_from(value) {
                Ok(v) => Tlv::Crc32c(u32::from_be_bytes(v)),
                Err(_) => return Err(Error::TlvLength(kind)),
            },
            tlv_type::NOOP => Tlv::Noop(value.to_vec()),
            tlv_type::UNIQUE_ID => Tlv::UniqueId(value.to_vec()),
            tlv_type::SSL => Tlv::Ssl(Ssl::parse(value)?),
            tlv_type::NETNS => Tlv::NetNs(value.to_vec()),
            _ => Tlv::Other { kind, value: value.to_vec() },
        })
    }

    /// The TLV's type.
    pub fn kind(&self) -> u8 {
        match self {
            Tlv::Alpn(_) => tlv_type::ALPN,
            Tlv::Authority(_) => tlv_type::AUTHORITY,
            Tlv::Crc32c(_) => tlv_type::CRC32C,
            Tlv::Noop(_) => tlv_type::NOOP,
            Tlv::UniqueId(_) => tlv_type::UNIQUE_ID,
            Tlv::Ssl(_) => tlv_type::SSL,
            Tlv::NetNs(_) => tlv_type::NETNS,
            Tlv::Other { kind, .. } => *kind,
        }
    }

    /// The TLV's value as a writer puts it out: a UNIQUE_ID is cut to
    /// [`MAX_UNIQUE_ID`] bytes, and an `Other` whose type this module
    /// names but whose value it cannot read gives `None`. Byte values are
    /// borrowed, not copied.
    fn value(&self) -> Option<Cow<'_, [u8]>> {
        Some(match self {
            Tlv::Alpn(v) | Tlv::Authority(v) | Tlv::Noop(v) | Tlv::NetNs(v) => Cow::Borrowed(&v[..]),
            Tlv::Crc32c(c) => Cow::Owned(c.to_be_bytes().to_vec()),
            Tlv::UniqueId(v) => Cow::Borrowed(&v[..v.len().min(MAX_UNIQUE_ID)]),
            Tlv::Ssl(s) => Cow::Owned(s.to_value()),
            Tlv::Other { kind, value } => {
                check_raw(*kind, value).ok()?;
                Cow::Borrowed(&value[..])
            }
        })
    }
}

impl Ssl {
    /// Reads an `SSL` TLV's value. A value longer than [`MAX_TLV_VALUE`],
    /// which no header can hold, is refused.
    pub fn parse(value: &[u8]) -> Result<Ssl, Error> {
        check_ssl(value)?;
        let client = value[0];
        let verify = u32::from_be_bytes([value[1], value[2], value[3], value[4]]);
        let mut tlvs = Vec::new();
        let mut i = SSL_FIXED_LEN;
        while i < value.len() {
            let (kind, v, _, next) = next_tlv(value, i, value.len())?;
            tlvs.push(SslTlv::from_raw(kind, v));
            i = next;
        }
        Ok(Ssl { client, verify, tlvs })
    }

    /// The value's bytes. Sub-TLVs that would take the value past what a
    /// TLV can hold are left out.
    pub fn to_value(&self) -> Vec<u8> {
        // The value must fit in a TLV inside a header body.
        let limit = MAX_TLV_VALUE;
        let mut out = vec![self.client];
        out.extend_from_slice(&self.verify.to_be_bytes());
        for t in &self.tlvs {
            let v = t.value();
            if v.len() > limit - out.len() || limit - out.len() - v.len() < 3 {
                continue;
            }
            out.push(t.kind());
            out.extend_from_slice(&(v.len() as u16).to_be_bytes());
            out.extend_from_slice(v);
        }
        out
    }
}

impl SslTlv {
    /// Reads a sub-TLV of type `kind` from its value.
    pub fn from_raw(kind: u8, value: &[u8]) -> SslTlv {
        let v = value.to_vec();
        match kind {
            tlv_type::SSL_VERSION => SslTlv::Version(v),
            tlv_type::SSL_CN => SslTlv::CommonName(v),
            tlv_type::SSL_CIPHER => SslTlv::Cipher(v),
            tlv_type::SSL_SIG_ALG => SslTlv::SigAlg(v),
            tlv_type::SSL_KEY_ALG => SslTlv::KeyAlg(v),
            kind => SslTlv::Other { kind, value: v },
        }
    }

    /// The sub-TLV's type.
    pub fn kind(&self) -> u8 {
        match self {
            SslTlv::Version(_) => tlv_type::SSL_VERSION,
            SslTlv::CommonName(_) => tlv_type::SSL_CN,
            SslTlv::Cipher(_) => tlv_type::SSL_CIPHER,
            SslTlv::SigAlg(_) => tlv_type::SSL_SIG_ALG,
            SslTlv::KeyAlg(_) => tlv_type::SSL_KEY_ALG,
            SslTlv::Other { kind, .. } => *kind,
        }
    }

    /// The sub-TLV's value.
    pub fn value(&self) -> &[u8] {
        match self {
            SslTlv::Version(v)
            | SslTlv::CommonName(v)
            | SslTlv::Cipher(v)
            | SslTlv::SigAlg(v)
            | SslTlv::KeyAlg(v)
            | SslTlv::Other { value: v, .. } => v,
        }
    }
}

impl V2 {
    /// The header's bytes. TLVs that would take the header past
    /// [`V2_MAX_LEN`] are left out, as are a second CRC32C TLV and an
    /// `Other` TLV of a named type whose value is not valid for it. If a
    /// CRC32C TLV is written, its value is the checksum of the bytes
    /// written.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(V2_HEADER_LEN + UNIX_BLOCK_LEN);
        out.extend_from_slice(&V2_SIGNATURE);
        out.push(match self.command {
            Command::Local => 0x20,
            Command::Proxy => 0x21,
        });
        let t = |t: &Transport| match t {
            Transport::Stream => 1,
            Transport::Dgram => 2,
        };
        out.push(match &self.addresses {
            Addresses::Unspec => 0x00,
            Addresses::Inet { transport, .. } => 0x10 | t(transport),
            Addresses::Inet6 { transport, .. } => 0x20 | t(transport),
            Addresses::Unix { transport, .. } => 0x30 | t(transport),
        });
        out.extend_from_slice(&[0, 0]);
        match &self.addresses {
            Addresses::Unspec => {}
            Addresses::Inet { src, dst, src_port, dst_port, .. } => {
                out.extend_from_slice(&src.octets());
                out.extend_from_slice(&dst.octets());
                out.extend_from_slice(&src_port.to_be_bytes());
                out.extend_from_slice(&dst_port.to_be_bytes());
            }
            Addresses::Inet6 { src, dst, src_port, dst_port, .. } => {
                out.extend_from_slice(&src.octets());
                out.extend_from_slice(&dst.octets());
                out.extend_from_slice(&src_port.to_be_bytes());
                out.extend_from_slice(&dst_port.to_be_bytes());
            }
            Addresses::Unix { src, dst, .. } => {
                out.extend_from_slice(src);
                out.extend_from_slice(dst);
            }
        }
        let mut crc_at = None;
        for tlv in &self.tlvs {
            let kind = tlv.kind();
            if kind == tlv_type::CRC32C && crc_at.is_some() {
                continue;
            }
            let Some(value) = tlv.value() else { continue };
            let room = V2_MAX_LEN - out.len();
            if value.len() > room || room - value.len() < 3 {
                continue;
            }
            out.push(kind);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            if kind == tlv_type::CRC32C {
                crc_at = Some(out.len());
                out.extend_from_slice(&[0; 4]);
            } else {
                out.extend_from_slice(&value);
            }
        }
        let len = (out.len() - V2_HEADER_LEN) as u16;
        out[14..16].copy_from_slice(&len.to_be_bytes());
        if let Some(at) = crc_at {
            let crc = crc32c(&out);
            out[at..at + 4].copy_from_slice(&crc.to_be_bytes());
        }
        out
    }

    /// The value of the first TLV of type `kind`, if there is one whose
    /// value is plain bytes (not CRC32C or SSL).
    pub fn tlv(&self, kind: u8) -> Option<&[u8]> {
        self.tlvs.iter().find(|t| t.kind() == kind).and_then(|t| match t {
            Tlv::Alpn(v) | Tlv::Authority(v) | Tlv::Noop(v) | Tlv::UniqueId(v) | Tlv::NetNs(v) => Some(&v[..]),
            Tlv::Other { value, .. } => Some(&value[..]),
            Tlv::Crc32c(_) | Tlv::Ssl(_) => None,
        })
    }

    /// The first `SSL` TLV, if there is one.
    pub fn ssl(&self) -> Option<&Ssl> {
        self.tlvs.iter().find_map(|t| match t {
            Tlv::Ssl(s) => Some(s),
            _ => None,
        })
    }
}

/// A Unix socket path without the zero bytes that pad it: the bytes before
/// the first zero.
pub fn unix_path(addr: &[u8; UNIX_ADDR_LEN]) -> &[u8] {
    let end = addr.iter().position(|&c| c == 0).unwrap_or(UNIX_ADDR_LEN);
    &addr[..end]
}

/// A Unix socket address for a version 2 header: `path`, cut to
/// [`UNIX_ADDR_LEN`] bytes and padded with zeros.
pub fn unix_addr(path: &[u8]) -> [u8; UNIX_ADDR_LEN] {
    let mut out = [0u8; UNIX_ADDR_LEN];
    let n = path.len().min(UNIX_ADDR_LEN);
    out[..n].copy_from_slice(&path[..n]);
    out
}

/// The CRC32C (Castagnoli) checksum of `data`, as RFC 4960 appendix B
/// works it out. A version 2 CRC32C TLV holds this over the whole header,
/// with the TLV's own value set to zeros.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(!0, data) ^ !0
}

fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    crc
}

/// What a [`Decoder`] has found after a feed.
/// New code uses [`codec::Step`] with [`Headers`] and [`codec::Stream`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // one per connection, as with Header
pub enum Step {
    /// The bytes so far are part of a header. Feed more.
    NeedMore,
    /// The header is whole.
    Header {
        /// The header.
        header: Header,
        /// The bytes fed after the header. They belong to the protocol the
        /// connection carries.
        rest: Vec<u8>,
    },
    /// The bytes are not a valid header.
    Failed {
        /// What is wrong with them.
        error: Error,
        /// Every byte fed so far, for a world that accepts connections with
        /// no header when the error is [`Error::NotProxy`].
        bytes: Vec<u8>,
    },
    /// The decoder already returned `Header` or `Failed`. The fed bytes
    /// are dropped; read the connection directly.
    Finished,
}

/// Reads the PROXY header at the start of a connection. Feed it the bytes
/// the connection reads, in order, until it returns something other than
/// [`Step::NeedMore`]. It never holds more than [`MAX_HEADER_LEN`] bytes.
/// New code uses [`Headers`] with [`codec::Stream`].
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    finished: bool,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection and says what the decoder has
    /// found so far.
    pub fn feed(&mut self, bytes: &[u8]) -> Step {
        if self.finished {
            return Step::Finished;
        }
        // A full buffer always decides, since no header is longer.
        let take = bytes.len().min(MAX_HEADER_LEN - self.buf.len());
        self.buf.extend_from_slice(&bytes[..take]);
        match Header::parse(&self.buf) {
            Ok(None) => Step::NeedMore,
            Ok(Some((header, used))) => {
                self.finished = true;
                let mut rest = self.buf.split_off(used);
                rest.extend_from_slice(&bytes[take..]);
                self.buf = Vec::new();
                Step::Header { header, rest }
            }
            Err(error) => {
                self.finished = true;
                let mut all = std::mem::take(&mut self.buf);
                all.extend_from_slice(&bytes[take..]);
                Step::Failed { error, bytes: all }
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a header.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp4() -> Header {
        Header::V2(V2 {
            command: Command::Proxy,
            addresses: Addresses::Inet {
                transport: Transport::Stream,
                src: Ipv4Addr::new(192, 0, 2, 1),
                dst: Ipv4Addr::new(198, 51, 100, 2),
                src_port: 56324,
                dst_port: 443,
            },
            tlvs: vec![],
        })
    }

    fn reparses(h: &Header) -> Header {
        let bytes = h.to_bytes();
        let (back, used) = Header::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        back
    }

    // Examples from the HAProxy PROXY protocol specification, section 2.1.

    #[test]
    fn v1_examples() {
        let line = b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        let (h, used) = Header::parse(line).unwrap().unwrap();
        assert_eq!(used, line.len());
        let b = Ipv4Addr::BROADCAST;
        assert_eq!(h, Header::V1(V1::Tcp4 { src: b, dst: b, src_port: 65535, dst_port: 65535 }));
        assert_eq!(h.to_bytes(), line);

        let f = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let line = format!("PROXY TCP6 {f} {f} 65535 65535\r\n");
        assert_eq!(line.len(), 104);
        let (h, _) = Header::parse(line.as_bytes()).unwrap().unwrap();
        assert_eq!(h.to_bytes(), line.as_bytes());

        // The worst case: UNKNOWN with the longest addresses is 107 bytes.
        let line = format!("PROXY UNKNOWN {f} {f} 65535 65535\r\n");
        assert_eq!(line.len(), V1_MAX_LEN);
        let (h, _) = Header::parse(line.as_bytes()).unwrap().unwrap();
        assert_eq!(h, Header::V1(V1::Unknown(format!(" {f} {f} 65535 65535").into_bytes())));
        assert_eq!(h.to_bytes(), line.as_bytes());
        assert_eq!(h.addresses(), None);

        let (h, used) = Header::parse(b"PROXY UNKNOWN\r\nabc").unwrap().unwrap();
        assert_eq!((h, used), (Header::V1(V1::Unknown(vec![])), 15));

        let (h, _) = Header::parse(b"PROXY TCP6 2001:db8::1 ::ffff:192.0.2.1 0 80\r\n").unwrap().unwrap();
        let (s, d) = h.addresses().unwrap();
        assert_eq!(s.to_string(), "[2001:db8::1]:0");
        assert_eq!(d.port(), 80);
    }

    #[test]
    fn v1_errors() {
        let e = |b: &[u8]| Header::parse(b).unwrap_err();
        assert_eq!(e(b"GET / HTTP/1.1\r\n"), Error::NotProxy);
        assert_eq!(e(b"PROXY\r\n"), Error::NotProxy);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n"), Error::V1Syntax);
        assert_eq!(e(b"PROXY \r\n"), Error::V1Syntax);
        assert_eq!(e(b"PROXY \n"), Error::V1Syntax);
        assert_eq!(e(b"PROXY TCP5 1.2.3.4 5.6.7.8 1 2\r\n"), Error::V1Syntax);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n"), Error::V1Syntax);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n"), Error::V1Syntax);
        assert_eq!(e(b"PROXY TCP4  1.2.3.4 5.6.7.8 1\r\n"), Error::V1Address);
        assert_eq!(e(b"PROXY TCP4 1.2.3.400 5.6.7.8 1 2\r\n"), Error::V1Address);
        assert_eq!(e(b"PROXY TCP4 ::1 5.6.7.8 1 2\r\n"), Error::V1Address);
        assert_eq!(e(b"PROXY TCP6 1.2.3.4 ::1 1 2\r\n"), Error::V1Address);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.\xff 1 2\r\n"), Error::V1Address);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n"), Error::V1Port);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n"), Error::V1Port);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 \r\n"), Error::V1Port);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 +2\r\n"), Error::V1Port);
        assert_eq!(e(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 123456\r\n"), Error::V1Port);
        assert_eq!(e(&[b'P', b'R', b'O', b'X', b'Y', b' '].iter().copied().chain([b'x'; 101]).collect::<Vec<_>>()), Error::V1TooLong);
        // A port of 0 is allowed.
        assert!(Header::parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 0 0\r\n").unwrap().is_some());
    }

    #[test]
    fn v2_spec_layout() {
        let bytes = tcp4().to_bytes();
        let mut want = V2_SIGNATURE.to_vec();
        want.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c, 192, 0, 2, 1, 198, 51, 100, 2, 0xdc, 0x04, 0x01, 0xbb]);
        assert_eq!(bytes, want);
        assert_eq!(Header::parse(&bytes), Ok(Some((tcp4(), 28))));
        // Version 2 headers carry no addresses for LOCAL.
        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        let (h, _) = Header::parse(&local).unwrap().unwrap();
        assert_eq!(h, Header::V2(V2 { command: Command::Local, addresses: Addresses::Unspec, tlvs: vec![] }));
        assert_eq!(h.addresses(), None);
        assert_eq!(h.to_bytes(), local);
    }

    #[test]
    fn v2_every_family() {
        let tr = [Transport::Stream, Transport::Dgram];
        for (i, transport) in tr.into_iter().enumerate() {
            let fams = [
                Addresses::Inet { transport, src: Ipv4Addr::LOCALHOST, dst: Ipv4Addr::UNSPECIFIED, src_port: 1, dst_port: 2 },
                Addresses::Inet6 { transport, src: Ipv6Addr::LOCALHOST, dst: "2001:db8::2".parse().unwrap(), src_port: 3, dst_port: 4 },
                Addresses::Unix { transport, src: unix_addr(b"/run/a.sock"), dst: unix_addr(&[b'x'; 200]) },
            ];
            for (f, addresses) in fams.into_iter().enumerate() {
                let h = Header::V2(V2 { command: Command::Proxy, addresses, tlvs: vec![] });
                let bytes = h.to_bytes();
                assert_eq!(bytes[13], ((f as u8 + 1) << 4) | (i as u8 + 1));
                assert_eq!(bytes.len(), V2_HEADER_LEN + [INET_BLOCK_LEN, INET6_BLOCK_LEN, UNIX_BLOCK_LEN][f]);
                assert_eq!(reparses(&h), h);
                if let Header::V2(V2 { addresses: Addresses::Unix { src, dst, .. }, .. }) = &h {
                    assert_eq!(unix_path(src), b"/run/a.sock");
                    assert_eq!(unix_path(dst).len(), UNIX_ADDR_LEN);
                    assert_eq!(h.addresses(), None);
                } else {
                    assert!(h.addresses().is_some());
                }
            }
        }
    }

    #[test]
    fn v2_tlvs_and_ssl() {
        let ssl = Ssl {
            client: client::SSL | client::CERT_CONN | client::CERT_SESS,
            verify: 0,
            tlvs: vec![
                SslTlv::Version(b"TLSv1.3".to_vec()),
                SslTlv::CommonName(b"client".to_vec()),
                SslTlv::Cipher(b"TLS_AES_128_GCM_SHA256".to_vec()),
                SslTlv::SigAlg(b"SHA256".to_vec()),
                SslTlv::KeyAlg(b"RSA2048".to_vec()),
                SslTlv::Other { kind: 0x26, value: b"x".to_vec() },
            ],
        };
        let Header::V2(mut v2) = tcp4() else { unreachable!() };
        v2.tlvs = vec![
            Tlv::Alpn(b"h2".to_vec()),
            Tlv::Authority(b"example.com".to_vec()),
            Tlv::Crc32c(0),
            Tlv::Noop(vec![0; 3]),
            Tlv::UniqueId(vec![7; 16]),
            Tlv::Ssl(ssl.clone()),
            Tlv::NetNs(b"blue".to_vec()),
            Tlv::Other { kind: 0xea, value: vec![1, 2] },
        ];
        let h = Header::V2(v2.clone());
        let back = reparses(&h);
        let Header::V2(b) = &back else { panic!() };
        // The checksum was filled in.
        let Tlv::Crc32c(crc) = b.tlvs[2] else { panic!() };
        assert_ne!(crc, 0);
        assert_eq!(b.tlvs[..2], v2.tlvs[..2]);
        assert_eq!(b.tlvs[3..], v2.tlvs[3..]);
        assert_eq!(b.ssl(), Some(&ssl));
        assert_eq!(b.tlv(tlv_type::AUTHORITY), Some(&b"example.com"[..]));
        assert_eq!(b.tlv(tlv_type::CRC32C), None);
        assert_eq!(b.tlv(0x99), None);
        // A header read back writes the same bytes.
        assert_eq!(back.to_bytes(), h.to_bytes());
        assert_eq!(ssl.tlvs[0].value(), b"TLSv1.3");
    }

    #[test]
    fn crc32c_matches_rfc() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0; 32]), 0x8a91_36aa);
    }

    #[test]
    fn v2_errors() {
        let good = tcp4().to_bytes();
        let with = |at: usize, v: u8| {
            let mut b = good.clone();
            b[at] = v;
            Header::parse(&b)
        };
        assert_eq!(with(0, 0x0c), Err(Error::NotProxy));
        assert_eq!(with(11, 0), Err(Error::NotProxy));
        assert_eq!(with(12, 0x11), Err(Error::Version(1)));
        assert_eq!(with(12, 0x22), Err(Error::Command(2)));
        assert_eq!(with(13, 0x13), Err(Error::Family(0x13)));
        assert_eq!(with(13, 0x10), Err(Error::Family(0x10)));
        assert_eq!(with(13, 0x01), Err(Error::Family(0x01)));
        assert_eq!(with(15, 11), Err(Error::Length(11)));
        // Errors in the fixed part show before the rest arrives.
        assert_eq!(Header::parse(&with_prefix(&[0x31])), Err(Error::Version(3)));
        assert_eq!(Header::parse(&with_prefix(&[0x21, 0x40])), Err(Error::Family(0x40)));

        let body = |tlvs: &[u8]| {
            let mut b = V2_SIGNATURE.to_vec();
            b.extend_from_slice(&[0x21, 0x00]);
            b.extend_from_slice(&(tlvs.len() as u16).to_be_bytes());
            b.extend_from_slice(tlvs);
            Header::parse(&b)
        };
        assert_eq!(body(&[0x01, 0x00]), Err(Error::TlvTruncated));
        assert_eq!(body(&[0x01, 0x00, 0x02, b'h']), Err(Error::TlvTruncated));
        assert_eq!(body(&[0x03, 0x00, 0x02, 0, 0]), Err(Error::TlvLength(tlv_type::CRC32C)));
        assert_eq!(body(&[0x20, 0x00, 0x04, 1, 0, 0, 0]), Err(Error::TlvLength(tlv_type::SSL)));
        assert_eq!(body(&[0x20, 0x00, 0x07, 1, 0, 0, 0, 0, 0x21, 0]), Err(Error::TlvTruncated));
        let mut uid = vec![0x05, 0x00, 129];
        uid.extend_from_slice(&[0; 129]);
        assert_eq!(body(&uid), Err(Error::TlvLength(tlv_type::UNIQUE_ID)));
        assert_eq!(body(&[0x03, 0x00, 0x04, 1, 2, 3, 4]), Err(Error::Checksum));
        // Two checksums, even correct ones, are refused.
        let one = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![Tlv::Crc32c(0)] }).to_bytes();
        let mut two = one.clone();
        two.extend_from_slice(&one[16..]);
        two[15] = 14;
        assert_eq!(Header::parse(&two), Err(Error::Checksum));
        assert!(Header::parse(&one).unwrap().is_some());
        // A changed byte breaks the checksum.
        let mut bad = one.clone();
        bad[12] = 0x20;
        assert_eq!(Header::parse(&bad), Err(Error::Checksum));
    }

    fn with_prefix(tail: &[u8]) -> Vec<u8> {
        let mut b = V2_SIGNATURE.to_vec();
        b.extend_from_slice(tail);
        b
    }

    #[test]
    fn local_ignores_the_address_block() {
        // The spec: a receiver must accept a LOCAL header and discard the
        // protocol block, family included.
        let local = |fam: u8, body: &[u8]| {
            let mut b = with_prefix(&[0x20, fam]);
            b.extend_from_slice(&(body.len() as u16).to_be_bytes());
            b.extend_from_slice(body);
            Header::parse(&b)
        };
        let empty = Header::V2(V2 { command: Command::Local, addresses: Addresses::Unspec, tlvs: vec![] });
        assert_eq!(local(0x45, &[1, 2, 3]), Ok(Some((empty.clone(), 19))));
        assert_eq!(local(0x11, &[]), Ok(Some((empty.clone(), 16))));
        assert_eq!(local(0x00, &[0x01, 0x00]), Ok(Some((empty.clone(), 18))));
        assert_eq!(local(0x13, &[]).map(|h| h.map(|(h, _)| reparses(&h))), Ok(Some(empty)));
        // A partial LOCAL header with a bad family still needs more.
        assert_eq!(Header::parse(&with_prefix(&[0x20, 0x45, 0x00, 0x03, 1])), Ok(None));
        // A wrong checksum is still refused.
        let mut one = Header::V2(V2 { command: Command::Local, addresses: Addresses::Unspec, tlvs: vec![Tlv::Crc32c(0)] }).to_bytes();
        one[19] ^= 1;
        assert_eq!(Header::parse(&one), Err(Error::Checksum));
    }

    #[test]
    fn a_later_bad_tlv_does_not_hide_a_wrong_checksum() {
        // LOCAL: a wrong checksum followed by a truncated TLV. The checksum
        // should be 0x5c5f83af.
        let local = with_prefix(&[0x20, 0x00, 0x00, 0x08, 0x03, 0x00, 0x04, 0, 0, 0, 0, 0xff]);
        assert_eq!(Header::parse(&local), Err(Error::Checksum));
        // The same header with the right checksum is accepted, as LOCAL.
        let mut right = local.clone();
        right[19..23].copy_from_slice(&0x5c5f_83afu32.to_be_bytes());
        let empty = Header::V2(V2 { command: Command::Local, addresses: Addresses::Unspec, tlvs: vec![] });
        assert_eq!(Header::parse(&right), Ok(Some((empty, 24))));
        // A checksum after a TLV whose value is bad is still checked.
        let local = with_prefix(&[0x20, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x03, 0x00, 0x04, 0, 0, 0, 0]);
        assert_eq!(Header::parse(&local), Err(Error::Checksum));
        let mut proxy = local.clone();
        proxy[12] = 0x21;
        assert_eq!(Header::parse(&proxy), Err(Error::Checksum));
        // A CRC32C TLV that cannot be checked is refused under LOCAL too.
        let local = with_prefix(&[0x20, 0x00, 0x00, 0x05, 0x03, 0x00, 0x02, 0, 0]);
        assert_eq!(Header::parse(&local), Err(Error::TlvLength(tlv_type::CRC32C)));
    }

    #[test]
    fn raw_readers_refuse_values_no_header_can_hold() {
        // An SSL value over 65,532 bytes cannot be in any header.
        let mut ssl = vec![0, 0, 0, 0, 1];
        for _ in 0..21_844 {
            ssl.extend_from_slice(&[0xe0, 0, 0]);
        }
        assert_eq!(ssl.len(), 65_537);
        assert_eq!(Ssl::parse(&ssl), Err(Error::TlvLength(tlv_type::SSL)));
        assert_eq!(Tlv::from_raw(tlv_type::SSL, &ssl), Err(Error::TlvLength(tlv_type::SSL)));
        assert_eq!(Tlv::from_raw(tlv_type::NOOP, &[0; MAX_TLV_VALUE + 1]), Err(Error::TlvLength(tlv_type::NOOP)));
        assert_eq!(Tlv::from_raw(0xe0, &[0; MAX_TLV_VALUE + 1]), Err(Error::TlvLength(0xe0)));
        // The longest that fits reads, and writes back whole.
        ssl.truncate(MAX_TLV_VALUE - (MAX_TLV_VALUE - SSL_FIXED_LEN) % 3);
        let s = Ssl::parse(&ssl).unwrap();
        assert_eq!(s.to_value(), ssl);
        let h = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![Tlv::Ssl(s)] });
        assert_eq!(reparses(&h), h);
    }

    #[test]
    fn writers_borrow_values_they_check() {
        // Writing does not copy a byte value just to check or measure it.
        let big = vec![0u8; 100_000];
        for t in [
            Tlv::Noop(big.clone()),
            Tlv::UniqueId(big.clone()),
            Tlv::Other { kind: 0xe0, value: big.clone() },
            Tlv::Other { kind: tlv_type::SSL, value: big.clone() },
        ] {
            assert!(!matches!(t.value(), Some(std::borrow::Cow::Owned(_))), "{}", t.kind());
        }
    }

    #[test]
    fn v1_unknown_is_a_word() {
        assert_eq!(Header::parse(b"PROXY UNKNOWNfoo\r\n"), Err(Error::V1Syntax));
        assert_eq!(Header::parse(b"PROXY UNKNOWN4 1.2.3.4 5.6.7.8 1 2\r\n"), Err(Error::V1Syntax));
        assert!(Header::parse(b"PROXY UNKNOWN junk\r\n").unwrap().is_some());
        // The writer leaves out text that would join the word.
        let h = Header::V1(V1::Unknown(b"foo".to_vec()));
        assert_eq!(h.to_bytes(), b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn v2_short_length_fails_early() {
        // A PROXY header whose length cannot hold its address block fails
        // as soon as the length is read.
        assert_eq!(Header::parse(&with_prefix(&[0x21, 0x21, 0x00, 0x0c])), Err(Error::Length(12)));
    }

    #[test]
    fn every_truncated_prefix_needs_more() {
        let Header::V2(mut v2) = tcp4() else { unreachable!() };
        v2.tlvs = vec![Tlv::Crc32c(0), Tlv::Ssl(Ssl { client: 1, verify: 0, tlvs: vec![SslTlv::Version(b"TLSv1.2".to_vec())] })];
        let headers = [
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            b"PROXY TCP6 ::1 ::2 1 2\r\n".to_vec(),
            Header::V2(v2).to_bytes(),
            tcp4().to_bytes(),
        ];
        for h in &headers {
            for n in 0..h.len() {
                assert_eq!(Header::parse(&h[..n]), Ok(None), "{n} bytes of {h:?}");
            }
            assert!(Header::parse(h).unwrap().is_some());
        }
        assert_eq!(detect(b""), Detection::NeedMore);
        assert_eq!(detect(b"PRO"), Detection::NeedMore);
        assert_eq!(detect(b"PROXY "), Detection::V1);
        assert_eq!(detect(&V2_SIGNATURE[..5]), Detection::NeedMore);
        assert_eq!(detect(&V2_SIGNATURE), Detection::V2);
        assert_eq!(detect(b"\x16\x03\x01"), Detection::NotProxy);
    }

    #[test]
    fn decoder() {
        let mut stream = tcp4().to_bytes();
        stream.extend_from_slice(b"hello");
        let mut d = Decoder::new();
        let mut got = None;
        for (i, b) in stream.iter().enumerate() {
            match d.feed(std::slice::from_ref(b)) {
                Step::NeedMore => assert_eq!(d.buffered(), i + 1),
                Step::Header { header, rest } => {
                    assert_eq!(header, tcp4());
                    assert!(rest.is_empty());
                    got = Some(i);
                }
                Step::Finished => {}
                s => panic!("{s:?}"),
            }
        }
        assert_eq!(got, Some(27));
        assert_eq!(d.feed(b"x"), Step::Finished);
        assert_eq!(d.buffered(), 0);

        // Not a header: every byte comes back.
        let mut d = Decoder::new();
        assert_eq!(d.feed(b"PRO"), Step::NeedMore);
        assert_eq!(d.feed(b"BE x"), Step::Failed { error: Error::NotProxy, bytes: b"PROBE x".to_vec() });
        assert_eq!(d.feed(b"y"), Step::Finished);

        // The rest of one big feed comes back whole, though the decoder
        // keeps no more than a header's worth.
        let mut big = b"PROXY UNKNOWN\r\n".to_vec();
        big.extend(std::iter::repeat_n(9u8, 2 * MAX_HEADER_LEN));
        let mut d = Decoder::new();
        let Step::Header { rest, .. } = d.feed(&big) else { panic!() };
        assert_eq!(rest.len(), 2 * MAX_HEADER_LEN);
    }

    #[test]
    fn writers_cap_what_they_write() {
        // UNKNOWN text with a line feed, and too long.
        let h = Header::V1(V1::Unknown(b" a\nb".to_vec()));
        assert_eq!(reparses(&h), Header::V1(V1::Unknown(b" a".to_vec())));
        let mut long = vec![b'z'; 500];
        long[0] = b' ';
        let h = Header::V1(V1::Unknown(long.clone()));
        assert_eq!(h.to_bytes().len(), V1_MAX_LEN);
        assert_eq!(reparses(&h), Header::V1(V1::Unknown(long[..V1_MAX_UNKNOWN_REST].to_vec())));
        let h = Header::V1(V1::Unknown(b" \r".to_vec()));
        assert_eq!(reparses(&h), h);

        // TLVs past the length limit, a long unique ID, bad Other TLVs and
        // a second checksum are left out or cut.
        let h = Header::V2(V2 {
            command: Command::Local,
            addresses: Addresses::Unix { transport: Transport::Stream, src: [1; 108], dst: [2; 108] },
            tlvs: vec![
                Tlv::Noop(vec![0; 40_000]),
                Tlv::Noop(vec![0; 40_000]),
                Tlv::UniqueId(vec![5; 300]),
                Tlv::Other { kind: tlv_type::CRC32C, value: vec![1, 2, 3] },
                Tlv::Other { kind: tlv_type::SSL, value: vec![] },
                Tlv::Other { kind: tlv_type::CRC32C, value: vec![1, 2, 3, 4] },
                Tlv::Crc32c(9),
                Tlv::Ssl(Ssl { client: 0, verify: 1, tlvs: vec![SslTlv::Cipher(vec![3; 70_000]), SslTlv::CommonName(b"cn".to_vec())] }),
                Tlv::Noop(vec![0; 30_000]),
            ],
        });
        let bytes = h.to_bytes();
        assert!(bytes.len() <= V2_MAX_LEN);
        let Header::V2(back) = reparses(&h) else { panic!() };
        let kinds: Vec<u8> = back.tlvs.iter().map(Tlv::kind).collect();
        assert_eq!(kinds, [4, 5, 3, 0x20]);
        assert_eq!(back.tlv(tlv_type::UNIQUE_ID).unwrap().len(), MAX_UNIQUE_ID);
        assert_eq!(back.ssl().unwrap().tlvs, [SslTlv::CommonName(b"cn".to_vec())]);

        // A header that fills the length field exactly.
        let h = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![Tlv::Noop(vec![0; V2_MAX_BODY - 3])] });
        assert_eq!(h.to_bytes().len(), V2_MAX_LEN);
        assert_eq!(reparses(&h), h);
    }

    #[test]
    fn headers_from_socket_addresses() {
        let v4 = |s: &str| s.parse::<SocketAddr>().unwrap();
        let (a, b) = (v4("192.0.2.1:56324"), v4("198.51.100.2:443"));
        let (c, d) = (v4("[2001:db8::1]:1"), v4("[2001:db8::2]:2"));
        let mapped = v4("[::ffff:192.0.2.1]:56324");

        let h = Header::V1(V1::from_addrs(a, b));
        assert_eq!(h.to_bytes(), b"PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n");
        assert_eq!(h.addresses(), Some((a, b)));
        let h = Header::V1(V1::from_addrs(c, d));
        assert_eq!(reparses(&h).addresses(), Some((c, d)));
        // Mixed families share IPv6, with the IPv4 address mapped.
        let h = Header::V1(V1::from_addrs(a, d));
        assert_eq!(reparses(&h).addresses(), Some((mapped, d)));

        for transport in [Transport::Stream, Transport::Dgram] {
            for (s, t, want) in [(a, b, (a, b)), (c, d, (c, d)), (a, d, (mapped, d))] {
                let h = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::from_addrs(transport, s, t), tlvs: vec![] });
                assert_eq!(reparses(&h).addresses(), Some(want));
            }
        }
        // A scope ID or flow label is not part of the header.
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 9, 7, 3));
        let Header::V1(back) = reparses(&Header::V1(V1::from_addrs(scoped, d))) else { panic!() };
        assert_eq!(back, V1::Tcp6 { src: "fe80::1".parse().unwrap(), dst: "2001:db8::2".parse().unwrap(), src_port: 9, dst_port: 2 });
    }

    #[test]
    fn decoder_is_linear_on_the_longest_header() {
        // A byte at a time through the longest header does not reread it.
        let h = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![Tlv::Crc32c(0), Tlv::Noop(vec![0; V2_MAX_BODY - 10])] });
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), V2_MAX_LEN);
        let start = std::time::Instant::now();
        let mut d = Decoder::new();
        for (i, b) in bytes.iter().enumerate() {
            let step = d.feed(std::slice::from_ref(b));
            if i + 1 < bytes.len() {
                assert_eq!(step, Step::NeedMore);
            } else {
                assert_eq!(step, Step::Header { header: reparses(&h), rest: vec![] });
            }
        }
        assert!(start.elapsed().as_secs() < 5);
    }

    /// A small deterministic generator, so the fuzz loop runs the same way
    /// every time.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    fn random_header(r: &mut Lcg) -> Header {
        let transport = if r.below(2) == 0 { Transport::Stream } else { Transport::Dgram };
        let port = |r: &mut Lcg| r.next() as u16;
        match r.below(6) {
            0 => Header::V1(V1::Tcp4 { src: Ipv4Addr::from(r.next()), dst: Ipv4Addr::from(r.next()), src_port: port(r), dst_port: port(r) }),
            1 => {
                let a = |r: &mut Lcg| Ipv6Addr::from(u128::from(r.next()) << (r.below(4) * 32));
                Header::V1(V1::Tcp6 { src: a(r), dst: a(r), src_port: port(r), dst_port: port(r) })
            }
            2 => {
                let n = r.below(120) as usize;
                let mut text = r.bytes(n);
                if r.below(2) == 0 {
                    text.insert(0, b' ');
                }
                Header::V1(V1::Unknown(text))
            }
            _ => {
                let addresses = match r.below(4) {
                    0 => Addresses::Unspec,
                    1 => Addresses::Inet { transport, src: Ipv4Addr::from(r.next()), dst: Ipv4Addr::from(r.next()), src_port: port(r), dst_port: port(r) },
                    2 => Addresses::Inet6 {
                        transport,
                        src: Ipv6Addr::from(u128::from(r.next())),
                        dst: Ipv6Addr::from(u128::from(r.next()) << 96),
                        src_port: port(r),
                        dst_port: port(r),
                    },
                    _ => {
                        let (a, b) = (r.below(120) as usize, r.below(120) as usize);
                        Addresses::Unix { transport, src: unix_addr(&r.bytes(a)), dst: unix_addr(&r.bytes(b)) }
                    }
                };
                let mut tlvs = Vec::new();
                for _ in 0..r.below(5) {
                    let n = r.below(40) as usize;
                    let v = r.bytes(n);
                    tlvs.push(match r.below(9) {
                        0 => Tlv::Alpn(v),
                        1 => Tlv::Authority(v),
                        2 => Tlv::Crc32c(r.next()),
                        3 => Tlv::Noop(v),
                        4 => Tlv::UniqueId(v),
                        5 => Tlv::Ssl(Ssl {
                            client: r.next() as u8,
                            verify: r.next(),
                            tlvs: (0..r.below(4)).map(|_| SslTlv::from_raw(0x20 + r.below(8) as u8, &v)).collect(),
                        }),
                        6 => Tlv::NetNs(v),
                        _ => Tlv::Other { kind: r.next() as u8, value: v },
                    });
                }
                let command = if r.below(2) == 0 { Command::Local } else { Command::Proxy };
                Header::V2(V2 { command, addresses, tlvs })
            }
        }
    }

    /// Feeds `data` whole and a byte at a time, and checks both agree.
    fn check(data: &[u8]) {
        let whole = Header::parse(data);
        let mut d = Decoder::new();
        let mut bytewise = None;
        for (i, b) in data.iter().enumerate() {
            match d.feed(std::slice::from_ref(b)) {
                Step::NeedMore => assert!(d.buffered() <= MAX_HEADER_LEN),
                Step::Header { header, rest } => {
                    assert!(rest.is_empty());
                    bytewise = Some(Ok((header, i + 1)));
                    break;
                }
                Step::Failed { error, bytes } => {
                    assert_eq!(bytes, &data[..i + 1]);
                    bytewise = Some(Err(error));
                    break;
                }
                Step::Finished => unreachable!(),
            }
        }
        match (&whole, bytewise) {
            (Ok(None), None) => {}
            (Ok(Some(w)), Some(Ok(b))) => assert_eq!(w, &b),
            (Err(w), Some(Err(b))) => assert_eq!(*w, b),
            (w, b) => panic!("whole {w:?}, bytewise {b:?} for {data:?}"),
        }
        // The whole feed gives the same.
        let mut d = Decoder::new();
        match (d.feed(data), &whole) {
            (Step::NeedMore, Ok(None)) => {}
            (Step::Header { header, rest }, Ok(Some((h, used)))) => {
                assert_eq!(&header, h);
                assert_eq!(rest, &data[*used..]);
            }
            (Step::Failed { error, bytes }, Err(e)) => {
                assert_eq!(error, *e);
                assert_eq!(bytes, data);
            }
            (s, w) => panic!("feed {s:?}, parse {w:?}"),
        }
        // A header read can be written, and reads back the same.
        if let Ok(Some((h, _))) = &whole {
            assert_eq!(&reparses(h), h);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg(0x5eed);
        for round in 0..6000 {
            let h = random_header(&mut r);
            // Writers never write what the parser refuses, and a second
            // write changes nothing.
            let bytes = h.to_bytes();
            let (back, used) = Header::parse(&bytes).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(reparses(&back), back);
            assert_eq!(back.to_bytes(), bytes);
            // Every part of a written header needs more.
            for n in 0..bytes.len().min(300) {
                assert_eq!(Header::parse(&bytes[..n]), Ok(None), "{n} bytes of {bytes:?}");
            }
            let mut data = bytes;
            match round % 4 {
                0 => {
                    // Flip a few bytes.
                    for _ in 0..=r.below(3) {
                        let i = r.below(data.len() as u32) as usize;
                        data[i] = r.next() as u8;
                    }
                }
                1 => {
                    let n = r.below(data.len() as u32) as usize;
                    data.truncate(n);
                }
                2 => {
                    let n = r.below(20) as usize;
                    data.extend(r.bytes(n));
                }
                _ => {
                    // Pure noise, sometimes behind a valid prefix.
                    let n = r.below(80) as usize;
                    data = match r.below(3) {
                        0 => r.bytes(n),
                        1 => [&V1_PREFIX[..], &r.bytes(n)].concat(),
                        _ => [&V2_SIGNATURE[..], &r.bytes(n)].concat(),
                    };
                }
            }
            check(&data);
        }
    }
}
