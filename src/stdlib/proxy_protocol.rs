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
//! A server behind a proxy pushes the first connection bytes into
//! [`Stream<Headers>`](super::codec::Stream). It reads one [`Header`] result,
//! then hands the unread suffix to the next protocol with `swap` or
//! `into_parts`. A proxy appends its header with [`Wire::write`] before
//! sending the client's bytes.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. A version 2 header with a CRC32C TLV is checked against
//! its checksum. The specification says a receiver accepts a version 2
//! LOCAL header and discards its address block, so a LOCAL header whose
//! family, addresses or TLVs cannot be read gives no addresses and no TLVs
//! instead of an error. A CRC32C TLV that the reader can find in a LOCAL
//! header is still checked, even when a later TLV cannot be read.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::proxy_protocol::{Addresses, Command, Headers, Header, Tlv, Transport, V2};
//! use std::net::Ipv4Addr;
//!
//! // A version 1 header that arrives in two reads, with the client's
//! // request right behind it.
//! let mut decoder = Stream::new(Headers::new());
//! assert_eq!(decoder.push(b"PROXY TCP4 192.0.2.1 "), 21);
//! assert_eq!(decoder.next(), None);
//! let tail = b"198.51.100.2 56324 443\r\nGET / HTTP/1.1\r\n";
//! assert_eq!(decoder.push(tail), tail.len());
//! let header = decoder.next().unwrap().unwrap().unwrap();
//! let (source, destination) = header.addresses().unwrap();
//! assert_eq!(source.to_string(), "192.0.2.1:56324");
//! assert_eq!(destination.port(), 443);
//! assert_eq!(decoder.unread(), b"GET / HTTP/1.1\r\n");
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
//! let bytes = header.to_bytes().unwrap();
//! assert_eq!(Header::parse(&bytes), Ok(header));
//! ```

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
    /// The header has a different version from the requested wire type.
    WrongVersion,
}

impl core::fmt::Display for HeaderParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete PROXY header"),
            Self::Trailing => f.write_str("bytes after the PROXY header"),
            Self::WrongVersion => f.write_str("PROXY header has the wrong version"),
        }
    }
}
impl core::error::Error for HeaderParseError {}

impl Wire for Header {
    type ParseError = HeaderParseError;
    type WriteError = Error;

    /// Reads exactly one header. Refuses incomplete or trailing bytes,
    /// malformed headers and checksums changed by canonical re-encoding.
    /// LOCAL ignores an unreadable address block, but still checks any
    /// checksum TLV it can find, even before a later malformed TLV.
    fn parse(bytes: &[u8]) -> Result<Self, HeaderParseError> {
        let (header, used) = Self::parse_prefix(bytes)
            .map_err(HeaderParseError::Protocol)?.ok_or(HeaderParseError::Truncated)?;
        if used != bytes.len() {
            return Err(HeaderParseError::Trailing);
        }
        header.write(&mut Vec::new()).map_err(HeaderParseError::Protocol)?;
        Ok(header)
    }

    /// Appends at most [`MAX_HEADER_LEN`] bytes. Refuses oversized fields,
    /// duplicate or incorrect checksums, variant changes and UNKNOWN text
    /// with a newline or without its leading space. Leaves `out` unchanged
    /// on error. Checksums must already match the canonical header.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut bytes = Vec::new();
        match self {
            Header::V1(h) => h.write(&mut bytes)?,
            Header::V2(h) => h.write(&mut bytes)?,
        }
        out.extend_from_slice(&bytes);
        Ok(())
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
                Header::parse_prefix(fixed).map_err(HeaderError::Protocol)?;
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
        let item = Header::parse_prefix(bytes).and_then(|m| m.map(|(h, _)| h).ok_or(Error::V1Syntax));
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
/// The longest header of either version. [`Headers`] never needs more input.
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
    /// [`UNIX_ADDR_LEN`]. [`unix_path`] cuts the padding off. Writers take
    /// all [`UNIX_ADDR_LEN`] bytes as given, padding included.
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
    /// header writer refuses a value that does not match the canonical
    /// header's checksum. Use [`V2::with_checksum`] to set it.
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
    /// parser never makes an `Other` of a type named above. Writers refuse
    /// an `Other` that holds a type named above.
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
    /// Any other sub-type. Writers refuse an `Other` that holds a type
    /// named above.
    Other { kind: u8, value: Vec<u8> },
}

/// Why bytes are not a PROXY protocol header. A real server closes the
/// connection, unless the error is [`Error::NotProxy`] and it also accepts
/// connections with no header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The bytes start with neither `PROXY ` nor the version 2 signature.
    NotProxy,
    /// A version 1 line ran past [`V1_MAX_LEN`] bytes with no LF byte.
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
            Error::Unwritable => f.write_str("PROXY value cannot be written unchanged"),
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
    fn parse_prefix(b: &[u8]) -> Result<Option<(Header, usize)>, Error> {
        match detect(b) {
            Detection::NeedMore => Ok(None),
            Detection::NotProxy => Err(Error::NotProxy),
            Detection::V1 => Ok(parse_v1(b)?.map(|(h, n)| (Header::V1(h), n))),
            Detection::V2 => Ok(parse_v2(b)?.map(|(h, n)| (Header::V2(h), n))),
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

impl Wire for V1 {
    type ParseError = HeaderParseError;
    type WriteError = Error;

    /// Reads exactly one V1 header. Refuses the other version, malformed
    /// addresses or ports, lines longer than `V1_MAX_LEN`, incomplete input
    /// and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, HeaderParseError> {
        match Header::parse(bytes)? {
            Header::V1(value) => Ok(value),
            _ => Err(HeaderParseError::WrongVersion),
        }
    }

    /// Appends one CRLF-terminated line. Refuses UNKNOWN text longer than
    /// `V1_MAX_UNKNOWN_REST`, containing LF or missing its leading space.
    /// Leaves the destination unchanged on error.
    fn write(&self, dest: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = V1_PREFIX.to_vec();
        match self {
            V1::Tcp4 { src, dst, src_port, dst_port } => {
                out.extend_from_slice(format!("TCP4 {src} {dst} {src_port} {dst_port}").as_bytes());
            }
            V1::Tcp6 { src, dst, src_port, dst_port } => {
                out.extend_from_slice(format!("TCP6 {src} {dst} {src_port} {dst_port}").as_bytes());
            }
            V1::Unknown(rest) => {
                if rest.len() > V1_MAX_UNKNOWN_REST || rest.contains(&b'\n')
                    || (!rest.is_empty() && rest.first() != Some(&b' ')) {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(b"UNKNOWN");
                out.extend_from_slice(rest);
            }
        }
        out.extend_from_slice(b"\r\n");
        dest.extend_from_slice(&out);
        Ok(())
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
}

impl Wire for Ssl {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an SSL TLV value. Refuses fewer than [`SSL_FIXED_LEN`] bytes,
    /// more than [`MAX_TLV_VALUE`] bytes and incomplete sub-TLVs.
    fn parse(value: &[u8]) -> Result<Self, Error> {
        check_ssl(value)?;
        let client = value[0];
        let verify = u32::from_be_bytes([value[1], value[2], value[3], value[4]]);
        let mut tlvs = Vec::new();
        let mut i = SSL_FIXED_LEN;
        while i < value.len() {
            let (kind, v, _, next) = next_tlv(value, i, value.len())?;
            tlvs.push(SslTlv::from_raw(kind, v)?);
            i = next;
        }
        Ok(Ssl { client, verify, tlvs })
    }

    /// Refuses oversized sub-TLVs, named codes stored as `Other` and values
    /// exceeding [`MAX_TLV_VALUE`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let len = self.wire_len()?;
        let mut bytes = Vec::with_capacity(len);
        bytes.push(self.client);
        bytes.extend_from_slice(&self.verify.to_be_bytes());
        for tlv in &self.tlvs { tlv.write(&mut bytes)?; }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}
impl Ssl {
    fn wire_len(&self) -> Result<usize, Error> {
        self.tlvs.iter().try_fold(SSL_FIXED_LEN, |len, tlv| {
            len.checked_add(tlv.wire_len()?).filter(|&n| n <= MAX_TLV_VALUE).ok_or(Error::Unwritable)
        })
    }
}

impl Tlv {
    fn wire_len(&self) -> Result<usize, Error> {
        let n = match self {
            Self::Crc32c(_) => 4,
            Self::Ssl(ssl) => ssl.wire_len()?,
            Self::Alpn(v) | Self::Authority(v) | Self::Noop(v) | Self::NetNs(v) => v.len(),
            Self::UniqueId(v) if v.len() <= MAX_UNIQUE_ID => v.len(),
            Self::Other { kind, value } if !matches!(*kind, 1..=5 | 0x20 | 0x30) => value.len(),
            _ => return Err(Error::Unwritable),
        };
        n.checked_add(3).filter(|&n| n <= V2_MAX_BODY).ok_or(Error::Unwritable)
    }
}
impl SslTlv {
    fn wire_len(&self) -> Result<usize, Error> {
        if matches!(self, Self::Other { kind: 0x21..=0x25, .. }) {
            return Err(Error::Unwritable);
        }
        self.value().len().checked_add(3).filter(|&n| n <= MAX_TLV_VALUE - SSL_FIXED_LEN).ok_or(Error::Unwritable)
    }
}

macro_rules! tlv_wire {
    ($ty:ty, $read:expr, |$value:ident, $bytes:ident| $body:block) => {
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = Error;

            /// Reads one type, length and value. Refuses oversized values,
            /// malformed lengths and trailing bytes.
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                let (kind, value, _, used) = next_tlv(bytes, 0, bytes.len())?;
                if used != bytes.len() {
                    return Err(Error::TlvTruncated);
                }
                let parsed: Self = ($read)(kind, value)?;
                parsed.wire_len()?;
                Ok(parsed)
            }

            /// Refuses oversized values and `Other` variants with named codes.
            /// Leaves `out` unchanged on error. CRC32C values are stored as supplied.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                let n = self.wire_len()?;
                let mut bytes = Vec::with_capacity(n);
                bytes.push(self.kind());
                bytes.extend_from_slice(&((n - 3) as u16).to_be_bytes());
                let $value = self;
                let $bytes = &mut bytes;
                $body
                out.extend_from_slice(&bytes);
                Ok(())
            }
        }
    };
}
tlv_wire!(Tlv, Tlv::from_raw, |value, bytes| {
    match value {
        Tlv::Crc32c(crc) => bytes.extend_from_slice(&crc.to_be_bytes()),
        Tlv::Ssl(ssl) => ssl.write(bytes)?,
        Tlv::Alpn(v) | Tlv::Authority(v) | Tlv::Noop(v) | Tlv::NetNs(v)
        | Tlv::UniqueId(v) | Tlv::Other { value: v, .. } => bytes.extend_from_slice(v),
    }
});
tlv_wire!(SslTlv, SslTlv::from_raw, |value, bytes| {
    bytes.extend_from_slice(value.value());
});

impl SslTlv {
    /// Reads a sub-TLV of type `kind` from its value. Refuses a value that
    /// cannot fit beside the SSL fields inside [`MAX_TLV_VALUE`].
    pub fn from_raw(kind: u8, value: &[u8]) -> Result<SslTlv, Error> {
        if value.len() > MAX_TLV_VALUE - SSL_FIXED_LEN - 3 {
            return Err(Error::TlvLength(kind));
        }
        let v = value.to_vec();
        Ok(match kind {
            tlv_type::SSL_VERSION => SslTlv::Version(v),
            tlv_type::SSL_CN => SslTlv::CommonName(v),
            tlv_type::SSL_CIPHER => SslTlv::Cipher(v),
            tlv_type::SSL_SIG_ALG => SslTlv::SigAlg(v),
            tlv_type::SSL_KEY_ALG => SslTlv::KeyAlg(v),
            kind => SslTlv::Other { kind, value: v },
        })
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

impl Wire for V2 {
    type ParseError = HeaderParseError;
    type WriteError = Error;

    /// Reads exactly one V2 header. Refuses the other version, malformed
    /// or incomplete input, trailing bytes and noncanonical checksums.
    fn parse(bytes: &[u8]) -> Result<Self, HeaderParseError> {
        match Header::parse(bytes)? {
            Header::V2(value) => Ok(value),
            _ => Err(HeaderParseError::WrongVersion),
        }
    }

    /// Appends one binary header. Refuses oversized fields, variant changes,
    /// and incorrect or duplicate checksums. Leaves the destination unchanged
    /// on error. Use [`V2::with_checksum`] to set the canonical checksum.
    fn write(&self, dest: &mut Vec<u8>) -> Result<(), Error> {
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
        for tlv in &self.tlvs {
            let len = tlv.wire_len()?;
            if out.len().checked_add(len).is_none_or(|n| n > V2_MAX_LEN) {
                return Err(Error::Unwritable);
            }
            tlv.write(&mut out)?;
        }
        let len = u16::try_from(out.len().saturating_sub(V2_HEADER_LEN)).map_err(|_| Error::Unwritable)?;
        out[14..16].copy_from_slice(&len.to_be_bytes());
        if parse_v2(&out).ok().flatten().as_ref().map(|(h, _)| h) != Some(self) {
            return Err(Error::Unwritable);
        }
        dest.extend_from_slice(&out);
        Ok(())
    }
}
impl V2 {
    /// Appends a CRC32C TLV, or replaces the value of the existing one.
    /// The checksum covers the canonical header with its CRC32C value zeroed.
    /// Refuses duplicate checksums and any fields or total length that
    /// [`Wire::write`] refuses. All other fields and the TLV order stay as given.
    pub fn with_checksum(mut self) -> Result<V2, Error> {
        if self.tlvs.len() > V2_MAX_BODY / 3 {
            return Err(Error::Unwritable);
        }
        let mut found = None;
        for (index, tlv) in self.tlvs.iter().enumerate() {
            if matches!(tlv, Tlv::Crc32c(_)) && found.replace(index).is_some() {
                return Err(Error::Unwritable);
            }
        }
        let index = found.unwrap_or(self.tlvs.len());
        // A four-byte NOOP has the same size as CRC32C and can be written
        // before its checksum is known. Only its tag changes for calculation.
        let placeholder = Tlv::Noop(vec![0; 4]);
        if let Some(tlv) = self.tlvs.get_mut(index) {
            *tlv = placeholder;
        } else {
            self.tlvs.push(placeholder);
        }
        let mut bytes = self.to_bytes()?;
        let tail_len = self.tlvs[index..].iter().try_fold(0usize, |len, tlv| {
            len.checked_add(tlv.wire_len()?).ok_or(Error::Unwritable)
        })?;
        let at = bytes.len().checked_sub(tail_len).ok_or(Error::Unwritable)?;
        *bytes.get_mut(at).ok_or(Error::Unwritable)? = tlv_type::CRC32C;
        self.tlvs[index] = Tlv::Crc32c(crc32c(&bytes));
        Ok(self)
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

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Stream, contract, test_support::{chunks, decode_all, Lcg, mutate}};
    use HeaderParseError::Protocol as Protocol;

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
        let bytes = h.to_bytes().unwrap();
        Header::parse(&bytes).unwrap()
    }

    // Examples from the HAProxy PROXY protocol specification, section 2.1.

    #[test]
    fn v1_examples() {
        let line = b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        let h = Header::parse(line).unwrap();
        let b = Ipv4Addr::BROADCAST;
        assert_eq!(h, Header::V1(V1::Tcp4 { src: b, dst: b, src_port: 65535, dst_port: 65535 }));
        assert_eq!(h.to_bytes().unwrap(), line);

        let f = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        let line = format!("PROXY TCP6 {f} {f} 65535 65535\r\n");
        assert_eq!(line.len(), 104);
        let h = Header::parse(line.as_bytes()).unwrap();
        assert_eq!(h.to_bytes().unwrap(), line.as_bytes());

        // The worst case: UNKNOWN with the longest addresses is 107 bytes.
        let line = format!("PROXY UNKNOWN {f} {f} 65535 65535\r\n");
        assert_eq!(line.len(), V1_MAX_LEN);
        let h = Header::parse(line.as_bytes()).unwrap();
        assert_eq!(h, Header::V1(V1::Unknown(format!(" {f} {f} 65535 65535").into_bytes())));
        assert_eq!(h.to_bytes().unwrap(), line.as_bytes());
        assert_eq!(h.addresses(), None);

        let h = Header::parse(b"PROXY UNKNOWN\r\n").unwrap();
        assert_eq!(h, Header::V1(V1::Unknown(vec![])));
        assert_eq!(Header::parse(b"PROXY UNKNOWN\r\nabc"), Err(HeaderParseError::Trailing));

        let h = Header::parse(b"PROXY TCP6 2001:db8::1 ::ffff:192.0.2.1 0 80\r\n").unwrap();
        let (s, d) = h.addresses().unwrap();
        assert_eq!(s.to_string(), "[2001:db8::1]:0");
        assert_eq!(d.port(), 80);
    }

    #[test]
    fn v1_errors() {
        let e = |b: &[u8]| match Header::parse(b).unwrap_err() { Protocol(e) => e, other => panic!("{other:?}") };
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
        assert!(Header::parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 0 0\r\n").is_ok());
    }

    #[test]
    fn v2_spec_layout() {
        let bytes = tcp4().to_bytes().unwrap();
        let mut want = V2_SIGNATURE.to_vec();
        want.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c, 192, 0, 2, 1, 198, 51, 100, 2, 0xdc, 0x04, 0x01, 0xbb]);
        assert_eq!(bytes, want);
        assert_eq!(Header::parse(&bytes), Ok(tcp4()));
        // Version 2 headers carry no addresses for LOCAL.
        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        let h = Header::parse(&local).unwrap();
        assert_eq!(h, Header::V2(V2 { command: Command::Local, addresses: Addresses::Unspec, tlvs: vec![] }));
        assert_eq!(h.addresses(), None);
        assert_eq!(h.to_bytes().unwrap(), local);
    }

    #[test]
    fn v2_every_family() {
        let tr = [Transport::Stream, Transport::Dgram];
        for (i, transport) in tr.into_iter().enumerate() {
            let fams = [
                Addresses::Inet { transport, src: Ipv4Addr::LOCALHOST, dst: Ipv4Addr::UNSPECIFIED, src_port: 1, dst_port: 2 },
                Addresses::Inet6 { transport, src: Ipv6Addr::LOCALHOST, dst: "2001:db8::2".parse().unwrap(), src_port: 3, dst_port: 4 },
                Addresses::Unix { transport, src: { let mut a = [0; UNIX_ADDR_LEN]; a[..11].copy_from_slice(b"/run/a.sock"); a }, dst: [b'x'; UNIX_ADDR_LEN] },
            ];
            for (f, addresses) in fams.into_iter().enumerate() {
                let h = Header::V2(V2 { command: Command::Proxy, addresses, tlvs: vec![] });
                let bytes = h.to_bytes().unwrap();
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
        let v2 = v2.with_checksum().unwrap();
        assert!(matches!(v2.tlvs[2], Tlv::Crc32c(c) if c != 0));
        let h = Header::V2(v2.clone());
        let back = reparses(&h);
        let Header::V2(b) = &back else { panic!() };
        assert_eq!(b.tlvs, v2.tlvs);
        assert_eq!(b.ssl(), Some(&ssl));
        assert_eq!(b.tlv(tlv_type::AUTHORITY), Some(&b"example.com"[..]));
        assert_eq!(b.tlv(tlv_type::CRC32C), None);
        assert_eq!(b.tlv(0x99), None);
        // A header read back writes the same bytes.
        assert_eq!(back.to_bytes().unwrap(), h.to_bytes().unwrap());
        assert_eq!(ssl.tlvs[0].value(), b"TLSv1.3");
    }

    #[test]
    fn crc32c_matches_rfc() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0; 32]), 0x8a91_36aa);
    }

    #[test]
    fn v2_errors() {
        let good = tcp4().to_bytes().unwrap();
        let with = |at: usize, v: u8| {
            let mut b = good.clone();
            b[at] = v;
            Header::parse(&b)
        };
        assert_eq!(with(0, 0x0c), Err(Protocol(Error::NotProxy)));
        assert_eq!(with(11, 0), Err(Protocol(Error::NotProxy)));
        assert_eq!(with(12, 0x11), Err(Protocol(Error::Version(1))));
        assert_eq!(with(12, 0x22), Err(Protocol(Error::Command(2))));
        assert_eq!(with(13, 0x13), Err(Protocol(Error::Family(0x13))));
        assert_eq!(with(13, 0x10), Err(Protocol(Error::Family(0x10))));
        assert_eq!(with(13, 0x01), Err(Protocol(Error::Family(0x01))));
        assert_eq!(with(15, 11), Err(Protocol(Error::Length(11))));
        // Errors in the fixed part show before the rest arrives.
        assert_eq!(Header::parse(&with_prefix(&[0x31])), Err(Protocol(Error::Version(3))));
        assert_eq!(Header::parse(&with_prefix(&[0x21, 0x40])), Err(Protocol(Error::Family(0x40))));

        let body = |tlvs: &[u8]| {
            let mut b = V2_SIGNATURE.to_vec();
            b.extend_from_slice(&[0x21, 0x00]);
            b.extend_from_slice(&(tlvs.len() as u16).to_be_bytes());
            b.extend_from_slice(tlvs);
            Header::parse(&b)
        };
        assert_eq!(body(&[0x01, 0x00]), Err(Protocol(Error::TlvTruncated)));
        assert_eq!(body(&[0x01, 0x00, 0x02, b'h']), Err(Protocol(Error::TlvTruncated)));
        assert_eq!(body(&[0x03, 0x00, 0x02, 0, 0]), Err(Protocol(Error::TlvLength(tlv_type::CRC32C))));
        assert_eq!(body(&[0x20, 0x00, 0x04, 1, 0, 0, 0]), Err(Protocol(Error::TlvLength(tlv_type::SSL))));
        assert_eq!(body(&[0x20, 0x00, 0x07, 1, 0, 0, 0, 0, 0x21, 0]), Err(Protocol(Error::TlvTruncated)));
        let mut uid = vec![0x05, 0x00, 129];
        uid.extend_from_slice(&[0; 129]);
        assert_eq!(body(&uid), Err(Protocol(Error::TlvLength(tlv_type::UNIQUE_ID))));
        assert_eq!(body(&[0x03, 0x00, 0x04, 1, 2, 3, 4]), Err(Protocol(Error::Checksum)));
        // Two checksums, even correct ones, are refused.
        let one = checksum_header(Command::Proxy);
        let mut two = one.clone();
        two.extend_from_slice(&one[16..]);
        two[15] = 14;
        assert_eq!(Header::parse(&two), Err(Protocol(Error::Checksum)));
        assert!(Header::parse(&one).is_ok());
        // A changed byte breaks the checksum.
        let mut bad = one.clone();
        bad[12] = 0x20;
        assert_eq!(Header::parse(&bad), Err(Protocol(Error::Checksum)));
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
        assert_eq!(local(0x45, &[1, 2, 3]), Ok(empty.clone()));
        assert_eq!(local(0x11, &[]), Ok(empty.clone()));
        assert_eq!(local(0x00, &[0x01, 0x00]), Ok(empty.clone()));
        assert_eq!(local(0x13, &[]).map(|h| reparses(&h)), Ok(empty));
        // A partial LOCAL header with a bad family still needs more.
        assert_eq!(Header::parse(&with_prefix(&[0x20, 0x45, 0x00, 0x03, 1])), Err(HeaderParseError::Truncated));
        // A wrong checksum is still refused.
        let mut one = checksum_header(Command::Local);
        one[19] ^= 1;
        assert_eq!(Header::parse(&one), Err(Protocol(Error::Checksum)));
    }

    #[test]
    fn a_later_bad_tlv_does_not_hide_a_wrong_checksum() {
        // LOCAL: a wrong checksum followed by a truncated TLV. The checksum
        // should be 0x5c5f83af.
        let local = with_prefix(&[0x20, 0x00, 0x00, 0x08, 0x03, 0x00, 0x04, 0, 0, 0, 0, 0xff]);
        assert_eq!(Header::parse(&local), Err(Protocol(Error::Checksum)));
        // The same header with the right checksum is accepted, as LOCAL.
        let mut right = local.clone();
        right[19..23].copy_from_slice(&0x5c5f_83afu32.to_be_bytes());
        let empty = Header::V2(V2 { command: Command::Local, addresses: Addresses::Unspec, tlvs: vec![] });
        assert_eq!(Header::parse(&right), Ok(empty));
        // A checksum after a TLV whose value is bad is still checked.
        let local = with_prefix(&[0x20, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x03, 0x00, 0x04, 0, 0, 0, 0]);
        assert_eq!(Header::parse(&local), Err(Protocol(Error::Checksum)));
        let mut proxy = local.clone();
        proxy[12] = 0x21;
        assert_eq!(Header::parse(&proxy), Err(Protocol(Error::Checksum)));
        // A CRC32C TLV that cannot be checked is refused under LOCAL too.
        let local = with_prefix(&[0x20, 0x00, 0x00, 0x05, 0x03, 0x00, 0x02, 0, 0]);
        assert_eq!(Header::parse(&local), Err(Protocol(Error::TlvLength(tlv_type::CRC32C))));
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
        assert_eq!(SslTlv::from_raw(0xe0, &[0; MAX_TLV_VALUE - SSL_FIXED_LEN - 2]), Err(Error::TlvLength(0xe0)));
        let sub = SslTlv::from_raw(0xe0, &[0; MAX_TLV_VALUE - SSL_FIXED_LEN - 3]).unwrap();
        assert!(sub.to_bytes().is_ok());
        contract::check_wire_value(&sub);
        // The longest that fits reads, and writes back whole.
        ssl.truncate(MAX_TLV_VALUE - (MAX_TLV_VALUE - SSL_FIXED_LEN) % 3);
        let s = Ssl::parse(&ssl).unwrap();
        assert_eq!(s.to_bytes().unwrap(), ssl);
        let h = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![Tlv::Ssl(s)] });
        assert_eq!(reparses(&h), h);
    }

    #[test]
    fn v1_unknown_is_a_word() {
        assert_eq!(Header::parse(b"PROXY UNKNOWNfoo\r\n"), Err(Protocol(Error::V1Syntax)));
        assert_eq!(Header::parse(b"PROXY UNKNOWN4 1.2.3.4 5.6.7.8 1 2\r\n"), Err(Protocol(Error::V1Syntax)));
        assert!(Header::parse(b"PROXY UNKNOWN junk\r\n").is_ok());
        // The writer refuses text that would join the word.
        let h = Header::V1(V1::Unknown(b"foo".to_vec()));
        assert_eq!(h.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn v2_short_length_fails_early() {
        // A PROXY header whose length cannot hold its address block fails
        // as soon as the length is read.
        assert_eq!(Header::parse(&with_prefix(&[0x21, 0x21, 0x00, 0x0c])), Err(Protocol(Error::Length(12))));
    }

    #[test]
    fn every_truncated_prefix_needs_more() {
        let Header::V2(mut v2) = tcp4() else { unreachable!() };
        v2.tlvs = vec![Tlv::Ssl(Ssl { client: 1, verify: 0, tlvs: vec![SslTlv::Version(b"TLSv1.2".to_vec())] })];
        let headers = [
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            b"PROXY TCP6 ::1 ::2 1 2\r\n".to_vec(),
            Header::V2(v2).to_bytes().unwrap(),
            tcp4().to_bytes().unwrap(),
            checksum_header(Command::Proxy),
        ];
        for h in &headers {
            for n in 0..h.len() {
                assert_eq!(Header::parse(&h[..n]), Err(HeaderParseError::Truncated), "{n} bytes of {h:?}");
            }
            assert!(Header::parse(h).is_ok());
        }
        assert_eq!(detect(b""), Detection::NeedMore);
        assert_eq!(detect(b"PRO"), Detection::NeedMore);
        assert_eq!(detect(b"PROXY "), Detection::V1);
        assert_eq!(detect(&V2_SIGNATURE[..5]), Detection::NeedMore);
        assert_eq!(detect(&V2_SIGNATURE), Detection::V2);
        assert_eq!(detect(b"\x16\x03\x01"), Detection::NotProxy);
    }

    #[test]
    fn headers_from_socket_addresses() {
        let v4 = |s: &str| s.parse::<SocketAddr>().unwrap();
        let (a, b) = (v4("192.0.2.1:56324"), v4("198.51.100.2:443"));
        let (c, d) = (v4("[2001:db8::1]:1"), v4("[2001:db8::2]:2"));
        let mapped = v4("[::ffff:192.0.2.1]:56324");

        let h = Header::V1(V1::from_addrs(a, b));
        assert_eq!(h.to_bytes().unwrap(), b"PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n");
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

    fn checksum_header(command: Command) -> Vec<u8> {
        V2 { command, addresses: Addresses::Unspec, tlvs: vec![] }
            .with_checksum().unwrap().to_bytes().unwrap()
    }

    fn refused<T: Wire<WriteError = Error>>(value: T) {
        let mut bytes = vec![1, 2];
        assert_eq!(value.write(&mut bytes), Err(Error::Unwritable));
        assert_eq!(bytes, [1, 2]);
    }

    #[test]
    fn strict_writers_preserve_every_field() {
        for rest in [b" a\nb".to_vec(), vec![b' '; V1_MAX_UNKNOWN_REST + 1], b"foo".to_vec()] {
            refused(Header::V1(V1::Unknown(rest)));
        }
        for rest in [b" \r".to_vec(), vec![b' '; V1_MAX_UNKNOWN_REST]] {
            let header = Header::V1(V1::Unknown(rest));
            assert!(header.to_bytes().is_ok());
            contract::check_wire_value(&header);
        }
        for tlv in [Tlv::UniqueId(vec![5; MAX_UNIQUE_ID + 1]), Tlv::Noop(vec![0; MAX_TLV_VALUE + 1]),
            Tlv::Other { kind: tlv_type::CRC32C, value: vec![1, 2, 3] },
            Tlv::Other { kind: tlv_type::ALPN, value: b"h2".to_vec() },
            Tlv::Other { kind: tlv_type::SSL, value: vec![] },
            Tlv::Ssl(Ssl { client: 0, verify: 1, tlvs: vec![SslTlv::Cipher(vec![3; 70_000])] }),
            Tlv::Ssl(Ssl { client: 0, verify: 1, tlvs: vec![SslTlv::Other { kind: tlv_type::SSL_CN, value: vec![] }] })] {
            refused(Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![tlv] }));
        }
        for tlvs in [vec![Tlv::Noop(vec![0; 40_000]); 2], vec![Tlv::Crc32c(0); 2], vec![Tlv::Crc32c(0)]] {
            refused(Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs }));
        }
        let h = Header::V2(V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs: vec![Tlv::Noop(vec![0; MAX_TLV_VALUE])] });
        let bytes = h.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_HEADER_LEN);
        assert_eq!(Header::parse(&bytes), Ok(h.clone()));
        contract::check_decode_with_alloc_limit(Headers::new, &bytes, 2 * MAX_HEADER_LEN);
        assert_eq!(decode_all(Headers::new, &bytes), (vec![Ok(h)], None));
        for command in [Command::Local, Command::Proxy] {
            let bytes = checksum_header(command);
            assert_eq!(Header::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
            contract::check_wire::<Header>(&bytes);
        }
    }

    #[test]
    fn stream_handoff_and_not_proxy() {
        let mut bytes = tcp4().to_bytes().unwrap();
        bytes.extend_from_slice(b"payload");
        let mut s = Stream::new(Headers::new());
        assert_eq!(s.push(&bytes), bytes.len());
        assert_eq!(s.next(), Some(Ok(Ok(tcp4()))));
        assert_eq!(s.next(), None);
        assert_eq!(s.into_parts().0.unread(), b"payload");
        let mut s = Stream::new(Headers::new());
        assert_eq!(s.push(b"PRO"), 3);
        assert_eq!(s.next(), None);
        assert_eq!(s.push(b"BE x"), 4);
        assert_eq!(s.next(), Some(Err(codec::Fail::Protocol(HeaderError::Protocol(Error::NotProxy)))));
        assert_eq!(s.next(), None);
        assert_eq!(s.into_parts().0.unread(), b"PROBE x");
        // A payload beyond capacity remains with the caller, without copying or loss.
        let mut bytes = b"PROXY UNKNOWN\r\n".to_vec();
        bytes.extend(vec![7; MAX_HEADER_LEN + 10]);
        let mut s = Stream::new(Headers::new());
        let accepted = s.push(&bytes);
        assert_eq!(accepted, MAX_HEADER_LEN);
        s.next().unwrap().unwrap().unwrap();
        let (buffer, _) = s.into_parts();
        assert_eq!([buffer.unread(), &bytes[accepted..]].concat(), vec![7; MAX_HEADER_LEN + 10]);
    }

    #[test]
    fn checksums_are_constructed_without_changing_other_fields() {
        for command in [Command::Local, Command::Proxy] {
            let header = V2 { command, addresses: Addresses::Unspec, tlvs: vec![Tlv::Alpn(b"h2".to_vec())] };
            let checked = header.clone().with_checksum().unwrap();
            assert_eq!(checked.tlvs[..1], header.tlvs);
            assert_eq!(checked.tlvs.len(), 2);
            assert_eq!(checked.clone().with_checksum(), Ok(checked.clone()));
            assert_eq!(V2::parse(&checked.to_bytes().unwrap()), Ok(checked));
            let mut header = header;
            header.tlvs.insert(0, Tlv::Crc32c(0));
            let checked = header.with_checksum().unwrap();
            assert!(matches!(checked.tlvs[0], Tlv::Crc32c(_)));
            assert_eq!(checked.tlvs[1], Tlv::Alpn(b"h2".to_vec()));
            assert_eq!(V2::parse(&checked.to_bytes().unwrap()), Ok(checked));
        }
        for tlvs in [
            vec![Tlv::Crc32c(0); 2],
            vec![Tlv::Noop(vec![0; MAX_TLV_VALUE])],
            vec![Tlv::UniqueId(vec![0; MAX_UNIQUE_ID + 1])],
            vec![Tlv::Other { kind: tlv_type::ALPN, value: vec![] }],
            vec![Tlv::Ssl(Ssl { client: 0, verify: 0, tlvs: vec![SslTlv::Other { kind: tlv_type::SSL_CN, value: vec![] }] })],
        ] {
            let header = V2 { command: Command::Proxy, addresses: Addresses::Unspec, tlvs };
            assert_eq!(header.with_checksum(), Err(Error::Unwritable));
        }
        let longest = V2 { command: Command::Proxy, addresses: Addresses::Unspec,
            tlvs: vec![Tlv::Noop(vec![0; MAX_TLV_VALUE - 7])] }.with_checksum().unwrap();
        assert_eq!(longest.to_bytes().unwrap().len(), V2_MAX_LEN);
        contract::check_wire_value(&longest);
    }

    #[test]
    fn exact_version_readers_report_the_other_version() {
        assert_eq!(V1::parse(&tcp4().to_bytes().unwrap()), Err(HeaderParseError::WrongVersion));
        assert_eq!(V2::parse(b"PROXY UNKNOWN\r\n"), Err(HeaderParseError::WrongVersion));
        assert_eq!(HeaderParseError::WrongVersion.to_string(), "PROXY header has the wrong version");
    }

    #[test]
    fn longest_header_byte_at_a_time_is_bounded() {
        let header = V2 { command: Command::Proxy, addresses: Addresses::Unspec,
            tlvs: vec![Tlv::Noop(vec![0; MAX_TLV_VALUE])] };
        let bytes = header.to_bytes().unwrap();
        let mut stream = Stream::new(Headers::new());
        let started = std::time::Instant::now();
        for (i, chunk) in chunks(&bytes, &[1]).enumerate() {
            assert_eq!(stream.push(chunk), 1);
            if i + 1 < bytes.len() { assert_eq!(stream.next(), None); }
            assert!(stream.buffered() <= MAX_HEADER_LEN);
        }
        assert_eq!(stream.next(), Some(Ok(Ok(Header::V2(header)))));
        assert_eq!(stream.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    fn random_v2(rng: &mut Lcg) -> V2 {
        let transport = if rng.coin() { Transport::Stream } else { Transport::Dgram };
        let addresses = match rng.index(4) {
            0 => Addresses::Unspec,
            1 => Addresses::Inet { transport, src: Ipv4Addr::from(rng.next() as u32),
                dst: Ipv4Addr::from(rng.next() as u32), src_port: rng.next() as u16, dst_port: rng.next() as u16 },
            2 => Addresses::Inet6 { transport, src: Ipv6Addr::from(u128::from(rng.next())),
                dst: Ipv6Addr::from(u128::from(rng.next()) << 96), src_port: rng.next() as u16, dst_port: rng.next() as u16 },
            _ => {
                let mut src = [0; UNIX_ADDR_LEN];
                let mut dst = [0; UNIX_ADDR_LEN];
                rng.fill(&mut src);
                rng.fill(&mut dst);
                Addresses::Unix { transport, src, dst }
            }
        };
        let tlvs = (0..rng.index(6)).map(|_| {
            let value = rng.bytes(40);
            match rng.index(9) {
                0 => Tlv::Alpn(value),
                1 => Tlv::Authority(value),
                2 => Tlv::Crc32c(rng.next() as u32),
                3 => Tlv::Noop(value),
                4 => Tlv::UniqueId(value),
                5 => Tlv::Ssl(Ssl { client: rng.next() as u8, verify: rng.next() as u32,
                    tlvs: (0..rng.index(8)).map(|_| SslTlv::from_raw(0x20 + rng.index(8) as u8, &value).unwrap()).collect() }),
                6 => Tlv::NetNs(value),
                _ => Tlv::Other { kind: rng.next() as u8, value },
            }
        }).collect();
        V2 { command: if rng.coin() { Command::Local } else { Command::Proxy }, addresses, tlvs }
    }

    #[test]
    fn generated_contracts() {
        let mut rng = Lcg::new(0x5eed);
        let seeds = [tcp4().to_bytes().unwrap(), b"PROXY UNKNOWN text\r\n".to_vec(), checksum_header(Command::Proxy)];
        for _ in 0..512 {
            let mut bytes = if rng.coin() { seeds[rng.index(seeds.len())].clone() } else { rng.bytes(80) };
            mutate(&mut rng, &mut bytes);
            contract::check_decode_with_alloc_limit(Headers::new, &bytes, 2 * MAX_HEADER_LEN);
            contract::check_wire::<Header>(&bytes);
            contract::check_wire::<V1>(&bytes);
            contract::check_wire::<V2>(&bytes);
            contract::check_wire::<Tlv>(&bytes);
            contract::check_wire::<Ssl>(&bytes);
            contract::check_wire::<SslTlv>(&bytes);
            contract::check_wire_value(&Header::V1(V1::Unknown(rng.text(120).into_bytes())));
            contract::check_wire_value(&Tlv::Other { kind: rng.next() as u8, value: rng.bytes(40) });
            let header = random_v2(&mut rng);
            contract::check_wire_value(&header);
            if let Ok(header) = header.with_checksum() {
                assert!(header.to_bytes().is_ok());
                contract::check_wire_value(&header);
            }
        }
    }
}
