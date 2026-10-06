//! RDP connection messages from MS-RDPBCGR, with no I/O.
//!
//! [`Frames`] separates TPKT slow-path packets from fast-path packets.
//! [`Connection`] reads X.224 connection requests and confirms, including
//! cookies, routing tokens and security negotiation. [`McsConnect`] reads
//! the BER connection exchange and its PER GCC data. [`McsPdu`] reads the
//! following PER domain, user, channel and data messages. [`ClientInfo`],
//! [`LicenseError`] and [`ActivePdu`] read the plaintext carried in them.
//!
//! These are wire codecs, not a connection state machine. The caller checks
//! message order, negotiated flags, required data blocks and channel IDs.
//! TLS, CredSSP, RDP security exchange, encryption, signatures, compression,
//! graphics and input events are outside this module. Protected bytes stay
//! in [`Frame`], [`McsPdu::SendData`] or [`SecurityPayload`] unchanged. Never
//! pass ciphertext to a plaintext parser. The caller decides whether a
//! security header is present; its presence cannot be inferred from bytes.
//!
//! Lengths, counts, field boundaries and encoding choices are checked before
//! allocating. BER nesting is fixed; indefinite lengths and fragmented PER
//! lengths are refused. GCC supports the RDP conference name "1" and one
//! H.221 user-data set. Unknown data blocks and capability bodies survive
//! a round trip. Optional client core fields and extended client info are
//! preserved as bytes. Writers use the same checks as readers.
//!
//! Use [`Frames`] with [`Stream`](super::codec::Stream).
//! [`Frame`] implements [`Wire`] for exact parsing and transactional writing.
//! The inherent parser reads a prefix.
//! [`Connection::to_packet`] and [`write_data`] construct typed TPKT packets.
//! `Vec<DataBlock>` implements [`Wire`] for a bounded GCC block sequence.
//!
//! The wire definitions and examples are in [MS-RDPBCGR sections 2.2.1,
//! 2.2.8 and 4.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/).
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::rdp::{Connection, Frames, Frame, Negotiation, Protocols};
//!
//! // MS-RDPBCGR connection request: TLS and CredSSP are supported.
//! let bytes = [3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0,
//!              1, 0, 8, 0, 3, 0, 0, 0];
//! let mut decoder = Stream::new(Frames::new());
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! let Frame::SlowPath(packet) = decoder.next().unwrap().unwrap() else {
//!     panic!("expected TPKT");
//! };
//! let request = Connection::from_packet(&packet).unwrap();
//! assert_eq!(request.negotiation, Some(Negotiation::Request {
//!     flags: 0, protocols: Protocols(Protocols::TLS.0 | Protocols::HYBRID.0),
//! }));
//! assert_eq!(request.to_packet().unwrap().to_bytes().unwrap(), bytes);
//! ```

#![deny(missing_docs)]

use super::{
    codec::{Decode, Step, Wire},
    cotp, tpkt,
};

/// The usual RDP TCP port.
pub const PORT: u16 = 3389;
/// The largest transport frame, including its header.
pub const MAX_FRAME: usize = tpkt::MAX_PACKET;
/// The largest fast-path frame, including its two or three byte header.
pub const MAX_FAST_PATH: usize = 0x7fff;
/// The largest plaintext PDU, also the data room in one TPKT data TPDU.
pub const MAX_PDU: usize = MAX_FRAME - 7;
/// The largest unfragmented aligned PER length (14 bits).
pub const MAX_PER_LENGTH: usize = 0x3fff;
/// The largest GCC request, including the ConnectData wrapper.
pub const MAX_GCC_REQUEST: usize = 4096;
/// The largest GCC data block or block sequence accepted here.
pub const MAX_GCC_DATA: usize = MAX_PER_LENGTH;
/// The largest GCC response, including its wrapper.
pub const MAX_GCC_RESPONSE: usize = MAX_GCC_DATA + 32;
/// The largest count of GCC data blocks in one conference.
pub const MAX_BLOCKS: usize = 64;
/// The largest static virtual channel count allowed by MS-RDPBCGR.
pub const MAX_CHANNELS: usize = 31;
/// The largest monitor count allowed by MS-RDPBCGR.
pub const MAX_MONITORS: usize = 16;
/// The largest capability count accepted in one activation PDU.
pub const MAX_CAPABILITIES: usize = 64;
/// The largest capability body accepted here.
pub const MAX_CAPABILITY: usize = 16 * 1024;
/// The largest source descriptor in an activation PDU.
pub const MAX_DESCRIPTOR: usize = 1024;
/// The largest Client Info string in bytes, including its null terminator
/// (MS-RDPBCGR 2.2.1.11.1.1). Content is at most 510 bytes in Unicode and
/// 511 bytes in ANSI.
pub const MAX_INFO_STRING: usize = 512;
/// The largest opaque Extended Info Packet accepted here.
pub const MAX_EXTRA_INFO: usize = 16 * 1024;
/// The largest BER MCS domain selector accepted here.
pub const MAX_SELECTOR: usize = 16;
/// The largest X.224 cookie, routing token and negotiation data together.
pub const MAX_CONNECTION_DATA: usize = cotp::MAX_HEADER - 6;
/// The fixed byte length of a client computer name.
pub const CLIENT_NAME_LEN: usize = 32;
/// The fixed byte length of the client IME file name.
pub const IME_NAME_LEN: usize = 64;
/// The fixed byte length of a virtual channel name, including zero padding.
pub const CHANNEL_NAME_LEN: usize = 8;
/// The fixed byte length of a negotiation correlation identifier.
pub const CORRELATION_ID_LEN: usize = 16;
/// The largest optional client core suffix described in MS-RDPBCGR.
pub const MAX_CORE_OPTIONAL: usize = 102;
/// The required length of an encrypted session's server random.
pub const SERVER_RANDOM_LEN: usize = 32;
/// The server channel ID, the required Confirm Active originator.
pub const SERVER_CHANNEL_ID: u16 = 0x03ea;

/// A structural error, an unsupported encoding, or a local resource limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A complete-message parser ran out of bytes.
    Truncated,
    /// A field, tag, count or length is inconsistent; names the field.
    Invalid(&'static str),
    /// A named module limit would be exceeded.
    Limit(&'static str),
    /// An encoding is outside this module's documented subset.
    Unsupported(&'static str),
    /// The sibling TPKT parser rejected the header.
    Tpkt(tpkt::TpktError),
    /// The sibling COTP parser rejected the TPDU.
    Cotp(cotp::TpduError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("incomplete RDP message"),
            Self::Invalid(s) => write!(f, "invalid RDP {s}"),
            Self::Limit(s) => write!(f, "RDP limit exceeded: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported RDP {s}"),
            Self::Tpkt(e) => e.fmt(f),
            Self::Cotp(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}

fn check(ok: bool, field: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(field))
    }
}
fn bound(n: usize, max: usize, field: &'static str) -> Result<(), Error> {
    if n <= max {
        Ok(())
    } else {
        Err(Error::Limit(field))
    }
}
fn size(n: u32) -> Result<usize, Error> {
    usize::try_from(n).map_err(|_| Error::Limit("integer"))
}
fn u16_len(n: usize) -> Result<u16, Error> {
    u16::try_from(n).map_err(|_| Error::Limit("16-bit length"))
}

// Readers borrow slices and never recurse. All owning parsers first bound
// their input; nested readers cannot acquire bytes outside their parent.
struct Read<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Read<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Limit("length"))?;
        let b = self.b.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(u8::from_le_bytes(self.array()?))
    }
    fn le16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn be16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn le32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.array()?))
    }
    fn rest(&self) -> &'a [u8] {
        self.b.get(self.pos..).unwrap_or_default()
    }
    fn finish(&self) -> Result<(), Error> {
        check(self.rest().is_empty(), "trailing bytes")
    }
    fn expect(&mut self, b: &[u8]) -> Result<(), Error> {
        check(self.take(b.len())? == b, "tag or fixed field")
    }
    fn per_len(&mut self) -> Result<usize, Error> {
        let a = self.byte()?;
        if a & 0x80 == 0 {
            return Ok(usize::from(a));
        }
        if a & 0x40 != 0 {
            return Err(Error::Unsupported("fragmented PER length"));
        }
        Ok((usize::from(a & 0x3f) << 8) | usize::from(self.byte()?))
    }
    fn per_uint(&mut self) -> Result<u32, Error> {
        let n = self.per_len()?;
        check((1..=4).contains(&n), "PER integer length")?;
        unsigned(self.take(n)?)
    }
    fn per_signed(&mut self) -> Result<i32, Error> {
        let n = self.per_len()?;
        check((1..=4).contains(&n), "PER signed integer length")?;
        let b = self.take(n)?;
        let sign = if b.first().is_some_and(|x| x & 0x80 != 0) {
            0xff
        } else {
            0
        };
        let mut bytes = [sign; 4];
        bytes
            .get_mut(4 - n..)
            .ok_or(Error::Invalid("PER signed integer"))?
            .copy_from_slice(b);
        Ok(i32::from_be_bytes(bytes))
    }
    fn user_id(&mut self) -> Result<u32, Error> {
        Ok(u32::from(self.be16()?) + 1001)
    }
    fn mcs_result(&mut self, tag: u8) -> Result<u8, Error> {
        // Choice (6 bits), optional-ID bitmap (1 bit), then Result (4 bits).
        // The result straddles two octets; five alignment bits follow it.
        let tail = self.byte()?;
        check(tail & 0x1f == 0, "MCS result padding")?;
        Ok(((tag & 1) << 3) | (tail >> 5))
    }
    fn ber_len(&mut self) -> Result<usize, Error> {
        let a = self.byte()?;
        if a < 128 {
            return Ok(usize::from(a));
        }
        let n = usize::from(a & 0x7f);
        if n == 0 {
            return Err(Error::Unsupported("indefinite BER length"));
        }
        bound(n, 4, "BER length octets")?;
        let n = size(unsigned(self.take(n)?)?)?;
        bound(n, MAX_PDU, "BER value")?;
        Ok(n)
    }
    fn ber(&mut self, tag: &[u8]) -> Result<&'a [u8], Error> {
        self.expect(tag)?;
        let n = self.ber_len()?;
        self.take(n)
    }
    fn ber_uint(&mut self, tag: u8) -> Result<u32, Error> {
        let b = self.ber(&[tag])?;
        check(!b.is_empty(), "BER integer length")?;
        bound(b.len(), 5, "BER integer")?;
        // RDP examples also use unsigned ff ff without a sign octet.
        unsigned(b)
    }
}
fn unsigned(b: &[u8]) -> Result<u32, Error> {
    b.iter().try_fold(0u32, |v, &x| {
        v.checked_mul(256)
            .and_then(|v| v.checked_add(u32::from(x)))
            .ok_or(Error::Limit("integer"))
    })
}

// Each writer has a limit drawn from the public constants. Explicit growth
// avoids Vec's implicit doubling beyond that limit.
struct Write {
    b: Vec<u8>,
    limit: usize,
}
impl Write {
    fn new(limit: usize) -> Self {
        Self {
            b: Vec::new(),
            limit,
        }
    }
    fn put(&mut self, b: &[u8]) -> Result<(), Error> {
        let end = self
            .b
            .len()
            .checked_add(b.len())
            .ok_or(Error::Limit("writer"))?;
        bound(end, self.limit, "writer")?;
        if end > self.b.capacity() {
            let capacity = end
                .max(self.b.capacity().saturating_mul(2))
                .max(32)
                .min(self.limit);
            self.b.reserve_exact(capacity - self.b.len());
        }
        self.b.extend_from_slice(b);
        Ok(())
    }
    fn byte(&mut self, n: u8) -> Result<(), Error> {
        self.put(&[n])
    }
    fn le16(&mut self, n: u16) -> Result<(), Error> {
        self.put(&n.to_le_bytes())
    }
    fn be16(&mut self, n: u16) -> Result<(), Error> {
        self.put(&n.to_be_bytes())
    }
    fn le32(&mut self, n: u32) -> Result<(), Error> {
        self.put(&n.to_le_bytes())
    }
    fn per_len(&mut self, n: usize) -> Result<(), Error> {
        bound(n, MAX_PER_LENGTH, "PER length")?;
        if n < 128 {
            self.byte(n as u8)
        } else {
            self.be16((n as u16) | 0x8000)
        }
    }
    fn per_uint(&mut self, n: u32) -> Result<(), Error> {
        let bytes = n.to_be_bytes();
        let start = bytes.iter().position(|&x| x != 0).unwrap_or(3);
        let b = bytes.get(start..).ok_or(Error::Invalid("integer"))?;
        self.per_len(b.len())?;
        self.put(b)
    }
    fn per_signed(&mut self, n: i32) -> Result<(), Error> {
        let bytes = n.to_be_bytes();
        let mut start = 0;
        while let (Some(&a), Some(&b)) = (bytes.get(start), bytes.get(start + 1)) {
            if (a == 0 && b & 0x80 == 0) || (a == 0xff && b & 0x80 != 0) {
                start += 1;
            } else {
                break;
            }
        }
        let b = bytes
            .get(start..)
            .ok_or(Error::Invalid("PER signed integer"))?;
        self.per_len(b.len())?;
        self.put(b)
    }
    fn user_id(&mut self, id: u32) -> Result<(), Error> {
        check((1001..=65535).contains(&id), "MCS user ID")?;
        self.be16((id - 1001) as u16)
    }
    fn ber_len(&mut self, n: usize) -> Result<(), Error> {
        bound(n, MAX_PDU, "BER length")?;
        if n < 128 {
            self.byte(n as u8)
        } else if n <= 255 {
            self.put(&[0x81, n as u8])
        } else {
            self.byte(0x82)?;
            self.be16(n as u16)
        }
    }
    fn ber(&mut self, tag: &[u8], b: &[u8]) -> Result<(), Error> {
        self.put(tag)?;
        self.ber_len(b.len())?;
        self.put(b)
    }
    fn ber_uint(&mut self, tag: u8, n: u32) -> Result<(), Error> {
        let bytes = n.to_be_bytes();
        let start = bytes.iter().position(|&x| x != 0).unwrap_or(3);
        let b = bytes.get(start..).ok_or(Error::Invalid("integer"))?;
        let sign = b.first().is_some_and(|x| x & 0x80 != 0);
        self.byte(tag)?;
        self.ber_len(b.len() + usize::from(sign))?;
        if sign {
            self.byte(0)?;
        }
        self.put(b)
    }
}

/// A TPKT slow-path packet or an opaque fast-path packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// TPKT packet; use [`Connection::from_packet`] or [`read_data`] next.
    SlowPath(tpkt::Packet),
    /// Fast-path packet. Events, signatures and encrypted bytes stay opaque.
    FastPath {
        /// The original header byte; its action bits must be zero.
        header: u8,
        /// Everything after the length, bounded by [`MAX_FAST_PATH`] minus 3.
        payload: Vec<u8>,
    },
}

impl Frame {
    /// Reads one frame prefix, returning `None` for an incomplete frame.
    /// The returned count excludes bytes belonging to the next frame.
    pub fn parse(b: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let Some(&first) = b.first() else {
            return Ok(None);
        };
        if first == 3 {
            return tpkt::Packet::parse(b)
                .map(|p| p.map(|(p, n)| (Self::SlowPath(p), n)))
                .map_err(Error::Tpkt);
        }
        check(first & 3 == 0, "fast-path action")?;
        let Some(&a) = b.get(1) else { return Ok(None) };
        let (length, header_len) = if a & 128 == 0 {
            (usize::from(a), 2)
        } else {
            let Some(&lo) = b.get(2) else { return Ok(None) };
            ((usize::from(a & 127) << 8) | usize::from(lo), 3)
        };
        check(length >= header_len, "fast-path length")?;
        let Some(payload) = b.get(header_len..length) else {
            return Ok(None);
        };
        // A two-byte header may encode 127 bytes; all payloads fit the
        // conservative maximum that also allows the three-byte header.
        Ok(Some((
            Self::FastPath {
                header: first,
                payload: payload.to_vec(),
            },
            length,
        )))
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one transport frame, refusing partial or trailing bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match Self::parse(b)? {
            Some((frame, used)) if used == b.len() => Ok(frame),
            Some(_) => Err(Error::Invalid("trailing bytes")),
            None => Err(Error::Truncated),
        }
    }

    /// Writes one frame, using the shortest fast-path length encoding.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::SlowPath(p) => p
                .write(dst)
                .map_err(|_| Error::Invalid("TPKT payload length")),
            Self::FastPath { header, payload } => {
                check(header & 3 == 0, "fast-path action")?;
                bound(payload.len(), MAX_FAST_PATH - 3, "fast-path payload")?;
                let mut w = Write::new(MAX_FAST_PATH);
                w.byte(*header)?;
                if payload.len() <= 125 {
                    w.byte((payload.len() + 2) as u8)?;
                } else {
                    w.be16(((payload.len() + 3) as u16) | 0x8000)?;
                }
                w.put(payload)?;
                dst.extend_from_slice(&w.b);
                Ok(())
            }
        }
    }
}

/// Reads RDP slow-path and fast-path frames without holding input bytes.
///
/// Use with [`Stream`](super::codec::Stream) for a buffer limited to
/// [`MAX_FRAME`]. Partial frames return [`Step::Need`], including at EOF.
/// The stream reports truncation at EOF and framing errors once.
/// Slow-path framing uses the shared [`tpkt`] parser.
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;

impl Frames {
    /// Creates a frame decoder with a capacity of [`MAX_FRAME`] bytes.
    pub fn new() -> Self {
        Self
    }
}

impl Decode for Frames {
    type Item = Frame;
    type Error = Error;
    const NAME: &'static str = "RDP";

    fn capacity(&self) -> usize {
        MAX_FRAME
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, Error> {
        Ok(match Frame::parse(input)? {
            Some((frame, used)) => Step::Item(frame, used),
            None => Step::Need,
        })
    }
}

/// Extracts the bytes of an unsegmented RDP X.224 Data TPDU using COTP.
/// Use the sibling COTP reassembler yourself for non-RDP segmented traffic.
pub fn read_data(packet: &tpkt::Packet) -> Result<Vec<u8>, Error> {
    bound(packet.payload.len(), tpkt::MAX_PAYLOAD, "TPKT payload")?;
    check(
        packet.payload.get(..3) == Some(&[2, 0xf0, 0x80]),
        "RDP data TPDU",
    )?;
    match cotp::over_tpkt::tpdu(packet).map_err(Error::Cotp)? {
        cotp::Tpdu::Data(d) => Ok(d.data),
        _ => Err(Error::Invalid("RDP data TPDU")),
    }
}

/// Wraps at most [`MAX_PDU`] bytes in an unsegmented COTP Data TPDU and TPKT.
/// Checks the data size before constructing the packet.
pub fn write_data(data: &[u8]) -> Result<tpkt::Packet, Error> {
    bound(data.len(), MAX_PDU, "RDP data")?;
    Ok(cotp::over_tpkt::from_tpdu(&cotp::Tpdu::Data(cotp::Data {
        eot: true,
        number: 0,
        data: data.to_vec(),
    })))
}

/// Requested protocol bits, or one selected protocol. Unknown bits survive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocols(pub u32);
impl Protocols {
    /// Standard RDP security.
    pub const RDP: Self = Self(0);
    /// TLS security (PROTOCOL_SSL).
    pub const TLS: Self = Self(1);
    /// CredSSP security.
    pub const HYBRID: Self = Self(2);
    /// RDSTLS security.
    pub const RDSTLS: Self = Self(4);
    /// CredSSP with an early authorization result.
    pub const HYBRID_EX: Self = Self(8);
    /// RDS AAD authentication security.
    pub const RDSAAD: Self = Self(16);
}

/// Negotiation flag bits. Request and response flags use separate meanings.
pub mod negotiation_flags {
    /// Request: restricted admin mode is required.
    pub const RESTRICTED_ADMIN_REQUIRED: u8 = 1;
    /// Request: redirected authentication is required.
    pub const REDIRECTED_AUTH_REQUIRED: u8 = 2;
    /// Request: a 36-byte correlation structure follows.
    pub const CORRELATION_INFO_PRESENT: u8 = 8;
    /// Response: extended client data is supported.
    pub const EXTENDED_CLIENT_DATA_SUPPORTED: u8 = 1;
    /// Response: dynamic graphics virtual channels are supported.
    pub const DYNVC_GFX_SUPPORTED: u8 = 2;
    /// Response: restricted admin mode is supported.
    pub const RESTRICTED_ADMIN_SUPPORTED: u8 = 8;
    /// Response: redirected authentication is supported.
    pub const REDIRECTED_AUTH_SUPPORTED: u8 = 16;
}

/// A negotiation failure code, including values added by future revisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureCode(pub u32);
impl FailureCode {
    /// The server requires TLS or CredSSP.
    pub const TLS_REQUIRED: Self = Self(1);
    /// The server only allows standard RDP security.
    pub const TLS_NOT_ALLOWED: Self = Self(2);
    /// The server lacks an authentication certificate.
    pub const CERTIFICATE_MISSING: Self = Self(3);
    /// Requested protocols conflict with the security already in use.
    pub const INCONSISTENT_FLAGS: Self = Self(4);
    /// The server requires CredSSP.
    pub const HYBRID_REQUIRED: Self = Self(5);
    /// The server requires TLS with certificate-based client authentication.
    pub const TLS_USER_AUTH_REQUIRED: Self = Self(6);
    /// The server requires Entra authentication.
    pub const ENTRA_AUTH_REQUIRED: Self = Self(7);
}

/// The fixed eight-byte RDP negotiation structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Negotiation {
    /// Client protocol advertisement.
    Request {
        /// Request flags, including correlation presence.
        flags: u8,
        /// Requested security protocol bits.
        protocols: Protocols,
    },
    /// Server protocol selection.
    Response {
        /// Response capability flags.
        flags: u8,
        /// One selected protocol, or zero for standard RDP security.
        protocol: Protocols,
    },
    /// Server refusal; its reserved flag byte is always zero.
    Failure(FailureCode),
}
impl Negotiation {
    /// Reads exactly eight bytes; unknown protocol bits and failure codes survive.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        let mut r = Read::new(b);
        let kind = r.byte()?;
        let flags = r.byte()?;
        check(r.le16()? == 8, "negotiation length")?;
        let value = r.le32()?;
        r.finish()?;
        match kind {
            1 => Ok(Self::Request {
                flags,
                protocols: Protocols(value),
            }),
            2 => {
                check(value == 0 || value.is_power_of_two(), "selected protocol")?;
                Ok(Self::Response {
                    flags,
                    protocol: Protocols(value),
                })
            }
            3 => {
                check(flags == 0, "failure flags")?;
                Ok(Self::Failure(FailureCode(value)))
            }
            _ => Err(Error::Invalid("negotiation type")),
        }
    }
}

/// A connection request or the server's connection confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionKind {
    /// Client X.224 Connection Request.
    Request,
    /// Server X.224 Connection Confirm, including negotiation failure.
    Confirm,
}

/// The RDP fields in an X.224 connection header. References are retained;
/// class, credit and options must be zero. No data may follow the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    /// Request or confirm.
    pub kind: ConnectionKind,
    /// X.224 destination reference.
    pub destination: u16,
    /// X.224 source reference.
    pub source: u16,
    /// Cookie or routing token, including CRLF, or empty. At most
    /// [`MAX_CONNECTION_DATA`] bytes together with negotiation fields.
    pub routing_token: Vec<u8>,
    /// Optional security negotiation.
    pub negotiation: Option<Negotiation>,
    /// Optional correlation identifier. Reserved correlation bytes are zero.
    pub correlation_id: Option<[u8; CORRELATION_ID_LEN]>,
}
impl Connection {
    /// Reads the complete connection header in a sibling TPKT packet.
    pub fn from_packet(packet: &tpkt::Packet) -> Result<Self, Error> {
        bound(
            packet.payload.len(),
            cotp::MAX_HEADER + 1,
            "connection header",
        )?;
        let (kind, c) = match cotp::over_tpkt::tpdu(packet).map_err(Error::Cotp)? {
            cotp::Tpdu::ConnectionRequest(c) => (ConnectionKind::Request, c),
            cotp::Tpdu::ConnectionConfirm(c) => (ConnectionKind::Confirm, c),
            _ => return Err(Error::Invalid("connection TPDU")),
        };
        check(
            c.credit == 0 && c.class == 0 && c.options == 0 && c.data.is_empty(),
            "connection class or data",
        )?;
        // Read the original bytes: Variable may recognize a negotiation
        // structure as ordinary COTP parameters, which would lose its shape.
        let mut r = Read::new(packet.payload.get(7..).ok_or(Error::Truncated)?);
        let routing_token = if kind == ConnectionKind::Request
            && !r.rest().is_empty()
            && r.rest().first() != Some(&1)
        {
            let end = r
                .rest()
                .windows(2)
                .position(|x| x == b"\r\n")
                .ok_or(Error::Invalid("routing token terminator"))?
                + 2;
            r.take(end)?.to_vec()
        } else {
            Vec::new()
        };
        let negotiation = if r.rest().is_empty() {
            None
        } else {
            Some(Negotiation::parse(r.take(8)?)?)
        };
        let has_correlation =
            matches!(negotiation, Some(Negotiation::Request { flags, .. }) if flags & 8 != 0);
        let correlation_id = if has_correlation {
            r.expect(&[6, 0, 36, 0])?;
            let id = r.array()?;
            r.expect(&[0; CORRELATION_ID_LEN])?;
            Some(id)
        } else {
            None
        };
        r.finish()?;
        let out = Self {
            kind,
            destination: c.dst_ref,
            source: c.src_ref,
            routing_token,
            negotiation,
            correlation_id,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<(), Error> {
        bound(
            self.routing_token.len(),
            MAX_CONNECTION_DATA,
            "routing token",
        )?;
        if !self.routing_token.is_empty() {
            check(
                self.kind == ConnectionKind::Request
                    && self.routing_token.len() >= 2
                    && self.routing_token.first() != Some(&1)
                    && self.routing_token.windows(2).position(|x| x == b"\r\n")
                        == self.routing_token.len().checked_sub(2),
                "routing token",
            )?;
        }
        check(
            matches!(
                (self.kind, self.negotiation),
                (_, None)
                    | (ConnectionKind::Request, Some(Negotiation::Request { .. }))
                    | (
                        ConnectionKind::Confirm,
                        Some(Negotiation::Response { .. } | Negotiation::Failure(_))
                    )
            ),
            "negotiation direction",
        )?;
        let has =
            matches!(self.negotiation, Some(Negotiation::Request { flags, .. }) if flags & 8 != 0);
        check(has == self.correlation_id.is_some(), "correlation presence")
    }
    /// Returns a TPKT packet through the sibling COTP writer after checking
    /// the entire variable header fits; nothing is silently truncated.
    pub fn to_packet(&self) -> Result<tpkt::Packet, Error> {
        self.validate()?;
        let mut w = Write::new(MAX_CONNECTION_DATA);
        w.put(&self.routing_token)?;
        if let Some(n) = self.negotiation {
            w.put(&n.to_bytes()?)?;
        }
        if let Some(id) = self.correlation_id {
            w.put(&[6, 0, 36, 0])?;
            w.put(&id)?;
            w.put(&[0; CORRELATION_ID_LEN])?;
        }
        let c = cotp::Connect {
            dst_ref: self.destination,
            src_ref: self.source,
            variable: cotp::Variable::Raw(w.b),
            ..cotp::Connect::default()
        };
        let t = match self.kind {
            ConnectionKind::Request => cotp::Tpdu::ConnectionRequest(c),
            ConnectionKind::Confirm => cotp::Tpdu::ConnectionConfirm(c),
        };
        Ok(cotp::over_tpkt::from_tpdu(&t))
    }
}

/// The fixed part of CS_CORE. Names are UTF-16LE bytes; optional fields stay
/// in wire order in `optional`, ending at a complete field boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCore {
    /// Client RDP version.
    pub version: u32,
    /// Requested desktop width in pixels.
    pub desktop_width: u16,
    /// Requested desktop height in pixels.
    pub desktop_height: u16,
    /// Legacy color depth code: 0xca00 or 0xca01 when `optional` is empty.
    /// It is not checked when postBeta2ColorDepth is present.
    pub color_depth: u16,
    /// Secure attention sequence code.
    pub sas_sequence: u16,
    /// Keyboard layout identifier.
    pub keyboard_layout: u32,
    /// Client build number.
    pub client_build: u32,
    /// Computer name as 32 UTF-16LE bytes, with an aligned null terminator.
    pub client_name: [u8; CLIENT_NAME_LEN],
    /// Keyboard type.
    pub keyboard_type: u32,
    /// Keyboard subtype.
    pub keyboard_subtype: u32,
    /// Number of keyboard function keys.
    pub keyboard_function_keys: u32,
    /// IME file name as 64 UTF-16LE bytes, with an aligned null terminator.
    pub ime_file_name: [u8; IME_NAME_LEN],
    /// Optional suffix from postBeta2ColorDepth through deviceScaleFactor;
    /// at most [`MAX_CORE_OPTIONAL`] bytes. No partial fields are accepted.
    /// When highColorDepth is absent, postBeta2ColorDepth is 0xca00 through
    /// 0xca04. MS-RDPBCGR says to ignore desktopPhysicalWidth without
    /// desktopPhysicalHeight, and desktopScaleFactor without
    /// deviceScaleFactor; the reader drops such a field and writers refuse it.
    pub optional: Vec<u8>,
}

// Lengths of the optional client core suffix that end on a field boundary.
const CORE_BOUNDARIES: [usize; 16] = [0, 2, 4, 8, 10, 12, 14, 78, 79, 80, 84, 88, 92, 94, 98, 102];

fn utf16_terminated(b: &[u8]) -> bool {
    b.chunks_exact(2).any(|c| c == [0, 0])
}

impl ClientCore {
    // MS-RDPBCGR 2.2.1.3.2 and 3.3.5.3.3: terminated names and a valid
    // color depth in the field that governs it. An invalid highColorDepth
    // falls back to 8 bpp, so only the two older fields are checked.
    fn validate(&self) -> Result<(), Error> {
        check(
            utf16_terminated(&self.client_name),
            "unterminated client name",
        )?;
        check(
            utf16_terminated(&self.ime_file_name),
            "unterminated IME file name",
        )?;
        match self.optional.as_slice() {
            [] => check(
                matches!(self.color_depth, 0xca00 | 0xca01),
                "client core color depth",
            ),
            [a, b, rest @ ..] if rest.len() < 8 => check(
                (0xca00..=0xca04).contains(&u16::from_le_bytes([*a, *b])),
                "client core postBeta2 color depth",
            ),
            _ => Ok(()),
        }
    }
}

/// A static virtual channel requested by CS_NET.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelDefinition {
    /// Eight wire bytes: an ANSI name of at most seven characters, null
    /// terminated and zero padded.
    pub name: [u8; CHANNEL_NAME_LEN],
    /// CHANNEL_OPTION flags; unknown bits survive.
    pub options: u32,
}

/// A TS_MONITOR_DEF with inclusive desktop coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Monitor {
    /// Left desktop coordinate.
    pub left: i32,
    /// Top desktop coordinate.
    pub top: i32,
    /// Right desktop coordinate, at least `left`.
    pub right: i32,
    /// Bottom desktop coordinate, at least `top`.
    pub bottom: i32,
    /// Monitor flags, including primary-monitor bit 0.
    pub flags: u32,
}

/// A GCC client or server user-data block. Known blocks have typed fields;
/// unknown blocks remain bytes. Session-level requirements, such as one
/// primary monitor and matching channel counts, belong to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataBlock {
    /// CS_CORE (0xc001).
    ClientCore(ClientCore),
    /// CS_SECURITY (0xc002).
    ClientSecurity {
        /// Supported standard security encryption methods.
        encryption_methods: u32,
        /// Extended encryption methods.
        extended_methods: u32,
    },
    /// CS_NET (0xc003), at most [`MAX_CHANNELS`] definitions.
    ClientNetwork(Vec<ChannelDefinition>),
    /// CS_CLUSTER (0xc004).
    ClientCluster {
        /// Redirection support and version flags.
        flags: u32,
        /// Redirected session identifier.
        redirected_session_id: u32,
    },
    /// CS_MONITOR (0xc005); its reserved flags are zero.
    ClientMonitor(Vec<Monitor>),
    /// CS_MCS_MSGCHANNEL (0xc006); its reserved flags are zero.
    ClientMessageChannel,
    /// CS_MULTITRANSPORT (0xc00a), with transport capability flags.
    ClientMultitransport(u32),
    /// SC_CORE (0x0c01).
    ServerCore {
        /// Server RDP version.
        version: u32,
        /// The client's requested protocols, when this optional field exists.
        requested_protocols: Option<Protocols>,
        /// Optional early capability flags; requires requested_protocols.
        early_capability_flags: Option<u32>,
    },
    /// SC_SECURITY (0x0c02). Random and certificate are empty when both
    /// encryption fields are zero; otherwise random is exactly 32 bytes.
    ServerSecurity {
        /// Selected standard security method.
        encryption_method: u32,
        /// Standard security level.
        encryption_level: u32,
        /// Server random bytes, exactly [`SERVER_RANDOM_LEN`] when encryption is selected.
        random: Vec<u8>,
        /// Opaque certificate bytes, bounded by [`MAX_GCC_DATA`].
        certificate: Vec<u8>,
    },
    /// SC_NET (0x0c03). Odd channel counts carry two padding bytes on wire.
    ServerNetwork {
        /// The global I/O channel identifier.
        io_channel: u16,
        /// Static channel identifiers, at most [`MAX_CHANNELS`].
        channels: Vec<u16>,
    },
    /// SC_MCS_MSGCHANNEL (0x0c04), with the message channel identifier.
    ServerMessageChannel(u16),
    /// SC_MULTITRANSPORT (0x0c08), with transport capability flags.
    ServerMultitransport(u32),
    /// An unrecognized block type, including extensions outside this codec.
    Other {
        /// Wire type; must not alias a typed variant.
        kind: u16,
        /// Bytes after the four-byte header, bounded by [`MAX_GCC_DATA`].
        data: Vec<u8>,
    },
}
impl DataBlock {
    /// Returns the block's two-byte wire type.
    pub fn kind(&self) -> u16 {
        match self {
            Self::ClientCore(_) => 0xc001,
            Self::ClientSecurity { .. } => 0xc002,
            Self::ClientNetwork(_) => 0xc003,
            Self::ClientCluster { .. } => 0xc004,
            Self::ClientMonitor(_) => 0xc005,
            Self::ClientMessageChannel => 0xc006,
            Self::ClientMultitransport(_) => 0xc00a,
            Self::ServerCore { .. } => 0x0c01,
            Self::ServerSecurity { .. } => 0x0c02,
            Self::ServerNetwork { .. } => 0x0c03,
            Self::ServerMessageChannel(_) => 0x0c04,
            Self::ServerMultitransport(_) => 0x0c08,
            Self::Other { kind, .. } => *kind,
        }
    }
    /// Reads exactly one block including its four-byte header. Counts and
    /// inner lengths must exactly fill the enclosing block.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_GCC_DATA, "GCC block")?;
        let mut outer = Read::new(b);
        let kind = outer.le16()?;
        let length = usize::from(outer.le16()?);
        check(length >= 4 && length == b.len(), "GCC block length")?;
        let mut r = Read::new(outer.rest());
        let out = match kind {
            0xc001 => {
                let core = ClientCore {
                    version: r.le32()?,
                    desktop_width: r.le16()?,
                    desktop_height: r.le16()?,
                    color_depth: r.le16()?,
                    sas_sequence: r.le16()?,
                    keyboard_layout: r.le32()?,
                    client_build: r.le32()?,
                    client_name: r.array()?,
                    keyboard_type: r.le32()?,
                    keyboard_subtype: r.le32()?,
                    keyboard_function_keys: r.le32()?,
                    ime_file_name: r.array()?,
                    optional: {
                        let n = r.rest().len();
                        bound(n, MAX_CORE_OPTIONAL, "client core optional fields")?;
                        check(CORE_BOUNDARIES.contains(&n), "client core field boundary")?;
                        let mut optional = r.take(n)?.to_vec();
                        // An unpaired field is ignored by the receiver.
                        if n == 88 || n == 98 {
                            optional.truncate(n - 4);
                        }
                        optional
                    },
                };
                core.validate()?;
                Self::ClientCore(core)
            }
            0xc002 => Self::ClientSecurity {
                encryption_methods: r.le32()?,
                extended_methods: r.le32()?,
            },
            0xc003 => {
                let count = size(r.le32()?)?;
                bound(count, MAX_CHANNELS, "channels")?;
                let mut channels = Vec::with_capacity(count);
                for _ in 0..count {
                    let name: [u8; CHANNEL_NAME_LEN] = r.array()?;
                    check(name.contains(&0), "unterminated channel name")?;
                    channels.push(ChannelDefinition {
                        name,
                        options: r.le32()?,
                    });
                }
                Self::ClientNetwork(channels)
            }
            0xc004 => Self::ClientCluster {
                flags: r.le32()?,
                redirected_session_id: r.le32()?,
            },
            0xc005 => {
                check(r.le32()? == 0, "monitor reserved flags")?;
                let count = size(r.le32()?)?;
                check(count != 0, "monitor count")?;
                bound(count, MAX_MONITORS, "monitors")?;
                let mut monitors = Vec::with_capacity(count);
                for _ in 0..count {
                    let m = Monitor {
                        left: r.i32()?,
                        top: r.i32()?,
                        right: r.i32()?,
                        bottom: r.i32()?,
                        flags: r.le32()?,
                    };
                    check(m.right >= m.left && m.bottom >= m.top, "monitor rectangle")?;
                    monitors.push(m);
                }
                Self::ClientMonitor(monitors)
            }
            0xc006 => {
                check(r.le32()? == 0, "message channel flags")?;
                Self::ClientMessageChannel
            }
            0xc00a => Self::ClientMultitransport(r.le32()?),
            0x0c01 => Self::ServerCore {
                version: r.le32()?,
                requested_protocols: if r.rest().is_empty() {
                    None
                } else {
                    Some(Protocols(r.le32()?))
                },
                early_capability_flags: if r.rest().is_empty() {
                    None
                } else {
                    Some(r.le32()?)
                },
            },
            0x0c02 => {
                let encryption_method = r.le32()?;
                let encryption_level = r.le32()?;
                let (random, certificate) = if encryption_method == 0 && encryption_level == 0 {
                    (Vec::new(), Vec::new())
                } else {
                    let random_len = size(r.le32()?)?;
                    let cert_len = size(r.le32()?)?;
                    check(random_len == SERVER_RANDOM_LEN, "server random length")?;
                    bound(cert_len, MAX_GCC_DATA, "certificate")?;
                    (r.take(random_len)?.to_vec(), r.take(cert_len)?.to_vec())
                };
                Self::ServerSecurity {
                    encryption_method,
                    encryption_level,
                    random,
                    certificate,
                }
            }
            0x0c03 => {
                let io_channel = r.le16()?;
                let count = usize::from(r.le16()?);
                bound(count, MAX_CHANNELS, "channels")?;
                let mut channels = Vec::with_capacity(count);
                for _ in 0..count {
                    channels.push(r.le16()?);
                }
                if count % 2 != 0 {
                    r.take(2)?;
                } // Padding is ignored on read.
                Self::ServerNetwork {
                    io_channel,
                    channels,
                }
            }
            0x0c04 => Self::ServerMessageChannel(r.le16()?),
            0x0c08 => Self::ServerMultitransport(r.le32()?),
            _ => Self::Other {
                kind,
                data: r.take(r.rest().len())?.to_vec(),
            },
        };
        r.finish()?;
        Ok(out)
    }
}

/// Reads a complete sequence of GCC blocks, up to [`MAX_BLOCKS`] blocks
/// and [`MAX_GCC_DATA`] aggregate bytes. Order and duplicates are preserved.
fn read_blocks(b: &[u8]) -> Result<Vec<DataBlock>, Error> {
    bound(b.len(), MAX_GCC_DATA, "GCC blocks")?;
    let mut r = Read::new(b);
    let mut blocks = Vec::with_capacity(MAX_BLOCKS);
    while !r.rest().is_empty() {
        bound(blocks.len() + 1, MAX_BLOCKS, "GCC block count")?;
        let mut h = Read::new(r.rest());
        h.le16()?;
        let n = usize::from(h.le16()?);
        check(n >= 4, "GCC block length")?;
        blocks.push(DataBlock::parse(r.take(n)?)?);
    }
    Ok(blocks)
}

/// An RDP GCC Conference Create request or response, including ConnectData.
/// RDP's fixed conference name, OID and H.221 key are encoded automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GccConference {
    /// Client request; the whole encoding is at most [`MAX_GCC_REQUEST`].
    Request(Vec<DataBlock>),
    /// Server response, with at most [`MAX_GCC_DATA`] bytes of blocks.
    Response {
        /// GCC node identifier, 1001 through 65536 inclusive.
        node_id: u32,
        /// Conference tag encoded as a signed PER integer, limited to 32 bits.
        tag: i32,
        /// GCC result enumeration, 0 through 4; zero means success.
        result: u8,
        /// Server data blocks, up to [`MAX_BLOCKS`].
        blocks: Vec<DataBlock>,
    },
}
impl GccConference {
    /// Reads a complete RDP GCC wrapper. The response's outer connectPDU
    /// length is deliberately ignored, as MS-RDPBCGR 3.2.5.3.4 requires:
    /// real servers often send the constant 0x2a. Inner lengths stay checked.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_GCC_RESPONSE, "GCC conference")?;
        let mut r = Read::new(b);
        r.expect(&[0, 5, 0, 0x14, 0x7c, 0, 1])?;
        let outer_length = r.per_len()?;
        let body_length = r.rest().len();
        let kind = r.byte()?;
        let (node, tag, result) = match kind {
            0 => {
                bound(b.len(), MAX_GCC_REQUEST, "GCC request")?;
                check(outer_length == body_length, "GCC request length")?;
                r.expect(&[8, 0, 0x10, 0])?;
                (0, 0, 0)
            }
            0x14 => {
                let node = u32::from(r.be16()?) + 1001;
                check(node <= 65536, "GCC node ID")?;
                let tag = r.per_signed()?;
                let result = r.byte()?;
                check(result & 0x8f == 0 && result >> 4 <= 4, "GCC result")?;
                (node, tag, result >> 4)
            }
            _ => return Err(Error::Unsupported("GCC conference choice")),
        };
        r.expect(&[1, 0xc0, 0])?;
        r.expect(if kind == 0 { b"Duca" } else { b"McDn" })?;
        let length = r.per_len()?;
        let blocks = read_blocks(r.take(length)?)?;
        r.finish()?;
        check_block_direction(&blocks, kind == 0)?;
        if kind == 0 {
            Ok(Self::Request(blocks))
        } else {
            Ok(Self::Response {
                node_id: node,
                tag,
                result,
                blocks,
            })
        }
    }
}
fn check_block_direction(blocks: &[DataBlock], request: bool) -> Result<(), Error> {
    bound(blocks.len(), MAX_BLOCKS, "GCC block count")?;
    for b in blocks {
        let k = b.kind();
        // Unknown extension blocks can use future type ranges.
        check(
            if request {
                k & 0xff00 != 0x0c00
            } else {
                k & 0xff00 != 0xc000
            },
            "GCC block direction",
        )?;
    }
    Ok(())
}

/// The eight BER integers in an MCS DomainParameters sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainParameters {
    /// Maximum number of channel identifiers.
    pub max_channel_ids: u32,
    /// Maximum number of user identifiers.
    pub max_user_ids: u32,
    /// Maximum number of token identifiers.
    pub max_token_ids: u32,
    /// Number of supported priorities.
    pub num_priorities: u32,
    /// Minimum throughput.
    pub min_throughput: u32,
    /// Maximum domain height.
    pub max_height: u32,
    /// Maximum MCS PDU size.
    pub max_pdu_size: u32,
    /// MCS protocol version.
    pub protocol_version: u32,
}
impl DomainParameters {
    fn read(r: &mut Read<'_>) -> Result<Self, Error> {
        let mut r = Read::new(r.ber(&[0x30])?);
        let out = Self {
            max_channel_ids: r.ber_uint(2)?,
            max_user_ids: r.ber_uint(2)?,
            max_token_ids: r.ber_uint(2)?,
            num_priorities: r.ber_uint(2)?,
            min_throughput: r.ber_uint(2)?,
            max_height: r.ber_uint(2)?,
            max_pdu_size: r.ber_uint(2)?,
            protocol_version: r.ber_uint(2)?,
        };
        r.finish()?;
        Ok(out)
    }
    fn write(&self, w: &mut Write) -> Result<(), Error> {
        let mut body = Write::new(MAX_PDU);
        for n in [
            self.max_channel_ids,
            self.max_user_ids,
            self.max_token_ids,
            self.num_priorities,
            self.min_throughput,
            self.max_height,
            self.max_pdu_size,
            self.protocol_version,
        ] {
            body.ber_uint(2, n)?;
        }
        w.ber(&[0x30], &body.b)
    }
}

/// MCS Connect Initial and Connect Response, BER encoded around PER GCC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McsConnect {
    /// Application tag 101, Connect Initial.
    Initial {
        /// Calling domain selector, at most [`MAX_SELECTOR`] bytes.
        calling_domain: Vec<u8>,
        /// Called domain selector, at most [`MAX_SELECTOR`] bytes.
        called_domain: Vec<u8>,
        /// Upward flag from the BER Boolean.
        upward: bool,
        /// Requested domain parameters.
        target: DomainParameters,
        /// Minimum domain parameters.
        minimum: DomainParameters,
        /// Maximum domain parameters.
        maximum: DomainParameters,
        /// A GCC Conference Create Request.
        conference: GccConference,
    },
    /// Application tag 102, Connect Response.
    Response {
        /// MCS result, 0 through 15; zero means success.
        result: u8,
        /// Called connection identifier.
        called_connect_id: u32,
        /// Negotiated domain parameters.
        parameters: DomainParameters,
        /// A GCC Conference Create Response.
        conference: GccConference,
    },
}
impl McsConnect {
    /// Reads exactly one BER connection PDU after the COTP data header.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_PDU, "MCS connect")?;
        let mut outer = Read::new(b);
        outer.expect(&[0x7f])?;
        let kind = outer.byte()?;
        check(kind == 0x65 || kind == 0x66, "MCS connect tag")?;
        let length = outer.ber_len()?;
        let mut r = Read::new(outer.take(length)?);
        outer.finish()?;
        let out = if kind == 0x65 {
            let calling = r.ber(&[4])?;
            bound(calling.len(), MAX_SELECTOR, "calling selector")?;
            let called = r.ber(&[4])?;
            bound(called.len(), MAX_SELECTOR, "called selector")?;
            let boolean = r.ber(&[1])?;
            let upward = match boolean {
                [v] => *v != 0,
                _ => return Err(Error::Invalid("BER Boolean")),
            };
            Self::Initial {
                calling_domain: calling.to_vec(),
                called_domain: called.to_vec(),
                upward,
                target: DomainParameters::read(&mut r)?,
                minimum: DomainParameters::read(&mut r)?,
                maximum: DomainParameters::read(&mut r)?,
                conference: GccConference::parse(r.ber(&[4])?)?,
            }
        } else {
            let result = r.ber_uint(10)?;
            check(result <= 15, "MCS result")?;
            Self::Response {
                result: result as u8,
                called_connect_id: r.ber_uint(2)?,
                parameters: DomainParameters::read(&mut r)?,
                conference: GccConference::parse(r.ber(&[4])?)?,
            }
        };
        r.finish()?;
        out.direction()?;
        Ok(out)
    }
    fn direction(&self) -> Result<(), Error> {
        check(
            matches!(
                self,
                Self::Initial {
                    conference: GccConference::Request(_),
                    ..
                } | Self::Response {
                    conference: GccConference::Response { .. },
                    ..
                }
            ),
            "MCS/GCC direction",
        )
    }
}

/// MCS domain PDUs in the aligned PER form used by RDP. User identifiers
/// are decoded from their 1001-based representation; channel IDs are direct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McsPdu {
    /// Erect Domain Request (choice 1).
    ErectDomain {
        /// Sub-height, normally zero.
        sub_height: u32,
        /// Sub-interval, normally zero.
        sub_interval: u32,
    },
    /// Attach User Request (choice 10).
    AttachUserRequest,
    /// Attach User Confirm (choice 11).
    AttachUserConfirm {
        /// MCS result, 0 through 15.
        result: u8,
        /// Assigned user ID, present if and only if the result is 0
        /// (T.125 section 11.18).
        initiator: Option<u32>,
    },
    /// Channel Join Request (choice 14).
    ChannelJoinRequest {
        /// Attached user identifier.
        initiator: u32,
        /// Requested channel identifier.
        channel_id: u16,
    },
    /// Channel Join Confirm (choice 15).
    ChannelJoinConfirm {
        /// MCS result, 0 through 15.
        result: u8,
        /// Attached user identifier.
        initiator: u32,
        /// Requested channel identifier.
        requested: u16,
        /// Joined channel identifier, present if and only if the result is
        /// 0 (T.125 section 11.22); then it equals `requested`.
        channel_id: Option<u16>,
    },
    /// Send Data Request (choice 25) or Indication (choice 26). This carries
    /// client info, licensing and activation, or arbitrary protected bytes.
    SendData {
        /// False for request, true for indication.
        indication: bool,
        /// Sender's attached user identifier.
        initiator: u32,
        /// Destination channel identifier.
        channel_id: u16,
        /// Data priority, 0 through 3.
        priority: u8,
        /// Two segmentation bits: 3 means both begin and end.
        segmentation: u8,
        /// User data, at most [`MAX_PER_LENGTH`] bytes; not decrypted here.
        data: Vec<u8>,
    },
}
impl McsPdu {
    /// Reads exactly one supported MCS PER PDU, excluding COTP and TPKT.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_PDU, "MCS PDU")?;
        let mut r = Read::new(b);
        let tag = r.byte()?;
        let pdu = match tag {
            4 => Self::ErectDomain {
                sub_height: r.per_uint()?,
                sub_interval: r.per_uint()?,
            },
            0x28 => Self::AttachUserRequest,
            0x2c..=0x2f => Self::AttachUserConfirm {
                result: r.mcs_result(tag)?,
                initiator: if tag & 2 != 0 {
                    Some(r.user_id()?)
                } else {
                    None
                },
            },
            0x38 => Self::ChannelJoinRequest {
                initiator: r.user_id()?,
                channel_id: r.be16()?,
            },
            0x3c..=0x3f => Self::ChannelJoinConfirm {
                result: r.mcs_result(tag)?,
                initiator: r.user_id()?,
                requested: r.be16()?,
                channel_id: if tag & 2 != 0 { Some(r.be16()?) } else { None },
            },
            0x64 | 0x68 => {
                let initiator = r.user_id()?;
                let channel_id = r.be16()?;
                let bits = r.byte()?;
                check(bits & 15 == 0, "MCS priority padding")?;
                let n = r.per_len()?;
                Self::SendData {
                    indication: tag == 0x68,
                    initiator,
                    channel_id,
                    priority: bits >> 6,
                    segmentation: (bits >> 4) & 3,
                    data: r.take(n)?.to_vec(),
                }
            }
            _ => return Err(Error::Unsupported("MCS PER choice")),
        };
        r.finish()?;
        pdu.validate()?;
        Ok(pdu)
    }
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::AttachUserConfirm { result, initiator } => {
                check(
                    *result <= 15 && (*result == 0) == initiator.is_some(),
                    "attach confirm result",
                )?;
                if let Some(id) = initiator {
                    valid_user(*id)?;
                }
            }
            Self::ChannelJoinConfirm {
                result,
                initiator,
                requested,
                channel_id,
            } => {
                let expected = if *result == 0 { Some(*requested) } else { None };
                check(
                    *result <= 15 && *channel_id == expected,
                    "join confirm result",
                )?;
                valid_user(*initiator)?;
            }
            Self::ChannelJoinRequest { initiator, .. } => valid_user(*initiator)?,
            Self::SendData {
                initiator,
                priority,
                segmentation,
                data,
                ..
            } => {
                valid_user(*initiator)?;
                check(*priority <= 3 && *segmentation <= 3, "MCS data flags")?;
                bound(data.len(), MAX_PER_LENGTH, "MCS user data")?;
            }
            _ => {}
        }
        Ok(())
    }
}
fn valid_user(id: u32) -> Result<(), Error> {
    check((1001..=65535).contains(&id), "MCS user ID")
}

/// Flags in the basic security header.
pub mod security_flags {
    /// The payload carries an RDP security exchange.
    pub const EXCHANGE: u16 = 0x0001;
    /// The payload is encrypted; signatures remain in the opaque payload.
    pub const ENCRYPT: u16 = 0x0008;
    /// The payload carries Client Info.
    pub const INFO: u16 = 0x0040;
    /// The payload carries a licensing message.
    pub const LICENSE: u16 = 0x0080;
    /// The sender supports encrypted licensing messages.
    pub const LICENSE_ENCRYPT: u16 = 0x0200;
    /// Standard-security redirection also protects its payload.
    pub const REDIRECTION: u16 = 0x0400;
    /// The signature uses the salted MAC scheme.
    pub const SECURE_CHECKSUM: u16 = 0x0800;
    /// The high security flags contain valid data.
    pub const FLAGS_HI_VALID: u16 = 0x8000;
}

/// The basic four-byte security header followed by opaque bytes. Encrypted
/// signatures, FIPS headers and encrypted data are all retained in `data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityPayload {
    /// Low security flags.
    pub flags: u16,
    /// High flags, preserved even when FLAGS_HI_VALID is clear.
    pub flags_hi: u16,
    /// Bytes after the basic header, at most [`MAX_PDU`] minus 4.
    pub data: Vec<u8>,
}
impl SecurityPayload {
    /// Reads a complete payload that the caller knows has a security header.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_PDU, "security payload")?;
        let mut r = Read::new(b);
        Ok(Self {
            flags: r.le16()?,
            flags_hi: r.le16()?,
            data: r.rest().to_vec(),
        })
    }

    /// Returns plaintext bytes, or refuses an encrypted, redirection or
    /// security-exchange payload. Decryption is the caller's responsibility.
    pub fn plaintext(&self) -> Result<&[u8], Error> {
        check(
            self.flags
                & (security_flags::ENCRYPT
                    | security_flags::REDIRECTION
                    | security_flags::EXCHANGE)
                == 0,
            "protected security payload",
        )?;
        Ok(&self.data)
    }
}

/// INFO_UNICODE: Client Info strings are UTF-16LE instead of code-page bytes.
pub const INFO_UNICODE: u32 = 0x10;
/// INFO_RESERVED1 and INFO_RESERVED2, which MS-RDPBCGR says must not be set.
pub const INFO_RESERVED: u32 = 0x0180_0000;

/// The plaintext TS_INFO_PACKET. The five strings exclude their wire null
/// terminators. Their bytes are retained without Unicode or code-page
/// conversion. Extended Info is a version-dependent opaque suffix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientInfo {
    /// ANSI code page, or active language identifier when INFO_UNICODE is set.
    pub code_page: u32,
    /// INFO flags, including [`INFO_UNICODE`]; [`INFO_RESERVED`] is refused.
    pub flags: u32,
    /// Domain bytes; with its terminator, at most [`MAX_INFO_STRING`].
    pub domain: Vec<u8>,
    /// User name bytes; with its terminator, at most [`MAX_INFO_STRING`].
    pub user_name: Vec<u8>,
    /// Password or authentication bytes; with its terminator, at most [`MAX_INFO_STRING`].
    pub password: Vec<u8>,
    /// Alternate shell bytes; with its terminator, at most [`MAX_INFO_STRING`].
    pub alternate_shell: Vec<u8>,
    /// Working directory bytes; with its terminator, at most [`MAX_INFO_STRING`].
    pub working_dir: Vec<u8>,
    /// Extended Info Packet bytes, at most [`MAX_EXTRA_INFO`]. No time-zone,
    /// reconnect-cookie or address fields are interpreted here.
    pub extra_info: Vec<u8>,
}
impl ClientInfo {
    /// Reads a complete plaintext Info Packet, after the security header.
    /// Checks string lengths, Unicode alignment and all five terminators.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_PDU, "client info")?;
        let mut r = Read::new(b);
        let code_page = r.le32()?;
        let flags = r.le32()?;
        check(flags & INFO_RESERVED == 0, "reserved info flags")?;
        let unicode = flags & INFO_UNICODE != 0;
        let lengths = [r.le16()?, r.le16()?, r.le16()?, r.le16()?, r.le16()?];
        let mut strings = lengths.into_iter().map(|n| {
            let n = usize::from(n);
            bound(n + 1 + usize::from(unicode), MAX_INFO_STRING, "info string")?;
            check(!unicode || n % 2 == 0, "Unicode string length")?;
            let b = r.take(n)?.to_vec();
            r.expect(if unicode { &[0, 0] } else { &[0] })?;
            Ok(b)
        });
        let mut next = || strings.next().ok_or(Error::Truncated)?;
        let domain = next()?;
        let user_name = next()?;
        let password = next()?;
        let alternate_shell = next()?;
        let working_dir = next()?;
        bound(r.rest().len(), MAX_EXTRA_INFO, "extended info")?;
        Ok(Self {
            code_page,
            flags,
            domain,
            user_name,
            password,
            alternate_shell,
            working_dir,
            extra_info: r.rest().to_vec(),
        })
    }
}

/// A plaintext licensing ERROR_ALERT, including its preamble and error blob.
/// Full license negotiation belongs to MS-RDPELE and is outside this codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseError {
    /// Preamble flags: version 2 or 3, optionally with bit 7 set.
    pub flags: u8,
    /// Licensing error code; 7 is STATUS_VALID_CLIENT.
    pub error_code: u32,
    /// Licensing state transition; 2 is ST_NO_TRANSITION.
    pub state_transition: u32,
    /// Error blob type; MS-RDPBCGR 2.2.1.12.1.3 requires 4 (BB_ERROR_BLOB).
    pub blob_type: u16,
    /// Error blob bytes, at most [`MAX_PDU`] minus 16.
    pub blob: Vec<u8>,
}
impl LicenseError {
    /// Creates the MS-RDPBCGR 4.1.11 no-license response: valid client,
    /// no state transition, and an empty BB_ERROR_BLOB.
    pub fn valid_client() -> Self {
        Self {
            flags: 3,
            error_code: 7,
            state_transition: 2,
            blob_type: 4,
            blob: Vec::new(),
        }
    }
    /// Reads exactly one licensing error message after any decryption.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_PDU, "license error")?;
        let mut r = Read::new(b);
        r.expect(&[0xff])?;
        let flags = r.byte()?;
        check(matches!(flags & 0x7f, 2 | 3), "license preamble flags")?;
        check(usize::from(r.le16()?) == b.len(), "license message length")?;
        let error_code = r.le32()?;
        let state_transition = r.le32()?;
        let blob_type = r.le16()?;
        check(blob_type == 4, "license error blob type")?;
        let n = usize::from(r.le16()?);
        let blob = r.take(n)?.to_vec();
        r.finish()?;
        Ok(Self {
            flags,
            error_code,
            state_transition,
            blob_type,
            blob,
        })
    }
}

/// A capability set type. Unrecognized type numbers are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityType(pub u16);
impl CapabilityType {
    /// General capability (CAPSTYPE_GENERAL).
    pub const GENERAL: Self = Self(1);
    /// Bitmap capability.
    pub const BITMAP: Self = Self(2);
    /// Drawing orders capability.
    pub const ORDER: Self = Self(3);
    /// Revision 1 bitmap cache capability.
    pub const BITMAP_CACHE: Self = Self(4);
    /// Control capability.
    pub const CONTROL: Self = Self(5);
    /// Activation capability.
    pub const ACTIVATION: Self = Self(7);
    /// Pointer capability.
    pub const POINTER: Self = Self(8);
    /// Share capability.
    pub const SHARE: Self = Self(9);
    /// Color table cache capability.
    pub const COLOR_CACHE: Self = Self(10);
    /// Sound capability.
    pub const SOUND: Self = Self(12);
    /// Input capability.
    pub const INPUT: Self = Self(13);
    /// Font capability.
    pub const FONT: Self = Self(14);
    /// Brush capability.
    pub const BRUSH: Self = Self(15);
    /// Glyph cache capability.
    pub const GLYPH_CACHE: Self = Self(16);
    /// Offscreen bitmap cache capability.
    pub const OFFSCREEN_CACHE: Self = Self(17);
    /// Bitmap cache host support capability.
    pub const BITMAP_CACHE_HOST_SUPPORT: Self = Self(18);
    /// Revision 2 bitmap cache capability.
    pub const BITMAP_CACHE_REV2: Self = Self(19);
    /// Virtual channel capability.
    pub const VIRTUAL_CHANNEL: Self = Self(20);
    /// DrawNineGrid capability.
    pub const DRAW_NINE_GRID: Self = Self(21);
    /// GDI+ capability.
    pub const DRAW_GDI_PLUS: Self = Self(22);
    /// Remote programs capability.
    pub const RAIL: Self = Self(23);
    /// Window list capability.
    pub const WINDOW: Self = Self(24);
    /// Desktop composition capability.
    pub const DESKTOP_COMPOSITION: Self = Self(25);
    /// Multifragment update capability.
    pub const MULTIFRAGMENT_UPDATE: Self = Self(26);
    /// Large pointer capability.
    pub const LARGE_POINTER: Self = Self(27);
    /// Surface commands capability.
    pub const SURFACE_COMMANDS: Self = Self(28);
    /// Bitmap codecs capability.
    pub const BITMAP_CODECS: Self = Self(29);
    /// Frame acknowledgement capability.
    pub const FRAME_ACKNOWLEDGE: Self = Self(30);
    /// Revision 3 bitmap cache codec identifier capability.
    pub const BITMAP_CACHE_V3_CODEC_ID: Self = Self(32);
}

/// A capability header and its uninterpreted body. This codec checks the
/// envelope only; the caller interprets type-specific capability fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilitySet {
    /// Capability type, including unknown types.
    pub kind: CapabilityType,
    /// Body without the four-byte header, at most [`MAX_CAPABILITY`] bytes.
    pub data: Vec<u8>,
}
impl CapabilitySet {
    /// Reads exactly one capability set including its header.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_CAPABILITY + 4, "capability")?;
        let mut r = Read::new(b);
        let kind = CapabilityType(r.le16()?);
        let n = usize::from(r.le16()?);
        check(n >= 4 && n == b.len(), "capability length")?;
        Ok(Self {
            kind,
            data: r.rest().to_vec(),
        })
    }
}

/// The fields that distinguish the two activation PDUs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveKind {
    /// Demand Active (Share Control type 1).
    Demand {
        /// Trailing session identifier, ignored by clients but retained here.
        session_id: u32,
    },
    /// Confirm Active (Share Control type 3).
    Confirm {
        /// Originator identifier; must be [`SERVER_CHANNEL_ID`].
        originator_id: u16,
    },
}

/// A plaintext Demand Active or Confirm Active PDU, including its six-byte
/// Share Control Header. Security and MCS headers are handled separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivePdu {
    /// Demand or confirm, with its direction-specific field.
    pub kind: ActiveKind,
    /// Share Control source identifier.
    pub source: u16,
    /// Share identifier.
    pub share_id: u32,
    /// Source descriptor bytes, at most [`MAX_DESCRIPTOR`].
    pub source_descriptor: Vec<u8>,
    /// Capability sets in wire order, at most [`MAX_CAPABILITIES`].
    pub capabilities: Vec<CapabilitySet>,
    /// The ignored pad2Octets value, retained for exact byte round trips.
    pub padding: u16,
}
impl ActivePdu {
    /// Reads exactly one activation PDU. Checks Share Control type/version,
    /// aggregate capability length, individual lengths and capability count.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        bound(b.len(), MAX_PDU, "active PDU")?;
        let mut r = Read::new(b);
        check(usize::from(r.le16()?) == b.len(), "share control length")?;
        let kind = r.le16()?;
        check(kind == 0x11 || kind == 0x13, "share control type/version")?;
        let source = r.le16()?;
        let share_id = r.le32()?;
        let originator = if kind == 0x13 {
            let id = r.le16()?;
            check(id == SERVER_CHANNEL_ID, "confirm active originator")?;
            id
        } else {
            0
        };
        let descriptor_len = usize::from(r.le16()?);
        let combined_len = usize::from(r.le16()?);
        bound(descriptor_len, MAX_DESCRIPTOR, "source descriptor")?;
        let source_descriptor = r.take(descriptor_len)?.to_vec();
        check(combined_len >= 4, "combined capability length")?;
        let mut caps = Read::new(r.take(combined_len)?);
        let count = usize::from(caps.le16()?);
        bound(count, MAX_CAPABILITIES, "capability count")?;
        let padding = caps.le16()?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            let mut h = Read::new(caps.rest());
            h.le16()?;
            let n = usize::from(h.le16()?);
            check(n >= 4, "capability length")?;
            capabilities.push(CapabilitySet::parse(caps.take(n)?)?);
        }
        caps.finish()?;
        let kind = if kind == 0x11 {
            ActiveKind::Demand {
                session_id: r.le32()?,
            }
        } else {
            ActiveKind::Confirm {
                originator_id: originator,
            }
        };
        r.finish()?;
        Ok(Self {
            kind,
            source,
            share_id,
            source_descriptor,
            capabilities,
            padding,
        })
    }
}

impl Wire for Vec<DataBlock> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete GCC block sequence, preserving order and duplicates.
    /// Accepts at most [`MAX_BLOCKS`] blocks and [`MAX_GCC_DATA`] bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        read_blocks(b)
    }

    /// Appends a bounded block sequence. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        bound(self.len(), MAX_BLOCKS, "GCC block count")?;
        let mut bytes = Vec::new();
        for block in self {
            block.write(&mut bytes)?;
            bound(bytes.len(), MAX_GCC_DATA, "GCC blocks")?;
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Negotiation {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes the negotiation structure, refusing multiple selected protocols.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let (kind, flags, value) = match *self {
            Self::Request { flags, protocols } => (1, flags, protocols.0),
            Self::Response { flags, protocol } => {
                check(
                    protocol.0 == 0 || protocol.0.is_power_of_two(),
                    "selected protocol",
                )?;
                (2, flags, protocol.0)
            }
            Self::Failure(code) => (3, 0, code.0),
        };
        let [a, b, c, d] = value.to_le_bytes();
        dst.extend_from_slice(&[kind, flags, 8, 0, a, b, c, d]);
        Ok(())
    }
}

impl Wire for DataBlock {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes the block and checks its typed shape. Unknown blocks may not
    /// use known type codes. Padding in SC_NET is written as zero.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = Write::new(MAX_GCC_DATA - 4);
        match self {
            Self::ClientCore(c) => {
                w.le32(c.version)?;
                w.le16(c.desktop_width)?;
                w.le16(c.desktop_height)?;
                w.le16(c.color_depth)?;
                w.le16(c.sas_sequence)?;
                w.le32(c.keyboard_layout)?;
                w.le32(c.client_build)?;
                w.put(&c.client_name)?;
                w.le32(c.keyboard_type)?;
                w.le32(c.keyboard_subtype)?;
                w.le32(c.keyboard_function_keys)?;
                w.put(&c.ime_file_name)?;
                bound(
                    c.optional.len(),
                    MAX_CORE_OPTIONAL,
                    "client core optional fields",
                )?;
                check(
                    CORE_BOUNDARIES.contains(&c.optional.len())
                        && c.optional.len() != 88
                        && c.optional.len() != 98,
                    "client core field boundary",
                )?;
                w.put(&c.optional)?;
            }
            Self::ClientSecurity {
                encryption_methods,
                extended_methods,
            } => {
                w.le32(*encryption_methods)?;
                w.le32(*extended_methods)?;
            }
            Self::ClientNetwork(channels) => {
                bound(channels.len(), MAX_CHANNELS, "channels")?;
                w.le32(channels.len() as u32)?;
                for c in channels {
                    w.put(&c.name)?;
                    w.le32(c.options)?;
                }
            }
            Self::ClientCluster {
                flags,
                redirected_session_id,
            } => {
                w.le32(*flags)?;
                w.le32(*redirected_session_id)?;
            }
            Self::ClientMonitor(monitors) => {
                bound(monitors.len(), MAX_MONITORS, "monitors")?;
                w.le32(0)?;
                w.le32(monitors.len() as u32)?;
                for m in monitors {
                    w.put(&m.left.to_le_bytes())?;
                    w.put(&m.top.to_le_bytes())?;
                    w.put(&m.right.to_le_bytes())?;
                    w.put(&m.bottom.to_le_bytes())?;
                    w.le32(m.flags)?;
                }
            }
            Self::ClientMessageChannel => w.le32(0)?,
            Self::ClientMultitransport(flags) | Self::ServerMultitransport(flags) => {
                w.le32(*flags)?
            }
            Self::ServerCore {
                version,
                requested_protocols,
                early_capability_flags,
            } => {
                check(
                    early_capability_flags.is_none() || requested_protocols.is_some(),
                    "server core optional fields",
                )?;
                w.le32(*version)?;
                if let Some(p) = requested_protocols {
                    w.le32(p.0)?;
                }
                if let Some(f) = early_capability_flags {
                    w.le32(*f)?;
                }
            }
            Self::ServerSecurity {
                encryption_method,
                encryption_level,
                random,
                certificate,
            } => {
                w.le32(*encryption_method)?;
                w.le32(*encryption_level)?;
                if *encryption_method == 0 && *encryption_level == 0 {
                    check(
                        random.is_empty() && certificate.is_empty(),
                        "unencrypted server security",
                    )?;
                } else {
                    check(random.len() == SERVER_RANDOM_LEN, "server random length")?;
                    bound(certificate.len(), MAX_GCC_DATA, "certificate")?;
                    w.le32(SERVER_RANDOM_LEN as u32)?;
                    w.le32(certificate.len() as u32)?;
                    w.put(random)?;
                    w.put(certificate)?;
                }
            }
            Self::ServerNetwork {
                io_channel,
                channels,
            } => {
                bound(channels.len(), MAX_CHANNELS, "channels")?;
                w.le16(*io_channel)?;
                w.le16(channels.len() as u16)?;
                for &id in channels {
                    w.le16(id)?;
                }
                if channels.len() % 2 != 0 {
                    w.le16(0)?;
                }
            }
            Self::ServerMessageChannel(id) => w.le16(*id)?,
            Self::Other { data, .. } => w.put(data)?,
        }
        let mut out = Write::new(MAX_GCC_DATA);
        out.le16(self.kind())?;
        out.le16(u16_len(w.b.len() + 4)?)?;
        out.put(&w.b)?;
        check(Self::parse(&out.b)? == *self, "block type or fields")?;
        dst.extend_from_slice(&out.b);
        Ok(())
    }
}

impl Wire for GccConference {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes RDP GCC. Responses use the interoperable outer length 0x2a;
    /// all inner lengths describe the actual data.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let (blocks, request) = match self {
            Self::Request(b) => (b, true),
            Self::Response { blocks, .. } => (blocks, false),
        };
        check_block_direction(blocks, request)?;
        let blocks = blocks.to_bytes()?;
        let mut body = Write::new(MAX_GCC_RESPONSE);
        match self {
            Self::Request(_) => body.put(&[0, 8, 0, 0x10, 0])?,
            Self::Response {
                node_id,
                tag,
                result,
                ..
            } => {
                check((1001..=65536).contains(node_id), "GCC node ID")?;
                check(*result <= 4, "GCC result")?;
                body.byte(0x14)?;
                body.be16((node_id - 1001) as u16)?;
                body.per_signed(*tag)?;
                body.byte(result << 4)?;
            }
        }
        body.put(&[1, 0xc0, 0])?;
        body.put(if request { b"Duca" } else { b"McDn" })?;
        body.per_len(blocks.len())?;
        body.put(&blocks)?;
        let mut w = Write::new(if request {
            MAX_GCC_REQUEST
        } else {
            MAX_GCC_RESPONSE
        });
        w.put(&[0, 5, 0, 0x14, 0x7c, 0, 1])?;
        w.per_len(if request { body.b.len() } else { 0x2a })?;
        w.put(&body.b)?;
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

impl Wire for McsConnect {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes canonical definite BER, with a leading zero on positive
    /// integers whose high bit is set. Readers also accept Microsoft's
    /// unsigned integer examples without that leading zero.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        self.direction()?;
        let mut body = Write::new(MAX_PDU);
        let kind = match self {
            Self::Initial {
                calling_domain,
                called_domain,
                upward,
                target,
                minimum,
                maximum,
                conference,
            } => {
                bound(calling_domain.len(), MAX_SELECTOR, "calling selector")?;
                bound(called_domain.len(), MAX_SELECTOR, "called selector")?;
                body.ber(&[4], calling_domain)?;
                body.ber(&[4], called_domain)?;
                body.ber(&[1], &[if *upward { 0xff } else { 0 }])?;
                target.write(&mut body)?;
                minimum.write(&mut body)?;
                maximum.write(&mut body)?;
                body.ber(&[4], &conference.to_bytes()?)?;
                0x65
            }
            Self::Response {
                result,
                called_connect_id,
                parameters,
                conference,
            } => {
                check(*result <= 15, "MCS result")?;
                body.ber_uint(10, u32::from(*result))?;
                body.ber_uint(2, *called_connect_id)?;
                parameters.write(&mut body)?;
                body.ber(&[4], &conference.to_bytes()?)?;
                0x66
            }
        };
        let mut w = Write::new(MAX_PDU);
        w.ber(&[0x7f, kind], &body.b)?;
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

impl Wire for McsPdu {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes one PER PDU, checking ID ranges, results, optional fields,
    /// priorities and the unfragmented user-data length.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        let mut w = Write::new(MAX_PDU);
        match self {
            Self::ErectDomain {
                sub_height,
                sub_interval,
            } => {
                w.byte(4)?;
                w.per_uint(*sub_height)?;
                w.per_uint(*sub_interval)?;
            }
            Self::AttachUserRequest => w.byte(0x28)?,
            Self::AttachUserConfirm { result, initiator } => {
                w.byte((if initiator.is_some() { 0x2e } else { 0x2c }) | (result >> 3))?;
                w.byte((result & 7) << 5)?;
                if let Some(id) = initiator {
                    w.user_id(*id)?;
                }
            }
            Self::ChannelJoinRequest {
                initiator,
                channel_id,
            } => {
                w.byte(0x38)?;
                w.user_id(*initiator)?;
                w.be16(*channel_id)?;
            }
            Self::ChannelJoinConfirm {
                result,
                initiator,
                requested,
                channel_id,
            } => {
                w.byte((if channel_id.is_some() { 0x3e } else { 0x3c }) | (result >> 3))?;
                w.byte((result & 7) << 5)?;
                w.user_id(*initiator)?;
                w.be16(*requested)?;
                if let Some(id) = channel_id {
                    w.be16(*id)?;
                }
            }
            Self::SendData {
                indication,
                initiator,
                channel_id,
                priority,
                segmentation,
                data,
            } => {
                w.byte(if *indication { 0x68 } else { 0x64 })?;
                w.user_id(*initiator)?;
                w.be16(*channel_id)?;
                w.byte((priority << 6) | (segmentation << 4))?;
                w.per_len(data.len())?;
                w.put(data)?;
            }
        }
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

impl Wire for SecurityPayload {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes the header and opaque bytes without changing protection fields.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = Write::new(MAX_PDU);
        w.le16(self.flags)?;
        w.le16(self.flags_hi)?;
        w.put(&self.data)?;
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

impl Wire for ClientInfo {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes Info with recomputed lengths and null terminators. The opaque
    /// extended suffix is copied; its version is chosen by the caller.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let fields = [
            &self.domain,
            &self.user_name,
            &self.password,
            &self.alternate_shell,
            &self.working_dir,
        ];
        let unicode = self.flags & INFO_UNICODE != 0;
        check(self.flags & INFO_RESERVED == 0, "reserved info flags")?;
        let mut w = Write::new(MAX_PDU);
        w.le32(self.code_page)?;
        w.le32(self.flags)?;
        for b in fields {
            bound(
                b.len() + 1 + usize::from(unicode),
                MAX_INFO_STRING,
                "info string",
            )?;
            check(!unicode || b.len() % 2 == 0, "Unicode string length")?;
            w.le16(u16_len(b.len())?)?;
        }
        for b in fields {
            w.put(b)?;
            w.put(if unicode { &[0, 0] } else { &[0] })?;
        }
        bound(self.extra_info.len(), MAX_EXTRA_INFO, "extended info")?;
        w.put(&self.extra_info)?;
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

impl Wire for LicenseError {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes a licensing ERROR_ALERT with recomputed message and blob lengths.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        check(matches!(self.flags & 0x7f, 2 | 3), "license preamble flags")?;
        check(self.blob_type == 4, "license error blob type")?;
        bound(self.blob.len(), MAX_PDU - 16, "license error blob")?;
        let mut w = Write::new(MAX_PDU);
        w.byte(0xff)?;
        w.byte(self.flags)?;
        w.le16(u16_len(self.blob.len() + 16)?)?;
        w.le32(self.error_code)?;
        w.le32(self.state_transition)?;
        w.le16(self.blob_type)?;
        w.le16(u16_len(self.blob.len())?)?;
        w.put(&self.blob)?;
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

impl Wire for CapabilitySet {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes the capability header with the actual body length.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        bound(self.data.len(), MAX_CAPABILITY, "capability")?;
        let mut w = Write::new(MAX_CAPABILITY + 4);
        w.le16(self.kind.0)?;
        w.le16(u16_len(self.data.len() + 4)?)?;
        w.put(&self.data)?;
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

impl Wire for ActivePdu {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(b: &[u8]) -> Result<Self, Error> {
        Self::parse(b)
    }

    /// Writes an activation PDU with recomputed nested lengths and counts.
    /// No required capability set is synthesized; that is session policy.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        bound(
            self.source_descriptor.len(),
            MAX_DESCRIPTOR,
            "source descriptor",
        )?;
        bound(
            self.capabilities.len(),
            MAX_CAPABILITIES,
            "capability count",
        )?;
        let mut caps = Write::new(MAX_PDU);
        caps.le16(u16_len(self.capabilities.len())?)?;
        caps.le16(self.padding)?;
        for c in &self.capabilities {
            caps.put(&c.to_bytes()?)?;
        }
        let mut body = Write::new(MAX_PDU - 2);
        body.le16(match self.kind {
            ActiveKind::Demand { .. } => 0x11,
            ActiveKind::Confirm { .. } => 0x13,
        })?;
        body.le16(self.source)?;
        body.le32(self.share_id)?;
        if let ActiveKind::Confirm { originator_id } = self.kind {
            check(
                originator_id == SERVER_CHANNEL_ID,
                "confirm active originator",
            )?;
            body.le16(originator_id)?;
        }
        body.le16(u16_len(self.source_descriptor.len())?)?;
        body.le16(u16_len(caps.b.len())?)?;
        body.put(&self.source_descriptor)?;
        body.put(&caps.b)?;
        if let ActiveKind::Demand { session_id } = self.kind {
            body.le32(session_id)?;
        }
        let mut w = Write::new(MAX_PDU);
        w.le16(u16_len(body.b.len() + 2)?)?;
        w.put(&body.b)?;
        dst.extend_from_slice(&w.b);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{Fail, Stream, contract, pump, test_support::Lcg};

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() <= 2 * MAX_FRAME);
        s.split_whitespace()
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect()
    }

    // MS-RDPBCGR 4.1.3, complete 416-byte Connect Initial dump.
    fn initial_example() -> Vec<u8> {
        hex("03 00 01 a0 02 f0 80 7f 65 82 01 94 04 01 01 04
             01 01 01 01 ff 30 19 02 01 22 02 01 02 02 01 00
             02 01 01 02 01 00 02 01 01 02 02 ff ff 02 01 02
             30 19 02 01 01 02 01 01 02 01 01 02 01 01 02 01
             00 02 01 01 02 02 04 20 02 01 02 30 1c 02 02 ff
             ff 02 02 fc 17 02 02 ff ff 02 01 01 02 01 00 02
             01 01 02 02 ff ff 02 01 02 04 82 01 33 00 05 00
             14 7c 00 01 81 2a 00 08 00 10 00 01 c0 00 44 75
             63 61 81 1c 01 c0 d8 00 04 00 08 00 00 05 00 04
             01 ca 03 aa 09 04 00 00 ce 0e 00 00 45 00 4c 00
             54 00 4f 00 4e 00 53 00 2d 00 44 00 45 00 56 00
             32 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00
             00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 01 ca 01 00 00 00 00 00
             18 00 07 00 01 00 36 00 39 00 37 00 31 00 32 00
             2d 00 37 00 38 00 33 00 2d 00 30 00 33 00 35 00
             37 00 39 00 37 00 34 00 2d 00 34 00 32 00 37 00
             31 00 34 00 00 00 00 00 00 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00 00 00 00 00 04 c0 0c 00
             0d 00 00 00 00 00 00 00 02 c0 0c 00 1b 00 00 00
             00 00 00 00 03 c0 2c 00 03 00 00 00 72 64 70 64
             72 00 00 00 00 00 80 80 63 6c 69 70 72 64 72 00
             00 00 a0 c0 72 64 70 73 6e 64 00 00 00 00 00 c0")
    }

    // MS-RDPBCGR 4.1.4, complete Connect Response including opaque RSA bytes.
    fn response_example() -> Vec<u8> {
        hex("03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02
             01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01
             02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82
             01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00
             01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08
             00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed
             03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00
             00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a
             12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96
             e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00
             00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00
             00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe
             ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5
             cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55
             ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f
             55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00
             00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e
             f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef
             9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5
             69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a
             e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00
             00")
    }

    fn connection() -> Connection {
        Connection {
            kind: ConnectionKind::Request,
            destination: 0,
            source: 0,
            routing_token: Vec::new(),
            negotiation: Some(Negotiation::Request {
                flags: 0,
                protocols: Protocols(3),
            }),
            correlation_id: None,
        }
    }
    fn core() -> ClientCore {
        ClientCore {
            version: 0x80004,
            desktop_width: 1280,
            desktop_height: 1024,
            color_depth: 0xca01,
            sas_sequence: 0xaa03,
            keyboard_layout: 0x409,
            client_build: 3790,
            client_name: [0; CLIENT_NAME_LEN],
            keyboard_type: 4,
            keyboard_subtype: 0,
            keyboard_function_keys: 12,
            ime_file_name: [0; IME_NAME_LEN],
            optional: Vec::new(),
        }
    }
    fn client_blocks() -> Vec<DataBlock> {
        vec![
            DataBlock::ClientCore(core()),
            DataBlock::ClientSecurity {
                encryption_methods: 0x1b,
                extended_methods: 0,
            },
            DataBlock::ClientNetwork(vec![ChannelDefinition {
                name: *b"rdpdr\0\0\0",
                options: 0x80800000,
            }]),
            DataBlock::ClientCluster {
                flags: 13,
                redirected_session_id: 0,
            },
            DataBlock::ClientMonitor(vec![Monitor {
                left: 0,
                top: 0,
                right: 1279,
                bottom: 1023,
                flags: 1,
            }]),
            DataBlock::ClientMessageChannel,
            DataBlock::ClientMultitransport(3),
            DataBlock::Other {
                kind: 0xc008,
                data: vec![0; 12],
            },
        ]
    }
    fn server_blocks() -> Vec<DataBlock> {
        vec![
            DataBlock::ServerCore {
                version: 0x80004,
                requested_protocols: Some(Protocols(3)),
                early_capability_flags: Some(1),
            },
            DataBlock::ServerSecurity {
                encryption_method: 0,
                encryption_level: 0,
                random: vec![],
                certificate: vec![],
            },
            DataBlock::ServerNetwork {
                io_channel: 1003,
                channels: vec![1004, 1005, 1006],
            },
            DataBlock::ServerMessageChannel(1007),
            DataBlock::ServerMultitransport(3),
        ]
    }
    fn params() -> DomainParameters {
        DomainParameters {
            max_channel_ids: 34,
            max_user_ids: 2,
            max_token_ids: 0,
            num_priorities: 1,
            min_throughput: 0,
            max_height: 1,
            max_pdu_size: 65535,
            protocol_version: 2,
        }
    }
    fn initial() -> McsConnect {
        McsConnect::Initial {
            calling_domain: vec![1],
            called_domain: vec![1],
            upward: true,
            target: params(),
            minimum: params(),
            maximum: params(),
            conference: GccConference::Request(client_blocks()),
        }
    }
    fn response() -> McsConnect {
        McsConnect::Response {
            result: 0,
            called_connect_id: 0,
            parameters: params(),
            conference: GccConference::Response {
                node_id: 1002,
                tag: 1,
                result: 0,
                blocks: server_blocks(),
            },
        }
    }
    fn info() -> ClientInfo {
        ClientInfo {
            code_page: 0x409,
            flags: INFO_UNICODE,
            domain: vec![],
            user_name: vec![b'u', 0],
            password: vec![],
            alternate_shell: vec![],
            working_dir: vec![],
            extra_info: vec![],
        }
    }
    fn active(kind: ActiveKind) -> ActivePdu {
        ActivePdu {
            kind,
            source: 1002,
            share_id: 0x10000,
            source_descriptor: b"RDP\0".to_vec(),
            capabilities: vec![
                CapabilitySet {
                    kind: CapabilityType::GENERAL,
                    data: vec![0; 20],
                },
                CapabilitySet {
                    kind: CapabilityType(0xffff),
                    data: vec![7, 8, 9],
                },
            ],
            padding: 0x1234,
        }
    }
    fn mcspdus() -> Vec<McsPdu> {
        vec![
            McsPdu::ErectDomain {
                sub_height: 0,
                sub_interval: 0,
            },
            McsPdu::AttachUserRequest,
            McsPdu::AttachUserConfirm {
                result: 0,
                initiator: Some(1007),
            },
            McsPdu::AttachUserConfirm {
                result: 14,
                initiator: None,
            },
            McsPdu::ChannelJoinRequest {
                initiator: 1007,
                channel_id: 1003,
            },
            McsPdu::ChannelJoinConfirm {
                result: 0,
                initiator: 1007,
                requested: 1003,
                channel_id: Some(1003),
            },
            McsPdu::ChannelJoinConfirm {
                result: 14,
                initiator: 1007,
                requested: 1003,
                channel_id: None,
            },
            McsPdu::SendData {
                indication: false,
                initiator: 1007,
                channel_id: 1003,
                priority: 1,
                segmentation: 3,
                data: vec![1, 2, 3],
            },
            McsPdu::SendData {
                indication: true,
                initiator: 1002,
                channel_id: 1003,
                priority: 1,
                segmentation: 3,
                data: vec![],
            },
        ]
    }

    fn check_parsers(b: &[u8]) {
        macro_rules! roundtrip {
            ($t:ty) => {
                if let Ok(v) = <$t>::parse(b) {
                    let bytes = v.to_bytes().unwrap();
                    assert!(bytes.len() <= MAX_PDU);
                    assert_eq!(<$t>::parse(&bytes), Ok(v));
                }
            };
        }
        roundtrip!(Negotiation);
        roundtrip!(DataBlock);
        roundtrip!(GccConference);
        roundtrip!(McsConnect);
        roundtrip!(McsPdu);
        roundtrip!(ClientInfo);
        roundtrip!(SecurityPayload);
        roundtrip!(LicenseError);
        roundtrip!(CapabilitySet);
        roundtrip!(ActivePdu);
        if let Ok(blocks) = <Vec<DataBlock> as Wire>::parse(b) {
            assert_eq!(
                <Vec<DataBlock> as Wire>::parse(&blocks.to_bytes().unwrap()),
                Ok(blocks)
            );
        }
        if let Ok(Some((f, n))) = Frame::parse(b) {
            assert!(n <= b.len());
            let bytes = f.to_bytes().unwrap();
            assert_eq!(Frame::parse(&bytes), Ok(Some((f.clone(), bytes.len()))));
            if let Frame::SlowPath(p) = f {
                if let Ok(c) = Connection::from_packet(&p) {
                    assert_eq!(Connection::from_packet(&c.to_packet().unwrap()), Ok(c));
                }
                if let Ok(d) = read_data(&p) {
                    assert_eq!(read_data(&write_data(&d).unwrap()), Ok(d));
                }
            }
        }
    }

    #[test]
    fn spec_negotiation_exact_bytes() {
        let wire = hex("03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00");
        assert_eq!(connection().to_packet().unwrap().to_bytes().unwrap(), wire);
        let (packet, _) = tpkt::Packet::parse(&wire).unwrap().unwrap();
        assert_eq!(Connection::from_packet(&packet), Ok(connection()));
        for (n, b) in [
            (
                Negotiation::Response {
                    flags: 1,
                    protocol: Protocols::TLS,
                },
                hex("02 01 08 00 01 00 00 00"),
            ),
            (
                Negotiation::Failure(FailureCode::HYBRID_REQUIRED),
                hex("03 00 08 00 05 00 00 00"),
            ),
        ] {
            assert_eq!(n.to_bytes().unwrap().as_slice(), b);
            assert_eq!(Negotiation::parse(&b), Ok(n));
        }
    }

    #[test]
    fn cookie_and_correlation_roundtrip() {
        for token in [
            b"Cookie: mstshash=eltons\r\n".as_slice(),
            b"Cookie: msts=123.456.0000\r\n",
            b"",
        ] {
            for correlation in [false, true] {
                let mut c = connection();
                c.routing_token = token.to_vec();
                if correlation {
                    c.negotiation = Some(Negotiation::Request {
                        flags: 8,
                        protocols: Protocols(11),
                    });
                    c.correlation_id = Some([42; CORRELATION_ID_LEN]);
                }
                let packet = c.to_packet().unwrap();
                assert_eq!(Connection::from_packet(&packet), Ok(c));
            }
        }
        let mut legacy = connection();
        legacy.negotiation = None;
        assert_eq!(
            Connection::from_packet(&legacy.to_packet().unwrap()),
            Ok(legacy)
        );
    }

    #[test]
    fn connection_confirms_roundtrip() {
        for n in [
            None,
            Some(Negotiation::Response {
                flags: 0xff,
                protocol: Protocols(0x80000000),
            }),
            Some(Negotiation::Failure(FailureCode(0xffffffff))),
        ] {
            let c = Connection {
                kind: ConnectionKind::Confirm,
                destination: 17,
                source: 19,
                negotiation: n,
                routing_token: vec![],
                correlation_id: None,
            };
            assert_eq!(Connection::from_packet(&c.to_packet().unwrap()), Ok(c));
        }
    }

    #[test]
    fn negotiation_refusals() {
        for bytes in [
            hex("01 00 07 00 00 00 00 00"),
            hex("02 00 08 00 03 00 00 00"),
            hex("03 01 08 00 01 00 00 00"),
            hex("04 00 08 00 00 00 00 00"),
            hex("01 00 08 00 00 00 00 00 00"),
        ] {
            assert!(Negotiation::parse(&bytes).is_err());
        }
        assert!(
            Negotiation::Response {
                flags: 0,
                protocol: Protocols(3)
            }
            .to_bytes()
            .is_err()
        );
    }

    #[test]
    fn connection_refusals() {
        let mut c = connection();
        c.routing_token = b"missing CRLF".to_vec();
        assert!(c.to_packet().is_err());
        c.routing_token = b"a\r\nb\r\n".to_vec();
        assert!(c.to_packet().is_err());
        c.routing_token = vec![b'x'; MAX_CONNECTION_DATA];
        c.routing_token.extend_from_slice(b"\r\n");
        assert!(c.to_packet().is_err());
        c = connection();
        c.correlation_id = Some([0; CORRELATION_ID_LEN]);
        assert!(c.to_packet().is_err());
        c.correlation_id = None;
        c.negotiation = Some(Negotiation::Request {
            flags: 8,
            protocols: Protocols(0),
        });
        assert!(c.to_packet().is_err());
        c = connection();
        c.kind = ConnectionKind::Confirm;
        assert!(c.to_packet().is_err());
        c.negotiation = None;
        c.routing_token = b"x\r\n".to_vec();
        assert!(c.to_packet().is_err());
        for offset in [1, 6] {
            let mut p = connection().to_packet().unwrap();
            p.payload[offset] |= 1;
            assert!(Connection::from_packet(&p).is_err());
        }
        let mut p = connection().to_packet().unwrap();
        p.payload.push(0);
        assert!(Connection::from_packet(&p).is_err());
        let p = write_data(&[]).unwrap();
        assert!(Connection::from_packet(&p).is_err());
    }

    #[test]
    fn connection_header_boundary() {
        let mut c = connection();
        c.routing_token = vec![b'a'; MAX_CONNECTION_DATA - 10];
        c.routing_token.extend_from_slice(b"\r\n");
        let p = c.to_packet().unwrap();
        assert_eq!(p.payload.len(), cotp::MAX_HEADER + 1);
        assert_eq!(Connection::from_packet(&p), Ok(c.clone()));
        c.routing_token.insert(0, b'a');
        assert!(c.to_packet().is_err());
    }

    #[test]
    fn spec_connect_initial() {
        let wire = initial_example();
        assert_eq!(wire.len(), 416);
        let (packet, _) = tpkt::Packet::parse(&wire).unwrap().unwrap();
        let data = read_data(&packet).unwrap();
        let parsed = McsConnect::parse(&data).unwrap();
        let McsConnect::Initial {
            target,
            maximum,
            conference: GccConference::Request(ref blocks),
            ..
        } = parsed
        else {
            panic!()
        };
        assert_eq!(target.max_pdu_size, 65535);
        assert_eq!(maximum.max_user_ids, 64535);
        assert_eq!(blocks.len(), 4);
        let DataBlock::ClientCore(c) = &blocks[0] else {
            panic!()
        };
        assert_eq!((c.desktop_width, c.desktop_height), (1280, 1024));
        assert_eq!(c.optional.len(), 84);
        let DataBlock::ClientNetwork(channels) = &blocks[3] else {
            panic!()
        };
        assert_eq!(channels[1].name, *b"cliprdr\0");
        // The writer adds BER sign octets but preserves every typed value.
        assert_eq!(
            McsConnect::parse(&parsed.to_bytes().unwrap()),
            Ok(parsed.clone())
        );
        if let McsConnect::Initial { conference, .. } = &parsed {
            assert_eq!(conference.to_bytes().unwrap(), data[102..]);
        }
    }

    #[test]
    fn spec_connect_response() {
        let wire = response_example();
        assert_eq!(wire.len(), 337);
        let (packet, _) = tpkt::Packet::parse(&wire).unwrap().unwrap();
        let data = read_data(&packet).unwrap();
        let parsed = McsConnect::parse(&data).unwrap();
        assert_eq!(parsed.to_bytes().unwrap(), data);
        let McsConnect::Response {
            conference: GccConference::Response {
                node_id, blocks, ..
            },
            ..
        } = parsed
        else {
            panic!()
        };
        assert_eq!(node_id, 31219);
        let DataBlock::ServerSecurity {
            random,
            certificate,
            ..
        } = &blocks[2]
        else {
            panic!()
        };
        assert_eq!(random.len(), SERVER_RANDOM_LEN);
        assert_eq!(certificate.len(), 184);
    }

    #[test]
    fn spec_mcs_domain_and_channels_exact_bytes() {
        for (p, bytes) in mcspdus().into_iter().zip([
            "04 01 00 01 00",
            "28",
            "2e 00 00 06",
            "2d c0",
            "38 00 06 03 eb",
            "3e 00 00 06 03 eb 03 eb",
            "3d c0 00 06 03 eb",
            "64 00 06 03 eb 70 03 01 02 03",
            "68 00 01 03 eb 70 00",
        ]) {
            let bytes = hex(bytes);
            assert_eq!(p.to_bytes().unwrap(), bytes);
            assert_eq!(McsPdu::parse(&bytes), Ok(p));
        }
    }

    #[test]
    fn mcs_connect_and_gcc_roundtrips() {
        for c in [initial(), response()] {
            let b = c.to_bytes().unwrap();
            assert_eq!(McsConnect::parse(&b), Ok(c));
        }
        for n in [1001, 65536] {
            for tag in [
                i32::MIN,
                -129,
                -128,
                -1,
                0,
                1,
                127,
                128,
                255,
                256,
                65535,
                i32::MAX,
            ] {
                for result in 0..=4 {
                    let c = GccConference::Response {
                        node_id: n,
                        tag,
                        result,
                        blocks: server_blocks(),
                    };
                    assert_eq!(GccConference::parse(&c.to_bytes().unwrap()), Ok(c));
                }
            }
        }
    }

    #[test]
    fn gcc_response_ignored_length_and_request_checked_length() {
        let response = GccConference::Response {
            node_id: 1001,
            tag: 1,
            result: 0,
            blocks: server_blocks(),
        };
        let mut b = response.to_bytes().unwrap();
        b[7] = 1;
        assert_eq!(GccConference::parse(&b), Ok(response));
        let mut b = GccConference::Request(vec![]).to_bytes().unwrap();
        b[7] -= 1;
        assert!(GccConference::parse(&b).is_err());
        let mut b = GccConference::Request(vec![]).to_bytes().unwrap();
        b[16] = b'X';
        assert!(GccConference::parse(&b).is_err());
    }

    #[test]
    fn gcc_refusals_and_limits() {
        assert!(GccConference::Request(server_blocks()).to_bytes().is_err());
        for node_id in [0, 1000, 65537, u32::MAX] {
            assert!(
                GccConference::Response {
                    node_id,
                    tag: 1,
                    result: 0,
                    blocks: vec![]
                }
                .to_bytes()
                .is_err()
            );
        }
        assert!(
            GccConference::Response {
                node_id: 1001,
                tag: 1,
                result: 5,
                blocks: vec![]
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            GccConference::Request(vec![DataBlock::Other {
                kind: 0xf001,
                data: vec![0; MAX_GCC_REQUEST]
            }])
            .to_bytes()
            .is_err()
        );
        let mut c = initial();
        if let McsConnect::Initial { calling_domain, .. } = &mut c {
            *calling_domain = vec![0; MAX_SELECTOR + 1];
        }
        assert!(c.to_bytes().is_err());
        let mut c = response();
        if let McsConnect::Response { conference, .. } = &mut c {
            *conference = GccConference::Request(vec![]);
        }
        assert!(c.to_bytes().is_err());
        let mut b = GccConference::Request(vec![]).to_bytes().unwrap();
        b[7] = 0xc0;
        assert!(matches!(
            GccConference::parse(&b),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn ber_and_per_integer_refusals() {
        for b in [
            hex("7f 65 80"),
            hex("7f 65 85 00 00 00 00 00"),
            hex("7f 65 84 ff ff ff ff"),
            hex("7f 64 00"),
        ] {
            assert!(McsConnect::parse(&b).is_err());
        }
        for bytes in [
            hex("02 00"),
            hex("02 06 00 00 00 00 00 00"),
            hex("02 05 01 00 00 00 00"),
        ] {
            assert!(Read::new(&bytes).ber_uint(2).is_err());
        }
        for bytes in [
            hex("04 00 01 00"),
            hex("04 05 00 00 00 00 00 01 00"),
            hex("04 c0"),
            hex("28 00"),
        ] {
            assert!(McsPdu::parse(&bytes).is_err());
        }
        let mut r = Read::new(&[0x84, 0, 1, 0, 0]);
        assert!(r.ber_len().is_err());
        for n in [0, 127, 128, 255, 256, 65535, u32::MAX] {
            let p = McsPdu::ErectDomain {
                sub_height: n,
                sub_interval: n,
            };
            assert_eq!(McsPdu::parse(&p.to_bytes().unwrap()), Ok(p));
            let mut w = Write::new(MAX_PDU);
            w.ber_uint(2, n).unwrap();
            assert_eq!(Read::new(&w.b).ber_uint(2), Ok(n));
        }
    }

    #[test]
    fn all_gcc_blocks_roundtrip() {
        for b in client_blocks().into_iter().chain(server_blocks()) {
            assert_eq!(DataBlock::parse(&b.to_bytes().unwrap()), Ok(b));
        }
        let b = client_blocks();
        assert_eq!(
            <Vec<DataBlock> as Wire>::parse(&b.to_bytes().unwrap()),
            Ok(b)
        );
    }

    #[test]
    fn client_core_optional_boundaries() {
        for n in 0..=MAX_CORE_OPTIONAL + 1 {
            let mut c = core();
            // postBeta2ColorDepth 0xca01, then zeros.
            c.optional = [0x01, 0xca, 0, 0].into_iter().cycle().take(n).collect();
            let b = DataBlock::ClientCore(c);
            let result = b.to_bytes();
            let valid = [0, 2, 4, 8, 10, 12, 14, 78, 79, 80, 84, 92, 94, 102].contains(&n);
            assert_eq!(result.is_ok(), valid, "optional length {n}");
            if let Ok(wire) = result {
                assert_eq!(DataBlock::parse(&wire), Ok(b));
            }
        }
    }

    #[test]
    fn client_core_unpaired_fields_are_dropped_on_read() {
        // desktopPhysicalWidth without its height, and desktopScaleFactor
        // without deviceScaleFactor: MS-RDPBCGR 2.2.1.3.2 says to ignore them.
        for (n, kept) in [(88, 84), (98, 94)] {
            let mut c = core();
            c.optional = vec![0x01, 0xca];
            c.optional.resize(n, 7);
            assert!(DataBlock::ClientCore(c.clone()).to_bytes().is_err());
            let mut wire = hex("01 c0 00 00");
            let mut full = c.clone();
            full.optional.truncate(0);
            let fixed = DataBlock::ClientCore(full).to_bytes().unwrap();
            wire.extend_from_slice(&fixed[4..]);
            wire.extend_from_slice(&c.optional);
            let len = wire.len() as u16;
            wire[2..4].copy_from_slice(&len.to_le_bytes());
            let DataBlock::ClientCore(parsed) = DataBlock::parse(&wire).unwrap() else {
                panic!("expected client core");
            };
            assert_eq!(parsed.optional, c.optional[..kept]);
            let b = DataBlock::ClientCore(parsed);
            assert_eq!(DataBlock::parse(&b.to_bytes().unwrap()), Ok(b));
        }
    }

    #[test]
    fn client_core_color_depth_rules() {
        // MS-RDPBCGR 3.3.5.3.3: colorDepth governs without postBeta2ColorDepth,
        // which governs without highColorDepth. highColorDepth falls back.
        for (depth, optional, ok) in [
            (0xca00, vec![], true),
            (0xca01, vec![], true),
            (24, vec![], false),
            (0xca02, vec![], false),
            (24, vec![0x04, 0xca], true),
            (24, vec![0x05, 0xca], false),
            (24, vec![0x18, 0, 1, 0, 0, 0, 0, 0], false),
            (24, vec![0x03, 0xca, 1, 0, 0, 0, 0, 0], true),
            (24, vec![0, 0, 1, 0, 0, 0, 0, 0, 0x18, 0], true),
            (24, vec![0, 0, 1, 0, 0, 0, 0, 0, 0x99, 0], true),
        ] {
            let mut c = core();
            c.color_depth = depth;
            c.optional = optional.clone();
            let b = DataBlock::ClientCore(c);
            assert_eq!(b.to_bytes().is_ok(), ok, "{depth:x} {optional:x?}");
        }
        let mut wire = DataBlock::ClientCore(core()).to_bytes().unwrap();
        wire[12] = 24;
        wire[13] = 0;
        assert_eq!(
            DataBlock::parse(&wire),
            Err(Error::Invalid("client core color depth"))
        );
    }

    #[test]
    fn fixed_names_must_be_terminated() {
        // MS-RDPBCGR 2.2.1.3.2 and 2.2.1.3.4.1.
        let mut c = core();
        c.client_name = [b'A'; CLIENT_NAME_LEN];
        assert!(DataBlock::ClientCore(c.clone()).to_bytes().is_err());
        // A zero high byte next to a zero low byte across characters is not
        // an aligned terminator.
        c.client_name = [b'A'; CLIENT_NAME_LEN];
        for i in (1..CLIENT_NAME_LEN).step_by(2) {
            c.client_name[i] = 0;
        }
        assert!(DataBlock::ClientCore(c.clone()).to_bytes().is_err());
        c.client_name[30] = 0;
        assert!(DataBlock::ClientCore(c.clone()).to_bytes().is_ok());
        let mut c = core();
        c.ime_file_name = [0x41; IME_NAME_LEN];
        assert!(DataBlock::ClientCore(c.clone()).to_bytes().is_err());
        c.ime_file_name[62] = 0;
        c.ime_file_name[63] = 0;
        assert!(DataBlock::ClientCore(c).to_bytes().is_ok());
        let unterminated = DataBlock::ClientNetwork(vec![ChannelDefinition {
            name: *b"ABCDEFGH",
            options: 0,
        }]);
        assert!(unterminated.to_bytes().is_err());
        assert_eq!(
            DataBlock::parse(&hex(
                "03 c0 14 00 01 00 00 00 41 42 43 44 45 46 47 48 00 00 00 00"
            )),
            Err(Error::Invalid("unterminated channel name"))
        );
        let seven = DataBlock::ClientNetwork(vec![ChannelDefinition {
            name: *b"ABCDEFG\0",
            options: 0,
        }]);
        assert_eq!(DataBlock::parse(&seven.to_bytes().unwrap()), Ok(seven));
    }

    #[test]
    fn block_length_type_count_refusals() {
        for b in [
            hex("01 c0 03 00"),
            hex("02 c0 0c 00 00"),
            hex("03 c0 08 00 ff ff ff ff"),
            hex("01 0c 08 00 04 00 08 00 00"),
            hex("05 c0 0c 00 00 00 00 00 00 00 00 00"),
        ] {
            assert!(DataBlock::parse(&b).is_err());
        }
        assert!(
            DataBlock::Other {
                kind: 0xc006,
                data: vec![0; 4]
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            DataBlock::Other {
                kind: 0xffff,
                data: vec![0; MAX_GCC_DATA]
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            DataBlock::ClientNetwork(vec![
                ChannelDefinition {
                    name: [0; CHANNEL_NAME_LEN],
                    options: 0
                };
                MAX_CHANNELS + 1
            ])
            .to_bytes()
            .is_err()
        );
        assert!(
            DataBlock::ServerNetwork {
                io_channel: 1003,
                channels: vec![0; MAX_CHANNELS + 1]
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            vec![DataBlock::ClientMessageChannel; MAX_BLOCKS + 1]
                .to_bytes()
                .is_err()
        );
        let bytes = hex("06 c0 08 00 00 00 00 00").repeat(MAX_BLOCKS + 1);
        assert!(<Vec<DataBlock> as Wire>::parse(&bytes).is_err());
        assert!(<Vec<DataBlock> as Wire>::parse(&vec![0; MAX_GCC_DATA + 1]).is_err());
        assert!(
            Wire::to_bytes(&vec![
                DataBlock::Other {
                    kind: 0xff00,
                    data: vec![0; MAX_GCC_DATA / 2]
                },
                DataBlock::Other {
                    kind: 0xff01,
                    data: vec![0; MAX_GCC_DATA / 2]
                }
            ])
            .is_err()
        );
    }

    #[test]
    fn server_network_padding() {
        let block = DataBlock::ServerNetwork {
            io_channel: 1003,
            channels: vec![1004],
        };
        let mut b = block.to_bytes().unwrap();
        assert_eq!(b, hex("03 0c 0c 00 eb 03 01 00 ec 03 00 00"));
        b[10] = 0xff;
        b[11] = 0xee;
        assert_eq!(DataBlock::parse(&b), Ok(block));
        b.truncate(10);
        b[2] = 10;
        assert!(DataBlock::parse(&b).is_err());
        for n in [0, 2, 30, 31] {
            let b = DataBlock::ServerNetwork {
                io_channel: 1003,
                channels: vec![1004; n],
            };
            assert_eq!(DataBlock::parse(&b.to_bytes().unwrap()), Ok(b));
        }
    }

    #[test]
    fn monitor_reserved_and_rectangle_refusals() {
        let good = Monitor {
            left: -1280,
            top: 0,
            right: -1,
            bottom: 1023,
            flags: 0,
        };
        let b = DataBlock::ClientMonitor(vec![good]);
        assert_eq!(DataBlock::parse(&b.to_bytes().unwrap()), Ok(b.clone()));
        let mut wire = b.to_bytes().unwrap();
        wire[4] = 1;
        assert!(DataBlock::parse(&wire).is_err());
        assert!(
            DataBlock::ClientMonitor(vec![Monitor {
                left: i32::MAX,
                right: i32::MIN,
                ..good
            }])
            .to_bytes()
            .is_err()
        );
        assert!(
            DataBlock::ClientMonitor(vec![good; MAX_MONITORS + 1])
                .to_bytes()
                .is_err()
        );
        assert!(DataBlock::ClientMonitor(vec![]).to_bytes().is_err());
        assert!(DataBlock::parse(&hex("06 c0 08 00 01 00 00 00")).is_err());
    }

    #[test]
    fn security_block_shapes_and_refusals() {
        let mut b = DataBlock::ServerSecurity {
            encryption_method: 2,
            encryption_level: 2,
            random: vec![0xff; SERVER_RANDOM_LEN],
            certificate: vec![1, 2, 3],
        };
        assert_eq!(DataBlock::parse(&b.to_bytes().unwrap()), Ok(b.clone()));
        if let DataBlock::ServerSecurity { random, .. } = &mut b {
            random.pop();
        }
        assert!(b.to_bytes().is_err());
        b = DataBlock::ServerSecurity {
            encryption_method: 0,
            encryption_level: 0,
            random: vec![],
            certificate: vec![1],
        };
        assert!(b.to_bytes().is_err());
        assert!(
            DataBlock::ServerCore {
                version: 0,
                requested_protocols: None,
                early_capability_flags: Some(0)
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            DataBlock::parse(&hex(
                "02 0c 14 00 02 00 00 00 02 00 00 00 ff ff ff ff ff ff ff ff"
            ))
            .is_err()
        );
    }

    #[test]
    fn mcs_optional_ids_and_refusals() {
        for b in [
            hex("2c 00"),
            hex("2e 10 00 00"),
            hex("2e 00 ff ff"),
            hex("3c 00 00 00 03 eb"),
            hex("3e 00 00 00 03 eb 03 ec"),
            hex("64 00 00 03 eb 71 00"),
            hex("29"),
            hex("65"),
        ] {
            assert!(McsPdu::parse(&b).is_err(), "{b:x?}");
        }
        for id in [0, 1000, 65536, u32::MAX] {
            assert!(
                McsPdu::ChannelJoinRequest {
                    initiator: id,
                    channel_id: 1003
                }
                .to_bytes()
                .is_err()
            );
        }
        assert!(
            McsPdu::AttachUserConfirm {
                result: 0,
                initiator: None
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            McsPdu::ChannelJoinConfirm {
                result: 0,
                initiator: 1001,
                requested: 1003,
                channel_id: Some(1004)
            }
            .to_bytes()
            .is_err()
        );
        for (priority, segmentation, n) in [(4, 3, 0), (1, 4, 0), (1, 3, MAX_PER_LENGTH + 1)] {
            assert!(
                McsPdu::SendData {
                    indication: false,
                    initiator: 1001,
                    channel_id: 1003,
                    priority,
                    segmentation,
                    data: vec![0; n]
                }
                .to_bytes()
                .is_err()
            );
        }
    }

    #[test]
    fn failed_mcs_confirms_refuse_ids() {
        // AttachUserConfirm with result 1 and an initiator.
        assert_eq!(
            McsPdu::parse(&hex("2e 20 00 00")),
            Err(Error::Invalid("attach confirm result"))
        );
        // ChannelJoinConfirm with result 1 and a channel ID.
        assert_eq!(
            McsPdu::parse(&hex("3e 20 00 00 03 eb 03 eb")),
            Err(Error::Invalid("join confirm result"))
        );
        assert!(McsPdu::parse(&hex("2c 20")).is_ok());
        assert!(McsPdu::parse(&hex("3c 20 00 00 03 eb")).is_ok());
    }

    #[test]
    fn mcs_per_length_boundaries() {
        for n in [0, 1, 127, 128, 255, 256, MAX_PER_LENGTH] {
            let p = McsPdu::SendData {
                indication: true,
                initiator: 65535,
                channel_id: 65535,
                priority: 3,
                segmentation: 3,
                data: vec![0x5a; n],
            };
            let b = p.to_bytes().unwrap();
            assert_eq!(McsPdu::parse(&b), Ok(p));
        }
        assert!(McsPdu::parse(&hex("64 00 00 03 eb 70 c0")).is_err());
        // Nonminimal PER lengths are accepted and written canonically.
        let p = McsPdu::parse(&hex("68 00 00 03 eb 70 80 00")).unwrap();
        assert_eq!(p.to_bytes().unwrap(), hex("68 00 00 03 eb 70 00"));
    }

    #[test]
    fn client_info_exact_bytes_and_roundtrip() {
        let b = hex("09 04 00 00 10 00 00 00 00 00 02 00 00 00 00 00 00 00
                     00 00 75 00 00 00 00 00 00 00 00 00");
        assert_eq!(info().to_bytes().unwrap(), b);
        assert_eq!(ClientInfo::parse(&b), Ok(info()));
        let mut p = info();
        p.flags = 0;
        p.code_page = 1252;
        p.user_name = b"user".to_vec();
        p.extra_info = vec![1, 2, 3];
        assert_eq!(ClientInfo::parse(&p.to_bytes().unwrap()), Ok(p));
    }

    #[test]
    fn client_info_refusals_and_limits() {
        let mut p = info();
        p.user_name.push(1);
        assert!(p.to_bytes().is_err());
        p.user_name = vec![0; MAX_INFO_STRING];
        assert!(p.to_bytes().is_err());
        p = info();
        p.extra_info = vec![0; MAX_EXTRA_INFO + 1];
        assert!(p.to_bytes().is_err());
        let mut b = info().to_bytes().unwrap();
        b[10] = 3;
        assert!(ClientInfo::parse(&b).is_err());
        let mut b = info().to_bytes().unwrap();
        b[18] = 1;
        assert!(ClientInfo::parse(&b).is_err());
        let mut b = info().to_bytes().unwrap();
        b[8] = 0xff;
        b[9] = 0xff;
        assert!(ClientInfo::parse(&b).is_err());
        let mut p = info();
        p.domain = vec![0; MAX_INFO_STRING - 2];
        p.extra_info = vec![0; MAX_EXTRA_INFO];
        assert_eq!(ClientInfo::parse(&p.to_bytes().unwrap()), Ok(p));
    }

    #[test]
    fn client_info_string_limits_include_terminator() {
        // MS-RDPBCGR 2.2.1.11.1.1: at most 512 bytes with the terminator.
        for (flags, max) in [(INFO_UNICODE, 510), (0, 511)] {
            for field in 0..5 {
                let mut p = info();
                p.flags = flags;
                p.user_name.clear();
                let s = match field {
                    0 => &mut p.domain,
                    1 => &mut p.user_name,
                    2 => &mut p.password,
                    3 => &mut p.alternate_shell,
                    _ => &mut p.working_dir,
                };
                *s = vec![b'A'; max];
                let wire = p.to_bytes().unwrap();
                assert_eq!(ClientInfo::parse(&wire), Ok(p.clone()));
                let s = match field {
                    0 => &mut p.domain,
                    1 => &mut p.user_name,
                    2 => &mut p.password,
                    3 => &mut p.alternate_shell,
                    _ => &mut p.working_dir,
                };
                s.extend_from_slice(&[b'A'; 2]);
                assert_eq!(p.to_bytes(), Err(Error::Limit("info string")));
            }
        }
        // A Unicode user name of 256 characters is 514 bytes on the wire.
        let mut w = Write::new(MAX_PDU);
        w.le32(0x409).unwrap();
        w.le32(INFO_UNICODE).unwrap();
        for n in [0u16, 512, 0, 0, 0] {
            w.le16(n).unwrap();
        }
        w.put(&[0, 0]).unwrap();
        w.put(&[b'A', 0].repeat(256)).unwrap();
        w.put(&[0; 8]).unwrap();
        assert_eq!(ClientInfo::parse(&w.b), Err(Error::Limit("info string")));
    }

    #[test]
    fn client_info_reserved_flags_are_refused() {
        for bit in [0x0080_0000, 0x0100_0000] {
            let mut p = info();
            p.flags |= bit;
            assert_eq!(p.to_bytes(), Err(Error::Invalid("reserved info flags")));
            let mut wire = info().to_bytes().unwrap();
            wire[4..8].copy_from_slice(&(INFO_UNICODE | bit).to_le_bytes());
            assert_eq!(
                ClientInfo::parse(&wire),
                Err(Error::Invalid("reserved info flags"))
            );
        }
    }

    #[test]
    fn spec_no_license_exact_bytes() {
        let b = hex("ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00");
        assert_eq!(LicenseError::valid_client().to_bytes().unwrap(), b);
        assert_eq!(LicenseError::parse(&b), Ok(LicenseError::valid_client()));
    }

    #[test]
    fn license_refusals_and_blob_roundtrip() {
        let mut p = LicenseError::valid_client();
        p.flags = 0x83;
        p.blob = vec![1, 2, 3];
        assert_eq!(LicenseError::parse(&p.to_bytes().unwrap()), Ok(p.clone()));
        p.flags = 0x13;
        assert!(p.to_bytes().is_err());
        p.flags = 1;
        assert!(p.to_bytes().is_err());
        p.flags = 3;
        p.blob = vec![0; MAX_PDU - 15];
        assert!(p.to_bytes().is_err());
        for offset in [0, 1, 2, 14] {
            let mut b = LicenseError::valid_client().to_bytes().unwrap();
            b[offset] ^= 1;
            // Version 2 is valid, so corrupt it further at the version byte.
            if offset == 1 {
                b[offset] = 1;
            }
            assert!(LicenseError::parse(&b).is_err());
        }
    }

    #[test]
    fn license_error_blob_type_must_be_error_blob() {
        // MS-RDPBCGR 2.2.1.12.1.3: bbErrorInfo is a BB_ERROR_BLOB (4).
        for blob_type in [0, 1, 3, 5, 0xffff] {
            let mut p = LicenseError::valid_client();
            p.blob_type = blob_type;
            assert!(p.to_bytes().is_err());
            let mut wire = LicenseError::valid_client().to_bytes().unwrap();
            wire[12..14].copy_from_slice(&blob_type.to_le_bytes());
            assert_eq!(
                LicenseError::parse(&wire),
                Err(Error::Invalid("license error blob type"))
            );
        }
    }

    #[test]
    fn protected_payload_is_preserved() {
        // MS-RDPBCGR 4.1.11: this licensing message remains encrypted.
        let b = hex("03 00 00 2a 02 f0 80 68 00 01 03 eb 70 1c 88 02
                     02 03 8d 43 9a ab d5 2a 31 39 62 4d c1 ec 0d 99
                     88 e6 da ab 2c 02 72 4d 49 90");
        let (packet, _) = tpkt::Packet::parse(&b).unwrap().unwrap();
        let mcs = McsPdu::parse(&read_data(&packet).unwrap()).unwrap();
        assert_eq!(
            write_data(&mcs.to_bytes().unwrap())
                .unwrap()
                .to_bytes()
                .unwrap(),
            b
        );
        let McsPdu::SendData { data, .. } = mcs else {
            panic!()
        };
        let p = SecurityPayload::parse(&data).unwrap();
        assert_eq!(p.flags, 0x288);
        assert_eq!(p.flags_hi, 0x302);
        assert_eq!(p.to_bytes().unwrap(), data);
        assert!(p.plaintext().is_err());
        for flags in [security_flags::EXCHANGE, security_flags::REDIRECTION] {
            assert!(
                SecurityPayload {
                    flags,
                    flags_hi: 0,
                    data: vec![]
                }
                .plaintext()
                .is_err()
            );
        }
        let p = SecurityPayload {
            flags: security_flags::INFO,
            flags_hi: 0,
            data: info().to_bytes().unwrap(),
        };
        assert_eq!(ClientInfo::parse(p.plaintext().unwrap()), Ok(info()));
        assert!(
            SecurityPayload {
                flags: 0,
                flags_hi: 0,
                data: vec![0; MAX_PDU]
            }
            .to_bytes()
            .is_err()
        );
    }

    #[test]
    fn active_exact_bytes_and_capability_types() {
        let mut p = active(ActiveKind::Demand { session_id: 7 });
        p.source_descriptor = b"RDP\0".to_vec();
        p.padding = 0;
        p.capabilities = vec![CapabilitySet {
            kind: CapabilityType::GENERAL,
            data: vec![1, 2],
        }];
        let bytes = hex("20 00 11 00 ea 03 00 00 01 00 04 00 0a 00
                         52 44 50 00 01 00 00 00 01 00 06 00 01 02 07 00 00 00");
        assert_eq!(p.to_bytes().unwrap(), bytes);
        assert_eq!(ActivePdu::parse(&bytes), Ok(p));
        for kind in [
            ActiveKind::Demand {
                session_id: u32::MAX,
            },
            ActiveKind::Confirm {
                originator_id: 1002,
            },
        ] {
            let p = active(kind);
            assert_eq!(ActivePdu::parse(&p.to_bytes().unwrap()), Ok(p));
        }
    }

    #[test]
    fn confirm_active_originator_is_server_channel() {
        // MS-RDPBCGR 2.2.1.13.2.1: originatorID is 0x03ea.
        let good = active(ActiveKind::Confirm {
            originator_id: SERVER_CHANNEL_ID,
        });
        let wire = good.to_bytes().unwrap();
        assert_eq!(ActivePdu::parse(&wire), Ok(good));
        for id in [0, 1001, 1003, 0xffff] {
            let p = active(ActiveKind::Confirm { originator_id: id });
            assert_eq!(
                p.to_bytes(),
                Err(Error::Invalid("confirm active originator"))
            );
            let mut bad = wire.clone();
            bad[10..12].copy_from_slice(&id.to_le_bytes());
            assert_eq!(
                ActivePdu::parse(&bad),
                Err(Error::Invalid("confirm active originator"))
            );
        }
    }

    #[test]
    fn active_and_capability_refusals() {
        let p = active(ActiveKind::Demand { session_id: 0 });
        for offset in [0, 2, 12, 18, 24] {
            let mut b = p.to_bytes().unwrap();
            b[offset] ^= 0x40;
            assert!(ActivePdu::parse(&b).is_err(), "offset {offset}");
        }
        assert!(CapabilitySet::parse(&[1, 0, 3, 0]).is_err());
        assert!(
            CapabilitySet {
                kind: CapabilityType::GENERAL,
                data: vec![0; MAX_CAPABILITY + 1]
            }
            .to_bytes()
            .is_err()
        );
        let mut p = p;
        p.source_descriptor = vec![0; MAX_DESCRIPTOR + 1];
        assert!(p.to_bytes().is_err());
        p.source_descriptor.clear();
        p.capabilities = vec![
            CapabilitySet {
                kind: CapabilityType(1),
                data: vec![]
            };
            MAX_CAPABILITIES + 1
        ];
        assert!(p.to_bytes().is_err());
        p.capabilities = vec![
            CapabilitySet {
                kind: CapabilityType(1),
                data: vec![0; MAX_CAPABILITY]
            };
            4
        ];
        assert!(p.to_bytes().is_err());
    }

    #[test]
    fn fast_path_lengths_and_detection() {
        for n in [0, 1, 125, 126, 127, 128, 255, 256, MAX_FAST_PATH - 3] {
            for header in [0, 4, 0x3c, 0x80, 0xc0] {
                let f = Frame::FastPath {
                    header,
                    payload: vec![0xab; n],
                };
                let b = f.to_bytes().unwrap();
                assert_eq!(b.len(), n + if n <= 125 { 2 } else { 3 });
                assert_eq!(Frame::parse(&b), Ok(Some((f, b.len()))));
            }
        }
        assert_eq!(
            Frame::parse(&[0, 0x80, 3]),
            Ok(Some((
                Frame::FastPath {
                    header: 0,
                    payload: vec![]
                },
                3
            )))
        );
        assert!(Frame::parse(&[1]).is_err());
        assert!(Frame::parse(&[2]).is_err());
        assert!(Frame::parse(&[0, 1]).is_err());
        assert!(Frame::parse(&[0, 0x80, 2]).is_err());
        assert!(Frame::parse(&[3, 0, 0, 6]).is_err());
        assert!(
            Frame::FastPath {
                header: 3,
                payload: vec![]
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            Frame::FastPath {
                header: 0,
                payload: vec![0; MAX_FAST_PATH - 2]
            }
            .to_bytes()
            .is_err()
        );
    }

    #[test]
    fn data_transport_limits_and_refusals() {
        let b = vec![7; MAX_PDU];
        let p = write_data(&b).unwrap();
        assert_eq!(p.to_bytes().unwrap().len(), MAX_FRAME);
        assert_eq!(read_data(&p), Ok(b));
        assert!(write_data(&vec![0; MAX_PDU + 1]).is_err());
        let mut p = write_data(&[]).unwrap();
        p.payload[2] = 0;
        assert!(read_data(&p).is_err());
        let mut p = write_data(&[]).unwrap();
        p.payload[0] = 3;
        p.payload.push(0);
        assert!(read_data(&p).is_err());
        assert!(read_data(&connection().to_packet().unwrap()).is_err());
        assert!(
            Frame::SlowPath(tpkt::Packet::new(vec![]))
                .to_bytes()
                .is_err()
        );
    }

    #[test]
    fn every_prefix_frame_decoder() {
        let samples = [
            connection().to_packet().unwrap().to_bytes().unwrap(),
            initial_example(),
            response_example(),
            Frame::FastPath {
                header: 0x80,
                payload: vec![0xab; 128],
            }
            .to_bytes()
            .unwrap(),
        ];
        for b in samples {
            contract::check_decode(Frames::new, &b);
            for n in 0..b.len() {
                assert_eq!(Frame::parse(&b[..n]), Ok(None));
            }
            let mut stream = Stream::new(Frames);
            let mut frames = Vec::new();
            pump(&mut stream, &b, |frame| frames.push(frame)).unwrap();
            assert_eq!(frames, [Frame::parse(&b).unwrap().unwrap().0]);
        }
    }

    #[test]
    fn every_prefix_complete_message_parsers() {
        macro_rules! prefixes {
            ($t:ty, $value:expr) => {{
                let b = $value.to_bytes().unwrap();
                for n in 0..b.len() {
                    assert!(
                        <$t>::parse(&b[..n]).is_err(),
                        "{} prefix {n}",
                        stringify!($t)
                    );
                }
            }};
        }
        prefixes!(Negotiation, Negotiation::Failure(FailureCode(1)));
        prefixes!(McsConnect, initial());
        prefixes!(McsConnect, response());
        prefixes!(GccConference, GccConference::Request(client_blocks()));
        for b in client_blocks().into_iter().chain(server_blocks()) {
            prefixes!(DataBlock, b);
        }
        for p in mcspdus() {
            prefixes!(McsPdu, p);
        }
        prefixes!(ClientInfo, info());
        prefixes!(LicenseError, LicenseError::valid_client());
        prefixes!(ActivePdu, active(ActiveKind::Demand { session_id: 0 }));
        prefixes!(
            ActivePdu,
            active(ActiveKind::Confirm {
                originator_id: 1002
            })
        );
        prefixes!(
            CapabilitySet,
            CapabilitySet {
                kind: CapabilityType::BITMAP,
                data: vec![0; 24]
            }
        );
        // SecurityPayload and opaque Info suffixes need an external boundary.
        for n in 0..4 {
            assert!(SecurityPayload::parse(&[0; 4][..n]).is_err());
        }
    }

    #[test]
    fn streaming_backpressure_and_terminal_error() {
        let bytes = [0, 2].repeat(MAX_FRAME);
        contract::check_decode(Frames::new, &bytes);
        let mut stream = Stream::new(Frames);
        let mut count = 0;
        pump(&mut stream, &bytes, |_| count += 1).unwrap();
        assert_eq!(count, MAX_FRAME);
        assert_eq!(stream.buffered(), 0);
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&bytes), MAX_FRAME);
        assert_eq!(stream.push(&[0]), 0);
        while let Some(frame) = stream.next() {
            frame.unwrap();
        }
        assert!(stream.buffered() <= 1);
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&[1]), 1);
        let error = Fail::Protocol(Error::Invalid("fast-path action"));
        assert_eq!(stream.next(), Some(Err(error)));
        assert!(stream.next().is_none());
        assert_eq!(stream.push(&bytes), bytes.len());
    }

    #[test]
    fn maximum_frames_bytewise_and_mixed_stream() {
        let f = Frame::SlowPath(write_data(&vec![0; MAX_PDU]).unwrap());
        let b = f.to_bytes().unwrap();
        contract::check_decode(Frames::new, &b);
        let mut stream = Stream::new(Frames);
        let mut frames = Vec::new();
        pump(&mut stream, &b, |frame| frames.push(frame)).unwrap();
        assert_eq!(frames, [f]);
        let mut b = connection().to_packet().unwrap().to_bytes().unwrap();
        b.extend_from_slice(
            &Frame::FastPath {
                header: 0xc0,
                payload: vec![1; 130],
            }
            .to_bytes()
            .unwrap(),
        );
        b.extend_from_slice(&write_data(&[0x28]).unwrap().to_bytes().unwrap());
        contract::check_decode(Frames::new, &b);
        let mut stream = Stream::new(Frames);
        let mut frames = Vec::new();
        pump(&mut stream, &b, |frame| frames.push(frame)).unwrap();
        assert_eq!(frames.len(), 3);
    }

    #[test]
    fn all_mcs_confirmation_results_use_packed_per_bits() {
        // T.125: a six-bit choice, one optional-field bit, a four-bit
        // Result, then five zero padding bits before the next integer.
        for result in 0..=15 {
            for present in [false, true] {
                if (result == 0) != present {
                    // T.125 11.18 and 11.22: the ID is present if and only
                    // if the result is successful.
                    let p = McsPdu::AttachUserConfirm {
                        result,
                        initiator: present.then_some(1001),
                    };
                    assert!(p.to_bytes().is_err());
                    let p = McsPdu::ChannelJoinConfirm {
                        result,
                        initiator: 1001,
                        requested: 1003,
                        channel_id: present.then_some(1003),
                    };
                    assert!(p.to_bytes().is_err());
                    continue;
                }
                let p = McsPdu::AttachUserConfirm {
                    result,
                    initiator: present.then_some(1001),
                };
                let mut expected = vec![
                    0x2c | (u8::from(present) << 1) | (result >> 3),
                    (result & 7) << 5,
                ];
                if present {
                    expected.extend_from_slice(&[0, 0]);
                }
                assert_eq!(p.to_bytes().unwrap(), expected);
                assert_eq!(McsPdu::parse(&expected), Ok(p));
                expected[1] |= 1;
                assert!(McsPdu::parse(&expected).is_err());
                let p = McsPdu::ChannelJoinConfirm {
                    result,
                    initiator: 1001,
                    requested: 1003,
                    channel_id: present.then_some(1003),
                };
                let mut expected = vec![
                    0x3c | (u8::from(present) << 1) | (result >> 3),
                    (result & 7) << 5,
                    0,
                    0,
                    3,
                    0xeb,
                ];
                if present {
                    expected.extend_from_slice(&[3, 0xeb]);
                }
                assert_eq!(p.to_bytes().unwrap(), expected);
                assert_eq!(McsPdu::parse(&expected), Ok(p));
            }
        }
    }

    #[test]
    fn per_signed_conference_tags() {
        for (tag, bytes) in [
            (0, "01 00"),
            (127, "01 7f"),
            (128, "02 00 80"),
            (-1, "01 ff"),
            (-128, "01 80"),
            (-129, "02 ff 7f"),
            (i32::MIN, "04 80 00 00 00"),
        ] {
            let mut w = Write::new(MAX_PDU);
            w.per_signed(tag).unwrap();
            assert_eq!(w.b, hex(bytes));
            assert_eq!(Read::new(&w.b).per_signed(), Ok(tag));
        }
        assert!(Read::new(&[0]).per_signed().is_err());
        assert!(Read::new(&[5, 0, 0, 0, 0, 0]).per_signed().is_err());
    }

    #[test]
    fn one_byte_routing_tokens_are_refused() {
        // libFuzzer regression: None == checked_sub(2) must not allow a
        // one-byte token to masquerade as a CRLF-terminated string.
        for byte in 0..=255 {
            let mut c = connection();
            c.routing_token = vec![byte];
            assert!(c.to_packet().is_err());
        }
    }

    #[test]
    fn exact_gcc_aggregate_limits() {
        let p = GccConference::Request(vec![DataBlock::Other {
            kind: 0xf001,
            data: vec![0; MAX_GCC_REQUEST - 27],
        }]);
        let b = p.to_bytes().unwrap();
        assert_eq!(b.len(), MAX_GCC_REQUEST);
        assert_eq!(GccConference::parse(&b), Ok(p));
        let p = GccConference::Request(vec![DataBlock::Other {
            kind: 0xf001,
            data: vec![0; MAX_GCC_REQUEST - 26],
        }]);
        assert!(p.to_bytes().is_err());
        let block = DataBlock::Other {
            kind: 0xf001,
            data: vec![0; MAX_GCC_DATA - 4],
        };
        let p = GccConference::Response {
            node_id: 65536,
            tag: i32::MAX,
            result: 4,
            blocks: vec![block],
        };
        let b = p.to_bytes().unwrap();
        assert!(b.len() <= MAX_GCC_RESPONSE);
        assert_eq!(GccConference::parse(&b), Ok(p));
    }

    #[test]
    fn malformed_nested_gcc_and_ber_fields() {
        let good = GccConference::Response {
            node_id: 1001,
            tag: 1,
            result: 0,
            blocks: vec![],
        }
        .to_bytes()
        .unwrap();
        for (offset, value) in [
            (0, 1),
            (8, 0xff),
            (9, 0xff),
            (13, 0x80),
            (13, 0x50),
            (14, 2),
            (15, 0),
            (17, b'X'),
        ] {
            let mut bad = good.clone();
            bad[offset] = value;
            assert!(GccConference::parse(&bad).is_err(), "offset {offset}");
        }
        let mut w = Write::new(MAX_PDU);
        w.ber(&[4], &[1]).unwrap();
        w.ber(&[4], &[1]).unwrap();
        w.ber(&[1], &[]).unwrap();
        let mut outer = Write::new(MAX_PDU);
        outer.ber(&[0x7f, 0x65], &w.b).unwrap();
        assert_eq!(
            McsConnect::parse(&outer.b),
            Err(Error::Invalid("BER Boolean"))
        );
        assert!(DomainParameters::read(&mut Read::new(&[0x30, 0])).is_err());
        let mut w = Write::new(MAX_PDU);
        params().write(&mut w).unwrap();
        w.b[1] += 1;
        w.b.push(0);
        assert!(DomainParameters::read(&mut Read::new(&w.b)).is_err());
    }

    #[test]
    fn correlation_reserved_bytes_and_presence() {
        let mut c = connection();
        c.negotiation = Some(Negotiation::Request {
            flags: 8,
            protocols: Protocols(3),
        });
        c.correlation_id = Some([0; CORRELATION_ID_LEN]);
        let p = c.to_packet().unwrap();
        for offset in [15, 16, 17, 35, 50] {
            let mut bad = p.clone();
            bad.payload[offset] ^= 1;
            assert!(Connection::from_packet(&bad).is_err());
        }
        for n in 0..p.payload.len() {
            let mut bad = p.clone();
            bad.payload.truncate(n);
            assert!(Connection::from_packet(&bad).is_err());
        }
    }

    #[test]
    fn lcg_fuzz_roundtrips_and_streaming() {
        let mut rng = Lcg::new(0x726470);
        let mut seeds = vec![
            initial_example(),
            response_example(),
            initial().to_bytes().unwrap(),
            response().to_bytes().unwrap(),
            info().to_bytes().unwrap(),
            LicenseError::valid_client().to_bytes().unwrap(),
            active(ActiveKind::Demand { session_id: 7 })
                .to_bytes()
                .unwrap(),
            active(ActiveKind::Confirm {
                originator_id: 1002,
            })
            .to_bytes()
            .unwrap(),
            GccConference::Request(client_blocks()).to_bytes().unwrap(),
            connection().to_packet().unwrap().to_bytes().unwrap(),
        ];
        for b in client_blocks().into_iter().chain(server_blocks()) {
            seeds.push(b.to_bytes().unwrap());
        }
        for p in mcspdus() {
            seeds.push(p.to_bytes().unwrap());
        }
        for _ in 0..2500 {
            let n = rng.next() as usize % 512;
            let random: Vec<_> = (0..n).map(|_| rng.next() as u8).collect();
            check_parsers(&random);
            contract::check_decode(Frames::new, &random);
            let mut b = seeds[rng.next() as usize % seeds.len()].clone();
            for _ in 0..(rng.next() % 4) {
                let i = rng.next() as usize % b.len();
                b[i] ^= rng.next() as u8;
            }
            check_parsers(&b);
            contract::check_decode(Frames::new, &b);
        }
    }
}
