//! IPsec: reading and writing ESP and AH headers, with no I/O.
//!
//! IPsec protects IP packets with keys two hosts agree on, usually through
//! IKE. It adds one of two headers. ESP (the Encapsulating Security
//! Payload, IP protocol 50) encrypts what it carries: after a 4-byte SPI,
//! which names the security association, and a 4-byte sequence number,
//! everything is ciphertext and an integrity check value (the ICV). AH
//! (the Authentication Header, IP protocol 51) only signs: it carries the
//! SPI, the sequence number and the ICV in a header of its own, and the
//! packet it protects follows in the clear. When a NAT sits between the
//! hosts, ESP rides inside UDP on port 4500, next to the IKE messages and
//! one-byte keepalives that share the port. This module follows RFC 4303
//! (ESP), RFC 4302 (AH) and RFC 3948 (UDP encapsulation of ESP).
//!
//! Nothing here reads a socket, and nothing here encrypts, decrypts or
//! checks an ICV. A world that plays a VPN gateway hands the payload of
//! each IP packet of protocol [`ESP_PROTOCOL`] or [`AH_PROTOCOL`], or of
//! each UDP datagram to port [`NAT_T_PORT`], to [`EspPacket::parse`],
//! [`AhPacket::parse`] or [`Datagram::parse`]. It finds its keys by the
//! SPI. Once world code has decrypted an ESP payload (or the algorithm is
//! NULL encryption, from RFC 2410, which leaves it as it is),
//! [`Plaintext::parse`] reads the trailer: the padding, the pad length and
//! the next header. To send, it builds the same values and writes their
//! bytes through [`Wire::write`]. For pieces of one packet, use
//! [`Stream<Frames>`](super::codec::Stream), with `Frames = Collect<EspPacket>`,
//! `Collect<AhPacket>`, or `Collect<Datagram>`. Set the limit to [`MAX_PACKET`]
//! for IP payloads or [`MAX_DATAGRAM`] for UDP. Call `end` at that boundary.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. An SPI of zero is refused, since RFC 4303 and RFC 4302 forbid
//! it on the wire. So is an AH payload length too short for the fixed
//! fields, and a pad length longer than the plaintext. The AH reserved
//! field is kept as read, since RFC 4302 has it count in the ICV, and is
//! zero in every header a world builds with [`AhHeader::new`]. The AH
//! ICV field can end in padding after the algorithm's tag, which also
//! counts in the ICV as sent, so [`AhHeader::for_icv`] takes the
//! tag's length and zeroes only the tag.
//! Writers refuse what a reader would refuse, so bytes they return always
//! read back.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::ipsec::{next_header, Datagram, EspPacket, Plaintext};
//!
//! // An IPv4 packet (cut short here), padded to a 4-byte boundary with
//! // the default padding: 1, 2, and so on.
//! let plain = Plaintext::padded(b"ping".to_vec(), next_header::IPV4, 4).unwrap();
//! assert_eq!(plain.to_bytes().unwrap(), [b'p', b'i', b'n', b'g', 1, 2, 2, 4]);
//!
//! // With NULL encryption and no ICV, the plaintext is the ESP payload.
//! let esp = EspPacket { spi: 0x1000, sequence: 1, payload: plain.to_bytes().unwrap() };
//! let bytes = Datagram::Esp(esp).to_bytes().unwrap();
//! assert_eq!(&bytes[..8], [0, 0, 0x10, 0, 0, 0, 0, 1]);
//!
//! // A gateway on UDP port 4500 tells ESP from IKE and keepalives.
//! match Datagram::parse(&bytes).unwrap() {
//!     Datagram::Esp(p) => {
//!         assert_eq!(p.spi, 0x1000);
//!         let back = Plaintext::parse(&p.payload).unwrap();
//!         assert_eq!(back.data, b"ping");
//!         assert_eq!(back.next_header, next_header::IPV4);
//!         assert!(back.has_default_padding());
//!     }
//!     other => panic!("not ESP: {other:?}"),
//! }
//! assert_eq!(Datagram::parse(&[0xff]), Ok(Datagram::Keepalive));
//! assert_eq!(Datagram::parse(&[0, 0, 0, 0, 1]), Ok(Datagram::Ike(vec![1])));
//! ```

use super::codec::Wire;

/// The IP protocol number that marks an ESP packet.
pub const ESP_PROTOCOL: u8 = 50;
/// The IP protocol number that marks an AH packet.
pub const AH_PROTOCOL: u8 = 51;
/// The UDP port that carries ESP through a NAT, shared with IKE.
pub const NAT_T_PORT: u16 = 4500;
/// The length of the ESP header: the SPI and the sequence number.
pub const ESP_HEADER_LEN: usize = 8;
/// The length of the ESP trailer's fixed part: the pad length and the
/// next header.
pub const ESP_TRAILER_LEN: usize = 2;
/// The shortest ESP packet: the header, and at least the trailer's two
/// bytes after it, encrypted or not.
pub const MIN_ESP_LEN: usize = ESP_HEADER_LEN + ESP_TRAILER_LEN;
/// The length of the AH header's fixed fields: next header, payload
/// length, reserved, SPI and sequence number.
pub const AH_FIXED_LEN: usize = 12;
/// The longest AH header: a payload length of 255 means 257 32-bit words.
pub const MAX_AH_LEN: usize = (255 + 2) * 4;
/// The longest ICV an AH header can hold.
pub const MAX_ICV: usize = MAX_AH_LEN - AH_FIXED_LEN;
/// The most padding bytes an ESP trailer can hold, since the pad length
/// is one byte.
pub const MAX_PADDING: usize = 255;
/// The largest block size [`Plaintext::padded`] pads to.
pub const MAX_BLOCK_SIZE: usize = 256;
/// The longest ESP or AH packet, or plaintext, this module reads or
/// writes: the most an IPv4 total length or an IPv6 payload length field
/// allows.
pub const MAX_PACKET: usize = 65535;
/// The longest UDP payload, and so the longest [`Datagram`], this module
/// reads or writes: 65535 bytes less the 8-byte UDP header. Over IPv6 a
/// datagram this long can be sent.
pub const MAX_DATAGRAM: usize = MAX_PACKET - 8;
/// The longest UDP payload that fits in one IPv4 packet: [`MAX_DATAGRAM`]
/// less the 20-byte IPv4 header. [`Datagram::fits_ipv4`] checks it.
pub const MAX_DATAGRAM_IPV4: usize = MAX_DATAGRAM - 20;
/// The one byte of a NAT keepalive datagram, from RFC 3948, section 2.3.
pub const KEEPALIVE: u8 = 0xff;
/// The four zero bytes that start an IKE message on port 4500, where an
/// ESP packet would have its SPI. From RFC 3948, section 2.2.
pub const NON_ESP_MARKER: [u8; 4] = [0; 4];

/// Next header values: the IP protocol number of what ESP or AH protects.
pub mod next_header {
    /// An IPv4 packet, in tunnel mode.
    pub const IPV4: u8 = 4;
    /// A TCP segment, in transport mode.
    pub const TCP: u8 = 6;
    /// A UDP datagram, in transport mode.
    pub const UDP: u8 = 17;
    /// An IPv6 packet, in tunnel mode.
    pub const IPV6: u8 = 41;
    /// An ESP packet, as when AH protects ESP.
    pub const ESP: u8 = 50;
    /// An ICMPv6 message, in transport mode.
    pub const ICMPV6: u8 = 58;
    /// No next header. In ESP it marks a dummy packet, sent to hide
    /// traffic patterns, which the receiver drops (RFC 4303, section 2.6).
    pub const NONE: u8 = 59;
}

/// Why bytes are not a packet this module reads, or why a value cannot be
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpsecError {
    /// The bytes end before the packet does. Writers return it for an ESP
    /// payload shorter than the trailer's two bytes.
    Truncated,
    /// Bytes follow a standalone AH header.
    Trailing {
        /// Number of bytes after the AH header.
        remaining: usize,
    },
    /// The bytes are longer than [`MAX_PACKET`], or a datagram is longer
    /// than [`MAX_DATAGRAM`].
    TooLong,
    /// The SPI is zero, which RFC 4303 and RFC 4302 reserve for local use
    /// and forbid on the wire.
    ZeroSpi,
    /// The AH payload length field is zero: too short for the fixed fields.
    AhLength(u8),
    /// An AH ICV of this many bytes cannot be written: it must be a
    /// multiple of 4, and no longer than [`MAX_ICV`].
    IcvLength(usize),
    /// The ESP pad length says there are more padding bytes than the
    /// plaintext holds.
    PadLength(u8),
    /// An ESP trailer with this many padding bytes cannot be written: the
    /// most is [`MAX_PADDING`]. [`Plaintext::padded`] returns it for a
    /// block size that would need more.
    Padding(usize),
    /// [`Plaintext::padded`] was asked for a block size of zero, or above
    /// [`MAX_BLOCK_SIZE`].
    BlockSize(usize),
}

impl std::fmt::Display for IpsecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecError::Trailing { remaining } => {
                write!(f, "{remaining} bytes after the AH header")
            }
            IpsecError::Truncated => f.write_str("bytes end inside the IPsec packet"),
            IpsecError::TooLong => write!(f, "IPsec packet longer than {MAX_PACKET} bytes"),
            IpsecError::ZeroSpi => f.write_str("SPI of zero"),
            IpsecError::AhLength(n) => write!(f, "AH payload length {n}, below 1"),
            IpsecError::IcvLength(n) => write!(f, "AH ICV of {n} bytes, not a multiple of 4 up to {MAX_ICV}"),
            IpsecError::PadLength(n) => write!(f, "ESP pad length {n}, longer than the plaintext"),
            IpsecError::Padding(n) => write!(f, "{n} ESP padding bytes, above {MAX_PADDING}"),
            IpsecError::BlockSize(n) => write!(f, "block size {n}, outside 1..={MAX_BLOCK_SIZE}"),
        }
    }
}

impl std::error::Error for IpsecError {}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// One ESP packet: the header's fields and the bytes after them. The
/// payload holds whatever the algorithm puts there: an IV if it uses one,
/// the encrypted data and trailer, and the ICV. Only world code, which
/// knows the algorithm, can tell them apart.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EspPacket {
    /// The Security Parameters Index: which security association, and so
    /// which keys, the packet uses. Never zero.
    pub spi: u32,
    /// The low 32 bits of the sender's packet counter, which starts at 1.
    /// A receiver uses it to refuse replayed packets.
    pub sequence: u32,
    /// Everything after the header. At least [`ESP_TRAILER_LEN`] bytes.
    pub payload: Vec<u8>,
}

impl EspPacket {
    /// Splits the payload into the part before the ICV and the ICV of
    /// `icv_len` bytes, which the algorithm fixes. It fails with
    /// [`IpsecError::Truncated`] if that leaves fewer than
    /// [`ESP_TRAILER_LEN`] bytes before the ICV.
    pub fn split_icv(&self, icv_len: usize) -> Result<(&[u8], &[u8]), IpsecError> {
        let rest = self.payload.len().checked_sub(icv_len).ok_or(IpsecError::Truncated)?;
        if rest < ESP_TRAILER_LEN {
            return Err(IpsecError::Truncated);
        }
        Ok(self.payload.split_at(rest))
    }
}

/// The error the first bytes of an ESP packet already show, if any.
fn esp_prefix_error(b: &[u8]) -> Option<IpsecError> {
    (b.len() >= 4 && be32(b, 0) == 0).then_some(IpsecError::ZeroSpi)
}

/// The decrypted part of an ESP payload: the data, the padding, the pad
/// length and the next header, in that order (RFC 4303, section 2). The
/// pad length is worked out from the padding, so it is not kept. Any IV
/// and ICV are not part of it; world code removes them when it decrypts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Plaintext {
    /// The protected packet or segment. Traffic flow confidentiality
    /// padding, if the sender added any, is part of it, since only the
    /// inner packet's own length can tell where it ends.
    pub data: Vec<u8>,
    /// The padding bytes, at most [`MAX_PADDING`].
    pub padding: Vec<u8>,
    /// The IP protocol number of the data, from [`next_header`].
    pub next_header: u8,
}

impl Plaintext {
    /// The plaintext for `data`, with the default padding of RFC 4303,
    /// section 2.4 (the bytes 1, 2, 3, and so on), just long enough that
    /// the whole is a multiple of `block_size` bytes and of 4 bytes. RFC
    /// 4303 asks for both: a multiple of the cipher's block size, and a
    /// multiple of 4 whatever the cipher, so that an ICV after it starts
    /// on a 4-byte boundary. For NULL encryption, pass a block size of 1.
    /// Any IV the algorithm puts before the ciphertext must keep that
    /// boundary too; the usual ones, of 8 or 16 bytes, do.
    ///
    /// It fails with [`IpsecError::BlockSize`] for a block size of 0 or
    /// above [`MAX_BLOCK_SIZE`], with [`IpsecError::Padding`] if the
    /// padding would be longer than [`MAX_PADDING`] (only a block size
    /// above 64 that is not a multiple of 4 can need that), and with [`IpsecError::TooLong`] if
    /// the whole would be longer than [`MAX_PACKET`].
    pub fn padded(data: Vec<u8>, next_header: u8, block_size: usize) -> Result<Plaintext, IpsecError> {
        if block_size == 0 || block_size > MAX_BLOCK_SIZE {
            return Err(IpsecError::BlockSize(block_size));
        }
        if data.len() > MAX_PACKET {
            return Err(IpsecError::TooLong);
        }
        // The least common multiple of the block size and 4.
        let align = match block_size % 4 {
            0 => block_size,
            2 => block_size * 2,
            _ => block_size * 4,
        };
        let used = (data.len() + ESP_TRAILER_LEN) % align;
        let pad = (align - used) % align;
        if pad > MAX_PADDING {
            return Err(IpsecError::Padding(pad));
        }
        let padding = (1..=pad).map(|i| i as u8).collect();
        let p = Plaintext { data, padding, next_header };
        if p.len() > MAX_PACKET {
            return Err(IpsecError::TooLong);
        }
        Ok(p)
    }

    /// Whether the padding is the default one: 1, 2, 3, and so on. A
    /// receiver using an algorithm with no padding rules of its own should
    /// check it (RFC 4303, section 2.4).
    pub fn has_default_padding(&self) -> bool {
        self.padding.iter().enumerate().all(|(i, &b)| usize::from(b) == i + 1)
    }

    /// How many bytes the plaintext takes.
    pub fn len(&self) -> usize {
        self.data.len().saturating_add(self.padding.len()).saturating_add(ESP_TRAILER_LEN)
    }

    /// Whether the plaintext takes no bytes. It never does: the trailer
    /// always takes two.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// An AH header. The payload length is not kept: it is worked out from
/// the ICV.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AhHeader {
    /// The IP protocol number of what follows the header, from
    /// [`next_header`].
    pub next_header: u8,
    /// The reserved field. A sender must set it to zero. A receiver
    /// ignores it, except that its value is part of the ICV computation
    /// (RFC 4302, section 2.3), so it is kept as read and written as is.
    pub reserved: u16,
    /// The Security Parameters Index, as in ESP. Never zero.
    pub spi: u32,
    /// The low 32 bits of the sender's packet counter, as in ESP.
    pub sequence: u32,
    /// The whole ICV field: the integrity check value (the tag), whose
    /// length the algorithm fixes, then any padding the sender added to
    /// keep the header a multiple of 4 bytes (8 in IPv6). A multiple of 4
    /// bytes, at most [`MAX_ICV`]. [`AhHeader::split_icv`] tells the tag
    /// from the padding.
    pub icv: Vec<u8>,
}

impl AhHeader {
    /// A header with the reserved field set to zero, as a sender must.
    pub fn new(next_header: u8, spi: u32, sequence: u32, icv: Vec<u8>) -> AhHeader {
        AhHeader { next_header, reserved: 0, spi, sequence, icv }
    }

    /// Reads the AH header at the start of `b`, and returns it and its
    /// length in bytes.
    pub fn parse_prefix(b: &[u8]) -> Result<(AhHeader, usize), IpsecError> {
        if let Some(e) = ah_prefix_error(b) {
            return Err(e);
        }
        if b.len() < 2 {
            return Err(IpsecError::Truncated);
        }
        let len = (usize::from(b[1]) + 2) * 4;
        if b.len() < len {
            return Err(IpsecError::Truncated);
        }
        let header = AhHeader {
            next_header: b[0],
            reserved: u16::from_be_bytes([b[2], b[3]]),
            spi: be32(b, 4),
            sequence: be32(b, 8),
            icv: b[AH_FIXED_LEN..len].to_vec(),
        };
        Ok((header, len))
    }

    /// How many bytes the header takes.
    pub fn len(&self) -> usize {
        AH_FIXED_LEN.saturating_add(self.icv.len())
    }

    /// Whether the header takes no bytes. It never does.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether the header's length is a multiple of 8 bytes, as RFC 4302
    /// asks of AH in IPv6. In IPv4 a multiple of 4 is enough, and every
    /// header this module writes is one.
    pub fn is_ipv6_aligned(&self) -> bool {
        self.len().is_multiple_of(8)
    }

    fn check(&self) -> Result<(), IpsecError> {
        if self.spi == 0 {
            return Err(IpsecError::ZeroSpi);
        }
        if !self.icv.len().is_multiple_of(4) || self.icv.len() > MAX_ICV {
            return Err(IpsecError::IcvLength(self.icv.len()));
        }
        Ok(())
    }

    /// Splits the ICV field into the tag of `tag_len` bytes, which the
    /// algorithm fixes, and the padding after it. It fails with
    /// [`IpsecError::Truncated`] if the field is shorter than the tag.
    pub fn split_icv(&self, tag_len: usize) -> Result<(&[u8], &[u8]), IpsecError> {
        if tag_len > self.icv.len() {
            return Err(IpsecError::Truncated);
        }
        Ok(self.icv.split_at(tag_len))
    }

    /// Prepares the header for its ICV calculation (RFC 4302, section 3.3.3).
    /// Zeros the first `tag_len` ICV bytes. Preserves the reserved field and
    /// padding after the tag. Refuses an invalid header or a tag longer than
    /// the ICV field. Serialize the returned header with [`Wire::write`].
    pub fn for_icv(&self, tag_len: usize) -> Result<AhHeader, IpsecError> {
        self.check()?;
        self.split_icv(tag_len)?;
        let mut header = self.clone();
        header.icv[..tag_len].fill(0);
        Ok(header)
    }
}

/// The error the first bytes of an AH header already show, if any.
fn ah_prefix_error(b: &[u8]) -> Option<IpsecError> {
    if b.len() >= 2 && b[1] == 0 {
        return Some(IpsecError::AhLength(0));
    }
    (b.len() >= 8 && be32(b, 4) == 0).then_some(IpsecError::ZeroSpi)
}

/// One AH packet: the header and the packet it protects, which follows in
/// the clear.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AhPacket {
    /// The AH header.
    pub header: AhHeader,
    /// The protected packet, of the type `header.next_header` names.
    pub payload: Vec<u8>,
}

impl AhPacket {
    /// Reads the AH header at the start of `b`, and returns it with the
    /// rest of `b`, without copying the payload. It checks what
    /// [`AhPacket::parse`] checks.
    pub fn split(b: &[u8]) -> Result<(AhHeader, &[u8]), IpsecError> {
        if let Some(e) = ah_prefix_error(b) {
            return Err(e);
        }
        if b.len() > MAX_PACKET {
            return Err(IpsecError::TooLong);
        }
        let (header, used) = AhHeader::parse_prefix(b)?;
        Ok((header, &b[used..]))
    }
}

/// One UDP datagram on port [`NAT_T_PORT`], as RFC 3948 sorts them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Datagram {
    /// A NAT keepalive: the one byte [`KEEPALIVE`], sent to keep a NAT's
    /// mapping open. The receiver drops it.
    Keepalive,
    /// An IKE message, after the [`NON_ESP_MARKER`]. The marker is not
    /// kept.
    Ike(Vec<u8>),
    /// An ESP packet, which starts right at the UDP payload.
    Esp(EspPacket),
}

impl Datagram {
    /// Whether the datagram's UDP payload fits in one IPv4 packet: at most
    /// [`MAX_DATAGRAM_IPV4`] bytes.
    pub fn fits_ipv4(&self) -> bool {
        self.wire_len() <= MAX_DATAGRAM_IPV4
    }

    /// How many bytes the UDP payload takes.
    fn wire_len(&self) -> usize {
        match self {
            Datagram::Keepalive => 1,
            Datagram::Ike(m) => NON_ESP_MARKER.len().saturating_add(m.len()),
            Datagram::Esp(p) => ESP_HEADER_LEN.saturating_add(p.payload.len()),
        }
    }
}

impl Wire for EspPacket {
    type ParseError = IpsecError;
    type WriteError = IpsecError;

    /// Reads the ESP packet that fills `b`.
    /// Refuses a zero SPI, fewer than [`MIN_ESP_LEN`] bytes, or more than
    /// [`MAX_PACKET`] bytes.
    fn parse(b: &[u8]) -> Result<Self, IpsecError> {
        if let Some(e) = esp_prefix_error(b) {
            return Err(e);
        }
        if b.len() > MAX_PACKET {
            return Err(IpsecError::TooLong);
        }
        if b.len() < MIN_ESP_LEN {
            return Err(IpsecError::Truncated);
        }
        Ok(EspPacket { spi: be32(b, 0), sequence: be32(b, 4), payload: b[ESP_HEADER_LEN..].to_vec() })
    }

    /// The packet's bytes: the SPI, the sequence number and the payload.
    /// It fails with [`IpsecError::ZeroSpi`] for an SPI of zero, with
    /// [`IpsecError::Truncated`] for a payload shorter than
    /// [`ESP_TRAILER_LEN`], and with [`IpsecError::TooLong`] if the packet
    /// would be longer than [`MAX_PACKET`].
    /// Leaves the destination unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), IpsecError> {
        if self.spi == 0 {
            return Err(IpsecError::ZeroSpi);
        }
        if self.payload.len() < ESP_TRAILER_LEN {
            return Err(IpsecError::Truncated);
        }
        if self.payload.len() > MAX_PACKET - ESP_HEADER_LEN {
            return Err(IpsecError::TooLong);
        }
        out.reserve(ESP_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.spi.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl Wire for Plaintext {
    type ParseError = IpsecError;
    type WriteError = IpsecError;

    /// Reads the plaintext that fills `b`, from its last two bytes back.
    /// Refuses a missing trailer, padding beyond the slice, or more than
    /// [`MAX_PACKET`] bytes.
    fn parse(b: &[u8]) -> Result<Self, IpsecError> {
        if b.len() > MAX_PACKET {
            return Err(IpsecError::TooLong);
        }
        let Some(body) = b.len().checked_sub(ESP_TRAILER_LEN) else {
            return Err(IpsecError::Truncated);
        };
        let pad_len = b[body];
        let Some(data_len) = body.checked_sub(usize::from(pad_len)) else {
            return Err(IpsecError::PadLength(pad_len));
        };
        Ok(Plaintext { data: b[..data_len].to_vec(), padding: b[data_len..body].to_vec(), next_header: b[body + 1] })
    }

    /// The plaintext's bytes, ready for world code to encrypt. It fails
    /// with [`IpsecError::Padding`] for more than [`MAX_PADDING`] padding
    /// bytes, and with [`IpsecError::TooLong`] if the whole would be longer
    /// than [`MAX_PACKET`].
    /// Leaves the destination unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), IpsecError> {
        if self.padding.len() > MAX_PADDING {
            return Err(IpsecError::Padding(self.padding.len()));
        }
        if self.len() > MAX_PACKET {
            return Err(IpsecError::TooLong);
        }
        out.reserve(self.len());
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.padding);
        out.push(self.padding.len() as u8);
        out.push(self.next_header);
        Ok(())
    }
}

impl Wire for AhPacket {
    type ParseError = IpsecError;
    type WriteError = IpsecError;

    /// Reads the AH packet that fills `b`.
    /// Refuses a zero SPI, an invalid AH length, truncation, or more than
    /// [`MAX_PACKET`] bytes.
    fn parse(b: &[u8]) -> Result<Self, IpsecError> {
        let (header, payload) = AhPacket::split(b)?;
        Ok(AhPacket { header, payload: payload.to_vec() })
    }

    /// Appends an AH packet. Refuses a zero SPI, an ICV length that is not
    /// a multiple of four or exceeds [`MAX_ICV`], or a packet above
    /// [`MAX_PACKET`]. Leaves the destination unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), IpsecError> {
        self.header.check()?;
        let total = self.header.len().saturating_add(self.payload.len());
        if total > MAX_PACKET {
            return Err(IpsecError::TooLong);
        }
        out.reserve(total);
        self.header.write(out)?;
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl Wire for Datagram {
    type ParseError = IpsecError;
    type WriteError = IpsecError;

    /// Reads the datagram whose UDP payload is `b`. Refuses truncation
    /// and an ESP packet with a zero SPI. Returns [`IpsecError::TooLong`]
    /// for more than [`MAX_DATAGRAM`] bytes.
    fn parse(b: &[u8]) -> Result<Self, IpsecError> {
        if b == [KEEPALIVE] {
            return Ok(Datagram::Keepalive);
        }
        if b.len() > MAX_DATAGRAM {
            return Err(IpsecError::TooLong);
        }
        if b.len() < NON_ESP_MARKER.len() {
            return Err(IpsecError::Truncated);
        }
        if b[..4] == NON_ESP_MARKER {
            return Ok(Datagram::Ike(b[4..].to_vec()));
        }
        EspPacket::parse(b).map(Datagram::Esp)
    }

    /// Appends a NAT-T datagram. Refuses datagrams above [`MAX_DATAGRAM`]
    /// and ESP packets with a zero SPI or a short trailer. A datagram may
    /// still exceed an IPv4 payload; see [`Self::fits_ipv4`].
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), IpsecError> {
        if self.wire_len() > MAX_DATAGRAM {
            return Err(IpsecError::TooLong);
        }
        match self {
            Self::Keepalive => out.push(KEEPALIVE),
            Self::Ike(message) => {
                out.extend_from_slice(&NON_ESP_MARKER);
                out.extend_from_slice(message);
            }
            Self::Esp(packet) => packet.write(out)?,
        }
        Ok(())
    }
}

impl Wire for AhHeader {
    type ParseError = IpsecError;
    type WriteError = IpsecError;

    /// Reads a standalone AH header. Refuses a zero SPI, an invalid length,
    /// truncation, and bytes after the header.
    fn parse(b: &[u8]) -> Result<Self, IpsecError> {
        let (header, used) = Self::parse_prefix(b)?;
        if used != b.len() {
            return Err(IpsecError::Trailing {
                remaining: b.len() - used,
            });
        }
        Ok(header)
    }

    /// Appends a header. Refuses a zero SPI or an ICV whose length is not
    /// a multiple of four or exceeds [`MAX_ICV`]. Leaves `out` unchanged
    /// on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), IpsecError> {
        self.check()?;
        out.push(self.next_header);
        out.push((self.len() / 4 - 2) as u8);
        out.extend_from_slice(&self.reserved.to_be_bytes());
        out.extend_from_slice(&self.spi.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.icv);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{Collect, CollectError, Fail, contract, test_support::{Lcg, decode_all, mutate}};

    fn check<M>(limit: usize, b: &[u8]) -> Result<M, IpsecError>
    where M: Wire<ParseError = IpsecError, WriteError = IpsecError> + Clone + std::fmt::Debug + PartialEq {
        let make = || Collect::<M>::new(limit);
        contract::check_decode_with_alloc_limit(make, b, 2 * (limit + 1));
        contract::check_wire::<M>(b);
        let parsed = M::parse(b);
        let (items, failure) = decode_all(make, b);
        if b.len() <= limit {
            assert_eq!(failure, parsed.clone().err().map(|e| Fail::Protocol(CollectError::Parse(e))));
            assert_eq!(items, parsed.clone().ok().into_iter().collect::<Vec<_>>());
        } else {
            assert!(items.is_empty());
            assert_eq!(failure, Some(Fail::Protocol(CollectError::TooLong { limit })));
        }
        if let Ok(p) = &parsed { assert_eq!(p.to_bytes().unwrap(), b); }
        contract::check_wire::<Plaintext>(b);
        parsed
    }

    fn check_all(b: &[u8]) {
        let _ = check::<EspPacket>(MAX_PACKET, b);
        let _ = check::<AhPacket>(MAX_PACKET, b);
        let _ = check::<Datagram>(MAX_DATAGRAM, b);
        if let Ok(plain) = Plaintext::parse(b) {
            assert_eq!(plain.to_bytes().unwrap(), b);
            assert_eq!(plain.len(), b.len());
        }
    }

    fn esp(spi: u32, sequence: u32, payload: &[u8]) -> EspPacket {
        EspPacket { spi, sequence, payload: payload.to_vec() }
    }

    fn ah(next_header: u8, spi: u32, sequence: u32, icv: &[u8]) -> AhHeader {
        AhHeader::new(next_header, spi, sequence, icv.to_vec())
    }

    // The layouts of RFC 4303 section 2, RFC 4302 section 2 and RFC 3948
    // sections 2.1 to 2.3.

    #[test]
    fn esp_layout() {
        let b = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef];
        let p = check::<EspPacket>(MAX_PACKET, &b).unwrap();
        assert_eq!(p, esp(0x100, 42, &[0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(p.to_bytes().unwrap(), b);
        // With a 2-byte ICV, the rest is the encrypted part.
        assert_eq!(p.split_icv(2), Ok((&[0xde, 0xad][..], &[0xbe, 0xef][..])));
        assert_eq!(p.split_icv(0), Ok((&[0xde, 0xad, 0xbe, 0xef][..], &[][..])));
        assert_eq!(p.split_icv(3), Err(IpsecError::Truncated));
        assert_eq!(p.split_icv(usize::MAX), Err(IpsecError::Truncated));
    }

    #[test]
    fn esp_with_null_encryption() {
        // NULL encryption (RFC 2410) and no ICV: the payload is the
        // plaintext. A TCP segment of 5 bytes, padded to 8 with 1 byte.
        let plain = Plaintext::padded(vec![1, 2, 3, 4, 5], next_header::TCP, 4).unwrap();
        let bytes = plain.to_bytes().unwrap();
        assert_eq!(bytes, [1, 2, 3, 4, 5, 1, 1, 6]);
        let p = esp(7, 1, &bytes);
        let wire = p.to_bytes().unwrap();
        assert_eq!(wire, [0, 0, 0, 7, 0, 0, 0, 1, 1, 2, 3, 4, 5, 1, 1, 6]);
        let back = check::<EspPacket>(MAX_PACKET, &wire).unwrap();
        assert_eq!(Plaintext::parse(&back.payload), Ok(plain));
    }

    #[test]
    fn plaintext_trailer() {
        // No padding at all: pad length 0.
        let p = Plaintext::parse(&[9, 9, 0, 41]).unwrap();
        assert_eq!(p, Plaintext { data: vec![9, 9], padding: vec![], next_header: next_header::IPV6 });
        assert!(p.has_default_padding());
        // The smallest plaintext: no data, no padding.
        let p = Plaintext::parse(&[0, 59]).unwrap();
        assert_eq!(p.next_header, next_header::NONE);
        assert!(p.data.is_empty() && !p.is_empty());
        // Padding that is not the default reads, and says so.
        let p = Plaintext::parse(&[7, 0xaa, 0xbb, 2, 17]).unwrap();
        assert_eq!(p.data, [7]);
        assert_eq!(p.padding, [0xaa, 0xbb]);
        assert!(!p.has_default_padding());
        assert_eq!(p.to_bytes().unwrap(), [7, 0xaa, 0xbb, 2, 17]);
        // Padding that fills the whole body.
        let p = Plaintext::parse(&[1, 2, 2, 4]).unwrap();
        assert!(p.data.is_empty());
        assert_eq!(p.padding, [1, 2]);
    }

    #[test]
    fn padding_to_each_block_size() {
        for block in 1..=MAX_BLOCK_SIZE {
            for n in 0..40 {
                let p = match Plaintext::padded(vec![0x55; n], next_header::UDP, block) {
                    Ok(p) => p,
                    Err(IpsecError::Padding(pad)) => {
                        // Only a block size above 64 that is not a multiple
                        // of 4 can need more than 255 bytes to reach a
                        // multiple of both it and 4.
                        assert!(pad > MAX_PADDING && block > 64 && block % 4 != 0, "block {block}, {n} bytes");
                        continue;
                    }
                    Err(e) => panic!("block {block}, {n} bytes: {e}"),
                };
                // RFC 4303, section 2.4: a multiple of the block size and
                // of 4, with no more padding than that needs.
                assert_eq!(p.len() % block, 0, "block {block}, {n} bytes");
                assert_eq!(p.len() % 4, 0, "block {block}, {n} bytes");
                let align = (1..).map(|k| k * block).find(|m| m % 4 == 0).unwrap();
                assert!(p.padding.len() < align && p.padding.len() <= MAX_PADDING);
                assert!(p.has_default_padding());
                let b = p.to_bytes().unwrap();
                assert_eq!(Plaintext::parse(&b), Ok(p));
            }
        }
        // Block sizes up to 64 never need too much padding.
        for block in 1..=64 {
            for n in 0..300 {
                assert!(Plaintext::padded(vec![0; n], 4, block).is_ok(), "block {block}, {n} bytes");
            }
        }
        // A block of 255 bytes aligns to 1020, which can need too much.
        assert_eq!(Plaintext::padded(vec![], 4, 255), Err(IpsecError::Padding(1018)));
        // AES-CBC's 16-byte blocks: 10 + 2 bytes need 4 of padding.
        let p = Plaintext::padded(vec![0; 10], 4, 16).unwrap();
        assert_eq!(p.padding, [1, 2, 3, 4]);
        // The largest block can need the most padding.
        let p = Plaintext::padded(vec![0; 255], 4, 256).unwrap();
        assert_eq!(p.padding.len(), 255);
        assert_eq!(p.padding[254], 255);
    }

    #[test]
    fn null_encryption_pads_to_four_bytes() {
        // RFC 4303, section 2.4, with RFC 2410's block size of 1: "ping"
        // and the trailer take 6 bytes, so 2 bytes of padding make 8.
        let p = Plaintext::padded(b"ping".to_vec(), next_header::IPV4, 1).unwrap();
        assert_eq!(p.to_bytes().unwrap(), [b'p', b'i', b'n', b'g', 1, 2, 2, 4]);
        // Block sizes of 2 and 6 align to 4 and 12.
        let p = Plaintext::padded(vec![0; 3], 4, 2).unwrap();
        assert_eq!(p.padding, [1, 2, 3]);
        let p = Plaintext::padded(vec![0; 3], 4, 6).unwrap();
        assert_eq!(p.len(), 12);
        // Already aligned: no padding.
        let p = Plaintext::padded(vec![0; 6], 4, 1).unwrap();
        assert!(p.padding.is_empty());
    }

    #[test]
    fn ah_icv_padding_goes_into_the_icv() {
        // RFC 4302, section 3.3.3.2.1: in IPv6, a 16-byte tag needs 4 bytes
        // of padding to keep the header a multiple of 8 bytes. The padding
        // counts in the ICV as sent; only the tag is zeroed.
        let mut b = vec![next_header::TCP, 6, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 7];
        b.extend_from_slice(&[0x77; 16]);
        b.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let p = AhPacket::parse(&b).unwrap();
        assert!(p.header.is_ipv6_aligned());
        assert_eq!(p.header.split_icv(16), Ok((&[0x77; 16][..], &[0xaa, 0xbb, 0xcc, 0xdd][..])));
        let mut want = b[..12].to_vec();
        want.extend_from_slice(&[0; 16]);
        want.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(p.header.for_icv(16).and_then(|header| header.to_bytes()).unwrap(), want);
        // A tag that fills the field zeroes all of it.
        assert_eq!(&p.header.for_icv(20).and_then(|header| header.to_bytes()).unwrap()[12..], [0; 20]);
        assert_eq!(p.header.split_icv(21), Err(IpsecError::Truncated));
        // The bytes as sent are unchanged.
        assert_eq!(p.to_bytes().unwrap(), b);
    }

    #[test]
    fn udp_payload_limits() {
        // RFC 768: a UDP payload is at most 65535 - 8 bytes, and over IPv4
        // 20 more go to the IP header. Longer datagrams cannot be sent.
        assert_eq!(MAX_DATAGRAM, 65527);
        assert_eq!(MAX_DATAGRAM_IPV4, 65507);
        assert_eq!(Datagram::Ike(vec![0; 65_531]).to_bytes(), Err(IpsecError::TooLong));
        let ike = Datagram::Ike(vec![0; MAX_DATAGRAM - 4]);
        assert_eq!(ike.to_bytes().unwrap().len(), MAX_DATAGRAM);
        assert!(!ike.fits_ipv4());
        assert!(Datagram::Ike(vec![0; MAX_DATAGRAM_IPV4 - 4]).fits_ipv4());
        assert!(!Datagram::Ike(vec![0; MAX_DATAGRAM_IPV4 - 3]).fits_ipv4());
        assert!(Datagram::Keepalive.fits_ipv4());
        // ESP inside UDP has the same limit, though ESP alone has more.
        let big = esp(1, 1, &vec![0; MAX_DATAGRAM - 7]);
        assert!(big.to_bytes().is_ok());
        assert_eq!(Datagram::Esp(big).to_bytes(), Err(IpsecError::TooLong));
        let fits = Datagram::Esp(esp(1, 1, &vec![0; MAX_DATAGRAM - 8]));
        let bytes = fits.to_bytes().unwrap();
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &bytes), Ok(fits));
        // The reader holds to the same limit, all at once or in pieces.
        let mut long = bytes;
        long.push(0);
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &long), Err(IpsecError::TooLong));
    }

    #[test]
    fn ah_layout() {
        // HMAC-SHA1-96 gives a 12-byte ICV, so the header is 24 bytes, or
        // 6 words, and the payload length field is 6 - 2 = 4.
        let icv = [0x11; 12];
        let h = ah(next_header::TCP, 0x1234, 5, &icv);
        let mut b = vec![6, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 5];
        b.extend_from_slice(&icv);
        b.extend_from_slice(b"segment");
        let p = AhPacket { header: h.clone(), payload: b"segment".to_vec() };
        assert_eq!(p.to_bytes().unwrap(), b);
        assert_eq!(check::<AhPacket>(MAX_PACKET, &b), Ok(p));
        assert_eq!(h.len(), 24);
        assert!(h.is_ipv6_aligned() && !h.is_empty());
        assert_eq!(AhPacket::split(&b).unwrap(), (h.clone(), &b"segment"[..]));
        // For the ICV's own computation, the ICV is zero.
        let zeroed = h.for_icv(12).and_then(|header| header.to_bytes()).unwrap();
        assert_eq!(&zeroed[..12], &b[..12]);
        assert_eq!(&zeroed[12..], [0; 12]);
        // A 16-byte ICV makes a 28-byte header: fine in IPv4, not in IPv6.
        assert!(!ah(4, 1, 1, &[0; 16]).is_ipv6_aligned());
    }

    #[test]
    fn ah_shortest_and_longest() {
        // Payload length 1: the fixed fields alone, no ICV.
        let b = [next_header::IPV4, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let p = check::<AhPacket>(MAX_PACKET, &b).unwrap();
        assert_eq!(p.header, ah(4, 1, 0, &[]));
        assert!(p.payload.is_empty());
        // Payload length 255: the longest ICV.
        let h = ah(4, 1, 0, &[0x5a; MAX_ICV]);
        let bytes = h.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_AH_LEN);
        assert_eq!(bytes[1], 255);
        assert_eq!(AhHeader::parse_prefix(&bytes), Ok((h, MAX_AH_LEN)));
    }

    #[test]
    fn ah_reserved_field_is_kept() {
        let b = [4, 1, 0xab, 0xcd, 0, 0, 0, 9, 0, 0, 0, 1];
        let p = check::<AhPacket>(MAX_PACKET, &b).unwrap();
        assert_eq!(p.header, AhHeader { reserved: 0xabcd, ..ah(4, 9, 1, &[]) });
        assert_eq!(p.to_bytes().unwrap(), b);
        // A new header writes it as zero.
        assert_eq!(ah(4, 9, 1, &[]).to_bytes().unwrap(), [4, 1, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1]);
    }

    #[test]
    fn ah_reserved_field_goes_into_the_icv() {
        // RFC 4302, section 2.3: the receiver ignores the reserved field,
        // but its value is part of the ICV computation, so the zeroed form
        // must keep the bytes that came in.
        let b = [4, 2, 0xab, 0xcd, 0, 0, 0, 9, 0, 0, 0, 1, 0xee, 0xee, 0xee, 0xee];
        let p = AhPacket::parse(&b).unwrap();
        assert_eq!(p.header.for_icv(4).and_then(|header| header.to_bytes()).unwrap(), [4, 2, 0xab, 0xcd, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(p.to_bytes().unwrap(), b);
    }

    #[test]
    fn udp_datagrams() {
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &[0xff]), Ok(Datagram::Keepalive));
        assert_eq!(Datagram::Keepalive.to_bytes().unwrap(), [0xff]);
        // An IKE message after the non-ESP marker. An IKE header is longer;
        // its bytes are kept as they are.
        let b = [0, 0, 0, 0, 0x21, 0x22, 0x23];
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &b), Ok(Datagram::Ike(vec![0x21, 0x22, 0x23])));
        assert_eq!(Datagram::Ike(vec![0x21, 0x22, 0x23]).to_bytes().unwrap(), b);
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &[0, 0, 0, 0]), Ok(Datagram::Ike(vec![])));
        // Anything else is ESP.
        let b = [0, 0, 0x10, 0, 0, 0, 0, 3, 0, 4];
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &b), Ok(Datagram::Esp(esp(0x1000, 3, &[0, 4]))));
        // Two keepalive bytes are not a keepalive.
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &[0xff, 0xff]), Err(IpsecError::Truncated));
    }

    #[test]
    fn each_read_error() {
        // ESP.
        assert_eq!(check::<EspPacket>(MAX_PACKET, &[]), Err(IpsecError::Truncated));
        assert_eq!(check::<EspPacket>(MAX_PACKET, &[0, 0, 0, 0, 0, 0, 0, 1, 0, 4]), Err(IpsecError::ZeroSpi));
        assert_eq!(check::<EspPacket>(MAX_PACKET, &[0, 0, 0, 1, 0, 0, 0, 1, 0]), Err(IpsecError::Truncated));
        let mut long = vec![0, 0, 0, 1];
        long.resize(MAX_PACKET + 1, 0);
        assert_eq!(check::<EspPacket>(MAX_PACKET, &long), Err(IpsecError::TooLong));
        long.truncate(MAX_PACKET);
        assert!(check::<EspPacket>(MAX_PACKET, &long).is_ok());
        // AH.
        assert_eq!(check::<AhPacket>(MAX_PACKET, &[4]), Err(IpsecError::Truncated));
        assert_eq!(check::<AhPacket>(MAX_PACKET, &[4, 0, 0, 0, 0, 0, 0, 1]), Err(IpsecError::AhLength(0)));
        assert_eq!(check::<AhPacket>(MAX_PACKET, &[4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), Err(IpsecError::ZeroSpi));
        // A payload length of 3 says 20 bytes; 16 are there.
        assert_eq!(check::<AhPacket>(MAX_PACKET, &[4, 3, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]), Err(IpsecError::Truncated));
        let mut long = vec![4, 1, 0, 0, 0, 0, 0, 1];
        long.resize(MAX_PACKET + 1, 0);
        assert_eq!(check::<AhPacket>(MAX_PACKET, &long), Err(IpsecError::TooLong));
        // UDP.
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &[]), Err(IpsecError::Truncated));
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &[0x7f]), Err(IpsecError::Truncated));
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &[0, 0, 0, 1, 0, 0, 0, 1]), Err(IpsecError::Truncated));
        let mut long = vec![0; MAX_PACKET + 1];
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &long), Err(IpsecError::TooLong));
        long[3] = 1;
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &long), Err(IpsecError::TooLong));
        // The plaintext.
        assert_eq!(Plaintext::parse(&[]), Err(IpsecError::Truncated));
        assert_eq!(Plaintext::parse(&[4]), Err(IpsecError::Truncated));
        assert_eq!(Plaintext::parse(&[1, 2, 4]), Err(IpsecError::PadLength(2)));
        assert_eq!(Plaintext::parse(&[255, 4]), Err(IpsecError::PadLength(255)));
        assert_eq!(Plaintext::parse(&vec![0; MAX_PACKET + 1]), Err(IpsecError::TooLong));
    }

    #[test]
    fn each_write_error() {
        assert_eq!(esp(0, 1, &[0, 4]).to_bytes(), Err(IpsecError::ZeroSpi));
        assert_eq!(esp(1, 1, &[4]).to_bytes(), Err(IpsecError::Truncated));
        assert_eq!(esp(1, 1, &vec![0; MAX_PACKET - 7]).to_bytes(), Err(IpsecError::TooLong));
        assert!(esp(1, 1, &vec![0; MAX_PACKET - 8]).to_bytes().is_ok());
        assert_eq!(Datagram::Esp(esp(0, 1, &[0, 4])).to_bytes(), Err(IpsecError::ZeroSpi));
        assert_eq!(Datagram::Ike(vec![0; MAX_DATAGRAM - 3]).to_bytes(), Err(IpsecError::TooLong));
        assert!(Datagram::Ike(vec![0; MAX_DATAGRAM - 4]).to_bytes().is_ok());

        assert_eq!(ah(4, 0, 1, &[]).to_bytes(), Err(IpsecError::ZeroSpi));
        assert_eq!(ah(4, 0, 1, &[]).for_icv(0).and_then(|header| header.to_bytes()), Err(IpsecError::ZeroSpi));
        assert_eq!(ah(4, 1, 1, &[0; 12]).for_icv(16).and_then(|header| header.to_bytes()), Err(IpsecError::Truncated));
        assert_eq!(ah(4, 1, 1, &[0; 12]).for_icv(usize::MAX).and_then(|header| header.to_bytes()), Err(IpsecError::Truncated));
        assert_eq!(ah(4, 1, 1, &[0; 3]).to_bytes(), Err(IpsecError::IcvLength(3)));
        assert_eq!(ah(4, 1, 1, &[0; MAX_ICV + 4]).to_bytes(), Err(IpsecError::IcvLength(MAX_ICV + 4)));
        let p = AhPacket { header: ah(4, 1, 1, &[0; 3]), payload: vec![] };
        assert_eq!(p.to_bytes(), Err(IpsecError::IcvLength(3)));
        let p = AhPacket { header: ah(4, 1, 1, &[0; 12]), payload: vec![0; MAX_PACKET - 23] };
        assert_eq!(p.to_bytes(), Err(IpsecError::TooLong));
        let p = AhPacket { header: ah(4, 1, 1, &[0; 12]), payload: vec![0; MAX_PACKET - 24] };
        assert_eq!(p.to_bytes().unwrap().len(), MAX_PACKET);
        assert_eq!(
            AhPacket { header: ah(4, 0, 1, &[]), payload: vec![] }.to_bytes(),
            Err(IpsecError::ZeroSpi)
        );

        let p = Plaintext { data: vec![], padding: vec![0; 256], next_header: 4 };
        assert_eq!(p.to_bytes(), Err(IpsecError::Padding(256)));
        let p = Plaintext { data: vec![0; MAX_PACKET - 1], padding: vec![], next_header: 4 };
        assert_eq!(p.to_bytes(), Err(IpsecError::TooLong));
        assert_eq!(Plaintext::padded(vec![], 4, 0), Err(IpsecError::BlockSize(0)));
        assert_eq!(Plaintext::padded(vec![], 4, 257), Err(IpsecError::BlockSize(257)));
        assert_eq!(Plaintext::padded(vec![0; MAX_PACKET - 1], 4, 1), Err(IpsecError::TooLong));
        assert_eq!(Plaintext::padded(vec![0; MAX_PACKET + 1], 4, 1), Err(IpsecError::TooLong));
        // 65535 is not a multiple of 4, so padding to it overflows.
        assert_eq!(Plaintext::padded(vec![0; MAX_PACKET - 2], 4, 1), Err(IpsecError::TooLong));
        assert_eq!(Plaintext::padded(vec![0; MAX_PACKET - 5], 4, 1).unwrap().len(), MAX_PACKET - 3);
    }

    #[test]
    fn errors_display() {
        let all = [
            IpsecError::Truncated,
            IpsecError::Trailing { remaining: 1 },
            IpsecError::TooLong,
            IpsecError::ZeroSpi,
            IpsecError::AhLength(0),
            IpsecError::IcvLength(3),
            IpsecError::PadLength(9),
            IpsecError::Padding(300),
            IpsecError::BlockSize(0),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
    }

    fn esp_samples() -> Vec<EspPacket> {
        vec![esp(1, 0, &[0, 4]), esp(0xffff_ffff, 0xffff_ffff, b"ciphertext and icv")]
    }

    fn ah_samples() -> Vec<AhPacket> {
        vec![
            AhPacket { header: ah(4, 1, 1, &[]), payload: vec![] },
            AhPacket { header: ah(6, 0x200, 9, &[0xcc; 12]), payload: b"inner".to_vec() },
        ]
    }

    fn udp_samples() -> Vec<Datagram> {
        vec![Datagram::Keepalive, Datagram::Ike(vec![]), Datagram::Ike(b"ike message".to_vec()),
            Datagram::Esp(esp(0x1000, 2, &[1, 2, 3, 4, 2, 4]))]
    }

    #[test]
    fn every_truncated_prefix() {
        for p in esp_samples() {
            let b = p.to_bytes().unwrap();
            for n in 0..b.len() {
                let got = check::<EspPacket>(MAX_PACKET, &b[..n]);
                if n >= MIN_ESP_LEN { assert!(got.is_ok()); }
                else { assert_eq!(got, Err(IpsecError::Truncated)); }
            }
            assert_eq!(check::<EspPacket>(MAX_PACKET, &b), Ok(p));
        }
        for p in ah_samples() {
            let b = p.to_bytes().unwrap();
            for n in 0..b.len() {
                let got = check::<AhPacket>(MAX_PACKET, &b[..n]);
                if n >= p.header.len() {
                    let got = got.unwrap();
                    assert_eq!(got.header, p.header);
                    assert_eq!(got.payload, p.payload[..n - p.header.len()]);
                } else { assert_eq!(got, Err(IpsecError::Truncated)); }
            }
            assert_eq!(check::<AhPacket>(MAX_PACKET, &b), Ok(p));
        }
        for p in udp_samples() {
            let b = p.to_bytes().unwrap();
            for n in 0..b.len() {
                let got = check::<Datagram>(MAX_DATAGRAM, &b[..n]);
                match &p {
                    Datagram::Esp(_) if n >= MIN_ESP_LEN => assert!(got.is_ok()),
                    Datagram::Ike(m) if n >= 4 => assert_eq!(got, Ok(Datagram::Ike(m[..n - 4].to_vec()))),
                    _ => assert_eq!(got, Err(IpsecError::Truncated)),
                }
            }
            assert_eq!(check::<Datagram>(MAX_DATAGRAM, &b), Ok(p));
        }
        let b = Plaintext::padded(b"abcdefg".to_vec(), 4, 8).unwrap().to_bytes().unwrap();
        for n in 0..b.len() {
            let got = check::<Plaintext>(MAX_PACKET, &b[..n]);
            if n < 2 { assert_eq!(got, Err(IpsecError::Truncated)); }
        }
    }

    #[test]
    fn collection_chunk_contract() {
        let mut rng = Lcg::new(2410);
        for _ in 0..2_000 { random_packet(&mut rng).check(); }
    }

    #[test]
    fn collection_errors_and_limits() {
        assert_eq!(check::<EspPacket>(MAX_PACKET, &[0; 4]), Err(IpsecError::ZeroSpi));
        assert_eq!(check::<AhPacket>(MAX_PACKET, &[4, 0]), Err(IpsecError::AhLength(0)));
        assert_eq!(check::<Datagram>(MAX_DATAGRAM, &vec![1; 70_000]), Err(IpsecError::TooLong));
        let mut big = vec![1; 3 * MAX_PACKET];
        big[..4].copy_from_slice(&[0, 0, 0, 1]);
        assert_eq!(check::<EspPacket>(MAX_PACKET, &big), Err(IpsecError::TooLong));
    }

    #[test]
    fn values_can_key_maps() {
        fn check<T: std::hash::Hash + Eq + Clone>(values: Vec<T>) {
            let mut seen = std::collections::HashSet::new();
            for p in values { assert!(seen.insert(p.clone())); assert!(!seen.insert(p)); }
        }
        check(esp_samples());
        check(ah_samples());
        check(udp_samples());
    }

    trait Samples {
        fn spi(&mut self) -> u32;
    }

    impl Samples for Lcg {
        fn spi(&mut self) -> u32 {
            u32::from_be_bytes(std::array::from_fn(|_| self.next() as u8)).max(1)
        }
    }

    enum Packet {
        Esp(EspPacket),
        Ah(AhPacket),
        Udp(Datagram),
    }

    impl Packet {
        fn check(self) -> Vec<u8> {
            fn round_trip<M>(value: M, limit: usize) -> Vec<u8>
            where M: Wire<ParseError = IpsecError, WriteError = IpsecError> + Clone + std::fmt::Debug + PartialEq {
                contract::check_wire_value(&value);
                let bytes = value.to_bytes().unwrap();
                assert_eq!(check::<M>(limit, &bytes), Ok(value));
                bytes
            }
            match self {
                Self::Esp(value) => round_trip(value, MAX_PACKET),
                Self::Ah(value) => round_trip(value, MAX_PACKET),
                Self::Udp(value) => round_trip(value, MAX_DATAGRAM),
            }
        }
    }

    fn random_packet(rng: &mut Lcg) -> Packet {
        let esp_packet = |rng: &mut Lcg| {
            let mut payload = rng.bytes(40);
            payload.extend_from_slice(&[0, 4]);
            EspPacket { spi: rng.spi(), sequence: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)), payload }
        };
        match rng.index(5) {
            0 => Packet::Esp(esp_packet(rng)),
            1 => {
                let mut icv = vec![0; rng.index(9) * 4];
                rng.fill(&mut icv);
                let header = AhHeader { next_header: rng.next() as u8,
                    reserved: if rng.coin() { 0 } else { rng.next() as u16 },
                    spi: rng.spi(), sequence: u32::from_be_bytes(std::array::from_fn(|_| rng.next() as u8)), icv };
                Packet::Ah(AhPacket { header, payload: rng.bytes(32) })
            }
            2 => Packet::Udp(Datagram::Keepalive),
            3 => Packet::Udp(Datagram::Ike(rng.bytes(32))),
            _ => Packet::Udp(Datagram::Esp(esp_packet(rng))),
        }
    }

    #[test]
    fn fuzz_round_trips() {
        let mut rng = Lcg::new(0x4303);
        for _ in 0..3_000 {
            let b = random_packet(&mut rng).check();
            check_all(&b);
            // The plaintext writer and reader agree too.
            let n = rng.index(64);
            let data = rng.bytes(n);
            let block = rng.index(MAX_BLOCK_SIZE) + 1;
            match Plaintext::padded(data, rng.next() as u8, block) {
                Ok(plain) => {
                    assert_eq!(plain.len() % 4, 0);
                    assert_eq!(plain.len() % block, 0);
                    assert_eq!(Plaintext::parse(&plain.to_bytes().unwrap()), Ok(plain));
                }
                Err(e) => assert!(matches!(e, IpsecError::Padding(n) if n > MAX_PADDING), "{e}"),
            }
        }
    }

    #[test]
    fn fuzz_mutated_packets() {
        let mut rng = Lcg::new(0x4302);
        for _ in 0..4_000 {
            let mut b = random_packet(&mut rng).check();
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut b);
            }
            check_all(&b);
        }
    }

    #[test]
    fn fuzz_random_bytes() {
        let mut rng = Lcg::new(3948);
        for _ in 0..4_000 {
            let n = rng.index(48);
            let mut b = rng.bytes(n);
            // Aim some at zero SPIs and markers, and at small AH lengths.
            if b.len() >= 8 && rng.index(3) == 0 {
                b[..4].fill(0);
            }
            if b.len() >= 2 && !rng.coin() {
                b[1] %= 12;
            }
            check_all(&b);
        }
    }
}
