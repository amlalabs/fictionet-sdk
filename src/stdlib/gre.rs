//! GRE: reading and writing Generic Routing Encapsulation headers, with no
//! I/O.
//!
//! `Packet` reads and writes complete GRE and PPTP GRE packets through `Wire`.
//! There is no protocol stream decoder, PPTP control session, tunnel `Service`,
//! or live transport. The caller handles the inner payload.
//!
//! GRE carries one network's packets inside IP packets of another, as IP
//! protocol 47. Routers use it to build tunnels, and PPTP VPNs use it to
//! carry PPP frames. Every packet starts with a 4-byte header: flag bits,
//! a version and the EtherType of the payload. Flags then say which
//! optional fields follow. This module follows RFC 2784 (the header and
//! its checksum), RFC 2890 (the key and sequence number fields) and RFC
//! 2637, section 4.1 (the enhanced GRE header of PPTP, version 1, with its
//! call ID, payload length and acknowledgment number).
//!
//! Nothing here reads a socket. A world that plays a tunnel endpoint hands
//! the payload of each IP packet of protocol [`IP_PROTOCOL`] to
//! [`Packet::parse`], looks at the [`Header`], and does what it likes with
//! the inner payload. To send, it builds a [`Packet`] and writes the bytes
//! [`Wire::to_bytes`] returns. For pieces of one packet, use
//! [`Stream<Collect<Packet>>`](fictionet::stdlib::codec::Stream)
//! and a collection limit of [`MAX_PACKET`]. Call `end` at the packet boundary.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A header with an unknown version, with the routing bits or the
//! top recursion bit set, or with a checksum that does not match is
//! refused. A PPTP header must also clear the C bit, all of the recursion
//! control and the flags bits 9 to 12, and carry the K bit. It carries a
//! sequence number exactly when it carries a payload. The bits RFC 2784
//! reserves for later use are ignored when read and written as zero, as
//! the RFC asks.
//! So is the reserved field after the checksum. Writers
//! compute the checksum and the PPTP payload length themselves, so bytes
//! they return always read back.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::gre::{protocol, Header, Packet, PlainHeader};
//!
//! let packet = Packet {
//!     header: Header::Gre(PlainHeader { protocol: protocol::IPV4, checksum: true, key: Some(7), sequence: None }),
//!     payload: vec![0x45, 0x00],
//! };
//! let bytes = packet.to_bytes().unwrap();
//! // The C and K bits, version 0, protocol 0x0800. Then the checksum and
//! // a reserved field of zero, the key, and the payload.
//! assert_eq!(bytes, [0xa0, 0x00, 0x08, 0x00, 0x12, 0xf8, 0, 0, 0, 0, 0, 7, 0x45, 0x00]);
//!
//! let back = Packet::parse(&bytes).unwrap();
//! assert_eq!(back, packet);
//! assert_eq!(back.header.key(), Some(7));
//! ```

use fictionet::stdlib::codec::{be16, be32, Wire};
use fictionet::stdlib::ip::checksum;

/// The IP protocol number that marks a GRE packet.
pub const IP_PROTOCOL: u8 = 47;
/// The length of the fixed header, before the optional fields.
pub const BASE_HEADER_LEN: usize = 4;
/// The length of each optional field: the checksum with its reserved
/// half, the key, the sequence number and the acknowledgment number.
pub const FIELD_LEN: usize = 4;
/// The length of the shortest PPTP header: the fixed part and the key,
/// which PPTP always carries.
pub const PPTP_BASE_HEADER_LEN: usize = BASE_HEADER_LEN + FIELD_LEN;
/// The longest header of either version: the fixed part and three
/// optional fields.
pub const MAX_HEADER_LEN: usize = BASE_HEADER_LEN + 3 * FIELD_LEN;
/// The longest packet this module reads or writes, header and payload
/// together: the most an IPv4 total length or an IPv6 payload length
/// field allows.
pub const MAX_PACKET: usize = 65535;
/// The version of plain GRE, from RFC 2784.
pub const VERSION_GRE: u8 = 0;
/// The version of the enhanced GRE header of PPTP, from RFC 2637.
pub const VERSION_PPTP: u8 = 1;

/// Protocol types: the EtherType of the payload.
pub mod protocol {
    /// The payload is an IPv4 packet.
    pub const IPV4: u16 = 0x0800;
    /// The payload is an IPv6 packet.
    pub const IPV6: u16 = 0x86dd;
    /// The payload is a whole Ethernet frame.
    pub const TRANSPARENT_ETHERNET_BRIDGING: u16 = 0x6558;
    /// The payload is a PPP frame. A PPTP header always carries this type.
    pub const PPP: u16 = 0x880b;
}

// The bits of the first 16-bit word of the header.
const CHECKSUM_BIT: u16 = 0x8000;
const ROUTING_BIT: u16 = 0x4000;
const KEY_BIT: u16 = 0x2000;
const SEQUENCE_BIT: u16 = 0x1000;
const STRICT_ROUTE_BIT: u16 = 0x0800;
const RECURSION_BITS: u16 = 0x0700;
const ACK_BIT: u16 = 0x0080;
const VERSION_BITS: u16 = 0x0007;
// RFC 2784: a receiver discards a packet with any of bits 1 to 5 set,
// other than the key and sequence bits of RFC 2890.
const GRE_MUST_BE_ZERO: u16 = ROUTING_BIT | STRICT_ROUTE_BIT | 0x0400;
// RFC 2637: C, R, s, the recursion control and the flags (bits 9 to 12)
// are always zero.
const PPTP_FLAGS_BITS: u16 = 0x0078;
const PPTP_MUST_BE_ZERO: u16 = CHECKSUM_BIT | ROUTING_BIT | STRICT_ROUTE_BIT | RECURSION_BITS | PPTP_FLAGS_BITS;

/// A plain GRE header, version 0. The flag bits are worked out from which
/// fields are present, so none of them is kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PlainHeader {
    /// The EtherType of the payload, such as [`protocol::IPV4`].
    pub protocol: u16,
    /// Whether the packet carries a checksum. Its value is not kept: a
    /// reader checks it, and a writer computes it over the header and the
    /// payload.
    pub checksum: bool,
    /// The key, if the K bit is set. It tells apart flows within one
    /// tunnel.
    pub key: Option<u32>,
    /// The sequence number, if the S bit is set.
    pub sequence: Option<u32>,
}

/// The enhanced GRE header of PPTP, version 1. The protocol type is always
/// [`protocol::PPP`] and the payload length is worked out from the
/// payload, so neither is kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PptpHeader {
    /// The peer's call ID for the session the packet belongs to. It sits
    /// in the low half of the key field.
    pub call_id: u16,
    /// The sequence number, if the S bit is set. A packet carries one
    /// exactly when it carries data: a reader refuses, and a writer will
    /// not write, a sequence number without a payload or a payload without
    /// one.
    pub sequence: Option<u32>,
    /// The highest sequence number received from the peer, if the A bit is
    /// set.
    pub ack: Option<u32>,
}

/// A GRE header of either version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Header {
    /// Plain GRE, version 0.
    Gre(PlainHeader),
    /// PPTP's enhanced GRE, version 1.
    Pptp(PptpHeader),
}

impl Default for Header {
    fn default() -> Header {
        Header::Gre(PlainHeader::default())
    }
}

/// Why bytes are not a GRE packet, or why a packet cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The bytes end before the header does, or, in PPTP, before the
    /// payload length says the payload does.
    Truncated,
    /// The version was neither 0 nor 1. A receiver drops such packets.
    Version(u8),
    /// Flag bits that must be zero were set: these are the ones. In
    /// version 0 they are the routing bits and the top recursion bit; in
    /// version 1 they are also the C bit, all of the recursion control and
    /// the flags bits 9 to 12.
    Reserved(u16),
    /// A version 1 header without the K bit. PPTP always carries a key.
    MissingKey,
    /// A version 1 header whose protocol type, given here, was not
    /// [`protocol::PPP`].
    PptpProtocol(u16),
    /// A version 1 header with a sequence number and no payload, or with a
    /// payload and no sequence number. RFC 2637 sets the S bit exactly
    /// when a payload is present.
    PptpSequence,
    /// The checksum did not match the header and the payload.
    Checksum,
    /// The packet is longer than [`MAX_PACKET`].
    TooLong,
    /// Bytes follow the declared PPTP payload.
    Trailing {
        /// Number of bytes after the payload.
        remaining: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Trailing { remaining } => write!(f, "{remaining} bytes after the GRE packet"),
            Error::Truncated => f.write_str("bytes end inside the GRE packet"),
            Error::Version(v) => write!(f, "GRE version {v}, not 0 or 1"),
            Error::Reserved(bits) => write!(f, "GRE flag bits {bits:#06x} must be zero"),
            Error::MissingKey => f.write_str("PPTP GRE header without the K bit"),
            Error::PptpProtocol(p) => write!(f, "PPTP GRE protocol type {p:#06x}, not 0x880b"),
            Error::PptpSequence => f.write_str("PPTP GRE sequence number without a payload, or payload without one"),
            Error::Checksum => f.write_str("GRE checksum does not match"),
            Error::TooLong => write!(f, "GRE packet longer than {MAX_PACKET} bytes"),
        }
    }
}

impl std::error::Error for Error {}

impl Header {
    /// The version the header is written with: [`VERSION_GRE`] or
    /// [`VERSION_PPTP`].
    pub fn version(&self) -> u8 {
        match self {
            Header::Gre(_) => VERSION_GRE,
            Header::Pptp(_) => VERSION_PPTP,
        }
    }

    /// The EtherType of the payload. For PPTP it is always
    /// [`protocol::PPP`].
    pub fn protocol(&self) -> u16 {
        match self {
            Header::Gre(h) => h.protocol,
            Header::Pptp(_) => protocol::PPP,
        }
    }

    /// The sequence number, if the header carries one.
    pub fn sequence(&self) -> Option<u32> {
        match self {
            Header::Gre(h) => h.sequence,
            Header::Pptp(h) => h.sequence,
        }
    }

    /// The key field, if the header carries one. For PPTP it holds the
    /// payload length in its high half, which a writer fills in, so this
    /// returns only the call ID.
    pub fn key(&self) -> Option<u32> {
        match self {
            Header::Gre(h) => h.key,
            Header::Pptp(h) => Some(u32::from(h.call_id)),
        }
    }

    /// How many bytes the header takes, from 4 to [`MAX_HEADER_LEN`].
    pub fn len(&self) -> usize {
        let fields = |flags: [bool; 3]| flags.iter().filter(|&&f| f).count() * FIELD_LEN;
        match self {
            Header::Gre(h) => BASE_HEADER_LEN + fields([h.checksum, h.key.is_some(), h.sequence.is_some()]),
            Header::Pptp(h) => PPTP_BASE_HEADER_LEN + fields([h.sequence.is_some(), h.ack.is_some(), false]),
        }
    }

    /// Whether the header takes no bytes. It never does, so this is always
    /// false.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Reads the header at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the header and how many bytes
    /// it took. It fails as soon as the bytes it has show a bad header, so
    /// a longer `b` never turns an error into success. It does not check
    /// the checksum, which needs the whole packet; [`Header::split`] does.
    pub fn parse_prefix(b: &[u8]) -> Result<Option<(Header, usize)>, Error> {
        if b.len() < 2 {
            return Ok(None);
        }
        let flags = be16(b, 0).ok_or(Error::Truncated)?;
        let version = (flags & VERSION_BITS) as u8;
        match version {
            VERSION_GRE => {
                let bad = flags & GRE_MUST_BE_ZERO;
                if bad != 0 {
                    return Err(Error::Reserved(bad));
                }
            }
            VERSION_PPTP => {
                let bad = flags & PPTP_MUST_BE_ZERO;
                if bad != 0 {
                    return Err(Error::Reserved(bad));
                }
                if flags & KEY_BIT == 0 {
                    return Err(Error::MissingKey);
                }
            }
            v => return Err(Error::Version(v)),
        }
        if b.len() < BASE_HEADER_LEN {
            return Ok(None);
        }
        let proto = be16(b, 2).ok_or(Error::Truncated)?;
        if version == VERSION_PPTP && proto != protocol::PPP {
            return Err(Error::PptpProtocol(proto));
        }
        let has = |bit: u16| flags & bit != 0;
        let header = if version == VERSION_GRE {
            Header::Gre(PlainHeader {
                protocol: proto,
                checksum: has(CHECKSUM_BIT),
                key: has(KEY_BIT).then_some(0),
                sequence: has(SEQUENCE_BIT).then_some(0),
            })
        } else {
            Header::Pptp(PptpHeader {
                call_id: 0,
                sequence: has(SEQUENCE_BIT).then_some(0),
                ack: has(ACK_BIT).then_some(0),
            })
        };
        let len = header.len();
        if b.len() < len {
            return Ok(None);
        }
        // Fill in the fields, in the order they appear.
        let mut at = BASE_HEADER_LEN;
        let mut next = || {
            let v = be32(b, at).ok_or(Error::Truncated)?;
            at += FIELD_LEN;
            Ok::<_, Error>(v)
        };
        let header = match header {
            Header::Gre(mut h) => {
                if h.checksum {
                    // The checksum is checked over the whole packet, and
                    // the reserved half is ignored.
                    next()?;
                }
                h.key = h.key.map(|_| next()).transpose()?;
                h.sequence = h.sequence.map(|_| next()).transpose()?;
                Header::Gre(h)
            }
            Header::Pptp(mut h) => {
                // The payload length is the high half of the key field.
                let has_payload = be16(b, BASE_HEADER_LEN).ok_or(Error::Truncated)? != 0;
                if h.sequence.is_some() != has_payload {
                    return Err(Error::PptpSequence);
                }
                h.call_id = next()? as u16;
                h.sequence = h.sequence.map(|_| next()).transpose()?;
                h.ack = h.ack.map(|_| next()).transpose()?;
                Header::Pptp(h)
            }
        };
        Ok(Some((header, len)))
    }

    /// Splits a whole packet into its header and its payload, borrowed
    /// from `b`. It checks the checksum if there is one. For PPTP the
    /// payload is as long as the header's payload length field says, and
    /// bytes after it are refused.
    pub fn split(b: &[u8]) -> Result<(Header, &[u8]), Error> {
        let (header, used) = Header::parse_prefix(b)?.ok_or(Error::Truncated)?;
        if b.len() > MAX_PACKET {
            return Err(Error::TooLong);
        }
        match header {
            Header::Gre(h) => {
                if h.checksum && checksum(b) != 0 {
                    return Err(Error::Checksum);
                }
                Ok((header, &b[used..]))
            }
            Header::Pptp(_) => {
                let end = used.checked_add(usize::from(be16(b, BASE_HEADER_LEN).ok_or(Error::Truncated)?))
                    .ok_or(Error::TooLong)?;
                let payload = b.get(used..end).ok_or(Error::Truncated)?;
                if end != b.len() {
                    return Err(Error::Trailing { remaining: b.len() - end });
                }
                Ok((header, payload))
            }
        }
    }

    /// Appends the header's bytes to `out`, for a payload of
    /// `payload_len` bytes, with the checksum field zero. It fails with
    /// [`Error::TooLong`] if the header and the payload together would
    /// be longer than [`MAX_PACKET`], and with [`Error::PptpSequence`] if
    /// a PPTP header's sequence number does not match the payload; then
    /// `out` is left as it was.
    fn write(&self, payload_len: usize, out: &mut Vec<u8>) -> Result<(), Error> {
        let total = self.len().saturating_add(payload_len);
        if total > MAX_PACKET {
            return Err(Error::TooLong);
        }
        if let Header::Pptp(h) = self
            && h.sequence.is_some() != (payload_len > 0)
        {
            return Err(Error::PptpSequence);
        }
        let bit = |present: bool, bit: u16| if present { bit } else { 0 };
        match self {
            Header::Gre(h) => {
                let flags = bit(h.checksum, CHECKSUM_BIT)
                    | bit(h.key.is_some(), KEY_BIT)
                    | bit(h.sequence.is_some(), SEQUENCE_BIT)
                    | u16::from(VERSION_GRE);
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&h.protocol.to_be_bytes());
                if h.checksum {
                    out.extend_from_slice(&[0; FIELD_LEN]);
                }
                for v in [h.key, h.sequence].into_iter().flatten() {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            Header::Pptp(h) => {
                let flags = KEY_BIT
                    | bit(h.sequence.is_some(), SEQUENCE_BIT)
                    | bit(h.ack.is_some(), ACK_BIT)
                    | u16::from(VERSION_PPTP);
                // The header is at least 8 bytes, so the payload fits in 16 bits.
                let len = u16::try_from(payload_len).map_err(|_| Error::TooLong)?;
                out.extend_from_slice(&flags.to_be_bytes());
                out.extend_from_slice(&protocol::PPP.to_be_bytes());
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&h.call_id.to_be_bytes());
                for v in [h.sequence, h.ack].into_iter().flatten() {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
        }
        Ok(())
    }
}

/// One GRE packet: the header and the payload it carries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Packet {
    /// The header.
    pub header: Header,
    /// The payload: the inner packet, or for PPTP a PPP frame. A PPTP
    /// packet that only acknowledges carries none.
    pub payload: Vec<u8>,
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one packet and copies its payload.
    /// Refuses invalid flags, lengths, checksums, and trailing PPTP bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (header, payload) = Header::split(b)?;
        Ok(Packet { header, payload: payload.to_vec() })
    }

    /// Appends a packet with its checksum and PPTP payload length. Refuses
    /// a packet above [`MAX_PACKET`] or a PPTP sequence number whose presence
    /// does not match the payload. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        out.reserve(self.header.len().saturating_add(self.payload.len()).min(MAX_PACKET));
        self.header.write(self.payload.len(), out)?;
        out.extend_from_slice(&self.payload);
        if let Header::Gre(PlainHeader { checksum: true, .. }) = self.header {
            let sum = checksum(&out[start..]);
            let at = start + BASE_HEADER_LEN;
            out[at..at + 2].copy_from_slice(&sum.to_be_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Collect, CollectError, Fail, Lcg, contract,
        test_support::{decode_all, mutate},
    };

    fn collect(b: &[u8]) -> Result<Packet, Error> {
        let make = || Collect::<Packet>::new(MAX_PACKET);
        contract::check_decode_with_alloc_limit(make, b, 2 * (MAX_PACKET + 1));
        contract::check_wire::<Packet>(b);
        let parsed = Packet::parse(b);
        let (items, failure) = decode_all(make, b);
        if b.len() <= MAX_PACKET {
            assert_eq!(failure, parsed.clone().err().map(|e| Fail::Protocol(CollectError::Parse(e))));
            assert_eq!(items, parsed.clone().ok().into_iter().collect::<Vec<_>>());
        } else {
            assert_eq!(failure, Some(Fail::Protocol(CollectError::TooLong { limit: MAX_PACKET })));
        }
        parsed
    }

    fn gre(protocol: u16, checksum: bool, key: Option<u32>, sequence: Option<u32>) -> Header {
        Header::Gre(PlainHeader { protocol, checksum, key, sequence })
    }

    fn pptp(call_id: u16, sequence: Option<u32>, ack: Option<u32>) -> Header {
        Header::Pptp(PptpHeader { call_id, sequence, ack })
    }

    /// Parses `b` directly and through Collect and checks they agree. A packet read
    /// writes back to bytes that read the same.
    fn check(b: &[u8]) -> Result<Packet, Error> {
        let parsed = Packet::parse(b);
        assert_eq!(collect(b), parsed);
        if let Ok(p) = &parsed {
            let bytes = p.to_bytes().unwrap();
            assert!(bytes.len() <= b.len());
            assert_eq!(Packet::parse(&bytes).as_ref(), Ok(p));
            assert_eq!(p.header.len() + p.payload.len(), bytes.len());
        }
        // A prefix error never turns into success with more bytes.
        for n in 0..=b.len().min(MAX_HEADER_LEN) {
            if let Err(e) = Header::parse_prefix(&b[..n]) {
                assert_eq!(parsed, Err(e));
            }
        }
        parsed
    }

    // The layouts of RFC 2784 section 2.1, RFC 2890 section 2 and RFC 2637
    // section 4.1.

    #[test]
    fn plain_header() {
        // No flags, version 0, IPv4, then the inner packet.
        let b = [0x00, 0x00, 0x08, 0x00, 0x45, 0x00];
        let p = check(&b).unwrap();
        assert_eq!(p.header, gre(protocol::IPV4, false, None, None));
        assert_eq!(p.payload, [0x45, 0x00]);
        assert_eq!(p.to_bytes().unwrap(), b);
        assert_eq!(p.header.len(), BASE_HEADER_LEN);
        assert_eq!(p.header.version(), 0);
    }

    #[test]
    fn header_with_checksum() {
        // Words 0x8000 + 0x0800 + 0x4500 sum to 0xcd00, whose complement
        // is 0x32ff.
        let b = [0x80, 0x00, 0x08, 0x00, 0x32, 0xff, 0x00, 0x00, 0x45, 0x00];
        let p = check(&b).unwrap();
        assert_eq!(p.header, gre(protocol::IPV4, true, None, None));
        assert_eq!(p.payload, [0x45, 0x00]);
        assert_eq!(p.to_bytes().unwrap(), b);
        assert_eq!(checksum(&[0x80, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x45, 0x00]), 0x32ff);
    }

    #[test]
    fn checksum_over_odd_length() {
        // The last byte is padded: 0x8000 + 0x86dd = 0x106dd, folded to
        // 0x06de, plus 0x6000 is 0x66de, so the checksum is 0x9921.
        let b = [0x80, 0x00, 0x86, 0xdd, 0x99, 0x21, 0x00, 0x00, 0x60];
        let p = check(&b).unwrap();
        assert_eq!(p.header, gre(protocol::IPV6, true, None, None));
        assert_eq!(p.to_bytes().unwrap(), b);
    }

    #[test]
    fn checksum_accepts_negative_zero() {
        // A checksum of 0xffff in place of 0x0000 sums the same way.
        // Words 0x8000 + 0x7fff = 0xffff, so the written checksum is 0.
        let b = [0x80, 0x00, 0x7f, 0xff, 0x00, 0x00, 0x00, 0x00];
        assert!(check(&b).is_ok());
        assert_eq!(Packet::parse(&b).unwrap().to_bytes().unwrap(), b);
        let b = [0x80, 0x00, 0x7f, 0xff, 0xff, 0xff, 0x00, 0x00];
        assert!(check(&b).is_ok());
    }

    #[test]
    fn reserved_half_is_ignored() {
        // Reserved1 is ignored on receipt, but still covered by the
        // checksum. 0x8000 + 0x0800 + 0x1234 = 0x9a34, complement 0x65cb.
        let b = [0x80, 0x00, 0x08, 0x00, 0x65, 0xcb, 0x12, 0x34];
        let p = check(&b).unwrap();
        assert_eq!(p.header, gre(protocol::IPV4, true, None, None));
        assert!(p.payload.is_empty());
    }

    #[test]
    fn key_and_sequence() {
        // RFC 2890: C, K and S, then checksum, key and sequence number.
        let mut b = vec![0xb0, 0x00, 0x65, 0x58, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0, 0, 0, 9, 0xaa];
        let sum = checksum(&b);
        b[4..6].copy_from_slice(&sum.to_be_bytes());
        let p = check(&b).unwrap();
        assert_eq!(p.header, gre(protocol::TRANSPARENT_ETHERNET_BRIDGING, true, Some(0x01020304), Some(9)));
        assert_eq!(p.header.key(), Some(0x01020304));
        assert_eq!(p.header.sequence(), Some(9));
        assert_eq!(p.payload, [0xaa]);
        assert_eq!(p.to_bytes().unwrap(), b);
        assert_eq!(p.header.len(), MAX_HEADER_LEN);

        // Key only, and sequence only.
        let b = [0x20, 0x00, 0x08, 0x00, 0, 0, 0, 5];
        assert_eq!(check(&b).unwrap().header, gre(protocol::IPV4, false, Some(5), None));
        let b = [0x10, 0x00, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(check(&b).unwrap().header, gre(protocol::IPV4, false, None, Some(u32::MAX)));
    }

    #[test]
    fn doc_example() {
        let packet = Packet { header: gre(protocol::IPV4, true, Some(7), None), payload: vec![0x45, 0x00] };
        let bytes = packet.to_bytes().unwrap();
        assert_eq!(bytes, [0xa0, 0x00, 0x08, 0x00, 0x12, 0xf8, 0, 0, 0, 0, 0, 7, 0x45, 0x00]);
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back, packet);
        assert_eq!(back.header.key(), Some(7));
    }

    #[test]
    fn ignored_bits_are_written_as_zero() {
        // Bits 6 to 12 of version 0 (the low recursion bits, the A bit and
        // the flags) are ignored when read.
        let b = [0x03, 0xf8, 0x08, 0x00, 0x45];
        let p = check(&b).unwrap();
        assert_eq!(p.header, gre(protocol::IPV4, false, None, None));
        assert_eq!(p.to_bytes().unwrap(), [0x00, 0x00, 0x08, 0x00, 0x45]);
    }

    #[test]
    fn pptp_flags_bits_must_be_zero() {
        // RFC 2637 section 4.1: the Flags field, bits 9 to 12, must be zero.
        for bit in [0x40u8, 0x20, 0x10, 0x08] {
            let b = [0x30, 0x01 | bit, 0x88, 0x0b, 0, 1, 0, 1, 0, 0, 0, 1, 0x42];
            assert_eq!(check(&b), Err(Error::Reserved(u16::from(bit))), "{bit:#04x}");
            assert_eq!(Header::parse_prefix(&b[..2]), Err(Error::Reserved(u16::from(bit))));
        }
    }

    #[test]
    fn pptp_sequence_matches_payload() {
        // RFC 2637 section 4.1: S is set when a payload is present and
        // clear when none is. Data without a sequence number:
        let b = [0x20, 0x01, 0x88, 0x0b, 0, 1, 0, 1, 0x42];
        assert_eq!(check(&b), Err(Error::PptpSequence));
        // A sequence number without data:
        let b = [0x30, 0x01, 0x88, 0x0b, 0, 0, 0, 1, 0, 0, 0, 1];
        assert_eq!(check(&b), Err(Error::PptpSequence));
        assert_eq!(Header::parse_prefix(&[0x20, 0x01, 0x88, 0x0b, 0, 1, 0]), Ok(None));
        assert_eq!(Header::parse_prefix(&[0x20, 0x01, 0x88, 0x0b, 0, 1, 0, 1]), Err(Error::PptpSequence));
        assert!(!Error::PptpSequence.to_string().is_empty());

        // Writers refuse both, and leave `out` as it was.
        for (sequence, payload) in [(None, vec![0x42]), (Some(1), vec![])] {
            let p = Packet { header: pptp(1, sequence, Some(2)), payload };
            let mut out = vec![9];
            assert_eq!(p.write(&mut out), Err(Error::PptpSequence));
            assert_eq!(out, [9]);
            assert_eq!(p.to_bytes(), Err(Error::PptpSequence));
        }
    }

    #[test]
    fn pptp_data_packet() {
        // K, S and A, version 1, PPP, payload length 3, call ID 0x1234,
        // sequence 5, acknowledgment 4, then the PPP frame.
        let b = [0x30, 0x81, 0x88, 0x0b, 0x00, 0x03, 0x12, 0x34, 0, 0, 0, 5, 0, 0, 0, 4, 0xff, 0x03, 0x21];
        let p = check(&b).unwrap();
        assert_eq!(p.header, pptp(0x1234, Some(5), Some(4)));
        assert_eq!(p.header.protocol(), protocol::PPP);
        assert_eq!(p.header.version(), VERSION_PPTP);
        assert_eq!(p.header.key(), Some(0x1234));
        assert_eq!(p.payload, [0xff, 0x03, 0x21]);
        assert_eq!(p.to_bytes().unwrap(), b);
        assert_eq!(p.header.len(), MAX_HEADER_LEN);
    }

    #[test]
    fn pptp_ack_only() {
        // K and A, no payload: a bare acknowledgment.
        let b = [0x20, 0x81, 0x88, 0x0b, 0x00, 0x00, 0xbe, 0xef, 0, 0, 1, 0];
        let p = check(&b).unwrap();
        assert_eq!(p.header, pptp(0xbeef, None, Some(256)));
        assert!(p.payload.is_empty());
        assert_eq!(p.to_bytes().unwrap(), b);
    }

    #[test]
    fn pptp_refuses_trailing_bytes() {
        let b = [0x30, 0x01, 0x88, 0x0b, 0x00, 0x01, 0, 7, 0, 0, 0, 1, 0x42, 0xee, 0xee];
        assert_eq!(check(&b), Err(Error::Trailing { remaining: 2 }));
        assert_eq!(Header::split(&b), Err(Error::Trailing { remaining: 2 }));
        let p = check(&b[..13]).unwrap();
        assert_eq!(p.header, pptp(7, Some(1), None));
        assert_eq!(p.payload, [0x42]);
        assert_eq!(p.to_bytes().unwrap(), &b[..13]);
    }

    #[test]
    fn errors() {
        let cases: &[(&[u8], Error)] = &[
            (&[], Error::Truncated),
            (&[0x00], Error::Truncated),
            (&[0x00, 0x00, 0x08], Error::Truncated),
            // C and K set, but the bytes stop inside the key.
            (&[0xa0, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0, 0], Error::Truncated),
            // Versions 2 to 7.
            (&[0x00, 0x02], Error::Version(2)),
            (&[0x00, 0x07, 0x08, 0x00], Error::Version(7)),
            // The routing bit, the strict source route bit, the top
            // recursion bit.
            (&[0x40, 0x00, 0x08, 0x00], Error::Reserved(0x4000)),
            (&[0x08, 0x00, 0x08, 0x00], Error::Reserved(0x0800)),
            (&[0x04, 0x00], Error::Reserved(0x0400)),
            (&[0x4c, 0x00], Error::Reserved(0x4c00)),
            // PPTP with a checksum bit, with recursion, without a key.
            (&[0xa0, 0x01, 0x88, 0x0b, 0, 0, 0, 0], Error::Reserved(0x8000)),
            (&[0x21, 0x01], Error::Reserved(0x0100)),
            (&[0x00, 0x01, 0x88, 0x0b], Error::MissingKey),
            // PPTP carrying something other than PPP.
            (&[0x20, 0x01, 0x08, 0x00, 0, 0, 0, 0], Error::PptpProtocol(0x0800)),
            // PPTP whose payload length runs past the bytes.
            (&[0x30, 0x01, 0x88, 0x0b, 0, 2, 0, 0, 0, 0, 0, 1, 0xff], Error::Truncated),
            // PPTP data without a sequence number, and a sequence number
            // without data.
            (&[0x20, 0x01, 0x88, 0x0b, 0, 2, 0, 0, 0xff], Error::PptpSequence),
            (&[0x30, 0x01, 0x88, 0x0b, 0, 0, 0, 0, 0, 0, 0, 1], Error::PptpSequence),
            // PPTP with a flags bit set.
            (&[0x20, 0x09, 0x88, 0x0b], Error::Reserved(0x0008)),
            // A checksum off by one.
            (&[0x80, 0x00, 0x08, 0x00, 0x32, 0xfe, 0x00, 0x00, 0x45, 0x00], Error::Checksum),
            (&[0x80, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00], Error::Checksum),
        ];
        for (b, e) in cases {
            assert_eq!(check(b), Err(*e), "{b:02x?}");
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn header_prefix_errors_and_checksum() {
        assert_eq!(Header::parse_prefix(&[0]), Ok(None));
        assert_eq!(Header::parse_prefix(&[0, 3]), Err(Error::Version(3)));
        assert_eq!(Header::parse_prefix(&[0x20, 1, 0x86]), Ok(None));
        assert_eq!(Header::parse_prefix(&[0x20, 1, 0x86, 0xdd]), Err(Error::PptpProtocol(0x86dd)));
        assert_eq!(Header::parse_prefix(&[0x20, 0, 8, 0, 0, 0, 0]), Ok(None));
        assert_eq!(Header::parse_prefix(&[0x20, 0, 8, 0, 0, 0, 0, 3]), Ok(Some((gre(protocol::IPV4, false, Some(3), None), 8))));
        assert_eq!(collect(&[0x80, 0, 8, 0, 0x32, 0xfe, 0, 0, 0x45, 0]), Err(Error::Checksum));
    }

    #[test]
    fn too_long() {
        let mut b = vec![0x00, 0x00, 0x08, 0x00];
        b.resize(MAX_PACKET + 1, 0);
        assert_eq!(Packet::parse(&b), Err(Error::TooLong));
        assert_eq!(collect(&b), Err(Error::TooLong));
        b.pop();
        assert!(Packet::parse(&b).is_ok());
        // A bad header is reported before the length.
        let mut b = vec![0x00, 0x05];
        b.resize(MAX_PACKET + 10, 0);
        assert_eq!(check(&b), Err(Error::Version(5)));

        // Writers refuse the same.
        let fits = Packet { header: gre(1, true, Some(1), None), payload: vec![0xab; MAX_PACKET - 12] };
        let bytes = fits.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        assert_eq!(Packet::parse(&bytes), Ok(fits.clone()));
        let mut over = fits;
        over.payload.push(0);
        let mut out = vec![9];
        assert_eq!(over.write(&mut out), Err(Error::TooLong));
        assert_eq!(out, [9]);

        let fits = Packet { header: pptp(1, Some(1), Some(2)), payload: vec![0xab; MAX_PACKET - 16] };
        let bytes = fits.to_bytes().unwrap();
        assert_eq!(Packet::parse(&bytes), Ok(fits.clone()));
        let mut over = fits;
        over.payload.push(0);
        assert_eq!(over.to_bytes(), Err(Error::TooLong));
        assert!(!Error::TooLong.to_string().is_empty());
    }

    #[test]
    fn write_appends() {
        let p = Packet { header: gre(protocol::IPV6, true, None, Some(3)), payload: b"inner".to_vec() };
        let mut out = b"before".to_vec();
        p.write(&mut out).unwrap();
        assert_eq!(&out[..6], b"before");
        assert_eq!(&out[6..], &p.to_bytes().unwrap()[..]);
        assert_eq!(Packet::parse(&out[6..]), Ok(p));
    }

    fn sample_packets() -> Vec<Packet> {
        let mut out = Vec::new();
        for flags in 0..8u8 {
            let header = gre(
                protocol::IPV4,
                flags & 1 != 0,
                (flags & 2 != 0).then_some(0xdeadbeef),
                (flags & 4 != 0).then_some(42),
            );
            out.push(Packet { header, payload: b"abcdefg".to_vec() });
        }
        for flags in 0..4u8 {
            // A payload goes with a sequence number, and none without.
            let data = flags & 1 != 0;
            let header = pptp(0x0102, data.then_some(7), (flags & 2 != 0).then_some(6));
            let payload = if data { b"\xff\x03payload".to_vec() } else { Vec::new() };
            out.push(Packet { header, payload });
        }
        out
    }

    #[test]
    fn every_truncated_prefix() {
        for p in sample_packets() {
            let b = p.to_bytes().unwrap();
            let header_len = p.header.len();
            for n in 0..b.len() {
                let got = check(&b[..n]);
                if n < header_len {
                    assert_eq!(got, Err(Error::Truncated), "{p:?} cut at {n}");
                    continue;
                }
                match p.header {
                    Header::Pptp(_) => assert_eq!(got, Err(Error::Truncated), "{p:?} cut at {n}"),
                    Header::Gre(PlainHeader { checksum: true, .. }) => {
                        assert_eq!(got, Err(Error::Checksum), "{p:?} cut at {n}")
                    }
                    Header::Gre(_) => {
                        let got = got.unwrap();
                        assert_eq!(got.header, p.header);
                        assert_eq!(got.payload, &p.payload[..n - header_len]);
                    }
                }
            }
            assert_eq!(check(&b), Ok(p));
        }
    }

    #[test]
    fn every_flipped_bit_in_a_checksummed_packet() {
        let p = Packet { header: gre(protocol::IPV4, true, Some(1), Some(2)), payload: b"payload!".to_vec() };
        let b = p.to_bytes().unwrap();
        // Bit 0 is the C bit itself: clearing it leaves a packet with no
        // checksum to check.
        for i in 1..b.len() * 8 {
            let mut c = b.clone();
            c[i / 8] ^= 0x80 >> (i % 8);
            // Every other flipped bit breaks the header or the sum, even
            // one the reader otherwise ignores.
            assert!(check(&c).is_err(), "bit {i}");
        }
    }

    trait Samples {
        fn maybe(&mut self) -> Option<u32>;
    }

    impl Samples for Lcg {
        fn maybe(&mut self) -> Option<u32> {
            (!self.coin()).then(|| self.next() as u32)
        }
    }

    /// A random packet the writer accepts.
    fn random_packet(rng: &mut Lcg) -> Packet {
        if rng.index(3) == 0 {
            // PPTP carries a sequence number exactly when it carries data.
            let n = if rng.coin() { 47 } else { 0 };
            let payload = rng.bytes(n);
            let sequence = (!payload.is_empty()).then(|| rng.next() as u32);
            let header = pptp(rng.next() as u16, sequence, rng.maybe());
            return Packet { header, payload };
        }
        let protocols = [protocol::IPV4, protocol::IPV6, protocol::TRANSPARENT_ETHERNET_BRIDGING, rng.next() as u16];
        let proto = protocols[rng.index(protocols.len())];
        let header = gre(proto, !rng.coin(), rng.maybe(), rng.maybe());
        let n = rng.index(48);
        Packet {
            header,
            payload: rng.bytes(n),
        }
    }

    #[test]
    fn fuzz_round_trips() {
        let mut rng = Lcg::new(0x6e2e);
        for _ in 0..3_000 {
            let p = random_packet(&mut rng);
            let b = p.to_bytes().unwrap();
            assert_eq!(check(&b), Ok(p));
        }
    }

    #[test]
    fn fuzz_mutated_packets() {
        let mut rng = Lcg::new(0xc0de);
        for _ in 0..4_000 {
            let mut b = random_packet(&mut rng).to_bytes().unwrap();
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut b);
            }
            let _ = check(&b);
        }
    }

    #[test]
    fn fuzz_random_bytes() {
        let mut rng = Lcg::new(47);
        for _ in 0..4_000 {
            let n = rng.index(40);
            let mut b = rng.bytes(n);
            // Most random first bytes are refused at once; aim some at
            // valid flags and versions.
            if b.len() >= 4 && !rng.coin() {
                b[0] &= 0xb0;
                b[1] &= 0x81;
                if b[1] & 1 == 1 {
                    b[0] = (b[0] & 0x30) | 0x20;
                    b[2] = 0x88;
                    b[3] = 0x0b;
                    if b.len() >= 6 {
                        b[4] = 0;
                        b[5] %= 32;
                    }
                }
            }
            let _ = check(&b);
        }
    }
}
