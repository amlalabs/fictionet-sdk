//! RTP and RTCP: reading and writing media packets and their control
//! packets, with no I/O.
//!
//! RTP carries audio and video in real time: voice calls, video calls,
//! WebRTC, IP cameras and media servers all send it. Each RTP packet has a
//! 12-byte header with a payload type, a sequence number, a timestamp and
//! the sender's source identifier (SSRC), then the media. RTCP travels
//! beside it and says how the media is doing: senders and receivers send
//! reports, name themselves in source descriptions (SDES), say goodbye
//! (BYE), and ask for lost packets or new pictures in feedback messages.
//! Both run over UDP, on ports the two ends agree on in SDP. This module
//! follows RFC 3550 (RTP and RTCP), RFC 8285 (header extensions), RFC 4585
//! (feedback messages), RFC 5761 (RTP and RTCP on one port) and RFC 4571
//! (RTP and RTCP over a byte stream).
//!
//! An RTP packet is an [`RtpPacket`]. It may list contributing sources,
//! carry padding, and carry a [`HeaderExtension`] in either RFC 8285 form.
//! RTCP datagrams use [`fictionet::stdlib::rtcp::Datagram`]; compound packets use
//! [`fictionet::stdlib::rtcp::Compound`].
//!
//! Nothing here reads a socket. A world reads each UDP datagram with
//! [`Packet::parse`], which tells RTP from RTCP using RFC 5761. Over TCP,
//! [`Stream<rtcp::Frames>`](fictionet::stdlib::codec::Stream) splits RFC 4571 envelopes.
//! [`rtcp::Frame`] supplies the length prefix when sending. Media contents and
//! report policy belong to world code. SRTP and SRTCP are not handled here.
//!
//! ```
//! use fictionet::stdlib::{codec::Wire, rtcp, rtp::{RtpPacket, Packet}};
//! let packet = RtpPacket {
//!     marker: false, payload_type: 111, sequence: 1, timestamp: 160,
//!     ssrc: 7, csrcs: vec![], extension: None, payload: vec![0xf8], padding: 0,
//! };
//! let bytes = packet.to_bytes().unwrap();
//! assert_eq!(Packet::parse(&bytes), Ok(Packet::Rtp(packet)));
//! let tcp = rtcp::Frame(bytes).to_bytes().unwrap();
//! assert_eq!(&tcp[..2], &[0, 13]);
//! ```

/// The RTP version every packet carries, in its top two bits.
pub const VERSION: u8 = 2;
/// The longest RTP or RTCP packet a reader takes: the most a 16-bit length
/// can say, as in RFC 4571 framing. A UDP datagram is never longer.
pub const MAX_PACKET: usize = 65535;
/// The length of the fixed RTP header, before the CSRCs.
pub const RTP_HEADER_LEN: usize = 12;
/// The most CSRCs an RTP header can list: its 4-bit count.
pub const MAX_CSRCS: usize = 15;
/// The longest element data in the one-byte header extension form.
pub const MAX_ONE_BYTE_DATA: usize = 16;
/// The longest element data in the two-byte header extension form.
pub const MAX_TWO_BYTE_DATA: usize = 255;
/// The profile value that marks the one-byte header extension form.
pub const ONE_BYTE_PROFILE: u16 = 0xbede;
/// The profile value of the two-byte form, with its 4 application bits
/// zero.
pub const TWO_BYTE_PROFILE: u16 = 0x1000;

// ---------------------------------------------------------------------------
// RTP

use fictionet::stdlib::{codec::Wire, rtcp};

/// One RTP packet: the header's fields, the extension and the payload.
/// The version is always 2, and the padding, extension and CSRC count bits
/// are worked out from the other fields, so none of them is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpPacket {
    /// The marker bit. Its meaning is up to the profile; for video it often
    /// marks the last packet of a frame.
    pub marker: bool,
    /// The payload type, 0 to 127, which names the codec as SDP mapped it.
    /// With RTP and RTCP on one port, RFC
    /// 5761 rules out 64 to 95: with the marker set, the second byte is
    /// then an RTCP packet type, and [`Packet::parse`] reads it as RTCP.
    pub payload_type: u8,
    /// Goes up by one for each packet sent, so a receiver can find losses.
    pub sequence: u16,
    /// The sampling instant of the payload's first byte, in the codec's
    /// clock rate.
    pub timestamp: u32,
    /// The synchronization source: who sent the packet.
    pub ssrc: u32,
    /// The contributing sources, such as the speakers a mixer combined. A
    /// packet can list at most [`MAX_CSRCS`].
    pub csrcs: Vec<u32>,
    /// The header extension, if the packet has one.
    pub extension: Option<HeaderExtension>,
    /// The media, with the padding taken off.
    pub payload: Vec<u8>,
    /// How many padding bytes follow the payload, the count byte included.
    /// 0 means the packet has no padding. A writer fills the padding with
    /// zeros and ends it with the count.
    pub padding: u8,
}

/// An RTP header extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderExtension {
    /// The one-byte form of RFC 8285 (profile `0xBEDE`). Each element has
    /// an ID from 1 to 14 and 1 to 16 bytes of data. A reader skips zero
    /// bytes as padding, and stops at ID 15 or at ID 0 with a nonzero
    /// length, keeping the elements before it. A writer refuses invalid elements.
    OneByte(Vec<Element>),
    /// The two-byte form of RFC 8285 (profile `0x100X`). Each element has
    /// an ID from 1 to 255 and 0 to 255 bytes of data.
    TwoByte {
        /// The 4 application bits in the profile's low bits, from 0 to 15.
        app_bits: u8,
        /// The elements, in order, without padding.
        elements: Vec<Element>,
    },
    /// Any other extension, kept as bytes.
    Other {
        /// The 16-bit profile value that names the extension.
        profile: u16,
        /// The extension's data, in whole 32-bit words.
        data: Vec<u8>,
    },
}

/// One element of an RFC 8285 header extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    /// The local identifier, which SDP maps to an extension URI.
    pub id: u8,
    /// The element's data.
    pub data: Vec<u8>,
}

/// Why bytes are not an RTP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtpError {
    /// The bytes end before the header, CSRCs or extension do.
    Truncated,
    /// The version bits were not 2.
    Version(u8),
    /// The packet is longer than [`MAX_PACKET`] bytes.
    TooLong(usize),
    /// The padding bit was set, and the count in the last byte was 0 or
    /// ran into the header.
    Padding,
    /// An RFC 8285 element ran past the end of the extension.
    Extension,
}

impl std::fmt::Display for RtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RtpError::Truncated => f.write_str("RTP packet ends inside its header"),
            RtpError::Version(v) => write!(f, "RTP version {v}, not 2"),
            RtpError::TooLong(n) => write!(f, "RTP packet of {n} bytes, over {MAX_PACKET}"),
            RtpError::Padding => f.write_str("RTP padding count is 0 or runs into the header"),
            RtpError::Extension => f.write_str("RTP header extension element runs past its end"),
        }
    }
}

impl std::error::Error for RtpError {}

impl Wire for RtpPacket {
    type ParseError = RtpError;
    type WriteError = rtcp::EncodeError;
    /// Reads a whole datagram. Refuses bad versions, truncated fields, invalid
    /// padding or extension lengths, and packets over [`MAX_PACKET`].
    fn parse(b: &[u8]) -> Result<RtpPacket, RtpError> {
        if b.len() > MAX_PACKET {
            return Err(RtpError::TooLong(b.len()));
        }
        let mut r = Reader::new(b);
        let b0 = r.u8().ok_or(RtpError::Truncated)?;
        let version = b0 >> 6;
        if version != VERSION {
            return Err(RtpError::Version(version));
        }
        let b1 = r.u8().ok_or(RtpError::Truncated)?;
        let (Some(sequence), Some(timestamp), Some(ssrc)) = (r.u16(), r.u32(), r.u32()) else {
            return Err(RtpError::Truncated);
        };
        let mut csrcs = Vec::new();
        for _ in 0..b0 & 0x0f {
            csrcs.push(r.u32().ok_or(RtpError::Truncated)?);
        }
        let extension = if b0 & 0x10 != 0 {
            let (Some(profile), Some(words)) = (r.u16(), r.u16()) else {
                return Err(RtpError::Truncated);
            };
            let data = r.take(usize::from(words) * 4).ok_or(RtpError::Truncated)?;
            Some(parse_extension(profile, data)?)
        } else {
            None
        };
        let rest = r.rest();
        let padding = if b0 & 0x20 != 0 {
            let n = *b.last().ok_or(RtpError::Padding)?;
            if n == 0 || usize::from(n) > rest.len() {
                return Err(RtpError::Padding);
            }
            n
        } else {
            0
        };
        let payload = rest[..rest.len() - usize::from(padding)].to_vec();
        Ok(RtpPacket {
            marker: b1 & 0x80 != 0,
            payload_type: b1 & 0x7f,
            sequence,
            timestamp,
            ssrc,
            csrcs,
            extension,
            payload,
            padding,
        })
    }

    /// Appends the packet. Refuses out-of-range fields, invalid extension
    /// elements, variant aliases, unaligned opaque data, and oversized packets.
    /// Padding counts are preserved; padding octets are zero.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), rtcp::EncodeError> {
        if self.payload_type > 127
            || self.csrcs.len() > MAX_CSRCS
            || self.payload.len() > MAX_PACKET
        {
            return Err(rtcp::EncodeError::Unwritable);
        }
        let extension = self
            .extension
            .as_ref()
            .map(HeaderExtension::encode)
            .transpose()?;
        let padding = usize::from(self.padding);
        let size = RTP_HEADER_LEN
            + 4 * self.csrcs.len()
            + padding
            + self.payload.len()
            + extension.as_ref().map_or(0, |(_, data)| 4 + data.len());
        if size > MAX_PACKET {
            return Err(rtcp::EncodeError::Unwritable);
        }
        out.try_reserve_exact(size)
            .map_err(|_| rtcp::EncodeError::Unwritable)?;
        out.push(
            VERSION << 6
                | self.csrcs.len() as u8
                | if padding > 0 { 0x20 } else { 0 }
                | if extension.is_some() { 0x10 } else { 0 },
        );
        out.push(u8::from(self.marker) << 7 | self.payload_type);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for c in &self.csrcs {
            out.extend_from_slice(&c.to_be_bytes());
        }
        if let Some((profile, data)) = extension {
            out.extend_from_slice(&profile.to_be_bytes());
            out.extend_from_slice(&((data.len() / 4) as u16).to_be_bytes());
            out.extend_from_slice(&data);
        }
        out.extend_from_slice(&self.payload);
        if padding > 0 {
            out.resize(out.len() + padding - 1, 0);
            out.push(self.padding);
        }
        Ok(())
    }
}

impl HeaderExtension {
    /// The profile value written in front of the extension.
    pub fn profile(&self) -> u16 {
        match self {
            HeaderExtension::OneByte(_) => ONE_BYTE_PROFILE,
            HeaderExtension::TwoByte { app_bits, .. } => {
                TWO_BYTE_PROFILE | u16::from(*app_bits)
            }
            HeaderExtension::Other { profile, .. } => *profile,
        }
    }

    /// The first element with this ID, in either RFC 8285 form.
    pub fn get(&self, id: u8) -> Option<&Element> {
        match self {
            HeaderExtension::OneByte(e) | HeaderExtension::TwoByte { elements: e, .. } => {
                e.iter().find(|e| e.id == id)
            }
            HeaderExtension::Other { .. } => None,
        }
    }
    fn encode(&self) -> Result<(u16, Vec<u8>), rtcp::EncodeError> {
        let mut data = Vec::new();
        match self {
            Self::OneByte(elements) | Self::TwoByte { elements, .. } => {
                let one = matches!(self, Self::OneByte(_));
                if matches!(self, Self::TwoByte { app_bits, .. } if *app_bits > 15) {
                    return Err(rtcp::EncodeError::Unwritable);
                }
                let mut size = 0usize;
                for e in elements {
                    if (one && (!(1..=14).contains(&e.id) || !(1..=16).contains(&e.data.len())))
                        || (!one && (e.id == 0 || e.data.len() > 255))
                    {
                        return Err(rtcp::EncodeError::Unwritable);
                    }
                    size = size.saturating_add(e.data.len() + if one { 1 } else { 2 });
                    if size > MAX_PACKET {
                        return Err(rtcp::EncodeError::Unwritable);
                    }
                }
                let padded = size.div_ceil(4) * 4;
                if padded > MAX_PACKET {
                    return Err(rtcp::EncodeError::Unwritable);
                }
                data.try_reserve_exact(padded)
                    .map_err(|_| rtcp::EncodeError::Unwritable)?;
                for e in elements {
                    if one {
                        data.push(e.id << 4 | (e.data.len() - 1) as u8);
                    } else {
                        data.extend_from_slice(&[e.id, e.data.len() as u8]);
                    }
                    data.extend_from_slice(&e.data);
                }
                data.resize(padded, 0);
            }
            Self::Other { profile, data: raw } => {
                if *profile == ONE_BYTE_PROFILE
                    || *profile & 0xfff0 == TWO_BYTE_PROFILE
                    || !raw.len().is_multiple_of(4)
                    || raw.len() > MAX_PACKET
                {
                    return Err(rtcp::EncodeError::Unwritable);
                }
                data.try_reserve_exact(raw.len())
                    .map_err(|_| rtcp::EncodeError::Unwritable)?;
                data.extend_from_slice(raw);
            }
        }
        Ok((self.profile(), data))
    }
}

/// Reads an extension's data in the form its profile names.
fn parse_extension(profile: u16, data: &[u8]) -> Result<HeaderExtension, RtpError> {
    let two_byte = profile & 0xfff0 == TWO_BYTE_PROFILE;
    if profile != ONE_BYTE_PROFILE && !two_byte {
        return Ok(HeaderExtension::Other {
            profile,
            data: data.to_vec(),
        });
    }
    let mut elements = Vec::new();
    let mut i = 0;
    while let Some(&first) = data.get(i) {
        // In both forms a zero byte is padding (RFC 8285 section 4.2).
        let (id, len, start) = if two_byte {
            if first == 0 {
                i += 1;
                continue;
            }
            let len = *data.get(i + 1).ok_or(RtpError::Extension)?;
            (first, usize::from(len), i + 2)
        } else {
            let id = first >> 4;
            if first == 0 {
                i += 1;
                continue;
            }
            // ID 0 with a length, and ID 15, end processing of the whole
            // extension; the elements before them are kept (RFC 8285
            // section 4.2).
            if id == 0 || id == 15 {
                break;
            }
            (id, usize::from(first & 0x0f) + 1, i + 1)
        };
        let end = start + len;
        let bytes = data.get(start..end).ok_or(RtpError::Extension)?;
        elements.push(Element {
            id,
            data: bytes.to_vec(),
        });
        i = end;
    }
    Ok(if two_byte {
        HeaderExtension::TwoByte {
            app_bits: (profile & 0x0f) as u8,
            elements,
        }
    } else {
        HeaderExtension::OneByte(elements)
    })
}

/// Whether a datagram on a port that carries both RTP and RTCP is RTCP.
/// RFC 5761 tells them apart by the second byte: 192 to 223 is an RTCP
/// packet type.
pub fn is_rtcp(b: &[u8]) -> bool {
    matches!(b.get(1), Some(192..=223))
}

/// A datagram from a port that carries both RTP and RTCP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// An RTP packet.
    Rtp(RtpPacket),
    /// An RTCP datagram.
    Rtcp(rtcp::Datagram),
}

/// Why a datagram is neither RTP nor RTCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// It looked like RTP and did not read.
    Rtp(RtpError),
    /// It looked like RTCP and did not read.
    Rtcp(rtcp::ParseError),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::Rtp(e) => e.fmt(f),
            PacketError::Rtcp(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PacketError {}

impl Wire for Packet {
    type ParseError = PacketError;
    type WriteError = rtcp::EncodeError;
    /// Reads a datagram as RTCP if [`is_rtcp`] says so, and as RTP
    /// otherwise.
    /// Refuses any datagram rejected by its RTP or RTCP reader, and RTCP
    /// padding on a packet other than the last.
    fn parse(b: &[u8]) -> Result<Packet, PacketError> {
        if is_rtcp(b) {
            let datagram = rtcp::Datagram::parse(b).map_err(PacketError::Rtcp)?;
            if has_early_padding(&datagram) {
                return Err(PacketError::Rtcp(rtcp::ParseError::Padding));
            }
            Ok(Packet::Rtcp(datagram))
        } else {
            RtpPacket::parse(b)
                .map(Packet::Rtp)
                .map_err(PacketError::Rtp)
        }
    }

    /// Appends a multiplexed datagram. Refuses invalid packets and values
    /// whose second byte would select the other protocol, or whose RTCP
    /// padding appears on a packet other than the last.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), rtcp::EncodeError> {
        let bytes = match self {
            Self::Rtp(p) => p.to_bytes()?,
            Self::Rtcp(p) => {
                if has_early_padding(p) {
                    return Err(rtcp::EncodeError::Unwritable);
                }
                p.to_bytes()?
            }
        };
        if is_rtcp(&bytes) != matches!(self, Self::Rtcp(_)) {
            return Err(rtcp::EncodeError::Unwritable);
        }
        out.try_reserve_exact(bytes.len())
            .map_err(|_| rtcp::EncodeError::Unwritable)?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Whether RTCP padding appears before the last packet in a datagram.
fn has_early_padding(datagram: &rtcp::Datagram) -> bool {
    datagram.0.split_last().is_some_and(|(_, earlier)| {
        earlier.iter().any(|packet| packet.padding != 0)
    })
}

/// Reads big-endian numbers from a slice, giving `None` past its end.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = self.b.get(self.pos..).unwrap_or(&[]);
        self.pos = self.b.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        contract,
        test_support::{Lcg, mutate, decode_all},
    };
    fn rtp(payload: &[u8]) -> RtpPacket {
        RtpPacket {
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 2,
            ssrc: 3,
            csrcs: vec![],
            extension: None,
            payload: payload.to_vec(),
            padding: 0,
        }
    }

    #[test]
    fn rtp_fixed_header() {
        let b = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3,
        ];
        let p = RtpPacket::parse(&b).unwrap();
        assert_eq!(p.payload_type, 0);
        assert!(!p.marker);
        assert_eq!((p.sequence, p.timestamp, p.ssrc), (1, 160, 0xdead_beef));
        assert_eq!(p.payload, [1, 2, 3]);
        assert_eq!(p.to_bytes().unwrap(), b);
        assert!(!is_rtcp(&b));
        assert_eq!(Packet::parse(&b), Ok(Packet::Rtp(p)));
    }

    #[test]
    fn rtp_csrcs_and_padding() {
        let mut b = vec![0xa2, 0xe0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 2];
        b.extend_from_slice(&[0, 0, 0, 10, 0, 0, 0, 11]);
        b.extend_from_slice(&[0x55, 0x66]);
        b.extend_from_slice(&[0, 0, 3]);
        let p = RtpPacket::parse(&b).unwrap();
        assert!(p.marker);
        assert_eq!(p.payload_type, 0x60);
        assert_eq!(p.csrcs, [10, 11]);
        assert_eq!(p.payload, [0x55, 0x66]);
        assert_eq!(p.padding, 3);
        assert_eq!(p.to_bytes().unwrap(), b);
        // Padding that is all of the payload.
        let mut q = rtp(&[]);
        q.padding = 255;
        let bytes = q.to_bytes().unwrap();
        assert_eq!(bytes.len(), 12 + 255);
        assert_eq!(RtpPacket::parse(&bytes), Ok(q));
    }

    #[test]
    fn rtp_one_byte_extension_rfc8285() {
        // RFC 8285 section 4.2's layout: ID 1 with one byte, ID 2 with two,
        // two bytes of padding, ID 3 with four, then padding.
        let mut b = vec![0x90, 0x60, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        b.extend_from_slice(&[0xbe, 0xde, 0, 3]);
        b.extend_from_slice(&[0x10, 0xaa, 0x21, 0xbb, 0xbb, 0, 0, 0x33, 1, 2, 3, 4]);
        b.push(0x77);
        let p = RtpPacket::parse(&b).unwrap();
        let ext = p.extension.as_ref().unwrap();
        assert_eq!(
            ext,
            &HeaderExtension::OneByte(vec![
                Element {
                    id: 1,
                    data: vec![0xaa]
                },
                Element {
                    id: 2,
                    data: vec![0xbb, 0xbb]
                },
                Element {
                    id: 3,
                    data: vec![1, 2, 3, 4]
                },
            ])
        );
        assert_eq!(ext.get(2).unwrap().data, [0xbb, 0xbb]);
        assert_eq!(ext.get(9), None);
        assert_eq!(p.payload, [0x77]);
        // The writer packs the elements without the padding between them.
        let out = p.to_bytes().unwrap();
        assert_eq!(&out[12..16], &[0xbe, 0xde, 0, 3]);
        assert_eq!(
            &out[16..28],
            &[0x10, 0xaa, 0x21, 0xbb, 0xbb, 0x33, 1, 2, 3, 4, 0, 0]
        );
        assert_eq!(RtpPacket::parse(&out), Ok(p));
    }

    #[test]
    fn rtp_one_byte_id_15_ends_the_extension() {
        let mut b = vec![0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        b.extend_from_slice(&[
            0xbe, 0xde, 0, 2, 0x10, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);
        let p = RtpPacket::parse(&b).unwrap();
        assert_eq!(
            p.extension,
            Some(HeaderExtension::OneByte(vec![Element {
                id: 1,
                data: vec![0xaa]
            }]))
        );
        assert_eq!(RtpPacket::parse(&p.to_bytes().unwrap()), Ok(p));
    }

    #[test]
    fn rtp_two_byte_extension() {
        let mut b = vec![0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        b.extend_from_slice(&[
            0x10, 0x05, 0, 2, 0x01, 0x00, 0, 0x20, 0x03, 0xa1, 0xa2, 0xa3,
        ]);
        let p = RtpPacket::parse(&b).unwrap();
        assert_eq!(
            p.extension,
            Some(HeaderExtension::TwoByte {
                app_bits: 5,
                elements: vec![
                    Element {
                        id: 1,
                        data: vec![]
                    },
                    Element {
                        id: 0x20,
                        data: vec![0xa1, 0xa2, 0xa3]
                    }
                ],
            })
        );
        assert_eq!(p.extension.as_ref().unwrap().profile(), 0x1005);
        // The padding byte between the elements is dropped.
        let out = p.to_bytes().unwrap();
        assert_eq!(
            &out[12..24],
            &[
                0x10, 0x05, 0, 2, 0x01, 0x00, 0x20, 0x03, 0xa1, 0xa2, 0xa3, 0
            ]
        );
        assert_eq!(RtpPacket::parse(&out), Ok(p));
    }

    #[test]
    fn rtp_errors() {
        let good = [0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(RtpPacket::parse(&[]), Err(RtpError::Truncated));
        assert_eq!(RtpPacket::parse(&[0x80]), Err(RtpError::Truncated));
        assert_eq!(RtpPacket::parse(&good[..11]), Err(RtpError::Truncated));
        assert_eq!(
            RtpPacket::parse(&[0x40, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]),
            Err(RtpError::Version(1))
        );
        assert_eq!(RtpPacket::parse(&[0x00]), Err(RtpError::Version(0)));
        let mut long = good.to_vec();
        long.resize(MAX_PACKET + 1, 0);
        assert_eq!(
            RtpPacket::parse(&long),
            Err(RtpError::TooLong(MAX_PACKET + 1))
        );
        long.pop();
        assert!(RtpPacket::parse(&long).is_ok());
        // A CSRC count with no CSRCs.
        assert_eq!(
            RtpPacket::parse(&[0x81, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]),
            Err(RtpError::Truncated)
        );
        // An extension header with no extension, and one cut short.
        assert_eq!(
            RtpPacket::parse(&[0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe]),
            Err(RtpError::Truncated)
        );
        assert_eq!(
            RtpPacket::parse(&[
                0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe, 0xde, 0, 1, 0x10
            ]),
            Err(RtpError::Truncated)
        );
        // Padding count 0, and one that runs into the header.
        assert_eq!(
            RtpPacket::parse(&[0xa0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
            Err(RtpError::Padding)
        );
        assert_eq!(
            RtpPacket::parse(&[0xa0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 7, 3]),
            Err(RtpError::Padding)
        );
        assert_eq!(
            RtpPacket::parse(&[0xa0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]),
            Err(RtpError::Padding)
        );
        // Elements past the extension's end, in both forms.
        let one = [
            0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xbe, 0xde, 0, 1, 0x10, 1, 0x23, 1,
        ];
        assert_eq!(RtpPacket::parse(&one), Err(RtpError::Extension));
        let two = [
            0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0x10, 0x00, 0, 1, 0, 0, 0, 1,
        ];
        assert_eq!(RtpPacket::parse(&two), Err(RtpError::Extension));
        let two = [
            0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0x10, 0x00, 0, 1, 1, 3, 0, 0,
        ];
        assert_eq!(RtpPacket::parse(&two), Err(RtpError::Extension));
        for e in [
            RtpError::Truncated,
            RtpError::Version(3),
            RtpError::TooLong(70000),
            RtpError::Padding,
            RtpError::Extension,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn rtp_truncated_prefixes() {
        let mut p = rtp(&[1, 2, 3, 4]);
        p.csrcs = vec![9, 10];
        p.extension = Some(HeaderExtension::OneByte(vec![Element {
            id: 3,
            data: vec![5, 6, 7],
        }]));
        let b = p.to_bytes().unwrap();
        let header = 12 + 8 + 4 + 4;
        for n in 0..b.len() {
            let r = RtpPacket::parse(&b[..n]);
            if n < header {
                assert_eq!(r, Err(RtpError::Truncated), "{n} bytes");
            } else {
                assert_eq!(r.unwrap().payload, b[header..n]);
            }
        }
        p.padding = 4;
        let b = p.to_bytes().unwrap();
        for n in 0..b.len() {
            // Never a panic; a prefix's last byte is not the count.
            let _ = RtpPacket::parse(&b[..n]);
        }
    }

    #[test]
    fn review_one_byte_id_0_with_a_length_ends_the_extension() {
        // RFC 8285 section 4.2: an element with ID 0 and a nonzero length
        // ends processing of the extension; the elements before it stay.
        let mut b = vec![0x90, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        b.extend_from_slice(&[0xbe, 0xde, 0, 1, 0x10, 0xaa, 0x05, 0x00, 0x77]);
        let p = RtpPacket::parse(&b).unwrap();
        assert_eq!(
            p.extension,
            Some(HeaderExtension::OneByte(vec![Element {
                id: 1,
                data: vec![0xaa]
            }]))
        );
        assert_eq!(p.payload, [0x77]);
        assert_eq!(RtpPacket::parse(&p.to_bytes().unwrap()), Ok(p));
        // At the start, it leaves no elements; what follows is not read.
        b[16..20].copy_from_slice(&[0x05, 0x1f, 0xff, 0xff]);
        let p = RtpPacket::parse(&b).unwrap();
        assert_eq!(p.extension, Some(HeaderExtension::OneByte(vec![])));
        // A zero byte is still padding.
        b[16..20].copy_from_slice(&[0, 0x10, 0xaa, 0]);
        assert_eq!(
            RtpPacket::parse(&b)
                .unwrap()
                .extension
                .unwrap()
                .get(1)
                .unwrap()
                .data,
            [0xaa]
        );
    }

    #[test]
    fn rfc5761_demultiplexing() {
        for pt in 0..=255u8 {
            assert_eq!(is_rtcp(&[0x80, pt]), (192..=223).contains(&pt), "{pt}");
        }
        assert!(!is_rtcp(&[0x80]));
        // An RTP packet with payload type 72 and the marker set looks like
        // an SR, as RFC 5761 warns.
        let mut p = rtp(&[]);
        p.marker = true;
        p.payload_type = 72;
        assert!(is_rtcp(&p.to_bytes().unwrap()));
    }

    #[test]
    fn review_marked_payload_types_64_to_95_read_as_rtcp() {
        // RFC 5761 section 4: these payload types clash with RTCP types
        // when the marker is set, so Packet::parse reads them as RTCP.
        // RtpPacket::parse still reads them as RTP.
        for pt in 64..=95u8 {
            let mut p = rtp(&[0; 8]);
            p.marker = true;
            p.payload_type = pt;
            let b = p.to_bytes().unwrap();
            assert!(is_rtcp(&b), "{pt}");
            assert!(!matches!(Packet::parse(&b), Ok(Packet::Rtp(_))));
            assert_eq!(RtpPacket::parse(&b), Ok(p.clone()));
            p.marker = false;
            assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(Packet::Rtp(p)));
        }
    }

    #[test]
    fn rtp_other_extension() {
        let mut p = rtp(&[1]);
        p.extension = Some(HeaderExtension::Other {
            profile: 0xabcd,
            data: vec![1, 2, 3, 4, 5],
        });
        assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        p.extension = Some(HeaderExtension::Other {
            profile: 0xabcd,
            data: vec![1, 2, 3, 4, 5, 0, 0, 0],
        });
        let bytes = p.to_bytes().unwrap();
        assert_eq!(&bytes[12..24], &[0xab, 0xcd, 0, 2, 1, 2, 3, 4, 5, 0, 0, 0]);
        assert_eq!(RtpPacket::parse(&bytes), Ok(p.clone()));
        assert_eq!(p.extension.as_ref().unwrap().get(1), None);
        for data in [vec![0x1f, 0, 0, 0], vec![0x10, 7, 0, 0]] {
            p.extension = Some(HeaderExtension::Other {
                profile: ONE_BYTE_PROFILE,
                data,
            });
            assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        }
    }

    #[test]
    fn rtp_writer_refuses_clipping() {
        let mut p = rtp(&[]);
        p.payload_type = 128;
        contract::check_wire_value(&p);
        assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        p.payload_type = 127;
        p.csrcs = vec![0; 16];
        assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        p.csrcs = vec![0; 15];
        for e in [
            Element {
                id: 0,
                data: vec![1],
            },
            Element {
                id: 15,
                data: vec![1],
            },
            Element {
                id: 1,
                data: vec![],
            },
            Element {
                id: 2,
                data: vec![0; 17],
            },
        ] {
            p.extension = Some(HeaderExtension::OneByte(vec![e]));
            assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        }
        p.extension = Some(HeaderExtension::OneByte(vec![Element {
            id: 14,
            data: vec![0; 16],
        }]));
        assert!(p.to_bytes().is_ok());
        contract::check_wire_value(&p);
        for (app_bits, element) in [
            (
                16,
                Element {
                    id: 1,
                    data: vec![],
                },
            ),
            (
                0,
                Element {
                    id: 0,
                    data: vec![],
                },
            ),
            (
                0,
                Element {
                    id: 9,
                    data: vec![0; 256],
                },
            ),
        ] {
            p.extension = Some(HeaderExtension::TwoByte {
                app_bits,
                elements: vec![element],
            });
            assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        }
        p.extension = Some(HeaderExtension::TwoByte {
            app_bits: 0,
            elements: (1..=255)
                .map(|id| Element {
                    id,
                    data: vec![id; 255],
                })
                .collect(),
        });
        assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        p.extension = Some(HeaderExtension::Other {
            profile: 1,
            data: vec![0; 300_000],
        });
        assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
        p.extension = None;
        p.payload = vec![0; 100_000];
        assert_eq!(p.to_bytes(), Err(rtcp::EncodeError::Unwritable));
    }

    #[test]
    fn stream_splits_packets_and_null_frames() {
        let a = rtcp::Frame::from_packet(&rtp(&[1])).unwrap();
        let bytes = [
            rtcp::Frame(vec![]).to_bytes().unwrap(),
            a.to_bytes().unwrap(),
            rtcp::Frame(vec![]).to_bytes().unwrap(),
        ]
        .concat();
        contract::check_decode_with_alloc_limit(rtcp::Frames::new, &bytes, 2 * (MAX_PACKET + 2));
        let (items, error) = decode_all(rtcp::Frames::new, &bytes);
        assert_eq!(error, None);
        assert_eq!(items, [rtcp::Frame(vec![]), a.clone(), rtcp::Frame(vec![])]);
        assert_eq!(Packet::parse(&items[1].0), Ok(Packet::Rtp(rtp(&[1]))));
        let large = rtcp::Frame(vec![1; MAX_PACKET]).to_bytes().unwrap();
        contract::check_decode_with_alloc_limit(rtcp::Frames::new, &large, 2 * (MAX_PACKET + 2));
        assert_eq!(
            rtcp::Frame(vec![1; MAX_PACKET + 1]).to_bytes(),
            Err(rtcp::EncodeError::Unwritable)
        );
        let many = a.to_bytes().unwrap().repeat(200_000);
        let started = std::time::Instant::now();
        let (items, error) = decode_all(rtcp::Frames::new, &many);
        // Allow slow test hosts while catching repeated scans or front removal.
        assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
        assert_eq!(items.len(), 200_000);
        assert_eq!(error, None);
    }

    #[test]
    fn fuzz_parsers_and_writers() {
        use rtcp::{Body, SenderReport, ReceiverReport, SdesChunk, SdesItem, Bye, App,
            TransportFeedback, TransportMessage, Nack, PayloadFeedback, PayloadMessage,
            ExtendedReport, XrBlock};

        let control = rtcp::Compound(vec![
            Body::SenderReport(SenderReport {
                ssrc: 1, ntp_timestamp: 2, rtp_timestamp: 3, packet_count: 4,
                octet_count: 5, reports: vec![], extension: vec![],
            }).into(),
            Body::ReceiverReport(ReceiverReport {
                ssrc: 1, reports: vec![], extension: vec![],
            }).into(),
            Body::SourceDescription(vec![SdesChunk {
                ssrc: 1, items: vec![SdesItem { kind: rtcp::sdes::CNAME, text: b"a@b".to_vec() }],
            }]).into(),
            Body::App(App { subtype: 3, ssrc: 1, name: *b"TEST", data: vec![0; 4] }).into(),
            Body::TransportFeedback(TransportFeedback {
                sender_ssrc: 1, media_ssrc: 2,
                message: TransportMessage::Nack(vec![Nack { pid: 3, blp: 5 }]),
            }).into(),
            Body::PayloadFeedback(PayloadFeedback {
                sender_ssrc: 1, media_ssrc: 2, message: PayloadMessage::Pli,
            }).into(),
            Body::ExtendedReport(ExtendedReport {
                ssrc: 1, blocks: vec![XrBlock::receiver_reference_time(2)],
            }).into(),
            Body::Other { packet_type: 208, count: 3, data: vec![1; 4] }.into(),
            Body::Bye(Bye { sources: vec![1], reason: Some(b"bye".to_vec()) }).into(),
        ]);
        let mut seeds = vec![control.to_bytes().unwrap()];
        seeds.extend(control.0.iter().map(|packet| packet.to_bytes().unwrap()));
        for extension in [
            None,
            Some(HeaderExtension::OneByte(vec![
                Element { id: 1, data: vec![2] }, Element { id: 14, data: vec![3; 16] },
            ])),
            Some(HeaderExtension::TwoByte { app_bits: 7, elements: vec![
                Element { id: 1, data: vec![] }, Element { id: 255, data: vec![4; 255] },
            ] }),
            Some(HeaderExtension::Other { profile: 123, data: vec![5; 8] }),
        ] {
            let mut packet = rtp(&[1, 2, 3]);
            packet.extension = extension;
            seeds.push(packet.to_bytes().unwrap());
        }
        for seed in &seeds {
            assert!(Packet::parse(seed).is_ok());
            contract::check_wire::<Packet>(seed);
        }
        let stream: Vec<u8> = seeds.iter()
            .flat_map(|bytes| rtcp::Frame(bytes.clone()).to_bytes().unwrap()).collect();
        seeds.push(stream);
        let mut rng = Lcg::new(42);
        for _ in 0..5_000 {
            let mut bytes = if rng.coin() {
                rng.bytes(200)
            } else {
                seeds[rng.index(seeds.len())].clone()
            };
            for _ in 0..2 {
                if rng.index(4) != 0 && let Some(first) = bytes.first_mut() {
                    *first = (*first & 0x3f) | (VERSION << 6);
                }
                contract::check_wire::<RtpPacket>(&bytes);
                contract::check_wire::<Packet>(&bytes);
                contract::check_decode_with_alloc_limit(rtcp::Frames::new, &bytes, 2 * (MAX_PACKET + 2));
                mutate(&mut rng, &mut bytes);
            }
            let mut p = rtp(&rng.bytes(40));
            if rng.index(100) == 0 {
                p.payload = vec![0; MAX_PACKET + 1];
            }
            p.marker = rng.coin();
            p.payload_type = rng.next() as u8;
            p.csrcs = (0..rng.index(20)).map(|_| rng.next() as u32).collect();
            p.padding = rng.next() as u8;
            p.extension = match rng.index(4) {
                0 => None,
                1 => Some(HeaderExtension::OneByte((0..rng.index(8)).map(|_| Element {
                    id: rng.index(17) as u8,
                    data: rng.bytes(20),
                }).collect())),
                2 => Some(HeaderExtension::TwoByte {
                    app_bits: rng.index(20) as u8,
                    elements: (0..rng.index(8)).map(|_| Element {
                        id: rng.next() as u8,
                        data: rng.bytes(260),
                    }).collect(),
                }),
                _ => Some(HeaderExtension::Other {
                    profile: match rng.index(3) {
                        0 => ONE_BYTE_PROFILE,
                        1 => TWO_BYTE_PROFILE | rng.index(16) as u16,
                        _ => rng.next() as u16,
                    },
                    data: rng.bytes(24),
                }),
            };
            contract::check_wire_value(&p);
            contract::check_wire_value(&Packet::Rtp(p));
        }
    }
}
