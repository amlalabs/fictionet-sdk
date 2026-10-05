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
//! An RTP packet is an [`RtpPacket`]. It may list contributing sources
//! (CSRCs), carry padding, and carry a [`HeaderExtension`] in the one-byte
//! or two-byte form of RFC 8285. An RTCP datagram holds one or more RTCP
//! packets back to back, read by [`parse_packets`] into [`RtcpPacket`]s and
//! written by [`write_packets`]. RFC 3550 calls such a datagram a compound
//! packet and sets rules for it: it starts with a sender or receiver report
//! and it carries an SDES CNAME. [`parse_compound`] reads a datagram and
//! checks those rules, [`check_compound`] checks packets a world is about
//! to send, and [`write_compound`] writes them and checks the bytes.
//!
//! Nothing here reads a socket. A world that plays a media server takes
//! each UDP datagram it receives, reads it with [`Packet::parse`], which
//! tells RTP from RTCP as RFC 5761 does, and sends the bytes of what it
//! answers. Over TCP, a [`Decoder`] splits the byte stream into packets
//! first, and [`frame`] puts the length in front of each packet sent.
//! What the media holds, and what a report should say, is up to world code.
//! SRTP and SRTCP encryption are not handled here.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. Writers clamp what they write, so the bytes they make
//! always read back.
//!
//! New stream stacks use the shared [`Frames`] and [`Frame`] from
//! [`super::rtcp`]. [`RtpPacket`] implements [`super::codec::Wire`] for
//! strict datagram writing. The legacy [`Decoder`] keeps its larger
//! [`MAX_BUFFERED`] read-ahead limit. Existing RTCP items stay available;
//! new RTCP codec stacks use the richer [`super::rtcp`] types.
//!
//! ```
//! use fictionet::stdlib::rtp::{
//!     Element, HeaderExtension, Packet, ReceiverReport, ReportBlock, RtcpPacket, RtpPacket, SdesChunk,
//!     SdesItem, parse_compound, sdes, write_packets,
//! };
//!
//! // An audio packet with its level in a one-byte header extension.
//! let packet = RtpPacket {
//!     marker: true,
//!     payload_type: 111,
//!     sequence: 0x1234,
//!     timestamp: 160,
//!     ssrc: 0x1234_5678,
//!     csrcs: vec![],
//!     extension: Some(HeaderExtension::OneByte(vec![Element { id: 1, data: vec![0x9e] }])),
//!     payload: vec![0xf8, 0xff, 0xfe],
//!     padding: 0,
//! };
//! let bytes = packet.to_bytes();
//! assert_eq!(&bytes[..4], &[0x90, 0xef, 0x12, 0x34]);
//! // The extension: the one-byte profile, one word of elements, then
//! // element 1 with one byte of data and two bytes of padding.
//! assert_eq!(&bytes[12..20], &[0xbe, 0xde, 0, 1, 0x10, 0x9e, 0, 0]);
//! assert_eq!(Packet::parse(&bytes), Ok(Packet::Rtp(packet)));
//!
//! // The receiver's report on that source, with its CNAME.
//! let report = vec![
//!     RtcpPacket::ReceiverReport(ReceiverReport {
//!         ssrc: 0xaaaa_aaaa,
//!         reports: vec![ReportBlock {
//!             ssrc: 0x1234_5678,
//!             fraction_lost: 0,
//!             cumulative_lost: 0,
//!             highest_sequence: 0x1234,
//!             jitter: 0,
//!             last_sr: 0,
//!             delay_since_last_sr: 0,
//!         }],
//!         extension: vec![],
//!     }),
//!     RtcpPacket::SourceDescription(vec![SdesChunk {
//!         ssrc: 0xaaaa_aaaa,
//!         items: vec![SdesItem { kind: sdes::CNAME, text: b"agent@example".to_vec() }],
//!     }]),
//! ];
//! let bytes = write_packets(&report);
//! // A 32-byte receiver report, then a 24-byte SDES packet.
//! assert_eq!(bytes.len(), 56);
//! assert_eq!(&bytes[..4], &[0x81, 201, 0, 7]);
//! assert_eq!(parse_compound(&bytes), Ok(report));
//! ```

/// The RTP version every packet carries, in its top two bits.
pub const VERSION: u8 = 2;
/// The longest RTP or RTCP packet a reader takes: the most a 16-bit length
/// can say, as in RFC 4571 framing. A UDP datagram is never longer.
pub const MAX_PACKET: usize = 65535;
/// The longest single RTCP packet a writer makes: the longest length,
/// counted in 32-bit words, that fits in [`MAX_PACKET`].
pub const MAX_RTCP_PACKET: usize = 65532;
/// The length of the fixed RTP header, before the CSRCs.
pub const RTP_HEADER_LEN: usize = 12;
/// The length of the RTCP header that starts every RTCP packet.
pub const RTCP_HEADER_LEN: usize = 4;
/// The most CSRCs an RTP header can list: its 4-bit count.
pub const MAX_CSRCS: usize = 15;
/// The most items a 5-bit RTCP count can say: report blocks in a report,
/// chunks in an SDES packet, sources in a BYE.
pub const MAX_COUNT: usize = 31;
/// The length of one report block.
pub const REPORT_BLOCK_LEN: usize = 24;
/// The longest SDES item text and the longest BYE reason: an 8-bit length.
pub const MAX_TEXT: usize = 255;
/// The longest element data in the one-byte header extension form.
pub const MAX_ONE_BYTE_DATA: usize = 16;
/// The longest element data in the two-byte header extension form.
pub const MAX_TWO_BYTE_DATA: usize = 255;
/// The profile value that marks the one-byte header extension form.
pub const ONE_BYTE_PROFILE: u16 = 0xbede;
/// The profile value of the two-byte form, with its 4 application bits
/// zero.
pub const TWO_BYTE_PROFILE: u16 = 0x1000;
/// The lowest cumulative loss a report block can carry: a signed 24-bit
/// number.
pub const MIN_CUMULATIVE_LOST: i32 = -(1 << 23);
/// The highest cumulative loss a report block can carry.
pub const MAX_CUMULATIVE_LOST: i32 = (1 << 23) - 1;
/// The most bytes a [`Decoder`] holds that have not been taken out: two
/// of the longest RFC 4571 frames, each a 2-byte length and a packet.
pub const MAX_BUFFERED: usize = 2 * (2 + MAX_PACKET);

/// RTCP packet types, from RFC 3550 and RFC 4585.
pub mod packet_type {
    /// Sender report.
    pub const SR: u8 = 200;
    /// Receiver report.
    pub const RR: u8 = 201;
    /// Source description.
    pub const SDES: u8 = 202;
    /// Goodbye: a source is leaving.
    pub const BYE: u8 = 203;
    /// Application-defined.
    pub const APP: u8 = 204;
    /// Transport-layer feedback, such as a NACK.
    pub const RTPFB: u8 = 205;
    /// Payload-specific feedback, such as a picture loss indication.
    pub const PSFB: u8 = 206;
}

/// SDES item types, from RFC 3550 section 6.5.
pub mod sdes {
    /// Ends the item list of a chunk. A writer adds it; it is never an item.
    pub const END: u8 = 0;
    /// Canonical name, such as `user@host`. Every compound packet needs one.
    pub const CNAME: u8 = 1;
    /// A person's name.
    pub const NAME: u8 = 2;
    /// An email address.
    pub const EMAIL: u8 = 3;
    /// A phone number.
    pub const PHONE: u8 = 4;
    /// A location.
    pub const LOC: u8 = 5;
    /// The application or tool that sends.
    pub const TOOL: u8 = 6;
    /// A short note on the source's state.
    pub const NOTE: u8 = 7;
    /// A private extension: a prefix length, a prefix, then a value.
    pub const PRIV: u8 = 8;
}

/// Feedback message types (the FMT field), from RFC 4585 section 6.
pub mod feedback {
    /// Transport-layer feedback 1: generic NACK.
    pub const NACK: u8 = 1;
    /// Payload-specific feedback 1: picture loss indication.
    pub const PLI: u8 = 1;
    /// Payload-specific feedback 2: slice loss indication.
    pub const SLI: u8 = 2;
    /// Payload-specific feedback 3: reference picture selection indication.
    pub const RPSI: u8 = 3;
    /// Payload-specific feedback 15: application-layer feedback.
    pub const AFB: u8 = 15;
}

// ---------------------------------------------------------------------------
// RTP

use super::codec::Wire;

/// The shared RFC 4571 envelope, including null frames.
pub use super::rtcp::Frame;
/// A shared RFC 4571 payload length error.
pub use super::rtcp::FrameError;
/// An exact RFC 4571 envelope parse error.
pub use super::rtcp::FrameParseError;
/// The shared RFC 4571 framer for RTP and RTCP datagrams.
pub use super::rtcp::Frames;

/// One RTP packet: the header's fields, the extension and the payload.
/// The version is always 2, and the padding, extension and CSRC count bits
/// are worked out from the other fields, so none of them is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpPacket {
    /// The marker bit. Its meaning is up to the profile; for video it often
    /// marks the last packet of a frame.
    pub marker: bool,
    /// The payload type, 0 to 127, which names the codec as SDP mapped it.
    /// A writer keeps the low 7 bits. With RTP and RTCP on one port, RFC
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
    /// writer keeps the first [`MAX_CSRCS`].
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
    /// length, keeping the elements before it. A writer leaves out
    /// elements that break these limits.
    OneByte(Vec<Element>),
    /// The two-byte form of RFC 8285 (profile `0x100X`). Each element has
    /// an ID from 1 to 255 and 0 to 255 bytes of data. A writer leaves out
    /// elements that break these limits.
    TwoByte {
        /// The 4 application bits in the profile's low bits. A writer keeps
        /// the low 4 bits.
        app_bits: u8,
        /// The elements, in order, without padding.
        elements: Vec<Element>,
    },
    /// Any other extension, kept as bytes.
    Other {
        /// The 16-bit profile value that names the extension.
        profile: u16,
        /// The extension's data. A reader gives a multiple of 4 bytes; a
        /// writer pads with zeros to one.
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

impl RtpPacket {
    /// Reads the RTP packet in `b`, a whole datagram.
    pub fn parse(b: &[u8]) -> Result<RtpPacket, RtpError> {
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

    /// The packet's bytes. Fields are clamped as each one's doc says, and
    /// the payload is cut so the packet fits in [`MAX_PACKET`] bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let csrcs = &self.csrcs[..self.csrcs.len().min(MAX_CSRCS)];
        let padding = usize::from(self.padding);
        let mut b0 = VERSION << 6 | csrcs.len() as u8;
        if padding > 0 {
            b0 |= 0x20;
        }
        if self.extension.is_some() {
            b0 |= 0x10;
        }
        let header = RTP_HEADER_LEN + 4 * csrcs.len();
        // The header is at most 72 bytes, so this never underflows.
        let extension = self
            .extension
            .as_ref()
            .map(|ext| ext.encode((MAX_PACKET - header - padding - 4) / 4 * 4));
        let ext_len = extension.as_ref().map_or(0, |(_, data)| 4 + data.len());
        let payload = &self.payload[..self
            .payload
            .len()
            .min(MAX_PACKET - header - ext_len - padding)];
        // The exact length, so the buffer is never larger than MAX_PACKET.
        let mut out = Vec::with_capacity(header + ext_len + payload.len() + padding);
        out.push(b0);
        out.push(u8::from(self.marker) << 7 | self.payload_type & 0x7f);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for c in csrcs {
            out.extend_from_slice(&c.to_be_bytes());
        }
        if let Some((profile, data)) = &extension {
            out.extend_from_slice(&profile.to_be_bytes());
            out.extend_from_slice(&((data.len() / 4) as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        out.extend_from_slice(payload);
        if padding > 0 {
            out.resize(out.len() + padding - 1, 0);
            out.push(self.padding);
        }
        out
    }
}

/// An RTP packet cannot be written without changing its value.
///
/// A field exceeds its wire range or [`MAX_PACKET`], an extension element
/// would be omitted, or an extension would parse as another variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeError;

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RTP packet cannot be represented without changing its value")
    }
}

impl core::error::Error for EncodeError {}

impl Wire for RtpPacket {
    type ParseError = RtpError;
    type WriteError = EncodeError;

    fn parse(bytes: &[u8]) -> Result<Self, RtpError> {
        RtpPacket::parse(bytes)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // The legacy writer stages at most MAX_PACKET bytes. Comparing
        // before appending refuses clipping, padding, and variant aliases.
        let bytes = self.to_bytes();
        if RtpPacket::parse(&bytes).as_ref() != Ok(self) {
            return Err(EncodeError);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl HeaderExtension {
    /// The profile value written in front of the extension.
    pub fn profile(&self) -> u16 {
        match self {
            HeaderExtension::OneByte(_) => ONE_BYTE_PROFILE,
            HeaderExtension::TwoByte { app_bits, .. } => {
                TWO_BYTE_PROFILE | u16::from(app_bits & 0x0f)
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

    /// The profile and the data, padded to a multiple of 4 bytes and no
    /// longer than `room`, which is a multiple of 4. Elements that do not
    /// fit are left out. An `Other` whose profile names an RFC 8285 form,
    /// but whose data does not read in that form, is written with no data.
    fn encode(&self, room: usize) -> (u16, Vec<u8>) {
        let profile = self.profile();
        let mut data = Vec::new();
        match self {
            HeaderExtension::OneByte(elements) => {
                for e in elements {
                    let ok =
                        (1..=14).contains(&e.id) && (1..=MAX_ONE_BYTE_DATA).contains(&e.data.len());
                    if ok && data.len() + 1 + e.data.len() <= room {
                        data.push(e.id << 4 | (e.data.len() - 1) as u8);
                        data.extend_from_slice(&e.data);
                    }
                }
            }
            HeaderExtension::TwoByte { elements, .. } => {
                for e in elements {
                    let ok = e.id != 0 && e.data.len() <= MAX_TWO_BYTE_DATA;
                    if ok && data.len() + 2 + e.data.len() <= room {
                        data.push(e.id);
                        data.push(e.data.len() as u8);
                        data.extend_from_slice(&e.data);
                    }
                }
            }
            HeaderExtension::Other { data: raw, .. } => {
                data.extend_from_slice(&raw[..raw.len().min(room)]);
            }
        }
        data.resize(data.len().div_ceil(4) * 4, 0);
        if matches!(self, HeaderExtension::Other { .. }) && parse_extension(profile, &data).is_err()
        {
            data.clear();
        }
        (profile, data)
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

// ---------------------------------------------------------------------------
// RTCP

/// One RTCP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RtcpPacket {
    /// Type 200: a sender's report on what it sent and what it received.
    SenderReport(SenderReport),
    /// Type 201: a receiver's report on what it received.
    ReceiverReport(ReceiverReport),
    /// Type 202: items that describe sources, one chunk per source. A
    /// writer keeps the first [`MAX_COUNT`] chunks, and leaves out items
    /// once the packet would pass [`MAX_RTCP_PACKET`] bytes.
    SourceDescription(Vec<SdesChunk>),
    /// Type 203: sources that are leaving.
    Bye(Bye),
    /// Type 204: an application-defined packet.
    App(App),
    /// Types 205 and 206: a feedback message from RFC 4585.
    Feedback(Feedback),
    /// Any other packet type, with its body unread.
    Other {
        /// The packet type.
        packet_type: u8,
        /// The 5-bit count field. A writer keeps the low 5 bits.
        count: u8,
        /// The body after the 4-byte header, without padding. A reader
        /// gives a multiple of 4 bytes; a writer pads with zeros to one.
        body: Vec<u8>,
    },
}

/// A sender report (RFC 3550 section 6.4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReport {
    /// The sender's SSRC.
    pub ssrc: u32,
    /// When the report was sent, as a 64-bit NTP timestamp.
    pub ntp_timestamp: u64,
    /// The same instant in the RTP timestamp clock.
    pub rtp_timestamp: u32,
    /// How many RTP packets the sender has sent.
    pub packet_count: u32,
    /// How many payload bytes the sender has sent.
    pub octet_count: u32,
    /// What the sender received from other sources. A writer keeps the
    /// first [`MAX_COUNT`].
    pub reports: Vec<ReportBlock>,
    /// Profile-specific bytes after the report blocks. A reader gives a
    /// multiple of 4 bytes; a writer pads with zeros to one, and cuts it
    /// so the packet fits in [`MAX_RTCP_PACKET`] bytes.
    pub extension: Vec<u8>,
}

/// A receiver report (RFC 3550 section 6.4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverReport {
    /// The reporter's SSRC.
    pub ssrc: u32,
    /// What the reporter received, one block per source. A writer keeps
    /// the first [`MAX_COUNT`].
    pub reports: Vec<ReportBlock>,
    /// Profile-specific bytes after the report blocks, as in
    /// [`SenderReport::extension`].
    pub extension: Vec<u8>,
}

/// What one receiver saw of one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportBlock {
    /// The source this block reports on.
    pub ssrc: u32,
    /// The share of packets lost since the last report, in 256ths.
    pub fraction_lost: u8,
    /// Packets lost since the start: expected less received. It is a
    /// signed 24-bit number, negative when duplicates arrived. A writer
    /// clamps it to [`MIN_CUMULATIVE_LOST`]..=[`MAX_CUMULATIVE_LOST`].
    pub cumulative_lost: i32,
    /// The highest sequence number received, with the count of wraps in
    /// the top 16 bits.
    pub highest_sequence: u32,
    /// The interarrival jitter, in RTP timestamp units.
    pub jitter: u32,
    /// The middle 32 bits of the NTP timestamp of the source's last sender
    /// report, or 0 if none came.
    pub last_sr: u32,
    /// The time since that sender report, in 65536ths of a second.
    pub delay_since_last_sr: u32,
}

/// One SDES chunk: a source and the items that describe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesChunk {
    /// The source the items describe.
    pub ssrc: u32,
    /// The items, in order.
    pub items: Vec<SdesItem>,
}

/// One SDES item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesItem {
    /// The item type, one of the constants in [`sdes`]. A writer leaves
    /// out items of type 0, which would end the list.
    pub kind: u8,
    /// The item's text, UTF-8 by the specification but kept as bytes. A
    /// writer keeps the first [`MAX_TEXT`] bytes, cutting UTF-8 text at a
    /// character boundary. A PRIV item's text starts with the prefix
    /// length, then the prefix and the value; a reader rejects, and a
    /// writer leaves out, a PRIV item whose prefix length runs past it.
    pub text: Vec<u8>,
}

/// A BYE packet (RFC 3550 section 6.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bye {
    /// The sources that are leaving. A writer keeps the first
    /// [`MAX_COUNT`].
    pub sources: Vec<u32>,
    /// Why they are leaving, if a reason is given. A writer keeps the first
    /// [`MAX_TEXT`] bytes, cutting UTF-8 text at a character boundary.
    pub reason: Option<Vec<u8>>,
}

/// An APP packet (RFC 3550 section 6.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    /// The 5-bit subtype, in the count field. A writer keeps the low 5
    /// bits.
    pub subtype: u8,
    /// The sender's SSRC.
    pub ssrc: u32,
    /// Four ASCII characters that name the application.
    pub name: [u8; 4],
    /// The application's data. A reader gives a multiple of 4 bytes; a
    /// writer pads with zeros to one, and cuts it to fit the packet.
    pub data: Vec<u8>,
}

/// A feedback message (RFC 4585 section 6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feedback {
    /// The SSRC of the source that sends the feedback.
    pub sender_ssrc: u32,
    /// The SSRC of the media source the feedback is about.
    pub media_ssrc: u32,
    /// What the feedback says. It also sets the packet type.
    pub message: FeedbackMessage,
}

/// The kind of feedback and its feedback control information (FCI).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedbackMessage {
    /// Transport-layer FMT 1: these packets were lost. RFC 4585 needs at
    /// least one entry, so a reader rejects an empty list and a writer
    /// writes nothing for one.
    Nack(Vec<Nack>),
    /// Payload-specific FMT 1: the receiver lost part of a picture and
    /// needs a new one. It carries no FCI.
    Pli,
    /// Payload-specific FMT 2: slices of a picture were lost. As with
    /// [`FeedbackMessage::Nack`], the list must not be empty.
    Sli(Vec<Sli>),
    /// Payload-specific FMT 3: the receiver has this reference picture.
    Rpsi(Rpsi),
    /// Payload-specific FMT 15: application-layer feedback, such as REMB,
    /// kept as bytes. A reader gives a multiple of 4 bytes; a writer pads
    /// with zeros to one.
    Afb(Vec<u8>),
    /// Any other transport-layer feedback, with its FCI unread.
    TransportOther {
        /// The 5-bit FMT. A writer keeps the low 5 bits.
        fmt: u8,
        /// The FCI, as in [`FeedbackMessage::Afb`].
        fci: Vec<u8>,
    },
    /// Any other payload-specific feedback, with its FCI unread.
    PayloadOther {
        /// The 5-bit FMT. A writer keeps the low 5 bits.
        fmt: u8,
        /// The FCI, as in [`FeedbackMessage::Afb`].
        fci: Vec<u8>,
    },
}

/// One generic NACK entry (RFC 4585 section 6.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nack {
    /// The sequence number of a lost packet.
    pub pid: u16,
    /// A bitmask of more losses: bit `i` set means packet `pid + i + 1`
    /// was lost too.
    pub blp: u16,
}

impl Nack {
    /// The sequence numbers this entry says were lost, in order.
    pub fn lost(&self) -> Vec<u16> {
        let mut out = vec![self.pid];
        for i in 0..16u16 {
            if self.blp >> i & 1 == 1 {
                out.push(self.pid.wrapping_add(i + 1));
            }
        }
        out
    }
}

/// One slice loss indication entry (RFC 4585 section 6.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sli {
    /// The first lost macroblock, 13 bits. A writer keeps the low 13.
    pub first: u16,
    /// How many macroblocks were lost, 13 bits. A writer keeps the low 13.
    pub number: u16,
    /// The low 6 bits of the picture ID. A writer keeps the low 6.
    pub picture_id: u8,
}

/// A reference picture selection indication (RFC 4585 section 6.3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rpsi {
    /// How many bits at the end of `data` are padding. They are zero: a
    /// reader rejects set padding bits, and a writer clears them.
    pub padding_bits: u8,
    /// The payload type the bit string is for. A writer keeps the low 7
    /// bits.
    pub payload_type: u8,
    /// The codec's own bit string, then the padding bits. A writer pads it
    /// with zero bytes so the FCI is a multiple of 4 bytes, and counts
    /// them in `padding_bits`.
    pub data: Vec<u8>,
}

/// Why bytes are not RTCP, or not a compound packet RFC 3550 allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcpError {
    /// The bytes end before a header, or before the length a header says.
    Truncated,
    /// The bytes are longer than [`MAX_PACKET`].
    TooLong(usize),
    /// A packet's version bits were not 2.
    Version(u8),
    /// A packet that is not the last was padded, or the padding count was
    /// 0, not a multiple of 4, or longer than the body.
    Padding,
    /// The body of a packet of this type does not match its count or its
    /// format.
    Body(u8),
    /// A compound packet held no packets.
    Empty,
    /// A compound packet started with this type, not a sender or receiver
    /// report.
    FirstNotReport(u8),
    /// A compound packet had no SDES CNAME item in an SDES packet right
    /// after its reports.
    NoCname,
}

impl std::fmt::Display for RtcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RtcpError::Truncated => f.write_str("RTCP packet ends before its length says"),
            RtcpError::TooLong(n) => write!(f, "RTCP datagram of {n} bytes, over {MAX_PACKET}"),
            RtcpError::Version(v) => write!(f, "RTCP version {v}, not 2"),
            RtcpError::Padding => f.write_str("RTCP padding is misplaced or its count is wrong"),
            RtcpError::Body(t) => write!(f, "RTCP packet type {t} has a malformed body"),
            RtcpError::Empty => f.write_str("compound RTCP packet is empty"),
            RtcpError::FirstNotReport(t) => {
                write!(f, "compound RTCP packet starts with type {t}, not SR or RR")
            }
            RtcpError::NoCname => {
                f.write_str("compound RTCP packet has no SDES CNAME after its reports")
            }
        }
    }
}

impl std::error::Error for RtcpError {}

/// Reads every RTCP packet in `b`, a whole datagram, in order. Each must
/// be version 2, the lengths must add up to the datagram's length, and
/// only the last packet may be padded. This does not check the compound
/// rules, so it also reads the reduced-size packets of RFC 5506. No bytes
/// at all read as no packets.
pub fn parse_packets(b: &[u8]) -> Result<Vec<RtcpPacket>, RtcpError> {
    if b.len() > MAX_PACKET {
        return Err(RtcpError::TooLong(b.len()));
    }
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let [b0, pt, l0, l1, ..] = *rest else {
            return Err(RtcpError::Truncated);
        };
        let version = b0 >> 6;
        if version != VERSION {
            return Err(RtcpError::Version(version));
        }
        let len = (usize::from(u16::from_be_bytes([l0, l1])) + 1) * 4;
        let packet = rest.get(..len).ok_or(RtcpError::Truncated)?;
        let mut body = &packet[RTCP_HEADER_LEN..];
        if b0 & 0x20 != 0 {
            if len != rest.len() {
                return Err(RtcpError::Padding);
            }
            let n = usize::from(*body.last().ok_or(RtcpError::Padding)?);
            if n == 0 || n % 4 != 0 || n > body.len() {
                return Err(RtcpError::Padding);
            }
            body = &body[..body.len() - n];
        }
        out.push(parse_body(pt, b0 & 0x1f, body)?);
        rest = &rest[len..];
    }
    Ok(out)
}

/// Reads a compound RTCP packet and checks it with [`check_compound`].
pub fn parse_compound(b: &[u8]) -> Result<Vec<RtcpPacket>, RtcpError> {
    let packets = parse_packets(b)?;
    check_compound(&packets)?;
    Ok(packets)
}

/// Checks the rules RFC 3550 section 6.1 sets for a compound packet, in
/// the order it lists them: it holds at least one packet, the first is a
/// sender or receiver report, and any further reports are followed by an
/// SDES packet with a CNAME item, before any packet of another type. Of a
/// run of SDES packets there, one CNAME is enough. Only the first
/// [`MAX_COUNT`] chunks of an SDES packet count, since a writer keeps no
/// more. ([`parse_packets`] checks the rest: versions, lengths and
/// padding.)
pub fn check_compound(packets: &[RtcpPacket]) -> Result<(), RtcpError> {
    let first = packets.first().ok_or(RtcpError::Empty)?;
    if !matches!(
        first,
        RtcpPacket::SenderReport(_) | RtcpPacket::ReceiverReport(_)
    ) {
        return Err(RtcpError::FirstNotReport(first.packet_type()));
    }
    let has_cname = packets
        .iter()
        .skip_while(|p| {
            matches!(
                p,
                RtcpPacket::SenderReport(_) | RtcpPacket::ReceiverReport(_)
            )
        })
        .map_while(|p| match p {
            RtcpPacket::SourceDescription(chunks) => Some(chunks),
            _ => None,
        })
        .any(|chunks| {
            chunks
                .iter()
                .take(MAX_COUNT)
                .any(|c| c.items.iter().any(|i| i.kind == sdes::CNAME))
        });
    if has_cname {
        Ok(())
    } else {
        Err(RtcpError::NoCname)
    }
}

/// The bytes of `packets`, back to back, with no padding. Writing stops
/// before a packet that would take the total past [`MAX_PACKET`], and a
/// packet that writes no bytes is left out. This does not check the
/// compound rules; [`write_compound`] does.
pub fn write_packets(packets: &[RtcpPacket]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        let bytes = p.to_bytes();
        if out.len() + bytes.len() > MAX_PACKET {
            break;
        }
        out.extend_from_slice(&bytes);
    }
    out
}

/// The bytes of a compound packet, as [`write_packets`] makes them, if
/// every packet is written and the bytes pass [`parse_compound`]. It fails
/// with [`RtcpError::Body`] for a packet that writes no bytes, such as a
/// NACK with no entries, with [`RtcpError::TooLong`] when the packets do
/// not fit in [`MAX_PACKET`] bytes, and with the error of
/// [`check_compound`] when what is written breaks a compound rule, as when
/// a writer cut the SDES item with the CNAME.
pub fn write_compound(packets: &[RtcpPacket]) -> Result<Vec<u8>, RtcpError> {
    check_compound(packets)?;
    let mut out = Vec::new();
    for p in packets {
        let bytes = p.to_bytes();
        if bytes.is_empty() {
            return Err(RtcpError::Body(p.packet_type()));
        }
        let total = out.len() + bytes.len();
        if total > MAX_PACKET {
            return Err(RtcpError::TooLong(total));
        }
        out.extend_from_slice(&bytes);
    }
    parse_compound(&out)?;
    Ok(out)
}

impl RtcpPacket {
    /// The packet type written in the header.
    pub fn packet_type(&self) -> u8 {
        match self {
            RtcpPacket::SenderReport(_) => packet_type::SR,
            RtcpPacket::ReceiverReport(_) => packet_type::RR,
            RtcpPacket::SourceDescription(_) => packet_type::SDES,
            RtcpPacket::Bye(_) => packet_type::BYE,
            RtcpPacket::App(_) => packet_type::APP,
            RtcpPacket::Feedback(f) => match f.message {
                FeedbackMessage::Nack(_) | FeedbackMessage::TransportOther { .. } => {
                    packet_type::RTPFB
                }
                _ => packet_type::PSFB,
            },
            RtcpPacket::Other { packet_type, .. } => *packet_type,
        }
    }

    /// The packet's bytes, no more than [`MAX_RTCP_PACKET`] of them, with
    /// fields clamped as each one's doc says. An `Other` packet whose type
    /// this module reads, but whose body does not read as that type, and a
    /// feedback message whose FCI does not read, write as no bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let room = MAX_RTCP_PACKET - RTCP_HEADER_LEN;
        let mut body = Vec::new();
        let count = match self {
            RtcpPacket::SenderReport(sr) => {
                body.extend_from_slice(&sr.ssrc.to_be_bytes());
                body.extend_from_slice(&sr.ntp_timestamp.to_be_bytes());
                body.extend_from_slice(&sr.rtp_timestamp.to_be_bytes());
                body.extend_from_slice(&sr.packet_count.to_be_bytes());
                body.extend_from_slice(&sr.octet_count.to_be_bytes());
                write_reports(&mut body, &sr.reports, &sr.extension, room)
            }
            RtcpPacket::ReceiverReport(rr) => {
                body.extend_from_slice(&rr.ssrc.to_be_bytes());
                write_reports(&mut body, &rr.reports, &rr.extension, room)
            }
            RtcpPacket::SourceDescription(chunks) => write_sdes(&mut body, chunks, room),
            RtcpPacket::Bye(bye) => {
                let sources = &bye.sources[..bye.sources.len().min(MAX_COUNT)];
                for s in sources {
                    body.extend_from_slice(&s.to_be_bytes());
                }
                if let Some(reason) = &bye.reason {
                    let reason = cut_text(reason);
                    body.push(reason.len() as u8);
                    body.extend_from_slice(reason);
                    pad4(&mut body);
                }
                sources.len() as u8
            }
            RtcpPacket::App(app) => {
                body.extend_from_slice(&app.ssrc.to_be_bytes());
                body.extend_from_slice(&app.name);
                append_capped(&mut body, &app.data, room);
                app.subtype & 0x1f
            }
            RtcpPacket::Feedback(fb) => {
                body.extend_from_slice(&fb.sender_ssrc.to_be_bytes());
                body.extend_from_slice(&fb.media_ssrc.to_be_bytes());
                fb.message.write_fci(&mut body, room)
            }
            RtcpPacket::Other {
                count, body: raw, ..
            } => {
                append_capped(&mut body, raw, room);
                count & 0x1f
            }
        };
        let words = (RTCP_HEADER_LEN + body.len()) / 4 - 1;
        let mut out = Vec::with_capacity(RTCP_HEADER_LEN + body.len());
        out.push(VERSION << 6 | count);
        out.push(self.packet_type());
        out.extend_from_slice(&(words as u16).to_be_bytes());
        out.extend_from_slice(&body);
        // Bodies that do not read back as their type are not written.
        if parse_packets(&out).is_err() {
            return Vec::new();
        }
        out
    }
}

impl FeedbackMessage {
    /// The FMT field.
    pub fn fmt(&self) -> u8 {
        match self {
            FeedbackMessage::Nack(_) => feedback::NACK,
            FeedbackMessage::Pli => feedback::PLI,
            FeedbackMessage::Sli(_) => feedback::SLI,
            FeedbackMessage::Rpsi(_) => feedback::RPSI,
            FeedbackMessage::Afb(_) => feedback::AFB,
            FeedbackMessage::TransportOther { fmt, .. }
            | FeedbackMessage::PayloadOther { fmt, .. } => fmt & 0x1f,
        }
    }

    /// Writes the FCI into `body` within `room` bytes in all, and gives the
    /// FMT.
    fn write_fci(&self, body: &mut Vec<u8>, room: usize) -> u8 {
        match self {
            FeedbackMessage::Nack(entries) => {
                for n in entries {
                    if body.len() + 4 > room {
                        break;
                    }
                    body.extend_from_slice(&n.pid.to_be_bytes());
                    body.extend_from_slice(&n.blp.to_be_bytes());
                }
            }
            FeedbackMessage::Pli => {}
            FeedbackMessage::Sli(entries) => {
                for s in entries {
                    if body.len() + 4 > room {
                        break;
                    }
                    let word = u32::from(s.first & 0x1fff) << 19
                        | u32::from(s.number & 0x1fff) << 6
                        | u32::from(s.picture_id & 0x3f);
                    body.extend_from_slice(&word.to_be_bytes());
                }
            }
            FeedbackMessage::Rpsi(r) => {
                let data = &r.data[..r.data.len().min(room - body.len() - 2)];
                let start = body.len();
                body.push(r.padding_bits);
                body.push(r.payload_type & 0x7f);
                body.extend_from_slice(data);
                pad4(body);
                let added = body.len() - start - 2 - data.len();
                let bits = (body.len() - start - 2) * 8;
                let pb = (usize::from(r.padding_bits) + 8 * added).min(255).min(bits);
                body[start] = pb as u8;
                // Padding bits are zero (RFC 4585 section 6.3.3.2).
                clear_low_bits(&mut body[start + 2..], pb);
            }
            FeedbackMessage::Afb(fci)
            | FeedbackMessage::TransportOther { fci, .. }
            | FeedbackMessage::PayloadOther { fci, .. } => append_capped(body, fci, room),
        }
        self.fmt()
    }
}

/// Reads the body of one packet of type `pt`.
fn parse_body(pt: u8, count: u8, body: &[u8]) -> Result<RtcpPacket, RtcpError> {
    let bad = RtcpError::Body(pt);
    let mut r = Reader::new(body);
    Ok(match pt {
        packet_type::SR | packet_type::RR => {
            let ssrc = r.u32().ok_or(bad)?;
            let sender = if pt == packet_type::SR {
                let (Some(ntp), Some(rtp), Some(packets), Some(octets)) =
                    (r.u64(), r.u32(), r.u32(), r.u32())
                else {
                    return Err(bad);
                };
                Some((ntp, rtp, packets, octets))
            } else {
                None
            };
            let mut reports = Vec::new();
            for _ in 0..count {
                let block = r.take(REPORT_BLOCK_LEN).ok_or(bad)?;
                reports.push(parse_report_block(block));
            }
            let extension = r.rest().to_vec();
            match sender {
                Some((ntp_timestamp, rtp_timestamp, packet_count, octet_count)) => {
                    RtcpPacket::SenderReport(SenderReport {
                        ssrc,
                        ntp_timestamp,
                        rtp_timestamp,
                        packet_count,
                        octet_count,
                        reports,
                        extension,
                    })
                }
                None => RtcpPacket::ReceiverReport(ReceiverReport {
                    ssrc,
                    reports,
                    extension,
                }),
            }
        }
        packet_type::SDES => {
            let mut chunks = Vec::new();
            for _ in 0..count {
                let ssrc = r.u32().ok_or(bad)?;
                let mut items = Vec::new();
                loop {
                    let kind = r.u8().ok_or(bad)?;
                    if kind == sdes::END {
                        // The null octet, then null octets to the next word.
                        let pad = (4 - r.pos % 4) % 4;
                        if r.take(pad).ok_or(bad)?.iter().any(|&x| x != 0) {
                            return Err(bad);
                        }
                        break;
                    }
                    let len = r.u8().ok_or(bad)?;
                    let text = r.take(usize::from(len)).ok_or(bad)?;
                    if !sdes_text_ok(kind, text) {
                        return Err(bad);
                    }
                    items.push(SdesItem {
                        kind,
                        text: text.to_vec(),
                    });
                }
                chunks.push(SdesChunk { ssrc, items });
            }
            if !r.rest().is_empty() {
                return Err(bad);
            }
            RtcpPacket::SourceDescription(chunks)
        }
        packet_type::BYE => {
            let mut sources = Vec::new();
            for _ in 0..count {
                sources.push(r.u32().ok_or(bad)?);
            }
            let rest = r.rest();
            let reason = match rest.split_first() {
                None => None,
                Some((&len, after)) => {
                    let len = usize::from(len);
                    // The reason, then null octets to the next word.
                    if len > after.len()
                        || (1 + len).div_ceil(4) * 4 != rest.len()
                        || after[len..].iter().any(|&x| x != 0)
                    {
                        return Err(bad);
                    }
                    Some(after[..len].to_vec())
                }
            };
            RtcpPacket::Bye(Bye { sources, reason })
        }
        packet_type::APP => {
            let (Some(ssrc), Some(name)) = (r.u32(), r.take(4)) else {
                return Err(bad);
            };
            let name = [name[0], name[1], name[2], name[3]];
            RtcpPacket::App(App {
                subtype: count,
                ssrc,
                name,
                data: r.rest().to_vec(),
            })
        }
        packet_type::RTPFB | packet_type::PSFB => {
            let (Some(sender_ssrc), Some(media_ssrc)) = (r.u32(), r.u32()) else {
                return Err(bad);
            };
            let fci = r.rest();
            // A NACK or SLI must carry at least one entry (RFC 4585
            // sections 6.2.1 and 6.3.2).
            let needs_entry = (pt, count) == (packet_type::RTPFB, feedback::NACK)
                || (pt, count) == (packet_type::PSFB, feedback::SLI);
            if needs_entry && fci.is_empty() {
                return Err(bad);
            }
            let message = match (pt, count) {
                (packet_type::RTPFB, feedback::NACK) => FeedbackMessage::Nack(
                    fci.chunks_exact(4)
                        .map(|c| Nack {
                            pid: u16::from_be_bytes([c[0], c[1]]),
                            blp: u16::from_be_bytes([c[2], c[3]]),
                        })
                        .collect(),
                ),
                (packet_type::RTPFB, fmt) => FeedbackMessage::TransportOther {
                    fmt,
                    fci: fci.to_vec(),
                },
                (_, feedback::PLI) => {
                    if !fci.is_empty() {
                        return Err(bad);
                    }
                    FeedbackMessage::Pli
                }
                (_, feedback::SLI) => FeedbackMessage::Sli(
                    fci.chunks_exact(4)
                        .map(|c| {
                            let w = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                            Sli {
                                first: (w >> 19) as u16,
                                number: (w >> 6 & 0x1fff) as u16,
                                picture_id: (w & 0x3f) as u8,
                            }
                        })
                        .collect(),
                ),
                (_, feedback::RPSI) => {
                    let [padding_bits, pt_byte, data @ ..] = fci else {
                        return Err(bad);
                    };
                    // The padding bits must fit and be zero (RFC 4585
                    // section 6.3.3.2).
                    if usize::from(*padding_bits) > data.len() * 8
                        || low_bits_set(data, usize::from(*padding_bits))
                    {
                        return Err(bad);
                    }
                    FeedbackMessage::Rpsi(Rpsi {
                        padding_bits: *padding_bits,
                        payload_type: pt_byte & 0x7f,
                        data: data.to_vec(),
                    })
                }
                (_, feedback::AFB) => FeedbackMessage::Afb(fci.to_vec()),
                (_, fmt) => FeedbackMessage::PayloadOther {
                    fmt,
                    fci: fci.to_vec(),
                },
            };
            RtcpPacket::Feedback(Feedback {
                sender_ssrc,
                media_ssrc,
                message,
            })
        }
        _ => RtcpPacket::Other {
            packet_type: pt,
            count,
            body: body.to_vec(),
        },
    })
}

fn parse_report_block(b: &[u8]) -> ReportBlock {
    let word = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    // The 24-bit loss count, sign-extended.
    let lost = (word(4) << 8) as i32 >> 8;
    ReportBlock {
        ssrc: word(0),
        fraction_lost: b[4],
        cumulative_lost: lost,
        highest_sequence: word(8),
        jitter: word(12),
        last_sr: word(16),
        delay_since_last_sr: word(20),
    }
}

/// Writes report blocks and an extension after the fixed part of a report,
/// within `room` bytes, and gives the count.
fn write_reports(body: &mut Vec<u8>, reports: &[ReportBlock], extension: &[u8], room: usize) -> u8 {
    let reports = &reports[..reports.len().min(MAX_COUNT)];
    for rb in reports {
        let lost = rb
            .cumulative_lost
            .clamp(MIN_CUMULATIVE_LOST, MAX_CUMULATIVE_LOST) as u32
            & 0x00ff_ffff;
        body.extend_from_slice(&rb.ssrc.to_be_bytes());
        body.extend_from_slice(&(u32::from(rb.fraction_lost) << 24 | lost).to_be_bytes());
        body.extend_from_slice(&rb.highest_sequence.to_be_bytes());
        body.extend_from_slice(&rb.jitter.to_be_bytes());
        body.extend_from_slice(&rb.last_sr.to_be_bytes());
        body.extend_from_slice(&rb.delay_since_last_sr.to_be_bytes());
    }
    append_capped(body, extension, room);
    reports.len() as u8
}

/// Writes SDES chunks within `room` bytes, and gives the count.
fn write_sdes(body: &mut Vec<u8>, chunks: &[SdesChunk], room: usize) -> u8 {
    let mut written = 0;
    for c in chunks.iter().take(MAX_COUNT) {
        // The SSRC and a word that ends the item list.
        if body.len() + 8 > room {
            break;
        }
        body.extend_from_slice(&c.ssrc.to_be_bytes());
        for item in &c.items {
            let text = cut_text(&item.text);
            if item.kind == sdes::END || !sdes_text_ok(item.kind, text) {
                continue;
            }
            if (body.len() + 2 + text.len() + 1).div_ceil(4) * 4 > room {
                break;
            }
            body.push(item.kind);
            body.push(text.len() as u8);
            body.extend_from_slice(text);
        }
        body.push(sdes::END);
        pad4(body);
        written += 1;
    }
    written
}

/// Appends as much of `data` as fits in `room` bytes in all, padded with
/// zeros to a multiple of 4. `body` and `room` are multiples of 4.
fn append_capped(body: &mut Vec<u8>, data: &[u8], room: usize) {
    let n = data.len().min(room.saturating_sub(body.len()));
    body.extend_from_slice(&data[..n]);
    pad4(body);
}

/// Whether any of the last `n` bits of `b` is set. `n` is at most
/// `8 * b.len()`.
fn low_bits_set(b: &[u8], n: usize) -> bool {
    let (whole, part) = (n / 8, n % 8);
    let tail = &b[b.len() - whole..];
    let partial = b.len().checked_sub(whole + 1).map_or(0, |i| b[i]);
    tail.iter().any(|&x| x != 0) || part > 0 && partial & ((1u8 << part) - 1) != 0
}

/// Clears the last `n` bits of `b`. `n` is at most `8 * b.len()`.
fn clear_low_bits(b: &mut [u8], n: usize) {
    let (whole, part) = (n / 8, n % 8);
    let len = b.len();
    b[len - whole..].fill(0);
    if part > 0
        && let Some(x) = len.checked_sub(whole + 1).and_then(|i| b.get_mut(i)) {
            *x &= !((1u8 << part) - 1);
        }
}

/// The first [`MAX_TEXT`] bytes of SDES or BYE text. Text that is UTF-8,
/// as RFC 3550 says it is, is cut at a character boundary, so it stays
/// UTF-8.
fn cut_text(text: &[u8]) -> &[u8] {
    if text.len() <= MAX_TEXT {
        return text;
    }
    match std::str::from_utf8(text) {
        Ok(s) => {
            let mut end = MAX_TEXT;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            &text[..end]
        }
        Err(_) => &text[..MAX_TEXT],
    }
}

/// Whether an SDES item's text reads as its type says: a PRIV item holds
/// a prefix length, then at least that many bytes of prefix (RFC 3550
/// section 6.5.8). Other types hold any text.
fn sdes_text_ok(kind: u8, text: &[u8]) -> bool {
    kind != sdes::PRIV
        || text
            .split_first()
            .is_some_and(|(&n, rest)| usize::from(n) <= rest.len())
}

fn pad4(b: &mut Vec<u8>) {
    b.resize(b.len().div_ceil(4) * 4, 0);
}

// ---------------------------------------------------------------------------
// Telling RTP from RTCP, and streams

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
    /// RTCP packets, read with [`parse_packets`].
    Rtcp(Vec<RtcpPacket>),
}

/// Why a datagram is neither RTP nor RTCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// It looked like RTP and did not read.
    Rtp(RtpError),
    /// It looked like RTCP and did not read.
    Rtcp(RtcpError),
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

impl Packet {
    /// Reads a datagram as RTCP if [`is_rtcp`] says so, and as RTP
    /// otherwise.
    pub fn parse(b: &[u8]) -> Result<Packet, PacketError> {
        if is_rtcp(b) {
            parse_packets(b)
                .map(Packet::Rtcp)
                .map_err(PacketError::Rtcp)
        } else {
            RtpPacket::parse(b)
                .map(Packet::Rtp)
                .map_err(PacketError::Rtp)
        }
    }
}

/// A packet with its 16-bit length in front, as RFC 4571 sends RTP and
/// RTCP over TCP. A packet longer than [`MAX_PACKET`] is cut to that
/// length; no writer here makes one.
pub fn frame(packet: &[u8]) -> Vec<u8> {
    let packet = &packet[..packet.len().min(MAX_PACKET)];
    let mut out = Vec::with_capacity(2 + packet.len());
    out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    out.extend_from_slice(packet);
    out
}

/// Splits an RFC 4571 byte stream into packets. Feed it the bytes a
/// connection reads, in order, and take packets out until it has none.
/// A frame of length 0 is the null packet RFC 4571 section 2 allows, and
/// comes out as no bytes: skip it. Each other packet's bytes then go to
/// [`Packet::parse`]. It holds at most [`MAX_BUFFERED`] bytes that have
/// not been taken out.
///
/// ```
/// use fictionet::stdlib::rtp::{Decoder, frame};
///
/// let stream = [frame(&[1, 2]), frame(&[]), frame(&[3])].concat();
/// let mut d = Decoder::new();
/// let mut packets = Vec::new();
/// let mut rest = &stream[..];
/// while !rest.is_empty() {
///     let used = d.feed(rest);
///     rest = &rest[used..];
///     while let Some(p) = d.next_packet() {
///         // A null packet carries nothing.
///         if !p.is_empty() {
///             packets.push(p);
///         }
///     }
/// }
/// assert_eq!(packets, [vec![1, 2], vec![3]]);
/// ```
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer.
    start: usize,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Takes bytes read from the connection, from the start of `bytes`,
    /// and returns how many it took. It takes them all unless that would
    /// make it hold more than [`MAX_BUFFERED`] bytes. Then take packets
    /// out and feed it the rest. When it takes no bytes, it holds at least
    /// one whole packet, so a loop of feeding and taking out always ends.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes
            .len()
            .min(MAX_BUFFERED.saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The next whole packet, if one has come. Any 16-bit length is valid,
    /// so the stream never breaks; a null packet, of length 0, comes out
    /// empty.
    pub fn next_packet(&mut self) -> Option<Vec<u8>> {
        let rest = self.buf.get(self.start..)?;
        let [a, b, ..] = *rest else { return None };
        let end = 2 + usize::from(u16::from_be_bytes([a, b]));
        let packet = rest.get(2..end)?.to_vec();
        self.start += end;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        Some(packet)
    }

    /// How many bytes are held, waiting to be taken out.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }
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

    fn u64(&mut self) -> Option<u64> {
        let (hi, lo) = (self.u32()?, self.u32()?);
        Some(u64::from(hi) << 32 | u64::from(lo))
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

    fn block(ssrc: u32, lost: i32) -> ReportBlock {
        ReportBlock {
            ssrc,
            fraction_lost: 0x40,
            cumulative_lost: lost,
            highest_sequence: 0x0001_0005,
            jitter: 7,
            last_sr: 0x1234_5678,
            delay_since_last_sr: 0x0001_0000,
        }
    }

    fn cname(ssrc: u32) -> RtcpPacket {
        RtcpPacket::SourceDescription(vec![SdesChunk {
            ssrc,
            items: vec![SdesItem {
                kind: sdes::CNAME,
                text: b"a@b".to_vec(),
            }],
        }])
    }

    /// A compound packet with one of every kind.
    fn every_kind() -> Vec<RtcpPacket> {
        vec![
            RtcpPacket::SenderReport(SenderReport {
                ssrc: 0x1111_1111,
                ntp_timestamp: 0x0102_0304_0506_0708,
                rtp_timestamp: 9,
                packet_count: 10,
                octet_count: 11,
                reports: vec![block(0x2222_2222, -3), block(5, MAX_CUMULATIVE_LOST)],
                extension: vec![1, 2, 3, 4],
            }),
            RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc: 6,
                reports: vec![],
                extension: vec![],
            }),
            RtcpPacket::SourceDescription(vec![
                SdesChunk {
                    ssrc: 0x1111_1111,
                    items: vec![
                        SdesItem {
                            kind: sdes::CNAME,
                            text: b"user@host".to_vec(),
                        },
                        SdesItem {
                            kind: sdes::TOOL,
                            text: b"x".to_vec(),
                        },
                        SdesItem {
                            kind: sdes::NOTE,
                            text: vec![],
                        },
                    ],
                },
                SdesChunk {
                    ssrc: 7,
                    items: vec![],
                },
            ]),
            RtcpPacket::App(App {
                subtype: 3,
                ssrc: 8,
                name: *b"TEST",
                data: vec![9; 8],
            }),
            RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: FeedbackMessage::Nack(vec![Nack {
                    pid: 100,
                    blp: 0b101,
                }]),
            }),
            RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: FeedbackMessage::Pli,
            }),
            RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: FeedbackMessage::Sli(vec![Sli {
                    first: 0x1fff,
                    number: 5,
                    picture_id: 0x3f,
                }]),
            }),
            RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: FeedbackMessage::Rpsi(Rpsi {
                    padding_bits: 4,
                    payload_type: 96,
                    data: vec![0xab, 0xc0],
                }),
            }),
            RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 0,
                message: FeedbackMessage::Afb(b"REMB\x01\x0a\x00\x00".to_vec()),
            }),
            RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: FeedbackMessage::TransportOther {
                    fmt: 15,
                    fci: vec![0; 4],
                },
            }),
            RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: FeedbackMessage::PayloadOther {
                    fmt: 4,
                    fci: vec![1, 2, 3, 4],
                },
            }),
            RtcpPacket::Other {
                packet_type: 207,
                count: 2,
                body: vec![5; 4],
            },
            RtcpPacket::Bye(Bye {
                sources: vec![0x1111_1111, 7],
                reason: Some(b"done".to_vec()),
            }),
        ]
    }

    // RTP, RFC 3550 section 5.1.

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
        assert_eq!(p.to_bytes(), b);
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
        assert_eq!(p.to_bytes(), b);
        // Padding that is all of the payload.
        let mut q = rtp(&[]);
        q.padding = 255;
        let bytes = q.to_bytes();
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
        let out = p.to_bytes();
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
        assert_eq!(RtpPacket::parse(&p.to_bytes()), Ok(p));
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
        let out = p.to_bytes();
        assert_eq!(
            &out[12..24],
            &[
                0x10, 0x05, 0, 2, 0x01, 0x00, 0x20, 0x03, 0xa1, 0xa2, 0xa3, 0
            ]
        );
        assert_eq!(RtpPacket::parse(&out), Ok(p));
    }

    #[test]
    fn rtp_other_extension() {
        let mut p = rtp(&[1]);
        p.extension = Some(HeaderExtension::Other {
            profile: 0xabcd,
            data: vec![1, 2, 3, 4, 5],
        });
        let out = p.to_bytes();
        assert_eq!(&out[12..24], &[0xab, 0xcd, 0, 2, 1, 2, 3, 4, 5, 0, 0, 0]);
        let back = RtpPacket::parse(&out).unwrap();
        assert_eq!(
            back.extension,
            Some(HeaderExtension::Other {
                profile: 0xabcd,
                data: vec![1, 2, 3, 4, 5, 0, 0, 0]
            })
        );
        assert_eq!(back.extension.unwrap().get(1), None);
        // An Other that claims the one-byte form but does not read in it is
        // written empty.
        p.extension = Some(HeaderExtension::Other {
            profile: ONE_BYTE_PROFILE,
            data: vec![0x1f, 0, 0, 0],
        });
        let back = RtpPacket::parse(&p.to_bytes()).unwrap();
        assert_eq!(back.extension, Some(HeaderExtension::OneByte(vec![])));
        // One that does read is kept.
        p.extension = Some(HeaderExtension::Other {
            profile: ONE_BYTE_PROFILE,
            data: vec![0x10, 7, 0, 0],
        });
        let back = RtpPacket::parse(&p.to_bytes()).unwrap();
        assert_eq!(
            back.extension,
            Some(HeaderExtension::OneByte(vec![Element {
                id: 1,
                data: vec![7]
            }]))
        );
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
    fn rtp_writer_clamps() {
        let p = RtpPacket {
            marker: true,
            payload_type: 0xff,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            csrcs: (0..40).collect(),
            extension: Some(HeaderExtension::OneByte(vec![
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
                Element {
                    id: 14,
                    data: vec![0; 16],
                },
            ])),
            payload: vec![0xee; 100_000],
            padding: 9,
        };
        let out = p.to_bytes();
        assert_eq!(out.len(), MAX_PACKET);
        let back = RtpPacket::parse(&out).unwrap();
        assert_eq!(back.payload_type, 0x7f);
        assert_eq!(back.csrcs.len(), MAX_CSRCS);
        assert_eq!(
            back.extension,
            Some(HeaderExtension::OneByte(vec![Element {
                id: 14,
                data: vec![0; 16]
            }]))
        );
        assert_eq!(back.padding, 9);
        let mut two = rtp(&[]);
        two.extension = Some(HeaderExtension::TwoByte {
            app_bits: 0xff,
            elements: vec![
                Element {
                    id: 0,
                    data: vec![],
                },
                Element {
                    id: 9,
                    data: vec![0; 256],
                },
            ],
        });
        let back = RtpPacket::parse(&two.to_bytes()).unwrap();
        assert_eq!(
            back.extension,
            Some(HeaderExtension::TwoByte {
                app_bits: 15,
                elements: vec![]
            })
        );
        // A huge extension is cut to fit, element by element.
        let mut big = rtp(&[1, 2, 3]);
        big.extension = Some(HeaderExtension::TwoByte {
            app_bits: 0,
            elements: (1..=255)
                .map(|id| Element {
                    id,
                    data: vec![id; 255],
                })
                .collect(),
        });
        let out = big.to_bytes();
        assert!(out.len() <= MAX_PACKET);
        assert!(RtpPacket::parse(&out).is_ok());
        big.extension = Some(HeaderExtension::Other {
            profile: 1,
            data: vec![1; 300_000],
        });
        let out = big.to_bytes();
        assert!(out.len() <= MAX_PACKET);
        assert!(RtpPacket::parse(&out).is_ok());
    }

    #[test]
    fn rtp_truncated_prefixes() {
        let mut p = rtp(&[1, 2, 3, 4]);
        p.csrcs = vec![9, 10];
        p.extension = Some(HeaderExtension::OneByte(vec![Element {
            id: 3,
            data: vec![5, 6, 7],
        }]));
        let b = p.to_bytes();
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
        let b = p.to_bytes();
        for n in 0..b.len() {
            // Never a panic; a prefix's last byte is not the count.
            let _ = RtpPacket::parse(&b[..n]);
        }
    }

    // RTCP, RFC 3550 section 6.

    #[test]
    fn sender_report_bytes() {
        let sr = RtcpPacket::SenderReport(SenderReport {
            ssrc: 0x0102_0304,
            ntp_timestamp: 0xe000_0000_8000_0000,
            rtp_timestamp: 0x10,
            packet_count: 2,
            octet_count: 320,
            reports: vec![block(0x0a0b_0c0d, -1)],
            extension: vec![],
        });
        let b = sr.to_bytes();
        assert_eq!(b.len(), 52);
        assert_eq!(&b[..4], &[0x81, 200, 0, 12]);
        assert_eq!(&b[4..8], &[1, 2, 3, 4]);
        assert_eq!(&b[8..16], &[0xe0, 0, 0, 0, 0x80, 0, 0, 0]);
        // The block: SSRC, then fraction lost 0x40 and -1 in 24 bits.
        assert_eq!(
            &b[28..36],
            &[0x0a, 0x0b, 0x0c, 0x0d, 0x40, 0xff, 0xff, 0xff]
        );
        assert_eq!(parse_packets(&b), Ok(vec![sr]));
        assert!(is_rtcp(&b));
    }

    #[test]
    fn sdes_bye_app_bytes() {
        let sdes = RtcpPacket::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![SdesItem {
                kind: sdes::CNAME,
                text: b"ab".to_vec(),
            }],
        }]);
        // SSRC, CNAME item of 4 bytes, null octet, 3 bytes of padding.
        assert_eq!(
            sdes.to_bytes(),
            [0x81, 202, 0, 3, 0, 0, 0, 1, 1, 2, b'a', b'b', 0, 0, 0, 0]
        );
        let bye = RtcpPacket::Bye(Bye {
            sources: vec![1],
            reason: Some(b"bye".to_vec()),
        });
        assert_eq!(
            bye.to_bytes(),
            [0x81, 203, 0, 2, 0, 0, 0, 1, 3, b'b', b'y', b'e']
        );
        let bye = RtcpPacket::Bye(Bye {
            sources: vec![],
            reason: None,
        });
        assert_eq!(bye.to_bytes(), [0x80, 203, 0, 0]);
        assert_eq!(parse_packets(&bye.to_bytes()), Ok(vec![bye]));
        let bye = RtcpPacket::Bye(Bye {
            sources: vec![],
            reason: Some(vec![]),
        });
        assert_eq!(parse_packets(&bye.to_bytes()), Ok(vec![bye]));
        let app = RtcpPacket::App(App {
            subtype: 0x3f,
            ssrc: 2,
            name: *b"abcd",
            data: vec![1],
        });
        assert_eq!(
            app.to_bytes(),
            [
                0x9f, 204, 0, 3, 0, 0, 0, 2, b'a', b'b', b'c', b'd', 1, 0, 0, 0
            ]
        );
    }

    #[test]
    fn feedback_bytes() {
        // A generic NACK for 100, 101 and 103.
        let nack = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: FeedbackMessage::Nack(vec![Nack {
                pid: 100,
                blp: 0b101,
            }]),
        });
        assert_eq!(
            nack.to_bytes(),
            [0x81, 205, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 100, 0, 5]
        );
        assert_eq!(
            Nack {
                pid: 100,
                blp: 0b101
            }
            .lost(),
            [100, 101, 103]
        );
        assert_eq!(Nack { pid: 65535, blp: 1 }.lost(), [65535, 0]);
        // A PLI has no FCI, so its length is 2.
        let pli = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: FeedbackMessage::Pli,
        });
        assert_eq!(pli.to_bytes(), [0x81, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]);
        let sli = Sli {
            first: 1,
            number: 2,
            picture_id: 3,
        };
        let b = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: FeedbackMessage::Sli(vec![sli]),
        })
        .to_bytes();
        assert_eq!(&b[12..], &(1u32 << 19 | 2 << 6 | 3).to_be_bytes());
        // RPSI pads its bit string, and counts the padding.
        let rpsi = Rpsi {
            padding_bits: 3,
            payload_type: 0xe0,
            data: vec![0xff],
        };
        let b = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: FeedbackMessage::Rpsi(rpsi),
        })
        .to_bytes();
        // The three padding bits set in 0xff are cleared.
        assert_eq!(&b[12..], &[11, 0x60, 0xf8, 0]);
        let [
            RtcpPacket::Feedback(Feedback {
                message: FeedbackMessage::Rpsi(r),
                ..
            }),
        ] = &parse_packets(&b).unwrap()[..]
        else {
            panic!()
        };
        assert_eq!(
            r,
            &Rpsi {
                padding_bits: 11,
                payload_type: 0x60,
                data: vec![0xf8, 0]
            }
        );
        // An FMT this module does not read keeps its FCI.
        let other = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: FeedbackMessage::TransportOther {
                fmt: 3,
                fci: vec![1, 2, 3, 4],
            },
        });
        assert_eq!(parse_packets(&other.to_bytes()), Ok(vec![other]));
    }

    #[test]
    fn compound_round_trip() {
        let packets = every_kind();
        let b = write_packets(&packets);
        assert_eq!(parse_compound(&b), Ok(packets.clone()));
        for p in &packets {
            assert_eq!(parse_packets(&p.to_bytes()), Ok(vec![p.clone()]));
        }
        assert_eq!(packets[0].packet_type(), packet_type::SR);
        assert_eq!(packets[4].packet_type(), packet_type::RTPFB);
        assert_eq!(packets[5].packet_type(), packet_type::PSFB);
        assert_eq!(Packet::parse(&b), Ok(Packet::Rtcp(packets)));
        assert_eq!(parse_packets(&[]), Ok(vec![]));
    }

    #[test]
    fn padding_on_the_last_packet() {
        let mut b = write_packets(&[
            RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc: 1,
                reports: vec![],
                extension: vec![],
            }),
            cname(1),
        ]);
        let sdes_at = 8;
        // Pad the SDES packet by 8 bytes.
        b[sdes_at] |= 0x20;
        b[sdes_at + 3] += 2;
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);
        let packets = parse_compound(&b).unwrap();
        assert_eq!(packets[1], cname(1));
        // Padding on the first packet is refused.
        let mut c = b.clone();
        c[0] |= 0x20;
        assert_eq!(parse_packets(&c), Err(RtcpError::Padding));
        // A count of 0, one not a multiple of 4, one past the body.
        for n in [0, 6, 24] {
            let mut c = b.clone();
            *c.last_mut().unwrap() = n;
            assert_eq!(parse_packets(&c), Err(RtcpError::Padding), "count {n}");
        }
        // A padded packet of a header alone.
        assert_eq!(parse_packets(&[0xa0, 203, 0, 0]), Err(RtcpError::Padding));
        // Padding that eats the report.
        let mut c = vec![0xa0, 201, 0, 1, 0, 0, 0, 4];
        assert_eq!(parse_packets(&c), Err(RtcpError::Body(201)));
        c[7] = 0;
        assert_eq!(parse_packets(&c), Err(RtcpError::Padding));
    }

    #[test]
    fn rtcp_errors() {
        assert_eq!(parse_packets(&[0x80]), Err(RtcpError::Truncated));
        assert_eq!(
            parse_packets(&[0x80, 201, 0, 1, 0, 0]),
            Err(RtcpError::Truncated)
        );
        assert_eq!(
            parse_packets(&[0x40, 201, 0, 0]),
            Err(RtcpError::Version(1))
        );
        assert_eq!(
            parse_packets(&vec![0; MAX_PACKET + 1]),
            Err(RtcpError::TooLong(MAX_PACKET + 1))
        );
        let body = |pt: u8, count: u8, body: &[u8]| {
            let mut b = vec![0x80 | count, pt, 0, (body.len() / 4) as u8];
            b.extend_from_slice(body);
            parse_packets(&b)
        };
        // Reports shorter than their fixed part or their count.
        assert_eq!(body(200, 0, &[0; 20]), Err(RtcpError::Body(200)));
        assert_eq!(body(200, 1, &[0; 24]), Err(RtcpError::Body(200)));
        assert_eq!(body(201, 0, &[]), Err(RtcpError::Body(201)));
        assert_eq!(body(201, 2, &[0; 28]), Err(RtcpError::Body(201)));
        assert!(body(201, 1, &[0; 28]).is_ok());
        // SDES: a chunk with no end, an item past the end, an extra word,
        // and a missing chunk.
        assert_eq!(
            body(202, 1, &[0, 0, 0, 1, 1, 2, b'a', b'b']),
            Err(RtcpError::Body(202))
        );
        assert_eq!(
            body(202, 1, &[0, 0, 0, 1, 1, 9, b'a', b'b']),
            Err(RtcpError::Body(202))
        );
        assert_eq!(
            body(202, 1, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(RtcpError::Body(202))
        );
        assert_eq!(
            body(202, 2, &[0, 0, 0, 1, 0, 0, 0, 0]),
            Err(RtcpError::Body(202))
        );
        assert_eq!(body(202, 1, &[0, 0, 0, 1]), Err(RtcpError::Body(202)));
        // BYE: too few sources, a reason past the end, too much after it.
        assert_eq!(body(203, 2, &[0, 0, 0, 1]), Err(RtcpError::Body(203)));
        assert_eq!(
            body(203, 0, &[9, b'a', b'b', b'c']),
            Err(RtcpError::Body(203))
        );
        assert_eq!(
            body(203, 0, &[1, b'a', 0, 0, 0, 0, 0, 0]),
            Err(RtcpError::Body(203))
        );
        // APP and feedback shorter than their SSRCs and name.
        assert_eq!(body(204, 0, &[0, 0, 0, 1]), Err(RtcpError::Body(204)));
        assert_eq!(body(205, 1, &[0, 0, 0, 1]), Err(RtcpError::Body(205)));
        assert_eq!(body(206, 1, &[0, 0, 0, 1]), Err(RtcpError::Body(206)));
        // A PLI with FCI, an RPSI with none, an RPSI with too many padding bits.
        assert_eq!(
            body(206, 1, &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0]),
            Err(RtcpError::Body(206))
        );
        assert_eq!(
            body(206, 3, &[0, 0, 0, 1, 0, 0, 0, 2]),
            Err(RtcpError::Body(206))
        );
        assert_eq!(
            body(206, 3, &[0, 0, 0, 1, 0, 0, 0, 2, 17, 96, 0, 0]),
            Err(RtcpError::Body(206))
        );
        assert!(body(206, 3, &[0, 0, 0, 1, 0, 0, 0, 2, 16, 96, 0, 0]).is_ok());
        // Compound rules.
        let rr = RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 1,
            reports: vec![],
            extension: vec![],
        });
        let bye = RtcpPacket::Bye(Bye {
            sources: vec![1],
            reason: None,
        });
        assert_eq!(parse_compound(&[]), Err(RtcpError::Empty));
        assert_eq!(check_compound(&[]), Err(RtcpError::Empty));
        assert_eq!(
            parse_compound(&write_packets(&[cname(1), rr.clone()])),
            Err(RtcpError::FirstNotReport(202))
        );
        assert_eq!(
            parse_compound(&write_packets(&[rr.clone(), bye.clone()])),
            Err(RtcpError::NoCname)
        );
        let no_cname = RtcpPacket::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![SdesItem {
                kind: sdes::NAME,
                text: b"x".to_vec(),
            }],
        }]);
        assert_eq!(
            check_compound(&[rr.clone(), no_cname]),
            Err(RtcpError::NoCname)
        );
        assert_eq!(check_compound(&[rr, cname(1), bye]), Ok(()));
        assert_eq!(parse_compound(&[0x80]), Err(RtcpError::Truncated));
        for e in [
            RtcpError::Truncated,
            RtcpError::TooLong(1),
            RtcpError::Version(0),
            RtcpError::Padding,
            RtcpError::Body(200),
            RtcpError::Empty,
            RtcpError::FirstNotReport(203),
            RtcpError::NoCname,
        ] {
            assert!(!e.to_string().is_empty());
            assert!(!PacketError::Rtcp(e).to_string().is_empty());
        }
        assert_eq!(
            Packet::parse(&[0x80, 200, 0]),
            Err(PacketError::Rtcp(RtcpError::Truncated))
        );
        assert_eq!(
            Packet::parse(&[0x80, 100, 0]),
            Err(PacketError::Rtp(RtpError::Truncated))
        );
    }

    #[test]
    fn rtcp_truncated_prefixes() {
        let packets = every_kind();
        let b = write_packets(&packets);
        let mut ends = vec![0];
        for p in &packets {
            ends.push(ends.last().unwrap() + p.to_bytes().len());
        }
        for n in 0..b.len() {
            let r = parse_packets(&b[..n]);
            if let Some(i) = ends.iter().position(|&e| e == n) {
                assert_eq!(r, Ok(packets[..i].to_vec()));
            } else {
                assert_eq!(r, Err(RtcpError::Truncated), "{n} bytes");
            }
        }
    }

    #[test]
    fn rtcp_writers_clamp() {
        let many: Vec<ReportBlock> = (0..40).map(|i| block(i, i32::MIN)).collect();
        let sr = RtcpPacket::SenderReport(SenderReport {
            ssrc: 1,
            ntp_timestamp: 0,
            rtp_timestamp: 0,
            packet_count: 0,
            octet_count: 0,
            reports: many.clone(),
            extension: vec![1; 100_000],
        });
        let b = sr.to_bytes();
        assert!(b.len() <= MAX_RTCP_PACKET);
        let [RtcpPacket::SenderReport(back)] = &parse_packets(&b).unwrap()[..] else {
            panic!()
        };
        assert_eq!(back.reports.len(), MAX_COUNT);
        assert_eq!(back.reports[0].cumulative_lost, MIN_CUMULATIVE_LOST);
        let rr = RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 1,
            reports: many,
            extension: vec![],
        });
        let [RtcpPacket::ReceiverReport(back)] = &parse_packets(&rr.to_bytes()).unwrap()[..] else {
            panic!()
        };
        assert_eq!(back.reports.len(), MAX_COUNT);
        // SDES: too many chunks, long text, END items, more than fits.
        let chunk = SdesChunk {
            ssrc: 1,
            items: vec![
                SdesItem {
                    kind: sdes::END,
                    text: b"gone".to_vec(),
                },
                SdesItem {
                    kind: sdes::NOTE,
                    text: vec![b'n'; 300],
                },
                SdesItem {
                    kind: sdes::PRIV,
                    text: vec![b'p'; 255],
                },
            ]
            .into_iter()
            .cycle()
            .take(30)
            .collect(),
        };
        let sdes = RtcpPacket::SourceDescription(vec![chunk; 40]);
        let b = sdes.to_bytes();
        assert!(b.len() <= MAX_RTCP_PACKET);
        let [RtcpPacket::SourceDescription(back)] = &parse_packets(&b).unwrap()[..] else {
            panic!()
        };
        assert!(back.len() <= MAX_COUNT);
        assert!(
            back.iter()
                .flat_map(|c| &c.items)
                .all(|i| i.kind != sdes::END && i.text.len() <= MAX_TEXT)
        );
        let bye = RtcpPacket::Bye(Bye {
            sources: (0..50).collect(),
            reason: Some(vec![b'r'; 400]),
        });
        let [RtcpPacket::Bye(back)] = &parse_packets(&bye.to_bytes()).unwrap()[..] else {
            panic!()
        };
        assert_eq!(
            (back.sources.len(), back.reason.as_ref().unwrap().len()),
            (MAX_COUNT, MAX_TEXT)
        );
        let nack = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 0,
            media_ssrc: 0,
            message: FeedbackMessage::Nack(vec![Nack { pid: 1, blp: 0 }; 20_000]),
        });
        let b = nack.to_bytes();
        assert!(b.len() <= MAX_RTCP_PACKET && parse_packets(&b).is_ok());
        let rpsi = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 0,
            media_ssrc: 0,
            message: FeedbackMessage::Rpsi(Rpsi {
                padding_bits: 255,
                payload_type: 0,
                data: vec![],
            }),
        });
        let b = rpsi.to_bytes();
        assert_eq!(&b[12..], &[16, 0, 0, 0]);
        // An Other with a type this module reads, and a body that does not
        // read, writes nothing; a PayloadOther that claims to be a PLI with
        // FCI does too.
        let other = RtcpPacket::Other {
            packet_type: 200,
            count: 0,
            body: vec![],
        };
        assert_eq!(other.to_bytes(), Vec::<u8>::new());
        let fake = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 0,
            media_ssrc: 0,
            message: FeedbackMessage::PayloadOther {
                fmt: 1,
                fci: vec![0; 4],
            },
        });
        assert_eq!(fake.to_bytes(), Vec::<u8>::new());
        // write_packets stops before the total would pass MAX_PACKET.
        let big = RtcpPacket::App(App {
            subtype: 0,
            ssrc: 0,
            name: *b"BIG ",
            data: vec![0; 40_000],
        });
        let b = write_packets(&[big.clone(), big.clone(), cname(1)]);
        assert_eq!(parse_packets(&b).unwrap().len(), 1);
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
        assert!(is_rtcp(&p.to_bytes()));
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = rtp(&[1, 2, 3]).to_bytes();
        let b = write_packets(&every_kind());
        let mut stream = frame(&a);
        stream.extend_from_slice(&frame(&b));
        stream.extend_from_slice(&frame(&[]));
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for (i, byte) in stream.iter().enumerate() {
            assert_eq!(d.feed(std::slice::from_ref(byte)), 1);
            while let Some(p) = d.next_packet() {
                got.push(p);
            }
            assert_eq!(
                d.buffered() + got.iter().map(|p| p.len() + 2).sum::<usize>(),
                i + 1
            );
        }
        assert_eq!(got, [a.clone(), b.clone(), vec![]]);
        assert_eq!(d.buffered(), 0);
        assert!(matches!(Packet::parse(&got[0]), Ok(Packet::Rtp(_))));
        assert!(matches!(Packet::parse(&got[1]), Ok(Packet::Rtcp(_))));
        // Every prefix of a frame waits for more.
        let f = frame(&a);
        for n in 0..f.len() {
            let mut d = Decoder::new();
            assert_eq!(d.feed(&f[..n]), n);
            assert_eq!(d.next_packet(), None, "{n} bytes");
            assert_eq!(d.buffered(), n);
        }
        assert_eq!(frame(&vec![7; MAX_PACKET + 10]).len(), 2 + MAX_PACKET);
    }

    #[test]
    fn decoder_takes_many_small_packets_in_linear_time() {
        let one = frame(&rtp(&[0; 20]).to_bytes());
        let stream: Vec<u8> = one
            .iter()
            .copied()
            .cycle()
            .take(one.len() * 200_000)
            .collect();
        let started = std::time::Instant::now();
        let n = split(&stream).0.len();
        assert_eq!(n, 200_000);
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
    }

    /// A deterministic pseudo-random generator for the fuzz loops.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// Splits a stream with feeds as large as the decoder takes.
    fn split(stream: &[u8]) -> (Vec<Vec<u8>>, Decoder) {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        let mut rest = stream;
        loop {
            let used = d.feed(rest);
            rest = &rest[used..];
            assert!(d.buffered() <= MAX_BUFFERED);
            while let Some(p) = d.next_packet() {
                out.push(p);
            }
            if rest.is_empty() {
                return (out, d);
            }
            assert!(used > 0 || d.buffered() < MAX_BUFFERED);
        }
    }

    fn check_bytes(data: &[u8]) {
        if let Ok(p) = RtpPacket::parse(data) {
            let out = p.to_bytes();
            assert!(out.len() <= data.len());
            assert_eq!(RtpPacket::parse(&out), Ok(p));
        }
        if let Ok(ps) = parse_packets(data) {
            let out = write_packets(&ps);
            assert!(out.len() <= data.len());
            assert_eq!(parse_packets(&out), Ok(ps.clone()));
            for p in &ps {
                assert_eq!(parse_packets(&p.to_bytes()), Ok(vec![p.clone()]));
            }
            // Packets read from a datagram that pass the compound rules
            // write as a compound packet, the same bytes as write_packets.
            let ok = check_compound(&ps).is_ok();
            assert_eq!(parse_compound(data).is_ok(), ok);
            if ok {
                assert_eq!(write_compound(&ps), Ok(out));
            }
        }
        let _ = Packet::parse(data);
        // The bytes as an RFC 4571 stream, whole and a byte at a time.
        let (a, whole) = split(data);
        let mut bytewise = Decoder::new();
        let mut b = Vec::new();
        for byte in data {
            assert_eq!(bytewise.feed(std::slice::from_ref(byte)), 1);
            while let Some(p) = bytewise.next_packet() {
                b.push(p);
            }
        }
        assert_eq!(a, b);
        assert_eq!(whole.buffered(), bytewise.buffered());
    }

    #[test]
    fn fuzz_parsers() {
        let mut rng = Lcg(0x5eed);
        let mut seeds: Vec<Vec<u8>> = vec![write_packets(&every_kind())];
        let mut p = rtp(&[1, 2, 3, 4, 5]);
        p.csrcs = vec![1, 2];
        p.padding = 4;
        p.extension = Some(HeaderExtension::OneByte(vec![Element {
            id: 1,
            data: vec![1, 2],
        }]));
        seeds.push(p.to_bytes());
        p.extension = Some(HeaderExtension::TwoByte {
            app_bits: 1,
            elements: vec![Element {
                id: 7,
                data: vec![3; 5],
            }],
        });
        seeds.push(p.to_bytes());
        for p in every_kind() {
            seeds.push(p.to_bytes());
        }
        let mut stream = Vec::new();
        for s in &seeds {
            stream.extend_from_slice(&frame(s));
        }
        seeds.push(stream);
        for i in 0..20_000 {
            let mut data = if i % 4 == 0 {
                let n = rng.below(80);
                rng.bytes(n)
            } else {
                seeds[rng.below(seeds.len())].clone()
            };
            for _ in 0..rng.below(4) {
                if data.is_empty() {
                    break;
                }
                let at = rng.below(data.len());
                match rng.below(4) {
                    0 => data[at] = rng.next() as u8,
                    1 => data[at] ^= 1 << rng.below(8),
                    2 => data.truncate(at),
                    _ => data.insert(at, rng.next() as u8),
                }
            }
            // Keep the version bits right most of the time, so the deeper
            // readers run.
            if i % 3 != 0 && !data.is_empty() {
                data[0] = data[0] & 0x3f | 0x80;
            }
            check_bytes(&data);
        }
    }

    fn random_element(rng: &mut Lcg) -> Element {
        let n = if rng.below(10) == 0 {
            rng.below(300)
        } else {
            rng.below(18)
        };
        Element {
            id: rng.below(256) as u8,
            data: rng.bytes(n),
        }
    }

    fn random_rtcp(rng: &mut Lcg) -> RtcpPacket {
        let small = |rng: &mut Lcg| rng.below(12);
        let block = |rng: &mut Lcg| ReportBlock {
            ssrc: rng.next(),
            fraction_lost: rng.next() as u8,
            cumulative_lost: rng.next() as i32,
            highest_sequence: rng.next(),
            jitter: rng.next(),
            last_sr: rng.next(),
            delay_since_last_sr: rng.next(),
        };
        match rng.below(8) {
            0 => RtcpPacket::SenderReport(SenderReport {
                ssrc: rng.next(),
                ntp_timestamp: u64::from(rng.next()) << 32 | u64::from(rng.next()),
                rtp_timestamp: rng.next(),
                packet_count: rng.next(),
                octet_count: rng.next(),
                reports: (0..rng.below(35)).map(|_| block(rng)).collect(),
                extension: {
                    let n = small(rng);
                    rng.bytes(n)
                },
            }),
            1 => RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc: rng.next(),
                reports: (0..rng.below(35)).map(|_| block(rng)).collect(),
                extension: {
                    let n = small(rng);
                    rng.bytes(n)
                },
            }),
            2 => RtcpPacket::SourceDescription(
                (0..rng.below(4))
                    .map(|_| SdesChunk {
                        ssrc: rng.next(),
                        items: (0..rng.below(4))
                            .map(|_| SdesItem {
                                kind: rng.below(10) as u8,
                                text: {
                                    let n = rng.below(20);
                                    rng.bytes(n)
                                },
                            })
                            .collect(),
                    })
                    .collect(),
            ),
            3 => RtcpPacket::Bye(Bye {
                sources: (0..rng.below(35)).map(|_| rng.next()).collect(),
                reason: if rng.below(2) == 0 {
                    None
                } else {
                    let n = rng.below(300);
                    Some(rng.bytes(n))
                },
            }),
            4 => RtcpPacket::App(App {
                subtype: rng.next() as u8,
                ssrc: rng.next(),
                name: [1, 2, 3, 4],
                data: {
                    let n = small(rng);
                    rng.bytes(n)
                },
            }),
            5 | 6 => {
                let fci = {
                    let n = small(rng);
                    rng.bytes(n)
                };
                let message = match rng.below(7) {
                    0 => FeedbackMessage::Nack(
                        (0..rng.below(4))
                            .map(|_| Nack {
                                pid: rng.next() as u16,
                                blp: rng.next() as u16,
                            })
                            .collect(),
                    ),
                    1 => FeedbackMessage::Pli,
                    2 => FeedbackMessage::Sli(
                        (0..rng.below(4))
                            .map(|_| Sli {
                                first: rng.next() as u16,
                                number: rng.next() as u16,
                                picture_id: rng.next() as u8,
                            })
                            .collect(),
                    ),
                    3 => FeedbackMessage::Rpsi(Rpsi {
                        padding_bits: rng.next() as u8,
                        payload_type: rng.next() as u8,
                        data: fci,
                    }),
                    4 => FeedbackMessage::Afb(fci),
                    5 => FeedbackMessage::TransportOther {
                        fmt: rng.next() as u8,
                        fci,
                    },
                    _ => FeedbackMessage::PayloadOther {
                        fmt: rng.next() as u8,
                        fci,
                    },
                };
                RtcpPacket::Feedback(Feedback {
                    sender_ssrc: rng.next(),
                    media_ssrc: rng.next(),
                    message,
                })
            }
            _ => RtcpPacket::Other {
                packet_type: rng.next() as u8,
                count: rng.next() as u8,
                body: {
                    let n = small(rng);
                    rng.bytes(n)
                },
            },
        }
    }

    #[test]
    fn fuzz_writers() {
        let mut rng = Lcg(42);
        for _ in 0..5_000 {
            let extension = match rng.below(4) {
                0 => None,
                1 => Some(HeaderExtension::OneByte(
                    (0..rng.below(6))
                        .map(|_| random_element(&mut rng))
                        .collect(),
                )),
                2 => Some(HeaderExtension::TwoByte {
                    app_bits: rng.next() as u8,
                    elements: (0..rng.below(6))
                        .map(|_| random_element(&mut rng))
                        .collect(),
                }),
                _ => {
                    let profile =
                        [ONE_BYTE_PROFILE, TWO_BYTE_PROFILE | 3, rng.next() as u16][rng.below(3)];
                    let n = rng.below(20);
                    Some(HeaderExtension::Other {
                        profile,
                        data: rng.bytes(n),
                    })
                }
            };
            let p = RtpPacket {
                marker: rng.below(2) == 0,
                payload_type: rng.next() as u8,
                sequence: rng.next() as u16,
                timestamp: rng.next(),
                ssrc: rng.next(),
                csrcs: (0..rng.below(20)).map(|_| rng.next()).collect(),
                extension,
                payload: {
                    let n = if rng.below(50) == 0 {
                        MAX_PACKET + rng.below(MAX_PACKET)
                    } else {
                        rng.below(40)
                    };
                    rng.bytes(n)
                },
                padding: if rng.below(2) == 0 {
                    0
                } else {
                    rng.next() as u8
                },
            };
            let out = p.to_bytes();
            assert!(out.len() <= MAX_PACKET && out.capacity() <= MAX_PACKET);
            // An Other in an RFC 8285 form reads as that form, so only
            // the second write is sure to match.
            let back = RtpPacket::parse(&out).unwrap();
            assert_eq!(RtpPacket::parse(&back.to_bytes()), Ok(back));
            check_bytes(&out);

            let packets: Vec<RtcpPacket> =
                (0..rng.below(5)).map(|_| random_rtcp(&mut rng)).collect();
            let out = write_packets(&packets);
            let back = parse_packets(&out).unwrap();
            assert_eq!(parse_packets(&write_packets(&back)), Ok(back));
            // What write_compound gives always passes parse_compound.
            if let Ok(b) = write_compound(&packets) {
                assert_eq!(b, out);
                assert!(parse_compound(&b).is_ok());
            }
            check_bytes(&out);
        }
    }

    // Problems found in review, each against the RFC text.

    #[test]
    fn review_empty_nack_and_sli_are_rejected() {
        // RFC 4585 sections 6.2.1 and 6.3.2: the FCI must hold at least one
        // NACK or SLI entry.
        let nack = [0x81, 205, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(parse_packets(&nack), Err(RtcpError::Body(205)));
        let sli = [0x82, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(parse_packets(&sli), Err(RtcpError::Body(206)));
        // So the writer writes nothing for them.
        for message in [FeedbackMessage::Nack(vec![]), FeedbackMessage::Sli(vec![])] {
            let p = RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message,
            });
            assert_eq!(p.to_bytes(), Vec::<u8>::new());
        }
    }

    #[test]
    fn review_sdes_padding_must_be_null() {
        // RFC 3550 section 6.5: the item list ends in null octets up to the
        // next 32-bit boundary.
        let good = [0x81, 202, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0];
        assert!(parse_packets(&good).is_ok());
        let bad = [0x81, 202, 0, 2, 0, 0, 0, 1, 0, 0, 7, 0];
        assert_eq!(parse_packets(&bad), Err(RtcpError::Body(202)));
    }

    #[test]
    fn review_bye_padding_must_be_null() {
        // RFC 3550 section 6.6: the reason is padded with null octets.
        let good = [0x81, 203, 0, 2, 0, 0, 0, 1, 2, b'h', b'i', 0];
        assert!(parse_packets(&good).is_ok());
        let bad = [0x81, 203, 0, 2, 0, 0, 0, 1, 2, b'h', b'i', 9];
        assert_eq!(parse_packets(&bad), Err(RtcpError::Body(203)));
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
        assert_eq!(RtpPacket::parse(&p.to_bytes()), Ok(p));
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
    fn review_decoder_holds_at_most_max_buffered() {
        // Feeding without taking packets out stops at MAX_BUFFERED.
        let one = frame(&[7; 1000]);
        let mut d = Decoder::new();
        let mut taken = 0;
        for _ in 0..1000 {
            taken += d.feed(&one);
        }
        assert_eq!(taken, MAX_BUFFERED);
        assert_eq!(d.buffered(), MAX_BUFFERED);
        assert_eq!(d.feed(&one), 0);
        // Taking a packet out makes room for exactly its frame.
        assert_eq!(d.next_packet(), Some(vec![7; 1000]));
        assert_eq!(d.feed(&one), one.len());
        // A stream far larger than the limit still splits whole, and a
        // full decoder always holds a packet to take out.
        let big = frame(&[1; MAX_PACKET]);
        let stream: Vec<u8> = big
            .iter()
            .chain(&one)
            .copied()
            .cycle()
            .take(10 * big.len())
            .collect();
        let (packets, d) = split(&stream);
        let lens: usize = packets.iter().map(|p| p.len() + 2).sum();
        assert_eq!(lens + d.buffered(), stream.len());
        assert!(packets.len() >= 9);
        // A clone carries on the same way.
        let mut a = Decoder::new();
        assert_eq!(a.feed(&one[..3]), 3);
        let mut b = a.clone();
        assert_eq!(a.feed(&one[3..]), one.len() - 3);
        assert_eq!(b.feed(&one[3..]), one.len() - 3);
        assert_eq!(a.next_packet(), b.next_packet());
        assert_eq!((a.buffered(), b.buffered()), (0, 0));
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
            let b = p.to_bytes();
            assert!(is_rtcp(&b), "{pt}");
            assert!(!matches!(Packet::parse(&b), Ok(Packet::Rtp(_))));
            assert_eq!(RtpPacket::parse(&b), Ok(p.clone()));
            p.marker = false;
            assert_eq!(Packet::parse(&p.to_bytes()), Ok(Packet::Rtp(p)));
        }
    }

    #[test]
    fn review_rtp_writer_allocates_at_most_max_packet() {
        // A caller's payload far past MAX_PACKET must not size the buffer.
        let mut p = rtp(&vec![1; 4 * MAX_PACKET]);
        p.padding = 8;
        let out = p.to_bytes();
        assert_eq!(out.len(), MAX_PACKET);
        assert!(out.capacity() <= MAX_PACKET, "{}", out.capacity());
        p.extension = Some(HeaderExtension::Other {
            profile: 1,
            data: vec![2; 2 * MAX_PACKET],
        });
        let out = p.to_bytes();
        assert!(out.len() <= MAX_PACKET && out.capacity() <= MAX_PACKET);
        assert!(RtpPacket::parse(&out).is_ok());
    }

    #[test]
    fn review_compound_cname_comes_right_after_the_reports() {
        // RFC 3550 section 6.1: SR or RR, any additional RRs, then an SDES
        // packet with a CNAME, then other packet types.
        let rr = |ssrc| {
            RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc,
                reports: vec![],
                extension: vec![],
            })
        };
        let pli = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: FeedbackMessage::Pli,
        });
        assert_eq!(
            check_compound(&[rr(1), pli.clone(), cname(1)]),
            Err(RtcpError::NoCname)
        );
        assert_eq!(
            parse_compound(&write_packets(&[rr(1), pli.clone(), cname(1)])),
            Err(RtcpError::NoCname)
        );
        assert_eq!(
            check_compound(&[rr(1), rr(2), cname(1), pli.clone()]),
            Ok(())
        );
        let no_cname = RtcpPacket::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![],
        }]);
        assert_eq!(check_compound(&[rr(1), no_cname, cname(1), pli]), Ok(()));
        // A CNAME only in a chunk past MAX_COUNT is never written.
        let mut chunks = vec![
            SdesChunk {
                ssrc: 9,
                items: vec![],
            };
            MAX_COUNT
        ];
        chunks.push(SdesChunk {
            ssrc: 1,
            items: vec![SdesItem {
                kind: sdes::CNAME,
                text: b"a@b".to_vec(),
            }],
        });
        let late = [rr(1), RtcpPacket::SourceDescription(chunks)];
        assert_eq!(check_compound(&late), Err(RtcpError::NoCname));
        assert_eq!(write_compound(&late), Err(RtcpError::NoCname));
    }

    #[test]
    fn review_write_compound_checks_what_is_written() {
        // A report that fills the datagram leaves no room for the SDES:
        // write_packets drops it, write_compound says so.
        let big = RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 1,
            reports: vec![],
            extension: vec![0; 65_524],
        });
        let packets = [big, cname(1)];
        assert_eq!(check_compound(&packets), Ok(()));
        assert_eq!(
            parse_compound(&write_packets(&packets)),
            Err(RtcpError::NoCname)
        );
        assert!(matches!(
            write_compound(&packets),
            Err(RtcpError::TooLong(_))
        ));
        // A packet that writes no bytes, such as an empty NACK.
        let rr = RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 1,
            reports: vec![],
            extension: vec![],
        });
        let empty_nack = RtcpPacket::Feedback(Feedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: FeedbackMessage::Nack(vec![]),
        });
        assert_eq!(
            write_compound(&[rr.clone(), cname(1), empty_nack]),
            Err(RtcpError::Body(packet_type::RTPFB))
        );
        // Packets that follow the rules write as write_packets does.
        let packets = every_kind();
        let b = write_compound(&packets).unwrap();
        assert_eq!(b, write_packets(&packets));
        assert_eq!(parse_compound(&b), Ok(packets));
        assert_eq!(write_compound(&[]), Err(RtcpError::Empty));
        assert_eq!(
            write_compound(&[cname(1), rr]),
            Err(RtcpError::FirstNotReport(202))
        );
    }

    #[test]
    fn review_rpsi_padding_bits_are_zero() {
        // RFC 4585 section 6.3.3.2: the padding bits are set to zero.
        let fci = |pb: u8, data: [u8; 2]| {
            let mut b = vec![0x83, 206, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, pb, 96];
            b.extend_from_slice(&data);
            parse_packets(&b)
        };
        assert_eq!(fci(3, [0xab, 0x07]), Err(RtcpError::Body(206)));
        assert_eq!(fci(9, [0x01, 0x00]), Err(RtcpError::Body(206)));
        assert!(fci(3, [0xab, 0x08]).is_ok());
        assert!(fci(9, [0x02, 0x00]).is_ok());
        assert!(fci(16, [0, 0]).is_ok());
        assert!(fci(0, [0xff, 0xff]).is_ok());
        for pb in 0..=40u8 {
            let p = RtcpPacket::Feedback(Feedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: FeedbackMessage::Rpsi(Rpsi {
                    padding_bits: pb,
                    payload_type: 96,
                    data: vec![0xff; 3],
                }),
            });
            let b = p.to_bytes();
            let [
                RtcpPacket::Feedback(Feedback {
                    message: FeedbackMessage::Rpsi(r),
                    ..
                }),
            ] = &parse_packets(&b).unwrap()[..]
            else {
                panic!("{pb}")
            };
            assert!(!low_bits_set(&r.data, usize::from(r.padding_bits)), "{pb}");
        }
    }

    #[test]
    fn review_text_is_cut_at_a_character_boundary() {
        // RFC 3550 sections 6.5 and 6.6: SDES text and BYE reasons are
        // UTF-8, so a cut must not split a character.
        let text = "\u{e9}".repeat(128).into_bytes();
        let sdes = RtcpPacket::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![SdesItem {
                kind: sdes::NOTE,
                text: text.clone(),
            }],
        }]);
        let [RtcpPacket::SourceDescription(back)] = &parse_packets(&sdes.to_bytes()).unwrap()[..]
        else {
            panic!()
        };
        assert_eq!(back[0].items[0].text.len(), 254);
        assert!(std::str::from_utf8(&back[0].items[0].text).is_ok());
        let bye = RtcpPacket::Bye(Bye {
            sources: vec![1],
            reason: Some(text),
        });
        let [RtcpPacket::Bye(back)] = &parse_packets(&bye.to_bytes()).unwrap()[..] else {
            panic!()
        };
        let reason = back.reason.as_ref().unwrap();
        assert_eq!(reason.len(), 254);
        assert!(std::str::from_utf8(reason).is_ok());
        // Bytes that are not UTF-8 are cut at MAX_TEXT.
        assert_eq!(cut_text(&[0xff; 300]).len(), MAX_TEXT);
        assert_eq!(cut_text(b"abc"), b"abc");
    }

    #[test]
    fn review_priv_prefix_length_is_checked() {
        // RFC 3550 section 6.5.8: a PRIV item holds a prefix length, the
        // prefix, then the value.
        let bad = [0x81, 202, 0, 2, 0, 0, 0, 1, 8, 1, 0xff, 0];
        assert_eq!(parse_packets(&bad), Err(RtcpError::Body(202)));
        let empty = [0x81, 202, 0, 2, 0, 0, 0, 1, 8, 0, 0, 0];
        assert_eq!(parse_packets(&empty), Err(RtcpError::Body(202)));
        // Prefix "ab", value "x"; and a prefix with no value.
        let good = [0x81, 202, 0, 3, 0, 0, 0, 1, 8, 4, 2, b'a', b'b', b'x', 0, 0];
        assert!(parse_packets(&good).is_ok());
        let good = [0x81, 202, 0, 2, 0, 0, 0, 1, 8, 1, 0, 0];
        assert!(parse_packets(&good).is_ok());
        // The writer leaves out PRIV items that would not read.
        let p = RtcpPacket::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![
                SdesItem {
                    kind: sdes::PRIV,
                    text: vec![],
                },
                SdesItem {
                    kind: sdes::PRIV,
                    text: vec![5, b'a'],
                },
                SdesItem {
                    kind: sdes::PRIV,
                    text: [&[255][..], &[b'p'; 300][..]].concat(),
                },
                SdesItem {
                    kind: sdes::PRIV,
                    text: b"\x01ab".to_vec(),
                },
            ],
        }]);
        let [RtcpPacket::SourceDescription(back)] = &parse_packets(&p.to_bytes()).unwrap()[..]
        else {
            panic!()
        };
        assert_eq!(
            back[0].items,
            [SdesItem {
                kind: sdes::PRIV,
                text: b"\x01ab".to_vec()
            }]
        );
    }

    #[test]
    fn review_null_frames_are_empty_packets() {
        // RFC 4571 section 2: a length of 0 is the null packet. It comes
        // out empty, and the documented loop skips it.
        let a = rtp(&[1]).to_bytes();
        let stream = [frame(&[]), frame(&a), frame(&[])].concat();
        let (packets, _) = split(&stream);
        assert_eq!(packets, [vec![], a.clone(), vec![]]);
        let parsed: Vec<Packet> = packets
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| Packet::parse(p).unwrap())
            .collect();
        assert_eq!(parsed, [Packet::Rtp(rtp(&[1]))]);
    }
}
