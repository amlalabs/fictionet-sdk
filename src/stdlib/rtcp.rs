//! RTCP: reading and writing RTP control packets, with no I/O.
//!
//! RTCP travels beside RTP media and says how the media is doing. Senders
//! and receivers send reports on loss and jitter, name themselves in source
//! descriptions (SDES), say goodbye (BYE), and ask for lost packets, new
//! pictures or lower bitrates in feedback messages. It runs over UDP, on
//! the RTP port plus one, or on the RTP port itself when the two ends agree
//! to mux them. This module follows RFC 3550 (RTP and RTCP), RFC 4585 (the
//! feedback messages), RFC 5104 (FIR, TMMBR and TMMBN), RFC 3611 (extended
//! reports), RFC 5761 and RFC 7983 (telling packets apart on one port),
//! RFC 4571 (RTP and RTCP over a byte stream), and
//! draft-alvestrand-rmcat-remb (REMB).
//!
//! An RTCP datagram holds one or more packets back to back, each behind a
//! 4-byte common header: the version, a padding flag, a 5-bit count, the
//! packet type and the length in 32-bit words, less one. RFC 3550 calls
//! such a datagram a compound packet and sets rules for it. It starts with
//! a sender or receiver report, it carries an SDES CNAME, and only its last
//! packet may carry padding. RFC 4585 adds that feedback comes after the
//! reports and SDES. [`parse_packets`] reads a datagram into
//! [`Packet`]s. [`parse_compound`] reads one and checks those rules.
//! [`check_compound`] checks packets a world is about to send, and
//! [`write_compound`] writes them. The [`rtp`](crate::stdlib::rtp) module
//! reads the common packet types too. This module also reads TMMBR, TMMBN,
//! FIR, REMB and extended reports.
//!
//! Nothing here reads a socket. A world that plays a media server takes
//! each UDP datagram it receives, tells RTP from RTCP and from STUN or DTLS
//! with [`classify`], reads the RTCP with [`parse_compound`], and sends the
//! bytes of what it answers. Over TCP, a [`Decoder`] splits the byte stream
//! into datagrams first, and [`frame`] puts the length in front of each one
//! sent. What a report should say, and what to do about a NACK or a PLI, is
//! up to world code. SRTCP encryption is not handled here.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. Writers return an [`EncodeError`] rather than write
//! bytes a reader would refuse or read back as something else.
//!
//! ```
//! use fictionet::stdlib::rtcp::{
//!     Body, Demux, Nack, Packet, PayloadFeedback, PayloadMessage, ReceiverReport, SdesChunk, SdesItem,
//!     TransportFeedback, TransportMessage, classify, parse_compound, sdes, write_compound,
//! };
//!
//! // A receiver with nothing to report yet names itself and asks for a
//! // new picture.
//! let packets: Vec<Packet> = vec![
//!     Body::ReceiverReport(ReceiverReport { ssrc: 0xaaaa_aaaa, reports: vec![], extension: vec![] }).into(),
//!     Body::SourceDescription(vec![SdesChunk {
//!         ssrc: 0xaaaa_aaaa,
//!         items: vec![SdesItem { kind: sdes::CNAME, text: b"agent".to_vec() }],
//!     }])
//!     .into(),
//!     Body::PayloadFeedback(PayloadFeedback {
//!         sender_ssrc: 0xaaaa_aaaa,
//!         media_ssrc: 0x1234_5678,
//!         message: PayloadMessage::Pli,
//!     })
//!     .into(),
//! ];
//! let bytes = write_compound(&packets).unwrap();
//! // An 8-byte receiver report, a 16-byte SDES packet, then a 12-byte PLI.
//! assert_eq!(bytes.len(), 36);
//! assert_eq!(&bytes[..4], &[0x80, 201, 0, 1]);
//! assert_eq!(&bytes[24..28], &[0x81, 206, 0, 2]);
//! assert_eq!(classify(&bytes), Demux::Rtcp);
//! assert_eq!(parse_compound(&bytes), Ok(packets));
//!
//! // A NACK for sequence 100, and 102 from its bitmask.
//! let nack = Nack { pid: 100, blp: 0b10 };
//! assert_eq!(nack.lost(), vec![100, 102]);
//! let feedback = TransportFeedback { sender_ssrc: 1, media_ssrc: 2, message: TransportMessage::Nack(vec![nack]) };
//! let bytes = Packet::from(Body::TransportFeedback(feedback)).to_bytes().unwrap();
//! assert_eq!(bytes, [0x81, 205, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 100, 0, 2]);
//! ```

/// The RTP version every packet carries, in its top two bits.
pub const VERSION: u8 = 2;
/// The length of the common header in front of every RTCP packet.
pub const HEADER_LEN: usize = 4;
/// The longest datagram [`parse_packets`] reads and [`write_packets`]
/// writes: the most a UDP datagram holds.
pub const MAX_DATAGRAM: usize = 65535;
/// The longest single packet, header included: the longest whole number of
/// 32-bit words a datagram holds.
pub const MAX_PACKET: usize = 65532;
/// The most report blocks, SDES chunks, BYE sources, or the highest
/// subtype or feedback message type, the 5-bit count field holds.
pub const MAX_COUNT: usize = 31;
/// The length of one report block in a sender or receiver report.
pub const REPORT_BLOCK_LEN: usize = 24;
/// The longest SDES item text or BYE reason, in bytes.
pub const MAX_TEXT: usize = 255;
/// The most SSRCs one REMB message may list.
pub const MAX_REMB_SSRCS: usize = 255;
/// The lowest cumulative loss a report block holds, in 24 signed bits.
pub const MIN_CUMULATIVE_LOST: i32 = -(1 << 23);
/// The highest cumulative loss a report block holds.
pub const MAX_CUMULATIVE_LOST: i32 = (1 << 23) - 1;
/// The longest datagram an RFC 4571 frame carries: its length field is 16
/// bits.
pub const MAX_FRAME: usize = 65535;
/// The most bytes a [`Decoder`] holds that have not been taken out: one
/// longest frame and its length field.
pub const MAX_BUFFERED: usize = 2 + MAX_FRAME;

/// RTCP packet types.
pub mod packet_type {
    /// Sender report (RFC 3550).
    pub const SR: u8 = 200;
    /// Receiver report (RFC 3550).
    pub const RR: u8 = 201;
    /// Source description (RFC 3550).
    pub const SDES: u8 = 202;
    /// Goodbye (RFC 3550).
    pub const BYE: u8 = 203;
    /// Application-defined (RFC 3550).
    pub const APP: u8 = 204;
    /// Transport-layer feedback (RFC 4585).
    pub const RTPFB: u8 = 205;
    /// Payload-specific feedback (RFC 4585).
    pub const PSFB: u8 = 206;
    /// Extended report (RFC 3611).
    pub const XR: u8 = 207;
}

/// SDES item types from RFC 3550. Other numbers are kept by number.
pub mod sdes {
    /// Ends a chunk's items. Never an item's own type.
    pub const END: u8 = 0;
    /// Canonical name, such as `user@host`. Every compound packet carries
    /// one.
    pub const CNAME: u8 = 1;
    /// The user's name.
    pub const NAME: u8 = 2;
    /// An email address.
    pub const EMAIL: u8 = 3;
    /// A phone number.
    pub const PHONE: u8 = 4;
    /// Where the user is.
    pub const LOC: u8 = 5;
    /// The application or tool's name and version.
    pub const TOOL: u8 = 6;
    /// A notice or status.
    pub const NOTE: u8 = 7;
    /// A private extension: a prefix length, the prefix, then a value.
    pub const PRIV: u8 = 8;
}

/// Transport-layer feedback message types (the FMT field of a
/// [`packet_type::RTPFB`] packet) this module reads by name.
pub mod rtpfb {
    /// Generic NACK (RFC 4585).
    pub const NACK: u8 = 1;
    /// Temporary maximum media stream bitrate request (RFC 5104).
    pub const TMMBR: u8 = 3;
    /// Temporary maximum media stream bitrate notification (RFC 5104).
    pub const TMMBN: u8 = 4;
}

/// Payload-specific feedback message types (the FMT field of a
/// [`packet_type::PSFB`] packet) this module reads by name.
pub mod psfb {
    /// Picture loss indication (RFC 4585).
    pub const PLI: u8 = 1;
    /// Slice loss indication (RFC 4585).
    pub const SLI: u8 = 2;
    /// Reference picture selection indication (RFC 4585).
    pub const RPSI: u8 = 3;
    /// Full intra request (RFC 5104).
    pub const FIR: u8 = 4;
    /// Application layer feedback (RFC 4585), which carries REMB.
    pub const AFB: u8 = 15;
}

/// Extended report block types from RFC 3611.
pub mod xr {
    /// Loss run-length encoding.
    pub const LOSS_RLE: u8 = 1;
    /// Duplicate run-length encoding.
    pub const DUPLICATE_RLE: u8 = 2;
    /// Packet receipt times.
    pub const PACKET_RECEIPT_TIMES: u8 = 3;
    /// Receiver reference time: a receiver's NTP timestamp.
    pub const RECEIVER_REFERENCE_TIME: u8 = 4;
    /// Delay since last receiver report: the answer to a reference time.
    pub const DLRR: u8 = 5;
    /// Statistics summary.
    pub const STATISTICS_SUMMARY: u8 = 6;
    /// VoIP metrics.
    pub const VOIP_METRICS: u8 = 7;
}

/// One RTCP packet: what it carries, and how many bytes of padding follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The packet's type and contents.
    pub body: Body,
    /// Bytes of padding after the contents, the last of which holds their
    /// number. 0 means no padding and a clear padding flag. It is a
    /// multiple of 4 (RFC 3550 section 6.4.1), and the contents fill whole
    /// 32-bit words. A REMB never carries padding.
    pub padding: u8,
}

impl From<Body> for Packet {
    fn from(body: Body) -> Packet {
        Packet { body, padding: 0 }
    }
}

/// What an RTCP packet carries, by packet type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// Type 200: a sender's report.
    SenderReport(SenderReport),
    /// Type 201: a receiver's report.
    ReceiverReport(ReceiverReport),
    /// Type 202: source descriptions, at most [`MAX_COUNT`] chunks.
    SourceDescription(Vec<SdesChunk>),
    /// Type 203: sources leaving the session.
    Bye(Bye),
    /// Type 204: an application-defined packet.
    App(App),
    /// Type 205: transport-layer feedback.
    TransportFeedback(TransportFeedback),
    /// Type 206: payload-specific feedback.
    PayloadFeedback(PayloadFeedback),
    /// Type 207: an extended report.
    ExtendedReport(ExtendedReport),
    /// Any other packet type, with its count field and contents unread.
    Other {
        /// The packet type: any but 200 to 207.
        packet_type: u8,
        /// The 5-bit count field.
        count: u8,
        /// The contents after the header, padding left out: whole 32-bit
        /// words.
        data: Vec<u8>,
    },
}

/// A sender report: what a source has sent, and how it hears others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReport {
    /// The sender's SSRC.
    pub ssrc: u32,
    /// The wall-clock time the report was sent, as a 64-bit NTP timestamp.
    pub ntp_timestamp: u64,
    /// The same time in the RTP timestamp's units.
    pub rtp_timestamp: u32,
    /// RTP packets sent so far.
    pub packet_count: u32,
    /// Payload bytes sent so far.
    pub octet_count: u32,
    /// Reports on sources heard, at most [`MAX_COUNT`].
    pub reports: Vec<ReportBlock>,
    /// A profile-specific extension: whole 32-bit words.
    pub extension: Vec<u8>,
}

/// A receiver report: how a source that does not send hears others.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverReport {
    /// The reporter's SSRC.
    pub ssrc: u32,
    /// Reports on sources heard, at most [`MAX_COUNT`].
    pub reports: Vec<ReportBlock>,
    /// A profile-specific extension: whole 32-bit words.
    pub extension: Vec<u8>,
}

/// One report block: how the reporter hears one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportBlock {
    /// The source reported on.
    pub ssrc: u32,
    /// The share of packets lost since the last report, in 256ths.
    pub fraction_lost: u8,
    /// Packets lost in all, from [`MIN_CUMULATIVE_LOST`] to
    /// [`MAX_CUMULATIVE_LOST`]. Duplicates can make it negative.
    pub cumulative_lost: i32,
    /// The highest sequence number received, with the count of wraps in
    /// the top 16 bits.
    pub highest_sequence: u32,
    /// Interarrival jitter, in RTP timestamp units.
    pub jitter: u32,
    /// The middle 32 bits of the last sender report's NTP timestamp.
    pub last_sr: u32,
    /// The time since that sender report, in 65536ths of a second.
    pub delay_since_last_sr: u32,
}

/// One SDES chunk: items that describe one source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesChunk {
    /// The source described.
    pub ssrc: u32,
    /// Its items, in order.
    pub items: Vec<SdesItem>,
}

/// One SDES item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesItem {
    /// The item type, from [`sdes`] or any other number but 0.
    pub kind: u8,
    /// The item's text, at most [`MAX_TEXT`] bytes. RFC 3550 says UTF-8,
    /// but any bytes are kept. A [`sdes::PRIV`] item's text is a prefix
    /// length, the prefix and the value, and the prefix must fit.
    pub text: Vec<u8>,
}

impl SdesItem {
    /// Whether the item's text fits its type: a [`sdes::PRIV`] item needs
    /// a prefix length that fits. Any text fits other types.
    fn layout_ok(&self) -> bool {
        self.kind != sdes::PRIV || self.priv_parts().is_some()
    }

    /// A [`sdes::PRIV`] item's prefix and value. `None` for any other
    /// type, or when the prefix length runs past the text.
    pub fn priv_parts(&self) -> Option<(&[u8], &[u8])> {
        if self.kind != sdes::PRIV {
            return None;
        }
        let (&n, rest) = self.text.split_first()?;
        let n = usize::from(n);
        if n > rest.len() {
            return None;
        }
        Some(rest.split_at(n))
    }
}

/// A BYE: sources leaving the session, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bye {
    /// The sources leaving, at most [`MAX_COUNT`].
    pub sources: Vec<u32>,
    /// The reason, at most [`MAX_TEXT`] bytes. `None` leaves the field out,
    /// which is not the same packet as an empty reason.
    pub reason: Option<Vec<u8>>,
}

/// An application-defined packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App {
    /// The subtype, 0 to 31, in the count field.
    pub subtype: u8,
    /// The sender's SSRC.
    pub ssrc: u32,
    /// The four-character name of the application.
    pub name: [u8; 4],
    /// Application data: whole 32-bit words.
    pub data: Vec<u8>,
}

/// A transport-layer feedback message (RFC 4585, type 205).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportFeedback {
    /// The SSRC of the source sending the feedback.
    pub sender_ssrc: u32,
    /// The SSRC of the media source it is about. TMMBR and TMMBN do not
    /// use it: they name sources in their entries, writers refuse any
    /// value but 0, and readers read it as 0 (RFC 5104 sections 4.2.1.2
    /// and 4.2.2.2).
    pub media_ssrc: u32,
    /// The message.
    pub message: TransportMessage,
}

/// A transport-layer feedback message, by its FMT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportMessage {
    /// FMT 1: packets the receiver asks to be sent again. At least one.
    Nack(Vec<Nack>),
    /// FMT 3: bitrate limits a receiver asks for. At least one.
    Tmmbr(Vec<Tmmb>),
    /// FMT 4: bitrate limits a sender has accepted. May be empty.
    Tmmbn(Vec<Tmmb>),
    /// Any other FMT, with its feedback control information unread.
    Other {
        /// The FMT: 0 to 31, but not 1, 3 or 4.
        fmt: u8,
        /// The feedback control information: whole 32-bit words.
        fci: Vec<u8>,
    },
}

/// One generic NACK entry: a lost packet and a mask of 16 more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nack {
    /// The sequence number of a lost packet.
    pub pid: u16,
    /// Bit `i` set means packet `pid + i + 1` was lost too.
    pub blp: u16,
}

impl Nack {
    /// Every sequence number this entry says was lost, in order. Sequence
    /// numbers wrap at 65536.
    pub fn lost(&self) -> Vec<u16> {
        let mut out = vec![self.pid];
        for i in 0..16u16 {
            if self.blp >> i & 1 == 1 {
                out.push(self.pid.wrapping_add(i + 1));
            }
        }
        out
    }

    /// Entries that ask for every sequence number in `lost`, at most one
    /// entry per number. A number from 1 to 16 past the current entry's
    /// `pid` goes in its mask. Any other starts a new entry. Sorted input,
    /// with wraps at 65536 in order, gives the fewest entries.
    pub fn from_lost(lost: &[u16]) -> Vec<Nack> {
        let mut out: Vec<Nack> = Vec::new();
        for &seq in lost {
            match out.last_mut() {
                Some(n) if (1..=16).contains(&seq.wrapping_sub(n.pid)) => {
                    n.blp |= 1 << (seq.wrapping_sub(n.pid) - 1);
                }
                _ => out.push(Nack { pid: seq, blp: 0 }),
            }
        }
        out
    }
}

/// One TMMBR or TMMBN entry: a bitrate limit. The bitrate is
/// `mantissa * 2^exponent` bits per second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tmmb {
    /// In a TMMBR, the media sender the limit is for. In a TMMBN, the
    /// limit's owner: the participant that asked for it, usually a
    /// receiver (RFC 5104 sections 4.2.1.1 and 4.2.2.1).
    pub ssrc: u32,
    /// The bitrate's exponent, 0 to 63.
    pub exponent: u8,
    /// The bitrate's mantissa, below 2^17.
    pub mantissa: u32,
    /// The measured per-packet overhead in bytes, below 512.
    pub overhead: u16,
}

impl Tmmb {
    /// The bitrate limit in bits per second, at most `u64::MAX`.
    pub fn bitrate(&self) -> u64 {
        bitrate(self.mantissa, self.exponent)
    }

    /// An entry with `ssrc` and a limit of `bps`, rounded down to what 17
    /// bits of mantissa hold. For a TMMBR, `ssrc` is the media sender to
    /// limit. For a TMMBN, it is the limit's owner.
    pub fn with_bitrate(ssrc: u32, bps: u64, overhead: u16) -> Tmmb {
        let (exponent, mantissa) = split_bitrate(bps, 17);
        Tmmb { ssrc, exponent, mantissa, overhead }
    }
}

/// A payload-specific feedback message (RFC 4585, type 206).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFeedback {
    /// The SSRC of the source sending the feedback.
    pub sender_ssrc: u32,
    /// The SSRC of the media source it is about. FIR and REMB do not use
    /// it: writers refuse any value but 0, and readers read it as 0 (RFC
    /// 5104 section 4.3.1.2, draft-alvestrand-rmcat-remb section 2.2).
    pub media_ssrc: u32,
    /// The message.
    pub message: PayloadMessage,
}

/// A payload-specific feedback message, by its FMT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadMessage {
    /// FMT 1: the receiver lost a picture and wants a new one.
    Pli,
    /// FMT 2: macroblocks lost. At least one entry.
    Sli(Vec<Sli>),
    /// FMT 3: the reference picture the receiver has.
    Rpsi(Rpsi),
    /// FMT 4: a request for a full intra picture. At least one entry.
    Fir(Vec<Fir>),
    /// FMT 15 with `REMB` first: a receiver's estimated maximum bitrate.
    /// FMT 15 that starts with `REMB` but does not fit one is malformed.
    Remb(Remb),
    /// FMT 15 with anything else: application layer feedback, unread.
    /// Whole 32-bit words that do not start with `REMB`.
    Afb(Vec<u8>),
    /// Any other FMT, with its feedback control information unread.
    Other {
        /// The FMT: 0 to 31, but not 1, 2, 3, 4 or 15.
        fmt: u8,
        /// The feedback control information: whole 32-bit words.
        fci: Vec<u8>,
    },
}

/// One slice loss entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sli {
    /// The first lost macroblock, below 8192.
    pub first: u16,
    /// How many macroblocks were lost, below 8192.
    pub number: u16,
    /// The low 6 bits of the picture's ID, below 64.
    pub picture_id: u8,
}

/// A reference picture selection indication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rpsi {
    /// The RTP payload type the bit string is for, below 128.
    pub payload_type: u8,
    /// How many bits at the end of `data` are padding, not part of the
    /// bit string: below 32, at most `8 * data.len()`, and all zero (RFC
    /// 4585 section 6.3.3.2).
    pub padding_bits: u8,
    /// The codec's bit string and its padding. With the 2 bytes before
    /// it, whole 32-bit words.
    pub data: Vec<u8>,
}

/// One full intra request entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fir {
    /// The media source asked for a new picture.
    pub ssrc: u32,
    /// A sequence number the requester raises with each new request, so a
    /// repeat can be told from a new one.
    pub sequence: u8,
}

/// A receiver estimated maximum bitrate message. The bitrate is
/// `mantissa * 2^exponent` bits per second.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remb {
    /// The bitrate's exponent, 0 to 63.
    pub exponent: u8,
    /// The bitrate's mantissa, below 2^18.
    pub mantissa: u32,
    /// The sources the estimate is for: at least one, at most
    /// [`MAX_REMB_SSRCS`].
    pub ssrcs: Vec<u32>,
}

impl Remb {
    /// The estimated bitrate in bits per second, at most `u64::MAX`.
    pub fn bitrate(&self) -> u64 {
        bitrate(self.mantissa, self.exponent)
    }

    /// An estimate of `bps` for `ssrcs`, rounded down to what 18 bits of
    /// mantissa hold.
    pub fn with_bitrate(bps: u64, ssrcs: Vec<u32>) -> Remb {
        let (exponent, mantissa) = split_bitrate(bps, 18);
        Remb { exponent, mantissa, ssrcs }
    }
}

/// An extended report (RFC 3611): blocks typed by number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedReport {
    /// The reporter's SSRC.
    pub ssrc: u32,
    /// The report blocks, in order.
    pub blocks: Vec<XrBlock>,
}

/// One extended report block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XrBlock {
    /// The block type, from [`xr`] or any other number.
    pub block_type: u8,
    /// The byte after the type, whose meaning depends on it. It is
    /// reserved in receiver reference time, DLRR and VoIP metrics blocks:
    /// writers refuse any value but 0, and readers read it as 0.
    pub type_specific: u8,
    /// The block's contents after its 4-byte header: whole 32-bit words.
    /// RFC 3611 sets the length of the types in [`xr`]: at least 8 bytes
    /// for types 1 to 3, 8 for a receiver reference time, a multiple of
    /// 12 for a DLRR, 36 for a statistics summary and 32 for VoIP
    /// metrics. Other types may hold any number of words.
    pub data: Vec<u8>,
}

/// One DLRR sub-block: the answer to one receiver's reference time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DlrrItem {
    /// The receiver that sent the reference time.
    pub ssrc: u32,
    /// The middle 32 bits of its NTP timestamp.
    pub last_rr: u32,
    /// The time since it came, in 65536ths of a second.
    pub delay_since_last_rr: u32,
}

impl XrBlock {
    /// A receiver reference time block holding `ntp_timestamp`.
    pub fn receiver_reference_time(ntp_timestamp: u64) -> XrBlock {
        XrBlock {
            block_type: xr::RECEIVER_REFERENCE_TIME,
            type_specific: 0,
            data: ntp_timestamp.to_be_bytes().to_vec(),
        }
    }

    /// A receiver reference time block's NTP timestamp. `None` for any
    /// other block, or one of the wrong length.
    pub fn ntp_timestamp(&self) -> Option<u64> {
        if self.block_type != xr::RECEIVER_REFERENCE_TIME {
            return None;
        }
        let b: [u8; 8] = self.data.as_slice().try_into().ok()?;
        Some(u64::from_be_bytes(b))
    }

    /// A DLRR block holding `items`.
    pub fn dlrr(items: &[DlrrItem]) -> XrBlock {
        let mut data = Vec::with_capacity(12 * items.len());
        for i in items {
            data.extend_from_slice(&i.ssrc.to_be_bytes());
            data.extend_from_slice(&i.last_rr.to_be_bytes());
            data.extend_from_slice(&i.delay_since_last_rr.to_be_bytes());
        }
        XrBlock { block_type: xr::DLRR, type_specific: 0, data }
    }

    /// A DLRR block's items. `None` for any other block, or one whose
    /// length is not a whole number of items.
    pub fn dlrr_items(&self) -> Option<Vec<DlrrItem>> {
        if self.block_type != xr::DLRR || !self.data.len().is_multiple_of(12) {
            return None;
        }
        Some(
            self.data
                .chunks_exact(12)
                .map(|c| DlrrItem { ssrc: be32(c, 0), last_rr: be32(c, 4), delay_since_last_rr: be32(c, 8) })
                .collect(),
        )
    }
}

/// Why bytes are not RTCP packets this module can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The datagram held no bytes.
    Empty,
    /// The datagram was longer than [`MAX_DATAGRAM`], or a header gave a
    /// packet longer than [`MAX_PACKET`]. Holds that length.
    TooLong(usize),
    /// A header, or the length it gives, ran past the end of the datagram.
    Truncated,
    /// The version was not 2; holds what it was.
    Version(u8),
    /// The padding flag was set, but the last byte said 0 bytes of
    /// padding, a number that is not a multiple of 4, or more than the
    /// packet holds.
    Padding,
    /// A packet's contents do not fit its type; holds the packet type.
    Malformed(u8),
    /// The packets read, but break a rule for compound packets.
    Compound(CompoundError),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => f.write_str("an empty RTCP datagram"),
            ParseError::TooLong(n) => write!(f, "a {n}-byte datagram or packet, longer than UDP holds"),
            ParseError::Truncated => f.write_str("an RTCP packet runs past the end of the datagram"),
            ParseError::Version(v) => write!(f, "RTP version {v}, not 2"),
            ParseError::Padding => f.write_str("a padding count of 0 or more than the packet holds"),
            ParseError::Malformed(t) => write!(f, "contents that do not fit RTCP packet type {t}"),
            ParseError::Compound(e) => write!(f, "not a valid compound packet: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A rule of RFC 3550 for compound packets that a list of packets breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompoundError {
    /// There are no packets.
    Empty,
    /// The first packet is not a sender or receiver report; holds its
    /// packet type.
    FirstNotReport(u8),
    /// No SDES chunk carries a CNAME item.
    NoCname,
    /// A packet other than the last carries padding.
    Padding,
    /// A feedback packet (RTPFB or PSFB) comes before a sender report,
    /// receiver report or SDES packet. RFC 4585 puts feedback after them.
    FeedbackOrder,
}

impl std::fmt::Display for CompoundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompoundError::Empty => f.write_str("no packets"),
            CompoundError::FirstNotReport(t) => write!(f, "the first packet is type {t}, not SR or RR"),
            CompoundError::NoCname => f.write_str("no SDES CNAME item"),
            CompoundError::Padding => f.write_str("padding on a packet other than the last"),
            CompoundError::FeedbackOrder => f.write_str("a feedback packet before a report or SDES packet"),
        }
    }
}

impl std::error::Error for CompoundError {}

/// Why a writer refused a value: its bytes would break the specification,
/// or a reader would read them back as something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// More report blocks, chunks or sources than the count field holds,
    /// or more SSRCs than a REMB lists.
    TooMany,
    /// Text longer than [`MAX_TEXT`], a packet longer than [`MAX_PACKET`],
    /// a datagram longer than [`MAX_DATAGRAM`], or a block longer than its
    /// length field holds.
    TooLong,
    /// A field outside the bits it is written in: a cumulative loss, an
    /// exponent, mantissa or overhead, an SLI field, an RPSI payload type
    /// or padding bit count, a subtype or FMT over 31, or an SDES item of
    /// type 0. Also a value the specification rules out: RPSI padding bits
    /// that are not zero, a PRIV item whose prefix does not fit, a media
    /// SSRC other than 0 in a TMMBR, TMMBN, FIR or REMB, a REMB with
    /// padding, or a known XR block of the wrong length or with a reserved
    /// byte set.
    Range,
    /// Contents and padding that do not fill whole 32-bit words.
    Alignment,
    /// No packets, or a NACK, TMMBR, SLI, FIR or REMB with no entries.
    Empty,
    /// An `Other` value a reader would read back as a typed one, or an
    /// `Afb` that starts with `REMB`.
    Alias,
    /// The packets break a rule for compound packets.
    Compound(CompoundError),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooMany => f.write_str("more entries than the packet's count field holds"),
            EncodeError::TooLong => f.write_str("longer than the field or datagram holds"),
            EncodeError::Range => f.write_str("a field outside the bits it is written in"),
            EncodeError::Alignment => f.write_str("contents that do not fill whole 32-bit words"),
            EncodeError::Empty => f.write_str("a list that may not be empty is"),
            EncodeError::Alias => f.write_str("an untyped value that would read back as a typed one"),
            EncodeError::Compound(e) => write!(f, "not a valid compound packet: {e}"),
        }
    }
}

impl std::error::Error for EncodeError {}

impl Body {
    /// The packet type this body is written with.
    pub fn packet_type(&self) -> u8 {
        match self {
            Body::SenderReport(_) => packet_type::SR,
            Body::ReceiverReport(_) => packet_type::RR,
            Body::SourceDescription(_) => packet_type::SDES,
            Body::Bye(_) => packet_type::BYE,
            Body::App(_) => packet_type::APP,
            Body::TransportFeedback(_) => packet_type::RTPFB,
            Body::PayloadFeedback(_) => packet_type::PSFB,
            Body::ExtendedReport(_) => packet_type::XR,
            Body::Other { packet_type, .. } => *packet_type,
        }
    }

    /// Whether this is a REMB, which never carries padding.
    fn is_remb(&self) -> bool {
        matches!(self, Body::PayloadFeedback(PayloadFeedback { message: PayloadMessage::Remb(_), .. }))
    }

    /// Reads contents `c`, padding left out, of a packet of type `pt` with
    /// count field `count`.
    fn parse(pt: u8, count: u8, c: &[u8]) -> Result<Body, ParseError> {
        let bad = ParseError::Malformed(pt);
        let typed = (packet_type::SR..=packet_type::XR).contains(&pt);
        if typed && !c.len().is_multiple_of(4) {
            return Err(bad);
        }
        let n = usize::from(count);
        Ok(match pt {
            packet_type::SR => {
                if c.len() < 24 + n * REPORT_BLOCK_LEN {
                    return Err(bad);
                }
                Body::SenderReport(SenderReport {
                    ssrc: be32(c, 0),
                    ntp_timestamp: u64::from(be32(c, 4)) << 32 | u64::from(be32(c, 8)),
                    rtp_timestamp: be32(c, 12),
                    packet_count: be32(c, 16),
                    octet_count: be32(c, 20),
                    reports: report_blocks(&c[24..], n),
                    extension: c[24 + n * REPORT_BLOCK_LEN..].to_vec(),
                })
            }
            packet_type::RR => {
                if c.len() < 4 + n * REPORT_BLOCK_LEN {
                    return Err(bad);
                }
                Body::ReceiverReport(ReceiverReport {
                    ssrc: be32(c, 0),
                    reports: report_blocks(&c[4..], n),
                    extension: c[4 + n * REPORT_BLOCK_LEN..].to_vec(),
                })
            }
            packet_type::SDES => Body::SourceDescription(parse_sdes(c, n).ok_or(bad)?),
            packet_type::BYE => {
                if c.len() < 4 * n {
                    return Err(bad);
                }
                let sources = (0..n).map(|i| be32(c, 4 * i)).collect();
                let rest = &c[4 * n..];
                let reason = match rest.split_first() {
                    None => None,
                    Some((&len, rest)) => {
                        let len = usize::from(len);
                        if len > rest.len() {
                            return Err(bad);
                        }
                        let (text, tail) = rest.split_at(len);
                        if tail.len() >= 4 || tail.iter().any(|&b| b != 0) {
                            return Err(bad);
                        }
                        Some(text.to_vec())
                    }
                };
                Body::Bye(Bye { sources, reason })
            }
            packet_type::APP => {
                if c.len() < 8 {
                    return Err(bad);
                }
                Body::App(App {
                    subtype: count,
                    ssrc: be32(c, 0),
                    name: [c[4], c[5], c[6], c[7]],
                    data: c[8..].to_vec(),
                })
            }
            packet_type::RTPFB => {
                if c.len() < 8 {
                    return Err(bad);
                }
                let fci = &c[8..];
                let mut media_ssrc = be32(c, 4);
                let message = match count {
                    rtpfb::NACK => {
                        if fci.is_empty() {
                            return Err(bad);
                        }
                        TransportMessage::Nack(
                            fci.chunks_exact(4).map(|e| Nack { pid: be16(e, 0), blp: be16(e, 2) }).collect(),
                        )
                    }
                    rtpfb::TMMBR | rtpfb::TMMBN => {
                        if !fci.len().is_multiple_of(8) || (count == rtpfb::TMMBR && fci.is_empty()) {
                            return Err(bad);
                        }
                        let items = fci
                            .chunks_exact(8)
                            .map(|e| {
                                let v = be32(e, 4);
                                Tmmb {
                                    ssrc: be32(e, 0),
                                    exponent: (v >> 26) as u8,
                                    mantissa: v >> 9 & 0x1_ffff,
                                    overhead: (v & 0x1ff) as u16,
                                }
                            })
                            .collect();
                        // The media SSRC is unused, and ignored on reading.
                        media_ssrc = 0;
                        if count == rtpfb::TMMBR {
                            TransportMessage::Tmmbr(items)
                        } else {
                            TransportMessage::Tmmbn(items)
                        }
                    }
                    fmt => TransportMessage::Other { fmt, fci: fci.to_vec() },
                };
                Body::TransportFeedback(TransportFeedback { sender_ssrc: be32(c, 0), media_ssrc, message })
            }
            packet_type::PSFB => {
                if c.len() < 8 {
                    return Err(bad);
                }
                let fci = &c[8..];
                let mut media_ssrc = be32(c, 4);
                let message = match count {
                    psfb::PLI => {
                        if !fci.is_empty() {
                            return Err(bad);
                        }
                        PayloadMessage::Pli
                    }
                    psfb::SLI => {
                        if fci.is_empty() {
                            return Err(bad);
                        }
                        PayloadMessage::Sli(
                            fci.chunks_exact(4)
                                .map(|e| {
                                    let v = be32(e, 0);
                                    Sli {
                                        first: (v >> 19) as u16,
                                        number: (v >> 6 & 0x1fff) as u16,
                                        picture_id: (v & 0x3f) as u8,
                                    }
                                })
                                .collect(),
                        )
                    }
                    psfb::RPSI => {
                        let [pb, pt, data @ ..] = fci else { return Err(bad) };
                        if !rpsi_padding_ok(*pb, data) {
                            return Err(bad);
                        }
                        // The bit above the payload type is ignored on reading.
                        PayloadMessage::Rpsi(Rpsi { payload_type: pt & 0x7f, padding_bits: *pb, data: data.to_vec() })
                    }
                    psfb::FIR => {
                        if fci.is_empty() || !fci.len().is_multiple_of(8) {
                            return Err(bad);
                        }
                        // The media SSRC is unused, and ignored on reading.
                        media_ssrc = 0;
                        PayloadMessage::Fir(
                            fci.chunks_exact(8).map(|e| Fir { ssrc: be32(e, 0), sequence: e[4] }).collect(),
                        )
                    }
                    psfb::AFB if fci.starts_with(REMB_ID) => {
                        // The media SSRC is unused, and ignored on reading.
                        media_ssrc = 0;
                        PayloadMessage::Remb(parse_remb(fci).ok_or(bad)?)
                    }
                    psfb::AFB => PayloadMessage::Afb(fci.to_vec()),
                    fmt => PayloadMessage::Other { fmt, fci: fci.to_vec() },
                };
                Body::PayloadFeedback(PayloadFeedback { sender_ssrc: be32(c, 0), media_ssrc, message })
            }
            packet_type::XR => {
                if c.len() < 4 {
                    return Err(bad);
                }
                let mut blocks = Vec::new();
                let mut pos = 4;
                while pos < c.len() {
                    // The header and the length it gives must fit.
                    let header = c.get(pos..pos + 4).ok_or(bad)?;
                    let len = 4 * (usize::from(be16(header, 2)) + 1);
                    let block = c.get(pos..pos + len).ok_or(bad)?;
                    let (block_type, data) = (header[0], &block[4..]);
                    if !xr_layout_ok(block_type, data.len()) {
                        return Err(bad);
                    }
                    // A reserved byte after the type is ignored on reading.
                    let type_specific = if xr_reserved(block_type) { 0 } else { header[1] };
                    blocks.push(XrBlock { block_type, type_specific, data: data.to_vec() });
                    pos += len;
                }
                Body::ExtendedReport(ExtendedReport { ssrc: be32(c, 0), blocks })
            }
            _ => Body::Other { packet_type: pt, count, data: c.to_vec() },
        })
    }

    /// The count field and contents this body is written with.
    fn encode(&self) -> Result<(u8, Vec<u8>), EncodeError> {
        let mut out = Vec::new();
        let count = match self {
            Body::SenderReport(sr) => {
                out.extend_from_slice(&sr.ssrc.to_be_bytes());
                out.extend_from_slice(&sr.ntp_timestamp.to_be_bytes());
                out.extend_from_slice(&sr.rtp_timestamp.to_be_bytes());
                out.extend_from_slice(&sr.packet_count.to_be_bytes());
                out.extend_from_slice(&sr.octet_count.to_be_bytes());
                write_reports(&mut out, &sr.reports, &sr.extension)?
            }
            Body::ReceiverReport(rr) => {
                out.extend_from_slice(&rr.ssrc.to_be_bytes());
                write_reports(&mut out, &rr.reports, &rr.extension)?
            }
            Body::SourceDescription(chunks) => {
                if chunks.len() > MAX_COUNT {
                    return Err(EncodeError::TooMany);
                }
                for chunk in chunks {
                    out.extend_from_slice(&chunk.ssrc.to_be_bytes());
                    for item in &chunk.items {
                        if item.kind == sdes::END {
                            return Err(EncodeError::Range);
                        }
                        if item.text.len() > MAX_TEXT {
                            return Err(EncodeError::TooLong);
                        }
                        if !item.layout_ok() {
                            return Err(EncodeError::Range);
                        }
                        check_size(out.len() + 2 + item.text.len())?;
                        out.push(item.kind);
                        out.push(item.text.len() as u8);
                        out.extend_from_slice(&item.text);
                    }
                    out.push(sdes::END);
                    pad_words(&mut out);
                }
                chunks.len() as u8
            }
            Body::Bye(bye) => {
                if bye.sources.len() > MAX_COUNT {
                    return Err(EncodeError::TooMany);
                }
                for s in &bye.sources {
                    out.extend_from_slice(&s.to_be_bytes());
                }
                if let Some(reason) = &bye.reason {
                    if reason.len() > MAX_TEXT {
                        return Err(EncodeError::TooLong);
                    }
                    out.push(reason.len() as u8);
                    out.extend_from_slice(reason);
                    pad_words(&mut out);
                }
                bye.sources.len() as u8
            }
            Body::App(app) => {
                if usize::from(app.subtype) > MAX_COUNT {
                    return Err(EncodeError::Range);
                }
                words(&app.data)?;
                check_size(8usize.saturating_add(app.data.len()))?;
                out.extend_from_slice(&app.ssrc.to_be_bytes());
                out.extend_from_slice(&app.name);
                out.extend_from_slice(&app.data);
                app.subtype
            }
            Body::TransportFeedback(fb) => {
                out.extend_from_slice(&fb.sender_ssrc.to_be_bytes());
                out.extend_from_slice(&fb.media_ssrc.to_be_bytes());
                match &fb.message {
                    TransportMessage::Nack(entries) => {
                        nonempty(entries)?;
                        check_size(out.len() + 4 * entries.len())?;
                        for e in entries {
                            out.extend_from_slice(&e.pid.to_be_bytes());
                            out.extend_from_slice(&e.blp.to_be_bytes());
                        }
                        rtpfb::NACK
                    }
                    TransportMessage::Tmmbr(items) | TransportMessage::Tmmbn(items) => {
                        unused_media_ssrc(fb.media_ssrc)?;
                        let request = matches!(fb.message, TransportMessage::Tmmbr(_));
                        if request {
                            nonempty(items)?;
                        }
                        check_size(out.len() + 8 * items.len())?;
                        for i in items {
                            if i.exponent > 63 || i.mantissa >= 1 << 17 || i.overhead >= 1 << 9 {
                                return Err(EncodeError::Range);
                            }
                            out.extend_from_slice(&i.ssrc.to_be_bytes());
                            let v = u32::from(i.exponent) << 26 | i.mantissa << 9 | u32::from(i.overhead);
                            out.extend_from_slice(&v.to_be_bytes());
                        }
                        if request { rtpfb::TMMBR } else { rtpfb::TMMBN }
                    }
                    TransportMessage::Other { fmt, fci } => {
                        if usize::from(*fmt) > MAX_COUNT {
                            return Err(EncodeError::Range);
                        }
                        if matches!(*fmt, rtpfb::NACK | rtpfb::TMMBR | rtpfb::TMMBN) {
                            return Err(EncodeError::Alias);
                        }
                        words(fci)?;
                        check_size(out.len().saturating_add(fci.len()))?;
                        out.extend_from_slice(fci);
                        *fmt
                    }
                }
            }
            Body::PayloadFeedback(fb) => {
                out.extend_from_slice(&fb.sender_ssrc.to_be_bytes());
                out.extend_from_slice(&fb.media_ssrc.to_be_bytes());
                match &fb.message {
                    PayloadMessage::Pli => psfb::PLI,
                    PayloadMessage::Sli(entries) => {
                        nonempty(entries)?;
                        check_size(out.len() + 4 * entries.len())?;
                        for e in entries {
                            if e.first >= 1 << 13 || e.number >= 1 << 13 || e.picture_id >= 1 << 6 {
                                return Err(EncodeError::Range);
                            }
                            let v = u32::from(e.first) << 19 | u32::from(e.number) << 6 | u32::from(e.picture_id);
                            out.extend_from_slice(&v.to_be_bytes());
                        }
                        psfb::SLI
                    }
                    PayloadMessage::Rpsi(r) => {
                        check_size(out.len().saturating_add(2).saturating_add(r.data.len()))?;
                        if r.payload_type > 127 || !rpsi_padding_ok(r.padding_bits, &r.data) {
                            return Err(EncodeError::Range);
                        }
                        if (2 + r.data.len()) % 4 != 0 {
                            return Err(EncodeError::Alignment);
                        }
                        out.push(r.padding_bits);
                        out.push(r.payload_type);
                        out.extend_from_slice(&r.data);
                        psfb::RPSI
                    }
                    PayloadMessage::Fir(entries) => {
                        unused_media_ssrc(fb.media_ssrc)?;
                        nonempty(entries)?;
                        check_size(out.len() + 8 * entries.len())?;
                        for e in entries {
                            out.extend_from_slice(&e.ssrc.to_be_bytes());
                            out.extend_from_slice(&[e.sequence, 0, 0, 0]);
                        }
                        psfb::FIR
                    }
                    PayloadMessage::Remb(remb) => {
                        unused_media_ssrc(fb.media_ssrc)?;
                        nonempty(&remb.ssrcs)?;
                        if remb.ssrcs.len() > MAX_REMB_SSRCS {
                            return Err(EncodeError::TooMany);
                        }
                        if remb.exponent > 63 || remb.mantissa >= 1 << 18 {
                            return Err(EncodeError::Range);
                        }
                        out.extend_from_slice(REMB_ID);
                        let v = (remb.ssrcs.len() as u32) << 24 | u32::from(remb.exponent) << 18 | remb.mantissa;
                        out.extend_from_slice(&v.to_be_bytes());
                        for s in &remb.ssrcs {
                            out.extend_from_slice(&s.to_be_bytes());
                        }
                        psfb::AFB
                    }
                    PayloadMessage::Afb(data) => {
                        words(data)?;
                        if data.starts_with(REMB_ID) {
                            return Err(EncodeError::Alias);
                        }
                        check_size(out.len().saturating_add(data.len()))?;
                        out.extend_from_slice(data);
                        psfb::AFB
                    }
                    PayloadMessage::Other { fmt, fci } => {
                        if usize::from(*fmt) > MAX_COUNT {
                            return Err(EncodeError::Range);
                        }
                        if matches!(*fmt, psfb::PLI | psfb::SLI | psfb::RPSI | psfb::FIR | psfb::AFB) {
                            return Err(EncodeError::Alias);
                        }
                        words(fci)?;
                        check_size(out.len().saturating_add(fci.len()))?;
                        out.extend_from_slice(fci);
                        *fmt
                    }
                }
            }
            Body::ExtendedReport(report) => {
                out.extend_from_slice(&report.ssrc.to_be_bytes());
                for b in &report.blocks {
                    words(&b.data)?;
                    if !xr_layout_ok(b.block_type, b.data.len()) || (xr_reserved(b.block_type) && b.type_specific != 0)
                    {
                        return Err(EncodeError::Range);
                    }
                    let n = u16::try_from(b.data.len() / 4).map_err(|_| EncodeError::TooLong)?;
                    check_size(out.len() + 4 + b.data.len())?;
                    out.extend_from_slice(&[b.block_type, b.type_specific]);
                    out.extend_from_slice(&n.to_be_bytes());
                    out.extend_from_slice(&b.data);
                }
                0
            }
            Body::Other { packet_type, count, data } => {
                if (packet_type::SR..=packet_type::XR).contains(packet_type) {
                    return Err(EncodeError::Alias);
                }
                if usize::from(*count) > MAX_COUNT {
                    return Err(EncodeError::Range);
                }
                words(data)?;
                check_size(data.len())?;
                out.extend_from_slice(data);
                *count
            }
        };
        Ok((count, out))
    }
}

impl Packet {
    /// Reads the packet at the start of `b`, and returns it and how many
    /// bytes of `b` it took. A packet longer than [`MAX_PACKET`] is an
    /// error, as no datagram holds one.
    pub fn parse(b: &[u8]) -> Result<(Packet, usize), ParseError> {
        if b.len() < HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let version = b[0] >> 6;
        if version != VERSION {
            return Err(ParseError::Version(version));
        }
        let padded = b[0] & 0x20 != 0;
        let count = b[0] & 0x1f;
        let pt = b[1];
        let len = 4 * (usize::from(be16(b, 2)) + 1);
        if len > MAX_PACKET {
            return Err(ParseError::TooLong(len));
        }
        let body = b.get(HEADER_LEN..len).ok_or(ParseError::Truncated)?;
        let padding = if padded {
            match body.last() {
                Some(&n) if n != 0 && n % 4 == 0 && usize::from(n) <= body.len() => n,
                _ => return Err(ParseError::Padding),
            }
        } else {
            0
        };
        let content = &body[..body.len() - usize::from(padding)];
        let body = Body::parse(pt, count, content)?;
        if padding != 0 && body.is_remb() {
            return Err(ParseError::Malformed(pt));
        }
        Ok((Packet { body, padding }, len))
    }

    /// The packet's bytes. A packet [`Packet::parse`] would refuse, or read
    /// back as another packet, is an error.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let (count, content) = self.body.encode()?;
        let pad = usize::from(self.padding);
        if !pad.is_multiple_of(4) || !content.len().is_multiple_of(4) {
            return Err(EncodeError::Alignment);
        }
        if pad > 0 && self.body.is_remb() {
            return Err(EncodeError::Range);
        }
        let total = HEADER_LEN + content.len() + pad;
        if total > MAX_PACKET {
            return Err(EncodeError::TooLong);
        }
        let mut out = Vec::with_capacity(total);
        let flag = if pad > 0 { 0x20 } else { 0 };
        out.push(VERSION << 6 | flag | count);
        out.push(self.body.packet_type());
        out.extend_from_slice(&((total / 4 - 1) as u16).to_be_bytes());
        out.extend_from_slice(&content);
        if pad > 0 {
            out.resize(total - 1, 0);
            out.push(self.padding);
        }
        Ok(out)
    }
}

/// Reads every packet in an RTCP datagram, in order. It checks each
/// packet's header, length, padding and contents, and that the lengths add
/// up to the datagram's, but not the rules for compound packets; see
/// [`parse_compound`].
pub fn parse_packets(b: &[u8]) -> Result<Vec<Packet>, ParseError> {
    if b.is_empty() {
        return Err(ParseError::Empty);
    }
    if b.len() > MAX_DATAGRAM {
        return Err(ParseError::TooLong(b.len()));
    }
    let mut packets = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let (packet, used) = Packet::parse(rest)?;
        packets.push(packet);
        rest = &rest[used..];
    }
    Ok(packets)
}

/// Reads a compound RTCP datagram, as [`parse_packets`] does, and checks
/// the rules of RFC 3550 for it with [`check_compound`].
pub fn parse_compound(b: &[u8]) -> Result<Vec<Packet>, ParseError> {
    let packets = parse_packets(b)?;
    check_compound(&packets).map_err(ParseError::Compound)?;
    Ok(packets)
}

/// Checks the rules of RFC 3550 for a compound packet: there is at least
/// one packet, the first is a sender or receiver report, an SDES chunk
/// carries a CNAME item, only the last packet has padding, and no
/// feedback packet comes before a report or SDES packet (RFC 4585
/// section 3.1). RFC 5506
/// lets two ends agree to send packets without these rules; such a world
/// uses [`parse_packets`] and [`write_packets`] instead.
pub fn check_compound(packets: &[Packet]) -> Result<(), CompoundError> {
    let (last, _) = packets.split_last().ok_or(CompoundError::Empty)?;
    let first = &packets[0];
    if !matches!(first.body, Body::SenderReport(_) | Body::ReceiverReport(_)) {
        return Err(CompoundError::FirstNotReport(first.body.packet_type()));
    }
    if packets.iter().any(|p| p.padding != 0 && !std::ptr::eq(p, last)) {
        return Err(CompoundError::Padding);
    }
    let feedback = packets.iter().position(|p| matches!(p.body, Body::TransportFeedback(_) | Body::PayloadFeedback(_)));
    if let Some(at) = feedback {
        let after = &packets[at..];
        if after
            .iter()
            .any(|p| matches!(p.body, Body::SenderReport(_) | Body::ReceiverReport(_) | Body::SourceDescription(_)))
        {
            return Err(CompoundError::FeedbackOrder);
        }
    }
    let cname = packets.iter().any(|p| match &p.body {
        Body::SourceDescription(chunks) => chunks.iter().any(|c| c.items.iter().any(|i| i.kind == sdes::CNAME)),
        _ => false,
    });
    if !cname {
        return Err(CompoundError::NoCname);
    }
    Ok(())
}

/// The bytes of a datagram holding `packets` back to back. No packets, a
/// packet [`Packet::to_bytes`] refuses, or more than [`MAX_DATAGRAM`]
/// bytes is an error.
pub fn write_packets(packets: &[Packet]) -> Result<Vec<u8>, EncodeError> {
    if packets.is_empty() {
        return Err(EncodeError::Empty);
    }
    let mut out = Vec::new();
    for p in packets {
        out.extend_from_slice(&p.to_bytes()?);
        if out.len() > MAX_DATAGRAM {
            return Err(EncodeError::TooLong);
        }
    }
    Ok(out)
}

/// The bytes of a compound datagram holding `packets`, as
/// [`write_packets`] writes them, once they pass [`check_compound`].
pub fn write_compound(packets: &[Packet]) -> Result<Vec<u8>, EncodeError> {
    check_compound(packets).map_err(EncodeError::Compound)?;
    write_packets(packets)
}

/// What a datagram on a port shared by several protocols is, by the rules
/// of RFC 7983 and RFC 5761.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Demux {
    /// STUN: first byte 0 to 3.
    Stun,
    /// ZRTP: first byte 16 to 19.
    Zrtp,
    /// DTLS: first byte 20 to 63.
    Dtls,
    /// A TURN channel message: first byte 64 to 79.
    TurnChannel,
    /// RTP: first byte 128 to 191, and a second byte outside 192 to 223.
    Rtp,
    /// RTCP: first byte 128 to 191, and a second byte of 192 to 223, which
    /// RFC 5761 keeps for RTCP packet types.
    Rtcp,
    /// Anything else, or a datagram too short to tell.
    Unknown,
}

/// Tells what a datagram is from its first two bytes. It looks at nothing
/// else, so an RTP or RTCP answer still needs its own parser to check it.
pub fn classify(b: &[u8]) -> Demux {
    match b {
        [0..=3, ..] => Demux::Stun,
        [16..=19, ..] => Demux::Zrtp,
        [20..=63, ..] => Demux::Dtls,
        [64..=79, ..] => Demux::TurnChannel,
        [128..=191, 192..=223, ..] => Demux::Rtcp,
        [128..=191, _, ..] => Demux::Rtp,
        _ => Demux::Unknown,
    }
}

/// `datagram` with its 16-bit length in front, as RFC 4571 sends RTP and
/// RTCP over a byte stream. Longer than [`MAX_FRAME`] is an error.
pub fn frame(datagram: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let n = u16::try_from(datagram.len()).map_err(|_| EncodeError::TooLong)?;
    let mut out = Vec::with_capacity(2 + datagram.len());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(datagram);
    Ok(out)
}

/// Splits an RFC 4571 byte stream into datagrams. Feed it the bytes a
/// connection reads, in order, and take datagrams out until it has none.
/// Any 16-bit length is valid, so the stream never breaks.
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
    /// make it hold more than [`MAX_BUFFERED`] bytes. Then take datagrams
    /// out with [`Decoder::next_frame`] and feed it the rest. Once it is
    /// full, `next_frame` always gives a datagram, so a loop of feeding
    /// and taking out always ends.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes.len().min(MAX_BUFFERED.saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The next whole datagram, if one has come. `None` means it needs
    /// more bytes.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        let rest = self.buf.get(self.start..)?;
        if rest.len() < 2 {
            return None;
        }
        let end = 2 + usize::from(be16(rest, 0));
        let datagram = rest.get(2..end)?.to_vec();
        self.start += end;
        Some(datagram)
    }

    /// How many bytes are held, waiting for the rest of a datagram.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }
}

/// Reads `n` report blocks from the start of `b`, which holds them all.
fn report_blocks(b: &[u8], n: usize) -> Vec<ReportBlock> {
    b.chunks_exact(REPORT_BLOCK_LEN)
        .take(n)
        .map(|r| {
            let raw = be32(r, 4) & 0xff_ffff;
            // Sign-extend the 24-bit loss.
            let lost = if raw & 0x80_0000 != 0 { raw as i32 - (1 << 24) } else { raw as i32 };
            ReportBlock {
                ssrc: be32(r, 0),
                fraction_lost: r[4],
                cumulative_lost: lost,
                highest_sequence: be32(r, 8),
                jitter: be32(r, 12),
                last_sr: be32(r, 16),
                delay_since_last_sr: be32(r, 20),
            }
        })
        .collect()
}

/// Writes report blocks and an extension, and returns the count field.
fn write_reports(out: &mut Vec<u8>, reports: &[ReportBlock], extension: &[u8]) -> Result<u8, EncodeError> {
    if reports.len() > MAX_COUNT {
        return Err(EncodeError::TooMany);
    }
    words(extension)?;
    check_size(out.len() + REPORT_BLOCK_LEN * reports.len() + extension.len())?;
    for r in reports {
        if !(MIN_CUMULATIVE_LOST..=MAX_CUMULATIVE_LOST).contains(&r.cumulative_lost) {
            return Err(EncodeError::Range);
        }
        out.extend_from_slice(&r.ssrc.to_be_bytes());
        let lost = (r.cumulative_lost as u32) & 0xff_ffff;
        out.extend_from_slice(&(u32::from(r.fraction_lost) << 24 | lost).to_be_bytes());
        out.extend_from_slice(&r.highest_sequence.to_be_bytes());
        out.extend_from_slice(&r.jitter.to_be_bytes());
        out.extend_from_slice(&r.last_sr.to_be_bytes());
        out.extend_from_slice(&r.delay_since_last_sr.to_be_bytes());
    }
    out.extend_from_slice(extension);
    Ok(reports.len() as u8)
}

/// Reads `n` SDES chunks that fill `c` exactly. Each chunk's items end
/// with a zero byte, and zeros pad it to a whole word.
fn parse_sdes(c: &[u8], n: usize) -> Option<Vec<SdesChunk>> {
    let mut chunks = Vec::new();
    let mut pos = 0usize;
    for _ in 0..n {
        let ssrc = be32(c.get(pos..pos + 4)?, 0);
        pos += 4;
        let mut items = Vec::new();
        loop {
            let kind = *c.get(pos)?;
            if kind == sdes::END {
                let end = (pos + 1).div_ceil(4) * 4;
                if c.get(pos..end)?.iter().any(|&b| b != 0) {
                    return None;
                }
                pos = end;
                break;
            }
            let len = usize::from(*c.get(pos + 1)?);
            let text = c.get(pos + 2..pos + 2 + len)?;
            let item = SdesItem { kind, text: text.to_vec() };
            if !item.layout_ok() {
                return None;
            }
            items.push(item);
            pos += 2 + len;
        }
        chunks.push(SdesChunk { ssrc, items });
    }
    if pos != c.len() {
        return None;
    }
    Some(chunks)
}

/// The four bytes that start a REMB's feedback control information.
const REMB_ID: &[u8] = b"REMB";

/// Reads a REMB from application layer feedback that starts with
/// [`REMB_ID`]: the number of SSRCs, at least one, the bitrate, then
/// exactly that many SSRCs. `None` if it does not fit.
fn parse_remb(fci: &[u8]) -> Option<Remb> {
    let (head, rest) = (fci.get(..8)?, fci.get(8..)?);
    if !head.starts_with(REMB_ID) {
        return None;
    }
    let v = be32(head, 4);
    let n = (v >> 24) as usize;
    if n == 0 || rest.len() != 4 * n {
        return None;
    }
    Some(Remb {
        exponent: (v >> 18 & 0x3f) as u8,
        mantissa: v & 0x3_ffff,
        ssrcs: rest.chunks_exact(4).map(|s| be32(s, 0)).collect(),
    })
}

/// `mantissa * 2^exponent`, at most `u64::MAX`.
fn bitrate(mantissa: u32, exponent: u8) -> u64 {
    let v = u128::from(mantissa) << exponent.min(63);
    u64::try_from(v).unwrap_or(u64::MAX)
}

/// The exponent and a mantissa of at most `bits` bits whose product is
/// `bps`, rounded down.
fn split_bitrate(bps: u64, bits: u32) -> (u8, u32) {
    let mut m = bps;
    let mut e = 0u8;
    while m >> bits != 0 {
        m >>= 1;
        e += 1;
    }
    (e, m as u32)
}

/// Checks the media SSRC of a message that does not use it, which RFC
/// 5104 and the REMB draft set to 0.
fn unused_media_ssrc(ssrc: u32) -> Result<(), EncodeError> {
    if ssrc == 0 { Ok(()) } else { Err(EncodeError::Range) }
}

/// Whether `pb` padding bits fit RFC 4585 section 6.3.3.2: fewer than 32,
/// within `data`, and all zero.
fn rpsi_padding_ok(pb: u8, data: &[u8]) -> bool {
    if pb >= 32 || usize::from(pb).div_ceil(8) > data.len() {
        return false;
    }
    let mut bits = u32::from(pb);
    for &b in data.iter().rev() {
        if bits == 0 {
            break;
        }
        let k = bits.min(8);
        let mask = ((1u16 << k) - 1) as u8;
        if b & mask != 0 {
            return false;
        }
        bits -= k;
    }
    true
}

/// Whether an XR block of type `block_type` may hold `len` bytes after its
/// header (RFC 3611 sections 4.1 to 4.7). Other types may hold any length.
fn xr_layout_ok(block_type: u8, len: usize) -> bool {
    match block_type {
        // The source's SSRC and the first and last sequence numbers.
        xr::LOSS_RLE | xr::DUPLICATE_RLE | xr::PACKET_RECEIPT_TIMES => len >= 8,
        xr::RECEIVER_REFERENCE_TIME => len == 8,
        xr::DLRR => len.is_multiple_of(12),
        xr::STATISTICS_SUMMARY => len == 36,
        xr::VOIP_METRICS => len == 32,
        _ => true,
    }
}

/// Whether the byte after an XR block's type is reserved: written as 0
/// and ignored on reading (RFC 3611 sections 4.4, 4.5 and 4.7).
fn xr_reserved(block_type: u8) -> bool {
    matches!(block_type, xr::RECEIVER_REFERENCE_TIME | xr::DLRR | xr::VOIP_METRICS)
}

/// Pads `out` with zeros to a whole number of 32-bit words.
fn pad_words(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Checks that `b` is whole 32-bit words.
fn words(b: &[u8]) -> Result<(), EncodeError> {
    if b.len().is_multiple_of(4) { Ok(()) } else { Err(EncodeError::Alignment) }
}

/// Checks that a list that may not be empty is not.
fn nonempty<T>(v: &[T]) -> Result<(), EncodeError> {
    if v.is_empty() { Err(EncodeError::Empty) } else { Ok(()) }
}

/// Checks that contents of `n` bytes fit in one packet, before writing
/// them.
fn check_size(n: usize) -> Result<(), EncodeError> {
    if n > MAX_PACKET - HEADER_LEN { Err(EncodeError::TooLong) } else { Ok(()) }
}

/// The big-endian `u16` at `b[i..i + 2]`, or 0 past the end. Callers check
/// lengths first.
fn be16(b: &[u8], i: usize) -> u16 {
    match b.get(i..i + 2) {
        Some(&[x, y]) => u16::from_be_bytes([x, y]),
        _ => 0,
    }
}

/// The big-endian `u32` at `b[i..i + 4]`, or 0 past the end. Callers check
/// lengths first.
fn be32(b: &[u8], i: usize) -> u32 {
    match b.get(i..i + 4) {
        Some(&[w, x, y, z]) => u32::from_be_bytes([w, x, y, z]),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(ssrc: u32) -> Packet {
        Body::ReceiverReport(ReceiverReport { ssrc, reports: vec![], extension: vec![] }).into()
    }

    fn cname(ssrc: u32, name: &[u8]) -> Packet {
        Body::SourceDescription(vec![SdesChunk {
            ssrc,
            items: vec![SdesItem { kind: sdes::CNAME, text: name.to_vec() }],
        }])
        .into()
    }

    fn block(n: u32) -> ReportBlock {
        ReportBlock {
            ssrc: n,
            fraction_lost: 0x40,
            cumulative_lost: -2,
            highest_sequence: 0x0001_0010,
            jitter: 7,
            last_sr: 0x1234_5678,
            delay_since_last_sr: 0x0001_8000,
        }
    }

    /// Writes a packet and checks it reads back the same.
    fn round_trip(p: &Packet) -> Vec<u8> {
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes.len() % 4, 0);
        assert_eq!(Packet::parse(&bytes), Ok((p.clone(), bytes.len())));
        bytes
    }

    // RFC 3550 section 6.4.1: the sender report's layout.
    #[test]
    fn sender_report_layout() {
        let sr = Packet::from(Body::SenderReport(SenderReport {
            ssrc: 0x0102_0304,
            ntp_timestamp: 0xe000_0000_8000_0000,
            rtp_timestamp: 160,
            packet_count: 10,
            octet_count: 1600,
            reports: vec![block(9)],
            extension: vec![],
        }));
        let b = round_trip(&sr);
        assert_eq!(b.len(), 4 + 24 + 24);
        assert_eq!(&b[..4], &[0x81, 200, 0, 12]);
        assert_eq!(&b[4..8], &[1, 2, 3, 4]);
        assert_eq!(&b[8..16], &[0xe0, 0, 0, 0, 0x80, 0, 0, 0]);
        // The block: SSRC 9, fraction 0x40, loss -2 in 24 bits.
        assert_eq!(&b[28..36], &[0, 0, 0, 9, 0x40, 0xff, 0xff, 0xfe]);
    }

    #[test]
    fn receiver_report_with_extension_and_loss_limits() {
        let mut lo = block(1);
        lo.cumulative_lost = MIN_CUMULATIVE_LOST;
        let mut hi = block(2);
        hi.cumulative_lost = MAX_CUMULATIVE_LOST;
        let p = Packet::from(Body::ReceiverReport(ReceiverReport {
            ssrc: 5,
            reports: vec![lo, hi],
            extension: vec![1, 2, 3, 4],
        }));
        let b = round_trip(&p);
        assert_eq!(&b[..4], &[0x82, 201, 0, 14]);
        assert_eq!(&b[13..16], &[0x80, 0, 0]);
        assert_eq!(&b[37..40], &[0x7f, 0xff, 0xff]);
    }

    // RFC 3550 section 6.5: chunks of items, a zero byte, then padding.
    #[test]
    fn sdes_chunks_and_padding() {
        let p = Packet::from(Body::SourceDescription(vec![
            SdesChunk {
                ssrc: 1,
                items: vec![
                    SdesItem { kind: sdes::CNAME, text: b"ab".to_vec() },
                    SdesItem { kind: sdes::TOOL, text: vec![] },
                ],
            },
            SdesChunk { ssrc: 2, items: vec![] },
        ]));
        let b = round_trip(&p);
        assert_eq!(b, [0x82, 202, 0, 5, 0, 0, 0, 1, 1, 2, b'a', b'b', 6, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0]);
        let item = SdesItem { kind: sdes::PRIV, text: b"\x03abcxyz".to_vec() };
        assert_eq!(item.priv_parts(), Some((&b"abc"[..], &b"xyz"[..])));
        assert_eq!(SdesItem { kind: sdes::PRIV, text: vec![9, 1] }.priv_parts(), None);
        assert_eq!(SdesItem { kind: sdes::NOTE, text: vec![0] }.priv_parts(), None);
        // A non-zero byte in the padding, and a chunk left over.
        let mut bad = b.clone();
        bad[15] = 1;
        assert_eq!(Packet::parse(&bad), Err(ParseError::Malformed(202)));
        let mut bad = b.clone();
        bad[0] = 0x81;
        assert_eq!(Packet::parse(&bad), Err(ParseError::Malformed(202)));
    }

    // RFC 3550 section 6.6.
    #[test]
    fn bye_with_and_without_reason() {
        let p = Packet::from(Body::Bye(Bye { sources: vec![7], reason: Some(b"done".to_vec()) }));
        let b = round_trip(&p);
        assert_eq!(b, [0x81, 203, 0, 3, 0, 0, 0, 7, 4, b'd', b'o', b'n', b'e', 0, 0, 0]);
        let none = round_trip(&Packet::from(Body::Bye(Bye { sources: vec![1, 2], reason: None })));
        assert_eq!(none.len(), 12);
        let empty = round_trip(&Packet::from(Body::Bye(Bye { sources: vec![], reason: Some(vec![]) })));
        assert_eq!(empty, [0x80, 203, 0, 1, 0, 0, 0, 0]);
        // A reason longer than the packet, and junk after it.
        assert_eq!(Packet::parse(&[0x80, 203, 0, 1, 9, 0, 0, 0]), Err(ParseError::Malformed(203)));
        assert_eq!(Packet::parse(&[0x80, 203, 0, 1, 0, 0, 1, 0]), Err(ParseError::Malformed(203)));
        assert_eq!(Packet::parse(&[0x80, 203, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]), Err(ParseError::Malformed(203)));
        // A count past the contents.
        assert_eq!(Packet::parse(&[0x82, 203, 0, 1, 0, 0, 0, 7]), Err(ParseError::Malformed(203)));
    }

    #[test]
    fn app() {
        let p = Packet::from(Body::App(App { subtype: 3, ssrc: 1, name: *b"TEST", data: vec![9; 8] }));
        let b = round_trip(&p);
        assert_eq!(&b[..12], &[0x83, 204, 0, 4, 0, 0, 0, 1, b'T', b'E', b'S', b'T']);
        assert_eq!(Packet::parse(&[0x80, 204, 0, 1, 0, 0, 0, 1]), Err(ParseError::Malformed(204)));
    }

    // RFC 4585 section 6.2.1.
    #[test]
    fn generic_nack() {
        assert_eq!(Nack { pid: 65535, blp: 0x8001 }.lost(), vec![65535, 0, 15]);
        let p = Packet::from(Body::TransportFeedback(TransportFeedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: TransportMessage::Nack(vec![Nack { pid: 1, blp: 0 }, Nack { pid: 40, blp: 0xffff }]),
        }));
        let b = round_trip(&p);
        assert_eq!(&b[..4], &[0x81, 205, 0, 4]);
        // A NACK with no entries.
        assert_eq!(Packet::parse(&[0x81, 205, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]), Err(ParseError::Malformed(205)));
    }

    // RFC 5104 sections 4.2.1 and 4.2.2.
    #[test]
    fn tmmbr_and_tmmbn() {
        let item = Tmmb::with_bitrate(9, 1_000_000, 40);
        assert_eq!(item.bitrate(), 1_000_000 >> item.exponent << item.exponent);
        assert!(item.mantissa < 1 << 17);
        let p = Packet::from(Body::TransportFeedback(TransportFeedback {
            sender_ssrc: 1,
            media_ssrc: 0,
            message: TransportMessage::Tmmbr(vec![item]),
        }));
        let b = round_trip(&p);
        assert_eq!(&b[..4], &[0x83, 205, 0, 4]);
        let v = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
        assert_eq!(v >> 26, u32::from(item.exponent));
        assert_eq!(v & 0x1ff, 40);
        let n = Packet::from(Body::TransportFeedback(TransportFeedback {
            sender_ssrc: 1,
            media_ssrc: 0,
            message: TransportMessage::Tmmbn(vec![]),
        }));
        assert_eq!(round_trip(&n), [0x84, 205, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]);
        // A TMMBR with no entries, and one with half an entry.
        assert_eq!(Packet::parse(&[0x83, 205, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]), Err(ParseError::Malformed(205)));
        assert_eq!(
            Packet::parse(&[0x84, 205, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ParseError::Malformed(205))
        );
        assert_eq!(Tmmb { ssrc: 0, exponent: 63, mantissa: 0x1_ffff, overhead: 0 }.bitrate(), u64::MAX);
    }

    // RFC 4585 sections 6.3.1 to 6.3.3, RFC 5104 section 4.3.1.
    #[test]
    fn pli_sli_rpsi_fir() {
        let fb =
            |message| Packet::from(Body::PayloadFeedback(PayloadFeedback { sender_ssrc: 1, media_ssrc: 2, message }));
        assert_eq!(round_trip(&fb(PayloadMessage::Pli)), [0x81, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]);
        let b = round_trip(&fb(PayloadMessage::Sli(vec![Sli { first: 8191, number: 1, picture_id: 63 }])));
        assert_eq!(&b[12..], &[0xff, 0xf8, 0x00, 0x7f]);
        let b = round_trip(&fb(PayloadMessage::Rpsi(Rpsi { payload_type: 96, padding_bits: 4, data: vec![0xa0, 0] })));
        assert_eq!(&b[..4], &[0x83, 206, 0, 3]);
        assert_eq!(&b[12..], &[4, 96, 0xa0, 0]);
        let fir = Packet::from(Body::PayloadFeedback(PayloadFeedback {
            sender_ssrc: 1,
            media_ssrc: 0,
            message: PayloadMessage::Fir(vec![Fir { ssrc: 5, sequence: 9 }]),
        }));
        let b = round_trip(&fir);
        assert_eq!(&b[..4], &[0x84, 206, 0, 4]);
        assert_eq!(&b[12..], &[0, 0, 0, 5, 9, 0, 0, 0]);
        // A FIR's reserved bytes are ignored.
        let mut r = b.clone();
        r[17] = 0xff;
        assert_eq!(Packet::parse(&r).unwrap().0, fir);
        // PLI with FCI, empty SLI and FIR, RPSI with too many padding bits
        // or no room for its two leading bytes.
        let head = [0, 0, 0, 1, 0, 0, 0, 2];
        let with = |first: u8, len: u8, fci: &[u8]| [&[first, 206, 0, len][..], &head, fci].concat();
        for bad in [
            with(0x81, 3, &[0, 0, 0, 0]),
            with(0x82, 2, &[]),
            with(0x84, 2, &[]),
            with(0x84, 3, &[0, 0, 0, 0]),
            with(0x83, 3, &[17, 96, 0, 0]),
            with(0x83, 2, &[]),
        ] {
            assert_eq!(Packet::parse(&bad), Err(ParseError::Malformed(206)), "{bad:?}");
        }
    }

    // draft-alvestrand-rmcat-remb section 2.2.
    #[test]
    fn remb() {
        let bytes = [
            0x8f, 0xce, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 0, b'R', b'E', b'M', b'B', 0x01, 0x0a, 0x00, 0x10, 0, 0, 0, 9,
        ];
        let (p, used) = Packet::parse(&bytes).unwrap();
        assert_eq!(used, 24);
        let Body::PayloadFeedback(PayloadFeedback { message: PayloadMessage::Remb(r), .. }) = &p.body else {
            panic!("{p:?}")
        };
        // Exponent 2, mantissa 0x20010.
        assert_eq!((r.exponent, r.mantissa, r.ssrcs.clone()), (2, 0x2_0010, vec![9]));
        assert_eq!(r.bitrate(), 0x2_0010 * 4);
        assert_eq!(p.to_bytes().unwrap(), bytes);
        let w = Remb::with_bitrate(2_500_000, vec![]);
        assert!(w.mantissa < 1 << 18 && w.bitrate() <= 2_500_000 && w.bitrate() > 2_490_000);
        // A count that does not match is a bad REMB.
        let mut afb = bytes;
        afb[16] = 2;
        assert_eq!(Packet::parse(&afb), Err(ParseError::Malformed(206)));
    }

    // RFC 3611 sections 4.4 and 4.5.
    #[test]
    fn extended_reports() {
        let items = [DlrrItem { ssrc: 1, last_rr: 2, delay_since_last_rr: 3 }];
        let p = Packet::from(Body::ExtendedReport(ExtendedReport {
            ssrc: 7,
            blocks: vec![
                XrBlock::receiver_reference_time(0x0102_0304_0506_0708),
                XrBlock::dlrr(&items),
                XrBlock { block_type: 99, type_specific: 5, data: vec![] },
            ],
        }));
        let b = round_trip(&p);
        assert_eq!(&b[..4], &[0x80, 207, 0, 9]);
        assert_eq!(&b[8..12], &[4, 0, 0, 2]);
        assert_eq!(&b[20..24], &[5, 0, 0, 3]);
        assert_eq!(&b[36..40], &[99, 5, 0, 0]);
        let Body::ExtendedReport(x) = &p.body else { panic!() };
        assert_eq!(x.blocks[0].ntp_timestamp(), Some(0x0102_0304_0506_0708));
        assert_eq!(x.blocks[1].dlrr_items(), Some(items.to_vec()));
        assert_eq!(x.blocks[1].ntp_timestamp(), None);
        assert_eq!(x.blocks[0].dlrr_items(), None);
        // A block whose length runs past the packet, and a cut-off header.
        assert_eq!(Packet::parse(&[0x80, 207, 0, 2, 0, 0, 0, 7, 4, 0, 0, 2]), Err(ParseError::Malformed(207)));
        assert_eq!(Packet::parse(&[0x80, 207, 0, 0]), Err(ParseError::Malformed(207)));
    }

    #[test]
    fn other_types_and_aliases() {
        let p = Packet { body: Body::Other { packet_type: 210, count: 4, data: vec![1, 2, 3, 4] }, padding: 4 };
        let b = round_trip(&p);
        assert_eq!(b, [0xa4, 210, 0, 2, 1, 2, 3, 4, 0, 0, 0, 4]);
        let other = |packet_type| Packet::from(Body::Other { packet_type, count: 0, data: vec![] });
        for t in 200..=207 {
            assert_eq!(other(t).to_bytes(), Err(EncodeError::Alias));
        }
        let fb = |fmt| {
            Packet::from(Body::TransportFeedback(TransportFeedback {
                sender_ssrc: 0,
                media_ssrc: 0,
                message: TransportMessage::Other { fmt, fci: vec![] },
            }))
        };
        assert_eq!(fb(1).to_bytes(), Err(EncodeError::Alias));
        assert_eq!(fb(32).to_bytes(), Err(EncodeError::Range));
        round_trip(&fb(15));
        let ps = |fmt| {
            Packet::from(Body::PayloadFeedback(PayloadFeedback {
                sender_ssrc: 0,
                media_ssrc: 0,
                message: PayloadMessage::Other { fmt, fci: vec![0; 4] },
            }))
        };
        assert_eq!(ps(15).to_bytes(), Err(EncodeError::Alias));
        round_trip(&ps(5));
        let afb = Packet::from(Body::PayloadFeedback(PayloadFeedback {
            sender_ssrc: 0,
            media_ssrc: 0,
            message: PayloadMessage::Afb(b"REMB\0\0\0\0".to_vec()),
        }));
        assert_eq!(afb.to_bytes(), Err(EncodeError::Alias));
    }

    // RFC 3550 section 6.4.1: padding, with the count in the last byte.
    #[test]
    fn padding() {
        let p = Packet { padding: 4, ..rr(1) };
        let b = round_trip(&p);
        assert_eq!(b, [0xa0, 201, 0, 2, 0, 0, 0, 1, 0, 0, 0, 4]);
        assert_eq!(Packet { padding: 3, ..rr(1) }.to_bytes(), Err(EncodeError::Alignment));
        // A count of 0, and one past the packet.
        assert_eq!(Packet::parse(&[0xa0, 201, 0, 1, 0, 0, 0, 0]), Err(ParseError::Padding));
        assert_eq!(Packet::parse(&[0xa0, 201, 0, 1, 0, 0, 0, 5]), Err(ParseError::Padding));
        assert_eq!(Packet::parse(&[0xa0, 210, 0, 0]), Err(ParseError::Padding));
        // A count that is not a multiple of four.
        assert_eq!(Packet::parse(&[0xa0, 201, 0, 1, 0, 0, 0, 3]), Err(ParseError::Padding));
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse_packets(&[]), Err(ParseError::Empty));
        assert_eq!(parse_packets(&vec![0x80; MAX_DATAGRAM + 1]), Err(ParseError::TooLong(MAX_DATAGRAM + 1)));
        assert_eq!(parse_packets(&[0x80, 201, 0]), Err(ParseError::Truncated));
        assert_eq!(parse_packets(&[0x80, 201, 0, 1, 0, 0]), Err(ParseError::Truncated));
        assert_eq!(parse_packets(&[0x40, 201, 0, 0]), Err(ParseError::Version(1)));
        assert_eq!(parse_packets(&[0x80, 200, 0, 1, 0, 0, 0, 0]), Err(ParseError::Malformed(200)));
        assert_eq!(parse_packets(&[0x81, 201, 0, 1, 0, 0, 0, 0]), Err(ParseError::Malformed(201)));
        assert_eq!(parse_packets(&[0x80, 201, 0, 0]), Err(ParseError::Malformed(201)));
        assert_eq!(parse_packets(&[0x81, 202, 0, 0]), Err(ParseError::Malformed(202)));
        assert_eq!(parse_packets(&[0x80, 205, 0, 1, 0, 0, 0, 0]), Err(ParseError::Malformed(205)));
        assert_eq!(parse_packets(&[0x81, 206, 0, 1, 0, 0, 0, 0]), Err(ParseError::Malformed(206)));
        // A typed packet whose contents are not whole words.
        assert_eq!(parse_packets(&[0x80, 204, 0, 1, 0, 0, 0, 1]), Err(ParseError::Malformed(204)));
        for e in [ParseError::Empty, ParseError::Compound(CompoundError::NoCname), ParseError::Version(0)] {
            assert!(!e.to_string().is_empty());
        }
    }

    // RFC 3550 sections 6.1 and A.2.
    #[test]
    fn compound_rules() {
        let good = vec![rr(1), cname(1, b"x")];
        let bytes = write_compound(&good).unwrap();
        assert_eq!(parse_compound(&bytes), Ok(good.clone()));
        assert_eq!(check_compound(&[]), Err(CompoundError::Empty));
        assert_eq!(check_compound(&[cname(1, b"x"), rr(1)]), Err(CompoundError::FirstNotReport(202)));
        assert_eq!(check_compound(&[rr(1)]), Err(CompoundError::NoCname));
        let no_cname = Packet::from(Body::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![SdesItem { kind: sdes::NAME, text: vec![] }],
        }]));
        assert_eq!(check_compound(&[rr(1), no_cname]), Err(CompoundError::NoCname));
        let padded = vec![Packet { padding: 4, ..rr(1) }, cname(1, b"x")];
        assert_eq!(check_compound(&padded), Err(CompoundError::Padding));
        assert_eq!(write_compound(&padded), Err(EncodeError::Compound(CompoundError::Padding)));
        let bytes = write_packets(&padded).unwrap();
        assert_eq!(parse_packets(&bytes), Ok(padded));
        assert_eq!(parse_compound(&bytes), Err(ParseError::Compound(CompoundError::Padding)));
        let last = vec![rr(1), Packet { padding: 8, ..cname(1, b"x") }];
        assert_eq!(parse_compound(&write_compound(&last).unwrap()), Ok(last));
        assert_eq!(write_compound(&[]), Err(EncodeError::Compound(CompoundError::Empty)));
        assert_eq!(write_packets(&[]), Err(EncodeError::Empty));
    }

    // RFC 4585 section 6.3.3.2: the bit before the payload type is set to
    // 0 on sending and ignored on reading.
    #[test]
    fn rpsi_reserved_bit_is_ignored() {
        let bytes = [0x83, 206, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0x80 | 96, 0xa0, 0];
        let (p, _) = Packet::parse(&bytes).unwrap();
        let want = Rpsi { payload_type: 96, padding_bits: 0, data: vec![0xa0, 0] };
        assert_eq!(
            p.body,
            Body::PayloadFeedback(PayloadFeedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: PayloadMessage::Rpsi(want),
            })
        );
        assert_eq!(p.to_bytes().unwrap()[13], 96);
    }

    // RFC 4585 section 3.1: feedback comes after the RR or SR and SDES.
    #[test]
    fn feedback_after_reports_and_sdes() {
        let pli = Packet::from(Body::PayloadFeedback(PayloadFeedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: PayloadMessage::Pli,
        }));
        let nack = Packet::from(Body::TransportFeedback(TransportFeedback {
            sender_ssrc: 1,
            media_ssrc: 2,
            message: TransportMessage::Nack(vec![Nack { pid: 1, blp: 0 }]),
        }));
        assert_eq!(check_compound(&[rr(1), cname(1, b"x"), pli.clone(), nack.clone()]), Ok(()));
        assert_eq!(check_compound(&[rr(1), pli.clone(), cname(1, b"x")]), Err(CompoundError::FeedbackOrder));
        assert_eq!(check_compound(&[rr(1), nack.clone(), rr(2), cname(1, b"x")]), Err(CompoundError::FeedbackOrder));
        let bytes = write_packets(&[rr(1), pli.clone(), cname(1, b"x")]).unwrap();
        assert_eq!(parse_compound(&bytes), Err(ParseError::Compound(CompoundError::FeedbackOrder)));
        assert_eq!(
            write_compound(&[rr(1), nack, cname(1, b"x")]),
            Err(EncodeError::Compound(CompoundError::FeedbackOrder))
        );
    }

    // A length field can give a packet longer than a datagram holds. Read
    // alone, from a longer buffer, it must not read as a packet the
    // writer refuses.
    #[test]
    fn packet_longer_than_max_packet() {
        let mut b = vec![0u8; 4 * 65536];
        b[..4].copy_from_slice(&[0x80, 210, 0xff, 0xff]);
        assert_eq!(Packet::parse(&b), Err(ParseError::TooLong(4 * 65536)));
        let mut b = vec![0u8; MAX_PACKET + 4];
        let words = (MAX_PACKET / 4) as u16;
        b[..4].copy_from_slice(&[0x80, 210, (words >> 8) as u8, words as u8]);
        assert_eq!(Packet::parse(&b), Err(ParseError::TooLong(MAX_PACKET + 4)));
        // The longest packet reads and writes back.
        let words = (MAX_PACKET / 4 - 1) as u16;
        b[..4].copy_from_slice(&[0x80, 210, (words >> 8) as u8, words as u8]);
        let (p, used) = Packet::parse(&b).unwrap();
        assert_eq!(used, MAX_PACKET);
        assert_eq!(p.to_bytes().unwrap(), &b[..MAX_PACKET]);
    }

    #[test]
    fn nack_from_lost() {
        assert_eq!(Nack::from_lost(&[]), vec![]);
        let lost = [100, 102, 116, 117, 65535, 0, 15, 16];
        let nacks = Nack::from_lost(&lost);
        assert_eq!(
            nacks,
            vec![
                Nack { pid: 100, blp: 0b10 | 1 << 15 },
                Nack { pid: 117, blp: 0 },
                Nack { pid: 65535, blp: 1 | 1 << 15 },
                Nack { pid: 16, blp: 0 },
            ]
        );
        let back: Vec<u16> = nacks.iter().flat_map(|n| n.lost()).collect();
        assert_eq!(back, lost);
        // Repeats and numbers that go back start a new entry, and every
        // number listed is still asked for.
        let nacks = Nack::from_lost(&[5, 5, 3]);
        assert_eq!(nacks, vec![Nack { pid: 5, blp: 0 }, Nack { pid: 5, blp: 0 }, Nack { pid: 3, blp: 0 }]);
        let mut r = Lcg(0x6e61_636b);
        for _ in 0..2000 {
            let lost: Vec<u16> = (0..r.below(40)).map(|_| r.next() as u16 % 64).collect();
            let nacks = Nack::from_lost(&lost);
            assert!(nacks.len() <= lost.len());
            let mut want = lost.clone();
            let mut got: Vec<u16> = nacks.iter().flat_map(|n| n.lost()).collect();
            want.sort_unstable();
            want.dedup();
            got.sort_unstable();
            got.dedup();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn encode_errors() {
        let mut too_lost = block(1);
        too_lost.cumulative_lost = MAX_CUMULATIVE_LOST + 1;
        let rrb = |reports: Vec<ReportBlock>, extension: Vec<u8>| {
            Packet::from(Body::ReceiverReport(ReceiverReport { ssrc: 1, reports, extension }))
        };
        assert_eq!(rrb(vec![block(1); 32], vec![]).to_bytes(), Err(EncodeError::TooMany));
        assert_eq!(rrb(vec![too_lost], vec![]).to_bytes(), Err(EncodeError::Range));
        assert_eq!(rrb(vec![], vec![0; 3]).to_bytes(), Err(EncodeError::Alignment));
        assert_eq!(rrb(vec![], vec![0; MAX_PACKET]).to_bytes(), Err(EncodeError::TooLong));
        let sd = |chunks| Packet::from(Body::SourceDescription(chunks));
        assert_eq!(sd(vec![SdesChunk { ssrc: 0, items: vec![] }; 32]).to_bytes(), Err(EncodeError::TooMany));
        let item = |kind, n| vec![SdesChunk { ssrc: 0, items: vec![SdesItem { kind, text: vec![b'a'; n] }] }];
        assert_eq!(sd(item(0, 1)).to_bytes(), Err(EncodeError::Range));
        assert_eq!(sd(item(1, 256)).to_bytes(), Err(EncodeError::TooLong));
        round_trip(&sd(item(1, 255)));
        let bye = |sources: Vec<u32>, reason| Packet::from(Body::Bye(Bye { sources, reason }));
        assert_eq!(bye(vec![0; 32], None).to_bytes(), Err(EncodeError::TooMany));
        assert_eq!(bye(vec![], Some(vec![0; 256])).to_bytes(), Err(EncodeError::TooLong));
        let app = |subtype, n| Packet::from(Body::App(App { subtype, ssrc: 0, name: *b"abcd", data: vec![0; n] }));
        assert_eq!(app(32, 0).to_bytes(), Err(EncodeError::Range));
        assert_eq!(app(0, 2).to_bytes(), Err(EncodeError::Alignment));
        let tf = |message| {
            Packet::from(Body::TransportFeedback(TransportFeedback { sender_ssrc: 0, media_ssrc: 0, message }))
        };
        assert_eq!(tf(TransportMessage::Nack(vec![])).to_bytes(), Err(EncodeError::Empty));
        assert_eq!(tf(TransportMessage::Tmmbr(vec![])).to_bytes(), Err(EncodeError::Empty));
        let t = Tmmb { ssrc: 0, exponent: 64, mantissa: 0, overhead: 0 };
        assert_eq!(tf(TransportMessage::Tmmbn(vec![t])).to_bytes(), Err(EncodeError::Range));
        let t = Tmmb { exponent: 0, mantissa: 1 << 17, ..t };
        assert_eq!(tf(TransportMessage::Tmmbn(vec![t])).to_bytes(), Err(EncodeError::Range));
        let t = Tmmb { mantissa: 0, overhead: 512, ..t };
        assert_eq!(tf(TransportMessage::Tmmbn(vec![t])).to_bytes(), Err(EncodeError::Range));
        assert_eq!(tf(TransportMessage::Other { fmt: 2, fci: vec![0] }).to_bytes(), Err(EncodeError::Alignment));
        let nacks = vec![Nack { pid: 0, blp: 0 }; MAX_PACKET / 4];
        assert_eq!(tf(TransportMessage::Nack(nacks)).to_bytes(), Err(EncodeError::TooLong));
        let pf =
            |message| Packet::from(Body::PayloadFeedback(PayloadFeedback { sender_ssrc: 0, media_ssrc: 0, message }));
        assert_eq!(pf(PayloadMessage::Sli(vec![])).to_bytes(), Err(EncodeError::Empty));
        assert_eq!(pf(PayloadMessage::Fir(vec![])).to_bytes(), Err(EncodeError::Empty));
        for s in [
            Sli { first: 8192, number: 0, picture_id: 0 },
            Sli { first: 0, number: 8192, picture_id: 0 },
            Sli { first: 0, number: 0, picture_id: 64 },
        ] {
            assert_eq!(pf(PayloadMessage::Sli(vec![s])).to_bytes(), Err(EncodeError::Range));
        }
        let rp =
            |payload_type, padding_bits, n| PayloadMessage::Rpsi(Rpsi { payload_type, padding_bits, data: vec![0; n] });
        assert_eq!(pf(rp(128, 0, 2)).to_bytes(), Err(EncodeError::Range));
        assert_eq!(pf(rp(0, 17, 2)).to_bytes(), Err(EncodeError::Range));
        assert_eq!(pf(rp(0, 0, 3)).to_bytes(), Err(EncodeError::Alignment));
        let remb = |exponent, mantissa, n| PayloadMessage::Remb(Remb { exponent, mantissa, ssrcs: vec![0; n] });
        assert_eq!(pf(remb(64, 0, 1)).to_bytes(), Err(EncodeError::Range));
        assert_eq!(pf(remb(0, 1 << 18, 1)).to_bytes(), Err(EncodeError::Range));
        assert_eq!(pf(remb(0, 0, 256)).to_bytes(), Err(EncodeError::TooMany));
        assert_eq!(pf(PayloadMessage::Afb(vec![0; 5])).to_bytes(), Err(EncodeError::Alignment));
        assert_eq!(pf(PayloadMessage::Other { fmt: 32, fci: vec![] }).to_bytes(), Err(EncodeError::Range));
        let x = |data| {
            Packet::from(Body::ExtendedReport(ExtendedReport {
                ssrc: 0,
                blocks: vec![XrBlock { block_type: 1, type_specific: 0, data }],
            }))
        };
        assert_eq!(x(vec![0; 2]).to_bytes(), Err(EncodeError::Alignment));
        assert_eq!(x(vec![0; 4 * 65536]).to_bytes(), Err(EncodeError::TooLong));
        assert_eq!(x(vec![0; MAX_PACKET]).to_bytes(), Err(EncodeError::TooLong));
        let o = |count| Packet::from(Body::Other { packet_type: 0, count, data: vec![] });
        assert_eq!(o(32).to_bytes(), Err(EncodeError::Range));
        // A datagram past the limit.
        let big = rrb(vec![], vec![0; 32000]);
        assert_eq!(write_packets(&[big.clone(), big.clone(), big]), Err(EncodeError::TooLong));
        assert_eq!(frame(&vec![0; MAX_FRAME + 1]), Err(EncodeError::TooLong));
        for e in [EncodeError::Alias, EncodeError::Compound(CompoundError::Padding)] {
            assert!(!e.to_string().is_empty());
        }
    }

    // RFC 7983 section 7 and RFC 5761 section 4.
    #[test]
    fn classify_by_first_bytes() {
        assert_eq!(classify(&[0, 1]), Demux::Stun);
        assert_eq!(classify(&[17]), Demux::Zrtp);
        assert_eq!(classify(&[22, 254, 253]), Demux::Dtls);
        assert_eq!(classify(&[0x40, 0]), Demux::TurnChannel);
        assert_eq!(classify(&[0x80, 0x60]), Demux::Rtp);
        assert_eq!(classify(&[0x80, 0xe0]), Demux::Rtp);
        assert_eq!(classify(&[0x80, 200]), Demux::Rtcp);
        assert_eq!(classify(&[0xbf, 223]), Demux::Rtcp);
        assert_eq!(classify(&[0x80]), Demux::Unknown);
        assert_eq!(classify(&[]), Demux::Unknown);
        assert_eq!(classify(&[0xc0, 200]), Demux::Unknown);
        assert_eq!(classify(&[8, 200]), Demux::Unknown);
    }

    fn split(data: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        for c in data.chunks(chunk.max(1)) {
            let mut rest = c;
            while !rest.is_empty() {
                let took = d.feed(rest);
                assert!(d.buffered() <= MAX_BUFFERED);
                rest = &rest[took..];
                let mut progress = took > 0;
                while let Some(f) = d.next_frame() {
                    out.push(f);
                    progress = true;
                }
                assert!(progress);
            }
        }
        out
    }

    // RFC 4571 section 2.
    #[test]
    fn decoder_splits_a_stream() {
        let a = write_compound(&[rr(1), cname(1, b"a")]).unwrap();
        let b = vec![0x80, 201, 0, 1, 0, 0, 0, 2];
        let stream = [frame(&a).unwrap(), frame(&[]).unwrap(), frame(&b).unwrap(), vec![0, 9, 1]].concat();
        let want = vec![a, vec![], b];
        for chunk in [1, 2, 3, 7, 1000] {
            assert_eq!(split(&stream, chunk), want);
        }
        // The longest frame fills the decoder and still comes out.
        let big = vec![7u8; MAX_FRAME];
        let s = [frame(&big).unwrap(), frame(&[1]).unwrap()].concat();
        assert_eq!(split(&s, 65536), vec![big, vec![1]]);
    }

    #[test]
    fn every_truncated_prefix() {
        let packets = vec![
            Packet::from(Body::SenderReport(SenderReport {
                ssrc: 1,
                ntp_timestamp: 2,
                rtp_timestamp: 3,
                packet_count: 4,
                octet_count: 5,
                reports: vec![block(6)],
                extension: vec![],
            })),
            cname(1, b"agent@example"),
            Packet::from(Body::PayloadFeedback(PayloadFeedback {
                sender_ssrc: 1,
                media_ssrc: 0,
                message: PayloadMessage::Remb(Remb::with_bitrate(500_000, vec![6])),
            })),
            Packet::from(Body::ExtendedReport(ExtendedReport {
                ssrc: 1,
                blocks: vec![XrBlock::receiver_reference_time(9)],
            })),
            Packet { padding: 4, ..Packet::from(Body::Bye(Bye { sources: vec![1], reason: Some(b"bye".to_vec()) })) },
        ];
        let bytes = write_compound(&packets).unwrap();
        assert_eq!(parse_compound(&bytes), Ok(packets.clone()));
        let mut ends = Vec::new();
        let mut at = 0;
        for p in &packets {
            at += p.to_bytes().unwrap().len();
            ends.push(at);
        }
        for i in 0..bytes.len() {
            let r = parse_packets(&bytes[..i]);
            match ends.iter().position(|&e| e == i) {
                Some(k) => assert_eq!(r, Ok(packets[..=k].to_vec())),
                None if i == 0 => assert_eq!(r, Err(ParseError::Empty)),
                None => assert_eq!(r, Err(ParseError::Truncated), "{i}"),
            }
            // A single packet cut short never reads.
            if i < ends[0] {
                assert!(Packet::parse(&bytes[..i]).is_err());
            }
        }
    }

    fn psfb(media_ssrc: u32, message: PayloadMessage) -> Packet {
        Packet::from(Body::PayloadFeedback(PayloadFeedback { sender_ssrc: 1, media_ssrc, message }))
    }

    // Writers check the size of caller data before they copy it.
    #[test]
    fn writers_check_size_before_copying() {
        let big = vec![0u8; MAX_PACKET];
        let bodies = [
            Body::App(App { subtype: 0, ssrc: 0, name: *b"TEST", data: big.clone() }),
            Body::TransportFeedback(TransportFeedback {
                sender_ssrc: 0,
                media_ssrc: 0,
                message: TransportMessage::Other { fmt: 9, fci: big.clone() },
            }),
            Body::PayloadFeedback(PayloadFeedback {
                sender_ssrc: 0,
                media_ssrc: 0,
                message: PayloadMessage::Other { fmt: 9, fci: big.clone() },
            }),
            Body::PayloadFeedback(PayloadFeedback {
                sender_ssrc: 0,
                media_ssrc: 0,
                message: PayloadMessage::Afb(big.clone()),
            }),
            Body::PayloadFeedback(PayloadFeedback {
                sender_ssrc: 0,
                media_ssrc: 0,
                message: PayloadMessage::Rpsi(Rpsi {
                    payload_type: 96,
                    padding_bits: 0,
                    data: vec![0; MAX_PACKET + 2],
                }),
            }),
            Body::Other { packet_type: 210, count: 0, data: big },
        ];
        for b in bodies {
            assert_eq!(b.encode(), Err(EncodeError::TooLong), "{}", b.packet_type());
        }
    }

    // RFC 5104 sections 4.2.1.2, 4.2.2.2 and 4.3.1.2, and
    // draft-alvestrand-rmcat-remb section 2.2: the media SSRC is 0.
    #[test]
    fn media_ssrc_zero_where_unused() {
        let tmmb = Tmmb { ssrc: 9, exponent: 1, mantissa: 2, overhead: 3 };
        let tf = |media_ssrc, message| {
            Packet::from(Body::TransportFeedback(TransportFeedback { sender_ssrc: 1, media_ssrc, message }))
        };
        let remb = || PayloadMessage::Remb(Remb { exponent: 1, mantissa: 2, ssrcs: vec![9] });
        let fir = || PayloadMessage::Fir(vec![Fir { ssrc: 9, sequence: 1 }]);
        for p in [
            tf(2, TransportMessage::Tmmbr(vec![tmmb])),
            tf(2, TransportMessage::Tmmbn(vec![tmmb])),
            psfb(2, remb()),
            psfb(2, fir()),
        ] {
            assert_eq!(p.to_bytes(), Err(EncodeError::Range), "{p:?}");
        }
        // Read, a nonzero media SSRC is ignored.
        for p in [tf(0, TransportMessage::Tmmbr(vec![tmmb])), psfb(0, remb()), psfb(0, fir())] {
            let mut b = round_trip(&p);
            b[11] = 2;
            assert_eq!(Packet::parse(&b), Ok((p, b.len())));
        }
        // PLI keeps its media SSRC.
        round_trip(&psfb(2, PayloadMessage::Pli));
    }

    // RFC 3611 sections 4.1 to 4.7: the lengths of known blocks, and
    // reserved bytes set to 0 and ignored.
    #[test]
    fn known_xr_block_layouts() {
        let xr = |block_type, type_specific, n| {
            Packet::from(Body::ExtendedReport(ExtendedReport {
                ssrc: 1,
                blocks: vec![XrBlock { block_type, type_specific, data: vec![0; n] }],
            }))
        };
        for (t, good, bad) in [
            (xr::LOSS_RLE, &[8, 12][..], &[0, 4][..]),
            (xr::DUPLICATE_RLE, &[8], &[4]),
            (xr::PACKET_RECEIPT_TIMES, &[8, 16], &[0]),
            (xr::RECEIVER_REFERENCE_TIME, &[8], &[0, 4, 12]),
            (xr::DLRR, &[0, 12, 24], &[4, 8, 16]),
            (xr::STATISTICS_SUMMARY, &[36], &[32, 40]),
            (xr::VOIP_METRICS, &[32], &[28, 36]),
        ] {
            for &n in good {
                round_trip(&xr(t, 0, n));
            }
            for &n in bad {
                let p = xr(t, 0, n);
                assert_eq!(p.to_bytes(), Err(EncodeError::Range), "{t} {n}");
                let words = (2 + n / 4) as u8;
                let b = [&[0x80, 207, 0, words, 0, 0, 0, 1, t, 0, 0, (n / 4) as u8][..], &vec![0; n]].concat();
                assert_eq!(Packet::parse(&b), Err(ParseError::Malformed(207)), "{t} {n}");
            }
        }
        for t in [xr::RECEIVER_REFERENCE_TIME, xr::DLRR, xr::VOIP_METRICS] {
            let n = if t == xr::VOIP_METRICS {
                32
            } else {
                12 * usize::from(t == xr::DLRR) + 8 * usize::from(t != xr::DLRR)
            };
            assert_eq!(xr(t, 1, n).to_bytes(), Err(EncodeError::Range));
            let mut b = round_trip(&xr(t, 0, n));
            b[9] = 0xff;
            assert_eq!(Packet::parse(&b), Ok((xr(t, 0, n), b.len())));
        }
        // Other types keep the byte after the type.
        round_trip(&xr(xr::STATISTICS_SUMMARY, 0xe8, 36));
        round_trip(&xr(99, 7, 0));
    }

    // RFC 4585 section 6.3.3.2: PB counts the zero bits up to the next
    // 32-bit boundary.
    #[test]
    fn rpsi_padding() {
        let rp =
            |padding_bits, data: Vec<u8>| psfb(2, PayloadMessage::Rpsi(Rpsi { payload_type: 96, padding_bits, data }));
        round_trip(&rp(4, vec![0xf0, 0]));
        round_trip(&rp(31, vec![0x80, 0, 0, 0, 0, 0]));
        assert_eq!(rp(4, vec![0, 0xff]).to_bytes(), Err(EncodeError::Range));
        assert_eq!(rp(9, vec![0xff, 0x01]).to_bytes(), Err(EncodeError::Range));
        assert_eq!(rp(32, vec![0; 6]).to_bytes(), Err(EncodeError::Range));
        let head = [0x83, 206, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2];
        for bad in [[4, 96, 0, 0x0f], [32, 96, 0, 0]] {
            let b = [&head[..], &bad].concat();
            assert_eq!(Packet::parse(&b), Err(ParseError::Malformed(206)), "{bad:?}");
        }
    }

    // draft-alvestrand-rmcat-remb section 2.2: the padding bit is always
    // 0, and there is at least one SSRC.
    #[test]
    fn remb_rules() {
        let remb = |ssrcs| PayloadMessage::Remb(Remb { exponent: 1, mantissa: 2, ssrcs });
        assert_eq!(Packet { padding: 4, ..psfb(0, remb(vec![9])) }.to_bytes(), Err(EncodeError::Range));
        let b = [0xaf, 206, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, b'R', b'E', b'M', b'B', 1, 0, 0, 0, 0, 0, 0, 4];
        assert_eq!(Packet::parse(&b), Err(ParseError::Malformed(206)));
        assert_eq!(psfb(0, remb(vec![])).to_bytes(), Err(EncodeError::Empty));
        // `REMB` with a count that does not match, or no SSRCs, is a bad
        // REMB, not other application layer feedback.
        let head = [0x8f, 206, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0];
        for fci in [[b'R', b'E', b'M', b'B', 1, 0, 0, 0], [b'R', b'E', b'M', b'B', 0, 0, 0, 0]] {
            let b = [&head[..], &fci].concat();
            assert_eq!(Packet::parse(&b), Err(ParseError::Malformed(206)), "{fci:?}");
        }
        let b = [0x8f, 206, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0, b'R', b'E', b'M', b'B'];
        assert_eq!(Packet::parse(&b), Err(ParseError::Malformed(206)));
        assert_eq!(psfb(0, PayloadMessage::Afb(b"REMB".to_vec())).to_bytes(), Err(EncodeError::Alias));
        assert_eq!(
            psfb(0, PayloadMessage::Afb(b"REMB\x02\0\0\0\0\0\0\x01".to_vec())).to_bytes(),
            Err(EncodeError::Alias)
        );
        round_trip(&psfb(0, PayloadMessage::Afb(b"REMX\x02\0\0\0".to_vec())));
    }

    // RFC 3550 section 6.5.8: a PRIV item holds a prefix length, the
    // prefix, then the value.
    #[test]
    fn sdes_priv_layout() {
        let sd = |text: &[u8]| {
            Packet::from(Body::SourceDescription(vec![SdesChunk {
                ssrc: 1,
                items: vec![SdesItem { kind: sdes::PRIV, text: text.to_vec() }],
            }]))
        };
        round_trip(&sd(b"\x01ab"));
        round_trip(&sd(b"\x00"));
        assert_eq!(sd(b"\x03a").to_bytes(), Err(EncodeError::Range));
        assert_eq!(sd(b"").to_bytes(), Err(EncodeError::Range));
        for item in [[8, 2, 3, b'a'], [8, 0, 0, 0]] {
            let b = [&[0x81, 202, 0, 3, 0, 0, 0, 1][..], &item, &[0, 0, 0, 0]].concat();
            assert_eq!(Packet::parse(&b), Err(ParseError::Malformed(202)), "{item:?}");
        }
    }

    // RFC 3550 section 6.4.1: the padding count is a multiple of four,
    // for every packet type.
    #[test]
    fn padding_is_whole_words() {
        assert_eq!(Packet::parse(&[0xa4, 210, 0, 1, 1, 2, 3, 1]), Err(ParseError::Padding));
        assert_eq!(Packet::parse(&[0xa4, 210, 0, 1, 1, 2, 3, 3]), Err(ParseError::Padding));
        let p = Packet { body: Body::Other { packet_type: 210, count: 4, data: vec![1, 2, 3] }, padding: 1 };
        assert_eq!(p.to_bytes(), Err(EncodeError::Alignment));
        let p = Packet { body: Body::Other { packet_type: 210, count: 4, data: vec![1, 2, 3] }, padding: 0 };
        assert_eq!(p.to_bytes(), Err(EncodeError::Alignment));
        round_trip(&Packet { body: Body::Other { packet_type: 210, count: 4, data: vec![1, 2, 3, 4] }, padding: 4 });
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
        /// 0 to `max` random bytes.
        fn some(&mut self, max: u32) -> Vec<u8> {
            let n = self.below(max + 1) as usize;
            self.bytes(n)
        }
    }

    /// Reads `data` every way there is, and checks what reads writes back
    /// and reads the same.
    fn check(data: &[u8]) {
        let _ = classify(data);
        if let Ok(packets) = parse_packets(data) {
            let bytes = write_packets(&packets).unwrap();
            assert_eq!(bytes.len(), data.len());
            assert_eq!(parse_packets(&bytes), Ok(packets.clone()));
            assert_eq!(parse_compound(data).is_ok(), check_compound(&packets).is_ok());
        }
        if let Ok((p, used)) = Packet::parse(data) {
            assert!(used <= data.len());
            let bytes = p.to_bytes().unwrap();
            assert_eq!(Packet::parse(&bytes), Ok((p, bytes.len())));
        }
    }

    /// A packet built from random numbers, often out of range.
    fn random_packet(r: &mut Lcg) -> Packet {
        let n = |r: &mut Lcg, max: u32| r.below(max + 1) as usize;
        let rb = |r: &mut Lcg| ReportBlock {
            ssrc: r.next(),
            fraction_lost: r.next() as u8,
            cumulative_lost: r.next() as i32 >> (r.below(2) * 8),
            highest_sequence: r.next(),
            jitter: r.next(),
            last_sr: r.next(),
            delay_since_last_sr: r.next(),
        };
        let fmt = |r: &mut Lcg| r.below(34) as u8;
        let body = match r.below(16) {
            0 => Body::SenderReport(SenderReport {
                ssrc: r.next(),
                ntp_timestamp: u64::from(r.next()) << 32 | u64::from(r.next()),
                rtp_timestamp: r.next(),
                packet_count: r.next(),
                octet_count: r.next(),
                reports: (0..n(r, 33)).map(|_| rb(r)).collect(),
                extension: r.some(9),
            }),
            1 => Body::ReceiverReport(ReceiverReport {
                ssrc: r.next(),
                reports: (0..n(r, 33)).map(|_| rb(r)).collect(),
                extension: r.some(9),
            }),
            2 => Body::SourceDescription(
                (0..n(r, 33))
                    .map(|_| SdesChunk {
                        ssrc: r.next(),
                        items: (0..n(r, 4)).map(|_| SdesItem { kind: r.below(10) as u8, text: r.some(20) }).collect(),
                    })
                    .collect(),
            ),
            3 => Body::Bye(Bye {
                sources: (0..n(r, 33)).map(|_| r.next()).collect(),
                reason: if r.below(2) == 0 { None } else { Some(r.some(260)) },
            }),
            4 => Body::App(App { subtype: fmt(r), ssrc: r.next(), name: [1, 2, 3, 4], data: r.some(13) }),
            5..=7 => {
                let entries = n(r, 4);
                let message = match r.below(4) {
                    0 => TransportMessage::Nack(
                        (0..entries).map(|_| Nack { pid: r.next() as u16, blp: r.next() as u16 }).collect(),
                    ),
                    k => {
                        let items = (0..entries)
                            .map(|_| Tmmb {
                                ssrc: r.next(),
                                exponent: r.below(66) as u8,
                                mantissa: r.below(1 << 17) + r.below(2),
                                overhead: r.below(513) as u16,
                            })
                            .collect();
                        match k {
                            1 => TransportMessage::Tmmbr(items),
                            2 => TransportMessage::Tmmbn(items),
                            _ => TransportMessage::Other { fmt: fmt(r), fci: r.some(9) },
                        }
                    }
                };
                let media_ssrc = if r.below(2) == 0 { 0 } else { r.next() };
                Body::TransportFeedback(TransportFeedback { sender_ssrc: r.next(), media_ssrc, message })
            }
            8..=11 => {
                let entries = n(r, 4);
                let message = match r.below(7) {
                    0 => PayloadMessage::Pli,
                    1 => PayloadMessage::Sli(
                        (0..entries)
                            .map(|_| Sli {
                                first: r.below(8200) as u16,
                                number: r.below(8200) as u16,
                                picture_id: r.below(66) as u8,
                            })
                            .collect(),
                    ),
                    2 => {
                        let len = 2 + 4 * n(r, 2) + n(r, 1);
                        PayloadMessage::Rpsi(Rpsi {
                            payload_type: r.below(130) as u8,
                            padding_bits: r.below(50) as u8,
                            data: r.bytes(len),
                        })
                    }
                    3 => PayloadMessage::Fir(
                        (0..entries).map(|_| Fir { ssrc: r.next(), sequence: r.next() as u8 }).collect(),
                    ),
                    4 => PayloadMessage::Remb(Remb {
                        exponent: r.below(66) as u8,
                        mantissa: r.below(1 << 18) + r.below(2),
                        ssrcs: (0..entries).map(|_| r.next()).collect(),
                    }),
                    5 => {
                        let k = n(r, 3);
                        let mut d = r.bytes(4 * k);
                        if r.below(2) == 0 && d.len() >= 8 {
                            d[..4].copy_from_slice(b"REMB");
                        }
                        PayloadMessage::Afb(d)
                    }
                    _ => PayloadMessage::Other { fmt: fmt(r), fci: r.some(9) },
                };
                let media_ssrc = if r.below(2) == 0 { 0 } else { r.next() };
                Body::PayloadFeedback(PayloadFeedback { sender_ssrc: r.next(), media_ssrc, message })
            }
            12 | 13 => Body::ExtendedReport(ExtendedReport {
                ssrc: r.next(),
                blocks: (0..n(r, 3))
                    .map(|_| {
                        let words = n(r, 10);
                        XrBlock {
                            block_type: r.below(9) as u8,
                            type_specific: if r.below(2) == 0 { 0 } else { r.next() as u8 },
                            data: r.bytes(4 * words),
                        }
                    })
                    .collect(),
            }),
            _ => Body::Other { packet_type: r.next() as u8, count: fmt(r), data: r.some(9) },
        };
        let padding = match r.below(4) {
            0 => r.next() as u8,
            1 => 4 * r.below(3) as u8,
            _ => 0,
        };
        Packet { body, padding }
    }

    #[test]
    fn lcg_fuzz_parsers() {
        let mut r = Lcg(0x5254_4350);
        let seed = write_compound(&[
            rr(1),
            cname(1, b"a"),
            Packet::from(Body::TransportFeedback(TransportFeedback {
                sender_ssrc: 1,
                media_ssrc: 2,
                message: TransportMessage::Nack(vec![Nack { pid: 3, blp: 4 }]),
            })),
        ])
        .unwrap();
        for i in 0..20000 {
            let data = if i % 2 == 0 {
                // Random bytes, often with a version-2 header in front.
                let mut d = r.some(79);
                if let Some(b) = d.first_mut()
                    && r.below(4) != 0
                {
                    *b = 0x80 | (*b & 0x3f);
                }
                if d.len() > 1 && r.below(2) == 0 {
                    d[1] = 200 + r.below(8) as u8;
                }
                d
            } else {
                // The seed with a few bytes changed.
                let mut d = seed.clone();
                for _ in 0..1 + r.below(3) {
                    let at = r.below(d.len() as u32) as usize;
                    d[at] = r.next() as u8;
                }
                d.truncate(d.len() - r.below(3) as usize);
                d
            };
            check(&data);
            // Through the stream decoder, whole and a byte at a time.
            let stream = [frame(&data).unwrap(), data.clone()].concat();
            let whole = split(&stream, stream.len());
            assert_eq!(split(&stream, 1), whole);
            assert_eq!(whole.first(), Some(&data));
        }
    }

    #[test]
    fn lcg_fuzz_writers() {
        let mut r = Lcg(0x7772_6974);
        let mut written = 0;
        let mut kinds = std::collections::BTreeSet::new();
        for _ in 0..20000 {
            let p = random_packet(&mut r);
            if let Ok(bytes) = p.to_bytes() {
                written += 1;
                kinds.insert((bytes[1], bytes[0] & 0x1f));
                assert!(bytes.len() <= MAX_PACKET && bytes.len() % 4 == 0);
                assert_eq!(Packet::parse(&bytes), Ok((p.clone(), bytes.len())));
                assert_eq!(parse_packets(&bytes), Ok(vec![p.clone()]));
                let compound = vec![rr(1), cname(1, b"c"), p];
                if let Ok(b) = write_compound(&compound) {
                    assert_eq!(parse_compound(&b), Ok(compound));
                }
            }
        }
        // Enough values are valid that the loop tests the writers.
        assert!(written > 5000, "{written}");
        // Including the messages with an unused media SSRC.
        for k in [(205, 3), (205, 4), (206, 4), (206, 15), (206, 3), (207, 0)] {
            assert!(kinds.contains(&k), "{k:?}");
        }
    }
}
