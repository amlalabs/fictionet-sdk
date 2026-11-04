//! MPTCP: reading and writing the TCP options of Multipath TCP, the keys,
//! tokens and HMACs its handshakes use, and the data level of a connection
//! with one subflow, with no I/O.
//!
//! [`MptcpOption`] reads and writes one option through `Wire`. [`token`],
//! [`idsn`] and [`join_hmac`] compute what RFC 8684 derives from the keys,
//! and [`dss_checksum`] the checksum of a mapping. [`DataLevel`] gives the
//! DSS for each segment of a connection that has one subflow. There is no
//! data sequence reassembly over several subflows, path manager,
//! `Service`, or live transport.
//!
//! Multipath TCP lets one connection use several paths at once, such as
//! Wi-Fi and a mobile network. The first TCP connection, the first
//! subflow, opens with MP_CAPABLE in its SYN, SYN/ACK and ACK, which
//! exchanges a 64-bit key from each host. Each later subflow opens with
//! MP_JOIN, which names the connection by a 32-bit token hashed from the
//! listener's key, and proves the keys are known with an HMAC. Data is
//! placed in one connection-level sequence space with DSS options.
//! ADD_ADDR and REMOVE_ADDR announce and withdraw addresses, MP_PRIO marks
//! a subflow as a backup, MP_FAIL and MP_FASTCLOSE end things abruptly,
//! and MP_TCPRST says why a subflow was reset. Linux has spoken MPTCP
//! since 5.6. This module follows RFC 8684, version 1 of the protocol.
//!
//! Every MPTCP option is TCP option kind 30 ([`KIND`]). Its first 4 bits
//! are a subtype, and the subtype and the option's Length say what
//! follows. [`MptcpOption::parse`] reads the option's data, the bytes
//! after Kind and Length, as a TCP header's option list hands them over,
//! and [`MptcpOption::write`] writes them back. The option's Length is
//! that data's length plus 2. Errors give lengths as the option's Length,
//! as the RFC's figures do.
//!
//! The reader is strict. It refuses a Length the subtype does not define,
//! the unassigned subtypes 0x9 to 0xe and the experimental 0xf, an option
//! longer than the 40 bytes a TCP header has room for, and an MP_CAPABLE
//! that names no crypto algorithm (bits D to H all clear), which RFC 8684
//! says is invalid. Reserved bits are ignored on receipt and written as
//! zero, so an option read and written again may differ from its bytes
//! only in those bits. MP_CAPABLE keeps its version and all its flags.
//!
//! MP_CAPABLE version 0 (RFC 6824) has the same layout, with the
//! sender's key in the SYN too, so the reader takes it at Lengths 12 and
//! 20 only. Bit C, which RFC 6824 left to crypto algorithms that were
//! never assigned, reads as [`Capable::no_new_subflows`]. Version 0's own
//! ADD_ADDR and MP_PRIO layouts are not read here: they fail as Lengths
//! version 1 does not define.
//!
//! The caller knows what this module does not: whether the segment is a
//! SYN, a SYN/ACK or an ACK, which keys belong to which connection, and
//! whether checksums were negotiated. A listener answers an MP_CAPABLE
//! SYN with a SYN/ACK carrying [`Keys::Sender`] and its own random key,
//! checks the keys echoed in the third ACK, and finds a joining subflow's
//! connection by its [`token`].
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::protocols::mptcp::{
//!     Capable, KIND, Keys, MptcpOption, algorithm, token,
//! };
//!
//! // A Linux client's SYN carries MP_CAPABLE version 1: Kind 30,
//! // Length 4, subtype 0 and version 1, then flag H (HMAC-SHA256). It
//! // sets flag A, for checksums, only when net.mptcp.checksum_enabled
//! // is on, which it is not by default.
//! let syn = [KIND, 4, 0x01, 0x01];
//! let MptcpOption::Capable(offer) = MptcpOption::parse(&syn[2..]).unwrap() else {
//!     unreachable!()
//! };
//! assert_eq!((offer.version, offer.keys), (1, Keys::Absent));
//! assert!(!offer.checksum_required);
//!
//! // The listener picks a key and sends it back in the SYN/ACK, choosing
//! // HMAC-SHA256.
//! let key = 0x0123_4567_89ab_cdef;
//! let answer = MptcpOption::Capable(Capable {
//!     algorithms: algorithm::HMAC_SHA256,
//!     keys: Keys::Sender(key),
//!     ..offer
//! });
//! let data = answer.to_bytes().unwrap();
//! assert_eq!(data.len() + 2, 12);
//! assert_eq!(data[..2], [0x01, 0x01]);
//!
//! // A joining subflow names this connection by the key's token.
//! assert_eq!(token(key), 0x55c5_3f5d);
//! ```

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use smoltcp::wire::TcpSeqNumber;

use fictionet::stdlib::codec::{Reader, Truncated, Wire};

/// The TCP option kind every MPTCP option has (RFC 8684 section 7.1).
pub const KIND: u8 = 30;
/// The MPTCP version this module follows, RFC 8684's.
pub const VERSION: u8 = 1;
/// The longest option Length: a TCP header has 40 bytes for options.
pub const MAX_LEN: usize = 40;
/// The most Address IDs one REMOVE_ADDR can carry, in the longest option.
pub const MAX_REMOVE_IDS: usize = MAX_LEN - 3;

/// The subtype in the first 4 bits of every MPTCP option (RFC 8684
/// section 7.2). 0x9 to 0xe are unassigned.
pub mod subtype {
    /// Multipath Capable: opens the first subflow.
    pub const MP_CAPABLE: u8 = 0x0;
    /// Join Connection: opens another subflow.
    pub const MP_JOIN: u8 = 0x1;
    /// Data Sequence Signal: data acknowledgment and mapping.
    pub const DSS: u8 = 0x2;
    /// Add Address.
    pub const ADD_ADDR: u8 = 0x3;
    /// Remove Address.
    pub const REMOVE_ADDR: u8 = 0x4;
    /// Change Subflow Priority.
    pub const MP_PRIO: u8 = 0x5;
    /// Fallback.
    pub const MP_FAIL: u8 = 0x6;
    /// Fast Close.
    pub const MP_FASTCLOSE: u8 = 0x7;
    /// Subflow Reset.
    pub const MP_TCPRST: u8 = 0x8;
    /// Reserved for private experiments. Readers refuse it, since no
    /// layout is defined.
    pub const MP_EXPERIMENTAL: u8 = 0xf;
}

/// Bits D to H of MP_CAPABLE, which negotiate the crypto algorithm
/// (RFC 8684 section 7.3). The initiator sets one bit for each algorithm
/// it supports, and the responder answers with the one it chose.
pub mod algorithm {
    /// Bit H: HMAC-SHA256, the only algorithm RFC 8684 assigns. In
    /// version 0 (RFC 6824) the same bit meant HMAC-SHA1.
    pub const HMAC_SHA256: u8 = 0x01;
    /// All of bits D to H.
    pub const ALL: u8 = 0x1f;
}

/// MP_TCPRST reason codes (RFC 8684 section 3.6). Readers keep any
/// value as given.
pub mod reason {
    /// Unspecified error: the subflow is no longer available.
    pub const UNSPECIFIED: u8 = 0x00;
    /// An error in processing MPTCP options.
    pub const MPTCP_SPECIFIC: u8 = 0x01;
    /// The sender lacks resources for the subflow.
    pub const LACK_OF_RESOURCES: u8 = 0x02;
    /// The sender's policy prohibits the subflow.
    pub const ADMINISTRATIVELY_PROHIBITED: u8 = 0x03;
    /// Too much data outstanding on the subflow.
    pub const TOO_MUCH_OUTSTANDING_DATA: u8 = 0x04;
    /// The subflow performed too poorly.
    pub const UNACCEPTABLE_PERFORMANCE: u8 = 0x05;
    /// A middlebox interfered with MPTCP signaling.
    pub const MIDDLEBOX_INTERFERENCE: u8 = 0x06;
}

/// One MPTCP option (RFC 8684 section 3), from its subtype on.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MptcpOption {
    /// MP_CAPABLE (section 3.1), on the first subflow's handshake and,
    /// with data parameters, on the initiator's first data.
    Capable(Capable),
    /// MP_JOIN (section 3.2), on a later subflow's handshake.
    Join(Join),
    /// DSS (section 3.3).
    Dss(Dss),
    /// ADD_ADDR (section 3.4.1).
    AddAddr(AddAddr),
    /// REMOVE_ADDR (section 3.4.2): the Address IDs withdrawn, at least
    /// one and at most [`MAX_REMOVE_IDS`].
    RemoveAddr {
        /// The Address IDs, in the order sent.
        address_ids: Vec<u8>,
    },
    /// MP_PRIO (section 3.3.8): changes the backup flag of the subflow
    /// it is sent on.
    Prio {
        /// The B flag: the sender asks that this subflow carry data only
        /// when no subflow without it is usable.
        backup: bool,
    },
    /// MP_FAIL (section 3.7): the data sequence number at the start of
    /// the mapping whose checksum failed.
    Fail {
        /// The full 64-bit data sequence number.
        data_sequence_number: DataSequence,
    },
    /// MP_FASTCLOSE (section 3.5): closes the whole connection at once.
    FastClose {
        /// The key of the host receiving the option, as it declared it
        /// in MP_CAPABLE.
        receiver_key: u64,
    },
    /// MP_TCPRST (section 3.6), on a RST: why the subflow was reset.
    TcpRst {
        /// The T flag: the error is transient, so the peer may try the
        /// path again.
        transient: bool,
        /// One of the [`reason`] codes, or another byte.
        reason: u8,
    },
}

/// MP_CAPABLE (RFC 8684 section 3.1, figure 4): the version, the flags
/// and the keys the option's Length says are there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Capable {
    /// The MPTCP version, 4 bits: [`VERSION`] for RFC 8684, 0 for RFC
    /// 6824. Writers refuse a value above 15.
    pub version: u8,
    /// Flag A: checksums required.
    pub checksum_required: bool,
    /// Flag B: the extensibility flag, which RFC 8684 says to send as 0.
    /// A host that does not understand it ignores the option.
    pub extensibility: bool,
    /// Flag C: the sender accepts no more subflows to the source address
    /// and port of this packet.
    pub no_new_subflows: bool,
    /// Flags D to H, the crypto algorithms offered or chosen, as the low
    /// 5 bits: see [`algorithm`]. Never 0, and writers refuse a value
    /// above [`algorithm::ALL`].
    pub algorithms: u8,
    /// The keys and data parameters.
    pub keys: Keys,
}

/// What follows MP_CAPABLE's flags, which its Length decides. "Sender"
/// and "receiver" are those of the packet the option is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Keys {
    /// Nothing (Length 4): a version 1 SYN.
    Absent,
    /// The sender's key (Length 12): a SYN/ACK, or a version 0 SYN.
    Sender(u64),
    /// Both keys (Length 20): the initiator's key, then the listener's,
    /// on the third ACK.
    Both {
        /// The sender's key.
        sender: u64,
        /// The receiver's key, echoed back.
        receiver: u64,
    },
    /// Both keys and the first data's parameters (Length 22, or 24 with
    /// a checksum): the initiator's first data. Version 1 only.
    Data {
        /// The sender's key.
        sender: u64,
        /// The receiver's key, echoed back.
        receiver: u64,
        /// How many bytes of the segment's payload the mapping covers.
        data_level_length: u16,
        /// The DSS checksum, present when checksums were negotiated.
        checksum: Option<u16>,
    },
}

/// MP_JOIN (RFC 8684 section 3.2), in the form for each packet of a new
/// subflow's handshake. The option's Length tells the forms apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Join {
    /// On the SYN (Length 12, figure 5).
    Syn {
        /// The B flag: the sender wants this subflow kept as a backup.
        backup: bool,
        /// The sender's identifier for its source address.
        address_id: u8,
        /// The receiver's [`token`], naming the connection to join.
        token: u32,
        /// The sender's random number.
        random: u32,
    },
    /// On the SYN/ACK (Length 16, figure 6).
    SynAck {
        /// The B flag, as on the SYN.
        backup: bool,
        /// The sender's identifier for its source address.
        address_id: u8,
        /// The leftmost 64 bits of the sender's [`join_hmac`].
        hmac: [u8; 8],
        /// The sender's random number.
        random: u32,
    },
    /// On the initiator's first ACK (Length 24, figure 7).
    Ack {
        /// The leftmost 160 bits of the sender's [`join_hmac`].
        hmac: [u8; 20],
    },
}

/// A full MPTCP data sequence number, modulo 2^64.
///
/// Serial ordering is defined only within a half-space. In particular,
/// numbers exactly 2^63 apart have no order. There is deliberately no `Ord`:
/// sequence numbers cannot be sorted as ordinary integers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DataSequence(u64);

impl DataSequence {
    /// Reads the bits of a full data sequence number from the wire or digest.
    pub const fn new(bits: u64) -> Self {
        Self(bits)
    }

    /// The bits to write to a full-width wire field.
    pub const fn to_bits(self) -> u64 {
        self.0
    }

    /// The low 32 bits used by a short DSS field.
    pub const fn short(self) -> u32 {
        self.0 as u32
    }

    /// Advances within the serial half-space, wrapping at 2^64.
    ///
    /// Panics if the increment is at least 2^63, whose order is undefined.
    pub fn advance(self, bytes: u64) -> Self {
        assert!(
            bytes <= i64::MAX as u64,
            "data sequence increment exceeds half-space"
        );
        Self(self.0.wrapping_add(bytes))
    }

    /// Signed serial displacement from `other`, or `None` at exactly 2^63.
    pub fn offset_from(self, other: Self) -> Option<i64> {
        let distance = self.0.wrapping_sub(other.0) as i64;
        (distance != i64::MIN).then_some(distance)
    }

    /// Whether this number is at or before `other` in serial order.
    /// An ambiguous half-space distance returns false.
    pub fn at_or_before(self, other: Self) -> bool {
        self.offset_from(other)
            .is_some_and(|distance| distance <= 0)
    }

    /// Expands a DSS field near this position. A short field exactly half
    /// its 32-bit space away goes backward; a full field is already expanded.
    pub fn expand(self, sequence: Sequence) -> Self {
        match sequence {
            Sequence::Long(full) => full,
            Sequence::Short(low) => {
                let distance = low.wrapping_sub(self.short()) as i32;
                Self(self.0.wrapping_add_signed(i64::from(distance)))
            }
        }
    }
}

/// A data sequence number or Data ACK in DSS, which a flag makes 4 or 8
/// octets long. The default is the 8-octet 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sequence {
    /// A 4-octet number: the low 32 bits of the 64-bit one.
    Short(u32),
    /// An 8-octet number.
    Long(DataSequence),
}

impl Default for Sequence {
    fn default() -> Sequence {
        Sequence::Long(DataSequence::new(0))
    }
}

/// DSS (RFC 8684 section 3.3, figure 9): a Data ACK, a mapping, both or
/// neither, and the DATA_FIN flag. The default has neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Dss {
    /// Flag A, with flag a giving the size: the next data sequence
    /// number the sender expects.
    pub data_ack: Option<Sequence>,
    /// Flag M, with flag m giving the size of its data sequence number.
    pub mapping: Option<Mapping>,
    /// Flag F: DATA_FIN, the mapping covers the sender's last data.
    pub data_fin: bool,
}

/// A data sequence mapping (RFC 8684 section 3.3.1): which bytes of the
/// subflow carry which bytes of the connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mapping {
    /// The data sequence number of the first byte mapped.
    pub data_sequence_number: Sequence,
    /// The subflow sequence number of the first byte, relative to the
    /// subflow's SYN.
    pub subflow_sequence_number: u32,
    /// How many bytes the mapping covers. 0 is the infinite mapping a
    /// host falls back to TCP with.
    pub data_level_length: u16,
    /// The DSS checksum, present when checksums were negotiated. The
    /// option's Length tells whether it is there.
    pub checksum: Option<u16>,
}

/// ADD_ADDR (RFC 8684 section 3.4.1, figure 12): an address, and maybe a
/// port, on which the sender can be reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddAddr {
    /// The sender's identifier for the address.
    pub address_id: u8,
    /// The address, IPv4 or IPv6.
    pub address: IpAddr,
    /// The port, when it differs from the current subflow's.
    pub port: Option<u16>,
    /// The rightmost 64 bits of the sender's HMAC over the Address ID,
    /// address and port. `None` is an echo (flag E), which acknowledges
    /// an ADD_ADDR received and carries no HMAC.
    pub hmac: Option<[u8; 8]>,
}

/// Why an MPTCP option cannot be read or written. A host that cannot
/// read an option ignores it, which for MP_CAPABLE means falling back to
/// plain TCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The option had no data, so no subtype (Length 2).
    NoSubtype,
    /// The option's Length was over [`MAX_LEN`], more than a TCP header
    /// holds. It holds the Length.
    TooLong(usize),
    /// An unassigned subtype, or [`subtype::MP_EXPERIMENTAL`]. It holds
    /// the subtype.
    Subtype(u8),
    /// A Length the subtype does not define with these flags or this
    /// version.
    Length {
        /// The subtype.
        subtype: u8,
        /// The option's Length.
        length: usize,
    },
    /// MP_CAPABLE with flags D to H all clear, which names no crypto
    /// algorithm. RFC 8684 section 3.1 says to treat it as invalid.
    NoAlgorithm,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::NoSubtype => f.write_str("MPTCP option with no subtype"),
            Error::TooLong(n) => write!(f, "MPTCP option of length {n}, over {MAX_LEN}"),
            Error::Subtype(s) => write!(f, "MPTCP subtype {s:#x} has no defined layout"),
            Error::Length { subtype, length } => {
                write!(
                    f,
                    "MPTCP subtype {subtype:#x} does not define length {length}"
                )
            }
            Error::NoAlgorithm => f.write_str("MP_CAPABLE names no crypto algorithm"),
        }
    }
}

impl std::error::Error for Error {}

impl MptcpOption {
    /// The option's subtype, one of the [`subtype`] values.
    pub fn subtype(&self) -> u8 {
        match self {
            MptcpOption::Capable(_) => subtype::MP_CAPABLE,
            MptcpOption::Join(_) => subtype::MP_JOIN,
            MptcpOption::Dss(_) => subtype::DSS,
            MptcpOption::AddAddr(_) => subtype::ADD_ADDR,
            MptcpOption::RemoveAddr { .. } => subtype::REMOVE_ADDR,
            MptcpOption::Prio { .. } => subtype::MP_PRIO,
            MptcpOption::Fail { .. } => subtype::MP_FAIL,
            MptcpOption::FastClose { .. } => subtype::MP_FASTCLOSE,
            MptcpOption::TcpRst { .. } => subtype::MP_TCPRST,
        }
    }
}

/// DSS flag bits, in the option's second byte.
const DSS_DATA_FIN: u8 = 0x10;
const DSS_LONG_DSN: u8 = 0x08;
const DSS_MAPPING: u8 = 0x04;
const DSS_LONG_ACK: u8 = 0x02;
const DSS_ACK: u8 = 0x01;

/// MP_CAPABLE flag bits A, B and C.
const CAPABLE_A: u8 = 0x80;
const CAPABLE_B: u8 = 0x40;
const CAPABLE_C: u8 = 0x20;

/// The lowest bit of the subtype's nibble: B in MP_JOIN and MP_PRIO, E in
/// ADD_ADDR, T in MP_TCPRST.
const LOW_FLAG: u8 = 0x01;

impl Wire for MptcpOption {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one option from its data, the bytes after Kind and Length.
    /// Refuses unassigned subtypes and Lengths the subtype does not
    /// define. Reads the whole input.
    fn parse(data: &[u8]) -> Result<MptcpOption, Error> {
        let length = data.len() + 2;
        if length > MAX_LEN {
            return Err(Error::TooLong(length));
        }
        let Some((&first, rest)) = data.split_first() else {
            return Err(Error::NoSubtype);
        };
        let sub = first >> 4;
        let low = first & 0x0f;
        let bad = Error::Length {
            subtype: sub,
            length,
        };
        // Every read below is within a length checked first, so a short
        // read cannot happen. It still fails as the Length, not a panic.
        let mut r = Reader::new(rest);
        let short = |_: Truncated| bad;
        let option = match sub {
            subtype::MP_CAPABLE => {
                let flags = r.u8().map_err(short)?;
                let keys = match rest.len() {
                    1 => Keys::Absent,
                    9 => Keys::Sender(r.u64_be().map_err(short)?),
                    17 => Keys::Both {
                        sender: r.u64_be().map_err(short)?,
                        receiver: r.u64_be().map_err(short)?,
                    },
                    19 | 21 => Keys::Data {
                        sender: r.u64_be().map_err(short)?,
                        receiver: r.u64_be().map_err(short)?,
                        data_level_length: r.u16_be().map_err(short)?,
                        checksum: match r.remaining() {
                            0 => None,
                            _ => Some(r.u16_be().map_err(short)?),
                        },
                    },
                    _ => return Err(bad),
                };
                if low == 0 && !matches!(keys, Keys::Sender(_) | Keys::Both { .. }) {
                    return Err(bad);
                }
                let algorithms = flags & algorithm::ALL;
                if algorithms == 0 {
                    return Err(Error::NoAlgorithm);
                }
                MptcpOption::Capable(Capable {
                    version: low,
                    checksum_required: flags & CAPABLE_A != 0,
                    extensibility: flags & CAPABLE_B != 0,
                    no_new_subflows: flags & CAPABLE_C != 0,
                    algorithms,
                    keys,
                })
            }
            subtype::MP_JOIN => {
                let backup = low & LOW_FLAG != 0;
                MptcpOption::Join(match length {
                    12 => Join::Syn {
                        backup,
                        address_id: r.u8().map_err(short)?,
                        token: r.u32_be().map_err(short)?,
                        random: r.u32_be().map_err(short)?,
                    },
                    16 => Join::SynAck {
                        backup,
                        address_id: r.u8().map_err(short)?,
                        hmac: r.array().map_err(short)?,
                        random: r.u32_be().map_err(short)?,
                    },
                    24 => {
                        r.skip(1).map_err(short)?;
                        Join::Ack {
                            hmac: r.array().map_err(short)?,
                        }
                    }
                    _ => return Err(bad),
                })
            }
            subtype::DSS => {
                let flags = r.u8().map_err(short)?;
                let ack_len = match (flags & DSS_ACK != 0, flags & DSS_LONG_ACK != 0) {
                    (false, _) => 0,
                    (true, false) => 4,
                    (true, true) => 8,
                };
                let dsn_len = match (flags & DSS_MAPPING != 0, flags & DSS_LONG_DSN != 0) {
                    (false, _) => None,
                    (true, false) => Some(4),
                    (true, true) => Some(8),
                };
                // The mapping is the DSN, 4 octets of subflow sequence
                // number and 2 of data-level length, then maybe 2 of
                // checksum.
                let checksum = match dsn_len {
                    None if rest.len() == 1 + ack_len => false,
                    Some(n) if rest.len() == 1 + ack_len + n + 6 => false,
                    Some(n) if rest.len() == 1 + ack_len + n + 8 => true,
                    _ => return Err(bad),
                };
                let data_ack = match ack_len {
                    0 => None,
                    4 => Some(Sequence::Short(r.u32_be().map_err(short)?)),
                    _ => Some(Sequence::Long(DataSequence::new(
                        r.u64_be().map_err(short)?,
                    ))),
                };
                let mapping = match dsn_len {
                    None => None,
                    Some(n) => Some(Mapping {
                        data_sequence_number: if n == 4 {
                            Sequence::Short(r.u32_be().map_err(short)?)
                        } else {
                            Sequence::Long(DataSequence::new(r.u64_be().map_err(short)?))
                        },
                        subflow_sequence_number: r.u32_be().map_err(short)?,
                        data_level_length: r.u16_be().map_err(short)?,
                        checksum: if checksum {
                            Some(r.u16_be().map_err(short)?)
                        } else {
                            None
                        },
                    }),
                };
                MptcpOption::Dss(Dss {
                    data_ack,
                    mapping,
                    data_fin: flags & DSS_DATA_FIN != 0,
                })
            }
            subtype::ADD_ADDR => {
                let echo = low & LOW_FLAG != 0;
                let address_id = r.u8().map_err(short)?;
                // After the Address ID: the address, 2 octets of port if
                // given, and 8 of HMAC unless this is an echo.
                let hmac_len = if echo { 0 } else { 8 };
                let after = rest.len().saturating_sub(1).saturating_sub(hmac_len);
                let (v6, port) = match after {
                    4 => (false, false),
                    6 => (false, true),
                    16 => (true, false),
                    18 => (true, true),
                    _ => return Err(bad),
                };
                if rest.len() != 1 + after + hmac_len {
                    return Err(bad);
                }
                let address = if v6 {
                    IpAddr::V6(Ipv6Addr::from(r.array::<16>().map_err(short)?))
                } else {
                    IpAddr::V4(Ipv4Addr::from(r.array::<4>().map_err(short)?))
                };
                MptcpOption::AddAddr(AddAddr {
                    address_id,
                    address,
                    port: if port {
                        Some(r.u16_be().map_err(short)?)
                    } else {
                        None
                    },
                    hmac: if echo {
                        None
                    } else {
                        Some(r.array().map_err(short)?)
                    },
                })
            }
            subtype::REMOVE_ADDR => {
                if rest.is_empty() {
                    return Err(bad);
                }
                MptcpOption::RemoveAddr {
                    address_ids: r.rest().to_vec(),
                }
            }
            subtype::MP_PRIO => {
                if !rest.is_empty() {
                    return Err(bad);
                }
                MptcpOption::Prio {
                    backup: low & LOW_FLAG != 0,
                }
            }
            subtype::MP_FAIL | subtype::MP_FASTCLOSE => {
                if length != 12 {
                    return Err(bad);
                }
                r.skip(1).map_err(short)?;
                let value = r.u64_be().map_err(short)?;
                if sub == subtype::MP_FAIL {
                    MptcpOption::Fail {
                        data_sequence_number: DataSequence::new(value),
                    }
                } else {
                    MptcpOption::FastClose {
                        receiver_key: value,
                    }
                }
            }
            subtype::MP_TCPRST => {
                if length != 4 {
                    return Err(bad);
                }
                MptcpOption::TcpRst {
                    transient: low & LOW_FLAG != 0,
                    reason: r.u8().map_err(short)?,
                }
            }
            other => return Err(Error::Subtype(other)),
        };
        r.finish().map_err(|_| bad)?;
        Ok(option)
    }

    /// Appends the option's data, the bytes after Kind and Length.
    /// Refuses an MP_CAPABLE version above 15, algorithms that are 0 or
    /// above [`algorithm::ALL`], version 0 keys that RFC 6824 does not
    /// define, and a REMOVE_ADDR with no Address IDs or more than
    /// [`MAX_REMOVE_IDS`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut b = Vec::with_capacity(MAX_LEN - 2);
        let sub = self.subtype() << 4;
        match self {
            MptcpOption::Capable(c) => {
                if c.version > 0x0f || c.algorithms == 0 || c.algorithms > algorithm::ALL {
                    return Err(Error::Unwritable);
                }
                if c.version == 0 && !matches!(c.keys, Keys::Sender(_) | Keys::Both { .. }) {
                    return Err(Error::Unwritable);
                }
                let mut flags = c.algorithms;
                if c.checksum_required {
                    flags |= CAPABLE_A;
                }
                if c.extensibility {
                    flags |= CAPABLE_B;
                }
                if c.no_new_subflows {
                    flags |= CAPABLE_C;
                }
                b.extend_from_slice(&[sub | c.version, flags]);
                match c.keys {
                    Keys::Absent => {}
                    Keys::Sender(key) => b.extend_from_slice(&key.to_be_bytes()),
                    Keys::Both { sender, receiver } => {
                        b.extend_from_slice(&sender.to_be_bytes());
                        b.extend_from_slice(&receiver.to_be_bytes());
                    }
                    Keys::Data {
                        sender,
                        receiver,
                        data_level_length,
                        checksum,
                    } => {
                        b.extend_from_slice(&sender.to_be_bytes());
                        b.extend_from_slice(&receiver.to_be_bytes());
                        b.extend_from_slice(&data_level_length.to_be_bytes());
                        if let Some(sum) = checksum {
                            b.extend_from_slice(&sum.to_be_bytes());
                        }
                    }
                }
            }
            MptcpOption::Join(Join::Syn {
                backup,
                address_id,
                token,
                random,
            }) => {
                b.extend_from_slice(&[sub | u8::from(*backup), *address_id]);
                b.extend_from_slice(&token.to_be_bytes());
                b.extend_from_slice(&random.to_be_bytes());
            }
            MptcpOption::Join(Join::SynAck {
                backup,
                address_id,
                hmac,
                random,
            }) => {
                b.extend_from_slice(&[sub | u8::from(*backup), *address_id]);
                b.extend_from_slice(hmac);
                b.extend_from_slice(&random.to_be_bytes());
            }
            MptcpOption::Join(Join::Ack { hmac }) => {
                b.extend_from_slice(&[sub, 0]);
                b.extend_from_slice(hmac);
            }
            MptcpOption::Dss(d) => {
                let mut flags = 0;
                if d.data_fin {
                    flags |= DSS_DATA_FIN;
                }
                if let Some(ack) = d.data_ack {
                    flags |= DSS_ACK;
                    if matches!(ack, Sequence::Long(_)) {
                        flags |= DSS_LONG_ACK;
                    }
                }
                if let Some(m) = d.mapping {
                    flags |= DSS_MAPPING;
                    if matches!(m.data_sequence_number, Sequence::Long(_)) {
                        flags |= DSS_LONG_DSN;
                    }
                }
                b.extend_from_slice(&[sub, flags]);
                if let Some(ack) = d.data_ack {
                    write_sequence(ack, &mut b);
                }
                if let Some(m) = d.mapping {
                    write_sequence(m.data_sequence_number, &mut b);
                    b.extend_from_slice(&m.subflow_sequence_number.to_be_bytes());
                    b.extend_from_slice(&m.data_level_length.to_be_bytes());
                    if let Some(sum) = m.checksum {
                        b.extend_from_slice(&sum.to_be_bytes());
                    }
                }
            }
            MptcpOption::AddAddr(a) => {
                b.extend_from_slice(&[sub | u8::from(a.hmac.is_none()), a.address_id]);
                match a.address {
                    IpAddr::V4(v4) => b.extend_from_slice(&v4.octets()),
                    IpAddr::V6(v6) => b.extend_from_slice(&v6.octets()),
                }
                if let Some(port) = a.port {
                    b.extend_from_slice(&port.to_be_bytes());
                }
                if let Some(hmac) = a.hmac {
                    b.extend_from_slice(&hmac);
                }
            }
            MptcpOption::RemoveAddr { address_ids } => {
                if address_ids.is_empty() || address_ids.len() > MAX_REMOVE_IDS {
                    return Err(Error::Unwritable);
                }
                b.push(sub);
                b.extend_from_slice(address_ids);
            }
            MptcpOption::Prio { backup } => b.push(sub | u8::from(*backup)),
            MptcpOption::Fail {
                data_sequence_number,
            } => {
                b.extend_from_slice(&[sub, 0]);
                b.extend_from_slice(&data_sequence_number.to_bits().to_be_bytes());
            }
            MptcpOption::FastClose {
                receiver_key: value,
            } => {
                b.extend_from_slice(&[sub, 0]);
                b.extend_from_slice(&value.to_be_bytes());
            }
            MptcpOption::TcpRst { transient, reason } => {
                b.extend_from_slice(&[sub | u8::from(*transient), *reason]);
            }
        }
        dst.extend_from_slice(&b);
        Ok(())
    }
}

fn write_sequence(s: Sequence, b: &mut Vec<u8>) {
    match s {
        Sequence::Short(n) => b.extend_from_slice(&n.to_be_bytes()),
        Sequence::Long(n) => b.extend_from_slice(&n.to_bits().to_be_bytes()),
    }
}

/// The SHA-256 digest of a key in network byte order, as RFC 8684
/// section 3.1 hashes it.
fn key_digest(key: u64) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, &key.to_be_bytes());
    let mut out = [0; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// A key's token (RFC 8684 section 3.1): the most significant 32 bits of
/// its SHA-256 hash. MP_JOIN names a connection by the receiver's token.
///
/// ```
/// use fictionet::stdlib::protocols::mptcp::token;
/// assert_eq!(token(0xfedc_ba98_7654_3210), 0x18f9_781b);
/// ```
pub fn token(key: u64) -> u32 {
    let d = key_digest(key);
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// A key's initial data sequence number (RFC 8684 section 3.1): the least
/// significant 64 bits of its SHA-256 hash. The SYN takes the first data
/// sequence number, so a host's first data byte is IDSN + 1.
///
/// ```
/// use fictionet::stdlib::protocols::mptcp::idsn;
/// assert_eq!(idsn(0xfedc_ba98_7654_3210).to_bits(), 0x2808_18bf_0fa7_e28e);
/// ```
pub fn idsn(key: u64) -> DataSequence {
    let d = key_digest(key);
    let mut low = [0; 8];
    low.copy_from_slice(&d[24..]);
    DataSequence::new(u64::from_be_bytes(low))
}

/// The HMAC-SHA256 a host sends in MP_JOIN (RFC 8684 section 3.2): keyed
/// with its own key then its peer's, over its own random number then its
/// peer's. [`Join::SynAck`] carries the leftmost 8 bytes and [`Join::Ack`]
/// the leftmost 20.
///
/// ```
/// use fictionet::stdlib::protocols::mptcp::join_hmac;
/// // The listener B answers a join from A: HMAC-B uses Key-B + Key-A
/// // and R-B + R-A.
/// let (key_a, key_b) = (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
/// let hmac_b = join_hmac(key_b, key_a, 0xaabb_ccdd, 0x1122_3344);
/// assert_eq!(hmac_b[..8], [0x3b, 0xae, 0x5a, 0xbc, 0x81, 0x0a, 0x33, 0xc2]);
/// ```
pub fn join_hmac(own_key: u64, peer_key: u64, own_random: u32, peer_random: u32) -> [u8; 32] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&own_key.to_be_bytes());
    key[8..].copy_from_slice(&peer_key.to_be_bytes());
    let mut message = [0; 8];
    message[..4].copy_from_slice(&own_random.to_be_bytes());
    message[4..].copy_from_slice(&peer_random.to_be_bytes());
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
        &message,
    );
    let mut out = [0; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// The DSS checksum of a mapping (RFC 8684 section 3.3.1): the Internet
/// checksum of a pseudo-header, which holds the full 64-bit data sequence
/// number, the relative subflow sequence number, the Data-Level Length and
/// two zero bytes, followed by the bytes the mapping covers. A DATA_FIN
/// with no data covers no bytes.
///
/// ```
/// use fictionet::stdlib::protocols::mptcp::{DataSequence, dss_checksum};
/// let sum = dss_checksum(DataSequence::new(0x0102_0304_0506_0708), 1, 2, b"hi");
/// assert_eq!(sum, 0x877f);
/// ```
pub fn dss_checksum(
    data_sequence_number: DataSequence,
    subflow_sequence_number: u32,
    data_level_length: u16,
    data: &[u8],
) -> u16 {
    use fictionet::stdlib::network::ip;
    let mut header = [0; 16];
    header[..8].copy_from_slice(&data_sequence_number.to_bits().to_be_bytes());
    header[8..12].copy_from_slice(&subflow_sequence_number.to_be_bytes());
    header[12..14].copy_from_slice(&data_level_length.to_be_bytes());
    ip::fold(ip::sum(ip::sum(0, &header), data))
}

/// Width used for outgoing data acknowledgments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AckWidth {
    /// Use the full data sequence number.
    #[default]
    Full,
    /// Match the width of the latest peer mapping.
    MatchMapping,
}

/// The data level of a Multipath TCP connection with one subflow, at one
/// end, with no I/O (RFC 8684 section 3.3): the DSS each segment this end
/// sends carries, and whether the connection has fallen back to plain TCP
/// (section 3.7).
///
/// This end's bytes go in data sequence order as they go on the subflow:
/// its first byte is its IDSN + 1, and DATA_FIN comes with its FIN. Each
/// segment it sends maps its own bytes with a 64-bit data sequence number,
/// and acknowledges what the peer has sent so far. Data ACKs use 64 bits
/// by default; [`DataLevel::ack_width`] selects another policy.
///
/// The peer's data must come under a mapping: a DSS, or an MP_CAPABLE
/// with data, which maps the peer's first bytes from subflow sequence
/// number 1 (section 3.1). When data the peer sends is outside every
/// mapping it sent, or the peer sends an infinite mapping, the connection
/// falls back only if no data is buffered and no DATA_FIN has been accepted.
/// Otherwise it fails. Both terminal states release the MPTCP queues; a
/// failed connection retains only its error and frozen data acknowledgment.
///
/// The peer's DATA_FIN takes the last data sequence number of its mapping
/// (section 3.3.3), and the Data ACK covers it once every byte before it
/// has come. It may come on a segment with no data and no FIN, as permitted by section 3.3.3, and such a segment is
/// acknowledged at once. The peer's FIN closes only the subflow, and takes
/// no data sequence number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataLevel {
    state: DataState,
    checksums: bool,
    ack_width: AckWidth,
}

/// Only the receiving state owns queues and a sender. Failure retains its
/// error and frozen acknowledgment, with no ability to map or deliver data.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DataState {
    Receiving { receive: Receiver, send: Sender },
    FallenBack,
    Failed { error: DataError, ack: Sequence },
}

/// Why the data level must close its subflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataError {
    /// The mapping does not match the negotiated checksum mode.
    ChecksumMode,
    /// A mapping checksum is invalid.
    Checksum,
    /// Conflicting mappings, ambiguous sequence order, or exhausted receive space.
    Mapping,
}

#[derive(Clone, Copy, Debug)]
enum Transition {
    /// The first byte of this call that belongs to plain TCP.
    Plain(usize),
    Failed(DataError),
}

impl From<DataError> for Transition {
    fn from(error: DataError) -> Self {
        Self::Failed(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Sender {
    initial: DataSequence,
    state: SendState,
    iss: TcpSeqNumber,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendState {
    Open { next: DataSequence },
    Finished { fin: DataSequence },
}

impl SendState {
    fn next(self) -> DataSequence {
        match self {
            Self::Open { next } => next,
            Self::Finished { fin } => fin.advance(1),
        }
    }
}

impl Sender {
    fn mapping(
        &mut self,
        seq: TcpSeqNumber,
        payload: &[u8],
        fin: bool,
        checksums: bool,
    ) -> Result<Option<Mapping>, DataError> {
        let Some(length) = payload
            .len()
            .checked_add(usize::from(fin))
            .and_then(|n| u16::try_from(n).ok())
        else {
            return Ok(None);
        };
        if length == 0 {
            return Ok(None);
        }
        let offset = seq.relative_to(self.iss);
        let low = self.initial.advance(u64::from(offset)).short();
        let start = self.state.next().expand(Sequence::Short(low));
        let range = DataRange {
            start,
            bytes: length - u16::from(fin),
            fin,
        };
        match self.state {
            SendState::Finished { fin } => range.within(fin)?,
            SendState::Open { next } => {
                if fin {
                    if !next.at_or_before(range.end()) {
                        return Err(DataError::Mapping);
                    }
                    self.state = SendState::Finished { fin: range.end() };
                } else if next.at_or_before(range.end()) {
                    self.state = SendState::Open { next: range.end() };
                }
            }
        }
        let subflow_sequence_number = if payload.is_empty() { 0 } else { offset };
        Ok(Some(Mapping {
            data_sequence_number: Sequence::Long(start),
            subflow_sequence_number,
            data_level_length: length,
            checksum: checksums
                .then(|| dss_checksum(start, subflow_sequence_number, length, payload)),
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DataRange {
    start: DataSequence,
    bytes: u16,
    fin: bool,
}

impl DataRange {
    fn end(self) -> DataSequence {
        self.start.advance(u64::from(self.bytes))
    }

    /// Both directions use this rule for a stream whose FIN is fixed.
    fn within(self, fin: DataSequence) -> Result<(), DataError> {
        let available = fin.offset_from(self.start).ok_or(DataError::Mapping)?;
        let bytes = i64::from(self.bytes);
        if bytes <= available && (!self.fin || bytes == available) {
            Ok(())
        } else {
            Err(DataError::Mapping)
        }
    }
}

/// Admission owns the fixed FIN and every data-level byte. Pending mappings
/// and completed mappings pass through the same boundary rule, since a FIN
/// can arrive between the announcement of a mapping and its completion.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DataStream {
    next: DataSequence,
    fin: Option<DataSequence>,
    ready: Vec<(DataSequence, Vec<u8>)>,
}

impl DataStream {
    fn admit(&mut self, range: DataRange, data: Option<Vec<u8>>) -> Result<(), DataError> {
        let end = range.end();
        let skip = self
            .next
            .offset_from(range.start)
            .ok_or(DataError::Mapping)?;
        if let Some(fin) = self.fin {
            range.within(fin)?;
        }
        if range.fin
            && (!self.next.at_or_before(end)
                || self.ready.iter().any(|(start, bytes)| {
                    DataRange {
                        start: *start,
                        bytes: bytes.len() as u16,
                        fin: false,
                    }
                    .within(end)
                    .is_err()
                }))
        {
            return Err(DataError::Mapping);
        }
        if let Some(data) = data {
            if range.fin {
                self.fin = Some(end);
            }
            // Reinjection cannot deliver already acknowledged bytes again.
            if !data.is_empty() && skip < i64::from(range.bytes) {
                let skip = skip.max(0) as usize;
                self.ready
                    .push((range.start.advance(skip as u64), data[skip..].to_vec()));
            }
        }
        Ok(())
    }

    fn deliver(&mut self, out: &mut Vec<u8>) {
        while let Some((index, skip)) =
            self.ready
                .iter()
                .enumerate()
                .find_map(|(index, (start, bytes))| {
                    let skip = usize::try_from(self.next.offset_from(*start)?).ok()?;
                    (skip < bytes.len()).then_some((index, skip))
                })
        {
            let (_, bytes) = self.ready.remove(index);
            out.extend_from_slice(&bytes[skip..]);
            self.next = self.next.advance((bytes.len() - skip) as u64);
        }
        self.ready.retain(|(start, bytes)| {
            self.next
                .offset_from(*start)
                .is_none_or(|skip| skip < bytes.len() as i64)
        });
    }

    fn ack(&self) -> DataSequence {
        self.next.advance(u64::from(self.fin == Some(self.next)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Receiver {
    initial: DataSequence,
    irs: TcpSeqNumber,
    long_ack: bool,
    mapped_until: TcpSeqNumber,
    mappings: Vec<ReceivedMapping>,
    stream: DataStream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceivedMapping {
    /// The handshake's MP_CAPABLE mapping takes its original option once.
    seeded: bool,
    start: TcpSeqNumber,
    range: DataRange,
    mapping: Mapping,
    data: Vec<u8>,
}

impl Receiver {
    fn ack(&self, width: AckWidth) -> Sequence {
        let next = self.stream.ack();
        if width == AckWidth::Full || self.long_ack {
            Sequence::Long(next)
        } else {
            Sequence::Short(next.short())
        }
    }

    fn fallback(&self, offset: usize) -> Transition {
        if self.stream.fin.is_some()
            || !self.stream.ready.is_empty()
            || self.mappings.iter().any(|m| !m.data.is_empty())
        {
            Transition::Failed(DataError::Mapping)
        } else {
            Transition::Plain(offset)
        }
    }

    fn received(
        &mut self,
        seq: TcpSeqNumber,
        payload: usize,
        checksums: bool,
        options: impl IntoIterator<Item = MptcpOption>,
    ) -> Result<bool, Transition> {
        if payload > i32::MAX as usize {
            return Err(DataError::Mapping.into());
        }
        let mut answer = false;
        for option in options {
            let (mapping, fin) = match option {
                MptcpOption::Dss(Dss {
                    mapping: Some(mapping),
                    data_fin,
                    ..
                }) => (mapping, data_fin),
                MptcpOption::Capable(Capable {
                    keys:
                        Keys::Data {
                            data_level_length,
                            checksum,
                            ..
                        },
                    ..
                }) => (
                    Mapping {
                        data_sequence_number: Sequence::Long(self.initial.advance(1)),
                        subflow_sequence_number: 1,
                        data_level_length,
                        checksum,
                    },
                    false,
                ),
                _ => continue,
            };
            let length = mapping.data_level_length;
            if length == 0 {
                return Err(self.fallback(0));
            }
            if mapping.checksum.is_some() != checksums {
                return Err(DataError::ChecksumMode.into());
            }
            self.long_ack = matches!(mapping.data_sequence_number, Sequence::Long(_));
            let range = DataRange {
                start: self.stream.next.expand(mapping.data_sequence_number),
                bytes: length - u16::from(fin),
                fin,
            };
            let start = self.irs.at_offset(mapping.subflow_sequence_number);
            if range.bytes == 0 {
                if mapping.checksum.is_some_and(|sum| {
                    sum != dss_checksum(range.start, mapping.subflow_sequence_number, length, &[])
                }) {
                    return Err(DataError::Checksum.into());
                }
                self.stream.admit(range, Some(Vec::new()))?;
            } else {
                self.stream.admit(range, None)?;
                let end = start + usize::from(range.bytes);
                if end > self.mapped_until {
                    self.mapped_until = end;
                }
                if let Some(existing) = self.mappings.iter_mut().find(|m| m.start == start) {
                    if existing.seeded {
                        existing.seeded = false;
                        existing.mapping = mapping;
                        existing.range = range;
                    } else if existing.range != range
                        || existing.mapping.checksum != mapping.checksum
                    {
                        return Err(DataError::Mapping.into());
                    }
                } else if self.mappings.iter().any(|m| {
                    start.relative_to(m.start) < u32::from(m.range.bytes)
                        || m.start.relative_to(start) < u32::from(range.bytes)
                }) || self.mappings.len() >= 256
                {
                    return Err(DataError::Mapping.into());
                } else {
                    self.mappings.push(ReceivedMapping {
                        seeded: false,
                        start,
                        range,
                        mapping,
                        data: Vec::new(),
                    });
                }
            }
            answer |= fin;
        }
        if payload > 0 && seq + payload > self.mapped_until {
            return Err(self.fallback(0));
        }
        Ok(answer)
    }

    fn arrived(
        &mut self,
        seq: TcpSeqNumber,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Transition> {
        if data.len() > i32::MAX as usize {
            return Err(DataError::Mapping.into());
        }
        let mut offset = 0;
        while offset < data.len() {
            let at = seq + offset;
            let index = self
                .mappings
                .iter()
                .position(|m| at.relative_to(m.start) < u32::from(m.range.bytes))
                .ok_or_else(|| self.fallback(offset))?;
            let m = &mut self.mappings[index];
            let inside = at.relative_to(m.start) as usize;
            if inside != m.data.len() {
                return Err(DataError::Mapping.into());
            }
            let count = (usize::from(m.range.bytes) - inside).min(data.len() - offset);
            m.data.extend_from_slice(&data[offset..offset + count]);
            offset += count;
            if m.data.len() == usize::from(m.range.bytes) {
                let m = self.mappings.remove(index);
                if m.mapping.checksum.is_some_and(|sum| {
                    sum != dss_checksum(
                        m.range.start,
                        m.mapping.subflow_sequence_number,
                        m.mapping.data_level_length,
                        &m.data,
                    )
                }) {
                    return Err(DataError::Checksum.into());
                }
                self.stream.admit(m.range, Some(m.data))?;
            }
        }
        self.stream.deliver(out);
        let buffered = self.mappings.iter().map(|m| m.data.len()).sum::<usize>()
            + self
                .stream
                .ready
                .iter()
                .map(|(_, data)| data.len())
                .sum::<usize>();
        if buffered > 65_535 {
            return Err(DataError::Mapping.into());
        }
        Ok(())
    }
}

impl DataLevel {
    /// The most option bytes a DSS uses with a full ACK, full mapping and checksum.
    pub const ROOM: usize = 28;

    /// A single-subflow connection negotiated with these keys and initial TCP
    /// sequence numbers. `first` is the MP_CAPABLE third ACK's data length.
    pub fn new(
        local_key: u64,
        remote_key: u64,
        iss: u32,
        irs: u32,
        checksums: bool,
        first: Option<u16>,
    ) -> Self {
        let local = idsn(local_key);
        let remote = idsn(remote_key);
        let irs = TcpSeqNumber::new(irs);
        Self {
            checksums,
            ack_width: AckWidth::default(),
            state: DataState::Receiving {
                send: Sender {
                    initial: local,
                    state: SendState::Open {
                        next: local.advance(1),
                    },
                    iss: TcpSeqNumber::new(iss),
                },
                receive: Receiver {
                    initial: remote,
                    irs,
                    long_ack: first.is_some(),
                    mapped_until: irs + 1 + usize::from(first.unwrap_or(0)),
                    mappings: first
                        .into_iter()
                        .filter(|n| *n > 0)
                        .map(|length| ReceivedMapping {
                            seeded: true,
                            start: irs + 1,
                            range: DataRange {
                                start: remote.advance(1),
                                bytes: length,
                                fin: false,
                            },
                            mapping: Mapping {
                                data_sequence_number: Sequence::Long(remote.advance(1)),
                                subflow_sequence_number: 1,
                                data_level_length: length,
                                checksum: None,
                            },
                            data: Vec::new(),
                        })
                        .collect(),
                    stream: DataStream {
                        next: remote.advance(1),
                        fin: None,
                        ready: Vec::new(),
                    },
                },
            },
        }
    }

    /// Selects the width of outgoing Data ACKs.
    pub fn ack_width(mut self, width: AckWidth) -> Self {
        self.ack_width = width;
        self
    }

    /// Whether the connection has fallen back to plain TCP.
    pub fn fallen_back(&self) -> bool {
        matches!(self.state, DataState::FallenBack)
    }

    /// The error that requires a subflow reset, if any.
    pub fn error(&self) -> Option<DataError> {
        match self.state {
            DataState::Failed { error, .. } => Some(error),
            _ => None,
        }
    }

    /// The only lifecycle transition point. Terminal states never invoke the
    /// operation, and relinquish all mappings and send state.
    fn update<T>(
        &mut self,
        operation: impl FnOnce(&mut Receiver, &mut Sender) -> Result<T, Transition>,
    ) -> Result<T, Transition> {
        let (receive, send) = match &mut self.state {
            DataState::Receiving { receive, send } => (receive, send),
            DataState::FallenBack => return Err(Transition::Plain(0)),
            DataState::Failed { error, .. } => return Err(Transition::Failed(*error)),
        };
        let result = operation(receive, send);
        if let Err(exit) = result {
            self.state = match exit {
                Transition::Plain(_) => DataState::FallenBack,
                Transition::Failed(error) => DataState::Failed {
                    error,
                    ack: receive.ack(self.ack_width),
                },
            };
        }
        result
    }

    /// Takes an in-window segment's mapping options. A DATA_FIN asks for an
    /// immediate ACK. A subflow FIN alone does not close the data stream.
    pub fn received(
        &mut self,
        seq: u32,
        payload: usize,
        options: impl IntoIterator<Item = MptcpOption>,
    ) -> bool {
        let checksums = self.checksums;
        self.update(|receive, _| {
            receive.received(TcpSeqNumber::new(seq), payload, checksums, options)
        })
        .unwrap_or(false)
    }

    /// Takes contiguous subflow bytes and appends completed data in data order.
    /// On failure this call appends nothing. At most one TCP window is buffered.
    pub fn arrived(&mut self, seq: u32, data: &[u8], out: &mut Vec<u8>) {
        let before = out.len();
        match self.update(|receive, _| receive.arrived(TcpSeqNumber::new(seq), data, out)) {
            Ok(()) => (),
            Err(Transition::Plain(offset)) => out.extend_from_slice(&data[offset..]),
            Err(Transition::Failed(_)) => out.truncate(before),
        }
    }

    /// The outgoing DSS, or none in plain TCP. Failed connections can repeat
    /// only their frozen data ACK; they cannot create new mappings.
    pub fn sent(&mut self, seq: u32, payload: &[u8], fin: bool, acknowledge: bool) -> Option<Dss> {
        if let DataState::Failed { ack, .. } = self.state {
            return acknowledge.then_some(Dss {
                data_ack: Some(ack),
                mapping: None,
                data_fin: false,
            });
        }
        let (checksums, width) = (self.checksums, self.ack_width);
        self.update(|receive, send| {
            let mapping = send.mapping(TcpSeqNumber::new(seq), payload, fin, checksums)?;
            if (!payload.is_empty() || fin) && mapping.is_none() {
                return Ok(None);
            }
            let data_ack = acknowledge.then(|| receive.ack(width));
            Ok((mapping.is_some() || data_ack.is_some()).then_some(Dss {
                data_ack,
                mapping,
                data_fin: fin,
            }))
        })
        .ok()
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::test_support::{contract, rounds};

    // Keys and random numbers for hosts A (the initiator) and B (the
    // listener). The tokens, IDSNs and HMACs below were computed from
    // them with Python's hashlib and hmac, not with this module.
    const KEY_A: u64 = 0x0123_4567_89ab_cdef;
    const KEY_B: u64 = 0xfedc_ba98_7654_3210;
    const R_A: u32 = 0x1122_3344;
    const R_B: u32 = 0xaabb_ccdd;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Checks a whole option as the RFC's figures draw it, Kind and
    /// Length first: the Length matches, the data reads as `value`, and
    /// `value` writes the same data back, with no prefix or longer input
    /// read as the same value.
    fn figure(option: &[u8], value: &MptcpOption) {
        assert_eq!(option[0], KIND);
        assert_eq!(usize::from(option[1]), option.len());
        assert_eq!(MptcpOption::parse(&option[2..]).as_ref(), Ok(value));
        assert_eq!(contract::check_written(value), option[2..]);
        for cut in 2..option.len() {
            assert_ne!(MptcpOption::parse(&option[2..cut]).as_ref(), Ok(value));
        }
        let mut longer = option[2..].to_vec();
        longer.push(0);
        assert_ne!(MptcpOption::parse(&longer).as_ref(), Ok(value));
    }

    fn capable(version: u8, flags: u8, keys: Keys) -> MptcpOption {
        MptcpOption::Capable(Capable {
            version,
            checksum_required: flags & 0x80 != 0,
            extensibility: flags & 0x40 != 0,
            no_new_subflows: flags & 0x20 != 0,
            algorithms: flags & 0x1f,
            keys,
        })
    }

    #[test]
    fn figure_4_mp_capable_in_each_packet() {
        // SYN: only the first 4 octets, version 1, A and H.
        figure(&[30, 4, 0x01, 0x81], &capable(1, 0x81, Keys::Absent));
        // SYN/ACK: B's key.
        let mut syn_ack = vec![30, 12, 0x01, 0x81];
        syn_ack.extend_from_slice(&KEY_B.to_be_bytes());
        figure(&syn_ack, &capable(1, 0x81, Keys::Sender(KEY_B)));
        // ACK: A's key, then B's.
        let mut ack = vec![30, 20, 0x01, 0x81];
        ack.extend_from_slice(&KEY_A.to_be_bytes());
        ack.extend_from_slice(&KEY_B.to_be_bytes());
        let both = Keys::Both {
            sender: KEY_A,
            receiver: KEY_B,
        };
        figure(&ack, &capable(1, 0x81, both));
        // ACK with first data: the Data-Level Length, then the checksum
        // when checksums are in use.
        let mut data = ack.clone();
        data[1] = 22;
        data.extend_from_slice(&[0x01, 0x2c]);
        let with_data = |checksum| Keys::Data {
            sender: KEY_A,
            receiver: KEY_B,
            data_level_length: 300,
            checksum,
        };
        figure(&data, &capable(1, 0x81, with_data(None)));
        data[1] = 24;
        data.extend_from_slice(&[0xbe, 0xef]);
        figure(&data, &capable(1, 0x81, with_data(Some(0xbeef))));
    }

    #[test]
    fn mp_capable_keeps_every_flag_and_version() {
        // B, C and every algorithm bit, A clear: all kept, as given.
        figure(&[30, 4, 0x01, 0x7f], &capable(1, 0x7f, Keys::Absent));
        // A version above 1, which a listener must read to answer with
        // its own.
        figure(&[30, 4, 0x0f, 0x01], &capable(15, 0x01, Keys::Absent));
        // Bits D to H all clear name no algorithm.
        assert_eq!(MptcpOption::parse(&[0x01, 0xe0]), Err(Error::NoAlgorithm));
        let mut syn_ack = vec![0x01, 0x80];
        syn_ack.extend_from_slice(&KEY_B.to_be_bytes());
        assert_eq!(MptcpOption::parse(&syn_ack), Err(Error::NoAlgorithm));
    }

    #[test]
    fn mp_capable_version_0_has_keys_in_the_syn() {
        // RFC 6824: the SYN and the SYN/ACK carry the sender's key, and
        // the ACK both keys.
        let mut syn = vec![30, 12, 0x00, 0x81];
        syn.extend_from_slice(&KEY_A.to_be_bytes());
        figure(&syn, &capable(0, 0x81, Keys::Sender(KEY_A)));
        let mut ack = vec![30, 20, 0x00, 0x01];
        ack.extend_from_slice(&KEY_A.to_be_bytes());
        ack.extend_from_slice(&KEY_B.to_be_bytes());
        let both = Keys::Both {
            sender: KEY_A,
            receiver: KEY_B,
        };
        figure(&ack, &capable(0, 0x01, both));
        // Version 0 has no 4-octet SYN and no data parameters.
        let bad = |length| Err(Error::Length { subtype: 0, length });
        assert_eq!(MptcpOption::parse(&[0x00, 0x81]), bad(4));
        let mut data = ack[2..].to_vec();
        data.extend_from_slice(&[0, 1]);
        assert_eq!(MptcpOption::parse(&data), bad(22));
        data.extend_from_slice(&[0, 1]);
        assert_eq!(MptcpOption::parse(&data), bad(24));
        assert_eq!(
            contract::check_refused(&capable(0, 0x81, Keys::Absent)),
            Error::Unwritable
        );
        let data = Keys::Data {
            sender: 1,
            receiver: 2,
            data_level_length: 3,
            checksum: None,
        };
        assert_eq!(
            contract::check_refused(&capable(0, 0x81, data)),
            Error::Unwritable
        );
    }

    #[test]
    fn token_and_idsn_hash_the_key() {
        // Section 3.1: the most significant 32 bits and the least
        // significant 64 bits of SHA-256 over the key in network order.
        assert_eq!(token(KEY_A), 0x55c5_3f5d);
        assert_eq!(idsn(KEY_A).to_bits(), 0x5707_62cd_38be_9818);
        assert_eq!(token(KEY_B), 0x18f9_781b);
        assert_eq!(idsn(KEY_B).to_bits(), 0x2808_18bf_0fa7_e28e);
    }

    #[test]
    fn figure_8_join_handshake() {
        // SYN + MP_JOIN(Token-B, R-A), from A's second address, ID 1.
        let syn = Join::Syn {
            backup: false,
            address_id: 1,
            token: token(KEY_B),
            random: R_A,
        };
        figure(
            &[
                30, 12, 0x10, 1, 0x18, 0xf9, 0x78, 0x1b, 0x11, 0x22, 0x33, 0x44,
            ],
            &MptcpOption::Join(syn),
        );

        // SYN/ACK + MP_JOIN(HMAC-B, R-B): HMAC-B is keyed with Key-B then
        // Key-A, over R-B then R-A, and truncated to its leftmost 64 bits.
        let hmac_b = join_hmac(KEY_B, KEY_A, R_B, R_A);
        assert_eq!(
            hmac_b.to_vec(),
            hex("3bae5abc810a33c2e293af8b4572e4827e89510eea113d42098dff12ea4fad3f")
        );
        let mut truncated = [0; 8];
        truncated.copy_from_slice(&hmac_b[..8]);
        let syn_ack = Join::SynAck {
            backup: true,
            address_id: 0,
            hmac: truncated,
            random: R_B,
        };
        let mut option = vec![30, 16, 0x11, 0];
        option.extend_from_slice(&hmac_b[..8]);
        option.extend_from_slice(&R_B.to_be_bytes());
        figure(&option, &MptcpOption::Join(syn_ack));

        // ACK + MP_JOIN(HMAC-A): the leftmost 160 bits.
        let hmac_a = join_hmac(KEY_A, KEY_B, R_A, R_B);
        assert_eq!(
            hmac_a.to_vec(),
            hex("f61753d6b8ac227764b9d1b17a6f5ceeec9d1a8a4351afe5408a31e58cbbe7ba")
        );
        let mut truncated = [0; 20];
        truncated.copy_from_slice(&hmac_a[..20]);
        let mut option = vec![30, 24, 0x10, 0];
        option.extend_from_slice(&hmac_a[..20]);
        figure(&option, &MptcpOption::Join(Join::Ack { hmac: truncated }));
    }

    #[test]
    fn figure_9_dss_with_every_field() {
        // A, a, M, m and F: an 8-octet Data ACK and DSN, the subflow
        // sequence number, the Data-Level Length and a checksum. 28
        // octets, the most a DSS can be.
        let mut option = vec![30, 28, 0x20, 0x1f];
        option.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        option.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());
        option.extend_from_slice(&[0, 0, 0, 1, 0x05, 0xa0, 0xab, 0xcd]);
        let dss = Dss {
            data_ack: Some(Sequence::Long(DataSequence::new(0x0102_0304_0506_0708))),
            mapping: Some(Mapping {
                data_sequence_number: Sequence::Long(DataSequence::new(0x1112_1314_1516_1718)),
                subflow_sequence_number: 1,
                data_level_length: 1440,
                checksum: Some(0xabcd),
            }),
            data_fin: true,
        };
        figure(&option, &MptcpOption::Dss(dss));
        // A 4-octet Data ACK alone: Length 8.
        let ack = Dss {
            data_ack: Some(Sequence::Short(7)),
            ..Dss::default()
        };
        figure(&[30, 8, 0x20, 0x01, 0, 0, 0, 7], &MptcpOption::Dss(ack));
        // A DATA_FIN with neither: Length 4.
        let fin = Dss {
            data_fin: true,
            ..Dss::default()
        };
        figure(&[30, 4, 0x20, 0x10], &MptcpOption::Dss(fin));
    }

    #[test]
    fn dss_lengths_follow_the_flags() {
        let sequences = [
            None,
            Some(Sequence::Short(9)),
            Some(Sequence::Long(DataSequence::new(9))),
        ];
        for data_ack in sequences {
            for dsn in sequences {
                for checksum in [None, Some(0x1234)] {
                    for data_fin in [false, true] {
                        let mapping = dsn.map(|data_sequence_number| Mapping {
                            data_sequence_number,
                            subflow_sequence_number: 3,
                            data_level_length: 4,
                            checksum,
                        });
                        let dss = MptcpOption::Dss(Dss {
                            data_ack,
                            mapping,
                            data_fin,
                        });
                        let size = |s: Option<Sequence>| match s {
                            None => 0,
                            Some(Sequence::Short(_)) => 4,
                            Some(Sequence::Long(_)) => 8,
                        };
                        let mut length = 4 + size(data_ack);
                        if let Some(m) = mapping {
                            length += size(Some(m.data_sequence_number)) + 6;
                            length += if m.checksum.is_some() { 2 } else { 0 };
                        }
                        let bytes = contract::check_written(&dss);
                        assert_eq!(bytes.len() + 2, length, "{dss:?}");
                        assert!(length <= 28);
                    }
                }
            }
        }
        // a and m mean nothing without A and M: ignored, written as 0.
        assert_eq!(
            MptcpOption::parse(&[0x20, 0x0a]),
            Ok(MptcpOption::Dss(Dss::default()))
        );
        assert_eq!(
            MptcpOption::Dss(Dss::default()).to_bytes(),
            Ok(vec![0x20, 0])
        );
        // A set but no Data ACK, and M set with the mapping cut short.
        let bad = |length| Err(Error::Length { subtype: 2, length });
        assert_eq!(MptcpOption::parse(&[0x20, 0x01]), bad(4));
        assert_eq!(MptcpOption::parse(&[0x20, 0x04, 0, 0, 0, 1]), bad(8));
        assert_eq!(
            MptcpOption::parse(&[0x20, 0x04, 0, 0, 0, 1, 0, 0, 0, 1, 0]),
            bad(13)
        );
    }

    #[test]
    fn figure_12_add_addr_in_each_length() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7));
        let hmac = [1, 2, 3, 4, 5, 6, 7, 8];
        let cases = [
            (v4, None, None, 8),
            (v4, Some(8080), None, 10),
            (v4, None, Some(hmac), 16),
            (v4, Some(8080), Some(hmac), 18),
            (v6, None, None, 20),
            (v6, Some(8080), None, 22),
            (v6, None, Some(hmac), 28),
            (v6, Some(8080), Some(hmac), 30),
        ];
        for (address, port, hmac, length) in cases {
            let value = MptcpOption::AddAddr(AddAddr {
                address_id: 5,
                address,
                port,
                hmac,
            });
            let mut option = vec![30, length, 0x30 | u8::from(hmac.is_none()), 5];
            match address {
                IpAddr::V4(a) => option.extend_from_slice(&a.octets()),
                IpAddr::V6(a) => option.extend_from_slice(&a.octets()),
            }
            if let Some(p) = port {
                option.extend_from_slice(&p.to_be_bytes());
            }
            if let Some(h) = hmac {
                option.extend_from_slice(&h);
            }
            figure(&option, &value);
            // The same bytes with the E flag turned over: an echo with
            // HMAC-sized room, or an HMAC that is missing. No length
            // means both.
            option[2] ^= 0x01;
            assert_eq!(
                MptcpOption::parse(&option[2..]),
                Err(Error::Length {
                    subtype: 3,
                    length: usize::from(length)
                })
            );
        }
    }

    #[test]
    fn figures_11_and_13_to_16() {
        figure(&[30, 3, 0x51], &MptcpOption::Prio { backup: true });
        figure(&[30, 3, 0x50], &MptcpOption::Prio { backup: false });
        figure(
            &[30, 4, 0x40, 9],
            &MptcpOption::RemoveAddr {
                address_ids: vec![9],
            },
        );
        figure(
            &[30, 6, 0x40, 1, 2, 3],
            &MptcpOption::RemoveAddr {
                address_ids: vec![1, 2, 3],
            },
        );
        let mut option = vec![30, 12, 0x70, 0];
        option.extend_from_slice(&KEY_B.to_be_bytes());
        figure(
            &option,
            &MptcpOption::FastClose {
                receiver_key: KEY_B,
            },
        );
        let mut option = vec![30, 12, 0x60, 0];
        option.extend_from_slice(&u64::MAX.to_be_bytes());
        figure(
            &option,
            &MptcpOption::Fail {
                data_sequence_number: DataSequence::new(u64::MAX),
            },
        );
        figure(
            &[30, 4, 0x81, reason::ADMINISTRATIVELY_PROHIBITED],
            &MptcpOption::TcpRst {
                transient: true,
                reason: reason::ADMINISTRATIVELY_PROHIBITED,
            },
        );
        // A reason code RFC 8684 does not define is kept.
        figure(
            &[30, 4, 0x80, 0x77],
            &MptcpOption::TcpRst {
                transient: false,
                reason: 0x77,
            },
        );
    }

    #[test]
    fn reserved_bits_are_ignored_and_written_as_zero() {
        let cases: [(&[u8], &[u8]); 7] = [
            // MP_JOIN SYN: the 3 bits before B.
            (
                &[0x1f, 1, 0, 0, 0, 2, 0, 0, 0, 3],
                &[0x11, 1, 0, 0, 0, 2, 0, 0, 0, 3],
            ),
            // DSS: the 4 bits after the subtype and the 3 before F.
            (&[0x2f, 0xe0], &[0x20, 0]),
            // ADD_ADDR: the 3 bits before E.
            (&[0x3f, 0, 1, 2, 3, 4], &[0x31, 0, 1, 2, 3, 4]),
            // REMOVE_ADDR, MP_PRIO and MP_TCPRST (U, V and W).
            (&[0x4f, 7], &[0x40, 7]),
            (&[0x5e], &[0x50]),
            (&[0x8e, 2], &[0x80, 2]),
            // MP_FASTCLOSE: 12 reserved bits.
            (
                &[0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0, 1],
                &[0x70, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
        ];
        for (sent, written) in cases {
            let value = MptcpOption::parse(sent).unwrap();
            assert_eq!(value.to_bytes().unwrap(), written, "{sent:02x?}");
            assert_eq!(MptcpOption::parse(written), Ok(value));
        }
        // The MP_JOIN ACK's 12 reserved bits.
        let mut sent = vec![0x1f, 0xff];
        sent.extend_from_slice(&[0xaa; 20]);
        let value = MptcpOption::parse(&sent).unwrap();
        assert_eq!(value, MptcpOption::Join(Join::Ack { hmac: [0xaa; 20] }));
        assert_eq!(value.to_bytes().unwrap()[..2], [0x10, 0]);
    }

    /// The option Lengths RFC 8684 defines for each subtype, with any
    /// flags and version.
    fn defined(sub: u8) -> Vec<usize> {
        match sub {
            subtype::MP_CAPABLE => vec![4, 12, 20, 22, 24],
            subtype::MP_JOIN => vec![12, 16, 24],
            subtype::DSS => vec![4, 8, 12, 14, 16, 18, 20, 22, 24, 26, 28],
            subtype::ADD_ADDR => vec![8, 10, 16, 18, 20, 22, 28, 30],
            subtype::REMOVE_ADDR => (4..=MAX_LEN).collect(),
            subtype::MP_PRIO => vec![3],
            subtype::MP_FAIL | subtype::MP_FASTCLOSE => vec![12],
            subtype::MP_TCPRST => vec![4],
            _ => vec![],
        }
    }

    #[test]
    fn every_length_of_every_subtype() {
        let mut rng = Lcg::new(0x8684);
        for sub in 0..16u8 {
            let lengths = defined(sub);
            for length in 3..=MAX_LEN {
                // Each defined Length reads with some flags; each other
                // Length reads with none.
                let mut read = false;
                for low in 0..16u8 {
                    for second in 0..=255u8 {
                        let mut data = vec![0; length - 2];
                        rng.fill(&mut data);
                        data[0] = sub << 4 | low;
                        if let Some(b) = data.get_mut(1) {
                            *b = second;
                        }
                        match MptcpOption::parse(&data) {
                            Ok(value) => {
                                assert!(lengths.contains(&length), "{data:02x?}");
                                assert_eq!(value.subtype(), sub);
                                read = true;
                            }
                            Err(Error::Length { subtype, length: l }) => {
                                assert_eq!((subtype, l), (sub, length));
                            }
                            Err(Error::Subtype(s)) => {
                                assert!(lengths.is_empty() && s == sub);
                            }
                            Err(Error::NoAlgorithm) => {
                                assert_eq!(sub, subtype::MP_CAPABLE);
                                assert_eq!(second & algorithm::ALL, 0);
                            }
                            Err(e) => panic!("{data:02x?}: {e}"),
                        }
                    }
                }
                assert_eq!(
                    read,
                    lengths.contains(&length),
                    "subtype {sub} length {length}"
                );
            }
        }
    }

    #[test]
    fn errors() {
        assert_eq!(MptcpOption::parse(&[]), Err(Error::NoSubtype));
        for sub in 0x9..=0xf {
            assert_eq!(MptcpOption::parse(&[sub << 4, 0]), Err(Error::Subtype(sub)));
        }
        // Longer than a TCP header holds, whatever the subtype.
        let mut long = vec![0x40; MAX_LEN - 2];
        assert!(MptcpOption::parse(&long).is_ok());
        long.push(1);
        assert_eq!(MptcpOption::parse(&long), Err(Error::TooLong(MAX_LEN + 1)));
        assert_eq!(MptcpOption::parse(&[0x00; 300]), Err(Error::TooLong(302)));
        for e in [
            Error::Unwritable,
            Error::NoSubtype,
            Error::TooLong(41),
            Error::Subtype(0xf),
            Error::Length {
                subtype: 1,
                length: 13,
            },
            Error::NoAlgorithm,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_refuse_what_would_not_read_back() {
        for (version, flags) in [(16, 0x81), (1, 0x80), (1, 0x00)] {
            assert_eq!(
                contract::check_refused(&capable(version, flags, Keys::Absent)),
                Error::Unwritable
            );
        }
        let wide = MptcpOption::Capable(Capable {
            algorithms: 0x21,
            ..match capable(1, 0x01, Keys::Absent) {
                MptcpOption::Capable(c) => c,
                _ => unreachable!(),
            }
        });
        assert_eq!(contract::check_refused(&wide), Error::Unwritable);
        let remove = |n| MptcpOption::RemoveAddr {
            address_ids: vec![1; n],
        };
        assert_eq!(contract::check_refused(&remove(0)), Error::Unwritable);
        assert_eq!(
            contract::check_refused(&remove(MAX_REMOVE_IDS + 1)),
            Error::Unwritable
        );
        assert_eq!(
            contract::check_written(&remove(MAX_REMOVE_IDS)).len() + 2,
            MAX_LEN
        );
    }

    /// A random option of any subtype, built rather than read.
    fn random_option(rng: &mut Lcg) -> MptcpOption {
        let r64 = |rng: &mut Lcg| rng.next();
        let seq = |rng: &mut Lcg| {
            if rng.coin() {
                Sequence::Short(rng.next() as u32)
            } else {
                Sequence::Long(DataSequence::new(rng.next()))
            }
        };
        let maybe16 = |rng: &mut Lcg| rng.coin().then(|| rng.next() as u16);
        match rng.index(9) {
            0 => MptcpOption::Capable(Capable {
                version: rng.index(17) as u8,
                checksum_required: rng.coin(),
                extensibility: rng.coin(),
                no_new_subflows: rng.coin(),
                algorithms: rng.index(0x22) as u8,
                keys: match rng.index(4) {
                    0 => Keys::Absent,
                    1 => Keys::Sender(r64(rng)),
                    2 => Keys::Both {
                        sender: r64(rng),
                        receiver: r64(rng),
                    },
                    _ => Keys::Data {
                        sender: r64(rng),
                        receiver: r64(rng),
                        data_level_length: rng.next() as u16,
                        checksum: maybe16(rng),
                    },
                },
            }),
            1 => MptcpOption::Join(match rng.index(3) {
                0 => Join::Syn {
                    backup: rng.coin(),
                    address_id: rng.next() as u8,
                    token: rng.next() as u32,
                    random: rng.next() as u32,
                },
                1 => Join::SynAck {
                    backup: rng.coin(),
                    address_id: rng.next() as u8,
                    hmac: (rng.next()).to_be_bytes(),
                    random: rng.next() as u32,
                },
                _ => {
                    let mut hmac = [0; 20];
                    rng.fill(&mut hmac);
                    Join::Ack { hmac }
                }
            }),
            2 => MptcpOption::Dss(Dss {
                data_ack: rng.coin().then(|| seq(rng)),
                mapping: rng.coin().then(|| Mapping {
                    data_sequence_number: seq(rng),
                    subflow_sequence_number: rng.next() as u32,
                    data_level_length: rng.next() as u16,
                    checksum: maybe16(rng),
                }),
                data_fin: rng.coin(),
            }),
            3 => MptcpOption::AddAddr(AddAddr {
                address_id: rng.next() as u8,
                address: if rng.coin() {
                    IpAddr::V4(Ipv4Addr::from(rng.next() as u32))
                } else {
                    IpAddr::V6(Ipv6Addr::from(
                        u128::from(rng.next()) << 64 | u128::from(rng.next()),
                    ))
                },
                port: maybe16(rng),
                hmac: rng.coin().then(|| rng.next().to_be_bytes()),
            }),
            4 => MptcpOption::RemoveAddr {
                address_ids: (0..rng.index(MAX_REMOVE_IDS + 2))
                    .map(|_| rng.next() as u8)
                    .collect(),
            },
            5 => MptcpOption::Prio { backup: rng.coin() },
            6 => MptcpOption::Fail {
                data_sequence_number: DataSequence::new(rng.next()),
            },
            7 => MptcpOption::FastClose {
                receiver_key: rng.next(),
            },
            _ => MptcpOption::TcpRst {
                transient: rng.coin(),
                reason: rng.next() as u8,
            },
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5eed_001e);
        let mut parsed = 0;
        for _ in 0..rounds(20_000) {
            // Random data up to a little past the longest option, often
            // with a defined subtype and a crypto bit set, so many reach
            // the layouts.
            let mut data = vec![0; rng.index(MAX_LEN + 2)];
            rng.fill(&mut data);
            if !data.is_empty() && rng.coin() {
                data[0] = (rng.index(9) as u8) << 4 | (data[0] & 0x0f);
                if let Some(b) = data.get_mut(1) {
                    *b |= 1;
                }
            }
            contract::check_wire::<MptcpOption>(&data);
            if let Ok(value) = MptcpOption::parse(&data) {
                parsed += 1;
                assert_eq!(value.to_bytes().unwrap().len(), data.len());
            }
            for n in 0..data.len() {
                contract::check_wire::<MptcpOption>(&data[..n]);
            }
        }
        assert!(parsed > 1000, "{parsed}");
        // Built options: a write keeps the whole value or refuses it.
        for _ in 0..rounds(20_000) {
            let value = random_option(&mut rng);
            contract::check_wire_value(&value);
            if let Ok(bytes) = value.to_bytes() {
                assert!(bytes.len() + 2 <= MAX_LEN);
                assert_eq!(bytes[0] >> 4, value.subtype());
            }
        }
    }

    /// The DSS checksum is the Internet checksum of the pseudo-header and
    /// the data, added up here word by word.
    #[test]
    fn dss_checksum_covers_the_pseudo_header_and_the_data() {
        let words = |bytes: &[u8]| -> u32 {
            bytes
                .chunks(2)
                .map(|w| u32::from(w[0]) << 8 | u32::from(*w.get(1).unwrap_or(&0)))
                .sum()
        };
        for (dsn, ssn, data) in [
            (0x0102_0304_0506_0708u64, 1u32, &b"hi"[..]),
            (u64::MAX, u32::MAX, &b"odd"[..]),
            (7, 0, &b""[..]),
        ] {
            let len = data.len() as u16 + u16::from(data.is_empty());
            let mut sum = words(&dsn.to_be_bytes()) + words(&ssn.to_be_bytes());
            sum += u32::from(len) + words(data);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            assert_eq!(
                dss_checksum(DataSequence::new(dsn), ssn, len, data),
                !(sum as u16)
            );
        }
    }

    const ISS: u32 = 0xffff_fff0;
    const IRS: u32 = 1000;

    fn mapping(dsn: Sequence, ssn: u32, len: u16) -> MptcpOption {
        MptcpOption::Dss(Dss {
            data_ack: None,
            mapping: Some(Mapping {
                data_sequence_number: dsn,
                subflow_sequence_number: ssn,
                data_level_length: len,
                checksum: None,
            }),
            data_fin: false,
        })
    }

    /// The listener's first bytes are IDSN + 1 on, mapped by the segment
    /// that carries them, with the peer's data acknowledged at its IDSN +
    /// 1 on, using the full sequence number.
    #[test]
    fn a_data_level_maps_what_it_sends_and_acknowledges_what_it_got() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let first = level.sent(ISS.wrapping_add(1), b"SSH-2.0", false, true);
        assert_eq!(
            first,
            Some(Dss {
                data_ack: Some(Sequence::Long(idsn(KEY_A).advance(1))),
                mapping: Some(Mapping {
                    data_sequence_number: Sequence::Long(idsn(KEY_B).advance(1)),
                    subflow_sequence_number: 1,
                    data_level_length: 7,
                    checksum: None,
                }),
                data_fin: false,
            })
        );
        let bytes = MptcpOption::Dss(first.unwrap()).to_bytes().unwrap();
        assert!(bytes.len() + 2 <= DataLevel::ROOM);
        // The peer maps 5 bytes with a 64-bit number: the ACK now has 8
        // octets, and covers them.
        let dsn = Sequence::Long(idsn(KEY_A).advance(1));
        level.received(IRS + 1, 5, [mapping(dsn, 1, 5)]);
        level.arrived(IRS + 1, b"hello", &mut Vec::new());
        assert_eq!(
            level.sent(ISS.wrapping_add(8), b"", false, true),
            Some(Dss {
                data_ack: Some(Sequence::Long(idsn(KEY_A).advance(6))),
                mapping: None,
                data_fin: false,
            })
        );
        // The FIN carries DATA_FIN, with no subflow bytes mapped.
        assert_eq!(
            level.sent(ISS.wrapping_add(8), b"", true, true),
            Some(Dss {
                data_ack: Some(Sequence::Long(idsn(KEY_A).advance(6))),
                mapping: Some(Mapping {
                    data_sequence_number: Sequence::Long(idsn(KEY_B).advance(8)),
                    subflow_sequence_number: 0,
                    data_level_length: 1,
                    checksum: None,
                }),
                data_fin: true,
            })
        );
        // A FIN from the peer without DATA_FIN is not data.
        level.received(IRS + 6, 0, []);
        let dss = level.sent(ISS.wrapping_add(9), b"", false, true);
        assert_eq!(
            dss.unwrap().data_ack,
            Some(Sequence::Long(idsn(KEY_A).advance(6)))
        );
        assert!(!level.fallen_back());
    }

    /// With checksums, each mapping carries the checksum of its bytes.
    #[test]
    fn a_data_level_with_checksums_sums_each_mapping() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, true, None);
        let dss = level
            .sent(ISS.wrapping_add(3), b"abc", false, true)
            .unwrap();
        let dsn = idsn(KEY_B).advance(3);
        let mapping = dss.mapping.unwrap();
        assert_eq!(mapping.checksum, Some(dss_checksum(dsn, 3, 3, b"abc")));
        let bytes = MptcpOption::Dss(dss).to_bytes().unwrap();
        assert_eq!(bytes.len() + 2, 28, "an 8-octet Data ACK");
    }

    /// Data from the peer outside every mapping, or an infinite mapping,
    /// makes the connection fall back: no more DSS.
    #[test]
    fn a_data_level_falls_back_on_unmapped_data() {
        let dsn = Sequence::Short(idsn(KEY_A).advance(1).short());
        // Data the MP_CAPABLE on the third ACK mapped is fine.
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, Some(10));
        level.received(IRS + 1, 10, []);
        assert!(!level.fallen_back());
        level.received(IRS + 11, 4, [mapping(dsn, 11, 2)]);
        assert!(level.fallen_back(), "two bytes past the mapping");
        assert_eq!(level.sent(ISS + 1, b"x", false, true), None);

        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        level.received(IRS + 1, 1, []);
        assert!(level.fallen_back(), "data with no mapping");

        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        level.received(IRS + 1, 0, [mapping(dsn, 1, 0)]);
        assert!(level.fallen_back(), "an infinite mapping");
    }

    /// A mapping sent again must be the same: a second DSS for the same
    /// bytes with another data sequence number violates section 3.3.1,
    /// even before those bytes come.
    #[test]
    fn a_data_level_refuses_a_conflicting_mapping() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let dsn = |offset: u64| Sequence::Long(idsn(KEY_A).advance(offset));
        level.received(IRS + 1, 0, [mapping(dsn(1), 1, 5)]);
        level.received(IRS + 1, 0, [mapping(dsn(1), 1, 5)]);
        assert_eq!(level.error(), None, "the same mapping again");
        level.received(IRS + 1, 0, [mapping(dsn(9), 1, 5)]);
        assert_eq!(level.error(), Some(DataError::Mapping));
    }

    /// After a third ACK with no data, a Linux client that speaks first
    /// maps its first bytes with MP_CAPABLE and data (section 3.1): from
    /// its IDSN + 1, at subflow sequence number 1, in 64 bits.
    #[test]
    fn a_data_level_takes_mp_capable_with_data_as_a_mapping() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let first = MptcpOption::Capable(Capable {
            version: 1,
            checksum_required: false,
            extensibility: false,
            no_new_subflows: false,
            algorithms: algorithm::HMAC_SHA256,
            keys: Keys::Data {
                sender: KEY_A,
                receiver: KEY_B,
                data_level_length: 5,
                checksum: None,
            },
        });
        assert!(!level.received(IRS + 1, 5, [first.clone()]));
        assert!(!level.fallen_back());
        // A retransmission carries the same immutable mapping.
        level.received(IRS + 1, 5, [first]);
        level.arrived(IRS + 1, b"hello", &mut Vec::new());
        assert!(!level.fallen_back());
        let dss = level.sent(ISS.wrapping_add(1), b"HTTP", false, true);
        assert_eq!(
            dss.unwrap().data_ack,
            Some(Sequence::Long(idsn(KEY_A).advance(6)))
        );
        // Its mapping covers those 5 bytes and no more.
        level.received(IRS + 6, 1, []);
        assert!(level.fallen_back());
    }

    /// A DATA_FIN on a segment with no data and no FIN, as Linux sends it
    /// on shutdown, takes one data sequence number: it is acknowledged at
    /// once, and the FIN that comes later takes none.
    #[test]
    fn a_data_level_acknowledges_a_data_fin_alone() {
        for long in [true, false] {
            let at = |n: u64| {
                let dsn = idsn(KEY_A).advance(n);
                if long {
                    Sequence::Long(dsn)
                } else {
                    Sequence::Short(dsn.short())
                }
            };
            let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
            assert!(!level.received(IRS + 1, 5, [mapping(at(1), 1, 5)]));
            level.arrived(IRS + 1, b"hello", &mut Vec::new());
            let data_fin = MptcpOption::Dss(Dss {
                data_ack: None,
                mapping: Some(Mapping {
                    data_sequence_number: at(6),
                    subflow_sequence_number: 0,
                    data_level_length: 1,
                    checksum: None,
                }),
                data_fin: true,
            });
            assert!(level.received(IRS + 6, 0, [data_fin.clone()]));
            let data_ack = |level: &mut DataLevel| {
                let dss = level.sent(ISS.wrapping_add(1), b"", false, true);
                match dss.unwrap().data_ack.unwrap() {
                    Sequence::Long(n) => n,
                    Sequence::Short(_) => panic!("default Data ACKs use the full sequence number"),
                }
            };
            let after_data_fin = idsn(KEY_A).advance(7);
            let expected = after_data_fin;
            assert_eq!(data_ack(&mut level), expected);
            // Sent again, it is acknowledged again, and counts once.
            assert!(level.received(IRS + 6, 0, [data_fin]));
            assert_eq!(data_ack(&mut level), expected);
            // The subflow's FIN, without DATA_FIN.
            assert!(!level.received(IRS + 6, 0, []));
            assert_eq!(data_ack(&mut level), expected);
            assert!(!level.fallen_back());
        }
    }

    /// A DATA_FIN that comes before the data it follows is acknowledged
    /// only once that data has come.
    #[test]
    fn a_data_level_acknowledges_a_data_fin_in_order() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let dsn = |n: u64| Sequence::Long(idsn(KEY_A).advance(n));
        // Data and DATA_FIN in one mapping, with the FIN: 3 bytes, then the
        // DATA_FIN.
        let last = MptcpOption::Dss(Dss {
            data_ack: None,
            mapping: Some(Mapping {
                data_sequence_number: dsn(3),
                subflow_sequence_number: 3,
                data_level_length: 4,
                checksum: None,
            }),
            data_fin: true,
        });
        assert!(level.received(IRS + 3, 3, [last]));
        let data_ack = |level: &mut DataLevel| {
            let dss = level.sent(ISS.wrapping_add(1), b"", false, true);
            dss.unwrap().data_ack.unwrap()
        };
        // Bytes 1 and 2 are missing: the subflow ACK stays at 1.
        assert_eq!(data_ack(&mut level), dsn(1));
        level.received(IRS + 1, 2, [mapping(dsn(1), 1, 2)]);
        level.arrived(IRS + 1, b"hello", &mut Vec::new());
        // All 5 bytes and the FIN: the DATA_FIN is covered.
        assert_eq!(data_ack(&mut level), dsn(7));
        assert!(!level.fallen_back());
    }
    #[test]
    fn checksums_gate_delivery_until_the_whole_mapping_arrives() {
        let dsn = idsn(KEY_A).advance(1);
        for checksum in [None, Some(0), Some(dss_checksum(dsn, 1, 5, b"hello"))] {
            let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, true, None);
            let option = MptcpOption::Dss(Dss {
                data_ack: None,
                mapping: Some(Mapping {
                    data_sequence_number: Sequence::Long(dsn),
                    subflow_sequence_number: 1,
                    data_level_length: 5,
                    checksum,
                }),
                data_fin: false,
            });
            level.received(IRS + 1, 2, [option]);
            let mut out = Vec::new();
            level.arrived(IRS + 1, b"he", &mut out);
            assert!(out.is_empty());
            level.arrived(IRS + 3, b"llo", &mut out);
            if checksum == Some(dss_checksum(dsn, 1, 5, b"hello")) {
                assert_eq!(out, b"hello");
                assert_eq!(level.error(), None);
            } else {
                assert!(out.is_empty());
                assert!(level.error().is_some());
            }
        }
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        level.received(
            IRS + 1,
            1,
            [MptcpOption::Dss(Dss {
                data_ack: None,
                mapping: Some(Mapping {
                    data_sequence_number: Sequence::Long(dsn),
                    subflow_sequence_number: 1,
                    data_level_length: 1,
                    checksum: Some(1),
                }),
                data_fin: false,
            })],
        );
        assert_eq!(level.error(), Some(DataError::ChecksumMode));
    }

    #[test]
    fn data_sequence_gaps_are_queued_and_acknowledged_in_full() {
        let dsn = idsn(KEY_A).advance(1);
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        level.received(IRS + 1, 5, [mapping(Sequence::Long(dsn.advance(5)), 1, 5)]);
        let mut out = Vec::new();
        level.arrived(IRS + 1, b"world", &mut out);
        assert!(out.is_empty());
        assert_eq!(
            level.sent(ISS + 1, b"", false, true).unwrap().data_ack,
            Some(Sequence::Long(dsn))
        );
        level.received(IRS + 6, 5, [mapping(Sequence::Short(dsn.short()), 6, 5)]);
        level.arrived(IRS + 6, b"hello", &mut out);
        assert_eq!(out, b"helloworld");
        assert_eq!(
            level.sent(ISS + 1, b"", false, true).unwrap().data_ack,
            Some(Sequence::Long(dsn.advance(10)))
        );
        assert_eq!(level.error(), None);
    }
    fn end_mapping(dsn: DataSequence) -> MptcpOption {
        MptcpOption::Dss(Dss {
            data_ack: None,
            data_fin: true,
            mapping: Some(Mapping {
                data_sequence_number: Sequence::Long(dsn),
                subflow_sequence_number: 0,
                data_level_length: 1,
                checksum: None,
            }),
        })
    }

    #[test]
    fn data_fin_rejects_later_data_and_fallback() {
        let first = idsn(KEY_A).advance(1);
        for mapped in [false, true] {
            let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
            level.received(IRS + 1, 0, [end_mapping(first)]);
            let options = mapped.then(|| mapping(Sequence::Long(first), 1, 1));
            level.received(IRS + 1, 1, options);
            let mut out = Vec::new();
            level.arrived(IRS + 1, b"x", &mut out);
            assert!(out.is_empty());
            assert_eq!(level.error(), Some(DataError::Mapping));
            assert!(!level.fallen_back());
            assert_eq!(
                level.sent(ISS + 1, b"", false, true).unwrap().data_ack,
                Some(Sequence::Long(first.advance(1)))
            );
        }
    }

    #[test]
    fn data_fin_cannot_move_or_precede_accepted_data() {
        let first = idsn(KEY_A).advance(1);
        for buffered in [false, true] {
            let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
            let dsn = first.advance(u64::from(buffered));
            level.received(IRS + 1, 1, [mapping(Sequence::Long(dsn), 1, 1)]);
            level.arrived(IRS + 1, b"x", &mut Vec::new());
            level.received(IRS + 2, 0, [end_mapping(first)]);
            assert_eq!(level.error(), Some(DataError::Mapping));
        }
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        level.received(IRS + 1, 0, [end_mapping(first)]);
        level.received(IRS + 1, 0, [end_mapping(first.advance(1))]);
        assert_eq!(level.error(), Some(DataError::Mapping));
    }

    #[test]
    fn mapping_errors_are_terminal() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, true, None);
        level.received(
            IRS + 1,
            1,
            [mapping(Sequence::Long(idsn(KEY_A).advance(1)), 1, 1)],
        );
        assert_eq!(level.error(), Some(DataError::ChecksumMode));
        let failed = level.clone();
        level.received(IRS + 1, 1, []);
        assert_eq!(level, failed);
    }

    #[test]
    fn data_sequences_wrap_and_leave_half_space_unordered() {
        let zero = DataSequence::new(0);
        let last = DataSequence::new(u64::MAX);
        let half = DataSequence::new(1 << 63);
        assert_eq!(last.advance(1), zero);
        assert!(last.at_or_before(zero));
        assert!(!zero.at_or_before(last));
        assert_eq!(zero.offset_from(last), Some(1));
        assert_eq!(last.offset_from(zero), Some(-1));
        assert_eq!(half.offset_from(zero), None);
        assert_eq!(zero.offset_from(half), None);
        assert!(!half.at_or_before(zero));
        assert!(!zero.at_or_before(half));
    }

    #[test]
    fn outgoing_fin_is_fixed_and_failed_senders_cannot_map() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let last = level.sent(ISS + 1, b"ab", true, false).unwrap();
        assert_eq!(level.sent(ISS + 1, b"ab", true, false), Some(last));
        assert!(level.sent(ISS + 2, b"b", false, false).is_some());
        for (seq, payload, fin) in [(ISS + 3, &b"x"[..], false), (ISS + 4, &b""[..], true)] {
            let mut failed = level.clone();
            assert_eq!(failed.sent(seq, payload, fin, false), None);
            assert_eq!(failed.error(), Some(DataError::Mapping));
            let frozen = failed.clone();
            assert_eq!(failed.sent(ISS + 1, b"ab", false, false), None);
            assert_eq!(
                failed.sent(ISS + 1, b"ab", false, true).unwrap().mapping,
                None
            );
            failed.received(IRS + 1, 1, []);
            assert_eq!(failed, frozen);
            assert!(!failed.fallen_back());
        }
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        assert!(level.sent(ISS + 1, b"ab", false, false).is_some());
        assert_eq!(level.sent(ISS + 2, b"", true, false), None);
        assert_eq!(level.error(), Some(DataError::Mapping));
    }

    #[test]
    fn pending_mapping_obeys_a_fin_received_before_completion() {
        let first = idsn(KEY_A).advance(1);
        for length in [1, 2] {
            let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
            level.received(IRS + 1, 2, [mapping(Sequence::Long(first), 1, 2)]);
            let mut out = Vec::new();
            level.arrived(IRS + 1, b"a", &mut out);
            assert!(out.is_empty());
            level.received(IRS + 2, 0, [end_mapping(first.advance(length))]);
            level.arrived(IRS + 2, b"b", &mut out);
            if length == 1 {
                assert!(out.is_empty());
                assert_eq!(level.error(), Some(DataError::Mapping));
            } else {
                assert_eq!(out, b"ab");
                assert_eq!(level.error(), None);
            }
        }
    }

    #[test]
    fn an_out_of_order_data_fin_is_idempotent() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let fin = end_mapping(idsn(KEY_A).advance(3));
        assert!(level.received(IRS + 1, 0, [fin.clone()]));
        let remembered = level.clone();
        for _ in 0..100 {
            assert!(level.received(IRS + 1, 0, [fin.clone()]));
            assert_eq!(level, remembered);
        }
    }

    #[test]
    fn buffered_data_is_not_lost_across_a_serial_half_space_boundary() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let far = idsn(KEY_A).advance(1).advance(i64::MAX as u64);
        level.received(IRS + 1, 2, [mapping(Sequence::Long(far), 1, 2)]);
        let mut out = Vec::new();
        level.arrived(IRS + 1, b"ab", &mut out);
        assert!(out.is_empty());
        level.received(IRS + 3, 1, []);
        assert_eq!(level.error(), Some(DataError::Mapping));
        assert!(!level.fallen_back());
    }

    #[test]
    fn a_mapping_cannot_cross_the_serial_half_space_to_evade_fin() {
        let first = idsn(KEY_A).advance(1);
        let far = first.advance(i64::MAX as u64);
        for fin_first in [false, true] {
            let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
            if fin_first {
                level.received(IRS + 1, 0, [end_mapping(first)]);
            }
            level.received(IRS + 1, 2, [mapping(Sequence::Long(far), 1, 2)]);
            let mut out = Vec::new();
            level.arrived(IRS + 1, b"ab", &mut out);
            if !fin_first {
                level.received(IRS + 3, 0, [end_mapping(first)]);
            }
            assert!(out.is_empty());
            assert_eq!(level.error(), Some(DataError::Mapping));
        }
    }

    #[test]
    fn outgoing_data_sequence_survives_subflow_wrap_and_retransmission() {
        let mut level = DataLevel::new(KEY_B, KEY_A, ISS, IRS, false, None);
        let payload = vec![0; 65535];
        for offset in (1..(1u64 << 32) + 131070).step_by(payload.len()) {
            let dss = level
                .sent(ISS.wrapping_add(offset as u32), &payload, false, false)
                .unwrap();
            assert_eq!(
                dss.mapping.unwrap().data_sequence_number,
                Sequence::Long(idsn(KEY_B).advance(offset))
            );
        }
        let before = level.clone();
        for offset in [(1u64 << 32) - 65535, (1u64 << 32) + 1] {
            let dss = level
                .sent(ISS.wrapping_add(offset as u32), b"x", false, false)
                .unwrap();
            assert_eq!(
                dss.mapping.unwrap().data_sequence_number,
                Sequence::Long(idsn(KEY_B).advance(offset))
            );
            assert_eq!(
                level, before,
                "retransmission does not rewind the send position"
            );
        }
    }
}
