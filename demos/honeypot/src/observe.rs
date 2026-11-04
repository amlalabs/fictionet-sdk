//! What the honeypot writes down: every packet in a pcapng file, and a
//! typed [`Observation`] per event of interest as one JSON object per line.
//!
//! The [`Observer`] sees each packet as it crosses an attachment, before
//! the world does. The pcapng file gets each packet as it crossed
//! ([`Observer::crossed`]). The observations are made from whole packets
//! ([`Observer::whole`]): the relay puts fragments together, and the world
//! gets the whole packet it made. A packet from the sandbox side whose IPv4
//! header or TCP checksum is wrong is in the capture only, as a host
//! discards it unread. Every other one is logged as the world sees it,
//! whether or not the world then takes it: one for an address the world
//! does not reach, or with a source its route refuses, is logged and
//! dropped, and its line names that address. For packets from the sandbox
//! side it records:
//!
//! - every SYN ([`Observation::Syn`]): source and destination, flags, all its TCP
//!   options in order, why the options could not all be read, the MPTCP
//!   options decoded, its payload, and the time since the same source's
//!   previous SYN when that SYN was within the burst window;
//! - every other segment with a payload, a FIN, a RST or an MPTCP option
//!   ([`Observation::Segment`]), with its options and payload;
//! - a burst of SYNs, or of SYNs with MP_JOIN, from one source address
//!   ([`Observation::Burst`]).
//!
//! A SYN carries the source address its sender wrote, which a sender can
//! spoof, so the source of a `syn` or `burst` line is a claim. Only the
//! segments of a connection whose handshake completed name an address
//! that sent them: the world's initial sequence numbers and SYN cookies
//! cannot be guessed.
//!
//! For packets to the sandbox side it records each RST the world sends,
//! and the SYN-ACK that first answers a SYN within the handshake timeout
//! ([`Observation::Answer`]), with their options. The SYN-ACKs the world
//! sends again, until the handshake completes, are in the capture only.
//!
//! Neither file can stop the world. A record a file refuses, when the disk
//! is full say, is lost, and the next line the log takes once both files
//! take records again says how many were ([`Observation::Lost`]).
//!
//! Each option list is logged twice over: every option with its bytes, in
//! order ([`Opt`]), and the MPTCP ones decoded with every field the stdlib
//! codec reads ([`Mptcp`]). So signatures written later can be run over
//! either.
//!
//! # Bursts are a heuristic
//!
//! The exploit for CVE-2026-98432 is not public. The published
//! description says it races connection setup on a server with an MPTCP
//! listener, so the observer flags what such a race would look like: at
//! least [`Burst::syns`] SYNs, or SYNs carrying MP_JOIN, from one source
//! address within [`Burst::window`]. That is a guess at the attack's shape,
//! not a signature of it. Every SYN is logged in full whether or not it is
//! part of a burst, so signatures written later can be run over the log.
//!
//! The observer keeps state for a source only while that source has a SYN
//! within the burst window. Answers are tracked separately for at most
//! the listener's 63 second handshake timeout. Both expire even when no
//! further packets arrive, bounding retention after a spoofed flood.
//! The time since a source's previous SYN is given when that SYN was within
//! the window; each line's timestamp gives longer gaps.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Waker};
use std::time::Duration;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ip::{self, protocol};
use fictionet::stdlib::network::tcp::{self, OptionsError, TcpOption};
use fictionet::stdlib::pcap;
use fictionet::stdlib::protocols::mptcp::{self, AddAddr, Capable, Dss, Join, Keys, Mapping};
use fictionet::stdlib::protocols::mptcp::{MptcpOption, Sequence};
use fictionet::time::Instant;
use serde::{Serialize, Serializer};

use crate::Clock;
use crate::config::Burst;
use crate::mptcp::Tokens;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

const ANSWER_TIMEOUT: Duration = Duration::from_secs(63);

/// Which way a packet crosses an attachment, logged as `in` or `out`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// From the sandbox (or the internet) into the world.
    In,
    /// From the world to the sandbox.
    Out,
}

/// One event, as a line of the log. Times are microseconds since the Unix
/// epoch. `attachment` names the attachment the packet crossed:
/// `internet` for the route, or a sandbox's name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Observation {
    /// A SYN into the world.
    Syn {
        /// When it arrived.
        at_us: u64,
        /// The attachment it came through.
        attachment: Arc<str>,
        /// Its source address and port.
        src: SocketAddr,
        /// Its destination address and port.
        dst: SocketAddr,
        /// Its TCP flags.
        flags: Flags,
        /// Its initial sequence number.
        seq: u32,
        /// Its TCP options, in order, up to the first malformed one.
        options: Vec<Opt>,
        /// Why its options could not all be read.
        #[serde(skip_serializing_if = "Option::is_none")]
        options_fault: Option<OptionsFault>,
        /// Its MPTCP options, decoded.
        mptcp: Vec<Mptcp>,
        /// Its payload, when it carried one.
        #[serde(skip_serializing_if = "Hex::is_empty")]
        payload: Hex,
        /// Microseconds since this source's previous SYN, if that was
        /// within the burst window.
        #[serde(skip_serializing_if = "Option::is_none")]
        gap_us: Option<u64>,
    },
    /// Any other segment into the world with a payload, a FIN, a RST or
    /// MPTCP options.
    Segment {
        /// When it arrived.
        at_us: u64,
        /// The attachment it came through.
        attachment: Arc<str>,
        /// Its source address and port.
        src: SocketAddr,
        /// Its destination address and port.
        dst: SocketAddr,
        /// Its TCP flags.
        flags: Flags,
        /// Its sequence number.
        seq: u32,
        /// Its TCP options, in order, up to the first malformed one.
        options: Vec<Opt>,
        /// Why its options could not all be read.
        #[serde(skip_serializing_if = "Option::is_none")]
        options_fault: Option<OptionsFault>,
        /// Its MPTCP options, decoded.
        mptcp: Vec<Mptcp>,
        /// Its payload.
        payload: Hex,
    },
    /// A RST from the world, or the SYN-ACK that first answers a SYN.
    Answer {
        /// When it left.
        at_us: u64,
        /// The attachment it went out on.
        attachment: Arc<str>,
        /// The world's address and port.
        src: SocketAddr,
        /// The address and port it went to.
        dst: SocketAddr,
        /// Its TCP flags.
        flags: Flags,
        /// Its TCP options, in order.
        options: Vec<Opt>,
        /// Its MPTCP options, decoded.
        mptcp: Vec<Mptcp>,
    },
    /// A source sent a burst of SYNs: see the [module docs](self).
    Burst {
        /// When the SYN that made it a burst arrived.
        at_us: u64,
        /// The source address.
        src: IpAddr,
        /// What the SYNs carried.
        kind: BurstKind,
        /// How many there were within the window.
        syns: usize,
        /// The window, in microseconds.
        window_us: u64,
    },
    /// What the files could not take since the last line, such as while
    /// the disk was full: see the [module docs](self).
    Lost {
        /// When the log took lines again.
        at_us: u64,
        /// Packets left out of the capture.
        packets: u64,
        /// Observations left out of the log.
        observations: u64,
    },
}

/// What the SYNs of a burst carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BurstKind {
    /// Any SYN.
    Syns,
    /// SYNs with MP_JOIN.
    Joins,
}

/// Why a segment's options could not all be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionsFault {
    /// The header length does not fit the segment.
    Header,
    /// An option's Length is under 2 or runs past the header.
    Malformed,
}

/// One TCP option, as logged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Opt {
    /// No-Operation.
    Nop,
    /// Maximum Segment Size.
    Mss {
        /// The size.
        value: u16,
    },
    /// Window Scale.
    WindowScale {
        /// The shift.
        shift: u8,
    },
    /// SACK-Permitted.
    SackPermitted,
    /// SACK blocks.
    Sack {
        /// Left and right edges.
        blocks: Vec<(u32, u32)>,
    },
    /// Timestamps.
    Timestamps {
        /// TSval.
        tsval: u32,
        /// TSecr.
        tsecr: u32,
    },
    /// Any other kind, MPTCP's 30 included, or a known kind of another
    /// length: the bytes after Kind and Length.
    Other {
        /// The kind.
        number: u8,
        /// The data.
        data: Hex,
    },
}

impl From<&TcpOption> for Opt {
    fn from(option: &TcpOption) -> Opt {
        match option {
            TcpOption::NoOperation => Opt::Nop,
            TcpOption::MaxSegmentSize(value) => Opt::Mss { value: *value },
            TcpOption::WindowScale(shift) => Opt::WindowScale { shift: *shift },
            TcpOption::SackPermitted => Opt::SackPermitted,
            TcpOption::Sack(blocks) => Opt::Sack {
                blocks: blocks.clone(),
            },
            TcpOption::Timestamps { tsval, tsecr } => Opt::Timestamps {
                tsval: *tsval,
                tsecr: *tsecr,
            },
            TcpOption::Unknown { kind, data } => Opt::Other {
                number: *kind,
                data: Hex(data.clone()),
            },
        }
    }
}

/// One MPTCP option (RFC 8684), as logged, with every field the stdlib
/// codec reads. Keys, tokens and HMACs are in hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "subtype", rename_all = "snake_case")]
pub enum Mptcp {
    /// MP_CAPABLE. Which of the keys and data parameters are there says
    /// which form it has: none on a SYN, the sender's key on a SYN-ACK,
    /// both keys on the third ACK, and the data parameters too on the first
    /// data.
    MpCapable {
        /// The version.
        version: u8,
        /// Flag A.
        checksum_required: bool,
        /// Flag B.
        extensibility: bool,
        /// Flag C.
        no_new_subflows: bool,
        /// Flags D to H.
        algorithms: u8,
        /// The sender's key, when the option has one.
        #[serde(skip_serializing_if = "Option::is_none")]
        sender_key: Option<Key>,
        /// The receiver's key, when the option echoes it.
        #[serde(skip_serializing_if = "Option::is_none")]
        receiver_key: Option<Key>,
        /// The first data's length, when it carries one.
        #[serde(skip_serializing_if = "Option::is_none")]
        data_level_length: Option<u16>,
        /// The first data's DSS checksum, when it carries one.
        #[serde(skip_serializing_if = "Option::is_none")]
        checksum: Option<u16>,
    },
    /// MP_JOIN on a SYN.
    MpJoinSyn {
        /// Flag B.
        backup: bool,
        /// The sender's address ID.
        address_id: u8,
        /// The token of the connection it joins.
        token: Token,
        /// Whether one of the server's open connections has that token.
        token_known: bool,
        /// The sender's random number.
        random: u32,
    },
    /// MP_JOIN on a SYN-ACK.
    MpJoinSynAck {
        /// Flag B.
        backup: bool,
        /// The sender's address ID.
        address_id: u8,
        /// The truncated HMAC.
        hmac: Hex,
        /// The sender's random number.
        random: u32,
    },
    /// MP_JOIN on the third ACK.
    MpJoinAck {
        /// The HMAC.
        hmac: Hex,
    },
    /// DSS.
    Dss {
        /// The Data ACK, with its size.
        #[serde(skip_serializing_if = "Option::is_none")]
        data_ack: Option<Seq>,
        /// The data sequence mapping.
        #[serde(skip_serializing_if = "Option::is_none")]
        mapping: Option<DssMapping>,
        /// DATA_FIN.
        data_fin: bool,
    },
    /// ADD_ADDR.
    AddAddr {
        /// The address ID.
        address_id: u8,
        /// The address.
        address: IpAddr,
        /// The port, if given.
        #[serde(skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// The truncated HMAC. None for an echo (flag E), which has none.
        #[serde(skip_serializing_if = "Option::is_none")]
        hmac: Option<Hex>,
    },
    /// REMOVE_ADDR.
    RemoveAddr {
        /// The address IDs.
        address_ids: Vec<u8>,
    },
    /// MP_PRIO.
    MpPrio {
        /// Flag B.
        backup: bool,
    },
    /// MP_FAIL.
    MpFail {
        /// The data sequence number.
        data_sequence_number: u64,
    },
    /// MP_FASTCLOSE.
    MpFastclose {
        /// The receiver's key.
        receiver_key: Key,
    },
    /// MP_TCPRST.
    MpTcprst {
        /// Flag T.
        transient: bool,
        /// The reason code.
        reason: u8,
    },
    /// An option of kind 30 the codec could not read.
    Malformed {
        /// Why, as the codec says.
        fault: MptcpFault,
        /// The bytes after Kind and Length.
        data: Hex,
    },
}

/// A DSS sequence number with the size it was sent at: the stdlib codec's
/// [`Sequence`], as logged, such as `{"short": 5}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Seq {
    /// 4 octets.
    Short(u32),
    /// 8 octets.
    Long(u64),
}

impl From<Sequence> for Seq {
    fn from(sequence: Sequence) -> Seq {
        match sequence {
            Sequence::Short(n) => Seq::Short(n),
            Sequence::Long(n) => Seq::Long(n.to_bits()),
        }
    }
}

/// A DSS data sequence mapping, as logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DssMapping {
    /// The data sequence number of the first byte, with its size.
    pub data_sequence_number: Seq,
    /// The subflow sequence number of the first byte.
    pub subflow_sequence_number: u32,
    /// How many bytes it covers.
    pub data_level_length: u16,
    /// The DSS checksum, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<u16>,
}

/// Why an MPTCP option could not be read: the stdlib codec's
/// [`mptcp::Error`], as logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "fault", rename_all = "snake_case")]
pub enum MptcpFault {
    /// No subtype.
    NoSubtype,
    /// Longer than a TCP header holds.
    TooLong,
    /// An unassigned or experimental subtype.
    Subtype {
        /// The subtype.
        subtype: u8,
    },
    /// A Length the subtype does not define.
    Length {
        /// The subtype.
        subtype: u8,
        /// The option's Length.
        length: usize,
    },
    /// MP_CAPABLE with no crypto algorithm.
    NoAlgorithm,
    /// A value the codec cannot write, which reading never gives.
    Unwritable,
}

impl From<mptcp::Error> for MptcpFault {
    fn from(error: mptcp::Error) -> MptcpFault {
        match error {
            mptcp::Error::NoSubtype => MptcpFault::NoSubtype,
            mptcp::Error::TooLong(_) => MptcpFault::TooLong,
            mptcp::Error::Unwritable => MptcpFault::Unwritable,
            mptcp::Error::Subtype(subtype) => MptcpFault::Subtype { subtype },
            mptcp::Error::Length { subtype, length } => MptcpFault::Length { subtype, length },
            mptcp::Error::NoAlgorithm => MptcpFault::NoAlgorithm,
        }
    }
}

impl Mptcp {
    /// The option with this data, the bytes after Kind and Length.
    /// `known` says whether a token names an open connection.
    fn read(data: &[u8], known: impl Fn(u32) -> bool) -> Mptcp {
        match MptcpOption::parse(data) {
            Ok(option) => Mptcp::from_option(option, known),
            Err(error) => Mptcp::Malformed {
                fault: error.into(),
                data: Hex(data.to_vec()),
            },
        }
    }

    /// `option` as logged. Every field is taken apart by name, so a field
    /// the codec gains cannot be left out unseen.
    fn from_option(option: MptcpOption, known: impl Fn(u32) -> bool) -> Mptcp {
        match option {
            MptcpOption::Capable(Capable {
                version,
                checksum_required,
                extensibility,
                no_new_subflows,
                algorithms,
                keys,
            }) => {
                let (sender, receiver, data_level_length, checksum) = match keys {
                    Keys::Absent => (None, None, None, None),
                    Keys::Sender(key) => (Some(key), None, None, None),
                    Keys::Both { sender, receiver } => (Some(sender), Some(receiver), None, None),
                    Keys::Data {
                        sender,
                        receiver,
                        data_level_length,
                        checksum,
                    } => (
                        Some(sender),
                        Some(receiver),
                        Some(data_level_length),
                        checksum,
                    ),
                };
                Mptcp::MpCapable {
                    version,
                    checksum_required,
                    extensibility,
                    no_new_subflows,
                    algorithms,
                    sender_key: sender.map(Key),
                    receiver_key: receiver.map(Key),
                    data_level_length,
                    checksum,
                }
            }
            MptcpOption::Join(Join::Syn {
                backup,
                address_id,
                token,
                random,
            }) => Mptcp::MpJoinSyn {
                backup,
                address_id,
                token: Token(token),
                token_known: known(token),
                random,
            },
            MptcpOption::Join(Join::SynAck {
                backup,
                address_id,
                hmac,
                random,
            }) => Mptcp::MpJoinSynAck {
                backup,
                address_id,
                hmac: Hex(hmac.to_vec()),
                random,
            },
            MptcpOption::Join(Join::Ack { hmac }) => Mptcp::MpJoinAck {
                hmac: Hex(hmac.to_vec()),
            },
            MptcpOption::Dss(Dss {
                data_ack,
                mapping,
                data_fin,
            }) => Mptcp::Dss {
                data_ack: data_ack.map(Seq::from),
                mapping: mapping.map(
                    |Mapping {
                         data_sequence_number,
                         subflow_sequence_number,
                         data_level_length,
                         checksum,
                     }| DssMapping {
                        data_sequence_number: data_sequence_number.into(),
                        subflow_sequence_number,
                        data_level_length,
                        checksum,
                    },
                ),
                data_fin,
            },
            MptcpOption::AddAddr(AddAddr {
                address_id,
                address,
                port,
                hmac,
            }) => Mptcp::AddAddr {
                address_id,
                address,
                port,
                hmac: hmac.map(|h| Hex(h.to_vec())),
            },
            MptcpOption::RemoveAddr { address_ids } => Mptcp::RemoveAddr { address_ids },
            MptcpOption::Prio { backup } => Mptcp::MpPrio { backup },
            MptcpOption::Fail {
                data_sequence_number,
            } => Mptcp::MpFail {
                data_sequence_number: data_sequence_number.to_bits(),
            },
            MptcpOption::FastClose { receiver_key } => Mptcp::MpFastclose {
                receiver_key: Key(receiver_key),
            },
            MptcpOption::TcpRst { transient, reason } => Mptcp::MpTcprst { transient, reason },
        }
    }
}

/// Bytes, logged as lowercase hex.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hex(pub Vec<u8>);

impl Hex {
    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(self.0.len() * 2);
        for byte in &self.0 {
            text.push_str(&format!("{byte:02x}"));
        }
        s.serialize_str(&text)
    }
}

/// An MPTCP key, logged as 16 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key(pub u64);

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:016x}", self.0))
    }
}

/// An MPTCP token, logged as 8 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token(pub u32);

impl Serialize for Token {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:08x}", self.0))
    }
}

/// TCP flags, logged as the names of those set, such as `SYN|ACK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Serialize for Flags {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        const NAMES: [&str; 8] = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"];
        let set: Vec<&str> = NAMES
            .iter()
            .enumerate()
            .filter(|(bit, _)| self.0 & (1 << bit) != 0)
            .map(|(_, name)| *name)
            .collect();
        s.serialize_str(&set.join("|"))
    }
}

/// Where the observer writes.
pub struct Sinks {
    /// Observations, one JSON object per line.
    pub log: Box<dyn Write + Send>,
    /// Every packet, as pcapng.
    pub pcap: Box<dyn Write + Send>,
}

/// One file the observer writes, a record at a time: a pcapng block, or a
/// line of the log. A record the file refuses is lost. One it takes only
/// part of is finished before the next record, so the file never holds
/// part of one record followed by another.
pub(super) struct Sink {
    out: Box<dyn Write + Send>,
    /// The rest of a record the file took only part of.
    torn: Vec<u8>,
}

impl Sink {
    pub(super) fn new(out: Box<dyn Write + Send>) -> Sink {
        Sink {
            out,
            torn: Vec::new(),
        }
    }

    /// Writes `record`, after the rest of a torn one. Returns whether the
    /// file took it: all of it, or a part whose rest comes first next time.
    pub(super) fn put(&mut self, record: &[u8]) -> bool {
        if !self.torn.is_empty() {
            let torn = std::mem::take(&mut self.torn);
            let wrote = self.write(&torn);
            if wrote < torn.len() {
                self.torn = torn[wrote..].to_vec();
                return false;
            }
        }
        let wrote = self.write(record);
        if wrote == 0 {
            return false;
        }
        self.torn = record[wrote..].to_vec();
        // A writer that keeps what it could not write yet, as a BufWriter
        // does, writes it with a later record.
        let _ = self.out.flush();
        true
    }

    /// Writes as much of `bytes` as the file takes. Returns how much.
    fn write(&mut self, bytes: &[u8]) -> usize {
        let mut wrote = 0;
        while wrote < bytes.len() {
            match self.out.write(&bytes[wrote..]) {
                Ok(0) => break,
                Ok(n) => wrote += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        wrote
    }
}

/// What the files could not take since the log last said so.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Lost {
    packets: u64,
    observations: u64,
}

/// The answer a SYN awaits: from the address the SYN went to, to the one
/// it came from, acknowledging its sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Awaited {
    from: SocketAddr,
    to: SocketAddr,
    ack: u32,
}

/// One source address with a SYN in the burst window.
struct Source {
    /// When its last SYN arrived.
    last: Instant,
    /// Its SYNs, and those with MP_JOIN, in the window.
    syns: usize,
    joins: usize,
    /// Which bursts were flagged since it was last quiet for a window.
    flagged_syns: bool,
    flagged_joins: bool,
}

/// Writes the packet log and the observations. See the [module docs](self).
pub struct Observer {
    log: Sink,
    pcap: Sink,
    /// Whether the capture took the last packet.
    capturing: bool,
    lost: Lost,
    clock: Clock,
    burst: Burst,
    tokens: Arc<Tokens>,
    /// The SYNs within the window, oldest first: when, from where, whether
    /// each carried MP_JOIN.
    recent: VecDeque<(Instant, IpAddr, bool)>,
    sources: HashMap<IpAddr, Source>,
    /// Pending answers, with their most recent SYN and outstanding count.
    awaited: HashMap<Awaited, (Instant, usize)>,
    pending: VecDeque<(Instant, Awaited)>,
    expiry_waiter: Option<Waker>,
}

impl Observer {
    /// Starts the pcapng file in `sinks`. `tokens` says which MP_JOIN
    /// tokens name an open connection.
    pub fn new(
        mut sinks: Sinks,
        clock: Clock,
        burst: Burst,
        tokens: Arc<Tokens>,
    ) -> io::Result<Observer> {
        let mut header = Vec::new();
        pcap::start(&mut header, &[]);
        sinks.pcap.write_all(&header)?;
        sinks.pcap.flush()?;
        Ok(Observer {
            log: Sink::new(sinks.log),
            pcap: Sink::new(sinks.pcap),
            capturing: true,
            lost: Lost::default(),
            clock,
            burst,
            tokens,
            recent: VecDeque::new(),
            sources: HashMap::new(),
            awaited: HashMap::new(),
            pending: VecDeque::new(),
            expiry_waiter: None,
        })
    }

    /// How many source addresses the observer holds state for.
    pub fn sources(&self) -> usize {
        self.sources.len()
    }

    /// Writes `packet`, which crossed `attachment` at `now`, to the packet
    /// log as it is. Any bytes may come here.
    pub fn crossed(
        &mut self,
        attachment: &Arc<str>,
        direction: Direction,
        packet: &[u8],
        now: Instant,
    ) {
        let at_us = self.clock.micros(now);
        let mut block = Vec::with_capacity(packet.len() + 64);
        let way = match direction {
            Direction::In => "in",
            Direction::Out => "out",
        };
        pcap::packet(
            &mut block,
            at_us,
            packet.len(),
            packet,
            Some(&format!("{attachment} {way}")),
        );
        self.capturing = self.pcap.put(&block);
        if !self.capturing {
            self.lost.packets += 1;
        }
    }

    /// Writes what `packet` shows: a whole packet, as the world takes it
    /// in, that crossed `attachment` at `now`. Any bytes may come here.
    pub fn whole(
        &mut self,
        attachment: &Arc<str>,
        direction: Direction,
        packet: &[u8],
        now: Instant,
    ) {
        let mut observations = self.observe(attachment, direction, packet, now);
        if self.lost != Lost::default() && self.capturing {
            let lost = Observation::Lost {
                at_us: self.clock.micros(now),
                packets: self.lost.packets,
                observations: self.lost.observations,
            };
            observations.insert(0, lost);
            self.lost = Lost::default();
        }
        for observation in observations {
            let mut line = serde_json::to_vec(&observation).expect("observations are plain data");
            line.push(b'\n');
            if !self.log.put(&line) {
                match observation {
                    // Still owed: it goes on the next line taken.
                    Observation::Lost {
                        packets,
                        observations,
                        ..
                    } => {
                        self.lost.packets += packets;
                        self.lost.observations += observations;
                    }
                    _ => self.lost.observations += 1,
                }
            }
        }
    }

    /// What `packet`, a whole one, shows.
    fn observe(
        &mut self,
        attachment: &Arc<str>,
        direction: Direction,
        packet: &[u8],
        now: Instant,
    ) -> Vec<Observation> {
        self.expire(now);
        let Some(header) = ip::Header::parse_truncated(packet) else {
            return Vec::new();
        };
        if header.protocol != protocol::TCP || header.fragment.is_some_and(|f| f.offset != 0) {
            return Vec::new();
        }
        let t = header.payload(packet);
        if t.len() < 20 {
            return Vec::new();
        }
        // A host discards a packet with a wrong checksum unread (RFC 1122
        // sections 3.2.1.2 and 4.2.2.7).
        let wrong = || {
            (header.src.is_ipv4() && ip::checksum(&packet[..header.payload.start]) != 0)
                || ip::transport_checksum(header.src, header.dst, protocol::TCP, t) != 0
        };
        if direction == Direction::In && wrong() {
            return Vec::new();
        }
        let at_us = self.clock.micros(now);
        let src = SocketAddr::new(header.src, u16::from_be_bytes([t[0], t[1]]));
        let dst = SocketAddr::new(header.dst, u16::from_be_bytes([t[2], t[3]]));
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let flags = t[13];
        let (read, options_fault) = match tcp::options(t) {
            Ok(options) => (options, None),
            Err(OptionsError::Malformed(read)) => (read, Some(OptionsFault::Malformed)),
            Err(OptionsError::Header) => (Vec::new(), Some(OptionsFault::Header)),
        };
        let tokens = &self.tokens;
        let mptcp: Vec<Mptcp> = read
            .iter()
            .filter_map(|o| match o {
                TcpOption::Unknown { kind, data } if *kind == mptcp::KIND => {
                    Some(Mptcp::read(data, |token| tokens.knows(token)))
                }
                _ => None,
            })
            .collect();
        let options: Vec<Opt> = read.iter().map(Opt::from).collect();
        let attachment = attachment.clone();
        if direction == Direction::Out {
            let rst = flags & RST != 0;
            let syn_ack = flags & (SYN | ACK) == SYN | ACK;
            let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
            let awaited = Awaited {
                from: src,
                to: dst,
                ack,
            };
            // An answer with no pending SYN is a retransmission.
            let first = (rst || syn_ack) && self.answered(awaited);
            if rst || (syn_ack && first) {
                return vec![Observation::Answer {
                    at_us,
                    attachment,
                    src,
                    dst,
                    flags: Flags(flags),
                    options,
                    mptcp,
                }];
            }
            return Vec::new();
        }
        let offset = usize::from(t[12] >> 4) * 4;
        let payload = Hex(t
            .get(offset..)
            .filter(|_| offset >= 20)
            .unwrap_or_default()
            .to_vec());
        if flags & (SYN | RST | ACK) == SYN {
            let join = mptcp.iter().any(|m| matches!(m, Mptcp::MpJoinSyn { .. }));
            let awaited = Awaited {
                from: dst,
                to: src,
                ack: seq.wrapping_add(1),
            };
            let (gap_us, bursts) = self.syn(src.ip(), join, awaited, now);
            let mut out = vec![Observation::Syn {
                at_us,
                attachment,
                src,
                dst,
                flags: Flags(flags),
                seq,
                options,
                options_fault,
                mptcp,
                payload,
                gap_us,
            }];
            out.extend(bursts.into_iter().map(|(kind, syns)| Observation::Burst {
                at_us,
                src: src.ip(),
                kind,
                syns,
                window_us: self.burst.window.as_micros() as u64,
            }));
            return out;
        }
        if payload.is_empty() && mptcp.is_empty() && flags & (FIN | RST) == 0 {
            return Vec::new();
        }
        vec![Observation::Segment {
            at_us,
            attachment,
            src,
            dst,
            flags: Flags(flags),
            seq,
            options,
            options_fault,
            mptcp,
            payload,
        }]
    }

    /// Whether a SYN awaits `answer`. It awaits it no more.
    fn answered(&mut self, answer: Awaited) -> bool {
        let Some(waiting) = self.awaited.get_mut(&answer) else {
            return false;
        };
        waiting.1 -= 1;
        if waiting.1 == 0 {
            self.awaited.remove(&answer);
        }
        true
    }

    /// The next expiry, waking the caller when new state changes its deadline.
    pub(crate) fn expiry(&mut self, cx: &mut Context<'_>) -> Instant {
        self.expiry_waiter = Some(cx.waker().clone());
        let burst = self.recent.front().map(|(at, ..)| *at + self.burst.window);
        let answer = self.pending.front().map(|(at, _)| *at + ANSWER_TIMEOUT);
        burst
            .into_iter()
            .chain(answer)
            .min()
            .unwrap_or(Instant::from_since_start(Duration::MAX))
    }

    /// Releases expired burst and unanswered SYN state, including while quiet.
    pub(crate) fn expire(&mut self, now: Instant) {
        while let Some(&(at, from, joined)) = self.recent.front() {
            if now < at + self.burst.window {
                break;
            }
            self.recent.pop_front();
            if let Some(source) = self.sources.get_mut(&from) {
                source.syns -= 1;
                source.joins -= usize::from(joined);
                if source.syns == 0 {
                    self.sources.remove(&from);
                }
            }
        }
        while let Some(&(at, answer)) = self.pending.front() {
            let current = self
                .awaited
                .get(&answer)
                .is_some_and(|waiting| waiting.0 == at);
            if current && now < at + ANSWER_TIMEOUT {
                break;
            }
            self.pending.pop_front();
            if current {
                self.awaited.remove(&answer);
            }
        }
        if self.recent.is_empty() {
            self.recent.shrink_to_fit();
            self.sources.shrink_to_fit();
        }
        if self.pending.is_empty() {
            self.pending.shrink_to_fit();
            self.awaited.shrink_to_fit();
        }
    }

    /// Counts a SYN from `src`, with MP_JOIN if `join`, that awaits
    /// `answer`. Returns the time since its previous SYN within the window,
    /// and the bursts it starts.
    fn syn(
        &mut self,
        src: IpAddr,
        join: bool,
        answer: Awaited,
        now: Instant,
    ) -> (Option<u64>, Vec<(BurstKind, usize)>) {
        self.expire(now);
        self.recent.push_back((now, src, join));
        self.pending.push_back((now, answer));
        let waiting = self.awaited.entry(answer).or_insert((now, 0));
        waiting.0 = now;
        waiting.1 += 1;
        if let Some(waiter) = self.expiry_waiter.take() {
            waiter.wake();
        }
        let source = self.sources.entry(src).or_insert(Source {
            last: now,
            syns: 0,
            joins: 0,
            flagged_syns: false,
            flagged_joins: false,
        });
        let gap = (source.syns > 0).then(|| {
            now.since_start()
                .saturating_sub(source.last.since_start())
                .as_micros() as u64
        });
        source.last = now;
        source.syns += 1;
        source.joins += usize::from(join);
        let mut bursts = Vec::new();
        if source.syns >= self.burst.syns && !source.flagged_syns {
            source.flagged_syns = true;
            bursts.push((BurstKind::Syns, source.syns));
        }
        if source.joins >= self.burst.syns && !source.flagged_joins {
            source.flagged_joins = true;
            bursts.push((BurstKind::Joins, source.joins));
        }
        (gap, bursts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::network::ip::{Fields, packet_with, transport_checksum};

    #[test]
    fn hex_keys_tokens_and_flags_serialize_as_text() {
        let line = serde_json::to_string(&Mptcp::MpJoinSyn {
            backup: false,
            address_id: 2,
            token: Token(0xab),
            token_known: true,
            random: 9,
        })
        .unwrap();
        assert_eq!(
            line,
            r#"{"subtype":"mp_join_syn","backup":false,"address_id":2,"token":"000000ab","token_known":true,"random":9}"#
        );
        assert_eq!(serde_json::to_string(&Flags(0x12)).unwrap(), r#""SYN|ACK""#);
        assert_eq!(
            serde_json::to_string(&Key(1)).unwrap(),
            r#""0000000000000001""#
        );
        assert_eq!(
            serde_json::to_string(&Hex(vec![0, 0xff])).unwrap(),
            r#""00ff""#
        );
    }

    /// Every malformed kind-30 option the codec refuses is logged with the
    /// codec's reason.
    #[test]
    fn malformed_mptcp_options_keep_their_bytes() {
        let read = |data: &[u8]| Mptcp::read(data, |_| false);
        assert_eq!(
            read(&[]),
            Mptcp::Malformed {
                fault: MptcpFault::NoSubtype,
                data: Hex(Vec::new())
            }
        );
        assert_eq!(
            read(&[0x90, 0]),
            Mptcp::Malformed {
                fault: MptcpFault::Subtype { subtype: 9 },
                data: Hex(vec![0x90, 0])
            }
        );
        assert_eq!(
            read(&[0x10, 0, 0]),
            Mptcp::Malformed {
                fault: MptcpFault::Length {
                    subtype: 1,
                    length: 5
                },
                data: Hex(vec![0x10, 0, 0])
            }
        );
        assert_eq!(
            read(&[0x01, 0x80]),
            Mptcp::Malformed {
                fault: MptcpFault::NoAlgorithm,
                data: Hex(vec![0x01, 0x80])
            }
        );
    }

    /// Every field the codec reads is in the log: the HMAC of ADD_ADDR,
    /// the checksums of DSS and of MP_CAPABLE's first data, and the size
    /// of each DSS sequence number.
    #[test]
    fn mptcp_options_are_logged_in_full() {
        let logged = |option: MptcpOption| {
            let data = option.to_bytes().unwrap();
            serde_json::to_value(Mptcp::read(&data, |_| false)).unwrap()
        };
        let add_addr = logged(MptcpOption::AddAddr(AddAddr {
            address_id: 3,
            address: "192.0.2.7".parse().unwrap(),
            port: None,
            hmac: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        }));
        assert_eq!(
            add_addr,
            serde_json::json!({"subtype": "add_addr", "address_id": 3,
                "address": "192.0.2.7", "hmac": "0102030405060708"})
        );
        let dss = logged(MptcpOption::Dss(Dss {
            data_ack: Some(Sequence::Short(5)),
            mapping: Some(Mapping {
                data_sequence_number: Sequence::Long(mptcp::DataSequence::new(6)),
                subflow_sequence_number: 7,
                data_level_length: 8,
                checksum: Some(0xbeef),
            }),
            data_fin: false,
        }));
        assert_eq!(
            dss,
            serde_json::json!({"subtype": "dss", "data_ack": {"short": 5},
                "mapping": {"data_sequence_number": {"long": 6},
                    "subflow_sequence_number": 7, "data_level_length": 8,
                    "checksum": 0xbeef},
                "data_fin": false})
        );
        let first_data = logged(MptcpOption::Capable(Capable {
            version: 1,
            checksum_required: true,
            extensibility: false,
            no_new_subflows: false,
            algorithms: 1,
            keys: Keys::Data {
                sender: 1,
                receiver: 2,
                data_level_length: 3,
                checksum: Some(4),
            },
        }));
        assert_eq!(first_data["checksum"], 4);
        assert_eq!(first_data["data_level_length"], 3);
    }

    fn observer() -> Observer {
        Observer::new(
            Sinks {
                log: Box::new(io::sink()),
                pcap: Box::new(io::sink()),
            },
            Clock::at_unix_secs(0),
            Burst {
                window: Duration::from_millis(100),
                syns: 3,
            },
            Arc::default(),
        )
        .unwrap()
    }

    /// A TCP segment from 192.0.2.1:4000 to 203.0.113.10:22.
    fn segment(flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
        let (src, dst): (IpAddr, IpAddr) = (
            "192.0.2.1".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
        );
        let mut t = vec![0x0f, 0xa0, 0, 22, 0, 0, 0, 1, 0, 0, 0, 0];
        t.push(((20 + options.len()) / 4) as u8 * 16);
        t.extend_from_slice(&[flags, 0xff, 0xff, 0, 0, 0, 0]);
        t.extend_from_slice(options);
        t.extend_from_slice(payload);
        let sum = transport_checksum(src, dst, 6, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        packet_with(src, dst, 6, Fields::default(), &t).0
    }

    fn observe(observer: &mut Observer, direction: Direction, packet: &[u8]) -> Vec<Observation> {
        let at = Instant::from_since_start(Duration::from_secs(1));
        observer.observe(&Arc::from("internet"), direction, packet, at)
    }

    /// A bare FIN is a segment line, as the docs say.
    #[test]
    fn a_bare_fin_is_logged() {
        let fin = segment(FIN | ACK, &[], b"");
        let [Observation::Segment { flags, payload, .. }] =
            &observe(&mut observer(), Direction::In, &fin)[..]
        else {
            panic!("one segment line")
        };
        assert_eq!((flags.0, payload.is_empty()), (FIN | ACK, true));
    }

    /// Data on a SYN is in its line.
    #[test]
    fn a_syn_s_payload_is_logged() {
        let syn = segment(SYN, &[2, 4, 5, 0xb4], b"PAYLOAD-IN-SYN");
        let [Observation::Syn { payload, .. }] = &observe(&mut observer(), Direction::In, &syn)[..]
        else {
            panic!("one SYN line")
        };
        assert_eq!(payload.0, b"PAYLOAD-IN-SYN");
        let line = serde_json::to_value(&observe(&mut observer(), Direction::In, &syn)[0]).unwrap();
        assert_eq!(line["payload"], "5041594c4f41442d494e2d53594e");
        // A SYN with none has no payload field.
        let bare = segment(SYN, &[], b"");
        let line =
            serde_json::to_value(&observe(&mut observer(), Direction::In, &bare)[0]).unwrap();
        assert!(line.get("payload").is_none(), "{line}");
    }

    #[test]
    fn syn_flags_keep_scanner_probes_and_ecn() {
        for (bits, text) in [
            (SYN, "SYN"),
            (SYN | FIN, "FIN|SYN"),
            (SYN | 0x08, "SYN|PSH"),
            (SYN | 0x20, "SYN|URG"),
            (SYN | 0xc0, "SYN|ECE|CWR"),
        ] {
            let seen = observe(&mut observer(), Direction::In, &segment(bits, &[], b""));
            let line = serde_json::to_value(&seen[0]).unwrap();
            assert_eq!(line["event"], "syn");
            assert_eq!(line["flags"], text);
        }
    }

    /// Segments and answers keep every option's bytes, MPTCP or not.
    #[test]
    fn segments_and_answers_keep_their_options() {
        let add_addr = [30, 16, 0x30, 3, 192, 0, 2, 7, 1, 2, 3, 4, 5, 6, 7, 8];
        let ack = segment(ACK, &add_addr, b"");
        let [Observation::Segment { options, mptcp, .. }] =
            &observe(&mut observer(), Direction::In, &ack)[..]
        else {
            panic!("one segment line")
        };
        assert_eq!(
            options,
            &[Opt::Other {
                number: 30,
                data: Hex(add_addr[2..].to_vec())
            }]
        );
        assert!(matches!(&mptcp[..], [Mptcp::AddAddr { hmac: Some(_), .. }]));
        let rst = segment(RST | ACK, &[30, 4, 0x80, 3], b"");
        let [Observation::Answer { options, .. }] =
            &observe(&mut observer(), Direction::Out, &rst)[..]
        else {
            panic!("one answer line")
        };
        assert_eq!(
            options,
            &[Opt::Other {
                number: 30,
                data: Hex(vec![0x80, 3])
            }]
        );
    }

    /// A client's RST is logged though it carries nothing else, since a
    /// race in connection setup may turn on one. A bare ACK is not.
    #[test]
    fn a_client_rst_is_logged() {
        let rst = segment(RST, &[], b"");
        assert!(matches!(
            &observe(&mut observer(), Direction::In, &rst)[..],
            [Observation::Segment {
                flags: Flags(RST),
                ..
            }]
        ));
        let ack = segment(ACK, &[], b"");
        assert_eq!(observe(&mut observer(), Direction::In, &ack), []);
    }

    #[test]
    fn burst_state_lasts_one_window() {
        let mut observer = observer();
        let at = |ms| Instant::from_since_start(Duration::from_millis(ms));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        assert_eq!(observer.syn(a, false, awaits(), at(0)), (None, vec![]));
        assert_eq!(
            observer.syn(a, true, awaits(), at(10)),
            (Some(10_000), vec![])
        );
        assert_eq!(observer.syn(b, false, awaits(), at(20)), (None, vec![]));
        assert_eq!(
            observer.syn(a, true, awaits(), at(30)),
            (Some(20_000), vec![(BurstKind::Syns, 3)])
        );
        // Flagged once while it lasts.
        assert_eq!(
            observer.syn(a, true, awaits(), at(40)),
            (Some(10_000), vec![(BurstKind::Joins, 3)])
        );
        assert_eq!(
            observer.syn(a, false, awaits(), at(50)),
            (Some(10_000), vec![])
        );
        assert_eq!(observer.sources(), 2);
        // A window later both have aged out; only the newest source is held,
        // and its SYN gives no gap: the one before was outside the window.
        assert_eq!(observer.syn(b, false, awaits(), at(500)), (None, vec![]));
        assert_eq!(observer.sources(), 1);
        assert_eq!(observer.recent.len(), 1);
        assert_eq!(observer.awaited[&awaits()].1, 7);
        observer.expire(at(600));
        assert_eq!(observer.sources(), 0);
        assert!(observer.recent.is_empty());
        assert_eq!(observer.awaited[&awaits()].1, 7);
        observer.expire(at(63_500));
        assert!(observer.awaited.is_empty());
        assert!(observer.pending.is_empty());
    }

    /// The answer the SYNs of `burst_state_lasts_one_window` await.
    fn awaits() -> Awaited {
        Awaited {
            from: "203.0.113.10:22".parse().unwrap(),
            to: "192.0.2.1:4000".parse().unwrap(),
            ack: 2,
        }
    }

    /// A SYN or segment whose IPv4 header or TCP checksum is wrong is not
    /// logged, and counts toward no burst: a host discards it unread.
    #[test]
    fn packets_with_wrong_checksums_are_not_logged() {
        let mut observer = observer();
        for (at, bit) in [(26, 1u8), (36, 0x80), (10, 1)] {
            for flags in [SYN, ACK | FIN] {
                let mut packet = segment(flags, &[2, 4, 5, 0xb4], b"x");
                packet[at] ^= bit;
                let seen = observe(&mut observer, Direction::In, &packet);
                assert!(seen.is_empty(), "byte {at}: {seen:?}");
            }
        }
        assert_eq!(observer.sources(), 0);
        let good = segment(SYN, &[2, 4, 5, 0xb4], b"x");
        assert_eq!(observe(&mut observer, Direction::In, &good).len(), 1);
    }

    /// The world's packet answering `segment`'s SYN: from 203.0.113.10:22
    /// to 192.0.2.1:4000, acknowledging sequence number 1.
    fn answer(flags: u8) -> Vec<u8> {
        let (src, dst): (IpAddr, IpAddr) = (
            "203.0.113.10".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        );
        let mut t = vec![
            0, 22, 0x0f, 0xa0, 0, 0, 0, 9, 0, 0, 0, 2, 0x50, flags, 0xff, 0xff,
        ];
        t.extend_from_slice(&[0, 0, 0, 0]);
        let sum = transport_checksum(src, dst, 6, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        packet_with(src, dst, 6, Fields::default(), &t).0
    }

    /// The SYN-ACK that first answers a SYN is logged, and the ones sent
    /// again are not; every RST is.
    #[test]
    fn a_syn_s_first_answer_is_logged_once() {
        let mut observer = observer();
        let syn_ack = answer(SYN | ACK);
        let answers = |observer: &mut Observer, packet: &[u8]| {
            observe(observer, Direction::Out, packet)
                .into_iter()
                .filter(|o| matches!(o, Observation::Answer { .. }))
                .count()
        };
        assert_eq!(answers(&mut observer, &syn_ack), 0, "no SYN yet");
        observe(&mut observer, Direction::In, &segment(SYN, &[], b""));
        assert_eq!(answers(&mut observer, &syn_ack), 1);
        assert_eq!(answers(&mut observer, &syn_ack), 0, "sent again");
        // The client sends its SYN again: the answer to that is logged.
        observe(&mut observer, Direction::In, &segment(SYN, &[], b""));
        assert_eq!(answers(&mut observer, &syn_ack), 1);
        assert!(observer.awaited.is_empty());
        let rst = answer(RST | ACK);
        assert_eq!(answers(&mut observer, &rst), 1);
        assert_eq!(answers(&mut observer, &rst), 1);
    }

    #[test]
    fn answers_outlive_the_burst_window() {
        for window in [Duration::ZERO, Duration::from_millis(100)] {
            let mut observer = observer();
            observer.burst.window = window;
            let at = Instant::from_since_start(Duration::from_secs(1));
            for _ in 0..2 {
                observer.observe(
                    &Arc::from("internet"),
                    Direction::In,
                    &segment(SYN, &[], b""),
                    at,
                );
            }
            let later = at + Duration::from_secs(1);
            observer.expire(later);
            assert_eq!(observer.sources(), 0);
            for _ in 0..2 {
                assert!(matches!(
                    observer.observe(
                        &Arc::from("internet"),
                        Direction::Out,
                        &answer(SYN | ACK),
                        later,
                    )[..],
                    [Observation::Answer { .. }]
                ));
            }
            assert!(observer.awaited.is_empty());
            assert!(
                observer
                    .observe(
                        &Arc::from("internet"),
                        Direction::Out,
                        &answer(SYN | ACK),
                        later,
                    )
                    .is_empty()
            );
        }
    }

    #[test]
    fn an_old_syn_expiry_preserves_its_new_attempt() {
        let mut observer = observer();
        let source = awaits().to.ip();
        observer.syn(source, false, awaits(), Instant::ZERO);
        assert!(observer.answered(awaits()));
        observer.syn(
            source,
            false,
            awaits(),
            Instant::from_since_start(Duration::from_secs(1)),
        );
        observer.expire(Instant::from_since_start(ANSWER_TIMEOUT));
        assert!(observer.answered(awaits()));
        observer.expire(Instant::from_since_start(ANSWER_TIMEOUT));
        assert!(observer.pending.is_empty());
        assert!(observer.awaited.is_empty());
    }

    /// Takes the first `room` bytes written, then refuses all until
    /// `room` grows.
    #[derive(Clone, Default)]
    struct Disk(Arc<std::sync::Mutex<(Vec<u8>, usize)>>);

    impl Write for Disk {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut disk = self.0.lock().unwrap();
            let free = disk.1 - disk.0.len();
            if free == 0 {
                return Err(io::ErrorKind::StorageFull.into());
            }
            let n = buf.len().min(free);
            disk.0.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A full disk loses records but stops nothing. A record cut short is
    /// finished first once there is room, so the file holds whole records,
    /// and the log then says how many packets and lines were lost.
    #[test]
    fn a_full_disk_loses_records_and_says_so() {
        let (log, pcap) = (Disk::default(), Disk::default());
        log.0.lock().unwrap().1 = usize::MAX;
        pcap.0.lock().unwrap().1 = usize::MAX;
        let mut observer = Observer::new(
            Sinks {
                log: Box::new(log.clone()),
                pcap: Box::new(pcap.clone()),
            },
            Clock::at_unix_secs(0),
            Burst {
                window: Duration::from_millis(100),
                syns: 100,
            },
            Arc::default(),
        )
        .unwrap();
        let name = Arc::from("internet");
        let at = Instant::from_since_start(Duration::from_secs(1));
        let syn = segment(SYN, &[], b"");
        // The capture has room for its header and half a packet.
        let header = pcap.0.lock().unwrap().0.len();
        pcap.0.lock().unwrap().1 = header + 20;
        for _ in 0..3 {
            observer.crossed(&name, Direction::In, &syn, at);
            observer.whole(&name, Direction::In, &syn, at);
        }
        // The log has the three SYNs: nothing is owed yet, as the capture
        // takes nothing.
        let lines = |log: &Disk| {
            String::from_utf8(log.0.lock().unwrap().0.clone())
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(lines(&log).len(), 3);
        // The log fills up too.
        let full = log.0.lock().unwrap().0.len();
        log.0.lock().unwrap().1 = full;
        observer.crossed(&name, Direction::In, &syn, at);
        observer.whole(&name, Direction::In, &syn, at);
        // Room again: the cut packet is finished, and the log says what
        // was lost.
        pcap.0.lock().unwrap().1 = usize::MAX;
        log.0.lock().unwrap().1 = usize::MAX;
        observer.crossed(&name, Direction::In, &syn, at);
        observer.whole(&name, Direction::In, &syn, at);
        let lines = lines(&log);
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert_eq!(
            lines[3],
            serde_json::json!({"event": "lost", "at_us": 1_000_000,
                "packets": 3, "observations": 1})
        );
        assert_eq!(lines[4]["event"], "syn");
        // The capture holds its header, then two whole blocks: the first
        // packet and the last.
        let capture = pcap.0.lock().unwrap().0.clone();
        let mut rest = &capture[header..];
        let mut blocks = 0;
        while !rest.is_empty() {
            let len = u32::from_le_bytes(rest[4..8].try_into().unwrap()) as usize;
            assert_eq!(rest[len - 4..len], rest[4..8], "a whole block");
            rest = &rest[len..];
            blocks += 1;
        }
        assert_eq!(blocks, 2);
    }
}
