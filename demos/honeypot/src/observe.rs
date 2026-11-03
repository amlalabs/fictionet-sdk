//! What the honeypot writes down: every packet in a pcapng file, and a
//! typed [`Observation`] per event of interest as one JSON object per line.
//!
//! The [`Observer`] sees each packet as it crosses an attachment, before
//! the world's TCP does, so a packet the world drops is still logged. For
//! packets from the sandbox side it records:
//!
//! - every SYN ([`Observation::Syn`]): source and destination, all its TCP
//!   options in order, why the options could not all be read, the MPTCP
//!   options decoded, and the time since the same source's previous SYN;
//! - every other segment with a payload or an MPTCP option
//!   ([`Observation::Segment`]), with the payload bytes;
//! - a burst of SYNs, or of SYNs with MP_JOIN, from one source address
//!   ([`Observation::Burst`]).
//!
//! For packets to the sandbox side it records each SYN-ACK and RST the
//! world sends ([`Observation::Answer`]), with their MPTCP options.
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
//! within the burst window. Its memory is the SYNs of the last window, so a
//! flood from spoofed addresses cannot grow it past what one window holds.
//! The time since a source's previous SYN is given when that SYN was within
//! the window; each line's timestamp gives longer gaps.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ip::{self, protocol};
use fictionet::stdlib::network::tcp::{self, OptionsError, TcpOption};
use fictionet::stdlib::pcap;
use fictionet::stdlib::protocols::mptcp::{self, Join, MptcpOption, Sequence};
use fictionet::time::Instant;
use serde::{Serialize, Serializer};

use crate::Clock;
use crate::config::Burst;
use crate::mptcp::Tokens;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// Which way a packet crosses an attachment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        /// Its initial sequence number.
        seq: u32,
        /// Its TCP options, in order, up to the first malformed one.
        options: Vec<Opt>,
        /// Why its options could not all be read.
        #[serde(skip_serializing_if = "Option::is_none")]
        options_fault: Option<OptionsFault>,
        /// Its MPTCP options, decoded.
        mptcp: Vec<Mptcp>,
        /// Microseconds since this source's previous SYN, if that was
        /// within the burst window.
        #[serde(skip_serializing_if = "Option::is_none")]
        gap_us: Option<u64>,
    },
    /// Any other segment into the world with a payload or MPTCP options.
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
        /// Its MPTCP options, decoded.
        mptcp: Vec<Mptcp>,
        /// Its payload.
        payload: Hex,
    },
    /// A SYN-ACK or RST from the world.
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
    /// Any other kind, MPTCP's 30 included: the bytes after Kind and
    /// Length.
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

/// One MPTCP option (RFC 8684), as logged. Keys and tokens are in hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "subtype", rename_all = "snake_case")]
pub enum Mptcp {
    /// MP_CAPABLE.
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
        /// The Data ACK.
        #[serde(skip_serializing_if = "Option::is_none")]
        data_ack: Option<u64>,
        /// The mapping's data sequence number.
        #[serde(skip_serializing_if = "Option::is_none")]
        data_sequence_number: Option<u64>,
        /// The mapping's subflow sequence number.
        #[serde(skip_serializing_if = "Option::is_none")]
        subflow_sequence_number: Option<u32>,
        /// The mapping's length.
        #[serde(skip_serializing_if = "Option::is_none")]
        data_level_length: Option<u16>,
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
        /// Whether it is an echo (no HMAC).
        echo: bool,
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
        let option = match MptcpOption::parse(data) {
            Ok(option) => option,
            Err(error) => {
                return Mptcp::Malformed {
                    fault: error.into(),
                    data: Hex(data.to_vec()),
                };
            }
        };
        let seq = |s: Sequence| match s {
            Sequence::Short(n) => u64::from(n),
            Sequence::Long(n) => n,
        };
        match option {
            MptcpOption::Capable(c) => {
                let (sender, receiver, length) = match c.keys {
                    mptcp::Keys::Absent => (None, None, None),
                    mptcp::Keys::Sender(k) => (Some(k), None, None),
                    mptcp::Keys::Both { sender, receiver } => (Some(sender), Some(receiver), None),
                    mptcp::Keys::Data {
                        sender,
                        receiver,
                        data_level_length,
                        ..
                    } => (Some(sender), Some(receiver), Some(data_level_length)),
                };
                Mptcp::MpCapable {
                    version: c.version,
                    checksum_required: c.checksum_required,
                    extensibility: c.extensibility,
                    no_new_subflows: c.no_new_subflows,
                    algorithms: c.algorithms,
                    sender_key: sender.map(Key),
                    receiver_key: receiver.map(Key),
                    data_level_length: length,
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
            MptcpOption::Dss(dss) => Mptcp::Dss {
                data_ack: dss.data_ack.map(seq),
                data_sequence_number: dss.mapping.map(|m| seq(m.data_sequence_number)),
                subflow_sequence_number: dss.mapping.map(|m| m.subflow_sequence_number),
                data_level_length: dss.mapping.map(|m| m.data_level_length),
                data_fin: dss.data_fin,
            },
            MptcpOption::AddAddr(a) => Mptcp::AddAddr {
                address_id: a.address_id,
                address: a.address,
                port: a.port,
                echo: a.hmac.is_none(),
            },
            MptcpOption::RemoveAddr { address_ids } => Mptcp::RemoveAddr { address_ids },
            MptcpOption::Prio { backup } => Mptcp::MpPrio { backup },
            MptcpOption::Fail {
                data_sequence_number,
            } => Mptcp::MpFail {
                data_sequence_number,
            },
            MptcpOption::FastClose { receiver_key } => Mptcp::MpFastclose {
                receiver_key: Key(receiver_key),
            },
            MptcpOption::TcpRst { transient, reason } => Mptcp::MpTcprst { transient, reason },
        }
    }
}

/// Bytes, logged as lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hex(pub Vec<u8>);

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
    sinks: Sinks,
    clock: Clock,
    burst: Burst,
    tokens: Arc<Tokens>,
    /// The SYNs within the window, oldest first: when, from where, and
    /// whether each carried MP_JOIN.
    recent: VecDeque<(Instant, IpAddr, bool)>,
    sources: HashMap<IpAddr, Source>,
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
            sinks,
            clock,
            burst,
            tokens,
            recent: VecDeque::new(),
            sources: HashMap::new(),
        })
    }

    /// How many source addresses the observer holds state for.
    pub fn sources(&self) -> usize {
        self.sources.len()
    }

    /// Writes `packet`, which crossed `attachment` at `now`, and what it
    /// shows. Any bytes may come here.
    pub fn packet(
        &mut self,
        attachment: &Arc<str>,
        direction: Direction,
        packet: &[u8],
        now: Instant,
    ) -> io::Result<()> {
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
        self.sinks.pcap.write_all(&block)?;
        for observation in self.observe(attachment, direction, packet, now) {
            serde_json::to_writer(&mut self.sinks.log, &observation)?;
            self.sinks.log.write_all(b"\n")?;
        }
        self.sinks.log.flush()?;
        self.sinks.pcap.flush()
    }

    /// What `packet` shows.
    fn observe(
        &mut self,
        attachment: &Arc<str>,
        direction: Direction,
        packet: &[u8],
        now: Instant,
    ) -> Vec<Observation> {
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
        let at_us = self.clock.micros(now);
        let src = SocketAddr::new(header.src, u16::from_be_bytes([t[0], t[1]]));
        let dst = SocketAddr::new(header.dst, u16::from_be_bytes([t[2], t[3]]));
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let flags = t[13];
        let (options, options_fault) = match tcp::options(t) {
            Ok(options) => (options, None),
            Err(OptionsError::Malformed(read)) => (read, Some(OptionsFault::Malformed)),
            Err(OptionsError::Header) => (Vec::new(), Some(OptionsFault::Header)),
        };
        let tokens = &self.tokens;
        let mptcp: Vec<Mptcp> = options
            .iter()
            .filter_map(|o| match o {
                TcpOption::Unknown { kind, data } if *kind == mptcp::KIND => {
                    Some(Mptcp::read(data, |token| tokens.knows(token)))
                }
                _ => None,
            })
            .collect();
        let attachment = attachment.clone();
        if direction == Direction::Out {
            if flags & RST != 0 || flags & (SYN | ACK) == SYN | ACK {
                return vec![Observation::Answer {
                    at_us,
                    attachment,
                    src,
                    dst,
                    flags: Flags(flags),
                    mptcp,
                }];
            }
            return Vec::new();
        }
        if flags & (SYN | RST | ACK) == SYN {
            let join = mptcp.iter().any(|m| matches!(m, Mptcp::MpJoinSyn { .. }));
            let (gap_us, bursts) = self.syn(src.ip(), join, now);
            let mut out = vec![Observation::Syn {
                at_us,
                attachment,
                src,
                dst,
                seq,
                options: options.iter().map(Opt::from).collect(),
                options_fault,
                mptcp,
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
        let offset = usize::from(t[12] >> 4) * 4;
        let payload = t.get(offset..).filter(|_| offset >= 20).unwrap_or_default();
        if payload.is_empty() && mptcp.is_empty() && flags & FIN == 0 {
            return Vec::new();
        }
        vec![Observation::Segment {
            at_us,
            attachment,
            src,
            dst,
            flags: Flags(flags),
            seq,
            mptcp,
            payload: Hex(payload.to_vec()),
        }]
    }

    /// Counts a SYN from `src`, with MP_JOIN if `join`. Returns the time
    /// since its previous SYN within the window, and the bursts it starts.
    fn syn(
        &mut self,
        src: IpAddr,
        join: bool,
        now: Instant,
    ) -> (Option<u64>, Vec<(BurstKind, usize)>) {
        let window = self.burst.window;
        while let Some(&(at, from, joined)) = self.recent.front() {
            if now.since_start().saturating_sub(at.since_start()) < window {
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
        self.recent.push_back((now, src, join));
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
    use std::time::Duration;

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

    #[test]
    fn burst_state_lasts_one_window() {
        let mut observer = Observer::new(
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
        .unwrap();
        let at = |ms| Instant::from_since_start(Duration::from_millis(ms));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        assert_eq!(observer.syn(a, false, at(0)), (None, vec![]));
        assert_eq!(observer.syn(a, true, at(10)), (Some(10_000), vec![]));
        assert_eq!(observer.syn(b, false, at(20)), (None, vec![]));
        assert_eq!(
            observer.syn(a, true, at(30)),
            (Some(20_000), vec![(BurstKind::Syns, 3)])
        );
        // Flagged once while it lasts.
        assert_eq!(
            observer.syn(a, true, at(40)),
            (Some(10_000), vec![(BurstKind::Joins, 3)])
        );
        assert_eq!(observer.syn(a, false, at(50)), (Some(10_000), vec![]));
        assert_eq!(observer.sources(), 2);
        // A window later both have aged out; only the newest source is held.
        assert_eq!(observer.syn(b, false, at(500)), (None, vec![]));
        assert_eq!(observer.sources(), 1);
        assert_eq!(observer.recent.len(), 1);
    }
}
