//! MLDv2 reports: how an IPv6 host tells the routers on its link which
//! multicast groups it listens to, with no I/O.
//!
//! MLD (Multicast Listener Discovery) is IGMP for IPv6, carried in
//! ICMPv6. A host that joins a group sends an unsolicited report so that
//! routers and switches that watch MLD deliver the group's traffic to it.
//! An IPv6 host joins at least the solicited-node group of each of its
//! addresses (see [`ndp::solicited_node`](super::ndp::solicited_node)),
//! because neighbor solicitations for the address go there. This module
//! reads and writes the version 2 report of
//! [RFC 3810](https://www.rfc-editor.org/rfc/rfc3810), section 5.2. It
//! does not read queries: when to report, and what to say, is the caller's.
//!
//! [`Report`] is one report. [`Report::parse`] reads the ICMPv6 message
//! without its checksum, and [`Report::receive`] checks the checksum first
//! (RFC 4443, section 2.3). [`Report::emit`] writes the message with its
//! checksum. [`Report::packet`] writes the whole IPv6 packet as RFC 3810
//! section 5 requires: to all MLDv2-capable routers (ff02::16), with hop
//! limit 1, and with a Hop-by-Hop Options header carrying the Router Alert
//! option (RFC 2711) so routers look at a packet that is not addressed to
//! them. [`Report::from_packet`] reads such a packet and checks the same
//! things, as RFC 3810 section 6.2 asks of a router.
//!
//! Readers check lengths, the type, and what each address is for: a
//! record's group must be multicast, and a source must be neither
//! multicast nor the unspecified address. Writers check the same, so what
//! they write reads back. Auxiliary data in a record is skipped, since RFC
//! 3810 defines none (section 5.2.10), and never written. Reserved fields
//! are ignored and written as zero.
//!
//! ```
//! use std::net::Ipv6Addr;
//! use fictionet::stdlib::protocols::mld::{Record, RecordType, Report};
//! use fictionet::stdlib::protocols::ndp::solicited_node;
//!
//! // A host about to use 2001:db8::2 joins its solicited-node group,
//! // before it has a link-local address of its own.
//! let report = Report {
//!     records: vec![Record {
//!         kind: RecordType::ChangeToExclude,
//!         group: solicited_node("2001:db8::2".parse().unwrap()),
//!         sources: vec![],
//!     }],
//! };
//! let packet = report.packet(Ipv6Addr::UNSPECIFIED).unwrap();
//! assert_eq!(packet[7], 1, "hop limit");
//! assert_eq!(&packet[40..48], &[58, 0, 5, 2, 0, 0, 1, 0], "Router Alert");
//! assert_eq!(Report::from_packet(&packet).unwrap(), report);
//! ```

use std::net::Ipv6Addr;

use fictionet::stdlib::network::ip::{self, Fields, Header, protocol};

/// The ICMPv6 type of a version 2 report (RFC 3810, section 5.2).
pub const REPORT_V2: u8 = 143;
/// All MLDv2-capable routers, ff02::16 (RFC 3810, section 5.2.14), where
/// reports go.
pub const ALL_MLDV2_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);
/// The hop limit every MLD message is sent with, and the only one a
/// receiver accepts (RFC 3810, sections 5 and 6.2).
pub const HOP_LIMIT: u8 = 1;
/// The Hop-by-Hop Options header every report packet starts with: next
/// header ICMPv6, length 0 (8 bytes), the Router Alert option (type 5,
/// length 2) with value 0, which means MLD (RFC 2711, section 2.1), and a
/// PadN option of length 0 to fill the 8 bytes.
pub const ROUTER_ALERT_HEADER: [u8; 8] = [protocol::ICMPV6, 0, 5, 2, 0, 0, 1, 0];
/// The length of a report before its records.
pub const HEADER_LEN: usize = 8;
/// The length of a record before its sources.
pub const RECORD_HEADER_LEN: usize = 20;
/// The longest report this module reads or writes: the most an IPv6
/// packet's 16-bit payload length can describe (RFC 8200, section 3),
/// less the Hop-by-Hop Options header.
pub const MAX_MESSAGE: usize = 65_535 - ROUTER_ALERT_HEADER.len();

/// The type of a multicast address record (RFC 3810, section 5.2.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// MODE_IS_INCLUDE (1): the host hears the group from the listed
    /// sources only. Sent in answer to a query.
    ModeIsInclude,
    /// MODE_IS_EXCLUDE (2): the host hears the group from every source but
    /// the listed ones. Sent in answer to a query.
    ModeIsExclude,
    /// CHANGE_TO_INCLUDE_MODE (3): the host now hears the group from the
    /// listed sources only. With no sources, it has left the group.
    ChangeToInclude,
    /// CHANGE_TO_EXCLUDE_MODE (4): the host now hears the group from every
    /// source but the listed ones. With no sources, it has joined the
    /// group.
    ChangeToExclude,
    /// ALLOW_NEW_SOURCES (5): the host now also hears the listed sources.
    AllowNewSources,
    /// BLOCK_OLD_SOURCES (6): the host no longer hears the listed sources.
    BlockOldSources,
    /// Any other code. RFC 3810 section 5.2.12 asks receivers to ignore
    /// such records. The parser never gives a code from 1 to 6 here, and
    /// the writers refuse one, since it would read back as one of the
    /// types above.
    Other(u8),
}

impl RecordType {
    /// The record type's code on the wire.
    pub fn code(self) -> u8 {
        match self {
            RecordType::ModeIsInclude => 1,
            RecordType::ModeIsExclude => 2,
            RecordType::ChangeToInclude => 3,
            RecordType::ChangeToExclude => 4,
            RecordType::AllowNewSources => 5,
            RecordType::BlockOldSources => 6,
            RecordType::Other(c) => c,
        }
    }

    /// The record type a code stands for.
    pub fn from_code(c: u8) -> RecordType {
        match c {
            1 => RecordType::ModeIsInclude,
            2 => RecordType::ModeIsExclude,
            3 => RecordType::ChangeToInclude,
            4 => RecordType::ChangeToExclude,
            5 => RecordType::AllowNewSources,
            6 => RecordType::BlockOldSources,
            c => RecordType::Other(c),
        }
    }
}

/// One multicast address record of a report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record {
    /// What the record says about the group.
    pub kind: RecordType,
    /// The multicast group.
    pub group: Ipv6Addr,
    /// The sources the record lists.
    pub sources: Vec<Ipv6Addr>,
}

/// A version 2 report: the sender's state for some groups, or changes to
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Report {
    /// The records, in order.
    pub records: Vec<Record>,
}

/// Why bytes are not a valid report, or why a report cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The bytes end before the report does.
    Truncated,
    /// Bytes follow the last record.
    Trailing {
        /// Number of bytes after the report.
        remaining: usize,
    },
    /// The report is longer than [`MAX_MESSAGE`], or has more records, or a
    /// record more sources, than a 16-bit count holds.
    TooLong,
    /// The ICMPv6 type is not [`REPORT_V2`].
    UnknownType(u8),
    /// The ICMPv6 checksum is wrong.
    Checksum,
    /// A group is not multicast, or a source is multicast or unspecified.
    Address(Ipv6Addr),
    /// The bytes are not an IPv6 packet whose header can be read, or the
    /// packet is a fragment or does not carry ICMPv6.
    NotIpv6,
    /// The packet's hop limit is not [`HOP_LIMIT`].
    HopLimit(u8),
    /// The packet's source is neither link-local nor the unspecified
    /// address (RFC 3810, sections 5.2.13 and 6.2).
    Source(Ipv6Addr),
    /// The packet has no Hop-by-Hop Options header with the Router Alert
    /// option for MLD.
    NoRouterAlert,
    /// A record type is [`RecordType::Other`] with a code from 1 to 6.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("MLDv2 report cut short"),
            Error::Trailing { remaining } => write!(f, "{remaining} bytes after the MLDv2 report"),
            Error::TooLong => f.write_str("MLDv2 report too long"),
            Error::UnknownType(t) => write!(f, "ICMPv6 type {t} is not an MLDv2 report"),
            Error::Checksum => f.write_str("wrong ICMPv6 checksum"),
            Error::Address(a) => write!(f, "{a} is wrong for its field in an MLDv2 report"),
            Error::NotIpv6 => f.write_str("not an unfragmented IPv6 packet carrying ICMPv6"),
            Error::HopLimit(h) => write!(f, "MLDv2 report with hop limit {h}"),
            Error::Source(a) => write!(f, "MLDv2 report from {a}"),
            Error::NoRouterAlert => f.write_str("MLDv2 report without the Router Alert option"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
        }
    }
}

impl std::error::Error for Error {}

/// Checks that `group` is multicast and every source is a unicast address.
fn check_record(group: Ipv6Addr, sources: &[Ipv6Addr]) -> Result<(), Error> {
    if !group.is_multicast() {
        return Err(Error::Address(group));
    }
    match sources
        .iter()
        .find(|s| s.is_multicast() || s.is_unspecified())
    {
        Some(s) => Err(Error::Address(*s)),
        None => Ok(()),
    }
}

/// Checks the source of a report packet: link-local, or the unspecified
/// address before the host has a link-local address (RFC 3810, section
/// 5.2.13).
fn check_source(source: Ipv6Addr) -> Result<(), Error> {
    if source.is_unicast_link_local() || source.is_unspecified() {
        Ok(())
    } else {
        Err(Error::Source(source))
    }
}

impl Report {
    /// Reads a report from the ICMPv6 bytes alone, without checking the
    /// checksum. Bytes after the last record are an error.
    pub fn parse(msg: &[u8]) -> Result<Report, Error> {
        if msg.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let &t = msg.first().ok_or(Error::Truncated)?;
        if t != REPORT_V2 {
            return Err(Error::UnknownType(t));
        }
        if msg.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let count = u16::from_be_bytes([msg[6], msg[7]]);
        let mut at = HEADER_LEN;
        // No more is reserved than the bytes can hold.
        let mut records = Vec::with_capacity(
            usize::from(count).min((msg.len() - HEADER_LEN) / RECORD_HEADER_LEN),
        );
        for _ in 0..count {
            let r = msg
                .get(at..at + RECORD_HEADER_LEN)
                .ok_or(Error::Truncated)?;
            let aux = usize::from(r[1]) * 4;
            let n = usize::from(u16::from_be_bytes([r[2], r[3]]));
            let group = Ipv6Addr::from(<[u8; 16]>::try_from(&r[4..20]).unwrap());
            let start = at + RECORD_HEADER_LEN;
            let end = start + n * 16;
            let sources: Vec<Ipv6Addr> = msg
                .get(start..end)
                .ok_or(Error::Truncated)?
                .as_chunks::<16>()
                .0
                .iter()
                .map(|s| Ipv6Addr::from(*s))
                .collect();
            check_record(group, &sources)?;
            at = end + aux;
            if at > msg.len() {
                return Err(Error::Truncated);
            }
            records.push(Record {
                kind: RecordType::from_code(r[0]),
                group,
                sources,
            });
        }
        match msg.len() - at {
            0 => Ok(Report { records }),
            remaining => Err(Error::Trailing { remaining }),
        }
    }

    /// Reads a report as a receiver must: checks the ICMPv6 checksum over
    /// the pseudo-header of `source` and `destination` (RFC 4443, section
    /// 2.3), then [`parse`](Report::parse)s it.
    pub fn receive(source: Ipv6Addr, destination: Ipv6Addr, msg: &[u8]) -> Result<Report, Error> {
        if msg.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        if ip::transport_checksum(source.into(), destination.into(), protocol::ICMPV6, msg) != 0 {
            return Err(Error::Checksum);
        }
        Report::parse(msg)
    }

    /// Reads a whole IPv6 packet as a router must (RFC 3810, section 6.2):
    /// hop limit 1, a link-local or unspecified source, a Hop-by-Hop
    /// Options header with the Router Alert option for MLD, and then a
    /// report with a good checksum. Any destination is taken.
    pub fn from_packet(packet: &[u8]) -> Result<Report, Error> {
        let h = Header::parse(packet).ok_or(Error::NotIpv6)?;
        let (std::net::IpAddr::V6(source), std::net::IpAddr::V6(destination)) = (h.src, h.dst)
        else {
            return Err(Error::NotIpv6);
        };
        if h.protocol != protocol::ICMPV6 || h.fragment.is_some() {
            return Err(Error::NotIpv6);
        }
        if packet[7] != HOP_LIMIT {
            return Err(Error::HopLimit(packet[7]));
        }
        check_source(source)?;
        if !has_router_alert(packet) {
            return Err(Error::NoRouterAlert);
        }
        Report::receive(source, destination, h.payload(packet))
    }

    /// The ICMPv6 message from `source` to `destination`, with its
    /// checksum filled in. Fails if a group or source is wrong for its
    /// field, a record type is [`RecordType::Other`] with a known code, or
    /// the report is longer than [`MAX_MESSAGE`] or its counts do not fit
    /// 16 bits.
    pub fn emit(&self, source: Ipv6Addr, destination: Ipv6Addr) -> Result<Vec<u8>, Error> {
        let mut len = HEADER_LEN;
        for r in &self.records {
            if let RecordType::Other(1..=6) = r.kind {
                return Err(Error::Unwritable);
            }
            check_record(r.group, &r.sources)?;
            if r.sources.len() > usize::from(u16::MAX) {
                return Err(Error::TooLong);
            }
            len += RECORD_HEADER_LEN + r.sources.len() * 16;
        }
        let count = u16::try_from(self.records.len()).map_err(|_| Error::TooLong)?;
        if len > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&[REPORT_V2, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&count.to_be_bytes());
        for r in &self.records {
            out.push(r.kind.code());
            out.push(0);
            out.extend_from_slice(&(r.sources.len() as u16).to_be_bytes());
            out.extend_from_slice(&r.group.octets());
            for s in &r.sources {
                out.extend_from_slice(&s.octets());
            }
        }
        let sum = ip::transport_checksum(source.into(), destination.into(), protocol::ICMPV6, &out);
        out[2..4].copy_from_slice(&sum.to_be_bytes());
        Ok(out)
    }

    /// The whole IPv6 packet from `source` to [`ALL_MLDV2_ROUTERS`], with
    /// hop limit 1 and the Router Alert option, as RFC 3810 section 5
    /// requires. `source` must be link-local, or unspecified while the host
    /// has no link-local address yet (section 5.2.13).
    pub fn packet(&self, source: Ipv6Addr) -> Result<Vec<u8>, Error> {
        check_source(source)?;
        let msg = self.emit(source, ALL_MLDV2_ROUTERS)?;
        let payload = [&ROUTER_ALERT_HEADER[..], &msg].concat();
        Ok(ip::packet_with(
            source.into(),
            ALL_MLDV2_ROUTERS.into(),
            0,
            Fields {
                ttl: HOP_LIMIT,
                ..Fields::default()
            },
            &payload,
        )
        .into_vec())
    }
}

/// Whether `packet`, an IPv6 packet [`Header::parse`] has read, starts
/// with a Hop-by-Hop Options header that holds the Router Alert option
/// with value 0, for MLD (RFC 2711, section 2.1).
fn has_router_alert(packet: &[u8]) -> bool {
    // Next header 0 is Hop-by-Hop Options, which may only come first.
    if packet[6] != 0 {
        return false;
    }
    let Some(&units) = packet.get(41) else {
        return false;
    };
    let Some(mut options) = packet.get(42..40 + (usize::from(units) + 1) * 8) else {
        return false;
    };
    while let Some(&kind) = options.first() {
        // Pad1 is one byte with no length.
        if kind == 0 {
            options = &options[1..];
            continue;
        }
        let Some(&len) = options.get(1) else {
            return false;
        };
        let Some(data) = options.get(2..2 + usize::from(len)) else {
            return false;
        };
        if kind == 5 && data == [0, 0] {
            return true;
        }
        options = &options[2 + usize::from(len)..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn sample() -> Report {
        Report {
            records: vec![
                Record {
                    kind: RecordType::ChangeToExclude,
                    group: addr("ff02::1:ff12:3456"),
                    sources: vec![],
                },
                Record {
                    kind: RecordType::ModeIsInclude,
                    group: addr("ff3e::8000:1"),
                    sources: vec![addr("2001:db8::1"), addr("fe80::9")],
                },
                Record {
                    kind: RecordType::Other(9),
                    group: addr("ff05::2"),
                    sources: vec![],
                },
            ],
        }
    }

    const SOURCE: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x5054, 0xff, 0xfe12, 0x3456);

    #[test]
    fn reports_round_trip() {
        for report in [sample(), Report { records: vec![] }] {
            let msg = report.emit(SOURCE, ALL_MLDV2_ROUTERS).unwrap();
            assert_eq!(Report::parse(&msg), Ok(report.clone()));
            assert_eq!(
                Report::receive(SOURCE, ALL_MLDV2_ROUTERS, &msg),
                Ok(report.clone())
            );
            for source in [SOURCE, Ipv6Addr::UNSPECIFIED] {
                let packet = report.packet(source).unwrap();
                assert_eq!(Report::from_packet(&packet), Ok(report.clone()));
            }
        }
    }

    #[test]
    fn a_report_from_its_layout() {
        // RFC 3810 section 5.2: type 143, reserved, checksum, reserved,
        // the number of records; then each record (5.2.4 to 5.2.12): type,
        // auxiliary data length, number of sources, group, sources.
        let mut msg = vec![143, 0, 0, 0, 0, 0, 0, 2];
        msg.extend_from_slice(&[4, 0, 0, 0]);
        msg.extend_from_slice(&addr("ff02::1:ff12:3456").octets());
        msg.extend_from_slice(&[1, 1, 0, 1]);
        msg.extend_from_slice(&addr("ff3e::8000:1").octets());
        msg.extend_from_slice(&addr("2001:db8::1").octets());
        msg.extend_from_slice(&[0xaa; 4]); // one word of auxiliary data
        let sum = ip::transport_checksum(
            SOURCE.into(),
            ALL_MLDV2_ROUTERS.into(),
            protocol::ICMPV6,
            &msg,
        );
        msg[2..4].copy_from_slice(&sum.to_be_bytes());
        let expected = Report {
            records: vec![
                Record {
                    kind: RecordType::ChangeToExclude,
                    group: addr("ff02::1:ff12:3456"),
                    sources: vec![],
                },
                Record {
                    kind: RecordType::ModeIsInclude,
                    group: addr("ff3e::8000:1"),
                    sources: vec![addr("2001:db8::1")],
                },
            ],
        };
        assert_eq!(
            Report::receive(SOURCE, ALL_MLDV2_ROUTERS, &msg),
            Ok(expected.clone())
        );
        // Written again, without the auxiliary data.
        let again = expected.emit(SOURCE, ALL_MLDV2_ROUTERS).unwrap();
        assert_eq!(again.len(), msg.len() - 4);
        assert_eq!(again[29], 0, "auxiliary data length");
        assert_eq!(&again[4..29], &msg[4..29]);
        assert_eq!(&again[30..], &msg[30..msg.len() - 4]);
    }

    #[test]
    fn the_packet_has_the_header_rfc_3810_requires() {
        let packet = sample().packet(SOURCE).unwrap();
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(packet[6], 0, "hop-by-hop options first");
        assert_eq!(packet[7], 1, "hop limit");
        assert_eq!(&packet[8..24], &SOURCE.octets());
        assert_eq!(&packet[24..40], &ALL_MLDV2_ROUTERS.octets());
        assert_eq!(&packet[40..48], &[58, 0, 5, 2, 0, 0, 1, 0]);
        assert_eq!(packet[48], REPORT_V2);
        assert_eq!(
            usize::from(u16::from_be_bytes([packet[4], packet[5]])),
            packet.len() - 40
        );
    }

    #[test]
    fn packets_without_what_rfc_3810_requires_are_refused() {
        let good = sample().packet(SOURCE).unwrap();
        let mut hop = good.clone();
        hop[7] = 2;
        assert_eq!(Report::from_packet(&hop), Err(Error::HopLimit(2)));
        // No Router Alert: the option's type changed to PadN.
        let mut no_alert = good.clone();
        no_alert[42] = 1;
        assert_eq!(Report::from_packet(&no_alert), Err(Error::NoRouterAlert));
        // Router Alert for RSVP (value 1), not MLD.
        let mut rsvp = good.clone();
        rsvp[45] = 1;
        assert_eq!(Report::from_packet(&rsvp), Err(Error::NoRouterAlert));
        // No Hop-by-Hop header at all.
        let bare = ip::packet_with(
            SOURCE.into(),
            ALL_MLDV2_ROUTERS.into(),
            protocol::ICMPV6,
            Fields {
                ttl: 1,
                ..Fields::default()
            },
            &good[48..],
        )
        .to_vec();
        assert_eq!(Report::from_packet(&bare), Err(Error::NoRouterAlert));
        let global = addr("2001:db8::2");
        assert_eq!(sample().packet(global), Err(Error::Source(global)));
        let mut from_global = good.clone();
        from_global[8..24].copy_from_slice(&global.octets());
        assert_eq!(
            Report::from_packet(&from_global),
            Err(Error::Source(global))
        );
        let mut bad_sum = good.clone();
        bad_sum[50] ^= 1;
        assert_eq!(Report::from_packet(&bad_sum), Err(Error::Checksum));
        assert_eq!(Report::from_packet(&good[..39]), Err(Error::NotIpv6));
    }

    #[test]
    fn every_truncation_fails_without_panicking() {
        let msg = sample().emit(SOURCE, ALL_MLDV2_ROUTERS).unwrap();
        for len in 0..msg.len() {
            assert!(Report::parse(&msg[..len]).is_err(), "{len}");
            assert!(Report::receive(SOURCE, ALL_MLDV2_ROUTERS, &msg[..len]).is_err());
        }
        let packet = sample().packet(SOURCE).unwrap();
        for len in 0..packet.len() {
            assert!(Report::from_packet(&packet[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn every_byte_value_at_every_position_reads_or_fails_cleanly() {
        let msg = sample().emit(SOURCE, ALL_MLDV2_ROUTERS).unwrap();
        for at in 0..msg.len() {
            for value in [0, 1, 2, 4, 6, 0x7f, 0x80, 0xff] {
                let mut b = msg.clone();
                b[at] = value;
                if let Ok(read) = Report::parse(&b) {
                    let again = read.emit(SOURCE, ALL_MLDV2_ROUTERS).unwrap();
                    assert_eq!(Report::parse(&again), Ok(read));
                }
            }
        }
        let packet = sample().packet(SOURCE).unwrap();
        for at in 0..packet.len() {
            for value in [0, 1, 2, 5, 0xff] {
                let mut b = packet.clone();
                b[at] = value;
                let _ = Report::from_packet(&b);
            }
        }
    }

    #[test]
    fn trailing_bytes_and_wrong_addresses_are_refused() {
        let mut msg = sample().emit(SOURCE, ALL_MLDV2_ROUTERS).unwrap();
        msg.push(0);
        assert_eq!(Report::parse(&msg), Err(Error::Trailing { remaining: 1 }));
        assert_eq!(
            Report::parse(&[130, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::UnknownType(130))
        );
        for (group, sources) in [
            (addr("2001:db8::1"), vec![]),
            (addr("ff02::16"), vec![addr("ff02::1")]),
            (addr("ff02::16"), vec![Ipv6Addr::UNSPECIFIED]),
        ] {
            let bad = sources.first().copied().unwrap_or(group);
            let report = Report {
                records: vec![Record {
                    kind: RecordType::ModeIsInclude,
                    group,
                    sources: sources.clone(),
                }],
            };
            assert_eq!(
                report.emit(SOURCE, ALL_MLDV2_ROUTERS),
                Err(Error::Address(bad))
            );
            // The same bytes, written by hand, read as the same error.
            let mut b = vec![143, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, sources.len() as u8];
            b.extend_from_slice(&group.octets());
            for s in &sources {
                b.extend_from_slice(&s.octets());
            }
            assert_eq!(Report::parse(&b), Err(Error::Address(bad)));
        }
        let known = Report {
            records: vec![Record {
                kind: RecordType::Other(4),
                group: addr("ff02::16"),
                sources: vec![],
            }],
        };
        assert_eq!(
            known.emit(SOURCE, ALL_MLDV2_ROUTERS),
            Err(Error::Unwritable)
        );
        let huge = Report {
            records: vec![Record {
                kind: RecordType::ModeIsInclude,
                group: addr("ff02::16"),
                sources: vec![addr("2001:db8::1"); 4096],
            }],
        };
        assert_eq!(huge.emit(SOURCE, ALL_MLDV2_ROUTERS), Err(Error::TooLong));
        // A count of records the bytes cannot hold reserves nothing extra
        // and fails.
        assert_eq!(
            Report::parse(&[143, 0, 0, 0, 0, 0, 0xff, 0xff]),
            Err(Error::Truncated)
        );
    }
}
