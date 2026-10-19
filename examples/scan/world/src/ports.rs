//! Passive IPv4 probe tracking on the scanner's link.
//!
//! Snapshots and deltas own their rows and use run time in whole milliseconds.
//! Rows stay for the run. At capacity, new keys count as untracked probes.
//! Repeated probes advance revisions but keep the last answered state.
//! Facts mark new rows and state changes; deltas contain only each row's
//! latest version. JSON bounds apply to compact serialization of these views.
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use fictionet::events::{Level, opt};
use fictionet::stdlib::network::{Direction, ip};
use fictionet::sync::Mutex;
use fictionet::{Cx, Packet};
use serde::{Deserialize, Serialize};

use crate::{MACHINES, OFFICE};

/// Maximum number of distinct host, protocol and port rows in a run.
pub const MAX_ROWS: usize = 16_384;

/// The transport used by a probe. TCP sorts before UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// The latest answered probe's result, or no answer yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Unanswered,
    Open,
    Closed,
    Unreachable,
}

impl PortState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unanswered => "unanswered",
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Unreachable => "unreachable",
        }
    }
}

/// One port's probes and latest answered state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRow {
    pub host: Ipv4Addr,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub first_probe_ms: u64,
    pub last_probe_ms: u64,
    pub probes: u64,
    pub revision: u64,
}

impl PortRow {
    /// Maximum compact JSON size, with the largest address, port and counters.
    pub const MAX_JSON_BYTES: usize = concat!(
        r#"{"host":"255.255.255.255","port":65535,"protocol":"tcp","state":"unreachable","first_probe_ms":"#,
        "18446744073709551615",
        r#","last_probe_ms":"#,
        "18446744073709551615",
        r#","probes":"#,
        "18446744073709551615",
        r#","revision":"#,
        "18446744073709551615}"
    ).len();
}

/// Whether a machine runs inside the world or behind a real attachment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineKind {
    Simulated,
    Real,
}

/// An office machine's label and address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Machine {
    pub name: String,
    pub addr: Ipv4Addr,
    pub kind: MachineKind,
}

fn machines() -> Vec<Machine> {
    MACHINES
        .iter()
        .map(|m| Machine {
            name: m.name.into(),
            addr: Ipv4Addr::new(10, 0, 0, m.host),
            kind: m.kind,
        })
        .collect()
}

const fn machines_json_bytes() -> usize {
    let mut n = 2;
    let mut i = 0;
    while i < MACHINES.len() {
        n += r#"{"name":"","addr":"255.255.255.255","kind":"simulated"}"#.len()
            + MACHINES[i].name.len()
            + 1;
        i += 1;
    }
    n
}

/// A complete port map. Rows sort by address, protocol, then port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMap {
    pub revision: u64,
    pub at_ms: u64,
    pub max_rows: usize,
    pub untracked: u64,
    pub machines: Vec<Machine>,
    pub rows: Vec<PortRow>,
}

impl PortMap {
    /// Compact JSON bound for snapshots produced by [`Ports`].
    pub const MAX_JSON_BYTES: usize =
        r#"{"revision":18446744073709551615,"at_ms":18446744073709551615,"max_rows":,"untracked":18446744073709551615,"machines":,"rows":[]}"#.len()
        + (MAX_ROWS.ilog10() as usize + 1) + machines_json_bytes() + MAX_ROWS * (PortRow::MAX_JSON_BYTES + 1);
}

/// Latest versions of rows changed after a revision, sorted as a snapshot.
/// This is a delta of rows, not a history of every probe or answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortChanges {
    pub from_revision: u64,
    pub revision: u64,
    pub at_ms: u64,
    pub untracked: u64,
    pub rows: Vec<PortRow>,
}

impl PortChanges {
    /// Compact JSON bound for deltas produced by [`Ports`].
    pub const MAX_JSON_BYTES: usize =
        r#"{"from_revision":18446744073709551615,"revision":18446744073709551615,"at_ms":18446744073709551615,"untracked":18446744073709551615,"rows":[]}"#.len()
        + MAX_ROWS * (PortRow::MAX_JSON_BYTES + 1);
}

/// A shared view of the scanner's probes, readable outside the world.
#[derive(Clone)]
pub struct Ports(Arc<Mutex<Tracker>>);

impl Ports {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Tracker::new(MAX_ROWS))))
    }

    /// Copies the complete map and the five office labels.
    pub fn snapshot(&self) -> PortMap {
        self.0.lock().snapshot()
    }

    /// Copies rows whose last change is newer than `revision`.
    /// At or past the current revision, the rows are empty.
    pub fn changes_since(&self, revision: u64) -> PortChanges {
        self.0.lock().changes_since(revision)
    }

    pub(crate) fn tap(&self, fcx: &Cx, direction: Direction, packet: &Packet) -> bool {
        let signal = self.0.lock().packet(
            direction,
            &packet.0,
            fcx.now().since_start().as_millis() as u64,
        );
        match signal {
            Signal::Port(row, previous) => fcx.emit("scan", "port", |e| {
                e.level(Level::Info)
                    .summary(format_args!(
                        "{}:{}/{} {}",
                        row.host,
                        row.port,
                        row.protocol.as_str(),
                        row.state.as_str()
                    ))
                    .field("host", row.host.to_string())
                    .field("port", u32::from(row.port))
                    .field("protocol", row.protocol.as_str())
                    .field("state", row.state.as_str())
                    .field("previous", opt(previous.map(PortState::as_str)))
                    .field("first_probe_ms", row.first_probe_ms)
                    .field("last_probe_ms", row.last_probe_ms)
                    .field("probes", row.probes)
                    .field("revision", row.revision)
            }),
            Signal::Full => fcx.emit("scan", "full", |e| {
                e.level(Level::Notice).field("max_rows", MAX_ROWS as u64)
            }),
            Signal::None => {}
        }
        true
    }
}

type Key = (Ipv4Addr, Protocol, u16);
struct Tracked {
    row: PortRow,
    source: IpAddr,
    source_port: u16,
    sequence: u32,
}

struct Tracker {
    rows: BTreeMap<Key, Tracked>,
    max_rows: usize,
    revision: u64,
    at_ms: u64,
    untracked: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum Signal {
    None,
    Port(PortRow, Option<PortState>),
    Full,
}

impl Tracker {
    fn new(max_rows: usize) -> Self {
        Self {
            rows: BTreeMap::new(),
            max_rows,
            revision: 0,
            at_ms: 0,
            untracked: 0,
        }
    }

    fn snapshot(&self) -> PortMap {
        PortMap {
            revision: self.revision,
            at_ms: self.at_ms,
            max_rows: self.max_rows,
            untracked: self.untracked,
            machines: machines(),
            rows: self.rows.values().map(|t| t.row.clone()).collect(),
        }
    }

    fn changes_since(&self, revision: u64) -> PortChanges {
        PortChanges {
            from_revision: revision,
            revision: self.revision,
            at_ms: self.at_ms,
            untracked: self.untracked,
            rows: self
                .rows
                .values()
                .filter(|t| t.row.revision > revision)
                .map(|t| t.row.clone())
                .collect(),
        }
    }

    fn packet(&mut self, direction: Direction, bytes: &[u8], at_ms: u64) -> Signal {
        let Some(h) = header(bytes, false) else {
            return Signal::None;
        };
        let transport = h.payload(bytes);
        if direction == Direction::ToInner && h.protocol == 1 {
            if transport.len() < 8 || transport[0] != 3 {
                return Signal::None;
            }
            let quoted = &transport[8..];
            let Some(q) = header(quoted, true) else {
                return Signal::None;
            };
            let Some(protocol) = protocol(q.protocol) else {
                return Signal::None;
            };
            let IpAddr::V4(host) = q.dst else {
                return Signal::None;
            };
            let t = q.payload(quoted);
            if t.len() < 8 {
                return Signal::None;
            }
            let key = (host, protocol, word(t, 2));
            let Some(row) = self.rows.get(&key) else {
                return Signal::None;
            };
            if row.source != q.src
                || h.dst != row.source
                || row.source_port != word(t, 0)
                || (protocol == Protocol::Tcp && row.sequence != dword(t, 4))
            {
                return Signal::None;
            }
            return self.answer(
                key,
                if transport[1] == 3 {
                    PortState::Closed
                } else {
                    PortState::Unreachable
                },
                at_ms,
            );
        }
        let Some(protocol) = protocol(h.protocol) else {
            return Signal::None;
        };
        let flags = match protocol {
            Protocol::Tcp => {
                if transport.len() < 20 {
                    return Signal::None;
                }
                let len = usize::from(transport[12] >> 4) * 4;
                if len < 20 || len > transport.len() {
                    return Signal::None;
                }
                transport[13]
            }
            Protocol::Udp => {
                if transport.len() < 8 {
                    return Signal::None;
                }
                let len = usize::from(word(transport, 4));
                if len < 8 || (len > transport.len() && h.fragment.is_none()) {
                    return Signal::None;
                }
                0
            }
        };
        match direction {
            Direction::FromInner => {
                if !OFFICE.contains(h.dst) || (protocol == Protocol::Tcp && flags & 0x17 != 0x02) {
                    return Signal::None;
                }
                let IpAddr::V4(host) = h.dst else {
                    return Signal::None;
                };
                let key = (host, protocol, word(transport, 2));
                let created = !self.rows.contains_key(&key);
                if created && self.rows.len() == self.max_rows {
                    self.untracked += 1;
                    return if self.untracked == 1 {
                        Signal::Full
                    } else {
                        Signal::None
                    };
                }
                self.revision += 1;
                self.at_ms = at_ms;
                let tracked = self.rows.entry(key).or_insert_with(|| Tracked {
                    row: PortRow {
                        host,
                        protocol,
                        port: key.2,
                        state: PortState::Unanswered,
                        first_probe_ms: at_ms,
                        last_probe_ms: at_ms,
                        probes: 0,
                        revision: 0,
                    },
                    source: h.src,
                    source_port: 0,
                    sequence: 0,
                });
                tracked.row.last_probe_ms = at_ms;
                tracked.row.probes += 1;
                tracked.row.revision = self.revision;
                tracked.source = h.src;
                tracked.source_port = word(transport, 0);
                tracked.sequence = if protocol == Protocol::Tcp {
                    dword(transport, 4)
                } else {
                    0
                };
                if created {
                    Signal::Port(tracked.row.clone(), None)
                } else {
                    Signal::None
                }
            }
            Direction::ToInner => {
                let IpAddr::V4(host) = h.src else {
                    return Signal::None;
                };
                let key = (host, protocol, word(transport, 0));
                let Some(row) = self.rows.get(&key) else {
                    return Signal::None;
                };
                if h.dst != row.source || word(transport, 2) != row.source_port {
                    return Signal::None;
                }
                let state = match protocol {
                    Protocol::Udp => PortState::Open,
                    Protocol::Tcp => {
                        if flags & 0x10 == 0 || dword(transport, 8) != row.sequence.wrapping_add(1)
                        {
                            return Signal::None;
                        }
                        if flags & 4 != 0 {
                            PortState::Closed
                        } else if flags & 2 != 0 {
                            PortState::Open
                        } else {
                            return Signal::None;
                        }
                    }
                };
                self.answer(key, state, at_ms)
            }
        }
    }

    fn answer(&mut self, key: Key, state: PortState, at_ms: u64) -> Signal {
        let row = &mut self.rows.get_mut(&key).unwrap().row;
        if row.state == state {
            return Signal::None;
        }
        let previous = row.state;
        self.revision += 1;
        self.at_ms = at_ms;
        row.state = state;
        row.revision = self.revision;
        Signal::Port(row.clone(), Some(previous))
    }
}

fn protocol(number: u8) -> Option<Protocol> {
    match number {
        6 => Some(Protocol::Tcp),
        17 => Some(Protocol::Udp),
        _ => None,
    }
}

fn header(bytes: &[u8], quoted: bool) -> Option<ip::Header> {
    if bytes.first()? >> 4 != 4 {
        return None;
    }
    let h = if quoted {
        ip::Header::parse_truncated(bytes)?
    } else {
        ip::Header::parse(bytes)?
    };
    if h.fragment.is_some_and(|f| f.offset != 0) || ip::checksum(&bytes[..h.payload.start]) != 0 {
        return None;
    }
    Some(h)
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use Direction::{FromInner, ToInner};
    use PortState::{Closed, Open, Unanswered, Unreachable};

    const SCANNER: Ipv4Addr = Ipv4Addr::new(10, 0, 9, 2);
    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);

    fn tcp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ports: (u16, u16),
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut t = vec![0; 20];
        t[..2].copy_from_slice(&ports.0.to_be_bytes());
        t[2..4].copy_from_slice(&ports.1.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        let sum = ip::transport_checksum(src.into(), dst.into(), 6, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        ip::packet(src.into(), dst.into(), 6, &t).0
    }

    fn syn(port: u16, source: u16, seq: u32) -> Vec<u8> {
        tcp(SCANNER, HOST, (source, port), seq, 0, 2)
    }
    fn reply(source: u16, ack: u32, flags: u8) -> Vec<u8> {
        tcp(HOST, SCANNER, (80, source), 7, ack, flags)
    }

    fn udp(src: Ipv4Addr, dst: Ipv4Addr, ports: (u16, u16)) -> Vec<u8> {
        let mut t = [0; 8];
        fictionet::stdlib::network::udp::encode(
            (src, ports.0).into(),
            (dst, ports.1).into(),
            b"",
            &mut t,
        )
        .unwrap();
        ip::packet(src.into(), dst.into(), 17, &t).0
    }

    fn unreachable(quote: &[u8], code: u8) -> Vec<u8> {
        let mut t = vec![3, code, 0, 0, 0, 0, 0, 0];
        t.extend_from_slice(quote);
        let sum = ip::checksum(&t);
        t[2..4].copy_from_slice(&sum.to_be_bytes());
        ip::packet(Ipv4Addr::new(10, 0, 9, 1).into(), SCANNER.into(), 1, &t).0
    }

    fn state(t: &Tracker, expected: PortState, probes: u64, revision: u64) {
        assert_eq!(
            t.snapshot().rows,
            [PortRow {
                host: HOST,
                port: 80,
                protocol: Protocol::Tcp,
                state: expected,
                first_probe_ms: 10,
                last_probe_ms: if probes == 1 { 10 } else { 20 },
                probes,
                revision,
            }]
        );
        assert_eq!(t.revision, revision);
    }

    #[test]
    fn tcp_answers_match_only_the_latest_probe_and_repeats_keep_the_answer() {
        let mut t = Tracker::new(10);
        let initial = t.packet(FromInner, &syn(80, 4000, 100), 10);
        state(&t, Unanswered, 1, 1);
        assert_eq!(initial, Signal::Port(t.snapshot().rows[0].clone(), None));
        assert_eq!(
            t.packet(ToInner, &reply(4000, 101, 0x12), 14),
            Signal::Port(
                PortRow {
                    state: Open,
                    revision: 2,
                    ..t.snapshot().rows[0].clone()
                },
                Some(Unanswered)
            )
        );
        state(&t, Open, 1, 2);
        assert_eq!(t.at_ms, 14);
        assert_eq!(t.packet(ToInner, &reply(4000, 101, 0x12), 15), Signal::None);
        assert_eq!(t.at_ms, 14);
        assert_eq!(t.packet(FromInner, &syn(80, 4001, 200), 20), Signal::None);
        state(&t, Open, 2, 3);
        for packet in [
            reply(4000, 101, 0x14),
            reply(4001, 101, 0x14),
            reply(4001, 201, 4),
            reply(4001, 0, 0x14),
            reply(4001, 201, 0x10),
            tcp(HOST, Ipv4Addr::new(10, 0, 9, 3), (80, 4001), 0, 201, 0x14),
        ] {
            assert_eq!(t.packet(ToInner, &packet, 21), Signal::None);
            state(&t, Open, 2, 3);
        }
        assert!(matches!(
            t.packet(ToInner, &reply(4001, 201, 0x14), 24),
            Signal::Port(_, Some(Open))
        ));
        state(&t, Closed, 2, 4);
        assert_eq!(t.packet(ToInner, &reply(4001, 201, 0x14), 25), Signal::None);
        assert_eq!(t.at_ms, 24);
        assert!(matches!(
            t.packet(ToInner, &reply(4001, 201, 0x12), 26),
            Signal::Port(_, Some(Closed))
        ));
        state(&t, Open, 2, 5);
        t.packet(FromInner, &syn(80, 4001, u32::MAX), 20);
        t.packet(ToInner, &reply(4001, 0, 0x14), 30);
        state(&t, Closed, 3, 7);
    }

    #[test]
    fn udp_and_icmp_match_the_quoted_transport_and_source() {
        let mut t = Tracker::new(10);
        let probe = udp(SCANNER, HOST, (4000, 53));
        t.packet(FromInner, &probe, 1);
        assert_eq!(
            t.packet(ToInner, &udp(HOST, SCANNER, (53, 4001)), 2),
            Signal::None
        );
        assert!(matches!(
            t.packet(ToInner, &udp(HOST, SCANNER, (53, 4000)), 3),
            Signal::Port(PortRow { state: Open, .. }, Some(Unanswered))
        ));
        for (code, expected) in [
            (3, Closed),
            (1, Unreachable),
            (0, Unreachable),
            (13, Unreachable),
        ] {
            let prior = t.revision;
            t.packet(ToInner, &unreachable(&probe[..28], code), 4);
            assert_eq!(t.snapshot().rows[0].state, expected);
            assert_eq!(
                t.revision,
                if code == 3 || code == 1 {
                    prior + 1
                } else {
                    prior
                }
            );
        }
        t.packet(FromInner, &udp(SCANNER, HOST, (4001, 53)), 5);
        assert_eq!(
            t.packet(ToInner, &unreachable(&probe[..28], 3), 6),
            Signal::None
        );
        let other = udp(Ipv4Addr::new(10, 0, 9, 3), HOST, (4001, 53));
        assert_eq!(t.packet(ToInner, &unreachable(&other, 3), 6), Signal::None);
        let tcp = syn(80, 4000, 100);
        t.packet(FromInner, &tcp, 10);
        t.packet(FromInner, &syn(80, 4000, 200), 20);
        assert_eq!(
            t.packet(ToInner, &unreachable(&tcp[..28], 3), 21),
            Signal::None
        );
        assert!(matches!(
            t.packet(ToInner, &unreachable(&syn(80, 4000, 200)[..28], 3), 22),
            Signal::Port(PortRow { state: Closed, .. }, Some(Unanswered))
        ));
        for quote in [&syn(81, 4000, 200)[..28], &syn(80, 4001, 200)[..28]] {
            assert_eq!(t.packet(ToInner, &unreachable(quote, 1), 23), Signal::None);
        }
    }

    #[test]
    fn only_office_syns_and_udp_create_rows() {
        let mut t = Tracker::new(10);
        for flags in [0, 1, 4, 0x10, 0x12, 3, 6, 0x13] {
            assert_eq!(
                t.packet(FromInner, &tcp(SCANNER, HOST, (4000, 80), 1, 0, flags), 1),
                Signal::None
            );
        }
        for outside in [
            Ipv4Addr::new(10, 0, 9, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(10, 0, 1, 0),
        ] {
            t.packet(FromInner, &tcp(SCANNER, outside, (4000, 80), 1, 0, 2), 1);
            t.packet(FromInner, &udp(SCANNER, outside, (4000, 53)), 1);
        }
        t.packet(ToInner, &reply(4000, 2, 0x12), 1);
        t.packet(ToInner, &unreachable(&syn(80, 4000, 1)[..28], 3), 1);
        assert_eq!(t.revision, 0);
        assert!(t.snapshot().rows.is_empty());
        t.packet(FromInner, &tcp(SCANNER, HOST, (4000, 80), 1, 0, 0xc2), 1);
        assert_eq!(t.revision, 1);
    }

    #[test]
    fn capacity_preserves_existing_rows_and_signals_full_once() {
        let mut t = Tracker::new(2);
        t.packet(FromInner, &syn(81, 4000, 1), 10);
        t.packet(FromInner, &syn(80, 4000, 2), 11);
        let before = t.snapshot();
        assert_eq!(
            before.rows.iter().map(|r| r.port).collect::<Vec<_>>(),
            [80, 81]
        );
        assert_eq!(t.packet(FromInner, &syn(82, 4000, 3), 12), Signal::Full);
        assert_eq!(t.packet(FromInner, &syn(82, 4000, 3), 13), Signal::None);
        assert_eq!(t.untracked, 2);
        assert_eq!(t.revision, 2);
        assert_eq!(t.at_ms, 11);
        assert_eq!(t.packet(FromInner, &syn(80, 4000, 2), 20), Signal::None);
        t.packet(ToInner, &reply(4000, 3, 0x12), 24);
        let after = t.snapshot();
        assert_eq!(after.rows.len(), 2);
        assert_eq!(after.rows[0].probes, 2);
        assert_eq!(after.rows[0].state, Open);
        assert_eq!(
            t.changes_since(2),
            PortChanges {
                from_revision: 2,
                revision: 4,
                at_ms: 24,
                untracked: 2,
                rows: vec![after.rows[0].clone()]
            }
        );
        assert_eq!(t.changes_since(0).rows, after.rows);
        assert!(t.changes_since(4).rows.is_empty());
        assert!(t.changes_since(u64::MAX).rows.is_empty());
    }

    #[test]
    fn truncated_malformed_and_noninitial_fragments_are_ignored() {
        let mut t = Tracker::new(10);
        let good = syn(80, 4000, 1);
        for n in 0..good.len() {
            assert_eq!(t.packet(FromInner, &good[..n], 0), Signal::None);
        }
        for (at, value) in [
            (0, 0x65),
            (0, 0x44),
            (0, 0x4f),
            (2, 255),
            (3, 19),
            (6, 0),
            (7, 1),
            (32, 0x40),
            (32, 0xf0),
        ] {
            let mut bad = good.clone();
            bad[at] = value;
            if at == 6 {
                bad[7] = 1;
            }
            ip::set_header_checksum(&mut bad[..20]);
            assert_eq!(t.packet(FromInner, &bad, 0), Signal::None);
        }
        for len in [0u16, 7, 9, u16::MAX] {
            let mut bad = udp(SCANNER, HOST, (4000, 53));
            bad[24..26].copy_from_slice(&len.to_be_bytes());
            assert_eq!(t.packet(FromInner, &bad, 0), Signal::None);
        }
        t.packet(FromInner, &good, 1);
        let error = unreachable(&good[..28], 3);
        for n in 20..error.len() {
            let mut short = error[..n].to_vec();
            short[2..4].copy_from_slice(&(n as u16).to_be_bytes());
            ip::set_header_checksum(&mut short[..20]);
            assert_eq!(t.packet(ToInner, &short, 2), Signal::None);
        }
        let mut fragment = good.clone();
        fragment[6] = 0x20;
        ip::set_header_checksum(&mut fragment[..20]);
        t.packet(FromInner, &fragment, 3);
        assert_eq!(t.snapshot().rows[0].probes, 2);
    }

    #[test]
    fn arbitrary_packets_in_both_directions_do_not_panic() {
        let mut seed = 0x7a91_b53e_6284_cdf0u64;
        let mut random = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut t = Tracker::new(16);
        for i in 0..10_000 {
            let mut packet = vec![0; (random() % 256) as usize];
            for byte in &mut packet {
                *byte = random() as u8;
            }
            if i % 2 == 0 && packet.len() >= 20 {
                packet[0] = 0x45;
                let len = packet.len() as u16;
                packet[2..4].copy_from_slice(&len.to_be_bytes());
                packet[6..8].fill(0);
                packet[9] = [1, 6, 17][i % 3];
                packet[16..20].copy_from_slice(&HOST.octets());
                ip::set_header_checksum(&mut packet[..20]);
            }
            t.packet(FromInner, &packet, i as u64);
            t.packet(ToInner, &packet, i as u64);
        }
    }

    fn roundtrip<T: Serialize + for<'a> Deserialize<'a> + PartialEq + std::fmt::Debug>(
        value: &T,
        bound: usize,
    ) {
        let bytes = serde_json::to_vec(value).unwrap();
        assert!(bytes.len() <= bound, "{} > {bound}", bytes.len());
        assert_eq!(&serde_json::from_slice::<T>(&bytes).unwrap(), value);
    }

    #[test]
    fn largest_projections_fit_the_json_bounds_and_roundtrip() {
        let row = PortRow {
            host: Ipv4Addr::BROADCAST,
            port: u16::MAX,
            protocol: Protocol::Tcp,
            state: Unreachable,
            first_probe_ms: u64::MAX,
            last_probe_ms: u64::MAX,
            probes: u64::MAX,
            revision: u64::MAX,
        };
        roundtrip(&row, PortRow::MAX_JSON_BYTES);
        let map = PortMap {
            revision: u64::MAX,
            at_ms: u64::MAX,
            max_rows: MAX_ROWS,
            untracked: u64::MAX,
            machines: machines(),
            rows: vec![row; MAX_ROWS],
        };
        roundtrip(&map, PortMap::MAX_JSON_BYTES);
        let changes = PortChanges {
            from_revision: u64::MAX,
            revision: u64::MAX,
            at_ms: u64::MAX,
            untracked: u64::MAX,
            rows: map.rows,
        };
        roundtrip(&changes, PortChanges::MAX_JSON_BYTES);
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            assert_eq!(
                serde_json::to_string(&protocol).unwrap(),
                format!("\"{}\"", protocol.as_str())
            );
        }
        for state in [Unanswered, Open, Closed, Unreachable] {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{}\"", state.as_str())
            );
        }
        let empty = Ports::new();
        roundtrip(&empty.snapshot(), PortMap::MAX_JSON_BYTES);
        roundtrip(&empty.changes_since(0), PortChanges::MAX_JSON_BYTES);
    }
}
