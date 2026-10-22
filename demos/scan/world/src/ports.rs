//! The tap watches IPv4 packets on the scanner's link and changes nothing.
//! A probe is a TCP SYN with ACK, RST and FIN clear, a UDP packet, or an
//! ICMP echo request (type 8, code 0), sent to the office subnet. An echo row
//! uses protocol `icmp` and port 0. An answer must match the latest probe's
//! addresses and ports. TCP answers must also match its sequence number;
//! echo answers must match its identifier and sequence number.
//!
//! A row starts `unanswered`. A TCP SYN-ACK, UDP reply or echo reply means
//! `open`. For an echo row, this means the host answered.
//! A TCP RST-ACK or ICMP port-unreachable means `closed`. Other ICMP
//! destination unreachable codes, and any code quoting an echo request,
//! mean `unreachable`. Repeated probes keep
//! the last answered state. Stale replies and noninitial fragments are ignored.
//!
//! A `scan.port` fact marks a new row or a state change. It includes the
//! previous state, probe count, first and last probe times, and revision.
//! The previous state is null for a new row. Times are whole milliseconds
//! since the run began. A port scan makes thousands of these facts, so each
//! is a repeatable fact: the host, protocol, state and previous state
//! identify it, and the port, times, probe count and revision are its
//! detail. An event store with a separate budget for repeatable facts, such
//! as `fictionet_observe::Memory`, keeps them from evicting other events.
//!
//! [`Tap::snapshot`] copies the five office labels and all rows, sorted
//! by address, protocol, then port. Each tracked probe or state change
//! advances the revision. The map includes the last row change time and the
//! `untracked` count. [`PortMap::MAX_JSON_BYTES`] bounds its compact JSON.
//! [`Tap::changed_since`] says whether a copy is out of date.
//!
//! Rows stay for the run, up to [`MAX_ROWS`] (16,384). At capacity, probes for
//! new keys increment `untracked`; existing rows still update. The first
//! untracked probe emits one `scan.full` fact with `max_rows`.
//!
//! The tap also keeps the first data each open port sent to the scanner, as
//! described in [`crate::banners`]. A `scan.banner` fact marks each new one,
//! with its host, port, text, server value, time and revision. A new banner
//! advances the revision too. The map lists banners sorted by host, then
//! port, and includes the `untracked_banners` count.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use example_common::names::name;
use fictionet::events::{Fields, Level, opt};
use fictionet::stdlib::network::{Direction, ip};
use fictionet::sync::Mutex;
use fictionet::{Cx, Packet};
use serde::{Deserialize, Serialize};

use crate::banners::{Banner, Banners, MAX_BANNERS, Offer};
use crate::{MACHINES, OFFICE};

/// Maximum number of distinct host, protocol and port rows in a run.
pub const MAX_ROWS: usize = 16_384;

/// The protocol used by a probe. Sorts TCP, UDP, then ICMP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// A TCP probe.
    Tcp,
    /// A UDP probe.
    Udp,
    /// An ICMP echo probe.
    Icmp,
}

/// The latest answered probe's result, or no answer yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    /// No matching answer has arrived.
    Unanswered,
    /// A matching TCP SYN-ACK, UDP reply or ICMP echo reply arrived.
    Open,
    /// A matching TCP RST-ACK or ICMP port-unreachable arrived.
    Closed,
    /// A matching ICMP unreachable arrived, with any code for an echo probe.
    Unreachable,
}

/// One port's probes and latest answered state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRow {
    /// The probed host's IPv4 address.
    pub host: Ipv4Addr,
    /// The probed destination port, or zero for an ICMP echo.
    pub port: u16,
    /// The probe's protocol.
    pub protocol: Protocol,
    /// The latest answered state, or no answer yet.
    pub state: PortState,
    /// The first probe's time in whole milliseconds since the run began.
    pub first_probe_ms: u64,
    /// The latest probe's time in whole milliseconds since the run began.
    pub last_probe_ms: u64,
    /// The number of probes for this row.
    pub probes: u64,
    /// The map revision when this row last changed.
    pub revision: u64,
}

impl PortRow {
    /// Maximum compact JSON size, with the largest address, port and counters.
    pub const MAX_JSON_BYTES: usize = concat!(
        r#"{"host":"255.255.255.255","port":65535,"protocol":"icmp","state":"unreachable","first_probe_ms":"#,
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
    /// Runs inside the world.
    Simulated,
    /// Runs behind a real attachment.
    Real,
}

/// An office machine's label and address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Machine {
    /// The machine's label.
    pub name: String,
    /// The machine's IPv4 address.
    pub addr: Ipv4Addr,
    /// Whether the machine is simulated or real.
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
    /// The current map revision.
    pub revision: u64,
    /// The last row change time in milliseconds since the run began, or zero.
    pub at_ms: u64,
    /// The maximum number of rows the map can hold.
    pub max_rows: usize,
    /// Probes for new keys that could not fit in the map.
    pub untracked: u64,
    /// Banners that could not fit in the map.
    pub untracked_banners: u64,
    /// The five office machines, including those with no probes.
    pub machines: Vec<Machine>,
    /// All tracked rows, sorted by address, protocol, then port.
    pub rows: Vec<PortRow>,
    /// Every kept banner, sorted by host, then port.
    pub banners: Vec<Banner>,
}

impl PortMap {
    /// Compact JSON bound for snapshots produced by [`Tap`].
    pub const MAX_JSON_BYTES: usize = concat!(
        r#"{"revision":18446744073709551615,"at_ms":18446744073709551615,"#,
        r#""max_rows":,"untracked":18446744073709551615,"#,
        r#""untracked_banners":18446744073709551615,"#,
        r#""machines":,"rows":[],"banners":[]}"#,
    )
    .len()
        + (MAX_ROWS.ilog10() as usize + 1)
        + machines_json_bytes()
        + MAX_ROWS * (PortRow::MAX_JSON_BYTES + 1)
        + MAX_BANNERS * (Banner::MAX_JSON_BYTES + 1);
}

/// A shared view of the scanner's probes, readable outside the world.
#[derive(Clone)]
pub struct Tap(Arc<Mutex<Tracker>>);

impl Tap {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Tracker::new(MAX_ROWS))))
    }

    /// Copies the complete map and the five office labels.
    pub fn snapshot(&self) -> PortMap {
        self.0.lock().snapshot()
    }

    /// Whether the map changed after `map` was copied from it: a tracked
    /// probe, a state change, a new banner, or one more untracked probe or
    /// banner.
    pub fn changed_since(&self, map: &PortMap) -> bool {
        let t = self.0.lock();
        (t.revision, t.untracked, t.banners.untracked)
            != (map.revision, map.untracked, map.untracked_banners)
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
                        name(&row.protocol),
                        name(&row.state)
                    ))
                    .field("host", row.host.to_string())
                    .field("protocol", name(&row.protocol))
                    .field("state", name(&row.state))
                    .field("previous", opt(previous.map(|state| name(&state))))
                    .repeat(
                        Fields::new()
                            .with("port", u32::from(row.port))
                            .with("first_probe_ms", row.first_probe_ms)
                            .with("last_probe_ms", row.last_probe_ms)
                            .with("probes", row.probes)
                            .with("revision", row.revision),
                    )
            }),
            Signal::Full => fcx.emit("scan", "full", |e| {
                e.level(Level::Notice).field("max_rows", MAX_ROWS as u64)
            }),
            Signal::Banner(banner) => fcx.emit("scan", "banner", |e| {
                e.level(Level::Info)
                    .summary(format_args!(
                        "{}:{}/tcp {}",
                        banner.host,
                        banner.port,
                        banner.server.as_deref().unwrap_or(&banner.text)
                    ))
                    .field("host", banner.host.to_string())
                    .field("port", u32::from(banner.port))
                    .field("text", banner.text.as_str())
                    .field("server", opt(banner.server.as_deref()))
                    .field("at_ms", banner.at_ms)
                    .field("revision", banner.revision)
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
    /// The sequence number of the SYN-ACK that answered the latest TCP probe.
    answer_sequence: Option<u32>,
}

struct Tracker {
    rows: BTreeMap<Key, Tracked>,
    max_rows: usize,
    revision: u64,
    at_ms: u64,
    untracked: u64,
    banners: Banners,
}

#[derive(Debug, PartialEq, Eq)]
enum Signal {
    None,
    Port(PortRow, Option<PortState>),
    Full,
    Banner(Banner),
}

impl Tracker {
    fn new(max_rows: usize) -> Self {
        Self::with_banners(max_rows, MAX_BANNERS)
    }

    fn with_banners(max_rows: usize, max_banners: usize) -> Self {
        Self {
            rows: BTreeMap::new(),
            max_rows,
            revision: 0,
            at_ms: 0,
            untracked: 0,
            banners: Banners::new(max_banners),
        }
    }

    fn snapshot(&self) -> PortMap {
        PortMap {
            revision: self.revision,
            at_ms: self.at_ms,
            max_rows: self.max_rows,
            untracked: self.untracked,
            untracked_banners: self.banners.untracked,
            machines: machines(),
            rows: self.rows.values().map(|t| t.row.clone()).collect(),
            banners: self.banners.all(),
        }
    }

    fn packet(&mut self, direction: Direction, bytes: &[u8], at_ms: u64) -> Signal {
        let Some(h) = header(bytes, false) else {
            return Signal::None;
        };
        let transport = h.payload(bytes);
        if transport.len() < 8 {
            return Signal::None;
        }
        if direction == Direction::ToInner && h.protocol == 1 && transport[0] == 3 {
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
            let echo = protocol == Protocol::Icmp;
            if echo && t[..2] != [8, 0] {
                return Signal::None;
            }
            let key = (host, protocol, if echo { 0 } else { word(t, 2) });
            let Some(row) = self.rows.get(&key) else {
                return Signal::None;
            };
            if row.source != q.src
                || h.dst != row.source
                || (!echo && row.source_port != word(t, 0))
                || (protocol != Protocol::Udp && row.sequence != dword(t, 4))
            {
                return Signal::None;
            }
            return self.answer(
                key,
                if transport[1] == 3 && !echo {
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
        let mut data: &[u8] = &[];
        let flags = match protocol {
            Protocol::Tcp => {
                if transport.len() < 20 {
                    return Signal::None;
                }
                let len = usize::from(transport[12] >> 4) * 4;
                if len < 20 || len > transport.len() {
                    return Signal::None;
                }
                data = &transport[len..];
                transport[13]
            }
            Protocol::Udp => {
                let len = usize::from(word(transport, 4));
                if len < 8 || (len > transport.len() && h.fragment.is_none()) {
                    return Signal::None;
                }
                0
            }
            Protocol::Icmp => {
                let kind = if direction == Direction::FromInner {
                    8
                } else {
                    0
                };
                if transport[..2] != [kind, 0] {
                    return Signal::None;
                }
                0
            }
        };
        let echo = protocol == Protocol::Icmp;
        match direction {
            Direction::FromInner => {
                if !OFFICE.contains(h.dst) || (protocol == Protocol::Tcp && flags & 0x17 != 0x02) {
                    return Signal::None;
                }
                let IpAddr::V4(host) = h.dst else {
                    return Signal::None;
                };
                let key = (host, protocol, if echo { 0 } else { word(transport, 2) });
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
                    answer_sequence: None,
                });
                tracked.answer_sequence = None;
                tracked.row.last_probe_ms = at_ms;
                tracked.row.probes += 1;
                tracked.row.revision = self.revision;
                tracked.source = h.src;
                tracked.source_port = if echo { 0 } else { word(transport, 0) };
                tracked.sequence = if protocol != Protocol::Udp {
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
                let key = (host, protocol, if echo { 0 } else { word(transport, 0) });
                let Some(row) = self.rows.get(&key) else {
                    return Signal::None;
                };
                if h.dst != row.source || (!echo && word(transport, 2) != row.source_port) {
                    return Signal::None;
                }
                let state = match protocol {
                    Protocol::Icmp => {
                        if dword(transport, 4) != row.sequence {
                            return Signal::None;
                        }
                        PortState::Open
                    }
                    Protocol::Udp => PortState::Open,
                    Protocol::Tcp => {
                        // ACK set, SYN and RST clear, with data: maybe a first data segment.
                        if flags & 0x16 == 0x10 && !data.is_empty() {
                            return self.banner(key, dword(transport, 4), data, at_ms);
                        }
                        if flags & 0x10 == 0 || dword(transport, 8) != row.sequence.wrapping_add(1)
                        {
                            return Signal::None;
                        }
                        if flags & 4 != 0 {
                            PortState::Closed
                        } else if flags & 2 != 0 {
                            let sequence = dword(transport, 4);
                            self.rows.get_mut(&key).unwrap().answer_sequence = Some(sequence);
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

    /// Keeps a banner from the first data segment of an open port's latest
    /// connection: the segment whose sequence number follows the SYN-ACK.
    fn banner(&mut self, key: Key, sequence: u32, data: &[u8], at_ms: u64) -> Signal {
        let tracked = &self.rows[&key];
        if tracked.row.state != PortState::Open
            || tracked.answer_sequence.map(|s| s.wrapping_add(1)) != Some(sequence)
        {
            return Signal::None;
        }
        match self
            .banners
            .offer(key.0, key.2, data, at_ms, self.revision + 1)
        {
            Offer::Kept(banner) => {
                self.revision += 1;
                self.at_ms = at_ms;
                Signal::Banner(banner)
            }
            Offer::Known | Offer::Full => Signal::None,
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
        1 => Some(Protocol::Icmp),
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

    fn echo(src: Ipv4Addr, dst: Ipv4Addr, kind: u8, code: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut t = vec![kind, code, 0, 0];
        t.extend_from_slice(&id.to_be_bytes());
        t.extend_from_slice(&seq.to_be_bytes());
        let sum = ip::checksum(&t);
        t[2..4].copy_from_slice(&sum.to_be_bytes());
        ip::packet(src.into(), dst.into(), 1, &t).0
    }

    #[test]
    fn echo_answers_match_the_latest_identifier_sequence_and_addresses() {
        let mut t = Tracker::new(10);
        assert!(matches!(
            t.packet(FromInner, &echo(SCANNER, HOST, 8, 0, 123, 1), 10),
            Signal::Port(
                PortRow {
                    protocol: Protocol::Icmp,
                    port: 0,
                    state: Unanswered,
                    ..
                },
                None
            )
        ));
        assert_eq!(
            t.packet(FromInner, &echo(SCANNER, HOST, 8, 0, 124, 2), 20),
            Signal::None
        );
        let before = t.snapshot();
        for (src, dst, id, seq) in [
            (HOST, SCANNER, 123, 2),
            (HOST, SCANNER, 124, 1),
            (HOST, SCANNER, 123, 1),
            (Ipv4Addr::new(10, 0, 0, 11), SCANNER, 124, 2),
            (HOST, Ipv4Addr::new(10, 0, 9, 3), 124, 2),
        ] {
            assert_eq!(
                t.packet(ToInner, &echo(src, dst, 0, 0, id, seq), 21),
                Signal::None
            );
            assert_eq!(t.snapshot(), before);
        }
        assert!(matches!(
            t.packet(ToInner, &echo(HOST, SCANNER, 0, 0, 124, 2), 22),
            Signal::Port(PortRow { state: Open, .. }, Some(Unanswered))
        ));
        let row = PortRow {
            host: HOST,
            port: 0,
            protocol: Protocol::Icmp,
            state: Open,
            first_probe_ms: 10,
            last_probe_ms: 20,
            probes: 2,
            revision: 3,
        };
        assert_eq!(t.snapshot().rows, [row]);
        assert_eq!((t.revision, t.at_ms), (3, 22));
        assert_eq!(
            t.packet(ToInner, &echo(HOST, SCANNER, 0, 0, 124, 2), 23),
            Signal::None
        );
        assert_eq!(
            t.packet(FromInner, &echo(SCANNER, HOST, 8, 0, 125, 3), 24),
            Signal::None
        );
        assert_eq!(t.snapshot().rows[0].state, Open);
        assert_eq!(t.snapshot().rows[0].probes, 3);
        assert_eq!(t.revision, 4);
    }

    #[test]
    fn echo_unreachable_matches_the_quoted_request_for_every_code() {
        let absent = Ipv4Addr::new(10, 0, 0, 14);
        for code in 0..=u8::MAX {
            let mut t = Tracker::new(10);
            let probe = echo(SCANNER, absent, 8, 0, 124, 2);
            t.packet(FromInner, &probe, 10);
            let before = t.snapshot();
            for quote in [
                echo(SCANNER, absent, 8, 0, 123, 2),
                echo(SCANNER, absent, 8, 0, 124, 1),
                echo(SCANNER, HOST, 8, 0, 124, 2),
                echo(Ipv4Addr::new(10, 0, 9, 3), absent, 8, 0, 124, 2),
                echo(SCANNER, absent, 0, 0, 124, 2),
                echo(SCANNER, absent, 8, 1, 124, 2),
            ] {
                assert_eq!(
                    t.packet(ToInner, &unreachable(&quote, code), 11),
                    Signal::None
                );
                assert_eq!(t.snapshot(), before);
            }
            assert!(matches!(
                t.packet(ToInner, &unreachable(&probe, code), 12),
                Signal::Port(
                    PortRow {
                        state: Unreachable,
                        ..
                    },
                    Some(Unanswered)
                )
            ));
            assert_eq!(t.snapshot().rows[0].host, absent);
            assert_eq!(t.revision, 2);
        }
    }

    #[test]
    fn unsolicited_echo_replies_and_other_echo_traffic_are_ignored() {
        let mut t = Tracker::new(10);
        assert_eq!(
            t.packet(ToInner, &echo(HOST, SCANNER, 0, 0, 123, 1), 1),
            Signal::None
        );
        for (dst, kind, code) in [
            (Ipv4Addr::new(10, 0, 9, 1), 8, 0),
            (Ipv4Addr::new(10, 0, 1, 0), 8, 0),
            (HOST, 0, 0),
            (HOST, 8, 1),
            (HOST, 13, 0),
        ] {
            assert_eq!(
                t.packet(FromInner, &echo(SCANNER, dst, kind, code, 123, 1), 1),
                Signal::None
            );
        }
        assert_eq!(t.revision, 0);
        assert!(t.snapshot().rows.is_empty());
    }

    #[test]
    fn echo_rows_share_the_bound_and_sort_after_udp() {
        let mut t = Tracker::new(3);
        let probe = echo(SCANNER, HOST, 8, 0, 123, 1);
        t.packet(FromInner, &probe, 1);
        t.packet(FromInner, &udp(SCANNER, HOST, (4000, 53)), 2);
        t.packet(FromInner, &syn(80, 4000, 1), 3);
        assert_eq!(
            t.snapshot()
                .rows
                .iter()
                .map(|r| r.protocol)
                .collect::<Vec<_>>(),
            [Protocol::Tcp, Protocol::Udp, Protocol::Icmp]
        );
        let extra = echo(SCANNER, Ipv4Addr::new(10, 0, 0, 11), 8, 0, 123, 1);
        assert_eq!(t.packet(FromInner, &extra, 4), Signal::Full);
        assert_eq!(t.packet(FromInner, &extra, 5), Signal::None);
        assert_eq!(t.packet(FromInner, &probe, 6), Signal::None);
        t.packet(ToInner, &echo(HOST, SCANNER, 0, 0, 123, 1), 7);
        assert_eq!(t.snapshot().rows.len(), 3);
        assert_eq!(t.snapshot().rows[2].state, Open);
        assert_eq!(t.snapshot().rows[2].probes, 2);
        assert_eq!(t.untracked, 2);
        assert_eq!(t.revision, 5);
    }

    #[test]
    fn longest_protocol_fits_the_exact_json_row_bound() {
        let row = PortRow {
            host: Ipv4Addr::BROADCAST,
            port: u16::MAX,
            protocol: Protocol::Icmp,
            state: Unreachable,
            first_probe_ms: u64::MAX,
            last_probe_ms: u64::MAX,
            probes: u64::MAX,
            revision: u64::MAX,
        };
        assert_eq!(
            serde_json::to_vec(&row).unwrap().len(),
            PortRow::MAX_JSON_BYTES
        );
        assert_eq!(serde_json::to_string(&Protocol::Icmp).unwrap(), "\"icmp\"");
        roundtrip(&row, PortRow::MAX_JSON_BYTES);
        let map = PortMap {
            revision: u64::MAX,
            at_ms: u64::MAX,
            max_rows: MAX_ROWS,
            untracked: u64::MAX,
            untracked_banners: u64::MAX,
            machines: machines(),
            rows: vec![row; MAX_ROWS],
            banners: vec![longest_banner(); MAX_BANNERS],
        };
        roundtrip(&map, PortMap::MAX_JSON_BYTES);
    }

    fn longest_banner() -> Banner {
        Banner {
            host: Ipv4Addr::BROADCAST,
            port: u16::MAX,
            text: "\"".repeat(crate::banners::MAX_TEXT_BYTES),
            server: Some("\"".repeat(crate::banners::MAX_TEXT_BYTES)),
            at_ms: u64::MAX,
            revision: u64::MAX,
        }
    }

    fn segment(port: u16, client: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0; 20];
        t[..2].copy_from_slice(&port.to_be_bytes());
        t[2..4].copy_from_slice(&client.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&101u32.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        t.extend_from_slice(payload);
        let sum = ip::transport_checksum(HOST.into(), SCANNER.into(), 6, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        ip::packet(HOST.into(), SCANNER.into(), 6, &t).0
    }

    /// Probes `port` and answers with a SYN-ACK whose sequence number is 7.
    fn opened(t: &mut Tracker, port: u16, client: u16) {
        t.packet(FromInner, &syn(port, client, 100), 10);
        t.packet(ToInner, &segment(port, client, 7, 0x12, b""), 11);
    }

    const SSH: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20\r\n";

    #[test]
    fn the_first_data_segment_after_the_syn_ack_is_the_banner() {
        let mut t = Tracker::new(10);
        opened(&mut t, 22, 4000);
        assert_eq!(t.revision, 2);
        // A segment later in the stream is not the first data segment.
        assert_eq!(
            t.packet(ToInner, &segment(22, 4000, 9, 0x18, SSH), 12),
            Signal::None
        );
        let banner = Banner {
            host: HOST,
            port: 22,
            text: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20".into(),
            server: None,
            at_ms: 13,
            revision: 3,
        };
        assert_eq!(
            t.packet(ToInner, &segment(22, 4000, 8, 0x18, SSH), 13),
            Signal::Banner(banner.clone())
        );
        assert_eq!((t.revision, t.at_ms), (3, 13));
        assert_eq!(t.snapshot().banners, std::slice::from_ref(&banner));
        assert_eq!(
            t.packet(ToInner, &segment(22, 4000, 8, 0x19, SSH), 14),
            Signal::None
        );
        assert_eq!(t.revision, 3);
    }

    #[test]
    fn an_http_banner_keeps_the_status_line_and_server_value() {
        let mut t = Tracker::new(10);
        opened(&mut t, 80, 4000);
        let response =
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nDate: today\r\n\r\n<html>";
        let Signal::Banner(banner) = t.packet(ToInner, &segment(80, 4000, 8, 0x18, response), 12)
        else {
            panic!("expected a banner");
        };
        assert_eq!(banner.text, "HTTP/1.1 200 OK");
        assert_eq!(banner.server.as_deref(), Some("nginx/1.24.0 (Ubuntu)"));
    }

    #[test]
    fn data_from_closed_unanswered_or_other_connections_is_ignored() {
        let mut t = Tracker::new(10);
        t.packet(FromInner, &syn(23, 4000, 100), 10);
        t.packet(FromInner, &syn(25, 4001, 100), 10);
        t.packet(ToInner, &segment(25, 4001, 7, 0x14, b""), 11);
        assert_eq!(t.snapshot().rows[1].state, Closed);
        let before = t.revision;
        for packet in [
            segment(23, 4000, 8, 0x18, SSH),
            segment(25, 4001, 8, 0x18, SSH),
        ] {
            assert_eq!(t.packet(ToInner, &packet, 12), Signal::None);
        }
        opened(&mut t, 22, 4002);
        let before_data = t.revision;
        for packet in [
            // To another client port, with SYN set, with RST set, and with no data.
            segment(22, 4003, 8, 0x18, SSH),
            segment(22, 4002, 8, 0x02, SSH),
            segment(22, 4002, 8, 0x04, SSH),
            segment(22, 4002, 8, 0x18, b""),
        ] {
            assert_eq!(t.packet(ToInner, &packet, 12), Signal::None);
        }
        assert_eq!(t.revision, before_data);
        assert!(before_data > before);
        assert!(t.snapshot().banners.is_empty());
    }

    #[test]
    fn a_second_connection_does_not_replace_the_banner() {
        let mut t = Tracker::new(10);
        opened(&mut t, 22, 4000);
        t.packet(
            ToInner,
            &segment(22, 4000, 8, 0x18, b"SSH-2.0-first\r\n"),
            12,
        );
        opened(&mut t, 22, 4001);
        let revision = t.revision;
        assert_eq!(
            t.packet(
                ToInner,
                &segment(22, 4001, 8, 0x18, b"SSH-2.0-second\r\n"),
                13
            ),
            Signal::None
        );
        assert_eq!(t.revision, revision);
        assert_eq!(t.snapshot().banners[0].text, "SSH-2.0-first");
        assert_eq!(t.snapshot().banners[0].at_ms, 12);
    }

    #[test]
    fn banners_past_the_bound_are_counted_and_never_evict() {
        let mut t = Tracker::with_banners(10, 1);
        opened(&mut t, 22, 4000);
        opened(&mut t, 80, 4001);
        t.packet(ToInner, &segment(22, 4000, 8, 0x18, SSH), 12);
        let revision = t.revision;
        assert_eq!(
            t.packet(
                ToInner,
                &segment(80, 4001, 8, 0x18, b"HTTP/1.1 200 OK\r\n"),
                13
            ),
            Signal::None
        );
        assert_eq!(t.revision, revision);
        let map = t.snapshot();
        assert_eq!(map.untracked_banners, 1);
        assert_eq!(map.banners.len(), 1);
        assert_eq!(map.banners[0].port, 22);
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
            Ipv4Addr::new(104, 18, 0, 1),
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
        assert_eq!((after.revision, after.at_ms, after.untracked), (4, 24, 2));
        assert_eq!(after.rows[0].revision, 4);
        assert_eq!(after.rows[1], before.rows[1]);
    }

    #[test]
    fn a_copy_is_out_of_date_after_a_tracked_or_untracked_probe() {
        let ports = Tap(Arc::new(Mutex::new(Tracker::new(1))));
        let empty = ports.snapshot();
        assert!(!ports.changed_since(&empty));
        ports.0.lock().packet(FromInner, &syn(80, 4000, 1), 10);
        assert!(ports.changed_since(&empty));
        let one = ports.snapshot();
        assert!(!ports.changed_since(&one));
        // A full map leaves the revision alone but counts the probe.
        ports.0.lock().packet(FromInner, &syn(81, 4000, 2), 11);
        assert_eq!(ports.snapshot().revision, one.revision);
        assert!(ports.changed_since(&one));
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
            untracked_banners: u64::MAX,
            machines: machines(),
            rows: vec![row; MAX_ROWS],
            banners: vec![longest_banner(); MAX_BANNERS],
        };
        roundtrip(&map, PortMap::MAX_JSON_BYTES);
        let empty = Tap::new();
        roundtrip(&empty.snapshot(), PortMap::MAX_JSON_BYTES);
    }
}
