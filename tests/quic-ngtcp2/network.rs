// The link between two endpoints, in virtual time, and the packets it carried.
//
// It models the QUIC Interop Runner's ns-3 scenarios: a one-way delay, a
// bottleneck rate with a queue of whole packets, and, per direction, a rate
// at which packets are dropped or corrupted, in runs of bounded length, as
// the simulator's `drop-rate` and `corrupt-rate` scenarios do. Every random choice
// comes from the scenario's seed, so a run repeats exactly.

use std::collections::VecDeque;
use std::time::Duration;

use fictionet::stdlib::services::quic::{QUIC_V1, QUIC_V2};

/// One end of a connection, driven by `run`
pub trait Endpoint {
    /// Take one datagram that arrived at `now`
    fn receive(&mut self, datagram: &[u8], now: Duration);
    /// The next datagram to send at `now`, if any
    fn transmit(&mut self, now: Duration) -> Option<Vec<u8>>;
    /// When the endpoint next needs to run without input
    fn timer(&self) -> Option<Duration>;
    /// The connection's current QUIC version
    fn version(&self) -> Option<u32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// What happens to some packets in one direction
#[derive(Clone, Copy, Debug)]
pub enum Impairment {
    None,
    /// Each packet is dropped with probability `percent`, but never more
    /// than `burst` in a row
    Drop {
        percent: u64,
        burst: u64,
    },
    /// As `Drop`, but a chosen packet has one of its first 51 bytes
    /// replaced, so the QUIC header is often hit. Version Negotiation
    /// packets pass unchanged.
    Corrupt {
        percent: u64,
        burst: u64,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    pub delay: Duration,
    pub bits_per_second: u64,
    /// Packets waiting for the bottleneck; more are dropped
    pub queue: usize,
    pub to_server: Impairment,
    pub to_client: Impairment,
    pub seed: u64,
}

impl Scenario {
    /// `simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25`
    pub fn simple(seed: u64) -> Self {
        Self {
            delay: Duration::from_millis(15),
            bits_per_second: 10_000_000,
            queue: 25,
            to_server: Impairment::None,
            to_client: Impairment::None,
            seed,
        }
    }

    /// `drop-rate ... --rate_to_*=percent --burst_to_*=3`
    pub fn drop_rate(percent: u64, seed: u64) -> Self {
        let drop = Impairment::Drop { percent, burst: 3 };
        Self {
            to_server: drop,
            to_client: drop,
            ..Self::simple(seed)
        }
    }

    /// `corrupt-rate ... --rate_to_*=percent --burst_to_*=3`
    pub fn corrupt_rate(percent: u64, seed: u64) -> Self {
        let corrupt = Impairment::Corrupt { percent, burst: 3 };
        Self {
            to_server: corrupt,
            to_client: corrupt,
            ..Self::simple(seed)
        }
    }
}

struct Direction {
    impairment: Impairment,
    rng: u64,
    in_a_row: u64,
    /// Packets on the link: when each leaves the bottleneck, when it arrives
    queue: VecDeque<(Duration, Duration, Vec<u8>)>,
    free_at: Duration,
    dropped: usize,
    corrupted: usize,
    overflowed: usize,
}

impl Direction {
    fn new(impairment: Impairment, seed: u64) -> Self {
        Self {
            impairment,
            rng: seed,
            in_a_row: 0,
            queue: VecDeque::new(),
            free_at: Duration::ZERO,
            dropped: 0,
            corrupted: 0,
            overflowed: 0,
        }
    }

    fn random(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Whether this packet falls in a burst
    /// As the network simulator's `drop-rate` and `corrupt-rate` decide
    fn impaired(&mut self, percent: u64, burst: u64) -> bool {
        if self.in_a_row >= burst {
            self.in_a_row = 0;
            return false;
        }
        if self.random() % 100 < percent {
            self.in_a_row += 1;
            return true;
        }
        self.in_a_row = 0;
        false
    }

    fn send(&mut self, now: Duration, mut bytes: Vec<u8>, scenario: &Scenario) {
        match self.impairment {
            Impairment::None => {}
            Impairment::Drop { percent, burst } => {
                if self.impaired(percent, burst) {
                    self.dropped += 1;
                    return;
                }
            }
            Impairment::Corrupt { percent, burst } => {
                let negotiation = bytes.len() >= 5 && bytes[0] & 0x80 != 0 && bytes[1..5] == [0; 4];
                if negotiation {
                    self.in_a_row = 0;
                } else if self.impaired(percent, burst) {
                    let at = (self.random() % (bytes.len().min(51) as u64)) as usize;
                    bytes[at] ^= 1 + (self.random() % 255) as u8;
                    self.corrupted += 1;
                }
            }
        }
        let waiting = self
            .queue
            .iter()
            .filter(|(leaves, ..)| *leaves > now)
            .count();
        if waiting >= scenario.queue {
            self.overflowed += 1;
            return;
        }
        let serialize =
            Duration::from_nanos(bytes.len() as u64 * 8 * 1_000_000_000 / scenario.bits_per_second);
        let leaves = self.free_at.max(now) + serialize;
        self.free_at = leaves;
        self.queue
            .push_back((leaves, leaves + scenario.delay, bytes));
    }
}

/// A datagram one side handed to the link, before any impairment
pub struct Sent {
    pub from: Side,
    pub bytes: Vec<u8>,
}

pub struct Network {
    pub now: Duration,
    scenario: Scenario,
    to_server: Direction,
    to_client: Direction,
    pub trace: Vec<Sent>,
}

impl Network {
    pub fn new(scenario: Scenario) -> Self {
        Self {
            now: Duration::ZERO,
            scenario,
            to_server: Direction::new(scenario.to_server, scenario.seed),
            to_client: Direction::new(scenario.to_client, !scenario.seed),
            trace: Vec::new(),
        }
    }

    pub fn send(&mut self, from: Side, bytes: Vec<u8>) {
        assert!(!bytes.is_empty() && bytes.len() <= 1500);
        self.trace.push(Sent {
            from,
            bytes: bytes.clone(),
        });
        let direction = match from {
            Side::Client => &mut self.to_server,
            Side::Server => &mut self.to_client,
        };
        direction.send(self.now, bytes, &self.scenario);
    }

    fn next_arrival(&self) -> Option<Duration> {
        [&self.to_server, &self.to_client]
            .into_iter()
            .filter_map(|direction| direction.queue.front().map(|(_, arrives, _)| *arrives))
            .min()
    }

    /// Datagrams reaching `side` by now
    fn arrivals(&mut self, side: Side) -> Vec<Vec<u8>> {
        let direction = match side {
            Side::Client => &mut self.to_client,
            Side::Server => &mut self.to_server,
        };
        let mut arrived = Vec::new();
        while direction
            .queue
            .front()
            .is_some_and(|(_, arrives, _)| *arrives <= self.now)
        {
            arrived.push(direction.queue.pop_front().unwrap().2);
        }
        arrived
    }

    /// Packets dropped, corrupted, and lost to a full queue
    pub fn impaired(&self) -> (usize, usize, usize) {
        let both = [&self.to_server, &self.to_client];
        (
            both.iter().map(|d| d.dropped).sum(),
            both.iter().map(|d| d.corrupted).sum(),
            both.iter().map(|d| d.overflowed).sum(),
        )
    }

    /// Run both endpoints until `done`, or until neither has anything left
    /// to do and nothing is in flight, in virtual time
    pub fn run<C: Endpoint, S: Endpoint>(
        &mut self,
        client: &mut C,
        server: &mut S,
        mut done: impl FnMut(&mut C, &mut S, Duration) -> bool,
    ) {
        const LIMIT: Duration = Duration::from_secs(300);
        loop {
            for datagram in self.arrivals(Side::Server) {
                server.receive(&datagram, self.now);
            }
            for datagram in self.arrivals(Side::Client) {
                client.receive(&datagram, self.now);
            }
            while let Some(datagram) = client.transmit(self.now) {
                self.send(Side::Client, datagram);
            }
            while let Some(datagram) = server.transmit(self.now) {
                self.send(Side::Server, datagram);
            }
            if done(client, server, self.now) {
                return;
            }
            let Some(next) = [client.timer(), server.timer(), self.next_arrival()]
                .into_iter()
                .flatten()
                .min()
            else {
                return;
            };
            // A timer due now has run; the next step is strictly later.
            self.now = next.max(self.now + Duration::from_micros(1));
            assert!(
                self.now < LIMIT,
                "no completion in {LIMIT:?} of virtual time"
            );
        }
    }
}

/// A QUIC packet type, read from the long header's type bits for its
/// version (RFC 9000 section 17.2, RFC 9369 section 3.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    Short,
}

#[derive(Debug)]
pub struct Packet {
    pub from: Side,
    pub kind: Kind,
    /// 0 for Version Negotiation; `None` for short headers
    pub version: Option<u32>,
    /// The token of an Initial or Retry
    pub token: Vec<u8>,
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let len = 1 << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for byte in bytes.get(1..len)? {
        value = value << 8 | u64::from(*byte);
    }
    Some((value, len))
}

fn kind(first: u8, version: u32) -> Option<Kind> {
    let bits = (first >> 4) & 0b11;
    let kinds = match version {
        QUIC_V1 => [Kind::Initial, Kind::ZeroRtt, Kind::Handshake, Kind::Retry],
        QUIC_V2 => [Kind::Retry, Kind::Initial, Kind::ZeroRtt, Kind::Handshake],
        _ => return None,
    };
    Some(kinds[usize::from(bits)])
}

/// The coalesced packets of one datagram, read from their unprotected
/// header fields
fn datagram(from: Side, mut bytes: &[u8], packets: &mut Vec<Packet>) -> Option<()> {
    let mut coalesced = false;
    while let Some(&first) = bytes.first() {
        if first & 0x80 == 0 {
            // The fixed bit may be greased (RFC 9287) and the other bits are
            // protected, so a short header's first byte may be zero; after
            // coalesced long header packets a zero byte is padding.
            if !coalesced || first != 0 {
                packets.push(Packet {
                    from,
                    kind: Kind::Short,
                    version: None,
                    token: Vec::new(),
                });
            }
            return Some(());
        }
        let version = u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?);
        if version == 0 {
            packets.push(Packet {
                from,
                kind: Kind::VersionNegotiation,
                version: Some(0),
                token: Vec::new(),
            });
            return Some(());
        }
        let mut at = 5;
        for _ in 0..2 {
            at += 1 + usize::from(*bytes.get(at)?);
        }
        let kind = kind(first, version)?;
        let mut token = Vec::new();
        if kind == Kind::Retry {
            token = bytes.get(at..bytes.len().checked_sub(16)?)?.to_vec();
            packets.push(Packet {
                from,
                kind,
                version: Some(version),
                token,
            });
            return Some(());
        }
        if kind == Kind::Initial {
            let (len, n) = varint(bytes.get(at..)?)?;
            at += n;
            token = bytes.get(at..at + usize::try_from(len).ok()?)?.to_vec();
            at += token.len();
        }
        let (len, n) = varint(bytes.get(at..)?)?;
        at += n + usize::try_from(len).ok()?;
        packets.push(Packet {
            from,
            kind,
            version: Some(version),
            token,
        });
        bytes = bytes.get(at..)?;
        coalesced = true;
    }
    Some(())
}

impl Network {
    /// Every packet sent, as sent; a datagram that does not parse is a
    /// test failure, since corruption happens after the trace
    pub fn packets(&self) -> Vec<Packet> {
        let mut packets = Vec::new();
        for sent in &self.trace {
            datagram(sent.from, &sent.bytes, &mut packets).expect("a well-formed datagram");
        }
        packets
    }

    /// The versions of `kind` packets `from` sent, in order
    pub fn versions(&self, from: Side, kind: Kind) -> Vec<u32> {
        self.packets()
            .into_iter()
            .filter(|packet| packet.from == from && packet.kind == kind)
            .filter_map(|packet| packet.version)
            .collect()
    }
}
