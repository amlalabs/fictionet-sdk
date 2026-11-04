//! What a resolver remembers about the servers it asks: how long each one
//! takes to answer, and so how long to wait for it (RFC 6298).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use fictionet::time::Instant;

use super::Config;

/// The round trips of the servers a resolver asked, by address.
///
/// Each reply updates its server's smoothed round trip and its variation
/// as RFC 6298 §2 computes them, and the wait for the server becomes the
/// smoothed round trip plus four times the variation. A timeout doubles
/// the wait. Every wait lies between the configuration's shortest and
/// longest. A server the resolver knows nothing of, or has not heard of
/// for `ttl`, gets the wait for unknown servers.
#[derive(Clone, Debug)]
pub(super) struct Servers {
    /// The wait for a server the resolver knows nothing of.
    unknown: Duration,
    /// How long what was learned of a server is kept after it was last
    /// updated.
    ttl: Duration,
    /// The shortest wait for a server that replied.
    min: Duration,
    /// The longest wait for any server.
    max: Duration,
    /// How much longer than the quickest wait a wait may be and still be
    /// chosen among.
    band: Duration,
    hosts: BTreeMap<IpAddr, Host>,
    /// How many hosts there were after the last sweep of expired ones.
    swept: usize,
}

#[derive(Clone, Copy, Debug)]
struct Host {
    /// The smoothed round trip and its variation, once a reply came.
    rtt: Option<Rtt>,
    rto: Duration,
    expires: Instant,
}

/// A server's smoothed round trip and its variation (RFC 6298 §2).
#[derive(Clone, Copy, Debug)]
struct Rtt {
    srtt: Duration,
    rttvar: Duration,
}

impl Servers {
    /// A table that knows no server yet, with the waits `config` gives:
    /// [`retransmit`](Config::retransmit) for an unknown server, within
    /// [`min_timeout`](Config::min_timeout) and
    /// [`max_timeout`](Config::max_timeout), its servers remembered for
    /// [`server_ttl`](Config::server_ttl), and chosen among within
    /// [`band`](Config::band).
    pub(super) fn new(config: &Config) -> Servers {
        Servers {
            unknown: config.retransmit,
            ttl: config.server_ttl,
            min: config.min_timeout,
            max: config.max_timeout,
            band: config.band,
            hosts: BTreeMap::new(),
            swept: 0,
        }
    }

    /// Forgets every server.
    pub(super) fn clear(&mut self) {
        self.hosts.clear();
        self.swept = 0;
    }

    /// How long to wait for a reply from `address` now.
    pub(super) fn timeout(&self, address: IpAddr, now: Instant) -> Duration {
        self.live(address, now)
            .map_or(self.unknown, |host| host.rto)
    }

    /// The servers among `candidates` to choose from: those whose wait is
    /// within the band of the shortest, so that a server that keeps timing
    /// out is asked only when nothing quicker is left.
    pub(super) fn band(&self, candidates: &[SocketAddr], now: Instant) -> Vec<SocketAddr> {
        let quickest = candidates
            .iter()
            .map(|server| self.timeout(server.ip(), now))
            .min()
            .unwrap_or(self.unknown);
        candidates
            .iter()
            .copied()
            .filter(|server| self.timeout(server.ip(), now) <= quickest + self.band)
            .collect()
    }

    /// Notes a reply from `address` that took `rtt`. The first reply
    /// sets the smoothed round trip to `rtt` and its variation to half of
    /// it (RFC 6298 §2.2); each later one updates both (RFC 6298 §2.3).
    pub(super) fn replied(&mut self, address: IpAddr, rtt: Duration, now: Instant) {
        let mut host = self.host(address, now);
        let next = match host.rtt {
            None => Rtt {
                srtt: rtt,
                rttvar: rtt / 2,
            },
            Some(Rtt { srtt, rttvar }) => Rtt {
                rttvar: (rttvar * 3 + rtt.abs_diff(srtt)) / 4,
                srtt: (srtt * 7 + rtt) / 8,
            },
        };
        host.rto = (next.srtt + next.rttvar * 4).max(self.min).min(self.max);
        host.rtt = Some(next);
        self.store(address, host, now);
    }

    /// Notes that `address` did not reply in time: its wait doubles
    /// (RFC 6298 §5.5).
    pub(super) fn lost(&mut self, address: IpAddr, now: Instant) {
        let mut host = self.host(address, now);
        host.rto = (host.rto * 2).min(self.max);
        self.store(address, host, now);
    }

    /// What is known of `address` now, or a server never heard from.
    fn host(&self, address: IpAddr, now: Instant) -> Host {
        self.live(address, now).copied().unwrap_or(Host {
            rtt: None,
            rto: self.unknown,
            expires: now,
        })
    }

    fn live(&self, address: IpAddr, now: Instant) -> Option<&Host> {
        self.hosts.get(&address).filter(|host| now < host.expires)
    }

    fn store(&mut self, address: IpAddr, mut host: Host, now: Instant) {
        host.expires = now + self.ttl;
        self.hosts.insert(address, host);
        if self.hosts.len() >= 2 * self.swept.max(64) {
            self.hosts.retain(|_, host| now < host.expires);
            self.swept = self.hosts.len();
        }
    }
}
