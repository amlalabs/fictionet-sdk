//! What a resolver remembers about the servers it asks: how long each one
//! takes to answer, and so how long to wait for it, as Unbound's
//! infrastructure cache keeps it (`util/rtt.c`).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use fictionet::time::Instant;

/// The shortest wait for any server: Unbound's `RTT_MIN_TIMEOUT`.
const MIN_TIMEOUT: Duration = Duration::from_millis(50);

/// The longest wait for any server: Unbound's `RTT_MAX_TIMEOUT`.
const MAX_TIMEOUT: Duration = Duration::from_secs(120);

/// Servers whose wait is within this of the shortest one's are chosen
/// among at random: Unbound's `RTT_BAND`.
const BAND: Duration = Duration::from_millis(400);

/// The round trips of the servers a resolver asked, by address.
///
/// Each reply updates its server's smoothed round trip and its variation
/// as RFC 6298 §2 computes them, and the wait for the server becomes the
/// smoothed round trip plus four times the variation. A timeout doubles
/// the wait. A server the resolver knows nothing of, or has not heard of
/// for `ttl`, gets the wait for unknown servers.
#[derive(Clone, Debug)]
pub(super) struct Servers {
    /// The wait for a server the resolver knows nothing of.
    unknown: Duration,
    /// How long what was learned of a server is kept after it was last
    /// updated.
    ttl: Duration,
    hosts: BTreeMap<IpAddr, Host>,
    /// How many hosts there were after the last sweep of expired ones.
    swept: usize,
}

#[derive(Clone, Copy, Debug)]
struct Host {
    srtt: Duration,
    rttvar: Duration,
    rto: Duration,
    expires: Instant,
}

impl Servers {
    /// A table that knows no server yet.
    pub(super) fn new(unknown: Duration, ttl: Duration) -> Servers {
        Servers {
            unknown,
            ttl,
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
    /// within [`BAND`] of the shortest, so that a server that keeps timing
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
            .filter(|server| self.timeout(server.ip(), now) <= quickest + BAND)
            .collect()
    }

    /// Notes a reply from `address` that took `rtt` (RFC 6298 §2.2, §2.3).
    pub(super) fn replied(&mut self, address: IpAddr, rtt: Duration, now: Instant) {
        let mut host = self.live(address, now).copied().unwrap_or(Host {
            srtt: Duration::ZERO,
            rttvar: self.unknown / 4,
            rto: self.unknown,
            expires: now,
        });
        let delta = rtt.abs_diff(host.srtt);
        host.rttvar = (host.rttvar * 3 + delta) / 4;
        host.srtt = (host.srtt * 7 + rtt) / 8;
        host.rto = (host.srtt + host.rttvar * 4).clamp(MIN_TIMEOUT, MAX_TIMEOUT);
        self.store(address, host, now);
    }

    /// Notes that `address` did not reply in time: its wait doubles
    /// (RFC 6298 §5.5).
    pub(super) fn lost(&mut self, address: IpAddr, now: Instant) {
        let mut host = self.live(address, now).copied().unwrap_or(Host {
            srtt: Duration::ZERO,
            rttvar: self.unknown / 4,
            rto: self.unknown,
            expires: now,
        });
        host.rto = (host.rto * 2).min(MAX_TIMEOUT);
        self.store(address, host, now);
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
