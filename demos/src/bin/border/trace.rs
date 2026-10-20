//! Bounded UDP traceroute reconstruction from a guest link's IPv4 packets.
//!
//! Outgoing probe tuples retain their original TTL. ICMP quotes correlate replies
//! to those probes, including the destination's port-unreachable answer. Starting
//! at TTL one replaces the preceding run; late replies cannot enter the new run.
//! This recognizes UDP traceroute, not arbitrary ICMP or TCP probes.

use super::tls::ipv4;
use border_world::scenario::BANK_ADDR;
use serde::Serialize;
use std::net::Ipv4Addr;

const MAX_PROBES: usize = 64;
const MAX_HOPS: usize = 32;

#[derive(Clone, Debug, Serialize)]
pub struct Hop {
    pub ttl: u8,
    pub address: Ipv4Addr,
    pub at_ms: u64,
    pub round_trip_ms: u64,
    pub destination: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Trace {
    pub started_ms: u64,
    pub updated_ms: u64,
    pub complete: bool,
    pub hops: Vec<Hop>,
    pub dropped: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    id: u16,
}
struct Probe {
    key: Key,
    ttl: u8,
    at_ms: u64,
}

#[derive(Default)]
pub struct Tracker {
    pub trace: Option<Trace>,
    probes: Vec<Probe>,
    source_port: Option<u16>,
}

fn addr(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}
fn key(header: &[u8], payload: &[u8]) -> Option<Key> {
    if header[9] != 17 || payload.len() < 8 {
        return None;
    }
    Some(Key {
        source: addr(&header[12..16]),
        destination: addr(&header[16..20]),
        source_port: u16::from_be_bytes([payload[0], payload[1]]),
        destination_port: u16::from_be_bytes([payload[2], payload[3]]),
        id: u16::from_be_bytes([header[4], header[5]]),
    })
}

impl Tracker {
    pub fn packet(&mut self, at_ms: u64, outgoing: bool, bytes: &[u8]) {
        let Some((h, p)) = ipv4(bytes) else {
            return;
        };
        if outgoing {
            let Some(key) = key(h, p).filter(|k| {
                k.destination == BANK_ADDR && (33434..=33534).contains(&k.destination_port)
            }) else {
                return;
            };
            if h[8] == 1
                && (self.source_port != Some(key.source_port)
                    || self
                        .trace
                        .as_ref()
                        .is_none_or(|t| t.complete || t.hops.iter().any(|h| h.ttl > 1)))
            {
                self.trace = Some(Trace {
                    started_ms: at_ms,
                    updated_ms: at_ms,
                    ..Trace::default()
                });
                self.probes.clear();
                self.source_port = Some(key.source_port);
            }
            let Some(trace) = &mut self.trace else {
                return;
            };
            if self.source_port != Some(key.source_port) || self.probes.iter().any(|p| p.key == key)
            {
                return;
            }
            if self.probes.len() == MAX_PROBES {
                self.probes.remove(0);
                trace.dropped += 1;
            }
            self.probes.push(Probe {
                key,
                ttl: h[8],
                at_ms,
            });
        } else {
            if h[9] != 1 || p.len() < 36 || !matches!((p[0], p[1]), (11, 0) | (3, 3)) {
                return;
            }
            // An ICMP quote may contain only the original IP header and eight bytes.
            let quote = &p[8..];
            let qh = usize::from(quote[0] & 15) * 4;
            if quote[0] >> 4 != 4 || qh < 20 || quote.len() < qh + 8 {
                return;
            }
            let Some(key) = key(&quote[..qh], &quote[qh..]) else {
                return;
            };
            let Some(index) = self.probes.iter().position(|p| p.key == key) else {
                return;
            };
            let probe = self.probes.remove(index);
            let trace = self.trace.as_mut().expect("a pending probe has a trace");
            let address = addr(&h[12..16]);
            let destination = p[0] == 3 && address == BANK_ADDR;
            let hop = Hop {
                ttl: probe.ttl,
                address,
                at_ms,
                round_trip_ms: at_ms.saturating_sub(probe.at_ms),
                destination,
            };
            if let Some(old) = trace.hops.iter_mut().find(|h| h.ttl == probe.ttl) {
                *old = hop;
            } else if trace.hops.len() < MAX_HOPS {
                trace.hops.push(hop);
                trace.hops.sort_by_key(|h| h.ttl);
            } else {
                trace.dropped += 1;
            }
            trace.updated_ms = at_ms;
            trace.complete |= destination;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(ttl: u8, port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[3] = 28;
        p[8] = ttl;
        p[9] = 17;
        p[12..16].copy_from_slice(&[192, 168, 1, 2]);
        p[16..20].copy_from_slice(&BANK_ADDR.octets());
        p[20..22].copy_from_slice(&port.to_be_bytes());
        p[22..24].copy_from_slice(&(33433 + u16::from(ttl)).to_be_bytes());
        p[25] = 8;
        p
    }
    fn reply(probe: &[u8], from: Ipv4Addr, destination: bool) -> Vec<u8> {
        border_world::path::icmp_error(
            probe,
            from,
            64,
            1,
            if destination { 3 } else { 11 },
            if destination { 3 } else { 0 },
        )
        .unwrap()
        .0
    }
    #[test]
    fn replies_complete_and_replace_the_trace_without_late_hops() {
        let mut tracker = Tracker::default();
        let old = packet(2, 40000);
        for (ttl, from) in [
            (1, Ipv4Addr::new(192, 168, 1, 1)),
            (2, Ipv4Addr::new(84, 21, 44, 1)),
            (3, BANK_ADDR),
        ] {
            let p = packet(ttl, 40000);
            tracker.packet(10, true, &p);
            tracker.packet(34, false, &reply(&p, from, ttl == 3));
        }
        let trace = tracker.trace.as_ref().unwrap();
        assert!(trace.complete);
        assert_eq!(trace.hops.len(), 3);
        assert_eq!(trace.hops[2].round_trip_ms, 24);
        let first = packet(1, 41000);
        tracker.packet(50, true, &first);
        tracker.packet(51, false, &reply(&old, BANK_ADDR, false));
        assert!(tracker.trace.as_ref().unwrap().hops.is_empty());
        tracker.packet(
            52,
            false,
            &reply(&first, Ipv4Addr::new(192, 168, 1, 1), false),
        );
        assert_eq!(tracker.trace.as_ref().unwrap().hops.len(), 1);
        assert_eq!(tracker.trace.as_ref().unwrap().started_ms, 50);
        assert!(!tracker.trace.as_ref().unwrap().complete);
    }
    #[test]
    fn probes_and_hops_stay_bounded_and_report_loss() {
        let mut tracker = Tracker::default();
        for ttl in 1..=100 {
            let p = packet(ttl, 40000);
            tracker.packet(10, true, &p);
        }
        assert_eq!(tracker.probes.len(), MAX_PROBES);
        assert_eq!(tracker.trace.as_ref().unwrap().dropped, 36);
        for ttl in 37..=100 {
            let p = packet(ttl, 40000);
            tracker.packet(20, false, &reply(&p, BANK_ADDR, false));
        }
        assert_eq!(tracker.trace.as_ref().unwrap().hops.len(), MAX_HOPS);
        assert_eq!(tracker.trace.as_ref().unwrap().dropped, 68);
        for n in 0..28 {
            tracker.packet(30, true, &packet(1, 2)[..n]);
        }
    }
}
