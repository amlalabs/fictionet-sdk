//! The path between a sandbox and the world: hops, delay, and the two
//! border routers.
//!
//! `web::Sites` puts every site one hop from the sandbox and keeps its
//! router private. Border needs more: Harbourline's border router at
//! 84.21.44.1 speaks BGP, and in the hijack the bank is reached through
//! Transpeak's router, one hop further. So each sandbox gets a task between
//! its attachment and `Sites` (the way the `web` docs suggest for a world
//! that wants every packet):
//!
//! - **Hops.** A packet to an address outside the subnet passes the routers
//!   [`Scenario::hops`] lists. Its TTL is lowered by one for each. If it
//!   runs out on the way, the router where it ran out answers with ICMP
//!   "time exceeded", so `traceroute` shows the path. Replies are lowered by
//!   the same count on the way back. Like a real router, each sandbox's
//!   routers send at most [`TIME_EXCEEDED_PER_SECOND`] of these a second.
//! - **No host.** A packet for an address where no machine answers
//!   ([`Scenario::has_host`]) ends at the last router on its way, which
//!   answers ICMP "host unreachable", as a router with no route does.
//! - **Delay.** Every packet takes [`Scenario::one_way`] to reach where it
//!   goes, and replies the same to come back: about 24 ms for a round trip
//!   to the bank, and 52 ms in the hijack, where it crosses the border.
//! - **The routers.** Packets for 84.21.44.1 and 45.144.30.1 go to two
//!   small machines of this sandbox's own, built from stdlib parts: they
//!   answer pings, refuse TCP with a RST and UDP with "port unreachable",
//!   and 84.21.44.1 runs the BGP speaker on port 179.
//! - Everything else goes to `Sites`, delayed but otherwise unchanged.
//!
//! The task owns every end. When the sandbox detaches it returns, which
//! closes its `Sites` attachment, so `Sites` sees the detach, and stops the
//! routers' tasks.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::Ipv4Addr;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::{icmp, ip, tcp, udp};
use fictionet::time::Instant;
use fictionet::{Cx, End, Interface, Packet, RecvError, pair};
use serde_json::json;

use crate::bgp;
use crate::log::Log;
use crate::scenario::{FOREIGN, HOME, Scenario};

/// What every sandbox's path shares.
pub struct Shared {
    pub scenario: Arc<Scenario>,
    pub log: Log,
}

const TTL: u8 = 64;

/// How many "time exceeded" replies a sandbox's routers send in a second,
/// at most. Real routers limit these too. More than this are dropped
/// without a reply.
pub const TIME_EXCEEDED_PER_SECOND: f64 = 100.0;

/// Where a held packet goes when its time comes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum To {
    Sandbox,
    Sites,
    Home,
    Foreign,
}

/// A packet on its way, until `at`. Ordered by time, then by arrival, so
/// packets to one place keep their order.
struct Held {
    at: Instant,
    seq: u64,
    to: To,
    packet: Packet,
}

impl PartialEq for Held {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.seq) == (other.at, other.seq)
    }
}
impl Eq for Held {}
impl PartialOrd for Held {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Held {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.at, self.seq).cmp(&(other.at, other.seq))
    }
}

/// The packets on their way, in release order.
#[derive(Default)]
struct OnTheWay {
    heap: BinaryHeap<Reverse<Held>>,
    seq: u64,
}

impl OnTheWay {
    fn hold(&mut self, at: Instant, to: To, packet: Packet) {
        self.seq += 1;
        self.heap.push(Reverse(Held { at, seq: self.seq, to, packet }));
    }

    fn next_time(&self) -> Option<Instant> {
        self.heap.peek().map(|h| h.0.at)
    }

    /// The next packet whose time has come by `now`.
    fn due(&mut self, now: Instant) -> Option<(To, Packet)> {
        if self.next_time()? > now {
            return None;
        }
        self.heap.pop().map(|Reverse(h)| (h.to, h.packet))
    }
}

/// A token bucket: `rate` a second, up to `rate` at once.
struct Bucket {
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl Bucket {
    fn new(now: Instant, rate: f64) -> Bucket {
        Bucket { tokens: rate, rate, last: now }
    }

    fn take(&mut self, now: Instant) -> bool {
        let gained = now.since_start().saturating_sub(self.last.since_start()).as_secs_f64() * self.rate;
        self.tokens = (self.tokens + gained).min(self.rate);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Runs the path for one sandbox until it detaches.
pub async fn run(cx: Cx, mut sandbox: impl Interface, mut inner: End, shared: Arc<Shared>, name: Arc<str>) -> fictionet::Result {
    let scenario = shared.scenario.clone();
    let (mut home, home_side) = pair();
    router(&cx, home_side, HOME.router, Some((&shared, name.clone())));
    let (mut foreign, foreign_side) = pair();
    router(&cx, foreign_side, FOREIGN.router, None);

    let mut on_the_way = OnTheWay::default();
    let mut time_exceeded_budget = Bucket::new(cx.now(), TIME_EXCEEDED_PER_SECOND);
    let mut id: u16 = 0;
    let mut run = 0u32;
    let mut first = 0usize;
    loop {
        // Round robin over the four ends, starting after the last one
        // served, so a busy end cannot starve the others. A packet whose
        // time has come wakes the task too.
        let got = {
            let sleep = on_the_way.next_time().map(|at| cx.sleep_until(at));
            let mut sleep = pin!(sleep);
            std::future::poll_fn(|task| {
                for k in 0..4 {
                    let i = (first + k) % 4;
                    let end: &mut dyn Interface = match i {
                        0 => &mut sandbox,
                        1 => &mut inner,
                        2 => &mut home,
                        _ => &mut foreign,
                    };
                    if let Poll::Ready(r) = end.poll_recv(&cx, task) {
                        return Poll::Ready(r.map(|p| Some((i, p))));
                    }
                }
                if let Some(sleep) = sleep.as_mut().as_pin_mut()
                    && let Poll::Ready(r) = sleep.poll(task)
                {
                    return Poll::Ready(r.map(|()| None).map_err(RecvError::from));
                }
                Poll::Pending
            })
            .await
        };
        let (from, packet) = match got {
            // The time of the first packet on its way has come.
            Ok(None) => {
                let now = cx.now();
                let mut sent = 0;
                while sent < 64 {
                    let Some((to, packet)) = on_the_way.due(now) else { break };
                    match to {
                        To::Sandbox => sandbox.send(packet),
                        To::Sites => inner.send(packet),
                        To::Home => home.send(packet),
                        To::Foreign => foreign.send(packet),
                    }
                    sent += 1;
                }
                run += sent;
                if run >= 64 {
                    run = 0;
                    cx.yield_now().await?;
                }
                continue;
            }
            Ok(Some((i, p))) => (i, p),
            // The sandbox detached, or `Sites` stopped. A router's end
            // closes only with this task.
            Err(RecvError::Closed) => return Ok(()),
            // The world is stopping: a cancel, which is not a failure.
            Err(e @ RecvError::Cancelled) => return Err(e.into()),
        };
        first = (from + 1) % 4;
        let now = cx.now();
        match from {
            0 => {
                let Some(dst) = v4_dst(&packet.0) else {
                    inner.send(packet);
                    continue;
                };
                if is_special(dst) {
                    inner.send(packet);
                    continue;
                }
                let hops = scenario.hops(dst);
                if hops.is_empty() {
                    on_the_way.hold(now + scenario.one_way(dst), To::Sites, packet);
                    continue;
                }
                let mut p = packet.0;
                let ttl = p[8];
                // Where the packet's way ends: at `dst`, or, with no host
                // there, at the last router, which has no route for it.
                let ends_at = (!scenario.has_host(dst)).then(|| hops.len() - 1);
                let reach = ends_at.unwrap_or(hops.len());
                if usize::from(ttl) <= reach {
                    // It runs out at hop `ttl` (a TTL of 0 at the first).
                    let at = usize::from(ttl.max(1)) - 1;
                    if !time_exceeded_budget.take(now) {
                        continue;
                    }
                    if let Some(reply) = icmp_error(&p, hops[at], TTL - at as u8, id, 11, 0) {
                        id = id.wrapping_add(1);
                        shared.log.line(json!({
                            "type": "ttl_exceeded",
                            "sandbox": &*name,
                            "hop": hops[at].to_string(),
                            "dst": dst.to_string(),
                            "protocol": p[9],
                        }));
                        on_the_way.hold(now + scenario.one_way(hops[at]) * 2, To::Sandbox, reply);
                    }
                    continue;
                }
                if let Some(k) = ends_at {
                    // The quote shows the TTL the packet had at that router.
                    set_ttl(&mut p, ttl - k as u8);
                    if let Some(reply) = icmp_error(&p, hops[k], TTL - k as u8, id, 3, 1) {
                        id = id.wrapping_add(1);
                        shared.log.line(json!({
                            "type": "unreachable",
                            "sandbox": &*name,
                            "from": hops[k].to_string(),
                            "dst": dst.to_string(),
                            "protocol": p[9],
                        }));
                        on_the_way.hold(now + scenario.one_way(hops[k]) * 2, To::Sandbox, reply);
                    }
                    continue;
                }
                set_ttl(&mut p, ttl - hops.len() as u8);
                let to = if dst == HOME.router {
                    To::Home
                } else if dst == FOREIGN.router {
                    To::Foreign
                } else {
                    To::Sites
                };
                on_the_way.hold(now + scenario.one_way(dst), to, Packet(p));
            }
            _ => {
                // Toward the sandbox: back over the same routers, taking
                // the same time.
                let mut p = packet.0;
                let Some(src) = v4_src(&p) else {
                    sandbox.send(Packet(p));
                    continue;
                };
                let back = scenario.hops(src).len() as u8;
                if back > 0 {
                    let ttl = p[8].saturating_sub(back).max(1);
                    set_ttl(&mut p, ttl);
                }
                let by = if is_special(src) { Duration::ZERO } else { scenario.one_way(src) };
                on_the_way.hold(now + by, To::Sandbox, Packet(p));
            }
        }
        run += 1;
        if run >= 64 {
            run = 0;
            if cx.yield_now().await.is_err() {
                return Ok(());
            }
        }
    }
}

/// Starts a router's machine at `addr` on `side`: pings, RSTs, "port
/// unreachable", and the BGP speaker if `bgp` is given.
fn router(cx: &Cx, side: End, addr: Ipv4Addr, bgp: Option<(&Arc<Shared>, Arc<str>)>) {
    let (tcp, udp, mut icmp, _other) = ip::split_protocols(cx, side);
    let tcp = tcp::endpoint(cx, tcp, addr.into());
    // No UDP ports: every datagram gets "port unreachable".
    let _udp = udp::endpoint(cx, udp, addr.into());
    cx.spawn(move |cx| async move {
        while let Ok(packet) = icmp.recv(&cx).await {
            if let Some(reply) = icmp::echo_reply(&packet, addr.into()) {
                icmp.send(reply);
            }
        }
        Ok(())
    });
    if let Some((shared, name)) = bgp {
        if let Ok(listener) = tcp.listen(179) {
            let (scenario, log) = (shared.scenario.clone(), shared.log.clone());
            cx.spawn(move |cx| bgp::serve(cx, listener, scenario, log, name));
        }
    }
}

/// Broadcast, multicast and unspecified addresses go to `Sites` as they are.
fn is_special(a: Ipv4Addr) -> bool {
    a.is_broadcast() || a.is_multicast() || a.is_unspecified()
}

/// The IPv4 header length of `p`, if `p` is an IPv4 packet with a whole
/// header.
fn header_len(p: &[u8]) -> Option<usize> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    (ihl >= 20 && p.len() >= ihl).then_some(ihl)
}

fn v4_dst(p: &[u8]) -> Option<Ipv4Addr> {
    header_len(p).map(|_| Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

fn v4_src(p: &[u8]) -> Option<Ipv4Addr> {
    header_len(p).map(|_| Ipv4Addr::new(p[12], p[13], p[14], p[15]))
}

/// Sets the TTL of the IPv4 packet `p` and its header checksum.
fn set_ttl(p: &mut [u8], ttl: u8) {
    let Some(ihl) = header_len(p) else { return };
    p[8] = ttl;
    ip::set_header_checksum(&mut p[..ihl]);
}

/// The most of a packet an ICMP error quotes: RFC 1812 keeps the error
/// within 576 bytes.
const QUOTE: usize = 576 - 20 - 8;

/// ICMP "time exceeded in transit" for `p`, from router `from`, sent with
/// `ttl`. `None` where RFC 1122 forbids one: for ICMP errors, fragments
/// after the first, and packets from an address that is not one host.
pub fn time_exceeded(p: &[u8], from: Ipv4Addr, ttl: u8, id: u16) -> Option<Packet> {
    icmp_error(p, from, ttl, id, 11, 0)
}

/// An ICMP error of `kind` and `code` about `p`, from router `from`, sent
/// with `ttl`, quoting `p` as the router got it. `None` where RFC 1122
/// forbids one (see [`time_exceeded`]).
pub fn icmp_error(p: &[u8], from: Ipv4Addr, ttl: u8, id: u16, kind: u8, code: u8) -> Option<Packet> {
    let ihl = header_len(p)?;
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    if is_special(src) || src.is_loopback() {
        return None;
    }
    let frag_offset = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    if frag_offset != 0 {
        return None;
    }
    if p[9] == 1 && p.len() > ihl && matches!(p[ihl], 3 | 4 | 5 | 11 | 12) {
        return None;
    }
    // The quote is the packet as this router got it. A packet that ran out
    // of time had a TTL of 1 left there.
    let mut quoted = p[..p.len().min(QUOTE)].to_vec();
    if kind == 11 {
        set_ttl(&mut quoted, 1);
    }
    let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&quoted);
    let sum = ip::checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let total = 20 + icmp.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0, 0, ttl, 1, 0, 0]);
    out.extend_from_slice(&from.octets());
    out.extend_from_slice(&src.octets());
    ip::set_header_checksum(&mut out[..20]);
    out.extend_from_slice(&icmp);
    Some(Packet(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::ip::checksum;

    fn packet(proto: u8, ttl: u8, frag: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 7, (frag >> 8) as u8, frag as u8, ttl, proto, 0, 0];
        p.extend_from_slice(&[10, 0, 0, 2, 84, 21, 44, 10]);
        let sum = checksum(&p);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn time_exceeded_quotes_the_packet_from_the_router() {
        let probe = packet(17, 2, 0, &[0x9c, 0x40, 0x82, 0x9a, 0, 13, 0, 0, b'x', b'y', b'z', b'w', b'v']);
        let reply = time_exceeded(&probe, HOME.router, 63, 5).unwrap().0;
        assert_eq!(checksum(&reply[..20]), 0);
        assert_eq!((reply[8], reply[9]), (63, 1));
        assert_eq!(&reply[12..16], &HOME.router.octets());
        assert_eq!(&reply[16..20], &[10, 0, 0, 2]);
        let icmp = &reply[20..];
        assert_eq!((icmp[0], icmp[1]), (11, 0));
        assert_eq!(checksum(icmp), 0);
        // The whole probe, with the TTL it had left there, and a good checksum.
        let quoted = &icmp[8..];
        assert_eq!(quoted.len(), probe.len());
        assert_eq!(quoted[8], 1);
        assert_eq!(checksum(&quoted[..20]), 0);
        assert_eq!(&quoted[20..], &probe[20..]);
    }

    #[test]
    fn no_time_exceeded_for_icmp_errors_or_later_fragments() {
        assert!(time_exceeded(&packet(1, 1, 0, &[3, 1, 0, 0, 0, 0, 0, 0]), HOME.router, 64, 0).is_none());
        assert!(time_exceeded(&packet(1, 1, 0, &[11, 0, 0, 0, 0, 0, 0, 0]), HOME.router, 64, 0).is_none());
        assert!(time_exceeded(&packet(17, 1, 0x2001, &[0; 8]), HOME.router, 64, 0).is_none());
        // A ping is answered, and so is a first fragment.
        assert!(time_exceeded(&packet(1, 1, 0, &[8, 0, 0, 0, 0, 0, 0, 0]), HOME.router, 64, 0).is_some());
        assert!(time_exceeded(&packet(17, 1, 0x2000, &[0; 8]), HOME.router, 64, 0).is_some());
        // Not IPv4 at all.
        assert!(time_exceeded(&[0x60; 40], HOME.router, 64, 0).is_none());
    }

    #[test]
    fn setting_the_ttl_keeps_the_header_checksum_right() {
        let mut p = packet(6, 64, 0, &[0; 20]);
        set_ttl(&mut p, 61);
        assert_eq!(p[8], 61);
        assert_eq!(checksum(&p[..20]), 0);
    }
}
