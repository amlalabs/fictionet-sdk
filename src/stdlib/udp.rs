//! UDP: sockets for a machine on the simulated network.
//!
//! Use this module to give a machine UDP, for example to run a DNS server
//! (see [`dns`](crate::stdlib::dns)). [`endpoint`] takes an [`Interface`]
//! that carries the machine's UDP packets, and the machine's address. It returns an [`Endpoint`], on which you
//! [`bind`](Endpoint::bind) a [`Socket`] for each port. A socket receives
//! datagrams with [`recv`](Socket::recv) and sends them with
//! [`send_to`](Socket::send_to).
//!
//! The interface comes from [`ip::split_protocols`](crate::stdlib::ip::split_protocols),
//! which splits a machine's packets so that only UDP, and ICMP errors
//! about it, reach this layer.
//! The [`ip`](crate::stdlib::ip) page shows a whole machine.

use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use crate::cx::CancelWait;
use crate::stdlib::wire;
use crate::{Cx, Error, Interface, Packet, RecvError};

/// How many datagrams a socket holds before it drops new ones, like a full
/// socket buffer.
const QUEUE: usize = 1024;

/// Starts UDP for a machine with address `addr`, on the UDP packets of
/// `inner`.
///
/// Starts a background task and returns immediately with an [`Endpoint`].
/// The task takes UDP packets sent to `addr`, and to the multicast groups
/// the endpoint [joined](Endpoint::join), and drops the rest. A packet for
/// `addr` and a port with no socket gets an ICMP "port unreachable" reply,
/// because that is part of UDP's job. Everything it sends goes into
/// `inner`.
///
/// The task stops when the caller's [region](crate::Cx#regions) is
/// cancelled or `inner` closes. The endpoint's sockets then return
/// [`RecvError::Closed`] once their queued datagrams have been received.
///
/// A datagram with a bad checksum is dropped. So is one over IPv6 whose
/// checksum field is zero: that means "no checksum" only over IPv4, and
/// RFC 8200 forbids it over IPv6.
///
/// A socket holds at most 1,024 datagrams it has not received yet. Further
/// datagrams are dropped, as with a full socket buffer. ICMP messages that
/// reach this layer, such as errors about datagrams it sent, are dropped.
#[track_caller]
pub fn endpoint(cx: &Cx, inner: impl Interface, addr: IpAddr) -> Endpoint {
    let shared = Arc::new(Shared {
        addr,
        inner: Mutex::new(Box::new(inner)),
        state: Mutex::new(State { sockets: HashMap::new(), stopped: false, ip_id: cx.random_u64() as u16, groups: Vec::new() }),
    });
    let driver = shared.clone();
    cx.spawn_as(|| "udp::endpoint".into(), move |cx| async move {
        drive(&cx, &driver).await;
        let wakers: Vec<Waker> = {
            let mut st = driver.state.lock().unwrap();
            st.stopped = true;
            st.sockets.values_mut().filter_map(|s| s.waker.take()).collect()
        };
        for w in wakers {
            w.wake();
        }
        Ok(())
    });
    Endpoint { shared }
}

struct Shared {
    addr: IpAddr,
    /// The interface. The driver reads it; `send_to` and the driver write it.
    inner: Mutex<Box<dyn Interface>>,
    state: Mutex<State>,
}

struct State {
    sockets: HashMap<u16, Queue>,
    /// Multicast groups joined.
    groups: Vec<IpAddr>,
    stopped: bool,
    ip_id: u16,
}

#[derive(Default)]
struct Queue {
    datagrams: VecDeque<(Vec<u8>, SocketAddr)>,
    waker: Option<Waker>,
}

async fn drive(cx: &Cx, shared: &Shared) {
    loop {
        let mut n = 0;
        loop {
            let next = poll_fn(|task| {
                let mut inner = shared.inner.lock().unwrap();
                match inner.poll_recv(cx, task) {
                    Poll::Ready(r) => Poll::Ready(Some(r)),
                    // Only wait when nothing came in this round; otherwise
                    // hand back to yield.
                    Poll::Pending if n > 0 => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            match next {
                Some(Ok(packet)) => {
                    deliver(shared, packet);
                    n += 1;
                    if n == 64 {
                        break;
                    }
                }
                Some(Err(_)) => return,
                None => break,
            }
        }
        if n == 64 && cx.yield_now().await.is_err() {
            return;
        }
    }
}

/// Puts one packet from the interface into its socket, or answers it with port
/// unreachable.
fn deliver(shared: &Shared, packet: Packet) {
    let Some(ip) = parse_ip(&packet.0) else { return };
    if ip.proto != UDP {
        return;
    }
    let group = ip.dst != shared.addr;
    if group && !shared.state.lock().unwrap().groups.contains(&ip.dst) {
        return;
    }
    let udp = &packet.0[ip.payload..ip.end];
    if udp.len() < 8 {
        return;
    }
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if len < 8 || len > udp.len() {
        return;
    }
    let udp = &udp[..len];
    if !udp_checksum_ok(ip.src, ip.dst, udp) {
        return;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let from = SocketAddr::new(ip.src, src_port);
    let reply = {
        let mut st = shared.state.lock().unwrap();
        match st.sockets.get_mut(&dst_port) {
            Some(q) => {
                if q.datagrams.len() < QUEUE {
                    q.datagrams.push_back((udp[8..].to_vec(), from));
                }
                if let Some(w) = q.waker.take() {
                    w.wake();
                }
                None
            }
            // No one answers a group's datagram with an error.
            None if group => None,
            None => {
                st.ip_id = st.ip_id.wrapping_add(1);
                port_unreachable(&packet.0[..ip.end], ip.src, ip.dst, st.ip_id)
            }
        }
    };
    if let Some(reply) = reply {
        shared.inner.lock().unwrap().send(reply);
    }
}

/// One machine's UDP, made by [`endpoint`].
///
/// An `Endpoint` is a handle to the endpoint's task. Clones share the same
/// machine.
#[derive(Clone)]
pub struct Endpoint {
    shared: Arc<Shared>,
}

impl Endpoint {
    /// Joins the multicast group `group`: datagrams sent to it reach this
    /// endpoint's sockets on their ports, as datagrams to its own address
    /// do. Delivering them is the network's job: a
    /// [`route::lan`](crate::stdlib::route::lan) floods multicast to every
    /// member.
    ///
    /// Fails if `group` is not a multicast address of the endpoint's family.
    pub fn join(&self, group: IpAddr) -> Result<(), Error> {
        if !group.is_multicast() || group.is_ipv4() != self.shared.addr.is_ipv4() {
            return Err(format!("{group} is not a multicast group {} can join", self.shared.addr).into());
        }
        let mut st = self.shared.state.lock().unwrap();
        if !st.groups.contains(&group) {
            st.groups.push(group);
        }
        Ok(())
    }

    /// Leaves the multicast group `group`.
    pub fn leave(&self, group: IpAddr) {
        self.shared.state.lock().unwrap().groups.retain(|g| *g != group);
    }

    /// Opens a socket on `port`.
    ///
    /// Fails if `port` is 0 or a socket is already open there. Dropping the
    /// socket frees the port.
    pub fn bind(&self, port: u16) -> Result<Socket, Error> {
        if port == 0 {
            return Err("UDP port 0 cannot be bound".into());
        }
        let mut st = self.shared.state.lock().unwrap();
        if st.sockets.contains_key(&port) {
            return Err(format!("UDP port {port} is already bound on {}", self.shared.addr).into());
        }
        st.sockets.insert(port, Queue::default());
        Ok(Socket { shared: self.shared.clone(), port, wait: CancelWait::default() })
    }
}

/// A UDP socket on one port.
pub struct Socket {
    shared: Arc<Shared>,
    port: u16,
    wait: CancelWait,
}

impl Socket {
    /// Waits for the next datagram. Returns its bytes and who sent it.
    ///
    /// Returns early with [`RecvError::Cancelled`] if `cx`'s
    /// [region](crate::Cx#regions) is cancelled, and fails with
    /// [`RecvError::Closed`] once the endpoint has stopped and every
    /// datagram already queued for this socket has been received.
    pub async fn recv(&mut self, cx: &Cx) -> Result<(Vec<u8>, SocketAddr), RecvError> {
        let port = self.port;
        let shared = &self.shared;
        let wait = &mut self.wait;
        poll_fn(|task| {
            if cx.is_cancelled() {
                return Poll::Ready(Err(RecvError::Cancelled));
            }
            {
                let mut st = shared.state.lock().unwrap();
                let stopped = st.stopped;
                let q = st.sockets.get_mut(&port).expect("a bound socket has a queue");
                if let Some(d) = q.datagrams.pop_front() {
                    return Poll::Ready(Ok(d));
                }
                if stopped {
                    return Poll::Ready(Err(RecvError::Closed));
                }
                match &q.waker {
                    Some(w) if w.will_wake(task.waker()) => {}
                    _ => q.waker = Some(task.waker().clone()),
                }
            }
            if cx.register_cancel(task.waker(), wait) {
                return Poll::Ready(Err(RecvError::Cancelled));
            }
            Poll::Pending
        })
        .await
    }

    /// Sends `data` to `to`.
    ///
    /// Never waits, like [`Interface::send`]. If it cannot be delivered, it
    /// is lost, as UDP datagrams are. A datagram to an address of the other
    /// IP version than the endpoint's, or one too long for a single IP
    /// packet, is lost too. Datagrams are never split into fragments.
    pub fn send_to(&mut self, data: &[u8], to: SocketAddr) {
        let src = self.shared.addr;
        // IPv4's total length counts its 20-byte header; IPv6's payload
        // length does not count its 40-byte header.
        let max = if src.is_ipv4() { 65_535 - 20 - 8 } else { 65_535 - 8 };
        if src.is_ipv4() != to.is_ipv4() || data.len() > max {
            return;
        }
        let mut udp = Vec::with_capacity(8 + data.len());
        udp.extend_from_slice(&self.port.to_be_bytes());
        udp.extend_from_slice(&to.port().to_be_bytes());
        udp.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(data);
        let mut sum = transport_checksum(src, to.ip(), UDP, &udp);
        if sum == 0 {
            sum = 0xffff;
        }
        udp[6..8].copy_from_slice(&sum.to_be_bytes());
        let id = {
            let mut st = self.shared.state.lock().unwrap();
            if st.stopped {
                return;
            }
            st.ip_id = st.ip_id.wrapping_add(1);
            st.ip_id
        };
        let packet = ip_packet(src, to.ip(), UDP, id, &udp);
        self.shared.inner.lock().unwrap().send(packet);
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let removed = self.shared.state.lock().unwrap().sockets.remove(&self.port);
        drop(removed);
    }
}

// Small IP helpers, shared with the TCP endpoint.

pub(crate) const TCP: u8 = 6;
pub(crate) const UDP: u8 = 17;

/// The parts of an IP header the endpoints need.
pub(crate) struct IpInfo {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    /// The upper-layer protocol, after any IPv6 extension headers.
    pub(crate) proto: u8,
    /// Where the upper-layer header starts.
    pub(crate) payload: usize,
    /// Where the packet ends, from its length field.
    pub(crate) end: usize,
}

/// Reads an IPv4 or IPv6 header. `None` for anything malformed, including
/// IPv6 extension headers that [`wire::ext6_chain`] rejects, and for
/// fragments, which [`split_protocols`](crate::stdlib::ip::split_protocols)
/// puts back together before they reach an endpoint.
pub(crate) fn parse_ip(p: &[u8]) -> Option<IpInfo> {
    match p.first()? >> 4 {
        4 => {
            if p.len() < 20 {
                return None;
            }
            let ihl = (p[0] & 0x0f) as usize * 4;
            let total = u16::from_be_bytes([p[2], p[3]]) as usize;
            if ihl < 20 || total < ihl || total > p.len() {
                return None;
            }
            let frag = u16::from_be_bytes([p[6], p[7]]);
            if frag & 0x3fff != 0 {
                return None; // more fragments, or an offset
            }
            let src = IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
            Some(IpInfo { src, dst, proto: p[9], payload: ihl, end: total })
        }
        6 => {
            // Extension headers a host must not accept make the packet
            // malformed here. `split_protocols` answers them where RFC 8200
            // asks for an answer.
            let chain = wire::ext6_chain(p).ok()?;
            if chain.frag.is_some() {
                return None;
            }
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap()));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()));
            Some(IpInfo { src, dst, proto: chain.proto, payload: chain.upper, end: chain.end })
        }
        _ => None,
    }
}

fn sum16(mut acc: u32, data: &[u8]) -> u32 {
    let (chunks, rest) = data.as_chunks::<2>();
    for c in chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = rest {
        acc += (*last as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The TCP/UDP/ICMPv6 checksum over the pseudo-header and `data`. Over a
/// segment whose checksum field is filled in, a correct one gives 0.
pub(crate) fn transport_checksum(src: IpAddr, dst: IpAddr, proto: u8, data: &[u8]) -> u16 {
    let mut acc = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum16(acc, &s.octets());
            acc = sum16(acc, &d.octets());
            acc += proto as u32 + data.len() as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = sum16(acc, &s.octets());
            acc = sum16(acc, &d.octets());
            acc += (data.len() as u32 >> 16) + (data.len() as u32 & 0xffff) + proto as u32;
        }
        _ => return 1,
    }
    fold(sum16(acc, data))
}

/// Whether the UDP datagram `udp`, from `src` to `dst`, has a good
/// checksum. A checksum field of zero means "no checksum" over IPv4. Over
/// IPv6 it is never valid (RFC 8200, section 8.1): a sender whose sum
/// comes out as zero sends `0xffff` instead.
pub(crate) fn udp_checksum_ok(src: IpAddr, dst: IpAddr, udp: &[u8]) -> bool {
    if udp.len() < 8 {
        return false;
    }
    if udp[6..8] == [0, 0] {
        return src.is_ipv4();
    }
    transport_checksum(src, dst, UDP, udp) == 0
}

/// The checksum of an IPv4 header whose checksum field is zero.
pub(crate) fn ipv4_header_checksum(header: &[u8]) -> u16 {
    fold(sum16(0, header))
}

/// Builds an IP packet around `payload`, whose checksums are already done.
pub(crate) fn ip_packet(src: IpAddr, dst: IpAddr, proto: u8, id: u16, payload: &[u8]) -> Packet {
    let mut p;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            p = Vec::with_capacity(20 + payload.len());
            let total = (20 + payload.len()) as u16;
            p.extend_from_slice(&[0x45, 0]);
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&[0x40, 0, 64, proto, 0, 0]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let sum = fold(sum16(0, &p[..20]));
            p[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            p = Vec::with_capacity(40 + payload.len());
            p.extend_from_slice(&[0x60, 0, 0, 0]);
            p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            p.extend_from_slice(&[proto, 64]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
        }
        _ => unreachable!("callers check that the versions match"),
    }
    p.extend_from_slice(payload);
    Packet(p)
}

/// The ICMP "port unreachable" answer to `original`, a packet from `src` to
/// `dst` (this machine). It quotes as much of `original` as RFC 1812 (IPv4)
/// and RFC 4443 (IPv6) allow.
fn port_unreachable(original: &[u8], src: IpAddr, dst: IpAddr, id: u16) -> Option<Packet> {
    if is_not_unicast(src) {
        return None;
    }
    match (src, dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            let quote = &original[..original.len().min(576 - 28)];
            let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(quote);
            let sum = fold(sum16(0, &icmp));
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            Some(ip_packet(dst, src, 1, id, &icmp))
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            let quote = &original[..original.len().min(1280 - 48)];
            let mut icmp = vec![1, 4, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(quote);
            let sum = transport_checksum(dst, src, 58, &icmp);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            Some(ip_packet(dst, src, 58, id, &icmp))
        }
        _ => None,
    }
}

/// Addresses that never get ICMP errors: unspecified, broadcast, multicast.
fn is_not_unicast(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => a.is_unspecified() || a.is_broadcast() || a.is_multicast(),
        IpAddr::V6(a) => a.is_unspecified() || a.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_checksum_means_none_only_over_ipv4() {
        let (v4a, v4b): (IpAddr, IpAddr) = ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
        let (v6a, v6b): (IpAddr, IpAddr) = ("2001:db8::2".parse().unwrap(), "2001:db8::1".parse().unwrap());
        let mut u = vec![0, 1, 0, 2, 0, 10, 0, 0, 0xab, 0xcd];
        assert!(udp_checksum_ok(v4a, v4b, &u));
        assert!(!udp_checksum_ok(v6a, v6b, &u));
        // Data whose sum, with the field zero, comes out as zero: over
        // IPv6, the field must say 0xffff.
        let w = (0..=u16::MAX)
            .find(|w| {
                u[8..10].copy_from_slice(&w.to_be_bytes());
                transport_checksum(v6a, v6b, UDP, &u) == 0
            })
            .expect("some data sums to zero");
        u[8..10].copy_from_slice(&w.to_be_bytes());
        assert!(!udp_checksum_ok(v6a, v6b, &u));
        u[6..8].copy_from_slice(&[0xff, 0xff]);
        assert!(udp_checksum_ok(v6a, v6b, &u));
        // A wrong checksum fails over both.
        u[6..8].copy_from_slice(&[0x12, 0x34]);
        assert!(!udp_checksum_ok(v6a, v6b, &u));
        assert!(!udp_checksum_ok(v4a, v4b, &u));
    }
}
