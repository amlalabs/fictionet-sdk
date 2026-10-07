//! UDP: sockets for a machine on the simulated network.
//!
//! Use this module to give a machine UDP, for example to run a DNS server
//! (see [`dns`](crate::stdlib::dns)). [`endpoint`] takes an [`Interface`]
//! that carries the machine's UDP packets, and the machine's address. It returns an [`Endpoint`], on which you
//! [`bind`](Endpoint::bind) a [`Socket`] for each port. A socket receives
//! datagrams with [`recv`](Socket::recv) and sends them with
//! [`send_to`](Socket::send_to).
//!
//! The interface comes from [`ip::split_protocols`],
//! which splits a machine's packets so that only UDP, and ICMP errors
//! about it, reach this layer.
//! The [`ip`] page shows a whole machine.

use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use crate::cx::CancelWait;
use crate::stdlib::icmp;
use crate::stdlib::ip::{self, Fields, Header, protocol};
use crate::{Cx, Error, Interface, Packet, RecvError};

/// How many bytes of datagrams a socket holds before it drops new ones,
/// like a full socket buffer, counting [`DATAGRAM_COST`] more for each.
const QUEUE: usize = 1 << 20;
/// What a queued datagram costs beyond its bytes: its sender's address and
/// its place in the queue. So a flood of tiny datagrams is bounded too.
const DATAGRAM_COST: usize = 64;

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
/// A socket holds at most 1 MiB of datagrams it has not received yet,
/// counting 64 bytes more for each datagram. Further datagrams are dropped,
/// as with a full socket buffer. ICMP messages that
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
    /// What `datagrams` holds, counted as for [`QUEUE`].
    bytes: usize,
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
    let Some(ip) = Header::parse_whole(&packet.0) else { return };
    if ip.protocol != protocol::UDP {
        return;
    }
    let group = ip.dst != shared.addr;
    if group && !shared.state.lock().unwrap().groups.contains(&ip.dst) {
        return;
    }
    let udp = ip.payload(&packet.0);
    if udp.len() < 8 {
        return;
    }
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if len < 8 || len > udp.len() {
        return;
    }
    let udp = &udp[..len];
    if !ip::udp_checksum_ok(ip.src, ip.dst, udp) {
        return;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let from = SocketAddr::new(ip.src, src_port);
    let reply = {
        let mut st = shared.state.lock().unwrap();
        match st.sockets.get_mut(&dst_port) {
            Some(q) => {
                let cost = udp.len() - 8 + DATAGRAM_COST;
                if q.bytes + cost <= QUEUE {
                    q.bytes += cost;
                    q.datagrams.push_back((udp[8..].to_vec(), from));
                }
                if let Some(w) = q.waker.take() {
                    w.wake();
                }
                None
            }
            // No one answers a group's datagram with an error.
            None if group => None,
            None => port_unreachable(&packet.0, ip.dst),
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
            return Err(fictionet::Error::msg(format!("{group} is not a multicast group {} can join", self.shared.addr)));
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
            return Err(fictionet::Error::msg("UDP port 0 cannot be bound"));
        }
        let mut st = self.shared.state.lock().unwrap();
        if st.sockets.contains_key(&port) {
            return Err(fictionet::Error::msg(format!("UDP port {port} is already bound on {}", self.shared.addr)));
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
                    q.bytes -= d.0.len() + DATAGRAM_COST;
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
        let mut sum = ip::transport_checksum(src, to.ip(), protocol::UDP, &udp);
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
        let packet = ip::packet_with(src, to.ip(), protocol::UDP, Fields { id, ..Fields::default() }, &udp);
        self.shared.inner.lock().unwrap().send(packet);
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let removed = self.shared.state.lock().unwrap().sockets.remove(&self.port);
        drop(removed);
    }
}

/// The ICMP "port unreachable" answer to `packet`, a whole UDP packet to
/// `addr`, this machine (RFC 1122, RFC 4443).
fn port_unreachable(packet: &[u8], addr: IpAddr) -> Option<Packet> {
    match addr {
        IpAddr::V4(_) => icmp::error(packet, addr, 3, 3, 0),
        IpAddr::V6(_) => icmp::error(packet, addr, 1, 4, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block_on, pair, run};

    /// A UDP datagram from 10.0.0.2 to port 53 of 10.0.0.1, with a good
    /// checksum.
    fn datagram(data: &[u8]) -> Packet {
        let (src, dst): (IpAddr, IpAddr) = ("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());
        let mut u = [&[0, 9, 0, 53][..], &((8 + data.len()) as u16).to_be_bytes(), &[0, 0], data].concat();
        let sum = ip::transport_checksum(src, dst, protocol::UDP, &u);
        u[6..8].copy_from_slice(&sum.to_be_bytes());
        ip::packet(src, dst, protocol::UDP, &u)
    }

    /// A socket's queue is bounded by bytes, not by datagrams: before, it
    /// held 1,024 of any size, 64 MiB of the largest.
    #[test]
    fn a_socket_holds_at_most_its_queue_in_bytes() {
        let result = block_on(run(|cx| async move {
            let (mut raw, side) = pair();
            let mut socket = endpoint(&cx, side, "10.0.0.1".parse().unwrap()).bind(53)?;
            let big = vec![7; 60_000];
            for _ in 0..40 {
                raw.send(datagram(&big));
            }
            cx.sleep(crate::time::ms(10)).await?;
            let fits = QUEUE / (big.len() + DATAGRAM_COST);
            for _ in 0..fits {
                assert_eq!(socket.recv(&cx).await?.0.len(), big.len());
            }
            // The rest were dropped, and the room is there again.
            raw.send(datagram(b"after"));
            assert_eq!(socket.recv(&cx).await?.0, b"after");
            Err::<(), crate::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
}
