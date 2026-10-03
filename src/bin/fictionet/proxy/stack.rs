//! Attach's own TCP/IP stack: the sandbox's kernel, in userspace.
//!
//! The SDK's stdlib stack runs on the world's interface ([`Link`]):
//! `ip::split_protocols`, `tcp::endpoint` and `udp::endpoint` at the
//! sandbox's address. A proxied connection becomes a lookup at the world's
//! DNS server (UDP from the sandbox's address) and a TCP connection from
//! that address. The world sees ordinary IP packets from that address, but
//! made by this stack, not by a sandbox kernel: `fictionet::lowering` lists
//! the differences.
//!
//! Nothing here opens a socket on the host toward a destination a client
//! names. Every connection is made of packets on the world's interface.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use fictionet::stdlib::tcp::TcpConnection;
use fictionet::stdlib::{ConnError, ip, tcp, udp};
use fictionet::{Cx, End, Interface, Packet, RecvError};
use tokio::sync::oneshot;

use super::dns::{self, Lookup};
use super::link::Link;

/// How long a connection may take to open before the client is told it
/// timed out. The stack itself would wait two minutes for a SYN that is
/// never answered.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A DNS query is sent again after each of these waits, then given up.
const DNS_WAITS: [Duration; 3] = [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4)];
/// At most this many names are cached.
const CACHE_SIZE: usize = 4096;
/// A name the world says does not exist is remembered this long, so a
/// client that retries it does not send a query each time.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);
/// Local ports for DNS queries.
const EPHEMERAL: u16 = 49152;

/// Why a connection could not be made. Each door maps it to its own
/// answer: an HTTP status, or a SOCKS5 reply code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    /// The name does not exist in the world (NXDOMAIN), or has no IPv4
    /// address.
    NoSuchName,
    /// The world's DNS server answered with an error, or not at all.
    Dns(String),
    /// The other side answered the SYN with a RST.
    Refused,
    /// ICMP destination unreachable, with its code: 0 network, 1 host,
    /// 3 port, and so on.
    Unreachable(u8),
    /// No answer within [`CONNECT_TIMEOUT`].
    TimedOut,
    /// The world is gone: the connection to it closed.
    WorldGone,
    /// An address this stack cannot reach: IPv6, or port 0.
    BadAddress(&'static str),
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::NoSuchName => f.write_str("no such name in the world"),
            Fail::Dns(why) => write!(f, "the world's DNS failed: {why}"),
            Fail::Refused => f.write_str("connection refused"),
            Fail::Unreachable(0) => f.write_str("network unreachable"),
            Fail::Unreachable(1) => f.write_str("host unreachable"),
            Fail::Unreachable(3) => f.write_str("port unreachable"),
            Fail::Unreachable(code) => write!(f, "destination unreachable (ICMP code {code})"),
            Fail::TimedOut => f.write_str("connection timed out"),
            Fail::WorldGone => f.write_str("the world is gone"),
            Fail::BadAddress(why) => f.write_str(why),
        }
    }
}

/// Where a client wants to go, as it named it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    Name(String),
    V4(Ipv4Addr),
    V6(std::net::Ipv6Addr),
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Name(n) => f.write_str(n),
            Host::V4(a) => write!(f, "{a}"),
            Host::V6(a) => write!(f, "[{a}]"),
        }
    }
}

impl Host {
    /// Reads a host as it appears in a URL or a CONNECT target: a name, an
    /// IPv4 address, or an IPv6 address in brackets.
    pub(crate) fn parse(s: &str) -> Option<Host> {
        if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            return inner.parse().ok().map(Host::V6);
        }
        if let Ok(a) = s.parse::<Ipv4Addr>() {
            return Some(Host::V4(a));
        }
        dns::normalize(s).map(Host::Name)
    }
}

/// The stack. Clones share it.
#[derive(Clone)]
pub(crate) struct Stack {
    cx: Cx,
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    dns: SocketAddr,
    unreachable: Arc<Unreachable>,
    /// Each name's answer, and until when it holds: an address, or
    /// [`Fail::NoSuchName`].
    cache: Arc<Mutex<HashMap<String, Cached>>>,
    /// Lookups on their way, by name. A client that asks for a name already
    /// being looked up waits for that lookup instead of sending its own.
    pending: Arc<Mutex<HashMap<String, Arc<Lookup1>>>>,
}

/// A cached answer, and until when it holds.
type Cached = (Result<Ipv4Addr, Fail>, Instant);

/// One lookup, shared by the clients waiting for it.
type Lookup1 = tokio::sync::OnceCell<Result<(Ipv4Addr, u32), Fail>>;

/// A client's place in [`Stack::pending`]. Dropping it removes the lookup
/// once it has finished, or once no other client waits for it, so a name
/// whose clients all went away leaves nothing behind.
struct Waiting<'a> {
    pending: &'a Mutex<HashMap<String, Arc<Lookup1>>>,
    name: &'a str,
    /// Always `Some` until dropped.
    lookup: Option<Arc<Lookup1>>,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().unwrap();
        let Some(lookup) = self.lookup.take() else { return };
        // Clones are made and dropped only under this lock, so the count is
        // exact: the map's and this one mean no one else waits.
        let mine = pending.get(self.name).is_some_and(|l| Arc::ptr_eq(l, &lookup));
        if mine && (lookup.initialized() || Arc::strong_count(&lookup) == 2) {
            pending.remove(self.name);
        }
        drop(lookup);
    }
}

impl Stack {
    /// Starts the stack at `addr` on `link`, in `cx`'s region.
    pub(crate) fn new(cx: &Cx, link: Link, addr: Ipv4Addr, dns: Ipv4Addr) -> Stack {
        let (tcp_end, udp_end, _icmp, _other) = ip::split_protocols(cx, link);
        let unreachable = Arc::new(Unreachable::default());
        let watched = Watch { inner: tcp_end, unreachable: unreachable.clone() };
        Stack {
            cx: cx.clone(),
            tcp: tcp::endpoint(cx, watched, IpAddr::V4(addr)),
            udp: udp::endpoint(cx, udp_end, IpAddr::V4(addr)),
            dns: SocketAddr::new(IpAddr::V4(dns), 53),
            unreachable,
            cache: Arc::default(),
            pending: Arc::default(),
        }
    }

    pub(crate) fn cx(&self) -> &Cx {
        &self.cx
    }

    /// The world's address for `host`.
    pub(crate) async fn resolve(&self, host: &Host) -> Result<Ipv4Addr, Fail> {
        let name = match host {
            Host::V4(a) => return Ok(*a),
            Host::V6(_) => return Err(Fail::BadAddress("IPv6 is not supported: attach's stack is IPv4 only")),
            Host::Name(n) => n,
        };
        let cached = || {
            self.cache.lock().unwrap().get(name).filter(|(_, until)| Instant::now() < *until).map(|(a, _)| a.clone())
        };
        if let Some(answer) = cached() {
            return answer;
        }
        // One lookup per name at a time. If the client that started it goes
        // away, the next one waiting runs the lookup instead.
        let lookup = self.pending.lock().unwrap().entry(name.clone()).or_default().clone();
        let waiting = Waiting { pending: &self.pending, name, lookup: Some(lookup) };
        // A lookup that finished between the check above and joining this
        // one has put its answer in the cache already.
        if let Some(answer) = cached() {
            return answer;
        }
        let lookup = waiting.lookup.as_ref().unwrap();
        let result = lookup.get_or_init(|| self.lookup(name)).await.clone();
        let (answer, keep) = match result {
            Ok((addr, ttl)) => (Ok(addr), Duration::from_secs(ttl.into())),
            Err(Fail::NoSuchName) => (Err(Fail::NoSuchName), NEGATIVE_TTL),
            // A failure may pass: the next client asks again.
            Err(e) => return Err(e),
        };
        // Into the cache before the lookup leaves `pending` (when `waiting`
        // drops), so a client that comes later finds one or the other.
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_SIZE {
            let now = Instant::now();
            cache.retain(|_, (_, until)| *until > now);
            if cache.len() >= CACHE_SIZE {
                cache.clear();
            }
        }
        cache.insert(name.clone(), (answer.clone(), Instant::now() + keep));
        answer
    }

    /// Asks the world's DNS server for `name`'s `A` record.
    async fn lookup(&self, name: &str) -> Result<(Ipv4Addr, u32), Fail> {
        let mut socket = self.bind_ephemeral()?;
        let id = self.cx.random_u64() as u16;
        let q = dns::query(name, id).ok_or(Fail::NoSuchName)?;
        for wait in DNS_WAITS {
            socket.send_to(&q, self.dns);
            let deadline = tokio::time::Instant::now() + wait;
            loop {
                match tokio::time::timeout_at(deadline, socket.recv(&self.cx)).await {
                    Err(_) => break,
                    Ok(Err(RecvError::Closed | RecvError::Cancelled)) => return Err(Fail::WorldGone),
                    Ok(Ok((bytes, from))) => match dns::answer(&bytes, from, self.dns, name, id) {
                        None => continue,
                        Some(Ok(found)) => return Ok(found),
                        Some(Err(Lookup::NoSuchName)) => return Err(Fail::NoSuchName),
                        Some(Err(Lookup::Failed(why))) => return Err(Fail::Dns(why)),
                    },
                }
            }
        }
        Err(Fail::Dns(format!("no answer from {} in 7 s", self.dns.ip())))
    }

    /// A UDP socket on a free port from 49152 up, picked at random.
    fn bind_ephemeral(&self) -> Result<udp::Socket, Fail> {
        let span = (65536 - EPHEMERAL as u32) as u64;
        let start = self.cx.random_u64() % span;
        for i in 0..64 {
            let port = EPHEMERAL + ((start + i) % span) as u16;
            if let Ok(s) = self.udp.bind(port) {
                return Ok(s);
            }
        }
        Err(Fail::Dns("no free UDP port for the query".into()))
    }

    /// Looks `host` up and opens a TCP connection to it from the sandbox's
    /// address. Returns the connection and the address it went to.
    pub(crate) async fn connect(&self, host: &Host, port: u16) -> Result<(TcpConnection, Ipv4Addr), Fail> {
        if port == 0 {
            return Err(Fail::BadAddress("port 0"));
        }
        let addr = self.resolve(host).await?;
        let to = SocketAddr::new(IpAddr::V4(addr), port);
        let icmp = self.unreachable.watch(to);
        let opened = race(self.tcp.connect(&self.cx, to), icmp);
        match tokio::time::timeout(CONNECT_TIMEOUT, opened).await {
            Err(_) => Err(Fail::TimedOut),
            Ok(Either::Left(Ok(conn))) => Ok((conn, addr)),
            Ok(Either::Left(Err(e))) => Err(match e {
                ConnError::Refused | ConnError::Reset => Fail::Refused,
                ConnError::TimedOut => Fail::TimedOut,
                ConnError::Closed | ConnError::Cancelled | ConnError::Broken => Fail::WorldGone,
            }),
            Ok(Either::Right(Ok(code))) => Err(Fail::Unreachable(code)),
            Ok(Either::Right(Err(_))) => Err(Fail::WorldGone),
        }
    }
}

/// Connections waiting to open, by where they go, so an ICMP
/// "destination unreachable" about one can end its wait at once. The TCP
/// endpoint drops ICMP, so without this a connection to an address with
/// no machine would wait out [`CONNECT_TIMEOUT`].
#[derive(Default)]
struct Unreachable {
    waiting: Mutex<Watchers>,
}

#[derive(Default)]
struct Watchers {
    by_destination: HashMap<SocketAddr, Vec<oneshot::Sender<u8>>>,
    /// How many senders `by_destination` holds.
    senders: usize,
    /// How many it held after the last sweep of every destination.
    swept: usize,
}

impl Unreachable {
    fn watch(&self, to: SocketAddr) -> oneshot::Receiver<u8> {
        let (tx, rx) = oneshot::channel();
        let mut guard = self.waiting.lock().unwrap();
        let w = &mut *guard;
        // Drop the entries of connections that are no longer waiting, once
        // the count has doubled since the last sweep. A burst of connects,
        // to one destination or many, then costs time in proportion to its
        // size, not its square.
        w.by_destination.entry(to).or_default().push(tx);
        w.senders += 1;
        if w.senders > 2 * w.swept + 64 {
            w.by_destination.retain(|_, v| {
                v.retain(|s| !s.is_closed());
                !v.is_empty()
            });
            w.senders = w.by_destination.values().map(Vec::len).sum();
            w.swept = w.senders;
        }
        rx
    }

    fn report(&self, about: SocketAddr, code: u8) {
        let senders = {
            let mut w = self.waiting.lock().unwrap();
            let senders = w.by_destination.remove(&about);
            w.senders -= senders.as_ref().map_or(0, Vec::len);
            senders
        };
        for s in senders.into_iter().flatten() {
            let _ = s.send(code);
        }
    }
}

/// The TCP end of the split, with ICMP errors about TCP packets taken out
/// and reported to [`Unreachable`].
struct Watch {
    inner: End,
    unreachable: Arc<Unreachable>,
}

impl Interface for Watch {
    fn poll_recv(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        loop {
            match self.inner.poll_recv(cx, task) {
                Poll::Ready(Ok(p)) => match unreachable_about(&p.0) {
                    Some((about, code)) => self.unreachable.report(about, code),
                    None => return Poll::Ready(Ok(p)),
                },
                other => return other,
            }
        }
    }

    fn send(&mut self, packet: Packet) {
        self.inner.send(packet);
    }
}

/// If `p` is an ICMPv4 "destination unreachable" about a TCP packet,
/// where that packet went and the ICMP code.
pub(crate) fn unreachable_about(p: &[u8]) -> Option<(SocketAddr, u8)> {
    let ihl = (*p.first()? & 0x0f) as usize * 4;
    if p[0] >> 4 != 4 || ihl < 20 || *p.get(9)? != 1 {
        return None;
    }
    let icmp = p.get(ihl..)?;
    if *icmp.first()? != 3 {
        return None;
    }
    let code = *icmp.get(1)?;
    let inner = icmp.get(8..)?;
    let inner_ihl = (*inner.first()? & 0x0f) as usize * 4;
    if inner[0] >> 4 != 4 || inner_ihl < 20 || *inner.get(9)? != 6 {
        return None;
    }
    let dst = Ipv4Addr::new(*inner.get(16)?, *inner.get(17)?, *inner.get(18)?, *inner.get(19)?);
    let tcp = inner.get(inner_ihl..inner_ihl + 4)?;
    let port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Some((SocketAddr::new(IpAddr::V4(dst), port), code))
}

pub(crate) enum Either<A, B> {
    Left(A),
    Right(B),
}

/// Waits for the first of two futures, and drops the other.
pub(crate) async fn race<A: Future, B: Future>(a: A, b: B) -> Either<A::Output, B::Output> {
    let mut a = pin!(a);
    let mut b = pin!(b);
    poll_fn(|task| {
        if let Poll::Ready(x) = a.as_mut().poll(task) {
            return Poll::Ready(Either::Left(x));
        }
        if let Poll::Ready(y) = b.as_mut().poll(task) {
            return Poll::Ready(Either::Right(y));
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ICMP "host unreachable" from 10.0.0.1 about a SYN from
    /// 10.0.0.2:50000 to 192.0.2.7:443.
    fn host_unreachable() -> Vec<u8> {
        let mut syn = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 2, 192, 0, 2, 7];
        syn.extend_from_slice(&50000u16.to_be_bytes());
        syn.extend_from_slice(&443u16.to_be_bytes());
        syn.extend_from_slice(&[0; 16]);
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        p.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&syn);
        p
    }

    #[test]
    fn icmp_unreachable_names_the_destination() {
        let p = host_unreachable();
        assert_eq!(unreachable_about(&p), Some(("192.0.2.7:443".parse().unwrap(), 1)));
        // Not ICMP, not type 3, not about TCP, cut short.
        let mut udp = p.clone();
        udp[9] = 17;
        assert_eq!(unreachable_about(&udp), None);
        let mut echo = p.clone();
        echo[20] = 0;
        assert_eq!(unreachable_about(&echo), None);
        let mut about_udp = p.clone();
        about_udp[28 + 9] = 17;
        assert_eq!(unreachable_about(&about_udp), None);
        for n in 0..p.len() - 16 {
            assert_eq!(unreachable_about(&p[..n]), None, "{n}");
        }
        assert_eq!(unreachable_about(&[]), None);
    }

    #[test]
    fn hosts_parse_as_names_and_addresses() {
        assert_eq!(Host::parse("Example.test"), Some(Host::Name("example.test".into())));
        assert_eq!(Host::parse("203.0.113.10"), Some(Host::V4(Ipv4Addr::new(203, 0, 113, 10))));
        assert_eq!(Host::parse("[fd00::1]"), Some(Host::V6("fd00::1".parse().unwrap())));
        assert_eq!(Host::parse("fd00::1"), None);
        assert_eq!(Host::parse("[nope]"), None);
        assert_eq!(Host::parse("a b"), None);
        assert_eq!(Host::parse("[fd00::1]").unwrap().to_string(), "[fd00::1]");
    }

    #[test]
    fn watchers_of_finished_connects_do_not_pile_up() {
        let u = Unreachable::default();
        let mut live = Vec::new();
        for i in 0..10_000u32 {
            let to = SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 80));
            let rx = u.watch(to);
            // One connect in a hundred still waits; the rest are done.
            if i % 100 == 0 {
                live.push(rx);
            }
            let w = u.waiting.lock().unwrap();
            assert!(w.senders <= 2 * (live.len() + 1) + 64 + 1, "{} senders for {} live", w.senders, live.len());
            assert_eq!(w.senders, w.by_destination.values().map(Vec::len).sum::<usize>());
        }
    }

    #[test]
    fn unreachable_reports_reach_only_their_destination() {
        let u = Unreachable::default();
        let a: SocketAddr = "192.0.2.7:443".parse().unwrap();
        let b: SocketAddr = "192.0.2.8:443".parse().unwrap();
        let mut ra = u.watch(a);
        let mut rb = u.watch(b);
        u.report(a, 1);
        assert_eq!(ra.try_recv(), Ok(1));
        assert!(rb.try_recv().is_err());
        drop(rb);
        // A dropped watcher is cleaned up at the next sweep, once the
        // count has doubled.
        let mut keep = Vec::new();
        for _ in 0..70 {
            keep.push(u.watch(a));
        }
        let w = u.waiting.lock().unwrap();
        assert!(!w.by_destination.contains_key(&b));
        assert_eq!(w.senders, 70);
    }
}
