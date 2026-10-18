//! Attach's own TCP/IP stack: the sandbox's kernel, in userspace.
//!
//! The SDK's stdlib stack runs on the world's interface ([`Link`]):
//! `ip::split_protocols`, `tcp::endpoint` and `udp::endpoint` at the
//! sandbox's address. A proxied connection becomes a lookup at the world's
//! DNS server (UDP from the sandbox's address) and a TCP connection from
//! that address. The world sees ordinary IP packets from that address, but
//! made by this stack, not by a sandbox kernel: `fictionet::guide::lowering` lists
//! the differences.
//!
//! Nothing here opens a socket on the host toward a destination a client
//! names. Every connection is made of packets on the world's interface.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fictionet::stdlib::network::tcp::TcpConnection;
use fictionet::stdlib::network::{ConnError, ip, tcp, udp};
use fictionet::{Cx, RecvError};

use super::link::Link;
use fictionet_cli::attach_proxy::Host;
use fictionet_cli::attach_proxy::dns::{self, Lookup};

/// How long a connection may take to open before the client is told it
/// timed out. The stack itself would wait two minutes for a SYN that is
/// never answered.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A DNS query is sent again after each of these waits, then given up.
const DNS_WAITS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];
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

/// The stack. Clones share it.
#[derive(Clone)]
pub(crate) struct Stack {
    fcx: Cx,
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    dns: SocketAddr,
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
        let Some(lookup) = self.lookup.take() else {
            return;
        };
        // Clones are made and dropped only under this lock, so the count is
        // exact: the map's and this one mean no one else waits.
        let mine = pending
            .get(self.name)
            .is_some_and(|l| Arc::ptr_eq(l, &lookup));
        if mine && (lookup.initialized() || Arc::strong_count(&lookup) == 2) {
            pending.remove(self.name);
        }
        drop(lookup);
    }
}

impl Stack {
    /// Starts the stack at `addr` on `link`, in `fcx`'s region.
    pub(crate) fn new(fcx: &Cx, link: Link, addr: Ipv4Addr, dns: Ipv4Addr) -> Stack {
        let (tcp_end, udp_end, _icmp, _other) = ip::split_protocols(fcx, link);
        Stack {
            fcx: fcx.clone(),
            tcp: tcp::endpoint(fcx, tcp_end, IpAddr::V4(addr)),
            udp: udp::endpoint(fcx, udp_end, IpAddr::V4(addr)),
            dns: SocketAddr::new(IpAddr::V4(dns), 53),
            cache: Arc::default(),
            pending: Arc::default(),
        }
    }

    pub(crate) fn fcx(&self) -> &Cx {
        &self.fcx
    }

    /// The world's address for `host`.
    pub(crate) async fn resolve(&self, host: &Host) -> Result<Ipv4Addr, Fail> {
        let name = match host {
            Host::V4(a) => return Ok(*a),
            Host::V6(_) => {
                return Err(Fail::BadAddress(
                    "IPv6 is not supported: attach's stack is IPv4 only",
                ));
            }
            Host::Name(n) => n,
        };
        let cached = || {
            self.cache
                .lock()
                .unwrap()
                .get(name)
                .filter(|(_, until)| Instant::now() < *until)
                .map(|(a, _)| a.clone())
        };
        if let Some(answer) = cached() {
            return answer;
        }
        // One lookup per name at a time. If the client that started it goes
        // away, the next one waiting runs the lookup instead.
        let lookup = self
            .pending
            .lock()
            .unwrap()
            .entry(name.clone())
            .or_default()
            .clone();
        let waiting = Waiting {
            pending: &self.pending,
            name,
            lookup: Some(lookup),
        };
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
        let id = self.fcx.random_u64() as u16;
        let q = dns::query(name, id).ok_or(Fail::NoSuchName)?;
        for wait in DNS_WAITS {
            socket.send_to(&q, self.dns);
            let deadline = tokio::time::Instant::now() + wait;
            loop {
                match tokio::time::timeout_at(deadline, socket.recv(&self.fcx)).await {
                    Err(_) => break,
                    Ok(Err(RecvError::Closed | RecvError::Cancelled)) => {
                        return Err(Fail::WorldGone);
                    }
                    Ok(Ok((bytes, from))) => match dns::answer(&bytes, from, self.dns, name, id) {
                        None => continue,
                        Some(Ok(found)) => return Ok(found),
                        Some(Err(Lookup::NoSuchName)) => return Err(Fail::NoSuchName),
                        Some(Err(Lookup::Failed(why))) => return Err(Fail::Dns(why)),
                    },
                }
            }
        }
        Err(Fail::Dns(format!(
            "no answer from {} in 7 s",
            self.dns.ip()
        )))
    }

    /// A UDP socket on a free port from 49152 up, picked at random.
    fn bind_ephemeral(&self) -> Result<udp::Socket, Fail> {
        let span = (65536 - EPHEMERAL as u32) as u64;
        let start = self.fcx.random_u64() % span;
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
    pub(crate) async fn connect(
        &self,
        host: &Host,
        port: u16,
    ) -> Result<(TcpConnection, Ipv4Addr), Fail> {
        if port == 0 {
            return Err(Fail::BadAddress("port 0"));
        }
        let addr = self.resolve(host).await?;
        let to = SocketAddr::new(IpAddr::V4(addr), port);
        let opened = self.tcp.connect(&self.fcx, to);
        match tokio::time::timeout(CONNECT_TIMEOUT, opened).await {
            Err(_) => Err(Fail::TimedOut),
            Ok(Ok(conn)) => Ok((conn, addr)),
            Ok(Err(e)) => Err(match e {
                ConnError::Refused | ConnError::Reset => Fail::Refused,
                ConnError::TimedOut => Fail::TimedOut,
                ConnError::Unreachable(code) => Fail::Unreachable(code),
                ConnError::Closed | ConnError::Cancelled | ConnError::Broken => Fail::WorldGone,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_expired_alias_is_looked_up_again() {
        use fictionet::stdlib::protocols::dns::op::Message;
        use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME};
        use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record};
        use std::sync::atomic::{AtomicUsize, Ordering};

        for alias_ttl in [0, 1] {
            fictionet::lab(fictionet::Seed::from_u64(8), move |fcx| async move {
                let (client, world) = fictionet::pair();
                let (tcp_end, udp_end, _, _) = ip::split_protocols(&fcx, client);
                let addr = Ipv4Addr::new(10, 0, 0, 2);
                let dns: SocketAddr = "10.0.0.1:53".parse().unwrap();
                let stack = Stack {
                    fcx: fcx.clone(),
                    tcp: tcp::endpoint(&fcx, tcp_end, addr.into()),
                    udp: udp::endpoint(&fcx, udp_end, addr.into()),
                    dns,
                    cache: Arc::default(),
                    pending: Arc::default(),
                };
                let mut server = udp::endpoint(&fcx, world, dns.ip()).bind(53)?;
                let queries = Arc::new(AtomicUsize::new(0));
                let count = queries.clone();
                fcx.spawn(move |fcx| async move {
                    while let Ok((bytes, from)) = server.recv(&fcx).await {
                        let n = count.fetch_add(1, Ordering::SeqCst);
                        let query = Message::from_vec(&bytes).unwrap();
                        let mut reply =
                            Message::response(query.metadata.id, query.metadata.op_code);
                        reply.queries = query.queries;
                        let target =
                            Name::from_ascii(if n == 0 { "old.test." } else { "new.test." })
                                .unwrap();
                        reply.answers.push(Record::from_rdata(
                            reply.queries[0].name().clone(),
                            if n == 0 { alias_ttl } else { 60 },
                            RData::CNAME(CNAME(target.clone())),
                        ));
                        reply.answers.push(Record::from_rdata(
                            target,
                            60,
                            RData::A(A(Ipv4Addr::new(192, 0, 2, if n == 0 { 1 } else { 2 }))),
                        ));
                        server.send_to(&reply.to_vec().unwrap(), from);
                    }
                    Ok(())
                });
                let host = Host::Name("www.test".into());
                assert_eq!(stack.resolve(&host).await, Ok(Ipv4Addr::new(192, 0, 2, 1)));
                if alias_ttl != 0 {
                    // Age the cached answer by two seconds without a wall-clock wait.
                    stack.cache.lock().unwrap().get_mut("www.test").unwrap().1 -=
                        Duration::from_secs(2);
                }
                assert_eq!(stack.resolve(&host).await, Ok(Ipv4Addr::new(192, 0, 2, 2)));
                assert_eq!(stack.resolve(&host).await, Ok(Ipv4Addr::new(192, 0, 2, 2)));
                assert_eq!(queries.load(Ordering::SeqCst), 2);
                assert!(stack.pending.lock().unwrap().is_empty());
                fcx.cancel();
                Ok(())
            })
            .await
            .unwrap();
        }
    }
}
