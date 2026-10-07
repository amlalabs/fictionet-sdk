//! A network of hosts and services in a few lines: the sandboxes' side,
//! DNS, addresses, a router, one machine per address, and the services on
//! each.
//!
//! [`Net`] builds the whole network around the [`Host`]s a world declares.
//! Each host has addresses, DNS names, and services on its ports: any
//! [`Service`] over TCP or UDP, the same over TLS chosen by SNI, and any
//! [`Accept`] of the world's own, such as [`httpd::Server`] for HTTP with
//! name-based virtual hosting. Every sandbox that attaches is put on the
//! sandboxes' subnet, given an address by DHCP or by its first packet, and
//! kept from reaching the other sandboxes. A world then writes only its
//! services.
//!
//! An office: a domain controller that answers LDAP and Kerberos, a web
//! server, and a PLC, with DNS names for each:
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::{httpd, net::{Host, Net}, serve};
//! # struct Ldap; struct Plc; struct Directory; struct Plant;
//! # macro_rules! svc { ($t:ty, $w:ty) => {
//! # impl serve::Service for $t {
//! #     type Decoder = fictionet::stdlib::codec::Lines; type State = $w; type Error = std::convert::Infallible;
//! #     fn decoder(&self) -> Self::Decoder { fictionet::stdlib::codec::Lines::new(64, fictionet::stdlib::codec::Ending::LfOrCrlf) }
//! #     fn on_item(&mut self, _: Result<Vec<u8>, fictionet::stdlib::codec::LineError>, _: &$w, _: &mut serve::Driver<'_>) -> std::result::Result<serve::Flow, Self::Error> { Ok(serve::Flow::Continue) }
//! # } } }
//! # svc!(Ldap, Directory); svc!(Plc, Plant);
//! # fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let directory = Arc::new(Directory);
//! let plant = Arc::new(Plant);
//! let intranet = httpd::Router::new().get("/", |_, _| http::Response::new("intranet\n".into()));
//! fcx.events().to_file("/tmp/office-events.jsonl")?;
//! Net::new()
//!     .host("dc01", |h| h.at("10.20.0.10".parse::<std::net::Ipv4Addr>().unwrap()).dns_name("dc01.corp.test").tcp(389, directory.clone(), || Ldap))
//!     .host("www", |h| h.dns_name("intranet.corp.test").accept(80, httpd::Server::new(intranet)))
//!     .host("plc1", |h| h.at("10.30.0.5".parse::<std::net::Ipv4Addr>().unwrap()).tcp(502, plant, || Plc))
//!     .serve(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```
//!
//! [`web::Sites`](crate::stdlib::web::Sites) is a preset on `Net` for a
//! world of websites, whose hosts appear as their names are looked up
//! ([`Net::resolve`]).
//!
//! # What `serve` builds
//!
//! - **The sandboxes' side.** Every sandbox that attaches, now or later,
//!   joins two subnets: `10.0.0.0/24` for IPv4, with the gateway and the DNS
//!   server at `10.0.0.1`, and `2001:db8::/64` for IPv6, with the gateway
//!   and the DNS server at `2001:db8::1`. [`Net::subnet`] changes either.
//!   DHCP hands out IPv4 addresses; a sandbox with a fixed address is known
//!   by the source of its first packet. Each sandbox owns one address of
//!   each family, bound to its attachment, and packets from any other
//!   source are dropped. Its fragments are put back together in its own
//!   filter, so a fragment can never complete another sandbox's packet.
//! - **Sandboxes cannot reach each other.** A packet to the sandboxes'
//!   subnet other than the gateway is dropped. [`Net::route`] attaches a
//!   trusted sandbox, such as a real container playing a host, at a fixed
//!   prefix outside that subnet, with no filter.
//! - **DNS** at the gateway, over UDP and TCP. It answers A and AAAA for
//!   each host's names, NODATA for other types, NXDOMAIN for every other
//!   name.
//! - **Addresses.** A host with [`Host::at`] uses that address; otherwise
//!   it gets a free one from `198.18.0.0/15` (IPv4) and `2001:2::/48`
//!   (IPv6). Hosts with the same address share one machine.
//! - **A router** with one route per machine. A packet for any other
//!   address gets ICMP "host unreachable" (ICMPv6 "address unreachable").
//!   The router is private ([`Router::keep_ttl`](super::route::Router::keep_ttl)):
//!   it leaves TTLs as they are, so every machine is one hop from the
//!   sandbox.
//! - **LANs.** [`Net::lan`] adds an IP subnet that hosts join with
//!   [`Host::on`] and attached virtual machines with [`Net::member`], as
//!   machines on one Ethernet: broadcast and multicast reach every member.
//!   The router sends the LAN's prefix to its gateway, the LAN's first
//!   address answers DNS, and the packets the LAN drops are recorded
//!   (as [repeats](crate::events#repeats)).
//! - **Machines** answer pings, reset TCP to closed ports and answer UDP to
//!   closed ports with "port unreachable". A sandbox may have 256
//!   connections open at once to one machine
//!   ([`Limits::connections_per_peer`]); past that, new ones are reset. Each
//!   service has its own cap too ([`ServeOptions::max_conns`]).
//! - **Budgets.** What every connection from one sandbox holds is charged
//!   to that sandbox's [`Budget`], 256 MiB unless
//!   [`Limits::sandbox_budget`] says otherwise: a connection that would pass
//!   it is closed. A sandbox has one budget for both its addresses, from
//!   when it attaches until it detaches. A trusted sandbox
//!   ([`Net::route`]) has none.
//! - **Every link** inside the network holds at most 4 MiB of packets each
//!   way; past that, packets are dropped, as on a congested link.
//! - **Events.** The network records every fact in the run's
//!   [events](crate::events): a `run.start` event first, `net` events for
//!   sandboxes attaching,
//!   binding, detaching and packets dropped (`net.blocked`, counted as
//!   [repeats](crate::events#repeats)), `dns.query`
//!   for every DNS message, `tls.handshake` for every handshake on a TLS
//!   port, and each service's own events. Every event names its sandbox
//!   and, for a connection, its number (from 1, on every port of every
//!   machine).
//! - **Errors.** A host that cannot be served as declared, such as one at
//!   an address a host cannot have, two services on one port (one with
//!   TLS and one without count as two), or a port
//!   that cannot be listened on, makes [`Net::serve`] fail.
//!
//! The limits and rules are those [`web::Sites`](crate::stdlib::web::Sites)
//! documents in detail, which runs on this.

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::task::Poll;
use std::time::Duration;

use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::dhcp::{self, opt};
use fictionet::stdlib::dns::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use fictionet::stdlib::dns::rr::{DNSClass, RData, Record, RecordType, rdata::A, rdata::AAAA};
use fictionet::stdlib::ip::{Header, Intake, Reassembly};
use fictionet::events::{ConnInfo, Event, Fields, Level, Sandbox, opt as jopt};
use fictionet::stdlib::route::{self, Prefix, Router};
use fictionet::stdlib::serve::{self, Budget, Counted, ServeOptions, Service, TlsSelect};
use fictionet::stdlib::tls::ServerConfig;
use fictionet::stdlib::{ConnError, Connection, ConnectionExt, PortEvent, Ports, icmp, ip, tcp, udp};
use fictionet::time::Instant;
use fictionet::{Attachment, Attachments, Cx, End, Error, Interface, InterfaceExt, Packet};

#[cfg(doc)]
use fictionet::stdlib::httpd;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// How long a DHCP lease lasts. The binding itself lasts until the sandbox
/// detaches; the lease time only tells the client when to renew.
const LEASE: u32 = 3600;

/// Where hosts without an IPv4 [`Host::at`] get their addresses:
/// `198.18.0.0/15`.
const AUTO_BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const AUTO_SIZE: u32 = 1 << 17;

/// Where hosts without an IPv6 [`Host::at`] get theirs: `2001:2::/48`,
/// the IPv6 range set aside for benchmarking (RFC 5180).
const AUTO6_BASE: u128 = 0x2001_0002_0000_0000_0000_0000_0000_0000;
const AUTO6_LEN: u8 = 48;
const AUTO6_SIZE: u128 = 1 << (128 - AUTO6_LEN);

/// Each link inside the network holds at most this many bytes of packets
/// each way.
const LINK_QUEUE: usize = 4 << 20;

/// At most this many names that have no host are remembered (about 35 MB).
const MAX_UNKNOWN_NAMES: usize = 100_000;

/// How many names may have a host made by [`Net::resolve`], unless the
/// world sets another limit.
pub const MAX_HOSTS: usize = 20_000;

/// How long resolvers may keep an answer, in seconds.
const TTL: u32 = 60;

fn link() -> (End, End) {
    fictionet::pair_with_limit(LINK_QUEUE)
}

/// Locks a mutex, ignoring poison: a panic elsewhere must not take the
/// whole network down with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A name as hosts are kept: lowercase, without a trailing dot.
fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Limits

/// The network's limits and timers, for [`Net::limits`]. Tests set small
/// ones so they do not wait out real-world timeouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// How many connections one peer address may have open at one machine
    /// (or at the gateway's DNS) at once, counted until each has finished
    /// closing. Default 256.
    pub connections_per_peer: usize,
    /// How long a client has, from connecting, to finish its TLS handshake,
    /// or on an HTTP port without TLS to send its first bytes; and from a
    /// service's STARTTLS, to finish that handshake. Default 10 seconds.
    pub handshake: Duration,
    /// How long a DNS-over-TCP connection may sit idle between queries (RFC
    /// 7766, section 6.2.3). Default 10 seconds.
    pub dns_tcp_idle: Duration,
    /// Bytes the connections of one sandbox may hold at once, all services
    /// together: see [`Budget`]. Default 256 MiB.
    pub sandbox_budget: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            connections_per_peer: 256,
            handshake: Duration::from_secs(10),
            dns_tcp_idle: Duration::from_secs(10),
            sandbox_budget: 256 << 20,
        }
    }
}

// ---------------------------------------------------------------------------
// Hosts

/// Which address families a host has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Both,
    V4,
    V6,
}

/// Picks the TLS config for one handshake, with randomness from the `Cx`.
pub type ConfigFor = Arc<dyn Fn(&Cx) -> Arc<ServerConfig> + Send + Sync>;

/// One connection, accepted on a port of a machine, as an [`Accept`] gets
/// it.
pub struct Arrival {
    /// The connection: after the TLS handshake, on a TLS port.
    pub conn: Box<dyn Connection>,
    /// Who it is from, and where it arrived.
    pub info: ConnInfo,
    /// The TCP socket underneath, to keep a count until it is gone
    /// ([`tcp::GoneWatch::hold_until_gone`]) or to reset it.
    pub socket: tcp::GoneWatch,
    /// The budget of the sandbox it came from. `None` if it came from no
    /// attached sandbox, such as a trusted one ([`Net::route`]).
    pub budget: Option<Budget>,
    /// [`Limits::handshake`]: how long a client has to send its first
    /// bytes.
    pub handshake: Duration,
    /// The network's seed ([`Net::seed`]), for [`ServeOptions::seed`].
    pub seed: u64,
}

/// Serves connections on one port of a host. [`Host::tcp`] and
/// [`Host::tls`] make one for a [`Service`]; [`httpd::Server`] is HTTP's.
/// A world writes its own for anything else.
pub trait Accept: Any + Send + Sync {
    /// Serves one connection.
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// The protocols to offer with ALPN when this serves a TLS port, such
    /// as `h2` and `http/1.1`. Default none: the config's own list.
    fn alpn(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// A host is placed on this accept's port at its address (for a TLS
    /// port, on one of the port's names), with the DNS names `names` and
    /// the accept `other`. The first host on a port is offered its own
    /// accept. Returns whether this accept serves that host too, as
    /// virtual hosts share an HTTP port; if not, `other` serves the port
    /// alone, which on a plain port is an error. The default takes only
    /// itself.
    fn share(&self, names: &[String], other: &Arc<dyn Accept>) -> bool {
        let _ = names;
        std::ptr::addr_eq(self as *const Self, Arc::as_ptr(other))
    }
}

/// Serves a [`Service`] made fresh for each connection.
struct ServiceAccept<S: Service, M> {
    state: Arc<S::State>,
    make: M,
    opts: ServeOptions,
    open: Arc<AtomicUsize>,
}

impl<S: Service, M> ServiceAccept<S, M> {
    fn new(state: Arc<S::State>, make: M, opts: ServeOptions) -> ServiceAccept<S, M> {
        ServiceAccept { state, make, opts, open: Arc::default() }
    }
}

impl<S, M> Accept for ServiceAccept<S, M>
where
    S: Service,
    M: Fn() -> S + Send + Sync + 'static,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let Some(guard) = Counted::enter(&self.open, self.opts.max_conns) else {
            let (src, dst) = (arrival.info.peer, arrival.info.local);
            let event = blocked_event(BlockedWhy::TooManyConnections, Some(PROTO_TCP), src.map(|a| a.ip()), dst.map(|a| a.ip()));
            let conn = ConnInfo { sandbox: arrival.info.sandbox.clone(), ..ConnInfo::default() };
            fcx.record_repeat(event.conn(&conn), port_detail(dst.map(|a| a.port())));
            arrival.socket.reset();
            return Box::pin(async {});
        };
        arrival.socket.hold_until_gone(Box::new(guard));
        let mut service = (self.make)();
        let state = self.state.clone();
        let mut opts = self.opts.clone();
        if opts.budget.is_none() {
            opts.budget = arrival.budget;
        }
        opts.handshake = arrival.handshake;
        opts.seed ^= arrival.seed;
        let (conn, info) = (arrival.conn, arrival.info);
        Box::pin(async move {
            let _ = serve::serve(&fcx, conn, info, &mut service, &state, &opts).await;
        })
    }
}

/// Starts serving a UDP port of a machine: the socket, its address, the
/// seed, and who the sandboxes are.
type UdpStart = Arc<dyn Fn(&Cx, udp::Socket, SocketAddr, u64, Option<serve::SandboxOf>) + Send + Sync>;

/// Which names a TLS service on a port answers to, by the SNI the client
/// sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sni {
    /// Every name, and none: the port's fallback.
    Any,
    /// Each of the host's DNS names ([`Host::dns_name`]).
    Names,
    /// This name.
    Name(String),
}

impl From<&str> for Sni {
    fn from(name: &str) -> Sni {
        Sni::Name(normalize(name))
    }
}

/// What a host serves on one port.
#[derive(Clone)]
enum PortSpec {
    Tcp(Arc<dyn Accept>),
    Tls { sni: Sni, config: ConfigFor, accept: Arc<dyn Accept> },
    Udp(UdpStart),
}

/// One host: its addresses, DNS names and services. See [`Net::host`] and
/// [`Net::resolve`].
#[derive(Clone)]
pub struct Host {
    label: String,
    names: Vec<String>,
    at: Option<Ipv4Addr>,
    at_v6: Option<Ipv6Addr>,
    family: Family,
    ports: Vec<(u16, PortSpec)>,
    lan: Option<String>,
}

impl Host {
    /// A host called `label` (for observers), with no names or services.
    pub fn new(label: &str) -> Host {
        Host { label: label.to_owned(), names: Vec::new(), at: None, at_v6: None, family: Family::Both, ports: Vec::new(), lan: None }
    }

    /// Serves the host at `addr`, IPv4 or IPv6, which sets its address of
    /// that family. Two calls give it both. A family without `at` gets a
    /// free address from that family's range.
    ///
    /// The address must be one a host can have, outside the sandboxes'
    /// subnet: not unspecified, broadcast, multicast or loopback, and for
    /// IPv6 not link-local or IPv4-mapped. If it is not, [`Net::serve`]
    /// fails; a host made by [`Net::resolve`] is not served, and its name
    /// gets NXDOMAIN.
    pub fn at(self, addr: impl Into<IpAddr>) -> Host {
        match addr.into() {
            IpAddr::V4(a) => Host { at: Some(a), ..self },
            IpAddr::V6(a) => Host { at_v6: Some(a), ..self },
        }
    }

    /// Places the host on the LAN called `lan` ([`Net::lan`]): it has one
    /// address, of the LAN's family, inside the LAN's prefix (the one given
    /// with [`at`](Self::at), or a free one), and shares the subnet with
    /// the LAN's other hosts and members.
    pub fn on(self, lan: &str) -> Host {
        Host { lan: Some(lan.to_owned()), ..self }
    }

    /// Gives the host only an IPv4 address.
    pub fn ipv4_only(self) -> Host {
        Host { family: Family::V4, ..self }
    }

    /// Gives the host only an IPv6 address.
    pub fn ipv6_only(self) -> Host {
        Host { family: Family::V6, ..self }
    }

    /// Makes the gateway's DNS answer `name` with the host's addresses. A
    /// host can have many names; its HTTP sites and TLS services for
    /// [`Sni::Names`] are served under each.
    pub fn dns_name(mut self, name: &str) -> Host {
        self.names.push(normalize(name));
        self
    }

    /// Serves TCP `port` with a [`Service`] made by `make` for each
    /// connection, sharing `world`, with the default [`ServeOptions`].
    /// Connections are numbered, `conn.open` and `conn.close` events record
    /// each, and the service's events name the sandbox each came from.
    pub fn tcp<S, M>(self, port: u16, state: Arc<S::State>, make: M) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decoder as Decode>::Error: Clone + Send,
    {
        self.tcp_with(port, state, make, ServeOptions::default())
    }

    /// The same with these options: a transcript, a fault plan, an idle
    /// limit, a connection cap, a STARTTLS config. The sandbox's budget
    /// applies when `opts` has none. A STARTTLS handshake has
    /// [`Limits::handshake`], whatever `opts` says.
    pub fn tcp_with<S, M>(self, port: u16, state: Arc<S::State>, make: M, opts: ServeOptions) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decoder as Decode>::Error: Clone + Send,
    {
        self.accept(port, ServiceAccept::new(state, make, opts))
    }

    /// Serves TCP `port` with TLS for the names `sni` gives, then a
    /// [`Service`] made by `make`, with the default [`ServeOptions`], as
    /// [`tcp`](Self::tcp). Several `tls` calls on one port route by SNI; a
    /// name with no entry is rejected with `unrecognized_name`.
    pub fn tls<S, M>(
        self,
        port: u16,
        sni: impl Into<Sni>,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
        state: Arc<S::State>,
        make: M,
    ) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decoder as Decode>::Error: Clone + Send,
    {
        let accept = ServiceAccept::new(state, make, ServeOptions::default());
        self.tls_accept(port, sni, config_for, accept)
    }

    /// Serves TCP `port` with `accept`.
    pub fn accept(mut self, port: u16, accept: impl Accept) -> Host {
        self.ports.push((port, PortSpec::Tcp(Arc::new(accept))));
        self
    }

    /// Serves TCP `port` with TLS for the names `sni` gives, with the
    /// config `config_for` returns for each handshake, then `accept`.
    pub fn tls_accept(mut self, port: u16, sni: impl Into<Sni>, config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static, accept: impl Accept) -> Host {
        let spec = PortSpec::Tls { sni: sni.into(), config: Arc::new(config_for), accept: Arc::new(accept) };
        self.ports.push((port, spec));
        self
    }

    /// Serves UDP `port` with one [`Service`] made by `make`, which gets
    /// every datagram ([`serve::serve_datagram`]).
    pub fn udp<S, M>(self, port: u16, state: Arc<S::State>, make: M) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decoder as Decode>::Error: Clone + Send,
    {
        self.udp_with(port, state, make, ServeOptions::default())
    }

    /// The same with these options. The network names each datagram's
    /// sandbox ([`ServeOptions::sandbox`]).
    pub fn udp_with<S, M>(mut self, port: u16, state: Arc<S::State>, make: M, opts: ServeOptions) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decoder as Decode>::Error: Clone + Send,
    {
        let start: UdpStart = Arc::new(move |fcx, socket, local, seed, sandbox| {
            let mut service = make();
            let state = state.clone();
            let mut opts = opts.clone();
            if sandbox.is_some() {
                opts.sandbox = sandbox;
            }
            opts.seed ^= seed;
            fcx.spawn(move |fcx| async move {
                Ok(serve::serve_datagram(&fcx, socket, local, &mut service, &state, &opts).await?)
            });
        });
        self.ports.push((port, PortSpec::Udp(start)));
        self
    }
}

// ---------------------------------------------------------------------------
// The network

/// Turns a name into a host, or `None`. Runs once per name.
type Resolver = dyn Fn(&str) -> Option<Host> + Send + Sync;

/// A network of hosts and services, and the sandboxes' side of it. See the
/// [module docs](self).
pub struct Net {
    subnet: Prefix,
    subnet_v6: Prefix,
    ipv6: bool,
    hosts: Vec<Host>,
    resolver: Option<Arc<Resolver>>,
    max_hosts: usize,
    routes: Vec<(String, Prefix)>,
    registry: Option<fictionet::observe::Registry>,
    group: String,
    limits: Limits,
    seed: u64,
    start: Fields,
    lans: Vec<(String, Prefix)>,
    members: Vec<(String, String, IpAddr)>,
}

impl Default for Net {
    fn default() -> Net {
        Net::new()
    }
}

impl Net {
    /// An empty network with the default subnets, dual-stack.
    pub fn new() -> Net {
        Net {
            subnet: Prefix { addr: Ipv4Addr::new(10, 0, 0, 0).into(), len: 24 },
            subnet_v6: Prefix { addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).into(), len: 64 },
            ipv6: true,
            hosts: Vec::new(),
            resolver: None,
            max_hosts: MAX_HOSTS,
            routes: Vec::new(),
            registry: None,
            group: "net".to_owned(),
            limits: Limits::default(),
            seed: 0,
            start: Fields::new(),
            lans: Vec::new(),
            members: Vec::new(),
        }
    }

    /// Sets the sandboxes' IPv4 or IPv6 subnet, whichever `subnet` is. The
    /// gateway and DNS server take the address after the subnet's own. An
    /// IPv4 subnet must have a length from 8 to 30; an IPv6 one from 8 to
    /// 126, inside `2000::/3` or `fc00::/7`. Otherwise
    /// [`serve`](Net::serve) fails.
    pub fn subnet(self, subnet: Prefix) -> Net {
        match subnet.addr {
            IpAddr::V4(_) => Net { subnet, ..self },
            IpAddr::V6(_) => Net { subnet_v6: subnet, ..self },
        }
    }

    /// Turns IPv6 off: hosts have only IPv4 addresses, DNS answers AAAA
    /// with NODATA, and every IPv6 packet from a sandbox is dropped.
    pub fn ipv4_only(self) -> Net {
        Net { ipv6: false, ..self }
    }

    /// Adds the fields of the `run.start` event the network records first
    /// ([`EventLog::start`](fictionet::events::EventLog::start)), such as
    /// the date the world says it is.
    pub fn start_fields(self, start: Fields) -> Net {
        Net { start, ..self }
    }

    /// Adds a host called `label`, built by `build`:
    /// `net.host("dc01", |h| h.at(addr).tcp(389, directory, || Ldap))`.
    pub fn host(mut self, label: &str, build: impl FnOnce(Host) -> Host) -> Net {
        self.hosts.push(build(Host::new(label)));
        self
    }

    /// Adds a host built on its own.
    pub fn add_host(mut self, host: Host) -> Net {
        self.hosts.push(host);
        self
    }

    /// Asks `resolve` for a host the first time a name that no host has is
    /// looked up. `Some(host)` creates it then, with that name as a DNS
    /// name; `None` gives NXDOMAIN. The answer is kept for the run.
    /// `resolve` must return quickly: it runs inside the DNS task. A host
    /// that cannot be served is recorded as a `net.error` event, and its
    /// name gets NXDOMAIN.
    pub fn resolve(self, resolve: impl Fn(&str) -> Option<Host> + Send + Sync + 'static) -> Net {
        Net { resolver: Some(Arc::new(resolve)), ..self }
    }

    /// Sets how many names may get a host from [`resolve`](Net::resolve).
    /// Default [`MAX_HOSTS`]. Past it, a new name gets SERVFAIL.
    pub fn max_hosts(self, max_hosts: usize) -> Net {
        Net { max_hosts, ..self }
    }

    /// Wires the sandbox called `name` straight to the router at `prefix`,
    /// with no filter, no address binding and no DHCP: a trusted
    /// participant, such as a real container that plays one of the hosts.
    /// Packets for `prefix` go to it, and what it sends is routed as it is.
    pub fn route(mut self, name: &str, prefix: Prefix) -> Net {
        self.routes.push((name.to_owned(), prefix));
        self
    }

    /// Adds an IP LAN called `name` on `prefix` ([`route::lan`]). Hosts
    /// placed on it with [`Host::on`] and sandboxes attached to it with
    /// [`Net::member`] share the subnet as machines on one Ethernet do,
    /// broadcast and multicast included. The router sends `prefix` to the
    /// LAN's gateway, so sandboxes and the other hosts reach its members,
    /// and members reach everything else through it. The LAN's first
    /// address (`.1` of a `/24`) answers DNS as the network's gateway does,
    /// for members to use. The packets the LAN drops are recorded as
    /// `net.blocked` [repeats](fictionet::events#repeats), with `why` `Lan`
    /// and the reason in `detail`.
    ///
    /// [`serve`](Net::serve) fails if `prefix` overlaps the sandboxes'
    /// subnets or another LAN, or leaves no room for members.
    pub fn lan(mut self, name: &str, prefix: Prefix) -> Net {
        self.lans.push((name.to_owned(), prefix.canonical()));
        self
    }

    /// Attaches the sandbox called `name` to the LAN `lan` at `addr`, with
    /// no filter, no address binding and no DHCP: a trusted member, such
    /// as a GOAD virtual machine attached with `fictionet attach --type
    /// tap`. Events name it as a sandbox. [`serve`](Net::serve)
    /// fails if there is no such LAN, `addr` is not a member address of it,
    /// or another member has it.
    pub fn member(mut self, name: &str, lan: &str, addr: IpAddr) -> Net {
        self.members.push((name.to_owned(), lan.to_owned(), addr));
        self
    }

    /// Installs `registry` for observers when the network starts, so the
    /// dashboard decodes the services' protocols.
    pub fn observe(self, registry: fictionet::observe::Registry) -> Net {
        Net { registry: Some(registry), ..self }
    }

    /// Names the group observers see for the network's tasks.
    pub fn group(self, name: &str) -> Net {
        Net { group: name.to_owned(), ..self }
    }

    /// Sets the network's limits and timers.
    pub fn limits(self, limits: Limits) -> Net {
        Net { limits, ..self }
    }

    /// Sets the seed every service's randomness is drawn from, mixed with
    /// each connection's number ([`ServeOptions::seed`]). Default 0: runs
    /// whose connections arrive in the same order draw the same numbers.
    pub fn seed(self, seed: u64) -> Net {
        Net { seed, ..self }
    }

    /// Builds the network and starts it. Every sandbox in `attachments`,
    /// including ones that attach later, is connected.
    ///
    /// Returns once every host is placed. The network runs in background
    /// tasks in `fcx`'s region until that region is cancelled. Fails if a
    /// subnet cannot be used, or a host cannot be served as declared.
    pub fn serve(self, fcx: &Cx, mut attachments: Attachments) -> Result<(), Error> {
        let subnet = Subnet::new(self.subnet)?;
        let subnet6 = if self.ipv6 { Some(Subnet6::new(self.subnet_v6)?) } else { None };
        fcx.events().start(fcx, self.start);
        if let Some(registry) = self.registry {
            fcx.observe_protocols(registry);
        }
        let caller = fcx.clone();
        let fcx = &fcx.group(self.group.clone());
        let router = route::router(fcx, Vec::new());
        // Every host is one hop from the sandbox: the router is private.
        router.keep_ttl();

        // Everything without a better route: answered with "host unreachable".
        let (router_side, unreachable_side) = link();
        router.add(Prefix { addr: Ipv4Addr::UNSPECIFIED.into(), len: 0 }, Box::new(router_side));
        let gateway = subnet.gateway;
        fcx.spawn(move |fcx| unreachable(fcx, unreachable_side, gateway.into()));
        if let Some(subnet6) = subnet6 {
            let (router_side, unreachable_side) = link();
            router.add(Prefix { addr: Ipv6Addr::UNSPECIFIED.into(), len: 0 }, Box::new(router_side));
            let gateway = subnet6.gateway;
            fcx.spawn(move |fcx| unreachable(fcx, unreachable_side, gateway.into()));
        }
        let hooks = Arc::new(Hooks {
            by_addr: Mutex::default(),
            conns: AtomicU64::new(0),
            attached: Mutex::default(),
        });
        let lans = make_lans(fcx, &router, &hooks, &subnet, subnet6.as_ref(), self.lans, &self.members)?;
        let routes: Vec<(String, Prefix)> = self.routes;
        let shared = Arc::new(Shared {
            fcx: fcx.clone(),
            resolver: self.resolver,
            subnet,
            subnet6,
            router,
            world: Mutex::new(World::new(self.max_hosts)),
            leases: Mutex::new(Leases::default()),
            gateway_tcp: Mutex::new(Vec::new()),
            hooks,
            fixed: routes.iter().map(|(_, p)| *p).collect(),
            limits: self.limits,
            seed: self.seed,
            lans,
        });
        start_gateway(&shared)?;
        for seg in shared.lans.values() {
            let (lan_side, side) = link();
            seg.lan.add(seg.dns, Box::new(lan_side))?;
            start_dns(&shared, &shared.fcx.group("lan gateway"), side, seg.dns)?;
        }
        {
            let mut world = lock(&shared.world);
            for host in self.hosts {
                let names = host.names.clone();
                let label = host.label.clone();
                let placed = shared.place(&mut world, host).map_err(|e| fictionet::Error::msg(format!("host {label}: {e}")))?;
                for name in names {
                    world.names.insert(name, Known::Host(placed));
                }
            }
        }

        let members = self.members;
        caller.spawn(move |fcx| async move {
            loop {
                let sandbox = attachments.next(&fcx).await?;
                if let Some((_, prefix)) = routes.iter().find(|(n, _)| n == sandbox.name()) {
                    shared.router.add(*prefix, Box::new(sandbox));
                    continue;
                }
                if let Some((name, lan, addr)) = members.iter().find(|(n, _, _)| n == sandbox.name()) {
                    shared.join_lan(&fcx, name, lan, *addr, sandbox);
                    continue;
                }
                let shared = shared.clone();
                fcx.spawn(move |fcx| filter(fcx, sandbox, shared));
            }
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// What the network's tasks share

/// What events need to name sandboxes.
struct Hooks {
    /// The sandbox that last bound each address. An entry stays after its
    /// sandbox detaches, until another binds the address, so packets and
    /// connections still on their way name the sandbox that sent them.
    by_addr: Mutex<HashMap<IpAddr, Sandbox>>,
    /// The last connection number given out.
    conns: AtomicU64,
    /// The sandboxes attached now, by id, each with its budget.
    attached: Mutex<HashMap<u64, Budget>>,
}

impl Hooks {
    fn record(&self, fcx: &Cx, conn: &ConnInfo, event: Event) {
        fcx.record(event.conn(conn));
    }

    /// Records a `net.blocked` event, with its detail, as a repeat: a
    /// flood of them is counted, not kept one by one.
    fn blocked(&self, fcx: &Cx, conn: &ConnInfo, (event, detail): (Event, Fields)) {
        fcx.record_repeat(event.conn(conn), detail);
    }

    fn sandbox_at(&self, addr: IpAddr) -> Sandbox {
        if let Some(s) = lock(&self.by_addr).get(&addr) {
            return s.clone();
        }
        let (v4, v6) = match addr {
            IpAddr::V4(a) => (Some(a), None),
            IpAddr::V6(a) => (None, Some(a)),
        };
        Sandbox { id: 0, name: Arc::from(""), addr: v4, addr_v6: v6 }
    }

    fn is_attached(&self, id: u64) -> bool {
        lock(&self.attached).contains_key(&id)
    }

    /// The budget of the sandbox with id `id`, while it is attached.
    fn budget(&self, id: u64) -> Option<Budget> {
        lock(&self.attached).get(&id).cloned()
    }

    fn next_conn(&self) -> u64 {
        self.conns.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn sandbox_only(sandbox: Sandbox) -> ConnInfo {
    ConnInfo { sandbox: Some(sandbox), ..ConnInfo::default() }
}

/// The sandboxes' subnet.
#[derive(Clone, Copy, Debug)]
struct Subnet {
    net: u32,
    mask: u32,
    gateway: Ipv4Addr,
}

impl Subnet {
    fn new(p: Prefix) -> Result<Subnet, Error> {
        let IpAddr::V4(a) = p.addr else {
            return Err(fictionet::Error::msg(format!("the sandboxes' subnet {}/{} must be IPv4", p.addr, p.len)));
        };
        if !(8..=30).contains(&p.len) {
            return Err(fictionet::Error::msg(format!("the sandboxes' subnet {a}/{} must have a length from 8 to 30", p.len)));
        }
        let mask = u32::MAX << (32 - p.len as u32);
        let net = u32::from(a) & mask;
        Ok(Subnet { net, mask, gateway: Ipv4Addr::from(net + 1) })
    }

    fn contains(&self, a: Ipv4Addr) -> bool {
        u32::from(a) & self.mask == self.net
    }

    fn broadcast(&self) -> u32 {
        self.net | !self.mask
    }

    fn is_sandbox(&self, a: Ipv4Addr) -> bool {
        let n = u32::from(a);
        self.contains(a) && n != self.net && n != self.broadcast() && a != self.gateway
    }

    fn sandboxes(&self) -> impl Iterator<Item = Ipv4Addr> {
        (self.net + 2..self.broadcast()).map(Ipv4Addr::from)
    }

    fn mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.mask)
    }
}

/// The sandboxes' IPv6 subnet.
#[derive(Clone, Copy, Debug)]
struct Subnet6 {
    net: u128,
    mask: u128,
    gateway: Ipv6Addr,
}

impl Subnet6 {
    fn new(p: Prefix) -> Result<Subnet6, Error> {
        let IpAddr::V6(a) = p.addr else {
            return Err(fictionet::Error::msg(format!("the sandboxes' IPv6 subnet {}/{} must be IPv6", p.addr, p.len)));
        };
        if !(8..=126).contains(&p.len) {
            return Err(fictionet::Error::msg(format!("the sandboxes' IPv6 subnet {a}/{} must have a length from 8 to 126", p.len)));
        }
        let mask = u128::MAX << (128 - p.len as u32);
        let net = u128::from(a) & mask;
        let global = net >> 125 == 0b001;
        let ula = net >> 121 == 0b111_1110;
        if !(global || ula) {
            return Err(fictionet::Error::msg(format!("the sandboxes' IPv6 subnet {a}/{} must lie inside 2000::/3 or fc00::/7", p.len)));
        }
        Ok(Subnet6 { net, mask, gateway: Ipv6Addr::from(net + 1) })
    }

    fn contains(&self, a: Ipv6Addr) -> bool {
        u128::from(a) & self.mask == self.net
    }

    fn is_sandbox(&self, a: Ipv6Addr) -> bool {
        self.contains(a) && u128::from(a) != self.net && a != self.gateway
    }
}

/// A host's addresses. A name with a host has at least one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Placed {
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
}

fn may_serve_v4(a: Ipv4Addr, subnet: &Subnet) -> bool {
    !(subnet.contains(a) || a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.is_loopback())
}

fn may_serve_v6(a: Ipv6Addr, subnet: &Subnet6) -> bool {
    !(subnet.contains(a)
        || a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || a.is_unicast_link_local()
        || a.to_ipv4_mapped().is_some())
}

/// What a name is known as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Known {
    Host(Placed),
    NoHost,
}

/// What a lookup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lookup {
    Host(Placed),
    NoHost,
    /// The resolver gave a host, but the network has as many as it may.
    Full,
}

/// Names and machines.
struct World {
    names: HashMap<String, Known>,
    unknown: usize,
    max_unknown: usize,
    resolved: usize,
    max_hosts: usize,
    machines: HashMap<IpAddr, Arc<Machine>>,
    next_auto: u32,
    next_auto6: u128,
    auto_full: bool,
}

impl World {
    fn new(max_hosts: usize) -> World {
        World {
            names: HashMap::new(),
            unknown: 0,
            max_unknown: MAX_UNKNOWN_NAMES,
            resolved: 0,
            max_hosts,
            machines: HashMap::new(),
            next_auto: 1,
            next_auto6: 1,
            auto_full: false,
        }
    }

    /// Keeps the answer for a resolved `name`, unless it has no host and too
    /// many of those are kept already, or it is longer than a host name
    /// can be.
    fn remember(&mut self, name: &str, known: Known) {
        match known {
            Known::NoHost if self.unknown >= self.max_unknown || name.len() > 253 => return,
            Known::NoHost => self.unknown += 1,
            Known::Host(_) => self.resolved += 1,
        }
        self.names.insert(name.to_owned(), known);
    }

    fn free_auto(&mut self, subnet: &Subnet) -> Option<Ipv4Addr> {
        if self.auto_full {
            return None;
        }
        for _ in 0..AUTO_SIZE {
            let n = self.next_auto;
            self.next_auto = (self.next_auto + 1) % AUTO_SIZE;
            if n == 0 || n == AUTO_SIZE - 1 {
                continue;
            }
            let a = Ipv4Addr::from(AUTO_BASE + n);
            if !subnet.contains(a) && !self.machines.contains_key(&a.into()) {
                return Some(a);
            }
        }
        self.auto_full = true;
        None
    }

    fn free_auto6(&mut self, subnet: &Subnet6) -> Option<Ipv6Addr> {
        let pool_mask = u128::MAX << (128 - AUTO6_LEN as u32);
        if subnet.mask <= pool_mask && subnet.contains(Ipv6Addr::from(AUTO6_BASE)) {
            return None;
        }
        for _ in 0..self.machines.len() + 4 {
            let n = self.next_auto6;
            self.next_auto6 = (self.next_auto6 + 1) % AUTO6_SIZE;
            if n == 0 {
                continue;
            }
            let a = Ipv6Addr::from(AUTO6_BASE + n);
            if subnet.contains(a) {
                self.next_auto6 = ((subnet.net | !subnet.mask) - AUTO6_BASE + 1) % AUTO6_SIZE;
                continue;
            }
            if !self.machines.contains_key(&a.into()) {
                return Some(a);
            }
        }
        None
    }
}

/// Everything the tasks of one network share.
struct Shared {
    fcx: Cx,
    resolver: Option<Arc<Resolver>>,
    subnet: Subnet,
    subnet6: Option<Subnet6>,
    router: Router,
    world: Mutex<World>,
    leases: Mutex<Leases>,
    gateway_tcp: Mutex<Vec<tcp::Endpoint>>,
    hooks: Arc<Hooks>,
    /// Prefixes of trusted sandboxes ([`Net::route`]).
    fixed: Vec<Prefix>,
    limits: Limits,
    seed: u64,
    /// The LANs, by name.
    lans: HashMap<String, LanSeg>,
}

/// One LAN of the network ([`Net::lan`]).
struct LanSeg {
    prefix: Prefix,
    lan: route::Lan,
    /// Where its DNS answers: its first address.
    dns: IpAddr,
    /// Addresses members have, which hosts may not take.
    members: HashSet<IpAddr>,
}

/// The address `n` after the network address of `p`, if it is inside `p`.
fn nth(p: &Prefix, n: u128) -> Option<IpAddr> {
    match p.addr {
        IpAddr::V4(a) => {
            let size = 1u128 << (32 - u32::from(p.len.min(32)));
            (n < size).then(|| IpAddr::V4(Ipv4Addr::from(u32::from(a) + n as u32)))
        }
        IpAddr::V6(a) => {
            let bits = 128 - u32::from(p.len.min(128));
            (bits == 128 || n < (1u128 << bits)).then(|| IpAddr::V6(Ipv6Addr::from(u128::from(a) + n)))
        }
    }
}

/// Whether `a` and `b` share any address.
fn overlap(a: &Prefix, b: &Prefix) -> bool {
    prefix_contains(a, b.addr) || prefix_contains(b, a.addr)
}

/// Starts the network's LANs: each wired to the router through its
/// gateway, with its drops recorded. Checks them and their members.
fn make_lans(
    fcx: &Cx,
    router: &Router,
    hooks: &Arc<Hooks>,
    subnet: &Subnet,
    subnet6: Option<&Subnet6>,
    lans: Vec<(String, Prefix)>,
    members: &[(String, String, IpAddr)],
) -> Result<HashMap<String, LanSeg>, Error> {
    let sandboxes4 = Prefix { addr: IpAddr::V4(Ipv4Addr::from(subnet.net)), len: subnet.mask.count_ones() as u8 };
    let sandboxes6 = subnet6.map(|s| Prefix { addr: IpAddr::V6(Ipv6Addr::from(s.net)), len: s.mask.count_ones() as u8 });
    let mut made: HashMap<String, LanSeg> = HashMap::new();
    for (name, prefix) in lans {
        let max = if prefix.addr.is_ipv4() { 30 } else { 126 };
        if prefix.len > max {
            return Err(fictionet::Error::msg(format!("LAN {name}: {}/{} leaves no room for members", prefix.addr, prefix.len)));
        }
        if overlap(&prefix, &sandboxes4) || sandboxes6.as_ref().is_some_and(|s| overlap(&prefix, s)) {
            return Err(fictionet::Error::msg(format!("LAN {name}: {}/{} overlaps the sandboxes' subnet", prefix.addr, prefix.len)));
        }
        if let Some((other, _)) = made.iter().find(|(n, l)| **n == name || overlap(&prefix, &l.prefix)) {
            return Err(fictionet::Error::msg(format!("LAN {name}: {}/{} overlaps LAN {other}", prefix.addr, prefix.len)));
        }
        let names = hooks.clone();
        let on_drop: route::OnDrop = Arc::new(move |fcx: &Cx, packet: &Packet, why: &'static str| {
            let src = Header::parse_truncated(&packet.0).map(|h| h.src);
            let conn = src.map_or_else(ConnInfo::default, |a| sandbox_only(names.sandbox_at(a)));
            let (event, detail) = blocked(BlockedWhy::Lan, &packet.0);
            names.blocked(fcx, &conn, (event.field("detail", why), detail));
        });
        let lan = route::lan(&fcx.group(format!("lan {name}")), prefix, Some(on_drop));
        let (lan_side, router_side) = link();
        lan.gateway(Box::new(lan_side))?;
        router.add(prefix, Box::new(router_side));
        let dns = nth(&prefix, 1).ok_or_else(|| fictionet::Error::msg("a LAN has room for its DNS"))?;
        made.insert(name, LanSeg { prefix, lan, dns, members: HashSet::new() });
    }
    for (member, lan, addr) in members {
        let Some(seg) = made.get_mut(lan) else {
            return Err(fictionet::Error::msg(format!("member {member}: there is no LAN called {lan}")));
        };
        let broadcast = match seg.prefix.addr {
            IpAddr::V4(a) => Some(IpAddr::V4(Ipv4Addr::from(u32::from(a) | (u32::MAX >> seg.prefix.len)))),
            IpAddr::V6(_) => None,
        };
        if !prefix_contains(&seg.prefix, *addr) || *addr == seg.prefix.addr || *addr == seg.dns || Some(*addr) == broadcast {
            return Err(fictionet::Error::msg(format!("member {member}: {addr} is not a member address of LAN {lan}")));
        }
        if !seg.members.insert(*addr) {
            return Err(fictionet::Error::msg(format!("member {member}: another member of LAN {lan} has {addr}")));
        }
    }
    Ok(made)
}

fn prefix_contains(p: &Prefix, a: IpAddr) -> bool {
    match (p.addr, a) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = if p.len == 0 { 0 } else { u32::MAX << (32 - u32::from(p.len.min(32))) };
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = if p.len == 0 { 0 } else { u128::MAX << (128 - u32::from(p.len.min(128))) };
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

impl Shared {
    /// What `name` is. The first lookup of a name no host has runs the
    /// resolver and, for a host, starts its machines.
    fn lookup(self: &Arc<Self>, name: &str) -> Lookup {
        let mut world = lock(&self.world);
        if let Some(known) = world.names.get(name) {
            return match known {
                Known::Host(p) => Lookup::Host(*p),
                Known::NoHost => Lookup::NoHost,
            };
        }
        let Some(resolver) = &self.resolver else { return Lookup::NoHost };
        let known = match resolver(name) {
            Some(_) if world.resolved >= world.max_hosts => return Lookup::Full,
            Some(mut host) => {
                if !host.names.iter().any(|n| n == name) {
                    host.names.insert(0, name.to_owned());
                }
                let label = host.label.clone();
                match self.place(&mut world, host) {
                    Ok(p) => Known::Host(p),
                    Err(e) => {
                        let event = Event::new("net", "error").level(Level::Notice).summary(format!("host {label} for {name}: {e}")).field("name", name).field("error", e);
                        self.hooks.record(&self.fcx, &ConnInfo::default(), event);
                        Known::NoHost
                    }
                }
            }
            None => Known::NoHost,
        };
        world.remember(name, known);
        match known {
            Known::Host(p) => Lookup::Host(p),
            Known::NoHost => Lookup::NoHost,
        }
    }

    /// Gives `host` its addresses and machines, and adds its services.
    /// Fails if an address given with `at` cannot be served, it ends up
    /// with no address, or a service cannot be added.
    fn place(self: &Arc<Self>, world: &mut World, host: Host) -> Result<Placed, String> {
        if let Some(name) = &host.lan {
            return self.place_on_lan(world, name, &host);
        }
        for a in host.at.map(IpAddr::V4).into_iter().chain(host.at_v6.map(IpAddr::V6)) {
            if let Some((name, _)) = self.lans.iter().find(|(_, l)| prefix_contains(&l.prefix, a)) {
                return Err(format!("{a} is on LAN {name}: place the host there with Host::on"));
            }
        }
        let wants_v4 = host.family != Family::V6;
        let subnet6 = self.subnet6.filter(|_| host.family != Family::V4);
        let mut placed = Placed::default();
        if wants_v4 {
            placed.v4 = match host.at {
                Some(a) if may_serve_v4(a, &self.subnet) => Some(a),
                Some(a) => return Err(format!("{a} is not an address a host can have here")),
                None => world.free_auto(&self.subnet),
            };
        }
        if let Some(subnet6) = subnet6 {
            placed.v6 = match host.at_v6 {
                Some(a) if may_serve_v6(a, &subnet6) => Some(a),
                Some(a) => return Err(format!("{a} is not an address a host can have here")),
                None => world.free_auto6(&subnet6),
            };
        }
        if placed == Placed::default() {
            return Err("no address is left for it".into());
        }
        let label = host.names.first().cloned().unwrap_or_else(|| host.label.clone());
        let addrs = placed.v4.map(IpAddr::V4).into_iter().chain(placed.v6.map(IpAddr::V6));
        for addr in addrs {
            let machine = match world.machines.get(&addr) {
                Some(m) => m.clone(),
                None => {
                    let m = Machine::start(self, addr, &label, None)?;
                    world.machines.insert(addr, m.clone());
                    m
                }
            };
            machine.add(&host)?;
        }
        Ok(placed)
    }

    /// Places `host` on the LAN `name`, at its `at` address of the LAN's
    /// family or the first free one from the LAN's second address up.
    fn place_on_lan(self: &Arc<Self>, world: &mut World, name: &str, host: &Host) -> Result<Placed, String> {
        let seg = self.lans.get(name).ok_or_else(|| format!("there is no LAN called {name}"))?;
        let v4 = seg.prefix.addr.is_ipv4();
        let given = if v4 { host.at.map(IpAddr::V4) } else { host.at_v6.map(IpAddr::V6) };
        let free = |a: IpAddr| a != seg.dns && !seg.members.contains(&a);
        let addr = match given {
            Some(a) if prefix_contains(&seg.prefix, a) && a != seg.prefix.addr && free(a) && !a.is_multicast() => a,
            Some(a) => return Err(format!("{a} is not a free address on LAN {name}")),
            None => (2..1u128 << 16)
                .map_while(|n| nth(&seg.prefix, n))
                .filter(|a| prefix_contains(&seg.prefix, *a))
                .find(|a| free(*a) && !world.machines.contains_key(a))
                .ok_or_else(|| format!("LAN {name} has no free address left"))?,
        };
        let machine = match world.machines.get(&addr) {
            Some(m) => m.clone(),
            None => {
                let label = host.names.first().cloned().unwrap_or_else(|| host.label.clone());
                let m = Machine::start(self, addr, &label, Some(&seg.lan))?;
                world.machines.insert(addr, m.clone());
                m
            }
        };
        machine.add(host)?;
        Ok(match addr {
            IpAddr::V4(a) => Placed { v4: Some(a), v6: None },
            IpAddr::V6(a) => Placed { v4: None, v6: Some(a) },
        })
    }

    /// A member sandbox attached: it joins its LAN at its address, with no
    /// filter, and events know it by that address. It detaches as any
    /// sandbox does when the LAN lets its interface go: when it closes,
    /// when another takes its address, or when it could not join.
    fn join_lan(self: &Arc<Self>, fcx: &Cx, name: &str, lan: &str, addr: IpAddr, sandbox: Attachment) {
        let Some(seg) = self.lans.get(lan) else { return };
        let attached = Arc::new(Attached::new(self, fcx, Arc::from(name), Some(addr)));
        let hooks = &self.hooks;
        let me = Sandbox {
            id: attached.owner,
            name: Arc::from(name),
            addr: if let IpAddr::V4(a) = addr { Some(a) } else { None },
            addr_v6: if let IpAddr::V6(a) = addr { Some(a) } else { None },
        };
        lock(&hooks.by_addr).insert(addr, me.clone());
        let member = Member { sandbox, _attached: attached.clone() };
        let joined = seg.lan.add(addr, Box::new(member));
        let event = match joined {
            Ok(()) => Event::new("net", "attached").summary(format!("sandbox {name} joined LAN {lan} at {addr}")),
            Err(e) => Event::new("net", "error").level(Level::Notice).summary(format!("sandbox {name} could not join LAN {lan}: {e}")).field("error", e.to_string()),
        };
        hooks.record(fcx, &sandbox_only(me), event.field("lan", lan).field("addr", addr.to_string()));
    }
}
// ---------------------------------------------------------------------------
// Machines

/// Open connections by peer address, for
/// [`Limits::connections_per_peer`].
struct Peers {
    open: Mutex<HashMap<IpAddr, usize>>,
    max: usize,
}

impl Peers {
    fn new(max: usize) -> Arc<Peers> {
        Arc::new(Peers { open: Mutex::default(), max })
    }

    fn enter(self: &Arc<Self>, peer: IpAddr) -> Option<PeerGuard> {
        let mut map = lock(&self.open);
        let n = map.entry(peer).or_default();
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(PeerGuard { peers: self.clone(), peer })
    }
}

struct PeerGuard {
    peers: Arc<Peers>,
    peer: IpAddr,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut map = lock(&self.peers.open);
        if let Some(n) = map.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.peer);
            }
        }
    }
}

/// A TLS name on a port: its config, with the accept's ALPN list set
/// (cached), and the accept that serves it.
struct TlsName {
    config: ConfigFor,
    accept: Arc<dyn Accept>,
    alpn: Vec<Vec<u8>>,
    last: Mutex<Option<(Arc<ServerConfig>, Arc<ServerConfig>)>>,
}

impl TlsName {
    fn config(&self, fcx: &Cx) -> Arc<ServerConfig> {
        let given = (self.config)(fcx);
        if self.alpn.is_empty() {
            return given;
        }
        let mut last = lock(&self.last);
        if let Some((from, with_alpn)) = &*last
            && Arc::ptr_eq(from, &given)
        {
            return with_alpn.clone();
        }
        let mut config = (*given).clone();
        config.alpn_protocols = self.alpn.clone();
        let config = Arc::new(config);
        *last = Some((given, config.clone()));
        config
    }
}

/// What one TCP port of a machine serves.
#[derive(Default)]
struct Port {
    plain: RwLock<Option<Arc<dyn Accept>>>,
    /// TLS by SNI; the empty name is "any name".
    tls: RwLock<HashMap<String, Arc<TlsName>>>,
}

/// One address with its services.
struct Machine {
    fcx: Cx,
    addr: IpAddr,
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    ports: Mutex<HashMap<u16, Arc<Port>>>,
    udp_ports: Mutex<HashSet<u16>>,
    peers: Arc<Peers>,
    shared: std::sync::Weak<Shared>,
}

impl Machine {
    /// Starts a machine at `addr`: a route, TCP and UDP with no ports open,
    /// and ping replies, in a group named after `label` and the address.
    fn start(shared: &Arc<Shared>, addr: IpAddr, label: &str, lan: Option<&route::Lan>) -> Result<Arc<Machine>, String> {
        let fcx = &shared.fcx.group(format!("{label} ({addr})"));
        let (router_side, side) = link();
        match lan {
            Some(lan) => lan.add(addr, Box::new(router_side)).map_err(|e| e.to_string())?,
            None => shared.router.add(host_prefix(addr), Box::new(router_side)),
        }
        let (tcp, udp, icmp, _other) = ip::split_protocols(fcx, side);
        let tcp = tcp::endpoint(fcx, tcp, addr);
        let udp = udp::endpoint(fcx, udp, addr);
        fcx.spawn(move |fcx| pings(fcx, icmp, addr));
        Ok(Arc::new(Machine {
            fcx: fcx.clone(),
            addr,
            tcp,
            udp,
            ports: Mutex::new(HashMap::new()),
            udp_ports: Mutex::new(HashSet::new()),
            peers: Peers::new(shared.limits.connections_per_peer),
            shared: Arc::downgrade(shared),
        }))
    }

    /// The port `port`, made and listened on if it is new.
    fn port(self: &Arc<Self>, port: u16) -> Result<Arc<Port>, String> {
        let mut ports = lock(&self.ports);
        if let Some(p) = ports.get(&port) {
            return Ok(p.clone());
        }
        let listener = self.tcp.listen(port).map_err(|e| format!("TCP port {port} at {}: {e}", self.addr))?;
        let p: Arc<Port> = Arc::default();
        ports.insert(port, p.clone());
        let (m, slot) = (self.clone(), p.clone());
        self.fcx.spawn(move |fcx| accept(fcx, listener, m, slot));
        Ok(p)
    }

    /// Adds a host's services.
    fn add(self: &Arc<Self>, host: &Host) -> Result<(), String> {
        let seed = self.shared.upgrade().map_or(0, |s| s.seed);
        let sandbox: Option<serve::SandboxOf> = self.shared.upgrade().map(|s| {
            let hooks = s.hooks.clone();
            Arc::new(move |a: IpAddr| Some(hooks.sandbox_at(a))) as serve::SandboxOf
        });
        let addr = self.addr;
        for (number, spec) in &host.ports {
            match spec {
                PortSpec::Udp(start) => {
                    if !lock(&self.udp_ports).insert(*number) {
                        return Err(format!("UDP port {number} at {addr} is already served"));
                    }
                    let socket = self.udp.bind(*number).map_err(|e| format!("UDP port {number} at {addr}: {e}"))?;
                    start(&self.fcx, socket, SocketAddr::new(addr, *number), seed, sandbox.clone());
                }
                PortSpec::Tcp(accept) => {
                    let port = self.port(*number)?;
                    if !port.tls.read().unwrap_or_else(|e| e.into_inner()).is_empty() {
                        return Err(format!("TCP port {number} at {addr} serves TLS, and cannot serve without it too"));
                    }
                    let mut plain = port.plain.write().unwrap_or_else(|e| e.into_inner());
                    match &*plain {
                        None => {
                            accept.share(&host.names, accept);
                            *plain = Some(accept.clone());
                        }
                        Some(front) => {
                            if !front.share(&host.names, accept) {
                                return Err(format!("TCP port {number} at {addr} is already served by another host"));
                            }
                        }
                    }
                }
                PortSpec::Tls { sni, config, accept } => {
                    let port = self.port(*number)?;
                    if port.plain.read().unwrap_or_else(|e| e.into_inner()).is_some() {
                        return Err(format!("TCP port {number} at {addr} serves without TLS, and cannot serve TLS too"));
                    }
                    let names: Vec<String> = match sni {
                        Sni::Any => vec![String::new()],
                        Sni::Name(n) => vec![n.clone()],
                        Sni::Names if host.names.is_empty() => {
                            return Err(format!("TLS on port {number} is for the host's names, and it has none"));
                        }
                        Sni::Names => host.names.clone(),
                    };
                    let mut tls = port.tls.write().unwrap_or_else(|e| e.into_inner());
                    if let Some(taken) = names.iter().find(|n| tls.contains_key(*n)) {
                        let name = if taken.is_empty() { "any name" } else { taken.as_str() };
                        return Err(format!("TLS port {number} at {addr} already serves {name}"));
                    }
                    let front = tls.values().next().map(|t| t.accept.clone());
                    let served_by = match front {
                        Some(front) if front.share(&host.names, accept) => front,
                        _ => {
                            accept.share(&host.names, accept);
                            accept.clone()
                        }
                    };
                    for name in names {
                        let alpn = served_by.alpn();
                        let entry = TlsName { config: config.clone(), accept: served_by.clone(), alpn, last: Mutex::new(None) };
                        tls.insert(name, Arc::new(entry));
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether TCP `port` is open here.
    fn serves_tcp(&self, port: u16) -> bool {
        lock(&self.ports).contains_key(&port)
    }

    /// Whether UDP `port` is open here.
    fn serves_udp(&self, port: u16) -> bool {
        lock(&self.udp_ports).contains(&port)
    }
}

/// The route to one address: `/32` or `/128`.
fn host_prefix(addr: IpAddr) -> Prefix {
    Prefix { addr, len: if addr.is_ipv4() { 32 } else { 128 } }
}

/// Records that a connection was reset for being past its sandbox's
/// limit.
fn too_many(fcx: &Cx, hooks: &Hooks, conn: &tcp::TcpConnection) {
    let (peer, local) = (conn.peer_addr(), conn.local_addr());
    let event = blocked_event(BlockedWhy::TooManyConnections, Some(PROTO_TCP), Some(peer.ip()), Some(local.ip()));
    hooks.blocked(fcx, &sandbox_only(hooks.sandbox_at(peer.ip())), (event, port_detail(Some(local.port()))));
}

/// Accepts connections on one port of a machine. Each is served in its own
/// region.
async fn accept(fcx: Cx, mut listener: tcp::Listener, machine: Arc<Machine>, port: Arc<Port>) -> fictionet::Result {
    loop {
        match listener.accept(&fcx).await {
            Ok(conn) => {
                let Some(shared) = machine.shared.upgrade() else { return Ok(()) };
                let hooks = shared.hooks.clone();
                let Some(guard) = machine.peers.enter(conn.peer_addr().ip()) else {
                    too_many(&fcx, &hooks, &conn);
                    conn.reset();
                    continue;
                };
                conn.hold_until_gone(Box::new(guard));
                let sandbox = Some(hooks.sandbox_at(conn.peer_addr().ip()));
                let info = ConnInfo::new(hooks.next_conn(), conn.local_addr(), conn.peer_addr()).from_sandbox(sandbox);
                let accepted = fcx.now();
                let port = port.clone();
                fcx.spawn(move |fcx| async move {
                    let _ = fcx
                        .region(move |fcx| async move {
                            connection(fcx, conn, info, accepted, port, shared).await;
                            Ok(())
                        })
                        .await;
                    Ok(())
                });
            }
            Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
            Err(_) => {}
        }
    }
}

/// Serves one connection: TLS by SNI first if the port has TLS names, then
/// the name's accept.
async fn connection(fcx: Cx, conn: tcp::TcpConnection, info: ConnInfo, accepted: Instant, port: Arc<Port>, shared: Arc<Shared>) {
    let hooks = shared.hooks.clone();
    let socket = conn.gone_watch();
    let sandbox_id = info.sandbox.as_ref().map(|s| s.id);
    let budget = sandbox_id.and_then(|id| hooks.budget(id));
    let arrival = |conn: Box<dyn Connection>, info: ConnInfo| Arrival {
        conn,
        info,
        socket: socket.clone(),
        budget: budget.clone(),
        handshake: shared.limits.handshake,
        seed: shared.seed,
    };
    let has_tls = !port.tls.read().unwrap_or_else(|e| e.into_inner()).is_empty();
    if !has_tls {
        let plain = port.plain.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(accept) = plain {
            accept.serve(fcx.clone(), arrival(Box::new(conn), info)).await;
        }
        return;
    }
    let names = port.clone();
    let chosen: Arc<Mutex<Option<Arc<TlsName>>>> = Arc::default();
    let pick = chosen.clone();
    let select: TlsSelect = Arc::new(move |sni, fcx| {
        let tls = names.tls.read().unwrap_or_else(|e| e.into_inner());
        let name = sni.and_then(|n| tls.get(n)).or_else(|| tls.get(""))?.clone();
        let config = name.config(fcx);
        *lock(&pick) = Some(name);
        Some(config)
    });
    let detached = || sandbox_id.is_some_and(|id| !hooks.is_attached(id));
    let deadline = accepted + shared.limits.handshake;
    let Ok((tls, info)) = serve::accept_tls(&fcx, conn, &info, &select, deadline, detached).await else {
        return;
    };
    let Some(name) = lock(&chosen).take() else { return };
    name.accept.serve(fcx.clone(), arrival(Box::new(tls), info)).await;
}

/// Answers pings to `addr`.
async fn pings(fcx: Cx, mut icmp: End, addr: IpAddr) -> fictionet::Result {
    let mut run = 0;
    while let Ok(packet) = icmp.recv(&fcx).await {
        if let Some(reply) = icmp::echo_reply(&packet, addr) {
            icmp.send(reply);
        }
        run = (run + 1) % 64;
        if run == 0 && fcx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

/// The gateway, at its IPv4 address and, with IPv6, at its IPv6 address:
/// DNS over UDP and TCP on port 53, and ping replies. DHCP is answered in
/// each sandbox's filter, which knows which sandbox asked.
fn start_gateway(shared: &Arc<Shared>) -> Result<(), Error> {
    let gateways = std::iter::once(IpAddr::V4(shared.subnet.gateway)).chain(shared.subnet6.map(|s| IpAddr::V6(s.gateway)));
    let fcx = &shared.fcx.group("gateway");
    for gateway in gateways {
        let (router_side, side) = link();
        shared.router.add(host_prefix(gateway), Box::new(router_side));
        start_dns(shared, fcx, side, gateway)?;
    }
    Ok(())
}

/// DNS over UDP and TCP on port 53, and ping replies, at `addr` on `side`.
fn start_dns(shared: &Arc<Shared>, fcx: &Cx, side: End, addr: IpAddr) -> Result<(), Error> {
    let (tcp, udp, icmp, _other) = ip::split_protocols(fcx, side);
    let tcp = tcp::endpoint(fcx, tcp, addr);
    let udp = udp::endpoint(fcx, udp, addr);
    let socket = udp.bind(53)?;
    let listener = tcp.listen(53)?;
    lock(&shared.gateway_tcp).push(tcp);
    let s = shared.clone();
    fcx.spawn(move |fcx| dns_udp(fcx, socket, s));
    let s = shared.clone();
    fcx.spawn(move |fcx| dns_tcp(fcx, listener, s));
    fcx.spawn(move |fcx| pings(fcx, icmp, addr));
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS at the gateway

/// What the DNS server answered, for the event.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DnsAnswer {
    Addr(IpAddr),
    NoData,
    NxDomain,
    Error(u16),
    None,
}

/// The answer to one DNS message, and what it was.
struct Answered {
    reply: Option<Vec<u8>>,
    name: Option<String>,
    qtype: Option<u16>,
    answer: DnsAnswer,
}

impl Answered {
    fn none() -> Answered {
        Answered { reply: None, name: None, qtype: None, answer: DnsAnswer::None }
    }

    fn event(&self, tcp: bool) -> Event {
        let answer = if self.reply.is_some() { self.answer.clone() } else { DnsAnswer::None };
        let (kind, addr, rcode) = match &answer {
            DnsAnswer::Addr(a) => ("addr", Some(a.to_string()), None),
            DnsAnswer::NoData => ("nodata", None, None),
            DnsAnswer::NxDomain => ("nxdomain", None, None),
            DnsAnswer::Error(code) => ("error", None, Some(u32::from(*code))),
            DnsAnswer::None => ("none", None, None),
        };
        Event::new("dns", "query")
            .summary(format!("{} {}: {}", self.name.as_deref().unwrap_or("-"), self.qtype.unwrap_or(0), addr.as_deref().unwrap_or(kind)))
            .field("tcp", tcp)
            .field("name", jopt(self.name.clone()))
            .field("qtype", jopt(self.qtype.map(u32::from)))
            .field("answer", kind)
            .field("addr", jopt(addr))
            .field("rcode", jopt(rcode))
    }
}

/// The answer to one DNS message.
fn answer(shared: &Arc<Shared>, bytes: &[u8]) -> Answered {
    let query = match Message::from_vec(bytes) {
        Ok(q) => q,
        Err(_) => {
            if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
                return Answered::none();
            }
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            let reply = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr).to_vec().ok();
            return Answered { reply, name: None, qtype: None, answer: DnsAnswer::Error(1) };
        }
    };
    if query.metadata.message_type != MessageType::Query {
        return Answered::none();
    }
    let first = query.queries.first().filter(|_| query.queries.len() == 1);
    let mut name = first.map(|q| normalize(&q.name().to_ascii()));
    let qtype = first.map(|q| u16::from(q.query_type()));
    let event_answer;
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.metadata.authoritative = true;
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.queries = query.queries.clone();
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        reply.edns = Some(edns);
    }
    if query.metadata.op_code != OpCode::Query {
        reply.metadata.response_code = ResponseCode::NotImp;
        event_answer = DnsAnswer::Error(4);
    } else if query.queries.len() != 1 {
        reply.metadata.response_code = ResponseCode::FormErr;
        event_answer = DnsAnswer::Error(1);
        name = None;
    } else {
        let q = &query.queries[0];
        let name = name.as_deref().unwrap_or_default();
        let found = if name.is_empty() { Lookup::NoHost } else { shared.lookup(name) };
        match found {
            Lookup::NoHost => {
                reply.metadata.response_code = ResponseCode::NXDomain;
                event_answer = DnsAnswer::NxDomain;
            }
            Lookup::Full => {
                reply.metadata.response_code = ResponseCode::ServFail;
                event_answer = DnsAnswer::Error(2);
            }
            Lookup::Host(placed) => {
                let class_ok = matches!(q.query_class(), DNSClass::IN | DNSClass::ANY);
                let rdata = match (class_ok, q.query_type()) {
                    (true, RecordType::A) => placed.v4.map(|a| RData::A(A(a))),
                    (true, RecordType::AAAA) => placed.v6.map(|a| RData::AAAA(AAAA(a))),
                    _ => None,
                };
                match rdata {
                    Some(rdata) => {
                        event_answer = DnsAnswer::Addr(match &rdata {
                            RData::A(a) => a.0.into(),
                            RData::AAAA(a) => a.0.into(),
                            _ => unreachable!("only A and AAAA are made"),
                        });
                        reply.answers.push(Record::from_rdata(q.name().clone(), TTL, rdata));
                    }
                    None => event_answer = DnsAnswer::NoData,
                }
            }
        }
    }
    let qtype = if name.is_some() { qtype } else { None };
    Answered { reply: reply.to_vec().ok(), name, qtype, answer: event_answer }
}

/// DNS over UDP on the gateway's port 53.
async fn dns_udp(fcx: Cx, mut socket: udp::Socket, shared: Arc<Shared>) -> fictionet::Result {
    let mut run = 0;
    let hooks = shared.hooks.clone();
    while let Ok((query, from)) = socket.recv(&fcx).await {
        let answered = answer(&shared, &query);
        let info = ConnInfo { sandbox: Some(hooks.sandbox_at(from.ip())), peer: Some(from), ..ConnInfo::default() };
        hooks.record(&fcx, &info, answered.event(false));
        if let Some(reply) = answered.reply {
            socket.send_to(&reply, from);
        }
        run = (run + 1) % 64;
        if run == 0 && fcx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

/// DNS over TCP on the gateway's port 53.
async fn dns_tcp(fcx: Cx, mut listener: tcp::Listener, shared: Arc<Shared>) -> fictionet::Result {
    let peers = Peers::new(shared.limits.connections_per_peer);
    loop {
        match listener.accept(&fcx).await {
            Ok(conn) => {
                let Some(guard) = peers.enter(conn.peer_addr().ip()) else {
                    too_many(&fcx, &shared.hooks, &conn);
                    conn.reset();
                    continue;
                };
                conn.hold_until_gone(Box::new(guard));
                let shared = shared.clone();
                fcx.spawn(move |fcx| async move {
                    let _ = dns_conn(&fcx, conn, &shared).await;
                    Ok(())
                });
            }
            Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
            Err(_) => {}
        }
    }
}

async fn dns_conn(fcx: &Cx, mut conn: tcp::TcpConnection, shared: &Arc<Shared>) -> Result<(), ConnError> {
    let hooks = shared.hooks.clone();
    let info = ConnInfo {
        sandbox: Some(hooks.sandbox_at(conn.peer_addr().ip())),
        peer: Some(conn.peer_addr()),
        local: Some(conn.local_addr()),
        ..ConnInfo::default()
    };
    loop {
        let read = async {
            let mut len = [0u8; 2];
            if !read_exact(fcx, &mut conn, &mut len).await? {
                return Ok::<_, ConnError>(None);
            }
            let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
            if !read_exact(fcx, &mut conn, &mut query).await? {
                return Ok(None);
            }
            Ok(Some(query))
        };
        let Ok(read) = fcx.race(Some(fcx.now() + shared.limits.dns_tcp_idle), read).await else { return Ok(()) };
        let Some(query) = read? else { return Ok(()) };
        let answered = answer(shared, &query);
        hooks.record(fcx, &info, answered.event(true));
        let Some(reply) = answered.reply else { continue };
        let Ok(n) = u16::try_from(reply.len()) else { continue };
        let mut framed = n.to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        conn.write_all(fcx, &framed).await?;
    }
}

async fn read_exact<C: Connection>(fcx: &Cx, conn: &mut C, buf: &mut [u8]) -> Result<bool, ConnError> {
    let mut at = 0;
    while at < buf.len() {
        let n = conn.read(fcx, &mut buf[at..]).await?;
        if n == 0 {
            return Ok(false);
        }
        at += n;
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// ICMP "host unreachable"

/// Answers every packet with ICMP "host unreachable", or ICMPv6 "address
/// unreachable", from the gateway's address of the same family.
async fn unreachable(fcx: Cx, mut end: End, gateway: IpAddr) -> fictionet::Result {
    let mut run = 0;
    while let Ok(packet) = end.recv(&fcx).await {
        let reply = match gateway {
            IpAddr::V4(g) => icmp::host_unreachable(&packet.0, g),
            IpAddr::V6(g) => icmp::address_unreachable(&packet.0, g),
        };
        if let Some(reply) = reply {
            end.send(reply);
        }
        run = (run + 1) % 64;
        if run == 0 && fcx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Address binding and DHCP

/// Which attachment holds which address.
#[derive(Default)]
struct Leases {
    by_addr: HashMap<Ipv4Addr, (u64, bool)>,
    by_owner: HashMap<u64, Ipv4Addr>,
    by_addr6: HashMap<Ipv6Addr, u64>,
    by_owner6: HashMap<u64, Ipv6Addr>,
    next_owner: u64,
}

impl Leases {
    fn new_owner(&mut self) -> u64 {
        self.next_owner += 1;
        self.next_owner
    }

    fn of(&self, owner: u64) -> Option<(Ipv4Addr, bool)> {
        let a = *self.by_owner.get(&owner)?;
        Some((a, self.by_addr[&a].1))
    }

    fn free_for(&self, owner: u64, a: Ipv4Addr) -> bool {
        self.by_addr.get(&a).is_none_or(|(o, _)| *o == owner)
    }

    fn set(&mut self, owner: u64, a: Ipv4Addr, bound: bool) {
        self.release(owner);
        self.by_addr.insert(a, (owner, bound));
        self.by_owner.insert(owner, a);
    }

    fn release(&mut self, owner: u64) {
        if let Some(a) = self.by_owner.remove(&owner) {
            self.by_addr.remove(&a);
        }
    }

    fn release_all(&mut self, owner: u64) {
        self.release(owner);
        if let Some(a) = self.by_owner6.remove(&owner) {
            self.by_addr6.remove(&a);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bind {
    New,
    Already,
    Refused,
}

impl Shared {
    fn offer(&self, owner: u64, requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let mut leases = lock(&self.leases);
        let mine = leases.of(owner);
        if let Some((a, true)) = mine {
            return Some(a);
        }
        if let Some(r) = requested
            && self.subnet.is_sandbox(r)
            && leases.free_for(owner, r)
        {
            leases.set(owner, r, false);
            return Some(r);
        }
        if let Some((a, false)) = mine {
            return Some(a);
        }
        let a = self.subnet.sandboxes().find(|a| !leases.by_addr.contains_key(a))?;
        leases.set(owner, a, false);
        Some(a)
    }

    fn may_bind(&self, owner: u64, a: Ipv4Addr) -> bool {
        let leases = lock(&self.leases);
        !matches!(leases.of(owner), Some((_, true))) && self.subnet.is_sandbox(a) && leases.free_for(owner, a)
    }

    fn bind(&self, owner: u64, a: Ipv4Addr) -> Bind {
        let mut leases = lock(&self.leases);
        if let Some((b, true)) = leases.of(owner) {
            return if a == b { Bind::Already } else { Bind::Refused };
        }
        if self.subnet.is_sandbox(a) && leases.free_for(owner, a) {
            leases.set(owner, a, true);
            Bind::New
        } else {
            Bind::Refused
        }
    }

    fn bind6(&self, owner: u64, a: Ipv6Addr) -> Bind {
        let Some(subnet) = &self.subnet6 else { return Bind::Refused };
        let mut leases = lock(&self.leases);
        if let Some(b) = leases.by_owner6.get(&owner) {
            return if a == *b { Bind::Already } else { Bind::Refused };
        }
        if subnet.is_sandbox(a) && !leases.by_addr6.contains_key(&a) {
            leases.by_addr6.insert(a, owner);
            leases.by_owner6.insert(owner, a);
            Bind::New
        } else {
            Bind::Refused
        }
    }

    fn dhcp(&self, owner: u64, src: Ipv4Addr, m: &dhcp::Message) -> (Option<Packet>, Option<Ipv4Addr>) {
        if m.op != dhcp::BOOTREQUEST {
            return (None, None);
        }
        match m.message_type() {
            Some(dhcp::DISCOVER) => match self.offer(owner, m.option_addr(opt::REQUESTED_IP)) {
                Some(a) => (Some(self.dhcp_reply(m, dhcp::OFFER, a)), None),
                None => (None, None),
            },
            Some(dhcp::REQUEST) => {
                if m.option_addr(opt::SERVER_ID).is_some_and(|s| s != self.subnet.gateway) {
                    return (None, None);
                }
                let wanted = m.option_addr(opt::REQUESTED_IP).or((!m.ciaddr.is_unspecified()).then_some(m.ciaddr));
                let Some(wanted) = wanted else { return (None, None) };
                match self.bind(owner, wanted) {
                    Bind::New => (Some(self.dhcp_reply(m, dhcp::ACK, wanted)), Some(wanted)),
                    Bind::Already => (Some(self.dhcp_reply(m, dhcp::ACK, wanted)), None),
                    Bind::Refused => (Some(self.dhcp_reply(m, dhcp::NAK, Ipv4Addr::UNSPECIFIED)), None),
                }
            }
            Some(dhcp::INFORM) if !m.ciaddr.is_unspecified() && m.ciaddr == src => {
                (Some(self.dhcp_reply(m, dhcp::INFORM, Ipv4Addr::UNSPECIFIED)), None)
            }
            _ => (None, None),
        }
    }

    fn dhcp_reply(&self, request: &dhcp::Message, kind: u8, yiaddr: Ipv4Addr) -> Packet {
        let gateway = self.subnet.gateway;
        let mut m = dhcp::Message::new(dhcp::BOOTREPLY, request.xid);
        m.htype = request.htype;
        m.hlen = request.hlen;
        m.flags = request.flags;
        m.giaddr = request.giaddr;
        m.chaddr = request.chaddr;
        m.yiaddr = yiaddr;
        if kind == dhcp::INFORM {
            m.ciaddr = request.ciaddr;
        }
        m.push(opt::MESSAGE_TYPE, [if kind == dhcp::INFORM { dhcp::ACK } else { kind }]);
        m.push(opt::SERVER_ID, gateway.octets());
        if kind != dhcp::NAK {
            if kind != dhcp::INFORM {
                m.push(opt::LEASE_TIME, LEASE.to_be_bytes());
                m.push(opt::RENEWAL_TIME, (LEASE / 2).to_be_bytes());
                m.push(opt::REBINDING_TIME, (LEASE / 8 * 7).to_be_bytes());
            }
            m.push(opt::SUBNET_MASK, self.subnet.mask().octets());
            m.push(opt::ROUTER, gateway.octets());
            m.push(opt::DNS, gateway.octets());
        }
        let to = if kind != dhcp::NAK && !request.ciaddr.is_unspecified() { request.ciaddr } else { Ipv4Addr::BROADCAST };
        udp_packet(gateway, dhcp::SERVER_PORT, to, dhcp::CLIENT_PORT, &m.to_bytes().expect("a reply with distinct options writes"))
    }
}

/// A UDP packet with correct checksums.
fn udp_packet(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Packet {
    let mut u = Vec::with_capacity(8 + data.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let mut sum = ip::transport_checksum(src.into(), dst.into(), PROTO_UDP, &u);
    if sum == 0 {
        sum = 0xffff;
    }
    u[6..8].copy_from_slice(&sum.to_be_bytes());
    ip::packet(src.into(), dst.into(), PROTO_UDP, &u)
}

/// If `packet` (with header `h`) is for the DHCP server (UDP port 67 at the
/// broadcast address or the gateway), its message, or `Some(None)` if it
/// does not parse. `None` for every other packet.
fn to_dhcp_server(packet: &[u8], h: &Header, gateway: Ipv4Addr) -> Option<Option<dhcp::Message>> {
    if h.protocol != PROTO_UDP || h.fragment.is_some() {
        return None;
    }
    let dst = h.dst;
    if dst != IpAddr::V4(Ipv4Addr::BROADCAST) && dst != IpAddr::V4(gateway) {
        return None;
    }
    let u = h.payload(packet);
    if u.len() < 8 || u16::from_be_bytes([u[2], u[3]]) != dhcp::SERVER_PORT {
        return None;
    }
    let len = (u16::from_be_bytes([u[4], u[5]]) as usize).clamp(8, u.len());
    Some(dhcp::Message::parse(&u[8..len]).ok())
}

/// One attachment's time on the network, the same for a sandbox behind a
/// filter and a LAN member. Made when it attaches, which gives it an id
/// and its budget. Dropped when it detaches, which resets its connections,
/// frees its addresses and its budget, and records `net.detached`.
struct Attached {
    shared: Arc<Shared>,
    owner: u64,
    fcx: Cx,
    name: Arc<str>,
    /// A LAN member's address. A filtered sandbox's are its leases.
    fixed: Option<IpAddr>,
}

impl Attached {
    fn new(shared: &Arc<Shared>, fcx: &Cx, name: Arc<str>, fixed: Option<IpAddr>) -> Attached {
        let owner = lock(&shared.leases).new_owner();
        lock(&shared.hooks.attached).insert(owner, Budget::new(shared.limits.sandbox_budget));
        Attached { shared: shared.clone(), owner, fcx: fcx.clone(), name, fixed }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        let shared = &self.shared;
        lock(&shared.hooks.attached).remove(&self.owner);
        let (bound, bound6) = match self.fixed {
            Some(IpAddr::V4(a)) => (Some(a), None),
            Some(IpAddr::V6(a)) => (None, Some(a)),
            None => {
                let leases = lock(&shared.leases);
                let v4 = leases.of(self.owner).and_then(|(a, bound)| bound.then_some(a));
                (v4, leases.by_owner6.get(&self.owner).copied())
            }
        };
        let addrs: Vec<IpAddr> = bound.map(IpAddr::V4).into_iter().chain(bound6.map(IpAddr::V6)).collect();
        if !addrs.is_empty() {
            let machines: Vec<Arc<Machine>> = lock(&shared.world).machines.values().cloned().collect();
            for m in machines {
                for a in &addrs {
                    m.tcp.abort_peer(*a);
                }
            }
            for tcp in lock(&shared.gateway_tcp).iter() {
                for a in &addrs {
                    tcp.abort_peer(*a);
                }
            }
        }
        lock(&shared.leases).release_all(self.owner);
        let sandbox = Sandbox { id: self.owner, name: self.name.clone(), addr: bound, addr_v6: bound6 };
        let event = Event::new("net", "detached").summary(format!("sandbox {} detached", self.name));
        shared.hooks.record(&self.fcx, &sandbox_only(sandbox), event);
    }
}

/// A LAN member's attachment, which holds its [`Attached`]: the member
/// detaches when the LAN drops this.
struct Member {
    sandbox: Attachment,
    _attached: Arc<Attached>,
}

impl Interface for Member {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut std::task::Context<'_>) -> Poll<Result<Packet, fictionet::RecvError>> {
        self.sandbox.poll_recv(fcx, cx)
    }

    fn send(&mut self, packet: Packet) {
        self.sandbox.send(packet);
    }

    fn observe_link(&self) -> Option<fictionet::observe::LinkHandle> {
        self.sandbox.observe_link()
    }
}

/// One sandbox's filter, between its attachment and the router.
async fn filter(fcx: Cx, sandbox: Attachment, shared: Arc<Shared>) -> fictionet::Result {
    let name: Arc<str> = Arc::from(sandbox.name());
    let attached = Attached::new(&shared, &fcx, name.clone(), None);
    let mut f = Filter {
        shared: shared.clone(),
        owner: attached.owner,
        name,
        ports: Ports::new(vec![Box::new(sandbox) as Box<dyn Interface>]),
        bound: None,
        bound6: None,
        route4: None,
        route6: None,
        reassembly: Reassembly::default(),
    };
    let event = Event::new("net", "attached").summary(format!("sandbox {} attached", f.name));
    shared.hooks.record(&fcx, &sandbox_only(f.me()), event);
    // Detaches before the filter's links close.
    let _attached = attached;
    loop {
        let deadline = f.reassembly.next_expiry();
        match f.ports.next(&fcx, deadline, |_| Poll::Pending).await? {
            PortEvent::Packet(0, packet) => match ip::version(&packet.0) {
                Some(6) => f.sent_v6(&fcx, packet),
                _ => f.sent_v4(&fcx, packet),
            },
            PortEvent::Packet(_, packet) => f.ports.send(0, packet),
            PortEvent::Closed(_) => return Ok(()),
            PortEvent::Timer => f.reassembly.expire(fcx.now()),
            PortEvent::Extra => {}
        }
    }
}

/// Why the network dropped or refused a packet from a sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockedWhy {
    /// Its source was not the sandbox's address, or the static address it
    /// tried to bind was not free. Dropped.
    NotItsAddress,
    /// It was for another sandbox's address. Dropped.
    OtherSandbox,
    /// It was for a broadcast, multicast or unspecified address, and was
    /// not DHCP. Dropped.
    Broadcast,
    /// It was IPv6, on a network with IPv6 off. Dropped.
    Ipv6,
    /// It was not an IP packet, or its header was broken. Dropped.
    Malformed,
    /// No machine has its destination: answered "host unreachable".
    NoRoute,
    /// Its destination port is closed: TCP gets a RST, UDP "port
    /// unreachable".
    ClosedPort,
    /// A new TCP connection past the sandbox's limit per machine, or past
    /// a service's cap. Reset.
    TooManyConnections,
    /// A LAN dropped it; the event's `detail` says why, such as "no member
    /// at that address".
    Lan,
}

impl BlockedWhy {
    /// The name in the `why` field of a `net.blocked` event: the variant's
    /// name, as `NotItsAddress`.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockedWhy::NotItsAddress => "NotItsAddress",
            BlockedWhy::OtherSandbox => "OtherSandbox",
            BlockedWhy::Broadcast => "Broadcast",
            BlockedWhy::Ipv6 => "Ipv6",
            BlockedWhy::Malformed => "Malformed",
            BlockedWhy::NoRoute => "NoRoute",
            BlockedWhy::ClosedPort => "ClosedPort",
            BlockedWhy::TooManyConnections => "TooManyConnections",
            BlockedWhy::Lan => "Lan",
        }
    }
}

/// A `net.blocked` event. The destination port goes in its detail
/// ([`port_detail`]), since a scan changes it with every packet.
fn blocked_event(why: BlockedWhy, protocol: Option<u8>, src: Option<IpAddr>, dst: Option<IpAddr>) -> Event {
    Event::new("net", "blocked")
        .level(Level::Notice)
        .summary(format!("blocked {}: {} -> {}", why.as_str(), src.map_or("-".into(), |a| a.to_string()), dst.map_or("-".into(), |a| a.to_string())))
        .field("why", why.as_str())
        .field("protocol", jopt(protocol.map(u32::from)))
        .field("src", jopt(src.map(|a| a.to_string())))
        .field("dst", jopt(dst.map(|a| a.to_string())))
}

/// The detail of a `net.blocked` event: its destination port.
fn port_detail(port: Option<u16>) -> Fields {
    Fields::new().with("dst_port", jopt(port.map(u32::from)))
}

/// The event for a blocked packet, and its detail.
fn blocked(why: BlockedWhy, p: &[u8]) -> (Event, Fields) {
    match Header::parse_truncated(p) {
        Some(h) => (blocked_event(why, Some(h.protocol), Some(h.src), Some(h.dst)), port_detail(h.dst_port(p))),
        None => (blocked_event(why, None, None, None), port_detail(None)),
    }
}

struct Filter {
    shared: Arc<Shared>,
    owner: u64,
    name: Arc<str>,
    ports: Ports,
    bound: Option<Ipv4Addr>,
    bound6: Option<Ipv6Addr>,
    route4: Option<usize>,
    route6: Option<usize>,
    reassembly: Reassembly,
}

impl Filter {
    fn me(&self) -> Sandbox {
        Sandbox { id: self.owner, name: self.name.clone(), addr: self.bound, addr_v6: self.bound6 }
    }

    fn block(&self, fcx: &Cx, why: BlockedWhy, packet: &[u8]) {
        self.shared.hooks.blocked(fcx, &sandbox_only(self.me()), blocked(why, packet));
    }

    fn bound_now(&mut self, fcx: &Cx, addr: IpAddr, by_dhcp: bool) {
        let (router_side, mine) = link();
        self.shared.router.add(host_prefix(addr), Box::new(router_side));
        let port = self.ports.add(Box::new(mine));
        match addr {
            IpAddr::V4(a) => (self.bound, self.route4) = (Some(a), Some(port)),
            IpAddr::V6(a) => (self.bound6, self.route6) = (Some(a), Some(port)),
        }
        let sandbox = self.me();
        let mut by_addr = lock(&self.shared.hooks.by_addr);
        for a in self.bound.map(IpAddr::V4).into_iter().chain(self.bound6.map(IpAddr::V6)) {
            by_addr.insert(a, sandbox.clone());
        }
        drop(by_addr);
        let event = Event::new("net", "bound")
            .summary(format!("sandbox {} bound {addr}", self.name))
            .field("by_dhcp", by_dhcp)
            .field("addr", addr.to_string());
        self.shared.hooks.record(fcx, &sandbox_only(sandbox), event);
    }

    fn sent_v4(&mut self, fcx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let gateway = shared.subnet.gateway;
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv4()) else {
            self.block(fcx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (h.src, h.dst) else { return };
        if let Some(message) = to_dhcp_server(&packet.0, &h, gateway) {
            let Some(message) = message else { return };
            let inform_first =
                self.bound.is_none() && message.message_type() == Some(dhcp::INFORM) && shared.may_bind(self.owner, src);
            if !(src.is_unspecified() || Some(src) == self.bound || inform_first) {
                self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            let (reply, new) = shared.dhcp(self.owner, src, &message);
            if let Some(a) = new {
                self.bound_now(fcx, a.into(), true);
            }
            if let Some(reply) = reply {
                self.ports.send(0, reply);
            }
            return;
        }
        match self.bound {
            Some(a) if a == src => {}
            Some(_) => {
                self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind(self.owner, src) != Bind::New {
                    self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(fcx, src.into(), false);
            }
        }
        if dst.is_broadcast() || dst.is_multicast() || dst.is_unspecified() {
            self.block(fcx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        if shared.subnet.contains(dst) && dst != gateway {
            self.block(fcx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(fcx, self.route4, packet);
    }

    fn sent_v6(&mut self, fcx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let Some(subnet) = shared.subnet6 else {
            self.block(fcx, BlockedWhy::Ipv6, &packet.0);
            return;
        };
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv6()) else {
            self.block(fcx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (h.src, h.dst) else { return };
        if dst.is_multicast() || dst.is_unspecified() {
            self.block(fcx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        match self.bound6 {
            Some(a) if a == src => {}
            Some(_) => {
                self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind6(self.owner, src) != Bind::New {
                    self.block(fcx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(fcx, src.into(), false);
            }
        }
        if subnet.contains(dst) && dst != subnet.gateway {
            self.block(fcx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(fcx, self.route6, packet);
    }

    fn forward(&mut self, fcx: &Cx, route: Option<usize>, packet: Packet) {
        let packet = match self.reassembly.push(packet, fcx.now()) {
            Intake::Whole(p) => p,
            Intake::Waiting => return,
            Intake::Refused { packet, answer } => {
                if !self.shared.is_host(&packet.0) {
                    packet
                } else {
                    if let Some(answer) = answer {
                        self.ports.send(0, answer);
                    }
                    return;
                }
            }
        };
        if let Some(why) = self.shared.refused(&packet.0) {
            self.block(fcx, why, &packet.0);
        }
        if let Some(port) = route {
            self.ports.send(port, packet);
        }
    }
}

impl Shared {
    /// Whether `dst` is the gateway, or a LAN's DNS address.
    fn is_gateway(&self, dst: IpAddr) -> bool {
        let gateway = match dst {
            IpAddr::V4(a) => a == self.subnet.gateway,
            IpAddr::V6(a) => self.subnet6.is_some_and(|s| a == s.gateway),
        };
        gateway || self.lans.values().any(|l| l.dns == dst)
    }

    /// Whether `p` is for the gateway or a machine.
    fn is_host(&self, p: &[u8]) -> bool {
        let Some(dst) = ip::destination(p) else { return false };
        self.is_gateway(dst) || lock(&self.world).machines.contains_key(&dst)
    }

    /// Why the network will refuse `p`: no machine has its address, or its
    /// port is not served there. `None` if it will be delivered.
    fn refused(&self, p: &[u8]) -> Option<BlockedWhy> {
        let dst = ip::destination(p)?;
        let closed = |open: &dyn Fn(u8, u16) -> bool| answered_closed(p, open);
        if self.is_gateway(dst) {
            return closed(&|_, p| p == 53).then_some(BlockedWhy::ClosedPort);
        }
        let machine = lock(&self.world).machines.get(&dst).cloned();
        match machine {
            Some(m) => closed(&|proto, p| if proto == PROTO_TCP { m.serves_tcp(p) } else { m.serves_udp(p) })
                .then_some(BlockedWhy::ClosedPort),
            // A trusted sandbox's prefix, or a LAN, which reports its own
            // drops.
            None if self.fixed.iter().chain(self.lans.values().map(|l| &l.prefix)).any(|p| prefix_contains(p, dst)) => None,
            None => Some(BlockedWhy::NoRoute),
        }
    }
}

/// Whether `p`, a whole TCP or UDP packet, is for a port that `open` says
/// is closed, and will be answered as such: it is not a TCP RST, and its
/// checksum is good. The port is looked up first, so only a packet for a
/// closed port has its checksum checked.
fn answered_closed(p: &[u8], open: impl Fn(u8, u16) -> bool) -> bool {
    let Some(h) = Header::parse_whole(p) else { return false };
    if !matches!(h.protocol, PROTO_TCP | PROTO_UDP) {
        return false;
    }
    let t = h.payload(p);
    if t.len() < 8 || open(h.protocol, u16::from_be_bytes([t[2], t[3]])) {
        return false;
    }
    if h.protocol == PROTO_TCP && t.get(13).is_some_and(|flags| flags & 0x04 != 0) {
        return false;
    }
    match h.protocol {
        PROTO_UDP => ip::udp_checksum_ok(h.src, h.dst, t),
        _ => ip::transport_checksum(h.src, h.dst, h.protocol, t) == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_automatic_range_is_not_scanned_again() {
        let mut w = World::new(MAX_HOSTS);
        let subnet = Subnet::new(Prefix { addr: Ipv4Addr::new(198, 0, 0, 0).into(), len: 8 }).unwrap();
        assert_eq!(w.free_auto(&subnet), None);
        assert!(w.auto_full);
        let started = std::time::Instant::now();
        for _ in 0..10_000 {
            assert_eq!(w.free_auto(&subnet), None);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "{:?}", started.elapsed());
    }

    #[test]
    fn names_without_a_host_are_remembered_up_to_a_limit() {
        let mut w = World::new(MAX_HOSTS);
        assert_eq!(w.max_unknown, 100_000);
        w.max_unknown = 3;
        for i in 0..10 {
            w.remember(&format!("n{i}.test"), Known::NoHost);
        }
        assert_eq!((w.names.len(), w.unknown), (3, 3));
        for i in 0..10 {
            w.remember(&format!("s{i}.test"), Known::Host(Placed { v4: Some(Ipv4Addr::new(198, 18, 0, i + 1)), v6: None }));
        }
        assert_eq!((w.names.len(), w.resolved), (13, 10));
        let mut w = World::new(MAX_HOSTS);
        w.remember(&"\\255".repeat(64), Known::NoHost);
        assert!(w.names.is_empty());
    }

    fn subnet6(s: &str) -> Result<Subnet6, Error> {
        Subnet6::new(s.parse().unwrap())
    }

    #[test]
    fn ipv6_subnets_must_be_global_or_unique_local() {
        let s = subnet6("2001:db8::/64").unwrap();
        assert_eq!(s.gateway, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert!(s.is_sandbox("2001:db8::2".parse().unwrap()));
        for not in ["2001:db8::", "2001:db8::1", "2001:db8:0:1::2"] {
            assert!(!s.is_sandbox(not.parse().unwrap()), "{not}");
        }
        for bad in ["fe80::/64", "ff02::/16", "::/8", "::ffff:0:0/96", "2001:db8::/127", "2000::/4", "10.0.0.0/24"] {
            assert!(subnet6(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn automatic_ipv6_addresses_count_up_and_skip_the_subnet() {
        let mut w = World::new(MAX_HOSTS);
        let s = subnet6("2001:db8::/64").unwrap();
        assert_eq!(w.free_auto6(&s), Some("2001:2::1".parse().unwrap()));
        assert_eq!(w.free_auto6(&s), Some("2001:2::2".parse().unwrap()));
        let mut w = World::new(MAX_HOSTS);
        let inside = subnet6("2001:2::/120").unwrap();
        assert_eq!(w.free_auto6(&inside), Some("2001:2::100".parse().unwrap()));
        assert_eq!(World::new(MAX_HOSTS).free_auto6(&subnet6("2001::/16").unwrap()), None);
    }

    #[test]
    fn hosts_cannot_have_addresses_a_host_cannot_have() {
        let s = subnet6("2001:db8::/64").unwrap();
        assert!(may_serve_v6("2a02:ec80:300:ed1a::1".parse().unwrap(), &s));
        for bad in ["::", "::1", "ff02::1", "fe80::1", "::ffff:1.2.3.4", "2001:db8::5"] {
            assert!(!may_serve_v6(bad.parse().unwrap(), &s), "{bad}");
        }
    }

    /// A packet for an open port is let through without its checksum being
    /// checked; only one for a closed port has it checked. Before, every
    /// forwarded packet was checksummed first, and a bad one was never
    /// looked up.
    #[test]
    fn the_port_is_looked_up_before_the_checksum() {
        let (src, dst) = (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 40, 0, 1));
        let good = udp_packet(src, 5000, dst, 9, b"hello").0;
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        let looked = AtomicUsize::new(0);
        let open = |is_open: bool| {
            let looked = &looked;
            move |_: u8, _: u16| {
                looked.fetch_add(1, Ordering::Relaxed);
                is_open
            }
        };
        assert!(!answered_closed(&bad, open(true)));
        assert_eq!(looked.load(Ordering::Relaxed), 1, "the port of a packet with a bad checksum is looked up");
        assert!(!answered_closed(&good, open(true)));
        assert!(answered_closed(&good, open(false)));
        assert!(!answered_closed(&bad, open(false)), "a bad checksum to a closed port is dropped, not answered");
        // A TCP SYN to a closed port is answered; a RST is not.
        let tcp = |flags: u8| {
            let mut t = vec![0u8; 20];
            t[2..4].copy_from_slice(&80u16.to_be_bytes());
            t[12] = 5 << 4;
            t[13] = flags;
            let sum = ip::transport_checksum(src.into(), dst.into(), PROTO_TCP, &t);
            t[16..18].copy_from_slice(&sum.to_be_bytes());
            ip::packet(src.into(), dst.into(), PROTO_TCP, &t).0
        };
        assert!(answered_closed(&tcp(0x02), open(false)));
        assert!(!answered_closed(&tcp(0x04), open(false)));
    }

    #[test]
    fn prefixes_contain_their_addresses() {
        let p: Prefix = "10.0.0.50/32".parse().unwrap();
        assert!(prefix_contains(&p, "10.0.0.50".parse().unwrap()));
        assert!(!prefix_contains(&p, "10.0.0.51".parse().unwrap()));
        let p: Prefix = "10.0.9.0/24".parse().unwrap();
        assert!(prefix_contains(&p, "10.0.9.200".parse().unwrap()));
        assert!(!prefix_contains(&p, "2001:db8::1".parse().unwrap()));
    }
}
