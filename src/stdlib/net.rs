//! A network of hosts and services in a few lines: the sandboxes' side,
//! DNS, addresses, a router, one machine per address, and the services on
//! each.
//!
//! [`Net`] builds the whole network around the [`Host`]s a world declares.
//! Each host has addresses, DNS names, and services on its ports: any
//! [`Service`] over TCP or UDP, the same over TLS chosen by SNI, and HTTP
//! sites ([`httpd`]) with name-based virtual hosting.
//! Every sandbox that attaches is put on the sandboxes' subnet, given an
//! address by DHCP or by its first packet, and kept from reaching the other
//! sandboxes. A world then writes only its services.
//!
//! An office: a domain controller that answers LDAP and Kerberos, a web
//! server, and a PLC, with DNS names for each:
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::{httpd, journal::Journal, net::{Host, Net}, serve};
//! # struct Ldap; struct Plc; struct Directory; struct Plant;
//! # macro_rules! svc { ($t:ty, $w:ty) => {
//! # impl serve::Service for $t {
//! #     type Decode = fictionet::stdlib::codec::Lines; type World = $w; type Error = std::convert::Infallible;
//! #     fn decoder(&self) -> Self::Decode { fictionet::stdlib::codec::Lines::new(64, fictionet::stdlib::codec::Ending::LfOrCrlf) }
//! #     fn on_item(&mut self, _: Result<Vec<u8>, fictionet::stdlib::codec::LineError>, _: &$w, _: &mut serve::ServeCtx<'_>) -> std::result::Result<serve::Flow, Self::Error> { Ok(serve::Flow::Continue) }
//! # } } }
//! # svc!(Ldap, Directory); svc!(Plc, Plant);
//! # fn world(cx: Cx, attachments: Attachments) -> Result {
//! let directory = Arc::new(Directory);
//! let plant = Arc::new(Plant);
//! let intranet = httpd::Router::new().get("/", |_, _| http::Response::new("intranet\n".into()));
//! Net::new()
//!     .journal(Journal::new().to_file("/tmp/office-journal.jsonl")?)
//!     .host("dc01")
//!         .at("10.20.0.10".parse::<std::net::Ipv4Addr>()?)
//!         .dns_name("dc01.corp.test")
//!         .tcp(389, directory.clone(), || Ldap)
//!         .done()
//!     .host("www")
//!         .dns_name("intranet.corp.test")
//!         .http(80, intranet)
//!         .done()
//!     .host("plc1")
//!         .at("10.30.0.5".parse::<std::net::Ipv4Addr>()?)
//!         .tcp(502, plant, || Plc)
//!         .done()
//!     .serve(&cx, attachments)?;
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
//! - **Machines** answer pings, reset TCP to closed ports and answer UDP to
//!   closed ports with "port unreachable". A sandbox may have 256
//!   connections open at once to one machine; past that, new ones are
//!   reset.
//! - **Every link** inside the network holds at most 4 MiB of packets each
//!   way; past that, packets are dropped, as on a congested link.
//! - **The journal**, if set ([`Net::journal`]), gets every fact: `net`
//!   events for sandboxes attaching, binding, detaching and packets
//!   dropped (`net.blocked`), `dns.query` for every DNS message,
//!   `tls.handshake` for every handshake on a TLS port, and each service's
//!   own events. Every event names its sandbox and, for a connection, its
//!   number (from 1, on every port of every machine).
//!
//! The limits and rules are those [`web::Sites`](crate::stdlib::web::Sites)
//! documents in detail, which runs on this.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::task::Poll;
use std::time::Duration;

use fictionet::stdlib::codec::Decode;
use fictionet::stdlib::dhcp::{self, opt};
use fictionet::stdlib::dns::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use fictionet::stdlib::dns::rr::{DNSClass, RData, Record, RecordType, rdata::A, rdata::AAAA};
use fictionet::stdlib::httpd::{self, Handler, HttpOptions, VHost, VirtualHosts};
use fictionet::stdlib::ip::{Header, Intake, Reassembly};
use fictionet::stdlib::journal::{ConnInfo, Event, Journal, Level, Sandbox, opt as jopt};
use fictionet::stdlib::route::{self, Prefix, Router};
use fictionet::stdlib::serve::{self, ServeOptions, Service, TlsSelect};
use fictionet::stdlib::tls::ServerConfig;
use fictionet::stdlib::{ConnError, Connection, ConnectionExt, PortEvent, Ports, icmp, ip, tcp, udp};
use fictionet::time::Instant;
use fictionet::{Attachment, Attachments, Cx, End, Error, Interface, InterfaceExt, Packet};

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

/// How many connections one peer address may have open at one machine (or
/// at the gateway's DNS) at once, counted until each has finished closing.
pub const CONNECTIONS_PER_PEER: usize = 256;

/// How long a client has, from connecting, to finish its TLS handshake, or
/// on an HTTP port without TLS to send its first bytes.
pub const HANDSHAKE_TIME: Duration = Duration::from_secs(10);

/// How long a DNS-over-TCP connection may sit idle between queries (RFC
/// 7766, section 6.2.3).
const DNS_TCP_IDLE: Duration = Duration::from_secs(10);

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

/// Serves one accepted connection of one port. [`Host::tcp`] and the
/// others make these; a world can write its own for [`Host::accept`].
pub trait Accept: Send + Sync + 'static {
    /// Serves `conn`, which arrived as `info` says. `gone` says when the
    /// client reset it. `journal` is the network's.
    fn serve(&self, cx: Cx, conn: Box<dyn Connection>, info: ConnInfo, gone: tcp::GoneWatch, journal: Option<Journal>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Serves a [`Service`] made fresh for each connection.
struct ServiceAccept<S: Service, M> {
    world: Arc<S::World>,
    make: M,
    opts: ServeOptions,
}

impl<S, M> Accept for ServiceAccept<S, M>
where
    S: Service,
    M: Fn() -> S + Send + Sync + 'static,
    <S::Decode as Decode>::Error: Clone + Send,
{
    fn serve(&self, cx: Cx, conn: Box<dyn Connection>, info: ConnInfo, gone: tcp::GoneWatch, journal: Option<Journal>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut service = (self.make)();
        let world = self.world.clone();
        let mut opts = self.opts.clone();
        if journal.is_some() {
            opts.journal = journal;
        }
        Box::pin(async move {
            let _ = serve::serve(&cx, conn, info, Some(gone), &mut service, &world, &opts).await;
        })
    }
}

/// Serves HTTP with a machine's virtual hosts for one port.
struct HttpAccept {
    vhosts: VirtualHosts,
    opts: HttpOptions,
}

impl Accept for HttpAccept {
    fn serve(&self, cx: Cx, conn: Box<dyn Connection>, info: ConnInfo, gone: tcp::GoneWatch, _journal: Option<Journal>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler: Arc<dyn Handler> = Arc::new(self.vhosts.clone());
        let opts = self.opts.clone();
        Box::pin(async move {
            httpd::serve_connection(&cx, conn, info, Some(gone), handler, &opts).await;
        })
    }
}

/// Starts serving a UDP port of a machine.
type UdpStart = Arc<dyn Fn(&Cx, udp::Socket, SocketAddr, Option<Journal>) + Send + Sync>;

/// One TLS name on a port: its config, and what serves the connection
/// after the handshake.
#[derive(Clone)]
enum AfterTls {
    Accept(Arc<dyn Accept>),
    /// HTTP, with the port's virtual hosts.
    Http,
}

/// What a host serves on one port.
#[derive(Clone)]
enum PortSpec {
    Tcp(Arc<dyn Accept>),
    Tls { sni: Option<String>, config: ConfigFor, then: AfterTls },
    Http { vhost: VHost, tls: Option<ConfigFor> },
    Udp(UdpStart),
}

/// A website on ports 80 and 443, as [`web::Sites`](crate::stdlib::web::Sites)
/// serves one: see [`Host::web`].
#[derive(Clone)]
pub struct Website {
    handler: Arc<dyn Handler>,
    tls: Option<ConfigFor>,
    plain_http: bool,
    default_host: bool,
}

impl Website {
    /// A website served by `handler`, over plain HTTP only.
    pub fn new(handler: impl Handler) -> Website {
        Website { handler: Arc::new(handler), tls: None, plain_http: false, default_host: false }
    }

    /// The same, from a shared handler.
    pub fn shared(handler: Arc<dyn Handler>) -> Website {
        Website { handler, tls: None, plain_http: false, default_host: false }
    }

    /// Serves it over HTTPS on port 443, with the config `config_for`
    /// returns for each handshake. Port 80 then redirects to https.
    pub fn tls(self, config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static) -> Website {
        Website { tls: Some(Arc::new(config_for)), ..self }
    }

    /// With TLS, answers plain HTTP on port 80 too, with no redirect.
    pub fn plain_http(self) -> Website {
        Website { plain_http: true, ..self }
    }

    /// Answers requests at its address whose host names no site there.
    pub fn default_host(self) -> Website {
        Website { default_host: true, ..self }
    }
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
    default_host: bool,
}

impl Host {
    /// A host called `label` (for observers), with no names or services.
    pub fn new(label: &str) -> Host {
        Host {
            label: label.to_owned(),
            names: Vec::new(),
            at: None,
            at_v6: None,
            family: Family::Both,
            ports: Vec::new(),
            default_host: false,
        }
    }

    /// Serves the host at `addr`, IPv4 or IPv6, which sets its address of
    /// that family. Two calls give it both. A family without `at` gets a
    /// free address from that family's range.
    ///
    /// The address must be one a host can have, outside the sandboxes'
    /// subnet: not unspecified, broadcast, multicast or loopback, and for
    /// IPv6 not link-local or IPv4-mapped. If it is not, the host is not
    /// served.
    pub fn at(self, addr: impl Into<IpAddr>) -> Host {
        match addr.into() {
            IpAddr::V4(a) => Host { at: Some(a), ..self },
            IpAddr::V6(a) => Host { at_v6: Some(a), ..self },
        }
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
    /// host can have many names; its HTTP sites and TLS services are
    /// served under each.
    pub fn dns_name(mut self, name: &str) -> Host {
        self.names.push(httpd::normalize(name));
        self
    }

    /// Serves TCP `port` with a [`Service`] made by `make` for each
    /// connection, sharing `world`. Connections are numbered, and the
    /// service's events reach the network's journal.
    pub fn tcp<S, M>(mut self, port: u16, world: Arc<S::World>, make: M) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        let accept = ServiceAccept { world, make, opts: ServeOptions::default().connection_events(false) };
        self.ports.push((port, PortSpec::Tcp(Arc::new(accept))));
        self
    }

    /// The same with these options: a transcript, a fault plan, an idle
    /// limit. The network's journal replaces any in `opts`.
    pub fn tcp_with<S, M>(mut self, port: u16, world: Arc<S::World>, make: M, opts: ServeOptions) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        let accept = ServiceAccept { world, make, opts };
        self.ports.push((port, PortSpec::Tcp(Arc::new(accept))));
        self
    }

    /// Serves TCP `port` with TLS for `sni` (or for every name, with
    /// `None`), then a [`Service`] made by `make`. Several `tls` calls on one
    /// port route by SNI; a name with no entry is rejected with
    /// `unrecognized_name`.
    pub fn tls<S, M>(
        mut self,
        port: u16,
        sni: Option<&str>,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
        world: Arc<S::World>,
        make: M,
    ) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        let accept = ServiceAccept { world, make, opts: ServeOptions::default().connection_events(false) };
        let spec = PortSpec::Tls { sni: sni.map(httpd::normalize), config: Arc::new(config_for), then: AfterTls::Accept(Arc::new(accept)) };
        self.ports.push((port, spec));
        self
    }

    /// Serves UDP `port` with a [`Service`] that reads one datagram at a
    /// time ([`serve::serve_datagram`]).
    pub fn udp<S, M>(mut self, port: u16, world: Arc<S::World>, make: M) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        let start: UdpStart = Arc::new(move |cx, socket, local, journal| {
            let mut service = make();
            let world = world.clone();
            let opts = ServeOptions { journal, ..ServeOptions::default() };
            cx.spawn(move |cx| async move {
                let _ = serve::serve_datagram(&cx, socket, local, &mut service, &world, &opts).await;
                Ok(())
            });
        });
        self.ports.push((port, PortSpec::Udp(start)));
        self
    }

    /// Serves TCP `port` with `accept`, a connection handler of the world's
    /// own.
    pub fn accept(mut self, port: u16, accept: impl Accept) -> Host {
        self.ports.push((port, PortSpec::Tcp(Arc::new(accept))));
        self
    }

    /// Serves plain HTTP on `port` with `handler`, for each of the host's
    /// names. Hosts at one address share the port, and each request goes
    /// to the host its `Host` header names ([`VirtualHosts`]).
    pub fn http(mut self, port: u16, handler: impl Handler) -> Host {
        self.ports.push((port, PortSpec::Http { vhost: VHost::new(handler), tls: None }));
        self
    }

    /// Serves HTTPS on `port` with `handler`, for each of the host's names,
    /// with the config `config_for` returns. ALPN offers `h2` and
    /// `http/1.1`.
    pub fn https(mut self, port: u16, config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static, handler: impl Handler) -> Host {
        let vhost = VHost { handler: Arc::new(handler), https: true, plain_http: false };
        self.ports.push((port, PortSpec::Http { vhost, tls: Some(Arc::new(config_for)) }));
        self
    }

    /// Serves `site` on ports 80 and 443 the way websites are served: with
    /// TLS, HTTPS on 443 and a redirect to it on 80 (unless
    /// [`plain_http`](Website::plain_http)); without, plain HTTP on 80.
    pub fn web(mut self, site: Website) -> Host {
        let https = site.tls.is_some();
        self.default_host |= site.default_host;
        let plain = VHost { handler: site.handler.clone(), https, plain_http: site.plain_http };
        self.ports.push((80, PortSpec::Http { vhost: plain, tls: None }));
        if let Some(config) = site.tls {
            let secure = VHost { handler: site.handler, https: true, plain_http: false };
            self.ports.push((443, PortSpec::Http { vhost: secure, tls: Some(config) }));
        }
        self
    }

    /// Makes the host's HTTP sites the default ones at its address: they
    /// answer requests whose host names no site there.
    pub fn default_host(self) -> Host {
        Host { default_host: true, ..self }
    }
}

/// [`Host`], while it is added to a [`Net`]: [`done`](Self::done) adds it.
/// [`Net::add_host`] adds a host built on its own.
pub struct HostBuilder {
    net: Net,
    host: Host,
}

impl HostBuilder {
    /// See [`Host::at`].
    pub fn at(self, addr: impl Into<IpAddr>) -> HostBuilder {
        HostBuilder { host: self.host.at(addr), ..self }
    }

    /// See [`Host::ipv4_only`].
    pub fn ipv4_only(self) -> HostBuilder {
        HostBuilder { host: self.host.ipv4_only(), ..self }
    }

    /// See [`Host::ipv6_only`].
    pub fn ipv6_only(self) -> HostBuilder {
        HostBuilder { host: self.host.ipv6_only(), ..self }
    }

    /// See [`Host::dns_name`].
    pub fn dns_name(self, name: &str) -> HostBuilder {
        HostBuilder { host: self.host.dns_name(name), ..self }
    }

    /// See [`Host::tcp`].
    pub fn tcp<S, M>(self, port: u16, world: Arc<S::World>, make: M) -> HostBuilder
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        HostBuilder { host: self.host.tcp(port, world, make), ..self }
    }

    /// See [`Host::tcp_with`].
    pub fn tcp_with<S, M>(self, port: u16, world: Arc<S::World>, make: M, opts: ServeOptions) -> HostBuilder
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        HostBuilder { host: self.host.tcp_with(port, world, make, opts), ..self }
    }

    /// See [`Host::tls`].
    pub fn tls<S, M>(
        self,
        port: u16,
        sni: Option<&str>,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
        world: Arc<S::World>,
        make: M,
    ) -> HostBuilder
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        HostBuilder { host: self.host.tls(port, sni, config_for, world, make), ..self }
    }

    /// See [`Host::udp`].
    pub fn udp<S, M>(self, port: u16, world: Arc<S::World>, make: M) -> HostBuilder
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decode as Decode>::Error: Clone + Send,
    {
        HostBuilder { host: self.host.udp(port, world, make), ..self }
    }

    /// See [`Host::accept`].
    pub fn accept(self, port: u16, accept: impl Accept) -> HostBuilder {
        HostBuilder { host: self.host.accept(port, accept), ..self }
    }

    /// See [`Host::http`].
    pub fn http(self, port: u16, handler: impl Handler) -> HostBuilder {
        HostBuilder { host: self.host.http(port, handler), ..self }
    }

    /// See [`Host::https`].
    pub fn https(self, port: u16, config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static, handler: impl Handler) -> HostBuilder {
        HostBuilder { host: self.host.https(port, config_for, handler), ..self }
    }

    /// See [`Host::web`].
    pub fn web(self, site: Website) -> HostBuilder {
        HostBuilder { host: self.host.web(site), ..self }
    }

    /// See [`Host::default_host`].
    pub fn default_host(self) -> HostBuilder {
        HostBuilder { host: self.host.default_host(), ..self }
    }

    /// Adds the host to the network.
    pub fn done(self) -> Net {
        let mut net = self.net;
        net.hosts.push(self.host);
        net
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
    journal: Option<Journal>,
    routes: Vec<(String, Prefix)>,
    registry: Option<fictionet::observe::Registry>,
    group: String,
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
            journal: None,
            routes: Vec::new(),
            registry: None,
            group: "net".to_owned(),
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

    /// Records every fact in `journal`.
    pub fn journal(self, journal: Journal) -> Net {
        Net { journal: Some(journal), ..self }
    }

    /// Starts a host called `label`; [`HostBuilder::done`] adds it.
    pub fn host(self, label: &str) -> HostBuilder {
        HostBuilder { net: self, host: Host::new(label) }
    }

    /// Adds a host built on its own.
    pub fn add_host(mut self, host: Host) -> Net {
        self.hosts.push(host);
        self
    }

    /// Asks `resolve` for a host the first time a name that no host has is
    /// looked up. `Some(host)` creates it then, with that name as a DNS
    /// name; `None` gives NXDOMAIN. The answer is kept for the run.
    /// `resolve` must return quickly: it runs inside the DNS task.
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

    /// Installs `registry` for observers when the network starts, so the
    /// dashboard decodes the services' protocols.
    pub fn observe(self, registry: fictionet::observe::Registry) -> Net {
        Net { registry: Some(registry), ..self }
    }

    /// Names the group observers see for the network's tasks.
    pub fn group(self, name: &str) -> Net {
        Net { group: name.to_owned(), ..self }
    }

    /// Builds the network and starts it. Every sandbox in `attachments`,
    /// including ones that attach later, is connected.
    ///
    /// Returns immediately. The network runs in background tasks in `cx`'s
    /// region until that region is cancelled. Fails if a subnet cannot be
    /// used.
    pub fn serve(self, cx: &Cx, mut attachments: Attachments) -> Result<(), Error> {
        let subnet = Subnet::new(self.subnet)?;
        let subnet6 = if self.ipv6 { Some(Subnet6::new(self.subnet_v6)?) } else { None };
        if let Some(registry) = self.registry {
            cx.observe_protocols(registry);
        }
        let caller = cx.clone();
        let cx = &cx.group(self.group.clone());
        let router = route::router(cx, Vec::new());

        // Everything without a better route: answered with "host unreachable".
        let (router_side, unreachable_side) = link();
        router.add(Prefix { addr: Ipv4Addr::UNSPECIFIED.into(), len: 0 }, Box::new(router_side));
        let gateway = subnet.gateway;
        cx.spawn(move |cx| unreachable(cx, unreachable_side, gateway.into()));
        if let Some(subnet6) = subnet6 {
            let (router_side, unreachable_side) = link();
            router.add(Prefix { addr: Ipv6Addr::UNSPECIFIED.into(), len: 0 }, Box::new(router_side));
            let gateway = subnet6.gateway;
            cx.spawn(move |cx| unreachable(cx, unreachable_side, gateway.into()));
        }
        let hooks = Arc::new(Hooks {
            journal: self.journal,
            by_addr: Mutex::default(),
            conns: AtomicU64::new(0),
            attached: Mutex::default(),
        });
        let routes: Vec<(String, Prefix)> = self.routes;
        let shared = Arc::new(Shared {
            cx: cx.clone(),
            resolver: self.resolver,
            subnet,
            subnet6,
            router,
            world: Mutex::new(World::new(self.max_hosts)),
            leases: Mutex::new(Leases::default()),
            gateway_tcp: Mutex::new(Vec::new()),
            hooks,
            fixed: routes.iter().map(|(_, p)| *p).collect(),
        });
        start_gateway(&shared)?;
        {
            let mut world = lock(&shared.world);
            for host in self.hosts {
                let names = host.names.clone();
                let placed = shared.place(&mut world, host);
                for name in names {
                    world.names.insert(name, placed.map_or(Known::NoHost, Known::Host));
                }
            }
        }

        caller.spawn(move |cx| async move {
            while let Some(sandbox) = attachments.next(&cx).await {
                if let Some((_, prefix)) = routes.iter().find(|(n, _)| n == sandbox.name()) {
                    shared.router.add(*prefix, Box::new(sandbox));
                    continue;
                }
                let shared = shared.clone();
                cx.spawn(move |cx| filter(cx, sandbox, shared));
            }
            Ok(())
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// What the network's tasks share

/// The journal, and what events need to name sandboxes.
struct Hooks {
    journal: Option<Journal>,
    /// The sandbox that last bound each address. An entry stays after its
    /// sandbox detaches, until another binds the address, so packets and
    /// connections still on their way name the sandbox that sent them.
    by_addr: Mutex<HashMap<IpAddr, Sandbox>>,
    /// The last connection number given out.
    conns: AtomicU64,
    /// The ids of the sandboxes attached now.
    attached: Mutex<HashSet<u64>>,
}

impl Hooks {
    /// Whether events are kept: a journal is set.
    fn on(&self) -> bool {
        self.journal.is_some()
    }

    fn record(&self, cx: &Cx, conn: &ConnInfo, event: Event) {
        if let Some(j) = &self.journal {
            j.record(cx, conn, event);
        }
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
        lock(&self.attached).contains(&id)
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
            return Err(format!("the sandboxes' subnet {}/{} must be IPv4", p.addr, p.len).into());
        };
        if !(8..=30).contains(&p.len) {
            return Err(format!("the sandboxes' subnet {a}/{} must have a length from 8 to 30", p.len).into());
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
            return Err(format!("the sandboxes' IPv6 subnet {}/{} must be IPv6", p.addr, p.len).into());
        };
        if !(8..=126).contains(&p.len) {
            return Err(format!("the sandboxes' IPv6 subnet {a}/{} must have a length from 8 to 126", p.len).into());
        }
        let mask = u128::MAX << (128 - p.len as u32);
        let net = u128::from(a) & mask;
        let global = net >> 125 == 0b001;
        let ula = net >> 121 == 0b111_1110;
        if !(global || ula) {
            return Err(format!("the sandboxes' IPv6 subnet {a}/{} must lie inside 2000::/3 or fc00::/7", p.len).into());
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
    cx: Cx,
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
                match self.place(&mut world, host) {
                    Some(p) => Known::Host(p),
                    None => Known::NoHost,
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
    /// `None` if an address given with `at` cannot be served, or it ends up
    /// with no address.
    fn place(self: &Arc<Self>, world: &mut World, host: Host) -> Option<Placed> {
        let wants_v4 = host.family != Family::V6;
        let subnet6 = self.subnet6.filter(|_| host.family != Family::V4);
        let mut placed = Placed::default();
        if wants_v4 {
            placed.v4 = match host.at {
                Some(a) if may_serve_v4(a, &self.subnet) => Some(a),
                Some(_) => return None,
                None => world.free_auto(&self.subnet),
            };
        }
        if let Some(subnet6) = subnet6 {
            placed.v6 = match host.at_v6 {
                Some(a) if may_serve_v6(a, &subnet6) => Some(a),
                Some(_) => return None,
                None => world.free_auto6(&subnet6),
            };
        }
        if placed == Placed::default() {
            return None;
        }
        let label = host.names.first().cloned().unwrap_or_else(|| host.label.clone());
        let addrs = placed.v4.map(IpAddr::V4).into_iter().chain(placed.v6.map(IpAddr::V6));
        for addr in addrs {
            let machine = match world.machines.get(&addr) {
                Some(m) => m.clone(),
                None => {
                    let m = Machine::start(self, addr, &label);
                    world.machines.insert(addr, m.clone());
                    m
                }
            };
            machine.add(&host);
        }
        Some(placed)
    }
}

// ---------------------------------------------------------------------------
// Machines

/// Open connections by peer address, for [`CONNECTIONS_PER_PEER`].
#[derive(Default)]
struct Peers(Mutex<HashMap<IpAddr, usize>>);

impl Peers {
    fn enter(self: &Arc<Self>, peer: IpAddr) -> Option<PeerGuard> {
        let mut map = lock(&self.0);
        let n = map.entry(peer).or_default();
        if *n >= CONNECTIONS_PER_PEER {
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
        let mut map = lock(&self.peers.0);
        if let Some(n) = map.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.peer);
            }
        }
    }
}

/// A TLS name on a port, with the config cached with ALPN set for HTTP.
struct TlsName {
    config: ConfigFor,
    then: AfterTls,
    http: bool,
    last: Mutex<Option<(Arc<ServerConfig>, Arc<ServerConfig>)>>,
}

impl TlsName {
    fn config(&self, cx: &Cx) -> Arc<ServerConfig> {
        let given = (self.config)(cx);
        if !self.http {
            return given;
        }
        let mut last = lock(&self.last);
        if let Some((from, with_alpn)) = &*last
            && Arc::ptr_eq(from, &given)
        {
            return with_alpn.clone();
        }
        let mut config = (*given).clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
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
    http: VirtualHosts,
    http_opts: Mutex<Option<HttpOptions>>,
}

/// One address with its services.
struct Machine {
    cx: Cx,
    addr: IpAddr,
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    ports: Mutex<HashMap<u16, Arc<Port>>>,
    udp_ports: Mutex<HashSet<u16>>,
    peers: Arc<Peers>,
    hooks: Arc<Hooks>,
}

impl Machine {
    /// Starts a machine at `addr`: a route, TCP and UDP with no ports open,
    /// and ping replies, in a group named after `label` and the address.
    fn start(shared: &Arc<Shared>, addr: IpAddr, label: &str) -> Arc<Machine> {
        let cx = &shared.cx.group(format!("{label} ({addr})"));
        let (router_side, side) = link();
        shared.router.add(host_prefix(addr), Box::new(router_side));
        let (tcp, udp, icmp, _other) = ip::split_protocols(cx, side);
        let tcp = tcp::endpoint(cx, tcp, addr);
        let udp = udp::endpoint(cx, udp, addr);
        cx.spawn(move |cx| pings(cx, icmp, addr));
        Arc::new(Machine {
            cx: cx.clone(),
            addr,
            tcp,
            udp,
            ports: Mutex::new(HashMap::new()),
            udp_ports: Mutex::new(HashSet::new()),
            peers: Arc::default(),
            hooks: shared.hooks.clone(),
        })
    }

    /// The port `port`, made and listened on if it is new.
    fn port(self: &Arc<Self>, port: u16) -> Option<Arc<Port>> {
        let mut ports = lock(&self.ports);
        if let Some(p) = ports.get(&port) {
            return Some(p.clone());
        }
        let listener = self.tcp.listen(port).ok()?;
        let p: Arc<Port> = Arc::default();
        ports.insert(port, p.clone());
        let (m, slot) = (self.clone(), p.clone());
        self.cx.spawn(move |cx| accept(cx, listener, m, slot));
        Some(p)
    }

    /// Adds a host's services. A port's plain service, once set, stays: a
    /// second host at this address cannot take it.
    fn add(self: &Arc<Self>, host: &Host) {
        let journal = self.hooks.journal.clone();
        for (number, spec) in &host.ports {
            match spec {
                PortSpec::Udp(start) => {
                    if lock(&self.udp_ports).insert(*number)
                        && let Ok(socket) = self.udp.bind(*number)
                    {
                        start(&self.cx, socket, SocketAddr::new(self.addr, *number), journal.clone());
                    }
                }
                PortSpec::Tcp(accept) => {
                    let Some(port) = self.port(*number) else { continue };
                    port.plain.write().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(|| accept.clone());
                }
                PortSpec::Tls { sni, config, then } => {
                    let Some(port) = self.port(*number) else { continue };
                    let name = Arc::new(TlsName { config: config.clone(), then: then.clone(), http: false, last: Mutex::new(None) });
                    let mut tls = port.tls.write().unwrap_or_else(|e| e.into_inner());
                    tls.entry(sni.clone().unwrap_or_default()).or_insert(name);
                }
                PortSpec::Http { vhost, tls } => {
                    let Some(port) = self.port(*number) else { continue };
                    {
                        let mut opts = lock(&port.http_opts);
                        if opts.is_none() {
                            *opts = Some(HttpOptions {
                                first_bytes: Some(HANDSHAKE_TIME),
                                journal: journal.clone(),
                                ..HttpOptions::default()
                            });
                            if tls.is_none() {
                                let accept: Arc<dyn Accept> = Arc::new(HttpAccept { vhosts: port.http.clone(), opts: opts.clone().unwrap_or_default() });
                                port.plain.write().unwrap_or_else(|e| e.into_inner()).get_or_insert(accept);
                            }
                        }
                    }
                    for name in &host.names {
                        port.http.insert(name, vhost.clone());
                        if let Some(config) = tls {
                            let entry = Arc::new(TlsName { config: config.clone(), then: AfterTls::Http, http: true, last: Mutex::new(None) });
                            port.tls.write().unwrap_or_else(|e| e.into_inner()).entry(name.clone()).or_insert(entry);
                        }
                    }
                    if host.default_host {
                        port.http.set_default(vhost.clone());
                    }
                }
            }
        }
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

/// Tells the journal that a connection was reset for being past its
/// sandbox's limit.
fn too_many(cx: &Cx, hooks: &Hooks, conn: &tcp::TcpConnection) {
    if hooks.on() {
        let (peer, local) = (conn.peer_addr(), conn.local_addr());
        let event = blocked_event(BlockedWhy::TooManyConnections, Some(PROTO_TCP), Some(peer.ip()), Some(local.ip()), Some(local.port()));
        hooks.record(cx, &sandbox_only(hooks.sandbox_at(peer.ip())), event);
    }
}

/// Accepts connections on one port of a machine. Each is served in its own
/// region.
async fn accept(cx: Cx, mut listener: tcp::Listener, machine: Arc<Machine>, port: Arc<Port>) -> fictionet::Result {
    loop {
        match listener.accept(&cx).await {
            Ok(conn) => {
                let Some(guard) = machine.peers.enter(conn.peer_addr().ip()) else {
                    too_many(&cx, &machine.hooks, &conn);
                    conn.reset();
                    continue;
                };
                conn.hold_until_gone(Box::new(guard));
                let hooks = machine.hooks.clone();
                let sandbox = hooks.on().then(|| hooks.sandbox_at(conn.peer_addr().ip()));
                let id = if hooks.on() { hooks.next_conn() } else { 0 };
                let info = ConnInfo::new(id, conn.local_addr(), conn.peer_addr()).from_sandbox(sandbox);
                let accepted = cx.now();
                let port = port.clone();
                cx.spawn(move |cx| async move {
                    let _ = cx
                        .region(move |cx| async move {
                            connection(cx, conn, info, accepted, port, hooks).await;
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
/// the service.
async fn connection(cx: Cx, conn: tcp::TcpConnection, info: ConnInfo, accepted: Instant, port: Arc<Port>, hooks: Arc<Hooks>) {
    let gone = conn.gone_watch();
    let has_tls = !port.tls.read().unwrap_or_else(|e| e.into_inner()).is_empty();
    if !has_tls {
        let plain = port.plain.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(accept) = plain {
            accept.serve(cx.clone(), Box::new(conn), info, gone, hooks.journal.clone()).await;
        }
        return;
    }
    let names = port.clone();
    let chosen: Arc<Mutex<Option<Arc<TlsName>>>> = Arc::default();
    let pick = chosen.clone();
    let select: TlsSelect = Arc::new(move |sni, cx| {
        let tls = names.tls.read().unwrap_or_else(|e| e.into_inner());
        let name = sni.and_then(|n| tls.get(n)).or_else(|| tls.get(""))?.clone();
        let config = name.config(cx);
        *lock(&pick) = Some(name);
        Some(config)
    });
    let sandbox_id = info.sandbox.as_ref().map(|s| s.id);
    let detached = || sandbox_id.is_some_and(|id| !hooks.is_attached(id));
    let journal = hooks.journal.as_ref();
    let Some((tls, info)) = serve::accept_tls(&cx, conn, &info, &select, accepted + HANDSHAKE_TIME, journal, detached).await else {
        return;
    };
    let Some(name) = lock(&chosen).take() else { return };
    let conn: Box<dyn Connection> = Box::new(tls);
    match &name.then {
        AfterTls::Accept(accept) => accept.serve(cx.clone(), conn, info, gone, hooks.journal.clone()).await,
        AfterTls::Http => {
            let opts = lock(&port.http_opts).clone().unwrap_or_default();
            let handler: Arc<dyn Handler> = Arc::new(port.http.clone());
            httpd::serve_connection(&cx, conn, info, Some(gone), handler, &opts).await;
        }
    }
}

/// Answers pings to `addr`.
async fn pings(cx: Cx, mut icmp: End, addr: IpAddr) -> fictionet::Result {
    let mut run = 0;
    while let Ok(packet) = icmp.recv(&cx).await {
        if let Some(reply) = icmp::echo_reply(&packet, addr) {
            icmp.send(reply);
        }
        run = (run + 1) % 64;
        if run == 0 && cx.yield_now().await.is_err() {
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
    let cx = &shared.cx.group("gateway");
    for gateway in gateways {
        let (router_side, side) = link();
        shared.router.add(host_prefix(gateway), Box::new(router_side));
        let (tcp, udp, icmp, _other) = ip::split_protocols(cx, side);
        let tcp = tcp::endpoint(cx, tcp, gateway);
        let udp = udp::endpoint(cx, udp, gateway);
        let socket = udp.bind(53)?;
        let listener = tcp.listen(53)?;
        lock(&shared.gateway_tcp).push(tcp);
        let s = shared.clone();
        cx.spawn(move |cx| dns_udp(cx, socket, s));
        let s = shared.clone();
        cx.spawn(move |cx| dns_tcp(cx, listener, s));
        cx.spawn(move |cx| pings(cx, icmp, gateway));
    }
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
    let mut name = first.map(|q| httpd::normalize(&q.name().to_ascii()));
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
async fn dns_udp(cx: Cx, mut socket: udp::Socket, shared: Arc<Shared>) -> fictionet::Result {
    let mut run = 0;
    let hooks = shared.hooks.clone();
    while let Ok((query, from)) = socket.recv(&cx).await {
        let answered = answer(&shared, &query);
        if hooks.on() {
            let info = ConnInfo { sandbox: Some(hooks.sandbox_at(from.ip())), peer: Some(from), ..ConnInfo::default() };
            hooks.record(&cx, &info, answered.event(false));
        }
        if let Some(reply) = answered.reply {
            socket.send_to(&reply, from);
        }
        run = (run + 1) % 64;
        if run == 0 && cx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

/// DNS over TCP on the gateway's port 53.
async fn dns_tcp(cx: Cx, mut listener: tcp::Listener, shared: Arc<Shared>) -> fictionet::Result {
    let peers = Arc::new(Peers::default());
    loop {
        match listener.accept(&cx).await {
            Ok(conn) => {
                let Some(guard) = peers.enter(conn.peer_addr().ip()) else {
                    too_many(&cx, &shared.hooks, &conn);
                    conn.reset();
                    continue;
                };
                conn.hold_until_gone(Box::new(guard));
                let shared = shared.clone();
                cx.spawn(move |cx| async move {
                    let _ = dns_conn(&cx, conn, &shared).await;
                    Ok(())
                });
            }
            Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
            Err(_) => {}
        }
    }
}

async fn dns_conn(cx: &Cx, mut conn: tcp::TcpConnection, shared: &Arc<Shared>) -> Result<(), ConnError> {
    let hooks = shared.hooks.clone();
    let info = hooks.on().then(|| ConnInfo {
        sandbox: Some(hooks.sandbox_at(conn.peer_addr().ip())),
        peer: Some(conn.peer_addr()),
        local: Some(conn.local_addr()),
        ..ConnInfo::default()
    });
    loop {
        let read = async {
            let mut len = [0u8; 2];
            if !read_exact(cx, &mut conn, &mut len).await? {
                return Ok::<_, ConnError>(None);
            }
            let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
            if !read_exact(cx, &mut conn, &mut query).await? {
                return Ok(None);
            }
            Ok(Some(query))
        };
        let Ok(read) = serve::until(cx, Some(cx.now() + DNS_TCP_IDLE), read).await else { return Ok(()) };
        let Some(query) = read? else { return Ok(()) };
        let answered = answer(shared, &query);
        if let Some(info) = &info {
            hooks.record(cx, info, answered.event(true));
        }
        let Some(reply) = answered.reply else { continue };
        let Ok(n) = u16::try_from(reply.len()) else { continue };
        let mut framed = n.to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        conn.write_all(cx, &framed).await?;
    }
}

async fn read_exact<C: Connection>(cx: &Cx, conn: &mut C, buf: &mut [u8]) -> Result<bool, ConnError> {
    let mut at = 0;
    while at < buf.len() {
        let n = conn.read(cx, &mut buf[at..]).await?;
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
async fn unreachable(cx: Cx, mut end: End, gateway: IpAddr) -> fictionet::Result {
    let mut run = 0;
    while let Ok(packet) = end.recv(&cx).await {
        let reply = match gateway {
            IpAddr::V4(g) => icmp::host_unreachable(&packet.0, g),
            IpAddr::V6(g) => icmp::address_unreachable(&packet.0, g),
        };
        if let Some(reply) = reply {
            end.send(reply);
        }
        run = (run + 1) % 64;
        if run == 0 && cx.yield_now().await.is_err() {
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
        udp_packet(gateway, dhcp::SERVER_PORT, to, dhcp::CLIENT_PORT, &m.to_bytes())
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
    if h.protocol != PROTO_UDP || h.fragment {
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
    Some(dhcp::Message::parse(&u[8..len]))
}

/// Frees an attachment's address when its filter ends.
struct Release {
    shared: Arc<Shared>,
    owner: u64,
    cx: Cx,
    name: Arc<str>,
}

impl Drop for Release {
    fn drop(&mut self) {
        let shared = &self.shared;
        if shared.hooks.on() {
            lock(&shared.hooks.attached).remove(&self.owner);
        }
        let (bound, bound6) = {
            let leases = lock(&shared.leases);
            let v4 = leases.of(self.owner).and_then(|(a, bound)| bound.then_some(a));
            (v4, leases.by_owner6.get(&self.owner).copied())
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
        if shared.hooks.on() {
            let sandbox = Sandbox { id: self.owner, name: self.name.clone(), addr: bound, addr_v6: bound6 };
            let event = Event::new("net", "detached").summary(format!("sandbox {} detached", self.name));
            shared.hooks.record(&self.cx, &sandbox_only(sandbox), event);
        }
    }
}

/// One sandbox's filter, between its attachment and the router.
async fn filter(cx: Cx, sandbox: Attachment, shared: Arc<Shared>) -> fictionet::Result {
    let name: Arc<str> = Arc::from(sandbox.name());
    let owner = lock(&shared.leases).new_owner();
    let mut f = Filter {
        on: shared.hooks.on(),
        shared: shared.clone(),
        owner,
        name: name.clone(),
        ports: Ports::new(vec![Box::new(sandbox) as Box<dyn Interface>]),
        bound: None,
        bound6: None,
        route4: None,
        route6: None,
        reassembly: Reassembly::default(),
    };
    if f.on {
        lock(&shared.hooks.attached).insert(owner);
        let event = Event::new("net", "attached").summary(format!("sandbox {name} attached"));
        shared.hooks.record(&cx, &sandbox_only(f.me()), event);
    }
    let _release = Release { shared, owner, cx: cx.clone(), name };
    loop {
        let deadline = f.reassembly.next_expiry();
        match f.ports.next(&cx, deadline, |_| Poll::Pending).await {
            PortEvent::Packet(0, packet) => match ip::version(&packet.0) {
                Some(6) => f.sent_v6(&cx, packet),
                _ => f.sent_v4(&cx, packet),
            },
            PortEvent::Packet(_, packet) => f.ports.send(0, packet),
            PortEvent::Closed(_) | PortEvent::Cancelled => return Ok(()),
            PortEvent::Timer => f.reassembly.expire(cx.now()),
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
    /// A new TCP connection past the sandbox's limit per machine. Reset.
    TooManyConnections,
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
        }
    }
}

fn blocked_event(why: BlockedWhy, protocol: Option<u8>, src: Option<IpAddr>, dst: Option<IpAddr>, dst_port: Option<u16>) -> Event {
    Event::new("net", "blocked")
        .level(Level::Notice)
        .summary(format!("blocked {}: {} -> {}", why.as_str(), src.map_or("-".into(), |a| a.to_string()), dst.map_or("-".into(), |a| a.to_string())))
        .field("why", why.as_str())
        .field("protocol", jopt(protocol.map(u32::from)))
        .field("src", jopt(src.map(|a| a.to_string())))
        .field("dst", jopt(dst.map(|a| a.to_string())))
        .field("dst_port", jopt(dst_port.map(u32::from)))
}

/// The event for a blocked packet.
fn blocked(why: BlockedWhy, p: &[u8]) -> Event {
    match Header::parse_truncated(p) {
        Some(h) => {
            let port = (h.fragment_offset == 0 && matches!(h.protocol, PROTO_TCP | PROTO_UDP))
                .then(|| h.payload(p))
                .filter(|t| t.len() >= 4)
                .map(|t| u16::from_be_bytes([t[2], t[3]]));
            blocked_event(why, Some(h.protocol), Some(h.src), Some(h.dst), port)
        }
        None => blocked_event(why, None, None, None, None),
    }
}

struct Filter {
    shared: Arc<Shared>,
    on: bool,
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

    fn block(&self, cx: &Cx, why: BlockedWhy, packet: &[u8]) {
        if self.on {
            self.shared.hooks.record(cx, &sandbox_only(self.me()), blocked(why, packet));
        }
    }

    fn bound_now(&mut self, cx: &Cx, addr: IpAddr, by_dhcp: bool) {
        let (router_side, mine) = link();
        self.shared.router.add(host_prefix(addr), Box::new(router_side));
        let port = self.ports.add(Box::new(mine));
        match addr {
            IpAddr::V4(a) => (self.bound, self.route4) = (Some(a), Some(port)),
            IpAddr::V6(a) => (self.bound6, self.route6) = (Some(a), Some(port)),
        }
        if self.on {
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
            self.shared.hooks.record(cx, &sandbox_only(sandbox), event);
        }
    }

    fn sent_v4(&mut self, cx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let gateway = shared.subnet.gateway;
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv4()) else {
            self.block(cx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (h.src, h.dst) else { return };
        if let Some(message) = to_dhcp_server(&packet.0, &h, gateway) {
            let Some(message) = message else { return };
            let inform_first =
                self.bound.is_none() && message.message_type() == Some(dhcp::INFORM) && shared.may_bind(self.owner, src);
            if !(src.is_unspecified() || Some(src) == self.bound || inform_first) {
                self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            let (reply, new) = shared.dhcp(self.owner, src, &message);
            if let Some(a) = new {
                self.bound_now(cx, a.into(), true);
            }
            if let Some(reply) = reply {
                self.ports.send(0, reply);
            }
            return;
        }
        match self.bound {
            Some(a) if a == src => {}
            Some(_) => {
                self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind(self.owner, src) != Bind::New {
                    self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(cx, src.into(), false);
            }
        }
        if dst.is_broadcast() || dst.is_multicast() || dst.is_unspecified() {
            self.block(cx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        if shared.subnet.contains(dst) && dst != gateway {
            self.block(cx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(cx, self.route4, packet);
    }

    fn sent_v6(&mut self, cx: &Cx, packet: Packet) {
        let shared = self.shared.clone();
        let Some(subnet) = shared.subnet6 else {
            self.block(cx, BlockedWhy::Ipv6, &packet.0);
            return;
        };
        let Some(h) = Header::parse(&packet.0).filter(|h| h.src.is_ipv6()) else {
            self.block(cx, BlockedWhy::Malformed, &packet.0);
            return;
        };
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (h.src, h.dst) else { return };
        if dst.is_multicast() || dst.is_unspecified() {
            self.block(cx, BlockedWhy::Broadcast, &packet.0);
            return;
        }
        match self.bound6 {
            Some(a) if a == src => {}
            Some(_) => {
                self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                return;
            }
            None => {
                if shared.bind6(self.owner, src) != Bind::New {
                    self.block(cx, BlockedWhy::NotItsAddress, &packet.0);
                    return;
                }
                self.bound_now(cx, src.into(), false);
            }
        }
        if subnet.contains(dst) && dst != subnet.gateway {
            self.block(cx, BlockedWhy::OtherSandbox, &packet.0);
            return;
        }
        self.forward(cx, self.route6, packet);
    }

    fn forward(&mut self, cx: &Cx, route: Option<usize>, packet: Packet) {
        let packet = match self.reassembly.intake(packet, cx.now()) {
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
        if self.on
            && let Some(why) = self.shared.refused(&packet.0)
        {
            self.block(cx, why, &packet.0);
        }
        if let Some(port) = route {
            self.ports.send(port, packet);
        }
    }
}

impl Shared {
    fn is_gateway(&self, dst: IpAddr) -> bool {
        match dst {
            IpAddr::V4(a) => a == self.subnet.gateway,
            IpAddr::V6(a) => self.subnet6.is_some_and(|s| a == s.gateway),
        }
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
        let port = transport(p);
        let closed = |open: &dyn Fn(u8, u16) -> bool| match port {
            Some((PROTO_TCP, port, rst)) => !open(PROTO_TCP, port) && !rst,
            Some((proto, port, _)) => !open(proto, port),
            None => false,
        };
        if self.is_gateway(dst) {
            return closed(&|_, p| p == 53).then_some(BlockedWhy::ClosedPort);
        }
        if self.fixed.iter().any(|p| prefix_contains(p, dst)) {
            return None;
        }
        let machine = lock(&self.world).machines.get(&dst).cloned();
        match machine {
            None => Some(BlockedWhy::NoRoute),
            Some(m) => closed(&|proto, p| if proto == PROTO_TCP { m.serves_tcp(p) } else { m.serves_udp(p) })
                .then_some(BlockedWhy::ClosedPort),
        }
    }
}

/// The protocol, destination port, and whether it is a TCP RST, of a whole
/// TCP or UDP packet with a good checksum.
fn transport(p: &[u8]) -> Option<(u8, u16, bool)> {
    let h = Header::parse_whole(p)?;
    if !matches!(h.protocol, PROTO_TCP | PROTO_UDP) {
        return None;
    }
    let t = h.payload(p);
    if t.len() < 8 {
        return None;
    }
    let good = match h.protocol {
        PROTO_UDP => ip::udp_checksum_ok(h.src, h.dst, t),
        _ => ip::transport_checksum(h.src, h.dst, h.protocol, t) == 0,
    };
    if !good {
        return None;
    }
    let rst = h.protocol == PROTO_TCP && t.get(13).is_some_and(|flags| flags & 0x04 != 0);
    Some((h.protocol, u16::from_be_bytes([t[2], t[3]]), rst))
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
