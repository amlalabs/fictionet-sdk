//! A network of hosts and services in a few lines: the sandboxes' side,
//! DNS, addresses, a router, one machine per address, and the services on
//! each.
//!
//! [`Net`] builds the whole network around the [`Host`]s a world declares.
//! Each host has addresses, DNS names, and services on its ports: any
//! [`Service`] over TCP or UDP, the same over TLS chosen by SNI, and any
//! [`PortServer`] of the world's own, such as [`httpd::Server`] for HTTP with
//! name-based virtual hosting. Every sandbox that attaches is put on the
//! sandboxes' subnet, given an address by DHCP or by its first packet, and
//! kept from reaching the other sandboxes. A world then writes only its
//! services.
//!
//! An office: a domain controller that answers LDAP and Kerberos, a web
//! server, and a PLC, with DNS names for each:
//!
//! ```
//! # fictionet::cfg_std! {
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::{httpd, net::{Host, Net}, serve};
//! # struct Ldap; struct Plc; struct Directory; struct Plant;
//! # macro_rules! svc { ($t:ty, $w:ty) => {
//! # impl serve::Service for $t {
//! #     type Decoder = fictionet::stdlib::codec::Lines; type State = $w; type Error = std::convert::Infallible;
//! #     fn decoder(&self) -> Self::Decoder { fictionet::stdlib::codec::Lines::new(64, fictionet::stdlib::codec::Ending::LfOrCrlf) }
//! #     fn on_item(&mut self, _: Result<Vec<u8>, fictionet::stdlib::codec::LineError>, _: &$w, _: &mut serve::Driver<'_, Self::Decoder>) -> std::result::Result<serve::Flow, Self::Error> { Ok(serve::Flow::Continue) }
//! # } } }
//! # svc!(Ldap, Directory); svc!(Plc, Plant);
//! # async fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let directory = Arc::new(Directory);
//! let plant = Arc::new(Plant);
//! let intranet = httpd::Router::new().get("/", |_, _| http::Response::new("intranet\n".into()));
//! fcx.events().to_file("/tmp/office-events.jsonl")?;
//! Net::new()
//!     .host("dc01", |h| h.at("10.20.0.10".parse::<std::net::Ipv4Addr>().unwrap()).dns_name("dc01.corp.test").tcp(389, directory.clone(), || Ldap))
//!     .host("www", |h| h.dns_name("intranet.corp.test").port_server(80, httpd::Server::new(intranet)))
//!     .host("plc1", |h| h.at("10.30.0.5".parse::<std::net::Ipv4Addr>().unwrap()).tcp(502, plant, || Plc))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! [`web::Sites`](fictionet::stdlib::web::Sites) is a preset on `Net` for a
//! world of websites, whose hosts appear as their names are looked up
//! ([`Net::resolve`]).
//!
//! # What `start` builds
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
//!   DHCP drops requests with a UDP length below eight bytes or beyond the
//!   IP payload, or an incorrect nonzero UDP checksum. An IPv4 zero checksum
//!   is accepted. Dropped requests do not reserve or bind an address.
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
//!   (as [repeats](fictionet::events#repeats)).
//! - **Machines** answer pings, reset TCP to closed ports and answer UDP to
//!   closed ports with "port unreachable". UDP delivery and closed-port
//!   events use the declared UDP length. Invalid lengths are dropped;
//!   trailing IP payload bytes are ignored when checking the checksum.
//!   A peer address may have 256 connections open at once across the
//!   network ([`Limits::connections_per_peer`]); past that, new ones are
//!   reset. Each service has its own cap too ([`ServeOptions::max_conns`]).
//! - **Budgets.** Service-layer holdings for one sandbox are charged to
//!   that sandbox's [`Budget`], 256 MiB unless [`Limits::sandbox_budget`]
//!   says otherwise. A connection that would pass it is closed. The service
//!   driver charges its buffers and what the service reports holding, and
//!   HTTP/2 charges retained request heads, events and bodies (see [`httpd`]).
//!   A [`PortServer`] of your own charges what it chooses. A sandbox has one
//!   budget for both its addresses, from when it attaches until it
//!   detaches. A trusted sandbox ([`Net::route`]) has none.
//! - **Every link** inside the network holds at most 4 MiB of packets each
//!   way; past that, packets are dropped, as on a congested link.
//! - **Events.** The network records every fact in the run's
//!   [events](fictionet::events): a `run.start` event first, `net` events for
//!   sandboxes attaching,
//!   binding, detaching and packets dropped (`net.blocked`, counted as
//!   [repeats](fictionet::events#repeats)), `dns.query`
//!   for every DNS message, `tls.handshake` for every handshake on a TLS
//!   port, and each service's own events. Every event names its sandbox
//!   and, for a connection, its number (from 1, on every port of every
//!   machine).
//! - **Errors.** A host that cannot be served as declared, such as one at
//!   an address a host cannot have, two services on one port (one with
//!   TLS and one without count as two), or a port
//!   that cannot be listened on, makes [`Net::start`] fail. A rejected host
//!   adds no machine, route, listener, task, TLS name or virtual host, and
//!   consumes no automatic address. Existing hosts remain unchanged. Hosts
//!   returned by the resolver follow the same rule; their failed lookups
//!   record `net.error` and answer NXDOMAIN.
//!
//! The limits and rules are those [`web::Sites`](fictionet::stdlib::web::Sites)
//! documents in detail, which runs on this.

use fictionet::sync::Mutex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use fictionet::events::{ConnInfo, Event, Fields, Level, Sandbox, opt as jopt};
use fictionet::stdlib::codec::{Collect, CollectError, Decode, Step, Wire};
use fictionet::stdlib::dhcp;
use fictionet::stdlib::dns::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use fictionet::stdlib::dns::rr::{DNSClass, RData, Record, RecordType, rdata::A, rdata::AAAA};
use fictionet::stdlib::ip::{Header, Intake, Reassembly};
use fictionet::stdlib::route::{self, Prefix, Router};
use fictionet::stdlib::serve::{self, Budget, Counted, ServeOptions, Service};
use fictionet::stdlib::{
    ConnError, icmp, ip,
    ports::{self, Ports},
    tcp, udp,
};
use fictionet::{Attachment, Attachments, Cx, End, Error, Interface, InterfaceExt, Packet};

fictionet::cfg_std! {
#[cfg(doc)]
use fictionet::stdlib::httpd;
}

#[path = "net/addresses.rs"]
mod addresses;

#[path = "net/hosts.rs"]
mod hosts;

use addresses::{AUTO, AUTO6, Bind, Leases, Subnet, Subnet6};
pub use hosts::{Arrival, ConfigFor, Host, PortServer, PreparedShare, Sni};
use hosts::{Known, Lookup, Machine, Peers, World, host_prefix, pings, too_many};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// Each link inside the network holds at most this many bytes of packets
/// each way.
const LINK_QUEUE: usize = 4 << 20;

/// How many names may have a host made by [`Net::resolve`], unless the
/// world sets another limit.
pub const MAX_HOSTS: usize = 20_000;

/// How long resolvers may keep an answer, in seconds.
const TTL: u32 = 60;

fn link() -> (End, End) {
    fictionet::pair_with_limit(LINK_QUEUE)
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
    /// How many connections one peer address may have open across all machines
    /// and gateway DNS listeners at once, counted until each has finished
    /// closing. Default 256.
    pub connections_per_peer: usize,
    /// How long a client has, from connecting, to finish its TLS handshake,
    /// or on an HTTP port without TLS to send its first bytes; and from a
    /// service's STARTTLS, to finish that handshake. Default 10 seconds.
    pub handshake: Duration,
    /// How long a DNS-over-TCP connection may sit idle between queries (RFC
    /// 7766, section 6.2.3). Default 10 seconds.
    pub dns_tcp_idle: Duration,
    /// Bytes held by the service layer for one sandbox, all services
    /// together: see [`Budget`]. Excludes TCP buffers and TLS handshakes.
    /// Default 256 MiB.
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
            subnet: Prefix {
                addr: Ipv4Addr::new(10, 0, 0, 0).into(),
                len: 24,
            },
            subnet_v6: Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).into(),
                len: 64,
            },
            ipv6: true,
            hosts: Vec::new(),
            resolver: None,
            max_hosts: MAX_HOSTS,
            routes: Vec::new(),
            registry: None,
            group: "net".to_owned(),
            limits: Limits::default(),
            start: Fields::new(),
            lans: Vec::new(),
            members: Vec::new(),
        }
    }

    /// Sets the sandboxes' IPv4 or IPv6 subnet, whichever `subnet` is. The
    /// gateway and DNS server take the address after the subnet's own. An
    /// IPv4 subnet must have a length from 8 to 30; an IPv6 one from 8 to
    /// 126, inside `2000::/3` or `fc00::/7`. Otherwise
    /// [`start`](Net::start) fails.
    pub fn subnet(self, subnet: Prefix) -> Net {
        match subnet.addr {
            IpAddr::V4(_) => Net { subnet, ..self },
            IpAddr::V6(_) => Net {
                subnet_v6: subnet,
                ..self
            },
        }
    }

    /// Turns IPv6 off: hosts have only IPv4 addresses, DNS answers AAAA
    /// with NODATA, and every IPv6 packet from a sandbox is dropped.
    pub fn ipv4_only(self) -> Net {
        Net {
            ipv6: false,
            ..self
        }
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
        Net {
            resolver: Some(Arc::new(resolve)),
            ..self
        }
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
    /// `lan.drop` [repeats](fictionet::events#repeats), with the reason in `why`
    /// and the LAN name in `lan`.
    ///
    /// [`start`](Net::start) fails if `prefix` overlaps the sandboxes'
    /// subnets, the automatic address pools (`198.18.0.0/15` and
    /// `2001:2::/48`), or another LAN, or leaves no room for members.
    pub fn lan(mut self, name: &str, prefix: Prefix) -> Net {
        self.lans.push((name.to_owned(), prefix.canonical()));
        self
    }

    /// Attaches the sandbox called `name` to the LAN `lan` at `addr`, with
    /// no filter, no address binding and no DHCP: a trusted member, such
    /// as a GOAD virtual machine attached with `fictionet attach --type
    /// tap`. Events name it as a sandbox. [`start`](Net::start)
    /// fails if there is no such LAN, `addr` is not a member address of it,
    /// or another member has it.
    pub fn member(mut self, name: &str, lan: &str, addr: IpAddr) -> Net {
        self.members.push((name.to_owned(), lan.to_owned(), addr));
        self
    }

    /// Installs `registry` for observers when the network starts, so the
    /// dashboard decodes the services' protocols.
    pub fn observe(self, registry: fictionet::observe::Registry) -> Net {
        Net {
            registry: Some(registry),
            ..self
        }
    }

    /// Names the group observers see for the network's tasks.
    pub fn group(self, name: &str) -> Net {
        Net {
            group: name.to_owned(),
            ..self
        }
    }

    /// Sets the network's limits and timers.
    pub fn limits(self, limits: Limits) -> Net {
        Net { limits, ..self }
    }

    /// Builds the network and starts it. Every sandbox in `attachments`,
    /// including ones that attach later, is connected.
    ///
    /// Returns once every host is placed. The network runs in background
    /// tasks in `fcx`'s region until that region is cancelled. Fails if a
    /// subnet cannot be used, or a host cannot be served as declared.
    /// A rejected host leaves no installation behind. Earlier hosts and
    /// the network infrastructure remain until the region is cancelled.
    pub fn start(self, fcx: &Cx, mut attachments: Attachments) -> Result<(), Error> {
        let subnet = Subnet::new(self.subnet)?;
        let subnet6 = if self.ipv6 {
            Some(Subnet6::new(self.subnet_v6)?)
        } else {
            None
        };
        fcx.events().start(fcx, self.start);
        if let Some(registry) = self.registry {
            fcx.observe_protocols(registry);
        }
        let caller = fcx.clone();
        let fcx = &fcx.group(self.group.clone());
        let router = route::router::<Box<dyn Interface>>(fcx, Vec::new());
        // Every host is one hop from the sandbox: the router is private.
        router.keep_ttl();

        // Everything without a better route: answered with "host unreachable".
        let (router_side, unreachable_side) = link();
        router.add(
            Prefix {
                addr: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
            },
            Box::new(router_side),
        );
        let gateway = subnet.gateway;
        fcx.spawn(move |fcx| unreachable(fcx, unreachable_side, gateway.into()));
        if let Some(subnet6) = subnet6 {
            let (router_side, unreachable_side) = link();
            router.add(
                Prefix {
                    addr: Ipv6Addr::UNSPECIFIED.into(),
                    len: 0,
                },
                Box::new(router_side),
            );
            let gateway = subnet6.gateway;
            fcx.spawn(move |fcx| unreachable(fcx, unreachable_side, gateway.into()));
        }
        let hooks = Arc::new(Hooks {
            by_addr: Mutex::default(),
            conns: AtomicU64::new(0),
            attached: Mutex::default(),
        });
        let lans = make_lans(
            fcx,
            &router,
            &hooks,
            &subnet,
            subnet6.as_ref(),
            self.lans,
            &self.members,
        )?;
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
            peers: Peers::new(self.limits.connections_per_peer),
            limits: self.limits,
            lans,
        });
        start_gateway(&shared)?;
        {
            let mut world = shared.world.lock();
            for host in self.hosts {
                let names = host.names.clone();
                let label = host.label.clone();
                let placed = shared
                    .place(&mut world, host)
                    .map_err(|e| fictionet::Error::msg(format!("host {label}: {e}")))?;
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
                if let Some((name, lan, addr)) =
                    members.iter().find(|(n, _, _)| n == sandbox.name())
                {
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
        if let Some(s) = self.by_addr.lock().get(&addr) {
            return s.clone();
        }
        let (v4, v6) = match addr {
            IpAddr::V4(a) => (Some(a), None),
            IpAddr::V6(a) => (None, Some(a)),
        };
        Sandbox {
            id: 0,
            name: Arc::from(""),
            addr: v4,
            addr_v6: v6,
        }
    }

    fn is_attached(&self, id: u64) -> bool {
        self.attached.lock().contains_key(&id)
    }

    /// The budget of the sandbox with id `id`, while it is attached.
    fn budget(&self, id: u64) -> Option<Budget> {
        self.attached.lock().get(&id).cloned()
    }

    fn next_conn(&self) -> u64 {
        self.conns.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn sandbox_only(sandbox: Sandbox) -> ConnInfo {
    ConnInfo {
        sandbox: Some(sandbox),
        ..ConnInfo::default()
    }
}

/// Everything the tasks of one network share.
struct Shared {
    peers: Arc<Peers>,
    fcx: Cx,
    resolver: Option<Arc<Resolver>>,
    subnet: Subnet,
    subnet6: Option<Subnet6>,
    router: Router<Box<dyn Interface>>,
    world: Mutex<World>,
    leases: Mutex<Leases>,
    gateway_tcp: Mutex<Vec<tcp::Endpoint>>,
    hooks: Arc<Hooks>,
    /// Prefixes of trusted sandboxes ([`Net::route`]).
    fixed: Vec<Prefix>,
    limits: Limits,
    /// The LANs, by name.
    lans: BTreeMap<String, LanSeg>,
}

/// One LAN of the network ([`Net::lan`]).
struct LanSeg {
    prefix: Prefix,
    lan: route::Lan<Box<dyn Interface>>,
    /// Where its DNS answers: its first address.
    dns: IpAddr,
    /// Addresses members have, which hosts may not take.
    members: HashSet<IpAddr>,
}

/// Starts the network's LANs: each wired to the router through its
/// gateway, with its drops recorded. Checks them and their members.
fn make_lans(
    fcx: &Cx,
    router: &Router<Box<dyn Interface>>,
    hooks: &Arc<Hooks>,
    subnet: &Subnet,
    subnet6: Option<&Subnet6>,
    lans: Vec<(String, Prefix)>,
    members: &[(String, String, IpAddr)],
) -> Result<BTreeMap<String, LanSeg>, Error> {
    let mut made: BTreeMap<String, LanSeg> = BTreeMap::new();
    for (name, prefix) in lans {
        if prefix.overlaps(AUTO) || prefix.overlaps(AUTO6) {
            return Err(fictionet::Error::msg(format!(
                "LAN {name}: {}/{} overlaps the automatic address pool",
                prefix.addr, prefix.len
            )));
        }
        let max = if prefix.addr.is_ipv4() { 30 } else { 126 };
        if prefix.len > max {
            return Err(fictionet::Error::msg(format!(
                "LAN {name}: {}/{} leaves no room for members",
                prefix.addr, prefix.len
            )));
        }
        if prefix.overlaps(subnet.prefix) || subnet6.is_some_and(|s| prefix.overlaps(s.prefix)) {
            return Err(fictionet::Error::msg(format!(
                "LAN {name}: {}/{} overlaps the sandboxes' subnet",
                prefix.addr, prefix.len
            )));
        }
        if let Some((other, _)) = made
            .iter()
            .find(|(n, l)| **n == name || prefix.overlaps(l.prefix))
        {
            return Err(fictionet::Error::msg(format!(
                "LAN {name}: {}/{} overlaps LAN {other}",
                prefix.addr, prefix.len
            )));
        }
        let segment = name.clone();
        let names = hooks.clone();
        let lan = route::lan::<Box<dyn Interface>, _>(
            &fcx.group(format!("lan {name}")),
            prefix,
            move |mut event| {
                // A packet from the gateway has no member to name. Its source
                // passed a sandbox filter's address check, so the address
                // names the sandbox that sent it.
                if event.conn.sandbox.is_none() {
                    let src = event.str("src").and_then(|a| a.parse::<IpAddr>().ok());
                    event.conn.sandbox = src.and_then(|a| names.by_addr.lock().get(&a).cloned());
                }
                event.field("lan", segment.clone())
            },
        );
        let (lan_side, router_side) = link();
        lan.gateway(Box::new(lan_side))?;
        router.add(prefix, Box::new(router_side));
        let dns = prefix
            .nth(1)
            .ok_or_else(|| fictionet::Error::msg("a LAN has room for its DNS"))?;
        made.insert(
            name,
            LanSeg {
                prefix,
                lan,
                dns,
                members: HashSet::new(),
            },
        );
    }
    for (member, lan, addr) in members {
        let Some(seg) = made.get_mut(lan) else {
            return Err(fictionet::Error::msg(format!(
                "member {member}: there is no LAN called {lan}"
            )));
        };
        let broadcast = seg.prefix.broadcast().map(IpAddr::V4);
        if !seg.prefix.contains(*addr)
            || *addr == seg.prefix.addr
            || *addr == seg.dns
            || Some(*addr) == broadcast
        {
            return Err(fictionet::Error::msg(format!(
                "member {member}: {addr} is not a member address of LAN {lan}"
            )));
        }
        if !seg.members.insert(*addr) {
            return Err(fictionet::Error::msg(format!(
                "member {member}: another member of LAN {lan} has {addr}"
            )));
        }
    }
    Ok(made)
}

impl Shared {
    /// A member sandbox attached: it joins its LAN at its address, with no
    /// filter, and events know it by that address. It detaches as any
    /// sandbox does when the LAN lets its interface go: when it closes,
    /// when another takes its address, or when it could not join.
    fn join_lan(
        self: &Arc<Self>,
        fcx: &Cx,
        name: &str,
        lan: &str,
        addr: IpAddr,
        sandbox: Attachment,
    ) {
        let Some(seg) = self.lans.get(lan) else {
            return;
        };
        let attached = Arc::new(Attached::new(self, fcx, Arc::from(name), Some(addr)));
        let hooks = &self.hooks;
        let me = Sandbox {
            id: attached.owner,
            name: Arc::from(name),
            addr: if let IpAddr::V4(a) = addr {
                Some(a)
            } else {
                None
            },
            addr_v6: if let IpAddr::V6(a) = addr {
                Some(a)
            } else {
                None
            },
        };
        hooks.by_addr.lock().insert(addr, me.clone());
        let member = Member {
            sandbox,
            _attached: attached.clone(),
        };
        let joined = seg.lan.add(addr, Box::new(member), Some(me.clone()));
        let event = match joined {
            Ok(()) => Event::new("net", "attached")
                .summary(format!("sandbox {name} joined LAN {lan} at {addr}")),
            Err(e) => Event::new("net", "error")
                .level(Level::Notice)
                .summary(format!("sandbox {name} could not join LAN {lan}: {e}"))
                .field("error", e.to_string()),
        };
        hooks.record(
            fcx,
            &sandbox_only(me),
            event.field("lan", lan).field("addr", addr.to_string()),
        );
    }
}
/// The gateway, at its IPv4 address and, with IPv6, at its IPv6 address:
/// DNS over UDP and TCP on port 53, and ping replies. DHCP is answered in
/// each sandbox's filter, which knows which sandbox asked. LAN DNS
/// services start after these gateways, in ascending LAN name order.
fn start_gateway(shared: &Arc<Shared>) -> Result<(), Error> {
    let gateways = std::iter::once(IpAddr::V4(shared.subnet.gateway))
        .chain(shared.subnet6.map(|s| IpAddr::V6(s.gateway)));
    let fcx = &shared.fcx.group("gateway");
    for gateway in gateways {
        let (router_side, side) = link();
        shared
            .router
            .add(host_prefix(gateway), Box::new(router_side));
        start_dns(shared, fcx, side, gateway)?;
    }
    for seg in shared.lans.values() {
        let (lan_side, side) = link();
        seg.lan.add(seg.dns, Box::new(lan_side), None)?;
        start_dns(shared, &shared.fcx.group("lan gateway"), side, seg.dns)?;
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
    shared.gateway_tcp.lock().push(tcp);
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
        Answered {
            reply: None,
            name: None,
            qtype: None,
            answer: DnsAnswer::None,
        }
    }

    fn event(&self, tcp: bool) -> Event {
        let answer = if self.reply.is_some() {
            self.answer.clone()
        } else {
            DnsAnswer::None
        };
        let (kind, addr, rcode) = match &answer {
            DnsAnswer::Addr(a) => ("addr", Some(a.to_string()), None),
            DnsAnswer::NoData => ("nodata", None, None),
            DnsAnswer::NxDomain => ("nxdomain", None, None),
            DnsAnswer::Error(code) => ("error", None, Some(u32::from(*code))),
            DnsAnswer::None => ("none", None, None),
        };
        Event::new("dns", "query")
            .summary(format!(
                "{} {}: {}",
                self.name.as_deref().unwrap_or("-"),
                self.qtype.unwrap_or(0),
                addr.as_deref().unwrap_or(kind)
            ))
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
            let reply = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr)
                .to_vec()
                .ok();
            return Answered {
                reply,
                name: None,
                qtype: None,
                answer: DnsAnswer::Error(1),
            };
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
        let found = if name.is_empty() {
            Lookup::NoHost
        } else {
            shared.lookup(name)
        };
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
                        reply
                            .answers
                            .push(Record::from_rdata(q.name().clone(), TTL, rdata));
                    }
                    None => event_answer = DnsAnswer::NoData,
                }
            }
        }
    }
    let qtype = if name.is_some() { qtype } else { None };
    Answered {
        reply: reply.to_vec().ok(),
        name,
        qtype,
        answer: event_answer,
    }
}

/// Framing for a DNS query over UDP or TCP.
struct DnsQueries {
    tcp: bool,
    datagram: Collect<Vec<u8>, true>,
}

impl Decode for DnsQueries {
    type Item = Vec<u8>;
    type Error = CollectError<core::convert::Infallible>;
    const NAME: &'static str = "DNS query";

    fn capacity(&self) -> usize {
        65537
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Vec<u8>>, Self::Error> {
        if !self.tcp {
            return self.datagram.decode(input, eof);
        }
        let Some(prefix) = input.get(..2) else {
            return Ok(Step::Need);
        };
        let end = 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        Ok(match input.get(2..end) {
            Some(query) => Step::Item(query.to_vec(), end),
            None => Step::Need,
        })
    }
}

struct Dns {
    tcp: bool,
}

impl Service for Dns {
    type Decoder = DnsQueries;
    type State = Arc<Shared>;
    type Error = core::convert::Infallible;

    fn decoder(&self) -> DnsQueries {
        DnsQueries {
            tcp: self.tcp,
            datagram: Collect::bytes(65535),
        }
    }

    fn on_open(
        &mut self,
        shared: &Arc<Shared>,
        driver: &mut serve::Driver<'_, DnsQueries>,
    ) -> Result<serve::Flow, Self::Error> {
        if self.tcp {
            driver.set_timer("query", shared.limits.dns_tcp_idle);
        }
        Ok(serve::Flow::Continue)
    }

    fn on_item(
        &mut self,
        query: Vec<u8>,
        shared: &Arc<Shared>,
        driver: &mut serve::Driver<'_, DnsQueries>,
    ) -> Result<serve::Flow, Self::Error> {
        let answered = answer(shared, &query);
        driver.record(answered.event(self.tcp));
        if let Some(reply) = answered.reply {
            if self.tcp {
                if let Ok(n) = u16::try_from(reply.len()) {
                    driver.reply().extend_from_slice(&n.to_be_bytes());
                    driver.reply().extend_from_slice(&reply);
                }
            } else {
                driver.reply().extend_from_slice(&reply);
            }
        }
        self.on_open(shared, driver)
    }

    fn on_timer(
        &mut self,
        _: serve::Timer,
        _: &Arc<Shared>,
        _: &mut serve::Driver<'_, DnsQueries>,
    ) -> Result<serve::Flow, Self::Error> {
        Ok(serve::Flow::Close)
    }
}

/// DNS over UDP on the gateway's port 53.
async fn dns_udp(fcx: Cx, socket: udp::Socket, shared: Arc<Shared>) -> fictionet::Result {
    let local = socket.local_addr();
    let hooks = shared.hooks.clone();
    let opts = ServeOptions {
        sandbox: Some(Arc::new(move |addr| Some(hooks.sandbox_at(addr)))),
        ..ServeOptions::default()
    };
    let _ = serve::datagram(&fcx, socket, local, &mut Dns { tcp: false }, &shared, &opts).await;
    Ok(())
}

/// DNS over TCP on the gateway's port 53.
async fn dns_tcp(fcx: Cx, mut listener: tcp::Listener, shared: Arc<Shared>) -> fictionet::Result {
    let peers = shared.peers.clone();
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

async fn dns_conn(
    fcx: &Cx,
    conn: tcp::TcpConnection,
    shared: &Arc<Shared>,
) -> Result<(), ConnError> {
    let info = ConnInfo {
        sandbox: Some(shared.hooks.sandbox_at(conn.peer_addr().ip())),
        peer: Some(conn.peer_addr()),
        local: Some(conn.local_addr()),
        ..ConnInfo::default()
    };
    let opts = ServeOptions {
        idle: None,
        connection_events: false,
        budget: info
            .sandbox
            .as_ref()
            .and_then(|sandbox| shared.hooks.budget(sandbox.id)),
        ..ServeOptions::default()
    };
    let _ = serve::connection(fcx, conn, info, &mut Dns { tcp: true }, shared, &opts).await;
    Ok(())
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

/// A UDP packet with correct checksums.
fn udp_packet(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, data: &[u8]) -> Packet {
    let len = udp::encoded_len(src.into(), dst.into(), data.len())
        .expect("a DHCP reply fits one IPv4 packet");
    let mut u = vec![0; len];
    udp::encode(
        SocketAddr::new(src.into(), sport),
        SocketAddr::new(dst.into(), dport),
        data,
        &mut u,
    )
    .expect("a checked UDP length fits");
    ip::packet(src.into(), dst.into(), PROTO_UDP, &u)
}

/// If `packet` (with header `h`) is for the DHCP server (UDP port 67 at the
/// broadcast address or the gateway), its message, or `Some(None)` if
/// its UDP envelope or message is invalid. `None` for every other packet.
fn to_dhcp_server(packet: &[u8], h: &Header, gateway: Ipv4Addr) -> Option<Option<dhcp::Message>> {
    if h.protocol != PROTO_UDP || h.fragment.is_some() {
        return None;
    }
    let dst = h.dst;
    if dst != IpAddr::V4(Ipv4Addr::BROADCAST) && dst != IpAddr::V4(gateway) {
        return None;
    }
    let u = h.payload(packet);
    if u.len() < 4 || u16::from_be_bytes([u[2], u[3]]) != dhcp::SERVER_PORT {
        return None;
    }
    let Some(u) = udp::Datagram::parse(u) else {
        return Some(None);
    };
    if !u.checksum_ok(h.src, h.dst) {
        return Some(None);
    }
    Some(dhcp::Message::parse(u.payload()).ok())
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
        let owner = shared.leases.lock().new_owner();
        shared
            .hooks
            .attached
            .lock()
            .insert(owner, Budget::new(shared.limits.sandbox_budget));
        Attached {
            shared: shared.clone(),
            owner,
            fcx: fcx.clone(),
            name,
            fixed,
        }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        let shared = &self.shared;
        shared.hooks.attached.lock().remove(&self.owner);
        let (bound, bound6) = match self.fixed {
            Some(IpAddr::V4(a)) => (Some(a), None),
            Some(IpAddr::V6(a)) => (None, Some(a)),
            None => {
                let leases = shared.leases.lock();
                let v4 = leases
                    .of(self.owner)
                    .and_then(|(a, bound)| bound.then_some(a));
                (v4, leases.by_owner6.get(&self.owner).copied())
            }
        };
        let addrs: Vec<IpAddr> = bound
            .map(IpAddr::V4)
            .into_iter()
            .chain(bound6.map(IpAddr::V6))
            .collect();
        if !addrs.is_empty() {
            let machines: Vec<Arc<Machine>> =
                shared.world.lock().machines.values().cloned().collect();
            for m in machines {
                for a in &addrs {
                    m.tcp.abort_peer(*a);
                }
            }
            for tcp in shared.gateway_tcp.lock().iter() {
                for a in &addrs {
                    tcp.abort_peer(*a);
                }
            }
        }
        shared.leases.lock().release_all(self.owner);
        let sandbox = Sandbox {
            id: self.owner,
            name: self.name.clone(),
            addr: bound,
            addr_v6: bound6,
        };
        let event =
            Event::new("net", "detached").summary(format!("sandbox {} detached", self.name));
        shared
            .hooks
            .record(&self.fcx, &sandbox_only(sandbox), event);
    }
}

/// A LAN member's attachment, which holds its [`Attached`]: the member
/// detaches when the LAN drops this.
struct Member {
    sandbox: Attachment,
    _attached: Arc<Attached>,
}

impl Interface for Member {
    fn poll_recv(
        &mut self,
        fcx: &Cx,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Packet, fictionet::RecvError>> {
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
            ports::Event::Packet(0, packet) => match ip::version(&packet.0) {
                Some(6) => f.sent_v6(&fcx, packet),
                _ => f.sent_v4(&fcx, packet),
            },
            ports::Event::Packet(_, packet) => f.ports.send(0, packet),
            ports::Event::Closed(_) => return Ok(()),
            ports::Event::Timer => f.reassembly.expire(fcx.now()),
            ports::Event::Extra => {}
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
    /// A new TCP connection past the network's limit per peer address, or past
    /// a service's cap. Reset.
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

/// Counts an accepted connection or records why the connection limit refused it.
pub fn connection_limit(
    fcx: &Cx,
    info: &ConnInfo,
    open: &Arc<AtomicUsize>,
    max: usize,
) -> Option<Counted> {
    let guard = Counted::enter(open, max);
    if guard.is_none() {
        let (src, dst) = (info.peer, info.local);
        let event = blocked_event(
            BlockedWhy::TooManyConnections,
            Some(PROTO_TCP),
            src.map(|a| a.ip()),
            dst.map(|a| a.ip()),
        );
        let conn = ConnInfo {
            sandbox: info.sandbox.clone(),
            ..ConnInfo::default()
        };
        fcx.record_repeat(event.conn(&conn), port_detail(dst.map(|a| a.port())));
    }
    guard
}

/// A `net.blocked` event. The destination port goes in its detail
/// ([`port_detail`]), since a scan changes it with every packet.
fn blocked_event(
    why: BlockedWhy,
    protocol: Option<u8>,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
) -> Event {
    Event::new("net", "blocked")
        .level(Level::Notice)
        .summary(format!(
            "blocked {}: {} -> {}",
            why.as_str(),
            src.map_or("-".into(), |a| a.to_string()),
            dst.map_or("-".into(), |a| a.to_string())
        ))
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
        Some(h) => (
            blocked_event(why, Some(h.protocol), Some(h.src), Some(h.dst)),
            port_detail(h.dst_port(p)),
        ),
        None => (blocked_event(why, None, None, None), port_detail(None)),
    }
}

struct Filter {
    shared: Arc<Shared>,
    owner: u64,
    name: Arc<str>,
    ports: Ports<Box<dyn Interface>>,
    bound: Option<Ipv4Addr>,
    bound6: Option<Ipv6Addr>,
    route4: Option<usize>,
    route6: Option<usize>,
    reassembly: Reassembly,
}

impl Filter {
    fn me(&self) -> Sandbox {
        Sandbox {
            id: self.owner,
            name: self.name.clone(),
            addr: self.bound,
            addr_v6: self.bound6,
        }
    }

    fn block(&self, fcx: &Cx, why: BlockedWhy, packet: &[u8]) {
        self.shared
            .hooks
            .blocked(fcx, &sandbox_only(self.me()), blocked(why, packet));
    }

    fn bound_now(&mut self, fcx: &Cx, addr: IpAddr, by_dhcp: bool) {
        let (router_side, mine) = link();
        self.shared
            .router
            .add(host_prefix(addr), Box::new(router_side));
        let port = self.ports.add(Box::new(mine));
        match addr {
            IpAddr::V4(a) => (self.bound, self.route4) = (Some(a), Some(port)),
            IpAddr::V6(a) => (self.bound6, self.route6) = (Some(a), Some(port)),
        }
        let sandbox = self.me();
        let mut by_addr = self.shared.hooks.by_addr.lock();
        for a in self
            .bound
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.bound6.map(IpAddr::V6))
        {
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
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (h.src, h.dst) else {
            return;
        };
        if let Some(message) = to_dhcp_server(&packet.0, &h, gateway) {
            let Some(message) = message else { return };
            let inform_first = self.bound.is_none()
                && message.message_type() == Some(dhcp::INFORM)
                && shared.may_bind(self.owner, src);
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
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (h.src, h.dst) else {
            return;
        };
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
        let Some(dst) = ip::destination(p) else {
            return false;
        };
        self.is_gateway(dst) || self.world.lock().machines.contains_key(&dst)
    }

    /// Why the network will refuse `p`: no machine has its address, or its
    /// port is not served there. `None` if it will be delivered.
    fn refused(&self, p: &[u8]) -> Option<BlockedWhy> {
        let dst = ip::destination(p)?;
        let closed = |open: &dyn Fn(u8, u16) -> bool| answered_closed(p, open);
        if self.is_gateway(dst) {
            return closed(&|_, p| p == 53).then_some(BlockedWhy::ClosedPort);
        }
        let machine = self.world.lock().machines.get(&dst).cloned();
        match machine {
            Some(m) => closed(&|proto, p| {
                if proto == PROTO_TCP {
                    m.serves_tcp(p)
                } else {
                    m.serves_udp(p)
                }
            })
            .then_some(BlockedWhy::ClosedPort),
            // A trusted sandbox's prefix, or a LAN, which reports its own
            // drops.
            None if self
                .fixed
                .iter()
                .chain(self.lans.values().map(|l| &l.prefix))
                .any(|p| p.contains(dst)) =>
            {
                None
            }
            None => Some(BlockedWhy::NoRoute),
        }
    }
}

/// Whether `p`, a whole TCP or UDP packet, is for a port that `open` says
/// is closed, and will be answered as such: it is not a TCP RST, and its
/// checksum is good. The port is looked up first, so only a packet for a
/// closed port has its checksum checked.
fn answered_closed(p: &[u8], open: impl Fn(u8, u16) -> bool) -> bool {
    let Some(h) = Header::parse_whole(p) else {
        return false;
    };
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
        PROTO_UDP => udp::Datagram::parse(t).is_some_and(|u| u.checksum_ok(h.src, h.dst)),
        _ => ip::transport_checksum(h.src, h.dst, h.protocol, t) == 0,
    }
}

fictionet::cfg_std! {
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_dns_endpoints_start_in_name_order() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let subnet = Subnet::new("198.18.0.0/16".parse().unwrap()).unwrap();
                let router = route::router::<Box<dyn Interface>>(&fcx, Vec::new());
                let hooks = Arc::new(Hooks {
                    by_addr: Mutex::default(),
                    conns: AtomicU64::new(0),
                    attached: Mutex::default(),
                });
                let lans = make_lans(
                    &fcx,
                    &router,
                    &hooks,
                    &subnet,
                    None,
                    [
                        ("z", "10.0.1.0/24"),
                        ("a", "10.0.3.0/24"),
                        ("m", "10.0.2.0/24"),
                    ]
                    .map(|(name, prefix)| (name.to_owned(), prefix.parse().unwrap()))
                    .into(),
                    &[],
                )?;
                let shared = Arc::new(Shared {
                    fcx: fcx.clone(),
                    resolver: None,
                    subnet,
                    subnet6: None,
                    router,
                    world: Mutex::new(World::new(MAX_HOSTS)),
                    leases: Mutex::default(),
                    gateway_tcp: Mutex::default(),
                    hooks,
                    fixed: Vec::new(),
                    peers: Peers::new(Limits::default().connections_per_peer),
                    limits: Limits::default(),
                    lans,
                });
                start_gateway(&shared)?;
                let addresses: Vec<_> = shared
                    .gateway_tcp
                    .lock()
                    .iter()
                    .map(tcp::Endpoint::addr)
                    .collect();
                assert_eq!(
                    addresses,
                    ["198.18.0.1", "10.0.3.1", "10.0.2.1", "10.0.1.1"]
                        .map(|s| s.parse::<IpAddr>().unwrap())
                );
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
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
        assert_eq!(
            looked.load(Ordering::Relaxed),
            1,
            "the port of a packet with a bad checksum is looked up"
        );
        assert!(!answered_closed(&good, open(true)));
        assert!(answered_closed(&good, open(false)));
        assert!(
            !answered_closed(&bad, open(false)),
            "a bad checksum to a closed port is dropped, not answered"
        );
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
    fn closed_udp_ports_use_the_declared_datagram_boundary() {
        for (src, dst) in [
            ("10.0.0.2", "10.40.0.1"),
            ("2001:db8::2", "2001:2::1"),
        ] {
            let src: IpAddr = src.parse().unwrap();
            let dst: IpAddr = dst.parse().unwrap();
            let packet = |u: &[u8]| ip::packet(src, dst, PROTO_UDP, u).0;
            let mut u = [0; 10];
            udp::encode(SocketAddr::new(src, 5000), SocketAddr::new(dst, 9), b"hi", &mut u)
                .unwrap();
            let mut trailing = u.to_vec();
            trailing.extend_from_slice(b"outside UDP");
            assert!(answered_closed(&packet(&trailing), |_, _| false));
            assert!(!answered_closed(&packet(&trailing), |_, _| true));
            // A checksum over the entire IP payload does not validate the
            // datagram whose UDP length ends before that payload does.
            trailing[6..8].fill(0);
            let sum = ip::transport_checksum(src, dst, PROTO_UDP, &trailing);
            trailing[6..8].copy_from_slice(&sum.to_be_bytes());
            assert!(!answered_closed(&packet(&trailing), |_, _| false));
            for len in [0u16, 7, 11, u16::MAX] {
                let mut bad = u;
                bad[4..6].copy_from_slice(&len.to_be_bytes());
                bad[6..8].fill(0);
                if src.is_ipv4() {
                    assert!(!answered_closed(&packet(&bad), |_, _| false));
                }
                let sum = ip::transport_checksum(src, dst, PROTO_UDP, &bad);
                bad[6..8].copy_from_slice(&sum.to_be_bytes());
                assert!(!answered_closed(&packet(&bad), |_, _| false));
            }
        }
    }

}

}
