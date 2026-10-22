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
//! services. Each world reports its own typed observations from its services.
//!
//! An office: a domain controller that answers LDAP and Kerberos, a web
//! server, and a PLC, with DNS names for each:
//!
//! ```
//! # fictionet::cfg_std! {
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::{web::httpd, world::net::{Host, Net}, services::serve};
//! # struct Ldap; struct Plc; struct Directory; struct Plant;
//! # macro_rules! svc { ($t:ty, $w:ty) => {
//! # impl serve::Service for $t {
//!     type Timer = ();
//! #     type Decoder = fictionet::stdlib::codec::Lines; type State = $w; type Error = std::convert::Infallible;
//! #     fn decoder(&self) -> Self::Decoder { fictionet::stdlib::codec::Lines::new(64, fictionet::stdlib::codec::Ending::LfOrCrlf) }
//! #     fn on_item(&mut self, _: Result<Vec<u8>, fictionet::stdlib::codec::LineError>, _: &$w, _: &mut serve::Driver<'_, Self::Decoder, Self::Timer>) -> std::result::Result<serve::Flow, Self::Error> { Ok(serve::Flow::Continue) }
//! # } } }
//! # svc!(Ldap, Directory); svc!(Plc, Plant);
//! # async fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let directory = Arc::new(Directory);
//! let plant = Arc::new(Plant);
//! let intranet = httpd::tower(axum::Router::new().route("/", axum::routing::get(|| async { "intranet\n" })));
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
//!   it gets a free one from `104.18.0.0/15` (IPv4) and `2606:4700:100::/48`
//!   (IPv6). Hosts with the same address share one machine.
//! - **A router** with one route per machine. A packet for any other address
//!   gets ICMP "host unreachable" (ICMPv6 "address unreachable"). The router is
//!   private
//!   ([`Router::keep_ttl`](fictionet::stdlib::network::route::Router::keep_ttl)):
//!   it leaves TTLs as they are, so every machine is one hop from the sandbox.
//! - **LANs.** [`Net::lan`] adds an IP subnet that hosts join with
//!   [`Host::on`] and attached virtual machines with [`Net::member`], as
//!   machines on one Ethernet: broadcast and multicast reach every member.
//!   The router sends the LAN's prefix to its gateway, the LAN's first
//!   address answers DNS.
//! - **Machines** answer pings, reset TCP to closed ports and answer UDP to
//!   closed ports with "port unreachable". UDP delivery and closed-port
//!   replies use the declared UDP length. Invalid lengths are dropped;
//!   trailing IP payload bytes are ignored when checking the checksum.
//!   A peer address may have 256 connections open at once across the
//!   network ([`Limits::connections_per_peer`]); past that, new ones are
//!   reset. Each service has its own cap too ([`ServeOptions::max_conns`]).
//! - **Budgets.** Service-layer holdings for one sandbox are charged to
//!   that sandbox's [`Budget`], 256 MiB unless [`Limits::sandbox_budget`]
//!   says otherwise. A connection that would pass it is closed. The service
//!   driver charges its buffers and what the service reports holding, and
//!   HTTP/2 charges retained request heads and bodies (see [`httpd`]).
//!   A [`PortServer`] of your own charges what it chooses. A sandbox has one
//!   budget for both its addresses, from when it attaches until it
//!   detaches. A trusted sandbox ([`Net::route`]) has none.
//! - **Every link** inside the network holds at most 4 MiB of packets each
//!   way; past that, packets are dropped, as on a congested link.
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
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use fictionet::stdlib::network::route::{self, Prefix, Router};
use fictionet::stdlib::network::{icmp, tcp};
#[cfg(doc)]
use fictionet::stdlib::services::serve::{Budget, ServeOptions, Service};
use fictionet::{Attachments, Cx, End, Error, Interface, InterfaceExt};

fictionet::cfg_std! {
#[cfg(doc)]
use fictionet::stdlib::web::httpd;
}

mod addresses;
mod attachments;
mod dns;
mod hosts;
mod names;

use addresses::{AUTO, AUTO6, Leases, Subnet, Subnet6};
pub use attachments::connection_limit;
use attachments::{Hooks, filter, udp_packet};
use dns::start_dns;
use hosts::{
    Admission, Installation, Known, Lookup, LookupContext, Machines, Peers, World, host_prefix,
};
pub use hosts::{Arrival, ConfigFor, Host, PortServer, PreparedShare, Sni};
pub use names::normalize;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// Each link inside the network holds at most this many bytes of packets
/// each way.
const LINK_QUEUE: usize = 4 << 20;

/// How many names may have a host made by [`Net::resolve`], unless the
/// world sets another limit.
pub const MAX_HOSTS: usize = 20_000;

fn link() -> (End, End) {
    fictionet::pair_with_limit(LINK_QUEUE)
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

/// A LAN definition shared by a network, its hosts and attached members.
///
/// ```
/// use fictionet::stdlib::world::net::{Lan, Net};
/// let office = Lan::new("office", "192.168.56.0/24".parse()?);
/// let net = Net::new().lan(&office)
///     .host("directory", |host| host.on(&office))
///     .member("workstation", &office, "192.168.56.20".parse()?);
/// # Ok::<(), fictionet::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Lan {
    name: String,
    prefix: Prefix,
}

impl Lan {
    /// Defines a named IP subnet. Add it to a network with [`Net::lan`].
    pub fn new(name: &str, prefix: Prefix) -> Self {
        Self {
            name: name.to_owned(),
            prefix: prefix.canonical(),
        }
    }
}

/// A network of hosts and services, and the sandboxes' side of it. See the
/// [module docs](self).
pub struct Net {
    subnet: Prefix,
    subnet_v6: Prefix,
    ipv6: bool,
    hosts: Vec<Host>,
    resolver: Option<Arc<Resolver>>,
    unreachable: Option<Arc<dyn Fn(Unreachable) + Send + Sync>>,
    max_hosts: usize,
    routes: Vec<(String, Prefix)>,
    limits: Limits,
    lans: Vec<Lan>,
    members: Vec<(String, Lan, IpAddr)>,
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
            unreachable: None,
            max_hosts: MAX_HOSTS,
            routes: Vec::new(),
            limits: Limits::default(),
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
    /// that cannot be served gets NXDOMAIN.
    pub fn resolve(self, resolve: impl Fn(&str) -> Option<Host> + Send + Sync + 'static) -> Net {
        Net {
            resolver: Some(Arc::new(resolve)),
            ..self
        }
    }

    /// Calls `report` when a packet has no route in this network.
    pub fn on_unreachable(mut self, report: impl Fn(Unreachable) + Send + Sync + 'static) -> Self {
        self.unreachable = Some(Arc::new(report));
        self
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
    /// Events attribute source addresses in `prefix` to this sandbox.
    pub fn route(mut self, name: &str, prefix: Prefix) -> Net {
        self.routes.push((name.to_owned(), prefix));
        self
    }

    /// Adds an IP LAN ([`route::lan`]). Hosts
    /// placed on it with [`Host::on`] and sandboxes attached to it with
    /// [`Net::member`] share the subnet as machines on one Ethernet do,
    /// broadcast and multicast included. The router sends `prefix` to the
    /// LAN's gateway, so sandboxes and the other hosts reach its members,
    /// and members reach everything else through it. The LAN's first
    /// address (`.1` of a `/24`) answers DNS as the network's gateway does,
    /// for members to use.
    ///
    /// [`start`](Net::start) fails if the LAN prefix overlaps the sandboxes'
    /// subnets, the automatic address pools (`104.18.0.0/15` and
    /// `2606:4700:100::/48`), or another LAN, or leaves no room for members.
    pub fn lan(mut self, lan: &Lan) -> Net {
        self.lans.push(lan.clone());
        self
    }

    /// Attaches the sandbox called `name` to the LAN `lan` at `addr`, with
    /// no filter, no address binding and no DHCP: a trusted member, such
    /// as a GOAD virtual machine attached with `fictionet attach tap`. Events name it as a sandbox. [`start`](Net::start)
    /// fails if there is no such LAN, `addr` is not a member address of it,
    /// or another member has it.
    pub fn member(mut self, name: &str, lan: &Lan, addr: IpAddr) -> Net {
        self.members.push((name.to_owned(), lan.clone(), addr));
        self
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
        let caller = fcx.clone();
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
        let report = self.unreachable.clone();
        fcx.spawn(move |fcx| unreachable(fcx, unreachable_side, gateway.into(), report));
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
            let report = self.unreachable.clone();
            fcx.spawn(move |fcx| unreachable(fcx, unreachable_side, gateway.into(), report));
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
            world: Arc::new(Mutex::new(World::new(self.max_hosts))),
            leases: Arc::new(Mutex::new(Leases::default())),
            gateway_tcp: Arc::new(Mutex::new(Vec::new())),
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
                    .installation()
                    .place(&mut world, host)
                    .map_err(|e| fictionet::Error::msg(format!("host {label}: {e}")))?;
                for name in names {
                    world.names.insert(name, Known::Host(placed));
                }
            }
        }

        let members = self.members;
        let context = shared.attachments();
        caller.spawn(move |fcx| async move {
            loop {
                let sandbox = attachments.next(&fcx).await?;
                if let Some((_, prefix)) = routes.iter().find(|(n, _)| n == sandbox.name()) {
                    shared
                        .router
                        .add(*prefix, Box::new(context.routed(sandbox, *prefix)));
                    continue;
                }
                if let Some((name, lan, addr)) =
                    members.iter().find(|(n, _, _)| n == sandbox.name())
                {
                    if let Some(seg) = shared.lans.get(&lan.name) {
                        context.join_lan(&fcx, name, &lan.name, &seg.lan, *addr, sandbox);
                    }
                    continue;
                }
                let context = context.clone();
                fcx.spawn(move |fcx| filter(fcx, sandbox, context));
            }
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// What the network's tasks share

/// Network state assembled into capability contexts for its subsystems.
struct Shared {
    peers: Arc<Peers>,
    fcx: Cx,
    resolver: Option<Arc<Resolver>>,
    subnet: Subnet,
    subnet6: Option<Subnet6>,
    router: Router<Box<dyn Interface>>,
    world: Arc<Mutex<World>>,
    leases: Arc<Mutex<Leases>>,
    gateway_tcp: Arc<Mutex<Vec<tcp::Endpoint>>>,
    hooks: Arc<Hooks>,
    /// Prefixes of trusted sandboxes ([`Net::route`]).
    fixed: Vec<Prefix>,
    limits: Limits,
    /// The LANs, by name.
    lans: BTreeMap<String, LanSeg>,
}

impl Shared {
    fn admission(&self) -> Admission {
        Admission {
            peers: self.peers.clone(),
            hooks: self.hooks.clone(),
        }
    }

    fn installation(&self) -> Installation<'_> {
        Installation {
            fcx: &self.fcx,
            subnet: self.subnet,
            subnet6: self.subnet6,
            router: &self.router,
            lans: &self.lans,
            admission: self.admission(),
            handshake: self.limits.handshake,
        }
    }

    fn lookup(&self, name: &str) -> Lookup {
        LookupContext {
            world: &self.world,
            resolver: self.resolver.as_deref(),
            installation: self.installation(),
        }
        .lookup(name)
    }

    fn dns(self: &Arc<Self>) -> dns::Context {
        let shared = self.clone();
        dns::Context {
            state: dns::State {
                lookup: Arc::new(move |name| shared.lookup(name)),
                tcp_idle: self.limits.dns_tcp_idle,
            },
            admission: self.admission(),
        }
    }

    fn attachments(&self) -> Arc<attachments::Context> {
        let machines = Machines::new(self.world.clone());
        let abort = machines.clone();
        let gateway_tcp = self.gateway_tcp.clone();
        Arc::new(attachments::Context {
            bindings: addresses::Bindings::new(self.subnet, self.subnet6, self.leases.clone()),
            hooks: self.hooks.clone(),
            sandbox_budget: self.limits.sandbox_budget,
            router: self.router.clone(),
            destinations: attachments::Destinations {
                gateways: std::iter::once(IpAddr::V4(self.subnet.gateway))
                    .chain(self.subnet6.map(|s| IpAddr::V6(s.gateway)))
                    .chain(self.lans.values().map(|l| l.dns))
                    .collect(),
                trusted: self
                    .fixed
                    .iter()
                    .copied()
                    .chain(self.lans.values().map(|l| l.prefix))
                    .collect(),
                machines,
            },
            abort_peers: Arc::new(move |addrs| {
                abort.abort_peers(addrs);
                for tcp in gateway_tcp.lock().iter() {
                    for addr in addrs {
                        tcp.abort_peer(*addr);
                    }
                }
            }),
        })
    }
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
    _hooks: &Arc<Hooks>,
    subnet: &Subnet,
    subnet6: Option<&Subnet6>,
    lans: Vec<Lan>,
    members: &[(String, Lan, IpAddr)],
) -> Result<BTreeMap<String, LanSeg>, Error> {
    let mut made: BTreeMap<String, LanSeg> = BTreeMap::new();
    for Lan { name, prefix } in lans {
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
        let lan = route::lan::<Box<dyn Interface>>(fcx, prefix);
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
        let name = &lan.name;
        let Some(seg) = made
            .get_mut(&lan.name)
            .filter(|seg| seg.prefix == lan.prefix)
        else {
            return Err(fictionet::Error::msg(format!(
                "member {member}: LAN {name} is not configured in this network"
            )));
        };
        let broadcast = seg.prefix.broadcast().map(IpAddr::V4);
        if !seg.prefix.contains(*addr)
            || *addr == seg.prefix.addr
            || *addr == seg.dns
            || Some(*addr) == broadcast
        {
            return Err(fictionet::Error::msg(format!(
                "member {member}: {addr} is not a member address of LAN {name}"
            )));
        }
        if !seg.members.insert(*addr) {
            return Err(fictionet::Error::msg(format!(
                "member {member}: another member of LAN {name} has {addr}"
            )));
        }
    }
    Ok(made)
}

/// The gateway, at its IPv4 address and, with IPv6, at its IPv6 address:
/// DNS over UDP and TCP on port 53, and ping replies. DHCP is answered in
/// each sandbox's filter, which knows which sandbox asked. LAN DNS
/// services start after these gateways, in ascending LAN name order.
fn start_gateway(shared: &Arc<Shared>) -> Result<(), Error> {
    let gateways = std::iter::once(IpAddr::V4(shared.subnet.gateway))
        .chain(shared.subnet6.map(|s| IpAddr::V6(s.gateway)));
    let fcx = &shared.fcx.clone();
    for gateway in gateways {
        let (router_side, side) = link();
        shared
            .router
            .add(host_prefix(gateway), Box::new(router_side));
        let tcp = start_dns(shared.dns(), fcx, side, gateway)?;
        shared.gateway_tcp.lock().push(tcp);
    }
    for seg in shared.lans.values() {
        let (lan_side, side) = link();
        seg.lan.add(seg.dns, Box::new(lan_side))?;
        let tcp = start_dns(shared.dns(), &shared.fcx.clone(), side, seg.dns)?;
        shared.gateway_tcp.lock().push(tcp);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ICMP "host unreachable"

/// A packet whose destination has no route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unreachable {
    /// Source address of the packet.
    pub from: IpAddr,
    /// Destination address of the packet.
    pub to: IpAddr,
}

/// Answers with ICMP from the gateway's address of the same family.
async fn unreachable(
    fcx: Cx,
    mut end: End,
    gateway: IpAddr,
    report: Option<Arc<dyn Fn(Unreachable) + Send + Sync>>,
) -> fictionet::Result {
    let mut run = 0;
    while let Ok(packet) = end.recv(&fcx).await {
        if let Some(report) = &report
            && let Some(header) = crate::stdlib::network::ip::Header::parse(&packet.0)
        {
            report(Unreachable {
                from: header.src,
                to: header.dst,
            });
        }
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

fictionet::cfg_std! {
#[cfg(test)]
mod tests {
    use super::*;
    use super::attachments::answered_closed;
    use fictionet::stdlib::network::{ip, udp};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn lan_dns_endpoints_start_in_name_order() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let subnet = Subnet::new("104.18.0.0/16".parse().unwrap()).unwrap();
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
                    .map(|(name, prefix)| Lan::new(name, prefix.parse().unwrap()))
                    .into(),
                    &[],
                )?;
                let shared = Arc::new(Shared {
                    fcx: fcx.clone(),
                    resolver: None,
                    subnet,
                    subnet6: None,
                    router,
                    world: Arc::new(Mutex::new(World::new(MAX_HOSTS))),
                    leases: Arc::default(),
                    gateway_tcp: Arc::default(),
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
                    ["104.18.0.1", "10.0.3.1", "10.0.2.1", "10.0.1.1"]
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
            ("2001:db8::2", "2606:4700:100::1"),
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

#[cfg(test)]
mod unreachable_tests {
    use super::*;
    use crate::stdlib::network::ip;

    #[test]
    fn a_world_can_report_missing_routes_without_changing_icmp_replies() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let facts = Arc::new(Mutex::new(Vec::new()));
                let recorded = facts.clone();
                let (attacher, attachments) = fictionet::attachments();
                Net::new()
                    .on_unreachable(move |fact| recorded.lock().push(fact))
                    .start(&cx, attachments)?;
                let mut guest = attacher.attach("guest")?;
                let routes = [
                    ("10.0.0.2", "203.0.113.9", "10.0.0.1"),
                    ("2001:db8::2", "2001:db8:99::9", "2001:db8::1"),
                ];
                for (from, to, gateway) in routes {
                    let from: IpAddr = from.parse()?;
                    let to: IpAddr = to.parse()?;
                    guest.send(ip::packet(from, to, 253, &[1, 2, 3]));
                    let reply = guest.recv(&cx).await?;
                    let header = ip::Header::parse(&reply.0).unwrap();
                    assert_eq!(header.src, gateway.parse::<IpAddr>()?);
                    assert_eq!(header.dst, from);
                    let payload = header.payload(&reply.0);
                    assert_eq!(
                        &payload[..2],
                        if from.is_ipv4() { &[3, 1] } else { &[1, 3] }
                    );
                    assert_eq!(facts.lock().last(), Some(&Unreachable { from, to }));
                }
                assert_eq!(facts.lock().len(), 2);
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
}
