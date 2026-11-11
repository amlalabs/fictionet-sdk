//! A network of hosts and services in a few lines: the sandboxes' side,
//! DNS, addresses, a router, one machine per address, and the services on
//! each.
//!
//! [`Net`] builds the whole network around the [`Host`]s a world declares.
//! Each host has addresses, DNS names, and services on its ports: any
//! [layer](fictionet::stdlib::layer) stack over TCP or UDP
//! ([`Host::tcp_stack`], [`Host::udp_stack`]), the same over TLS chosen by
//! SNI ([`Host::tls_stack`]), and any [`PortServer`] of the world's own, such
//! as [`httpd::Server`] for HTTP with name-based virtual hosting. Every
//! sandbox that attaches is put on the sandboxes' subnet, given an address by
//! DHCP or by its first packet, and kept from reaching the other sandboxes. A
//! world then writes only its services. Each world reports its own typed
//! observations from its services.
//!
//! An office: a domain controller that answers LDAP, a web server, and a
//! PLC, with DNS names for each:
//!
//! ```
//! # use std::convert::Infallible;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::layer::{Admit, ByteStream, Env, Layer, StreamCommand, StreamEvent, Top};
//! # use fictionet::stdlib::{web::httpd, world::net::{Host, Net}};
//! # struct Ldap; struct Plc;
//! # macro_rules! stack { ($t:ty) => {
//! # impl Layer for $t {
//! #     type Lower = ByteStream; type Upper = Top; type Report = Infallible; type Timer = ();
//! #     type Work = (); type Done = (); type Error = Infallible;
//! #     fn on_event(&mut self, _: &mut Env<'_, Infallible>, e: StreamEvent) -> std::result::Result<Admit<StreamEvent>, Infallible> { Ok(Admit::Closed(e)) }
//! #     fn on_command(&mut self, _: &mut Env<'_, Infallible>, c: Infallible) -> std::result::Result<Admit<Infallible>, Infallible> { match c {} }
//! #     fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> { None }
//! #     fn take_event(&mut self) -> Option<Infallible> { None }
//! # } } }
//! # stack!(Ldap); stack!(Plc);
//! # async fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let intranet = fictionet_extras::httpd::tower(axum::Router::new().route("/", axum::routing::get(|| async { "intranet\n" })));
//! Net::new(fictionet_extras::network::cdn_pools())
//!     .host("dc01", |h| h.at("10.20.0.10".parse::<std::net::Ipv4Addr>().unwrap()).dns_name("dc01.corp.test").tcp_stack(389, |_| Ldap))
//!     .host("www", |h| h.dns_name("intranet.corp.test").port_server(80, httpd::Server::new(intranet)))
//!     .host("plc1", |h| h.at("10.30.0.5".parse::<std::net::Ipv4Addr>().unwrap()).tcp_stack(502, |_| Plc))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```
//!
//! [`web::Sites`](fictionet::stdlib::web::Sites) is a preset on `Net` for a
//! world of websites, whose hosts appear as their names are looked up
//! ([`dns::placing`]).
//!
//! # Programs and hosts placed later
//!
//! A host can also run code of its own on its machines, as a resolver, a
//! mail relay or a bot would: [`Host::program`] runs a [`Program`] with the
//! machine's [`Endpoints`], whose TCP and UDP endpoints send from the
//! machine's address through the router. [`Host::delay`] puts a fixed
//! delay on the link between a host's machines and the network, so the
//! host feels far away. [`Net::handle`] gives a [`NetHandle`] whose
//! [`add_host`](NetHandle::add_host) places a host while the network
//! runs, by the same rules as the hosts given before [`Net::start`]:
//!
//! ```
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::world::net::{Endpoints, Host, Net};
//! # async fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let net = Net::new(fictionet::stdlib::world::net::Pools {
//!     v4: Some("192.0.2.0/24".parse()?),
//!     v6: Some("2001:db8:1::/64".parse()?),
//! });
//! let handle = net.handle();
//! let net = net.host("spawner", |h| {
//!     h.program(move |_fcx: Cx, _machine: Endpoints| {
//!         let handle = handle.clone();
//!         async move {
//!             handle.add_host(Host::new("later").dns_name("later.test"))?;
//!             Ok(())
//!         }
//!     })
//! });
//! net.start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```
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
//!   sandbox at a fixed prefix outside that subnet, such as a real
//!   container playing a host or the open internet, with no address
//!   binding or DHCP. It drops only packets from sources the network does
//!   not route back to it.
//! - **DNS** at the gateway, over UDP and TCP: a recursive resolver
//!   ([`Config::new`](fictionet::stdlib::services::dns::resolver::Config::new) with no root hints),
//!   with no route to the internet. It answers each host's names with the
//!   host's addresses, and other types with NODATA. Another name under a
//!   top-level domain that a host's name uses gets NXDOMAIN, and a name
//!   under any other top-level domain gets SERVFAIL with Extended DNS Error
//!   22, No Reachable Authority, as a resolver on a network with no
//!   internet answers ([`Declared`]). Answers come with RA set, an SOA in
//!   negative answers, TTLs that count down, and the EDNS a resolver sends.
//!   [`Net::gateway`] runs something else there.
//! - **Addresses.** A host with [`Host::at`] uses that address; otherwise
//!   it gets a free one from the world's [`Pools`], one per address family.
//!   Hosts with the same address share one machine.
//! - **A router** with one route per machine. A packet for any other address
//!   gets ICMP "host unreachable" (ICMPv6 "address unreachable"), or is silently
//!   dropped with [`Net::drop_unrouted`]. The router is
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
//!   reset. Each port has its own cap too, for each sandbox apart
//!   ([`Host::tcp_stack_with`]).
//! - **Budgets.** Service-layer holdings for one sandbox are charged to
//!   that sandbox's [`Budget`], 256 MiB unless [`Limits::sandbox_budget`]
//!   says otherwise. A connection that would pass it is closed. The stack
//!   runner charges its read buffer and the bytes the stack has not taken,
//!   each layer charges what it holds, and HTTP/2 charges retained request
//!   heads and bodies (see [`httpd`]). The packets a sandbox sends through
//!   `fictionet attach` are paid from its budget while anything keeps them.
//!   A [`PortServer`] of your own charges what it chooses. A sandbox has one
//!   budget for both its addresses, from when it attaches until it
//!   detaches. A route ([`Net::route`]) has none.
//! - **Every link** inside the network holds at most 4 MiB of packets each
//!   way; past that, packets are dropped, as on a congested link.
//! - **Errors.** A host that cannot be served as declared, such as one at
//!   an address a host cannot have, two services on one port (one with
//!   TLS and one without count as two), or a port
//!   that cannot be listened on, makes [`Net::start`] fail. A rejected host
//!   adds no machine, route, listener, task, TLS name or virtual host, and
//!   consumes no automatic address. Existing hosts remain unchanged. A
//!   host given to [`NetHandle::add_host`] follows the same rule, and the
//!   call returns the error.
//!
//! The limits and rules are those [`web::Sites`](fictionet::stdlib::web::Sites)
//! documents in detail, which runs on this.

use fictionet::sync::Mutex;
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, SystemTime};

#[cfg(doc)]
use fictionet::stdlib::layer::Budget;
use fictionet::stdlib::network::route::{self, Prefix, Router};
use fictionet::stdlib::network::{icmp, tcp};
use fictionet::stdlib::services::dns::WallClock;
use fictionet::stdlib::services::dns::resolver::Config;
use fictionet::{Attachments, Cx, End, Error, Interface, InterfaceExt};

#[cfg(doc)]
use fictionet::stdlib::web::httpd;

mod addresses;
mod attachments;
pub mod dns;
mod hosts;
mod names;

pub use addresses::Placed;
use addresses::{Leases, Subnet, Subnet6, check_pools};
pub use attachments::Sandbox;
use attachments::{Destinations, Hooks, filter, udp_packet};
use dns::Recursive;
use hosts::{Admission, Installation, Machines, Peers, World, host_prefix};
pub use hosts::{
    Arrival, CertificateFor, CertificateFuture, DEFAULT_MAX_CONNS, DatagramServer, Declared,
    Endpoints, Host, Opening, PortServer, PortStack, PreparedShare, Program, Sni,
};
pub use names::normalize;

const PROTO_UDP: u8 = 17;

/// Each link inside the network holds at most this many bytes of packets
/// each way.
const LINK_QUEUE: usize = 4 << 20;

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
    /// or on an HTTP port without TLS to send its first bytes. Default 10
    /// seconds.
    pub handshake: Duration,
    /// How long a DNS-over-TCP connection may sit idle between queries (RFC
    /// 7766, section 6.2.3). Default 10 seconds.
    pub dns_tcp_idle: Duration,
    /// How long a write may take no bytes on a connection to a TLS port, a
    /// client that stopped reading, before the network gives up on it.
    /// Default 30 seconds.
    pub write_timeout: Duration,
    /// Bytes held by the service layer for one sandbox, all services
    /// together: see [`Budget`]. Excludes TCP buffers and the state rustls
    /// keeps itself; TLS's own buffers count. The blocks the sandbox's
    /// packets arrive in from `fictionet attach` are paid from it too, for
    /// as long as anything keeps them, a TCP buffer included: with no room
    /// the world reads no more of its packets until memory frees, and a
    /// budget too small for one block (2 KiB) detaches it. Default 256 MiB.
    pub sandbox_budget: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            connections_per_peer: 256,
            handshake: Duration::from_secs(10),
            dns_tcp_idle: Duration::from_secs(10),
            write_timeout: Duration::from_secs(30),
            sandbox_budget: 256 << 20,
        }
    }
}

// ---------------------------------------------------------------------------
// The network

/// Builds what runs at a gateway address: see [`Net::gateway`].
type Gateway = dyn Fn(Host, Declared) -> Host + Send + Sync;

/// A LAN definition shared by a network, its hosts and attached members.
///
/// ```
/// use fictionet::stdlib::world::net::{Lan, Net, Pools};
/// let office = Lan::new("office", "192.168.56.0/24".parse()?);
/// let net = Net::new(Pools::NONE).lan(&office)
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

/// Where hosts without a fixed address ([`Host::at`]) get theirs, one
/// prefix per address family. The world chooses them: the addresses are
/// what sandboxes see in DNS answers and connections.
/// `fictionet_extras::network::cdn_pools` gives public CDN space.
///
/// A family with no pool has no automatic addresses: its hosts need
/// [`Host::at`], or have only the other family. An IPv4 pool must have a
/// length of at most 30, and its first and last addresses are never handed
/// out; an IPv6 pool at most 127, and its first address is never handed
/// out. Otherwise [`Net::start`] fails. Addresses in the sandboxes'
/// subnets and addresses no host may have are skipped.
///
/// ```
/// use fictionet::stdlib::world::net::{Net, Pools};
/// let cdn = Net::new(fictionet_extras::network::cdn_pools());
/// let own = Net::new(Pools {
///     v4: Some("104.16.0.0/13".parse()?),
///     v6: None,
/// });
/// let explicit = Net::new(Pools::NONE);
/// # Ok::<(), fictionet::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pools {
    /// The IPv4 pool.
    pub v4: Option<Prefix>,
    /// The IPv6 pool.
    pub v6: Option<Prefix>,
}

impl Pools {
    /// No automatic addresses: every host needs [`Host::at`].
    pub const NONE: Pools = Pools { v4: None, v6: None };
}

/// The pools the network's own tests use.
#[cfg(test)]
const TEST_POOLS: Pools = Pools {
    v4: Some(Prefix {
        addr: IpAddr::V4(Ipv4Addr::new(104, 18, 0, 0)),
        len: 15,
    }),
    v6: Some(Prefix {
        addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x100, 0, 0, 0, 0, 0)),
        len: 48,
    }),
};

/// Why the network refused a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No route leads to the destination.
    NoRoute,
    /// The destination port has no listener or socket.
    ClosedPort,
    /// The sandbox's egress policy disallows the destination.
    Policy,
}

/// A packet the network could not deliver.
#[derive(Clone, Debug)]
pub struct RefusedPacket {
    /// When it was refused.
    pub at: fictionet::time::Instant,
    /// The sender, recipient and sandbox, when known.
    pub conn: fictionet::stdlib::network::ConnInfo,
    /// Source address, including protocols without ports.
    pub from: IpAddr,
    /// Destination address, including protocols without ports.
    pub to: IpAddr,
    /// IP protocol number.
    pub protocol: u8,
    /// Why delivery failed.
    pub reason: Refusal,
}

/// The outcome of a TLS handshake on a host's port.
#[derive(Debug)]
pub struct TlsObservation {
    /// When the handshake ended.
    pub at: fictionet::time::Instant,
    /// The connection, including the requested server name when available.
    pub conn: fictionet::stdlib::network::ConnInfo,
    /// Whether TLS was established, or why it failed.
    pub result: Result<(), fictionet::stdlib::services::tls::HandshakeError>,
}

/// A sandbox attachment's lifecycle change.
#[derive(Clone, Copy, Debug)]
pub enum AttachmentChange {
    /// The attachment joined the network.
    Attached,
    /// An address was bound, either by DHCP or from its first packet.
    Bound {
        /// Whether DHCP supplied the address.
        by_dhcp: bool,
    },
    /// The attachment left the network.
    Detached,
}

/// A sandbox joining, binding an address, or leaving the network.
#[derive(Clone, Debug)]
pub struct AttachmentObservation {
    /// When the change happened.
    pub at: fictionet::time::Instant,
    /// The attachment and its addresses at that time.
    pub sandbox: Sandbox,
    /// What changed.
    pub change: AttachmentChange,
}

type OnRefused = Arc<dyn Fn(&RefusedPacket) + Send + Sync>;
type OnTls = Arc<dyn Fn(&TlsObservation) + Send + Sync>;
type OnAttachment = Arc<dyn Fn(&AttachmentObservation) + Send + Sync>;
type OnDns = Arc<dyn Fn(&fictionet::stdlib::services::dns::Event) + Send + Sync>;

/// A network of hosts and services, and the sandboxes' side of it. See the
/// [module docs](self).
pub struct Net {
    pools: Pools,
    subnet: Prefix,
    subnet_v6: Prefix,
    ipv6: bool,
    hosts: Vec<Host>,
    gateway: Arc<Gateway>,
    unreachable: Option<Arc<dyn Fn(Unreachable) + Send + Sync>>,
    refused_observe: Option<OnRefused>,
    tls_observe: Option<OnTls>,
    attachment_observe: Option<OnAttachment>,
    dns_observe: Option<OnDns>,

    drop_unrouted: bool,
    egress: Option<Arc<Egress>>,
    routes: Vec<(String, Prefix)>,
    limits: Limits,
    lans: Vec<Lan>,
    members: Vec<(String, Lan, IpAddr)>,
    handle: NetHandle,
}

impl Net {
    /// An empty network with the default subnets, dual-stack, whose hosts
    /// without [`Host::at`] get addresses from `pools`.
    pub fn new(pools: Pools) -> Net {
        Net {
            pools,
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
            gateway: Arc::new(default_gateway),
            unreachable: None,
            refused_observe: None,
            tls_observe: None,
            attachment_observe: None,
            dns_observe: None,
            drop_unrouted: false,
            egress: None,
            routes: Vec::new(),
            limits: Limits::default(),
            lans: Vec::new(),
            members: Vec::new(),
            handle: NetHandle::default(),
        }
    }

    /// Observes closed ports, unrouted packets and egress policy refusals.
    pub fn on_refused(mut self, observe: impl Fn(&RefusedPacket) + Send + Sync + 'static) -> Self {
        self.refused_observe = Some(Arc::new(observe));
        self
    }

    /// Observes TLS handshakes, including failures before a service runs.
    pub fn on_tls(mut self, observe: impl Fn(&TlsObservation) + Send + Sync + 'static) -> Self {
        self.tls_observe = Some(Arc::new(observe));
        self
    }

    /// Observes sandbox attachments and address bindings.
    pub fn on_attachment(
        mut self,
        observe: impl Fn(&AttachmentObservation) + Send + Sync + 'static,
    ) -> Self {
        self.attachment_observe = Some(Arc::new(observe));
        self
    }

    /// Observes the DNS engines on every machine in this network.
    pub fn on_dns(
        mut self,
        observe: impl Fn(&fictionet::stdlib::services::dns::Event) + Send + Sync + 'static,
    ) -> Self {
        self.dns_observe = Some(Arc::new(observe));
        self
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
    /// `net.host("dc01", |h| h.at(addr).tcp_stack(389, |_| Ldap::new()))`.
    pub fn host(mut self, label: &str, build: impl FnOnce(Host) -> Host) -> Net {
        self.hosts.push(build(Host::new(label)));
        self
    }

    /// Adds a host built on its own.
    pub fn add_host(mut self, host: Host) -> Net {
        self.hosts.push(host);
        self
    }

    /// Adds several hosts built on their own, such as the ones a preset
    /// returns.
    pub fn hosts(mut self, hosts: impl IntoIterator<Item = Host>) -> Net {
        self.hosts.extend(hosts);
        self
    }

    /// A handle to this network, for world code that places hosts while
    /// it runs. It can be taken before [`start`](Net::start), to give to
    /// the programs and callbacks the network will run, and works once
    /// `start` has returned.
    pub fn handle(&self) -> NetHandle {
        self.handle.clone()
    }

    /// Sets what runs at each gateway address: the sandboxes' gateway of
    /// each family and each LAN's DNS address. `build` gets a host and the
    /// names the network's hosts declare, as zone data ([`Declared`]), and
    /// returns the host with the programs and services the gateway runs.
    /// Only those are used; the gateway keeps its own address and answers
    /// pings. It is called once per gateway address, so each address has
    /// its own programs, and a resolver its own cache.
    ///
    /// The default runs a recursive resolver with no route to the
    /// internet, answering the declared names: [`Config::new`] with no
    /// root hints, under [`Declared::over`], and a clock that starts at the
    /// Unix epoch, since a resolver that asks no other server checks no
    /// signature. A world whose resolver iterates to root servers of its
    /// own gives it root hints ([`Config::hints`]).
    ///
    /// [`Config::new`]: fictionet::stdlib::services::dns::resolver::Config::new
    /// [`Config::hints`]: fictionet::stdlib::services::dns::resolver::Config::hints
    pub fn gateway(self, build: impl Fn(Host, Declared) -> Host + Send + Sync + 'static) -> Net {
        Net {
            gateway: Arc::new(build),
            ..self
        }
    }

    /// Calls `report` when a packet has no route in this network.
    pub fn on_unreachable(mut self, report: impl Fn(Unreachable) + Send + Sync + 'static) -> Self {
        self.unreachable = Some(Arc::new(report));
        self
    }

    /// Silently drops packets with no route, as a filtering firewall does.
    /// Clients use their normal retransmission and timeout behavior.
    /// [`Net::on_unreachable`] still reports each dropped packet.
    pub fn drop_unrouted(mut self) -> Self {
        self.drop_unrouted = true;
        self
    }

    /// Filters ordinary sandboxes' TCP and UDP destinations outside their
    /// gateway. False silently drops the packet after IP reassembly. Hosts,
    /// trusted routes and LAN members are unaffected. The predicate must
    /// return quickly and must not call back into the network.
    pub fn egress(mut self, allow: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        self.egress = Some(Arc::new(allow));
        self
    }

    /// Wires the sandbox called `name` straight to the router at `prefix`,
    /// with no address binding and no DHCP: a real container that plays
    /// one of the hosts, say, or the open internet coming in through a TUN
    /// device. Packets for `prefix` go to it. What it sends is routed as it
    /// is, fragments included, when its source address is one the network
    /// routes back to it: one in `prefix` that no subnet, gateway, host or
    /// longer route has. Packets from any other source are dropped, as a
    /// router with strict reverse-path forwarding drops them (RFC 3704
    /// section 2.2), so a route open to the internet cannot send packets in
    /// another sandbox's or host's name. That is the only filter: unlike a
    /// sandbox's, a route's packets are not otherwise checked. Connections
    /// from addresses in `prefix` that no other sandbox has name this
    /// sandbox, and the network keeps nothing per source address, so a
    /// route open to the internet can carry any number of them.
    ///
    /// Call it again with the same `name` to give the sandbox more
    /// prefixes, such as `0.0.0.0/0` and `::/0` for the internet over both
    /// IPv4 and IPv6. The sandbox is then one route for all of them.
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
    /// subnets, the network's [`Pools`], or another LAN, or leaves no room
    /// for members.
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
    pub fn start(self, fcx: &Cx, attachments: Attachments) -> Result<(), Error> {
        self.launch(fcx, attachments).map(drop)
    }

    /// [`start`](Net::start), returning the state the network's tasks share.
    fn launch(self, fcx: &Cx, mut attachments: Attachments) -> Result<Arc<Shared>, Error> {
        check_pools(&self.pools)?;
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
        let lans = make_lans(
            fcx,
            &router,
            &subnet,
            subnet6.as_ref(),
            &self.pools,
            self.lans,
            &self.members,
        )?;
        let world = Arc::new(Mutex::new(World::new(self.pools)));
        let routes: Vec<(String, Prefix)> = self.routes;
        let fixed: Vec<Prefix> = routes.iter().map(|(_, p)| *p).collect();
        let hooks = Arc::new(Hooks {
            by_addr: Mutex::default(),
            routes: Mutex::default(),
            conns: AtomicU64::new(0),
            attached: Mutex::default(),
            destinations: Destinations {
                subnets: std::iter::once(subnet.prefix)
                    .chain(subnet6.map(|s| s.prefix))
                    .collect(),
                gateways: std::iter::once(IpAddr::V4(subnet.gateway))
                    .chain(subnet6.map(|s| IpAddr::V6(s.gateway)))
                    .chain(lans.values().map(|l| l.dns))
                    .collect(),
                trusted: fixed
                    .iter()
                    .copied()
                    .chain(lans.values().map(|l| l.prefix))
                    .collect(),
                machines: Machines::new(world.clone()),
            },
            refused_observe: self.refused_observe,
            tls_observe: self.tls_observe,
            attachment_observe: self.attachment_observe,
            dns_observe: self.dns_observe,
        });

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
        let drop_unrouted = self.drop_unrouted;
        let report_hooks = hooks.clone();
        fcx.spawn(move |fcx| {
            unreachable(
                fcx,
                unreachable_side,
                gateway.into(),
                report,
                drop_unrouted,
                report_hooks,
            )
        });
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
            let report_hooks = hooks.clone();
            fcx.spawn(move |fcx| {
                unreachable(
                    fcx,
                    unreachable_side,
                    gateway.into(),
                    report,
                    drop_unrouted,
                    report_hooks,
                )
            });
        }
        let shared = Arc::new(Shared {
            fcx: fcx.clone(),
            subnet,
            subnet6,
            router,
            world,
            leases: Arc::new(Mutex::new(Leases::default())),
            gateway_tcp: Arc::new(Mutex::new(Vec::new())),
            hooks,
            peers: Peers::new(self.limits.connections_per_peer),
            limits: self.limits,
            egress: self.egress,
            lans,
        });
        start_gateway(&shared, &*self.gateway)?;
        {
            let mut world = shared.world.lock();
            for host in self.hosts {
                shared.place(&mut world, host)?;
            }
        }
        // A network starts once, so the handle has no network yet.
        let _ = self.handle.0.set(Arc::downgrade(&shared));

        let members = self.members;
        let context = shared.attachments();
        let net = shared.clone();
        caller.spawn(move |fcx| async move {
            loop {
                let sandbox = attachments.next(&fcx).await?;
                let prefixes: Vec<Prefix> = routes
                    .iter()
                    .filter(|(n, _)| n == sandbox.name())
                    .map(|(_, p)| *p)
                    .collect();
                if !prefixes.is_empty() {
                    let routed = context.routed(&fcx, sandbox, prefixes.clone());
                    shared.router.add_prefixes(prefixes, Box::new(routed));
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
        Ok(net)
    }
}

/// Places hosts in a running network: see [`Net::handle`].
///
/// A handle holds the network weakly, so it does not keep a network alive
/// after its region is cancelled.
#[derive(Clone, Default)]
pub struct NetHandle(Arc<OnceLock<Weak<Shared>>>);

impl NetHandle {
    /// Places `host` while the network runs, by the same rules as the
    /// hosts given before [`start`](Net::start): never on the sandboxes'
    /// subnet or at an address a host cannot have, on a LAN only with
    /// [`Host::on`], and with no service on a port another host at that
    /// address already serves. Its names are declared from then on
    /// ([`Declared`]), and its programs start. A rejected host leaves
    /// nothing behind.
    ///
    /// Fails before the network has started, after it has stopped, and for
    /// a host that cannot be placed. Zone data may call it while a
    /// resolver waits for a view, as [`dns::placing`] does; it takes the
    /// network's lock, which no code holds while it calls into a resolver.
    pub fn add_host(&self, host: Host) -> Result<Placed, Error> {
        let shared = self.shared()?;
        let mut world = shared.world.lock();
        shared.place(&mut world, host)
    }

    /// Whether a host's machine is at `addr`. Before the network has
    /// started, none is.
    pub fn has_machine(&self, addr: IpAddr) -> bool {
        self.shared()
            .is_ok_and(|shared| shared.world.lock().machines.contains_key(&addr))
    }

    /// Whether a machine at `addr` has a socket open on UDP port `port`,
    /// as a program that answers DNS there has on port 53. Before the
    /// network has started, none has.
    pub fn udp_bound(&self, addr: IpAddr, port: u16) -> bool {
        self.shared().is_ok_and(|shared| {
            shared
                .world
                .lock()
                .machines
                .get(&addr)
                .is_some_and(|machine| machine.udp_bound(port))
        })
    }

    fn shared(&self) -> Result<Arc<Shared>, Error> {
        let network = self
            .0
            .get()
            .ok_or_else(|| Error::msg("the network has not started"))?;
        network
            .upgrade()
            .ok_or_else(|| Error::msg("the network has stopped"))
    }
}

// ---------------------------------------------------------------------------
// What the network's tasks share

type Egress = dyn Fn(SocketAddr) -> bool + Send + Sync;

/// Network state assembled into capability contexts for its subsystems.
struct Shared {
    peers: Arc<Peers>,
    fcx: Cx,
    subnet: Subnet,
    subnet6: Option<Subnet6>,
    router: Router<Box<dyn Interface>>,
    world: Arc<Mutex<World>>,
    leases: Arc<Mutex<Leases>>,
    gateway_tcp: Arc<Mutex<Vec<tcp::Endpoint>>>,
    hooks: Arc<Hooks>,
    limits: Limits,
    egress: Option<Arc<Egress>>,
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
            limits: self.limits,
        }
    }

    /// Places `host` and declares its names, which then answer with its
    /// addresses.
    fn place(&self, world: &mut World, host: Host) -> Result<Placed, Error> {
        let names = host.names.clone();
        let label = host.label.clone();
        let placed = self
            .installation()
            .place(world, host)
            .map_err(|e| fictionet::Error::msg(format!("host {label}: {e}")))?;
        world.declare(&names, placed);
        Ok(placed)
    }

    fn attachments(&self) -> Arc<attachments::Context> {
        let abort = self.hooks.destinations.machines.clone();
        let gateway_tcp = self.gateway_tcp.clone();
        Arc::new(attachments::Context {
            bindings: addresses::Bindings::new(self.subnet, self.subnet6, self.leases.clone()),
            hooks: self.hooks.clone(),
            sandbox_budget: self.limits.sandbox_budget,
            egress: self.egress.clone(),
            router: self.router.clone(),
            abort_peers: Arc::new(move |which| {
                abort.abort_peers(which);
                for tcp in gateway_tcp.lock().iter() {
                    tcp.abort_peers(which);
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
    subnet: &Subnet,
    subnet6: Option<&Subnet6>,
    pools: &Pools,
    lans: Vec<Lan>,
    members: &[(String, Lan, IpAddr)],
) -> Result<BTreeMap<String, LanSeg>, Error> {
    let mut made: BTreeMap<String, LanSeg> = BTreeMap::new();
    for Lan { name, prefix } in lans {
        if [pools.v4, pools.v6]
            .into_iter()
            .flatten()
            .any(|pool| prefix.overlaps(pool))
        {
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

/// What runs at a gateway address unless [`Net::gateway`] says otherwise.
fn default_gateway(host: Host, declared: Declared) -> Host {
    let clock = WallClock {
        start: SystemTime::UNIX_EPOCH,
    };
    let config = Config {
        hints: Vec::new(),
        ..Config::new()
    };
    host.program(Recursive::new(declared.over(config), clock))
}

/// The gateway: a machine at its IPv4 address and, with IPv6, at its IPv6
/// address, running what `build` gives it, DNS on port 53 by default, and
/// answering pings. DHCP is answered in each sandbox's filter, which knows
/// which sandbox asked. The LANs' DNS machines start after these gateways,
/// in ascending LAN name order. Each gateway's TCP endpoint is kept, so
/// its connections count toward the per-peer limit and end when their
/// sandbox detaches.
fn start_gateway(shared: &Arc<Shared>, build: &Gateway) -> Result<(), Error> {
    let declared = Declared::new(shared.world.clone());
    let installation = shared.installation();
    let failed =
        |addr: IpAddr| move |e: String| fictionet::Error::msg(format!("gateway {addr}: {e}"));
    let gateways = std::iter::once(IpAddr::V4(shared.subnet.gateway))
        .chain(shared.subnet6.map(|s| IpAddr::V6(s.gateway)));
    for gateway in gateways {
        let host = build(Host::new("gateway"), declared.clone());
        let attach = |side| {
            shared.router.add(host_prefix(gateway), side);
            Ok(())
        };
        let tcp = installation
            .gateway(gateway, &host, attach)
            .map_err(failed(gateway))?;
        shared.gateway_tcp.lock().push(tcp);
    }
    for seg in shared.lans.values() {
        let host = build(Host::new("gateway"), declared.clone());
        let attach = |side| seg.lan.add(seg.dns, side).map_err(|e| e.to_string());
        let tcp = installation
            .gateway(seg.dns, &host, attach)
            .map_err(failed(seg.dns))?;
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
    drop_unrouted: bool,
    hooks: Arc<Hooks>,
) -> fictionet::Result {
    let mut run = 0;
    while let Ok(packet) = end.recv(&fcx).await {
        hooks.refused(&fcx, &packet, Refusal::NoRoute);
        if let Some(report) = &report
            && let Some(header) = crate::stdlib::network::ip::Header::parse(&packet)
        {
            report(Unreachable {
                from: header.src,
                to: header.dst,
            });
        }
        if !drop_unrouted {
            let reply = match gateway {
                IpAddr::V4(g) => icmp::host_unreachable(&packet, g),
                IpAddr::V6(g) => icmp::address_unreachable(&packet, g),
            };
            if let Some(reply) = reply {
                end.send(reply);
            }
        }
        run = (run + 1) % 64;
        if run == 0 && fcx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::network::ConnInfo;
    use fictionet::stdlib::network::ConnectionExt;
    use fictionet::stdlib::network::ip;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PROTO_TCP: u8 = 6;

    #[test]
    fn lan_dns_endpoints_start_in_name_order() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let subnet = Subnet::new("104.18.0.0/16".parse().unwrap()).unwrap();
                let router = route::router::<Box<dyn Interface>>(&fcx, Vec::new());
                let lans = make_lans(
                    &fcx,
                    &router,
                    &subnet,
                    None,
                    &TEST_POOLS,
                    [
                        ("z", "10.0.1.0/24"),
                        ("a", "10.0.3.0/24"),
                        ("m", "10.0.2.0/24"),
                    ]
                    .map(|(name, prefix)| Lan::new(name, prefix.parse().unwrap()))
                    .into(),
                    &[],
                )?;
                let world = Arc::new(Mutex::new(World::new(TEST_POOLS)));
                let hooks = Arc::new(Hooks {
                    by_addr: Mutex::default(),
                    routes: Mutex::default(),
                    conns: AtomicU64::new(0),
                    attached: Mutex::default(),
                    destinations: Destinations {
                        subnets: vec![subnet.prefix],
                        gateways: std::iter::once(IpAddr::V4(subnet.gateway))
                            .chain(lans.values().map(|l| l.dns))
                            .collect(),
                        trusted: lans.values().map(|l| l.prefix).collect(),
                        machines: Machines::new(world.clone()),
                    },
                    refused_observe: None,
                    tls_observe: None,
                    attachment_observe: None,
                    dns_observe: None,
                });
                let shared = Arc::new(Shared {
                    fcx: fcx.clone(),
                    subnet,
                    subnet6: None,
                    router,
                    world,
                    leases: Arc::default(),
                    gateway_tcp: Arc::default(),
                    hooks,
                    peers: Peers::new(Limits::default().connections_per_peer),
                    limits: Limits::default(),
                    egress: None,
                    lans,
                });
                start_gateway(&shared, &default_gateway)?;
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

    /// Records who each connection is from. With `hold`, keeps it until it is
    /// gone and counts it in `gone`; otherwise closes it at once.
    struct Spy {
        from: Arc<Mutex<Vec<ConnInfo>>>,
        hold: bool,
        gone: Arc<AtomicUsize>,
    }

    impl PortServer for Spy {
        fn serve_connection(
            &self,
            _: Cx,
            arrival: Arrival,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
            self.from.lock().push(arrival.info);
            let (hold, gone) = (self.hold, self.gone.clone());
            let (conn, socket) = (arrival.conn, arrival.socket);
            Box::pin(async move {
                if hold {
                    std::future::poll_fn(move |cx| socket.poll_gone(cx)).await;
                    drop(conn);
                    gone.fetch_add(1, Ordering::SeqCst);
                }
            })
        }
    }

    /// A route open to the whole internet carries connections from many
    /// addresses, and SYNs from many more that never finish, as spoofed
    /// ones do. Each connection names the route's sandbox, and once they
    /// end the network keeps nothing for any of those addresses. When the
    /// route's sandbox detaches, the connections still open are reset.
    /// Before, the route kept an entry for every source address it ever
    /// forwarded.
    #[test]
    fn a_public_route_keeps_nothing_per_source() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let server = Ipv4Addr::new(10, 40, 0, 1);
                let from = Arc::new(Mutex::new(Vec::new()));
                let gone = Arc::new(AtomicUsize::new(0));
                let spy = |hold| Spy {
                    from: from.clone(),
                    hold,
                    gone: gone.clone(),
                };
                let (attacher, attachments) = fictionet::attachments();
                let net = Net::new(TEST_POOLS)
                    .ipv4_only()
                    .host("svc", |h| {
                        h.at(server)
                            .port_server(22, spy(false))
                            .port_server(23, spy(true))
                    })
                    .route("internet", "0.0.0.0/0".parse()?)
                    .launch(&fcx, attachments)?;

                // The internet side: a router with the world behind the
                // attachment, a machine at each client address, and a raw
                // link for spoofed SYNs, whose SYN-ACKs have no route back.
                let internet = route::router::<Box<dyn Interface>>(&fcx, Vec::new());
                internet.add(
                    "10.40.0.0/16".parse()?,
                    Box::new(attacher.attach("internet")?),
                );
                let (raw_side, mut raw) = link();
                internet.add("192.0.2.1/32".parse()?, Box::new(raw_side));
                let clients: Vec<IpAddr> = (0..200u32)
                    .map(|n| IpAddr::V4(Ipv4Addr::from(0xc612_0000 + n)))
                    .collect();
                let mut machines = Vec::new();
                for &addr in &clients {
                    let (router_side, side) = link();
                    internet.add(host_prefix(addr), Box::new(router_side));
                    machines.push(tcp::endpoint(&fcx, side, addr));
                }

                for n in 0..1000u32 {
                    let src = Ipv4Addr::from(0x0b00_0000 + n);
                    let mut t = vec![0u8; 20];
                    t[0..2].copy_from_slice(&4000u16.to_be_bytes());
                    t[2..4].copy_from_slice(&22u16.to_be_bytes());
                    t[12] = 5 << 4;
                    t[13] = 0x02;
                    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
                    let sum = ip::transport_checksum(src.into(), server.into(), PROTO_TCP, &t);
                    t[16..18].copy_from_slice(&sum.to_be_bytes());
                    raw.send(ip::packet(src.into(), server.into(), PROTO_TCP, &t));
                }
                for machine in &machines {
                    let mut conn = machine
                        .connect(&fcx, SocketAddr::new(server.into(), 22))
                        .await?;
                    let mut buf = [0; 1];
                    assert_eq!(conn.read(&fcx, &mut buf).await?, 0);
                }
                let held = machines[0]
                    .connect(&fcx, SocketAddr::new(server.into(), 23))
                    .await?;
                fcx.sleep(Duration::from_secs(1)).await?;
                {
                    let from = from.lock();
                    assert_eq!(from.len(), clients.len() + 1);
                    for (n, info) in from.iter().enumerate() {
                        assert_eq!(info.peer.map(|p| p.ip()), Some(clients[n % clients.len()]));
                        assert_eq!(info.sandbox.as_ref().map(|s| &*s.name), Some("internet"));
                    }
                }
                assert!(net.hooks.by_addr.lock().is_empty());
                assert_eq!(net.hooks.routes.lock().len(), 1);
                assert_eq!(net.peers.peers(), 1, "only the held connection's peer");

                // The SYN-ACKs to the spoofed addresses time out, and the
                // closed connections finish closing.
                fcx.sleep(Duration::from_secs(150)).await?;
                assert_eq!(net.peers.peers(), 1);
                assert_eq!(gone.load(Ordering::SeqCst), 0);

                // The route's sandbox detaches: its open connection is
                // reset at once, not left to time out.
                internet.add("10.40.0.0/16".parse()?, Box::new(link().0));
                fcx.sleep(Duration::from_secs(1)).await?;
                assert_eq!(gone.load(Ordering::SeqCst), 1);
                assert_eq!(net.peers.peers(), 0);
                assert!(net.hooks.by_addr.lock().is_empty());
                assert_eq!(net.hooks.routes.lock().len(), 1);
                drop(held);
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    /// After `after`, connects to `to` and keeps the connection until it
    /// is gone, which it counts in `gone`. Counts connecting in
    /// `connected`.
    struct Caller {
        to: SocketAddr,
        after: Duration,
        connected: Arc<AtomicUsize>,
        gone: Arc<AtomicUsize>,
    }

    impl Program for Caller {
        fn run(
            &self,
            fcx: Cx,
            machine: Endpoints,
        ) -> std::pin::Pin<Box<dyn Future<Output = fictionet::Result> + Send>> {
            let (to, after) = (self.to, self.after);
            let (connected, gone) = (self.connected.clone(), self.gone.clone());
            Box::pin(async move {
                fcx.sleep(after).await?;
                let conn = machine.tcp.connect(&fcx, to).await?;
                connected.fetch_add(1, Ordering::SeqCst);
                let watch = conn.gone_watch();
                std::future::poll_fn(|cx| watch.poll_gone(cx)).await;
                drop(conn);
                gone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    /// A route carries only sources the network has nowhere else, so a
    /// connection between two hosts is not the route's, whether the route's
    /// sandbox attached before or after it was made: it names no sandbox,
    /// and it outlives the route's sandbox, whose detaching resets only
    /// the connections the route carried.
    #[test]
    fn a_route_detaching_leaves_host_connections_alone() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let (a, b, c) = (
                    Ipv4Addr::new(10, 40, 0, 1),
                    Ipv4Addr::new(10, 40, 0, 2),
                    Ipv4Addr::new(10, 40, 0, 3),
                );
                let from = Arc::new(Mutex::new(Vec::new()));
                let gone = Arc::new(AtomicUsize::new(0));
                let connected = Arc::new(AtomicUsize::new(0));
                let caller = |after| Caller {
                    to: SocketAddr::new(b.into(), 23),
                    after: Duration::from_secs(after),
                    connected: connected.clone(),
                    gone: gone.clone(),
                };
                let (attacher, attachments) = fictionet::attachments();
                Net::new(TEST_POOLS)
                    .ipv4_only()
                    .host("b", |h| {
                        h.at(b).port_server(
                            23,
                            Spy {
                                from: from.clone(),
                                hold: true,
                                gone: gone.clone(),
                            },
                        )
                    })
                    .host("a", |h| h.at(a).program(caller(0)))
                    .host("c", |h| h.at(c).program(caller(2)))
                    .route("internet", "0.0.0.0/0".parse()?)
                    .start(&fcx, attachments)?;
                fcx.sleep(Duration::from_secs(1)).await?;
                assert_eq!(connected.load(Ordering::SeqCst), 1);

                let internet = attacher.attach("internet")?;
                fcx.sleep(Duration::from_secs(2)).await?;
                assert_eq!(connected.load(Ordering::SeqCst), 2);

                drop(internet);
                fcx.sleep(Duration::from_secs(1)).await?;
                assert_eq!(
                    gone.load(Ordering::SeqCst),
                    0,
                    "the hosts' connections outlive the route's sandbox"
                );
                let sandboxes: Vec<(u64, Arc<str>)> = from
                    .lock()
                    .iter()
                    .map(|info| {
                        let s = info
                            .sandbox
                            .as_ref()
                            .expect("a port server names a sandbox");
                        (s.id, s.name.clone())
                    })
                    .collect();
                let unnamed = (0, Arc::from(""));
                assert_eq!(
                    sandboxes,
                    [unnamed.clone(), unnamed],
                    "a host is no sandbox, before or after the route attached"
                );
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    /// Answers each SYN with one option, and records what it serves.
    struct Answers {
        from: Arc<Mutex<Vec<ConnInfo>>>,
    }

    impl PortServer for Answers {
        fn serve_connection(
            &self,
            _: Cx,
            arrival: Arrival,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
            self.from.lock().push(arrival.info);
            Box::pin(async {})
        }

        fn answer(&self) -> Option<Box<dyn tcp::Answer>> {
            Some(Box::new(|syn: &tcp::Syn<'_>| {
                if syn.options.contains(&tcp::TcpOption::Unknown {
                    kind: 253,
                    data: vec![1],
                }) {
                    tcp::SynAnswer::Refuse(vec![tcp::TcpOption::Unknown {
                        kind: 253,
                        data: vec![0],
                    }])
                } else {
                    tcp::SynAnswer::Accept(vec![tcp::TcpOption::Unknown {
                        kind: 253,
                        data: vec![9],
                    }])
                }
            }))
        }
    }

    /// A host's port server answers the SYNs its port gets: a SYN-ACK with
    /// its options, which the connection's ConnInfo keeps, or a RST.
    #[test]
    fn a_port_server_answers_syns() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let server = Ipv4Addr::new(10, 40, 0, 1);
                let from = Arc::new(Mutex::new(Vec::new()));
                let (attacher, attachments) = fictionet::attachments();
                Net::new(TEST_POOLS)
                    .ipv4_only()
                    .host("svc", |h| {
                        h.at(server).port_server(22, Answers { from: from.clone() })
                    })
                    .route("internet", "198.51.100.0/24".parse()?)
                    .start(&fcx, attachments)?;
                let mut internet = attacher.attach("internet")?;
                let client = Ipv4Addr::new(198, 51, 100, 7);
                let syn = |port: u16, seq: u32, ack: u32, flags: u8, options: &[u8]| {
                    let mut t = vec![0u8; 20];
                    t[0..2].copy_from_slice(&port.to_be_bytes());
                    t[2..4].copy_from_slice(&22u16.to_be_bytes());
                    t[4..8].copy_from_slice(&seq.to_be_bytes());
                    t[8..12].copy_from_slice(&ack.to_be_bytes());
                    t[12] = ((20 + options.len()) / 4) as u8 * 16;
                    t[13] = flags;
                    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
                    t.extend_from_slice(options);
                    let sum = ip::transport_checksum(client.into(), server.into(), PROTO_TCP, &t);
                    t[16..18].copy_from_slice(&sum.to_be_bytes());
                    ip::packet(client.into(), server.into(), PROTO_TCP, &t)
                };
                let tcp_of = |p: &fictionet::Packet| p[20..].to_vec();

                internet.send(syn(4000, 100, 0, 0x02, &[253, 3, 2, 0]));
                let syn_ack = tcp_of(&internet.recv(&fcx).await?);
                assert_eq!(syn_ack[13], 0x12);
                let answered = tcp::options(&syn_ack).unwrap();
                assert_eq!(
                    answered.last(),
                    Some(&tcp::TcpOption::Unknown {
                        kind: 253,
                        data: vec![9]
                    })
                );
                let iss = u32::from_be_bytes(syn_ack[4..8].try_into().unwrap());
                internet.send(syn(4000, 101, iss.wrapping_add(1), 0x10, &[]));

                internet.send(syn(4001, 100, 0, 0x02, &[253, 3, 1, 0]));
                let refused = loop {
                    let t = tcp_of(&internet.recv(&fcx).await?);
                    if t[0..4] == [0, 22, 0x0f, 0xa1] {
                        break t;
                    }
                };
                assert_eq!(refused[13] & 0x06, 0x04, "a RST");
                assert_eq!(
                    tcp::options(&refused),
                    Ok(vec![tcp::TcpOption::Unknown {
                        kind: 253,
                        data: vec![0]
                    }])
                );
                fcx.sleep(Duration::from_secs(1)).await?;
                let from = from.lock();
                assert_eq!(from.len(), 1, "the refused attempt is never served");
                assert_eq!(from[0].peer, Some(SocketAddr::new(client.into(), 4000)));
                assert_eq!(
                    from[0].handshake.as_ref().unwrap().syn.as_deref(),
                    Some(
                        &[tcp::TcpOption::Unknown {
                            kind: 253,
                            data: vec![2]
                        }][..]
                    )
                );
                assert_eq!(
                    from[0].handshake.as_ref().unwrap().syn_ack.as_deref(),
                    Some(
                        &[tcp::TcpOption::Unknown {
                            kind: 253,
                            data: vec![9]
                        }][..]
                    )
                );
                drop(from);
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A route open to the whole internet passes on only packets from
    /// addresses the network routes back to it. One that claims an
    /// attached sandbox's address or a host's own is dropped, so neither
    /// gets answers to what it never sent.
    #[test]
    fn a_route_drops_sources_the_network_has_elsewhere() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let server = Ipv4Addr::new(10, 40, 0, 1);
                let from = Arc::new(Mutex::new(Vec::new()));
                let (attacher, attachments) = fictionet::attachments();
                Net::new(TEST_POOLS)
                    .ipv4_only()
                    .host("svc", |h| {
                        h.at(server).port_server(
                            22,
                            Spy {
                                from: from.clone(),
                                hold: true,
                                gone: Arc::default(),
                            },
                        )
                    })
                    .route("internet", "0.0.0.0/0".parse()?)
                    .start(&fcx, attachments)?;
                let mut internet = attacher.attach("internet")?;
                let mut agent = attacher.attach("agent")?;
                let syn = |src: Ipv4Addr, sport: u16| {
                    let mut t = vec![0u8; 20];
                    t[0..2].copy_from_slice(&sport.to_be_bytes());
                    t[2..4].copy_from_slice(&22u16.to_be_bytes());
                    t[12] = 5 << 4;
                    t[13] = 0x02;
                    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
                    let sum = ip::transport_checksum(src.into(), server.into(), PROTO_TCP, &t);
                    t[16..18].copy_from_slice(&sum.to_be_bytes());
                    ip::packet(src.into(), server.into(), PROTO_TCP, &t)
                };
                let within = |fcx: &Cx| Some(fcx.now() + Duration::from_secs(1));
                let agent_addr = Ipv4Addr::new(10, 0, 0, 2);
                agent.send(syn(agent_addr, 45000));
                let syn_ack = fcx.race(within(&fcx), agent.recv(&fcx)).await??;
                assert_eq!(syn_ack[20 + 13], 0x12, "the agent's own SYN is answered");

                internet.send(syn(agent_addr, 45001));
                internet.send(syn(server, 45002));
                internet.send(syn(Ipv4Addr::new(10, 0, 0, 1), 45003));
                internet.send(syn(Ipv4Addr::new(198, 51, 100, 7), 45004));
                let syn_ack = fcx.race(within(&fcx), internet.recv(&fcx)).await??;
                assert_eq!(&syn_ack[16..20], &[198, 51, 100, 7]);
                assert!(fcx.race(within(&fcx), internet.recv(&fcx)).await.is_err());
                // The agent's own SYN-ACK may come again, and nothing else.
                while let Ok(p) = fcx.race(within(&fcx), agent.recv(&fcx)).await {
                    let p = p?;
                    assert_eq!(u16::from_be_bytes([p[22], p[23]]), 45000);
                }
                drop((internet, agent));
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    /// One route name can carry a prefix of each family: the sandbox
    /// attached under it gets both, and what it sends from either is
    /// passed on. Before, only the first prefix with the name was wired,
    /// and the second was dropped without an error.
    #[test]
    fn a_route_carries_a_prefix_of_each_family() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let server4: IpAddr = "10.40.0.1".parse()?;
                let server6: IpAddr = "2001:db8:40::1".parse()?;
                let from = Arc::new(Mutex::new(Vec::new()));
                let (attacher, attachments) = fictionet::attachments();
                Net::new(TEST_POOLS)
                    .host("svc", |h| {
                        h.at(server4).at(server6).port_server(
                            22,
                            Spy {
                                from: from.clone(),
                                hold: true,
                                gone: Arc::default(),
                            },
                        )
                    })
                    .route("internet", "0.0.0.0/0".parse()?)
                    .route("internet", "::/0".parse()?)
                    .start(&fcx, attachments)?;
                let mut internet = attacher.attach("internet")?;
                let syn = |src: IpAddr, dst: IpAddr| {
                    let mut t = vec![0u8; 20];
                    t[0..2].copy_from_slice(&4000u16.to_be_bytes());
                    t[2..4].copy_from_slice(&22u16.to_be_bytes());
                    t[12] = 5 << 4;
                    t[13] = 0x02;
                    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
                    let sum = ip::transport_checksum(src, dst, PROTO_TCP, &t);
                    t[16..18].copy_from_slice(&sum.to_be_bytes());
                    ip::packet(src, dst, PROTO_TCP, &t)
                };
                let within = |fcx: &Cx| Some(fcx.now() + Duration::from_secs(1));
                for (client, server) in [
                    ("198.51.100.7".parse::<IpAddr>()?, server4),
                    ("2001:db8:ffff::7".parse()?, server6),
                ] {
                    internet.send(syn(client, server));
                    let syn_ack = fcx.race(within(&fcx), internet.recv(&fcx)).await??;
                    assert_eq!(ip::source(&syn_ack[..]), Some(server));
                    assert_eq!(ip::destination(&syn_ack[..]), Some(client));
                }
                drop(internet);
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
}

#[cfg(test)]
mod unreachable_tests {
    use super::*;
    use crate::stdlib::network::ip;

    #[test]
    fn dropped_unrouted_packets_are_reported_without_icmp_replies() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let facts = Arc::new(Mutex::new(Vec::new()));
                let recorded = facts.clone();
                let (attacher, attachments) = fictionet::attachments();
                Net::new(TEST_POOLS)
                    .drop_unrouted()
                    .on_unreachable(move |fact| recorded.lock().push(fact))
                    .start(&cx, attachments)?;
                let mut guest = attacher.attach("guest")?;
                let routes = [
                    ("10.0.0.2", "203.0.113.9"),
                    ("2001:db8::2", "2001:db8:99::9"),
                ];
                for (from, to) in routes {
                    guest.send(ip::packet(from.parse()?, to.parse()?, 253, &[1, 2, 3]));
                }
                let received = cx
                    .race(
                        Some(cx.now() + std::time::Duration::from_secs(1)),
                        guest.recv(&cx),
                    )
                    .await;
                assert!(matches!(received, Err(fictionet::RaceError::Deadline)));
                let facts = facts.lock();
                assert_eq!(facts.len(), 2);
                for (from, to) in routes {
                    assert!(facts.contains(&Unreachable {
                        from: from.parse()?,
                        to: to.parse()?,
                    }));
                }
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn a_world_can_report_missing_routes_without_changing_icmp_replies() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let facts = Arc::new(Mutex::new(Vec::new()));
                let recorded = facts.clone();
                let (attacher, attachments) = fictionet::attachments();
                Net::new(TEST_POOLS)
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
                    let header = ip::Header::parse(&reply[..]).unwrap();
                    assert_eq!(header.src, gateway.parse::<IpAddr>()?);
                    assert_eq!(header.dst, from);
                    let payload = header.payload(&reply[..]);
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
