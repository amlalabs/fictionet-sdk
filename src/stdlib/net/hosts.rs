use super::addresses::{Allocator, Placed, Subnet, Subnet6, may_serve_v4, may_serve_v6};
use super::attachments::answered_closed;
use super::{
    BlockedWhy, Hooks, LanSeg, PROTO_TCP, Resolver, blocked_event, connection_limit, link,
    normalize, port_detail, sandbox_only,
};
use fictionet::events::{ConnInfo, Event, Level};
use fictionet::stdlib::codec::Decode;
use fictionet::stdlib::route::{Prefix, Router};
use fictionet::stdlib::serve::{self, Budget, ServeOptions, Service, TlsSelect};
use fictionet::stdlib::tls::ServerConfig;
use fictionet::stdlib::{ConnError, Connection, icmp, ip, tcp, udp};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, End, Interface, InterfaceExt};
use std::any::Any;
use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[cfg(doc)]
use super::{Limits, Net};

fictionet::cfg_std! {
#[cfg(doc)]
use fictionet::stdlib::httpd;
}

/// At most this many names that have no host are remembered (about 35 MB).
const MAX_UNKNOWN_NAMES: usize = 100_000;

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

/// One connection, accepted on a port of a machine, as a [`PortServer`] gets
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
}

/// Serves connections on one port of a host. [`Host::tcp`] and
/// [`Host::tls`] make one for a [`Service`]; [`httpd::Server`] is HTTP's.
/// A world writes its own for anything else.
pub trait PortServer: Any + Send + Sync {
    /// Serves one connection.
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// The protocols to offer with ALPN when this serves a TLS port, such
    /// as `h2` and `http/1.1`. Default none: the config's own list.
    fn alpn(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Prepares to serve `other`'s DNS `names` at the local endpoint.
    /// This must not change either server. Return a token that commits
    /// the registration without failure, scoped to `local`. Dropping
    /// the token must leave both servers unchanged.
    ///
    /// The first host is offered its own accept. `None` declines sharing:
    /// on an occupied plain port this is an error; on TLS, `other` serves
    /// its names separately and is offered itself. Declining that offer
    /// installs it without a commit. The default shares only with itself.
    /// Subsequent TLS hosts are always offered to the first accept, even
    /// if it declined an earlier host.
    ///
    /// `Net` prepares every port at every address before committing any
    /// sharing. Tokens commit in address and port declaration order.
    /// Several tokens may be prepared before any commits, so a token
    /// must also work after earlier tokens have committed.
    fn prepare_share(
        &self,
        local: SocketAddr,
        names: &[String],
        other: &Arc<dyn PortServer>,
    ) -> Option<PreparedShare> {
        let _ = (local, names);
        std::ptr::addr_eq(self as *const Self, Arc::as_ptr(other))
            .then(|| PreparedShare::new(|| {}))
    }
}

/// A side-effect-free sharing decision from [`PortServer::prepare_share`].
/// Dropping it cancels the registration. Only [`commit`](Self::commit)
/// changes the server.
pub struct PreparedShare(Box<dyn FnOnce() + Send>);

impl PreparedShare {
    /// Captures an infallible commit, including its local endpoint and
    /// the prepared registration. The closure runs only on commit.
    pub fn new(commit: impl FnOnce() + Send + 'static) -> PreparedShare {
        PreparedShare(Box::new(commit))
    }

    /// Applies the prepared registration. This must not fail or reject it.
    pub fn commit(self) {
        (self.0)();
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
        ServiceAccept {
            state,
            make,
            opts,
            open: Arc::default(),
        }
    }
}

impl<S, M> PortServer for ServiceAccept<S, M>
where
    S: Service,
    M: Fn() -> S + Send + Sync + 'static,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let Some(guard) = connection_limit(&fcx, &arrival.info, &self.open, self.opts.max_conns)
        else {
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
        let (conn, info) = (arrival.conn, arrival.info);
        Box::pin(async move {
            let _ = serve::connection(&fcx, conn, info, &mut service, &state, &opts).await;
        })
    }
}

/// Starts serving a UDP port of a machine: the socket, its address,
/// and who the sandboxes are.
pub(super) type UdpStart =
    Arc<dyn Fn(&Cx, udp::Socket, SocketAddr, Option<serve::SandboxOf>) + Send + Sync>;

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
pub(super) enum PortSpec {
    Tcp(Arc<dyn PortServer>),
    Tls {
        sni: Sni,
        config: ConfigFor,
        accept: Arc<dyn PortServer>,
    },
    Udp(UdpStart),
}

/// One host: its addresses, DNS names and services. See [`Net::host`] and
/// [`Net::resolve`].
#[derive(Clone)]
pub struct Host {
    pub(super) label: String,
    pub(super) names: Vec<String>,
    at: Option<Ipv4Addr>,
    at_v6: Option<Ipv6Addr>,
    family: Family,
    pub(super) ports: Vec<(u16, PortSpec)>,
    lan: Option<String>,
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
            lan: None,
        }
    }

    /// Serves the host at `addr`, IPv4 or IPv6, which sets its address of
    /// that family. Two calls give it both. A family without `at` gets a
    /// free address from that family's range.
    ///
    /// The address must be one a host can have, outside the sandboxes'
    /// subnet: not unspecified, broadcast, multicast or loopback, and for
    /// IPv6 not link-local or IPv4-mapped. If it is not, [`Net::start`]
    /// fails; a host made by [`Net::resolve`] is not served, and its name
    /// gets NXDOMAIN.
    pub fn at(self, addr: impl Into<IpAddr>) -> Host {
        match addr.into() {
            IpAddr::V4(a) => Host {
                at: Some(a),
                ..self
            },
            IpAddr::V6(a) => Host {
                at_v6: Some(a),
                ..self
            },
        }
    }

    /// Places the host on the LAN called `lan` ([`Net::lan`]): it has one
    /// address, of the LAN's family, inside the LAN's prefix (the one given
    /// with [`at`](Self::at), or a free one), and shares the subnet with
    /// the LAN's other hosts and members.
    pub fn on(self, lan: &str) -> Host {
        Host {
            lan: Some(lan.to_owned()),
            ..self
        }
    }

    /// Gives the host only an IPv4 address.
    pub fn ipv4_only(self) -> Host {
        Host {
            family: Family::V4,
            ..self
        }
    }

    /// Gives the host only an IPv6 address.
    pub fn ipv6_only(self) -> Host {
        Host {
            family: Family::V6,
            ..self
        }
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
    pub fn tcp_with<S, M>(
        self,
        port: u16,
        state: Arc<S::State>,
        make: M,
        opts: ServeOptions,
    ) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decoder as Decode>::Error: Clone + Send,
    {
        self.port_server(port, ServiceAccept::new(state, make, opts))
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
    pub fn port_server(mut self, port: u16, accept: impl PortServer) -> Host {
        self.ports.push((port, PortSpec::Tcp(Arc::new(accept))));
        self
    }

    /// Serves TCP `port` with TLS for the names `sni` gives, with the
    /// config `config_for` returns for each handshake, then `accept`.
    pub fn tls_accept(
        mut self,
        port: u16,
        sni: impl Into<Sni>,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
        accept: impl PortServer,
    ) -> Host {
        let spec = PortSpec::Tls {
            sni: sni.into(),
            config: Arc::new(config_for),
            accept: Arc::new(accept),
        };
        self.ports.push((port, spec));
        self
    }

    /// Serves UDP `port` with one [`Service`] made by `make`, which gets
    /// every datagram ([`serve::datagram`]).
    /// Port zero asks the endpoint to choose a free port ([`udp::Endpoint::bind`]).
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
    pub fn udp_with<S, M>(
        mut self,
        port: u16,
        state: Arc<S::State>,
        make: M,
        opts: ServeOptions,
    ) -> Host
    where
        S: Service,
        M: Fn() -> S + Send + Sync + 'static,
        <S::Decoder as Decode>::Error: Clone + Send,
    {
        let start: UdpStart = Arc::new(move |fcx, socket, local, sandbox| {
            let mut service = make();
            let state = state.clone();
            let mut opts = opts.clone();
            if sandbox.is_some() {
                opts.sandbox = sandbox;
            }
            fcx.spawn(move |fcx| async move {
                Ok(serve::datagram(&fcx, socket, local, &mut service, &state, &opts).await?)
            });
        });
        self.ports.push((port, PortSpec::Udp(start)));
        self
    }
}

/// What a name is known as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Known {
    Host(Placed),
    NoHost,
}

/// What a lookup found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lookup {
    Host(Placed),
    NoHost,
    /// The resolver gave a host, but the network has as many as it may.
    Full,
}

/// Names and machines.
pub(super) struct World {
    pub(super) names: HashMap<String, Known>,
    unknown: usize,
    pub(super) max_unknown: usize,
    pub(super) resolved: usize,
    max_hosts: usize,
    /// Machines in address order for aborting a detached peer.
    pub(super) machines: BTreeMap<IpAddr, Arc<Machine>>,
    pub(super) addresses: Allocator,
}

impl World {
    pub(super) fn new(max_hosts: usize) -> World {
        World {
            names: HashMap::new(),
            unknown: 0,
            max_unknown: MAX_UNKNOWN_NAMES,
            resolved: 0,
            max_hosts,
            machines: BTreeMap::new(),
            addresses: Allocator::default(),
        }
    }

    pub(super) fn free_auto(&mut self, subnet: &Subnet) -> Option<Ipv4Addr> {
        self.addresses.free_auto(subnet, &self.machines)
    }

    pub(super) fn free_auto6(&mut self, subnet: &Subnet6) -> Option<Ipv6Addr> {
        self.addresses.free_auto6(subnet, &self.machines)
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
}

/// Resolves names and publishes hosts through the installation boundary.
pub(super) struct LookupContext<'a> {
    pub(super) world: &'a Mutex<World>,
    pub(super) resolver: Option<&'a Resolver>,
    pub(super) installation: Installation<'a>,
}

impl LookupContext<'_> {
    /// What `name` is. The first lookup of a name no host has runs the
    /// resolver and, for a host, starts its machines.
    pub(super) fn lookup(&self, name: &str) -> Lookup {
        let mut world = self.world.lock();
        if let Some(known) = world.names.get(name) {
            return match known {
                Known::Host(p) => Lookup::Host(*p),
                Known::NoHost => Lookup::NoHost,
            };
        }
        let Some(resolver) = &self.resolver else {
            return Lookup::NoHost;
        };
        let known = match resolver(name) {
            Some(_) if world.resolved >= world.max_hosts => return Lookup::Full,
            Some(mut host) => {
                if !host.names.iter().any(|n| n == name) {
                    host.names.insert(0, name.to_owned());
                }
                let label = host.label.clone();
                match self.installation.place(&mut world, host) {
                    Ok(p) => Known::Host(p),
                    Err(e) => {
                        let event = Event::new("net", "error")
                            .level(Level::Notice)
                            .summary(format!("host {label} for {name}: {e}"))
                            .field("name", name)
                            .field("error", e);
                        self.installation.admission.hooks.record(
                            self.installation.fcx,
                            &ConnInfo::default(),
                            event,
                        );
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
}

/// The capabilities needed to prepare and publish a host's routes and services.
pub(super) struct Installation<'a> {
    pub(super) fcx: &'a Cx,
    pub(super) subnet: Subnet,
    pub(super) subnet6: Option<Subnet6>,
    pub(super) router: &'a Router<Box<dyn Interface>>,
    pub(super) lans: &'a BTreeMap<String, LanSeg>,
    pub(super) admission: Admission,
    pub(super) handshake: Duration,
}

impl Installation<'_> {
    /// Gives `host` its addresses and machines, and adds its services.
    /// Fails if an address given with `at` cannot be served, it ends up
    /// with no address, or a service cannot be added.
    pub(super) fn place(&self, world: &mut World, host: Host) -> Result<Placed, String> {
        let automatic = (world.addresses.next_auto, world.addresses.next_auto6);
        let result = self.place_inner(world, host);
        if result.is_err() {
            (world.addresses.next_auto, world.addresses.next_auto6) = automatic;
        }
        result
    }

    /// Prepares `host` at every address, then commits it. A failure
    /// leaves no machine, route, port or task, but may have taken
    /// automatic addresses, which `place` gives back.
    fn place_inner(&self, world: &mut World, host: Host) -> Result<Placed, String> {
        if let Some(name) = &host.lan {
            return self.place_on_lan(world, name, &host);
        }
        for a in host
            .at
            .map(IpAddr::V4)
            .into_iter()
            .chain(host.at_v6.map(IpAddr::V6))
        {
            if let Some((name, _)) = self.lans.iter().find(|(_, l)| l.prefix.contains(a)) {
                return Err(format!(
                    "{a} is on LAN {name}: place the host there with Host::on"
                ));
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
        let label = host
            .names
            .first()
            .cloned()
            .unwrap_or_else(|| host.label.clone());
        let addrs = placed
            .v4
            .map(IpAddr::V4)
            .into_iter()
            .chain(placed.v6.map(IpAddr::V6));
        let prepared = addrs
            .map(|addr| {
                let machine = Machine::stage(self, addr, &label, world.machines.get(&addr));
                let ports = machine.machine.prepare(&host)?;
                Ok((machine, ports))
            })
            .collect::<Result<Vec<_>, String>>()?;
        for (mut machine, ports) in prepared {
            if let Some(side) = machine.route.take() {
                self.router
                    .add(host_prefix(machine.machine.addr), Box::new(side));
            }
            machine.commit(world, ports);
        }
        Ok(placed)
    }

    /// Places `host` on the LAN `name`, at its `at` address of the LAN's
    /// family or the first free one from the LAN's second address up.
    fn place_on_lan(&self, world: &mut World, name: &str, host: &Host) -> Result<Placed, String> {
        let seg = self
            .lans
            .get(name)
            .ok_or_else(|| format!("there is no LAN called {name}"))?;
        let v4 = seg.prefix.addr.is_ipv4();
        let given = if v4 {
            host.at.map(IpAddr::V4)
        } else {
            host.at_v6.map(IpAddr::V6)
        };
        let free = |a: IpAddr| a != seg.dns && !seg.members.contains(&a);
        let addr = match given {
            Some(a)
                if seg.prefix.contains(a)
                    && a != seg.prefix.addr
                    && free(a)
                    && !a.is_multicast() =>
            {
                a
            }
            Some(a) => return Err(format!("{a} is not a free address on LAN {name}")),
            None => (2..1u128 << 16)
                .map_while(|n| seg.prefix.nth(n))
                .filter(|a| seg.prefix.contains(*a))
                .find(|a| free(*a) && !world.machines.contains_key(a))
                .ok_or_else(|| format!("LAN {name} has no free address left"))?,
        };
        let label = host.names.first().unwrap_or(&host.label);
        let mut machine = Machine::stage(self, addr, label, world.machines.get(&addr));
        let ports = machine.machine.prepare(host)?;
        // Joining is the last fallible step. No service or task has started.
        if let Some(side) = machine.route.take() {
            seg.lan
                .add(addr, Box::new(side), None)
                .map_err(|e| e.to_string())?;
        }
        machine.commit(world, ports);
        Ok(match addr {
            IpAddr::V4(a) => Placed {
                v4: Some(a),
                v6: None,
            },
            IpAddr::V6(a) => Placed {
                v4: None,
                v6: Some(a),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Machines

/// Read-only host routing queries and transport cleanup for attachments.
#[derive(Clone)]
pub(super) struct Machines {
    world: Arc<Mutex<World>>,
}

impl Machines {
    pub(super) fn new(world: Arc<Mutex<World>>) -> Self {
        Self { world }
    }

    pub(super) fn contains(&self, addr: IpAddr) -> bool {
        self.world.lock().machines.contains_key(&addr)
    }

    pub(super) fn closed(&self, addr: IpAddr, packet: &[u8]) -> Option<bool> {
        let machine = self.world.lock().machines.get(&addr).cloned()?;
        Some(answered_closed(packet, |proto, port| {
            if proto == PROTO_TCP {
                machine.serves_tcp(port)
            } else {
                machine.serves_udp(port)
            }
        }))
    }

    pub(super) fn abort_peers(&self, addrs: &[IpAddr]) {
        let machines: Vec<_> = self.world.lock().machines.values().cloned().collect();
        for machine in machines {
            for addr in addrs {
                machine.tcp.abort_peer(*addr);
            }
        }
    }
}

/// Peer admission and sandbox identity shared by ordinary services and DNS.
#[derive(Clone)]
pub(super) struct Admission {
    pub(super) peers: Arc<Peers>,
    pub(super) hooks: Arc<Hooks>,
}

impl Admission {
    pub(super) fn admit(&self, fcx: &Cx, conn: tcp::TcpConnection) -> Option<tcp::TcpConnection> {
        let Some(guard) = self.peers.enter(conn.peer_addr().ip()) else {
            too_many(fcx, &self.hooks, &conn);
            conn.reset();
            return None;
        };
        conn.hold_until_gone(Box::new(guard));
        Some(conn)
    }

    pub(super) fn sandbox(&self) -> serve::SandboxOf {
        let hooks = self.hooks.clone();
        Arc::new(move |addr| Some(hooks.sandbox_at(addr)))
    }
}

/// Open connections by peer address, for
/// [`Limits::connections_per_peer`].
pub(super) struct Peers {
    open: Mutex<HashMap<IpAddr, usize>>,
    max: usize,
}

impl Peers {
    pub(super) fn new(max: usize) -> Arc<Peers> {
        Arc::new(Peers {
            open: Mutex::default(),
            max,
        })
    }

    pub(super) fn enter(self: &Arc<Self>, peer: IpAddr) -> Option<PeerGuard> {
        let mut map = self.open.lock();
        let n = map.entry(peer).or_default();
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(PeerGuard {
            peers: self.clone(),
            peer,
        })
    }
}

pub(super) struct PeerGuard {
    peers: Arc<Peers>,
    peer: IpAddr,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        let mut map = self.peers.open.lock();
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
    accept: Arc<dyn PortServer>,
    alpn: Vec<Vec<u8>>,
    last: Mutex<Option<(Arc<ServerConfig>, Arc<ServerConfig>)>>,
}

impl TlsName {
    fn config(&self, fcx: &Cx) -> Arc<ServerConfig> {
        let given = (self.config)(fcx);
        if self.alpn.is_empty() {
            return given;
        }
        let mut last = self.last.lock();
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
    plain: RwLock<Option<Arc<dyn PortServer>>>,
    /// TLS by SNI; the empty name is "any name".
    tls: RwLock<TlsNames>,
}

/// TLS names and the first installed handler offered subsequent services.
#[derive(Default)]
struct TlsNames {
    by_name: HashMap<String, Arc<TlsName>>,
    first: Option<Arc<dyn PortServer>>,
}

fn tls_names(sni: &Sni, names: &[String], port: u16) -> Result<Vec<String>, String> {
    match sni {
        Sni::Any => Ok(vec![String::new()]),
        Sni::Name(n) => Ok(vec![n.clone()]),
        Sni::Names if names.is_empty() => Err(format!(
            "TLS on port {port} is for the host's names, and it has none"
        )),
        Sni::Names => Ok(names.to_vec()),
    }
}

/// One TCP port as this preparation leaves it: the installed or new port,
/// the listener staged for a new one, and the handlers and names reserved.
struct PortPlan {
    port: Arc<Port>,
    listener: Option<tcp::Listener>,
    plain: Option<Arc<dyn PortServer>>,
    first_tls: Option<Arc<dyn PortServer>>,
    names: HashSet<String>,
}

/// One service with its socket and sharing decision ready to commit.
enum PreparedPort {
    Udp {
        number: u16,
        socket: udp::Socket,
        start: UdpStart,
    },
    Tcp {
        number: u16,
        port: Arc<Port>,
        listener: Option<tcp::Listener>,
        service: PreparedTcp,
        share: Option<PreparedShare>,
    },
}

enum PreparedTcp {
    Plain(Arc<dyn PortServer>),
    Tls {
        accept: Arc<dyn PortServer>,
        entries: Vec<(String, Arc<TlsName>)>,
    },
}

/// A new machine has no published route or running tasks until commit.
struct PreparedMachine {
    machine: Arc<Machine>,
    route: Option<End>,
    start: Option<Box<dyn FnOnce() + Send>>,
}

impl PreparedMachine {
    fn commit(self, world: &mut World, ports: Vec<PreparedPort>) {
        if let Some(start) = self.start {
            start();
            world
                .machines
                .insert(self.machine.addr, self.machine.clone());
        }
        self.machine.add(ports);
    }
}

/// One address with its services.
pub(super) struct Machine {
    fcx: Cx,
    addr: IpAddr,
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    ports: Mutex<HashMap<u16, Arc<Port>>>,
    udp_ports: Mutex<HashSet<u16>>,
    admission: Admission,
    handshake: Duration,
}

impl Machine {
    /// Builds a machine without publishing its route or starting its tasks.
    fn stage(
        installation: &Installation<'_>,
        addr: IpAddr,
        label: &str,
        existing: Option<&Arc<Machine>>,
    ) -> PreparedMachine {
        if let Some(machine) = existing {
            return PreparedMachine {
                machine: machine.clone(),
                route: None,
                start: None,
            };
        }
        let fcx = installation.fcx.group(format!("{label} ({addr})"));
        let (router_side, side) = link();
        let ((tcp, udp, icmp, _other), split) = ip::prepare_split_protocols(&fcx, side);
        let (tcp, tcp_task) = tcp::prepare_endpoint(&fcx, tcp, addr, tcp::Options::default());
        let (udp, udp_task) = udp::prepare_endpoint(&fcx, udp, addr);
        let machine = Arc::new(Machine {
            fcx: fcx.clone(),
            addr,
            tcp,
            udp,
            ports: Mutex::new(HashMap::new()),
            udp_ports: Mutex::new(HashSet::new()),
            admission: installation.admission.clone(),
            handshake: installation.handshake,
        });
        PreparedMachine {
            machine,
            route: Some(router_side),
            start: Some(Box::new(move || {
                split.start(&fcx);
                tcp_task.start(&fcx);
                udp_task.start(&fcx);
                fcx.spawn(move |fcx| pings(fcx, icmp, addr));
            })),
        }
    }

    /// Checks services against installed ports and earlier preparations.
    fn prepare(&self, host: &Host) -> Result<Vec<PreparedPort>, String> {
        let addr = self.addr;
        let mut ports = HashMap::<u16, PortPlan>::new();
        let mut udp_ports = HashSet::new();
        let mut prepared = Vec::new();
        for (number, spec) in &host.ports {
            let local = SocketAddr::new(addr, *number);
            if let PortSpec::Udp(start) = spec {
                if !udp_ports.insert(*number) || self.udp_ports.lock().contains(number) {
                    return Err(format!("UDP port {number} at {addr} is already served"));
                }
                let socket = self
                    .udp
                    .bind(*number)
                    .map_err(|e| format!("UDP port {number} at {addr}: {e}"))?;
                prepared.push(PreparedPort::Udp {
                    number: *number,
                    socket,
                    start: start.clone(),
                });
                continue;
            }
            if *number == 0 {
                return Err(format!(
                    "TCP port {number} at {addr}: TCP port 0 cannot be listened on"
                ));
            }
            let port = match ports.entry(*number) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let existing = self.ports.lock().get(number).cloned();
                    let listener = if existing.is_none() {
                        Some(
                            self.tcp
                                .listen(*number)
                                .map_err(|e| format!("TCP port {number} at {addr}: {e}"))?,
                        )
                    } else {
                        None
                    };
                    let port = existing.unwrap_or_default();
                    let plain = port.plain.read().unwrap_or_else(|e| e.into_inner()).clone();
                    let first_tls = port
                        .tls
                        .read()
                        .unwrap_or_else(|e| e.into_inner())
                        .first
                        .clone();
                    entry.insert(PortPlan {
                        port,
                        listener,
                        plain,
                        first_tls,
                        names: HashSet::new(),
                    })
                }
            };
            let tls = port.port.tls.read().unwrap_or_else(|e| e.into_inner());
            let (service, share) = match spec {
                PortSpec::Udp(_) => unreachable!(),
                PortSpec::Tcp(accept) => {
                    if !port.names.is_empty() || !tls.by_name.is_empty() {
                        return Err(format!(
                            "TCP port {number} at {addr} serves TLS, and cannot serve without it too"
                        ));
                    }
                    let (served_by, share) = match &port.plain {
                        None => (
                            accept.clone(),
                            accept.prepare_share(local, &host.names, accept),
                        ),
                        Some(front) => {
                            let share = front.prepare_share(local, &host.names, accept)
                                .ok_or_else(|| format!(
                                    "TCP port {number} at {addr} is already served by another host"
                                ))?;
                            (front.clone(), Some(share))
                        }
                    };
                    port.plain = Some(served_by.clone());
                    (PreparedTcp::Plain(served_by), share)
                }
                PortSpec::Tls {
                    sni,
                    config,
                    accept,
                } => {
                    if port.plain.is_some() {
                        return Err(format!(
                            "TCP port {number} at {addr} serves without TLS, and cannot serve TLS too"
                        ));
                    }
                    let names = tls_names(sni, &host.names, *number)?;
                    if let Some(taken) = names
                        .iter()
                        .find(|n| port.names.contains(*n) || tls.by_name.contains_key(*n))
                    {
                        let name = if taken.is_empty() {
                            "any name"
                        } else {
                            taken.as_str()
                        };
                        return Err(format!("TLS port {number} at {addr} already serves {name}"));
                    }
                    let shared = port.first_tls.as_ref().and_then(|front| {
                        front
                            .prepare_share(local, &host.names, accept)
                            .map(|share| (front.clone(), Some(share)))
                    });
                    let (served_by, share) = shared.unwrap_or_else(|| {
                        (
                            accept.clone(),
                            accept.prepare_share(local, &host.names, accept),
                        )
                    });
                    port.first_tls.get_or_insert_with(|| served_by.clone());
                    port.names.extend(names.iter().cloned());
                    let entries = names
                        .into_iter()
                        .map(|name| {
                            let entry = TlsName {
                                config: config.clone(),
                                accept: served_by.clone(),
                                alpn: served_by.alpn(),
                                last: Mutex::new(None),
                            };
                            (name, Arc::new(entry))
                        })
                        .collect();
                    (
                        PreparedTcp::Tls {
                            accept: served_by,
                            entries,
                        },
                        share,
                    )
                }
            };
            prepared.push(PreparedPort::Tcp {
                number: *number,
                port: port.port.clone(),
                listener: port.listener.take(),
                service,
                share,
            });
        }
        Ok(prepared)
    }

    /// Installs the prepared services in declaration order without failure.
    fn add(self: &Arc<Self>, prepared: Vec<PreparedPort>) {
        let sandbox = Some(self.admission.sandbox());
        for prepared in prepared {
            match prepared {
                PreparedPort::Udp {
                    number,
                    socket,
                    start,
                } => {
                    self.udp_ports.lock().insert(number);
                    start(
                        &self.fcx,
                        socket,
                        SocketAddr::new(self.addr, number),
                        sandbox.clone(),
                    );
                }
                PreparedPort::Tcp {
                    number,
                    port,
                    listener,
                    service,
                    share,
                } => {
                    if let Some(share) = share {
                        share.commit();
                    }
                    match service {
                        PreparedTcp::Plain(accept) => {
                            *port.plain.write().unwrap_or_else(|e| e.into_inner()) = Some(accept);
                        }
                        PreparedTcp::Tls { accept, entries } => {
                            let mut tls = port.tls.write().unwrap_or_else(|e| e.into_inner());
                            tls.first.get_or_insert(accept);
                            tls.by_name.extend(entries);
                        }
                    }
                    if let Some(listener) = listener {
                        self.ports.lock().insert(number, port.clone());
                        let machine = self.clone();
                        self.fcx
                            .spawn(move |fcx| accept(fcx, listener, machine, port));
                    }
                }
            }
        }
    }

    /// Whether TCP `port` is open here.
    pub(super) fn serves_tcp(&self, port: u16) -> bool {
        self.ports.lock().contains_key(&port)
    }

    /// Whether UDP `port` is open here.
    pub(super) fn serves_udp(&self, port: u16) -> bool {
        self.udp_ports.lock().contains(&port)
    }
}

/// The route to one address: `/32` or `/128`.
pub(super) fn host_prefix(addr: IpAddr) -> Prefix {
    Prefix {
        addr,
        len: if addr.is_ipv4() { 32 } else { 128 },
    }
}

/// Records that a connection was reset for being past its sandbox's
/// limit.
pub(super) fn too_many(fcx: &Cx, hooks: &Hooks, conn: &tcp::TcpConnection) {
    let (peer, local) = (conn.peer_addr(), conn.local_addr());
    let event = blocked_event(
        BlockedWhy::TooManyConnections,
        Some(PROTO_TCP),
        Some(peer.ip()),
        Some(local.ip()),
    );
    hooks.blocked(
        fcx,
        &sandbox_only(hooks.sandbox_at(peer.ip())),
        (event, port_detail(Some(local.port()))),
    );
}

/// Accepts connections on one port of a machine. Each is served in its own
/// region.
async fn accept(
    fcx: Cx,
    mut listener: tcp::Listener,
    machine: Arc<Machine>,
    port: Arc<Port>,
) -> fictionet::Result {
    loop {
        match listener.accept(&fcx).await {
            Ok(conn) => {
                let admission = machine.admission.clone();
                let Some(conn) = admission.admit(&fcx, conn) else {
                    continue;
                };
                let hooks = &admission.hooks;
                let sandbox = Some(hooks.sandbox_at(conn.peer_addr().ip()));
                let info = ConnInfo::new(hooks.next_conn(), conn.local_addr(), conn.peer_addr())
                    .from_sandbox(sandbox);
                let accepted = fcx.now();
                let handshake = machine.handshake;
                let port = port.clone();
                fcx.spawn(move |fcx| async move {
                    let _ = fcx
                        .region(move |fcx| async move {
                            connection(fcx, conn, info, accepted, port, admission, handshake).await;
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
async fn connection(
    fcx: Cx,
    conn: tcp::TcpConnection,
    info: ConnInfo,
    accepted: Instant,
    port: Arc<Port>,
    admission: Admission,
    handshake: Duration,
) {
    let hooks = admission.hooks;
    let socket = conn.gone_watch();
    let sandbox_id = info.sandbox.as_ref().map(|s| s.id);
    let budget = sandbox_id.and_then(|id| hooks.budget(id));
    let arrival = |conn: Box<dyn Connection>, info: ConnInfo| Arrival {
        conn,
        info,
        socket: socket.clone(),
        budget: budget.clone(),
        handshake,
    };
    let has_tls = !port
        .tls
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .by_name
        .is_empty();
    if !has_tls {
        let plain = port.plain.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(accept) = plain {
            accept
                .serve(fcx.clone(), arrival(Box::new(conn), info))
                .await;
        }
        return;
    }
    let names = port.clone();
    let chosen: Arc<Mutex<Option<Arc<TlsName>>>> = Arc::default();
    let pick = chosen.clone();
    let select: TlsSelect = Arc::new(move |sni, fcx| {
        let tls = names.tls.read().unwrap_or_else(|e| e.into_inner());
        let name = sni
            .and_then(|n| tls.by_name.get(n))
            .or_else(|| tls.by_name.get(""))?
            .clone();
        let config = name.config(fcx);
        *pick.lock() = Some(name);
        Some(config)
    });
    let detached = || sandbox_id.is_some_and(|id| !hooks.is_attached(id));
    let deadline = accepted + handshake;
    let Ok((tls, info)) = serve::accept_tls(&fcx, conn, &info, &select, deadline, detached).await
    else {
        return;
    };
    let Some(name) = chosen.lock().take() else {
        return;
    };
    name.accept
        .serve(fcx.clone(), arrival(Box::new(tls), info))
        .await;
}

/// Answers pings to `addr`.
pub(super) async fn pings(fcx: Cx, mut icmp: End, addr: IpAddr) -> fictionet::Result {
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

fictionet::cfg_std! {
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{MAX_HOSTS, Net};

    #[test]
    fn tls_sharing_uses_the_first_installed_accept() {
        struct Offers(&'static str, Arc<Mutex<Vec<&'static str>>>);
        impl PortServer for Offers {
            fn serve(&self, _: Cx, _: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                Box::pin(async {})
            }
            fn prepare_share(
                &self,
                local: SocketAddr,
                _: &[String],
                _: &Arc<dyn PortServer>,
            ) -> Option<PreparedShare> {
                assert_eq!(local, "203.0.113.8:443".parse().unwrap());
                self.1.lock().push(self.0);
                None
            }
        }
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let log = Arc::new(Mutex::new(Vec::new()));
                let mut net = Net::new().ipv4_only();
                for name in ["z.test", "a.test", "m.test", "b.test", "y.test"] {
                    net = net.host(name, |h| {
                        h.at(Ipv4Addr::new(203, 0, 113, 8)).tls_accept(
                            443,
                            name,
                            |_| panic!("no handshake"),
                            Offers(name, log.clone()),
                        )
                    });
                }
                let (_attacher, attachments) = fictionet::attachments();
                net.start(&fcx, attachments)?;
                assert_eq!(
                    *log.lock(),
                    [
                        "z.test", "z.test", "a.test", "z.test", "m.test", "z.test", "b.test",
                        "z.test", "y.test"
                    ]
                );
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
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
            w.remember(
                &format!("s{i}.test"),
                Known::Host(Placed {
                    v4: Some(Ipv4Addr::new(198, 18, 0, i + 1)),
                    v6: None,
                }),
            );
        }
        assert_eq!((w.names.len(), w.resolved), (13, 10));
        let mut w = World::new(MAX_HOSTS);
        w.remember(&"\\255".repeat(64), Known::NoHost);
        assert!(w.names.is_empty());
    }
}
}
