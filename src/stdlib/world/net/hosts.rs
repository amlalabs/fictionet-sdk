use super::addresses::{Allocator, Placed, Subnet, Subnet6, may_serve_v4, may_serve_v6};
use super::dns::HOST_TTL;
use super::{Hooks, LanSeg, Limits, link, normalize};
use fictionet::stdlib::layer::{Budget, ByteStream, Datagrams, Layer, Top};
use fictionet::stdlib::network::route::{Prefix, Router};
use fictionet::stdlib::network::{ConnError, Connection, icmp, ip, tcp, udp};
use fictionet::stdlib::network::{ConnInfo, Transport};
use fictionet::stdlib::protocols::dns::label_count;
use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RecordSet};
use fictionet::stdlib::services::dns::resolver::{Config, LocalZone};
use fictionet::stdlib::services::dns::zone::{
    Denied, EmptyApex, Fact, Node, Revision, Transparent, View, ZoneData, additional_targets,
};
use fictionet::stdlib::services::stack::{
    self, Boxed, Counted, Job, StackError, StreamEnd, StreamLimits,
};
use fictionet::stdlib::services::tls::{self, HandshakeError, ServerConfig};
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
use super::{Net, NetHandle};

#[cfg(doc)]
use fictionet::stdlib::web::httpd;

// ---------------------------------------------------------------------------
// Hosts

/// Which address families a host has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Both,
    V4,
    V6,
}

/// The TLS config for one handshake, once it is picked.
pub type ConfigFuture = Pin<Box<dyn Future<Output = Arc<ServerConfig>> + Send>>;

/// Picks the TLS config for one handshake, with randomness from the `Cx`.
/// Picking may take time (a check of the real host, say): only that
/// handshake waits, up to its deadline, while the world goes on.
pub type ConfigFor = Arc<dyn Fn(&Cx) -> ConfigFuture + Send + Sync>;

/// One connection, accepted on a port of a machine, as a [`PortServer`] gets
/// it.
pub struct Arrival {
    /// The network default for HTTP exchange observations.
    pub http_observe: Option<fictionet::stdlib::web::httpd::Observe>,
    /// The connection: after the TLS handshake, on a TLS port.
    pub conn: Box<dyn Connection>,
    /// Who it is from, and where it arrived.
    pub info: ConnInfo,
    /// The TCP socket underneath, to keep a count until it is gone
    /// ([`tcp::GoneWatch::hold_until_gone`]) or to reset it.
    pub socket: tcp::GoneWatch,
    /// The budget of the sandbox it came from. `None` if it came from no
    /// attached sandbox, such as a route ([`Net::route`]).
    pub budget: Option<Budget>,
    /// The network's limits and timers ([`Net::limits`]), such as
    /// [`Limits::handshake`], how long a client has to send its first
    /// bytes, and [`Limits::dns_tcp_idle`] for a port that serves DNS.
    pub limits: Limits,
}

/// A connection on a TLS port whose handshake is done, before anything
/// serves it: what an [`Arrival`] holds but the connection, which is the
/// TLS layer's to carry. [`PortServer::over_tls`] gets one.
pub struct Opening {
    /// The network default for HTTP exchange observations.
    pub http_observe: Option<fictionet::stdlib::web::httpd::Observe>,
    /// Who it is from, where it arrived, and the name and protocol TLS
    /// settled ([`ConnInfo::sni`], [`ConnInfo::alpn`]).
    pub info: ConnInfo,
    /// The TCP socket underneath.
    pub socket: tcp::GoneWatch,
    /// The budget of the sandbox it came from, which the whole stack is
    /// charged to.
    pub budget: Option<Budget>,
    /// The network's limits and timers.
    pub limits: Limits,
}

impl Opening {
    /// The arrival of `conn`, which carries the decrypted bytes.
    pub fn arrive(self, conn: Box<dyn Connection>) -> Arrival {
        Arrival {
            http_observe: self.http_observe,
            conn,
            info: self.info,
            socket: self.socket,
            budget: self.budget,
            limits: self.limits,
        }
    }
}

/// Serves connections on one port of a host. [`Host::tcp_stack`] makes one
/// for a layer stack; [`httpd::Server`] is HTTP's.
/// A world writes its own for anything else.
pub trait PortServer: Any + Send + Sync {
    /// Serves one connection.
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// The layer that serves one connection on a TLS port once its
    /// handshake is done, over the decrypted stream, in the same stack as
    /// TLS. Default `None`: [`serve`](Self::serve) gets the decrypted stream
    /// as a connection, through a [`Tunnel`](stack::Tunnel).
    fn over_tls(&self, fcx: &Cx, opening: &Opening) -> Option<Boxed> {
        let _ = (fcx, opening);
        None
    }

    /// TLS implementation for this listener. The first TLS server installed
    /// at an address and port chooses it for every name sharing that listener.
    /// Certificates remain per name; application selection uses each name's
    /// server (which may be shared through `prepare_share`).
    fn tls_factory(&self) -> tls::Factory {
        tls::Factory::default()
    }

    /// Pending connection limit for this port. The first server opening
    /// a shared port chooses its limit; `None` uses the host's TCP default.
    fn backlog(&self) -> Option<usize> {
        None
    }

    /// The protocols to offer with ALPN when this serves a TLS port, such
    /// as `h2` and `http/1.1`. Default none: the config's own list.
    fn alpn(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// How the port answers each connection attempt's handshake
    /// ([`tcp::Listener::answer`]), such as an MPTCP server with
    /// MP_CAPABLE. Asked when the port's listener opens, and again when
    /// another server would share the port. A SYN comes
    /// before anything that tells hosts apart, so a server that answers
    /// cannot share its port with another host: placing one there fails.
    /// Default `None`: the endpoint's plain handshake.
    fn answer(&self) -> Option<Box<dyn tcp::Answer>> {
        None
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
pub struct PreparedShare {
    commit: Box<dyn FnOnce() + Send>,
    tls_server: Option<Arc<dyn PortServer>>,
}

impl PreparedShare {
    /// Captures an infallible commit, including its local endpoint and
    /// the prepared registration. The closure runs only on commit.
    pub fn new(commit: impl FnOnce() + Send + 'static) -> PreparedShare {
        PreparedShare {
            commit: Box::new(commit),
            tls_server: None,
        }
    }

    /// Chooses the application server for these TLS names after sharing.
    /// This server can retain shared routing while choosing its own ALPN
    /// protocols and application. Plain connections still use the first
    /// server; the TLS implementation also remains the listener's first.
    pub fn tls_server(mut self, server: Arc<dyn PortServer>) -> Self {
        self.tls_server = Some(server);
        self
    }

    /// Applies the prepared registration. This must not fail or reject it.
    pub fn commit(self) {
        (self.commit)();
    }
}

/// The connections a port served with [`Host::tcp_stack`] serves at once.
pub const DEFAULT_MAX_CONNS: usize = 64;

/// Serves a layer stack made fresh for each connection.
struct StackAccept<M> {
    make: M,
    max_conns: usize,
    limits: StreamLimits,
    open: Arc<AtomicUsize>,
}

impl<L, M> PortServer for StackAccept<M>
where
    L: Layer<Lower = ByteStream, Upper = Top> + Send + 'static,
    L::Work: Job<Done = L::Done>,
    L::Report: Send,
    L::Done: Send,
    L::Error: Send,
    M: Fn(&ConnInfo) -> L + Send + Sync + 'static,
{
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let Some(guard) = Counted::enter(&self.open, self.max_conns) else {
            arrival.socket.reset();
            return Box::pin(async {});
        };
        arrival.socket.hold_until_gone(Box::new(guard));
        let layer = (self.make)(&arrival.info);
        let budget = arrival.budget.unwrap_or_else(Budget::unlimited);
        let (conn, info, socket, limits) =
            (arrival.conn, arrival.info, arrival.socket, self.limits);
        Box::pin(async move {
            let ended = stack::stream(&fcx, conn, &info, layer, budget, limits, |_| {});
            if let Ok(StreamEnd::Reset) = ended.await {
                socket.reset();
            }
        })
    }
}

/// Starts serving a UDP port of a machine: the socket and its address.
pub(super) type UdpStart = Arc<dyn Fn(&Cx, udp::Socket, SocketAddr) + Send + Sync>;

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

/// One host: its addresses, DNS names, services and programs. See
/// [`Net::host`] and [`NetHandle::add_host`].
#[derive(Clone)]
pub struct Host {
    pub(super) label: String,
    pub(super) names: Vec<String>,
    at: Option<Ipv4Addr>,
    at_v6: Option<Ipv6Addr>,
    family: Family,
    pub(super) ports: Vec<(u16, PortSpec)>,
    lan: Option<super::Lan>,
    tcp_options: tcp::Options,
    programs: Vec<Arc<dyn Program>>,
    delay: Option<Duration>,
    icmp_options: icmp::Options,
    udp_settings: udp::Settings,
}

impl Host {
    /// A host called `label`, with no names or services.
    pub fn new(label: &str) -> Host {
        Host {
            label: label.to_owned(),
            names: Vec::new(),
            at: None,
            at_v6: None,
            family: Family::Both,
            ports: Vec::new(),
            lan: None,
            tcp_options: tcp::Options::default(),
            programs: Vec::new(),
            delay: None,
            icmp_options: icmp::Options::default(),
            udp_settings: udp::Settings::default(),
        }
    }

    /// Sets transport choices for this host's TCP endpoints.
    pub fn tcp_options(mut self, options: tcp::Options) -> Self {
        self.tcp_options = options;
        self
    }

    /// Sets this host's echo and UDP error reply choices.
    pub fn icmp_options(mut self, options: icmp::Options) -> Self {
        self.icmp_options = options;
        self
    }

    /// Sets the choices for this host's UDP endpoints.
    pub fn udp_settings(mut self, settings: udp::Settings) -> Self {
        self.udp_settings = settings;
        self
    }

    /// Serves the host at `addr`, IPv4 or IPv6, which sets its address of
    /// that family. Two calls give it both. A family without `at` gets a
    /// free address from that family's range.
    ///
    /// The address must be one a host can have, outside the sandboxes'
    /// subnet: not unspecified, broadcast, multicast or loopback, and for
    /// IPv6 not link-local or IPv4-mapped. If it is not, [`Net::start`]
    /// fails, and so does [`NetHandle::add_host`].
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
    pub fn on(self, lan: &super::Lan) -> Host {
        Host {
            lan: Some(lan.clone()),
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

    /// Declares `name` for the host: the gateway's resolver answers it with
    /// the host's addresses (see [`Declared`]). A host can have many names;
    /// its HTTP sites and TLS services for [`Sni::Names`] are served under
    /// each.
    pub fn dns_name(mut self, name: &str) -> Host {
        self.names.push(normalize(name));
        self
    }

    /// Serves TCP `port` with `accept`.
    pub fn port_server(mut self, port: u16, accept: impl PortServer) -> Host {
        self.ports.push((port, PortSpec::Tcp(Arc::new(accept))));
        self
    }

    /// Serves TCP `port` with TLS for the names `sni` gives, with the
    /// config `config_for` returns for each handshake, then `accept`.
    /// The default composition is `Chain<TlsLayer, Later<Boxed>>` through
    /// `Secure`; `accept.over_tls` constructs the application in the box.
    /// The first TLS server at an address and port supplies the listener's
    /// [`PortServer::tls_factory`], including for names installed later.
    pub fn tls_accept(
        self,
        port: u16,
        sni: impl Into<Sni>,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
        accept: impl PortServer,
    ) -> Host {
        self.tls_accept_when(
            port,
            sni,
            move |fcx| std::future::ready(config_for(fcx)),
            accept,
        )
    }

    /// [`tls_accept`](Self::tls_accept) with a config that may take time
    /// to pick: each handshake waits for its own, up to its deadline.
    /// Uses the same `Chain<TlsLayer, Later<Boxed>>` default composition
    /// and listener-level factory rule as [`tls_accept`](Self::tls_accept).
    pub fn tls_accept_when<F>(
        mut self,
        port: u16,
        sni: impl Into<Sni>,
        config_for: impl Fn(&Cx) -> F + Send + Sync + 'static,
        accept: impl PortServer,
    ) -> Host
    where
        F: Future<Output = Arc<ServerConfig>> + Send + 'static,
    {
        let spec = PortSpec::Tls {
            sni: sni.into(),
            config: Arc::new(move |fcx| Box::pin(config_for(fcx)) as ConfigFuture),
            accept: Arc::new(accept),
        };
        self.ports.push((port, spec));
        self
    }

    /// Serves the literal TCP `port`, including zero, with a layer stack
    /// made by `make` for each connection, from the connection's
    /// [`ConnInfo`], which numbers it and names its sandbox.
    /// [`stack::stream`] runs it with the default [`StreamLimits`],
    /// charging the sandbox's budget, at most [`DEFAULT_MAX_CONNS`] at
    /// once. Past that, a new connection is reset as soon as it is
    /// accepted, and each counts until its socket is gone. A connection the
    /// stack resets is reset.
    pub fn tcp_stack<L, M>(self, port: u16, make: M) -> Host
    where
        L: Layer<Lower = ByteStream, Upper = Top> + Send + 'static,
        L::Work: Job<Done = L::Done>,
        L::Report: Send,
        L::Done: Send,
        L::Error: Send,
        M: Fn(&ConnInfo) -> L + Send + Sync + 'static,
    {
        self.tcp_stack_with(port, StreamLimits::default(), DEFAULT_MAX_CONNS, make)
    }

    /// The same with these limits and at most `max_conns` connections at
    /// once.
    pub fn tcp_stack_with<L, M>(
        self,
        port: u16,
        limits: StreamLimits,
        max_conns: usize,
        make: M,
    ) -> Host
    where
        L: Layer<Lower = ByteStream, Upper = Top> + Send + 'static,
        L::Work: Job<Done = L::Done>,
        L::Report: Send,
        L::Done: Send,
        L::Error: Send,
        M: Fn(&ConnInfo) -> L + Send + Sync + 'static,
    {
        self.port_server(
            port,
            StackAccept {
                make,
                max_conns,
                limits,
                open: Arc::default(),
            },
        )
    }

    /// Serves TCP `port` with TLS for the names `sni` gives, with the
    /// config `config_for` returns for each handshake, then a layer stack
    /// made by `make` for each connection over the decrypted stream, as
    /// [`tcp_stack`](Self::tcp_stack) does over TCP. Its [`ConnInfo`] has
    /// the name and protocol TLS settled. Several TLS servers on one port
    /// route by SNI; a name with no entry is rejected with
    /// `unrecognized_name`.
    pub fn tls_stack<L, M>(
        self,
        port: u16,
        sni: impl Into<Sni>,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
        make: M,
    ) -> Host
    where
        L: Layer<Lower = ByteStream, Upper = Top> + Send + 'static,
        L::Work: Job<Done = L::Done>,
        L::Report: Send,
        L::Done: Send,
        L::Error: Send,
        M: Fn(&ConnInfo) -> L + Send + Sync + 'static,
    {
        let accept = StackAccept {
            make,
            max_conns: DEFAULT_MAX_CONNS,
            limits: StreamLimits::default(),
            open: Arc::default(),
        };
        self.tls_accept(port, sni, config_for, accept)
    }

    /// Serves UDP `port` with one layer stack made by `make` from the
    /// socket's [`ConnInfo`]: its address, which says the port the
    /// endpoint chose for port zero, and [`Transport::Udp`]. The stack
    /// holds the conversation for the socket's whole life and gets every
    /// datagram with its sender's address ([`stack::datagrams`]). Port
    /// zero asks the endpoint to choose a free port
    /// ([`udp::Endpoint::bind`]). Retained datagrams and layer state share
    /// `budget` across every sender and every instance of this host.
    pub fn udp_stack<L, M>(mut self, port: u16, budget: Budget, make: M) -> Host
    where
        L: Layer<Lower = Datagrams<SocketAddr>, Upper = Top> + Send + 'static,
        L::Work: Job<Done = L::Done>,
        L::Report: Send,
        L::Done: Send,
        L::Error: core::error::Error + Send + Sync + 'static,
        M: Fn(&ConnInfo) -> L + Send + Sync + 'static,
    {
        let start: UdpStart = Arc::new(move |fcx, socket, local| {
            let budget = budget.clone();
            let layer = make(&ConnInfo {
                local: Some(local),
                transport: Transport::Udp,
                ..ConnInfo::default()
            });
            fcx.spawn(move |fcx| async move {
                match stack::datagrams(&fcx, socket, local, layer, budget, |_| {}).await {
                    Ok(()) => Ok(()),
                    Err(StackError::Cancelled) => Err(fictionet::Cancelled.into()),
                    Err(StackError::Layer(e)) => Err(e.into()),
                    Err(StackError::Budget) => {
                        Err(std::io::Error::other("datagram memory budget exhausted").into())
                    }
                }
            });
        });
        self.ports.push((port, PortSpec::Udp(start)));
        self
    }

    /// Runs `program` on each of this host's machines once the host is
    /// placed, with that machine's [`Endpoints`]. A host with an IPv4 and
    /// an IPv6 address has two machines, so the program runs twice. On a
    /// machine that another host made first, the program starts at once
    /// and shares the machine's endpoints with every other program there.
    ///
    /// An error from the program fails the network's region, as an error
    /// from any of the world's tasks does. A program that may fail without
    /// ending the world handles its own errors and returns `Ok(())`.
    pub fn program(mut self, program: impl Program) -> Host {
        self.programs.push(Arc::new(program));
        self
    }

    /// Delays every packet between each of this host's machines and the
    /// network by `by`, in each direction ([`delay`](fictionet::stdlib::network::delay)),
    /// so a round trip to the host takes `2 * by` longer. The delay is
    /// set when a machine is made: a host placed at an address that
    /// already has a machine keeps that machine's link as it is.
    pub fn delay(self, by: Duration) -> Host {
        Host {
            delay: Some(by),
            ..self
        }
    }
}

// ---------------------------------------------------------------------------
// Programs

/// A machine's side of the network, for a [`Program`] that runs on it.
///
/// The endpoints are the machine's own: a connection from
/// [`tcp::Endpoint::connect`] or a datagram from a socket of
/// [`udp::Endpoint::bind`] leaves from [`addr`](Self::addr) through the
/// network's router, as a packet from any host does. Listeners and sockets
/// a program opens share the machine's ports with the host's services, so
/// a port either has is taken for the other.
#[derive(Clone)]
pub struct Endpoints {
    /// The machine's address.
    pub addr: IpAddr,
    /// The machine's TCP endpoint.
    pub tcp: tcp::Endpoint,
    /// The machine's UDP endpoint.
    pub udp: udp::Endpoint,
    admission: Admission,
    limits: Limits,
}

impl Endpoints {
    pub(super) fn observe_dns(&self, event: &fictionet::stdlib::services::dns::Event) {
        if let Some(observe) = &self.admission.hooks.dns_observe {
            observe(event);
        }
    }

    /// The network's limits and timers ([`Net::limits`]), for a program
    /// that serves what the network's own services serve, such as DNS over
    /// TCP with [`Limits::dns_tcp_idle`].
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// The sandbox that `peer` belongs to, or `None` for a peer that is no
    /// sandbox.
    pub fn sandbox_of(&self, peer: IpAddr) -> Option<super::Sandbox> {
        self.admission.hooks.sandbox_of(peer)
    }

    /// The service budget of the sandbox that `peer` belongs to
    /// ([`Limits::sandbox_budget`]), for a program that charges what it
    /// holds for that sandbox's connections, as [`Arrival::budget`] is for
    /// a port's server. `None` for a peer that is no attached sandbox, or
    /// a trusted one.
    pub fn budget_of(&self, peer: IpAddr) -> Option<Budget> {
        let hooks = &self.admission.hooks;
        hooks.budget(hooks.sandbox_at(peer).id)
    }

    /// Applies the network's per-peer connection limit
    /// ([`Limits::connections_per_peer`]) to a connection the program
    /// accepted, as the host's services have it applied for them. Returns
    /// the connection, counted until it is gone, or `None` after resetting
    /// it when its peer already has as many open as it may.
    pub fn admit(&self, conn: tcp::TcpConnection) -> Option<tcp::TcpConnection> {
        self.admission.peers.admit(conn)
    }
}

/// Code that runs on a machine, as a resolver, a mail relay or a bot would
/// on a real one. [`Host::program`] runs it. Any
/// `Fn(Cx, Endpoints) -> impl Future<Output = fictionet::Result>` is one:
///
/// ```
/// # use fictionet::stdlib::world::net::{Endpoints, Host};
/// # use fictionet::Cx;
/// let greeter = Host::new("greeter").program(|_fcx: Cx, machine: Endpoints| async move {
///     let mut socket = machine.udp.bind(0)?;
///     socket.send_to(b"hello", "203.0.113.7:7".parse()?);
///     Ok(())
/// });
/// ```
pub trait Program: Send + Sync + 'static {
    /// Runs the program on the machine whose endpoints are `machine`, in
    /// the network's region.
    fn run(
        &self,
        fcx: Cx,
        machine: Endpoints,
    ) -> Pin<Box<dyn Future<Output = fictionet::Result> + Send>>;
}

impl<F, Fut> Program for F
where
    F: Fn(Cx, Endpoints) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = fictionet::Result> + Send + 'static,
{
    fn run(
        &self,
        fcx: Cx,
        machine: Endpoints,
    ) -> Pin<Box<dyn Future<Output = fictionet::Result> + Send>> {
        Box::pin(self(fcx, machine))
    }
}

// ---------------------------------------------------------------------------
// Names and machines

/// Machines, their addresses, and the names hosts declare.
pub(super) struct World {
    /// Each declared name, with the addresses of the host that has it.
    pub(super) declared: BTreeMap<LowerName, Placed>,
    /// Counts the changes to `declared`: the revision of its zones.
    revision: u64,
    /// Machines in address order for aborting a detached peer.
    pub(super) machines: BTreeMap<IpAddr, Arc<Machine>>,
    pub(super) addresses: Allocator,
}

impl World {
    pub(super) fn new(pools: super::Pools) -> World {
        World {
            declared: BTreeMap::new(),
            revision: 0,
            machines: BTreeMap::new(),
            addresses: Allocator::new(pools),
        }
    }

    pub(super) fn free_auto(&mut self, subnet: &Subnet) -> Option<Ipv4Addr> {
        self.addresses.free_auto(subnet, &self.machines)
    }

    pub(super) fn free_auto6(&mut self, subnet: &Subnet6) -> Option<Ipv6Addr> {
        self.addresses.free_auto6(subnet, &self.machines)
    }

    /// Declares `names` for a host placed at `placed`. A name declared
    /// before now answers with these addresses. A name that is not a DNS
    /// name, or is the root, cannot be asked for and is left out.
    pub(super) fn declare(&mut self, names: &[String], placed: Placed) {
        for name in names {
            let Ok(name) = Name::from_ascii(format!("{name}.")) else {
                continue;
            };
            if !name.is_root() {
                self.declared.insert(LowerName::new(&name), placed);
            }
        }
        self.revision += 1;
    }

    /// Whether a declared name is at or below `name`.
    fn declares_below(&self, name: &LowerName) -> bool {
        // The names below a name follow it directly in canonical order.
        self.declared
            .range(name.clone()..)
            .next()
            .is_some_and(|(other, _)| name.zone_of(other))
    }

    /// Whether a declared name is at or below `name` and inside none of
    /// `zones`.
    fn declares_outside(&self, name: &LowerName, zones: &[LowerName]) -> bool {
        // The names below a name follow it directly in canonical order.
        self.declared
            .range(name.clone()..)
            .take_while(|(other, _)| name.zone_of(other))
            .any(|(other, _)| !zones.iter().any(|zone| zone.zone_of(other)))
    }

    /// What a zone of the declared names holds at `name`, with `apex_sets`
    /// at `apex` beside them.
    fn fact(&self, apex: &LowerName, apex_sets: &[RecordSet], name: &LowerName) -> Fact<Node> {
        let mut sets = BTreeMap::new();
        if name == apex {
            for set in apex_sets {
                sets.insert(set.record_type(), set.clone());
            }
        }
        if let Some(placed) = self.declared.get(name) {
            for set in placed.rrsets(&Name::from(name.clone()), HOST_TTL) {
                sets.insert(set.record_type(), set);
            }
        }
        if !sets.is_empty() {
            Fact::Present(Node::Data(sets))
        } else if self.declares_below(name) {
            Fact::Present(Node::Empty)
        } else {
            Fact::Absent
        }
    }

    /// A view of the declared names as a zone at `apex` with the SOA
    /// `soa` and the RRsets `apex_sets` at its apex, holding the facts an
    /// answer for `qname` reads: each name from `qname` up to the apex,
    /// the wildcard below each, and each name from an NS, MX, or SRV
    /// target in the zone up to the apex, for the additional section.
    pub(super) fn view(
        &self,
        apex: LowerName,
        soa: RecordSet,
        apex_sets: &[RecordSet],
        qname: &LowerName,
    ) -> Facts {
        let mut facts = BTreeMap::new();
        let mut name = qname.clone();
        loop {
            facts.insert(name.clone(), self.fact(&apex, apex_sets, &name));
            if let Ok(wildcard) = name.prepend_label("*") {
                let wildcard = LowerName::new(&wildcard);
                let fact = self.fact(&apex, apex_sets, &wildcard);
                facts.insert(wildcard, fact);
            }
            if name == apex {
                break;
            }
            name = name.base_name();
        }
        let wanted: Vec<LowerName> = facts
            .values()
            .filter_map(|fact| match fact {
                Fact::Present(Node::Data(sets)) => Some(sets.values()),
                _ => None,
            })
            .flatten()
            .flat_map(additional_targets)
            .filter(|target| apex.zone_of(target))
            .collect();
        for mut name in wanted {
            while !facts.contains_key(&name) {
                facts.insert(name.clone(), self.fact(&apex, apex_sets, &name));
                if name == apex {
                    break;
                }
                name = name.base_name();
            }
        }
        Facts {
            apex,
            soa,
            revision: Revision(self.revision),
            facts,
        }
    }
}

/// The names the network's hosts declare with [`Host::dns_name`], or that
/// hosts placed with [`NetHandle::add_host`] declare, as zone data for a
/// resolver's local zones.
///
/// It is one static local zone per top-level domain those names use:
/// each holds the declared names under it, and denies the rest. In it
/// each declared name has its host's A and AAAA records, a name with
/// declared names below it is an empty non-terminal, and every other name
/// under that top-level domain does not exist. A name inside one of the
/// resolver's other local zones, such as `home.arpa`, is in a zone at that
/// zone's apex instead ([`Declared::over`]). Each zone has the SOA and NS
/// records of [`EmptyApex::rfc6303`]. Under a top-level domain no
/// declared name uses, it knows nothing, so a resolver goes on to its
/// other zones and to iteration. The zones grow as hosts are placed.
///
/// A static zone denies every undeclared name under its top-level domain.
/// A world whose resolver also iterates to real servers, and whose hosts
/// declare names under real top-level domains, passes
/// [`Declared::transparent`] instead, so the declared names answer and the
/// rest are asked of the internet. [`Net::gateway`] hands it to the code
/// that builds the gateway.
#[derive(Clone)]
pub struct Declared {
    world: Arc<Mutex<World>>,
    root: LowerName,
    /// The apexes of the resolver's other local zones, which
    /// [`over`](Declared::over) makes give way to the declared names.
    zones: Arc<[LowerName]>,
    /// Whether each zone has the SOA and NS records of
    /// [`EmptyApex::rfc6303`] at its apex. The zones of [`Declared::transparent`] have
    /// none.
    apex_records: bool,
}

impl Declared {
    pub(super) fn new(world: Arc<Mutex<World>>) -> Declared {
        Declared {
            world,
            root: LowerName::new(&Name::root()),
            zones: Arc::new([]),
            apex_records: true,
        }
    }

    /// The declared names in an implicit transparent zone, as a resolver
    /// serves local data that no local zone contains, with no SOA
    /// or NS records of its own. A declared name answers with its host's
    /// addresses, and NODATA for other types. Every other name, a
    /// top-level domain's apex and a name above a declared name among
    /// them, is unknown, so a resolver asks its next local zone or
    /// iterates for it.
    pub fn transparent(&self) -> Transparent<Declared> {
        Transparent(Declared {
            apex_records: false,
            ..self.clone()
        })
    }

    /// `config` with the declared names served before anything else: these
    /// zones are added as a local zone whose answers keep AA, and each of
    /// `config`'s local zones with a declared name at or below its apex
    /// gives way to them. The declared names then answer inside a zone at
    /// that apex, with the apex records of [`EmptyApex::rfc6303`]. So a
    /// world that declares `dc01.corp.test` or `nas.home.arpa` gets its
    /// address, where a default `test` zone (RFC 6761 §6.2) or `home.arpa`
    /// zone (RFC 8375) would deny it, and the other names in that zone
    /// still do not exist.
    pub fn over(&self, mut config: Config) -> Config {
        let declared = Declared {
            zones: config
                .local
                .iter()
                .map(|zone| zone.data.apex().clone())
                .filter(|apex| !apex.is_root())
                .collect(),
            ..self.clone()
        };
        config.local = config
            .local
            .into_iter()
            .map(|zone| {
                if zone.data.apex().is_root() {
                    zone
                } else {
                    LocalZone {
                        data: Arc::new(GivesWay {
                            zone: zone.data,
                            declared: declared.clone(),
                        }),
                        ..zone
                    }
                }
            })
            .collect();
        config.local(LocalZone::new(Arc::new(declared)))
    }

    /// Whether a declared name is at or below `apex`.
    fn declares_below(&self, apex: &LowerName) -> bool {
        self.world.lock().declares_below(apex)
    }
}

impl ZoneData for Declared {
    /// The root: the zones cover every top-level domain a declared name
    /// will ever use. Each view's apex is the deepest of the local zones
    /// that gave way above its question's name, or else the name's
    /// top-level domain.
    fn apex(&self) -> &LowerName {
        &self.root
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        let qname = LowerName::new(question.name());
        if qname.is_root() {
            return Arc::new(Facts::unknown(self.root.clone()));
        }
        let world = self.world.lock();
        let zone = self
            .zones
            .iter()
            .filter(|zone| zone.zone_of(&qname) && world.declares_below(zone))
            .max_by_key(|zone| label_count(zone))
            .cloned();
        let apex = match zone {
            Some(zone) => zone,
            None => {
                // A declared name inside another local zone is in that
                // zone, so only the others make a zone of their top-level
                // domain.
                let tld = LowerName::new(&qname.trim_to(1));
                if !world.declares_outside(&tld, &self.zones) {
                    return Arc::new(Facts::unknown(tld));
                }
                tld
            }
        };
        let (soa, ns) = EmptyApex::rfc6303().records(&Name::from(apex.clone()));
        let apex_sets = if self.apex_records {
            vec![soa.clone(), ns]
        } else {
            Vec::new()
        };
        Arc::new(world.view(apex, soa, &apex_sets, &qname))
    }
}

/// A local zone that gives way to the declared zones when a declared name
/// uses its apex: its views then know nothing, so the resolver asks the
/// next local zone, the declared ones.
struct GivesWay {
    zone: Arc<dyn ZoneData>,
    declared: Declared,
}

impl ZoneData for GivesWay {
    fn apex(&self) -> &LowerName {
        self.zone.apex()
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        if self.declared.declares_below(self.zone.apex()) {
            return Arc::new(Facts::unknown(self.zone.apex().clone()));
        }
        self.zone.view(question)
    }
}

/// The facts of a zone of the declared names that one question reads, at
/// one revision. Every other name is unknown.
pub(super) struct Facts {
    apex: LowerName,
    soa: RecordSet,
    revision: Revision,
    facts: BTreeMap<LowerName, Fact<Node>>,
}

impl Facts {
    /// A view of the zone at `apex` that knows nothing.
    pub(super) fn unknown(apex: LowerName) -> Facts {
        Facts {
            soa: EmptyApex::rfc6303().records(&Name::from(apex.clone())).0,
            apex,
            revision: Revision(0),
            facts: BTreeMap::new(),
        }
    }
}

impl View for Facts {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn revision(&self) -> Revision {
        self.revision
    }

    fn soa(&self) -> &RecordSet {
        &self.soa
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        match self.facts.get(name) {
            Some(Fact::Present(node)) => Fact::Present(node),
            Some(Fact::Absent) => Fact::Absent,
            Some(Fact::Unknown) | None => Fact::Unknown,
        }
    }

    /// Declared zones are unsigned.
    fn denial(&self, _name: &LowerName, _kind: Denied) -> Fact<Vec<RecordSet>> {
        Fact::Present(Vec::new())
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
    pub(super) limits: Limits,
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
                let machine = Machine::stage(
                    self,
                    addr,
                    &label,
                    world.machines.get(&addr),
                    host.tcp_options,
                    host.icmp_options.clone(),
                    host.udp_settings,
                );
                let ports = machine.machine.prepare(&host)?;
                Ok((machine, ports))
            })
            .collect::<Result<Vec<_>, String>>()?;
        for (mut machine, ports) in prepared {
            if let Some(side) = machine.route.take() {
                self.router
                    .add(host_prefix(machine.machine.addr), self.wire(side, &host));
            }
            machine.commit(world, ports, &host.programs);
        }
        Ok(placed)
    }

    /// The network's end of a new machine's link, through the host's delay
    /// if it has one.
    fn wire(&self, side: End, host: &Host) -> Box<dyn Interface> {
        match host.delay {
            Some(by) => Box::new(fictionet::stdlib::network::delay(self.fcx, by, side)),
            None => Box::new(side),
        }
    }

    /// Places `host` on the LAN `name`, at its `at` address of the LAN's
    /// family or the first free one from the LAN's second address up.
    fn place_on_lan(
        &self,
        world: &mut World,
        lan: &super::Lan,
        host: &Host,
    ) -> Result<Placed, String> {
        let name = &lan.name;
        let seg = self
            .lans
            .get(name)
            .filter(|seg| seg.prefix == lan.prefix)
            .ok_or_else(|| format!("LAN {name} is not configured in this network"))?;
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
        let mut machine = Machine::stage(
            self,
            addr,
            label,
            world.machines.get(&addr),
            host.tcp_options,
            host.icmp_options.clone(),
            host.udp_settings,
        );
        let ports = machine.machine.prepare(host)?;
        // Joining is the last fallible step. No service or program has
        // started. A delay's task ends when a failed join drops its link.
        if let Some(side) = machine.route.take() {
            seg.lan
                .add(addr, self.wire(side, host))
                .map_err(|e| e.to_string())?;
        }
        machine.commit(world, ports, &host.programs);
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

    /// Makes the machine at the gateway address `addr`, with `host`'s
    /// services and programs. Its address, names and LAN are the
    /// gateway's, whatever `host` says. A gateway is not one of the hosts'
    /// machines, which the network classifies apart from it, so it is not
    /// recorded in the world. `attach` wires its link into the network.
    /// Returns its TCP endpoint.
    pub(super) fn gateway(
        &self,
        addr: IpAddr,
        host: &Host,
        attach: impl FnOnce(Box<dyn Interface>) -> Result<(), String>,
    ) -> Result<tcp::Endpoint, String> {
        let mut machine = Machine::stage(
            self,
            addr,
            &host.label,
            None,
            host.tcp_options,
            host.icmp_options.clone(),
            host.udp_settings,
        );
        let ports = machine.machine.prepare(host)?;
        if let Some(side) = machine.route.take() {
            attach(self.wire(side, host))?;
        }
        if let Some(start) = machine.start.take() {
            start();
        }
        machine.machine.add(ports);
        machine.machine.run(&host.programs);
        Ok(machine.machine.tcp.clone())
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

    /// The machines' addresses now.
    pub(super) fn addresses(&self) -> HashSet<IpAddr> {
        self.world.lock().machines.keys().copied().collect()
    }

    pub(super) fn abort_peers(&self, which: &dyn Fn(IpAddr) -> bool) {
        let machines: Vec<_> = self.world.lock().machines.values().cloned().collect();
        for machine in machines {
            machine.tcp.abort_peers(which);
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
    pub(super) fn admit(&self, _fcx: &Cx, conn: tcp::TcpConnection) -> Option<tcp::TcpConnection> {
        self.peers.admit(conn)
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

    /// How many peer addresses have connections open.
    #[cfg(test)]
    pub(super) fn peers(&self) -> usize {
        self.open.lock().len()
    }

    /// Counts `conn` against its peer until it is gone, or resets it if
    /// its peer already has as many open as it may.
    fn admit(self: &Arc<Self>, conn: tcp::TcpConnection) -> Option<tcp::TcpConnection> {
        let Some(guard) = self.enter(conn.peer_addr().ip()) else {
            conn.reset();
            return None;
        };
        conn.hold_until_gone(Box::new(guard));
        Some(conn)
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
    async fn config(&self, fcx: &Cx) -> Arc<ServerConfig> {
        let given = (self.config)(fcx).await;
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
    /// Starts a new machine's tasks, adds the services, then starts the
    /// programs. A machine that already ran starts only the programs.
    fn commit(self, world: &mut World, ports: Vec<PreparedPort>, programs: &[Arc<dyn Program>]) {
        if let Some(start) = self.start {
            start();
            world
                .machines
                .insert(self.machine.addr, self.machine.clone());
        }
        self.machine.add(ports);
        self.machine.run(programs);
    }
}

/// One address with its services.
pub(super) struct Machine {
    fcx: Cx,
    addr: IpAddr,
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    ports: Mutex<HashMap<u16, Arc<Port>>>,
    admission: Admission,
    limits: Limits,
}

impl Machine {
    /// Whether a socket is open on UDP port `port`.
    pub(super) fn udp_bound(&self, port: u16) -> bool {
        self.udp.is_bound(port)
    }

    /// Builds a machine without publishing its route or starting its tasks.
    fn stage(
        installation: &Installation<'_>,
        addr: IpAddr,
        _label: &str,
        existing: Option<&Arc<Machine>>,
        options: tcp::Options,
        icmp_options: icmp::Options,
        udp_settings: udp::Settings,
    ) -> PreparedMachine {
        if let Some(machine) = existing {
            return PreparedMachine {
                machine: machine.clone(),
                route: None,
                start: None,
            };
        }
        let fcx = installation.fcx.clone();
        let (router_side, side) = link();
        let ((tcp, udp, icmp, _other), split) = ip::prepare_split_protocols(&fcx, side);
        let (tcp, tcp_task) = tcp::prepare_endpoint(&fcx, tcp, addr, options);
        let hooks = installation.admission.hooks.clone();
        tcp.limit_isolated_peers(move |addr| hooks.by_addr.lock().contains_key(&addr));
        let (udp, udp_task) = udp::prepare_endpoint(&fcx, udp, addr);
        if installation.admission.hooks.refused_observe.is_some() {
            for protocol in [6, 17] {
                let hooks = installation.admission.hooks.clone();
                let fcx = fcx.clone();
                let observe = Arc::new(move |peer: SocketAddr, local: SocketAddr| {
                    if let Some(observe) = &hooks.refused_observe {
                        let conn = ConnInfo {
                            local: Some(local),
                            peer: Some(peer),
                            sandbox: hooks.sandbox_of(peer.ip()),
                            transport: if protocol == 17 {
                                Transport::Udp
                            } else {
                                Transport::Tcp
                            },
                            ..Default::default()
                        };
                        observe(&super::RefusedPacket {
                            at: fcx.now(),
                            conn,
                            from: peer.ip(),
                            to: local.ip(),
                            protocol,
                            reason: super::Refusal::ClosedPort,
                        });
                    }
                });
                if protocol == 6 {
                    tcp.on_refused(observe);
                } else {
                    udp.on_refused(observe);
                }
            }
        }
        udp.icmp_options(icmp_options.clone());
        udp.settings(udp_settings);
        let machine = Arc::new(Machine {
            fcx: fcx.clone(),
            addr,
            tcp,
            udp,
            ports: Mutex::new(HashMap::new()),
            admission: installation.admission.clone(),
            limits: installation.limits,
        });
        PreparedMachine {
            machine,
            route: Some(router_side),
            start: Some(Box::new(move || {
                split.start(&fcx);
                tcp_task.start(&fcx);
                udp_task.start(&fcx);
                fcx.spawn(move |fcx| pings(fcx, icmp, addr, icmp_options));
            })),
        }
    }

    /// Checks services against installed ports and earlier preparations.
    fn prepare(&self, host: &Host) -> Result<Vec<PreparedPort>, String> {
        let addr = self.addr;
        let mut ports = HashMap::<u16, PortPlan>::new();
        let mut prepared = Vec::new();
        for (number, spec) in &host.ports {
            let local = SocketAddr::new(addr, *number);
            if let PortSpec::Udp(start) = spec {
                let socket = self
                    .udp
                    .bind(*number)
                    .map_err(|e| format!("UDP port {number} at {addr}: {e}"))?;
                prepared.push(PreparedPort::Udp {
                    socket,
                    start: start.clone(),
                });
                continue;
            }
            let port = match ports.entry(*number) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let existing = self.ports.lock().get(number).cloned();
                    let listener = if existing.is_none() {
                        let mut listener = self
                            .tcp
                            .listen(*number)
                            .map_err(|e| format!("TCP port {number} at {addr}: {e}"))?;
                        let opener = match spec {
                            PortSpec::Tcp(accept) | PortSpec::Tls { accept, .. } => accept,
                            PortSpec::Udp(_) => unreachable!(),
                        };
                        if let Some(backlog) = opener.backlog() {
                            listener.backlog(backlog);
                        }
                        if let Some(answer) = opener.answer() {
                            listener.answer(answer);
                        }
                        Some(listener)
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
            let accept = match spec {
                PortSpec::Tcp(accept) | PortSpec::Tls { accept, .. } => accept,
                PortSpec::Udp(_) => unreachable!(),
            };
            if let Some(front) = port.plain.as_ref().or(port.first_tls.as_ref())
                && !Arc::ptr_eq(front, accept)
                && (front.answer().is_some() || accept.answer().is_some())
            {
                return Err(format!(
                    "TCP port {number} at {addr} answers handshakes for one server, and cannot be shared"
                ));
            }
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
                    let application = share
                        .as_ref()
                        .and_then(|share| share.tls_server.clone())
                        .unwrap_or_else(|| served_by.clone());
                    port.names.extend(names.iter().cloned());
                    let entries = names
                        .into_iter()
                        .map(|name| {
                            let entry = TlsName {
                                config: config.clone(),
                                accept: application.clone(),
                                alpn: application.alpn(),
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
        for prepared in prepared {
            match prepared {
                PreparedPort::Udp { socket, start } => {
                    let local = socket.local_addr();
                    start(&self.fcx, socket, local);
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

    /// Starts each program on this machine, with its endpoints.
    fn run(&self, programs: &[Arc<dyn Program>]) {
        for program in programs {
            let program = program.clone();
            let machine = Endpoints {
                addr: self.addr,
                tcp: self.tcp.clone(),
                udp: self.udp.clone(),
                admission: self.admission.clone(),
                limits: self.limits,
            };
            // The program is called in its own task, not inside this call,
            // which runs under the network's lock, so it may use the
            // network's handle from its first line.
            self.fcx
                .spawn(move |fcx| async move { program.run(fcx, machine).await });
        }
    }
}

/// The route to one address: `/32` or `/128`.
pub(super) fn host_prefix(addr: IpAddr) -> Prefix {
    Prefix {
        addr,
        len: if addr.is_ipv4() { 32 } else { 128 },
    }
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
                let mut info =
                    ConnInfo::new(hooks.next_conn(), conn.local_addr(), conn.peer_addr())
                        .from_sandbox(sandbox);
                info.handshake = conn.handshake().cloned();
                let accepted = fcx.now();
                let limits = machine.limits;
                let port = port.clone();
                fcx.spawn(move |fcx| async move {
                    let _ = fcx
                        .region(move |fcx| async move {
                            connection(fcx, conn, info, accepted, port, admission, limits).await;
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

/// Serves one connection: on a port with TLS names, one stack of TLS and,
/// once its handshake is done, what the name's accept serves over it;
/// otherwise the port's accept.
async fn connection(
    fcx: Cx,
    conn: tcp::TcpConnection,
    info: ConnInfo,
    accepted: Instant,
    port: Arc<Port>,
    admission: Admission,
    limits: Limits,
) {
    let hooks = admission.hooks;
    let socket = conn.gone_watch();
    let sandbox_id = info.sandbox.as_ref().map(|s| s.id);
    let budget = sandbox_id.and_then(|id| hooks.budget(id));
    let has_tls = !port
        .tls
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .by_name
        .is_empty();
    if !has_tls {
        let plain = port.plain.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(accept) = plain {
            let arrival = Arrival {
                http_observe: hooks.http_observe.clone(),
                conn: Box::new(conn),
                info,
                socket,
                budget,
                limits,
            };
            accept.serve(fcx.clone(), arrival).await;
        }
        return;
    }

    // The name the client asked for, as the port knows its names.
    let requested: Arc<Mutex<Option<Arc<str>>>> = Arc::default();
    let select = {
        let (names, requested) = (port.clone(), requested.clone());
        move |fcx: Cx, server_name: Option<String>| {
            let sni = server_name
                .as_deref()
                .map(|n| Arc::<str>::from(n.trim_end_matches('.').to_ascii_lowercase()));
            let name = {
                let tls = names.tls.read().unwrap_or_else(|e| e.into_inner());
                sni.as_deref()
                    .and_then(|n| tls.by_name.get(n))
                    .or_else(|| tls.by_name.get(""))
                    .cloned()
            };
            *requested.lock() = sni;
            Box::pin(async move {
                let name = name?;
                let config = name.config(&fcx).await;
                Some(config)
            }) as tls::Picking
        }
    };
    let handshook = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serve = {
        let (fcx, info, budget) = (fcx.clone(), info.clone(), budget.clone());
        let handshook = handshook.clone();
        let names = port.clone();
        let (http_observe, tls_observe) = (hooks.http_observe.clone(), hooks.tls_observe.clone());
        move |state: tls::Handshake<'_>| -> Boxed {
            handshook.store(true, std::sync::atomic::Ordering::Relaxed);
            let tls::Handshake::Established { server_name, alpn } = state else {
                unreachable!("Secure constructs applications only after negotiation")
            };
            let server_name = server_name.map(normalize);
            let info = info.over_tls(server_name.as_deref(), alpn);
            if let Some(observe) = &tls_observe {
                observe(&super::TlsObservation {
                    at: fcx.now(),
                    conn: info.clone(),
                    result: Ok(()),
                });
            }
            let opening = Opening {
                http_observe,
                info,
                socket,
                budget,
                limits,
            };
            // Application routing follows the replacement's negotiated name.
            let name = {
                let tls = names.tls.read().unwrap_or_else(|e| e.into_inner());
                server_name
                    .as_deref()
                    .and_then(|name| tls.by_name.get(name))
                    .or_else(|| tls.by_name.get(""))
                    .cloned()
            };
            let Some(name) = name else {
                return Boxed::new(stack::Tunnel::new(|_, _| async {}));
            };
            if let Some(stack) = name.accept.over_tls(&fcx, &opening) {
                return stack;
            }
            let accept = name.accept.clone();
            Boxed::new(stack::Tunnel::new(move |fcx, conn| {
                accept.serve(fcx, opening.arrive(conn))
            }))
        }
    };
    let listener = port
        .tls
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .first
        .clone()
        .expect("TLS listener has a server");
    let factory = listener.tls_factory();
    let stream = StreamLimits {
        idle: None,
        write_timeout: Some(limits.write_timeout),
    };
    let budget = budget.unwrap_or_else(Budget::unlimited);
    let secure = factory.build(
        tls::Opening {
            cx: fcx.clone(),
            info: info.clone(),
            budget: budget.clone(),
            deadline: accepted + limits.handshake,
            select: Arc::new(select),
        },
        serve,
    );
    let ended = stack::stream(&fcx, conn, &info, secure, budget, stream, |_| {}).await;
    if handshook.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let error = match ended {
        Err(StackError::Layer(e)) => factory.handshake_error(e),
        Err(StackError::Cancelled) => HandshakeError::Cancelled,
        Ok(StreamEnd::Conn(e)) => e.into(),
        Ok(StreamEnd::Budget) => HandshakeError::Failed("no budget for the handshake".into()),
        Ok(_) | Err(StackError::Budget) => HandshakeError::Closed,
    };
    if let Some(observe) = &hooks.tls_observe {
        let mut info = info;
        info.tls = true;
        info.sni = requested.lock().take();
        observe(&super::TlsObservation {
            at: fcx.now(),
            conn: info,
            result: Err(error),
        });
    }
}

/// Answers pings to `addr`.
pub(super) async fn pings(
    fcx: Cx,
    mut icmp: End,
    addr: IpAddr,
    options: icmp::Options,
) -> fictionet::Result {
    let mut run = 0;
    while let Ok(packet) = icmp.recv(&fcx).await {
        if let Some(reply) = options.echo_reply(&packet, addr) {
            icmp.send(reply);
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
    use super::super::{Net, TEST_POOLS};
    use super::*;

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
                let mut net = Net::new(TEST_POOLS).ipv4_only();
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

    /// A server that answers handshakes cannot share its port with another
    /// host's, whichever comes first: the SYN comes before the TLS hello
    /// that would tell them apart.
    #[test]
    fn a_port_that_answers_handshakes_is_not_shared() {
        struct Plain;
        impl PortServer for Plain {
            fn serve(&self, _: Cx, _: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                Box::pin(async {})
            }
        }
        struct Answering;
        impl PortServer for Answering {
            fn serve(&self, _: Cx, _: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                Box::pin(async {})
            }
            fn answer(&self) -> Option<Box<dyn tcp::Answer>> {
                Some(Box::new(|_: &tcp::Syn<'_>| {
                    tcp::SynAnswer::Accept(Vec::new())
                }))
            }
        }
        let addr = Ipv4Addr::new(203, 0, 113, 8);
        for answering_first in [true, false] {
            fictionet::block_on(fictionet::run(
                fictionet::Seed::random(),
                move |fcx| async move {
                    let mut net = Net::new(TEST_POOLS).ipv4_only();
                    for (name, answers) in
                        [("a.test", answering_first), ("b.test", !answering_first)]
                    {
                        net = net.host(name, |h| {
                            let h = h.at(addr);
                            if answers {
                                h.tls_accept(443, name, |_| panic!("no handshake"), Answering)
                            } else {
                                h.tls_accept(443, name, |_| panic!("no handshake"), Plain)
                            }
                        });
                    }
                    let (_attacher, attachments) = fictionet::attachments();
                    let error = net.start(&fcx, attachments).unwrap_err().to_string();
                    assert!(error.contains("cannot be shared"), "{error}");
                    fcx.cancel();
                    Ok(())
                },
            ))
            .unwrap();
        }
    }
}
