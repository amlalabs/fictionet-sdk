//! Programs that run DNS engines on a machine: the engine decides, and the
//! driver here carries its queries, answers, and exchanges as packets.
//!
//! A driver runs on one machine. Its engines and the routes to their
//! clients sit behind one mutex, which is held only while an engine takes
//! an input and its actions are handed out, never across an await. Its
//! tasks: a loop on UDP port 53, one task per TCP client connection on port
//! 53, one per exchange the engines start, and a timer that wakes at the
//! engines' next deadline. Engine actions and events leave in the order the
//! engine queued them.
//!
//! Locks are taken in one order: an engine's mutex, then a zone's own lock
//! (a [`Lazy`](fictionet::stdlib::services::dns::zone::Lazy) zone asking its
//! provider, or zone data an authority learns from real servers
//! filing a lookup's response), then the network's lock (a provider
//! placing a host). Nothing that holds the network's lock calls into an
//! engine. A lookup runs in a task of its own, with no lock held.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::hash::Hash;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::SystemTime;

use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::network::{ConnError, ConnectionExt, tcp, udp};
use fictionet::stdlib::protocols::dns::dnssec::Ring;
use fictionet::stdlib::protocols::dns::{Framing, Parsed, Queries, Request, stream_framed};
use fictionet::stdlib::services::dns::authority::{Authority, AuthorityEngine, ServerConfig};
use fictionet::stdlib::services::dns::resolver::{Config, Resolver};
use fictionet::stdlib::services::dns::{
    Action, Client, Engine, Event, ExchangeFailure, Generation, Input, Lookup, Session, Token,
    Transmit, WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, Entropy, RaceError};

use super::super::{Endpoints, Program};
use super::session::Namespace;
use super::upstream::Upstream;

/// The port DNS servers answer on (RFC 1035 §4.2).
const PORT: u16 = 53;

/// The first port a resolver's UDP exchanges may leave from: RFC 6056
/// §3.2 has ephemeral ports drawn from the whole range 1024 to 65535.
const FIRST_PORT: u16 = 1024;

/// How many bytes a DNS-over-TCP connection reads at a time.
const READ_BUFFER: usize = 4096;

/// A world's callback for an engine's events.
type OnEvent = Arc<dyn Fn(&Event) + Send + Sync>;

// ---------------------------------------------------------------------------
// Authoritative

/// A program that answers as an authoritative server: an
/// [`Authority`] in an [`AuthorityEngine`], on UDP and TCP port 53 of each
/// machine it runs on.
///
/// Each machine has its own engine, for its own address. The authority's
/// lookups, its questions to a server of a zone, go to the
/// [`upstream`](Self::upstream), and the engine files what
/// comes back; without one, no answer comes and the engine gives up on
/// them at its deadline. A TCP connection stays open after a
/// response until the client closes it or it is idle for
/// [`Limits::dns_tcp_idle`](super::super::Limits::dns_tcp_idle)
/// (RFC 7766 §6.2.3), and its queries may be pipelined. Its buffers are
/// charged to its sandbox's budget
/// ([`Limits::sandbox_budget`](super::super::Limits::sandbox_budget)), and
/// it counts toward the per-peer connection limit.
pub struct Authoritative<A: Authority> {
    authority: Arc<A>,
    server: ServerConfig,
    upstream: Option<Arc<dyn Upstream>>,
    namespace: Option<Namespace>,
    on_event: Option<OnEvent>,
}

impl<A: Authority> Authoritative<A> {
    /// A server answering as `authority`, with the front `server`.
    pub fn new(authority: A, server: ServerConfig) -> Authoritative<A> {
        Authoritative {
            authority: Arc::new(authority),
            server,
            upstream: None,
            namespace: None,
            on_event: None,
        }
    }

    /// Puts the authority's lookups to `upstream`.
    pub fn upstream(self, upstream: impl Upstream) -> Authoritative<A> {
        Authoritative {
            upstream: Some(Arc::new(upstream)),
            ..self
        }
    }

    /// Answers for the sessions of `namespace`: when it advances, the
    /// authority drops what its lookups filed, and the engine
    /// abandons its lookups and asks again in the new session.
    pub fn namespace(self, namespace: &Namespace) -> Authoritative<A> {
        Authoritative {
            namespace: Some(namespace.clone()),
            ..self
        }
    }

    /// Calls `f` with each event the engine reports, in order. It runs
    /// while the engine waits, so it must return quickly and must not put
    /// a query to this program.
    pub fn on_event(self, f: impl Fn(&Event) + Send + Sync + 'static) -> Authoritative<A> {
        Authoritative {
            on_event: Some(Arc::new(f)),
            ..self
        }
    }
}

impl<A: Authority> Program for Authoritative<A> {
    fn run(
        &self,
        fcx: Cx,
        machine: Endpoints,
    ) -> Pin<Box<dyn Future<Output = fictionet::Result> + Send>> {
        let (authority, server) = (self.authority.clone(), self.server.clone());
        let local = SocketAddr::new(machine.addr, PORT);
        let make = move |session: Session| {
            let mut engine = AuthorityEngine::new(authority.clone(), server.clone(), local);
            engine.advance(session);
            engine
        };
        let driver = Arc::new(Driver {
            fcx: fcx.clone(),
            machine,
            make: Box::new(make),
            // An authority reads no dates, so its first session's clock is
            // never used.
            first: Session {
                generation: Generation(0),
                clock: WallClock {
                    start: SystemTime::UNIX_EPOCH,
                },
            },
            namespace: self.namespace.clone(),
            on_event: self.on_event.clone(),
            carrier: Arc::new(ToUpstream(self.upstream.clone())),
            state: Mutex::new(State::new(Box::new(Whole))),
            kick: Mailbox::new(),
            datagrams: Mailbox::new(),
        });
        Box::pin(async move { driver.start(&fcx) })
    }
}

// ---------------------------------------------------------------------------
// Recursive

/// A program that answers as a recursive resolver: a [`Resolver`] on UDP
/// and TCP port 53 of each machine it runs on.
///
/// The resolver's questions to other servers leave the machine as real
/// packets: over UDP from a port drawn from the run's entropy, or over TCP
/// with [`tcp::Endpoint::connect`]. A TCP reset or an ICMP error on connect
/// fails the exchange at once. UDP sockets do not report ICMP errors, so a
/// UDP exchange fails only when the resolver's deadline passes. A question
/// to an address of the family this machine lacks fails at once, as on a
/// machine with no route for that family. So the same resolver works
/// against authoritative programs on other hosts, against a real server
/// attached with [`Net::route`](super::super::Net::route), or against
/// nothing, and the network's dissector sees its exchanges.
///
/// Each machine has one engine, and so one cache, by default.
/// [`partition`](Self::partition) gives each machine one engine per key
/// instead. TCP connections are kept open and pipelined as
/// [`Authoritative`] keeps them.
pub struct Recursive {
    config: Config,
    clock: WallClock,
    partition: Arc<dyn Fn() -> Box<dyn Partition> + Send + Sync>,
    namespace: Option<Namespace>,
    on_event: Option<OnEvent>,
    drivers: Drivers,
}

/// The drivers of one [`Recursive`], for its [`ResolverHandle`]s.
type Drivers = Arc<Mutex<Vec<Weak<Driver<Resolver>>>>>;

impl Recursive {
    /// A resolver behaving as `config`, checking signatures against dates
    /// from `clock`.
    pub fn new(config: Config, clock: WallClock) -> Recursive {
        Recursive {
            config,
            clock,
            partition: Arc::new(|| Box::new(Whole) as Box<dyn Partition>),
            namespace: None,
            on_event: None,
            drivers: Arc::default(),
        }
    }

    /// One engine, with its own cache, for each value of `key` on each
    /// machine, instead of one per machine.
    pub fn partition<K, F>(self, key: F) -> Recursive
    where
        K: Hash + Eq + Send + 'static,
        F: Fn(&Client) -> K + Send + Sync + 'static,
    {
        let key: Arc<dyn Fn(&Client) -> K + Send + Sync> = Arc::new(key);
        Recursive {
            partition: Arc::new(move || {
                Box::new(ByKey {
                    key: key.clone(),
                    engines: HashMap::new(),
                }) as Box<dyn Partition>
            }),
            ..self
        }
    }

    /// One engine for each sandbox, by [`Client::sandbox`], and one for
    /// every client that is no sandbox: sandboxes can neither warm nor
    /// probe each other's caches, as with a public resolver.
    pub fn per_sandbox(self) -> Recursive {
        self.partition(|client: &Client| client.sandbox.as_ref().map(|sandbox| sandbox.id))
    }

    /// Answers for the sessions of `namespace`: when it advances, every
    /// engine abandons its exchanges, empties its cache, starts the queries
    /// still waiting again, and checks signatures against the new
    /// session's clock.
    pub fn namespace(self, namespace: &Namespace) -> Recursive {
        Recursive {
            namespace: Some(namespace.clone()),
            ..self
        }
    }

    /// Calls `f` with each event the engines report, in order. It runs
    /// while the engine waits, so it must return quickly and must not put
    /// a query to this program.
    pub fn on_event(self, f: impl Fn(&Event) + Send + Sync + 'static) -> Recursive {
        Recursive {
            on_event: Some(Arc::new(f)),
            ..self
        }
    }

    /// A handle that puts queries to this resolver's engines from other
    /// fronts, such as DNS over TLS or over HTTPS on the same host. It
    /// reaches the engines once the program runs.
    pub fn handle(&self) -> ResolverHandle {
        ResolverHandle {
            drivers: self.drivers.clone(),
        }
    }
}

impl Program for Recursive {
    fn run(
        &self,
        fcx: Cx,
        machine: Endpoints,
    ) -> Pin<Box<dyn Future<Output = fictionet::Result> + Send>> {
        let config = self.config.clone();
        let make = move |session: Session| {
            let mut engine = Resolver::new(config.clone(), Ring, session.clock);
            engine.advance(session);
            engine
        };
        let driver = Arc::new(Driver {
            fcx: fcx.clone(),
            machine,
            make: Box::new(make),
            first: Session {
                generation: Generation(0),
                clock: self.clock,
            },
            namespace: self.namespace.clone(),
            on_event: self.on_event.clone(),
            carrier: Arc::new(Packets),
            state: Mutex::new(State::new((self.partition)())),
            kick: Mailbox::new(),
            datagrams: Mailbox::new(),
        });
        let mut drivers = self.drivers.lock();
        drivers.retain(|driver| driver.strong_count() > 0);
        drivers.push(Arc::downgrade(&driver));
        Box::pin(async move { driver.start(&fcx) })
    }
}

/// Puts queries to a running [`Recursive`]'s engines, as a DNS-over-TLS or
/// DNS-over-HTTPS front on the same host does. See [`Recursive::handle`].
#[derive(Clone)]
pub struct ResolverHandle {
    drivers: Drivers,
}

impl ResolverHandle {
    /// The reply to the query `bytes` from `client`, as the resolver would
    /// send it over `client`'s transport: the same engine, cache, and
    /// rendering as for a query over UDP or TCP to the address
    /// `client.local` names.
    ///
    /// `None` when no machine of the resolver has that address, or not
    /// yet; when the resolver drops the query unanswered, as it does a
    /// message shorter than a header or a response
    /// ([`Request::parse`] gives silence); or when `fcx` is cancelled.
    /// Dropping the future before it finishes withdraws the query, as a
    /// client that disconnects does.
    pub async fn query(&self, fcx: &Cx, client: Client, bytes: Vec<u8>) -> Option<Vec<u8>> {
        if let Parsed::Silent = Request::parse(&bytes, client.transport) {
            return None;
        }
        let driver = self
            .drivers
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .find(|driver| driver.machine.addr == client.local.ip())?;
        // Each query is a client of its own, so its answer comes back here
        // whatever else the front sends.
        let (id, answers) = driver.open();
        let client = Client {
            connection: Some(id),
            ..client
        };
        let _waiting = Waiting {
            driver: driver.clone(),
            client: client.clone(),
        };
        driver.query(client, bytes);
        let answers = fcx.race(None, answers.take()).await.ok().flatten()?;
        answers.into_iter().next()
    }
}

/// A query put through a [`ResolverHandle`]: once it is answered or
/// dropped, its client is gone.
struct Waiting {
    driver: Arc<Driver<Resolver>>,
    client: Client,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.driver.close(&self.client);
    }
}

// ---------------------------------------------------------------------------
// Partitions

/// Which of a machine's engines answers a client.
trait Partition: Send {
    /// The engine for `client`: an index below `engines`, or `engines`
    /// itself for a new one.
    fn engine(&mut self, client: &Client, engines: usize) -> usize;
    /// The engine `client` already has, if any.
    fn find(&self, client: &Client) -> Option<usize>;
}

/// One engine for every client.
struct Whole;

impl Partition for Whole {
    fn engine(&mut self, _client: &Client, _engines: usize) -> usize {
        0
    }

    fn find(&self, _client: &Client) -> Option<usize> {
        Some(0)
    }
}

/// One engine per value of a key.
struct ByKey<K> {
    key: Arc<dyn Fn(&Client) -> K + Send + Sync>,
    engines: HashMap<K, usize>,
}

impl<K: Hash + Eq + Send> Partition for ByKey<K> {
    fn engine(&mut self, client: &Client, engines: usize) -> usize {
        *self.engines.entry((self.key)(client)).or_insert(engines)
    }

    fn find(&self, client: &Client) -> Option<usize> {
        self.engines.get(&(self.key)(client)).copied()
    }
}

// ---------------------------------------------------------------------------
// Carrying exchanges

/// Hands an exchange's completion to the engine that started it.
type Deliver = Arc<dyn Fn(Input) + Send + Sync>;

/// What an engine asks its driver to carry.
enum Outgoing {
    /// Bytes for a server, as a resolver sends them.
    Transmit(Transmit),
    /// A lookup for the upstream, as an authority makes it.
    Lookup { token: Token, lookup: Lookup },
}

impl Outgoing {
    fn token(&self) -> Token {
        match self {
            Outgoing::Transmit(transmit) => transmit.token,
            Outgoing::Lookup { token, .. } => *token,
        }
    }
}

/// How a program's exchanges travel.
trait Carrier: Send + Sync + 'static {
    /// Carries `outgoing` from `machine` and delivers what comes back.
    /// The future ends when nothing more will come; the driver drops it
    /// when the engine abandons the exchange.
    fn carry(
        &self,
        fcx: Cx,
        machine: Endpoints,
        outgoing: Outgoing,
        deliver: Deliver,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// A resolver's exchanges: real packets from the machine. A resolver makes
/// no lookups.
struct Packets;

impl Carrier for Packets {
    fn carry(
        &self,
        fcx: Cx,
        machine: Endpoints,
        outgoing: Outgoing,
        deliver: Deliver,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let Outgoing::Transmit(transmit) = outgoing else {
            return Box::pin(std::future::ready(()));
        };
        Box::pin(async move {
            let token = transmit.token;
            let fail = |failure| deliver(Input::Failed { token, failure });
            // A kernel with no route for the family fails the send at once.
            if transmit.to.is_ipv4() != machine.addr.is_ipv4() {
                return fail(ExchangeFailure::Unreachable);
            }
            match transmit.transport {
                Transport::Udp => {
                    let Some(mut socket) = bind_random(&fcx, &machine.udp) else {
                        return fail(ExchangeFailure::Unreachable);
                    };
                    socket.send_to(&transmit.bytes, transmit.to);
                    // A datagram from elsewhere goes to the engine too,
                    // which ignores it; the server's own reply ends the
                    // exchange.
                    while let Ok((bytes, from)) = socket.recv(&fcx).await {
                        deliver(Input::Reply {
                            token,
                            from,
                            transport: Transport::Udp,
                            bytes,
                        });
                        if from == transmit.to {
                            return;
                        }
                    }
                }
                Transport::Tcp => match exchange_tcp(&fcx, &machine, &transmit).await {
                    Ok(bytes) => deliver(Input::Reply {
                        token,
                        from: transmit.to,
                        transport: Transport::Tcp,
                        bytes,
                    }),
                    Err(error) => {
                        if let Some(failure) = failure(error) {
                            fail(failure);
                        }
                    }
                },
            }
        })
    }
}

/// A UDP socket on a port drawn from `entropy` in the range 1024 to 65535
/// (RFC 6056 §3.2, RFC 5452 §9.2). While the port drawn is taken, the
/// next one is tried, wrapping around the range, as RFC 6056 §3.3.1
/// does. `None` only when every port of the range is taken.
fn bind_random(entropy: &dyn Entropy, udp: &udp::Endpoint) -> Option<udp::Socket> {
    let ports = u64::from(u16::MAX - FIRST_PORT) + 1;
    let first = entropy.random_below(ports);
    (0..ports).find_map(|step| {
        let offset = u16::try_from((first + step) % ports).ok()?;
        udp.bind(FIRST_PORT + offset).ok()
    })
}

/// Sends `transmit` over a new TCP connection and reads one reply, each
/// after its two-octet length (RFC 1035 §4.2.2). The resolver closes the
/// connection once it has the reply.
async fn exchange_tcp(
    fcx: &Cx,
    machine: &Endpoints,
    transmit: &Transmit,
) -> Result<Vec<u8>, ConnError> {
    let mut conn = machine.tcp.connect(fcx, transmit.to).await?;
    let framed = stream_framed(&transmit.bytes).ok_or(ConnError::Broken)?;
    conn.write_all(fcx, &framed).await?;
    let mut len = [0; 2];
    read_exact(fcx, &mut conn, &mut len).await?;
    let mut reply = vec![0; usize::from(u16::from_be_bytes(len))];
    read_exact(fcx, &mut conn, &mut reply).await?;
    Ok(reply)
}

/// Fills `buf` from `conn`. The other side closing first is
/// [`ConnError::Closed`].
async fn read_exact(
    fcx: &Cx,
    conn: &mut tcp::TcpConnection,
    buf: &mut [u8],
) -> Result<(), ConnError> {
    let mut filled = 0;
    while filled < buf.len() {
        match conn.read(fcx, &mut buf[filled..]).await? {
            0 => return Err(ConnError::Closed),
            n => filled += n,
        }
    }
    Ok(())
}

/// What a connection error tells the engine. A timeout or a cancel tells
/// it nothing: the engine's own deadline decides.
fn failure(error: ConnError) -> Option<ExchangeFailure> {
    match error {
        ConnError::Refused | ConnError::Reset => Some(ExchangeFailure::Refused),
        ConnError::Unreachable(_) => Some(ExchangeFailure::Unreachable),
        ConnError::Closed | ConnError::Broken => Some(ExchangeFailure::Closed),
        ConnError::TimedOut | ConnError::Cancelled => None,
    }
}

/// An authority's lookups: put to its upstream, if it has one, and what
/// came of each handed to the engine, which files it. An authority sends
/// no bytes of its own.
struct ToUpstream(Option<Arc<dyn Upstream>>);

impl Carrier for ToUpstream {
    fn carry(
        &self,
        fcx: Cx,
        _machine: Endpoints,
        outgoing: Outgoing,
        deliver: Deliver,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let upstream = self.0.clone();
        Box::pin(async move {
            let (Outgoing::Lookup { token, lookup }, Some(upstream)) = (outgoing, upstream) else {
                return;
            };
            let looked = upstream.lookup(&fcx, lookup).await;
            deliver(Input::Looked { token, looked });
        })
    }
}

// ---------------------------------------------------------------------------
// The driver

/// Runs a program's engines on one machine.
struct Driver<E: Engine + Send + 'static> {
    fcx: Cx,
    machine: Endpoints,
    /// Makes an engine in a session.
    make: Box<dyn Fn(Session) -> E + Send + Sync>,
    /// The session without a namespace.
    first: Session,
    namespace: Option<Namespace>,
    on_event: Option<OnEvent>,
    carrier: Arc<dyn Carrier>,
    state: Mutex<State<E>>,
    /// Wakes the timer when the next deadline moves.
    kick: Mailbox<()>,
    /// Answers for UDP clients, which the task on port 53 sends.
    datagrams: Mailbox<(Vec<u8>, SocketAddr)>,
}

/// What the driver's mutex guards.
struct State<E> {
    engines: Vec<E>,
    partition: Box<dyn Partition>,
    /// Each running exchange, by engine and token, with what cancels it.
    exchanges: HashMap<(usize, Token), Arc<Mailbox<()>>>,
    /// Where the answers for each stream client and handle query go.
    clients: HashMap<u64, Arc<Mailbox<Vec<u8>>>>,
    next_client: u64,
    /// The engines' next deadline, as the timer last heard it.
    deadline: Option<Instant>,
}

impl<E> State<E> {
    fn new(partition: Box<dyn Partition>) -> State<E> {
        State {
            engines: Vec::new(),
            partition,
            exchanges: HashMap::new(),
            clients: HashMap::new(),
            next_client: 0,
            deadline: None,
        }
    }
}

/// What woke one of the driver's loops.
enum Next<O, I> {
    /// Answers to send, or `None` when there will be none.
    Out(Option<Vec<O>>),
    /// What came in.
    In(I),
    /// The connection was idle too long.
    Idle,
}

impl<E: Engine + Send + 'static> Driver<E> {
    /// Listens on port 53 and starts the driver's tasks. Fails if port 53
    /// is taken on the machine.
    fn start(self: Arc<Self>, fcx: &Cx) -> fictionet::Result {
        let socket = self.machine.udp.bind(PORT)?;
        let listener = self.machine.tcp.listen(PORT)?;
        let driver = self.clone();
        fcx.spawn(move |fcx| driver.serve_datagrams(fcx, socket));
        let driver = self.clone();
        fcx.spawn(move |fcx| driver.serve_streams(fcx, listener));
        fcx.spawn(move |fcx| self.wake_at_deadlines(fcx));
        Ok(())
    }

    /// The session engines answer for now.
    fn session(&self) -> Session {
        self.namespace
            .as_ref()
            .map_or(self.first, Namespace::current)
    }

    /// A client at `peer` that asked the server at `local`.
    fn client(
        &self,
        peer: SocketAddr,
        local: SocketAddr,
        transport: Transport,
        connection: Option<u64>,
    ) -> Client {
        Client {
            peer,
            local,
            transport,
            connection,
            sandbox: self.machine.sandbox_of(peer.ip()),
        }
    }

    /// A new client number and where its answers will go.
    fn open(&self) -> (u64, Arc<Mailbox<Vec<u8>>>) {
        let mut state = self.state.lock();
        let id = state.next_client;
        state.next_client += 1;
        let answers = Arc::new(Mailbox::new());
        state.clients.insert(id, answers.clone());
        (id, answers)
    }

    /// Hands `bytes` from `client` to its engine.
    fn query(self: &Arc<Self>, client: Client, bytes: Vec<u8>) {
        let mut state = self.state.lock();
        let engines = state.engines.len();
        let index = state.partition.engine(&client, engines);
        if index == engines {
            state.engines.push((self.make)(self.session()));
        }
        let query = fictionet::stdlib::services::dns::ClientQuery { client, bytes };
        self.handle(&mut state, index, Input::Query(query));
        self.settle(&mut state);
    }

    /// Hands an exchange's completion to engine `index`.
    fn complete(self: &Arc<Self>, index: usize, input: Input) {
        let mut state = self.state.lock();
        self.handle(&mut state, index, input);
        self.settle(&mut state);
    }

    /// Tells `client`'s engine that it is gone, and forgets where its
    /// answers went.
    fn close(self: &Arc<Self>, client: &Client) {
        let mut state = self.state.lock();
        if let Some(id) = client.connection
            && let Some(answers) = state.clients.remove(&id)
        {
            answers.close();
        }
        if let Some(index) = state.partition.find(client)
            && index < state.engines.len()
        {
            self.handle(&mut state, index, Input::Gone(client.clone()));
            self.settle(&mut state);
        }
    }

    /// Ticks every engine whose deadline has come.
    fn tick(self: &Arc<Self>) {
        let mut state = self.state.lock();
        let now = self.fcx.now();
        for index in 0..state.engines.len() {
            if state.engines[index]
                .next_deadline()
                .is_some_and(|deadline| deadline <= now)
            {
                self.handle(&mut state, index, Input::Tick);
            }
        }
        self.settle(&mut state);
    }

    /// Gives engine `index` `input`, after moving it to the namespace's
    /// session if that has advanced, and hands out what it asks for.
    fn handle(self: &Arc<Self>, state: &mut State<E>, index: usize, input: Input) {
        if let Some(namespace) = &self.namespace {
            let session = namespace.current();
            if session.generation != state.engines[index].generation() {
                state.engines[index].advance(session);
                self.drain(state, index);
            }
        }
        let now = self.fcx.now();
        state.engines[index].handle(input, now, &self.fcx);
        self.drain(state, index);
    }

    /// Hands out engine `index`'s actions and events, in order.
    fn drain(self: &Arc<Self>, state: &mut State<E>, index: usize) {
        while let Some(action) = state.engines[index].poll() {
            match action {
                Action::Send(transmit) => {
                    self.carry(state, index, Outgoing::Transmit(transmit));
                }
                Action::Lookup { token, lookup } => {
                    self.carry(state, index, Outgoing::Lookup { token, lookup });
                }
                Action::Answer(answer) => match answer.client.connection {
                    Some(id) => {
                        if let Some(answers) = state.clients.get(&id) {
                            answers.push(answer.bytes);
                        }
                    }
                    None => self.datagrams.push((answer.bytes, answer.client.peer)),
                },
                Action::Abandon(token) => {
                    if let Some(cancel) = state.exchanges.remove(&(index, token)) {
                        cancel.close();
                    }
                }
                Action::Event(event) => {
                    self.machine.observe_dns(&event);
                    if let Some(on_event) = &self.on_event {
                        on_event(&event);
                    }
                }
            }
        }
    }

    /// Starts carrying `outgoing` for engine `index`, in a task of its own
    /// that ends when the exchange does or the engine abandons it.
    fn carry(self: &Arc<Self>, state: &mut State<E>, index: usize, outgoing: Outgoing) {
        let token = outgoing.token();
        let cancel = Arc::new(Mailbox::new());
        state.exchanges.insert((index, token), cancel.clone());
        let driver = self.clone();
        self.fcx.spawn(move |fcx| async move {
            let deliver: Deliver = {
                let driver = driver.clone();
                Arc::new(move |input| driver.complete(index, input))
            };
            let mut carried =
                driver
                    .carrier
                    .carry(fcx.clone(), driver.machine.clone(), outgoing, deliver);
            let abandoned = poll_fn(|cx| {
                if cancel.poll_take(cx).is_ready() {
                    return Poll::Ready(());
                }
                carried.as_mut().poll(cx)
            });
            let _ = fcx.race(None, abandoned).await;
            driver.state.lock().exchanges.remove(&(index, token));
            Ok(())
        });
    }

    /// Tells the timer when the engines next need a tick, if that moved.
    fn settle(&self, state: &mut State<E>) {
        let deadline = state.engines.iter().filter_map(Engine::next_deadline).min();
        if deadline != state.deadline {
            state.deadline = deadline;
            self.kick.push(());
        }
    }

    /// Ticks the engines at each deadline they ask for.
    async fn wake_at_deadlines(self: Arc<Self>, fcx: Cx) -> fictionet::Result {
        loop {
            let deadline = self.state.lock().deadline;
            match fcx.race(deadline, self.kick.take()).await {
                Ok(_) => {}
                Err(RaceError::Deadline) => self.tick(),
                Err(RaceError::Cancelled) => return Ok(()),
            }
        }
    }

    /// Takes queries on UDP port 53 and sends the engines' answers from it.
    async fn serve_datagrams(
        self: Arc<Self>,
        fcx: Cx,
        mut socket: udp::Socket,
    ) -> fictionet::Result {
        let local = socket.local_addr();
        loop {
            let next = {
                let mut recv = pin!(socket.recv(&fcx));
                poll_fn(|cx| {
                    if let Poll::Ready(answers) = self.datagrams.poll_take(cx) {
                        return Poll::Ready(Next::Out(answers));
                    }
                    recv.as_mut().poll(cx).map(Next::In)
                })
                .await
            };
            match next {
                Next::Out(Some(answers)) => {
                    for (bytes, peer) in answers {
                        socket.send_to(&bytes, peer);
                    }
                }
                Next::In(Ok((bytes, peer))) => {
                    let client = self.client(peer, local, Transport::Udp, None);
                    self.query(client, bytes);
                }
                Next::Out(None) | Next::In(Err(_)) | Next::Idle => return Ok(()),
            }
        }
    }

    /// Accepts TCP connections on port 53, each admitted under the
    /// network's per-peer limit.
    async fn serve_streams(
        self: Arc<Self>,
        fcx: Cx,
        mut listener: tcp::Listener,
    ) -> fictionet::Result {
        loop {
            match listener.accept(&fcx).await {
                Ok(conn) => {
                    let Some(conn) = self.machine.admit(conn) else {
                        continue;
                    };
                    let driver = self.clone();
                    fcx.spawn(move |fcx| async move {
                        driver.serve_stream(&fcx, conn).await;
                        Ok(())
                    });
                }
                Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
                Err(_) => {}
            }
        }
    }

    /// Serves one TCP client: queries after their two-octet lengths, which
    /// may be pipelined, and answers in the order they are ready. The
    /// connection stays open after an answer, until the client closes it
    /// or it has been quiet for the network's DNS idle time
    /// (RFC 7766 §6.2.3).
    async fn serve_stream(self: &Arc<Self>, fcx: &Cx, mut conn: tcp::TcpConnection) {
        let mut buf = vec![0; READ_BUFFER];
        // The connection's read buffer and the bytes read but not yet
        // framed are charged to its sandbox's budget, as the service driver
        // charges them; one that does not fit is closed.
        let mut charge = match self.machine.budget_of(conn.peer_addr().ip()) {
            Some(budget) => match budget.charge(buf.len()) {
                Some(charge) => Some(charge),
                None => return,
            },
            None => None,
        };
        let (id, answers) = self.open();
        let client = self.client(
            conn.peer_addr(),
            conn.local_addr(),
            Transport::Tcp,
            Some(id),
        );
        let idle = self.machine.limits().dns_tcp_idle;
        let mut queries = Queries::new(Framing::Stream);
        let mut input = Vec::new();
        let mut quiet_since = fcx.now();
        loop {
            let next = {
                let mut read = pin!(conn.read(fcx, &mut buf));
                let mut quiet = pin!(fcx.sleep_until(quiet_since + idle));
                poll_fn(|cx| {
                    if let Poll::Ready(out) = answers.poll_take(cx) {
                        return Poll::Ready(Next::Out(out));
                    }
                    if let Poll::Ready(read) = read.as_mut().poll(cx) {
                        return Poll::Ready(Next::In(read));
                    }
                    quiet.as_mut().poll(cx).map(|_| Next::Idle)
                })
                .await
            };
            match next {
                Next::Out(Some(out)) => {
                    if write_framed(fcx, &mut conn, out).await.is_err() {
                        break;
                    }
                    quiet_since = fcx.now();
                }
                Next::In(Ok(n)) if n > 0 => {
                    input.extend_from_slice(&buf[..n]);
                    while let Ok(Step::Item(query, used)) = queries.decode(&input, false) {
                        input.drain(..used);
                        self.query(client.clone(), query);
                    }
                    if let Some(charge) = &mut charge
                        && !charge.set(buf.len() + input.len())
                    {
                        break;
                    }
                    quiet_since = fcx.now();
                }
                Next::Out(None) | Next::In(_) | Next::Idle => break,
            }
        }
        self.close(&client);
    }
}

/// Writes each message after its two-octet length.
async fn write_framed(
    fcx: &Cx,
    conn: &mut tcp::TcpConnection,
    messages: Vec<Vec<u8>>,
) -> Result<(), ConnError> {
    for message in messages {
        // Engines fit stream answers to 65535 octets (RFC 1035 §4.2.2).
        let framed = stream_framed(&message).ok_or(ConnError::Broken)?;
        conn.write_all(fcx, &framed).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mailboxes

/// Items handed from one task to another, which waits for them.
struct Mailbox<T>(Mutex<Slot<T>>);

struct Slot<T> {
    items: Vec<T>,
    closed: bool,
    waker: Option<Waker>,
}

impl<T> Mailbox<T> {
    fn new() -> Mailbox<T> {
        Mailbox(Mutex::new(Slot {
            items: Vec::new(),
            closed: false,
            waker: None,
        }))
    }

    /// Adds `item` and wakes the waiting task. A closed mailbox drops it.
    fn push(&self, item: T) {
        let waker = {
            let mut slot = self.0.lock();
            if slot.closed {
                return;
            }
            slot.items.push(item);
            slot.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Takes no more items, and wakes the waiting task.
    fn close(&self) {
        let waker = {
            let mut slot = self.0.lock();
            slot.closed = true;
            slot.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Every item waiting, or `None` once the mailbox is closed and empty.
    fn poll_take(&self, cx: &mut Context<'_>) -> Poll<Option<Vec<T>>> {
        let mut slot = self.0.lock();
        if !slot.items.is_empty() {
            return Poll::Ready(Some(std::mem::take(&mut slot.items)));
        }
        if slot.closed {
            return Poll::Ready(None);
        }
        let old = slot.waker.replace(cx.waker().clone());
        drop(slot);
        drop(old);
        Poll::Pending
    }

    async fn take(&self) -> Option<Vec<T>> {
        poll_fn(|cx| self.poll_take(cx)).await
    }
}
