//! DNS over TLS and DNS over HTTPS in front of a running [`Recursive`](super::Recursive):
//! the same engines and caches answer, whichever way a query arrives.
//!
//! [`Fronts`] puts a resolver's [`ResolverHandle`] behind two more ports of
//! a host. On TCP port 853 it serves DNS over TLS (RFC 7858): each query
//! after its two-octet length, as over TCP port 53, pipelined, and answered
//! as each answer is ready. On TCP port 443 it serves DNS over HTTPS
//! (RFC 8484) to its names and to clients that connect to the address
//! with no name: `GET /dns-query?dns=...` and `POST /dns-query` with the
//! query as `application/dns-message`, answered in the same media type
//! with a `Cache-Control` freshness no longer than the answer's smallest
//! TTL (RFC 8484 §5.1).
//!
//! Every other request, a path other than `/dns-query` or a GET with no
//! `dns` parameter, goes to the world's [`fallback`](Fronts::fallback)
//! handler, such as one that serves a JSON API or a real operator's error
//! pages. Without one it gets a plain `404` or `400`.
//!
//! A query from either front reaches the resolver as a stream client
//! ([`Transport::Tcp`]) from the connection's peer and sandbox, so a
//! sandbox's DNS over HTTPS answer comes from the cache its UDP questions
//! filled, with the same TTL countdown and the same validation.
//!
//! The certificates are the world's: a TLS server proves who it is with
//! its private key on every handshake, and the world holds no operator's
//! key. A world's CA issues a resolver's certificate for its DNS over
//! HTTPS names and its addresses, as IP SANs (RFC 5280 §4.2.1.6), so a
//! client that connects to an address checks it as it would check a name.
//! DNS over QUIC is not served: UDP port 853 stays closed.
//!
//! ```
//! # use std::net::Ipv4Addr;
//! # use std::time::SystemTime;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::protocols::dns::rr::Name;
//! # use fictionet::stdlib::protocols::x509::{Time, Validity};
//! # use fictionet::stdlib::services::ca::Ca;
//! # use fictionet::stdlib::services::dns::{WallClock, resolver::Config};
//! # use fictionet::stdlib::world::net::Net;
//! # use fictionet::stdlib::world::net::dns::Recursive;
//! # use fictionet::stdlib::world::net::dns::encrypted::Fronts;
//! # async fn world(fcx: Cx, attachments: Attachments, ca: Ca) -> Result {
//! # let start = SystemTime::now();
//! # let clock = WallClock { start };
//! # let validity = Validity { not_before: Time::from_unix(1_700_000_000)?, not_after: Time::from_unix(1_900_000_000)? };
//! let tls = ca.issue(&fcx, &["dns.example", "45.33.9.9"], validity)?.server_config(&fcx, start)?;
//! let resolver = Recursive::new(Config::new(), clock);
//! let fronts = Fronts::new(resolver.handle(), move |_| tls.clone())
//!     .names([Name::from_ascii("dns.example.")?]);
//! Net::new(fictionet::stdlib::world::net::Pools {
//!     v4: Some("192.0.2.0/24".parse()?),
//!     v6: Some("2001:db8:1::/64".parse()?),
//! })
//!     .host("resolver", |h| fronts.doh(fronts.dot(h.at(Ipv4Addr::new(45, 33, 9, 9)).program(resolver))))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, SystemTime};

use http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderValue, Method, Request, Response, StatusCode};

use fictionet::Cx;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::base64::{self, Padding};
use fictionet::stdlib::layer::{
    Admit, Budget, Chain, Charge, Decoded, Env, Framed, Framing, Layer, MessageCommand,
    MessageEvent, Owned, OwnedWork, Timers, Top, WorkOwner,
};
use fictionet::stdlib::network::{ConnInfo, Transport};
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData};
use fictionet::stdlib::protocols::dns::{
    Framing as DnsFraming, Queries, StreamMessage, read_message,
};
use fictionet::stdlib::protocols::urlencoded_form::{self, Form};
use fictionet::stdlib::services::dns::Client;
use fictionet::stdlib::services::stack::{self, Boxed, Job, StreamEnd, StreamLimits};
use fictionet::stdlib::services::tls::{self, ServerConfig};
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Reply, request_host};
use fictionet::time::Instant;

use super::super::{Arrival, Host, Limits, Opening, PortServer, Sni};
use super::ResolverHandle;

/// The port of DNS over TLS (RFC 7858 §3.1).
const DOT_PORT: u16 = 853;

/// The port of DNS over HTTPS: HTTPS's own (RFC 8484 §5, RFC 9110 §4.2.2).
const DOH_PORT: u16 = 443;

/// The path RFC 8484's examples use, which every large operator serves.
const DNS_QUERY: &str = "/dns-query";

/// The media type of a DNS message over HTTPS (RFC 8484 §6).
const DNS_MESSAGE: &str = "application/dns-message";

/// The largest DNS message the `application/dns-message` media type
/// carries (RFC 8484 §6).
const MAX_MESSAGE: usize = u16::MAX as usize;

/// What a TLS port's handshake gets its config from.
type TlsFor = Arc<dyn Fn(&Cx) -> Arc<ServerConfig> + Send + Sync>;

/// A query's answer, or `None` when the service leaves it unanswered.
/// Dropping this future cancels the query. Services must keep any work they
/// start owned by the future, so a closed connection cannot leave it running.
pub type QueryFuture = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>;

/// The DNS application shared by DNS over TLS and DNS over HTTPS.
///
/// `query` receives a whole DNS message without stream framing, and the
/// connection's client identity. It returns a whole response without framing.
/// The fronts retain framing, connection limits, cancellation and delivery:
/// DoT sends each completed answer as a whole message, while DoH answers the
/// corresponding HTTP request. The default service is [`ResolverHandle`].
/// Async closures with these arguments also implement this trait.
pub trait QueryService: Send + Sync + 'static {
    /// Answer one query in the connection's world context.
    fn query(&self, fcx: Cx, client: Client, message: Vec<u8>) -> QueryFuture;
}

impl QueryService for ResolverHandle {
    fn query(&self, fcx: Cx, client: Client, message: Vec<u8>) -> QueryFuture {
        let resolver = self.clone();
        Box::pin(async move { resolver.query(&fcx, client, message).await })
    }
}

impl<F, Fut> QueryService for F
where
    F: Fn(Cx, Client, Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<Vec<u8>>> + Send + 'static,
{
    fn query(&self, fcx: Cx, client: Client, message: Vec<u8>) -> QueryFuture {
        Box::pin(self(fcx, client, message))
    }
}

/// DNS over TLS and over HTTPS in front of a [`Recursive`](super::Recursive),
/// added to a host with [`dot`](Self::dot) and [`doh`](Self::doh). See the
/// [module docs](self).
pub struct Fronts<Q = ResolverHandle> {
    resolver: Arc<Q>,
    tls: TlsFor,
    tls_layer: tls::Factory,
    names: Vec<LowerName>,
    at: Option<IpAddr>,
    date: Option<SystemTime>,
    fallback: Option<Arc<dyn Handler>>,
}

impl<Q> Clone for Fronts<Q> {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            tls: self.tls.clone(),
            tls_layer: self.tls_layer.clone(),
            names: self.names.clone(),
            at: self.at,
            date: self.date,
            fallback: self.fallback.clone(),
        }
    }
}

impl<Q: QueryService> Fronts<Q> {
    /// Fronts for the resolver `resolver` reaches, whose TLS handshakes
    /// use the config `tls` returns for each. Pass a [`ResolverHandle`] for
    /// the default recursive service, or any [`QueryService`] to replace it.
    pub fn new(
        resolver: Q,
        tls: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    ) -> Self {
        Fronts {
            resolver: Arc::new(resolver),
            tls: Arc::new(tls),
            tls_layer: tls::Factory::default(),
            names: Vec::new(),
            at: None,
            date: None,
            fallback: None,
        }
    }

    /// Replaces TLS for both encrypted fronts. The first server installed
    /// on an address and port supplies the TLS factory for every name on
    /// that listener; certificate selection remains per name.
    pub fn tls_layer(mut self, factory: tls::Factory) -> Self {
        self.tls_layer = factory;
        self
    }

    /// Replaces the DNS application while keeping both fronts' configuration.
    /// Framing and client identity still belong to the fronts.
    pub fn query_service<S: QueryService>(self, service: S) -> Fronts<S> {
        Fronts {
            resolver: Arc::new(service),
            tls: self.tls,
            tls_layer: self.tls_layer,
            names: self.names,
            at: self.at,
            date: self.date,
            fallback: self.fallback,
        }
    }

    /// Answers every DNS over HTTPS request RFC 8484 does not cover with
    /// `handler`: a path other than `/dns-query`, and a GET of it with no
    /// `dns` parameter. It is called only for requests to the fronts'
    /// names and address. A handler that puts questions to the resolver
    /// itself, such as a JSON API, does so through
    /// [`client`](Self::client) and [`resolver`](Self::resolver) of the
    /// fronts it answers for, so it is made after
    /// [`resolver_at`](Self::resolver_at).
    pub fn fallback(self, handler: Arc<dyn Handler>) -> Self {
        Fronts {
            fallback: Some(handler),
            ..self
        }
    }

    /// The names DNS over HTTPS answers to, such as `dns.example`. A
    /// request over TLS for another name, by SNI or by its host, gets
    /// `421 Misdirected Request`; a request for the address it arrived
    /// at, with no name, is answered.
    pub fn names(self, names: impl IntoIterator<Item = Name>) -> Self {
        Fronts {
            names: names
                .into_iter()
                .map(|mut name| {
                    name.set_fqdn(true);
                    LowerName::new(&name)
                })
                .collect(),
            ..self
        }
    }

    /// Puts queries to the resolver's machine at `addr` instead of the one
    /// at the address the client connected to. A front on another host
    /// needs it, such as DNS over HTTPS at the addresses of a name of its
    /// own that are not the resolver's. The resolver then sees each query
    /// as asked of `addr`.
    pub fn resolver_at(self, addr: IpAddr) -> Self {
        Fronts {
            at: Some(addr),
            ..self
        }
    }

    /// Sends `Date` headers on DNS over HTTPS answers, `start` being the
    /// world's date at the start of the run
    /// ([`httpd::Server::date`]).
    pub fn date(self, start: SystemTime) -> Self {
        Fronts {
            date: Some(start),
            ..self
        }
    }

    /// The client a query over `conn` reaches the resolver as: the
    /// connection's peer and sandbox over [`Transport::Tcp`], asking the
    /// address the connection arrived at, or the one
    /// [`resolver_at`](Self::resolver_at) gives. `None` for a connection
    /// with no addresses, which no network made.
    pub fn client(&self, conn: &ConnInfo) -> Option<Client> {
        self.front().client(conn)
    }

    /// The query service the fronts put queries to, by default a resolver handle.
    pub fn resolver(&self) -> &Q {
        &self.resolver
    }

    /// `host` serving DNS over TLS on TCP port 853, for any name a client
    /// sends, offering `dot`, the ALPN identifier IANA registers for it.
    ///
    /// The default composition is `Secure<Chain<Framed<Queries,
    /// StreamMessage>, Queried>, _>`: `Secure` builds
    /// `Chain<TlsLayer, Later<_>>`, and `Queried` invokes this query service.
    pub fn dot(&self, host: Host) -> Host {
        let tls = self.tls.clone();
        let port = Dot {
            front: Arc::new(self.front()),
            tls_layer: self.tls_layer.clone(),
        };
        host.tls_accept(DOT_PORT, Sni::Any, move |fcx| tls(fcx), port)
    }

    /// `host` serving DNS over HTTPS on TCP port 443, over HTTP/1.1 and
    /// HTTP/2. Its handshake takes any name, since a client that connects
    /// to the address sends none; its requests are answered only for
    /// [`names`](Self::names) and the address. Those names are its own on
    /// the port, so no other host at the address can serve them there.
    ///
    /// The default composition is `Secure<Http, _>`, with
    /// `Chain<TlsLayer, Later<Http>>` deferring HTTP until negotiation.
    /// `Http` chooses HTTP/1's `Switch` or HTTP/2's
    /// `Chain<Http2, Children<Respond, Top, Opening>>`; their handlers invoke this service.
    pub fn doh(&self, host: Host) -> Host {
        let server = || {
            let server = httpd::Server::new(Doh {
                front: Arc::new(self.front()),
                names: self.names.clone(),
                fallback: self.fallback.clone(),
            })
            .https()
            .tls_layer(self.tls_layer.clone())
            .default_host();
            match self.date {
                Some(start) => server.date(start),
                None => server,
            }
        };
        let tls = self.tls.clone();
        let mut host = host.tls_accept(DOH_PORT, Sni::Any, move |fcx| tls(fcx), server());
        for name in &self.names {
            let tls = self.tls.clone();
            let sni = Sni::from(name.to_ascii().as_str());
            host = host.tls_accept(DOH_PORT, sni, move |fcx| tls(fcx), server());
        }
        host
    }

    fn front(&self) -> Front {
        Front {
            resolver: self.resolver.clone(),
            at: self.at,
        }
    }
}

/// What both fronts put queries to.
struct Front {
    resolver: Arc<dyn QueryService>,
    at: Option<IpAddr>,
}

impl Front {
    /// The client a query over `conn` is from. `None` for a connection
    /// with no addresses, which no network made.
    fn client(&self, conn: &ConnInfo) -> Option<Client> {
        let (peer, local) = (conn.peer?, conn.local?);
        let local = self
            .at
            .map_or(local, |at| SocketAddr::new(at, local.port()));
        Some(Client {
            peer,
            local,
            transport: Transport::Tcp,
            connection: None,
            // The serve layer reports a peer no sandbox has with id 0
            // (`ServeOptions::sandbox`).
            sandbox: conn.sandbox.clone().filter(|sandbox| sandbox.id != 0),
        })
    }
}

// ---------------------------------------------------------------------------
// DNS over TLS

/// How many queries one DNS over TLS connection may have with the resolver
/// and answered but not yet written, together. A client that pipelines
/// more waits: its next query is read once an answer is written, or once
/// the resolver leaves a query unanswered.
const QUERIES: usize = 32;

/// The stack of one DNS over TLS connection, over TLS or a plain
/// connection: DNS stream framing, then [`Queried`].
type DotStack = Chain<Framed<Queries, StreamMessage>, Queried>;

/// DNS over TLS on one port.
struct Dot {
    front: Arc<Front>,
    tls_layer: tls::Factory,
}

impl Dot {
    /// The stack for the connection `conn`, under the network's `limits`.
    fn stack(&self, conn: &ConnInfo, limits: &Limits) -> DotStack {
        Chain::new(
            Framed::new(Queries::new(DnsFraming::Stream)),
            Queried::new(self.front.clone(), conn, limits.dns_tcp_idle),
        )
    }
}

impl PortServer for Dot {
    fn tls_factory(&self) -> tls::Factory {
        self.tls_layer.clone()
    }

    /// The same stack over a connection with no TLS in front.
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let stack = self.stack(&arrival.info, &arrival.limits);
        let budget = arrival.budget.unwrap_or_else(Budget::unlimited);
        // The stack keeps its own idle time.
        let limits = StreamLimits {
            idle: None,
            write_timeout: Some(arrival.limits.write_timeout),
        };
        let (conn, info, socket) = (arrival.conn, arrival.info, arrival.socket);
        Box::pin(async move {
            let ended = stack::stream(&fcx, conn, &info, stack, budget, limits, |_| {});
            if let Ok(StreamEnd::Reset) = ended.await {
                socket.reset();
            }
        })
    }

    /// Queries and answers in the same stack as TLS.
    fn over_tls(&self, _fcx: &Cx, opening: &Opening) -> Option<Boxed> {
        Some(Boxed::new(self.stack(&opening.info, &opening.limits)))
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        vec![b"dot".to_vec()]
    }
}

/// The port [`Queried`] runs on: whole queries up, answers down.
type QueryPort = Framing<Queries, StreamMessage>;

/// The timer of a DNS over TLS connection with no query waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Quiet;

/// One DNS over TLS connection's queries: each goes to the resolver as it
/// arrives, as [work](Ask), and each answer is written whole as soon as it
/// is ready, so answers may come out of order (RFC 7766 §6.2.1.1). A query
/// the resolver leaves unanswered writes nothing.
///
/// A query keeps its charge to the connection's budget while the resolver
/// has it, and its answer is charged before it is kept. An answer that
/// does not fit closes the connection, as the queries still with the
/// resolver are dropped.
///
/// The connection closes once it has been quiet for the network's idle
/// time for DNS over TCP with no query waiting (RFC 7766 §6.2.3, RFC 7858
/// §3.4), or once the client has ended its direction and every answer is
/// written.
struct Queried {
    front: Arc<Front>,
    /// Who the queries are from. `None` for a connection with no
    /// addresses, which no network made: its queries go nowhere.
    client: Option<Client>,
    idle: Duration,
    owner: WorkOwner,
    /// The next query's number. The work of a query is known by it, since
    /// two queries on a connection may carry the same DNS ID.
    next: u64,
    /// The numbers of the queries with the resolver, or waiting in `work`
    /// to go to it.
    asking: Vec<u64>,
    work: VecDeque<OwnedWork<Ask>>,
    /// Answers the framing below has not taken yet, in the order they came.
    answers: VecDeque<Owned<StreamMessage>>,
    timers: Timers<Quiet>,
    /// No more queries are read: the client's input is over, the
    /// connection was quiet too long, or an answer did not fit.
    over: bool,
    end_sent: bool,
}

impl Queried {
    /// The queries of the connection `conn` to the resolver `front` puts
    /// them to, closed after `idle` with none waiting.
    fn new(front: Arc<Front>, conn: &ConnInfo, idle: Duration) -> Queried {
        Queried {
            client: front.client(conn),
            front,
            idle,
            owner: WorkOwner::new(),
            next: 0,
            asking: Vec::new(),
            work: VecDeque::new(),
            answers: VecDeque::new(),
            timers: Timers::new(),
            over: false,
            end_sent: false,
        }
    }

    /// Reads no more queries.
    fn stop(&mut self) {
        self.over = true;
        self.timers.cancel(&Quiet);
    }

    /// Whether no query is waiting: none with the resolver, and no answer
    /// left to hand below.
    fn quiet(&self) -> bool {
        self.asking.is_empty() && self.answers.is_empty()
    }
}

impl Layer for Queried {
    type Lower = QueryPort;
    type Upper = Top;
    type Report = Infallible;
    type Timer = Quiet;
    type Work = OwnedWork<Ask>;
    type Done = Answered;
    type Error = Infallible;

    fn is_terminal(&self) -> bool {
        self.end_sent
    }

    fn on_event(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        event: MessageEvent<Decoded<Queries>>,
    ) -> Result<Admit<MessageEvent<Decoded<Queries>>>, Infallible> {
        if self.over {
            return Ok(Admit::Closed(event));
        }
        match event {
            MessageEvent::Message(Ok(query)) => {
                if self.asking.len() + self.answers.len() >= QUERIES {
                    return Ok(Admit::Blocked(MessageEvent::Message(Ok(query))));
                }
                self.timers.cancel(&Quiet);
                let Some(client) = self.client.clone() else {
                    return Ok(Admit::Taken);
                };
                // The framing charged it as the longest message; it keeps
                // only what it holds, and less always fits.
                let (query, mut charge) = query.into_parts();
                charge.set(query.capacity());
                let generation = self.next;
                self.next += 1;
                self.asking.push(generation);
                self.work.push_back(self.owner.own(Ask {
                    generation,
                    resolver: self.front.resolver.clone(),
                    query: Some((client, query)),
                    charge: Some(charge),
                    asking: None,
                }));
            }
            // A stream of DNS messages fails only cut short: what came
            // whole is still answered.
            MessageEvent::Message(Err(_)) | MessageEvent::Ended => self.stop(),
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn on_timer(&mut self, _env: &mut Env<'_, Infallible>, timer: Quiet) -> Result<(), Infallible> {
        self.timers.cancel(&timer);
        if !self.over && self.quiet() {
            self.stop();
        }
        Ok(())
    }

    fn on_done(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        done: Answered,
    ) -> Result<(), Infallible> {
        let Some(at) = self.asking.iter().position(|g| *g == done.generation) else {
            return Ok(());
        };
        self.asking.swap_remove(at);
        match done.outcome {
            Outcome::Answer(answer) => self.answers.push_back(answer),
            Outcome::Unanswered => {}
            Outcome::Budget => {
                self.stop();
                self.owner.cancel();
                self.owner = WorkOwner::new();
                self.work.clear();
                self.asking.clear();
            }
        }
        Ok(())
    }

    /// Starts the idle time once no query is waiting.
    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        if !self.over && self.quiet() && self.timers.get(&Quiet).is_none() {
            self.timers.set(Quiet, env.now() + self.idle);
        }
        Ok(false)
    }

    fn take_command(&mut self) -> Option<MessageCommand<Owned<StreamMessage>>> {
        if let Some(answer) = self.answers.pop_front() {
            return Some(MessageCommand::Send(answer));
        }
        if self.over && self.asking.is_empty() && !self.end_sent {
            self.end_sent = true;
            return Some(MessageCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<OwnedWork<Ask>> {
        self.work.pop_front()
    }

    fn deadline(&self) -> Option<(Instant, Quiet)> {
        self.timers.next()
    }
}

/// The resolver's answer to one query, on its way.
type Asking = QueryFuture;

/// One query of a DNS over TLS connection, with the resolver until it
/// answers. Run with no world, it is unanswered.
struct Ask {
    generation: u64,
    resolver: Arc<dyn QueryService>,
    query: Option<(Client, Vec<u8>)>,
    /// What the query holds while the resolver has it, then what its
    /// answer holds.
    charge: Option<Charge>,
    asking: Option<Asking>,
}

/// What became of one query.
struct Answered {
    generation: u64,
    outcome: Outcome,
}

enum Outcome {
    /// The resolver answered with this message.
    Answer(Owned<StreamMessage>),
    /// The resolver dropped the query.
    Unanswered,
    /// The resolver answered, and the connection's budget has no room for
    /// the answer.
    Budget,
}

impl Job for Ask {
    type Done = Answered;

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Answered> {
        if let Some((client, query)) = self.query.take()
            && let Some(fcx) = fcx.cloned()
        {
            self.asking = Some(self.resolver.query(fcx, client, query));
        }
        let answer = match &mut self.asking {
            Some(asking) => ready!(asking.as_mut().poll(cx)),
            None => None,
        };
        self.asking = None;
        let outcome = match (answer, self.charge.take()) {
            (Some(answer), Some(mut charge)) => {
                if charge.set(answer.capacity()) {
                    Outcome::Answer(Owned::new(StreamMessage(answer), charge))
                } else {
                    Outcome::Budget
                }
            }
            (Some(_), None) => Outcome::Budget,
            (None, _) => Outcome::Unanswered,
        };
        Poll::Ready(Answered {
            generation: self.generation,
            outcome,
        })
    }
}

// ---------------------------------------------------------------------------
// DNS over HTTPS

/// DNS over HTTPS for one resolver: RFC 8484 at `/dns-query`, for the
/// fronts' names and the address, and the world's fallback for the rest.
struct Doh {
    front: Arc<Front>,
    names: Vec<LowerName>,
    fallback: Option<Arc<dyn Handler>>,
}

impl Handler for Doh {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let conn = ex.conn();
        let client = self
            .front
            .client(conn)
            .filter(|_| self.serves(conn, &request));
        let Some(client) = client else {
            let refusal = Refusal::Text(
                StatusCode::MISDIRECTED_REQUEST,
                "This server does not serve that host.\n",
            );
            return Reply::Now(refusal.response());
        };
        let query = match ask(&request) {
            Asked::Query(query) => query,
            Asked::Refused(refusal) => return Reply::Now(refusal.response()),
            Asked::Elsewhere(refusal) => {
                return match &self.fallback {
                    Some(fallback) => fallback.call(request, ex),
                    None => Reply::Now(refusal.response()),
                };
            }
        };
        let resolver = self.front.resolver.clone();
        Reply::Later(Box::new(move |fcx| {
            Box::pin(async move {
                let Some(answer) = resolver.query(fcx, client, query).await else {
                    let refusal =
                        Refusal::Text(StatusCode::BAD_REQUEST, "The query is not a DNS query.\n");
                    return Ok(refusal.response());
                };
                Ok(message_response(answer))
            })
        }))
    }
}

/// What a request asks of RFC 8484's `/dns-query`.
enum Asked {
    /// This query, as a DNS message.
    Query(Vec<u8>),
    /// Nothing, for this reason RFC 8484 gives.
    Refused(Refusal),
    /// Nothing RFC 8484 covers: the fallback answers it, or else this
    /// refusal.
    Elsewhere(Refusal),
}

/// Why a request gets no answer from the resolver.
enum Refusal {
    /// This status, with this text.
    Text(StatusCode, &'static str),
    /// `405 Method Not Allowed`, with the methods the path allows.
    Method(&'static str),
}

impl Refusal {
    fn response(self) -> Response<Body> {
        match self {
            Refusal::Text(status, text) => httpd::text(status, text),
            Refusal::Method(allowed) => {
                let mut response =
                    httpd::text(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed.\n");
                response
                    .headers_mut()
                    .insert(ALLOW, HeaderValue::from_static(allowed));
                response
            }
        }
    }
}

impl Doh {
    /// Whether this resolver answers `request` over `conn`: a name the
    /// client sent with SNI must be one of its names, and the request's
    /// host must be one of them or the address it arrived at.
    fn serves(&self, conn: &ConnInfo, request: &Request<Body>) -> bool {
        let named = |host: &str| fqdn(host).is_some_and(|name| self.names.contains(&name));
        let sni = conn.sni.as_deref().is_none_or(named);
        let host = request_host(request).is_some_and(|host| {
            let literal = host.trim_start_matches('[').trim_end_matches(']');
            match IpAddr::from_str(literal) {
                Ok(addr) => conn.local.is_some_and(|local| local.ip() == addr),
                Err(_) => named(&host),
            }
        });
        sni && host
    }
}

/// `host`, a name as SNI and HTTP give it, without the root's dot, as the
/// fully qualified name it means.
fn fqdn(host: &str) -> Option<LowerName> {
    let mut name = Name::from_ascii(host).ok()?;
    name.set_fqdn(true);
    Some(LowerName::new(&name))
}

/// The query `request` asks of `/dns-query` (RFC 8484 §4.1), or why it
/// asks none.
fn ask(request: &Request<Body>) -> Asked {
    if request.uri().path() != DNS_QUERY {
        return Asked::Elsewhere(Refusal::Text(StatusCode::NOT_FOUND, "Not found.\n"));
    }
    let method = request.method();
    if *method == Method::POST {
        return posted(request);
    }
    if *method != Method::GET {
        return Asked::Refused(Refusal::Method("GET, POST"));
    }
    let query = request.uri().query().unwrap_or("");
    let Ok(form) = Form::parse(query.as_bytes()) else {
        return Asked::Refused(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "Bad query string.\n",
        ));
    };
    let Some(dns) = urlencoded_form::first(&form.pairs, "dns") else {
        return Asked::Elsewhere(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The request has no dns parameter.\n",
        ));
    };
    match base64url(dns) {
        Some(query) => Asked::Query(query),
        None => Asked::Refused(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The dns parameter is not a DNS message in base64url.\n",
        )),
    }
}

/// The DNS message a POST carries as its body (RFC 8484 §4.1).
fn posted(request: &Request<Body>) -> Asked {
    let media = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase());
    if media.as_deref() != Some(DNS_MESSAGE) {
        return Asked::Refused(Refusal::Text(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported media type.\n",
        ));
    }
    let Some(body) = request.body().bytes() else {
        return Asked::Refused(Refusal::Text(
            StatusCode::BAD_REQUEST,
            "The body did not arrive whole.\n",
        ));
    };
    if body.len() > MAX_MESSAGE {
        return Asked::Refused(Refusal::Text(
            StatusCode::PAYLOAD_TOO_LARGE,
            "A DNS message is at most 65535 octets.\n",
        ));
    }
    Asked::Query(body.to_vec())
}

/// The `dns` parameter of a GET: base64url (RFC 4648 §5), which RFC 8484
/// §6 sends without padding. Padding is accepted, as decoders commonly do.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let standard: Vec<u8> = text
        .bytes()
        .map(|byte| match byte {
            b'-' => Some(b'+'),
            b'_' => Some(b'/'),
            b'+' | b'/' => None,
            byte => Some(byte),
        })
        .collect::<Option<_>>()?;
    let message = base64::decode(&standard, Padding::Optional)?;
    (message.len() <= MAX_MESSAGE).then_some(message)
}

/// The response carrying the resolver's `answer` as
/// `application/dns-message`, with a `Cache-Control` freshness from
/// [`freshness`] when the answer parses. Every DNS answer, SERVFAIL and
/// NXDOMAIN included, is `200 OK` (RFC 8484 §4.2.1).
pub fn message_response(answer: Vec<u8>) -> Response<Body> {
    let freshness = read_message(&answer).ok().as_ref().and_then(freshness);
    let mut response = Response::new(Body::from(answer));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE));
    if let Some(seconds) = freshness
        && let Ok(value) = HeaderValue::from_str(&format!("max-age={seconds}"))
    {
        headers.insert(CACHE_CONTROL, value);
    }
    response
}

/// How long an HTTP cache may keep a response carrying `message`
/// (RFC 8484 §5.1): the smallest TTL in its answer section, or for an
/// answer with no records the TTL of the SOA in its authority section,
/// no longer than that SOA's MINIMUM (RFC 2308 §5). `None` when it has
/// neither, as a SERVFAIL has.
pub fn freshness(message: &Message) -> Option<u32> {
    if !message.answers.is_empty() {
        return message.answers.iter().map(|record| record.ttl).min();
    }
    message
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min()
}

#[cfg(test)]
mod tests {
    //! DNS over TLS's queries over its framing, in a harness: the test does
    //! the resolver's part, so it decides when each query is answered and
    //! with what. The tests compare what the client reads with what the
    //! resolver answered, never fixed bytes.

    use std::task::Waker;

    use super::super::Recursive;
    use super::*;
    use fictionet::stdlib::codec::{Decode, Step};
    use fictionet::stdlib::layer::{Harness, Side};
    use fictionet::stdlib::services::dns::WallClock;
    use fictionet::stdlib::services::dns::resolver::Config;
    use fictionet::{Entropy, Seed, SeededEntropy};

    const IDLE: Duration = Duration::from_secs(10);

    fn harness(budget: Budget) -> Harness<DotStack> {
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let front = Arc::new(Front {
            resolver: Arc::new(Recursive::new(Config::new(), clock).handle()),
            at: None,
        });
        let local = "192.0.2.1:853".parse().unwrap();
        let peer = "198.51.100.7:40000".parse().unwrap();
        let conn = ConnInfo::new(1, local, peer);
        let stack = Chain::new(
            Framed::new(Queries::new(DnsFraming::Stream)),
            Queried::new(front, &conn, IDLE),
        );
        Harness::with_budget(Seed::from_u64(7), stack, budget)
    }

    /// A message of `len` octets, different for each `seed`. The layer
    /// does not read messages, so it need not be DNS.
    fn message(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    /// `messages` as a client writes them, each after its length.
    fn framed(messages: &[Vec<u8>]) -> Vec<u8> {
        messages
            .iter()
            .flat_map(|m| StreamMessage(m.clone()).to_bytes().unwrap())
            .collect()
    }

    /// The client sends `bytes` in pieces of 1 to 7 octets.
    fn push_cut(h: &mut Harness<DotStack>, bytes: &[u8], seed: u64) {
        let cuts = SeededEntropy::new(Seed::from_u64(seed));
        let mut at = 0;
        while at < bytes.len() {
            let end = (at + 1 + cuts.random_below(7) as usize).min(bytes.len());
            h.push(&bytes[at..end]).unwrap();
            at = end;
        }
    }

    /// The messages a client reads from `bytes`, which must hold only
    /// whole ones.
    fn read(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut queries = Queries::new(DnsFraming::Stream);
        let mut at = 0;
        let mut messages = Vec::new();
        while at < bytes.len() {
            let Step::Item(message, used) = queries.decode(&bytes[at..], false).unwrap() else {
                panic!("a message cut short");
            };
            messages.push(message);
            at += used;
        }
        messages
    }

    /// The queries the stack has handed the resolver since last asked.
    fn asks(h: &mut Harness<DotStack>) -> Vec<OwnedWork<Ask>> {
        let mut asks = Vec::new();
        while let Some(work) = h.work() {
            // The framing asks for no work.
            let Side::Upper(ask) = work;
            asks.push(ask);
        }
        asks
    }

    fn query_of(ask: &OwnedWork<Ask>) -> &[u8] {
        &ask.work.query.as_ref().expect("not yet polled").1
    }

    fn answered(ask: &OwnedWork<Ask>, answer: Vec<u8>) -> Side<Infallible, Answered> {
        let charge = Budget::unlimited().charge(answer.len()).unwrap();
        Side::Upper(Answered {
            generation: ask.work.generation,
            outcome: Outcome::Answer(Owned::new(StreamMessage(answer), charge)),
        })
    }

    fn unanswered(ask: &OwnedWork<Ask>) -> Side<Infallible, Answered> {
        Side::Upper(Answered {
            generation: ask.work.generation,
            outcome: Outcome::Unanswered,
        })
    }

    /// Polls `ask` once, with no world, as the runner would, its resolver
    /// answering at once with `answer`.
    fn poll_answering(ask: &mut OwnedWork<Ask>, answer: Option<Vec<u8>>) -> Answered {
        ask.work.query = None;
        ask.work.asking = Some(Box::pin(std::future::ready(answer)));
        let mut cx = Context::from_waker(Waker::noop());
        match Job::poll(ask, None, &mut cx) {
            Poll::Ready(done) => done,
            Poll::Pending => panic!("a ready answer is pending"),
        }
    }

    #[test]
    fn replacement_service_receives_whole_queries_and_connection_identity() {
        fictionet::block_on(fictionet::lab(Seed::from_u64(19), |fcx| async move {
            let local: SocketAddr = "192.0.2.1:853".parse().unwrap();
            let peer: SocketAddr = "198.51.100.7:40000".parse().unwrap();
            let resolver_ip: IpAddr = "192.0.2.53".parse().unwrap();
            let service = move |_: Cx, client: Client, mut query: Vec<u8>| async move {
                assert_eq!(client.peer, peer);
                assert_eq!(client.local, SocketAddr::new(resolver_ip, local.port()));
                assert_eq!(client.transport, Transport::Tcp);
                query.reverse();
                Some(query)
            };
            let fronts = Fronts::new(service, |_| panic!("no handshake in this harness"))
                .resolver_at(resolver_ip);
            let conn = ConnInfo::new(1, local, peer);
            let dot = Dot {
                front: Arc::new(fronts.front()),
                tls_layer: fronts.tls_layer.clone(),
            };
            let mut h = Harness::with_budget(
                Seed::from_u64(20),
                dot.stack(&conn, &Limits::default()),
                Budget::unlimited(),
            );
            let queries = [message(1, 20), message(2, 25)];
            push_cut(&mut h, &framed(&queries), 21);
            let mut work = asks(&mut h);
            assert_eq!(work.len(), queries.len());
            let mut expected = Vec::new();
            for ask in work.iter_mut().rev() {
                let mut answer = query_of(ask).to_vec();
                answer.reverse();
                expected.push(answer);
                let mut cx = Context::from_waker(Waker::noop());
                let Poll::Ready(done) = Job::poll(ask, Some(&fcx), &mut cx) else {
                    panic!("the service answers immediately");
                };
                h.complete(Side::Upper(done)).unwrap();
            }
            assert_eq!(read(h.output()), expected);
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn each_answer_goes_out_whole_as_soon_as_it_is_ready() {
        for seed in 0..8 {
            let mut h = harness(Budget::unlimited());
            let queries: Vec<_> = (0..3).map(|i| message(i * 40, 12 + i as usize)).collect();
            push_cut(&mut h, &framed(&queries), seed);
            let asks = asks(&mut h);
            let asked: Vec<_> = asks.iter().map(|a| query_of(a).to_vec()).collect();
            assert_eq!(asked, queries);
            assert!(h.output().is_empty());
            // The last is answered first, the first next, and the middle
            // one never.
            let (last, first) = (message(200, 30), message(100, 20));
            h.complete(answered(&asks[2], last.clone())).unwrap();
            h.complete(answered(&asks[0], first.clone())).unwrap();
            h.complete(unanswered(&asks[1])).unwrap();
            assert_eq!(read(h.output()), [last, first.clone()]);
            // The connection goes on.
            push_cut(&mut h, &framed(&[message(7, 17)]), seed);
            let more = self::asks(&mut h);
            assert_eq!(more.len(), 1);
            h.complete(answered(&more[0], message(9, 40))).unwrap();
            assert_eq!(read(h.output()).len(), 3);
            assert!(!h.ended());
        }
    }

    #[test]
    fn two_queries_with_the_same_id_are_two_queries() {
        let mut h = harness(Budget::unlimited());
        let query = message(1, 20);
        h.push(&framed(&[query.clone(), query.clone()])).unwrap();
        let asks = asks(&mut h);
        assert_eq!(asks.len(), 2);
        let (one, two) = (message(50, 25), message(90, 25));
        h.complete(answered(&asks[1], two.clone())).unwrap();
        // A result for a query already answered changes nothing.
        h.complete(answered(&asks[1], message(3, 10))).unwrap();
        h.complete(answered(&asks[0], one.clone())).unwrap();
        assert_eq!(read(h.output()), [two, one]);
    }

    #[test]
    fn a_client_that_pipelines_past_the_limit_waits_for_its_answers() {
        let extra = 10;
        let mut h = harness(Budget::unlimited());
        let queries: Vec<_> = (0..QUERIES + extra).map(|i| message(i as u8, 12)).collect();
        h.push(&framed(&queries)).unwrap();
        let first = asks(&mut h);
        assert_eq!(first.len(), QUERIES);
        // Answers the client does not read hold their places.
        h.withhold();
        for ask in &first {
            h.complete(answered(ask, query_of(ask).to_vec())).unwrap();
        }
        let mut pending = asks(&mut h);
        assert!(pending.len() < extra, "{} more read", pending.len());
        // Once it reads, the rest go to the resolver.
        h.allow_all().unwrap();
        let mut total = first.len();
        while !pending.is_empty() {
            for ask in &pending {
                h.complete(answered(ask, query_of(ask).to_vec())).unwrap();
            }
            total += pending.len();
            pending = asks(&mut h);
        }
        assert_eq!(total, queries.len());
        let mut out = read(h.output());
        out.sort();
        let mut sent = queries.clone();
        sent.sort();
        assert_eq!(out, sent);
    }

    #[test]
    fn a_quiet_connection_closes_after_the_idle_time_and_a_waiting_query_keeps_it_open() {
        let tick = Duration::from_millis(1);
        let mut quiet = harness(Budget::unlimited());
        quiet.settle().unwrap();
        quiet.advance(IDLE - tick).unwrap();
        assert!(!quiet.ended());
        quiet.advance(tick).unwrap();
        assert!(quiet.ended());

        let mut h = harness(Budget::unlimited());
        h.settle().unwrap();
        h.advance(IDLE / 2).unwrap();
        h.push(&framed(&[message(1, 12)])).unwrap();
        let asks = asks(&mut h);
        // The resolver takes three idle times to answer.
        h.advance(IDLE * 3).unwrap();
        assert!(!h.ended());
        let answer = message(2, 30);
        h.complete(answered(&asks[0], answer.clone())).unwrap();
        assert_eq!(read(h.output()), [answer]);
        // The idle time starts again from the answer.
        h.advance(IDLE - tick).unwrap();
        assert!(!h.ended());
        h.advance(tick).unwrap();
        assert!(h.ended());
    }

    #[test]
    fn a_client_that_ends_its_direction_still_gets_its_answers() {
        let mut h = harness(Budget::unlimited());
        h.push(&framed(&[message(1, 12), message(2, 12)])).unwrap();
        // Half a third query, then the end.
        h.push(&framed(&[message(3, 12)])[..5]).unwrap();
        h.end().unwrap();
        let asks = asks(&mut h);
        assert_eq!(asks.len(), 2);
        assert!(!h.ended());
        let answer = message(4, 30);
        h.complete(answered(&asks[1], answer.clone())).unwrap();
        assert!(!h.ended());
        h.complete(unanswered(&asks[0])).unwrap();
        assert!(h.ended());
        assert_eq!(read(h.output()), [answer]);
        assert!(h.layer().is_terminal());
    }

    #[test]
    fn a_query_stays_charged_while_the_resolver_has_it() {
        let budget = Budget::unlimited();
        let mut h = harness(budget.clone());
        h.settle().unwrap();
        let before = budget.used();
        let query = message(1, 300);
        h.push(&framed(std::slice::from_ref(&query))).unwrap();
        let mut asks = asks(&mut h);
        assert!(budget.used() >= before + query.len());
        // The answer takes the query's place in the budget until it is
        // written.
        let answer = message(2, 900);
        let done = poll_answering(&mut asks[0], Some(answer.clone()));
        drop(asks);
        assert!(budget.used() >= before + answer.len());
        h.complete(Side::Upper(done)).unwrap();
        assert_eq!(read(h.output()), [answer]);
        assert_eq!(budget.used(), before);
    }

    #[test]
    fn an_answer_with_no_room_closes_the_connection_and_drops_the_other_queries() {
        let budget = Budget::new(1 << 20);
        let mut h = harness(budget.clone());
        h.push(&framed(&[message(1, 12), message(2, 12)])).unwrap();
        let mut asks = asks(&mut h);
        // More than the budget has left once the query gives back its charge.
        let room = budget.limit() - budget.used() + query_of(&asks[0]).len();
        let done = poll_answering(&mut asks[0], Some(message(3, room + 1)));
        assert!(matches!(done.outcome, Outcome::Budget));
        h.complete(Side::Upper(done)).unwrap();
        assert!(asks[1].cancelled());
        // The other query's answer, had it come, writes nothing.
        h.complete(answered(&asks[1], message(4, 12))).unwrap();
        assert!(h.output().is_empty());
        assert!(h.ended());
    }

    #[test]
    fn a_closed_connection_cancels_its_queries() {
        let mut h = harness(Budget::unlimited());
        h.push(&framed(&[message(1, 12)])).unwrap();
        let asks = asks(&mut h);
        assert!(!asks[0].cancelled());
        drop(h);
        assert!(asks[0].cancelled());
    }

    #[test]
    fn a_query_with_no_world_is_unanswered() {
        let mut h = harness(Budget::unlimited());
        h.push(&framed(&[message(1, 12)])).unwrap();
        let mut asks = asks(&mut h);
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(done) = Job::poll(&mut asks[0], None, &mut cx) else {
            panic!("a query with no world waits");
        };
        assert!(matches!(done.outcome, Outcome::Unanswered));
        h.complete(Side::Upper(done)).unwrap();
        assert!(h.output().is_empty());
        assert!(!h.ended());
    }
}
