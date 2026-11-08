//! HTTP as a service: plain handlers, an adapter for tower services (axum
//! included), and name-based virtual hosting.
//!
//! [`Http1`] is a [`Layer`](fictionet::stdlib::layer::Layer) over an
//! ordered byte stream. [`Http2`] is a [`serve`] service on the shared
//! HTTP/2 frame layer and HPACK. Both servers run with `std` alone.
//! [`serve_connection`] runs them over a live connection. TLS comes from
//! `fictionet::stdlib::services::tls`. This module supplies no HTTP client.
//!
//! A [`Handler`] answers one request. Adapters and virtual hosting:
//!
//! - [`tower`]: any `tower_service::Service<http::Request<Body>>`, such as an
//!   `axum::Router`, run as the connection's work.
//! - [`VirtualHosts`]: picks a handler by the request's host, as a web server
//!   with several sites at one address does, with the redirect to https and
//!   the `421 Misdirected Request` of [`web::Sites`](fictionet::stdlib::web::Sites).
//!
//! On a [`Net`](fictionet::stdlib::world::net::Net), a [`Server`] is the
//! [`PortServer`](fictionet::stdlib::world::net::PortServer) that serves HTTP on a host's
//! port: sites of several hosts at one address share the port as virtual
//! hosts. [`Server::served_by`] puts a site on ports 80 and 443 the way
//! websites are served. `Net` knows nothing of HTTP, so a copy of this
//! component with its own handlers plugs in the same way. Copy `httpd.rs`
//! together with the `httpd/` directory, keeping the relative paths.
//!
//! [`Http1`] speaks HTTP/1.0 and 1.1 to a client, on [`http1`]'s decoder:
//! keep-alive, pipelining, `Expect: 100-continue`, `HEAD`, chunked
//! responses for bodies of unknown length, and 30-second limits on each
//! request's head and on its body. [`serve_connection`] picks the version for a
//! connection: HTTP/2 by ALPN or by the client's preface, else HTTP/1.
//! An unknown-length HTTP/1.1 body ends with a zero-size chunk only at EOF.
//! Pending polls and empty data frames do not end the response.
//! All backends suppress response bodies for `HEAD`, informational statuses,
//! `204` and `304`. For other statuses, `HEAD` keeps the handler's
//! `Content-Length`, or uses the body's known length when none was set.
//! Native HTTP/1 omits lengths for bodyless statuses and otherwise writes
//! the body's known length or chooses framing for an unknown length.
//! HTTP/2 preserves a valid supplied length when it agrees with that policy,
//! and on `304` preserves the supplied length of the selected representation.
//! Native HTTP/1 writes its own `Connection` header. It closes the
//! connection after a response, other than `101`, whose handler's
//! `Connection` header names `close`, and drops the handler's other tokens.
//! It writes field names with each word capitalized (`Content-Type`), as
//! most HTTP/1 servers do. HTTP/2 names stay lowercase, as that protocol
//! requires.
//!
//! An upgrade request reaches the native HTTP/1 handler. A handler hands
//! the connection on by putting an [`UpgradeHandler`] in the extensions of
//! a `101` answer, or of a 2xx answer to CONNECT: once the answer is
//! written, HTTP is over, and [`Http1::upgradable`] runs the upgrade
//! handler on the rest of the stream, with the bytes the client sent past
//! the request first. The stdlib's
//! [`websocket`](fictionet::stdlib::protocols::websocket) codec can serve it
//! directly.
//! # Dates
//!
//! The world owns its dates. A response carries a `Date` header only when
//! the world gave the date it was at the start of the run, with
//! [`Http1::date`], [`HttpOptions::date`] or [`Server::date`]: the header
//! is then that date plus the run's clock.
//! Without one, responses have no `Date` header (RFC 9110 lets a server
//! with no clock leave it out). The host's clock is never used, so a world
//! set in 2019 never sends a date from the year it runs in. A `Date` the
//! handler sets itself is sent as it is.
//!
//! HTTP/2 uses the same [`Handler`], [`Limits`] and seeded randomness.
//! The serve driver charges input and output storage, HPACK state, stream
//! metadata, retained request heads and bodies, and pending responses to the
//! connection's [`Budget`]. A head that does not fit is refused before its
//! handler runs, with `answer: budget` and no status. A body that exceeds its
//! allowance receives `503`. Transport storage belongs to its transport.
//! After the HTTP/2 server resets a stream, it ignores that stream's late
//! HEADERS and DATA for one second. It holds at most 50 reset streams at a
//! time. HEADERS and DATA on any other closed stream are errors. The
//! one-second hold, body deadlines and SETTINGS acknowledgment deadlines are
//! all timed on the run's clock.
//! Stream flow control, reset limits and bounded header assembly apply
//! independently of the runtime. PING and GOAWAY are handled by the service;
//! graceful shutdown drains admitted streams.
//!
//! ```
//! use fictionet::stdlib::layer::Harness;
//! use fictionet::stdlib::services::stack::Polling;
//! use fictionet::stdlib::web::httpd::{Body, Exchange, Handler, Http1, Reply};
//!
//! struct Pages;
//! impl Handler for Pages {
//!     fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
//!         let body = match request.uri().path() {
//!             "/hello" => Body::from("hi\n"),
//!             _ => request.into_body(),
//!         };
//!         Reply::Now(http::Response::new(body))
//!     }
//! }
//! let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Pages)).with_worker(Polling::new());
//! h.push(b"GET /hello HTTP/1.1\r\nHost: a.test\r\n\r\n")?;
//! let reply = h.take_output();
//! assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! assert!(reply.ends_with(b"\r\n\r\nhi\n"));
//! h.push(b"POST /echo HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nok")?;
//! assert!(h.take_output().ends_with(b"\r\n\r\nok"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Observation
//!
//! A world reports typed facts directly from its handlers. For delivery
//! accounting, [`HttpOptions::observe`] receives the request and response heads,
//! receipt outcome, and body bytes in completely written pieces. Response
//! extensions carry world-owned facts without a shared event schema.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fictionet::RaceError;
use fictionet::stdlib::layer::{Budget, Side};
use fictionet::stdlib::network::Connection;
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::protocols::http1;
use fictionet::stdlib::services::serve::ConnInfo;
use fictionet::stdlib::services::serve::Prefixed;
use fictionet::stdlib::services::serve::{self, ServeOptions};
use fictionet::stdlib::services::stack::{self, StackError, StreamLimits};
use fictionet::{Cancelled, Cx};

mod body;
mod handlers;
mod http2;
mod native;
mod response;
mod sites;

pub use body::Body;
pub use handlers::{
    BadGateway, Exchange, Handler, Later, Reply, Reset, Tower, UpgradeHandler, text, tower,
};

pub use http2::{Http2, Timer as Http2Timer};
pub use native::{
    Closing, Done as Http1Done, Http1, Next, Report as Http1Report, Timer as Http1Timer,
    Work as Http1Work,
};
pub use response::{date_header, http_date};
pub use sites::{Answer, Routing, Server, Target, VHost, VirtualHosts, normalize, request_host};

/// How receipt of a request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// The whole body arrived within the limits.
    Complete,
    /// Receipt ended before the whole body arrived.
    CutOff,
    /// A body chunk exceeded the body limit.
    TooLarge,
    /// The body deadline expired.
    Timeout,
    /// The request could not fit in the service budget.
    Budget,
}

/// A finished or interrupted response to a dispatched HTTP request.
/// Rejections before dispatch (including malformed heads and HTTP/1 body timeouts)
/// are outside this callback. Request and response extensions belong to the
/// world; the server does not interpret them.
pub struct Observation {
    /// When the request was dispatched.
    pub at: fictionet::time::Instant,
    /// The connection carrying the request.
    pub conn: serve::ConnInfo,
    /// The parsed request head, without its body.
    pub request: http::request::Parts,
    /// The response selected for transmission, if one was produced.
    pub response: Option<http::response::Parts>,
    /// Whether the entire request arrived.
    pub received: Received,
    /// Response body bytes in fully written pieces. An interrupted piece is
    /// not counted, so this is a lower bound on bytes accepted by the transport.
    pub sent: u64,
    /// The response stream ended normally and all emitted framing was written.
    pub complete: bool,
}

/// Receives one observation when a dispatched response finishes or is cancelled.
/// Callbacks run synchronously and should hand off slow work themselves.
pub type Observe = Arc<dyn Fn(Observation) + Send + Sync>;

struct Delivery {
    observe: Observe,
    observation: Option<Observation>,
    produced: u64,
    pending: Option<(u64, usize)>,
    held: usize,
}

impl Delivery {
    fn new(
        observe: &Option<Observe>,
        request: &http::Request<Body>,
        conn: &serve::ConnInfo,
        at: fictionet::time::Instant,
        received: Received,
    ) -> Option<Self> {
        let observe = observe.as_ref()?.clone();
        let mut head = http::Request::new(());
        *head.method_mut() = request.method().clone();
        *head.uri_mut() = request.uri().clone();
        *head.version_mut() = request.version();
        *head.headers_mut() = request.headers().clone();
        *head.extensions_mut() = request.extensions().clone();
        let held = response::request_held(&head);
        Some(Self {
            held,
            observe,
            observation: Some(Observation {
                at,
                conn: conn.clone(),
                request: head.into_parts().0,
                response: None,
                received,
                sent: 0,
                complete: false,
            }),
            produced: 0,
            pending: None,
        })
    }

    fn response(&mut self, parts: &http::response::Parts) {
        if let Some(observation) = &mut self.observation {
            let headers = &parts.headers;
            self.held += std::mem::size_of::<http::response::Parts>()
                + (headers.capacity() + headers.len() - headers.keys_len())
                    * std::mem::size_of::<(http::HeaderName, http::HeaderValue)>()
                + headers
                    .iter()
                    .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
                    .sum::<usize>();
            observation.response = Some(parts.clone());
        }
    }

    fn piece(&mut self, length: usize, body: usize) {
        self.produced += length as u64;
        self.pending = Some((self.produced, body));
    }

    fn update(&mut self, written: u64) {
        if let Some((end, body)) = self.pending
            && written >= end
        {
            if let Some(observation) = &mut self.observation {
                observation.sent += body as u64;
            }
            self.pending = None;
        }
    }

    fn finish(&mut self, written: u64, complete: bool) {
        self.update(written);
        if let Some(mut observation) = self.observation.take() {
            self.held = 0;
            observation.complete = complete;
            (self.observe)(observation);
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        if let Some(observation) = self.observation.take() {
            (self.observe)(observation);
        }
    }
}

/// HTTP's limits and timers, for both versions.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Head limits for HTTP/1's decoder.
    pub head: http1::Limits,
    /// The largest request body held. An oversized body gets `413`
    /// without calling the handler. Native HTTP/1 drains the request
    /// before answering and closes the connection. HTTP/2 rejects it during collection.
    /// Default 64 MiB.
    pub body: usize,
    /// HTTP/1: how long a request's head may take to arrive, counted from
    /// when the service starts waiting for it, which includes the wait
    /// between requests. HTTP/2 has no request-head deadline. Default 30 seconds.
    pub header_timeout: Duration,
    /// How long a request's body may take to arrive, counted from its
    /// head, so a client that trickles a body cannot hold the connection
    /// for ever. Native HTTP/1 closes the connection. HTTP/2 answers `408` when collection times out,
    /// or `400` on a body read error, without calling the handler.
    /// All these deadlines use the Fictionet clock. Default 30 seconds.
    pub body_timeout: Duration,
    /// How long a write may take no bytes before the connection ends: a
    /// client that stopped reading. Default 30 seconds.
    pub write_timeout: Duration,
    /// HTTP/2: the most streams open at once on one connection, which
    /// the server announces in its settings. Default 100, the least RFC
    /// 9113 recommends.
    pub streams: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            head: http1::Limits::default(),
            body: 64 << 20,
            header_timeout: Duration::from_secs(30),
            body_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            streams: 100,
        }
    }
}

/// The most of a body handed to the connection at once, so the count of
/// bytes sent stays close to what went out.
const PIECE: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// One connection, either version

/// How [`serve_connection`] serves a connection.
#[derive(Clone, Default)]
pub struct HttpOptions {
    /// Optional completion callback, shared by both HTTP versions.
    pub observe: Option<Observe>,
    /// Limits and timers, for both versions.
    pub limits: Limits,
    /// On a connection without TLS, how long the client has from
    /// connecting to send its first bytes. Past it, the connection closes
    /// if no bytes arrived. `None` waits as long as
    /// the HTTP/1 head limit allows.
    pub first_bytes: Option<Duration>,
    /// What connections are charged to ([`ServeOptions::budget`]): over
    /// HTTP/1 and HTTP/2 what the driver and service hold, including each request's head and body,
    /// and each response frame until its last slice is
    /// dropped. Heads count method, URI and header bytes, plus header slots;
    /// hidden capacities, extensions and third-party overhead are excluded.
    /// Transport buffers are excluded.
    /// Response storage is charged by its original byte length; spare capacity
    /// and backing storage outside a supplied slice are not exposed by `Bytes`.
    pub budget: Option<Budget>,
    /// The world's date and time at the start of the run, for `Date`
    /// headers. `None`: no `Date` header. See [Dates](self#dates).
    pub date: Option<SystemTime>,
}

use fictionet::stdlib::protocols::http2::PREFACE;

/// HTTP/1 for the connection `info` names, answering with `handler` as
/// `opts` says: what [`serve_connection`] runs, and what a site runs over
/// TLS in the same stack.
pub(super) fn http1_for(handler: Arc<dyn Handler>, opts: &HttpOptions, info: &ConnInfo) -> Http1 {
    let mut http1 = Http1::with(handler, opts.limits).conn(info.clone());
    http1.date = opts.date;
    http1.observe = opts.observe.clone();
    http1
}

/// Serves one connection with `handler`: HTTP/2 when TLS agreed on `h2`, or
/// when a client without TLS starts with HTTP/2's preface; HTTP/1
/// otherwise. Both versions work with `std`.
/// `info` supplies connection metadata to the handler.
/// An empty half-close is silent. EOF within an HTTP/2 preface goes through
/// HTTP/1's truncated-head handling and answers 400.
///
/// Returns `Ok(())` when the connection ended, however it ended: a
/// connection's failure ends that connection. Returns [`Cancelled`] if `fcx`'s
/// [region](fictionet::Cx#regions) is cancelled first.
#[deny(clippy::let_underscore_must_use)]
pub async fn serve_connection<C: Connection + Unpin>(
    fcx: &Cx,
    conn: C,
    info: ConnInfo,
    handler: Arc<dyn Handler>,
    opts: &HttpOptions,
) -> Result<(), Cancelled> {
    let mut conn = conn;
    let mut first = Vec::new();
    let head_deadline = fcx.now() + opts.limits.header_timeout;
    let first_timeout = opts.first_bytes.unwrap_or(opts.limits.header_timeout);
    let h2 = if info.tls {
        info.alpn.as_deref() == Some(b"h2".as_slice())
    } else {
        // With HTTP/2, read enough to identify its preface. Otherwise,
        // wait for one byte to enforce the first-byte timeout.
        let preface = async {
            let mut buf = [0u8; 24];
            while first.len() < PREFACE.len() && PREFACE.starts_with(&first) {
                let room = PREFACE.len() - first.len();
                match conn.read(fcx, &mut buf[..room]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => first.extend_from_slice(&buf[..n]),
                }
            }
        };
        match fcx.race(Some(fcx.now() + first_timeout), preface).await {
            Ok(()) => {}
            Err(RaceError::Cancelled) => return Err(Cancelled),
            Err(RaceError::Deadline) => {
                return Ok(());
            }
        }
        first == PREFACE
    };
    let conn = Prefixed::new(first, conn);
    if h2 {
        let serve_opts = ServeOptions {
            idle: None,
            write_timeout: Some(opts.limits.write_timeout),
            budget: opts.budget.clone(),
            ..ServeOptions::default()
        };
        let mut service = Http2::with(handler, opts.limits);
        service.observe = opts.observe.clone();
        service.date = opts
            .date
            .and_then(|date| date.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|date| date.as_secs());
        return match serve::connection(fcx, conn, info, &mut service, &(), &serve_opts).await {
            Err(serve::ServeError::Cancelled) => Err(Cancelled),
            _ => Ok(()),
        };
    }
    let mut http1 = http1_for(handler, opts, &info);
    if !info.tls && opts.first_bytes.is_none() {
        http1.first_head_deadline = Some(head_deadline);
    }
    let budget = opts.budget.clone().unwrap_or_else(Budget::unlimited);
    let limits = StreamLimits {
        idle: None,
        write_timeout: Some(opts.limits.write_timeout),
    };
    match stack::stream(fcx, conn, &info, http1.upgradable(), budget, limits, |_| {}).await {
        Ok(_) | Err(StackError::Budget) => Ok(()),
        Err(StackError::Cancelled) => Err(Cancelled),
        Err(StackError::Layer(Side::Lower(never) | Side::Upper(never))) => match never {},
    }
}
