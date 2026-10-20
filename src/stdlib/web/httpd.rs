//! HTTP as a service: a router whose handlers get plain byte bodies, an
//! adapter that runs any tower service (axum included), and name-based
//! virtual hosting, all on [`serve`].
//!
//! `Http1` is a caller-driven `Service` on the `http1` decoder.
//! [`Http2`] uses the shared HTTP/2 frame layer and HPACK. Both servers run
//! with `std` alone. `serve_connection` runs them over a live connection. TLS comes from
//! `fictionet::stdlib::services::tls`. This module supplies no HTTP client.
//!
//! A [`Handler`] answers one request. Three kinds come ready:
//!
//! - [`Router`]: routes by method and path to plain functions. A handler
//!   gets an [`Exchange`] (the clock reading, randomness, the connection)
//!   and an `http::Request<Bytes>`, and returns an `http::Response<Bytes>`.
//!   No runtime is involved, so it unit-tests with
//!   [`serve::Harness`]. An async route gets
//!   a [`Cx`] instead. Callbacks run only with bodies held in full;
//!   incomplete bodies get `400 Bad Request`.
//! - [`tower`]: any `tower_service::Service<http::Request<Body>>`, such as an
//!   `axum::Router`, run as deferred work of the connection.
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
//! [`Http1`] is the [`Service`](fictionet::stdlib::services::serve::Service) that speaks
//! HTTP/1.0 and 1.1 to a client, on [`http1`]'s
//! decoder: keep-alive, pipelining, `Expect: 100-continue`, `HEAD`, chunked
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
//! The hyper adapter leaves supplied lengths to hyper's framing rules.
//! Native HTTP/1 writes its own `Connection` header. It closes the
//! connection after a response, other than `101`, whose handler's
//! `Connection` header names `close`, and drops the handler's other tokens.
//! It writes field names with each word capitalized (`Content-Type`), as
//! most HTTP/1 servers do. HTTP/2 names stay lowercase, as that protocol
//! requires.
//!
//! An upgrade request reaches the native HTTP/1 handler. A synchronous handler
//! returns `101` with an [`UpgradeHandler`] extension to receive the connection
//! after the response is written, including unread bytes. The stdlib's
//! [`websocket`](fictionet::stdlib::protocols::websocket) codec can serve it directly.
//! With the opt-in `tokio` feature, tower handlers use hyper's HTTP/1 upgrade
//! extension so axum's `WebSocketUpgrade` continues to work: the tower adapter
//! returns [`Reply::Handoff`], and the native server replays the request, body
//! included, on hyper's HTTP/1 server.
//!
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
//! HTTP/2 uses the same [`Handler`], events, [`Limits`] and seeded randomness.
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
//! use bytes::Bytes;
//! use fictionet::stdlib::web::httpd::{Http1, Router};
//! use fictionet::stdlib::services::serve::Harness;
//!
//! let router = Router::new()
//!     .get("/hello", |_, _| http::Response::new(Bytes::from("hi\n")))
//!     .post("/echo", |_, request: http::Request<Bytes>| http::Response::new(request.into_body()));
//! let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
//! let reply = h.push(b"GET /hello HTTP/1.1\r\nHost: a.test\r\n\r\n")?;
//! assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! assert!(reply.ends_with(b"\r\n\r\nhi\n"));
//! let reply = h.push(b"POST /echo HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nok")?;
//! assert!(reply.ends_with(b"\r\n\r\nok"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Events
//!
//! Every request a handler or the service answered is one `http.request`
//! event, also when the client gave up before the answer. Its fields:
//! `scheme`, `sni`, `host` (the URI's authority or the `Host` header, in
//! lowercase, without port or trailing dot, `null` if none), `method`,
//! `uri`, `path`, `query`, `version` (`HTTP/1.1`, `HTTP/2.0`), `headers`
//! (`[name, value]` pairs in the order of `http::HeaderMap`), `started`
//! (seconds on the run's clock), `answer` (`handler`, `error`, `cancelled`,
//! `no_host` for an HTTP/1.1 request without a `Host` field, which gets
//! `400` without reaching the handler, what the handler set, such as
//! `redirect`, or `too_large`, `timeout`, `cut_off` or `budget` for a
//! request the service turned down; `too_large` wins over `no_host`),
//! `received` (`complete`, `cut_off`, `too_large`, `timeout` or
//! `budget` for request receipt), `status`, `sent` (response body bytes the
//! connection took) and `complete`
//! (whether it took the whole body). Over HTTP/1 a byte counts once it is
//! written, and the event is made after the last one is; over HTTP/2 once
//! the service queues it for the stream. A handler adds its own fields by putting
//! [`Fields`] in its response's extensions, or using [`RequestFields`] before
//! the response exists. Virtual host requests also carry
//! `world_site`: the matched registered name, or `the default site` for a fallback.
//! An opt-in [`BodyClassifier`] sees the
//! head before virtual hosting and admission, body chunks before limits
//! discard them, and the receipt outcome. Install it with [`Http1::observe`],
//! [`HttpOptions::observe`], [`Server::observe`] or
//! [`web::Site::observe`](fictionet::stdlib::web::Site::observe). Its request-local
//! state can retain authority and classification across chunks without logging
//! plaintext bodies. BodyClassifier fields come first, handler fields override them,
//! response fields override recorded request fields, and service facts win last. `answer` comes from the response, never the
//! observer. No body bytes are added to the event automatically.
//!
//! A native HTTP/1 body timeout also finishes the request event with
//! `answer: timeout`, `received: timeout`, a null status and `complete: false`.
//! Request receipt and response completion are separate: a successful error
//! response can have `complete: true` with `received: too_large`.
//! Native HTTP/1 observes decoded blocks and, on failure or timeout, any
//! buffered partial body block. Buffered partial bytes are not observed on
//! connection reset, budget end or cancellation. An HTTP/1.1 request without
//! Host is answered from bytes buffered with its head; later body bytes are
//! not observed, leaving `received: cut_off` unless already too large.
//! HTTP/2 observes each data frame it admits and stops observing at rejection.
//! Only decoded body data is observed, not chunk framing, chunk extensions
//! or trailers.
//! Neither backend relaxes its limits to observe more bytes. Requests rejected
//! before a parsed head reaches the service have no request event. Bytes after
//! an upgrade handoff are outside HTTP observation. A missing handler label
//! does not show that nothing was exposed; consumers need complete receipt or
//! an observer verdict to judge safety.
//! If hyper's body read reports region cancellation, `received` is `cut_off`;
//! its response still uses `answer: timeout` and status `408`. Consumers must
//! use `received` to distinguish this from a body deadline.
//! A connection that ends in an error is one `http.error` event, with
//! `local`, `cause` (`protocol`, `timeout` or `transport`) and `detail`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fictionet::RaceError;
use fictionet::events::{ConnInfo, Fields};
use fictionet::stdlib::network::Connection;
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::protocols::http1;
use fictionet::stdlib::services::serve::Prefixed;
use fictionet::stdlib::services::serve::{self, Budget, ServeOptions};
use fictionet::{Cancelled, Cx};

mod body;
mod handlers;
mod http2;
mod native;
mod response;
mod sites;

fictionet::cfg_tokio! {
/// The opt-in tower HTTP/1 upgrade adapter.
mod upgrade;
}

pub use body::Body;
pub use handlers::{
    BadGateway, Exchange, Handler, Later, Reply, Router, Tower, UpgradeHandler, text, tower,
};

pub use http2::Http2;
pub use native::Http1;
pub use response::{date_header, http_date};
pub use sites::{Routing, Server, Target, VHost, VirtualHosts, normalize, request_host};

use response::error_event;

/// How much of a request body the service received and admitted.
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

impl Received {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::CutOff => "cut_off",
            Self::TooLarge => "too_large",
            Self::Timeout => "timeout",
            Self::Budget => "budget",
        }
    }
}

/// Whether the run wants this request's event. Installed in request extensions
/// before the handler runs, so response metadata can be constructed lazily.
#[derive(Clone, Copy, Debug)]
pub struct EventInterest(pub bool);

impl EventInterest {
    /// Checks the interest supplied by the HTTP server. Direct handler callers
    /// opt in by inserting this extension.
    pub fn of<B>(request: &http::Request<B>) -> bool {
        request
            .extensions()
            .get::<Self>()
            .is_some_and(|interest| interest.0)
    }
}

/// Request-local event fields that survive cancellation and handler errors.
/// The server installs this extension only when request events are enabled.
/// Fields use the event's bounds; overflowing them marks the event truncated.
/// Recorded handler fields override classifier fields. Response fields override
/// recorded handler fields. Service facts, including the chosen site, win last.
/// `answer` always comes from the service or response, never this store.
#[derive(Clone)]
pub struct RequestFields(
    Arc<fictionet::sync::Mutex<(fictionet::events::Event, fictionet::events::Event)>>,
);

impl Default for RequestFields {
    fn default() -> Self {
        Self(Arc::new(fictionet::sync::Mutex::new((
            fictionet::events::Event::new("http", "request"),
            fictionet::events::Event::new("http", "request"),
        ))))
    }
}

impl RequestFields {
    /// Records handler fields before a response exists. Does nothing when the
    /// server is not observing this request. Build fields only when interested.
    pub fn record<B>(request: &http::Request<B>, fields: Fields) {
        if let Some(store) = request.extensions().get::<Self>() {
            store.record_fields(fields);
        }
    }

    /// Records handler fields directly on this request's store.
    pub fn record_fields(&self, fields: Fields) {
        self.extend(fields, false);
    }

    fn extend(&self, mut fields: Fields, service: bool) {
        fields.remove("answer");
        let mut stored = self.0.lock();
        let event = if service {
            &mut stored.1
        } else {
            &mut stored.0
        };
        *event = std::mem::replace(event, fictionet::events::Event::new("http", "request"))
            .fields(fields);
    }
}

/// Classifies arrivals before routing or admission, without retaining body bytes.
///
/// Callbacks run only when the run observer wants the request event.
/// Each request has its own `state`, separate from handler extensions. Use it
/// to carry identity and bounded classification state from `head` to `body`
/// and `end`, including across concurrent HTTP/2 streams. Callbacks run on
/// the world's path: use no host clock or entropy, and bound retained state.
/// State and returned fields, like handler extensions, are outside the service
/// budget. Keep both bounded.
/// Return only redacted facts; returned fields are merged in callback order.
/// Handler fields then override them, and service facts win last.
/// The service never logs body bytes itself. Head fields keep their ordinary
/// event representation; this hook does not redact URI or header values.
pub trait BodyClassifier: Send + Sync + 'static {
    /// A parsed head, including its original authority and connection identity.
    /// Runs before virtual hosting, body limits and request budget admission.
    fn head(
        &self,
        _head: &http::request::Parts,
        _conn: &ConnInfo,
        _state: &mut http::Extensions,
    ) -> Option<Fields> {
        None
    }

    /// Decoded body data as it arrives, before any limit discards it.
    /// Chunk framing, chunk extensions and trailers are not observed.
    /// Chunk boundaries follow the decoder, not network reads. Native HTTP/1
    /// observes buffered partial bytes on decode failure and timeout only,
    /// not on connection reset, budget end or cancellation. Hyper stops on
    /// rejection; native HTTP/1 keeps observing while draining an oversized body.
    /// An HTTP/1.1 request without Host is answered from bytes buffered with its
    /// head; later body bytes are not observed, leaving `received: cut_off` unless
    /// already too large.
    fn body(&self, _bytes: &[u8], _state: &mut http::Extensions) -> Option<Fields> {
        None
    }

    /// Receipt ended, even when no handler ran. Called once per observed head.
    fn end(&self, _received: Received, _state: &mut http::Extensions) -> Option<Fields> {
        None
    }
}

/// HTTP's limits and timers, for both versions.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Head limits for HTTP/1's decoder.
    pub head: http1::Limits,
    /// The largest request body held. An oversized body gets `413`
    /// without calling the handler. Native HTTP/1 drains the request
    /// before answering and closes the connection. Hyper's HTTP/1
    /// upgrade path and HTTP/2 reject it during collection.
    /// Default 64 MiB.
    pub body: usize,
    /// HTTP/1: how long a request's head may take to arrive, counted from
    /// when the service starts waiting for it, which includes the wait
    /// between requests. This also applies to hyper's HTTP/1 upgrade
    /// path. HTTP/2 has no request-head deadline. Default 30 seconds.
    pub header_timeout: Duration,
    /// How long a request's body may take to arrive, counted from its
    /// head, so a client that trickles a body cannot hold the connection
    /// for ever. Native HTTP/1 closes the connection. Hyper's HTTP/1
    /// upgrade path and HTTP/2 answer `408` when collection times out,
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
    /// Observes parsed heads and body receipt before routing or admission.
    pub observe: Option<Arc<dyn BodyClassifier>>,
    /// Limits and timers, for both versions.
    pub limits: Limits,
    /// On a connection without TLS, how long the client has from
    /// connecting to send its first bytes. Past it, the connection closes
    /// with an `http.error` event, cause `timeout`. `None` waits as long as
    /// the HTTP/1 head limit allows.
    pub first_bytes: Option<Duration>,
    /// What connections are charged to ([`ServeOptions::budget`]): over
    /// HTTP/1 and HTTP/2 what the driver and service hold, including each request's head and body,
    /// its event metadata, and each response frame until its last slice is
    /// dropped. Heads count method, URI and header bytes, plus header slots;
    /// hidden capacities, extensions and third-party overhead are excluded.
    /// Events use [`Event::size`](fictionet::events::Event::size). Transport buffers are excluded.
    /// Response storage is charged by its original byte length; spare capacity
    /// and backing storage outside a supplied slice are not exposed by `Bytes`.
    pub budget: Option<Budget>,
    /// The world's date and time at the start of the run, for `Date`
    /// headers. `None`: no `Date` header. See [Dates](self#dates).
    pub date: Option<SystemTime>,
}

use fictionet::stdlib::protocols::http2::PREFACE;

/// Serves one connection with `handler`: HTTP/2 when TLS agreed on `h2`, or
/// when a client without TLS starts with HTTP/2's preface; HTTP/1
/// otherwise. Both versions work with `std`; hyper upgrades require `tokio`.
/// `info` names the connection in events.
/// An empty half-close is silent. EOF within an HTTP/2 preface goes through
/// HTTP/1's truncated-head handling: `http.error` with cause `protocol` and 400.
///
/// Returns `Ok(())` when the connection ended, however it ended: a
/// connection's failure is the connection's, and the run's events say what
/// it was. Returns [`Cancelled`] if `fcx`'s
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
                let secs = first_timeout.as_secs();
                fcx.emitter(&info).emit("http", "error", |_| {
                    error_event(
                        &info,
                        "timeout",
                        format!("no bytes within {secs} seconds of connecting"),
                    )
                    .conn(&info)
                });
                return Ok(());
            }
        }
        first == PREFACE
    };
    let conn = Prefixed::new(first, conn);
    let serve_opts = ServeOptions {
        protocol: if h2 { "http2" } else { "http1" },
        idle: None,
        write_timeout: Some(opts.limits.write_timeout),
        connection_events: false,
        budget: opts.budget.clone(),
        ..ServeOptions::default()
    };
    if h2 {
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
    let mut service = Http1::with(handler.clone(), opts.limits);
    service.date = opts.date;
    service.observe = opts.observe.clone();
    if !info.tls && opts.first_bytes.is_none() {
        service.first_head_deadline = Some(head_deadline);
    }
    match serve::connection(fcx, conn, info.clone(), &mut service, &(), &serve_opts).await {
        Ok(serve::Served::Upgraded(serve::Upgrade::Handoff, rest)) => {
            if let Some(upgrade) = service.upgrade.take() {
                upgrade.run(fcx.clone(), Box::new(rest)).await;
                return if fcx.is_cancelled() {
                    Err(Cancelled)
                } else {
                    Ok(())
                };
            }
            fictionet::cfg_tokio! {
                // Hyper reads the request again and carries out its upgrade.
                if let Some((head, tracker)) = service.handoff.take() {
                    return upgrade::serve_upgrade(
                        fcx, Prefixed::new(head, rest), handler, info, opts, tracker,
                    ).await;
                }
            }
            Ok(())
        }
        Err(serve::ServeError::Cancelled) => Err(Cancelled),
        // The driver recorded the failure as a `conn.error` event.
        Ok(_) | Err(_) => Ok(()),
    }
}
