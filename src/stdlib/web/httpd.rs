//! HTTP as a service: plain handlers, an adapter for tower services (axum
//! included), and name-based virtual hosting, all on [`serve`].
//!
//! `Http1` is a caller-driven `Service` on the `http1` decoder.
//! [`Http2`] uses the shared HTTP/2 frame layer and HPACK. Both servers run
//! with `std` alone. `serve_connection` runs them over a live connection. TLS comes from
//! `fictionet::stdlib::services::tls`. This module supplies no HTTP client.
//!
//! A [`Handler`] answers one request. Adapters and virtual hosting:
//!
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
//! use fictionet::stdlib::web::httpd::{Body, Exchange, Handler, Http1, Reply};
//! use fictionet::stdlib::services::serve::Harness;
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
//! let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Pages), ());
//! let reply = h.push(b"GET /hello HTTP/1.1\r\nHost: a.test\r\n\r\n")?;
//! assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
//! assert!(reply.ends_with(b"\r\n\r\nhi\n"));
//! let reply = h.push(b"POST /echo HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nok")?;
//! assert!(reply.ends_with(b"\r\n\r\nok"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Observation
//!
//! A world reports typed facts directly from its handlers. A body wrapper
//! can report streaming progress and completion to that world's own stream.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fictionet::RaceError;
use fictionet::stdlib::services::serve::ConnInfo;
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

pub use body::Body;
pub use handlers::{
    BadGateway, Exchange, Handler, Later, Reply, Tower, UpgradeHandler, text, tower,
};

pub use http2::{Http2, Timer as Http2Timer};
pub use native::{Http1, Timer as Http1Timer};
pub use response::{date_header, http_date};
pub use sites::{Routing, Server, Target, VHost, VirtualHosts, normalize, request_host};



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
    let serve_opts = ServeOptions {
        idle: None,
        write_timeout: Some(opts.limits.write_timeout),
        budget: opts.budget.clone(),
        ..ServeOptions::default()
    };
    if h2 {
        let mut service = Http2::with(handler, opts.limits);
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
            Ok(())
        }
        Err(serve::ServeError::Cancelled) => Err(Cancelled),
        Ok(_) | Err(_) => Ok(()),
    }
}
