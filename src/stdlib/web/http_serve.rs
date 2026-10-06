//! Ports 80 and 443 on a machine: TLS by SNI, HTTP/1.1 and HTTP/2 with
//! hyper, and routing each request to its site by host.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST, LOCATION};
use http::uri::{Authority, Scheme};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;

use super::names::{normalize, too_many};
use super::net::{Hooks, Machine};
use super::{BadGateway, Body, Event, Executor, Http, HttpAnswer, HttpError, HttpErrorCause, Sandbox, Target, Tls, TlsOutcome};
use crate::stdlib::tls::HandshakeError;
use crate::stdlib::{ConnError, Connection, ConnectionExt, tcp, tls};
use crate::time::Instant;
use crate::{Cx, Error};

/// What an HTTP/2 client sends first, with no TLS ("prior knowledge").
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How long a client has, from connecting, to finish its TLS handshake, or
/// on port 80 to send the first bytes of its request. A connection that
/// takes longer is closed.
pub(super) const HANDSHAKE_TIME: Duration = Duration::from_secs(10);

/// `fut`, or `None` if it takes longer than `limit`.
pub(super) async fn time_limit<T>(cx: &Cx, limit: Duration, fut: impl Future<Output = T>) -> Option<T> {
    match until(cx, cx.now() + limit, fut).await {
        Limited::Done(v) => Some(v),
        Limited::TimedOut | Limited::Cancelled => None,
    }
}

/// How [`until`] ended.
enum Limited<T> {
    Done(T),
    TimedOut,
    /// The region was cancelled: the world is stopping.
    Cancelled,
}

/// `fut`, unless `deadline` passes or the region is cancelled first.
async fn until<T>(cx: &Cx, deadline: Instant, fut: impl Future<Output = T>) -> Limited<T> {
    let mut fut = std::pin::pin!(fut);
    let mut sleep = std::pin::pin!(cx.sleep_until(deadline));
    std::future::poll_fn(|task| {
        if let Poll::Ready(v) = fut.as_mut().poll(task) {
            return Poll::Ready(Limited::Done(v));
        }
        match sleep.as_mut().poll(task) {
            Poll::Ready(Ok(())) => Poll::Ready(Limited::TimedOut),
            Poll::Ready(Err(_)) => Poll::Ready(Limited::Cancelled),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// A connection as it was accepted: when, and, if the world wants events,
/// its sandbox and number.
struct Arrival {
    accepted: Instant,
    seen: Option<(Sandbox, u64)>,
}

/// Accepts connections on one port of a machine. Each connection is served
/// in its own region, with its HTTP/2 streams as tasks in that region.
pub(super) async fn accept(cx: Cx, mut listener: tcp::Listener, machine: Arc<Machine>, https: bool) -> crate::Result {
    loop {
        match listener.accept(&cx).await {
            Ok(conn) => {
                // Past its share, a peer's connection is reset immediately.
                let Some(guard) = machine.peers.enter(conn.peer_addr().ip()) else {
                    too_many(&cx, &machine.hooks, &conn);
                    conn.reset();
                    continue;
                };
                // The count lasts until the socket is gone, closing included.
                conn.hold_until_gone(Box::new(guard));
                // The handshake clock starts now, and the sandbox is the one
                // that has this address now.
                let hooks = &machine.hooks;
                let seen = hooks.on().then(|| (hooks.sandbox_at(conn.peer_addr().ip()), hooks.next_conn()));
                let arrival = Arrival { accepted: cx.now(), seen };
                let machine = machine.clone();
                cx.spawn(move |cx| async move {
                    // One bad connection is not a failure of the world.
                    let _ = cx
                        .region(move |cx| async move {
                            connection(cx, conn, machine, https, arrival).await;
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

/// What the events of one connection need. Made only when the world set an
/// event callback.
struct Watch {
    cx: Cx,
    hooks: Arc<Hooks>,
    /// The sandbox, as it was when the connection arrived.
    sandbox: Sandbox,
    conn: u64,
    local: SocketAddr,
}

impl Watch {
    fn emit(&self, event: Event) {
        self.hooks.emit(&self.cx, event);
    }

    fn http_error(&self, cause: HttpErrorCause, detail: String) {
        self.emit(Event::HttpError(HttpError {
            sandbox: self.sandbox.clone(),
            conn: self.conn,
            local: self.local,
            cause,
            detail,
        }));
    }

    /// Whether `Sites` ended the connection itself: its sandbox detached.
    fn detached(&self) -> bool {
        !self.hooks.is_attached(self.sandbox.id)
    }
}

/// How a failed handshake shows in a [`Tls`] event.
fn tls_outcome(e: HandshakeError, watch: &Watch) -> TlsOutcome {
    match e {
        HandshakeError::Alert(a) => TlsOutcome::Alert(a),
        HandshakeError::Failed(why) => TlsOutcome::Failed(why),
        HandshakeError::Conn(ConnError::Broken) => TlsOutcome::Failed("the connection broke".into()),
        HandshakeError::Conn(ConnError::Cancelled) => TlsOutcome::Aborted,
        // A detaching sandbox's connections are reset by Sites.
        HandshakeError::Conn(ConnError::Reset) if watch.detached() => TlsOutcome::Aborted,
        HandshakeError::Closed | HandshakeError::Conn(_) => TlsOutcome::Closed,
    }
}

/// Serves one connection.
async fn connection(cx: Cx, conn: tcp::TcpConnection, machine: Arc<Machine>, https: bool, arrival: Arrival) {
    let local = conn.local_addr();
    let port = local.port();
    let watch = arrival.seen.map(|(sandbox, conn)| {
        Arc::new(Watch { cx: cx.clone(), hooks: machine.hooks.clone(), sandbox, conn, local })
    });
    let deadline = arrival.accepted + HANDSHAKE_TIME;
    // Taken before the connection moves into TLS and hyper.
    let gone = conn.gone_watch();
    if https {
        let mut sni: Option<String> = None;
        let mut failed: Option<HandshakeError> = None;
        let mut rejected = false;
        let handshake = async {
            let hello = match tls::server_detailed(&cx, conn).await {
                Ok(hello) => hello,
                Err(e) => {
                    failed = Some(e);
                    return None;
                }
            };
            sni = hello.server_name().map(normalize);
            // Only a site at this address with TLS. A hello with no name, or
            // with a name that is not such a site, is rejected.
            let site = sni.as_deref().and_then(|n| machine.site(n)).filter(|s| s.tls.is_some());
            let Some(site) = site else {
                rejected = true;
                let _ = hello.reject(&cx).await;
                return None;
            };
            let config = site.tls.as_ref().expect("filtered on tls").config(&cx);
            match hello.finish_detailed(&cx, config).await {
                Ok(conn) => Some(conn),
                Err(e) => {
                    failed = Some(e);
                    None
                }
            }
        };
        let done = until(&cx, deadline, handshake).await;
        let (conn, outcome) = match done {
            Limited::Done(Some(conn)) => {
                let alpn = conn.alpn().map(<[u8]>::to_vec);
                (Some(conn), TlsOutcome::Accepted { alpn })
            }
            Limited::Done(None) if rejected => (None, TlsOutcome::Rejected),
            Limited::Done(None) => (None, TlsOutcome::Closed),
            Limited::TimedOut => (None, TlsOutcome::TimedOut),
            Limited::Cancelled => (None, TlsOutcome::Aborted),
        };
        if let Some(w) = &watch {
            let outcome = match failed {
                Some(e) => tls_outcome(e, w),
                None => outcome,
            };
            w.emit(Event::Tls(Tls { sandbox: w.sandbox.clone(), conn: w.conn, addr: local.ip(), sni: sni.clone(), outcome }));
        }
        let Some(conn) = conn else { return };
        let h2 = conn.alpn() == Some(b"h2".as_slice());
        serve_http(cx, conn, Vec::new(), machine, Scheme::HTTPS, port, h2, sni, watch, gone).await;
    } else {
        // Read until the bytes cannot be the HTTP/2 preface, or are all of it.
        let mut conn = conn;
        let mut first = Vec::new();
        let preface = async {
            let mut buf = [0u8; 24];
            while first.len() < PREFACE.len() && PREFACE.starts_with(&first) {
                match conn.read(&cx, &mut buf[..PREFACE.len() - first.len()]).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => first.extend_from_slice(&buf[..n]),
                }
            }
            true
        };
        match until(&cx, deadline, preface).await {
            Limited::Done(true) => {}
            Limited::Done(false) | Limited::Cancelled => return,
            Limited::TimedOut => {
                if let Some(w) = &watch {
                    let detail = format!("no bytes within {} seconds of connecting", HANDSHAKE_TIME.as_secs());
                    w.http_error(HttpErrorCause::Timeout, detail);
                }
                return;
            }
        }
        let h2 = first == PREFACE;
        serve_http(cx, conn, first, machine, Scheme::HTTP, port, h2, None, watch, gone).await;
    }
}

/// Runs hyper on a connection. `first` holds bytes already read from it.
#[allow(clippy::too_many_arguments)]
async fn serve_http<C: Connection + Unpin>(
    cx: Cx,
    conn: C,
    first: Vec<u8>,
    machine: Arc<Machine>,
    scheme: Scheme,
    port: u16,
    h2: bool,
    sni: Option<String>,
    watch: Option<Arc<Watch>>,
    gone: tcp::GoneWatch,
) {
    let broke = watch.as_ref().map(|_| Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let io = Io { cx: cx.clone(), conn, broke: broke.clone(), first, at: 0, buf: vec![0; 16 * 1024].into_boxed_slice() };
    let route = Route { machine, scheme, port, sni, watch: watch.clone() };
    // In a browser, `std::time::Instant::now` and `SystemTime::now` panic.
    // hyper's timer API is in `Instant`, so there hyper runs without a timer
    // (HTTP/1.1 then has no header read timeout), and it writes no `Date`
    // header, which it takes from `SystemTime`.
    let browser = cfg!(target_arch = "wasm32");
    let timer = (!browser).then(|| CxTimer { cx: cx.clone() });
    let served: Pin<Box<dyn Future<Output = Result<(), hyper::Error>> + Send>> = if h2 {
        let mut builder = hyper::server::conn::http2::Builder::new(Executor::new(&cx));
        builder.auto_date_header(!browser);
        if let Some(timer) = timer {
            builder.timer(timer);
        }
        Box::pin(builder.serve_connection(io, route))
    } else {
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder.half_close(true).auto_date_header(!browser);
        if let Some(timer) = timer {
            builder.timer(timer);
        }
        Box::pin(builder.serve_connection(io, route))
    };
    // HTTP/1.1 with half-close does not read while a handler works, so
    // hyper would not see a reset (by the client, or by Sites when the
    // sandbox detaches) until the handler returns. So the connection ends
    // as soon as it is reset: its handlers are dropped, and with events on,
    // the requests in flight end as cancelled.
    // It also ends when the world stops: a handler that waits on something
    // outside the world would otherwise keep the region from ending.
    let mut served = served;
    let mut stopping = std::pin::pin!(cx.cancelled());
    let result = std::future::poll_fn(|task| {
        if let Poll::Ready(r) = served.as_mut().poll(task) {
            return Poll::Ready(Some(r));
        }
        if gone.poll_gone(task).is_ready() || stopping.as_mut().poll(task).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await;
    drop(served);
    let Some(result) = result else { return };
    let Some(w) = &watch else { return };
    let broke = broke.is_some_and(|b| b.load(std::sync::atomic::Ordering::Relaxed));
    match result {
        Err(e) => {
            if let Some(cause) = http_error_cause(&e) {
                w.http_error(cause, e.to_string());
            } else if broke {
                w.http_error(HttpErrorCause::Transport, e.to_string());
            }
        }
        Ok(()) if broke => w.http_error(HttpErrorCause::Transport, "a TLS record did not decrypt".into()),
        Ok(()) => {}
    }
}

/// Why hyper ended a connection with `e`, if it is an error the world hears
/// about: the client's bytes were not HTTP, or the TLS under it failed. The
/// client closing or resetting the connection, and timeouts, are not.
fn http_error_cause(e: &hyper::Error) -> Option<HttpErrorCause> {
    if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() {
        return Some(HttpErrorCause::Protocol);
    }
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if let Some(e) = s.downcast_ref::<h2::Error>() {
            if let Some(io) = e.get_io() {
                return transport(io);
            }
            // h2 found the client's frames broke the protocol.
            let protocol = e.is_library() && e.reason().is_some_and(|r| r != h2::Reason::NO_ERROR);
            return protocol.then_some(HttpErrorCause::Protocol);
        }
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            return transport(io);
        }
        source = s.source();
    }
    None
}

/// A TLS connection fails reads with `Broken` when a record is bad.
fn transport(io: &std::io::Error) -> Option<HttpErrorCause> {
    let broken = io.get_ref().and_then(|e| e.downcast_ref::<ConnError>()) == Some(&ConnError::Broken);
    broken.then_some(HttpErrorCause::Transport)
}

// ---------------------------------------------------------------------------
// Routing

/// Sends each request to the site for its host.
#[derive(Clone)]
struct Route {
    machine: Arc<Machine>,
    scheme: Scheme,
    port: u16,
    /// The connection's SNI, for [`Target::sni`].
    sni: Option<String>,
    watch: Option<Arc<Watch>>,
}

impl Route {
    fn target(&self, host: &str) -> Target {
        Target { scheme: self.scheme.clone(), host: host.to_owned(), port: self.port, sni: self.sni.clone() }
    }
}

impl hyper::service::Service<Request<Incoming>> for Route {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        if request.method() != http::Method::HEAD {
            return self.route(request);
        }
        let reply = self.route(request);
        Box::pin(async move { reply.await.map(headers_only) })
    }
}

impl Route {
    fn route(&self, mut request: Request<Incoming>) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
        let host = request_host(&request);
        // The request is tracked from here: exactly one event, however it
        // ends.
        let tracked = self.watch.as_ref().map(|watch| {
            Tracked(Some(Pending {
                http: Http {
                    sandbox: watch.sandbox.clone(),
                    conn: watch.conn,
                    local: watch.local,
                    scheme: self.scheme.clone(),
                    sni: self.sni.clone(),
                    host: host.clone(),
                    started: watch.cx.now(),
                    method: request.method().clone(),
                    uri: request.uri().clone(),
                    version: request.version(),
                    headers: request.headers().clone(),
                    answer: HttpAnswer::Cancelled,
                    status: None,
                    sent: 0,
                    complete: false,
                    extensions: http::Extensions::new(),
                },
                watch: watch.clone(),
            }))
        });
        let Some(host) = host else {
            return ready(answered(tracked, HttpAnswer::NoHost, text(StatusCode::BAD_REQUEST, "The request names no host.\n")));
        };
        let misdirected = |tracked| {
            ready(answered(
                tracked,
                HttpAnswer::Misdirected,
                text(StatusCode::MISDIRECTED_REQUEST, "This server does not serve that host.\n"),
            ))
        };
        let Some(site) = self.machine.site_or_default(&host) else {
            return misdirected(tracked);
        };
        let https = self.scheme == Scheme::HTTPS;
        match (https, site.tls.is_some()) {
            // A site without TLS, asked for on a TLS connection made for
            // another site at this address.
            (true, false) => misdirected(tracked),
            (false, true) if !site.plain_http => {
                let path = request.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
                let location = format!("https://{host}{path}");
                let mut response = text(StatusCode::MOVED_PERMANENTLY, &format!("Moved to {location}\n"));
                if let Ok(value) = location.parse() {
                    response.headers_mut().insert(LOCATION, value);
                }
                ready(answered(tracked, HttpAnswer::Redirect, response))
            }
            _ => {
                request.extensions_mut().insert(self.target(&host));
                let reply = (site.handler)(request);
                // If hyper drops this future before the handler returns
                // (the client reset the stream or the connection), `tracked`
                // is dropped with it and reports the request cancelled.
                Box::pin(async move {
                    match reply.await {
                        Ok(response) => Ok(answered(tracked, HttpAnswer::Handler, response)),
                        Err(e) if e.is::<BadGateway>() => {
                            Ok(answered(tracked, HttpAnswer::Error, text(StatusCode::BAD_GATEWAY, &format!("{e}\n"))))
                        }
                        Err(_) => Ok(answered(
                            tracked,
                            HttpAnswer::Error,
                            text(StatusCode::INTERNAL_SERVER_ERROR, "The site failed to answer.\n"),
                        )),
                    }
                })
            }
        }
    }
}

/// The response to a `HEAD` request: `response`'s headers with no body.
/// hyper leaves the body out on HTTP/1.1 but sends it on HTTP/2, which
/// breaks the stream, so the body is dropped here for both. A body of
/// known length keeps its length as `content-length`, as a real server's
/// answer to `HEAD` does.
fn headers_only(response: Response<Body>) -> Response<Body> {
    let (mut parts, body) = response.into_parts();
    let status = parts.status;
    let bodiless = status.is_informational() || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED;
    if let Some(len) = http_body::Body::size_hint(&body).exact()
        && !bodiless && !parts.headers.contains_key(CONTENT_LENGTH)
    {
        parts.headers.insert(CONTENT_LENGTH, http::HeaderValue::from(len));
    }
    // Dropping a counted body ends its event: complete, with nothing sent.
    drop(body);
    Response::from_parts(parts, Empty::new().map_err(|never| match never {}).boxed_unsync())
}

/// A request's event, still being filled in.
struct Pending {
    http: Http,
    watch: Arc<Watch>,
}

/// A request being tracked. Dropping it makes the request's event, with
/// what is known by then: [`HttpAnswer::Cancelled`] if no response came.
struct Tracked(Option<Pending>);

impl Tracked {
    fn end(&mut self) {
        if let Some(p) = self.0.take() {
            p.watch.emit(Event::Http(p.http));
        }
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.end();
    }
}

/// `response`, with its body counted for the request's event, if the
/// world wants events. The response's extensions go to the event.
fn answered(tracked: Option<Tracked>, answer: HttpAnswer, response: Response<Body>) -> Response<Body> {
    let Some(mut tracked) = tracked else { return response };
    let (mut parts, body) = response.into_parts();
    let status = parts.status;
    // Responses that never carry a body are whole once they are sent.
    let no_body = status.is_informational() || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED;
    if let Some(p) = &mut tracked.0 {
        p.http.extensions = std::mem::take(&mut parts.extensions);
        p.http.answer = answer;
        p.http.status = Some(status);
        p.http.complete = false;
        let no_body = no_body || p.http.method == http::Method::HEAD;
        let counted = Counted { body, rest: Bytes::new(), no_body, tracked };
        return Response::from_parts(parts, Body::new(counted));
    }
    Response::from_parts(parts, body)
}

/// The most of a body [`Counted`] hands hyper at once. hyper takes the next
/// piece only once the connection has room for more, so the count of bytes
/// sent stays close to what went out, even for a body that is one large
/// chunk.
const PIECE: usize = 16 * 1024;

/// A response body that counts the bytes sent, and makes the request's
/// event when it ends or is dropped.
struct Counted {
    body: Body,
    /// What is left of a chunk larger than [`PIECE`].
    rest: Bytes,
    /// The response has no body to send (HEAD, 204, 304, 1xx).
    no_body: bool,
    tracked: Tracked,
}

impl Counted {
    fn add(&mut self, n: usize) {
        if let Some(p) = &mut self.tracked.0 {
            p.http.sent += n as u64;
        }
    }

    fn end(&mut self, complete: bool) {
        if let Some(p) = &mut self.tracked.0 {
            p.http.complete = complete;
        }
        self.tracked.end();
    }
}

impl http_body::Body for Counted {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        if !this.rest.is_empty() {
            let piece = this.rest.split_to(this.rest.len().min(PIECE));
            this.add(piece.len());
            return Poll::Ready(Some(Ok(http_body::Frame::data(piece))));
        }
        let mut polled = Pin::new(&mut this.body).poll_frame(task);
        if let Poll::Ready(Some(Ok(frame))) = &mut polled
            && let Some(data) = frame.data_mut()
            && data.len() > PIECE
        {
            this.rest = data.split_off(PIECE);
        }
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let n = data.len();
                    this.add(n);
                }
            }
            Poll::Ready(Some(Err(_))) => this.end(false),
            Poll::Ready(None) => this.end(true),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.rest.is_empty() && self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let inner = self.body.size_hint();
        let rest = self.rest.len() as u64;
        let mut hint = http_body::SizeHint::new();
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper + rest);
        }
        hint.set_lower(inner.lower() + rest);
        hint
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        // hyper may stop polling once the body says it has ended, and never
        // polls the body of a response that has none.
        let complete = http_body::Body::is_end_stream(self) || self.no_body;
        self.end(complete);
    }
}

/// The host a request is for: the authority of its URI (HTTP/2's
/// `:authority`, or an absolute URI in HTTP/1.1), else its `Host` header.
/// Lowercase, without the port or a trailing dot.
fn request_host<B>(request: &Request<B>) -> Option<String> {
    let host = match request.uri().authority() {
        Some(a) => a.host().to_owned(),
        None => {
            let value = request.headers().get(HOST)?.to_str().ok()?;
            value.parse::<Authority>().ok()?.host().to_owned()
        }
    };
    let host = normalize(&host);
    (!host.is_empty()).then_some(host)
}

fn ready(response: Response<Body>) -> Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>> {
    Box::pin(std::future::ready(Ok(response)))
}

/// A short plain-text response.
fn text(status: StatusCode, body: &str) -> Response<Body> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_owned())).map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = status;
    response.headers_mut().insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

// ---------------------------------------------------------------------------
// hyper's I/O and timer, from a Connection and a Cx

/// A [`Connection`] as hyper's `Read` and `Write`. Bytes in `first` are
/// read before any from the connection.
struct Io<C> {
    cx: Cx,
    conn: C,
    /// Set when a read failed with [`ConnError::Broken`]: on TLS, a record
    /// that would not decrypt. hyper drops read errors between requests,
    /// so the event needs to know this itself.
    broke: Option<Arc<std::sync::atomic::AtomicBool>>,
    first: Vec<u8>,
    at: usize,
    buf: Box<[u8]>,
}

fn to_io(e: ConnError) -> std::io::Error {
    use std::io::ErrorKind;
    let kind = match e {
        ConnError::Cancelled => ErrorKind::Interrupted,
        ConnError::Refused => ErrorKind::ConnectionRefused,
        ConnError::Reset => ErrorKind::ConnectionReset,
        ConnError::TimedOut => ErrorKind::TimedOut,
        ConnError::Closed => ErrorKind::BrokenPipe,
        ConnError::Broken => ErrorKind::InvalidData,
    };
    std::io::Error::new(kind, e)
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.at < this.first.len() {
            let n = buf.remaining().min(this.first.len() - this.at);
            buf.put_slice(&this.first[this.at..this.at + n]);
            this.at += n;
            if this.at == this.first.len() {
                this.first = Vec::new();
                this.at = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let want = buf.remaining().min(this.buf.len());
        match this.conn.poll_read(&this.cx, task, &mut this.buf[..want]) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&this.buf[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                if e == ConnError::Broken && let Some(broke) = &this.broke {
                    broke.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Poll::Ready(Err(to_io(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.conn.poll_write(&this.cx, task, data).map_err(to_io)
    }

    /// Vectored, so hyper queues a response's chunks and writes them
    /// straight from where they are. Without it, hyper copies each chunk
    /// into one write buffer of its own, which then keeps the size of the
    /// largest response (about a megabyte for a 1 MiB body) for as long as
    /// the connection stays open.
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut done = 0;
        for buf in bufs.iter().filter(|b| !b.is_empty()) {
            match this.conn.poll_write(&this.cx, task, buf) {
                Poll::Ready(Ok(n)) => {
                    done += n;
                    if n < buf.len() {
                        break;
                    }
                }
                // Bytes already taken are reported; the error comes again
                // on the next write.
                Poll::Ready(Err(e)) if done == 0 => return Poll::Ready(Err(to_io(e))),
                Poll::Pending if done == 0 => return Poll::Pending,
                Poll::Ready(Err(_)) | Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(done))
    }

    /// A connection hands bytes on as soon as it takes them.
    fn poll_flush(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn.poll_shutdown(&this.cx, task).map_err(to_io)
    }
}

/// hyper's timer, on the run's clock. hyper uses it for the HTTP/1.1
/// header read timeout (30 seconds).
#[derive(Clone)]
struct CxTimer {
    cx: Cx,
}

impl hyper::rt::Timer for CxTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let cx = self.cx.clone();
        Box::pin(CxSleep(Box::pin(async move {
            // A cancelled region ends the sleep too; the connection then
            // ends on its own.
            let _ = cx.sleep(duration).await;
        })))
    }

    fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        self.sleep(deadline.saturating_duration_since(std::time::Instant::now()))
    }
}

/// A sleep for hyper, which wants it `Sync`.
struct CxSleep(Pin<Box<dyn Future<Output = ()> + Send>>);

// SAFETY: `CxSleep` gives no access to its future through `&self`: the
// only way in is `poll`, which takes `Pin<&mut Self>`. So sharing a
// `&CxSleep` between threads cannot touch the future at all.
unsafe impl Sync for CxSleep {}

impl Future for CxSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        self.get_mut().0.as_mut().poll(task)
    }
}

impl hyper::rt::Sleep for CxSleep {}

// ---------------------------------------------------------------------------
// The proxy

/// The client [`proxy`](super::proxy) forwards with.
#[cfg(feature = "tokio")]
pub(super) type ProxyClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Incoming,
>;

#[cfg(feature = "tokio")]
pub(super) fn proxy_client() -> ProxyClient {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider)
        .expect("ring supports the default TLS versions")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
}

/// Headers that belong to one connection and are not passed on (RFC 9110,
/// section 7.6.1).
#[cfg(feature = "tokio")]
const HOP_BY_HOP: [&str; 8] =
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization"];

#[cfg(feature = "tokio")]
fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    // Headers the Connection header names are hop-by-hop too.
    let named: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect();
    for name in HOP_BY_HOP.iter().copied().chain(named.iter().map(String::as_str)) {
        headers.remove(name);
    }
}

/// Forwards one request to its [`Target`] over the world's own network.
#[cfg(feature = "tokio")]
pub(super) async fn forward(client: Arc<ProxyClient>, request: Request<Incoming>) -> Result<Response<Incoming>, Error> {
    let target = request
        .extensions()
        .get::<Target>()
        .cloned()
        .ok_or("web::proxy() serves only requests that web::Sites routed: there is no web::Target")?;
    let (mut parts, body) = request.into_parts();
    let default_port = (target.scheme == Scheme::HTTP && target.port == 80) || (target.scheme == Scheme::HTTPS && target.port == 443);
    let authority = if default_port { target.host.clone() } else { format!("{}:{}", target.host, target.port) };
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    parts.uri = format!("{}://{}{}", target.scheme, authority, path).parse()?;
    parts.version = http::Version::HTTP_11;
    strip_hop_by_hop(&mut parts.headers);
    parts.headers.insert(HOST, authority.parse()?);
    let mut response =
        client.request(Request::from_parts(parts, body)).await.map_err(|e| BadGateway(format!("{}: {e}", target.host)))?;
    strip_hop_by_hop(response.headers_mut());
    Ok(response)
}
