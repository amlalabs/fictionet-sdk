use std::future::poll_fn;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, DATE};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body::{Body as _, Frame, SizeHint};
use hyper::body::Incoming;

use fictionet::RaceError;
use fictionet::events::{ConnInfo, Fields};
use fictionet::stdlib::codec::{Buffer, Decode, Step};
use fictionet::stdlib::http1::{self, Event as H1};
use fictionet::stdlib::serve::{Budget, Charge, PanicNote, Prefixed};
use fictionet::stdlib::{ConnError, Connection};
use fictionet::time::Instant;
use fictionet::{Cancelled, Cx, Error};

use super::response::{
    ResponsePolicy, Track, Tracker, answered, error_event, error_response, request_held,
};
use super::{
    Body, Exchange, Handler, HttpOptions, Limits, Observer, PIECE, Received, Reply,
    UpgradeHandler, date_header, text,
};

/// Runs hyper's HTTP/2 server on `conn`.
pub(super) async fn serve<C: Connection + Unpin>(
    fcx: &Cx,
    conn: C,
    handler: Arc<dyn Handler>,
    info: ConnInfo,
    opts: &HttpOptions,
) -> Result<(), Cancelled> {
    let broke = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let io = Io::new(fcx, conn, broke.clone(), opts.limits.write_timeout);
    let route = Route::new(fcx, handler, &info, opts);
    let mut builder = hyper::server::conn::http2::Builder::new(Executor { fcx: fcx.clone() });
    // hyper would take a `Date` header from the host's clock: the route
    // writes the world's.
    // Hyper still refreshes its internal date cache using SystemTime,
    // but auto_date_header(false) prevents that value reaching the wire.
    builder.auto_date_header(false);
    builder.max_concurrent_streams(opts.limits.streams);
    // h2 retains reset streams using its own host clock. Its public API
    // cannot inject Cx time; that third-party limitation remains in labs.
    // hyper reads all the time on HTTP/2, so a reset ends it on its own.
    let served = builder.serve_connection(io, route);
    finish(fcx, &info, &broke, None, fcx.race(None, served).await)
}

/// Runs hyper's HTTP/1 server on `conn`, with upgrades: where
/// [`Http1`](super::Http1) hands over a connection whose request asks for a protocol
/// upgrade, such as a WebSocket handshake. The request carries hyper's
/// `OnUpgrade`, so `hyper::upgrade::on` and axum's `WebSocketUpgrade`
/// work, and the connection goes to whatever awaits it once the `101`
/// is sent. Other requests on the connection are answered as usual.
pub(super) async fn serve_upgrade<C: Connection + Unpin + Send + 'static>(
    fcx: &Cx,
    conn: C,
    handler: Arc<dyn Handler>,
    info: ConnInfo,
    opts: &HttpOptions,
) -> Result<(), Cancelled> {
    let broke = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut io = Io::new(
        fcx,
        Box::new(conn) as Box<dyn Connection>,
        broke.clone(),
        opts.limits.write_timeout,
    );
    let upgraded = Arc::new(AtomicBool::new(false));
    let refused = Arc::new(OnceLock::new());
    io.heads = Some(HeadCheck::new(
        fcx,
        opts.limits,
        upgraded.clone(),
        refused.clone(),
    ));
    let mut route = Route::new(fcx, handler, &info, opts);
    route.upgraded = Some(upgraded);
    let mut builder = hyper::server::conn::http1::Builder::new();
    // Hyper still refreshes its internal date cache using SystemTime,
    // but auto_date_header(false) prevents that value reaching the wire.
    builder.auto_date_header(false);
    builder.max_headers(opts.limits.head.headers);
    // Hyper requires at least 8192 bytes. HeadCheck enforces smaller limits.
    builder.max_buf_size(opts.limits.head.head.max(8192));
    if cfg!(target_arch = "wasm32") {
        // HeadCheck enforces the deadline without a host Instant.
        builder.header_read_timeout(None);
    } else {
        builder.timer(CxTimer::new(fcx.clone()));
        builder.header_read_timeout(opts.limits.header_timeout);
    }
    let served = builder.serve_connection(io, route).with_upgrades();
    let raced = fcx.race(None, served).await;
    finish(fcx, &info, &broke, refused.get(), raced)
}

/// How a connection hyper served ends: [`Cancelled`] if `fcx`'s region
/// was cancelled, whether hyper saw it first or its I/O did; otherwise
/// it ended, and an error is recorded.
fn finish(
    fcx: &Cx,
    info: &ConnInfo,
    broke: &std::sync::atomic::AtomicBool,
    refused: Option<&http1::Error>,
    raced: Result<Result<(), hyper::Error>, RaceError>,
) -> Result<(), Cancelled> {
    let Ok(result) = raced else {
        return Err(Cancelled);
    };
    if fcx.is_cancelled() {
        return Err(Cancelled);
    }
    report(fcx, info, broke, refused, result);
    Ok(())
}

/// Records how a connection hyper served ended, if in an error. `refused`
/// is the request head [`HeadCheck`] refused, if one: hyper's result
/// cannot say, since a read error on an idle connection before any byte of
/// the next head reaches hyper is, to hyper, the client closing.
fn report(
    fcx: &Cx,
    info: &ConnInfo,
    broke: &std::sync::atomic::AtomicBool,
    refused: Option<&http1::Error>,
    result: Result<(), hyper::Error>,
) {
    let broke = broke.load(std::sync::atomic::Ordering::Relaxed);
    let cause = match (&result, refused) {
        (_, Some(e)) => Some(("protocol", e.to_string())),
        (Err(e), None) => match error_cause(e) {
            Some(cause) => Some((cause, e.to_string())),
            None if broke => Some(("transport", e.to_string())),
            None => None,
        },
        (Ok(()), None) if broke => {
            Some(("transport", "a TLS record did not decrypt".to_owned()))
        }
        (Ok(()), None) => None,
    };
    if let Some((cause, detail)) = cause {
        fcx.record(error_event(info, cause, detail).conn(info));
    }
}

/// Why hyper ended a connection with `e`, if it is an error worth an
/// event: the client's bytes broke HTTP/2, or the TLS under it failed.
fn error_cause(e: &hyper::Error) -> Option<&'static str> {
    if e.is_parse() || e.is_parse_too_large() || e.is_parse_status() {
        return Some("protocol");
    }
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if let Some(e) = s.downcast_ref::<::h2::Error>() {
            if let Some(io) = e.get_io() {
                return transport(io);
            }
            let protocol =
                e.is_library() && e.reason().is_some_and(|r| r != ::h2::Reason::NO_ERROR);
            return protocol.then_some("protocol");
        }
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            return transport(io);
        }
        source = s.source();
    }
    None
}

fn transport(io: &std::io::Error) -> Option<&'static str> {
    let broken =
        io.get_ref().and_then(|e| e.downcast_ref::<ConnError>()) == Some(&ConnError::Broken);
    if broken {
        Some("transport")
    } else {
        match io.kind() {
            std::io::ErrorKind::InvalidData => Some("protocol"),
            std::io::ErrorKind::TimedOut => Some("timeout"),
            _ => None,
        }
    }
}

/// Answers each request hyper reads, with the connection's limits,
/// budget and randomness.
#[derive(Clone)]
struct Route {
    fcx: Cx,
    handler: Arc<dyn Handler>,
    info: Arc<ConnInfo>,
    date: Option<SystemTime>,
    limits: Limits,
    budget: Option<Budget>,
    observe: Option<Arc<dyn Observer>>,
    upgraded: Option<Arc<AtomicBool>>,
}

impl Route {
    fn new(fcx: &Cx, handler: Arc<dyn Handler>, info: &ConnInfo, opts: &HttpOptions) -> Route {
        Route {
            fcx: fcx.clone(),
            handler,
            info: Arc::new(info.clone()),
            date: opts.date,
            limits: opts.limits,
            budget: opts.budget.clone(),
            observe: opts.observe.clone(),
            upgraded: None,
        }
    }

    /// Reads a request's body, charging it as it comes. `Err` is the
    /// answer instead.
    async fn body(
        &self,
        body: Incoming,
        charge: &mut Option<Charge>,
        tracker: &mut Tracker,
    ) -> Result<Bytes, Box<Response<Body>>> {
        let read = async {
            let mut body = pin!(body);
            let mut got = Vec::new();
            while let Some(frame) = poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
                let Ok(frame) = frame else {
                    tracker.received(Received::CutOff);
                    return Err(Box::new(answered(
                        text(StatusCode::BAD_REQUEST, "The request body was cut off.\n"),
                        "cut_off",
                    )));
                };
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                tracker.body(&data);
                let len = got.len() + data.len();
                if len > self.limits.body {
                    tracker.received(Received::TooLarge);
                    return Err(Box::new(answered(
                        text(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "The request body is too large.\n",
                        ),
                        "too_large",
                    )));
                }
                if !charge.as_mut().is_none_or(|c| c.set(len)) {
                    tracker.received(Received::Budget);
                    return Err(Box::new(over_budget()));
                }
                got.extend_from_slice(&data);
            }
            tracker.received(Received::Complete);
            Ok(Bytes::from(got))
        };
        match self
            .fcx
            .race(Some(self.fcx.now() + self.limits.body_timeout), read)
            .await
        {
            Ok(got) => got,
            Err(error) => {
                tracker.received(if error == RaceError::Deadline {
                    Received::Timeout
                } else {
                    Received::CutOff
                });
                Err(Box::new(answered(
                    text(
                        StatusCode::REQUEST_TIMEOUT,
                        "The request body took too long.\n",
                    ),
                    "timeout",
                )))
            }
        }
    }
}

/// The answer when the sandbox's budget cannot hold a body.
fn over_budget() -> Response<Body> {
    answered(
        text(
            StatusCode::SERVICE_UNAVAILABLE,
            "The server cannot hold this request now.\n",
        ),
        "budget",
    )
}

type Answer = Pin<Box<dyn Future<Output = Result<Response<Counted>, Error>> + Send>>;

impl hyper::service::Service<Request<Incoming>> for Route {
    type Response = Response<Counted>;
    type Error = Error;
    type Future = Answer;

    fn call(&self, request: Request<Incoming>) -> Answer {
        let mut tracker = Tracker::observing(&request, &self.info, self.observe.clone());
        tracker.start(&request, &self.info, self.fcx.now());
        let metadata = self.budget.as_ref().map(|budget| {
            let head = budget.charge(request_held(&request))?;
            let event = budget.charge(tracker.held())?;
            Some((head, event))
        });
        let (head_charge, event_charge) = match metadata {
            Some(Some((head, event))) => (Some(head), Some(event)),
            None => (None, None),
            Some(None) => {
                tracker.received(Received::Budget);
                if let Some(event) = tracker.finish(
                    Some(Fields::new().with("answer", "budget")), None, 0, false,
                ) {
                    self.fcx.record(event.conn(&self.info));
                }
                return Box::pin(std::future::ready(Err(Error::msg(
                    "request metadata exceeds budget",
                ))));
            }
        };
        let on_upgrade = request
            .extensions()
            .get::<hyper::upgrade::OnUpgrade>()
            .cloned();
        let route = self.clone();
        let track = Track {
            tracker,
            _charge: event_charge,
            fcx: route.fcx.clone(),
            info: route.info.clone(),
            extra: None,
            status: None,
            sent: 0,
            complete: false,
            _note: PanicNote::new("an httpd handler over HTTP/2", &route.info),
        };
        Box::pin(async move {
            // Dropped with the future if the client resets the stream.
            let mut track = track;
            // Charged a piece at a time: the request's body, then the
            // response body while it is held in full.
            let mut charge = route.budget.as_ref().and_then(|b| b.charge(0));
            let (parts, body) = request.into_parts();
            let head_only = parts.method == Method::HEAD;
            let response = match route.body(body, &mut charge, &mut track.tracker).await {
                Err(answer) => {
                    drop(parts);
                    *answer
                }
                Ok(body) => {
                    let mut request = Request::from_parts(parts, Body::from(body));
                    request.extensions_mut().insert((*route.info).clone());
                    let now = route.fcx.now();
                    let reply = route
                        .handler
                        .call(request, &mut Exchange::new(now, &route.fcx, &route.info));
                    match reply {
                        Reply::Now(r) => r,
                        Reply::Later(work) => match work(route.fcx.clone()).await {
                            Ok(r) => r,
                            Err(e) => error_response(&e),
                        },
                    }
                }
            };
            drop(head_charge);
            if response.status() == StatusCode::SWITCHING_PROTOCOLS
                && let Some(upgraded) = &route.upgraded
            {
                upgraded.store(true, Ordering::Relaxed);
            }
            if response.status() == StatusCode::SWITCHING_PROTOCOLS
                && let Some(upgrade) = response.extensions().get::<UpgradeHandler>().cloned()
                && let Some(on_upgrade) = on_upgrade
            {
                route.fcx.spawn(move |fcx| async move {
                    if let Ok(upgraded) = on_upgrade.await
                        && let Ok(parts) = upgraded.downcast::<Io<Box<dyn Connection>>>()
                    {
                        let mut first = parts.read_buf.to_vec();
                        if let Some(heads) = parts.io.heads {
                            first.extend_from_slice(heads.input.unread());
                        }
                        let conn = Prefixed::new(first, parts.io.conn);
                        upgrade.run(fcx, Box::new(conn)).await;
                    }
                    Ok(())
                });
            }
            let (parts, body) = response.into_parts();
            let fits = charge.as_mut().is_none_or(|c| c.set(body.full_len()));
            let (mut parts, body) = if fits {
                (parts, body)
            } else {
                over_budget().into_parts()
            };
            let policy = ResponsePolicy::new(
                &parts,
                body.size_hint().exact(),
                head_only,
                date_header(route.date, route.fcx.now()),
            );
            if let Some(date) = policy.date {
                parts.headers.insert(DATE, date);
            }
            track.extra = parts.extensions.get::<Fields>().cloned();
            track.status = Some(parts.status);
            let bodiless = policy.bodiless;
            let body = if bodiless {
                // hyper would send the body on HTTP/2 even for HEAD,
                // which breaks the stream.
                if let Some(len) = policy.len
                    && !parts.headers.contains_key(CONTENT_LENGTH)
                {
                    parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
                }
                track.complete = true;
                Body::empty()
            } else {
                body
            };
            if let Some(c) = &mut charge {
                c.set(body.full_len());
            }
            parts.extensions = http::Extensions::new();
            Ok(Response::from_parts(
                parts,
                Counted {
                    body,
                    rest: Bytes::new(),
                    track,
                    bodiless,
                    failed: false,
                    charge,
                    budget: route.budget.clone(),
                },
            ))
        })
    }
}

/// A response body that counts the bytes sent and makes the request's
/// event when it ends or is dropped.
pub(super) struct Counted {
    body: Body,
    rest: Bytes,
    track: Track,
    bodiless: bool,
    failed: bool,
    /// What the body held in full still holds.
    charge: Option<Charge>,
    budget: Option<Budget>,
}

impl http_body::Body for Counted {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        if !this.rest.is_empty() {
            let piece = this.rest.split_to(this.rest.len().min(PIECE));
            if this.rest.is_empty() {
                this.rest = Bytes::new();
            }
            this.track.sent += piece.len() as u64;
            return Poll::Ready(Some(Ok(Frame::data(piece))));
        }
        let mut polled = Pin::new(&mut this.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &mut polled
            && let Some(data) = frame.data_mut()
        {
            let mut charge = this
                .charge
                .take()
                .or_else(|| this.budget.as_ref().and_then(|b| b.charge(0)));
            if charge.as_mut().is_some_and(|c| !c.set(data.len())) {
                this.failed = true;
                this.body = Body::empty();
                return Poll::Ready(Some(Err(Error::msg("response body exceeds budget"))));
            }
            *data = Bytes::from_owner(ChargedBytes {
                bytes: std::mem::take(data),
                _charge: charge,
            });
            if data.len() > PIECE {
                this.rest = data.split_off(PIECE);
            }
        }
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.track.sent += data.len() as u64;
                }
            }
            Poll::Ready(Some(Err(_))) => {
                this.failed = true;
                this.track.complete = false;
            }
            Poll::Ready(None) => this.track.complete = true,
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.rest.is_empty() && self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let inner = self.body.size_hint();
        let rest = self.rest.len() as u64;
        let mut hint = SizeHint::new();
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper + rest);
        }
        hint.set_lower(inner.lower() + rest);
        hint
    }
}

struct ChargedBytes {
    bytes: Bytes,
    _charge: Option<Charge>,
}

impl AsRef<[u8]> for ChargedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        // hyper may stop polling once the body says it has ended.
        if !self.failed && (http_body::Body::is_end_stream(self) || self.bodiless) {
            self.track.complete = true;
        }
    }
}

/// Validates request framing before hyper receives it, including heads
/// after an Upgrade request that received an ordinary response. A head
/// it refuses goes in `refused` for [`report`].
struct HeadCheck {
    decoder: http1::RequestEvents,
    input: Buffer,
    ready: usize,
    eof: bool,
    upgraded: Arc<AtomicBool>,
    refused: Arc<OnceLock<http1::Error>>,
    timer: fictionet::Timer,
    deadline: Option<Instant>,
    timeout: Duration,
}

impl HeadCheck {
    fn new(
        fcx: &Cx,
        limits: Limits,
        upgraded: Arc<AtomicBool>,
        refused: Arc<OnceLock<http1::Error>>,
    ) -> Self {
        let decoder = http1::RequestEvents::with_limits(limits.head);
        let input = Buffer::new(decoder.capacity());
        Self {
            decoder,
            input,
            ready: 0,
            eof: false,
            upgraded,
            refused,
            timer: fictionet::Timer::new(fcx),
            deadline: Some(fcx.now() + limits.header_timeout),
            timeout: limits.header_timeout,
        }
    }

    fn poll_read<C: Connection + Unpin>(
        &mut self,
        conn: &mut C,
        fcx: &Cx,
        cx: &mut Context<'_>,
        out: &mut hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.upgraded.load(Ordering::Relaxed) {
                self.ready = self.input.len();
            }
            if self.ready != 0 {
                let n = self.ready.min(out.remaining());
                out.put_slice(&self.input.unread()[..n]);
                self.input.consume(n);
                self.ready -= n;
                return Poll::Ready(Ok(()));
            }
            if !self.upgraded.load(Ordering::Relaxed) {
                if let Some(deadline) = self.deadline {
                    match self.timer.poll_until(cx, deadline) {
                        Poll::Ready(Ok(())) => {
                            return Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
                        }
                        Poll::Ready(Err(_)) => {
                            return Poll::Ready(Err(ConnError::Cancelled.into()));
                        }
                        Poll::Pending => {}
                    }
                }
                match self.decoder.decode(self.input.unread(), self.eof) {
                    Ok(Step::Item(item, n)) => {
                        match item {
                            H1::Head(_) => self.deadline = None,
                            H1::Done => self.deadline = Some(fcx.now() + self.timeout),
                            H1::Body(_) => {}
                        }
                        self.ready = n;
                        continue;
                    }
                    Ok(Step::Skip(n)) => {
                        self.ready = n;
                        continue;
                    }
                    Ok(Step::End) => return Poll::Ready(Ok(())),
                    Ok(Step::Need) => {}
                    Err(e) => {
                        let _ = self.refused.set(e);
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e,
                        )));
                    }
                }
            }
            if self.eof {
                if self.upgraded.load(Ordering::Relaxed) {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(std::io::ErrorKind::UnexpectedEof.into()));
            }
            self.input.set_limit(self.decoder.capacity());
            let spare = self.input.spare();
            if spare.is_empty() {
                return Poll::Ready(Err(std::io::ErrorKind::InvalidData.into()));
            }
            match conn.poll_read(fcx, cx, spare) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(n)) => {
                    self.input.commit(n);
                    self.eof = n == 0;
                }
            }
        }
    }
}

/// The timer of a write that waits.
type Stall = Pin<Box<dyn Future<Output = Result<(), fictionet::Cancelled>> + Send>>;

/// A connection as hyper's `Read` and `Write`. A write that takes no
/// bytes for `stall` fails with `TimedOut`, which ends the connection:
/// a client that stopped reading.
struct Io<C> {
    fcx: Cx,
    conn: C,
    broke: Arc<std::sync::atomic::AtomicBool>,
    buf: Box<[u8]>,
    stall: Duration,
    /// Armed while a write waits.
    stalled: Option<Stall>,
    heads: Option<HeadCheck>,
}

impl<C: Connection + Unpin> Io<C> {
    fn new(
        fcx: &Cx,
        conn: C,
        broke: Arc<std::sync::atomic::AtomicBool>,
        stall: Duration,
    ) -> Io<C> {
        Io {
            fcx: fcx.clone(),
            conn,
            broke,
            buf: vec![0; 16 * 1024].into_boxed_slice(),
            stall,
            stalled: None,
            heads: None,
        }
    }

    /// One write, with the stall timer: armed when it waits, cleared
    /// when bytes go.
    fn write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
        match self.conn.poll_write(&self.fcx, cx, data) {
            Poll::Pending => {
                let fcx = self.fcx.clone();
                let stall = self.stall;
                let timer = self
                    .stalled
                    .get_or_insert_with(|| Box::pin(async move { fcx.sleep(stall).await }));
                match timer.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => Poll::Ready(Err(ConnError::TimedOut)),
                    Poll::Ready(Err(_)) => Poll::Ready(Err(ConnError::Cancelled)),
                    Poll::Pending => Poll::Pending,
                }
            }
            done => {
                self.stalled = None;
                done
            }
        }
    }
}

impl<C: Connection + Unpin> hyper::rt::Read for Io<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(heads) = &mut this.heads {
            return heads.poll_read(&mut this.conn, &this.fcx, cx, &mut buf);
        }
        let want = buf.remaining().min(this.buf.len());
        match this.conn.poll_read(&this.fcx, cx, &mut this.buf[..want]) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&this.buf[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                if e == ConnError::Broken {
                    this.broke.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Poll::Ready(Err(e.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<C: Connection + Unpin> hyper::rt::Write for Io<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().write(cx, data).map_err(std::io::Error::from)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut done = 0;
        for buf in bufs.iter().filter(|b| !b.is_empty()) {
            match this.write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    done += n;
                    if n < buf.len() {
                        break;
                    }
                }
                Poll::Ready(Err(e)) if done == 0 => return Poll::Ready(Err(e.into())),
                Poll::Pending if done == 0 => return Poll::Pending,
                Poll::Ready(Err(_)) | Poll::Pending => break,
            }
        }
        // Bytes went: a later wait counts from now.
        this.stalled = None;
        Poll::Ready(Ok(done))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.conn
            .poll_shutdown(&this.fcx, cx)
            .map_err(std::io::Error::from)
    }
}

/// Runs hyper's streams as tasks, which end when the world stops.
#[derive(Clone)]
struct Executor {
    fcx: Cx,
}

impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, work: F) {
        self.fcx.spawn(move |fcx| async move {
            let mut work = pin!(work);
            let mut stopping = pin!(fcx.cancelled());
            poll_fn(|cx| {
                if work.as_mut().poll(cx).is_ready() || stopping.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
                Poll::Pending
            })
            .await;
            Ok(())
        });
    }
}

/// hyper's timer, on the run's clock.
#[derive(Clone)]
struct CxTimer {
    fcx: Cx,
    origin: std::time::Instant,
}

impl CxTimer {
    fn new(fcx: Cx) -> Self {
        Self {
            fcx,
            origin: std::time::Instant::now(),
        }
    }

    fn at(&self, deadline: fictionet::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(CxSleep(fictionet::Timer::new(&self.fcx), deadline))
    }
}

impl hyper::rt::Timer for CxTimer {
    fn now(&self) -> std::time::Instant {
        self.origin + self.fcx.now().since_start()
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let at = self
            .fcx
            .now()
            .since_start()
            .checked_add(duration)
            .unwrap_or(Duration::MAX);
        self.at(fictionet::time::Instant::from_since_start(at))
    }

    fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        self.at(fictionet::time::Instant::from_since_start(
            deadline.saturating_duration_since(self.origin),
        ))
    }
}

/// A sleep for hyper, which cannot represent cancellation.
struct CxSleep(fictionet::Timer, fictionet::time::Instant);

impl Future for CxSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        match this.0.poll_until(cx, this.1) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            _ => Poll::Pending,
        }
    }
}

impl hyper::rt::Sleep for CxSleep {}

#[cfg(test)]
mod tests {
    use super::super::{PREFACE, Router};
    use super::*;
    use fictionet::stdlib::json::Value;
    use fictionet::sync::Mutex;
    use hyper::rt::Timer;

    #[test]
    fn response_frames_keep_the_charge_after_the_body_is_dropped() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(0),
            |fcx| async move {
                let budget = Budget::new(3 * PIECE);
                let info = Arc::new(ConnInfo::default());
                let request = Request::new(Body::empty());
                let mut body = Counted {
                    body: Body::from(vec![b'x'; 2 * PIECE]),
                    rest: Bytes::new(),
                    track: Track {
                        tracker: Tracker::new(&request, &info, fcx.now()),
                        _charge: None,
                        fcx: fcx.clone(),
                        info: info.clone(),
                        extra: None,
                        status: Some(StatusCode::OK),
                        sent: 0,
                        complete: false,
                        _note: PanicNote::new("test response", &info),
                    },
                    bodiless: false,
                    failed: false,
                    charge: budget.charge(2 * PIECE),
                    budget: Some(budget.clone()),
                };
                let mut cx = Context::from_waker(std::task::Waker::noop());
                let Poll::Ready(Some(Ok(first))) = Pin::new(&mut body).poll_frame(&mut cx)
                else {
                    panic!("first frame")
                };
                assert_eq!(budget.used(), 2 * PIECE);
                let Poll::Ready(Some(Ok(last))) = Pin::new(&mut body).poll_frame(&mut cx)
                else {
                    panic!("last frame")
                };
                drop(body);
                drop(first);
                assert_eq!(budget.used(), 2 * PIECE);
                assert_eq!(last.data_ref().unwrap().len(), PIECE);
                drop(last);
                assert_eq!(budget.used(), 0);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn hyper_deadlines_use_the_clock_at_creation() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(0),
            |fcx| async move {
                let timer = CxTimer::new(fcx.clone());
                let origin = timer.now();
                let relative = timer.sleep(Duration::from_secs(10));
                let absolute = timer.sleep_until(origin + Duration::from_secs(20));
                fcx.sleep(Duration::from_secs(5)).await?;
                assert_eq!(timer.now().duration_since(origin), Duration::from_secs(5));
                // First polling a sleep later does not shift its deadline.
                relative.await;
                assert_eq!(fcx.now().since_start(), Duration::from_secs(10));
                absolute.await;
                assert_eq!(fcx.now().since_start(), Duration::from_secs(20));
                let later_timer = CxTimer::new(fcx.clone());
                later_timer
                    .sleep_until(later_timer.now() + Duration::from_secs(3))
                    .await;
                assert_eq!(fcx.now().since_start(), Duration::from_secs(23));
                Ok(())
            },
        ))
        .unwrap();
    }

    struct StalledBody {
        input: Bytes,
    }

    impl Connection for StalledBody {
        fn poll_read(
            &mut self,
            _: &Cx,
            _: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<Result<usize, ConnError>> {
            if self.input.is_empty() {
                return Poll::Pending;
            }
            let n = buf.len().min(self.input.len());
            buf[..n].copy_from_slice(&self.input.split_to(n));
            Poll::Ready(Ok(n))
        }

        fn poll_write(
            &mut self,
            _: &Cx,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<Result<usize, ConnError>> {
            Poll::Ready(Ok(data.len()))
        }

        fn poll_shutdown(
            &mut self,
            _: &Cx,
            _: &mut Context<'_>,
        ) -> Poll<Result<(), ConnError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn http2_body_timeout_uses_the_fictionet_deadline() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let mut input = PREFACE.to_vec();
                input.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
                // POST / over HTTP, with no END_STREAM on the headers.
                let block = b"\x83\x86\x84\x01\x01a";
                input.extend_from_slice(&[0, 0, block.len() as u8, 1, 4, 0, 0, 0, 1]);
                input.extend_from_slice(block);
                let conn = StalledBody {
                    input: Bytes::from(input),
                };
                let duration = Duration::from_millis(40);
                let opts = HttpOptions {
                    limits: Limits {
                        body_timeout: duration,
                        ..Limits::default()
                    },
                    ..HttpOptions::default()
                };
                let handler = Router::new().post("/", |_, _| {
                    panic!("a stalled body cannot reach the handler")
                });
                let mut served = pin!(serve(
                    &fcx,
                    conn,
                    Arc::new(handler),
                    ConnInfo::default(),
                    &opts
                ));
                let log = fcx.events();
                let wait = async {
                    loop {
                        if let Some(event) = log.of("http", "request").pop() {
                            break event;
                        }
                        fcx.sleep(Duration::from_millis(1)).await.unwrap();
                    }
                };
                let mut wait = pin!(wait);
                let event = fcx
                    .race(
                        Some(fcx.now() + Duration::from_secs(2)),
                        poll_fn(|cx| {
                            assert!(served.as_mut().poll(cx).is_pending());
                            wait.as_mut().poll(cx)
                        }),
                    )
                    .await
                    .unwrap();
                let started = event.get("started").unwrap().as_f64().unwrap();
                let elapsed = event.at.since_start().as_secs_f64() - started;
                assert_eq!(elapsed, duration.as_secs_f64());
                assert_eq!(event.str("answer"), Some("timeout"));
                assert_eq!(event.u64("status"), Some(408));
                assert_eq!(event.str("version"), Some("HTTP/2.0"));
                assert_eq!(event.get("complete").and_then(Value::as_bool), Some(true));
                assert_eq!(log.of("http", "request").len(), 1);
                assert!(log.of("http", "error").is_empty());
                Ok(())
            },
        ))
        .unwrap();
    }

    /// A hyper sleep on a cancelled `Cx` stays pending instead of
    /// firing.
    #[test]
    fn a_cancelled_sleep_never_fires() {
        fictionet::block_on(fictionet::run(
            fictionet::Seed::random(),
            |fcx| async move {
                let slot: Arc<Mutex<Option<Cx>>> = Arc::default();
                let s = slot.clone();
                let _ = fcx
                    .region(|inner| async move {
                        *s.lock() = Some(inner.clone());
                        inner.cancel();
                        Ok(())
                    })
                    .await;
                let inner = slot.lock().take().unwrap();
                assert!(inner.is_cancelled());
                let mut sleep = CxTimer::new(inner).sleep(Duration::from_secs(5));
                let pending = |sleep: &mut Pin<Box<dyn hyper::rt::Sleep>>| {
                    sleep
                        .as_mut()
                        .poll(&mut Context::from_waker(std::task::Waker::noop()))
                        .is_pending()
                };
                assert!(pending(&mut sleep));
                fcx.sleep(Duration::from_millis(5)).await?;
                assert!(pending(&mut sleep));
                Ok(())
            },
        ))
        .unwrap();
    }
}
