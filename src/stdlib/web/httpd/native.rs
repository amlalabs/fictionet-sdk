use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body::{Body as _, Frame};

use fictionet::events::Fields;
use fictionet::stdlib::codec::{Decode, Step, Wire};
use fictionet::stdlib::network::ConnError;
use fictionet::stdlib::protocols::http1::{self, Event as H1, RequestHead};
use fictionet::stdlib::services::serve::{
    self, Driver, Ended, Flow, Pending, PendingDriver, Timer,
};
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::body::Inner;
use super::handlers::status_only;
use super::response::{
    ResponsePolicy, Tracker, answered, error_event, error_response, head_held, request_held,
};
use super::sites::no_host;
use super::{
    Body, BodyClassifier, Exchange, Handler, Later, Limits, PIECE, Received, Reply, UpgradeHandler,
    date_header,
};

// ---------------------------------------------------------------------------
// HTTP/1 as a service

/// [`Http1`]'s timer for a request's head.
const HEAD: Timer = "head";
/// [`Http1`]'s timer for a request's body.
const BODY: Timer = "body";

/// HTTP/1.0 and 1.1 for one connection, answering with a [`Handler`].
pub struct Http1 {
    handler: Arc<dyn Handler>,
    pub(super) observe: Option<Arc<dyn BodyClassifier>>,
    tracker: Option<Tracker>,
    opts: Limits,
    /// The world's date at the start of the run, for `Date` headers.
    pub(super) date: Option<SystemTime>,
    /// A request handed to hyper ([`Reply::Handoff`]), as bytes, once the
    /// connection is handed over for it, with the tracker that has already
    /// observed its head and body.
    pub(super) handoff: Option<(Vec<u8>, Tracker)>,
    pub(super) upgrade: Option<UpgradeHandler>,
    head: Option<RequestHead>,
    body: Vec<u8>,
    too_big: bool,
    started: Instant,
    pub(super) first_head_deadline: Option<Instant>,
}

impl Http1 {
    /// Answers with `handler`, with default options.
    pub fn new(handler: impl Handler) -> Http1 {
        Http1::with(Arc::new(handler), Limits::default())
    }

    /// Answers with `handler` and `opts`.
    pub fn with(handler: Arc<dyn Handler>, opts: Limits) -> Http1 {
        Http1 {
            handler,
            observe: None,
            tracker: None,
            opts,
            date: None,
            handoff: None,
            upgrade: None,
            head: None,
            body: Vec::new(),
            too_big: false,
            started: Instant::ZERO,
            first_head_deadline: None,
        }
    }

    /// The request a handler handed off ([`Reply::Handoff`]), such as a
    /// WebSocket handshake for axum, after the service handed the connection
    /// back for it ([`Upgrade::Handoff`](serve::Upgrade::Handoff)): its head
    /// and body as bytes, to be read again in front of the connection's unread ones.
    /// [`serve_connection`](super::serve_connection) serves such a
    /// connection on hyper's HTTP/1, which carries out the upgrade.
    pub fn take_handoff(&mut self) -> Option<Vec<u8>> {
        self.handoff.take().map(|(bytes, _)| bytes)
    }

    /// Sends a `Date` header with each response: `start`, the world's date
    /// and time at the start of the run, plus the run's clock. See
    /// [Dates](super#dates).
    pub fn date(mut self, start: SystemTime) -> Http1 {
        self.date = Some(start);
        self
    }

    /// Observes each request before routing and while its body arrives.
    pub fn observe(mut self, observer: Arc<dyn BodyClassifier>) -> Http1 {
        self.observe = Some(observer);
        self
    }

    fn track(&mut self, head: &RequestHead, driver: &Driver<'_, http1::RequestEvents>) {
        let enabled = driver.event_enabled("http", "request");
        if !enabled || self.observe.is_none() {
            self.tracker = Some(Tracker::tracking(enabled));
            return;
        }
        if let Some(request) = to_request(head, version_of(head), Body::empty()) {
            self.tracker = Some(Tracker::observing(
                enabled,
                &request,
                driver.conn(),
                self.observe.clone(),
            ));
        }
    }

    fn finish_receipt(
        &mut self,
        driver: &mut Driver<'_, http1::RequestEvents>,
        received: Received,
    ) {
        if let Some(mut tracker) = self.tracker.take() {
            tracker.received(received);
            if driver.event_enabled("http", "request")
                && let Some(head) = &self.head
                && let Some(mut request) = to_request(head, version_of(head), Body::empty())
            {
                tracker.start(&mut request, driver.conn(), self.started);
            }
            if let Some(event) = tracker.finish(
                || Some(Fields::new().with("answer", received.as_str())),
                None,
                0,
                false,
            ) {
                driver.emit("http", "request", |_| event);
            }
        }
        self.head = None;
    }

    fn respond(&mut self, driver: &mut Driver<'_, http1::RequestEvents>) -> Flow {
        let held = self.body.capacity();
        let body = Body::from(std::mem::take(&mut self.body));
        let close = self.too_big;
        if let Some(tracker) = &mut self.tracker {
            tracker.received(if self.too_big {
                Received::TooLarge
            } else {
                Received::Complete
            });
        }
        self.dispatch(driver, body, close, held)
    }

    /// Answers the request whose head is pending, with `body`.
    /// `close` closes the connection after the answer.
    fn dispatch(
        &mut self,
        driver: &mut Driver<'_, http1::RequestEvents>,
        body: Body,
        close: bool,
        held: usize,
    ) -> Flow {
        let Some(head) = self.head.take() else {
            return Flow::Close;
        };
        let version = version_of(&head);
        let keep_alive = !close && head.keep_alive().unwrap_or(false) && head.method != "CONNECT";
        let request = match to_request(&head, version, body) {
            Some(r) => r,
            None => {
                let date = date_header(self.date, driver.now());
                write_simple(driver.reply(), version, StatusCode::BAD_REQUEST, date);
                return Flow::Close;
            }
        };
        let mut request = request;
        request.extensions_mut().insert(driver.conn().clone());
        if driver.event_enabled("http", "request") {
            request.extensions_mut().insert(super::EventInterest(true));
        }
        let head_only = request.method() == Method::HEAD;
        let mut tracker = self.tracker.take().expect("a parsed request has a tracker");
        tracker.start(&mut request, driver.conn(), self.started);
        let held = held + request_held(&request);
        let now = driver.now();
        let conn = driver.conn().clone();
        // RFC 9112 section 3.2: an HTTP/1.1 request without Host gets 400
        // from the service, unless its body is too large. The decoder
        // refuses such a head, so only `on_fail` brings one here.
        let lacks_host = version == Version::HTTP_11 && !request.headers().contains_key(HOST);
        let reply = if self.too_big {
            Reply::Now(answered(
                status_only(StatusCode::PAYLOAD_TOO_LARGE),
                "too_large",
                driver.event_enabled("http", "request"),
            ))
        } else if lacks_host {
            Reply::Now(no_host(driver.event_enabled("http", "request")))
        } else {
            self.handler
                .call(request, &mut Exchange::new(now, driver.entropy(), &conn))
        };
        if let Reply::Now(response) = &reply
            && response.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(upgrade) = response.extensions().get::<UpgradeHandler>()
        {
            self.upgrade = Some(upgrade.clone());
        }
        let close = (!keep_alive || lacks_host) && self.upgrade.is_none();
        // Every answer goes out as deferred work, so its event is made
        // once its bytes are written.
        let (work, response) = match reply {
            Reply::Now(response) => (None, Some(response)),
            Reply::Later(work) => (Some(work), None),
            Reply::Handoff(request) => {
                // Hyper reads the request again, body included, in front of
                // the bytes still unread.
                if let Some(body) = request.body().bytes() {
                    self.handoff = http1::Request {
                        head,
                        body: body.to_vec(),
                    }
                    .to_bytes()
                    .ok()
                    .map(|bytes| (bytes, tracker));
                    driver.cancel_timer(BODY);
                    return Flow::Upgrade(serve::Upgrade::Handoff);
                }
                // A body that was cut off cannot be read again.
                (
                    None,
                    Some(answered(
                        status_only(StatusCode::BAD_REQUEST),
                        "cut_off",
                        driver.event_enabled("http", "request"),
                    )),
                )
            }
        };
        driver.defer(
            Streaming::new(work, response, version, head_only, close, tracker)
                .dated(self.date, now)
                .holding_request(held),
        );
        if self.upgrade.is_some() {
            driver.cancel_timer(BODY);
            Flow::Upgrade(serve::Upgrade::Handoff)
        } else {
            self.after(driver, close)
        }
    }

    fn after(&mut self, driver: &mut Driver<'_, http1::RequestEvents>, close: bool) -> Flow {
        driver.cancel_timer(BODY);
        if close {
            return Flow::Close;
        }
        driver.set_timer(HEAD, self.opts.header_timeout);
        Flow::Continue
    }
}

/// The head at the start of `unread`, read with an empty Host field added
/// after its request line, if that makes it a request head: an HTTP/1.1
/// request that named no host.
fn without_host(unread: &[u8]) -> Option<(RequestHead, http1::RequestEvents, usize)> {
    let line_end = unread.windows(2).position(|w| w == b"\r\n")?;
    let head_end = unread.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    if head_end <= line_end {
        return None;
    }
    let mut patched = unread[..line_end + 2].to_vec();
    patched.extend_from_slice(b"Host:\r\n");
    patched.extend_from_slice(&unread[line_end + 2..head_end]);
    let mut decoder = http1::RequestEvents::new();
    let Step::Item(H1::Head(mut head), _) = decoder.decode(&patched, false).ok()? else {
        return None;
    };
    // The event records the request as it came, without the field added.
    if head
        .headers
        .first()
        .is_some_and(|h| h.name == "Host" && h.value.is_empty())
    {
        head.headers.remove(0);
    }
    Some((head, decoder, head_end))
}

/// A request body that ends early: `bytes`, then an error saying `why`.
/// A handler that reads it frame by frame sees what came.
fn partial(bytes: Bytes, why: &'static str) -> Body {
    struct Partial(Option<Bytes>, Option<&'static str>);
    impl http_body::Body for Partial {
        type Data = Bytes;
        type Error = Error;
        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
            let this = self.get_mut();
            if let Some(b) = this.0.take().filter(|b| !b.is_empty()) {
                return Poll::Ready(Some(Ok(Frame::data(b))));
            }
            Poll::Ready(this.1.take().map(|why| Err(fictionet::Error::msg(why))))
        }
    }
    Body::new(Partial(Some(bytes), Some(why)))
}

fn version_of(head: &RequestHead) -> Version {
    match head.version {
        http1::Version::Http10 => Version::HTTP_10,
        http1::Version::Http11 => Version::HTTP_11,
    }
}

fn to_request(head: &RequestHead, version: Version, body: Body) -> Option<Request<Body>> {
    let mut builder = Request::builder()
        .method(head.method.as_bytes())
        .uri(head.target.as_str())
        .version(version);
    let headers = builder.headers_mut()?;
    for h in &head.headers {
        let name = HeaderName::from_bytes(h.name.as_bytes()).ok()?;
        let value = HeaderValue::from_bytes(&h.value).ok()?;
        headers.append(name, value);
    }
    builder.body(body).ok()
}

/// Writes a response head. Returns whether the connection must close
/// after the body. Closing follows the request's `close` flag, the
/// response's `Connection: close` token (except for 101), or an HTTP/1.0
/// body of unknown length.
fn encode(
    out: &mut Vec<u8>,
    version: Version,
    parts: &http::response::Parts,
    policy: &ResponsePolicy,
    close: bool,
) -> bool {
    let status = parts.status;
    let v10 = version == Version::HTTP_10;
    let mut close = close
        || (status != StatusCode::SWITCHING_PROTOCOLS
            && parts.headers.get_all("connection").iter().any(|value| {
                value
                    .as_bytes()
                    .split(|b| *b == b',')
                    .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"))
            }));
    out.extend_from_slice(if v10 { b"HTTP/1.0 " } else { b"HTTP/1.1 " });
    out.extend_from_slice(status.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(status.canonical_reason().unwrap_or("").as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in &parts.headers {
        if matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "connection" | "keep-alive"
        ) {
            continue;
        }
        title_case(out, name.as_str());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some(date) = &policy.date {
        out.extend_from_slice(b"Date: ");
        out.extend_from_slice(date.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    match policy.len {
        Some(n) => out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes()),
        None if policy.bodiless => {}
        None if v10 => close = true,
        None => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
    }
    if status == StatusCode::SWITCHING_PROTOCOLS {
        out.extend_from_slice(b"Connection: upgrade\r\n");
    } else if close && !v10 {
        out.extend_from_slice(b"Connection: close\r\n");
    } else if !close && v10 {
        out.extend_from_slice(b"Connection: keep-alive\r\n");
    }
    out.extend_from_slice(b"\r\n");
    close
}

/// Writes a field name with each word capitalized (`Content-Type`), as
/// Apache, nginx and most other HTTP/1 servers do. The `http` crate keeps
/// names in lowercase, and tools that recognize servers by their replies,
/// such as `nmap -sV`, match `Server:` with its capital.
fn title_case(out: &mut Vec<u8>, name: &str) {
    let mut start = true;
    for b in name.bytes() {
        out.push(if start { b.to_ascii_uppercase() } else { b });
        start = b == b'-';
    }
}

fn write_simple(
    out: &mut Vec<u8>,
    version: Version,
    status: StatusCode,
    date: Option<HeaderValue>,
) {
    let (parts, _) = status_only(status).into_parts();
    let policy = ResponsePolicy::new(&parts, Some(0), false, date);
    encode(out, version, &parts, &policy, true);
}

impl serve::Service for Http1 {
    type Decoder = http1::RequestEvents;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> http1::RequestEvents {
        http1::RequestEvents::with_limits(self.opts.head)
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<Flow, Infallible> {
        let timeout = self
            .first_head_deadline
            .take()
            .map_or(self.opts.header_timeout, |at| {
                at.since_start().saturating_sub(driver.now().since_start())
            });
        driver.set_timer(HEAD, timeout);
        Ok(Flow::Continue)
    }

    fn on_item(
        &mut self,
        item: H1<RequestHead>,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<Flow, Infallible> {
        match item {
            H1::Head(head) => {
                driver.cancel_timer(HEAD);
                driver.set_timer(BODY, self.opts.body_timeout);
                if head.expects_continue() {
                    driver
                        .reply()
                        .extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                self.started = driver.now();
                self.track(&head, driver);
                self.head = Some(head);
                self.body.clear();
                self.too_big = false;
            }
            H1::Body(bytes) => {
                if let Some(tracker) = &mut self.tracker {
                    tracker.body(&bytes);
                }
                if self.body.len() + bytes.len() > self.opts.body {
                    self.too_big = true;
                } else {
                    self.body.extend_from_slice(&bytes);
                }
            }
            H1::Done => return Ok(self.respond(driver)),
        }
        Ok(Flow::Continue)
    }

    fn on_timer(
        &mut self,
        _: Timer,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<Flow, Infallible> {
        let detail = if self.head.is_some() {
            Some("request body timed out")
        } else if !driver.unread().is_empty() {
            Some("request head timed out")
        } else {
            None
        };
        if let Some(detail) = detail {
            driver.emit("http", "error", |_| {
                error_event(driver.conn(), "timeout", detail)
            });
        }
        // The observer still sees the body bytes the decoder buffers.
        if let Some(tracker) = &mut self.tracker {
            let len = driver
                .peek_decoder()
                .pending_body_len(driver.unread().len());
            tracker.body(&driver.unread()[..len]);
        }
        self.finish_receipt(driver, Received::Timeout);
        Ok(Flow::Close)
    }

    fn held(&self) -> usize {
        self.body.capacity()
            + self.head.as_ref().map_or(0, head_held)
            + self.tracker.as_ref().map_or(0, Tracker::held)
    }

    fn on_fail(
        &mut self,
        error: &serve_fail::Fail,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<(), Infallible> {
        if self.head.is_some() {
            let buffered = driver.unread().len();
            let len = driver.peek_decoder().pending_body_len(buffered);
            if let Some(tracker) = &mut self.tracker {
                tracker.body(&driver.unread()[..len]);
                tracker.received(if self.too_big {
                    Received::TooLarge
                } else {
                    Received::CutOff
                });
            }
            // The body was cut off: the handler still sees what came, as a
            // body that ends in an error.
            let mut got = std::mem::take(&mut self.body);
            let room = self.opts.body.saturating_sub(got.len());
            got.extend_from_slice(&driver.unread()[..driver.unread().len().min(room)]);
            let held = got.capacity();
            let body = partial(Bytes::from(got), "the request body was cut off");
            self.dispatch(driver, body, true, held);
            return Ok(());
        }
        if matches!(
            error,
            fictionet::stdlib::codec::Fail::Protocol(http1::Error::Host)
        ) && let Some((head, mut decoder, head_end)) = without_host(driver.unread())
        {
            // The service answers an HTTP/1.1 request with no Host field
            // with `400` and `no_host`, then closes the connection.
            self.started = driver.now();
            self.track(&head, driver);
            if let Some(tracker) = &mut self.tracker {
                let mut unread = &driver.unread()[head_end..];
                let mut received_bytes = 0;
                let received = loop {
                    match decoder.decode(unread, false) {
                        Ok(Step::Item(H1::Body(bytes), n)) => {
                            tracker.body(&bytes);
                            received_bytes += bytes.len();
                            unread = &unread[n..];
                        }
                        Ok(Step::Skip(n)) => unread = &unread[n..],
                        Ok(Step::Item(H1::Done, _)) => break Received::Complete,
                        _ => {
                            let len = decoder.pending_body_len(unread.len());
                            tracker.body(&unread[..len]);
                            received_bytes += len;
                            break Received::CutOff;
                        }
                    }
                };
                self.too_big = received_bytes > self.opts.body;
                tracker.received(if self.too_big {
                    Received::TooLarge
                } else {
                    received
                });
            }
            self.head = Some(head);
            self.dispatch(driver, Body::empty(), true, 0);
            return Ok(());
        }
        driver.emit("http", "error", |_| {
            error_event(driver.conn(), "protocol", fictionet::ErrorChain(error))
        });
        let date = date_header(self.date, driver.now());
        let status = if matches!(
            error,
            fictionet::stdlib::codec::Fail::Protocol(http1::Error::UnsupportedTransferCoding)
        ) {
            StatusCode::NOT_IMPLEMENTED
        } else {
            StatusCode::BAD_REQUEST
        };
        write_simple(driver.reply(), Version::HTTP_11, status, date);
        Ok(())
    }

    fn on_end(
        &mut self,
        end: Ended,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents>,
    ) -> Result<(), Infallible> {
        // The client broke off inside a request head, as by a reset. A head
        // cut off by the end of input fails the decoder and is logged there.
        if let Ended::Conn(e) = end
            && e != ConnError::Broken
            && self.head.is_none()
            && !driver.unread().is_empty()
        {
            driver.emit("http", "error", |_| {
                error_event(
                    driver.conn(),
                    "protocol",
                    format_args!("the connection ended inside a request head: {e}"),
                )
            });
        }
        self.finish_receipt(
            driver,
            if end == Ended::Budget {
                Received::Budget
            } else {
                Received::CutOff
            },
        );
        if end == Ended::Conn(ConnError::Broken) {
            driver.emit("http", "error", |_| {
                error_event(driver.conn(), "transport", "a TLS record did not decrypt")
            });
        }
        Ok(())
    }
}

mod serve_fail {
    pub type Fail = fictionet::stdlib::codec::Fail<fictionet::stdlib::protocols::http1::Error>;
}

/// A handler's response, on its way.
type Making = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

/// A response being made or streamed, as deferred work of a connection.
///
/// Its event says what the connection took: each piece counts in `sent`
/// once the driver wrote all of it, and the event is made when the last
/// piece is written, or when the connection ends first.
struct Streaming {
    work: Option<Later>,
    making: Option<Making>,
    body: Option<Body>,
    rest: Bytes,
    rest_held: usize,
    request_held: usize,
    response: Option<Response<Body>>,
    version: Version,
    head_only: bool,
    close: bool,
    chunked: bool,
    tracker: Tracker,
    extra: Option<Fields>,
    status: Option<StatusCode>,
    /// Body bytes the connection took.
    body_sent: u64,
    /// Bytes returned to the driver, and the body bytes in the last piece,
    /// which count once the driver has written that far.
    returned: u64,
    in_flight: u64,
    finished: bool,
    /// The world's date at the start of the run, and when the request was
    /// answered, for the `Date` header.
    date: Option<SystemTime>,
    asked: Instant,
}

impl Streaming {
    fn new(
        work: Option<Later>,
        response: Option<Response<Body>>,
        version: Version,
        head_only: bool,
        close: bool,
        tracker: Tracker,
    ) -> Streaming {
        Streaming {
            work,
            making: None,
            body: None,
            rest: Bytes::new(),
            rest_held: 0,
            request_held: 0,
            response,
            version,
            head_only,
            close,
            chunked: false,
            tracker,
            extra: None,
            status: None,
            body_sent: 0,
            returned: 0,
            in_flight: 0,
            finished: false,
            date: None,
            asked: Instant::ZERO,
        }
    }

    fn holding_request(mut self, held: usize) -> Self {
        if self.work.is_some() {
            self.request_held = held;
        }
        self
    }

    fn take_piece(&mut self) -> Bytes {
        let piece = self.rest.split_to(self.rest.len().min(PIECE));
        if self.rest.is_empty() {
            self.rest = Bytes::new();
            self.rest_held = 0;
        }
        piece
    }

    /// Dates the response from `date`, the world's date at the start of
    /// the run, when it is made; `asked` is the time without a [`Cx`].
    fn dated(self, date: Option<SystemTime>, asked: Instant) -> Streaming {
        Streaming {
            date,
            asked,
            ..self
        }
    }

    /// Counts the last piece's body bytes once the driver wrote it all.
    fn confirm(&mut self, driver: &PendingDriver<'_>) {
        if driver.written() >= self.returned {
            self.body_sent += std::mem::take(&mut self.in_flight);
        }
    }

    /// Hands the driver `bytes`, of which `body` are body bytes.
    fn piece(&mut self, bytes: Vec<u8>, body: usize) -> Poll<Option<Result<Vec<u8>, Error>>> {
        self.returned += bytes.len() as u64;
        self.in_flight = body as u64;
        Poll::Ready(Some(Ok(bytes)))
    }

    fn end(&mut self, driver: &mut PendingDriver<'_>, complete: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(e) =
            self.tracker
                .finish(|| self.extra.take(), self.status, self.body_sent, complete)
        {
            driver.emit("http", "request", |_| e);
        }
    }

    /// `piece` as it goes on the wire: a chunk, when chunked.
    fn frame(&self, piece: &[u8], out: &mut Vec<u8>) {
        if self.chunked {
            out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            out.extend_from_slice(piece);
            out.extend_from_slice(b"\r\n");
        } else {
            out.extend_from_slice(piece);
        }
    }
}

impl Pending for Streaming {
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, Error>>> {
        // The driver polls again only once the last piece is written.
        self.confirm(driver);
        loop {
            if let Some(work) = self.work.take() {
                self.making = Some(match driver.fcx() {
                    Some(fcx) => work(fcx.clone()),
                    None => Box::pin(std::future::ready(Err(fictionet::Error::msg(
                        "this answer needs a Cx: give the harness one with Harness::with_fcx",
                    )))),
                });
            }
            if let Some(making) = &mut self.making {
                let response = match making.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(r)) => r,
                    Poll::Ready(Err(e)) => {
                        error_response(&e, driver.event_enabled("http", "request"))
                    }
                };
                self.making = None;
                self.request_held = 0;
                self.response = Some(response);
            }
            if let Some(response) = self.response.take() {
                let (mut parts, body) = response.into_parts();
                let now = driver.fcx().map_or(self.asked, Cx::now);
                let policy = ResponsePolicy::new(
                    &parts,
                    body.size_hint().exact(),
                    self.head_only,
                    date_header(self.date, now),
                );
                let mut head = Vec::new();
                self.close = encode(&mut head, self.version, &parts, &policy, self.close);
                if self.close {
                    // The request, the handler's `Connection: close`, or a
                    // body that ends with the connection closes it.
                    driver.close();
                }
                self.status = Some(parts.status);
                self.extra = parts.extensions.remove::<Fields>();
                self.chunked =
                    !policy.bodiless && policy.len.is_none() && self.version != Version::HTTP_10;
                if policy.bodiless {
                    return self.piece(head, 0);
                }
                // A body held in full goes out with the head, a piece at
                // a time.
                match body.0 {
                    Inner::Full(bytes) => {
                        self.rest = bytes.unwrap_or_default();
                        self.rest_held = self.rest.len();
                    }
                    stream => self.body = Some(Body(stream)),
                }
                // A streamed body has nothing held yet, and an empty chunk
                // would end it before it starts.
                let piece = self.take_piece();
                if !piece.is_empty() {
                    self.frame(&piece, &mut head);
                }
                return self.piece(head, piece.len());
            }
            if !self.rest.is_empty() {
                let piece = self.take_piece();
                let mut out = Vec::with_capacity(piece.len() + 12);
                self.frame(&piece, &mut out);
                return self.piece(out, piece.len());
            }
            let Some(body) = &mut self.body else {
                self.end(driver, true);
                return Poll::Ready(None);
            };
            match Pin::new(body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.body = None;
                    if self.chunked {
                        self.chunked = false;
                        return self.piece(b"0\r\n\r\n".to_vec(), 0);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.body = None;
                    self.end(driver, false);
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        self.rest_held = data.len();
                        self.rest = data;
                    }
                }
            }
        }
    }

    fn cancel(&mut self, driver: &mut PendingDriver<'_>) {
        self.confirm(driver);
        if self.status.is_none() {
            self.extra = None;
        }
        self.end(driver, false);
    }

    fn held(&self) -> usize {
        let response = self.response.as_ref().map_or(0, |r| r.body().full_len());
        let body = self.body.as_ref().map_or(0, Body::full_len);
        self.request_held + self.tracker.held() + self.rest_held + response + body
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use fictionet::events::ConnInfo;
    use fictionet::sync::Mutex;

    #[test]
    fn response_suffix_keeps_the_original_charge() {
        use fictionet::stdlib::codec::{Ending, Lines};
        use fictionet::stdlib::services::serve::{Harness, Service};
        struct Checked {
            inner: Streaming,
            held: Arc<Mutex<Vec<usize>>>,
        }
        impl Pending for Checked {
            fn poll_next(
                &mut self,
                driver: &mut PendingDriver<'_>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Vec<u8>, Error>>> {
                let result = self.inner.poll_next(driver, cx);
                self.held.lock().push(self.inner.held());
                result
            }
        }
        struct Start(Option<Checked>);
        impl Service for Start {
            type Decoder = Lines;
            type State = ();
            type Error = Infallible;
            fn decoder(&self) -> Lines {
                Lines::new(16, Ending::LfOrCrlf)
            }
            fn on_item(
                &mut self,
                _: <Lines as fictionet::stdlib::codec::Decode>::Item,
                _: &(),
                _: &mut Driver<'_, Lines>,
            ) -> Result<Flow, Infallible> {
                Ok(Flow::Close)
            }
            fn on_open(
                &mut self,
                _: &(),
                driver: &mut Driver<'_, Lines>,
            ) -> Result<Flow, Infallible> {
                driver.defer(self.0.take().unwrap());
                Ok(Flow::Close)
            }
        }
        let held = Arc::new(Mutex::new(Vec::new()));
        let tracker = Tracker::new(
            &Request::new(Body::empty()),
            &ConnInfo::default(),
            Instant::ZERO,
        );
        let metadata = tracker.held();
        let inner = Streaming::new(
            None,
            Some(Response::new(Body::from(vec![b'x'; 3 * PIECE]))),
            Version::HTTP_11,
            false,
            true,
            tracker,
        );
        let mut harness = Harness::new(
            fictionet::Seed::from_u64(0),
            Start(Some(Checked {
                inner,
                held: held.clone(),
            })),
            (),
        );
        harness.open().unwrap();
        assert_eq!(
            &held.lock()[..3],
            &[3 * PIECE + metadata, 3 * PIECE + metadata, metadata]
        );
        assert_eq!(held.lock().last(), Some(&0));
    }
}
