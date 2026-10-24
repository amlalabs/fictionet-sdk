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

use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::protocols::http1::{self, Event as H1, RequestHead};
use fictionet::stdlib::services::serve::{
    self, Driver, Flow, Pending, PendingDriver,
};
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::body::Inner;
use super::handlers::status_only;
use super::response::{
    ResponsePolicy, error_response, head_held, request_held,
};
use super::sites::no_host;
use super::{
    Body, Exchange, Handler, Later, Limits, PIECE, Reply, UpgradeHandler,
    date_header,
};

// ---------------------------------------------------------------------------
// HTTP/1 as a service

/// HTTP/1 request deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer {
    /// Waiting for the request head.
    Head,
    /// Waiting for the request body.
    Body,
}

/// HTTP/1.0 and 1.1 for one connection, answering with a [`Handler`].
pub struct Http1 {
    handler: Arc<dyn Handler>,
    opts: Limits,
    /// The world's date at the start of the run, for `Date` headers.
    pub(super) date: Option<SystemTime>,
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
            opts,
            date: None,
            upgrade: None,
            head: None,
            body: Vec::new(),
            too_big: false,
            started: Instant::ZERO,
            first_head_deadline: None,
        }
    }

    /// Sends a `Date` header with each response: `start`, the world's date
    /// and time at the start of the run, plus the run's clock. See
    /// [Dates](super#dates).
    pub fn date(mut self, start: SystemTime) -> Http1 {
        self.date = Some(start);
        self
    }


    fn respond(&mut self, driver: &mut Driver<'_, http1::RequestEvents, Timer>) -> Flow {
        let held = self.body.capacity();
        let body = Body::from(std::mem::take(&mut self.body));
        let close = self.too_big;

        self.dispatch(driver, body, close, held)
    }

    /// Answers the request whose head is pending, with `body`.
    /// `close` closes the connection after the answer.
    fn dispatch(
        &mut self,
        driver: &mut Driver<'_, http1::RequestEvents, Timer>,
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

        let head_only = request.method() == Method::HEAD;
        let held = held + request_held(&request);
        let now = driver.now();
        let conn = driver.conn().clone();
        // RFC 9112 section 3.2: an HTTP/1.1 request without Host gets 400
        // from the service, unless its body is too large. The decoder
        // refuses such a head, so only `on_fail` brings one here.
        let lacks_host = version == Version::HTTP_11 && !request.headers().contains_key(HOST);
        let reply = if self.too_big {
            Reply::Now(status_only(StatusCode::PAYLOAD_TOO_LARGE))
        } else if lacks_host {
            Reply::Now(no_host())
        } else if request.headers().contains_key(http::header::UPGRADE)
            && matches!(&request.body().0, Inner::Stream(_))
        {
            Reply::Now(status_only(StatusCode::BAD_REQUEST))
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
        let (work, response) = match reply {
            Reply::Now(response) => (None, Some(response)),
            Reply::Later(work) => (Some(work), None),

        };
        driver.defer(
            Streaming::new(work, response, version, head_only, close)
                .dated(self.date, now)
                .holding_request(held),
        );
        if self.upgrade.is_some() {
            driver.cancel_timer(Timer::Body);
            Flow::Upgrade(serve::Upgrade::Handoff)
        } else {
            self.after(driver, close)
        }
    }

    fn after(&mut self, driver: &mut Driver<'_, http1::RequestEvents, Timer>, close: bool) -> Flow {
        driver.cancel_timer(Timer::Body);
        if close {
            return Flow::Close;
        }
        driver.set_timer(Timer::Head, self.opts.header_timeout);
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
    // Preserve the request as it came, without the field added.
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
    type Timer = Timer;
    type Decoder = http1::RequestEvents;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> http1::RequestEvents {
        http1::RequestEvents::with_limits(self.opts.head)
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents, Timer>,
    ) -> Result<Flow, Infallible> {
        let timeout = self
            .first_head_deadline
            .take()
            .map_or(self.opts.header_timeout, |at| {
                at.since_start().saturating_sub(driver.now().since_start())
            });
        driver.set_timer(Timer::Head, timeout);
        Ok(Flow::Continue)
    }

    fn on_item(
        &mut self,
        item: H1<RequestHead>,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents, Timer>,
    ) -> Result<Flow, Infallible> {
        match item {
            H1::Head(head) => {
                driver.cancel_timer(Timer::Head);
                driver.set_timer(Timer::Body, self.opts.body_timeout);
                if head.expects_continue() {
                    driver
                        .reply()
                        .extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                self.started = driver.now();
                self.head = Some(head);
                self.body.clear();
                self.too_big = false;
            }
            H1::Body(bytes) => {

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
        _driver: &mut Driver<'_, http1::RequestEvents, Timer>,
    ) -> Result<Flow, Infallible> {
        self.head = None;
        Ok(Flow::Close)
    }

    fn held(&self) -> usize {
        self.body.capacity()
            + self.head.as_ref().map_or(0, head_held)
    }

    fn on_fail(
        &mut self,
        error: &serve_fail::Fail,
        _: &(),
        driver: &mut Driver<'_, http1::RequestEvents, Timer>,
    ) -> Result<(), Infallible> {
        if self.head.is_some() {

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

                let mut unread = &driver.unread()[head_end..];
                let mut received_bytes = 0;
                loop {
                    match decoder.decode(unread, false) {
                        Ok(Step::Item(H1::Body(bytes), n)) => {

                            received_bytes += bytes.len();
                            unread = &unread[n..];
                        }
                        Ok(Step::Skip(n)) => unread = &unread[n..],
                        Ok(Step::Item(H1::Done, _)) => break,
                        _ => {
                            let len = decoder.pending_body_len(unread.len());

                            received_bytes += len;
                            break;
                        }
                    }
                };
                self.too_big = received_bytes > self.opts.body;


            self.head = Some(head);
            self.dispatch(driver, Body::empty(), true, 0);
            return Ok(());
        }

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

}

mod serve_fail {
    pub type Fail = fictionet::stdlib::codec::Fail<fictionet::stdlib::protocols::http1::Error>;
}

/// A handler's response, on its way.
type Making = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

/// A response being made or streamed, as deferred work of a connection.
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
    /// Body bytes the connection took.
    /// Bytes returned to the driver, and the body bytes in the last piece,
    /// which count once the driver has written that far.
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


    /// Hands the driver `bytes`, of which `body` are body bytes.
    fn piece(&mut self, bytes: Vec<u8>, _body: usize) -> Poll<Option<Result<Vec<u8>, Error>>> {
        Poll::Ready(Some(Ok(bytes)))
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
                        error_response(&e)
                    }
                };
                self.making = None;
                self.request_held = 0;
                self.response = Some(response);
            }
            if let Some(response) = self.response.take() {
                let (parts, body) =
                    response.into_parts();
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


    fn held(&self) -> usize {
        let response = self.response.as_ref().map_or(0, |r| r.body().full_len());
        let body = self.body.as_ref().map_or(0, Body::full_len);
        self.request_held + self.rest_held + response + body
    }
}

#[cfg(test)]
mod router_tests {
    use super::*;
    
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
    type Timer = ();
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
        let inner = Streaming::new(
            None,
            Some(Response::new(Body::from(vec![b'x'; 3 * PIECE]))),
            Version::HTTP_11,
            false,
            true,
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
            &[3 * PIECE, 3 * PIECE, 0]
        );
        assert_eq!(held.lock().last(), Some(&0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use fictionet::stdlib::services::serve::Harness;
    use fictionet::sync::Mutex;

    /// Records the data frames of each request body until it ends or fails.
    struct Frames(Arc<Mutex<Vec<u8>>>);

    impl Handler for Frames {
        fn call(&self, request: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let mut body = request.into_body();
            let mut cx = Context::from_waker(std::task::Waker::noop());
            while let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) {
                if let Ok(data) = frame.into_data() {
                    self.0.lock().extend_from_slice(&data);
                }
            }
            Reply::Now(Response::new(Body::empty()))
        }
    }

    #[test]
    fn a_failed_chunked_body_reaches_the_handler_without_its_framing() {
        for (rest, sent) in [
            // A chunk size that is not hex.
            (&b"3\r\nabc\r\nzz\r\n"[..], &b"abc"[..]),
            // A chunk extension, then a whole second request.
            (
                b"3\r\nabc\r\n0;x\r\n\r\nGET /admin HTTP/1.1\r\nHost: a\r\n\r\n",
                b"abc",
            ),
        ] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let mut h = Harness::new(
                fictionet::Seed::from_u64(0),
                Http1::new(Frames(seen.clone())),
                (),
            );
            let mut request =
                b"POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            request.extend_from_slice(rest);
            let _ = h.push(&request);
            assert_eq!(
                String::from_utf8_lossy(&seen.lock()),
                String::from_utf8_lossy(sent),
                "{:?}",
                String::from_utf8_lossy(rest)
            );
        }
    }

    /// A body that waits until `open` is set, then sends `done`.
    struct Gate(Arc<AtomicBool>, bool);

    impl http_body::Body for Gate {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            if !self.0.load(Ordering::Relaxed) {
                return Poll::Pending;
            }
            if self.1 {
                return Poll::Ready(None);
            }
            self.1 = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"done")))))
        }
    }

    struct Slow(Arc<AtomicBool>);

    impl Handler for Slow {
        fn call(&self, request: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let body = if request.uri().path() == "/slow" {
                Body::new(Gate(self.0.clone(), false))
            } else {
                Body::from("next")
            };
            Reply::Now(Response::new(body))
        }
    }

    #[test]
    fn a_pipelined_request_survives_a_response_slower_than_the_head_timeout() {
        let open = Arc::new(AtomicBool::new(false));
        let mut h = Harness::new(
            fictionet::Seed::from_u64(0),
            Http1::new(Slow(open.clone())),
            (),
        );
        h.push(b"GET /slow HTTP/1.1\r\nHost: a\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n")
            .unwrap();
        // The first response takes longer than the 30-second head timeout,
        // while the second request already waits in the buffer.
        h.advance(Duration::from_secs(31)).unwrap();
        open.store(true, Ordering::Relaxed);
        h.poll().unwrap();
        let out = String::from_utf8_lossy(h.output()).into_owned();
        assert_eq!(out.matches("HTTP/1.1 200 OK\r\n").count(), 2, "{out:?}");
        assert!(out.ends_with("\r\n\r\nnext"), "{out:?}");
        assert!(!h.closed());
    }

    struct Hello;

    impl Handler for Hello {
        fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            Reply::Now(Response::new(Body::from("hello")))
        }
    }

    #[test]
    fn a_successful_connect_answer_has_no_body_framing() {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Hello), ());
        let _ = h.push(b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n");
        // After a 2xx to CONNECT every byte is tunnel data, so the answer
        // must be a whole response for CONNECT with nothing after its head.
        let out = h.output().to_vec();
        assert_eq!(
            http1::Response::parse_for(&out, "CONNECT").map(|r| r.head.status),
            Ok(200),
            "{:?}",
            String::from_utf8_lossy(&out)
        );
    }
}
