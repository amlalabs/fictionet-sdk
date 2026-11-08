use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Version};
use http_body::{Body as _, Frame};

use fictionet::stdlib::codec::{Fail, Stream};
use fictionet::stdlib::layer::{
    Admit, ByteStream, Charge, Chunk, CommandOf, Env, Handoff, Handover, Job, Layer, StreamCommand,
    StreamEvent, Switch, Timers, Top, Tunnel,
};
use fictionet::stdlib::protocols::http1::{self, Event as H1, RequestError, RequestHead};
use fictionet::stdlib::services::serve::ConnInfo;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::body::Inner;
use super::handlers::status_only;
use super::response::{Asked, ResponsePolicy, error_response, head_held, request_held};
use super::sites::no_host;
use super::{
    Body, Delivery, Exchange, Handler, Later, Limits, PIECE, Received, Reply, Reset,
    UpgradeHandler, date_header,
};

// ---------------------------------------------------------------------------
// HTTP/1 as a layer

/// HTTP/1 request deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer {
    /// Waiting for the request head.
    Head,
    /// Waiting for the request body.
    Body,
}

/// What [`Http1`] reports about a connection.
#[derive(Debug)]
pub enum Report {
    /// The request bytes could not be read as HTTP/1. The client was
    /// answered when it could be, and the connection closes.
    Failed(Fail<RequestError>),
    /// A handler's work or a response body failed with this error, or a
    /// handler asked for no answer at all ([`Reset`]). The connection closes.
    Work(Error),
    /// The connection is closing, and why.
    Closing(Closing),
}

/// Why an HTTP/1 connection closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closing {
    /// An exchange said so: the request's or the handler's
    /// `Connection: close`, HTTP/1.0, a body that ends with the
    /// connection, or a CONNECT that nothing took over.
    Done,
    /// The client sent everything, and every request was answered.
    PeerEnded,
    /// The request bytes could not be read.
    Failed,
    /// The request's head or body took longer than its deadline.
    Timeout(Timer),
    /// The connection held more than its budget allows.
    Budget,
    /// A handler's work or a response body failed ([`Report::Work`]).
    Work,
    /// The connection was reset.
    Reset,
}

/// What runs on an HTTP/1 connection once HTTP is over: the code a
/// response handed the connection to with an [`UpgradeHandler`].
pub enum Next {
    /// A `101 Switching Protocols` answer to an upgrade, such as to
    /// WebSocket.
    Upgrade(UpgradeHandler),
    /// A 2xx answer to CONNECT: a tunnel.
    Connect(UpgradeHandler),
}

impl From<Next> for Tunnel {
    fn from(next: Next) -> Tunnel {
        let (Next::Upgrade(handler) | Next::Connect(handler)) = next;
        Tunnel::new(move |fcx, conn| handler.run(fcx, conn))
    }
}

/// Where a connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Nothing has happened yet: the connection is not yet charged.
    Opening,
    /// Reading requests.
    Reading,
    /// Answering the request read last.
    Answering,
    /// HTTP is over and what comes next is ready to take over.
    Switching,
    /// Writing what is left before the end.
    Closing,
    /// Ended, handed over, or reset.
    Closed,
}

/// HTTP/1.0 and 1.1 for one connection, answering with a [`Handler`]: a
/// [`Layer`] over an ordered byte stream, with nothing above it.
///
/// It reads one request at a time and answers it before it reads the
/// next; requests pipelined behind it wait in its input buffer, and input
/// past that buffer waits below. A handler's async answer and each frame of
/// a streamed body are its [`Work`], which whatever runs it polls. Each
/// piece of a response is handed down once the one before it was written,
/// so delivery is counted in written pieces.
///
/// Everything it holds is charged to the connection's budget before it
/// grows: its input buffer, the request head and body, a response's held
/// body and metadata, and each piece of output until it is written. Past
/// the budget the connection closes with nothing more written.
///
/// A response that hands the connection on with an [`UpgradeHandler`] (a
/// `101`, or a 2xx to CONNECT) ends HTTP: [`upgradable`](Self::upgradable)
/// runs what comes next, through [`Switch`], with the bytes the client sent
/// past the request.
pub struct Http1 {
    pub(super) observe: Option<super::Observe>,
    handler: Arc<dyn Handler>,
    opts: Limits,
    /// The world's date at the start of the run, for `Date` headers.
    pub(super) date: Option<SystemTime>,
    conn: ConnInfo,
    pub(super) first_head_deadline: Option<Instant>,
    stream: Stream<http1::RequestEvents>,
    /// Bytes past the end of HTTP, kept for what comes next.
    after: VecDeque<Chunk>,
    after_len: usize,
    charge: Option<Charge>,
    phase: Phase,
    timers: Timers<Timer>,
    head: Option<RequestHead>,
    body: Vec<u8>,
    too_big: bool,
    responding: Option<Responding>,
    out: VecDeque<StreamCommand>,
    /// Bytes put in `out`, handed below, and written, since the start.
    queued: u64,
    handed: u64,
    written: u64,
    work: Option<Work>,
    /// Numbers each piece of work, so a result for one that no longer
    /// matters is ignored.
    generation: u64,
    peer_ended: bool,
    next: Option<Next>,
    /// What the successor gets, once HTTP is over.
    leftover: Vec<StreamEvent>,
}

impl Http1 {
    /// Answers with `handler`, with default options.
    pub fn new(handler: impl Handler) -> Http1 {
        Http1::with(Arc::new(handler), Limits::default())
    }

    /// Answers with `handler` and `opts`.
    pub fn with(handler: Arc<dyn Handler>, opts: Limits) -> Http1 {
        Http1 {
            observe: None,
            handler,
            opts,
            date: None,
            conn: ConnInfo::default(),
            first_head_deadline: None,
            stream: Stream::new(http1::RequestEvents::with_limits(opts.head)),
            after: VecDeque::new(),
            after_len: 0,
            charge: None,
            phase: Phase::Opening,
            timers: Timers::new(),
            head: None,
            body: Vec::new(),
            too_big: false,
            responding: None,
            out: VecDeque::new(),
            queued: 0,
            handed: 0,
            written: 0,
            work: None,
            generation: 0,
            peer_ended: false,
            next: None,
            leftover: Vec::new(),
        }
    }

    /// Sends a `Date` header with each response: `start`, the world's date
    /// and time at the start of the run, plus the run's clock. See
    /// [Dates](super#dates).
    pub fn date(mut self, start: SystemTime) -> Http1 {
        self.date = Some(start);
        self
    }

    /// Receives response completion and cancellation observations.
    pub fn observe(mut self, observe: super::Observe) -> Self {
        self.observe = Some(observe);
        self
    }

    /// Says which connection this is: handlers find it in each request's
    /// extensions and in their [`Exchange`].
    pub fn conn(mut self, conn: ConnInfo) -> Self {
        self.conn = conn;
        self
    }

    /// This connection, with what a response hands it on to running after
    /// HTTP.
    pub fn upgradable(self) -> Switch<Http1, Tunnel> {
        Switch::new(self)
    }

    /// The bytes held, as charged to the budget. Output carries its own
    /// charge.
    fn holding(&self) -> usize {
        self.stream
            .limit()
            .max(self.stream.allocated())
            .saturating_add(self.stream.held())
            .saturating_add(self.after_len)
            .saturating_add(self.head.as_ref().map_or(0, head_held))
            .saturating_add(self.body.capacity())
            .saturating_add(self.responding.as_ref().map_or(0, Responding::held))
    }

    /// Charges what is held and `more`, if it fits.
    fn fits(&mut self, more: usize) -> bool {
        let need = self.holding().saturating_add(more);
        self.charge.as_mut().is_none_or(|charge| charge.set(need))
    }

    /// Takes the first charge and starts waiting for the first head.
    fn open(&mut self, env: &mut Env<'_, Report>) {
        self.phase = Phase::Reading;
        match env.budget().charge(self.holding()) {
            Some(charge) => self.charge = Some(charge),
            None => return self.over_budget(env),
        }
        let at = self
            .first_head_deadline
            .take()
            .unwrap_or(env.now() + self.opts.header_timeout);
        self.timers.set(Timer::Head, at);
    }

    /// Queues `bytes` to write, charged to the budget. Returns whether
    /// they fit.
    fn push_out(&mut self, env: &mut Env<'_, Report>, bytes: Vec<u8>) -> bool {
        let Some(charge) = env.budget().charge(bytes.len()) else {
            return false;
        };
        self.queued += bytes.len() as u64;
        self.out
            .push_back(StreamCommand::Write(Chunk::with_charge(bytes, charge)));
        true
    }

    /// Whether everything queued has been handed below and written.
    fn all_written(&self) -> bool {
        self.out.is_empty() && self.written >= self.handed
    }

    /// Starts closing: what is queued is written, then the direction ends.
    fn close(&mut self, env: &mut Env<'_, Report>, why: Closing) {
        if matches!(self.phase, Phase::Closing | Phase::Closed) {
            return;
        }
        env.report(Report::Closing(why));
        self.timers = Timers::new();
        self.head = None;
        self.body = Vec::new();
        self.responding = None;
        self.work = None;
        self.generation += 1;
        self.next = None;
        self.phase = Phase::Closing;
        self.out.push_back(StreamCommand::End);
        // What is left, such as the input buffer, still counts.
        let need = self.holding();
        if let Some(charge) = &mut self.charge {
            charge.set(need.min(charge.bytes()));
        }
    }

    /// The connection holds more than its budget allows: nothing more is
    /// written, and it closes.
    fn over_budget(&mut self, env: &mut Env<'_, Report>) {
        self.out.clear();
        self.close(env, Closing::Budget);
    }

    /// Reads one item of the request, if one is there.
    fn read(&mut self, env: &mut Env<'_, Report>) -> bool {
        match self.stream.next() {
            None if self.stream.is_done() => {
                let why = if self.peer_ended
                    && self.stream.unread().is_empty()
                    && self.after.is_empty()
                {
                    Closing::PeerEnded
                } else {
                    Closing::Done
                };
                self.close(env, why);
                true
            }
            None => false,
            Some(Ok(H1::Head(head))) => {
                self.timers.cancel(&Timer::Head);
                self.timers
                    .set(Timer::Body, env.now() + self.opts.body_timeout);
                if head.expects_continue()
                    && !self.push_out(env, b"HTTP/1.1 100 Continue\r\n\r\n".to_vec())
                {
                    self.over_budget(env);
                    return true;
                }
                if !self.fits(head_held(&head)) {
                    self.over_budget(env);
                    return true;
                }
                self.head = Some(head);
                self.body = Vec::new();
                self.too_big = false;
                true
            }
            Some(Ok(H1::Body(bytes))) => {
                let need = self.body.len() + bytes.len();
                if need > self.opts.body {
                    self.too_big = true;
                    return true;
                }
                if need > self.body.capacity() {
                    // Grow as a vector does, charging the whole growth first.
                    let cap = need.max(self.body.capacity() * 2).min(self.opts.body);
                    if !self.fits(cap - self.body.capacity()) {
                        self.over_budget(env);
                        return true;
                    }
                    self.body.reserve_exact(cap - self.body.len());
                }
                self.body.extend_from_slice(&bytes);
                true
            }
            Some(Ok(H1::Done)) => {
                let held = self.body.capacity();
                let body = Body::from(std::mem::take(&mut self.body));
                let close = self.too_big;
                self.dispatch(env, body, close, held, Closing::Done);
                true
            }
            Some(Err(fail)) => {
                self.fail(env, fail);
                true
            }
        }
    }

    /// Answers the request whose head is pending, with `body`. `close`
    /// closes the connection after the answer, for the reason `then`.
    fn dispatch(
        &mut self,
        env: &mut Env<'_, Report>,
        body: Body,
        close: bool,
        held: usize,
        then: Closing,
    ) {
        let Some(head) = self.head.take() else {
            return self.close(env, Closing::Done);
        };
        let version = version_of(&head);
        let keep_alive = !close && head.keep_alive().unwrap_or(false) && head.method != "CONNECT";
        let Some(mut request) = to_request(&head, version, body) else {
            let date = date_header(self.date, env.now());
            let mut out = Vec::new();
            write_simple(&mut out, version, StatusCode::BAD_REQUEST, date);
            if !self.push_out(env, out) {
                return self.over_budget(env);
            }
            return self.close(env, Closing::Failed);
        };
        request.extensions_mut().insert(self.conn.clone());

        let wants = Asked::of(request.method());
        let held = held + request_held(&request);
        let now = env.now();
        // RFC 9112 section 3.2: an HTTP/1.1 request without Host gets 400
        // from the service, unless its body is too large. The decoder
        // refuses such a head, so only a failure brings one here.
        let lacks_host = version == Version::HTTP_11 && !request.headers().contains_key(HOST);
        let received = if self.too_big {
            Received::TooLarge
        } else if close {
            Received::CutOff
        } else {
            Received::Complete
        };
        let delivery = Delivery::new(&self.observe, &request, &self.conn, now, received);
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
                .call(request, &mut Exchange::new(now, env.entropy(), &self.conn))
        };
        let (stage, request_held) = match reply {
            Reply::Now(response) => (Stage::Made(response), 0),
            Reply::Later(later) => {
                self.generation += 1;
                self.work = Some(Work {
                    generation: self.generation,
                    op: Op::Make {
                        later: Some(later),
                        making: None,
                    },
                });
                (Stage::Making, held)
            }
        };
        self.timers.cancel(&Timer::Body);
        self.responding = Some(Responding {
            delivery,
            version,
            wants,
            close: !keep_alive || lacks_host,
            then,
            chunked: false,
            request_held,
            stage,
            rest: Bytes::new(),
            rest_held: 0,
            base: self.queued,
        });
        self.phase = Phase::Answering;
    }

    /// The request bytes failed to decode with `fail`.
    fn fail(&mut self, env: &mut Env<'_, Report>, fail: Fail<RequestError>) {
        if self.head.is_some() {
            // The body was cut off: the handler still sees what came, as a
            // body that ends in an error. Of the unread bytes, only body
            // data counts: chunk framing and later requests are not body.
            let mut got = std::mem::take(&mut self.body);
            let room = self.opts.body.saturating_sub(got.len());
            let buffered = self.stream.unread().len();
            let pending = self.stream.decoder().pending_body_len(buffered);
            got.extend_from_slice(&self.stream.unread()[..pending.min(room)]);
            let held = got.capacity();
            let body = partial(Bytes::from(got), "the request body was cut off");
            self.dispatch(env, body, true, held, Closing::Failed);
            env.report(Report::Failed(fail));
            return;
        }
        if let Fail::Protocol(RequestError::Rejected(rejected)) = &fail
            && rejected.error == http1::Error::Host
            && rejected.framing.is_ok()
            && !rejected
                .head
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("host"))
        {
            self.too_big = rejected.received_body_bytes > self.opts.body;
            self.head = Some(rejected.head.clone());
            self.dispatch(env, Body::empty(), true, 0, Closing::Failed);
            env.report(Report::Failed(fail));
            return;
        }
        let date = date_header(self.date, env.now());
        let status = if matches!(
            &fail,
            Fail::Protocol(error) if error.reason() == http1::Error::UnsupportedTransferCoding
        ) {
            StatusCode::NOT_IMPLEMENTED
        } else {
            StatusCode::BAD_REQUEST
        };
        env.report(Report::Failed(fail));
        let mut out = Vec::new();
        write_simple(&mut out, Version::HTTP_11, status, date);
        if !self.push_out(env, out) {
            return self.over_budget(env);
        }
        self.close(env, Closing::Failed);
    }

    /// Moves the response on by one piece, once the last one is written.
    fn respond(&mut self, env: &mut Env<'_, Report>) -> bool {
        if !self.all_written() {
            return false;
        }
        let Some(mut r) = self.responding.take() else {
            return false;
        };
        if let Some(delivery) = &mut r.delivery {
            delivery.update(self.written.saturating_sub(r.base));
        }
        match std::mem::replace(&mut r.stage, Stage::Body(None)) {
            stage @ (Stage::Making | Stage::Polling) => {
                r.stage = stage;
                self.responding = Some(r);
                false
            }
            Stage::Made(response) => {
                self.start(env, r, response);
                true
            }
            body if !r.rest.is_empty() => {
                r.stage = body;
                let piece = r.take_piece();
                let mut out = Vec::with_capacity(piece.len() + 12);
                r.frame(&piece, &mut out);
                self.piece(env, r, out, piece.len());
                true
            }
            Stage::Body(Some(body)) => {
                self.generation += 1;
                self.work = Some(Work {
                    generation: self.generation,
                    op: Op::Frame(Some(body)),
                });
                r.stage = Stage::Polling;
                self.responding = Some(r);
                true
            }
            Stage::Body(None) if r.chunked => {
                r.chunked = false;
                self.piece(env, r, b"0\r\n\r\n".to_vec(), 0);
                true
            }
            Stage::Body(None) => {
                self.finish(env, r);
                true
            }
        }
    }

    /// Writes the head of `response`, with the first piece of a body held
    /// in full.
    fn start(&mut self, env: &mut Env<'_, Report>, mut r: Responding, response: Response<Body>) {
        let (parts, body) = response.into_parts();
        if let Some(delivery) = &mut r.delivery {
            delivery.response(&parts);
        }
        let hands_on = parts.status == StatusCode::SWITCHING_PROTOCOLS
            || (r.wants == Asked::Tunnel && parts.status.is_success());
        if hands_on && let Some(handler) = parts.extensions.get::<UpgradeHandler>() {
            self.next = Some(if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                Next::Upgrade(handler.clone())
            } else {
                Next::Connect(handler.clone())
            });
            r.close = false;
        }
        let policy = ResponsePolicy::new(
            &parts,
            body.size_hint().exact(),
            r.wants,
            date_header(self.date, env.now()),
        );
        let mut head = Vec::new();
        r.close = encode(&mut head, r.version, &parts, &policy, r.close);
        r.chunked = !policy.bodiless && policy.len.is_none() && r.version != Version::HTTP_10;
        if policy.bodiless {
            return self.piece(env, r, head, 0);
        }
        // A body held in full goes out with the head, a piece at a time.
        match body.0 {
            Inner::Full(bytes) => {
                r.rest = bytes.unwrap_or_default();
                r.rest_held = r.rest.len();
            }
            stream => r.stage = Stage::Body(Some(Body(stream))),
        }
        // A streamed body has nothing held yet, and an empty chunk would
        // end it before it starts.
        let piece = r.take_piece();
        if !piece.is_empty() {
            r.frame(&piece, &mut head);
        }
        self.piece(env, r, head, piece.len())
    }

    /// Queues `bytes` of the response, of which `body` are body bytes.
    fn piece(&mut self, env: &mut Env<'_, Report>, mut r: Responding, bytes: Vec<u8>, body: usize) {
        if let Some(delivery) = &mut r.delivery {
            delivery.piece(bytes.len(), body);
        }
        self.responding = Some(r);
        if !self.fits(0) || !self.push_out(env, bytes) {
            self.over_budget(env);
        }
    }

    /// The response is written: wait for the next request, close, or
    /// hand the connection on.
    fn finish(&mut self, env: &mut Env<'_, Report>, mut r: Responding) {
        if let Some(mut delivery) = r.delivery.take() {
            delivery.finish(self.written.saturating_sub(r.base), true);
        }
        if self.next.is_some() {
            self.hand_on();
        } else if r.close {
            self.close(env, r.then);
        } else {
            self.timers
                .set(Timer::Head, env.now() + self.opts.header_timeout);
            self.phase = Phase::Reading;
        }
    }

    /// Gathers what the successor reads first: the bytes past the request,
    /// with their charge, and the client's end if it came.
    fn hand_on(&mut self) {
        self.timers = Timers::new();
        let unread = self.stream.unread();
        if !unread.is_empty() {
            let bytes = unread.to_vec();
            let chunk = match self.charge.as_mut().and_then(|c| c.split(bytes.len())) {
                Some(charge) => Chunk::with_charge(bytes, charge),
                None => Chunk::new(bytes),
            };
            self.leftover.push(StreamEvent::Data(chunk));
        }
        self.leftover
            .extend(self.after.drain(..).map(StreamEvent::Data));
        self.after_len = 0;
        if self.peer_ended {
            self.leftover.push(StreamEvent::Ended);
        }
        self.phase = Phase::Switching;
    }
}

/// A response being made or written.
struct Responding {
    delivery: Option<Delivery>,
    version: Version,
    wants: Asked,
    close: bool,
    /// Why the connection closes after it, if it does.
    then: Closing,
    chunked: bool,
    /// The request a handler's work holds while it makes the answer.
    request_held: usize,
    stage: Stage,
    /// Body bytes held in full and not yet written, and the length of the
    /// allocation they share, which stays charged until the last of them.
    rest: Bytes,
    rest_held: usize,
    /// Where the response starts among the bytes queued.
    base: u64,
}

enum Stage {
    /// A handler's work is making the response.
    Making,
    /// The response, to start.
    Made(Response<Body>),
    /// The head is out; the body's next frames, if it streams.
    Body(Option<Body>),
    /// The next frame is being polled.
    Polling,
}

impl Responding {
    fn held(&self) -> usize {
        let response = match &self.stage {
            Stage::Made(response) => response.body().full_len(),
            Stage::Body(Some(body)) => body.full_len(),
            _ => 0,
        };
        self.delivery.as_ref().map_or(0, |delivery| delivery.held)
            + self.request_held
            + self.rest_held
            + response
    }

    fn take_piece(&mut self) -> Bytes {
        let piece = self.rest.split_to(self.rest.len().min(PIECE));
        if self.rest.is_empty() {
            self.rest = Bytes::new();
            self.rest_held = 0;
        }
        piece
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

impl Layer for Http1 {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Report;
    type Timer = Timer;
    type Work = Work;
    type Done = Done;
    type Error = std::convert::Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Report>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Self::Error> {
        if self.phase == Phase::Opening {
            self.open(env);
        }
        match event {
            StreamEvent::Data(mut chunk) => {
                if matches!(self.phase, Phase::Closing | Phase::Closed) || self.peer_ended {
                    return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                }
                if chunk.is_empty() {
                    return Ok(Admit::Taken);
                }
                if self.phase == Phase::Switching {
                    self.leftover.push(StreamEvent::Data(chunk));
                    return Ok(Admit::Taken);
                }
                if self.stream.is_done() {
                    // Past the end of HTTP: what comes next reads it.
                    if self.after_len >= self.stream.limit() {
                        return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                    }
                    if !self.fits(chunk.len()) {
                        self.over_budget(env);
                        return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                    }
                    self.after_len += chunk.len();
                    self.after.push_back(chunk);
                    return Ok(Admit::Taken);
                }
                let n = self.stream.push(&chunk);
                Ok(if n == 0 {
                    Admit::Blocked(StreamEvent::Data(chunk))
                } else if n < chunk.len() {
                    chunk.advance(n);
                    Admit::Partial(StreamEvent::Data(chunk))
                } else {
                    Admit::Taken
                })
            }
            StreamEvent::Written(n) => {
                self.written += n;
                Ok(Admit::Taken)
            }
            StreamEvent::Ended => {
                if !self.peer_ended {
                    self.peer_ended = true;
                    if self.phase == Phase::Switching {
                        self.leftover.push(StreamEvent::Ended);
                    } else if !self.stream.is_done() {
                        self.stream.end();
                    }
                }
                Ok(Admit::Taken)
            }
            StreamEvent::Reset => {
                if self.phase != Phase::Closed {
                    env.report(Report::Closing(Closing::Reset));
                }
                self.out.clear();
                self.timers = Timers::new();
                self.responding = None;
                self.work = None;
                self.generation += 1;
                self.next = None;
                self.phase = Phase::Closed;
                Ok(Admit::Taken)
            }
        }
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, Report>,
        command: CommandOf<Top>,
    ) -> Result<Admit<CommandOf<Top>>, Self::Error> {
        match command {}
    }

    fn on_timer(&mut self, env: &mut Env<'_, Report>, timer: Timer) -> Result<(), Self::Error> {
        if self.timers.fire(&timer, env.now()) {
            self.close(env, Closing::Timeout(timer));
        }
        Ok(())
    }

    fn on_done(&mut self, env: &mut Env<'_, Report>, done: Done) -> Result<(), Self::Error> {
        if done.generation != self.generation {
            return Ok(());
        }
        let Some(r) = &mut self.responding else {
            return Ok(());
        };
        let failed = match done.answer {
            Answer::Made(Ok(response)) => {
                r.stage = Stage::Made(response);
                r.request_held = 0;
                None
            }
            // An error that asks for no answer closes the connection
            // unanswered.
            Answer::Made(Err(e)) if e.is::<Reset>() => Some(e),
            Answer::Made(Err(e)) => {
                r.stage = Stage::Made(error_response(&e));
                r.request_held = 0;
                None
            }
            Answer::Frame(body, Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data()
                    && !data.is_empty()
                {
                    r.rest_held = data.len();
                    r.rest = data;
                }
                r.stage = Stage::Body(Some(body));
                None
            }
            Answer::Frame(_, None) => {
                r.stage = Stage::Body(None);
                None
            }
            // The bytes so far may have broken the framing: close.
            Answer::Frame(_, Some(Err(e))) => Some(e),
        };
        if let Some(e) = failed {
            env.report(Report::Work(e));
            self.close(env, Closing::Work);
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Report>) -> Result<bool, Self::Error> {
        let moved = match self.phase {
            Phase::Opening => {
                self.open(env);
                true
            }
            Phase::Reading => self.read(env),
            Phase::Answering => self.respond(env),
            Phase::Switching | Phase::Closing | Phase::Closed => false,
        };
        if moved && matches!(self.phase, Phase::Reading | Phase::Answering) && !self.fits(0) {
            self.over_budget(env);
        }
        Ok(moved)
    }

    fn take_command(&mut self) -> Option<StreamCommand> {
        let command = self.out.pop_front()?;
        match &command {
            StreamCommand::Write(chunk) => self.handed += chunk.len() as u64,
            StreamCommand::End | StreamCommand::Reset => self.phase = Phase::Closed,
        }
        Some(command)
    }

    fn take_event(&mut self) -> Option<std::convert::Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<Work> {
        self.work.take()
    }

    fn deadline(&self) -> Option<(Instant, Timer)> {
        self.timers.next()
    }
}

impl Handoff for Http1 {
    type Next = Next;

    fn handover(&mut self) -> Option<Handover<Next, ByteStream, Top>> {
        if self.phase != Phase::Switching {
            return None;
        }
        let next = self.next.take()?;
        self.phase = Phase::Closed;
        Some(Handover {
            next,
            below: std::mem::take(&mut self.leftover),
            above: Vec::new(),
        })
    }
}

/// A handler's answer on its way.
type Making = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

/// Work [`Http1`] asks the world to do for a response: make a handler's
/// async answer, or poll a streamed body for its next frame.
pub struct Work {
    generation: u64,
    op: Op,
}

enum Op {
    Make {
        later: Option<Later>,
        making: Option<Making>,
    },
    Frame(Option<Body>),
}

/// The result of [`Work`].
pub struct Done {
    generation: u64,
    answer: Answer,
}

enum Answer {
    Made(Result<Response<Body>, Error>),
    /// The body back, with its next frame or its end.
    Frame(Body, Option<Result<Frame<Bytes>, Error>>),
}

impl Job for Work {
    type Done = Done;

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Done> {
        let generation = self.generation;
        let answer = match &mut self.op {
            Op::Make { later, making } => {
                if let Some(later) = later.take() {
                    *making = Some(match fcx {
                        Some(fcx) => later(fcx.clone()),
                        None => Box::pin(std::future::ready(Err(Error::msg(
                            "this answer needs a Cx: run the harness's work with one",
                        )))),
                    });
                }
                let made = match making {
                    Some(making) => ready!(making.as_mut().poll(cx)),
                    None => Err(Error::msg("this answer was already made")),
                };
                *making = None;
                Answer::Made(made)
            }
            Op::Frame(body) => {
                let frame = match body {
                    Some(body) => ready!(Pin::new(body).poll_frame(cx)),
                    None => None,
                };
                Answer::Frame(body.take().unwrap_or_default(), frame)
            }
        };
        Poll::Ready(Done { generation, answer })
    }
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
    let policy = ResponsePolicy::new(&parts, Some(0), Asked::Body, date);
    encode(out, version, &parts, &policy, true);
}

#[cfg(test)]
mod router_tests {
    use super::*;

    use fictionet::stdlib::layer::{Budget, Harness};
    use fictionet::sync::Mutex;

    #[test]
    fn delivery_matches_written_body_and_retains_response_extensions() {
        #[derive(Clone)]
        struct Length(usize);
        struct Echo;
        impl Handler for Echo {
            fn call(&self, request: Request<Body>, _: &mut Exchange<'_>) -> Reply {
                let bytes = request.body().bytes().unwrap();
                let mut response = Response::new(Body::from(bytes.clone()));
                response.extensions_mut().insert(Length(bytes.len()));
                Reply::Now(response)
            }
        }
        for length in [0, 7, PIECE + 31] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let collect = seen.clone();
            let mut harness = Harness::new(
                fictionet::Seed::from_u64(1),
                Http1::new(Echo).observe(Arc::new(move |observation| {
                    collect.lock().push(observation)
                })),
            )
            .running_work();
            let mut request = format!(
                "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: {length}\r\n\r\n"
            )
            .into_bytes();
            request.extend((0..length).map(|n| n as u8));
            harness.push(&request).unwrap();
            let response = http1::Response::parse_for(harness.output(), "POST").unwrap();
            let seen = seen.lock();
            let [observation] = seen.as_slice() else {
                panic!("one completion per request");
            };
            assert!(observation.complete);
            assert_eq!(observation.sent as usize, response.body.len());
            assert_eq!(
                observation
                    .response
                    .as_ref()
                    .unwrap()
                    .extensions
                    .get::<Length>()
                    .unwrap()
                    .0,
                response.body.len()
            );
        }
    }

    #[test]
    fn abandoning_a_stream_reports_incomplete_delivery_once() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collect = seen.clone();
        struct Waiting;
        impl http_body::Body for Waiting {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::convert::Infallible>>>
            {
                Poll::Pending
            }
        }
        struct Wait;
        impl Handler for Wait {
            fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
                Reply::Now(Response::new(Body::new(Waiting)))
            }
        }
        let mut harness = Harness::new(
            fictionet::Seed::from_u64(1),
            Http1::new(Wait).observe(Arc::new(move |observation| {
                collect.lock().push(observation)
            })),
        )
        .running_work();
        harness
            .push(b"GET /slow HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        assert!(seen.lock().is_empty());
        drop(harness);
        let seen = seen.lock();
        let [observation] = seen.as_slice() else {
            panic!("one cancellation per request");
        };
        assert!(!observation.complete);
        assert!(observation.response.is_some());
    }

    /// A body held in full stays charged in full until its last piece is
    /// written: its pieces share its allocation.
    #[test]
    fn response_suffix_keeps_the_original_charge() {
        struct Big;
        impl Handler for Big {
            fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
                Reply::Now(Response::new(Body::from(vec![b'x'; 3 * PIECE])))
            }
        }
        let budget = Budget::new(1 << 20);
        let mut h = Harness::with_budget(
            fictionet::Seed::from_u64(0),
            Http1::new(Big),
            budget.clone(),
        )
        .running_work();
        h.settle().unwrap();
        let base = budget.used();
        h.withhold();
        h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
        // The body's first piece goes with the head. Until the last piece
        // leaves the body, which is after the head and two pieces are
        // written, the whole body stays charged.
        let mut taken = 0;
        while taken <= 2 * PIECE {
            assert!(budget.used() >= base + 3 * PIECE, "{taken}");
            h.allow(PIECE / 2).unwrap();
            taken += PIECE / 2;
        }
        h.allow_all().unwrap();
        assert_eq!(budget.used(), base);
        let response = http1::Response::parse_for(h.output(), "GET").unwrap();
        assert_eq!(response.body.len(), 3 * PIECE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use fictionet::stdlib::layer::Harness;
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
            )
            .running_work();
            let mut request =
                b"POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            request.extend_from_slice(rest);
            h.push(&request).unwrap();
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
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, std::convert::Infallible>>> {
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
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Slow(open.clone())))
            .running_work();
        h.push(b"GET /slow HTTP/1.1\r\nHost: a\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n")
            .unwrap();
        // The first response takes longer than the 30-second head timeout,
        // while the second request already waits in the buffer.
        h.advance(Duration::from_secs(31)).unwrap();
        open.store(true, Ordering::Relaxed);
        h.settle().unwrap();
        let out = String::from_utf8_lossy(h.output()).into_owned();
        assert_eq!(out.matches("HTTP/1.1 200 OK\r\n").count(), 2, "{out:?}");
        assert!(out.ends_with("\r\n\r\nnext"), "{out:?}");
        assert!(!h.ended());
    }

    struct Hello;

    impl Handler for Hello {
        fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            Reply::Now(Response::new(Body::from("hello")))
        }
    }

    #[test]
    fn a_successful_connect_answer_has_no_body_framing() {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Hello)).running_work();
        h.push(b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n")
            .unwrap();
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

    /// Counts the requests it answers, each with its path.
    struct Count(Arc<AtomicUsize>);

    impl Handler for Count {
        fn call(&self, request: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            self.0.fetch_add(1, Ordering::Relaxed);
            let path = request.uri().path().to_owned();
            Reply::Now(Response::new(Body::from(path.repeat(4096))))
        }
    }

    /// A client that stops reading holds up its own pipeline and nothing
    /// is lost: the next request is read only once the answer before it is
    /// written, and every answer arrives whole and in order however the
    /// transport takes the bytes.
    #[test]
    fn withheld_output_holds_the_pipeline_and_loses_nothing() {
        let input = b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n";
        let whole = {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut h =
                Harness::new(fictionet::Seed::from_u64(0), Http1::new(Count(calls))).running_work();
            h.push(input).unwrap();
            h.output().to_vec()
        };
        for step in [1, 7, 1000, PIECE + 3] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut h = Harness::new(
                fictionet::Seed::from_u64(0),
                Http1::new(Count(calls.clone())),
            )
            .running_work();
            h.withhold();
            h.push(input).unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            assert!(h.output().is_empty());
            let first = whole.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4 + 8192;
            while h.output().len() < whole.len() {
                let before = h.output().len();
                h.allow(step).unwrap();
                assert!(h.output().len() > before, "{step}");
                // The second request is read only after the first answer
                // is all written.
                let answered = calls.load(Ordering::Relaxed);
                assert_eq!(answered == 2, h.output().len() >= first, "{step}");
            }
            assert_eq!(h.output(), whole, "{step}");
            assert!(!h.ended());
        }
    }
}
