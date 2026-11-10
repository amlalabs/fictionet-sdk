use crate::stdlib::web::Response;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use bytes::Bytes;
use http::{HeaderValue, StatusCode, Version};
use http_body::{Body as _, Frame};

use fictionet::stdlib::codec::{Fail, Stream, base64};
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Charge, ChargedBytes, Chunk, CommandOf, Env, Handoff, Handover,
    Layer, OwnedWork, Side, StreamCommand, StreamEvent, Successor, Switch, Timers, Top, WorkOwner,
};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::protocols::http1::{self, Event as H1, RequestError};
use fictionet::stdlib::protocols::http2::{DEFAULT_FRAME_SIZE, MAX_WINDOW, Setting};
use fictionet::stdlib::services::stack::{Job, Tunnel};
use fictionet::stdlib::web::Head;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::handlers::status_only;
use super::http2::{Http2Server, Responder};
use super::response::{Asked, Dates, ResponsePolicy, response_held};
use super::sites::no_host;
use super::{
    Body, Delivery, Exchange, Handler, Later, Limits, PIECE, Received, Reply, Reset, UpgradeHandler,
};
use crate::stdlib::web::{Request, Site};

// ---------------------------------------------------------------------------
// HTTP/1 as a layer

const HEADROOM: usize = 64;

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

/// What runs on an HTTP/1 connection once HTTP/1 is over: the code a
/// response handed the connection to with an [`UpgradeHandler`], or HTTP/2.
pub enum Next {
    /// A `101 Switching Protocols` answer to an upgrade, such as to
    /// WebSocket.
    Upgrade(UpgradeHandler),
    /// A 2xx answer to CONNECT: a tunnel.
    Connect(UpgradeHandler),
    /// A `101` answer to `Upgrade: h2c`: HTTP/2, with the request that
    /// asked as its stream 1.
    H2c(Box<Http2Server>),
}

/// What runs after HTTP/1 hands its connection on: a tunnel to code
/// written against a connection, or HTTP/2.
pub type Upgraded = Side<Tunnel, Http2Server>;

impl Successor<Next> for Upgraded {
    fn succeed(next: Next) -> Upgraded {
        match next {
            Next::Upgrade(handler) | Next::Connect(handler) => {
                Side::Lower(Tunnel::new(move |fcx, conn| handler.run(fcx, conn)))
            }
            Next::H2c(server) => Side::Upper(*server),
        }
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
/// Input storage, decoded heads, owned bodies and wire output are reserved
/// before allocation. Full bodies carry their backing's reservation;
/// admission transfers it, copying only when shared storage needs a new
/// payer. Opaque HTTP body frames are copied into reserved storage.
/// Handler and body-stream internals and world-owned facts remain outside
/// this byte accounting. Past the budget
/// the connection closes with nothing more written.
///
/// A response that hands the connection on with an [`UpgradeHandler`] (a
/// `101`, or a 2xx to CONNECT) ends HTTP: [`upgradable`](Self::upgradable)
/// runs what comes next, through [`Switch`], with the bytes the client sent
/// past the request.
pub struct Http1 {
    pub(super) observe: Option<super::Observe>,
    handler: Arc<dyn Handler>,
    opts: Limits,
    /// `Date` headers, from the world's date at the start of the run.
    pub(super) dates: Dates,
    conn: ConnInfo,
    site: Site,
    /// Whether `Upgrade: h2c` hands the connection to HTTP/2.
    h2c: bool,
    pub(super) first_head_deadline: Option<Instant>,
    stream: Stream<http1::RequestEvents>,
    /// Bytes past the end of HTTP, kept for what comes next.
    after: ChargedBytes,
    phase: Phase,
    timers: Timers<Timer>,
    head: Option<Head>,
    body: ChargedBytes,
    too_big: bool,
    responding: Option<Responding>,
    out: VecDeque<StreamCommand>,
    /// Bytes put in `out`, handed below, and written, since the start.
    queued: u64,
    handed: u64,
    written: u64,
    work: Option<Work>,
    work_owner: WorkOwner,
    /// Numbers each piece of work, so a result for one that no longer
    /// matters is ignored.
    generation: u64,
    peer_ended: bool,
    next: Option<Next>,
    /// What the successor gets, once HTTP is over.
    leftover: Vec<StreamEvent>,
    charge: Option<Charge>,
    /// One body-result allowance, transferred through Work and Done while polling.
    frame_charge: Option<Charge>,
    output_pools: Option<(fictionet::Pool, fictionet::Pool)>,
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
            dates: Dates::new(None),
            conn: ConnInfo::default(),
            site: Site::connection(&ConnInfo::default()),
            h2c: false,
            first_head_deadline: None,
            stream: Stream::new(http1::RequestEvents::with_limits(opts.head)),
            after: ChargedBytes::new(&Budget::unlimited()),
            charge: None,
            frame_charge: None,
            output_pools: None,
            phase: Phase::Opening,
            timers: Timers::new(),
            head: None,
            body: ChargedBytes::new(&Budget::unlimited()),
            too_big: false,
            responding: None,
            out: VecDeque::new(),
            queued: 0,
            handed: 0,
            written: 0,
            work: None,
            work_owner: WorkOwner::new(),
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
        self.dates = Dates::new(Some(start));
        self
    }

    /// Receives response completion and cancellation observations.
    pub fn observe(mut self, observe: super::Observe) -> Self {
        self.observe = Some(observe);
        self
    }

    /// Sets the trusted connection metadata, borrowed through [`Exchange`].
    pub fn conn(mut self, conn: ConnInfo) -> Self {
        self.site = Site::connection(&conn);
        self.conn = conn;
        self
    }

    /// Accepts HTTP/2 by `Upgrade: h2c` (RFC 7540 section 3.2), as a
    /// server without TLS may: an HTTP/1.1 request that asks for it, with
    /// valid `HTTP2-Settings`, gets `101 Switching Protocols` instead of
    /// the handler, and once that is written the connection is HTTP/2 with
    /// the request as stream 1, answered by the same handler. A request
    /// whose upgrade headers or settings are not valid stays on HTTP/1.
    pub fn h2c(mut self) -> Http1 {
        self.h2c = true;
        self
    }

    /// This connection, with what a response hands it on to running after
    /// HTTP/1.
    pub fn upgradable(self) -> Switch<Http1, Upgraded> {
        Switch::new(self)
    }

    /// HTTP/2 for this connection after `Upgrade: h2c`.
    fn http2(&self, settings: &[Setting], request: Request) -> Option<Http2Server> {
        Responder::shared(self.handler.clone())
            .limits(self.opts)
            .maybe_observe(self.observe.clone())
            .maybe_date(self.dates.start())
            .conn(self.conn.clone())
            .upgraded(settings, request)
    }

    /// Head backings carry their reservations. Stream keeps a copy of a
    /// rejected request box; head clones share their already paid backing.
    /// Body events still copy one configured block.
    fn decode_reservation(&self) -> usize {
        (2 * size_of::<http1::RejectedRequest>()).max(self.opts.head.body_chunk)
    }

    /// Takes the first charge and starts waiting for the first head.
    fn open(&mut self, env: &mut Env<'_, Report>) {
        self.phase = Phase::Reading;
        // The decoder's bounded input and temporary heads are paid once.
        // Retained bodies, heads and output own their reservations separately.
        let bytes = self
            .stream
            .limit()
            .saturating_mul(2)
            .saturating_add(self.decode_reservation())
            .saturating_add(self.dates.held())
            .saturating_add(PIECE);
        match env.budget().charge(bytes) {
            Some(mut charge) => {
                self.frame_charge = charge.split(PIECE);
                self.charge = Some(charge);
            }
            None => return self.over_budget(env),
        }
        let small = fictionet::Pool::new(env.budget(), 2048, 4);
        let large = fictionet::Pool::new(env.budget(), 16384 + HEADROOM, 2);
        // Reserve the reusable small head at open, so its cache is part of
        // the connection's idle storage rather than an outstanding response.
        let Some(head) = small.take(env.budget(), HEADROOM) else {
            return self.over_budget(env);
        };
        drop(head);
        self.stream
            .decoder()
            .storage(env.budget().clone(), small.clone(), large.clone());
        self.output_pools = Some((small, large));
        self.body = ChargedBytes::new(env.budget());
        self.after = ChargedBytes::new(env.budget());
        let at = self
            .first_head_deadline
            .take()
            .unwrap_or(env.now() + self.opts.header_timeout);
        self.timers.set(Timer::Head, at);
    }

    /// Queues bytes whose allocation was reserved before encoding.
    fn push_out(&mut self, bytes: impl Into<Chunk>) {
        let bytes = bytes.into();
        self.queued += bytes.len() as u64;
        self.out.push_back(StreamCommand::Write(bytes));
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
        self.body.clear();
        self.body.trim();
        self.responding = None;
        self.work = None;
        self.work_owner.cancel();
        self.generation += 1;
        self.next = None;
        self.phase = Phase::Closing;
        self.out.push_back(StreamCommand::End);
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
                if head.expects_continue() {
                    let bytes = b"HTTP/1.1 100 Continue\r\n\r\n";
                    let Some(out) = ChargedBytes::copy_of(env.budget(), bytes) else {
                        self.over_budget(env);
                        return true;
                    };
                    self.push_out(out);
                }
                self.head = Some(head);
                self.body.clear();
                self.body.trim();
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
                    if !self.body.grow_to(cap) {
                        self.over_budget(env);
                        return true;
                    }
                }
                self.body
                    .extend_within(&bytes)
                    .expect("body growth reserved room");
                true
            }
            Some(Ok(H1::Done)) => {
                let bytes = self.take_body(env.budget());
                let body = Body::from(bytes);
                let close = self.too_big;
                self.dispatch(env, body, close, Closing::Done);
                true
            }
            Some(Err(fail)) => {
                self.fail(env, fail);
                true
            }
        }
    }

    /// Move the body's reservation into its shared backing storage. Handler
    /// clones and streams may outlive both this layer and its current job.
    fn take_body(&mut self, budget: &Budget) -> Chunk {
        let bytes = std::mem::replace(&mut self.body, ChargedBytes::new(budget));
        if bytes.is_empty() {
            Chunk::default()
        } else {
            Chunk::from(bytes)
        }
    }

    /// Answers the request whose head is pending, with `body`. `close`
    /// closes the connection after the answer, for the reason `then`.
    fn dispatch(&mut self, env: &mut Env<'_, Report>, body: Body, close: bool, then: Closing) {
        let Some(head) = self.head.take() else {
            return self.close(env, Closing::Done);
        };
        let version = version_of(&head);
        let keep_alive = !close && head.keep_alive().unwrap_or(false) && head.method() != "CONNECT";
        let request = Request {
            head,
            body,
            site: self.site.clone(),
        };
        let wants = Asked::of(request.head.method());
        let held = request.head.held();
        let now = env.now();
        // RFC 9112 section 3.2: an HTTP/1.1 request without Host gets 400
        // from the service, unless its body is too large. The decoder
        // refuses such a head, so only a failure brings one here.
        let lacks_host = version == Version::HTTP_11 && request.head.field(b"host").is_none();
        let received = if self.too_big {
            Received::TooLarge
        } else if close {
            Received::CutOff
        } else {
            Received::Complete
        };
        // The observation's copy of the head is paid for before it is made.
        let mut delivery = match &self.observe {
            Some(_) => {
                let Some(charge) = env.budget().charge(held) else {
                    return self.over_budget(env);
                };
                Delivery::new(&self.observe, &request, &self.conn, now, received)
                    .map(|delivery| (delivery, charge))
            }
            None => None,
        };
        let h2c = (self.h2c && keep_alive && !self.too_big && !lacks_host)
            .then(|| h2c_settings(&request))
            .flatten();
        let reply = if self.too_big {
            Reply::Now(status_only(StatusCode::PAYLOAD_TOO_LARGE))
        } else if lacks_host {
            Reply::Now(no_host())
        } else if request.head.field(b"upgrade").is_some()
            && matches!(&request.body, Body::Stream(_))
        {
            Reply::Now(status_only(StatusCode::BAD_REQUEST))
        } else if let Some(settings) = h2c {
            // The request is HTTP/2's stream 1, observed there: the 101
            // is not its answer.
            if let Some(server) = self.http2(&settings, request) {
                delivery = None;
                self.next = Some(Next::H2c(Box::new(server)));
                let mut switching = status_only(StatusCode::SWITCHING_PROTOCOLS);
                switching.fields = crate::stdlib::web::Fields::new([("upgrade", b"h2c")]);
                Reply::Now(switching)
            } else {
                Reply::Now(status_only(StatusCode::BAD_REQUEST))
            }
        } else {
            self.handler
                .call(request, &mut Exchange::new(now, env.entropy(), &self.conn))
        };
        let (stage, body_charge) = match reply {
            Reply::Now(mut response) => {
                if !response.fields.admit(env.budget()) || !response.body.admit(env.budget()) {
                    return self.over_budget(env);
                }
                (Stage::Made(response), None)
            }
            Reply::Later(later) => {
                self.generation += 1;
                self.work = Some(Work {
                    generation: self.generation,
                    lease: self.work_owner.own(()),
                    charge: None,
                    budget: env.budget().clone(),
                    op: Op::Make {
                        later: Some(later),
                        making: None,
                    },
                });
                (Stage::Making, None)
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
            body_charge,
            stage,
            rest: Chunk::default(),
            base: self.queued,
        });
        self.phase = Phase::Answering;
    }

    /// The request bytes failed to decode with `fail`.
    fn fail(&mut self, env: &mut Env<'_, Report>, fail: Fail<RequestError>) {
        if matches!(&fail, Fail::Protocol(error) if error.reason() == http1::Error::Budget) {
            return self.over_budget(env);
        }
        if self.head.is_some() {
            // The body was cut off: the handler still sees what came, as a
            // body that ends in an error. Of the unread bytes, only body
            // data counts: chunk framing and later requests are not body.
            let room = self.opts.body.saturating_sub(self.body.len());
            let buffered = self.stream.unread().len();
            let pending = self.stream.decoder().pending_body_len(buffered);
            let added = pending.min(room);
            let need = self.body.len().saturating_add(added);
            if !self.body.grow_to(need) {
                return self.over_budget(env);
            }
            self.body
                .extend_within(&self.stream.unread()[..added])
                .expect("body growth reserved room");
            let bytes = self.take_body(env.budget());
            let body = partial(Bytes::from_owner(bytes), "the request body was cut off");
            self.dispatch(env, body, true, Closing::Failed);
            env.report(Report::Failed(fail));
            return;
        }
        if let Fail::Protocol(RequestError::Rejected(rejected)) = &fail
            && rejected.error == http1::Error::Host
            && rejected.framing.is_ok()
            && rejected.head.header("host").is_none()
        {
            self.too_big = rejected.received_body_bytes > self.opts.body;
            self.head = Some(rejected.head.clone());
            self.dispatch(env, Body::empty(), true, Closing::Failed);
            env.report(Report::Failed(fail));
            return;
        }
        let date = self.dates.at(env.now());
        let status = if matches!(
            &fail,
            Fail::Protocol(error) if error.reason() == http1::Error::UnsupportedTransferCoding
        ) {
            StatusCode::NOT_IMPLEMENTED
        } else {
            StatusCode::BAD_REQUEST
        };
        env.report(Report::Failed(fail));
        let Some(out) = simple_output(env, Version::HTTP_11, status, date) else {
            return self.over_budget(env);
        };
        self.push_out(out);
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
        if let Some((delivery, _)) = &mut r.delivery {
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
                if !r.chunked {
                    let body_len = piece.len();
                    self.piece(env, r, piece, body_len);
                    return true;
                }
                let framed = ChargedBytes::with_capacity(
                    env.budget(),
                    piece.len() + 2 * size_of::<usize>() + 4,
                )
                .and_then(|mut out| {
                    out.fill(|out| {
                        r.frame(&piece, out);
                        Ok::<_, Infallible>(())
                    })
                    .ok()?;
                    Some(out)
                });
                let Some(out) = framed else {
                    self.over_budget(env);
                    return true;
                };
                let body_len = piece.len();
                drop(piece);
                self.piece(env, r, out.into(), body_len);
                true
            }
            Stage::Body(Some(body)) => {
                let charge = self.frame_charge.take().expect("one body frame at a time");
                self.generation += 1;
                self.work = Some(Work {
                    generation: self.generation,
                    lease: self.work_owner.own(()),
                    charge: Some(charge),
                    budget: env.budget().clone(),
                    op: Op::Frame(Some(body)),
                });
                r.stage = Stage::Polling;
                self.responding = Some(r);
                true
            }
            Stage::Body(None) if r.chunked => {
                r.chunked = false;
                let bytes = b"0\r\n\r\n";
                let Some(out) = ChargedBytes::copy_of(env.budget(), bytes) else {
                    self.over_budget(env);
                    return true;
                };
                self.piece(env, r, out.into(), 0);
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
    fn start(&mut self, env: &mut Env<'_, Report>, mut r: Responding, response: Response) {
        let mut parts = response;
        let body = std::mem::take(&mut parts.body);
        if let Some((delivery, charge)) = &mut r.delivery {
            // The copy of the response head is paid for before it is made.
            let need = charge.bytes().saturating_add(response_held(&parts));
            if !charge.grow_to(need) {
                return self.over_budget(env);
            }
            delivery.response(&parts);
        }
        let hands_on = parts.status == StatusCode::SWITCHING_PROTOCOLS
            || (r.wants == Asked::Tunnel && parts.status.is_success());
        if matches!(self.next, Some(Next::H2c(_))) {
            // The service's own 101 to `Upgrade: h2c`.
            r.close = false;
        } else if hands_on && let Some(handler) = parts.upgrade.as_ref() {
            self.next = Some(if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                Next::Upgrade(handler.clone())
            } else {
                Next::Connect(handler.clone())
            });
            r.close = false;
        } else if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            // A 101 ends HTTP on the connection (RFC 9110 section 15.2.2):
            // with nothing to take it over, the connection closes.
            r.close = true;
        }
        let policy = ResponsePolicy::new(&parts, body.size_hint().exact(), r.wants, || {
            self.dates.at(env.now())
        });
        let Some(bound) = head_bound(&parts, &policy) else {
            return self.over_budget(env);
        };
        let (small, large) = self.output_pools.as_ref().expect("opened connection");
        let head = if bound <= small.slot() - HEADROOM {
            small.take(env.budget(), HEADROOM)
        } else if bound <= large.slot() - HEADROOM {
            large.take(env.budget(), HEADROOM)
        } else {
            bound.checked_add(HEADROOM).and_then(|size| {
                fictionet::Pool::new(env.budget(), size, 0).take(env.budget(), HEADROOM)
            })
        };
        let Some(mut head) = head else {
            return self.over_budget(env);
        };
        let mut encoded = None;
        head.fill(|room| {
            let length = room.len();
            let mut out = room;
            encoded = Some(encode(&mut out, r.version, &parts, &policy, r.close));
            length - out.len()
        });
        match encoded {
            Some(Ok(close)) => r.close = close,
            _ => return self.over_budget(env),
        }
        r.chunked = !policy.bodiless && policy.len.is_none() && r.version != Version::HTTP_10;
        let mut body_len = 0;
        if !policy.bodiless {
            match body {
                Body::Full(bytes) if bytes.len() <= head.room() => {
                    body_len = bytes.len();
                    head.extend_within(&bytes).expect("body fits head block");
                }
                Body::Full(bytes) => r.rest = bytes,
                stream => r.stage = Stage::Body(Some(stream)),
            }
        }
        self.piece(env, r, head, body_len)
    }

    /// Queues `bytes` of the response, of which `body` are body bytes.
    fn piece(&mut self, _env: &mut Env<'_, Report>, mut r: Responding, bytes: Chunk, body: usize) {
        if let Some((delivery, _)) = &mut r.delivery {
            delivery.piece(bytes.len(), body);
        }
        if r.rest.is_empty() {
            if self.frame_charge.is_none() {
                self.frame_charge = r.body_charge.take();
                // A body frame's room: what it needs past this is charged
                // before its bytes are copied (`Op::Frame`).
                if let Some(charge) = &mut self.frame_charge {
                    charge.shrink_to(PIECE);
                }
            } else {
                r.body_charge = None;
            }
        }
        self.responding = Some(r);
        self.push_out(bytes);
    }

    /// The response is written: wait for the next request, close, or
    /// hand the connection on.
    fn finish(&mut self, env: &mut Env<'_, Report>, mut r: Responding) {
        if let Some((mut delivery, _)) = r.delivery.take() {
            delivery.finish(self.written.saturating_sub(r.base), true);
        }
        if self.next.is_some() {
            self.hand_on(env);
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
    fn hand_on(&mut self, env: &mut Env<'_, Report>) {
        self.timers = Timers::new();
        let unread = self.stream.unread();
        if !unread.is_empty() {
            let Some(bytes) = ChargedBytes::copy_of(env.budget(), unread) else {
                return self.over_budget(env);
            };
            self.leftover.push(StreamEvent::Data(Chunk::from(bytes)));
        }
        if !self.after.is_empty() {
            let mut bytes = std::mem::replace(&mut self.after, ChargedBytes::new(env.budget()));
            bytes.trim();
            self.leftover.push(StreamEvent::Data(Chunk::from(bytes)));
        }
        if self.peer_ended {
            self.leftover.push(StreamEvent::Ended);
        }
        self.phase = Phase::Switching;
    }
}

/// A response being made or written.
struct Responding {
    /// The observation being made and the charge for its copies of the
    /// request and response heads.
    delivery: Option<(Delivery, Charge)>,
    version: Version,
    wants: Asked,
    close: bool,
    /// Why the connection closes after it, if it does.
    then: Closing,
    chunked: bool,
    stage: Stage,
    /// Body bytes not yet written. Full bodies carry their own reservation;
    /// streamed frames are covered by `body_charge` until the last piece.
    rest: Chunk,
    /// Where the response starts among the bytes queued.
    base: u64,
    body_charge: Option<Charge>,
}

enum Stage {
    /// A handler's work is making the response.
    Making,
    /// The response, to start.
    Made(Response),
    /// The head is out; the body's next frames, if it streams.
    Body(Option<Body>),
    /// The next frame is being polled.
    Polling,
}

impl Responding {
    fn take_piece(&mut self) -> Chunk {
        let piece = self.rest.split_to(self.rest.len().min(PIECE));
        if self.rest.is_empty() {
            self.rest = Chunk::default();
        }
        piece
    }

    /// `piece` as it goes on the wire: a chunk, when chunked.
    fn frame(&self, piece: &[u8], out: &mut Vec<u8>) {
        if self.chunked {
            write!(out, "{:x}\r\n", piece.len()).expect("writing into a vector succeeds");
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

    fn report_bytes(report: &Report) -> Option<usize> {
        match report {
            Report::Work(_) => None,
            Report::Failed(Fail::Protocol(RequestError::Rejected(_))) => {
                // The head backing carries its own reservation.
                Some(size_of::<http1::RejectedRequest>())
            }
            Report::Failed(_) | Report::Closing(_) => Some(0),
        }
    }

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
                    // Keep bounded staging room until Switch advances; EOF
                    // has its own final slot after preceding data.
                    if self.leftover.len() >= 4 {
                        return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                    }
                    if !chunk.repay(env.budget()) {
                        self.over_budget(env);
                        return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                    }
                    self.leftover.push(StreamEvent::Data(chunk));
                    return Ok(Admit::Taken);
                }
                if self.stream.is_done() {
                    // Past the end of HTTP: what comes next reads it.
                    if self.after.len() >= self.stream.limit() {
                        return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                    }
                    let n = chunk.len().min(self.stream.limit() - self.after.len());
                    let need = self.after.len() + n;
                    if need > self.after.capacity() {
                        let cap = need
                            .max(self.after.capacity().saturating_mul(2))
                            .min(self.stream.limit());
                        if !self.after.grow_to(cap) {
                            self.over_budget(env);
                            return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                        }
                    }
                    self.after
                        .extend_within(&chunk[..n])
                        .expect("handoff growth reserved room");
                    chunk.advance(n);
                    return Ok(if chunk.is_empty() {
                        Admit::Taken
                    } else {
                        Admit::Partial(StreamEvent::Data(chunk))
                    });
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
                self.work_owner.cancel();
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

    fn on_timer(&mut self, env: &mut Env<'_, Report>, timer: Timer) -> Result<bool, Self::Error> {
        let fired = self.timers.fire(&timer, env.now());
        if fired {
            self.close(env, Closing::Timeout(timer));
        }
        Ok(fired)
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
                r.body_charge = done.charge;
                r.stage = Stage::Made(response);
                None
            }
            // An error that asks for no answer closes the connection
            // unanswered.
            Answer::Made(Err(e)) if e.is::<Reset>() => Some(e),
            Answer::Made(Err(e)) => {
                let Some((response, charge)) = error_output(&e, env.budget()) else {
                    self.over_budget(env);
                    return Ok(());
                };
                r.body_charge = Some(charge);
                r.stage = Stage::Made(response);
                None
            }
            Answer::Frame(body, Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data()
                    && !data.is_empty()
                {
                    r.rest = data;
                    r.body_charge = done.charge;
                } else {
                    self.frame_charge = done.charge;
                }
                r.stage = Stage::Body(Some(body));
                None
            }
            Answer::Frame(_, None) => {
                self.frame_charge = done.charge;
                r.stage = Stage::Body(None);
                None
            }
            // The bytes so far may have broken the framing: close.
            Answer::Frame(_, Some(Err(e))) => {
                self.frame_charge = done.charge;
                Some(e)
            }
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
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
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

    fn is_terminal(&self) -> bool {
        self.phase == Phase::Closed
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
type Making = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send>>;

/// Work [`Http1`] asks the world to do for a response: make a handler's
/// async answer, or poll a streamed body for its next frame.
pub struct Work {
    generation: u64,
    lease: OwnedWork<()>,
    op: Op,
    charge: Option<Charge>,
    budget: Budget,
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
    charge: Option<Charge>,
}

enum Answer {
    Made(Result<Response, Error>),
    /// The body back, with its next frame or its end.
    Frame(Body, Option<Result<Frame<Chunk>, Error>>),
}

impl Job for Work {
    type Done = Done;

    fn cancelled(&self) -> bool {
        self.lease.cancelled()
    }

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
                let made = made.and_then(|mut response| {
                    // A body all there now goes out with the head, without
                    // work of its own.
                    response.body.settle(cx, &self.budget)?;
                    if !response.fields.admit(&self.budget) || !response.body.admit(&self.budget) {
                        return Err(Error::msg(
                            "the response body exceeds the connection budget",
                        ));
                    }
                    self.charge = None;
                    Ok(response)
                });
                Answer::Made(made)
            }
            Op::Frame(body) => {
                let frame = match body {
                    Some(body) => ready!(Pin::new(body).poll_frame(cx)),
                    None => None,
                };
                let frame = frame.map(|frame| {
                    frame.and_then(|frame| {
                        let data = match frame.into_data() {
                            Ok(data) => data,
                            Err(_) => return Ok(Frame::data(Chunk::default())),
                        };
                        let want = PIECE.max(data.len());
                        let fits = self.charge.as_mut().is_some_and(|charge| {
                            if want < charge.bytes() {
                                charge.shrink_to(want);
                                true
                            } else {
                                charge.grow_to(want)
                            }
                        });
                        if !fits {
                            return Err(Error::msg("the body frame exceeds the connection budget"));
                        }
                        Ok(Frame::data(Chunk::unpaid(data.to_vec())))
                    })
                });
                Answer::Frame(body.take().unwrap_or_default(), frame)
            }
        };
        Poll::Ready(Done {
            generation,
            charge: self.charge.take(),
            answer,
        })
    }
}

/// The client's settings, if `request` asks to upgrade to HTTP/2 the way
/// RFC 7540 section 3.2 says: HTTP/1.1, `Upgrade` naming `h2c`, a
/// `Connection` naming `Upgrade` and `HTTP2-Settings`, and one
/// `HTTP2-Settings` whose base64url holds valid SETTINGS. `None` keeps the
/// request on HTTP/1.
fn h2c_settings(request: &Request) -> Option<Vec<Setting>> {
    fn tokens<'a>(request: &'a Request, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        request
            .head
            .fields()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name.as_bytes()))
            .flat_map(|(_, value)| value.split(|b| *b == b','))
            .map(<[u8]>::trim_ascii)
    }
    if request.head.version() != http1::Version::Http11
        || !matches!(&request.body, Body::Full(_))
        || !tokens(request, "upgrade").any(|t| t.eq_ignore_ascii_case(b"h2c"))
        || !tokens(request, "connection").any(|t| t.eq_ignore_ascii_case(b"upgrade"))
        || !tokens(request, "connection").any(|t| t.eq_ignore_ascii_case(b"http2-settings"))
    {
        return None;
    }
    let mut values = request
        .head
        .fields()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"http2-settings"))
        .map(|(_, value)| value);
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    // base64url (RFC 4648 section 5), its padding left off.
    let standard: Vec<u8> = value
        .iter()
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            b => *b,
        })
        .collect();
    let payload = base64::decode(&standard, base64::Padding::Optional)?;
    if !payload.len().is_multiple_of(6) {
        return None;
    }
    let settings: Vec<Setting> = payload
        .chunks(6)
        .map(|s| Setting {
            id: u16::from_be_bytes([s[0], s[1]]),
            value: u32::from_be_bytes([s[2], s[3], s[4], s[5]]),
        })
        .collect();
    let valid = settings.iter().all(|s| match s.id {
        2 => s.value <= 1,
        4 => s.value <= MAX_WINDOW,
        5 => (DEFAULT_FRAME_SIZE as u32..=0xff_ffff).contains(&s.value),
        _ => true,
    });
    valid.then_some(settings)
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

fn version_of(head: &Head) -> Version {
    match head.version() {
        http1::Version::Http10 => Version::HTTP_10,
        http1::Version::Http11 => Version::HTTP_11,
        http1::Version::Http2 => Version::HTTP_2,
    }
}

/// Error bodies are constructed under the same reservation as normal output.
fn error_output(error: &Error, budget: &Budget) -> Option<(Response, Charge)> {
    let (status, prefix, message, suffix) = match error.downcast_ref::<super::BadGateway>() {
        Some(error) => (
            StatusCode::BAD_GATEWAY,
            "bad gateway: ",
            error.0.as_str(),
            "\n",
        ),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
            "The site failed to answer.\n",
            "",
        ),
    };
    let len = prefix
        .len()
        .checked_add(message.len())?
        .checked_add(suffix.len())?;
    let mut bytes = ChargedBytes::with_capacity(budget, len)?;
    bytes.extend_within(prefix.as_bytes()).ok()?;
    bytes.extend_within(message.as_bytes()).ok()?;
    bytes.extend_within(suffix.as_bytes()).ok()?;
    let (bytes, charge) = bytes.into_parts();
    let name = "content-type";
    let value = b"text/plain; charset=utf-8";
    let size = crate::stdlib::web::Fields::record_size(name.len(), value.len())?;
    let pool = fictionet::Pool::new(budget, size, 0);
    let mut fields = crate::stdlib::web::Fields::in_block(pool.take(budget, 0)?).ok()?;
    fields.push(name, value).ok()?;
    let mut response = Response::new(Body::from(bytes));
    response.status = status;
    response.fields = fields;
    Some((response, charge))
}

/// Bounds headers plus every generated field. Suppressed application fields
/// still count, so the reservation never depends on allocating an encoding.
fn head_bound(parts: &Response, policy: &ResponsePolicy) -> Option<usize> {
    let fixed = b"HTTP/1.1 ".len()
        + parts.status.as_str().len()
        + 1
        + parts.status.canonical_reason().unwrap_or("").len()
        + 2
        + b"Content-Length: ".len()
        + 20
        + 2
        + b"Transfer-Encoding: chunked\r\n".len()
        + b"Connection: keep-alive\r\n".len()
        + 2;
    let date = policy
        .date
        .as_ref()
        .map_or(0, |date| b"Date: ".len() + date.len() + 2);
    parts
        .fields
        .iter()
        .try_fold(fixed.checked_add(date)?, |n, (name, value)| {
            n.checked_add(name.len())?
                .checked_add(value.len())?
                .checked_add(4)
        })
}

/// Writes a response head. Returns whether the connection must close
/// after the body. Closing follows the request's `close` flag, the
/// response's `Connection: close` token (except for 101), or an HTTP/1.0
/// body of unknown length.
fn encode(
    out: &mut impl std::io::Write,
    version: Version,
    parts: &Response,
    policy: &ResponsePolicy,
    close: bool,
) -> std::io::Result<bool> {
    let status = parts.status;
    let v10 = version == Version::HTTP_10;
    let mut close = close
        || (status != StatusCode::SWITCHING_PROTOCOLS
            && parts
                .fields
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(b"connection"))
                .any(|(_, value)| {
                    value
                        .split(|b| *b == b',')
                        .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"))
                }));
    out.write_all(if v10 { b"HTTP/1.0 " } else { b"HTTP/1.1 " })?;
    out.write_all(status.as_str().as_bytes())?;
    out.write_all(b" ")?;
    out.write_all(status.canonical_reason().unwrap_or("").as_bytes())?;
    out.write_all(b"\r\n")?;
    for (name, value) in parts.fields.iter() {
        if [
            b"content-length".as_slice(),
            b"transfer-encoding",
            b"connection",
            b"keep-alive",
        ]
        .iter()
        .any(|skip| name.eq_ignore_ascii_case(skip))
        {
            continue;
        }
        title_case(out, name)?;
        out.write_all(b": ")?;
        out.write_all(value)?;
        out.write_all(b"\r\n")?;
    }
    if let Some(date) = &policy.date {
        out.write_all(b"Date: ")?;
        out.write_all(date.as_bytes())?;
        out.write_all(b"\r\n")?;
    }
    match policy.len {
        Some(n) => write!(out, "Content-Length: {n}\r\n")?,
        None if policy.bodiless => {}
        None if v10 => close = true,
        None => out.write_all(b"Transfer-Encoding: chunked\r\n")?,
    }
    if status == StatusCode::SWITCHING_PROTOCOLS {
        out.write_all(b"Connection: upgrade\r\n")?;
    } else if close && !v10 {
        out.write_all(b"Connection: close\r\n")?;
    } else if !close && v10 {
        out.write_all(b"Connection: keep-alive\r\n")?;
    }
    out.write_all(b"\r\n")?;
    Ok(close)
}

/// Writes a field name with each word capitalized (`Content-Type`), as
/// Apache, nginx and most other HTTP/1 servers do. The `http` crate keeps
/// names in lowercase, and tools that recognize servers by their replies,
/// such as `nmap -sV`, match `Server:` with its capital.
fn title_case(out: &mut impl std::io::Write, name: &[u8]) -> std::io::Result<()> {
    let mut start = true;
    for &b in name {
        out.write_all(&[if start {
            b.to_ascii_uppercase()
        } else {
            b.to_ascii_lowercase()
        }])?;
        start = b == b'-';
    }
    Ok(())
}

fn simple_output(
    env: &Env<'_, Report>,
    version: Version,
    status: StatusCode,
    date: Option<HeaderValue>,
) -> Option<ChargedBytes> {
    let parts = status_only(status);
    let policy = ResponsePolicy::new(&parts, Some(0), Asked::Body, || date);
    let mut out = ChargedBytes::with_capacity(env.budget(), head_bound(&parts, &policy)?)?;
    out.fill(|out| encode(out, version, &parts, &policy, true))
        .ok()?;
    Some(out)
}

#[cfg(test)]
mod router_tests {
    use super::*;

    use fictionet::stdlib::layer::{Budget, Harness};
    use fictionet::stdlib::services::stack::Polling;
    use fictionet::sync::Mutex;

    #[test]
    fn observation_budget_is_reserved_before_calling_the_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Count(Arc<AtomicUsize>);
        impl Handler for Count {
            fn call(&self, _: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
                self.0.fetch_add(1, Ordering::Relaxed);
                Reply::Now(Response::new(Body::empty()))
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let budget = Budget::new(1 << 20);
        let mut h = Harness::with_budget(
            fictionet::Seed::from_u64(14),
            Http1::new(Count(calls.clone())).observe(Arc::new(|_| {})),
            budget.clone(),
        );
        let body = b"x";
        h.push(b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\n")
            .unwrap();
        assert!(h.layer().head.is_some());
        let other = budget
            .charge(budget.limit() - budget.used() - 2 * body.len())
            .unwrap();
        h.push(body).unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "observation storage must fit before dispatch"
        );
        assert!(budget.used() <= budget.limit());
        drop(h);
        assert_eq!(budget.used(), other.bytes());
        drop(other);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_handler_retaining_request_bytes_retains_the_backing_reservation() {
        struct Keep(Arc<Mutex<Option<Chunk>>>);
        impl Handler for Keep {
            fn call(
                &self,
                request: fictionet::stdlib::web::Request,
                _: &mut Exchange<'_>,
            ) -> Reply {
                *self.0.lock() = request.body.bytes();
                Reply::Now(Response::new(Body::empty()))
            }
        }
        let held = Arc::new(Mutex::new(None));
        let budget = Budget::new(1 << 20);
        let mut h = Harness::with_budget(
            fictionet::Seed::from_u64(13),
            Http1::new(Keep(held.clone())),
            budget.clone(),
        );
        h.push(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nbody")
            .unwrap();
        drop(h);
        assert_eq!(budget.used(), 4);
        held.lock().take();
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn pending_request_work_keeps_its_memory_after_the_layer_is_dropped() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Wait(Arc<AtomicUsize>);
        impl Handler for Wait {
            fn call(
                &self,
                request: fictionet::stdlib::web::Request,
                _: &mut Exchange<'_>,
            ) -> Reply {
                let bytes = request.head.held() + request.body.bytes().unwrap().charged();
                self.0.store(bytes, Ordering::Relaxed);
                Reply::Later(Box::new(move |_| {
                    Box::pin(async move {
                        let _request = request;
                        std::future::pending().await
                    })
                }))
            }
        }
        let budget = Budget::new(1 << 20);
        let retained = Arc::new(AtomicUsize::new(0));
        let mut h = Harness::with_budget(
            fictionet::Seed::from_u64(12),
            Http1::new(Wait(retained.clone())),
            budget.clone(),
        );
        h.push(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nbody")
            .unwrap();
        let work = h.work().expect("handler work");
        assert!(
            work.charge.is_none(),
            "request storage carries its own charge"
        );
        let reserved = retained.load(Ordering::Relaxed);
        assert!(reserved > 0);
        drop(h);
        assert!(work.cancelled());
        assert_eq!(budget.used(), reserved);
        drop(work);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn completed_body_work_keeps_its_reservation_until_delivery() {
        let budget = Budget::new(2 * PIECE);
        let owner = WorkOwner::new();
        let mut work = Work {
            generation: 0,
            lease: owner.own(()),
            budget: budget.clone(),
            charge: Some(budget.charge(PIECE).unwrap()),
            op: Op::Frame(Some(Body::from(vec![b'x'; PIECE + 1]))),
        };
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(done) = work.poll(None, &mut cx) else {
            panic!("full body is ready")
        };
        drop(work);
        assert_eq!(budget.used(), PIECE + 1);
        let Answer::Frame(_, Some(Ok(frame))) = &done.answer else {
            panic!("a frame")
        };
        assert_eq!(frame.data_ref().unwrap().len(), PIECE + 1);
        drop(done);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn response_admission_releases_opaque_backing_storage() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Backing {
            bytes: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl AsRef<[u8]> for Backing {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Backing {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Relaxed);
            }
        }
        struct Answer(Mutex<Option<Bytes>>);
        impl Handler for Answer {
            fn call(&self, _: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
                Reply::Now(Response::new(Body::from(self.0.lock().take().unwrap())))
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let bytes = Bytes::from_owner(Backing {
            bytes: vec![b'x'; 1 << 20],
            dropped: dropped.clone(),
        })
        .slice(7..18);
        let mut h = Harness::new(
            fictionet::Seed::from_u64(10),
            Http1::new(Answer(Mutex::new(Some(bytes)))),
        );
        h.withhold();
        h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
        assert!(
            dropped.load(Ordering::Relaxed),
            "the short body no longer retains the large external allocation"
        );
        h.allow_all().unwrap();
        assert_eq!(
            http1::Response::parse_for(h.output(), "GET")
                .unwrap()
                .body
                .len(),
            11
        );
    }

    #[test]
    fn blocked_response_input_capacity_stays_reserved() {
        struct Answer;
        impl Handler for Answer {
            fn call(&self, _: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
                Reply::Now(Response::new(Body::from("body")))
            }
        }
        let budget = Budget::new(1 << 20);
        let mut h = Harness::with_budget(
            fictionet::Seed::from_u64(11),
            Http1::new(Answer),
            budget.clone(),
        );
        h.withhold();
        let request = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n";
        for _ in 0..128 {
            h.push(request).unwrap();
            let layer = h.layer();
            assert!(
                layer.charge.as_ref().unwrap().bytes()
                    >= layer.stream.allocated() + layer.stream.held()
            );
        }
        drop(h);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn delivery_matches_written_body_and_retains_response_facts() {
        #[derive(Clone)]
        struct Length(usize);
        struct Echo;
        impl Handler for Echo {
            fn call(
                &self,
                request: fictionet::stdlib::web::Request,
                _: &mut Exchange<'_>,
            ) -> Reply {
                let bytes = request.body.bytes().unwrap();
                let mut response = Response::new(Body::from(bytes.clone()));
                response.facts = Some(crate::stdlib::web::Facts::new(Length(bytes.len())));
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
            .with_worker(Polling::new());
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
                    .facts
                    .as_ref()
                    .unwrap()
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
            fn call(&self, _: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
                Reply::Now(Response::new(Body::new(Waiting)))
            }
        }
        let mut harness = Harness::new(
            fictionet::Seed::from_u64(1),
            Http1::new(Wait).observe(Arc::new(move |observation| {
                collect.lock().push(observation)
            })),
        )
        .with_worker(Polling::new());
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
            fn call(&self, _: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
                Reply::Now(Response::new(Body::from(vec![b'x'; 3 * PIECE])))
            }
        }
        let budget = Budget::new(1 << 20);
        let mut h = Harness::with_budget(
            fictionet::Seed::from_u64(0),
            Http1::new(Big),
            budget.clone(),
        )
        .with_worker(Polling::new());
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
    use fictionet::stdlib::services::stack::Polling;
    use fictionet::sync::Mutex;

    /// Records the data frames of each request body until it ends or fails.
    struct Frames(Arc<Mutex<Vec<u8>>>);

    impl Handler for Frames {
        fn call(&self, request: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
            let mut body = request.body;
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
            .with_worker(Polling::new());
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

    #[test]
    fn ambiguous_framing_never_dispatches_a_pipelined_request() {
        struct Paths(Arc<Mutex<Vec<String>>>);
        impl Handler for Paths {
            fn call(
                &self,
                request: fictionet::stdlib::web::Request,
                _: &mut Exchange<'_>,
            ) -> Reply {
                self.0.lock().push(request.head.path().to_owned());
                Reply::Now(Response::new(Body::empty()))
            }
        }
        for (fields, body, accepted) in [
            ("Content-Length: 1\r\nContent-Length: 1\r\n", "x", true),
            ("Content-Length: 1, 1\r\n", "x", true),
            (
                "Transfer-Encoding: chunked\r\n",
                "1\r\nx\r\n0\r\n\r\n",
                true,
            ),
            (
                "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
                "x",
                false,
            ),
            (
                "Transfer-Encoding: chunked\r\nContent-Length: 1\r\n",
                "x",
                false,
            ),
            ("Content-Length: 1\r\nContent-Length: 2\r\n", "x", false),
            ("Content-Length: 1, 2\r\n", "x", false),
            ("Transfer-Encoding: chunked, gzip\r\n", "", false),
            ("Transfer-Encoding: gzip, chunked\r\n", "0\r\n\r\n", false),
            ("Transfer-Encoding: gzip\r\n", "", false),
            (
                "Transfer-Encoding: chunked\r\n",
                "10000000000000000\r\n",
                false,
            ),
            ("Transfer-Encoding: chunked\r\n", "0;x=y\r\n\r\n", false),
            ("Transfer-Encoding: chunked\r\n", "0\r\nX: y\r\n\r\n", false),
            ("Content-Length: 1\r\n 0\r\n", "x", false),
            ("Content-Length: 1\n", "x", false),
            ("X: a\rb\r\n", "", false),
        ] {
            let first = format!("POST /first HTTP/1.1\r\nHost: a\r\n{fields}\r\n{body}");
            let mut wire = first.as_bytes().to_vec();
            wire.extend_from_slice(b"GET /admin HTTP/1.1\r\nHost: a\r\n\r\n");
            // Exercise every split, including inside the two length fields,
            // the body boundary and the next request's start line.
            for cut in 0..=wire.len() {
                let seen = Arc::new(Mutex::new(Vec::new()));
                let mut h = Harness::new(
                    fictionet::Seed::from_u64(0),
                    Http1::new(Paths(seen.clone())),
                )
                .with_worker(Polling::new());
                h.push(&wire[..cut]).unwrap();
                h.push(&wire[cut..]).unwrap();
                let (responses, error) =
                    fictionet::stdlib::test_support::decode_all(http1::Responses::new, h.output());
                assert!(error.is_none(), "{fields:?}, cut {cut}: {error:?}");
                assert_eq!(responses.len(), if accepted { 2 } else { 1 });
                assert!(responses.iter().all(|response| response.body.is_empty()));
                let paths = seen.lock();
                if accepted {
                    assert_eq!(&*paths, &["/first", "/admin"], "{fields:?}, cut {cut}");
                } else {
                    assert!(
                        !paths.iter().any(|path| path == "/admin"),
                        "{fields:?}, cut {cut}"
                    );
                }
            }
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
        fn call(&self, request: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
            let body = if request.head.path() == "/slow" {
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
            .with_worker(Polling::new());
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

    #[test]
    fn http_two_upgrade_refuses_unrepresentable_request_heads() {
        let server = Http1::new(Hello);
        for (target, representable) in [("/kept", true), ("http://[", false)] {
            let request = Request {
                head: Head::new(
                    "GET",
                    target,
                    http1::Version::Http11,
                    [("host", "example.test")],
                ),
                body: Body::empty(),
                site: Site::connection(&ConnInfo::default()),
            };
            assert_eq!(server.http2(&[], request).is_some(), representable);
        }
    }

    impl Handler for Hello {
        fn call(&self, _: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
            Reply::Now(Response::new(Body::from("hello")))
        }
    }

    #[test]
    fn a_successful_connect_answer_has_no_body_framing() {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Hello))
            .with_worker(Polling::new());
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

    /// Answers every request with a bare 101: no UpgradeHandler.
    struct Bare101;

    impl Handler for Bare101 {
        fn call(&self, _: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
            let mut response = Response::new(Body::empty());
            response.status = StatusCode::SWITCHING_PROTOCOLS;
            Reply::Now(response)
        }
    }

    /// A 101 ends HTTP on the connection (RFC 9110 section 15.2.2). With
    /// nothing to take the connection over, it closes: the bytes after the
    /// upgrade request are not read as another request. Found by
    /// `verification/http/tla/Pipeline.tla` (`NoHttpAfter101`).
    #[test]
    fn a_101_without_an_upgrade_handler_closes() {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Bare101))
            .with_worker(Polling::new());
        h.push(
            b"GET /a HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n\
              GET /b HTTP/1.1\r\nHost: a\r\n\r\n",
        )
        .unwrap();
        let out = String::from_utf8_lossy(h.output()).into_owned();
        assert!(out.starts_with("HTTP/1.1 101 "), "{out}");
        assert_eq!(out.matches("HTTP/1.1 ").count(), 1, "{out}");
        assert!(h.ended(), "{out}");
    }

    /// Counts the requests it answers, each with its path.
    struct Count(Arc<AtomicUsize>);

    impl Handler for Count {
        fn call(&self, request: fictionet::stdlib::web::Request, _: &mut Exchange<'_>) -> Reply {
            self.0.fetch_add(1, Ordering::Relaxed);
            let path = request.head.path().to_owned();
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
            let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Count(calls)))
                .with_worker(Polling::new());
            h.push(input).unwrap();
            h.output().to_vec()
        };
        for step in [1, 7, 1000, PIECE + 3] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut h = Harness::new(
                fictionet::Seed::from_u64(0),
                Http1::new(Count(calls.clone())),
            )
            .with_worker(Polling::new());
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

#[cfg(test)]
mod body_admission_tests {
    use super::*;
    use fictionet::Pool;

    #[test]
    fn full_body_admission_moves_storage_and_refuses_without_changes() {
        let owner = Budget::new(4096);
        let pool = Pool::new(&owner, 512, 2);
        let mut block = pool.take(&owner, 64).unwrap();
        block.extend_within(b"response").unwrap();
        let address = block.as_ptr();
        let mut body = Body::Full(block);
        let short = Budget::new(pool.slot() - 1);
        assert!(!body.admit(&short));
        assert!(short.used() == 0);
        assert_eq!(body.bytes().unwrap().as_ptr(), address);
        let destination = Budget::new(pool.slot());
        assert!(body.admit(&destination));
        assert_eq!(body.bytes().unwrap().as_ptr(), address);
        assert!(destination.used() >= pool.slot());
        drop(body);
        assert!(destination.used() == 0);
        assert!(pool.free() > 0);
    }
}
