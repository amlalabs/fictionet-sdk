//! A [`Handler`] on one HTTP/2 exchange.
use crate::stdlib::web::Response;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};

use fictionet::stdlib::layer::{
    Budget, Chain, Charge, ChargedSegments, Children, Chunk, Env, Layer, Top,
};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::protocols::http2::{ErrorCode, Setting};
use fictionet::stdlib::services::stack::Job;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::super::response::{Asked, ResponsePolicy, error_response};
use super::super::{
    AltSvc, Body, Delivery, Exchange, Handler, Later, Limits, Observe, PIECE, Received, Reply,
    Reset, text,
};
use super::{Ending, ExchangeCommand, ExchangeEvent, Http2, HttpExchange, Opening, ResponseHead};

/// HTTP/2 answered by a [`Handler`]: the [`Http2`] connection with a
/// [`Respond`] on each stream. [`Responder::http2`] makes one.
pub type Http2Server = Chain<Http2, Children<Respond, Top, Opening>>;

/// How each exchange of a connection is answered: the handler, the limits,
/// the delivery observer, the world's date and the connection.
#[derive(Clone)]
pub struct Responder {
    handler: Arc<dyn Handler>,
    limits: Limits,
    observe: Option<Observe>,
    date: Option<SystemTime>,
    conn: ConnInfo,
    site: crate::stdlib::web::Site,
    http3: Arc<dyn super::super::Http3Profile>,
}

impl Responder {
    /// Answers with `handler`, with default limits.
    pub fn new(handler: impl Handler) -> Self {
        Self::shared(Arc::new(handler))
    }

    /// Answers with a shared handler.
    pub fn shared(handler: Arc<dyn Handler>) -> Self {
        Self {
            handler,
            limits: Limits::default(),
            observe: None,
            date: None,
            conn: ConnInfo::default(),
            site: crate::stdlib::web::Site::connection(&ConnInfo::default()),
            http3: Arc::new(super::super::Http3Standard),
        }
    }

    /// With these limits and timers.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Receives response completion and cancellation observations.
    pub fn observe(mut self, observe: Observe) -> Self {
        self.observe = Some(observe);
        self
    }

    /// Sends a `Date` header with each response: `start`, the world's date
    /// and time at the start of the run, plus the run's clock. See
    /// [Dates](super::super#dates).
    pub fn date(mut self, start: SystemTime) -> Self {
        self.date = Some(start);
        self
    }

    pub(in super::super) fn maybe_date(mut self, start: Option<SystemTime>) -> Self {
        self.date = start;
        self
    }

    pub(in super::super) fn maybe_observe(mut self, observe: Option<Observe>) -> Self {
        self.observe = observe;
        self
    }

    /// Sets the trusted connection metadata, borrowed through [`Exchange`].
    pub fn conn(mut self, conn: ConnInfo) -> Self {
        self.site = crate::stdlib::web::Site::connection(&conn);
        self.conn = conn;
        self
    }

    /// HTTP/2 on one connection, with a [`Respond`] on each stream.
    pub fn http2(&self) -> Http2Server {
        self.server(Http2::new(self.limits))
    }

    /// What each HTTP/3 connection advertises and how it encodes fields.
    /// The default is [`Http3Standard`](super::super::Http3Standard).
    pub fn http3_profile(mut self, profile: impl super::super::Http3Profile + 'static) -> Self {
        self.http3 = Arc::new(profile);
        self
    }

    /// HTTP/3 over an established QUIC stream carrier, with a handler on each request.
    pub fn http3(&self) -> super::super::Http3Server {
        let mut connection = super::super::Http3::new(self.limits).profile(self.http3.clone());
        if let Some(start) = self.date {
            connection = connection.date(start);
        }
        let shared = Arc::new(self.clone());
        Chain::new(
            connection,
            Children::new(
                (self.limits.streams as usize).min(4096),
                Http2::WINDOW,
                move |_, opening, budget| Respond::new(shared.clone(), opening, budget),
            ),
        )
    }

    /// HTTP/3 for every connection `listener` accepts on one UDP socket:
    /// [`http3`](Self::http3) on each, with that connection's metadata,
    /// and charged to that connection's budget
    /// ([`Accepted::budget`](fictionet::stdlib::services::quic::Accepted::budget)).
    pub fn http3_listener(
        &self,
        listener: fictionet::stdlib::services::quic::Listener,
    ) -> super::super::Http3Listener {
        use fictionet::stdlib::services::quic::Accepted;
        let responder = self.clone();
        let applications = Children::new(
            listener.connections(),
            0,
            move |_, accepted: Accepted, _| Some(responder.clone().conn(accepted.info).http3()),
        )
        .budgets(|_, accepted: &Accepted, _| accepted.budget.clone());
        Chain::new(listener, applications)
    }

    /// HTTP/2 after an HTTP/1 `Upgrade: h2c`: `request`, whose whole body
    /// came over HTTP/1, is stream 1, and the client's `settings` apply.
    pub(in super::super) fn upgraded(
        &self,
        settings: &[Setting],
        request: crate::stdlib::web::Request,
    ) -> Option<Http2Server> {
        let parts = request.head.to_http().ok()?;
        let head = Request::from_parts(parts, ());
        let body = request
            .body
            .bytes()
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| Chunk::unpaid(bytes.to_vec()));
        Some(self.server(Http2::upgraded(self.limits, settings, head, body)))
    }

    fn server(&self, mut connection: Http2) -> Http2Server {
        // The connection dates each head as it frames it, so its streams
        // share one header per second.
        if let Some(start) = self.date {
            connection = connection.date(start);
        }
        let shared = Arc::new(self.clone());
        let limit = (self.limits.streams as usize).min(4096);
        Chain::new(
            connection,
            Children::new(limit, Http2::WINDOW, move |_, opening, budget| {
                Respond::new(shared.clone(), opening, budget)
            }),
        )
    }
}

/// A [`Handler`] on one [`HttpExchange`]: the application's side of one
/// HTTP/2 stream.
///
/// It collects the request's body within the body limit, the body deadline
/// and the budget, then calls the handler, or answers `413`, `408` or `503`
/// without it. A handler's async answer and each frame of a streamed body
/// are its [`Work`]. The response's head goes down with the framing the
/// shared response policy chose, then its body within the connection's
/// credit, then its trailers or its end. The response replaces the request
/// in the budget; one the budget cannot hold gets `503`, and a streamed
/// chunk it cannot hold resets this stream alone.
///
/// The handler takes a [`Head`](crate::stdlib::web::Head) that is the
/// block the connection decoded the request's head into, with its charge:
/// nothing is copied or converted, and the block goes back to the
/// connection when the handler drops the head. A stream whose
/// pseudo-fields are not visible ASCII is reset with `PROTOCOL_ERROR`.
pub struct Respond {
    responder: Arc<Responder>,
    head: Option<crate::stdlib::web::Head>,
    /// What this exchange holds besides the request's head and body: the
    /// response's head. Response chunks carry their own charge.
    charge: Option<Charge>,
    /// The request's body as it is collected, in segments that carry
    /// their charge.
    body: Option<ChargedSegments>,
    /// The body's length, when `content-length` gave it.
    length: Option<u64>,
    deadline: Option<Instant>,
    /// The request ended before it was answered.
    ended: bool,
    stage: Stage,
    wants: Asked,
    /// What the response advertises, as the handler's exchange said.
    alt_svc: Option<AltSvc>,
    delivery: Option<Delivery>,
    /// The next command, for the connection to take.
    next: Option<ExchangeCommand>,
    /// Body bytes held in full, not yet sent.
    rest: Chunk,
    generation: u64,
    work: Option<Work>,
}

enum Stage {
    /// Collecting the request's body.
    Collecting,
    /// The handler's work is making the response.
    Making,
    /// The response, to start.
    Made(Response),
    /// The head is out; a streamed body's next frames, if it streams.
    Body(Option<Body>),
    /// The next frame is being polled.
    Polling,
    /// The trailers or the end, once the body is out.
    Ending(Option<Box<HeaderMap>>),
    /// Nothing more to send.
    Done,
}

impl Respond {
    /// The exchange `opening` starts, its head the block the connection
    /// decoded it into, with the room to answer `503` charged to `budget`
    /// first. `None`, with nothing charged, when the budget has no room for
    /// it: the stream is refused before its handler runs.
    fn new(responder: Arc<Responder>, opening: Opening, budget: &Budget) -> Option<Respond> {
        let reserve = budget.charge(answer_reserve())?;
        let deadline = (!opening.ended).then(|| opening.at + responder.limits.body_timeout);
        let version = opening.head.version();
        let length = opening.head.content_length();
        let head = crate::stdlib::web::Head::multiplexed(opening.head.into_fields(), version);
        let (stage, next) = match head {
            Some(_) => (Stage::Collecting, None),
            // A head the connection could check but whose pseudo-fields
            // are not visible ASCII is the client's error on this stream
            // alone.
            None => (
                Stage::Done,
                Some(ExchangeCommand::Reset(ErrorCode::ProtocolError)),
            ),
        };
        Some(Respond {
            responder,
            head,
            charge: Some(reserve),
            body: None,
            length,
            deadline: deadline.filter(|_| next.is_none()),
            ended: opening.ended,
            stage,
            wants: Asked::Body,
            alt_svc: None,
            delivery: None,
            next,
            rest: Chunk::default(),
            generation: 0,
            work: None,
        })
    }

    /// Charges `bytes` in place of what is charged now. Returns whether it
    /// fits.
    fn hold(&mut self, env: &Env<'_, Infallible>, bytes: usize) -> bool {
        // More than the whole budget never fits, and this exchange answers
        // that itself (`503`): it is not asked for, so it is not taken for
        // a need of the child's that no release could meet.
        if bytes > env.budget().limit() {
            return false;
        }
        match &mut self.charge {
            Some(charge) if bytes < charge.bytes() => {
                charge.shrink_to(bytes);
                true
            }
            Some(charge) => charge.grow_to(bytes),
            None => {
                self.charge = env.budget().charge(bytes);
                self.charge.is_some()
            }
        }
    }

    /// The bytes of the request's body collected so far.
    fn collected(&self) -> usize {
        self.body.as_ref().map_or(0, |body| body.len())
    }

    /// The request's body grows by `chunk`, into room charged before it is
    /// allocated. A body whose `content-length` passes the limit is too
    /// large at its first bytes: the connection holds the body to that
    /// length.
    fn collect(&mut self, env: &mut Env<'_, Infallible>, chunk: Chunk) {
        let limits = self.responder.limits;
        let len = self.collected();
        let length = self
            .length
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX));
        if len.saturating_add(chunk.len()) > limits.body || length.is_some_and(|n| n > limits.body)
        {
            return self.dispatch(env, Received::TooLarge);
        }
        if !collect_into(&mut self.body, &chunk, length, limits.body, env.budget()) {
            self.dispatch(env, Received::Budget);
        }
    }

    /// Answers the request: with the handler for a whole one, or with the
    /// status for one that could not be received.
    fn dispatch(&mut self, env: &mut Env<'_, Infallible>, mut received: Received) {
        let Some(head) = self.head.take() else {
            return;
        };
        self.deadline = None;
        let responder = self.responder.clone();
        // A body not received whole is never read: its storage goes now,
        // as the answer may need the room.
        let segments = self.body.take();
        let body = match segments {
            Some(segments) if matches!(received, Received::Complete) => {
                Body::from_segments(segments, env.budget()).unwrap_or_else(|| {
                    received = Received::Budget;
                    Body::empty()
                })
            }
            _ => Body::empty(),
        };
        let request = crate::stdlib::web::Request {
            head,
            body,
            site: responder.site.clone(),
        };
        self.wants = Asked::of(request.head.method());
        let now = env.now();
        self.delivery = Delivery::new(&responder.observe, &request, &responder.conn, now, received);
        let responses = super::super::Responses::unpooled(env.budget());
        let reply = match received {
            Received::Complete => {
                let mut exchange =
                    Exchange::new(now, env.entropy(), &responder.conn, responses.clone());
                let reply = responder.handler.call(request, &mut exchange);
                self.alt_svc = exchange.advertised();
                reply
            }
            refused => {
                // Nothing reads a body that was not received whole: its
                // storage goes before the answer is made, which may need
                // the room.
                drop(request);
                let (status, why) = match refused {
                    Received::TooLarge => (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "The request body is too large.\n",
                    ),
                    Received::Budget => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "The server cannot hold this request now.\n",
                    ),
                    Received::Timeout => (
                        StatusCode::REQUEST_TIMEOUT,
                        "The request body took too long.\n",
                    ),
                    Received::CutOff => {
                        (StatusCode::BAD_REQUEST, "The request body was cut off.\n")
                    }
                    Received::Complete => unreachable!("a whole request goes to the handler"),
                };
                Reply::Now(text(&responses, status, why))
            }
        };
        match reply {
            Reply::Now(response) => self.made(env, response, false),
            Reply::Later(later) => {
                // Only work still making its response holds the request.
                self.generation += 1;
                self.work = Some(Work {
                    generation: self.generation,
                    op: Op::Make {
                        later: Some(later),
                        making: None,
                    },
                });
                self.stage = Stage::Making;
            }
        }
    }

    /// The response replaces the request in the budget. One the budget
    /// cannot hold gets `503` instead, so it does not end the connection's
    /// other streams.
    fn made(&mut self, env: &Env<'_, Infallible>, mut response: Response, settle: bool) {
        let delivery = self.delivery.as_ref().map_or(0, |d| d.held);
        let budget = env.budget().clone();
        // Storage past the whole limit never fits, and this exchange
        // answers that itself with `503`: it is not charged, so it is not
        // taken for a need of the child's that no release could meet. A
        // body poll's refusal instead belongs to the child runner.
        let storable = response.fields.capacity() <= budget.limit()
            && response.body.capacity() <= budget.limit();
        let fits = storable && self.hold(env, response_held(&response) + delivery);
        let settled = if fits && settle && matches!(response.body, Body::Stream(_)) {
            let waker = env.waker();
            response
                .body
                .settle(&mut Context::from_waker(&waker), &budget)
                .is_ok()
        } else {
            fits
        };
        let response = if settled && response.fields.repay(&budget) && response.body.admit(&budget)
        {
            response
        } else {
            drop(response);
            let mut response = over_budget(&super::super::Responses::unpooled(&budget));
            if !self.hold(env, response_held(&response) + delivery)
                || !response.fields.repay(&budget)
                || !response.body.admit(&budget)
            {
                self.reset();
                return;
            }
            response
        };
        self.stage = Stage::Made(response);
    }

    /// The response's head, with the framing fields the shared policy
    /// chose.
    fn start(&mut self, response: Response) {
        let mut parts = response;
        let body = std::mem::take(&mut parts.body);
        if let Some(delivery) = &mut self.delivery {
            delivery.response(&parts);
        }
        // No `Date` here: the connection adds it when it frames the head.
        let policy =
            ResponsePolicy::new(&parts, body.remaining(), self.wants, || None, self.alt_svc);
        // Room for the length and the advertisement the policy may add.
        let Ok(mut headers) =
            HeaderMap::try_with_capacity(parts.fields.iter().len().saturating_add(2))
        else {
            self.reset();
            return;
        };
        for (name, value) in parts.fields.iter() {
            let (Ok(name), Ok(value)) =
                (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
            else {
                self.reset();
                return;
            };
            if matches!(
                name.as_str(),
                "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
            ) {
                continue;
            }
            headers.append(name, value);
        }
        // Preserve a valid field that agrees with the response policy. On
        // 304 it describes the selected representation, not the absent body.
        let supplied = super::content_length(&headers)
            .ok()
            .flatten()
            .filter(|&length| {
                policy.len == Some(length) || parts.status == StatusCode::NOT_MODIFIED
            })
            .and_then(|_| headers.get("content-length").cloned());
        headers.remove(http::header::CONTENT_LENGTH);
        if let Some(length) = supplied {
            headers.insert(http::header::CONTENT_LENGTH, length);
        } else if let Some(length) = policy.len {
            headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        if let Some(alt_svc) = policy.alt_svc {
            headers.append(
                http::header::ALT_SVC,
                HeaderValue::from_static(alt_svc.value()),
            );
        }
        let end = policy.bodiless || body.is_end_stream();
        self.next = Some(ExchangeCommand::Head(Box::new(ResponseHead {
            status: parts.status,
            headers,
            end,
        })));
        if end {
            self.stage = Stage::Done;
            return;
        }
        self.stage = match body {
            Body::Full(bytes) => {
                self.rest = bytes;
                Stage::Body(None)
            }
            stream => Stage::Body(Some(stream)),
        };
    }

    /// Splits a body without copying; its backing retains the reservation.
    fn piece(&mut self) -> Chunk {
        let piece = self.rest.split_to(self.rest.len().min(PIECE));
        if self.rest.is_empty() {
            self.rest = Chunk::default();
        }
        piece
    }

    fn reset(&mut self) {
        self.stage = Stage::Done;
        self.rest = Chunk::default();
        self.work = None;
        self.next = Some(ExchangeCommand::Reset(ErrorCode::InternalError));
    }

    /// Moves the response on by one command, once the last was taken.
    fn respond(&mut self) -> bool {
        if self.next.is_some() {
            return false;
        }
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Made(response) => {
                self.start(response);
                true
            }
            Stage::Body(body) if !self.rest.is_empty() => {
                self.stage = Stage::Body(body);
                self.next = Some(ExchangeCommand::Data(self.piece()));
                true
            }
            Stage::Body(Some(body)) => {
                self.generation += 1;
                self.work = Some(Work {
                    generation: self.generation,
                    op: Op::Frame(Some(body)),
                });
                self.stage = Stage::Polling;
                true
            }
            Stage::Body(None) => {
                self.next = Some(ExchangeCommand::End);
                true
            }
            Stage::Ending(trailers) => {
                self.next = Some(match trailers {
                    Some(trailers) => ExchangeCommand::Trailers(trailers),
                    None => ExchangeCommand::End,
                });
                true
            }
            stage => {
                self.stage = stage;
                false
            }
        }
    }
}

impl Layer for Respond {
    type Lower = HttpExchange;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Work;
    type Done = Done;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: ExchangeEvent,
    ) -> Result<fictionet::stdlib::layer::Admit<ExchangeEvent>, Infallible> {
        let collecting = matches!(self.stage, Stage::Collecting) && !self.ended;
        match event {
            ExchangeEvent::Data(chunk) if collecting => self.collect(env, chunk),
            // A body past its answer is dropped as it comes.
            ExchangeEvent::Data(_) => {}
            ExchangeEvent::Trailers(_) | ExchangeEvent::End if collecting => {
                self.dispatch(env, Received::Complete);
            }
            ExchangeEvent::Trailers(_) | ExchangeEvent::End => {}
            // The body limit comes before the budget, as it does for bytes
            // the connection could hold.
            ExchangeEvent::Overflow(dropped) if collecting => {
                let past = self.collected() as u64 + dropped > self.responder.limits.body as u64;
                let received = if past {
                    Received::TooLarge
                } else {
                    Received::Budget
                };
                self.dispatch(env, received);
            }
            ExchangeEvent::Overflow(_) => {}
            ExchangeEvent::Written(n) => {
                if let Some(delivery) = &mut self.delivery {
                    delivery.written(n);
                }
            }
            ExchangeEvent::Closed { why, written } => {
                if let Some(mut delivery) = self.delivery.take() {
                    delivery.written(written);
                    delivery.end(why == Ending::Done);
                }
                self.stage = Stage::Done;
                self.work = None;
                self.next = None;
            }
        }
        Ok(fictionet::stdlib::layer::Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<fictionet::stdlib::layer::Admit<Infallible>, Infallible> {
        match command {}
    }

    fn on_timer(&mut self, env: &mut Env<'_, Infallible>, _: ()) -> Result<bool, Infallible> {
        if self.deadline.is_none_or(|at| at > env.now()) {
            return Ok(false);
        }
        self.deadline = None;
        if matches!(self.stage, Stage::Collecting) {
            self.dispatch(env, Received::Timeout);
        }
        Ok(true)
    }

    fn on_done(&mut self, env: &mut Env<'_, Infallible>, done: Done) -> Result<(), Infallible> {
        if done.generation != self.generation {
            return Ok(());
        }
        match done.answer {
            Answer::Made(_) if !matches!(self.stage, Stage::Making) => {}
            Answer::Made(Ok(response)) => self.made(env, response, true),
            // An error on the stream's work resets it unanswered.
            Answer::Made(Err(error)) if error.is::<Reset>() => self.reset(),
            Answer::Made(Err(error)) => self.made(
                env,
                error_response(&super::super::Responses::unpooled(env.budget()), &error),
                false,
            ),
            Answer::Frame(..) if !matches!(self.stage, Stage::Polling) => {}
            Answer::Frame(body, Some(Ok(mut chunk))) => {
                if chunk.repay(env.budget()) {
                    self.rest = chunk;
                    self.stage = Stage::Body(Some(body));
                } else {
                    self.reset();
                }
            }
            Answer::Frame(mut body, None) => {
                let trailers = body.take_trailers().map(|fields| {
                    let mut headers = HeaderMap::new();
                    for (name, value) in fields.iter() {
                        headers.append(
                            HeaderName::from_bytes(name).expect("validated name"),
                            HeaderValue::from_bytes(value).expect("validated value"),
                        );
                    }
                    Box::new(headers)
                });
                self.stage = Stage::Ending(trailers);
            }
            Answer::Frame(_, Some(Err(_))) => self.reset(),
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        if matches!(self.stage, Stage::Collecting) && self.ended && self.head.is_some() {
            self.dispatch(env, Received::Complete);
            return Ok(true);
        }
        Ok(self.respond())
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<ExchangeCommand> {
        self.next.take()
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<Work> {
        self.work.take()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.deadline.map(|at| (at, ()))
    }
}

/// A handler's answer on its way.
type Making = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send>>;

/// Work [`Respond`] asks the world to do: make a handler's async answer, or
/// poll a streamed body for its next frame.
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
    Made(Result<Response, Error>),
    /// The body back, with its next frame or its end.
    Frame(Body, Option<Result<Chunk, Error>>),
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
                    Some(body) => ready!(body.poll_next(cx)),
                    None => None,
                };
                Answer::Frame(body.take().unwrap_or_default(), frame)
            }
        };
        Poll::Ready(Done { generation, answer })
    }
}

/// Keeps `piece` with the request body collected in `body`, in room
/// charged to `budget` before it is allocated, and moves nothing already
/// kept. A body whose `length` is known, within the limit, takes one
/// segment of exactly that length with its first bytes and never grows;
/// one of unknown length, at most `most` bytes, grows by a segment at a
/// time ([`ChargedSegments::extend`]). `false`, with the body as it was,
/// when the budget has no room for the piece.
pub(super) fn collect_into(
    body: &mut Option<ChargedSegments>,
    piece: &[u8],
    length: Option<usize>,
    most: usize,
    budget: &Budget,
) -> bool {
    if body.is_none() {
        *body = match length {
            Some(length) => ChargedSegments::with_capacity(budget, length),
            None => Some(ChargedSegments::new(budget)),
        };
    }
    let Some(body) = body else {
        return false;
    };
    body.extend(piece, length.unwrap_or(most))
}

pub(super) fn response_held(response: &Response) -> usize {
    fields_held(response.fields.len(), response.fields.octets())
}

/// What the head of a response with `count` fields of `octets` name and
/// value bytes holds once its fields are in a header map: the map's
/// rounded capacity plus duplicate slots, under the same public-size
/// accounting as `headers_held`, and the octets. Field backing storage
/// carries its own reservation until conversion finishes.
fn fields_held(count: usize, octets: usize) -> usize {
    count
        .saturating_add(1)
        .saturating_mul(4)
        .saturating_mul(std::mem::size_of::<(HeaderName, HeaderValue)>())
        .saturating_add(20)
        .saturating_add(octets)
}

/// What a stream holds from its opening so that it can always answer
/// `503`: the head of [`over_budget`]'s response, which has one field. A
/// stream the budget has no room for this is refused before its handler
/// runs.
fn answer_reserve() -> usize {
    fields_held(1, "content-type".len() + "text/plain; charset=utf-8".len())
}

fn over_budget(storage: &super::super::Responses) -> Response {
    text(
        storage,
        StatusCode::SERVICE_UNAVAILABLE,
        "The server cannot hold this response now.\n",
    )
}

/// Counted proofs of how a request body is collected (Resource properties
/// in verification/README.md).
#[cfg(kani)]
#[path = "../../../../../verification/http/kani/collect.rs"]
mod collect_proofs;

#[cfg(test)]
mod tests {
    use super::*;

    /// A body whose `content-length` is known takes one allocation of
    /// that length with its first bytes, and every later piece goes in it:
    /// the budget holds the length and one place from the first piece to
    /// the last, and nothing moves. Before, the body doubled as it came,
    /// and each growth needed the old allocation beside the new.
    #[test]
    fn a_body_of_known_length_is_reserved_once() {
        const LENGTH: usize = 8800;
        let budget = Budget::new(LENGTH + ChargedSegments::PLACE);
        let mut body = None;
        let mut at = None;
        for piece in [b'e'; LENGTH].chunks(37) {
            assert!(collect_into(
                &mut body,
                piece,
                Some(LENGTH),
                LENGTH,
                &budget
            ));
            let kept = body.as_ref().unwrap();
            assert_eq!(kept.pieces().len(), 1);
            let first = kept.pieces()[0].as_ptr();
            assert_eq!(*at.get_or_insert(first), first, "the body moved");
            assert!(budget.used() <= LENGTH + ChargedSegments::PLACE);
        }
        let body = Body::from_segments(body.unwrap(), &budget).unwrap();
        assert_eq!(
            body.bytes().unwrap().as_ptr(),
            at.unwrap(),
            "handed on where it lies"
        );
        assert_eq!(body.remaining(), Some(LENGTH as u64));
        drop(body);
        assert_eq!(budget.used(), 0);
    }
}
