//! A [`Handler`] on one HTTP/2 exchange.
use crate::stdlib::web::Response;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};

use fictionet::stdlib::layer::{Chain, Charge, ChargedBytes, Children, Chunk, Env, Layer, Top};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::protocols::http2::{ErrorCode, Setting};
use fictionet::stdlib::services::stack::Job;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::super::response::{Asked, ResponsePolicy, error_response};
use super::super::{
    Body, Delivery, Exchange, Handler, Later, Limits, Observe, PIECE, Received, Reply, Reset, text,
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

    /// HTTP/2 after an HTTP/1 `Upgrade: h2c`: `request`, whose whole body
    /// came over HTTP/1, is stream 1, and the client's `settings` apply.
    pub(in super::super) fn upgraded(
        &self,
        settings: &[Setting],
        request: crate::stdlib::web::Request,
    ) -> Option<Http2Server> {
        let parts = request.head.to_http().ok()?;
        let body = request.body;
        let mut head = Request::from_parts(parts, ());
        *head.version_mut() = http::Version::HTTP_2;
        let body = body
            .bytes()
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| Chunk::unpaid(bytes.to_vec()));
        let opening = Opening {
            request: Box::new(head),
            ended: body.is_none(),
            at: Instant::ZERO,
            charge: None,
        };
        Some(self.server(Http2::upgraded(self.limits, settings, opening, body)))
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
            Children::new(limit, Http2::WINDOW, move |_, opening, _| {
                Some(Respond::new(shared.clone(), opening))
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
pub struct Respond {
    state: Box<State>,
}

struct State {
    responder: Arc<Responder>,
    head: Option<Request<()>>,
    /// What this exchange holds besides the request's body: the request's
    /// head, then the response's head. Response chunks carry their own charge.
    charge: Option<Charge>,
    /// The request's body as it is collected, which carries its charge.
    body: Option<ChargedBytes>,
    deadline: Option<Instant>,
    /// The request ended before it was answered.
    ended: bool,
    stage: Stage,
    wants: Asked,
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
    fn new(responder: Arc<Responder>, opening: Opening) -> Respond {
        let deadline = (!opening.ended).then(|| opening.at + responder.limits.body_timeout);
        Respond {
            state: Box::new(State {
                responder,
                head: Some(*opening.request),
                charge: opening.charge,
                body: None,
                deadline,
                ended: opening.ended,
                stage: Stage::Collecting,
                wants: Asked::Body,
                delivery: None,
                next: None,
                rest: Chunk::default(),
                generation: 0,
                work: None,
            }),
        }
    }
}

impl State {
    /// Charges `bytes` in place of what is charged now. Returns whether it
    /// fits.
    fn hold(&mut self, env: &Env<'_, Infallible>, bytes: usize) -> bool {
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
    /// allocated.
    fn collect(&mut self, env: &mut Env<'_, Infallible>, chunk: Chunk) {
        let limits = self.responder.limits;
        let len = self.collected();
        if len.saturating_add(chunk.len()) > limits.body {
            return self.dispatch(env, Received::TooLarge);
        }
        let room = match &mut self.body {
            Some(body) => body.grow_to(len + chunk.len()),
            None => {
                self.body = ChargedBytes::with_capacity(env.budget(), chunk.len());
                self.body.is_some()
            }
        };
        if !room
            || self
                .body
                .as_mut()
                .is_none_or(|body| body.extend_within(&chunk).is_err())
        {
            self.dispatch(env, Received::Budget);
        }
    }

    /// Answers the request: with the handler for a whole one, or with the
    /// status for one that could not be received.
    fn dispatch(&mut self, env: &mut Env<'_, Infallible>, received: Received) {
        let Some(head) = self.head.take() else {
            return;
        };
        self.deadline = None;
        let responder = self.responder.clone();
        let (parts, ()) = head.into_parts();
        let body = self.body.take().map(Chunk::from).unwrap_or_default();
        let uri = &parts.uri;
        let target = [
            uri.scheme_str().unwrap_or(""),
            if uri.scheme().is_some() { "://" } else { "" },
            uri.authority().map_or("", |a| a.as_str()),
            uri.path(),
            if uri.query().is_some() { "?" } else { "" },
            uri.query().unwrap_or(""),
        ];
        let size = parts.headers.iter().fold(
            target
                .iter()
                .try_fold(parts.method.as_str().len(), |len, part| {
                    len.checked_add(part.len())
                }),
            |size, (name, value)| {
                size?.checked_add(crate::stdlib::web::Head::record_size(
                    name.as_str().len(),
                    value.as_bytes().len(),
                )?)
            },
        );
        let Some(block) = size.and_then(|size| {
            let charge = env.budget().charge(size)?;
            Some(
                Chunk::paid(vec![0; size], charge)
                    .expect("reserved head")
                    .slice(0..0),
            )
        }) else {
            self.reset();
            return;
        };
        let mut head = crate::stdlib::web::Head::in_block(
            block,
            parts.method.as_str(),
            &target,
            crate::stdlib::protocols::http1::Version::Http2,
        )
        .expect("reserved request head");
        for (name, value) in &parts.headers {
            head.push(name.as_str(), value.as_bytes())
                .expect("reserved field records");
        }
        drop(parts);
        if responder.observe.is_none()
            && let Some(charge) = &mut self.charge
        {
            // Release request storage but keep the admission owner's view.
            // Response refusals are handled here, outside the runner's view.
            charge.shrink_to(0);
        }
        let request = crate::stdlib::web::Request {
            head,
            body: Body::from(body),
            site: responder.site.clone(),
        };
        self.wants = Asked::of(request.head.method());
        let now = env.now();
        self.delivery = Delivery::new(&responder.observe, &request, &responder.conn, now, received);
        let responses = super::super::Responses::unpooled(env.budget());
        let reply = match received {
            Received::Complete => responder.handler.call(
                request,
                &mut Exchange::new(now, env.entropy(), &responder.conn, responses.clone()),
            ),
            Received::TooLarge => Reply::Now(text(
                &responses,
                StatusCode::PAYLOAD_TOO_LARGE,
                "The request body is too large.\n",
            )),
            Received::Budget => Reply::Now(text(
                &responses,
                StatusCode::SERVICE_UNAVAILABLE,
                "The server cannot hold this request now.\n",
            )),
            Received::Timeout => Reply::Now(text(
                &responses,
                StatusCode::REQUEST_TIMEOUT,
                "The request body took too long.\n",
            )),
            Received::CutOff => Reply::Now(text(
                &responses,
                StatusCode::BAD_REQUEST,
                "The request body was cut off.\n",
            )),
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
        let fits = self.hold(env, response_held(&response) + delivery);
        // Response admission uses the head's account: this owner handles
        // its refusal with a service-unavailable response. A body poll's
        // refusal instead belongs to the child runner and resets the stream.
        let budget = self
            .charge
            .as_ref()
            .map_or_else(|| env.budget().clone(), |charge| charge.budget().clone());
        let settled = if fits && settle && matches!(response.body, Body::Stream(_)) {
            let waker = env.waker();
            response
                .body
                .settle(&mut Context::from_waker(&waker), &budget)
                .is_ok()
        } else {
            fits
        };
        let response = if settled && response.fields.admit(&budget) && response.body.admit(&budget)
        {
            response
        } else {
            drop(response);
            let mut response = over_budget(&super::super::Responses::unpooled(&budget));
            if !self.hold(env, response_held(&response) + delivery)
                || !response.fields.admit(&budget)
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
        let policy = ResponsePolicy::new(&parts, body.remaining(), self.wants, || None);
        let Ok(mut headers) =
            HeaderMap::try_with_capacity(parts.fields.iter().len().saturating_add(1))
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
        let state = &mut *self.state;
        let collecting = matches!(state.stage, Stage::Collecting) && !state.ended;
        match event {
            ExchangeEvent::Data(chunk) if collecting => state.collect(env, chunk),
            // A body past its answer is dropped as it comes.
            ExchangeEvent::Data(_) => {}
            ExchangeEvent::Trailers(_) | ExchangeEvent::End if collecting => {
                state.dispatch(env, Received::Complete);
            }
            ExchangeEvent::Trailers(_) | ExchangeEvent::End => {}
            // The body limit comes before the budget, as it does for bytes
            // the connection could hold.
            ExchangeEvent::Overflow(dropped) if collecting => {
                let past = state.collected() as u64 + dropped > state.responder.limits.body as u64;
                let received = if past {
                    Received::TooLarge
                } else {
                    Received::Budget
                };
                state.dispatch(env, received);
            }
            ExchangeEvent::Overflow(_) => {}
            ExchangeEvent::Written(n) => {
                if let Some(delivery) = &mut state.delivery {
                    delivery.written(n);
                }
            }
            ExchangeEvent::Closed { why, written } => {
                if let Some(mut delivery) = state.delivery.take() {
                    delivery.written(written);
                    delivery.end(why == Ending::Done);
                }
                state.stage = Stage::Done;
                state.work = None;
                state.next = None;
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
        let state = &mut *self.state;
        if state.deadline.is_none_or(|at| at > env.now()) {
            return Ok(false);
        }
        state.deadline = None;
        if matches!(state.stage, Stage::Collecting) {
            state.dispatch(env, Received::Timeout);
        }
        Ok(true)
    }

    fn on_done(&mut self, env: &mut Env<'_, Infallible>, done: Done) -> Result<(), Infallible> {
        let state = &mut *self.state;
        if done.generation != state.generation {
            return Ok(());
        }
        match done.answer {
            Answer::Made(_) if !matches!(state.stage, Stage::Making) => {}
            Answer::Made(Ok(response)) => state.made(env, response, true),
            // An error on the stream's work resets it unanswered.
            Answer::Made(Err(error)) if error.is::<Reset>() => state.reset(),
            Answer::Made(Err(error)) => state.made(
                env,
                error_response(&super::super::Responses::unpooled(env.budget()), &error),
                false,
            ),
            Answer::Frame(..) if !matches!(state.stage, Stage::Polling) => {}
            Answer::Frame(body, Some(Ok(mut chunk))) => {
                if chunk.repay(env.budget()) {
                    state.rest = chunk;
                    state.stage = Stage::Body(Some(body));
                } else {
                    state.reset();
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
                state.stage = Stage::Ending(trailers);
            }
            Answer::Frame(_, Some(Err(_))) => state.reset(),
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        let state = &mut *self.state;
        if matches!(state.stage, Stage::Collecting) && state.ended && state.head.is_some() {
            state.dispatch(env, Received::Complete);
            return Ok(true);
        }
        Ok(state.respond())
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<ExchangeCommand> {
        self.state.next.take()
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<Work> {
        self.state.work.take()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.state.deadline.map(|at| (at, ()))
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

pub(super) fn response_held(response: &Response) -> usize {
    // Bound HeaderMap's rounded capacity plus duplicate slots, under the
    // same public-size accounting as headers_held. Field backing storage
    // carries its own reservation until conversion finishes.
    let slots = response
        .fields
        .iter()
        .len()
        .saturating_add(1)
        .saturating_mul(4);
    response.fields.iter().fold(
        slots
            .saturating_mul(std::mem::size_of::<(HeaderName, HeaderValue)>())
            .saturating_add(20),
        |held, (name, value)| held.saturating_add(name.len()).saturating_add(value.len()),
    )
}

fn over_budget(storage: &super::super::Responses) -> Response {
    text(
        storage,
        StatusCode::SERVICE_UNAVAILABLE,
        "The server cannot hold this response now.\n",
    )
}
