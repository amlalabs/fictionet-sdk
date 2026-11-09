//! A [`Handler`] on one HTTP/2 exchange.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::SystemTime;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body::{Body as _, Frame};

use fictionet::stdlib::layer::{Chain, Charge, Children, Chunk, Env, Layer, Top};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::protocols::http2::{ErrorCode, Setting};
use fictionet::stdlib::services::stack::Job;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::super::response::{Asked, ResponsePolicy, date_header, error_response};
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

    /// Says which connection this is: handlers find it in each request's
    /// extensions and in their [`Exchange`].
    pub fn conn(mut self, conn: ConnInfo) -> Self {
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
        request: Request<Body>,
    ) -> Http2Server {
        let (parts, body) = request.into_parts();
        let mut head = Request::from_parts(parts, ());
        *head.version_mut() = http::Version::HTTP_2;
        let body = body
            .bytes()
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| Chunk::new(bytes.to_vec()));
        let opening = Opening {
            request: Box::new(head),
            ended: body.is_none(),
            at: Instant::ZERO,
            charge: None,
        };
        self.server(Http2::upgraded(self.limits, settings, opening, body))
    }

    fn server(&self, connection: Http2) -> Http2Server {
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
    /// What this exchange holds: the request's head and body, then the
    /// response's head and the body bytes not yet sent.
    charge: Option<Charge>,
    body: Vec<u8>,
    deadline: Option<Instant>,
    /// The request ended before it was answered.
    ended: bool,
    stage: Stage,
    wants: Asked,
    delivery: Option<Delivery>,
    /// The next command, for the connection to take.
    next: Option<ExchangeCommand>,
    /// Body bytes held in full, not yet sent.
    rest: Bytes,
    generation: u64,
    work: Option<Work>,
}

enum Stage {
    /// Collecting the request's body.
    Collecting,
    /// The handler's work is making the response.
    Making,
    /// The response, to start.
    Made(Response<Body>),
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
                body: Vec::new(),
                deadline,
                ended: opening.ended,
                stage: Stage::Collecting,
                wants: Asked::Body,
                delivery: None,
                next: None,
                rest: Bytes::new(),
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
            Some(charge) => charge.set(bytes),
            None => {
                self.charge = env.budget().charge(bytes);
                self.charge.is_some()
            }
        }
    }

    fn held(&self) -> usize {
        self.charge.as_ref().map_or(0, Charge::bytes)
    }

    /// The request's body grows by `chunk`.
    fn collect(&mut self, env: &mut Env<'_, Infallible>, chunk: Chunk) {
        let limits = self.responder.limits;
        if self.body.len().saturating_add(chunk.len()) > limits.body {
            return self.dispatch(env, Received::TooLarge);
        }
        let growth = (self.body.len() + chunk.len()).saturating_sub(self.body.capacity());
        let held = self.held();
        if !self.hold(env, held + growth) || self.body.try_reserve_exact(chunk.len()).is_err() {
            return self.dispatch(env, Received::Budget);
        }
        self.body.extend_from_slice(&chunk);
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
        let mut request = Request::from_parts(parts, Body::from(std::mem::take(&mut self.body)));
        request.extensions_mut().insert(responder.conn.clone());
        self.wants = Asked::of(request.method());
        let now = env.now();
        self.delivery = Delivery::new(&responder.observe, &request, &responder.conn, now, received);
        let reply = match received {
            Received::Complete => responder.handler.call(
                request,
                &mut Exchange::new(now, env.entropy(), &responder.conn),
            ),
            Received::TooLarge => Reply::Now(text(
                StatusCode::PAYLOAD_TOO_LARGE,
                "The request body is too large.\n",
            )),
            Received::Budget => Reply::Now(text(
                StatusCode::SERVICE_UNAVAILABLE,
                "The server cannot hold this request now.\n",
            )),
            Received::Timeout => Reply::Now(text(
                StatusCode::REQUEST_TIMEOUT,
                "The request body took too long.\n",
            )),
            Received::CutOff => Reply::Now(text(
                StatusCode::BAD_REQUEST,
                "The request body was cut off.\n",
            )),
        };
        match reply {
            Reply::Now(response) => self.made(env, response),
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
    fn made(&mut self, env: &Env<'_, Infallible>, response: Response<Body>) {
        let delivery = self.delivery.as_ref().map_or(0, |d| d.held);
        let response = if self.hold(env, response_held(&response) + delivery) {
            response
        } else {
            let response = over_budget();
            // Less than the request held, so it fits.
            self.hold(env, response_held(&response) + delivery);
            response
        };
        self.stage = Stage::Made(response);
    }

    /// The response's head, with the framing fields the shared policy
    /// chose.
    fn start(&mut self, env: &Env<'_, Infallible>, response: Response<Body>) {
        let (parts, body) = response.into_parts();
        if let Some(delivery) = &mut self.delivery {
            delivery.response(&parts);
        }
        let date = date_header(self.responder.date, env.now());
        let policy = ResponsePolicy::new(&parts, body.size_hint().exact(), self.wants, date);
        let mut headers = HeaderMap::with_capacity(parts.headers.len() + 2);
        for (name, value) in &parts.headers {
            if matches!(
                name.as_str(),
                "connection"
                    | "content-length"
                    | "proxy-connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "upgrade"
            ) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        // Preserve a valid field that agrees with the response policy. On
        // 304 it describes the selected representation, not the absent body.
        let supplied = super::content_length(&parts.headers)
            .ok()
            .flatten()
            .filter(|&length| {
                policy.len == Some(length) || parts.status == StatusCode::NOT_MODIFIED
            })
            .and_then(|_| parts.headers.get("content-length"));
        if let Some(length) = supplied {
            headers.insert(http::header::CONTENT_LENGTH, length.clone());
        } else if let Some(length) = policy.len {
            headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        if let Some(date) = policy.date {
            headers.insert(http::header::DATE, date);
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
        self.stage = match body.0 {
            super::super::body::Inner::Full(bytes) => {
                self.rest = bytes.unwrap_or_default();
                Stage::Body(None)
            }
            stream => Stage::Body(Some(Body(stream))),
        };
    }

    /// The next piece of the body held in full, carrying its share of the
    /// charge.
    fn piece(&mut self, env: &Env<'_, Infallible>) -> Option<Chunk> {
        let piece = self.rest.split_to(self.rest.len().min(PIECE));
        if self.rest.is_empty() {
            self.rest = Bytes::new();
        }
        let charge = match self.charge.as_mut().and_then(|c| c.split(piece.len())) {
            Some(charge) => charge,
            None => env.budget().charge(piece.len())?,
        };
        Some(Chunk::with_charge(piece.to_vec(), charge))
    }

    fn reset(&mut self) {
        self.stage = Stage::Done;
        self.rest = Bytes::new();
        self.work = None;
        self.next = Some(ExchangeCommand::Reset(ErrorCode::InternalError));
    }

    /// Moves the response on by one command, once the last was taken.
    fn respond(&mut self, env: &mut Env<'_, Infallible>) -> bool {
        if self.next.is_some() {
            return false;
        }
        match std::mem::replace(&mut self.stage, Stage::Done) {
            Stage::Made(response) => {
                self.start(env, response);
                true
            }
            Stage::Body(body) if !self.rest.is_empty() => {
                self.stage = Stage::Body(body);
                match self.piece(env) {
                    Some(chunk) => self.next = Some(ExchangeCommand::Data(chunk)),
                    None => self.reset(),
                }
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
                let past = state.body.len() as u64 + dropped > state.responder.limits.body as u64;
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

    fn on_timer(&mut self, env: &mut Env<'_, Infallible>, _: ()) -> Result<(), Infallible> {
        let state = &mut *self.state;
        if state.deadline.is_some_and(|at| at <= env.now()) {
            state.deadline = None;
            if matches!(state.stage, Stage::Collecting) {
                state.dispatch(env, Received::Timeout);
            }
        }
        Ok(())
    }

    fn on_done(&mut self, env: &mut Env<'_, Infallible>, done: Done) -> Result<(), Infallible> {
        let state = &mut *self.state;
        if done.generation != state.generation {
            return Ok(());
        }
        match done.answer {
            Answer::Made(_) if !matches!(state.stage, Stage::Making) => {}
            Answer::Made(Ok(response)) => state.made(env, response),
            // An error on the stream's work resets it unanswered.
            Answer::Made(Err(error)) if error.is::<Reset>() => state.reset(),
            Answer::Made(Err(error)) => state.made(env, error_response(&error)),
            Answer::Frame(..) if !matches!(state.stage, Stage::Polling) => {}
            Answer::Frame(body, Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    // The head is out, so a chunk the budget cannot hold
                    // resets this stream alone.
                    let held = state.held();
                    if !data.is_empty() && !state.hold(env, held + data.len()) {
                        state.reset();
                    } else {
                        state.rest = data;
                        state.stage = Stage::Body(Some(body));
                    }
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => state.stage = Stage::Ending(Some(Box::new(trailers))),
                    Err(_) => state.stage = Stage::Body(Some(body)),
                },
            },
            Answer::Frame(_, None) => state.stage = Stage::Ending(None),
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
        Ok(state.respond(env))
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
type Making = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

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
                // A body all there now goes out with the head, without
                // work of its own.
                Answer::Made(made.map(|mut response| {
                    response.body_mut().settle(cx);
                    response
                }))
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

pub(super) fn response_held(response: &Response<Body>) -> usize {
    let headers = response.headers();
    let slots = headers.capacity() + headers.len() - headers.keys_len();
    response.body().full_len()
        + slots * std::mem::size_of::<(HeaderName, HeaderValue)>()
        + headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
}

fn over_budget() -> Response<Body> {
    text(
        StatusCode::SERVICE_UNAVAILABLE,
        "The server cannot hold this response now.\n",
    )
}
