// Copyright (c) 2017 h2 authors
// Portions adapted from h2 under the MIT license; see LICENSE-h2 in this directory.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use http_body::Body as _;

use fictionet::stdlib::codec::{Fail, Wire};
use fictionet::stdlib::protocols::hpack;
use fictionet::stdlib::protocols::http2::{self as wire, ErrorCode, Frame, Input, Inputs};
use fictionet::stdlib::services::serve::{
    self, Done, Driver, Ended, Flow, Pending, PendingDriver,
};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, Error};

use super::response::{
    Asked, ResponsePolicy, error_response, request_held,
};
use super::{Body, Exchange, Handler, Later, Limits, Received, Reply, text};

/// HTTP/2 stream deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer {
    /// The next stream head or body deadline.
    Deadline,
}
const RESET_LIFETIME: Duration = Duration::from_secs(1);
const RESET_MAX: usize = 50;
const PENDING_RESET_MAX: usize = 20;
const ERROR_RESET_MAX: usize = 1024;

/// HTTP/2 for one connection, driven by bytes and the serve driver's clock.
/// Uses the shared frame codec and HPACK decoder, with independently scheduled
/// responses. No runtime is required, including in a [`serve::Harness`].
pub struct Http2 {
    handler: Arc<dyn Handler>,
    limits: Limits,
    pub(super) date: Option<u64>,
    headers: wire::HeaderBlocks,
    streams: BTreeMap<u32, Stream>,
    send: Arc<Mutex<Outbound>>,
    resets: VecDeque<(u32, Instant)>,
    last_stream: u32,
    received_settings: bool,
    awaiting_ack: bool,
    settings_deadline: Option<Instant>,
    continuations: usize,
    error_resets: usize,
    draining: bool,
    shutdown_ping: Option<[u8; 8]>,
    shutdown_requested: bool,
    goaway_last: Option<u32>,
}

struct Stream {
    request: Option<Request<Body>>,
    body: Vec<u8>,
    deadline: Option<Instant>,
    remaining: Option<u64>,
    recv_closed: bool,
}

impl Stream {
    /// The bytes its request's head and body hold.
    fn request_held(&self) -> usize {
        self.request.as_ref().map_or(0, request_held) + self.body.capacity()
    }
}

struct Outbound {
    recv_window: i32,
    window: i32,
    initial: i32,
    frame: usize,
    streams: BTreeMap<u32, Window>,
    pending_resets: usize,
    encoder: hpack::Encoder,
}

struct Window {
    recv_window: i32,
    available: i32,
    waker: Option<Waker>,
    accepted: bool,
}

impl Http2 {
    /// Answers requests using the default limits.
    pub fn new(handler: impl Handler) -> Self {
        Self::with(Arc::new(handler), Limits::default())
    }

    /// Answers requests using the supplied handler and limits.
    pub fn with(handler: Arc<dyn Handler>, limits: Limits) -> Self {
        Self {
            handler,
            limits,
            date: None,
            headers: wire::HeaderBlocks::with_limits(wire::Limits {
                header_list: limits.head.head,
                header_block: limits.head.head,
                ..wire::Limits::default()
            }),
            streams: BTreeMap::new(),
            send: Arc::new(Mutex::new(Outbound {
                window: 65_535,
                recv_window: 65_535,
                initial: 65_535,
                frame: wire::DEFAULT_FRAME_SIZE,
                streams: BTreeMap::new(),
                pending_resets: 0,
                encoder: hpack::Encoder::new(0),
            })),
            resets: VecDeque::with_capacity(RESET_MAX),
            last_stream: 0,
            received_settings: false,
            awaiting_ack: true,
            settings_deadline: None,
            continuations: 0,
            error_resets: 0,
            draining: false,
            shutdown_ping: None,
            shutdown_requested: false,
            goaway_last: None,
        }
    }


    /// Begins graceful shutdown on the next driver wake or input.
    /// A GOAWAY and PING round trip establishes which requests were in flight;
    /// those requests finish before the connection closes.
    pub fn graceful_shutdown(&mut self) {
        self.shutdown_requested = true;
    }

    fn arm(&self, driver: &mut Driver<'_, Inputs, Timer>) {
        let deadline = self
            .streams
            .values()
            .filter_map(|s| s.deadline)
            .chain(self.resets.front().map(|(_, at)| *at))
            .chain(self.settings_deadline)
            .min();
        if let Some(at) = deadline {
            driver.set_timer(
                Timer::Deadline,
                at.since_start().saturating_sub(driver.now().since_start()),
            );
        } else {
            driver.cancel_timer(Timer::Deadline);
        }
    }

    fn goaway(&mut self, code: ErrorCode, last: u32, driver: &mut Driver<'_, Inputs, Timer>) {
        let last = last.min(self.goaway_last.unwrap_or(wire::MAX_WINDOW));
        self.goaway_last = Some(last);
        write(
            &wire::GoAway {
                flags: 0,
                last_stream: last,
                code: code as u32,
                debug: Vec::new(),
            },
            driver.reply(),
        );
    }

    fn fail(&mut self, error: wire::Error, driver: &mut Driver<'_, Inputs, Timer>) -> Flow {
        self.goaway(error.code, self.last_stream, driver);
        Flow::Close
    }

    fn cancel(&mut self, id: u32, driver: &mut Driver<'_, Inputs, Timer>) {
        driver.cancel_keyed(u64::from(id));
        self.send.lock().streams.remove(&id);
        self.streams.remove(&id);
    }

    /// Resets stream `id` and ignores its late frames for a while.
    fn write_reset(&mut self, id: u32, code: ErrorCode, driver: &mut Driver<'_, Inputs, Timer>) {
        self.cancel(id, driver);
        write(
            &wire::Reset {
                stream: id,
                flags: 0,
                code: code as u32,
            },
            driver.reply(),
        );
        if self.resets.len() < RESET_MAX && !self.resets.iter().any(|(s, _)| *s == id) {
            self.resets.push_back((id, driver.now() + RESET_LIFETIME));
        }
    }

    /// Resets stream `id` for the client's error. Too many such resets end
    /// the connection.
    fn reset(
        &mut self,
        id: u32,
        code: ErrorCode,
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<(), wire::Error> {
        self.write_reset(id, code, driver);
        self.error_resets += 1;
        if self.error_resets > ERROR_RESET_MAX {
            return Err(problem(
                ErrorCode::EnhanceYourCalm,
                "too many local error resets",
            ));
        }
        Ok(())
    }

    fn ignored(&self, id: u32) -> bool {
        self.resets.iter().any(|(s, _)| *s == id)
    }

    /// Answers stream `id`'s request. `charged` is what the budget already
    /// counts for its head and body. That is nothing for a stream the
    /// current frame opened, and never the body bytes the current frame added.
    fn dispatch(
        &mut self,
        id: u32,
        received: Received,
        charged: usize,
        driver: &mut Driver<'_, Inputs, Timer>,
    ) {
        let stream = self.streams.get_mut(&id).expect("an admitted stream");
        stream.deadline = None;
        let held = stream.request_held();
        let mut request = stream.request.take().expect("request dispatched once");

        *request.body_mut() = Body::from(std::mem::take(&mut stream.body));
        let head_only = request.method() == Method::HEAD;
        let reply = match received {
            Received::Complete => self.handler.call(
                request,
                &mut Exchange::new(driver.now(), driver.entropy(), driver.conn()),
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
            Received::CutOff => Reply::Now(text(StatusCode::BAD_REQUEST, "The request body was cut off.\n")),
        };
        let (work, response) = match reply {
            Reply::Now(response) => {
                // The response replaces the request in the budget. One the
                // budget cannot hold gets 503 instead, so it does not end
                // the connection's other streams.
                let response = if fits(driver.budget(), response_held(&response), charged) {
                    response
                } else {
                    over_budget()
                };
                (None, Some(response))
            }
            Reply::Later(work) => (Some(work), None),

        };
        driver.defer_keyed(
            u64::from(id),
            Sending {
                id,
                send: self.send.clone(),
                // Only work still making its response holds the request.
                request_held: if work.is_some() { held } else { 0 },
                budget: driver.budget().cloned(),
                work,
                making: None,
                response,
                body: None,
                rest: Bytes::new(),
                rest_held: 0,
                head_only,
                date: self.date,
                asked: driver.now(),
                end_sent: false,
            },
        );
    }

    fn headers(
        &mut self,
        read: wire::BlockRead,
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<(), wire::Error> {
        let Some(block) = read.block else {
            return Ok(());
        };
        let id = read.stream;
        if id & 1 == 0 {
            return Err(problem(
                ErrorCode::ProtocolError,
                "client opened an even stream",
            ));
        }
        if self.ignored(id) {
            return Ok(());
        }
        if let Some(stream) = self.streams.get(&id) {
            if stream.recv_closed {
                return self.reset(id, ErrorCode::StreamClosed, driver);
            }
            if !read.end || !valid_trailers(&block) {
                return self.reset(id, ErrorCode::ProtocolError, driver);
            }
            if stream.remaining.is_some_and(|n| n != 0) {
                return self.reset(id, ErrorCode::ProtocolError, driver);
            }
            let stream = self.streams.get_mut(&id).unwrap();
            stream.recv_closed = true;
            if stream.request.is_some() {
                let charged = stream.request_held();
                self.dispatch(id, Received::Complete, charged, driver);
            }
            return Ok(());
        }
        if id <= self.last_stream {
            // A stream that ended, or one below an identifier already used
            // (RFC 9113 sections 5.1 and 5.1.1): either is a connection
            // error, and, as in h2, the two are not told apart.
            return Err(problem(
                ErrorCode::ProtocolError,
                "HEADERS on a closed stream",
            ));
        }
        self.last_stream = id;
        if self.draining || self.streams.len() >= self.limits.streams as usize {
            // A client can open streams before it reads our SETTINGS or GOAWAY,
            // so, as in h2, these refusals do not count as errors.
            self.write_reset(id, ErrorCode::RefusedStream, driver);
            return Ok(());
        }
        let list_size: usize = block
            .headers
            .iter()
            .map(|h| {
                h.name.as_ref().map_or(0, Vec::len) + h.value.as_ref().map_or(0, Vec::len) + 32
            })
            .sum();
        if block.more != 0
            || block.headers.len() > self.limits.head.headers
            || list_size > self.limits.head.head
        {
            let mut fragment = Vec::new();
            self.send
                .lock()
                .encoder
                .encode_block(&[hpack::Field::new(":status", "431")], &mut fragment)
                .expect("static header");
            write(
                &wire::Headers {
                    stream: id,
                    flags: 5,
                    fragment,
                    priority: None,
                    padding: None,
                },
                driver.reply(),
            );
            return self.reset(id, ErrorCode::RefusedStream, driver);
        }
        let Some(mut request) = request(block, self.limits) else {
            return self.reset(id, ErrorCode::ProtocolError, driver);
        };
        let remaining = match content_length(request.headers()) {
            Ok(n) => n,
            Err(()) => return self.reset(id, ErrorCode::ProtocolError, driver),
        };
        if read.end && remaining.is_some_and(|n| n != 0) {
            return self.reset(id, ErrorCode::ProtocolError, driver);
        }
        if !fits(
            driver.budget(),
            request_held(&request) + std::mem::size_of::<Stream>(),
            0,
        ) {


            return self.reset(id, ErrorCode::RefusedStream, driver);
        }
        request.extensions_mut().insert(driver.conn().clone());

        self.streams.insert(
            id,
            Stream {
                request: Some(request),
                body: Vec::new(),
                deadline: (!read.end).then_some(driver.now() + self.limits.body_timeout),
                remaining,
                recv_closed: read.end,
            },
        );
        let mut send = self.send.lock();
        let initial = send.initial;
        send.streams.insert(
            id,
            Window {
                recv_window: 65_535,
                available: initial,
                waker: None,
                accepted: false,
            },
        );
        drop(send);
        // Acceptance runs after the current input batch so a reset burst cannot
        // accumulate abandoned requests faster than the application drains them.
        driver.defer_keyed(0, Accept(self.send.clone()));
        if read.end {
            self.dispatch(id, Received::Complete, 0, driver);
        }
        Ok(())
    }

    fn data(
        &mut self,
        data: wire::Data,
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<(), wire::Error> {
        let id = data.stream;
        let size = data.data.len() + data.padding.as_ref().map_or(0, |p| p.len() + 1);
        let mut send = self.send.lock();
        send.recv_window -= size as i32;
        if send.recv_window < 0 {
            return Err(problem(
                ErrorCode::FlowControlError,
                "connection receive window exceeded",
            ));
        }
        drop(send);
        // The connection window counts every DATA frame, padding and frames for
        // reset streams included. Credit returns after the input batch, so DATA
        // sent before the client saw a WINDOW_UPDATE must fit the old window.
        driver.defer_keyed(0, Accept(self.send.clone()));
        if self.ignored(id) {
            return Ok(());
        }
        let Some(stream) = self.streams.get(&id) else {
            if id > self.last_stream || id & 1 == 0 {
                return Err(problem(ErrorCode::ProtocolError, "data on an idle stream"));
            }
            return self.reset(id, ErrorCode::StreamClosed, driver);
        };
        if stream.recv_closed {
            return self.reset(id, ErrorCode::StreamClosed, driver);
        }
        let mut send = self.send.lock();
        let window = send.streams.get_mut(&id).expect("an admitted stream");
        window.recv_window -= size as i32;
        if window.recv_window < 0 {
            drop(send);
            return self.reset(id, ErrorCode::FlowControlError, driver);
        }
        drop(send);
        let charged = stream.request_held();
        let growth = stream
            .body
            .len()
            .saturating_add(data.data.len())
            .saturating_sub(stream.body.capacity());
        let room = fits(driver.budget(), growth, 0);
        let stream = self.streams.get_mut(&id).unwrap();
        if let Some(remaining) = &mut stream.remaining {
            let Some(n) = remaining.checked_sub(data.data.len() as u64) else {
                return self.reset(id, ErrorCode::ProtocolError, driver);
            };
            *remaining = n;
            if data.flags & 1 != 0 && n != 0 {
                return self.reset(id, ErrorCode::ProtocolError, driver);
            }
        }
        stream.recv_closed = data.flags & 1 != 0;
        if stream.request.is_some() {
            if stream.body.len().saturating_add(data.data.len()) > self.limits.body {
                self.dispatch(id, Received::TooLarge, charged, driver);
            } else if !room || stream.body.try_reserve_exact(data.data.len()).is_err() {
                self.dispatch(id, Received::Budget, charged, driver);
            } else {
                stream.body.extend_from_slice(&data.data);
                if stream.recv_closed {
                    self.dispatch(id, Received::Complete, charged, driver);
                }
            }
        }
        Ok(())
    }

    fn frame(&mut self, frame: Frame, driver: &mut Driver<'_, Inputs, Timer>) -> Result<(), wire::Error> {
        if !self.received_settings && !matches!(&frame, Frame::Settings(s) if s.flags & 1 == 0) {
            return Err(problem(
                ErrorCode::ProtocolError,
                "first frame is not SETTINGS",
            ));
        }
        if matches!(frame, Frame::Continuation(_)) {
            self.continuations += 1;
            let minimum = (self.limits.head.head / wire::DEFAULT_FRAME_SIZE).max(1);
            if self.continuations > minimum.saturating_add(minimum >> 2).max(5) {
                return Err(problem(
                    ErrorCode::EnhanceYourCalm,
                    "too many continuation frames",
                ));
            }
        } else {
            self.continuations = 0;
        }
        let headers = self.headers.read_frame(&frame)?;
        match frame {
            // A stream that depends on itself is a stream error (RFC 9113
            // section 5.3.1). Its block was decoded above, so HPACK stays in step.
            Frame::Headers(h) if h.priority.is_some_and(|p| p.stream == h.stream) => {
                if h.stream & 1 == 0 {
                    return Err(problem(
                        ErrorCode::ProtocolError,
                        "client opened an even stream",
                    ));
                }
                self.last_stream = self.last_stream.max(h.stream);
                self.reset(h.stream, ErrorCode::ProtocolError, driver)?;
            }
            Frame::Headers(_) | Frame::Continuation(_) => self.headers(headers, driver)?,
            Frame::Data(data) => self.data(data, driver)?,
            Frame::Settings(settings) => {
                if settings.flags & 1 != 0 {
                    if !self.awaiting_ack {
                        return Err(problem(
                            ErrorCode::ProtocolError,
                            "unexpected SETTINGS acknowledgment",
                        ));
                    }
                    self.awaiting_ack = false;
                    self.settings_deadline = None;
                } else {
                    self.received_settings = true;
                    write(
                        &wire::Settings {
                            flags: 1,
                            entries: Vec::new(),
                        },
                        driver.reply(),
                    );
                    let mut send = self.send.lock();
                    for setting in settings.entries {
                        match setting.id {
                            1 => send.encoder.set_settings_limit(setting.value as usize),
                            4 => {
                                let initial = setting.value as i32;
                                let delta = initial - send.initial;
                                for window in send.streams.values_mut() {
                                    window.available =
                                        window.available.checked_add(delta).ok_or_else(|| {
                                            problem(
                                                ErrorCode::FlowControlError,
                                                "initial window overflow",
                                            )
                                        })?;
                                    if let Some(waker) = window.waker.take() {
                                        waker.wake();
                                    }
                                }
                                send.initial = initial;
                            }
                            5 => send.frame = setting.value as usize,
                            _ => {}
                        }
                    }
                }
            }
            Frame::WindowUpdate(update) => {
                let mut send = self.send.lock();
                if update.stream == 0 {
                    send.window = send
                        .window
                        .checked_add(update.increment as i32)
                        .ok_or_else(|| {
                            problem(ErrorCode::FlowControlError, "connection window overflow")
                        })?;
                    for window in send.streams.values_mut() {
                        if let Some(waker) = window.waker.take() {
                            waker.wake();
                        }
                    }
                } else if let Some(window) = send.streams.get_mut(&update.stream) {
                    if let Some(n) = window.available.checked_add(update.increment as i32) {
                        window.available = n;
                        if let Some(waker) = window.waker.take() {
                            waker.wake();
                        }
                    } else {
                        drop(send);
                        self.reset(update.stream, ErrorCode::FlowControlError, driver)?;
                    }
                } else if update.stream > self.last_stream || update.stream & 1 == 0 {
                    return Err(problem(
                        ErrorCode::ProtocolError,
                        "window update on idle stream",
                    ));
                }
            }
            Frame::Reset(reset) => {
                if reset.stream > self.last_stream || reset.stream & 1 == 0 {
                    return Err(problem(ErrorCode::ProtocolError, "reset on idle stream"));
                }
                let mut send = self.send.lock();
                if send.streams.get(&reset.stream).is_some_and(|s| !s.accepted) {
                    send.pending_resets += 1;
                    if send.pending_resets > PENDING_RESET_MAX {
                        return Err(problem(
                            ErrorCode::EnhanceYourCalm,
                            "too many pending request resets",
                        ));
                    }
                }
                drop(send);
                self.cancel(reset.stream, driver);
            }
            Frame::Ping(ping) if ping.flags & 1 == 0 => {
                write(
                    &wire::Ping {
                        flags: 1,
                        opaque: ping.opaque,
                    },
                    driver.reply(),
                );
            }
            Frame::Ping(ping) => {
                if self.shutdown_ping == Some(ping.opaque) {
                    self.shutdown_ping = None;
                    self.draining = true;
                    self.goaway(ErrorCode::NoError, self.last_stream, driver);
                }
            }
            Frame::GoAway(_) => {
                self.draining = true;
                self.goaway(ErrorCode::NoError, self.last_stream, driver);
            }
            Frame::PushPromise(_) => {
                return Err(problem(
                    ErrorCode::ProtocolError,
                    "client sent PUSH_PROMISE",
                ));
            }
            Frame::Priority(_) | Frame::Unknown(_) => {}
        }
        Ok(())
    }

    fn flow(&mut self, driver: &mut Driver<'_, Inputs, Timer>) -> Flow {
        if self.shutdown_requested && self.shutdown_ping.is_none() && !self.draining {
            self.shutdown_requested = false;
            let opaque = driver.random_u64().to_be_bytes();
            self.shutdown_ping = Some(opaque);
            self.goaway(ErrorCode::NoError, wire::MAX_WINDOW, driver);
            write(&wire::Ping { flags: 0, opaque }, driver.reply());
        }
        self.arm(driver);
        if self.draining && self.streams.is_empty() {
            Flow::Close
        } else {
            Flow::Continue
        }
    }
}

impl serve::Service for Http2 {
    type Timer = Timer;
    type Decoder = Inputs;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> Inputs {
        Inputs::for_server(wire::DEFAULT_FRAME_SIZE)
    }

    fn on_open(&mut self, _: &(), driver: &mut Driver<'_, Inputs, Timer>) -> Result<Flow, Infallible> {
        write(
            &wire::Settings {
                flags: 0,
                entries: vec![
                    wire::Setting {
                        id: 3,
                        value: self.limits.streams,
                    },
                    wire::Setting {
                        id: 6,
                        value: self.limits.head.head.min(u32::MAX as usize) as u32,
                    },
                ],
            },
            driver.reply(),
        );
        self.settings_deadline = Some(driver.now() + self.limits.header_timeout);
        Ok(self.flow(driver))
    }

    fn on_item(
        &mut self,
        item: Input,
        _: &(),
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<Flow, Infallible> {
        let result = match item {
            Input::Frame(frame) => self.frame(frame, driver),
            Input::Refused { header, error, .. } => {
                // PRIORITY may name a stream in any state (RFC 9113 section
                // 6.3), so a bad one resets just that stream. RST_STREAM may
                // not name an idle stream (section 6.4), so there it ends the
                // connection instead, as section 5.4.1 allows.
                let priority = header.kind == 2;
                let idle = header.stream > self.last_stream || header.stream & 1 == 0;
                if !self.received_settings || self.headers.pending() || (!priority && idle) {
                    Err(problem(
                        ErrorCode::ProtocolError,
                        "invalid frame on an idle stream or inside headers",
                    ))
                } else if idle {
                    Err(error)
                } else if priority || self.streams.contains_key(&header.stream) {
                    self.reset(header.stream, error.code, driver)
                } else {
                    Ok(())
                }
            }
            Input::Preface => Ok(()),
        };
        if let Err(error) = result {
            return Ok(self.fail(error, driver));
        }
        Ok(self.flow(driver))
    }

    fn on_timer(
        &mut self,
        _: Timer,
        _: &(),
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<Flow, Infallible> {
        let now = driver.now();
        if self.settings_deadline.is_some_and(|at| at <= now) {
            return Ok(self.fail(
                problem(
                    ErrorCode::SettingsTimeout,
                    "SETTINGS acknowledgment timed out",
                ),
                driver,
            ));
        }
        while self.resets.front().is_some_and(|(_, at)| *at <= now) {
            self.resets.pop_front();
        }
        let expired: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, s)| s.deadline.is_some_and(|at| at <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            let charged = self.streams[&id].request_held();
            self.dispatch(id, Received::Timeout, charged, driver);
        }
        Ok(self.flow(driver))
    }

    fn on_wake(&mut self, _: &(), driver: &mut Driver<'_, Inputs, Timer>) -> Result<Flow, Infallible> {
        Ok(self.flow(driver))
    }

    fn on_done(
        &mut self,
        key: u64,
        done: Done,
        _: &(),
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<Flow, Infallible> {
        let id = key as u32;
        if id == 0 {
            return Ok(self.flow(driver));
        }
        let code = match done {
            Done::Failed(_) => Some(ErrorCode::InternalError),
            // The response is complete but the request is not: ask the client
            // to stop sending it, without an error (RFC 9113 section 8.1).
            Done::Finished if self.streams.get(&id).is_some_and(|s| !s.recv_closed) => {
                Some(ErrorCode::NoError)
            }
            Done::Finished => None,
        };
        if let Some(code) = code {
            // These resets are not for the client's errors, so, as in h2,
            // they do not count toward the limit on error resets.
            self.write_reset(id, code, driver);
        } else {
            self.streams.remove(&id);
            self.send.lock().streams.remove(&id);
        }
        Ok(self.flow(driver))
    }

    fn on_fail(
        &mut self,
        error: &Fail<wire::Error>,
        _: &(),
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<(), Infallible> {
        let error = match error {
            Fail::Protocol(error) => *error,
            _ => problem(ErrorCode::ProtocolError, "truncated HTTP/2 frame"),
        };
        self.fail(error, driver);
        Ok(())
    }

    fn on_end(
        &mut self,
        end: Ended,
        _: &(),
        driver: &mut Driver<'_, Inputs, Timer>,
    ) -> Result<(), Infallible> {
        if end == Ended::Budget {
            // Tell the client why its streams stop, rather than just closing.
            self.goaway(ErrorCode::EnhanceYourCalm, self.last_stream, driver);
        }
        self.streams.clear();
        self.send.lock().streams.clear();
        self.resets = VecDeque::new();

        Ok(())
    }

    fn held(&self) -> usize {
        self.headers.allocated()
            + self.resets.capacity() * std::mem::size_of::<(u32, Instant)>()
            + self
                .streams
                .values()
                .map(|s| {
                    std::mem::size_of::<Stream>()
                        + s.body.capacity()
                        + s.request.as_ref().map_or(0, request_held)
                })
                .sum::<usize>()
            + {
                let send = self.send.lock();
                send.streams.len() * std::mem::size_of::<(u32, Window)>() + send.encoder.held()
            }
    }
}

/// Whether `budget` can hold `size` more bytes once the `released` bytes
/// it counts now are let go.
fn fits(budget: Option<&serve::Budget>, size: usize, released: usize) -> bool {
    budget.is_none_or(|b| size <= b.limit().saturating_sub(b.used().saturating_sub(released)))
}

fn problem(code: ErrorCode, reason: &'static str) -> wire::Error {
    wire::Error { code, reason }
}

fn write<W: Wire<WriteError = wire::Error>>(frame: &W, out: &mut Vec<u8>) {
    frame.write(out).expect("outbound frame has valid fields");
}

fn window_update(stream: u32, increment: usize, out: &mut Vec<u8>) {
    write(
        &wire::WindowUpdate {
            stream,
            flags: 0,
            increment: increment as u32,
        },
        out,
    );
}

fn content_length(headers: &http::HeaderMap) -> Result<Option<u64>, ()> {
    let mut length = None;
    for value in headers.get_all("content-length") {
        let value = value.to_str().map_err(|_| ())?;
        if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
            return Err(());
        }
        let value = value.parse().map_err(|_| ())?;
        if length.is_some_and(|old| old != value) {
            return Err(());
        }
        length = Some(value);
    }
    Ok(length)
}

fn valid_trailers(block: &hpack::Block) -> bool {
    block.more == 0
        && block.headers.iter().all(|h| {
            h.name
                .as_ref()
                .is_some_and(|n| !n.starts_with(b":") && valid_name(n))
                && h.value
                    .as_ref()
                    .is_some_and(|v| HeaderValue::from_bytes(v).is_ok())
        })
}

fn valid_name(name: &[u8]) -> bool {
    !name.iter().any(u8::is_ascii_uppercase)
        && HeaderName::from_bytes(name).is_ok()
        && !matches!(
            name,
            b"connection" | b"proxy-connection" | b"keep-alive" | b"transfer-encoding" | b"upgrade"
        )
}

fn request(block: hpack::Block, limits: Limits) -> Option<Request<Body>> {
    if block.more != 0 || block.headers.len() > limits.head.headers {
        return None;
    }
    let mut method = None;
    let mut scheme = None;
    let mut authority = None;
    let mut path = None;
    let mut regular = false;
    let mut headers = http::HeaderMap::new();
    let mut cookie: Option<Vec<u8>> = None;
    let mut list_size = 0usize;
    for h in block.headers {
        let (name, value) = (h.name?, h.value?);
        list_size = list_size.checked_add(name.len() + value.len() + 32)?;
        if list_size > limits.head.head {
            return None;
        }
        if name.starts_with(b":") {
            if regular {
                return None;
            }
            let target = match name.as_slice() {
                b":method" => &mut method,
                b":scheme" => &mut scheme,
                b":authority" => &mut authority,
                b":path" => &mut path,
                _ => return None,
            };
            if target.replace(String::from_utf8(value).ok()?).is_some() {
                return None;
            }
        } else {
            regular = true;
            if !valid_name(&name) || (name == b"te" && value != b"trailers") {
                return None;
            }
            // A client may split a cookie into several fields. They reach
            // the application joined with "; " (RFC 9113 section 8.2.3).
            if name == b"cookie"
                && let Some(first) = headers.get(http::header::COOKIE)
            {
                let joined = cookie.get_or_insert_with(|| first.as_bytes().to_vec());
                joined.extend_from_slice(b"; ");
                joined.extend_from_slice(&value);
            } else {
                headers.append(
                    HeaderName::from_bytes(&name).ok()?,
                    HeaderValue::from_bytes(&value).ok()?,
                );
            }
        }
    }
    if let Some(cookie) = cookie {
        headers.insert(http::header::COOKIE, HeaderValue::from_bytes(&cookie).ok()?);
    }
    let method = Method::from_bytes(method?.as_bytes()).ok()?;
    let mut uri = http::uri::Parts::default();
    uri.authority = authority.map(|a| a.parse()).transpose().ok()?;
    if method == Method::CONNECT {
        if scheme.is_some() || path.is_some() || uri.authority.is_none() {
            return None;
        }
    } else {
        let scheme: http::uri::Scheme = scheme?.parse().ok()?;
        if uri.authority.is_some() {
            uri.scheme = Some(scheme);
        }
        let path = path?;
        if path.is_empty()
            || (!path.starts_with('/') && !(method == Method::OPTIONS && path == "*"))
        {
            return None;
        }
        uri.path_and_query = Some(path.parse().ok()?);
    }
    let mut request = Request::builder()
        .method(method)
        .uri(http::Uri::from_parts(uri).ok()?)
        .version(Version::HTTP_2)
        .body(Body::empty())
        .ok()?;
    *request.headers_mut() = headers;
    Some(request)
}

struct Accept(Arc<Mutex<Outbound>>);

impl Pending for Accept {
    fn poll_next(
        &mut self,
        _: &mut PendingDriver<'_>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, Error>>> {
        let mut send = self.0.lock();
        let mut out = Vec::new();
        release_window(0, &mut send.recv_window, &mut out);
        for (&id, stream) in &mut send.streams {
            stream.accepted = true;
            release_window(id, &mut stream.recv_window, &mut out);
        }
        send.pending_resets = 0;
        if out.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(out)))
        }
    }
}

/// Returns the credit DATA used once it is at least half of what the client
/// has left, as h2 does, so many small frames share one WINDOW_UPDATE.
fn release_window(id: u32, window: &mut i32, out: &mut Vec<u8>) {
    let used = 65_535 - *window;
    if used > 0 && used >= *window / 2 {
        window_update(id, used as usize, out);
        *window = 65_535;
    }
}

fn response_held(response: &Response<Body>) -> usize {
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

type Making = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

struct Sending {
    budget: Option<serve::Budget>,
    id: u32,
    send: Arc<Mutex<Outbound>>,
    work: Option<Later>,
    making: Option<Making>,
    response: Option<Response<Body>>,
    body: Option<Body>,
    rest: Bytes,
    rest_held: usize,
    request_held: usize,
    head_only: bool,
    date: Option<u64>,
    asked: Instant,
    end_sent: bool,
}

impl Sending {


    fn headers(&self, fields: &[hpack::Field], end: bool) -> Result<Vec<u8>, Error> {
        let mut block = Vec::new();
        // A zero-capacity table keeps response storage bounded while still
        // honoring the peer's required table-size updates.
        self.send.lock().encoder.encode_block(fields, &mut block)?;
        let mut out = Vec::new();
        let max = self.send.lock().frame;
        let first = block.len().min(max);
        wire::Headers {
            stream: self.id,
            flags: u8::from(end) | if first == block.len() { 4 } else { 0 },
            fragment: block[..first].to_vec(),
            padding: None,
            priority: None,
        }
        .write(&mut out)?;
        let rest = &block[first..];
        for (index, fragment) in rest.chunks(max).enumerate() {
            wire::Continuation {
                stream: self.id,
                flags: if (index + 1) * max >= rest.len() {
                    4
                } else {
                    0
                },
                fragment: fragment.to_vec(),
            }
            .write(&mut out)?;
        }
        Ok(out)
    }
}

impl Pending for Sending {
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, Error>>> {
        if let Some(work) = self.work.take() {
            self.making = Some(match driver.fcx() {
                Some(fcx) => work(fcx.clone()),
                None => Box::pin(std::future::ready(Err(Error::msg(
                    "this answer needs a Cx: use Harness::with_fcx",
                )))),
            });
        }
        if let Some(making) = &mut self.making {
            let response = match making.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(response)) => response,
                Poll::Ready(Err(error)) => {
                    error_response(&error)
                }
            };
            self.making = None;
            // The response replaces the request in the budget. One it cannot
            // hold gets 503, so the other streams go on.
            let room = fits(
                self.budget.as_ref(),
                response_held(&response),
                self.request_held,
            );
            self.request_held = 0;
            self.response = Some(if room {
                response
            } else {
                over_budget()
            });
        }
        if let Some(response) = self.response.take() {
            let (parts, body) = response.into_parts();
            let now = driver.fcx().map_or(self.asked, Cx::now);
            let date = self.date.and_then(|date| {
                HeaderValue::from_str(&super::http_date(
                    date.saturating_add(now.since_start().as_secs()),
                ))
                .ok()
            });
            let asked = if self.head_only {
                Asked::Head
            } else {
                Asked::Body
            };
            let policy = ResponsePolicy::new(&parts, body.size_hint().exact(), asked, date);
            let mut fields = vec![hpack::Field::new(":status", parts.status.as_str())];
            for (name, value) in &parts.headers {
                if matches!(
                    name.as_str(),
                    "connection"
                        | "proxy-connection"
                        | "keep-alive"
                        | "transfer-encoding"
                        | "upgrade"
                ) {
                    continue;
                }
                fields.push(hpack::Field::new(name.as_str(), value.as_bytes()));
            }
            if !parts.headers.contains_key("content-length")
                && let Some(length) = policy.len
            {
                fields.push(hpack::Field::new("content-length", length.to_string()));
            }
            if let Some(date) = policy.date {
                fields.push(hpack::Field::new("date", date.as_bytes()));
            }
            self.end_sent = policy.bodiless || body.is_end_stream();
            if !self.end_sent {
                self.body = Some(body);
            }
            return Poll::Ready(Some(self.headers(&fields, self.end_sent)));
        }
        loop {
            if !self.rest.is_empty() {
                let mut send = self.send.lock();
                let capacity = send.window.max(0) as usize;
                let frame = send.frame.min(wire::DEFAULT_FRAME_SIZE);
                let Some(window) = send.streams.get_mut(&self.id) else {
                    return Poll::Ready(None);
                };
                let n = self
                    .rest
                    .len()
                    .min(capacity)
                    .min(window.available.max(0) as usize)
                    .min(frame);
                if n == 0 {
                    window.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                window.available -= n as i32;
                send.window -= n as i32;
                drop(send);
                let data = self.rest.split_to(n).to_vec();
                if self.rest.is_empty() {
                    self.rest = Bytes::new();
                    self.rest_held = 0;
                }
                return Poll::Ready(Some(
                    wire::Data {
                        stream: self.id,
                        flags: 0,
                        data,
                        padding: None,
                    }
                    .to_bytes()
                    .map_err(Into::into),
                ));
            }
            if self.end_sent {

                return Poll::Ready(None);
            }
            let Some(body) = &mut self.body else {
                self.end_sent = true;
                return Poll::Ready(Some(
                    wire::Data {
                        stream: self.id,
                        flags: 1,
                        data: Vec::new(),
                        padding: None,
                    }
                    .to_bytes()
                    .map_err(Into::into),
                ));
            };
            let held = body.full_len();
            match Pin::new(body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => self.body = None,
                Poll::Ready(Some(Err(error))) => {

                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        // The headers are out, so a chunk the budget cannot
                        // hold resets this stream alone.
                        if !fits(self.budget.as_ref(), data.len(), held) {

                            return Poll::Ready(Some(Err(Error::msg(
                                "response body exceeds budget",
                            ))));
                        }
                        self.rest_held = data.len();
                        self.rest = data;
                    }
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            let fields: Vec<_> = trailers
                                .iter()
                                .map(|(n, v)| hpack::Field::new(n.as_str(), v.as_bytes()))
                                .collect();
                            self.end_sent = true;
                            self.body = None;
                            return Poll::Ready(Some(self.headers(&fields, true)));
                        }
                    }
                },
            }
        }
    }

    fn cancel(&mut self, _driver: &mut PendingDriver<'_>) {

    }

    fn held(&self) -> usize {
        self.request_held
            + self.rest_held
            + self.body.as_ref().map_or(0, Body::full_len)
            + self.response.as_ref().map_or(0, response_held)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HttpOptions, PREFACE};
    use super::*;
    use fictionet::stdlib::services::serve::ConnInfo;
    use fictionet::stdlib::network::{ConnError, Connection};
    use std::future::poll_fn;
    use std::pin::pin;
    struct StalledBody {
        input: Bytes,
        output: Arc<Mutex<Vec<u8>>>,
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
            self.output.lock().extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
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
                let output = Arc::new(Mutex::new(Vec::new()));
                let conn = StalledBody {
                    output: output.clone(),
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
                struct Reject;
                impl Handler for Reject {
                    fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
                        panic!("a stalled body cannot reach the handler")
                    }
                }
                let handler = Reject;
                let mut served = pin!(super::super::serve_connection(
                    &fcx,
                    conn,
                    ConnInfo::default(),
                    Arc::new(handler),
                    &opts
                ));
                let mut blocks = wire::HeaderBlocks::with_limits(Default::default());
                let mut consumed = 0;
                let status = poll_fn(|cx| {
                    assert!(served.as_mut().poll(cx).is_pending());
                    let output = output.lock();
                    while output.len() >= consumed + 9 {
                        let header = wire::FrameHeader::parse(&output[consumed..consumed + 9]).unwrap();
                        let end = consumed + 9 + header.length;
                        if end > output.len() { break; }
                        let frame = Frame::parse(&output[consumed..end]).unwrap();
                        consumed = end;
                        let read = blocks.read_frame(&frame).unwrap();
                        if let Some(block) = read.block
                            && let Some(status) = block.headers.into_iter().find(|header| header.name.as_deref() == Some(b":status"))
                        { return Poll::Ready(status.value.unwrap()); }
                    }
                    Poll::Pending
                }).await;
                assert_eq!(status, b"408");
                assert_eq!(fcx.now().since_start(), duration);
                Ok(())
            },
        ))
        .unwrap();
    }
}
