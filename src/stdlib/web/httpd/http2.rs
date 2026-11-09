// Copyright (c) 2017 h2 authors
// Portions adapted from h2 under the MIT license; see LICENSE-h2 in this directory.

//! HTTP/2 as layers: [`Http2`], the connection, with a byte stream below
//! and one [`HttpExchange`] child per stream above; [`Respond`], a
//! [`Handler`](super::Handler) on one exchange; and [`Grpc`], gRPC calls on
//! one exchange.

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Version};

use fictionet::stdlib::codec::{self, Fail, Wire};
use fictionet::stdlib::layer::{
    Admit, ByteStream, Charge, ChildId, Chunk, Credited, Env, Layer, Mux, MuxCommand, MuxEvent,
    MuxOp, Slots, StreamCommand, StreamEvent, Top,
};
use fictionet::stdlib::protocols::hpack;
use fictionet::stdlib::protocols::http2::{self as wire, ErrorCode, Frame, Input, Inputs};
use fictionet::time::Instant;

use super::Limits;
use super::response::request_held;

mod exchange;
mod grpc;
mod respond;

pub use exchange::{Ending, ExchangeCommand, ExchangeEvent, HttpExchange, Opening, ResponseHead};
pub use grpc::{Grpc, GrpcCommand, GrpcEvent};
pub use respond::{Http2Server, Respond, Responder, Work as RespondWork};

/// HTTP/2 connection deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer {
    /// The SETTINGS acknowledgment deadline, or the end of a reset
    /// stream's hold.
    Deadline,
}

/// What [`Http2`] reports about its connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// The connection failed and sent GOAWAY with this error.
    Failed(wire::Error),
    /// The connection held more than its budget allows: GOAWAY with
    /// `ENHANCE_YOUR_CALM`, then the end.
    Budget,
}

const RESET_LIFETIME: Duration = Duration::from_secs(1);
const RESET_MAX: usize = 50;
const PENDING_RESET_MAX: usize = 20;
const ERROR_RESET_MAX: usize = 1024;
/// The receive window of the connection and of each stream, which the
/// server never changes from the protocol's default.
const WINDOW: i32 = 65_535;
/// How many response body bytes the connection takes from one exchange
/// before it has framed them.
const SEND_CREDIT: u64 = wire::DEFAULT_FRAME_SIZE as u64;
/// How many events wait for the children before decoding pauses.
const UP_LIMIT: usize = 64;
/// How many output bytes wait for the transport before input pauses.
const OUT_LIMIT: usize = 64 << 10;
/// How many frames one advance reads.
const FRAMES: usize = 16;
/// The bytes of the last GOAWAY, kept back from the start.
const LAST_WORDS: usize = wire::HEADER_LEN + 8;

/// HTTP/2 for one connection: a [`Layer`] with an ordered byte stream below
/// and one [`HttpExchange`] child per stream above ([`Mux`]).
///
/// The connection owns everything the streams share: the frame decoder,
/// HPACK in both directions, SETTINGS and their acknowledgment deadline,
/// the wire's stream numbers and states, both levels of flow control,
/// resets and their limits, PING and GOAWAY. A request whose head is valid
/// opens a child with the head as its [`Opening`]; its body and end come up
/// within the credit the child grants, and the child's response goes down
/// within the credit the connection grants. Receive credit returns to the
/// client by WINDOW_UPDATE once a batch of input is read: on the connection
/// for bytes it no longer holds, and on a stream once its child has read
/// what it was given, so a child that stops reading stops its own stream
/// and leaves the others the connection's window. Response bytes go out
/// within both of the client's windows.
///
/// [`Responder::http2`] puts a [`Respond`] on each stream, answering with a
/// [`Handler`](super::Handler); [`Grpc`] serves gRPC calls on a stream.
///
/// After the server resets a stream, it ignores that stream's late HEADERS
/// and DATA for one second, and holds at most 50 such streams. A client
/// that makes the server reset more than 1024 streams for its errors, or
/// resets more than 20 streams the server has not taken in yet, loses the
/// connection with `ENHANCE_YOUR_CALM`. Input storage, HPACK state, stream
/// state, request heads and bodies, and output frames are charged to the
/// connection's budget before they grow. Past it, the connection sends
/// GOAWAY with `ENHANCE_YOUR_CALM` and ends.
pub struct Http2 {
    limits: Limits,
    phase: Phase,
    /// The chunk of input being read, all of one delivery.
    input: Option<Chunk>,
    peer_ended: bool,
    frames: codec::Stream<Inputs>,
    headers: wire::HeaderBlocks,
    encoder: hpack::Encoder,
    streams: BTreeMap<u32, Stream>,
    children: Option<Slots<u32>>,
    resets: VecDeque<(u32, Instant)>,
    recv_window: i32,
    send_window: i32,
    initial: i32,
    frame: usize,
    last_stream: u32,
    received_settings: bool,
    awaiting_ack: bool,
    settings_deadline: Option<Instant>,
    continuations: usize,
    error_resets: usize,
    pending_resets: usize,
    /// Credit may be due: since it last returned, input arrived, a child
    /// granted credit, or a stream with held bytes ended.
    batch: bool,
    draining: bool,
    shutdown_ping: Option<[u8; 8]>,
    shutdown_requested: bool,
    goaway_last: Option<u32>,
    up: VecDeque<MuxEvent<HttpExchange, Top, Opening>>,
    out: VecDeque<StreamCommand>,
    out_bytes: usize,
    /// What was queued, in order, for the transport's completions.
    sent: VecDeque<Piece>,
    /// The stream whose frame went out last, so streams take turns.
    turn: u32,
    charge: Option<Charge>,
    last_words: Option<Charge>,
    /// The request an HTTP/1 `Upgrade: h2c` brought, for stream 1.
    upgrade: Option<(Opening, Option<Chunk>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Opening,
    Open,
    /// The end is queued behind the output.
    Closing,
    Closed,
}

struct Stream {
    child: ChildId,
    _entry: Charge,
    accepted: bool,
    recv_closed: bool,
    remaining: Option<u64>,
    recv_window: i32,
    /// Bytes of DATA frames waiting in `pending` for the child's credit:
    /// they count against the receive windows until they go up.
    held: u32,
    /// Bytes waiting in `pending` that came outside the receive windows:
    /// the body an `Upgrade: h2c` request brought over HTTP/1. They are
    /// first in `pending`, ahead of any DATA.
    outside: u64,
    /// Credit the child granted for its events.
    credit: u64,
    /// The most credit the child has held at once: its window. Its credit
    /// is back at the peak once it has read all it was given.
    peak: u64,
    credited: bool,
    pending: VecDeque<ExchangeEvent>,
    overflow: bool,
    send_window: i32,
    /// Credit the child holds for its body.
    granted: u64,
    out: VecDeque<Chunk>,
    out_bytes: u64,
    reply: Reply,
    written: u64,
}

enum Reply {
    Waiting,
    Body,
    Ending(Option<Box<HeaderMap>>),
    Ended,
}

/// Bytes handed to the transport, and what their completion means.
struct Piece {
    stream: u32,
    bytes: u64,
    body: u64,
    end: bool,
}

/// The stream a client HEADERS lands on.
enum HeadersOn {
    /// One the server reset a moment ago: the frame is ignored.
    Reset,
    /// One already open: the block is its trailers.
    Open,
    /// A new stream, above every identifier used so far.
    New,
}

impl Http2 {
    /// The connection, with these limits.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            phase: Phase::Opening,
            input: None,
            peer_ended: false,
            frames: codec::Stream::new(Inputs::client_side(wire::DEFAULT_FRAME_SIZE)),
            headers: wire::HeaderBlocks::with_limits(wire::Limits {
                header_list: limits.head.head,
                header_block: limits.head.head,
                ..wire::Limits::default()
            }),
            encoder: hpack::Encoder::new(0),
            streams: BTreeMap::new(),
            children: None,
            resets: VecDeque::new(),
            recv_window: WINDOW,
            send_window: WINDOW,
            initial: WINDOW,
            frame: wire::DEFAULT_FRAME_SIZE,
            last_stream: 0,
            received_settings: false,
            awaiting_ack: true,
            settings_deadline: None,
            continuations: 0,
            error_resets: 0,
            pending_resets: 0,
            batch: false,
            draining: false,
            shutdown_ping: None,
            shutdown_requested: false,
            goaway_last: None,
            up: VecDeque::new(),
            out: VecDeque::new(),
            out_bytes: 0,
            sent: VecDeque::new(),
            turn: 0,
            charge: None,
            last_words: None,
            upgrade: None,
        }
    }

    /// The connection an HTTP/1 `Upgrade: h2c` started: the client's
    /// `HTTP2-Settings` already apply, and its request is stream 1, with
    /// the whole body that came with it. The client's preface comes next.
    pub(super) fn upgraded(
        limits: Limits,
        settings: &[wire::Setting],
        opening: Opening,
        body: Option<Chunk>,
    ) -> Self {
        let mut h2 = Self::new(limits);
        for setting in settings {
            // HTTP/1 checked them; none can fail here.
            let _ = h2.peer_setting(*setting);
        }
        h2.last_stream = 1;
        h2.upgrade = Some((opening, body));
        h2
    }

    /// The child credit each exchange should grant: a stream's whole
    /// receive window, so the connection never holds body bytes for a child
    /// that reads.
    pub const WINDOW: u64 = WINDOW as u64;

    /// Begins graceful shutdown: GOAWAY and a PING, then, once the PING
    /// comes back and the streams in flight are known, a final GOAWAY. The
    /// connection closes when those streams finish.
    pub fn graceful_shutdown(&mut self) {
        self.shutdown_requested = true;
    }

    /// The streams open now.
    pub fn streams(&self) -> usize {
        self.streams.len()
    }

    /// What the connection holds, as charged to its budget. Output frames,
    /// request bodies and response bodies carry their own charges.
    fn holding(&self) -> usize {
        self.frames
            .limit()
            .max(self.frames.allocated())
            .saturating_add(self.headers.allocated())
            .saturating_add(self.encoder.held())
            .saturating_add(self.resets.capacity() * size_of::<(u32, Instant)>())
            .saturating_add(self.up.capacity() * size_of::<MuxEvent<HttpExchange, Top, Opening>>())
            .saturating_add(self.out.capacity() * size_of::<StreamCommand>())
            .saturating_add(self.sent.capacity() * size_of::<Piece>())
    }

    /// Charges what is held now. Returns whether it fits.
    fn fits(&mut self) -> bool {
        let need = self.holding();
        self.charge.as_mut().is_none_or(|charge| charge.set(need))
    }

    fn open(&mut self, env: &mut Env<'_, Report>) {
        self.phase = Phase::Open;
        // The list of recent resets is held at its bound from the start.
        let resets = RESET_MAX * size_of::<(u32, Instant)>();
        let Some(charge) = env.budget().charge(self.holding() + resets) else {
            self.phase = Phase::Closing;
            self.out.push_back(StreamCommand::End);
            return;
        };
        self.resets.reserve_exact(RESET_MAX);
        self.charge = Some(charge);
        self.last_words = env.budget().charge(LAST_WORDS);
        self.children = Slots::with_budget(self.limits.streams as usize, env.budget());
        if self.last_words.is_none() || self.children.is_none() {
            return self.over_budget(env);
        }
        let settings = wire::Settings {
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
        };
        if !self.control(env, wire::HEADER_LEN + 12, &settings) {
            return;
        }
        self.settings_deadline = Some(env.now() + self.limits.header_timeout);
        if let Some((mut opening, body)) = self.upgrade.take() {
            opening.at = env.now();
            let ended = body.is_none();
            let admitted = self.admit(env, 1, opening, None, ended).is_ok();
            // The request came whole over HTTP/1: stream 1 is half closed
            // from the client's side (RFC 7540 section 3.2).
            if let Some(stream) = self.streams.get_mut(&1) {
                stream.recv_closed = true;
            }
            if admitted && let Some(mut chunk) = body {
                if chunk.reserve(env.budget()) {
                    self.tell_outside(1, chunk);
                } else {
                    self.tell(1, ExchangeEvent::Overflow(chunk.len() as u64));
                }
                self.tell(1, ExchangeEvent::End);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Output

    /// Queues output bytes, charged before they were allocated, for
    /// `stream` (0 for the connection).
    fn queue(&mut self, chunk: Chunk, stream: u32, body: u64, end: bool) {
        let bytes = chunk.len();
        self.out_bytes += bytes;
        self.sent.push_back(Piece {
            stream,
            bytes: bytes as u64,
            body,
            end,
        });
        self.out.push_back(StreamCommand::Write(chunk));
    }

    /// Writes a frame of `len` bytes. Past the budget, the connection ends.
    /// Returns whether it was queued.
    fn frame_for<W: Wire<WriteError = wire::Error>>(
        &mut self,
        env: &mut Env<'_, Report>,
        len: usize,
        frame: &W,
        stream: u32,
        end: bool,
    ) -> bool {
        let Some(charge) = env.budget().charge(len) else {
            self.over_budget(env);
            return false;
        };
        let mut bytes = Vec::with_capacity(len);
        frame
            .write(&mut bytes)
            .expect("outbound frame has valid fields");
        debug_assert_eq!(bytes.len(), len);
        self.queue(Chunk::with_charge(bytes, charge), stream, 0, end);
        true
    }

    /// A connection frame.
    fn control<W: Wire<WriteError = wire::Error>>(
        &mut self,
        env: &mut Env<'_, Report>,
        len: usize,
        frame: &W,
    ) -> bool {
        self.frame_for(env, len, frame, 0, false)
    }

    fn goaway(&mut self, env: &mut Env<'_, Report>, code: ErrorCode, last: u32) {
        let last = last.min(self.goaway_last.unwrap_or(wire::MAX_WINDOW));
        self.goaway_last = Some(last);
        self.control(
            env,
            LAST_WORDS,
            &wire::GoAway {
                flags: 0,
                last_stream: last,
                code: code as u32,
                debug: Vec::new(),
            },
        );
    }

    /// Ends the connection for `error`: GOAWAY, then the end.
    fn fail(&mut self, env: &mut Env<'_, Report>, error: wire::Error) {
        env.report(Report::Failed(error));
        self.goaway(env, error.code, self.last_stream);
        self.close();
    }

    /// Ends the connection once what is queued is written. Every exchange
    /// still open is told the connection is gone.
    fn close(&mut self) {
        if matches!(self.phase, Phase::Closing | Phase::Closed) {
            return;
        }
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            self.end_stream(id, Ending::Gone);
        }
        self.resets = VecDeque::new();
        self.input = None;
        self.phase = Phase::Closing;
        self.out.push_back(StreamCommand::End);
    }

    /// The connection holds more than its budget allows: nothing more is
    /// written but GOAWAY with `ENHANCE_YOUR_CALM`, which was paid for at
    /// the start, and it ends.
    fn over_budget(&mut self, env: &mut Env<'_, Report>) {
        if matches!(self.phase, Phase::Closing | Phase::Closed) {
            return;
        }
        env.report(Report::Budget);
        self.out.clear();
        self.sent.clear();
        self.out_bytes = 0;
        if let Some(charge) = self.last_words.take() {
            let mut bytes = Vec::with_capacity(LAST_WORDS);
            wire::GoAway {
                flags: 0,
                last_stream: self
                    .last_stream
                    .min(self.goaway_last.unwrap_or(wire::MAX_WINDOW)),
                code: ErrorCode::EnhanceYourCalm as u32,
                debug: Vec::new(),
            }
            .write(&mut bytes)
            .expect("outbound frame has valid fields");
            self.queue(Chunk::with_charge(bytes, charge), 0, 0, false);
        }
        self.close();
    }

    /// Resets stream `id` and ignores its late frames for a while. Not an
    /// error of the client's: it does not count toward the reset limit.
    fn write_reset(&mut self, env: &mut Env<'_, Report>, id: u32, code: ErrorCode) {
        if self.streams.contains_key(&id) {
            self.end_stream(id, Ending::Reset(code));
        }
        self.frame_for(
            env,
            wire::HEADER_LEN + 4,
            &wire::Reset {
                stream: id,
                flags: 0,
                code: code as u32,
            },
            id,
            false,
        );
        if self.resets.len() < RESET_MAX && !self.resets.iter().any(|(s, _)| *s == id) {
            if self.resets.capacity() == 0 {
                self.resets.reserve_exact(RESET_MAX);
            }
            self.resets.push_back((id, env.now() + RESET_LIFETIME));
        }
    }

    /// Resets stream `id` for the client's error. Too many such resets end
    /// the connection.
    fn reset(
        &mut self,
        env: &mut Env<'_, Report>,
        id: u32,
        code: ErrorCode,
    ) -> Result<(), wire::Error> {
        self.write_reset(env, id, code);
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

    // -----------------------------------------------------------------------
    // Children

    /// Opens stream `id`'s child with `opening`, or refuses the stream
    /// when its head and state do not fit the budget.
    fn admit(
        &mut self,
        env: &mut Env<'_, Report>,
        id: u32,
        mut opening: Opening,
        remaining: Option<u64>,
        ended: bool,
    ) -> Result<(), wire::Error> {
        let entry = env.budget().charge(size_of::<(u32, Stream)>());
        let head = env.budget().charge(request_held(&opening.request));
        let (Some(entry), Some(head)) = (entry, head) else {
            return self.reset(env, id, ErrorCode::RefusedStream);
        };
        let Some(child) = self.children.as_mut().and_then(|c| c.insert(id).ok()) else {
            return self.reset(env, id, ErrorCode::RefusedStream);
        };
        let child_id = child.id();
        opening.charge = Some(head);
        opening.ended = ended;
        self.streams.insert(
            id,
            Stream {
                child: child_id,
                _entry: entry,
                accepted: false,
                recv_closed: ended,
                remaining,
                recv_window: WINDOW,
                held: 0,
                outside: 0,
                credit: 0,
                peak: 0,
                credited: false,
                pending: VecDeque::new(),
                overflow: false,
                send_window: self.initial,
                granted: SEND_CREDIT,
                out: VecDeque::new(),
                out_bytes: 0,
                reply: Reply::Waiting,
                written: 0,
            },
        );
        self.up
            .push_back(MuxEvent::Opened(child, opening, SEND_CREDIT));
        self.up.push_back(MuxEvent::Credit(child_id, SEND_CREDIT));
        Ok(())
    }

    /// Sends stream `id`'s child `event`, in order behind what waits for
    /// its credit. Its body bytes came in DATA frames, within the receive
    /// windows.
    fn tell(&mut self, id: u32, event: ExchangeEvent) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        stream.held += event.credit() as u32;
        stream.pending.push_back(event);
        self.forward(id);
    }

    /// Sends stream `id`'s child the body an `Upgrade: h2c` request
    /// brought, which came outside the receive windows.
    fn tell_outside(&mut self, id: u32, chunk: Chunk) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        stream.outside += chunk.len() as u64;
        stream.pending.push_back(ExchangeEvent::Data(chunk));
        self.forward(id);
    }

    /// Moves what waits for stream `id`'s credit up, as far as it goes. A
    /// body piece larger than the credit goes up in part: the child's
    /// credit may never cover it whole.
    fn forward(&mut self, id: u32) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        while let Some(event) = stream.pending.front_mut() {
            let cost = event.credit();
            let event = if cost <= stream.credit {
                stream.pending.pop_front().expect("a pending event")
            } else if let ExchangeEvent::Data(chunk) = event
                && stream.credit > 0
            {
                ExchangeEvent::Data(chunk.split_to(stream.credit as usize))
            } else {
                break;
            };
            let cost = event.credit();
            stream.credit -= cost;
            let outside = cost.min(stream.outside);
            stream.outside -= outside;
            stream.held -= (cost - outside) as u32;
            self.up.push_back(MuxEvent::Child(stream.child, event));
        }
    }

    /// Stream `id` is over: its child hears why, and its number is free.
    fn end_stream(&mut self, id: u32, why: Ending) {
        let Some(stream) = self.streams.remove(&id) else {
            return;
        };
        // What it held is dropped: its credit may be due.
        self.batch |= stream.held > 0;
        if let Some(children) = &mut self.children {
            children.remove(stream.child);
        }
        self.up.push_back(MuxEvent::Child(
            stream.child,
            ExchangeEvent::Closed {
                why,
                written: stream.written,
            },
        ));
    }

    // -----------------------------------------------------------------------
    // Input

    /// Finds the stream a client HEADERS on stream `id` lands on. One on an
    /// even stream, a stream that ended, or one below an identifier already
    /// used ends the connection.
    fn headers_on(&self, id: u32) -> Result<HeadersOn, wire::Error> {
        if id & 1 == 0 {
            return Err(problem(
                ErrorCode::ProtocolError,
                "client opened an even stream",
            ));
        }
        if self.ignored(id) {
            return Ok(HeadersOn::Reset);
        }
        if self.streams.contains_key(&id) {
            return Ok(HeadersOn::Open);
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
        Ok(HeadersOn::New)
    }

    fn on_headers(
        &mut self,
        env: &mut Env<'_, Report>,
        read: wire::BlockRead,
    ) -> Result<(), wire::Error> {
        let Some(block) = read.block else {
            return Ok(());
        };
        let id = read.stream;
        match self.headers_on(id)? {
            HeadersOn::Reset => return Ok(()),
            HeadersOn::Open => {}
            HeadersOn::New => {
                self.last_stream = id;
            }
        }
        if let Some(stream) = self.streams.get(&id) {
            if stream.recv_closed {
                return self.reset(env, id, ErrorCode::StreamClosed);
            }
            if !read.end || !valid_trailers(&block) {
                return self.reset(env, id, ErrorCode::ProtocolError);
            }
            if stream.remaining.is_some_and(|n| n != 0) {
                return self.reset(env, id, ErrorCode::ProtocolError);
            }
            let trailers = trailer_map(block);
            self.streams
                .get_mut(&id)
                .expect("an open stream")
                .recv_closed = true;
            self.tell(id, ExchangeEvent::Trailers(Box::new(trailers)));
            return Ok(());
        }
        if self.draining || self.streams.len() >= self.limits.streams as usize {
            // A client can open streams before it reads our SETTINGS or GOAWAY,
            // so, as in h2, these refusals do not count as errors.
            self.write_reset(env, id, ErrorCode::RefusedStream);
            return Ok(());
        }
        let list_size: usize = block
            .headers
            .iter()
            .map(|h| h.name.len() + h.value.len() + 32)
            .sum();
        if block.more != 0
            || block.headers.len() > self.limits.head.headers
            || list_size > self.limits.head.head
        {
            let mut fragment = Vec::new();
            self.encoder
                .encode_block(&[hpack::Field::new(":status", "431")], &mut fragment)
                .expect("static header");
            let len = wire::HEADER_LEN + fragment.len();
            if !self.frame_for(
                env,
                len,
                &wire::Headers {
                    stream: id,
                    flags: 5,
                    fragment,
                    priority: None,
                    padding: None,
                },
                id,
                false,
            ) {
                return Ok(());
            }
            return self.reset(env, id, ErrorCode::RefusedStream);
        }
        let Some(request) = request(block, self.limits) else {
            return self.reset(env, id, ErrorCode::ProtocolError);
        };
        let remaining = match content_length(request.headers()) {
            Ok(n) => n,
            Err(()) => return self.reset(env, id, ErrorCode::ProtocolError),
        };
        if read.end && remaining.is_some_and(|n| n != 0) {
            return self.reset(env, id, ErrorCode::ProtocolError);
        }
        self.batch = true;
        let opening = Opening {
            request: Box::new(request),
            ended: read.end,
            at: env.now(),
            charge: None,
        };
        self.admit(env, id, opening, remaining, read.end)
    }

    fn on_data(&mut self, env: &mut Env<'_, Report>, data: wire::Data) -> Result<(), wire::Error> {
        let id = data.stream;
        let size = data.data.len() + data.padding.as_ref().map_or(0, |p| p.len() + 1);
        self.recv_window -= size as i32;
        if self.recv_window < 0 {
            return Err(problem(
                ErrorCode::FlowControlError,
                "connection receive window exceeded",
            ));
        }
        // The connection window counts every DATA frame, padding and frames for
        // reset streams included. Credit returns after the input batch, so DATA
        // sent before the client saw a WINDOW_UPDATE must fit the old window.
        self.batch = true;
        if self.ignored(id) {
            return Ok(());
        }
        let Some(stream) = self.streams.get_mut(&id) else {
            if id > self.last_stream || id & 1 == 0 {
                return Err(problem(ErrorCode::ProtocolError, "data on an idle stream"));
            }
            return self.reset(env, id, ErrorCode::StreamClosed);
        };
        if stream.recv_closed {
            return self.reset(env, id, ErrorCode::StreamClosed);
        }
        stream.recv_window -= size as i32;
        if stream.recv_window < 0 {
            return self.reset(env, id, ErrorCode::FlowControlError);
        }
        if let Some(remaining) = &mut stream.remaining {
            let Some(n) = remaining.checked_sub(data.data.len() as u64) else {
                return self.reset(env, id, ErrorCode::ProtocolError);
            };
            *remaining = n;
            if data.flags & 1 != 0 && n != 0 {
                return self.reset(env, id, ErrorCode::ProtocolError);
            }
        }
        let end = data.flags & 1 != 0;
        stream.recv_closed = end;
        if !data.data.is_empty() && !stream.overflow {
            match env.budget().charge(data.data.capacity()) {
                Some(charge) => {
                    let chunk = Chunk::with_charge(data.data, charge);
                    self.tell(id, ExchangeEvent::Data(chunk));
                }
                None => {
                    // The body is the stream's alone to lose: its child
                    // answers, and the other streams go on.
                    let dropped = data.data.len() as u64;
                    self.streams.get_mut(&id).expect("an open stream").overflow = true;
                    self.tell(id, ExchangeEvent::Overflow(dropped));
                }
            }
        }
        if end {
            self.tell(id, ExchangeEvent::End);
        }
        Ok(())
    }

    /// Applies one of the client's settings.
    fn peer_setting(&mut self, setting: wire::Setting) -> Result<(), wire::Error> {
        match setting.id {
            1 => self.encoder.set_settings_limit(setting.value as usize),
            4 => {
                let initial = setting.value as i32;
                for stream in self.streams.values_mut() {
                    stream.send_window = shifted(stream.send_window, self.initial, initial)
                        .ok_or_else(|| {
                            problem(ErrorCode::FlowControlError, "initial window overflow")
                        })?;
                }
                self.initial = initial;
            }
            5 => self.frame = setting.value as usize,
            _ => {}
        }
        Ok(())
    }

    fn on_frame(&mut self, env: &mut Env<'_, Report>, frame: Frame) -> Result<(), wire::Error> {
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
                match self.headers_on(h.stream)? {
                    HeadersOn::Reset => {}
                    HeadersOn::Open => self.reset(env, h.stream, ErrorCode::ProtocolError)?,
                    HeadersOn::New => {
                        self.last_stream = h.stream;
                        self.reset(env, h.stream, ErrorCode::ProtocolError)?;
                    }
                }
            }
            Frame::Headers(_) | Frame::Continuation(_) => self.on_headers(env, headers)?,
            Frame::Data(data) => self.on_data(env, data)?,
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
                    for setting in settings.entries {
                        self.peer_setting(setting)?;
                    }
                    // Every value is applied: now the acknowledgment (RFC
                    // 9113 section 6.5.3).
                    self.control(
                        env,
                        wire::HEADER_LEN,
                        &wire::Settings {
                            flags: 1,
                            entries: Vec::new(),
                        },
                    );
                }
            }
            Frame::WindowUpdate(update) => {
                if update.stream == 0 {
                    self.send_window =
                        grown(self.send_window, update.increment).ok_or_else(|| {
                            problem(ErrorCode::FlowControlError, "connection window overflow")
                        })?;
                } else if let Some(stream) = self.streams.get_mut(&update.stream) {
                    if let Some(n) = grown(stream.send_window, update.increment) {
                        stream.send_window = n;
                    } else {
                        self.reset(env, update.stream, ErrorCode::FlowControlError)?;
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
                if self.streams.get(&reset.stream).is_some_and(|s| !s.accepted) {
                    self.pending_resets += 1;
                    if self.pending_resets > PENDING_RESET_MAX {
                        return Err(problem(
                            ErrorCode::EnhanceYourCalm,
                            "too many pending request resets",
                        ));
                    }
                }
                let code = code_of(reset.code);
                self.end_stream(reset.stream, Ending::Reset(code));
            }
            Frame::Ping(ping) if ping.flags & 1 == 0 => {
                self.control(
                    env,
                    wire::HEADER_LEN + 8,
                    &wire::Ping {
                        flags: 1,
                        opaque: ping.opaque,
                    },
                );
            }
            Frame::Ping(ping) => {
                if self.shutdown_ping == Some(ping.opaque) {
                    self.shutdown_ping = None;
                    self.draining = true;
                    self.goaway(env, ErrorCode::NoError, self.last_stream);
                }
            }
            Frame::GoAway(_) => {
                self.draining = true;
                self.goaway(env, ErrorCode::NoError, self.last_stream);
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

    fn on_input(&mut self, env: &mut Env<'_, Report>, item: Input) -> Result<(), wire::Error> {
        match item {
            Input::Frame(frame) => self.on_frame(env, frame),
            Input::Refused {
                scope: wire::ErrorScope::Connection,
                error,
                ..
            } => Err(error),
            Input::Refused {
                header,
                error,
                scope: wire::ErrorScope::Stream,
                ..
            } => {
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
                } else if self.ignored(header.stream) {
                    // The server reset this stream a moment ago, so it
                    // ignores the stream's late frames (section 5.1).
                    Ok(())
                } else if priority || self.streams.contains_key(&header.stream) {
                    self.reset(env, header.stream, error.code)
                } else {
                    Ok(())
                }
            }
            Input::Preface => Ok(()),
        }
    }

    /// Reads input until a bounded number of frames is read, the children
    /// or the transport fall behind, or no whole frame is left. Returns
    /// whether anything moved, and whether all the input is read.
    fn read(&mut self, env: &mut Env<'_, Report>) -> (bool, bool) {
        let mut moved = false;
        for _ in 0..FRAMES {
            if self.phase != Phase::Open || self.up.len() >= UP_LIMIT || self.out_bytes >= OUT_LIMIT
            {
                return (moved, false);
            }
            if let Some(chunk) = &mut self.input {
                let n = self.frames.push(chunk);
                chunk.advance(n);
                if chunk.is_empty() {
                    self.input = None;
                }
                moved |= n > 0;
            }
            if self.input.is_none() && self.peer_ended && !self.frames.is_eof() {
                self.frames.end();
            }
            match self.frames.next() {
                Some(Ok(item)) => {
                    moved = true;
                    if let Err(error) = self.on_input(env, item) {
                        self.fail(env, error);
                        return (true, false);
                    }
                }
                Some(Err(fail)) => {
                    let error = match fail {
                        Fail::Protocol(error) => error,
                        _ => problem(ErrorCode::ProtocolError, "truncated HTTP/2 frame"),
                    };
                    self.fail(env, error);
                    return (true, false);
                }
                None if self.input.is_some() => {}
                None => return (moved, true),
            }
        }
        (moved, false)
    }

    /// The batch of input is read: credit goes back to the client, on the
    /// connection for what it no longer holds, on each stream for what its
    /// child can still take, once it is at least half of what the client
    /// has left, as h2 does, so many small frames share one WINDOW_UPDATE.
    /// Streams opened in the batch are taken in.
    fn release(&mut self, env: &mut Env<'_, Report>) -> bool {
        let held: i64 = self.streams.values().map(|s| i64::from(s.held)).sum();
        if let Some(back) = credit_back(self.recv_window, i64::from(WINDOW) - held) {
            if !self.window_update(env, 0, back) {
                return true;
            }
            self.recv_window += back as i32;
        }
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            let stream = self.streams.get_mut(&id).expect("an open stream");
            stream.accepted = true;
            // A stream's window follows its child: once the child has read
            // all it was given, the client may send what it can take. A
            // child that stops reading stops its stream, and only its
            // stream.
            if stream.credit < stream.peak {
                continue;
            }
            let room = (stream.credit.min(WINDOW as u64) as i64) - i64::from(stream.held);
            if let Some(back) = credit_back(stream.recv_window, room) {
                if !self.window_update(env, id, back) {
                    return true;
                }
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.recv_window += back as i32;
                }
            }
        }
        self.pending_resets = 0;
        self.batch = false;
        true
    }

    fn window_update(&mut self, env: &mut Env<'_, Report>, stream: u32, increment: u32) -> bool {
        self.control(
            env,
            wire::HEADER_LEN + 4,
            &wire::WindowUpdate {
                stream,
                flags: 0,
                increment,
            },
        )
    }

    // -----------------------------------------------------------------------
    // Responses

    fn on_child(&mut self, env: &mut Env<'_, Report>, child: ChildId, command: ExchangeCommand) {
        let Some(&id) = self.children.as_ref().and_then(|c| c.get(child)) else {
            return;
        };
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let body = matches!(stream.reply, Reply::Body);
        match command {
            ExchangeCommand::Reset(code) => self.write_reset(env, id, code),
            ExchangeCommand::Head(head) if matches!(stream.reply, Reply::Waiting) => {
                self.response_head(env, id, *head);
            }
            ExchangeCommand::Data(chunk) if body && chunk.len() as u64 <= stream.granted => {
                stream.granted -= chunk.len() as u64;
                stream.out_bytes += chunk.len() as u64;
                stream.out.push_back(chunk);
            }
            ExchangeCommand::Trailers(trailers) if body => {
                stream.reply = Reply::Ending(Some(trailers));
            }
            ExchangeCommand::End if body => stream.reply = Reply::Ending(None),
            // A child that answers out of order, or past its credit, broke
            // its exchange: the stream alone is reset.
            _ => self.write_reset(env, id, ErrorCode::InternalError),
        }
    }

    /// Encodes a response head as HEADERS and CONTINUATION frames, which go
    /// out together.
    fn response_head(&mut self, env: &mut Env<'_, Report>, id: u32, head: ResponseHead) {
        let mut fields = vec![hpack::Field::new(":status", head.status.as_str())];
        fields.extend(fields_of(&head.headers));
        if self.header_block(env, id, &fields, head.end)
            && let Some(stream) = self.streams.get_mut(&id)
        {
            stream.reply = if head.end { Reply::Ended } else { Reply::Body };
        }
    }

    /// Writes a header block on stream `id`. Returns whether it went out;
    /// one that cannot be encoded resets the stream.
    fn header_block(
        &mut self,
        env: &mut Env<'_, Report>,
        id: u32,
        fields: &[hpack::Field],
        end: bool,
    ) -> bool {
        let mut block = Vec::new();
        // A zero-capacity table keeps response storage bounded while still
        // honoring the peer's required table-size updates.
        if self.encoder.encode_block(fields, &mut block).is_err() {
            self.write_reset(env, id, ErrorCode::InternalError);
            return false;
        }
        let max = self.frame.max(1);
        let first = block.len().min(max);
        let frames = 1 + (block.len() - first).div_ceil(max);
        let len = block.len() + frames * wire::HEADER_LEN;
        let Some(charge) = env.budget().charge(len) else {
            self.over_budget(env);
            return false;
        };
        let mut out = Vec::with_capacity(len);
        let write = |out: &mut Vec<u8>| -> Result<(), wire::Error> {
            wire::Headers {
                stream: id,
                flags: u8::from(end) | if first == block.len() { 4 } else { 0 },
                fragment: block[..first].to_vec(),
                padding: None,
                priority: None,
            }
            .write(out)?;
            let rest = &block[first..];
            for (index, fragment) in rest.chunks(max).enumerate() {
                wire::Continuation {
                    stream: id,
                    flags: if (index + 1) * max >= rest.len() {
                        4
                    } else {
                        0
                    },
                    fragment: fragment.to_vec(),
                }
                .write(out)?;
            }
            Ok(())
        };
        if write(&mut out).is_err() {
            drop(charge);
            self.write_reset(env, id, ErrorCode::InternalError);
            return false;
        }
        self.queue(Chunk::with_charge(out, charge), id, 0, end);
        true
    }

    /// Frames response bodies within both windows, a frame per stream in
    /// turn, and the ends of bodies whose bytes are all out.
    fn send(&mut self, env: &mut Env<'_, Report>) -> bool {
        let mut moved = false;
        loop {
            let mut any = false;
            let ids: Vec<u32> = self
                .streams
                .range(self.turn.saturating_add(1)..)
                .chain(self.streams.range(..=self.turn))
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                if self.out_bytes >= OUT_LIMIT || self.phase != Phase::Open {
                    return moved;
                }
                if self.send_one(env, id) {
                    self.turn = id;
                    any = true;
                    moved = true;
                }
            }
            if !any {
                return moved;
            }
        }
    }

    /// One frame of stream `id`'s response, if it can go. Returns whether
    /// one went.
    fn send_one(&mut self, env: &mut Env<'_, Report>, id: u32) -> bool {
        let frame = self.frame.min(wire::DEFAULT_FRAME_SIZE);
        let window = self.send_window;
        let Some(stream) = self.streams.get_mut(&id) else {
            return false;
        };
        if let Some(front) = stream.out.front_mut() {
            let n = sendable(front.len(), window, stream.send_window, frame);
            if n == 0 {
                return false;
            }
            let payload = front.split_to(n);
            if front.is_empty() {
                stream.out.pop_front();
            }
            stream.send_window -= n as i32;
            stream.out_bytes -= n as u64;
            self.send_window -= n as i32;
            let Some(charge) = env.budget().charge(wire::HEADER_LEN) else {
                self.over_budget(env);
                return true;
            };
            let mut header = Vec::with_capacity(wire::HEADER_LEN);
            wire::FrameHeader {
                length: n,
                kind: 0,
                flags: 0,
                stream: id,
            }
            .write(&mut header)
            .expect("outbound frame has valid fields");
            self.queue(Chunk::with_charge(header, charge), id, 0, false);
            self.queue(payload, id, n as u64, false);
            self.grant(id);
            return true;
        }
        match std::mem::replace(&mut stream.reply, Reply::Ended) {
            Reply::Ending(None) => {
                self.frame_for(
                    env,
                    wire::HEADER_LEN,
                    &wire::Data {
                        stream: id,
                        flags: 1,
                        data: Vec::new(),
                        padding: None,
                    },
                    id,
                    true,
                );
                true
            }
            Reply::Ending(Some(trailers)) => {
                let fields = fields_of(&trailers);
                self.header_block(env, id, &fields, true);
                true
            }
            other => {
                stream.reply = other;
                false
            }
        }
    }

    /// Gives stream `id`'s child more credit for its body, as the bytes it
    /// sent go out.
    fn grant(&mut self, id: u32) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let more = more_credit(stream.granted, stream.out_bytes);
        if more > 0 && matches!(stream.reply, Reply::Body) {
            stream.granted += more;
            self.up.push_back(MuxEvent::Credit(stream.child, more));
        }
    }

    /// The transport took `n` more bytes: the frames they finish count for
    /// their streams, and a stream whose response's end went out is over.
    fn written(&mut self, env: &mut Env<'_, Report>, mut n: u64) {
        let mut touched: Vec<u32> = Vec::new();
        let mut finished: Vec<u32> = Vec::new();
        while n > 0 {
            let Some(piece) = self.sent.front_mut() else {
                break;
            };
            let step = n.min(piece.bytes);
            piece.bytes -= step;
            n -= step;
            self.out_bytes = self.out_bytes.saturating_sub(step as usize);
            if piece.bytes > 0 {
                break;
            }
            let piece = self.sent.pop_front().expect("a piece");
            if self.sent.is_empty() {
                self.sent = VecDeque::new();
            }
            if piece.stream == 0 {
                continue;
            }
            if let Some(stream) = self.streams.get_mut(&piece.stream) {
                if piece.body > 0 {
                    stream.written += piece.body;
                    if !touched.contains(&piece.stream) {
                        touched.push(piece.stream);
                    }
                }
                if piece.end {
                    finished.push(piece.stream);
                }
            }
        }
        for id in touched {
            if let Some(stream) = self.streams.get(&id)
                && !finished.contains(&id)
            {
                self.up.push_back(MuxEvent::Child(
                    stream.child,
                    ExchangeEvent::Written(stream.written),
                ));
            }
        }
        for id in finished {
            let open = self.streams.get(&id).is_some_and(|s| !s.recv_closed);
            self.end_stream(id, Ending::Done);
            if open {
                // The response is complete but the request is not: ask the
                // client to stop sending it, without an error (RFC 9113
                // section 8.1). Not the client's error, so not counted.
                self.write_reset(env, id, ErrorCode::NoError);
            }
        }
    }
}

impl Layer for Http2 {
    type Lower = ByteStream;
    type Upper = Mux<HttpExchange, Top, Opening>;
    type Report = Report;
    type Timer = Timer;
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn report_bytes(_: &Report) -> Option<usize> {
        Some(0)
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Report>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        if self.phase == Phase::Opening {
            self.open(env);
        }
        match event {
            StreamEvent::Data(chunk) => {
                if matches!(self.phase, Phase::Closing | Phase::Closed) || self.peer_ended {
                    return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                }
                if chunk.is_empty() {
                    return Ok(Admit::Taken);
                }
                // One delivery at a time, read whole before the next, and
                // none while the transport falls behind. The delivery keeps
                // whatever charge it came with: the bytes are read from it
                // into the frame buffer, which is held at its bound.
                if self.input.is_some() || self.out_bytes >= OUT_LIMIT {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                self.input = Some(chunk);
                Ok(Admit::Taken)
            }
            StreamEvent::Written(n) => {
                self.written(env, n);
                Ok(Admit::Taken)
            }
            StreamEvent::Ended => {
                self.peer_ended = true;
                Ok(Admit::Taken)
            }
            StreamEvent::Reset => {
                let ids: Vec<u32> = self.streams.keys().copied().collect();
                for id in ids {
                    self.end_stream(id, Ending::Gone);
                }
                self.out.clear();
                self.sent.clear();
                self.out_bytes = 0;
                self.input = None;
                self.resets = VecDeque::new();
                self.phase = Phase::Closed;
                Ok(Admit::Taken)
            }
        }
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Report>,
        command: MuxCommand<HttpExchange, Top>,
    ) -> Result<Admit<MuxCommand<HttpExchange, Top>>, Infallible> {
        if self.phase == Phase::Opening {
            self.open(env);
        }
        if matches!(self.phase, Phase::Closing | Phase::Closed) {
            return Ok(Admit::Closed(command));
        }
        // A response head is framed at once: it waits while the transport
        // falls behind.
        if matches!(command.op(), MuxOp::Child(_, ExchangeCommand::Head(_)))
            && self.out_bytes >= OUT_LIMIT
        {
            return Ok(Admit::Blocked(command));
        }
        match command.into_op() {
            MuxOp::Child(child, command) => {
                self.on_child(env, child, command);
                Ok(Admit::Taken)
            }
            MuxOp::Credit(child, units) => {
                if let Some(&id) = self.children.as_ref().and_then(|c| c.get(child)) {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.credit = stream.credit.saturating_add(units);
                        stream.peak = stream.peak.max(stream.credit);
                        stream.credited = true;
                    }
                    self.forward(id);
                    // The child read: credit for its stream may be due.
                    self.batch = true;
                }
                Ok(Admit::Taken)
            }
            MuxOp::Close(child) => {
                // The children refused or dropped this exchange: its stream
                // is refused, or reset if its response had begun.
                if let Some(&id) = self.children.as_ref().and_then(|c| c.get(child))
                    && let Some(stream) = self.streams.get(&id)
                {
                    let code = if matches!(stream.reply, Reply::Waiting) {
                        ErrorCode::RefusedStream
                    } else {
                        ErrorCode::InternalError
                    };
                    self.write_reset(env, id, code);
                }
                Ok(Admit::Taken)
            }
            MuxOp::Control(never) => match never {},
        }
    }

    fn on_timer(&mut self, env: &mut Env<'_, Report>, _: Timer) -> Result<(), Infallible> {
        let now = env.now();
        if self.phase != Phase::Open {
            return Ok(());
        }
        if self.settings_deadline.is_some_and(|at| at <= now) {
            self.settings_deadline = None;
            self.fail(
                env,
                problem(
                    ErrorCode::SettingsTimeout,
                    "SETTINGS acknowledgment timed out",
                ),
            );
            return Ok(());
        }
        while self.resets.front().is_some_and(|(_, at)| *at <= now) {
            self.resets.pop_front();
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Report>) -> Result<bool, Infallible> {
        let mut moved = false;
        if self.phase == Phase::Opening {
            self.open(env);
            moved = true;
        }
        if self.phase != Phase::Open {
            return Ok(moved);
        }
        if self.shutdown_requested && self.shutdown_ping.is_none() && !self.draining {
            self.shutdown_requested = false;
            let opaque = env.entropy().random_u64().to_be_bytes();
            self.shutdown_ping = Some(opaque);
            self.goaway(env, ErrorCode::NoError, wire::MAX_WINDOW);
            self.control(env, wire::HEADER_LEN + 8, &wire::Ping { flags: 0, opaque });
            moved = true;
        }
        let (read, drained) = self.read(env);
        moved |= read;
        // The batch is over once every byte of it is read and handed up,
        // and every child it opened has granted its first credit.
        if drained
            && self.batch
            && self.up.is_empty()
            && self.streams.values().all(|s| s.credited)
            && self.phase == Phase::Open
        {
            moved |= self.release(env);
        }
        if self.phase == Phase::Open {
            moved |= self.send(env);
        }
        if self.phase == Phase::Open && self.draining && self.streams.is_empty() {
            self.close();
            moved = true;
        }
        if self.phase == Phase::Open && drained && self.peer_ended && self.input.is_none() {
            // The client sent everything: what is queued goes out, and the
            // connection ends with no GOAWAY.
            self.close();
            moved = true;
        }
        if matches!(self.phase, Phase::Open) && !self.fits() {
            self.over_budget(env);
            moved = true;
        }
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        let command = self.out.pop_front()?;
        if matches!(command, StreamCommand::End | StreamCommand::Reset) {
            self.phase = Phase::Closed;
        }
        if self.out.is_empty() {
            // Queues hold nothing while the connection is idle; the next
            // advance charges what is left.
            self.out = VecDeque::new();
        }
        Some(command)
    }

    fn take_event(&mut self) -> Option<MuxEvent<HttpExchange, Top, Opening>> {
        let event = self.up.pop_front()?;
        if self.up.is_empty() {
            self.up = VecDeque::new();
        }
        Some(event)
    }

    fn is_terminal(&self) -> bool {
        self.phase == Phase::Closed
    }

    fn deadline(&self) -> Option<(Instant, Timer)> {
        if self.phase != Phase::Open {
            return None;
        }
        self.resets
            .front()
            .map(|(_, at)| *at)
            .into_iter()
            .chain(self.settings_deadline)
            .min()
            .map(|at| (at, Timer::Deadline))
    }
}

fn problem(code: ErrorCode, reason: &'static str) -> wire::Error {
    wire::Error { code, reason }
}

/// The credit `release` returns for a receive window at `window` that may
/// hold up to `room`: what tops it up to `room`, once that is at least half
/// of what the client has left, as h2 does, so many small frames share one
/// WINDOW_UPDATE.
fn credit_back(window: i32, room: i64) -> Option<u32> {
    let back = room - i64::from(window);
    (back > 0 && back >= i64::from(window / 2)).then_some(back as u32)
}

/// How much of a body piece of `len` bytes one DATA frame carries: the
/// least of it, the connection's and the stream's send windows, and the
/// frame size. A window is negative after the client shrinks its initial
/// window, and then carries nothing.
fn sendable(len: usize, connection: i32, stream: i32, frame: usize) -> usize {
    len.min(connection.max(0) as usize)
        .min(stream.max(0) as usize)
        .min(frame)
}

/// A send window after a WINDOW_UPDATE of `increment`, or `None` past
/// 2^31 - 1 (RFC 9113 section 6.9.1).
fn grown(window: i32, increment: u32) -> Option<i32> {
    window.checked_add(i32::try_from(increment).ok()?)
}

/// A stream's send window after the client moves its initial window from
/// `old` to `new`, or `None` past 2^31 - 1 (RFC 9113 section 6.9.2).
fn shifted(window: i32, old: i32, new: i32) -> Option<i32> {
    window.checked_add(new - old)
}

/// The body credit a child gets as its bytes go out: what tops its granted
/// and queued bytes back up to `SEND_CREDIT`.
fn more_credit(granted: u64, queued: u64) -> u64 {
    SEND_CREDIT.saturating_sub(granted.saturating_add(queued))
}

/// The code of a wire value, with unknown codes treated as `INTERNAL_ERROR`
/// (RFC 9113 section 7).
fn code_of(code: u32) -> ErrorCode {
    use ErrorCode::*;
    [
        NoError,
        ProtocolError,
        InternalError,
        FlowControlError,
        SettingsTimeout,
        StreamClosed,
        FrameSizeError,
        RefusedStream,
        Cancel,
        CompressionError,
        ConnectError,
        EnhanceYourCalm,
        InadequateSecurity,
        Http11Required,
    ]
    .get(code as usize)
    .copied()
    .unwrap_or(InternalError)
}

/// Fields HTTP/2 carries of `headers`: never the connection-specific ones
/// (RFC 9113 section 8.2.2).
fn fields_of(headers: &HeaderMap) -> Vec<hpack::Field> {
    headers
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
            )
        })
        .map(|(name, value)| hpack::Field::new(name.as_str(), value.as_bytes()))
        .collect()
}

pub(super) fn content_length(headers: &http::HeaderMap) -> Result<Option<u64>, ()> {
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
            !h.name.starts_with(b":")
                && valid_name(&h.name)
                && HeaderValue::from_bytes(&h.value).is_ok()
        })
}

/// A checked trailer block as a map.
fn trailer_map(block: hpack::Block) -> HeaderMap {
    let mut map = HeaderMap::new();
    for h in block.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&h.name),
            HeaderValue::from_bytes(&h.value),
        ) {
            map.append(name, value);
        }
    }
    map
}

fn valid_name(name: &[u8]) -> bool {
    !name.iter().any(u8::is_ascii_uppercase)
        && HeaderName::from_bytes(name).is_ok()
        && !matches!(
            name,
            b"connection" | b"proxy-connection" | b"keep-alive" | b"transfer-encoding" | b"upgrade"
        )
}

fn request(block: hpack::Block, limits: Limits) -> Option<Request<()>> {
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
        let (name, value) = (h.name, h.value);
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
        .body(())
        .ok()?;
    *request.headers_mut() = headers;
    Some(request)
}

/// Bounded proofs over the flow-control arithmetic, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../../verification/http2-layer/kani/flow.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::super::{Body, Exchange, Handler, HttpOptions, Reply, text};
    use super::*;
    use fictionet::Cx;
    use fictionet::stdlib::layer::Harness;
    use fictionet::stdlib::network::ConnInfo;
    use fictionet::stdlib::network::{ConnError, Connection};
    use fictionet::stdlib::services::stack::Polling;
    use fictionet::sync::Mutex;
    use http::StatusCode;
    use std::future::{Future, poll_fn};
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    struct StalledBody {
        input: bytes::Bytes,
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
                let mut input = wire::PREFACE.to_vec();
                input.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
                // POST / over HTTP, with no END_STREAM on the headers.
                let block = b"\x83\x86\x84\x01\x01a";
                input.extend_from_slice(&[0, 0, block.len() as u8, 1, 4, 0, 0, 0, 1]);
                input.extend_from_slice(block);
                let output = Arc::new(Mutex::new(Vec::new()));
                let conn = StalledBody {
                    output: output.clone(),
                    input: bytes::Bytes::from(input),
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
                        let header =
                            wire::FrameHeader::parse(&output[consumed..consumed + 9]).unwrap();
                        let end = consumed + 9 + header.length;
                        if end > output.len() {
                            break;
                        }
                        let frame = Frame::parse(&output[consumed..end]).unwrap();
                        consumed = end;
                        let read = blocks.read_frame(&frame).unwrap();
                        if let Some(block) = read.block
                            && let Some(status) = block
                                .headers
                                .into_iter()
                                .find(|header| header.name == b":status")
                        {
                            return Poll::Ready(status.value);
                        }
                    }
                    Poll::Pending
                })
                .await;
                assert_eq!(status, b"408");
                assert_eq!(fcx.now().since_start(), duration);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn closing_http2_returns_the_unaccepted_command() {
        use fictionet::stdlib::layer::{Budget, Driver, Slots};
        for phase in [Phase::Closing, Phase::Closed] {
            let mut http = Http2::new(Limits::default());
            http.phase = phase;
            let mut driver = Driver::new(
                http,
                Arc::new(fictionet::SeededEntropy::new(fictionet::Seed::from_u64(91))),
                Budget::unlimited(),
                Instant::ZERO,
            );
            let mut slots = Slots::new(1);
            let child = slots.insert(()).unwrap();
            let id = child.id();
            let answer = driver.command(child.close()).unwrap();
            let Admit::Closed(command) = answer else {
                panic!("closed input must return ownership")
            };
            assert!(matches!(command.into_op(), MuxOp::Close(found) if found == id));
        }
    }

    struct NotFound;
    impl Handler for NotFound {
        fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            Reply::Now(text(StatusCode::NOT_FOUND, "Not found.\n"))
        }
    }

    fn harness() -> Harness<Http2Server> {
        Harness::new(
            fictionet::Seed::from_u64(1),
            Responder::new(NotFound).http2(),
        )
        .with_worker(Polling::new())
    }

    /// The client sends `bytes`; what the server wrote back.
    fn push(harness: &mut Harness<Http2Server>, bytes: &[u8]) -> Vec<u8> {
        harness.push(bytes).unwrap();
        harness.take_output()
    }

    fn write<W: Wire<WriteError = wire::Error>>(frame: &W, out: &mut Vec<u8>) {
        frame.write(out).expect("outbound frame has valid fields");
    }

    /// The client preface, its SETTINGS, and its acknowledgment of the server's.
    fn client_preface() -> Vec<u8> {
        let mut bytes = wire::PREFACE.to_vec();
        for flags in [0, 1] {
            write(
                &wire::Settings {
                    flags,
                    entries: Vec::new(),
                },
                &mut bytes,
            );
        }
        bytes
    }

    /// `POST /` over HTTP as one HEADERS frame on `stream` that ends the
    /// stream. With `self_dependent`, its priority names the stream itself,
    /// which no writer produces.
    fn post(stream: u32, self_dependent: bool) -> Vec<u8> {
        let block = [0x83, 0x86, 0x84];
        let priority = if self_dependent { 5 } else { 0 };
        let mut bytes = vec![0, 0, (block.len() + priority) as u8, 1];
        bytes.push(if self_dependent { 0x25 } else { 5 });
        bytes.extend_from_slice(&stream.to_be_bytes());
        if self_dependent {
            bytes.extend_from_slice(&stream.to_be_bytes());
            bytes.push(0);
        }
        bytes.extend_from_slice(&block);
        bytes
    }

    fn frames(mut bytes: &[u8]) -> Vec<Frame> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let header = wire::FrameHeader::parse(&bytes[..9]).unwrap();
            let end = 9 + header.length;
            frames.push(Frame::parse(&bytes[..end]).unwrap());
            bytes = &bytes[end..];
        }
        frames
    }

    #[test]
    fn self_dependent_headers_preserve_compression_across_continuations() {
        for fragmented in [false, true] {
            let mut harness = harness();
            push(&mut harness, &client_preface());
            let mut encoder = hpack::Encoder::new(4096);
            let fields = [
                hpack::Field::new(":method", "GET"),
                hpack::Field::new(":scheme", "http"),
                hpack::Field::new(":path", "/"),
                hpack::Field::new("x-saved", "retained"),
            ];
            let mut block = Vec::new();
            encoder.encode_block(&fields, &mut block).unwrap();
            let split = if fragmented {
                block.len() / 2
            } else {
                block.len()
            };
            let mut input = wire::FrameHeader {
                length: 5 + split,
                kind: 1,
                flags: if fragmented { 0x21 } else { 0x25 },
                stream: 1,
            }
            .to_bytes()
            .unwrap();
            input.extend_from_slice(&[0, 0, 0, 1, 0]);
            input.extend_from_slice(&block[..split]);
            if fragmented {
                wire::Continuation {
                    stream: 1,
                    flags: 4,
                    fragment: block[split..].to_vec(),
                }
                .write(&mut input)
                .unwrap();
            }
            let mut indexed = Vec::new();
            encoder.encode_block(&fields, &mut indexed).unwrap();
            assert!(indexed.len() < block.len());
            wire::Headers {
                stream: 3,
                flags: 5,
                fragment: indexed,
                priority: None,
                padding: None,
            }
            .write(&mut input)
            .unwrap();
            let output = frames(&push(&mut harness, &input));
            assert!(output.iter().any(|f| matches!(f, Frame::Reset(r)
                if r.stream == 1 && r.code == ErrorCode::ProtocolError as u32)));
            assert!(
                output
                    .iter()
                    .any(|f| matches!(f, Frame::Headers(h) if h.stream == 3))
            );
            assert!(!output.iter().any(|f| matches!(f, Frame::GoAway(_))));
            assert!(!harness.ended());
        }
    }

    #[test]
    fn self_dependent_headers_on_a_closed_stream_end_the_connection() {
        // HEADERS on a stream that has ended, or below one already opened,
        // ends the connection (RFC 9113 sections 5.1 and 5.1.1), whatever
        // priority the frame carries.
        for (open, again) in [(1, 1), (5, 3)] {
            let mut harness = harness();
            push(&mut harness, &client_preface());
            let output = frames(&push(&mut harness, &post(open, false)));
            assert!(
                output
                    .iter()
                    .any(|f| matches!(f, Frame::Headers(h) if h.stream == open))
            );
            let output = frames(&push(&mut harness, &post(again, true)));
            assert!(
                output.iter().any(|f| matches!(f, Frame::GoAway(g)
                    if g.last_stream == open && g.code == ErrorCode::ProtocolError as u32)),
                "{output:?}"
            );
            assert!(!output.iter().any(|f| matches!(f, Frame::Reset(_))));
            assert!(harness.ended());
        }
    }

    /// A child that takes every event but body bytes, which it reads only
    /// while `reads` is set, or from the time `from` on.
    struct Sink {
        reads: bool,
        from: Option<Instant>,
    }

    impl Sink {
        fn reading(reads: bool) -> Sink {
            Sink { reads, from: None }
        }

        fn reading_from(at: Instant) -> Sink {
            Sink {
                reads: false,
                from: Some(at),
            }
        }
    }

    impl Layer for Sink {
        type Lower = HttpExchange;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;

        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: ExchangeEvent,
        ) -> Result<Admit<ExchangeEvent>, Infallible> {
            if !self.reads && matches!(event, ExchangeEvent::Data(_)) {
                return Ok(Admit::Blocked(event));
            }
            Ok(Admit::Taken)
        }

        fn deadline(&self) -> Option<(Instant, ())> {
            self.from.filter(|_| !self.reads).map(|at| (at, ()))
        }

        fn on_timer(&mut self, _: &mut Env<'_, Infallible>, (): ()) -> Result<(), Infallible> {
            self.reads = true;
            Ok(())
        }

        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }

        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<ExchangeCommand> {
            None
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    #[test]
    fn a_stalled_upgrade_body_holds_back_only_its_own_stream() {
        use fictionet::stdlib::layer::{Chain, Children};
        // An `Upgrade: h2c` request whose child never reads its body. The
        // body came over HTTP/1, outside every receive window, so the
        // bytes it holds must not keep the connection's credit from the
        // client's other streams.
        let request = Request::builder()
            .method(Method::POST)
            .uri("/stall")
            .version(Version::HTTP_2)
            .body(())
            .unwrap();
        let opening = Opening {
            request: Box::new(request),
            ended: false,
            at: Instant::ZERO,
            charge: None,
        };
        let body = Chunk::new(vec![b'x'; 200_000]);
        let server = Chain::new(
            Http2::upgraded(Limits::default(), &[], opening, Some(body)),
            Children::new(8, Http2::WINDOW, |_, opening: Opening, _| {
                Some(Sink::reading(opening.request.uri().path() != "/stall"))
            }),
        );
        let mut harness = Harness::new(fictionet::Seed::from_u64(1), server);
        harness.push(&client_preface()).unwrap();
        harness.take_output();
        let mut input = headers_without_end(3);
        input.extend(window_of_data(3));
        harness.push(&input).unwrap();
        let output = frames(&harness.take_output());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream == 0)),
            "{output:?}"
        );
        assert!(!harness.ended());
    }

    /// `POST /` over HTTP as one HEADERS frame on `stream`, its body to
    /// come.
    fn headers_without_end(stream: u32) -> Vec<u8> {
        let mut bytes = vec![0, 0, 3, 1, 4];
        bytes.extend_from_slice(&stream.to_be_bytes());
        bytes.extend_from_slice(&[0x83, 0x86, 0x84]);
        bytes
    }

    /// DATA on `stream` filling a whole default receive window.
    fn window_of_data(stream: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for len in [16_384, 16_384, 16_384, 16_383] {
            write(
                &wire::Data {
                    stream,
                    flags: 0,
                    data: vec![b'y'; len],
                    padding: None,
                },
                &mut bytes,
            );
        }
        bytes
    }

    /// `POST <path>` over HTTP as one HEADERS frame on `stream`, its body to
    /// come.
    fn headers_to(stream: u32, path: &str) -> Vec<u8> {
        let mut block = vec![0x83, 0x86, 0x04, path.len() as u8];
        block.extend_from_slice(path.as_bytes());
        let mut bytes = Vec::new();
        write(
            &wire::Headers {
                stream,
                flags: 4,
                fragment: block,
                priority: None,
                padding: None,
            },
            &mut bytes,
        );
        bytes
    }

    #[test]
    fn a_child_that_stops_reading_stops_only_its_own_stream() {
        use fictionet::stdlib::layer::{Chain, Children};
        let server = Chain::new(
            Http2::new(Limits::default()),
            Children::new(8, Http2::WINDOW, |_, opening: Opening, _| {
                Some(Sink::reading(opening.request.uri().path() != "/stall"))
            }),
        );
        let mut harness = Harness::new(fictionet::Seed::from_u64(1), server);
        harness.push(&client_preface()).unwrap();
        harness.take_output();
        harness.push(&headers_to(1, "/stall")).unwrap();
        // The client sends stream 1 all the credit the server gives it.
        let (mut connection, mut stream) = (i64::from(WINDOW), i64::from(WINDOW));
        for _ in 0..64 {
            let n = connection.min(stream).min(16_384);
            if n == 0 {
                break;
            }
            let mut data = Vec::new();
            write(
                &wire::Data {
                    stream: 1,
                    flags: 0,
                    data: vec![b'y'; n as usize],
                    padding: None,
                },
                &mut data,
            );
            harness.push(&data).unwrap();
            connection -= n;
            stream -= n;
            for frame in frames(&harness.take_output()) {
                if let Frame::WindowUpdate(w) = frame {
                    match w.stream {
                        0 => connection += i64::from(w.increment),
                        1 => stream += i64::from(w.increment),
                        _ => {}
                    }
                }
            }
        }
        // Its child stopped reading, so stream 1 stopped; the connection
        // still has room for the other streams.
        assert_eq!(stream, 0);
        assert!(connection > 0, "{connection}");
        let mut input = headers_to(3, "/");
        input.extend(window_of_data(3));
        harness.push(&input).unwrap();
        let output = frames(&harness.take_output());
        assert!(!output.iter().any(|f| matches!(f, Frame::GoAway(_))));
        assert!(!harness.ended());
    }

    #[test]
    fn credit_returns_once_a_slow_child_reads() {
        use fictionet::stdlib::layer::{Chain, Children};
        let later = std::time::Duration::from_secs(1);
        let mut child = Some(Sink::reading_from(Instant::ZERO + later));
        let server = Chain::new(
            Http2::new(Limits::default()),
            Children::new(8, Http2::WINDOW, move |_, _, _| {
                Some(child.take().expect("one stream"))
            }),
        );
        let mut harness = Harness::new(fictionet::Seed::from_u64(1), server);
        harness.push(&client_preface()).unwrap();
        harness.take_output();
        // The window goes up to the child, which does not read it yet: the
        // connection's credit comes back, the stream's does not.
        let mut input = headers_without_end(1);
        input.extend(window_of_data(1));
        harness.push(&input).unwrap();
        let output = frames(&harness.take_output());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream == 0)),
            "{output:?}"
        );
        assert!(
            !output
                .iter()
                .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream == 1)),
            "{output:?}"
        );
        // The child reads, long after the batch: the stream's credit comes
        // back with no more input.
        harness.advance(later).unwrap();
        let output = frames(&harness.take_output());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream == 1)),
            "{output:?}"
        );
        assert!(!harness.ended());
    }

    #[test]
    fn credit_held_for_a_stream_that_ends_returns() {
        use fictionet::stdlib::layer::{Chain, Children};
        // With a child window smaller than the stream's, the connection
        // holds the rest of a window of body for a child that never reads.
        // When the stream ends, those bytes are gone, and the client's
        // connection credit must come back.
        let server = Chain::new(
            Http2::new(Limits::default()),
            Children::new(8, 16_384, |_, _, _| Some(Sink::reading(false))),
        );
        let mut harness = Harness::new(fictionet::Seed::from_u64(1), server);
        harness.push(&client_preface()).unwrap();
        let mut input = headers_without_end(1);
        input.extend(window_of_data(1));
        harness.push(&input).unwrap();
        harness.take_output();
        let mut reset = Vec::new();
        write(
            &wire::Reset {
                stream: 1,
                flags: 0,
                code: ErrorCode::Cancel as u32,
            },
            &mut reset,
        );
        harness.push(&reset).unwrap();
        let output = frames(&harness.take_output());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream == 0)),
            "{output:?}"
        );
        assert!(!harness.ended());
    }

    #[test]
    fn settings_that_fail_are_not_acknowledged() {
        let mut harness = harness();
        push(&mut harness, &client_preface());
        // Stream 1 is open, its send window raised to 2^31 - 1.
        let mut input = headers_without_end(1);
        write(
            &wire::WindowUpdate {
                stream: 1,
                flags: 0,
                increment: wire::MAX_WINDOW - WINDOW as u32,
            },
            &mut input,
        );
        push(&mut harness, &input);
        // One more byte of initial window takes it past 2^31 - 1: a
        // connection error (RFC 9113 section 6.9.2), so the settings were
        // never applied and get no acknowledgment (section 6.5.3).
        let mut settings = Vec::new();
        write(
            &wire::Settings {
                flags: 0,
                entries: vec![wire::Setting {
                    id: 4,
                    value: WINDOW as u32 + 1,
                }],
            },
            &mut settings,
        );
        let output = frames(&push(&mut harness, &settings));
        assert!(
            output.iter().any(|f| matches!(f, Frame::GoAway(g)
                if g.code == ErrorCode::FlowControlError as u32)),
            "{output:?}"
        );
        assert!(
            !output
                .iter()
                .any(|f| matches!(f, Frame::Settings(s) if s.flags & 1 != 0)),
            "{output:?}"
        );
    }

    const BODY: &[u8] = b"hello";

    /// A stream's child installed in place of [`Respond`]: with a request
    /// for `/stuck` it never takes an event; otherwise it answers with
    /// [`BODY`] once the request ends.
    struct Picky {
        stuck: bool,
        out: VecDeque<ExchangeCommand>,
    }

    impl Picky {
        fn new(opening: Opening) -> Self {
            let mut picky = Picky {
                stuck: opening.request.uri().path() == "/stuck",
                out: VecDeque::new(),
            };
            if opening.ended && !picky.stuck {
                picky.answer();
            }
            picky
        }

        fn answer(&mut self) {
            self.out.extend([
                ExchangeCommand::Head(Box::new(ResponseHead {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    end: false,
                })),
                ExchangeCommand::Data(Chunk::new(BODY.to_vec())),
                ExchangeCommand::End,
            ]);
        }
    }

    impl Layer for Picky {
        type Lower = HttpExchange;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;

        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            event: ExchangeEvent,
        ) -> Result<Admit<ExchangeEvent>, Infallible> {
            if self.stuck {
                return Ok(Admit::Blocked(event));
            }
            if matches!(event, ExchangeEvent::End | ExchangeEvent::Trailers(_)) {
                self.answer();
            }
            Ok(Admit::Taken)
        }

        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }

        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<ExchangeCommand> {
            self.out.pop_front()
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    fn request_block(encoder: &mut hpack::Encoder, method: &str, path: &str) -> Vec<u8> {
        let mut block = Vec::new();
        encoder
            .encode_block(
                &[
                    hpack::Field::new(":method", method),
                    hpack::Field::new(":scheme", "http"),
                    hpack::Field::new(":path", path),
                ],
                &mut block,
            )
            .unwrap();
        block
    }

    #[test]
    fn a_child_that_never_reads_holds_up_neither_its_siblings_nor_the_connection() {
        let server = fictionet::stdlib::layer::Chain::new(
            Http2::new(Limits::default()),
            fictionet::stdlib::layer::Children::new(16, Http2::WINDOW, |_, opening, _| {
                Some(Picky::new(opening))
            }),
        );
        let mut harness = Harness::new(fictionet::Seed::from_u64(2), server);
        // The client's streams start with no window, so a response body
        // goes out only after the client's WINDOW_UPDATE is read.
        let mut input = wire::PREFACE.to_vec();
        write(
            &wire::Settings {
                flags: 0,
                entries: vec![wire::Setting { id: 4, value: 0 }],
            },
            &mut input,
        );
        write(
            &wire::Settings {
                flags: 1,
                entries: Vec::new(),
            },
            &mut input,
        );
        harness.push(&input).unwrap();
        harness.take_output();

        let mut encoder = hpack::Encoder::new(4096);
        let mut input = Vec::new();
        // Stream 1's child never reads: its body comes in far more pieces
        // than a child holds, and past half the connection's window.
        write(
            &wire::Headers {
                stream: 1,
                flags: 4,
                fragment: request_block(&mut encoder, "POST", "/stuck"),
                priority: None,
                padding: None,
            },
            &mut input,
        );
        for _ in 0..200 {
            write(
                &wire::Data {
                    stream: 1,
                    flags: 0,
                    data: vec![0; 200],
                    padding: None,
                },
                &mut input,
            );
        }
        // Behind it: connection traffic and a sibling request.
        write(
            &wire::Ping {
                flags: 0,
                opaque: *b"isolated",
            },
            &mut input,
        );
        write(
            &wire::Settings {
                flags: 0,
                entries: vec![wire::Setting { id: 2, value: 0 }],
            },
            &mut input,
        );
        write(
            &wire::Headers {
                stream: 3,
                flags: 5,
                fragment: request_block(&mut encoder, "GET", "/"),
                priority: None,
                padding: None,
            },
            &mut input,
        );
        write(
            &wire::WindowUpdate {
                stream: 3,
                flags: 0,
                increment: BODY.len() as u32,
            },
            &mut input,
        );
        harness.push(&input).unwrap();
        let output = frames(&harness.take_output());

        assert!(
            output.iter().any(|f| matches!(f, Frame::Ping(p)
                if p.flags & 1 == 1 && p.opaque == *b"isolated")),
            "{output:?}"
        );
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Settings(s) if s.flags & 1 == 1))
        );
        // The stuck child alone is reset, and the body it never read gives
        // the connection's window back.
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Reset(r) if r.stream == 1))
        );
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::WindowUpdate(w) if w.stream == 0))
        );
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Headers(h) if h.stream == 3))
        );
        let body: Vec<u8> = output
            .iter()
            .filter_map(|f| match f {
                Frame::Data(d) if d.stream == 3 => Some(d.data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(body, BODY);
        assert!(!output.iter().any(|f| matches!(f, Frame::GoAway(_))));
        assert!(!harness.ended());
    }

    #[test]
    fn late_frames_on_a_reset_stream_are_ignored() {
        let mut harness = harness();
        push(&mut harness, &client_preface());
        let output = frames(&push(&mut harness, &post(1, true)));
        assert!(output.iter().any(|f| matches!(f, Frame::Reset(r)
            if r.stream == 1 && r.code == ErrorCode::ProtocolError as u32)));
        // The server reset stream 1, so it ignores the stream's late frames
        // for a while (RFC 9113 section 5.1), even ones that would be
        // stream errors on an open stream.
        for late in [
            post(1, false),
            post(1, true),
            // PRIORITY with a 4-byte payload.
            vec![0, 0, 4, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0],
        ] {
            assert_eq!(frames(&push(&mut harness, &late)), [], "{late:?}");
        }
        assert!(!harness.ended());
    }
}
