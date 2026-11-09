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
    Admit, ByteStream, Charge, ChildId, Chunk, Env, Layer, Mux, MuxCommand, MuxEvent, MuxOp, Slots,
    StreamCommand, StreamEvent, Top,
};
use fictionet::stdlib::protocols::hpack;
use fictionet::stdlib::protocols::http2::{self as wire, ErrorCode, Frame, Input, Inputs};
use fictionet::time::Instant;

use super::Limits;
use super::response::{Dates, headers_held, request_held};

mod exchange;
mod grpc;
mod respond;

pub use exchange::{
    Ending, ExchangeCommand, ExchangeEvent, HttpExchange, Opening, RequestTrailers, ResponseHead,
};
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
/// The places each connection queue keeps while the connection is idle,
/// held from the start, so ordinary requests do not allocate them again.
/// A queue that grew past them gives the rest back once it drains.
const KEEP: usize = 8;

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
    /// The DATA bytes all streams hold for their children: they count
    /// against the connection's receive window.
    windowed_bytes: u64,
    /// Streams whose child has not granted credit yet.
    uncredited: usize,
    /// Streams whose receive credit may be due: their window, held bytes
    /// or child credit changed since the last release, or they are new.
    credit_due: Vec<u32>,
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
    /// Bytes queued for the transport whose completion has not come.
    unwritten_bytes: usize,
    /// What was queued, in order, for the transport's completions.
    sent: VecDeque<Piece>,
    /// The streams a completion touched and finished: kept between
    /// completions so none allocates, bounded by the streams open at once.
    touched: Vec<u32>,
    finished: Vec<u32>,
    /// Streams with a frame they can send, in the order they take turns.
    runnable: VecDeque<u32>,
    /// Streams whose next frame waits for the connection's send window.
    awaiting_window: VecDeque<u32>,
    charge: Option<Charge>,
    last_words: Option<Charge>,
    /// The request an HTTP/1 `Upgrade: h2c` brought, for stream 1.
    upgrade: Option<(Opening, Option<Chunk>)>,
    /// The `Date` headers of the responses: one made per second of the
    /// world's clock serves every stream framed in that second.
    dates: Dates,
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
    /// A release has taken the stream in. A client reset of a stream not
    /// yet taken in counts toward the pending reset limit.
    accepted: bool,
    receive: Receive,
    delivery: Delivery,
    response: Response,
}

/// The request as it comes off the wire, within the stream's receive
/// window.
struct Receive {
    /// The client sent the request's end.
    closed: bool,
    /// The body bytes `content-length` still promises.
    content_remaining: Option<u64>,
    /// The bytes the client may still send on the stream.
    window: i32,
    /// The stream is in the connection's `credit_due`.
    credit_due: bool,
}

/// The request on its way up to the child, within the credit the child
/// grants.
struct Delivery {
    /// Body bytes that wait for the child's credit, in order. Behind them
    /// go the overflow, if any, and then the end.
    pending: ChargedQueue<Chunk>,
    /// Bytes of DATA frames waiting in `pending`: they count against the
    /// receive windows until they go up.
    windowed_bytes: u32,
    /// Bytes waiting in `pending` that came outside the receive windows:
    /// the body an `Upgrade: h2c` request brought over HTTP/1. They are
    /// first in `pending`, ahead of any DATA.
    unwindowed_bytes: u64,
    /// Credit the child granted that its events have not used.
    credit_bytes: u64,
    /// The most credit the child has held at once: its window. Its credit
    /// is back at the peak once it has read all it was given.
    peak_credit_bytes: u64,
    /// The child has granted credit at least once.
    credited: bool,
    overflow: Overflow,
    end: RequestEnd,
}

/// Whether the connection could hold a request's body.
enum Overflow {
    /// All of it so far.
    None,
    /// It dropped this many bytes and drops the rest of the body. The
    /// child hears once the body before them has gone up.
    Dropped(u64),
    /// It drops the rest of the body, as the child heard.
    Told,
}

/// A request's end on its way to the child.
enum RequestEnd {
    /// The request goes on.
    Open,
    /// The request ended, with these trailers if it had any. The child
    /// hears once its body and any overflow have gone up.
    Ended(Option<Box<RequestTrailers>>),
    /// The child heard the end.
    Told,
}

/// A queue whose storage is charged to the budget before it grows.
struct ChargedQueue<T> {
    items: VecDeque<T>,
    storage: Charge,
}

impl<T> ChargedQueue<T> {
    /// An empty queue, its storage charged to `storage` as it grows.
    fn new(storage: Charge) -> Self {
        Self {
            items: VecDeque::new(),
            storage,
        }
    }

    /// Puts `item` at the back, charging the queue's growth first. Hands
    /// `item` back if the growth does not fit.
    fn push_back(&mut self, item: T) -> Result<(), T> {
        if self.items.len() == self.items.capacity() {
            let places = (self.items.capacity() * 2).max(4);
            if !self.storage.set(places * size_of::<T>()) {
                return Err(item);
            }
            self.items.reserve_exact(places - self.items.len());
        }
        self.items.push_back(item);
        Ok(())
    }

    fn front_mut(&mut self) -> Option<&mut T> {
        self.items.front_mut()
    }

    fn pop_front(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The response on its way out, within the client's send windows.
struct Response {
    /// The bytes the client lets the server send on the stream.
    window: i32,
    /// Body credit the child holds: the bytes it may still send down.
    credit_bytes: u64,
    /// Body bytes the child sent that wait to be framed.
    queue: ChargedQueue<Chunk>,
    /// The bytes in `queue`.
    queued_bytes: u64,
    /// Body bytes whose whole frames the transport took.
    written_bytes: u64,
    reply: Reply,
    turn: Turn,
}

impl Response {
    /// Whether the stream has a frame its own window lets it send: body
    /// bytes, or its end once they are all out.
    fn has_frame(&self) -> bool {
        if self.queue.is_empty() {
            matches!(self.reply, Reply::Ending(_))
        } else {
            self.window > 0
        }
    }
}

enum Reply {
    Waiting,
    Body,
    Ending(Option<Box<HeaderMap>>),
    Ended,
}

/// Where a stream waits to send.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    /// Nowhere: it has no frame it can send.
    Idle,
    /// In the connection's `runnable`.
    Runnable,
    /// In the connection's `awaiting_window`.
    AwaitingWindow,
}

/// What one turn of a stream sent.
enum Sent {
    Frame,
    Nothing,
    /// Its next frame needs the connection's send window.
    AwaitingWindow,
}

/// Bytes handed to the transport, and what their completion means.
struct Piece {
    stream: u32,
    bytes: u64,
    body: u64,
    end: bool,
    /// The bytes continue the frame of the piece before them.
    continues: bool,
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
            windowed_bytes: 0,
            uncredited: 0,
            credit_due: Vec::new(),
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
            unwritten_bytes: 0,
            sent: VecDeque::new(),
            touched: Vec::new(),
            finished: Vec::new(),
            runnable: VecDeque::new(),
            awaiting_window: VecDeque::new(),
            charge: None,
            last_words: None,
            upgrade: None,
            dates: Dates::new(None),
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
            .saturating_add(self.dates.held())
            .saturating_add(self.resets.capacity() * size_of::<(u32, Instant)>())
            .saturating_add(self.up.capacity() * size_of::<MuxEvent<HttpExchange, Top, Opening>>())
            .saturating_add(self.out.capacity() * size_of::<StreamCommand>())
            .saturating_add(self.sent.capacity() * size_of::<Piece>())
            .saturating_add(
                (self.touched.capacity()
                    + self.finished.capacity()
                    + self.credit_due.capacity()
                    + self.runnable.capacity()
                    + self.awaiting_window.capacity())
                    * size_of::<u32>(),
            )
    }

    /// What the places the queues keep hold.
    fn kept() -> usize {
        KEEP * (size_of::<MuxEvent<HttpExchange, Top, Opening>>()
            + size_of::<StreamCommand>()
            + size_of::<Piece>()
            + 5 * size_of::<u32>())
    }

    /// Gives each queue the places it keeps, which [`Self::kept`] counts.
    fn keep(&mut self) {
        self.up.reserve_exact(KEEP);
        self.out.reserve_exact(KEEP);
        self.sent.reserve_exact(KEEP);
        self.touched.reserve_exact(KEEP);
        self.finished.reserve_exact(KEEP);
        self.credit_due.reserve_exact(KEEP);
        self.runnable.reserve_exact(KEEP);
        self.awaiting_window.reserve_exact(KEEP);
    }

    /// Charges what is held now. Returns whether it fits.
    fn fits(&mut self) -> bool {
        let need = self.holding();
        self.charge.as_mut().is_none_or(|charge| charge.set(need))
    }

    fn open(&mut self, env: &mut Env<'_, Report>) {
        self.phase = Phase::Open;
        // The list of recent resets is held at its bound from the start,
        // and the queues at the places they keep.
        let resets = RESET_MAX * size_of::<(u32, Instant)>();
        let Some(charge) = env.budget().charge(self.holding() + resets + Self::kept()) else {
            self.phase = Phase::Closing;
            self.out.push_back(StreamCommand::End);
            return;
        };
        self.resets.reserve_exact(RESET_MAX);
        self.keep();
        self.charge = Some(charge);
        if !self.fits() {
            return self.over_budget(env);
        }
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
                stream.receive.closed = true;
            }
            if admitted && let Some(mut chunk) = body {
                if chunk.reserve(env.budget()) {
                    self.deliver_body(1, chunk, false);
                } else {
                    self.overflow(1, chunk.len() as u64);
                }
                self.end_request(1, None);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Output

    /// Queues output bytes, charged before they were allocated, for
    /// `stream` (0 for the connection).
    fn queue(&mut self, chunk: Chunk, stream: u32, body: u64, end: bool) {
        self.push_piece(chunk, stream, body, end, false);
    }

    /// Queues the rest of the frame queued last: a DATA frame's payload
    /// behind its header.
    fn queue_continuation(&mut self, chunk: Chunk, stream: u32, body: u64) {
        self.push_piece(chunk, stream, body, false, true);
    }

    fn push_piece(&mut self, chunk: Chunk, stream: u32, body: u64, end: bool, continues: bool) {
        let bytes = chunk.len();
        self.unwritten_bytes += bytes;
        self.sent.push_back(Piece {
            stream,
            bytes: bytes as u64,
            body,
            end,
            continues,
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
        self.end_all();
        self.resets = VecDeque::new();
        self.input = None;
        self.phase = Phase::Closing;
        self.out.push_back(StreamCommand::End);
    }

    /// Every stream still open ends: its exchange is told the connection
    /// is gone, and nothing waits for a turn or for credit.
    fn end_all(&mut self) {
        self.runnable = VecDeque::new();
        self.awaiting_window = VecDeque::new();
        self.credit_due = Vec::new();
        while let Some((&id, _)) = self.streams.first_key_value() {
            self.end_stream(id, Ending::Gone);
        }
    }

    /// The connection holds more than its budget allows: nothing more is
    /// written but GOAWAY with `ENHANCE_YOUR_CALM`, which was paid for at
    /// the start, and it ends.
    fn over_budget(&mut self, env: &mut Env<'_, Report>) {
        if matches!(self.phase, Phase::Closing | Phase::Closed) {
            return;
        }
        env.report(Report::Budget);
        // What the transport has not taken is dropped, except the rest of
        // a frame whose start it took: GOAWAY must begin a frame of its
        // own. Bytes the transport took keep their pieces, so the
        // completions still to come count against them.
        debug_assert!(
            self.out
                .iter()
                .all(|command| matches!(command, StreamCommand::Write(_)))
        );
        let first = self.sent.len() - self.out.len();
        let keep = usize::from(self.sent.get(first).is_some_and(|piece| piece.continues));
        for piece in self.sent.drain(first + keep..) {
            self.unwritten_bytes -= piece.bytes as usize;
        }
        self.out.truncate(keep);
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
        // The stream's queues charge their storage as they grow.
        let pending = env.budget().charge(0).expect("nothing always fits");
        let queue = env.budget().charge(0).expect("nothing always fits");
        self.streams.insert(
            id,
            Stream {
                child: child_id,
                _entry: entry,
                accepted: false,
                receive: Receive {
                    closed: ended,
                    content_remaining: remaining,
                    window: WINDOW,
                    credit_due: false,
                },
                delivery: Delivery {
                    pending: ChargedQueue::new(pending),
                    windowed_bytes: 0,
                    unwindowed_bytes: 0,
                    credit_bytes: 0,
                    peak_credit_bytes: 0,
                    credited: false,
                    overflow: Overflow::None,
                    end: RequestEnd::Open,
                },
                response: Response {
                    window: self.initial,
                    credit_bytes: SEND_CREDIT,
                    queue: ChargedQueue::new(queue),
                    queued_bytes: 0,
                    written_bytes: 0,
                    reply: Reply::Waiting,
                    turn: Turn::Idle,
                },
            },
        );
        self.uncredited += 1;
        // The next release takes the stream in.
        self.credit_may_be_due(id);
        self.up
            .push_back(MuxEvent::Opened(child, opening, SEND_CREDIT));
        self.up.push_back(MuxEvent::Credit(child_id, SEND_CREDIT));
        Ok(())
    }

    /// Stream `id`'s receive credit may be due at the next release.
    fn credit_may_be_due(&mut self, id: u32) {
        if let Some(stream) = self.streams.get_mut(&id)
            && !stream.receive.credit_due
        {
            stream.receive.credit_due = true;
            self.credit_due.push(id);
        }
    }

    /// Puts stream `id` in line to send, if it has a frame its window lets
    /// it send and is not in line already.
    fn schedule(&mut self, id: u32) {
        if let Some(stream) = self.streams.get_mut(&id) {
            schedule(&mut self.runnable, id, &mut stream.response);
        }
    }

    /// Sends stream `id`'s child body bytes, in order behind what waits for
    /// its credit. `windowed` bytes came in DATA frames, within the receive
    /// windows; the others are the body an `Upgrade: h2c` request brought
    /// over HTTP/1. Bytes the stream's queue cannot hold overflow.
    fn deliver_body(&mut self, id: u32, chunk: Chunk, windowed: bool) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let delivery = &mut stream.delivery;
        let len = chunk.len();
        match delivery.pending.push_back(chunk) {
            Ok(()) if windowed => {
                delivery.windowed_bytes += len as u32;
                self.windowed_bytes += len as u64;
            }
            Ok(()) => delivery.unwindowed_bytes += len as u64,
            Err(_) => delivery.overflow = Overflow::Dropped(len as u64),
        }
        self.forward(id);
    }

    /// The connection cannot hold the next `dropped` bytes of stream
    /// `id`'s body: it drops them and the rest of the body, and the child
    /// hears so.
    fn overflow(&mut self, id: u32, dropped: u64) {
        if let Some(stream) = self.streams.get_mut(&id)
            && matches!(stream.delivery.overflow, Overflow::None)
        {
            stream.delivery.overflow = Overflow::Dropped(dropped);
        }
        self.forward(id);
    }

    /// Stream `id`'s request ended, with `trailers` if it had them.
    fn end_request(&mut self, id: u32, trailers: Option<Box<RequestTrailers>>) {
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.delivery.end = RequestEnd::Ended(trailers);
        }
        self.forward(id);
    }

    /// Moves what waits for stream `id`'s credit up, as far as it goes. A
    /// body piece larger than the credit goes up in part: the child's
    /// credit may never cover it whole. The overflow and the end follow
    /// the body, and need no credit.
    fn forward(&mut self, id: u32) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let delivery = &mut stream.delivery;
        let mut moved = false;
        while delivery.credit_bytes > 0
            && let Some(front) = delivery.pending.front_mut()
        {
            let n = (front.len() as u64).min(delivery.credit_bytes);
            let chunk = if n == front.len() as u64 {
                delivery.pending.pop_front().expect("a pending chunk")
            } else {
                front.split_to(n as usize)
            };
            delivery.credit_bytes -= n;
            let unwindowed = n.min(delivery.unwindowed_bytes);
            delivery.unwindowed_bytes -= unwindowed;
            delivery.windowed_bytes -= (n - unwindowed) as u32;
            self.windowed_bytes -= n - unwindowed;
            self.up
                .push_back(MuxEvent::Child(stream.child, ExchangeEvent::Data(chunk)));
            moved = true;
        }
        // The child's credit and the bytes held changed.
        if moved && !stream.receive.credit_due {
            stream.receive.credit_due = true;
            self.credit_due.push(id);
        }
        if !delivery.pending.is_empty() {
            return;
        }
        if let Overflow::Dropped(dropped) = delivery.overflow {
            delivery.overflow = Overflow::Told;
            self.up.push_back(MuxEvent::Child(
                stream.child,
                ExchangeEvent::Overflow(dropped),
            ));
        }
        match std::mem::replace(&mut delivery.end, RequestEnd::Told) {
            RequestEnd::Ended(trailers) => {
                let event = trailers.map_or(ExchangeEvent::End, ExchangeEvent::Trailers);
                self.up.push_back(MuxEvent::Child(stream.child, event));
            }
            other => delivery.end = other,
        }
    }

    /// Stream `id` is over: its child hears why, and its number is free.
    fn end_stream(&mut self, id: u32, why: Ending) {
        let Some(stream) = self.streams.remove(&id) else {
            return;
        };
        // What it held is dropped: its credit may be due.
        self.batch |= stream.delivery.windowed_bytes > 0;
        self.windowed_bytes -= u64::from(stream.delivery.windowed_bytes);
        self.uncredited -= usize::from(!stream.delivery.credited);
        if stream.receive.credit_due {
            self.credit_due.retain(|&due| due != id);
        }
        match stream.response.turn {
            Turn::Idle => {}
            Turn::Runnable => self.runnable.retain(|&next| next != id),
            Turn::AwaitingWindow => self.awaiting_window.retain(|&next| next != id),
        }
        if let Some(children) = &mut self.children {
            children.remove(stream.child);
        }
        self.up.push_back(MuxEvent::Child(
            stream.child,
            ExchangeEvent::Closed {
                why,
                written: stream.response.written_bytes,
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
            if stream.receive.closed {
                return self.reset(env, id, ErrorCode::StreamClosed);
            }
            if !read.end || !valid_trailers(&block) {
                return self.reset(env, id, ErrorCode::ProtocolError);
            }
            if stream.receive.content_remaining.is_some_and(|n| n != 0) {
                return self.reset(env, id, ErrorCode::ProtocolError);
            }
            let fields = trailer_map(block);
            let held = size_of::<RequestTrailers>() + headers_held(&fields);
            let Some(charge) = env.budget().charge(held) else {
                return self.reset(env, id, ErrorCode::EnhanceYourCalm);
            };
            self.streams
                .get_mut(&id)
                .expect("an open stream")
                .receive
                .closed = true;
            self.end_request(id, Some(Box::new(RequestTrailers { fields, charge })));
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
        let receive = &mut stream.receive;
        if receive.closed {
            return self.reset(env, id, ErrorCode::StreamClosed);
        }
        receive.window -= size as i32;
        if !receive.credit_due {
            receive.credit_due = true;
            self.credit_due.push(id);
        }
        if receive.window < 0 {
            return self.reset(env, id, ErrorCode::FlowControlError);
        }
        if let Some(remaining) = &mut receive.content_remaining {
            let Some(n) = remaining.checked_sub(data.data.len() as u64) else {
                return self.reset(env, id, ErrorCode::ProtocolError);
            };
            *remaining = n;
            if data.flags & 1 != 0 && n != 0 {
                return self.reset(env, id, ErrorCode::ProtocolError);
            }
        }
        let end = data.flags & 1 != 0;
        receive.closed = end;
        if !data.data.is_empty() && matches!(stream.delivery.overflow, Overflow::None) {
            match env.budget().charge(data.data.capacity()) {
                Some(charge) => {
                    let chunk = Chunk::with_charge(data.data, charge);
                    self.deliver_body(id, chunk, true);
                }
                // The body is the stream's alone to lose: its child
                // answers, and the other streams go on.
                None => self.overflow(id, data.data.len() as u64),
            }
        }
        if end {
            self.end_request(id, None);
        }
        Ok(())
    }

    /// Applies one of the client's settings.
    fn peer_setting(&mut self, setting: wire::Setting) -> Result<(), wire::Error> {
        match setting.id {
            1 => self.encoder.set_settings_limit(setting.value as usize),
            4 => {
                let initial = setting.value as i32;
                for (&id, stream) in self.streams.iter_mut() {
                    stream.response.window = shifted(stream.response.window, self.initial, initial)
                        .ok_or_else(|| {
                            problem(ErrorCode::FlowControlError, "initial window overflow")
                        })?;
                    schedule(&mut self.runnable, id, &mut stream.response);
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
                    if self.send_window > 0 {
                        // The streams that waited for it take their turns again.
                        while let Some(id) = self.awaiting_window.pop_front() {
                            if let Some(stream) = self.streams.get_mut(&id) {
                                stream.response.turn = Turn::Runnable;
                                self.runnable.push_back(id);
                            }
                        }
                        trim(&mut self.awaiting_window);
                    }
                } else if let Some(stream) = self.streams.get_mut(&update.stream) {
                    if let Some(n) = grown(stream.response.window, update.increment) {
                        stream.response.window = n;
                        schedule(&mut self.runnable, update.stream, &mut stream.response);
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
            if self.phase != Phase::Open
                || self.up.len() >= UP_LIMIT
                || self.unwritten_bytes >= OUT_LIMIT
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
        let held = self.windowed_bytes as i64;
        if let Some(back) = credit_back(self.recv_window, i64::from(WINDOW) - held) {
            if !self.window_update(env, 0, back) {
                return true;
            }
            self.recv_window += back as i32;
        }
        // Only streams whose credit changed can be due, in ascending order
        // as the client reads them.
        let mut due = std::mem::take(&mut self.credit_due);
        due.sort_unstable();
        for &id in &due {
            let Some(stream) = self.streams.get_mut(&id) else {
                continue;
            };
            stream.receive.credit_due = false;
            stream.accepted = true;
            // A stream's window follows its child: once the child has read
            // all it was given, the client may send what it can take. A
            // child that stops reading stops its stream, and only its
            // stream.
            let delivery = &stream.delivery;
            if delivery.credit_bytes < delivery.peak_credit_bytes {
                continue;
            }
            let room = (delivery.credit_bytes.min(WINDOW as u64) as i64)
                - i64::from(delivery.windowed_bytes);
            if let Some(back) = credit_back(stream.receive.window, room) {
                if !self.window_update(env, id, back) {
                    // The connection is over: every stream has ended.
                    return true;
                }
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.receive.window += back as i32;
                }
            }
        }
        due.clear();
        due.shrink_to(KEEP);
        self.credit_due = due;
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
        let response = &mut stream.response;
        let body = matches!(response.reply, Reply::Body);
        match command {
            ExchangeCommand::Reset(code) => self.write_reset(env, id, code),
            ExchangeCommand::Head(head) if matches!(response.reply, Reply::Waiting) => {
                self.response_head(env, id, *head);
            }
            ExchangeCommand::Data(chunk) if body && chunk.len() as u64 <= response.credit_bytes => {
                let len = chunk.len() as u64;
                if response.queue.push_back(chunk).is_err() {
                    return self.over_budget(env);
                }
                response.credit_bytes -= len;
                response.queued_bytes += len;
            }
            ExchangeCommand::Trailers(trailers) if body => {
                response.reply = Reply::Ending(Some(trailers));
            }
            ExchangeCommand::End if body => response.reply = Reply::Ending(None),
            // A child that answers out of order, or past its credit, broke
            // its exchange: the stream alone is reset.
            _ => self.write_reset(env, id, ErrorCode::InternalError),
        }
        self.schedule(id);
    }

    /// Encodes a response head as HEADERS and CONTINUATION frames, which go
    /// out together. A head without a `Date` is dated as it is framed, when
    /// the world has a date.
    fn response_head(&mut self, env: &mut Env<'_, Report>, id: u32, head: ResponseHead) {
        let mut fields = vec![hpack::Field::new(":status", head.status.as_str())];
        fields.extend(fields_of(&head.headers));
        if !head.headers.contains_key(http::header::DATE)
            && let Some(date) = self.dates.at(env.now())
        {
            fields.push(hpack::Field::new("date", date.as_bytes()));
        }
        if self.header_block(env, id, &fields, head.end)
            && let Some(stream) = self.streams.get_mut(&id)
        {
            stream.response.reply = if head.end { Reply::Ended } else { Reply::Body };
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
        // Streams take turns a frame at a time: one that sent goes to the
        // back of the line if it has more it can send.
        while self.unwritten_bytes < OUT_LIMIT
            && self.phase == Phase::Open
            && let Some(id) = self.runnable.pop_front()
        {
            let Some(stream) = self.streams.get_mut(&id) else {
                continue;
            };
            stream.response.turn = Turn::Idle;
            match self.send_one(env, id) {
                Sent::Frame => {
                    moved = true;
                    self.schedule(id);
                }
                Sent::Nothing => {}
                Sent::AwaitingWindow => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.response.turn = Turn::AwaitingWindow;
                        self.awaiting_window.push_back(id);
                    }
                }
            }
        }
        trim(&mut self.runnable);
        moved
    }

    /// One frame of stream `id`'s response, if it can go.
    fn send_one(&mut self, env: &mut Env<'_, Report>, id: u32) -> Sent {
        let frame = self.frame.min(wire::DEFAULT_FRAME_SIZE);
        let window = self.send_window;
        let Some(stream) = self.streams.get_mut(&id) else {
            return Sent::Nothing;
        };
        let response = &mut stream.response;
        if let Some(front) = response.queue.front_mut() {
            let n = sendable(front.len(), window, response.window, frame);
            if n == 0 {
                // A stream window that opens schedules the stream again.
                return if response.window > 0 {
                    Sent::AwaitingWindow
                } else {
                    Sent::Nothing
                };
            }
            let payload = front.split_to(n);
            if front.is_empty() {
                response.queue.pop_front();
            }
            response.window -= n as i32;
            response.queued_bytes -= n as u64;
            self.send_window -= n as i32;
            // A frame short of the largest is copied whole into one write,
            // so the transport, and a TLS layer below it, takes the header
            // and payload together. A largest frame keeps its payload in
            // the child's allocation, behind a header of its own: that is
            // where bulk bodies go, and a TLS record could not hold both.
            let whole = n < frame;
            let len = wire::HEADER_LEN + if whole { n } else { 0 };
            let Some(charge) = env.budget().charge(len) else {
                self.over_budget(env);
                return Sent::Frame;
            };
            let mut bytes = Vec::with_capacity(len);
            wire::FrameHeader {
                length: n,
                kind: 0,
                flags: 0,
                stream: id,
            }
            .write(&mut bytes)
            .expect("outbound frame has valid fields");
            if whole {
                bytes.extend_from_slice(&payload);
                self.queue(Chunk::with_charge(bytes, charge), id, n as u64, false);
            } else {
                self.queue(Chunk::with_charge(bytes, charge), id, 0, false);
                self.queue_continuation(payload, id, n as u64);
            }
            self.grant(id);
            return Sent::Frame;
        }
        match std::mem::replace(&mut response.reply, Reply::Ended) {
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
                Sent::Frame
            }
            Reply::Ending(Some(trailers)) => {
                let fields = fields_of(&trailers);
                self.header_block(env, id, &fields, true);
                Sent::Frame
            }
            other => {
                response.reply = other;
                Sent::Nothing
            }
        }
    }

    /// Gives stream `id`'s child more credit for its body, as the bytes it
    /// sent go out.
    fn grant(&mut self, id: u32) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let response = &mut stream.response;
        let more = more_credit(response.credit_bytes, response.queued_bytes);
        if more > 0 && matches!(response.reply, Reply::Body) {
            response.credit_bytes += more;
            self.up.push_back(MuxEvent::Credit(stream.child, more));
        }
    }

    /// The transport took `n` more bytes: the frames they finish count for
    /// their streams, and a stream whose response's end went out is over.
    fn written(&mut self, env: &mut Env<'_, Report>, mut n: u64) {
        let mut touched = std::mem::take(&mut self.touched);
        let mut finished = std::mem::take(&mut self.finished);
        while n > 0 {
            let Some(piece) = self.sent.front_mut() else {
                break;
            };
            let step = n.min(piece.bytes);
            piece.bytes -= step;
            n -= step;
            self.unwritten_bytes = self.unwritten_bytes.saturating_sub(step as usize);
            if piece.bytes > 0 {
                break;
            }
            let piece = self.sent.pop_front().expect("a piece");
            trim(&mut self.sent);
            if piece.stream == 0 {
                continue;
            }
            if let Some(stream) = self.streams.get_mut(&piece.stream) {
                if piece.body > 0 {
                    stream.response.written_bytes += piece.body;
                    if !touched.contains(&piece.stream) {
                        touched.push(piece.stream);
                    }
                }
                if piece.end {
                    finished.push(piece.stream);
                }
            }
        }
        for &id in &touched {
            if let Some(stream) = self.streams.get(&id)
                && !finished.contains(&id)
            {
                self.up.push_back(MuxEvent::Child(
                    stream.child,
                    ExchangeEvent::Written(stream.response.written_bytes),
                ));
            }
        }
        for &id in &finished {
            let open = self.streams.get(&id).is_some_and(|s| !s.receive.closed);
            self.end_stream(id, Ending::Done);
            if open {
                // The response is complete but the request is not: ask the
                // client to stop sending it, without an error (RFC 9113
                // section 8.1). Not the client's error, so not counted.
                self.write_reset(env, id, ErrorCode::NoError);
            }
        }
        touched.clear();
        finished.clear();
        touched.shrink_to(KEEP);
        finished.shrink_to(KEEP);
        self.touched = touched;
        self.finished = finished;
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
                if self.input.is_some() || self.unwritten_bytes >= OUT_LIMIT {
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
                self.end_all();
                self.out.clear();
                self.sent.clear();
                self.unwritten_bytes = 0;
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
            && self.unwritten_bytes >= OUT_LIMIT
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
                        let delivery = &mut stream.delivery;
                        delivery.credit_bytes = delivery.credit_bytes.saturating_add(units);
                        delivery.peak_credit_bytes =
                            delivery.peak_credit_bytes.max(delivery.credit_bytes);
                        self.uncredited -= usize::from(!delivery.credited);
                        delivery.credited = true;
                    }
                    self.credit_may_be_due(id);
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
                    let code = if matches!(stream.response.reply, Reply::Waiting) {
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

    fn on_timer(&mut self, env: &mut Env<'_, Report>, _: Timer) -> Result<bool, Infallible> {
        let now = env.now();
        if self.phase != Phase::Open {
            return Ok(false);
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
            return Ok(true);
        }
        let mut forgot = false;
        while self.resets.front().is_some_and(|(_, at)| *at <= now) {
            self.resets.pop_front();
            forgot = true;
        }
        Ok(forgot)
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
            && self.uncredited == 0
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
        // The next advance charges what the queue kept.
        trim(&mut self.out);
        Some(command)
    }

    fn take_event(&mut self) -> Option<MuxEvent<HttpExchange, Top, Opening>> {
        let event = self.up.pop_front()?;
        trim(&mut self.up);
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

/// A drained queue gives back the places it grew past [`KEEP`].
fn trim<T>(queue: &mut VecDeque<T>) {
    if queue.is_empty() {
        queue.shrink_to(KEEP);
    }
}

/// Puts stream `id`, with `response`, at the back of `runnable` if it has
/// a frame its window lets it send and waits nowhere yet.
fn schedule(runnable: &mut VecDeque<u32>, id: u32, response: &mut Response) {
    if response.turn == Turn::Idle && response.has_frame() {
        response.turn = Turn::Runnable;
        runnable.push_back(id);
    }
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
    use fictionet::stdlib::layer::{Budget, Harness};
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

    fn frames(bytes: &[u8]) -> Vec<Frame> {
        whole_frames(bytes).expect("the output is whole frames")
    }

    /// The frames in `bytes`, or `None` if they are not whole frames.
    fn whole_frames(mut bytes: &[u8]) -> Option<Vec<Frame>> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let header = wire::FrameHeader::parse(bytes.get(..wire::HEADER_LEN)?).ok()?;
            let end = wire::HEADER_LEN + header.length;
            frames.push(Frame::parse(bytes.get(..end)?).ok()?);
            bytes = &bytes[end..];
        }
        Some(frames)
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

        fn on_timer(&mut self, _: &mut Env<'_, Infallible>, (): ()) -> Result<bool, Infallible> {
            self.reads = true;
            Ok(true)
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
        body: Vec<u8>,
        /// The bytes of body each command carries.
        piece: usize,
        out: VecDeque<ExchangeCommand>,
    }

    impl Picky {
        fn new(opening: Opening) -> Self {
            Self::answering(opening, BODY.to_vec(), BODY.len())
        }

        /// The same, answering with `body` in commands of `piece` bytes.
        fn answering(opening: Opening, body: Vec<u8>, piece: usize) -> Self {
            let mut picky = Picky {
                stuck: opening.request.uri().path() == "/stuck",
                body,
                piece,
                out: VecDeque::new(),
            };
            if opening.ended && !picky.stuck {
                picky.answer();
            }
            picky
        }

        fn answer(&mut self) {
            self.out
                .push_back(ExchangeCommand::Head(Box::new(ResponseHead {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    end: false,
                })));
            for piece in self.body.chunks(self.piece) {
                self.out
                    .push_back(ExchangeCommand::Data(Chunk::new(piece.to_vec())));
            }
            self.out.push_back(ExchangeCommand::End);
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

    /// A server whose streams answer `GET` with `body`, charging `budget`.
    fn answering(
        body: Vec<u8>,
        piece: usize,
        budget: Budget,
    ) -> Harness<impl Layer<Lower = ByteStream, Error: std::fmt::Debug>> {
        use fictionet::stdlib::layer::{Chain, Children};
        let server = Chain::new(
            Http2::new(Limits::default()),
            Children::new(16, Http2::WINDOW, move |_, opening, _| {
                Some(Picky::answering(opening, body.clone(), piece))
            }),
        );
        Harness::with_budget(fictionet::Seed::from_u64(3), server, budget)
    }

    /// `GET <path>` on `stream`, with no body.
    fn get(encoder: &mut hpack::Encoder, stream: u32, path: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        write(
            &wire::Headers {
                stream,
                flags: 5,
                fragment: request_block(encoder, "GET", path),
                priority: None,
                padding: None,
            },
            &mut bytes,
        );
        bytes
    }

    #[test]
    fn running_out_of_budget_mid_frame_finishes_the_frame_before_goaway() {
        // A whole frame of body: its DATA header and payload go down as
        // separate writes.
        let body = vec![b'z'; wire::DEFAULT_FRAME_SIZE];
        let budget = Budget::new(1 << 24);
        let mut harness = answering(body.clone(), body.len(), budget.clone());
        harness.push(&client_preface()).unwrap();
        harness.take_output();
        harness.withhold();
        let mut encoder = hpack::Encoder::new(4096);
        harness.push(&get(&mut encoder, 1, "/")).unwrap();
        // The transport takes the response's HEADERS frame and part of the
        // DATA frame's header; the payload waits behind it.
        harness.allow(wire::HEADER_LEN).unwrap();
        let head = wire::FrameHeader::parse(harness.output()).unwrap();
        assert_eq!(head.kind, 1, "the response's HEADERS go first");
        harness.allow(head.length + 4).unwrap();
        // The budget runs out while a PING waits for its answer.
        let _rest = budget.charge(budget.limit() - budget.used()).unwrap();
        let mut ping = Vec::new();
        write(
            &wire::Ping {
                flags: 0,
                opaque: *b"overfull",
            },
            &mut ping,
        );
        harness.push(&ping).unwrap();
        harness.allow_all().unwrap();
        let output = whole_frames(harness.output()).expect("the output is whole frames");
        let sent: Vec<u8> = output
            .iter()
            .filter_map(|f| match f {
                Frame::Data(d) if d.stream == 1 => Some(d.data.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(sent, body);
        assert!(
            matches!(output.last(), Some(Frame::GoAway(g))
                if g.code == ErrorCode::EnhanceYourCalm as u32),
            "{output:?}"
        );
        assert!(harness.ended());
    }

    #[test]
    fn a_body_in_many_small_frames_charges_the_queue_that_holds_it() {
        use fictionet::stdlib::layer::{Chain, Children};
        // A child that grants one byte of credit and never reads: the rest
        // of the body waits in the connection, one queue entry per frame.
        let budget = Budget::unlimited();
        let server = Chain::new(
            Http2::new(Limits::default()),
            Children::new(8, 1, |_, _, _| Some(Sink::reading(false))),
        );
        let mut harness =
            Harness::with_budget(fictionet::Seed::from_u64(4), server, budget.clone());
        harness.push(&client_preface()).unwrap();
        harness.push(&headers_without_end(1)).unwrap();
        let before = budget.used();
        let count = 8192;
        let mut input = Vec::new();
        for _ in 0..count {
            write(
                &wire::Data {
                    stream: 1,
                    flags: 0,
                    data: vec![b'y'],
                    padding: None,
                },
                &mut input,
            );
        }
        harness.push(&input).unwrap();
        assert!(!harness.ended());
        let charged = budget.used() - before;
        assert!(
            charged >= count * size_of::<Chunk>(),
            "{charged} bytes charged for {count} queued pieces"
        );
    }

    #[test]
    fn a_response_in_many_small_pieces_charges_the_queue_that_holds_it() {
        let count = 4096;
        let budget = Budget::unlimited();
        let mut harness = answering(vec![b'p'; count], 1, budget.clone());
        // The client's streams start with no window: the body waits in
        // the connection.
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
        let before = budget.used();
        let mut encoder = hpack::Encoder::new(4096);
        harness.push(&get(&mut encoder, 1, "/")).unwrap();
        let output = frames(&harness.take_output());
        assert!(
            output
                .iter()
                .any(|f| matches!(f, Frame::Headers(h) if h.stream == 1))
        );
        assert!(!output.iter().any(|f| matches!(f, Frame::Data(_))));
        let charged = budget.used() - before;
        assert!(
            charged >= count * size_of::<Chunk>(),
            "{charged} bytes charged for {count} queued pieces"
        );
    }

    #[test]
    fn received_trailers_are_charged_while_they_are_held() {
        let budget = Budget::unlimited();
        // `/stuck` takes no event, so the trailers wait for it.
        let mut harness = answering(BODY.to_vec(), BODY.len(), budget.clone());
        harness.push(&client_preface()).unwrap();
        harness.push(&headers_to(1, "/stuck")).unwrap();
        let before = budget.used();
        let value = vec![b'v'; 4000];
        let mut block = Vec::new();
        hpack::Encoder::new(0)
            .encode_block(
                &[hpack::Field::new("x-trailer", value.as_slice())],
                &mut block,
            )
            .unwrap();
        let mut input = Vec::new();
        write(
            &wire::Headers {
                stream: 1,
                flags: 5,
                fragment: block,
                priority: None,
                padding: None,
            },
            &mut input,
        );
        harness.push(&input).unwrap();
        let held = budget.used() - before;
        assert!(held >= value.len(), "{held} bytes charged while held");
        // The client gives up on the stream: the trailers are dropped, and
        // their charge with them.
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
        assert!(budget.used() < before + value.len());
        assert!(!harness.ended());
    }

    /// Every write the server queues for the transport after a request
    /// for `body`.
    fn writes_for(body: Vec<u8>) -> Vec<Chunk> {
        let mut harness = answering(body.clone(), body.len(), Budget::unlimited());
        harness.push(&client_preface()).unwrap();
        harness.take_output();
        harness.withhold();
        let mut encoder = hpack::Encoder::new(4096);
        harness.push(&get(&mut encoder, 1, "/")).unwrap();
        let mut writes = Vec::new();
        while let Some(command) = harness.driver().take_command() {
            if let StreamCommand::Write(chunk) = command {
                writes.push(chunk);
            }
        }
        writes
    }

    #[test]
    fn a_short_data_frame_goes_down_in_one_write() {
        let body = vec![b's'; 100];
        let writes = writes_for(body.clone());
        // Each write is whole frames, so a TLS layer below seals a frame's
        // header and payload together.
        for write in &writes {
            assert!(whole_frames(write).is_some(), "{write:?}");
        }
        let sent: Vec<u8> = writes
            .iter()
            .flat_map(|write| frames(write))
            .filter_map(|f| match f {
                Frame::Data(d) if d.stream == 1 => Some(d.data),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(sent, body);
    }

    #[test]
    fn drained_queues_keep_a_few_places_between_requests() {
        let mut harness = Harness::new(fictionet::Seed::from_u64(5), Http2::new(Limits::default()));
        harness.push(&client_preface()).unwrap();
        // A burst of PINGs fills the output queues past what they keep.
        let mut input = Vec::new();
        for i in 0..64u64 {
            write(
                &wire::Ping {
                    flags: 0,
                    opaque: i.to_be_bytes(),
                },
                &mut input,
            );
        }
        harness.push(&input).unwrap();
        let acks = frames(&harness.take_output())
            .iter()
            .filter(|f| matches!(f, Frame::Ping(p) if p.flags & 1 != 0))
            .count();
        assert_eq!(acks, 64);
        // Drained, they keep a few places for the next request, and no
        // more.
        let http = harness.layer();
        for capacity in [http.out.capacity(), http.sent.capacity()] {
            assert!((1..=KEEP).contains(&capacity), "{capacity}");
        }
        assert!(!harness.ended());
    }

    #[test]
    fn streams_take_turns_a_frame_at_a_time() {
        let body = vec![b't'; 3 * wire::DEFAULT_FRAME_SIZE];
        let mut harness = answering(body.clone(), wire::DEFAULT_FRAME_SIZE, Budget::unlimited());
        let mut input = client_preface();
        // Room on the connection for both bodies whole.
        write(
            &wire::WindowUpdate {
                stream: 0,
                flags: 0,
                increment: 1 << 20,
            },
            &mut input,
        );
        let mut encoder = hpack::Encoder::new(4096);
        input.extend(get(&mut encoder, 1, "/"));
        input.extend(get(&mut encoder, 3, "/"));
        harness.push(&input).unwrap();
        let order: Vec<u32> = frames(&harness.take_output())
            .into_iter()
            .filter_map(|f| match f {
                Frame::Data(d) if !d.data.is_empty() => Some(d.stream),
                _ => None,
            })
            .collect();
        for stream in [1, 3] {
            let sent = order.iter().filter(|&&s| s == stream).count();
            assert!(sent >= 3, "{order:?}");
        }
        // A stream sends twice in a row only once the other has no frame
        // left.
        for (i, pair) in order.windows(2).enumerate() {
            if pair[0] == pair[1] {
                assert!(order[i + 1..].iter().all(|&s| s == pair[0]), "{order:?}");
            }
        }
    }

    #[test]
    fn streams_blocked_on_the_connection_window_send_when_it_opens() {
        let body = vec![b'c'; 40_000];
        let mut harness = answering(body.clone(), body.len(), Budget::unlimited());
        // The client's streams have room for their bodies, but the
        // connection's window holds less than both.
        let mut input = wire::PREFACE.to_vec();
        write(
            &wire::Settings {
                flags: 0,
                entries: vec![wire::Setting {
                    id: 4,
                    value: 1 << 20,
                }],
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
        let mut input = get(&mut encoder, 1, "/");
        input.extend(get(&mut encoder, 3, "/"));
        harness.push(&input).unwrap();
        let mut output = frames(&harness.take_output());
        let data = |output: &[Frame]| -> usize {
            output
                .iter()
                .filter_map(|f| match f {
                    Frame::Data(d) => Some(d.data.len()),
                    _ => None,
                })
                .sum()
        };
        assert_eq!(data(&output), WINDOW as usize);
        let mut update = Vec::new();
        write(
            &wire::WindowUpdate {
                stream: 0,
                flags: 0,
                increment: 1 << 20,
            },
            &mut update,
        );
        harness.push(&update).unwrap();
        output.extend(frames(&harness.take_output()));
        assert_eq!(data(&output), 2 * body.len());
        for stream in [1, 3] {
            assert!(
                output
                    .iter()
                    .any(|f| matches!(f, Frame::Data(d) if d.stream == stream && d.flags & 1 != 0)),
                "{output:?}"
            );
        }
    }

    /// The `Date` fields of the response heads on `stream` in `output`.
    fn dates_on(stream: u32, output: &[u8]) -> Vec<Vec<u8>> {
        let mut blocks = wire::HeaderBlocks::with_limits(Default::default());
        let mut dates = Vec::new();
        for frame in frames(output) {
            let on = matches!(&frame, Frame::Headers(h) if h.stream == stream);
            if let Some(block) = blocks.read_frame(&frame).unwrap().block
                && on
            {
                dates.extend(
                    block
                        .headers
                        .into_iter()
                        .filter(|field| field.name == b"date")
                        .map(|field| field.value),
                );
            }
        }
        dates
    }

    #[test]
    fn a_head_held_back_by_the_transport_is_dated_when_it_is_framed() {
        use fictionet::stdlib::web::httpd::date_header;
        use std::time::SystemTime;
        struct Answers;
        impl Handler for Answers {
            fn call(&self, request: Request<Body>, _: &mut Exchange<'_>) -> Reply {
                if request.uri().path() == "/big" {
                    return Reply::Now(http::Response::new(Body::from(vec![b'b'; 100_000])));
                }
                Reply::Later(Box::new(|fcx| {
                    Box::pin(async move {
                        fcx.sleep(Duration::from_secs(1)).await?;
                        Ok(text(StatusCode::OK, "late\n"))
                    })
                }))
            }
        }
        let start = SystemTime::UNIX_EPOCH;
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(7),
            move |fcx| async move {
                let server = Responder::new(Answers).date(start).http2();
                let mut harness = Harness::new(fictionet::Seed::from_u64(7), server)
                    .with_worker(Polling::in_world(fcx.clone()));
                harness.push(&client_preface()).unwrap();
                harness.take_output();
                harness.withhold();
                let mut encoder = hpack::Encoder::new(4096);
                let mut input = get(&mut encoder, 1, "/big");
                input.extend(get(&mut encoder, 3, "/late"));
                harness.push(&input).unwrap();
                // The big body fills what the transport may fall behind by.
                // The late answer comes after it, and its head waits.
                fcx.sleep(Duration::from_millis(1500)).await?;
                let made = fcx.now();
                harness.allow(0).unwrap();
                fcx.sleep(Duration::from_secs(2)).await?;
                let framed = fcx.now();
                harness.allow_all().unwrap();
                let dates = dates_on(3, harness.output());
                let when = |at| date_header(Some(start), at).unwrap().as_bytes().to_vec();
                assert_ne!(when(made), when(framed));
                assert_eq!(dates, [when(framed)]);
                assert_eq!(dates_on(1, harness.output()).len(), 1);
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
}
