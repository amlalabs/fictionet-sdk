//! The synchronous TLS state machine. The driver owns bytes once they leave it.

use std::future::Future;
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::ServerConfig;
use rustls::server::{
    Accepted, AcceptedAlert, Acceptor, IntoConnectionError, UnbufferedServerConnection,
};
use rustls::unbuffered::{ConnectionState, EncryptError, UnbufferedStatus};

use super::HandshakeError;
use super::budget::TlsBudget;
use fictionet::Cx;
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Charge, Chunk, Env, Layer, StreamCommand, StreamEvent, Timers,
};
use fictionet::stdlib::services::stack::Job;
use fictionet::time::Instant;

/// The most plaintext one record carries (RFC 8446 section 5.1, RFC 5246
/// section 6.2.1). One write takes at most this much.
const PLAINTEXT: usize = 1 << 14;
/// A record's header: its type, version and length.
const HEADER: usize = 5;
/// The most a record's body may be: 2^14 + 2048 bytes in TLS 1.2 (RFC 5246
/// section 6.2.3); TLS 1.3 allows less, 2^14 + 256 (RFC 8446 section 5.2).
/// rustls refuses a header that says more.
const BODY: usize = (1 << 14) + 2048;
/// The most input held while a handshake message is joined: the records
/// joined so far and the one arriving, headers included. rustls's buffered
/// reader holds no more (`MAX_HANDSHAKE_SIZE`), and a message whose parts
/// need more fails the connection.
const JOINED: usize = 0xffff;
/// The room kept from the first byte for the buffer the connection's final
/// alert goes down in: a fatal alert or a `close_notify` record, or the
/// acceptor's alert, all well under it.
const ALERT_ROOM: usize = 64;
const UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

/// The client's requested name and application protocols, before selection.
pub struct Hello {
    server_name: Option<String>,
    alpn: Vec<Vec<u8>>,
    _charge: Charge,
}

impl Hello {
    /// The server name from the client's hello.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Offered application protocols, in the client's order.
    pub fn alpn(&self) -> Vec<&[u8]> {
        self.alpn.iter().map(Vec::as_slice).collect()
    }
}

/// A config on its way, picked for a client's hello.
pub type Picking = Pin<Box<dyn Future<Output = Option<Arc<ServerConfig>>> + Send>>;

/// How a [`TlsLayer`] gets its config once it has read the client's hello.
#[derive(Clone)]
enum Select {
    /// Always this one.
    Config(Arc<ServerConfig>),
    /// What this picks for the hello, with the world's context.
    With(Arc<dyn Fn(Cx, Arc<Hello>) -> Picking + Send + Sync>),
}

/// The work of a [`TlsLayer`]: picking the config for the client's
/// [`Hello`]. Its result is the config, or `None` to refuse the name the
/// client asked for with `unrecognized_name`.
///
/// Whatever runs the layer polls it as a [`Job`], or, in a
/// [`Harness`](fictionet::stdlib::layer::Harness) that does not, the test
/// reads the hello here and completes the work itself.
pub struct Pick {
    hello: Arc<Hello>,
    select: Select,
    picking: Option<Picking>,
}

impl Pick {
    /// What the client asked for.
    pub fn hello(&self) -> &Hello {
        &self.hello
    }
}

impl Job for Pick {
    type Done = Option<Arc<ServerConfig>>;

    /// A layer that picks with the world's context refuses the name when
    /// there is no world to pick in.
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<Self::Done> {
        let picking = match (&self.select, &mut self.picking, fcx) {
            (Select::Config(config), _, _) => return Poll::Ready(Some(config.clone())),
            (Select::With(_), Some(picking), _) => picking,
            (Select::With(select), picking @ None, Some(fcx)) => {
                picking.insert(select(fcx.clone(), self.hello.clone()))
            }
            (Select::With(_), None, None) => return Poll::Ready(None),
        };
        let result = picking.as_mut().poll(cx);
        if result.is_ready() {
            self.picking = None;
        }
        result
    }
}

/// Server TLS over an ordered stream, exposing a decrypted ordered stream.
///
/// Once it has read the client's [`Hello`] it asks for its config as work
/// ([`Pick`]): always the same one ([`new`](Self::new)), or one the world
/// picks for the hello ([`selecting`](Self::selecting)). No config refuses
/// the name with `unrecognized_name`. A handshake that has not finished by
/// its deadline ([`handshake_by`](Self::handshake_by)) fails with
/// [`HandshakeError::TimedOut`] and the connection ends. The
/// configuration's crypto provider supplies the connection's explicit entropy.
/// A failure remains available while its alert drains, allowing the carrier to
/// report the original TLS failure even if sending the alert also fails.
///
/// After the hello the connection runs on rustls's unbuffered API, and the
/// chunks that arrive from below are the record buffers. A record is
/// decrypted where it arrived, and its plaintext goes up as a slice of that
/// chunk: the records whole in one chunk go up together, as one slice, with
/// nothing copied or allocated. Only a record that arrives across chunks
/// is copied, into one buffer with the rest of it, paid for first; so is a
/// handshake message that spans records, as rustls joins it in the buffer
/// it arrived in. A write is sealed into one buffer of exactly its
/// record's size, which goes down whole.
///
/// The connection's budget pays for every buffer it holds, rustls's own
/// included: the bytes waiting for the rest of their record, the records
/// going down, the handshake records rustls queues, what parsing each of
/// the client's handshake messages holds (the hello's until it is
/// answered), and the hello snapshot.
/// A buffer the budget has no room for waits: the layer takes no more input,
/// keeps the write it could not pay for, and goes on when memory frees. An
/// idle connection holds no buffer. It is charged the hello and the room
/// kept for its final alert, a fatal alert or a `close_notify`, which goes
/// out whatever the budget says. rustls's protocol state, such as keys, the
/// transcript and certificates, is not a buffer and is not charged.
pub struct TlsLayer {
    acceptor: Option<Acceptor>,
    accepted: Option<Accepted>,
    /// The config picked for `accepted`, kept while the budget has no room
    /// for the server's flight.
    unpaid_config: Option<Arc<ServerConfig>>,
    tls: Option<UnbufferedServerConnection>,
    /// Bytes from below not done with yet: the parts of a handshake message
    /// being joined, then a record not yet whole, or records rustls has not
    /// processed yet when [`Self::pending`] says so.
    input: Option<Chunk>,
    /// rustls stopped before the end of `input`: there may be whole records
    /// in it still to process.
    pending: bool,
    /// Pays for the buffer the final alert goes down in, when the budget
    /// has no room for it. Kept from the first byte.
    alert_room: Option<Charge>,
    /// A plaintext write waiting to be sealed.
    to_write: Option<Chunk>,
    /// A `close_notify` waiting to be sealed.
    to_close: bool,
    hello: Option<Arc<Hello>>,
    select: Select,
    work: bool,
    deadline: Timers<()>,
    initialized: bool,
    alert: Option<AcceptedAlert>,
    reject: bool,
    first_byte: Option<u8>,
    failure: Option<HandshakeError>,
    failed: bool,
    /// The peer's `close_notify` arrived: nothing more is read.
    peer_closed: bool,
    input_ended: bool,
    ended: bool,
    closing: bool,
    end_sent: bool,
    reset: bool,
    reset_sent: bool,
    below: Option<StreamCommand>,
    above: Option<StreamEvent>,
    ciphertext_emitted: u64,
    ciphertext_completed: u64,
    plaintext_completion: Option<PlaintextCompletion>,
    completed_plaintext_bytes: u64,
}

/// An accepted plaintext write, completed upstream once downstream has
/// completed the ciphertext through `ciphertext_end`. The end is unknown
/// until the write is sealed.
#[derive(Clone, Copy)]
struct PlaintextCompletion {
    plaintext_bytes: usize,
    ciphertext_end: Option<u64>,
}

/// One state rustls reached, with what it borrowed let go.
enum Step {
    /// A record decrypted where it lies: its plaintext, and its own bytes
    /// to discard after the discard the state came with.
    Plain(Range<usize>, usize),
    /// Keep going.
    Next,
    /// Stop: rustls wants more input, or what it offers has no room yet.
    Stop,
    /// Stop: what is left of the input waits for the slots to free.
    Wait,
}

/// A buffer of `len` bytes for records going down, paid for by `budget`,
/// or, for the final alert, by the room kept for it when the budget has
/// none. `None` if neither pays.
fn block(budget: &Budget, len: usize, alert_room: Option<&mut Option<Charge>>) -> Option<Block> {
    let charge = match budget.charge(len) {
        Some(charge) => charge,
        None => {
            let room = alert_room?;
            if room.as_ref()?.bytes() < len {
                return None;
            }
            room.take()?
        }
    };
    Some(Block {
        bytes: vec![0; len],
        written: 0,
        charge,
    })
}

/// Records going down, written into a buffer paid for before it was made.
struct Block {
    bytes: Vec<u8>,
    written: usize,
    charge: Charge,
}

impl Block {
    fn room(&mut self) -> &mut [u8] {
        &mut self.bytes[self.written..]
    }

    fn room_len(&self) -> usize {
        self.bytes.len() - self.written
    }

    /// The records written, as a chunk that carries the charge.
    fn into_chunk(mut self) -> Result<Chunk, HandshakeError> {
        self.bytes.truncate(self.written);
        Chunk::paid(self.bytes, self.charge)
            .map_err(|_| HandshakeError::Failed("TLS output outgrew its charge".into()))
    }
}

impl TlsLayer {
    /// Serves `config` to every client. Waits for a ClientHello without
    /// allocating rustls state yet.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self::with(Select::Config(config))
    }

    /// Serves the config `select` picks for the client's hello, with the
    /// world's context. It may take time: only this handshake waits for it.
    /// `None` refuses the name the client asked for.
    pub fn selecting<F>(select: impl Fn(Cx, Arc<Hello>) -> F + Send + Sync + 'static) -> Self
    where
        F: Future<Output = Option<Arc<ServerConfig>>> + Send + 'static,
    {
        Self::with(Select::With(Arc::new(move |fcx, hello| {
            Box::pin(select(fcx, hello)) as Picking
        })))
    }

    /// Fails the handshake if it has not finished at `at`, picking
    /// included.
    pub fn handshake_by(mut self, at: Instant) -> Self {
        self.deadline.set((), at);
        self
    }

    fn with(select: Select) -> Self {
        Self {
            acceptor: None,
            accepted: None,
            unpaid_config: None,
            tls: None,
            input: None,
            pending: false,
            alert_room: None,
            to_write: None,
            to_close: false,
            hello: None,
            select,
            work: false,
            deadline: Timers::new(),
            initialized: false,
            alert: None,
            reject: false,
            first_byte: None,
            failure: None,
            failed: false,
            peer_closed: false,
            input_ended: false,
            ended: false,
            closing: false,
            end_sent: false,
            reset: false,
            reset_sent: false,
            below: None,
            above: None,
            ciphertext_emitted: 0,
            ciphertext_completed: 0,
            plaintext_completion: None,
            completed_plaintext_bytes: 0,
        }
    }

    /// What the client asked for, once its hello is complete.
    pub fn hello(&self) -> Option<&Hello> {
        self.hello.as_deref()
    }

    /// Whether a successful handshake is still outstanding.
    pub fn is_handshaking(&self) -> bool {
        self.tls.as_ref().is_none_or(|tls| tls.is_handshaking())
    }

    /// The negotiated application protocol, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.as_ref().and_then(|tls| tls.alpn_protocol())
    }

    /// The protocol failure, including while its alert is still pending.
    pub fn failure(&self) -> Option<&HandshakeError> {
        self.failure.as_ref()
    }

    /// Takes the protocol failure. Taking it does not reopen the connection.
    pub fn take_failure(&mut self) -> Option<HandshakeError> {
        self.failure.take()
    }

    /// Whether ciphertext remains queued or awaits downstream completion.
    pub fn output_pending(&self) -> bool {
        self.below.is_some()
            || self.ciphertext_emitted != self.ciphertext_completed
            || self.alert.is_some()
            || self.reject
            || self.to_write.is_some()
            || self.to_close
            || self.tls.as_ref().is_some_and(|tls| tls.wants_write())
    }

    fn fail(&mut self, error: HandshakeError) {
        if !self.failed {
            self.failure = Some(error);
            self.failed = true;
            self.closing = true;
            // Nothing more is read or written but the alert.
            self.to_write = None;
            self.to_close = false;
            self.pending = false;
            self.input = None;
        }
    }

    fn protocol_error(error: rustls::Error) -> HandshakeError {
        match error {
            rustls::Error::AlertReceived(alert) => HandshakeError::Alert(u8::from(alert)),
            error => HandshakeError::Failed(error.to_string()),
        }
    }

    fn abort(&mut self) {
        self.reset = true;
        self.input_ended = true;
        self.closing = true;
        self.work = false;
        self.deadline = Timers::new();
        self.above = None;
        self.below = None;
        self.acceptor = None;
        self.accepted = None;
        self.unpaid_config = None;
        self.tls = None;
        self.input = None;
        self.pending = false;
        self.alert_room = None;
        self.to_write = None;
        self.to_close = false;
        self.hello = None;
        self.alert = None;
        self.reject = false;
        self.failure = None;
        self.ciphertext_completed = self.ciphertext_emitted;
        self.plaintext_completion = None;
        self.completed_plaintext_bytes = 0;
    }

    /// Asks the acceptor for the client's hello: taken once it is whole and
    /// the budget pays for what parsing it holds, which the hello keeps
    /// until it is answered. Until then the acceptor stays, and
    /// [`Self::hello_waits`] says whether it is the room it waits for.
    fn accept(&mut self) {
        let Some(acceptor) = self.acceptor.as_mut() else {
            return;
        };
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                self.accepted = Some(accepted);
                self.acceptor = None;
            }
            Ok(None) => {}
            Err((error, alert)) => {
                if self.first_byte == Some(22) {
                    self.alert = Some(alert);
                }
                self.acceptor = None;
                self.fail(Self::protocol_error(error));
            }
        }
    }

    /// The client's hello is whole, and waits for the budget to pay for
    /// what parsing it holds.
    fn hello_waits(&self) -> bool {
        self.acceptor.as_ref().is_some_and(Acceptor::wants_budget)
    }

    /// Answers the client's hello with `config`. `false` if the budget had
    /// no room for the server's flight: the hello and the config are kept
    /// to try again when memory frees.
    fn connect(&mut self, config: Arc<ServerConfig>) -> bool {
        let Some(accepted) = self.accepted.take() else {
            return true;
        };
        match accepted.into_unbuffered(config.clone()) {
            Ok(tls) => self.tls = Some(tls),
            Err(IntoConnectionError::Unpaid(accepted)) => {
                self.accepted = Some(*accepted);
                self.unpaid_config = Some(config);
                return false;
            }
            Err(IntoConnectionError::Failed(error, alert)) => {
                self.alert = Some(alert);
                self.fail(Self::protocol_error(error));
            }
        }
        true
    }

    /// The acceptor's answer for the carrier below: `unrecognized_name`, or
    /// the alert it made. `None` if neither the budget nor the room kept for
    /// the final alert pays for its buffer yet.
    fn acceptor_output(&mut self, budget: &Budget) -> Result<Option<Chunk>, HandshakeError> {
        let failed = |error: io::Error| HandshakeError::Failed(error.to_string());
        let len = match (self.reject, &self.alert) {
            (true, _) => UNRECOGNIZED_NAME.len(),
            (false, Some(alert)) => alert.len(),
            (false, None) => return Ok(None),
        };
        let Some(mut out) = block(budget, len, Some(&mut self.alert_room)) else {
            return Ok(None);
        };
        if self.reject {
            out.room().copy_from_slice(&UNRECOGNIZED_NAME);
            out.written = len;
        } else if let Some(alert) = self.alert.as_mut() {
            let mut room = out.room();
            alert.write_all(&mut room).map_err(failed)?;
            out.written = len - room.len();
        }
        out.into_chunk().map(Some)
    }

    /// Runs rustls over the input held, in place. Records are decrypted
    /// where they arrived, and the plaintext of every one rustls takes in
    /// this call goes up as one chunk: each record's plaintext is moved
    /// back over the bytes already done with to follow the one before, in
    /// the same buffer. Handshake records rustls queues, a write waiting to
    /// be sealed and a `close_notify` go down in one buffer, paid for
    /// first. Stops when rustls wants more input, when the slots each way
    /// are taken or memory has no room, or when the connection fails.
    /// Returns whether anything moved.
    fn pump(&mut self, budget: &Budget) -> Result<bool, HandshakeError> {
        let Some(tls) = self.tls.as_mut() else {
            return Ok(false);
        };
        // Once the connection failed only its alert goes out: no input is
        // read again, and rustls is asked for nothing but what it queued.
        if self.failed && !tls.wants_write() {
            return Ok(false);
        }
        // Input is read only while there is room above for its plaintext.
        // Without it, output still goes: rustls is given no input, which
        // it allows while no handshake message is being joined in it.
        let read = !self.failed && self.above.is_none();
        let mut none: [u8; 0] = [];
        let bytes: &mut [u8] = match (&mut self.input, read) {
            (Some(input), true) => match input.make_mut(budget) {
                Some(bytes) => bytes,
                None => return Ok(false),
            },
            (Some(_), false) if !self.failed && tls.joined() != 0 => return Ok(false),
            _ => &mut none,
        };

        let below_free = self.below.is_none();
        let mut out: Option<Block> = None;
        let mut plain: Option<Range<usize>> = None;
        let mut done = 0;
        let mut error = None;
        let mut sealed = None;
        let mut stopped = Step::Stop;
        loop {
            let UnbufferedStatus { discard, state } = tls.process_tls_records(&mut bytes[done..]);
            let step = match state {
                Err(e) => {
                    error = Some(Self::protocol_error(e));
                    Step::Stop
                }
                Ok(ConnectionState::ReadTraffic(mut traffic)) => match traffic.next_record() {
                    Some(Ok(record)) => Step::Plain(record.payload, record.discard),
                    Some(Err(e)) => {
                        error = Some(Self::protocol_error(e));
                        Step::Stop
                    }
                    None => Step::Next,
                },
                Ok(ConnectionState::EncodeTlsData(mut encode)) => {
                    if out.is_none() && below_free {
                        let queued = encode.queued_len();
                        let room = self.failed.then_some(&mut self.alert_room);
                        out = block(budget, queued, room);
                    }
                    match out.as_mut() {
                        Some(block) if block.room_len() >= encode.len() => {
                            block.written += encode
                                .encode(block.room())
                                .map_err(|e| HandshakeError::Failed(e.to_string()))?;
                            Step::Next
                        }
                        // The record stays queued until there is room.
                        _ => Step::Wait,
                    }
                }
                Ok(ConnectionState::TransmitTlsData(transmit)) => {
                    transmit.done();
                    // What a failed connection queued is out.
                    match self.failed {
                        true => Step::Stop,
                        false => Step::Next,
                    }
                }
                Ok(ConnectionState::PeerClosed) => {
                    self.peer_closed = true;
                    Step::Next
                }
                Ok(ConnectionState::WriteTraffic(mut write)) if !self.failed && out.is_none() => {
                    if let Some(plaintext) = self.to_write.as_ref() {
                        let need = write.encrypted_len(plaintext.len());
                        if let Some(block) =
                            seal(budget, need, |room| write.encrypt(plaintext, room))?
                        {
                            sealed = Some(plaintext.len());
                            out = Some(block);
                        }
                    } else if self.to_close {
                        let len = write.close_notify_len();
                        if let Some(mut block) = block(budget, len, Some(&mut self.alert_room)) {
                            block.written = write
                                .queue_close_notify(block.room())
                                .map_err(|e| HandshakeError::Failed(e.to_string()))?;
                            self.to_close = false;
                            self.closing = true;
                            out = Some(block);
                        }
                    }
                    Step::Stop
                }
                // The budget has no room for what the next message may
                // make: it waits in the input until memory frees.
                Ok(ConnectionState::BlockedBudget) => Step::Wait,
                Ok(ConnectionState::ReadEarlyData(_)) => {
                    error = Some(HandshakeError::Failed(
                        "early data is not taken on this connection".into(),
                    ));
                    Step::Stop
                }
                Ok(_) => Step::Stop,
            };
            // The state is let go: its record's plaintext can be moved.
            match step {
                Step::Plain(at, own) => {
                    let at = done + at.start..done + at.end;
                    match plain.as_mut() {
                        None => plain = Some(at),
                        Some(gathered) => {
                            let len = at.len();
                            bytes.copy_within(at, gathered.end);
                            gathered.end += len;
                        }
                    }
                    done += discard + own;
                }
                Step::Next => done += discard,
                stop @ (Step::Stop | Step::Wait) => {
                    done += discard;
                    stopped = stop;
                    break;
                }
            }
            if error.is_some() {
                break;
            }
        }

        let moved = plain.is_some() || out.is_some() || done != 0 || error.is_some();
        if read {
            self.pending = matches!(stopped, Step::Wait) && error.is_none();
        }
        if let Some(input) = self.input.take_if(|_| read) {
            // Records with no plaintext hand nothing up: an empty chunk
            // above reads as the end of the stream.
            if let Some(plain) = plain.filter(|plain| !plain.is_empty()) {
                self.above = Some(StreamEvent::Data(input.slice(plain)));
            }
            if done < input.len() {
                self.input = Some(input.slice(done..input.len()));
            }
        }
        if let Some(block) = out {
            let bytes = block.into_chunk()?;
            self.ciphertext_emitted += bytes.len() as u64;
            if let Some(plaintext_bytes) = sealed {
                self.to_write = None;
                self.plaintext_completion = Some(PlaintextCompletion {
                    plaintext_bytes,
                    ciphertext_end: Some(self.ciphertext_emitted),
                });
            }
            self.below = Some(StreamCommand::Write(bytes));
        }
        if self.peer_closed {
            self.input_ended = true;
        }
        if let Some(error) = error {
            self.fail(error);
        }
        Ok(moved)
    }

    /// Takes `chunk` in as input: whole records are processed where they
    /// lie, and bytes that continue a record held are joined to it in one
    /// buffer, paid for first, up to the end of that record. A handshake
    /// message whose parts need more than [`JOINED`] bytes fails the
    /// connection. Returns what is left of the chunk, which waits, or
    /// `None` once all of it is taken.
    fn take_input(
        &mut self,
        budget: &Budget,
        mut chunk: Chunk,
    ) -> Result<Option<Chunk>, HandshakeError> {
        loop {
            if chunk.is_empty() {
                return Ok(None);
            }
            if self.failed || self.pending || self.above.is_some() {
                return Ok(Some(chunk));
            }
            let joined = self.tls.as_ref().map_or(0, |tls| tls.joined());
            let Some(input) = self.input.as_mut() else {
                // Nothing held: the chunk itself, the one piece holding its
                // backing, is the record buffer, paid for by this
                // connection before it is taken.
                if !chunk.repay(budget) {
                    return Ok(Some(chunk));
                }
                self.input = Some(chunk);
                self.pump(budget)?;
                return Ok(None);
            };
            match join(input, &mut chunk, joined, budget)? {
                Joined::Took => {}
                Joined::Unpaid => return Ok(Some(chunk)),
                Joined::Outgrew => {
                    self.fail(HandshakeError::Failed(
                        "a handshake message outgrew the most a message may be joined in".into(),
                    ));
                    continue;
                }
            }
            self.pump(budget)?;
        }
    }

    fn complete_plaintext_write(&mut self) {
        if let Some(PlaintextCompletion {
            plaintext_bytes,
            ciphertext_end: Some(end),
        }) = self.plaintext_completion
            && self.ciphertext_completed >= end
        {
            self.completed_plaintext_bytes += plaintext_bytes as u64;
            self.plaintext_completion = None;
        }
    }
}

/// What [`join`] did with the start of a chunk.
enum Joined {
    /// It took the bytes, up to the end of the record arriving.
    Took,
    /// The input held needs a larger buffer and the budget has no room:
    /// nothing was taken.
    Unpaid,
    /// The parts of the handshake message being joined would need more
    /// than [`JOINED`]: nothing was taken, and the connection fails.
    Outgrew,
}

/// Takes the start of `chunk` into `input`, the bytes held, up to the end
/// of the record arriving after `joined` bytes of them, which rustls is
/// joining as a handshake message. The bytes go in after what is held, in
/// place when the buffer has room. Otherwise they go with what is held
/// into a new buffer, paid for first while the old one is still held, with
/// room for the whole record arriving and, while a message is being
/// joined, for twice what is held, up to [`JOINED`]: joining a message from
/// many records copies what is held a few times, not once a record.
fn join(
    input: &mut Chunk,
    chunk: &mut Chunk,
    joined: usize,
    budget: &Budget,
) -> Result<Joined, HandshakeError> {
    let end = record_end(input, joined);
    if joined != 0 && end > JOINED {
        return Ok(Joined::Outgrew);
    }
    let take = end.saturating_sub(input.len()).min(chunk.len());
    if input.extend_within(&chunk[..take]).is_err() {
        let room = match joined {
            0 => end,
            _ => end.max(input.len() * 2).min(JOINED),
        };
        let Some(mut bytes) = Chunk::block(budget, 0, room) else {
            return Ok(Joined::Unpaid);
        };
        bytes
            .extend_within(input)
            .and_then(|()| bytes.extend_within(&chunk[..take]))
            .map_err(|_| HandshakeError::Failed("a record outgrew its buffer".into()))?;
        *input = bytes;
    }
    chunk.advance(take);
    Ok(Joined::Took)
}

/// Where the record arriving after `joined` bytes of `input` ends, or its
/// header while that is incomplete. A body longer than a record may be
/// counts as the most it may be: rustls refuses the header once it is
/// whole, and nothing past that is taken.
fn record_end(input: &[u8], joined: usize) -> usize {
    match input.get(joined + 3..joined + HEADER) {
        Some(len) => joined + HEADER + usize::from(u16::from_be_bytes([len[0], len[1]])).min(BODY),
        None => joined + HEADER,
    }
}

/// Seals plaintext with `encrypt` into a buffer of `need` bytes, paid for
/// first; once more into the larger size encrypt asks for, if a key update
/// it started adds a record. `None` if the budget has no room.
fn seal(
    budget: &Budget,
    mut need: usize,
    mut encrypt: impl FnMut(&mut [u8]) -> Result<usize, EncryptError>,
) -> Result<Option<Block>, HandshakeError> {
    loop {
        let Some(mut block) = block(budget, need, None) else {
            return Ok(None);
        };
        match encrypt(block.room()) {
            Ok(written) => {
                block.written = written;
                return Ok(Some(block));
            }
            Err(EncryptError::InsufficientSize(more)) if more.required_size > need => {
                need = more.required_size;
            }
            Err(e) => return Err(HandshakeError::Failed(e.to_string())),
        }
    }
}

impl Layer for TlsLayer {
    type Lower = ByteStream;
    type Upper = ByteStream;
    type Report = ();
    type Timer = ();
    type Work = Pick;
    type Done = Option<Arc<ServerConfig>>;
    type Error = HandshakeError;

    fn on_event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, HandshakeError> {
        match event {
            event if self.reset => Ok(Admit::Closed(event)),
            StreamEvent::Written(n) => {
                if n > self.ciphertext_emitted - self.ciphertext_completed {
                    return Err(HandshakeError::Failed(
                        "TLS output completed more than once".into(),
                    ));
                }
                self.ciphertext_completed += n;
                self.complete_plaintext_write();
                Ok(Admit::Taken)
            }
            StreamEvent::Reset => {
                self.abort();
                self.reset_sent = true;
                self.above = Some(StreamEvent::Reset);
                Ok(Admit::Taken)
            }
            event if self.input_ended || self.failed || self.reset => Ok(Admit::Closed(event)),
            StreamEvent::Ended => {
                // The end comes after every record already read: after the
                // plaintext waiting above, and after records waiting for
                // room.
                if self.above.is_some() || self.pending {
                    return Ok(Admit::Blocked(StreamEvent::Ended));
                }
                self.input_ended = true;
                if self.is_handshaking() {
                    self.fail(HandshakeError::Closed);
                }
                Ok(Admit::Taken)
            }
            StreamEvent::Data(chunk) => {
                if chunk.is_empty() {
                    return Ok(Admit::Taken);
                }
                if self.accepted.is_some()
                    || self.above.is_some()
                    || self.below.is_some()
                    || self.pending
                    || self.tls.as_ref().is_some_and(|tls| tls.wants_write())
                {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                if !self.initialized {
                    // The room for the final alert's buffer is kept from
                    // the first byte, so that the alert goes out whatever
                    // the budget says when it is sent.
                    let Some(room) = env.budget().charge(ALERT_ROOM) else {
                        return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                    };
                    self.alert_room = Some(room);
                    self.acceptor = Some(Acceptor::with_budget(TlsBudget::of(env.budget())));
                    self.initialized = true;
                }
                let before = chunk.len();
                let rest = if self.tls.is_some() {
                    match self.take_input(env.budget(), chunk)? {
                        Some(rest) => rest,
                        None => return Ok(Admit::Taken),
                    }
                } else if self.acceptor.is_some() {
                    // A whole hello waiting for the room to parse it is
                    // taken first: nothing more is read before it.
                    if self.hello_waits() {
                        self.accept();
                        if self.failed {
                            return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                        }
                        if self.hello_waits() || self.accepted.is_some() {
                            return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                        }
                    }
                    let Some(acceptor) = self.acceptor.as_mut() else {
                        return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                    };
                    let mut chunk = chunk;
                    self.first_byte.get_or_insert(chunk[0]);
                    let n = match acceptor.read_tls(&mut &chunk[..]) {
                        Ok(0) => {
                            self.fail(HandshakeError::Failed("TLS took no input bytes".into()));
                            return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                        }
                        Ok(n) => n,
                        // No room to read into: the bytes wait, and the
                        // runner comes back when memory frees.
                        Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                            return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                        }
                        Err(error) => {
                            self.fail(HandshakeError::Failed(error.to_string()));
                            return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                        }
                    };
                    chunk.advance(n);
                    self.accept();
                    chunk
                } else {
                    return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                };
                Ok(if rest.is_empty() {
                    Admit::Taken
                } else if rest.len() == before {
                    Admit::Blocked(StreamEvent::Data(rest))
                } else {
                    Admit::Partial(StreamEvent::Data(rest))
                })
            }
        }
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: StreamCommand,
    ) -> Result<Admit<StreamCommand>, HandshakeError> {
        if matches!(command, StreamCommand::Reset) && !self.reset {
            self.abort();
            return Ok(Admit::Taken);
        }
        if self.closing || self.failed || self.reset {
            return Ok(Admit::Closed(command));
        }
        match command {
            StreamCommand::Reset => Ok(Admit::Closed(StreamCommand::Reset)),
            StreamCommand::End => {
                if self.is_handshaking() || self.output_pending() || self.pending {
                    return Ok(Admit::Blocked(StreamCommand::End));
                }
                // Taken once it is sealed; without room it waits above.
                self.to_close = true;
                self.pump(env.budget())?;
                if std::mem::take(&mut self.to_close) {
                    return Ok(Admit::Blocked(StreamCommand::End));
                }
                Ok(Admit::Taken)
            }
            StreamCommand::Write(mut chunk) => {
                // One plaintext write is outstanding until its ciphertext
                // completes. Pipelining needs a completion record and a
                // charge for each queued write.
                if self.is_handshaking()
                    || self.plaintext_completion.is_some()
                    || self.output_pending()
                    || self.pending
                {
                    return Ok(Admit::Blocked(StreamCommand::Write(chunk)));
                }
                if chunk.is_empty() {
                    return Ok(Admit::Taken);
                }
                // At most one record's plaintext, sealed into one buffer,
                // and taken once it is; without room it waits above.
                let take = chunk.len().min(PLAINTEXT);
                self.to_write = Some(chunk.slice(0..take));
                self.pump(env.budget())?;
                if self.to_write.take().is_some() {
                    return Ok(Admit::Blocked(StreamCommand::Write(chunk)));
                }
                chunk.advance(take);
                Ok(if chunk.is_empty() {
                    Admit::Taken
                } else {
                    Admit::Partial(StreamCommand::Write(chunk))
                })
            }
        }
    }

    fn on_done(
        &mut self,
        _env: &mut Env<'_, ()>,
        config: Self::Done,
    ) -> Result<(), HandshakeError> {
        if self.failed || self.reset {
            // A pick that finished after the handshake gave up.
            return Ok(());
        }
        if self.accepted.is_none() {
            return Err(HandshakeError::Failed(
                "TLS configuration without a client hello".into(),
            ));
        }
        self.work = false;
        let Some(config) = config else {
            self.accepted = None;
            self.reject = true;
            self.fail(HandshakeError::Rejected);
            return Ok(());
        };
        // Without room for the flight, `advance` tries again when memory
        // frees.
        self.connect(config);
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, HandshakeError> {
        if self.reset {
            if self.below.is_none() && !self.reset_sent {
                self.below = Some(StreamCommand::Reset);
                self.reset_sent = true;
                return Ok(true);
            }
            return Ok(false);
        }
        // Memory freed since the budget had no room to parse the hello.
        if self.hello_waits() {
            self.accept();
            if self.hello_waits() {
                return Ok(false);
            }
            if self.failed {
                return Ok(true);
            }
        }
        if self.hello.is_none()
            && let Some(accepted) = self.accepted.as_ref()
        {
            let hello = accepted.client_hello();
            let (count, payload) = hello.alpn().map_or((0, 0), |protocols| {
                protocols.fold((0, 0), |(count, size), protocol| {
                    (count + 1, size + protocol.len())
                })
            });
            let bytes = std::mem::size_of::<Hello>()
                + 2 * std::mem::size_of::<usize>()
                + count * std::mem::size_of::<Vec<u8>>()
                + payload
                + hello.server_name().map_or(0, str::len);
            let Some(charge) = env.budget().charge(bytes) else {
                return Ok(false);
            };
            let mut alpn = Vec::with_capacity(count);
            if let Some(protocols) = hello.alpn() {
                alpn.extend(protocols.map(<[u8]>::to_vec));
            }
            self.hello = Some(Arc::new(Hello {
                server_name: hello.server_name().map(str::to_owned),
                alpn,
                _charge: charge,
            }));
            self.work = true;
            return Ok(true);
        }
        // Memory freed since the budget had no room for the server's
        // flight.
        let mut moved = false;
        if let Some(config) = self.unpaid_config.take() {
            if !self.connect(config) {
                return Ok(false);
            }
            moved = true;
        }
        // At most one charged chunk each way is retained by this layer.
        if self.below.is_none() && (self.reject || self.alert.is_some()) {
            let Some(bytes) = self.acceptor_output(env.budget())? else {
                return Ok(moved);
            };
            self.reject = false;
            self.alert = None;
            if !bytes.is_empty() {
                self.ciphertext_emitted += bytes.len() as u64;
                self.below = Some(StreamCommand::Write(bytes));
            }
            return Ok(true);
        }
        // Records rustls queued, records held back for the slots, a write
        // or a close waiting for memory.
        if self.below.is_none() || self.pending {
            moved |= self.pump(env.budget())?;
        }
        if self.above.is_none()
            && !self.ended
            && !self.pending
            && !self.failed
            && self.input_ended
            && !self.is_handshaking()
        {
            self.ended = true;
            self.above = Some(StreamEvent::Ended);
            return Ok(true);
        }
        if self.closing && !self.end_sent && !self.output_pending() {
            self.end_sent = true;
            self.below = Some(StreamCommand::End);
            return Ok(true);
        }
        if self.failed
            && !self.output_pending()
            && let Some(error) = self.failure.take()
        {
            return Err(error);
        }
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        self.below.take()
    }

    fn take_event(&mut self) -> Option<StreamEvent> {
        if self.completed_plaintext_bytes != 0 {
            return Some(StreamEvent::Written(std::mem::take(
                &mut self.completed_plaintext_bytes,
            )));
        }
        self.above.take()
    }

    fn take_urgent(&mut self) -> Option<StreamEvent> {
        (self.completed_plaintext_bytes != 0)
            .then(|| StreamEvent::Written(std::mem::take(&mut self.completed_plaintext_bytes)))
    }

    fn take_work(&mut self) -> Option<Pick> {
        if !std::mem::take(&mut self.work) {
            return None;
        }
        Some(Pick {
            hello: self.hello.clone()?,
            select: self.select.clone(),
            picking: None,
        })
    }

    fn on_timer(&mut self, env: &mut Env<'_, ()>, _: ()) -> Result<bool, HandshakeError> {
        let fired = self.deadline.fire(&(), env.now());
        if fired && self.is_handshaking() {
            // No alert: the client hears the end of the stream.
            self.work = false;
            self.accepted = None;
            self.fail(HandshakeError::TimedOut);
        }
        Ok(fired)
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.deadline
            .next()
            .filter(|_| self.is_handshaking() && !self.failed)
    }
}

/// Bounded proofs over the write accounting, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../../verification/tls/kani/LayerProof.rs"]
mod proofs;

/// Bounded proofs that the input joined for a handshake message stays
/// within its budget and is moved a few times, with every allocation
/// counted, run with `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`.
#[cfg(kani)]
#[path = "../../../../verification/tls/kani/join.rs"]
mod resource_proofs;

impl super::Negotiation for TlsLayer {
    fn handshake(&self) -> super::Handshake<'_> {
        if self.failed || self.reset {
            super::Handshake::Failed
        } else if self.is_handshaking() {
            super::Handshake::Pending
        } else {
            super::Handshake::Established {
                server_name: self.hello().and_then(Hello::server_name),
                alpn: self.alpn(),
            }
        }
    }
}

#[cfg(test)]
mod tests;
