//! SSH servers over composable byte streams, following RFCs 4252, 4253 and 4254.
//!
//! [`Handler`] chooses authentication and starts sessions. [`Session`] consumes
//! input bytes and terminal events; [`Output`] queues stdout, stderr and exit
//! status under a fixed bound, or disconnects the entire connection. Channel
//! windows apply when the queue is sent.
//! The world supplies identity, authentication policy and application behavior.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Waker;
use std::time::Duration;

use super::stack;
use crate::Cx;
use crate::stdlib::codec::{Heap, Wire, parse_paid};
use crate::stdlib::layer::{
    Admit, Budget, ByteStream, Chain, Charge, ChargedBytes, ChargedDeque, ChildId, Children,
    Chunk as Bytes, Closing, Env, Layer, Mux, MuxCommand, MuxEvent, MuxOp, Owned, Slots,
    StreamCommand, StreamEvent, Timers, Top, WriteFailure,
};
use crate::stdlib::protocols::ssh::transport::{HostKey, TransportError};
use crate::stdlib::protocols::ssh::{self, auth, connection as wire};
use crate::stdlib::world::net::{Arrival, PortServer};
use crate::sync::Mutex;
use crate::time::Instant;
use fictionet::stdlib::network::ConnInfo;

pub mod channel;
pub mod transport;
use transport::{PacketTransport, StandardTransport, State as TransportState};
mod session;
use channel::{ChannelCommand, ChannelEvent, ChannelPort};
pub use session::SessionLayer;

const WINDOW: u32 = 65536;
const PACKET: u32 = 32000;
const OUTPUT_LIMIT: usize = 256 * 1024;
const MAX_AUTH_REQUESTS: u32 = 1024;

/// An authentication method from RFCs 4252 and 4256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Password authentication.
    Password,
    /// A public key with proof of possession.
    PublicKey,
    /// A server challenge and client responses.
    KeyboardInteractive,
}
impl AuthMethod {
    /// The protocol name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PublicKey => "publickey",
            Self::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

/// An authentication attempt, including cryptographic proof when supplied.
pub struct AuthAttempt<'a> {
    /// The client's request; a public key without a signature is only a probe.
    pub request: &'a auth::Request,
    /// Whether a supplied signature proves possession of the offered key.
    pub signature_verified: bool,
    /// Answers to the last keyboard-interactive challenge.
    pub responses: Option<&'a [Vec<u8>]>,
}

/// The application's decision for an authentication attempt.
#[derive(Clone, Debug)]
pub enum AuthDecision {
    /// Authenticate, or acknowledge a public key probe without authenticating.
    Accept,
    /// Continue authentication, optionally after another factor succeeded.
    Reject {
        /// Methods that may follow.
        methods: Vec<AuthMethod>,
        /// Whether one factor succeeded.
        partial_success: bool,
        /// Delay before sending the failure response, measured by the world.
        delay: Duration,
    },
    /// Ask a keyboard-interactive challenge (RFC 4256).
    Challenge {
        /// Challenge name.
        name: String,
        /// Instructions shown to the client.
        instruction: String,
        /// Prompts and whether input should be echoed.
        prompts: Vec<auth::Prompt>,
    },
}

/// Terminal dimensions from RFC 4254 section 6.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pty {
    /// Terminal type, such as `xterm`.
    pub terminal: String,
    /// Width in character cells.
    pub columns: u32,
    /// Height in character cells.
    pub rows: u32,
    /// Width in pixels, or zero when unknown.
    pub pixel_width: u32,
    /// Height in pixels, or zero when unknown.
    pub pixel_height: u32,
    /// Encoded terminal mode settings.
    pub modes: Vec<wire::TerminalMode>,
}

/// The program requested on a session channel (RFC 4254 section 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Program {
    /// An interactive shell.
    Shell,
    /// A command's uninterpreted bytes.
    Exec(Vec<u8>),
    /// A named subsystem, such as SFTP.
    Subsystem(String),
}

/// Everything accepted before starting a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRequest {
    /// Authenticated account name.
    pub user: String,
    /// Server channel number.
    pub channel: u32,
    /// The program to start.
    pub program: Program,
    /// The requested terminal, if any.
    pub pty: Option<Pty>,
    /// Accepted environment entries, as name and value bytes.
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
}

/// An event on an established session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// New terminal dimensions.
    WindowChange {
        /// Width in character cells.
        columns: u32,
        /// Height in character cells.
        rows: u32,
        /// Width in pixels, or zero when unspecified.
        pixel_width: u32,
        /// Height in pixels, or zero when unspecified.
        pixel_height: u32,
    },
    /// A signal name without its `SIG` prefix.
    Signal(String),
    /// The peer finished sending input.
    Eof,
    /// The channel closed.
    Closed,
}

/// The connection and world time of an application callback.
pub struct Context<'a> {
    /// Connection identity and addresses.
    pub connection: &'a ConnInfo,
    /// Time supplied by the service driver.
    pub now: Instant,
}

/// A typed protocol fact or completed transition emitted by the server.
#[derive(Clone, Debug)]
pub enum Event {
    /// Client identification.
    Version(ssh::Identification),
    /// Client key exchange proposal, including subsequent rekeys.
    KexInit(ssh::KexInit),
    /// Authentication request with proof validation result.
    Authentication {
        /// Credentials or method probe supplied by the peer.
        request: auth::Request,
        /// Whether the supplied signature proves possession of the key.
        verified: bool,
    },
    /// Answers to a keyboard-interactive challenge.
    AuthenticationResponses(Vec<Vec<u8>>),
    /// Application authentication decision.
    AuthenticationDecision(AuthDecision),
    /// Authentication completed and the success response was queued.
    Authenticated {
        /// Authenticated account name.
        user: String,
        /// The authentication method that completed login.
        method: String,
    },
    /// A connection protocol request or channel lifecycle message.
    Connection(wire::Message),
    /// Input bytes on a channel.
    Input {
        /// Server channel number.
        channel: u32,
        /// Unmodified application bytes.
        data: Vec<u8>,
    },
    /// Output bytes committed to SSH packets.
    Output {
        /// Server channel number.
        channel: u32,
        /// Whether these bytes are standard error.
        stderr: bool,
        /// Unmodified application bytes.
        data: Vec<u8>,
    },
    /// The process exit status sent on a channel.
    Exit {
        /// Server channel number.
        channel: u32,
        /// Application exit status.
        status: u32,
    },
    /// The SSH connection ended.
    End(Ended),
}

/// Application policy and session factory for an SSH connection.
pub trait Handler: Send + Sync + 'static {
    /// The application's running session.
    type Session: Session;
    /// Decide each authentication attempt. Invalid signatures cannot authenticate.
    fn authenticate(&self, context: &Context<'_>, attempt: &AuthAttempt<'_>) -> AuthDecision;
    /// Accept or refuse terminal and environment requests before program start.
    fn configure(
        &self,
        _context: &Context<'_>,
        _channel: u32,
        request: &wire::SessionRequest,
    ) -> bool {
        matches!(request, wire::SessionRequest::Pty { .. })
    }
    /// Start a shell, command or subsystem. `None` refuses the request.
    fn open(
        &self,
        context: &Context<'_>,
        request: &SessionRequest,
        output: &mut Output,
    ) -> Option<Self::Session>;
    /// Accept an application-owned stream for a direct TCP forwarding channel.
    /// The default refuses it. No host connection is opened by the service;
    /// the application supplies all stream behavior through the returned session.
    fn direct_tcpip(
        &self,
        _context: &Context<'_>,
        _channel: u32,
        _endpoint: &wire::TcpIp,
        _output: &mut Output,
    ) -> Option<Self::Session> {
        None
    }
    /// Accept a connection-wide request, returning its success response fields.
    /// The default refuses every request. Responses must be shorter than
    /// [`ssh::MAX_PAYLOAD`], leaving room for the message number; larger responses
    /// are refused. For a dynamically allocated forwarding port, return its
    /// four-byte network-order value. The application owns any listener behavior.
    fn global_request(
        &self,
        _context: &Context<'_>,
        _request: &wire::GlobalRequest,
    ) -> Option<Vec<u8>> {
        None
    }
    /// Observe protocol activity. Wrappers can record these without changing policy.
    fn observe(&self, _context: &Context<'_>, _event: &Event) {}
}

/// An application's raw byte stream on one SSH channel.
pub trait Session: Send + 'static {
    /// Consume input bytes and optionally queue output.
    fn input(&mut self, context: &Context<'_>, bytes: &[u8], output: &mut Output);
    /// Receive terminal changes, signals and channel lifecycle events.
    fn event(&mut self, _context: &Context<'_>, _event: &SessionEvent, _output: &mut Output) {}
    /// Extended input, such as standard error from another endpoint.
    fn extended(
        &mut self,
        _context: &Context<'_>,
        _kind: u32,
        _bytes: &[u8],
        _output: &mut Output,
    ) {
    }
    /// A success or failure reply to an application channel request.
    fn reply(&mut self, _context: &Context<'_>, _accepted: bool, _output: &mut Output) {}
    /// Bytes retained by the application, charged to the connection's budget.
    fn held(&self) -> usize {
        0
    }
}

#[derive(Debug)]
enum Chunk {
    Data { stderr: bool, data: Bytes },
    Exit(u32),
}

/// Bounded session output and connection-wide disconnect requests.
#[derive(Debug)]
pub struct Output {
    chunks: ChargedDeque<Chunk>,
    bytes: usize,
    exited: bool,
    disconnect: bool,
    hangup: bool,
    budget: Budget,
}

/// Output would exceed the queue bound or follow an exit or disconnect.
#[derive(Clone, Copy, Debug)]
pub struct OutputFull;
impl std::fmt::Display for OutputFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SSH output queue is full or closed")
    }
}
impl std::error::Error for OutputFull {}
impl Default for Output {
    fn default() -> Self {
        Self::with_budget(Budget::unlimited())
    }
}

impl Output {
    fn with_budget(budget: Budget) -> Self {
        Self {
            chunks: ChargedDeque::new(&budget, 1025),
            budget,
            bytes: 0,
            exited: false,
            disconnect: false,
            hangup: false,
        }
    }
    fn clear(&mut self) {
        drop(self.chunks.drain(..));
        self.bytes = 0;
        self.exited = false;
        self.disconnect = false;
        self.hangup = false;
    }
    fn reserve(&mut self) -> Result<(), OutputFull> {
        if self.chunks.places() == 0 {
            let budget = &self.budget;
            self.chunks = ChargedDeque::with_places(budget, 1025, 1025).ok_or(OutputFull)?;
        }
        Ok(())
    }
    /// Queue stdout bytes, preserving their order. Refusal changes nothing.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), OutputFull> {
        self.push(false, bytes)
    }
    /// Queue extended-data stderr bytes (RFC 4254 section 5.2).
    pub fn stderr(&mut self, bytes: &[u8]) -> Result<(), OutputFull> {
        self.push(true, bytes)
    }
    fn next_bytes(&self, bytes: usize) -> Result<usize, OutputFull> {
        if self.exited
            || bytes > OUTPUT_LIMIT.saturating_sub(self.bytes)
            || self.chunks.len() >= 1024
        {
            return Err(OutputFull);
        }
        Ok(self.bytes + bytes)
    }
    fn push(&mut self, stderr: bool, bytes: &[u8]) -> Result<(), OutputFull> {
        let next = self.next_bytes(bytes.len())?;
        if !bytes.is_empty() {
            let mut data = if self.chunks.places() == 0 {
                let places = 1025 * size_of::<Chunk>();
                let mut charge = self.budget.charge(places + bytes.len()).ok_or(OutputFull)?;
                self.chunks = charge.split(places).unwrap().into_deque();
                charge.into_bytes()
            } else {
                ChargedBytes::with_capacity(&self.budget, bytes.len()).ok_or(OutputFull)?
            };
            data.extend_within(bytes)
                .expect("output was reserved in full");
            self.bytes = next;
            assert!(
                self.chunks
                    .push_back(Chunk::Data {
                        stderr,
                        data: Bytes::from_bytes(data),
                    })
                    .is_ok()
            );
        }
        Ok(())
    }
    /// Finish output, then send EOF and close after queued bytes drain.
    /// Session channels also send the process exit status; direct TCP streams
    /// have no process status.
    pub fn exit(&mut self, status: u32) {
        if !self.exited {
            if self.reserve().is_err() {
                self.disconnect();
                return;
            }
            self.exited = true;
            assert!(self.chunks.push_back(Chunk::Exit(status)).is_ok());
        }
    }
    /// Disconnect the whole SSH connection, discarding queued channel output.
    /// This takes precedence over channel flow control and pending requests.
    pub fn disconnect(&mut self) {
        self.exited = true;
        self.disconnect = true;
        drop(self.chunks.drain(..));
        self.bytes = 0;
    }
    /// Drain this channel's queued output, then silently close the connection.
    /// Channel flow control and key exchange continue while output drains;
    /// further application input and requests are ignored.
    pub fn hangup(&mut self) {
        self.exited = true;
        self.hangup = true;
    }
    /// Remaining room for queued output bytes.
    pub fn available(&self) -> usize {
        if self.exited {
            0
        } else {
            OUTPUT_LIMIT - self.bytes
        }
    }
}

/// Whole-connection shutdown that channel applications ask for. It reaches
/// the connection beside channel traffic, so it never waits behind output the
/// peer has granted no window for. The strongest request holds. Closing
/// silently once a channel's output has drained stays on that channel, after
/// its output ([`ChannelCommand::Hangup`]).
///
/// A request may come from anywhere, such as another task: it wakes the
/// connection, which acts on it at once.
#[derive(Clone, Debug)]
pub struct ConnectionControl(Arc<Control>);

#[derive(Debug)]
struct Control {
    requested: AtomicU8,
    /// The connection's [`Env::waker`], from its first step on.
    waker: Mutex<Option<Waker>>,
}

/// How far the connection has been asked to shut down, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Requested {
    Open = 0,
    Drain = 1,
    Disconnect = 2,
}

impl ConnectionControl {
    fn new() -> Self {
        Self(Arc::new(Control {
            requested: AtomicU8::new(Requested::Open as u8),
            waker: Mutex::new(None),
        }))
    }
    /// Keeps the connection's waker, the first time it steps: the waker
    /// stays good for the connection's life ([`Env::waker`]). Called before
    /// the connection reads [`requested`](Self::requested), so a request
    /// either finds the waker or is read after it.
    fn watch(&self, env: &Env<'_, Ended>) {
        let mut waker = self.0.waker.lock();
        if waker.is_none() {
            *waker = Some(env.waker());
        }
    }
    /// Stop reading application input and requests while queued output
    /// drains. Window adjustments and channel closes are still read.
    pub fn drain(&self) {
        self.request(Requested::Drain);
    }
    /// Disconnect the whole connection at once.
    pub fn disconnect(&self) {
        self.request(Requested::Disconnect);
    }
    fn request(&self, requested: Requested) {
        let before = self
            .0
            .requested
            .fetch_max(requested as u8, Ordering::AcqRel);
        if before < requested as u8 {
            let waker = self.0.waker.lock().clone();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
    fn requested(&self) -> Requested {
        match self.0.requested.load(Ordering::Acquire) {
            0 => Requested::Open,
            1 => Requested::Drain,
            _ => Requested::Disconnect,
        }
    }
}

/// SSH identity and per-connection resource limits.
#[derive(Clone)]
pub struct Config {
    /// Host signing key, shared by connections.
    pub host_key: Arc<HostKey>,
    /// Server software identification.
    pub identification: ssh::Identification,
    /// Optional ordered proposal, restricted to implemented algorithms.
    pub proposal: Option<ssh::KexInit>,
    /// Maximum time to authenticate.
    pub login_grace: Duration,
    /// Maximum failed attempts before disconnecting. Independently, a
    /// connection allows at most 1024 authentication requests, including probes
    /// and keyboard-interactive responses.
    pub max_attempts: u32,
    /// Maximum simultaneously open channels.
    pub max_channels: usize,
    /// Optional pre-authentication banner (RFC 4252 section 5.4).
    pub banner: Option<String>,
}
impl Config {
    /// A protocol server with bounded channels and authentication attempts.
    pub fn new(host_key: Arc<HostKey>, identification: ssh::Identification) -> Self {
        Self {
            host_key,
            identification,
            proposal: None,
            login_grace: Duration::from_secs(120),
            max_attempts: 6,
            max_channels: 16,
            banner: None,
        }
    }
}

/// Why the SSH connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The client sent everything it will send, and every item was handled.
    /// The reply is still written.
    Eof,
    /// The application or protocol closed the connection.
    Closed,
    /// The SSH packet decoder failed.
    Failed,
    /// The idle deadline expired.
    Idle,
    /// The connection needed more than its [`Budget`]'s whole limit. A
    /// charge that only finds no room now waits for memory instead.
    Budget(crate::stdlib::layer::Starved),
    /// Reading or writing failed: the client reset the connection, or TLS
    /// broke ([`crate::stdlib::network::ConnError::Broken`]).
    Conn(crate::stdlib::network::ConnError),
    /// The connection's region was cancelled. A notification
    /// delivered to the observer.
    Cancelled,
}

impl Ended {
    /// A stable spelling of the connection's end reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Ended::Eof => "eof",
            Ended::Closed => "closed",
            Ended::Failed => "failed",
            Ended::Idle => "idle",
            Ended::Budget(_) => "budget",
            Ended::Conn(crate::stdlib::network::ConnError::Reset) => "reset",
            Ended::Conn(crate::stdlib::network::ConnError::Broken) => "broken",
            Ended::Conn(crate::stdlib::network::ConnError::TimedOut) => "timed_out",
            Ended::Conn(_) => "error",
            Ended::Cancelled => "cancelled",
        }
    }
}

/// A port server running SSH and its session children on the common stack runner.
pub struct Server<H: Handler> {
    /// Protocol configuration.
    pub config: Arc<Config>,
    /// Application authentication and session policy.
    pub handler: Arc<H>,
    /// Idle and write deadlines.
    pub limits: stack::StreamLimits,
    /// Optional shared allocation budget.
    pub budget: Option<Budget>,
    /// Optional listener backlog.
    pub backlog: Option<usize>,
}
/// A server with a caller-supplied transport factory and standard sessions.
pub struct WithTransport<H: Handler, F> {
    server: Server<H>,
    factory: F,
}
impl<H: Handler> Server<H> {
    /// Install a fresh transport per arrival, retaining Handler and Children.
    pub fn with_transport<T: PacketTransport, F>(self, factory: F) -> WithTransport<H, F>
    where
        F: Fn(&transport::Opening<'_>) -> T + Send + Sync + 'static,
    {
        WithTransport {
            server: self,
            factory,
        }
    }
    fn serve_with<T: PacketTransport>(
        &self,
        fcx: Cx,
        arrival: Arrival,
        factory: impl FnOnce(&transport::Opening<'_>) -> T,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let info = Arc::new(arrival.info);
        let handler = self.handler.clone();
        let budget = self
            .budget
            .clone()
            .or(arrival.budget)
            .unwrap_or_else(Budget::unlimited);
        let limits = self.limits;
        let now = fcx.now();
        let transport = factory(&transport::Opening {
            config: &self.config,
            info: &info,
            budget: &budget,
            limits,
            now,
            login_deadline: now + self.config.login_grace,
        });
        let layer = Ssh::with_transport(
            self.config.clone(),
            handler.clone(),
            info.clone(),
            transport,
        )
        .sessions();
        Box::pin(async move {
            let mut protocol_end = Ended::Eof;
            let result =
                stack::stream(&fcx, arrival.conn, &info, layer, budget, limits, |report| {
                    if let crate::stdlib::layer::Side::Lower(reason) = report {
                        protocol_end = reason;
                    }
                })
                .await;
            let end = match result {
                Ok(stack::StreamEnd::Finished) => protocol_end,
                Ok(stack::StreamEnd::Idle) => Ended::Idle,
                Ok(stack::StreamEnd::Budget(starved)) => Ended::Budget(starved),
                Ok(stack::StreamEnd::Conn(error)) => Ended::Conn(error),
                Ok(stack::StreamEnd::Reset) => {
                    Ended::Conn(crate::stdlib::network::ConnError::Reset)
                }
                Err(stack::StackError::Cancelled) => Ended::Cancelled,
                Err(stack::StackError::Layer(_)) => Ended::Failed,
            };
            handler.observe(
                &Context {
                    connection: &info,
                    now: fcx.now(),
                },
                &Event::End(end),
            );
        })
    }
}

impl<H: Handler> PortServer for Server<H> {
    fn backlog(&self) -> Option<usize> {
        self.backlog
    }
    fn serve_connection(
        &self,
        fcx: Cx,
        arrival: Arrival,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.serve_with(fcx, arrival, |opening| {
            StandardTransport::new(opening.config)
        })
    }
}
impl<H: Handler, T: PacketTransport, F> PortServer for WithTransport<H, F>
where
    F: Fn(&transport::Opening<'_>) -> T + Send + Sync + 'static,
{
    fn backlog(&self) -> Option<usize> {
        self.server.backlog
    }
    fn serve_connection(
        &self,
        fcx: Cx,
        arrival: Arrival,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.server.serve_with(fcx, arrival, &self.factory)
    }
}

/// Why the SSH connection layer could not continue. Storage the budget
/// cannot pay for is never one: the connection waits for memory, and a
/// channel it cannot hold is refused.
#[derive(Debug)]
pub enum Error {
    /// Invalid protocol traffic or cryptographic state.
    Protocol(TransportError),
}
impl From<TransportError> for Error {
    fn from(error: TransportError) -> Self {
        Self::Protocol(error)
    }
}
impl From<ssh::Error> for Error {
    fn from(error: ssh::Error) -> Self {
        Self::Protocol(error.into())
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {}

/// Authentication deadlines owned by one SSH layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer {
    /// Maximum authentication time.
    Login,
    /// Delayed authentication failure.
    Failure,
}

struct Channel {
    wire: u32,
    peer: u32,
    window: u32,
    max_packet: u32,
    granted: u64,
    receive: u64,
    advertised: u32,
    accepted: bool,
    confirmed: bool,
    eof: bool,
    sent_eof: bool,
    closed: bool,
}
impl Channel {
    fn consume_receive(&mut self, bytes: usize) -> Result<(), TransportError> {
        if !self.confirmed
            || self.eof
            || self.closed
            || bytes > PACKET as usize
            || bytes as u64 > self.receive
            || bytes > self.advertised as usize
        {
            return Err(TransportError::State);
        }
        self.receive -= bytes as u64;
        self.advertised -= bytes as u32;
        Ok(())
    }

    fn consume_send(&mut self, bytes: usize) -> Result<(), TransportError> {
        if self.closed
            || self.sent_eof
            || bytes as u64 > self.granted
            || bytes > self.window as usize
            || bytes > self.max_packet as usize
        {
            return Err(TransportError::State);
        }
        self.granted -= bytes as u64;
        self.window -= bytes as u32;
        Ok(())
    }

    /// The window adjustment to send now, if one is due: everything the
    /// channel can take beyond what the peer was told, once that is at
    /// least what the peer has left. The peer then hears of new room about
    /// once per half window it uses, as OpenSSH tells it, and never runs
    /// dry while room is owed: at zero left, any room owed is due.
    fn adjustment(&self) -> Option<u32> {
        let owed = self.receive.saturating_sub(u64::from(self.advertised));
        let owed = owed.min(u64::from(u32::MAX - self.advertised)) as u32;
        (owed > 0 && owed >= self.advertised).then_some(owed)
    }
}

struct Flight {
    bytes: usize,
    child: Option<(ChildId, u64)>,
}

/// A synchronous SSH connection: a byte stream below and typed channels above.
/// Authentication and connection requests remain with the parent. Attach
/// [`Children`] directly for another channel application, or use [`Self::sessions`].
/// Host configuration and synchronous policy callback allocations belong to the
/// caller. Everything else is paid for before it is allocated: the transport
/// pays for its own buffers, and each packet is paid for before it is parsed.
/// Storage the budget cannot pay for now waits for memory, or refuses the
/// channel that asked for it; it never fails the connection.
pub struct Ssh<H: Handler, T: PacketTransport = StandardTransport> {
    config: Arc<Config>,
    handler: Arc<H>,
    connection: Arc<ConnInfo>,
    transport: T,
    timers: Timers<Timer>,
    started: bool,
    ended: bool,
    end_sent: bool,
    /// Whether the channel table and the queues are paid for.
    reserved: bool,
    /// What goes down next, written into room for four packets that was
    /// paid for before it was allocated.
    out: Option<ChargedBytes>,
    /// Room to encode one outgoing payload before the transport seals it,
    /// paid for with the output's room.
    payload: Option<ChargedBytes>,
    out_child: Option<(ChildId, u64)>,
    flights: ChargedDeque<Flight>,
    up: ChargedDeque<MuxEvent<ChannelPort, Top, Owned<channel::Opening>>>,
    channels: Slots<Channel>,
    next_channel: u32,
    credit_turn: Option<ChildId>,
    control: ConnectionControl,
    /// The authenticated account, charged for what it holds.
    user: Option<Owned<String>>,
    /// The account the client authenticates as, until it has, charged
    /// for what it holds.
    auth_user: Option<Owned<String>>,
    service_requested: bool,
    attempts: u32,
    auth_requests: u32,
    /// The request a keyboard-interactive challenge answers, with what
    /// parsing it was charged, and how many answers it wants.
    challenge: Option<(Owned<auth::Request>, usize)>,
    /// A failure waiting out its delay: the methods the handler named, in
    /// the vector its decision allocated (the caller's, like the rest of a
    /// policy callback's values), and whether one factor succeeded.
    failure: Option<(Vec<AuthMethod>, bool)>,
    failure_ready: bool,
    /// Application packets the transport decoded, each with the charge
    /// that paid for it, waiting to be parsed.
    pending_packets: ChargedDeque<(u32, Owned<Vec<u8>>)>,
}

/// Runs `write` with the transport and the output, which the step made
/// sure of first ([`Ssh::room`]). A writer that grows the output past the
/// room paid for fails the connection; its own result comes back as it was.
fn fill<T, R, E>(
    out: &mut Option<ChargedBytes>,
    transport: &mut T,
    write: impl FnOnce(&mut T, &mut Vec<u8>) -> Result<R, E>,
) -> Result<Result<R, E>, Error> {
    let out = out.as_mut().ok_or(TransportError::State)?;
    match out.fill(|out| write(transport, out)) {
        Ok(written) => Ok(Ok(written)),
        Err(WriteFailure::Value(error)) => Ok(Err(error)),
        Err(WriteFailure::Bound) => Err(TransportError::State.into()),
    }
}

/// Seals `payload` into one packet in the output, which the step made
/// sure has room for one ([`Ssh::room`]).
fn seal<T: PacketTransport>(
    out: &mut Option<ChargedBytes>,
    transport: &mut T,
    payload: &[u8],
) -> Result<(), Error> {
    if out.as_ref().is_none_or(|out| out.room() < ssh::MAX_PACKET) {
        return Err(TransportError::State.into());
    }
    fill(out, transport, |transport, out| {
        transport.write_packet(payload, out)
    })?
    .map_err(Error::Protocol)
}

/// What became of an application packet.
#[must_use]
enum Handled {
    /// It was taken.
    Done,
    /// What it takes was refused before anything changed: it waits,
    /// unparsed, for memory (layer rule 9).
    Waiting,
}

/// SSH with one synchronous application adapter on every scoped channel.
pub type Sessions<H, T = StandardTransport> =
    Chain<Ssh<H, T>, Children<SessionLayer<H>, Top, Owned<channel::Opening>>>;

impl<H: Handler> Ssh<H> {
    /// A fresh SSH layer with explicit connection identity.
    pub fn new(config: Arc<Config>, handler: Arc<H>, connection: Arc<ConnInfo>) -> Self {
        let transport = StandardTransport::new(&config);
        Self::with_transport(config, handler, connection, transport)
    }
}
impl<H: Handler, T: PacketTransport> Ssh<H, T> {
    /// Compose a transport with the standard authentication and channel layer.
    /// With sessions the stack is `Chain<Ssh<H, T>, Children<SessionLayer<H>, Top, Owned<channel::Opening>>>`.
    pub fn with_transport(
        config: Arc<Config>,
        handler: Arc<H>,
        connection: Arc<ConnInfo>,
        transport: T,
    ) -> Self {
        let limit = config.max_channels;
        Self {
            config,
            handler,
            connection,
            transport,
            timers: Timers::new(),
            started: false,
            ended: false,
            end_sent: false,
            reserved: false,
            out: None,
            payload: None,
            out_child: None,
            flights: ChargedDeque::new(&Budget::unlimited(), 128),
            up: ChargedDeque::new(&Budget::unlimited(), 8),
            channels: Slots::new(limit),
            next_channel: 0,
            credit_turn: None,
            control: ConnectionControl::new(),
            user: None,
            auth_user: None,
            service_requested: false,
            attempts: 0,
            auth_requests: 0,
            challenge: None,
            failure: None,
            failure_ready: false,
            pending_packets: ChargedDeque::new(&Budget::unlimited(), 128),
        }
    }
    /// Run the configured Handler and Session policy on each channel.
    pub fn sessions(self) -> Sessions<H, T> {
        let handler = self.handler.clone();
        let connection = self.connection.clone();
        let limit = self.config.max_channels;
        let control = self.control();
        Chain::new(
            self,
            Children::new(limit, u64::from(WINDOW), move |_, opening, budget| {
                Some(SessionLayer::new(
                    handler.clone(),
                    connection.clone(),
                    control.clone(),
                    opening,
                    budget,
                ))
            }),
        )
    }
    /// The connection's shutdown control, for the applications on its channels.
    pub fn control(&self) -> ConnectionControl {
        self.control.clone()
    }
    fn context(&self, now: Instant) -> Context<'_> {
        Context {
            connection: &self.connection,
            now,
        }
    }
    /// Charges the connection's fixed storage once, all of it or none: the
    /// channel table and its queues. `false` leaves nothing charged, to
    /// try again once memory frees (layer rule 9). What authentication
    /// keeps is charged as it is kept, each value for what it holds.
    fn reserve(&mut self, budget: &Budget) -> bool {
        if self.reserved {
            return true;
        }
        let Some(channels) = Slots::with_budget(self.config.max_channels, budget) else {
            return false;
        };
        let Some(flights) = ChargedDeque::with_places(budget, 128, 128) else {
            return false;
        };
        let Some(pending_packets) = ChargedDeque::with_places(budget, 128, 128) else {
            return false;
        };
        let Some(up) = ChargedDeque::with_places(budget, 8, 8) else {
            return false;
        };
        self.channels = channels;
        self.flights = flights;
        self.pending_packets = pending_packets;
        self.up = up;
        self.reserved = true;
        true
    }
    /// Makes sure of room for what a step writes, four packets, and for
    /// encoding each payload before it is sealed, paid for before it is
    /// allocated. `false` when the budget has none now: the step waits for
    /// memory (layer rule 9). A step writes only into an empty output, so
    /// the room is all there.
    fn room(&mut self, budget: &Budget) -> bool {
        if self.out.is_none() {
            self.out = ChargedBytes::with_capacity(budget, 4 * ssh::MAX_PACKET);
        }
        if self.payload.is_none() {
            self.payload = ChargedBytes::with_capacity(budget, ssh::MAX_PAYLOAD);
        }
        self.out.is_some() && self.payload.is_some()
    }
    /// Whether output waits to go down.
    fn out_pending(&self) -> bool {
        self.out.as_ref().is_some_and(|out| !out.is_empty())
    }
    /// Runs `write` with the transport and the output.
    fn written<R, E>(
        &mut self,
        write: impl FnOnce(&mut T, &mut Vec<u8>) -> Result<R, E>,
    ) -> Result<Result<R, E>, Error> {
        fill(&mut self.out, &mut self.transport, write)
    }
    /// Queues `event` for the channels. Events are raised only while fewer
    /// than four wait, and a step stops raising at four, so the queue's
    /// eight places always hold them: a full queue is a broken state that
    /// fails the connection rather than growing.
    fn raise(
        &mut self,
        event: MuxEvent<ChannelPort, Top, Owned<channel::Opening>>,
    ) -> Result<(), Error> {
        self.up
            .push_back(event)
            .map_err(|_| TransportError::State.into())
    }
    fn send(&mut self, message: &impl Wire<WriteError = ssh::Error>) -> Result<(), Error> {
        self.send_with(|payload| message.write(payload))
    }
    /// Encodes one payload with `encode` into the room paid for it, and
    /// seals it into the output. A payload past [`ssh::MAX_PAYLOAD`] is
    /// one the writers refuse, so it fails the connection.
    fn send_with(
        &mut self,
        encode: impl FnOnce(&mut Vec<u8>) -> Result<(), ssh::Error>,
    ) -> Result<(), Error> {
        let payload = self.payload.as_mut().ok_or(TransportError::State)?;
        payload.clear();
        match payload.fill(encode) {
            Ok(()) => {}
            Err(WriteFailure::Value(error)) => return Err(error.into()),
            Err(WriteFailure::Bound) => return Err(TransportError::State.into()),
        }
        seal(&mut self.out, &mut self.transport, payload)
    }
    fn close(&mut self, env: &mut Env<'_, Ended>, reason: Ended) {
        if !self.ended {
            self.ended = true;
            self.timers = Timers::new();
            env.report(reason);
        }
    }
    fn disconnect(
        &mut self,
        env: &mut Env<'_, Ended>,
        reason: ssh::DisconnectReason,
        description: &str,
    ) -> Result<(), Error> {
        self.written(|transport, out| transport.disconnect(reason, description, out))??;
        self.close(env, Ended::Closed);
        Ok(())
    }
    fn id(&self, wire: u32) -> Result<ChildId, Error> {
        self.channels
            .ids()
            .find(|id| self.channels.get(*id).unwrap().wire == wire)
            .ok_or_else(|| TransportError::State.into())
    }
    /// The session identifier, once the first exchange settled it.
    fn session_id(&self) -> Option<&[u8]> {
        match self.transport.state() {
            TransportState::Established { session_id, .. }
            | TransportState::Rekeying { session_id } => Some(session_id),
            TransportState::Pending => None,
        }
    }
    /// A USERAUTH_REQUEST, or the answers to a challenge. What it takes is
    /// paid for before anything changes: its parse, the observer's copies
    /// of the request and the answers, the account names kept while and
    /// once it authenticates, the method's name, the banner's copy, and
    /// what checking a signature allocates. Refused, it waits unparsed.
    fn authentication(
        &mut self,
        payload: &[u8],
        env: &mut Env<'_, Ended>,
    ) -> Result<Handled, Error> {
        if !self.service_requested || self.failure.is_some() {
            return Err(TransportError::State.into());
        }
        let budget = env.budget().clone();
        let (request, responses) = if payload.first() == Some(&61) {
            let Some(parsed) = parse_paid(&budget, payload, auth::Message::parse) else {
                return Ok(Handled::Waiting);
            };
            let (auth::Message::InfoResponse(responses), charge) = parsed?.into_parts() else {
                return Err(TransportError::State.into());
            };
            (None, Some(Owned::new(responses, charge)))
        } else {
            let Some(parsed) = parse_paid(&budget, payload, auth::Request::parse) else {
                return Ok(Handled::Waiting);
            };
            (Some(parsed?), None)
        };
        let pending = request
            .as_deref()
            .or(self.challenge.as_ref().map(|(request, _)| &**request))
            .ok_or(TransportError::State)?;
        let banner = match (&self.auth_user, &self.config.banner) {
            (None, Some(banner)) => banner.len(),
            _ => 0,
        };
        let verifying = match &pending.method {
            auth::Method::PublicKey {
                signature: Some(_), ..
            } => auth::Request::most_verify_heap(
                payload.len(),
                self.session_id().map_or(0, <[u8]>::len),
            ),
            _ => 0,
        };
        let need = pending.heap()
            + responses.as_deref().map_or(0, Heap::heap)
            + 2 * pending.user.len()
            + pending.method.name().len()
            + banner
            + verifying;
        let Some(mut paid) = budget.charge(need) else {
            return Ok(Handled::Waiting);
        };
        self.auth_requests = self.auth_requests.saturating_add(1);
        if self.auth_requests > MAX_AUTH_REQUESTS {
            return Err(TransportError::State.into());
        }
        let (request, responses) = match responses {
            Some(responses) => {
                self.handler.observe(
                    &self.context(env.now()),
                    &Event::AuthenticationResponses((*responses).clone()),
                );
                let (request, count) = self.challenge.take().ok_or(TransportError::State)?;
                if responses.len() != count {
                    return Err(TransportError::State.into());
                }
                (request, Some(responses))
            }
            None => {
                self.challenge = None;
                (request.ok_or(TransportError::State)?, None)
            }
        };
        if request.service != "ssh-connection" {
            return Err(TransportError::State.into());
        }
        if self
            .auth_user
            .as_deref()
            .is_some_and(|user| *user != request.user)
        {
            return Err(TransportError::State.into());
        }
        if self.auth_user.is_none() {
            let name = paid
                .split(request.user.len())
                .ok_or(TransportError::State)?;
            self.auth_user = Some(Owned::new(request.user.clone(), name));
            if let Some(message) = &self.config.banner {
                self.send(&auth::Message::Banner {
                    message: message.clone(),
                    language: String::new(),
                })?;
            }
        }
        let verified = request
            .verify_public_key(self.session_id().ok_or(TransportError::State)?, payload)
            .unwrap_or(false);
        self.handler.observe(
            &self.context(env.now()),
            &Event::Authentication {
                request: (*request).clone(),
                verified,
            },
        );
        let attempt = AuthAttempt {
            request: &request,
            signature_verified: verified,
            responses: responses.as_ref().map(|responses| responses.as_slice()),
        };
        let decision = self
            .handler
            .authenticate(&self.context(env.now()), &attempt);
        self.handler.observe(
            &self.context(env.now()),
            &Event::AuthenticationDecision(decision.clone()),
        );
        let probe = matches!(
            &request.method,
            auth::Method::PublicKey {
                signature: None,
                ..
            }
        );
        if matches!(
            &request.method,
            auth::Method::PublicKey {
                signature: Some(_),
                ..
            }
        ) && !verified
        {
            return Err(TransportError::Crypto.into());
        }
        match decision {
            AuthDecision::Accept if probe => {
                let (request, _parsed) = request.into_parts();
                if let auth::Method::PublicKey { algorithm, key, .. } = request.method {
                    self.send(&auth::Message::PublicKeyOk { algorithm, key })?;
                }
            }
            AuthDecision::Accept => {
                self.send(&auth::Message::Success)?;
                let name = paid
                    .split(request.user.len())
                    .ok_or(TransportError::State)?;
                self.user = Some(Owned::new(request.user.clone(), name));
                self.auth_user = None;
                self.challenge = None;
                self.timers.cancel(&Timer::Login);
                let (request, _parsed) = request.into_parts();
                self.handler.observe(
                    &self.context(env.now()),
                    &Event::Authenticated {
                        user: request.user,
                        method: request.method.name().to_owned(),
                    },
                );
            }
            AuthDecision::Reject {
                methods,
                partial_success,
                delay,
            } => {
                if !partial_success
                    && !(self.auth_requests == 1 && matches!(request.method, auth::Method::None))
                {
                    self.attempts = self.attempts.saturating_add(1);
                }
                if delay.is_zero() {
                    self.send_with(|out| {
                        auth::write_failure(methods.iter().map(|m| m.name()), partial_success, out)
                    })?;
                } else {
                    self.failure = Some((methods, partial_success));
                    self.failure_ready = false;
                    self.timers.set(Timer::Failure, env.now() + delay);
                }
            }
            AuthDecision::Challenge {
                name,
                instruction,
                prompts,
            } => {
                if !matches!(request.method, auth::Method::KeyboardInteractive { .. }) {
                    return Err(TransportError::State.into());
                }
                let count = prompts.len();
                self.send(&auth::Message::InfoRequest {
                    name,
                    instruction,
                    language: String::new(),
                    prompts,
                })?;
                self.challenge = Some((request, count));
            }
        }
        Ok(Handled::Done)
    }

    /// Parses a connection message, paid for before it is parsed, and
    /// takes it. Refused, it waits unparsed.
    fn connection(&mut self, payload: &[u8], env: &mut Env<'_, Ended>) -> Result<Handled, Error> {
        let Some(message) = parse_paid(env.budget(), payload, wire::Message::parse) else {
            return Ok(Handled::Waiting);
        };
        self.connection_message(message?, env)
    }

    /// Takes a parsed connection message with what it was charged. The
    /// observer's copy is paid for before anything changes, and for
    /// channel data the observer's copy of the bytes and the channel's
    /// own: refused, the message waits. What the message holds moves on
    /// with its charge: a channel request to its channel, an opening's
    /// kind to the opening.
    fn connection_message(
        &mut self,
        message: Owned<wire::Message>,
        env: &mut Env<'_, Ended>,
    ) -> Result<Handled, Error> {
        let copies = message.heap()
            + match &*message {
                wire::Message::Data { data, .. } | wire::Message::ExtendedData { data, .. } => {
                    2 * data.len()
                }
                _ => 0,
            };
        let Some(mut paid) = env.budget().charge(copies) else {
            return Ok(Handled::Waiting);
        };
        self.handler.observe(
            &self.context(env.now()),
            &Event::Connection((*message).clone()),
        );
        let (message, mut parsed) = message.into_parts();
        match message {
            wire::Message::GlobalRequest {
                want_reply,
                request,
            } => {
                let response = self
                    .handler
                    .global_request(&self.context(env.now()), &request)
                    .filter(|data| data.len() < ssh::MAX_PAYLOAD);
                if want_reply {
                    self.send(&match response {
                        Some(data) => wire::Message::RequestSuccess(data),
                        None => wire::Message::RequestFailure,
                    })?;
                }
            }
            wire::Message::ChannelOpen {
                sender,
                window,
                max_packet,
                kind,
            } => {
                if self
                    .channels
                    .ids()
                    .any(|id| self.channels.get(id).unwrap().peer == sender)
                {
                    return Err(TransportError::State.into());
                }
                if self.channels.len() == self.config.max_channels || max_packet == 0 {
                    self.refuse(sender, Closing::Prohibited)?;
                    return Ok(Handled::Done);
                }
                // The opening holds the kind, charged with the message,
                // and a copy of the account name. A channel the budget
                // cannot hold now is refused; the connection and its
                // other channels go on.
                let user = self.user.as_deref().ok_or(TransportError::State)?;
                if !parsed.grow_to(parsed.bytes() + user.len()) {
                    self.refuse(sender, Closing::ResourceShortage)?;
                    return Ok(Handled::Done);
                }
                let wire = self.next_channel;
                self.next_channel = wire.checked_add(1).ok_or(TransportError::State)?;
                let opening = Owned::new(
                    channel::Opening {
                        user: user.clone(),
                        channel: wire,
                        kind,
                    },
                    parsed,
                );
                let child = self
                    .channels
                    .insert(Channel {
                        wire,
                        peer: sender,
                        window,
                        max_packet: max_packet.min(PACKET),
                        granted: 0,
                        receive: 0,
                        advertised: 0,
                        accepted: false,
                        confirmed: false,
                        eof: false,
                        sent_eof: false,
                        closed: false,
                    })
                    .map_err(|_| TransportError::State)?;
                self.raise(MuxEvent::Opened(
                    child,
                    opening,
                    max_packet.min(PACKET) as u64,
                ))?;
            }
            wire::Message::WindowAdjust { recipient, bytes } => {
                let id = self.id(recipient)?;
                let channel = self.channels.get_mut(id).unwrap();
                channel.window = channel
                    .window
                    .checked_add(bytes)
                    .ok_or(TransportError::State)?;
            }
            wire::Message::Data { recipient, data } => {
                self.input(env, &mut paid, recipient, None, data)?
            }
            wire::Message::ExtendedData {
                recipient,
                kind,
                data,
            } => self.input(env, &mut paid, recipient, Some(kind), data)?,
            wire::Message::ChannelRequest {
                recipient,
                want_reply,
                request,
            } => {
                let id = self.id(recipient)?;
                if self.channels.get(id).unwrap().closed {
                    return Err(TransportError::State.into());
                }
                // All the message holds is the request's.
                self.raise(MuxEvent::Child(
                    id,
                    ChannelEvent::Request {
                        want_reply,
                        request: Owned::new(request, parsed),
                    },
                ))?;
            }
            wire::Message::ChannelSuccess(recipient) | wire::Message::ChannelFailure(recipient) => {
                let id = self.id(recipient)?;
                self.raise(MuxEvent::Child(
                    id,
                    ChannelEvent::Reply(matches!(message, wire::Message::ChannelSuccess(_))),
                ))?;
            }
            wire::Message::Eof(recipient) => {
                let id = self.id(recipient)?;
                let channel = self.channels.get_mut(id).unwrap();
                if channel.eof {
                    return Err(TransportError::State.into());
                }
                channel.eof = true;
                self.raise(MuxEvent::Child(
                    id,
                    ChannelEvent::Stream(StreamEvent::Ended),
                ))?;
            }
            wire::Message::Close(recipient) => {
                let id = self.id(recipient)?;
                let channel = self.channels.remove(id).unwrap();
                if !channel.closed {
                    self.send(&wire::Message::Close(channel.peer))?;
                }
                self.raise(MuxEvent::Child(
                    id,
                    ChannelEvent::Stream(StreamEvent::Reset),
                ))?;
            }
            _ => return Err(TransportError::State.into()),
        }
        Ok(Handled::Done)
    }
    /// Refuses the peer's channel `peer`, not yet confirmed, telling it
    /// `why` as RFC 4254 section 5.1 spells it: prohibited (1) past the
    /// channel limit or when the application says no or is done before
    /// taking it, resource shortage (4) when there is no memory for it
    /// now, and connect failed (2) when it was taken and failed before it
    /// could be confirmed.
    fn refuse(&mut self, peer: u32, why: Closing) -> Result<(), Error> {
        let (reason, description) = match why {
            Closing::Prohibited | Closing::Done => (1, "Channel refused"),
            Closing::ResourceShortage => (4, "Resource shortage"),
            Closing::Failed => (2, "Channel failed"),
        };
        self.send(&wire::Message::ChannelOpenFailure {
            recipient: peer,
            reason,
            description: description.into(),
            language: String::new(),
        })
    }
    /// Channel data: the observer's copy and the channel's, both paid for
    /// in `paid` before the message was taken.
    fn input(
        &mut self,
        env: &Env<'_, Ended>,
        paid: &mut Charge,
        recipient: u32,
        kind: Option<u32>,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let id = self.id(recipient)?;
        let channel = self.channels.get_mut(id).unwrap();
        channel.consume_receive(data.len())?;
        if kind.is_none() {
            self.handler.observe(
                &self.context(env.now()),
                &Event::Input {
                    channel: recipient,
                    data: data.clone(),
                },
            );
        }
        let mut kept = paid
            .split(data.len())
            .ok_or(TransportError::State)?
            .into_bytes();
        kept.extend_within(&data)
            .map_err(|_| TransportError::State)?;
        let data = Bytes::from_bytes(kept);
        self.raise(MuxEvent::Child(
            id,
            match kind {
                Some(kind) => ChannelEvent::Extended { kind, data },
                None => ChannelEvent::Stream(StreamEvent::Data(data)),
            },
        ))?;
        Ok(())
    }
    /// Takes one application packet, or leaves it untouched to wait for
    /// memory: each kind is parsed with [`parse_paid`], its type's bound
    /// charged before the parse and shrunk to what it holds after.
    fn packet(
        &mut self,
        sequence: u32,
        payload: &[u8],
        env: &mut Env<'_, Ended>,
    ) -> Result<Handled, Error> {
        if self.control.requested() != Requested::Open {
            return match payload.first() {
                Some(93) => self.connection(payload, env),
                Some(97) => {
                    self.close(env, Ended::Closed);
                    Ok(Handled::Done)
                }
                _ => Ok(Handled::Done),
            };
        }
        if self.user.is_none()
            && (self.attempts >= self.config.max_attempts
                || self.auth_requests >= MAX_AUTH_REQUESTS)
        {
            self.disconnect(
                env,
                ssh::DisconnectReason::NoMoreAuthMethodsAvailable,
                "Too many authentication failures",
            )?;
            return Ok(Handled::Done);
        }
        match payload.first().copied().ok_or(TransportError::State)? {
            5 if self.user.is_none() && !self.service_requested => {
                let Some(parsed) = parse_paid(env.budget(), payload, ssh::Message::parse) else {
                    return Ok(Handled::Waiting);
                };
                let (ssh::Message::ServiceRequest(service), _parsed) = parsed?.into_parts() else {
                    return Err(TransportError::State.into());
                };
                if service != "ssh-userauth" {
                    return Err(TransportError::State.into());
                }
                self.send(&ssh::Message::ServiceAccept(service))?;
                self.service_requested = true;
            }
            50 | 61 if self.user.is_none() => return self.authentication(payload, env),
            50 if self.user.is_some() => {}
            80..=82 | 90..=100 if self.user.is_some() => return self.connection(payload, env),
            _ => self.send(&ssh::Message::Unimplemented(sequence))?,
        }
        Ok(Handled::Done)
    }
    /// One step. Storage a step needs that the budget cannot pay for now
    /// makes it wait for memory, changing nothing (layer rule 9): the fixed
    /// storage first, and room for output before each action that writes.
    fn progress(&mut self, env: &mut Env<'_, Ended>) -> Result<bool, Error> {
        if !self.ended && !self.reserve(env.budget()) {
            return Ok(false);
        }
        if self.control.requested() == Requested::Disconnect && !self.ended {
            if !self.room(env.budget()) {
                return Ok(false);
            }
            self.disconnect(
                env,
                ssh::DisconnectReason::ByApplication,
                "Connection closed by application",
            )?;
            return Ok(true);
        }
        if self.ended || self.out_pending() || self.up.len() >= 4 || self.flights.len() >= 120 {
            return Ok(false);
        }
        if !self.started {
            if !self.room(env.budget()) {
                return Ok(false);
            }
            let mut seed = [0; 32];
            env.entropy().fill_random(&mut seed);
            self.written(|transport, out| transport.start(seed, out))??;
            self.timers
                .set(Timer::Login, env.now() + self.config.login_grace);
            self.started = true;
            return Ok(true);
        }
        if matches!(self.transport.state(), TransportState::Established { .. }) {
            if self.failure_ready {
                if !self.room(env.budget()) {
                    return Ok(false);
                }
                if let Some((methods, partial_success)) = self.failure.take() {
                    self.send_with(|out| {
                        auth::write_failure(methods.iter().map(|m| m.name()), partial_success, out)
                    })?;
                }
                self.failure_ready = false;
                return Ok(true);
            }
            if self.user.is_none()
                && self.failure.is_none()
                && (self.attempts >= self.config.max_attempts
                    || self.auth_requests >= MAX_AUTH_REQUESTS)
            {
                if !self.room(env.budget()) {
                    return Ok(false);
                }
                self.disconnect(
                    env,
                    ssh::DisconnectReason::NoMoreAuthMethodsAvailable,
                    "Too many authentication failures",
                )?;
                return Ok(true);
            }
            if !self.pending_packets.is_empty() {
                if !self.room(env.budget()) {
                    return Ok(false);
                }
                // A packet whose parse or copies the budget refuses goes
                // back to the front, unparsed and unchanged.
                let (sequence, payload) = self.pending_packets.pop_front().unwrap();
                return match self.packet(sequence, &payload, env)? {
                    Handled::Done => Ok(true),
                    Handled::Waiting => {
                        self.pending_packets
                            .push_front((sequence, payload))
                            .map_err(|_| TransportError::State)?;
                        Ok(false)
                    }
                };
            }
            let eligible = |id: &ChildId| {
                let channel = self.channels.get(*id).unwrap();
                channel.accepted
                    && !channel.closed
                    && (!channel.confirmed && channel.receive > 0
                        || channel.confirmed
                            && (channel.adjustment().is_some()
                                || channel.granted == 0 && channel.window > 0 && !channel.sent_eof))
            };
            let id = self
                .channels
                .ids()
                .filter(eligible)
                .find(|id| self.credit_turn.is_none_or(|turn| *id > turn))
                .or_else(|| self.channels.ids().find(eligible));
            if let Some(id) = id {
                let channel = self.channels.get(id).unwrap();
                let credit = channel.confirmed && channel.adjustment().is_none();
                if !credit && !self.room(env.budget()) {
                    return Ok(false);
                }
                self.credit_turn = Some(id);
                let channel = self.channels.get_mut(id).unwrap();
                let peer = channel.peer;
                if !channel.confirmed {
                    channel.confirmed = true;
                    channel.advertised = channel.receive.min(WINDOW as u64) as u32;
                    let window = channel.advertised;
                    let wire = channel.wire;
                    self.send(&wire::Message::ChannelOpenConfirmation {
                        recipient: peer,
                        sender: wire,
                        window,
                        max_packet: PACKET,
                        data: Vec::new(),
                    })?;
                } else if let Some(bytes) = channel.adjustment() {
                    channel.advertised += bytes;
                    self.send(&wire::Message::WindowAdjust {
                        recipient: peer,
                        bytes,
                    })?;
                } else {
                    let units = channel.window.min(channel.max_packet) as u64;
                    channel.granted = units;
                    self.raise(MuxEvent::Credit(id, units))?;
                }
                return Ok(true);
            }
            if self.transport.needs_rekey() {
                if !self.room(env.budget()) {
                    return Ok(false);
                }
                self.written(|transport, out| transport.rekey(out))??;
                return Ok(true);
            }
        }
        if !self.transport.poll_ready() || !self.room(env.budget()) {
            return Ok(false);
        }
        let (handler, connection, now) = (&self.handler, &self.connection, env.now());
        let mut observe = |observation| {
            let event = match observation {
                transport::Observation::Version(version) => Event::Version(version),
                transport::Observation::Proposal(proposal) => Event::KexInit(*proposal),
            };
            handler.observe(&Context { connection, now }, &event);
        };
        let polled = fill(&mut self.out, &mut self.transport, |transport, out| {
            transport.poll(env.budget(), out, &mut observe)
        })?;
        let event = match polled {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(false),
            Err(transport::Failure::Framing(_)) => {
                self.written(|transport, out| {
                    transport.disconnect(
                        ssh::DisconnectReason::ProtocolError,
                        "Invalid SSH packet",
                        out,
                    )
                })??;
                self.close(env, Ended::Failed);
                return Ok(true);
            }
            Err(transport::Failure::Protocol(error)) => return Err(error.into()),
        };
        if let transport::Event::End = event {
            self.close(env, Ended::Eof);
            return Ok(true);
        }
        if let transport::Event::Packet { sequence, payload } = event {
            if payload.first() == Some(&1) {
                self.close(env, Ended::Closed);
                return Ok(true);
            }
            let held: usize = self
                .pending_packets
                .iter()
                .map(|(_, data)| data.len())
                .sum();
            if self.pending_packets.len() >= 128 || held + payload.len() > OUTPUT_LIMIT {
                return Err(TransportError::State.into());
            }
            self.pending_packets
                .push_back((sequence, payload))
                .map_err(|_| TransportError::State)?;
        }
        Ok(true)
    }
}

impl<H: Handler, T: PacketTransport> Layer for Ssh<H, T> {
    fn report_bytes(_: &Ended) -> Option<usize> {
        Some(0)
    }
    fn is_terminal(&self) -> bool {
        self.ended
    }
    type Lower = ByteStream;
    type Upper = Mux<ChannelPort, Top, Owned<channel::Opening>>;
    type Report = Ended;
    type Timer = Timer;
    type Work = ();
    type Done = ();
    type Error = Error;
    fn advance(&mut self, env: &mut Env<'_, Ended>) -> Result<bool, Error> {
        self.control.watch(env);
        self.progress(env)
    }
    fn on_event(
        &mut self,
        env: &mut Env<'_, Ended>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Error> {
        match event {
            StreamEvent::Data(mut data) => {
                if self.ended {
                    return Ok(Admit::Closed(StreamEvent::Data(data)));
                }
                if !self.reserve(env.budget()) {
                    return Ok(Admit::Blocked(StreamEvent::Data(data)));
                }
                let n = self.transport.push(env.budget(), &data);
                data.advance(n);
                if !data.is_empty() {
                    return Ok(if n == 0 {
                        Admit::Blocked(StreamEvent::Data(data))
                    } else {
                        Admit::Partial(StreamEvent::Data(data))
                    });
                }
            }
            StreamEvent::Ended => self.transport.end(),
            StreamEvent::Reset => {
                self.close(env, Ended::Conn(crate::stdlib::network::ConnError::Reset))
            }
            StreamEvent::Written(mut n) => {
                if self.up.len() >= 4 {
                    return Ok(Admit::Blocked(StreamEvent::Written(n)));
                }
                while n > 0 {
                    let flight = self.flights.front_mut().ok_or(TransportError::State)?;
                    let used = n.min(flight.bytes as u64);
                    flight.bytes -= used as usize;
                    n -= used;
                    if flight.bytes == 0 {
                        let flight = self.flights.pop_front().unwrap();
                        if let Some((id, bytes)) = flight.child
                            && self.channels.contains(id)
                        {
                            self.raise(MuxEvent::Child(
                                id,
                                ChannelEvent::Stream(StreamEvent::Written(bytes)),
                            ))?;
                        }
                    }
                    if n > 0 && self.up.len() >= 4 {
                        return Ok(Admit::Partial(StreamEvent::Written(n)));
                    }
                }
            }
        }
        Ok(Admit::Taken)
    }
    fn on_command(
        &mut self,
        env: &mut Env<'_, Ended>,
        command: MuxCommand<ChannelPort, Top>,
    ) -> Result<Admit<MuxCommand<ChannelPort, Top>>, Error> {
        if self.ended {
            return Ok(Admit::Closed(command));
        }
        if self.out_pending()
            || self.up.len() >= 4
            || !matches!(self.transport.state(), TransportState::Established { .. })
            || self.flights.len() >= 120
            || !self.room(env.budget())
        {
            return Ok(Admit::Blocked(command));
        }
        // Channel output is copied twice before it is sealed, into its
        // message and for the observer. Both copies are paid for first,
        // and held until the command is done.
        let copies = match command.op() {
            MuxOp::Child(
                _,
                ChannelCommand::Stream(StreamCommand::Write(data))
                | ChannelCommand::Extended { data, .. },
            ) => 2 * data.len(),
            _ => 0,
        };
        let Some(_copies) = env.budget().charge(copies) else {
            return Ok(Admit::Blocked(command));
        };
        match command.into_op() {
            MuxOp::Control(never) => match never {},
            MuxOp::Credit(id, units) | MuxOp::Window(id, units, _) => {
                if let Some(channel) = self.channels.get_mut(id) {
                    channel.receive = channel
                        .receive
                        .checked_add(units)
                        .filter(|n| *n <= u32::MAX as u64)
                        .ok_or(TransportError::State)?;
                }
            }
            MuxOp::Close(id, why) => {
                // A confirmed channel closes, whatever the cause: CLOSE
                // carries none. One not yet confirmed is refused with the
                // receiver's cause.
                if let Some(channel) = self.channels.get_mut(id)
                    && !channel.closed
                {
                    channel.closed = true;
                    let peer = channel.peer;
                    if channel.confirmed {
                        self.send(&wire::Message::Close(peer))?;
                    } else {
                        self.channels.remove(id);
                        self.refuse(peer, why)?;
                        self.raise(MuxEvent::Closed(id))?;
                    }
                }
            }
            MuxOp::Child(id, command) => {
                let Some(channel) = self.channels.get(id) else {
                    return Ok(Admit::Taken);
                };
                if channel.closed {
                    return Ok(Admit::Taken);
                }
                let peer = channel.peer;
                let wire = channel.wire;
                match command {
                    ChannelCommand::Accept(accepted) => {
                        if accepted {
                            let channel = self.channels.get_mut(id).unwrap();
                            if channel.accepted {
                                return Err(TransportError::State.into());
                            }
                            channel.accepted = true;
                        } else {
                            self.channels.remove(id);
                            if self.next_channel == wire + 1 {
                                self.next_channel = wire;
                            }
                            self.refuse(peer, Closing::Prohibited)?;
                            self.raise(MuxEvent::Closed(id))?;
                        }
                    }
                    ChannelCommand::Stream(StreamCommand::Write(data)) => {
                        self.channel_write(env, id, None, data)?
                    }
                    ChannelCommand::Extended { kind, data } => {
                        self.channel_write(env, id, Some(kind), data)?
                    }
                    ChannelCommand::Stream(StreamCommand::End) => {
                        let channel = self.channels.get_mut(id).unwrap();
                        if channel.sent_eof {
                            return Err(TransportError::State.into());
                        }
                        channel.sent_eof = true;
                        self.send(&wire::Message::Eof(peer))?;
                    }
                    ChannelCommand::Stream(StreamCommand::Reset) | ChannelCommand::Close => {
                        self.channels.get_mut(id).unwrap().closed = true;
                        self.send(&wire::Message::Close(peer))?;
                        self.raise(MuxEvent::Child(
                            id,
                            ChannelEvent::Stream(StreamEvent::Reset),
                        ))?;
                    }
                    ChannelCommand::Reply(accepted) => self.send(&if accepted {
                        wire::Message::ChannelSuccess(peer)
                    } else {
                        wire::Message::ChannelFailure(peer)
                    })?,
                    ChannelCommand::Request {
                        want_reply,
                        request,
                    } => {
                        let (request, _charge) = request.into_parts();
                        if let wire::SessionRequest::ExitStatus(status) = request {
                            self.handler.observe(
                                &self.context(env.now()),
                                &Event::Exit {
                                    channel: wire,
                                    status,
                                },
                            );
                        }
                        self.send(&wire::Message::ChannelRequest {
                            recipient: peer,
                            want_reply,
                            request,
                        })?;
                    }
                    ChannelCommand::Hangup => self.close(env, Ended::Closed),
                }
            }
        }
        Ok(Admit::Taken)
    }
    fn take_event(&mut self) -> Option<MuxEvent<ChannelPort, Top, Owned<channel::Opening>>> {
        self.up.pop_front().or_else(|| {
            if !self.ended {
                return None;
            }
            let id = self.channels.ids().next()?;
            self.channels.remove(id);
            Some(MuxEvent::Child(
                id,
                ChannelEvent::Stream(StreamEvent::Reset),
            ))
        })
    }
    fn take_urgent(&mut self) -> Option<MuxEvent<ChannelPort, Top, Owned<channel::Opening>>> {
        let position = self.up.iter().position(|event| {
            matches!(
                event,
                MuxEvent::Child(
                    _,
                    ChannelEvent::Stream(StreamEvent::Written(_) | StreamEvent::Reset)
                )
            )
        })?;
        self.up.remove(position)
    }
    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        if let Some(bytes) = self.out.take_if(|out| !out.is_empty()) {
            assert!(
                self.flights
                    .push_back(Flight {
                        bytes: bytes.len(),
                        child: self.out_child.take(),
                    })
                    .is_ok()
            );
            return Some(StreamCommand::Write(Bytes::from_bytes(bytes)));
        }
        if self.ended && !self.end_sent {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }
    fn deadline(&self) -> Option<(Instant, Timer)> {
        self.timers.next()
    }
    fn on_timer(&mut self, env: &mut Env<'_, Ended>, timer: Timer) -> Result<bool, Error> {
        let fired = self.timers.fire(&timer, env.now());
        if fired {
            match timer {
                Timer::Login if self.room(env.budget()) => self.disconnect(
                    env,
                    ssh::DisconnectReason::ByApplication,
                    "Login grace time exceeded",
                )?,
                // Without memory to say why, the connection closes all the same.
                Timer::Login => self.close(env, Ended::Closed),
                Timer::Failure => self.failure_ready = true,
            }
        }
        Ok(fired)
    }
}
impl<H: Handler, T: PacketTransport> Ssh<H, T> {
    fn channel_write(
        &mut self,
        env: &Env<'_, Ended>,
        id: ChildId,
        kind: Option<u32>,
        data: Bytes,
    ) -> Result<(), Error> {
        let channel = self.channels.get_mut(id).unwrap();
        channel.consume_send(data.len())?;
        let peer = channel.peer;
        let wire = channel.wire;
        let bytes = data.to_vec();
        self.handler.observe(
            &self.context(env.now()),
            &Event::Output {
                channel: wire,
                stderr: kind == Some(1),
                data: bytes.clone(),
            },
        );
        self.send(&match kind {
            Some(kind) => wire::Message::ExtendedData {
                recipient: peer,
                kind,
                data: bytes,
            },
            None => wire::Message::Data {
                recipient: peer,
                data: bytes,
            },
        })?;
        self.out_child = Some((id, data.len() as u64));
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(super) struct Observed(pub(super) Mutex<Vec<Event>>);
    pub(super) struct NoSession;
    impl Session for NoSession {
        fn input(&mut self, _: &Context<'_>, _: &[u8], _: &mut Output) {}
    }
    impl Handler for Observed {
        type Session = NoSession;

        fn authenticate(&self, _: &Context<'_>, attempt: &AuthAttempt<'_>) -> AuthDecision {
            match attempt.request.method {
                auth::Method::Password { .. } | auth::Method::PublicKey { .. } => {
                    AuthDecision::Accept
                }
                _ => AuthDecision::Reject {
                    methods: vec![AuthMethod::Password, AuthMethod::PublicKey],
                    partial_success: false,
                    delay: Duration::ZERO,
                },
            }
        }

        fn open(&self, _: &Context<'_>, _: &SessionRequest, _: &mut Output) -> Option<NoSession> {
            None
        }

        fn observe(&self, _: &Context<'_>, event: &Event) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    struct Client;
    impl russh::client::Handler for Client {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct Signer {
        observed: Arc<Observed>,
        invalid: bool,
    }
    impl russh::Signer for Signer {
        type Error = russh::AgentAuthError;

        async fn auth_sign(
            &mut self,
            _: &russh::keys::agent::AgentIdentity,
            _: Option<russh::keys::HashAlg>,
            mut data: Vec<u8>,
        ) -> Result<Vec<u8>, Self::Error> {
            let events = self.observed.0.lock().unwrap();
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    Event::AuthenticationDecision(AuthDecision::Accept)
                ))
            );
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, Event::Authenticated { .. }))
            );
            drop(events);
            let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
            let mut signature = key.sign(&data).as_ref().to_vec();
            if self.invalid {
                signature[0] ^= 1;
            }
            let mut blob = ssh::SshString(b"ssh-ed25519".to_vec()).to_bytes().unwrap();
            ssh::SshString(signature).write(&mut blob).unwrap();
            ssh::SshString(blob).write(&mut data).unwrap();
            Ok(data)
        }
    }

    #[tokio::test]
    async fn authentication_completion_excludes_probes_and_invalid_signatures() {
        for method in ["password", "publickey", "invalid"] {
            let observed = Arc::new(Observed(Mutex::new(Vec::new())));
            let config = Config::new(
                Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
                ssh::Identification::new("2.0", "test", None).unwrap(),
            );
            let mut harness = crate::stdlib::layer::Harness::new(
                crate::Seed::from_u64(1),
                Ssh::new(
                    Arc::new(config),
                    observed.clone(),
                    Arc::new(ConnInfo::new(
                        1,
                        "127.0.0.1:22".parse().unwrap(),
                        "127.0.0.1:1234".parse().unwrap(),
                    )),
                ),
            );
            let (client, mut server) = tokio::io::duplex(1 << 20);
            let task = tokio::spawn(async move {
                harness.settle().unwrap();
                server.write_all(&harness.take_output()).await.unwrap();
                let mut input = [0; 8192];
                loop {
                    let len = server.read(&mut input).await.unwrap();
                    if len == 0 {
                        break;
                    }
                    match harness.push(&input[..len]) {
                        Ok(()) => server.write_all(&harness.take_output()).await.unwrap(),
                        Err(_) => break,
                    }
                }
                harness.layer().user.as_deref().cloned()
            });
            let mut client = russh::client::connect_stream(
                Arc::new(russh::client::Config::default()),
                client,
                Client,
            )
            .await
            .unwrap();
            let successful = if method == "password" {
                client
                    .authenticate_password("guest", "secret")
                    .await
                    .unwrap()
                    .success()
            } else {
                let key = russh::keys::PrivateKey::from(
                    russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]),
                );
                client
                    .authenticate_publickey_with(
                        "guest",
                        key.public_key().clone(),
                        None,
                        &mut Signer {
                            observed: observed.clone(),
                            invalid: method == "invalid",
                        },
                    )
                    .await
                    .is_ok_and(|result| result.success())
            };
            assert_eq!(successful, method != "invalid");
            if successful {
                client
                    .disconnect(russh::Disconnect::ByApplication, "done", "")
                    .await
                    .unwrap();
            }
            drop(client);
            let user = task.await.unwrap();
            assert_eq!(user.as_deref(), (method != "invalid").then_some("guest"));
            let events = observed.0.lock().unwrap();
            let completed: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    Event::Authenticated { user, method } => Some((user.as_str(), method.as_str())),
                    _ => None,
                })
                .collect();
            if method == "invalid" {
                assert!(completed.is_empty());
                assert!(events.iter().any(|event| matches!(
                    event,
                    Event::Authentication {
                        request: auth::Request {
                            method: auth::Method::PublicKey {
                                signature: Some(_),
                                ..
                            },
                            ..
                        },
                        verified: false
                    }
                )));
            } else {
                assert_eq!(completed, [("guest", method)]);
            }
        }
    }

    /// A connection whose budget has no room waits, holding nothing, and
    /// starts once memory frees: no room is never a protocol failure.
    #[test]
    fn a_connection_without_memory_waits_and_starts_once_memory_frees() {
        let budget = Budget::new(1 << 20);
        let config = Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        ));
        let layer = Ssh::new(
            config,
            Arc::new(Observed(Mutex::new(Vec::new()))),
            Arc::new(ConnInfo::default()),
        );
        let mut harness = crate::stdlib::layer::Harness::with_budget(
            crate::Seed::from_u64(3),
            layer,
            budget.clone(),
        );
        let elsewhere = budget.charge(budget.limit()).unwrap();
        harness.settle().unwrap();
        harness.push(b"SSH-2.0-client\r\n").unwrap();
        assert!(harness.take_output().is_empty());
        assert!(!harness.ended());
        assert_eq!(budget.used(), elsewhere.bytes());
        drop(elsewhere);
        harness.settle().unwrap();
        assert!(!harness.take_output().is_empty());
        assert!(!harness.ended());
        drop(harness);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn malformed_packets_report_failure_and_release_the_budget() {
        let budget = Budget::new(32 << 20);
        let observed = Arc::new(Observed(Mutex::new(Vec::new())));
        let config = Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        ));
        let layer = Ssh::new(config, observed, Arc::new(ConnInfo::default()));
        let mut harness = crate::stdlib::layer::Harness::with_budget(
            crate::Seed::from_u64(3),
            layer,
            budget.clone(),
        );
        harness.settle().unwrap();
        harness.push(b"SSH-2.0-client\r\n").unwrap();
        harness.push(&[0; 16]).unwrap();
        assert!(harness.ended());
        assert!(
            harness
                .driver()
                .observations()
                .iter()
                .any(|end| matches!(end, Ended::Failed))
        );
        drop(harness);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn idle_transport_does_not_reserve_packet_scratch() {
        let budget = Budget::new(1 << 20);
        let config = Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        ));
        let mut harness = crate::stdlib::layer::Harness::with_budget(
            crate::Seed::from_u64(3),
            Ssh::new(
                config,
                Arc::new(Observed(Mutex::new(Vec::new()))),
                Arc::new(ConnInfo::default()),
            ),
            budget.clone(),
        );
        harness.settle().unwrap();
        assert!(!harness.take_output().is_empty());
        harness.settle().unwrap();
        drop(harness);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn rejected_negotiation_preserves_peer_observations() {
        let observed = Arc::new(Observed(Mutex::new(Vec::new())));
        let config = Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        ));
        let mut proposal =
            ssh::transport::Transport::new(config.host_key.clone(), config.identification.clone())
                .proposal()
                .clone();
        proposal.kex_algorithms = vec!["unsupported-exchange".into()];
        let packet = ssh::Packet::from_message(&ssh::Message::KexInit(proposal.clone()))
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut harness = crate::stdlib::layer::Harness::new(
            crate::Seed::from_u64(3),
            Ssh::new(config, observed.clone(), Arc::new(ConnInfo::default())),
        );
        harness.settle().unwrap();
        harness.push(b"SSH-2.0-client\r\n").unwrap();
        assert!(matches!(
            harness.push(&packet),
            Err(Error::Protocol(TransportError::Algorithm))
        ));
        let events = observed.0.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Version(_)))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::KexInit(peer) if peer == &proposal))
        );
    }

    struct Echo(Arc<Mutex<Vec<Program>>>);
    struct EchoSession;
    impl Session for EchoSession {
        fn input(&mut self, _: &Context<'_>, data: &[u8], output: &mut Output) {
            output.write(data).unwrap();
        }
        fn event(&mut self, _: &Context<'_>, event: &SessionEvent, output: &mut Output) {
            if matches!(event, SessionEvent::Eof) {
                output.exit(7);
            }
        }
    }
    impl Handler for Echo {
        type Session = EchoSession;
        fn authenticate(&self, _: &Context<'_>, _: &AuthAttempt<'_>) -> AuthDecision {
            AuthDecision::Accept
        }
        fn open(
            &self,
            _: &Context<'_>,
            request: &SessionRequest,
            output: &mut Output,
        ) -> Option<EchoSession> {
            self.0.lock().unwrap().push(request.program.clone());
            match &request.program {
                Program::Exec(command) if command == b"large" => {
                    output.write(&vec![b'x'; 100_000]).unwrap()
                }
                _ => output.stderr(b"diagnostic").unwrap(),
            }
            Some(EchoSession)
        }
    }

    #[tokio::test]
    async fn channels_preserve_windows_stderr_subsystems_rekey_and_siblings() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let programs = Arc::new(Mutex::new(Vec::new()));
            let config = Arc::new(Config::new(
                Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
                ssh::Identification::new("2.0", "test", None).unwrap(),
            ));
            let layer = Ssh::new(
                config,
                Arc::new(Echo(programs.clone())),
                Arc::new(ConnInfo::default()),
            )
            .sessions();
            let budget = Budget::new(32 << 20);
            let mut harness = crate::stdlib::layer::Harness::with_budget(
                crate::Seed::from_u64(17),
                layer,
                budget.clone(),
            );
            let (client, mut server) = tokio::io::duplex(1 << 20);
            let task = tokio::spawn(async move {
                harness.settle().unwrap();
                server.write_all(&harness.take_output()).await.unwrap();
                let mut input = [0; 8192];
                loop {
                    let n = server.read(&mut input).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    harness.push(&input[..n]).unwrap();
                    server.write_all(&harness.take_output()).await.unwrap();
                    if harness.ended() {
                        break;
                    }
                }
            });
            let config = russh::client::Config {
                window_size: 1024,
                maximum_packet_size: 1024,
                ..Default::default()
            };
            let mut client = russh::client::connect_stream(Arc::new(config), client, Client)
                .await
                .unwrap();
            assert!(
                client
                    .authenticate_password("guest", "secret")
                    .await
                    .unwrap()
                    .success()
            );
            let mut stalled = client.channel_open_session().await.unwrap();
            stalled.exec(true, b"large".to_vec()).await.unwrap();
            let mut active = client.channel_open_session().await.unwrap();
            active.request_subsystem(true, "echo").await.unwrap();
            client.rekey_soon().await.unwrap();
            let input = vec![b'a'; 100_000];
            active.data(&input[..]).await.unwrap();
            active.eof().await.unwrap();
            let mut bytes = Vec::new();
            let mut stderr = Vec::new();
            let mut exit = None;
            let mut eof = false;
            while let Some(message) = active.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => bytes.extend_from_slice(&data),
                    russh::ChannelMsg::ExtendedData { data, ext } => {
                        assert_eq!(ext, 1);
                        stderr.extend_from_slice(&data);
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    russh::ChannelMsg::Eof => eof = true,
                    russh::ChannelMsg::Close => break,
                    russh::ChannelMsg::Success => {}
                    russh::ChannelMsg::WindowAdjusted { new_size } => assert!(new_size > 0),
                    other => panic!("unexpected channel message: {other:?}"),
                }
            }
            assert_eq!(bytes, input);
            assert_eq!(stderr, b"diagnostic");
            assert_eq!(exit, Some(7));
            assert!(eof);
            stalled.eof().await.unwrap();
            let mut received = Vec::new();
            while let Some(message) = stalled.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => received.extend_from_slice(&data),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            assert_eq!(received, vec![b'x'; 100_000]);
            let mut third = client.channel_open_session().await.unwrap();
            third.exec(true, b"last".to_vec()).await.unwrap();
            third.eof().await.unwrap();
            let mut third_closed = false;
            while let Some(message) = third.wait().await {
                if matches!(message, russh::ChannelMsg::Close) {
                    third_closed = true;
                    break;
                }
            }
            assert!(third_closed);
            client
                .disconnect(russh::Disconnect::ByApplication, "done", "")
                .await
                .unwrap();
            drop(client);
            task.await.unwrap();
            assert_eq!(
                *programs.lock().unwrap(),
                vec![
                    Program::Exec(b"large".to_vec()),
                    Program::Subsystem("echo".into()),
                    Program::Exec(b"last".to_vec())
                ]
            );
            assert_eq!(budget.used(), 0);
        })
        .await
        .unwrap();
    }

    /// A client that counts the window adjustments it receives.
    struct Adjustments(Arc<std::sync::atomic::AtomicUsize>);
    impl russh::client::Handler for Adjustments {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn window_adjusted(
            &mut self,
            _: russh::ChannelId,
            _: u32,
            _: &mut russh::client::Session,
        ) -> Result<(), Self::Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Opens `channels` echo channels; with all of them open, each in turn
    /// sends a full receive window before it reads anything back. Returns
    /// the window adjustments the client received.
    async fn full_windows(seed: u64, channels: usize) -> usize {
        let config = Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        ));
        let programs = Arc::new(Mutex::new(Vec::new()));
        let layer = Ssh::new(
            config,
            Arc::new(Echo(programs)),
            Arc::new(ConnInfo::default()),
        )
        .sessions();
        let budget = Budget::new(32 << 20);
        let mut harness = crate::stdlib::layer::Harness::with_budget(
            crate::Seed::from_u64(seed),
            layer,
            budget.clone(),
        );
        let (client, mut server) = tokio::io::duplex(1 << 20);
        let task = tokio::spawn(async move {
            harness.settle().unwrap();
            server.write_all(&harness.take_output()).await.unwrap();
            let mut input = [0; 8192];
            loop {
                let n = server.read(&mut input).await.unwrap();
                if n == 0 {
                    break;
                }
                harness.push(&input[..n]).unwrap();
                server.write_all(&harness.take_output()).await.unwrap();
                if harness.ended() {
                    break;
                }
            }
        });
        let adjustments = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut client = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            client,
            Adjustments(adjustments.clone()),
        )
        .await
        .unwrap();
        assert!(
            client
                .authenticate_password("guest", "secret")
                .await
                .unwrap()
                .success()
        );
        let mut open = Vec::new();
        for _ in 0..channels {
            let channel = client.channel_open_session().await.unwrap();
            channel.exec(true, b"echo".to_vec()).await.unwrap();
            open.push(channel);
        }
        let block = [b'w'; 1024];
        for channel in &mut open {
            for _ in 0..WINDOW as usize / block.len() {
                channel.data(&block[..]).await.unwrap();
            }
            channel.eof().await.unwrap();
            let mut received = 0;
            let mut exit = None;
            while let Some(message) = channel.wait().await {
                match message {
                    russh::ChannelMsg::Data { data } => received += data.len(),
                    russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
            assert_eq!(received, WINDOW as usize);
            assert_eq!(exit, Some(7));
        }
        client
            .disconnect(russh::Disconnect::ByApplication, "done", "")
            .await
            .unwrap();
        drop(client);
        task.await.unwrap();
        assert_eq!(budget.used(), 0);
        adjustments.load(Ordering::Relaxed)
    }

    /// A client that sends a channel's whole window before reading, with
    /// other channels open, gets its echo, exit status and close. The peer
    /// hears of new room about once per half window it used, not once per
    /// packet the server consumed: a client that buffers a bounded number
    /// of messages per channel (russh, 100) stalled behind one adjustment
    /// per kilobyte.
    #[tokio::test]
    async fn full_windows_on_open_channels_finish_with_an_adjustment_per_half_window() {
        tokio::time::timeout(Duration::from_secs(120), async {
            for seed in 0..16 {
                for channels in [4, 1] {
                    let adjustments = full_windows(seed, channels).await;
                    // One per half window each channel's peer used, and a
                    // last one that tops the window up once it is done.
                    let most = channels * (WINDOW as usize / (WINDOW as usize / 2) + 1);
                    assert!(
                        adjustments <= most,
                        "{channels} channels got {adjustments} window adjustments, more than {most}"
                    );
                }
            }
        })
        .await
        .unwrap();
    }

    struct Shutdown(bool);
    impl Session for Shutdown {
        fn input(&mut self, _: &Context<'_>, _: &[u8], output: &mut Output) {
            if self.0 {
                output.hangup();
            } else {
                output.disconnect();
            }
        }
    }
    impl Handler for Shutdown {
        type Session = Shutdown;
        fn authenticate(&self, _: &Context<'_>, _: &AuthAttempt<'_>) -> AuthDecision {
            AuthDecision::Accept
        }
        fn open(
            &self,
            _: &Context<'_>,
            _: &SessionRequest,
            output: &mut Output,
        ) -> Option<Shutdown> {
            output.write(&vec![b'x'; 100_000]).unwrap();
            Some(Shutdown(self.0))
        }
    }

    #[test]
    fn session_shutdown_reaches_the_connection_before_queued_output() {
        for hangup in [false, true] {
            let budget = Budget::new(1 << 20);
            let control = ConnectionControl::new();
            let opening = Owned::new(
                channel::Opening {
                    user: "guest".into(),
                    channel: 0,
                    kind: wire::OpenKind::Session,
                },
                budget.charge(0).unwrap(),
            );
            let session = SessionLayer::new(
                Arc::new(Shutdown(hangup)),
                Arc::new(ConnInfo::default()),
                control.clone(),
                opening,
                &budget,
            );
            let mut driver = crate::stdlib::layer::Driver::new(
                session,
                Arc::new(crate::SeededEntropy::new(crate::Seed::from_u64(3))),
                budget.clone(),
                Instant::ZERO,
            );
            driver.run().unwrap();
            assert!(matches!(
                driver.take_command(),
                Some(ChannelCommand::Accept(true))
            ));
            let request = Owned::new(
                wire::SessionRequest::Exec(b"stop".to_vec()),
                budget.charge(0).unwrap(),
            );
            assert!(
                driver
                    .deliver(ChannelEvent::Request {
                        want_reply: true,
                        request,
                    })
                    .unwrap()
                    .moved()
            );
            driver.run().unwrap();
            assert!(matches!(
                driver.take_command(),
                Some(ChannelCommand::Reply(true))
            ));
            // The session's output is queued and not yet taken.
            assert_eq!(control.requested(), Requested::Open);
            assert!(
                driver
                    .deliver(ChannelEvent::Stream(StreamEvent::Data(Bytes::unpaid(
                        b"trigger".to_vec()
                    ))))
                    .unwrap()
                    .moved()
            );
            driver.run().unwrap();
            if hangup {
                assert_eq!(control.requested(), Requested::Drain);
                let Some(ChannelCommand::Stream(StreamCommand::Write(data))) =
                    driver.take_command()
                else {
                    panic!("queued output must still drain");
                };
                assert_eq!(data.len(), 100_000);
                assert!(matches!(
                    driver.take_command(),
                    Some(ChannelCommand::Hangup)
                ));
            } else {
                assert_eq!(control.requested(), Requested::Disconnect);
            }
            assert!(driver.take_command().is_none());
        }
    }

    /// Counts the wakes of the task that runs the stack.
    #[derive(Default)]
    struct Task(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for Task {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn a_shutdown_asked_for_between_steps_wakes_the_connection() {
        let config = Arc::new(Config::new(
            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        ));
        let ssh = Ssh::new(
            config,
            Arc::new(Shutdown(false)),
            Arc::new(ConnInfo::default()),
        );
        let control = ssh.control();
        let mut driver = crate::stdlib::layer::Driver::new(
            ssh,
            Arc::new(crate::SeededEntropy::new(crate::Seed::from_u64(5))),
            Budget::new(1 << 20),
            Instant::ZERO,
        );
        let task = Arc::new(Task::default());
        driver.set_waker(&Waker::from(task.clone()));
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        assert!(!driver.layer().is_terminal());
        // Another task asks, while no call into the connection runs.
        let drain = control.clone();
        std::thread::spawn(move || drain.drain()).join().unwrap();
        assert_eq!(task.0.load(Ordering::Acquire), 1);
        assert!(driver.woken());
        driver.run().unwrap();
        assert!(!driver.woken());
        assert!(!driver.layer().is_terminal());
        std::thread::spawn(move || control.disconnect())
            .join()
            .unwrap();
        assert_eq!(task.0.load(Ordering::Acquire), 2);
        assert!(driver.woken());
        driver.run().unwrap();
        assert!(driver.layer().is_terminal());
    }

    #[tokio::test]
    async fn connection_shutdown_policy_bypasses_stalled_child_output() {
        tokio::time::timeout(Duration::from_secs(30), async {
            for hangup in [false, true] {
                let config = Arc::new(Config::new(
                    Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
                    ssh::Identification::new("2.0", "test", None).unwrap(),
                ));
                let layer = Ssh::new(
                    config,
                    Arc::new(Shutdown(hangup)),
                    Arc::new(ConnInfo::default()),
                )
                .sessions();
                let mut harness =
                    crate::stdlib::layer::Harness::new(crate::Seed::from_u64(19), layer);
                let (client, mut server) = tokio::io::duplex(1 << 20);
                let task = tokio::spawn(async move {
                    harness.settle().unwrap();
                    server.write_all(&harness.take_output()).await.unwrap();
                    let mut input = [0; 8192];
                    loop {
                        let n = server.read(&mut input).await.unwrap();
                        assert!(n > 0, "server must initiate shutdown");
                        harness.push(&input[..n]).unwrap();
                        server.write_all(&harness.take_output()).await.unwrap();
                        if harness.ended() {
                            break;
                        }
                    }
                });
                let config = russh::client::Config {
                    window_size: if hangup { 1024 } else { 0 },
                    maximum_packet_size: 1024,
                    ..Default::default()
                };
                let mut client = russh::client::connect_stream(Arc::new(config), client, Client)
                    .await
                    .unwrap();
                assert!(
                    client
                        .authenticate_password("guest", "secret")
                        .await
                        .unwrap()
                        .success()
                );
                let mut channel = client.channel_open_session().await.unwrap();
                channel.exec(true, b"stop".to_vec()).await.unwrap();
                assert!(matches!(
                    channel.wait().await,
                    Some(russh::ChannelMsg::Success)
                ));
                channel.data(&b"trigger"[..]).await.unwrap();
                let mut received = Vec::new();
                while let Some(message) = channel.wait().await {
                    if let russh::ChannelMsg::Data { data } = message {
                        received.extend_from_slice(&data);
                    }
                }
                assert_eq!(
                    received,
                    if hangup {
                        vec![b'x'; 100_000]
                    } else {
                        Vec::new()
                    }
                );
                task.await.unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn port_server_runs_real_client_channels_over_tcp() {
        use crate::stdlib::network::{ip, tcp};
        use crate::tokio::ConnectionTokioExt;
        tokio::time::timeout(
            Duration::from_secs(30),
            crate::run(crate::Seed::from_u64(42), |fcx| async move {
                let (a, b) = crate::pair();
                let (a, _, _, _) = ip::split_protocols(&fcx, a);
                let (b, _, _, _) = ip::split_protocols(&fcx, b);
                let server = tcp::endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
                let client = tcp::endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
                let mut listener = server.listen(22)?;
                let budget = Budget::new(32 << 20);
                let server_budget = budget.clone();
                let task = fcx.spawn(move |fcx| async move {
                    let connection = listener.accept(&fcx).await?;
                    let arrival = Arrival {
                        info: ConnInfo::new(1, connection.local_addr(), connection.peer_addr()),
                        socket: Arc::new(connection.gone_watch()),
                        conn: Box::new(connection),
                        budget: Some(server_budget),
                        limits: Default::default(),
                    };
                    let server = Server {
                        config: Arc::new(Config::new(
                            Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap()),
                            ssh::Identification::new("2.0", "test", None).unwrap(),
                        )),
                        handler: Arc::new(Echo(Arc::new(Mutex::new(Vec::new())))),
                        limits: stack::StreamLimits::default(),
                        budget: None,
                        backlog: None,
                    };
                    server.serve_connection(fcx, arrival).await;
                    Ok(())
                });
                let connection = client.connect(&fcx, "10.0.0.1:22".parse().unwrap()).await?;
                let mut client = russh::client::connect_stream(
                    Arc::new(Default::default()),
                    connection.into_tokio(&fcx),
                    Client,
                )
                .await?;
                assert!(
                    client
                        .authenticate_password("guest", "secret")
                        .await?
                        .success()
                );
                let mut channel = client.channel_open_session().await?;
                channel.exec(true, b"echo".to_vec()).await?;
                channel.data(&b"runner"[..]).await?;
                channel.eof().await?;
                let mut data = Vec::new();
                let mut stderr = Vec::new();
                let mut status = None;
                let mut closed = false;
                while let Some(message) = channel.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data: bytes } => data.extend_from_slice(&bytes),
                        russh::ChannelMsg::ExtendedData { data, ext } => {
                            assert_eq!(ext, 1);
                            stderr.extend_from_slice(&data);
                        }
                        russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                        russh::ChannelMsg::Close => {
                            closed = true;
                            break;
                        }
                        _ => {}
                    }
                }
                assert_eq!(data, b"runner");
                assert_eq!(stderr, b"diagnostic");
                assert_eq!(status, Some(7));
                assert!(closed);
                client
                    .disconnect(russh::Disconnect::ByApplication, "done", "")
                    .await?;
                drop(client);
                task.join(&fcx).await?;
                assert_eq!(budget.used(), 0);
                fcx.cancel();
                Ok(())
            }),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[test]
    fn refused_output_keeps_the_queue_and_budget_unchanged() {
        let payload = b"terminal output";
        let places = 1025 * size_of::<Chunk>();
        for limit in [payload.len() - 1, places, places + payload.len() - 1] {
            let budget = Budget::new(limit);
            let mut output = Output::with_budget(budget.clone());
            let before = budget.used();
            assert!(output.write(payload).is_err());
            assert!(output.chunks.is_empty());
            assert_eq!(output.bytes, 0);
            assert_eq!(budget.used(), before, "a refused write retains nothing");
            assert!(budget.used() <= budget.limit());
        }
    }

    #[test]
    fn hangup_preserves_pending_output_and_refuses_more() {
        let mut output = Output::default();
        output.write(b"pending terminal echo").unwrap();
        output.stderr(b"pending diagnostic").unwrap();
        output.hangup();
        assert!(output.write(b"late output").is_err());
        assert!(output.stderr(b"late diagnostic").is_err());
        output.exit(0);
        assert!(!output.chunks.is_empty());
        assert!(
            output
                .chunks
                .iter()
                .all(|chunk| matches!(chunk, Chunk::Data { .. }))
        );

        output.disconnect();
        assert!(output.chunks.is_empty());
        assert!(output.write(b"after disconnect").is_err());
    }
}

#[cfg(test)]
#[path = "ssh/tests.rs"]
mod boundary_tests;

#[cfg(kani)]
#[path = "../../../verification/ssh-layer/kani/mod.rs"]
mod proofs;
