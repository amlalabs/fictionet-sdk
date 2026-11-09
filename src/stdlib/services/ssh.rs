//! SSH servers over composable byte streams, following RFCs 4252, 4253 and 4254.
//!
//! [`Handler`] chooses authentication and starts sessions. [`Session`] consumes
//! input bytes and terminal events; [`Output`] queues stdout, stderr and exit
//! status under a fixed bound, or disconnects the entire connection. Channel
//! windows apply when the queue is sent.
//! The world supplies identity, authentication policy and application behavior.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Waker;
use std::time::Duration;

use super::stack;
use crate::Cx;
use crate::stdlib::codec::Wire;
use crate::stdlib::layer::{
    Admit, Budget, ByteStream, Chain, Charge, ChildId, Children, Chunk as Bytes, Env, Layer, Mux,
    MuxCommand, MuxEvent, MuxOp, Owned, Slots, StreamCommand, StreamEvent, Timers, Top,
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
#[derive(Default, Debug)]
pub struct Output {
    chunks: VecDeque<Chunk>,
    bytes: usize,
    exited: bool,
    disconnect: bool,
    hangup: bool,
    budget: Option<Budget>,
    storage: Option<Charge>,
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
impl Output {
    fn with_budget(budget: Budget) -> Self {
        Self {
            budget: Some(budget),
            ..Self::default()
        }
    }
    fn clear(&mut self) {
        self.chunks.clear();
        self.bytes = 0;
        self.exited = false;
        self.disconnect = false;
        self.hangup = false;
    }
    fn reserve(&mut self) -> Result<(), OutputFull> {
        if self.storage.is_none() {
            let budget = self.budget.get_or_insert_with(Budget::unlimited);
            let charge = budget
                .charge(1025 * std::mem::size_of::<Chunk>())
                .ok_or(OutputFull)?;
            self.chunks = VecDeque::with_capacity(1025);
            self.storage = Some(charge);
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
            self.reserve()?;
            let charge = self
                .budget
                .as_ref()
                .unwrap()
                .charge(bytes.len())
                .ok_or(OutputFull)?;
            self.bytes = next;
            self.chunks.push_back(Chunk::Data {
                stderr,
                data: Bytes::with_charge(bytes.to_vec(), charge),
            });
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
            self.chunks.push_back(Chunk::Exit(status));
        }
    }
    /// Disconnect the whole SSH connection, discarding queued channel output.
    /// This takes precedence over channel flow control and pending requests.
    pub fn disconnect(&mut self) {
        self.exited = true;
        self.disconnect = true;
        self.chunks.clear();
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
    /// The connection held more than its [`Budget`] allows.
    Budget,
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
            Ended::Budget => "budget",
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
                Ok(stack::StreamEnd::Budget) | Err(stack::StackError::Budget) => Ended::Budget,
                Ok(stack::StreamEnd::Conn(error)) => Ended::Conn(error),
                Ok(stack::StreamEnd::Reset) => {
                    Ended::Conn(crate::stdlib::network::ConnError::Reset)
                }
                Err(stack::StackError::Cancelled) => Ended::Cancelled,
                Err(stack::StackError::Layer(crate::stdlib::layer::Side::Lower(Error::Budget))) => {
                    Ended::Budget
                }
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

/// Why the SSH connection layer could not continue.
#[derive(Debug)]
pub enum Error {
    /// Invalid protocol traffic or cryptographic state.
    Protocol(TransportError),
    /// The connection could not reserve bounded protocol storage.
    Budget,
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
            Self::Budget => f.write_str("SSH storage exceeds the memory budget"),
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
}

struct Flight {
    bytes: usize,
    child: Option<(ChildId, u64)>,
}

/// A synchronous SSH connection: a byte stream below and typed channels above.
/// Authentication and connection requests remain with the parent. Attach
/// [`Children`] directly for another channel application, or use [`Self::sessions`].
/// Host configuration and synchronous policy callback allocations belong to the
/// caller. Bounded transport parsing storage is reserved before decoding.
pub struct Ssh<H: Handler, T: PacketTransport = StandardTransport> {
    config: Arc<Config>,
    handler: Arc<H>,
    connection: Arc<ConnInfo>,
    transport: T,
    timers: Timers<Timer>,
    started: bool,
    ended: bool,
    end_sent: bool,
    state: Option<Charge>,
    out: Vec<u8>,
    out_charge: Option<Charge>,
    out_child: Option<(ChildId, u64)>,
    flights: VecDeque<Flight>,
    up: VecDeque<MuxEvent<ChannelPort, Top, Owned<channel::Opening>>>,
    channels: Slots<Channel>,
    next_channel: u32,
    credit_turn: Option<ChildId>,
    control: ConnectionControl,
    user: Option<String>,
    auth_user: Option<String>,
    service_requested: bool,
    attempts: u32,
    auth_requests: u32,
    challenge: Option<(auth::Request, usize)>,
    failure: Option<Vec<u8>>,
    failure_ready: bool,
    pending_packets: VecDeque<(u32, Owned<Vec<u8>>)>,
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
            state: None,
            out: Vec::new(),
            out_charge: None,
            out_child: None,
            flights: VecDeque::new(),
            up: VecDeque::new(),
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
            pending_packets: VecDeque::new(),
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
    fn observe_transport(&self, observation: &transport::Observation, now: Instant) {
        let event = match observation {
            transport::Observation::Version(version) => Event::Version(version.clone()),
            transport::Observation::Proposal(proposal) => Event::KexInit(proposal.as_ref().clone()),
        };
        self.handler.observe(&self.context(now), &event);
    }
    fn resident_bytes(&self) -> usize {
        self.transport.resident_bytes() + 6 * ssh::MAX_PAYLOAD
    }
    fn scratch(&mut self) -> Result<(), Error> {
        // A name list may expand a two-byte wire name into a String and its
        // allocation. Parsing and observation can temporarily hold several copies.
        let charge = self.state.as_mut().ok_or(TransportError::State)?;
        if charge.set(charge.bytes() + 64 * ssh::MAX_PACKET) {
            Ok(())
        } else {
            Err(Error::Budget)
        }
    }
    fn reserve(&mut self, env: &Env<'_, Ended>) -> Result<(), Error> {
        if self.state.is_none() {
            // Authentication retains bounded request fields and challenge state.
            let bytes = self.resident_bytes()
                + 128 * std::mem::size_of::<Flight>()
                + 128 * std::mem::size_of::<(u32, Owned<Vec<u8>>)>()
                + 8 * std::mem::size_of::<MuxEvent<ChannelPort, Top, Owned<channel::Opening>>>();
            let charge = env.budget().charge(bytes).ok_or(Error::Budget)?;
            self.channels =
                Slots::with_budget(self.config.max_channels, env.budget()).ok_or(Error::Budget)?;
            self.flights = VecDeque::with_capacity(128);
            self.pending_packets = VecDeque::with_capacity(128);
            self.up = VecDeque::with_capacity(8);
            self.state = Some(charge);
        }
        Ok(())
    }
    fn output(&mut self, env: &Env<'_, Ended>) -> Result<(), Error> {
        if self.out_charge.is_none() {
            let bytes = 4 * ssh::MAX_PACKET;
            let charge = env.budget().charge(bytes).ok_or(Error::Budget)?;
            self.out = Vec::with_capacity(bytes);
            self.out_charge = Some(charge);
        }
        Ok(())
    }
    fn write(&mut self, env: &Env<'_, Ended>, payload: &[u8]) -> Result<(), Error> {
        self.output(env)?;
        if self.out.len() + ssh::MAX_PACKET > self.out.capacity() {
            return Err(TransportError::State.into());
        }
        self.transport
            .write_packet(payload, &mut self.out)
            .map_err(Error::Protocol)
    }
    fn send(
        &mut self,
        env: &Env<'_, Ended>,
        message: &impl Wire<WriteError = ssh::Error>,
    ) -> Result<(), Error> {
        self.write(env, &message.to_bytes()?)
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
        self.output(env)?;
        self.transport
            .disconnect(reason, description, &mut self.out)?;
        self.close(env, Ended::Closed);
        Ok(())
    }
    fn id(&self, wire: u32) -> Result<ChildId, Error> {
        self.channels
            .ids()
            .find(|id| self.channels.get(*id).unwrap().wire == wire)
            .ok_or_else(|| TransportError::State.into())
    }
    fn authentication(&mut self, payload: &[u8], env: &mut Env<'_, Ended>) -> Result<(), Error> {
        if !self.service_requested || self.failure.is_some() {
            return Err(TransportError::State.into());
        }
        self.auth_requests = self.auth_requests.saturating_add(1);
        if self.auth_requests > MAX_AUTH_REQUESTS {
            return Err(TransportError::State.into());
        }
        let (request, responses) = if payload.first() == Some(&61) {
            let auth::Message::InfoResponse(responses) = auth::Message::parse(payload)? else {
                return Err(TransportError::State.into());
            };
            self.handler.observe(
                &self.context(env.now()),
                &Event::AuthenticationResponses(responses.clone()),
            );
            let (request, count) = self.challenge.take().ok_or(TransportError::State)?;
            if responses.len() != count {
                return Err(TransportError::State.into());
            }
            (request, Some(responses))
        } else {
            self.challenge = None;
            (auth::Request::parse(payload)?, None)
        };
        if request.service != "ssh-connection" {
            return Err(TransportError::State.into());
        }
        if self
            .auth_user
            .as_ref()
            .is_some_and(|user| user != &request.user)
        {
            return Err(TransportError::State.into());
        }
        if self.auth_user.is_none() {
            self.auth_user = Some(request.user.clone());
            if let Some(message) = &self.config.banner {
                self.send(
                    env,
                    &auth::Message::Banner {
                        message: message.clone(),
                        language: String::new(),
                    },
                )?;
            }
        }
        let verified = request
            .verify_public_key(
                match self.transport.state() {
                    TransportState::Established { session_id, .. }
                    | TransportState::Rekeying { session_id } => Some(session_id),
                    TransportState::Pending => None,
                }
                .ok_or(TransportError::State)?,
                payload,
            )
            .unwrap_or(false);
        self.handler.observe(
            &self.context(env.now()),
            &Event::Authentication {
                request: request.clone(),
                verified,
            },
        );
        let attempt = AuthAttempt {
            request: &request,
            signature_verified: verified,
            responses: responses.as_deref(),
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
                if let auth::Method::PublicKey { algorithm, key, .. } = request.method {
                    self.send(env, &auth::Message::PublicKeyOk { algorithm, key })?;
                }
            }
            AuthDecision::Accept => {
                self.send(env, &auth::Message::Success)?;
                self.user = Some(request.user.clone());
                self.auth_user = None;
                self.challenge = None;
                self.timers.cancel(&Timer::Login);
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
                let failure = auth::Message::Failure {
                    methods: methods.into_iter().map(|m| m.name().to_owned()).collect(),
                    partial_success,
                }
                .to_bytes()?;
                if delay.is_zero() {
                    self.write(env, &failure)?;
                } else {
                    self.failure = Some(failure);
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
                self.send(
                    env,
                    &auth::Message::InfoRequest {
                        name,
                        instruction,
                        language: String::new(),
                        prompts,
                    },
                )?;
                self.challenge = Some((request, count));
            }
        }
        Ok(())
    }

    fn connection_message(
        &mut self,
        message: wire::Message,
        env: &mut Env<'_, Ended>,
    ) -> Result<(), Error> {
        self.handler.observe(
            &self.context(env.now()),
            &Event::Connection(message.clone()),
        );
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
                    self.send(
                        env,
                        &match response {
                            Some(data) => wire::Message::RequestSuccess(data),
                            None => wire::Message::RequestFailure,
                        },
                    )?;
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
                    return self.refuse(env, sender);
                }
                let wire = self.next_channel;
                self.next_channel = wire.checked_add(1).ok_or(TransportError::State)?;
                let charge = env
                    .budget()
                    .charge(ssh::MAX_PAYLOAD * 2)
                    .ok_or(Error::Budget)?;
                let opening = Owned::new(
                    channel::Opening {
                        user: self.user.clone().ok_or(TransportError::State)?,
                        channel: wire,
                        kind,
                    },
                    charge,
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
                self.up.push_back(MuxEvent::Opened(
                    child,
                    opening,
                    max_packet.min(PACKET) as u64,
                ));
            }
            wire::Message::WindowAdjust { recipient, bytes } => {
                let id = self.id(recipient)?;
                let channel = self.channels.get_mut(id).unwrap();
                channel.window = channel
                    .window
                    .checked_add(bytes)
                    .ok_or(TransportError::State)?;
            }
            wire::Message::Data { recipient, data } => self.input(env, recipient, None, data)?,
            wire::Message::ExtendedData {
                recipient,
                kind,
                data,
            } => self.input(env, recipient, Some(kind), data)?,
            wire::Message::ChannelRequest {
                recipient,
                want_reply,
                request,
            } => {
                let id = self.id(recipient)?;
                if self.channels.get(id).unwrap().closed {
                    return Err(TransportError::State.into());
                }
                let charge = env
                    .budget()
                    .charge(ssh::MAX_PAYLOAD * 2)
                    .ok_or(Error::Budget)?;
                self.up.push_back(MuxEvent::Child(
                    id,
                    ChannelEvent::Request {
                        want_reply,
                        request: Owned::new(request, charge),
                    },
                ));
            }
            wire::Message::ChannelSuccess(recipient) | wire::Message::ChannelFailure(recipient) => {
                let id = self.id(recipient)?;
                self.up.push_back(MuxEvent::Child(
                    id,
                    ChannelEvent::Reply(matches!(message, wire::Message::ChannelSuccess(_))),
                ));
            }
            wire::Message::Eof(recipient) => {
                let id = self.id(recipient)?;
                let channel = self.channels.get_mut(id).unwrap();
                if channel.eof {
                    return Err(TransportError::State.into());
                }
                channel.eof = true;
                self.up.push_back(MuxEvent::Child(
                    id,
                    ChannelEvent::Stream(StreamEvent::Ended),
                ));
            }
            wire::Message::Close(recipient) => {
                let id = self.id(recipient)?;
                let channel = self.channels.remove(id).unwrap();
                if !channel.closed {
                    self.send(env, &wire::Message::Close(channel.peer))?;
                }
                self.up.push_back(MuxEvent::Child(
                    id,
                    ChannelEvent::Stream(StreamEvent::Reset),
                ));
            }
            _ => return Err(TransportError::State.into()),
        }
        Ok(())
    }
    fn refuse(&mut self, env: &Env<'_, Ended>, peer: u32) -> Result<(), Error> {
        self.send(
            env,
            &wire::Message::ChannelOpenFailure {
                recipient: peer,
                reason: 1,
                description: "Channel refused".into(),
                language: String::new(),
            },
        )
    }
    fn input(
        &mut self,
        env: &Env<'_, Ended>,
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
        let charge = env.budget().charge(data.capacity()).ok_or(Error::Budget)?;
        let data = Bytes::with_charge(data, charge);
        self.up.push_back(MuxEvent::Child(
            id,
            match kind {
                Some(kind) => ChannelEvent::Extended { kind, data },
                None => ChannelEvent::Stream(StreamEvent::Data(data)),
            },
        ));
        Ok(())
    }
    fn packet(
        &mut self,
        sequence: u32,
        payload: &[u8],
        env: &mut Env<'_, Ended>,
    ) -> Result<(), Error> {
        if self.control.requested() != Requested::Open {
            return match payload.first() {
                Some(93) => self.connection_message(wire::Message::parse(payload)?, env),
                Some(97) => {
                    self.close(env, Ended::Closed);
                    Ok(())
                }
                _ => Ok(()),
            };
        }
        if self.user.is_none()
            && (self.attempts >= self.config.max_attempts
                || self.auth_requests >= MAX_AUTH_REQUESTS)
        {
            return self.disconnect(
                env,
                ssh::DisconnectReason::NoMoreAuthMethodsAvailable,
                "Too many authentication failures",
            );
        }
        match payload.first().copied().ok_or(TransportError::State)? {
            5 if self.user.is_none() && !self.service_requested => {
                let ssh::Message::ServiceRequest(service) = ssh::Message::parse(payload)? else {
                    return Err(TransportError::State.into());
                };
                if service != "ssh-userauth" {
                    return Err(TransportError::State.into());
                }
                self.send(env, &ssh::Message::ServiceAccept(service))?;
                self.service_requested = true;
            }
            50 | 61 if self.user.is_none() => self.authentication(payload, env)?,
            50 if self.user.is_some() => {}
            80..=82 | 90..=100 if self.user.is_some() => {
                self.connection_message(wire::Message::parse(payload)?, env)?
            }
            _ => self.send(env, &ssh::Message::Unimplemented(sequence))?,
        }
        Ok(())
    }
    fn progress(&mut self, env: &mut Env<'_, Ended>) -> Result<bool, Error> {
        if self.control.requested() == Requested::Disconnect && !self.ended {
            self.disconnect(
                env,
                ssh::DisconnectReason::ByApplication,
                "Connection closed by application",
            )?;
            return Ok(true);
        }
        if self.ended || !self.out.is_empty() || self.up.len() >= 4 || self.flights.len() >= 120 {
            return Ok(false);
        }
        self.reserve(env)?;
        if !self.started {
            self.output(env)?;
            let mut seed = [0; 32];
            env.entropy().fill_random(&mut seed);
            self.transport.start(seed, &mut self.out)?;
            self.timers
                .set(Timer::Login, env.now() + self.config.login_grace);
            self.started = true;
            return Ok(true);
        }
        if matches!(self.transport.state(), TransportState::Established { .. }) {
            if self.failure_ready {
                if let Some(failure) = self.failure.take() {
                    self.write(env, &failure)?;
                }
                self.failure_ready = false;
                return Ok(true);
            }
            if self.user.is_none()
                && self.failure.is_none()
                && (self.attempts >= self.config.max_attempts
                    || self.auth_requests >= MAX_AUTH_REQUESTS)
            {
                self.disconnect(
                    env,
                    ssh::DisconnectReason::NoMoreAuthMethodsAvailable,
                    "Too many authentication failures",
                )?;
                return Ok(true);
            }
            if let Some((sequence, payload)) = self.pending_packets.pop_front() {
                self.scratch()?;
                self.packet(sequence, &payload, env)?;
                return Ok(true);
            }
            let eligible = |id: &ChildId| {
                let channel = self.channels.get(*id).unwrap();
                channel.accepted
                    && !channel.closed
                    && (!channel.confirmed && channel.receive > 0
                        || channel.confirmed
                            && (channel.receive > channel.advertised as u64
                                || channel.granted == 0 && channel.window > 0 && !channel.sent_eof))
            };
            let id = self
                .channels
                .ids()
                .filter(eligible)
                .find(|id| self.credit_turn.is_none_or(|turn| *id > turn))
                .or_else(|| self.channels.ids().find(eligible));
            if let Some(id) = id {
                self.credit_turn = Some(id);
                let channel = self.channels.get_mut(id).unwrap();
                let peer = channel.peer;
                if !channel.confirmed {
                    channel.confirmed = true;
                    channel.advertised = channel.receive.min(WINDOW as u64) as u32;
                    let window = channel.advertised;
                    let wire = channel.wire;
                    self.send(
                        env,
                        &wire::Message::ChannelOpenConfirmation {
                            recipient: peer,
                            sender: wire,
                            window,
                            max_packet: PACKET,
                            data: Vec::new(),
                        },
                    )?;
                } else if channel.receive > channel.advertised as u64 {
                    let bytes = (channel.receive - channel.advertised as u64)
                        .min(u32::MAX as u64 - channel.advertised as u64)
                        as u32;
                    channel.advertised += bytes;
                    self.send(
                        env,
                        &wire::Message::WindowAdjust {
                            recipient: peer,
                            bytes,
                        },
                    )?;
                } else {
                    let units = channel.window.min(channel.max_packet) as u64;
                    channel.granted = units;
                    self.up.push_back(MuxEvent::Credit(id, units));
                }
                return Ok(true);
            }
            if self.transport.needs_rekey() {
                self.output(env)?;
                self.transport.rekey(&mut self.out)?;
                return Ok(true);
            }
        }
        if !self.transport.poll_ready() {
            return Ok(false);
        }
        self.scratch()?;
        self.output(env)?;
        let event = match self.transport.poll(&mut self.out) {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(false),
            Err(transport::Failure::Framing(_)) => {
                self.transport.disconnect(
                    ssh::DisconnectReason::ProtocolError,
                    "Invalid SSH packet",
                    &mut self.out,
                )?;
                self.close(env, Ended::Failed);
                return Ok(true);
            }
            Err(transport::Failure::Protocol { error, observation }) => {
                if let Some(observation) = observation {
                    self.observe_transport(&observation, env.now());
                }
                return Err(error.into());
            }
        };
        match &event {
            transport::Event::Observed(observation) => {
                self.observe_transport(observation, env.now())
            }
            transport::Event::End => {
                self.close(env, Ended::Eof);
                return Ok(true);
            }
            _ => {}
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
            let charge = env
                .budget()
                .charge(payload.capacity())
                .ok_or(Error::Budget)?;
            self.pending_packets
                .push_back((sequence, Owned::new(payload, charge)));
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
        let result = self.progress(env);
        let bytes = self.resident_bytes()
            + 128 * std::mem::size_of::<Flight>()
            + 128 * std::mem::size_of::<(u32, Owned<Vec<u8>>)>()
            + 8 * std::mem::size_of::<MuxEvent<ChannelPort, Top, Owned<channel::Opening>>>();
        if let Some(charge) = &mut self.state
            && !charge.set(bytes)
        {
            return Err(Error::Budget);
        }
        result
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
                self.reserve(env)?;
                let n = self.transport.push(&data);
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
                            self.up.push_back(MuxEvent::Child(
                                id,
                                ChannelEvent::Stream(StreamEvent::Written(bytes)),
                            ));
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
        if !self.out.is_empty()
            || self.up.len() >= 4
            || !matches!(self.transport.state(), TransportState::Established { .. })
            || self.flights.len() >= 120
        {
            return Ok(Admit::Blocked(command));
        }
        match command.into_op() {
            MuxOp::Control(never) => match never {},
            MuxOp::Credit(id, units) => {
                if let Some(channel) = self.channels.get_mut(id) {
                    channel.receive = channel
                        .receive
                        .checked_add(units)
                        .filter(|n| *n <= u32::MAX as u64)
                        .ok_or(TransportError::State)?;
                }
            }
            MuxOp::Close(id) => {
                if let Some(channel) = self.channels.get_mut(id)
                    && !channel.closed
                {
                    channel.closed = true;
                    let peer = channel.peer;
                    if channel.confirmed {
                        self.send(env, &wire::Message::Close(peer))?;
                    } else {
                        self.channels.remove(id);
                        self.refuse(env, peer)?;
                        self.up.push_back(MuxEvent::Closed(id));
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
                            self.refuse(env, peer)?;
                            self.up.push_back(MuxEvent::Closed(id));
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
                        self.send(env, &wire::Message::Eof(peer))?;
                    }
                    ChannelCommand::Stream(StreamCommand::Reset) | ChannelCommand::Close => {
                        self.channels.get_mut(id).unwrap().closed = true;
                        self.send(env, &wire::Message::Close(peer))?;
                        self.up.push_back(MuxEvent::Child(
                            id,
                            ChannelEvent::Stream(StreamEvent::Reset),
                        ));
                    }
                    ChannelCommand::Reply(accepted) => self.send(
                        env,
                        &if accepted {
                            wire::Message::ChannelSuccess(peer)
                        } else {
                            wire::Message::ChannelFailure(peer)
                        },
                    )?,
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
                        self.send(
                            env,
                            &wire::Message::ChannelRequest {
                                recipient: peer,
                                want_reply,
                                request,
                            },
                        )?;
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
        if !self.out.is_empty() {
            let bytes = std::mem::take(&mut self.out);
            self.flights.push_back(Flight {
                bytes: bytes.len(),
                child: self.out_child.take(),
            });
            return Some(StreamCommand::Write(Bytes::with_charge(
                bytes,
                self.out_charge.take().unwrap(),
            )));
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
    fn on_timer(&mut self, env: &mut Env<'_, Ended>, timer: Timer) -> Result<(), Error> {
        if self.timers.fire(&timer, env.now()) {
            match timer {
                Timer::Login => self.disconnect(
                    env,
                    ssh::DisconnectReason::ByApplication,
                    "Login grace time exceeded",
                )?,
                Timer::Failure => self.failure_ready = true,
            }
        }
        Ok(())
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
        self.send(
            env,
            &match kind {
                Some(kind) => wire::Message::ExtendedData {
                    recipient: peer,
                    kind,
                    data: bytes,
                },
                None => wire::Message::Data {
                    recipient: peer,
                    data: bytes,
                },
            },
        )?;
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
                harness.layer().user.clone()
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

    #[test]
    fn exhausted_storage_is_distinct_from_invalid_protocol_traffic() {
        let budget = Budget::new(0);
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
        assert!(matches!(harness.settle(), Err(Error::Budget)));
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
                    .deliver(ChannelEvent::Stream(StreamEvent::Data(Bytes::new(
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
