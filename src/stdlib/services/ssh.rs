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
use std::time::Duration;

use super::serve::ConnInfo;
use super::stack;
use crate::stdlib::layer::{Admit, Budget, ByteStream, Chain, Charge, ChildId, Children, Chunk as Bytes, Env, Layer, Mux, MuxCommand, MuxEvent, MuxOp, Owned, Slots, StreamCommand, StreamEvent, Timers, Top};
use crate::Cx;
use crate::stdlib::codec::{Stream, Wire};
use crate::stdlib::protocols::ssh::transport::{
    HostKey, Transport, TransportError, TransportEvent,
};
use crate::stdlib::protocols::ssh::{self, auth, connection as wire};
use crate::stdlib::world::net::{Arrival, PortServer};
use crate::time::Instant;

pub mod channel;
mod session;
pub use session::SessionLayer;
use channel::{ChannelPort, ChannelEvent, ChannelCommand, Opening};

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
    fn extended(&mut self, _context: &Context<'_>, _kind: u32, _bytes: &[u8], _output: &mut Output) {}
    /// A success or failure reply to an application channel request.
    fn reply(&mut self, _context: &Context<'_>, _accepted: bool, _output: &mut Output) {}
    /// Bytes retained by the application, charged to the connection's budget.
    fn held(&self) -> usize {
        0
    }
}

#[derive(Debug)]
enum Chunk {
    Data {
        stderr: bool,
        data: Bytes,
    },
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
    fn with_budget(budget: Budget) -> Self { Self { budget: Some(budget), ..Self::default() } }
    fn clear(&mut self) {
        self.chunks.clear(); self.bytes = 0; self.exited = false; self.disconnect = false; self.hangup = false;
    }
    fn reserve(&mut self) -> Result<(), OutputFull> {
        if self.storage.is_none() {
            let budget = self.budget.get_or_insert_with(Budget::unlimited);
            let charge = budget.charge(1025 * std::mem::size_of::<Chunk>()).ok_or(OutputFull)?;
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
    fn push(&mut self, stderr: bool, bytes: &[u8]) -> Result<(), OutputFull> {
        if self.exited
            || bytes.len() > OUTPUT_LIMIT.saturating_sub(self.bytes)
            || self.chunks.len() >= 1024
        {
            return Err(OutputFull);
        }
        if !bytes.is_empty() {
            self.reserve()?;
            let charge = self.budget.as_ref().unwrap().charge(bytes.len()).ok_or(OutputFull)?;
            self.bytes += bytes.len();
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
            if self.reserve().is_err() { self.disconnect(); return; }
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
    /// delivered to the observer; [`connection`] itself then returns
    /// [`ServeError::Cancelled`], or the failure that cancelled the region.
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
impl<H: Handler> PortServer for Server<H> {
    fn backlog(&self) -> Option<usize> { self.backlog }
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let info = Arc::new(arrival.info);
        let layer = Ssh::new(self.config.clone(), self.handler.clone(), info.clone()).sessions();
        let handler = self.handler.clone();
        let budget = self.budget.clone().or(arrival.budget).unwrap_or_else(Budget::unlimited);
        let limits = self.limits;
        Box::pin(async move {
            let mut protocol_end = Ended::Eof;
            let result = stack::stream(&fcx, arrival.conn, &info, layer, budget, limits, |report| {
                if let crate::stdlib::layer::Side::Lower(reason) = report { protocol_end = reason; }
            }).await;
            let end = match result {
                Ok(stack::StreamEnd::Finished) => protocol_end,
                Ok(stack::StreamEnd::Idle) => Ended::Idle,
                Ok(stack::StreamEnd::Budget) | Err(stack::StackError::Budget) => Ended::Budget,
                Ok(stack::StreamEnd::Conn(error)) => Ended::Conn(error),
                Ok(stack::StreamEnd::Reset) => Ended::Conn(crate::stdlib::network::ConnError::Reset),
                Err(stack::StackError::Cancelled) => Ended::Cancelled,
                Err(stack::StackError::Layer(_)) => Ended::Closed,
            };
            handler.observe(&Context { connection: &info, now: fcx.now() }, &Event::End(end));
        })
    }
}

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
    eof: bool,
    sent_eof: bool,
    closed: bool,
    written: u64,
}
struct Flight { bytes: usize, child: Option<(ChildId, u64)> }

/// A synchronous SSH connection: a byte stream below and typed channels above.
/// Authentication and connection requests remain with the parent. Attach
/// [`Children`] directly for another channel application, or use [`Self::sessions`].
/// Host configuration and synchronous policy callback allocations belong to the
/// caller. Bounded transport parsing storage is reserved before decoding.
pub struct Ssh<H: Handler> {
    config: Arc<Config>,
    handler: Arc<H>,
    connection: Arc<ConnInfo>,
    stream: Stream<Transport>,
    timers: Timers<Timer>,
    started: bool,
    ended: bool,
    end_sent: bool,
    state: Option<Charge>,
    out: Vec<u8>,
    out_charge: Option<Charge>,
    out_child: Option<(ChildId, u64)>,
    flights: VecDeque<Flight>,
    up: VecDeque<MuxEvent<ChannelPort, Top, Owned<Opening>>>,
    channels: Slots<Channel>,
    next_channel: u32,
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
pub type Sessions<H> = Chain<Ssh<H>, Children<SessionLayer<H>, Top, Owned<Opening>>>;

impl<H: Handler> Ssh<H> {
    /// A fresh SSH layer with explicit connection identity.
    pub fn new(config: Arc<Config>, handler: Arc<H>, connection: Arc<ConnInfo>) -> Self {
        let stream = Stream::new(Transport::new(config.host_key.clone(), config.identification.clone()));
        let limit = config.max_channels;
        Self { config, handler, connection, stream, timers: Timers::new(), started: false,
            ended: false, end_sent: false, state: None, out: Vec::new(), out_charge: None,
            out_child: None, flights: VecDeque::new(), up: VecDeque::new(), channels: Slots::new(limit),
            next_channel: 0, user: None, auth_user: None, service_requested: false, attempts: 0,
            auth_requests: 0, challenge: None, failure: None, failure_ready: false, pending_packets: VecDeque::new() }
    }
    /// Run the configured Handler and Session policy on each channel.
    pub fn sessions(self) -> Sessions<H> {
        let handler = self.handler.clone();
        let connection = self.connection.clone();
        let limit = self.config.max_channels;
        Chain::new(self, Children::new(limit, u64::from(WINDOW), move |_, opening, budget| {
            SessionLayer::new(handler.clone(), connection.clone(), opening, budget)
        }))
    }
    fn context(&self, now: Instant) -> Context<'_> { Context { connection: &self.connection, now } }
    fn reserve(&mut self, env: &Env<'_, Ended>) -> Result<(), TransportError> {
        if self.state.is_none() {
            // Name lists can expand into many owned strings; this covers the
            // buffered packet, transport exchanges, parsing scratch and queues.
            let bytes = 64 * ssh::MAX_PACKET + 128 * std::mem::size_of::<Flight>()
                + 128 * std::mem::size_of::<(u32, Owned<Vec<u8>>)>()
                + 8 * std::mem::size_of::<MuxEvent<ChannelPort, Top, Owned<Opening>>>();
            let charge = env.budget().charge(bytes).ok_or(TransportError::State)?;
            self.channels = Slots::with_budget(self.config.max_channels, env.budget()).ok_or(TransportError::State)?;
            self.flights = VecDeque::with_capacity(128);
            self.pending_packets = VecDeque::with_capacity(128);
            self.up = VecDeque::with_capacity(8);
            self.state = Some(charge);
        }
        Ok(())
    }
    fn output(&mut self, env: &Env<'_, Ended>) -> Result<(), TransportError> {
        if self.out_charge.is_none() {
            let bytes = 4 * ssh::MAX_PACKET;
            let charge = env.budget().charge(bytes).ok_or(TransportError::State)?;
            self.out = Vec::with_capacity(bytes);
            self.out_charge = Some(charge);
        }
        Ok(())
    }
    fn write(&mut self, env: &Env<'_, Ended>, payload: &[u8]) -> Result<(), TransportError> {
        self.output(env)?;
        if self.out.len() + ssh::MAX_PACKET > self.out.capacity() { return Err(TransportError::State); }
        self.stream.decoder().write_packet(payload, &mut self.out)
    }
    fn send(&mut self, env: &Env<'_, Ended>, message: &impl Wire<WriteError = ssh::Error>) -> Result<(), TransportError> {
        self.write(env, &message.to_bytes()?)
    }
    fn close(&mut self, env: &mut Env<'_, Ended>, reason: Ended) {
        if !self.ended { self.ended = true; self.timers = Timers::new(); env.report(reason); }
    }
    fn disconnect(&mut self, env: &mut Env<'_, Ended>, reason: ssh::DisconnectReason, description: &str) -> Result<(), TransportError> {
        self.output(env)?;
        self.stream.decoder().disconnect(reason, description, &mut self.out)?;
        self.close(env, Ended::Closed);
        Ok(())
    }
    fn id(&self, wire: u32) -> Result<ChildId, TransportError> {
        self.channels.ids().find(|id| self.channels.get(*id).unwrap().wire == wire).ok_or(TransportError::State)
    }
    fn authentication(
        &mut self,
        payload: &[u8],
        env: &mut Env<'_, Ended>,
    ) -> Result<(), TransportError> {
        if !self.service_requested || self.failure.is_some() {
            return Err(TransportError::State);
        }
        self.auth_requests = self.auth_requests.saturating_add(1);
        if self.auth_requests > MAX_AUTH_REQUESTS {
            return Err(TransportError::State);
        }
        let (request, responses) = if payload.first() == Some(&61) {
            let auth::Message::InfoResponse(responses) = auth::Message::parse(payload)? else {
                return Err(TransportError::State);
            };
            self.handler.observe(
                &self.context(env.now()),
                &Event::AuthenticationResponses(responses.clone()),
            );
            let (request, count) = self.challenge.take().ok_or(TransportError::State)?;
            if responses.len() != count {
                return Err(TransportError::State);
            }
            (request, Some(responses))
        } else {
            self.challenge = None;
            (auth::Request::parse(payload)?, None)
        };
        if request.service != "ssh-connection" {
            return Err(TransportError::State);
        }
        if self
            .auth_user
            .as_ref()
            .is_some_and(|user| user != &request.user)
        {
            return Err(TransportError::State);
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
                self.stream.decoder()
                    .session_id()
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
        let decision = self.handler.authenticate(&self.context(env.now()), &attempt);
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
            return Err(TransportError::Crypto);
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
                    return Err(TransportError::State);
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

