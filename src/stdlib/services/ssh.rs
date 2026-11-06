//! SSH servers over [`serve::connection`], following RFCs 4252, 4253 and 4254.
//!
//! [`Handler`] chooses authentication and starts sessions. [`Session`] consumes
//! input bytes and terminal events; [`Output`] queues stdout, stderr and exit
//! status under a fixed bound, or disconnects the entire connection. Channel
//! windows apply when the queue is sent.
//! The world supplies identity, authentication policy and application behavior.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::serve::{self, ConnInfo, Driver, Flow, Service};
use crate::Cx;
use crate::stdlib::codec::Wire;
use crate::stdlib::protocols::ssh::transport::{
    HostKey, Transport, TransportError, TransportEvent,
};
use crate::stdlib::protocols::ssh::{self, auth, connection as wire};
use crate::stdlib::world::net::{Arrival, PortServer};
use crate::time::Instant;

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

/// A typed fact emitted by the server, before calling application code.
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
    End(serve::Ended),
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
    /// Bytes retained by the application, charged to the connection's budget.
    fn held(&self) -> usize {
        0
    }
}

#[derive(Debug)]
enum Chunk {
    Data {
        stderr: bool,
        data: Vec<u8>,
        offset: usize,
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
            self.bytes += bytes.len();
            self.chunks.push_back(Chunk::Data {
                stderr,
                data: bytes.to_vec(),
                offset: 0,
            });
        }
        Ok(())
    }
    /// Finish output, then send EOF and close after queued bytes drain.
    /// Session channels also send the process exit status; direct TCP streams
    /// have no process status.
    pub fn exit(&mut self, status: u32) {
        if !self.exited {
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

/// A port server that drives SSH through the common service driver.
pub struct Server<H: Handler> {
    /// Protocol configuration.
    pub config: Arc<Config>,
    /// Application policy and session implementation.
    pub handler: Arc<H>,
    /// Connection timeouts and budget.
    pub options: serve::ServeOptions,
    /// Optional listener backlog; `None` uses the network's default.
    pub backlog: Option<usize>,
}
impl<H: Handler> PortServer for Server<H> {
    fn backlog(&self) -> Option<usize> {
        self.backlog
    }

    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut service = Ssh::new(self.config.clone(), self.handler.clone());
        let mut options = self.options.clone();
        if options.budget.is_none() {
            options.budget = arrival.budget;
        }
        options.handshake = arrival.limits.handshake;
        Box::pin(async move {
            let _ = serve::connection(
                &fcx,
                arrival.conn,
                arrival.info,
                &mut service,
                &(),
                &options,
            )
            .await;
        })
    }
}

/// Service timers for authentication and delayed replies.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    /// Authentication deadline.
    Login,
    /// A delayed authentication failure.
    Failure,
}

struct Channel<S> {
    peer: u32,
    window: u32,
    max_packet: u32,
    session_channel: bool,
    pty: Option<Pty>,
    environment: Vec<(Vec<u8>, Vec<u8>)>,
    session: Option<S>,
    output: Output,
    eof: bool,
    closed: bool,
}

/// One SSH connection, usable directly with [`serve::connection`].
pub struct Ssh<H: Handler> {
    config: Arc<Config>,
    handler: Arc<H>,
    user: Option<String>,
    auth_user: Option<String>,
    service_requested: bool,
    attempts: u32,
    auth_requests: u32,
    challenge: Option<(auth::Request, usize)>,
    failure: Option<Vec<u8>>,
    failure_ready: bool,
    pending_packets: VecDeque<(u32, Vec<u8>)>,
    channels: BTreeMap<u32, Channel<H::Session>>,
    next_channel: u32,
}
impl<H: Handler> Ssh<H> {
    /// A fresh connection with shared configuration and application policy.
    pub fn new(config: Arc<Config>, handler: Arc<H>) -> Self {
        Self {
            config,
            handler,
            user: None,
            auth_user: None,
            service_requested: false,
            attempts: 0,
            auth_requests: 0,
            challenge: None,
            failure: None,
            failure_ready: false,
            pending_packets: VecDeque::new(),
            channels: BTreeMap::new(),
            next_channel: 0,
        }
    }
}

type DriverOf<'a> = Driver<'a, Transport, Timer>;

fn context<'a>(driver: &'a DriverOf<'_>) -> Context<'a> {
    Context {
        connection: driver.conn(),
        now: driver.now(),
    }
}
fn write(driver: &mut DriverOf<'_>, payload: &[u8]) -> Result<(), TransportError> {
    let mut bytes = Vec::new();
    driver.decoder().write_packet(payload, &mut bytes)?;
    driver.reply().extend(bytes);
    Ok(())
}
fn send(
    driver: &mut DriverOf<'_>,
    message: &impl Wire<WriteError = ssh::Error>,
) -> Result<(), TransportError> {
    write(driver, &message.to_bytes()?)
}

fn disconnect(
    driver: &mut DriverOf<'_>,
    reason: ssh::DisconnectReason,
    description: &str,
) -> Result<Flow, TransportError> {
    let mut bytes = Vec::new();
    driver
        .decoder()
        .disconnect(reason, description, &mut bytes)?;
    driver.reply().extend(bytes);
    Ok(Flow::Close)
}

impl<H: Handler> Ssh<H> {
    fn finish(&mut self, driver: &mut DriverOf<'_>) -> Result<Flow, TransportError> {
        if self.failure_ready && !driver.peek_decoder().is_rekeying() {
            if let Some(failure) = self.failure.take() {
                write(driver, &failure)?;
            }
            self.failure_ready = false;
        }
        if self.user.is_none()
            && self.failure.is_none()
            && (self.attempts >= self.config.max_attempts
                || self.auth_requests >= MAX_AUTH_REQUESTS)
        {
            return disconnect(
                driver,
                ssh::DisconnectReason::NoMoreAuthMethodsAvailable,
                "Too many authentication failures",
            );
        }
        if self
            .channels
            .values()
            .any(|channel| channel.output.disconnect)
        {
            return disconnect(
                driver,
                ssh::DisconnectReason::ByApplication,
                "Connection closed by application",
            );
        }
        self.flush(driver)?;
        if driver.peek_decoder().needs_rekey() && !driver.peek_decoder().is_rekeying() {
            let mut bytes = Vec::new();
            driver.decoder().rekey(&mut bytes)?;
            driver.reply().extend(bytes);
        }
        Ok(Flow::Continue)
    }

    fn authentication(
        &mut self,
        payload: &[u8],
        driver: &mut DriverOf<'_>,
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
                &context(driver),
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
                send(
                    driver,
                    &auth::Message::Banner {
                        message: message.clone(),
                        language: String::new(),
                    },
                )?;
            }
        }
        let verified = request
            .verify_public_key(
                driver
                    .peek_decoder()
                    .session_id()
                    .ok_or(TransportError::State)?,
                payload,
            )
            .unwrap_or(false);
        self.handler.observe(
            &context(driver),
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
        let decision = self.handler.authenticate(&context(driver), &attempt);
        self.handler.observe(
            &context(driver),
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
                    send(driver, &auth::Message::PublicKeyOk { algorithm, key })?;
                }
            }
            AuthDecision::Accept => {
                send(driver, &auth::Message::Success)?;
                self.user = Some(request.user);
                self.auth_user = None;
                self.challenge = None;
                driver.cancel_timer(Timer::Login);
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
                    write(driver, &failure)?;
                } else {
                    self.failure = Some(failure);
                    self.failure_ready = false;
                    driver.set_timer(Timer::Failure, delay);
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
                send(
                    driver,
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
        driver: &mut DriverOf<'_>,
    ) -> Result<(), TransportError> {
        self.handler
            .observe(&context(driver), &Event::Connection(message.clone()));
        match message {
            wire::Message::GlobalRequest {
                want_reply,
                request,
            } => {
                let response = self
                    .handler
                    .global_request(&context(driver), &request)
                    .filter(|data| data.len() < ssh::MAX_PAYLOAD);
                if want_reply {
                    send(
                        driver,
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
                if self.channels.values().any(|c| c.peer == sender) {
                    return Err(TransportError::State);
                }
                if !matches!(
                    kind,
                    wire::OpenKind::Session | wire::OpenKind::DirectTcpIp(_)
                ) || self.channels.len() >= self.config.max_channels
                    || max_packet == 0
                {
                    send(
                        driver,
                        &wire::Message::ChannelOpenFailure {
                            recipient: sender,
                            reason: 1,
                            description: "Channel refused".into(),
                            language: String::new(),
                        },
                    )?;
                    return Ok(());
                }
                let id = self.next_channel;
                let session_channel = matches!(kind, wire::OpenKind::Session);
                let mut output = Output::default();
                let session = if let wire::OpenKind::DirectTcpIp(endpoint) = &kind {
                    let session =
                        self.handler
                            .direct_tcpip(&context(driver), id, endpoint, &mut output);
                    if session.is_none() {
                        send(
                            driver,
                            &wire::Message::ChannelOpenFailure {
                                recipient: sender,
                                reason: 1,
                                description: "Channel refused".into(),
                                language: String::new(),
                            },
                        )?;
                        return Ok(());
                    }
                    session
                } else {
                    None
                };
                self.next_channel = id.checked_add(1).ok_or(TransportError::State)?;
                self.channels.insert(
                    id,
                    Channel {
                        peer: sender,
                        window,
                        max_packet: max_packet.min(PACKET),
                        session_channel,
                        pty: None,
                        environment: Vec::new(),
                        session,
                        output,
                        eof: false,
                        closed: false,
                    },
                );
                send(
                    driver,
                    &wire::Message::ChannelOpenConfirmation {
                        recipient: sender,
                        sender: id,
                        window: WINDOW,
                        max_packet: PACKET,
                        data: Vec::new(),
                    },
                )?;
            }
            wire::Message::WindowAdjust { recipient, bytes } => {
                let channel = self
                    .channels
                    .get_mut(&recipient)
                    .ok_or(TransportError::State)?;
                channel.window = channel
                    .window
                    .checked_add(bytes)
                    .ok_or(TransportError::State)?;
            }
            wire::Message::Data { recipient, data } => {
                let channel = self
                    .channels
                    .get_mut(&recipient)
                    .ok_or(TransportError::State)?;
                if channel.eof || channel.closed || data.len() > PACKET as usize {
                    return Err(TransportError::State);
                }
                let session = channel.session.as_mut().ok_or(TransportError::State)?;
                self.handler.observe(
                    &context(driver),
                    &Event::Input {
                        channel: recipient,
                        data: data.clone(),
                    },
                );
                session.input(&context(driver), &data, &mut channel.output);
                if !data.is_empty() {
                    send(
                        driver,
                        &wire::Message::WindowAdjust {
                            recipient: channel.peer,
                            bytes: data.len() as u32,
                        },
                    )?;
                }
            }
            wire::Message::ChannelRequest {
                recipient,
                want_reply,
                request,
            } => {
                let channel = self
                    .channels
                    .get_mut(&recipient)
                    .ok_or(TransportError::State)?;
                if channel.closed {
                    return Err(TransportError::State);
                }
                if !channel.session_channel {
                    if want_reply {
                        send(driver, &wire::Message::ChannelFailure(channel.peer))?;
                    }
                    return Ok(());
                }
                let accepted = match request {
                    wire::SessionRequest::Pty {
                        ref terminal,
                        ref dimensions,
                        ref modes,
                    } if channel.session.is_none() && channel.pty.is_none() => {
                        let accepted =
                            self.handler
                                .configure(&context(driver), recipient, &request);
                        if accepted {
                            channel.pty = Some(Pty {
                                terminal: terminal.clone(),
                                columns: dimensions.columns,
                                rows: dimensions.rows,
                                pixel_width: dimensions.pixel_width,
                                pixel_height: dimensions.pixel_height,
                                modes: modes.clone(),
                            });
                        }
                        accepted
                    }
                    wire::SessionRequest::Env {
                        ref name,
                        ref value,
                    } if channel.session.is_none() && channel.environment.len() < 32 => {
                        let held: usize = channel
                            .environment
                            .iter()
                            .map(|(n, v)| n.len() + v.len())
                            .sum();
                        let accepted = held + name.len() + value.len() <= 8192
                            && self
                                .handler
                                .configure(&context(driver), recipient, &request);
                        if accepted {
                            channel.environment.push((name.clone(), value.clone()));
                        }
                        accepted
                    }
                    wire::SessionRequest::Shell
                    | wire::SessionRequest::Exec(_)
                    | wire::SessionRequest::Subsystem(_)
                        if channel.session.is_none() =>
                    {
                        let program = match request {
                            wire::SessionRequest::Shell => Program::Shell,
                            wire::SessionRequest::Exec(c) => Program::Exec(c),
                            wire::SessionRequest::Subsystem(n) => Program::Subsystem(n),
                            _ => unreachable!(),
                        };
                        let request = SessionRequest {
                            user: self.user.clone().ok_or(TransportError::State)?,
                            channel: recipient,
                            program,
                            pty: channel.pty.clone(),
                            environment: channel.environment.clone(),
                        };
                        channel.session =
                            self.handler
                                .open(&context(driver), &request, &mut channel.output);
                        if let Some(session) = &mut channel.session {
                            if channel.eof {
                                session.event(
                                    &context(driver),
                                    &SessionEvent::Eof,
                                    &mut channel.output,
                                );
                            }
                        } else {
                            channel.output = Output::default();
                        }
                        channel.session.is_some()
                    }
                    wire::SessionRequest::WindowChange(dimensions) if channel.pty.is_some() => {
                        if let Some(pty) = &mut channel.pty {
                            pty.columns = dimensions.columns;
                            pty.rows = dimensions.rows;
                            pty.pixel_width = dimensions.pixel_width;
                            pty.pixel_height = dimensions.pixel_height;
                        }
                        if let Some(session) = &mut channel.session {
                            session.event(
                                &context(driver),
                                &SessionEvent::WindowChange {
                                    columns: dimensions.columns,
                                    rows: dimensions.rows,
                                    pixel_width: dimensions.pixel_width,
                                    pixel_height: dimensions.pixel_height,
                                },
                                &mut channel.output,
                            );
                        }
                        true
                    }
                    wire::SessionRequest::Signal(signal) if channel.session.is_some() => {
                        channel.session.as_mut().unwrap().event(
                            &context(driver),
                            &SessionEvent::Signal(signal),
                            &mut channel.output,
                        );
                        true
                    }
                    _ => false,
                };
                if want_reply {
                    send(
                        driver,
                        &if accepted {
                            wire::Message::ChannelSuccess(channel.peer)
                        } else {
                            wire::Message::ChannelFailure(channel.peer)
                        },
                    )?;
                }
            }
            wire::Message::Eof(id) => {
                let channel = self.channels.get_mut(&id).ok_or(TransportError::State)?;
                if channel.eof {
                    return Err(TransportError::State);
                }
                channel.eof = true;
                if let Some(session) = &mut channel.session {
                    session.event(&context(driver), &SessionEvent::Eof, &mut channel.output);
                }
            }
            wire::Message::Close(id) => {
                let mut channel = self.channels.remove(&id).ok_or(TransportError::State)?;
                if let Some(session) = &mut channel.session {
                    session.event(&context(driver), &SessionEvent::Closed, &mut channel.output);
                }
                if !channel.closed {
                    send(driver, &wire::Message::Close(channel.peer))?;
                }
            }
            _ => return Err(TransportError::State),
        }
        Ok(())
    }

    fn flush(&mut self, driver: &mut DriverOf<'_>) -> Result<(), TransportError> {
        if driver.peek_decoder().is_rekeying() {
            return Ok(());
        }
        let mut packets = 0;
        for (&id, channel) in &mut self.channels {
            while let Some(chunk) = channel.output.chunks.front_mut() {
                if packets >= 64 {
                    driver.wake_handle().wake();
                    return Ok(());
                }
                match chunk {
                    Chunk::Data {
                        stderr,
                        data,
                        offset,
                    } => {
                        let n = (data.len() - *offset)
                            .min(channel.window as usize)
                            .min(channel.max_packet as usize);
                        if n == 0 {
                            break;
                        }
                        let bytes = data[*offset..*offset + n].to_vec();
                        let message = if *stderr {
                            wire::Message::ExtendedData {
                                recipient: channel.peer,
                                kind: 1,
                                data: bytes.clone(),
                            }
                        } else {
                            wire::Message::Data {
                                recipient: channel.peer,
                                data: bytes.clone(),
                            }
                        };
                        send(driver, &message)?;
                        packets += 1;
                        self.handler.observe(
                            &context(driver),
                            &Event::Output {
                                channel: id,
                                stderr: *stderr,
                                data: bytes,
                            },
                        );
                        *offset += n;
                        channel.window -= n as u32;
                        channel.output.bytes -= n;
                        if *offset < data.len() {
                            continue;
                        }
                    }
                    Chunk::Exit(status) => {
                        if channel.session_channel {
                            send(
                                driver,
                                &wire::Message::ChannelRequest {
                                    recipient: channel.peer,
                                    want_reply: false,
                                    request: wire::SessionRequest::ExitStatus(*status),
                                },
                            )?;
                            self.handler.observe(
                                &context(driver),
                                &Event::Exit {
                                    channel: id,
                                    status: *status,
                                },
                            );
                            packets += 1;
                        }
                        send(driver, &wire::Message::Eof(channel.peer))?;
                        send(driver, &wire::Message::Close(channel.peer))?;
                        channel.closed = true;
                        packets += 2;
                    }
                }
                channel.output.chunks.pop_front();
            }
        }
        Ok(())
    }
}

impl<H: Handler> Service for Ssh<H> {
    type Timer = Timer;
    type Decoder = Transport;
    type State = ();
    type Error = TransportError;
    fn decoder(&self) -> Transport {
        Transport::new(
            self.config.host_key.clone(),
            self.config.identification.clone(),
        )
    }
    fn on_open(&mut self, _: &(), driver: &mut DriverOf<'_>) -> Result<Flow, TransportError> {
        let mut seed = [0; 32];
        driver.entropy().fill_random(&mut seed);
        driver.decoder().seed(seed)?;
        if let Some(proposal) = &self.config.proposal {
            driver.decoder().set_proposal(proposal.clone())?;
        }
        let mut bytes = Vec::new();
        driver.decoder().start(&mut bytes)?;
        driver.reply().extend(bytes);
        driver.set_timer(Timer::Login, self.config.login_grace);
        Ok(Flow::Continue)
    }
    fn on_item(
        &mut self,
        event: TransportEvent,
        _: &(),
        driver: &mut DriverOf<'_>,
    ) -> Result<Flow, TransportError> {
        match &event {
            TransportEvent::Version(version) => self
                .handler
                .observe(&context(driver), &Event::Version(version.clone())),
            TransportEvent::Packet { payload, .. } if payload.first() == Some(&20) => {
                if let ssh::Message::KexInit(proposal) = ssh::Message::parse(payload)? {
                    self.handler
                        .observe(&context(driver), &Event::KexInit(proposal));
                }
            }
            _ => {}
        }
        let sequence = match &event {
            TransportEvent::Packet { sequence, .. } => *sequence,
            _ => 0,
        };
        let mut bytes = Vec::new();
        let payload = driver.decoder().handle(event, &mut bytes)?;
        driver.reply().extend(bytes);
        if let Some(payload) = payload {
            if payload.first() == Some(&1) {
                return Ok(Flow::Close);
            }
            let held: usize = self
                .pending_packets
                .iter()
                .map(|(_, bytes)| bytes.len())
                .sum();
            if self.pending_packets.len() >= 128 || held + payload.len() > OUTPUT_LIMIT {
                return Err(TransportError::State);
            }
            self.pending_packets.push_back((sequence, payload));
        }
        if self.failure_ready && !driver.peek_decoder().is_rekeying() {
            if let Some(failure) = self.failure.take() {
                write(driver, &failure)?;
            }
            self.failure_ready = false;
        }
        while !driver.peek_decoder().is_rekeying()
            && !self
                .channels
                .values()
                .any(|channel| channel.output.disconnect)
        {
            let Some((sequence, payload)) = self.pending_packets.pop_front() else {
                break;
            };
            if self.user.is_none()
                && (self.attempts >= self.config.max_attempts
                    || self.auth_requests >= MAX_AUTH_REQUESTS)
            {
                return disconnect(
                    driver,
                    ssh::DisconnectReason::NoMoreAuthMethodsAvailable,
                    "Too many authentication failures",
                );
            }
            match payload.first().copied().ok_or(TransportError::State)? {
                5 if self.user.is_none() && !self.service_requested => {
                    let ssh::Message::ServiceRequest(service) = ssh::Message::parse(&payload)?
                    else {
                        return Err(TransportError::State);
                    };
                    if service != "ssh-userauth" {
                        return Err(TransportError::State);
                    }
                    send(driver, &ssh::Message::ServiceAccept(service))?;
                    self.service_requested = true;
                }
                50 | 61 if self.user.is_none() => self.authentication(&payload, driver)?,
                50 if self.user.is_some() => {}
                80..=82 | 90..=100 if self.user.is_some() => {
                    self.connection_message(wire::Message::parse(&payload)?, driver)?
                }
                _ => send(driver, &ssh::Message::Unimplemented(sequence))?,
            }
        }
        self.finish(driver)
    }
    fn on_timer(
        &mut self,
        timer: Timer,
        _: &(),
        driver: &mut DriverOf<'_>,
    ) -> Result<Flow, TransportError> {
        match timer {
            Timer::Login => disconnect(
                driver,
                ssh::DisconnectReason::ByApplication,
                "Login grace time exceeded",
            ),
            Timer::Failure => {
                self.failure_ready = true;
                self.finish(driver)
            }
        }
    }
    fn on_wake(&mut self, _: &(), driver: &mut DriverOf<'_>) -> Result<Flow, TransportError> {
        self.finish(driver)
    }
    fn on_fail(
        &mut self,
        _: &crate::stdlib::codec::Fail<TransportError>,
        _: &(),
        driver: &mut DriverOf<'_>,
    ) -> Result<(), TransportError> {
        disconnect(
            driver,
            ssh::DisconnectReason::ProtocolError,
            "Invalid SSH packet",
        )?;
        Ok(())
    }
    fn on_end(
        &mut self,
        end: serve::Ended,
        _: &(),
        driver: &mut DriverOf<'_>,
    ) -> Result<(), TransportError> {
        for channel in self.channels.values_mut() {
            if let Some(session) = &mut channel.session {
                session.event(&context(driver), &SessionEvent::Closed, &mut channel.output);
            }
        }
        self.handler.observe(&context(driver), &Event::End(end));
        Ok(())
    }
    fn held(&self) -> usize {
        self.channels
            .values()
            .map(|c| {
                std::mem::size_of_val(c)
                    + c.output.chunks.capacity() * std::mem::size_of::<Chunk>()
                    + c.output
                        .chunks
                        .iter()
                        .map(|chunk| match chunk {
                            Chunk::Data { data, .. } => data.capacity(),
                            Chunk::Exit(_) => 0,
                        })
                        .sum::<usize>()
                    + c.pty.as_ref().map_or(0, |pty| {
                        pty.terminal.capacity()
                            + pty.modes.capacity() * std::mem::size_of::<wire::TerminalMode>()
                    })
                    + c.environment.capacity() * std::mem::size_of::<(Vec<u8>, Vec<u8>)>()
                    + c.environment
                        .iter()
                        .map(|(n, v)| n.capacity() + v.capacity())
                        .sum::<usize>()
                    + c.session.as_ref().map_or(0, Session::held)
            })
            .sum::<usize>()
            + self.failure.as_ref().map_or(0, Vec::capacity)
            + self.user.as_ref().map_or(0, String::capacity)
            + self.auth_user.as_ref().map_or(0, String::capacity)
            + self.challenge.as_ref().map_or(0, |(request, _)| {
                request.user.capacity()
                    + request.service.capacity()
                    + match &request.method {
                        auth::Method::KeyboardInteractive {
                            language,
                            submethods,
                        } => language.capacity() + submethods.capacity(),
                        _ => 0,
                    }
            })
            + self.pending_packets.capacity() * std::mem::size_of::<(u32, Vec<u8>)>()
            + self
                .pending_packets
                .iter()
                .map(|(_, bytes)| bytes.capacity())
                .sum::<usize>()
    }
}
