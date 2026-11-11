//! Opt-in SSH observation without changing the application's policy.
//!
//! [`Observed`] forwards authentication, configuration and sessions unchanged.
//! It retains no history and opens no files. The world supplies an [`Observer`]
//! and chooses its own bounded storage or streaming log. [`Record`] is an
//! owned, typed copy of a fact that serializes and deserializes.
//! [`Record::redacted`] omits credentials and application bytes;
//! [`Record::new`] explicitly retains those bytes for restricted evidence.

use std::net::SocketAddr;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ConnError;
use fictionet::stdlib::protocols::ssh::{self as protocol, auth, connection};
use fictionet::stdlib::services::ssh::{
    AuthAttempt, AuthDecision, Context, Ended, Event, Handler, Output, SessionRequest,
};
use fictionet::time::Instant;
use serde::{Deserialize, Serialize};

/// A world's observation destination. Calls are synchronous and ordered.
pub trait Observer: Send + Sync + 'static {
    /// Record a typed fact. Implementations should bound retained state.
    fn record(&self, context: &Context<'_>, event: &Event);
}

/// A handler with a caller-owned observation destination.
pub struct Observed<H, O> {
    /// Authentication policy and session factory.
    pub handler: H,
    /// Destination for protocol facts, including credentials and byte streams.
    pub observer: O,
}

impl<H: Handler, O: Observer> Handler for Observed<H, O> {
    type Session = H::Session;

    fn authenticate(&self, context: &Context<'_>, attempt: &AuthAttempt<'_>) -> AuthDecision {
        self.handler.authenticate(context, attempt)
    }

    fn configure(
        &self,
        context: &Context<'_>,
        channel: u32,
        request: &connection::SessionRequest,
    ) -> bool {
        self.handler.configure(context, channel, request)
    }

    fn open(
        &self,
        context: &Context<'_>,
        request: &SessionRequest,
        output: &mut Output,
    ) -> Option<Self::Session> {
        self.handler.open(context, request, output)
    }

    fn observe(&self, context: &Context<'_>, event: &Event) {
        self.observer.record(context, event);
        self.handler.observe(context, event);
    }

    fn direct_tcpip(
        &self,
        context: &Context<'_>,
        channel: u32,
        endpoint: &connection::TcpIp,
        output: &mut Output,
    ) -> Option<Self::Session> {
        self.handler
            .direct_tcpip(context, channel, endpoint, output)
    }

    fn global_request(
        &self,
        context: &Context<'_>,
        request: &connection::GlobalRequest,
    ) -> Option<Vec<u8>> {
        self.handler.global_request(context, request)
    }
}

/// A fact and its connection context, owned and typed.
///
/// [`Record::redacted`] keeps lengths without credentials or application
/// bytes. [`Record::new`] keeps the exact bytes for restricted evidence. Its
/// `wire_payload` fields can be decoded with the corresponding protocol
/// codec; they are reconstructed payloads, not encrypted packets or padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Microseconds from the origin the record was made with.
    pub elapsed_micros: u64,
    /// The connection's number, from whoever accepted it.
    pub connection: Option<u64>,
    /// The world's side of the connection.
    pub local: Option<SocketAddr>,
    /// The client's side.
    pub peer: Option<SocketAddr>,
    /// Whether credentials and application bytes were left out.
    pub redacted: bool,
    /// What happened.
    #[serde(flatten)]
    pub fact: Fact,
}

/// The fact a [`Record`] holds, one per [`Event`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Fact {
    /// The client's identification line.
    Version {
        /// The protocol version, such as `2.0`.
        protocol: String,
        /// The software version.
        software: String,
        /// The comments after the software version.
        comments: Option<String>,
    },
    /// The client's key exchange proposal.
    KexInit {
        /// Key exchange methods.
        kex: Vec<String>,
        /// Host key types.
        host_keys: Vec<String>,
        /// Ciphers from client to server.
        ciphers_client_to_server: Vec<String>,
        /// Ciphers from server to client.
        ciphers_server_to_client: Vec<String>,
        /// MACs from client to server.
        macs_client_to_server: Vec<String>,
        /// MACs from server to client.
        macs_server_to_client: Vec<String>,
        /// Compression from client to server.
        compression_client_to_server: Vec<String>,
        /// Compression from server to client.
        compression_server_to_client: Vec<String>,
        /// The KEXINIT payload's length.
        wire_payload_bytes: usize,
        /// The KEXINIT payload, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wire_payload: Option<Vec<u8>>,
    },
    /// An authentication request.
    Authentication {
        /// The account.
        user: String,
        /// The service asked for.
        service: String,
        /// The method's name.
        method: String,
        /// Whether a signature proved possession of the key.
        signature_verified: bool,
        /// What the method carried.
        #[serde(flatten)]
        credential: Credential,
        /// The request payload, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wire_payload: Option<Vec<u8>>,
    },
    /// Answers to a keyboard-interactive challenge.
    AuthenticationResponses {
        /// Each answer's length.
        response_bytes: Vec<usize>,
        /// The answers, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        responses: Option<Vec<Vec<u8>>>,
    },
    /// Authentication completed.
    Authenticated {
        /// The account.
        user: String,
        /// The method that completed it.
        method: String,
    },
    /// The application's authentication decision.
    AuthenticationDecision {
        /// What it decided.
        #[serde(flatten)]
        decision: Decision,
    },
    /// A connection protocol message.
    Connection {
        /// The message.
        message: Message,
        /// Its payload, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wire_payload: Option<Vec<u8>>,
    },
    /// Input bytes on a channel.
    Input {
        /// The server's channel number.
        channel: u32,
        /// How many bytes.
        data_bytes: usize,
        /// The bytes, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<Vec<u8>>,
    },
    /// Output bytes on a channel.
    Output {
        /// The server's channel number.
        channel: u32,
        /// Whether these are standard error.
        stderr: bool,
        /// How many bytes.
        data_bytes: usize,
        /// The bytes, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<Vec<u8>>,
    },
    /// An exit status sent on a channel.
    Exit {
        /// The server's channel number.
        channel: u32,
        /// The status.
        status: u32,
    },
    /// The connection ended.
    End {
        /// Why.
        reason: EndReason,
    },
}

/// What an authentication method carried. The method's name is in
/// [`Fact::Authentication`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Credential {
    /// A password, or a password change.
    Password {
        /// The password's length.
        password_bytes: usize,
        /// The new password's length, for a change.
        new_password_bytes: Option<usize>,
        /// The password, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<Vec<u8>>,
        /// The new password, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_password: Option<Vec<u8>>,
    },
    /// A public key, with a signature when it is more than a probe.
    PublicKey {
        /// The signature algorithm.
        algorithm: String,
        /// The SSH encoded key.
        key: Vec<u8>,
        /// The key's SHA-256 fingerprint.
        fingerprint_sha256: [u8; 32],
        /// The SSH encoded signature.
        signature: Option<Vec<u8>>,
    },
    /// The start of a keyboard-interactive exchange.
    KeyboardInteractive {
        /// The language preference.
        language: String,
        /// The submethod preferences.
        submethods: String,
    },
    /// A method the server does not interpret.
    Other {
        /// The method's data length.
        data_bytes: usize,
        /// The data, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<Vec<u8>>,
    },
    /// The `none` method.
    None {},
}

/// An authentication decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Authenticated, or a key probe acknowledged.
    Accept,
    /// Refused.
    Reject {
        /// The methods that may follow.
        methods: Vec<String>,
        /// Whether one factor succeeded.
        partial_success: bool,
        /// The delay before the failure response.
        delay_micros: u64,
    },
    /// A keyboard-interactive challenge.
    Challenge {
        /// The challenge's name.
        name: String,
        /// Its instructions.
        instruction: String,
        /// Its prompts, and whether each echoes.
        prompts: Vec<(String, bool)>,
    },
}

/// A connection protocol message, without its application bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Message {
    /// A global request.
    GlobalRequest {
        /// Whether a reply was asked for.
        want_reply: bool,
    },
    /// A global request succeeded.
    RequestSuccess,
    /// A global request failed.
    RequestFailure,
    /// A channel open request.
    ChannelOpen {
        /// The sender's channel number.
        sender: u32,
        /// The initial window.
        window: u32,
        /// The maximum packet size.
        max_packet: u32,
        /// The channel type, such as `session`.
        channel_type: String,
    },
    /// A channel open confirmation.
    ChannelOpenConfirmation {
        /// The recipient channel.
        recipient: u32,
    },
    /// A channel open failure.
    ChannelOpenFailure {
        /// The recipient channel.
        recipient: u32,
    },
    /// A window adjustment.
    WindowAdjust {
        /// The recipient channel.
        recipient: u32,
    },
    /// Channel data.
    Data {
        /// The recipient channel.
        recipient: u32,
        /// How many bytes.
        data_bytes: usize,
    },
    /// Extended channel data.
    ExtendedData {
        /// The recipient channel.
        recipient: u32,
        /// How many bytes.
        data_bytes: usize,
    },
    /// End of a channel's data.
    Eof {
        /// The recipient channel.
        recipient: u32,
    },
    /// A channel close.
    Close {
        /// The recipient channel.
        recipient: u32,
    },
    /// A channel request.
    ChannelRequest {
        /// The recipient channel.
        recipient: u32,
        /// Whether a reply was asked for.
        want_reply: bool,
        /// The request.
        request: Request,
    },
    /// A channel request succeeded.
    ChannelSuccess {
        /// The recipient channel.
        recipient: u32,
    },
    /// A channel request failed.
    ChannelFailure {
        /// The recipient channel.
        recipient: u32,
    },
}

/// A session channel request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// A pseudo-terminal.
    Pty {
        /// The terminal type.
        terminal: String,
        /// Character columns.
        columns: u32,
        /// Character rows.
        rows: u32,
        /// Width in pixels.
        pixel_width: u32,
        /// Height in pixels.
        pixel_height: u32,
        /// Terminal modes, as opcode and value.
        modes: Vec<(u8, u32)>,
    },
    /// A shell.
    Shell,
    /// A command.
    Exec {
        /// The command's length.
        command_bytes: usize,
        /// The command, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<Vec<u8>>,
    },
    /// An environment variable.
    Env {
        /// The variable's name.
        name: Vec<u8>,
        /// The value's length.
        value_bytes: usize,
        /// The value, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<Vec<u8>>,
    },
    /// A subsystem, such as `sftp`.
    Subsystem {
        /// Its name.
        name: String,
    },
    /// A terminal size change.
    WindowChange {
        /// Character columns.
        columns: u32,
        /// Character rows.
        rows: u32,
        /// Width in pixels.
        pixel_width: u32,
        /// Height in pixels.
        pixel_height: u32,
    },
    /// A signal.
    Signal {
        /// Its name without `SIG`.
        signal: String,
    },
    /// An exit status.
    ExitStatus {
        /// The status.
        status: u32,
    },
    /// An exit signal.
    ExitSignal {
        /// Its name without `SIG`.
        signal: String,
        /// Whether a core was dumped.
        core_dumped: bool,
        /// The message.
        message: String,
        /// The message's language.
        language: String,
    },
    /// A request the server does not interpret.
    Other {
        /// The request's name.
        name: String,
        /// Its data length.
        data_bytes: usize,
        /// Its data, unless redacted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<Vec<u8>>,
    },
}

/// Why the connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The client sent everything it will send.
    Eof,
    /// The application or protocol closed the connection.
    Closed,
    /// The packet decoder failed.
    Failed,
    /// The idle deadline expired.
    Idle,
    /// The connection needed more than its memory budget.
    Budget,
    /// The client reset the connection.
    Reset,
    /// TLS or the connection broke.
    Broken,
    /// A read or write timed out.
    TimedOut,
    /// Another connection error.
    Error,
    /// The connection's region was cancelled.
    Cancelled,
}

impl From<Ended> for EndReason {
    fn from(ended: Ended) -> EndReason {
        match ended {
            Ended::Eof => EndReason::Eof,
            Ended::Closed => EndReason::Closed,
            Ended::Failed => EndReason::Failed,
            Ended::Idle => EndReason::Idle,
            Ended::Budget(_) => EndReason::Budget,
            Ended::Conn(ConnError::Reset) => EndReason::Reset,
            Ended::Conn(ConnError::Broken) => EndReason::Broken,
            Ended::Conn(ConnError::TimedOut) => EndReason::TimedOut,
            Ended::Conn(_) => EndReason::Error,
            Ended::Cancelled => EndReason::Cancelled,
        }
    }
}

/// A payload the protocol codec could not write back, so no record was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unwritable;

impl std::fmt::Display for Unwritable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the SSH payload could not be written back")
    }
}

impl std::error::Error for Unwritable {}

impl Record {
    /// `event` with its exact credentials and bytes, for restricted evidence.
    pub fn new(context: &Context<'_>, event: &Event, origin: Instant) -> Result<Self, Unwritable> {
        Self::make(context, event, origin, false)
    }

    /// `event` with lengths and protocol facts, without credentials,
    /// application bytes or reconstructed payloads.
    pub fn redacted(
        context: &Context<'_>,
        event: &Event,
        origin: Instant,
    ) -> Result<Self, Unwritable> {
        Self::make(context, event, origin, true)
    }

    fn make(
        context: &Context<'_>,
        event: &Event,
        origin: Instant,
        redacted: bool,
    ) -> Result<Self, Unwritable> {
        let kept = |bytes: &Vec<u8>| (!redacted).then(|| bytes.clone());
        let fact = match event {
            Event::Version(version) => Fact::Version {
                protocol: version.proto().into(),
                software: version.software().into(),
                comments: version.comments().map(Into::into),
            },
            Event::KexInit(proposal) => {
                let payload = wire(&protocol::Message::KexInit(proposal.clone()))?;
                Fact::KexInit {
                    kex: proposal.kex_algorithms.clone(),
                    host_keys: proposal.server_host_key_algorithms.clone(),
                    ciphers_client_to_server: proposal.encryption_client_to_server.clone(),
                    ciphers_server_to_client: proposal.encryption_server_to_client.clone(),
                    macs_client_to_server: proposal.mac_client_to_server.clone(),
                    macs_server_to_client: proposal.mac_server_to_client.clone(),
                    compression_client_to_server: proposal.compression_client_to_server.clone(),
                    compression_server_to_client: proposal.compression_server_to_client.clone(),
                    wire_payload_bytes: payload.len(),
                    wire_payload: (!redacted).then_some(payload),
                }
            }
            Event::Authentication { request, verified } => Fact::Authentication {
                user: request.user.clone(),
                service: request.service.clone(),
                method: request.method.name().into(),
                signature_verified: *verified,
                credential: match &request.method {
                    auth::Method::Password {
                        password,
                        new_password,
                    } => Credential::Password {
                        password_bytes: password.len(),
                        new_password_bytes: new_password.as_ref().map(Vec::len),
                        password: kept(password),
                        new_password: new_password.as_ref().and_then(kept),
                    },
                    auth::Method::PublicKey {
                        algorithm,
                        key,
                        signature,
                    } => Credential::PublicKey {
                        algorithm: algorithm.clone(),
                        key: key.clone(),
                        fingerprint_sha256: auth::public_key_fingerprint(key),
                        signature: signature.clone(),
                    },
                    auth::Method::KeyboardInteractive {
                        language,
                        submethods,
                    } => Credential::KeyboardInteractive {
                        language: language.clone(),
                        submethods: submethods.clone(),
                    },
                    auth::Method::Other { data, .. } => Credential::Other {
                        data_bytes: data.len(),
                        data: kept(data),
                    },
                    auth::Method::None => Credential::None {},
                },
                wire_payload: (!redacted).then(|| wire(request)).transpose()?,
            },
            Event::AuthenticationResponses(responses) => Fact::AuthenticationResponses {
                response_bytes: responses.iter().map(Vec::len).collect(),
                responses: (!redacted).then(|| responses.clone()),
            },
            Event::Authenticated { user, method } => Fact::Authenticated {
                user: user.clone(),
                method: method.clone(),
            },
            Event::AuthenticationDecision(decision) => Fact::AuthenticationDecision {
                decision: match decision {
                    AuthDecision::Accept => Decision::Accept,
                    AuthDecision::Reject {
                        methods,
                        partial_success,
                        delay,
                    } => Decision::Reject {
                        methods: methods.iter().map(|m| m.name().into()).collect(),
                        partial_success: *partial_success,
                        delay_micros: delay.as_micros().min(u64::MAX.into()) as u64,
                    },
                    AuthDecision::Challenge {
                        name,
                        instruction,
                        prompts,
                    } => Decision::Challenge {
                        name: name.clone(),
                        instruction: instruction.clone(),
                        prompts: prompts.iter().map(|p| (p.text.clone(), p.echo)).collect(),
                    },
                },
            },
            Event::Connection(message) => Fact::Connection {
                message: Message::new(message, redacted),
                wire_payload: (!redacted).then(|| wire(message)).transpose()?,
            },
            Event::Input { channel, data } => Fact::Input {
                channel: *channel,
                data_bytes: data.len(),
                data: kept(data),
            },
            Event::Output {
                channel,
                stderr,
                data,
            } => Fact::Output {
                channel: *channel,
                stderr: *stderr,
                data_bytes: data.len(),
                data: kept(data),
            },
            Event::Exit { channel, status } => Fact::Exit {
                channel: *channel,
                status: *status,
            },
            Event::End(reason) => Fact::End {
                reason: (*reason).into(),
            },
        };
        let elapsed = context
            .now
            .since_start()
            .saturating_sub(origin.since_start());
        Ok(Record {
            elapsed_micros: elapsed.as_micros().min(u64::MAX.into()) as u64,
            connection: context.connection.id,
            local: context.connection.local,
            peer: context.connection.peer,
            redacted,
            fact,
        })
    }
}

impl Message {
    fn new(message: &connection::Message, redacted: bool) -> Message {
        use connection::Message as Wire;
        match message {
            Wire::GlobalRequest { want_reply, .. } => Message::GlobalRequest {
                want_reply: *want_reply,
            },
            Wire::RequestSuccess(_) => Message::RequestSuccess,
            Wire::RequestFailure => Message::RequestFailure,
            Wire::ChannelOpen {
                sender,
                window,
                max_packet,
                kind,
            } => Message::ChannelOpen {
                sender: *sender,
                window: *window,
                max_packet: *max_packet,
                channel_type: match kind {
                    connection::OpenKind::Session => "session",
                    connection::OpenKind::DirectTcpIp(_) => "direct-tcpip",
                    connection::OpenKind::ForwardedTcpIp(_) => "forwarded-tcpip",
                    connection::OpenKind::Other { name, .. } => name,
                }
                .into(),
            },
            Wire::ChannelOpenConfirmation { recipient, .. } => Message::ChannelOpenConfirmation {
                recipient: *recipient,
            },
            Wire::ChannelOpenFailure { recipient, .. } => Message::ChannelOpenFailure {
                recipient: *recipient,
            },
            Wire::WindowAdjust { recipient, .. } => Message::WindowAdjust {
                recipient: *recipient,
            },
            Wire::Data { recipient, data } => Message::Data {
                recipient: *recipient,
                data_bytes: data.len(),
            },
            Wire::ExtendedData {
                recipient, data, ..
            } => Message::ExtendedData {
                recipient: *recipient,
                data_bytes: data.len(),
            },
            Wire::Eof(recipient) => Message::Eof {
                recipient: *recipient,
            },
            Wire::Close(recipient) => Message::Close {
                recipient: *recipient,
            },
            Wire::ChannelRequest {
                recipient,
                want_reply,
                request,
            } => Message::ChannelRequest {
                recipient: *recipient,
                want_reply: *want_reply,
                request: Request::new(request, redacted),
            },
            Wire::ChannelSuccess(recipient) => Message::ChannelSuccess {
                recipient: *recipient,
            },
            Wire::ChannelFailure(recipient) => Message::ChannelFailure {
                recipient: *recipient,
            },
        }
    }
}

impl Request {
    fn new(request: &connection::SessionRequest, redacted: bool) -> Request {
        use connection::SessionRequest;
        let kept = |bytes: &Vec<u8>| (!redacted).then(|| bytes.clone());
        match request {
            SessionRequest::Pty {
                terminal,
                dimensions,
                modes,
            } => Request::Pty {
                terminal: terminal.clone(),
                columns: dimensions.columns,
                rows: dimensions.rows,
                pixel_width: dimensions.pixel_width,
                pixel_height: dimensions.pixel_height,
                modes: modes.iter().map(|m| (m.opcode, m.value)).collect(),
            },
            SessionRequest::Shell => Request::Shell,
            SessionRequest::Exec(command) => Request::Exec {
                command_bytes: command.len(),
                command: kept(command),
            },
            SessionRequest::Env { name, value } => Request::Env {
                name: name.clone(),
                value_bytes: value.len(),
                value: kept(value),
            },
            SessionRequest::Subsystem(name) => Request::Subsystem { name: name.clone() },
            SessionRequest::WindowChange(dimensions) => Request::WindowChange {
                columns: dimensions.columns,
                rows: dimensions.rows,
                pixel_width: dimensions.pixel_width,
                pixel_height: dimensions.pixel_height,
            },
            SessionRequest::Signal(signal) => Request::Signal {
                signal: signal.clone(),
            },
            SessionRequest::ExitStatus(status) => Request::ExitStatus { status: *status },
            SessionRequest::ExitSignal {
                signal,
                core_dumped,
                message,
                language,
            } => Request::ExitSignal {
                signal: signal.clone(),
                core_dumped: *core_dumped,
                message: message.clone(),
                language: language.clone(),
            },
            SessionRequest::Other { name, data } => Request::Other {
                name: name.clone(),
                data_bytes: data.len(),
                data: kept(data),
            },
        }
    }
}

fn wire<W: Wire>(message: &W) -> Result<Vec<u8>, Unwritable> {
    message.to_bytes().map_err(|_| Unwritable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::network::ConnInfo;

    #[test]
    fn redacted_evidence_omits_credentials_and_nested_application_bytes() {
        let connection = ConnInfo::default();
        let context = Context {
            connection: &connection,
            now: Instant::ZERO,
        };
        let secret = b"sensitive command and credential".to_vec();
        let events = [
            Event::Authentication {
                request: auth::Request {
                    user: "guest".into(),
                    service: "ssh-connection".into(),
                    method: auth::Method::Password {
                        password: secret.clone(),
                        new_password: Some(secret.clone()),
                    },
                },
                verified: false,
            },
            Event::AuthenticationResponses(vec![secret.clone()]),
            Event::Input {
                channel: 0,
                data: secret.clone(),
            },
            Event::Output {
                channel: 0,
                stderr: false,
                data: secret.clone(),
            },
            Event::Connection(connection::Message::Data {
                recipient: 0,
                data: secret.clone(),
            }),
            Event::Connection(connection::Message::ChannelRequest {
                recipient: 0,
                want_reply: true,
                request: connection::SessionRequest::Exec(secret.clone()),
            }),
            Event::Connection(connection::Message::ChannelRequest {
                recipient: 0,
                want_reply: true,
                request: connection::SessionRequest::Env {
                    name: b"TOKEN".to_vec(),
                    value: secret.clone(),
                },
            }),
            Event::Connection(connection::Message::ChannelRequest {
                recipient: 0,
                want_reply: true,
                request: connection::SessionRequest::Other {
                    name: "custom".into(),
                    data: secret.clone(),
                },
            }),
        ];
        for event in events {
            let value =
                serde_json::to_value(Record::redacted(&context, &event, Instant::ZERO).unwrap())
                    .unwrap();
            assert_eq!(value["redacted"], true);
            assert!(value.get("wire_payload").is_none());
            assert!(value.get("password").is_none());
            assert!(value.get("new_password").is_none());
            assert!(value.get("responses").is_none());
            assert!(value.get("data").is_none());
            for field in ["command", "value", "data"] {
                assert!(value["message"]["request"].get(field).is_none());
            }
            let length = match event {
                Event::Authentication { .. } => &value["password_bytes"],
                Event::AuthenticationResponses(_) => &value["response_bytes"][0],
                Event::Input { .. } | Event::Output { .. } => &value["data_bytes"],
                Event::Connection(connection::Message::Data { .. }) => {
                    &value["message"]["data_bytes"]
                }
                Event::Connection(connection::Message::ChannelRequest { request, .. }) => {
                    &value["message"]["request"][match request {
                        connection::SessionRequest::Exec(_) => "command_bytes",
                        connection::SessionRequest::Env { .. } => "value_bytes",
                        _ => "data_bytes",
                    }]
                }
                _ => unreachable!(),
            };
            assert_eq!(length, secret.len());
        }
    }

    #[test]
    fn recorded_credentials_round_trip_without_text_loss() {
        let connection = ConnInfo::new(
            7,
            "127.0.0.1:22".parse().unwrap(),
            "127.0.0.2:30000".parse().unwrap(),
        );
        let context = Context {
            connection: &connection,
            now: Instant::ZERO,
        };
        for bytes in [vec![], vec![0, 255, 13, 10], (0..=255).collect()] {
            let request = auth::Request {
                user: "guest".into(),
                service: "ssh-connection".into(),
                method: auth::Method::Password {
                    password: bytes.clone(),
                    new_password: None,
                },
            };
            let event = Event::Authentication {
                request: request.clone(),
                verified: false,
            };
            let value = serde_json::to_value(Record::new(&context, &event, Instant::ZERO).unwrap())
                .unwrap();
            let password: Vec<u8> = serde_json::from_value(value["password"].clone()).unwrap();
            assert_eq!(password, bytes);
            let wire: Vec<u8> = serde_json::from_value(value["wire_payload"].clone()).unwrap();
            assert_eq!(auth::Request::parse(&wire).unwrap(), request);
        }
    }

    #[test]
    fn every_fact_round_trips_through_json_kept_and_redacted() {
        use std::time::Duration;
        let connection = ConnInfo::new(
            3,
            "192.0.2.1:22".parse().unwrap(),
            "198.51.100.7:40000".parse().unwrap(),
        );
        let context = Context {
            connection: &connection,
            now: Instant::from_since_start(Duration::from_micros(250)),
        };
        let bytes = b"bytes".to_vec();
        let channel_request = |request| {
            Event::Connection(connection::Message::ChannelRequest {
                recipient: 1,
                want_reply: false,
                request,
            })
        };
        let authentication = |method| Event::Authentication {
            request: auth::Request {
                user: "root".into(),
                service: "ssh-connection".into(),
                method,
            },
            verified: false,
        };
        let dimensions = connection::Dimensions {
            columns: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        };
        let events = [
            Event::Version(protocol::Identification::new("2.0", "OpenSSH_9.6", None).unwrap()),
            Event::KexInit(protocol::KexInit {
                kex_algorithms: vec!["curve25519-sha256".into()],
                server_host_key_algorithms: vec!["ssh-ed25519".into()],
                encryption_client_to_server: vec!["aes128-ctr".into()],
                encryption_server_to_client: vec!["aes128-ctr".into()],
                mac_client_to_server: vec!["hmac-sha2-256".into()],
                mac_server_to_client: vec!["hmac-sha2-256".into()],
                compression_client_to_server: vec!["none".into()],
                compression_server_to_client: vec!["none".into()],
                ..Default::default()
            }),
            authentication(auth::Method::Password {
                password: bytes.clone(),
                new_password: Some(bytes.clone()),
            }),
            authentication(auth::Method::PublicKey {
                algorithm: "ssh-ed25519".into(),
                key: bytes.clone(),
                signature: None,
            }),
            authentication(auth::Method::KeyboardInteractive {
                language: String::new(),
                submethods: "pam".into(),
            }),
            authentication(auth::Method::Other {
                name: "hostbased".into(),
                data: bytes.clone(),
            }),
            authentication(auth::Method::None),
            Event::AuthenticationResponses(vec![bytes.clone()]),
            Event::AuthenticationDecision(AuthDecision::Accept),
            Event::AuthenticationDecision(AuthDecision::Reject {
                methods: vec![fictionet::stdlib::services::ssh::AuthMethod::Password],
                partial_success: false,
                delay: Duration::from_millis(3),
            }),
            Event::AuthenticationDecision(AuthDecision::Challenge {
                name: "n".into(),
                instruction: "i".into(),
                prompts: vec![auth::Prompt {
                    text: "Password: ".into(),
                    echo: false,
                }],
            }),
            Event::Authenticated {
                user: "root".into(),
                method: "password".into(),
            },
            Event::Connection(connection::Message::ChannelOpen {
                sender: 0,
                window: 1024,
                max_packet: 512,
                kind: connection::OpenKind::Session,
            }),
            Event::Connection(connection::Message::Data {
                recipient: 0,
                data: bytes.clone(),
            }),
            channel_request(connection::SessionRequest::Pty {
                terminal: "xterm".into(),
                dimensions: dimensions.clone(),
                modes: vec![connection::TerminalMode {
                    opcode: 1,
                    value: 3,
                }],
            }),
            channel_request(connection::SessionRequest::Shell),
            channel_request(connection::SessionRequest::Exec(bytes.clone())),
            channel_request(connection::SessionRequest::Env {
                name: b"LANG".to_vec(),
                value: bytes.clone(),
            }),
            channel_request(connection::SessionRequest::WindowChange(dimensions)),
            channel_request(connection::SessionRequest::Other {
                name: "custom".into(),
                data: bytes.clone(),
            }),
            Event::Input {
                channel: 0,
                data: bytes.clone(),
            },
            Event::Output {
                channel: 0,
                stderr: true,
                data: bytes.clone(),
            },
            Event::Exit {
                channel: 0,
                status: 1,
            },
            Event::End(fictionet::stdlib::services::ssh::Ended::Idle),
        ];
        for event in &events {
            for record in [
                Record::new(&context, event, Instant::ZERO).unwrap(),
                Record::redacted(&context, event, Instant::ZERO).unwrap(),
            ] {
                assert_eq!(record.elapsed_micros, 250);
                assert_eq!(record.connection, Some(3));
                let value = serde_json::to_value(&record).unwrap();
                assert_eq!(
                    serde_json::from_value::<Record>(value).unwrap(),
                    record,
                    "{event:?}"
                );
            }
        }
    }
}
