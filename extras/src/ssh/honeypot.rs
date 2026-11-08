//! Opt-in SSH observation without changing the application's policy.
//!
//! [`Observed`] forwards authentication, configuration and sessions unchanged.
//! It retains no history and opens no files. The world supplies an [`Observer`]
//! and chooses its own bounded storage or streaming log. [`Record`] serializes
//! typed facts. [`Record::redacted`] omits credentials and application bytes;
//! [`Record::new`] explicitly retains those bytes for restricted evidence.

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::ssh::{self as protocol, auth, connection};
use fictionet::stdlib::services::ssh::{
    AuthAttempt, AuthDecision, Context, Event, Handler, Output, SessionRequest,
};
use fictionet::time::Instant;
use serde::Serialize;
use serde::ser::{Error, SerializeMap, Serializer};

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

/// A serializable view of a fact and its connection context.
///
/// [`Record::redacted`] preserves lengths without credentials or application
/// bytes. [`Record::new`] preserves exact byte arrays for restricted evidence.
/// Its `wire_payload` fields can be decoded with the corresponding protocol
/// codec; they are reconstructed payloads, not encrypted packets or padding.
pub struct Record<'a> {
    context: &'a Context<'a>,
    event: &'a Event,
    origin: Instant,
    redacted: bool,
}

impl<'a> Record<'a> {
    /// Borrow a fact with exact credentials and bytes for restricted evidence.
    pub fn new(context: &'a Context<'a>, event: &'a Event, origin: Instant) -> Self {
        Self {
            context,
            event,
            origin,
            redacted: false,
        }
    }

    /// Preserve lengths and protocol facts without credentials or application bytes.
    /// Reconstructed authentication and connection payloads are omitted too.
    pub fn redacted(context: &'a Context<'a>, event: &'a Event, origin: Instant) -> Self {
        Self {
            context,
            event,
            origin,
            redacted: true,
        }
    }
}

impl Serialize for Record<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer.serialize_map(None)?;
        let elapsed = self
            .context
            .now
            .since_start()
            .saturating_sub(self.origin.since_start());
        record.serialize_entry("elapsed_micros", &elapsed.as_micros())?;
        record.serialize_entry("connection", &self.context.connection.id)?;
        record.serialize_entry("local", &self.context.connection.local)?;
        record.serialize_entry("peer", &self.context.connection.peer)?;
        record.serialize_entry("redacted", &self.redacted)?;
        match self.event {
            Event::Version(version) => {
                record.serialize_entry("event", "version")?;
                record.serialize_entry("protocol", version.proto())?;
                record.serialize_entry("software", version.software())?;
                record.serialize_entry("comments", &version.comments())?;
            }
            Event::KexInit(proposal) => {
                record.serialize_entry("event", "kex_init")?;
                record.serialize_entry("kex", &proposal.kex_algorithms)?;
                record.serialize_entry("host_keys", &proposal.server_host_key_algorithms)?;
                record.serialize_entry(
                    "ciphers_client_to_server",
                    &proposal.encryption_client_to_server,
                )?;
                record.serialize_entry(
                    "ciphers_server_to_client",
                    &proposal.encryption_server_to_client,
                )?;
                record.serialize_entry("macs_client_to_server", &proposal.mac_client_to_server)?;
                record.serialize_entry("macs_server_to_client", &proposal.mac_server_to_client)?;
                record.serialize_entry(
                    "compression_client_to_server",
                    &proposal.compression_client_to_server,
                )?;
                record.serialize_entry(
                    "compression_server_to_client",
                    &proposal.compression_server_to_client,
                )?;
                record.serialize_entry(
                    "wire_payload",
                    &wire_bytes::<S, _>(&protocol::Message::KexInit(proposal.clone()))?,
                )?;
            }
            Event::Authentication { request, verified } => {
                record.serialize_entry("event", "authentication")?;
                record.serialize_entry("user", &request.user)?;
                record.serialize_entry("service", &request.service)?;
                record.serialize_entry("method", request.method.name())?;
                record.serialize_entry("signature_verified", verified)?;
                match &request.method {
                    auth::Method::Password {
                        password,
                        new_password,
                    } => {
                        record.serialize_entry("password_bytes", &password.len())?;
                        record.serialize_entry(
                            "new_password_bytes",
                            &new_password.as_ref().map(Vec::len),
                        )?;
                        if !self.redacted {
                            record.serialize_entry("password", password)?;
                            record.serialize_entry("new_password", new_password)?;
                        }
                    }
                    auth::Method::PublicKey {
                        algorithm,
                        key,
                        signature,
                    } => {
                        record.serialize_entry("algorithm", algorithm)?;
                        record.serialize_entry("key", key)?;
                        record.serialize_entry(
                            "fingerprint_sha256",
                            &auth::public_key_fingerprint(key),
                        )?;
                        record.serialize_entry("signature", signature)?;
                    }
                    auth::Method::KeyboardInteractive {
                        language,
                        submethods,
                    } => {
                        record.serialize_entry("language", language)?;
                        record.serialize_entry("submethods", submethods)?;
                    }
                    auth::Method::Other { data, .. } => {
                        record.serialize_entry("data_bytes", &data.len())?;
                        if !self.redacted {
                            record.serialize_entry("data", data)?;
                        }
                    }
                    auth::Method::None => {}
                }
                if !self.redacted {
                    record.serialize_entry("wire_payload", &wire_bytes::<S, _>(request)?)?;
                }
            }
            Event::AuthenticationResponses(responses) => {
                record.serialize_entry("event", "authentication_responses")?;
                record.serialize_entry(
                    "response_bytes",
                    &responses.iter().map(Vec::len).collect::<Vec<_>>(),
                )?;
                if !self.redacted {
                    record.serialize_entry("responses", responses)?;
                }
            }
            Event::Authenticated { user, method } => {
                record.serialize_entry("event", "authenticated")?;
                record.serialize_entry("user", user)?;
                record.serialize_entry("method", method)?;
            }
            Event::AuthenticationDecision(decision) => {
                record.serialize_entry("event", "authentication_decision")?;
                match decision {
                    AuthDecision::Accept => record.serialize_entry("decision", "accept")?,
                    AuthDecision::Reject {
                        methods,
                        partial_success,
                        delay,
                    } => {
                        record.serialize_entry("decision", "reject")?;
                        record.serialize_entry(
                            "methods",
                            &methods.iter().map(|m| m.name()).collect::<Vec<_>>(),
                        )?;
                        record.serialize_entry("partial_success", partial_success)?;
                        record.serialize_entry("delay_micros", &delay.as_micros())?;
                    }
                    AuthDecision::Challenge {
                        name,
                        instruction,
                        prompts,
                    } => {
                        record.serialize_entry("decision", "challenge")?;
                        record.serialize_entry("name", name)?;
                        record.serialize_entry("instruction", instruction)?;
                        record.serialize_entry(
                            "prompts",
                            &prompts
                                .iter()
                                .map(|p| (&p.text, p.echo))
                                .collect::<Vec<_>>(),
                        )?;
                    }
                }
            }
            Event::Connection(message) => {
                record.serialize_entry("event", "connection")?;
                record.serialize_entry("message", &ConnectionRecord(message, self.redacted))?;
                if !self.redacted {
                    record.serialize_entry("wire_payload", &wire_bytes::<S, _>(message)?)?;
                }
            }
            Event::Input { channel, data } => {
                record.serialize_entry("event", "input")?;
                record.serialize_entry("channel", channel)?;
                record.serialize_entry("data_bytes", &data.len())?;
                if !self.redacted {
                    record.serialize_entry("data", data)?;
                }
            }
            Event::Output {
                channel,
                stderr,
                data,
            } => {
                record.serialize_entry("event", "output")?;
                record.serialize_entry("channel", channel)?;
                record.serialize_entry("stderr", stderr)?;
                record.serialize_entry("data_bytes", &data.len())?;
                if !self.redacted {
                    record.serialize_entry("data", data)?;
                }
            }
            Event::Exit { channel, status } => {
                record.serialize_entry("event", "exit")?;
                record.serialize_entry("channel", channel)?;
                record.serialize_entry("status", status)?;
            }
            Event::End(reason) => {
                record.serialize_entry("event", "end")?;
                record.serialize_entry("reason", reason.as_str())?;
            }
        }
        record.end()
    }
}

fn wire_bytes<S: Serializer, W: Wire>(wire: &W) -> Result<Vec<u8>, S::Error>
where
    W::WriteError: std::fmt::Display,
{
    wire.to_bytes().map_err(S::Error::custom)
}

struct ConnectionRecord<'a>(&'a connection::Message, bool);

impl Serialize for ConnectionRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use connection::Message;
        let mut record = serializer.serialize_map(None)?;
        let kind = match self.0 {
            Message::GlobalRequest { .. } => "global_request",
            Message::RequestSuccess(_) => "request_success",
            Message::RequestFailure => "request_failure",
            Message::ChannelOpen { .. } => "channel_open",
            Message::ChannelOpenConfirmation { .. } => "channel_open_confirmation",
            Message::ChannelOpenFailure { .. } => "channel_open_failure",
            Message::WindowAdjust { .. } => "window_adjust",
            Message::Data { .. } => "data",
            Message::ExtendedData { .. } => "extended_data",
            Message::Eof(_) => "eof",
            Message::Close(_) => "close",
            Message::ChannelRequest { .. } => "channel_request",
            Message::ChannelSuccess(_) => "channel_success",
            Message::ChannelFailure(_) => "channel_failure",
        };
        record.serialize_entry("kind", kind)?;
        match self.0 {
            Message::ChannelOpen {
                sender,
                window,
                max_packet,
                kind,
            } => {
                record.serialize_entry("sender", sender)?;
                record.serialize_entry("window", window)?;
                record.serialize_entry("max_packet", max_packet)?;
                let name = match kind {
                    connection::OpenKind::Session => "session",
                    connection::OpenKind::DirectTcpIp(_) => "direct-tcpip",
                    connection::OpenKind::ForwardedTcpIp(_) => "forwarded-tcpip",
                    connection::OpenKind::Other { name, .. } => name,
                };
                record.serialize_entry("channel_type", name)?;
            }
            Message::ChannelRequest {
                recipient,
                want_reply,
                request,
            } => {
                record.serialize_entry("recipient", recipient)?;
                record.serialize_entry("want_reply", want_reply)?;
                record.serialize_entry("request", &SessionRecord(request, self.1))?;
            }
            Message::Data { recipient, data }
            | Message::ExtendedData {
                recipient, data, ..
            } => {
                record.serialize_entry("recipient", recipient)?;
                record.serialize_entry("data_bytes", &data.len())?;
            }
            Message::ChannelOpenConfirmation { recipient, .. }
            | Message::ChannelOpenFailure { recipient, .. }
            | Message::WindowAdjust { recipient, .. }
            | Message::Eof(recipient)
            | Message::Close(recipient)
            | Message::ChannelSuccess(recipient)
            | Message::ChannelFailure(recipient) => {
                record.serialize_entry("recipient", recipient)?;
            }
            Message::GlobalRequest { want_reply, .. } => {
                record.serialize_entry("want_reply", want_reply)?
            }
            Message::RequestSuccess(_) | Message::RequestFailure => {}
        }
        record.end()
    }
}

struct SessionRecord<'a>(&'a connection::SessionRequest, bool);

impl Serialize for SessionRecord<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use connection::SessionRequest;
        let mut record = serializer.serialize_map(None)?;
        let kind = match self.0 {
            SessionRequest::Pty { .. } => "pty",
            SessionRequest::Shell => "shell",
            SessionRequest::Exec(_) => "exec",
            SessionRequest::Env { .. } => "env",
            SessionRequest::Subsystem(_) => "subsystem",
            SessionRequest::WindowChange(_) => "window_change",
            SessionRequest::Signal(_) => "signal",
            SessionRequest::ExitStatus(_) => "exit_status",
            SessionRequest::ExitSignal { .. } => "exit_signal",
            SessionRequest::Other { name, .. } => name,
        };
        record.serialize_entry("kind", kind)?;
        match self.0 {
            SessionRequest::Pty {
                terminal,
                dimensions,
                modes,
            } => {
                record.serialize_entry("terminal", terminal)?;
                dimensions_fields(&mut record, dimensions)?;
                record.serialize_entry(
                    "modes",
                    &modes
                        .iter()
                        .map(|m| (m.opcode, m.value))
                        .collect::<Vec<_>>(),
                )?;
            }
            SessionRequest::WindowChange(dimensions) => dimensions_fields(&mut record, dimensions)?,
            SessionRequest::Exec(command) => {
                record.serialize_entry("command_bytes", &command.len())?;
                if !self.1 {
                    record.serialize_entry("command", command)?;
                }
            }
            SessionRequest::Env { name, value } => {
                record.serialize_entry("name", name)?;
                record.serialize_entry("value_bytes", &value.len())?;
                if !self.1 {
                    record.serialize_entry("value", value)?;
                }
            }
            SessionRequest::Subsystem(name) => record.serialize_entry("name", name)?,
            SessionRequest::Signal(signal) => record.serialize_entry("signal", signal)?,
            SessionRequest::ExitStatus(status) => record.serialize_entry("status", status)?,
            SessionRequest::ExitSignal {
                signal,
                core_dumped,
                message,
                language,
            } => {
                record.serialize_entry("signal", signal)?;
                record.serialize_entry("core_dumped", core_dumped)?;
                record.serialize_entry("message", message)?;
                record.serialize_entry("language", language)?;
            }
            SessionRequest::Other { data, .. } => {
                record.serialize_entry("data_bytes", &data.len())?;
                if !self.1 {
                    record.serialize_entry("data", data)?;
                }
            }
            SessionRequest::Shell => {}
        }
        record.end()
    }
}

fn dimensions_fields<M: SerializeMap>(
    map: &mut M,
    dimensions: &connection::Dimensions,
) -> Result<(), M::Error> {
    map.serialize_entry("columns", &dimensions.columns)?;
    map.serialize_entry("rows", &dimensions.rows)?;
    map.serialize_entry("pixel_width", &dimensions.pixel_width)?;
    map.serialize_entry("pixel_height", &dimensions.pixel_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::services::serve::ConnInfo;

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
                serde_json::to_value(Record::redacted(&context, &event, Instant::ZERO)).unwrap();
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
            let value = serde_json::to_value(Record::new(&context, &event, Instant::ZERO)).unwrap();
            let password: Vec<u8> = serde_json::from_value(value["password"].clone()).unwrap();
            assert_eq!(password, bytes);
            let wire: Vec<u8> = serde_json::from_value(value["wire_payload"].clone()).unwrap();
            assert_eq!(auth::Request::parse(&wire).unwrap(), request);
        }
    }
}
