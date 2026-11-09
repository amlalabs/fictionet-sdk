//! An independently owned TLS layer with small outgoing records.
//! Copied from the stdlib layer and built using only public SDK contracts.

use std::future::Future;
use std::io::{self, BufRead, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::ServerConfig;
use rustls::server::{Accepted, AcceptedAlert, Acceptor, ServerConnection};

use fictionet::Cx;
use fictionet::stdlib::layer::{
    Admit, ByteStream, Charge, Chunk, Env, Layer, StreamCommand, StreamEvent, Timers,
};
use fictionet::stdlib::services::stack::Job;
use fictionet::stdlib::services::tls::{Handshake, HandshakeError, Negotiation};
use fictionet::time::Instant;

const CHUNK: usize = 16 * 1024;
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
/// The budget covers this adapter's hello snapshot and transferred byte
/// buffers. Rustls owns its protocol and cryptographic allocations separately;
/// its buffer limits and read readiness bound streaming input and output, but
/// are not a byte-exact heap limit for handshake state or user configurations.
pub struct TlsLayer {
    acceptor: Option<Acceptor>,
    accepted: Option<Accepted>,
    tls: Option<ServerConnection>,
    hello: Option<Arc<Hello>>,
    select: Select,
    work: bool,
    deadline: Timers<()>,
    initialized: bool,
    output_reserve: Option<Charge>,
    alert: Option<AcceptedAlert>,
    reject: bool,
    first_byte: Option<u8>,
    failure: Option<HandshakeError>,
    failed: bool,
    input_ended: bool,
    ended: bool,
    closing: bool,
    end_sent: bool,
    reset: bool,
    reset_sent: bool,
    below: Option<StreamCommand>,
    above: Option<StreamEvent>,
    produced: u64,
    delivered: u64,
    pending_plaintext: usize,
    fence: Option<u64>,
    credit: u64,
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
            tls: None,
            hello: None,
            select,
            work: false,
            deadline: Timers::new(),
            initialized: false,
            output_reserve: None,
            alert: None,
            reject: false,
            first_byte: None,
            failure: None,
            failed: false,
            input_ended: false,
            ended: false,
            closing: false,
            end_sent: false,
            reset: false,
            reset_sent: false,
            below: None,
            above: None,
            produced: 0,
            delivered: 0,
            pending_plaintext: 0,
            fence: None,
            credit: 0,
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
            || self.produced != self.delivered
            || self.alert.is_some()
            || self.reject
            || self.tls.as_ref().is_some_and(|tls| tls.wants_write())
    }

    fn fail(&mut self, error: HandshakeError) {
        if !self.failed {
            self.failure = Some(error);
            self.failed = true;
            self.closing = true;
        }
    }

    fn protocol_error(error: rustls::Error) -> HandshakeError {
        match error {
            rustls::Error::AlertReceived(alert) => HandshakeError::Alert(u8::from(alert)),
            error => HandshakeError::Failed(error.to_string()),
        }
    }

    fn process(&mut self) {
        if let Some(tls) = self.tls.as_mut()
            && let Err(error) = tls.process_new_packets()
        {
            self.fail(Self::protocol_error(error));
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
        self.tls = None;
        self.hello = None;
        self.alert = None;
        self.reject = false;
        self.failure = None;
        self.output_reserve = None;
        self.delivered = self.produced;
        self.pending_plaintext = 0;
        self.fence = None;
        self.credit = 0;
    }

    fn reserve_output(&mut self, env: &Env<'_, ()>) -> bool {
        if self.output_reserve.is_none() {
            self.output_reserve = env.budget().charge(CHUNK);
        }
        self.output_reserve.is_some()
    }

    fn credit_written(&mut self) {
        if self.fence.is_some_and(|fence| self.delivered >= fence) {
            self.credit += self.pending_plaintext as u64;
            self.pending_plaintext = 0;
            self.fence = None;
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
                if n > self.produced - self.delivered {
                    return Err(HandshakeError::Failed(
                        "TLS output completed more than once".into(),
                    ));
                }
                self.delivered += n;
                self.credit_written();
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
                if let Some(tls) = self.tls.as_mut()
                    && tls
                        .reader()
                        .into_first_chunk()
                        .is_ok_and(|bytes| !bytes.is_empty())
                {
                    return Ok(Admit::Blocked(StreamEvent::Ended));
                }
                self.input_ended = true;
                if self.is_handshaking() {
                    self.fail(HandshakeError::Closed);
                } else if let Some(tls) = self.tls.as_mut() {
                    match tls.read_tls(&mut &[][..]) {
                        Ok(_) => self.process(),
                        Err(error) => self.fail(HandshakeError::Failed(error.to_string())),
                    }
                }
                Ok(Admit::Taken)
            }
            StreamEvent::Data(mut chunk) => {
                if chunk.is_empty() {
                    return Ok(Admit::Taken);
                }
                if self.accepted.is_some()
                    || self.above.is_some()
                    || self.below.is_some()
                    || self
                        .tls
                        .as_ref()
                        .is_some_and(|tls| tls.wants_write() || !tls.wants_read())
                {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                // Reserve the next output allocation before processing bytes
                // that can produce a handshake response or a fatal alert.
                if !self.reserve_output(env) {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                if !self.initialized {
                    self.acceptor = Some(Acceptor::default());
                    self.initialized = true;
                }
                let limit = chunk.len().min(CHUNK);
                let read = if let Some(tls) = self.tls.as_mut() {
                    tls.read_tls(&mut &chunk[..limit])
                } else if let Some(acceptor) = self.acceptor.as_mut() {
                    self.first_byte.get_or_insert(chunk[0]);
                    acceptor.read_tls(&mut &chunk[..limit])
                } else {
                    return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                };
                let n = match read {
                    Ok(0) => {
                        self.fail(HandshakeError::Failed("TLS took no input bytes".into()));
                        return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                    }
                    Ok(n) => n,
                    Err(error) => {
                        self.fail(HandshakeError::Failed(error.to_string()));
                        return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                    }
                };
                chunk.advance(n);
                if let Some(acceptor) = self.acceptor.as_mut() {
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
                } else {
                    self.process();
                }
                Ok(if chunk.is_empty() {
                    Admit::Taken
                } else {
                    Admit::Partial(StreamEvent::Data(chunk))
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
                if self.is_handshaking() || !self.reserve_output(env) {
                    return Ok(Admit::Blocked(StreamCommand::End));
                }
                self.closing = true;
                self.tls.as_mut().unwrap().send_close_notify();
                Ok(Admit::Taken)
            }
            StreamCommand::Write(mut chunk) => {
                if self.is_handshaking() || self.pending_plaintext != 0 || self.output_pending() {
                    return Ok(Admit::Blocked(StreamCommand::Write(chunk)));
                }
                if chunk.is_empty() {
                    return Ok(Admit::Taken);
                }
                if !self.reserve_output(env) {
                    return Ok(Admit::Blocked(StreamCommand::Write(chunk)));
                }
                let n = self
                    .tls
                    .as_mut()
                    .unwrap()
                    .writer()
                    .write(&chunk[..chunk.len().min(CHUNK)])
                    .map_err(|error| HandshakeError::Failed(error.to_string()))?;
                if n == 0 {
                    return Ok(Admit::Blocked(StreamCommand::Write(chunk)));
                }
                self.pending_plaintext = n;
                chunk.advance(n);
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
        let accepted = self.accepted.take().ok_or_else(|| {
            HandshakeError::Failed("TLS configuration without a client hello".into())
        })?;
        self.work = false;
        let Some(config) = config else {
            self.reject = true;
            self.fail(HandshakeError::Rejected);
            return Ok(());
        };
        // This owned variant fragments every outgoing record at 512 bytes.
        // Its caller still supplies certificates, protocol choices and entropy.
        let mut config = (*config).clone();
        config.max_fragment_size = Some(512);
        match accepted.into_connection(Arc::new(config)) {
            Ok(mut tls) => {
                tls.set_buffer_limit(Some(CHUNK * 2));
                self.tls = Some(tls);
            }
            Err((error, alert)) => {
                self.alert = Some(alert);
                self.fail(Self::protocol_error(error));
            }
        }
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
        // At most one charged chunk each way is retained by this layer.
        if self.below.is_none()
            && (self.reject
                || self.alert.is_some()
                || self.tls.as_ref().is_some_and(|tls| tls.wants_write()))
        {
            if !self.reserve_output(env) {
                return Ok(false);
            }
            let charge = self.output_reserve.take().unwrap();
            let mut bytes = vec![0; CHUNK];
            let mut writer = &mut bytes[..];
            let result = if self.reject {
                writer.write(UNRECOGNIZED_NAME.as_slice())
            } else if let Some(alert) = self.alert.as_mut() {
                alert.write(&mut writer)
            } else {
                self.tls.as_mut().unwrap().write_tls(&mut writer)
            };
            let n = result.map_err(|error| HandshakeError::Failed(error.to_string()))?;
            self.reject = false;
            if n == 0 {
                self.alert = None;
            } else {
                bytes.truncate(n);
                self.produced += n as u64;
                self.below = Some(StreamCommand::Write(Chunk::with_charge(bytes, charge)));
            }
            if self.pending_plaintext != 0
                && self.fence.is_none()
                && !self.tls.as_ref().is_some_and(|tls| tls.wants_write())
            {
                self.fence = Some(self.produced);
                self.credit_written();
            }
            return Ok(true);
        }
        if self.above.is_none()
            && !self.ended
            && !self.failed
            && let Some(tls) = self.tls.as_mut()
        {
            match tls.reader().into_first_chunk() {
                Ok([]) => {
                    self.ended = true;
                    self.input_ended = true;
                    self.above = Some(StreamEvent::Ended);
                    return Ok(true);
                }
                Ok(plaintext) => {
                    let n = plaintext.len().min(CHUNK);
                    let Some(charge) = env.budget().charge(n) else {
                        return Ok(false);
                    };
                    let bytes = plaintext[..n].to_vec();
                    tls.reader().consume(n);
                    self.above = Some(StreamEvent::Data(Chunk::with_charge(bytes, charge)));
                    return Ok(true);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    self.ended = true;
                    self.above = Some(StreamEvent::Ended);
                    return Ok(true);
                }
                Err(error) => self.fail(HandshakeError::Failed(error.to_string())),
            }
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
        Ok(false)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        self.below.take()
    }

    fn take_event(&mut self) -> Option<StreamEvent> {
        if self.credit != 0 {
            return Some(StreamEvent::Written(std::mem::take(&mut self.credit)));
        }
        self.above.take()
    }

    fn take_urgent(&mut self) -> Option<StreamEvent> {
        (self.credit != 0).then(|| StreamEvent::Written(std::mem::take(&mut self.credit)))
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

impl Negotiation for TlsLayer {
    fn handshake(&self) -> Handshake<'_> {
        if self.failed || self.reset {
            Handshake::Failed
        } else if self.is_handshaking() {
            Handshake::Pending
        } else {
            Handshake::Established {
                server_name: self.hello().and_then(Hello::server_name),
                alpn: self.alpn(),
            }
        }
    }
}
