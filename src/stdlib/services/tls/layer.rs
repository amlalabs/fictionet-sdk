//! The synchronous TLS state machine. The driver owns bytes once they leave it.

use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::ServerConfig;
use rustls::server::{Accepted, AcceptedAlert, Acceptor, ServerConnection};

use super::HandshakeError;
use fictionet::Cx;
use fictionet::stdlib::layer::{
    Admit, ByteStream, Charge, Chunk, Env, Layer, StreamCommand, StreamEvent, Timers,
};
use fictionet::stdlib::services::stack::Job;
use fictionet::time::Instant;

const CHUNK: usize = 16 * 1024;
/// The most one record takes on the wire: a 5-byte header and at most
/// 2^14 + 2048 bytes of ciphertext in TLS 1.2 (RFC 5246 section 6.2.3).
/// TLS 1.3 allows less, 2^14 + 256 (RFC 8446 section 5.2).
const RECORD: usize = 5 + (1 << 14) + 2048;
const UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

/// Appends to a vector up to its capacity, so a TLS write fills exactly the
/// allocation made for it and never grows it.
struct Fill<'a>(&'a mut Vec<u8>);

impl Write for Fill<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(self.0.capacity() - self.0.len());
        self.0.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            let n = self.write(buf)?;
            total += n;
            if n < buf.len() {
                break;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
    ciphertext_emitted: u64,
    ciphertext_completed: u64,
    plaintext_completion: Option<PlaintextCompletion>,
    completed_plaintext_bytes: u64,
}

/// An accepted plaintext write, completed upstream once downstream has
/// completed the ciphertext through `ciphertext_end`. The end is unknown
/// until rustls has nothing more queued for the write.
#[derive(Clone, Copy)]
struct PlaintextCompletion {
    plaintext_bytes: usize,
    ciphertext_end: Option<u64>,
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
        self.ciphertext_completed = self.ciphertext_emitted;
        self.plaintext_completion = None;
        self.completed_plaintext_bytes = 0;
    }

    fn reserve_output(&mut self, env: &Env<'_, ()>) -> bool {
        if self.output_reserve.is_none() {
            self.output_reserve = env.budget().charge(RECORD);
        }
        self.output_reserve.is_some()
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
                // One plaintext write is outstanding until its ciphertext
                // completes. Pipelining needs a completion record and a
                // charge for each queued write.
                if self.is_handshaking()
                    || self.plaintext_completion.is_some()
                    || self.output_pending()
                {
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
                self.plaintext_completion = Some(PlaintextCompletion {
                    plaintext_bytes: n,
                    ciphertext_end: None,
                });
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
        match accepted.into_connection(config) {
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
            let mut charge = self.output_reserve.take().unwrap();
            // The reservation holds the largest record, so a single whole
            // record goes down in the buffer rustls encrypted it into.
            // Anything else is copied into room for exactly what is to go,
            // up to the reservation: several records coalesced, the rest
            // of a split record, the rejection, or the alert, whose size is
            // not known ahead. Either way the reservation then shrinks to
            // the allocation it covers.
            let owned = if self.reject || self.alert.is_some() {
                None
            } else {
                self.tls
                    .as_mut()
                    .unwrap()
                    .take_sendable_tls_chunk(charge.bytes())
            };
            let bytes = if let Some(bytes) = owned {
                bytes
            } else {
                let room = if self.reject {
                    UNRECOGNIZED_NAME.len()
                } else if self.alert.is_some() {
                    charge.bytes()
                } else {
                    self.tls
                        .as_ref()
                        .unwrap()
                        .sendable_tls_len()
                        .min(charge.bytes())
                };
                let mut bytes = Vec::with_capacity(room);
                let result = if self.reject {
                    Fill(&mut bytes).write(UNRECOGNIZED_NAME.as_slice())
                } else if let Some(alert) = self.alert.as_mut() {
                    alert.write(&mut Fill(&mut bytes))
                } else {
                    self.tls.as_mut().unwrap().write_tls(&mut Fill(&mut bytes))
                };
                result.map_err(|error| HandshakeError::Failed(error.to_string()))?;
                bytes.shrink_to_fit();
                bytes
            };
            self.reject = false;
            if bytes.is_empty() {
                self.alert = None;
            } else {
                // Both paths above bound the allocation by the reservation,
                // so shrinking the charge to it always fits.
                let shrunk = charge.set(bytes.capacity());
                debug_assert!(shrunk, "ciphertext outgrew its reservation");
                self.ciphertext_emitted += bytes.len() as u64;
                self.below = Some(StreamCommand::Write(Chunk::with_charge(bytes, charge)));
            }
            if let Some(completion) = self.plaintext_completion.as_mut()
                && completion.ciphertext_end.is_none()
                && !self.tls.as_ref().is_some_and(|tls| tls.wants_write())
            {
                completion.ciphertext_end = Some(self.ciphertext_emitted);
                self.complete_plaintext_write();
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
                    // A record's plaintext is at most a chunk (RFC 8446
                    // section 5.1), and goes up in the buffer rustls
                    // decrypted it into.
                    let n = plaintext.len();
                    let Some(mut charge) = env.budget().charge(n) else {
                        return Ok(false);
                    };
                    let mut bytes = tls
                        .reader()
                        .take_first_chunk()
                        .map_err(|error| HandshakeError::Failed(error.to_string()))?;
                    if bytes.capacity() > n && !charge.set(bytes.capacity()) {
                        bytes.shrink_to_fit();
                    }
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

    fn on_timer(&mut self, env: &mut Env<'_, ()>, _: ()) -> Result<(), HandshakeError> {
        if self.deadline.fire(&(), env.now()) && self.is_handshaking() {
            // No alert: the client hears the end of the stream.
            self.work = false;
            self.accepted = None;
            self.fail(HandshakeError::TimedOut);
        }
        Ok(())
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
mod ciphertext_transfer_tests {
    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::layer::Harness;

    #[test]
    fn sole_ciphertext_reaches_the_driver_with_its_original_allocation() {
        struct Inspect(*const u8);
        impl Write for Inspect {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0 = bytes.as_ptr();
                Ok(0)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())),
        );
        let mut tls = ServerConnection::new(config.clone()).unwrap();
        tls.send_close_notify();
        let mut inspect = Inspect(std::ptr::null());
        assert_eq!(tls.write_tls(&mut inspect).unwrap(), 0);
        assert!(!inspect.0.is_null());
        let queued = tls.sendable_tls_len();
        let mut layer = TlsLayer::new(config);
        layer.tls = Some(tls);
        let mut harness = Harness::new(Seed::from_u64(42), layer);
        harness.driver().run().unwrap();
        let budget = harness.driver().budget().clone();
        let mut output = None;
        harness.driver().send_below(|command| {
            let StreamCommand::Write(bytes) = command else {
                panic!("expected ciphertext")
            };
            assert!(output.replace(bytes).is_none());
            Admit::Taken
        });
        let output = output.unwrap();
        assert_eq!(output.as_ptr(), inspect.0);
        assert_eq!(output.len(), queued);
        assert!(output.charged() >= output.len());
        assert!(!harness.layer().tls.as_ref().unwrap().wants_write());
        drop(harness);
        assert_eq!(budget.used(), output.charged());
        drop(output);
        assert_eq!(budget.used(), 0);
    }

    /// A full record, the most plaintext one can carry, goes down whole in
    /// one write, in the buffer rustls encrypted it into, in TLS 1.2 and
    /// 1.3 alike.
    #[test]
    fn a_full_record_goes_down_in_one_write_without_a_copy() {
        use fictionet::stdlib::protocols::x509;
        use fictionet::stdlib::services::ca::Ca;
        use std::time::{Duration, UNIX_EPOCH};

        struct Inspect(*const u8);
        impl Write for Inspect {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0 = bytes.as_ptr();
                Ok(0)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        /// Moves what `from` has to send into `to`.
        fn deliver<A, B>(
            from: &mut rustls::ConnectionCommon<A>,
            to: &mut rustls::ConnectionCommon<B>,
        ) {
            let mut bytes = Vec::new();
            while from.wants_write() {
                from.write_tls(&mut bytes).unwrap();
            }
            let mut rest = bytes.as_slice();
            while !rest.is_empty() {
                to.read_tls(&mut rest).unwrap();
                to.process_new_packets().unwrap();
            }
        }

        fictionet::block_on(fictionet::lab(Seed::from_u64(43), |cx| async move {
            let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
            let ca = Ca::new(&cx, "Record CA")?;
            let validity = x509::Validity {
                not_before: x509::Time::from_unix(1_700_000_000).unwrap(),
                not_after: x509::Time::from_unix(2_000_000_000).unwrap(),
            };
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.cert_der())?;
            let roots = Arc::new(roots);
            for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                let config = ca
                    .issue(&cx, &["record.example"], validity.clone())?
                    .server_config(&cx, start)?;
                let client_config = Arc::new(
                    super::super::client_config_builder(&cx, start)
                        .with_protocol_versions(&[version])?
                        .with_root_certificates(roots.clone())
                        .with_no_client_auth(),
                );
                let mut client = rustls::ClientConnection::new(
                    client_config,
                    "record.example".try_into().unwrap(),
                )?;
                let mut tls = ServerConnection::new(config.clone())?;
                while client.is_handshaking() || tls.is_handshaking() || tls.wants_write() {
                    deliver(&mut *client, &mut *tls);
                    deliver(&mut *tls, &mut *client);
                }
                assert_eq!(tls.protocol_version(), Some(version.version));

                let plaintext = vec![7u8; 1 << 14];
                assert_eq!(tls.writer().write(&plaintext)?, plaintext.len());
                let mut inspect = Inspect(std::ptr::null());
                assert_eq!(tls.write_tls(&mut inspect)?, 0);
                let queued = tls.sendable_tls_len();
                let mut layer = TlsLayer::new(config);
                layer.tls = Some(tls);
                let mut harness = Harness::new(Seed::from_u64(44), layer);
                let mut writes = Vec::new();
                loop {
                    harness.driver().run().unwrap();
                    let moved = harness.driver().send_below(|command| {
                        let StreamCommand::Write(bytes) = command else {
                            panic!("expected ciphertext")
                        };
                        writes.push(bytes);
                        Admit::Taken
                    });
                    if !moved {
                        break;
                    }
                }
                assert_eq!(writes.len(), 1, "{version:?}: one write for one record");
                assert_eq!(writes[0].as_ptr(), inspect.0, "{version:?}: copied");
                assert_eq!(writes[0].len(), queued);
                let mut rest = &writes[0][..];
                while !rest.is_empty() {
                    client.read_tls(&mut rest)?;
                    client.process_new_packets()?;
                }
                let mut received = Vec::new();
                if let Err(error) = io::Read::read_to_end(&mut client.reader(), &mut received) {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                }
                assert!(
                    received == plaintext,
                    "{version:?}: the client reads the plaintext"
                );
            }
            Ok(())
        }))
        .unwrap();
    }
}
