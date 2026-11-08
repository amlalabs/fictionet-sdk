//! TLS: the server side of a TLS connection, played by the world.
//!
//! Use this module when a machine in the world serves HTTPS, or any other
//! protocol over TLS, by hand. If the world is a set of websites,
//! [`web::Sites`](fictionet::stdlib::web::Sites) does TLS for you.
//!
//! [`TlsLayer`] is a synchronous protocol layer with ordered byte streams
//! below and above it. Compose it with [`Chain`](fictionet::stdlib::layer::Chain)
//! or drive it without a runtime using [`Harness`](fictionet::stdlib::layer::Harness).
//! The functions here adapt connection readiness to that same layer.
//!
//! The live adapter takes a [`Connection`], usually a
//! [`TcpConnection`](fictionet::stdlib::network::tcp::TcpConnection), and gives back a
//! `Connection` that carries the decrypted bytes.
//!
//! The world supplies a rustls [`ServerConfig`], using certificate files
//! or certificates issued by [`ca`](fictionet::stdlib::services::ca). This module
//! handles the TLS connection. A world can supply a rustls key logger and pass its own
//! key log entries to [`dissect`](fictionet::stdlib::dissect) for decryption.
//!
//! The handshake has two steps, so the world can decide how to answer after
//! it sees what the client asked for. [`server`] reads the client's hello,
//! and [`ClientHello::finish`] completes the handshake with the config the
//! world picks. In this example, the world serves a fake certificate on
//! one connection in ten:
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::Cx;
//! # use fictionet::stdlib::{network::{tcp, Connection}, services::tls};
//! # use rustls::ServerConfig;
//! # async fn serve_stripe(_fcx: &Cx, _conn: impl Connection) {}
//! # async fn accept(fcx: Cx, mut listener: tcp::Listener, real: Arc<ServerConfig>, fake: Arc<ServerConfig>) {
//! while let Ok(tcp) = listener.accept(&fcx).await {
//!     let (real, fake) = (real.clone(), fake.clone()); // Arc<ServerConfig>s
//!     fcx.spawn(move |fcx| async move {
//!         // Reads the client's hello. Nothing is sent to the client yet.
//!         // One bad connection is not a failure of the world, so errors end
//!         // this task with Ok(()).
//!         let Ok(hello) = tls::server(&fcx, tcp).await else { return Ok(()) };
//!
//!         // A fake certificate 10% of the time.
//!         let config = if fcx.random_f64() < 0.1 { fake } else { real };
//!
//!         let Ok(conn) = hello.finish(&fcx, config).await else { return Ok(()) };
//!         serve_stripe(&fcx, conn).await;
//!         Ok(())
//!     });
//! }
//! # }
//! ```
//!
//! A world that always uses one config writes the same two steps and never
//! looks at the hello.
//!
//! This module is the simplest way to serve TLS, not the only one. A world
//! can run rustls, OpenSSL, or anything else over a connection itself,
//! since [`Connection`] is an open trait.

mod layer;
mod provider;

pub use provider::{client_config_builder, config_builder, crypto_provider};

pub use layer::{Hello, TlsLayer};

use fictionet::stdlib::layer::{Admit, Budget, Chunk, Driver, StreamCommand, StreamEvent};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Context, Poll};

pub use rustls::ServerConfig;

use fictionet::Cx;
use fictionet::stdlib::network::{ConnError, Connection};

/// The name of a TLS alert, or "unknown" for an unrecognized code.
pub fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        30 => "decompression_failure",
        40 => "handshake_failure",
        41 => "no_certificate",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        60 => "export_restriction",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        100 => "no_renegotiation",
        109 => "missing_extension",
        110 => "unsupported_extension",
        111 => "certificate_unobtainable",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        114 => "bad_certificate_hash_value",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        117 => "general_error",
        120 => "no_application_protocol",
        121 => "ech_required",
        _ => "unknown",
    }
}

/// How much to read from the connection underneath in one read.
const READ_CHUNK: usize = 16 * 1024;
/// Socket readiness translated into the layer driver's owned inputs and outputs.
struct Io<C> {
    conn: C,
    driver: Driver<TlsLayer>,
    input: Option<StreamEvent>,
    plaintext: VecDeque<Chunk>,
    ended: bool,
    eof: bool,
    credited: u64,
    pending_write: Option<Chunk>,
}

impl<C: Connection> Io<C> {
    fn new(fcx: &Cx, conn: C) -> Self {
        Self {
            conn,
            driver: Driver::new(
                TlsLayer::new(),
                Arc::new(fcx.clone()),
                Budget::unlimited(),
                fcx.now(),
            ),
            input: None,
            plaintext: VecDeque::new(),
            ended: false,
            eof: false,
            credited: 0,
            pending_write: None,
        }
    }

    fn collect(&mut self) {
        self.driver.send_above(|event| {
            match event {
                StreamEvent::Data(bytes) => self.plaintext.push_back(bytes),
                StreamEvent::Written(n) => self.credited += n,
                StreamEvent::Ended | StreamEvent::Reset => self.ended = true,
            }
            Admit::Taken
        });
    }

    fn poll_flush(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), HandshakeError>> {
        self.driver.set_now(fcx.now());
        for _ in 0..1024 {
            self.driver.run()?;
            let mut written = 0;
            let mut error = None;
            let mut blocked = false;
            let conn = &mut self.conn;
            let moved = self.driver.send_below(|command| match command {
                StreamCommand::Write(mut bytes) => match conn.poll_write(fcx, cx, &bytes) {
                    Poll::Ready(Ok(0)) => {
                        error = Some(ConnError::Closed);
                        Admit::Blocked(StreamCommand::Write(bytes))
                    }
                    Poll::Ready(Ok(n)) => {
                        written += n as u64;
                        bytes.advance(n);
                        if bytes.is_empty() {
                            Admit::Taken
                        } else {
                            Admit::Partial(StreamCommand::Write(bytes))
                        }
                    }
                    Poll::Ready(Err(e)) => {
                        error = Some(e);
                        Admit::Blocked(StreamCommand::Write(bytes))
                    }
                    Poll::Pending => {
                        blocked = true;
                        Admit::Blocked(StreamCommand::Write(bytes))
                    }
                },
                StreamCommand::End | StreamCommand::Reset => match conn.poll_shutdown(fcx, cx) {
                    Poll::Ready(Ok(())) => Admit::Taken,
                    Poll::Ready(Err(e)) => {
                        error = Some(e);
                        Admit::Blocked(command)
                    }
                    Poll::Pending => {
                        blocked = true;
                        Admit::Blocked(command)
                    }
                },
            });
            if written != 0 {
                match self.driver.deliver(StreamEvent::Written(written))? {
                    Admit::Taken => {}
                    _ => {
                        return Poll::Ready(Err(HandshakeError::Failed(
                            "TLS refused write completion".into(),
                        )));
                    }
                }
            }
            self.collect();
            if let Some(e) = error {
                return Poll::Ready(Err(e.into()));
            }
            if blocked {
                return Poll::Pending;
            }
            if !moved && !self.driver.holds_output() && !self.driver.layer().output_pending() {
                return Poll::Ready(Ok(()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_fill(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), HandshakeError>> {
        self.driver.set_now(fcx.now());
        if self.input.is_none() {
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            let charge = self
                .driver
                .budget()
                .charge(READ_CHUNK)
                .ok_or_else(|| HandshakeError::Failed("TLS input budget exhausted".into()))?;
            let mut bytes = vec![0; READ_CHUNK];
            let n = match self.conn.poll_read(fcx, cx, &mut bytes) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Poll::Pending,
            };
            self.input = Some(if n == 0 {
                self.eof = true;
                StreamEvent::Ended
            } else {
                bytes.truncate(n);
                StreamEvent::Data(Chunk::with_charge(bytes, charge))
            });
        }
        let event = self.input.take().unwrap();
        match self.driver.deliver(event)? {
            Admit::Taken | Admit::Closed(_) => {}
            Admit::Partial(rest) => self.input = Some(rest),
            Admit::Blocked(rest) => {
                self.input = Some(rest);
                return Poll::Pending;
            }
        }
        self.driver.run()?;
        self.collect();
        Poll::Ready(Ok(()))
    }

    fn poll_handshake(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        hello: bool,
    ) -> Poll<Result<(), HandshakeError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(HandshakeError::Cancelled));
        }
        for _ in 0..1024 {
            let flushed = self.poll_flush(fcx, cx);
            if self.driver.layer().failure().is_some() {
                if flushed.is_pending() {
                    return Poll::Pending;
                }
                return Poll::Ready(Err(self.driver.layer_mut().take_failure().unwrap()));
            }
            match flushed {
                Poll::Ready(result) => result?,
                Poll::Pending => return Poll::Pending,
            }
            if if hello {
                self.driver.layer().hello().is_some()
            } else {
                !self.driver.layer().is_handshaking()
            } {
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Err(HandshakeError::Closed));
            }
            match self.poll_fill(fcx, cx) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// How a handshake failed, in more detail than [`ConnError`]: what
/// [`server_detailed`], [`ClientHello::finish_detailed`] and
/// [`serve::accept_tls`](fictionet::stdlib::services::serve::accept_tls) return, for a
/// world that logs how each handshake ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The client closed the connection before the handshake finished.
    Closed,
    /// The client sent this fatal alert.
    Alert(u8),
    /// The bytes were not TLS, or broke the protocol.
    Failed(String),
    /// There was no config for the name the client asked for, and the
    /// handshake was refused with `unrecognized_name`. Returned by
    /// [`TlsLayer`] and `accept_tls`.
    Rejected,
    /// The handshake did not finish by its deadline. Only from
    /// `accept_tls`.
    TimedOut,
    /// The connection underneath failed. Never [`ConnError::Cancelled`]:
    /// a cancel is [`HandshakeError::Cancelled`].
    Conn(ConnError),
    /// The [region](fictionet::Cx#regions) of the `Cx` passed to the call was
    /// cancelled while it waited.
    Cancelled,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Closed => {
                f.write_str("the client closed the connection before the handshake finished")
            }
            HandshakeError::Alert(a) => write!(f, "the client sent alert {a}"),
            HandshakeError::Failed(why) => f.write_str(why),
            HandshakeError::Rejected => {
                f.write_str("there is no TLS config for the name the client asked for")
            }
            HandshakeError::TimedOut => f.write_str("the handshake did not finish in time"),
            HandshakeError::Conn(_) => f.write_str("the connection failed during the handshake"),
            HandshakeError::Cancelled => f.write_str("the handshake stopped"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandshakeError::Conn(e) => Some(e),
            HandshakeError::Cancelled => Some(&fictionet::Cancelled),
            _ => None,
        }
    }
}

impl From<ConnError> for HandshakeError {
    /// A connection's error, with a cancel as [`HandshakeError::Cancelled`].
    fn from(e: ConnError) -> Self {
        match e {
            ConnError::Cancelled => HandshakeError::Cancelled,
            e => HandshakeError::Conn(e),
        }
    }
}

impl From<fictionet::Cancelled> for HandshakeError {
    fn from(_: fictionet::Cancelled) -> Self {
        HandshakeError::Cancelled
    }
}

impl HandshakeError {
    fn into_conn(self) -> ConnError {
        match self {
            HandshakeError::Conn(e) => e,
            HandshakeError::Cancelled => ConnError::Cancelled,
            HandshakeError::TimedOut => ConnError::TimedOut,
            _ => ConnError::Broken,
        }
    }
}

/// Starts the server side of a TLS handshake on `conn`.
///
/// Waits for the client's first message, its hello, reads it, and returns.
/// Nothing has been sent to the client yet. Finish the handshake with
/// [`ClientHello::finish`], or drop the hello to close the connection.
///
/// Fails with [`ConnError::Broken`] if the client's first message is not a
/// TLS hello, or if the client closes the connection before it sent a whole
/// hello. A malformed hello gets rustls' fatal alert first. Input that is
/// not TLS gets no answer. An error of the connection underneath, such as
/// [`ConnError::Cancelled`] when `fcx`'s [region](fictionet::Cx#regions) is
/// cancelled, comes out as it is.
pub async fn server<C: Connection>(fcx: &Cx, conn: C) -> Result<ClientHello<C>, ConnError> {
    server_detailed(fcx, conn)
        .await
        .map_err(HandshakeError::into_conn)
}

/// [`server`], failing with how the hello went wrong. A malformed hello
/// gets rustls' fatal alert first. Input that is not TLS gets no answer.
pub async fn server_detailed<C: Connection>(
    fcx: &Cx,
    conn: C,
) -> Result<ClientHello<C>, HandshakeError> {
    let mut io = Io::new(fcx, conn);
    poll_fn(|cx| io.poll_handshake(fcx, cx, true)).await?;
    Ok(ClientHello { io })
}

/// What the client asked for, before the server has answered.
pub struct ClientHello<C> {
    io: Io<C>,
}

impl<C: Connection> ClientHello<C> {
    /// The name the client asked for (SNI), such as `api.stripe.com`. `None`
    /// if the client sent no name, for example when it connected to a bare
    /// IP address.
    pub fn server_name(&self) -> Option<&str> {
        self.io.driver.layer().hello().and_then(Hello::server_name)
    }

    /// The application protocols the client offers (ALPN), such as `h2` and
    /// `http/1.1`, in the client's order of preference.
    pub fn alpn(&self) -> Vec<&[u8]> {
        self.io
            .driver
            .layer()
            .hello()
            .map(Hello::alpn)
            .unwrap_or_default()
    }

    /// The connection underneath, for example to see who connected.
    pub fn inner(&self) -> &C {
        &self.io.conn
    }

    /// Refuses the name the client asked for: sends the `unrecognized_name`
    /// alert and closes the connection. Dropping the hello instead closes the
    /// connection with no alert.
    pub async fn reject(mut self, fcx: &Cx) -> Result<(), ConnError> {
        self.io
            .driver
            .complete(None)
            .map_err(HandshakeError::into_conn)?;
        match poll_fn(|cx| self.io.poll_flush(fcx, cx)).await {
            Ok(()) | Err(HandshakeError::Rejected) => Ok(()),
            Err(error) => Err(error.into_conn()),
        }
    }

    /// Finishes the handshake with `config`.
    ///
    /// Fails with [`ConnError::Broken`] if the handshake fails, for example
    /// because the client rejected the certificate. An error of the
    /// connection underneath comes out as it is.
    pub async fn finish(
        self,
        fcx: &Cx,
        config: Arc<ServerConfig>,
    ) -> Result<TlsConnection<C>, ConnError> {
        self.finish_detailed(fcx, config)
            .await
            .map_err(HandshakeError::into_conn)
    }

    /// [`finish`](ClientHello::finish), failing with how the handshake went
    /// wrong.
    pub async fn finish_detailed(
        self,
        fcx: &Cx,
        config: Arc<ServerConfig>,
    ) -> Result<TlsConnection<C>, HandshakeError> {
        let mut io = self.io;
        io.driver.complete(Some(config))?;
        poll_fn(|cx| io.poll_handshake(fcx, cx, false)).await?;
        Ok(TlsConnection { io, closing: false })
    }
}

/// A finished TLS connection. Reads and writes carry the decrypted bytes.
///
/// A read reports a failure of the connection underneath even when it happened
/// while sending TLS output, such as a KeyUpdate reply. Plaintext already
/// decrypted is kept for the next read. Output waits for the next read or write
/// only when the connection has no room for it.
pub struct TlsConnection<C> {
    io: Io<C>,
    /// `close_notify` is queued.
    closing: bool,
}

impl<C: Connection> TlsConnection<C> {
    /// The connection underneath.
    pub fn inner(&self) -> &C {
        &self.io.conn
    }

    /// The application protocol both sides agreed on (ALPN), if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.io.driver.layer().alpn()
    }
}

impl<C: Connection> Connection for TlsConnection<C> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        for _ in 0..1024 {
            self.io.collect();
            if let Some(bytes) = self.io.plaintext.front_mut() {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                bytes.advance(n);
                if bytes.is_empty() {
                    self.io.plaintext.pop_front();
                }
                return Poll::Ready(Ok(n));
            }
            if self.io.ended {
                return Poll::Ready(Ok(0));
            }
            let filled = self.io.poll_fill(fcx, cx);
            let flushed = self.io.poll_flush(fcx, cx);
            if self.io.driver.layer().failure().is_some() {
                return Poll::Ready(Err(ConnError::Broken));
            }
            if let Poll::Ready(Err(e)) = flushed {
                return Poll::Ready(Err(e.into_conn()));
            }
            if !self.io.plaintext.is_empty() || self.io.ended {
                continue;
            }
            match filled {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into_conn())),
                Poll::Pending if self.io.input.is_some() && flushed.is_ready() => continue,
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        match self.io.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into_conn())),
            Poll::Pending => return Poll::Pending,
        }
        if let Some(previous) = self.io.pending_write.take() {
            if self.io.credited < previous.len() as u64 {
                self.io.pending_write = Some(previous);
                return Poll::Pending;
            }
            self.io.credited -= previous.len() as u64;
            if data.starts_with(&previous) {
                return Poll::Ready(Ok(previous.len()));
            }
        }
        if self.closing {
            return Poll::Ready(Err(ConnError::Closed));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(16 * 1024);
        let budget = self.io.driver.budget();
        let charge = budget.charge(n).ok_or(ConnError::Broken)?;
        let retry_charge = budget.charge(n).ok_or(ConnError::Broken)?;
        let command = StreamCommand::Write(Chunk::with_charge(data[..n].to_vec(), charge));
        let accepted = match self
            .io
            .driver
            .command(command)
            .map_err(HandshakeError::into_conn)?
        {
            Admit::Taken => n,
            Admit::Partial(StreamCommand::Write(rest)) => n - rest.len(),
            Admit::Closed(_) => return Poll::Ready(Err(ConnError::Closed)),
            Admit::Blocked(_) => return Poll::Pending,
            _ => return Poll::Ready(Err(ConnError::Broken)),
        };
        // A retry is matched by content because Connection's borrowed write
        // interface has no identity that survives dropping its future.
        let n = accepted;
        self.io.pending_write = Some(Chunk::with_charge(data[..n].to_vec(), retry_charge));
        match self.io.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => {
                if self.io.credited < n as u64 {
                    return Poll::Pending;
                }
                self.io.credited -= n as u64;
                self.io.pending_write = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into_conn())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        match self.io.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into_conn())),
            Poll::Pending => return Poll::Pending,
        }
        if !self.closing {
            match self
                .io
                .driver
                .command(StreamCommand::End)
                .map_err(HandshakeError::into_conn)?
            {
                Admit::Taken | Admit::Closed(_) => self.closing = true,
                _ => return Poll::Pending,
            }
        }
        self.io
            .poll_flush(fcx, cx)
            .map(|r| r.map_err(HandshakeError::into_conn))
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.io.conn.poll_gone(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::alert_name;

    #[test]
    fn tls_alert_names() {
        let known = [
            (0, "close_notify"),
            (10, "unexpected_message"),
            (20, "bad_record_mac"),
            (21, "decryption_failed"),
            (22, "record_overflow"),
            (30, "decompression_failure"),
            (40, "handshake_failure"),
            (41, "no_certificate"),
            (42, "bad_certificate"),
            (43, "unsupported_certificate"),
            (44, "certificate_revoked"),
            (45, "certificate_expired"),
            (46, "certificate_unknown"),
            (47, "illegal_parameter"),
            (48, "unknown_ca"),
            (49, "access_denied"),
            (50, "decode_error"),
            (51, "decrypt_error"),
            (60, "export_restriction"),
            (70, "protocol_version"),
            (71, "insufficient_security"),
            (80, "internal_error"),
            (86, "inappropriate_fallback"),
            (90, "user_canceled"),
            (100, "no_renegotiation"),
            (109, "missing_extension"),
            (110, "unsupported_extension"),
            (111, "certificate_unobtainable"),
            (112, "unrecognized_name"),
            (113, "bad_certificate_status_response"),
            (114, "bad_certificate_hash_value"),
            (115, "unknown_psk_identity"),
            (116, "certificate_required"),
            (117, "general_error"),
            (120, "no_application_protocol"),
            (121, "ech_required"),
        ];
        for code in 0..=u8::MAX {
            let expected = known
                .iter()
                .find(|(c, _)| *c == code)
                .map_or("unknown", |(_, name)| *name);
            assert_eq!(alert_name(code), expected, "alert {code}");
        }
    }
}
