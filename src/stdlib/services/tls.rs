//! TLS: the server side of a TLS connection, played by the world.
//!
//! Use this module when a machine in the world serves HTTPS, or any other
//! protocol over TLS, by hand. If the world is a set of websites,
//! [`web::Sites`](fictionet::stdlib::web::Sites) does TLS for you.
//!
//! [`TlsLayer`] is TLS as a [layer](fictionet::stdlib::layer), with ordered
//! byte streams below and above it and no I/O. Put a protocol on top of it
//! with [`Chain`](fictionet::stdlib::layer::Chain), as
//! `Chain<TlsLayer, Http1>` serves HTTPS, or with [`Secure`] when what runs
//! on top depends on the name and protocol the handshake settles. Run the
//! stack over a TCP connection with
//! [`stack::stream`](fictionet::stdlib::services::stack::stream), or without
//! a runtime in a [`Harness`](fictionet::stdlib::layer::Harness).
//!
//! For code written against a [`Connection`], [`server`] runs the same
//! layer over one, usually a
//! [`TcpConnection`](fictionet::stdlib::network::tcp::TcpConnection), and
//! gives back a `Connection` that carries the decrypted bytes.
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

mod factory;
mod layer;
mod provider;
mod secure;

#[cfg(kani)]
#[path = "../../../verification/tls-contract/kani/Buffers.rs"]
mod contract_buffers;

pub use provider::{client_config_builder, config_builder, crypto_provider};

pub use factory::{Build, Factory, Handshake, Negotiation, Selection};
pub use layer::{Hello, Pick, Picking, TlsLayer};
pub use secure::Secure;

use std::future::poll_fn;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use fictionet::stdlib::layer::Budget;
use fictionet::stdlib::services::stack::{Halt, Opened, StackError, StreamEnd};
use fictionet::sync::Mutex;

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

/// How a handshake failed, in more detail than [`ConnError`]: what
/// [`server_detailed`], [`ClientHello::finish_detailed`] and [`TlsLayer`]
/// return, for a world that logs how each handshake ended.
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
    /// [`TlsLayer`].
    Rejected,
    /// The handshake did not finish by its deadline: from a [`TlsLayer`]
    /// given one ([`TlsLayer::handshake_by`]).
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

impl From<HandshakeError> for ConnError {
    /// A handshake's failure as a connection's: the connection's own error
    /// as it was, a cancel, a timeout, and anything else as
    /// [`ConnError::Broken`].
    fn from(e: HandshakeError) -> ConnError {
        match e {
            HandshakeError::Conn(e) => e,
            HandshakeError::Cancelled => ConnError::Cancelled,
            HandshakeError::TimedOut => ConnError::TimedOut,
            _ => ConnError::Broken,
        }
    }
}

impl From<StackError<HandshakeError>> for HandshakeError {
    fn from(e: StackError<HandshakeError>) -> HandshakeError {
        match e {
            StackError::Layer(e) => e,
            StackError::Budget => HandshakeError::Failed("input memory budget exhausted".into()),
            StackError::Cancelled => HandshakeError::Cancelled,
        }
    }
}

/// How a run that ended without the layer's own error ended, as a
/// handshake's failure.
fn ended(end: StreamEnd) -> HandshakeError {
    match end {
        StreamEnd::Conn(e) => e.into(),
        StreamEnd::Reset => HandshakeError::Conn(ConnError::Reset),
        StreamEnd::Finished | StreamEnd::Idle => HandshakeError::Closed,
        StreamEnd::Budget => HandshakeError::Failed("no budget for the TLS input".into()),
    }
}

/// The world's answer to a hello, once it gives one: the config, or `None`
/// to refuse the name.
#[derive(Default)]
struct Answer {
    config: Option<Option<Arc<ServerConfig>>>,
    waiting: Option<Waker>,
}

type Answered = Arc<Mutex<Answer>>;

fn answer(answered: &Answered, config: Option<Arc<ServerConfig>>) {
    let mut answer = answered.lock();
    answer.config = Some(config);
    if let Some(waker) = answer.waiting.take() {
        waker.wake();
    }
}

/// Moves the handshake on until `done` says it has gone far enough, or it
/// fails. A failure that sends an alert is returned once the alert is out.
fn poll_handshake<C: Connection>(
    tls: &mut Opened<TlsLayer, C>,
    fcx: &Cx,
    cx: &mut Context<'_>,
    done: impl Fn(&TlsLayer) -> bool,
) -> Poll<Result<(), HandshakeError>> {
    if fcx.is_cancelled() {
        return Poll::Ready(Err(HandshakeError::Cancelled));
    }
    match tls.poll_run(fcx, cx) {
        Poll::Ready(Ok(Halt::Conn(e))) => Poll::Ready(Err(e.into())),
        Poll::Ready(Ok(Halt::End(end))) => Poll::Ready(Err(ended(end))),
        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        Poll::Pending if tls.stack().failure().is_none() && done(tls.stack()) => {
            Poll::Ready(Ok(()))
        }
        Poll::Pending => Poll::Pending,
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
    Ok(server_detailed(fcx, conn).await?)
}

/// [`server`], failing with how the hello went wrong. A malformed hello
/// gets rustls' fatal alert first. Input that is not TLS gets no answer.
pub async fn server_detailed<C: Connection>(
    fcx: &Cx,
    conn: C,
) -> Result<ClientHello<C>, HandshakeError> {
    let answered = Answered::default();
    let waiting = answered.clone();
    let layer = TlsLayer::selecting(move |_, _| {
        let answered = waiting.clone();
        poll_fn(move |cx| {
            let mut answer = answered.lock();
            match answer.config.take() {
                Some(config) => Poll::Ready(config),
                None => {
                    answer.waiting = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
    });
    let mut tls = Opened::new(fcx, conn, layer, Budget::unlimited());
    poll_fn(|cx| poll_handshake(&mut tls, fcx, cx, |tls| tls.hello().is_some())).await?;
    Ok(ClientHello { tls, answered })
}

/// What the client asked for, before the server has answered.
pub struct ClientHello<C> {
    tls: Opened<TlsLayer, C>,
    answered: Answered,
}

impl<C: Connection> ClientHello<C> {
    /// The name the client asked for (SNI), such as `api.stripe.com`. `None`
    /// if the client sent no name, for example when it connected to a bare
    /// IP address.
    pub fn server_name(&self) -> Option<&str> {
        self.tls.stack().hello().and_then(Hello::server_name)
    }

    /// The application protocols the client offers (ALPN), such as `h2` and
    /// `http/1.1`, in the client's order of preference.
    pub fn alpn(&self) -> Vec<&[u8]> {
        self.tls
            .stack()
            .hello()
            .map(Hello::alpn)
            .unwrap_or_default()
    }

    /// The connection underneath, for example to see who connected.
    pub fn inner(&self) -> &C {
        self.tls.conn()
    }

    /// Refuses the name the client asked for: sends the `unrecognized_name`
    /// alert and closes the connection. Dropping the hello instead closes the
    /// connection with no alert.
    pub async fn reject(mut self, fcx: &Cx) -> Result<(), ConnError> {
        answer(&self.answered, None);
        match poll_fn(|cx| poll_handshake(&mut self.tls, fcx, cx, |_| false)).await {
            Ok(()) | Err(HandshakeError::Rejected) => Ok(()),
            Err(error) => Err(error.into()),
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
        Ok(self.finish_detailed(fcx, config).await?)
    }

    /// [`finish`](ClientHello::finish), failing with how the handshake went
    /// wrong.
    pub async fn finish_detailed(
        mut self,
        fcx: &Cx,
        config: Arc<ServerConfig>,
    ) -> Result<TlsConnection<C>, HandshakeError> {
        answer(&self.answered, Some(config));
        poll_fn(|cx| poll_handshake(&mut self.tls, fcx, cx, |tls| !tls.is_handshaking())).await?;
        Ok(TlsConnection { tls: self.tls })
    }
}

/// A finished TLS connection: [`TlsLayer`] over the connection underneath,
/// [opened](Opened) as a connection. Reads and writes carry the decrypted
/// bytes.
///
/// A read reports a failure of the connection underneath even when it happened
/// while sending TLS output, such as a KeyUpdate reply. Plaintext already
/// decrypted is kept for the next read. A write returns once its ciphertext
/// was taken by the connection underneath.
pub struct TlsConnection<C> {
    tls: Opened<TlsLayer, C>,
}

impl<C: Connection> TlsConnection<C> {
    /// The connection underneath.
    pub fn inner(&self) -> &C {
        self.tls.conn()
    }

    /// The application protocol both sides agreed on (ALPN), if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.stack().alpn()
    }
}

impl<C: Connection> Connection for TlsConnection<C> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        match self.tls.poll_read(fcx, cx, buf) {
            read @ Poll::Ready(Ok(_)) => read,
            // A protocol failure is the reader's to hear at once, before its
            // alert is out, and before a failure of the connection
            // underneath that sending the alert met.
            _ if self.tls.stack().failure().is_some() => Poll::Ready(Err(ConnError::Broken)),
            read => read,
        }
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        self.tls.poll_write(fcx, cx, data)
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.tls.poll_shutdown(fcx, cx)
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.tls.poll_gone(cx)
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
