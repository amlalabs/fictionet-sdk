//! TLS: the server side of a TLS connection, played by the world.
//!
//! Use this module when a machine in the world serves HTTPS, or any other
//! protocol over TLS, by hand. If the world is a set of websites,
//! [`web::Sites`](crate::stdlib::web::Sites) does TLS for you.
//!
//! TLS here is middleware. It takes a [`Connection`], usually a
//! [`TcpConnection`](crate::stdlib::tcp::TcpConnection), and gives back a
//! `Connection` that carries the decrypted bytes.
//!
//! Certificates are not Fictionet's concern. The world builds an ordinary
//! rustls [`ServerConfig`] from whatever it likes, usually files named in its
//! `args`. Fictionet never reads files or issues certificates.
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
//! # use fictionet::stdlib::{tcp, tls, Connection};
//! # use rustls::ServerConfig;
//! # async fn serve_stripe(_cx: &Cx, _conn: impl Connection) {}
//! # async fn accept(cx: Cx, mut listener: tcp::Listener, real: Arc<ServerConfig>, fake: Arc<ServerConfig>) {
//! while let Ok(tcp) = listener.accept(&cx).await {
//!     let (real, fake) = (real.clone(), fake.clone()); // Arc<ServerConfig>s
//!     cx.spawn(move |cx| async move {
//!         // Reads the client's hello. Nothing is sent to the client yet.
//!         // One bad connection is not a failure of the world, so errors end
//!         // this task with Ok(()).
//!         let Ok(hello) = tls::server(&cx, tcp).await else { return Ok(()) };
//!
//!         // A fake certificate 10% of the time.
//!         let config = if cx.random_f64() < 0.1 { fake } else { real };
//!
//!         let Ok(conn) = hello.finish(&cx, config).await else { return Ok(()) };
//!         serve_stripe(&cx, conn).await;
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

use std::cell::RefCell;
use std::future::poll_fn;
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

pub use rustls::ServerConfig;

use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};
use rustls::pki_types::UnixTime;
use rustls::server::{Acceptor, ServerConnection};
use rustls::time_provider::TimeProvider;
use rustls::{ConfigBuilder, WantsVersions};

use crate::Cx;
use crate::stdlib::{ConnError, Connection};

/// Starts a rustls server config whose time and randomness come from `cx`.
///
/// rustls reads the current time, to check certificate validity and ticket
/// lifetimes, and draws random values for the handshake. A config built
/// with rustls's own builder takes both from the operating system. This
/// builder takes them from the world instead:
///
/// - **Time** is `start` plus the time since the run started, from `cx`.
///   `start` is the world's date and time when the run started, which the
///   world takes from its arguments (see [No dates](crate::time#no-dates)).
///   So a world set in 2019 checks certificates against 2019.
/// - **Random values**, such as the server random, session IDs and ticket
///   keys, come from [`Cx::random_u64`](crate::Cx::random_u64).
///
/// Key exchange is the exception. rustls's built-in providers make each
/// ephemeral key with the operating system's randomness, inside the
/// provider's key-exchange code. So the bytes of a TLS handshake differ from
/// run to run.
///
/// Random values are drawn while [`server`], [`ClientHello::finish`] or a
/// [`TlsConnection`] is working, and come from the `Cx` passed to that call.
/// A config handed to other TLS code, outside this module, falls back to
/// the operating system's randomness.
///
/// Pass the crypto provider to use, such as
/// `rustls::crypto::ring::default_provider()`. Continue as with
/// `ServerConfig::builder()`:
///
/// ```
/// # use fictionet::{Cx, Result, stdlib::tls};
/// # use rustls::pki_types::{CertificateDer, PrivateKeyDer};
/// # fn make(cx: Cx, start: std::time::SystemTime, chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result {
/// let config = tls::config_builder(&cx, start, rustls::crypto::ring::default_provider())
///     .with_safe_default_protocol_versions()?
///     .with_no_client_auth()
///     .with_single_cert(chain, key)?;
/// # drop(config);
/// # Ok(())
/// # }
/// ```
pub fn config_builder(
    cx: &Cx,
    start: SystemTime,
    provider: CryptoProvider,
) -> ConfigBuilder<ServerConfig, WantsVersions> {
    let provider = CryptoProvider { secure_random: &CxRandom, ..provider };
    let clock = CxClock { cx: cx.clone(), start };
    ServerConfig::builder_with_details(Arc::new(provider), Arc::new(clock))
}

/// The world's date: `start` plus the run's clock.
struct CxClock {
    cx: Cx,
    start: SystemTime,
}

impl std::fmt::Debug for CxClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CxClock").field("start", &self.start).finish_non_exhaustive()
    }
}

impl TimeProvider for CxClock {
    fn current_time(&self) -> Option<UnixTime> {
        let now = self.start.checked_add(self.cx.now().since_start())?;
        Some(UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH).ok()?))
    }
}

thread_local! {
    /// The `Cx` of the TLS work running on this thread now, if any.
    static CURRENT: RefCell<Option<Cx>> = const { RefCell::new(None) };
}

/// Runs `f` with `cx` as the source of [`CxRandom`].
fn with_cx<T>(cx: &Cx, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Cx>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            CURRENT.with(|c| *c.borrow_mut() = previous);
        }
    }
    let previous = CURRENT.with(|c| c.borrow_mut().replace(cx.clone()));
    let _restore = Restore(previous);
    f()
}

/// rustls's `SecureRandom`, from the `Cx` of the TLS work that draws it.
///
/// rustls keeps it as a `&'static`, so it cannot hold a `Cx` itself: it
/// reads the one [`with_cx`] set for this thread.
#[derive(Debug)]
struct CxRandom;

impl SecureRandom for CxRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        CURRENT.with(|c| match &*c.borrow() {
            Some(cx) => {
                for chunk in buf.chunks_mut(8) {
                    chunk.copy_from_slice(&cx.random_u64().to_le_bytes()[..chunk.len()]);
                }
                Ok(())
            }
            None => os_random(buf),
        })
    }
}

fn os_random(buf: &mut [u8]) -> Result<(), GetRandomFailed> {
    crate::sys::random_bytes(buf).map_err(|_| GetRandomFailed)
}

/// How much to read from the connection underneath in one read.
const READ_CHUNK: usize = 16 * 1024;
/// The most plaintext one `poll_write` encrypts.
const WRITE_CHUNK: usize = 64 * 1024;

/// The byte plumbing between rustls and the connection underneath.
struct Io<C> {
    conn: C,
    /// Bytes read from `conn` that rustls has not taken yet.
    inbuf: Vec<u8>,
    /// Encrypted bytes for `conn` that it has not taken yet, from `out_pos`.
    out: Vec<u8>,
    out_pos: usize,
    /// `conn` said it will send nothing more.
    eof: bool,
}

impl<C: Connection> Io<C> {
    fn new(conn: C) -> Self {
        Io { conn, inbuf: Vec::new(), out: Vec::new(), out_pos: 0, eof: false }
    }

    /// Hands all of `out` to `conn`.
    fn poll_flush(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        while self.out_pos < self.out.len() {
            match self.conn.poll_write(cx, task, &self.out[self.out_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(ConnError::Closed)),
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Reads more bytes from `conn` into `inbuf`, or sets `eof`.
    fn poll_fill(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        let old = self.inbuf.len();
        self.inbuf.resize(old + READ_CHUNK, 0);
        let result = self.conn.poll_read(cx, task, &mut self.inbuf[old..]);
        let n = match &result {
            Poll::Ready(Ok(n)) => *n,
            _ => 0,
        };
        self.inbuf.truncate(old + n);
        match result {
            Poll::Ready(Ok(0)) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Moves what rustls wants to send into `out`.
    fn take_output(&mut self, tls: &mut ServerConnection) {
        while tls.wants_write() {
            if tls.write_tls(&mut self.out).is_err() {
                break;
            }
        }
    }

    /// Feeds `inbuf` (or the end of input) to rustls and processes it. On a
    /// TLS error, queues the alert rustls made and fails with what went
    /// wrong.
    fn feed(&mut self, cx: &Cx, tls: &mut ServerConnection) -> Result<(), HandshakeError> {
        if self.inbuf.is_empty() {
            if self.eof {
                // Tells rustls the input ended.
                let _ = tls.read_tls(&mut &[][..]);
            }
        } else {
            let n = tls.read_tls(&mut &self.inbuf[..]).map_err(|e| HandshakeError::Failed(e.to_string()))?;
            if n == 0 {
                return Err(HandshakeError::Failed("rustls took no bytes".into()));
            }
            self.inbuf.drain(..n);
        }
        let result = with_cx(cx, || tls.process_new_packets().map(|_| ()));
        if let Err(e) = result {
            self.take_output(tls);
            return Err(match e {
                rustls::Error::AlertReceived(alert) => HandshakeError::Alert(u8::from(alert)),
                e => HandshakeError::Failed(e.to_string()),
            });
        }
        Ok(())
    }
}

/// How a handshake failed, in more detail than [`ConnError`]: what
/// [`server_detailed`], [`ClientHello::finish_detailed`] and
/// [`serve::accept_tls`](crate::stdlib::serve::accept_tls) return, for a
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
    /// handshake was refused with `unrecognized_name`. Only from
    /// `accept_tls`.
    Rejected,
    /// The handshake did not finish by its deadline. Only from
    /// `accept_tls`.
    TimedOut,
    /// The connection underneath failed. Never [`ConnError::Cancelled`]:
    /// a cancel is [`HandshakeError::Cancelled`].
    Conn(ConnError),
    /// The [region](crate::Cx#regions) of the `Cx` passed to the call was
    /// cancelled while it waited.
    Cancelled,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Closed => f.write_str("the client closed the connection before the handshake finished"),
            HandshakeError::Alert(a) => write!(f, "the client sent alert {a}"),
            HandshakeError::Failed(why) => f.write_str(why),
            HandshakeError::Rejected => f.write_str("there is no TLS config for the name the client asked for"),
            HandshakeError::TimedOut => f.write_str("the handshake did not finish in time"),
            HandshakeError::Conn(e) => write!(f, "{e}"),
            HandshakeError::Cancelled => f.write_str("the region was cancelled"),
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
/// hello. An error of the connection underneath, such as
/// [`ConnError::Cancelled`] when `cx`'s [region](crate::Cx#regions) is
/// cancelled, comes out as it is.
pub async fn server<C: Connection>(cx: &Cx, conn: C) -> Result<ClientHello<C>, ConnError> {
    server_detailed(cx, conn).await.map_err(HandshakeError::into_conn)
}

/// [`server`], failing with how the hello went wrong.
pub async fn server_detailed<C: Connection>(cx: &Cx, conn: C) -> Result<ClientHello<C>, HandshakeError> {
    let mut io = Io::new(conn);
    let mut acceptor = Acceptor::default();
    let accepted = poll_fn(|task| {
        loop {
            if !io.inbuf.is_empty() {
                let n = acceptor.read_tls(&mut &io.inbuf[..]).map_err(|e| HandshakeError::Failed(e.to_string()))?;
                io.inbuf.drain(..n);
                match acceptor.accept() {
                    Ok(Some(accepted)) => return Poll::Ready(Ok(accepted)),
                    Ok(None) if n == 0 => return Poll::Ready(Err(HandshakeError::Failed("the hello is too large".into()))),
                    Ok(None) => continue,
                    // Not a TLS hello. Nothing is sent: the connection closes.
                    Err((e, _)) => return Poll::Ready(Err(HandshakeError::Failed(e.to_string()))),
                }
            }
            if io.eof {
                return Poll::Ready(Err(HandshakeError::Closed));
            }
            match io.poll_fill(cx, task) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await?;
    let hello = accepted.client_hello();
    let server_name = hello.server_name().map(str::to_owned);
    let alpn = hello.alpn().map(|protocols| protocols.map(<[u8]>::to_vec).collect()).unwrap_or_default();
    Ok(ClientHello { conn: io.conn, inbuf: io.inbuf, accepted, server_name, alpn })
}

/// What the client asked for, before the server has answered.
pub struct ClientHello<C> {
    conn: C,
    /// Bytes the client sent after its hello, not yet read by rustls.
    inbuf: Vec<u8>,
    accepted: rustls::server::Accepted,
    server_name: Option<String>,
    alpn: Vec<Vec<u8>>,
}

/// The `unrecognized_name` alert (112) as a fatal alert record, unencrypted,
/// as it is sent before the server's hello.
const UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

impl<C: Connection> ClientHello<C> {
    /// The name the client asked for (SNI), such as `api.stripe.com`. `None`
    /// if the client sent no name, for example when it connected to a bare
    /// IP address.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// The application protocols the client offers (ALPN), such as `h2` and
    /// `http/1.1`, in the client's order of preference.
    pub fn alpn(&self) -> Vec<&[u8]> {
        self.alpn.iter().map(Vec::as_slice).collect()
    }

    /// The connection underneath, for example to see who connected.
    pub fn inner(&self) -> &C {
        &self.conn
    }

    /// Refuses the name the client asked for: sends the `unrecognized_name`
    /// alert and closes the connection. Dropping the hello instead closes the
    /// connection with no alert.
    pub async fn reject(self, cx: &Cx) -> Result<(), ConnError> {
        use crate::stdlib::ConnectionExt;
        let mut conn = self.conn;
        conn.write_all(cx, &UNRECOGNIZED_NAME).await?;
        conn.shutdown(cx).await
    }

    /// Finishes the handshake with `config`.
    ///
    /// Fails with [`ConnError::Broken`] if the handshake fails, for example
    /// because the client rejected the certificate. An error of the
    /// connection underneath comes out as it is.
    pub async fn finish(self, cx: &Cx, config: Arc<ServerConfig>) -> Result<TlsConnection<C>, ConnError> {
        self.finish_detailed(cx, config).await.map_err(HandshakeError::into_conn)
    }

    /// [`finish`](ClientHello::finish), failing with how the handshake went
    /// wrong.
    pub async fn finish_detailed(
        self,
        cx: &Cx,
        config: Arc<ServerConfig>,
    ) -> Result<TlsConnection<C>, HandshakeError> {
        let mut io = Io { conn: self.conn, inbuf: self.inbuf, out: Vec::new(), out_pos: 0, eof: false };
        let config = crate::observe::observed_config(cx, config, self.server_name.as_deref());
        let mut tls = match with_cx(cx, || self.accepted.into_connection(config)) {
            Ok(tls) => tls,
            Err((e, mut alert)) => {
                // Best effort: tell the client why, then close.
                let _ = alert.write_all(&mut io.out);
                let _ = poll_fn(|task| io.poll_flush(cx, task)).await;
                return Err(HandshakeError::Failed(e.to_string()));
            }
        };
        let result = poll_fn(|task| {
            loop {
                io.take_output(&mut tls);
                match io.poll_flush(cx, task) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => return Poll::Pending,
                }
                if !tls.is_handshaking() {
                    return Poll::Ready(Ok(()));
                }
                if !io.inbuf.is_empty() {
                    io.feed(cx, &mut tls)?;
                    continue;
                }
                if io.eof {
                    return Poll::Ready(Err(HandshakeError::Closed));
                }
                match io.poll_fill(cx, task) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
        match result {
            Ok(()) => Ok(TlsConnection { io, tls, taken: None, closing: false }),
            Err(e) => {
                // Send the alert rustls made, if there is one.
                if !io.out.is_empty() {
                    let _ = poll_fn(|task| io.poll_flush(cx, task)).await;
                }
                Err(e)
            }
        }
    }
}

/// A finished TLS connection. Reads and writes carry the decrypted bytes.
pub struct TlsConnection<C> {
    io: Io<C>,
    tls: ServerConnection,
    /// Plaintext rustls has encrypted for an earlier `poll_write` whose
    /// output `conn` has not taken yet. Reported as taken once it has.
    taken: Option<usize>,
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
        self.tls.alpn_protocol()
    }
}

impl<C: Connection> Connection for TlsConnection<C> {
    fn poll_read(
        &mut self,
        cx: &Cx,
        task: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        // A cancel comes first, before plaintext already decrypted.
        if cx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match self.tls.reader().read(buf) {
                // Ok(0) is the client's close_notify.
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                // The client closed the connection without close_notify.
                // A server reads that as the end of input, like most do.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Poll::Ready(Ok(0)),
                Err(_) => return Poll::Ready(Err(ConnError::Broken)),
            }
            if !self.io.inbuf.is_empty() || self.io.eof {
                let eof_seen = self.io.inbuf.is_empty();
                let fed = self.io.feed(cx, &mut self.tls);
                // rustls may have something to send: a key update, a ticket
                // or an alert. Hand it on if `conn` has room now; otherwise
                // the next write or read sends it.
                self.io.take_output(&mut self.tls);
                let _ = self.io.poll_flush(cx, task);
                if fed.is_err() {
                    return Poll::Ready(Err(ConnError::Broken));
                }
                if eof_seen {
                    // The end of input was fed; the reader now says how it
                    // ended. Never loop on it twice.
                    return match self.tls.reader().read(buf) {
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::UnexpectedEof => {
                            Poll::Ready(Ok(0))
                        }
                        Err(_) => Poll::Ready(Err(ConnError::Broken)),
                    };
                }
                continue;
            }
            match self.io.poll_fill(cx, task) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Output queued by an earlier read still goes out.
                    let _ = self.io.poll_flush(cx, task);
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_write(&mut self, cx: &Cx, task: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
        if let Some(n) = self.taken {
            // The caller retries the same bytes; they are already encrypted.
            return match self.io.poll_flush(cx, task) {
                Poll::Ready(Ok(())) => {
                    self.taken = None;
                    Poll::Ready(Ok(n))
                }
                other => other.map(|r| r.map(|()| 0)),
            };
        }
        if self.closing {
            return Poll::Ready(Err(ConnError::Closed));
        }
        match self.io.poll_flush(cx, task) {
            Poll::Ready(Ok(())) => {}
            other => return other.map(|r| r.map(|()| 0)),
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &data[..data.len().min(WRITE_CHUNK)];
        let n = match self.tls.writer().write(chunk) {
            Ok(0) | Err(_) => return Poll::Ready(Err(ConnError::Closed)),
            Ok(n) => n,
        };
        self.io.take_output(&mut self.tls);
        match self.io.poll_flush(cx, task) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                self.taken = Some(n);
                Poll::Pending
            }
        }
    }

    /// Sends `close_notify`, then shuts down the connection underneath.
    fn poll_shutdown(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        if !self.closing {
            self.closing = true;
            self.tls.send_close_notify();
            self.io.take_output(&mut self.tls);
        }
        match self.io.poll_flush(cx, task) {
            Poll::Ready(Ok(())) => self.io.conn.poll_shutdown(cx, task),
            other => other,
        }
    }

    fn poll_gone(&self, task: &mut Context<'_>) -> Poll<()> {
        self.io.conn.poll_gone(task)
    }
}
