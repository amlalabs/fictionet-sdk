//! Clients for machines that play a sandbox in a simulated network.
//!
//! [`machine`] splits a cable into TCP, UDP, and ICMP. DNS queries and
//! TLS handshakes use the run's clock and randomness.

use fictionet::stdlib::dns::op::{Message, Query};
use fictionet::stdlib::dns::rr::{Name, RecordType};
use fictionet::stdlib::{dns, ip, tcp, udp};
use fictionet::{End, Error, Interface};
use std::net::{IpAddr, SocketAddr};

/// TCP, UDP, and ICMP on one sandbox cable.
pub struct Machine {
    /// The machine's TCP endpoint.
    pub tcp: tcp::Endpoint,
    /// The machine's UDP endpoint.
    pub udp: udp::Endpoint,
    /// The machine's ICMP packets.
    pub icmp: End,
}

/// Builds a machine at `addr` on a cable.
pub fn machine(fcx: &Cx, end: impl Interface, addr: impl Into<IpAddr>) -> Machine {
    let addr = addr.into();
    let (t, u, icmp, _) = ip::split_protocols(fcx, end);
    Machine {
        tcp: tcp::endpoint(fcx, t, addr),
        udp: udp::endpoint(fcx, u, addr),
        icmp,
    }
}

impl Machine {
    /// Queries a DNS server, waiting for an answer with this query's ID.
    /// Cancellation ends the wait. The caller can impose a shorter deadline.
    pub async fn lookup(
        &self,
        fcx: &Cx,
        server: IpAddr,
        name: &str,
        kind: RecordType,
    ) -> Result<Message, Error> {
        let mut socket = self.udp.bind(0)?;
        let mut query = Message::query();
        query.metadata.id = fcx.random_u64() as u16;
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(name)?, kind));
        let to = SocketAddr::new(server, 53);
        socket.send_to(&query.to_vec()?, to);
        loop {
            let (bytes, from) = socket.recv(fcx).await?;
            if from != to {
                continue;
            }
            let answer = Message::from_vec(&bytes)?;
            if answer.metadata.id == query.metadata.id
                && answer.metadata.message_type == dns::op::MessageType::Response
            {
                return Ok(answer);
            }
        }
    }
}

use fictionet::{
    Cx,
    stdlib::{ConnError, Connection, tls},
};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::future::poll_fn;
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

struct Clock(Cx, std::time::SystemTime);
impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Clock")
    }
}
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            self.1.duration_since(std::time::UNIX_EPOCH).ok()? + self.0.now().since_start(),
        ))
    }
}
/// A rustls client carried by a simulated connection.
pub struct TlsClient<C> {
    /// The underlying connection.
    pub conn: C,
    /// The TLS session.
    pub tls: ClientConnection,
    out: Vec<u8>,
    inbuf: Box<[u8]>,
    /// Bytes read from `conn` that rustls could not take yet, because its
    /// plaintext buffer was full.
    pending: Vec<u8>,
}

#[derive(Debug)]
/// A TLS handshake failure.
pub enum TlsError {
    /// The underlying connection failed.
    Conn(ConnError),
    /// TLS verification or framing failed.
    Tls(rustls::Error),
}

impl<C: Connection + Unpin> TlsClient<C> {
    /// Creates a client with trusted roots and the world's starting date.
    pub fn new(
        fcx: &Cx,
        conn: C,
        roots: &Arc<RootCertStore>,
        name: &str,
        alpn: &[&[u8]],
        start: SystemTime,
    ) -> Self {
        let config = client_config(fcx, start, Some(roots), alpn);
        let tls = tls::with_context(fcx, || {
            ClientConnection::new(config, ServerName::try_from(name.to_owned()).unwrap())
        })
        .unwrap();
        TlsClient::with(conn, tls)
    }

    /// Wraps an existing TLS session.
    pub fn with(conn: C, tls: ClientConnection) -> Self {
        TlsClient {
            conn,
            tls,
            out: Vec::new(),
            inbuf: vec![0; 4096].into_boxed_slice(),
            pending: Vec::new(),
        }
    }

    fn poll_flush(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        loop {
            if self.out.is_empty() {
                if !self.tls.wants_write() {
                    return Poll::Ready(Ok(()));
                }
                self.tls.write_tls(&mut self.out).unwrap();
            }
            match self.conn.poll_write(fcx, cx, &self.out) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(ConnError::Closed)),
                Poll::Ready(Ok(n)) => {
                    self.out.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Reads from the connection into rustls once. `Ok(false)` at the end
    /// of the stream.
    fn poll_fill(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<bool, TlsError>> {
        let fresh;
        let mut data: &[u8] = if !self.pending.is_empty() {
            fresh = std::mem::take(&mut self.pending);
            &fresh
        } else {
            let n = match self.conn.poll_read(fcx, cx, &mut self.inbuf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(TlsError::Conn(e))),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                let _ = self.tls.read_tls(&mut &[][..]);
            }
            &self.inbuf[..n]
        };
        let n = data.len();
        loop {
            if !data.is_empty() && self.tls.read_tls(&mut data).is_err() {
                // The plaintext buffer is full: the reader must take some
                // first.
                self.pending = data.to_vec();
                return Poll::Ready(Ok(true));
            }
            let r = tls::with_context(fcx, || self.tls.process_new_packets());
            if let Err(e) = r {
                // Send our alert, best effort.
                let _ = self.poll_flush(fcx, cx);
                return Poll::Ready(Err(TlsError::Tls(e)));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(n > 0));
            }
        }
    }

    /// Completes the TLS handshake.
    pub async fn handshake(&mut self, fcx: &Cx) -> Result<(), TlsError> {
        poll_fn(|cx| {
            loop {
                match self.poll_flush(fcx, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(TlsError::Conn(e))),
                    Poll::Pending => return Poll::Pending,
                }
                if !self.tls.is_handshaking() {
                    return Poll::Ready(Ok(()));
                }
                match self.poll_fill(fcx, cx) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) => {
                        return Poll::Ready(Err(TlsError::Conn(ConnError::Closed)));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
    }
}

impl<C: Connection + Unpin> Connection for TlsClient<C> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Poll::Ready(Ok(0)),
                Err(_) => return Poll::Ready(Err(ConnError::Broken)),
            }
            if let Poll::Ready(Err(e)) = self.poll_flush(fcx, cx) {
                return Poll::Ready(Err(e));
            }
            match self.poll_fill(fcx, cx) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => {
                    return match self.tls.reader().read(buf) {
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(_) => Poll::Ready(Ok(0)),
                    };
                }
                Poll::Ready(Err(_)) => return Poll::Ready(Err(ConnError::Broken)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        match self.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let n = self.tls.writer().write(data).unwrap();
        let _ = self.poll_flush(fcx, cx);
        Poll::Ready(Ok(n))
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.tls.send_close_notify();
        match self.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => self.conn.poll_shutdown(fcx, cx),
            other => other,
        }
    }
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conn(e) => e.fmt(f),
            Self::Tls(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for TlsError {}

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::CertificateDer;
use rustls::{DigitallySignedStruct, SignatureScheme};
/// Accepts any certificate: an agent that runs `curl -k`.
#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The client's TLS: verify against `roots`, or not at all.
pub fn client_config(
    fcx: &Cx,
    start: SystemTime,
    roots: Option<&Arc<RootCertStore>>,
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_details(
        Arc::new(tls::crypto_provider()),
        Arc::new(Clock(fcx.clone(), start)),
    )
    .with_safe_default_protocol_versions()
    .unwrap();
    let mut config = match roots {
        Some(roots) => builder
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
        None => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

impl Machine {
    /// Connects with TLS. With no roots, the client accepts any certificate.
    /// `start` supplies the world's date for certificate verification.
    pub async fn tls(
        &self,
        fcx: &Cx,
        to: SocketAddr,
        name: &str,
        roots: Option<&Arc<RootCertStore>>,
        start: SystemTime,
    ) -> Result<TlsClient<tcp::TcpConnection>, Error> {
        let config = client_config(fcx, start, roots, &[b"http/1.1"]);
        self.tls_with_config(fcx, to, name, config).await
    }

    /// Connects with a client configuration, including its ALPN preferences.
    pub async fn tls_with_config(
        &self,
        fcx: &Cx,
        to: SocketAddr,
        name: &str,
        config: Arc<ClientConfig>,
    ) -> Result<TlsClient<tcp::TcpConnection>, Error> {
        let conn = self.tcp.connect(fcx, to).await?;
        let name = ServerName::try_from(name.to_owned())?;
        let session = tls::with_context(fcx, || ClientConnection::new(config, name))?;
        let mut client = TlsClient::with(conn, session);
        client.handshake(fcx).await?;
        Ok(client)
    }
}

/// Sends one HTTP/1.1 request and reads its final response.
/// The decoder bounds the response with the HTTP module's default limits.
pub async fn request(
    fcx: &Cx,
    conn: &mut impl Connection,
    request: &fictionet::stdlib::http1::Request,
) -> Result<fictionet::stdlib::http1::Response, Error> {
    use fictionet::stdlib::codec::{Stream, Wire};
    use fictionet::stdlib::{ConnectionExt, http1};
    let mut decoder = http1::Responses::new();
    decoder.expect_method(&request.head.method)?;
    let mut stream = Stream::new(decoder);
    conn.write_all(fcx, &request.to_bytes()?).await?;
    let mut buf = [0; 4096];
    loop {
        while let Some(response) = stream.next() {
            let response = response.map_err(|e| Error::msg(format!("HTTP response: {e:?}")))?;
            if response.head.status >= 200 || response.head.status == 101 {
                return Ok(response);
            }
        }
        if stream.is_done() {
            return Err(Error::msg("connection ended before an HTTP response"));
        }
        let n = conn.read(fcx, &mut buf).await?;
        if n == 0 {
            stream.end();
        } else if stream.push(&buf[..n]) != n {
            return Err(Error::msg("HTTP response exceeds the buffer limit"));
        }
    }
}
