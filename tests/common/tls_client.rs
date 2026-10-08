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
use std::time::Duration;

pub const DATE: u64 = 1_893_456_000;
struct Clock(Cx);
impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Clock")
    }
}
impl rustls::time_provider::TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            Duration::from_secs(DATE) + self.0.now().since_start(),
        ))
    }
}
pub struct TlsClient<C> {
    pub conn: C,
    pub tls: ClientConnection,
    out: Vec<u8>,
    inbuf: Box<[u8]>,
    /// Bytes read from `conn` that rustls could not take yet, because its
    /// plaintext buffer was full.
    pending: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum TlsError {
    Conn(ConnError),
    Tls(rustls::Error),
}

impl<C: Connection + Unpin> TlsClient<C> {
    pub fn new(fcx: &Cx, conn: C, roots: &Arc<RootCertStore>, name: &str, alpn: &[&[u8]]) -> Self {
        let mut config = ClientConfig::builder_with_details(
            Arc::new(tls::crypto_provider()),
            Arc::new(Clock(fcx.clone())),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let tls = tls::with_context(fcx, || {
            ClientConnection::new(
                Arc::new(config),
                ServerName::try_from(name.to_owned()).unwrap(),
            )
        })
        .unwrap();
        TlsClient::with(conn, tls)
    }

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
        if let Poll::Ready(Err(e)) = self.poll_flush(fcx, cx) {
            return Poll::Ready(Err(e));
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
