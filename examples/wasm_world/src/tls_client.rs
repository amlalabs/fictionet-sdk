//! The sandbox's side of TLS: a rustls client over a stdlib connection.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::task::{Context, Poll};

use fictionet::Cx;
use fictionet::stdlib::{ConnError, Connection};
use rustls::ClientConnection;

/// A TLS client connection over `C`, itself a [`Connection`].
pub(crate) struct TlsClient<C> {
    conn: C,
    tls: ClientConnection,
    /// TLS bytes not yet written to `conn`.
    out: Vec<u8>,
    inbuf: Box<[u8]>,
}

impl<C: Connection> TlsClient<C> {
    pub(crate) fn new(
        conn: C,
        config: Arc<rustls::ClientConfig>,
        name: &str,
    ) -> fictionet::Result<Self> {
        let tls = ClientConnection::new(config, name.to_owned().try_into()?)?;
        Ok(TlsClient {
            conn,
            tls,
            out: Vec::new(),
            inbuf: vec![0; 16 * 1024].into_boxed_slice(),
        })
    }

    /// Finishes the handshake.
    pub(crate) async fn handshake(&mut self, fcx: &Cx) -> Result<(), ConnError> {
        std::future::poll_fn(|cx| {
            loop {
                match self.poll_flush(fcx, cx) {
                    Poll::Ready(Ok(())) => {}
                    other => return other,
                }
                if !self.tls.is_handshaking() {
                    return Poll::Ready(Ok(()));
                }
                match self.poll_fill(fcx, cx) {
                    Poll::Ready(Ok(true)) => {}
                    Poll::Ready(Ok(false)) => return Poll::Ready(Err(ConnError::Closed)),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
    }

    /// Writes out what rustls has to send.
    fn poll_flush(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        loop {
            if self.out.is_empty() {
                if !self.tls.wants_write() {
                    return Poll::Ready(Ok(()));
                }
                self.tls
                    .write_tls(&mut self.out)
                    .map_err(|_| ConnError::Broken)?;
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

    /// Reads once from the connection into rustls. `Ok(false)` at the end
    /// of the stream.
    fn poll_fill(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<bool, ConnError>> {
        let n = match self.conn.poll_read(fcx, cx, &mut self.inbuf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let mut data = &self.inbuf[..n];
        loop {
            // The world's records are small, and the reader takes the
            // plaintext as it comes, so rustls always has room here.
            self.tls
                .read_tls(&mut data)
                .map_err(|_| ConnError::Broken)?;
            self.tls
                .process_new_packets()
                .map_err(|_| ConnError::Broken)?;
            if data.is_empty() {
                return Poll::Ready(Ok(n > 0));
            }
        }
    }
}

impl<C: Connection> Connection for TlsClient<C> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        // A cancel comes first, before plaintext already decrypted.
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
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
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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
        let n = self
            .tls
            .writer()
            .write(data)
            .map_err(|_| ConnError::Broken)?;
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
