//! Ciphertext delivery for the sandbox TLS client.

use super::ConnectionCommon;
use fictionet::Cx;
use fictionet::stdlib::network::{ConnError, Connection};
use std::task::{Context, Poll};

/// Ciphertext waiting for the connection underneath.
#[derive(Default)]
pub(crate) struct Output {
    /// Encrypted bytes for the connection, not yet taken from `pos` onward.
    pub(crate) bytes: Vec<u8>,
    pos: usize,
}

impl Output {
    /// Moves what rustls wants to send into `bytes`.
    pub(crate) fn take_output<Data>(
        &mut self,
        tls: &mut ConnectionCommon<Data>,
    ) -> Result<(), ConnError> {
        while tls.wants_write() {
            tls.write_tls(&mut self.bytes)
                .map_err(|_| ConnError::Broken)?;
        }
        Ok(())
    }

    /// Hands all queued ciphertext to the connection underneath, and
    /// flushes it.
    #[must_use = "transport failures and backpressure must be handled"]
    pub(crate) fn poll_flush<C: Connection>(
        &mut self,
        conn: &mut C,
        fcx: &Cx,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnError>> {
        while self.pos < self.bytes.len() {
            match conn.poll_write(fcx, cx, &self.bytes[self.pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(ConnError::Closed)),
                Poll::Ready(Ok(n)) => self.pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.bytes.clear();
        self.pos = 0;
        conn.poll_flush(fcx, cx)
    }

    /// A read can defer output when there is no room, but must report failure.
    #[must_use = "a read must report transport output failures"]
    pub(crate) fn flush_for_read<C: Connection>(
        &mut self,
        conn: &mut C,
        fcx: &Cx,
        cx: &mut Context<'_>,
    ) -> Result<(), ConnError> {
        match self.poll_flush(conn, fcx, cx) {
            Poll::Ready(Err(e)) => Err(e),
            Poll::Ready(Ok(())) | Poll::Pending => Ok(()),
        }
    }
}
