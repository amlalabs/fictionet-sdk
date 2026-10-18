//! Ciphertext delivery and plaintext credit shared by the TLS adapters.

use fictionet::Cx;
use fictionet::stdlib::network::{ConnError, Connection};
use rustls::ConnectionCommon;
use std::task::{Context, Poll};

/// Ciphertext waiting for the connection underneath, and the write it completes.
#[derive(Default)]
pub(crate) struct Output {
    /// Encrypted bytes for the connection, not yet taken from `pos` onward.
    pub(crate) bytes: Vec<u8>,
    pos: usize,
    /// Plaintext encrypted for a pending write, credited once its output is sent.
    taken: Option<Vec<u8>>,
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

    /// Hands all queued ciphertext to the connection underneath.
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
        Poll::Ready(Ok(()))
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

    /// Finishes an earlier write, crediting it only if these are its bytes.
    pub(crate) fn poll_credit<C: Connection>(
        &mut self,
        conn: &mut C,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<Option<usize>, ConnError>> {
        let Some(previous) = self.taken.as_ref() else {
            return Poll::Ready(Ok(None));
        };
        let same = data.starts_with(previous);
        let n = previous.len();
        match self.poll_flush(conn, fcx, cx) {
            Poll::Ready(Ok(())) => {
                self.taken = None;
                Poll::Ready(Ok(same.then_some(n)))
            }
            other => other.map(|r| r.map(|()| None)),
        }
    }

    /// Reports newly encrypted plaintext only once its ciphertext is taken.
    pub(crate) fn poll_written<C: Connection>(
        &mut self,
        conn: &mut C,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        match self.poll_flush(conn, fcx, cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(data.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                self.taken = Some(data.to_vec());
                Poll::Pending
            }
        }
    }
}
