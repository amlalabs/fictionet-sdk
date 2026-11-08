use std::collections::VecDeque;
use std::task::{Context, Poll};

use fictionet::Cx;
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Chunk, Layer, StreamCommand, StreamEvent,
};
use fictionet::stdlib::network::{ConnError, Connection};

use super::live::{Halt, Live};
use super::{Job, StackError, StreamEnd, StreamLimits};

/// The most decrypted, decoded or otherwise delivered bytes an opened
/// stack holds for its reader before the stack's input waits.
const ROOM: usize = 64 * 1024;
/// The most bytes one write offers the stack.
const WRITE: usize = 16 * 1024;

/// A stack with a byte stream above it, run over a live connection, as a
/// [`Connection`]: reads are the stack's bytes from above, and writes go
/// down through it. TLS over TCP opened this way is a connection that
/// carries the decrypted bytes.
///
/// Reading or writing moves the stack and the connection underneath on,
/// with the same runner as [`stream`](super::stream). A write returns once
/// the stack reports its bytes written ([`StreamEvent::Written`] from
/// above), so a write that returns has crossed every layer and the
/// transport took what they made of it. A write dropped before it returned
/// stays the stack's: the next write that starts with the same bytes is
/// told they were written once they are, and is not sent again. Bytes the
/// stack delivers wait for a read, up to 64 KiB; past that the stack's
/// input waits, and with it the peer.
pub struct Opened<L: Layer<Lower = ByteStream, Upper = ByteStream>, C> {
    live: Live<L, C>,
    above: Above,
    /// The bytes of a write that returned `Pending`, until the stack
    /// reports them written.
    pending: Option<Chunk>,
    /// End went to the stack.
    closing: bool,
}

/// What came up from the stack and has not been read.
#[derive(Default)]
struct Above {
    bytes: VecDeque<Chunk>,
    len: usize,
    /// The stack reported this many bytes written.
    written: u64,
    ended: bool,
    reset: bool,
}

impl Above {
    fn take(&mut self, event: StreamEvent) -> Admit<StreamEvent> {
        match event {
            StreamEvent::Data(chunk) if self.len >= ROOM => {
                Admit::Blocked(StreamEvent::Data(chunk))
            }
            StreamEvent::Data(chunk) => {
                self.len += chunk.len();
                self.bytes.push_back(chunk);
                Admit::Taken
            }
            StreamEvent::Written(n) => {
                self.written += n;
                Admit::Taken
            }
            StreamEvent::Ended => {
                self.ended = true;
                Admit::Taken
            }
            StreamEvent::Reset => {
                self.ended = true;
                self.reset = true;
                Admit::Taken
            }
        }
    }
}

impl<L, C> Opened<L, C>
where
    L: Layer<Lower = ByteStream, Upper = ByteStream>,
    L::Work: Job<Done = L::Done>,
    L::Error: Into<ConnError>,
    C: Connection,
{
    /// Runs `stack` over `conn` in the world of `fcx`, charging `budget`,
    /// with no idle or write limit: the connection's user decides how long
    /// to wait.
    pub fn new(fcx: &Cx, conn: C, stack: L, budget: Budget) -> Opened<L, C> {
        let limits = StreamLimits {
            idle: None,
            write_timeout: None,
        };
        Opened {
            live: Live::new(fcx, conn, stack, budget, limits),
            above: Above::default(),
            pending: None,
            closing: false,
        }
    }

    /// The stack.
    pub fn stack(&self) -> &L {
        self.live.stack()
    }

    /// The connection underneath.
    pub fn conn(&self) -> &C {
        self.live.conn()
    }

    /// Moves the stack and its connection on until nothing more can move
    /// now. `Pending` while it waits, with `cx` woken when it can move
    /// again; `Ready` when reading or writing the connection failed, which
    /// polling again retries, or with how the run ended: the stack's own
    /// error the first time it gives up.
    pub(crate) fn poll_run(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Halt, StackError<L::Error>>> {
        let above = &mut self.above;
        self.live
            .poll(fcx, cx, &mut |event| above.take(event), &mut |_| {})
    }

    /// Runs the stack, with a failure as the connection's error.
    fn pump(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Result<(), ConnError> {
        match self.poll_run(fcx, cx) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(Halt::Conn(e))) => Err(e),
            Poll::Ready(Ok(Halt::End(StreamEnd::Conn(e)))) => Err(e),
            Poll::Ready(Ok(Halt::End(StreamEnd::Reset))) => Err(ConnError::Reset),
            Poll::Ready(Ok(Halt::End(_))) => Err(ConnError::Broken),
            Poll::Ready(Err(StackError::Cancelled)) => Err(ConnError::Cancelled),
            Poll::Ready(Err(StackError::Layer(e))) => Err(e.into()),
        }
    }

    /// Reads what the stack delivered into `buf`, if it delivered anything,
    /// or its end.
    fn deliver(&mut self, buf: &mut [u8]) -> Option<Result<usize, ConnError>> {
        if let Some(chunk) = self.above.bytes.front_mut() {
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            chunk.advance(n);
            if chunk.is_empty() {
                self.above.bytes.pop_front();
            }
            self.above.len -= n;
            return Some(Ok(n));
        }
        if self.above.reset {
            return Some(Err(ConnError::Reset));
        }
        self.above.ended.then_some(Ok(0))
    }

    /// Takes `n` bytes of what the stack reported written, if it reported
    /// that many.
    fn credit(&mut self, n: usize) -> bool {
        if self.above.written < n as u64 {
            return false;
        }
        self.above.written -= n as u64;
        true
    }
}

impl<L, C> Connection for Opened<L, C>
where
    L: Layer<Lower = ByteStream, Upper = ByteStream> + Send + 'static,
    L::Work: Job<Done = L::Done>,
    L::Error: Into<ConnError>,
    L::Report: Send,
    C: Connection,
{
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
        // What came before goes first; a failure comes before what this
        // call brings.
        if let Some(read) = self.deliver(buf) {
            return Poll::Ready(read);
        }
        self.pump(fcx, cx)?;
        match self.deliver(buf) {
            Some(read) => Poll::Ready(read),
            None => Poll::Pending,
        }
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
        self.pump(fcx, cx)?;
        if let Some(previous) = self.pending.take() {
            if !self.credit(previous.len()) {
                self.pending = Some(previous);
                return Poll::Pending;
            }
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
        let n = data.len().min(WRITE);
        let budget = self.live.driver().budget().clone();
        let charge = budget.charge(n).ok_or(ConnError::Broken)?;
        let kept = budget.charge(n).ok_or(ConnError::Broken)?;
        let command = StreamCommand::Write(Chunk::with_charge(data[..n].to_vec(), charge));
        let taken = match self.live.driver().command(command).map_err(Into::into)? {
            Admit::Taken => n,
            Admit::Partial(StreamCommand::Write(rest)) => n - rest.len(),
            Admit::Closed(_) => return Poll::Ready(Err(ConnError::Closed)),
            Admit::Blocked(_) => return Poll::Pending,
            Admit::Partial(_) => return Poll::Ready(Err(ConnError::Broken)),
        };
        // A retry is matched by content: a dropped write leaves nothing
        // else that a later call could name.
        self.pending = Some(Chunk::with_charge(data[..taken].to_vec(), kept));
        self.pump(fcx, cx)?;
        if !self.credit(taken) {
            return Poll::Pending;
        }
        self.pending = None;
        Poll::Ready(Ok(taken))
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        self.pump(fcx, cx)?;
        if !self.closing {
            match self
                .live
                .driver()
                .command(StreamCommand::End)
                .map_err(Into::into)?
            {
                Admit::Taken | Admit::Closed(_) => self.closing = true,
                _ => return Poll::Pending,
            }
            self.pump(fcx, cx)?;
        }
        if self.live.shut() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.live.conn().poll_gone(cx)
    }
}
