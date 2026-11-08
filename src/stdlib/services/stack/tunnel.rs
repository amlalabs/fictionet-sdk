use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use super::Job;
use fictionet::Cx;
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Chunk, CommandOf, Env, EventOf, Layer, StreamCommand, StreamEvent,
    Top,
};
use fictionet::stdlib::network::{ConnError, Connection};
use fictionet::sync::Mutex;

/// The most bytes each way a tunnel holds before it stops taking more.
const ROOM: usize = 64 * 1024;

type Start =
    Box<dyn FnOnce(Cx, Box<dyn Connection>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// Hands a byte stream to async code that wants a [`Connection`]: what
/// runs after a CONNECT or a WebSocket upgrade, written against a
/// connection rather than as a layer.
///
/// The tunnel is a layer with a byte stream below and nothing above. Its one
/// piece of work runs the code with a connection whose reads are the
/// stream's bytes from below and whose writes go down the stream, so the
/// code runs over whatever carries the stream: TCP, TLS, or a CONNECT
/// inside TLS. Each way holds at most 64 KiB; past that, the stream's input
/// waits and the code's writes wait. Dropping the connection ends the
/// stream's direction, and the stream's end or reset reaches the code's
/// reads. What the code writes is charged to the stack's budget.
pub struct Tunnel {
    shared: Arc<Mutex<Shared>>,
    takeover: Option<Start>,
}

struct Shared {
    /// Bytes from below the code has not read.
    inbound: VecDeque<Chunk>,
    inbound_len: usize,
    /// The peer sent everything.
    ended: bool,
    /// The stream was reset, or the tunnel is gone.
    reset: bool,
    /// Bytes the code wrote that have not gone down.
    outbound: VecDeque<Chunk>,
    outbound_len: usize,
    /// The code will write nothing more.
    finished: bool,
    /// The application released its connection.
    released: bool,
    /// `End` went down.
    end_sent: bool,
    budget: Option<Budget>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    gone: Option<Waker>,
    /// Whatever runs the stack, to wake when the code writes from
    /// elsewhere.
    runner: Option<Waker>,
}

impl Shared {
    fn wake_code(&mut self) {
        for waker in [self.reader.take(), self.writer.take(), self.gone.take()]
            .into_iter()
            .flatten()
        {
            waker.wake();
        }
    }

    fn wake_runner(&mut self) {
        if let Some(waker) = &self.runner {
            waker.wake_by_ref();
        }
    }
}

impl Tunnel {
    /// A tunnel that runs `takeover` with the context of the world and the
    /// stream as a connection.
    pub fn new<F, Fut>(takeover: F) -> Tunnel
    where
        F: FnOnce(Cx, Box<dyn Connection>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Tunnel {
            shared: Arc::new(Mutex::new(Shared {
                inbound: VecDeque::new(),
                inbound_len: 0,
                ended: false,
                reset: false,
                outbound: VecDeque::new(),
                outbound_len: 0,
                finished: false,
                released: false,
                end_sent: false,
                budget: None,
                reader: None,
                writer: None,
                gone: None,
                runner: None,
            })),
            takeover: Some(Box::new(move |fcx, conn| Box::pin(takeover(fcx, conn)))),
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        let mut shared = self.shared.lock();
        shared.reset = true;
        shared.wake_code();
    }
}

impl Layer for Tunnel {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Takeover;
    type Done = ();
    type Error = Infallible;

    fn is_terminal(&self) -> bool {
        self.shared.lock().released
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        let mut shared = self.shared.lock();
        shared.budget.get_or_insert_with(|| env.budget().clone());
        match event {
            StreamEvent::Data(chunk) => {
                if shared.reset || shared.ended {
                    return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                }
                if shared.inbound_len >= ROOM {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                shared.inbound_len += chunk.len();
                shared.inbound.push_back(chunk);
            }
            StreamEvent::Written(_) => {}
            StreamEvent::Ended => shared.ended = true,
            StreamEvent::Reset => shared.reset = true,
        }
        shared.wake_code();
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: CommandOf<Top>,
    ) -> Result<Admit<CommandOf<Top>>, Infallible> {
        match command {}
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        let mut shared = self.shared.lock();
        if shared.budget.is_none() {
            shared.budget = Some(env.budget().clone());
            return Ok(true);
        }
        Ok(false)
    }

    fn take_command(&mut self) -> Option<StreamCommand> {
        let mut shared = self.shared.lock();
        if let Some(chunk) = shared.outbound.pop_front() {
            shared.outbound_len -= chunk.len();
            if let Some(waker) = shared.writer.take() {
                waker.wake();
            }
            return Some(StreamCommand::Write(chunk));
        }
        if shared.finished && !shared.end_sent && !shared.reset {
            shared.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<EventOf<Top>> {
        None
    }

    fn take_work(&mut self) -> Option<Takeover> {
        // The code starts once the tunnel knows what to charge its writes to.
        self.shared.lock().budget.as_ref()?;
        let takeover = self.takeover.take()?;
        Some(Takeover {
            takeover: Some(takeover),
            running: None,
            shared: self.shared.clone(),
        })
    }
}

/// The work of a [`Tunnel`]: the code that took the stream over.
pub struct Takeover {
    takeover: Option<Start>,
    running: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    shared: Arc<Mutex<Shared>>,
}

impl Job for Takeover {
    type Done = ();

    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<()> {
        self.shared.lock().runner = Some(cx.waker().clone());
        if let Some(takeover) = self.takeover.take() {
            let Some(fcx) = fcx else {
                // Nothing can take the stream over without a world.
                let mut shared = self.shared.lock();
                shared.finished = true;
                shared.released = true;
                return Poll::Ready(());
            };
            let conn = Box::new(TunnelConn {
                shared: self.shared.clone(),
            });
            self.running = Some(takeover(fcx.clone(), conn));
        }
        match &mut self.running {
            Some(running) => running.as_mut().poll(cx),
            None => Poll::Ready(()),
        }
    }
}

/// The stream as the code sees it.
struct TunnelConn {
    shared: Arc<Mutex<Shared>>,
}

impl Connection for TunnelConn {
    fn poll_read(
        &mut self,
        _: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        let mut shared = self.shared.lock();
        if let Some(chunk) = shared.inbound.front_mut() {
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            chunk.advance(n);
            if chunk.is_empty() {
                shared.inbound.pop_front();
            }
            shared.inbound_len -= n;
            // There is room for more from below.
            shared.wake_runner();
            return Poll::Ready(Ok(n));
        }
        if shared.reset {
            return Poll::Ready(Err(ConnError::Reset));
        }
        if shared.ended {
            return Poll::Ready(Ok(0));
        }
        shared.reader = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_write(
        &mut self,
        _: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        let mut shared = self.shared.lock();
        if shared.reset {
            return Poll::Ready(Err(ConnError::Reset));
        }
        if shared.finished {
            return Poll::Ready(Err(ConnError::Closed));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let room = ROOM.saturating_sub(shared.outbound_len);
        if room == 0 {
            shared.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(data.len());
        let charge = match &shared.budget {
            Some(budget) => match budget.charge(n) {
                Some(charge) => Some(charge),
                None => return Poll::Ready(Err(ConnError::Closed)),
            },
            None => None,
        };
        let bytes = data[..n].to_vec();
        let chunk = match charge {
            Some(charge) => Chunk::with_charge(bytes, charge),
            None => Chunk::new(bytes),
        };
        shared.outbound_len += n;
        shared.outbound.push_back(chunk);
        shared.wake_runner();
        Poll::Ready(Ok(n))
    }

    fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        let mut shared = self.shared.lock();
        shared.finished = true;
        shared.wake_runner();
        Poll::Ready(Ok(()))
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut shared = self.shared.lock();
        if shared.reset {
            return Poll::Ready(());
        }
        shared.gone = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for TunnelConn {
    fn drop(&mut self) {
        let mut shared = self.shared.lock();
        shared.finished = true;
        shared.released = true;
        shared.wake_runner();
    }
}
