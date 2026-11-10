use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, ChargedBytes, Chunk, Driver, EventOf, Layer, StreamCommand,
    StreamEvent,
};
use fictionet::stdlib::network::{ConnError, Connection, Read};
use fictionet::{Cx, Timer};

use super::job::Jobs;
use super::lifetime::{Expiry, Lifetime, Outstanding};
use super::{Job, StackError, StreamEnd, StreamLimits};

/// How big each read is. The buffer is charged to the connection's budget
/// before anything is read into it, and kept from read to read.
pub(super) const READ: usize = 16 * 1024;

/// How many rounds one poll makes before it lets the rest of the world
/// run.
const ROUNDS: usize = 64;

/// Why [`Live::poll`] stopped before it had to wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Halt {
    /// Reading or writing the connection failed with this. Nothing else
    /// changed: the stack has not heard, a write that failed is still held,
    /// and polling again tries again. A runner that gives up on the
    /// connection says so with [`Live::broken`].
    Conn(ConnError),
    /// The run ended, and keeps answering this.
    End(StreamEnd),
}

/// A stack running over a live connection: the one place a stream stack
/// meets the runtime.
///
/// Each [`poll`](Self::poll) reads the connection into the stack while the
/// stack takes what it read before, writes what the stack hands below as
/// far as the connection takes it, flushes the connection and reports each
/// byte flushed once as [`StreamEvent::Written`], polls the stack's work
/// and gives back what finished, fires the stack's due timers, and keeps
/// the limits. Then it waits for whichever of those can move next, or, if
/// the budget refused a charge in the last round, for memory to free.
/// Bytes read are paid for before the stack sees them; without room to
/// pay, the read buffer that already paid for them goes with them, and the
/// next read waits for memory to pay for a new buffer, leaving the bytes
/// in the connection meanwhile. The stack stays synchronous:
/// this only translates readiness, so it behaves the same here as in a
/// [`Harness`](fictionet::stdlib::layer::Harness).
///
/// [`stream`](super::stream) polls one until its stack is done;
/// [`Opened`](super::Opened) polls one whenever its connection is read,
/// written or flushed.
pub(super) struct Live<L: Layer<Lower = ByteStream>, C> {
    conn: C,
    driver: Driver<L>,
    jobs: Jobs<L::Work>,
    /// The read buffer, [`READ`] bytes paid for: `None` once it went to
    /// the stack with bytes there was no room to pay a copy of, until the
    /// budget has room for a new one.
    buf: Option<ChargedBytes>,
    /// Read and not yet taken by the stack.
    input: Option<StreamEvent>,
    /// Taken by the connection and not yet flushed.
    unflushed: u64,
    /// Flushed to the transport and not yet reported to the stack.
    unreported: u64,
    /// The idle and write limits, and the ends of both directions.
    lifetime: Lifetime,
    /// Armed for the next deadline, and moved as it moves.
    timer: Option<Timer>,
    /// How the run ended, once it has.
    stopped: Option<StreamEnd>,
}

impl<L, C> Live<L, C>
where
    L: Layer<Lower = ByteStream>,
    L::Work: Job<Done = L::Done>,
    C: Connection,
{
    /// Runs `stack` over `conn` in the world of `fcx`, charging `budget`.
    /// A budget without room for the read buffer at the start never runs
    /// the stack: the run ends with [`StreamEnd::Budget`].
    pub(super) fn new(
        fcx: &Cx,
        conn: C,
        stack: L,
        budget: Budget,
        limits: StreamLimits,
    ) -> Live<L, C> {
        let buf = read_buffer(&budget);
        Live {
            conn,
            jobs: Jobs::new(&budget),
            driver: Driver::new(stack, Arc::new(fcx.clone()), budget, fcx.now()),
            stopped: buf.is_none().then_some(StreamEnd::Budget),
            buf,
            input: None,
            unflushed: 0,
            unreported: 0,
            lifetime: Lifetime::new(limits),
            timer: None,
        }
    }

    pub(super) fn conn(&self) -> &C {
        &self.conn
    }

    pub(super) fn driver(&mut self) -> &mut Driver<L> {
        &mut self.driver
    }

    pub(super) fn stack(&self) -> &L {
        self.driver.layer()
    }

    /// Whether the stack's end of its direction went out.
    pub(super) fn shut(&self) -> bool {
        self.lifetime.output_over()
    }

    fn outstanding(&self) -> Outstanding {
        Outstanding {
            output: self.writing(),
            input: self.input.is_some(),
            work: !self.jobs.is_empty(),
        }
    }

    /// Whether output is still on its way down: the stack holds some, or
    /// the connection took some and has not flushed it.
    fn writing(&self) -> bool {
        self.driver.holds_output() || self.unflushed > 0
    }

    /// How the run finished, once the stack has ended its direction, every
    /// byte of it is written and reported, no work is left, and input has
    /// ended or the stack explicitly declares its whole lifetime terminal.
    pub(super) fn finished(&self) -> Option<StreamEnd> {
        (self.unreported == 0
            && self
                .lifetime
                .finished(self.driver.layer().is_terminal(), self.outstanding()))
        .then_some(if self.lifetime.idled() {
            StreamEnd::Idle
        } else {
            StreamEnd::Finished
        })
    }

    /// Moves the stack and its connection on until nothing more can move
    /// now: `Pending` once it waits, with `cx` woken when something can
    /// move again. `Ready` when reading or writing the connection failed
    /// ([`Halt::Conn`]), or when the run ended: the stack reset the
    /// connection or gave up on it, the budget ran out, or a write stalled.
    /// After it ended it keeps answering the same.
    ///
    /// `above` takes the stack's events for what is above it, and `report`
    /// its reports.
    pub(super) fn poll(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        above: &mut dyn FnMut(EventOf<L::Upper>) -> Admit<EventOf<L::Upper>>,
        report: &mut dyn FnMut(L::Report),
    ) -> Poll<Result<Halt, StackError<L::Error>>> {
        if let Some(end) = self.stopped {
            return Poll::Ready(Ok(Halt::End(end)));
        }
        let polled = self.step(fcx, cx, above, report);
        if let Poll::Ready(Err(StackError::Layer(_))) = &polled {
            // A stack that gave up has nothing more to say.
            self.stopped = Some(StreamEnd::Conn(ConnError::Broken));
        }
        polled
    }

    fn stop(&mut self, end: StreamEnd) -> StreamEnd {
        self.stopped = Some(end);
        end
    }

    fn step(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        above: &mut dyn FnMut(EventOf<L::Upper>) -> Admit<EventOf<L::Upper>>,
        report: &mut dyn FnMut(L::Report),
    ) -> Poll<Result<Halt, StackError<L::Error>>> {
        // One reading of the clock for the batch: time that passes while it
        // runs is seen when a timer comes due.
        let mut now = fcx.now();
        self.driver.set_now(now);
        // A layer that wakes from outside its calls wakes this task, and
        // every round below runs the stack.
        self.driver.set_waker(cx.waker());
        for _ in 0..ROUNDS {
            // A charge refused in a round that moved something is tried
            // again in the next; one refused in the round that waits is
            // tried again when memory frees.
            let refusals = self.driver.refusals();
            // Read first, so input that came with a failed write is not
            // left behind.
            let mut read_failed = None;
            let mut moved = false;
            if self.input.is_none() && !self.lifetime.input_over() {
                // A read buffer that went to the stack is paid for again
                // before the next read. Without room, the bytes stay in
                // the connection, and the round's refusal gets the stack
                // woken when memory frees.
                if self.buf.is_none() {
                    self.buf = read_buffer(self.driver.budget());
                }
                if let Some(buf) = &mut self.buf {
                    match self.conn.poll_read_owned(fcx, cx, buf) {
                        Poll::Ready(Ok(Read::Copied(0))) => {
                            self.input = Some(StreamEvent::Ended);
                        }
                        Poll::Ready(Ok(read)) => {
                            self.input = Some(StreamEvent::Data(self.pay(read)));
                            self.lifetime.took_input();
                        }
                        Poll::Ready(Err(ConnError::Cancelled)) => {
                            return Poll::Ready(Err(StackError::Cancelled));
                        }
                        Poll::Ready(Err(e)) => read_failed = Some(e),
                        Poll::Pending => {}
                    }
                }
                moved |= self.input.is_some();
            }
            if self.driver.layer().is_terminal()
                || (self.lifetime.input_over() && self.lifetime.output_over())
            {
                self.jobs.close_completed();
            }
            let driver = &mut self.driver;
            moved |= self
                .jobs
                .poll(Some(fcx), cx, |done| driver.complete(done))
                .map_err(StackError::Layer)?;
            moved |= self.jobs.take(&mut self.driver);
            if self.jobs.budget_exhausted() {
                return Poll::Ready(Ok(Halt::End(self.stop(StreamEnd::Budget))));
            }
            if self.unreported > 0
                && !matches!(
                    self.driver
                        .deliver(StreamEvent::Written(self.unreported))
                        .map_err(StackError::Layer)?,
                    Admit::Blocked(_)
                )
            {
                self.unreported = 0;
                moved = true;
            }
            if let Some(event) = self.input.take() {
                let ended = matches!(event, StreamEvent::Ended);
                match self.driver.deliver(event).map_err(StackError::Layer)? {
                    Admit::Taken => {
                        if ended {
                            self.lifetime.end_input();
                        }
                        moved = true;
                    }
                    Admit::Partial(rest) => {
                        self.input = Some(rest);
                        moved = true;
                    }
                    Admit::Blocked(event) => self.input = Some(event),
                    Admit::Closed(_) => {
                        self.lifetime.end_input();
                        moved = true;
                    }
                }
            }
            moved |= self.driver.run().map_err(StackError::Layer)?;
            moved |= self.driver.send_above(&mut *above);

            let (mut wrote, mut failed, mut reset) = (0u64, None, false);
            let (conn, lifetime) = (&mut self.conn, &mut self.lifetime);
            let sent = self.driver.send_below(|command| match command {
                command if lifetime.output_over() || reset || failed.is_some() => {
                    Admit::Closed(command)
                }
                StreamCommand::Write(mut chunk) => {
                    if chunk.is_empty() {
                        return Admit::Taken;
                    }
                    match conn.poll_write_chunk(fcx, cx, &chunk) {
                        // A connection that takes nothing of a write is closed.
                        Poll::Ready(Ok(0)) => {
                            failed = Some(ConnError::Closed);
                            Admit::Blocked(StreamCommand::Write(chunk))
                        }
                        Poll::Ready(Ok(n)) => {
                            let n = n.min(chunk.len());
                            chunk.advance(n);
                            wrote += n as u64;
                            if chunk.is_empty() {
                                Admit::Taken
                            } else {
                                Admit::Partial(StreamCommand::Write(chunk))
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            failed = Some(e);
                            Admit::Blocked(StreamCommand::Write(chunk))
                        }
                        Poll::Pending => Admit::Blocked(StreamCommand::Write(chunk)),
                    }
                }
                StreamCommand::End => match conn.poll_shutdown(fcx, cx) {
                    Poll::Ready(Ok(())) => {
                        lifetime.end_output();
                        Admit::Taken
                    }
                    Poll::Ready(Err(e)) => {
                        failed = Some(e);
                        Admit::Blocked(StreamCommand::End)
                    }
                    Poll::Pending => Admit::Blocked(StreamCommand::End),
                },
                StreamCommand::Reset => {
                    reset = true;
                    Admit::Taken
                }
            });
            self.driver.observations().drain().for_each(&mut *report);
            moved |= sent;
            if reset {
                return Poll::Ready(Ok(Halt::End(self.stop(StreamEnd::Reset))));
            }
            self.unflushed += wrote;
            if let Some(e) = failed {
                // The write stays held, to try again.
                return Poll::Ready(Ok(Halt::Conn(e)));
            }
            if wrote > 0 {
                self.lifetime.wrote();
            }
            // Bytes count as written once the connection has handed them on.
            if self.unflushed > 0 {
                match self.conn.poll_flush(fcx, cx) {
                    Poll::Ready(Ok(())) => {
                        self.unreported += std::mem::take(&mut self.unflushed);
                        moved = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Ok(Halt::Conn(e))),
                    Poll::Pending => {}
                }
            }
            if let Some(e) = read_failed {
                return Poll::Ready(Ok(Halt::Conn(e)));
            }
            if moved {
                continue;
            }

            // The limits, as of now.
            self.lifetime.settle(now, self.outstanding());
            match self.lifetime.due(now) {
                Some(Expiry::Stalled) => {
                    self.lifetime.expire(Expiry::Stalled);
                    let end = self.broken(ConnError::TimedOut, above, report)?;
                    return Poll::Ready(Ok(Halt::End(end)));
                }
                Some(Expiry::Idle) => {
                    self.lifetime.expire(Expiry::Idle);
                    self.input = Some(StreamEvent::Ended);
                    continue;
                }
                None => {}
            }
            let deadline = [
                self.driver.deadline(),
                self.lifetime.deadline().map(|(at, _)| at),
            ]
            .into_iter()
            .flatten()
            .min();
            let Some(at) = deadline else {
                if let Some(timer) = &mut self.timer {
                    timer.clear();
                }
                self.driver.wake_when_freed(refusals);
                return Poll::Pending;
            };
            let timer = self.timer.get_or_insert_with(|| Timer::new(fcx));
            match timer.poll_until(cx, at) {
                Poll::Pending => {
                    self.driver.wake_when_freed(refusals);
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {}
                // Its region was cancelled: the next round arms a timer in
                // the region of this poll.
                Poll::Ready(Err(_)) => self.timer = None,
            }
            now = fcx.now();
            self.driver.set_now(now);
        }
        // Busy for a while: let the rest of the world run, then go on.
        // This pause is internal work, not time spent waiting for the peer.
        self.lifetime.interrupt();
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// The bytes `read` brought, paid for by the stack's budget before the
    /// stack sees them: a copy out of the read buffer charged first, or the
    /// chunk the connection handed over moved onto the budget. When the
    /// budget has no room for that, the read buffer, which paid for its
    /// bytes already, goes on with them, cut to their size, and the next
    /// read waits for a new one.
    fn pay(&mut self, read: Read) -> Chunk {
        let budget = self.driver.budget();
        let mut buf = match read {
            Read::Copied(n) => match ChargedBytes::copy_of(budget, &self.held()[..n]) {
                Some(copy) => return copy.into_chunk(),
                None => {
                    let mut buf = self.buf.take().expect("read into the buffer");
                    buf.truncate(n);
                    buf
                }
            },
            Read::Owned(mut chunk) => {
                if chunk.repay(budget) {
                    return chunk;
                }
                // Never longer than the buffer.
                let mut buf = self.buf.take().expect("read with the buffer");
                buf[..chunk.len()].copy_from_slice(&chunk);
                buf.truncate(chunk.len());
                buf
            }
        };
        buf.trim();
        buf.into_chunk()
    }

    /// The read buffer, while it is here.
    fn held(&self) -> &[u8] {
        self.buf.as_deref().expect("read into the buffer")
    }

    /// Gives up on the connection, which failed with `e`: the stack hears
    /// that it is gone and says what it still has to say above, and the run
    /// ends with [`StreamEnd::Conn`].
    pub(super) fn broken(
        &mut self,
        e: ConnError,
        above: &mut dyn FnMut(EventOf<L::Upper>) -> Admit<EventOf<L::Upper>>,
        report: &mut dyn FnMut(L::Report),
    ) -> Result<StreamEnd, StackError<L::Error>> {
        if e == ConnError::Cancelled {
            return Err(StackError::Cancelled);
        }
        self.input = None;
        self.lifetime.end_input();
        let end = self.stop(StreamEnd::Conn(e));
        // A stack that refuses the reset has already closed.
        let _ = self
            .driver
            .deliver(StreamEvent::Reset)
            .map_err(StackError::Layer)?;
        for _ in 0..ROUNDS {
            let moved = self.driver.run().map_err(StackError::Layer)?;
            self.driver.observations().drain().for_each(&mut *report);
            if !(self.driver.send_above(&mut *above) || moved) {
                break;
            }
        }
        Ok(end)
    }
}

/// A read buffer of [`READ`] bytes, charged to `budget` before it is
/// allocated, or `None` if the budget has no room for it.
fn read_buffer(budget: &Budget) -> Option<ChargedBytes> {
    let mut buf = ChargedBytes::with_capacity(budget, READ)?;
    buf.fill(|bytes| {
        bytes.resize(bytes.capacity(), 0);
        Ok::<_, Infallible>(())
    })
    .expect("filling to the capacity never grows it");
    Some(buf)
}
