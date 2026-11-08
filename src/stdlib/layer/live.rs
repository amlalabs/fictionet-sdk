//! Running a stack over a live connection.
//!
//! [`run`] is the one place where a stack meets the runtime: it reads the
//! connection into the stack, writes the stack's output to it, sleeps until
//! the stack's next deadline, polls the stack's work, and reports what the
//! transport took. The stack itself stays synchronous; this only translates
//! readiness, so a stack behaves the same here as in the
//! [`Harness`](super::Harness).

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::layer::job::Jobs;
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Chunk, Driver, Job, Layer, StreamCommand, StreamEvent, Top,
};
use fictionet::stdlib::network::{ConnError, Connection};
use fictionet::sync::Mutex;
use fictionet::time::Instant;

/// How big each read is.
const READ: usize = 16 * 1024;
/// How many rounds one wake of the task makes before it lets others run.
const ROUNDS: usize = 64;

/// How [`run`] runs a stack.
#[derive(Clone, Debug)]
pub struct Live {
    /// What the stack is charged to.
    pub budget: Budget,
    /// How long a write may take no bytes before the connection ends, as
    /// a client that stopped reading. `None` waits for ever.
    pub write_timeout: Option<Duration>,
}

impl Default for Live {
    fn default() -> Live {
        Live {
            budget: Budget::unlimited(),
            write_timeout: None,
        }
    }
}

/// How a run over a live connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The stack ended its direction, every byte of it was written, and no
    /// work is left.
    Closed,
    /// The stack reset the connection.
    Reset,
    /// The connection failed: the peer reset it, or a read or write broke.
    /// The stack heard [`StreamEvent::Reset`].
    Broken(ConnError),
    /// A write took no bytes for [`Live::write_timeout`].
    Stalled,
    /// The world is stopping: `fcx`'s region was cancelled.
    Cancelled,
}

/// Runs `stack` over `conn` until it ends, with `fcx` as the world's
/// context: its time, its entropy, and the context the stack's work runs
/// with.
///
/// Input the stack refuses waits, and nothing more is read until it takes
/// it, so a stack that stops reading holds up the peer, not memory. The
/// transport's acceptance of each write comes back as
/// [`StreamEvent::Written`]. A due timer goes off before more input is
/// offered. The run ends once the stack has ended its direction with every
/// byte written and no work left, or when the connection fails, a write
/// stalls, or the world stops. Dropping the run drops the stack and its
/// work.
///
/// The stack's work runs in a [region](fictionet::Cx#regions) of its own:
/// what it spawns is cancelled when the run ends, and its failures end that
/// work, not the run.
pub async fn run<L, C>(fcx: &Cx, conn: C, stack: L, opts: &Live) -> Result<Outcome, L::Error>
where
    L: Layer<Lower = ByteStream, Upper = Top>,
    L::Work: Job<Done = L::Done>,
    C: Connection,
{
    let mut result = None;
    {
        let slot = &mut result;
        let finished = Mutex::new(None);
        let finished_ref = &finished;
        let mut region = pin!(fcx.region(|child| async move {
            *slot = Some(drive(&child, conn, stack, opts).await);
            *finished_ref.lock() = Some(child);
            Ok(())
        }));
        // The region's failures belong to the work that failed.
        let _ = poll_fn(|cx| {
            let polled = region.as_mut().poll(cx);
            if polled.is_pending() {
                // The run is over but work it spawned still runs: stop it.
                let child = finished.lock().take();
                if let Some(child) = child {
                    child.cancel();
                }
            }
            polled
        })
        .await;
    }
    result.unwrap_or(Ok(Outcome::Cancelled))
}

async fn drive<L, C>(fcx: &Cx, mut conn: C, stack: L, opts: &Live) -> Result<Outcome, L::Error>
where
    L: Layer<Lower = ByteStream, Upper = Top>,
    L::Work: Job<Done = L::Done>,
    C: Connection,
{
    let mut driver = Driver::new(stack, Arc::new(fcx.clone()), opts.budget.clone(), fcx.now());
    let mut jobs = Jobs::new();
    let mut buf = vec![0u8; READ];
    // Input the stack has not taken yet.
    let mut input: Option<StreamEvent> = None;
    let mut read_closed = false;
    let mut write_ended = false;
    // Bytes the transport took that the stack has not heard about.
    let mut unreported = 0u64;
    let mut armed: Option<Instant> = None;
    let mut sleep = pin!(None::<Instant>.map(|at| fcx.sleep_until(at)));
    let mut stall = pin!(None::<Instant>.map(|at| fcx.sleep_until(at)));
    let mut stalling = false;
    let mut cancelled = pin!(fcx.cancelled());
    poll_fn(|cx| {
        for _ in 0..ROUNDS {
            if cancelled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(Outcome::Cancelled));
            }
            driver.set_now(fcx.now());
            let mut failure = None;
            let mut reset = false;
            let mut wrote = false;
            let mut moved = jobs.poll(Some(fcx), cx, |done| driver.complete(done))?;
            while let Some(work) = driver.take_work() {
                jobs.push(work);
                moved = true;
            }
            if unreported > 0
                && !matches!(
                    driver.deliver(StreamEvent::Written(unreported))?,
                    Admit::Blocked(_)
                )
            {
                unreported = 0;
                moved = true;
            }
            if let Some(event) = input.take() {
                match driver.deliver(event)? {
                    Admit::Taken => moved = true,
                    Admit::Partial(rest) => {
                        input = Some(rest);
                        moved = true;
                    }
                    Admit::Blocked(event) => input = Some(event),
                    Admit::Closed(_) => {
                        read_closed = true;
                        moved = true;
                    }
                }
            }
            moved |= driver.run()?;
            moved |= driver.send_below(|command| match command {
                _ if write_ended || failure.is_some() => Admit::Closed(command),
                StreamCommand::Write(mut chunk) => {
                    if chunk.is_empty() {
                        return Admit::Taken;
                    }
                    match conn.poll_write(fcx, cx, &chunk) {
                        Poll::Ready(Ok(n)) => {
                            let n = n.min(chunk.len());
                            chunk.advance(n);
                            unreported += n as u64;
                            wrote = true;
                            if chunk.is_empty() {
                                Admit::Taken
                            } else {
                                Admit::Partial(StreamCommand::Write(chunk))
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            failure = Some(e);
                            Admit::Closed(StreamCommand::Write(chunk))
                        }
                        Poll::Pending => Admit::Blocked(StreamCommand::Write(chunk)),
                    }
                }
                StreamCommand::End => match conn.poll_shutdown(fcx, cx) {
                    Poll::Ready(Ok(())) => {
                        write_ended = true;
                        Admit::Taken
                    }
                    Poll::Ready(Err(e)) => {
                        failure = Some(e);
                        Admit::Closed(StreamCommand::End)
                    }
                    Poll::Pending => Admit::Blocked(StreamCommand::End),
                },
                StreamCommand::Reset => {
                    reset = true;
                    Admit::Taken
                }
            });
            if reset {
                return Poll::Ready(Ok(Outcome::Reset));
            }
            if let Some(e) = failure {
                return Poll::Ready(broken(&mut driver, e));
            }
            if wrote || !driver.holds_output() {
                stall.set(None);
                stalling = false;
            }
            if moved {
                continue;
            }
            if input.is_none() && !read_closed {
                match conn.poll_read(fcx, cx, &mut buf) {
                    Poll::Ready(Ok(0)) => {
                        input = Some(StreamEvent::Ended);
                        read_closed = true;
                        continue;
                    }
                    Poll::Ready(Ok(n)) => {
                        input = Some(StreamEvent::Data(Chunk::new(buf[..n].to_vec())));
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(broken(&mut driver, e)),
                    Poll::Pending => {}
                }
            }
            if conn.poll_gone(cx).is_ready() {
                return Poll::Ready(broken(&mut driver, ConnError::Reset));
            }
            if write_ended && jobs.is_empty() && !driver.holds_output() {
                return Poll::Ready(Ok(Outcome::Closed));
            }
            let deadline = driver.deadline();
            if deadline != armed {
                sleep.set(deadline.map(|at| fcx.sleep_until(at)));
                armed = deadline;
            }
            if let Some(sleeping) = sleep.as_mut().as_pin_mut()
                && sleeping.poll(cx).is_ready()
            {
                sleep.set(None);
                armed = None;
                continue;
            }
            if let Some(timeout) = opts.write_timeout
                && driver.holds_output()
            {
                if !stalling {
                    stall.set(Some(fcx.sleep_until(fcx.now() + timeout)));
                    stalling = true;
                }
                if let Some(waiting) = stall.as_mut().as_pin_mut()
                    && waiting.poll(cx).is_ready()
                {
                    return Poll::Ready(Ok(Outcome::Stalled));
                }
            }
            return Poll::Pending;
        }
        // Busy for a while: let the rest of the world run, then go on.
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

/// The connection failed with `e`: the stack hears that it is gone.
fn broken<L: Layer<Lower = ByteStream>>(
    driver: &mut Driver<L>,
    e: ConnError,
) -> Result<Outcome, L::Error> {
    if e == ConnError::Cancelled {
        return Ok(Outcome::Cancelled);
    }
    let _ = driver.deliver(StreamEvent::Reset)?;
    Ok(Outcome::Broken(e))
}
