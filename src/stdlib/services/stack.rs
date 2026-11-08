//! Runs a [layer](fictionet::stdlib::layer) stack over a live connection
//! or UDP socket.
//!
//! The stack does the protocol; these runners only move bytes. [`stream`]
//! reads a [`Connection`] into a stack's [`ByteStream`] and writes what the
//! stack gives back, with the write completion, the ends and the resets
//! between them. [`datagrams`] does the same for a [`DatagramSocket`] and a
//! stack over [`Datagrams`]. Both drive the stack with a
//! [`Driver`](fictionet::stdlib::layer::Driver): time from the run's clock,
//! entropy from the run, and timers when the stack names them.
//!
//! [`Host::tcp_stack`](fictionet::stdlib::world::net::Host::tcp_stack) and
//! [`Host::udp_stack`](fictionet::stdlib::world::net::Host::udp_stack)
//! serve a host's port with these.

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Chunk, Datagram, DatagramCommand, DatagramEvent, Datagrams, Driver,
    Layer, Never, StreamCommand, StreamEvent, Top,
};
use fictionet::stdlib::network::{ConnError, Connection, DatagramSocket};
use fictionet::stdlib::services::serve::{ConnInfo, PanicNote, Transport};
use fictionet::time::Instant;
use fictionet::{Cancelled, Cx, RecvError};

/// How big each read is. The buffer is charged to the connection's
/// budget for as long as the connection runs.
const READ: usize = 16 * 1024;

/// How many rounds a runner makes before it lets the rest of the world
/// run.
const FAIR: u32 = 64;

/// The limits [`stream`] keeps on a connection.
#[derive(Clone, Copy, Debug)]
pub struct StreamLimits {
    /// End the input of a connection that sends nothing for this long
    /// while the runner waits for it with nothing to write. The stack
    /// hears [`StreamEvent::Ended`], as if the peer had ended its
    /// direction. Default 10 seconds. `None` waits forever.
    pub idle: Option<Duration>,
    /// Give up on a connection whose writes take no bytes for this long: a
    /// peer that stopped reading. Default 10 seconds. `None` waits forever.
    pub write_timeout: Option<Duration>,
}

impl Default for StreamLimits {
    fn default() -> StreamLimits {
        StreamLimits {
            idle: Some(Duration::from_secs(10)),
            write_timeout: Some(Duration::from_secs(10)),
        }
    }
}

/// How a connection [`stream`] ran ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEnd {
    /// The stack ended its direction and its input is over.
    Finished,
    /// The same, after the runner ended the input of an idle connection
    /// ([`StreamLimits::idle`]).
    Idle,
    /// The stack reset the connection. Whoever owns the socket resets it.
    Reset,
    /// The budget had no room for the connection's read buffer, so the
    /// stack never ran, or for bytes it read, and the stack heard
    /// [`StreamEvent::Reset`].
    Budget,
    /// Reading or writing failed: the peer reset the connection, or it
    /// stopped reading ([`ConnError::TimedOut`]). The stack heard
    /// [`StreamEvent::Reset`].
    Conn(ConnError),
}

/// Why a runner stopped early.
#[derive(Debug)]
pub enum StackError<E> {
    /// The stack gave up on its connection with this error.
    Layer(E),
    /// The run's [region](fictionet::Cx#regions) was cancelled.
    Cancelled,
}

impl<E: core::fmt::Display> core::fmt::Display for StackError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StackError::Layer(e) => e.fmt(f),
            StackError::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for StackError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            StackError::Layer(e) => Some(e),
            StackError::Cancelled => Some(&Cancelled),
        }
    }
}

impl<E> From<Cancelled> for StackError<E> {
    fn from(_: Cancelled) -> StackError<E> {
        StackError::Cancelled
    }
}

/// What one wait on the connection brought.
#[derive(Default)]
struct Polled {
    /// Bytes the transport took.
    written: u64,
    /// The stack's end of its direction went out.
    shut: bool,
    /// The stack asked for a reset.
    reset: bool,
    failed: Option<ConnError>,
    read: Option<Result<usize, ConnError>>,
    /// Held output moved, or the stack handed over more.
    moved: bool,
}

/// Runs `layer` over `conn` until the connection ends, charging what it
/// holds to `budget`.
///
/// The runner reads only while the stack has taken everything it read
/// before, so a stack that stops taking input stops the peer, and it
/// writes only what the transport takes, reporting each byte taken once
/// as [`StreamEvent::Written`]. Due timers go off before more input is
/// read. It returns once the stack has ended its direction and its input
/// is over (it heard [`StreamEvent::Ended`], or refused input as closed),
/// or when the connection fails, the stack resets it, or `limits` give up
/// on it. A panic in the stack names it and `info` on standard error as it
/// unwinds ([`PanicNote`]).
///
/// The stack asks for no work and makes no reports ([`Never`]): this
/// runner has nowhere to send either.
pub async fn stream<L, C>(
    fcx: &Cx,
    mut conn: C,
    info: &ConnInfo,
    layer: L,
    budget: Budget,
    limits: StreamLimits,
) -> Result<StreamEnd, StackError<L::Error>>
where
    L: Layer<Lower = ByteStream, Upper = Top>,
    L::Work: Never,
    L::Report: Never,
    C: Connection,
{
    let _note = PanicNote::new(std::any::type_name::<L>(), info);
    let Some(_buffer) = budget.charge(READ) else {
        return Ok(StreamEnd::Budget);
    };
    let mut buf = vec![0u8; READ];
    let mut driver = Driver::new(layer, Arc::new(fcx.clone()), budget.clone(), fcx.now());
    // Read and not yet taken by the stack.
    let mut input: Option<StreamEvent> = None;
    // Taken by the transport and not yet reported to the stack.
    let mut written = 0u64;
    let mut input_over = false;
    let mut shut = false;
    let mut idled = false;
    let mut idle_from = fcx.now();
    let mut stalled_since: Option<Instant> = None;
    let mut rounds = 0u32;
    loop {
        let now = fcx.now();
        driver.set_now(now);
        let settled = settle(&mut driver, |driver| {
            let mut moved = false;
            if written > 0 {
                match driver.deliver(StreamEvent::Written(written))? {
                    Admit::Blocked(_) => {}
                    _ => {
                        written = 0;
                        moved = true;
                    }
                }
            }
            if let Some(event) = input.take() {
                let ended = matches!(event, StreamEvent::Ended);
                match driver.deliver(event)? {
                    Admit::Taken => input_over |= ended,
                    Admit::Closed(_) => input_over = true,
                    Admit::Partial(rest) => input = Some(rest),
                    Admit::Blocked(rest) => {
                        input = Some(rest);
                        return Ok(moved);
                    }
                }
                moved = true;
            }
            Ok(moved)
        })?;
        if !settled {
            rounds = 0;
            fcx.yield_now().await?;
            continue;
        }
        if shut && input_over {
            return Ok(if idled {
                StreamEnd::Idle
            } else {
                StreamEnd::Finished
            });
        }

        // The limits, as of now.
        if driver.holds_output() {
            let since = *stalled_since.get_or_insert(now);
            if limits.write_timeout.is_some_and(|d| now >= since + d) {
                return end_broken(&mut driver, ConnError::TimedOut);
            }
        } else {
            stalled_since = None;
        }
        let reading = !input_over && input.is_none();
        let waiting = reading && !driver.holds_output();
        if waiting && limits.idle.is_some_and(|d| now >= idle_from + d) {
            idled = true;
            input = Some(StreamEvent::Ended);
            continue;
        }
        let deadline = [
            driver.deadline(),
            limits.idle.filter(|_| waiting).map(|d| idle_from + d),
            stalled_since.zip(limits.write_timeout).map(|(t, d)| t + d),
        ]
        .into_iter()
        .flatten()
        .min();

        let polled = {
            let mut sleep = pin!(deadline.map(|t| fcx.sleep_until(t)));
            let mut cancelled = pin!(fcx.cancelled());
            let conn = &mut conn;
            let driver = &mut driver;
            let buf = &mut buf;
            poll_fn(|cx| {
                if cancelled.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(StackError::Cancelled));
                }
                let mut p = Polled::default();
                p.moved = driver.send_below(|command| match command {
                    command if p.shut || p.reset || p.failed.is_some() || shut => {
                        Admit::Closed(command)
                    }
                    StreamCommand::Write(mut chunk) if !chunk.is_empty() => {
                        match conn.poll_write(fcx, cx, &chunk) {
                            Poll::Ready(Ok(n)) => {
                                p.written += n as u64;
                                chunk.advance(n);
                                if chunk.is_empty() {
                                    Admit::Taken
                                } else {
                                    Admit::Partial(StreamCommand::Write(chunk))
                                }
                            }
                            Poll::Ready(Err(e)) => {
                                p.failed = Some(e);
                                Admit::Closed(StreamCommand::Write(chunk))
                            }
                            Poll::Pending => Admit::Blocked(StreamCommand::Write(chunk)),
                        }
                    }
                    StreamCommand::Write(_) => Admit::Taken,
                    StreamCommand::End => match conn.poll_shutdown(fcx, cx) {
                        Poll::Ready(Ok(())) => {
                            p.shut = true;
                            Admit::Taken
                        }
                        Poll::Ready(Err(e)) => {
                            p.failed = Some(e);
                            Admit::Closed(StreamCommand::End)
                        }
                        Poll::Pending => Admit::Blocked(StreamCommand::End),
                    },
                    StreamCommand::Reset => {
                        p.reset = true;
                        Admit::Taken
                    }
                });
                if reading && p.failed.is_none() {
                    if let Poll::Ready(r) = conn.poll_read(fcx, cx, buf) {
                        p.read = Some(r);
                    }
                }
                if p.failed.is_none() && conn.poll_gone(cx).is_ready() {
                    p.failed = Some(ConnError::Reset);
                }
                let due = sleep
                    .as_mut()
                    .as_pin_mut()
                    .is_some_and(|s| s.poll(cx).is_ready());
                if p.moved || p.read.is_some() || p.failed.is_some() || p.reset || due {
                    Poll::Ready(Ok(p))
                } else {
                    Poll::Pending
                }
            })
            .await?
        };

        written += polled.written;
        shut |= polled.shut;
        if polled.written > 0 {
            stalled_since = None;
            idle_from = fcx.now();
        }
        if polled.reset {
            return Ok(StreamEnd::Reset);
        }
        match polled.read {
            Some(Ok(0)) => input = Some(StreamEvent::Ended),
            Some(Ok(n)) => {
                // Charge first, then copy out of the read buffer.
                let Some(charge) = budget.charge(n) else {
                    return end_broken(&mut driver, ConnError::Reset).map(|_| StreamEnd::Budget);
                };
                input = Some(StreamEvent::Data(Chunk::with_charge(
                    buf[..n].to_vec(),
                    charge,
                )));
                idle_from = fcx.now();
            }
            Some(Err(ConnError::Cancelled)) => return Err(StackError::Cancelled),
            Some(Err(e)) => return end_broken(&mut driver, e),
            None => {}
        }
        if let Some(e) = polled.failed {
            if e == ConnError::Cancelled {
                return Err(StackError::Cancelled);
            }
            return end_broken(&mut driver, e);
        }
        rounds = (rounds + 1) % FAIR;
        if rounds == 0 {
            fcx.yield_now().await?;
        }
    }
}

/// Offers the stack its input with `offer`, which says whether anything
/// moved, and runs it, until nothing moves. Returns whether it settled
/// within [`FAIR`] rounds; a stack still moving gets the next turn.
fn settle<L>(
    driver: &mut Driver<L>,
    mut offer: impl FnMut(&mut Driver<L>) -> Result<bool, L::Error>,
) -> Result<bool, StackError<L::Error>>
where
    L: Layer,
    L::Work: Never,
    L::Report: Never,
{
    for _ in 0..FAIR {
        let mut moved = offer(driver).map_err(StackError::Layer)?;
        moved |= driver.run().map_err(StackError::Layer)?;
        if let Some(work) = driver.take_work() {
            work.never();
        }
        if let Some(report) = driver.observations().drain().next() {
            report.never();
        }
        if !moved {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Tells the stack its connection is gone, and lets it settle.
fn end_broken<L>(driver: &mut Driver<L>, e: ConnError) -> Result<StreamEnd, StackError<L::Error>>
where
    L: Layer<Lower = ByteStream>,
    L::Work: Never,
    L::Report: Never,
{
    let mut reset = Some(StreamEvent::Reset);
    settle(driver, |driver| match reset.take() {
        Some(event) => driver.deliver(event).map(|_| true),
        None => Ok(false),
    })?;
    Ok(StreamEnd::Conn(e))
}

/// Runs `layer` over every datagram of `socket`, which is bound at
/// `local`, until the socket closes or the stack ends it.
///
/// The stack is one conversation for the socket's whole life: it keeps
/// whatever state it likes between datagrams, and its timers run between
/// them. Each datagram comes up whole with its sender's address, and each
/// one the stack sends goes to the address it names, at once. A datagram
/// the stack has not taken holds up the next receive, so the socket queues
/// them. When the socket closes the stack hears [`DatagramEvent::Ended`]
/// and sends what it still has. A panic in the stack names it and the
/// socket on standard error as it unwinds ([`PanicNote`]).
///
/// The stack asks for no work and makes no reports ([`Never`]).
pub async fn datagrams<L, D>(
    fcx: &Cx,
    mut socket: D,
    local: SocketAddr,
    layer: L,
) -> Result<(), StackError<L::Error>>
where
    L: Layer<Lower = Datagrams<SocketAddr>, Upper = Top>,
    L::Work: Never,
    L::Report: Never,
    D: DatagramSocket,
{
    let info = ConnInfo {
        local: Some(local),
        transport: Transport::Udp,
        ..ConnInfo::default()
    };
    let _note = PanicNote::new(std::any::type_name::<L>(), &info);
    let mut driver = Driver::new(layer, Arc::new(fcx.clone()), Budget::unlimited(), fcx.now());
    let mut input: Option<DatagramEvent<SocketAddr>> = None;
    let mut socket_closed = false;
    let mut rounds = 0u32;
    loop {
        driver.set_now(fcx.now());
        let mut ended = false;
        let settled = settle(&mut driver, |driver| {
            let mut moved = false;
            if let Some(event) = input.take() {
                match driver.deliver(event)? {
                    Admit::Taken | Admit::Closed(_) => moved = true,
                    Admit::Partial(rest) | Admit::Blocked(rest) => input = Some(rest),
                }
            }
            moved |= driver.send_below(|command| match command {
                _ if ended => Admit::Closed(command),
                DatagramCommand::Send(datagram) => {
                    let (payload, to) = datagram.into_parts();
                    socket.send_to(&payload, to);
                    Admit::Taken
                }
                DatagramCommand::End => {
                    ended = true;
                    Admit::Taken
                }
            });
            Ok(moved)
        })?;
        if ended || (socket_closed && input.is_none()) {
            return Ok(());
        }
        if !settled {
            rounds = 0;
            fcx.yield_now().await?;
            continue;
        }

        let deadline = driver.deadline();
        let got = {
            let receive = input.is_none() && !socket_closed;
            let mut recv = pin!(socket.recv(fcx));
            let mut sleep = pin!(deadline.map(|t| fcx.sleep_until(t)));
            let mut cancelled = pin!(fcx.cancelled());
            poll_fn(|cx| {
                if cancelled.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(StackError::Cancelled));
                }
                if receive && let Poll::Ready(r) = recv.as_mut().poll(cx) {
                    return Poll::Ready(Ok(Some(r)));
                }
                if let Some(s) = sleep.as_mut().as_pin_mut()
                    && s.poll(cx).is_ready()
                {
                    return Poll::Ready(Ok(None));
                }
                Poll::Pending
            })
            .await?
        };
        match got {
            Some(Ok((bytes, from))) => {
                input = Some(DatagramEvent::Datagram(Datagram::new(
                    Chunk::new(bytes),
                    from,
                )));
            }
            Some(Err(RecvError::Closed)) => {
                socket_closed = true;
                input = Some(DatagramEvent::Ended);
            }
            Some(Err(RecvError::Cancelled)) => return Err(StackError::Cancelled),
            None => {}
        }
        rounds = (rounds + 1) % FAIR;
        if rounds == 0 {
            fcx.yield_now().await?;
        }
    }
}

#[cfg(test)]
mod tests;
