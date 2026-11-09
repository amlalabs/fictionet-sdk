//! Runs [layer](fictionet::stdlib::layer) stacks over live connections and
//! UDP sockets: the one place a stack meets the runtime.
//!
//! A stack does the protocol with no I/O; a runner moves bytes, time and
//! work between it and the world, and nothing else. There is one runner for
//! byte streams and one for datagrams:
//!
//! - [`stream`] reads a [`Connection`] into a stack's [`ByteStream`] and
//!   writes what the stack gives back, with the write completions, the ends
//!   and the resets between them, until the stack is done. [`Opened`] is
//!   the same runner for a stack with a byte stream above it, such as TLS:
//!   it is a [`Connection`] that carries the stack's bytes from above.
//! - [`datagrams`] runs a stack over [`Datagrams`] on a [`DatagramSocket`],
//!   one conversation for the socket's whole life.
//!
//! Both drive the stack with a [`Driver`]: the world's time, the world's
//! entropy, and timers when the stack names them. Both poll the stack's
//! [`Work`](Layer::Work) as a [`Job`] and give back what finished, and both
//! hand the stack's [reports](Layer::Report) to a function the caller
//! gives. [`Polling`] does the same work for a
//! [`Harness`](fictionet::stdlib::layer::Harness), with or without a world.
//!
//! Two pieces join stacks to code written against a [`Connection`]:
//! [`Tunnel`] is a layer that hands the rest of a byte stream to such code,
//! as what runs after a CONNECT does, and [`Boxed`] is any server stack
//! behind one type, for whatever picks one at run time.
//!
//! [`Host::tcp_stack`](fictionet::stdlib::world::net::Host::tcp_stack) and
//! [`Host::udp_stack`](fictionet::stdlib::world::net::Host::udp_stack)
//! serve a host's port with these.

mod boxed;
mod job;
mod live;
mod open;
mod tunnel;

pub use boxed::{BoxError, Boxed};
pub use job::{Job, Polling};
pub use open::Opened;
pub use tunnel::{Takeover, Tunnel};

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Chunk, Datagram, DatagramCommand, DatagramEvent, Datagrams, Driver,
    Layer, Top,
};
use fictionet::stdlib::network::{ConnError, ConnInfo, Connection, DatagramSocket, Transport};
use fictionet::sync::Mutex;
use fictionet::{Cancelled, Cx, RecvError};

pub(crate) use job::Jobs;
pub(crate) use live::Halt;
use live::Live;

/// How many rounds a runner makes before it lets the rest of the world
/// run.
const FAIR: u32 = 64;

/// The limits [`stream`] keeps on a connection.
#[derive(Clone, Copy, Debug)]
pub struct StreamLimits {
    /// End the input of a connection that sends nothing for this long
    /// while the runner waits for it with nothing to write and no work
    /// running. The stack hears [`StreamEvent::Ended`], as if the peer had
    /// ended its direction. Default 10 seconds. `None` waits forever.
    ///
    /// [`StreamEvent::Ended`]: fictionet::stdlib::layer::StreamEvent::Ended
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

/// How a stream run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEnd {
    /// The stack ended its direction, every byte of it was written, and no
    /// work is left, and input ended or the stack declared itself terminal.
    Finished,
    /// The same, after the runner ended the input of an idle connection
    /// ([`StreamLimits::idle`]).
    Idle,
    /// The stack reset the connection. Whoever owns the socket resets it.
    Reset,
    /// The budget had no room for the connection's read buffer, so the
    /// stack never ran, for its work slots, or for bytes it read.
    /// When input allocation fails the stack hears
    /// [`StreamEvent::Reset`](fictionet::stdlib::layer::StreamEvent::Reset).
    Budget,
    /// Reading or writing failed: the peer reset the connection, or it
    /// stopped reading ([`ConnError::TimedOut`]). The stack heard
    /// [`StreamEvent::Reset`](fictionet::stdlib::layer::StreamEvent::Reset).
    ///
    /// [`ConnError::TimedOut`]: fictionet::stdlib::network::ConnError::TimedOut
    Conn(fictionet::stdlib::network::ConnError),
}

/// Why a runner stopped early.
#[derive(Debug)]
pub enum StackError<E> {
    /// The stack gave up on its connection with this error.
    Layer(E),
    /// The runner could not retain input or work within its memory budget.
    Budget,
    /// The run's [region](fictionet::Cx#regions) was cancelled.
    Cancelled,
}

impl<E: core::fmt::Display> core::fmt::Display for StackError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StackError::Layer(e) => e.fmt(f),
            StackError::Budget => f.write_str("stack memory budget exhausted"),
            StackError::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for StackError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            StackError::Layer(e) => Some(e),
            StackError::Budget => None,
            StackError::Cancelled => Some(&Cancelled),
        }
    }
}

impl<E> From<Cancelled> for StackError<E> {
    fn from(_: Cancelled) -> StackError<E> {
        StackError::Cancelled
    }
}

/// A panic in world code is the world's bug. Fictionet does not catch it:
/// it ends the run. The panic's own message says where in the code it
/// happened; a `PanicNote` alive while it unwinds adds which stack and
/// connection, on standard error. [`stream`] and [`datagrams`] keep one
/// while they run a stack.
pub struct PanicNote {
    service: &'static str,
    conn: ConnInfo,
}

impl PanicNote {
    /// A note for `service` (such as `std::any::type_name` of it) serving
    /// `conn`.
    pub fn new(service: &'static str, conn: &ConnInfo) -> PanicNote {
        PanicNote {
            service,
            conn: conn.clone(),
        }
    }
}

impl std::fmt::Display for PanicNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the panic came from {}", self.service)?;
        let c = &self.conn;
        if let Some(id) = c.id {
            write!(f, ", serving connection {id}")?;
        }
        if let Some(peer) = c.peer {
            write!(f, " from {peer}")?;
        }
        if let Some(local) = c.local {
            write!(f, " to {local} ({})", c.transport.as_str())?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for PanicNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PanicNote({self})")
    }
}

impl Drop for PanicNote {
    fn drop(&mut self) {
        if std::thread::panicking() {
            use std::io::Write as _;
            // Never a second panic while unwinding.
            let _ = writeln!(std::io::stderr(), "fictionet: {self}");
        }
    }
}

/// Counts one open connection of a listener until dropped, so a listener
/// can refuse connections past its cap. A port server keeps it with the
/// accepted socket ([`TcpConnection::hold_until_gone`]), so a connection
/// counts until its socket is gone, not only while its stack runs.
///
/// [`TcpConnection::hold_until_gone`]: fictionet::stdlib::network::tcp::TcpConnection::hold_until_gone
pub struct Counted(Arc<AtomicUsize>);

impl Counted {
    /// Counts one more in `open`, unless it already counts `max`.
    pub fn enter(open: &Arc<AtomicUsize>, max: usize) -> Option<Counted> {
        open.try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()?;
        Some(Counted(open.clone()))
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Runs `stack` over `conn` until the stack is done with it, charging
/// what it holds to `budget` and handing its reports to `report`.
///
/// The runner reads only while the stack has taken everything it read
/// before, so a stack that stops taking input stops the peer, and it
/// writes only what the transport takes, reporting each byte taken once
/// as [`StreamEvent::Written`](fictionet::stdlib::layer::StreamEvent::Written).
/// Due timers go off before more input is offered. The stack's work runs
/// with the world's context in a [region](fictionet::Cx#regions) of its
/// own: what it spawns is cancelled when the run ends. A task of the work
/// that fails ends that work and cancels the run, never the caller's
/// region.
///
/// It returns once the stack has ended its direction with every byte
/// written and no work left, and input has ended or the stack declares
/// itself terminal, or when the connection fails, the stack
/// resets it or gives up on it, or `limits` give up on it. A cancel of the
/// run's region wins over any of these but the stack giving up
/// ([`StackError::Cancelled`]). A panic in the
/// stack names it and `info` on standard error as it unwinds
/// ([`PanicNote`]). Dropping the run drops the stack and its work.
pub async fn stream<L, C>(
    fcx: &Cx,
    conn: C,
    info: &ConnInfo,
    stack: L,
    budget: Budget,
    limits: StreamLimits,
    mut report: impl FnMut(L::Report) + Send,
) -> Result<StreamEnd, StackError<L::Error>>
where
    L: Layer<Lower = ByteStream, Upper = Top>,
    L::Work: Job<Done = L::Done>,
    C: Connection,
{
    let _note = PanicNote::new(std::any::type_name::<L>(), info);
    in_region(fcx, move |fcx| async move {
        let mut live = Live::new(&fcx, conn, stack, budget, limits);
        let mut cancelled = pin!(fcx.cancelled());
        poll_fn(|cx| {
            if cancelled.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(StackError::Cancelled));
            }
            let above = &mut |event| match event {};
            let polled = live.poll(&fcx, cx, above, &mut report);
            // A cancel that landed while the stack ran, as a read or the
            // stack's work did something, wins over how the stack ended.
            if fcx.is_cancelled() && !matches!(polled, Poll::Ready(Err(StackError::Layer(_)))) {
                return Poll::Ready(Err(StackError::Cancelled));
            }
            let failed = match polled {
                Poll::Ready(Ok(Halt::End(end))) => return Poll::Ready(Ok(end)),
                Poll::Ready(Ok(Halt::Conn(e))) => e,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => match live.finished() {
                    Some(end) => return Poll::Ready(Ok(end)),
                    // A peer that reset the connection while nothing was
                    // read or written.
                    None if live.conn().poll_gone(cx).is_ready() => ConnError::Reset,
                    None => return Poll::Pending,
                },
            };
            Poll::Ready(live.broken(failed, above, &mut report))
        })
        .await
    })
    .await
}

/// Runs `stack` over every datagram of `socket`, which is bound at
/// `local`, until the socket closes or the stack ends it, handing its
/// reports to `report`, charging retained input and layer state to `budget`.
/// The socket owns its receive allocation until it returns; that transport
/// storage is outside this budget. Before retaining a returned datagram the
/// runner charges its full capacity, or drops it and returns a budget error.
///
/// The stack is one conversation for the socket's whole life: it keeps
/// whatever state it likes between datagrams, and its timers run between
/// them. Each datagram comes up whole with its sender's address, and each
/// one the stack sends goes to the address it names, at once. A datagram
/// the stack has not taken holds up the next receive, so the socket queues
/// them. When the socket closes the stack hears [`DatagramEvent::Ended`]
/// and sends what it still has. The stack's work runs as [`stream`]'s
/// does. A panic in the stack names it and the socket on standard error as
/// it unwinds ([`PanicNote`]).
pub async fn datagrams<L, D>(
    fcx: &Cx,
    socket: D,
    local: SocketAddr,
    stack: L,
    budget: Budget,
    mut report: impl FnMut(L::Report) + Send,
) -> Result<(), StackError<L::Error>>
where
    L: Layer<Lower = Datagrams<SocketAddr>, Upper = Top>,
    L::Work: Job<Done = L::Done>,
    D: DatagramSocket,
{
    let info = ConnInfo {
        local: Some(local),
        transport: Transport::Udp,
        ..ConnInfo::default()
    };
    let _note = PanicNote::new(std::any::type_name::<L>(), &info);
    in_region(fcx, move |fcx| async move {
        run_datagrams(&fcx, socket, stack, budget, &mut report).await
    })
    .await
}

async fn run_datagrams<L, D>(
    fcx: &Cx,
    mut socket: D,
    stack: L,
    budget: Budget,
    report: &mut (impl FnMut(L::Report) + Send),
) -> Result<(), StackError<L::Error>>
where
    L: Layer<Lower = Datagrams<SocketAddr>, Upper = Top>,
    L::Work: Job<Done = L::Done>,
    D: DatagramSocket,
{
    let mut driver = Driver::new(stack, std::sync::Arc::new(fcx.clone()), budget, fcx.now());
    let mut jobs = Jobs::new();
    let mut input: Option<DatagramEvent<SocketAddr>> = None;
    let mut socket_closed = false;
    let mut rounds = 0u32;
    loop {
        driver.set_now(fcx.now());
        if driver.layer().is_terminal() {
            jobs.close_completed();
        }
        // Poll work even while a productive layer keeps the runner busy.
        poll_fn(|cx| {
            Poll::Ready(jobs.poll(Some(fcx), cx, |done| {
                driver.complete(done).map_err(StackError::Layer)
            }))
        })
        .await?;
        let mut ended = false;
        let mut settled = false;
        for _ in 0..FAIR {
            let mut moved = false;
            moved |= jobs.take(&mut driver);
            if jobs.budget_exhausted() {
                return Err(StackError::Budget);
            }
            if let Some(event) = input.take() {
                match driver.deliver(event).map_err(StackError::Layer)? {
                    Admit::Taken | Admit::Closed(_) => moved = true,
                    Admit::Partial(rest) | Admit::Blocked(rest) => input = Some(rest),
                }
            }
            moved |= driver.run().map_err(StackError::Layer)?;
            driver.observations().drain().for_each(&mut *report);
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
            if !moved {
                settled = true;
                break;
            }
        }
        // A closed socket still gets what the stack has left, so only a
        // settled stack is done with it.
        if ended || (settled && socket_closed && input.is_none() && jobs.is_empty()) {
            jobs.close_completed();
            // As the stream runner does, a cancel that landed meanwhile wins.
            if fcx.is_cancelled() {
                return Err(StackError::Cancelled);
            }
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
                if driver.layer().is_terminal() {
                    jobs.close_completed();
                }
                let done = jobs.poll(Some(fcx), cx, |done| {
                    driver.complete(done).map_err(StackError::Layer)
                })?;
                if receive && let Poll::Ready(r) = recv.as_mut().poll(cx) {
                    return Poll::Ready(Ok(Some(r)));
                }
                let due = sleep
                    .as_mut()
                    .as_pin_mut()
                    .is_some_and(|s| s.poll(cx).is_ready());
                if done || due {
                    return Poll::Ready(Ok(None));
                }
                Poll::Pending
            })
            .await?
        };
        match got {
            Some(Ok((bytes, from))) => {
                let charge = driver
                    .budget()
                    .charge(bytes.capacity())
                    .ok_or(StackError::Budget)?;
                input = Some(DatagramEvent::Datagram(Datagram::new(
                    Chunk::with_charge(bytes, charge),
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

/// Runs `run` with a context for a [region](fictionet::Cx#regions) of its
/// own, and stops that region's work once `run` returns: work a stack
/// spawned does not outlive its run, and its failures stay its own.
async fn in_region<T, E, F, Fut>(fcx: &Cx, run: F) -> Result<T, StackError<E>>
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = Result<T, StackError<E>>>,
{
    let mut result = None;
    {
        let slot = &mut result;
        let finished = Mutex::new(None);
        let finished_ref = &finished;
        let mut region = pin!(fcx.region(|child| async move {
            *slot = Some(run(child.clone()).await);
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
    result.unwrap_or(Err(StackError::Cancelled))
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
#[path = "../../../../verification/layer-runtime/kani/admission.rs"]
mod proofs;
