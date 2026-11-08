//! Services: a protocol's server, written once with no I/O, run over any
//! connection.
//!
//! A [`Service`] is the server side of one protocol for one connection.
//! It gets decoded items, appends reply bytes and asks for timers. A world
//! can report typed facts directly through its service state. The [`Harness`]
//! runs the same service without a socket.
//!
//! [`connection`] is the one driver that joins a service to a
//! [`Connection`]: it reads, decodes, calls the
//! service, writes its reply, honors its timers, and closes. [`listen`]
//! runs [`connection`] for every connection an [`Accept`] listener accepts, with a
//! cap on how many are open, and TLS first when the options ask for it.
//! The driver and the [`Harness`] share one state machine, so a service
//! that passes its harness tests behaves the same over a real connection.
//!
//! A [`DatagramService`] is the server side of one protocol for one UDP
//! socket, and [`datagram`] runs it: each datagram is decoded on its own,
//! and the service can send datagrams to anyone. It shares the clock,
//! entropy, timers and wakes with a [`Service`], and has nothing of a
//! stream's deferred work, upgrades or ends.
//!
//! A service that echoes each line back, and closes on `quit`:
//!
//! ```
//! use fictionet::stdlib::codec::{Ending, LineError, Lines};
//! use fictionet::stdlib::services::serve::{Flow, Harness, Service, Driver};
//!
//! struct Echo;
//! impl Service for Echo {
//!     type Timer = ();
//!     type Decoder = Lines;
//!     type State = ();
//!     type Error = std::convert::Infallible;
//!     fn decoder(&self) -> Lines { Lines::new(1024, Ending::LfOrCrlf) }
//!     fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), driver: &mut Driver<'_, Self::Decoder, Self::Timer>) -> Result<Flow, Self::Error> {
//!         let line = line.unwrap_or_default();
//!         if line == b"quit" {
//!             return Ok(Flow::Close);
//!         }
//!
//!         driver.reply().extend_from_slice(&line);
//!         driver.reply().push(b'\n');
//!         Ok(Flow::Continue)
//!     }
//! }
//!
//! let mut h = Harness::new(fictionet::Seed::from_u64(0), Echo, ());
//! assert_eq!(h.push(b"hello\nwor")?, b"hello\n");
//! assert_eq!(h.push(b"ld\nquit\n")?, b"world\n");
//! assert!(h.closed());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! In a world, `listen` serves it on a port:
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::{Cx, Result, stdlib::{network::{ip, tcp}, services::serve}};
//! # struct Echo;
//! # impl serve::Service for Echo {
//! #     type Timer = ();
//! #     type Decoder = fictionet::stdlib::codec::Lines; type State = (); type Error = std::convert::Infallible;
//! #     fn decoder(&self) -> Self::Decoder { fictionet::stdlib::codec::Lines::new(64, fictionet::stdlib::codec::Ending::LfOrCrlf) }
//! #     fn on_item(&mut self, _: Result<Vec<u8>, fictionet::stdlib::codec::LineError>, _: &(), _: &mut serve::Driver<'_, Self::Decoder, Self::Timer>) -> std::result::Result<serve::Flow, Self::Error> { Ok(serve::Flow::Continue) }
//! # }
//! # fn start(fcx: &Cx, side: fictionet::End) -> Result {
//! let (tcp, _udp, _icmp, _other) = ip::split_protocols(fcx, side);
//! let machine = tcp::endpoint(fcx, tcp, "10.0.0.10".parse()?);
//! serve::listen(fcx, machine.listen(7)?, Arc::new(()), || Echo, serve::ServeOptions::default(), fictionet::stdlib::world::net::DEFAULT_MAX_CONNS, None);
//! # Ok(())
//! # }
//! ```
//!
//! [`net::Net`](fictionet::stdlib::world::net::Net) does this for every host and
//! port of a network, and [`httpd`](fictionet::stdlib::web::httpd) is HTTP as a
//! service.
//!
//! # What the driver promises
//!
//! - **One call at a time.** The service's methods are called in order, in
//!   the connection's task. Each call's reply is written before the next
//!   call.
//! - **Panics are bugs.** The driver does not catch a panic in a call or
//!   in deferred work: it ends the run, as a panic anywhere in a world
//!   does. As it unwinds, the driver names the service and the connection
//!   on standard error ([`PanicNote`]).
//! - **Progress, not stalls.** Bytes the decoder takes count as progress,
//!   whether or not they make an item, so a decoder that skips a long run
//!   of bytes is never mistaken for a stuck one. A decoder that breaks
//!   the [`Decode`] contract fails with
//!   [`Fail::Stuck`]. Input the buffer cannot take (a failed allocation)
//!   fails with [`Fail::Refused`].
//!   [`Service::on_fail`] hears both.
//! - **Timers.** [`Driver::set_timer`] arms a named timer; several can
//!   run at once. Each counts from when the call's reply is written. A due
//!   timer is handled before more input is read, so a client that never
//!   stops sending cannot starve a heartbeat.
//! - **Wakes.** [`Driver::wake_handle`] gives a handle the world or
//!   another connection keeps; [`WakeHandle::wake`] calls
//!   [`Service::on_wake`] in this connection's task, for a fill pushed to
//!   a trader or a notification pushed to a client.
//! - **Deferred work.** [`Driver::defer`] hands the driver async work
//!   whose bytes it writes, in order, before it reads on (an HTTP/1
//!   response from a tower service). [`Driver::defer_keyed`] starts work
//!   that runs beside the reads and the other keyed work, each writing
//!   whole frames as they come, and [`Service::on_done`] hears when one
//!   ends: concurrent responses, as HTTP/2 streams need.
//! - **Idle.** With [`ServeOptions::idle`], a connection that sends nothing
//!   for that long while the driver waits for it is closed, after
//!   [`Service::on_end`] with [`Ended::Idle`]. Deferred work suspends the
//!   clock: once it ends, the client has the whole idle time again.
//! - **Writes.** A write that takes no bytes for
//!   [`ServeOptions::write_timeout`] ends the connection with
//!   [`Ended::Conn`]`(`[`ConnError::TimedOut`]`)`: a client that stops
//!   reading. A client that resets the connection ends it at once, also
//!   while a write waits.
//! - **Budget.** With [`ServeOptions::budget`], the bytes the connection
//!   holds are charged to a [`Budget`] shared with other connections: the
//!   larger of decoder capacity and read buffer size, decoder-held state,
//!   the bytes waiting for the decoder,
//!   [`Service::held`], the reply bytes not yet written, and what deferred
//!   work holds ([`Pending::held`]). Past it the connection closes with
//!   [`Ended::Budget`], and its deferred work is cancelled.
//! - **Ends.** [`Service::on_end`] is called once, with why the connection
//!   ended. Its reply is written when the connection can still take it: the
//!   client half-closed ([`Ended::Eof`]), the service closed, the service's
//!   decoder failed, the connection sat idle or went over its budget.
//!   Dropping the serving future or harness cancels remaining deferred work
//!   and closes its wake handle, but does not call `on_end` or write a reply.
//! - **Stops.** When the world stops, a running service hears [`Ended::Cancelled`].
//!   [`connection`] returns [`ServeError::Cancelled`], also during final
//!   shutdown, unless it has a failure to return. If
//!   [`Service::on_end`] already ran, it is not called again.
//! - **Upgrades.** A call that returns [`Flow::Upgrade`] says what comes
//!   next: [`Upgrade::Decoder`] goes
//!   on with a fresh decoder; [`Upgrade::Handoff`] hands the connection
//!   and its unread bytes back in [`Served::Upgraded`], for a CONNECT
//!   tunnel. A decoder that ends ([`Step::End`](fictionet::stdlib::codec::Step::End))
//!   asks [`Service::on_decoder_end`] which.

use fictionet::sync::Mutex;
use fictionet::{Entropy, Seed, SeededEntropy};
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use fictionet::stdlib::codec::{Decode, Fail, Stream};
use fictionet::stdlib::layer::{Budget, Charge};
use fictionet::stdlib::network::{Accept, Accepted, DatagramSocket};
use fictionet::stdlib::network::{ConnError, Connection, ConnectionExt};
use fictionet::stdlib::network::{ConnInfo, Transport};
use fictionet::stdlib::services::stack::{Counted, PanicNote};
use fictionet::stdlib::world::net::Sandbox;
use fictionet::time::Instant;
use fictionet::{Cancelled, Cx, RaceError, RecvError, Task};

// ---------------------------------------------------------------------------
// The service

/// A sans-IO server for one connection of one protocol. The driver owns
/// the [`Stream`] and the output; the service owns its state.
///
/// Make one per connection ([`listen`] takes a function that does). State
/// shared with the rest of the world, such as a directory, a process model
/// or an order book, is the `State`, passed to every call.
///
/// A protocol that frames the same messages two ways, such as Kerberos
/// (a length prefix over TCP, one message per datagram over UDP), is a
/// thin `Service` and a thin [`DatagramService`] over one core of its own:
/// each picks its decoder and hands the message to the shared code.
pub trait Service: Send + 'static {
    /// This service's timer names. Use an enum, or `()` when no timers are needed.
    type Timer: Copy + Eq + Send + 'static;
    /// How this service's bytes become items.
    type Decoder: Decode + Send + 'static;
    /// State shared by every connection, such as a directory or an order book.
    type State: Send + Sync + 'static;
    /// Why the service gives up on a connection. The driver closes it
    /// and returns the error.
    type Error: core::error::Error + Send + Sync + 'static;

    /// A fresh decoder for a new connection, and after
    /// [`Upgrade::Decoder`].
    fn decoder(&self) -> Self::Decoder;

    /// The connection is open and nothing is read yet. A protocol whose
    /// server speaks first (SSH, SMTP, FTP banners) writes here.
    fn on_open(
        &mut self,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// One decoded item. Append reply bytes with [`Driver::reply`].
    fn on_item(
        &mut self,
        item: <Self::Decoder as Decode>::Item,
        state: &Self::State,
        driver: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<Flow, Self::Error>;

    /// The timer named `timer`, set with [`Driver::set_timer`], went off.
    fn on_timer(
        &mut self,
        _timer: Self::Timer,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// The connection's [`WakeHandle`] was woken. Several wakes before the
    /// driver gets to it are one call.
    fn on_wake(
        &mut self,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// Work started with [`Driver::defer_keyed`] under `key` ended, as
    /// `done` says. Not called for work the service cancelled or replaced.
    fn on_done(
        &mut self,
        _key: u64,
        _done: Done,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// The decoder failed: the bytes are not this protocol. A reply, such
    /// as an error message, is written before the connection closes.
    fn on_fail(
        &mut self,
        _error: &Fail<<Self::Decoder as Decode>::Error>,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The decoder ended ([`Step::End`](fictionet::stdlib::codec::Step::End)):
    /// the bytes after it belong to something else. [`Flow::Continue`]
    /// goes on with a fresh decoder, as [`Upgrade::Decoder`] does. The
    /// default hands the connection back ([`Upgrade::Handoff`]).
    fn on_decoder_end(
        &mut self,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Upgrade(Upgrade::Handoff))
    }

    /// The driver ended the connection, for the reason in `end`. Called once,
    /// last, when driven to termination, not when the future or harness is dropped.
    fn on_end(
        &mut self,
        _end: Ended,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Bytes the service itself holds for this connection, such as a
    /// request body it collects. Charged to the connection's [`Budget`]
    /// with the decoder's. Default 0.
    fn held(&self) -> usize {
        0
    }
}

/// What a call hands back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Keep the connection open.
    Continue,
    /// Write the reply, then close.
    Close,
    /// Write the reply, then change what runs on the connection.
    Upgrade(Upgrade),
}

/// What comes after [`Flow::Upgrade`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upgrade {
    /// Go on with the same service and a fresh decoder from
    /// [`Service::decoder`], which reads the bytes not yet decoded. For a
    /// protocol whose framing changes after a handshake.
    Decoder,
    /// Hand the connection and its unread bytes back to whoever called
    /// [`connection`] ([`Served::Upgraded`]): a CONNECT tunnel, or a protocol
    /// served by other code.
    Handoff,
}

impl Upgrade {
    /// `decoder` or `handoff`.
    pub fn as_str(self) -> &'static str {
        match self {
            Upgrade::Decoder => "decoder",
            Upgrade::Handoff => "handoff",
        }
    }
}

/// Why a connection ended, as [`Service::on_end`] hears it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The client sent everything it will send, and every item was handled.
    /// The reply is still written.
    Eof,
    /// The service returned [`Flow::Close`], or the service or deferred work failed.
    Closed,
    /// The decoder failed, after [`Service::on_fail`].
    Failed,
    /// Nothing arrived for [`ServeOptions::idle`].
    Idle,
    /// The connection held more than its [`Budget`] allows.
    Budget,
    /// Reading or writing failed: the client reset the connection, or TLS
    /// broke ([`ConnError::Broken`]).
    Conn(ConnError),
    /// The connection's region was cancelled. A notification
    /// for [`Service::on_end`]; [`connection`] itself then returns
    /// [`ServeError::Cancelled`], or the failure that cancelled the region.
    Cancelled,
}

impl Ended {
    /// Whether the connection can still take a last reply.
    pub fn writable(self) -> bool {
        matches!(
            self,
            Ended::Eof | Ended::Closed | Ended::Failed | Ended::Idle | Ended::Budget
        )
    }

    /// A stable spelling of the connection's end reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Ended::Eof => "eof",
            Ended::Closed => "closed",
            Ended::Failed => "failed",
            Ended::Idle => "idle",
            Ended::Budget => "budget",
            Ended::Conn(ConnError::Reset) => "reset",
            Ended::Conn(ConnError::Broken) => "broken",
            Ended::Conn(ConnError::TimedOut) => "timed_out",
            Ended::Conn(_) => "error",
            Ended::Cancelled => "cancelled",
        }
    }
}

/// How keyed work ended, as [`Service::on_done`] hears it.
#[derive(Clone, Debug)]
pub enum Done {
    /// It wrote everything it had.
    Finished,
    /// It failed with this error, the work's own. Its bytes so far were
    /// written.
    Failed(fictionet::Error),
}

/// Async work a service hands the driver with [`Driver::defer`] or
/// [`Driver::defer_keyed`]: bytes to write as they come, such as a
/// response from a tower service.
pub trait Pending: Send + 'static {
    /// The next bytes to write, or `None` when done. Keyed work yields
    /// whole frames: the driver never splits one, and writes other work's
    /// frames between them. An error on ordered work closes the
    /// connection, since the bytes so far may have broken the protocol's
    /// framing; on keyed work it ends that work ([`Done::Failed`]).
    ///
    /// The driver polls the work again only once the bytes it returned
    /// were written, so [`PendingDriver::written`] then counts them.
    fn poll_next(
        &mut self,
        driver: &mut PendingDriver<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>>;

    /// The connection went away, the world is stopping, or the service
    /// cancelled the work, before it finished. The work is dropped after
    /// this.
    fn cancel(&mut self, _ctx: &mut PendingDriver<'_>) {}

    /// Bytes the work holds while it waits, such as a response body not
    /// yet returned. Charged to the connection's [`Budget`]. Default 0.
    fn held(&self) -> usize {
        0
    }
}

/// What deferred work sees while it runs.
pub struct PendingDriver<'a> {
    fcx: Option<&'a Cx>,
    written: u64,
    conn: &'a ConnInfo,
    close: bool,
}

impl PendingDriver<'_> {
    /// The connection's context, for async work. `None` in a [`Harness`]
    /// made without one ([`Harness::with_fcx`]). During [`connection`], cancelling
    /// this context ends only this connection and its work.
    pub fn fcx(&self) -> Option<&Cx> {
        self.fcx
    }

    /// Bytes of this work the connection took so far: each piece the work
    /// returned counts once all of it is written.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Closes the connection once this work is done and its bytes are
    /// written: an HTTP/1.0 response whose body ends with the connection.
    pub fn close(&mut self) {
        self.close = true;
    }

    /// The connection.
    pub fn conn(&self) -> &ConnInfo {
        self.conn
    }
}

/// Wakes one connection's service from anywhere: the world, another
/// connection, a timed task. Cheap to clone. Get one with
/// [`Driver::wake_handle`] and keep it where the event happens, such as
/// in an order book next to the order it belongs to.
///
/// Each [`wake`](Self::wake) asks for one [`Service::on_wake`]; wakes
/// before the driver gets to it are one call. Once the connection has
/// ended, [`is_closed`](Self::is_closed) says so and waking does nothing,
/// so the world can drop handles of connections that are gone.
#[derive(Clone)]
pub struct WakeHandle {
    inner: Arc<WakeInner>,
}

struct WakeInner {
    woken: AtomicBool,
    closed: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

/// Closes the service's handle even if its future is dropped during STARTTLS.
struct WakeOwner(WakeHandle);

impl Drop for WakeOwner {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl std::fmt::Debug for WakeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeHandle")
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl WakeHandle {
    fn new() -> WakeHandle {
        WakeHandle {
            inner: Arc::new(WakeInner {
                woken: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                waker: Mutex::new(None),
            }),
        }
    }

    /// Asks for a [`Service::on_wake`] call.
    pub fn wake(&self) {
        if self.is_closed() {
            return;
        }
        self.inner.woken.store(true, Ordering::Release);
        let waker = self.inner.waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        let old = self.inner.waker.lock().replace(cx.waker().clone());
        drop(old);
        if self.inner.woken.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn take(&self) -> bool {
        self.inner.woken.swap(false, Ordering::AcqRel)
    }

    fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        let old = self.inner.waker.lock().take();
        drop(old);
    }
}

#[cfg(test)]
mod wake_tests {
    use super::*;

    #[test]
    fn service_waiter_replacement_and_close_release_wakers_outside_the_lock() {
        struct CheckDrop(std::sync::Weak<WakeInner>, Arc<AtomicBool>);
        impl Wake for CheckDrop {
            fn wake(self: Arc<Self>) {
                panic!("replacing or releasing a waiter must not wake it");
            }
        }
        impl Drop for CheckDrop {
            fn drop(&mut self) {
                assert!(self.0.upgrade().unwrap().waker.try_lock().is_some());
                self.1.store(true, Ordering::SeqCst);
            }
        }
        for close in [false, true] {
            let handle = WakeHandle::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let waker = Waker::from(Arc::new(CheckDrop(
                Arc::downgrade(&handle.inner),
                dropped.clone(),
            )));
            assert!(handle.poll(&mut Context::from_waker(&waker)).is_pending());
            drop(waker);
            if close {
                handle.close();
                assert!(handle.is_closed());
            } else {
                assert!(
                    handle
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                handle.wake();
                assert!(
                    handle
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                );
                assert!(handle.take());
            }
            assert!(dropped.load(Ordering::SeqCst));
        }
    }
}

/// The calls whose meaning is the same for a [`Service`] and a
/// [`DatagramService`]: the clock, entropy, timers, the connection and
/// wakes. Each context type has the fields `now`, `conn`, `timers` and
/// `s`, a scratch with `entropy`, `timers` and `wake`.
macro_rules! common_calls {
    () => {
        /// The run's clock, read by the driver before this call.
        pub fn now(&self) -> Instant {
            self.now
        }

        /// The run's entropy source, or the standalone harness's seeded source.
        pub fn entropy(&self) -> &dyn Entropy {
            self.s.entropy.as_ref()
        }

        /// A random number from the run's stream, or the standalone harness's stream.
        pub fn random_u64(&mut self) -> u64 {
            self.s.entropy.random_u64()
        }

        /// Arms the timer `name` to go off `d` after this call's output is
        /// written, replacing it if it is armed.
        pub fn set_timer(&mut self, name: T, d: Duration) {
            self.s.timers.retain(|(n, _)| *n != name);
            self.s.timers.push((name, Some(d)));
        }

        /// Disarms the timer `name`.
        pub fn cancel_timer(&mut self, name: T) {
            self.s.timers.retain(|(n, _)| *n != name);
            self.s.timers.push((name, None));
        }

        /// When the timer `name` goes off, if it is armed. A timer set in this
        /// call says `now` plus its duration.
        pub fn timer(&self, name: T) -> Option<Instant> {
            if let Some((_, d)) = self.s.timers.iter().find(|(n, _)| *n == name) {
                return d.map(|d| self.now + d);
            }
            self.timers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, at)| *at)
        }

        /// The connection: its number, sandbox, addresses and transport.
        pub fn conn(&self) -> &ConnInfo {
            self.conn
        }

        /// A handle that wakes this service from anywhere: see
        /// [`WakeHandle`].
        pub fn wake_handle(&self) -> WakeHandle {
            self.s.wake.clone()
        }
    };
}

/// The service's side of the driver, for one call: the reply, the clock
/// reading the driver took, seeded randomness, and
/// what the call asked for. Every [`Service`] method takes it as `driver`.
pub struct Driver<'a, D, T = ()> {
    decoder: &'a mut D,
    s: &'a mut Scratch<T>,
    now: Instant,
    conn: &'a ConnInfo,
    timers: &'a [(T, Instant)],
    budget: Option<&'a Budget>,
}

impl<D, T: Copy + Eq> Driver<'_, D, T> {
    common_calls!();

    /// The connection's budget, for rejecting a request before retaining it.
    /// The driver still charges all service and deferred-work holdings.
    pub fn budget(&self) -> Option<&Budget> {
        self.budget
    }

    /// The active decoder, read-only.
    pub fn peek_decoder(&self) -> &D {
        self.decoder
    }

    /// The active decoder.
    pub fn decoder(&mut self) -> &mut D {
        self.decoder
    }

    /// Bytes to send, after anything already there.
    pub fn reply(&mut self) -> &mut Vec<u8> {
        &mut self.s.reply
    }

    /// How many bytes the client has sent so far.
    pub fn bytes_in(&self) -> u64 {
        self.s.bytes_in
    }

    /// In [`Service::on_fail`], the bytes the decoder could not use: a
    /// message cut off by the end of input, or bytes that are not this
    /// protocol. In [`Service::on_timer`] and [`Service::on_end`], the bytes
    /// still buffered by the stream decoder. Empty in every other call.
    pub fn unread(&self) -> &[u8] {
        &self.s.unread
    }

    /// Hands the driver async work whose bytes it writes, in order, after
    /// this call's reply and before it reads on. Timers and wakes wait
    /// too. Several are run one after another.
    pub fn defer(&mut self, work: impl Pending) {
        self.s.ordered.push(Box::new(work));
    }

    /// Starts async work under `key` that runs beside the reads and the
    /// other keyed work. Its frames are written whole, as they come;
    /// [`Service::on_done`] hears when it ends. Work already under `key`
    /// is cancelled first.
    pub fn defer_keyed(&mut self, key: u64, work: impl Pending) {
        self.s.keyed.push((key, Some(Box::new(work))));
    }

    /// Cancels the keyed work under `key`, if it runs.
    pub fn cancel_keyed(&mut self, key: u64) {
        self.s.keyed.push((key, None));
    }
}

/// What the per-connection state looks like to a call.
struct Scratch<T> {
    reply: Vec<u8>,
    entropy: Arc<dyn Entropy>,
    timers: Vec<(T, Option<Duration>)>,
    ordered: Vec<Box<dyn Pending>>,
    keyed: Vec<(u64, Option<Box<dyn Pending>>)>,
    wake: WakeHandle,
    bytes_in: u64,
    unread: Vec<u8>,
}

impl<T> Scratch<T> {
    fn new(entropy: Arc<dyn Entropy>) -> Scratch<T> {
        Scratch {
            reply: Vec::new(),
            entropy,
            timers: Vec::new(),
            ordered: Vec::new(),
            keyed: Vec::new(),
            wake: WakeHandle::new(),
            bytes_in: 0,
            unread: Vec::new(),
        }
    }

    /// Throws away what a call asked for, when its output cannot be
    /// written.
    fn discard(&mut self) {
        self.reply.clear();
        self.ordered.clear();
        self.keyed.clear();
    }
}

/// Applies the timer requests of the last call at `now`.
fn arm<T: Copy + Eq>(
    timers: &mut Vec<(T, Instant)>,
    requests: &mut Vec<(T, Option<Duration>)>,
    now: Instant,
) {
    for (name, d) in requests.drain(..) {
        timers.retain(|(n, _)| *n != name);
        if let Some(d) = d {
            timers.push((name, now + d));
        }
    }
}

/// The index of the timer due first at `now`, if one is.
fn due<T>(timers: &[(T, Instant)], now: Instant) -> Option<usize> {
    let (i, (_, at)) = timers.iter().enumerate().min_by_key(|(_, (_, at))| *at)?;
    (*at <= now).then_some(i)
}

// ---------------------------------------------------------------------------
// Options

/// Names the sandbox at an address, for the [`ConnInfo`] of a connection
/// [`listen`] accepts or a datagram [`datagram`] receives.
pub type SandboxOf = Arc<dyn Fn(std::net::IpAddr) -> Option<Sandbox> + Send + Sync>;

/// How [`connection`] serves one stream connection, for itself or for a
/// listener.
#[derive(Clone)]
pub struct ServeOptions {
    /// Close a connection after this long with no bytes from the client,
    /// while the driver waits for them; deferred work suspends the clock.
    /// Default 10 seconds. `None` waits forever.
    pub idle: Option<Duration>,
    /// End a connection whose write takes no bytes for this long: a client
    /// that stops reading. Default 10 seconds. `None` waits forever; a
    /// reset or the world stopping still ends the wait.
    pub write_timeout: Option<Duration>,
    /// The read buffer's limit, at least the decoder's capacity. Larger
    /// lets the decoder see more at once. Default 0: the capacity.
    pub read_buffer: usize,
    /// The bytes each connection's holdings are charged to. Default none.
    pub budget: Option<Budget>,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            idle: Some(Duration::from_secs(10)),
            write_timeout: Some(Duration::from_secs(10)),
            read_buffer: 0,
            budget: None,
        }
    }
}

impl std::fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeOptions")
            .field("idle", &self.idle)
            .field("write_timeout", &self.write_timeout)
            .field("budget", &self.budget)
            .finish()
    }
}

impl ServeOptions {
    /// Sets the idle limit.
    pub fn idle(self, idle: Option<Duration>) -> ServeOptions {
        ServeOptions { idle, ..self }
    }

    /// Sets the write limit.
    pub fn write_timeout(self, write_timeout: Option<Duration>) -> ServeOptions {
        ServeOptions {
            write_timeout,
            ..self
        }
    }

    /// Charges every connection to `budget`.
    pub fn budget(self, budget: Budget) -> ServeOptions {
        ServeOptions {
            budget: Some(budget),
            ..self
        }
    }
}

// ---------------------------------------------------------------------------
// Handing back

/// Why [`connection`] stopped early. The connection was closed.
#[derive(Debug)]
pub enum ServeError<E> {
    /// The service returned this error.
    Service(E),
    /// Ordered deferred work or a task in the connection's child region failed.
    Pending(fictionet::Error),
    /// The connection's [region](fictionet::Cx#regions) or its parent was
    /// cancelled. A running service hears [`Ended::Cancelled`] in
    /// [`Service::on_end`]. Cancellation during the TLS handshake or while
    /// the service is already ending closes the connection immediately.
    /// During final shutdown, `on_end` has already heard the primary cause.
    /// A service, deferred-work,
    /// or child-task failure takes precedence over cancellation.
    Cancelled,
}

impl<E: core::fmt::Display> core::fmt::Display for ServeError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeError::Service(_) => f.write_str("the service failed"),
            ServeError::Pending(_) => f.write_str("deferred work failed"),
            ServeError::Cancelled => f.write_str("serving stopped"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ServeError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ServeError::Service(e) => Some(e),
            ServeError::Pending(e) => Some(&**e),
            ServeError::Cancelled => Some(&fictionet::Cancelled),
        }
    }
}

impl<E> From<fictionet::Cancelled> for ServeError<E> {
    fn from(_: fictionet::Cancelled) -> Self {
        ServeError::Cancelled
    }
}

/// How [`connection`] ended, when it was not cancelled.
#[derive(Debug)]
pub enum Served<C> {
    /// The connection is closed, or broken. Never [`Ended::Cancelled`]: a
    /// cancel is [`ServeError::Cancelled`].
    Closed(Ended),
    /// The service asked for an upgrade the caller performs: the
    /// connection with its unread bytes. [`connection`] returns only
    /// [`Upgrade::Handoff`].
    Upgraded(Upgrade, Prefixed<C>),
}

/// A connection with bytes already read from it in front: what a handoff
/// gives back. It reads the unread bytes first, then the connection.
#[derive(Debug)]
pub struct Prefixed<C> {
    unread: Vec<u8>,
    at: usize,
    conn: C,
}

impl<C> Prefixed<C> {
    /// `conn`, with `unread` read first.
    pub fn new(unread: Vec<u8>, conn: C) -> Prefixed<C> {
        Prefixed {
            unread,
            at: 0,
            conn,
        }
    }

    /// The bytes still to be read before the connection's own.
    pub fn unread(&self) -> &[u8] {
        &self.unread[self.at..]
    }

    /// The connection underneath. Bytes of [`unread`](Self::unread) are
    /// lost unless taken first.
    pub fn into_parts(self) -> (Vec<u8>, C) {
        (self.unread[self.at..].to_vec(), self.conn)
    }

    /// The connection underneath, by reference.
    pub fn inner(&self) -> &C {
        &self.conn
    }
}

impl<C: Connection> Connection for Prefixed<C> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        // A cancel comes first, before the bytes held here.
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        if self.at < self.unread.len() {
            let n = buf.len().min(self.unread.len() - self.at);
            buf[..n].copy_from_slice(&self.unread[self.at..self.at + n]);
            self.at += n;
            if self.at == self.unread.len() {
                self.unread = Vec::new();
                self.at = 0;
            }
            return Poll::Ready(Ok(n));
        }
        self.conn.poll_read(fcx, cx, buf)
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        self.conn.poll_write(fcx, cx, data)
    }

    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.conn.poll_shutdown(fcx, cx)
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.conn.poll_gone(cx)
    }
}

// ---------------------------------------------------------------------------
// The state machine the driver and the harness share

/// What the driver writes, in order.
struct Out(Vec<u8>, Option<(u64, u64)>);

/// Async work the driver runs, with what the connection took of it so far.
struct Work {
    id: u64,
    pending: Box<dyn Pending>,
    written: u64,
    /// Close the connection once it is done ([`PendingDriver::close`]).
    close: bool,
}

/// What went wrong beyond the connection's end.
enum Failure<E> {
    Service(E),
    Pending(fictionet::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Running,
    /// Ending: ordered work drains, then `on_end`, then its work drains.
    Ending {
        end: Ended,
        called: bool,
    },
    Upgrading(Upgrade),
    Ended(Ended),
}

/// The next item from a service's decoder.
type Decoded<S> = Option<
    Result<
        <<S as Service>::Decoder as Decode>::Item,
        Fail<<<S as Service>::Decoder as Decode>::Error>,
    >,
>;

/// What the state machine needs next.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// Write what is out, then ask again.
    Again,
    /// Wait for something: bytes (if `read`), deferred work, a wake (if
    /// `wake`), or the deadline.
    Wait {
        read: bool,
        wake: bool,
        deadline: Option<Instant>,
    },
    /// Hand the connection on.
    Upgrade(Upgrade),
    /// Done: write what is out if the end allows, then close.
    Closed(Ended),
}

/// One connection's state, with no I/O: the decoder and the bytes waiting
/// for it, the service's timers and deferred work, and what is to be
/// written. [`connection`] and [`Harness`] both run it.
struct Core<S: Service> {
    fcx: Option<Cx>,
    stream: Stream<S::Decoder>,
    read_buffer: usize,
    queue: VecDeque<(Vec<u8>, usize)>,
    s: Scratch<S::Timer>,
    info: ConnInfo,
    timers: Vec<(S::Timer, Instant)>,
    idle: Option<Duration>,
    /// When the idle clock last started: the client's last bytes, or the
    /// driver resuming its wait for them after deferred work.
    idle_from: Instant,
    /// Deferred work ran at the last `advance`: the idle clock was suspended.
    working: bool,
    eof: bool,
    ordered: VecDeque<Work>,
    keyed: Vec<(u64, Work)>,
    held_flow: Option<Flow>,
    state: State,
    out: VecDeque<Out>,
    failure: Option<Failure<S::Error>>,
    decode_fail: Option<Fail<<S::Decoder as Decode>::Error>>,
    budget: Option<Budget>,
    charge: Option<Charge>,
    /// The decoder was swapped for a fresh one ([`Upgrade::Decoder`]).
    fresh: bool,
    /// The number of the next deferred work.
    next_work: u64,
}

impl<S: Service> Core<S> {
    fn cancel_work(&mut self, mut work: Work) {
        let mut driver = PendingDriver {
            fcx: self.fcx.as_ref(),
            written: work.written,
            conn: &self.info,
            close: false,
        };
        work.pending.cancel(&mut driver);
    }

    fn cancel_all(&mut self, ordered: bool) {
        for (_, work) in std::mem::take(&mut self.keyed) {
            self.cancel_work(work);
        }
        if ordered {
            for work in std::mem::take(&mut self.ordered) {
                self.cancel_work(work);
            }
        }
    }
}

impl<S: Service> Drop for Core<S> {
    fn drop(&mut self) {
        self.cancel_all(true);
    }
}

impl<S: Service> Core<S>
where
    <S::Decoder as Decode>::Error: Clone,
{
    fn new(
        fcx: Option<Cx>,
        entropy: Arc<dyn Entropy>,
        service: &S,
        info: ConnInfo,
        opts: &ServeOptions,
        wake: Option<WakeHandle>,
        now: Instant,
    ) -> Core<S> {
        let mut s = Scratch::new(entropy);
        if let Some(w) = wake {
            s.wake = w;
        }
        Core {
            fcx,
            stream: Stream::with_buffer(service.decoder(), opts.read_buffer),
            read_buffer: opts.read_buffer,
            queue: VecDeque::new(),
            s,
            info,
            timers: Vec::new(),
            idle: opts.idle,
            idle_from: now,
            working: false,
            eof: false,
            ordered: VecDeque::new(),
            keyed: Vec::new(),
            held_flow: None,
            state: State::Running,
            out: VecDeque::new(),
            failure: None,
            decode_fail: None,
            budget: opts.budget.clone(),
            charge: None,
            fresh: false,
            next_work: 0,
        }
    }

    /// Takes the first charge, then calls `on_open`. A connection whose
    /// first charge does not fit is closed with no call.
    fn open(&mut self, service: &mut S, state: &S::State, now: Instant) {
        if let Some(budget) = self.budget.clone() {
            let Some(charge) = budget.charge(self.holding(service)) else {
                self.end_now(Ended::Budget);
                return;
            };
            self.charge = Some(charge);
        }
        self.call(now, |driver| service.on_open(state, driver));
    }

    /// The bytes this connection holds, as charged to its budget.
    fn holding(&mut self, service: &S) -> usize {
        let queued: usize = self.queue.iter().map(|(bytes, _)| bytes.capacity()).sum();
        let out: usize = self
            .out
            .iter()
            .map(|o| {
                let Out(b, _) = o;
                b.capacity()
            })
            .sum();
        let work: usize = self
            .ordered
            .iter()
            .chain(self.keyed.iter().map(|(_, w)| w))
            .map(|w| w.pending.held())
            .sum();
        self.stream
            .decoder()
            .capacity()
            .max(self.read_buffer)
            .max(self.stream.allocated())
            .saturating_add(self.stream.held())
            .saturating_add(queued)
            .saturating_add(service.held())
            .saturating_add(out)
            .saturating_add(work)
    }

    /// Charges what the connection holds now. Past the budget, nothing
    /// more is written and the deferred work is cancelled; the connection
    /// ends with [`Ended::Budget`], and `on_end` may still reply.
    fn recharge(&mut self, service: &S) {
        if self.charge.is_none() || matches!(self.state, State::Ended(_) | State::Upgrading(_)) {
            return;
        }
        let need = self.holding(service);
        if self.charge.as_mut().is_some_and(|c| c.set(need)) {
            return;
        }
        self.out.clear();
        self.cancel_all(true);
        match self.state {
            State::Running => self.finish(Ended::Budget),
            State::Ending { called: false, .. } => {
                self.state = State::Ending {
                    end: Ended::Budget,
                    called: false,
                }
            }
            _ => self.end_now(Ended::Budget),
        }
        // What is left, such as the decoder's capacity, still counts.
        let need = self.holding(service);
        if let Some(c) = &mut self.charge {
            c.set(need.min(c.bytes()));
        }
    }

    /// Bytes from the client.
    fn input(&mut self, bytes: &[u8], now: Instant) {
        self.s.bytes_in += bytes.len() as u64;
        self.idle_from = now;
        if self.queue.is_empty() {
            let n = self.stream.push(bytes);
            if n < bytes.len() {
                self.queue.push_back((bytes[n..].to_vec(), 0));
            }
        } else {
            self.queue.push_back((bytes.to_vec(), 0));
        }
    }

    /// The client will send nothing more.
    fn input_eof(&mut self) {
        self.eof = true;
    }

    /// `n` bytes of the work numbered `id` were written.
    fn wrote(&mut self, credit: Option<(u64, u64)>) {
        let Some((id, n)) = credit else { return };
        if let Some(w) = self
            .ordered
            .iter_mut()
            .chain(self.keyed.iter_mut().map(|(_, w)| w))
            .find(|w| w.id == id)
        {
            w.written += n;
        }
    }

    fn new_work(&mut self, pending: Box<dyn Pending>) -> Work {
        self.next_work += 1;
        Work {
            id: self.next_work,
            pending,
            written: 0,
            close: false,
        }
    }

    /// The connection broke, or the world is stopping. A connection that
    /// was ending, or about to be handed on, ends at once.
    fn broken(&mut self, end: Ended) {
        self.out.clear();
        match self.state {
            State::Running => self.finish(end),
            State::Ending { .. } | State::Upgrading(_) => {
                self.cancel_all(true);
                self.end_now(end);
            }
            State::Ended(_) => {}
        }
    }

    /// Whether the driver has async work to poll.
    fn has_work(&self) -> bool {
        !self.ordered.is_empty() || !self.keyed.is_empty()
    }

    /// Bytes read but not decoded, for a handoff.
    fn unread(&mut self) -> Vec<u8> {
        let mut unread = self.stream.unread().to_vec();
        for (bytes, at) in self.queue.drain(..) {
            unread.extend_from_slice(&bytes[at..]);
        }
        unread
    }

    /// Queues bytes to write and credits their deferred work when written.
    fn push_out(&mut self, bytes: Vec<u8>, work: Option<u64>) {
        if !bytes.is_empty() {
            let credit = work.map(|id| (id, bytes.len() as u64));
            self.out.push_back(Out(bytes, credit));
        }
    }

    /// Takes what the last call asked for: its reply, its deferred work.
    fn collect(&mut self) {
        let reply = std::mem::take(&mut self.s.reply);
        self.push_out(reply, None);
        for pending in std::mem::take(&mut self.s.ordered) {
            let work = self.new_work(pending);
            self.ordered.push_back(work);
        }
        for (key, work) in std::mem::take(&mut self.s.keyed) {
            if let Some(i) = self.keyed.iter().position(|(k, _)| *k == key) {
                let (_, old) = self.keyed.remove(i);
                self.cancel_work(old);
            }
            if let Some(pending) = work {
                let work = self.new_work(pending);
                self.keyed.push((key, work));
            }
        }
    }

    /// Ends at once: no more calls, nothing more written.
    fn end_now(&mut self, end: Ended) {
        self.out.clear();
        self.held_flow = None;
        self.s.wake.close();
        self.state = State::Ended(end);
    }

    /// Calls the service with a context for this call, then takes what it
    /// asked for.
    fn call(
        &mut self,
        now: Instant,
        f: impl FnOnce(&mut Driver<'_, S::Decoder, S::Timer>) -> Result<Flow, S::Error>,
    ) {
        let result = {
            let mut driver = Driver {
                decoder: self.stream.decoder(),
                s: &mut self.s,
                now,
                conn: &self.info,
                timers: &self.timers,
                budget: self.budget.as_ref(),
            };
            f(&mut driver)
        };
        match result {
            Err(e) => {
                self.collect();
                self.failure.get_or_insert(Failure::Service(e));
                self.finish(Ended::Closed);
            }
            Ok(flow) => {
                self.collect();
                if self.state == State::Running
                    && flow != Flow::Continue
                    && self.held_flow.is_none()
                {
                    self.held_flow = Some(flow);
                }
            }
        }
    }

    /// Starts ending with `end`. A writable end drains ordered work and
    /// writes `on_end`'s reply; any other end cancels the work.
    fn finish(&mut self, end: Ended) {
        if self.state != State::Running {
            return;
        }
        self.held_flow = None;
        self.s.wake.close();
        self.cancel_all(!end.writable());
        if !end.writable() {
            self.out.clear();
        }
        self.state = State::Ending { end, called: false };
    }

    fn apply(&mut self, flow: Flow, service: &S) {
        match flow {
            Flow::Continue => {}
            Flow::Close => self.finish(Ended::Closed),
            Flow::Upgrade(Upgrade::Decoder) => {
                let unread = self.stream.unread().to_vec();
                self.stream = Stream::with_buffer(service.decoder(), self.read_buffer);
                self.fresh = true;
                if !unread.is_empty() {
                    self.queue.push_front((unread, 0));
                }
            }
            Flow::Upgrade(how) => {
                self.cancel_all(true);
                self.state = State::Upgrading(how);
            }
        }
    }

    /// The decoder failed with `fail`.
    fn failed(
        &mut self,
        service: &mut S,
        state: &S::State,
        now: Instant,
        fail: Fail<<S::Decoder as Decode>::Error>,
    ) {
        self.s.unread = self.stream.unread().to_vec();
        let result = {
            let mut driver = Driver {
                decoder: self.stream.decoder(),
                s: &mut self.s,
                now,
                conn: &self.info,
                timers: &self.timers,
                budget: self.budget.as_ref(),
            };
            service.on_fail(&fail, state, &mut driver)
        };
        self.s.unread = Vec::new();
        self.decode_fail = Some(fail);
        self.collect();
        if let Err(e) = result {
            self.failure.get_or_insert(Failure::Service(e));
        }
        self.finish(Ended::Failed);
    }

    /// Moves bytes from the queue into the decoder, up to the buffer limit.
    /// Returns how many it took.
    fn feed(&mut self) -> usize {
        let mut pushed = 0;
        while let Some((bytes, at)) = self.queue.front_mut() {
            let n = self.stream.push(&bytes[*at..]);
            *at += n;
            pushed += n;
            if *at == bytes.len() {
                self.queue.pop_front();
            } else {
                break;
            }
        }
        pushed
    }

    fn next_item(&mut self) -> Decoded<S> {
        self.stream.with_next(|item, _, _| item)
    }

    fn next_deadline(&self) -> Option<Instant> {
        let timer = self.timers.iter().map(|(_, at)| *at).min();
        // Deferred work running is not a silent client.
        let idle = self
            .idle
            .filter(|_| !self.has_work())
            .map(|i| self.idle_from + i);
        match (timer, idle) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// One step: at most one call into the service.
    fn advance(&mut self, service: &mut S, state: &S::State, now: Instant) -> Next {
        arm(&mut self.timers, &mut self.s.timers, now);
        self.recharge(service);
        match self.state {
            State::Ended(end) => return Next::Closed(end),
            State::Upgrading(how) => return Next::Upgrade(how),
            State::Ending { end, called } => return self.ending(service, state, now, end, called),
            State::Running => {}
        }
        // The idle clock runs only while the driver waits for the client,
        // not under deferred work: it restarts when that wait resumes.
        let working = self.has_work();
        if self.working && !working {
            self.idle_from = now;
        }
        self.working = working;
        if !self.ordered.is_empty() {
            // Reads, timers and wakes wait for ordered work.
            return Next::Wait {
                read: false,
                wake: false,
                deadline: None,
            };
        }
        if let Some(flow) = self.held_flow.take() {
            self.apply(flow, service);
            return Next::Again;
        }
        // A due timer before more input, so input cannot starve it.
        if let Some(i) = due(&self.timers, now) {
            let (name, _) = self.timers.remove(i);
            self.s.unread = self.stream.unread().to_vec();
            self.call(now, |driver| service.on_timer(name, state, driver));
            self.s.unread = Vec::new();
            return Next::Again;
        }
        if self.s.wake.take() {
            self.call(now, |driver| service.on_wake(state, driver));
            return Next::Again;
        }
        if let Some(idle) = self.idle
            && !working
            && now >= self.idle_from + idle
        {
            self.finish(Ended::Idle);
            return Next::Again;
        }
        loop {
            let pushed = self.feed();
            if self.state != State::Running {
                return Next::Again;
            }
            if self.eof && self.queue.is_empty() {
                self.stream.end();
            }
            match self.next_item() {
                Some(Ok(item)) => {
                    self.call(now, |driver| service.on_item(item, state, driver));
                    return Next::Again;
                }
                Some(Err(fail)) => {
                    self.failed(service, state, now, fail);
                    return Next::Again;
                }
                None => {}
            }
            if self.stream.is_done() {
                if self.eof && self.queue.is_empty() && self.stream.unread().is_empty() {
                    self.finish(Ended::Eof);
                } else if self.fresh && self.stream.offset() == 0 {
                    // A fresh decoder that ends before it reads a byte
                    // would end again and again: hand the bytes on.
                    self.held_flow = Some(Flow::Upgrade(Upgrade::Handoff));
                } else {
                    // The decoder ended: the rest belongs to what comes
                    // next, which the service decides.
                    self.call(now, |driver| {
                        service.on_decoder_end(state, driver).map(|f| {
                            if f == Flow::Continue {
                                Flow::Upgrade(Upgrade::Decoder)
                            } else {
                                f
                            }
                        })
                    });
                }
                return Next::Again;
            }
            if pushed > 0 {
                // Bytes the decoder took are progress, item or not.
                continue;
            }

            if !self.queue.is_empty() {
                // The buffer took nothing and the decoder yielded nothing: a
                // decoder at capacity has already failed as Stuck, so the
                // allocation failed.
                let fail = Fail::Refused {
                    unread: self.stream.buffered(),
                    limit: self.stream.limit(),
                };
                self.failed(service, state, now, fail);
                return Next::Again;
            }
            break;
        }
        Next::Wait {
            read: !self.eof,
            wake: true,
            deadline: self.next_deadline(),
        }
    }

    fn ending(
        &mut self,
        service: &mut S,
        state: &S::State,
        now: Instant,
        end: Ended,
        called: bool,
    ) -> Next {
        if !self.ordered.is_empty() {
            return Next::Wait {
                read: false,
                wake: false,
                deadline: None,
            };
        }
        if called {
            self.state = State::Ended(end);
            return Next::Closed(end);
        }
        self.state = State::Ending { end, called: true };
        self.s.unread = self.stream.unread().to_vec();
        let result = {
            let mut driver = Driver {
                decoder: self.stream.decoder(),
                s: &mut self.s,
                now,
                conn: &self.info,
                timers: &self.timers,
                budget: self.budget.as_ref(),
            };
            service.on_end(end, state, &mut driver)
        };
        self.s.unread = Vec::new();
        if let Err(e) = result {
            self.failure.get_or_insert(Failure::Service(e));
        }
        self.s.keyed.clear();
        if end.writable() {
            let reply = std::mem::take(&mut self.s.reply);
            self.push_out(reply, None);
            for pending in std::mem::take(&mut self.s.ordered) {
                let work = self.new_work(pending);
                self.ordered.push_back(work);
            }
        }
        self.s.discard();
        Next::Again
    }

    /// Polls the deferred work. Returns whether any made progress: bytes
    /// to write, or work that ended.
    fn poll_work(
        &mut self,
        service: &mut S,
        state: &S::State,
        now: Instant,
        cx: &mut Context<'_>,
    ) -> bool {
        let mut progress = false;
        if let Some(work) = self.ordered.front_mut() {
            let (polled, close) = {
                let mut driver = PendingDriver {
                    fcx: self.fcx.as_ref(),
                    written: work.written,
                    conn: &self.info,
                    close: false,
                };
                (work.pending.poll_next(&mut driver, cx), driver.close)
            };
            work.close |= close;
            let (id, close) = (work.id, work.close);
            match polled {
                Poll::Pending => {}
                Poll::Ready(Some(Ok(bytes))) => {
                    self.push_out(bytes, Some(id));
                    return true;
                }
                Poll::Ready(None) => {
                    self.ordered.pop_front();
                    if close {
                        self.finish_after_work();
                    }
                    return true;
                }
                Poll::Ready(Some(Err(e))) => {
                    self.ordered.pop_front();
                    self.failure.get_or_insert(Failure::Pending(e));
                    for work in std::mem::take(&mut self.ordered) {
                        self.cancel_work(work);
                    }
                    self.finish(Ended::Closed);
                    return true;
                }
            }
        }
        let mut i = 0;
        while i < self.keyed.len() && self.state == State::Running {
            let (polled, close) = {
                let (_, work) = &mut self.keyed[i];
                let mut driver = PendingDriver {
                    fcx: self.fcx.as_ref(),
                    written: work.written,
                    conn: &self.info,
                    close: false,
                };
                (work.pending.poll_next(&mut driver, cx), driver.close)
            };
            self.keyed[i].1.close |= close;
            let done = match polled {
                Poll::Pending => {
                    i += 1;
                    continue;
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    let id = self.keyed[i].1.id;
                    self.push_out(bytes, Some(id));
                    progress = true;
                    i += 1;
                    continue;
                }
                Poll::Ready(None) => Done::Finished,
                Poll::Ready(Some(Err(e))) => Done::Failed(e),
            };
            let (key, work) = self.keyed.remove(i);
            progress = true;
            self.call(now, |driver| service.on_done(key, done, state, driver));
            if work.close {
                self.finish_after_work();
            }
        }
        progress
    }

    /// Work that asked to close the connection is done: the connection
    /// ends as if the service returned [`Flow::Close`], and ordered work
    /// after it is cancelled, since its bytes cannot follow.
    fn finish_after_work(&mut self) {
        if self.state != State::Running {
            return;
        }
        for work in std::mem::take(&mut self.ordered) {
            self.cancel_work(work);
        }
        self.finish(Ended::Closed);
    }
}

// ---------------------------------------------------------------------------
// The driver

/// How big each read is.
const READ: usize = 16 * 1024;

/// What woke the driver while it waited. Everything is polled each
/// time, so busy deferred work cannot starve the reads, nor the reverse.
#[derive(Default)]
struct Woke {
    read: Option<Result<usize, ConnError>>,
    gone: bool,
    cancelled: bool,
}

fn conn_end(e: ConnError) -> Ended {
    match e {
        ConnError::Cancelled => Ended::Cancelled,
        e => Ended::Conn(e),
    }
}

/// Writes all of `data`, unless the client resets the connection, the
/// world stops, or a write takes no bytes for `stall`: a client that
/// stopped reading. Returns how the connection ends if it does.
async fn write_all<C: Connection>(
    fcx: &Cx,
    conn: &mut C,
    data: &[u8],
    stall: Option<Duration>,
) -> Result<(), Ended> {
    let mut data = data;
    let mut sleep = pin!(stall.map(|d| fcx.sleep_until(fcx.now() + d)));
    let mut cancelled = pin!(fcx.cancelled());
    poll_fn(|cx| {
        let mut moved = false;
        while !data.is_empty() {
            match conn.poll_write(fcx, cx, data) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(Ended::Conn(ConnError::Closed))),
                Poll::Ready(Ok(n)) => {
                    data = &data[n..];
                    moved = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(conn_end(e))),
                Poll::Pending => break,
            }
        }
        if data.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Ended::Cancelled));
        }
        if conn.poll_gone(cx).is_ready() {
            return Poll::Ready(Err(Ended::Conn(ConnError::Reset)));
        }
        if moved {
            sleep.set(stall.map(|d| fcx.sleep_until(fcx.now() + d)));
        }
        match sleep.as_mut().as_pin_mut().map(|s| s.poll(cx)) {
            Some(Poll::Ready(Ok(()))) => Poll::Ready(Err(Ended::Conn(ConnError::TimedOut))),
            Some(Poll::Ready(Err(_))) => Poll::Ready(Err(Ended::Cancelled)),
            _ => Poll::Pending,
        }
    })
    .await
}

/// Serves one connection with `service` until it ends. Returns how it
/// ended, or the connection with its unread bytes after
/// [`Upgrade::Handoff`]. Returns [`ServeError::Cancelled`] if `fcx`'s
/// [region](fictionet::Cx#regions) is cancelled, also at a handoff or
/// during final shutdown, unless a failure takes precedence.
///
/// `info` identifies the connection to the service; [`listen`] fills it in. The
/// connection ends as soon as the client resets it, even while deferred
/// work runs and nothing reads ([`Connection::poll_gone`]). Deferred work
/// receives a child region; cancelling it closes only this connection.
/// A task failure in that region returns as [`ServeError::Pending`]
/// unless the driver already has a service or deferred-work failure.
///
/// Final shutdown waits at most five seconds. Cancellation returns
/// [`ServeError::Cancelled`] unless there is a primary failure. Other shutdown
/// failures keep [`Served::Closed`]. [`Service::on_end`] is not called again.
#[deny(clippy::let_underscore_must_use)]
pub async fn connection<S, C>(
    fcx: &Cx,
    conn: C,
    info: ConnInfo,
    service: &mut S,
    state: &S::State,
    opts: &ServeOptions,
) -> Result<Served<Box<dyn Connection>>, ServeError<S::Error>>
where
    S: Service,
    C: Connection,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    let mut result = None;
    let region_result = {
        let slot = &mut result;
        let finished = fictionet::sync::Mutex::new(None);
        let finished_ref = &finished;
        let info = info.clone();
        let mut region = std::pin::pin!(fcx.region(|child| async move {
            *slot = Some(serve_in_region(&child, conn, info, service, state, opts).await);
            *finished_ref.lock() = Some(child);
            Ok(())
        }));
        std::future::poll_fn(|cx| {
            let polled = region.as_mut().poll(cx);
            if polled.is_pending() {
                // The connection has ended but its spawned work is still running.
                // A region with no remaining work ends without a run-wide wake.
                let child = finished.lock().take();
                if let Some(child) = child {
                    child.cancel();
                }
            }
            polled
        })
        .await
    };
    let mut result = result.expect("the connection region completed");
    if let Err(e) = region_result {
        let cancelled =
            std::iter::successors(Some(&*e as &(dyn std::error::Error + 'static)), |e| {
                e.source()
            })
            .any(|e| e.is::<Cancelled>());
        if !cancelled {
            result = match result {
                Err(ServeError::Service(_) | ServeError::Pending(_)) => result,
                _ => Err(ServeError::Pending(e)),
            };
        }
    }
    result
}

async fn serve_in_region<S, C>(
    fcx: &Cx,
    conn: C,
    info: ConnInfo,
    service: &mut S,
    state: &S::State,
    opts: &ServeOptions,
) -> Result<Served<Box<dyn Connection>>, ServeError<S::Error>>
where
    S: Service,
    C: Connection,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    let conn: Box<dyn Connection> = Box::new(conn);
    let wake = WakeHandle::new();
    let _wake_owner = WakeOwner(wake.clone());
    run(fcx, conn, info, service, state, opts, wake).await
}

#[deny(clippy::let_underscore_must_use)]
async fn run<S, C>(
    fcx: &Cx,
    mut conn: C,
    info: ConnInfo,
    service: &mut S,
    state: &S::State,
    opts: &ServeOptions,
    wake: WakeHandle,
) -> Result<Served<C>, ServeError<S::Error>>
where
    S: Service,
    C: Connection,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    let _note = PanicNote::new(std::any::type_name::<S>(), &info);
    let mut core: Core<S> = Core::new(
        Some(fcx.clone()),
        Arc::new(fcx.clone()),
        service,
        info,
        opts,
        Some(wake),
        fcx.now(),
    );
    core.open(service, state, fcx.now());
    let mut buf = vec![0u8; READ];
    let mut run = 0u32;
    loop {
        // What is out counts against the budget while it is written.
        core.recharge(service);
        // Write what is out.
        while let Some(out) = core.out.pop_front() {
            let Out(bytes, credit) = out;
            if bytes.is_empty() {
                core.wrote(credit);
                continue;
            }
            match write_all(fcx, &mut conn, &bytes, opts.write_timeout).await {
                Ok(()) => core.wrote(credit),
                Err(end) => core.broken(end),
            }
        }

        let now = fcx.now();
        let next = core.advance(service, state, now);
        match next {
            Next::Again => {
                run = (run + 1) % 64;
                if run == 0 && fcx.yield_now().await.is_err() {
                    core.broken(Ended::Cancelled);
                }
            }

            Next::Wait {
                read,
                wake,
                deadline,
            } => {
                let woke = {
                    let conn = &mut conn;
                    let buf = &mut buf;
                    let core = &mut core;
                    let service = &mut *service;
                    let mut sleep = pin!(deadline.map(|t| fcx.sleep_until(t)));
                    let mut cancelled = pin!(fcx.cancelled());
                    poll_fn(|cx| {
                        if cancelled.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(Woke {
                                cancelled: true,
                                ..Woke::default()
                            });
                        }
                        let mut woke = Woke::default();
                        let mut any =
                            core.has_work() && core.poll_work(service, state, fcx.now(), cx);
                        any |= wake && core.s.wake.poll(cx).is_ready();
                        if read && let Poll::Ready(r) = conn.poll_read(fcx, cx, buf) {
                            woke.read = Some(r);
                            any = true;
                        }
                        woke.gone = conn.poll_gone(cx).is_ready();
                        any |= woke.gone;
                        if let Some(s) = sleep.as_mut().as_pin_mut() {
                            any |= s.poll(cx).is_ready();
                        }
                        if any {
                            Poll::Ready(woke)
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                };
                if woke.cancelled {
                    core.broken(Ended::Cancelled);
                }
                match woke.read {
                    Some(Ok(0)) => core.input_eof(),
                    Some(Ok(n)) => core.input(&buf[..n], fcx.now()),
                    Some(Err(e)) => core.broken(conn_end(e)),
                    None => {}
                }
                // A reset both fails the read and wakes the gone watch. Count it
                // once: a second end would close the connection without `on_end`.
                if woke.gone && !matches!(woke.read, Some(Err(_))) {
                    core.broken(Ended::Conn(ConnError::Reset));
                }
            }
            Next::Upgrade(how) => {
                // A cancelled region hands nothing on, as it writes nothing.
                if fcx.is_cancelled() {
                    core.broken(Ended::Cancelled);
                    continue;
                }
                let unread = core.unread();
                core.s.wake.close();
                return Ok(Served::Upgraded(how, Prefixed::new(unread, conn)));
            }
            Next::Closed(end) => {
                let shutdown = if end.writable() {
                    match fcx
                        .race(Some(fcx.now() + Duration::from_secs(5)), conn.shutdown(fcx))
                        .await
                    {
                        Ok(Ok(())) => None,
                        Ok(Err(e)) => Some(e),
                        Err(RaceError::Cancelled) => Some(ConnError::Cancelled),
                        Err(RaceError::Deadline) => Some(ConnError::TimedOut),
                    }
                } else {
                    None
                };
                let failure = core.failure.take();
                drop(core);
                return match failure {
                    Some(Failure::Service(e)) => Err(ServeError::Service(e)),
                    Some(Failure::Pending(e)) => Err(ServeError::Pending(e)),
                    None if end == Ended::Cancelled || shutdown == Some(ConnError::Cancelled) => {
                        Err(ServeError::Cancelled)
                    }
                    None => Ok(Served::Closed(end)),
                };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Listening

/// Accepts connections on `listener` and serves each with a fresh service
/// from `make`, in a task of its own, until the listener closes or the
/// region is cancelled. At most `max_conns` connections are served at once
/// ([`DEFAULT_MAX_CONNS`](fictionet::stdlib::world::net::DEFAULT_MAX_CONNS) is the usual choice); past that, a new one is
/// reset as soon as it is accepted. Each counts until its socket is gone,
/// so a client that never finishes closing cannot open more. Connections
/// are numbered from 1, in the order they are accepted. `sandbox` names
/// the sandbox each connection came from, by its peer address, in its
/// [`ConnInfo`]. Returns the accepting task.
///
/// A connection's failure ends its task with `Ok`, so it does not fail the world.
pub fn listen<S, M, A: Accept>(
    fcx: &Cx,
    mut listener: A,
    state: Arc<S::State>,
    make: M,
    opts: ServeOptions,
    max_conns: usize,
    sandbox: Option<SandboxOf>,
) -> Task
where
    S: Service,
    M: Fn() -> S + Send + Sync + 'static,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    let make = Arc::new(make);
    fcx.spawn(move |fcx| async move {
        let open = Arc::new(AtomicUsize::new(0));
        let mut ids = 0u64;
        loop {
            let conn = match listener.accept(&fcx).await {
                Ok(conn) => conn,
                Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
                Err(_) => continue,
            };
            let mut info = ConnInfo::new(ids + 1, conn.local_addr(), conn.peer_addr());
            info.handshake = conn.handshake();
            info.sandbox = info
                .peer
                .and_then(|peer| sandbox.as_ref().and_then(|f| f(peer.ip())));
            let Some(guard) = Counted::enter(&open, max_conns) else {
                conn.reset();
                continue;
            };
            conn.hold_until_gone(guard);
            ids += 1;
            let (state, make, opts) = (state.clone(), make.clone(), opts.clone());
            fcx.spawn(move |fcx| async move {
                let mut service = make();
                let _ = connection(&fcx, conn, info, &mut service, &state, &opts).await;
                Ok(())
            });
        }
    })
}

// ---------------------------------------------------------------------------
// Datagrams

/// A sans-IO server for one UDP socket of one protocol, run by
/// [`datagram`]. The runner owns the socket and the output; the service
/// owns its state.
///
/// Each datagram is decoded on its own, with a fresh decoder that sees the
/// end of input after it, as DNS, DHCP, Kerberos and Modbus over UDP frame
/// their messages. The reply bytes of one datagram's items go back to its
/// sender as one datagram; [`DatagramContext::send_to`] sends more, to
/// anyone, from any call.
///
/// An error a call returns ends that call: the rest of the current
/// datagram is dropped, what the call asked for is still sent, and serving
/// goes on with the next datagram.
pub trait DatagramService: Send + 'static {
    /// This service's timer names. Use an enum, or `()` when no timers are needed.
    type Timer: Copy + Eq + Send + 'static;
    /// How one datagram's bytes become items.
    type Decoder: Decode + Send + 'static;
    /// State shared with the rest of the world, such as a directory.
    type State: Send + Sync + 'static;
    /// Why the service gives up on a call.
    type Error: core::error::Error + Send + Sync + 'static;

    /// A fresh decoder, for each datagram.
    fn decoder(&self) -> Self::Decoder;

    /// Serving starts, before the first datagram.
    fn on_open(
        &mut self,
        _state: &Self::State,
        _cx: &mut DatagramContext<'_, Self::Timer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// One decoded item of the current datagram. Append reply bytes for
    /// its sender with [`DatagramDriver::reply`].
    fn on_item(
        &mut self,
        item: <Self::Decoder as Decode>::Item,
        state: &Self::State,
        driver: &mut DatagramDriver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<DatagramFlow, Self::Error>;

    /// The timer named `timer`, set with [`DatagramContext::set_timer`],
    /// went off.
    fn on_timer(
        &mut self,
        _timer: Self::Timer,
        _state: &Self::State,
        _cx: &mut DatagramContext<'_, Self::Timer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The service's [`WakeHandle`] was woken. Several wakes before the
    /// runner gets to it are one call.
    fn on_wake(
        &mut self,
        _state: &Self::State,
        _cx: &mut DatagramContext<'_, Self::Timer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The decoder failed on the current datagram, or the datagram was
    /// larger than the decoder could hold ([`Fail::Refused`]). A reply,
    /// such as an error message, still goes to its sender; the rest of the
    /// datagram is dropped.
    fn on_fail(
        &mut self,
        _error: &Fail<<Self::Decoder as Decode>::Error>,
        _state: &Self::State,
        _driver: &mut DatagramDriver<'_, Self::Decoder, Self::Timer>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// What [`DatagramService::on_item`] does with the rest of its datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramFlow {
    /// Decode the next item of the datagram.
    Continue,
    /// Drop the rest of the datagram, and send the reply.
    Finish,
}

/// How [`datagram`] runs.
#[derive(Clone, Default)]
pub struct DatagramOptions {
    /// A budget the service's calls can check
    /// ([`DatagramContext::budget`]). The runner charges nothing to it.
    pub budget: Option<Budget>,
    /// Names the sandbox each datagram came from, in its [`ConnInfo`].
    pub sandbox: Option<SandboxOf>,
}

impl std::fmt::Debug for DatagramOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramOptions")
            .field("budget", &self.budget)
            .field("sandbox", &self.sandbox.is_some())
            .finish()
    }
}

/// What every [`DatagramService`] call can do: read the clock and
/// entropy, run timers, hand out a wake handle, and send datagrams.
/// [`DatagramService::on_open`], `on_timer` and `on_wake` take it as
/// `cx`; [`DatagramDriver`] derefs to it.
pub struct DatagramContext<'a, T = ()> {
    s: &'a mut DatagramScratch<T>,
    now: Instant,
    conn: &'a ConnInfo,
    timers: &'a [(T, Instant)],
    budget: Option<&'a Budget>,
}

impl<T: Copy + Eq> DatagramContext<'_, T> {
    common_calls!();

    /// The budget [`DatagramOptions::budget`] gave, for rejecting a
    /// request before retaining it. Nothing is charged to it for the
    /// service.
    pub fn budget(&self) -> Option<&Budget> {
        self.budget
    }

    /// How many bytes the socket has received so far, from every sender.
    pub fn bytes_in(&self) -> u64 {
        self.s.bytes_in
    }

    /// Sends `bytes` as one datagram to `to`, once this call returns.
    /// Several per call, to anyone: a retransmission in packets that fit
    /// the path, or a heartbeat from [`DatagramService::on_timer`].
    pub fn send_to(&mut self, to: SocketAddr, bytes: Vec<u8>) {
        self.s.sends.push((to, bytes));
    }
}

/// What a [`DatagramService`] call about one datagram sees: the
/// datagram's decoder, the reply to its sender, and everything of a
/// [`DatagramContext`]. [`DatagramService::on_item`] and `on_fail` take it
/// as `driver`.
pub struct DatagramDriver<'a, D, T = ()> {
    decoder: &'a mut D,
    reply: &'a mut Vec<u8>,
    unread: &'a [u8],
    cx: DatagramContext<'a, T>,
}

impl<D, T> DatagramDriver<'_, D, T> {
    /// The current datagram's decoder, read-only.
    pub fn peek_decoder(&self) -> &D {
        self.decoder
    }

    /// The current datagram's decoder. Changes apply to the rest of this
    /// datagram; the next one starts with a fresh decoder.
    pub fn decoder(&mut self) -> &mut D {
        self.decoder
    }

    /// Bytes to send to the datagram's sender, after anything already
    /// there. The replies to one datagram's items go back as one datagram.
    pub fn reply(&mut self) -> &mut Vec<u8> {
        self.reply
    }

    /// In [`DatagramService::on_fail`], the bytes of the datagram the
    /// decoder could not use. Empty in [`DatagramService::on_item`].
    pub fn unread(&self) -> &[u8] {
        self.unread
    }
}

impl<'a, D, T> std::ops::Deref for DatagramDriver<'a, D, T> {
    type Target = DatagramContext<'a, T>;

    fn deref(&self) -> &DatagramContext<'a, T> {
        &self.cx
    }
}

impl<'a, D, T> std::ops::DerefMut for DatagramDriver<'a, D, T> {
    fn deref_mut(&mut self) -> &mut DatagramContext<'a, T> {
        &mut self.cx
    }
}

/// What a datagram service's calls ask for, between calls.
struct DatagramScratch<T> {
    entropy: Arc<dyn Entropy>,
    timers: Vec<(T, Option<Duration>)>,
    wake: WakeHandle,
    sends: Vec<(SocketAddr, Vec<u8>)>,
    bytes_in: u64,
}

impl<T> DatagramScratch<T> {
    /// Sends the datagrams the last call asked for.
    fn send(&mut self, socket: &mut impl DatagramSocket) {
        for (to, bytes) in self.sends.drain(..) {
            socket.send_to(&bytes, to);
        }
    }
}

/// Serves every datagram on `socket` with one `service`, until the socket
/// closes or the region is cancelled.
///
/// The service's [`ConnInfo`] names the socket in `local`, with
/// [`Transport::Udp`], and in calls about a datagram its sender in `peer`
/// and the sender's sandbox ([`DatagramOptions::sandbox`]).
/// [`DatagramService::on_open`] is called once at the start; timers and
/// wakes work as over a connection. A panic is not caught: it ends the
/// run, as it does over a connection.
///
/// Returns `Ok(())` once the socket closes, and [`Cancelled`] if `fcx`'s
/// [region](fictionet::Cx#regions) is cancelled.
pub async fn datagram<S, D: DatagramSocket>(
    fcx: &Cx,
    mut socket: D,
    local: SocketAddr,
    service: &mut S,
    state: &S::State,
    opts: &DatagramOptions,
) -> Result<(), Cancelled>
where
    S: DatagramService,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    let base = ConnInfo {
        local: Some(local),
        transport: Transport::Udp,
        ..ConnInfo::default()
    };
    let _note = PanicNote::new(std::any::type_name::<S>(), &base);
    let mut s = DatagramScratch {
        entropy: Arc::new(fcx.clone()),
        timers: Vec::new(),
        wake: WakeHandle::new(),
        sends: Vec::new(),
        bytes_in: 0,
    };
    let mut timers: Vec<(S::Timer, Instant)> = Vec::new();
    let wake = s.wake.clone();
    let _wake_owner = WakeOwner(wake.clone());
    let budget = opts.budget.as_ref();
    // An error ends only the call that returned it: serving goes on.
    let _ = service.on_open(
        state,
        &mut DatagramContext {
            s: &mut s,
            now: fcx.now(),
            conn: &base,
            timers: &timers,
            budget,
        },
    );
    s.send(&mut socket);
    let mut run = 0u32;
    loop {
        let now = fcx.now();
        arm(&mut timers, &mut s.timers, now);
        if let Some(i) = due(&timers, now) {
            let (name, _) = timers.remove(i);
            let mut cx = DatagramContext {
                s: &mut s,
                now,
                conn: &base,
                timers: &timers,
                budget,
            };
            let _ = service.on_timer(name, state, &mut cx);
            s.send(&mut socket);
            continue;
        }
        if wake.take() {
            let mut cx = DatagramContext {
                s: &mut s,
                now,
                conn: &base,
                timers: &timers,
                budget,
            };
            let _ = service.on_wake(state, &mut cx);
            s.send(&mut socket);
            continue;
        }
        let deadline = timers.iter().map(|(_, at)| *at).min();
        let got = {
            let mut recv = pin!(socket.recv(fcx));
            let mut sleep = pin!(deadline.map(|t| fcx.sleep_until(t)));
            poll_fn(|cx| {
                if let Poll::Ready(r) = recv.as_mut().poll(cx) {
                    return Poll::Ready(Some(r));
                }
                if wake.poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                if let Some(s) = sleep.as_mut().as_pin_mut()
                    && s.poll(cx).is_ready()
                {
                    return Poll::Ready(None);
                }
                Poll::Pending
            })
            .await
        };
        let Some(got) = got else { continue };
        let (datagram, from) = match got {
            Ok(got) => got,
            Err(RecvError::Closed) => break Ok(()),
            Err(RecvError::Cancelled) => break Err(Cancelled),
        };
        let info = ConnInfo {
            peer: Some(from),
            sandbox: opts.sandbox.as_ref().and_then(|f| f(from.ip())),
            ..base.clone()
        };
        let _note = PanicNote::new(std::any::type_name::<S>(), &info);
        s.bytes_in = s.bytes_in.saturating_add(datagram.len() as u64);
        let mut stream = Stream::with_buffer(service.decoder(), datagram.len());
        let taken = stream.push(&datagram);
        stream.end();
        let mut reply = Vec::new();
        loop {
            let now = fcx.now();
            let (fail, unread) = match stream.next() {
                Some(Ok(item)) => {
                    let mut driver = DatagramDriver {
                        decoder: stream.decoder(),
                        reply: &mut reply,
                        unread: &[],
                        cx: DatagramContext {
                            s: &mut s,
                            now,
                            conn: &info,
                            timers: &timers,
                            budget,
                        },
                    };
                    let flow = service.on_item(item, state, &mut driver);
                    s.send(&mut socket);
                    if let Ok(DatagramFlow::Continue) = flow {
                        continue;
                    }
                    break;
                }
                Some(Err(fail)) => (fail, Some(stream.unread().to_vec())),
                // Longer than the decoder could hold at once.
                None if taken < datagram.len() => {
                    let fail = Fail::Refused {
                        unread: datagram.len(),
                        limit: stream.limit(),
                    };
                    (fail, None)
                }
                None => break,
            };
            let mut driver = DatagramDriver {
                decoder: stream.decoder(),
                reply: &mut reply,
                unread: unread.as_deref().unwrap_or(&datagram),
                cx: DatagramContext {
                    s: &mut s,
                    now,
                    conn: &info,
                    timers: &timers,
                    budget,
                },
            };
            let _ = service.on_fail(&fail, state, &mut driver);
            s.send(&mut socket);
            break;
        }
        // The replies to one datagram's items go back as one datagram.
        if !reply.is_empty() {
            socket.send_to(&reply, from);
        }
        run = (run + 1) % 64;
        if run == 0
            && let Err(cancelled) = fcx.yield_now().await
        {
            break Err(cancelled);
        }
    }
}

// ---------------------------------------------------------------------------
// The harness

/// Why a [`Harness`] call stopped.
#[derive(Debug)]
pub enum HarnessError<D, S> {
    /// The decoder failed. [`Service::on_fail`] ran, and its reply is in
    /// [`Harness::output`].
    Decode(Fail<D>),
    /// The service returned an error.
    Service(S),
    /// Ordered deferred work failed.
    Pending(fictionet::Error),
    /// The connection is closed: no more bytes are taken.
    Closed,
    /// The service asked for this upgrade, which hands the connection on:
    /// the harness runs nothing more.
    Upgraded(Upgrade),
}

impl<D: core::fmt::Display, S: core::fmt::Display> core::fmt::Display for HarnessError<D, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HarnessError::Decode(e) => write!(f, "decoder: {e}"),
            HarnessError::Service(_) => f.write_str("the service failed"),
            HarnessError::Pending(_) => f.write_str("deferred work failed"),
            HarnessError::Closed => f.write_str("the connection is closed"),
            HarnessError::Upgraded(u) => {
                write!(f, "the service asked for an upgrade: {}", u.as_str())
            }
        }
    }
}

impl<D: core::fmt::Debug + core::fmt::Display, S: core::error::Error + 'static> core::error::Error
    for HarnessError<D, S>
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            HarnessError::Service(e) => Some(e),
            HarnessError::Pending(e) => Some(&**e),
            HarnessError::Decode(_) | HarnessError::Closed | HarnessError::Upgraded(_) => None,
        }
    }
}

/// A waker that remembers it was woken, for the harness's polls.
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

/// Runs a service with no I/O and no runtime: push the client's bytes,
/// get the reply. For unit tests and fuzz targets. It
/// runs the same state machine as [`connection`], so timers, wakes, deferred
/// work, upgrades and ends behave as they do over a connection. The clock
/// stands still until [`advance`](Self::advance) moves it, unless bound
/// to a `Cx`, whose clock it reads instead.
///
/// Deferred work is polled until it waits on something other than
/// itself; [`poll`](Self::poll) polls it again. Work that needs a [`Cx`]
/// gets one from [`with_fcx`](Self::with_fcx).
pub struct Harness<S: Service> {
    service: S,
    state: S::State,
    core: Core<S>,
    now: Instant,
    opened: bool,
    output: Vec<u8>,
    upgraded: Option<Upgrade>,
    /// Whether a call returned the upgrade.
    reported: bool,
}

type HarnessResult<S> = Result<
    Vec<u8>,
    HarnessError<<<S as Service>::Decoder as Decode>::Error, <S as Service>::Error>,
>;

impl<S: Service> Harness<S>
where
    <S::Decoder as Decode>::Error: Clone,
{
    /// A connection to `service`, with `state`, at time zero, numbered 1,
    /// with no idle limit and a standalone stream initialized by `seed`.
    pub fn new(seed: Seed, service: S, state: S::State) -> Harness<S> {
        Harness::with_options(seed, service, state, ServeOptions::default().idle(None))
    }

    /// The same with `opts`: an idle limit and a budget.
    /// The standalone entropy stream starts from `seed`. TLS is not
    /// used.
    pub fn with_options(seed: Seed, service: S, state: S::State, opts: ServeOptions) -> Harness<S> {
        let info = ConnInfo {
            id: Some(1),
            ..ConnInfo::default()
        };
        let core = Core::new(
            None,
            Arc::new(SeededEntropy::new(seed)),
            &service,
            info,
            &opts,
            None,
            Instant::ZERO,
        );
        Harness {
            service,
            state,
            core,
            now: Instant::ZERO,
            opened: false,
            output: Vec::new(),
            upgraded: None,
            reported: false,
        }
    }

    /// The connection the service sees.
    pub fn with_conn(mut self, conn: ConnInfo) -> Harness<S> {
        self.core.info = conn;
        self
    }

    /// Binds the clock, entropy and deferred work to `fcx`. Call before
    /// opening the harness. Manual [`advance`](Self::advance) then panics.
    pub fn with_fcx(mut self, fcx: Cx) -> Harness<S> {
        assert!(!self.opened, "bind the context before opening the harness");
        self.now = fcx.now();
        self.core.idle_from = self.now;
        self.core.s.entropy = Arc::new(fcx.clone());
        self.core.fcx = Some(fcx);
        self
    }

    /// Runs the state machine until it waits.
    fn run(&mut self) -> HarnessResult<S> {
        self.read_clock();
        let mut reply = Vec::new();
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut idle_polls = 0;
        loop {
            self.drain(&mut reply);
            match self.core.advance(&mut self.service, &self.state, self.now) {
                Next::Again => {}
                Next::Wait { .. } => {
                    if !self.core.has_work() || idle_polls > 1000 {
                        break;
                    }
                    flag.0.store(false, Ordering::Release);
                    let progress = self.core.poll_work(
                        &mut self.service,
                        &self.state,
                        self.now,
                        &mut Context::from_waker(&waker),
                    );
                    if progress {
                        idle_polls = 0;
                    } else if flag.0.load(Ordering::Acquire) {
                        idle_polls += 1;
                    } else {
                        break;
                    }
                }
                Next::Upgrade(how) => {
                    self.upgraded = Some(how);
                    break;
                }
                Next::Closed(_) => break,
            }
        }
        self.drain(&mut reply);
        if let Some(f) = self.core.failure.take() {
            return Err(match f {
                Failure::Service(e) => HarnessError::Service(e),
                Failure::Pending(e) => HarnessError::Pending(e),
            });
        }
        if let Some(fail) = self.core.decode_fail.take() {
            return Err(HarnessError::Decode(fail));
        }
        if let Some(how) = self.upgraded
            && !self.reported
        {
            self.reported = true;
            return Err(HarnessError::Upgraded(how));
        }
        Ok(reply)
    }

    /// Takes what is out as written, after charging it as the driver
    /// does.
    fn drain(&mut self, reply: &mut Vec<u8>) {
        self.core.recharge(&self.service);
        while let Some(out) = self.core.out.pop_front() {
            let Out(b, credit) = out;
            self.output.extend_from_slice(&b);
            reply.extend_from_slice(&b);
            self.core.wrote(credit);
        }
    }

    fn read_clock(&mut self) {
        if let Some(fcx) = &self.core.fcx {
            self.now = fcx.now();
        }
    }

    /// Opens the connection, if it is not open yet: what the service
    /// sends first.
    pub fn open(&mut self) -> HarnessResult<S> {
        self.read_clock();
        if self.opened {
            return Ok(Vec::new());
        }
        self.opened = true;
        self.core.open(&mut self.service, &self.state, self.now);
        self.run()
    }

    fn check_open(&self) -> Result<(), HarnessError<<S::Decoder as Decode>::Error, S::Error>> {
        if let Some(how) = self.upgraded {
            return Err(HarnessError::Upgraded(how));
        }
        if self.closed() {
            return Err(HarnessError::Closed);
        }
        Ok(())
    }

    /// The client sends `bytes`. Returns the reply to them.
    pub fn push(&mut self, bytes: &[u8]) -> HarnessResult<S> {
        let mut reply = self.open()?;
        self.check_open()?;
        self.core.input(bytes, self.now);
        reply.extend(self.run()?);
        Ok(reply)
    }

    /// The client half-closes: the service sees the end of input.
    pub fn end(&mut self) -> HarnessResult<S> {
        let mut reply = self.open()?;
        self.check_open()?;
        self.core.input_eof();
        reply.extend(self.run()?);
        Ok(reply)
    }

    /// Moves the clock by `d`. Timers that come due go off, in order, each
    /// at its own time, so a timer set again from `on_timer` counts from
    /// when it went off; returns their replies. Panics when bound to a `Cx`.
    pub fn advance(&mut self, d: Duration) -> HarnessResult<S> {
        assert!(
            self.core.fcx.is_none(),
            "a context-bound harness uses the run clock"
        );
        let until = self.now + d;
        let mut reply = Vec::new();
        loop {
            if self.closed() || self.upgraded.is_some() {
                self.now = until;
                return Ok(reply);
            }
            let next = self.core.next_deadline();
            match next {
                Some(at) if at <= until => self.now = self.now.max(at),
                _ => {
                    self.now = until;
                    reply.extend(self.run()?);
                    return Ok(reply);
                }
            }
            reply.extend(self.run()?);
            if self.core.next_deadline() == next {
                // Due, and still waiting: deferred work holds it back.
                self.now = until;
                reply.extend(self.run()?);
                return Ok(reply);
            }
        }
    }

    /// Polls deferred work again, and handles a wake: what they wrote.
    pub fn poll(&mut self) -> HarnessResult<S> {
        if self.closed() || self.upgraded.is_some() {
            return Ok(Vec::new());
        }
        self.run()
    }

    /// A handle that wakes the service; [`poll`](Self::poll) runs the wake.
    pub fn wake_handle(&self) -> WakeHandle {
        self.core.s.wake.clone()
    }

    /// When the first armed timer goes off, if one is armed.
    pub fn deadline(&self) -> Option<Instant> {
        self.core.timers.iter().map(|(_, at)| *at).min()
    }

    /// When the timer `name` goes off, if it is armed.
    pub fn timer(&self, name: S::Timer) -> Option<Instant> {
        self.core
            .timers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, at)| *at)
    }

    /// How many deferred works run: ordered, then keyed.
    pub fn pending(&self) -> (usize, usize) {
        (self.core.ordered.len(), self.core.keyed.len())
    }

    /// Whether the connection has ended.
    pub fn closed(&self) -> bool {
        matches!(self.core.state, State::Ended(_))
    }

    /// How it ended.
    pub fn end_reason(&self) -> Option<Ended> {
        match self.core.state {
            State::Ended(end) => Some(end),
            _ => None,
        }
    }

    /// The upgrade the service asked for, if it did.
    pub fn upgraded(&self) -> Option<Upgrade> {
        self.upgraded
    }

    /// Every byte the service sent.
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// The service, to look at its state.
    pub fn service(&self) -> &S {
        &self.service
    }

    /// The service's shared state.
    pub fn state(&self) -> &S::State {
        &self.state
    }
}

impl<S: Service> Drop for Harness<S> {
    fn drop(&mut self) {
        self.core.s.wake.close();
    }
}

/// Bounded proofs over the timers, the budget, the connection count and
/// the wake handle, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../verification/lifecycle/kani/ServeProof.rs"]
mod proofs;
