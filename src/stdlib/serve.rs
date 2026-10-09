//! Services: a protocol's server, written once with no I/O, run over any
//! connection.
//!
//! A [`Service`] is the server side of one protocol for one connection.
//! It gets decoded items, appends reply bytes, records facts in the
//! run's [events](fictionet::events), and asks for timers. It reads no
//! clock and touches no socket, so it unit-tests with the [`Harness`]
//! here, fuzzes with the codec's contract tools, and a world copies its
//! file to change it. It has the shape of a FIX session: items in, bytes
//! and events and timers out.
//!
//! [`connection`] is the one driver that joins a service to a
//! [`Connection`]: it reads, decodes, calls the
//! service, writes its reply, honors its timers, and closes. [`listen`]
//! runs [`connection`] for every connection an [`Accept`] listener accepts, with a
//! cap on how many are open, and TLS first when the options ask for it.
//! [`datagram`] does the same for a UDP socket. The driver and the
//! [`Harness`] share one state machine, so a service that passes its
//! harness tests behaves the same over a real connection.
//!
//! The driver carries the codec tools without the service knowing:
//! a [`Transcript`] records both directions with a
//! [`Recorder`], and a [`FaultPlan`] runs
//! [`Faults`] on the bytes and items in, and
//! the bytes out.
//!
//! A service that echoes each line back, and closes on `quit`:
//!
//! ```
//! use fictionet::stdlib::codec::{Ending, LineError, Lines};
//! use fictionet::events::Event;
//! use fictionet::stdlib::serve::{Flow, Harness, Service, Driver};
//!
//! struct Echo;
//! impl Service for Echo {
//!     type Decoder = Lines;
//!     type State = ();
//!     type Error = std::convert::Infallible;
//!     fn decoder(&self) -> Lines { Lines::new(1024, Ending::LfOrCrlf) }
//!     fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), driver: &mut Driver<'_, Self::Decoder>) -> Result<Flow, Self::Error> {
//!         let line = line.unwrap_or_default();
//!         if line == b"quit" {
//!             return Ok(Flow::Close);
//!         }
//!         driver.record(Event::new("echo", "line").field("bytes", line.len() as u64));
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
//! assert_eq!(h.events().len(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! In a world, `listen` serves it on a port:
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::{Cx, Result, stdlib::{ip, tcp, serve}};
//! # struct Echo;
//! # impl serve::Service for Echo {
//! #     type Decoder = fictionet::stdlib::codec::Lines; type State = (); type Error = std::convert::Infallible;
//! #     fn decoder(&self) -> Self::Decoder { fictionet::stdlib::codec::Lines::new(64, fictionet::stdlib::codec::Ending::LfOrCrlf) }
//! #     fn on_item(&mut self, _: Result<Vec<u8>, fictionet::stdlib::codec::LineError>, _: &(), _: &mut serve::Driver<'_, Self::Decoder>) -> std::result::Result<serve::Flow, Self::Error> { Ok(serve::Flow::Continue) }
//! # }
//! # fn start(fcx: &Cx, side: fictionet::End) -> Result {
//! let (tcp, _udp, _icmp, _other) = ip::split_protocols(fcx, side);
//! let machine = tcp::endpoint(fcx, tcp, "10.0.0.10".parse()?);
//! serve::listen(fcx, machine.listen(7)?, Arc::new(()), || Echo, serve::ServeOptions::default());
//! # Ok(())
//! # }
//! ```
//!
//! [`net::Net`](fictionet::stdlib::net::Net) does this for every host and
//! port of a network, and [`httpd`](fictionet::stdlib::httpd) is HTTP as a
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
//!   [`Fail::Stuck`]. Input the buffer cannot take (a failed allocation,
//!   a datagram larger than the buffer) fails with [`Fail::Refused`].
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
//!   [`Service::on_end`] with [`Ended::Idle`].
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
//! - **Stops.** When the world stops, the service hears [`Ended::Cancelled`]
//!   and [`connection`] returns [`ServeError::Cancelled`], also when the stop
//!   comes during a TLS handshake. A stop is never a closed or broken
//!   connection.
//! - **Upgrades.** A call that returns [`Flow::Upgrade`] says what comes
//!   next: [`Upgrade::Tls`] shakes hands as a TLS server with
//!   [`ServeOptions::starttls`] and calls [`Service::on_open`] again over
//!   TLS (STARTTLS in SMTP, LDAP and Postgres); [`Upgrade::Decoder`] goes
//!   on with a fresh decoder; [`Upgrade::Handoff`] hands the connection
//!   and its unread bytes back in [`Served::Upgraded`], for a CONNECT
//!   tunnel. A decoder that ends ([`Step::End`](fictionet::stdlib::codec::Step::End))
//!   asks [`Service::on_decoder_end`] which.

use fictionet::sync::Mutex;
use fictionet::{Entropy, Seed, SeededEntropy};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use fictionet::events::{ConnInfo, Event, Level, Sandbox, Transport, opt};
use fictionet::stdlib::codec::{
    Buffer, ByteFault, Decode, Fail, FaultDelay, Faults, ItemFault, Record, Recorder, RewriteError,
    Rule, Side, Stream, StreamEvent,
};
use fictionet::stdlib::tls::{self, HandshakeError, ServerConfig, TlsConnection};
use fictionet::stdlib::{Accept, Accepted, DatagramSocket};
use fictionet::stdlib::{ConnError, Connection, ConnectionExt};
use fictionet::time::Instant;
use fictionet::{Cancelled, Cx, ErrorChain, RaceError, RecvError, Task};

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
/// (a length prefix over TCP, one message per datagram over UDP), is two
/// thin services over one core of its own: each picks its decoder and
/// hands the message to the shared code. [`ConnInfo::transport`] says
/// which one a call came over.
pub trait Service: Send + 'static {
    /// How this service's bytes become items.
    type Decoder: Decode + Send + 'static;
    /// State shared by every connection, such as a directory or an order book.
    type State: Send + Sync + 'static;
    /// Why the service gives up on a connection. The driver closes it,
    /// records `conn.error`, and returns the error.
    type Error: core::error::Error + Send + Sync + 'static;

    /// A fresh decoder for a new connection, and after
    /// [`Upgrade::Decoder`] or a TLS upgrade.
    fn decoder(&self) -> Self::Decoder;

    /// The connection is open and nothing is read yet. A protocol whose
    /// server speaks first (SSH, SMTP, FTP banners) writes here. Called
    /// again after [`Upgrade::Tls`], once the handshake is done:
    /// `driver.conn().tls` is then true.
    fn on_open(
        &mut self,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// One decoded item. Append reply bytes with [`Driver::reply`].
    fn on_item(
        &mut self,
        item: <Self::Decoder as Decode>::Item,
        state: &Self::State,
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error>;

    /// The timer named `timer`, set with [`Driver::set_timer`], went off.
    fn on_timer(
        &mut self,
        _timer: Timer,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// The connection's [`WakeHandle`] was woken. Several wakes before the
    /// driver gets to it are one call.
    fn on_wake(
        &mut self,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder>,
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
        _ctx: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// The decoder failed: the bytes are not this protocol. A reply, such
    /// as an error message, is written before the connection closes.
    fn on_fail(
        &mut self,
        _error: &Fail<<Self::Decoder as Decode>::Error>,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder>,
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
        _ctx: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Self::Error> {
        Ok(Flow::Upgrade(Upgrade::Handoff))
    }

    /// The connection ended, for the reason in `end`. Called once, last.
    fn on_end(
        &mut self,
        _end: Ended,
        _state: &Self::State,
        _ctx: &mut Driver<'_, Self::Decoder>,
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

/// A timer's name. A service names its timers, such as `"heartbeat"` and
/// `"logon"`, and [`Service::on_timer`] hears which one went off.
pub type Timer = &'static str;

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
    /// Shake hands as a TLS server on the connection, with the config
    /// [`ServeOptions::starttls`] picks, then go on with the same service
    /// over TLS: a fresh decoder, and [`Service::on_open`] again. STARTTLS
    /// in SMTP, IMAP and LDAP, and Postgres's `SSLRequest`.
    Tls,
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
    /// `tls`, `decoder` or `handoff`.
    pub fn as_str(self) -> &'static str {
        match self {
            Upgrade::Tls => "tls",
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
    /// The service returned [`Flow::Close`], or an error.
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
    /// [`ServeError::Cancelled`].
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

    /// The name in a `conn.close` event: `eof`, `closed`, `failed`,
    /// `idle`, `budget`, `reset`, `broken`, `timed_out` (a write took no
    /// bytes for [`ServeOptions::write_timeout`]), `error` or `cancelled`.
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
    events: &'a mut Vec<Event>,
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

    /// Records an event, from this connection.
    pub fn record(&mut self, event: Event) {
        self.events.push(event);
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
        *self.inner.waker.lock() = Some(cx.waker().clone());
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
        self.inner.waker.lock().take();
    }
}

/// Bytes connections may hold, shared by every connection charged to it:
/// one sandbox's connections in [`Net`](fictionet::stdlib::net::Net). Cheap to
/// clone; clones share the count.
///
/// Each connection charges the larger of its decoder's capacity and
/// [`ServeOptions::read_buffer`], the decoder's held state ([`Decode::held`]),
/// the bytes read but
/// not yet decoded, [`Service::held`], the reply bytes not yet written,
/// and [`Pending::held`]. A connection that would take the total past the
/// limit closes with [`Ended::Budget`]; one that cannot get its first charge
/// is closed before the service sees it. Code that holds bytes outside a
/// service, such as HTTP/2 on hyper, takes a [`Charge`] of its own.
#[derive(Clone)]
pub struct Budget {
    inner: Arc<BudgetInner>,
}

struct BudgetInner {
    used: AtomicUsize,
    limit: usize,
}

impl std::fmt::Debug for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget")
            .field("used", &self.used())
            .field("limit", &self.limit())
            .finish()
    }
}

impl Budget {
    /// At most `limit` bytes.
    pub fn new(limit: usize) -> Budget {
        Budget {
            inner: Arc::new(BudgetInner {
                used: AtomicUsize::new(0),
                limit,
            }),
        }
    }

    /// Bytes charged now.
    pub fn used(&self) -> usize {
        self.inner.used.load(Ordering::Relaxed)
    }

    /// The limit.
    pub fn limit(&self) -> usize {
        self.inner.limit
    }

    /// Moves a charge from `from` bytes to `to`. Refuses, changing
    /// nothing, if that would pass the limit.
    // Rust 1.99 deprecates fetch_update for try_update, which is newer than
    // the MSRV (1.91).
    #[allow(deprecated)]
    fn recharge(&self, from: usize, to: usize) -> bool {
        if to <= from {
            self.inner.used.fetch_sub(from - to, Ordering::Relaxed);
            return true;
        }
        let more = to - from;
        self.inner
            .used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(more).filter(|n| *n <= self.inner.limit)
            })
            .is_ok()
    }

    /// A charge of `bytes`, or `None` if they do not fit.
    pub fn charge(&self, bytes: usize) -> Option<Charge> {
        let mut charge = Charge {
            budget: self.clone(),
            now: 0,
        };
        charge.set(bytes).then_some(charge)
    }
}

/// Bytes charged to a [`Budget`], given back when dropped.
pub struct Charge {
    budget: Budget,
    now: usize,
}

impl std::fmt::Debug for Charge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Charge").field("bytes", &self.now).finish()
    }
}

impl Charge {
    /// The bytes charged now.
    pub fn bytes(&self) -> usize {
        self.now
    }

    /// Charges `to` bytes instead. Refuses, changing nothing, if that
    /// would take the budget past its limit; less always fits.
    pub fn set(&mut self, to: usize) -> bool {
        if to == self.now {
            return true;
        }
        if self.budget.recharge(self.now, to) {
            self.now = to;
            true
        } else {
            false
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.recharge(self.now, 0);
    }
}

/// The service's side of the driver, for one call: the reply, the clock
/// reading the driver took, seeded randomness, the events to record, and
/// what the call asked for. Every [`Service`] method takes it as `driver`.
pub struct Driver<'a, D> {
    decoder: &'a mut D,
    s: &'a mut Scratch,
    now: Instant,
    conn: &'a ConnInfo,
    timers: &'a [(Timer, Instant)],
}

impl<D> Driver<'_, D> {
    /// The active decoder. Access stops item faults for this connection.
    /// Over UDP, item and failure calls access the current datagram's decoder.
    /// Other calls use a separate decoder whose changes do not affect datagrams.
    pub fn decoder(&mut self) -> &mut D {
        self.s.decoder_touched = true;
        self.decoder
    }

    /// Bytes to send, after anything already there. Over UDP, they go to
    /// the sender of the datagram being handled, as one datagram.
    pub fn reply(&mut self) -> &mut Vec<u8> {
        &mut self.s.reply
    }

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

    /// Arms the timer `name` to go off `d` after this call's reply is
    /// written, replacing it if it is armed.
    pub fn set_timer(&mut self, name: Timer, d: Duration) {
        self.s.timers.retain(|(n, _)| *n != name);
        self.s.timers.push((name, Some(d)));
    }

    /// Disarms the timer `name`.
    pub fn cancel_timer(&mut self, name: Timer) {
        self.s.timers.retain(|(n, _)| *n != name);
        self.s.timers.push((name, None));
    }

    /// When the timer `name` goes off, if it is armed. A timer set in this
    /// call says `now` plus its duration.
    pub fn timer(&self, name: Timer) -> Option<Instant> {
        if let Some((_, d)) = self.s.timers.iter().find(|(n, _)| *n == name) {
            return d.map(|d| self.now + d);
        }
        self.timers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, at)| *at)
    }

    /// Records `event` in the run's events, from this connection.
    pub fn record(&mut self, event: Event) {
        self.s.events.push(event);
    }

    /// The connection: its number, sandbox, addresses and transport.
    pub fn conn(&self) -> &ConnInfo {
        self.conn
    }

    /// How many bytes the client has sent so far.
    pub fn bytes_in(&self) -> u64 {
        self.s.bytes_in
    }

    /// In [`Service::on_fail`], the bytes the decoder could not use: a
    /// message cut off by the end of input, or bytes that are not this
    /// protocol. In [`Service::on_timer`], the bytes still buffered by the
    /// stream decoder. Empty in every other call.
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

    /// A handle that wakes this connection's service from anywhere: see
    /// [`WakeHandle`].
    pub fn wake_handle(&self) -> WakeHandle {
        self.s.wake.clone()
    }

    /// Sends `bytes` as one datagram to `to`. For datagram services
    /// ([`datagram`]): several per call, to anyone, at any time, such
    /// as a retransmission in packets that fit the path, or a heartbeat
    /// from [`Service::on_timer`]. A connection's driver drops them.
    pub fn send_to(&mut self, to: SocketAddr, bytes: Vec<u8>) {
        self.s.datagrams.push((to, bytes));
    }
}

/// What the per-connection state looks like to a call.
struct Scratch {
    decoder_touched: bool,
    reply: Vec<u8>,
    events: Vec<Event>,
    datagrams: Vec<(SocketAddr, Vec<u8>)>,
    entropy: Arc<dyn Entropy>,
    timers: Vec<(Timer, Option<Duration>)>,
    ordered: Vec<Box<dyn Pending>>,
    keyed: Vec<(u64, Option<Box<dyn Pending>>)>,
    wake: WakeHandle,
    bytes_in: u64,
    unread: Vec<u8>,
}

impl Scratch {
    fn new(entropy: Arc<dyn Entropy>) -> Scratch {
        Scratch {
            decoder_touched: false,
            reply: Vec::new(),
            events: Vec::new(),
            datagrams: Vec::new(),
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
        self.datagrams.clear();
        self.ordered.clear();
        self.keyed.clear();
    }
}

/// Applies the timer requests of the last call at `now`.
fn arm(
    timers: &mut Vec<(Timer, Instant)>,
    requests: &mut Vec<(Timer, Option<Duration>)>,
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
fn due(timers: &[(Timer, Instant)], now: Instant) -> Option<usize> {
    let (i, (_, at)) = timers.iter().enumerate().min_by_key(|(_, (_, at))| *at)?;
    (*at <= now).then_some(i)
}

/// Names a service and its connection in a panic that unwinds past it.
///
/// A panic in world code is the world's bug. Fictionet does not catch it:
/// it ends the run. The panic's own message says where in the code it
/// happened; a `PanicNote` alive while it unwinds adds which service and
/// connection, on standard error. [`connection`], [`datagram`] and
/// HTTP/2 in [`httpd`](fictionet::stdlib::httpd) keep one while they call
/// world code.
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

// ---------------------------------------------------------------------------
// Options, transcripts and fault plans

/// The bytes both ways of every connection a driver served, bounded.
///
/// Records items and skipped bytes from the client as the service's
/// decoder read them ([`Side::Client`]), and each write to the
/// client as one skipped run ([`Side::Server`]). Items are
/// kept as their exact bytes only, so one transcript serves any protocol;
/// failures keep their message. The tag is the connection number.
#[derive(Clone)]
pub struct Transcript {
    inner: Arc<Mutex<Recorder<(), String>>>,
}

impl Transcript {
    /// Keeps at most `max_entries` records and `max_bytes` of their bytes,
    /// evicting the oldest.
    pub fn new(max_entries: usize, max_bytes: usize) -> Transcript {
        Transcript {
            inner: Arc::new(Mutex::new(Recorder::new(max_entries, max_bytes))),
        }
    }

    /// The records kept, oldest first.
    pub fn records(&self) -> Vec<Record<(), String>> {
        self.lock().iter().cloned().collect()
    }

    /// How many records were dropped for the bounds.
    pub fn dropped(&self) -> u64 {
        self.lock().dropped()
    }

    fn lock(&self) -> fictionet::sync::MutexGuard<'_, Recorder<(), String>> {
        self.inner.lock()
    }

    fn observe<T, E: core::fmt::Display>(
        &self,
        tag: u64,
        direction: Side,
        event: StreamEvent<'_, T, E>,
    ) {
        let mut recorder = self.lock();
        match event {
            StreamEvent::Item { bytes, range, .. } => {
                recorder.observe_tagged(
                    tag,
                    direction,
                    StreamEvent::Item {
                        item: &(),
                        bytes,
                        range,
                    },
                );
            }
            StreamEvent::Skipped { bytes, range } => {
                recorder.observe_tagged(tag, direction, StreamEvent::Skipped { bytes, range });
            }
            StreamEvent::Ended { offset } => {
                recorder.observe_tagged(tag, direction, StreamEvent::Ended { offset });
            }
            StreamEvent::Failed {
                error,
                bytes,
                range,
            } => {
                let error = match error {
                    Fail::Protocol(e) => Fail::Protocol(e.to_string()),
                    Fail::Truncated { unread } => Fail::Truncated { unread: *unread },
                    Fail::Stuck { unread, capacity } => Fail::Stuck {
                        unread: *unread,
                        capacity: *capacity,
                    },
                    Fail::Refused { unread, limit } => Fail::Refused {
                        unread: *unread,
                        limit: *limit,
                    },
                };
                recorder.observe_tagged(
                    tag,
                    direction,
                    StreamEvent::Failed {
                        error: &error,
                        bytes,
                        range,
                    },
                );
            }
        }
    }
}

/// A fault plan for [`Faults`]: byte rules for each direction and item
/// rules for the client's items. Decisions draw from the driver's entropy source.
///
/// Item rules run on the client's decoded items before the service sees
/// them, through a second decoder: a replacement is raw bytes the service
/// then decodes. Delays are honored by the driver: it waits before the
/// bytes after the delay's offset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Rules for each chunk read from the client.
    pub inbound: Vec<Rule<ByteFault>>,
    /// Rules for each chunk written to the client.
    pub outbound: Vec<Rule<ByteFault>>,
    /// Rules for each item the client sent.
    pub items: Vec<Rule<ItemFault<Vec<u8>>>>,
}

/// A fault plan the world can change while connections run. When it changes,
/// every connection served with it uses the new rules from its next chunk
/// or item. Cheap to clone; clones share the plan.
#[derive(Clone, Default)]
pub struct FaultPlan {
    inner: Arc<Mutex<Arc<Plan>>>,
}

impl std::fmt::Debug for FaultPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

impl FaultPlan {
    /// A plan with these rules.
    pub fn new(plan: Plan) -> FaultPlan {
        FaultPlan {
            inner: Arc::new(Mutex::new(Arc::new(plan))),
        }
    }

    /// Replaces the rules.
    pub fn set(&self, plan: Plan) {
        *self.inner.lock() = Arc::new(plan);
    }

    /// Removes every rule.
    pub fn clear(&self) {
        self.set(Plan::default());
    }

    /// The rules now.
    pub fn get(&self) -> Arc<Plan> {
        self.inner.lock().clone()
    }
}

/// Names the sandbox at an address, for the [`ConnInfo`] of a datagram
/// ([`ServeOptions::sandbox`]).
pub type SandboxOf = Arc<dyn Fn(std::net::IpAddr) -> Option<Sandbox> + Send + Sync>;

/// Chooses the TLS config for a handshake from the client's SNI. `None`
/// rejects the handshake with `unrecognized_name`.
pub type TlsSelect = Arc<dyn Fn(Option<&str>, &Cx) -> Option<Arc<ServerConfig>> + Send + Sync>;

/// How [`listen`] and [`connection`] run.
#[derive(Clone)]
pub struct ServeOptions {
    /// Connections served at once; past this, a new one is reset as soon
    /// as it is accepted, and counts until its socket is gone. Default 64.
    pub max_conns: usize,
    /// Close a connection after this long with no bytes from the client,
    /// while the driver waits for them. Default 10 seconds. `None` waits
    /// forever.
    pub idle: Option<Duration>,
    /// End a connection whose write takes no bytes for this long: a client
    /// that stops reading. Default 10 seconds. `None` waits forever; a
    /// reset or the world stopping still ends the wait.
    pub write_timeout: Option<Duration>,
    /// Records both directions.
    pub record: Option<Transcript>,
    /// Faults on the bytes and items.
    pub faults: Option<FaultPlan>,
    /// Shake hands first, with the config this picks.
    pub tls: Option<TlsSelect>,
    /// The config for [`Upgrade::Tls`]. Without one, a service that asks
    /// for TLS is closed with a `conn.error` event.
    pub starttls: Option<TlsSelect>,
    /// How long a client has from connecting (or from STARTTLS) to finish
    /// its TLS handshake. Default 10 seconds.
    pub handshake: Duration,
    /// Record `conn.open` and `conn.close` events. Default on.
    pub connection_events: bool,
    /// The read buffer's limit, at least the decoder's capacity. Larger
    /// lets the decoder see more at once. Default 0: the capacity.
    pub read_buffer: usize,
    /// The bytes each connection's holdings are charged to. Default none.
    pub budget: Option<Budget>,
    /// Names the sandbox each datagram came from, in its [`ConnInfo`].
    /// [`Net`](fictionet::stdlib::net::Net) sets it; a connection's sandbox is
    /// given with its `ConnInfo` instead.
    pub sandbox: Option<SandboxOf>,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            max_conns: 64,
            idle: Some(Duration::from_secs(10)),
            write_timeout: Some(Duration::from_secs(10)),
            record: None,
            faults: None,
            tls: None,
            starttls: None,
            handshake: Duration::from_secs(10),
            connection_events: true,
            read_buffer: 0,
            budget: None,
            sandbox: None,
        }
    }
}

impl std::fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeOptions")
            .field("max_conns", &self.max_conns)
            .field("idle", &self.idle)
            .field("write_timeout", &self.write_timeout)
            .field("record", &self.record.is_some())
            .field("faults", &self.faults)
            .field("tls", &self.tls.is_some())
            .field("starttls", &self.starttls.is_some())
            .field("connection_events", &self.connection_events)
            .field("budget", &self.budget)
            .finish()
    }
}

impl ServeOptions {
    /// Records both directions in `transcript`.
    pub fn record(self, transcript: Transcript) -> ServeOptions {
        ServeOptions {
            record: Some(transcript),
            ..self
        }
    }

    /// Runs `plan` on every connection.
    pub fn faults(self, plan: FaultPlan) -> ServeOptions {
        ServeOptions {
            faults: Some(plan),
            ..self
        }
    }

    /// Shakes hands with `config` for every name.
    pub fn tls(self, config: Arc<ServerConfig>) -> ServeOptions {
        ServeOptions {
            tls: Some(Arc::new(move |_, _| Some(config.clone()))),
            ..self
        }
    }

    /// Shakes hands with the config `select` picks for the client's SNI.
    pub fn tls_by_name(
        self,
        select: impl Fn(Option<&str>, &Cx) -> Option<Arc<ServerConfig>> + Send + Sync + 'static,
    ) -> ServeOptions {
        ServeOptions {
            tls: Some(Arc::new(select)),
            ..self
        }
    }

    /// Shakes hands with `config` when the service asks for
    /// [`Upgrade::Tls`].
    pub fn starttls(self, config: Arc<ServerConfig>) -> ServeOptions {
        ServeOptions {
            starttls: Some(Arc::new(move |_, _| Some(config.clone()))),
            ..self
        }
    }

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

    /// Sets the connection cap.
    pub fn max_conns(self, max_conns: usize) -> ServeOptions {
        ServeOptions { max_conns, ..self }
    }

    /// Charges every connection to `budget`.
    pub fn budget(self, budget: Budget) -> ServeOptions {
        ServeOptions {
            budget: Some(budget),
            ..self
        }
    }

    /// Turns `conn.open` and `conn.close` events on or off.
    pub fn connection_events(self, on: bool) -> ServeOptions {
        ServeOptions {
            connection_events: on,
            ..self
        }
    }
}

// ---------------------------------------------------------------------------
// Handing back

/// Why [`connection`] stopped early. The connection was closed. For a failure,
/// the run's events have a `conn.error` event that says why.
#[derive(Debug)]
pub enum ServeError<E> {
    /// The service returned this error.
    Service(E),
    /// Ordered deferred work failed.
    Pending(fictionet::Error),
    /// The connection's [region](fictionet::Cx#regions) or its parent was
    /// cancelled. A running service hears [`Ended::Cancelled`] in
    /// [`Service::on_end`]. Cancellation during the TLS handshake or while
    /// the service is already ending closes the connection immediately.
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
    /// connection with its unread bytes. [`connection`] performs
    /// [`Upgrade::Tls`] itself and returns only [`Upgrade::Handoff`].
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
// Faults on one connection

/// Bytes waiting to enter the decoder, and the waits between them that
/// delay faults asked for.
enum Segment {
    Bytes(Vec<u8>, usize),
    Wait(Duration),
}

/// The fault state of one connection.
struct ConnFaults<D: Decode> {
    plan: FaultPlan,
    pending: VecDeque<Segment>,
    eof: bool,
    inbound: Faults,
    outbound: Faults,
    /// The second decoder item rules run on. Gone once it fails or ends.
    front: Option<Stream<D>>,
    /// Why item rules stopped, until the driver records it.
    stopped: Option<&'static str>,
}

// The fault engine hands the replacement type by reference, `&Vec<u8>`.
#[allow(clippy::ptr_arg)]
fn write_raw(value: &Vec<u8>, out: &mut Buffer) -> Result<(), RewriteError<Infallible>> {
    if value.len() > out.room() {
        return Err(RewriteError::TooLong { limit: out.limit() });
    }
    if out.push(value) != value.len() {
        return Err(RewriteError::Allocation);
    }
    Ok(())
}

/// The largest buffer item faults may build for one item or chunk.
const FAULT_OUTPUT: usize = 4 << 20;
/// The most items a hold rule may keep at once.
const FAULT_HELD: usize = 256;

impl<D: Decode> ConnFaults<D>
where
    D::Error: Clone,
{
    fn new(plan: &FaultPlan, decoder: D) -> ConnFaults<D> {
        ConnFaults {
            plan: plan.clone(),
            pending: VecDeque::new(),
            eof: false,
            inbound: Faults::new(FAULT_OUTPUT, FAULT_HELD),
            outbound: Faults::new(FAULT_OUTPUT, FAULT_HELD),
            front: Some(Stream::new(decoder)),
            stopped: None,
        }
    }

    /// Runs the byte rules for the client's chunk, then the item rules,
    /// and adds what comes out to `queue`.
    fn inbound(
        &mut self,
        entropy: &dyn Entropy,
        chunk: &[u8],
        eof: bool,
        queue: &mut VecDeque<Segment>,
    ) {
        let plan = self.plan.get();
        let mut pieces: Vec<Segment> = Vec::new();
        if chunk.is_empty() {
        } else if plan.inbound.is_empty() {
            pieces.push(Segment::Bytes(chunk.to_vec(), 0));
        } else {
            let mut out = Vec::new();
            match self.inbound.bytes(entropy, &plan.inbound, chunk, &mut out) {
                Ok(Some(FaultDelay { at, duration })) => {
                    let at = at.min(out.len());
                    let rest = out.split_off(at);
                    pieces.push(Segment::Bytes(out, 0));
                    pieces.push(Segment::Wait(duration));
                    pieces.push(Segment::Bytes(rest, 0));
                }
                Ok(None) => pieces.push(Segment::Bytes(out, 0)),
                Err(_) => pieces.push(Segment::Bytes(chunk.to_vec(), 0)),
            }
        }
        self.pending.extend(pieces);
        self.eof |= eof;
        // Framing waits until the service asks for its next item.
        if self.front.is_none() {
            queue.append(&mut self.pending);
        }
    }

    fn pump(&mut self, entropy: &dyn Entropy, queue: &mut VecDeque<Segment>) {
        let plan = self.plan.get();
        loop {
            let Some(front) = self.front.as_mut() else {
                queue.append(&mut self.pending);
                return;
            };
            let mut out = Vec::new();
            let mut pushed = 0;
            if let Some(Segment::Bytes(bytes, at)) = self.pending.front_mut() {
                let room = self.inbound.room(front, &out);
                let end = bytes.len().min(at.saturating_add(room));
                pushed = front.push(&bytes[*at..end]);
                *at += pushed;
                if *at == bytes.len() {
                    self.pending.pop_front();
                }
            }
            if self.eof && self.pending.is_empty() {
                front.end();
            }
            let result = self
                .inbound
                .next_with(entropy, front, &mut out, &plan.items, write_raw);
            let progressed = result.is_some();
            if let Some(Ok(Some(FaultDelay { at, duration }))) = result {
                let tail = out.split_off(at.min(out.len()));
                if !out.is_empty() {
                    queue.push_back(Segment::Bytes(std::mem::take(&mut out), 0));
                }
                queue.push_back(Segment::Wait(duration));
                out = tail;
            }
            if !out.is_empty() {
                queue.push_back(Segment::Bytes(out, 0));
            }
            if front.is_done() {
                let why = if front.failed().is_some() {
                    "failed"
                } else {
                    "ended"
                };
                self.stop(why, queue);
                return;
            }
            if !queue.is_empty() {
                return;
            }
            if pushed == 0 && !progressed {
                if matches!(self.pending.front(), Some(Segment::Wait(_))) {
                    queue.push_back(self.pending.pop_front().unwrap());
                } else if matches!(self.pending.front(), Some(Segment::Bytes(_, _))) {
                    self.stop("stuck", queue);
                }
                return;
            }
        }
    }

    fn stop(&mut self, why: &'static str, queue: &mut VecDeque<Segment>) {
        if let Some(front) = self.front.take() {
            let mut bytes = Vec::new();
            let _ = self.inbound.flush(&mut bytes);
            bytes.extend_from_slice(front.unread());
            if !bytes.is_empty() {
                queue.push_back(Segment::Bytes(bytes, 0));
            }
            self.stopped = Some(why);
        }
        queue.append(&mut self.pending);
    }

    /// The `conn.faults` event for item rules that stopped since the last
    /// call: the client's bytes went on unchanged from there.
    fn stopped(&mut self) -> Option<Event> {
        let why = self.stopped.take()?;
        let summary = match why {
            "decoder" => "item faults stopped: the service accessed its decoder",
            "upgrade" => "item faults stopped: the service upgraded the connection",
            "failed" => "item faults stopped: the client's bytes did not decode",
            "ended" => "item faults stopped: the decoder ended",
            _ => "item faults stopped: the decoder could take no more",
        };
        Some(
            Event::new("conn", "faults")
                .level(Level::Notice)
                .summary(summary)
                .field("stopped", why),
        )
    }

    /// Runs the outbound byte rules over one chunk: the bytes to write and
    /// where to wait.
    fn outbound(&mut self, entropy: &dyn Entropy, chunk: Vec<u8>) -> (Vec<u8>, Option<FaultDelay>) {
        let plan = self.plan.get();
        if plan.outbound.is_empty() {
            return (chunk, None);
        }
        let mut out = Vec::new();
        match self
            .outbound
            .bytes(entropy, &plan.outbound, &chunk, &mut out)
        {
            Ok(delay) => (out, delay),
            Err(_) => (chunk, None),
        }
    }
}

// ---------------------------------------------------------------------------
// The state machine the driver and the harness share

/// What the driver writes, in order.
enum Out {
    /// Bytes, and the work (by number) whose piece of that many bytes is
    /// all written once they are.
    Bytes(Vec<u8>, Option<(u64, u64)>),
    Delay(Duration),
}

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
    /// An inbound fault delay: wait this long, then ask again.
    Sleep(Duration),
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
    faults: Option<ConnFaults<S::Decoder>>,
    queue: VecDeque<Segment>,
    record: Option<Transcript>,
    s: Scratch,
    info: ConnInfo,
    timers: Vec<(Timer, Instant)>,
    idle: Option<Duration>,
    idle_from: Instant,
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
            faults: opts
                .faults
                .as_ref()
                .map(|plan| ConnFaults::new(plan, service.decoder())),
            queue: VecDeque::new(),
            record: opts.record.clone(),
            s,
            info,
            timers: Vec::new(),
            idle: opts.idle,
            idle_from: now,
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
            let mut charge = Charge { budget, now: 0 };
            if !charge.set(self.holding(service)) {
                self.end_now(Ended::Budget);
                return;
            }
            self.charge = Some(charge);
        }
        self.call(now, |driver| service.on_open(state, driver));
    }

    /// The bytes this connection holds, as charged to its budget.
    fn holding(&mut self, service: &S) -> usize {
        let queued: usize = self
            .queue
            .iter()
            .map(|s| {
                if let Segment::Bytes(b, at) = s {
                    b.len() - at
                } else {
                    0
                }
            })
            .sum();
        let out: usize = self
            .out
            .iter()
            .map(|o| if let Out::Bytes(b, _) = o { b.len() } else { 0 })
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
            .saturating_add(self.stream.held())
            .saturating_add(queued)
            .saturating_add(self.faults.as_ref().map_or(0, |f| {
                f.pending
                    .iter()
                    .map(|s| match s {
                        Segment::Bytes(bytes, _) => bytes.len(),
                        Segment::Wait(_) => 0,
                    })
                    .sum::<usize>()
                    .saturating_add(f.front.as_ref().map_or(0, |front| front.unread().len()))
            }))
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
        match &mut self.faults {
            Some(f) => {
                f.inbound(self.s.entropy.as_ref(), bytes, false, &mut self.queue);
                self.s.events.extend(f.stopped());
            }
            None if self.queue.is_empty() => {
                // Straight into the decoder's buffer: one copy, not two.
                let n = self.stream.push(bytes);
                if n < bytes.len() {
                    self.queue.push_back(Segment::Bytes(bytes[n..].to_vec(), 0));
                }
            }
            None => self.queue.push_back(Segment::Bytes(bytes.to_vec(), 0)),
        }
    }

    /// The client will send nothing more.
    fn input_eof(&mut self) {
        self.eof = true;
        if let Some(f) = &mut self.faults {
            f.inbound(self.s.entropy.as_ref(), &[], true, &mut self.queue);
            self.s.events.extend(f.stopped());
        }
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

    /// The connection broke, or the world is stopping.
    fn broken(&mut self, end: Ended) {
        self.out.clear();
        if matches!(self.state, State::Ending { .. }) {
            self.cancel_all(true);
            self.end_now(end);
        } else {
            self.finish(end);
        }
    }

    /// Whether the driver has async work to poll.
    fn has_work(&self) -> bool {
        !self.ordered.is_empty() || !self.keyed.is_empty()
    }

    /// Bytes read but not decoded, for a handoff.
    fn unread(&mut self) -> Vec<u8> {
        let mut unread = self.stream.unread().to_vec();
        for segment in self.queue.drain(..) {
            if let Segment::Bytes(bytes, at) = segment {
                unread.extend_from_slice(&bytes[at..]);
            }
        }
        unread
    }

    /// Queues `bytes` to write, through the outbound faults. `work` is the
    /// number of the work they came from: it is credited with their length
    /// once the last of them is written.
    fn push_out(&mut self, bytes: Vec<u8>, work: Option<u64>) {
        if bytes.is_empty() {
            return;
        }
        let credit = work.map(|id| (id, bytes.len() as u64));
        let (bytes, delay) = match &mut self.faults {
            Some(f) => f.outbound(self.s.entropy.as_ref(), bytes),
            None => (bytes, None),
        };
        match delay {
            None => self.out.push_back(Out::Bytes(bytes, credit)),
            Some(FaultDelay { at, duration }) => {
                let mut bytes = bytes;
                let rest = bytes.split_off(at.min(bytes.len()));
                self.out.push_back(Out::Bytes(bytes, None));
                self.out.push_back(Out::Delay(duration));
                self.out.push_back(Out::Bytes(rest, credit));
            }
        }
    }

    fn pending_ctx<'a>(
        fcx: Option<&'a Cx>,
        events: &'a mut Vec<Event>,
        written: u64,
        conn: &'a ConnInfo,
    ) -> PendingDriver<'a> {
        PendingDriver {
            fcx,
            events,
            written,
            conn,
            close: false,
        }
    }

    fn cancel_work(&mut self, mut work: Work) {
        let mut events = Vec::new();
        let mut driver =
            Self::pending_ctx(self.fcx.as_ref(), &mut events, work.written, &self.info);
        work.pending.cancel(&mut driver);
        self.s.events.append(&mut events);
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

    /// Stops item rules for this connection and records the `conn.faults` event.
    fn stop_item_faults(&mut self, why: &'static str) {
        if let Some(faults) = &mut self.faults {
            faults.stop(why, &mut self.queue);
            self.s.events.extend(faults.stopped());
        }
    }

    /// Takes what the last call asked for: its reply, its deferred work.
    fn collect(&mut self) {
        if std::mem::take(&mut self.s.decoder_touched) {
            self.stop_item_faults("decoder");
        }
        let reply = std::mem::take(&mut self.s.reply);
        self.push_out(reply, None);
        self.s.datagrams.clear();
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
        f: impl FnOnce(&mut Driver<'_, S::Decoder>) -> Result<Flow, S::Error>,
    ) {
        let result = {
            let mut driver = Driver {
                decoder: self.stream.decoder(),
                s: &mut self.s,
                now,
                conn: &self.info,
                timers: &self.timers,
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
                if flow != Flow::Continue && self.held_flow.is_none() {
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
        if matches!(flow, Flow::Upgrade(_)) {
            self.stop_item_faults("upgrade");
        }
        match flow {
            Flow::Continue => {}
            Flow::Close => self.finish(Ended::Closed),
            Flow::Upgrade(Upgrade::Decoder) => {
                let unread = self.stream.unread().to_vec();
                self.stream = Stream::with_buffer(service.decoder(), self.read_buffer);
                self.fresh = true;
                if !unread.is_empty() {
                    self.queue.push_front(Segment::Bytes(unread, 0));
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

    /// Moves bytes from the queue into the decoder, up to a fault delay.
    /// Returns how many it took.
    fn feed(&mut self) -> usize {
        if self.queue.is_empty()
            && let Some(faults) = &mut self.faults
        {
            faults.pump(self.s.entropy.as_ref(), &mut self.queue);
            self.s.events.extend(faults.stopped());
        }
        let mut pushed = 0;
        while let Some(Segment::Bytes(bytes, at)) = self.queue.front_mut() {
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
        let tag = self.info.id.unwrap_or(0);
        let record = &self.record;
        self.stream.with_next_observed(
            |item, _, _| item,
            |event| {
                if let Some(t) = record {
                    t.observe(tag, Side::Client, event);
                }
            },
        )
    }

    fn next_deadline(&self) -> Option<Instant> {
        let timer = self.timers.iter().map(|(_, at)| *at).min();
        // Keyed work running is not a silent client.
        let idle = self
            .idle
            .filter(|_| self.keyed.is_empty())
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
            && self.keyed.is_empty()
            && now >= self.idle_from + idle
        {
            self.finish(Ended::Idle);
            return Next::Again;
        }
        loop {
            let pushed = self.feed();
            if self.eof
                && self.queue.is_empty()
                && self
                    .faults
                    .as_ref()
                    .is_none_or(|f| f.front.is_none() && f.pending.is_empty())
            {
                self.stream.end();
            }
            match self.next_item() {
                Some(Ok(item)) => {
                    self.idle_from = now;
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
            if let Some(Segment::Wait(d)) = self.queue.front() {
                let d = *d;
                self.queue.pop_front();
                return Next::Sleep(d);
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
        let result = {
            let mut driver = Driver {
                decoder: self.stream.decoder(),
                s: &mut self.s,
                now,
                conn: &self.info,
                timers: &self.timers,
            };
            service.on_end(end, state, &mut driver)
        };
        if std::mem::take(&mut self.s.decoder_touched) {
            self.stop_item_faults("decoder");
        }
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
            let mut events = Vec::new();
            let (polled, close) = {
                let mut driver = PendingDriver {
                    fcx: self.fcx.as_ref(),
                    events: &mut events,
                    written: work.written,
                    conn: &self.info,
                    close: false,
                };
                (work.pending.poll_next(&mut driver, cx), driver.close)
            };
            work.close |= close;
            let (id, close) = (work.id, work.close);
            self.s.events.append(&mut events);
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
            let mut events = Vec::new();
            let (polled, close) = {
                let (_, work) = &mut self.keyed[i];
                let mut driver = PendingDriver {
                    fcx: self.fcx.as_ref(),
                    events: &mut events,
                    written: work.written,
                    conn: &self.info,
                    close: false,
                };
                (work.pending.poll_next(&mut driver, cx), driver.close)
            };
            self.keyed[i].1.close |= close;
            self.s.events.append(&mut events);
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
            self.idle_from = now;
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

/// Records an event from the connection `info`.
fn record(fcx: &Cx, info: &ConnInfo, event: Event) {
    fcx.record(event.conn(info));
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

/// Serves one connection with `service` until it ends: TLS first with
/// [`ServeOptions::tls`], then the service, with every [`Upgrade::Tls`]
/// it asks for performed with [`ServeOptions::starttls`]. Returns how it
/// ended, or the connection with its unread bytes after
/// [`Upgrade::Handoff`]. Returns [`ServeError::Cancelled`] if `fcx`'s
/// [region](fictionet::Cx#regions) is cancelled, also during a TLS
/// handshake.
///
/// `info` names the connection in events; [`listen`] fills it in. The
/// connection ends as soon as the client resets it, even while deferred
/// work runs and nothing reads ([`Connection::poll_gone`]). Deferred work
/// receives a child region; cancelling it closes only this connection.
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
    {
        let slot = &mut result;
        let finished = fictionet::sync::Mutex::new(None);
        let finished_ref = &finished;
        let mut region = std::pin::pin!(fcx.region(|child| async move {
            *slot = Some(serve_in_region(&child, conn, info, service, state, opts).await);
            *finished_ref.lock() = Some(child);
            Ok(())
        }));
        let _ = std::future::poll_fn(|cx| {
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
        .await;
    }
    result.expect("the connection region completed")
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
    let mut conn: Box<dyn Connection> = Box::new(conn);
    let mut info = info;
    if let Some(select) = &opts.tls {
        let (tls, i) =
            match accept_tls(fcx, conn, &info, select, fcx.now() + opts.handshake, || {
                false
            })
            .await
            {
                Ok(done) => done,
                Err(e) => return tls_failed(e),
            };
        conn = Box::new(tls);
        info = i;
    }
    let mut first = true;
    let wake = WakeHandle::new();
    loop {
        let served = run(
            fcx,
            conn,
            info.clone(),
            service,
            state,
            opts,
            first,
            wake.clone(),
        )
        .await?;
        first = false;
        let rest = match served {
            Served::Upgraded(Upgrade::Tls, rest) => rest,
            other => return Ok(other),
        };
        let Some(select) = &opts.starttls else {
            let event = Event::new("conn", "error")
                .level(Level::Notice)
                .summary("the service asked for TLS, and there is no TLS config")
                .field("error", "no TLS config for the upgrade");
            record(fcx, &info, event);
            return Ok(Served::Closed(Ended::Failed));
        };
        let deadline = fcx.now() + opts.handshake;
        let (tls, i) = match accept_tls(fcx, rest, &info, select, deadline, || false).await {
            Ok(done) => done,
            Err(e) => return tls_failed(e),
        };
        conn = Box::new(tls);
        info = i;
    }
}

/// How [`connection`] ends when its TLS handshake fails: cancelled if the
/// handshake was, else with the connection closed as broken.
fn tls_failed<E>(e: HandshakeError) -> Result<Served<Box<dyn Connection>>, ServeError<E>> {
    match e {
        HandshakeError::Cancelled => Err(ServeError::Cancelled),
        _ => Ok(Served::Closed(Ended::Conn(ConnError::Broken))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run<S, C>(
    fcx: &Cx,
    mut conn: C,
    info: ConnInfo,
    service: &mut S,
    state: &S::State,
    opts: &ServeOptions,
    first: bool,
    wake: WakeHandle,
) -> Result<Served<C>, ServeError<S::Error>>
where
    S: Service,
    C: Connection,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    if first && opts.connection_events {
        record(
            fcx,
            &info,
            Event::new("conn", "open").summary("connection opened"),
        );
    }
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
    let tag = core.info.id.unwrap_or(0);
    let mut buf = vec![0u8; READ];
    let mut out_offset = 0u64;
    let mut run = 0u32;
    loop {
        // What is out counts against the budget while it is written.
        core.recharge(service);
        if !core.s.events.is_empty() {
            for event in std::mem::take(&mut core.s.events) {
                record(fcx, &core.info, event);
            }
        }
        // Write what is out, through the transcript.
        while let Some(out) = core.out.pop_front() {
            match out {
                Out::Bytes(bytes, credit) => {
                    if bytes.is_empty() {
                        core.wrote(credit);
                        continue;
                    }
                    if let Some(t) = &opts.record {
                        let end = out_offset.saturating_add(bytes.len() as u64);
                        t.observe::<(), String>(
                            tag,
                            Side::Server,
                            StreamEvent::Skipped {
                                bytes: &bytes,
                                range: out_offset..end,
                            },
                        );
                    }
                    out_offset = out_offset.saturating_add(bytes.len() as u64);
                    match write_all(fcx, &mut conn, &bytes, opts.write_timeout).await {
                        Ok(()) => core.wrote(credit),
                        Err(end) => core.broken(end),
                    }
                }
                Out::Delay(d) => {
                    if fcx.sleep(d).await.is_err() {
                        core.broken(Ended::Cancelled);
                    }
                }
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
            Next::Sleep(d) => {
                if fcx.sleep(d).await.is_err() {
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
                if woke.gone {
                    core.broken(Ended::Conn(ConnError::Reset));
                }
            }
            Next::Upgrade(how) => {
                for event in std::mem::take(&mut core.s.events) {
                    record(fcx, &core.info, event);
                }
                if opts.connection_events {
                    record(
                        fcx,
                        &core.info,
                        Event::new("conn", "upgrade")
                            .summary(format!("connection upgraded: {}", how.as_str()))
                            .field("to", how.as_str()),
                    );
                }
                let unread = core.unread();
                // The service goes on after TLS, with the same handle.
                if how != Upgrade::Tls {
                    core.s.wake.close();
                }
                return Ok(Served::Upgraded(how, Prefixed::new(unread, conn)));
            }
            Next::Closed(end) => {
                for event in std::mem::take(&mut core.s.events) {
                    record(fcx, &core.info, event);
                }
                if end.writable() {
                    let _ = fcx
                        .race(Some(fcx.now() + Duration::from_secs(5)), conn.shutdown(fcx))
                        .await;
                }
                let info = core.info.clone();
                let failure = core.failure.take();
                match &failure {
                    Some(Failure::Service(e)) => {
                        let e = ErrorChain(e);
                        let event = Event::new("conn", "error")
                            .level(Level::Notice)
                            .summary(format!("the service failed: {e}"))
                            .field("error", e.to_string())
                            .field("kind", "service");
                        record(fcx, &info, event);
                    }
                    Some(Failure::Pending(e)) => {
                        let e = ErrorChain(&**e);
                        let event = Event::new("conn", "error")
                            .level(Level::Notice)
                            .summary(format!("deferred work failed: {e}"))
                            .field("error", e.to_string())
                            .field("kind", "deferred");
                        record(fcx, &info, event);
                    }
                    None => {}
                }
                if opts.connection_events {
                    record(
                        fcx,
                        &info,
                        Event::new("conn", "close")
                            .field("end", end.as_str())
                            .summary(format!("connection closed: {}", end.as_str())),
                    );
                }
                drop(core);
                return match failure {
                    Some(Failure::Service(e)) => Err(ServeError::Service(e)),
                    Some(Failure::Pending(e)) => Err(ServeError::Pending(e)),
                    None if end == Ended::Cancelled => Err(ServeError::Cancelled),
                    None => Ok(Served::Closed(end)),
                };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TLS

/// How a TLS handshake ended, as the `tls.handshake` event says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsOutcome {
    /// It finished, with this protocol agreed by ALPN.
    Accepted {
        /// The protocol, if one was agreed.
        alpn: Option<Vec<u8>>,
    },
    /// Refused with `unrecognized_name`: no config for the SNI.
    Rejected,
    /// The client sent this alert, such as 48 (`unknown_ca`).
    /// The event records its name as `alert` and its number as `alert_code`.
    Alert(u8),
    /// The bytes were not TLS, or broke the protocol.
    Failed(String),
    /// The client closed the connection first.
    Closed,
    /// It did not finish in time.
    TimedOut,
    /// The sandbox detached while it ran.
    Detached,
    /// The world stopped: the region was cancelled.
    Cancelled,
}

impl TlsOutcome {
    /// `accepted`, `rejected`, `alert`, `failed`, `closed`, `timed_out`,
    /// `detached` or `cancelled`.
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsOutcome::Accepted { .. } => "accepted",
            TlsOutcome::Rejected => "rejected",
            TlsOutcome::Alert(_) => "alert",
            TlsOutcome::Failed(_) => "failed",
            TlsOutcome::Closed => "closed",
            TlsOutcome::TimedOut => "timed_out",
            TlsOutcome::Detached => "detached",
            TlsOutcome::Cancelled => "cancelled",
        }
    }

    /// The outcome of a handshake that failed with `e`. `detached` says
    /// whether the sandbox detached, for a reset that came from the world.
    fn of(e: &HandshakeError, detached: bool) -> TlsOutcome {
        match e {
            HandshakeError::Alert(a) => TlsOutcome::Alert(*a),
            HandshakeError::Failed(why) => TlsOutcome::Failed(why.clone()),
            HandshakeError::Conn(ConnError::Broken) => {
                TlsOutcome::Failed("the connection broke".into())
            }
            HandshakeError::Rejected => TlsOutcome::Rejected,
            HandshakeError::TimedOut => TlsOutcome::TimedOut,
            HandshakeError::Cancelled => TlsOutcome::Cancelled,
            HandshakeError::Conn(ConnError::Reset) if detached => TlsOutcome::Detached,
            _ => TlsOutcome::Closed,
        }
    }
}

/// Shakes hands as a TLS server on `conn`, with the config `select` picks
/// for the client's SNI, by `deadline`. Records a `tls.handshake` event
/// with the outcome. A client alert has its name in `alert` and its number
/// in `alert_code`. `detached` says whether the sandbox has detached, for
/// a reset that came from the world.
///
/// Returns the TLS connection and `info` with its SNI and ALPN, or how the
/// handshake failed: [`HandshakeError::Rejected`] when `select` has no
/// config for the name, [`HandshakeError::TimedOut`] past `deadline`, and
/// [`HandshakeError::Cancelled`] if `fcx`'s [region](fictionet::Cx#regions)
/// is cancelled.
pub async fn accept_tls<C: Connection>(
    fcx: &Cx,
    conn: C,
    info: &ConnInfo,
    select: &TlsSelect,
    deadline: Instant,
    detached: impl Fn() -> bool,
) -> Result<(TlsConnection<C>, ConnInfo), HandshakeError> {
    let mut sni: Option<String> = None;
    let handshake = async {
        let hello = tls::server_detailed(fcx, conn).await?;
        sni = hello
            .server_name()
            .map(|n| n.trim_end_matches('.').to_ascii_lowercase());
        let Some(config) = select(sni.as_deref(), fcx) else {
            let _ = hello.reject(fcx).await;
            return Err(HandshakeError::Rejected);
        };
        hello.finish_detailed(fcx, config).await
    };
    let done = match fcx.race(Some(deadline), handshake).await {
        Ok(done) => done,
        Err(RaceError::Deadline) => Err(HandshakeError::TimedOut),
        Err(RaceError::Cancelled) => Err(HandshakeError::Cancelled),
    };
    let outcome = match &done {
        Ok(conn) => TlsOutcome::Accepted {
            alpn: conn.alpn().map(<[u8]>::to_vec),
        },
        Err(e) => TlsOutcome::of(e, detached()),
    };
    let mut event = Event::new("tls", "handshake")
        .summary(match &sni {
            Some(n) => format!("TLS for {n}: {}", outcome.as_str()),
            None => format!("TLS with no name: {}", outcome.as_str()),
        })
        .level(if matches!(outcome, TlsOutcome::Accepted { .. }) {
            Level::Info
        } else {
            Level::Notice
        })
        .field("addr", opt(info.local.map(|a| a.ip().to_string())))
        .field("sni", opt(sni.clone()))
        .field("outcome", outcome.as_str());
    match &outcome {
        TlsOutcome::Accepted { alpn } => {
            event = event.field(
                "alpn",
                opt(alpn
                    .as_ref()
                    .map(|a| String::from_utf8_lossy(a).into_owned())),
            );
        }
        TlsOutcome::Alert(a) => {
            event = event
                .field("alert", tls::alert_name(*a))
                .field("alert_code", u32::from(*a))
        }
        TlsOutcome::Failed(why) => event = event.field("detail", why.as_str()),
        _ => {}
    }
    record(fcx, info, event);
    let conn = done?;
    let info = info.clone().over_tls(sni.as_deref(), conn.alpn());
    Ok((conn, info))
}

// ---------------------------------------------------------------------------
// Listening

/// Accepts connections on `listener` and serves each with a fresh service
/// from `make`, in a task of its own, until the listener closes or the
/// region is cancelled. With [`ServeOptions::tls`], each connection shakes
/// hands first. Past [`ServeOptions::max_conns`], a new connection is
/// reset; each counts until its socket is gone, so a client that never
/// finishes closing cannot open more. Connections are numbered from 1, in
/// the order they are accepted. Returns the accepting task.
///
/// A connection's failure is that connection's: the run's events record
/// it as `conn.error`, and its task ends with `Ok`, so it does not fail
/// the world.
pub fn listen<S, M, A: Accept>(
    fcx: &Cx,
    mut listener: A,
    state: Arc<S::State>,
    make: M,
    opts: ServeOptions,
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
            info.sandbox = info
                .peer
                .and_then(|peer| opts.sandbox.as_ref().and_then(|f| f(peer.ip())));
            let Some(guard) =
                fictionet::stdlib::net::connection_limit(&fcx, &info, &open, opts.max_conns)
            else {
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

/// Counts one open connection until dropped.
pub struct Counted(Arc<AtomicUsize>);

impl Counted {
    /// Counts one more in `open`, unless it already counts `max`.
    // Rust 1.99 deprecates fetch_update for try_update, which is newer than
    // the MSRV (1.91).
    #[allow(deprecated)]
    pub fn enter(open: &Arc<AtomicUsize>, max: usize) -> Option<Counted> {
        open.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
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

// ---------------------------------------------------------------------------
// Datagrams

type DatagramCall<'a, S> =
    dyn FnMut(&mut Driver<'_, <S as Service>::Decoder>) -> Result<Flow, <S as Service>::Error> + 'a;

/// Serves every datagram on `socket` with one `service`, until the socket
/// closes or the region is cancelled.
///
/// Each datagram is decoded on its own, with a fresh decoder that sees the
/// end of input after it, as DNS, DHCP, Kerberos and Modbus over UDP frame
/// their messages. The reply bytes of one datagram's items go back to its
/// sender as one datagram; [`Driver::send_to`] sends more, to anyone.
/// The service's [`ConnInfo`] names the sender in `peer`, with
/// [`Transport::Udp`]. [`Service::on_open`] is called once at the start,
/// timers and wakes work as over a connection (with no sender: use
/// `send_to`), and a decoder failure is answered with
/// [`Service::on_fail`]. [`Flow::Close`] drops the rest of a datagram.
/// Deferred work is not run. A service error is recorded as `conn.error`
/// and serving goes on. A panic is not caught: it ends the run, as it
/// does over a connection.
///
/// Returns `Ok(())` once the socket closes, and [`Cancelled`] if `fcx`'s
/// [region](fictionet::Cx#regions) is cancelled.
pub async fn datagram<S, D: DatagramSocket>(
    fcx: &Cx,
    mut socket: D,
    local: SocketAddr,
    service: &mut S,
    state: &S::State,
    opts: &ServeOptions,
) -> Result<(), Cancelled>
where
    S: Service,
    <S::Decoder as Decode>::Error: Clone + Send,
{
    let base = ConnInfo {
        local: Some(local),
        transport: Transport::Udp,
        ..ConnInfo::default()
    };
    let _note = PanicNote::new(std::any::type_name::<S>(), &base);
    let mut s = Scratch::new(Arc::new(fcx.clone()));
    let mut timers: Vec<(Timer, Instant)> = Vec::new();
    let wake = s.wake.clone();
    // One call, then its datagrams and events. The reply stays for the
    // caller to send, or drop.
    let mut lifecycle_decoder = service.decoder();
    let called = |decoder: &mut S::Decoder,
                  s: &mut Scratch,
                  timers: &[(Timer, Instant)],
                  socket: &mut D,
                  info: &ConnInfo,
                  f: &mut DatagramCall<'_, S>|
     -> Flow {
        let result = {
            let mut driver = Driver {
                decoder,
                s: &mut *s,
                now: fcx.now(),
                conn: info,
                timers,
            };
            f(&mut driver)
        };
        for event in std::mem::take(&mut s.events) {
            record(fcx, info, event);
        }
        let flow = match result {
            Err(e) => {
                let e = ErrorChain(&e);
                let event = Event::new("conn", "error")
                    .level(Level::Notice)
                    .summary(format!("the service failed: {e}"))
                    .field("error", e.to_string())
                    .field("kind", "service");
                record(fcx, info, event);
                Flow::Close
            }
            Ok(flow) => flow,
        };
        for (to, bytes) in s.datagrams.drain(..) {
            socket.send_to(&bytes, to);
        }
        s.ordered.clear();
        s.keyed.clear();
        flow
    };
    called(
        &mut lifecycle_decoder,
        &mut s,
        &timers,
        &mut socket,
        &base,
        &mut |driver| service.on_open(state, driver),
    );
    s.reply.clear();
    let mut run = 0u32;
    let ended = loop {
        let now = fcx.now();
        arm(&mut timers, &mut s.timers, now);
        if let Some(i) = due(&timers, now) {
            let (name, _) = timers.remove(i);
            called(
                &mut lifecycle_decoder,
                &mut s,
                &timers,
                &mut socket,
                &base,
                &mut |driver| service.on_timer(name, state, driver),
            );
            s.reply.clear();
            continue;
        }
        if wake.take() {
            called(
                &mut lifecycle_decoder,
                &mut s,
                &timers,
                &mut socket,
                &base,
                &mut |driver| service.on_wake(state, driver),
            );
            s.reply.clear();
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
        let sandbox = opts.sandbox.as_ref().and_then(|f| f(from.ip()));
        let info = ConnInfo {
            peer: Some(from),
            sandbox,
            ..base.clone()
        };
        let _note = PanicNote::new(std::any::type_name::<S>(), &info);
        s.bytes_in = s.bytes_in.saturating_add(datagram.len() as u64);
        let mut stream = Stream::with_buffer(service.decoder(), datagram.len());
        let taken = stream.push(&datagram);
        stream.end();
        loop {
            let flow = match stream.next() {
                Some(Ok(item)) => {
                    let mut item = Some(item);
                    called(
                        stream.decoder(),
                        &mut s,
                        &timers,
                        &mut socket,
                        &info,
                        &mut |driver| match item.take() {
                            Some(item) => service.on_item(item, state, driver),
                            None => Ok(Flow::Close),
                        },
                    )
                }
                Some(Err(fail)) => {
                    s.unread = stream.unread().to_vec();
                    let flow = called(
                        stream.decoder(),
                        &mut s,
                        &timers,
                        &mut socket,
                        &info,
                        &mut |driver| service.on_fail(&fail, state, driver).map(|()| Flow::Close),
                    );
                    s.unread = Vec::new();
                    flow
                }
                None => {
                    if taken < datagram.len() {
                        // Longer than the decoder could hold at once.
                        let fail = Fail::Refused {
                            unread: datagram.len(),
                            limit: stream.limit(),
                        };
                        s.unread = datagram.clone();
                        let flow = called(
                            stream.decoder(),
                            &mut s,
                            &timers,
                            &mut socket,
                            &info,
                            &mut |driver| {
                                service.on_fail(&fail, state, driver).map(|()| Flow::Close)
                            },
                        );
                        s.unread = Vec::new();
                        flow
                    } else {
                        Flow::Close
                    }
                }
            };
            if flow != Flow::Continue {
                break;
            }
        }
        // The replies to one datagram's items go back as one datagram.
        let reply = std::mem::take(&mut s.reply);
        if !reply.is_empty() {
            socket.send_to(&reply, from);
        }
        run = (run + 1) % 64;
        if run == 0
            && let Err(cancelled) = fcx.yield_now().await
        {
            break Err(cancelled);
        }
    };
    wake.close();
    ended
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
    /// The service asked for this upgrade; see [`Harness::resume`].
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
/// get the reply. For unit tests, fuzz targets and contract checks. It
/// runs the same state machine as [`connection`], so timers, wakes, deferred
/// work, upgrades and ends behave as they do over a connection. The clock
/// stands still until [`advance`](Self::advance) moves it, unless bound
/// to a `Cx`, whose clock it reads instead; inbound fault delays take no time.
///
/// Deferred work is polled until it waits on something other than
/// itself; [`poll`](Self::poll) polls it again. Work that needs a [`Cx`]
/// gets one from [`with_fcx`](Self::with_fcx).
pub struct Harness<S: Service> {
    service: S,
    state: S::State,
    core: Core<S>,
    opts: ServeOptions,
    now: Instant,
    opened: bool,
    events: Vec<Event>,
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

    /// The same with `opts`: an idle limit, a fault plan and a budget.
    /// The standalone entropy stream starts from `seed`. TLS and the
    /// connection cap are not used, and events are kept in the harness
    /// ([`Harness::events`]), not recorded.
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
            opts,
            now: Instant::ZERO,
            opened: false,
            events: Vec::new(),
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
                Next::Again | Next::Sleep(_) => {}
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
        self.events.append(&mut self.core.s.events);
        while let Some(out) = self.core.out.pop_front() {
            if let Out::Bytes(b, credit) = out {
                self.output.extend_from_slice(&b);
                reply.extend_from_slice(&b);
                self.core.wrote(credit);
            }
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

    /// After [`HarnessError::Upgraded`]: goes on as [`connection`] does once the
    /// upgrade is done, as the connection `conn` (for TLS, with `tls` set).
    /// The service gets a fresh decoder that reads the unread bytes, and
    /// [`Service::on_open`] again. Returns what it sends.
    pub fn resume(&mut self, conn: ConnInfo) -> HarnessResult<S> {
        if self.upgraded.take().is_none() {
            return Ok(Vec::new());
        }
        self.read_clock();
        self.reported = false;
        let unread = self.core.unread();
        let wake = self.core.s.wake.clone();
        let fcx = self.core.fcx.take();
        let mut core = Core::new(
            fcx,
            self.core.s.entropy.clone(),
            &self.service,
            conn,
            &self.opts,
            Some(wake),
            self.now,
        );
        core.s.bytes_in = self.core.s.bytes_in;
        if !unread.is_empty() {
            core.queue.push_back(Segment::Bytes(unread, 0));
        }
        self.core = core;
        self.core.open(&mut self.service, &self.state, self.now);
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
    pub fn timer(&self, name: Timer) -> Option<Instant> {
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

    /// Every event the service recorded.
    pub fn events(&self) -> &[Event] {
        &self.events
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
