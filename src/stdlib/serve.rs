//! Services: a protocol's server, written once with no I/O, run over any
//! connection.
//!
//! A [`Service`] is the server side of one protocol for one connection.
//! It gets decoded items, appends reply bytes, records facts in the
//! [`journal`](crate::stdlib::journal), and asks for timers. It reads no
//! clock and touches no socket, so it unit-tests with the [`Harness`]
//! here, fuzzes with the codec's contract tools, and a world copies its
//! file to change it. It has the shape of a FIX session: items in, bytes
//! and events and timers out.
//!
//! [`serve`] is the one driver that joins a service to a
//! [`Connection`]: it reads, decodes, calls the
//! service, writes its reply, honors its timers, and closes. [`listen`]
//! runs `serve` for every connection a [`Listener`] accepts, with a
//! cap on how many are open, and TLS first when the options ask for it.
//! [`serve_datagram`] does the same for a UDP socket, one datagram at a
//! time. The driver carries the codec tools without the service knowing:
//! a [`Transcript`] records both directions with a
//! [`Recorder`], and a [`FaultPlan`] runs
//! [`Faults`] on the bytes and items in, and
//! the bytes out.
//!
//! A service that echoes each line back, and closes on `quit`:
//!
//! ```
//! use fictionet::stdlib::codec::{Ending, LineError, Lines};
//! use fictionet::stdlib::journal::Event;
//! use fictionet::stdlib::serve::{Flow, Harness, Service, ServeCtx};
//!
//! struct Echo;
//! impl Service for Echo {
//!     type Decode = Lines;
//!     type World = ();
//!     type Error = std::convert::Infallible;
//!     fn decoder(&self) -> Lines { Lines::new(1024, Ending::LfOrCrlf) }
//!     fn on_item(&mut self, line: Result<Vec<u8>, LineError>, _: &(), ctx: &mut ServeCtx<'_>) -> Result<Flow, Self::Error> {
//!         let line = line.unwrap_or_default();
//!         if line == b"quit" {
//!             return Ok(Flow::Close);
//!         }
//!         ctx.log(Event::new("echo", "line").field("bytes", line.len() as u64));
//!         ctx.reply().extend_from_slice(&line);
//!         ctx.reply().push(b'\n');
//!         Ok(Flow::Continue)
//!     }
//! }
//!
//! let mut h = Harness::new(Echo, ());
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
//! #     type Decode = fictionet::stdlib::codec::Lines; type World = (); type Error = std::convert::Infallible;
//! #     fn decoder(&self) -> Self::Decode { fictionet::stdlib::codec::Lines::new(64, fictionet::stdlib::codec::Ending::LfOrCrlf) }
//! #     fn on_item(&mut self, _: Result<Vec<u8>, fictionet::stdlib::codec::LineError>, _: &(), _: &mut serve::ServeCtx<'_>) -> std::result::Result<serve::Flow, Self::Error> { Ok(serve::Flow::Continue) }
//! # }
//! # fn world(cx: &Cx, side: fictionet::End) -> Result {
//! let (tcp, _udp, _icmp, _other) = ip::split_protocols(cx, side);
//! let machine = tcp::endpoint(cx, tcp, "10.0.0.10".parse()?);
//! serve::listen(cx, machine.listen(7)?, Arc::new(()), || Echo, serve::ServeOptions::default());
//! # Ok(())
//! # }
//! ```
//!
//! [`net::Net`](crate::stdlib::net::Net) does this for every host and
//! port of a network, and [`httpd`](crate::stdlib::httpd) is HTTP as a
//! service.
//!
//! # What the driver promises
//!
//! - **One call at a time.** The service's methods are called in order, in
//!   the connection's task. Each call's reply is written before the next
//!   item is decoded. A service may hand the driver async work with
//!   [`ServeCtx::defer`], for adapters such as tower; the driver writes its
//!   bytes, in order, before it reads on.
//! - **Timers.** [`ServeCtx::wake_in`] asks for one [`Service::on_tick`]
//!   after a time. The time counts from when the driver next waits for
//!   input, after the call's reply and deferred work are written, so a slow
//!   write never eats into it. A later `wake_in` replaces it.
//! - **Idle.** With [`ServeOptions::idle`], a connection that sends nothing
//!   for that long while the driver waits for it is closed, after
//!   [`Service::on_end`] with [`End::Idle`].
//! - **Ends.** [`Service::on_end`] is called once, with why the connection
//!   ended. Its reply is written when the connection can still take it: the
//!   client half-closed ([`End::Eof`]), the service closed, the service's
//!   decoder failed, or the connection sat idle.
//! - **Handoff.** A decoder that ends ([`Step::End`](crate::stdlib::codec::Step::End)),
//!   or a call that returns [`Flow::Upgrade`], hands the connection back
//!   with its unread bytes in [`Served::Upgraded`], for STARTTLS or a
//!   CONNECT tunnel.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::stdlib::codec::{
    Buffer, ByteFault, Decode, Direction, Fail, FaultDelay, Faults, ItemFault, Lcg, Record, Recorder, RewriteError,
    Rule, Stream, StreamEvent,
};
use fictionet::stdlib::journal::{ConnInfo, Event, Journal, Level};
use fictionet::stdlib::tcp::{GoneWatch, Listener};
use fictionet::stdlib::tls::{self, HandshakeError, ServerConfig, TlsConnection};
use fictionet::stdlib::udp::Socket;
use fictionet::stdlib::{ConnError, Connection, ConnectionExt};
use fictionet::time::Instant;
use fictionet::{Cx, Task};

// ---------------------------------------------------------------------------
// The service

/// A sans-IO server for one connection of one protocol. The driver owns
/// the [`Stream`] and the output; the service owns its state.
///
/// Make one per connection ([`listen`] takes a function that does). State
/// shared with the rest of the world, such as a directory, a process model
/// or an order book, is the `World`, passed to every call.
pub trait Service: Send + 'static {
    /// How this service's bytes become items.
    type Decode: Decode + Send + 'static;
    /// State shared with the world, read by every connection.
    type World: Send + Sync + 'static;
    /// Why the service gives up on a connection. The driver closes it and
    /// returns the error.
    type Error: core::error::Error + Send + Sync + 'static;

    /// A fresh decoder for a new connection.
    fn decoder(&self) -> Self::Decode;

    /// The connection is open and nothing is read yet. A protocol whose
    /// server speaks first (SSH, SMTP, FTP banners) writes here.
    fn on_open(&mut self, _world: &Self::World, _ctx: &mut ServeCtx<'_>) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// One decoded item. Append reply bytes with [`ServeCtx::reply`].
    fn on_item(
        &mut self,
        item: <Self::Decode as Decode>::Item,
        world: &Self::World,
        ctx: &mut ServeCtx<'_>,
    ) -> Result<Flow, Self::Error>;

    /// The timer asked for with [`ServeCtx::wake_in`] went off.
    fn on_tick(&mut self, _world: &Self::World, _ctx: &mut ServeCtx<'_>) -> Result<Flow, Self::Error> {
        Ok(Flow::Continue)
    }

    /// The decoder failed: the bytes are not this protocol. A reply, such
    /// as an error message, is written before the connection closes.
    fn on_fail(
        &mut self,
        _error: &Fail<<Self::Decode as Decode>::Error>,
        _world: &Self::World,
        _ctx: &mut ServeCtx<'_>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The connection ended, for the reason in `end`. Called once, last.
    fn on_end(&mut self, _end: End, _world: &Self::World, _ctx: &mut ServeCtx<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// What a call hands back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Keep the connection open.
    Continue,
    /// Write the reply, then close.
    Close,
    /// Write the reply, then hand the connection and its unread bytes back
    /// to the caller of [`serve`] ([`Served::Upgraded`]).
    Upgrade,
}

/// Why a connection ended, as [`Service::on_end`] hears it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// The client sent everything it will send, and every item was handled.
    /// The reply is still written.
    Eof,
    /// The service returned [`Flow::Close`].
    Closed,
    /// The decoder failed, after [`Service::on_fail`].
    Failed,
    /// Nothing arrived for [`ServeOptions::idle`].
    Idle,
    /// Reading or writing failed: the client reset the connection, or TLS
    /// broke ([`ConnError::Broken`]).
    Conn(ConnError),
    /// The world is stopping.
    Cancelled,
}

/// Async work a service hands the driver with [`ServeCtx::defer`]: bytes
/// to write as they come, such as a response from a tower service.
pub trait Pending: Send + 'static {
    /// The next bytes to write, or `None` when done. An error closes the
    /// connection: the bytes so far may have broken the protocol's framing.
    fn poll_next(&mut self, ctx: &mut PendingCtx<'_>, task: &mut Context<'_>) -> Poll<Option<Result<Vec<u8>, fictionet::Error>>>;

    /// The connection went away, or the world is stopping, before the work
    /// finished. The work is dropped after this.
    fn cancel(&mut self, _ctx: &mut PendingCtx<'_>) {}
}

/// What deferred work sees while it runs.
pub struct PendingCtx<'a> {
    cx: &'a Cx,
    events: &'a mut Vec<Event>,
    written: u64,
    conn: &'a ConnInfo,
    logging: bool,
}

impl PendingCtx<'_> {
    /// The connection's context, for async work.
    pub fn cx(&self) -> &Cx {
        self.cx
    }

    /// Bytes of this work written to the connection so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Records an event in the journal.
    pub fn log(&mut self, event: Event) {
        if self.logging {
            self.events.push(event);
        }
    }

    /// Whether events reach anyone.
    pub fn logging(&self) -> bool {
        self.logging
    }

    /// The connection.
    pub fn conn(&self) -> &ConnInfo {
        self.conn
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TimerRequest {
    #[default]
    Unchanged,
    Set(Duration),
    Cancel,
}

/// The driver's scratch for one call: the reply, the clock reading the
/// driver took, seeded randomness, and the events to record.
pub struct ServeCtx<'a> {
    reply: &'a mut Vec<u8>,
    now: Instant,
    rng: &'a mut Lcg,
    events: &'a mut Vec<Event>,
    logging: bool,
    conn: &'a ConnInfo,
    timer: &'a mut TimerRequest,
    deferred: &'a mut Option<Box<dyn Pending>>,
    bytes_in: u64,
    unread: &'a [u8],
}

impl ServeCtx<'_> {
    /// Bytes to send, after anything already there.
    pub fn reply(&mut self) -> &mut Vec<u8> {
        self.reply
    }

    /// The run's clock, read by the driver before this call.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// A random number from the connection's own generator, seeded from
    /// the world's.
    pub fn random_u64(&mut self) -> u64 {
        self.rng.next()
    }

    /// Asks for one [`Service::on_tick`] after `d`, counted from when the
    /// driver next waits for input. Replaces a timer asked for before.
    pub fn wake_in(&mut self, d: Duration) {
        *self.timer = TimerRequest::Set(d);
    }

    /// Cancels the timer.
    pub fn cancel_wake(&mut self) {
        *self.timer = TimerRequest::Cancel;
    }

    /// Records `event` in the journal, from this connection.
    pub fn log(&mut self, event: Event) {
        if self.logging {
            self.events.push(event);
        }
    }

    /// Whether events reach anyone. A service skips building an event that
    /// would be thrown away.
    pub fn logging(&self) -> bool {
        self.logging
    }

    /// The connection: its number, sandbox and addresses.
    pub fn conn(&self) -> &ConnInfo {
        self.conn
    }

    /// How many bytes the client has sent so far.
    pub fn bytes_in(&self) -> u64 {
        self.bytes_in
    }

    /// In [`Service::on_fail`], the bytes the decoder could not use: a
    /// message cut off by the end of input, or bytes that are not this
    /// protocol. Empty in every other call.
    pub fn unread(&self) -> &[u8] {
        self.unread
    }

    /// Hands the driver async work whose bytes it writes, in order, after
    /// this call's reply and before it reads on. At most one at a time: a
    /// second call replaces the first.
    pub fn defer(&mut self, work: impl Pending) {
        *self.deferred = Some(Box::new(work));
    }
}

/// What the per-connection state looks like to a call.
struct Scratch {
    reply: Vec<u8>,
    events: Vec<Event>,
    rng: Lcg,
    logging: bool,
    timer: TimerRequest,
    deferred: Option<Box<dyn Pending>>,
    bytes_in: u64,
    unread: Vec<u8>,
}

impl Scratch {
    fn new(seed: u64, logging: bool) -> Scratch {
        Scratch {
            reply: Vec::new(),
            events: Vec::new(),
            rng: Lcg::new(seed),
            logging,
            timer: TimerRequest::Unchanged,
            deferred: None,
            bytes_in: 0,
            unread: Vec::new(),
        }
    }

    fn ctx<'a>(&'a mut self, now: Instant, conn: &'a ConnInfo) -> ServeCtx<'a> {
        ServeCtx {
            reply: &mut self.reply,
            now,
            rng: &mut self.rng,
            events: &mut self.events,
            logging: self.logging,
            conn,
            timer: &mut self.timer,
            deferred: &mut self.deferred,
            bytes_in: self.bytes_in,
            unread: &self.unread,
        }
    }
}

// ---------------------------------------------------------------------------
// Options, transcripts and fault plans

/// The bytes both ways of every connection a driver served, bounded.
///
/// Records items and skipped bytes from the client as the service's
/// decoder read them ([`Direction::ClientToServer`]), and each write to the
/// client as one skipped run ([`Direction::ServerToClient`]). Items are
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
        Transcript { inner: Arc::new(Mutex::new(Recorder::new(max_entries, max_bytes))) }
    }

    /// The records kept, oldest first.
    pub fn records(&self) -> Vec<Record<(), String>> {
        self.lock().iter().cloned().collect()
    }

    /// How many records were dropped for the bounds.
    pub fn dropped(&self) -> u64 {
        self.lock().dropped()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Recorder<(), String>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn observe<T, E: core::fmt::Display>(&self, tag: u64, direction: Direction, event: StreamEvent<'_, T, E>) {
        let mut recorder = self.lock();
        match event {
            StreamEvent::Item { bytes, range, .. } => {
                recorder.observe_tagged(tag, direction, StreamEvent::Item { item: &(), bytes, range });
            }
            StreamEvent::Skipped { bytes, range } => {
                recorder.observe_tagged(tag, direction, StreamEvent::Skipped { bytes, range });
            }
            StreamEvent::Ended { offset } => {
                recorder.observe_tagged(tag, direction, StreamEvent::Ended { offset });
            }
            StreamEvent::Failed { error, bytes, range } => {
                let error = match error {
                    Fail::Protocol(e) => Fail::Protocol(e.to_string()),
                    Fail::Truncated { unread } => Fail::Truncated { unread: *unread },
                    Fail::Stuck { unread, capacity } => Fail::Stuck { unread: *unread, capacity: *capacity },
                };
                recorder.observe_tagged(tag, direction, StreamEvent::Failed { error: &error, bytes, range });
            }
        }
    }
}

/// A fault plan for [`Faults`]: byte rules for each direction and item
/// rules for the client's items, with a seed.
///
/// Item rules run on the client's decoded items before the service sees
/// them, through a second decoder: a replacement is raw bytes the service
/// then decodes. Delays are honored by the driver: it waits before the
/// bytes after the delay's offset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// The seed. Each connection seeds its own generator with this and its
    /// connection number, so a run with the same connections repeats.
    pub seed: u64,
    /// Rules for each chunk read from the client.
    pub inbound: Vec<Rule<ByteFault>>,
    /// Rules for each chunk written to the client.
    pub outbound: Vec<Rule<ByteFault>>,
    /// Rules for each item the client sent.
    pub items: Vec<Rule<ItemFault<Vec<u8>>>>,
}

/// A fault plan the world can change while connections run: a
/// [`Scenario`](crate::stdlib::scenario::Scenario) step sets a new one, and
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
        FaultPlan { inner: Arc::new(Mutex::new(Arc::new(plan))) }
    }

    /// Replaces the rules.
    pub fn set(&self, plan: Plan) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Arc::new(plan);
    }

    /// Removes every rule, keeping the seed.
    pub fn clear(&self) {
        let seed = self.get().seed;
        self.set(Plan { seed, ..Plan::default() });
    }

    /// The rules now.
    pub fn get(&self) -> Arc<Plan> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Chooses the TLS config for a handshake from the client's SNI. `None`
/// rejects the handshake with `unrecognized_name`.
pub type TlsSelect = Arc<dyn Fn(Option<&str>, &Cx) -> Option<Arc<ServerConfig>> + Send + Sync>;

/// How [`listen`] and [`serve`] run.
#[derive(Clone)]
pub struct ServeOptions {
    /// Connections one listener serves at once; past this, a new one is
    /// reset as soon as it is accepted. Default 64.
    pub max_conns: usize,
    /// Close a connection after this long with no bytes from the client,
    /// while the driver waits for them. Default 10 seconds. `None` waits
    /// forever.
    pub idle: Option<Duration>,
    /// Where events go. `None` drops them.
    pub journal: Option<Journal>,
    /// Records both directions.
    pub record: Option<Transcript>,
    /// Faults on the bytes and items.
    pub faults: Option<FaultPlan>,
    /// Shake hands first, with the config this picks.
    pub tls: Option<TlsSelect>,
    /// How long a client has from connecting to finish its TLS handshake.
    /// Default 10 seconds.
    pub handshake: Duration,
    /// Record `conn.open` and `conn.close` events. Default on.
    pub connection_events: bool,
    /// The read buffer's limit, at least the decoder's capacity. Larger
    /// lets the decoder see more at once. Default 0: the capacity.
    pub read_buffer: usize,
    /// Numbers connections, from 1. Clones of these options share it.
    pub ids: Arc<AtomicU64>,
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            max_conns: 64,
            idle: Some(Duration::from_secs(10)),
            journal: None,
            record: None,
            faults: None,
            tls: None,
            handshake: Duration::from_secs(10),
            connection_events: true,
            read_buffer: 0,
            ids: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl std::fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServeOptions")
            .field("max_conns", &self.max_conns)
            .field("idle", &self.idle)
            .field("journal", &self.journal.is_some())
            .field("record", &self.record.is_some())
            .field("faults", &self.faults)
            .field("tls", &self.tls.is_some())
            .field("connection_events", &self.connection_events)
            .finish()
    }
}

impl ServeOptions {
    /// Sends events to `journal`.
    pub fn journal(self, journal: Journal) -> ServeOptions {
        ServeOptions { journal: Some(journal), ..self }
    }

    /// Records both directions in `transcript`.
    pub fn record(self, transcript: Transcript) -> ServeOptions {
        ServeOptions { record: Some(transcript), ..self }
    }

    /// Runs `plan` on every connection.
    pub fn faults(self, plan: FaultPlan) -> ServeOptions {
        ServeOptions { faults: Some(plan), ..self }
    }

    /// Shakes hands with `config` for every name.
    pub fn tls(self, config: Arc<ServerConfig>) -> ServeOptions {
        ServeOptions { tls: Some(Arc::new(move |_, _| Some(config.clone()))), ..self }
    }

    /// Shakes hands with the config `select` picks for the client's SNI.
    pub fn tls_by_name(self, select: impl Fn(Option<&str>, &Cx) -> Option<Arc<ServerConfig>> + Send + Sync + 'static) -> ServeOptions {
        ServeOptions { tls: Some(Arc::new(select)), ..self }
    }

    /// Sets the idle limit.
    pub fn idle(self, idle: Option<Duration>) -> ServeOptions {
        ServeOptions { idle, ..self }
    }

    /// Sets the connection cap.
    pub fn max_conns(self, max_conns: usize) -> ServeOptions {
        ServeOptions { max_conns, ..self }
    }

    /// Turns `conn.open` and `conn.close` events on or off.
    pub fn connection_events(self, on: bool) -> ServeOptions {
        ServeOptions { connection_events: on, ..self }
    }

    fn next_id(&self) -> u64 {
        self.ids.fetch_add(1, Ordering::Relaxed) + 1
    }
}

// ---------------------------------------------------------------------------
// The driver

/// Why [`serve`] stopped early.
#[derive(Debug)]
pub enum ServeError<E> {
    /// The service returned this error. The connection was closed.
    Service(E),
    /// Deferred work failed. The connection was closed.
    Pending(fictionet::Error),
}

impl<E: core::fmt::Display> core::fmt::Display for ServeError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServeError::Service(e) => write!(f, "service: {e}"),
            ServeError::Pending(e) => write!(f, "deferred work: {e}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for ServeError<E> {}

/// How [`serve`] ended.
#[derive(Debug)]
pub enum Served<C> {
    /// The connection is closed, or broken.
    Closed(End),
    /// The service handed the connection back ([`Flow::Upgrade`], or its
    /// decoder ended).
    Upgraded(Prefixed<C>),
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
        Prefixed { unread, at: 0, conn }
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
    fn poll_read(&mut self, cx: &Cx, task: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, ConnError>> {
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
        self.conn.poll_read(cx, task, buf)
    }

    fn poll_write(&mut self, cx: &Cx, task: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize, ConnError>> {
        self.conn.poll_write(cx, task, data)
    }

    fn poll_shutdown(&mut self, cx: &Cx, task: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        self.conn.poll_shutdown(cx, task)
    }
}

/// Bytes waiting to enter the decoder, and the waits between them that
/// delay faults asked for.
enum Segment {
    Bytes(Vec<u8>, usize),
    Wait(Duration),
}

/// The fault state of one connection.
struct ConnFaults<D: Decode> {
    plan: FaultPlan,
    inbound: Faults,
    outbound: Faults,
    /// The second decoder item rules run on. Gone once it fails or ends.
    front: Option<Stream<D>>,
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
    /// Runs the byte rules for the client's chunk, then the item rules,
    /// and adds what comes out to `queue`.
    fn inbound(&mut self, chunk: &[u8], eof: bool, queue: &mut VecDeque<Segment>) {
        let plan = self.plan.get();
        let mut pieces: Vec<Segment> = Vec::new();
        if chunk.is_empty() {
        } else if plan.inbound.is_empty() {
            pieces.push(Segment::Bytes(chunk.to_vec(), 0));
        } else {
            let mut out = Vec::new();
            match self.inbound.bytes(&plan.inbound, chunk, &mut out) {
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
        for piece in pieces {
            match piece {
                Segment::Bytes(bytes, _) => self.items(&plan, &bytes, false, queue),
                wait => queue.push_back(wait),
            }
        }
        if eof {
            self.items(&plan, &[], true, queue);
        }
    }

    /// Runs the item rules over `bytes` through the front decoder.
    fn items(&mut self, plan: &Plan, bytes: &[u8], eof: bool, queue: &mut VecDeque<Segment>) {
        let Some(front) = self.front.as_mut() else {
            if !bytes.is_empty() {
                queue.push_back(Segment::Bytes(bytes.to_vec(), 0));
            }
            return;
        };
        let mut rest = bytes;
        let mut out = Vec::new();
        loop {
            let room = self.inbound.room(front, &out);
            let n = front.push(&rest[..rest.len().min(room)]);
            rest = &rest[n..];
            if eof && rest.is_empty() {
                front.end();
            }
            let mut moved = n > 0;
            while let Some(result) = self.inbound.next_with(front, &mut out, &plan.items, write_raw) {
                moved = true;
                match result {
                    Ok(Some(FaultDelay { at, duration })) => {
                        let at = at.min(out.len());
                        let tail = out.split_off(at);
                        queue.push_back(Segment::Bytes(std::mem::take(&mut out), 0));
                        queue.push_back(Segment::Wait(duration));
                        out = tail;
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            if !out.is_empty() {
                queue.push_back(Segment::Bytes(std::mem::take(&mut out), 0));
            }
            if front.is_done() {
                // Failed or ended: the rest goes through unchanged, and so
                // does everything after it.
                let mut left = front.unread().to_vec();
                left.extend_from_slice(rest);
                let _ = self.inbound.flush(&mut out);
                if !out.is_empty() {
                    queue.push_back(Segment::Bytes(std::mem::take(&mut out), 0));
                }
                if !left.is_empty() {
                    queue.push_back(Segment::Bytes(left, 0));
                }
                self.front = None;
                return;
            }
            if rest.is_empty() || !moved {
                if eof {
                    let _ = self.inbound.flush(&mut out);
                    if !out.is_empty() {
                        queue.push_back(Segment::Bytes(out, 0));
                    }
                }
                if !rest.is_empty() {
                    queue.push_back(Segment::Bytes(rest.to_vec(), 0));
                    self.front = None;
                }
                return;
            }
        }
    }

    /// Runs the outbound byte rules over one chunk: the bytes to write and
    /// where to wait.
    fn outbound(&mut self, chunk: &[u8]) -> (Vec<u8>, Option<FaultDelay>) {
        let plan = self.plan.get();
        if plan.outbound.is_empty() {
            return (chunk.to_vec(), None);
        }
        let mut out = Vec::new();
        match self.outbound.bytes(&plan.outbound, chunk, &mut out) {
            Ok(delay) => (out, delay),
            Err(_) => (chunk.to_vec(), None),
        }
    }
}

/// `fut`, unless `deadline` passes first. `Err(true)` if the region was
/// cancelled, `Err(false)` on the deadline.
pub async fn until<T>(cx: &Cx, deadline: Option<Instant>, fut: impl Future<Output = T>) -> Result<T, bool> {
    let mut fut = pin!(fut);
    let mut sleep = pin!(deadline.map(|d| cx.sleep_until(d)));
    let mut cancelled = pin!(cx.cancelled());
    poll_fn(|task| {
        if let Poll::Ready(v) = fut.as_mut().poll(task) {
            return Poll::Ready(Ok(v));
        }
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(true));
        }
        if let Some(sleep) = sleep.as_mut().as_pin_mut() {
            match sleep.poll(task) {
                Poll::Ready(Ok(())) => return Poll::Ready(Err(false)),
                Poll::Ready(Err(_)) => return Poll::Ready(Err(true)),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    })
    .await
}

/// What woke the driver while it waited for input.
enum Woke {
    Read(Result<usize, ConnError>),
    Timer,
    Idle,
    Cancelled,
    Gone,
}

/// One connection being served.
struct Driver<'o, S: Service, C> {
    conn: C,
    info: ConnInfo,
    opts: &'o ServeOptions,
    scratch: Scratch,
    timer_armed: Option<Duration>,
    deadline: Option<Instant>,
    faults: Option<ConnFaults<S::Decode>>,
    queue: VecDeque<Segment>,
    /// Bytes written to the client so far, for the transcript.
    out_offset: u64,
    gone: Option<GoneWatch>,
    ended: bool,
}

impl<S: Service, C: Connection> Driver<'_, S, C>
where
    <S::Decode as Decode>::Error: Clone + Send,
{
    /// Sends the events of the last call to the journal.
    fn flush_events(&mut self, cx: &Cx) {
        if self.scratch.events.is_empty() {
            return;
        }
        let events = std::mem::take(&mut self.scratch.events);
        if let Some(journal) = &self.opts.journal {
            for event in events {
                journal.record(cx, &self.info, event);
            }
        }
    }

    /// Writes `bytes`, through the outbound faults and the transcript.
    async fn write(&mut self, cx: &Cx, bytes: &[u8]) -> Result<(), ConnError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let (out, delay) = match &mut self.faults {
            Some(f) => f.outbound(bytes),
            None => (bytes.to_vec(), None),
        };
        let at = delay.map_or(out.len(), |d| d.at.min(out.len()));
        self.write_now(cx, &out[..at]).await?;
        if let Some(delay) = delay {
            cx.sleep(delay.duration).await.map_err(|_| ConnError::Cancelled)?;
            self.write_now(cx, &out[at..]).await?;
        }
        Ok(())
    }

    async fn write_now(&mut self, cx: &Cx, bytes: &[u8]) -> Result<(), ConnError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if let Some(t) = &self.opts.record {
            let start = self.out_offset;
            let end = start.saturating_add(bytes.len() as u64);
            t.observe::<(), String>(self.info.id.unwrap_or(0), Direction::ServerToClient, StreamEvent::Skipped { bytes, range: start..end });
        }
        self.out_offset = self.out_offset.saturating_add(bytes.len() as u64);
        self.conn.write_all(cx, bytes).await
    }

    /// After a call: records its events, takes its timer, writes its reply
    /// and runs its deferred work. `Err` with the end if the connection
    /// ended meanwhile.
    async fn after(&mut self, cx: &Cx) -> Result<(), End> {
        self.flush_events(cx);
        match std::mem::take(&mut self.scratch.timer) {
            TimerRequest::Unchanged => {}
            TimerRequest::Set(d) => {
                self.timer_armed = Some(d);
                self.deadline = None;
            }
            TimerRequest::Cancel => {
                self.timer_armed = None;
                self.deadline = None;
            }
        }
        let reply = std::mem::take(&mut self.scratch.reply);
        if let Err(e) = self.write(cx, &reply).await {
            return Err(conn_end(e));
        }
        if let Some(work) = self.scratch.deferred.take() {
            self.run_pending(cx, work).await?;
        }
        Ok(())
    }

    async fn run_pending(&mut self, cx: &Cx, mut work: Box<dyn Pending>) -> Result<(), End> {
        let mut written = 0u64;
        let logging = self.scratch.logging;
        loop {
            let mut events = Vec::new();
            let next = {
                let info = &self.info;
                let gone = &self.gone;
                let mut cancelled = pin!(cx.cancelled());
                poll_fn(|task| {
                    let mut ctx = PendingCtx { cx, events: &mut events, written, conn: info, logging };
                    if let Poll::Ready(next) = work.poll_next(&mut ctx, task) {
                        return Poll::Ready(Ok(next));
                    }
                    if cancelled.as_mut().poll(task).is_ready() {
                        return Poll::Ready(Err(End::Cancelled));
                    }
                    if let Some(g) = gone
                        && g.poll_gone(task).is_ready()
                    {
                        return Poll::Ready(Err(End::Conn(ConnError::Reset)));
                    }
                    Poll::Pending
                })
                .await
            };
            self.scratch.events.append(&mut events);
            match next {
                Ok(Some(Ok(bytes))) => {
                    self.flush_events(cx);
                    if let Err(e) = self.write(cx, &bytes).await {
                        self.cancel_pending(cx, &mut work, written);
                        return Err(conn_end(e));
                    }
                    written += bytes.len() as u64;
                }
                Ok(Some(Err(_))) => {
                    self.flush_events(cx);
                    return Err(End::Closed);
                }
                Ok(None) => {
                    self.flush_events(cx);
                    return Ok(());
                }
                Err(end) => {
                    self.cancel_pending(cx, &mut work, written);
                    return Err(end);
                }
            }
        }
    }

    fn cancel_pending(&mut self, cx: &Cx, work: &mut Box<dyn Pending>, written: u64) {
        let mut events = Vec::new();
        let mut ctx = PendingCtx { cx, events: &mut events, written, conn: &self.info, logging: self.scratch.logging };
        work.cancel(&mut ctx);
        self.scratch.events.append(&mut events);
        self.flush_events(cx);
    }

    /// Ends the connection: `on_end`, the last reply if it can still be
    /// written, and a shutdown.
    async fn finish(&mut self, cx: &Cx, service: &mut S, world: &S::World, end: End) -> Result<End, ServeError<S::Error>> {
        if self.ended {
            return Ok(end);
        }
        self.ended = true;
        let result = service.on_end(end, world, &mut self.scratch.ctx(cx.now(), &self.info));
        self.flush_events(cx);
        let writable = matches!(end, End::Eof | End::Closed | End::Failed | End::Idle);
        if writable {
            let reply = std::mem::take(&mut self.scratch.reply);
            let _ = self.write(cx, &reply).await;
            if let Some(work) = self.scratch.deferred.take() {
                let _ = self.run_pending(cx, work).await;
            }
            let _ = until(cx, Some(cx.now() + Duration::from_secs(5)), self.conn.shutdown(cx)).await;
        }
        if self.opts.connection_events
            && let Some(j) = &self.opts.journal
        {
            j.record(cx, &self.info, Event::new("conn", "close").field("end", end_name(end)).summary(format!("connection closed: {}", end_name(end))));
        }
        self.scratch.deferred = None;
        result.map_err(ServeError::Service)?;
        Ok(end)
    }

    fn arm_timer(&mut self, now: Instant) {
        if let Some(d) = self.timer_armed.take() {
            self.deadline = Some(now + d);
        }
    }
}

fn conn_end(e: ConnError) -> End {
    match e {
        ConnError::Cancelled => End::Cancelled,
        e => End::Conn(e),
    }
}

fn end_name(end: End) -> &'static str {
    match end {
        End::Eof => "eof",
        End::Closed => "closed",
        End::Failed => "failed",
        End::Idle => "idle",
        End::Conn(ConnError::Reset) => "reset",
        End::Conn(ConnError::Broken) => "broken",
        End::Conn(_) => "error",
        End::Cancelled => "cancelled",
    }
}

/// How big each read is.
const READ: usize = 16 * 1024;

/// Serves one connection with `service` until it ends. Returns how it
/// ended, or the connection with its unread bytes after a handoff.
///
/// `info` names the connection in events; [`listen`] fills it in. `gone`,
/// when given, ends the connection as soon as the client resets it, even
/// while deferred work runs and nothing reads (see
/// [`TcpConnection::gone_watch`](crate::stdlib::tcp::TcpConnection::gone_watch)).
pub async fn serve<S, C>(
    cx: &Cx,
    conn: C,
    info: ConnInfo,
    gone: Option<GoneWatch>,
    service: &mut S,
    world: &S::World,
    opts: &ServeOptions,
) -> Result<Served<C>, ServeError<S::Error>>
where
    S: Service,
    C: Connection,
    <S::Decode as Decode>::Error: Clone + Send,
{
    let logging = opts.journal.as_ref().is_some_and(|j| j.wants(cx));
    let seed = cx.random_u64();
    let faults = opts.faults.as_ref().map(|plan| {
        let seed = plan.get().seed ^ info.id.unwrap_or(0).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        ConnFaults {
            plan: plan.clone(),
            inbound: Faults::new(seed, FAULT_OUTPUT, FAULT_HELD),
            outbound: Faults::new(seed ^ 1, FAULT_OUTPUT, FAULT_HELD),
            front: Some(Stream::new(service.decoder())),
        }
    });
    let mut d: Driver<'_, S, C> = Driver {
        conn,
        info,
        opts,
        scratch: Scratch::new(seed, logging),
        timer_armed: None,
        deadline: None,
        faults,
        queue: VecDeque::new(),
        out_offset: 0,
        gone,
        ended: false,
    };
    if opts.connection_events
        && let Some(j) = &opts.journal
    {
        j.record(cx, &d.info, Event::new("conn", "open").summary("connection opened"));
    }
    let mut stream = Stream::with_buffer(service.decoder(), opts.read_buffer);
    let tag = d.info.id.unwrap_or(0);
    let flow = service.on_open(world, &mut d.scratch.ctx(cx.now(), &d.info)).map_err(ServeError::Service);
    let flow = match flow {
        Ok(flow) => flow,
        Err(e) => {
            let _ = d.finish(cx, service, world, End::Closed).await;
            return Err(e);
        }
    };
    if let Err(end) = d.after(cx).await {
        return d.finish(cx, service, world, end).await.map(Served::Closed);
    }
    match flow {
        Flow::Continue => {}
        Flow::Close => return d.finish(cx, service, world, End::Closed).await.map(Served::Closed),
        Flow::Upgrade => return Ok(Served::Upgraded(upgraded(d, stream))),
    }
    let mut buf = vec![0u8; READ];
    let mut eof = false;
    let mut idle_from = cx.now();
    loop {
        // Feed what waits, up to the first delay.
        while let Some(front) = d.queue.front_mut() {
            match front {
                Segment::Bytes(bytes, at) => {
                    let n = stream.push(&bytes[*at..]);
                    *at += n;
                    if *at == bytes.len() {
                        d.queue.pop_front();
                    } else {
                        break;
                    }
                }
                Segment::Wait(_) => break,
            }
        }
        if eof && d.queue.is_empty() {
            stream.end();
        }
        // Every item that is whole.
        let mut handled = false;
        loop {
            enum Called<E> {
                Item(Result<Flow, E>),
                Failed(Result<(), E>),
                Nothing,
            }
            let called = {
            let record = opts.record.clone();
            let next = stream.with_next_observed(
                |item, _, _| item,
                |event| {
                    if let Some(t) = &record {
                        t.observe(tag, Direction::ClientToServer, event);
                    }
                },
            );
            match next {
                Some(Ok(item)) => Called::Item(service.on_item(item, world, &mut d.scratch.ctx(cx.now(), &d.info))),
                Some(Err(fail)) => {
                    d.scratch.unread = stream.unread().to_vec();
                    let result = service.on_fail(&fail, world, &mut d.scratch.ctx(cx.now(), &d.info));
                    d.scratch.unread = Vec::new();
                    Called::Failed(result)
                }
                None => Called::Nothing,
            }
            };
            match called {
                Called::Item(flow) => {
                    handled = true;
                    let flow = match flow {
                        Ok(flow) => flow,
                        Err(e) => {
                            let _ = d.finish(cx, service, world, End::Closed).await;
                            return Err(ServeError::Service(e));
                        }
                    };
                    if let Err(end) = d.after(cx).await {
                        return d.finish(cx, service, world, end).await.map(Served::Closed);
                    }
                    match flow {
                        Flow::Continue => {}
                        Flow::Close => return d.finish(cx, service, world, End::Closed).await.map(Served::Closed),
                        Flow::Upgrade => return Ok(Served::Upgraded(upgraded(d, stream))),
                    }
                }
                Called::Failed(result) => {
                    if let Err(e) = result {
                        let _ = d.finish(cx, service, world, End::Failed).await;
                        return Err(ServeError::Service(e));
                    }
                    if let Err(end) = d.after(cx).await {
                        return d.finish(cx, service, world, end).await.map(Served::Closed);
                    }
                    return d.finish(cx, service, world, End::Failed).await.map(Served::Closed);
                }
                Called::Nothing => break,
            }
        }
        if stream.is_done() {
            if stream.failed().is_none() && !(eof && d.queue.is_empty() && stream.unread().is_empty()) {
                // The decoder ended: the rest belongs to the next protocol.
                return Ok(Served::Upgraded(upgraded(d, stream)));
            }
            return d.finish(cx, service, world, End::Eof).await.map(Served::Closed);
        }
        if handled {
            idle_from = cx.now();
        }
        // A delay a fault asked for, once everything before it is in.
        if let Some(Segment::Wait(w)) = d.queue.front() {
            let w = *w;
            d.queue.pop_front();
            if cx.sleep(w).await.is_err() {
                return d.finish(cx, service, world, End::Cancelled).await.map(Served::Closed);
            }
            continue;
        }
        if !d.queue.is_empty() || eof {
            // The decoder cannot take more until it makes progress, which
            // the next pass reports as stuck if it never does.
            if !handled && !eof {
                return d.finish(cx, service, world, End::Failed).await.map(Served::Closed);
            }
            continue;
        }
        // Wait for bytes, the timer, idleness, a reset or the end.
        d.arm_timer(cx.now());
        let idle_at = opts.idle.map(|i| idle_from + i);
        let woke = {
            let conn = &mut d.conn;
            let gone = &d.gone;
            let timer = d.deadline;
            let mut timer_sleep = pin!(timer.map(|t| cx.sleep_until(t)));
            let mut idle_sleep = pin!(idle_at.map(|t| cx.sleep_until(t)));
            let mut cancelled = pin!(cx.cancelled());
            poll_fn(|task| {
                if let Poll::Ready(r) = conn.poll_read(cx, task, &mut buf) {
                    return Poll::Ready(Woke::Read(r));
                }
                if cancelled.as_mut().poll(task).is_ready() {
                    return Poll::Ready(Woke::Cancelled);
                }
                if let Some(g) = gone
                    && g.poll_gone(task).is_ready()
                {
                    return Poll::Ready(Woke::Gone);
                }
                if let Some(s) = timer_sleep.as_mut().as_pin_mut()
                    && s.poll(task).is_ready()
                {
                    return Poll::Ready(Woke::Timer);
                }
                if let Some(s) = idle_sleep.as_mut().as_pin_mut()
                    && s.poll(task).is_ready()
                {
                    return Poll::Ready(Woke::Idle);
                }
                Poll::Pending
            })
            .await
        };
        match woke {
            Woke::Read(Ok(0)) => {
                eof = true;
                if let Some(f) = &mut d.faults {
                    f.inbound(&[], true, &mut d.queue);
                }
            }
            Woke::Read(Ok(n)) => {
                d.scratch.bytes_in += n as u64;
                idle_from = cx.now();
                match &mut d.faults {
                    Some(f) => f.inbound(&buf[..n], false, &mut d.queue),
                    None => d.queue.push_back(Segment::Bytes(buf[..n].to_vec(), 0)),
                }
            }
            Woke::Read(Err(e)) => return d.finish(cx, service, world, conn_end(e)).await.map(Served::Closed),
            Woke::Cancelled => return d.finish(cx, service, world, End::Cancelled).await.map(Served::Closed),
            Woke::Gone => return d.finish(cx, service, world, End::Conn(ConnError::Reset)).await.map(Served::Closed),
            Woke::Idle => return d.finish(cx, service, world, End::Idle).await.map(Served::Closed),
            Woke::Timer => {
                d.deadline = None;
                let flow = service.on_tick(world, &mut d.scratch.ctx(cx.now(), &d.info));
                let flow = match flow {
                    Ok(flow) => flow,
                    Err(e) => {
                        let _ = d.finish(cx, service, world, End::Closed).await;
                        return Err(ServeError::Service(e));
                    }
                };
                if let Err(end) = d.after(cx).await {
                    return d.finish(cx, service, world, end).await.map(Served::Closed);
                }
                match flow {
                    Flow::Continue => {}
                    Flow::Close => return d.finish(cx, service, world, End::Closed).await.map(Served::Closed),
                    Flow::Upgrade => return Ok(Served::Upgraded(upgraded(d, stream))),
                }
            }
        }
    }
}

/// The connection and every byte not yet decoded, for a handoff.
fn upgraded<S: Service, C>(d: Driver<'_, S, C>, stream: Stream<S::Decode>) -> Prefixed<C> {
    let mut unread = stream.unread().to_vec();
    for segment in d.queue {
        if let Segment::Bytes(bytes, at) = segment {
            unread.extend_from_slice(&bytes[at..]);
        }
    }
    Prefixed::new(unread, d.conn)
}

// ---------------------------------------------------------------------------
// TLS

/// How a TLS handshake ended, as the `tls.handshake` event says.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsOutcome {
    /// It finished, with this protocol agreed by ALPN.
    Accepted {
        /// The protocol, if one was agreed.
        alpn: Option<Vec<u8>>,
    },
    /// Refused with `unrecognized_name`: no config for the SNI.
    Rejected,
    /// The client sent this alert, such as 48 (`unknown_ca`).
    Alert(u8),
    /// The bytes were not TLS, or broke the protocol.
    Failed(String),
    /// The client closed the connection first.
    Closed,
    /// It did not finish in time.
    TimedOut,
    /// The world ended it: the sandbox detached, or the world stopped.
    Aborted,
}

impl TlsOutcome {
    /// `accepted`, `rejected`, `alert`, `failed`, `closed`, `timed_out` or
    /// `aborted`.
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsOutcome::Accepted { .. } => "accepted",
            TlsOutcome::Rejected => "rejected",
            TlsOutcome::Alert(_) => "alert",
            TlsOutcome::Failed(_) => "failed",
            TlsOutcome::Closed => "closed",
            TlsOutcome::TimedOut => "timed_out",
            TlsOutcome::Aborted => "aborted",
        }
    }
}

/// Shakes hands as a TLS server on `conn`, with the config `select` picks
/// for the client's SNI, by `deadline`. Records a `tls.handshake` event in
/// `journal` with the outcome. `aborted` says whether the world itself
/// ended the connection, for a reset that came from the world.
///
/// Returns the TLS connection and `info` with its SNI and ALPN.
pub async fn accept_tls<C: Connection>(
    cx: &Cx,
    conn: C,
    info: &ConnInfo,
    select: &TlsSelect,
    deadline: Instant,
    journal: Option<&Journal>,
    aborted: impl Fn() -> bool,
) -> Option<(TlsConnection<C>, ConnInfo)> {
    let mut sni: Option<String> = None;
    let mut failed: Option<HandshakeError> = None;
    let mut rejected = false;
    let handshake = async {
        let hello = match tls::server_detailed(cx, conn).await {
            Ok(hello) => hello,
            Err(e) => {
                failed = Some(e);
                return None;
            }
        };
        sni = hello.server_name().map(|n| n.trim_end_matches('.').to_ascii_lowercase());
        let Some(config) = select(sni.as_deref(), cx) else {
            rejected = true;
            let _ = hello.reject(cx).await;
            return None;
        };
        match hello.finish_detailed(cx, config).await {
            Ok(conn) => Some(conn),
            Err(e) => {
                failed = Some(e);
                None
            }
        }
    };
    let done = until(cx, Some(deadline), handshake).await;
    let (conn, outcome) = match done {
        Ok(Some(conn)) => {
            let alpn = conn.alpn().map(<[u8]>::to_vec);
            (Some(conn), TlsOutcome::Accepted { alpn })
        }
        Ok(None) if rejected => (None, TlsOutcome::Rejected),
        Ok(None) => (None, TlsOutcome::Closed),
        Err(false) => (None, TlsOutcome::TimedOut),
        Err(true) => (None, TlsOutcome::Aborted),
    };
    let outcome = match failed {
        Some(HandshakeError::Alert(a)) => TlsOutcome::Alert(a),
        Some(HandshakeError::Failed(why)) => TlsOutcome::Failed(why),
        Some(HandshakeError::Conn(ConnError::Broken)) => TlsOutcome::Failed("the connection broke".into()),
        Some(HandshakeError::Conn(ConnError::Cancelled)) => TlsOutcome::Aborted,
        Some(HandshakeError::Conn(ConnError::Reset)) if aborted() => TlsOutcome::Aborted,
        Some(_) => TlsOutcome::Closed,
        None => outcome,
    };
    if let Some(j) = journal
        && j.wants(cx)
    {
        let mut event = Event::new("tls", "handshake")
            .summary(match &sni {
                Some(n) => format!("TLS for {n}: {}", outcome.as_str()),
                None => format!("TLS with no name: {}", outcome.as_str()),
            })
            .level(if matches!(outcome, TlsOutcome::Accepted { .. }) { Level::Info } else { Level::Notice })
            .field("addr", fictionet::stdlib::journal::opt(info.local.map(|a| a.ip().to_string())))
            .field("sni", fictionet::stdlib::journal::opt(sni.clone()))
            .field("outcome", outcome.as_str());
        match &outcome {
            TlsOutcome::Accepted { alpn } => {
                event = event.field("alpn", fictionet::stdlib::journal::opt(alpn.as_ref().map(|a| String::from_utf8_lossy(a).into_owned())));
            }
            TlsOutcome::Alert(a) => event = event.field("alert", u32::from(*a)),
            TlsOutcome::Failed(why) => event = event.field("detail", why.as_str()),
            _ => {}
        }
        j.record(cx, info, event);
    }
    let conn = conn?;
    let info = info.clone().over_tls(sni.as_deref(), conn.alpn());
    Some((conn, info))
}

// ---------------------------------------------------------------------------
// Listening

/// Accepts connections on `listener` and serves each with a fresh service
/// from `make`, in a task of its own, until the listener closes or the
/// region is cancelled. With [`ServeOptions::tls`], each connection shakes
/// hands first. Returns the accepting task.
pub fn listen<S, M>(cx: &Cx, mut listener: Listener, world: Arc<S::World>, make: M, opts: ServeOptions) -> Task
where
    S: Service,
    M: Fn() -> S + Send + Sync + 'static,
    <S::Decode as Decode>::Error: Clone + Send,
{
    let make = Arc::new(make);
    cx.spawn(move |cx| async move {
        let open = Arc::new(AtomicUsize::new(0));
        loop {
            let conn = match listener.accept(&cx).await {
                Ok(conn) => conn,
                Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
                Err(_) => continue,
            };
            if open.load(Ordering::Relaxed) >= opts.max_conns {
                conn.reset();
                continue;
            }
            open.fetch_add(1, Ordering::Relaxed);
            let guard = Counted(open.clone());
            let info = ConnInfo::new(opts.next_id(), conn.local_addr(), conn.peer_addr());
            let (world, make, opts) = (world.clone(), make.clone(), opts.clone());
            cx.spawn(move |cx| async move {
                let _guard = guard;
                let gone = Some(conn.gone_watch());
                let mut service = make();
                match &opts.tls {
                    None => {
                        let _ = serve(&cx, conn, info, gone, &mut service, &world, &opts).await;
                    }
                    Some(select) => {
                        let deadline = cx.now() + opts.handshake;
                        if let Some((conn, info)) = accept_tls(&cx, conn, &info, select, deadline, opts.journal.as_ref(), || false).await {
                            let _ = serve(&cx, conn, info, gone, &mut service, &world, &opts).await;
                        }
                    }
                }
                Ok(())
            });
        }
    })
}

/// Counts one open connection until dropped.
struct Counted(Arc<AtomicUsize>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Serves every datagram on `socket` with `service`, one at a time, until
/// the socket closes or the region is cancelled.
///
/// Each datagram is decoded on its own, with a fresh decoder that sees the
/// end of input after it, as DNS, DHCP and Modbus over UDP frame their
/// messages. The reply bytes of one datagram's items go back to its sender
/// as one datagram. The service's [`ConnInfo`] names the sender in `peer`.
/// Timers and deferred work are not used over UDP.
pub async fn serve_datagram<S>(
    cx: &Cx,
    mut socket: Socket,
    local: SocketAddr,
    service: &mut S,
    world: &S::World,
    opts: &ServeOptions,
) -> Result<(), ServeError<S::Error>>
where
    S: Service,
    <S::Decode as Decode>::Error: Clone + Send,
{
    let mut scratch = Scratch::new(cx.random_u64(), opts.journal.as_ref().is_some_and(|j| j.wants(cx)));
    let mut run = 0u32;
    while let Ok((datagram, from)) = socket.recv(cx).await {
        let info = ConnInfo { local: Some(local), peer: Some(from), ..ConnInfo::default() };
        let mut stream = Stream::with_buffer(service.decoder(), datagram.len());
        let n = stream.push(&datagram);
        stream.end();
        let mut fail = n < datagram.len();
        loop {
            match stream.next() {
                Some(Ok(item)) => {
                    let flow = service.on_item(item, world, &mut scratch.ctx(cx.now(), &info)).map_err(ServeError::Service)?;
                    if flow != Flow::Continue {
                        break;
                    }
                }
                Some(Err(e)) => {
                    scratch.unread = stream.unread().to_vec();
                    let result = service.on_fail(&e, world, &mut scratch.ctx(cx.now(), &info));
                    scratch.unread = Vec::new();
                    result.map_err(ServeError::Service)?;
                    fail = false;
                    break;
                }
                None => break,
            }
        }
        let _ = fail;
        scratch.deferred = None;
        if let Some(j) = &opts.journal {
            for event in std::mem::take(&mut scratch.events) {
                j.record(cx, &info, event);
            }
        }
        scratch.events.clear();
        let reply = std::mem::take(&mut scratch.reply);
        if !reply.is_empty() {
            socket.send_to(&reply, from);
        }
        run = (run + 1) % 64;
        if run == 0 && cx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The harness

/// Why [`Harness::push`] stopped.
#[derive(Debug)]
pub enum HarnessError<D, S> {
    /// The decoder failed. [`Service::on_fail`] ran, and its reply is in
    /// [`Harness::output`].
    Decode(Fail<D>),
    /// The service returned an error.
    Service(S),
    /// The connection is closed: no more bytes are taken.
    Closed,
}

impl<D: core::fmt::Display, S: core::fmt::Display> core::fmt::Display for HarnessError<D, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HarnessError::Decode(e) => write!(f, "decoder: {e}"),
            HarnessError::Service(e) => write!(f, "service: {e}"),
            HarnessError::Closed => f.write_str("the connection is closed"),
        }
    }
}

impl<D: core::error::Error, S: core::error::Error> core::error::Error for HarnessError<D, S> {}

/// Runs a service with no I/O and no runtime: push the client's bytes,
/// get the reply. For unit tests, fuzz targets and contract checks. The
/// clock stands still until [`advance`](Self::advance) moves it, and the
/// timer goes off then.
pub struct Harness<S: Service> {
    service: S,
    world: S::World,
    stream: Stream<S::Decode>,
    scratch: Scratch,
    conn: ConnInfo,
    now: Instant,
    deadline: Option<Instant>,
    opened: bool,
    closed: Option<End>,
    events: Vec<Event>,
    output: Vec<u8>,
}

type HarnessResult<S> = Result<Vec<u8>, HarnessError<<<S as Service>::Decode as Decode>::Error, <S as Service>::Error>>;

impl<S: Service> Harness<S>
where
    <S::Decode as Decode>::Error: Clone,
{
    /// A connection to `service`, with `world`, at time zero, numbered 1.
    pub fn new(service: S, world: S::World) -> Harness<S> {
        let stream = Stream::new(service.decoder());
        Harness {
            service,
            world,
            stream,
            scratch: Scratch::new(1, true),
            conn: ConnInfo { id: Some(1), ..ConnInfo::default() },
            now: Instant::ZERO,
            deadline: None,
            opened: false,
            closed: None,
            events: Vec::new(),
            output: Vec::new(),
        }
    }

    /// The connection the service sees.
    pub fn with_conn(mut self, conn: ConnInfo) -> Harness<S> {
        self.conn = conn;
        self
    }

    fn take(&mut self) -> Vec<u8> {
        self.events.append(&mut self.scratch.events);
        match std::mem::take(&mut self.scratch.timer) {
            TimerRequest::Unchanged => {}
            TimerRequest::Set(d) => self.deadline = Some(self.now + d),
            TimerRequest::Cancel => self.deadline = None,
        }
        self.scratch.deferred = None;
        let reply = std::mem::take(&mut self.scratch.reply);
        self.output.extend_from_slice(&reply);
        reply
    }

    fn flow(&mut self, flow: Flow) {
        if flow != Flow::Continue && self.closed.is_none() {
            self.end_with(End::Closed);
        }
    }

    fn end_with(&mut self, end: End) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(end);
        let _ = self.service.on_end(end, &self.world, &mut self.scratch.ctx(self.now, &self.conn));
    }

    /// Opens the connection, if it is not open yet: what the service
    /// sends first.
    pub fn open(&mut self) -> HarnessResult<S> {
        if self.opened {
            return Ok(Vec::new());
        }
        self.opened = true;
        let flow = self.service.on_open(&self.world, &mut self.scratch.ctx(self.now, &self.conn)).map_err(HarnessError::Service)?;
        self.flow(flow);
        Ok(self.take())
    }

    /// The client sends `bytes`. Returns the reply to them.
    pub fn push(&mut self, bytes: &[u8]) -> HarnessResult<S> {
        let mut reply = self.open()?;
        if self.closed.is_some() {
            return Err(HarnessError::Closed);
        }
        let mut rest = bytes;
        self.scratch.bytes_in += bytes.len() as u64;
        loop {
            let n = self.stream.push(rest);
            rest = &rest[n..];
            reply.extend(self.items()?);
            if self.closed.is_some() || self.stream.is_done() || rest.is_empty() {
                return Ok(reply);
            }
            if n == 0 {
                return Err(HarnessError::Closed);
            }
        }
    }

    fn items(&mut self) -> HarnessResult<S> {
        let mut reply = Vec::new();
        while self.closed.is_none() {
            match self.stream.next() {
                Some(Ok(item)) => {
                    let flow = self.service.on_item(item, &self.world, &mut self.scratch.ctx(self.now, &self.conn)).map_err(HarnessError::Service)?;
                    self.flow(flow);
                    reply.extend(self.take());
                }
                Some(Err(e)) => {
                    self.scratch.unread = self.stream.unread().to_vec();
                    let result = self.service.on_fail(&e, &self.world, &mut self.scratch.ctx(self.now, &self.conn));
                    self.scratch.unread = Vec::new();
                    result.map_err(HarnessError::Service)?;
                    self.end_with(End::Failed);
                    reply.extend(self.take());
                    return Err(HarnessError::Decode(e));
                }
                None => break,
            }
        }
        Ok(reply)
    }

    /// The client half-closes: the service sees the end of input.
    pub fn end(&mut self) -> HarnessResult<S> {
        let mut reply = self.open()?;
        self.stream.end();
        reply.extend(self.items()?);
        self.end_with(End::Eof);
        reply.extend(self.take());
        Ok(reply)
    }

    /// Moves the clock by `d`. If the timer goes off, the service ticks;
    /// returns its reply.
    pub fn advance(&mut self, d: Duration) -> HarnessResult<S> {
        self.now = self.now + d;
        if self.closed.is_some() || self.deadline.is_none_or(|t| t > self.now) {
            return Ok(Vec::new());
        }
        self.deadline = None;
        let flow = self.service.on_tick(&self.world, &mut self.scratch.ctx(self.now, &self.conn)).map_err(HarnessError::Service)?;
        self.flow(flow);
        Ok(self.take())
    }

    /// When the timer will go off, if it is set.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether the connection has ended.
    pub fn closed(&self) -> bool {
        self.closed.is_some()
    }

    /// How it ended.
    pub fn end_reason(&self) -> Option<End> {
        self.closed
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

    /// The world.
    pub fn world(&self) -> &S::World {
        &self.world
    }
}
