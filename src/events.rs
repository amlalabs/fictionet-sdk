//! Events: everything a world reports about itself, kept by the run
//! whether or not anyone reads it.
//!
//! An [`Event`] is one fact: the source that saw it (`"dns"`, `"http"`,
//! `"lan"`, `"modbus"`), its kind (`"query"`, `"request"`, `"drop"`), a
//! one-line summary, a [`Level`], the connection it came from
//! ([`ConnInfo`]), and named [`Fields`] whose values are JSON. Services,
//! the network and the core's own pieces (a [bottleneck] that drops a
//! packet, a [router] that loses a route, a LAN) all record events, and so
//! can world code:
//!
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use fictionet::events::{Event, Level};
//! # fictionet::block_on(fictionet::run(fictionet::Seed::random(), |fcx| async move {
//! fcx.record(Event::new("modbus", "write_register")
//!     .summary("register 40001 = 900")
//!     .level(Level::Alarm)
//!     .field("register", 40001u32)
//!     .field("value", 900u32));
//! let events = fcx.events().of("modbus", "write_register");
//! assert_eq!(events[0].u64("value"), Some(900));
//! # Ok(()) }))?;
//! # }
//! # Ok::<(), fictionet::Error>(())
//! ```
//!
//! # The event log
//!
//! Every run keeps an [`EventLog`], from its first moment to its end,
//! with no sink to set. Recording numbers each event (`seq`, from 1, with
//! no gaps) and dates it on the run's clock ([`Cx::now`]), never the
//! host's. In a lab, repeatability depends on the world's inputs and clock
//! use; see [Repeatable runs](crate::running#repeatable-runs), including
//! the HTTP/2 exception.
//! The log is bounded: it holds the latest [`MAX_EVENTS`] events, and at
//! most [`MAX_EVENT_BYTES`] of them ([`Event::size`]). Past either limit
//! the oldest go first. An event larger than its part's byte limit is
//! numbered but not kept, without evicting other events. Every reader
//! that missed some is told how many, with an `events.dropped` event in
//! their place ([`EventLog::after`]), including gaps from rejected events.
//!
//! [`Net::start`](crate::stdlib::net::Net::start) records `run.start`, with
//! the seed and clock origin. Neither [`run`](crate::run) nor
//! [`lab`](crate::lab) emits it automatically. A world built from lower-level
//! pieces calls `fcx.events().start(&fcx, Fields::new())` itself. The event
//! log reports what happened; it is not a recording of every input needed
//! to replay a real run.
//!
//! # Repeats
//!
//! Some events come once per packet: a packet the network refuses
//! (`net.blocked`), or one a LAN, a router or a [bottleneck] drops
//! (`drop`). The sandbox decides how many of those there are, so an agent
//! that scans every port or floods a link would otherwise fill the log
//! and push out the events a grader reads. Such events are recorded with
//! [`Cx::record_repeat`], which counts them instead:
//!
//! - Repeats are alike when their source, kind, connection and fields
//!   match. Fields that change with every packet, such as a destination
//!   port or a length, go in the `detail` given beside the event, and do
//!   not tell repeats apart.
//! - The first of a run of alike repeats is recorded as it comes, with its
//!   detail and the field `count` set to 1. For the next
//!   [`REPEAT_WINDOW`] on the run's clock, repeats of it are only counted.
//!   When the window has passed, the first event recorded after it, or the
//!   run's end, records one more event for them: the same source, kind,
//!   connection and fields, `count` repeats, and for each detail field
//!   that is a number, its lowest and highest values as `[low, high]`.
//!   The sum of `count` over alike events is how many repeats there were.
//! - Repeats are kept apart from every other event, within their own
//!   bounds: the latest [`MAX_REPEATS`] of them, and at most
//!   [`MAX_REPEAT_BYTES`]. Past either, the oldest repeat goes first. A
//!   flood of repeats never pushes out another event, and other events
//!   never push out repeats. A reader that missed some is told as for any
//!   other event: an `events.dropped` event stands where they were.
//! - Open windows have separate bounds: 1,024 windows and
//!   [`MAX_OPEN_REPEAT_BYTES`] for their keys, first events and numeric
//!   detail ranges. To make room, the oldest windows record their counts
//!   early. A repeat too large for a window is recorded individually with
//!   `count` set to 1, subject to the repeat history's limits.
//!
//! While its windows fit, a flood costs at most two events per second for
//! each distinct kind of repeat, and never costs the run a service's
//! event, an HTTP request, a DNS query, a TLS handshake or a connection's
//! open and close.
//!
//! Everything that reads events reads this log:
//!
//! - observers such as `fictionet dashboard` and `fictionet observe
//!   watch`, which see what the log still holds when they connect, then
//!   every new event as it comes (see [`observe`](crate::observe#events));
//! - a JSON Lines file, one event per line, for a grader that reads it
//!   after the run ([`EventLog::to_file`]);
//! - callbacks in the same process ([`EventLog::subscribe`]);
//! - a grader or a test in the same process, which reads the log itself,
//!   during the run or after it ([`EventLog::all`] and [`EventLog::wait`]).
//!
//! A reader that starts late misses nothing the log still holds: a file
//! or a callback set halfway through a run first gets what the log kept,
//! then the rest as it is recorded. Live callbacks receive even events
//! too large to retain. File sinks still apply their own queue limits.
//!
//! Native real runs with `std` write files on a helper thread with a bounded
//! queue. In browsers, labs and builds without `std`, sinks write and flush
//! synchronously in the subscription's drainer, in event order, without
//! writer-queue overflow or writer scheduling affecting the log. A lab's
//! `run.start.wall` is null; real runs record their wall date. Attach a sink
//! before recording begins to retain events beyond the in-memory log's limits.
//!
//! # What it costs
//!
//! Byte budgets charge owned capacities and shared connection metadata
//! in full for each retained copy, with estimated allocation overhead.
//! They exclude spare capacity in history queues and window indexes,
//! static strings, temporary allocations while recording or reading, and
//! copies held by readers, callbacks, or pending subscription deliveries.
//! These are retention budgets, not a process-memory limit.
//!
//! Recording takes the event the caller built, looks up the task that
//! recorded it, and appends it to the log under one lock. Each subscription
//! queues replay and live events in sequence order. One caller drains that
//! queue, invoking callbacks one at a time outside the log and delivery locks.
//! Reentrant or concurrent recording leaves queued callbacks to the active
//! drainer, which may run in a different task or thread from the recorder.
//! Callbacks must return quickly and never block. See [`EventLog::subscribe`].
//! The `sites` group of the performance suite (`cargo bench
//! --bench perf -- sites`) measures the cost on HTTPS requests, which
//! record one `http.request` event each. On a busy 24-core machine, a
//! median of three runs took 9.5 µs of CPU per HTTP/1.1 request from ten
//! sandboxes, against 7.9 µs before every run kept its events, and 12.9 µs
//! per HTTP/2 request against 11.5 µs. Most of it is building the event:
//! its headers and fields are about 25 allocations.
//!
//! # Why "event"
//!
//! Fictionet used to call one thing four names: the journal's entries,
//! the graph's notes, the dashboard's "Events", and custom events from
//! world code. They were the same fact (who saw what, when, from which
//! connection), so now they are one type with one name. "Event" is the
//! word the dashboard and world code already used, and it says what the
//! thing is: something that happened at a time. "Note" now means only a
//! line of a decoded packet's layer ([`Layer::note`]), and the log that
//! holds events is the event log.
//!
//! [bottleneck]: crate::stdlib::bottleneck
//! [router]: crate::stdlib::route::router
//! [`Cx::now`]: crate::Cx::now
//! [`Cx::record_repeat`]: crate::Cx::record_repeat
//! [`Layer::note`]: crate::observe::Layer::note

use fictionet::sync::Mutex;
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::sync::atomic::{AtomicU64, AtomicUsize};
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::sync::mpsc::{Receiver, sync_channel};

use crate::Cx;
use crate::stdlib::codec::Wire;
use crate::stdlib::json::Value;
use crate::time::Instant;

mod model;
mod repeat;
mod store;

pub(crate) use model::Origin;
pub use model::{ConnInfo, Event, Fields, Level, Sandbox, Transport, float, opt};
pub(crate) use store::Store;
use store::held;

/// Records that `source` dropped `packet`, and `why`, as a `drop` event
/// with the packet's addresses and protocol (a
/// [repeat](crate::events#repeats)). Its length, its destination port and
/// `detail` change with each packet, so they are its detail.
/// `enrich` adds context to the owned event before it is recorded.
pub fn record_drop<F>(
    fcx: &Cx,
    source: &'static str,
    packet: &crate::Packet,
    why: &'static str,
    detail: Fields,
    enrich: F,
) where
    F: FnOnce(Event) -> Event,
{
    let h = crate::stdlib::ip::Header::parse_truncated(&packet.0);
    let port = h.as_ref().and_then(|h| h.dst_port(&packet.0));
    let (src, dst) = match &h {
        Some(h) => (h.src.to_string(), h.dst.to_string()),
        None => ("?".to_owned(), "?".to_owned()),
    };
    let event = Event::new(source, "drop")
        .level(Level::Notice)
        .summary(format!("{src} → {dst}: {why}"))
        .field("src", opt(h.as_ref().map(|_| src)))
        .field("dst", opt(h.as_ref().map(|_| dst)))
        .field("protocol", opt(h.as_ref().map(|h| u32::from(h.protocol))))
        .field("why", why);
    let mut all = Fields::new()
        .with("len", packet.0.len() as u64)
        .with("dst_port", opt(port.map(u32::from)));
    all.extend(detail);
    fcx.record_repeat(enrich(event), all);
}

/// How many events a run's log holds. Past this, the oldest are dropped.
pub const MAX_EVENTS: usize = 50_000;
/// How many bytes of events a run's log holds, as [`Event::size`] counts
/// them. Past this, the oldest are dropped. A larger event is not kept.
pub const MAX_EVENT_BYTES: usize = 16 << 20;
/// How many [repeats](self#repeats) a run's log holds, beside its other
/// events. Past this, the oldest repeats are dropped.
pub const MAX_REPEATS: usize = 5_000;
/// How many bytes of [repeats](self#repeats) a run's log holds, beside its
/// other events. Past this, the oldest repeats are dropped. A larger
/// repeat is not kept.
pub const MAX_REPEAT_BYTES: usize = 2 << 20;
/// How many bytes open [repeat windows](self#repeats) hold, separately
/// from the recorded repeats. Counts close early to stay within this
/// budget. A repeat too large for a window is recorded individually.
pub const MAX_OPEN_REPEAT_BYTES: usize = 2 << 20;
/// How long, on the run's clock, repeats of an event are counted before
/// the log records their count. See [Repeats](self#repeats).
pub const REPEAT_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
/// How many events may wait for a file's writer thread.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
const FILE_QUEUE: usize = 100_000;
/// How many retained event bytes may wait for a file's writer thread.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
const FILE_QUEUE_BYTES: usize = MAX_EVENT_BYTES;

/// A run's events. Cheap to clone, and still readable after the run is
/// over. Get one with [`Cx::events`](crate::Cx::events). See the
/// [module docs](self).
#[derive(Clone)]
pub struct EventLog {
    store: Arc<Store>,
}

impl std::fmt::Debug for EventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.store.state.lock();
        let held = s.events.events.len() + s.repeats.events.len();
        f.debug_struct("EventLog")
            .field("recorded", &s.last)
            .field("held", &held)
            .field("dropped", &s.dropped)
            .finish()
    }
}

impl EventLog {
    pub(crate) fn new(store: Arc<Store>) -> EventLog {
        EventLog { store }
    }

    /// The events recorded after number `after`, at most `max`, oldest
    /// first. Where the log no longer holds some of them, an
    /// `events.dropped` event stands in their place and counts them (field
    /// `count`), numbered as the last one missed, so the next call can go
    /// on from the last event returned.
    pub fn after(&self, after: u64, max: usize) -> Vec<Event> {
        self.store
            .after(after, max)
            .into_iter()
            .map(|e| (*e).clone())
            .collect()
    }

    /// Every event the log holds, oldest first, with an `events.dropped`
    /// event wherever some were dropped.
    pub fn all(&self) -> Vec<Event> {
        self.after(0, usize::MAX)
    }

    /// The events of `source`'s `kind` the log holds.
    pub fn of(&self, source: &str, kind: &str) -> Vec<Event> {
        let s = self.store.state.lock();
        held(&s, 0)
            .filter(|e| e.is(source, kind))
            .map(|e| (**e).clone())
            .collect()
    }

    /// The number of the last event recorded: how many there have been.
    pub fn recorded(&self) -> u64 {
        self.store.last()
    }

    /// How many events the log has evicted or rejected for its limits.
    pub fn dropped(&self) -> u64 {
        self.store.state.lock().dropped
    }

    /// Calls `f` with every event the log holds now, oldest first (with
    /// an `events.dropped` event wherever some were dropped), then with
    /// every event recorded from now on until the run is over, including
    /// events too large to retain. Replay and live events share one FIFO:
    /// `f` runs in sequence order, one call at a time, outside the log and
    /// delivery locks. Once the run is over, `f` gets only what the log holds.
    ///
    /// `f` may read, record, or subscribe to the same log. Reentrant or
    /// concurrent recording queues events for the caller already draining
    /// this subscription. Recording or subscribing may return before those
    /// callbacks finish. Callbacks can run in a different task or thread from
    /// the recorder; no helper thread is created for them. Different
    /// subscriptions may run concurrently. A callback panic propagates to the
    /// caller draining it. If the run ends while a callback is active, that
    /// caller still drains the events already queued for the subscription.
    ///
    /// `f` must return quickly and never block: hand the event to a channel
    /// that never waits.
    pub fn subscribe(&self, f: impl Fn(&Event) + Send + Sync + 'static) {
        self.subscribe_arc(Arc::new(move |event| f(event)));
    }

    /// Writes every event to `path` as JSON Lines ([`Event::to_json`]),
    /// with the same delivery policy as [`EventLog::to_writer`]: what the
    /// log holds now, then each event as it is recorded. The file is created,
    /// or emptied.
    #[cfg(feature = "std")]
    pub fn to_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        self.to_writer(Box::new(std::io::BufWriter::new(file)));
        Ok(())
    }

    /// Writes every event to `out` as JSON Lines. A native real run with
    /// `std` uses a thread that flushes whenever it has caught up. The run's
    /// end waits for the thread to write and flush every line. In browsers,
    /// labs and builds without `std`, each line is written and flushed
    /// synchronously in the subscription's drainer, without a writer thread.
    /// Replay and live lines follow sequence order, with the callback context
    /// described by [`EventLog::subscribe`]. Successful synchronous sinks lose
    /// no lines.
    ///
    /// A line is lost, and counted ([`EventLog::lost`]), when it does not
    /// fit in the thread's queue (100,000 events or 16 MiB of retained
    /// event data), or when `out` fails. After a queue overflow the file gets
    /// an `events.lost` line with the count so far. After a failed write or
    /// flush the thread writes nothing more, and counts every line after
    /// it, and each line written since the last flush that worked, as
    /// lost. A grader throws away a sample with any line lost.
    pub fn to_writer(&self, out: Box<dyn Write + Send>) {
        if cfg!(target_arch = "wasm32")
            || !cfg!(feature = "std")
            || self.store.mode == crate::RunMode::Lab
        {
            let writer = Mutex::new(Some(out));
            let lost = self.store.lost.clone();
            self.subscribe(move |event| {
                let mut writer = writer.lock();
                let failed = match writer.as_mut() {
                    Some(out) => event.to_json().to_bytes().ok().is_none_or(|mut line| {
                        line.push(b'\n');
                        out.write_all(&line).and_then(|()| out.flush()).is_err()
                    }),
                    None => true,
                };
                if failed {
                    *writer = None;
                    lost.fetch_add(1, Ordering::Relaxed);
                }
            });
            #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
            return;
        }

        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            let (tx, rx) = sync_channel::<Arc<Event>>(FILE_QUEUE);
            let queued = Arc::new(AtomicUsize::new(0));
            let lost = self.store.lost.clone();
            let writer = {
                let (lost, queued) = (lost.clone(), queued.clone());
                std::thread::Builder::new()
                    .name("fictionet-events".into())
                    .spawn(move || write_lines(rx, out, &lost, &queued))
                    .expect("the event writer's thread starts")
            };
            self.subscribe_arc(Arc::new(move |event| {
                let len = event.size();
                if queued.fetch_add(len, Ordering::Relaxed) + len > FILE_QUEUE_BYTES
                    || tx.try_send(event.clone()).is_err()
                {
                    queued.fetch_sub(len, Ordering::Relaxed);
                    lost.fetch_add(1, Ordering::Relaxed);
                }
            }));
            let mut s = self.store.state.lock();
            if s.closed {
                // The run is over: the thread has all it will get.
                drop(s);
                let _ = writer.join();
            } else {
                s.writers.push(writer);
            }
        }
    }

    /// How many lines file writers lost: lines that did not fit in a
    /// writer's queue, or that a writer could not write.
    pub fn lost(&self) -> u64 {
        self.store.lost.load(Ordering::Relaxed)
    }

    /// Records the `run.start` event that anchors the run's clock. It is
    /// dated at the start of the run (`at` 0), and its `wall` field is the
    /// wall-clock time then, in seconds since the Unix epoch, as the run
    /// noted it when it began (`null` where there is no wall clock, as in a
    /// browser or a lab), so a reader can put every event's `at` on a calendar.
    /// The `seed` field is the run's 32-byte seed as 64 lowercase hexadecimal
    /// digits. The `rng` field is `chacha20-v1`, identifying the algorithm and
    /// contiguous-byte consumption convention. `fields` add the world's own
    /// facts, such as the date the world says it is (`world_date`): the world owns its dates, and services take
    /// them from it, never from the host's clock.
    /// [`Net::start`](crate::stdlib::net::Net::start) calls this when it
    /// starts serving. Neither [`run`](crate::run) nor [`lab`](crate::lab)
    /// calls it. Worlds without `Net` call it explicitly, usually before
    /// recording other events. Each call records another event; it is not
    /// deduplicated. Its `at` is zero even if recorded later, while its
    /// sequence number follows the events already recorded.
    pub fn start(&self, fcx: &Cx, fields: Fields) {
        let wall = if cfg!(target_arch = "wasm32") || fcx.mode() == crate::RunMode::Lab {
            Value::Null
        } else {
            fcx.run
                .start_wall
                .duration_since(crate::sys::UNIX_EPOCH)
                .map_or(Value::Null, |d| float(d.as_secs_f64()))
        };
        let event = Event::new("run", "start")
            .summary("the run started")
            .fields(fields)
            .field("wall", wall)
            .field("seed", fcx.run.environment.seed.to_string())
            .field("rng", "chacha20-v1");
        fcx.record_at(Instant::ZERO, event);
    }

    /// Waits until `n` held events match `pick`, checking every 10 ms on
    /// the run's clock, for at most `limit`. Returns those events, or every
    /// match so far if the time ran out. Each check first records the
    /// counts of [repeats](self#repeats) that are due. Returns early with
    /// [`Cancelled`](crate::Cancelled) if `fcx`'s [region](Cx#regions) is
    /// cancelled. Cancellation is checked before inspecting events and
    /// before returning matches, even if `n` is zero or the deadline has
    /// arrived. The last sleep is shortened to the remaining time. A limit
    /// that overflows the clock's range has no deadline.
    ///
    /// Each check takes a snapshot of the held events, oldest first, then
    /// calls `pick` without holding the log's lock. The predicate may read
    /// or record events in the same log. Events recorded during a check
    /// are considered on the next check.
    pub async fn wait(
        &self,
        fcx: &Cx,
        n: usize,
        limit: std::time::Duration,
        mut pick: impl FnMut(&Event) -> bool,
    ) -> Result<Vec<Event>, crate::Cancelled> {
        let deadline = fcx.now().since_start().saturating_add(limit);
        loop {
            if fcx.is_cancelled() {
                return Err(crate::Cancelled);
            }
            self.store.advance(fcx.now());
            let events: Vec<Arc<Event>> = {
                let s = self.store.state.lock();
                held(&s, 0).cloned().collect()
            };
            let got: Vec<Event> = events
                .into_iter()
                .filter(|e| pick(e))
                .map(|e| (*e).clone())
                .collect();
            if fcx.is_cancelled() {
                return Err(crate::Cancelled);
            }
            let now = fcx.now().since_start();
            if got.len() >= n || now >= deadline {
                return Ok(got);
            }
            let next = now
                .saturating_add(std::time::Duration::from_millis(10))
                .min(deadline);
            fcx.sleep_until(Instant::from_since_start(next)).await?;
        }
    }
}

/// Writes the lines from `rx` to `out` until the run is over. After a
/// failed write or flush, only counts them as lost.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
fn write_lines(
    rx: Receiver<Arc<Event>>,
    mut out: Box<dyn Write + Send>,
    lost: &AtomicU64,
    queued: &AtomicUsize,
) {
    let mut reported = 0;
    // Lines written since the last flush that worked.
    let mut unflushed = 0u64;
    let mut failed = false;
    let mut batch = Vec::new();
    while let Ok(event) = rx.recv() {
        batch.push(event);
        batch.extend(rx.try_iter());
        for event in batch.drain(..) {
            queued.fetch_sub(event.size(), Ordering::Relaxed);
            if failed {
                lost.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Ok(mut line) = event.to_json().to_bytes() else {
                lost.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            line.push(b'\n');
            if out.write_all(&line).is_ok() {
                unflushed += 1;
            } else {
                lost.fetch_add(unflushed + 1, Ordering::Relaxed);
                failed = true;
            }
        }
        if !failed {
            failed = finish_batch(&mut out, lost, &mut reported, &mut unflushed);
        }
    }
    if !failed {
        finish_batch(&mut out, lost, &mut reported, &mut unflushed);
    }
}

/// Writes an `events.lost` line if more were lost since the last, then
/// flushes. Returns whether that failed, counting the unflushed lines as
/// lost if so.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
fn finish_batch(
    out: &mut Box<dyn Write + Send>,
    lost: &AtomicU64,
    reported: &mut u64,
    unflushed: &mut u64,
) -> bool {
    let n = lost.load(Ordering::Relaxed);
    let report =
        format!("{{\"source\":\"events\",\"kind\":\"lost\",\"fields\":{{\"count\":{n}}}}}\n");
    let ok = (n == *reported || out.write_all(report.as_bytes()).is_ok()) && out.flush().is_ok();
    *reported = n;
    if ok {
        *unflushed = 0;
    } else {
        lost.fetch_add(*unflushed, Ordering::Relaxed);
    }
    !ok
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// An event's JSON says whether its connection was TLS, and its ALPN.
    #[test]
    fn json_names_tls_and_alpn() {
        let addr = SocketAddr::from(([10, 0, 0, 2], 443));
        let plain = Event::new("http", "request").conn(&ConnInfo::new(1, addr, addr));
        let line = plain.to_line();
        assert!(
            line.contains(r#""tls":false,"sni":null,"alpn":null"#),
            "{line}"
        );
        let tls = Event::new("http", "request")
            .conn(&ConnInfo::new(1, addr, addr).over_tls(Some("a.test"), Some(b"h2")));
        let line = tls.to_line();
        assert!(
            line.contains(r#""tls":true,"sni":"a.test","alpn":"h2""#),
            "{line}"
        );
    }

    /// A shared buffer a test writes events into, slowly, or failing after
    /// some lines.
    #[derive(Clone, Default)]
    pub(super) struct Sink {
        pub(super) bytes: Arc<Mutex<Vec<u8>>>,
        fail_after: Option<usize>,
        slow: bool,
    }

    impl Write for Sink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            let mut bytes = self.bytes.lock();
            if self
                .fail_after
                .is_some_and(|n| bytes.iter().filter(|b| **b == b'\n').count() >= n)
            {
                return Err(std::io::Error::other("the disk is full"));
            }
            if self.slow {
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            bytes.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn writer_queue_counts_retained_event_bytes() {
        let sink = Sink::default();
        let out = sink.clone();
        crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
            fcx.events().to_writer(Box::new(out));
            let mut summary = String::with_capacity(FILE_QUEUE_BYTES + 1);
            summary.push('x');
            fcx.record(Event::new("test", "large_capacity").summary(summary));
            assert_eq!(fcx.events().lost(), 1);
            Ok(())
        }))
        .unwrap();
        let bytes = sink.bytes.lock();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("large_capacity"));
        assert!(text.contains("lost"));
    }

    /// The run's end waits for a file writer to write every line.
    #[test]
    fn the_run_waits_for_its_file_writer() {
        let sink = Sink {
            slow: true,
            ..Sink::default()
        };
        let out = sink.clone();
        let kept = Arc::new(Mutex::new(None));
        let keep = kept.clone();
        crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
            fcx.events().to_writer(Box::new(out));
            for i in 0..500u32 {
                fcx.record(Event::new("test", "tick").field("i", i));
            }
            *keep.lock() = Some(fcx.events());
            Ok(())
        }))
        .unwrap();
        let log = kept.lock().take().unwrap();
        let lines = sink.bytes.lock().iter().filter(|b| **b == b'\n').count();
        assert_eq!((lines, log.lost()), (500, 0));
    }

    /// A write that fails is counted as lost, with every line after it.
    #[test]
    fn a_failed_write_is_counted_as_lost() {
        let sink = Sink {
            fail_after: Some(100),
            ..Sink::default()
        };
        let out = sink.clone();
        let kept = Arc::new(Mutex::new(None));
        let keep = kept.clone();
        crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
            fcx.events().to_writer(Box::new(out));
            for i in 0..300u32 {
                fcx.record(Event::new("test", "tick").field("i", i));
            }
            *keep.lock() = Some(fcx.events());
            Ok(())
        }))
        .unwrap();
        let log = kept.lock().take().unwrap();
        let lines = sink.bytes.lock().iter().filter(|b| **b == b'\n').count() as u64;
        // Lines written but not yet flushed when the write failed count as
        // lost too: they may not have reached the file.
        assert_eq!(lines, 100);
        assert!(
            log.lost() >= 200 && lines + log.lost() >= 300,
            "{}",
            log.lost()
        );
    }

    /// Events are recorded with no reader at all, numbered and dated on
    /// the run's clock, with the task that recorded them.
    #[test]
    fn every_run_records_its_events() {
        crate::block_on(crate::run(fictionet::Seed::random(), |fcx| async move {
            assert!(!fcx.observed());
            fcx.record(Event::new("world", "hello").field("n", 1u32));
            fcx.sleep(std::time::Duration::from_millis(5)).await?;
            fcx.record(Event::new("world", "hello").field("n", 2u32));
            let events = fcx.events().all();
            assert_eq!(events.len(), 2);
            assert_eq!((events[0].seq, events[1].seq), (1, 2));
            assert!(events[0].at < events[1].at && events[1].at <= fcx.now());
            assert_eq!(
                events[0].origin.as_ref().map(|o| o.task),
                Some(1),
                "the world function is the first task"
            );
            let json = events[1].to_line();
            assert!(
                json.contains(r#""source":"world","kind":"hello""#)
                    && json.contains(r#""node":"t1""#),
                "{json}"
            );
            Ok(())
        }))
        .unwrap();
    }
}
