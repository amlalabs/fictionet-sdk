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

use fictionet::sync::{Mutex, MutexGuard};
use std::collections::{HashMap, VecDeque};
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;
use std::sync::Arc;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::sync::mpsc::{Receiver, sync_channel};

use crate::Cx;
use crate::stdlib::codec::Wire;
use crate::stdlib::json::Value;
use crate::time::Instant;

mod model;
mod repeat;

pub(crate) use model::Origin;
pub use model::{ConnInfo, Event, Fields, Level, Sandbox, Transport, float, opt};
use repeat::{RepeatKey, Window};

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
/// How many runs of repeats are counted at once. Past this, the oldest
/// count is recorded early.
const OPEN_WINDOWS: usize = 1024;

/// A callback given to [`EventLog::subscribe`].
type Subscriber = Arc<dyn Fn(&Arc<Event>) + Send + Sync>;

/// A subscriber and the events waiting for it, delivered in order.
struct Subscription {
    f: Subscriber,
    delivery: Mutex<Delivery>,
}

/// The events queued for a subscriber, and whether a caller is draining
/// them.
#[derive(Default)]
struct Delivery {
    pending: VecDeque<Arc<Event>>,
    draining: bool,
}

/// Releases the drainer if a callback unwinds. The panic still propagates.
struct Drainer<'a> {
    delivery: &'a Mutex<Delivery>,
    active: bool,
}

impl Drop for Drainer<'_> {
    fn drop(&mut self) {
        if self.active {
            self.delivery.lock().draining = false;
        }
    }
}

impl Subscription {
    /// Called with the store locked, so replay and live events share its order.
    fn enqueue(&self, events: &[Arc<Event>]) {
        self.delivery.lock().pending.extend(events.iter().cloned());
    }

    fn drain(&self) {
        let mut delivery = self.delivery.lock();
        if delivery.draining {
            return;
        }
        delivery.draining = true;
        let mut drainer = Drainer {
            delivery: &self.delivery,
            active: true,
        };
        loop {
            let Some(event) = delivery.pending.pop_front() else {
                // Release ownership while locked, before another caller can take it.
                delivery.draining = false;
                drainer.active = false;
                return;
            };
            drop(delivery);
            (self.f)(&event);
            delivery = self.delivery.lock();
        }
    }
}

/// How many events may wait for a file's writer thread.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
const FILE_QUEUE: usize = 100_000;
/// How many retained event bytes may wait for a file's writer thread.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
const FILE_QUEUE_BYTES: usize = MAX_EVENT_BYTES;

/// What a run's log holds.
pub(crate) struct Store {
    mode: crate::RunMode,
    state: Mutex<State>,
    /// Lines file sinks could not keep up with, or could not write.
    lost: Arc<AtomicU64>,
}

/// One bounded part of the log: its events, oldest first.
struct Part {
    events: VecDeque<Arc<Event>>,
    bytes: usize,
    max: usize,
    max_bytes: usize,
}

impl Part {
    fn new(max: usize, max_bytes: usize) -> Part {
        Part {
            events: VecDeque::new(),
            bytes: 0,
            max,
            max_bytes,
        }
    }

    /// Keeps `event`, of `size` bytes, and drops the oldest past the
    /// bounds. Rejects an event that cannot fit by itself. Returns how
    /// many it dropped or rejected.
    fn push(&mut self, event: Arc<Event>, size: usize) -> u64 {
        if self.max == 0 || size > self.max_bytes {
            return 1;
        }
        self.events.push_back(event);
        self.bytes += size;
        let mut dropped = 0;
        while self.events.len() > self.max || self.bytes > self.max_bytes {
            let Some(old) = self.events.pop_front() else {
                break;
            };
            self.bytes -= old.size();
            dropped += 1;
        }
        dropped
    }
}

struct State {
    /// Every event but repeats.
    events: Part,
    repeats: Part,
    /// The number of the last event recorded.
    last: u64,
    /// How many events were dropped for the limits.
    dropped: u64,
    /// The latest time an event was recorded at.
    clock: Instant,
    /// The runs of repeats being counted.
    open: HashMap<Arc<RepeatKey>, Window>,
    /// Bytes charged to open keys and windows, apart from either history.
    open_bytes: usize,
    max_open_bytes: usize,
    /// The same, oldest first, each with when its count is due.
    due: VecDeque<(Instant, Arc<RepeatKey>)>,
    /// Shared, so recording takes a reference count, not a copy.
    subscribers: Arc<[Arc<Subscription>]>,
    /// Whether the run is over.
    closed: bool,
    /// The file writers' threads, joined when the run is over.
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    writers: Vec<std::thread::JoinHandle<()>>,
}

impl State {
    /// Numbers and keeps `event`, adding it to `out` for subscribers.
    fn keep(&mut self, mut event: Event, repeat: bool, out: &mut Vec<Arc<Event>>) {
        self.last += 1;
        event.seq = self.last;
        let size = event.size();
        let event = Arc::new(event);
        let part = if repeat {
            &mut self.repeats
        } else {
            &mut self.events
        };
        self.dropped += part.push(event.clone(), size);
        if !self.subscribers.is_empty() {
            out.push(event);
        }
    }

    /// Moves the clock to `at`, recording the counts that are due by then.
    fn advance(&mut self, at: Instant, out: &mut Vec<Arc<Event>>) {
        self.clock = self.clock.max(at);
        while self.due.front().is_some_and(|(due, _)| *due <= self.clock) {
            self.close_oldest(out);
        }
    }

    /// Records the count of the oldest run of repeats, and forgets it.
    fn close_oldest(&mut self, out: &mut Vec<Arc<Event>>) {
        let Some((_, key)) = self.due.pop_front() else {
            return;
        };
        if let Some(window) = self.open.remove(&key) {
            self.open_bytes -= key.size() + window.size();
            if let Some(event) = window.summary() {
                self.keep(event, true, out);
            }
        }
    }
}

impl Store {
    pub(crate) fn new(mode: crate::RunMode) -> Arc<Store> {
        Arc::new(Store {
            mode,
            state: Mutex::new(State {
                events: Part::new(MAX_EVENTS, MAX_EVENT_BYTES),
                repeats: Part::new(MAX_REPEATS, MAX_REPEAT_BYTES),
                last: 0,
                dropped: 0,
                clock: Instant::ZERO,
                open: HashMap::new(),
                open_bytes: 0,
                max_open_bytes: MAX_OPEN_REPEAT_BYTES,
                due: VecDeque::new(),
                subscribers: Arc::new([]),
                closed: false,
                #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
                writers: Vec::new(),
            }),
            lost: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Numbers `event`, keeps it, and calls the subscribers.
    pub(crate) fn push(&self, event: Event) {
        let mut out = Vec::new();
        let mut s = self.state.lock();
        s.advance(event.at, &mut out);
        s.keep(event, false, &mut out);
        Store::tell(s, &out);
    }

    /// Keeps `event` as a repeat, or counts it. See
    /// [Repeats](self#repeats).
    pub(crate) fn push_repeat(&self, mut event: Event, detail: Fields) {
        let key = RepeatKey {
            source: event.source,
            kind: event.kind,
            conn: std::mem::take(&mut event.conn),
            fields: std::mem::take(&mut event.fields),
        };
        let mut out = Vec::new();
        let mut s = self.state.lock();
        s.advance(event.at, &mut out);
        loop {
            let available = s.max_open_bytes - s.open_bytes;
            let Some(window) = s.open.get_mut(&key) else {
                break;
            };
            let before = window.ranges_size();
            if window.add(event.at, &detail, available) {
                let growth = window.ranges_size() - before;
                s.open_bytes += growth;
                Store::tell(s, &out);
                return;
            }
            s.close_oldest(&mut out);
        }
        event.conn = key.conn.clone();
        event.fields = key.fields.clone();
        let first = Window {
            first: event.clone(),
            count: 0,
            last: event.at,
            ranges: Vec::new(),
        };
        let size = key.size() + first.size();
        if size <= s.max_open_bytes {
            while s.open.len() >= OPEN_WINDOWS || s.open_bytes + size > s.max_open_bytes {
                s.close_oldest(&mut out);
            }
            let key = Arc::new(key);
            let due = s.clock + REPEAT_WINDOW;
            s.open_bytes += size;
            s.open.insert(key.clone(), first);
            s.due.push_back((due, key));
        }
        event.fields.extend(detail);
        event.fields.set("count", 1u64);
        s.keep(event, true, &mut out);
        Store::tell(s, &out);
    }

    /// Moves the log's clock to `at`, recording the counts of repeats due
    /// by then.
    pub(crate) fn advance(&self, at: Instant) {
        let mut out = Vec::new();
        let mut s = self.state.lock();
        s.advance(at, &mut out);
        Store::tell(s, &out);
    }

    /// Calls the subscribers with `events`, once `s` is unlocked.
    fn tell(s: MutexGuard<'_, State>, events: &[Arc<Event>]) {
        if s.subscribers.is_empty() || events.is_empty() {
            return;
        }
        let subscribers = s.subscribers.clone();
        for subscription in subscribers.iter() {
            subscription.enqueue(events);
        }
        drop(s);
        for subscription in subscribers.iter() {
            subscription.drain();
        }
    }

    /// The number of the last event recorded.
    pub(crate) fn last(&self) -> u64 {
        self.state.lock().last
    }

    /// Ends the log with the run: records every count of repeats still
    /// open, forgets the subscribers, and waits for the file writers to
    /// write everything.
    pub(crate) fn close(&self) {
        let mut out = Vec::new();
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        let writers;
        let subscribers = {
            let mut s = self.state.lock();
            while !s.due.is_empty() {
                s.close_oldest(&mut out);
            }
            s.closed = true;
            #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
            {
                writers = std::mem::take(&mut s.writers);
            }
            for subscription in s.subscribers.iter() {
                subscription.enqueue(&out);
            }
            std::mem::replace(&mut s.subscribers, Arc::new([]))
        };
        for subscription in subscribers.iter() {
            subscription.drain();
        }
        // The writers end once their senders, in the subscribers, are gone.
        drop(subscribers);
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        for writer in writers {
            let _ = writer.join();
        }
    }

    /// The events after number `after`, at most `max`, oldest first, with
    /// an `events.dropped` event wherever some of them are gone.
    pub(crate) fn after(&self, after: u64, max: usize) -> Vec<Arc<Event>> {
        let s = self.state.lock();
        after_locked(&s, after, max)
    }
}

/// The events held after number `after`, in order: the two parts merged.
fn held(s: &State, after: u64) -> impl Iterator<Item = &Arc<Event>> {
    let a = s.events.events.partition_point(|e| e.seq <= after);
    let b = s.repeats.events.partition_point(|e| e.seq <= after);
    let mut a = s.events.events.range(a..).peekable();
    let mut b = s.repeats.events.range(b..).peekable();
    std::iter::from_fn(move || match (a.peek(), b.peek()) {
        (Some(x), Some(y)) if y.seq < x.seq => b.next(),
        (Some(_), _) => a.next(),
        (None, _) => b.next(),
    })
}

fn after_locked(s: &State, after: u64, max: usize) -> Vec<Arc<Event>> {
    let mut out = Vec::new();
    let mut next = after + 1;
    for e in held(s, after) {
        if e.seq > next {
            if out.len() >= max {
                return out;
            }
            out.push(Arc::new(Event::dropped(e.seq - 1, e.at, e.seq - next)));
        }
        if out.len() >= max {
            return out;
        }
        out.push(e.clone());
        next = e.seq + 1;
    }
    if next <= s.last && out.len() < max {
        out.push(Arc::new(Event::dropped(s.last, s.clock, s.last + 1 - next)));
    }
    out
}

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

    fn subscribe_arc(&self, f: Subscriber) {
        let subscription = Arc::new(Subscription {
            f,
            delivery: Mutex::default(),
        });
        {
            let mut s = self.store.state.lock();
            subscription.enqueue(&after_locked(&s, 0, usize::MAX));
            if !s.closed {
                let mut all: Vec<_> = s.subscribers.iter().cloned().collect();
                all.push(subscription.clone());
                s.subscribers = all.into();
            }
        }
        subscription.drain();
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
    use super::model::{ARC_COUNTS, heap};
    use super::*;
    use std::borrow::Cow;
    use std::net::SocketAddr;

    fn numbered(store: &Store, n: u64) {
        for i in 0..n {
            store.push(Event::new("test", "tick").field("i", i));
        }
    }

    /// The log keeps the latest events, and a reader that fell behind gets
    /// one `events.dropped` event counting what it missed.
    #[test]
    fn the_oldest_events_go_first_and_readers_are_told() {
        let store = Store::new(crate::RunMode::Real);
        let total = MAX_EVENTS as u64 + 10;
        numbered(&store, total);
        let log = EventLog::new(store.clone());
        let held = store.state.lock().events.events.len() as u64;
        assert!(held <= MAX_EVENTS as u64 && store.state.lock().events.bytes <= MAX_EVENT_BYTES);
        let gone = total - held;
        assert!(gone >= 10);
        assert_eq!((log.dropped(), log.recorded()), (gone, total));
        let first = log.after(0, 3);
        assert!(first[0].is("events", "dropped"));
        assert_eq!((first[0].seq, first[0].u64("count")), (gone, Some(gone)));
        assert_eq!((first[1].seq, first[2].seq), (gone + 1, gone + 2));
        // A reader that goes on from the last event it saw misses nothing.
        assert_eq!(log.after(gone + 2, 1)[0].seq, gone + 3);
        // One that read up to the 5th is told it missed the rest of those
        // dropped.
        let late = log.after(5, 2);
        assert_eq!(
            (late[0].seq, late[0].u64("count"), late[1].seq),
            (gone, Some(gone - 5), gone + 1)
        );
        assert!(log.after(total, 10).is_empty());
        assert_eq!(log.all().len() as u64, held + 1);
    }

    #[test]
    fn the_byte_limit_holds() {
        let store = Store::new(crate::RunMode::Real);
        let big = "x".repeat(1 << 20);
        for _ in 0..40 {
            store.push(Event::new("test", "big").summary(big.clone()));
        }
        let s = store.state.lock();
        assert!(s.events.bytes <= MAX_EVENT_BYTES, "{}", s.events.bytes);
        assert!(s.events.events.len() < 40 && s.dropped > 0);
    }

    #[test]
    fn small_limits_reject_without_evicting_and_accept_exact_fits() {
        let event = Arc::new(Event::new("test", "small"));
        let size = event.size();
        for (max, bytes) in [(0, size), (1, 0), (1, size - 1)] {
            let mut part = Part::new(max, bytes);
            assert_eq!(part.push(event.clone(), size), 1);
            assert!(part.events.is_empty());
            assert_eq!(part.bytes, 0);
        }
        let mut part = Part::new(2, size);
        assert_eq!(part.push(event.clone(), size), 0);
        let large = Arc::new(Event::new("test", "large").summary("x"));
        assert_eq!(part.push(large.clone(), large.size()), 1);
        assert!(Arc::ptr_eq(&part.events[0], &event));
        assert_eq!(part.bytes, size);
        assert_eq!(part.push(event.clone(), size), 1);
        assert_eq!((part.events.len(), part.bytes), (1, size));
    }

    #[test]
    fn oversized_events_leave_gaps_but_reach_live_subscribers() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let live = seen.clone();
        log.subscribe(move |e| live.lock().push((e.seq, e.kind)));
        for repeat in [false, true] {
            let oversized = Event::new("test", "oversized").summary("x".repeat(if repeat {
                MAX_REPEAT_BYTES
            } else {
                MAX_EVENT_BYTES
            }));
            for event in [
                oversized.clone(),
                Event::new("test", "before"),
                oversized.clone(),
                Event::new("test", "after"),
                oversized,
            ] {
                if repeat {
                    store.push_repeat(event, Fields::new());
                } else {
                    store.push(event);
                }
            }
        }
        assert_eq!((log.recorded(), log.dropped()), (10, 6));
        assert_eq!(
            seen.lock().iter().map(|e| e.0).collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
        assert_eq!(seen.lock().iter().filter(|e| e.1 == "oversized").count(), 6);
        let all = log.all();
        assert_eq!(
            all.iter()
                .map(|e| (e.seq, e.u64("count")))
                .collect::<Vec<_>>(),
            [
                (1, Some(1)),
                (2, None),
                (3, Some(1)),
                (4, None),
                (6, Some(2)),
                (7, Some(1)),
                (8, Some(1)),
                (9, Some(1)),
                (10, Some(1))
            ]
        );
        let mut after = 0;
        for expected in &all {
            let page = log.after(after, 1);
            assert_eq!(&page[0], expected);
            after = page[0].seq;
        }
        assert!(log.after(after, 1).is_empty());
        store.close();
        let replay = Arc::new(Mutex::new(Vec::new()));
        let late = replay.clone();
        log.subscribe(move |e| late.lock().push(e.clone()));
        assert_eq!(*replay.lock(), all);
        assert_eq!(log.all(), all, "the closed log keeps its gaps");
    }

    #[test]
    fn metadata_is_charged_even_when_shared() {
        let mut event = Event::new("test", "metadata");
        let empty = event.size();
        let name: Arc<str> = "x".repeat(MAX_EVENT_BYTES / 2).into();
        event.conn = ConnInfo {
            sandbox: Some(Sandbox {
                id: 1,
                name: name.clone(),
                addr: None,
                addr_v6: None,
            }),
            sni: Some(name),
            alpn: Some(Arc::from(&b"h2"[..])),
            ..ConnInfo::default()
        };
        assert_eq!(
            event.size() - empty,
            2 * heap(ARC_COUNTS + MAX_EVENT_BYTES / 2) + heap(ARC_COUNTS + 2)
        );
        assert_eq!(event.clone().size(), event.size());
        let metadata = event.size();
        event.origin = Some(Origin {
            task: 1,
            name: Cow::Borrowed("static"),
            file: file!(),
            line: line!(),
            parent: 0,
        });
        assert_eq!(event.size(), metadata);
        let mut name = String::with_capacity(4096);
        name.push('x');
        let charged = heap(name.capacity());
        event.origin.as_mut().unwrap().name = Cow::Owned(name);
        assert_eq!(event.size(), metadata + charged);
        let store = Store::new(crate::RunMode::Lab);
        store.push(event);
        let s = store.state.lock();
        assert_eq!((s.events.bytes, s.dropped), (0, 1));
        assert!(s.events.events.is_empty());
    }

    /// A subscriber set late gets what the log holds, then what follows.
    #[test]
    fn subscribers_replay_then_follow() {
        let store = Store::new(crate::RunMode::Real);
        numbered(&store, 3);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        log.subscribe(move |e| s.lock().push(e.seq));
        numbered(&store, 2);
        assert_eq!(*seen.lock(), [1, 2, 3, 4, 5]);
        store.close();
        numbered(&store, 1);
        assert_eq!(seen.lock().len(), 5, "a closed log calls no one");
    }

    #[test]
    fn reentrant_recording_follows_the_rest_of_replay() {
        let store = Store::new(crate::RunMode::Lab);
        numbered(&store, 2);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let recording = store.clone();
        log.subscribe(move |event| {
            if event.seq == 1 {
                numbered(&recording, 1);
            }
            out.lock().push(event.seq);
        });
        store.close();
        assert_eq!(*seen.lock(), [1, 2, 3]);
    }

    #[test]
    fn reentrant_recording_reaches_each_subscriber_in_order() {
        for mode in [crate::RunMode::Lab, crate::RunMode::Real] {
            let store = Store::new(mode);
            let log = EventLog::new(store.clone());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let first = seen.clone();
            let recording = store.clone();
            log.subscribe(move |event| {
                if event.seq == 3 {
                    numbered(&recording, 1);
                }
                first.lock().push(event.seq);
            });
            numbered(&store, 2);
            let followed = Arc::new(Mutex::new(Vec::new()));
            let second = followed.clone();
            log.subscribe(move |event| second.lock().push(event.seq));
            let sink = Sink::default();
            log.to_writer(Box::new(sink.clone()));
            numbered(&store, 1);
            store.close();
            assert_eq!(*seen.lock(), [1, 2, 3, 4]);
            assert_eq!(*followed.lock(), [1, 2, 3, 4]);
            let expected: String = log
                .all()
                .iter()
                .map(|event| event.to_line() + "\n")
                .collect();
            assert_eq!(*sink.bytes.lock(), expected.as_bytes());
            assert_eq!(log.lost(), 0);
        }
    }

    #[test]
    fn reentrant_recording_follows_all_due_repeat_summaries() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let recording = store.clone();
        log.subscribe(move |event| {
            if event.seq == 3 {
                numbered(&recording, 1);
            }
            out.lock().push(event.seq);
        });
        for dst in ["192.0.2.1", "192.0.2.2"] {
            refused(&store, 0, dst, 1);
            refused(&store, 0, dst, 2);
        }
        store.advance(Instant::ZERO + REPEAT_WINDOW);
        store.close();
        assert_eq!(*seen.lock(), [1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_panicking_callback_releases_its_drainer() {
        let store = Store::new(crate::RunMode::Lab);
        numbered(&store, 2);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            log.subscribe(move |event| {
                assert_ne!(event.seq, 1, "callback panic");
                out.lock().push(event.seq);
            });
        }));
        assert!(result.is_err());
        numbered(&store, 1);
        store.close();
        assert_eq!(*seen.lock(), [2, 3]);
    }

    #[test]
    fn concurrent_recording_queues_behind_replay_and_live_callbacks() {
        for replay in [false, true] {
            let store = Store::new(crate::RunMode::Lab);
            let log = EventLog::new(store.clone());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let out = seen.clone();
            let (entered, started) = std::sync::mpsc::channel();
            let (release, resume) = std::sync::mpsc::channel();
            let resume = Mutex::new(resume);
            let callback = move |event: &Event| {
                if event.seq == 1 {
                    entered.send(()).unwrap();
                    resume.lock().recv().unwrap();
                }
                out.lock().push((event.seq, std::thread::current().id()));
            };
            let drainer = if replay {
                numbered(&store, 2);
                std::thread::spawn(move || log.subscribe(callback))
            } else {
                log.subscribe(callback);
                let recording = store.clone();
                std::thread::spawn(move || numbered(&recording, 1))
            };
            let thread = drainer.thread().id();
            started.recv().unwrap();
            numbered(&store, 1);
            let waiting = seen.lock().is_empty();
            release.send(()).unwrap();
            drainer.join().unwrap();
            store.close();
            assert!(waiting, "recording returns while its callback is queued");
            let last = if replay { 3 } else { 2 };
            let expected: Vec<_> = (1..=last).map(|seq| (seq, thread)).collect();
            assert_eq!(*seen.lock(), expected);
        }
    }

    #[test]
    fn closing_queues_repeat_summaries_behind_active_callbacks() {
        let store = Store::new(crate::RunMode::Lab);
        refused(&store, 0, "192.0.2.1", 1);
        refused(&store, 0, "192.0.2.1", 2);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let (entered, started) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume);
        let drainer = std::thread::spawn(move || {
            log.subscribe(move |event| {
                if event.seq == 1 {
                    entered.send(()).unwrap();
                    resume.lock().recv().unwrap();
                }
                out.lock().push(event.seq);
            });
        });
        started.recv().unwrap();
        store.close();
        let waiting = seen.lock().is_empty();
        release.send(()).unwrap();
        drainer.join().unwrap();
        assert!(
            waiting,
            "closing queues the summary without overlapping callbacks"
        );
        assert_eq!(*seen.lock(), [1, 2]);
    }

    fn at(ms: u64) -> Instant {
        Instant::ZERO + std::time::Duration::from_millis(ms)
    }

    fn timed(mut event: Event, ms: u64) -> Event {
        event.at = at(ms);
        event
    }

    /// A refused packet, as the network records one: the port is detail.
    fn refused(store: &Store, ms: u64, dst: &str, port: u16) {
        let mut event = Event::new("net", "blocked")
            .summary(format!("to {dst}"))
            .field("why", "ClosedPort")
            .field("dst", dst);
        event.at = at(ms);
        store.push_repeat(event, Fields::new().with("dst_port", u32::from(port)));
    }

    /// The first of a run of alike repeats is recorded at once; the rest
    /// of its window are counted, and the count recorded when the window
    /// has passed.
    #[test]
    fn repeats_are_counted_once_a_window() {
        let store = Store::new(crate::RunMode::Real);
        let log = EventLog::new(store.clone());
        for port in 1..=1000 {
            refused(&store, u64::from(port / 10), "192.0.2.1", port);
        }
        refused(&store, 50, "192.0.2.2", 22);
        assert_eq!(log.recorded(), 2, "one event for each destination");
        // Within the window, nothing more.
        store.push(timed(Event::new("http", "request"), 500));
        assert_eq!(log.recorded(), 3);
        // Past it, the counts come first, then the event that came after.
        store.push(timed(Event::new("http", "request"), 1200));
        let all = log.all();
        let shown: Vec<_> = all
            .iter()
            .map(|e| {
                (
                    e.kind,
                    e.str("dst"),
                    e.u64("count"),
                    e.get("dst_port").cloned(),
                )
            })
            .collect();
        let ports = |lo: u64, hi: u64| Some(Value::Array(vec![lo.into(), hi.into()]));
        assert_eq!(
            shown,
            [
                (
                    "blocked",
                    Some("192.0.2.1"),
                    Some(1),
                    Some(Value::from(1u32))
                ),
                (
                    "blocked",
                    Some("192.0.2.2"),
                    Some(1),
                    Some(Value::from(22u32))
                ),
                ("request", None, None, None),
                ("blocked", Some("192.0.2.1"), Some(999), ports(2, 1000)),
                ("request", None, None, None),
            ]
        );
        assert_eq!(
            (all[3].at, all[3].summary.as_str()),
            (at(100), "999 more: to 192.0.2.1")
        );
        // A new window after the old one closed starts with a recorded one.
        refused(&store, 1300, "192.0.2.1", 7);
        assert_eq!(
            log.of("net", "blocked").last().and_then(|e| e.u64("count")),
            Some(1)
        );
        // The run's end records every count still open.
        refused(&store, 1301, "192.0.2.1", 8);
        store.close();
        assert_eq!(
            log.of("net", "blocked").last().and_then(|e| e.u64("count")),
            Some(1)
        );
        assert_eq!(log.of("net", "blocked").len(), 5);
    }

    fn assert_open_budget(store: &Store) {
        let s = store.state.lock();
        assert_eq!(s.open.len(), s.due.len());
        assert!(s.open.len() <= OPEN_WINDOWS);
        assert!(s.open_bytes <= s.max_open_bytes);
        assert_eq!(
            s.open_bytes,
            s.open
                .iter()
                .map(|(k, w)| k.size() + w.size())
                .sum::<usize>()
        );
    }

    #[test]
    fn large_distinct_repeat_keys_close_oldest_windows_early() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let live = seen.clone();
        log.subscribe(move |e| live.lock().push((e.u64("i"), e.u64("count"))));
        for i in 0..40u64 {
            let event = Event::new("test", "repeat")
                .field("key", "x".repeat(128 << 10))
                .field("i", i);
            store.push_repeat(event.clone(), Fields::new());
            store.push_repeat(event, Fields::new());
            assert_open_budget(&store);
        }
        assert!(store.state.lock().open.len() < 40);
        assert!(
            log.dropped() > 0,
            "history eviction does not free open keys"
        );
        store.close();
        assert_open_budget(&store);
        assert_eq!(store.state.lock().open_bytes, 0);
        let seen = seen.lock();
        for i in 0..40 {
            assert_eq!(
                seen.iter()
                    .filter(|e| e.0 == Some(i))
                    .map(|e| e.1.unwrap())
                    .sum::<u64>(),
                2
            );
        }
        // Every second occurrence is a summary. They close in insertion order.
        let mut first = [false; 40];
        let summaries: Vec<_> = seen
            .iter()
            .filter_map(|e| {
                let i = e.0.unwrap() as usize;
                std::mem::replace(&mut first[i], true).then_some(i)
            })
            .collect();
        assert_eq!(summaries, (0..40).collect::<Vec<_>>());
    }

    #[test]
    fn a_repeat_too_large_for_a_window_is_recorded_individually() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let event =
            Event::new("test", "repeat").field("key", "x".repeat(MAX_OPEN_REPEAT_BYTES / 2));
        assert!(event.size() < MAX_REPEAT_BYTES);
        for _ in 0..3 {
            store.push_repeat(event.clone(), Fields::new());
            assert_open_budget(&store);
            assert_eq!(store.state.lock().open_bytes, 0);
        }
        assert_eq!((log.recorded(), log.dropped()), (3, 2));
        assert_eq!(log.of("test", "repeat")[0].u64("count"), Some(1));
    }

    #[test]
    fn growing_repeat_ranges_close_windows_before_exceeding_the_budget() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let event = Event::new("test", "repeat");
        store.push_repeat(event.clone(), Fields::new());
        let base = store.state.lock().open_bytes;
        store.state.lock().max_open_bytes =
            base + heap(4 * std::mem::size_of::<(&str, u64, u64)>());
        for name in ["a", "b", "c", "d", "e"] {
            store.push_repeat(event.clone(), Fields::new().with(name, 7u64));
            assert_open_budget(&store);
        }
        let all = log.all();
        assert_eq!(
            all.iter()
                .map(|e| e.u64("count").unwrap())
                .collect::<Vec<_>>(),
            [1, 4, 1]
        );
        assert_eq!(
            all[1].get("d"),
            Some(&Value::Array(vec![7u64.into(), 7u64.into()]))
        );
        assert_eq!(all[2].u64("e"), Some(7));
        store.advance(at(1000));
        assert_open_budget(&store);
        assert_eq!(store.state.lock().open_bytes, 0);
    }

    /// Repeats have bounds of their own: a flood of them, more than the
    /// log holds, never pushes out another event, and a reader is told
    /// where repeats are gone.
    #[test]
    fn a_flood_of_repeats_never_pushes_out_other_events() {
        let store = Store::new(crate::RunMode::Real);
        let log = EventLog::new(store.clone());
        for i in 0..10u32 {
            store.push(Event::new("http", "request").field("i", i));
        }
        // Every packet to a new address: a new run each time.
        let flood = MAX_EVENTS as u64 + 10;
        for i in 0..flood {
            refused(
                &store,
                i,
                &format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
                1,
            );
            if i == flood / 2 {
                store.push(Event::new("dns", "query"));
            }
        }
        assert_eq!(log.of("http", "request").len(), 10);
        assert_eq!(log.of("dns", "query").len(), 1);
        let s = store.state.lock();
        assert!(s.repeats.events.len() <= MAX_REPEATS && s.repeats.bytes <= MAX_REPEAT_BYTES);
        assert!(s.open.len() <= OPEN_WINDOWS && s.due.len() == s.open.len());
        drop(s);
        // Every number is either an event or counted in an
        // `events.dropped` event, in order.
        let mut next = 1;
        for e in log.all() {
            let first = if e.is("events", "dropped") {
                e.seq + 1 - e.u64("count").unwrap()
            } else {
                e.seq
            };
            assert_eq!(first, next, "{e:?}");
            next = e.seq + 1;
        }
        assert_eq!(next, log.recorded() + 1);
        assert_eq!(
            log.dropped()
                + (log
                    .all()
                    .iter()
                    .filter(|e| !e.is("events", "dropped"))
                    .count() as u64),
            log.recorded()
        );
    }

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
    struct Sink {
        bytes: Arc<Mutex<Vec<u8>>>,
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
