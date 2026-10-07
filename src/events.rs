//! Events: everything a world reports about itself, kept by the run
//! whether or not anyone reads it.
//!
//! An [`Event`] is one fact: the source that saw it (`"dns"`, `"http"`,
//! `"lan"`, `"modbus"`), its kind (`"query"`, `"request"`, `"drop"`), a
//! one-line summary, a [`Level`], the connection it came from
//! ([`ConnInfo`]), and named [`Fields`] whose values are JSON. Services,
//! the network and the core's own pieces (a [bottleneck] that drops a
//! packet, a [router] that loses a route, a LAN, the TLS server keeping
//! session keys) all record events, and so can world code:
//!
//! ```
//! use fictionet::events::{Event, Level};
//! # fictionet::block_on(fictionet::run(|cx| async move {
//! cx.record(Event::new("modbus", "write_register")
//!     .summary("register 40001 = 900")
//!     .level(Level::Alarm)
//!     .field("register", 40001u32)
//!     .field("value", 900u32));
//! let events = cx.events().of("modbus", "write_register");
//! assert_eq!(events[0].u64("value"), Some(900));
//! # Ok(()) }))?;
//! # Ok::<(), fictionet::Error>(())
//! ```
//!
//! # The event log
//!
//! Every run keeps an [`EventLog`], from its first moment to its end,
//! with no sink to set. Recording numbers each event (`seq`, from 1, with
//! no gaps) and dates it on the run's clock ([`Cx::now`]), never the
//! host's, so two runs that do the same things record the same sequence.
//! The log is bounded: it holds the latest [`MAX_EVENTS`] events, and at
//! most [`MAX_EVENT_BYTES`] of them ([`Event::size`]). Past either limit the oldest go first,
//! and every reader that missed some is told how many, with one
//! `events.dropped` event in their place ([`EventLog::after`]).
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
//!   during the run or after it ([`EventLog::all`], [`EventLog::wait`],
//!   and [`scenario`](crate::stdlib::scenario) checks).
//!
//! A reader that starts late misses nothing the log still holds: a file
//! or a callback set halfway through a run first gets what the log kept,
//! then the rest as it is recorded.
//!
//! # What it costs
//!
//! Recording takes the event the caller built, looks up the task that
//! recorded it, and appends it to the log under one lock. Callbacks run
//! after that, in the task that recorded, so they must return quickly and
//! never block. The `sites` group of the performance suite (`cargo bench
//! --bench perf -- sites`) measures the cost on HTTPS requests, which
//! record one event each.
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
//! [`Layer::note`]: crate::observe::Layer::note

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::Cx;
use crate::stdlib::codec::Wire;
use crate::stdlib::json::{Number, Value};
use crate::time::Instant;

/// How many events a run's log holds. Past this, the oldest are dropped.
pub const MAX_EVENTS: usize = 50_000;
/// How many bytes of events a run's log holds, as [`Event::size`] counts
/// them. Past this, the oldest are dropped.
pub const MAX_EVENT_BYTES: usize = 16 << 20;

/// How much an event matters to the people and graders reading the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// An ordinary fact: a query, a request, a connection.
    #[default]
    Info,
    /// Worth a look: a refused handshake, a malformed request, a dropped
    /// packet.
    Notice,
    /// The fact a scenario watches for: a safety limit crossed, a password
    /// sent to the wrong host, a tool's false answer accepted.
    Alarm,
}

impl Level {
    /// `info`, `notice` or `alarm`.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Notice => "notice",
            Level::Alarm => "alarm",
        }
    }
}

/// Named values, in the order they were set. Setting a name again
/// replaces its value in place.
///
/// Names are `&'static str`, chosen by the code that records. Facts whose
/// names come from the wire, such as LDAP attributes or OpenAPI paths, go
/// under one name as a JSON object or array of pairs.
///
/// An HTTP handler adds fields to its request's event by putting `Fields`
/// in its response's extensions (see [`httpd`](crate::stdlib::httpd)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields(Vec<(&'static str, Value)>);

impl Fields {
    /// No fields.
    pub fn new() -> Fields {
        Fields(Vec::new())
    }

    /// No fields, with room for `n` before it grows.
    pub fn with_capacity(n: usize) -> Fields {
        Fields(Vec::with_capacity(n))
    }

    /// Sets `name`, keeping its place if it was set before.
    pub fn set(&mut self, name: &'static str, value: impl Into<Value>) {
        let value = value.into();
        match self.0.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = value,
            None => self.0.push((name, value)),
        }
    }

    /// [`set`](Self::set), as a builder.
    pub fn with(mut self, name: &'static str, value: impl Into<Value>) -> Fields {
        self.set(name, value);
        self
    }

    /// The value of `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    /// Removes `name`, returning its value.
    pub fn remove(&mut self, name: &str) -> Option<Value> {
        let at = self.0.iter().position(|(n, _)| *n == name)?;
        Some(self.0.remove(at).1)
    }

    /// Every field, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &Value)> {
        self.0.iter().map(|(n, v)| (*n, v))
    }

    /// Sets every field of `other`, in its order.
    pub fn extend(&mut self, other: Fields) {
        if self.0.is_empty() {
            self.0 = other.0;
            return;
        }
        for (n, v) in other.0 {
            self.set(n, v);
        }
    }

    /// How many fields there are.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The fields as one JSON object.
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.iter().map(|(n, v)| ((*n).to_owned(), v.clone())).collect())
    }
}

/// A JSON value for an optional fact: `null` when it is absent.
pub fn opt<T: Into<Value>>(value: Option<T>) -> Value {
    value.map_or(Value::Null, Into::into)
}

/// A JSON number for a float. `null` for NaN and the infinities, which
/// JSON cannot hold.
pub fn float(value: f64) -> Value {
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

/// A sandbox, as an event names it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sandbox {
    /// The attachment, numbered from 1 in the order sandboxes attached. A
    /// name and an address can be used again after a sandbox detaches; the
    /// id never is.
    pub id: u64,
    /// Its attachment's name.
    pub name: Arc<str>,
    /// Its IPv4 address, once bound.
    pub addr: Option<Ipv4Addr>,
    /// Its IPv6 address, once bound.
    pub addr_v6: Option<Ipv6Addr>,
}

impl Sandbox {
    /// The sandbox as JSON: `{"id", "name", "addr", "addr_v6"}`.
    pub fn to_json(&self) -> Value {
        Value::Object(vec![
            ("id".into(), self.id.into()),
            ("name".into(), (*self.name).into()),
            ("addr".into(), opt(self.addr.map(|a| a.to_string()))),
            ("addr_v6".into(), opt(self.addr_v6.map(|a| a.to_string()))),
        ])
    }
}

/// How a connection's bytes travel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Transport {
    /// A byte stream: TCP, or TLS over it.
    #[default]
    Tcp,
    /// Datagrams: UDP.
    Udp,
}

impl Transport {
    /// `tcp` or `udp`.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

/// Where an event came from: the connection and the sandbox behind it.
/// Every field is optional, since some events belong to no connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnInfo {
    /// The connection's number, from whoever accepted it. [`Net`]
    /// numbers its connections from 1, on every port.
    ///
    /// [`Net`]: crate::stdlib::net::Net
    pub id: Option<u64>,
    /// The sandbox the connection came from, as it was when it arrived.
    pub sandbox: Option<Sandbox>,
    /// The world's side: the address and port the connection arrived on.
    pub local: Option<SocketAddr>,
    /// The other side.
    pub peer: Option<SocketAddr>,
    /// Whether the bytes arrived over TLS.
    pub tls: bool,
    /// The name the client sent in its TLS hello, in lowercase.
    pub sni: Option<Arc<str>>,
    /// The protocol the TLS handshake agreed on, such as `h2`.
    pub alpn: Option<Arc<[u8]>>,
    /// TCP or UDP. A service served both ways, such as a Kerberos KDC,
    /// answers by it: a reply too big for a datagram asks the client to
    /// use TCP.
    pub transport: Transport,
}

impl ConnInfo {
    /// A connection with this number between `local` and `peer`.
    pub fn new(id: u64, local: SocketAddr, peer: SocketAddr) -> ConnInfo {
        ConnInfo { id: Some(id), local: Some(local), peer: Some(peer), ..ConnInfo::default() }
    }

    /// The same, from `sandbox`.
    pub fn from_sandbox(mut self, sandbox: Option<Sandbox>) -> ConnInfo {
        self.sandbox = sandbox;
        self
    }

    /// The same, over TLS with this SNI and ALPN.
    pub fn over_tls(mut self, sni: Option<&str>, alpn: Option<&[u8]>) -> ConnInfo {
        self.tls = true;
        self.sni = sni.map(Arc::from);
        self.alpn = alpn.map(Arc::from);
        self
    }
}

/// The task that recorded an event, kept with it since the task may end
/// before anyone reads the event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Origin {
    pub(crate) task: u64,
    /// The task's name, as the graph keeps it (shortened when shown).
    pub(crate) name: Cow<'static, str>,
    pub(crate) file: &'static str,
    pub(crate) line: u32,
    pub(crate) parent: u64,
}

/// One fact a world recorded. See the [module docs](self).
///
/// Build one with [`Event::new`] and the methods after it, and record it
/// with [`Cx::record`](crate::Cx::record). Recording sets
/// [`seq`](Self::seq), [`at`](Self::at) and the task that recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Its place in the run's log, from 1. 0 until it is recorded.
    pub seq: u64,
    /// When it happened, on the run's clock.
    pub at: Instant,
    /// What saw it: `"dns"`, `"http"`, `"lan"`, `"modbus"`.
    pub source: &'static str,
    /// What happened: `"query"`, `"request"`, `"drop"`.
    pub kind: &'static str,
    /// One line for people: the dashboard's list, a world's console.
    pub summary: String,
    /// How much it matters.
    pub level: Level,
    /// The connection it came from, if any.
    pub conn: ConnInfo,
    /// The facts a grader queries.
    pub fields: Fields,
    /// The task that recorded it.
    pub(crate) origin: Option<Origin>,
}

impl Event {
    /// An [`Info`](Level::Info) event with no summary, no connection and
    /// no fields.
    pub fn new(source: &'static str, kind: &'static str) -> Event {
        Event {
            seq: 0,
            at: Instant::ZERO,
            source,
            kind,
            summary: String::new(),
            level: Level::Info,
            conn: ConnInfo::default(),
            fields: Fields::new(),
            origin: None,
        }
    }

    /// Sets the summary.
    pub fn summary(mut self, summary: impl Into<String>) -> Event {
        self.summary = summary.into();
        self
    }

    /// Sets the level.
    pub fn level(mut self, level: Level) -> Event {
        self.level = level;
        self
    }

    /// Sets the connection it came from.
    pub fn conn(mut self, conn: &ConnInfo) -> Event {
        self.conn = conn.clone();
        self
    }

    /// Sets one field.
    pub fn field(mut self, name: &'static str, value: impl Into<Value>) -> Event {
        self.fields.set(name, value);
        self
    }

    /// Sets every field of `fields`.
    pub fn fields(mut self, fields: Fields) -> Event {
        self.fields.extend(fields);
        self
    }

    /// The value of the field `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.get(name)
    }

    /// The field `name` as text.
    pub fn str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Value::as_str)
    }

    /// The field `name` as a number.
    pub fn u64(&self, name: &str) -> Option<u64> {
        self.get(name).and_then(Value::as_u64)
    }

    /// Whether this is `source`'s `kind`.
    pub fn is(&self, source: &str, kind: &str) -> bool {
        self.source == source && self.kind == kind
    }

    /// About how many bytes the event holds in memory, each allocation's
    /// overhead included, as the log counts them against
    /// [`MAX_EVENT_BYTES`].
    pub fn size(&self) -> usize {
        let slot = std::mem::size_of::<(&str, Value)>();
        let fields = self.fields.0.capacity() * slot + self.fields.0.iter().map(|(_, v)| value_size(v)).sum::<usize>();
        ALLOC + std::mem::size_of::<Event>() + heap(self.summary.capacity()) + heap(fields)
    }

    /// The event as one JSON object: `seq`, `at` (seconds since the run
    /// started), `source`, `kind`, `level`, `summary`, then the connection
    /// (`sandbox`, `conn`, `local`, `peer`, `transport`, `sni`), then
    /// `fields`, then the task that recorded it, if known: `node` (its id
    /// in the observe graph, such as `"t7"`), `task` (its name), `file`,
    /// `line` and `parent` (the id of the task that started it).
    pub fn to_json(&self) -> Value {
        let c = &self.conn;
        let mut out = vec![
            ("seq".into(), self.seq.into()),
            ("at".into(), float(self.at.since_start().as_secs_f64())),
            ("source".into(), self.source.into()),
            ("kind".into(), self.kind.into()),
            ("level".into(), self.level.as_str().into()),
            ("summary".into(), self.summary.as_str().into()),
            ("sandbox".into(), c.sandbox.as_ref().map_or(Value::Null, Sandbox::to_json)),
            ("conn".into(), opt(c.id)),
            ("local".into(), opt(c.local.map(|a| a.to_string()))),
            ("peer".into(), opt(c.peer.map(|a| a.to_string()))),
            ("transport".into(), c.transport.as_str().into()),
            ("sni".into(), opt(c.sni.as_deref())),
            ("fields".into(), self.fields.to_json()),
        ];
        if let Some(o) = &self.origin {
            let id = |t: u64| if t == 0 { Value::Null } else { Value::String(format!("t{t}")) };
            out.push(("node".into(), id(o.task)));
            out.push(("task".into(), crate::watch::short_name(&o.name).into()));
            out.push(("file".into(), o.file.into()));
            out.push(("line".into(), o.line.into()));
            out.push(("parent".into(), id(o.parent)));
        }
        Value::Object(out)
    }

    /// [`to_json`](Self::to_json) as one line of text, with no newline.
    pub fn to_line(&self) -> String {
        let bytes = self.to_json().to_bytes().unwrap_or_default();
        String::from_utf8(bytes).unwrap_or_default()
    }

    /// The event as an observe layer: its summary, and each field as a
    /// note. The dashboard shows it as it shows a decoded packet.
    pub fn layer(&self) -> crate::observe::Layer {
        let name = format!("{}.{}", self.source, self.kind);
        let mut layer = crate::observe::Layer::new(&name, 0, (0, 0));
        layer.summary = self.summary.clone();
        for (n, v) in self.fields.iter() {
            let text = match v {
                Value::String(s) => s.clone(),
                other => other.to_bytes().map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            };
            layer.note(n, text);
        }
        layer
    }

    /// The `events.dropped` event that stands for `count` events a reader
    /// missed, the last of which was number `seq`.
    fn dropped(seq: u64, at: Instant, count: u64) -> Event {
        let mut event = Event::new("events", "dropped")
            .level(Level::Notice)
            .summary(format!("{count} earlier events were dropped: the log keeps the latest {MAX_EVENTS}, up to {} MiB of them", MAX_EVENT_BYTES >> 20))
            .field("count", count);
        event.seq = seq;
        event.at = at;
        event
    }
}

/// What the allocator adds to each allocation, about.
const ALLOC: usize = 32;

/// The bytes an allocation of `n` takes, or none for an empty one.
fn heap(n: usize) -> usize {
    if n == 0 { 0 } else { n + ALLOC }
}

/// About how many bytes `v` holds on the heap, beyond its own slot.
fn value_size(v: &Value) -> usize {
    match v {
        Value::Null | Value::Bool(_) => 0,
        Value::Number(n) => heap(n.text().len()),
        Value::String(s) => heap(s.capacity()),
        Value::Array(items) => heap(items.capacity() * std::mem::size_of::<Value>()) + items.iter().map(value_size).sum::<usize>(),
        Value::Object(members) => {
            heap(members.capacity() * std::mem::size_of::<(String, Value)>())
                + members.iter().map(|(k, v)| heap(k.capacity()) + value_size(v)).sum::<usize>()
        }
    }
}

/// A callback given to [`EventLog::subscribe`].
type Subscriber = Arc<dyn Fn(&Event) + Send + Sync>;

/// How many lines may wait for a file's writer thread.
const FILE_QUEUE: usize = 100_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a run's log holds.
pub(crate) struct Store {
    state: Mutex<State>,
    /// Lines file sinks could not keep up with.
    lost: Arc<AtomicU64>,
}

struct State {
    events: VecDeque<Arc<Event>>,
    bytes: usize,
    /// The number of the last event recorded.
    last: u64,
    /// How many events were dropped for the limits.
    dropped: u64,
    /// Shared, so recording takes a reference count, not a copy.
    subscribers: Arc<[Subscriber]>,
}

impl Store {
    pub(crate) fn new() -> Arc<Store> {
        Arc::new(Store {
            state: Mutex::new(State { events: VecDeque::new(), bytes: 0, last: 0, dropped: 0, subscribers: Arc::new([]) }),
            lost: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Numbers `event`, keeps it, and calls the subscribers.
    pub(crate) fn push(&self, mut event: Event) {
        let size = event.size();
        let mut s = lock(&self.state);
        s.last += 1;
        event.seq = s.last;
        let event = Arc::new(event);
        s.events.push_back(event.clone());
        s.bytes += size;
        while s.events.len() > MAX_EVENTS || (s.bytes > MAX_EVENT_BYTES && s.events.len() > 1) {
            let Some(old) = s.events.pop_front() else { break };
            s.bytes -= old.size();
            s.dropped += 1;
        }
        if s.subscribers.is_empty() {
            return;
        }
        let subscribers = s.subscribers.clone();
        drop(s);
        for f in subscribers.iter() {
            f(&event);
        }
    }

    /// The number of the last event recorded.
    pub(crate) fn last(&self) -> u64 {
        lock(&self.state).last
    }

    /// Forgets the subscribers, so a file's writer finishes once the run
    /// is over.
    pub(crate) fn close(&self) {
        lock(&self.state).subscribers = Arc::new([]);
    }

    /// The events after number `after`, at most `max`, oldest first, with
    /// an `events.dropped` event first if some of them are gone.
    pub(crate) fn after(&self, after: u64, max: usize) -> Vec<Arc<Event>> {
        let s = lock(&self.state);
        after_locked(&s, after, max)
    }
}

fn after_locked(s: &State, after: u64, max: usize) -> Vec<Arc<Event>> {
    let mut out = Vec::new();
    if max == 0 {
        return out;
    }
    let first = s.events.front().map_or(s.last + 1, |e| e.seq);
    if after + 1 < first {
        let at = s.events.front().map_or(Instant::ZERO, |e| e.at);
        out.push(Arc::new(Event::dropped(first - 1, at, first - 1 - after)));
    }
    let skip = (after + 1).saturating_sub(first) as usize;
    out.extend(s.events.iter().skip(skip).take(max - out.len()).cloned());
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
        let s = lock(&self.store.state);
        f.debug_struct("EventLog").field("recorded", &s.last).field("held", &s.events.len()).field("dropped", &s.dropped).finish()
    }
}

impl EventLog {
    pub(crate) fn new(store: Arc<Store>) -> EventLog {
        EventLog { store }
    }

    /// The events recorded after number `after`, at most `max`, oldest
    /// first. If the log no longer holds some of them, the first event is
    /// an `events.dropped` one that counts them (field `count`), numbered
    /// as the last one missed, so the next call can go on from the last
    /// event returned.
    pub fn after(&self, after: u64, max: usize) -> Vec<Event> {
        self.store.after(after, max).into_iter().map(|e| (*e).clone()).collect()
    }

    /// Every event the log holds, oldest first, after an `events.dropped`
    /// event if some were dropped.
    pub fn all(&self) -> Vec<Event> {
        self.after(0, usize::MAX)
    }

    /// The events of `source`'s `kind` the log holds.
    pub fn of(&self, source: &str, kind: &str) -> Vec<Event> {
        let s = lock(&self.store.state);
        s.events.iter().filter(|e| e.is(source, kind)).map(|e| (**e).clone()).collect()
    }

    /// The number of the last event recorded: how many there have been.
    pub fn recorded(&self) -> u64 {
        self.store.last()
    }

    /// How many events the log has dropped for its limits.
    pub fn dropped(&self) -> u64 {
        lock(&self.store.state).dropped
    }

    /// Calls `f` with every event the log holds now, oldest first (after
    /// an `events.dropped` event if some were dropped), then with every
    /// event recorded from now on, in the task that records it, until the
    /// run is over. `f` must return quickly and never block: hand the
    /// event to a channel that never waits.
    pub fn subscribe(&self, f: impl Fn(&Event) + Send + Sync + 'static) {
        let f: Subscriber = Arc::new(f);
        let held = {
            let mut s = lock(&self.store.state);
            let held = after_locked(&s, 0, usize::MAX);
            let mut all: Vec<Subscriber> = s.subscribers.iter().cloned().collect();
            all.push(f.clone());
            s.subscribers = all.into();
            held
        };
        for e in held {
            f(&e);
        }
    }

    /// Writes every event to `path` as JSON Lines ([`Event::to_json`]),
    /// from a thread of its own: what the log holds now, then each event as
    /// it is recorded. The file is created, or emptied.
    pub fn to_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        self.to_writer(Box::new(std::io::BufWriter::new(file)));
        Ok(())
    }

    /// Writes every event to `out` as JSON Lines, from a thread of its own
    /// that flushes whenever it has caught up. A line that does not fit in
    /// the thread's queue is lost and counted ([`EventLog::lost`]), and the
    /// file gets an `events.lost` line with the count. A grader throws such
    /// a sample away. The thread ends once the run is over and it has
    /// written everything.
    pub fn to_writer(&self, out: Box<dyn Write + Send>) {
        let (tx, rx) = sync_channel::<Vec<u8>>(FILE_QUEUE);
        let lost = self.store.lost.clone();
        let reported = Arc::new(AtomicU64::new(0));
        std::thread::Builder::new()
            .name("fictionet-events".into())
            .spawn(move || write_lines(rx, out, &lost, &reported))
            .expect("the event writer's thread starts");
        let lost = self.store.lost.clone();
        self.subscribe(move |event| {
            let Ok(mut line) = event.to_json().to_bytes() else { return };
            line.push(b'\n');
            if tx.try_send(line).is_err() {
                lost.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    /// How many lines file writers could not keep up with.
    pub fn lost(&self) -> u64 {
        self.store.lost.load(Ordering::Relaxed)
    }

    /// Records the `run.start` event that anchors the run's clock. It is
    /// dated at the start of the run (`at` 0), and its `wall` field is the
    /// wall-clock time then, in seconds since the Unix epoch, as the run
    /// noted it when it began (`null` where there is no wall clock, as in a
    /// browser), so a reader can put every event's `at` on a calendar.
    /// `fields` add the world's own facts, such as the date the world says
    /// it is (`world_date`): the world owns its dates, and services take
    /// them from it, never from the host's clock.
    /// [`Net`](crate::stdlib::net::Net) records it when it starts serving.
    pub fn start(&self, cx: &Cx, fields: Fields) {
        let wall = if cfg!(target_arch = "wasm32") {
            Value::Null
        } else {
            cx.graph().start_wall.duration_since(crate::sys::UNIX_EPOCH).map_or(Value::Null, |d| float(d.as_secs_f64()))
        };
        let event = Event::new("run", "start").summary("the run started").fields(fields).field("wall", wall);
        cx.record_at(Instant::ZERO, event);
    }

    /// Waits until `n` held events match `pick`, checking every 10 ms on
    /// the run's clock, for at most `limit`. Returns those events, or every
    /// match so far if the time ran out.
    pub async fn wait(&self, cx: &Cx, n: usize, limit: std::time::Duration, mut pick: impl FnMut(&Event) -> bool) -> Vec<Event> {
        let deadline = cx.now() + limit;
        loop {
            let got: Vec<Event> = {
                let s = lock(&self.store.state);
                s.events.iter().filter(|e| pick(e)).map(|e| (**e).clone()).collect()
            };
            if got.len() >= n || cx.now() >= deadline {
                return got;
            }
            if cx.sleep(std::time::Duration::from_millis(10)).await.is_err() {
                return got;
            }
        }
    }
}

fn write_lines(rx: Receiver<Vec<u8>>, mut out: Box<dyn Write + Send>, lost: &AtomicU64, reported: &AtomicU64) {
    let report = |out: &mut Box<dyn Write + Send>| {
        let n = lost.load(Ordering::Relaxed);
        if n != reported.swap(n, Ordering::Relaxed) {
            let line = format!("{{\"source\":\"events\",\"kind\":\"lost\",\"fields\":{{\"count\":{n}}}}}\n");
            let _ = out.write_all(line.as_bytes());
        }
    };
    while let Ok(line) = rx.recv() {
        let _ = out.write_all(&line);
        while let Ok(more) = rx.try_recv() {
            let _ = out.write_all(&more);
        }
        report(&mut out);
        let _ = out.flush();
    }
    report(&mut out);
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numbered(store: &Store, n: u64) {
        for i in 0..n {
            store.push(Event::new("test", "tick").field("i", i));
        }
    }

    /// The log keeps the latest events, and a reader that fell behind gets
    /// one `events.dropped` event counting what it missed.
    #[test]
    fn the_oldest_events_go_first_and_readers_are_told() {
        let store = Store::new();
        let total = MAX_EVENTS as u64 + 10;
        numbered(&store, total);
        let log = EventLog::new(store.clone());
        let held = lock(&store.state).events.len() as u64;
        assert!(held <= MAX_EVENTS as u64 && lock(&store.state).bytes <= MAX_EVENT_BYTES);
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
        assert_eq!((late[0].seq, late[0].u64("count"), late[1].seq), (gone, Some(gone - 5), gone + 1));
        assert!(log.after(total, 10).is_empty());
        assert_eq!(log.all().len() as u64, held + 1);
    }

    #[test]
    fn the_byte_limit_holds() {
        let store = Store::new();
        let big = "x".repeat(1 << 20);
        for _ in 0..40 {
            store.push(Event::new("test", "big").summary(big.clone()));
        }
        let s = lock(&store.state);
        assert!(s.bytes <= MAX_EVENT_BYTES, "{}", s.bytes);
        assert!(s.events.len() < 40 && s.dropped > 0);
    }

    /// A subscriber set late gets what the log holds, then what follows.
    #[test]
    fn subscribers_replay_then_follow() {
        let store = Store::new();
        numbered(&store, 3);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        log.subscribe(move |e| s.lock().unwrap().push(e.seq));
        numbered(&store, 2);
        assert_eq!(*seen.lock().unwrap(), [1, 2, 3, 4, 5]);
        store.close();
        numbered(&store, 1);
        assert_eq!(seen.lock().unwrap().len(), 5, "a closed log calls no one");
    }

    /// Events are recorded with no reader at all, numbered and dated on
    /// the run's clock, with the task that recorded them.
    #[test]
    fn every_run_records_its_events() {
        crate::block_on(crate::run(|cx| async move {
            assert!(!cx.observed());
            cx.record(Event::new("world", "hello").field("n", 1u32));
            cx.sleep(std::time::Duration::from_millis(5)).await?;
            cx.record(Event::new("world", "hello").field("n", 2u32));
            let events = cx.events().all();
            assert_eq!(events.len(), 2);
            assert_eq!((events[0].seq, events[1].seq), (1, 2));
            assert!(events[0].at < events[1].at && events[1].at <= cx.now());
            assert_eq!(events[0].origin.as_ref().map(|o| o.task), Some(1), "the world function is the first task");
            let json = events[1].to_line();
            assert!(json.contains(r#""source":"world","kind":"hello""#) && json.contains(r#""node":"t1""#), "{json}");
            Ok(())
        }))
        .unwrap();
    }
}
