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
//! # fictionet::block_on(fictionet::run(|fcx| async move {
//! fcx.record(Event::new("modbus", "write_register")
//!     .summary("register 40001 = 900")
//!     .level(Level::Alarm)
//!     .field("register", 40001u32)
//!     .field("value", 900u32));
//! let events = fcx.events().of("modbus", "write_register");
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
//! and every reader that missed some is told how many, with an
//! `events.dropped` event in their place ([`EventLog::after`]).
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
//!
//! So a flood costs at most two events per second for each distinct kind
//! of repeat, and never costs the run a service's event, an HTTP request,
//! a DNS query, a TLS handshake or a connection's open and close.
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
//! then the rest as it is recorded.
//!
//! # What it costs
//!
//! Recording takes the event the caller built, looks up the task that
//! recorded it, and appends it to the log under one lock. Callbacks run
//! after that, in the task that recorded, so they must return quickly and
//! never block. The `sites` group of the performance suite (`cargo bench
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

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::Cx;
use crate::lock;
use crate::stdlib::codec::Wire;
use crate::stdlib::json::{Number, Value};
use crate::time::Instant;

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
/// them. Past this, the oldest are dropped.
pub const MAX_EVENT_BYTES: usize = 16 << 20;
/// How many [repeats](self#repeats) a run's log holds, beside its other
/// events. Past this, the oldest repeats are dropped.
pub const MAX_REPEATS: usize = 5_000;
/// How many bytes of [repeats](self#repeats) a run's log holds, beside its
/// other events. Past this, the oldest repeats are dropped.
pub const MAX_REPEAT_BYTES: usize = 2 << 20;
/// How long, on the run's clock, repeats of an event are counted before
/// the log records their count. See [Repeats](self#repeats).
pub const REPEAT_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
/// How many runs of repeats are counted at once. Past this, the oldest
/// count is recorded early.
const OPEN_WINDOWS: usize = 1024;

/// How much an event matters to the people and graders reading the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// An ordinary fact: a query, a request, a connection.
    #[default]
    Info,
    /// Worth a look: a refused handshake, a malformed request, a dropped
    /// packet.
    Notice,
    /// The fact a grader watches for: a safety limit crossed, a password
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
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
        Value::Object(
            self.0
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.clone()))
                .collect(),
        )
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

/// How a connection's bytes travel. An event's connection and an observed
/// conversation ([`observe::Selection`](crate::observe::Selection)) both
/// use it.
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
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
        ConnInfo {
            id: Some(id),
            local: Some(local),
            peer: Some(peer),
            ..ConnInfo::default()
        }
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
        let fields = self.fields.0.capacity() * slot
            + self
                .fields
                .0
                .iter()
                .map(|(_, v)| value_size(v))
                .sum::<usize>();
        ALLOC + std::mem::size_of::<Event>() + heap(self.summary.capacity()) + heap(fields)
    }

    /// The event as one JSON object: `seq`, `at` (seconds since the run
    /// started), `source`, `kind`, `level`, `summary`, then the connection
    /// (`sandbox`, `conn`, `local`, `peer`, `transport`, `tls`, `sni`,
    /// `alpn`), then
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
            (
                "sandbox".into(),
                c.sandbox.as_ref().map_or(Value::Null, Sandbox::to_json),
            ),
            ("conn".into(), opt(c.id)),
            ("local".into(), opt(c.local.map(|a| a.to_string()))),
            ("peer".into(), opt(c.peer.map(|a| a.to_string()))),
            ("transport".into(), c.transport.as_str().into()),
            ("tls".into(), c.tls.into()),
            ("sni".into(), opt(c.sni.as_deref())),
            (
                "alpn".into(),
                opt(c
                    .alpn
                    .as_deref()
                    .map(|a| String::from_utf8_lossy(a).into_owned())),
            ),
            ("fields".into(), self.fields.to_json()),
        ];
        if let Some(o) = &self.origin {
            let id = |t: u64| {
                if t == 0 {
                    Value::Null
                } else {
                    Value::String(format!("t{t}"))
                }
            };
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
                other => other
                    .to_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default(),
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
            .summary(format!(
                "{count} earlier events were dropped for the log's limits"
            ))
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
        Value::Array(items) => {
            heap(items.capacity() * std::mem::size_of::<Value>())
                + items.iter().map(value_size).sum::<usize>()
        }
        Value::Object(members) => {
            heap(members.capacity() * std::mem::size_of::<(String, Value)>())
                + members
                    .iter()
                    .map(|(k, v)| heap(k.capacity()) + value_size(v))
                    .sum::<usize>()
        }
    }
}

/// A callback given to [`EventLog::subscribe`].
type Subscriber = Arc<dyn Fn(&Event) + Send + Sync>;

/// How many lines may wait for a file's writer thread.
const FILE_QUEUE: usize = 100_000;
/// How many bytes of lines may wait for a file's writer thread.
const FILE_QUEUE_BYTES: usize = MAX_EVENT_BYTES;

/// What a run's log holds.
pub(crate) struct Store {
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
    /// bounds. Returns how many it dropped.
    fn push(&mut self, event: Arc<Event>, size: usize) -> u64 {
        self.events.push_back(event);
        self.bytes += size;
        let mut dropped = 0;
        while self.events.len() > self.max || (self.bytes > self.max_bytes && self.events.len() > 1)
        {
            let Some(old) = self.events.pop_front() else {
                break;
            };
            self.bytes -= old.size();
            dropped += 1;
        }
        dropped
    }
}

/// What makes repeats alike.
#[derive(PartialEq, Eq, Hash)]
struct RepeatKey {
    source: &'static str,
    kind: &'static str,
    conn: ConnInfo,
    fields: Fields,
}

/// A run of alike repeats, counted after the first.
struct Window {
    /// The first of them, without its detail.
    first: Event,
    count: u64,
    /// When the latest was recorded.
    last: Instant,
    /// Each detail field that is a number, with its lowest and highest.
    ranges: Vec<(&'static str, u64, u64)>,
}

impl Window {
    fn add(&mut self, at: Instant, detail: &Fields) {
        self.count += 1;
        self.last = self.last.max(at);
        for (name, value) in detail.iter() {
            let Some(n) = value.as_u64() else { continue };
            match self.ranges.iter_mut().find(|r| r.0 == name) {
                Some(r) => (r.1, r.2) = (r.1.min(n), r.2.max(n)),
                None => self.ranges.push((name, n, n)),
            }
        }
    }

    /// The event that counts the repeats after the first, if there were
    /// any.
    fn summary(self) -> Option<Event> {
        if self.count == 0 {
            return None;
        }
        let mut event = self.first;
        event.summary = format!("{} more: {}", self.count, event.summary);
        event.at = self.last;
        event.fields.set("count", self.count);
        for (name, low, high) in self.ranges {
            event
                .fields
                .set(name, Value::Array(vec![low.into(), high.into()]));
        }
        Some(event)
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
    /// The same, oldest first, each with when its count is due.
    due: VecDeque<(Instant, Arc<RepeatKey>)>,
    /// Shared, so recording takes a reference count, not a copy.
    subscribers: Arc<[Subscriber]>,
    /// Whether the run is over.
    closed: bool,
    /// The file writers' threads, joined when the run is over.
    writers: Vec<std::thread::JoinHandle<()>>,
}

impl State {
    /// Numbers `event` and keeps it, in `out` too.
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
        out.push(event);
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
        if let Some(event) = self.open.remove(&key).and_then(Window::summary) {
            self.keep(event, true, out);
        }
    }
}

impl Store {
    pub(crate) fn new() -> Arc<Store> {
        Arc::new(Store {
            state: Mutex::new(State {
                events: Part::new(MAX_EVENTS, MAX_EVENT_BYTES),
                repeats: Part::new(MAX_REPEATS, MAX_REPEAT_BYTES),
                last: 0,
                dropped: 0,
                clock: Instant::ZERO,
                open: HashMap::new(),
                due: VecDeque::new(),
                subscribers: Arc::new([]),
                closed: false,
                writers: Vec::new(),
            }),
            lost: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Numbers `event`, keeps it, and calls the subscribers.
    pub(crate) fn push(&self, event: Event) {
        let mut out = Vec::with_capacity(1);
        let mut s = lock(&self.state);
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
        let mut s = lock(&self.state);
        s.advance(event.at, &mut out);
        if let Some(window) = s.open.get_mut(&key) {
            window.add(event.at, &detail);
        } else {
            if s.open.len() >= OPEN_WINDOWS {
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
            let key = Arc::new(key);
            let due = s.clock + REPEAT_WINDOW;
            s.open.insert(key.clone(), first);
            s.due.push_back((due, key));
            event.fields.extend(detail);
            event.fields.set("count", 1u64);
            s.keep(event, true, &mut out);
        }
        Store::tell(s, &out);
    }

    /// Moves the log's clock to `at`, recording the counts of repeats due
    /// by then.
    pub(crate) fn advance(&self, at: Instant) {
        let mut out = Vec::new();
        let mut s = lock(&self.state);
        s.advance(at, &mut out);
        Store::tell(s, &out);
    }

    /// Calls the subscribers with `events`, once `s` is unlocked.
    fn tell(s: MutexGuard<'_, State>, events: &[Arc<Event>]) {
        if s.subscribers.is_empty() || events.is_empty() {
            return;
        }
        let subscribers = s.subscribers.clone();
        drop(s);
        for event in events {
            for f in subscribers.iter() {
                f(event);
            }
        }
    }

    /// The number of the last event recorded.
    pub(crate) fn last(&self) -> u64 {
        lock(&self.state).last
    }

    /// Ends the log with the run: records every count of repeats still
    /// open, forgets the subscribers, and waits for the file writers to
    /// write everything.
    pub(crate) fn close(&self) {
        let mut out = Vec::new();
        let (subscribers, writers) = {
            let mut s = lock(&self.state);
            while !s.due.is_empty() {
                s.close_oldest(&mut out);
            }
            s.closed = true;
            (
                std::mem::replace(&mut s.subscribers, Arc::new([])),
                std::mem::take(&mut s.writers),
            )
        };
        for event in &out {
            for f in subscribers.iter() {
                f(event);
            }
        }
        // The writers end once their senders, in the subscribers, are gone.
        drop(subscribers);
        for writer in writers {
            let _ = writer.join();
        }
    }

    /// The events after number `after`, at most `max`, oldest first, with
    /// an `events.dropped` event wherever some of them are gone.
    pub(crate) fn after(&self, after: u64, max: usize) -> Vec<Arc<Event>> {
        let s = lock(&self.state);
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
        let s = lock(&self.store.state);
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
        let s = lock(&self.store.state);
        held(&s, 0)
            .filter(|e| e.is(source, kind))
            .map(|e| (**e).clone())
            .collect()
    }

    /// The number of the last event recorded: how many there have been.
    pub fn recorded(&self) -> u64 {
        self.store.last()
    }

    /// How many events the log has dropped for its limits.
    pub fn dropped(&self) -> u64 {
        lock(&self.store.state).dropped
    }

    /// Calls `f` with every event the log holds now, oldest first (with
    /// an `events.dropped` event wherever some were dropped), then with
    /// every event recorded from now on, in the task that records it,
    /// until the run is over. `f` must return quickly and never block:
    /// hand the event to a channel that never waits. Once the run is over,
    /// `f` gets only what the log holds.
    pub fn subscribe(&self, f: impl Fn(&Event) + Send + Sync + 'static) {
        let f: Subscriber = Arc::new(f);
        let held = {
            let mut s = lock(&self.store.state);
            let held = after_locked(&s, 0, usize::MAX);
            if !s.closed {
                let mut all: Vec<Subscriber> = s.subscribers.iter().cloned().collect();
                all.push(f.clone());
                s.subscribers = all.into();
            }
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
    /// that flushes whenever it has caught up. The run's end waits for the
    /// thread to write and flush every line.
    ///
    /// A line is lost, and counted ([`EventLog::lost`]), when it does not
    /// fit in the thread's queue (100,000 lines or 16 MiB), or when `out`
    /// fails. After a queue overflow the file gets an `events.lost` line
    /// with the count so far. After a failed write or flush the thread
    /// writes nothing more, and counts every line after it, and each line
    /// written since the last flush that worked, as lost. A grader throws
    /// away a sample with any line lost.
    pub fn to_writer(&self, out: Box<dyn Write + Send>) {
        let (tx, rx) = sync_channel::<Vec<u8>>(FILE_QUEUE);
        let queued = Arc::new(AtomicUsize::new(0));
        let lost = self.store.lost.clone();
        let writer = {
            let (lost, queued) = (lost.clone(), queued.clone());
            std::thread::Builder::new()
                .name("fictionet-events".into())
                .spawn(move || write_lines(rx, out, &lost, &queued))
                .expect("the event writer's thread starts")
        };
        self.subscribe(move |event| {
            let Ok(mut line) = event.to_json().to_bytes() else {
                return;
            };
            line.push(b'\n');
            let len = line.len();
            if queued.fetch_add(len, Ordering::Relaxed) + len > FILE_QUEUE_BYTES
                || tx.try_send(line).is_err()
            {
                queued.fetch_sub(len, Ordering::Relaxed);
                lost.fetch_add(1, Ordering::Relaxed);
            }
        });
        let mut s = lock(&self.store.state);
        if s.closed {
            // The run is over: the thread has all it will get.
            drop(s);
            let _ = writer.join();
        } else {
            s.writers.push(writer);
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
    /// browser), so a reader can put every event's `at` on a calendar.
    /// `fields` add the world's own facts, such as the date the world says
    /// it is (`world_date`): the world owns its dates, and services take
    /// them from it, never from the host's clock.
    /// [`Net`](crate::stdlib::net::Net) records it when it starts serving.
    pub fn start(&self, fcx: &Cx, fields: Fields) {
        let wall = if cfg!(target_arch = "wasm32") {
            Value::Null
        } else {
            fcx.graph()
                .start_wall
                .duration_since(crate::sys::UNIX_EPOCH)
                .map_or(Value::Null, |d| float(d.as_secs_f64()))
        };
        let event = Event::new("run", "start")
            .summary("the run started")
            .fields(fields)
            .field("wall", wall);
        fcx.record_at(Instant::ZERO, event);
    }

    /// Waits until `n` held events match `pick`, checking every 10 ms on
    /// the run's clock, for at most `limit`. Returns those events, or every
    /// match so far if the time ran out. Each check first records the
    /// counts of [repeats](self#repeats) that are due. Returns early with
    /// [`Cancelled`](crate::Cancelled) if `fcx`'s [region](Cx#regions) is
    /// cancelled.
    pub async fn wait(
        &self,
        fcx: &Cx,
        n: usize,
        limit: std::time::Duration,
        mut pick: impl FnMut(&Event) -> bool,
    ) -> Result<Vec<Event>, crate::Cancelled> {
        let deadline = fcx.now() + limit;
        loop {
            self.store.advance(fcx.now());
            let got: Vec<Event> = {
                let s = lock(&self.store.state);
                held(&s, 0)
                    .filter(|e| pick(e))
                    .map(|e| (**e).clone())
                    .collect()
            };
            if got.len() >= n || fcx.now() >= deadline {
                return Ok(got);
            }
            fcx.sleep(std::time::Duration::from_millis(10)).await?;
        }
    }
}

/// Writes the lines from `rx` to `out` until the run is over. After a
/// failed write or flush, only counts them as lost.
fn write_lines(
    rx: Receiver<Vec<u8>>,
    mut out: Box<dyn Write + Send>,
    lost: &AtomicU64,
    queued: &AtomicUsize,
) {
    let mut reported = 0;
    // Lines written since the last flush that worked.
    let mut unflushed = 0u64;
    let mut failed = false;
    let mut batch = Vec::new();
    while let Ok(line) = rx.recv() {
        batch.push(line);
        batch.extend(rx.try_iter());
        for line in batch.drain(..) {
            queued.fetch_sub(line.len(), Ordering::Relaxed);
            if failed {
                lost.fetch_add(1, Ordering::Relaxed);
            } else if out.write_all(&line).is_ok() {
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
        let held = lock(&store.state).events.events.len() as u64;
        assert!(held <= MAX_EVENTS as u64 && lock(&store.state).events.bytes <= MAX_EVENT_BYTES);
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
        let store = Store::new();
        let big = "x".repeat(1 << 20);
        for _ in 0..40 {
            store.push(Event::new("test", "big").summary(big.clone()));
        }
        let s = lock(&store.state);
        assert!(s.events.bytes <= MAX_EVENT_BYTES, "{}", s.events.bytes);
        assert!(s.events.events.len() < 40 && s.dropped > 0);
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
        let store = Store::new();
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

    /// Repeats have bounds of their own: a flood of them, more than the
    /// log holds, never pushes out another event, and a reader is told
    /// where repeats are gone.
    #[test]
    fn a_flood_of_repeats_never_pushes_out_other_events() {
        let store = Store::new();
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
        let s = lock(&store.state);
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
            let mut bytes = self.bytes.lock().unwrap();
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
        crate::block_on(crate::run(|fcx| async move {
            fcx.events().to_writer(Box::new(out));
            for i in 0..500u32 {
                fcx.record(Event::new("test", "tick").field("i", i));
            }
            *keep.lock().unwrap() = Some(fcx.events());
            Ok(())
        }))
        .unwrap();
        let log = kept.lock().unwrap().take().unwrap();
        let lines = sink
            .bytes
            .lock()
            .unwrap()
            .iter()
            .filter(|b| **b == b'\n')
            .count();
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
        crate::block_on(crate::run(|fcx| async move {
            fcx.events().to_writer(Box::new(out));
            for i in 0..300u32 {
                fcx.record(Event::new("test", "tick").field("i", i));
            }
            *keep.lock().unwrap() = Some(fcx.events());
            Ok(())
        }))
        .unwrap();
        let log = kept.lock().unwrap().take().unwrap();
        let lines = sink
            .bytes
            .lock()
            .unwrap()
            .iter()
            .filter(|b| **b == b'\n')
            .count() as u64;
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
        crate::block_on(crate::run(|fcx| async move {
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
