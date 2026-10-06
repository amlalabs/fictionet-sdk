//! One log for a whole world: the facts every service records, in one
//! shape.
//!
//! A [`Journal`] is made once by the world and handed to everything that
//! records: [`serve`](crate::stdlib::serve) for each connection,
//! [`net::Net`](crate::stdlib::net::Net) for DNS, TLS, HTTP and the
//! sandboxes' packets, and the world's own code. Each fact is an [`Event`]:
//! the service that saw it (`"dns"`, `"http"`, `"modbus"`), its kind
//! (`"query"`, `"request"`, `"write_register"`), a one-line summary, a
//! [`Level`], and named [`Fields`] whose values are JSON. The journal wraps
//! it in an [`Entry`] with a sequence number, the run's clock reading, and
//! the connection it came from ([`ConnInfo`]): the sandbox, its addresses
//! and the connection number. A grader joins a sign-in to the requests
//! that follow it by those, never by guessing.
//!
//! Each entry goes to every sink the world set:
//!
//! - observers, such as `fictionet dashboard`, as a custom event named
//!   `service.kind`, only while one is watching ([`Journal::dashboard`]);
//! - a JSON Lines file, one entry per line, for a grader that reads it after
//!   the run ([`Journal::to_file`]);
//! - callbacks ([`Journal::subscribe`]), and an in-memory list for tests
//!   and graders in the same process ([`Journal::keep`]).
//!
//! The shape is the same as an observe layer (a summary and named fields),
//! so the dashboard shows a service's events and a decoded packet with the
//! same code: [`Entry::layer`] makes one.
//!
//! ```
//! use fictionet::stdlib::journal::{ConnInfo, Event, Journal, Level};
//! # fictionet::block_on(fictionet::run(|cx| async move {
//! let journal = Journal::new();
//! let kept = journal.keep(1000);
//! journal.record(&cx, &ConnInfo::default(), Event::new("modbus", "write_register")
//!     .summary("register 40001 = 900")
//!     .level(Level::Alarm)
//!     .field("register", 40001u32)
//!     .field("value", 900u32));
//! let entries = kept.entries();
//! assert_eq!(entries[0].event.get("value").and_then(|v| v.as_u64()), Some(900));
//! # Ok(()) }))?;
//! # Ok::<(), fictionet::Error>(())
//! ```
//!
//! Recording costs nothing while no sink would take the entry:
//! [`Journal::wants`] says whether one would, so a service skips building
//! an event no one reads.
//!
//! Callbacks run inside the task that recorded, so they must return
//! quickly and never block: hand the entry to a channel that never waits.
//! The file is written by a thread of its own, behind a bounded queue. An
//! entry that does not fit is lost and counted ([`Journal::lost`]), and the
//! file gets a `journal.lost` line with the count. A grader throws such a
//! sample away.

use std::collections::VecDeque;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, RwLock};

use fictionet::Cx;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::json::{Number, Value};
use fictionet::time::Instant;

/// How much an event matters to the people and graders reading the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// An ordinary fact: a query, a request, a connection.
    #[default]
    Info,
    /// Worth a look: a refused handshake, a malformed request, a blocked
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
/// An HTTP handler adds fields to its request's event by putting `Fields`
/// in its response's extensions (see [`httpd`](crate::stdlib::httpd)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields(Vec<(&'static str, Value)>);

impl Fields {
    /// No fields.
    pub fn new() -> Fields {
        Fields(Vec::new())
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

/// One fact a service chose to record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    /// The service that saw it: `"dns"`, `"http"`, `"modbus"`.
    pub service: &'static str,
    /// What happened: `"query"`, `"request"`, `"write_register"`.
    pub kind: &'static str,
    /// One line for people: the dashboard's list, a world's console.
    pub summary: String,
    /// How much it matters.
    pub level: Level,
    /// The facts a grader queries.
    pub fields: Fields,
}

impl Event {
    /// An [`Info`](Level::Info) event with no summary and no fields.
    pub fn new(service: &'static str, kind: &'static str) -> Event {
        Event { service, kind, summary: String::new(), level: Level::Info, fields: Fields::new() }
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

    /// Whether this is `service`'s `kind`.
    pub fn is(&self, service: &str, kind: &str) -> bool {
        self.service == service && self.kind == kind
    }
}

/// A sandbox, as an entry names it.
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

/// Where an event came from: the connection and the sandbox behind it.
/// Every field is optional, since some events belong to no connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
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

/// An event as the journal keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its place among the journal's entries, from 1.
    pub seq: u64,
    /// When it was recorded, on the run's clock.
    pub at: Instant,
    /// Where it came from.
    pub conn: ConnInfo,
    /// What happened.
    pub event: Event,
}

impl Entry {
    /// The value of the event's field `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.event.get(name)
    }

    /// The field `name` as text.
    pub fn str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Value::as_str)
    }

    /// The field `name` as a number.
    pub fn u64(&self, name: &str) -> Option<u64> {
        self.get(name).and_then(Value::as_u64)
    }

    /// Whether this is `service`'s `kind`.
    pub fn is(&self, service: &str, kind: &str) -> bool {
        self.event.is(service, kind)
    }

    /// The entry as one JSON object: `seq`, `at` (seconds since the run
    /// started), `service`, `kind`, `level`, `summary`, then the envelope
    /// (`sandbox`, `conn`, `local`, `peer`, `sni`), then `fields`.
    pub fn to_json(&self) -> Value {
        let c = &self.conn;
        Value::Object(vec![
            ("seq".into(), self.seq.into()),
            ("at".into(), float(self.at.since_start().as_secs_f64())),
            ("service".into(), self.event.service.into()),
            ("kind".into(), self.event.kind.into()),
            ("level".into(), self.event.level.as_str().into()),
            ("summary".into(), self.event.summary.as_str().into()),
            ("sandbox".into(), c.sandbox.as_ref().map_or(Value::Null, Sandbox::to_json)),
            ("conn".into(), opt(c.id)),
            ("local".into(), opt(c.local.map(|a| a.to_string()))),
            ("peer".into(), opt(c.peer.map(|a| a.to_string()))),
            ("sni".into(), opt(c.sni.as_deref())),
            ("fields".into(), self.event.fields.to_json()),
        ])
    }

    /// The entry as an observe layer: its summary, and each field as a
    /// note. The dashboard shows it as it shows a decoded packet.
    pub fn layer(&self) -> fictionet::observe::Layer {
        let name = format!("{}.{}", self.event.service, self.event.kind);
        let mut layer = fictionet::observe::Layer::new(&name, 0, (0, 0));
        layer.summary = self.event.summary.clone();
        for (n, v) in self.event.fields.iter() {
            let text = match v {
                Value::String(s) => s.clone(),
                other => other.to_bytes().map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
            };
            layer.note(n, text);
        }
        layer
    }
}

/// A callback given to [`Journal::subscribe`].
type Sink = Arc<dyn Fn(&Entry) + Send + Sync>;

/// How many lines may wait for the file's writer thread.
const FILE_QUEUE: usize = 100_000;

struct Inner {
    seq: AtomicU64,
    dashboard: AtomicBool,
    sinks: RwLock<Vec<Sink>>,
    /// Whether any sink is set: read on every record, so kept apart from
    /// the lock.
    any: AtomicBool,
    lost: Arc<AtomicU64>,
}

/// The world's log. Cheap to clone: clones share the sinks and the
/// sequence. See the [module docs](self).
#[derive(Clone)]
pub struct Journal {
    inner: Arc<Inner>,
}

impl Default for Journal {
    fn default() -> Journal {
        Journal::new()
    }
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("recorded", &self.inner.seq.load(Ordering::Relaxed))
            .field("lost", &self.lost())
            .finish()
    }
}

impl Journal {
    /// A journal with no sinks but observers: it shows its entries on the
    /// dashboard while one watches.
    pub fn new() -> Journal {
        Journal {
            inner: Arc::new(Inner {
                seq: AtomicU64::new(0),
                dashboard: AtomicBool::new(true),
                sinks: RwLock::new(Vec::new()),
                any: AtomicBool::new(false),
                lost: Arc::new(AtomicU64::new(0)),
            }),
        }
    }

    /// Turns the dashboard sink on or off. A world that already sends its
    /// own lines to observers turns it off, so they do not show twice.
    pub fn dashboard(self, on: bool) -> Journal {
        self.inner.dashboard.store(on, Ordering::Relaxed);
        self
    }

    /// Calls `sink` with every entry recorded from now on, in the task
    /// that records it. It must return quickly and never block.
    pub fn subscribe(&self, sink: impl Fn(&Entry) + Send + Sync + 'static) {
        self.inner.sinks.write().unwrap_or_else(|e| e.into_inner()).push(Arc::new(sink));
        self.inner.any.store(true, Ordering::Relaxed);
    }

    /// Also writes every entry to `path` as JSON Lines ([`Entry::to_json`]),
    /// from a thread of its own. The file is created, or emptied.
    pub fn to_file(self, path: impl AsRef<Path>) -> std::io::Result<Journal> {
        let file = std::fs::File::create(path)?;
        self.to_writer(Box::new(std::io::BufWriter::new(file)));
        Ok(self)
    }

    /// Writes every entry to `out` as JSON Lines, from a thread of its own
    /// that flushes whenever it has caught up.
    pub fn to_writer(&self, out: Box<dyn Write + Send>) {
        let (tx, rx) = sync_channel::<Vec<u8>>(FILE_QUEUE);
        let lost = self.inner.lost.clone();
        let reported = Arc::new(AtomicU64::new(0));
        std::thread::Builder::new()
            .name("fictionet-journal".into())
            .spawn(move || write_lines(rx, out, &lost, &reported))
            .expect("the journal's writer thread starts");
        let lost = self.inner.lost.clone();
        self.subscribe(move |entry| {
            let Ok(mut line) = entry.to_json().to_bytes() else { return };
            line.push(b'\n');
            if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = tx.try_send(line) {
                lost.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    /// Keeps the last `limit` entries in memory, for a test or a grader in
    /// the same process.
    pub fn keep(&self, limit: usize) -> Kept {
        let kept = Kept { inner: Arc::new(Mutex::new(KeptInner { entries: VecDeque::new(), limit, dropped: 0 })) };
        let k = kept.clone();
        self.subscribe(move |entry| {
            let mut inner = k.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.limit == 0 {
                inner.dropped += 1;
                return;
            }
            if inner.entries.len() >= inner.limit {
                inner.entries.pop_front();
                inner.dropped += 1;
            }
            inner.entries.push_back(entry.clone());
        });
        kept
    }

    /// Whether recording now would reach any sink: a callback, a file, or
    /// an observer watching `cx`'s world.
    pub fn wants(&self, cx: &Cx) -> bool {
        self.inner.any.load(Ordering::Relaxed) || (self.inner.dashboard.load(Ordering::Relaxed) && cx.observed())
    }

    /// Records `event`, from `conn`, at `cx`'s time.
    pub fn record(&self, cx: &Cx, conn: &ConnInfo, event: Event) {
        self.record_at(cx, cx.now(), conn, event);
    }

    /// Records `event` with the time it happened, which may be earlier
    /// than now.
    pub fn record_at(&self, cx: &Cx, at: Instant, conn: &ConnInfo, event: Event) {
        if !self.wants(cx) {
            return;
        }
        let seq = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = Entry { seq, at, conn: conn.clone(), event };
        if self.inner.dashboard.load(Ordering::Relaxed)
            && cx.observed()
            && let Ok(json) = entry.to_json().to_bytes()
        {
            let name = format!("{}.{}", entry.event.service, entry.event.kind);
            let _ = cx.emit(&name, &String::from_utf8_lossy(&json));
        }
        let sinks: Vec<Sink> = self.inner.sinks.read().unwrap_or_else(|e| e.into_inner()).clone();
        for sink in sinks {
            sink(&entry);
        }
    }

    /// How many entries the file sinks could not keep up with.
    pub fn lost(&self) -> u64 {
        self.inner.lost.load(Ordering::Relaxed)
    }
}

fn write_lines(rx: Receiver<Vec<u8>>, mut out: Box<dyn Write + Send>, lost: &AtomicU64, reported: &AtomicU64) {
    let report = |out: &mut Box<dyn Write + Send>| {
        let n = lost.load(Ordering::Relaxed);
        if n != reported.swap(n, Ordering::Relaxed) {
            let line = format!("{{\"service\":\"journal\",\"kind\":\"lost\",\"fields\":{{\"count\":{n}}}}}\n");
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

struct KeptInner {
    entries: VecDeque<Entry>,
    limit: usize,
    dropped: u64,
}

/// The entries kept by [`Journal::keep`].
#[derive(Clone)]
pub struct Kept {
    inner: Arc<Mutex<KeptInner>>,
}

impl Kept {
    /// The entries kept so far, oldest first.
    pub fn entries(&self) -> Vec<Entry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.iter().cloned().collect()
    }

    /// The entries of `service`'s `kind`.
    pub fn of(&self, service: &str, kind: &str) -> Vec<Entry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.iter().filter(|e| e.is(service, kind)).cloned().collect()
    }

    /// Forgets the entries kept so far.
    pub fn clear(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.clear();
    }

    /// How many entries were dropped for the limit.
    pub fn dropped(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).dropped
    }

    /// Waits until `n` entries match `pick`, checking every 10 ms, for at
    /// most `limit`. Returns those entries, or every match so far if the
    /// time ran out.
    pub async fn wait(&self, cx: &Cx, n: usize, limit: std::time::Duration, mut pick: impl FnMut(&Entry) -> bool) -> Vec<Entry> {
        let deadline = cx.now() + limit;
        loop {
            let got: Vec<Entry> = self.entries().into_iter().filter(|e| pick(e)).collect();
            if got.len() >= n || cx.now() >= deadline {
                return got;
            }
            if cx.sleep(std::time::Duration::from_millis(10)).await.is_err() {
                return got;
            }
        }
    }
}
