use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::stdlib::codec::Wire;
use crate::stdlib::json::{Number, Value};
use crate::time::Instant;

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

/// One fact a world recorded. See the [module docs](crate::events).
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
    /// [`MAX_EVENT_BYTES`](super::MAX_EVENT_BYTES). Shared connection metadata is charged in full
    /// for each event. Owned task names are included; static strings are not.
    pub fn size(&self) -> usize {
        heap(std::mem::size_of::<Event>() + ARC_COUNTS)
            + heap(self.summary.capacity())
            + fields_size(&self.fields)
            + conn_size(&self.conn)
            + self.origin.as_ref().map_or(0, |o| match &o.name {
                Cow::Owned(name) => heap(name.capacity()),
                Cow::Borrowed(_) => 0,
            })
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

    /// The `events.dropped` event that stands for `count` events a reader
    /// missed, the last of which was number `seq`.
    pub(super) fn dropped(seq: u64, at: Instant, count: u64) -> Event {
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
/// The strong and weak reference counts in an Arc allocation.
pub(super) const ARC_COUNTS: usize = 2 * std::mem::size_of::<usize>();

/// The bytes an allocation of `n` takes, or none for an empty one.
pub(super) fn heap(n: usize) -> usize {
    if n == 0 { 0 } else { n + ALLOC }
}

pub(super) fn fields_size(fields: &Fields) -> usize {
    heap(fields.0.capacity() * std::mem::size_of::<(&str, Value)>())
        + fields.0.iter().map(|(_, v)| value_size(v)).sum::<usize>()
}

pub(super) fn conn_size(conn: &ConnInfo) -> usize {
    conn.sandbox
        .as_ref()
        .map_or(0, |s| heap(ARC_COUNTS + s.name.len()))
        + conn.sni.as_ref().map_or(0, |s| heap(ARC_COUNTS + s.len()))
        + conn.alpn.as_ref().map_or(0, |a| heap(ARC_COUNTS + a.len()))
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
