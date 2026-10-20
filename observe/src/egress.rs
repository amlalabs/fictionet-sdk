//! Left the box: every connection attempt from each sandbox, grouped by
//! destination, with what the world did with it.
//!
//! [`Egress`] is an observer. It reads the events the world's services
//! already emit and keeps a bounded table:
//!
//! | Event | Becomes |
//! |---|---|
//! | `http.request` | A request served by a world site, or forwarded when its `forwarded` field names the real origin. `misdirected`, `no_host`, `too_large`, body `timeout` and `budget` answers are refused. Requests ending without an answer stay with their named site or origin and increment `unanswered`. |
//! | `tls.handshake` | A refused connection when the world rejected the name. |
//! | `dns.query` | A query served by the world's DNS, and a [`Lookup`] with its answer. |
//! | `net.blocked` | Refused (`ClosedPort`, `TooManyConnections`) or no route (every other reason), counted in packets. A world that answers some of a sandbox's packets itself, before its `Net` sees them, reports its refusals with this event too, naming the sandbox in a `sandbox` field. |
//! | `conn.open`, `conn.close` | A connection served by a world service, counted once per connection. |
//!
//! Forwarding means requests sent through `web::proxy` or `web::forward`,
//! including the mirror. A world that sends traffic out another way must
//! report the same `forwarded` origin on its request events.
//!
//! Only events from a sandbox count: their connection names the sandbox, or,
//! for `net.blocked` alone, their `sandbox` field does. A connection that carried a request,
//! a handshake or a query counts on that row; any other connection counts
//! when it closes. Names come from the request's host, the TLS name or the
//! sandbox's own DNS answers for the address.
//!
//! The table keeps at most [`EgressLimits`] rows. Attempts that would need a
//! new row past the bound are counted in [`EgressSnapshot::dropped`]; events
//! the run lost before this observer saw them are counted in
//! [`EgressSnapshot::lost`]. When both are zero, the table lists every
//! attempt the world's services reported.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use fictionet::events::{
    Event, HostId, Interest, Loss, Observation, Observer, Stamp, Stream, TopologyKind, TopologyRef,
};
use fictionet::sync::Mutex;

/// What the world did with an attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "page", derive(serde::Serialize))]
#[cfg_attr(feature = "page", serde(rename_all = "snake_case"))]
pub enum Outcome {
    /// A world site or service answered it. Nothing left the world.
    Served,
    /// The world sent it on to the real internet.
    Forwarded,
    /// The world refused it.
    Refused,
    /// Nothing in the world has that destination, so it went nowhere.
    NoRoute,
}

/// Bounds on what an [`Egress`] keeps.
#[derive(Clone, Copy, Debug)]
pub struct EgressLimits {
    /// Destination rows.
    pub rows: usize,
    /// Name lookups.
    pub lookups: usize,
    /// Addresses remembered with the name a sandbox looked up for them.
    pub names: usize,
    /// Open connections followed until they close.
    pub connections: usize,
}

impl Default for EgressLimits {
    fn default() -> Self {
        Self {
            rows: 1024,
            lookups: 1024,
            names: 4096,
            connections: 4096,
        }
    }
}

/// One destination, one outcome, from one sandbox.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "page", derive(serde::Serialize))]
pub struct Destination {
    /// The sandbox the attempts came from.
    pub sandbox: String,
    /// The address and port, such as `203.0.113.10:443`, or the address
    /// alone for a packet without ports.
    pub address: String,
    /// `tcp`, `udp`, `icmp`, `icmpv6`, `ip 47` for other protocols, or `-`
    /// when the packet was too broken to tell.
    pub transport: String,
    /// The name the sandbox used for it, when one is known.
    pub name: Option<String>,
    /// What the world did.
    pub outcome: Outcome,
    /// Who answered or why not: the world site's name, `the world's DNS`,
    /// the real origin for a forward, or the reason for a refusal.
    pub by: String,
    /// Connections.
    pub connections: u64,
    /// HTTP requests and DNS queries.
    pub requests: u64,
    /// Requests that ended without a complete application answer.
    pub unanswered: u64,
    /// Packets the network refused or dropped.
    pub packets: u64,
    /// The first attempt, in seconds on the run's clock.
    pub first: f64,
    /// The last attempt, in seconds on the run's clock.
    pub last: f64,
}

/// One name a sandbox looked up, and the world's answer.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "page", derive(serde::Serialize))]
pub struct Lookup {
    /// The sandbox that asked.
    pub sandbox: String,
    /// The name.
    pub name: String,
    /// An address, `no such name`, `no A record`, `no AAAA record`,
    /// `error <rcode>` or `no answer`.
    pub answer: String,
    /// How many times.
    pub count: u64,
    /// The first time, in seconds on the run's clock.
    pub first: f64,
    /// The last time, in seconds on the run's clock.
    pub last: f64,
}

/// An accepted connection awaiting an application outcome.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "page", derive(serde::Serialize))]
pub struct Pending {
    /// The sandbox making the connection.
    pub sandbox: String,
    /// The destination socket.
    pub address: String,
    /// The transport protocol.
    pub transport: String,
    /// The serving host, when the topology names it.
    pub service: Option<String>,
    /// When the connection opened, in run seconds.
    pub first: f64,
}

/// The table at one moment.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(feature = "page", derive(serde::Serialize))]
pub struct EgressSnapshot {
    /// Increases with every change.
    pub revision: u64,
    /// The last attempt, in seconds on the run's clock.
    pub at: f64,
    /// Destinations, by sandbox, address and outcome.
    pub destinations: Vec<Destination>,
    /// Lookups, by sandbox and name.
    pub lookups: Vec<Lookup>,
    /// Accepted connections whose application outcome has not arrived yet.
    pub pending: Vec<Pending>,
    /// Attempts and lookups not kept because the table was full.
    pub dropped: u64,
    /// Events or topology the run lost, and truncated events.
    pub lost: u64,
}

impl EgressSnapshot {
    /// Whether the table lists every attempt the world's services reported.
    pub fn complete(&self) -> bool {
        self.dropped == 0 && self.lost == 0
    }
}

type RowKey = (String, String, String, Outcome, String);
type ConnKey = (String, String, u64);

struct Open {
    address: String,
    transport: &'static str,
    /// The TLS name, once the handshake said it.
    sni: Option<String>,
    /// The connection is already counted on a row.
    counted: bool,
    first: f64,
    service: Option<String>,
}

#[derive(Default)]
struct State {
    revision: u64,
    at: f64,
    rows: BTreeMap<RowKey, Destination>,
    lookups: BTreeMap<(String, String, String), Lookup>,
    names: BTreeMap<(String, String), String>,
    hosts: BTreeMap<HostId, String>,
    open: BTreeMap<ConnKey, Open>,
    dropped: u64,
    lost: u64,
    changed: bool,
}

/// The left-the-box table, as an observer. Install it in the run's fanout
/// before the run starts; a `DashboardObserver` has one built in.
pub struct Egress {
    limits: EgressLimits,
    state: Mutex<State>,
}

impl Default for Egress {
    fn default() -> Self {
        Self::new(EgressLimits::default())
    }
}

/// The address of a socket, as the table shows it.
fn address(addr: SocketAddr) -> String {
    addr.to_string()
}

fn ip_of(address: &str) -> &str {
    match address.rsplit_once(':') {
        Some((ip, port)) if port.bytes().all(|b| b.is_ascii_digit()) => {
            ip.trim_start_matches('[').trim_end_matches(']')
        }
        _ => address,
    }
}

impl Egress {
    /// Creates an empty table with these bounds.
    pub fn new(limits: EgressLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    /// Increases with every change, so a reader can skip an unchanged table.
    pub fn revision(&self) -> u64 {
        self.state.lock().revision
    }

    /// The table now: destinations ordered by sandbox, then address.
    pub fn snapshot(&self) -> EgressSnapshot {
        let state = self.state.lock();
        EgressSnapshot {
            revision: state.revision,
            at: state.at,
            destinations: state.rows.values().cloned().collect(),
            lookups: state.lookups.values().cloned().collect(),
            pending: state
                .open
                .iter()
                .filter(|(_, open)| !open.counted)
                .map(|(key, open)| Pending {
                    sandbox: key.0.clone(),
                    address: open.address.clone(),
                    transport: open.transport.into(),
                    service: open.service.clone(),
                    first: open.first,
                })
                .collect(),
            dropped: state.dropped,
            lost: state.lost,
        }
    }

    fn topology(&self, at: f64, item: TopologyRef<'_>) {
        match item {
            TopologyRef::HostAdded { host, name, .. } => {
                let mut state = self.state.lock();
                if state.hosts.len() < self.limits.names && name.len() <= 1024 {
                    state.hosts.insert(host, name.to_owned());
                } else {
                    state.dropped += 1;
                    state.revision += 1;
                }
            }
            TopologyRef::HostRemoved { host } => {
                self.state.lock().hosts.remove(&host);
            }
            TopologyRef::ConnectionOpened { conn, host, .. } => {
                self.event(at, &Event::new("conn", "open").conn(conn));
                if let (Some(sandbox), Some(local), Some(id)) = (&conn.sandbox, conn.local, conn.id)
                {
                    let mut state = self.state.lock();
                    let service = host.and_then(|host| state.hosts.get(&host)).cloned();
                    if let Some(open) =
                        state
                            .open
                            .get_mut(&(sandbox.name.to_string(), local.to_string(), id))
                    {
                        open.service = service;
                    }
                }
            }
            TopologyRef::ConnectionClosed { conn } => {
                self.event(at, &Event::new("conn", "close").conn(conn));
            }
            _ => {}
        }
    }

    fn wanted(source: &str, kind: &str) -> bool {
        matches!(
            (source, kind),
            ("http", "request")
                | ("tls", "handshake")
                | ("dns", "query")
                | ("net", "blocked")
                | ("conn", "open")
                | ("conn", "close")
        )
    }

    /// A `net.blocked` event a world reports for a sandbox it answers itself.
    fn named_block(source: &str, kind: &str) -> bool {
        (source, kind) == ("net", "blocked")
    }

    fn event(&self, at: f64, event: &Event) {
        let named = || {
            Self::named_block(event.source, event.kind)
                .then(|| event.str("sandbox").map(str::to_owned))
                .flatten()
        };
        let Some(sandbox) = event
            .conn
            .sandbox
            .as_ref()
            .map(|s| s.name.to_string())
            .or_else(named)
        else {
            return;
        };
        let mut state = self.state.lock();
        let state = &mut *state;
        if event.is_truncated() {
            state.lost += 1;
            state.changed = true;
        }
        let local = event.conn.local.map(address);
        let transport = event.conn.transport.as_str();
        let conn = event
            .conn
            .id
            .zip(local.clone())
            .map(|(id, local)| (sandbox.clone(), local, id));
        match (event.source, event.kind) {
            ("conn", "open") => {
                if let (Some(key), Some(local)) = (conn, local) {
                    if state.open.contains_key(&key) {
                        return;
                    }
                    if state.open.len() >= self.limits.connections {
                        state.dropped += 1;
                        state.changed = true;
                    } else {
                        state.open.insert(
                            key,
                            Open {
                                address: local,
                                transport,
                                sni: event.conn.sni.as_deref().map(str::to_owned),
                                counted: false,
                                first: at,
                                service: None,
                            },
                        );
                        state.changed = true;
                    }
                }
            }
            ("conn", "close") => {
                if let Some(open) = conn.and_then(|key| state.open.remove(&key))
                    && !open.counted
                {
                    let by = open
                        .service
                        .or_else(|| open.sni.clone())
                        .unwrap_or_else(|| "a world service".into());
                    let name = open.sni.or_else(|| {
                        state
                            .names
                            .get(&(sandbox.clone(), ip_of(&open.address).into()))
                            .cloned()
                    });
                    let row = Row {
                        sandbox: &sandbox,
                        address: open.address,
                        transport: open.transport,
                        name,
                        outcome: Outcome::Served,
                        by,
                    };
                    state.add(&self.limits, row, at, Count::Connection);
                }
            }
            ("tls", "handshake") => {
                let sni = event.str("sni").map(str::to_owned);
                if let Some(open) = conn.as_ref().and_then(|key| state.open.get_mut(key)) {
                    open.sni.clone_from(&sni);
                }
                if let Some(outcome) = event.str("outcome")
                    && outcome != "accepted"
                {
                    let address = local.unwrap_or_else(|| "-".into());
                    let row = Row {
                        name: sni.clone(),
                        sandbox: &sandbox,
                        address,
                        transport,
                        outcome: Outcome::Refused,
                        by: match outcome {
                            "rejected" => "no site for that name".into(),
                            "timed_out" => "TLS handshake timed out".into(),
                            other => format!("TLS handshake {other}"),
                        },
                    };
                    // A connection the table does not follow still counts here.
                    if !matches!(state.connection(conn.as_ref()), Seen::Counted) {
                        state.add(&self.limits, row, at, Count::Connection);
                    }
                }
            }
            ("http", "request") => {
                let host = event
                    .str("host")
                    .map(str::to_owned)
                    .or_else(|| event.conn.sni.as_deref().map(str::to_owned));
                let address = local.unwrap_or_else(|| "-".into());
                if let Some(host) = &host {
                    state.name(&self.limits, &sandbox, ip_of(&address), host);
                }
                let (outcome, by) = if let Some(origin) = event.str("forwarded") {
                    (Outcome::Forwarded, origin.to_owned())
                } else if let Some(service) = event.str("served_by") {
                    (Outcome::Served, service.into())
                } else {
                    match event.str("answer") {
                        Some("misdirected") => (Outcome::Refused, "no site for that name".into()),
                        Some("no_host") => (Outcome::Refused, "no Host header".into()),
                        Some("too_large") => (
                            Outcome::Refused,
                            "the site turned it down: request too large".into(),
                        ),
                        Some("timeout") if event.str("received") == Some("timeout") => (
                            Outcome::Refused,
                            "the site turned it down: request body timed out".into(),
                        ),
                        Some("budget") => (
                            Outcome::Refused,
                            "the site turned it down: request budget exhausted".into(),
                        ),
                        _ => (
                            Outcome::Served,
                            event
                                .str("world_site")
                                .map(str::to_owned)
                                .unwrap_or_else(|| "an unnamed HTTP service".into()),
                        ),
                    }
                };
                let row = Row {
                    sandbox: &sandbox,
                    address,
                    transport,
                    name: host,
                    outcome,
                    by,
                };
                if let Seen::New = state.connection(conn.as_ref()) {
                    state.add(&self.limits, row.clone(), at, Count::Connection);
                }
                let unanswered =
                    matches!(event.str("answer"), Some("cancelled" | "cut_off" | "error"))
                        || event.get("status").is_none_or(|value| value.is_null())
                        || event
                            .get("complete")
                            .is_some_and(|value| value.as_bool() == Some(false));
                state.add(
                    &self.limits,
                    row,
                    at,
                    Count::Requests(1, u64::from(unanswered)),
                );
            }
            ("dns", "query") => {
                let name = event.str("name").map(str::to_owned);
                let answer = match event.str("answer") {
                    Some("addr") => event.str("addr").unwrap_or("an address").to_owned(),
                    Some("nxdomain") => "no such name".into(),
                    Some("nodata") => match event.u64("qtype") {
                        Some(1) => "no A record".into(),
                        Some(28) => "no AAAA record".into(),
                        Some(other) => format!("no type {other} record"),
                        None => "no record of that type".into(),
                    },
                    Some("error") => match event.u64("rcode") {
                        Some(rcode) => format!("error {rcode}"),
                        None => "error".into(),
                    },
                    _ => "no answer".into(),
                };
                if let Some(name) = &name {
                    if event.str("answer") == Some("addr")
                        && let Some(addr) = event.str("addr")
                    {
                        state.name(&self.limits, &sandbox, addr, name);
                    }
                    state.lookup(&self.limits, &sandbox, name, answer, at);
                }
                let row = Row {
                    sandbox: &sandbox,
                    address: local.unwrap_or_else(|| "-".into()),
                    transport,
                    name: None,
                    outcome: if event.str("answer") == Some("none") {
                        Outcome::Refused
                    } else {
                        Outcome::Served
                    },
                    by: if event.str("answer") == Some("none") {
                        "the world's DNS gave no answer"
                    } else {
                        "the world's DNS"
                    }
                    .into(),
                };
                if let Seen::New = state.connection(conn.as_ref()) {
                    state.add(&self.limits, row.clone(), at, Count::Connection);
                }
                state.add(
                    &self.limits,
                    row,
                    at,
                    Count::Requests(1, u64::from(event.str("answer") == Some("none"))),
                );
            }
            ("net", "blocked") => {
                let why = event.str("why").unwrap_or("");
                let (outcome, by) = match why {
                    "ClosedPort" => (Outcome::Refused, "port closed"),
                    "TooManyConnections" => (Outcome::Refused, "too many connections"),
                    "NoRoute" => (Outcome::NoRoute, "no machine at that address"),
                    "Ipv6" => (Outcome::NoRoute, "IPv6 is off"),
                    "OtherSandbox" => (Outcome::NoRoute, "another sandbox's address"),
                    "Broadcast" => (Outcome::NoRoute, "broadcast"),
                    "NotItsAddress" => (Outcome::NoRoute, "not its own source address"),
                    _ => (Outcome::NoRoute, "malformed packet"),
                };
                let dst = event.str("dst");
                let port = event.u64("dst_port");
                let address = match (dst, port) {
                    (Some(dst), Some(port)) if dst.contains(':') => format!("[{dst}]:{port}"),
                    (Some(dst), Some(port)) => format!("{dst}:{port}"),
                    (Some(dst), None) => dst.to_owned(),
                    (None, _) => "-".into(),
                };
                let transport = match event.u64("protocol") {
                    Some(1) => "icmp".to_owned(),
                    Some(6) => "tcp".to_owned(),
                    Some(17) => "udp".to_owned(),
                    Some(58) => "icmpv6".to_owned(),
                    Some(other) => format!("ip {other}"),
                    None => "-".to_owned(),
                };
                let name =
                    dst.and_then(|dst| state.names.get(&(sandbox.clone(), dst.into())).cloned());
                let row = Row {
                    sandbox: &sandbox,
                    address,
                    transport: &transport,
                    name,
                    outcome,
                    by: by.into(),
                };
                let count = event.u64("count").unwrap_or(1).max(1);
                state.add(&self.limits, row, at, Count::Packets(count));
            }
            _ => return,
        }
        if std::mem::take(&mut state.changed) {
            state.revision += 1;
            state.at = state.at.max(at);
        }
    }
}

#[derive(Clone)]
struct Row<'a> {
    sandbox: &'a str,
    address: String,
    transport: &'a str,
    name: Option<String>,
    outcome: Outcome,
    by: String,
}

#[derive(Clone, Copy)]
enum Count {
    Connection,
    Requests(u64, u64),
    Packets(u64),
}

/// What the table knew about an event's connection.
enum Seen {
    /// It follows the connection, which this event counts now.
    New,
    /// It follows the connection, already counted.
    Counted,
    /// It does not follow the connection.
    Untracked,
}

impl State {
    /// Marks a followed connection counted, saying whether it already was.
    fn connection(&mut self, key: Option<&ConnKey>) -> Seen {
        match key.and_then(|key| self.open.get_mut(key)) {
            Some(open) if !open.counted => {
                open.counted = true;
                Seen::New
            }
            Some(_) => Seen::Counted,
            None => Seen::Untracked,
        }
    }

    fn name(&mut self, limits: &EgressLimits, sandbox: &str, ip: &str, name: &str) {
        let key = (sandbox.to_owned(), ip.to_owned());
        if self.names.contains_key(&key) || self.names.len() < limits.names {
            self.names.insert(key, name.to_owned());
        } else {
            self.dropped += 1;
            self.changed = true;
        }
    }

    fn lookup(
        &mut self,
        limits: &EgressLimits,
        sandbox: &str,
        name: &str,
        answer: String,
        at: f64,
    ) {
        let key = (sandbox.to_owned(), name.to_owned(), answer);
        if let Some(lookup) = self.lookups.get_mut(&key) {
            lookup.count += 1;
            lookup.last = at;
        } else if self.lookups.len() >= limits.lookups {
            self.dropped += 1;
        } else {
            self.lookups.insert(
                key.clone(),
                Lookup {
                    sandbox: key.0,
                    name: key.1,
                    answer: key.2,
                    count: 1,
                    first: at,
                    last: at,
                },
            );
        }
        self.changed = true;
    }

    fn add(&mut self, limits: &EgressLimits, row: Row<'_>, at: f64, count: Count) {
        let amount = match count {
            Count::Connection => 1,
            Count::Requests(n, _) | Count::Packets(n) => n,
        };
        self.changed = true;
        let key = (
            row.sandbox.to_owned(),
            row.address,
            row.transport.to_owned(),
            row.outcome,
            row.by,
        );
        if !self.rows.contains_key(&key) && self.rows.len() >= limits.rows {
            self.dropped += amount;
            return;
        }
        let entry = self.rows.entry(key).or_insert_with_key(|key| Destination {
            sandbox: key.0.clone(),
            address: key.1.clone(),
            transport: key.2.clone(),
            name: None,
            outcome: key.3,
            by: key.4.clone(),
            connections: 0,
            requests: 0,
            unanswered: 0,
            packets: 0,
            first: at,
            last: at,
        });
        if entry.name.is_none() {
            entry.name = row.name;
        }
        match count {
            Count::Connection => entry.connections += 1,
            Count::Requests(n, unanswered) => {
                entry.requests += n;
                entry.unanswered += unanswered;
            }
            Count::Packets(n) => entry.packets += n,
        }
        entry.first = entry.first.min(at);
        entry.last = entry.last.max(at);
    }
}

impl Observer for Egress {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(meta, conn)
            if conn.sandbox.is_some() && Self::wanted(meta.source, meta.kind)
                || Self::named_block(meta.source, meta.kind))
            || matches!(
                interest,
                Interest::Topology(TopologyKind::Connection | TopologyKind::Host)
            )
    }

    fn observe(&self, stamp: Stamp, item: Observation<'_>) {
        let at = stamp.at.since_start().as_secs_f64();
        match item {
            Observation::Event(event) if Self::wanted(event.source, event.kind) => {
                self.event(at, event)
            }
            Observation::Topology(item) => self.topology(at, item),
            _ => {}
        }
    }

    fn lost(&self, loss: Loss) {
        if matches!(loss.stream, Stream::Events | Stream::Topology) && loss.count > 0 {
            let mut state = self.state.lock();
            state.lost += loss.count;
            state.revision += 1;
        }
    }
}

#[cfg(test)]
mod tests;
