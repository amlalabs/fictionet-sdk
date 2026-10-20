//! Bounded observations for Border. Certificates are fixed world data, made once
//! at startup and carried in this view. Routing stays in its authoritative topic.
//! Callbacks retain typed public fields only; a worker serializes replacement
//! snapshots without waiting for browsers. Machine addresses stay distinct from
//! the public destination on the guest link.

use super::{
    certificates::Certificates,
    trace::{Trace, Tracker},
};
use border_world::scenario::{BANK_ADDR, IMPOSTOR_ADDR, Identity, Scenario};
use fictionet::{
    events::{
        Event, Interest, Observation, Observer, Side, Stamp, Stream, TopologyKind, TopologyRef,
    },
    sync::Mutex,
    time::Instant,
};
use fictionet_observe::page::{StateLimits, StateTopic};
use serde::Serialize;
use std::{collections::VecDeque, net::Ipv4Addr, sync::Arc};

/// How many rows a [`Rows`] keeps unless it names its own bound.
pub(super) const ROWS: usize = 32;
const SANDBOXES: usize = 8;
const TEXT: usize = 256;

#[derive(Clone, Debug, Serialize)]
pub struct Rows<T, const N: usize = ROWS> {
    pub rows: VecDeque<T>,
    pub dropped: u64,
}
impl<T, const N: usize> Default for Rows<T, N> {
    fn default() -> Self {
        Self {
            rows: VecDeque::new(),
            dropped: 0,
        }
    }
}
impl<T, const N: usize> Rows<T, N> {
    /// Keeps `row`, dropping the oldest row once `N` are kept.
    pub(super) fn push(&mut self, row: T) {
        if self.rows.len() == N {
            self.rows.pop_front();
            self.dropped += 1;
        }
        self.rows.push_back(row);
    }
    /// Drops the row at `index`, counting it.
    pub(super) fn drop_at(&mut self, index: usize) {
        if self.rows.remove(index).is_some() {
            self.dropped += 1;
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Address {
    pub machine: Ipv4Addr,
    pub reached: Ipv4Addr,
}
impl Address {
    /// The only address translation in the page projection. The world's facts
    /// name the real endpoint; guest packets retain the bank's public address.
    fn new(machine: Ipv4Addr) -> Self {
        Self {
            machine,
            reached: if machine == IMPOSTOR_ADDR {
                BANK_ADDR
            } else {
                machine
            },
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Tls {
    pub peer: Option<std::net::SocketAddr>,
    pub port: Option<u16>,
    pub at_ms: u64,
    pub event: u64,
    pub sandbox: String,
    pub connection: Option<u64>,
    pub sni: String,
    pub endpoint: Address,
    pub identity: Option<Identity>,
    pub outcome: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Moment {
    pub peer: Option<std::net::SocketAddr>,
    pub port: Option<u16>,
    pub at_ms: u64,
    pub event: u64,
    pub sandbox: String,
    pub connection: Option<u64>,
    pub endpoint: Address,
    pub method: String,
    pub path: String,
    pub password: bool,
    pub payee: Option<String>,
    pub amount_pence: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Bgp {
    pub at_ms: u64,
    pub event: u64,
    pub sandbox: String,
    pub kind: String,
    pub message: String,
    pub announced: Vec<String>,
    pub withdrawn: Vec<String>,
    pub detail: String,
}
/// A guest link and its last traceroute. A link that has ended keeps its
/// last trace, so a stopped run still shows the path the guest saw.
#[derive(Clone, Debug, Serialize)]
pub struct GuestLink {
    pub sandbox: String,
    pub link: u64,
    pub ended_ms: Option<u64>,
    pub trace: Option<Trace>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct View {
    pub config: Option<Config>,
    pub certificates: Certificates,
    pub links: Vec<GuestLink>,
    pub bgp: Rows<Bgp>,
    pub tls: Rows<Tls>,
    pub moments: Rows<Moment>,
    pub lost: u64,
    pub truncated: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Country {
    pub name: &'static str,
    pub asn: u16,
    pub router: Ipv4Addr,
}
#[derive(Clone, Debug, Serialize)]
pub struct Config {
    pub guest: &'static str,
    pub bank: Ipv4Addr,
    pub impostor: Ipv4Addr,
    pub normal_ms: u64,
    pub hijacked_ms: u64,
    pub countries: Vec<Country>,
}
struct Link {
    id: u64,
    sandbox: String,
    ended_ms: Option<u64>,
    tracker: Tracker,
}
struct State {
    view: View,
    links: Vec<Link>,
    at: Instant,
}
impl State {
    fn view(&self) -> View {
        let mut view = self.view.clone();
        view.links = self
            .links
            .iter()
            .map(|link| GuestLink {
                sandbox: link.sandbox.clone(),
                link: link.id,
                ended_ms: link.ended_ms,
                trace: link.tracker.trace.clone(),
            })
            .collect();
        view
    }
    /// Border registers the guest attachment before the inner Sites attachment
    /// with the same name, so only the first link of a sandbox is captured. A
    /// guest that attaches again after its link ended replaces the ended link.
    /// Returns whether the view changed.
    fn link_added(&mut self, id: u64, sandbox: &str) -> bool {
        let existing = self.links.iter().position(|l| l.sandbox == sandbox);
        if existing.is_some_and(|i| self.links[i].ended_ms.is_none()) {
            return false;
        }
        if existing.is_none() && self.links.len() == SANDBOXES {
            self.view.lost += 1;
            return true;
        }
        let link = Link {
            id,
            sandbox: text(sandbox, &mut self.view.truncated),
            ended_ms: None,
            tracker: Tracker::default(),
        };
        match existing {
            Some(i) => self.links[i] = link,
            None => self.links.push(link),
        }
        true
    }
    fn link_removed(&mut self, id: u64, at_ms: u64) {
        if let Some(link) = self.links.iter_mut().find(|l| l.id == id) {
            link.ended_ms.get_or_insert(at_ms);
        }
    }
    /// The run's end closes every link still open. A link removed earlier
    /// keeps its own end time.
    fn run_ended(&mut self, at_ms: u64) {
        for link in &mut self.links {
            link.ended_ms.get_or_insert(at_ms);
        }
    }
}
struct Inner {
    state: Arc<Mutex<State>>,
    changed: tokio::sync::watch::Sender<()>,
}
#[derive(Clone)]
pub struct Projection {
    inner: Arc<Inner>,
    scenario: Arc<Scenario>,
    pub topic: StateTopic<View>,
    pub tls: super::tls::Capture,
}

impl Projection {
    pub fn new(scenario: Arc<Scenario>) -> Self {
        let (changed, mut changes) = tokio::sync::watch::channel(());
        let config = Config {
            guest: super::guest::HOSTNAME,
            bank: BANK_ADDR,
            impostor: IMPOSTOR_ADDR,
            normal_ms: (scenario
                .routed(border_world::scenario::Variant::Legitimate)
                .one_way(BANK_ADDR)
                * 2)
            .as_millis() as u64,
            hijacked_ms: (scenario
                .routed(border_world::scenario::Variant::Hijack)
                .one_way(BANK_ADDR)
                * 2)
            .as_millis() as u64,
            countries: [
                border_world::scenario::HOME,
                border_world::scenario::FOREIGN,
            ]
            .map(|c| Country {
                name: c.name,
                asn: c.asn,
                router: c.router,
            })
            .to_vec(),
        };
        let inner = Arc::new(Inner {
            state: Arc::new(Mutex::new(State {
                view: View {
                    config: Some(config),
                    ..View::default()
                },
                links: vec![],
                at: Instant::ZERO,
            })),
            changed,
        });
        let topic = StateTopic::new(StateLimits {
            max_bytes: 256 << 10,
        });
        // The worker ends once every projection is dropped. A change made just
        // before that, such as the run ending, is still published.
        let state = inner.state.clone();
        let output = topic.clone();
        tokio::spawn(async move {
            loop {
                let (at, view) = {
                    let state = state.lock();
                    (state.at, state.view())
                };
                // StateTopic retains a visible failure marker if a bound is exceeded.
                let _ = output.publish(at, &view);
                if changes.changed().await.is_err() {
                    break;
                }
            }
        });
        Self {
            inner,
            scenario,
            topic,
            tls: super::tls::Capture::new(),
        }
    }
    pub fn certificates(&self, at: Instant, certificates: Certificates) {
        let mut state = self.inner.state.lock();
        state.at = at;
        state.view.certificates = certificates;
        self.inner.changed.send_replace(());
    }
}

fn text(value: &str, truncated: &mut u64) -> String {
    let clean = border_world::events::redact_path(value);
    let mut end = clean.len().min(TEXT);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    if end < clean.len() {
        *truncated += 1;
    }
    clean[..end].into()
}
fn sandbox(e: &Event) -> &str {
    e.str("sandbox")
        .or_else(|| e.conn.sandbox.as_ref().map(|s| &*s.name))
        .unwrap_or("unknown")
}

impl View {
    fn event(&mut self, scenario: &Scenario, e: &Event) {
        let at_ms = e.at.since_start().as_millis() as u64;
        let sandbox = text(sandbox(e), &mut self.truncated);
        match (e.source, e.kind) {
            ("tls", "handshake") => {
                let Some(machine) = e.str("addr").and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
                    return;
                };
                let sni = e.str("sni").unwrap_or_default();
                self.tls.push(Tls {
                    peer: e.conn.peer,
                    port: e.conn.local.map(|a| a.port()),
                    at_ms,
                    event: e.seq,
                    sandbox,
                    connection: e.conn.id,
                    endpoint: Address::new(machine),
                    identity: scenario.identity(sni, machine),
                    sni: text(sni, &mut self.truncated),
                    outcome: text(e.str("outcome").unwrap_or("unknown"), &mut self.truncated),
                });
            }
            ("bgp", _) => {
                let mut prefixes = |name| {
                    let mut out = vec![];
                    if let Some(values) = e.get(name).and_then(|v| v.as_array()) {
                        for value in values.iter().take(8) {
                            if let Some(s) = value.as_str() {
                                out.push(text(s, &mut self.truncated));
                            }
                        }
                        self.truncated += values.len().saturating_sub(8) as u64;
                    }
                    out
                };
                let mut announced = prefixes("announced");
                let withdrawn = prefixes("withdrawn");
                if let Some(prefix) = e
                    .get("route")
                    .and_then(|v| v.get("prefix"))
                    .and_then(|v| v.as_str())
                {
                    announced.push(text(prefix, &mut self.truncated));
                }
                self.bgp.push(Bgp {
                    at_ms,
                    event: e.seq,
                    sandbox,
                    kind: e.kind.into(),
                    message: text(e.str("message").unwrap_or_default(), &mut self.truncated),
                    announced,
                    withdrawn,
                    detail: text(e.str("reason").unwrap_or_default(), &mut self.truncated),
                });
            }
            ("http", "request") if e.str("served_by") == Some("impostor") => {
                let password = e.get("carries_password").and_then(|v| v.as_bool()) == Some(true);
                let payment = e.str("page") == Some("payment");
                if !password && !payment {
                    return;
                }
                let Some(std::net::IpAddr::V4(machine)) = e.conn.local.map(|a| a.ip()) else {
                    return;
                };
                self.moments.push(Moment {
                    peer: e.conn.peer,
                    port: e.conn.local.map(|a| a.port()),
                    at_ms,
                    event: e.seq,
                    sandbox,
                    connection: e.conn.id,
                    endpoint: Address::new(machine),
                    password,
                    method: text(e.str("method").unwrap_or_default(), &mut self.truncated),
                    path: text(
                        e.str("path")
                            .unwrap_or_default()
                            .split('?')
                            .next()
                            .unwrap_or_default(),
                        &mut self.truncated,
                    ),
                    payee: e.str("payee").map(|v| text(v, &mut self.truncated)),
                    amount_pence: e.u64("amount_pence"),
                });
            }
            _ => {}
        }
    }
}
impl Observer for Projection {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        match interest {
            Interest::Event(m, _) => {
                m.source == "bgp"
                    || (m.source == "tls" && m.kind == "handshake")
                    || (m.source == "http" && m.kind == "request")
            }
            Interest::Topology(TopologyKind::Link) | Interest::Packet(_) => true,
            _ => false,
        }
    }
    fn observe(&self, stamp: Stamp, item: Observation<'_>) {
        let mut state = self.inner.state.lock();
        state.at = stamp.at;
        match item {
            Observation::Event(e) => state.view.event(&self.scenario, e),
            Observation::Topology(TopologyRef::LinkAdded {
                link,
                sandbox: Some(sandbox),
                ..
            }) => {
                if !state.link_added(link.get(), sandbox) {
                    return;
                }
            }
            Observation::Topology(TopologyRef::LinkRemoved { link, .. }) => {
                state.link_removed(link.get(), stamp.at.since_start().as_millis() as u64);
            }
            Observation::Packet(p) => {
                let Some(link) = state.links.iter_mut().find(|l| l.id == p.link.get()) else {
                    return;
                };
                self.tls.packet(
                    link.id,
                    &link.sandbox,
                    stamp.at.since_start().as_millis() as u64,
                    p.bytes,
                );
                link.tracker.packet(
                    stamp.at.since_start().as_millis() as u64,
                    p.side == Side::B,
                    p.bytes,
                );
            }
            _ => return,
        }
        self.inner.changed.send_replace(());
    }
    fn lost(&self, loss: fictionet::events::Loss) {
        if matches!(
            loss.stream,
            Stream::Events | Stream::Packets(_) | Stream::Topology
        ) {
            self.inner.state.lock().view.lost += loss.count;
            self.inner.changed.send_replace(());
        }
    }
    fn end(&self, at: Instant) {
        let mut state = self.inner.state.lock();
        state.at = at;
        state.run_ended(at.since_start().as_millis() as u64);
        self.inner.changed.send_replace(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{events::ConnInfo, stdlib::protocols::json::Value as J};
    #[test]
    fn announcements_withdrawals_and_impostor_sessions_keep_their_identity() {
        let scenario = super::super::control::scenario();
        let mut view = View::default();
        view.event(
            &scenario,
            &Event::new("bgp", "sent").field("message", "UPDATE").field(
                "route",
                J::Object(vec![("prefix".into(), "84.21.44.0/25".into())]),
            ),
        );
        view.event(
            &scenario,
            &Event::new("bgp", "sent")
                .field("message", "UPDATE")
                .field("withdrawn", J::Array(vec!["84.21.44.0/25".into()])),
        );
        assert_eq!(view.bgp.rows[0].announced, ["84.21.44.0/25"]);
        assert_eq!(view.bgp.rows[1].withdrawn, ["84.21.44.0/25"]);
        let conn = ConnInfo::new(
            7,
            "45.144.30.10:443".parse().unwrap(),
            "192.168.1.2:40000".parse().unwrap(),
        );
        view.event(
            &scenario,
            &Event::new("tls", "handshake")
                .conn(&conn)
                .field("addr", "45.144.30.10")
                .field("sni", "kestrelmoor.co.uk")
                .field("outcome", "ok"),
        );
        let tls = &view.tls.rows[0];
        assert_eq!(tls.identity, Some(Identity::Impostor));
        assert_eq!(tls.endpoint.machine, IMPOSTOR_ADDR);
        assert_eq!(tls.endpoint.reached, BANK_ADDR);
        assert_eq!(tls.connection, Some(7));
        let password = border_world::bank::ACCOUNT.password;
        view.event(
            &scenario,
            &Event::new("http", "request")
                .conn(&conn)
                .field("served_by", "impostor")
                .field("carries_password", true)
                .field("path", format!("/login/{password}?password={password}"))
                .field("method", "POST")
                .field("payee", password.to_uppercase()),
        );
        assert_eq!(view.moments.rows.len(), 1);
        let m = &view.moments.rows[0];
        assert_eq!(m.path, "/login/[password]");
        assert_eq!(m.connection, Some(7));
        assert_eq!(m.endpoint.machine, IMPOSTOR_ADDR);
        assert_eq!(m.endpoint.reached, BANK_ADDR);
        assert!(
            !serde_json::to_string(&view)
                .unwrap()
                .to_lowercase()
                .contains(&password.to_lowercase())
        );
    }
    #[test]
    fn every_history_is_bounded_and_marks_dropped_rows() {
        let mut view = View::default();
        let scenario = super::super::control::scenario();
        let conn = ConnInfo::new(
            7,
            "45.144.30.10:443".parse().unwrap(),
            "192.168.1.2:40000".parse().unwrap(),
        );
        for _ in 0..100 {
            view.event(
                &scenario,
                &Event::new("bgp", "established").field("sandbox", "x".repeat(1024)),
            );
            view.event(
                &scenario,
                &Event::new("tls", "handshake")
                    .field("addr", "45.144.30.10")
                    .field("sni", "x".repeat(1024)),
            );
            view.event(
                &scenario,
                &Event::new("http", "request")
                    .conn(&conn)
                    .field("served_by", "impostor")
                    .field("page", "payment")
                    .field("payee", "x".repeat(1024)),
            );
        }
        for (count, dropped) in [
            (view.bgp.rows.len(), view.bgp.dropped),
            (view.tls.rows.len(), view.tls.dropped),
            (view.moments.rows.len(), view.moments.dropped),
        ] {
            assert_eq!(count, ROWS);
            assert_eq!(dropped, 68);
        }
        assert_eq!(view.truncated, 300);
        assert!(serde_json::to_vec(&view).unwrap().len() < 256 << 10);
    }
    #[test]
    fn an_ended_guest_link_keeps_its_last_trace() {
        let mut state = State {
            view: View::default(),
            links: vec![],
            at: Instant::ZERO,
        };
        assert!(state.link_added(3, "rw-desktop"));
        // The inner Sites attachment with the same name is not captured.
        assert!(!state.link_added(4, "rw-desktop"));
        state.links[0].tracker.trace = Some(Trace {
            started_ms: 10,
            updated_ms: 40,
            complete: true,
            ..Trace::default()
        });
        state.link_removed(4, 50);
        assert_eq!(state.view().links[0].ended_ms, None);
        state.link_removed(3, 60);
        state.link_removed(3, 70);
        let view = state.view();
        assert_eq!(view.links.len(), 1);
        assert_eq!(view.links[0].ended_ms, Some(60));
        let trace = view.links[0].trace.as_ref().unwrap();
        assert!(trace.complete);
        assert_eq!(trace.started_ms, 10);
        // A guest attached again replaces its ended link and starts without a trace.
        assert!(state.link_added(5, "rw-desktop"));
        let view = state.view();
        assert_eq!(view.links.len(), 1);
        assert_eq!((view.links[0].link, view.links[0].ended_ms), (5, None));
        assert!(view.links[0].trace.is_none());
        // Links stay bounded, ended or not, and an extra sandbox counts as lost.
        for n in 0..SANDBOXES {
            state.link_added(10 + n as u64, &format!("guest-{n}"));
        }
        assert_eq!(state.links.len(), SANDBOXES);
        assert_eq!(state.view.lost, 1);
        // The run's end closes the open links; an earlier removal keeps its time.
        state.link_removed(10, 90);
        state.run_ended(100);
        let ended: Vec<_> = state.view().links.iter().map(|l| l.ended_ms).collect();
        assert_eq!(ended[..2], [Some(100), Some(90)]);
        assert!(ended.iter().all(Option::is_some));
    }
}
