use std::sync::Arc;
use std::time::{Duration, Instant};

use fictionet::events::{Interest, Loss, Observation, Observer, Stamp};
use fictionet::sync::Mutex;
use fictionet::time::Instant as RunTime;

use crate::egress::{Egress, EgressLimits, EgressSnapshot};
use crate::export::{Export, Selection};
use crate::json::{self, Object, Scalar};
use crate::watch::{Subscription as Hold, Watches};
use crate::{Collector, Options, Registry, Value, view};

/// How often a graph subscription sends what changed.
const GRAPH_TICK: Duration = Duration::from_millis(250);
/// How often a packet subscription looks for new packets.
pub(crate) const PACKET_TICK: Duration = Duration::from_millis(100);
/// Packet rows one poll sends to one subscription.
const ROWS_PER_POLL: usize = 500;
/// Subscriptions and capture downloads one session may hold.
const MAX_SUBSCRIPTIONS: usize = 64;

/// Collector limits, capture policies and packet decoding, fixed before
/// the run starts.
#[derive(Clone, Debug)]
pub struct DashboardOptions {
    /// All retention limits and capture policies.
    pub collector: Options,
    /// The protocols that link watches decode with. The default is the
    /// built-in registry.
    pub protocols: Registry,
    /// The most links watched at once. At capacity, a new link evicts the
    /// longest-idle watch, with the lowest link id breaking ties. When every
    /// watch has a subscriber, the request is refused. The default is 64.
    pub watches: usize,
    /// The most bytes of decoded rows kept across all watches. Past it, idle
    /// watches are forgotten first, longest idle first, then the oldest rows
    /// of any watch. Each watch also keeps at most 4,096 rows and 32 MiB.
    /// The default is 256 MiB.
    pub watch_bytes: usize,
    /// Bounds on the left-the-box table, [`DashboardHandle::egress`].
    pub egress: EgressLimits,
}

impl Default for DashboardOptions {
    fn default() -> Self {
        Self {
            collector: Options {
                policy: crate::policy::watched(),
                ..Options::default()
            },
            protocols: Registry::default(),
            watches: 64,
            watch_bytes: 256 << 20,
            egress: EgressLimits::default(),
        }
    }
}

/// A dashboard's observer and request service for one run.
pub struct DashboardObserver(Arc<Shared>);

/// A cheap handle usable before, during and after the run.
#[derive(Clone)]
pub struct DashboardHandle(pub(crate) Arc<Shared>);

pub(crate) struct Shared {
    pub(crate) collector: Collector,
    pub(crate) watches: Watches,
    egress: Egress,
    clock: Mutex<Clock>,
}

impl Shared {
    /// When the run started, since the Unix epoch. Labs have none.
    pub(crate) fn wall(&self) -> Option<Duration> {
        self.clock.lock().wall
    }
}

#[derive(Clone, Copy, Default)]
struct Clock {
    begun: bool,
    wall: Option<Duration>,
    at: Duration,
}

impl Observer for Shared {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        matches!(interest, Interest::Event(meta, _) if meta.source == "run" && meta.kind == "start")
            || self.collector.enabled(interest)
            || self.egress.enabled(interest)
    }

    fn observe(&self, stamp: Stamp, item: Observation<'_>) {
        {
            let mut clock = self.clock.lock();
            clock.begun = true;
            clock.at = clock.at.max(stamp.at.since_start());
            if let Observation::Event(event) = item
                && event.source == "run"
                && event.kind == "start"
            {
                clock.wall = event
                    .get("wall")
                    .and_then(|v| v.as_f64())
                    .and_then(|v| Duration::try_from_secs_f64(v).ok());
            }
        }
        self.egress.observe(stamp, item.clone());
        self.collector.observe(stamp, item);
    }
    fn lost(&self, loss: Loss) {
        self.egress.lost(loss.clone());
        self.collector.lost(loss);
    }
    fn end(&self, at: RunTime) {
        self.collector.end(at);
    }
}

impl DashboardObserver {
    /// Builds the collector before a run or any clients exist.
    pub fn new(options: DashboardOptions) -> Self {
        Self(Arc::new(Shared {
            watches: Watches::new(options.protocols, options.watches, options.watch_bytes),
            collector: Collector::with_options(options.collector),
            egress: Egress::new(options.egress),
            clock: Mutex::new(Clock::default()),
        }))
    }
    /// The observer to install in run options or a fanout.
    pub fn observer(&self) -> Arc<dyn Observer> {
        self.0.clone()
    }
    /// Gets a handle to the request service.
    pub fn handle(&self) -> DashboardHandle {
        DashboardHandle(self.0.clone())
    }
}

impl DashboardHandle {
    /// Creates one caller's session with a limit of 64 subscriptions and
    /// capture downloads. No thread or clock read is needed to drive it.
    pub fn session(&self) -> Session {
        Session {
            handle: self.clone(),
            subs: Vec::new(),
            downloads: Vec::new(),
        }
    }
    /// Every connection attempt from each sandbox so far, grouped by
    /// destination, with what the world did with it. See [`Egress`].
    pub fn egress(&self) -> EgressSnapshot {
        self.0.egress.snapshot()
    }
    pub(crate) fn begun(&self) -> bool {
        self.0.clock.lock().begun || self.0.collector.ended().is_some()
    }
    pub(crate) fn started(&self) -> String {
        self.0
            .clock
            .lock()
            .wall
            .map_or_else(|| "null".into(), |d| d.as_millis().to_string())
    }
    pub(crate) fn elapsed(&self, wall: Option<Duration>) -> Duration {
        if let Some(at) = self.0.collector.ended() {
            return at.since_start();
        }
        let clock = *self.0.clock.lock();
        wall.zip(clock.wall).map_or(clock.at, |(now, start)| {
            now.saturating_sub(start).max(clock.at)
        })
    }
    fn world(&self, wall: Option<Duration>) -> String {
        let begun = self.begun();
        let ended = self.0.collector.ended().is_some();
        Object::new()
            .num("observe", 2)
            .str("fictionet", env!("CARGO_PKG_VERSION"))
            .bool("running", begun && !ended)
            .bool("ended", ended)
            .raw("started", &self.started())
            .raw(
                "t",
                &if begun {
                    format!("{:.6}", self.elapsed(wall).as_secs_f64())
                } else {
                    "null".into()
                },
            )
            .done()
    }
}

struct Subscription {
    id: u32,
    next: Instant,
    kind: Kind,
}

enum Kind {
    /// `watch`: the graph, then what changed.
    Graph {
        shown: Option<Box<view::View>>,
        after: Option<u64>,
        waiting: bool,
        next_graph: Instant,
    },
    /// `packets`: one link's decoded packets as they are captured.
    Packets { hold: Hold, cursor: u64 },
}

/// A `pcap` reply still being written.
struct Download {
    id: u32,
    next: Instant,
    export: Export,
}

/// One caller's requests and subscriptions. Transports supply monotonic time
/// for polling and optional wall time since the Unix epoch for real runs.
pub struct Session {
    handle: DashboardHandle,
    subs: Vec<Subscription>,
    downloads: Vec<Download>,
}

pub(crate) fn error(message: &str) -> String {
    Object::new().str("error", message).done()
}
fn reply(id: u32, text: String) -> Value {
    Value {
        id,
        bytes: text.into_bytes(),
        binary: false,
        end: true,
    }
}
fn event(id: u32, name: &str, data: &str) -> Value {
    Value {
        id,
        bytes: Object::new()
            .str("event", name)
            .raw("data", data)
            .done()
            .into_bytes(),
        binary: false,
        end: name == "end",
    }
}
fn link_number(req: &std::collections::HashMap<String, Scalar>) -> Option<u64> {
    req.get("link").and_then(|v| match v {
        Scalar::Str(s) => s.strip_prefix('e').unwrap_or(s).parse().ok(),
        _ => v.as_u64(),
    })
}

impl Session {
    /// Handles a flat JSON request. Streaming values arrive through `poll`.
    /// Request ids must be unique while a subscription or download is active.
    pub fn request(
        &mut self,
        id: u32,
        text: &str,
        now: Instant,
        wall: Option<Duration>,
    ) -> Vec<Value> {
        if self.subs.iter().any(|s| s.id == id) || self.downloads.iter().any(|d| d.id == id) {
            return vec![reply(id, error("request id is already active"))];
        }
        if text.len() > 65_531 {
            return vec![reply(id, error("request exceeds 65,536 bytes"))];
        }
        let Some(req) = json::parse_flat(text) else {
            return vec![reply(id, error("the request is not a flat JSON object"))];
        };
        let Some(op) = req.get("op").and_then(Scalar::as_str) else {
            return vec![reply(id, error("the request has no op"))];
        };
        let handle = &self.handle;
        let shared = &handle.0;
        let full = self.subs.len() + self.downloads.len() >= MAX_SUBSCRIPTIONS;
        let response = match op {
            "world" => handle.world(wall),
            "watch" | "packets" | "pcap" if full => {
                error("this session has too many subscriptions")
            }
            "watch" => {
                self.subs.push(Subscription {
                    id,
                    next: now,
                    kind: Kind::Graph {
                        shown: None,
                        after: req.get("after").and_then(Scalar::as_u64),
                        waiting: false,
                        next_graph: now,
                    },
                });
                return Vec::new();
            }
            "cancel" => {
                let target = req
                    .get("id")
                    .and_then(Scalar::as_u64)
                    .and_then(|id| u32::try_from(id).ok());
                if let Some(index) = self.subs.iter().position(|s| Some(s.id) == target) {
                    let sub = self.subs.remove(index);
                    let ended = event(sub.id, "end", r#"{"reason":"cancelled"}"#);
                    if let Kind::Packets { hold, .. } = sub.kind {
                        hold.release(now);
                    }
                    return vec![ended, reply(id, r#"{"ok":true}"#.into())];
                }
                error("no such subscription")
            }
            "graph" | "counters" | "events" | "keylog" | "link" | "packets" | "packet" | "pcap"
                if !handle.begun() =>
            {
                error("no world is running yet")
            }
            "graph" => view::snapshot(handle, None, wall).1.1,
            "counters" => view::counters(handle, wall),
            "events" => {
                let after = req.get("after").and_then(Scalar::as_u64).unwrap_or(0);
                let max = req
                    .get("max")
                    .and_then(Scalar::as_u64)
                    .unwrap_or(1000)
                    .min(1000) as usize;
                view::events(handle, after, max)
            }
            "keylog" => {
                return vec![Value {
                    id,
                    bytes: shared.collector.keylog().into_bytes(),
                    binary: true,
                    end: true,
                }];
            }
            "link" | "packets" | "packet" | "pcap" => {
                let Some(number) = link_number(&req) else {
                    return vec![reply(id, error("the request needs a link, such as \"e5\""))];
                };
                match op {
                    "link" => view::link(handle, number).unwrap_or_else(|| error("no such link")),
                    "packets" => {
                        let acquired =
                            shared.watches.acquire(&shared.collector, number, now, || {
                                let link = shared.collector.find_link(number)?;
                                Some((link, view::describe(handle, link)))
                            });
                        match acquired {
                            Ok(hold) => {
                                let link = event(id, "link", &hold.watch().describe());
                                let cursor = req.get("after").and_then(Scalar::as_u64).unwrap_or(0);
                                self.subs.push(Subscription {
                                    id,
                                    next: now,
                                    kind: Kind::Packets { hold, cursor },
                                });
                                return vec![link];
                            }
                            Err(reason) => error(reason),
                        }
                    }
                    "packet" => match shared.watches.existing(number, now) {
                        Some(watch) => {
                            watch.pump(shared);
                            req.get("seq")
                                .and_then(Scalar::as_u64)
                                .and_then(|seq| watch.detail(seq))
                                .unwrap_or_else(|| error("that packet is not kept"))
                        }
                        None => error("nothing is watching that link"),
                    },
                    _ => match shared.collector.find_link(number) {
                        Some(link) => {
                            let mut export = shared.collector.export(&Selection {
                                streams: vec![
                                    fictionet::events::Stream::Packets(link),
                                    fictionet::events::Stream::Keys,
                                ],
                                wall: shared.wall(),
                                ..Selection::default()
                            });
                            let (bytes, last) = export.next_chunk();
                            if !last {
                                self.downloads.push(Download {
                                    id,
                                    next: now,
                                    export,
                                });
                            }
                            return vec![Value {
                                id,
                                bytes,
                                binary: true,
                                end: last,
                            }];
                        }
                        None => error("no such link"),
                    },
                }
            }
            other => error(&format!("unknown op {other}")),
        };
        vec![reply(id, response)]
    }

    #[cfg(feature = "page")]
    pub(crate) fn drain_pending(&mut self, now: Instant) {
        for sub in &mut self.subs {
            sub.next = now;
            if let Kind::Graph { next_graph, .. } = &mut sub.kind {
                *next_graph = now;
            }
        }
    }

    /// Returns the earliest subscription or download deadline, or none
    /// when idle.
    pub fn next_poll(&self) -> Option<Instant> {
        let subs = self.subs.iter().map(|s| s.next);
        subs.chain(self.downloads.iter().map(|d| d.next)).min()
    }

    /// Produces snapshots followed by changes, events, packets and stream
    /// endings, and the next piece of each capture download.
    pub fn poll(&mut self, now: Instant, wall: Option<Duration>) -> Vec<Value> {
        let mut out = Vec::new();
        let handle = self.handle.clone();
        if !self.subs.is_empty() {
            handle.0.watches.reap(now);
        }
        let mut index = 0;
        while index < self.subs.len() {
            let sub = &mut self.subs[index];
            let done = now >= sub.next && sub.poll(&handle, now, wall, &mut out);
            if done {
                if let Kind::Packets { hold, .. } = self.subs.remove(index).kind {
                    hold.release(now);
                }
            } else {
                index += 1;
            }
        }
        self.downloads.retain_mut(|download| {
            if now < download.next {
                return true;
            }
            let (bytes, last) = download.export.next_chunk();
            out.push(Value {
                id: download.id,
                bytes,
                binary: true,
                end: last,
            });
            !last
        });
        out
    }
}

impl Subscription {
    /// Adds what is new to `out`. Returns whether the stream ended.
    fn poll(
        &mut self,
        handle: &DashboardHandle,
        now: Instant,
        wall: Option<Duration>,
        out: &mut Vec<Value>,
    ) -> bool {
        let id = self.id;
        match &mut self.kind {
            Kind::Graph {
                shown,
                after,
                waiting,
                next_graph,
            } => {
                self.next = now + GRAPH_TICK;
                if !handle.begun() {
                    if !*waiting {
                        out.push(event(id, "waiting", "{}"));
                        *waiting = true;
                    }
                    return false;
                }
                if let Some(view) = shown {
                    if now >= *next_graph {
                        out.extend(
                            view::changes(handle, view, wall)
                                .into_iter()
                                .map(|(name, data)| event(id, name, &data)),
                        );
                        *next_graph = now + GRAPH_TICK;
                    }
                    let (messages, full) = view::event_changes(handle, view);
                    out.extend(
                        messages
                            .into_iter()
                            .map(|(name, data)| event(id, name, &data)),
                    );
                    self.next = if full { now } else { *next_graph };
                } else {
                    let (view, (name, data)) = view::snapshot(handle, *after, wall);
                    out.push(event(id, name, &data));
                    *next_graph = now + GRAPH_TICK;
                    self.next = if view.events_pending(handle) {
                        now
                    } else {
                        *next_graph
                    };
                    *shown = Some(Box::new(view));
                }
                let view = shown.as_ref().expect("shown snapshot");
                let ended = view.ended() && !view.events_pending(handle);
                if ended {
                    out.push(event(id, "end", r#"{"reason":"the world ended"}"#));
                }
                ended
            }
            Kind::Packets { hold, cursor } => {
                self.next = now + PACKET_TICK;
                let shared = &handle.0;
                let watch = hold.watch();
                // Decided before decoding, so the last packets of a link
                // that closes meanwhile are still sent.
                let closing = if !shared.collector.live(watch.id()) {
                    Some("the link closed")
                } else if shared.collector.ended().is_some() {
                    Some("the world ended")
                } else {
                    None
                };
                let drained = watch.pump(shared);
                let (missed, rows) = watch.rows_after(*cursor, ROWS_PER_POLL);
                if missed > 0 {
                    let gap = crate::loss::gap(
                        fictionet::events::Stream::Packets(watch.id()),
                        None,
                        *cursor,
                        *cursor + missed + 1,
                        missed,
                    );
                    out.push(event(id, "gap", &gap));
                    *cursor += missed;
                }
                if !drained || rows.len() == ROWS_PER_POLL {
                    self.next = now;
                }
                for (seq, row) in rows {
                    out.push(event(id, "packet", &row));
                    *cursor = seq;
                }
                let ended = drained && watch.rows_after(*cursor, 1).1.is_empty();
                match closing.filter(|_| ended) {
                    Some(reason) => {
                        let data = Object::new().str("reason", reason).done();
                        out.push(event(id, "end", &data));
                        true
                    }
                    None => false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fictionet::events::{Event, Stream};
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::protocols::json::Value as Json;
    use fictionet::{Interface, InterfaceExt, Packet, RunOptions, Seed, block_on, lab};

    fn request(session: &mut Session, id: u32, text: &str, now: Instant) -> Value {
        session.request(id, text, now, None).remove(0)
    }
    fn json(value: &Value) -> Json {
        Json::parse(&value.bytes).unwrap()
    }
    fn emit(observer: &dyn Observer, seq: u64, event: Event) {
        observer.observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at: RunTime::ZERO,
            },
            Observation::Event(&event),
        );
    }
    fn names(values: &[Value]) -> Vec<String> {
        values
            .iter()
            .map(|v| match v.envelope().unwrap() {
                crate::Envelope::Event { name, .. } => name,
                crate::Envelope::Error(error) => panic!("{error}"),
            })
            .collect()
    }

    #[test]
    fn world_waits_starts_and_ends_on_the_run_clock() {
        let dashboard = DashboardObserver::new(DashboardOptions::default());
        let mut session = dashboard.handle().session();
        let now = Instant::now();
        assert_eq!(
            String::from_utf8(request(&mut session, 1, r#"{"op":"world"}"#, now).bytes).unwrap(),
            format!(
                r#"{{"observe":2,"fictionet":"{}","running":false,"ended":false,"started":null,"t":null}}"#,
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(
            request(&mut session, 5, r#"{"op":"graph"}"#, now).bytes,
            br#"{"error":"no world is running yet"}"#
        );
        session.request(2, r#"{"op":"watch"}"#, now, None);
        let waiting = session.poll(now, None);
        assert_eq!(names(&waiting), ["waiting"]);
        assert_eq!(waiting[0].bytes, br#"{"event":"waiting","data":{}}"#);
        assert!(!waiting[0].end);
        emit(
            dashboard.observer().as_ref(),
            1,
            Event::new("run", "start").field("wall", fictionet::events::float(100.5)),
        );
        let value = session
            .request(
                3,
                r#"{"op":"world"}"#,
                now,
                Some(Duration::from_millis(102_000)),
            )
            .remove(0);
        assert_eq!(
            json(&value).get("started").and_then(Json::as_u64),
            Some(100_500)
        );
        assert_eq!(json(&value).get("t").and_then(Json::as_f64), Some(1.5));
        assert_eq!(
            names(&session.poll(now + Duration::from_millis(250), None)),
            ["snapshot"]
        );
        dashboard
            .observer()
            .end(RunTime::ZERO + Duration::from_secs(2));
        let end = session.poll(now + Duration::from_millis(500), None);
        assert_eq!(names(&end), ["ended", "end"]);
        assert!(!end[0].end);
        assert!(end[1].end);
        assert!(session.next_poll().is_none());
        let value = request(&mut session, 4, r#"{"op":"world"}"#, now);
        assert_eq!(json(&value).get("t").and_then(Json::as_f64), Some(2.0));
    }

    #[test]
    fn subscriptions_are_bounded_cancelled_and_reusable() {
        let dashboard = DashboardObserver::new(DashboardOptions::default());
        let mut session = dashboard.handle().session();
        let now = Instant::now();
        for id in 1..=64 {
            assert!(
                session
                    .request(id, r#"{"op":"watch"}"#, now, None)
                    .is_empty()
            );
        }
        assert!(matches!(
            request(&mut session, 65, r#"{"op":"watch"}"#, now).envelope(),
            Some(crate::Envelope::Error(_))
        ));
        assert_eq!(
            request(&mut session, 66, r#"{"op":"cancel","id":4294967297}"#, now).bytes,
            br#"{"error":"no such subscription"}"#
        );
        assert_eq!(session.subs.len(), 64);
        let cancelled = session.request(67, r#"{"op":"cancel","id":1}"#, now, None);
        assert_eq!(cancelled[0].id, 1);
        assert!(cancelled[0].end);
        assert_eq!(
            cancelled[0].bytes,
            br#"{"event":"end","data":{"reason":"cancelled"}}"#
        );
        assert_eq!(session.subs.len(), 63);
        assert_eq!(cancelled[1].bytes, br#"{"ok":true}"#);
        assert!(
            session
                .request(68, r#"{"op":"watch"}"#, now, None)
                .is_empty()
        );
        assert!(
            dashboard
                .handle()
                .session()
                .request(1, r#"{"op":"watch"}"#, now, None)
                .is_empty()
        );
    }

    #[test]
    fn events_replay_with_limits_loss_and_immediate_catch_up() {
        let dashboard = DashboardObserver::new(DashboardOptions {
            collector: Options {
                policy: crate::tests::policy([crate::Class::new("events")
                    .count(2200)
                    .bytes(4 << 20)]),
                ..Options::default()
            },
            ..DashboardOptions::default()
        });
        let mut session = dashboard.handle().session();
        let now = Instant::now();
        emit(dashboard.observer().as_ref(), 1, Event::new("run", "start"));
        session.request(1, r#"{"op":"watch","after":0}"#, now, None);
        assert_eq!(names(&session.poll(now, None)), ["snapshot"]);
        for seq in 2..=2002 {
            emit(
                dashboard.observer().as_ref(),
                seq,
                Event::new("test", "tick"),
            );
        }
        assert_eq!(session.poll(now, None).len(), 1000);
        assert_eq!(session.next_poll(), Some(now));
        assert_eq!(session.poll(now, None).len(), 1000);
        assert_eq!(session.poll(now, None).len(), 2);
        assert_eq!(session.next_poll(), Some(now + Duration::from_millis(250)));
        let value = json(&request(
            &mut session,
            2,
            r#"{"op":"events","after":1000,"max":2}"#,
            now,
        ));
        let events = value.get("events").and_then(Json::as_array).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].get("seq").and_then(Json::as_u64), Some(1001));
        dashboard.observer().lost(Loss::staged(Stream::Events, 3));
        let changes = session.poll(now + Duration::from_millis(250), None);
        assert!(
            changes
                .iter()
                .all(|v| !String::from_utf8_lossy(&v.bytes).contains("\"event\":\"gap\""))
        );
        assert!(
            changes
                .iter()
                .any(|v| String::from_utf8_lossy(&v.bytes).contains("staging"))
        );
    }

    #[test]
    fn lab_graph_has_groups_hosts_labels_counters_and_event_origins() {
        let dashboard = DashboardObserver::new(DashboardOptions {
            collector: crate::Options::default(),
            ..Default::default()
        });
        let handle = dashboard.handle();
        let (attacher, mut attachments) = fictionet::attachments();
        let mut sandbox = attacher.attach("guest").unwrap();
        block_on(lab(
            RunOptions::new(Seed::from_u64(7)).observer(dashboard.observer()),
            move |cx| async move {
                let mut session = handle.session();
                let now = Instant::now();
                let group = cx.group("network");
                let host = group.host("machine");
                let mut attachment = attachments.next(&cx).await?;
                attachment = cx.tap("guest link", attachment);
                sandbox.send(Packet(vec![0; 3]));
                attachment.recv(&cx).await?;
                host.emit("test", "origin", |e| e);
                let task = host.spawn(|_| async move { Ok(()) });
                cx.yield_now().await?;
                let graph = json(&request(&mut session, 1, r#"{"op":"graph"}"#, now));
                assert_eq!(graph.get("started"), Some(&Json::Null));
                assert_eq!(
                    graph.get("hosts").and_then(Json::as_array).unwrap().len(),
                    2
                );
                let nodes = graph.get("nodes").and_then(Json::as_array).unwrap();
                assert!(
                    nodes
                        .iter()
                        .any(|n| n.get("kind").and_then(Json::as_str) == Some("sandbox")
                            && n.get("host").and_then(Json::as_str).is_some())
                );
                let edges = graph.get("edges").and_then(Json::as_array).unwrap();
                assert_eq!(edges.len(), 1);
                assert_eq!(
                    edges[0].get("label").and_then(Json::as_str),
                    Some("guest link")
                );
                let link = edges[0].get("id").and_then(Json::as_str).unwrap();
                let value = json(&request(
                    &mut session,
                    2,
                    &format!(r#"{{"op":"link","link":"{link}"}}"#),
                    now,
                ));
                assert_eq!(
                    value.get("counters"),
                    Some(&Json::Array(vec![
                        0u64.into(),
                        0u64.into(),
                        1u64.into(),
                        3u64.into()
                    ]))
                );
                let events = json(&request(&mut session, 3, r#"{"op":"events"}"#, now));
                let origin = events
                    .get("events")
                    .and_then(Json::as_array)
                    .unwrap()
                    .iter()
                    .find(|e| e.get("kind").and_then(Json::as_str) == Some("origin"))
                    .unwrap_or_else(|| panic!("events: {events:?}"));
                for key in ["node", "task", "file", "line", "parent"] {
                    assert!(origin.get(key).is_some(), "{key}");
                }
                session.request(4, r#"{"op":"watch"}"#, now, None);
                assert_eq!(names(&session.poll(now, None)), ["snapshot"]);
                task.join(&cx).await?;
                drop((host, group, attachment, sandbox));
                cx.yield_now().await?;
                let changes = session.poll(now + Duration::from_millis(250), None);
                let names = names(&changes);
                assert!(names.contains(&"edge_end".into()));
                assert!(names.contains(&"node_end".into()));
                assert!(names.contains(&"group_end".into()));
                assert!(names.contains(&"host_end".into()));
                Ok(())
            },
        ))
        .unwrap();
    }
}
