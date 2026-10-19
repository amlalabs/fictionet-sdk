use std::collections::BTreeMap;
use std::time::Duration;

use crate::json::{self, Object};
use crate::{DashboardHandle, Topology};
use fictionet::events::{DisplayBatch, Event};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::json::Value;

#[derive(Default)]
pub(crate) struct View {
    nodes: BTreeMap<String, String>,
    edges: BTreeMap<String, String>,
    groups: BTreeMap<String, String>,
    hosts: BTreeMap<String, String>,
    counters: BTreeMap<String, [u64; 4]>,
    event_seq: u64,
    event_position: [u64; 2],
    dropped: u64,
    evicted: [u64; 2],
    ended: bool,
    revision: u64,
    status: String,
}
impl View {
    pub(crate) fn ended(&self) -> bool {
        self.ended
    }
    pub(crate) fn events_pending(&self, graph: &DashboardHandle) -> bool {
        self.event_seq < last_event(graph)
    }
}
pub(crate) type Message = (&'static str, String);
const SNAPSHOT_EVENTS: usize = 200;
const EVENTS_PER_CHANGE: usize = 1000;
fn edge_id(id: u64) -> String {
    format!("e{id}")
}

fn build(topology: Topology, ended: bool) -> View {
    let mut view = View {
        revision: topology.revision,
        ended,
        ..View::default()
    };
    for (id, group) in &topology.groups {
        view.groups.insert(
            id.to_string(),
            Object::new()
                .str("id", &id.to_string())
                .str("name", &group.name)
                .opt_str("parent", group.parent.map(|id| id.to_string()).as_deref())
                .done(),
        );
    }
    for (id, host) in &topology.hosts {
        view.hosts.insert(
            id.to_string(),
            Object::new()
                .str("id", &id.to_string())
                .str("name", &host.name)
                .opt_str("group", host.group.map(|id| id.to_string()).as_deref())
                .opt_str("sandbox", host.sandbox.as_deref())
                .done(),
        );
    }
    for (id, task) in &topology.tasks {
        let mut group = task.group;
        let mut host = None;
        for _ in 0..=topology.groups.len() {
            let Some(current) = group else {
                break;
            };
            host = topology
                .hosts
                .iter()
                .find(|(_, host)| host.group == Some(current))
                .map(|(id, _)| id.to_string());
            if host.is_some() {
                break;
            }
            group = topology.groups.get(&current).and_then(|g| g.parent);
        }
        let node = Object::new()
            .str("id", &id.to_string())
            .str(
                "kind",
                if task.name == "world" && task.parent.is_none() {
                    "world"
                } else {
                    "task"
                },
            )
            .str("name", &short_name(&task.name))
            .str("file", task.file)
            .num("line", task.line)
            .opt_str("parent", task.parent.map(|id| id.to_string()).as_deref())
            .opt_str("group", task.group.map(|id| id.to_string()).as_deref())
            .secs("started", task.started.since_start())
            .opt_str("host", host.as_deref())
            .done();
        view.nodes.insert(id.to_string(), node);
    }
    for (id, link) in &topology.links {
        let live =
            |id: Option<fictionet::events::TaskId>| id.filter(|id| topology.tasks.contains_key(id));
        let end = |side: usize| live(link.owners[side]).or_else(|| live(link.creator));
        let Some(a) = end(0) else {
            continue;
        };
        let b = if let Some(name) = &link.sandbox {
            let sid = format!("s{}", id.get());
            let group = live(link.owners[0])
                .and_then(|id| topology.tasks.get(&id))
                .and_then(|t| t.group);
            view.nodes.insert(
                sid.clone(),
                Object::new()
                    .str("id", &sid)
                    .str("kind", "sandbox")
                    .str("name", name)
                    .opt_str("group", group.map(|id| id.to_string()).as_deref())
                    .opt_str("host", link.host.map(|id| id.to_string()).as_deref())
                    .done(),
            );
            sid
        } else {
            let Some(b) = end(1).filter(|b| *b != a) else {
                continue;
            };
            b.to_string()
        };
        view.edges.insert(
            id.to_string(),
            Object::new()
                .str("id", &id.to_string())
                .str("a", &a.to_string())
                .str("b", &b)
                .opt_str(
                    "label",
                    (!link.label.is_empty()).then_some(link.label.as_str()),
                )
                .done(),
        );
        let [a, b] = link.counters.totals();
        view.counters
            .insert(id.to_string(), [a.packets, a.bytes, b.packets, b.bytes]);
    }
    view
}

pub(crate) fn counters(graph: &DashboardHandle, wall: Option<Duration>) -> String {
    let view = build(
        graph.0.collector.topology(),
        graph.0.collector.ended().is_some(),
    );
    Object::new()
        .secs("t", graph.elapsed(wall))
        .raw("edges", &counters_json(view.counters.iter()))
        .done()
}

fn status(graph: &DashboardHandle) -> String {
    use fictionet::events::Stream;
    let topology = graph.0.collector.topology();
    let losses = graph.0.collector.losses();
    let streams = losses.streams.iter().map(|loss| {
        let stream = match loss.stream {
            Stream::Events => "events".into(),
            Stream::Keys => "keys".into(),
            Stream::Topology => "topology".into(),
            Stream::Packets(id) => id.to_string(),
        };
        Object::new()
            .str("stream", &stream)
            .str("reason", &format!("{:?}", loss.reason).to_lowercase())
            .num("count", loss.count)
            .raw(
                "bytes",
                &loss.bytes.map_or_else(|| "null".into(), |n| n.to_string()),
            )
            .done()
    });
    let untracked = losses.untracked.iter().map(|loss| {
        Object::new()
            .str("reason", &format!("{:?}", loss.reason).to_lowercase())
            .num("count", loss.count)
            .num("bytes", loss.bytes)
            .done()
    });
    Object::new()
        .bool("incomplete", topology.incomplete)
        .num("refused", topology.refused)
        .num("missing", topology.missing)
        .num("truncated_bytes", topology.truncated_bytes)
        .raw("losses", &json::array(streams))
        .raw("untracked", &json::array(untracked))
        .done()
}

fn short_name(full: &str) -> String {
    // Cut generic arguments, which can hold paths of their own.
    let mut depth = 0;
    let mut plain = String::with_capacity(full.len());
    for ch in full.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => plain.push(ch),
            _ => {}
        }
    }
    let parts: Vec<&str> = plain
        .split("::")
        .filter(|p| !p.is_empty() && !p.starts_with('{'))
        .collect();
    let n = parts.len();
    parts[n.saturating_sub(2)..].join("::")
}

/// One event or an explicit serialization error at the same sequence.
fn event_line(event: &Event) -> String {
    let error = match event.to_line() {
        Ok(line) => return line,
        Err(error) => error.to_string(),
    };
    let mut replacement = event.clone();
    replacement.summary = format!("unserializable: {error}");
    replacement.fields = fictionet::events::Fields::new();
    replacement.fields.set("unserializable", error);

    // Only fixed-schema metadata and the error remain. Bound every text
    // value, including connection and task names, so even escaped strings
    // fit well below the JSON size limit. Depth and value count are fixed.
    fn bound_text(value: &mut Value) {
        match value {
            Value::String(text) if text.len() > 1024 => {
                let mut end = 1024;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
                text.push('…');
            }
            Value::Object(members) => {
                for (_, value) in members {
                    bound_text(value);
                }
            }
            _ => {}
        }
    }
    let mut value = replacement.to_json();
    bound_text(&mut value);
    let bytes = value
        .to_bytes()
        .expect("bounded event serialization error record");
    String::from_utf8(bytes).expect("JSON is UTF-8")
}

fn last_event(graph: &DashboardHandle) -> u64 {
    graph.0.collector.events().last()
}

fn history_batch(graph: &DashboardHandle, after: Option<u64>, max: usize) -> DisplayBatch {
    graph.0.collector.events().display_batch(after, max)
}

fn loss_line(dropped: u64, seq: u64) -> String {
    let mut event = Event::new("events", "dropped")
        .summary(format!("{dropped} events lost from retained history"))
        .field("count", dropped);
    event.seq = seq;
    event_line(&event)
}

/// The `events` reply: at most `max` events after number `after`.
pub(crate) fn events(graph: &DashboardHandle, after: u64, max: usize) -> String {
    let DisplayBatch {
        events,
        last,
        dropped,
        ..
    } = history_batch(graph, Some(after), max);
    let lines: Vec<String> = events.iter().map(event_line).collect();
    Object::new()
        .raw("events", &json::array(lines))
        .num("last", last)
        .num("dropped", dropped)
        .done()
}

/// The `link` reply: one link's ends, label and counts, if it is shown.
pub(crate) fn link(graph: &DashboardHandle, id: u64) -> Option<String> {
    let view = build(
        graph.0.collector.topology(),
        graph.0.collector.ended().is_some(),
    );
    let edge = view.edges.get(&edge_id(id))?;
    let c = view.counters.get(&edge_id(id))?;
    // The edge's JSON, with its counts added before the closing brace.
    Some(format!(
        "{},\"counters\":[{},{},{},{}]}}",
        &edge[..edge.len() - 1],
        c[0],
        c[1],
        c[2],
        c[3]
    ))
}

/// The `link` event of a packet stream: the edge's ends and label, or
/// nulls for a link the graph does not show, such as one already removed.
pub(crate) fn describe(graph: &DashboardHandle, id: fictionet::events::LinkId) -> String {
    let view = build(
        graph.0.collector.topology(),
        graph.0.collector.ended().is_some(),
    );
    view.edges
        .get(&edge_id(id.get()))
        .cloned()
        .unwrap_or_else(|| {
            Object::new()
                .str("id", &edge_id(id.get()))
                .raw("a", "null")
                .raw("b", "null")
                .raw("label", "null")
                .done()
        })
}

fn counters_json<'a>(counters: impl Iterator<Item = (&'a String, &'a [u64; 4])>) -> String {
    let mut out = String::from("{");
    for (i, (id, c)) in counters.enumerate() {
        if i > 0 {
            out.push(',');
        }
        json::string(&mut out, id);
        out.push_str(&format!(":[{},{},{},{}]", c[0], c[1], c[2], c[3]));
    }
    out.push('}');
    out
}

/// The whole graph, for a browser that just connected, with the latest
/// events, or none if `after` says where the browser's events start. Returns
/// the view the browser now has.
pub(crate) fn snapshot(
    graph: &DashboardHandle,
    after: Option<u64>,
    wall: Option<Duration>,
) -> (View, Message) {
    let mut view = build(
        graph.0.collector.topology(),
        graph.0.collector.ended().is_some(),
    );
    let DisplayBatch {
        events,
        last,
        dropped,
        evicted,
        position,
    } = history_batch(
        graph,
        after,
        if after.is_some() { 0 } else { SNAPSHOT_EVENTS },
    );
    view.event_seq = after.unwrap_or(last);
    view.event_position = position;
    view.dropped = dropped;
    view.evicted = evicted;
    let mut events: Vec<String> = events.iter().map(event_line).collect();
    if view.dropped != 0 {
        events.insert(0, loss_line(view.dropped, 0));
    }
    view.status = status(graph);
    let data = Object::new()
        .secs("t", graph.elapsed(wall))
        .raw("started", &graph.started())
        .num("revision", view.revision)
        .raw("hosts", &json::array(view.hosts.values()))
        .raw("status", &view.status)
        .bool("ended", view.ended)
        .raw("groups", &json::array(view.groups.values()))
        .raw("nodes", &json::array(view.nodes.values()))
        .raw("edges", &json::array(view.edges.values()))
        .raw("counters", &counters_json(view.counters.iter()))
        .raw("events", &json::array(events))
        .done();
    (view, ("snapshot", data))
}

/// What changed since `old`, which becomes the graph as it is now.
pub(crate) fn changes(
    graph: &DashboardHandle,
    old: &mut View,
    wall: Option<Duration>,
) -> Vec<Message> {
    let mut new = build(
        graph.0.collector.topology(),
        graph.0.collector.ended().is_some(),
    );
    new.event_seq = old.event_seq;
    new.event_position = old.event_position;
    new.dropped = old.dropped;
    new.evicted = old.evicted;
    let mut out = Vec::new();
    // Edges go first, then nodes, so a browser never holds an edge to a
    // node it was told is gone, nor a new edge to a node it has not met.
    for id in old.edges.keys().filter(|id| !new.edges.contains_key(*id)) {
        out.push(("edge_end", Object::new().str("id", id).done()));
    }
    // Groups go before the nodes in them; a group's parent sorts anywhere,
    // so a browser takes a group whose parent it has not met yet as is.
    for (id, group) in &new.groups {
        if old.groups.get(id) != Some(group) {
            out.push(("group", group.clone()));
        }
    }
    for (id, node) in &new.nodes {
        if old.nodes.get(id) != Some(node) {
            out.push(("node", node.clone()));
        }
    }
    for (id, edge) in &new.edges {
        if old.edges.get(id) != Some(edge) {
            out.push(("edge", edge.clone()));
        }
    }
    for id in old.nodes.keys().filter(|id| !new.nodes.contains_key(*id)) {
        out.push(("node_end", Object::new().str("id", id).done()));
    }
    for id in old.groups.keys().filter(|id| !new.groups.contains_key(*id)) {
        out.push(("group_end", Object::new().str("id", id).done()));
    }
    for (id, host) in &new.hosts {
        if old.hosts.get(id) != Some(host) {
            out.push(("host", host.clone()));
        }
    }
    for id in old.hosts.keys().filter(|id| !new.hosts.contains_key(*id)) {
        out.push(("host_end", Object::new().str("id", id).done()));
    }
    new.status = status(graph);
    if old.status != new.status || old.revision != new.revision {
        out.push((
            "status",
            Object::new()
                .num("revision", new.revision)
                .raw("status", &new.status)
                .done(),
        ));
    }
    out.extend(counter_changes(graph, &old.counters, &new.counters, wall));
    if new.ended && !old.ended {
        out.push(("ended", Object::new().secs("t", graph.elapsed(wall)).done()));
    }
    *old = new;
    out
}

fn counter_changes(
    graph: &DashboardHandle,
    old: &BTreeMap<String, [u64; 4]>,
    new: &BTreeMap<String, [u64; 4]>,
    wall: Option<Duration>,
) -> Vec<Message> {
    let changed = new.iter().filter(|(id, c)| old.get(*id) != Some(*c));
    let counters = counters_json(changed);
    if counters == "{}" {
        Vec::new()
    } else {
        vec![(
            "counters",
            Object::new()
                .secs("t", graph.elapsed(wall))
                .raw("edges", &counters)
                .done(),
        )]
    }
}

/// A bounded event batch and whether another batch may be waiting.
pub(crate) fn event_changes(graph: &DashboardHandle, view: &mut View) -> (Vec<Message>, bool) {
    let DisplayBatch {
        events,
        last,
        dropped,
        evicted,
        position,
    } = history_batch(graph, Some(view.event_seq), EVENTS_PER_CHANGE);
    let full = events.len() == EVENTS_PER_CHANGE;
    let mut messages = Vec::new();
    let rejected = (dropped - evicted.iter().sum::<u64>())
        .saturating_sub(view.dropped - view.evicted.iter().sum::<u64>());
    let missed = rejected
        + evicted
            .iter()
            .zip(view.event_position)
            .map(|(evicted, position)| evicted.saturating_sub(position))
            .sum::<u64>();
    if missed != 0 {
        messages.push(("event", loss_line(missed, view.event_seq)));
    }
    view.dropped = dropped;
    view.evicted = evicted;
    view.event_position = position;
    view.event_seq = if full {
        events.last().unwrap().seq
    } else {
        last.max(view.event_seq)
    };
    messages.extend(events.iter().map(|event| ("event", event_line(event))));
    (messages, full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DashboardObserver, DashboardOptions, Options};
    use fictionet::events::{Limits, Observation, Observer, Stamp, Stream};

    fn history_graph() -> DashboardHandle {
        DashboardObserver::new(DashboardOptions::default()).handle()
    }
    fn limited() -> DashboardHandle {
        DashboardObserver::new(DashboardOptions {
            collector: Options {
                events: Some(Limits::new(2, 4096)),
                noise: Limits::new(2, 4096),
                ..Options::default()
            },
            ..DashboardOptions::default()
        })
        .handle()
    }
    fn retain(graph: &DashboardHandle, event: Event) {
        retain_at(graph, graph.0.collector.events().last() + 1, event);
    }
    fn retain_at(graph: &DashboardHandle, seq: u64, event: Event) {
        graph.0.observe(
            Stamp {
                stream: Stream::Events,
                seq,
                at: event.at,
            },
            Observation::Event(&event),
        );
    }
    fn serialization_graph() -> DashboardHandle {
        let graph = history_graph();
        let mut event = Event::new("test", "big");
        event.summary = "x".repeat(1 << 20);
        retain(&graph, event);
        retain(&graph, Event::new("test", "normal"));
        graph
    }
    fn names(messages: &[Message]) -> Vec<&'static str> {
        messages.iter().map(|(name, _)| *name).collect()
    }
    #[test]
    fn live_viewers_only_report_evictions_after_their_cursor() {
        let graph = &limited();
        let (mut live, _) = snapshot(graph, Some(0), None);
        let (mut slow, _) = snapshot(graph, Some(0), None);
        for i in 0..6 {
            retain(graph, Event::new("test", "tick").field("i", i));
            let (messages, _) = event_changes(graph, &mut live);
            assert_eq!(messages.len(), 1);
            let event = Value::parse(messages[0].1.as_bytes()).unwrap();
            assert_eq!(event.get("kind").and_then(Value::as_str), Some("tick"));
        }
        let (messages, _) = event_changes(graph, &mut slow);
        assert_eq!(messages.len(), 3);
        let loss = Value::parse(messages[0].1.as_bytes()).unwrap();
        assert_eq!(
            loss.get("fields")
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(4)
        );
        assert!(event_changes(graph, &mut slow).0.is_empty());
    }

    #[test]
    fn sequence_gaps_do_not_inflate_missed_evictions() {
        let graph = &limited();
        let (mut view, _) = snapshot(graph, Some(0), None);
        for seq in [1, 100] {
            retain_at(graph, seq, Event::new("test", "tick"));
        }
        assert_eq!(event_changes(graph, &mut view).0.len(), 2);
        for seq in [200, 300, 400] {
            retain_at(graph, seq, Event::new("test", "tick"));
        }
        let (messages, full) = event_changes(graph, &mut view);
        assert!(!full);
        assert_eq!(messages.len(), 3);
        let loss = Value::parse(messages[0].1.as_bytes()).unwrap();
        assert_eq!(
            loss.get("fields")
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert!(event_changes(graph, &mut view).0.is_empty());
    }

    #[test]
    fn live_viewers_track_noise_evictions_separately() {
        let graph = &limited();
        retain_at(graph, 1, Event::new("http", "request"));
        let (mut live, _) = snapshot(graph, None, None);
        let (mut slow, _) = snapshot(graph, None, None);
        for i in 1..=10 {
            retain_at(
                graph,
                i * 100,
                Event::new("net", "blocked").repeat(fictionet::events::Fields::new()),
            );
            let (messages, full) = event_changes(graph, &mut live);
            assert!(!full);
            assert_eq!(messages.len(), 1);
            let event = Value::parse(messages[0].1.as_bytes()).unwrap();
            assert_eq!(event.get("kind").and_then(Value::as_str), Some("blocked"));
        }
        let (messages, _) = event_changes(graph, &mut slow);
        assert_eq!(messages.len(), 3);
        let loss = Value::parse(messages[0].1.as_bytes()).unwrap();
        assert_eq!(
            loss.get("fields")
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(8)
        );
        assert!(event_changes(graph, &mut slow).0.is_empty());
    }

    #[test]
    fn snapshots_count_records_instead_of_sequence_numbers() {
        let graph = history_graph();
        for index in 1..=250 {
            retain_at(&graph, index * 100, Event::new("test", "tick"));
        }
        let (mut view, (_, data)) = snapshot(&graph, None, None);
        let data = Value::parse(data.as_bytes()).unwrap();
        let events = data.get("events").unwrap().as_array().unwrap();
        assert_eq!(events.len(), 200);
        assert_eq!(events[0].get("seq").and_then(Value::as_u64), Some(5100));
        assert_eq!(events[199].get("seq").and_then(Value::as_u64), Some(25000));
        assert!(event_changes(&graph, &mut view).0.is_empty());
    }

    #[test]
    fn a_reported_rejection_does_not_turn_seen_evictions_into_loss() {
        let graph = &limited();
        retain(graph, Event::new("test", "first"));
        retain(graph, Event::new("test", "second"));
        retain(graph, Event::new("test", "large").summary("x".repeat(4096)));
        let mut view = View {
            event_seq: 1,
            event_position: [1, 0],
            dropped: 1,
            ..View::default()
        };
        retain(graph, Event::new("test", "fourth"));
        let (messages, _) = event_changes(graph, &mut view);
        assert_eq!(messages.len(), 2);
        assert!(
            messages
                .iter()
                .all(|(_, line)| !line.contains("events lost"))
        );
    }

    fn assert_serialization_error(event: &Value, seq: u64) {
        assert_eq!(event.get("seq").and_then(Value::as_u64), Some(seq));
        let fields = event.get("fields").unwrap();
        assert_eq!(fields.as_object().unwrap().len(), 1);
        let error = fields
            .get("unserializable")
            .and_then(Value::as_str)
            .unwrap();
        assert!(!error.is_empty());
        assert_eq!(
            event.get("summary").and_then(Value::as_str),
            Some(format!("unserializable: {error}").as_str())
        );
    }

    #[test]
    fn oversized_event_not_blank() {
        let graph = serialization_graph();
        for data in [events(&graph, 0, 10), snapshot(&graph, None, None).1.1] {
            let reply = Value::parse(data.as_bytes()).unwrap();
            let events = reply.get("events").and_then(Value::as_array).unwrap();
            assert_eq!(events.len(), 2);
            assert_serialization_error(&events[0], 1);
            assert_eq!(
                events[0].get("source").and_then(Value::as_str),
                Some("test")
            );
            assert_eq!(events[0].get("kind").and_then(Value::as_str), Some("big"));
            assert_eq!(events[1].get("seq").and_then(Value::as_u64), Some(2));
            assert_eq!(
                events[1].get("kind").and_then(Value::as_str),
                Some("normal")
            );
        }
        let reply = Value::parse(events(&graph, 0, 1).as_bytes()).unwrap();
        let events = reply.get("events").and_then(Value::as_array).unwrap();
        assert_eq!(events.len(), 1);
        assert_serialization_error(&events[0], 1);
    }

    #[test]
    fn cursor_never_skips_silently() {
        let graph = serialization_graph();
        let (mut view, _) = snapshot(&graph, Some(0), None);
        let (messages, full) = event_changes(&graph, &mut view);
        assert_eq!(names(&messages), ["event", "event"]);
        assert!(!full);
        assert_eq!(view.event_seq, 2);
        let events: Vec<_> = messages
            .iter()
            .map(|(_, data)| Value::parse(data.as_bytes()).unwrap())
            .collect();
        assert_serialization_error(&events[0], 1);
        assert_eq!(events[1].get("seq").and_then(Value::as_u64), Some(2));
        assert_eq!(
            events[1],
            history_batch(&graph, Some(1), 1).events[0].to_json()
        );
        assert!(event_changes(&graph, &mut view).0.is_empty());
        assert!(!view.events_pending(&graph));
    }
}
