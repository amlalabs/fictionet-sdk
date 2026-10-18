//! The graph as the browser sees it, and the messages that keep a browser
//! up to date: a snapshot first, then only what changed.

use std::collections::BTreeMap;

use super::json::{self, Object};
use std::sync::Arc;

use crate::events::{DisplayBatch, Event};
use crate::stdlib::codec::Wire;
use crate::stdlib::protocols::json::Value;
use crate::watch::{Graph, GraphState, Group, TaskInfo, short_name};

/// What one browser has been told.
#[derive(Default)]
pub(crate) struct View {
    /// Node id to its JSON.
    nodes: BTreeMap<String, String>,
    /// Edge id to its JSON.
    edges: BTreeMap<String, String>,
    /// Group id to its JSON.
    groups: BTreeMap<String, String>,
    counters: BTreeMap<String, [u64; 4]>,
    /// The number of the last event sent.
    event_seq: u64,
    /// Position among retained or evicted events, independent of sequence gaps.
    event_position: [u64; 2],
    dropped: u64,
    evicted: [u64; 2],
    ended: bool,
    revision: u64,
}

impl View {
    /// Whether the world had ended when this view was taken.
    pub(crate) fn ended(&self) -> bool {
        self.ended
    }

    pub(crate) fn events_pending(&self, graph: &Graph) -> bool {
        self.event_seq < last_event(graph)
    }
}

/// One server-sent event: its name and its JSON data.
pub(crate) type Message = (&'static str, String);

/// How many earlier events a snapshot carries.
const SNAPSHOT_EVENTS: usize = 200;
/// How many events one round of changes carries at most, so a replay of
/// the whole log goes out in pieces.
const EVENTS_PER_CHANGE: usize = 1000;
/// How many events an `events` reply carries unless asked for fewer.
pub(crate) const EVENTS_PER_REPLY: usize = 1000;

pub(crate) fn task_id(id: u64) -> String {
    format!("t{id}")
}

pub(crate) fn edge_id(id: u64) -> String {
    format!("e{id}")
}

fn sandbox_id(link: u64) -> String {
    format!("s{link}")
}

fn group_id(id: u64) -> String {
    format!("g{id}")
}

/// Adds `group`, and the groups it is inside, to `view`. Returns its id.
fn add_group(view: &mut View, group: &Arc<Group>) -> String {
    for g in group.chain() {
        let id = group_id(g.id);
        if view.groups.contains_key(&id) {
            break;
        }
        let parent = g.parent.as_ref().map(|p| group_id(p.id));
        let json = Object::new()
            .str("id", &id)
            .str("name", &g.name)
            .opt_str("parent", parent.as_deref())
            .done();
        view.groups.insert(id, json);
    }
    group_id(group.id)
}

/// One link that is drawn, copied out of the graph: its ends are tasks
/// that live, or a sandbox.
struct LinkRow {
    id: u64,
    meter: Arc<crate::watch::Meter>,
    a: u64,
    b: End,
    label: Option<Arc<str>>,
}

enum End {
    Task(u64),
    /// A sandbox, and the group of the task that reads it.
    Sandbox(Arc<str>, Option<Arc<Group>>),
}

/// What [`build`] needs from the graph, copied while its lock is held. The
/// world takes the same lock to start and end tasks, so it holds only this
/// copy: no sorting, no JSON, no counts. Links whose ends are both gone are
/// dropped.
struct Copy {
    revision: u64,
    ended: bool,
    tasks: Vec<(u64, TaskInfo)>,
    links: Vec<LinkRow>,
}

fn prune(s: &mut GraphState) {
    let before = s.links.len();
    s.links.retain(|_, l| l.meter.strong_count() > 0);
    if s.links.len() != before {
        s.revision += 1;
    }
}

fn copy(s: &mut GraphState) -> Copy {
    prune(s);
    let tasks = s.tasks.iter().map(|(&id, t)| (id, t.clone())).collect();
    let live = |task: u64| (task != 0 && s.tasks.contains_key(&task)).then_some(task);
    let mut links = Vec::with_capacity(s.links.len());
    for (id, link) in &s.links {
        let Some(meter) = link.meter.upgrade() else {
            continue;
        };
        let end = |side: usize| live(link.owners[side]).or_else(|| live(link.creator));
        let Some(a) = end(0) else { continue };
        let b = match &link.sandbox {
            Some(name) => {
                let reader = live(link.owners[0]).and_then(|t| s.tasks.get(&t));
                End::Sandbox(name.clone(), reader.and_then(|t| t.group.clone()))
            }
            None => match end(1) {
                Some(b) if b != a => End::Task(b),
                _ => continue,
            },
        };
        links.push(LinkRow {
            id: *id,
            meter,
            a,
            b,
            label: link.label.clone(),
        });
    }
    Copy {
        revision: s.revision,
        ended: s.ended,
        tasks,
        links,
    }
}

/// The graph as it was copied, in the form the browser sees.
fn build(mut c: Copy) -> View {
    let mut view = View {
        revision: c.revision,
        ended: c.ended,
        ..View::default()
    };
    c.tasks.sort_unstable_by_key(|(id, _)| *id);
    for (id, t) in &c.tasks {
        let kind = if t.name == "world" && t.parent == 0 {
            "world"
        } else {
            "task"
        };
        let parent = (t.parent != 0).then(|| task_id(t.parent));
        let group = t.group.as_ref().map(|g| add_group(&mut view, g));
        let node = Object::new()
            .str("id", &task_id(*id))
            .str("kind", kind)
            .str("name", &short_name(&t.name))
            .str("file", t.file)
            .num("line", t.line)
            .opt_str("parent", parent.as_deref())
            .opt_str("group", group.as_deref())
            .secs("started", t.started)
            .done();
        view.nodes.insert(task_id(*id), node);
    }
    c.links.sort_unstable_by_key(|l| l.id);
    for link in &c.links {
        let a = task_id(link.a);
        let b = match &link.b {
            End::Task(b) => task_id(*b),
            End::Sandbox(name, group) => {
                let sid = sandbox_id(link.id);
                // A sandbox sits in the group of the task that reads it.
                let group = group.as_ref().map(|g| add_group(&mut view, g));
                let node = Object::new()
                    .str("id", &sid)
                    .str("kind", "sandbox")
                    .str("name", name)
                    .opt_str("group", group.as_deref())
                    .done();
                view.nodes.insert(sid.clone(), node);
                sid
            }
        };
        let edge = Object::new()
            .str("id", &edge_id(link.id))
            .str("a", &a)
            .str("b", &b)
            .opt_str("label", link.label.as_deref())
            .done();
        view.edges.insert(edge_id(link.id), edge);
        view.counters.insert(edge_id(link.id), link.meter.totals());
    }
    view
}

/// The `counters` reply: every link's counts now.
pub(crate) fn counters(graph: &Graph) -> String {
    let c = copy(&mut graph.state());
    let counters: BTreeMap<_, _> = c
        .links
        .iter()
        .map(|link| (edge_id(link.id), link.meter.totals()))
        .collect();
    Object::new()
        .secs("t", graph.since_start())
        .raw("edges", &counters_json(counters.iter()))
        .done()
}

/// One event or an explicit serialization error at the same sequence.
fn event_line(event: &Event) -> String {
    let error = match event.to_line() {
        Ok(line) => return line,
        Err(error) => error.to_string(),
    };
    let mut replacement = Event::new(event.source, event.kind)
        .level(event.level)
        .conn(&event.conn)
        .summary(format!("unserializable: {error}"))
        .field("unserializable", error);
    replacement.seq = event.seq;
    replacement.at = event.at;
    replacement.origin = event.origin.clone();

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

fn last_event(graph: &Graph) -> u64 {
    graph.events.as_ref().map_or(0, |events| events.last())
}

fn history_batch(graph: &Graph, after: Option<u64>, max: usize) -> DisplayBatch {
    graph
        .events
        .as_ref()
        .map_or_else(DisplayBatch::default, |events| {
            events.display_batch(after, max)
        })
}

fn loss_line(dropped: u64, seq: u64) -> String {
    let mut event = Event::new("events", "dropped")
        .summary(format!("{dropped} events lost from retained history"))
        .field("count", dropped);
    event.seq = seq;
    event_line(&event)
}

/// The `events` reply: at most `max` events after number `after`.
pub(crate) fn events(graph: &Graph, after: u64, max: usize) -> String {
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
pub(crate) fn link(graph: &Graph, id: u64) -> Option<String> {
    let c = copy(&mut graph.state());
    let view = build(c);
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
pub(crate) fn snapshot(graph: &Graph, after: Option<u64>) -> (View, Message) {
    let c = copy(&mut graph.state());
    let mut view = build(c);
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
    let data = Object::new()
        .secs("t", graph.since_start())
        .num(
            "started",
            graph
                .start_wall
                .duration_since(crate::sys::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis()),
        )
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
pub(crate) fn changes(graph: &Graph, old: &mut View) -> Vec<Message> {
    let mut state = graph.state();
    prune(&mut state);
    if state.revision == old.revision {
        let mut counters = BTreeMap::new();
        for (id, link) in &state.links {
            let id = edge_id(*id);
            if old.edges.contains_key(&id)
                && let Some(meter) = link.meter.upgrade()
            {
                counters.insert(id, meter.totals());
            }
        }
        drop(state);
        let out = counter_changes(graph, &old.counters, &counters);
        old.counters = counters;
        return out;
    }
    let c = copy(&mut state);
    drop(state);
    let mut new = build(c);
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
    out.extend(counter_changes(graph, &old.counters, &new.counters));
    if new.ended && !old.ended {
        out.push(("ended", Object::new().secs("t", graph.since_start()).done()));
    }
    *old = new;
    out
}

fn counter_changes(
    graph: &Graph,
    old: &BTreeMap<String, [u64; 4]>,
    new: &BTreeMap<String, [u64; 4]>,
) -> Vec<Message> {
    let changed = new.iter().filter(|(id, c)| old.get(*id) != Some(*c));
    let counters = counters_json(changed);
    if counters == "{}" {
        Vec::new()
    } else {
        vec![(
            "counters",
            Object::new()
                .secs("t", graph.since_start())
                .raw("edges", &counters)
                .done(),
        )]
    }
}

/// A bounded event batch and whether another batch may be waiting.
pub(crate) fn event_changes(graph: &Graph, view: &mut View) -> (Vec<Message>, bool) {
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::watch::Meter;
    use std::panic::Location;

    fn history_graph() -> Arc<Graph> {
        let shared = crate::run::RunShared::new(crate::Seed::from_u64(7), crate::RunMode::Lab);
        let mut graph = shared.graph.clone();
        drop(shared);
        Arc::get_mut(&mut graph).unwrap().events = Some(Arc::new(crate::events::Memory::default()));
        graph
    }

    fn retain(graph: &Graph, event: Event) {
        retain_at(graph, graph.events.as_ref().unwrap().last() + 1, event);
    }

    fn retain_at(graph: &Graph, seq: u64, event: Event) {
        use crate::events::{Observation, Observer, Stamp};
        let history = graph.events.as_ref().unwrap();
        history.observe(Stamp { seq, at: event.at }, Observation::Event(&event));
    }

    fn serialization_graph() -> Arc<Graph> {
        let graph = history_graph();
        let mut event = Event::new("test", "big");
        event.summary = "x".repeat(1 << 20);
        retain(&graph, event);
        retain(&graph, Event::new("test", "normal"));
        graph
    }

    #[test]
    fn socket_events_require_explicit_retention() {
        let shared = crate::run::RunShared::new(crate::Seed::from_u64(7), crate::RunMode::Lab);
        let graph = shared.graph.clone();
        crate::block_on(crate::run::run_with(shared, |cx| async move {
            cx.emit("test", "tick", |event| event);
            Ok(())
        }))
        .unwrap();
        let reply = Value::parse(events(&graph, 0, 10).as_bytes()).unwrap();
        assert!(reply.get("events").unwrap().as_array().unwrap().is_empty());
        assert_eq!(reply.get("last").and_then(Value::as_u64), Some(0));
    }

    #[test]
    fn late_viewers_see_retained_history_and_loss() {
        let history = Arc::new(crate::events::Memory::new(crate::events::Limits::new(
            2, 4096,
        )));
        let shared = crate::run::RunShared::with_options(
            crate::RunOptions::new(crate::Seed::from_u64(7)).event_history(history.clone()),
            crate::RunMode::Lab,
        );
        let graph = shared.graph.clone();
        crate::block_on(crate::run::run_with(shared, |cx| async move {
            for i in 0..3u64 {
                cx.emit("test", "tick", |event| event.field("i", i));
            }
            Ok(())
        }))
        .unwrap();
        let (mut view, (_, data)) = snapshot(&graph, None);
        let data = Value::parse(data.as_bytes()).unwrap();
        let events = data.get("events").unwrap().as_array().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].get("kind").and_then(Value::as_str),
            Some("dropped")
        );
        assert_eq!(events[1].get("seq").and_then(Value::as_u64), Some(3));
        assert_eq!(events[2].get("seq").and_then(Value::as_u64), Some(4));
        assert!(event_changes(&graph, &mut view).0.is_empty());
        let (mut replay, _) = snapshot(&graph, Some(0));
        // A rejected final event must not leave a viewer waiting forever.
        retain(
            &graph,
            Event::new("test", "large").summary("x".repeat(8192)),
        );
        let (messages, full) = event_changes(&graph, &mut replay);
        assert!(!full);
        assert_eq!(messages.len(), 3);
        assert!(!replay.events_pending(&graph));
    }

    #[test]
    fn live_viewers_only_report_evictions_after_their_cursor() {
        let history = Arc::new(crate::events::Memory::new(crate::events::Limits::new(
            2, 4096,
        )));
        let shared = crate::run::RunShared::with_options(
            crate::RunOptions::new(crate::Seed::from_u64(7)).event_history(history),
            crate::RunMode::Lab,
        );
        let graph = shared.graph.clone();
        let (mut live, _) = snapshot(&graph, Some(0));
        let (mut slow, _) = snapshot(&graph, Some(0));
        for i in 0..6 {
            retain(&graph, Event::new("test", "tick").field("i", i));
            let (messages, _) = event_changes(&graph, &mut live);
            assert_eq!(messages.len(), 1);
            let event = Value::parse(messages[0].1.as_bytes()).unwrap();
            assert_eq!(event.get("kind").and_then(Value::as_str), Some("tick"));
        }
        let (messages, _) = event_changes(&graph, &mut slow);
        assert_eq!(messages.len(), 3);
        let loss = Value::parse(messages[0].1.as_bytes()).unwrap();
        assert_eq!(
            loss.get("fields")
                .unwrap()
                .get("count")
                .and_then(Value::as_u64),
            Some(4)
        );
        assert!(event_changes(&graph, &mut slow).0.is_empty());
    }

    #[test]
    fn sequence_gaps_do_not_inflate_missed_evictions() {
        let shared = crate::run::RunShared::with_options(
            crate::RunOptions::new(crate::Seed::from_u64(7)).event_history(Arc::new(
                crate::events::Memory::new(crate::events::Limits::new(2, 4096)),
            )),
            crate::RunMode::Lab,
        );
        let graph = &shared.graph;
        let (mut view, _) = snapshot(graph, Some(0));
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
        let memory = Arc::new(crate::events::Memory::with_noise_limits(
            crate::events::Limits::new(2, 4096),
            crate::events::Limits::new(2, 4096),
        ));
        let shared = crate::run::RunShared::with_options(
            crate::RunOptions::new(crate::Seed::from_u64(7)).event_history(memory),
            crate::RunMode::Lab,
        );
        let graph = &shared.graph;
        retain_at(graph, 1, Event::new("http", "request"));
        let (mut live, _) = snapshot(graph, None);
        let (mut slow, _) = snapshot(graph, None);
        for i in 1..=10 {
            retain_at(
                graph,
                i * 100,
                Event::new("net", "blocked").repeat(crate::events::Fields::new()),
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
        let (mut view, (_, data)) = snapshot(&graph, None);
        let data = Value::parse(data.as_bytes()).unwrap();
        let events = data.get("events").unwrap().as_array().unwrap();
        assert_eq!(events.len(), 200);
        assert_eq!(events[0].get("seq").and_then(Value::as_u64), Some(5100));
        assert_eq!(events[199].get("seq").and_then(Value::as_u64), Some(25000));
        assert!(event_changes(&graph, &mut view).0.is_empty());
    }

    #[test]
    fn a_reported_rejection_does_not_turn_seen_evictions_into_loss() {
        let history = Arc::new(crate::events::Memory::new(crate::events::Limits::new(
            2, 4096,
        )));
        let shared = crate::run::RunShared::with_options(
            crate::RunOptions::new(crate::Seed::from_u64(7)).event_history(history),
            crate::RunMode::Lab,
        );
        let graph = shared.graph.clone();
        retain(&graph, Event::new("test", "first"));
        retain(&graph, Event::new("test", "second"));
        retain(
            &graph,
            Event::new("test", "large").summary("x".repeat(4096)),
        );
        let mut view = View {
            event_seq: 1,
            event_position: [1, 0],
            dropped: 1,
            ..View::default()
        };
        retain(&graph, Event::new("test", "fourth"));
        let (messages, _) = event_changes(&graph, &mut view);
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
        for data in [events(&graph, 0, 10), snapshot(&graph, None).1.1] {
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
        let (mut view, _) = snapshot(&graph, Some(0));
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

    #[test]
    fn nested_value_failure_visible() {
        let mut value = Value::Null;
        for _ in 0..129 {
            value = Value::Array(vec![value]);
        }
        let mut event = Event::new("test", "nested");
        event.fields.set("nested", value);
        let layer = crate::observe::Layer::from_event(&event);
        assert_eq!(layer.fields.len(), 1);
        assert_eq!(layer.fields[0].name, "nested");
        assert!(layer.fields[0].value.starts_with("unserializable:"));
        assert_eq!(
            event.to_line().unwrap_err().kind,
            crate::stdlib::protocols::json::ErrorKind::TooDeep
        );
        let replacement = Value::parse(event_line(&event).as_bytes()).unwrap();
        assert_serialization_error(&replacement, 0);
    }

    #[test]
    fn many_value_failure_visible() {
        let mut event = Event::new("test", "many");
        event.fields.set(
            "many",
            Value::Array(vec![
                Value::Null;
                crate::stdlib::protocols::json::MAX_ELEMENTS
            ]),
        );
        let error = event.to_line().unwrap_err();
        assert_eq!(
            error.kind,
            crate::stdlib::protocols::json::ErrorKind::TooManyElements
        );
        let layer = crate::observe::Layer::from_event(&event);
        assert!(layer.fields[0].value.starts_with("unserializable:"));
        let replacement = Value::parse(event_line(&event).as_bytes()).unwrap();
        assert_serialization_error(&replacement, 0);
        assert_eq!(
            replacement.get("fields").unwrap().get("unserializable"),
            Some(&Value::from(error.to_string()))
        );
    }

    fn event_with_metadata() -> Event {
        use crate::events::{ConnInfo, Level, Origin, Sandbox, Transport};
        let mut conn = ConnInfo::new(
            42,
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .over_tls(Some("example.test"), Some(b"h2"))
        .from_sandbox(Some(Sandbox {
            id: 7,
            name: "agent".into(),
            addr: Some("10.0.0.2".parse().unwrap()),
            addr_v6: Some("fd00::2".parse().unwrap()),
        }));
        conn.transport = Transport::Udp;
        let mut event = Event::new("test", "big")
            .level(Level::Alarm)
            .conn(&conn)
            .field("original", "discarded");
        event.summary = "x".repeat(1 << 20);
        event.seq = u64::MAX;
        event.at = crate::time::Instant::from_since_start(crate::time::ms(42));
        event.origin = Some(Origin {
            task: u64::MAX,
            name: "world::worker".into(),
            file: "world.rs",
            line: u32::MAX,
            parent: u64::MAX - 1,
        });
        event
    }

    #[test]
    fn serialization_error_keeps_metadata() {
        let event = event_with_metadata();
        let replacement = Value::parse(event_line(&event).as_bytes()).unwrap();
        assert_serialization_error(&replacement, event.seq);
        for (name, value) in event.to_json().as_object().unwrap() {
            if name != "summary" && name != "fields" {
                assert_eq!(replacement.get(name), Some(value), "{name}");
            }
        }
        assert_eq!(
            replacement.get("fields").unwrap().get("unserializable"),
            Some(&Value::from(event.to_line().unwrap_err().to_string()))
        );
    }

    #[test]
    fn serialization_error_is_bounded() {
        for text in ["\0".repeat(1 << 20), "€".repeat(1 << 19)] {
            let text: &'static str = Box::leak(text.into_boxed_str());
            let mut event = event_with_metadata().summary("");
            event.source = text;
            event.kind = text;
            event.conn.sandbox.as_mut().unwrap().name = text.into();
            event.conn.sni = Some(text.into());
            event.conn.alpn = Some(text.as_bytes().into());
            let origin = event.origin.as_mut().unwrap();
            origin.name = text.into();
            origin.file = text;
            assert!(event.to_line().is_err());
            let line = event_line(&event);
            assert!(line.len() < 128 * 1024);
            let replacement = Value::parse(line.as_bytes()).unwrap();
            assert_serialization_error(&replacement, event.seq);
            for name in ["source", "kind", "sni", "alpn", "task", "file"] {
                let value = replacement.get(name).and_then(Value::as_str).unwrap();
                assert!(value.ends_with('…'), "{name}");
                assert!(value.len() <= 1024 + '…'.len_utf8(), "{name}");
            }
            let sandbox = replacement.get("sandbox").unwrap();
            let name = sandbox.get("name").and_then(Value::as_str).unwrap();
            assert!(name.ends_with('…'));
            assert!(name.len() <= 1024 + '…'.len_utf8());
        }
    }

    fn names(messages: &[Message]) -> Vec<&'static str> {
        messages.iter().map(|m| m.0).collect()
    }

    /// Every task started with a grouped `Cx` belongs to the group, stdlib
    /// tasks and tasks started by tasks included. Groups nest, a sandbox
    /// joins the group of the task that reads it, and a group is listed
    /// while something in it lives.
    #[test]
    fn tasks_and_sandboxes_report_their_groups() {
        use crate::Interface;
        use crate::prelude::*;
        use crate::stdlib::network::{delay, route};
        use crate::time::ms;
        let shared = crate::run::RunShared::new(crate::Seed::random(), crate::RunMode::Real);
        let graph = shared.graph.clone();
        let g = graph.clone();
        let (attacher, mut attachments) = crate::attachments();
        let _sandbox = attacher.attach("agent").unwrap();
        let seen = Arc::new(fictionet::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        crate::block_on(crate::run::run_with(shared, move |fcx| async move {
            let lan = fcx.group("office LAN");
            let hosts = lan.group("hosts");
            // Taken with the world's `Cx`, read by a task in the group.
            let sandbox = attachments.get(&fcx, "agent").await?;
            let slow = delay(&lan, ms(1), sandbox);
            let (to_host, host) = crate::pair();
            route::router(
                &fcx,
                vec![
                    ("0.0.0.0/0".parse()?, Box::new(slow) as Box<dyn Interface>),
                    ("10.0.0.5/32".parse()?, Box::new(to_host)),
                ],
            );
            hosts.spawn(move |fcx| async move {
                // A task started by a grouped task is in the group too.
                fcx.spawn(move |fcx| async move {
                    let mut host = host;
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the task only waits as a member of the group until the run is cancelled; the test checks the snapshot's groups"
                    )]
                    let _ = host.recv(&fcx).await;
                    Ok(())
                });
                Ok(())
            });
            fcx.sleep(ms(30)).await?;
            let (_, (_, data)) = snapshot(&g, None);
            s.lock().push(data);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
        let data = seen.lock().pop().unwrap();
        let groups: Vec<&str> = data
            .split(r#"{"id":"g"#)
            .skip(1)
            .map(|r| r.split('}').next().unwrap())
            .collect();
        assert_eq!(
            groups,
            [
                r#"1","name":"office LAN","parent":null"#,
                r#"2","name":"hosts","parent":"g1""#
            ],
            "{data}"
        );
        let node = |name: &str| {
            data.split(r#"{"id":""#)
                .find(|n| n.contains(&format!(r#""name":"{name}""#)))
                .unwrap_or_else(|| panic!("{name}: {data}"))
        };
        assert!(node("delay").contains(r#""group":"g1""#), "{data}");
        assert!(
            node("agent").contains(r#""kind":"sandbox""#)
                && node("agent").contains(r#""group":"g1""#),
            "{data}"
        );
        assert!(node("router").contains(r#""group":null"#), "{data}");
        assert!(node("world").contains(r#""group":null"#), "{data}");
        // The inner task: its future type is a closure in this test.
        let inner = data
            .split(r#"{"id":""#)
            .filter(|n| n.contains(r#""group":"g2""#))
            .count();
        assert_eq!(
            inner, 1,
            "the task started by the grouped task, alone in g2: {data}"
        );
    }

    /// A group that empties is announced gone, after its nodes.
    #[test]
    fn groups_come_and_go_with_their_tasks() {
        let graph = crate::run::RunShared::new(crate::Seed::random(), crate::RunMode::Real)
            .graph
            .clone();
        graph.task_started(1, "world".into(), Location::caller(), None);
        let (mut view, _) = snapshot(&graph, None);
        let outer = Group::new(graph.next_group(), "outer".into(), None);
        let inner = Group::new(graph.next_group(), "inner".into(), Some(outer.clone()));
        graph.task_started(2, "delay".into(), Location::caller(), Some(inner));
        let m = changes(&graph, &mut view);
        assert_eq!(names(&m), ["group", "group", "node"]);
        assert!(
            m[1].1.contains(r#""name":"inner","parent":"g1""#),
            "{}",
            m[1].1
        );
        assert!(m[2].1.contains(r#""group":"g2""#), "{}", m[2].1);
        graph.task_ended(2);
        assert_eq!(
            names(&changes(&graph, &mut view)),
            ["node_end", "group_end", "group_end"]
        );
    }

    #[test]
    fn link_changes_refresh_cached_topology() {
        let graph = crate::run::RunShared::new(crate::Seed::random(), crate::RunMode::Real)
            .graph
            .clone();
        graph.task_started(1, "world".into(), Location::caller(), None);
        graph.task_started(2, "worker".into(), Location::caller(), None);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        graph.owns(&meter, 1, 2);
        let (mut view, _) = snapshot(&graph, None);
        graph.label(&meter, "link label".into());
        let update = changes(&graph, &mut view);
        assert_eq!(names(&update), ["edge"]);
        assert!(update[0].1.contains("link label"));
        assert!(changes(&graph, &mut view).is_empty());
        meter.sent(0, &crate::Packet(vec![0; 32]));
        assert_eq!(names(&changes(&graph, &mut view)), ["counters"]);
        assert!(changes(&graph, &mut view).is_empty());
        drop(meter);
        assert_eq!(names(&changes(&graph, &mut view)), ["edge_end"]);
        assert_eq!(view.nodes.len(), 2);
    }

    #[test]
    fn unchanged_large_graph() {
        let graph = crate::run::RunShared::new(crate::Seed::random(), crate::RunMode::Real)
            .graph
            .clone();
        for id in 1..=1000 {
            graph.task_started(id, "worker".into(), Location::caller(), None);
        }
        let (mut view, _) = snapshot(&graph, None);
        let node = view.nodes["t1"].as_ptr();
        let started = std::time::Instant::now();
        for _ in 0..100 {
            assert!(changes(&graph, &mut view).is_empty());
            assert_eq!(view.nodes["t1"].as_ptr(), node);
        }
        eprintln!("100 unchanged graph ticks: {:?}", started.elapsed());
    }

    #[test]
    fn changes_follow_the_graph() {
        let graph = history_graph();
        graph.task_started(1, "world".into(), Location::caller(), None);
        let (mut view, (name, data)) = snapshot(&graph, None);
        assert_eq!(name, "snapshot");
        assert!(data.contains(r#""id":"t1","kind":"world""#), "{data}");
        assert!(changes(&graph, &mut view).is_empty());

        // A new task, and a pair between it and the world.
        graph.task_started(2, "delay".into(), Location::caller(), None);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        graph.owns(&meter, 1, 2);
        let m = changes(&graph, &mut view);
        assert_eq!(names(&m), ["node", "edge", "counters"]);
        assert!(m[1].1.contains(r#""a":"t1","b":"t2""#), "{}", m[1].1);

        let expected = counters_json(view.counters.iter());
        assert!(counters(&graph).contains(&format!("\"edges\":{expected}")));

        // The pair closes and the task ends: the edge goes before the node.
        drop(meter);
        graph.task_ended(2);
        assert_eq!(names(&changes(&graph, &mut view)), ["edge_end", "node_end"]);

        // Events are sent once each.
        retain(
            &graph,
            crate::events::Event::new("bottleneck", "drop").summary("queue full"),
        );
        let (m, full) = event_changes(&graph, &mut view);
        assert!(!full);
        assert_eq!(names(&m), ["event"]);
        assert!(
            m[0].1.contains(
                r#""source":"bottleneck","kind":"drop","level":"info","summary":"queue full""#
            ),
            "{}",
            m[0].1
        );
        assert!(event_changes(&graph, &mut view).0.is_empty());

        graph.run_ended();
        assert_eq!(names(&changes(&graph, &mut view)), ["node_end", "ended"]);
    }
}
