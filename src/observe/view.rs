//! The graph as the browser sees it, and the messages that keep a browser
//! up to date: a snapshot first, then only what changed.

use std::borrow::Cow;
use std::collections::BTreeMap;

use super::json::{self, Object};
use std::sync::Arc;

use crate::watch::{Graph, GraphState, Group, Note, short_name};

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
    /// The last note sent.
    note_seq: u64,
    ended: bool,
}

impl View {
    /// Whether the world had ended when this view was taken.
    pub(crate) fn ended(&self) -> bool {
        self.ended
    }
}

/// One server-sent event: its name and its JSON data.
pub(crate) type Message = (&'static str, String);

/// How many earlier notes a snapshot carries.
const SNAPSHOT_NOTES: usize = 200;

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
        let json = Object::new().str("id", &id).str("name", &g.name).opt_str("parent", parent.as_deref()).done();
        view.groups.insert(id, json);
    }
    group_id(group.id)
}

/// One task, copied out of the graph.
struct TaskRow {
    id: u64,
    parent: u64,
    group: Option<Arc<Group>>,
    name: Cow<'static, str>,
    file: &'static str,
    line: u32,
    started: std::time::Duration,
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
    ended: bool,
    tasks: Vec<TaskRow>,
    links: Vec<LinkRow>,
}

fn copy(s: &mut GraphState) -> Copy {
    s.links.retain(|_, l| l.meter.strong_count() > 0);
    let tasks = s
        .tasks
        .iter()
        .map(|(id, t)| TaskRow {
            id: *id,
            parent: t.parent,
            group: t.group.clone(),
            name: t.name.clone(),
            file: t.file,
            line: t.line,
            started: t.started,
        })
        .collect();
    let live = |task: u64| (task != 0 && s.tasks.contains_key(&task)).then_some(task);
    let mut links = Vec::with_capacity(s.links.len());
    for (id, link) in &s.links {
        let Some(meter) = link.meter.upgrade() else { continue };
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
        links.push(LinkRow { id: *id, meter, a, b, label: link.label.clone() });
    }
    Copy { ended: s.ended, tasks, links }
}

/// The graph as it was copied, in the form the browser sees.
fn build(mut c: Copy) -> View {
    let mut view = View { ended: c.ended, ..View::default() };
    c.tasks.sort_unstable_by_key(|t| t.id);
    for t in &c.tasks {
        let kind = if t.name == "world" && t.parent == 0 { "world" } else { "task" };
        let parent = (t.parent != 0).then(|| task_id(t.parent));
        let group = t.group.as_ref().map(|g| add_group(&mut view, g));
        let node = Object::new()
            .str("id", &task_id(t.id))
            .str("kind", kind)
            .str("name", &short_name(&t.name))
            .str("file", t.file)
            .num("line", t.line)
            .opt_str("parent", parent.as_deref())
            .opt_str("group", group.as_deref())
            .secs("started", t.started)
            .done();
        view.nodes.insert(task_id(t.id), node);
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

fn note_json(n: &Note) -> String {
    let o = Object::new()
        .num("seq", n.seq)
        .secs("t", n.at)
        .opt_str("node", (n.task != 0).then(|| task_id(n.task)).as_deref())
        .str("kind", n.kind);
    let o = match &n.from {
        Some((name, file, line, parent)) => o
            .str("task", name)
            .str("file", file)
            .num("line", line)
            .opt_str("parent", (*parent != 0).then(|| task_id(*parent)).as_deref()),
        None => o,
    };
    match &n.event {
        Some((name, data)) => o.str("name", name).raw("data", data),
        None => o.str("text", &n.text).bool("packet", n.packet.is_some()),
    }
    .done()
}

/// The `counters` reply: every link's counts now.
pub(crate) fn counters(graph: &Graph) -> String {
    let c = copy(&mut graph.state());
    let view = build(c);
    Object::new().secs("t", graph.start.elapsed()).raw("edges", &counters_json(view.counters.iter())).done()
}

/// The `notes` reply: the notes after number `after`.
pub(crate) fn notes(graph: &Graph, after: u64) -> String {
    let s = graph.state();
    let notes: Vec<String> = s.notes.iter().filter(|n| n.seq > after).map(note_json).collect();
    Object::new().raw("notes", &json::array(notes)).done()
}

/// The `link` reply: one link's ends, label and counts, if it is shown.
pub(crate) fn link(graph: &Graph, id: u64) -> Option<String> {
    let c = copy(&mut graph.state());
    let view = build(c);
    let edge = view.edges.get(&edge_id(id))?;
    let c = view.counters.get(&edge_id(id))?;
    // The edge's JSON, with its counts added before the closing brace.
    Some(format!("{},\"counters\":[{},{},{},{}]}}", &edge[..edge.len() - 1], c[0], c[1], c[2], c[3]))
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

/// The whole graph, for a browser that just connected. Returns the view
/// the browser now has.
pub(crate) fn snapshot(graph: &Graph) -> (View, Message) {
    let mut s = graph.state();
    let c = copy(&mut s);
    let skip = s.notes.len().saturating_sub(SNAPSHOT_NOTES);
    let notes: Vec<Note> = s.notes.iter().skip(skip).cloned().collect();
    drop(s);
    let mut view = build(c);
    view.note_seq = notes.last().map_or(0, |n| n.seq);
    let notes: Vec<String> = notes.iter().map(note_json).collect();
    let data = Object::new()
        .secs("t", graph.start.elapsed())
        .num("started", graph.start_wall.duration_since(crate::sys::UNIX_EPOCH).map_or(0, |d| d.as_millis()))
        .bool("ended", view.ended)
        .raw("groups", &json::array(view.groups.values()))
        .raw("nodes", &json::array(view.nodes.values()))
        .raw("edges", &json::array(view.edges.values()))
        .raw("counters", &counters_json(view.counters.iter()))
        .raw("notes", &json::array(notes))
        .done();
    (view, ("snapshot", data))
}

/// What changed since `old`, which becomes the graph as it is now.
pub(crate) fn changes(graph: &Graph, old: &mut View) -> Vec<Message> {
    let mut s = graph.state();
    let c = copy(&mut s);
    let notes: Vec<Note> = s.notes.iter().filter(|n| n.seq > old.note_seq).cloned().collect();
    let note_seq = s.notes.back().map_or(old.note_seq, |n| n.seq.max(old.note_seq));
    drop(s);
    let mut new = build(c);
    new.note_seq = note_seq;
    let notes: Vec<String> = notes.iter().map(note_json).collect();

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
    let changed = new.counters.iter().filter(|(id, c)| old.counters.get(*id) != Some(*c));
    let counters = counters_json(changed);
    if counters != "{}" {
        let data = Object::new().secs("t", graph.start.elapsed()).raw("edges", &counters).done();
        out.push(("counters", data));
    }
    for note in notes {
        out.push(("note", note));
    }
    if new.ended && !old.ended {
        out.push(("ended", Object::new().secs("t", graph.start.elapsed()).done()));
    }
    *old = new;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watch::Meter;
    use std::panic::Location;

    fn names(messages: &[Message]) -> Vec<&'static str> {
        messages.iter().map(|m| m.0).collect()
    }

    /// Every task started with a grouped `Cx` belongs to the group, stdlib
    /// tasks and tasks started by tasks included. Groups nest, a sandbox
    /// joins the group of the task that reads it, and a group is listed
    /// while something in it lives.
    #[test]
    fn tasks_and_sandboxes_report_their_groups() {
        use crate::prelude::*;
        use crate::Interface;
        use crate::stdlib::{delay, route};
        use crate::time::ms;
        let graph = Graph::new();
        let g = graph.clone();
        let (attacher, mut attachments) = crate::attachments();
        let _sandbox = attacher.attach("agent").unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        crate::block_on(crate::run::run_with(graph.clone(), move |cx| async move {
            let lan = cx.group("office LAN");
            let hosts = lan.group("hosts");
            // Taken with the world's `Cx`, read by a task in the group.
            let sandbox = attachments.get(&cx, "agent").await?;
            let slow = delay(&lan, ms(1), sandbox);
            let (to_host, host) = crate::pair();
            route::router(&cx, vec![("0.0.0.0/0".parse()?, Box::new(slow) as Box<dyn Interface>), ("10.0.0.5/32".parse()?, Box::new(to_host))]);
            hosts.spawn(move |cx| async move {
                // A task started by a grouped task is in the group too.
                cx.spawn(move |cx| async move {
                    let mut host = host;
                    let _ = host.recv(&cx).await;
                    Ok(())
                });
                Ok(())
            });
            cx.sleep(ms(30)).await?;
            let (_, (_, data)) = snapshot(&g);
            s.lock().unwrap().push(data);
            cx.cancel();
            Ok(())
        }))
        .unwrap();
        let data = seen.lock().unwrap().pop().unwrap();
        let groups: Vec<&str> = data.split(r#"{"id":"g"#).skip(1).map(|r| r.split('}').next().unwrap()).collect();
        assert_eq!(groups, [r#"1","name":"office LAN","parent":null"#, r#"2","name":"hosts","parent":"g1""#], "{data}");
        let node = |name: &str| data.split(r#"{"id":""#).find(|n| n.contains(&format!(r#""name":"{name}""#))).unwrap_or_else(|| panic!("{name}: {data}"));
        assert!(node("delay").contains(r#""group":"g1""#), "{data}");
        assert!(node("agent").contains(r#""kind":"sandbox""#) && node("agent").contains(r#""group":"g1""#), "{data}");
        assert!(node("router").contains(r#""group":null"#), "{data}");
        assert!(node("world").contains(r#""group":null"#), "{data}");
        // The inner task: its future type is a closure in this test.
        let inner = data.split(r#"{"id":""#).filter(|n| n.contains(r#""group":"g2""#)).count();
        assert_eq!(inner, 1, "the task started by the grouped task, alone in g2: {data}");
    }

    /// A group that empties is announced gone, after its nodes.
    #[test]
    fn groups_come_and_go_with_their_tasks() {
        let graph = Graph::new();
        graph.task_started(1, "world".into(), Location::caller(), None);
        let (mut view, _) = snapshot(&graph);
        let outer = Group::new(graph.next_group(), "outer".into(), None);
        let inner = Group::new(graph.next_group(), "inner".into(), Some(outer.clone()));
        graph.task_started(2, "delay".into(), Location::caller(), Some(inner));
        let m = changes(&graph, &mut view);
        assert_eq!(names(&m), ["group", "group", "node"]);
        assert!(m[1].1.contains(r#""name":"inner","parent":"g1""#), "{}", m[1].1);
        assert!(m[2].1.contains(r#""group":"g2""#), "{}", m[2].1);
        graph.task_ended(2);
        assert_eq!(names(&changes(&graph, &mut view)), ["node_end", "group_end", "group_end"]);
    }

    #[test]
    fn changes_follow_the_graph() {
        let graph = Graph::new();
        graph.task_started(1, "world".into(), Location::caller(), None);
        let (mut view, (name, data)) = snapshot(&graph);
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

        // The pair closes and the task ends: the edge goes before the node.
        drop(meter);
        graph.task_ended(2);
        assert_eq!(names(&changes(&graph, &mut view)), ["edge_end", "node_end"]);

        // Notes are sent once each.
        graph.note("drop", "queue full".into(), None);
        let m = changes(&graph, &mut view);
        assert_eq!(names(&m), ["note"]);
        assert!(m[0].1.contains(r#""kind":"drop","text":"queue full""#));
        assert!(changes(&graph, &mut view).is_empty());

        graph.run_ended();
        assert_eq!(names(&changes(&graph, &mut view)), ["node_end", "ended"]);
    }
}
