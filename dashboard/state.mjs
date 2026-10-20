// The page's graph: tasks, sandboxes, hosts, groups and links with their
// counters, recent events, loss status and the run clock, kept from the
// watch stream. The map keeps its layout and drawing on the same objects.
import { listen } from './dom.mjs';

export function createState() {
  const state = {
    nodes: new Map(), // id -> task or sandbox, as the world sent it
    edges: new Map(), // id -> link
    hosts: new Map(),
    groups: new Map(), // id -> { id, name, parent }
    events: [],
    serverT: 0, // the run's clock, in seconds, at the last message
    serverAt: 0, // performance.now() when it came
    startedMs: 0,
    ended: false,
    connected: false,
    // Whether a snapshot has arrived, so the graph is known.
    known: false,
    // The watch's loss status: `{ incomplete, losses, ... }`.
    status: null,
    selected: null, // { kind: 'node' | 'group' | 'edge' | 'ended', id }
    search: '',
    view: { x: 0, y: 0, k: 1 },
    userMoved: false,
    layoutDirty: true,
    sideDirty: true,
    // What the viewer chose on the map until the next snapshot: groups
    // opened or closed by hand (by group key), and nodes dragged to a place
    // (by node key).
    expanded: new Map(),
    pins: new Map(),
  };

  const runTime = () => state.serverT + (state.ended ? 0 : (performance.now() - state.serverAt) / 1000);

  function tick(t) {
    state.serverT = t;
    state.serverAt = performance.now();
  }

  function snapshot(s) {
    for (const id of [...state.edges.keys()]) removeEdge(id);
    for (const id of [...state.nodes.keys()]) removeNode(id);
    state.hosts.clear();
    for (const host of s.hosts || []) upsertHost(host);
    state.groups.clear();
    state.events = [];
    tick(s.t);
    state.startedMs = s.started;
    state.ended = s.ended;
    state.connected = true;
    state.known = true;
    state.status = s.status || null;
    // A new graph forgets the places and open groups chosen for the last one.
    state.pins.clear();
    state.expanded.clear();
    for (const g of s.groups || []) upsertGroup(g);
    for (const n of s.nodes) upsertNode(n);
    for (const e of s.edges) upsertEdge(e);
    for (const [id, c] of Object.entries(s.counters)) {
      const e = state.edges.get(id);
      if (e) {
        e.c = c;
        e.t = s.t;
      }
    }
    for (const n of s.events) addEvent(n);
    // Fit once the layout is made.
    state.userMoved = false;
    state.sideDirty = true;
  }

  function upsertHost(host) {
    state.hosts.set(host.id, host);
    state.layoutDirty = state.sideDirty = true;
  }

  function removeHost(id) {
    state.hosts.delete(id);
    state.layoutDirty = state.sideDirty = true;
  }

  function upsertGroup(d) {
    state.groups.set(d.id, { id: d.id, name: d.name, parent: d.parent || null });
    state.layoutDirty = true;
    state.sideDirty = true;
  }

  function removeGroup(id) {
    state.groups.delete(id);
    if (state.selected?.kind === 'group' && state.selected.id === id) state.selected = null;
    state.layoutDirty = true;
    state.sideDirty = true;
  }

  function upsertNode(d) {
    let n = state.nodes.get(d.id);
    if (!n) {
      n = { x: NaN, y: NaN, tx: 0, ty: 0, w: 0, h: 0, edges: new Set(), drops: 0, g: null };
      state.nodes.set(d.id, n);
    }
    Object.assign(n, d);
    if (n.group === undefined) n.group = null;
    if (n.g) {
      n.g.remove();
      n.g = null;
    }
    state.layoutDirty = true;
    state.sideDirty = true;
  }

  function removeNode(id) {
    const n = state.nodes.get(id);
    if (!n) return;
    if (n.g) n.g.remove();
    state.nodes.delete(id);
    if (state.selected && state.selected.kind === 'node' && state.selected.id === id) state.selected = null;
    state.layoutDirty = true;
    state.sideDirty = true;
  }

  function upsertEdge(d) {
    let e = state.edges.get(d.id);
    if (!e) {
      e = { c: [0, 0, 0, 0], t: runTime(), rate: [0, 0], bps: [0, 0], seen: 0 };
      state.edges.set(d.id, e);
    } else {
      for (const end of [e.a, e.b]) state.nodes.get(end)?.edges.delete(e.id);
    }
    Object.assign(e, d);
    for (const end of [e.a, e.b]) state.nodes.get(end)?.edges.add(e.id);
    state.layoutDirty = true;
    state.sideDirty = true;
  }

  function removeEdge(id) {
    const e = state.edges.get(id);
    if (!e) return;
    for (const end of [e.a, e.b]) state.nodes.get(end)?.edges.delete(id);
    state.edges.delete(id);
    state.layoutDirty = true;
    state.sideDirty = true;
  }

  function counters(m) {
    tick(m.t);
    const now = performance.now();
    for (const [id, c] of Object.entries(m.edges)) {
      const e = state.edges.get(id);
      if (!e) continue;
      const dt = m.t - e.t;
      if (dt > 0) {
        e.rate = [(c[0] - e.c[0]) / dt, (c[2] - e.c[2]) / dt];
        e.bps = [(c[1] - e.c[1]) / dt, (c[3] - e.c[3]) / dt];
        e.seen = now;
      }
      e.c = c;
      e.t = m.t;
    }
  }

  function addEvent(n) {
    state.events.push(n);
    if (state.events.length > 500) state.events.shift();
    if (n.kind === 'drop' && n.node) {
      const node = state.nodes.get(n.node);
      if (node) {
        // A drop event counts its repeats (see the events module's Repeats).
        node.drops += n.fields?.count ?? 1;
        if (node.g) {
          node.g.remove();
          node.g = null;
        }
      }
    }
    state.sideDirty = true;
  }

  return { state, runTime, tick, snapshot, upsertHost, removeHost, upsertGroup, removeGroup, upsertNode, removeNode, upsertEdge, removeEdge, counters, addEvent };
}

// The watch events the model listens for, and what each does to the graph.
// `error` and `open` change nothing there and only reach subscribers.
const WATCH = {
  waiting: (graph) => { graph.state.connected = true; },
  snapshot: (graph, data) => graph.snapshot(data),
  host: (graph, data) => graph.upsertHost(data),
  host_end: (graph, data) => graph.removeHost(data.id),
  group: (graph, data) => graph.upsertGroup(data),
  group_end: (graph, data) => graph.removeGroup(data.id),
  node: (graph, data) => graph.upsertNode(data),
  node_end: (graph, data) => graph.removeNode(data.id),
  edge: (graph, data) => graph.upsertEdge(data),
  edge_end: (graph, data) => graph.removeEdge(data.id),
  counters: (graph, data) => graph.counters(data),
  event: (graph, data) => graph.addEvent(data),
  ended: (graph, data) => {
    graph.tick(data.t);
    graph.state.ended = true;
    graph.state.sideDirty = true;
  },
  end: (graph, _, source) => {
    source.close();
    graph.state.ended = true;
  },
  status: (graph, data) => { graph.state.status = data.status; },
  world_error: (graph) => { graph.state.ended = true; },
  error: () => {},
  open: () => {},
};

/// The page's one graph, bound to `source`, a watch. Each watch event is
/// parsed once and applied to the graph; then `subscribe(listener)` calls
/// `listener(name, data)` with it. `subscribe` returns an unsubscribe function.
export function createModel(source) {
  const graph = createState();
  const listeners = new Set();
  const removers = Object.entries(WATCH).map(([name, apply]) => listen(source, name, (event) => {
    const data = event.data ? JSON.parse(event.data) : null;
    apply(graph, data, source);
    for (const listener of [...listeners]) listener(name, data);
  }));
  return {
    ...graph,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    dispose() {
      listeners.clear();
      removers.forEach((remove) => remove());
      source.close();
    },
  };
}
