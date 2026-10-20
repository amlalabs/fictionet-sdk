// Graph state, the run clock, and incoming snapshot and event application.
// The caller passes group views and status, layout, and pulse effects.
export function createState({ view, setStatus, loadLayout, pulse }) {
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
    selected: null, // { kind: 'node' | 'group' | 'edge' | 'ended', id }
    search: '',
    view: { x: 0, y: 0, k: 1 },
    userMoved: false,
    layoutDirty: true,
    sideDirty: true,
    // What the viewer chose, kept per world: groups opened or closed by
    // hand (by group key), and nodes dragged to a place (by node key).
    expanded: new Map(),
    pins: new Map(),
    worldKey: '',
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
    setStatus(s.ended ? 'ended' : 'running', s.ended ? 'World stopped' : 'Running');
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
    loadLayout(s.nodes);
    // Fit once the layout is made, dragged places included.
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
    const gv = view.gviews.get(id);
    if (gv?.g) gv.g.remove();
    view.gviews.delete(id);
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
    pulse(n);
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

// Bind one watch to a graph state. The owner closes it when its view leaves.
export function watchState(source, { state, setStatus, tick, snapshot, upsertHost, removeHost, upsertGroup, removeGroup, upsertNode, removeNode, upsertEdge, removeEdge, counters, addEvent }) {
  const cleanup = [];
  const on = (name, callback) => {
    source.addEventListener(name, callback);
    cleanup.push(() => source.removeEventListener(name, callback));
  };
    on('waiting', () => {
      state.connected = true;
      setStatus('waiting', 'Waiting for a world');
    });
    on('snapshot', (e) => snapshot(JSON.parse(e.data)));
    on('host', (e) => upsertHost?.(JSON.parse(e.data)));
    on('host_end', (e) => removeHost?.(JSON.parse(e.data).id));
    on('group', (e) => upsertGroup(JSON.parse(e.data)));
    on('group_end', (e) => removeGroup(JSON.parse(e.data).id));
    on('node', (e) => upsertNode(JSON.parse(e.data)));
    on('node_end', (e) => removeNode(JSON.parse(e.data).id));
    on('edge', (e) => upsertEdge(JSON.parse(e.data)));
    on('edge_end', (e) => removeEdge(JSON.parse(e.data).id));
    on('counters', (e) => counters(JSON.parse(e.data)));
    on('event', (e) => addEvent(JSON.parse(e.data)));
    on('ended', (e) => {
      tick(JSON.parse(e.data).t);
      state.ended = true;
      setStatus('ended', 'World stopped');
      state.sideDirty = true;
    });
    on('end', () => {
      source.close();
      if (!state.ended) setStatus('ended', 'The world closed');
      state.ended = true;
    });
    on('world_error', (e) => {
      state.ended = true;
      setStatus('ended', JSON.parse(e.data).error);
    });
    on('error', () => {
      if (!state.ended) setStatus('connecting', 'Reconnecting');
    });
  return () => {
    cleanup.forEach((remove) => remove());
    source.close();
  };
}
