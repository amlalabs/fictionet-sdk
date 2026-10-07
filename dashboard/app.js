// The Fictionet dashboard: draws a running world from the observe API.
// `fictionet dashboard` serves this page and turns each `GET api/<op>?...`
// into one observe request (see `fictionet::observe`): `watch` for the
// graph and its changes, `packets` for the packets of one link or several,
// `packet` for one packet's layers, `pcap` for a capture. No libraries: the
// graph is SVG, laid out in columns by distance from the sandboxes, with
// each open group laid out inside its own frame.
'use strict';

const $ = (id) => document.getElementById(id);
const SVGNS = 'http://www.w3.org/2000/svg';
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

// ---------------------------------------------------------------------------
// State

const state = {
  nodes: new Map(), // id -> task or sandbox, as the world sent it
  edges: new Map(), // id -> link
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

// The drawing, derived from the state by `derive`: what is shown, and the
// edges between what is shown.
const view = {
  items: new Map(), // display id -> a task, a sandbox, or a closed group
  dedges: new Map(), // display id -> an edge between two items
  frames: new Map(), // group id -> the frame of an open group
  owner: new Map(), // task or sandbox id -> the display id that shows it
  contOf: new Map(), // display id or 'f:'+group id -> the group it sits in, or null
  gviews: new Map(), // group id -> its closed-group item, kept across layouts
  info: new Map(), // group id -> { key, depth, leaves, sandboxes, tasks }
};

const el = (tag, attrs = {}, parent) => {
  const e = tag.startsWith('svg:') ? document.createElementNS(SVGNS, tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'text') e.textContent = v;
    else if (k === 'class') e.setAttribute('class', v);
    else e.setAttribute(k, v);
  }
  if (parent) parent.appendChild(e);
  return e;
};

const runTime = () => state.serverT + (state.ended ? 0 : (performance.now() - state.serverAt) / 1000);

function fmtDuration(s) {
  s = Math.max(0, Math.floor(s));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}
function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < u.length - 1);
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}
function fmtCount(n) {
  if (n < 1000) return String(Math.round(n));
  if (n < 1e6) return `${(n / 1e3).toFixed(n < 1e4 ? 1 : 0)}k`;
  return `${(n / 1e6).toFixed(1)}M`;
}
function fmtRate(n) {
  if (n <= 0) return '0';
  if (n < 10) return n.toFixed(1);
  return fmtCount(n);
}
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const shortFile = (f) => (f ? f.split('/').pop() : '');
const where = (n) => (n.file ? `${shortFile(n.file)}:${n.line}` : '');
const nodeLabel = (n) => (n ? n.name : '?');
const isGroup = (n) => n && n.kind === 'group';

// ---------------------------------------------------------------------------
// The graph stream

let events;
function connect() {
  events = new EventSource('api/watch');
  events.addEventListener('waiting', () => {
    state.connected = true;
    setStatus('waiting', 'Waiting for a world');
  });
  events.addEventListener('snapshot', (e) => snapshot(JSON.parse(e.data)));
  events.addEventListener('group', (e) => upsertGroup(JSON.parse(e.data)));
  events.addEventListener('group_end', (e) => removeGroup(JSON.parse(e.data).id));
  events.addEventListener('node', (e) => upsertNode(JSON.parse(e.data)));
  events.addEventListener('node_end', (e) => removeNode(JSON.parse(e.data).id));
  events.addEventListener('edge', (e) => upsertEdge(JSON.parse(e.data)));
  events.addEventListener('edge_end', (e) => removeEdge(JSON.parse(e.data).id));
  events.addEventListener('counters', (e) => counters(JSON.parse(e.data)));
  events.addEventListener('event', (e) => addEvent(JSON.parse(e.data)));
  events.addEventListener('ended', (e) => {
    tick(JSON.parse(e.data).t);
    state.ended = true;
    setStatus('ended', 'World stopped');
    state.sideDirty = true;
  });
  events.addEventListener('end', () => {
    // The stream is over: do not reconnect to a world that has ended.
    events.close();
    if (!state.ended) setStatus('ended', 'The world closed');
    state.ended = true;
  });
  events.onerror = () => {
    if (!state.ended) setStatus('connecting', 'Reconnecting');
  };
}

function tick(t) {
  state.serverT = t;
  state.serverAt = performance.now();
}

function setStatus(kind, text) {
  $('status').dataset.state = kind;
  $('status-text').textContent = text;
}

function snapshot(s) {
  for (const id of [...state.edges.keys()]) removeEdge(id);
  for (const id of [...state.nodes.keys()]) removeNode(id);
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

/// The class that colors an event: `bad` for drops, lost routes and
/// alarms, `good` for kept TLS keys.
function tone(n) {
  if (n.kind === 'drop' || n.kind === 'route_removed' || n.level === 'alarm') return 'bad';
  if (n.source === 'tls' && n.kind === 'keys') return 'good';
  return '';
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

/// The item an event came from, as drawn: the task, the closed group it is
/// in, or, for a short task with no links (one per connection), the
/// nearest of its ancestors that is drawn.
function drawnSource(n) {
  let id = n.node;
  let parent = n.parent;
  for (let hops = 0; hops < 8; hops++) {
    const node = state.nodes.get(id);
    if (node) {
      const shown = view.items.get(view.owner.get(id));
      if (shown?.g) return shown;
      // A task with no links shows in its closed group, if it has one.
      const closed = closedGroupOf(node.group);
      if (closed?.g) return closed;
    }
    id = node ? node.parent : parent;
    parent = null;
    if (!id) return null;
  }
  return null;
}

/// The outermost closed group that `gid` is in, or is, as drawn.
function closedGroupOf(gid) {
  for (const g of groupChain(gid)) {
    const item = view.items.get(g.id);
    if (item) return item;
  }
  return null;
}

/// A ring that grows out of the item an event came from, and fades.
function pulse(n) {
  if (reducedMotion.matches || document.hidden) return;
  const node = drawnSource(n);
  if (!node) return;
  const ring = el(
    'svg:rect',
    {
      class: `pulse ${tone(n)}`,
      x: node.x - 3,
      y: node.y - 3,
      width: node.w + 6,
      height: node.h + 6,
      rx: 10,
    },
    gLabels,
  );
  ring.addEventListener('animationend', () => ring.remove());
}

/// The packet rate a link shows now, each way: zero once updates stop.
function liveRate(e) {
  return performance.now() - e.seen < 700 ? e.rate : [0, 0];
}

/// A drawn edge's rate each way, from end a to end b and back: the sum of
/// the links it stands for.
const dRate = (d) => G.rates(d, liveRate);

/// A drawn edge's counts, as a link's: packets and bytes from a, then
/// from b.
const dCounts = (d) => G.counts(d);

function dBytesRate(d) {
  let b = 0;
  for (const { e } of d.members) {
    const r = liveRate(e);
    b += e.bps[0] * (r[0] > 0) + e.bps[1] * (r[1] > 0);
  }
  return b;
}

/// A drawn edge's two ends, the sandbox side first if it has one, and
/// whether that swapped them.
function ends(d) {
  const a = view.items.get(d.a);
  const b = view.items.get(d.b);
  const sandboxy = (n) => n && (n.kind === 'sandbox' || (isGroup(n) && n.sandboxes > 0));
  return sandboxy(b) && !sandboxy(a) ? [b, a, true] : [a, b, false];
}

// ---------------------------------------------------------------------------
// Groups: which are open, and what is drawn for each task.

const G = FictionetGroups;
const groupChain = (gid) => G.chain(state.groups, gid);
const parentOf = (gid) => G.parentOf(state.groups, gid);

/// Whether group `gid` is drawn open: as the viewer chose, or by default
/// when it is outermost and not too big.
function isOpen(gid) {
  const info = view.info.get(gid);
  if (!info) return false;
  if (state.expanded.has(info.key)) return state.expanded.get(info.key);
  return G.openByDefault(info);
}

/// Works out what is drawn (see `FictionetGroups.aggregate`), and keeps
/// what is drawn already for whatever is still there.
function derive() {
  const nodes = [...state.nodes.values()];
  view.info = G.info(state.groups, nodes);
  const agg = G.aggregate(state.groups, nodes, [...state.edges.values()], isOpen);
  const items = new Map();
  for (const [id, did] of agg.owner) {
    if (id !== did) continue;
    const n = state.nodes.get(id);
    n.edges2 = new Set();
    items.set(id, n);
  }
  for (const gid of agg.closed) {
    let gv = view.gviews.get(gid);
    if (!gv) {
      gv = { id: gid, kind: 'group', x: NaN, y: NaN, tx: 0, ty: 0, w: 0, h: 0, g: null };
      view.gviews.set(gid, gv);
    }
    const i = view.info.get(gid);
    const name = state.groups.get(gid).name;
    // What the box shows changed: draw it again.
    if (gv.g && (gv.name !== name || gv.tasks !== i.tasks || gv.sandboxes !== i.sandboxes)) {
      gv.g.remove();
      gv.g = null;
    }
    Object.assign(gv, { name, gid, leaves: i.leaves, sandboxes: i.sandboxes, tasks: i.tasks, key: `g|${i.key}`, edges: new Set() });
    items.set(gid, gv);
  }
  // Keys for the drawn tasks, for pins: the same task at the same place
  // in the same group gets the same key in every run.
  const seen = new Map();
  for (const n of nodes.filter(G.shown).sort((a, b) => Number(a.id.slice(1)) - Number(b.id.slice(1)))) {
    const gk = n.group && view.info.get(n.group) ? view.info.get(n.group).key : '';
    const base = n.kind === 'sandbox' ? `s|${n.name}` : `t|${gk}|${n.name}|${n.file}:${n.line}`;
    const k = seen.get(base) || 0;
    seen.set(base, k + 1);
    n.key = k ? `${base}|${k}` : base;
  }
  // What is no longer drawn loses its drawing.
  for (const n of state.nodes.values()) {
    if (n.g && !items.has(n.id)) {
      n.g.remove();
      n.g = null;
      n.placed = false;
    }
  }
  for (const [gid, gv] of view.gviews) {
    if (gv.g && !items.has(gid)) {
      gv.g.remove();
      gv.g = null;
      gv.placed = false;
    }
  }
  const old = view.dedges;
  const out = new Map();
  for (const d of agg.edges) {
    const prev = old.get(d.id);
    // An edge that is still there keeps its drawing, so its packets keep
    // moving.
    if (prev && prev.a === d.a && prev.b === d.b && prev.label === d.label) {
      prev.members = d.members;
      out.set(d.id, prev);
    } else {
      if (prev) dropEdgeDrawing(prev);
      out.set(d.id, Object.assign(d, { vis: [0, 0], acc: [0, 0], dots: [], g: null }));
    }
  }
  for (const [id, d] of old) if (!out.has(id)) dropEdgeDrawing(d);
  // Drawn tasks keep their drawn edges in `edges2`: `edges` stays their
  // links.
  for (const d of out.values()) {
    for (const end of [d.a, d.b]) {
      const n = items.get(end);
      (isGroup(n) ? n.edges : n.edges2).add(d.id);
    }
  }
  view.items = items;
  view.owner = agg.owner;
  view.contOf = agg.contOf;
  view.dedges = out;
  for (const [gid, f] of view.frames) {
    if (!agg.frames.has(gid)) {
      f.g?.remove();
      view.frames.delete(gid);
    }
  }
  for (const gid of agg.frames) {
    if (!view.frames.has(gid)) view.frames.set(gid, { gid, g: null, box: null, depth: view.info.get(gid).depth });
  }
  if (state.selected?.kind === 'edge' && !out.has(state.selected.id)) state.selected = null;
  if (state.selected?.kind === 'node' && !items.has(state.selected.id) && state.nodes.has(state.selected.id)) {
    // The task is now inside a closed group: select the group.
    const gid = agg.owner.get(state.selected.id);
    state.selected = gid && gid !== state.selected.id ? { kind: 'group', id: gid } : state.selected;
  }
}

/// The drawn edges of an item.
const dEdgesOf = (n) => (isGroup(n) ? n.edges : n.edges2 || new Set());

function dropEdgeDrawing(d) {
  if (d.g) d.g.remove();
  if (d.labelG) d.labelG.remove();
  for (const dot of d.dots || []) {
    dot.el.remove();
    dotCount--;
  }
  d.dots = [];
  d.g = null;
  d.labelG = null;
}

// ---------------------------------------------------------------------------
// Layout: in each container (the world, or an open group), columns by hops
// from the sandboxes, or from the links that leave the container; rows
// ordered so that edges cross as little as they can. An open group is laid
// out first, and takes the space of its frame in the container around it.
// The same graph always gets the same places, so the drawing stays still
// while the world runs. Nodes the viewer dragged stay where they were put.

const PAD = 16; // frame padding
const HEAD = 30; // frame header
const measure = document.createElement('canvas').getContext('2d');
function textWidth(text, font) {
  measure.font = font;
  return measure.measureText(text).width;
}
const MONO_FONT = "400 10.5px 'IBM Plex Mono', 'JetBrains Mono', 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace";

function sizeItem(n) {
  if (isGroup(n)) {
    n.sub = groupSub(n);
    n.w = Math.ceil(Math.max(textWidth(n.name, '600 13px DM Sans, system-ui, sans-serif'), textWidth(n.sub, MONO_FONT)) + 54);
    n.h = 48;
    return;
  }
  const sandbox = n.kind === 'sandbox';
  const nameFont = sandbox ? '550 13.5px DM Sans, system-ui, sans-serif' : '550 12.5px DM Sans, system-ui, sans-serif';
  const sub = sandbox ? 'sandbox' : where(n);
  n.w = Math.ceil(Math.max(textWidth(n.name, nameFont), textWidth(sub, MONO_FONT)) + (sandbox ? 40 : 26));
  n.h = sandbox ? 46 : 42;
}

function groupSub(n) {
  const parts = [];
  if (n.sandboxes) parts.push(plural(n.sandboxes, 'sandbox').replace('sandboxs', 'sandboxes'));
  parts.push(plural(n.tasks, 'task'));
  return parts.join(', ');
}

function sortKey(n) {
  const sandbox = n.kind === 'sandbox' || (n.kind === 'frame' && n.sandboxes > 0) || (isGroup(n) && n.sandboxes > 0);
  return `${sandbox ? 0 : 1}|${n.name}|${String(n.line || 0).padStart(6, '0')}|${n.id.replace(/^\D+/, '').padStart(8, '0')}`;
}

/// Places `items` (each with id, w, h) in columns. `adj` maps an item to
/// its neighbors; `isRoot` picks the items of the first column. Sets
/// each item's lx and ly, and returns the size of the whole.
function arrange(items, adj, isRoot, colGap) {
  const layer = new Map();
  const band = new Map();
  const bfs = (roots, b) => {
    const queue = [...roots];
    for (const r of roots) {
      layer.set(r, 0);
      band.set(r, b);
    }
    while (queue.length) {
      const id = queue.shift();
      for (const next of adj.get(id).slice().sort()) {
        if (!layer.has(next)) {
          layer.set(next, layer.get(id) + 1);
          band.set(next, b);
          queue.push(next);
        }
      }
    }
  };
  const byKey = items.slice().sort((a, b) => (sortKey(a) < sortKey(b) ? -1 : 1));
  const roots = byKey.filter(isRoot).map((n) => n.id);
  let bands = 0;
  if (roots.length) bfs(roots, bands++);
  for (;;) {
    const rest = byKey.filter((n) => !layer.has(n.id));
    if (!rest.length) break;
    rest.sort((a, b) => adj.get(b.id).length - adj.get(a.id).length);
    bfs([rest[0].id], bands++);
  }
  const rowGap = 16;
  let yTop = 0;
  let width = 0;
  for (let b = 0; b < bands; b++) {
    const members = byKey.filter((n) => band.get(n.id) === b);
    const depth = Math.max(...members.map((n) => layer.get(n.id)));
    const cols = Array.from({ length: depth + 1 }, () => []);
    for (const n of members) cols[layer.get(n.id)].push(n);
    const pos = new Map();
    const index = () => cols.forEach((col) => col.forEach((n, i) => pos.set(n.id, i / Math.max(1, col.length - 1))));
    index();
    const sweep = (col, side) => {
      const score = new Map();
      col.forEach((n, i) => {
        const ns = adj.get(n.id).filter((m) => layer.get(m) === layer.get(n.id) + side);
        score.set(n.id, ns.length ? ns.reduce((s, m) => s + pos.get(m), 0) / ns.length : pos.get(n.id));
        score.set(n.id + '#', i);
      });
      col.sort((a, b) => score.get(a.id) - score.get(b.id) || score.get(a.id + '#') - score.get(b.id + '#'));
    };
    for (let round = 0; round < 4; round++) {
      for (let c = 1; c < cols.length; c++) sweep(cols[c], -1);
      index();
      for (let c = cols.length - 2; c >= 0; c--) sweep(cols[c], +1);
      index();
    }
    let x = 0;
    const heights = cols.map((col) => col.reduce((s, n) => s + n.h, 0) + rowGap * Math.max(0, col.length - 1));
    const bandHeight = Math.max(...heights);
    cols.forEach((col, c) => {
      const w = Math.max(...col.map((n) => n.w), 0);
      let y = yTop + (bandHeight - heights[c]) / 2;
      for (const n of col) {
        n.lx = x + (w - n.w) / 2;
        n.ly = y;
        y += n.h + rowGap;
      }
      x += w + colGap;
    });
    width = Math.max(width, x - colGap);
    yTop += bandHeight + (b < bands - 1 ? 56 : 0);
  }
  return { w: width, h: yTop };
}

/// The item of container `cid` that holds drawn item `did`: the item
/// itself, or the frame of the open group it is in. `null` if it is not
/// in `cid` at all.
function itemIn(did, cid) {
  let c = view.contOf.get(did);
  if (c === cid) return did;
  while (c != null) {
    const p = parentOf(c);
    if (p === cid) return `f:${c}`;
    c = p;
  }
  return null;
}

function layout() {
  derive();
  const children = new Map([[null, []]]);
  for (const gid of view.frames.keys()) children.set(gid, []);
  for (const [did, n] of view.items) {
    sizeItem(n);
    children.get(view.contOf.get(did))?.push({ id: did, node: n, w: n.w, h: n.h, name: n.name, kind: n.kind, line: n.line, sandboxes: n.sandboxes });
  }
  for (const gid of view.frames.keys()) {
    const g = state.groups.get(gid);
    children.get(parentOf(gid))?.push({ id: `f:${gid}`, gid, kind: 'frame', name: g.name, sandboxes: view.info.get(gid).sandboxes });
  }
  const dlist = [...view.dedges.values()];
  // Lays out container `cid` and the open groups in it. Returns its size.
  const lay = (cid) => {
    const items = children.get(cid) || [];
    for (const it of items) {
      if (it.kind !== 'frame') continue;
      const inner = lay(it.gid);
      const title = textWidth(it.name, '600 12.5px DM Sans, system-ui, sans-serif') + 60;
      it.cw = inner.w;
      it.w = Math.max(inner.w, title) + PAD * 2;
      it.h = inner.h + HEAD + PAD;
    }
    const adj = new Map(items.map((it) => [it.id, []]));
    const leaving = new Set();
    for (const d of dlist) {
      const ia = itemIn(d.a, cid);
      const ib = itemIn(d.b, cid);
      if (ia && ib && ia !== ib) {
        adj.get(ia).push(ib);
        adj.get(ib).push(ia);
      } else if (ia && !ib) leaving.add(ia);
      else if (ib && !ia) leaving.add(ib);
    }
    const hasSandbox = (it) => it.kind === 'sandbox' || it.sandboxes > 0;
    const anySandbox = items.some(hasSandbox);
    const isRoot = cid === null || anySandbox ? hasSandbox : (it) => leaving.has(it.id);
    const size = arrange(items, adj, isRoot, cid === null ? 92 : 64);
    return size;
  };
  lay(null);
  // Places container `cid`'s items, with its top left corner at ox, oy.
  const place = (cid, ox, oy) => {
    for (const it of children.get(cid) || []) {
      const x = ox + it.lx;
      const y = oy + it.ly;
      if (it.kind === 'frame') {
        place(it.gid, x + PAD + (it.w - PAD * 2 - it.cw) / 2, y + HEAD);
        continue;
      }
      const n = it.node;
      const pin = state.pins.get(n.key);
      n.tx = pin ? pin.x : x;
      n.ty = pin ? pin.y : y;
      n.pinned = !!pin;
    }
  };
  place(null, 0, 0);
  makeRoom(children.get(null) || []);
  for (const n of view.items.values()) {
    if (Number.isNaN(n.x)) {
      // A new item grows out of its first neighbor that has a place.
      const near = [...dEdgesOf(n)]
        .map((id) => view.dedges.get(id))
        .map((d) => view.items.get(d.a === n.id ? d.b : d.a))
        .find((m) => m && !Number.isNaN(m.x));
      n.x = near ? near.x : n.tx;
      n.y = near ? near.y : n.ty;
    }
  }
  state.layoutDirty = false;
  if (!state.userMoved) fit(false);
}

/// Keeps what the viewer did not drag out of the way of what they did:
/// each outermost item that would overlap a dragged node, or a frame with
/// a dragged node in it, moves down until it is clear.
function makeRoom(top) {
  const GAP = 18;
  frameRects(true);
  const parts = top.map((it) => {
    const nodes = it.kind === 'frame' ? itemsInFrame(it.gid) : [it.node];
    const box = it.kind === 'frame' ? view.frames.get(it.gid)?.box : { x: it.node.tx, y: it.node.ty, w: it.node.w, h: it.node.h };
    return { nodes, box: box && { ...box }, fixed: nodes.some((n) => n.pinned) };
  });
  const placed = parts.filter((p) => p.fixed && p.box);
  if (!placed.length) return;
  const overlaps = (a, b) => a.x < b.x + b.w + GAP && b.x < a.x + a.w + GAP && a.y < b.y + b.h + GAP && b.y < a.y + a.h + GAP;
  for (const p of parts.filter((q) => !q.fixed && q.box).sort((a, b) => a.box.y - b.box.y)) {
    for (let round = 0; round < 50; round++) {
      const hit = placed.find((q) => overlaps(p.box, q.box));
      if (!hit) break;
      const dy = hit.box.y + hit.box.h + GAP - p.box.y;
      p.box.y += dy;
      for (const n of p.nodes) n.ty += dy;
    }
    placed.push(p);
  }
}

/// The drawn items inside open group `gid`, at any depth.
function itemsInFrame(gid) {
  const out = [];
  for (const [did, n] of view.items) {
    let c = view.contOf.get(did);
    while (c != null && c !== gid) c = parentOf(c);
    if (c === gid) out.push(n);
  }
  return out;
}

/// The frame of each open group: the box around what is drawn inside it,
/// innermost groups first so that outer frames hold the inner ones.
function frameRects(useTargets) {
  const list = [...view.frames.values()].sort((a, b) => b.depth - a.depth);
  for (const f of list) {
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    for (const n of itemsInFrame(f.gid)) {
      const x = useTargets ? n.tx : n.x;
      const y = useTargets ? n.ty : n.y;
      if (Number.isNaN(x)) continue;
      x0 = Math.min(x0, x);
      y0 = Math.min(y0, y);
      x1 = Math.max(x1, x + n.w);
      y1 = Math.max(y1, y + n.h);
    }
    // Inner frames, already measured.
    for (const g of list) {
      if (g.depth > f.depth && parentOf(g.gid) === f.gid && g.box) {
        x0 = Math.min(x0, g.box.x);
        y0 = Math.min(y0, g.box.y);
        x1 = Math.max(x1, g.box.x + g.box.w);
        y1 = Math.max(y1, g.box.y + g.box.h);
      }
    }
    if (x0 === Infinity) {
      f.box = null;
      continue;
    }
    const title = textWidth(state.groups.get(f.gid)?.name || '', '600 12.5px DM Sans, system-ui, sans-serif') + 60;
    const w = Math.max(x1 - x0 + PAD * 2, title);
    f.box = { x: x0 - PAD - (w - (x1 - x0 + PAD * 2)) / 2, y: y0 - HEAD, w, h: y1 - y0 + HEAD + PAD };
  }
  return list;
}

// ---------------------------------------------------------------------------
// Drawing

const gFrames = $('frames');
const gNodes = $('nodes');
const gEdges = $('edges');
const gDots = $('dots');
const gLabels = $('labels');
const viewport = $('viewport');

function drawNode(n) {
  if (isGroup(n)) return drawGroup(n);
  const sandbox = n.kind === 'sandbox';
  const g = el('svg:g', { class: `node ${n.kind}`, 'data-id': n.id, tabindex: '0', role: 'button' });
  if (state.selected && state.selected.kind === 'node' && state.selected.id === n.id) g.classList.add('selected');
  g.setAttribute('aria-label', sandbox ? `Sandbox ${n.name}` : `Task ${n.name}, spawned at ${where(n)}`);
  el('svg:rect', { class: 'box', width: n.w, height: n.h, rx: sandbox ? 9 : 7 }, g);
  const left = sandbox ? 28 : 13;
  if (sandbox) el('svg:rect', { class: 'mark', x: 12, y: n.h / 2 - 4, width: 8, height: 8, rx: 1 }, g);
  el('svg:text', { class: 'name', x: left, y: sandbox ? 20 : 18, text: n.name }, g);
  el('svg:text', { class: 'where', x: left, y: sandbox ? 35 : 32, text: sandbox ? 'sandbox' : where(n) }, g);
  if (n.drops > 0) {
    const label = `${fmtCount(n.drops)} dropped`;
    const w = label.length * 6.3 + 12;
    const b = el('svg:g', { class: 'badge', transform: `translate(${n.w - w + 6},-9)` }, g);
    el('svg:rect', { width: w, height: 17, rx: 8.5 }, b);
    el('svg:text', { x: 6, y: 12, text: label }, b);
  }
  hookItem(g, n, () => select({ kind: 'node', id: n.id }), () => nodeTip(n));
  gNodes.appendChild(g);
  n.g = g;
}

/// A closed group: one box, a little stack of cards, with a + to open it.
function drawGroup(n) {
  const g = el('svg:g', { class: 'node group', 'data-id': n.id, tabindex: '0', role: 'button' });
  if (state.selected?.kind === 'group' && state.selected.id === n.id) g.classList.add('selected');
  g.setAttribute('aria-label', `Group ${n.name}, ${n.sub}. Double-click to open.`);
  el('svg:rect', { class: 'card', x: 6, y: 6, width: n.w, height: n.h, rx: 8 }, g);
  el('svg:rect', { class: 'card', x: 3, y: 3, width: n.w, height: n.h, rx: 8 }, g);
  el('svg:rect', { class: 'box', width: n.w, height: n.h, rx: 8 }, g);
  el('svg:text', { class: 'name', x: 14, y: 21, text: n.name }, g);
  el('svg:text', { class: 'where', x: 14, y: 36, text: n.sub }, g);
  const t = el('svg:g', { class: 'toggle', transform: `translate(${n.w - 28},${n.h / 2 - 10})` }, g);
  el('svg:title', { text: 'Open the group' }, t);
  el('svg:rect', { width: 20, height: 20, rx: 5 }, t);
  el('svg:path', { d: 'M6 10h8M10 6v8' }, t);
  t.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (!suppressClick) toggleGroup(n.gid);
  });
  hookItem(g, n, () => select({ kind: 'group', id: n.gid }), () => groupTip(n.gid));
  g.addEventListener('dblclick', (ev) => {
    ev.stopPropagation();
    toggleGroup(n.gid);
  });
  gNodes.appendChild(g);
  n.g = g;
}

/// Click, keyboard, tooltip and drag for a drawn item.
function hookItem(g, n, onSelect, tipFill) {
  g.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (!suppressClick) onSelect();
  });
  g.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') {
      ev.preventDefault();
      onSelect();
    }
    if (isGroup(n) && (ev.key === '+' || ev.key === '=')) toggleGroup(n.gid);
  });
  g.addEventListener('pointerenter', (ev) => showTip(ev, tipFill));
  g.addEventListener('pointermove', moveTip);
  g.addEventListener('pointerleave', hideTip);
  g.addEventListener('pointerdown', (ev) => startDrag(ev, [n], n));
}

/// An open group's frame: a box behind what it holds, with its name on top.
function drawFrame(f) {
  const grp = state.groups.get(f.gid);
  const g = el('svg:g', { class: `frame depth${Math.min(f.depth, 3)}`, 'data-id': `f:${f.gid}` });
  f.rectEl = el('svg:rect', { class: 'fbox', rx: 12 }, g);
  const head = el('svg:g', { class: 'fhead', tabindex: '0', role: 'button' }, g);
  head.setAttribute('aria-label', `Group ${grp.name}, open. Double-click to close.`);
  f.headRect = el('svg:rect', { class: 'fhit', height: HEAD - 4, rx: 8 }, head);
  el('svg:text', { class: 'fname', x: 12, y: 19, text: grp.name }, head);
  f.toggle = el('svg:g', { class: 'toggle small' }, head);
  el('svg:title', { text: 'Close the group' }, f.toggle);
  el('svg:rect', { width: 18, height: 18, rx: 5 }, f.toggle);
  el('svg:path', { d: 'M5 9h8' }, f.toggle);
  f.toggle.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (!suppressClick) toggleGroup(f.gid);
  });
  head.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (!suppressClick) select({ kind: 'group', id: f.gid });
  });
  head.addEventListener('dblclick', (ev) => {
    ev.stopPropagation();
    toggleGroup(f.gid);
  });
  head.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') {
      ev.preventDefault();
      select({ kind: 'group', id: f.gid });
    }
    if (ev.key === '-') toggleGroup(f.gid);
  });
  head.addEventListener('pointerenter', (ev) => showTip(ev, () => groupTip(f.gid)));
  head.addEventListener('pointermove', moveTip);
  head.addEventListener('pointerleave', hideTip);
  head.addEventListener('pointerdown', (ev) => startDrag(ev, itemsInFrame(f.gid), null));
  // Outer frames first, so inner frames are drawn over them.
  const after = [...gFrames.children].find((c) => Number(c.dataset.depth) > f.depth);
  g.dataset.depth = f.depth;
  gFrames.insertBefore(g, after || null);
  f.g = g;
  f.drawn = '';
}

function updateFrames() {
  for (const f of frameRects(false)) {
    if (!f.g) drawFrame(f);
    const b = f.box;
    f.g.style.display = b ? '' : 'none';
    if (!b) continue;
    const sel = state.selected?.kind === 'group' && state.selected.id === f.gid;
    f.g.classList.toggle('selected', sel);
    const geom = `${b.x.toFixed(1)},${b.y.toFixed(1)},${b.w.toFixed(1)},${b.h.toFixed(1)}`;
    if (geom === f.drawn) continue;
    f.drawn = geom;
    f.g.setAttribute('transform', `translate(${b.x.toFixed(1)},${b.y.toFixed(1)})`);
    f.rectEl.setAttribute('width', b.w.toFixed(1));
    f.rectEl.setAttribute('height', b.h.toFixed(1));
    f.headRect.setAttribute('width', b.w.toFixed(1));
    f.toggle.setAttribute('transform', `translate(${(b.w - 26).toFixed(1)},4)`);
  }
}

function drawEdge(d) {
  const g = el('svg:g', { class: `edge${d.members.length > 1 ? ' merged' : ''}`, 'data-id': d.id, 'data-a': d.a, 'data-b': d.b });
  if (state.selected && state.selected.kind === 'edge' && state.selected.id === d.id) g.classList.add('selected');
  d.wire = el('svg:path', { class: 'wire' }, g);
  d.hit = el('svg:path', { class: 'hit' }, g);
  const label = d.label || (d.members.length > 1 ? `${d.members.length} links` : null);
  if (label) {
    // Labels sit above the moving packets, in a layer of their own.
    d.labelG = el('svg:g', { class: `route-label${d.label ? '' : ' count'}` }, gLabels);
    const w = label.length * 6.4 + 12;
    el('svg:rect', { x: -w / 2, y: -9, width: w, height: 18, rx: 4 }, d.labelG);
    el('svg:text', { x: -w / 2 + 6, y: 4, text: label }, d.labelG);
  }
  d.hit.addEventListener('click', (ev) => {
    ev.stopPropagation();
    select({ kind: 'edge', id: d.id });
    openPackets(d.id);
  });
  d.hit.addEventListener('pointerenter', (ev) => showTip(ev, () => edgeTip(d)));
  d.hit.addEventListener('pointermove', moveTip);
  d.hit.addEventListener('pointerleave', hideTip);
  gEdges.appendChild(g);
  d.g = g;
  d.geom = '';
}

/// The path from one item to another: out of the right side of the one on
/// the left, into the left side of the other. When the two overlap left
/// to right, a loop out to the right.
function edgePath(d) {
  const a = view.items.get(d.a);
  const b = view.items.get(d.b);
  if (!a || !b) return null;
  let [p, q] = [a, b];
  let forward = true;
  if (b.x + b.w / 2 < a.x + a.w / 2) {
    [p, q] = [b, a];
    forward = false;
  }
  if (q.x < p.x + p.w + 12) {
    const x1 = p.x + p.w;
    const x2 = q.x + q.w;
    const y1 = p.y + p.h / 2;
    const y2 = q.y + q.h / 2;
    const out = Math.max(x1, x2) + 40 + Math.abs(y2 - y1) * 0.15;
    return { d: `M${x1},${y1} C${out},${y1} ${out},${y2} ${x2},${y2}`, forward };
  }
  const x1 = p.x + p.w;
  const y1 = p.y + p.h / 2;
  const x2 = q.x;
  const y2 = q.y + q.h / 2;
  const mid = (x2 - x1) * 0.5;
  return { d: `M${x1},${y1} C${x1 + mid},${y1} ${x2 - mid},${y2} ${x2},${y2}`, forward };
}

function edgeWidth(pps) {
  return Math.min(9, 1.3 + 2.1 * Math.log10(1 + pps));
}

// ---------------------------------------------------------------------------
// The frame loop: items glide to their places, edges follow, packets move.

let last = performance.now();
let lastSide = 0;
let lastStats = 0;
let dotCount = 0;
const MAX_DOTS = 450;
const DOT_SPEED = 240; // px per second

function frame(now) {
  const dt = Math.min(0.1, (now - last) / 1000);
  last = now;
  if (state.layoutDirty) layout();
  stepTween(now);
  const ease = reducedMotion.matches ? 1 : 1 - Math.exp(-dt * 7);
  const moved = new Set();
  for (const n of view.items.values()) {
    if (!n.g) {
      // A new drawing has no place yet, wherever the item is.
      drawNode(n);
      n.placed = false;
    }
    if (drag?.items.includes(n)) {
      // Being dragged: it is where the pointer put it.
      moved.add(n.id);
    } else {
      const dx = n.tx - n.x;
      const dy = n.ty - n.y;
      if (Math.abs(dx) > 0.2 || Math.abs(dy) > 0.2) {
        n.x += dx * ease;
        n.y += dy * ease;
        moved.add(n.id);
      } else if (n.x !== n.tx || n.y !== n.ty) {
        n.x = n.tx;
        n.y = n.ty;
        moved.add(n.id);
      }
    }
    if (moved.has(n.id) || !n.placed) {
      n.g.setAttribute('transform', `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`);
      n.placed = true;
    }
  }
  updateFrames();
  let total = 0;
  for (const d of view.dedges.values()) {
    if (!d.g) drawEdge(d);
    const a = view.items.get(d.a);
    const b = view.items.get(d.b);
    if (!a || !b || Number.isNaN(a.x) || Number.isNaN(b.x)) continue;
    if (!d.geom || moved.has(d.a) || moved.has(d.b)) {
      const path = edgePath(d);
      if (!path) continue;
      d.wire.setAttribute('d', path.d);
      d.hit.setAttribute('d', path.d);
      d.forward = path.forward;
      d.geom = path.d;
      d.len = d.wire.getTotalLength();
      if (d.labelG) {
        // A route's label goes next to the item it leads to (end b), so
        // the labels of one router fan out instead of piling up.
        const w = Number(d.labelG.firstChild.getAttribute('width'));
        const at = Math.max(0.5, 1 - (w / 2 + 14) / Math.max(1, d.len));
        const m = d.wire.getPointAtLength((d.forward ? at : 1 - at) * d.len);
        d.labelG.setAttribute('transform', `translate(${m.x.toFixed(1)},${m.y.toFixed(1)})`);
      }
    }
    const rate = dRate(d);
    for (let s = 0; s < 2; s++) d.vis[s] += (rate[s] - d.vis[s]) * (1 - Math.exp(-dt * 5));
    const pps = d.vis[0] + d.vis[1];
    d.wire.setAttribute('stroke-width', edgeWidth(pps).toFixed(2));
    d.g.classList.toggle('live', pps > 0.5);
    if (!reducedMotion.matches) moveDots(d, dt);
  }
  for (const e of state.edges.values()) {
    if (state.nodes.get(e.b)?.kind === 'sandbox') {
      const r = liveRate(e);
      total += r[0] + r[1];
    }
  }
  flushPackets();
  if (now - lastStats > 500 || state.sideDirty) {
    lastStats = now;
    renderStats(total);
  }
  // The side panel is rebuilt when something changed, and once a second
  // for its rates, unless the viewer is pointing at it or typing in it.
  const side = $('side');
  const busy = side.matches(':hover') || side.contains(document.activeElement);
  if (state.sideDirty || (now - lastSide > 1000 && !busy)) {
    lastSide = now;
    renderSide();
    renderCrumbs();
    state.sideDirty = false;
  }
  requestAnimationFrame(frame);
}

function moveDots(d, dt) {
  for (let s = 0; s < 2; s++) {
    const pps = d.vis[s];
    if (pps < 0.05) {
      d.acc[s] = 0;
      continue;
    }
    // A dot is a handful of packets: a few per second on a quiet link,
    // never more than 14 per second on a busy one.
    d.acc[s] += Math.min(14, 1.4 + 2.6 * Math.log2(1 + pps)) * dt * (pps < 1 ? pps : 1);
    while (d.acc[s] >= 1 && dotCount < MAX_DOTS) {
      d.acc[s] -= 1;
      const dot = el('svg:circle', { class: s === 0 ? 'packet-dot' : 'packet-dot back', r: 2.6 }, gDots);
      d.dots.push({ el: dot, side: s, p: 0 });
      dotCount++;
    }
    if (d.acc[s] > 1) d.acc[s] = 1;
  }
  if (!d.dots.length) return;
  const step = (DOT_SPEED * dt) / Math.max(40, d.len || 1);
  d.dots = d.dots.filter((dot) => {
    dot.p += step;
    if (dot.p >= 1) {
      dot.el.remove();
      dotCount--;
      return false;
    }
    // Side 0 goes from a to b.
    const along = (dot.side === 0) === d.forward ? dot.p : 1 - dot.p;
    const pt = d.wire.getPointAtLength(along * d.len);
    dot.el.setAttribute('cx', pt.x.toFixed(1));
    dot.el.setAttribute('cy', pt.y.toFixed(1));
    return true;
  });
}

// ---------------------------------------------------------------------------
// Opening and closing groups

/// Opens a closed group, or closes an open one, where it is: the view moves
/// so the group's top left corner stays on the same spot of the screen.
function toggleGroup(gid) {
  const info = view.info.get(gid);
  if (!info) return;
  const open = isOpen(gid);
  // Where it is now, on screen.
  let anchor = null;
  if (open) {
    const f = view.frames.get(gid);
    if (f?.box) anchor = { x: f.box.x, y: f.box.y + HEAD };
  } else {
    const gv = view.items.get(gid);
    if (gv) anchor = { x: gv.x, y: gv.y };
  }
  const k0 = state.view.k;
  const screen = anchor && { x: anchor.x * k0 + state.view.x, y: anchor.y * k0 + state.view.y };
  state.expanded.set(info.key, !open);
  saveLayout();
  // The view stays as it is: no fitting while the group changes.
  state.userMoved = true;
  layout();
  if (!open && anchor) {
    // What the group holds grows out of where the group was.
    for (const n of itemsInFrame(gid)) {
      if (!n.g) {
        n.x = anchor.x;
        n.y = anchor.y;
      }
    }
  }
  let target = null;
  if (open) {
    const gv = view.items.get(gid);
    if (gv) {
      target = { x: gv.tx, y: gv.ty };
      if (anchor) {
        gv.x = anchor.x;
        gv.y = anchor.y;
      }
    }
  } else {
    frameRects(true);
    const f = view.frames.get(gid);
    if (f?.box) target = { x: f.box.x, y: f.box.y + HEAD };
  }
  if (anchor && target) {
    const k = state.view.k;
    state.view.x = screen.x - target.x * k;
    state.view.y = screen.y - target.y * k;
    // Every drawn item glides; the view jumps so the group stays put.
    for (const n of view.items.values()) {
      if (Number.isNaN(n.x)) continue;
      n.x += target.x - anchor.x;
      n.y += target.y - anchor.y;
    }
    state.userMoved = true;
    applyView();
  }
  // Then, if the group now reaches past the view, the view moves (and
  // zooms out, if it must) until it shows the whole group.
  frameRects(true);
  const f = view.frames.get(gid);
  const item = view.items.get(gid);
  const box = f?.box || (item && { x: item.tx, y: item.ty, w: item.w, h: item.h });
  if (box) showBox(box);
  select({ kind: 'group', id: gid });
}

/// Moves the view smoothly so that `box` is on screen, zooming out only
/// if it is bigger than the view.
function showBox(box) {
  const r = stage.getBoundingClientRect();
  const m = 28;
  const v = { ...state.view };
  const k = Math.min(v.k, (r.width - m * 2) / box.w, (r.height - m * 2) / box.h);
  // Zoom about the box's top left corner.
  v.x += box.x * (v.k - k);
  v.y += box.y * (v.k - k);
  v.k = k;
  const left = box.x * k + v.x;
  const top = box.y * k + v.y;
  const right = left + box.w * k;
  const bottom = top + box.h * k;
  if (right > r.width - m) v.x -= right - (r.width - m);
  if (bottom > r.height - m) v.y -= bottom - (r.height - m);
  if (left + (v.x - state.view.x) < m) v.x += m - (box.x * k + v.x);
  if (top + (v.y - state.view.y) < m) v.y += m - (box.y * k + v.y);
  if (Math.abs(v.x - state.view.x) < 1 && Math.abs(v.y - state.view.y) < 1 && v.k === state.view.k) return;
  tweenView(v);
}

let viewTween = null;
function tweenView(to) {
  if (reducedMotion.matches) {
    state.view = to;
    applyView();
    return;
  }
  viewTween = { from: { ...state.view }, to, t0: performance.now(), dur: 450 };
}

function stepTween(now) {
  if (!viewTween) return;
  const { from, to, t0, dur } = viewTween;
  const t = Math.min(1, (now - t0) / dur);
  const e = 1 - Math.pow(1 - t, 3);
  state.view = { x: from.x + (to.x - from.x) * e, y: from.y + (to.y - from.y) * e, k: from.k + (to.k - from.k) * e };
  applyView();
  if (t >= 1) viewTween = null;
}

// ---------------------------------------------------------------------------
// Dragging, pan and zoom

const stage = $('stage');
const graphSvg = $('graph');

function applyView() {
  const { x, y, k } = state.view;
  viewport.setAttribute('transform', `translate(${x.toFixed(1)},${y.toFixed(1)}) scale(${k.toFixed(4)})`);
}

function fit() {
  const nodes = [...view.items.values()];
  if (!nodes.length) return;
  let minX = Math.min(...nodes.map((n) => n.tx));
  let minY = Math.min(...nodes.map((n) => n.ty)) - 12;
  let maxX = Math.max(...nodes.map((n) => n.tx + n.w)) + 60;
  let maxY = Math.max(...nodes.map((n) => n.ty + n.h));
  for (const f of frameRects(true)) {
    if (!f.box) continue;
    minX = Math.min(minX, f.box.x);
    minY = Math.min(minY, f.box.y);
    maxX = Math.max(maxX, f.box.x + f.box.w);
    maxY = Math.max(maxY, f.box.y + f.box.h);
  }
  const r = stage.getBoundingClientRect();
  const pad = 56;
  const k = Math.min(1.35, (r.width - pad * 2) / (maxX - minX), (r.height - pad * 2 - 30) / (maxY - minY));
  state.view = {
    k,
    x: (r.width - (maxX - minX) * k) / 2 - minX * k,
    y: (r.height - 30 - (maxY - minY) * k) / 2 - minY * k,
  };
  applyView();
}

stage.addEventListener(
  'wheel',
  (ev) => {
    ev.preventDefault();
    viewTween = null;
    const r = stage.getBoundingClientRect();
    const px = ev.clientX - r.left;
    const py = ev.clientY - r.top;
    const k = Math.min(4, Math.max(0.15, state.view.k * Math.exp(-ev.deltaY * 0.0015)));
    const f = k / state.view.k;
    state.view = { k, x: px - (px - state.view.x) * f, y: py - (py - state.view.y) * f };
    state.userMoved = true;
    applyView();
  },
  { passive: false },
);

// A drag of items: { items, start: [{x, y}], px, py, moved, pointer }.
let drag = null;
// Set after a drag, so the click that ends it does not select.
let suppressClick = false;

function startDrag(ev, items, _n) {
  if (ev.button !== 0 || ev.target.closest('.toggle')) return;
  ev.stopPropagation();
  drag = { items, start: items.map((n) => ({ x: n.x, y: n.y })), px: ev.clientX, py: ev.clientY, moved: false, pointer: ev.pointerId };
  suppressClick = false;
  // The pointer is captured only once the drag moves, so that a click or
  // double-click without a move still reaches the item.
}

let pan = null;
stage.addEventListener('pointerdown', (ev) => {
  if (drag || ev.target.closest('.node, .edge .hit, .fhead, button, .crumbs')) return;
  viewTween = null;
  pan = { x: ev.clientX, y: ev.clientY, vx: state.view.x, vy: state.view.y, moved: false };
  stage.setPointerCapture(ev.pointerId);
});
stage.addEventListener('pointermove', (ev) => {
  if (drag) {
    const dx = (ev.clientX - drag.px) / state.view.k;
    const dy = (ev.clientY - drag.py) / state.view.k;
    if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 4 / state.view.k) return;
    if (!drag.moved) {
      drag.moved = true;
      stage.setPointerCapture(drag.pointer);
      hideTip();
      stage.classList.add('dragging');
    }
    drag.items.forEach((n, i) => {
      n.x = n.tx = drag.start[i].x + dx;
      n.y = n.ty = drag.start[i].y + dy;
    });
    return;
  }
  if (!pan) return;
  const dx = ev.clientX - pan.x;
  const dy = ev.clientY - pan.y;
  if (Math.abs(dx) + Math.abs(dy) > 3) {
    pan.moved = true;
    stage.classList.add('panning');
  }
  state.view.x = pan.vx + dx;
  state.view.y = pan.vy + dy;
  if (pan.moved) state.userMoved = true;
  applyView();
});
stage.addEventListener('pointerup', () => {
  if (drag) {
    if (drag.moved) {
      // The dragged items stay where they were dropped.
      for (const n of drag.items) {
        state.pins.set(n.key, { x: Math.round(n.x), y: Math.round(n.y) });
        n.pinned = true;
      }
      suppressClick = true;
      setTimeout(() => (suppressClick = false), 0);
      state.userMoved = true;
      saveLayout();
    }
    drag = null;
    stage.classList.remove('dragging');
    return;
  }
  if (pan && !pan.moved) select(null);
  pan = null;
  stage.classList.remove('panning');
});
stage.addEventListener('dblclick', (ev) => {
  if (ev.target.closest('.node, .edge .hit, .fhead, button, .crumbs, .legend')) return;
  resetLayout();
});
$('fit').addEventListener('click', () => {
  state.userMoved = false;
  fit();
});
$('reset').addEventListener('click', resetLayout);

/// Forgets every dragged place, lays the graph out again, and fits it.
function resetLayout() {
  state.pins.clear();
  saveLayout();
  state.userMoved = false;
  layout();
  fit();
}

new ResizeObserver(() => {
  if (!state.userMoved) fit();
}).observe(stage);

// The viewer's places and open groups, kept per world in this browser.
// A world is known by its own source files, which stay the same from run
// to run.
function loadLayout(nodes) {
  const files = [...new Set(nodes.filter((n) => n.file && !n.file.startsWith('src/')).map((n) => n.file))].sort();
  state.worldKey = `fictionet-layout:${files.join(',') || 'world'}`;
  state.pins.clear();
  state.expanded.clear();
  try {
    const saved = JSON.parse(localStorage.getItem(state.worldKey) || 'null');
    if (saved) {
      for (const [k, v] of Object.entries(saved.pins || {})) state.pins.set(k, v);
      for (const [k, v] of Object.entries(saved.open || {})) state.expanded.set(k, v);
    }
  } catch {
    // Storage may be refused or hold something else; start afresh.
  }
}

function saveLayout() {
  if (!state.worldKey) return;
  try {
    localStorage.setItem(state.worldKey, JSON.stringify({ pins: Object.fromEntries(state.pins), open: Object.fromEntries(state.expanded) }));
  } catch {
    // Private windows may refuse storage; the layout lasts for this page.
  }
}

// ---------------------------------------------------------------------------
// Tooltips

const tip = $('tip');
let tipFill = null;

function showTip(ev, fill) {
  if (drag?.moved) return;
  tipFill = fill;
  tip.replaceChildren(...fill());
  tip.hidden = false;
  moveTip(ev);
}
function moveTip(ev) {
  if (tip.hidden) return;
  if (tipFill) tip.replaceChildren(...tipFill());
  const r = tip.getBoundingClientRect();
  let x = ev.clientX + 16;
  let y = ev.clientY + 14;
  if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - 16;
  if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - 14;
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}
function hideTip() {
  tip.hidden = true;
  tipFill = null;
}

function table(rows) {
  const t = el('table');
  for (const [k, v] of rows) {
    const tr = el('tr', {}, t);
    el('td', { text: k }, tr);
    el('td', { text: v }, tr);
  }
  return t;
}

/// Packets a second on the drawn edges of an item.
function itemRate(n) {
  let pps = 0;
  for (const id of dEdgesOf(n)) {
    const d = view.dedges.get(id);
    if (d) {
      const r = dRate(d);
      pps += r[0] + r[1];
    }
  }
  return pps;
}

function nodeTip(n) {
  const out = [el('h3', { text: n.name })];
  if (n.kind === 'sandbox') {
    out.push(el('div', { class: 'sub', text: 'sandbox, attached to the world' }));
  } else {
    out.push(el('div', { class: 'sub', text: `${n.file}:${n.line}` }));
  }
  const rows = [];
  rows.push(['Links', String(n.edges.size)]);
  rows.push(['Packets/s on its links', fmtRate(itemRate(n))]);
  if (n.started !== undefined) rows.push(['Running for', fmtDuration(runTime() - n.started)]);
  if (n.drops) rows.push(['Packets dropped', fmtCount(n.drops)]);
  if (n.group && state.groups.has(n.group)) rows.push(['Group', groupChain(n.group).map((g) => g.name).join(' › ')]);
  out.push(table(rows));
  if (!n.pinned) out.push(el('div', { class: 'hint', text: 'Drag to move it' }));
  return out;
}

function groupTip(gid) {
  const g = state.groups.get(gid);
  const info = view.info.get(gid);
  if (!g || !info) return [];
  const out = [el('h3', { text: g.name })];
  out.push(el('div', { class: 'sub', text: groupChain(gid).map((c) => c.name).join(' › ') }));
  const item = view.items.get(gid);
  const rows = [['Tasks', String(info.tasks)]];
  if (info.sandboxes) rows.push(['Sandboxes', String(info.sandboxes)]);
  rows.push(['Packets/s in and out', fmtRate(groupRate(gid))]);
  out.push(table(rows));
  out.push(el('div', { class: 'hint', text: item ? 'Double-click to open it, drag to move it' : 'Double-click the name to close it' }));
  return out;
}

/// Packets a second on the drawn edges that cross group `gid`'s edge.
function groupRate(gid) {
  let pps = 0;
  for (const d of crossingEdges(gid)) {
    const r = dRate(d);
    pps += r[0] + r[1];
  }
  return pps;
}

/// The drawn edges with one end inside group `gid` and one outside.
function crossingEdges(gid) {
  const inside = (did) => {
    if (did === gid) return true;
    let c = view.contOf.get(did);
    while (c != null) {
      if (c === gid) return true;
      c = parentOf(c);
    }
    return false;
  };
  return [...view.dedges.values()].filter((d) => inside(d.a) !== inside(d.b));
}

function edgeTip(d) {
  const [a, b, swapped] = ends(d);
  const rate = dRate(d);
  const raw = dCounts(d);
  const c = swapped ? [raw[2], raw[3], raw[0], raw[1]] : raw;
  const out = [el('h3', { text: `${nodeLabel(a)} ↔ ${nodeLabel(b)}` })];
  if (d.members.length > 1) out.push(el('div', { class: 'sub', text: `${d.members.length} links, added up${d.label ? `, route ${d.label}` : ''}` }));
  else if (d.label) out.push(el('div', { class: 'sub', text: `route ${d.label}` }));
  else out.push(el('div', { class: 'sub', text: d.id }));
  out.push(
    table([
      [`${nodeLabel(a)} → ${nodeLabel(b)}`, `${fmtCount(c[0])} pkts, ${fmtBytes(c[1])}`],
      [`${nodeLabel(b)} → ${nodeLabel(a)}`, `${fmtCount(c[2])} pkts, ${fmtBytes(c[3])}`],
      ['Now', `${fmtRate(rate[0] + rate[1])} pkts/s, ${fmtBytes(Math.round(dBytesRate(d)))}/s`],
    ]),
  );
  out.push(el('div', { class: 'hint', text: 'Click to watch its packets' }));
  return out;
}

// ---------------------------------------------------------------------------
// Selection, search, the breadcrumb and the side panel

function select(sel) {
  state.selected = sel;
  for (const n of view.items.values()) {
    const on = !!sel && ((sel.kind === 'node' && sel.id === n.id) || (sel.kind === 'group' && isGroup(n) && sel.id === n.gid));
    n.g?.classList.toggle('selected', on);
  }
  for (const d of view.dedges.values()) d.g?.classList.toggle('selected', !!sel && sel.kind === 'edge' && sel.id === d.id);
  state.sideDirty = true;
}

$('search').addEventListener('input', (ev) => {
  state.search = ev.target.value.trim().toLowerCase();
  applySearch();
});
$('search').addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') {
    const hit = [...view.items.values()].find((n) => matches(n));
    if (hit) {
      const r = stage.getBoundingClientRect();
      state.view.x = r.width / 2 - (hit.tx + hit.w / 2) * state.view.k;
      state.view.y = r.height / 2 - (hit.ty + hit.h / 2) * state.view.k;
      state.userMoved = true;
      applyView();
      select(isGroup(hit) ? { kind: 'group', id: hit.gid } : { kind: 'node', id: hit.id });
    }
  } else if (ev.key === 'Escape') {
    ev.target.value = '';
    state.search = '';
    applySearch();
  }
});

function leafMatches(n) {
  const q = state.search;
  if (`${n.name} ${n.file || ''}:${n.line || ''} ${n.kind}`.toLowerCase().includes(q)) return true;
  for (const id of n.edges) {
    const e = state.edges.get(id);
    if (e?.label && e.label.toLowerCase().includes(q)) return true;
  }
  return false;
}

/// Whether a drawn item matches the search. A closed group matches by its
/// name, or when anything inside it matches.
function matches(n) {
  const q = state.search;
  if (!q) return false;
  if (!isGroup(n)) return leafMatches(n);
  if (n.name.toLowerCase().includes(q)) return true;
  for (const [id, did] of view.owner) {
    if (did === n.id && leafMatches(state.nodes.get(id))) return true;
  }
  return false;
}

function applySearch() {
  const q = state.search;
  for (const n of view.items.values()) {
    if (!n.g) continue;
    const m = q && matches(n);
    n.g.classList.toggle('match', !!m);
    n.g.classList.toggle('dim', !!q && !m);
  }
  for (const d of view.dedges.values()) {
    if (!d.g) continue;
    const a = view.items.get(d.a);
    const b = view.items.get(d.b);
    const m = q && ((d.label || '').toLowerCase().includes(q) || (a && matches(a)) || (b && matches(b)));
    d.g.classList.toggle('dim', !!q && !m);
  }
  state.sideDirty = true;
}

function renderStats(total) {
  const all = [...state.nodes.values()];
  $('stat-sandboxes').textContent = all.filter((n) => n.kind === 'sandbox').length;
  $('stat-tasks').textContent = all.filter((n) => n.kind !== 'sandbox').length;
  $('stat-links').textContent = state.edges.size;
  $('stat-rate').textContent = fmtRate(total);
  const empty = !state.nodes.size;
  $('empty').hidden = !empty;
  if (empty && state.connected) {
    $('empty-title').textContent = state.ended ? 'The world has stopped' : 'Waiting for the world';
  }
  if (state.search) applySearch();
}

/// The groups around the selection, as a path the viewer can climb.
function renderCrumbs() {
  const nav = $('crumbs');
  const sel = state.selected;
  let gid = null;
  if (sel?.kind === 'group') gid = sel.id;
  else if (sel?.kind === 'node') gid = state.nodes.get(sel.id)?.group || null;
  const chain = groupChain(gid);
  if (!chain.length) {
    nav.hidden = true;
    return;
  }
  const parts = [];
  const world = el('button', { type: 'button', text: 'World' });
  world.addEventListener('click', () => select(null));
  parts.push(world);
  chain.forEach((g, i) => {
    parts.push(el('span', { class: 'sep', 'aria-hidden': 'true', text: '›' }));
    const last = i === chain.length - 1 && sel.kind === 'group';
    const b = el('button', { type: 'button', text: g.name, class: last ? 'here' : '' });
    if (last) b.setAttribute('aria-current', 'true');
    b.addEventListener('click', () => focusGroup(g.id));
    parts.push(b);
  });
  if (sel.kind === 'node') {
    const n = state.nodes.get(sel.id);
    parts.push(el('span', { class: 'sep', 'aria-hidden': 'true', text: '›' }));
    parts.push(el('span', { class: 'leaf', text: n.name }));
  }
  nav.replaceChildren(...parts);
  nav.hidden = false;
}

function section(title, count) {
  const s = el('section');
  const h = el('h2', { text: title }, s);
  if (count !== undefined) el('small', { text: count }, h);
  return s;
}

function kv(parent, rows) {
  const dl = el('dl', { class: 'kv' }, parent);
  for (const [k, v, mono] of rows) {
    el('dt', { text: k }, dl);
    el('dd', { text: v, class: mono ? 'mono' : '' }, dl);
  }
  return dl;
}

function linkButton(text, onClick) {
  const b = el('button', { class: 'link what', type: 'button', text });
  b.addEventListener('click', onClick);
  return b;
}

function eventsList(parent, events) {
  if (!events.length) {
    el('p', { class: 'quiet', text: 'Nothing recorded yet. Services record what they see, bottlenecks and LANs the packets they drop, routers the routes they lose, TLS its session keys, and world code its own events.' }, parent);
    return;
  }
  const ul = el('ul', { class: 'rows' }, parent);
  for (const n of events.slice(-60).reverse()) {
    const li = el('li', { class: 'event-row' }, ul);
    el('time', { text: `${n.at.toFixed(1)}s` }, li);
    const node = state.nodes.get(n.node) || drawnSource(n);
    const head = el('span', {}, li);
    el('span', { class: `kind ${tone(n)}`, text: `${n.source}.${n.kind}` }, head);
    if (n.task || node) {
      head.append(' from ');
      const b = el('button', { class: 'link', type: 'button', text: n.task || node.name }, head);
      b.title = n.file ? `${n.file}:${n.line}` : '';
      b.addEventListener('click', () => {
        if (state.nodes.get(n.node)) focusNode(n.node);
        else select({ kind: 'ended', id: n.node, event: n });
      });
    }
    el('span', { class: 'text', text: n.summary || eventText(n.fields) }, li);
  }
}

/// An event's fields as `key value` pairs, or as JSON when they are not
/// an object.
function eventText(data) {
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    return Object.entries(data)
      .map(([k, v]) => `${k} ${typeof v === 'object' ? JSON.stringify(v) : v}`)
      .join(', ');
  }
  return JSON.stringify(data);
}

/// Brings drawn item `n` into the middle of the view.
function centerOn(n) {
  const r = stage.getBoundingClientRect();
  state.view.x = r.width / 2 - (n.tx + n.w / 2) * state.view.k;
  state.view.y = r.height / 2 - (n.ty + n.h / 2) * state.view.k;
  state.userMoved = true;
  applyView();
}

/// Selects a task or sandbox and brings it into view, or the closed group
/// it is drawn in.
function focusNode(id) {
  const n = state.nodes.get(id);
  if (!n) return;
  select({ kind: 'node', id });
  const shown = view.items.get(view.owner.get(id));
  if (shown) centerOn(shown);
}

/// Selects a group and brings it into view.
function focusGroup(gid) {
  select({ kind: 'group', id: gid });
  const item = view.items.get(gid);
  if (item) return centerOn(item);
  const f = view.frames.get(gid);
  if (f?.box) centerOn({ tx: f.box.x, ty: f.box.y, w: f.box.w, h: f.box.h });
}

/// What group `gid` holds directly: groups, then tasks and sandboxes by
/// where they were started.
function groupMembers(gid) {
  const groups = [...state.groups.values()].filter((g) => parentOf(g.id) === gid && view.info.get(g.id)?.tasks + view.info.get(g.id)?.sandboxes > 0);
  const leaves = [...state.nodes.values()].filter((n) => (n.group && state.groups.has(n.group) ? n.group : null) === gid);
  return { groups, leaves };
}

function membersList(parent, gid) {
  const { groups, leaves } = groupMembers(gid);
  const ul = el('ul', { class: 'rows' }, parent);
  for (const g of groups.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const li = el('li', {}, ul);
    li.append(linkButton(g.name, () => focusGroup(g.id)));
    el('span', { class: 'where', text: isOpen(g.id) ? 'open' : 'group' }, li);
    el('span', { class: 'count', text: `${fmtRate(groupRate(g.id))}/s` }, li);
  }
  const bySite = new Map();
  for (const n of leaves) {
    const key = n.kind === 'sandbox' ? `s|${n.id}` : `${n.name}|${n.file}:${n.line}`;
    const e = bySite.get(key) || { n, count: 0 };
    e.count++;
    bySite.set(key, e);
  }
  for (const { n, count } of [...bySite.values()].sort((x, y) => (x.n.name < y.n.name ? -1 : 1))) {
    const li = el('li', {}, ul);
    li.append(linkButton(n.name, () => focusNode(n.id)));
    el('span', { class: 'where', text: n.kind === 'sandbox' ? 'sandbox' : where(n) }, li);
    el('span', { class: 'count', text: count > 1 ? `×${count}` : '' }, li);
  }
  if (!ul.children.length) el('li', { class: 'quiet', text: 'Nothing running.' }, ul);
}

function renderSide() {
  const side = $('side');
  const out = [];
  const sel = state.selected;
  const now = runTime();
  if (sel && sel.kind === 'node' && state.nodes.get(sel.id)) {
    const n = state.nodes.get(sel.id);
    const s = el('section');
    el('h3', { class: 'selection-title', text: n.name }, s);
    el('p', { class: 'selection-kind', text: n.kind === 'sandbox' ? 'A sandbox attached to the world' : n.kind === 'world' ? 'The world function' : 'A task' }, s);
    const rows = [];
    if (n.file) rows.push(['Spawned at', `${n.file}:${n.line}`, true]);
    if (n.started !== undefined) rows.push(['Running for', fmtDuration(now - n.started)]);
    if (n.drops) rows.push(['Dropped', `${fmtCount(n.drops)} packets`]);
    kv(s, rows);
    if (n.group && state.groups.has(n.group)) {
      const row = el('p', { class: 'lead' }, s);
      row.append('In the group ');
      row.append(linkButton(state.groups.get(n.group).name, () => focusGroup(n.group)));
    }
    if (n.parent && state.nodes.get(n.parent)) {
      const p = state.nodes.get(n.parent);
      const row = el('p', { class: 'lead' }, s);
      row.append('Started by ');
      row.append(linkButton(p.name, () => focusNode(p.id)));
    }
    out.push(s);
    const links = section('Links', n.edges.size);
    const ul = el('ul', { class: 'rows' }, links);
    for (const id of n.edges) {
      const e = state.edges.get(id);
      if (!e) continue;
      const other = state.nodes.get(e.a === n.id ? e.b : e.a);
      const li = el('li', {}, ul);
      li.append(
        linkButton(`${nodeLabel(other)}${e.label ? `  ${e.label}` : ''}`, () => {
          openLinks(nodeLabel(n), nodeLabel(other), [{ e, flip: e.a !== n.id }], e.label);
        }),
      );
      const r = liveRate(e);
      el('span', { class: 'count', text: `${fmtRate(r[0] + r[1])}/s` }, li);
    }
    out.push(links);
    const ev = section('Events');
    eventsList(ev, state.events.filter((x) => x.node === n.id));
    out.push(ev);
  } else if (sel && sel.kind === 'group' && state.groups.has(sel.id)) {
    const g = state.groups.get(sel.id);
    const info = view.info.get(sel.id);
    const s = el('section');
    el('h3', { class: 'selection-title', text: g.name }, s);
    el('p', { class: 'selection-kind', text: `A group, ${isOpen(sel.id) ? 'open' : 'closed'}` }, s);
    const rows = [['Tasks', String(info?.tasks || 0)]];
    if (info?.sandboxes) rows.push(['Sandboxes', String(info.sandboxes)]);
    rows.push(['In and out now', `${fmtRate(groupRate(sel.id))} packets/s`]);
    kv(s, rows);
    const tools = el('div', { class: 'tools' }, s);
    const b = el('button', { class: 'button', type: 'button', text: isOpen(sel.id) ? 'Close the group' : 'Open the group' }, tools);
    b.addEventListener('click', () => toggleGroup(sel.id));
    out.push(s);
    const crossing = crossingEdges(sel.id);
    const links = section('In and out', crossing.length);
    if (!crossing.length) el('p', { class: 'quiet', text: 'No links cross this group’s edge.' }, links);
    const ul = el('ul', { class: 'rows' }, links);
    for (const d of crossing) {
      const [a, b2] = ends(d);
      const li = el('li', {}, ul);
      li.append(
        linkButton(`${nodeLabel(a)} ↔ ${nodeLabel(b2)}${d.members.length > 1 ? ` (${d.members.length} links)` : ''}`, () => {
          select({ kind: 'edge', id: d.id });
          openPackets(d.id);
        }),
      );
      const r = dRate(d);
      el('span', { class: 'count', text: `${fmtRate(r[0] + r[1])}/s` }, li);
    }
    out.push(links);
    const m = section('Inside');
    membersList(m, sel.id);
    out.push(m);
  } else if (sel && sel.kind === 'ended') {
    // A task that has ended, known only from the events it sent.
    const n = sel.event;
    const s = el('section');
    el('h3', { class: 'selection-title', text: n.task || 'A task' }, s);
    el('p', { class: 'selection-kind', text: 'A task that has ended' }, s);
    if (n.file) kv(s, [['Spawned at', `${n.file}:${n.line}`, true]]);
    const parent = n.parent && state.nodes.get(n.parent);
    if (parent) {
      const row = el('p', { class: 'lead' }, s);
      row.append('Started by ');
      row.append(linkButton(parent.name, () => focusNode(parent.id)));
    }
    out.push(s);
    const ev = section('Events');
    eventsList(ev, state.events.filter((x) => x.node === sel.id));
    out.push(ev);
  } else if (sel && sel.kind === 'edge' && view.dedges.get(sel.id)) {
    const d = view.dedges.get(sel.id);
    const [a, b, swapped] = ends(d);
    const raw = dCounts(d);
    const c = swapped ? [raw[2], raw[3], raw[0], raw[1]] : raw;
    const s = el('section');
    el('h3', { class: 'selection-title', text: `${nodeLabel(a)} ↔ ${nodeLabel(b)}` }, s);
    const kind = d.members.length > 1 ? `${d.members.length} links, added up` : d.label ? `A link, routed for ${d.label}` : 'A link between two tasks';
    el('p', { class: 'selection-kind', text: kind }, s);
    const r = dRate(d);
    kv(s, [
      [`${nodeLabel(a)} sent`, `${fmtCount(c[0])} packets, ${fmtBytes(c[1])}`],
      [`${nodeLabel(b)} sent`, `${fmtCount(c[2])} packets, ${fmtBytes(c[3])}`],
      ['Now', `${fmtRate(r[0] + r[1])} packets/s`],
    ]);
    out.push(s);
    if (d.members.length > 1) {
      const ls = section('Links', d.members.length);
      const ul = el('ul', { class: 'rows' }, ls);
      for (const { e } of d.members) {
        const ea = state.nodes.get(e.a);
        const eb = state.nodes.get(e.b);
        const li = el('li', {}, ul);
        li.append(linkButton(`${nodeLabel(ea)} ↔ ${nodeLabel(eb)}${e.label ? `  ${e.label}` : ''}`, () => openLinks(nodeLabel(ea), nodeLabel(eb), [{ e, flip: false }], e.label)));
        const lr = liveRate(e);
        el('span', { class: 'count', text: `${fmtRate(lr[0] + lr[1])}/s` }, li);
      }
      out.push(ls);
    }
  } else {
    const all = [...state.nodes.values()];
    const s = section('This world');
    if (!state.connected) el('p', { class: 'quiet', text: 'Connecting to the world.' }, s);
    else if (!all.length && !state.startedMs) el('p', { class: 'quiet', text: 'No world is running yet.' }, s);
    else {
      let packets = 0;
      let bytes = 0;
      for (const e of state.edges.values()) {
        if (state.nodes.get(e.b)?.kind === 'sandbox') {
          packets += e.c[0] + e.c[2];
          bytes += e.c[1] + e.c[3];
        }
      }
      kv(s, [
        [state.ended ? 'Ran for' : 'Running for', fmtDuration(now)],
        ['Started', state.startedMs ? new Date(state.startedMs).toLocaleTimeString() : ''],
        ['Sandbox traffic', `${fmtCount(packets)} packets, ${fmtBytes(bytes)}`],
      ]);
    }
    out.push(s);
    const boxes = all.filter((n) => n.kind === 'sandbox');
    const sb = section('Sandboxes', boxes.length);
    if (!boxes.length) el('p', { class: 'quiet', text: 'None attached. Each fictionet attach adds one.' }, sb);
    else {
      const ul = el('ul', { class: 'rows' }, sb);
      for (const n of boxes.sort((x, y) => (x.name < y.name ? -1 : 1))) {
        const li = el('li', {}, ul);
        li.append(linkButton(n.name, () => focusNode(n.id)));
        let r = 0;
        for (const id of n.edges) {
          const e = state.edges.get(id);
          if (e) r += liveRate(e)[0] + liveRate(e)[1];
        }
        el('span', { class: 'count', text: `${fmtRate(r)}/s` }, li);
      }
    }
    out.push(sb);
    // Groups, as a tree.
    const tops = [...state.groups.values()].filter((g) => !parentOf(g.id));
    if (tops.length) {
      const gs = section('Groups', state.groups.size);
      const ul = el('ul', { class: 'rows tree' }, gs);
      const walk = (g, depth) => {
        const li = el('li', {}, ul);
        li.style.paddingLeft = `${depth * 14}px`;
        li.append(linkButton(g.name, () => focusGroup(g.id)));
        el('span', { class: 'where', text: plural(view.info.get(g.id)?.tasks || 0, 'task') }, li);
        el('span', { class: 'count', text: `${fmtRate(groupRate(g.id))}/s` }, li);
        for (const c of [...state.groups.values()].filter((x) => parentOf(x.id) === g.id).sort((a, b) => (a.name < b.name ? -1 : 1))) walk(c, depth + 1);
      };
      for (const g of tops.sort((a, b) => (a.name < b.name ? -1 : 1))) walk(g, 0);
      out.push(gs);
    }
    // Tasks, grouped by where they were spawned. Tasks with no links,
    // such as one per connection, are only listed here.
    const sites = new Map();
    for (const n of all) {
      if (n.kind === 'sandbox') continue;
      const key = `${n.name}|${n.file}:${n.line}`;
      const g = sites.get(key) || { n, count: 0, linked: 0 };
      g.count++;
      if (n.edges.size) g.linked++;
      sites.set(key, g);
    }
    const ts = section('Tasks', all.length - boxes.length);
    const ul = el('ul', { class: 'rows' }, ts);
    const q = state.search;
    for (const g of [...sites.values()].sort((x, y) => y.count - x.count || (x.n.name < y.n.name ? -1 : 1))) {
      if (q && !`${g.n.name} ${g.n.file}:${g.n.line}`.toLowerCase().includes(q)) continue;
      const li = el('li', {}, ul);
      const target = all.find((m) => m.name === g.n.name && m.file === g.n.file && m.line === g.n.line && m.edges.size) || g.n;
      li.append(linkButton(g.n.name, () => focusNode(target.id)));
      el('span', { class: 'where', text: where(g.n) }, li);
      el('span', { class: 'count', text: g.count > 1 ? `×${g.count}` : '' }, li);
    }
    out.push(ts);
    const ev = section('Events', state.events.length || undefined);
    eventsList(ev, state.events);
    out.push(ev);
  }
  side.replaceChildren(...out);
}

// ---------------------------------------------------------------------------
// The packet drawer

const drawer = $('drawer');
const prows = $('prows');
const plist = $('plist');
// What the drawer watches: { links: [{ id, flip }], source, paused, held,
// queue, skipped, rows }. A packet's side is turned to the drawn edge's:
// 0 from its first end, 1 from its second.
let packets = null;
/// Rows the packet list keeps.
const MAX_ROWS = 3000;
/// How long a merged packet view holds packets to put them in order.
const MERGE_HOLD_MS = 400;

/// Opens the packets of drawn edge `id`: one link, or every link it stands
/// for, merged.
function openPackets(id) {
  const d = view.dedges.get(id);
  if (!d) return;
  const [first, second, swapped] = ends(d);
  // The drawer's first direction goes from the sandbox side.
  let members = d.members.map(({ e, flip }) => ({ e, flip: swapped ? !flip : flip }));
  // `fictionet dashboard` merges at most MAX_MERGED links: the busiest.
  const total = members.length;
  if (total > MAX_MERGED) {
    const busy = (m) => m.e.c[0] + m.e.c[2];
    members = members.sort((x, y) => busy(y) - busy(x)).slice(0, MAX_MERGED);
  }
  openLinks(nodeLabel(first), nodeLabel(second), members, d.label, total);
}

/// Links one merged packet view may watch, as `fictionet dashboard` allows.
const MAX_MERGED = 32;

/// Opens the packets of `members` ({ e, flip }): side 0 of the drawer goes
/// from `fromName` to `toName`.
function openLinks(fromName, toName, members, label, total = members.length) {
  closePackets();
  drawer.hidden = false;
  const many = members.length > 1;
  const count = total > members.length ? `  (the busiest ${members.length} of ${total} links)` : many ? `  (${members.length} links)` : '';
  $('drawer-title').textContent = `${fromName} ↔ ${toName}${label ? `  ${label}` : ''}${count}`;
  $('dir-a').textContent = `${fromName} → ${toName}`;
  $('dir-b').textContent = `${toName} → ${fromName}`;
  const list = members.map((m) => m.e.id).join(',');
  $('pcap').href = `api/pcap?link=${list}`;
  $('pcap').setAttribute('download', many ? 'fictionet-links.pcapng' : `fictionet-${list}.pcapng`);
  $('pause').textContent = 'Pause';
  $('sampled').hidden = true;
  prows.replaceChildren();
  $('tree').replaceChildren(el('p', { class: 'placeholder', text: many ? 'Packets from all of these links appear here, merged, as they cross. Select one to see its layers.' : 'Packets appear here as they cross the link. Select one to see its layers.' }));
  $('hex').hidden = true;
  const flips = new Map(members.map((m) => [m.e.id, m.flip]));
  const source = new EventSource(`api/packets?link=${list}`);
  packets = { flips, many, source, rows: 0, paused: false, held: [], queue: [], skipped: 0, open: members.length };
  source.addEventListener('packet', (ev) => {
    const p = JSON.parse(ev.data);
    if (!packets || packets.source !== source) return;
    p.link = p.link || list;
    p.came = performance.now();
    if (flips.get(p.link)) p.side = 1 - p.side;
    // Only the last rows are ever shown, so only those are kept while the
    // view is paused or the tab is hidden.
    const q = packets.paused ? packets.held : packets.queue;
    q.push(p);
    if (q.length > MAX_ROWS * 2) q.splice(0, q.length - MAX_ROWS);
  });
  source.addEventListener('link_end', () => {
    if (packets?.source === source) packets.open--;
  });
  source.addEventListener('end', () => {
    source.close();
    addGap(many ? 'Every one of these links has closed.' : 'The link closed: both of its ends are gone.');
  });
  if (!state.userMoved) fit();
}

function closePackets() {
  if (packets) packets.source.close();
  packets = null;
  drawer.hidden = true;
}

$('close-drawer').addEventListener('click', () => {
  closePackets();
  if (!state.userMoved) fit();
});
$('pause').addEventListener('click', () => {
  if (!packets) return;
  packets.paused = !packets.paused;
  $('pause').textContent = packets.paused ? `Resume` : 'Pause';
  if (!packets.paused) {
    packets.queue = packets.queue.concat(packets.held).slice(-MAX_ROWS);
    packets.held = [];
  }
});
$('pfilter').addEventListener('input', () => {
  for (const tr of prows.children) filterRow(tr);
});

function filterRow(tr) {
  const q = $('pfilter').value.trim().toLowerCase();
  tr.hidden = !!q && (tr.classList.contains('gap') || !(tr.dataset.text || '').includes(q));
}

function addGap(text, parent = prows) {
  const tr = el('tr', { class: 'gap' }, parent);
  el('td', { colspan: 8, text }, tr);
}

/// Adds the packets that came since the last frame, in one change to the
/// table, and keeps the newest in view unless the viewer scrolled up.
function flushPackets() {
  if (!packets || !packets.queue.length) return;
  const nearBottom = plist.scrollHeight - plist.scrollTop - plist.clientHeight < 40;
  let batch = packets.queue;
  packets.queue = [];
  if (packets.many) {
    // Merged links send their packets in turns, a little apart: hold each
    // packet for a moment, and add them in time order.
    const now = performance.now();
    batch.sort((a, b) => a.t - b.t);
    const ready = batch.findIndex((p) => now - p.came < MERGE_HOLD_MS);
    if (ready !== -1) {
      // Everything later than the first packet still held waits with it.
      packets.queue = batch.slice(ready);
      batch = batch.slice(0, ready);
    }
    if (!batch.length) return;
  }
  const frag = document.createDocumentFragment();
  // A flood only ever shows its last rows.
  for (const p of batch.slice(-MAX_ROWS)) addPacket(p, frag);
  prows.appendChild(frag);
  let extra = prows.children.length - MAX_ROWS;
  while (extra-- > 0) prows.firstChild.remove();
  if (nearBottom) plist.scrollTop = plist.scrollHeight;
}

function addPacket(p, parent) {
  if (p.skipped > 0) {
    packets.skipped += p.skipped;
    $('sampled').hidden = false;
    $('sampled').textContent = `Sampled: ${fmtCount(packets.skipped)} packets not copied`;
    $('sampled').title = 'The link is busy, so the dashboard copies some of its packets, not all. The rows with a dashed line above them follow packets that were not copied.';
  }
  packets.rows++;
  // One link numbers its own packets; merged links are numbered here.
  const no = packets.many ? packets.rows : p.seq;
  const tr = el('tr', { class: `${p.side === 1 ? 'back' : ''} ${p.skipped > 0 ? 'after-gap' : ''} ${p.tags.join(' ')}`, 'data-seq': p.seq, 'data-link': p.link }, parent);
  const cells = [no, p.t.toFixed(4), '', p.src, p.dst, p.proto, p.len, p.info];
  cells.forEach((c, i) => {
    const td = el('td', { text: String(c) }, tr);
    if (i === 2) {
      td.className = 'dir';
      el('i', {}, td);
    }
    if (i === 5) td.className = 'proto';
  });
  tr.title = p.skipped > 0 ? `${p.info}\n(${p.skipped} packet${p.skipped === 1 ? '' : 's'} before this one not copied)` : p.info;
  tr.dataset.text = `${p.src} ${p.dst} ${p.proto} ${p.info}`.toLowerCase();
  filterRow(tr);
  tr.addEventListener('click', () => showPacket(p, tr));
}

async function showPacket(p, tr) {
  if (!packets) return;
  for (const r of prows.querySelectorAll('tr.on')) r.classList.remove('on');
  tr.classList.add('on');
  const res = await fetch(`api/packet?link=${p.link}&seq=${p.seq}`);
  if (!res.ok) {
    $('tree').replaceChildren(el('p', { class: 'placeholder', text: 'This packet is no longer kept. The dashboard keeps the last 4,096 packets of a link.' }));
    return;
  }
  const d = await res.json();
  d.side = p.side;
  renderDetail(d);
}

let hexState = null;

function renderDetail(d) {
  const tree = $('tree');
  tree.replaceChildren();
  const head = el('details', { open: '' }, tree);
  const sum = el('summary', {}, head);
  el('b', { text: `Packet ${d.seq}` }, sum);
  el('span', { text: `, ${d.len} bytes at ${d.t.toFixed(6)}s, ${d.side === 0 ? $('dir-a').textContent : $('dir-b').textContent}` }, sum);
  // The layers below the application start closed, as in Wireshark, unless
  // they are all there is.
  const low = /^(Internet Protocol|Transmission Control|User Datagram)/;
  const onlyLow = d.layers.every((l) => low.test(l.name));
  for (const layer of d.layers) {
    const det = el('details', onlyLow || !low.test(layer.name) ? { open: '' } : {}, tree);
    const s = el('summary', {}, det);
    el('b', { text: layer.name }, s);
    if (layer.summary) el('span', { text: `, ${layer.summary}` }, s);
    s.addEventListener('pointerenter', () => mark(layer.buf, layer.range));
    for (const f of layer.fields) {
      const row = el('div', { class: 'field' }, det);
      el('span', { class: 'k', text: f.name }, row);
      el('span', { class: 'v', text: f.value }, row);
      if (f.range) {
        row.addEventListener('pointerenter', () => mark(layer.buf, f.range));
        row.addEventListener('click', () => {
          for (const r of tree.querySelectorAll('.field.on')) r.classList.remove('on');
          row.classList.add('on');
          hexState.pinned = [layer.buf, f.range];
          mark(layer.buf, f.range);
        });
      }
    }
  }
  tree.addEventListener('pointerleave', () => {
    if (hexState) mark(...(hexState.pinned || [hexState.buf, null]));
  });
  hexState = { buffers: d.buffers.map((b) => hexBytes(b.hex)), names: d.buffers.map((b) => b.name), buf: 0, range: null, pinned: null };
  const tabs = $('hex-tabs');
  tabs.replaceChildren();
  if (hexState.buffers.length > 1) {
    hexState.names.forEach((name, i) => {
      const b = el('button', { type: 'button', text: `${name} (${hexState.buffers[i].length})` }, tabs);
      b.addEventListener('click', () => mark(i, null));
    });
  }
  $('hex').hidden = false;
  // Open the bytes of the highest layer, such as decrypted HTTP/2.
  const top = d.layers[d.layers.length - 1];
  hexState.pinned = top ? [top.buf, top.range] : null;
  mark(top ? top.buf : 0, top ? top.range : null);
}

function hexBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function mark(buf, range) {
  if (!hexState) return;
  hexState.buf = buf;
  hexState.range = range;
  [...$('hex-tabs').children].forEach((b, i) => b.classList.toggle('on', i === buf));
  const bytes = hexState.buffers[buf] || new Uint8Array();
  const [ra, rb] = range || [-1, -1];
  const pre = $('hex-dump');
  pre.replaceChildren();
  const limit = Math.min(bytes.length, 8192);
  let firstMarked = null;
  for (let off = 0; off < limit; off += 16) {
    const line = document.createDocumentFragment();
    line.append(el('span', { class: 'off', text: off.toString(16).padStart(4, '0') + '  ' }));
    let hexPart = '';
    let asciiPart = '';
    const flush = (marked) => {
      if (!hexPart && !asciiPart) return;
      if (marked) {
        const m = el('mark', { text: hexPart });
        line.append(m);
        if (!firstMarked) firstMarked = m;
      } else line.append(hexPart);
      hexPart = '';
    };
    let inMark = false;
    for (let i = off; i < off + 16; i++) {
      const isMarked = i >= ra && i < rb;
      if (isMarked !== inMark) {
        flush(inMark);
        inMark = isMarked;
      }
      hexPart += i < limit ? bytes[i].toString(16).padStart(2, '0') : '  ';
      hexPart += i === off + 7 ? '  ' : ' ';
    }
    flush(inMark);
    inMark = false;
    line.append(' ');
    let ascii = '';
    for (let i = off; i < Math.min(off + 16, limit); i++) {
      const isMarked = i >= ra && i < rb;
      if (isMarked !== inMark) {
        if (inMark) line.append(el('mark', { text: ascii }));
        else line.append(ascii);
        ascii = '';
        inMark = isMarked;
      }
      const c = bytes[i];
      ascii += c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
    }
    if (inMark) line.append(el('mark', { text: ascii }));
    else line.append(ascii);
    void asciiPart;
    line.append('\n');
    pre.append(line);
  }
  if (bytes.length > limit) pre.append(el('span', { class: 'off', text: `… ${bytes.length - limit} more bytes` }));
  if (firstMarked) firstMarked.scrollIntoView({ block: 'nearest' });
}

// Resizing the drawer by its top edge.
$('grip').addEventListener('pointerdown', (ev) => {
  const startY = ev.clientY;
  const startH = drawer.getBoundingClientRect().height;
  const grip = ev.target;
  grip.setPointerCapture(ev.pointerId);
  const move = (m) => {
    const h = Math.max(160, Math.min(innerHeight - 160, startH - (m.clientY - startY)));
    drawer.style.setProperty('--drawer', `${h}px`);
  };
  const up = () => {
    grip.removeEventListener('pointermove', move);
    grip.removeEventListener('pointerup', up);
  };
  grip.addEventListener('pointermove', move);
  grip.addEventListener('pointerup', up);
});

// ---------------------------------------------------------------------------
// Theme: the system's, until the viewer picks one.

function storedTheme() {
  try {
    return localStorage.getItem('fictionet-theme');
  } catch {
    return null;
  }
}
function applyTheme(t) {
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
applyTheme(new URLSearchParams(location.search).get('theme') || storedTheme());
$('theme').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  const next = dark ? 'light' : 'dark';
  applyTheme(next);
  try {
    localStorage.setItem('fictionet-theme', next);
  } catch {
    // Private windows may refuse storage; the choice lasts for this page.
  }
});

document.addEventListener('keydown', (ev) => {
  if (ev.key === '/' && document.activeElement !== $('search') && document.activeElement !== $('pfilter')) {
    ev.preventDefault();
    $('search').focus();
  }
  if (ev.key === 'Escape' && document.activeElement === document.body) select(null);
});

connect();
renderSide();
requestAnimationFrame(frame);
