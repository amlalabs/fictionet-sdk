// The Fictionet dashboard's graph view: what is drawn for the state
// (`derive`), the SVG of each drawn item, edge and open group's frame, the
// rings that mark events, and the packets that move along the edges.
// components/map.mjs passes in the state and view, the layout's edge paths and
// frames, and the selection, drag, tooltip and packet steps the drawing
// hooks up, and calls `draw` once a frame.

import { FictionetGroups } from './groups.mjs';
import { HEAD } from './layout.mjs';

export function createGraph({ $, el, hostOverview = false, state, view, reducedMotion, isGroup, where, fmtCount, edgePath, frameRects, itemsInFrame, hookItem, select, toggleGroup, showTip, moveTip, hideTip, startDrag, currentDrag, clickSuppressed, nodeTip, groupTip, edgeTip, openPackets }) {
  /// The class that colors an event: `bad` for drops, lost routes and
  /// alarms, `good` for kept TLS keys.
  function tone(n) {
    if (n.kind === 'drop' || n.kind === 'route_removed' || n.level === 'alarm') return 'bad';
    if (n.source === 'tls' && n.kind === 'keys') return 'good';
    return '';
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
    if (reducedMotion.matches || $('graph').ownerDocument.hidden) return;
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
    if (hostOverview && [...state.hosts.values()].some((host) => host.group === gid)) return false;
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
  // Drawing

  const gFrames = $('frames');
  const gNodes = $('nodes');
  const gEdges = $('edges');
  const gDots = $('dots');
  const gLabels = $('labels');

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
      if (!clickSuppressed()) toggleGroup(n.gid);
    });
    hookItem(g, n, () => select({ kind: 'group', id: n.gid }), () => groupTip(n.gid));
    g.addEventListener('dblclick', (ev) => {
      ev.stopPropagation();
      toggleGroup(n.gid);
    });
    gNodes.appendChild(g);
    n.g = g;
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
      if (!clickSuppressed()) toggleGroup(f.gid);
    });
    head.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (!clickSuppressed()) select({ kind: 'group', id: f.gid });
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

  function edgeWidth(pps) {
    return Math.min(9, 1.3 + 2.1 * Math.log10(1 + pps));
  }

  // ---------------------------------------------------------------------------
  // The frame loop (components/map.mjs runs it): items glide to their places, edges
  // follow, packets move.

  let dotCount = 0;
  const MAX_DOTS = 450;
  const DOT_SPEED = 240; // px per second

  /// Moves the drawing on by `dt` seconds, and returns the packets a second
  /// to and from the sandboxes.
  function draw(dt) {
    const ease = reducedMotion.matches ? 1 : 1 - Math.exp(-dt * 7);
    const moved = new Set();
    for (const n of view.items.values()) {
      if (!n.g) {
        // A new drawing has no place yet, wherever the item is.
        drawNode(n);
        n.placed = false;
      }
      if (currentDrag()?.items.includes(n)) {
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
    return total;
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

  return { tone, drawnSource, pulse, liveRate, dRate, dCounts, dBytesRate, ends, groupChain, parentOf, isOpen, derive, dEdgesOf, draw };
}
