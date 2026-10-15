// Layout of the Fictionet dashboard's graph: the size and place of each
// drawn item, the frames of open groups, and the path of each drawn edge.
// No drawing: app.mjs passes in the state and view, text measurement, and
// the `derive` and `fit` steps that `layout` runs before and after placing,
// and draws what this works out. layout.test.mjs runs it on its own.

// ---------------------------------------------------------------------------
// Layout: in each container (the world, or an open group), columns by hops
// from the sandboxes, or from the links that leave the container; rows
// ordered so that edges cross as little as they can. An open group is laid
// out first, and takes the space of its frame in the container around it.
// The same graph always gets the same places, so the drawing stays still
// while the world runs. Nodes the viewer dragged stay where they were put.

const PAD = 16; // frame padding
export const HEAD = 30; // frame header
const MONO_FONT = "400 10.5px 'IBM Plex Mono', 'JetBrains Mono', 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace";

export function createLayout({ state, view, textWidth, parentOf, isGroup, plural, where, dEdgesOf, derive, fit }) {
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

  return { layout, itemsInFrame, frameRects, edgePath };
}
