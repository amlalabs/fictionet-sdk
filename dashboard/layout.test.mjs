// Tests for layout.mjs: `node --test dashboard/layout.test.mjs`. The Rust
// test `dashboard_js` runs them when node is installed. Text is measured
// as 7 px a character, so every place below can be worked out by hand.
'use strict';

import test from 'node:test';
import assert from 'node:assert/strict';
import { FictionetGroups } from './groups.mjs';
import { createLayout, HEAD } from './layout.mjs';

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const where = (n) => (n.file ? `${n.file}:${n.line}` : '');
const isGroup = (n) => n && n.kind === 'group';
const dEdgesOf = (n) => (isGroup(n) ? n.edges : n.edges2 || new Set());

const sandbox = (id, name) => ({ id, kind: 'sandbox', name, x: NaN, y: NaN, edges2: new Set() });
const task = (id, name, line) => ({ id, kind: 'task', name, file: 'main.rs', line, x: NaN, y: NaN, edges2: new Set() });

/// A layout over drawn `items`, `edges` between them and open `groups`,
/// as `derive` in app.mjs leaves the view. `contOf` gives the open group
/// each item sits in.
function world({ items, edges = [], groups = [], contOf = {}, pins = {} }) {
  const state = {
    groups: new Map(groups.map((g) => [g.id, { parent: null, ...g }])),
    pins: new Map(Object.entries(pins)),
    userMoved: false,
    layoutDirty: true,
  };
  const view = {
    items: new Map(items.map((n) => [n.id, n])),
    dedges: new Map(),
    frames: new Map(),
    contOf: new Map(),
    info: new Map(),
  };
  for (const n of items) view.contOf.set(n.id, contOf[n.id] ?? null);
  for (const g of state.groups.values()) {
    const depth = FictionetGroups.chain(state.groups, g.id).length - 1;
    view.frames.set(g.id, { gid: g.id, g: null, box: null, depth });
    view.contOf.set(`f:${g.id}`, g.parent);
    view.info.set(g.id, { sandboxes: 0 });
  }
  for (const [id, a, b] of edges) {
    view.dedges.set(id, { id, a, b });
    for (const end of [a, b]) dEdgesOf(view.items.get(end)).add(id);
  }
  const calls = [];
  const layout = createLayout({
    state,
    view,
    textWidth: (text) => text.length * 7,
    parentOf: (gid) => FictionetGroups.parentOf(state.groups, gid),
    isGroup,
    plural,
    where,
    dEdgesOf,
    derive: () => calls.push('derive'),
    fit: (...args) => calls.push(['fit', ...args]),
  });
  return { ...layout, state, view, calls };
}

const place = (n) => ({ w: n.w, h: n.h, tx: n.tx, ty: n.ty, x: n.x, y: n.y });

test('columns by hops from the sandbox, centered in the tallest column', () => {
  const s = sandbox('s1', 'agent');
  const a = task('t2', 'router', 10);
  const b = task('t3', 'web', 20);
  const w = world({ items: [s, a, b], edges: [['d1', 's1', 't2'], ['d2', 't2', 't3']] });
  w.layout();
  assert.deepEqual(w.calls, ['derive', ['fit', false]]);
  assert.equal(w.state.layoutDirty, false);
  // The sandbox: 'sandbox' is its longest text, 49 px, plus 40.
  assert.deepEqual(place(s), { w: 89, h: 46, tx: 0, ty: 0, x: 0, y: 0 });
  // Columns 92 px apart. A new item grows out of its first placed neighbor.
  assert.deepEqual(place(a), { w: 96, h: 42, tx: 181, ty: 2, x: 0, y: 0 });
  assert.deepEqual(place(b), { w: 96, h: 42, tx: 369, ty: 2, x: 0, y: 0 });
  assert.equal(s.pinned, false);
});

test('a closed group is sized by its name and what it holds', () => {
  const g = { id: 'g2', kind: 'group', name: 'lan', sandboxes: 1, tasks: 3, x: NaN, y: NaN, edges: new Set() };
  const w = world({ items: [g] });
  w.layout();
  assert.equal(g.sub, '1 sandbox, 3 tasks');
  assert.deepEqual(place(g), { w: 180, h: 48, tx: 0, ty: 0, x: 0, y: 0 });
});

test('an open group is laid out in its frame, and its frame moves clear of a dragged node', () => {
  const s = sandbox('s1', 'agent');
  s.key = 's|agent';
  const a = task('t2', 'router', 10);
  const b = task('t3', 'web', 20);
  const fixture = () => ({
    items: [s, a, b],
    edges: [['d1', 's1', 't2'], ['d2', 't2', 't3']],
    groups: [{ id: 'g1', name: 'office' }],
    contOf: { t2: 'g1', t3: 'g1' },
  });
  const w = world(fixture());
  w.layout();
  // Inside the frame, the task the outside link reaches comes first, 64 px
  // apart; the frame is 30 px of header and 16 px of padding around them.
  assert.deepEqual([s.tx, s.ty, a.tx, a.ty, b.tx, b.ty], [0, 21, 197, 30, 357, 30]);
  assert.deepEqual(w.itemsInFrame('g1'), [a, b]);
  const [frame] = w.frameRects(true);
  assert.deepEqual(frame.box, { x: 181, y: 0, w: 288, h: 42 + HEAD + 16 });

  for (const n of [s, a, b]) Object.assign(n, { x: NaN, y: NaN });
  const pinned = world({ ...fixture(), pins: { 's|agent': { x: 181, y: 0 } } });
  pinned.layout();
  assert.equal(s.pinned, true);
  assert.deepEqual([s.tx, s.ty], [181, 0]);
  // The frame moves down to 18 px below the dragged sandbox.
  assert.deepEqual([a.tx, a.ty, b.tx, b.ty], [197, 94, 357, 94]);
  assert.deepEqual(pinned.frameRects(true)[0].box, { x: 181, y: 64, w: 288, h: 88 });
});

test('edge paths run from the left item to the right one, or loop when they overlap', () => {
  const p = { id: 'p', x: 0, y: 0, w: 89, h: 46 };
  const q = { id: 'q', x: 181, y: 2, w: 96, h: 42 };
  const w = world({ items: [p, q] });
  assert.deepEqual(w.edgePath({ a: 'p', b: 'q' }), { d: 'M89,23 C135,23 135,23 181,23', forward: true });
  assert.deepEqual(w.edgePath({ a: 'q', b: 'p' }), { d: 'M89,23 C135,23 135,23 181,23', forward: false });
  Object.assign(q, { x: 50, y: 100, w: 100, h: 40 });
  Object.assign(p, { w: 100, h: 40 });
  assert.deepEqual(w.edgePath({ a: 'p', b: 'q' }), { d: 'M100,20 C205,20 205,120 150,120', forward: true });
  assert.equal(w.edgePath({ a: 'p', b: 'gone' }), null);
});
