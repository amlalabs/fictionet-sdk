// Tests for state.mjs: `node --test dashboard/state.test.mjs`. The Rust
// test `dashboard_js` runs them when node is installed.
'use strict';

import test from 'node:test';
import assert from 'node:assert/strict';
import { createModel, createState } from './state.mjs';

test('a snapshot replaces the graph and events and applies counters', () => {
  const w = createState();
  w.upsertGroup({ id: 'old-group', name: 'old' });
  w.upsertNode({ id: 'old-a' });
  w.upsertNode({ id: 'old-b' });
  w.upsertEdge({ id: 'old-edge', a: 'old-a', b: 'old-b' });
  w.addEvent({ kind: 'old' });
  w.state.pins.set('old-a', { x: 1, y: 2 });
  w.state.expanded.set('old-group', true);
  assert.equal(w.state.known, false);
  const snapshot = {
    t: 10,
    started: 1000,
    ended: false,
    groups: [{ id: 'g1', name: 'office' }],
    nodes: [{ id: 'a', name: 'router' }, { id: 'b', group: 'g1' }],
    edges: [{ id: 'e1', a: 'a', b: 'b' }],
    counters: { e1: [10, 1000, 20, 2000] },
    events: [{ kind: 'drop', node: 'a', fields: { count: 3 } }],
    status: { incomplete: false, losses: [] },
  };
  w.snapshot(snapshot);
  assert.deepEqual([...w.state.nodes.keys()], ['a', 'b']);
  assert.equal(w.state.nodes.get('a').name, 'router');
  assert.equal(w.state.nodes.get('b').group, 'g1');
  assert.deepEqual([...w.state.edges.keys()], ['e1']);
  assert.deepEqual([...w.state.groups.values()], [{ id: 'g1', name: 'office', parent: null }]);
  for (const node of w.state.nodes.values()) assert.deepEqual(node.edges, new Set(['e1']));
  assert.deepEqual(w.state.edges.get('e1').c, snapshot.counters.e1);
  assert.equal(w.state.edges.get('e1').t, 10);
  assert.deepEqual(w.state.events, snapshot.events);
  assert.equal(w.state.nodes.get('a').drops, 3);
  assert.equal(w.state.serverT, 10);
  assert.equal(w.state.startedMs, 1000);
  assert.equal(w.state.ended, false);
  assert.equal(w.state.connected, true);
  assert.equal(w.state.known, true);
  assert.deepEqual(w.state.status, snapshot.status);
  // A new graph forgets the places and open groups chosen for the last one.
  assert.equal(w.state.pins.size + w.state.expanded.size, 0);
});

test('node and edge updates keep endpoint edge sets and node removal clears selection', () => {
  const w = createState();
  for (const id of ['a', 'b', 'c']) w.upsertNode({ id });
  w.upsertEdge({ id: 'e1', a: 'a', b: 'b' });
  assert.deepEqual(w.state.nodes.get('a').edges, new Set(['e1']));
  assert.deepEqual(w.state.nodes.get('b').edges, new Set(['e1']));
  assert.deepEqual(w.state.nodes.get('c').edges, new Set());
  w.upsertNode({ id: 'a', name: 'router' });
  assert.equal(w.state.nodes.get('a').name, 'router');
  assert.deepEqual(w.state.nodes.get('a').edges, new Set(['e1']));
  w.upsertEdge({ id: 'e1', a: 'b', b: 'c' });
  assert.deepEqual(w.state.nodes.get('a').edges, new Set());
  assert.deepEqual(w.state.nodes.get('b').edges, new Set(['e1']));
  assert.deepEqual(w.state.nodes.get('c').edges, new Set(['e1']));
  w.removeEdge('e1');
  assert.equal(w.state.edges.size, 0);
  for (const node of w.state.nodes.values()) assert.deepEqual(node.edges, new Set());
  w.state.selected = { kind: 'node', id: 'a' };
  w.removeNode('b');
  assert.deepEqual(w.state.selected, { kind: 'node', id: 'a' });
  w.removeNode('a');
  assert.equal(w.state.selected, null);
  assert.deepEqual([...w.state.nodes.keys()], ['c']);
});

test('group removal clears a matching selection', () => {
  const w = createState();
  w.upsertGroup({ id: 'g1', name: 'office' });
  w.state.selected = { kind: 'group', id: 'g1' };
  w.removeGroup('g1');
  assert.equal(w.state.groups.size, 0);
  assert.equal(w.state.selected, null);
});

test('counters compute packet and byte rates from the previous counts', () => {
  const w = createState();
  w.snapshot({
    t: 10, started: 1000, ended: false, nodes: [{ id: 'a' }, { id: 'b' }],
    edges: [{ id: 'e1', a: 'a', b: 'b' }], counters: { e1: [10, 1000, 20, 2000] }, events: [],
  });
  w.counters({ t: 12, edges: { e1: [16, 1600, 30, 4000] } });
  const edge = w.state.edges.get('e1');
  assert.deepEqual(edge.rate, [3, 5]);
  assert.deepEqual(edge.bps, [300, 1000]);
  assert.deepEqual(edge.c, [16, 1600, 30, 4000]);
  assert.equal(edge.t, 12);
  w.counters({ t: 16, edges: { e1: [20, 2400, 38, 5200] } });
  assert.deepEqual(edge.rate, [1, 2]);
  assert.deepEqual(edge.bps, [200, 300]);
  assert.deepEqual(edge.c, [20, 2400, 38, 5200]);
  assert.equal(edge.t, 16);
});

test('events retain the newest 500 and drops count repeats with a default of one', () => {
  const w = createState();
  w.upsertNode({ id: 'a' });
  const events = Array.from({ length: 501 }, (_, t) => ({ kind: 'info', t }));
  for (const event of events) w.addEvent(event);
  assert.deepEqual(w.state.events, events.slice(1));
  assert.equal(w.state.nodes.get('a').drops, 0);
  const drops = [
    { kind: 'drop', node: 'a', fields: { count: 4 } },
    { kind: 'drop', node: 'a', fields: {} },
    { kind: 'drop', node: 'a' },
  ];
  for (const event of drops) w.addEvent(event);
  assert.equal(w.state.nodes.get('a').drops, 6);
  assert.deepEqual(w.state.events, [...events.slice(4), ...drops]);
});

test('the model tells subscribers each watch event once the graph holds it', () => {
  const source = new EventTarget();
  source.close = () => { source.closed = true; };
  const emit = (name, data) => { const event = new Event(name); if (data !== undefined) event.data = JSON.stringify(data); source.dispatchEvent(event); };
  const model = createModel(source);
  const heard = [];
  const stop = model.subscribe((name, data) => heard.push([name, data, model.state.nodes.size, model.state.edges.size]));
  emit('snapshot', { t: 1, started: 0, ended: false, nodes: [{ id: 'a' }], edges: [], counters: {}, events: [], status: { incomplete: true } });
  emit('edge', { id: 'e1', a: 'a', b: 'b' });
  emit('status', { status: { incomplete: false } });
  emit('open');
  assert.deepEqual(heard.map(([name, , nodes, edges]) => [name, nodes, edges]), [['snapshot', 1, 0], ['edge', 1, 1], ['status', 1, 1], ['open', 1, 1]]);
  assert.deepEqual(heard[1][1], { id: 'e1', a: 'a', b: 'b' });
  assert.equal(heard[3][1], null);
  assert.deepEqual(model.state.status, { incomplete: false });
  stop();
  emit('node', { id: 'c' });
  assert.equal(heard.length, 4, 'an unsubscribed listener hears nothing');
  assert.equal(model.state.nodes.size, 2);
  model.dispose();
  assert.equal(source.closed, true);
  emit('node', { id: 'd' });
  assert.equal(model.state.nodes.size, 2, 'a disposed model stops following the watch');
});
