// Tests for state.mjs: `node --test dashboard/state.test.mjs`. The Rust
// test `dashboard_js` runs them when node is installed.
'use strict';

import test from 'node:test';
import assert from 'node:assert/strict';
import { createState } from './state.mjs';

function world() {
  const statuses = [];
  const layouts = [];
  const pulses = [];
  const reducers = createState({
    view: { gviews: new Map() },
    setStatus: (...args) => statuses.push(args),
    loadLayout: (nodes) => layouts.push(nodes),
    pulse: (event) => pulses.push(event),
  });
  return { ...reducers, statuses, layouts, pulses };
}

test('a snapshot replaces the graph and events and applies counters and effects', () => {
  const w = world();
  w.upsertGroup({ id: 'old-group', name: 'old' });
  w.upsertNode({ id: 'old-a' });
  w.upsertNode({ id: 'old-b' });
  w.upsertEdge({ id: 'old-edge', a: 'old-a', b: 'old-b' });
  w.addEvent({ kind: 'old' });
  w.pulses.length = 0;
  const snapshot = {
    t: 10,
    started: 1000,
    ended: false,
    groups: [{ id: 'g1', name: 'office' }],
    nodes: [{ id: 'a', name: 'router' }, { id: 'b', group: 'g1' }],
    edges: [{ id: 'e1', a: 'a', b: 'b' }],
    counters: { e1: [10, 1000, 20, 2000] },
    events: [{ kind: 'drop', node: 'a', fields: { count: 3 } }],
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
  assert.deepEqual(w.statuses, [['running', 'Running']]);
  assert.deepEqual(w.layouts, [snapshot.nodes]);
  assert.deepEqual(w.pulses, snapshot.events);
});

test('node and edge updates keep endpoint edge sets and node removal clears selection', () => {
  const w = world();
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
  const w = world();
  w.upsertGroup({ id: 'g1', name: 'office' });
  w.state.selected = { kind: 'group', id: 'g1' };
  w.removeGroup('g1');
  assert.equal(w.state.groups.size, 0);
  assert.equal(w.state.selected, null);
});

test('counters compute packet and byte rates from the previous counts', () => {
  const w = world();
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
  const w = world();
  w.upsertNode({ id: 'a' });
  const events = Array.from({ length: 501 }, (_, t) => ({ kind: 'info', t }));
  for (const event of events) w.addEvent(event);
  assert.deepEqual(w.state.events, events.slice(1));
  assert.deepEqual(w.pulses, events);
  assert.equal(w.state.nodes.get('a').drops, 0);
  const drops = [
    { kind: 'drop', node: 'a', fields: { count: 4 } },
    { kind: 'drop', node: 'a', fields: {} },
    { kind: 'drop', node: 'a' },
  ];
  for (const event of drops) w.addEvent(event);
  assert.equal(w.state.nodes.get('a').drops, 6);
  assert.deepEqual(w.state.events, [...events.slice(4), ...drops]);
  assert.deepEqual(w.pulses, [...events, ...drops]);
});
