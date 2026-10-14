// Tests for transport.mjs: `node --test dashboard/transport.test.mjs`. The Rust
// test `dashboard_js` runs them when node is installed.
'use strict';

import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransport } from './transport.mjs';

function transport() {
  const sources = [];
  const requests = [];
  const calls = [];
  const state = { connected: false, ended: false, sideDirty: false };
  class EventSource {
    constructor(url) {
      this.url = url;
      this.listeners = new Map();
      this.closed = false;
      sources.push(this);
    }
    addEventListener(name, listener) {
      this.listeners.set(name, listener);
    }
    emit(name, data) {
      this.listeners.get(name)({ data: JSON.stringify(data) });
    }
    close() {
      this.closed = true;
    }
  }
  const reducers = { state };
  for (const name of ['setStatus', 'tick', 'snapshot', 'upsertGroup', 'removeGroup', 'upsertNode', 'removeNode', 'upsertEdge', 'removeEdge', 'counters', 'addEvent']) {
    reducers[name] = (...args) => calls.push([name, ...args]);
  }
  const response = { ok: true };
  const api = createTransport(reducers, {
    EventSource,
    fetch: async (url) => {
      requests.push(url);
      return response;
    },
  });
  return { ...api, state, sources, requests, calls, response };
}

test('connect routes named watch events to reducers with parsed data', () => {
  const t = transport();
  t.connect();
  assert.equal(t.sources.length, 1);
  const source = t.sources[0];
  assert.equal(source.url, 'api/watch');
  source.emit('waiting');
  assert.equal(t.state.connected, true);
  assert.deepEqual(t.calls, [['setStatus', 'waiting', 'Waiting for a world']]);
  const events = [
    ['snapshot', { t: 1, nodes: [], edges: [] }, 'snapshot'],
    ['group', { id: 'g1', name: 'office' }, 'upsertGroup'],
    ['group_end', { id: 'g1' }, 'removeGroup'],
    ['node', { id: 'a', name: 'router' }, 'upsertNode'],
    ['node_end', { id: 'a' }, 'removeNode'],
    ['edge', { id: 'e1', a: 'a', b: 'b' }, 'upsertEdge'],
    ['edge_end', { id: 'e1' }, 'removeEdge'],
    ['counters', { t: 2, edges: { e1: [1, 100, 2, 200] } }, 'counters'],
    ['event', { kind: 'drop', node: 'a', fields: { count: 2 } }, 'addEvent'],
  ];
  for (const [name, data] of events) source.emit(name, data);
  assert.deepEqual(t.calls.slice(1), events.map(([name, data, reducer]) => [reducer, name.endsWith('_end') ? data.id : data]));
  source.emit('ended', { t: 3 });
  assert.deepEqual(t.calls.slice(-2), [['tick', 3], ['setStatus', 'ended', 'World stopped']]);
  assert.equal(t.state.ended, true);
  assert.equal(t.state.sideDirty, true);
  const count = t.calls.length;
  source.emit('end');
  assert.equal(source.closed, true);
  assert.equal(t.calls.length, count);
});

test('end closes the watch and marks a world ended', () => {
  const t = transport();
  t.connect();
  t.sources[0].emit('end');
  assert.equal(t.sources[0].closed, true);
  assert.equal(t.state.ended, true);
  assert.deepEqual(t.calls, [['setStatus', 'ended', 'The world closed']]);
});

test('packetStream opens the requested links', () => {
  const t = transport();
  const source = t.packetStream('e1,e2');
  assert.equal(t.sources.length, 1);
  assert.equal(source, t.sources[0]);
  assert.equal(source.url, 'api/packets?link=e1,e2');
});

test('packet fetches the requested link and sequence', async () => {
  const t = transport();
  assert.equal(await t.packet({ link: 'e1', seq: 42 }), t.response);
  assert.deepEqual(t.requests, ['api/packet?link=e1&seq=42']);
});
