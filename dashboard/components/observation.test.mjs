import test from 'node:test';
import assert from 'node:assert/strict';
import { mount as map } from './map.mjs';
import { mount as packets } from './packets.mjs';
import { mount as events } from './events.mjs';
import { watchState } from '../state.mjs';
import { createSelection } from '../selection.mjs';
import { createDocument, Element } from '../test-dom.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));
function fixture(t) {
  const document = createDocument();
  const root = document.createElement('section');
  document.body.append(root);
  const frames = new Map(), observers = [], watches = [], streams = [], requests = [];
  t.mock.method(globalThis, 'requestAnimationFrame', (callback) => { const id = Symbol(); frames.set(id, callback); return id; });
  t.mock.method(globalThis, 'cancelAnimationFrame', (id) => frames.delete(id));
  const previousResize = globalThis.ResizeObserver;
  t.after(() => { globalThis.ResizeObserver = previousResize; });
  globalThis.ResizeObserver = class {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe() {}
    disconnect() { this.closed = true; }
  };
  class Source extends Element {
    constructor() { super('source'); }
    emit(name, value) { const event = new Event(name); event.data = JSON.stringify(value); this.dispatchEvent(event); }
    close() { this.closed = true; }
  }
  const selection = createSelection();
  const services = {
    selection, reducedMotion: { matches: true }, hosts: [{ name: 'alpha', sandbox: 'guest' }],
    transport: {
      connect(graph) { return watchState(this.watch(), graph); },
      watch() { const source = new Source(); watches.push(source); return source; },
      packetStream(list) { const source = new Source(); source.links = list; streams.push(source); return source; },
      async get(path, params, signal) { requests.push({ path, signal }); return { links: ['e2'] }; },
    },
  };
  return { root, frames, observers, watches, streams, services, selection, requests,
    snapshot: { t: 0, started: 1, ended: false, hosts: [{ id: 'h1', name: 'alpha', sandbox: 'guest', group: null }], groups: [], nodes: [{ id: 's1', kind: 'sandbox', name: 'guest', host: 'h1' }], edges: [], counters: {}, events: [] },
    frame() { const callbacks = [...frames.values()]; frames.clear(); callbacks.forEach((callback) => callback(performance.now())); },
    clean() {
      assert.equal(frames.size, 0);
      assert.ok(observers.every((observer) => observer.closed));
      for (const source of [...watches, ...streams]) { assert.equal(source.closed, true); assert.equal(source.listenerCount, 0); }
      const count = (node) => node.listenerCount + node.children.filter((child) => typeof child !== 'string').reduce((sum, child) => sum + count(child), 0);
      assert.equal(count(root), 0);
    },
  };
}

// Node has no browser frame scheduler or resize observer.
for (const name of ['requestAnimationFrame', 'cancelAnimationFrame', 'ResizeObserver']) globalThis[name] ??= function () {};

test('map uses its root and releases its watch, controls, observer and frames', (t) => {
  const h = fixture(t);
  const dispose = map(h.root, h.services);
  h.watches[0].emit('snapshot', h.snapshot);
  h.frame();
  assert.ok(h.root.querySelector('#nodes').children.length);
  h.root.querySelector('#search').value = 'guest';
  const search = h.root.querySelector('#search');
  search.dispatchEvent(new Event('input'));
  const key = new Event('keydown'); key.key = 'Enter'; search.dispatchEvent(key);
  assert.equal(h.selection.get().host, 'alpha');
  assert.equal(h.selection.get().node, 's1');
  dispose();
  h.clean();
});

test('packets watches the busiest guest links and scopes a selected host', async (t) => {
  const h = fixture(t);
  const dispose = packets(h.root, h.services);
  const edges = Array.from({ length: 35 }, (_, i) => ({ id: `e${i}`, a: 's1', b: 't1' }));
  h.watches[0].emit('snapshot', { ...h.snapshot, edges, counters: Object.fromEntries(edges.map((e, i) => [e.id, [i, 0, 0, 0]])) });
  assert.equal(h.streams[0].links.split(',').length, 32);
  assert.equal(h.streams[0].links.split(',')[0], 'e34');
  h.selection.set({ host: 'alpha' });
  await settle();
  assert.equal(h.requests[0].path, '/api/host/alpha/links');
  assert.equal(h.streams.at(-1).links, 'e2');
  assert.equal(h.streams[0].closed, true);
  h.streams.at(-1).emit('world_error', { error: 'no capture for this link' });
  assert.match(h.root.textContent, /no capture for this link/);
  dispose();
  h.clean();
});

test('events filters text, preserves loss and selects only explicit flow identities', (t) => {
  const h = fixture(t);
  const dispose = events(h.root, h.services);
  const event = { seq: 1, at: 2, node: 's1', sandbox: { name: 'guest' }, source: 'http', kind: 'request', summary: '<script>hello</script>', fields: {}, conn: 12 };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [event], status: { losses: [{ stream: 'events', count: 4, reason: 'eviction' }] } });
  assert.match(h.root.textContent, /4 lost/);
  assert.match(h.root.textContent, /<script>hello<\/script>/);
  assert.equal(h.root.querySelector('script'), null);
  h.root.querySelector('button.text').click();
  assert.equal(h.selection.get().connection, 12);
  assert.deepEqual(h.selection.get().links, []);
  const input = h.root.querySelector('input');
  input.value = 'missing'; input.dispatchEvent(new Event('input'));
  assert.doesNotMatch(h.root.querySelector('.event-list').textContent, /hello/);
  dispose();
  h.clean();
});
