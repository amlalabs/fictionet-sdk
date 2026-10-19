import test from 'node:test';
import assert from 'node:assert/strict';
import { mount as map } from './map.mjs';
import { mount as packets } from './packets.mjs';
import { mount as events } from './events.mjs';
import { watchState } from '../state.mjs';
import { createSelection } from '../selection.mjs';
import { createTransport } from '../transport.mjs';
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
  const watch = () => { const source = new Source(); watches.push(source); return source; };
  const services = {
    selection, reducedMotion: { matches: true }, hosts: [{ name: 'alpha', sandbox: 'guest' }],
    watch, connect: (graph) => watchState(watch(), graph),
    transport: {
      ...createTransport({}, {
        location: { href: 'http://127.0.0.1:7878/' }, storage: { getItem: () => 'secret' },
        async fetch(url, options) {
          assert.equal(options.headers.Authorization, 'Bearer secret');
          requests.push({ path: new URL(url).pathname, signal: options.signal });
          return Response.json({ links: ['e2'] });
        },
      }),
      packetStream(list) { const source = new Source(); source.links = list; streams.push(source); return source; },
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

test('all hosts keeps startup captures after their links leave the map', async (t) => {
  const h = fixture(t);
  const dispose = packets(h.root, h.services);
  h.watches[0].emit('snapshot', { ...h.snapshot, nodes: [], edges: [] });
  await settle();
  assert.equal(h.requests.at(-1).path, '/api/host/alpha/links');
  assert.equal(h.streams.at(-1).links, 'e2');
  assert.match(h.root.querySelector('#drawer-title').textContent, /All hosts/);
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
  h.root.querySelector('button.event-line').click();
  assert.equal(h.selection.get().connection, 12);
  assert.deepEqual(h.selection.get().links, []);
  const input = h.root.querySelector('input');
  input.value = 'missing'; input.dispatchEvent(new Event('input'));
  assert.doesNotMatch(h.root.querySelector('.event-list').textContent, /hello/);
  dispose();
  h.clean();
});

test('incoming events preserve a label being typed', (t) => {
  const h = fixture(t);
  h.services.labelCommand = '/api/command/labels';
  const dispose = events(h.root, h.services);
  const event = { seq: 1, at: 2, source: 'http', kind: 'request', summary: 'first', fields: {} };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [event] });
  h.root.querySelector('.event-line').click();
  h.root.querySelector('.label-action').querySelector('button').click();
  const input = h.root.querySelector('.label-action').querySelector('input');
  input.value = 'Follow this request';
  h.watches[0].emit('event', { ...event, seq: 2, summary: 'second' });
  assert.equal(h.root.querySelector('.label-action').querySelector('input'), input);
  assert.equal(input.value, 'Follow this request');
  assert.equal(h.root.querySelector('.label-action').querySelector('form').hidden, false);
  assert.equal(h.root.querySelector('.jump').hidden, false);
  assert.match(h.root.querySelector('.jump').textContent, /1 new/);
  dispose();
  h.clean();
});

test('a selected event shows its fields and offers only an approximate packet match', (t) => {
  const h = fixture(t);
  const pairs = [];
  h.services.packetPair = { set() {} };
  h.services.showPackets = (pair) => pairs.push(pair);
  const dispose = events(h.root, h.services);
  const event = { seq: 2, at: 3, sandbox: { name: 'guest' }, source: 'dns', kind: 'query', summary: 'example.test', fields: { name: 'example.test' }, local: '10.0.0.1:53', peer: '10.0.0.2:5000', transport: 'udp', tls: false, conn: null };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [event] });
  assert.equal(h.root.querySelector('.event-detail'), null);
  h.root.querySelector('button.event-line').click();
  assert.equal(h.selection.get().host, 'alpha');
  assert.match(h.root.querySelector('.event-detail').textContent, /10\.0\.0\.2:5000/);
  assert.match(h.root.textContent, /Approximate: matched by address and port, not by connection\./);
  h.root.querySelectorAll('button').find((button) => button.textContent === 'Show matching packets').click();
  assert.deepEqual(pairs, [{ local: '10.0.0.1:53', peer: '10.0.0.2:5000' }]);
  h.root.querySelector('button.event-line').click();
  assert.equal(h.root.querySelector('.event-detail'), null);
  assert.equal(h.selection.get().event, null);
  dispose();
  h.clean();
});

test('packets says when its links have nothing captured yet', (t) => {
  const h = fixture(t);
  const dispose = packets(h.root, h.services);
  h.watches[0].emit('snapshot', { ...h.snapshot, edges: [{ id: 'e1', a: 's1', b: 't1' }], counters: { e1: [0, 0, 0, 0] } });
  h.frame();
  const note = h.root.querySelector('#plist-empty');
  assert.equal(note.hidden, false);
  assert.match(note.textContent, /No packets yet/);
  h.streams[0].emit('packet', { seq: 1, t: 1, side: 0, len: 28, skipped: 0, evicted: 0, src: '10.0.0.2', dst: '10.0.0.3', proto: 'ICMP', info: 'Echo', tags: [] });
  h.frame();
  assert.equal(note.hidden, true);
  dispose();
  h.clean();
});

test('the map keeps its own selection instead of applying it back to itself', (t) => {
  // Drawn links move packets along their paths; the fake DOM has no geometry.
  for (const [name, value] of [['getTotalLength', () => 100], ['getPointAtLength', () => ({ x: 0, y: 0 })]]) {
    if (Element.prototype[name]) continue;
    Element.prototype[name] = value;
    t.after(() => { delete Element.prototype[name]; });
  }
  const h = fixture(t);
  const dispose = map(h.root, h.services);
  const snapshot = {
    ...h.snapshot,
    nodes: [...h.snapshot.nodes, { id: 't1', kind: 'task', name: 'filter', parent: null }],
    edges: [{ id: 'e1', a: 's1', b: 't1' }],
    counters: { e1: [1, 40, 1, 40] },
  };
  h.watches[0].emit('snapshot', snapshot);
  h.frame();
  h.frame();
  const hit = h.root.querySelectorAll('path.hit')[0];
  assert.ok(hit, 'the link is drawn');
  hit.dispatchEvent(new Event('click'));
  assert.deepEqual(h.selection.get().links, ['e1']);
  // The next frames must not undo the selection the map just made: the side
  // panel keeps describing the link.
  h.frame();
  h.frame();
  assert.deepEqual(h.selection.get().links, ['e1']);
  assert.match(h.root.querySelector('#side').textContent, /A link between/);
  assert.doesNotMatch(h.root.querySelector('#side').textContent, /This world/);
  dispose();
  h.clean();
});
