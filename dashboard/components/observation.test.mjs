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

test('a packet list keeps its rows when its links end and the run stops', async (t) => {
  const h = fixture(t);
  let stopped = false;
  h.services.stopped = () => stopped;
  const dispose = packets(h.root, h.services);
  h.watches[0].emit('snapshot', { ...h.snapshot, edges: [{ id: 'e2', a: 's1', b: 't1' }], counters: { e2: [1, 0, 0, 0] } });
  await settle();
  const opened = h.streams.length;
  h.streams.at(-1).emit('packet', { seq: 1, t: 1, side: 0, len: 28, skipped: 0, evicted: 0, src: '10.0.0.2', dst: '10.0.0.3', proto: 'ICMP', info: 'Echo', tags: [] });
  h.frame();
  const rows = () => h.root.querySelector('#prows').children.filter((row) => !row.classList.contains('gap')).length;
  assert.equal(rows(), 1);
  h.watches[0].emit('edge_end', { id: 'e2' });
  h.watches[0].emit('node_end', { id: 's1' });
  await settle();
  assert.equal(h.streams.length, opened, 'an ended link does not reopen the list');
  assert.equal(rows(), 1);
  stopped = true;
  h.watches[0].emit('edge', { id: 'e3', a: 's1', b: 't1' });
  await settle();
  assert.equal(h.streams.length, opened, 'a stopped run does not reopen the list');
  h.streams.at(-1).emit('end', { reason: 'every link closed' });
  h.frame();
  assert.equal(rows(), 1);
  assert.match(h.root.querySelector('#prows').textContent, /link closed/);
  dispose();
  h.clean();
});

test('the page\'s own console traffic is hidden with a count until a viewer shows it', async (t) => {
  const h = fixture(t);
  h.services.consoleAddresses = ['10.10.5.20'];
  const dispose = packets(h.root, h.services);
  h.watches[0].emit('snapshot', { ...h.snapshot, edges: [{ id: 'e2', a: 's1', b: 't1' }], counters: { e2: [1, 0, 0, 0] } });
  await settle();
  const sent = (stream) => {
    stream.emit('packet', { seq: 1, t: 1, side: 0, len: 90, skipped: 3, evicted: 0, src: '10.10.5.20:54926', dst: '10.0.0.2:22', proto: 'TCP', info: '54926 → 22', tags: [] });
    stream.emit('packet', { seq: 2, t: 2, side: 0, len: 60, skipped: 0, evicted: 0, src: '10.0.0.2:40000', dst: '142.250.1.1:443', proto: 'TLS', info: 'Client Hello', tags: [] });
    h.frame();
  };
  const rows = () => h.root.querySelector('#prows').children.filter((row) => !row.classList.contains('gap')).map((row) => row.dataset.src);
  const note = h.root.querySelector('#console-note');
  assert.equal(note.hidden, true);
  sent(h.streams.at(-1));
  assert.deepEqual(rows(), ['10.0.0.2:40000']);
  assert.equal(note.hidden, false);
  assert.equal(h.root.querySelector('#console-text').textContent, "1 packet of the page's own console traffic hidden, to and from 10.10.5.20.");
  assert.match(h.root.querySelector('#sampled').textContent, /3 packets not copied/, 'a hidden packet keeps its sampling count');
  const opened = h.streams.length;
  h.root.querySelector('#console-toggle').click();
  assert.equal(h.streams.length, opened + 1, 'showing reopens the stream to replay its history');
  sent(h.streams.at(-1));
  assert.deepEqual(rows(), ['10.10.5.20:54926', '10.0.0.2:40000']);
  assert.equal(h.root.querySelector('#console-text').textContent, "Showing the page's own console traffic, to and from 10.10.5.20.");
  assert.equal(h.root.querySelector('#console-toggle').textContent, 'Hide');
  dispose();
  h.clean();
});

test('events filters text, preserves loss and selects only explicit flow identities', (t) => {
  const h = fixture(t);
  const dispose = events(h.root, h.services);
  const event = { seq: 1, at: 2, node: 's1', sandbox: { name: 'guest' }, source: 'http', kind: 'request', summary: '<script>hello</script>', fields: {}, conn: 12 };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [event], status: { losses: [{ stream: 'events', count: 4, reason: 'eviction' }] } });
  h.frame();
  assert.match(h.root.textContent, /4 lost/);
  assert.match(h.root.textContent, /<script>hello<\/script>/);
  assert.equal(h.root.querySelector('script'), null);
  h.root.querySelector('button.event-line').click();
  assert.equal(h.selection.get().connection, 12);
  assert.deepEqual(h.selection.get().links, []);
  const input = h.root.querySelector('input');
  input.value = 'http.request'; input.dispatchEvent(new Event('input'));
  assert.match(h.root.querySelector('.event-list').textContent, /hello/);
  input.value = 'missing'; input.dispatchEvent(new Event('input'));
  assert.doesNotMatch(h.root.querySelector('.event-list').textContent, /hello/);
  dispose();
  h.clean();
});

test('a burst of events renders once per frame and keeps each row by key', (t) => {
  const h = fixture(t);
  const dispose = events(h.root, h.services);
  const event = (seq) => seq === 1999
    ? { seq, at: seq / 100, source: 'events', kind: 'dropped', fields: { count: 12, reason: 'eviction' } }
    : { seq, at: seq / 100, sandbox: { name: 'guest' }, source: 'scan', kind: 'port', summary: `port ${seq}`, fields: {} };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [] });
  h.frame();
  const document = h.root.ownerDocument, createElement = document.createElement;
  let built = 0;
  document.createElement = (tag) => { if (tag === 'div') built++; return createElement.call(document, tag); };
  // A port scan reports hundreds of ports at once.
  for (let seq = 1; seq <= 2000; seq++) h.watches[0].emit('event', event(seq));
  assert.equal(h.frames.size, 1, 'the whole burst waits for one frame');
  assert.equal(h.root.querySelectorAll('.event-item').length, 0);
  h.frame();
  const items = h.root.querySelectorAll('.event-item');
  assert.equal(items.length, 500);
  assert.match(items[0].textContent, /port 2000/);
  assert.match(items[1].textContent, /12 events were lost here \(eviction\)/);
  assert.match(items.at(-1).textContent, /port 1501/);
  assert.equal(built, 500, 'each kept row is built once');
  // One more event adds one row; every other row keeps its node.
  h.watches[0].emit('event', event(2001));
  h.frame();
  const next = h.root.querySelectorAll('.event-item');
  assert.equal(next.length, 500);
  assert.match(next[0].textContent, /port 2001/);
  assert.deepEqual(next.slice(1), items.slice(0, -1));
  assert.equal(built, 501);
  assert.equal(h.frames.size, 0);
  dispose();
  h.clean();
});

test('incoming events preserve a label being typed', (t) => {
  const h = fixture(t);
  h.services.labelCommand = '/api/command/labels';
  const dispose = events(h.root, h.services);
  const event = { seq: 1, at: 2, source: 'http', kind: 'request', summary: 'first', fields: {} };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [event] });
  h.frame();
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
  assert.equal(h.root.querySelector('.panel-tools').children[1], h.root.querySelector('.jump'));
  dispose();
  h.clean();
});

test('events offers new rows beside the filter and jumps to the newest event', (t) => {
  const h = fixture(t);
  const dispose = events(h.root, h.services);
  const event = { seq: 1, at: 2, source: 'http', kind: 'request', summary: 'first', fields: {} };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [event] });
  const list = h.root.querySelector('.event-list'), jump = h.root.querySelector('.jump');
  list.scrollTop = 80;
  list.dispatchEvent(new Event('scroll'));
  h.watches[0].emit('event', { ...event, seq: 2, summary: 'second' });
  assert.equal(list.scrollTop, 80);
  assert.doesNotMatch(list.textContent, /second/);
  assert.equal(h.root.querySelector('.panel-tools').children[1], jump);
  assert.equal(jump.textContent, '↑ 1 new');
  assert.equal(jump.hidden, false);
  jump.click();
  assert.equal(list.scrollTop, 0);
  assert.match(list.children[0].textContent, /second/);
  assert.equal(jump.hidden, true);
  dispose();
  h.clean();
});

test('packets offers new rows before Pause and jumps to the latest packets', (t) => {
  const h = fixture(t);
  const dispose = packets(h.root, h.services);
  h.watches[0].emit('snapshot', { ...h.snapshot, edges: [{ id: 'e1', a: 's1', b: 't1' }], counters: { e1: [0, 0, 0, 0] } });
  const list = h.root.querySelector('#plist'), jump = h.root.querySelector('#jump-packets');
  const controls = h.root.querySelector('.drawer-head').children;
  assert.equal(controls[controls.indexOf(jump) + 1], h.root.querySelector('#pause'));
  list.scrollHeight = 1000;
  list.clientHeight = 100;
  list.scrollTop = 40;
  h.streams[0].emit('packet', { seq: 1, t: 1, side: 0, len: 28, skipped: 0, evicted: 0, src: '10.0.0.2', dst: '10.0.0.3', proto: 'ICMP', info: 'Echo', tags: [] });
  h.frame();
  assert.equal(list.scrollTop, 40);
  assert.equal(jump.hidden, false);
  assert.equal(jump.textContent, '↓ 1 new');
  jump.click();
  assert.equal(list.scrollTop, 1000);
  assert.equal(jump.hidden, true);
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
  h.frame();
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

test('a late tab opens one packet stream once the graph is known and shows its loss before its rows', async (t) => {
  const h = fixture(t);
  const dispose = packets(h.root, h.services);
  await settle();
  h.frame();
  const note = h.root.querySelector('#plist-empty');
  assert.equal(h.streams.length, 0, 'no packet stream before the graph');
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, 'Loading packets…');
  const edges = [{ id: 'e2', a: 's1', b: 't1' }, { id: 'e3', a: 's1', b: 't2' }];
  h.watches[0].emit('snapshot', { ...h.snapshot, edges, counters: { e2: [2, 0, 0, 0], e3: [1, 0, 0, 0] } });
  await settle();
  assert.deepEqual(h.streams.map((stream) => stream.links), ['e2,e3'], 'one stream, opened once');
  // Link e3 has sent nothing yet, so e2's first row waits a moment. Its loss
  // shows at once, and the list does not claim there are no packets.
  h.streams[0].emit('packet', { seq: 9, link: 'e2', t: 4, side: 0, len: 28, skipped: 0, evicted: 7, src: '10.0.0.2', dst: '10.0.0.3', proto: 'ICMP', info: 'Echo', tags: [] });
  h.frame();
  assert.equal(h.root.querySelector('#prows').children.length, 0);
  assert.equal(h.root.querySelector('#sampled').textContent, 'Capture: 7 copies evicted');
  assert.equal(note.hidden, true);
  dispose();
  h.clean();
});

test('after the run stopped, packets say so instead of a fetch error and stop trying', async (t) => {
  const stoppedText = 'The run has stopped, so its packets can no longer be loaded.';
  // The page server is gone, so the host's links cannot be read.
  const h = fixture(t);
  h.services.stopped = () => true;
  h.services.transport.get = async () => { throw new TypeError('Failed to fetch'); };
  const dispose = packets(h.root, h.services);
  h.watches[0].emit('snapshot', { ...h.snapshot, nodes: [], edges: [] });
  await settle();
  assert.equal(h.root.querySelector('#prows').textContent, stoppedText);
  assert.doesNotMatch(h.root.textContent, /Failed to fetch/);
  dispose();
  h.clean();
  // A packet stream that drops after the run stopped says so once and closes.
  const live = fixture(t);
  let stopped = false;
  live.services.stopped = () => stopped;
  const stop = packets(live.root, live.services);
  live.watches[0].emit('snapshot', { ...live.snapshot, edges: [{ id: 'e2', a: 's1', b: 't1' }], counters: { e2: [1, 0, 0, 0] } });
  await settle();
  stopped = true;
  live.streams[0].emit('error', { error: 'Connection dropped. Reconnecting.' });
  live.frame();
  assert.equal(live.root.querySelector('#prows').textContent, stoppedText);
  assert.equal(live.streams[0].closed, true);
  stop();
  live.clean();
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

test('event and connection labels come from state and stay after the summary', (t) => {
  const h = fixture(t);
  let update, stopped = false;
  h.services.labelState = '/api/state/labels';
  h.services.labelCommand = '/api/command/labels';
  h.services.state = (path, callback) => { assert.equal(path, '/api/state/labels'); update = callback; return () => { stopped = true; }; };
  const dispose = events(h.root, h.services);
  const event = { seq: 7, at: 1.2, source: 'dns', kind: 'query', summary: 'example.test', conn: 4, fields: {} };
  h.watches[0].emit('snapshot', { ...h.snapshot, events: [event, { ...event, seq: 8, conn: 5 }] });
  update({ value: [{ text: 'download', target: { kind: 'event', seq: 7 } }, { text: 'lookup', target: { kind: 'connection', id: 4 } }] });
  h.frame();
  const lines = h.root.querySelectorAll('.event-line');
  assert.equal(lines[0].querySelector('.label-chip'), null);
  assert.equal(lines[1].querySelector('.text').textContent, 'example.testdownloadlookup');
  lines[1].click();
  assert.ok(h.root.querySelector('.event-detail-head').querySelector('.label-action'));
  h.selection.set({ event: null, connection: 5 });
  assert.equal(h.root.querySelectorAll('.event-line').length, 1);
  assert.equal(h.root.querySelector('.event-line').querySelector('.label-chip'), null);
  update({ value: [] });
  h.selection.set({ event: null, connection: null });
  assert.equal(h.root.querySelectorAll('.event-line').length, 2);
  assert.equal(h.root.querySelector('.label-chip'), null);
  dispose();
  assert.equal(stopped, true);
  h.clean();
});

test('selected startup links acquire their host name without changing the selection', async (t) => {
  const h = fixture(t);
  h.selection.set({ links: ['e2'] });
  const dispose = packets(h.root, h.services);
  h.watches[0].emit('snapshot', { ...h.snapshot, nodes: [], edges: [] });
  await settle();
  assert.deepEqual(h.selection.get().links, ['e2']);
  assert.equal(h.streams.at(-1).links, 'e2');
  assert.ok(h.streams.slice(0, -1).every((stream) => stream.closed));
  let update;
  h.services.transport.packet = async () => ({ ok: true, json: async () => ({ seq: 4, len: 28, t: 1, layers: [], buffers: [{ name: 'packet', hex: '4142' }] }) });
  dispose();
  const stop = packets(h.root, h.services, { onReady(view) { update = view; } });
  h.watches.at(-1).emit('snapshot', { ...h.snapshot, nodes: [], edges: [] });
  await settle();
  h.streams.at(-1).emit('packet', { seq: 4, link: 'e2', side: 0, t: 1, tags: [], src: 'a', dst: 'b', proto: 'ICMP', len: 28, info: 'Echo request' });
  update.flush();
  h.root.querySelector('#prows').querySelector('tr').click();
  await settle();
  assert.match(h.root.querySelector('.packet-detail-head').textContent, /Packet 4 · alpha's link, packet 4/);
  stop();
  h.clean();
});
