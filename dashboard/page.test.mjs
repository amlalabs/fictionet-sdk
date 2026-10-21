import test from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createServices, divider, appShell, showNotice } from './page.mjs';
import { createStateHub, createWatchHub } from './streams.mjs';
import { createDocument, Element } from './test-dom.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

test('packet choices persist per viewer and remain after page controls are disposed', async (t) => {
  const values = new Map();
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: (key) => values.get(key), setItem: (key, value) => values.set(key, value) } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'localStorage', previous); else delete globalThis.localStorage; });
  const h = harness(t);
  const services = createServices({ watch: () => h.stream('watch') }, {});
  const seen = [];
  const off = services.packetFilter.subscribe((value) => seen.push(value));
  assert.equal(services.packetFilter.get(), 'conversations');
  const stop = appShell(h.root, services, { title: 'Search', hosts: [], panels: [{ id: 'world', title: 'Web', area: 'workspace', kind: 'custom', module: '/world.mjs' }] });
  await settle();
  const menu = h.root.querySelector('#world-menu');
  const toggle = h.root.querySelector('.app-menu-button'); toggle.click();
  assert.equal(menu.hidden, false);
  const segment = menu.querySelector('.app-packet-filter').querySelector('.seg');
  assert.deepEqual(segment.children.map((b) => b.textContent), ['Conversations', 'Every packet']);
  assert.deepEqual(segment.children.map((b) => b.getAttribute('aria-pressed')), ['true', 'false']);
  segment.children[1].click();
  assert.equal(services.packetFilter.get(), 'every');
  assert.equal(values.get('fictionet-packet-filter'), 'every');
  assert.deepEqual(segment.children.map((b) => b.getAttribute('aria-pressed')), ['false', 'true']);
  assert.equal(createServices({}, {}).packetFilter.get(), 'every');
  const { mount: search } = await import('../demos/src/search/view.mjs');
  const state = services.state; services.state = () => () => {};
  const disposePage = search(h.root.querySelector('#app-world-panel'), services, { state: '/api/state/search' });
  assert.match(services.worldMenu.textContent, /New pages/);
  assert.doesNotMatch(menu.textContent, /canned|stub|seed|splice|store|generator|generated|cache/i);
  disposePage(); services.state = state;
  assert.equal(services.worldMenu.children.length, 0);
  assert.equal(segment.parentNode.parentNode, menu);
  assert.equal(services.packetFilter.get(), 'every');
  segment.children[0].click();
  assert.equal(values.get('fictionet-packet-filter'), 'conversations');
  assert.deepEqual(seen, ['conversations', 'every', 'conversations']);
  assert.doesNotMatch(menu.textContent, /canned|stub|seed|splice|store|generator|generated|cache/i);
  off(); stop(); services.dispose();
  assert.ok(segment.children.every((button) => button.listenerCount === 0));
});

test('packet choices work when browser storage is unavailable', () => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  try {
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, get() { throw new Error('Storage unavailable'); } });
    const services = createServices({}, {});
    assert.equal(services.packetFilter.get(), 'conversations');
    services.packetFilter.set('every');
    assert.equal(services.packetFilter.get(), 'every');
    services.dispose();
  } finally {
    if (previous) Object.defineProperty(globalThis, 'localStorage', previous); else delete globalThis.localStorage;
  }
});

class Source extends Element {
  constructor(kind, args) { super(kind); this.args = args; }
  emit(name, value) { const event = new Event(name); event.data = JSON.stringify(value); this.dispatchEvent(event); }
  close() { this.closed = true; }
}

test('every state topic shares one stream, which reopens only for a topic it does not carry', async () => {
  const streams = [];
  const services = createServices({
    stateStream(topics) { const source = new Source('state', { ...topics }); streams.push(source); return source; },
  }, {});
  const values = [], other = [], hosts = [], errors = [];
  const stop = services.state('/api/state/exchanges', (value) => values.push(value), (error) => errors.push(error));
  const stopOther = services.state('/api/state/exchanges', (value) => other.push(value));
  const stopHost = services.state('/api/state/host-alpha', (value) => hosts.push(value));
  await settle();
  assert.equal(streams.length, 1, 'subscriptions in one turn open one stream');
  assert.deepEqual(streams[0].args, { exchanges: undefined, 'host-alpha': undefined });
  streams[0].emit('snapshot', { topic: 'exchanges', revision: 1, value: [1] });
  streams[0].emit('snapshot', { topic: 'host-alpha', revision: 3, value: { state: 'booting' } });
  assert.deepEqual(hosts.map((snapshot) => snapshot.value.state), ['booting']);
  // Each change arrives as the topic's snapshot. An older one is ignored; a
  // status change keeps the revision.
  streams[0].emit('snapshot', { topic: 'exchanges', revision: 4, value: [4] });
  streams[0].emit('snapshot', { topic: 'exchanges', revision: 2, value: [2] });
  streams[0].emit('snapshot', { topic: 'exchanges', revision: 4, value: [4], status: { too_large: true } });
  assert.deepEqual(values.map((snapshot) => snapshot.revision), [1, 4, 4]);
  assert.deepEqual(other, values);
  // A dropped connection reconnects on its own: it fails nothing, and what
  // arrives after the reconnect is delivered.
  streams[0].emit('error', { error: 'Connection dropped. Reconnecting.' });
  assert.equal(errors.length, 0);
  streams[0].emit('snapshot', { topic: 'host-alpha', revision: 4, value: { state: 'ssh_up' } });
  assert.deepEqual(hosts.map((snapshot) => snapshot.value.state), ['booting', 'ssh_up']);
  // Closing a panel keeps its topic on the stream and current, so switching
  // back to it neither reopens the stream nor waits for the next change.
  stopHost();
  await settle();
  assert.equal(streams.length, 1);
  assert.equal(streams[0].closed, undefined);
  streams[0].emit('snapshot', { topic: 'host-alpha', revision: 5, value: { state: 'desktop_up' } });
  const again = [];
  const stopAgain = services.state('/api/state/host-alpha', (value) => again.push(value));
  await settle();
  assert.equal(streams.length, 1, 'a topic the stream carries opens no stream');
  assert.deepEqual(again.map((snapshot) => snapshot.value.state), ['desktop_up']);
  // A topic no panel shows stays current, so a panel that shows it later
  // gets the latest at once.
  stopAgain();
  streams[0].emit('snapshot', { topic: 'host-alpha', revision: 6, value: { state: 'stopped' } });
  const later = [];
  const stopLater = services.state('/api/state/host-alpha', (value) => later.push(value));
  assert.deepEqual(later.map((snapshot) => snapshot.value.state), ['stopped']);
  stopLater();
  // A new topic reopens the stream once, with what is held.
  const routes = [];
  const stopRoutes = services.state('/api/state/routing', (value) => routes.push(value), (error) => errors.push(error));
  await settle();
  assert.equal(streams[0].closed, true);
  assert.equal(streams[0].listenerCount, 0);
  assert.deepEqual(streams[1].args, { exchanges: 4, 'host-alpha': 6, routing: undefined });
  // A refusal ends the stream, every topic on it hears why, and a later
  // subscription opens a stream without them.
  streams[1].emit('world_error', { error: 'no such state topic: "routing"' });
  assert.deepEqual(errors.map((error) => error.message), ['no such state topic: "routing"', 'no such state topic: "routing"']);
  const stopLeases = services.state('/api/state/leases', () => {});
  await settle();
  assert.deepEqual(streams[2].args, { leases: undefined });
  // When nothing listens, no stream stays open.
  for (const unsubscribe of [stop, stopOther, stopRoutes]) unsubscribe();
  await settle();
  assert.equal(streams[2].closed, undefined);
  stopLeases();
  await settle();
  assert.equal(streams[2].closed, true);
  assert.equal(streams[2].listenerCount, 0);
  assert.equal(streams.length, 3, 'no stream while nothing listens');
  services.dispose();
});

test('a stream carries at most the server limit, dropping topics no panel shows to stay under it', async () => {
  const streams = [];
  const hub = createStateHub({ stateStream(topics) { const source = new Source('state', { ...topics }); streams.push(source); return source; } }, { most: 2 });
  const stopA = hub.subscribe('a', () => {});
  hub.subscribe('b', () => {});
  await settle();
  stopA();
  await settle();
  assert.equal(streams.length, 1);
  hub.subscribe('c', () => {});
  await settle();
  assert.deepEqual(Object.keys(streams[1].args), ['b', 'c']);
  hub.dispose();
});

test('after the run stopped, a state stream that cannot connect fails only topics with nothing to show', async () => {
  const streams = [];
  let stopped = false;
  const hub = createStateHub({ stateStream(topics) { const source = new Source('state', { ...topics }); streams.push(source); return source; } }, { stopped: () => stopped });
  const held = [], fresh = [];
  hub.subscribe('routing', (value) => held.push(value), (error) => held.push(error));
  await settle();
  streams[0].emit('snapshot', { topic: 'routing', revision: 2, value: { mode: 'legitimate' } });
  // The run ends; a panel opened now needs a topic the stream does not carry.
  stopped = true;
  hub.subscribe('results', (value) => fresh.push(value), (error) => fresh.push(error));
  await settle();
  streams[1].emit('error', { error: 'Connection dropped. Reconnecting.' });
  assert.deepEqual(fresh.map((item) => item.message), ['The run has stopped, so its state can no longer be loaded']);
  assert.deepEqual(held.map((item) => (item instanceof Error ? item.message : item.value.mode)), ['legitimate'], 'a topic with state keeps it and gets no error');
  assert.equal(streams[1].closed, true);
  // Another panel showing the same topic later asks again and hears the same.
  const later = [];
  hub.subscribe('results', (value) => later.push(value), (error) => later.push(error));
  await settle();
  streams[2].emit('error', { error: 'Connection dropped. Reconnecting.' });
  assert.deepEqual(later.map((item) => item.message), ['The run has stopped, so its state can no longer be loaded']);
  hub.dispose();
});

test('the watch hub replays the latest snapshot and changes to a late subscriber', async () => {
  const upstreams = [];
  const hub = createWatchHub({ watch() { const source = new Source('watch'); upstreams.push(source); return source; } }, { limit: 3 });
  const early = hub.subscribe(), seen = [];
  for (const name of ['snapshot', 'node', 'event']) early.addEventListener(name, (event) => seen.push(`${name}:${event.data}`));
  await settle();
  upstreams[0].emit('snapshot', { t: 1 });
  upstreams[0].emit('node', { id: 'n1' });
  const late = hub.subscribe(), replayed = [];
  for (const name of ['snapshot', 'node', 'event']) late.addEventListener(name, (event) => replayed.push(`${name}:${event.data}`));
  await settle();
  assert.deepEqual(replayed, ['snapshot:{"t":1}', 'node:{"id":"n1"}']);
  upstreams[0].emit('event', { seq: 1 });
  assert.equal(seen.length, 3);
  assert.equal(replayed.length, 3, 'live events follow the replay once');
  assert.equal(upstreams.length, 1, 'subscribers share one stream');
  // Counters are absolute: a late subscriber gets only the latest, and they
  // never fill the replay.
  for (let t = 1; t <= 50; t++) upstreams[0].emit('counters', { t });
  assert.equal(upstreams[0].closed, undefined);
  const third = hub.subscribe(), counters = [];
  third.addEventListener('counters', (event) => counters.push(event.data));
  await settle();
  assert.deepEqual(counters, ['{"t":50}']);
  third.close();
  // Past its limit the hub starts again from a fresh snapshot.
  upstreams[0].emit('event', { seq: 2 });
  upstreams[0].emit('event', { seq: 3 });
  assert.equal(upstreams[0].closed, true);
  assert.equal(upstreams[0].listenerCount, 0);
  assert.equal(upstreams.length, 2);
  early.close();
  late.close();
  hub.dispose();
  assert.equal(upstreams[1].closed, true);
  assert.equal(upstreams[1].listenerCount, 0);
});

test('a state hub with no topics opens nothing, and dispose closes its stream', async () => {
  const streams = [];
  const hub = createStateHub({ stateStream(topics) { const source = new Source('state', topics); streams.push(source); return source; } });
  await settle();
  assert.equal(streams.length, 0);
  hub.subscribe('leases', () => {});
  await settle();
  hub.dispose();
  assert.equal(streams[0].closed, true);
  assert.equal(streams[0].listenerCount, 0);
});

test('divider clamps keyboard movement and survives refused storage', (t) => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, get() { throw new Error('Storage refused'); } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'localStorage', previous); else delete globalThis.localStorage; });
  const document = createDocument(), element = document.createElement('div'), workspace = document.createElement('main');
  const dispose = divider(element, workspace, 'Demo');
  assert.equal(element.getAttribute('aria-valuenow'), '58');
  const key = (key) => { const event = new Event('keydown'); event.key = key; element.dispatchEvent(event); };
  key('ArrowLeft'); assert.equal(element.getAttribute('aria-valuenow'), '56');
  key('Home'); key('ArrowLeft'); assert.equal(element.getAttribute('aria-valuenow'), '25');
  key('End'); key('ArrowRight'); assert.equal(element.getAttribute('aria-valuenow'), '80');
  element.dispatchEvent(new Event('dblclick')); assert.equal(element.getAttribute('aria-valuenow'), '58');
  dispose(); assert.equal(element.listenerCount, 0);
});

// The page as page.html lays it out, with the ids page.mjs uses.
function pageRoot(document) {
  const root = document.createElement('div');
  root.setAttribute('id', 'demo');
  document.body.append(root);
  const add = (id, tag = 'div', parent = root) => { const node = document.createElement(tag); node.setAttribute('id', id); parent.append(node); return node; };
  for (const id of ['page-title', 'run-status', 'page-status', 'run-clock', 'moment-title', 'moment-time', 'host-bar', 'workbench', 'workspace', 'divider', 'scope-text', 'moment-status', 'inspector-content', 'notice', 'notice-title', 'notice-text']) add(id);
  for (const id of ['moment-banner', 'theme', 'clear-scope', 'notice-action']) add(id, 'button');
  add('tabs', 'div', add('tab-strip'));
  return root;
}

function harness(t) {
  const document = createDocument(), window = new Element('window');
  document.hidden = false;
  const root = pageRoot(document);
  const previous = { document: globalThis.document, window: globalThis.window };
  globalThis.document = document; globalThis.window = window;
  t.after(() => { globalThis.document = previous.document; globalThis.window = previous.window; });
  const resizeObserver = globalThis.ResizeObserver;
  globalThis.ResizeObserver = class { observe() {} disconnect() {} };
  t.after(() => { globalThis.ResizeObserver = resizeObserver; });
  const timers = new Map(), frames = new Map();
  t.mock.method(globalThis, 'setInterval', (callback) => { const id = Symbol(); timers.set(id, callback); return id; });
  t.mock.method(globalThis, 'clearInterval', (id) => timers.delete(id));
  t.mock.method(globalThis, 'setTimeout', (callback) => { const id = Symbol(); timers.set(id, callback); return id; });
  t.mock.method(globalThis, 'clearTimeout', (id) => timers.delete(id));
  globalThis.requestAnimationFrame ??= () => 0;
  globalThis.cancelAnimationFrame ??= () => {};
  t.mock.method(globalThis, 'requestAnimationFrame', (callback) => { const id = Symbol(); frames.set(id, callback); return id; });
  t.mock.method(globalThis, 'cancelAnimationFrame', (id) => frames.delete(id));
  globalThis.matchMedia ??= () => ({ matches: true, addEventListener() {}, removeEventListener() {} });
  // Long-lived HTTP streams open now, and the most ever open at once.
  const streams = [];
  const budget = { open: 0, most: 0 };
  const stream = (kind, args) => {
    const source = new Source(kind, args);
    budget.open++;
    budget.most = Math.max(budget.most, budget.open);
    source.close = () => { if (!source.closed) { source.closed = true; budget.open--; } };
    streams.push(source);
    return source;
  };
  return { document, window, root, timers, frames, streams, budget, stream };
}

const DESCRIPTION = {
  title: 'Fixture',
  moments: [{ id: 'paused', title: 'Traffic paused', events: '/api/event-table/paused' }],
  hosts: ['alpha', 'beta'].map((name) => ({ name, sandbox: name, status: `/api/state/host-${name}`, screen: null, terminal: null })),
  panels: [
    { id: 'packets', title: 'Packets', area: 'inspector', kind: 'packets' },
    { id: 'events', title: 'Events', area: 'inspector', kind: 'events' },
    { id: 'map', title: 'Map', area: 'inspector', kind: 'map' },
    { id: 'rows', title: 'Rows', area: 'inspector', kind: 'table', state: '/api/state/rows', columns: [] },
    { id: 'log', title: 'Log', area: 'inspector', kind: 'event_table', events: '/api/event-table/log', columns: [] },
    { id: 'traffic', title: 'Traffic', area: 'inspector', kind: 'control', command: '/api/command/traffic', state: '/api/state/traffic', actions: [] },
    { id: 'plant', title: 'Plant', area: 'inspector', kind: 'custom', module: '/panels/plant.mjs', state: '/api/state/rows' },
  ],
};

test('the page holds at most three long-lived streams across every panel, and none after dispose', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  let transportClosed = false, themeClosed = false;
  const transport = {
    get: async (path) => (path === '/api/page' ? DESCRIPTION : path.startsWith('/api/host/') ? { links: [] } : { rows: [], next: 0, dropped: 0 }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() { transportClosed = true; },
  };
  const stop = await mount(h.root, transport, { subscribe: (listener) => { listener('light'); return () => {}; }, dispose() { themeClosed = true; } });
  await settle();
  const watch = h.streams.find((source) => source.tag === 'watch');
  watch.emit('snapshot', { t: 1, started: 0, ended: false, hosts: [], groups: [], nodes: [{ id: 's1', kind: 'sandbox', name: 'alpha' }], edges: [{ id: 'e1', a: 's1', b: 't1' }], counters: { e1: [1, 1, 0, 0] }, events: [] });
  await settle();
  assert.equal(h.root.querySelectorAll('section.workspace-tile').length, 1);
  assert.equal(h.root.querySelector('section.workspace-tile').getAttribute('aria-label'), 'alpha');
  const pins = h.root.querySelectorAll('button.pin');
  pins[0].click(); pins[1].click();
  assert.equal(h.root.querySelectorAll('section.workspace-tile').length, 2);
  const tabs = h.root.querySelector('#tabs').children;
  assert.deepEqual(tabs.map((tab) => tab.textContent), ['Packets', 'Events', 'Map', 'Rows', 'Log', 'Traffic', 'Plant']);
  const states = () => h.streams.filter((source) => source.tag === 'state').length;
  let afterFirstPass;
  for (const [index, tab] of [...tabs, ...tabs].entries()) {
    if (index === tabs.length) afterFirstPass = states();
    tab.click();
    await settle();
    watch.emit('counters', { t: 2, edges: {} });
    await settle();
  }
  // Switching tabs must not reopen the state stream: a reopen drops what the
  // old stream had not delivered, and a page whose run just ended cannot
  // connect again, so it would keep showing stale state.
  assert.equal(states(), afterFirstPass, 'a second pass through every tab opened a state stream');
  // The keyboard moves focus along the tabs without opening them; Enter opens one.
  tabs[0].click();
  await settle();
  const right = new Event('keydown'); right.key = 'ArrowRight'; tabs[0].dispatchEvent(right);
  assert.equal(h.document.activeElement, tabs[1]);
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  assert.equal(tabs[1].getAttribute('aria-selected'), 'false');
  const enter = new Event('keydown'); enter.key = 'Enter'; tabs[1].dispatchEvent(enter);
  assert.equal(tabs[1].getAttribute('aria-selected'), 'true');
  assert.ok(h.budget.most <= 3, `the page held ${h.budget.most} streams at once`);
  assert.equal(h.streams.filter((source) => source.tag === 'watch').length, 1, 'one watch for every panel');
  stop();
  assert.equal(h.budget.open, 0);
  assert.equal(h.timers.size, 0);
  assert.equal(h.frames.size, 0);
  assert.equal(h.window.listenerCount, 0);
  assert.equal(h.document.listenerCount, 0);
  assert.ok(h.streams.every((source) => source.listenerCount === 0));
  assert.equal(transportClosed, true);
  assert.equal(themeClosed, true);
});

test('after the run stops, a moment read that fails says nothing and stops asking', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  let reads = 0, failing = false;
  const transport = {
    get: async (path) => {
      if (path === '/api/page') return DESCRIPTION;
      if (path === '/api/event-table/paused') {
        reads++;
        if (failing) throw new TypeError('Failed to fetch');
        return { rows: [], next: 0, dropped: 0 };
      }
      return path.startsWith('/api/host/') ? { links: [] } : { rows: [], next: 0, dropped: 0 };
    },
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  };
  const stop = await mount(h.root, transport, { subscribe: () => () => {}, dispose() {} });
  await settle();
  const watch = h.streams.find((source) => source.tag === 'watch');
  watch.emit('ended', { t: 5 });
  failing = true;
  const poll = async () => { const pending = [...h.timers.values()]; h.timers.clear(); pending.forEach((callback) => callback()); await settle(); };
  const before = reads;
  await poll();
  assert.equal(reads, before + 1);
  assert.equal(h.root.querySelector('#moment-status').textContent, '');
  await poll();
  assert.equal(reads, before + 1, 'a stopped page stops asking for moments');
  stop();
});

test('a refused page description shows one not signed in card', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const stop = await mount(h.root, {
    get: async () => { const error = new Error('Dashboard authorization failed'); error.status = 401; throw error; },
    close() {},
  }, { dispose() {} });
  assert.equal(h.root.dataset.state, 'notice');
  assert.equal(h.root.querySelector('#notice').hidden, false);
  assert.equal(h.root.querySelector('#notice-title').textContent, 'Not signed in');
  assert.equal(h.root.querySelector('#notice-text').textContent, 'Open the full link the demo printed, including the part after #.');
  assert.equal(h.root.querySelector('#host-bar').children.length, 0);
  stop();
});

test('choosing the terminal switch focuses the connected terminal but mounting it does not', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const sockets = [], terminals = [];
  class Terminal {
    constructor() { this.options = {}; terminals.push(this); }
    loadAddon() {}
    resize(cols, rows) { this.cols = cols; this.rows = rows; }
    open(display) { this.input = h.document.createElement('textarea'); display.append(this.input); }
    blur() {}
    focus() { this.input.focus(); }
    onData() { return { dispose() {} }; }
    dispose() {}
  }
  class FitAddon { proposeDimensions() { return { cols: 80, rows: 24 }; } }
  const modules = { '/vendor/ghostty-web/dist/ghostty-web.js': { Terminal, FitAddon, init: async () => {} } };
  // Node has no ResizeObserver or getComputedStyle; the terminal uses both.
  const previous = { ResizeObserver: globalThis.ResizeObserver, getComputedStyle: globalThis.getComputedStyle };
  t.after(() => Object.assign(globalThis, previous));
  globalThis.ResizeObserver = class { observe() {} disconnect() {} };
  globalThis.getComputedStyle = () => ({});
  for (const initial of ['screen', 'terminal']) {
    const description = {
      title: 'Fixture',
      hosts: [{ name: 'alpha', status: '/api/state/host-alpha', screen: initial === 'screen', terminal: true }],
      panels: [{ kind: 'terminal', host: 'alpha' }],
    };
    const stop = await mount(h.root, {
      get: async () => description,
      stateStream: (topics) => h.stream('state', { ...topics }),
      watch: () => h.stream('watch'),
      async socket() { const socket = new Source('socket'); socket.readyState = 0; sockets.push(socket); return { socket }; },
      close() {},
    }, { subscribe: () => () => {}, dispose() {} }, async (url) => modules[url]);
    t.after(stop);
    await settle();
    const source = h.streams.findLast((stream) => stream.tag === 'state' && !stream.closed);
    source.emit('snapshot', { topic: 'host-alpha', revision: 1, value: { state: 'ssh_up', terminal: true, screen: false } });
    const button = initial === 'screen'
      ? h.root.querySelector('.segmented').children[1]
      : h.root.querySelector('#theme');
    button.focus();
    if (initial === 'screen') button.click();
    await settle();
    assert.equal(h.document.activeElement, button, 'focus waits for the connection');
    const socket = sockets.at(-1), terminal = terminals.at(-1);
    assert.ok(socket);
    assert.ok(terminal);
    socket.readyState = 1;
    socket.dispatchEvent(new Event('open'));
    assert.equal(h.document.activeElement, initial === 'screen' ? terminal.input : button);
    stop();
  }
});

test('a custom workspace panel replaces the console tiles and hides the pins', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const description = {
    ...DESCRIPTION,
    panels: [
      { id: 'packets', title: 'Packets', area: 'inspector', kind: 'packets' },
      { id: 'plant', title: 'Plant', area: 'workspace', kind: 'custom', module: '/panels/plant.mjs', state: '/api/state/rows' },
    ],
  };
  const stop = await mount(h.root, {
    get: async (path) => (path === '/api/page' ? description : { rows: [], next: 0, dropped: 0 }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  }, { subscribe: (listener) => { listener('light'); return () => {}; }, dispose() {} });
  await settle();
  const workspace = h.root.querySelector('#workspace');
  assert.equal(workspace.querySelectorAll('section.custom-workspace').length, 1);
  assert.equal(workspace.querySelectorAll('section.workspace-tile').length, 0);
  assert.ok(h.root.querySelectorAll('button.pin').every((pin) => pin.hidden));
  assert.deepEqual(h.root.querySelector('#tabs').children.map((tab) => tab.textContent), ['Packets']);
  stop();
  assert.equal(h.budget.open, 0);
});

test('a custom workspace can sit beside consoles while pins remain available', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const description = { ...DESCRIPTION, panels: [
    { id: 'packets', title: 'Packets', area: 'inspector', kind: 'packets' },
    { id: 'plant', title: 'Plant', area: 'workspace', kind: 'custom', module: '/panels/plant.mjs', state: '/api/state/rows' },
    { id: 'alpha-screen', title: 'Screen', area: 'workspace', kind: 'screen', host: 'alpha' },
  ] };
  const stop = await mount(h.root, {
    get: async (path) => path === '/api/page' ? description : { rows: [], next: 0, dropped: 0 },
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'), packetStream: (links) => h.stream('packets', links), close() {},
  }, { subscribe: () => () => {}, dispose() {} });
  await settle();
  const workspace = h.root.querySelector('#workspace');
  const custom = workspace.querySelector('section.custom-workspace');
  assert.ok(custom);
  assert.equal(workspace.querySelectorAll('section.workspace-tile').length, 1);
  assert.ok(workspace.classList.contains('shared-workspace'));
  assert.ok(h.root.querySelector('#workbench').classList.contains('shared-workbench'));
  assert.equal(workspace.querySelector('section.workspace-tile').style.alignSelf, 'start');
  const pins = h.root.querySelectorAll('button.pin');
  assert.ok(pins.every((pin) => !pin.hidden));
  pins.forEach((pin) => pin.click());
  assert.equal(workspace.querySelectorAll('section.workspace-tile').length, 2);
  assert.equal(workspace.querySelector('section.custom-workspace'), custom);
  pins[0].click();
  assert.equal(workspace.querySelector('section.workspace-tile').getAttribute('aria-label'), 'beta');
  assert.equal(h.root.querySelector('#divider').getAttribute('aria-valuenow'), '68');
  stop();
  assert.equal(h.budget.open, 0);
  assert.equal(h.timers.size, 0);
});

test('a shared custom workspace keeps the console tile and releases both on disposal', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const description = { ...DESCRIPTION, hosts: DESCRIPTION.hosts.map((host) => ({ ...host, screen: true, terminal: true })), panels: [
    { id: 'plant', title: 'Plant', area: 'workspace', kind: 'custom', module: '/panels/plant.mjs', state: '/api/state/rows' },
    { id: 'alpha-screen', title: 'Alpha', area: 'workspace', kind: 'screen', host: 'alpha' },
  ] };
  const stop = await mount(h.root, {
    get: async (path) => path === '/api/page' ? description : { rows: [], next: 0, dropped: 0 },
    stateStream: (topics) => h.stream('state', topics), watch: () => h.stream('watch'), close() {},
  }, { subscribe: (listener) => { listener('light'); return () => {}; }, dispose() {} });
  await settle();
  const workspace = h.root.querySelector('#workspace');
  assert.ok(workspace.classList.contains('shared-workspace'));
  assert.ok(h.root.querySelector('#workbench').classList.contains('shared-workbench'));
  assert.equal(h.root.querySelector('#workbench').style['--workspace'], '68%');
  assert.equal(h.root.querySelector('#divider').getAttribute('aria-valuenow'), '68');
  assert.equal(workspace.querySelectorAll('section.custom-workspace').length, 1);
  assert.equal(workspace.querySelectorAll('section.workspace-tile').length, 1);
  assert.equal(workspace.querySelector('section.workspace-tile').style.alignSelf, 'start');
  const terminal = workspace.querySelectorAll('button').find((button) => button.textContent === 'Terminal');
  terminal.click();
  await settle();
  assert.equal(workspace.querySelector('section.workspace-tile').style.alignSelf, undefined);
  workspace.querySelectorAll('button').find((button) => button.textContent === 'Screen').click();
  await settle();
  assert.equal(workspace.querySelector('section.workspace-tile').style.alignSelf, 'start');
  assert.ok(h.root.querySelectorAll('button.pin').every((pin) => !pin.hidden));
  h.document.hidden = true; h.document.dispatchEvent(new Event('visibilitychange'));
  h.document.hidden = false; h.document.dispatchEvent(new Event('visibilitychange'));
  await settle();
  assert.equal(workspace.querySelectorAll('section.custom-workspace').length, 1);
  assert.equal(workspace.querySelectorAll('section.workspace-tile').length, 1);
  stop();
  assert.equal(h.budget.open, 0);
  assert.equal(h.timers.size, 0);
});

test('showPanel opens a custom panel by its id', async (t) => {
  const { registerHooks } = await import('node:module');
  let services;
  globalThis.openerMounted = (value) => { services = value; };
  const hooks = registerHooks({
    resolve(specifier, context, next) {
      if (specifier !== '/panels/opener.mjs') return next(specifier, context);
      return { url: 'data:text/javascript,export function mount(root, services) { globalThis.openerMounted(services); return () => {}; }', shortCircuit: true };
    },
  });
  t.after(() => { hooks.deregister(); delete globalThis.openerMounted; });
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const description = {
    ...DESCRIPTION,
    panels: [
      { id: 'packets', title: 'Packets', area: 'inspector', kind: 'packets' },
      { id: 'opener', title: 'Opener', area: 'inspector', kind: 'custom', module: '/panels/opener.mjs', state: '/api/state/rows' },
      { id: 'second', title: 'Second', area: 'inspector', kind: 'custom', module: '/panels/second.mjs', state: '/api/state/rows' },
    ],
  };
  const stop = await mount(h.root, {
    get: async (path) => (path === '/api/page' ? description : { rows: [], next: 0, dropped: 0 }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  }, { subscribe: (listener) => { listener('light'); return () => {}; }, dispose() {} });
  t.after(stop);
  const tabs = h.root.querySelector('#tabs').children;
  tabs[1].click();
  await settle();
  assert.ok(services, 'the custom panel mounted');
  const selected = () => tabs.filter((tab) => tab.getAttribute('aria-selected') === 'true').map((tab) => tab.textContent);
  services.showPanel('second');
  assert.deepEqual(selected(), ['Second']);
  services.showPanel('custom');
  assert.deepEqual(selected(), ['Opener'], 'a kind still opens the first panel of that kind');
  services.showPanel('packets');
  assert.deepEqual(selected(), ['Packets']);
  services.showPanel('missing');
  assert.deepEqual(selected(), ['Packets']);
});

test('the stopped page stays stopped without an Events reconnect banner after the stream drops', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const { createTransport } = await import('./transport.mjs');
  let watch, requests = 0;
  const transport = createTransport({ state: {} }, {
    location: { href: 'http://127.0.0.1:12345/' },
    storage: { getItem: () => 'token' },
    window: h.window,
    fetch: async (url) => {
      const path = new URL(url).pathname;
      if (path === '/api/page') return Response.json({ ...DESCRIPTION, hosts: [], moments: [], panels: [DESCRIPTION.panels[1]] });
      if (path === '/api/watch') {
        requests++;
        return new Response(new ReadableStream({ start(controller) { watch = controller; } }), { headers: { 'Content-Type': 'text/event-stream' } });
      }
      throw new Error(`Unexpected request: ${url}`);
    },
  });
  const stop = await mount(h.root, transport, { subscribe: () => () => {}, dispose() {} });
  await settle();
  const send = (name, data) => watch.enqueue(new TextEncoder().encode(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`));
  send('snapshot', { t: 1, ended: false, hosts: [], groups: [], nodes: [], edges: [], events: [], counters: {} });
  await settle();
  assert.equal(h.root.querySelector('#page-status').textContent, 'Running');
  send('ended', { t: 2 });
  send('end', { reason: 'the page server stopped' });
  watch.close();
  await settle();
  assert.equal(h.root.querySelector('#page-status').textContent, 'Stopped');
  assert.equal(h.root.querySelector('#run-status').dataset.state, 'stopped');
  assert.equal(h.root.querySelector('.loss-note').hidden, true);
  assert.doesNotMatch(h.root.textContent, /Connection dropped|Reconnecting/);
  assert.equal(requests, 1);
  stop();
});

test('a tab opened late shows the run time as soon as the snapshot comes', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const transport = {
    get: async (path) => (path === '/api/page' ? { ...DESCRIPTION, moments: [], panels: [DESCRIPTION.panels[2]] } : { links: [] }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  };
  const stop = await mount(h.root, transport, { subscribe: () => () => {}, dispose() {} });
  await settle();
  assert.equal(h.root.querySelector('#run-clock').textContent, '0s');
  // No clock timer runs here: the snapshot alone must set the clock.
  h.streams.find((source) => source.tag === 'watch').emit('snapshot', { t: 63.4, started: 0, ended: false, hosts: [], groups: [], nodes: [], edges: [], counters: {}, events: [] });
  assert.equal(h.root.querySelector('#page-status').textContent, 'Running');
  assert.equal(h.root.querySelector('#run-clock').textContent, '1m 3s');
  stop();
});

test('a page can open its inspector on its own panel', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const transport = {
    get: async (path) => (path === '/api/page' ? { ...DESCRIPTION, moments: [], inspector_first: 'plant' } : path.startsWith('/api/host/') ? { links: [] } : { rows: [], next: 0, dropped: 0 }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  };
  const stop = await mount(h.root, transport, { subscribe: () => () => {}, dispose() {} });
  const tabs = h.root.querySelector('#tabs').children;
  assert.deepEqual(tabs.map((tab) => tab.textContent), ['Plant', 'Rows', 'Log', 'Traffic', 'Packets', 'Events', 'Map']);
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  assert.equal(h.root.querySelector('#inspector-content').dataset.kind, 'custom');
  stop();
});

test('declared pins open both hosts without a click', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const description = { ...DESCRIPTION, hosts: DESCRIPTION.hosts.map((host) => ({ ...host, pinned: true })) };
  const transport = {
    get: async (path) => (path === '/api/page' ? description : path.startsWith('/api/host/') ? { links: [] } : { rows: [], next: 0, dropped: 0 }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  };
  const stop = await mount(h.root, transport, { subscribe: (listener) => { listener('light'); return () => {}; }, dispose() {} });
  await settle();
  assert.equal(h.root.querySelectorAll('section.workspace-tile').length, 2);
  const pins = h.root.querySelectorAll('button.pin');
  assert.ok(pins.every((pin) => pin.getAttribute('aria-pressed') === 'true'));
  pins[1].click();
  assert.equal(h.root.querySelectorAll('section.workspace-tile').length, 1);
  assert.equal(h.root.querySelector('section.workspace-tile').getAttribute('aria-label'), 'alpha');
  stop();
  assert.equal(h.budget.open, 0);
});

test('each host chip says who holds its input, from the leases topic', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const transport = {
    get: async (path) => (path === '/api/page' ? { ...DESCRIPTION, moments: [] } : path.startsWith('/api/host/') ? { links: [] } : { rows: [], next: 0, dropped: 0 }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  };
  const stop = await mount(h.root, transport, { subscribe: () => () => {}, dispose() {} });
  await settle();
  const state = h.streams.findLast((source) => source.tag === 'state' && !source.closed);
  assert.ok('leases' in state.args);
  const owners = h.root.querySelectorAll('span.host-owner');
  assert.deepEqual(owners.map((owner) => owner.dataset.owner), ['none', 'none']);
  state.emit('snapshot', { topic: 'leases', revision: 1, value: { alpha: { holder: 'another session' }, beta: { holder: null } } });
  assert.deepEqual(owners.map((owner) => [owner.textContent, owner.dataset.owner]), [['Another viewer has control', 'other'], ['', 'none']]);
  state.emit('world_error', { error: 'no such state topic: "leases"' });
  assert.equal(owners[1].textContent, 'Input control unavailable: no such state topic: "leases"');
  stop();
});

test('an app page shows its agent tabs and world panel, with a World menu and no inspector', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const description = {
    ...DESCRIPTION,
    title: 'Search',
    app: true,
    hosts: [{ name: 'alpha', sandbox: 'alpha', status: '/api/state/host-alpha', screen: '/api/screen/alpha', terminal: '/api/terminal/alpha' }],
    panels: [
      { id: 'packets', title: 'Packets', area: 'inspector', kind: 'packets' },
      { id: 'world', title: 'World', area: 'workspace', kind: 'custom', module: '/panels/world.mjs', state: '/api/state/rows' },
    ],
  };
  let mounted;
  const stop = await mount(h.root, {
    get: async (path) => (path === '/api/page' ? description : { rows: [], next: 0, dropped: 0 }),
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'),
    packetStream: (links) => h.stream('packets', links),
    close() {},
  }, { subscribe: (listener) => { listener('light'); return () => {}; }, dispose() {} }, async (url) => {
    if (url === '/panels/world.mjs') return { mount(root, services) { mounted = services.worldMenu; root.textContent = 'the world'; return () => {}; } };
    throw new TypeError('Failed to fetch dynamically imported module');
  });
  await settle();
  await settle();
  assert.ok(h.root.classList.contains('demo-app'));
  assert.equal(h.root.querySelector('#tabs'), null, 'no inspector');
  const tabs = h.root.querySelector('.app-tabs').children.filter((child) => child.getAttribute('role') === 'tab');
  assert.deepEqual(tabs.map((tab) => tab.textContent), ['Screen', 'Terminal']);
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  const screenPanel = h.root.querySelector('.app-console');
  tabs[1].click();
  assert.equal(tabs[1].getAttribute('aria-selected'), 'true');
  assert.equal(h.root.querySelector('.app-stage').dataset.kind, 'terminal');
  const terminalPanel = h.root.querySelectorAll('.app-console')[1];
  assert.equal(screenPanel.hidden, true);
  assert.equal(screenPanel.inert, true);
  tabs[0].click();
  assert.equal(h.root.querySelector('.app-console'), screenPanel);
  assert.equal(screenPanel.hidden, false);
  assert.equal(terminalPanel.hidden, true);
  assert.equal(terminalPanel.inert, true);
  tabs[1].click();
  assert.equal(h.root.querySelectorAll('.app-console')[1], terminalPanel);
  assert.match(h.root.textContent, /the world/);
  const world = h.root.querySelector('.app-world');
  const worldTabs = world.querySelector('.app-tabs');
  assert.equal(worldTabs.parentNode, world);
  assert.equal(world.children[0], worldTabs);
  assert.deepEqual(worldTabs.children.map((tab) => tab.textContent), ['World', 'Packets']);
  assert.equal(world.querySelector('#app-world-panel').hidden, false);
  assert.equal(world.querySelector('#app-packets-panel').hidden, true);
  const menu = h.root.querySelector('#world-menu');
  assert.equal(mounted, menu.querySelector('.app-world-controls'), 'the world panel fills its own controls');
  const button = h.root.querySelector('.app-menu-button');
  assert.equal(menu.hidden, true);
  button.click();
  assert.equal(menu.hidden, false);
  assert.equal(button.getAttribute('aria-expanded'), 'true');
  const escape = new Event('keydown'); escape.key = 'Escape'; h.document.dispatchEvent(escape);
  assert.equal(menu.hidden, true);
  const watch = h.streams.find((source) => source.tag === 'watch');
  watch.emit('snapshot', { t: 1, started: 0, ended: false, hosts: [], groups: [], nodes: [], edges: [], counters: {}, events: [] });
  await settle();
  assert.equal(h.root.querySelector('.app-live').textContent, 'Booting');
  assert.equal(h.root.querySelector('.app-live').dataset.live, 'false');
  const state = h.streams.findLast((source) => source.tag === 'state' && !source.closed);
  for (const [revision, readiness] of ['booting', 'network_up', 'ssh_up'].entries()) {
    state.emit('snapshot', { topic: 'host-alpha', revision: revision + 1, value: { state: readiness } });
    assert.equal(h.root.querySelector('.app-live').textContent, 'Booting');
    assert.equal(h.root.querySelector('.app-live').dataset.live, 'false');
  }
  state.emit('snapshot', { topic: 'host-alpha', revision: 4, value: { state: 'desktop_up', screen: true, terminal: true } });
  assert.equal(h.root.querySelector('.app-live').textContent, 'Live');
  assert.equal(h.root.querySelector('.app-live').dataset.live, 'true');
  stop();
  assert.equal(h.budget.open, 0);
  assert.equal(h.document.listenerCount, 0);
});

test('world tabs keep the custom view mounted and bound traffic to the visible packets tab', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const description = {
    title: 'Border', app: true, hosts: [DESCRIPTION.hosts[0]],
    panels: [{ id: 'world', title: 'World', area: 'workspace', kind: 'custom', module: '/panels/world.mjs', state: '/api/state/rows' }],
  };
  let mounts = 0, releases = 0;
  const stop = await mount(h.root, {
    get: async (path) => path === '/api/page' ? description : { links: ['guest-link'] },
    stateStream: (topics) => h.stream('state', { ...topics }),
    watch: () => h.stream('watch'), packetStream: (links) => h.stream('packets', links), close() {},
  }, { dispose() {} }, async () => ({ mount(root, services) {
    mounts++;
    const { el } = services.dom.scoped(root);
    el('svg:svg', { 'aria-label': 'Route picture' }, root);
    const list = el('div', { role: 'list', text: 'Route activity' }, root);
    const off = services.state('/api/state/rows', ({ value }) => { list.textContent = value.activity; });
    return () => { releases++; off(); };
  } }));
  t.after(stop);
  await settle();
  const worldTabs = h.root.querySelector('.app-world').querySelector('.app-tabs');
  const tabs = worldTabs.querySelectorAll('button');
  assert.deepEqual(tabs.map((tab) => tab.textContent), ['World', 'Packets']);
  assert.equal(mounts, 1);
  assert.equal(h.streams.filter((s) => s.tag === 'packets').length, 0);
  const packetPanel = h.root.querySelector('#app-packets-panel');
  const ownPanel = h.root.querySelector('#app-world-panel');
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  assert.equal(tabs[1].getAttribute('tabindex'), '-1');
  assert.equal(packetPanel.hidden, true);
  assert.equal(ownPanel.hidden, false);
  assert.match(ownPanel.textContent, /Route activity/);
  for (const tab of tabs) {
    const panel = h.root.querySelector(`#${tab.getAttribute('aria-controls')}`);
    assert.equal(panel.getAttribute('role'), 'tabpanel');
    assert.equal(panel.getAttribute('aria-labelledby'), tab.id);
  }
  h.streams.find((s) => s.tag === 'watch').emit('snapshot', {
    t: 1, ended: false, hosts: [], groups: [], events: [], counters: {},
    nodes: [{ id: 'guest', kind: 'sandbox', name: 'alpha' }], edges: [{ id: 'guest-link', a: 'guest', b: 'network' }],
  });
  await settle();
  assert.equal(h.streams.filter((s) => s.tag === 'packets').length, 0);
  const baseFrames = h.frames.size;
  tabs[1].click();
  await settle();
  assert.equal(packetPanel.hidden, false);
  assert.equal(ownPanel.hidden, true);
  assert.equal(tabs[0].getAttribute('tabindex'), '-1');
  assert.equal(tabs[1].getAttribute('tabindex'), '0');
  const state = h.streams.findLast((s) => s.tag === 'state' && !s.closed);
  const frame = () => {
    const callbacks = [...h.frames.values()]; h.frames.clear(); callbacks.forEach((fn) => fn(performance.now()));
  };
  frame();
  assert.ok(packetPanel.querySelector('#graph'));
  assert.equal(packetPanel.querySelector('#prows'), null);
  tabs[1].click();
  assert.equal(packetPanel.querySelectorAll('#graph').length, 1);
  tabs[0].click();
  assert.equal(ownPanel.hidden, false);
  assert.equal(packetPanel.hidden, true);
  assert.equal(h.frames.size, baseFrames);
  const key = (name, index) => {
    const event = new Event('keydown', { cancelable: true }); event.key = name;
    worldTabs.dispatchEvent(event);
    assert.equal(event.defaultPrevented, true);
    assert.equal(h.document.activeElement, tabs[index]);
    assert.deepEqual(tabs.map((tab) => tab.getAttribute('tabindex')), index === 0 ? ['0', '-1'] : ['-1', '0']);
    assert.deepEqual(tabs.map((tab) => tab.getAttribute('aria-selected')), index === 0 ? ['true', 'false'] : ['false', 'true']);
  };
  key('ArrowRight', 1);
  state.emit('snapshot', { topic: 'rows', revision: 1, value: { activity: 'Current route' } });
  key('ArrowRight', 0);
  key('ArrowLeft', 1);
  key('ArrowLeft', 0);
  key('End', 1);
  key('Home', 0);
  assert.equal(mounts, 1);
  assert.equal(releases, 0);
  assert.match(ownPanel.textContent, /Current route/);
  assert.equal(ownPanel.querySelector('svg').getAttribute('aria-label'), 'Route picture');
  key('End', 1);
  await settle();
  assert.equal(ownPanel.hidden, true);
  frame();
  assert.equal(packetPanel.querySelectorAll('#graph').length, 1);
  const graph = packetPanel.querySelector('#graph');
  h.document.hidden = true; h.document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(h.frames.size, baseFrames);
  h.document.hidden = false; h.document.dispatchEvent(new Event('visibilitychange'));
  frame();
  assert.ok(packetPanel.querySelector('#graph'));
  assert.notEqual(packetPanel.querySelector('#graph'), graph);
  key('Home', 0);
  assert.equal(h.frames.size, baseFrames);
  key('End', 1);
  frame();
  stop();
  assert.equal(mounts, 1);
  assert.equal(releases, 1);
  assert.ok(tabs.every((tab) => tab.listenerCount === 0));
  assert.equal(worldTabs.listenerCount, 0);
  assert.ok(h.streams.every((stream) => stream.closed && stream.listenerCount === 0));
  assert.equal(h.budget.open, 0);
  assert.equal(h.frames.size, 0);
  assert.equal(h.document.listenerCount, 0);
});

test('an app without a custom workspace starts with only Packets', async (t) => {
  const h = harness(t);
  const { mount } = await import('./page.mjs');
  const stop = await mount(h.root, {
    get: async (path) => path === '/api/page' ? { title: 'Network', app: true, hosts: [], panels: [] } : { links: [] },
    watch: () => h.stream('watch'), packetStream: (links) => h.stream('packets', links), close() {},
  }, { dispose() {} });
  const world = h.root.querySelector('.app-world');
  const tabs = world.querySelector('.app-tabs').children;
  assert.deepEqual(tabs.map((tab) => tab.textContent), ['Packets']);
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  assert.equal(tabs[0].getAttribute('tabindex'), '0');
  assert.equal(world.querySelector('#app-world-panel'), null);
  assert.equal(world.querySelector('#app-packets-panel').hidden, false);
  stop();
  assert.equal(h.budget.open, 0);
  assert.equal(h.document.listenerCount, 0);
});

test('an app can show sign out after replacing the inspector shell', (t) => {
  const h = harness(t);
  const services = createServices({ watch: () => h.stream('watch') }, {});
  const stop = appShell(h.root, services, { ...DESCRIPTION, hosts: [], panels: [] });
  assert.equal(h.root.querySelector('#notice'), null);
  showNotice(h.root, 'Not signed in', 'Open the page again.');
  assert.equal(h.root.dataset.state, 'notice');
  assert.equal(h.root.querySelector('.app-body').hidden, true);
  assert.equal(h.root.querySelector('#notice-title').textContent, 'Not signed in');
  assert.equal(h.root.querySelector('#notice-text').textContent, 'Open the page again.');
  assert.equal(h.root.querySelector('#notice-action').hidden, true);
  showNotice(h.root, 'Connection lost', 'Reload the page.', true);
  assert.equal(h.root.querySelectorAll('#notice').length, 1);
  assert.equal(h.root.querySelector('#notice-action').hidden, false);
  stop(); services.dispose();
});

test('the agent stage edge has three to one contrast against the page in both schemes', () => {
  const css = readFileSync(new URL('./page.css', import.meta.url), 'utf8');
  const pair = (name) => css.match(new RegExp(`--${name}: light-dark\\((#[0-9a-f]{6}), (#[0-9a-f]{6})\\)`)).slice(1);
  const luminance = (hex) => {
    const channels = hex.slice(1).match(/../g).map((value) => parseInt(value, 16) / 255)
      .map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  };
  const background = pair('app-bg'), edge = pair('app-stage-edge');
  for (let i = 0; i < 2; i++) {
    const values = [luminance(background[i]), luminance(edge[i])].sort((a, b) => a - b);
    assert.ok((values[1] + 0.05) / (values[0] + 0.05) >= 3);
  }
});
