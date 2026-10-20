import test from 'node:test';
import assert from 'node:assert/strict';
import { createServices, divider } from './page.mjs';
import { createStateHub, createWatchHub } from './streams.mjs';
import { createDocument, Element } from './test-dom.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

class Source extends Element {
  constructor(kind, args) { super(kind); this.args = args; }
  emit(name, value) { const event = new Event(name); event.data = JSON.stringify(value); this.dispatchEvent(event); }
  close() { this.closed = true; }
}

test('every state topic shares one stream, reopened with cursors when the topics change', async () => {
  const streams = [], requests = [];
  const services = createServices({
    stateStream(topics) { const source = new Source('state', { ...topics }); streams.push(source); return source; },
    get(path, _, signal) { return new Promise((resolve) => requests.push({ path, signal, resolve })); },
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
  // A delta is the author's: the hub fetches the replacement snapshot.
  streams[0].emit('delta', { topic: 'exchanges', revision: 2, delta: { custom: 'operation' } });
  streams[0].emit('delta', { topic: 'exchanges', revision: 3, delta: 'another' });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, '/api/state/exchanges');
  streams[0].emit('snapshot', { topic: 'exchanges', revision: 4, value: [4] });
  requests[0].resolve({ revision: 2, value: [2] });
  await settle();
  assert.equal(requests.length, 2);
  requests[1].resolve({ revision: 4, value: [4], status: { too_large: true } });
  await settle();
  assert.deepEqual(values.map((snapshot) => snapshot.revision), [1, 4, 4]);
  assert.deepEqual(other, values);
  // A dropped connection reconnects on its own: it fails nothing, and what
  // arrives after the reconnect is delivered.
  streams[0].emit('error', { error: 'Connection dropped. Reconnecting.' });
  assert.equal(errors.length, 0);
  streams[0].emit('snapshot', { topic: 'host-alpha', revision: 4, value: { state: 'ssh_up' } });
  assert.deepEqual(hosts.map((snapshot) => snapshot.value.state), ['booting', 'ssh_up']);
  // A refusal ends the stream, and every topic on it hears why.
  streams[0].emit('world_error', { error: 'too many streams' });
  assert.match(errors[0].message, /too many streams/);
  // Dropping a topic reopens the stream for the rest, with what is held.
  stopHost();
  await settle();
  assert.equal(streams[0].closed, true);
  assert.equal(streams[0].listenerCount, 0);
  assert.deepEqual(streams[1].args, { exchanges: 4 });
  // A topic another listener still holds keeps the stream open.
  stop();
  await settle();
  assert.equal(streams.length, 2);
  assert.equal(streams[1].closed, undefined);
  stopOther();
  await settle();
  assert.equal(streams[1].closed, true);
  assert.equal(streams[1].listenerCount, 0);
  assert.equal(streams.length, 2, 'no stream while nothing listens');
  assert.ok(requests.every((request) => request.signal.aborted));
  services.dispose();
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
  for (const tab of [...tabs, ...tabs]) {
    tab.click();
    await settle();
    watch.emit('counters', { t: 2, edges: {} });
    await settle();
  }
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
  assert.match(h.root.querySelector('#notice-text').textContent, /Open the URL the demo printed/);
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
    open(display) { this.input = h.document.createElement('textarea'); display.append(this.input); }
    focus() { this.input.focus(); }
    onData() { return { dispose() {} }; }
    onBinary() { return { dispose() {} }; }
    dispose() {}
  }
  class FitAddon { fit() {} }
  class ResizeObserver { observe() {} disconnect() {} }
  for (const initial of ['screen', 'terminal']) {
    const description = {
      title: 'Fixture',
      hosts: [{ name: 'alpha', status: '/api/state/host-alpha', screen: initial === 'screen', terminal: true }],
      panels: [{ kind: 'terminal', host: 'alpha', load: async () => [{ Terminal }, { FitAddon }], ResizeObserver, getComputedStyle: () => ({}) }],
    };
    const stop = await mount(h.root, {
      get: async () => description,
      stateStream: (topics) => h.stream('state', { ...topics }),
      watch: () => h.stream('watch'),
      async socket() { const socket = new Source('socket'); socket.readyState = 0; sockets.push(socket); return { socket }; },
      close() {},
    }, { subscribe: () => () => {}, dispose() {} });
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
