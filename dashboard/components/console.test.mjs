import test from 'node:test';
import assert from 'node:assert/strict';
import { mount as screen } from './screen.mjs';
import { mount as terminal } from './terminal.mjs';
import { createDocument, Element } from '../test-dom.mjs';
import { createTransport } from '../transport.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

function fixture() {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const subscriptions = new Map(), timers = new Map(), sockets = [], requests = [], rfbs = [], terminals = [], observers = [], themes = new Set();
  let status = { state: 'booting', screen: false, terminal: false }, holder = null;
  class Socket extends Element {
    constructor() { super('socket'); this.readyState = 0; this.sent = []; }
    send(data) { this.sent.push(data); }
    close() {
      if (this.readyState === 3) return;
      this.readyState = 3;
      this.dispatchEvent(new Event('close'));
    }
    open() { this.readyState = 1; this.dispatchEvent(new Event('open')); }
    receive(data) { const event = new Event('message'); event.data = data; this.dispatchEvent(event); }
  }
  class RFB extends Element {
    constructor(display, socket) { super('rfb'); this.socket = socket; rfbs.push(this); }
    disconnect() { this.disposed = true; this.disconnects = (this.disconnects || 0) + 1; }
  }
  class Terminal {
    constructor(options) { this.options = options; this.writes = []; this.inputs = new Set(); this.cols = 80; this.rows = 24; terminals.push(this); }
    loadAddon(addon) { this.addon = addon; }
    open(display) { display.clientWidth = 800; display.clientHeight = 600; }
    onData(callback) { this.data = callback; this.inputs.add(callback); return { dispose: () => this.inputs.delete(callback) }; }
    onBinary(callback) { this.binary = callback; this.inputs.add(callback); return { dispose: () => this.inputs.delete(callback) }; }
    write(bytes, callback) { this.writes.push({ bytes, callback }); }
    dispose() { this.disposed = true; this.addon.dispose(); }
  }
  class FitAddon { fit() { this.fitted = true; } dispose() { this.disposed = true; } }
  class ResizeObserver {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe() {}
    disconnect() { this.disposed = true; }
  }
  const services = {
    setTimeout(callback, delay) { const id = Symbol(); timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    state(path, callback, error) {
      subscriptions.set(path, { callback, error });
      callback({ value: path.endsWith('/leases') ? { alpha: { holder } } : status });
      return () => subscriptions.delete(path);
    },
    theme: { subscribe(callback) { themes.add(callback); callback('light'); return () => themes.delete(callback); } },
    transport: {
      ...createTransport({}, {
        location: { href: 'http://127.0.0.1:7878/' }, storage: { getItem: () => 'secret' },
        async fetch(url, options) {
          assert.equal(options.headers.Authorization, 'Bearer secret');
          requests.push({ method: options.method, path: new URL(url).pathname, body: JSON.parse(options.body) });
          return Response.json({ holder: options.method === 'POST' ? 'ours' : null });
        },
      }),
      async socket(capability, host) { const socket = new Socket(); sockets.push(socket); requests.push({ capability, host }); return { socket, session: 'ours' }; },
    },
  };
  return {
    root, services, subscriptions, timers, sockets, requests, rfbs, terminals, observers, themes,
    screenOptions: { host: 'alpha', load: async () => ({ default: RFB }) },
    terminalOptions: { host: 'alpha', load: async () => [{ Terminal }, { FitAddon }], ResizeObserver, getComputedStyle: () => ({ backgroundColor: 'rgb(233, 237, 223)', color: 'rgb(38, 62, 53)' }) },
    publish(value) { status = value; subscriptions.get('/api/state/host-alpha')?.callback({ value }); },
    lease(value) { holder = value; subscriptions.get('/api/state/leases')?.callback({ value: { alpha: { holder } } }); },
  };
}

test('screen stays unavailable while booting, watches by default and follows the live lease', async () => {
  const h = fixture(), ownership = [];
  const dispose = screen(h.root, h.services, { ...h.screenOptions, onOwnership: (text) => ownership.push(text) });
  await settle();
  assert.equal(h.sockets.length, 0);
  assert.match(h.root.textContent, /alpha is booting/);
  h.publish({ state: 'desktop_up', screen: true });
  await settle();
  const rfb = h.rfbs[0];
  assert.equal(rfb.viewOnly, true);
  assert.equal(rfb.scaleViewport, true);
  assert.equal(rfb.resizeSession, false);
  // The letterbox is the panel's own surface.
  assert.equal(rfb.background, 'transparent');
  const claim = h.root.querySelector('button');
  assert.equal(claim.hidden, true, 'take over waits for the screen to connect');
  rfb.dispatchEvent(new Event('connect'));
  assert.equal(claim.hidden, false);
  assert.equal(claim.disabled, false);
  claim.click();
  await settle();
  assert.deepEqual(h.requests.at(-1), { method: 'POST', path: '/api/lease', body: { host: 'alpha', session: 'ours', take: true } });
  assert.equal(rfb.viewOnly, true);
  h.lease('ours');
  assert.equal(rfb.viewOnly, false);
  assert.equal(claim.textContent, 'Release');
  assert.equal(ownership.at(-1), 'You have control');
  h.lease('another');
  assert.equal(rfb.viewOnly, true);
  assert.equal(ownership.at(-1), 'Another viewer has control');
  assert.match(h.root.textContent, /Another viewer took control/);
  const notice = [...h.timers.values()].find((timer) => timer.delay === 4000);
  assert.ok(notice, 'the lost-control notice clears itself');
  notice.callback();
  assert.match(h.root.textContent, /Another viewer has control/);
  h.lease('ours');
  claim.click();
  await settle();
  assert.equal(h.requests.at(-1).method, 'DELETE');
  assert.equal(rfb.viewOnly, true);
  h.lease(null);
  dispose();
  dispose();
  assert.equal(h.subscriptions.size + h.timers.size, 0);
  assert.equal(h.sockets[0].readyState, 3);
  assert.equal(rfb.disposed, true);
  assert.equal(rfb.listenerCount + h.sockets[0].listenerCount + claim.listenerCount, 0);
  assert.equal(h.root.children.length, 0);
});

test('screen reconnects with backoff and disposal cancels a scheduled reconnect', async () => {
  const h = fixture();
  h.publish({ screen: true });
  const dispose = screen(h.root, h.services, h.screenOptions);
  await settle();
  h.sockets[0].close();
  assert.match(h.root.textContent, /Connection lost\. Reconnecting in 4 s/);
  assert.equal([...h.timers.values()][0].delay, 4000);
  const reconnect = h.root.querySelectorAll('button')[1];
  reconnect.click();
  await settle();
  assert.equal(h.timers.size, 0);
  assert.equal(h.sockets.length, 2);
  h.sockets[1].close();
  assert.equal([...h.timers.values()][0].delay, 8000);
  dispose();
  assert.equal(h.timers.size, 0);
  assert.ok(h.rfbs.every((rfb) => rfb.disposed && !rfb.listenerCount));
  assert.ok(h.sockets.every((socket) => !socket.listenerCount));
  assert.equal(reconnect.listenerCount, 0);
});

test('a screen noVNC already disconnected is not disconnected again', async () => {
  const h = fixture();
  h.publish({ screen: true });
  const dispose = screen(h.root, h.services, h.screenOptions);
  await settle();
  const rfb = h.rfbs[0];
  rfb.dispatchEvent(new Event('connect'));
  rfb.dispatchEvent(new Event('disconnect'));
  assert.equal(rfb.disconnects, undefined);
  assert.match(h.root.textContent, /Connection lost\. Reconnecting in 4 s/);
  assert.equal(h.root.querySelector('button').hidden, true, 'no take over while disconnected');
  dispose();
  assert.equal(rfb.disconnects, undefined);
  assert.equal(h.timers.size, 0);
});

test('terminal acknowledges only consumed output and releases its socket, addon and observer', async () => {
  const h = fixture();
  h.publish({ terminal: true });
  const dispose = terminal(h.root, h.services, h.terminalOptions);
  await settle();
  const socket = h.sockets[0], term = h.terminals[0];
  assert.equal(term.options.scrollback, 5000);
  socket.open();
  assert.deepEqual(JSON.parse(socket.sent[0]), { type: 'resize', cols: 80, rows: 24 });
  term.cols = 100;
  h.observers[0].callback();
  assert.equal(JSON.parse(socket.sent.at(-1)).cols, 100);
  const bytes = new Uint8Array([0x61, 0xc3, 0xa9]);
  socket.receive(bytes.buffer);
  assert.equal(socket.sent.length, 2);
  assert.deepEqual(term.writes[0].bytes, bytes);
  term.writes[0].callback();
  assert.deepEqual(JSON.parse(socket.sent.at(-1)), { type: 'ack', bytes: 3 });
  term.data('é');
  assert.deepEqual(socket.sent.at(-1), new TextEncoder().encode('é'));
  term.binary('\xff');
  assert.deepEqual(socket.sent.at(-1), new Uint8Array([255]));
  socket.receive(new Uint8Array([1, 2]).buffer);
  const sent = socket.sent.length;
  const button = h.root.querySelector('button');
  dispose();
  term.writes[1].callback();
  assert.equal(socket.sent.length, sent);
  assert.equal(socket.readyState, 3);
  assert.equal(socket.listenerCount + button.listenerCount, 0);
  assert.equal(h.subscriptions.size + h.themes.size, 0);
  assert.equal(term.inputs.size, 0);
  assert.equal(term.disposed, true);
  assert.equal(term.addon.disposed, true);
  assert.equal(h.observers[0].disposed, true);
  assert.equal(h.root.children.length, 0);
});

test('terminal waits for SSH, reports a disconnect and reconnects only on request', async () => {
  const h = fixture();
  const dispose = terminal(h.root, h.services, h.terminalOptions);
  await settle();
  assert.match(h.root.textContent, /terminal opens when SSH is up/);
  assert.equal(h.sockets.length, 0);
  h.publish({ terminal: true });
  await settle();
  h.sockets[0].close();
  assert.match(h.root.textContent, /Disconnected\./);
  const reconnect = h.root.querySelector('button');
  assert.equal(reconnect.textContent, 'Reconnect');
  assert.equal(reconnect.hidden, false);
  assert.equal(h.timers.size, 0);
  reconnect.click();
  await settle();
  assert.equal(h.sockets.length, 2);
  h.publish({ state: 'stopped', terminal: false });
  assert.equal(h.sockets[1].readyState, 3);
  dispose();
});

test('console disposal handles imports and socket requests that finish late', async () => {
  for (const kind of ['screen', 'terminal']) {
    const mount = kind === 'screen' ? screen : terminal;
    const h = fixture();
    h.publish({ screen: true, terminal: true });
    let finish;
    const options = h[`${kind}Options`];
    const dispose = mount(h.root, h.services, { ...options, load: () => new Promise((resolve) => { finish = resolve; }) });
    dispose();
    finish(await options.load());
    await settle();
    assert.equal(h.sockets.length, 0);
    assert.equal(h.root.children.length, 0);
    assert.equal(h.subscriptions.size + h.themes.size, 0);

    const original = h.services.transport.socket;
    h.services.transport.socket = () => new Promise((resolve) => { finish = resolve; });
    const disposeAgain = mount(h.root, h.services, options);
    await settle();
    disposeAgain();
    const result = await original(kind, 'alpha');
    finish(result);
    await settle();
    assert.equal(result.socket.readyState, 3);
    assert.equal(h.rfbs.length + h.terminals.length, 0);
  }
});

test('missing libraries fail inside their own panel with the asset command', async () => {
  for (const [mount, library] of [[screen, 'noVNC'], [terminal, 'xterm.js']]) {
    const h = fixture();
    const dispose = mount(h.root, h.services, { host: 'alpha', load: async () => { throw new Error(library); } });
    await settle();
    assert.ok(h.root.textContent.includes(`${library} is not in this build.`));
    assert.match(h.root.textContent, /cargo xtask demo assets/);
    assert.equal(h.sockets.length, 0);
    dispose();
  }
});
