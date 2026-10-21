import test from 'node:test';
import assert from 'node:assert/strict';
import { mount as screen } from './screen.mjs';
import { mount as terminal } from './terminal.mjs';
import { createServices } from '../page.mjs';
import { createDocument, Element, fakeTimers } from '../test-dom.mjs';
import { createTransport } from '../transport.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

// The terminal fits itself with the browser's ResizeObserver and reads its
// colors with getComputedStyle; Node has neither.
let observers;
globalThis.ResizeObserver = class {
  constructor(callback) { this.callback = callback; observers.push(this); }
  observe() {}
  disconnect() { this.disposed = true; }
};
globalThis.getComputedStyle = () => ({ backgroundColor: 'rgb(233, 237, 223)', color: 'rgb(38, 62, 53)' });

function fixture(t) {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  observers = [];
  const timers = fakeTimers(t);
  const subscriptions = new Map(), sockets = [], requests = [], rfbs = [], terminals = [], themes = new Set();
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
    focus() { this.focuses = (this.focuses || 0) + 1; }
    onData(callback) { this.data = callback; this.inputs.add(callback); return { dispose: () => this.inputs.delete(callback) }; }
    onBinary(callback) { this.binary = callback; this.inputs.add(callback); return { dispose: () => this.inputs.delete(callback) }; }
    write(bytes, callback) { this.writes.push({ bytes, callback }); }
    dispose() { this.disposed = true; this.addon.dispose(); }
  }
  class FitAddon { fit() { this.fitted = true; } dispose() { this.disposed = true; } }
  const modules = {
    '/vendor/novnc/core/rfb.js': { default: RFB },
    '/vendor/ghostty-web/dist/ghostty-web.js': { Terminal, FitAddon, async init() {} },
  };
  const transport = {
    ...createTransport({}, {
      location: { href: 'http://127.0.0.1:7878/' }, storage: { getItem: () => 'secret' },
      async fetch(url, options) {
        assert.equal(options.headers.Authorization, 'Bearer secret');
        requests.push({ method: options.method, path: new URL(url).pathname, body: JSON.parse(options.body) });
        return Response.json({ holder: options.method === 'POST' ? 'ours' : null });
      },
    }),
    async socket(capability, host) { const socket = new Socket(); sockets.push(socket); requests.push({ capability, host }); return { socket, session: 'ours' }; },
  };
  const theme = { subscribe(callback) { themes.add(callback); callback('light'); return () => themes.delete(callback); } };
  const services = createServices(transport, theme, async (url) => {
    if (!modules[url]) throw new TypeError('Failed to fetch dynamically imported module');
    return modules[url];
  });
  // Each host's status and the input leases, as the state stream sends them.
  services.state = (path, callback, error) => {
    subscriptions.set(path, { callback, error });
    callback({ value: path.endsWith('/leases') ? { alpha: { holder } } : status });
    return () => subscriptions.delete(path);
  };
  return {
    root, services, subscriptions, timers, sockets, requests, rfbs, terminals, observers, themes,
    screenOptions: { host: 'alpha' },
    terminalOptions: { host: 'alpha' },
    publish(value) { status = value; subscriptions.get('/api/state/host-alpha')?.callback({ value }); },
    lease(value) { holder = value; subscriptions.get('/api/state/leases')?.callback({ value: { alpha: { holder } } }); },
  };
}

test('console cards follow each host state', async (t) => {
  for (const [kind, mount] of [['screen', screen], ['terminal', terminal]]) {
    const h = fixture(t);
    const dispose = mount(h.root, h.services, h[`${kind}Options`]);
    await settle();
    const message = h.root.querySelector('p'), card = message.parent;
    for (const state of ['booting', 'network_up', 'ssh_up', 'desktop_up', 'stopped']) {
      h.publish({ state, screen: state === 'desktop_up', terminal: state === 'ssh_up' || state === 'desktop_up' });
      await settle();
      if (state === 'stopped') {
        assert.equal(message.textContent, 'alpha has stopped.');
      } else if (state === 'booting') {
        assert.equal(message.textContent, kind === 'screen'
          ? 'alpha is booting. The screen opens when its desktop is up.'
          : 'alpha is booting. The terminal opens when SSH is up.');
      } else if (kind === 'screen' && state !== 'desktop_up') {
        assert.equal(message.textContent, 'alpha is up. The screen opens when its desktop is ready.');
      } else if (kind === 'terminal' && state === 'network_up') {
        assert.equal(message.textContent, 'alpha is on the network. The terminal opens when SSH is up.');
      } else {
        assert.equal(message.textContent, `Connecting to the ${kind}…`);
        if (kind === 'screen') h.rfbs.at(-1).dispatchEvent(new Event('connect'));
        else h.sockets.at(-1).open();
        assert.equal(card.hidden, true);
        continue;
      }
      assert.equal(card.hidden, false);
      assert.ok(h.sockets.every((socket) => socket.readyState === 3));
    }
    dispose();
  }
});

test('terminal focuses once on request and never on a later status change or reconnect', async (t) => {
  for (const focus of [false, true]) {
    const h = fixture(t);
    h.publish({ state: 'ssh_up', terminal: true });
    const dispose = terminal(h.root, h.services, { ...h.terminalOptions, focus });
    await settle();
    assert.equal(h.terminals[0].focuses, undefined);
    h.sockets[0].open();
    assert.equal(h.terminals[0].focuses || 0, Number(focus));
    h.publish({ state: 'desktop_up', terminal: true });
    assert.equal(h.terminals[0].focuses || 0, Number(focus));
    h.sockets[0].close();
    h.root.querySelector('button').click();
    await settle();
    h.sockets[1].open();
    assert.equal(h.terminals[1].focuses, undefined);
    h.publish({ state: 'stopped', terminal: false });
    h.publish({ state: 'ssh_up', terminal: true });
    await settle();
    h.sockets[2].open();
    assert.equal(h.terminals[2].focuses, undefined);
    dispose();
  }
  const h = fixture(t);
  const dispose = terminal(h.root, h.services, { ...h.terminalOptions, focus: true });
  await settle();
  h.publish({ state: 'ssh_up', terminal: true });
  await settle();
  h.sockets[0].open();
  assert.equal(h.terminals[0].focuses, undefined);
  dispose();
});

test('screen stays unavailable while booting, watches by default and follows the live lease', async (t) => {
  const h = fixture(t);
  const dispose = screen(h.root, h.services, h.screenOptions);
  const owner = h.root.querySelector('span.console-owner');
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
  assert.equal(owner.textContent, 'You have control');
  assert.equal(owner.dataset.owner, 'mine');
  h.lease('another');
  assert.equal(rfb.viewOnly, true);
  assert.equal(owner.dataset.owner, 'other');
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

test('screen reconnects with backoff and disposal cancels a scheduled reconnect', async (t) => {
  const h = fixture(t);
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

test('a screen noVNC already disconnected is not disconnected again', async (t) => {
  const h = fixture(t);
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

test('terminal acknowledges only consumed output and releases its socket, addon and observer', async (t) => {
  const h = fixture(t);
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

test('terminal waits for SSH, reports a disconnect and reconnects only on request', async (t) => {
  const h = fixture(t);
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

test('console disposal handles imports and socket requests that finish late', async (t) => {
  for (const kind of ['screen', 'terminal']) {
    const mount = kind === 'screen' ? screen : terminal;
    const h = fixture(t);
    h.publish({ screen: true, terminal: true });
    const load = h.services.importModule, late = [];
    h.services.importModule = (url) => new Promise((resolve) => late.push(() => resolve(load(url))));
    const options = h[`${kind}Options`];
    const dispose = mount(h.root, h.services, options);
    dispose();
    late.forEach((finish) => finish());
    await settle();
    assert.equal(h.sockets.length, 0);
    assert.equal(h.root.children.length, 0);
    assert.equal(h.subscriptions.size + h.themes.size, 0);

    h.services.importModule = load;
    let finish;
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

test('missing libraries fail inside their own panel with the asset command', async (t) => {
  for (const [mount, library] of [[screen, 'noVNC'], [terminal, 'ghostty-web']]) {
    const h = fixture(t);
    h.services.importModule = async () => { throw new TypeError('Failed to fetch dynamically imported module'); };
    const dispose = mount(h.root, h.services, { host: 'alpha' });
    await settle();
    assert.ok(h.root.textContent.includes(`${library} is not in this build.`));
    assert.match(h.root.textContent, /cargo xtask demo libraries/);
    assert.equal(h.sockets.length, 0);
    dispose();
  }
});

test('after the run stopped, consoles say they closed instead of blaming the build or the network', async (t) => {
  for (const [mount, closed] of [[screen, 'The screen closed when the run stopped.'], [terminal, 'The terminal closed when the run stopped.']]) {
    // The page server is gone, so the library cannot load.
    const h = fixture(t);
    h.services.run.set('stopped');
    h.services.importModule = async () => { throw new TypeError('Failed to fetch dynamically imported module'); };
    const dispose = mount(h.root, h.services, { host: 'alpha' });
    await settle();
    assert.ok(h.root.textContent.includes(closed), h.root.textContent);
    assert.doesNotMatch(h.root.textContent, /not in this build/);
    dispose();
    // A console that loses its connection after the run stopped does not try again.
    const live = fixture(t);
    live.publish({ state: 'desktop_up', screen: true, terminal: true });
    const stop = mount(live.root, live.services, mount === screen ? live.screenOptions : live.terminalOptions);
    await settle();
    live.services.run.set('stopped');
    live.sockets[0].close();
    await settle();
    assert.ok(live.root.textContent.includes(closed), live.root.textContent);
    assert.equal([...live.timers.values()].filter((timer) => timer.delay >= 1000).length, 0, 'no reconnect is scheduled');
    stop();
  }
});

test('an interactive screen takes free input on connect and fits the guest display to the panel', async (t) => {
  const h = fixture(t);
  const controls = h.root.ownerDocument.createElement('div');
  const dispose = screen(h.root, h.services, { ...h.screenOptions, interactive: true, controls });
  h.publish({ state: 'desktop_up', screen: true });
  await settle();
  const rfb = h.rfbs[0];
  rfb.dispatchEvent(new Event('connect'));
  await settle();
  assert.deepEqual(h.requests.at(-1), { method: 'POST', path: '/api/lease', body: { host: 'alpha', session: 'ours', take: false } });
  h.lease('ours');
  assert.equal(rfb.viewOnly, false);
  assert.equal(rfb.resizeSession, true);
  const claim = controls.querySelector('button');
  assert.equal(claim.hidden, true, 'the app needs no take over button while it holds input');
  assert.equal(controls.querySelector('span.console-owner').textContent, '');
  // Another viewer's input shows, with the way to take it back.
  h.lease('another');
  assert.equal(rfb.viewOnly, true);
  assert.equal(rfb.resizeSession, false);
  assert.equal(claim.hidden, false);
  dispose();
});

test('an interactive terminal starts large and its text size buttons resize it', async (t) => {
  const h = fixture(t);
  const controls = h.root.ownerDocument.createElement('div');
  const stored = new Map();
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: (k) => stored.get(k) ?? null, setItem: (k, v) => stored.set(k, v) } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'localStorage', previous); else delete globalThis.localStorage; });
  const dispose = terminal(h.root, h.services, { ...h.terminalOptions, interactive: true, controls });
  h.publish({ state: 'ssh_up', screen: false, terminal: true });
  await settle();
  h.sockets[0].open();
  const term = h.terminals[0];
  assert.equal(term.options.fontSize, 18);
  const [smaller, larger] = controls.querySelectorAll('button');
  assert.deepEqual([smaller.textContent, larger.textContent], ['A−', 'A+']);
  larger.click();
  larger.click();
  assert.equal(term.options.fontSize, 22);
  assert.equal(stored.get('fictionet-terminal-size'), '22');
  smaller.click();
  assert.equal(term.options.fontSize, 20);
  dispose();
  assert.equal(controls.children.length, 0);
});

test('the interactive desktop lists completed startup stages and the current stage', async (t) => {
  const h = fixture(t);
  const dispose = screen(h.root, h.services, { ...h.screenOptions, interactive: true });
  await settle();
  const steps = h.root.querySelector('.console-readiness');
  assert.deepEqual(steps.children.map((row) => row.children[1].textContent), ['Booting', 'Network up', 'SSH up', 'Desktop up']);
  for (const [index, state] of ['booting', 'network_up', 'ssh_up', 'desktop_up'].entries()) {
    h.publish({ state, screen: index === 3 });
    await settle();
    assert.deepEqual(steps.children.map((row) => row.dataset.done), steps.children.map((_, i) => String(i < index || index === 3)));
    assert.deepEqual(steps.children.map((row) => row.getAttribute('aria-current')), steps.children.map((_, i) => i === index && index !== 3 ? 'step' : 'false'));
  }
  h.rfbs[0].dispatchEvent(new Event('connect'));
  assert.equal(steps.parentNode.hidden, true);
  assert.equal(h.root.querySelector('.screen-display').dataset.ready, 'true');
  dispose();
});

test('Claude Code starts once after a split shell prompt only in an interactive capable guest', async (t) => {
  for (const [interactive, installed] of [[false, true], [true, false], [true, true]]) {
    const h = fixture(t);
    h.services.hosts = [{ name: 'alpha', claude_code: installed }];
    h.publish({ state: 'ssh_up', terminal: true });
    const options = { ...h.terminalOptions, interactive };
    let dispose = terminal(h.root, h.services, options);
    await settle();
    const socket = h.sockets[0];
    socket.open();
    const receive = (text) => {
      socket.receive(new TextEncoder().encode(text).buffer);
      h.terminals[0].writes.at(-1).callback();
    };
    const commands = (socket) => socket.sent.filter((value) => value instanceof Uint8Array).map((value) => new TextDecoder().decode(value));
    receive('analyst@workstation:~$');
    assert.deepEqual(commands(socket), []);
    receive(' ');
    assert.deepEqual(commands(socket), interactive && installed ? ['claude\r'] : []);
    receive('$ ');
    assert.deepEqual(commands(socket), interactive && installed ? ['claude\r'] : []);
    dispose();
    dispose = terminal(h.root, h.services, options);
    await settle();
    h.sockets[1].open();
    h.sockets[1].receive(new TextEncoder().encode('$ ').buffer);
    h.terminals[1].writes[0].callback();
    assert.deepEqual(commands(h.sockets[1]), []);
    dispose();
  }
});

test('desktop startup steps yield to library errors and reconnect messages', async (t) => {
  const h = fixture(t);
  h.services.importModule = async () => { throw new Error('Unavailable'); };
  const dispose = screen(h.root, h.services, { ...h.screenOptions, interactive: true });
  await settle();
  assert.equal(h.root.querySelector('.console-readiness').hidden, true);
  assert.equal(h.root.querySelector('p').hidden, false);
  assert.match(h.root.querySelector('p').textContent, /noVNC is not in this build/);
  dispose();
  const live = fixture(t);
  const stop = screen(live.root, live.services, { ...live.screenOptions, interactive: true });
  live.publish({ state: 'desktop_up', screen: true });
  await settle();
  live.rfbs[0].dispatchEvent(new Event('connect'));
  live.sockets[0].close();
  assert.equal(live.root.querySelector('.console-readiness').hidden, true);
  assert.equal(live.root.querySelector('p').hidden, false);
  assert.match(live.root.querySelector('p').textContent, /Reconnecting/);
  stop();
});
