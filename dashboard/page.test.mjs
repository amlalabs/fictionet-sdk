import test from 'node:test';
import assert from 'node:assert/strict';
import { createServices, divider } from './page.mjs';
import { createDocument, Element } from './test-dom.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));
test('state subscriptions share streams and replace unknown deltas without stale overwrites', async () => {
  const sources = [], requests = [];
  const services = createServices({
    stateStream(id) { const source = new Element(id); source.close = () => { source.closed = true; }; sources.push(source); return source; },
    get(path, _, signal) { return new Promise((resolve) => requests.push({ path, signal, resolve })); },
  }, {});
  const values = [], other = [], errors = [];
  const stop = services.state('/api/state/exchanges', (value) => values.push(value), (error) => errors.push(error));
  const stopOther = services.state('/api/state/exchanges', (value) => other.push(value));
  assert.equal(sources.length, 1);
  const emit = (name, value) => { const event = new Event(name); event.data = JSON.stringify(value); sources[0].dispatchEvent(event); };
  emit('snapshot', { revision: 1, value: [1] });
  emit('delta', { revision: 2, delta: { custom: 'operation' } });
  emit('delta', { revision: 3, delta: 'another' });
  assert.equal(requests.length, 1);
  emit('snapshot', { revision: 4, value: [4] });
  requests[0].resolve({ revision: 2, value: [2] });
  await settle();
  assert.equal(requests.length, 2);
  requests[1].resolve({ revision: 4, value: [4], status: { too_large: true } });
  await settle();
  assert.deepEqual(values.map((snapshot) => snapshot.revision), [1, 4, 4]);
  assert.deepEqual(other, values);
  emit('error', { error: 'Connection lost' });
  assert.match(errors[0].message, /Connection lost/);
  stop(); assert.equal(sources[0].closed, undefined);
  stopOther(); assert.equal(sources[0].closed, true);
  assert.equal(sources[0].listenerCount, 0);
  assert.ok(requests.every((request) => request.signal.aborted));
  services.dispose();
});

test('divider clamps keyboard movement and survives refused storage', (t) => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, get() { throw new Error('Storage refused'); } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'localStorage', previous); else delete globalThis.localStorage; });
  const document = createDocument(), element = document.createElement('div'), workspace = document.createElement('main');
  const dispose = divider(element, workspace, 'Demo');
  assert.equal(element.getAttribute('aria-valuenow'), '62');
  const key = (key) => { const event = new Event('keydown'); event.key = key; element.dispatchEvent(event); };
  key('ArrowLeft'); assert.equal(element.getAttribute('aria-valuenow'), '60');
  key('Home'); key('ArrowLeft'); assert.equal(element.getAttribute('aria-valuenow'), '25');
  key('End'); key('ArrowRight'); assert.equal(element.getAttribute('aria-valuenow'), '80');
  element.dispatchEvent(new Event('dblclick')); assert.equal(element.getAttribute('aria-valuenow'), '62');
  dispose(); assert.equal(element.listenerCount, 0);
});

test('page pins hosts, follows tab keyboard controls and disposes mounted state and globals', async (t) => {
  const { mount } = await import('./page.mjs');
  const document = createDocument(), window = new Element('window');
  document.hidden = false;
  const root = document.createElement('div'); document.body.append(root);
  for (const id of ['page-status', 'page-title', 'host-bar', 'divider', 'workbench', 'workspace', 'tabs', 'inspector-content', 'clear-scope', 'scope-text', 'run-clock', 'moment-banner', 'moment-status']) {
    const node = document.createElement(id === 'clear-scope' ? 'button' : 'div'); node.setAttribute('id', id); root.append(node);
  }
  const previousDocument = globalThis.document, previousWindow = globalThis.window;
  globalThis.document = document; globalThis.window = window;
  t.after(() => { globalThis.document = previousDocument; globalThis.window = previousWindow; });
  const timers = new Map();
  t.mock.method(globalThis, 'setInterval', (callback) => { const id = Symbol(); timers.set(id, callback); return id; });
  t.mock.method(globalThis, 'clearInterval', (id) => timers.delete(id));
  t.mock.method(globalThis, 'setTimeout', (callback) => { const id = Symbol(); timers.set(id, callback); return id; });
  t.mock.method(globalThis, 'clearTimeout', (id) => timers.delete(id));
  const sources = [];
  const source = () => { const stream = new Element('stream'); stream.close = () => { stream.closed = true; }; sources.push(stream); return stream; };
  const description = { title: 'Fixture', moments: [], hosts: ['alpha', 'beta'].map((name) => ({ name, sandbox: name, status: `/api/state/host-${name}`, screen: null, terminal: null })), panels: [
    { id: 'rows', title: 'Rows', area: 'inspector', kind: 'table', state: '/api/state/rows', columns: [] },
    { id: 'control', title: 'Control', area: 'inspector', kind: 'control', state: null, actions: [] },
  ] };
  let transportClosed = false, themeClosed = false;
  const stop = await mount(root, { get: async () => description, stateStream: source, watch: source, close() { transportClosed = true; } }, { dispose() { themeClosed = true; } });
  assert.match(root.querySelector('#workspace').textContent, /alpha/);
  const pins = root.querySelectorAll('button.pin'); pins[0].click(); pins[1].click();
  assert.equal(root.querySelectorAll('section.workspace-tile').length, 2);
  const tabs = root.querySelector('#tabs').children;
  const right = new Event('keydown'); right.key = 'ArrowRight'; tabs[0].dispatchEvent(right);
  assert.equal(document.activeElement, tabs[1]);
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  const enter = new Event('keydown'); enter.key = 'Enter'; tabs[1].dispatchEvent(enter);
  assert.equal(tabs[1].getAttribute('aria-selected'), 'true');
  assert.equal(sources.find((stream) => stream.closed)?.closed, true);
  stop();
  assert.equal(timers.size, 0);
  assert.equal(window.listenerCount, 0);
  assert.equal(document.listenerCount, 0);
  assert.ok(sources.every((stream) => stream.closed && stream.listenerCount === 0));
  assert.equal(transportClosed, true);
  assert.equal(themeClosed, true);
});
