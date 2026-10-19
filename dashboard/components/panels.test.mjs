import test from 'node:test';
import assert from 'node:assert/strict';
import { mount as table } from './table.mjs';
import { mount as eventTable } from './event-table.mjs';
import { mount as control } from './control.mjs';
import { mount as custom } from './custom.mjs';
import { createDocument } from '../test-dom.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));
function fixture() {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const subscriptions = new Set(), requests = [], timers = new Map();
  let publish, fail;
  const services = {
    state(path, snapshot, error) { publish = snapshot; fail = error; subscriptions.add(path); return () => subscriptions.delete(path); },
    transport: {
      post(path, body, signal) { return new Promise((resolve, reject) => requests.push({ path, body, signal, resolve, reject })); },
      get(path, params, signal) { return new Promise((resolve, reject) => requests.push({ path, params, signal, resolve, reject })); },
    },
    setTimeout(callback) { const id = Symbol(); timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
  };
  return { root, services, subscriptions, requests, timers, publish: (value) => publish(value), fail: (error) => fail(error) };
}

test('table renders column pointers and formats as text and replaces snapshots', () => {
  const h = fixture();
  const dispose = table(h.root, h.services, { state: '/api/state/rows', columns: [
    { label: '<Name>', pointer: '/a~1b/~0name', format: 'text' },
    { label: 'Bytes', pointer: '/bytes', format: 'bytes' },
    { label: 'Count', pointer: '/count', format: 'number' },
  ] });
  h.publish({ revision: 1, value: [{ 'a/b': { '~name': '<img src=x>' }, bytes: 2048, count: 1234 }] });
  assert.match(h.root.textContent, /<Name>/);
  assert.match(h.root.textContent, /<img src=x>/);
  assert.match(h.root.textContent, /2.0 KB/);
  assert.match(h.root.textContent, /1,234/);
  assert.equal(h.root.querySelector('img'), null);
  h.publish({ revision: 2, value: [] });
  assert.doesNotMatch(h.root.textContent, /<img/);
  assert.match(h.root.textContent, /No rows yet/);
  h.fail(new Error('state is unavailable'));
  assert.match(h.root.textContent, /state is unavailable/);
  dispose();
  assert.equal(h.subscriptions.size, 0);
  assert.equal(h.root.children.length, 0);
});

test('control sends the linked revision once and shows replies, rejections and timeouts', async () => {
  const h = fixture();
  const dispose = control(h.root, h.services, { state: '/api/state/traffic', command: '/api/command/traffic', actions: [{ label: '<Pause>', command: { running: false } }] });
  const button = h.root.querySelector('button');
  assert.equal(button.disabled, true);
  h.publish({ revision: 7, value: { running: true } });
  button.click(); button.click();
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].body.command.expected_revision, 7);
  assert.equal(h.requests[0].body.command.running, false);
  assert.match(h.requests[0].body.request_id, /^[0-9a-f-]{36}$/);
  h.requests[0].resolve({ status: 'applied', reply: '<done>' });
  await settle();
  assert.match(h.root.textContent, /Applied.*<done>/);
  h.publish({ revision: 8, value: { running: false } });
  button.click();
  assert.equal(h.requests[1].body.command.expected_revision, 8);
  assert.notEqual(h.requests[0].body.request_id, h.requests[1].body.request_id);
  h.requests[1].reject({ body: { rejection: { reason: 'stale_revision', current: 9 } } });
  await settle();
  assert.match(h.root.textContent, /Rejected.*stale_revision/);
  button.click();
  h.requests[2].reject({ body: { status: 'timeout' } });
  await settle();
  assert.match(h.root.textContent, /may still apply/);
  assert.equal(h.requests.length, 3);
  dispose();
  assert.equal(button.listenerCount, 0);
  assert.equal(h.subscriptions.size, 0);
  assert.ok(h.requests.every((request) => request.signal.aborted));
});

test('event table advances the server cursor and cancels pending reads and timers', async () => {
  const h = fixture();
  const dispose = eventTable(h.root, h.services, { events: '/api/event-table/log', columns: [{ label: 'Text', pointer: '/summary' }] });
  h.requests[0].resolve({ rows: [{ summary: '<world>' }], next: 11, dropped: 3 });
  await settle();
  assert.match(h.root.textContent, /<world>/);
  assert.match(h.root.textContent, /3 events lost/);
  const next = [...h.timers.values()][0]; h.timers.clear(); next();
  assert.deepEqual(h.requests[1].params, { after: 11 });
  dispose();
  h.requests[1].resolve({ rows: [{ summary: 'late' }], next: 12, dropped: 0 });
  await settle();
  assert.equal(h.requests[1].signal.aborted, true);
  assert.equal(h.timers.size, 0);
  assert.equal(h.root.children.length, 0);
});

test('custom panels dispose a late mount and reject foreign module paths', async () => {
  const h = fixture();
  let finish, stopped = 0, imports = 0;
  h.services.importModule = async () => { imports++; return { mount: () => new Promise((resolve) => { finish = resolve; }) }; };
  const dispose = custom(h.root, h.services, { module: '/panels/traffic.mjs', title: 'Traffic' });
  await settle(); dispose(); finish(() => stopped++); await settle();
  assert.equal(stopped, 1);
  const bad = custom(h.root, h.services, { module: 'https://example.com/panel.mjs', title: '<Traffic>' });
  await settle();
  assert.match(h.root.textContent, /Invalid panel module path/);
  assert.equal(imports, 1);
  bad();
});
