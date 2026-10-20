import test from 'node:test';
import assert from 'node:assert/strict';
import { mount as table } from './table.mjs';
import { mount as eventTable } from './event-table.mjs';
import { mount as control } from './control.mjs';
import { mount as custom } from './custom.mjs';
import { createDocument } from '../test-dom.mjs';
import { createTransport } from '../transport.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));
function fixture() {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const subscriptions = new Set(), requests = [], timers = new Map();
  let publish, fail;
  const services = {
    state(path, snapshot, error) { publish = snapshot; fail = error; subscriptions.add(path); return () => subscriptions.delete(path); },
    transport: createTransport({}, {
      location: { href: 'http://127.0.0.1:7878/' }, storage: { getItem: () => 'secret' },
      fetch(url, options) {
        const endpoint = new URL(url);
        assert.equal(options.headers.Authorization, 'Bearer secret');
        return new Promise((resolve, reject) => requests.push({
          path: endpoint.pathname, body: options.body && JSON.parse(options.body), signal: options.signal,
          params: Object.fromEntries([...endpoint.searchParams].map(([key, value]) => [key, Number(value)])),
          resolve: (value) => resolve(Response.json(value)), reject,
        }));
      },
    }),
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

test('tables update rows in place and build again only rows whose text changed', async () => {
  const h = fixture();
  const dispose = table(h.root, h.services, { state: '/api/state/rows', columns: [{ label: 'Host', pointer: '/host' }, { label: 'Packets', pointer: '/packets', format: 'number' }] });
  h.publish({ revision: 1, value: [{ host: 'alpha', packets: 1 }, { host: 'beta', packets: 1 }] });
  const [alpha, beta] = h.root.querySelectorAll('tr').slice(1);
  alpha.classList.remove('new-row');
  beta.classList.remove('new-row');
  h.publish({ revision: 2, value: [{ host: 'alpha', packets: 1 }, { host: 'gamma', packets: 0 }, { host: 'beta', packets: 2 }] });
  const rows = h.root.querySelectorAll('tr').slice(1);
  assert.equal(rows.length, 3);
  assert.equal(rows[0], alpha);
  assert.equal(alpha.classList.contains('new-row'), false);
  assert.deepEqual(rows.map((row) => row.textContent), ['alpha1', 'gamma0', 'beta2']);
  assert.ok(rows.slice(1).every((row) => row.classList.contains('new-row')));
  dispose();
  // Event tables name rows by event, so a row read again keeps its element.
  const log = fixture();
  const stop = eventTable(log.root, log.services, { events: '/api/event-table/log', columns: [{ label: 'Text', pointer: '/summary' }] });
  await settle();
  log.requests[0].resolve({ rows: [{ seq: 4, summary: 'first' }], next: 5, dropped: 0 });
  await settle();
  const first = log.root.querySelector('tbody').children[0];
  const next = [...log.timers.values()][0]; log.timers.clear(); next();
  await settle();
  log.requests[1].resolve({ rows: [{ seq: 5, summary: 'second' }], next: 6, dropped: 0 });
  await settle();
  const body = log.root.querySelector('tbody').children;
  assert.deepEqual(body.map((row) => row.textContent), ['first', 'second']);
  assert.equal(body[0], first);
  stop();
});

test('control sends the linked revision once and shows replies, rejections and timeouts', async () => {
  const h = fixture();
  const dispose = control(h.root, h.services, { state: '/api/state/traffic', command: '/api/command/traffic', actions: [{ label: '<Pause>', command: { running: false } }] });
  const button = h.root.querySelector('button');
  assert.equal(button.disabled, true);
  h.publish({ revision: 7, value: { running: true, last_change: 'boot' } });
  // The linked state is a key and value list, as text.
  assert.deepEqual(h.root.querySelectorAll('dt').map((dt) => dt.textContent), ['Running', 'Last change']);
  assert.deepEqual(h.root.querySelectorAll('dd').map((dd) => dd.textContent), ['true', 'boot']);
  button.click(); button.click();
  await settle();
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].body.command.expected_revision, 7);
  assert.equal(h.requests[0].body.command.running, false);
  assert.match(h.requests[0].body.request_id, /^[0-9a-f-]{36}$/);
  h.requests[0].resolve({ status: 'applied', reply: '<done>' });
  await settle();
  assert.match(h.root.textContent, /<Pause>: applied.*<done>/);
  h.publish({ revision: 8, value: { running: false } });
  button.click();
  await settle();
  assert.equal(h.requests[1].body.command.expected_revision, 8);
  assert.notEqual(h.requests[0].body.request_id, h.requests[1].body.request_id);
  h.requests[1].reject({ body: { rejection: { reason: 'stale_revision', current: 9 } } });
  await settle();
  assert.match(h.root.textContent, /Not applied: the state changed \(now revision 9\)\. Check it and try again\./);
  button.click();
  await settle();
  h.requests[2].reject({ body: { status: 'timeout' } });
  await settle();
  assert.match(h.root.textContent, /may still apply/);
  assert.equal(h.requests.length, 3);
  button.click();
  await settle();
  h.requests[3].resolve({ status: 'applied', reply: null });
  await settle();
  assert.match(h.root.querySelector('.control-reply').textContent, /^<Pause>: applied$/);
  dispose();
  assert.equal(button.listenerCount, 0);
  assert.equal(h.subscriptions.size, 0);
  assert.ok(h.requests.every((request) => request.signal.aborted));
});

test('control sends the world revision even when publication has a different revision', async () => {
  const h = fixture();
  const dispose = control(h.root, h.services, { state: '/api/state/switch', command: '/api/command/switch', actions: [{ label: 'On', command: { on: true } }] });
  h.publish({ revision: 1, value: { revision: 0, on: false } });
  h.root.querySelector('button').click();
  await settle();
  assert.equal(h.requests[0].body.command.expected_revision, 0);
  h.requests[0].resolve({ status: 'applied', reply: { revision: 1 } });
  await settle();
  h.publish({ revision: 3, value: { revision: 1, on: true } });
  h.root.querySelector('button').click();
  await settle();
  assert.equal(h.requests[1].body.command.expected_revision, 1);
  h.requests[1].resolve({ status: 'applied', reply: { revision: 1 } });
  await settle();
  dispose();
});

test('event table advances the server cursor and cancels pending reads and timers', async () => {
  const h = fixture();
  const dispose = eventTable(h.root, h.services, { events: '/api/event-table/log', columns: [{ label: 'Text', pointer: '/summary' }] });
  await settle();
  h.requests[0].resolve({ rows: [{ summary: '<world>' }], next: 11, dropped: 3 });
  await settle();
  assert.match(h.root.textContent, /<world>/);
  assert.match(h.root.textContent, /3 events were lost/);
  const next = [...h.timers.values()][0]; h.timers.clear(); next();
  await settle();
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

test('control uses the world revision when stream and world revisions differ', async () => {
  const h = fixture();
  const dispose = control(h.root, h.services, { state: '/api/state/routing', command: '/api/command/routing', actions: [{ label: 'Hijacked', command: { mode: 'hijack' } }] });
  h.publish({ revision: 1, value: { revision: 0, mode: 'legitimate' } });
  h.root.querySelector('button').click();
  await settle();
  assert.equal(h.requests[0].body.command.expected_revision, 0);
  h.requests[0].resolve({ status: 'applied', reply: { revision: 1 } });
  await settle();
  h.publish({ revision: 2, value: { revision: 1, mode: 'hijack' } });
  h.root.querySelector('button').click();
  await settle();
  assert.equal(h.requests[1].body.command.expected_revision, 1);
  dispose();
});
