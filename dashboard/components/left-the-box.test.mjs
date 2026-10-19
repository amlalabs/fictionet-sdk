import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransport } from '../transport.mjs';
import { mount } from './left-the-box.mjs';
import { createDocument } from '../test-dom.mjs';
import { createSelection } from '../selection.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

test('destinations show outcomes, scope guests, report loss and stop reads on disposal', async () => {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const requests = [], delays = [], timers = new Map(), selection = createSelection();
  const transport = createTransport({}, {
    location: { href: 'http://127.0.0.1:7878/' }, storage: { getItem: () => 'secret' },
    fetch(url, options) {
      assert.equal(options.headers.Authorization, 'Bearer secret');
      return new Promise((resolve, reject) => requests.push({
        path: new URL(url).pathname, signal: options.signal, reject,
        resolve: (value) => resolve(Response.json(value)),
      }));
    },
  });
  const dispose = mount(root, {
    selection, hosts: [{ name: 'alpha', sandbox: 'east' }, { name: 'beta', sandbox: 'west' }],
    transport,
    setTimeout(callback, delay) { delays.push(delay); const id = Symbol(); timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  const row = { sandbox: 'east', address: '203.0.113.1:443', transport: 'tcp', connections: 2, requests: 3, packets: 0, first: 1, last: 4 };
  const snapshot = { revision: 1, dropped: 0, lost: 0, pending: [], lookups: [], destinations: [
    { ...row, outcome: 'served', by: '<world.test>' },
    { ...row, outcome: 'served', by: 'host package cache' },
    { ...row, outcome: 'forwarded', by: 'https://archive.ubuntu.com' },
    { ...row, outcome: 'refused', by: 'port closed' },
    { ...row, sandbox: 'west', outcome: 'no_route', by: 'IPv6 is off' },
  ] };
  await settle();
  assert.equal(requests[0].path, '/api/egress');
  requests[0].resolve(snapshot);
  await settle();
  assert.match(root.textContent, /Served by the world.*<world.test>/);
  assert.equal(root.querySelector('world.test'), null);
  assert.match(root.textContent, /the host package cache/);
  assert.match(root.textContent, /Left the box: https:\/\/archive.ubuntu.com/);
  assert.match(root.textContent, /Refused.*port closed/);
  assert.match(root.textContent, /No route.*IPv6 is off/);
  assert.deepEqual(root.querySelector('tbody').querySelectorAll('td.numeric').map((cell) => cell.textContent), ['2', '3', '—', '1 s', '4 s']);
  assert.match(root.textContent, /Everything else stayed in the world/);
  selection.set({ host: 'alpha' });
  assert.doesNotMatch(root.textContent, /IPv6 is off/);
  selection.set({ host: null });
  assert.match(root.textContent, /IPv6 is off/);
  let next = [...timers.values()][0]; timers.clear(); next(); await settle();
  requests[1].resolve({ ...snapshot, revision: 2, dropped: 5, lost: 7 });
  await settle();
  assert.match(root.textContent, /5 attempts not kept, 7 observations lost/);
  assert.doesNotMatch(root.textContent, /Everything else stayed in the world/);
  next = [...timers.values()][0]; timers.clear(); next(); await settle();
  requests[2].resolve({ ...snapshot, revision: 3, pending: [{ ...row, service: 'jump server' }] });
  await settle();
  assert.match(root.textContent, /1 connections open, outcome not known yet/);
  assert.doesNotMatch(root.textContent, /jump server/);
  assert.match(root.textContent, /Everything else stayed in the world/);
  const table = root.querySelector('table'), details = root.querySelector('details');
  details.open = true;
  root.scrollTop = 80;
  document.hidden = true;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(delays.at(-1), 10000);
  next = [...timers.values()][0]; timers.clear(); next(); await settle();
  requests[3].resolve({ ...snapshot, revision: 3 });
  await settle();
  assert.equal(root.querySelector('table'), table);
  assert.equal(details.open, true);
  assert.equal(root.scrollTop, 80);
  document.hidden = false;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(delays.at(-1), 2000);
  next = [...timers.values()][0]; timers.clear(); next(); await settle();
  requests[4].reject(new Error('disconnected'));
  await settle();
  assert.match(root.textContent, /disconnected.*may be incomplete/);
  next = [...timers.values()][0]; timers.clear(); next(); await settle();
  dispose();
  transport.close();
  requests[5].resolve(snapshot);
  await settle();
  assert.equal(root.children.length, 0);
  assert.equal(timers.size, 0);
  assert.ok(requests.every((request) => request.signal.aborted));
});
