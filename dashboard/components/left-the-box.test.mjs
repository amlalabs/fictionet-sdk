import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransport } from '../transport.mjs';
import { mount } from './left-the-box.mjs';
import { createDocument, fakeTimers } from '../test-dom.mjs';
import { createSelection } from '../selection.mjs';
import { hostLookups } from '../page.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

test('destinations show outcomes, scope guests, report loss and stop reads on disposal', async (t) => {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const requests = [], timers = fakeTimers(t), selection = createSelection();
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
  const hosts = [{ name: 'alpha', sandbox: 'east' }, { name: 'beta', sandbox: 'west' }];
  const dispose = mount(root, {
    selection, hosts, ...hostLookups(() => hosts),
    transport,
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
  assert.match(root.textContent, /the host package cache/);
  assert.equal(root.querySelector('.egress-origins').textContent, 'https://archive.ubuntu.com3 requests');
  for (const address of root.querySelectorAll('.egress-address')) {
    assert.deepEqual(address.children.map((child) => child.tag), ['span', 'wbr', 'span']);
    assert.equal(address.children[0].textContent, 'https://');
    assert.equal(address.children[2].textContent, 'archive.ubuntu.com');
  }
  assert.equal(root.querySelector('svg').getAttribute('aria-hidden'), 'true');
  assert.match(root.textContent, /Refused.*port closed/);
  assert.match(root.textContent, /No route.*IPv6 is off/);
  assert.deepEqual(root.querySelector('table').querySelectorAll('th').map((cell) => cell.textContent), ['Destination', 'Answered by', 'Attempts', 'When']);
  assert.deepEqual(root.querySelector('tbody').querySelectorAll('td').map((cell) => cell.textContent), ['alpha203.0.113.1:443 tcp', 'https://archive.ubuntu.com', '3 requests · 2 connections', '1 s – 4 s']);
  assert.match(root.textContent, /Everything else stayed in the world/);
  selection.set({ host: 'alpha' });
  assert.doesNotMatch(root.textContent, /IPv6 is off/);
  selection.set({ host: null });
  assert.match(root.textContent, /IPv6 is off/);
  let next = [...timers.values()][0].callback; timers.clear(); next(); await settle();
  requests[1].resolve({ ...snapshot, revision: 2, dropped: 5, lost: 7 });
  await settle();
  assert.match(root.textContent, /5 attempts not kept, 7 observations lost/);
  assert.doesNotMatch(root.textContent, /Everything else stayed in the world/);
  next = [...timers.values()][0].callback; timers.clear(); next(); await settle();
  requests[2].resolve({ ...snapshot, revision: 3, pending: [{ ...row, service: 'jump server' }] });
  await settle();
  assert.match(root.textContent, /1 connection open, outcome not known yet/);
  assert.doesNotMatch(root.textContent, /jump server/);
  assert.match(root.textContent, /Everything else stayed in the world/);
  const table = root.querySelector('table'), details = root.querySelector('details');
  details.open = true;
  root.scrollTop = 80;
  document.hidden = true;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal([...timers.values()][0].delay, 10000);
  next = [...timers.values()][0].callback; timers.clear(); next(); await settle();
  requests[3].resolve({ ...snapshot, revision: 3 });
  await settle();
  assert.equal(root.querySelector('table'), table);
  assert.equal(details.open, true);
  assert.equal(root.scrollTop, 80);
  document.hidden = false;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal([...timers.values()][0].delay, 2000);
  next = [...timers.values()][0].callback; timers.clear(); next(); await settle();
  requests[4].reject(new Error('disconnected'));
  await settle();
  assert.match(root.textContent, /disconnected.*may be incomplete/);
  next = [...timers.values()][0].callback; timers.clear(); next(); await settle();
  dispose();
  transport.close();
  requests[5].resolve(snapshot);
  await settle();
  assert.equal(root.children.length, 0);
  assert.equal(timers.size, 0);
  assert.ok(requests.every((request) => request.signal.aborted));
});

test('containment escapes override completeness only in their scope', async (t) => {
  fakeTimers(t);
  const document = createDocument(), root = document.createElement('section');
  const selection = createSelection();
  let update, opened, stopped = false;
  const row = { sandbox: 'east', name: 'example.test', address: '203.0.113.10:443', transport: 'tcp', outcome: 'forwarded', by: 'https://example.test', requests: 1, connections: 1, packets: 0, first: .4, last: .4 };
  const hosts = [{ name: 'alpha', sandbox: 'east' }, { name: 'beta', sandbox: 'west' }];
  const dispose = mount(root, {
    selection, hosts, ...hostLookups(() => hosts),
    transport: { get: async () => ({ revision: 1, destinations: [row, { ...row, outcome: 'no_route', requests: 0, connections: 0, packets: 1, last: .400001 }], pending: [], lookups: [], dropped: 0, lost: 0 }) },
    containmentState: '/api/state/containment',
    state(path, callback) { assert.equal(path, '/api/state/containment'); update = callback; return () => { stopped = true; }; },
    showPanel(kind) { opened = kind; },
  });
  await settle();
  assert.doesNotMatch(root.textContent, /Everything else stayed/);
  update({ value: { probes: [{ guest: 'east', outcome: 'not_contained' }] } });
  assert.match(root.textContent, /The containment check found a way out that the world did not see/);
  assert.equal(root.querySelector('.egress-origins').textContent, 'https://example.test1 request');
  assert.match(root.textContent, /1 request · 1 connection/);
  assert.match(root.textContent, /1 packet/);
  assert.doesNotMatch(root.textContent, /0.4 s –/);
  assert.ok(root.querySelector('.egress-warning').querySelector('svg'));
  const counts = root.querySelector('.egress-counts');
  assert.equal(counts.tag, 'p');
  assert.equal(counts.textContent, 'Observed in the world: 0 served, 0 refused, 1 with no route.');
  assert.equal(counts.querySelector('button'), null);
  assert.match(root.querySelector('button').parent.textContent, /The containment check found a way out.*Open Containment/);
  root.querySelector('button').click();
  assert.equal(opened, 'containment');
  selection.set({ host: 'beta' });
  assert.match(root.textContent, /Everything else stayed/);
  assert.ok(root.querySelector('.egress-complete').querySelector('svg'));
  selection.set({ host: 'alpha' });
  assert.doesNotMatch(root.textContent, /Everything else stayed/);
  dispose();
  assert.equal(stopped, true);
});

test('after the run stopped, a failed read says so and stops asking', async (t) => {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const timers = fakeTimers(t);
  const dispose = mount(root, {
    selection: createSelection(), hosts: [], ...hostLookups(() => []), stopped: () => true,
    transport: { get: async () => { throw new TypeError('Failed to fetch'); } },
  });
  await settle();
  assert.equal(root.querySelector('.egress-summary').querySelector('p').textContent, 'The run has stopped, so destinations can no longer be loaded.');
  assert.doesNotMatch(root.textContent, /Failed to fetch/);
  assert.equal(timers.size, 0);
  dispose();
});
