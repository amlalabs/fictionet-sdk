import test from 'node:test';
import assert from 'node:assert/strict';
import { createDocument } from '../test-dom.mjs';
import { createSelection } from '../selection.mjs';
import { createTransport } from '../transport.mjs';
import { createServices } from '../page.mjs';
import { mount, guestResult } from './containment.mjs';
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('startup checks use authenticated state paths, render facts and scope guests', async () => {
  const document = createDocument(), root = document.createElement('section');
  const selection = createSelection();
  const requests = [];
  let source;
  const transport = createTransport({}, {
    location: { href: 'http://127.0.0.1:7878/' }, storage: { getItem: () => 'secret' },
    fetch: async (url, options) => {
      requests.push(url);
      assert.equal(options.headers.Authorization, 'Bearer secret');
      assert.equal(new URL(url).pathname, '/api/states/stream');
      return new Response(new ReadableStream({ start(controller) { source = controller; }, cancel() {} }), { headers: { 'Content-Type': 'text/event-stream' } });
    },
  });
  const services = createServices(transport);
  const dispose = mount(root, { selection, state: services.state, hosts: [{ name: 'alpha', sandbox: 'east' }] }, { state: '/api/state/containment' });
  assert.match(root.textContent, /No startup checks published/);
  await settle();
  const probe = { guest: 'east', name: 'Public DNS', command: '<dig @8.8.8.8>', outcome: 'contained', guest_result: 'Timed out', world_answer: 'no route: no machine at that address' };
  source.enqueue(new TextEncoder().encode(`event: snapshot\ndata: ${JSON.stringify({ topic: 'containment', revision: 1, value: { probes: [probe, { ...probe, guest: 'west', outcome: 'not_contained' }, { ...probe, name: 'Proxy settings', outcome: 'fact', proxies: [{ name: 'HTTPS_PROXY', destination: 'http://cache.test' }] }] } })}\n\n`));
  await settle();
  assert.match(root.textContent, /west · Public DNS: the guest got Timed out, and the world has no record of it/);
  assert.match(root.textContent, /<dig @8.8.8.8>/);
  assert.equal(root.querySelector('dig'), null);
  assert.match(root.textContent, /Timed out/);
  assert.match(root.textContent, /HTTPS_PROXY: http:\/\/cache.test/);
  selection.set({ host: 'alpha' });
  assert.doesNotMatch(root.textContent, /Not contained/);
  assert.match(root.textContent, /Contained/);
  assert.equal(requests.length, 1);
  dispose(); services.dispose(); transport.close();
  assert.equal(root.children.length, 0);
});

test('probe rows group guests, summarize outputs and expand full commands', () => {
  const document = createDocument(), root = document.createElement('section');
  const outcomes = ['contained', 'forwarded', 'not_contained', 'timed_out', 'unknown', 'missing_tool', 'fact'];
  const dispose = mount(root, {
    selection: createSelection(),
    state(path, callback) {
      callback({ value: { probes: outcomes.map((outcome) => ({ guest: 'alpha', name: outcome, outcome, command: 'curl https://example.test', destination: 'example.test', guest_result: '\nHTTP 200\nFull output', world_answer: 'https://example.test' })) } });
      return () => {};
    },
  }, { state: '/api/state/containment' });
  assert.equal(root.querySelectorAll('.containment-guest').length, 1);
  assert.equal(root.querySelectorAll('details').length, outcomes.length);
  assert.equal(root.querySelectorAll('.not-contained').length, 1);
  assert.equal(root.querySelectorAll('.outcome-pill').length, outcomes.length);
  assert.ok(root.querySelectorAll('.outcome-pill').every((pill) => pill.querySelector('svg').getAttribute('aria-hidden') === 'true'));
  assert.equal(root.querySelector('.probe-result').textContent, 'HTTP 200');
  assert.equal(root.querySelector('pre').textContent, '\nHTTP 200\nFull output');
  assert.match(root.querySelector('.containment-alert').textContent, /alpha · not_contained: the guest got HTTP 200 from https:\/\/example.test, and the world has no record of it/);
  const alert = root.querySelector('.containment-alert').children[0];
  assert.equal(alert.children[0].tag, 'svg');
  assert.equal(alert.children[0].getAttribute('aria-hidden'), 'true');
  assert.equal(alert.children[0].querySelector('path').getAttribute('d'), root.querySelector('.not_contained').querySelector('path').getAttribute('d'));
  dispose();
});


test('guest summaries skip tool metadata and keep the meaningful result', () => {
  assert.equal(guestResult(';; DiG 9.18\n;; global options: +cmd\n;; connection timed out; no servers could be reached'), 'connection timed out; no servers could be reached');
  assert.equal(guestResult('\nHTTP 200\nresponse body'), 'HTTP 200');
  assert.equal(guestResult('\nNo proxy settings set\n'), 'No proxy settings set');
});

test('startup checks that cannot load say whether the run has stopped', () => {
  for (const [stopped, text] of [[true, 'The run has stopped, so startup checks can no longer be loaded.'], [false, 'Could not load startup checks: no such state topic: "containment"']]) {
    const document = createDocument(), root = document.createElement('section');
    let fail;
    const dispose = mount(root, {
      selection: createSelection(), hosts: [], stopped: () => stopped,
      state: (_, update, error) => { fail = error; return () => {}; },
    }, { state: '/api/state/containment' });
    fail(new Error(stopped ? 'The run has stopped, so its state can no longer be loaded' : 'no such state topic: "containment"'));
    assert.equal(root.querySelector('.empty-note').textContent, text);
    dispose();
  }
});
