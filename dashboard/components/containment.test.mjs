import test from 'node:test';
import assert from 'node:assert/strict';
import { createDocument, liveSubscriptions } from '../test-dom.mjs';
import { createTransport } from '../transport.mjs';
import { createServices } from '../page.mjs';
import { mount } from './containment.mjs';
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('startup checks use authenticated state paths, render facts and scope guests', async () => {
  const document = createDocument(), root = document.createElement('section');
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
  const services = createServices(transport), selection = services.selection;
  services.hosts = [{ name: 'alpha', sandbox: 'east' }];
  const following = liveSubscriptions(selection);
  const dispose = mount(root, services, { state: '/api/state/containment' });
  assert.match(root.textContent, /No startup checks published/);
  await settle();
  const probe = { guest: 'east', name: 'Public DNS', command: '<dig @8.8.8.8>', destination: '8.8.8.8:53', outcome: 'contained', guest_result: 'Exit 9\nTimed out', summary: 'Timed out', world_answer: 'no route: no machine at that address' };
  source.enqueue(new TextEncoder().encode(`event: snapshot\ndata: ${JSON.stringify({ topic: 'containment', revision: 1, value: { probes: [probe, { ...probe, guest: 'west', outcome: 'not_contained' }, { ...probe, name: 'Proxy settings', outcome: 'fact', proxies: [{ name: 'HTTPS_PROXY', destination: 'http://cache.test', world_host: true }] }] } })}\n\n`));
  await settle();
  assert.match(root.textContent, /west · Public DNS: the guest got Timed out from 8.8.8.8:53, and the world did not see it/);
  assert.match(root.textContent, /<dig @8.8.8.8>/);
  assert.match(root.textContent, /Timed out/);
  assert.match(root.textContent, /HTTPS_PROXY: http:\/\/cache.test \(world host\)/);
  selection.set({ host: 'alpha' });
  assert.doesNotMatch(root.textContent, /Not contained/);
  assert.match(root.textContent, /Contained/);
  assert.equal(requests.length, 1);
  dispose();
  assert.equal(following(), 0);
  services.dispose(); transport.close();
  assert.equal(root.children.length, 0);
});

test('probe rows group guests, summarize outputs and expand full commands', () => {
  const document = createDocument(), root = document.createElement('section');
  const outcomes = ['contained', 'forwarded', 'not_contained', 'timed_out', 'unknown', 'missing_tool', 'fact'];
  const services = createServices({});
  services.state = (path, callback) => {
    callback({ value: { probes: outcomes.map((outcome) => ({ guest: 'alpha', name: outcome, outcome, command: 'curl https://example.test/path', destination: 'example.test', guest_result: '\nHTTP 200\nFull output', summary: 'HTTP 200', world_answer: 'https://example.test' })) } });
    return () => {};
  };
  const dispose = mount(root, services, { state: '/api/state/containment' });
  assert.equal(root.querySelectorAll('.containment-guest').length, 1);
  assert.equal(root.querySelectorAll('details').length, outcomes.length);
  assert.equal(root.querySelectorAll('.not-contained').length, 1);
  assert.equal(root.querySelectorAll('.outcome-pill').length, outcomes.length);
  assert.ok(root.querySelectorAll('.outcome-pill').every((pill) => pill.querySelector('svg').getAttribute('aria-hidden') === 'true'));
  assert.equal(root.querySelector('.probe-result').textContent, 'HTTP 200');
  assert.equal(root.querySelector('pre').textContent, '\nHTTP 200\nFull output');
  assert.match(root.querySelector('.containment-alert').textContent, /alpha · not_contained: the guest got HTTP 200 from example.test, and the world did not see it/);
  const alert = root.querySelector('.containment-alert').children[0];
  assert.equal(alert.children[0].tag, 'svg');
  assert.equal(alert.children[0].getAttribute('aria-hidden'), 'true');
  assert.equal(alert.children[0].querySelector('path').getAttribute('d'), root.querySelector('.not_contained').querySelector('path').getAttribute('d'));
  dispose();
});


test('startup checks that cannot load say whether the run has stopped', () => {
  for (const [stopped, text] of [[true, 'The run has stopped, so startup checks can no longer be loaded.'], [false, 'Could not load startup checks: no such state topic: "containment"']]) {
    const document = createDocument(), root = document.createElement('section');
    let fail;
    const services = createServices({});
    if (stopped) services.run.set('stopped');
    services.state = (_, update, error) => { fail = error; return () => {}; };
    const dispose = mount(root, services, { state: '/api/state/containment' });
    fail(new Error(stopped ? 'The run has stopped, so its state can no longer be loaded' : 'no such state topic: "containment"'));
    assert.equal(root.querySelector('.empty-note').textContent, text);
    dispose();
  }
});
