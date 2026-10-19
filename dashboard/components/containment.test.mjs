import test from 'node:test';
import assert from 'node:assert/strict';
import { createDocument } from '../test-dom.mjs';
import { createSelection } from '../selection.mjs';
import { createTransport } from '../transport.mjs';
import { createServices } from '../page.mjs';
import { mount } from './containment.mjs';
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
  source.enqueue(new TextEncoder().encode(`event: snapshot\ndata: ${JSON.stringify({ topic: 'containment', revision: 1, value: { probes: [probe, { ...probe, guest: 'west', outcome: 'not_contained' }, { ...probe, name: 'Proxy settings', outcome: 'fact', proxies: [{ name: 'HTTPS_PROXY', destination: 'http://cache.test', world_host: true }] }] } })}\n\n`));
  await settle();
  assert.match(root.textContent, /1 probe got an answer the world does not account for/);
  assert.match(root.textContent, /<dig @8.8.8.8>/);
  assert.equal(root.querySelector('dig'), null);
  assert.match(root.textContent, /Timed out/);
  assert.match(root.textContent, /HTTPS_PROXY: http:\/\/cache.test \(world host\)/);
  selection.set({ host: 'alpha' });
  assert.doesNotMatch(root.textContent, /Not contained/);
  assert.match(root.textContent, /Contained/);
  assert.equal(requests.length, 1);
  dispose(); services.dispose(); transport.close();
  assert.equal(root.children.length, 0);
});
