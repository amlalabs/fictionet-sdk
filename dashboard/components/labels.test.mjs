import test from 'node:test';
import assert from 'node:assert/strict';
import { createDocument } from '../test-dom.mjs';
import { createTransport } from '../transport.mjs';
import { createServices } from '../page.mjs';
import { mount, labelAction } from './labels.mjs';
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('typed labels, removal and scoped downloads use real authenticated transport paths', async (t) => {
  const document = createDocument(), root = document.createElement('section');
  const requests = [], downloads = [];
  let source;
  const create = document.createElement.bind(document);
  document.createElement = (tag) => {
    const element = create(tag);
    if (tag === 'a') element.addEventListener('click', () => downloads.push({ href: element.href, name: element.download }));
    return element;
  };
  const transport = createTransport({}, {
    document, location: { href: 'http://127.0.0.1:7878/' }, storage: { getItem: () => 'secret' },
    fetch: async (url, options) => {
      requests.push({ url, options });
      assert.equal(options.headers.Authorization, 'Bearer secret');
      assert.ok(!url.includes('secret'));
      if (new URL(url).pathname === '/api/states/stream') return new Response(new ReadableStream({ start(controller) { source = controller; }, cancel() {} }), { headers: { 'Content-Type': 'text/event-stream' } });
      return Response.json({ status: 'applied', reply: 1 });
    },
  });
  const services = createServices(transport);
  services.labelCommand = '/api/command/labels';
  const stop = mount(root, services, { state: '/api/state/labels', command: services.labelCommand });
  t.after(() => { stop(); services.dispose(); transport.close(); });
  await settle();
  source.enqueue(new TextEncoder().encode(`event: snapshot\ndata: ${JSON.stringify({ topic: 'labels', revision: 1, value: [{ id: 3, text: '<download>', target: { kind: 'event', seq: 7 }, at: 2 }] })}\n\n`));
  await settle();
  assert.match(root.textContent, /<download>Event 72 sRemove/);
  assert.equal(root.querySelector('download'), null);
  const remove = root.querySelectorAll('button').find((button) => button.textContent === 'Remove');
  remove.click(); await settle();
  assert.deepEqual(JSON.parse(requests.at(-1).options.body).command, { action: 'remove', id: 3 });
  for (const target of [{ kind: 'event', seq: 7 }, { kind: 'connection', id: 2, local: '192.0.2.1:80', peer: '10.0.2.15:40000' }, { kind: 'flow', link: 'e1', a: '192.0.2.1:80', b: '10.0.2.15:40000' }]) {
    const editor = document.createElement('div');
    labelAction(editor, services, target);
    editor.querySelector('button').click();
    editor.querySelector('input').value = 'download';
    editor.querySelector('form').dispatchEvent(new Event('submit', { cancelable: true }));
    await settle();
    assert.equal(new URL(requests.at(-1).url).pathname, '/api/command/labels');
    assert.deepEqual(JSON.parse(requests.at(-1).options.body).command, { action: 'add', target, text: 'download' });
    assert.match(editor.textContent, /Label added/);
  }
  services.selection.set({ host: 'alpha' });
  root.querySelectorAll('button').find((button) => button.textContent === 'Events (JSONL)').click();
  await settle();
  assert.equal(new URL(requests.at(-1).url).pathname, '/api/export/events');
  assert.equal(new URL(requests.at(-1).url).search, '?host=alpha');
  services.selection.set({ host: null });
  root.querySelectorAll('button').find((button) => button.textContent === 'Packets (pcapng)').click();
  await settle();
  assert.equal(new URL(requests.at(-1).url).pathname, '/api/export/packets');
  assert.equal(new URL(requests.at(-1).url).search, '');
  assert.equal(downloads.length, 2);
  assert.equal(downloads[0].name, 'fictionet-events.jsonl');
  assert.ok(downloads.every((item) => item.href.startsWith('blob:') && !item.href.includes('secret')));
});
