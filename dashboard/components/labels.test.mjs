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
  assert.match(root.textContent, /<download>Event 72.0s/);
  assert.equal(root.querySelector('download'), null);
  const remove = root.querySelectorAll('button').find((button) => button.getAttribute('aria-label') === 'Remove label <download>');
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

test('label editors cancel with Escape or Cancel and close after saving', async () => {
  const document = createDocument(), root = document.createElement('section');
  const commands = [];
  labelAction(root, { labelCommand: '/api/command/labels', transport: { post: async (_, value) => { commands.push(value.command); return { status: 'applied' }; } } }, { kind: 'event', seq: 7 });
  const open = root.querySelector('button'), form = root.querySelector('form');
  open.click();
  assert.equal(open.hidden, true);
  assert.equal(form.hidden, false);
  const escape = new Event('keydown', { cancelable: true });
  Object.defineProperty(escape, 'key', { value: 'Escape' });
  form.dispatchEvent(escape);
  assert.equal(form.hidden, true);
  assert.equal(open.hidden, false);
  assert.equal(commands.length, 0);
  open.click();
  root.querySelectorAll('button').find((button) => button.textContent === 'Cancel').click();
  assert.equal(form.hidden, true);
  open.click();
  root.querySelector('input').value = 'download';
  form.dispatchEvent(new Event('submit', { cancelable: true }));
  await settle();
  assert.deepEqual(commands, [{ action: 'add', target: { kind: 'event', seq: 7 }, text: 'download' }]);
  assert.equal(form.hidden, true);
  assert.equal(open.hidden, false);
});

test('label targets describe and select retained events, connections and host links', () => {
  const document = createDocument(), root = document.createElement('section');
  const watch = new EventTarget(); watch.close = () => {};
  const services = createServices({});
  const opened = [], pairs = [];
  services.watch = () => watch;
  services.showPanel = (kind) => opened.push(kind);
  services.showPackets = (pair) => pairs.push(pair);
  services.hosts = [{ name: 'beta', sandbox: 'west' }];
  services.state = (_, callback) => {
    callback({ value: [
      { id: 1, text: 'lookup', target: { kind: 'event', seq: 7 }, at: 1.2 },
      { id: 2, text: 'flow', target: { kind: 'flow', link: 'e2', a: '10.0.0.2', b: '10.0.0.3' }, at: 1.3 },
      { id: 3, text: 'connection', target: { kind: 'connection', id: 4, local: '10.0.0.2:53', peer: '10.0.0.3:99' }, at: 1.4 },
    ] }); return () => {};
  };
  const dispose = mount(root, services, { state: '/api/state/labels' });
  const event = { seq: 7, source: 'dns', kind: 'query', summary: 'example.test', conn: 4 };
  const snapshot = new Event('snapshot');
  snapshot.data = JSON.stringify({ events: [event], nodes: [{ id: 'n2', kind: 'sandbox', name: 'west' }], edges: [{ id: 'e2', a: 'n2', b: 'n3' }] });
  watch.dispatchEvent(snapshot);
  const targets = root.querySelectorAll('.label-target');
  assert.deepEqual(targets.map((button) => button.textContent), ['Event 7 · dns.query example.test', "beta's link · 10.0.0.2 ↔ 10.0.0.3", '10.0.0.2:53 ↔ 10.0.0.3:99']);
  targets[0].click();
  assert.deepEqual(services.selection.get().event, event);
  assert.deepEqual(opened, ['events']);
  targets[1].click();
  assert.deepEqual(services.selection.get().links, ['e2']);
  assert.deepEqual(pairs, [{ local: '10.0.0.2', peer: '10.0.0.3' }]);
  targets[2].click();
  assert.equal(services.selection.get().connection, 4);
  assert.equal(services.selection.get().event, null);
  assert.deepEqual(opened, ['events', 'events']);
  assert.equal(root.querySelectorAll('td.numeric')[0].textContent, '1.2s');
  assert.equal(root.querySelector('.label-remove').getAttribute('aria-label'), 'Remove label lookup');
  assert.ok(root.querySelector('.label-remove').querySelector('svg'));
  dispose(); services.dispose();
});

test('labels that cannot load say whether the run has stopped', () => {
  for (const [stopped, text] of [[true, 'The run has stopped, so labels can no longer be loaded.'], [false, 'Could not load labels: no such state topic: "labels"']]) {
    const document = createDocument(), root = document.createElement('section');
    const services = createServices({});
    let fail;
    services.watch = () => { const watch = new EventTarget(); watch.close = () => {}; return watch; };
    services.stopped = () => stopped;
    services.state = (_, update, error) => { fail = error; return () => {}; };
    const dispose = mount(root, services, { state: '/api/state/labels' });
    fail(new Error(stopped ? 'The run has stopped, so its state can no longer be loaded' : 'no such state topic: "labels"'));
    assert.equal(root.querySelector('.label-downloads').querySelectorAll('p')[1].textContent, text);
    dispose(); services.dispose();
  }
});
