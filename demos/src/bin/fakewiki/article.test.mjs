import test from 'node:test';
import assert from 'node:assert/strict';
import { mount } from './article.mjs';
import { createDocument, Element } from '../../../../dashboard/test-dom.mjs';
import * as dom from '../../../../dashboard/dom.mjs';
const settle = () => new Promise((resolve) => setImmediate(resolve));
const segment = (text, changed) => ({ text, changed });
const fixture = (served = 'real', revision = 0) => ({ revision, on: revision > 0, topics: [{ topic: 'stream_ripping', true_claim: 'Still restricted', false_claim: 'Fully legal', sources: [{ source: 'wikipedia', url: 'https://en.wikipedia.org/wiki/Stream_ripping', served, real: { title: 'Stream ripping', paragraphs: [[segment('Shared.', false), segment('<img src=x> Restricted.', true)]] }, tampered: { title: 'Stream ripping', paragraphs: [[segment('Shared.', false), segment('Fully legal.', true)]] } }] }] });
const read = (seq, served, revision) => ({ seq, at: seq, source: 'http', kind: 'request', sandbox: { name: 'workstation' }, conn: 'connection', fields: { host: 'en.wikipedia.org', scheme: 'https', path: '/wiki/Stream_ripping', topic: 'stream_ripping', source: 'wikipedia', served, tamper_revision: revision, status: 200, complete: true, method: 'GET' } });
function harness() {
  const document = createDocument(), root = document.createElement('section'), watch = new Element('watch'), states = new Map(), requests = [], selections = [];
  let closed = false;
  watch.close = () => { closed = true; };
  const services = {
    dom, state(path, callback) { states.set(path, callback); return () => states.delete(path); },
    transport: { get: async (path) => path.includes('context') ? ({ hosts: { 'en.wikipedia.org': '10.0.0.10' }, reader: 'Firefox (scripted)', reader_host: 'workstation' }) : ({ rows: [], next: 0 }), post: (path, body, signal) => new Promise((resolve, reject) => requests.push({ path, body, signal, resolve, reject })) },
    watch: () => watch, moment: (element) => element.classList.add('moment'),
    format: { fmtRunTime: (n) => `${n.toFixed(1)} s` }, runTime: () => 10,
    selection: { set: (value) => selections.push(value) },
  };
  const dispose = mount(root, services);
  const emit = (type, value) => { const event = new Event(type); event.data = JSON.stringify(value); watch.dispatchEvent(event); };
  const publish = (served = 'real', revision = 0) => {
    states.get('/api/state/article')({ value: { hosts: { 'en.wikipedia.org': '10.0.0.10' }, reader: 'Firefox (scripted)', reader_host: 'workstation' } });
    states.get('/api/state/tamper')({ value: { on: revision > 0, revision, since_start: { secs: revision, nanos: 0 } } });
    states.get('/api/state/diff')({ value: fixture(served, revision) });
  };
  return { root, watch, states, services, requests, selections, dispose, emit, publish, closed: () => closed };
}
test('article columns mark changed text and keep observed reads separate from served state', async () => {
  const h = harness(); h.publish(); await settle();
  assert.equal(h.root.querySelectorAll('span.changed').length, 2);
  assert.equal(h.root.querySelector('img'), null);
  assert.match(h.root.textContent, /<img src=x>/);
  assert.match(h.root.querySelectorAll('.article-head').find((node) => node.classList.contains('real')).textContent, /Served now/);
  assert.match(h.root.textContent, /0 reads: 0 real, 0 tampered/);
  h.emit('event', read(1, 'real', 0));
  h.publish('tampered', 1);
  assert.match(h.root.querySelectorAll('.article-head').find((node) => node.classList.contains('tampered')).textContent, /Served now/);
  assert.match(h.root.querySelectorAll('.article-head').find((node) => node.classList.contains('real')).textContent, /Read by Firefox \(scripted\).*r0/);
  assert.match(h.root.textContent, /has not read this page since/);
  h.emit('event', read(2, 'tampered', 1)); h.emit('event', read(2, 'tampered', 1));
  assert.match(h.root.textContent, /2 reads: 1 real, 1 tampered/);
  assert.match(h.root.querySelectorAll('.article-head').find((node) => node.classList.contains('tampered')).textContent, /Read by Firefox \(scripted\).*r1/);
  h.root.querySelector('button.real').click();
  assert.equal(h.selections[0].event.seq, 1);
  assert.equal(h.selections[0].connection, 'connection');
  h.dispose();
});
test('switch sends current revision once, stays pending, and reports stale state without retry', async () => {
  const h = harness(); h.publish('tampered', 7); await settle();
  const button = h.root.querySelector('.article-switch'); button.click(); button.click();
  assert.equal(button.disabled, true); assert.match(button.textContent, /Changing/);
  assert.equal(h.requests.length, 1);
  assert.deepEqual(h.requests[0].body.command, { type: 'set_tampering', on: false, expected_revision: 7 });
  h.requests[0].reject({ body: { rejection: { reason: 'stale_revision', current: 8 } } }); await settle();
  assert.match(h.root.textContent, /changed elsewhere. Current revision 8/);
  assert.equal(h.requests.length, 1); assert.equal(button.disabled, false);
  h.dispose();
});
test('mount and dispose release subscriptions, listeners and an in flight command', async () => {
  const h = harness(); h.publish(); await settle();
  const nodes = h.root.querySelectorAll('button');
  nodes.find((node) => node.classList.contains('article-switch')).click();
  h.dispose();
  assert.equal(h.states.size, 0); assert.equal(h.watch.listenerCount, 0); assert.equal(h.closed(), true);
  assert.ok(nodes.every((node) => node.listenerCount === 0));
  assert.equal(h.requests[0].signal.aborted, true);
  h.requests[0].resolve({ status: 'applied', reply: { revision: 1 } }); await settle();
  assert.equal(h.root.children.length, 0);
});
test('only complete article reads on known hosts count and losses remain visible', async () => {
  const h = harness(); h.publish(); await settle();
  const events = [read(1, 'real', 0), read(2, 'tampered', 1), read(3, 'real', 0), read(4, 'real', 0)];
  events[1].fields.complete = false; events[2].fields.host = 'other.example'; events[3].fields.method = 'HEAD';
  h.emit('snapshot', { events, status: { incomplete: true } });
  assert.match(h.root.textContent, /1 retained read: 1 real, 0 tampered/);
  assert.match(h.root.textContent, /History is incomplete/);
  h.dispose();
});

test('applied replies use the world wire format', async () => {
  const h = harness(); h.publish(); await settle();
  h.root.querySelector('.article-switch').click();
  h.requests[0].resolve({ status: 'applied', reply: { applied: { revision: 1, since_start: { secs: 2, nanos: 0 }, changed: true } } });
  await settle();
  assert.equal(h.root.querySelector('.article-reply').textContent, '');
  assert.equal(h.root.querySelector('.article-switch').disabled, false);
  assert.doesNotMatch(h.root.textContent, /undefined/);
  h.dispose();
});
test('a chosen source stays selected until following reads is restored', async () => {
  const h = harness(); h.publish(); await settle();
  const diff = fixture();
  diff.topics[0].sources.push({ ...structuredClone(diff.topics[0].sources[0]), source: 'legislation' });
  h.states.get('/api/state/diff')({ value: diff });
  h.root.querySelector('.article-chips').children[1].click();
  h.emit('event', read(1, 'real', 0));
  assert.equal(h.root.querySelector('.article-chips').children[1].getAttribute('aria-pressed'), 'true');
  h.root.querySelector('.text-button').click();
  assert.equal(h.root.querySelector('.article-chips').children[0].getAttribute('aria-pressed'), 'true');
  h.dispose();
});
test('filtered history fills older reads and merges replayed events once', async () => {
  const h = harness(); h.publish();
  const calls = [];
  h.services.transport.get = async (path, { after }) => {
    calls.push([path, after]);
    return { rows: path.includes('reads') && !after ? [read(1, 'real', 0)] : [], next: 10 };
  };
  h.emit('snapshot', { events: [read(2, 'tampered', 1)] });
  await settle();
  assert.match(h.root.textContent, /2 reads: 1 real, 1 tampered/);
  assert.ok(calls.some(([path, after]) => path.includes('reads') && after === 10));
  h.emit('snapshot', { events: [read(2, 'tampered', 1)] }); await settle();
  assert.match(h.root.textContent, /2 reads: 1 real, 1 tampered/);
  h.dispose();
});

test('history gaps are visible even when the filtered response has no reads', async () => {
  const h = harness(); h.publish();
  h.services.transport.get = async () => ({ rows: [], next: 0, dropped: 3 });
  h.emit('snapshot', { events: [] }); await settle();
  assert.match(h.root.textContent, /History is incomplete/);
  assert.match(h.root.textContent, /0 retained reads/);
  h.dispose();
});

test('switch track and checked state follow published state while commands are pending', async () => {
  const h = harness(); h.publish();
  const button = h.root.querySelector('.article-switch');
  assert.equal(button.getAttribute('role'), 'switch');
  assert.equal(button.getAttribute('aria-checked'), 'false');
  assert.equal(button.querySelector('.article-switch-track').getAttribute('aria-hidden'), 'true');
  assert.ok(button.querySelector('.article-switch-knob'));
  assert.match(button.textContent, /Serving the real article/);
  button.click();
  assert.equal(button.getAttribute('aria-busy'), 'true');
  assert.match(h.root.querySelector('.article-reply').textContent, /Waiting/);
  h.requests[0].resolve({ status: 'pending' }); await settle();
  assert.match(h.root.querySelector('.article-reply').textContent, /Command pending/);
  assert.equal(h.requests.length, 1);
  h.publish('tampered', 1);
  assert.equal(button.getAttribute('aria-checked'), 'true');
  assert.match(button.textContent, /Serving the tampered article/);
  h.dispose();
});

test('read badges mark new observations once and revision mismatches become callouts', () => {
  const h = harness(), moments = [];
  h.services.moment = (node) => { node.classList.add('moment'); moments.push(node.textContent); };
  h.publish();
  assert.equal(h.root.querySelector('.article-read'), null);
  h.emit('event', read(1, 'real', 0));
  assert.equal(moments.length, 1);
  assert.match(h.root.textContent, /1 read: 1 real, 0 tampered/);
  assert.equal(h.root.querySelector('.article-read').textContent, '✓ Read by Firefox (scripted) · r0 · 1.0 s');
  assert.equal(h.root.querySelector('.article-read-note').classList.contains('moment'), false);
  h.publish('tampered', 1);
  assert.equal(moments.length, 1);
  assert.equal(h.root.querySelector('.article-read-note').classList.contains('moment'), true);
  assert.equal(h.root.querySelector('.article-read-note').textContent, 'Firefox has not read this page since the switch changed.');
  assert.equal(h.root.querySelector('.article-read').textContent, moments[0]);
  h.emit('event', read(2, 'tampered', 1));
  h.emit('event', read(2, 'tampered', 1));
  assert.equal(moments.length, 2);
  assert.equal(h.root.querySelector('.article-read-note').classList.contains('moment'), false);
  assert.match(h.root.querySelector('.article-history').textContent, /0.0 s – 10.0 s/);
  h.dispose();
});

test('reader identity comes from context even when reads arrive before it', () => {
  const h = harness();
  const other = read(1, 'real', 0); other.sandbox.name = 'reader-machine';
  h.emit('snapshot', { events: [other, read(2, 'tampered', 1)] });
  h.publish();
  h.states.get('/api/state/article')({ value: { hosts: { 'en.wikipedia.org': '10.0.0.10' }, reader: 'Browser (scripted)', reader_host: 'reader-machine' } });
  assert.match(h.root.textContent, /1 read: 1 real, 0 tampered/);
  assert.match(h.root.querySelector('.article-read').textContent, /Read by Browser \(scripted\).*r0/);
  h.dispose();
});

test('topic segments and source chips expose selection and delivery meaning', () => {
  const h = harness(); h.publish();
  const diff = fixture();
  for (const [topic, title] of [['another_topic', 'Television licensing in the United Kingdom'], ['third_topic', 'Apollo 11']]) {
    const item = { ...structuredClone(diff.topics[0]), topic };
    item.sources[0].real.title = title;
    item.sources.unshift({ ...structuredClone(item.sources[0]), source: 'other', url: 'https://other.example/article', real: { title: 'Other title', paragraphs: [] } });
    diff.topics.push(item);
  }
  h.states.get('/api/state/diff')({ value: diff });
  const topics = h.root.querySelector('.article-topics');
  assert.equal(topics.getAttribute('aria-label'), 'Topic');
  assert.equal(topics.children.length, 3);
  assert.deepEqual(topics.children.map((button) => button.textContent), ['Stream ripping', 'Television licensing in the United Kingdom', 'Apollo 11']);
  assert.ok(topics.children.every((button) => button.getAttribute('title') === button.textContent));
  assert.ok(h.root.querySelector('.article-topic-row').querySelector('.text-button'));
  assert.equal(h.root.querySelector('.article-history').querySelector('.text-button'), null);
  topics.children[1].click();
  assert.equal(h.root.querySelector('.article-topics').children[1].getAttribute('aria-pressed'), 'true');
  const chip = h.root.querySelector('.article-chips').children[1];
  assert.equal(chip.querySelector('.article-source-host').textContent, 'en.wikipedia.org');
  assert.equal(chip.getAttribute('aria-label'), 'en.wikipedia.org · real · unread');
  assert.equal(chip.querySelector('.article-source-state').textContent, 'Real');
  assert.equal(chip.querySelector('.article-source-read'), null);
  h.emit('event', { ...read(1, 'real', 0), fields: { ...read(1, 'real', 0).fields, topic: 'another_topic' } });
  const readChip = h.root.querySelector('.article-chips').children[1];
  assert.equal(readChip.querySelector('.article-source-state').textContent, 'Real');
  assert.equal(readChip.querySelector('.article-source-read').textContent, '✓ read');
  assert.equal(readChip.getAttribute('aria-label'), 'en.wikipedia.org · real · read');
  diff.topics[1].sources[1].served = 'tampered';
  h.states.get('/api/state/diff')({ value: diff });
  const tag = h.root.querySelector('.article-chips').children[1].querySelector('.article-source-state');
  assert.equal(tag.textContent, 'Tampered');
  assert.ok(tag.classList.contains('tampered'));
  h.dispose();
});

test('callout sentences capitalize the supplied reader name', () => {
  const h = harness(); h.publish();
  h.states.get('/api/state/article')({ value: { hosts: { 'en.wikipedia.org': '10.0.0.10' }, reader: 'in-world client (scripted)', reader_host: 'workstation' } });
  h.emit('event', read(1, 'real', 0));
  h.states.get('/api/state/diff')({ value: fixture('tampered', 1) });
  assert.equal(h.root.querySelector('.article-read-note').textContent, 'In-world client has not read this page since the switch changed.');
  assert.match(h.root.querySelector('.article-read').textContent, /Read by in-world client \(scripted\)/);
  h.dispose();
});
