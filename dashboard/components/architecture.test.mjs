import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { architecture, mount } from './architecture.mjs';
import { createState } from '../state.mjs';
import { createDocument, Element } from '../test-dom.mjs';
import { createSelection } from '../selection.mjs';

const packets = JSON.parse(readFileSync(new URL('./fixtures/search-packets.json', import.meta.url)));
const hosts = [{ name: 'workstation', sandbox: 'workstation', claude_code: true, codex: true, firefox: true, terminal: 'terminal' }];
const declarations = [
  { title: 'DNS', source: 'dns', kinds: [], detail: 'name', outside: false },
  { title: 'Simulated web', source: 'adaptive', kinds: ['request'], detail: 'path', outside: false },
  { title: 'Package mirror', source: 'mirror', kinds: ['request'], detail: 'path', outside: false },
  { title: 'Model gateway', source: 'model', kinds: ['tool'], detail: 'query', outside: false },
  { title: 'Model calls', source: 'model', kinds: ['call'], detail: 'provider', outside: true },
  { title: 'Sign-in', source: 'signin', kinds: ['connection'], detail: 'host', outside: true },
];
const recording = {
  t: 9, started: 0, ended: false, hosts: [], groups: [],
  nodes: [{ id: 'vm', kind: 'sandbox', name: 'workstation' }, { id: 'world', kind: 'task', name: 'web' }, { id: 'admin', kind: 'sandbox', name: 'jump' }],
  edges: [{ id: 'traffic', a: 'vm', b: 'world' }, { id: 'management', a: 'admin', b: 'world' }],
  counters: { traffic: [packets.filter((p) => p.side === 0).length, 0, packets.filter((p) => p.side === 1).length, 0], management: [9000, 50000, 9000, 50000] },
  events: [
    { seq: 1, source: 'dns', kind: 'query', node: 'world', fields: { name: 'www.google.com' } },
    { seq: 2, source: 'adaptive', kind: 'request', node: 'world', fields: { path: '/search?q=corvane' } },
    { seq: 3, source: 'mirror', kind: 'request', node: 'world', fields: { path: '/ubuntu/dists/noble/InRelease' } },
    { seq: 4, source: 'model', kind: 'tool', node: 'world', sandbox: { name: 'workstation' }, local: '10.0.0.1:443', peer: '10.0.0.2:49152', fields: { tool: 'web_search', query: 'corvane gateway vulnerability details', source: 'world' } },
    { seq: 5, source: 'model', kind: 'tool', node: 'world', sandbox: { name: 'jump' }, fields: { query: 'administration', source: 'world' } },
  ],
};

test('architecture counts observed traffic and uses world service declarations', () => {
  const model = createState(); model.snapshot(recording);
  const rows = architecture(model.state, hosts, declarations);
  assert.deepEqual(rows.map(({ title, count, events }) => ({ title, count, events })), [
    { title: 'workstation', count: packets.length, events: ['tool'] },
    { title: 'DNS', count: 1, events: ['www.google.com'] },
    { title: 'Simulated web', count: 1, events: ['/search?q=corvane'] },
    { title: 'Package mirror', count: 1, events: ['/ubuntu/dists/noble/InRelease'] },
    { title: 'Model gateway', count: 1, events: ['corvane gateway vulnerability details'] },
    { title: 'Model calls', count: 0, events: [] },
    { title: 'Sign-in', count: 0, events: [] },
  ]);
  assert.ok(rows.every((row) => !row.links.includes('management')));
  assert.deepEqual(rows[0].programs, ['Claude Code', 'Codex', 'Firefox', 'Terminal']);
  assert.equal(rows[4].column, 1);
  assert.equal(rows[5].column, 2);
  const renamed = architecture(model.state, hosts, [{ ...declarations[3], title: 'Searches', source: 'other' }]);
  assert.equal(renamed[1].count, 0);
});

test('architecture is still without observations and pulses only for arriving traffic', (t) => {
  const document = createDocument(), root = document.createElement('section');
  const model = createState(), subscribers = new Set(), animations = [];
  const previous = Element.prototype.animate;
  Element.prototype.animate = function () { animations.push(this); return { finished: Promise.resolve(), cancel() {} }; };
  t.after(() => { Element.prototype.animate = previous; });
  const selection = createSelection(), pairs = [], opened = [];
  const stop = mount(root, {
    hosts, architecture: declarations, selection,
    graph: { state: model.state, subscribe(fn) { subscribers.add(fn); return () => subscribers.delete(fn); } },
    packetPair: { set: (value) => pairs.push(value) }, showPanel: (kind) => opened.push(kind),
  });
  const emit = (name, value) => subscribers.forEach((fn) => fn(name, value));
  assert.equal(animations.length, 0);
  assert.ok(root.querySelectorAll('.architecture-count').every((node) => node.textContent === '0'));
  emit('status', {}); emit('counters', {});
  assert.equal(animations.length, 0);
  model.snapshot(recording); emit('snapshot', recording);
  assert.equal(animations.length, 0);
  const event = { ...recording.events[3], seq: 6 };
  model.addEvent(event); emit('event', event);
  assert.equal(animations.length, 1);
  assert.equal(animations[0].querySelector('strong').textContent, 'Model gateway');
  const gateway = root.querySelectorAll('.architecture-box')[4];
  gateway.click();
  assert.deepEqual(selection.get().links, ['traffic']);
  assert.equal(opened.at(-1), 'packets');
  assert.deepEqual(pairs.at(-1).pairs, [['10.0.0.1:443', '10.0.0.2:49152'], ['10.0.0.1:443', '10.0.0.2:49152']]);
  const call = { seq: 7, source: 'model', kind: 'call', node: 'world', fields: { provider: 'api.anthropic.com' } };
  model.addEvent(call); emit('event', call);
  assert.equal(animations.length, 3);
  assert.equal(animations.at(-1).classList.contains('architecture-out'), true);
  emit('status', {}); emit('counters', {});
  assert.equal(animations.length, 3);
  stop();
  assert.equal(subscribers.size, 0);
  assert.equal(root.children.length, 0);
});
