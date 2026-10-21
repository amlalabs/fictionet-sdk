import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createDocument, liveSubscriptions } from '../test-dom.mjs';
import { createServices } from '../page.mjs';
import { mount } from './packets.mjs';
import { chipText, conversationRows, dnsRow } from './lanes.mjs';

const packets = JSON.parse(readFileSync(new URL('./fixtures/search-packets.json', import.meta.url)));

function setup(t, { names = new Map(), motion = false, host = 'workstation' } = {}) {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const media = Object.assign(new EventTarget(), { matches: !motion });
  document.defaultView = { matchMedia: () => media };
  const frames = new Map(), animations = [], states = new Map(), subscriptions = new Set();
  let nextFrame = 0;
  const before = { requestAnimationFrame: globalThis.requestAnimationFrame, cancelAnimationFrame: globalThis.cancelAnimationFrame };
  globalThis.requestAnimationFrame = (fn) => { frames.set(++nextFrame, fn); return nextFrame; };
  globalThis.cancelAnimationFrame = (id) => frames.delete(id);
  const create = document.createElement;
  document.createElement = (tag) => {
    const node = create(tag);
    node.animate = (_, options) => {
      const animation = { duration: options.duration, finished: new Promise(() => {}), cancel() { this.cancelled = true; } };
      animations.push(animation);
      return animation;
    };
    return node;
  };
  let source;
  const transport = {
    get: async () => ({ links: ['wire'] }),
    packetStream() {
      source = Object.assign(new EventTarget(), { close() { this.closed = true; } });
      return source;
    },
  };
  const services = createServices(transport);
  services.hosts = [{ name: host, sandbox: 'workstation', status: '/host' }];
  services.state = (path, fn) => { states.set(path, fn); return () => states.delete(path); };
  services.hostLabel = (name) => name;
  const graph = { state: { known: true, nodes: new Map([['guest', { name: 'workstation', kind: 'sandbox' }]]), edges: new Map([['wire', { id: 'wire', a: 'guest', b: 'net' }]]) }, subscribe(fn) { subscriptions.add(fn); return () => subscriptions.delete(fn); } };
  Object.defineProperty(services, 'graph', { value: graph });
  const counts = [services.endpointNames, services.packetFilter, services.selection].map((value) => liveSubscriptions(value));
  services.endpointNames.set(names);
  const stop = mount(root, services, { compact: true });
  states.get('/host')({ value: { addresses: ['10.0.0.2'] } });
  const frame = () => { const pending = [...frames.values()]; frames.clear(); pending.forEach((fn) => fn()); };
  const send = (rows) => {
    for (const row of rows) {
      const event = new Event('packet'); event.data = JSON.stringify({ ...row, link: 'wire' }); source.dispatchEvent(event);
    }
    frame();
  };
  t.after(() => { stop(); Object.assign(globalThis, before); });
  return { root, services, states, subscriptions, frames, animations, media, counts, stop, frame, send, source: () => source };
}

test('recorded DNS rows name the answer and TCP fragments stay out of conversations', () => {
  assert.equal(packets.length, 200);
  assert.equal(packets[0].t < 60 && packets.at(-1).t < 60, true);
  assert.deepEqual(dnsRow(packets[1]), { name: 'www.google.com', answers: [{ type: 'A', address: '142.250.180.4' }], back: true });
  const shown = conversationRows(packets);
  const ack = packets.find((p) => p.proto === 'TCP' && /\[ACK\].*Len=0\b/.test(p.info));
  const fragment = packets.find((p) => /part of a longer message/.test(p.info));
  assert.ok(ack && fragment);
  assert.equal(shown.includes(ack), false);
  assert.equal(shown.includes(fragment), false);
  for (const row of packets.filter((p) => /\[(?:SYN|FIN|RST)/.test(p.info))) assert.ok(shown.includes(row));
  assert.ok(shown.some((p) => p.proto === 'HTTP'));
  assert.equal(chipText(packets[1]), 'A 142.250.180.4');
  assert.equal(chipText({ ...packets[7], info: 'GET /topics HTTP/1.1' }), 'GET /topics');
  assert.deepEqual(dnsRow({ ...packets[0], info: 'Standard query 0x1234 A cafe' }).answers, []);
});

test('DNS and decoded traffic share a named lane with reply borders and accessible locks', (t) => {
  const h = setup(t);
  h.send(packets.slice(0, 9));
  assert.equal(h.root.querySelectorAll('.packet-lane').length, 1);
  const lane = h.root.querySelector('.packet-lane');
  assert.equal(lane.querySelector('b').textContent, 'www.google.com');
  assert.match(lane.textContent, /142.250.180.4DNSA 142.250.180.4SYNSYN·ACKClient HelloServer HelloCertificateFinishedGET/);
  assert.equal(lane.querySelectorAll('.back').length, 6);
  const rows = h.root.querySelector('#prows').children;
  assert.equal(rows.length, 8);
  assert.equal(rows[0].children[1].textContent, 'google.com → workstation');
  assert.equal(rows.at(-1).children[1].textContent, 'workstation → resolver');
  const locks = h.root.querySelectorAll('.packet-unlock');
  assert.equal(locks.length, 3);
  locks.forEach((lock) => assert.equal(lock.getAttribute('aria-label'), 'Decrypted'));
  assert.equal(h.animations.length, 0);
});

test('the packet filter restores retained ACK and payload rows without reopening the stream', (t) => {
  const h = setup(t);
  h.send(packets.slice(0, 30));
  const source = h.source();
  const rows = () => h.root.querySelector('#prows').children;
  const before = rows().length;
  h.services.packetFilter.set('every');
  assert.equal(rows().length, 30);
  assert.ok(rows().some((row) => row.classList.contains('quiet')));
  h.services.packetFilter.set('conversations');
  assert.equal(rows().length, before);
  assert.equal(h.source(), source);
  assert.equal(source.closed, undefined);
});

test('host status and page names take precedence over DNS and late names repaint routes', (t) => {
  const h = setup(t, { names: new Map([['142.250.180.4', 'registry.example'], ['10.0.0.2', 'wrong.example']]) });
  h.send(packets.slice(0, 9));
  const route = () => h.root.querySelector('#prows').children[0].children[1].textContent;
  assert.equal(route(), 'registry.example → workstation');
  assert.equal(h.root.querySelector('.packet-lane').querySelector('b').textContent, 'registry.example');
  h.services.endpointNames.set(new Map([['142.250.180.4', 'www.renamed.example']]));
  assert.equal(route(), 'renamed.example → workstation');
  h.services.endpointNames.set(new Map());
  assert.equal(route(), 'google.com → workstation');
});

test('lanes and chips stay bounded, rows stay at forty, and disposal ends work', (t) => {
  const h = setup(t, { motion: true });
  const rows = [];
  for (let site = 0; site < 9; site++) for (let i = 0; i < 14; i++) rows.push({ ...packets[2], seq: site * 14 + i, t: site * 14 + i, dst: `192.0.2.${site}:443` });
  rows.forEach((row) => h.send([row]));
  assert.equal(h.root.querySelectorAll('.packet-lane').length, 7);
  for (const lane of h.root.querySelectorAll('.packet-lane')) assert.equal(lane.querySelectorAll('.packet-chip').length, 11);
  assert.equal(h.root.querySelector('#prows').children.length, 40);
  assert.equal(h.frames.size, 0);
  assert.ok(h.animations.some((a) => a.duration === 240));
  assert.ok(h.animations.some((a) => a.duration === 220));
  assert.ok(h.animations.some((a) => a.duration === 200));
  h.media.matches = true; h.media.dispatchEvent(new Event('change'));
  assert.ok(h.animations.every((a) => a.cancelled));
  const count = h.animations.length;
  h.send([{ ...rows[0], seq: 999, t: 999 }]);
  assert.equal(h.animations.length, count);
  h.stop();
  assert.equal(h.source().closed, true);
  assert.equal(h.frames.size, 0);
  assert.equal(h.states.size, 0);
  assert.equal(h.subscriptions.size, 0);
  assert.deepEqual(h.counts.map((count) => count()), [0, 0, 0]);
  assert.equal(h.root.querySelector('#plist').listenerCount, 0);
});

test('unknown TCP payload and tagged errors remain visible', () => {
  const p = { ...packets[4], info: '1 → 2 [ACK, PSH] Seq=1 Len=26' };
  assert.deepEqual(conversationRows([p]), [p]);
  for (const tags of [['reset'], ['malformed'], ['gap'], ['retransmission']]) {
    const row = { ...packets[4], tags };
    assert.deepEqual(conversationRows([row]), [row]);
  }
});

test('decrypted TCP payload is hidden while its application rows stay visible', () => {
  const payloads = packets.filter((p) => p.proto === 'TCP' && p.tags.includes('decrypted'));
  assert.ok(payloads.length > 0);
  const shown = conversationRows(packets);
  payloads.forEach((p) => assert.equal(shown.includes(p), false));
  packets.filter((p) => p.proto.startsWith('HTTP')).forEach((p) => assert.ok(shown.includes(p)));
});

test('a DNS alias shares an address lane and old traffic keeps its time order', (t) => {
  const h = setup(t, { names: new Map([['142.250.180.4', 'alias.example']]) });
  h.send(packets.slice(0, 9));
  assert.equal(h.root.querySelectorAll('.packet-lane').length, 1);
  h.send([{ ...packets[2], seq: 1000, t: 1000, dst: '192.0.2.1:443' }]);
  const first = h.root.querySelectorAll('.packet-lane')[0];
  h.send([{ ...packets[2], seq: 1001, t: 1 }]);
  assert.equal(h.root.querySelectorAll('.packet-lane')[0], first);
  assert.equal(chipText({ ...packets[8], info: 'HTTP/1.1 200 OK' }), '200');
  assert.equal(chipText({ ...packets[2], info: '1 → 2 [ACK, FIN] Len=0' }), 'FIN·ACK');
});

test('refused DNS names have red reply chips and no address', (t) => {
  const h = setup(t);
  const query = { ...packets[0], info: 'Standard query 0x1234 A wiki.corp' };
  const reply = { ...packets[1], info: 'Standard query response 0x1234 A wiki.corp Non-Existent Domain', tags: ['dns-error'] };
  h.send([query, reply]);
  const lane = h.root.querySelector('.packet-lane');
  assert.equal(lane.querySelector('b').textContent, 'wiki.corp');
  assert.match(lane.textContent, /no addressDNSno such name/);
  assert.equal(lane.querySelector('.bad').classList.contains('back'), true);
  assert.equal(h.root.querySelector('#prows').children[0].classList.contains('bad'), true);
  assert.equal(h.root.querySelector('#plist').getAttribute('tabindex'), '0');
});

test('shell lanes use the declared host addresses for other apps and IPv6', (t) => {
  const h = setup(t, { host: 'rw-desktop' });
  h.send(packets.slice(0, 9));
  assert.equal(h.root.querySelectorAll('.packet-lane').length, 1);
  assert.equal(h.root.querySelector('#prows').children[0].children[1].textContent, 'google.com → rw-desktop');
  h.states.get('/host')({ value: { addresses: ['2001:db8::1'] } });
  h.send([{ ...packets[2], seq: 1000, t: 1000, src: '[2001:db8::1]:1234', dst: '[2001:db8::2]:443' }]);
  assert.equal(h.root.querySelector('#prows').children[0].children[1].textContent, 'rw-desktop → [2001:db8::2]:443');
  assert.match(h.root.querySelectorAll('.packet-lane')[0].textContent, /2001:db8::2/);
});


test('model requests and responses use the same lane and decrypted rows as other sites', (t) => {
  const h = setup(t, { names: new Map([['160.79.104.10', 'api.anthropic.com']]) });
  const request = { ...packets[7], src: '10.0.0.2:40000', dst: '160.79.104.10:443', proto: 'HTTP/2', info: 'HEADERS[1]: POST /v1/messages (api.anthropic.com)' };
  const response = { ...packets[8], src: request.dst, dst: request.src, proto: 'HTTP/2', info: 'HEADERS[1]: 200' };
  const data = { ...response, seq: 1000, t: 1000, len: 4198, info: 'DATA[1]' };
  h.send([request, response, data]);
  const lane = h.root.querySelector('.packet-lane');
  assert.equal(lane.querySelector('b').textContent, 'api.anthropic.com');
  assert.match(lane.textContent, /POST \/v1\/messages200DATA 4.1k/);
  assert.equal(lane.querySelectorAll('.back').length, 2);
  assert.equal(h.root.querySelectorAll('.packet-unlock').length, 3);
});
