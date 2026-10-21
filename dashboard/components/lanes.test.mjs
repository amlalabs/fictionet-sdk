import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createDocument, liveSubscriptions } from '../test-dom.mjs';
import { createServices } from '../page.mjs';
import { mount } from './packets.mjs';
import { chipText, conversationRows, dnsRow, kindOf, createLanes } from './lanes.mjs';

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
    const row = { ...p, tags };
    assert.deepEqual(conversationRows([row]), [row]);
  }
  for (const tags of [['gap'], ['malformed']]) {
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

test('combined HTTP/2 headers keep status chips short', () => {
  for (const info of ['HEADERS[13]: 200, DATA[13] 19 bytes', '200, DATA[7] 19 bytes...', 'HEADERS[7]: 404']) {
    assert.equal(chipText({ ...packets[8], proto: 'HTTP/2', info }), info.includes('404') ? '404' : '200');
  }
  assert.equal(chipText({ ...packets[7], proto: 'HTTP/2', info: 'HEADERS[13]: GET /topics (example.com)' }), 'GET /topics');
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

test('small ACKs and HTTP/2 control frames stay quiet regardless of retransmission tags', () => {
  const tcp = (flags, length, tags = []) => ({ ...packets[4], tags, info: `443 → 50153 [${flags}] Seq=1 Ack=1 Win=32768 Len=${length}${tags.includes('retransmission') ? ' [retransmission]' : ''}` });
  for (const tags of [[], ['retransmission'], ['decrypted'], ['reset']]) {
    for (const length of [0, 1]) assert.deepEqual(conversationRows([tcp('ACK', length, tags)]), []);
    for (const flags of ['SYN', 'SYN, ACK', 'FIN, ACK', 'RST, ACK']) {
      const row = tcp(flags, 1, tags);
      assert.deepEqual(conversationRows([row]), [row]);
    }
  }
  const controls = ['PING', 'PING ack', 'SETTINGS', 'SETTINGS ack', 'WINDOW_UPDATE[0] +12517377', 'WINDOW_UPDATE[1] +65535', 'PRIORITY[3]', 'GOAWAY NO_ERROR'];
  for (const info of controls) {
    const row = { ...packets[4], proto: 'HTTP/2', info, tags: ['decrypted'] };
    assert.deepEqual(conversationRows([row]), [], info);
    for (const tag of ['gap', 'malformed']) assert.deepEqual(conversationRows([{ ...row, tags: [tag] }]), [{ ...row, tags: [tag] }]);
  }
  const preface = { ...packets[4], proto: 'HTTP/2', info: 'Magic, SETTINGS, WINDOW_UPDATE[0] +12517377', tags: ['decrypted'] };
  assert.deepEqual(conversationRows([preface]), []);
  const opening = { ...preface, info: 'Magic, SETTINGS, WINDOW_UPDATE[0] +12517377, HEADERS[1]: GET /claude-code-releases/latest' };
  assert.deepEqual(conversationRows([opening]), [opening]);
  assert.equal(chipText(opening), 'GET /claude-code-rele…');
  assert.equal(chipText({ ...opening, info: 'SETTINGS ack, HEADERS[3]: 200, DATA[3] 19 bytes' }), '200');
  for (const info of ['GOAWAY INTERNAL_ERROR', 'RST_STREAM[1] CANCEL', 'HEADERS[1]: 200', 'DATA[1]']) {
    const row = { ...packets[4], proto: 'HTTP/2', info };
    assert.deepEqual(conversationRows([row]), [row]);
  }
});

test('quiet-only sites disappear in conversations and return with visible traffic', (t) => {
  const h = setup(t);
  const ack = { ...packets[4], tags: ['retransmission'], info: '443 → 50153 [ACK] Seq=0 Ack=1 Win=32768 Len=1 [retransmission]' };
  const ping = { ...ack, seq: 1001, proto: 'HTTP/2', info: 'PING ack', tags: ['decrypted'] };
  h.services.packetFilter.set('every');
  h.send([ack, ping]);
  assert.equal(h.root.querySelectorAll('.packet-lane').length, 1);
  assert.equal(h.root.querySelectorAll('.packet-chip.quiet').length, 2);
  assert.equal(h.root.querySelector('#prows').children.length, 2);
  h.services.packetFilter.set('conversations');
  assert.equal(h.root.querySelectorAll('.packet-lane').length, 0);
  assert.equal(h.root.querySelector('#prows').children.length, 0);
  h.send([{ ...ping, seq: 1002, info: 'HEADERS[1]: 200' }]);
  assert.equal(h.root.querySelectorAll('.packet-lane').length, 1);
  assert.equal(h.root.querySelectorAll('.packet-chip').length, 1);
  h.services.packetFilter.set('every');
  assert.equal(h.root.querySelector('#prows').children.length, 3);
});

test('connection resets and encrypted TLS closes are neutral and retain decoder text', (t) => {
  const h = setup(t);
  const reset = { ...packets[4], tags: ['reset'], info: '443 → 50153 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0' };
  const close = { ...reset, seq: 1001, proto: 'TLSv1.3', info: 'Encrypted Alert', tags: [] };
  h.send([reset, close]);
  assert.equal(kindOf(reset), 'tcp');
  assert.equal(kindOf(close), 'tcp');
  assert.equal(h.root.querySelectorAll('.bad').length, 0);
  const chips = h.root.querySelectorAll('.packet-chip');
  assert.deepEqual(chips.map((c) => c.textContent), ['RST·ACK', 'TLS close']);
  assert.equal(chips[1].getAttribute('title'), 'Encrypted Alert');
  assert.match(h.root.querySelector('#prows').textContent, /Encrypted Alert/);
  for (const tag of ['dns-error', 'malformed']) assert.equal(kindOf({ ...reset, tags: [tag] }), 'bad');
});

test('DNS record types join their queried name with address, empty and refused replies', (t) => {
  const h = setup(t);
  const cases = [
    ['A', 'A 185.42.118.20', [{ type: 'A', address: '185.42.118.20' }]],
    ['AAAA', 'AAAA 2001:db8::20', [{ type: 'AAAA', address: '2001:db8::20' }]],
    ['HTTPS', '', []],
    ['CNAME', 'CNAME bbc.example. A 185.42.118.20 AAAA 2001:db8::20', [{ type: 'A', address: '185.42.118.20' }, { type: 'AAAA', address: '2001:db8::20' }]],
    ['MX', 'MX 10 mail.example.', []],
    ['TXT', 'TXT "hello"', []],
    ['Unknown', '', []],
  ];
  let seq = 1000;
  for (const [type, answer, answers] of cases) {
    const host = `${type.toLowerCase()}.example`;
    const query = { ...packets[0], seq: seq++, t: seq, info: `Standard query 0xa17a ${type} ${host}` };
    const reply = { ...packets[1], seq: seq++, t: seq, info: `Standard query response 0xa17a ${type} ${host}${answer ? ` ${answer}` : ''}` };
    assert.deepEqual(dnsRow(query), { name: host, answers: [], back: false });
    assert.deepEqual(dnsRow(reply), { name: host, answers, back: true });
    assert.equal(chipText(query), 'DNS');
    assert.equal(chipText(reply), answers.map((a) => `${a.type} ${a.address}`).join(' · ') || 'DNS');
    h.send([query]);
    assert.ok(h.root.querySelectorAll('.packet-lane').some((lane) => lane.querySelector('b').textContent === host));
    h.send([reply]);
    assert.equal(h.root.querySelectorAll('.packet-lane').some((lane) => lane.querySelector('b').textContent === 'resolver'), false);
  }
  const query = { ...packets[0], seq: seq++, t: seq, info: 'Standard query 0xa17a HTTPS wiki.corp' };
  const reply = { ...packets[1], seq: seq++, t: seq, info: 'Standard query response 0xa17a HTTPS wiki.corp Non-Existent Domain', tags: ['dns-error'] };
  h.send([query, reply]);
  const lane = h.root.querySelectorAll('.packet-lane')[0];
  assert.equal(lane.querySelector('b').textContent, 'wiki.corp');
  assert.deepEqual(lane.querySelectorAll('.packet-chip').map((chip) => chip.textContent), ['DNS', 'no such name']);
  assert.equal(lane.querySelector('.bad').classList.contains('back'), true);
});

test('HTTPS queries and empty responses share the later address and connection lane', (t) => {
  const h = setup(t);
  h.send([
    { ...packets[0], info: 'Standard query 0xa17a HTTPS www.bbc.com' },
    { ...packets[1], info: 'Standard query response 0xa17a HTTPS www.bbc.com' },
    { ...packets[0], seq: 1000, t: 1000, info: 'Standard query 0xa17b A www.bbc.com' },
    { ...packets[1], seq: 1001, t: 1001, info: 'Standard query response 0xa17b A www.bbc.com A 185.42.118.20' },
    { ...packets[2], seq: 1002, t: 1002, dst: '185.42.118.20:443' },
  ]);
  const lanes = h.root.querySelectorAll('.packet-lane');
  assert.equal(lanes.length, 1);
  assert.equal(lanes[0].querySelector('b').textContent, 'www.bbc.com');
  assert.deepEqual(lanes[0].querySelectorAll('.packet-chip').map((chip) => chip.textContent), ['DNS', 'DNS', 'DNS', 'A 185.42.118.20', 'SYN']);
});

test('DATA totals and counts update one chip while retaining every packet row', (t) => {
  const h = setup(t, { motion: true });
  const data = { ...packets[8], proto: 'HTTP/2', info: 'DATA[1]', len: 1536 };
  h.send([{ ...packets[7], proto: 'HTTP/2', info: 'HEADERS[1]: GET / (www.google.com)' }, data]);
  const lane = h.root.querySelector('.packet-lane');
  const chip = lane.querySelectorAll('.packet-chip').at(-1);
  for (let i = 1; i < 5; i++) h.send([{ ...data, seq: 1000 + i, t: 1000 + i }]);
  assert.equal(lane.querySelectorAll('.packet-chip').length, 2);
  assert.equal(lane.querySelectorAll('.packet-chip').at(-1), chip);
  assert.equal(chip.textContent, 'DATA 7.5k×5');
  assert.equal(chip.querySelector('small').textContent, '×5');
  assert.equal(chip.classList.contains('back'), true);
  assert.equal(h.root.querySelector('#prows').children.length, 6);
  assert.equal(h.animations.filter((a) => a.duration === 160).length, 4);
  h.services.packetFilter.set('every');
  assert.equal(lane.parentNode, null);
  const replay = h.root.querySelector('.packet-lane');
  assert.deepEqual(replay.querySelectorAll('.packet-chip').map((c) => c.textContent), ['GET /', 'DATA 7.5k×5']);
  assert.equal(h.animations.filter((a) => a.duration === 160).length, 4);
});

test('DATA runs reset after another chip or direction and stay independent per lane', (t) => {
  const h = setup(t);
  const data = { ...packets[8], proto: 'HTTP/2', info: 'DATA[1]', len: 100 };
  const send = (row, seq) => h.send([{ ...row, seq, t: seq }]);
  send(data, 1000);
  send({ ...data, src: '192.0.2.9:443' }, 1001);
  send(data, 1002);
  send({ ...data, info: 'HEADERS[3]: 200' }, 1003);
  send(data, 1004);
  send({ ...data, src: data.dst, dst: data.src }, 1005);
  send(data, 1006);
  const lanes = h.root.querySelectorAll('.packet-lane');
  assert.deepEqual(lanes[0].querySelectorAll('.packet-chip').map((c) => c.textContent), ['DATA 200×2', '200', 'DATA 100', 'DATA 100', 'DATA 100']);
  assert.equal(lanes[1].querySelectorAll('.packet-chip').length, 1);
  assert.equal(h.root.querySelector('#prows').children.length, 7);
});

test('DATA merging keeps its final state and stops pulses under reduced motion', (t) => {
  const h = setup(t, { motion: true });
  const data = { ...packets[8], proto: 'HTTP/2', info: 'DATA[1]', len: 1536 };
  h.send([data, { ...data, seq: 1000, t: 1000 }]);
  assert.equal(h.animations.filter((a) => a.duration === 160).length, 1);
  h.media.matches = true;
  h.media.dispatchEvent(new Event('change'));
  assert.ok(h.animations.every((a) => a.cancelled));
  const count = h.animations.length;
  h.send([{ ...data, seq: 1001, t: 1001 }]);
  assert.equal(h.animations.length, count);
  assert.equal(h.root.querySelector('.packet-chip').textContent, 'DATA 4.5k×3');
  assert.equal(h.root.querySelector('#prows').children.length, 3);
});

test('a long DATA run preserves DNS, TLS and GET chips with motion disabled', (t) => {
  const h = setup(t);
  h.send(packets.slice(0, 9));
  const lane = h.root.querySelector('.packet-lane');
  const conversation = lane.querySelectorAll('.packet-chip');
  for (let i = 0; i < 20; i++) h.send([{ ...packets[8], seq: 1000 + i, t: 1000 + i, proto: 'HTTP/2', info: 'DATA[1]', len: 1536 }]);
  const chips = lane.querySelectorAll('.packet-chip');
  assert.deepEqual(chips.slice(0, -1), conversation);
  assert.equal(chips.at(-1).textContent, 'DATA 30.0k×20');
  assert.equal(h.root.querySelector('#prows').children.length, 28);
  assert.equal(h.animations.length, 0);
});

test('resets after a close are quiet only on the same connection', (t) => {
  const h = setup(t);
  const tcp = (info, t, extra = {}) => ({ ...packets[2], src: '10.0.0.2:40000', dst: '192.0.2.1:443', proto: 'TCP', tags: [], info, t, seq: 1000 + t, ...extra });
  const send = (p) => { h.send([p]); return h.root.querySelector('.packet-lane').querySelectorAll('.packet-chip').at(-1); };
  assert.equal(send(tcp('[SYN] Len=0', 1)).classList.contains('bad'), false);
  let rst = send(tcp('[RST, ACK] Len=0', 2, { tags: ['reset'] }));
  assert.equal(rst.classList.contains('quiet'), false);
  assert.equal(rst.classList.contains('tcp'), true);
  send(tcp('[FIN, ACK] Len=0', 3));
  rst = send(tcp('[RST, ACK] Len=0', 4));
  assert.equal(rst.classList.contains('quiet'), true);
  rst = send(tcp('[RST, ACK] Len=0', 5, { src: '10.0.0.2:40001' }));
  assert.equal(rst.classList.contains('quiet'), false);
  send(tcp('Encrypted Alert', 6, { proto: 'TLSv1.3', src: '192.0.2.1:443', dst: '10.0.0.2:40001' }));
  assert.equal(send(tcp('[RST, ACK] Len=0', 7, { src: '10.0.0.2:40001' })).classList.contains('quiet'), true);
  send(tcp('[SYN] Len=0', 8));
  assert.equal(send(tcp('[RST, ACK] Len=0', 9)).classList.contains('quiet'), false);
  rst = send(tcp('[RST, ACK] Len=0', 10, { tags: ['malformed'] }));
  assert.equal(rst.classList.contains('bad'), true);
  assert.equal(rst.classList.contains('quiet'), false);
  assert.equal(kindOf(tcp('[RST] Len=0', 11, { tags: ['reset'] })), 'tcp');
});

test('chips that cross the lane edge are hidden whole after insertion and resize', () => {
  const document = createDocument(), root = document.createElement('div');
  let resize, disconnected = false;
  document.defaultView = { ResizeObserver: class {
    constructor(fn) { resize = fn; }
    observe() {}
    disconnect() { disconnected = true; }
  } };
  const create = document.createElement;
  document.createElement = (tag) => {
    const node = create(tag);
    Object.defineProperty(node, 'offsetLeft', { get() { return root.edge ?? (node.parent?.children.indexOf(node) === 0 ? -1 : 10); } });
    return node;
  };
  const lanes = createLanes(root, { name: (value) => value, local: (value) => value.startsWith('10.0.0.2:'), addressFor: () => null, animate() {} });
  lanes.add({ ...packets[2], link: 'wire' }, false);
  lanes.add({ ...packets[3], link: 'wire' }, false);
  const chips = root.querySelectorAll('.packet-chip');
  assert.equal(chips[0].style.visibility, 'hidden');
  assert.equal(chips[1].style.visibility, '');
  root.edge = -10;
  resize();
  assert.ok(chips.every((chip) => chip.style.visibility === 'hidden'));
  root.edge = 0;
  resize();
  assert.ok(chips.every((chip) => chip.style.visibility === ''));
  lanes.dispose();
  assert.equal(disconnected, true);
});

test('packet times are printed only when the displayed time changes', (t) => {
  const h = setup(t);
  const p = { ...packets[7], info: 'GET / HTTP/1.1' };
  h.send([1, 1.001, 1.004, 2].map((time, i) => ({ ...p, seq: 1000 + i, t: time })));
  const times = () => h.root.querySelector('#prows').children.map((row) => row.children[0].textContent);
  assert.deepEqual(times(), ['2.00', '1.00', '', '']);
  h.send([{ ...p, seq: 1004, t: 2.001 }]);
  assert.deepEqual(times(), ['2.00', '', '1.00', '', '']);
  h.services.packetFilter.set('every');
  assert.deepEqual(times(), ['2.00', '', '1.00', '', '']);
});
