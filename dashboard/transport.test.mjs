// Tests for transport.mjs: `node --test dashboard/transport.test.mjs`.
// The Rust test `dashboard_js` runs these when node is installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransport, SIGN_IN } from './transport.mjs';
import { watchState } from './state.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

function transport(t, { fragment = '', token = 'secret', bootstrap = 204 } = {}) {
  const requests = [], sources = [], calls = [], downloads = [], revoked = [], sockets = [];
  const timers = new Map(), stored = new Map(token ? [['fictionet_token', token]] : []);
  const window = new EventTarget(), anchors = new Set(), delays = [];
  const state = { connected: false, ended: false, sideDirty: false };
  const location = { href: `http://127.0.0.1:7878/${fragment}` };
  // A graph that records what the watch applies to it.
  const reducers = { state };
  for (const name of ['tick', 'snapshot', 'upsertHost', 'removeHost', 'upsertGroup', 'removeGroup', 'upsertNode', 'removeNode', 'upsertEdge', 'removeEdge', 'counters', 'addEvent']) {
    reducers[name] = (...args) => calls.push([name, ...args]);
  }
  const storage = { getItem: (key) => stored.get(key), setItem: (key, value) => stored.set(key, value), removeItem: (key) => stored.delete(key) };
  let nextResponse;
  const api = createTransport({ setStatus: (...args) => calls.push(['setStatus', ...args]) }, {
    location, storage, window,
    WebSocket: class extends EventTarget {
      constructor(url) { super(); this.url = url; this.closed = false; sockets.push(this); }
      close() { this.closed = true; this.dispatchEvent(new Event('close')); }
    },
    history: { replaceState(_, __, path) { location.href = `http://127.0.0.1:7878${path}`; } },
    setTimeout(fn, delay) { const id = Symbol(); timers.set(id, fn); delays.push(delay); return id; },
    clearTimeout(id) { timers.delete(id); },
    URL: class extends URL {
      static createObjectURL(blob) { assert.ok(blob instanceof Blob); return 'blob:download'; }
      static revokeObjectURL(url) { revoked.push(url); }
    },
    document: {
      body: { appendChild(anchor) { anchors.add(anchor); } },
      createElement() {
        return {
          click() { assert.ok(anchors.has(this)); downloads.push({ href: this.href, filename: this.download }); },
          remove() { anchors.delete(this); },
        };
      },
    },
    fetch: async (url, options) => {
      requests.push({ url, ...options });
      assert.equal(new URL(url).origin, 'http://127.0.0.1:7878');
      assert.equal(options.credentials, 'omit');
      assert.equal(options.redirect, 'error');
      assert.equal(options.mode, 'same-origin');
      assert.equal(options.cache, 'no-store');
      if (url.endsWith('/bootstrap')) {
        assert.equal(options.method, 'POST');
        assert.equal(location.href, 'http://127.0.0.1:7878/');
        if (stored.has('fictionet_token')) assert.equal(options.headers.Authorization, `Bearer ${stored.get('fictionet_token')}`);
        return typeof bootstrap === 'function' ? bootstrap() : new Response(null, { status: bootstrap });
      }
      if (nextResponse) { const response = nextResponse; nextResponse = undefined; return response; }
      if (/\/(watch|packets|stream)(\?|$)/.test(url)) {
        const source = { cancelled: false };
        const body = new ReadableStream({
          start(controller) { source.controller = controller; },
          cancel() { source.cancelled = true; },
        });
        source.bytes = (bytes) => source.controller.enqueue(bytes);
        source.emit = (name, data = {}) => source.bytes(new TextEncoder().encode(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`));
        source.end = () => source.controller.close();
        sources.push(source);
        return new Response(body, { headers: { 'Content-Type': 'text/event-stream; charset=utf-8' } });
      }
      return new Response('download or detail');
    },
  });
  t.after(api.close);
  return {
    ...api, state, requests, sources, calls, timers, stored, location, downloads, revoked, anchors, delays, sockets,
    // The page's watch, applied to the recording graph; returns the source.
    connect() { const source = api.watch(); watchState(source, reducers); return source; },
    navigate(fragment) { location.href = `http://127.0.0.1:7878/${fragment}`; window.dispatchEvent(new Event('hashchange')); },
    respond(response) { nextResponse = response; },
    retry() { const [id, fn] = timers.entries().next().value; timers.delete(id); fn(); },
  };
}

test('bootstrap removes the URL before exchange, stores only after success and sends bearer requests', async (t) => {
  const h = transport(t, { fragment: '#token=secret%2B%3B%2Ftoken', token: 'old' });
  assert.equal(h.location.href, 'http://127.0.0.1:7878/');
  assert.equal(h.stored.size, 0);
  await h.packet({ link: 'e1', seq: 42 });
  assert.equal(h.stored.get('fictionet_token'), 'secret+;/token');
  assert.deepEqual(h.requests.map((r) => new URL(r.url).pathname), ['/api/bootstrap', '/api/packet']);
  for (const r of h.requests) assert.equal(r.headers.Authorization, 'Bearer secret+;/token');
  assert.match(h.requests[1].url, /link=e1&seq=42$/);
});

test('missing, invalid or used bootstrap cannot open an API stream', async (t) => {
  for (const options of [{ token: null }, { fragment: '#token=one&token=two' }, { fragment: '#token=used', bootstrap: 401 }]) {
    const h = transport(t, options);
    h.connect();
    await settle();
    assert.equal(h.sources.length, 0);
    assert.equal(h.stored.size, 0);
    assert.equal(h.timers.size, 0);
    assert.deepEqual(h.calls.at(-1), ['setStatus', 'ended', `Not signed in. ${SIGN_IN}`]);
    await assert.rejects(h.packet({ link: 'e1', seq: 1 }));
  }
});

test('a reload with a used bootstrap keeps the identical stored token', async (t) => {
  const h = transport(t, { fragment: '#token=secret', bootstrap: 401 });
  assert.equal(h.location.href, 'http://127.0.0.1:7878/');
  await h.packet({ link: 'e1', seq: 1 });
  assert.equal(h.stored.get('fictionet_token'), 'secret');
  assert.deepEqual(h.requests.map((r) => new URL(r.url).pathname), ['/api/bootstrap', '/api/packet']);
  assert.ok(h.requests.every((r) => r.headers.Authorization === 'Bearer secret'));
  assert.deepEqual(h.calls, []);
});

test('fragment navigation clears the URL immediately and keeps the matching session on rejection', async (t) => {
  const h = transport(t, { token: 'secret+;/token', bootstrap: 401 });
  h.connect();
  await settle();
  h.navigate('#token=secret%2B%3B%2Ftoken');
  assert.equal(h.location.href, 'http://127.0.0.1:7878/');
  await h.packet({ link: 'e1', seq: 1 });
  assert.equal(h.stored.get('fictionet_token'), 'secret+;/token');
  assert.equal(h.sources[0].cancelled, false);
  assert.deepEqual(h.requests.map((r) => new URL(r.url).pathname), ['/api/watch', '/api/bootstrap', '/api/packet']);
  assert.ok(h.requests.every((r) => r.headers.Authorization === 'Bearer secret+;/token'));
  assert.deepEqual(h.calls, []);
});

test('fragment navigation signs in an unsigned tab', async (t) => {
  const h = transport(t, { token: null });
  await settle();
  await assert.rejects(h.packet({ link: 'e1', seq: 1 }));
  h.navigate('#token=secret');
  assert.equal(h.location.href, 'http://127.0.0.1:7878/');
  await h.packet({ link: 'e1', seq: 1 });
  assert.equal(h.stored.get('fictionet_token'), 'secret');
  assert.equal(h.requests.at(-1).headers.Authorization, 'Bearer secret');
});

test('fragment navigation rejects a used bootstrap that differs from the stored token', async (t) => {
  const h = transport(t, { bootstrap: 401 });
  h.connect();
  await settle();
  h.navigate('#token=other');
  assert.equal(h.location.href, 'http://127.0.0.1:7878/');
  await assert.rejects(h.packet({ link: 'e1', seq: 1 }));
  assert.equal(h.stored.size, 0);
  assert.equal(h.sources[0].cancelled, true);
  assert.equal(h.timers.size, 0);
});

test('the watch parses split UTF-8, CRLF, comments and multiline data and routes named events', async (t) => {
  const h = transport(t);
  h.connect();
  await settle();
  assert.equal(h.requests[0].headers.Authorization, 'Bearer secret');
  const source = h.sources[0];
  source.emit('waiting');
  const events = [
    ['snapshot', { t: 1, nodes: [], edges: [] }, 'snapshot'],
    ['group', { id: 'g1', name: 'office' }, 'upsertGroup'],
    ['group_end', { id: 'g1' }, 'removeGroup'],
    ['node', { id: 'a', name: 'router' }, 'upsertNode'],
    ['node_end', { id: 'a' }, 'removeNode'],
    ['edge', { id: 'e1', a: 'a', b: 'b' }, 'upsertEdge'],
    ['edge_end', { id: 'e1' }, 'removeEdge'],
    ['counters', { t: 2, edges: { e1: [1, 100, 2, 200] } }, 'counters'],
    ['event', { kind: 'drop', node: 'a', fields: { count: 2 } }, 'addEvent'],
  ];
  for (const [name, data] of events) source.emit(name, data);
  const wire = ': ping\r\nevent: group\r\ndata: {"id":"g2",\r\ndata: "name":"café"}\r\n\r\n';
  for (const byte of new TextEncoder().encode(wire)) source.bytes(new Uint8Array([byte]));
  await settle();
  assert.equal(h.state.connected, true);
  assert.deepEqual(h.calls.slice(0, -1), events.map(([name, data, reducer]) => [reducer, name.endsWith('_end') ? data.id : data]));
  assert.deepEqual(h.calls.at(-1), ['upsertGroup', { id: 'g2', name: 'café' }]);
  source.emit('ended', { t: 3 });
  source.emit('end');
  await settle();
  assert.deepEqual(h.calls.at(-1), ['tick', 3]);
  assert.equal(h.state.ended, true);
  assert.equal(h.state.sideDirty, true);
  assert.equal(source.cancelled, true);
  assert.equal(h.timers.size, 0);
});

test('end closes the watch without retrying', async (t) => {
  const h = transport(t);
  h.connect();
  await settle();
  h.sources[0].emit('end');
  await settle();
  assert.equal(h.state.ended, true);
  assert.equal(h.sources[0].cancelled, true);
  assert.equal(h.timers.size, 0);
});

test('a watch refusal is terminal and keeps its reason, even after ended', async (t) => {
  for (const ended of [false, true]) {
    const h = transport(t), reasons = [];
    const source = h.connect();
    source.addEventListener('world_error', (event) => reasons.push(JSON.parse(event.data).error));
    await settle();
    if (ended) h.sources[0].emit('ended', { t: 3 });
    h.sources[0].emit('world_error', { error: 'the world closed during a reply value' });
    h.sources[0].end();
    await settle();
    assert.equal(h.timers.size, 0);
    assert.equal(h.state.ended, true);
    assert.deepEqual(reasons, ['the world closed during a reply value']);
  }
});

test('packet refusal is terminal and preserves the reason', async (t) => {
  const h = transport(t), seen = [];
  const source = h.packetStream('e1');
  source.addEventListener('world_error', (e) => seen.push(JSON.parse(e.data)));
  await settle();
  h.sources[0].emit('world_error', { error: 'no such link' });
  h.sources[0].end();
  await settle();
  assert.deepEqual(seen, [{ error: 'no such link' }]);
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests[0].signal.aborted, true);
});

test('a merged refusal leaves other links readable until the terminal end', async (t) => {
  const h = transport(t), seen = [];
  const source = h.packetStream('e1,e2');
  for (const name of ['link_error', 'packet', 'end']) {
    source.addEventListener(name, (e) => seen.push([name, JSON.parse(e.data)]));
  }
  await settle();
  h.sources[0].emit('link_error', { link: 'e1', error: 'no such link' });
  await settle();
  assert.equal(h.sources[0].cancelled, false);
  h.sources[0].emit('packet', { link: 'e2', seq: 1 });
  h.sources[0].emit('end', { reason: 'every link finished' });
  h.sources[0].end();
  await settle();
  assert.deepEqual(seen, [
    ['link_error', { link: 'e1', error: 'no such link' }],
    ['packet', { link: 'e2', seq: 1 }],
    ['end', { reason: 'every link finished' }],
  ]);
  assert.equal(h.timers.size, 0);
});

test('HTTP refusal reasons reach the watch and packet stream without retry', async (t) => {
  for (const status of [400, 502]) {
    const h = transport(t);
    h.respond(Response.json({ error: 'this world has too many watched links' }, { status }));
    const reasons = [];
    h.connect().addEventListener('world_error', (event) => reasons.push(JSON.parse(event.data).error));
    await settle();
    assert.deepEqual(reasons, ['this world has too many watched links']);
    assert.equal(h.state.ended, true);
    const seen = [];
    h.respond(Response.json({ error: 'no such link' }, { status }));
    h.packetStream('e1').addEventListener('world_error', (e) => seen.push(JSON.parse(e.data)));
    await settle();
    assert.deepEqual(seen, [{ error: 'no such link' }]);
    assert.equal(h.timers.size, 0);
  }
});

test('a busy page server is tried again, not taken as a refusal', async (t) => {
  const h = transport(t);
  const errors = [], refusals = [], snapshots = [];
  h.respond(Response.json({ error: 'too many streams' }, { status: 503 }));
  const source = h.stateStream({ leases: undefined, 'host-alpha': 4 });
  source.addEventListener('error', (e) => errors.push(JSON.parse(e.data)));
  source.addEventListener('world_error', (e) => refusals.push(JSON.parse(e.data)));
  source.addEventListener('snapshot', (e) => snapshots.push(JSON.parse(e.data)));
  await settle();
  assert.deepEqual(refusals, []);
  assert.deepEqual(errors, [{ error: 'The page server is busy (too many streams). Reconnecting.' }]);
  assert.deepEqual(h.delays, [1000]);
  h.retry();
  await settle();
  h.sources[0].emit('snapshot', { topic: 'leases', revision: 1, value: {} });
  await settle();
  assert.deepEqual(snapshots.map((snapshot) => snapshot.topic), ['leases']);
  assert.equal(h.requests.length, 2);
  for (const request of h.requests) assert.equal(new URL(request.url).searchParams.get('after'), 'host-alpha:4');
  source.close();
  await settle();
  assert.equal(h.timers.size, 0);
});

test('packet reconnect sends authorization and resets history before replay', async (t) => {
  const h = transport(t);
  const seen = [];
  const source = h.packetStream('e1,e2', () => seen.push('reset'));
  const errors = [];
  source.addEventListener('error', (e) => errors.push(JSON.parse(e.data)));
  source.addEventListener('packet', (e) => seen.push(JSON.parse(e.data).seq));
  await settle();
  h.sources[0].emit('packet', { seq: 1 });
  h.sources[0].end();
  await settle();
  assert.deepEqual(errors, [{ error: 'Connection dropped. Reconnecting.' }]);
  h.retry();
  await settle();
  h.sources[1].emit('packet', { seq: 1 });
  await settle();
  assert.deepEqual(seen, [1, 'reset', 1]);
  assert.equal(h.requests.length, 2);
  for (const r of h.requests) {
    assert.equal(r.headers.Authorization, 'Bearer secret');
    assert.equal(new URL(r.url).searchParams.get('link'), 'e1,e2');
  }
  source.close();
  assert.equal(h.requests[1].signal.aborted, true);
  await settle();
  assert.equal(h.timers.size, 0);
});

test('watch reconnects with bearer; authorization rejection signs out without retry', async (t) => {
  const h = transport(t), errors = [];
  h.connect().addEventListener('error', (event) => errors.push(JSON.parse(event.data).error));
  await settle();
  h.sources[0].end();
  await settle();
  assert.deepEqual(errors, ['Connection dropped. Reconnecting.']);
  h.respond(new Response(null, { status: 401 }));
  h.retry();
  await settle();
  assert.equal(h.requests[1].headers.Authorization, 'Bearer secret');
  assert.equal(h.stored.size, 0);
  assert.equal(h.timers.size, 0);
});

test('authorization failure closes every stream until the tab signs in again', async (t) => {
  for (const status of [401, 403]) {
    const h = transport(t);
    h.connect();
    h.packetStream('e1');
    await settle();
    h.respond(new Response(null, { status }));
    await assert.rejects(h.packet({ link: 'e1', seq: 1 }));
    assert.ok(h.sources.every((source) => source.cancelled));
    assert.equal(h.stored.size, 0);
    h.navigate('#token=new-secret');
    await settle();
    assert.equal(h.sources.length, 2, 'signing in again opens nothing by itself');
    h.packetStream('e1');
    await settle();
    assert.equal(h.sources.length, 3);
    assert.equal(h.requests.at(-1).headers.Authorization, 'Bearer new-secret');
    assert.equal(h.sources.at(-1).cancelled, false);
  }
});

test('close and logout abort streams and requests and cancel scheduled reconnects', async (t) => {
  for (const action of ['close', 'logout']) {
    const h = transport(t);
    h.connect();
    h.packetStream('e1');
    await h.packet({ link: 'e1', seq: 1 });
    h.sources[0].end();
    await settle();
    assert.equal(h.timers.size, 1);
    h[action]();
    await settle();
    assert.ok(h.requests.every((r) => r.signal.aborted));
    assert.equal(h.sources[1].cancelled, true);
    assert.equal(h.timers.size, 0);
    assert.equal(h.stored.size, action === 'close' ? 1 : 0);
    await assert.rejects(h.packet({ link: 'e1', seq: 2 }));
  }
});

test('detail cancellation propagates and download destinations cannot be supplied by callers', async (t) => {
  const h = transport(t);
  const controller = new AbortController();
  const malicious = 'http://127.0.0.1:9000/steal?token=x&seq=7#';
  await h.packet({ link: malicious, seq: 1 }, controller.signal);
  controller.abort();
  assert.equal(h.requests[0].signal.aborted, true);
  assert.equal(new URL(h.requests[0].url).searchParams.get('link'), malicious);
  await h.download('pcap', malicious);
  assert.deepEqual(h.downloads, [
    { href: 'blob:download', filename: `fictionet-${malicious}.pcapng`.replace(/[^a-zA-Z0-9.-]/g, '') },
  ]);
  await assert.rejects(h.download(malicious));
  assert.equal(h.requests.length, 2);
  assert.ok(h.requests.every((r) => r.headers.Authorization === 'Bearer secret'));
  assert.equal(h.anchors.size, 0);
  assert.deepEqual(h.revoked, []);
  assert.deepEqual(h.delays, [60000]);
  h.retry();
  assert.deepEqual(h.revoked, ['blob:download']);
});

test('closing during bootstrap cannot restore the token after its response arrives', async (t) => {
  let finish;
  const h = transport(t, { fragment: '#token=secret', token: null, bootstrap: () => new Promise((resolve) => { finish = resolve; }) });
  h.close();
  finish(new Response(null, { status: 204 }));
  await settle();
  assert.equal(h.stored.size, 0);
  assert.equal(h.requests[0].signal.aborted, true);
  await assert.rejects(h.packet({ link: 'e1', seq: 1 }));
  assert.equal(h.requests.length, 1);
});

test('non-stream HTTP responses stop a stream without reconnecting', async (t) => {
  for (const response of [new Response(null, { status: 204 }), new Response(null, { status: 404 }), new Response('{}')]) {
    const h = transport(t);
    h.respond(response);
    h.packetStream('e1');
    await settle();
    assert.equal(h.requests.length, 1);
    assert.equal(h.timers.size, 0);
    assert.equal(h.stored.get('fictionet_token'), 'secret');
  }
});

test('page JSON requests use fixed paths, bearers and JSON bodies', async (t) => {
  const h = transport(t);
  for (const path of ['/api/page', '/api/state/host-alpha', '/api/event-table/exchanges', '/api/host/alpha/links', '/api/world', '/api/events']) {
    h.respond(Response.json({ value: path }));
    assert.deepEqual(await h.get(path), { value: path });
    assert.equal(h.requests.at(-1).method, 'GET');
    assert.equal(h.requests.at(-1).body, undefined);
  }
  for (const [method, path] of [['post', '/api/command/traffic'], ['post', '/api/lease'], ['delete', '/api/lease'], ['post', '/api/ticket']]) {
    const body = { host: 'alpha', command: { running: false }, request_id: 'request' };
    h.respond(Response.json({ status: 'applied' }));
    assert.deepEqual(await h[method](path, body), { status: 'applied' });
    const request = h.requests.at(-1);
    assert.equal(request.method, method.toUpperCase());
    assert.equal(request.body, JSON.stringify(body));
    assert.equal(request.headers['Content-Type'], 'application/json');
  }
  assert.ok(h.requests.every((r) => r.headers.Authorization === 'Bearer secret'));
  h.respond(Response.json({ status: 'rejected', rejection: { reason: 'stale_revision', current: 4 } }, { status: 409 }));
  await assert.rejects(h.post('/api/command/traffic', {}), (error) => error.status === 409 && error.body.rejection.current === 4);
});

test('page paths reject foreign origins, traversal, encoded segments and wrong methods before fetch', async (t) => {
  const h = transport(t);
  for (const path of [
    'https://example.com/api/page', '//example.com/api/page', '/api/state/../page',
    '/api/state/%2e%2e', '/api/state/a/b', '/api/state/', '/api/state/a?x=1',
    '/api/state/a#token=x', '/api/state/a.b', `/api/state/${'a'.repeat(129)}`,
    '/api/host/a/links/extra', '/api/unknown',
  ]) await assert.rejects(h.get(path));
  await assert.rejects(h.post('/api/page', {}));
  await assert.rejects(h.delete('/api/command/traffic', {}));
  for (const id of ['../leases', '%2f', '', 'a,b', 'a:1']) assert.throws(() => h.stateStream({ [id]: undefined }));
  for (const after of [-1, 1.5, '3', null]) assert.throws(() => h.stateStream({ leases: after }));
  assert.throws(() => h.stateStream({}));
  assert.throws(() => h.stateStream(Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`t${i}`, undefined]))));
  await assert.rejects(h.get('/api/state/leases/stream'));
  for (const [capability, host] of [['screen/alpha', 'alpha'], ['screen', '../alpha'], ['terminal', ''], ['screen', undefined]]) {
    await assert.rejects(h.socket(capability, host));
  }
  assert.equal(h.requests.length, 0);
});

test('one state stream carries every topic, sends revisions and closes with the transport', async (t) => {
  const h = transport(t), seen = [];
  const stream = h.stateStream({ leases: 4, 'host-alpha': undefined });
  stream.addEventListener('snapshot', (event) => seen.push(JSON.parse(event.data)));
  await settle();
  assert.equal(h.requests[0].url, 'http://127.0.0.1:7878/api/states/stream?topics=leases%2Chost-alpha&after=leases%3A4');
  assert.equal(h.requests[0].headers.Authorization, 'Bearer secret');
  h.sources[0].emit('snapshot', { revision: 5, value: { alpha: { holder: null } } });
  h.sources[0].emit('snapshot', { revision: 6, value: { alpha: { holder: 'a' } } });
  await settle();
  assert.deepEqual(seen.map((v) => v.revision), [5, 6]);
  h.close();
  await settle();
  assert.equal(h.sources[0].cancelled, true);
  assert.equal(h.timers.size, 0);
});

test('sockets use a single use ticket in the query and never the bearer', async (t) => {
  for (const action of ['close', 'logout']) {
    const h = transport(t);
    const ticket = 'a'.repeat(64), session = 'b'.repeat(64);
    h.respond(Response.json({ ticket, session, expires_in: 30 }));
    const result = await h.socket('screen', 'alpha');
    assert.equal(result.session, session);
    assert.equal(result.socket, h.sockets[0]);
    assert.equal(result.socket.url, `ws://127.0.0.1:7878/ws/screen/alpha?ticket=${ticket}`);
    assert.equal(result.socket.binaryType, 'arraybuffer');
    assert.equal(h.requests[0].headers.Authorization, 'Bearer secret');
    assert.equal(h.requests[0].url, 'http://127.0.0.1:7878/api/ticket');
    assert.deepEqual(JSON.parse(h.requests[0].body), { capability: 'screen', host: 'alpha' });
    h[action]();
    assert.equal(result.socket.closed, true);
    await assert.rejects(h.socket('screen', 'alpha'));
    assert.equal(h.sockets.length, 1);
  }
});

test('refused and cancelled console requests never open a socket', async (t) => {
  const h = transport(t);
  h.respond(Response.json({ error: 'beta is still booting' }, { status: 404 }));
  await assert.rejects(h.socket('terminal', 'beta'), /beta is still booting/);
  assert.equal(h.sockets.length, 0);
  h.respond(Response.json({ ticket: 'not a ticket', session: 'bad' }));
  await assert.rejects(h.socket('screen', 'alpha'), /Invalid console ticket/);
  assert.equal(h.sockets.length, 0);
  let finish;
  h.respond(new Promise((resolve) => { finish = resolve; }));
  const pending = h.socket('screen', 'alpha');
  await settle();
  h.close();
  finish(Response.json({ ticket: 'a'.repeat(64), session: 'b'.repeat(64) }));
  await assert.rejects(pending, /cancelled/);
  assert.equal(h.sockets.length, 0);
});

test('disposing a console closes its socket and releases download timers on transport close', async (t) => {
  const h = transport(t), controller = new AbortController();
  h.respond(Response.json({ ticket: 'a'.repeat(64), session: 'b'.repeat(64) }));
  const { socket } = await h.socket('terminal', 'alpha', controller.signal);
  controller.abort();
  assert.equal(socket.closed, true);
  await h.download('pcap', 'e1');
  assert.equal(h.timers.size, 1);
  h.close();
  assert.equal(h.timers.size, 0);
  assert.deepEqual(h.revoked, ['blob:download']);
});

test('authorization refusal on page JSON routes also closes open consoles', async (t) => {
  for (const status of [401, 403]) {
    const h = transport(t);
    h.respond(Response.json({ ticket: 'a'.repeat(64), session: 'b'.repeat(64) }));
    const { socket } = await h.socket('screen', 'alpha');
    h.respond(Response.json({ error: 'not signed in' }, { status }));
    await assert.rejects(h.post('/api/lease', { host: 'alpha', session: 'b'.repeat(64) }));
    assert.equal(socket.closed, true);
    assert.equal(h.stored.size, 0);
    assert.equal(h.timers.size, 0);
  }
});
