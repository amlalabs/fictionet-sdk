// Tests for transport.mjs: `node --test dashboard/transport.test.mjs`.
// The Rust test `dashboard_js` runs these when node is installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createTransport } from './transport.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));

function transport(t, { fragment = '', token = 'secret', bootstrap = 204, onLogout } = {}) {
  const requests = [], sources = [], calls = [], downloads = [], revoked = [];
  const timers = new Map(), stored = new Map(token ? [['fictionet_token', token]] : []);
  const window = new EventTarget(), anchors = new Set(), delays = [];
  const state = { connected: false, ended: false, sideDirty: false };
  const location = { href: `http://127.0.0.1:7878/${fragment}` };
  const reducers = { state, onLogout };
  for (const name of ['setStatus', 'tick', 'snapshot', 'upsertGroup', 'removeGroup', 'upsertNode', 'removeNode', 'upsertEdge', 'removeEdge', 'counters', 'addEvent']) {
    reducers[name] = (...args) => calls.push([name, ...args]);
  }
  const storage = { getItem: (key) => stored.get(key), setItem: (key, value) => stored.set(key, value), removeItem: (key) => stored.delete(key) };
  let nextResponse;
  const api = createTransport(reducers, {
    location, storage, window,
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
      if (url.endsWith('/bootstrap')) {
        assert.equal(location.href, 'http://127.0.0.1:7878/');
        if (stored.has('fictionet_token')) assert.equal(options.headers.Authorization, `Bearer ${stored.get('fictionet_token')}`);
        return typeof bootstrap === 'function' ? bootstrap() : new Response(null, { status: bootstrap });
      }
      if (nextResponse) { const response = nextResponse; nextResponse = undefined; return response; }
      if (/\/(watch|packets)(\?|$)/.test(url)) {
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
    ...api, state, requests, sources, calls, timers, stored, location, downloads, revoked, anchors, delays,
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

test('fragment navigation can sign in an unsigned tab and resume its watch', async (t) => {
  const h = transport(t, { token: null });
  h.connect();
  await settle();
  assert.deepEqual(h.calls.at(-1), ['setStatus', 'ended', 'Not signed in. Open the dashboard bootstrap URL to sign in. If it was already used, restart the dashboard first.']);
  h.navigate('#token=secret');
  assert.equal(h.location.href, 'http://127.0.0.1:7878/');
  await settle();
  assert.equal(h.stored.get('fictionet_token'), 'secret');
  assert.equal(h.sources.length, 1);
  h.sources[0].emit('waiting');
  await settle();
  assert.deepEqual(h.calls.at(-1), ['setStatus', 'waiting', 'Waiting for a world']);
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

test('connect parses split UTF-8, CRLF, comments and multiline data and routes named events', async (t) => {
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
  assert.deepEqual(h.calls[0], ['setStatus', 'waiting', 'Waiting for a world']);
  assert.deepEqual(h.calls.slice(1, -1), events.map(([name, data, reducer]) => [reducer, name.endsWith('_end') ? data.id : data]));
  assert.deepEqual(h.calls.at(-1), ['upsertGroup', { id: 'g2', name: 'café' }]);
  source.emit('ended', { t: 3 });
  source.emit('end');
  await settle();
  assert.deepEqual(h.calls.slice(-2), [['tick', 3], ['setStatus', 'ended', 'World stopped']]);
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

test('packet reconnect sends authorization and resets history before replay', async (t) => {
  const h = transport(t);
  const seen = [];
  const source = h.packetStream('e1,e2', () => seen.push('reset'));
  source.addEventListener('packet', (e) => seen.push(JSON.parse(e.data).seq));
  await settle();
  h.sources[0].emit('packet', { seq: 1 });
  h.sources[0].end();
  await settle();
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
  const h = transport(t);
  h.connect();
  await settle();
  h.sources[0].end();
  await settle();
  assert.deepEqual(h.calls.at(-1), ['setStatus', 'connecting', 'Reconnecting']);
  h.respond(new Response(null, { status: 401 }));
  h.retry();
  await settle();
  assert.equal(h.requests[1].headers.Authorization, 'Bearer secret');
  assert.equal(h.stored.size, 0);
  assert.equal(h.timers.size, 0);
});

test('authorization failure closes the packet view before signing in again', async (t) => {
  for (const status of [401, 403]) {
    let packetView;
    const h = transport(t, { onLogout: () => { packetView.close(); packetView = null; } });
    h.connect();
    packetView = h.packetStream('e1');
    await settle();
    h.respond(new Response(null, { status }));
    await assert.rejects(h.packet({ link: 'e1', seq: 1 }));
    assert.equal(packetView, null);
    assert.ok(h.sources.every((source) => source.cancelled));
    assert.equal(h.stored.size, 0);
    h.navigate('#token=new-secret');
    await settle();
    assert.equal(h.sources.length, 3);
    assert.equal(packetView, null);
    packetView = h.packetStream('e1');
    await settle();
    assert.equal(h.sources.length, 4);
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
