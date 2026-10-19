import { watchState } from './state.mjs';

// One owner for origin-scoped authorization, requests, streams and downloads.
export function createTransport({ state, setStatus = () => {}, onLogout = () => {}, tick, snapshot, upsertHost, removeHost, upsertGroup, removeGroup, upsertNode, removeNode, upsertEdge, removeEdge, counters, addEvent }, {
  fetch = globalThis.fetch, location = globalThis.location, history = globalThis.history, window = globalThis.window,
  signedOutMessage = 'Not signed in. Open the dashboard bootstrap URL to sign in. If it was already used, restart the dashboard first.',
  WebSocket = globalThis.WebSocket,
  storage, document = globalThis.document, URL = globalThis.URL,
  setTimeout = globalThis.setTimeout, clearTimeout = globalThis.clearTimeout,
} = {}) {
  const page = new URL(location.href);
  const key = 'fictionet_token';
  let lifetime = new AbortController();
  const streams = new Set();
  const sockets = new Set();
  const downloads = new Map();
  let bootstrap = 0;
  let token;
  let events;
  let stopWatch;
  let watching = false;

  function stop() {
    stopWatch?.();
    lifetime.abort();
    for (const source of streams) source.close();
    for (const socket of sockets) socket.close();
    sockets.clear();
    for (const [url, timer] of downloads) {
      clearTimeout(timer);
      URL.revokeObjectURL(url);
    }
    downloads.clear();
    token = null;
  }

  function close() {
    window?.removeEventListener('hashchange', hashchange);
    stop();
  }

  function logout() {
    stop();
    try { storage?.removeItem(key); } catch { /* Storage may be disabled. */ }
    if (state) state.connected = false;
    onLogout();
    setStatus('ended', signedOutMessage);
  }

  // Endpoints are fixed; values are query parameters, never destinations.
  const segment = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
  const observation = ['egress', 'world', 'graph', 'counters', 'events', 'link', 'keylog', 'watch', 'packets', 'packet', 'pcap'];
  function endpoint(path, method) {
    if (method === 'POST' && ['/api/bootstrap', '/api/ticket', '/api/lease'].includes(path)) return path;
    if (method === 'DELETE' && path === '/api/lease') return path;
    if (method === 'GET' && (path === '/api/page' || path === '/api/states/stream' || path === '/api/export/events' || path === '/api/export/packets' || observation.some((op) => path === `/api/${op}`))) return path;
    const parts = path.split('/');
    if (parts[0] !== '' || parts[1] !== 'api' || !segment(parts[3])) throw new Error('Invalid page endpoint');
    if (parts.length === 4 && (
      (method === 'GET' && ['state', 'event-table'].includes(parts[2])) ||
      (method === 'POST' && parts[2] === 'command')
    )) return path;
    if (method === 'GET' && parts.length === 5 && parts[2] === 'host' && parts[4] === 'links') return path;
    throw new Error('Invalid page endpoint');
  }

  function send(op, params, signal, bearer = token, method = op === 'bootstrap' ? 'POST' : 'GET', body) {
    const path = endpoint(op.startsWith('/') ? op : `/api/${op}`, method);
    const url = new URL(path, page.origin);
    url.search = new URLSearchParams(params).toString();
    return fetch(url.href, {
      method,
      headers: { Authorization: `Bearer ${bearer}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      credentials: 'omit', mode: 'same-origin', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
      signal: signal ? AbortSignal.any([lifetime.signal, signal]) : lifetime.signal,
    });
  }

  function takeFragment() {
    const current = new URL(location.href);
    const fragment = new URLSearchParams(current.hash.slice(1));
    // Clear the displayed URL before any asynchronous work or API request.
    if (current.hash) history.replaceState(null, '', current.pathname + current.search);
    return fragment;
  }

  async function authorize(fragment) {
    const attempt = ++bootstrap;
    const signal = lifetime.signal;
    try {
      storage ??= globalThis.sessionStorage;
      const saved = storage.getItem(key);
      if (fragment.has('token')) {
        if (fragment.size !== 1 || !fragment.get('token')) throw new Error('Invalid bootstrap');
        const candidate = fragment.get('token');
        if (candidate !== saved) storage.removeItem(key);
        const response = await send('bootstrap', {}, undefined, candidate);
        if (signal.aborted || attempt !== bootstrap) return false;
        if (response.status !== 204 && candidate !== saved) throw new Error('Bootstrap failed');
        storage.setItem(key, candidate);
        token = candidate;
      } else {
        token = saved;
      }
      if (!token) throw new Error('Token required');
      return true;
    } catch {
      if (!signal.aborted && attempt === bootstrap) logout();
      return false;
    }
  }

  let ready = authorize(takeFragment());
  function hashchange() {
    const fragment = takeFragment();
    if (!fragment.has('token')) return;
    const reconnect = lifetime.signal.aborted;
    if (reconnect) lifetime = new AbortController();
    ready = authorize(fragment);
    if (reconnect && watching) connect();
  }
  window?.addEventListener('hashchange', hashchange);

  async function request(op, params, signal, method, body) {
    endpoint(op.startsWith('/') ? op : `/api/${op}`, method || 'GET');
    if (!await ready || lifetime.signal.aborted) throw new Error('The page is closed. Reload to reconnect.');
    const response = await send(op, params, signal, token, method, body);
    if (response.status === 401 || response.status === 403) {
      logout();
      throw new Error(signedOutMessage);
    }
    return response;
  }

  function stream(op, params) {
    const source = new EventTarget();
    const controller = new AbortController();
    let timer;
    let reader;
    source.close = () => {
      controller.abort();
      clearTimeout(timer);
      void reader?.cancel().catch(() => {});
      streams.delete(source);
    };
    const stopped = () => controller.signal.aborted || lifetime.signal.aborted;
    const emit = (name, data) => {
      if (stopped()) return;
      const event = new Event(name);
      event.data = data;
      source.dispatchEvent(event);
      if (name === 'world_error' || name === 'end') source.close();
    };
    async function run() {
      try {
        const response = await request(op, params, controller.signal);
        if (!response.ok || response.headers.get('Content-Type')?.split(';')[0] !== 'text/event-stream') {
          let error = `Stream request failed: HTTP ${response.status}`;
          try {
            const body = await response.json();
            if (typeof body.error === 'string') error = body.error;
            else error += ' (missing error reason)';
          } catch (e) {
            error += ` (could not read error response: ${e.message})`;
          }
          emit('world_error', JSON.stringify({ error }));
          return;
        }
        if (stopped()) {
          await response.body.cancel();
          return;
        }
        reader = response.body.getReader();
        emit('open');
        const decoder = new TextDecoder();
        let line = '', name = '', data = [], cr = false;
        const finishLine = () => {
          if (!line) {
            if (data.length) emit(name || 'message', data.join('\n'));
            name = '';
            data = [];
          } else if (!line.startsWith(':')) {
            const colon = line.indexOf(':');
            const field = colon < 0 ? line : line.slice(0, colon);
            const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '');
            if (field === 'event') name = value;
            if (field === 'data') data.push(value);
          }
          line = '';
        };
        while (!stopped()) {
          const { value, done } = await reader.read();
          if (done) break;
          for (const char of decoder.decode(value, { stream: true })) {
            if (char === '\n' && cr) { cr = false; continue; }
            cr = char === '\r';
            if (char === '\r' || char === '\n') finishLine();
            else line += char;
          }
        }
      } catch {
        // A dropped connection replays retained history on the next request.
      } finally {
        await reader?.cancel().catch(() => {});
        reader = undefined;
        if (!stopped()) {
          emit('error', JSON.stringify({ error: 'Connection dropped. Reconnecting.' }));
          if (!stopped()) timer = setTimeout(run, 1000);
        }
      }
    }
    streams.add(source);
    void run();
    return source;
  }

  function connect(observer) {
    watching = true;
    if (observer) ({ state, setStatus, tick, snapshot, upsertHost, removeHost, upsertGroup, removeGroup, upsertNode, removeNode, upsertEdge, removeEdge, counters, addEvent } = observer);
    stopWatch?.();
    events = stream('watch', {});
    const source = events;
    const unbind = watchState(source, { state, setStatus, tick, snapshot, upsertHost, removeHost, upsertGroup, removeGroup, upsertNode, removeNode, upsertEdge, removeEdge, counters, addEvent });
    stopWatch = () => {
      unbind();
      if (events === source) events = null;
    };
    return () => { watching = false; stopWatch?.(); };
  }

  function packetStream(list, reconnected = () => {}) {
    const source = stream('packets', { link: list });
    let opened = false;
    source.addEventListener('open', () => {
      if (opened) reconnected();
      opened = true;
    });
    return source;
  }

  function packet(p, signal) {
    return request('packet', { link: p.link, seq: p.seq }, signal);
  }

  async function download(kind, list = '') {
    if (!['pcap', 'events', 'packets'].includes(kind)) throw new Error('Unknown download');
    const exported = kind !== 'pcap';
    const response = await request(exported ? `/api/export/${kind}` : kind, exported ? (list ? { host: list } : {}) : { link: list });
    if (!response.ok) throw new Error('Download unavailable');
    const blob = await response.blob();
    if (lifetime.signal.aborted) return;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = kind === 'events' ? 'fictionet-events.jsonl' : (list.includes(',') ? 'fictionet-links.pcapng' : `fictionet-${list}.pcapng`).replace(/[^a-zA-Z0-9.-]/g, '');
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    downloads.set(url, setTimeout(() => {
      URL.revokeObjectURL(url);
      downloads.delete(url);
    }, 60000));
  }

  async function json(method, path, params, body, signal) {
    const response = await request(path, params, signal, method, body);
    const value = response.status === 204 ? null : await response.json();
    if (!response.ok) {
      const error = new Error(value?.error || value?.rejection?.message || value?.rejection?.reason || `HTTP ${response.status}`);
      error.status = response.status;
      error.body = value;
      throw error;
    }
    return value;
  }

  const get = (path, params = {}, signal) => json('GET', path, params, undefined, signal);
  const post = (path, body, signal) => json('POST', path, {}, body, signal);
  const remove = (path, body, signal) => json('DELETE', path, {}, body, signal);

  // One stream carries every state topic a page shows: `topics` maps each
  // topic id to the revision already held, or undefined for a snapshot.
  function stateStream(topics) {
    const entries = Object.entries(topics);
    const valid = ([id, after]) => segment(id) && (after === undefined || (Number.isSafeInteger(after) && after >= 0));
    if (!entries.length || entries.length > 64 || !entries.every(valid)) throw new Error('Invalid state topics');
    const cursors = entries.filter(([, after]) => after !== undefined).map(([id, after]) => `${id}:${after}`);
    return stream('/api/states/stream', { topics: entries.map(([id]) => id).join(','), ...(cursors.length ? { after: cursors.join(',') } : {}) });
  }

  async function socket(capability, host, signal) {
    if (!['screen', 'terminal'].includes(capability) || !segment(host)) throw new Error('Invalid console path');
    const result = await post('/api/ticket', { capability, host }, signal);
    if (lifetime.signal.aborted || signal?.aborted) throw new Error('Console request cancelled');
    if (typeof result.ticket !== 'string' || !/^[a-f0-9]{64}$/.test(result.ticket) ||
        typeof result.session !== 'string' || !/^[a-f0-9]{64}$/.test(result.session)) throw new Error('Invalid console ticket');
    const url = new URL(`/ws/${capability}/${host}`, page.origin);
    url.protocol = page.protocol === 'https:' ? 'wss:' : 'ws:';
    url.searchParams.set('ticket', result.ticket);
    const socket = new WebSocket(url.href);
    socket.binaryType = 'arraybuffer';
    sockets.add(socket);
    const cancel = () => socket.close();
    signal?.addEventListener('abort', cancel, { once: true });
    socket.addEventListener('close', () => {
      sockets.delete(socket);
      signal?.removeEventListener('abort', cancel);
    }, { once: true });
    return { socket, session: result.session };
  }

  return { get, post, delete: remove, stateStream, socket, watch: () => stream('watch', {}), connect, packetStream, packet, download, logout, close };
}
