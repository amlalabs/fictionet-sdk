// One owner for origin-scoped authorization, requests, streams and downloads.
export function createTransport({ state, setStatus = () => {}, onLogout = () => {}, tick, snapshot, upsertGroup, removeGroup, upsertNode, removeNode, upsertEdge, removeEdge, counters, addEvent }, {
  fetch = globalThis.fetch, location = globalThis.location, history = globalThis.history, window = globalThis.window,
  storage, document = globalThis.document, URL = globalThis.URL,
  setTimeout = globalThis.setTimeout, clearTimeout = globalThis.clearTimeout,
} = {}) {
  const page = new URL(location.href);
  const key = 'fictionet_token';
  let lifetime = new AbortController();
  const streams = new Set();
  let bootstrap = 0;
  let token;
  let events;

  function stop() {
    lifetime.abort();
    for (const source of streams) source.close();
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
    setStatus('ended', 'Not signed in. Open the dashboard bootstrap URL to sign in. If it was already used, restart the dashboard first.');
  }

  // Endpoints are fixed; values are query parameters, never destinations.
  function send(op, params, signal, bearer = token) {
    if (!['bootstrap', 'watch', 'packets', 'packet', 'pcap'].includes(op)) throw new Error('Unknown dashboard endpoint');
    const url = new URL(`/api/${op}`, page.origin);
    url.search = new URLSearchParams(params).toString();
    return fetch(url.href, {
      headers: { Authorization: `Bearer ${bearer}` },
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
    if (reconnect && events) connect();
  }
  window?.addEventListener('hashchange', hashchange);

  async function request(op, params, signal) {
    if (!await ready || lifetime.signal.aborted) throw new Error('Dashboard is closed');
    const response = await send(op, params, signal);
    if (response.status === 401 || response.status === 403) {
      logout();
      throw new Error('Dashboard authorization failed');
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
    };
    async function run() {
      try {
        const response = await request(op, params, controller.signal);
        if (!response.ok || response.headers.get('Content-Type')?.split(';')[0] !== 'text/event-stream') {
          emit('error');
          source.close();
          await response.body?.cancel();
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
          emit('error');
          if (!stopped()) timer = setTimeout(run, 1000);
        }
      }
    }
    streams.add(source);
    void run();
    return source;
  }

  function connect() {
    events?.close();
    events = stream('watch', {});
    events.addEventListener('waiting', () => {
      state.connected = true;
      setStatus('waiting', 'Waiting for a world');
    });
    events.addEventListener('snapshot', (e) => snapshot(JSON.parse(e.data)));
    events.addEventListener('group', (e) => upsertGroup(JSON.parse(e.data)));
    events.addEventListener('group_end', (e) => removeGroup(JSON.parse(e.data).id));
    events.addEventListener('node', (e) => upsertNode(JSON.parse(e.data)));
    events.addEventListener('node_end', (e) => removeNode(JSON.parse(e.data).id));
    events.addEventListener('edge', (e) => upsertEdge(JSON.parse(e.data)));
    events.addEventListener('edge_end', (e) => removeEdge(JSON.parse(e.data).id));
    events.addEventListener('counters', (e) => counters(JSON.parse(e.data)));
    events.addEventListener('event', (e) => addEvent(JSON.parse(e.data)));
    events.addEventListener('ended', (e) => {
      tick(JSON.parse(e.data).t);
      state.ended = true;
      setStatus('ended', 'World stopped');
      state.sideDirty = true;
    });
    events.addEventListener('end', () => {
      events.close();
      if (!state.ended) setStatus('ended', 'The world closed');
      state.ended = true;
    });
    events.addEventListener('error', () => {
      if (!state.ended) setStatus('connecting', 'Reconnecting');
    });
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

  async function download(kind, list) {
    if (kind !== 'pcap') throw new Error('Unknown download');
    const response = await request(kind, { link: list });
    if (!response.ok) throw new Error('Download unavailable');
    const blob = await response.blob();
    if (lifetime.signal.aborted) return;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = (list.includes(',') ? 'fictionet-links.pcapng' : `fictionet-${list}.pcapng`).replace(/[^a-zA-Z0-9.-]/g, '');
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  return { connect, packetStream, packet, download, logout, close };
}
