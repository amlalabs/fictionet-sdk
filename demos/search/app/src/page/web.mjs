import { mount as mountMap } from '../../components/map.mjs';
import { createState } from '../../state.mjs';
import { engine, hostOf } from './model.mjs';

const label = (text) => String(text || '').trim().split(/\s+/).slice(0, 3).join(' ');
const pageId = (url) => `page:${url}`;
const siteId = (url) => `site:${hostOf(url)}`;

export function createWeb(root, services) {
  const { state, runTime } = createState();
  state.known = state.connected = true;
  const subscribers = new Set();
  const previews = new Map(), lists = new Map(), observed = new Set(), opened = new Map();
  let restartSeq = 0;
  let snapshot = null, detailKey = null;
  const { el } = services.dom.scoped(root);
  const emit = (name, data) => subscribers.forEach((fn) => fn(name, data));
  const graph = { state, runTime, subscribe(fn) { subscribers.add(fn); return () => subscribers.delete(fn); } };
  const queryId = (id) => `search:${id}`;
  function node(id, text, subtitle, data) {
    let n = state.nodes.get(id);
    if (!n) {
      n = { id, kind: 'task', display: true, name: label(text), label: text, subtitle, edges: new Set(), x: NaN, y: NaN, tx: 0, ty: 0, g: null };
      state.nodes.set(id, n);
      state.layoutDirty = true;
    }
    n.data = data;
    return n;
  }
  function edge(a, b) {
    const id = `${a}\n${b}`;
    if (state.edges.has(id)) return;
    state.edges.set(id, { id, a, b, rate: [0, 0], bps: [0, 0], c: [0, 0, 0, 0], seen: 0 });
    state.nodes.get(a).edges.add(id);
    state.nodes.get(b).edges.add(id);
    state.layoutDirty = true;
  }
  function site(url, name) {
    return node(siteId(url), name || hostOf(url), 'Site', { kind: 'site', host: hostOf(url) });
  }
  function page(row) {
    const s = site(row.url, row.site);
    const p = node(pageId(row.url), row.title || new URL(row.url).pathname, 'Page', { kind: 'page', ...row });
    edge(s.id, p.id);
    return p;
  }
  function details(side, selected) {
    const n = state.nodes.get(selected?.id);
    const data = n?.data;
    const queries = !data ? [] : data.kind === 'search' ? [data] : [...state.nodes.values()].filter((item) => item.data.kind === 'search' && (lists.get(item.data.id) || []).some((r) => data.kind === 'site' ? hostOf(r.url) === data.host : r.url === data.url)).map((item) => item.data);
    const pages = !data ? [] : data.kind === 'page' ? [data] : [...state.nodes.values()].filter((item) => item.data.kind === 'page' && (data.kind === 'site' ? hostOf(item.data.url) === data.host : state.edges.has(`${n.id}\n${item.id}`))).map((item) => item.data);
    const key = JSON.stringify([selected?.id, data, queries, pages.map((p) => [p, previews.get(p.url)])]);
    if (key === detailKey) return;
    detailKey = key;
    const scroll = side.scrollTop;
    side.replaceChildren();
    side.hidden = !n;
    if (!n) return;
    const close = el('button', { type: 'button', text: 'Close', class: 'quiet' }, side);
    close.addEventListener('click', () => {
      state.selected = null;
      state.sideDirty = true;
      n.g?.classList.remove('selected');
      n.g?.focus();
    });
    el('h2', { text: n.name, title: n.label }, side);
    if (queries.length) {
      el('h3', { text: 'Queries' }, side);
      for (const q of queries) {
        el('p', { text: label(q.search), title: q.search }, side);
        el('p', { text: q.via === 'claude_web_search' ? 'Claude' : q.via === 'codex_web_search' ? 'Codex' : engine(q.engine) }, side);
      }
    }
    if (pages.length) el('h3', { text: 'Pages' }, side);
    for (const p of pages) {
      const button = el('button', { type: 'button', class: 'quiet', text: label(p.title || new URL(p.url).pathname), title: p.url }, side);
      button.addEventListener('click', () => { state.selected = { kind: 'node', id: pageId(p.url) }; state.sideDirty = true; });
      el('p', { text: previews.get(p.url)?.source || ({ from_store: 'Stored', written_live: 'Model-written', stored: 'Stored', fixed: 'Fixed', planted: 'Planted', missing: 'Missing', not_made: 'Refused' }[p.latest || p.made]) || 'Loading' }, side);
      const html = previews.get(p.url)?.html;
      if (html !== undefined) {
        const frame = el('iframe', { title: 'Page preview', sandbox: '', referrerpolicy: 'no-referrer', tabindex: '-1' }, side);
        const document = new DOMParser().parseFromString(html, 'text/html');
        document.body.inert = true;
        document.querySelectorAll('meta[http-equiv], base').forEach((element) => element.remove());
        frame.srcdoc = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; navigate-to 'none'">${document.documentElement.outerHTML}`;
      }
    }
    side.scrollTop = scroll;
  }
  const disposeMap = mountMap(root, {
    ...services, graph, hosts: [], map: { details },
    selection: { subscribe: () => () => {} },
  });
  function render(value, changes = []) {
    snapshot = value;
    for (const q of value.queries) {
      node(queryId(q.id), q.search, q.via === 'claude_web_search' ? 'Claude' : q.via === 'codex_web_search' ? 'Codex' : engine(q.engine), { kind: 'search', ...q });
      const result = value.results.find((r) => r.query_id === q.id);
      if (result && !lists.has(q.id)) lists.set(q.id, result.listed);
      for (const r of lists.get(q.id) || []) site(r.url, r.site);
    }
    for (const p of value.pages) if (p.fetches > 0 || p.waiting || p.making) page(p);
    for (const [id, rows] of lists) {
      const q = state.nodes.get(queryId(id));
      if (!q) continue;
      for (const r of rows) {
        const p = state.nodes.get(pageId(r.url));
        if (p && Math.max(p.data.at_ms, opened.get(r.url) || 0) >= q.data.at_ms) edge(q.id, p.id);
      }
    }
    state.sideDirty = true;
    emit('snapshot');
    for (const change of changes) {
      const id = change.query ? queryId(change.query.id) : change.page ? pageId(change.page.url) : null;
      if (id) emit('event', { node: id });
      if (change.type === 'search_answered') for (const r of lists.get(change.query.id) || []) emit('event', { node: siteId(r.url) });
      if (change.page) emit('event', { node: siteId(change.page.url) });
    }
  }
  return {
    apply: (changes, value) => render(value, changes),
    reset(value) {
      for (const n of state.nodes.values()) n.g?.remove();
      for (const e of state.edges.values()) e.g?.remove();
      state.nodes.clear(); state.edges.clear(); state.pins.clear();
      state.selected = null; state.userMoved = false; state.layoutDirty = true;
      previews.clear(); lists.clear(); observed.clear(); opened.clear();
      restartSeq = services.graph.state.events.filter((event) => event.source === 'web' && event.kind === 'restarted').at(-1)?.seq || 0;
      render(value);
      this.setEvents(services.graph.state.events);
    },
    setEvents(events) {
      let changed = false;
      const hits = new Set();
      for (const event of events) {
        if (event.seq <= restartSeq || observed.has(event.seq)) continue;
        observed.add(event.seq);
        const f = event.fields || {};
        if (f.query_id != null && Array.isArray(f.listed)) {
          lists.set(f.query_id, f.listed);
          for (const r of f.listed) hits.add(siteId(r.url));
          changed = true;
        }
        if (event.source === 'http' && event.kind === 'request' && f.kind === 'page') {
          const url = `${f.scheme || 'https'}://${f.host}${f.path || '/'}${f.query ? `?${f.query}` : ''}`;
          hits.add(pageId(url));
          hits.add(siteId(url));
          opened.set(url, event.at * 1000);
          changed = true;
          if (typeof f.preview === 'string') previews.set(url, { html: f.preview, source: f.served_by === 'WARC capture' ? 'Copied' : f.cache === 'generated' ? 'Model-written' : null });
        }
      }
      if (snapshot && changed) {
        render(snapshot);
        for (const id of hits) emit('event', { node: id });
      }
    },
    dispose: disposeMap,
  };
}
