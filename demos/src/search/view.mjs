import { engine, ms, time, made, siteReason, cache, outcome, counts, resultView, tree } from './model.mjs';

// Keep keyed elements in place unless their order or parent actually changes.
export function reconcile(parent, items, key, create, update, retained) {
  const wanted = new Set(items.map(key));
  for (const [id, entry] of retained) if (!wanted.has(id)) { entry.node.remove(); retained.delete(id); }
  items.forEach((item, index) => {
    const id = key(item);
    let entry = retained.get(id);
    const fresh = !entry;
    if (!entry) { entry = create(item); retained.set(id, entry); }
    update(entry, item, fresh);
    if (parent.children[index] !== entry.node) parent.insertBefore(entry.node, parent.children[index] || null);
  });
}

export function mount(root, services, options) {
  const doc = root.ownerDocument;
  root.classList.add('search-content');
  const el = (tag, text, parent, cls) => {
    const node = doc.createElement(tag);
    if (text != null) node.textContent = text;
    if (cls) node.setAttribute('class', cls);
    parent?.appendChild(node);
    return node;
  };
  const link = el('link', null, root);
  link.setAttribute('rel', 'stylesheet'); link.setAttribute('href', '/assets/search/style.css');
  const box = el('div', null, root, 'search-panel');
  const intro = el('header', null, box, 'search-intro');
  el('p', 'Every page here is made up by the world for this run.', intro, 'search-premise');
  const context = el('div', null, intro, 'search-context');
  const seed = el('p', 'Waiting for the world’s seed…', context, 'search-seed');
  const question = el('p', '', context, 'search-question');
  const disclosure = el('details', null, context);
  el('summary', 'Question, facts & forwarding policy', disclosure);
  const fullQuestion = el('p', '', disclosure);
  const facts = el('p', '', disclosure);
  const policy = el('div', 'Waiting for forwarding policy…', disclosure);
  const controls = el('section', null, intro, 'search-generator');
  el('span', 'stub generator (no model)', controls, 'search-eyebrow');
  const toggle = el('button', 'Waiting for generation state…', controls, 'search-toggle');
  toggle.type = 'button'; toggle.setAttribute('role', 'switch'); toggle.setAttribute('aria-checked', 'false');
  const revision = el('small', '', controls);
  const commandStatus = el('p', '', controls, 'search-command'); commandStatus.setAttribute('role', 'status');
  const error = el('p', '', box, 'search-error'); error.setAttribute('role', 'status');
  const meters = el('div', null, box, 'search-counts');
  const countNodes = new Map();
  const omitted = el('small', '', box, 'search-omitted');
  const columns = el('div', null, box, 'search-columns');
  const streamSection = el('section', null, columns, 'search-stream-section');
  el('h3', 'Search stream', streamSection);
  const source = el('p', 'Waiting for searcher…', streamSection, 'search-eyebrow');
  const stream = el('div', null, streamSection, 'search-stream');
  const empty = el('p', 'No searches yet. The web starts with a question.', streamSection, 'search-empty');
  const detail = el('section', null, columns, 'search-results');
  const detailTitle = el('h3', 'Results the world made', detail);
  const origin = el('p', 'Select a search to inspect its result list.', detail);
  const resultList = el('ol', null, detail);
  const treeSection = el('section', null, columns, 'search-tree-section');
  el('h3', 'The made-up web', treeSection);
  el('p', 'Searches → results → links', treeSection, 'search-eyebrow');
  const treeList = el('div', null, treeSection, 'search-tree');
  const treeEmpty = el('p', 'Sites and pages appear here when the world is asked for them.', treeSection, 'search-empty');
  const otherSites = el('div', null, treeSection, 'search-sites');
  const refused = el('div', null, treeSection, 'search-refused');
  const rows = new Map(), nodes = new Map(), results = new Map(), sites = new Map(), refusals = new Map();
  const seenSites = new Set();
  const controller = new AbortController();
  let snapshot, chosen, selectedPage, busy = false, waitingRevision, disposed = false, initialized = false;
  const cleanup = [];
  const listen = (node, name, fn) => { node.addEventListener(name, fn); cleanup.push(() => node.removeEventListener(name, fn)); };
  const set = (node, value) => { if (node.textContent !== String(value)) node.textContent = value; };
  const line = (parent, cls) => el('span', '', parent, cls);
  const stateButton = () => {
    const g = snapshot?.generator;
    toggle.disabled = !g || busy || (waitingRevision != null && g.generation_revision < waitingRevision);
    toggle.setAttribute('aria-busy', String(busy));
    toggle.setAttribute('aria-checked', String(!!g?.generate));
    set(toggle, busy ? 'Waiting for the world…' : g ? (g.generate ? 'Making new pages' : 'Serving only what exists') : 'Waiting for generation state…');
    if (g) set(revision, `Revision ${g.generation_revision} · changed at ${time(g.generation_at_ms)}`);
  };
  // Resolve real event identities; sequence numbers are never treated as request IDs.
  async function select(seq, host) {
    services.packetPair?.set(null);
    services.selection.set({ host: host || null, event: { seq }, request: null, connection: null, node: null, links: [] });
    try {
      const events = await services.transport.get('/api/events', { after: Math.max(0, seq - 1), max: 1 }, controller.signal);
      if (disposed || services.selection.get().event?.seq !== seq) return;
      const event = events.events?.find((e) => e.seq === seq);
      if (event) {
        services.selection.set({ event, host: event.sandbox?.name || host || null, request: event.fields?.request_id ?? null, connection: event.conn ?? null });
        services.packetPair?.set(event.local && event.peer ? { local: event.local, peer: event.peer } : null);
      }
    } catch (e) { if (!disposed) set(error, `Selection details unavailable: ${e.message}`); }
  }
  function openPage(url) {
    const p = snapshot?.pages.find((p) => p.url === url);
    if (!p) return;
    selectedPage = url;
    select(p.seq, null);
    render();
    nodes.get(`page:${url}`)?.node.scrollIntoView({ block: 'nearest' });
  }
  listen(toggle, 'click', async () => {
    if (toggle.disabled || disposed) return;
    const g = snapshot.generator;
    busy = true; stateButton(); set(commandStatus, 'Waiting for the world…');
    try {
      const reply = await services.transport.post('/api/command/generation', {
        request_id: crypto.randomUUID(),
        command: { command: 'set_generation', generate: !g.generate, expected_revision: g.generation_revision },
      }, controller.signal);
      if (disposed) return;
      if (reply.status === 'pending') set(commandStatus, 'Command pending. Read the state before trying again.');
      else { waitingRevision = reply.reply.revision; set(commandStatus, `Applied at ${time(reply.reply.at_ms)} · revision ${waitingRevision}`); }
    } catch (e) {
      if (disposed) return;
      const rejection = e.body?.rejection;
      if (rejection?.reason === 'stale_revision') {
        waitingRevision = rejection.current;
        set(commandStatus, `The switch changed elsewhere. Current revision ${rejection.current}. No retry was sent.`);
      } else set(commandStatus, e.body?.status === 'timeout' ? 'No reply yet. The command may still apply; read the state before trying again.' : `Command failed: ${e.message}`);
    } finally { if (!disposed) { busy = false; stateButton(); } }
  });
  // One delegated listener per list also covers rows added by later snapshots.
  const delegate = (parent, action) => listen(parent, 'click', (event) => {
    let target = event.target;
    while (target && target !== parent) { if (target.dataset?.identity) { action(target.dataset.identity); return; } target = target.parentElement; }
  });
  delegate(stream, (id) => {
    chosen = Number(id); selectedPage = null;
    const q = snapshot?.queries.find((q) => q.id === chosen);
    if (q) { select(q.answer_seq ?? q.seq, q.sandbox); render(); }
  });
  delegate(treeList, (url) => openPage(url));
  delegate(resultList, (url) => openPage(url));
  const card = (cls, parentTag = 'button') => {
    const node = el(parentTag, null, null, cls);
    if (parentTag === 'button') node.type = 'button';
    return { node, top: line(node, 'search-row-top'), title: line(node, 'search-row-title'), note: line(node, 'search-row-note') };
  };
  function render() {
    const s = snapshot;
    set(seed, `${s.seed.name} · world date ${s.seed.date}`);
    set(question, s.seed.question);
    set(fullQuestion, s.seed.question);
    set(facts, s.seed.facts.join('\n'));
    stateButton();
    for (const [label, value] of Object.entries(counts(s))) {
      if (!countNodes.has(label)) {
        const cell = el('div', null, meters);
        countNodes.set(label, el('b', '', cell)); el('span', label, cell);
      }
      set(countNodes.get(label), value);
    }
    const lost = Object.values(s.omitted).reduce((a, b) => a + b, 0);
    set(omitted, lost ? `${lost} rows are no longer held here. Counts describe retained rows. ${Object.entries(s.omitted).filter(([, n]) => n).map(([k, n]) => `${k.replaceAll('_', ' ')}: ${n}`).join(' · ')}` : '');
    empty.hidden = s.queries.length > 0;
    reconcile(stream, [...s.queries].reverse(), (q) => q.id, () => { const entry = card('search-row'); entry.badge = el('span', '', entry.top, 'search-engine'); entry.meta = el('span', '', entry.top); return entry; }, (entry, q, fresh) => {
      entry.node.dataset.identity = String(q.id);
      entry.node.setAttribute('aria-pressed', String(chosen === q.id));
      set(entry.badge, engine(q.engine));
      set(entry.meta, ` ${time(q.at_ms)} · ${q.sandbox || 'Host not reported'}${q.peer ? ` · ${q.peer}` : ''}`);
      set(entry.title, q.search);
      set(entry.note, `${outcome(q)}${q.cache ? ` · ${cache(q.cache)}` : ''}${q.serve_ms != null ? ` · ${ms(q.serve_ms)}` : ''}`);
      if (fresh) entry.node.classList.add('search-arrival');
    }, rows);
    const q = s.queries.find((q) => q.id === chosen);
    if (q) {
      set(detailTitle, `${q.search} · ${engine(q.engine)}`);
      const view = resultView(s, q); set(origin, view.origin);
      reconcile(resultList, view.rows, (r) => `${q.key}:${r.rank}:${r.url}`, () => {
        const node = el('li', null, null);
        return { node, title: line(node, 'search-row-title'), host: line(node, 'search-url'), url: line(node, 'search-path'), note: line(node, 'search-row-note'), open: el('button', '', node, 'search-open') };
      }, (entry, r) => {
        set(entry.title, `${r.rank}. ${r.title}`); set(entry.host, r.host); set(entry.url, r.url);
        set(entry.note, r.site ? `${r.site.address} · ${siteReason(r.site.reason)}` : 'No address assignment observed yet');
        entry.open.hidden = !r.page;
        entry.open.dataset.identity = r.url;
        set(entry.open, r.page ? `↳ Opened · ${made(r.page.made)} · ${ms(r.page.serve_ms)} · show page` : '');
      }, results);
    } else if (chosen != null) { set(origin, 'This search is no longer retained.'); reconcile(resultList, [], (r) => r.url, () => {}, () => {}, results); }
    const freshSites = new Set(s.sites.filter((site) => initialized && site.reason === 'pool' && !seenSites.has(site.host)).map((site) => site.host));
    const moments = new Set();
    const mark = (entry, host) => { if (freshSites.has(host) && !moments.has(host)) { services.moment(entry.node); moments.add(host); } };
    const branches = tree(s);
    treeEmpty.hidden = branches.length > 0;
    reconcile(treeList, branches, (n) => n.id, (n) => card(n.page ? 'search-node' : 'search-root', n.page ? 'button' : 'div'), (entry, n, fresh) => {
      entry.node.style.setProperty('--depth', n.depth);
      entry.node.dataset.depth = String(n.depth);
      if (n.page) {
        const p = n.page;
        entry.node.dataset.identity = p.url;
        entry.node.setAttribute('aria-pressed', String(selectedPage === p.url));
        set(entry.top, p.host); set(entry.title, p.title || p.url);
        const path = p.url.replace(/^https?:\/\/[^/]+/, '') || '/';
        set(entry.note, `${path}\n${made(p.made)} · first ${ms(p.first_serve_ms)} · latest ${ms(p.latest_serve_ms)}${p.fetches > 1 ? ` · ${p.fetches} fetches · ${made(p.latest)}` : ''}`);
        if (fresh) entry.node.classList.add('search-arrival');
        mark(entry, p.host);
      } else { set(entry.top, n.label); set(entry.title, ''); set(entry.note, ''); }
    }, nodes);
    reconcile(otherSites, s.sites.filter((site) => !s.pages.some((p) => p.host === site.host)), (site) => site.host, () => card('search-site', 'div'), (entry, site) => {
      set(entry.top, site.host); set(entry.title, `${site.address} · ${siteReason(site.reason)}`); set(entry.note, 'no page fetched'); mark(entry, site.host);
    }, sites);
    const occurrences = new Map();
    const refusedRows = s.refused.map((r) => { const key = `${r.name}:${r.at_ms}`; const count = occurrences.get(key) || 0; occurrences.set(key, count + 1); return { ...r, identity: `${key}:${count}` }; });
    reconcile(refused, refusedRows, (r) => r.identity, () => card('search-refusal', 'div'), (entry, r) => {
      set(entry.top, `× Refused · ${r.name}`); set(entry.title, r.reason); set(entry.note, time(r.at_ms));
    }, refusals);
    s.sites.forEach((site) => seenSites.add(site.host));
    initialized = true;
  }
  stateButton();
  cleanup.push(services.state('/api/state/policy', ({ value }) => {
    if (disposed || !value) return;
    set(source, value.searcher);
    policy.replaceChildren();
    el('p', `Made up: ${value.made_up}`, policy);
    el('p', 'Forwarded to the real internet for setup:', policy);
    const list = el('ul', null, policy);
    value.forwarded.forEach((row) => el('li', `${row.host} — ${row.why}`, list));
    el('p', `Refused: ${value.refused}`, policy);
  }, (e) => { if (!disposed) set(policy, `Policy unavailable: ${e.message}`); }));
  cleanup.push(services.state(options.state, ({ value }) => {
    if (disposed || !value) return;
    if (snapshot?.generator.generate && !value.generator.generate) services.moment(controls);
    snapshot = value; set(error, ''); render();
  }, (e) => { if (!disposed) { snapshot = null; stateButton(); set(error, `Search state unavailable: ${e.message}`); } }));
  return () => { disposed = true; controller.abort(); cleanup.forEach((off) => off()); root.classList.remove('search-content'); root.replaceChildren(); };
}
