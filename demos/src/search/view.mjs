import { engine, ms, made, siteReason, cache, outcome, counts, resultView, tree, rootNote } from './model.mjs';

// Names for the snapshot's omitted counts.
const OMITTED = { queries: 'searches', results: 'result lists', listed: 'results cut from long lists', pages: 'pages', sites: 'sites', refused: 'refused names', seed_facts: 'seed facts', seed_sites: 'seed sites' };

export function mount(root, services, options) {
  const { reconcile, listen } = services.dom, { fmtRunMs: time } = services.format;
  root.classList.add('search-content');
  const { el } = services.dom.scoped(root);
  el('link', { rel: 'stylesheet', href: '/assets/search/style.css' }, root);
  const box = el('div', { class: 'search-panel' }, root);
  const intro = el('header', { class: 'search-intro' }, box);
  el('p', { class: 'search-premise', text: 'Every page here is made up by the world for this run.' }, intro);
  const context = el('div', { class: 'search-context' }, intro);
  const seed = el('p', { class: 'search-seed', text: 'Waiting for the world’s seed…' }, context);
  const question = el('p', { class: 'search-question' }, context);
  const disclosure = el('details', {}, context);
  el('summary', { text: 'Question, facts & forwarding policy' }, disclosure);
  const fullQuestion = el('p', {}, disclosure);
  const facts = el('p', {}, disclosure);
  const policy = el('div', { text: 'Waiting for forwarding policy…' }, disclosure);
  const controls = el('section', { class: 'search-generator' }, intro);
  const toggle = el('button', { class: 'switch search-toggle' }, controls);
  toggle.type = 'button'; toggle.setAttribute('role', 'switch'); toggle.setAttribute('aria-checked', 'false');
  const track = el('span', { class: 'switch-track', 'aria-hidden': 'true' }, toggle);
  el('span', { class: 'switch-knob' }, track);
  const toggleLabel = el('span', { text: 'Waiting for generation state…' }, toggle);
  const revision = el('small', {}, controls);
  const commandStatus = el('p', { class: 'search-command', role: 'status' }, controls);
  const error = el('p', { class: 'search-error', role: 'status' }, box);
  const meters = el('div', { class: 'search-counts' }, box);
  const countNodes = new Map();
  const omitted = el('small', { class: 'search-omitted' }, box);
  const columns = el('div', { class: 'search-columns' }, box);
  const streamSection = el('section', { class: 'search-stream-section' }, columns);
  const streamHead = el('header', { class: 'search-section-head' }, streamSection);
  el('h3', { text: 'Search stream' }, streamHead);
  const source = el('p', { class: 'eyebrow', text: 'Waiting for searcher…' }, streamHead);
  const stream = el('div', { class: 'search-stream' }, streamSection);
  const empty = el('p', { class: 'note search-empty', text: 'No searches yet. The web starts with a question.' }, streamSection);
  const detail = el('section', { class: 'search-results' }, columns);
  const detailHead = el('header', { class: 'search-section-head' }, detail);
  const detailTitle = el('h3', { text: 'Results the world made' }, detailHead);
  const origin = el('p', { text: 'The newest search’s result list appears here.' }, detailHead);
  const resultList = el('ol', {}, detail);
  const treeSection = el('section', { class: 'search-tree-section' }, columns);
  const treeHead = el('header', { class: 'search-section-head' }, treeSection);
  el('h3', { text: 'The made-up web' }, treeHead);
  el('p', { class: 'eyebrow', text: 'Searches → results → links' }, treeHead);
  const treeList = el('div', { class: 'search-tree' }, treeSection);
  const treeEmpty = el('p', { class: 'note search-empty', text: 'No pages yet. Pages appear here when the world is asked for them.' }, treeSection);
  const sitesHead = el('h4', { class: 'search-list-head', text: 'Sites with no page in the tree' }, treeSection);
  const otherSites = el('div', { class: 'search-sites' }, treeSection);
  const refusedHead = el('h4', { class: 'search-list-head', text: 'Names the world refused' }, treeSection);
  const refused = el('div', { class: 'search-refused' }, treeSection);
  sitesHead.hidden = refusedHead.hidden = true;
  const rows = new Map(), nodes = new Map(), results = new Map(), sites = new Map(), refusals = new Map();
  // Hosts on screen when the panel opened, and hosts that had their moment.
  const firstSites = new Set(), marked = new Set();
  const controller = new AbortController();
  let snapshot, chosen, selectedPage, waitingRevision, disposed = false, initialized = false;
  const cleanup = [];
  const set = (node, value) => { if (node.textContent !== String(value)) node.textContent = value; };
  const line = (parent, cls) => el('span', { class: cls }, parent);
  const stateButton = () => {
    const g = snapshot?.generator;
    // A reply describes one revision; once the switch moves past it, it is history.
    if (!request.busy && g && waitingRevision != null && g.generation_revision > waitingRevision) { waitingRevision = null; set(commandStatus, ''); }
    toggle.disabled = !g || request.busy || (waitingRevision != null && g.generation_revision < waitingRevision);
    toggle.setAttribute('aria-busy', String(request.busy));
    toggle.setAttribute('aria-checked', String(!!g?.generate));
    toggle.dataset.known = String(!!g);
    set(toggleLabel, request.busy ? 'Waiting for the world…' : g ? (g.generate ? 'Making new pages' : 'Serving only what exists') : 'Waiting for generation state…');
    if (g) set(revision, `Revision ${g.generation_revision} · changed at ${time(g.generation_at_ms)}`);
  };
  const request = services.command(controller.signal, stateButton);
  // Resolve real event identities; sequence numbers are never treated as request IDs.
  async function select(seq, host) {
    services.packetPair.set(null);
    services.selection.set({ host: host || null, event: { seq }, request: null, connection: null, node: null, links: [] });
    try {
      const events = await services.transport.get('/api/events', { after: Math.max(0, seq - 1), max: 1 }, controller.signal);
      if (disposed || services.selection.get().event?.seq !== seq) return;
      const event = events.events?.find((e) => e.seq === seq);
      if (event) {
        services.selection.set({ event, host: event.sandbox?.name || host || null, request: event.fields?.request_id ?? null, connection: event.conn ?? null });
        services.packetPair.set(event.local && event.peer ? { local: event.local, peer: event.peer } : null);
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
  cleanup.push(listen(toggle, 'click', async () => {
    if (toggle.disabled || disposed) return;
    const g = snapshot.generator;
    set(commandStatus, 'Waiting for the world…');
    await request.send('/api/command/generation', { command: 'set_generation', generate: !g.generate }, g.generation_revision, {
      reply(reply) {
      if (reply.status === 'pending') set(commandStatus, 'Command pending. Read the state before trying again.');
      else { waitingRevision = reply.reply.revision; set(commandStatus, `Applied at ${time(reply.reply.at_ms)} · revision ${waitingRevision}`); }
      }, error(e) {
      const rejection = e.body?.rejection;
      if (rejection?.reason === 'stale_revision') {
        waitingRevision = rejection.current;
        set(commandStatus, `The switch changed elsewhere. Current revision ${rejection.current}. No retry was sent.`);
      } else set(commandStatus, e.body?.status === 'timeout' ? 'No reply yet. The command may still apply; read the state before trying again.' : `Command failed: ${e.message}`);
      },
    });
  }));
  // One delegated listener per list also covers rows added by later snapshots.
  const delegate = (parent, action) => cleanup.push(listen(parent, 'click', (event) => {
    let target = event.target;
    while (target && target !== parent) { if (target.dataset?.identity) { action(target.dataset.identity); return; } target = target.parentElement; }
  }));
  delegate(stream, (id) => {
    chosen = Number(id); selectedPage = null;
    const q = snapshot?.queries.find((q) => q.id === chosen);
    if (q) { select(q.answer_seq ?? q.seq, q.sandbox); render(); }
  });
  delegate(treeList, (url) => openPage(url));
  delegate(resultList, (url) => openPage(url));
  const card = (cls, parentTag = 'button') => {
    const node = el(parentTag, { class: cls }, null);
    if (parentTag === 'button') node.type = 'button';
    return { node, top: line(node, 'search-row-top'), title: line(node, 'search-row-title'), path: line(node, 'search-row-path'), note: line(node, 'search-row-note') };
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
        const cell = el('div', {}, meters);
        countNodes.set(label, el('b', {}, cell)); el('span', { text: label }, cell);
      }
      set(countNodes.get(label), value);
    }
    const lost = Object.values(s.omitted).reduce((a, b) => a + b, 0);
    set(omitted, lost ? `No longer held here: ${Object.entries(s.omitted).filter(([, n]) => n).map(([k, n]) => `${n} ${OMITTED[k] || k.replaceAll('_', ' ')}`).join(', ')}. The counts describe what is held.` : '');
    empty.hidden = s.queries.length > 0;
    reconcile(stream, [...s.queries].reverse(), (q) => q.id, () => { const entry = card('search-row'); entry.badge = el('span', { class: 'pill outline' }, entry.top); entry.meta = el('span', {}, entry.top); return entry; }, (entry, q, fresh) => {
      entry.node.dataset.identity = String(q.id);
      entry.node.setAttribute('aria-pressed', String(chosen === q.id));
      set(entry.badge, engine(q.engine));
      set(entry.meta, ` ${time(q.at_ms)} · ${q.sandbox || 'Host not reported'}${q.peer ? ` · ${q.peer}` : ''}`);
      set(entry.title, q.search);
      // A failure already names its cause, so its cache state would repeat it.
      const label = q.outcome.status === 'failed' ? '' : cache(q.cache);
      set(entry.note, `${outcome(q)}${label ? ` · ${label}` : ''}${q.serve_ms != null ? ` · ${ms(q.serve_ms)}` : ''}`);
      if (fresh) entry.node.classList.add('search-arrival');
    }, rows);
    // Until a viewer selects a search, the result list follows the newest
    // one that has results, or the newest when none has.
    const newest = s.queries.findLast((q) => q.results > 0) ?? s.queries.at(-1);
    const q = chosen == null ? newest : s.queries.find((q) => q.id === chosen);
    if (q) {
      set(detailTitle, `${q.search} · ${engine(q.engine)}`);
      const following = chosen == null ? `Newest search${q.results > 0 ? ' with results' : ''}; select one to keep it here. ` : '';
      const view = resultView(s, q); set(origin, `${following}${view.origin}`);
      reconcile(resultList, view.rows, (r) => `${q.key}:${r.rank}:${r.url}`, () => {
        const node = el('li', {}, null);
        return { node, title: line(node, 'search-row-title'), host: line(node, 'search-url'), url: line(node, 'search-path'), note: line(node, 'search-row-note'), open: el('button', { class: 'search-open' }, node) };
      }, (entry, r) => {
        set(entry.title, `${r.rank}. ${r.title}`); set(entry.host, r.host); set(entry.url, r.url);
        set(entry.note, r.site ? `${r.site.address} · ${siteReason(r.site.reason)}` : 'No address assignment observed yet');
        entry.open.hidden = !r.page;
        entry.open.dataset.identity = r.url;
        set(entry.open, r.page ? `Opened · ${made(r.page.made)} · ${ms(r.page.serve_ms)} · show page` : '');
      }, results);
    } else if (chosen != null) { set(origin, 'This search is no longer retained.'); reconcile(resultList, [], (r) => r.url, () => {}, () => {}, results); }
    if (!initialized) s.sites.forEach((site) => firstSites.add(site.host));
    // The story moment is the first page on a made-up site that is new to this
    // viewer; a lookup with no page is background traffic, not the story.
    const pool = new Set(s.sites.filter((site) => site.reason === 'pool').map((site) => site.host));
    const mark = (entry, host) => {
      if (!initialized || !pool.has(host) || firstSites.has(host) || marked.has(host)) return;
      services.moment(entry.node); marked.add(host);
    };
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
        set(entry.path, p.url.replace(/^https?:\/\/[^/]+/, '') || '/');
        set(entry.note, `${made(p.made)} · first ${ms(p.first_serve_ms)} · latest ${ms(p.latest_serve_ms)}${p.fetches > 1 ? ` · ${p.fetches} fetches · ${made(p.latest)}` : ''}`);
        if (fresh) entry.node.classList.add('search-arrival');
        mark(entry, p.host);
      } else { set(entry.top, n.label); set(entry.title, ''); set(entry.note, rootNote(s, n)); }
    }, nodes);
    const unfetched = s.sites.filter((site) => !s.pages.some((p) => p.host === site.host));
    sitesHead.hidden = !unfetched.length;
    reconcile(otherSites, unfetched, (site) => site.host, () => card('search-site', 'div'), (entry, site) => {
      set(entry.top, site.host); set(entry.title, `${site.address} · ${siteReason(site.reason)}`);
    }, sites);
    const occurrences = new Map();
    const refusedRows = s.refused.map((r) => { const key = `${r.name}:${r.at_ms}`; const count = occurrences.get(key) || 0; occurrences.set(key, count + 1); return { ...r, identity: `${key}:${count}` }; });
    reconcile(refused, refusedRows, (r) => r.identity, () => card('search-refusal', 'div'), (entry, r) => {
      set(entry.top, r.name); set(entry.title, r.reason); set(entry.note, `at ${time(r.at_ms)}`);
    }, refusals);
    refusedHead.hidden = !refusedRows.length;
    initialized = true;
  }
  stateButton();
  cleanup.push(services.state('/api/state/policy', ({ value }) => {
    if (disposed || !value) return;
    set(source, value.searcher);
    policy.replaceChildren();
    el('p', { text: `Made up: ${value.made_up}` }, policy);
    el('p', { text: 'Forwarded to the real internet for setup:' }, policy);
    const list = el('ul', {}, policy);
    value.forwarded.forEach((row) => el('li', { text: `${row.host} — ${row.why}` }, list));
    el('p', { text: `Refused: ${value.refused}` }, policy);
  }, (e) => { if (!disposed) set(policy, `Policy unavailable: ${e.message}`); }));
  cleanup.push(services.state(options.state, ({ value }) => {
    if (disposed || !value) return;
    if (snapshot?.generator.generate && !value.generator.generate) services.moment(controls);
    snapshot = value; set(error, ''); render();
  }, (e) => { if (!disposed) { snapshot = null; stateButton(); set(error, `Search state unavailable: ${e.message}`); } }));
  return () => { disposed = true; controller.abort(); cleanup.forEach((off) => off()); root.classList.remove('search-content'); root.replaceChildren(); };
}
