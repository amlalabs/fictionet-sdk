// What the world pane shows, derived only from the run's search snapshot.
export const ENGINES = ['google', 'bing', 'duckduckgo'];
export const engine = (name) => ({ google: 'Google', bing: 'Bing', duckduckgo: 'DuckDuckGo', you_tube: 'YouTube' }[name] || name);
export const ENGINE_HOSTS = { google: 'google.com', bing: 'bing.com', duckduckgo: 'duckduckgo.com', you_tube: 'youtube.com' };

// How the latest answer reached the reader.
export function queryTag(s, q) {
  if (q.outcome.status === 'pending') return 'asking';
  if (['failed', 'undelivered'].includes(q.outcome.status)) return 'failed';
  if (['generated', 'prefetched'].includes(q.cache)) return 'made';
  if (q.cache === 'planted') return 'planted';
  if (q.cache === 'missing') return 'missing';
  if (q.cache === 'fixed') return 'stored';
  if (q.cache === 'cached') {
    const made = s.queries.some((other) => other.key === q.key && other.id < q.id && ['generated', 'prefetched'].includes(other.cache));
    return made ? 'again' : 'stored';
  }
  return 'failed';
}

const pageState = (p) => p.status === 404 ? 'missing' : ({ stubbed: 'made', written_live: 'made', stored: 'stored', fixed: 'stored', planted: 'planted', missing: 'missing', not_made: 'refused' }[p.made] || 'asking');

export function pageTag(p) {
  return p.making ? 'making' : p.made === 'missing' || p.status === 404 ? 'missing' : p.fetches > 1 ? 'again' : pageState(p);
}

const byTime = (a, b) => a.at_ms - b.at_ms || a.seq - b.seq;
const queryTime = (q) => q.answer_at_ms ?? q.at_ms;
const pageTime = (p) => p.at_ms;
const served = (p) => p.status != null;
const lists = ['queries', 'pages', 'refused', 'planted'];

// Snapshot rows retain identity even when intermediate updates were missed.
export function diff(prev, next) {
  const changes = [];
  const add = (type, fields, at_ms, seq = 0) => changes.push({ type, ...fields, at_ms: at_ms ?? 0, seq: seq ?? 0 });
  const restart = prev && next.revision > prev.revision && lists.every((key) => !next[key]?.length) && lists.some((key) => prev[key]?.length);
  const oldQueries = new Map((prev?.queries || []).map((q) => [q.id, q]));
  for (const query of next.queries || []) {
    const old = oldQueries.get(query.id);
    if (!old) add('search_started', { query }, query.at_ms, query.seq);
    const answered = query.outcome.status !== 'pending' && (!old || old.outcome.status === 'pending');
    if (answered) {
      const list = [...(next.results?.find((r) => r.key === query.key)?.listed || [])].sort((a, b) => a.rank - b.rank);
      add('search_answered', { query, state: queryTag(next, query), list }, queryTime(query), query.answer_seq ?? query.seq);
    }
    const newServe = query.outcome.status === 'served' && (!old || old.outcome.status !== 'served' || old.answer_at_ms !== query.answer_at_ms || old.answer_seq !== query.answer_seq);
    if (newServe && query.carries > 0) add('fact_reached', { target: query, kind: 'query' }, queryTime(query), query.answer_seq ?? query.seq);
  }
  const oldPages = new Map((prev?.pages || []).map((p) => [p.url, p]));
  for (const page of next.pages || []) {
    const old = oldPages.get(page.url);
    if (page.making && !old?.making) add('page_making', { page }, page.at_ms, page.seq);
    const newServe = served(page) && (!old || !served(old) || page.fetches > old.fetches || page.latest_serve_ms !== old.latest_serve_ms);
    if (!newServe) continue;
    if (!old || !served(old)) add('page_opened', { page, state: pageState(page), reason: page.reason, via: page.via ?? null }, pageTime(page), page.seq);
    else if (page.fetches > old.fetches) add('page_again', { page }, pageTime(page), page.seq);
    if (page.carries > 0) add('fact_reached', { target: page, kind: 'page' }, pageTime(page), page.seq);
  }
  const plants = new Set((prev?.planted || []).map((p) => JSON.stringify([p.at_ms, p.text])));
  for (const plant of next.planted || []) if (!plants.has(JSON.stringify([plant.at_ms, plant.text]))) add('plant', { plant }, plant.at_ms, plant.seq);
  const refused = new Set((prev?.refused || []).map((r) => JSON.stringify([r.name, r.at_ms])));
  for (const row of next.refused || []) if (typed(row) && !refused.has(JSON.stringify([row.name, row.at_ms]))) add('refused', { name: row.name }, row.at_ms, row.seq);
  const g = next.generator;
  if (prev && g && (g.generate !== prev.generator?.generate || g.copied !== prev.generator?.copied)) add('generation', { generate: g.generate, copied: g.copied }, g.generation_at_ms ?? next.at_ms, g.generation_revision);
  changes.sort(byTime);
  if (restart) changes.unshift({ type: 'restart', at_ms: next.at_ms, seq: 0 });
  return changes;
}

// Slot coordinates and tie order match the map's center-out growth.
export function slots() {
  const centers = [];
  for (let row = 0; row < 6; row++) {
    for (const x of row % 2 === 0 ? [74, 198, 322, 446] : [136, 260, 384]) centers.push([x, 178 + 62 * row]);
  }
  const distance = ([x, y]) => Math.hypot(x - 260, (y - 335) * 1.6);
  return centers.sort((a, b) => distance(a) - distance(b));
}

// Assign active sites to the map's slots.
export function layout(prev, hosts, context = {}) {
  const all = new Set([...(context.seed?.sites || []), ...hosts]);
  const centers = slots();
  if (all.size > centers.length) {
    const rows = Math.ceil(all.size / 3.5);
    centers.length = 0;
    for (let row = 0; row < rows; row++) {
      for (const x of row % 2 === 0 ? [74, 198, 322, 446] : [136, 260, 384]) centers.push([x, 178 + row * 310 / (rows - 1)]);
    }
    centers.sort((a, b) => Math.hypot(a[0] - 260, a[1] - 335) - Math.hypot(b[0] - 260, b[1] - 335));
  }
  const old = context.restart ? new Map() : prev?.assignment || new Map();
  const assignment = new Map([...old].filter(([host, pos]) => all.has(host) && centers.some(([x, y]) => x === pos[0] && y === pos[1])));
  for (const host of all) {
    if (assignment.has(host)) continue;
    const free = centers.find(([x, y]) => ![...assignment.values()].some(([px, py]) => px === x && py === y));
    assignment.set(host, free);
  }
  return { assignment, evicted: [...old.keys()].filter((host) => !all.has(host)) };
}

// Names a person might have typed: not the service lookups (`_http._tcp.…`)
// the system makes on its own.
const typed = (r) => !r.name.startsWith('_');

// The newest rows first: searches, pages, refused names and plants.
export function rows(s, limit = 8) {
  const who = (item, fallback) => item.via === 'codex_web_search' ? 'Codex' : ['claude_web_search', 'web_fetch'].includes(item.via) ? 'Claude Code' : item.via === 'command_line' ? 'Command line' : fallback;
  const badge = (tag) => ({ again: 'again', planted: 'planted', refused: 'refused', making: 'writing', asking: 'writing', missing: 'not found' }[tag] || null);
  return [
    ...s.queries.map((q) => ({ at: q.at_ms, seq: q.seq ?? 0, who: who(q, short(q.site || engine(q.engine))), what: `“${q.search}”`, tag: queryTag(s, q) })),
    ...s.pages.filter((p) => p.fetches > 0 || p.waiting).map((p) => ({ at: pageTime(p), seq: p.seq ?? 0, who: who(p, short(p.site || p.host)), what: p.title || new URL(p.url).pathname, title: p.url, tag: pageTag(p), ...(p.carries > 0 ? { carries: true } : {}) })),
    ...s.refused.filter(typed).map((r) => ({ at: r.at_ms, seq: r.seq ?? 0, who: who(r, 'DNS'), what: r.name, tag: 'refused' })),
    ...(s.planted || []).map((p) => ({ at: p.at_ms, seq: p.seq ?? 0, who: 'You', what: p.text, tag: 'planted' })),
  ].sort((a, b) => b.at - a.at || b.seq - a.seq).slice(0, limit).map(({ seq, ...row }) => ({ ...row, badge: badge(row.tag) }));
}

export function hostOf(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

export function hostMark(host) {
  const key = host.toLowerCase().replace(/^www\./, '');
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(key)) hash = Math.imul(hash ^ byte, 0x01000193) >>> 0;
  const brand = {
    'google.com': ['G', '#4285f4'], 'bing.com': ['B', '#00809d'],
    'duckduckgo.com': ['D', '#de5833'], 'html.duckduckgo.com': ['D', '#de5833'],
    'lite.duckduckgo.com': ['D', '#de5833'], 'reddit.com': ['R', '#ff4500'],
    'youtube.com': ['▶', '#ff0000'], 'github.com': ['G', '#181717'],
  }[key] || ((key === 'wikipedia.org' || key.endsWith('.wikipedia.org')) ? ['W', '#333333'] : null);
  const hue = hash % 360 / 60;
  const chroma = (1 - Math.abs(2 * .36 - 1)) * .52;
  const x = chroma * (1 - Math.abs(hue % 2 - 1));
  const channels = [[chroma, x, 0], [x, chroma, 0], [0, chroma, x], [0, x, chroma], [x, 0, chroma], [chroma, 0, x]][Math.floor(hue)];
  const color = '#' + channels.map((c) => Math.round((c + .36 - chroma / 2) * 255).toString(16).padStart(2, '0')).join('');
  return { key, hash, color: brand?.[1] || color, letter: brand?.[0] || key.charAt(0).toUpperCase() };
}

const languages = new Intl.DisplayNames(['en'], { type: 'language', fallback: 'none' });

// Language and www aliases share a site's map position.
export function siteKey(host) {
  const name = host.toLowerCase().replace(/^www\./, '');
  const parts = name.split('.');
  const domain = parts.slice(1);
  const registrable = domain.length === 2 || (domain.length === 3 && domain.at(-1).length === 2 && domain.at(-2).length <= 3);
  if (registrable && /^[a-z]{2,3}$/.test(parts[0])) {
    const language = languages.of(parts[0]);
    if (language) return domain.join('.');
  }
  return name;
}

// Display names arrive with the world's rows.
export function short(site) {
  const name = {
    'Cybersecurity and Infrastructure Security Agency': 'CISA',
    'National Vulnerability Database': 'NVD',
  }[site] || site;
  return name;
}
