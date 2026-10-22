// What the world pane shows, derived only from the run's search snapshot.
export const engine = (name) => ({ google: 'Google', bing: 'Bing', duckduckgo: 'DuckDuckGo', you_tube: 'YouTube' }[name] || name);

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

const pageState = (p) => p.status === 404 ? 'missing' : ({ from_store: 'made', written_live: 'made', stored: 'stored', fixed: 'stored', planted: 'planted', missing: 'missing', not_made: 'refused' }[p.made] || 'asking');

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
  if (prev && g && (g.generate !== prev.generator?.generate || g.copied !== prev.generator?.copied || g.live_search !== prev.generator?.live_search)) add('generation', { generate: g.generate, copied: g.copied, live_search: g.live_search }, g.generation_at_ms ?? next.at_ms, g.generation_revision);
  changes.sort(byTime);
  if (restart) changes.unshift({ type: 'restart', at_ms: next.at_ms, seq: 0 });
  return changes;
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

// Display names arrive with the world's rows.
export function short(site) {
  const name = {
    'Cybersecurity and Infrastructure Security Agency': 'CISA',
    'National Vulnerability Database': 'NVD',
  }[site] || site;
  return name;
}
