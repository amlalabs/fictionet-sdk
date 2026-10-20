// Presentation derives only from the current run snapshot.
export const engine = (name) => ({ google: 'Google', bing: 'Bing', duckduckgo: 'DuckDuckGo' }[name] || name);
export const queryKey = (text) => text.toLowerCase().split(/[\p{White_Space}\u001c-\u001f]+/u).filter(Boolean).join(' ');
export const ms = (value) => value == null ? 'not reported' : `${value} ms`;
export const made = (value) => ({ stubbed: 'Made by the stub generator', stored: 'Served from memory', fixed: 'Written into the seed', missing: 'Not made, so 404', not_made: 'Not made: over the budget', written_live: 'Written by a model' }[value] || 'How it was made was not reported');
export const siteReason = (value) => ({ search_engine: 'Search engine address', seed: 'Address from the seed', pool: 'Address from the world’s pool', recorded: 'Address from storage' }[value] || 'Address reason not reported');
export const cache = (value) => ({ generated: 'Made for this search', cached: 'From memory', prefetched: 'Made ahead of this search', fixed: 'Written into the seed', missing: 'Generation was off', budget: 'Generation budget spent' }[value] || '');
export function outcome(q) {
  switch (q.outcome.status) {
    case 'pending': return '◌ Pending';
    case 'served': return q.results === 0 ? `Served with no results${q.cache === 'missing' ? ' — generation was off' : ''}` : `Served · ${q.results ?? 'unreported'} results`;
    case 'undelivered': return 'Not fully delivered';
    case 'failed': {
      const why = q.outcome.why;
      if (why === 'budget') return 'Failed: the run’s 200 generation calls are spent';
      if (why === 'abandoned') return 'Failed: the browser left before the answer';
      return `Failed: ${['backend_error', 'meta_error', 'error'].includes(why) ? 'the page maker failed' : 'reason not reported'}${q.outcome.error ? ` — ${q.outcome.error}` : ''}`;
    }
    default: return 'Outcome not reported';
  }
}
export function counts(s) {
  return {
    Searches: s.queries.length,
    Served: s.queries.filter((q) => q.outcome.status === 'served' && q.results > 0).length,
    'No results': s.queries.filter((q) => q.outcome.status === 'served' && q.results === 0).length,
    Failed: s.queries.filter((q) => q.outcome.status === 'failed').length,
    'Pages made': s.pages.filter((p) => ['stubbed', 'stored', 'fixed', 'written_live'].includes(p.made)).length,
    Sites: s.sites.length,
    Refused: s.refused.length,
  };
}
export function resultView(s, q) {
  if (q.outcome.status === 'pending') return { origin: 'Waiting for the result list.', rows: [] };
  if (q.results === 0) return { origin: q.cache === 'missing' ? 'No results: generation was off for this search.' : 'This search returned no results.', rows: [] };
  const list = s.results.find((r) => r.key === q.key);
  if (list && list.query_id > q.id) return { origin: 'The retained list was made after this search; its earlier results are no longer held.', rows: [] };
  if (!list) return { origin: q.outcome.status === 'pending' ? 'Waiting for the result list.' : 'No result list retained for this search.', rows: [] };
  const first = s.queries.find((item) => item.id === list.query_id);
  const origin = list.query_id === q.id
    ? (list.cache === 'generated' ? 'Made for this search.' : `${cache(list.cache) || 'First observed for this search'}.`)
    : `First made for ${first ? `“${first.search}” on ${engine(first.engine)}` : `an earlier search no longer retained (query ${list.query_id})`}. Reused for this search.`;
  return { origin, rows: list.listed.map((r) => ({ ...r, page: s.pages.find((p) => p.url === r.url), site: s.sites.find((site) => site.host === r.host) })) };
}
export function tree(s) {
  const roots = new Map();
  const pages = new Map(s.pages.map((p) => [p.url, { id: `page:${p.url}`, page: p, children: [] }]));
  const root = (id, label) => {
    if (!roots.has(id)) roots.set(id, { id, label, children: [] });
    return roots.get(id);
  };
  for (const q of s.queries) root(`query:${q.key}`, q.search);
  for (const node of pages.values()) {
    const r = node.page.reason;
    let parent;
    if (r.via === 'search') parent = root(`query:${queryKey(r.query)}`, r.query);
    else if (r.via === 'link') {
      parent = pages.get(r.from);
      const seen = new Set([node.page.url]);
      let ancestor = parent;
      while (ancestor) {
        if (seen.has(ancestor.page.url)) { parent = null; break; }
        seen.add(ancestor.page.url);
        ancestor = ancestor.page.reason.via === 'link' ? pages.get(ancestor.page.reason.from) : null;
      }
      parent ||= root(`link:${r.from}`, `Linked from ${r.from} (source page not retained)`);
    } else parent = root(r.via, ({ direct: 'Addresses typed directly', fixed: 'Seed’s fixed pages' })[r.via] || 'Creation reason not reported');
    parent.children.push(node);
  }
  const flat = [];
  const visit = (node, depth) => {
    flat.push({ ...node, depth });
    node.children.sort((a, b) => (a.page.reason.rank ?? 0) - (b.page.reason.rank ?? 0) || a.page.at_ms - b.page.at_ms);
    node.children.forEach((child) => visit(child, depth + 1));
  };
  roots.forEach((node) => visit(node, 0));
  return flat;
}
