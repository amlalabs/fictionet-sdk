// What the world pane shows, derived only from the run's search snapshot.
export const ENGINES = ['google', 'bing', 'duckduckgo'];
export const engine = (name) => ({ google: 'Google', bing: 'Bing', duckduckgo: 'DuckDuckGo' }[name] || name);
const ENGINE_HOSTS = { google: 'google.com', bing: 'bing.com', duckduckgo: 'duckduckgo.com' };

// How a search was answered: made now, from the canned pages, from what
// this run made before, or not at all.
export function queryTag(s, q) {
  if (q.outcome.status === 'pending') return 'asking';
  if (q.outcome.status === 'failed') return 'refused';
  if (q.cache === 'generated' || q.cache === 'prefetched') return 'made';
  if (q.cache === 'missing') return 'missing';
  if (q.cache === 'cached') {
    const made = s.queries.some((other) => other.key === q.key && other.id < q.id && ['generated', 'prefetched'].includes(other.cache));
    return made ? 'memory' : 'canned';
  }
  return 'asking';
}

// How a page was answered on its latest fetch.
export function pageTag(p) {
  const first = { stubbed: 'made', written_live: 'made', stored: 'canned', fixed: 'canned', planted: 'planted', missing: 'missing', not_made: 'refused' }[p.made] || 'asking';
  if (p.fetches > 1 && p.latest === 'stored' && first === 'made') return 'memory';
  return first;
}

// The newest rows first: searches, pages, refused names and plants.
export function rows(s, limit = 6) {
  const path = (url) => { try { const u = new URL(url); return `${u.pathname}${u.search}`; } catch { return url; } };
  return [
    ...s.queries.map((q) => ({ at: q.at_ms, who: ENGINE_HOSTS[q.engine] || q.engine, what: q.search, tag: queryTag(s, q) })),
    ...s.pages.map((p) => ({ at: p.at_ms, who: p.host, what: path(p.url), tag: pageTag(p) })),
    ...s.refused.map((r) => ({ at: r.at_ms, who: 'DNS', what: r.name, tag: 'refused' })),
    ...(s.planted || []).map((p) => ({ at: p.at_ms, who: p.kind === 'page' ? hostOf(p.url) : 'fact', what: p.text, tag: 'planted' })),
  ].sort((a, b) => b.at - a.at).slice(0, limit);
}

export function hostOf(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

// A host as the picture labels it: without www. and its last label.
export function short(host) {
  const name = host.replace(/^www\./, '');
  const parts = name.split('.');
  const label = parts.length > 2 && parts.at(-2).length <= 3 ? parts.slice(0, -2).join('.') : parts.slice(0, -1).join('.');
  return label.length > 18 ? `${label.slice(0, 17)}…` : label || name;
}

// The picture's parts: the newest search, how each engine answered it,
// the sites its list named with the pages opened on each, the newest
// planted items and the newest refused name.
export function picture(s) {
  const q = s.queries.at(-1);
  const key = q?.key;
  const engines = ENGINES.map((name) => {
    const asked = s.queries.findLast((other) => other.engine === name && other.key === key);
    return { name, label: engine(name), tag: asked ? queryTag(s, asked) : 'idle' };
  });
  const list = s.results.find((r) => r.key === key);
  const seedHosts = new Set(s.seed?.sites || []);
  const hosts = [];
  for (const r of list?.listed || []) if (!hosts.includes(r.host)) hosts.push(r.host);
  const sites = hosts.slice(0, 6).map((host) => {
    const opened = s.pages.filter((p) => p.host === host);
    return { host, label: short(host), pages: opened.length, seed: seedHosts.has(host), tag: opened.length ? pageTag(opened.at(-1)) : 'listed' };
  });
  const planted = (s.planted || []).slice(-2).map((p) => ({ label: p.kind === 'page' ? short(hostOf(p.url)) : 'fact', text: p.text }));
  const refused = s.refused.at(-1)?.name || null;
  return { query: q?.search || null, engines, sites, more: Math.max(0, hosts.length - 6), planted, refused };
}
