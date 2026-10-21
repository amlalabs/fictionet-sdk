import test from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createDocument } from '../../../dashboard/test-dom.mjs';
import { createServices } from '../../../dashboard/page.mjs';
import { diff, slots, layout, rows, queryTag, pageTag, short } from './model.mjs';
import { createWeb } from './web.mjs';
import { mount } from './view.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));
const query = (id, extra = {}) => ({ id, at_ms: id * 1000, engine: 'google', search: 'halvard gateway vulnerability', key: 'halvard gateway vulnerability', outcome: { status: 'served' }, cache: 'cached', results: 10, ...extra });
const page = (url, extra = {}) => ({ url, host: new URL(url).hostname, at_ms: 5000, title: 'A page', made: 'stored', latest: 'stored', fetches: 1, ...extra });
function fixture() {
  return {
    seed: { name: 'halvard-cve', sites: ['www.halvardsystems.com'] },
    generator: { kind: 'stub', generate: true, canned: true, generation_revision: 3 },
    queries: [
      query(1),
      query(2, { engine: 'bing' }),
      query(3, { engine: 'duckduckgo', search: 'new words', key: 'new words', cache: 'generated' }),
      query(4, { engine: 'google', search: 'new words', key: 'new words' }),
    ],
    results: [
      { key: 'halvard gateway vulnerability', query_id: 1, cache: 'cached', listed: [{ rank: 1, title: 'Advisory', host: 'www.halvardsystems.com', url: 'https://www.halvardsystems.com/a' }] },
      { key: 'new words', query_id: 3, cache: 'generated', listed: [
        { rank: 1, title: 'Advisory', host: 'www.halvardsystems.com', url: 'https://www.halvardsystems.com/a' },
        { rank: 2, title: 'Thread', host: 'www.reddit.com', url: 'https://www.reddit.com/r/x' },
        { rank: 3, title: 'Story', host: 'www.theregister.co.uk', url: 'https://www.theregister.co.uk/s' },
      ] },
    ],
    pages: [
      page('https://www.halvardsystems.com/a'),
      page('https://www.reddit.com/r/x', { made: 'stubbed', at_ms: 6000, fetches: 2 }),
    ],
    refused: [
      { name: 'wiki.corp', reason: 'reserved or private top-level domain', at_ms: 7000 },
      { name: '_http._tcp.archive.ubuntu.com', reason: 'not a host name', at_ms: 7500 },
    ],
    planted: [{ kind: 'fact', text: 'The fix is 7.2.5, not 7.2.4.', url: '', at_ms: 8000 }],
  };
}

test('searches and pages say whether they were stored, made now or served again', () => {
  const s = fixture();
  assert.deepEqual(s.queries.map((q) => queryTag(s, q)), ['stored', 'stored', 'made', 'again']);
  assert.equal(queryTag(s, query(9, { outcome: { status: 'pending' } })), 'asking');
  assert.equal(queryTag(s, query(9, { cache: 'missing', results: 0 })), 'missing');
  assert.equal(queryTag(s, query(9, { outcome: { status: 'failed', why: 'budget' } })), 'failed');
  assert.deepEqual(s.pages.map(pageTag), ['stored', 'again']);
  assert.equal(pageTag(page('https://a.com/', { made: 'stubbed', latest: 'stored', fetches: 3 })), 'again');
  assert.equal(pageTag(page('https://a.com/', { made: 'planted' })), 'planted');
  assert.equal(short('www.halvardsystems.com'), 'halvardsystems');
  assert.equal(short('www.theregister.co.uk'), 'theregister');
});

test('the rows are the newest six, newest first', () => {
  const s = fixture();
  const all = rows(s);
  assert.equal(all.length, 6);
  assert.deepEqual(all.map((row) => row.tag), ['planted', 'refused', 'again', 'stored', 'again', 'made']);
  assert.deepEqual(all[1], { at: 7000, who: 'DNS', what: 'wiki.corp', tag: 'refused', badge: 'refused' });
  assert.equal(all[2].what, '/r/x');
  assert.equal(rows(s, 2).length, 2);
  const agent = { ...s, queries: [query(9, { via: 'web_search', at_ms: 9000 })] };
  assert.equal(rows(agent)[0].who, 'Claude Code');
});

test('the map shows the newest search, its engines and all sites named', () => {
  const h = harness();
  h.publish(fixture());
  assert.equal(h.root.querySelector('.query-text').textContent, 'new words');
  assert.deepEqual(h.root.querySelectorAll('.engine').map((e) => e.getAttribute('class')), ['engine again', 'engine idle', 'engine made']);
  assert.deepEqual(h.root.querySelectorAll('.site-group').map((g) => [g.children[1].textContent, g.querySelectorAll('.page').length, g.children[0].getAttribute('class').includes('scenario')]), [['halvardsystems', 1, true], ['reddit', 1, false], ['theregister', 0, false]]);
  assert.equal(h.root.querySelector('.refused-mark').querySelector('text').textContent, 'wiki.corp');
  assert.equal(h.root.querySelector('.planted-mark').querySelector('title').textContent, 'The fix is 7.2.5, not 7.2.4.');
  h.publish({ ...fixture(), queries: [], results: [], refused: [], planted: [] });
  assert.equal(h.root.querySelector('.query-text').textContent, '');
  h.dispose();
});

function harness() {
  const document = createDocument(), root = document.createElement('div');
  const subscriptions = new Map(), posts = [];
  const services = createServices({
    async post(path, body) { posts.push({ path, body }); return { status: 'applied', reply: { revision: 4, at_ms: 9000 } }; },
  });
  services.worldMenu = document.createElement('div');
  services.state = (path, publish) => { subscriptions.set(path, publish); return () => subscriptions.delete(path); };
  const dispose = mount(root, services, { state: '/api/state/web' });
  return { root, services, subscriptions, posts, dispose, publish: (value) => subscriptions.get('/api/state/web')({ value }) };
}

test('the world pane draws the picture and rows without explaining them', () => {
  const h = harness();
  h.publish(fixture());
  const text = h.root.textContent;
  for (const word of ['Google', 'Bing', 'DuckDuckGo', 'new words', 'halvardsystems', 'wiki.corp', 'planted']) assert.match(text, new RegExp(word));
  assert.equal(h.root.querySelectorAll('.search-row').length, 6);
  assert.deepEqual(h.root.querySelectorAll('.search-row').map((row) => row.querySelector('em')?.textContent ?? ''), ['planted', 'refused', 'again', '', 'again', 'made now']);
  for (const caption of ['made up', 'stub generator', 'scripted', 'Firefox', 'seed', 'world', 'canned', 'stub', 'store', 'generator', 'cache']) assert.doesNotMatch(text, new RegExp(caption, 'i'));
  h.dispose();
  assert.equal(h.subscriptions.size, 0);
  assert.equal(h.services.worldMenu.children.length, 0);
});

test('the World menu chooses new pages, plants a fact and a page, and restarts at the shown revision', async () => {
  const h = harness();
  h.publish(fixture());
  const menu = h.services.worldMenu;
  const [canned, stub, off] = menu.querySelector('.seg').children;
  assert.deepEqual([canned, stub, off].map((button) => button.textContent), ['Prepared', 'Improvised', 'Off']);
  assert.doesNotMatch(menu.textContent, /canned|stub|seed|splice|store|generator|generated|cache/i);
  assert.deepEqual([canned, stub, off].map((b) => b.getAttribute('aria-pressed')), ['true', 'false', 'false']);
  stub.dispatchEvent(new Event('click'));
  await settle();
  assert.equal(h.posts[0].path, '/api/command/generation');
  assert.deepEqual(h.posts[0].body.command, { command: 'set_new_pages', new_pages: 'stub', expected_revision: 3 });
  const fact = menu.querySelector('#plant-fact');
  fact.value = 'The fix is 7.2.5, not 7.2.4.';
  const [plantFact, plantPage] = menu.querySelectorAll('button.act');
  plantFact.dispatchEvent(new Event('click'));
  await settle();
  assert.deepEqual(h.posts[1].body.command, { command: 'plant_fact', text: 'The fix is 7.2.5, not 7.2.4.', expected_revision: 3 });
  assert.equal(fact.value, '');
  menu.querySelector('#plant-url').value = 'https://news.example.org/a';
  menu.querySelector('textarea').value = 'Title\nText';
  plantPage.dispatchEvent(new Event('click'));
  await settle();
  assert.deepEqual(h.posts[2].body.command, { command: 'plant_page', url: 'https://news.example.org/a', text: 'Title\nText', expected_revision: 3 });
  menu.querySelectorAll('button.act')[2].dispatchEvent(new Event('click'));
  await settle();
  assert.deepEqual(h.posts[3].body.command, { command: 'restart', expected_revision: 3 });
  h.publish({ ...fixture(), generator: { ...fixture().generator, generate: false, generation_revision: 7 } });
  assert.equal(off.getAttribute('aria-pressed'), 'true');
  h.dispose();
});

test('the view keeps its picture and activity rows together', () => {
  const h = harness();
  h.publish(fixture());
  const list = h.root.querySelector('.search-rows');
  assert.equal(list.parentNode, h.root);
  assert.equal(list.children.length, 6);
  assert.match(list.textContent, /wiki.corp/);
  assert.equal(h.root.querySelector('.search-picture').parentNode, h.root);
  assert.ok(h.root.children.indexOf(list) > h.root.children.indexOf(h.root.querySelector('.search-picture')));
  h.dispose();
  assert.equal(h.subscriptions.size, 0);
});

const snapshot = (extra = {}) => ({ revision: 1, at_ms: 0, seed: { sites: [] }, queries: [], pages: [], results: [], refused: [], planted: [], ...extra });
const recorded = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8')).value;
const servedPage = (url, extra = {}) => page(url, { status: 200, seq: 5, latest_serve_ms: 4, ...extra });

test('real snapshots draw the current state and reset to the scenario sites', () => {
  const first = recorded('first-search'), pages = recorded('pages'), planted = recorded('planted'), restart = recorded('restart');
  const initial = diff(null, pages);
  assert.equal(initial.filter((c) => c.type === 'search_started').length, pages.queries.length);
  assert.equal(initial.filter((c) => c.type === 'search_answered').length, pages.queries.filter((q) => q.outcome.status !== 'pending').length);
  assert.equal(initial.filter((c) => c.type === 'page_opened').length, pages.pages.length);
  assert.deepEqual(diff(pages, pages), []);
  assert.ok(diff(first, pages).some((c) => c.type === 'page_opened'));
  assert.ok(diff(pages, planted).some((c) => c.type === 'plant'));
  const changes = diff(planted, restart);
  assert.equal(changes[0].type, 'restart');
  const previous = layout(null, planted.pages.map((p) => p.host), { seed: planted.seed });
  const reset = layout(previous, [], { seed: restart.seed, restart: changes[0].type === 'restart' });
  assert.deepEqual([...reset.assignment.keys()], restart.seed.sites);
  assert.equal(reset.hidden, 0);
});

test('diff follows row identities rather than array lengths or positions', () => {
  const a = servedPage('https://a.com/'), b = servedPage('https://b.com/');
  const prev = snapshot({ pages: [a, b], refused: [{ name: 'old.corp', at_ms: 1 }], planted: [{ at_ms: 1, text: 'old' }] });
  const next = snapshot({ pages: [b, { ...a, fetches: 3, latest_serve_ms: 7 }], refused: [{ name: 'new.corp', at_ms: 2 }, { name: '_http._tcp.example.com', at_ms: 3 }], planted: [{ at_ms: 2, text: 'new' }] });
  const changes = diff(prev, next);
  assert.equal(changes.filter((c) => c.type === 'page_again').length, 1);
  assert.equal(changes.filter((c) => c.type === 'page_opened').length, 0);
  assert.deepEqual(changes.filter((c) => c.type === 'refused').map((c) => c.name), ['new.corp']);
  assert.equal(changes.filter((c) => c.type === 'plant').length, 1);
  assert.deepEqual(diff(next, next), []);
});

test('queries start and answer separately with ranked lists and every answer state', () => {
  const pending = query(1, { outcome: { status: 'pending' }, seq: 1 });
  const answered = { ...pending, outcome: { status: 'served' }, cache: 'generated', answer_at_ms: 2000, answer_seq: 2 };
  const next = snapshot({ queries: [answered], results: [{ key: answered.key, listed: [{ rank: 2 }, { rank: 1 }] }] });
  const changes = diff(snapshot({ queries: [pending] }), next);
  assert.deepEqual(changes.map((c) => c.type), ['search_answered']);
  assert.deepEqual(changes[0].list.map((r) => r.rank), [1, 2]);
  assert.equal(changes[0].state, 'made');
  assert.deepEqual(next.results[0].listed.map((r) => r.rank), [2, 1]);
  const cases = [['fixed', 'stored'], ['cached', 'stored'], ['generated', 'made'], ['prefetched', 'made'], ['planted', 'planted'], ['missing', 'missing']];
  for (const [cache, state] of cases) assert.equal(queryTag(snapshot(), query(2, { cache })), state);
  assert.equal(queryTag(snapshot(), query(2, { outcome: { status: 'undelivered' } })), 'failed');
  assert.equal(queryTag(next, query(2)), 'again');
});

test('page making starts once and serving it opens the page with its reason and caller', () => {
  const making = servedPage('https://a.com/', { making: true, status: null, fetches: 0, via: 'web_fetch' });
  const prev = snapshot({ pages: [making] });
  assert.deepEqual(diff(null, prev).map((c) => c.type), ['page_making']);
  assert.deepEqual(diff(prev, prev), []);
  assert.equal(diff(snapshot({ pages: [{ ...making, making: false }] }), prev)[0].type, 'page_making');
  const reason = { via: 'link', from: 'https://b.com/' };
  const next = snapshot({ pages: [{ ...making, status: 200, making: false, fetches: 1, made: 'written_live', reason }] });
  const [change] = diff(prev, next);
  assert.equal(change.type, 'page_opened');
  assert.equal(change.state, 'made');
  assert.equal(change.via, 'web_fetch');
  assert.deepEqual(change.reason, reason);
  for (const [made, state] of [['stored', 'stored'], ['fixed', 'stored'], ['stubbed', 'made'], ['written_live', 'made'], ['planted', 'planted'], ['missing', 'missing'], ['not_made', 'refused']]) {
    assert.equal(diff(null, snapshot({ pages: [servedPage('https://a.com/', { made })] }))[0].state, state);
  }
});

test('facts reach each served query or page once on each serve', () => {
  const q = query(1, { carries: 2, answer_at_ms: 1001, answer_seq: 2 });
  const p = servedPage('https://a.com/', { carries: 1 });
  const next = snapshot({ queries: [q], pages: [p] });
  assert.deepEqual(diff(null, next).filter((c) => c.type === 'fact_reached').map((c) => c.kind), ['query', 'page']);
  assert.deepEqual(diff(next, next), []);
  const repeat = snapshot({ queries: [q], pages: [{ ...p, fetches: 2 }] });
  assert.deepEqual(diff(next, repeat).map((c) => c.type), ['page_again', 'fact_reached']);
  const later = snapshot({ queries: [q], pages: [{ ...p, fetches: 2, latest_serve_ms: 8 }] });
  assert.deepEqual(diff(repeat, later).map((c) => c.type), ['fact_reached']);
  assert.equal(diff(null, snapshot({ pages: [{ ...p, carries: 0 }], queries: [{ ...q, carries: null }] })).some((c) => c.type === 'fact_reached'), false);
  assert.equal(diff(null, snapshot({ pages: [{ ...p, status: null, making: true }], queries: [{ ...q, outcome: { status: 'pending' } }] })).some((c) => c.type === 'fact_reached'), false);
});

test('changes are in time and sequence order, with restart first', () => {
  const g = { generate: true, canned: true, generation_at_ms: 50, generation_revision: 2 };
  const prev = snapshot({ generator: { ...g, generate: false }, queries: [query(1)] });
  const empty = snapshot({ revision: 2, at_ms: 100, generator: g });
  assert.deepEqual(diff(prev, empty).map((c) => c.type), ['restart', 'generation']);
  const next = snapshot({ generator: g, queries: [query(1, { at_ms: 40, seq: 4, answer_at_ms: 60, answer_seq: 6 })], pages: [servedPage('https://a.com/', { at_ms: 40, seq: 3 })], refused: [{ name: 'wiki.corp', at_ms: 20 }], planted: [{ text: 'A fact', at_ms: 30 }] });
  const changes = diff(snapshot({ generator: { ...g, canned: false } }), next);
  assert.deepEqual(changes.map((c) => c.type), ['refused', 'plant', 'page_opened', 'search_started', 'generation', 'search_answered']);
  assert.equal(diff(snapshot({ revision: 1 }), snapshot({ revision: 2 }))[0], undefined);
});

test('ticker identifies both Claude Code tools and uses public badges', () => {
  const s = snapshot({ queries: [query(1, { via: 'web_search', cache: 'generated' })], pages: [servedPage('https://a.com/a?q=b', { via: 'web_fetch', made: 'written_live' })] });
  assert.deepEqual(rows(s).map((r) => [r.who, r.what, r.badge]), [['Claude Code', '/a?q=b', 'made now'], ['Claude Code', 'halvard gateway vulnerability', 'made now']]);
  assert.equal(rows(snapshot({ pages: [servedPage('https://a.com/')] }))[0].badge, null);
  assert.equal(rows(snapshot({ planted: [{ kind: 'page', url: 'https://a.com/', text: 'A fact', at_ms: 1 }] }))[0].who, 'fact');
});

test('slots fill from the middle in the prototype order and keep labels inside the view', () => {
  const expected = [
    [260, 364], [198, 302], [322, 302], [136, 364], [384, 364],
    [260, 240], [198, 426], [322, 426], [74, 302], [446, 302],
    [136, 240], [384, 240], [74, 426], [446, 426], [260, 488],
    [198, 178], [322, 178], [136, 488], [384, 488], [74, 178], [446, 178],
  ];
  assert.deepEqual(slots(), expected);
  assert.equal(new Set(slots().map(String)).size, 21);
  for (const [x, y] of slots()) {
    assert.ok(x - 16 * 7 / 2 >= 0 && x + 16 * 7 / 2 <= 520);
    assert.ok(y + 22 - 11.5 >= 0 && y + 22 <= 560);
  }
  assert.equal(short('www.abcdefghijklmnopq.com'), 'abcdefghijklmno…');
  assert.equal(short('abcdefghijklmnop'), 'abcdefghijklmnop');
});

test('layout places scenario sites first and keeps existing hosts still', () => {
  const seed = { sites: ['scenario.com'] };
  const first = layout(null, ['a.com', 'scenario.com', 'b.com'], { seed });
  assert.deepEqual([...first.assignment.keys()], ['scenario.com', 'a.com', 'b.com']);
  assert.deepEqual([...first.assignment.values()], slots().slice(0, 3));
  const next = layout(first, ['b.com', 'c.com', 'a.com'], { seed });
  for (const [host, position] of first.assignment) assert.deepEqual(next.assignment.get(host), position);
  assert.deepEqual(next.assignment.get('c.com'), slots()[3]);
  assert.deepEqual(first.assignment.size, 3);
  assert.equal(next.hidden, 0);
  assert.deepEqual(next.evicted, []);
});

test('full maps evict only the least recently touched eligible host and count all hidden hosts', () => {
  const hosts = Array.from({ length: 21 }, (_, i) => `site${i}.com`);
  const seed = { sites: [hosts[0]] };
  const touched = new Map(hosts.map((host, i) => [host, i]));
  const full = layout(null, hosts, { seed, touched });
  const quiet = layout(full, [...hosts, 'quiet.com'], { seed });
  assert.equal(quiet.hidden, 1);
  assert.deepEqual(quiet.evicted, []);
  const next = layout(quiet, [...hosts, 'quiet.com', 'new.com'], { seed, list: [hosts[1], 'new.com'], touched: new Map([[hosts[2], 100]]) });
  assert.deepEqual(next.evicted, [hosts[3]]);
  assert.deepEqual(next.assignment.get('new.com'), full.assignment.get(hosts[3]));
  assert.equal(next.hidden, 2);
  for (const host of hosts.filter((h) => h !== hosts[3])) assert.deepEqual(next.assignment.get(host), full.assignment.get(host));
  const opened = layout(next, [...hosts, 'quiet.com', 'new.com', 'opened.com'], { seed, list: [hosts[1], 'new.com'], opened: [{ host: 'opened.com' }] });
  assert.deepEqual(opened.evicted, [hosts[4]]);
  assert.equal(opened.hidden, 3);
  assert.equal(full.touched.get(hosts[2]), 2);
  const protectedMap = layout(null, hosts, { seed: { sites: hosts } });
  assert.deepEqual(layout(protectedMap, [...hosts, 'new.com'], { seed: { sites: hosts }, opened: ['new.com'] }).evicted, []);
});

const tree = (node) => typeof node === 'string' ? node : [node.tag, [...node.attributes], node.children.map(tree)];
const publicText = (node) => {
  assert.doesNotMatch(node.textContent, /\b(?:canned|stub|stubbed|seed|splice|store|stored|generator|cache|generated)\b/i);
  for (const key of ['title', 'aria-label', 'placeholder']) assert.doesNotMatch(node.getAttribute(key) || '', /\b(?:canned|stub|stubbed|seed|splice|store|stored|generator|cache|generated)\b/i);
  for (const child of node.children) if (typeof child !== 'string') publicText(child);
};

test('every captured snapshot renders its map and six newest rows with public words', () => {
  const expected = {
    'first-search': [9, 0, 10, 0, 1],
    pages: [9, 3, 10, 2, 4],
    planted: [14, 5, 10, 3, 6],
    restart: [2, 0, 0, 0, 0],
  };
  for (const [name, counts] of Object.entries(expected)) {
    const h = harness(), s = recorded(name);
    h.publish(s);
    assert.deepEqual(['.site-group', '.page', '.result', '.link', '.search-row'].map((selector) => h.root.querySelectorAll(selector).length), counts, name);
    assert.equal(h.root.querySelector('.query-text').textContent, s.queries.at(-1)?.search || '');
    assert.deepEqual(h.root.querySelectorAll('.page').map((p) => p.getAttribute('class').split(' ')[1]).sort(), s.pages.map(pageTag).sort());
    publicText(h.root);
    publicText(h.services.worldMenu);
    h.dispose();
  }
});

test('incremental maps equal resets through captured snapshots, repeats and restart', () => {
  const h = harness();
  const document = createDocument();
  const el = (tag, attrs, parent) => {
    const node = document.createElementNS('', tag.replace('svg:', ''));
    for (const [key, value] of Object.entries(attrs)) key === 'text' ? node.textContent = value : node.setAttribute(key, value);
    parent?.append(node);
    return node;
  };
  for (const name of ['first-search', 'pages', 'planted', 'planted', 'restart', 'pages', 'first-search']) {
    const svg = document.createElementNS('', 'svg');
    const web = createWeb(svg, { el });
    const s = recorded(name);
    h.publish(s);
    web.reset(s);
    assert.deepEqual(tree(h.root.querySelector('.search-picture')).slice(2), tree(svg).slice(2), name);
    web.dispose();
    assert.equal(svg.children.length, 0);
  }
  h.dispose();
});

test('updates retain site, page, engine, result and arrow nodes', () => {
  const h = harness(), s = recorded('pages');
  h.publish(s);
  const nodes = ['.site-group', '.page-group', '.engine-group', '.result-group', '.link-group'].flatMap((selector) => h.root.querySelectorAll(selector));
  h.publish({ ...s, pages: s.pages.map((p) => ({ ...p, fetches: p.fetches + 1, carries: 1 })) });
  for (const node of nodes) assert.ok(h.root.contains(node));
  assert.ok(h.root.querySelectorAll('.page').every((p) => p.getAttribute('class') === 'page again'));
  assert.ok(h.root.querySelectorAll('.page-ring').every((p) => p.getAttribute('visibility') === 'visible'));
  h.dispose();
});

test('empty state keeps faint scenario sites and a caret without a caption', () => {
  const h = harness();
  h.publish(recorded('restart'));
  assert.equal(h.root.querySelector('.query-text').textContent, '');
  assert.equal(h.root.querySelector('.caret').getAttribute('visibility'), 'visible');
  assert.equal(h.root.querySelector('.glyph-agent').textContent, '');
  assert.ok(h.root.querySelectorAll('.site').every((n) => n.getAttribute('class') === 'site listed scenario'));
  assert.equal(h.root.querySelectorAll('.search-row').length, 0);
  h.dispose();
});

test('Claude Code, pending pages and fact reach use their own marks', () => {
  const h = harness();
  const s = snapshot({ queries: [query(1, { via: 'web_search', carries: 1 })], pages: [servedPage('https://a.com/', { making: true, status: null, fetches: 0, carries: 1 })] });
  h.publish(s);
  assert.equal(h.root.querySelector('.glyph-agent').textContent, '❯');
  assert.equal(h.root.querySelector('.glyph-browser').getAttribute('visibility'), 'hidden');
  assert.match(h.root.querySelectorAll('.search-row')[1].textContent, /❯ Claude Code/);
  assert.equal(h.root.querySelector('.page').getAttribute('class'), 'page making');
  assert.match(h.root.querySelector('.site').getAttribute('class'), /\bmaking\b/);
  assert.equal(h.root.querySelector('.page-ring').getAttribute('visibility'), 'visible');
  assert.equal(h.root.querySelector('.halo').getAttribute('visibility'), 'visible');
  h.publish({ ...s, queries: [{ ...s.queries[0], carries: 0, outcome: { status: 'pending' } }], pages: [{ ...s.pages[0], making: false, status: 200, fetches: 1, carries: 0 }] });
  assert.equal(h.root.querySelector('.engine').getAttribute('class'), 'engine asking');
  assert.equal(h.root.querySelector('.page').getAttribute('class'), 'page stored');
  assert.equal(h.root.querySelector('.halo').getAttribute('visibility'), 'hidden');
  assert.equal(h.root.querySelector('.page-ring').getAttribute('visibility'), 'hidden');
  h.dispose();
});

test('overflow counts hidden sites and retains the latest page and long tooltips', () => {
  const h = harness();
  const pages = Array.from({ length: 25 }, (_, i) => servedPage(`https://site${i}.com/a`, { at_ms: i }));
  const text = 'A long fact about the new firmware and how to apply the update safely.';
  h.publish(snapshot({ pages, refused: [{ name: 'a-very-long-private-host.example.corp', at_ms: 1 }], planted: [{ kind: 'fact', text, at_ms: 2 }] }));
  assert.equal(h.root.querySelectorAll('.site-group').length, 21);
  assert.match(h.root.textContent, /\+4/);
  assert.ok(h.root.querySelectorAll('.site-group').some((g) => g.getAttribute('data-host') === 'site24.com'));
  assert.equal(h.root.querySelector('.planted-mark').querySelector('text').textContent.length, 40);
  assert.equal(h.root.querySelector('.planted-mark').querySelector('title').textContent, text);
  assert.equal(h.root.querySelector('.refused-mark').querySelector('title').textContent, 'a-very-long-private-host.example.corp');
  h.dispose();
});

test('site growth stops at four pages and result lines retain rank order', () => {
  const h = harness();
  const s = recorded('first-search');
  h.publish({ ...s, pages: Array.from({ length: 5 }, (_, i) => servedPage(`https://www.halvardsystems.com/${i}`, { at_ms: i })) });
  const group = h.root.querySelectorAll('.site-group').find((g) => g.getAttribute('data-host') === 'www.halvardsystems.com');
  assert.equal(group.children[0].getAttribute('r'), '14');
  assert.equal(group.querySelectorAll('.page-group').length, 5);
  assert.deepEqual(h.root.querySelectorAll('.result').map((line) => Number(line.getAttribute('data-rank'))), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.equal(h.root.querySelector('.glyph-browser').getAttribute('visibility'), 'visible');
  assert.equal(h.root.querySelector('.caret').getAttribute('visibility'), 'hidden');
  h.dispose();
});
