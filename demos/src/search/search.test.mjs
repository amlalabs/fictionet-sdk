import test from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createDocument } from '../../../dashboard/test-dom.mjs';
import { createServices, appShell } from '../../../dashboard/page.mjs';
import { diff, slots, layout, rows, engine, ENGINE_HOSTS, queryTag, pageTag, short, hostMark, siteKey } from './model.mjs';
import { createWeb } from './web.mjs';
import { createMotion } from './motion.mjs';
import { mount } from './view.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));
const query = (id, extra = {}) => ({ id, at_ms: id * 1000, engine: 'google', search: 'halvard gateway vulnerability', key: 'halvard gateway vulnerability', outcome: { status: 'served' }, cache: 'cached', results: 10, ...extra });
const page = (url, extra = {}) => ({ url, host: new URL(url).hostname, site: 'A Site', at_ms: 5000, title: 'A page', made: 'stored', latest: 'stored', fetches: 1, ...extra });
function fixture() {
  return {
    seed: { name: 'halvard-cve', sites: [{ host: 'www.halvardsystems.com', site: 'Halvard Systems' }] },
    generator: { kind: 'stub', generate: true, canned: true, generation_revision: 3 },
    queries: [
      query(1),
      query(2, { engine: 'bing' }),
      query(3, { engine: 'duckduckgo', search: 'new words', key: 'new words', cache: 'generated' }),
      query(4, { engine: 'google', search: 'new words', key: 'new words' }),
    ],
    results: [
      { key: 'halvard gateway vulnerability', query_id: 1, cache: 'cached', listed: [{ rank: 1, title: 'Advisory', host: 'www.halvardsystems.com', site: 'Halvard Systems', url: 'https://www.halvardsystems.com/a' }] },
      { key: 'new words', query_id: 3, cache: 'generated', listed: [
        { rank: 1, title: 'Advisory', host: 'www.halvardsystems.com', site: 'Halvard Systems', url: 'https://www.halvardsystems.com/a' },
        { rank: 2, title: 'Thread', host: 'www.reddit.com', site: 'Reddit', url: 'https://www.reddit.com/r/x' },
        { rank: 3, title: 'Story', host: 'www.theregister.co.uk', site: 'The Register', url: 'https://www.theregister.co.uk/s' },
      ] },
    ],
    pages: [
      page('https://www.halvardsystems.com/a', { site: 'Halvard Systems' }),
      page('https://www.reddit.com/r/x', { site: 'Reddit', made: 'stubbed', at_ms: 6000, fetches: 2 }),
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
  assert.equal(short('Halvard Systems'), 'Halvard Systems');
  assert.equal(short('The Register'), 'The Register');
});

test('the rows are the newest eight, newest first', () => {
  const s = fixture();
  const all = rows(s);
  assert.equal(all.length, 8);
  assert.deepEqual(all.map((row) => row.tag), ['planted', 'refused', 'again', 'stored', 'again', 'made', 'stored', 'stored']);
  assert.deepEqual(all[1], { at: 7000, who: 'DNS', what: 'wiki.corp', tag: 'refused', badge: 'refused' });
  assert.equal(all[2].what, 'A page');
  assert.equal(all[2].title, 'https://www.reddit.com/r/x');
  assert.equal(all[2].who, 'Reddit');
  assert.equal(rows(s, 2).length, 2);
  const agent = { ...s, queries: [query(9, { via: 'web_search', at_ms: 9000 })] };
  assert.equal(rows(agent)[0].who, 'Claude Code');
});

test('the map shows the newest search, its engines and all sites named', () => {
  const h = harness();
  h.publish(fixture());
  assert.equal(h.root.querySelector('.query-text').textContent, 'new words');
  assert.deepEqual(h.root.querySelectorAll('.engine').map((e) => e.getAttribute('class')), ['engine again', 'engine idle', 'engine made']);
  assert.deepEqual(h.root.querySelectorAll('.site-group').map((g) => [g.children[1].textContent, g.querySelectorAll('.page').length, g.children[0].getAttribute('class').includes('scenario')]), [['Halvard Systems', 1, true], ['Reddit', 1, false], ['The Register', 0, false]]);
  assert.equal(h.root.querySelector('.refused-mark').querySelector('text').textContent, 'wiki.corp');
  assert.equal(h.root.querySelector('.planted-mark').querySelector('title').textContent, 'The fix is 7.2.5, not 7.2.4.');
  h.publish({ ...fixture(), queries: [], results: [], refused: [], planted: [] });
  assert.equal(h.root.querySelector('.query-text').textContent, '');
  h.dispose();
});

function harness(window) {
  const document = window?.document || createDocument();
  if (window) document.defaultView = window;
  const root = document.createElement('div');
  const subscriptions = new Map(), posts = [];
  const watch = document.createElement('source');
  watch.close = () => {};
  const services = createServices({
    watch: () => watch,
    async post(path, body) { posts.push({ path, body }); return { status: 'applied', reply: { revision: 4, at_ms: 9000 } }; },
  });
  services.worldMenu = document.createElement('div');
  services.state = (path, publish) => { subscriptions.set(path, publish); return () => subscriptions.delete(path); };
  const dispose = mount(root, services, { state: '/api/state/web' });
  return { root, services, subscriptions, posts, watch, dispose: () => { dispose(); services.dispose(); }, publish: (value) => subscriptions.get('/api/state/web')({ value }) };
}

test('the world pane draws the picture and rows without explaining them', () => {
  const h = harness();
  h.publish(fixture());
  const text = h.root.textContent;
  for (const word of ['Google', 'Bing', 'DuckDuckGo', 'new words', 'halvardsystems', 'wiki.corp', 'planted']) assert.match(text, new RegExp(word));
  assert.equal(h.root.querySelectorAll('.search-row').length, 8);
  assert.deepEqual(h.root.querySelectorAll('.search-row').map((row) => row.querySelector('em')?.textContent ?? ''), ['planted', 'refused', 'again', '', 'again', '', '', '']);
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
  assert.deepEqual([canned, stub, off].map((button) => button.textContent), ['Prepared first', 'Improvised', 'Off']);
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
  assert.equal(list.children.length, 8);
  assert.match(list.textContent, /wiki.corp/);
  assert.equal(h.root.querySelector('.search-picture').parentNode, h.root);
  assert.ok(h.root.children.indexOf(list) > h.root.children.indexOf(h.root.querySelector('.search-picture')));
  h.dispose();
  assert.equal(h.subscriptions.size, 0);
});

const snapshot = (extra = {}) => ({ revision: 1, at_ms: 0, seed: { sites: [] }, queries: [], pages: [], results: [], refused: [], planted: [], ...extra });
const recorded = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8')).value;
const servedPage = (url, extra = {}) => page(url, { status: 200, seq: 5, latest_serve_ms: 4, ...extra });

test('captured snapshots include world names and the search, page, plant and restart stages', () => {
  const states = ['first-search', 'pages', 'planted', 'restart'].map((name) => {
    const response = JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8'));
    assert.equal(response.status.too_large, false);
    const s = response.value;
    for (const row of [...s.seed.sites, ...s.sites, ...s.pages, ...s.results.flatMap((r) => r.listed)]) {
      assert.equal(typeof row.site, 'string');
      assert.ok(row.site.trim().length > 0, row.host);
    }
    return s;
  });
  const [first, pages, planted, restart] = states;
  assert.equal(first.queries.length, 1);
  assert.equal(first.queries[0].outcome.status, 'served');
  assert.equal(first.results[0].listed.length, 10);
  assert.equal(first.pages.length, 0);
  assert.equal(pages.pages.length, 3);
  assert.ok(pages.pages.every((p) => p.status === 200 && p.fetches === 1));
  assert.deepEqual(planted.pages, pages.pages);
  assert.deepEqual(planted.planted.map(({ kind, text, url }) => ({ kind, text, url })), [
    { kind: 'fact', text: 'The fix is 7.2.5, not 7.2.4.', url: '' },
    { kind: 'page', text: 'Firmware update', url: 'https://news.example.org/update' },
  ]);
  for (const key of ['queries', 'results', 'pages', 'refused', 'planted']) assert.deepEqual(restart[key], []);
  assert.deepEqual(states.map((s) => s.generator.generation_revision), [0, 0, 2, 3]);
  for (let i = 1; i < states.length; i++) assert.ok(states[i].revision > states[i - 1].revision);
});

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
  const previous = layout(null, planted.pages.map((p) => p.host), { seed: { sites: planted.seed.sites.map((s) => s.host) } });
  const reset = layout(previous, [], { seed: { sites: restart.seed.sites.map((s) => s.host) }, restart: changes[0].type === 'restart' });
  assert.deepEqual([...reset.assignment.keys()], restart.seed.sites.map((s) => s.host));
  assert.deepEqual([...reset.assignment.values()], slots().slice(0, restart.seed.sites.length));
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
  assert.deepEqual(rows(s).map((r) => [r.who, r.what, r.badge]), [['Claude Code', 'A page', null], ['Claude Code', '“halvard gateway vulnerability”', null]]);
  assert.equal(rows(snapshot({ pages: [servedPage('https://a.com/')] }))[0].badge, null);
  assert.equal(rows(snapshot({ planted: [{ kind: 'page', url: 'https://a.com/', text: 'A fact', at_ms: 1 }] }))[0].who, 'You');
});

test('mixed ticker rows keep their time, identity, path and badge', () => {
  const s = snapshot({
    generator: fixture().generator,
    queries: [query(1, { cache: 'generated' }), query(2), query(3, { engine: 'bing', key: 'other', cache: 'fixed' }), query(4, { engine: 'duckduckgo', key: 'third', cache: 'prefetched' }), query(5, { via: 'web_search', cache: 'generated' })],
    pages: [page('https://www.example.com/old?q=yes', { at_ms: 6000 }), page('https://new.example.com/new', { at_ms: 7000, made: 'written_live', carries: 1 }), page('https://again.example.com/a', { at_ms: 8000, fetches: 2 }), page('https://tool.example.com/a?q=b', { at_ms: 9000, via: 'web_fetch', made: 'stubbed' }), page('https://wait.example.com/pending', { at_ms: 62000, making: true, status: null, made: 'not_made', fetches: 0 })],
    refused: [{ name: 'wiki.corp', at_ms: 10000 }],
    planted: [{ kind: 'fact', text: 'A fact', at_ms: 11000 }, { kind: 'page', text: 'A planted page', url: 'https://www.plant.example.com/a', at_ms: 12000 }],
  });
  const all = rows(s, 20);
  assert.deepEqual(all.map((r) => [r.at, r.who, r.what, r.badge]), [
    [62000, 'A Site', 'A page', 'writing'],
    [12000, 'You', 'A planted page', 'planted'],
    [11000, 'You', 'A fact', 'planted'],
    [10000, 'DNS', 'wiki.corp', 'refused'],
    [9000, 'Claude Code', 'A page', null],
    [8000, 'A Site', 'A page', 'again'],
    [7000, 'A Site', 'A page', null],
    [6000, 'A Site', 'A page', null],
    [5000, 'Claude Code', '“halvard gateway vulnerability”', null],
    [4000, 'DuckDuckGo', '“halvard gateway vulnerability”', null],
    [3000, 'Bing', '“halvard gateway vulnerability”', null],
    [2000, 'Google', '“halvard gateway vulnerability”', 'again'],
    [1000, 'Google', '“halvard gateway vulnerability”', null],
  ]);
  const h = harness(); h.publish(s);
  const lines = h.root.querySelectorAll('.search-row');
  assert.equal(lines.length, 8);
  assert.equal(lines[0].querySelector('time').textContent, 'now');
  assert.match(lines[4].textContent, /❯ Claude Code/);
  assert.equal(lines[4].querySelector('b').getAttribute('title'), 'https://tool.example.com/a?q=b');
  h.publish({ ...s, pages: s.pages.filter((p) => p.at_ms < 9000), queries: [], refused: [], planted: [] });
  const made = h.root.querySelectorAll('.search-row')[1];
  assert.ok(made.querySelector('.made-dot'));
  assert.equal(made.querySelector('.made-dot').getAttribute('role'), 'img');
  assert.equal(made.querySelector('.made-dot').getAttribute('aria-label'), 'Made now');
  assert.equal(made.querySelector('em'), null);
  assert.ok(made.querySelector('b').querySelector('.fact-dot'));
  h.publish({ ...s, pages: [{ ...s.pages.at(-1), making: false, status: 200, made: 'written_live', fetches: 1 }] });
  assert.ok(h.root.querySelector('.search-row').querySelector('.made-dot'));
  assert.equal(h.root.querySelector('.search-row').querySelector('em'), null);
  h.dispose();
});

test('each page mode posts its wire value and selects the snapshot choice', async () => {
  const h = harness(), s = fixture(); h.publish(s);
  const menu = h.services.worldMenu;
  const buttons = menu.querySelector('.seg').children;
  for (const [i, mode] of ['canned', 'stub', 'off'].entries()) {
    buttons[i].click(); await settle();
    assert.deepEqual(h.posts[i].body.command, { command: 'set_new_pages', new_pages: mode, expected_revision: 3 });
    h.publish({ ...s, generator: { ...s.generator, generate: mode !== 'off', canned: mode === 'canned' } });
    assert.deepEqual(buttons.map((b) => b.getAttribute('aria-pressed')), buttons.map((_, j) => String(i === j)));
    assert.equal(menu.querySelector('.mode-description'), null);
    assert.doesNotMatch(menu.textContent, /canned|stub|seed|splice|store|generator|generated|cache/i);
  }
  h.dispose();
});

test('the menu gives short status messages without exposing command internals', async () => {
  const h = harness(); h.publish(fixture());
  const menu = h.services.worldMenu, button = menu.querySelector('.seg').children[0];
  for (const reply of [
    { status: 'pending' },
    { status: 'rejected', rejection: { reason: 'invalid', message: 'This world has no canned pages' } },
  ]) {
    h.services.transport.post = async () => reply;
    button.click(); await settle();
    assert.ok(menu.querySelector('.note').textContent);
    assert.doesNotMatch(menu.textContent, /canned|stub|seed|splice|store|generator|generated|cache/i);
  }
  h.services.transport.post = async () => { throw Object.assign(new Error('generator unavailable'), { body: { rejection: { reason: 'stale_revision' } } }); };
  button.click(); await settle();
  assert.equal(menu.querySelector('.note').textContent, 'The world changed. Try again.');
  h.services.transport.post = async () => { throw new Error('generator unavailable'); };
  button.click(); await settle();
  assert.equal(menu.querySelector('.note').textContent, 'The request could not be completed.');
  assert.doesNotMatch(menu.textContent, /canned|stub|seed|splice|store|generator|generated|cache/i);
  h.dispose();
});

test('long ticker values retain their full tooltip', () => {
  const h = harness(), text = 'A long question '.repeat(20);
  h.publish(snapshot({ queries: [query(1, { search: text })] }));
  const what = h.root.querySelector('.search-row').querySelector('b');
  assert.equal(what.textContent, `“${text}”`);
  assert.equal(what.getAttribute('title'), `“${text}”`);
  h.dispose();
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
    assert.ok(x - 58 >= 0 && x + 58 <= 520);
    assert.ok(y + 32 - 12.5 >= 0 && y + 32 <= 560);
  }
  assert.equal(short('abcdefghijklmnopqrs'), 'abcdefghijklmnopqrs');
  for (const [i, [x, y]] of slots().entries()) for (const [tx, ty] of slots().slice(i + 1)) {
    assert.ok(Math.abs(y - ty) >= 12.5 || Math.abs(x - tx) >= 124);
  }
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
  assert.equal(next.assignment.size, 4);
  assert.deepEqual(next.evicted, []);
});

test('layout removes departed sites, reuses their slots and retains every requested host', () => {
  const hosts = Array.from({ length: 21 }, (_, i) => `site${i}.com`);
  const seed = { sites: [hosts[0]] };
  const full = layout(null, hosts, { seed });
  const next = layout(full, [...hosts.slice(1, -1), 'new.com'], { seed });
  assert.deepEqual(next.evicted, [hosts.at(-1)]);
  assert.deepEqual(next.assignment.get('new.com'), full.assignment.get(hosts.at(-1)));
  for (const host of hosts.slice(0, -1)) assert.deepEqual(next.assignment.get(host), full.assignment.get(host));
  assert.equal(next.assignment.size, 21);
  const expanded = layout(full, [...hosts, 'opened.com'], { seed });
  assert.equal(expanded.assignment.size, 22);
  assert.deepEqual(expanded.evicted, []);
  for (const host of [...hosts, 'opened.com']) assert.ok(expanded.assignment.has(host));
  assert.equal(new Set([...expanded.assignment.values()].map(String)).size, 22);
});

const tree = (node) => typeof node === 'string' ? node : [node.tag, [...node.attributes], node.children.map(tree)];
const publicText = (node) => {
  assert.doesNotMatch(node.textContent, /\b(?:canned|stub|stubbed|seed|splice|store|stored|generator|cache|generated)\b/i);
  for (const key of ['title', 'aria-label', 'placeholder']) assert.doesNotMatch(node.getAttribute(key) || '', /\b(?:canned|stub|stubbed|seed|splice|store|stored|generator|cache|generated)\b/i);
  for (const child of node.children) if (typeof child !== 'string') publicText(child);
};

test('every captured snapshot renders its map and eight newest rows with public words', () => {
  const expected = {
    'first-search': [9, 0, 10, 0, 1],
    pages: [9, 3, 10, 0, 4],
    planted: [9, 3, 10, 0, 6],
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

test('opened sites all remain visible with the latest page and long tooltips', () => {
  const h = harness();
  const pages = Array.from({ length: 25 }, (_, i) => servedPage(`https://site${i}.com/a`, { at_ms: i }));
  const text = 'A long fact about the new firmware and how to apply the update safely.';
  h.publish(snapshot({ pages, refused: [{ name: 'a-very-long-private-host.example.corp', at_ms: 1 }], planted: [{ kind: 'fact', text, at_ms: 2 }] }));
  assert.equal(h.root.querySelectorAll('.site-group').length, 25);
  assert.equal(h.root.querySelector('.overflow'), null);
  const positions = locations(h.root);
  assert.equal(new Set([...positions.values()].map(String)).size, 25);
  for (const [x, y] of positions.values()) {
    assert.ok(Number(x) - 58 >= 0 && Number(x) + 58 <= 520);
    assert.ok(Number(y) >= 178 && Number(y) <= 488);
  }

  assert.ok(h.root.querySelectorAll('.site-group').some((g) => g.getAttribute('data-host') === 'site24.com'));
  assert.equal(h.root.querySelector('.planted-mark').querySelectorAll('tspan').length, 2);
  assert.equal(h.root.querySelector('.planted-mark').querySelectorAll('tspan').map((line) => line.textContent).join(''), text);
  assert.equal(h.root.querySelector('.planted-mark').querySelector('title').textContent, text);
  assert.equal(h.root.querySelector('.refused-mark').querySelector('title').textContent, 'a-very-long-private-host.example.corp');
  h.dispose();
});

test('site growth reaches its limit at five pages and result lines retain rank order', () => {
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

function animationWindow({ reduced = false, hidden = false } = {}) {
  const document = createDocument(), media = document.createElement('media');
  document.hidden = hidden;
  media.matches = reduced;
  const calls = [], frames = new Map(), timers = new Map();
  let now = 0, timerId = 0;
  let frameId = 0;
  const create = document.createElement.bind(document);
  document.createElement = (tag) => {
    const node = create(tag);
    node.getTotalLength = () => tag === 'circle' ? 2 * Math.PI * Number(node.getAttribute('r')) : 100;
    node.getPointAtLength = (length) => ({ x: length, y: length });
    node.animate = (keyframes, options) => {
      let resolve, reject, pending = true;
      const finished = new Promise((yes, no) => { resolve = yes; reject = no; });
      const animation = {
        node, keyframes, options, finished, canceled: false,
        finish() { if (pending) { pending = false; resolve(); } },
        cancel() { animation.canceled = true; if (pending) { pending = false; reject(new Error('Canceled')); } },
      };
      calls.push(animation);
      return animation;
    };
    return node;
  };
  const window = {
    document, calls, media,
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { fn, at: now + ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
    advance(ms) {
      now += ms;
      for (const [id, timer] of timers) if (timer.at <= now) { timers.delete(id); timer.fn(); }
    },
    matchMedia: () => media,
    requestAnimationFrame(callback) { const id = ++frameId; frames.set(id, callback); return id; },
    cancelAnimationFrame(id) { frames.delete(id); },
    tick(now) { const batch = [...frames.values()]; frames.clear(); batch.forEach((callback) => callback(now)); },
    async finish() { calls.forEach((a) => a.finish()); window.advance(Math.max(0, ...[...timers.values()].map((timer) => timer.at - now))); window.tick(0); window.tick(1000); await settle(); },
    get frameCount() { return frames.size; },
  };
  return window;
}
const transientNodes = (root) => root.querySelectorAll('circle').concat(root.querySelectorAll('line'), root.querySelectorAll('path')).filter((node) => node.getAttribute('data-transient') !== null);
const locations = (root) => new Map(root.querySelectorAll('.site-group').map((g) => [g.getAttribute('data-host'), [g.children[0].getAttribute('cx'), g.children[0].getAttribute('cy')]]));
const resultList = (n) => ({ key: `question ${n}`, query_id: n, listed: [{ rank: 1, host: `site${n}.com`, url: `https://site${n}.com/` }] });

test('a twenty-fifth list preserves sites after the oldest list falls out', () => {
  const h = harness();
  let s = snapshot();
  h.publish(s);
  for (let n = 1; n <= 25; n++) {
    const before = locations(h.root);
    const q = query(n, { key: `question ${n}`, search: `question ${n}` });
    s = { ...s, queries: [...s.queries, q], results: [...s.results, resultList(n)].slice(-24) };
    h.publish(s);
    const after = locations(h.root);
    for (const [host, position] of before) if (after.has(host)) assert.deepEqual(after.get(host), position, host);
    if (n === 25) assert.ok(after.has('site25.com'));
  }
  h.dispose();
});

test('a new list retains the previous search in its slot and drops unrelated history', () => {
  const h = harness();
  const lists = Array.from({ length: 21 }, (_, i) => resultList(i + 1));
  const s = snapshot({ results: lists, queries: [query(21, { key: lists.at(-1).key })] });
  h.publish(s);
  const before = locations(h.root);
  const list = { ...resultList(22), listed: [22, 23, 24].map((i, rank) => ({ ...resultList(i).listed[0], rank: rank + 1 })) };
  h.publish({ ...s, results: [...lists, list], queries: [...s.queries, query(22, { key: list.key })] });
  const after = locations(h.root), evicted = [...before.keys()].filter((host) => !after.has(host));
  assert.equal(before.size, 1);
  assert.equal(after.size, 4);
  assert.equal(evicted.length, 0);
  for (const [host, position] of before) if (after.has(host)) assert.deepEqual(after.get(host), position, host);
  for (const row of list.listed) assert.ok(after.has(row.host));
  h.dispose();
});

function motionSequence() {
  const pending = query(1, { via: 'web_search', outcome: { status: 'pending' }, cache: 'unknown' });
  const answer = { ...pending, outcome: { status: 'served' }, cache: 'fixed' };
  let s = snapshot();
  const sequence = [s];
  const next = (extra) => { s = { ...s, ...extra }; sequence.push(s); };
  next({ queries: [pending] });
  next({ queries: [answer], results: [{ key: answer.key, query_id: 1, listed: [{ rank: 1, host: 'a.com', url: 'https://a.com/' }, { rank: 2, host: 'b.com', url: 'https://b.com/' }] }] });
  next({ pages: [servedPage('https://a.com/', { reason: { via: 'search', query: answer.search } })] });
  next({ pages: [...s.pages, servedPage('https://b.com/', { made: 'written_live', fetches: 0, status: null, making: true })] });
  next({ pages: [s.pages[0], { ...s.pages[1], fetches: 1, status: 200, making: false, via: 'web_fetch', reason: { via: 'link', from: 'https://a.com/' } }] });
  next({ pages: [s.pages[0], { ...s.pages[1], fetches: 2 }] });
  next({ planted: [{ kind: 'fact', text: 'Use 7.2.5, not 7.2.4', at_ms: 10 }] });
  next({ pages: s.pages.map((p) => ({ ...p, carries: 1, fetches: p.fetches + 1 })), queries: [...s.queries, query(2, { carries: 1, cache: 'generated' })] });
  next({ queries: [...s.queries, query(3, { carries: 1, cache: 'cached' })] });
  next({ refused: [{ name: 'wiki.corp', at_ms: 20 }] });
  next({ pages: [...s.pages, servedPage('https://b.com/direct', { reason: { via: 'direct' } })] });
  next({ revision: 2, queries: [], pages: [], results: [], planted: [], refused: [] });
  return sequence;
}

test('full and reduced motion finish in the same DOM through every fixture and event', async () => {
  for (const sequence of [motionSequence(), ['restart', 'first-search', 'pages', 'planted', 'restart'].map(recorded)]) {
    const fullWindow = animationWindow(), reducedWindow = animationWindow({ reduced: true });
    const full = harness(fullWindow), reduced = harness(reducedWindow);
    for (const s of sequence) {
      full.publish(s); reduced.publish(s);
      await fullWindow.finish(); await reducedWindow.finish();
      assert.equal(transientNodes(full.root).length, 0);
      assert.deepEqual(tree(full.root.querySelector('.search-picture')), tree(reduced.root.querySelector('.search-picture')));
      assert.deepEqual(tree(full.root.querySelector('.search-rows')), tree(reduced.root.querySelector('.search-rows')));
      const reset = harness(); reset.publish(s);
      assert.deepEqual(tree(full.root.querySelector('.search-picture')), tree(reset.root.querySelector('.search-picture')));
      reset.dispose();
    }
    assert.ok(fullWindow.calls.length > 0);
    assert.ok(reducedWindow.calls.every((a) => a.node.getAttribute('class') === 'ring again' && a.options.duration === 150 && a.keyframes.every((frame) => Object.keys(frame).join() === 'opacity')));
    full.dispose(); reduced.dispose();
  }
});

test('motion uses the specified durations, stagger, curved travel and pane outline class', async () => {
  const window = animationWindow(), h = harness(window);
  for (const s of motionSequence().slice(0, -1)) { h.publish(s); await window.finish(); }
  const calls = window.calls;
  for (const duration of [160, 200, 240, 260, 300, 320, 360, 380, 420, 440, 480, 500, 520, 560, 640, 700, 3520]) assert.ok(calls.some((a) => a.options.duration === duration), `${duration} ms`);
  assert.ok(calls.some((a) => a.options.duration === 240 && a.options.delay === 416));
  assert.ok(calls.some((a) => a.options.duration === 560 && a.options.delay === 740));
  assert.ok(calls.some((a) => a.options.duration === 520 && a.options.delay === 120));
  assert.ok(calls.some((a) => a.node.getAttribute('class') === 'travel agent'));
  assert.ok(calls.some((a) => a.node.getAttribute('class') === 'travel agent' && a.keyframes.length === 33));
  assert.ok(calls.some((a) => a.options.duration === 640 && a.keyframes[0].fillOpacity === 0));
  h.dispose();
});

test('a burst of twenty changes settles without transient nodes or delayed work', async () => {
  const window = animationWindow(), h = harness(window);
  h.publish(snapshot());
  const s = snapshot({ pages: Array.from({ length: 20 }, (_, i) => servedPage(`https://site${i}.com/`)) });
  h.publish(s);
  assert.equal(window.calls.length, 0);
  assert.equal(transientNodes(h.root).length, 0);
  await window.finish(); window.tick(2000); await settle();
  assert.equal(transientNodes(h.root).length, 0);
  assert.equal(window.frameCount, 0);
  assert.equal(h.root.querySelectorAll('.page').length, 20);
  h.dispose();
});

test('dispose cancels running animations and typing and removes every transient node', async () => {
  const window = animationWindow(), h = harness(window);
  const sequence = motionSequence();
  h.publish(sequence[0]); h.publish(sequence[1]); h.publish(sequence[2]);
  assert.ok(transientNodes(h.root).length);
  assert.ok(window.calls.length);
  const svg = h.root.querySelector('.search-picture');
  h.dispose(); await settle();
  assert.ok(window.calls.every((a) => a.canceled));
  assert.equal(window.frameCount, 0);
  assert.equal(svg.children.length, 0);
  assert.equal(window.media.listenerCount, 0);
  assert.equal(window.document.listenerCount, 0);
});

test('hidden documents apply changes without animation and hiding cancels current motion', async () => {
  const window = animationWindow({ hidden: true }), h = harness(window);
  const sequence = motionSequence();
  for (const s of sequence.slice(0, 7)) h.publish(s);
  assert.equal(window.calls.length, 0);
  assert.equal(window.frameCount, 0);
  assert.equal(transientNodes(h.root).length, 0);
  window.document.hidden = false;
  h.publish(sequence[7]);
  assert.ok(window.calls.length);
  window.document.hidden = true;
  window.document.dispatchEvent(new Event('visibilitychange'));
  await settle();
  assert.ok(window.calls.every((a) => a.canceled));
  assert.equal(transientNodes(h.root).length, 0);
  h.dispose();
});

test('reduced motion changes finish typing, cancel motion and turn off transitions', async () => {
  const window = animationWindow(), h = harness(window), sequence = motionSequence();
  h.publish(sequence[0]); h.publish(sequence[1]);
  assert.ok(window.frameCount);
  window.media.matches = true; window.media.dispatchEvent(new Event('change'));
  await settle();
  assert.equal(h.root.querySelector('.query-text').textContent, sequence[1].queries[0].search);
  assert.equal(window.frameCount, 0);
  assert.equal(transientNodes(h.root).length, 0);
  assert.ok(h.root.classList.contains('no-motion'));
  const count = window.calls.length;
  h.publish(sequence[2]);
  assert.equal(window.calls.length, count);
  window.media.matches = false; window.media.dispatchEvent(new Event('change'));
  assert.ok(!h.root.classList.contains('no-motion'));
  h.publish(sequence[3]);
  assert.ok(window.calls.length > count);
  h.dispose();
});

test('typing is bounded to nine hundred milliseconds and leaves no frame running', () => {
  const window = animationWindow(), motion = createMotion(window);
  const node = window.document.createElement('text'), text = 'long words '.repeat(50);
  motion.typeInto(node, text);
  window.tick(0); window.tick(450);
  assert.ok(node.textContent.length > 0 && node.textContent.length < text.length);
  window.tick(900);
  assert.equal(node.textContent, text);
  assert.equal(window.frameCount, 0);
  motion.dispose();
});

test('search sources never start an interval', () => {
  for (const file of readdirSync(new URL('.', import.meta.url)).filter((name) => name.endsWith('.mjs') && !name.endsWith('.test.mjs'))) {
    assert.doesNotMatch(readFileSync(new URL(file, import.meta.url), 'utf8'), /\bsetInterval\s*\(/, file);
  }
});

test('a pending repeat fades the previous results and waits for its answer', async () => {
  const window = animationWindow(), h = harness(window);
  const q = query(1), s = snapshot({ queries: [q], results: [{ key: q.key, query_id: 1, listed: [{ rank: 1, host: 'a.com', url: 'https://a.com/' }] }] });
  h.publish(s);
  const pending = query(2, { outcome: { status: 'pending' } });
  h.publish({ ...s, queries: [q, pending] });
  assert.equal(h.root.querySelectorAll('.result-group').length, 0);
  assert.ok(window.calls.some((a) => a.options.duration === 380 && a.node.getAttribute('class') === 'result'));
  assert.equal(h.root.querySelector('.engine').getAttribute('class'), 'engine asking');
  await window.finish();
  h.publish({ ...s, queries: [q, { ...pending, outcome: { status: 'served' } }] });
  assert.equal(h.root.querySelectorAll('.result-group').length, 1);
  assert.ok(window.calls.some((a) => a.options.duration === 240));
  await window.finish();
  assert.equal(transientNodes(h.root).length, 0);
  h.dispose();
});

test('ticker nodes and their current animation survive unchanged snapshots', async () => {
  const window = animationWindow(), h = harness(window);
  const sequence = motionSequence();
  h.publish(sequence[0]); h.publish(sequence[1]);
  const row = h.root.querySelector('.search-row');
  const animation = window.calls.find((a) => a.node === row);
  h.publish(sequence[1]);
  assert.equal(h.root.querySelector('.search-row'), row);
  assert.ok(animation && !animation.canceled);
  await window.finish(); h.dispose();
});

test('opened pages remain on the map across unchanged snapshots', () => {
  const h = harness(), lists = Array.from({ length: 21 }, (_, i) => resultList(i + 1));
  const s = snapshot({ results: lists, pages: lists.map((r) => servedPage(r.listed[0].url)), queries: [query(21, { key: lists.at(-1).key })] });
  h.publish(s);
  const before = locations(h.root), list = resultList(22);
  const next = { ...s, results: [...lists, list], queries: [...s.queries, query(22, { key: list.key })] };
  h.publish(next);
  const after = locations(h.root);
  assert.equal(after.size, 22);
  for (const host of before.keys()) assert.ok(after.has(host), host);
  assert.equal(new Set([...after.values()].map(String)).size, 22);
  h.publish(next);
  assert.deepEqual(locations(h.root), after);
  h.dispose();
});

test('site color follows the latest activity while page dots keep their positions', () => {
  const h = harness();
  const a = servedPage('https://a.com/z', { at_ms: 1, first_serve_ms: 0 });
  const b = servedPage('https://a.com/a', { at_ms: 2, first_serve_ms: 0, made: 'written_live' });
  h.publish(snapshot({ pages: [a, b] }));
  const positions = h.root.querySelectorAll('.page').map((dot) => [dot.getAttribute('cx'), dot.getAttribute('cy')]);
  assert.equal(h.root.querySelector('.site').getAttribute('class'), 'site made');
  h.publish(snapshot({ pages: [b, { ...a, at_ms: 3, fetches: 2 }] }));
  assert.equal(h.root.querySelector('.site').getAttribute('class'), 'site again');
  assert.deepEqual(h.root.querySelectorAll('.page').map((dot) => [dot.getAttribute('cx'), dot.getAttribute('cy')]), positions);
  h.dispose();
});

test('restart clears current motion immediately and starts no new animation', async () => {
  const window = animationWindow(), h = harness(window), sequence = motionSequence();
  for (const s of sequence.slice(0, 3)) h.publish(s);
  assert.ok(window.calls.length);
  const count = window.calls.length;
  h.publish(sequence.at(-1));
  assert.equal(window.calls.length, count);
  assert.ok(window.calls.every((a) => a.canceled));
  assert.equal(transientNodes(h.root).length, 0);
  assert.equal(h.root.querySelectorAll('.site').length, 0);
  assert.equal(h.root.querySelectorAll('.search-row').length, 0);
  assert.equal(window.frameCount, 0);
  await settle(); h.dispose();
});

test('snapshot sites publish packet endpoint names only when the addresses change', () => {
  const h = harness();
  const updates = [];
  const off = h.services.endpointNames.subscribe((names) => updates.push(names));
  const s = { ...fixture(), sites: [{ address: '192.0.2.1', host: 'www.example.com' }, { address: '192.0.2.2', host: 'api.anthropic.com' }] };
  h.publish(s);
  assert.deepEqual([...h.services.endpointNames.get()], [['192.0.2.1', 'www.example.com'], ['192.0.2.2', 'api.anthropic.com']]);
  h.publish({ ...s, revision: 2 });
  assert.equal(updates.length, 2);
  h.publish({ ...s, sites: [] });
  assert.equal(h.services.endpointNames.get().size, 0);
  off(); h.dispose();
});

test('same-site links keep page arrival motion without a lasting arrow', async () => {
  for (const reduced of [false, true]) {
    const window = animationWindow({ reduced }), h = harness(window);
    const first = servedPage('https://a.com/one');
    h.publish(snapshot({ pages: [first] }));
    const same = servedPage('https://a.com/two', { at_ms: 6000, reason: { via: 'link', from: first.url } });
    h.publish(snapshot({ pages: [first, same] }));
    assert.equal(h.root.querySelectorAll('.link').length, 0);
    assert.equal(h.root.querySelectorAll('.page').length, 2);
    assert.equal(window.calls.some((a) => a.node.classList.contains('travel') && a.options.duration === 520), !reduced);
    const other = servedPage('https://b.com/three', { at_ms: 7000, reason: { via: 'link', from: same.url } });
    h.publish(snapshot({ pages: [first, same, other] }));
    assert.equal(h.root.querySelectorAll('.link').length, 1);
    assert.equal(h.root.querySelector('.link-group').getAttribute('data-url'), other.url);
    await window.finish();
    assert.equal(transientNodes(h.root).length, 0);
    h.dispose();
  }
});

test('fact labels fit measured text at normal spacing and keep their full title', () => {
  const widthOf = (text) => [...text].reduce((sum, c) => sum + (c === 'W' ? 12 : 6), 0);
  const window = animationWindow({ reduced: true });
  const create = window.document.createElement;
  window.document.createElement = (tag) => {
    const node = create(tag);
    if (tag === 'text' || tag === 'tspan') node.getComputedTextLength = () => widthOf(node.textContent);
    return node;
  };
  const h = harness(window);
  for (const text of ['W'.repeat(70), 'The fix is ready.', 'i'.repeat(60)]) {
    h.publish(snapshot({ planted: [{ kind: 'fact', text, at_ms: 2 }] }));
    const mark = h.root.querySelector('.planted-mark'), label = mark.querySelector('text');
    assert.ok(label.getComputedTextLength() <= 448);
    assert.equal(label.getAttribute('textLength'), null);
    assert.equal(label.getAttribute('lengthAdjust'), null);
    assert.equal(mark.querySelector('title').textContent, text);
    if (widthOf(text) > 448) assert.match(label.textContent, /…$/);
    else assert.equal(label.textContent, text);
  }
  h.dispose();
});

test('fact labels refit when their tab becomes visible and stop observing on disposal', () => {
  const window = animationWindow({ reduced: true });
  let shown = false, resize, disconnected = false;
  window.ResizeObserver = class {
    constructor(callback) { resize = callback; }
    observe() {}
    disconnect() { disconnected = true; }
  };
  const create = window.document.createElement;
  window.document.createElement = (tag) => {
    const node = create(tag);
    if (tag === 'text' || tag === 'tspan') node.getComputedTextLength = () => shown ? node.textContent.length * 9 : 0;
    return node;
  };
  const h = harness(window), text = 'A fact with enough text to need cutting when the tab becomes visible.';
  h.publish(snapshot({ planted: [{ kind: 'fact', text, at_ms: 1 }] }));
  const label = h.root.querySelector('.planted-mark').querySelector('text');
  assert.equal(label.textContent, text);
  shown = true;
  resize();
  assert.ok(label.getComputedTextLength() <= 448);
  assert.match(label.textContent, /…$/);
  assert.equal(h.root.querySelector('.planted-mark').querySelector('title').textContent, text);
  h.dispose();
  assert.equal(disconnected, true);
});

test('host marks share the favicon hash, colors and letters', () => {
  const vectors = [
    ['halvardsystems.com', 3977212790, '#3c8c2c', 'H'],
    ['community.halvardsystems.com', 2834142159, '#8c6a2c', 'C'],
    ['securityweek.com', 746036644, '#8c322c', 'S'],
    ['nvd.nist.gov', 3869253279, '#6a2c8c', 'N'],
    ['theregister.com', 815285682, '#2c8c6f', 'T'],
    ['bleepingcomputer.com', 3169656055, '#8c842c', 'B'],
  ];
  for (const [key, hash, color, letter] of vectors) {
    assert.deepEqual(hostMark(key), { key, hash, color, letter });
    assert.deepEqual(hostMark(`WWW.${key.toUpperCase()}`), hostMark(key));
  }
  assert.equal(hostMark('é.com').hash, 229022918);
  for (const [hosts, letter, color] of [
    [['google.com', 'www.google.com'], 'G', '#4285f4'],
    [['bing.com'], 'B', '#00809d'],
    [['duckduckgo.com', 'html.duckduckgo.com', 'lite.duckduckgo.com'], 'D', '#de5833'],
    [['en.wikipedia.org', 'fr.wikipedia.org', 'www.wikipedia.org'], 'W', '#333333'],
    [['reddit.com'], 'R', '#ff4500'], [['youtube.com'], '▶', '#ff0000'], [['github.com'], 'G', '#181717'],
  ]) for (const host of hosts) assert.deepEqual([hostMark(host).letter, hostMark(host).color], [letter, color]);
});

test('story hosts have readable display names', () => {
  for (const [host, name] of [
    ['www.halvardsystems.com', 'Halvard Systems'], ['community.halvardsystems.com', 'Halvard Community'],
    ['docs.halvardsystems.com', 'Halvard Docs'], ['www.cisa.gov', 'CISA'],
    ['nvd.nist.gov', 'NVD'], ['en.wikipedia.org', 'Wikipedia'],
  ]) {
    const h = harness();
    h.publish(snapshot({ seed: { sites: [{ host, site: name }] } }));
    assert.equal(h.root.querySelector('.site-group').children[1].textContent, name);
    h.dispose();
  }
});

test('listed and opened sites carry marks while their rings keep the activity state', () => {
  const h = harness(), s = fixture();
  h.publish(s);
  const sites = h.root.querySelectorAll('.site-group');
  const listed = sites.find((g) => g.getAttribute('data-host') === 'www.theregister.co.uk');
  const opened = sites.find((g) => g.getAttribute('data-host') === 'www.halvardsystems.com');
  assert.equal(listed.getAttribute('class'), 'site-group listed');
  assert.equal(listed.querySelector('.site').getAttribute('r'), '8');
  assert.ok(Number(listed.querySelector('.site').getAttribute('r')) < Number(opened.querySelector('.site').getAttribute('r')));
  assert.equal(opened.getAttribute('class'), 'site-group opened');
  assert.equal(opened.querySelector('.site').getAttribute('r'), '9');
  assert.match(opened.querySelector('.site').getAttribute('class'), /stored scenario/);
  for (const g of sites) {
    const mark = hostMark(g.getAttribute('data-host'));
    assert.equal(g.style['--app-host-color'], mark.color);
    assert.equal(g.querySelector('.mark').textContent, mark.letter);
    assert.equal(g.querySelector('.mark').getAttribute('aria-hidden'), 'true');
    assert.equal(g.querySelector('title').textContent, g.getAttribute('data-host'));
  }
  assert.deepEqual(h.root.querySelectorAll('.engine-group').map((g) => g.querySelector('.mark').textContent), ['G', 'B', 'D']);
  assert.deepEqual(h.root.querySelectorAll('.engine-group').map((g) => g.getAttribute('class')), ['engine-group answered', 'engine-group idle', 'engine-group answered']);
  h.dispose();
});

test('a fact without a refused name uses the full row and cuts at seventy characters', () => {
  const h = harness(), text = 'i'.repeat(90);
  h.publish(snapshot({ planted: [{ kind: 'fact', text, at_ms: 1 }] }));
  const mark = h.root.querySelector('.planted-mark');
  assert.equal(mark.querySelector('text').textContent, 'i'.repeat(69) + '…');
  assert.equal(mark.querySelectorAll('tspan').length, 1);
  assert.equal(mark.querySelector('tspan').getAttribute('y'), '544');
  assert.equal(mark.querySelector('title').textContent, text);
  h.dispose();
});

test('wide labels fit every slot without touching neighboring labels', () => {
  const window = animationWindow({ reduced: true });
  const create = window.document.createElement;
  window.document.createElement = (tag) => {
    const node = create(tag);
    if (tag === 'text' || tag === 'tspan') node.getComputedTextLength = () => node.textContent.length * 11;
    return node;
  };
  const h = harness(window);
  h.publish(snapshot({ seed: { sites: [] }, pages: Array.from({ length: 21 }, (_, i) => servedPage(`https://${'w'.repeat(18)}${i}.com/`, { site: `${'W'.repeat(8)} ${'W'.repeat(15)}` })) }));
  const labels = h.root.querySelectorAll('.site-group').map((g) => g.querySelector('.label'));
  assert.equal(labels.length, 21);
  const boxes = labels.flatMap((label) => {
    const spans = label.querySelectorAll('tspan');
    assert.equal(spans.length, 2);
    assert.match(spans.at(-1).textContent, /…$/);
    return spans.map((span, index) => {
      const width = span.getComputedTextLength(), x = Number(span.getAttribute('x')), y = Number(label.getAttribute('y')) + index * 13;
      assert.ok(width <= 116);
      assert.ok(x - width / 2 >= 0 && x + width / 2 <= 520);
      assert.ok(y - 13 >= 0 && y <= 560);
      return { left: x - width / 2, right: x + width / 2, top: y - 12.5, bottom: y };
    });
  });
  for (const [i, a] of boxes.entries()) for (const b of boxes.slice(i + 1)) {
    assert.ok(a.right < b.left || b.right < a.left || a.bottom < b.top || b.bottom < a.top);
  }
  h.dispose();
});

test('site aliases merge while role subdomains keep their own nodes', () => {
  for (const [a, b, merge] of [
    ['en.wikipedia.org', 'www.wikipedia.org', true],
    ['de.wikipedia.org', 'fr.wikipedia.org', true],
    ['en.example.co.uk', 'www.example.co.uk', true],
    ['nvd.nist.gov', 'www.nvd.nist.gov', true],
    ['docs.python.org', 'python.org', false],
    ['community.halvardsystems.com', 'docs.halvardsystems.com', false],
    ['docs.halvardsystems.com', 'www.halvardsystems.com', false],
    ['nvd.nist.gov', 'nist.gov', false],
    ['api.example.com', 'example.com', false],
    ['en.docs.python.org', 'docs.python.org', false],
  ]) assert.equal(siteKey(a) === siteKey(b), merge, `${a} / ${b}`);
});

test('world names label merged nodes and every alias contributes its pages', () => {
  const h = harness();
  const s = snapshot({ seed: { sites: [] }, queries: [query(1)], results: [{ key: query(1).key, query_id: 1, listed: [
    { rank: 1, host: 'en.wikipedia.org', site: 'Wikipedia', url: 'https://en.wikipedia.org/wiki/A' },
    { rank: 2, host: 'www.wikipedia.org', site: 'Wikipedia', url: 'https://www.wikipedia.org/' },
    { rank: 3, host: 'docs.python.org', site: 'Python Documentation', url: 'https://docs.python.org/' },
  ] }], pages: [
    servedPage('https://en.wikipedia.org/wiki/A', { site: 'Wikipedia' }),
    servedPage('https://www.wikipedia.org/', { site: 'Wikipedia' }),
  ] });
  h.publish(s);
  const groups = h.root.querySelectorAll('.site-group');
  assert.equal(groups.length, 2);
  const wiki = groups.find((g) => g.children[1].textContent === 'Wikipedia');
  assert.equal(wiki.querySelectorAll('.page').length, 2);
  assert.equal(wiki.children[0].getAttribute('r'), '10.25');
  assert.equal(wiki.querySelector('.mark').textContent, 'W');
  assert.equal(wiki.querySelector('title').textContent, 'en.wikipedia.org');
  assert.equal(groups.find((g) => g !== wiki).children[1].textContent, 'Python Documentation');
  assert.equal(h.root.querySelectorAll('.result').length, 3);
  assert.deepEqual(h.root.querySelectorAll('.result').slice(0, 2).map((line) => [line.getAttribute('x2'), line.getAttribute('y2')]),
    Array(2).fill([wiki.children[0].getAttribute('cx'), String(Number(wiki.children[0].getAttribute('cy')) - 16)]));
  h.dispose();
});

for (const reduced of [false, true]) test(`made pages hold the site's dashes for nine hundred milliseconds with reduced motion ${reduced}`, async () => {
  const window = animationWindow({ reduced }), h = harness(window);
  const before = snapshot();
  h.publish(before);
  const p = servedPage('https://docs.python.org/new', { site: 'Python Documentation', made: 'stubbed' });
  h.publish({ ...before, pages: [p] });
  const site = h.root.querySelector('.site');
  assert.match(site.getAttribute('class'), /\bmaking\b/);
  window.advance(899);
  assert.match(site.getAttribute('class'), /\bmaking\b/);
  h.publish({ ...before, revision: 2, pages: [p] });
  assert.match(site.getAttribute('class'), /\bmaking\b/);
  window.advance(1);
  assert.doesNotMatch(site.getAttribute('class'), /\bmaking\b/);
  const pending = servedPage('https://docs.python.org/next', { site: p.site, making: true, fetches: 0, status: null });
  h.publish({ ...before, pages: [p, pending] });
  window.advance(2000);
  assert.match(site.getAttribute('class'), /\bmaking\b/);
  h.publish({ ...before, pages: [p, { ...pending, making: false, fetches: 1, status: 200, made: 'written_live' }] });
  window.advance(899);
  assert.match(site.getAttribute('class'), /\bmaking\b/);
  window.advance(1);
  assert.doesNotMatch(site.getAttribute('class'), /\bmaking\b/);
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(css, /@keyframes site-making \{ to \{ stroke-dashoffset: -12; \} \}/);
  assert.match(css, /prefers-reduced-motion: reduce[^}]+\.search-picture \.site\.making \{ animation: none;/);
  h.dispose();
});

test('long profile names have concise map labels', () => {
  for (const [name, label] of [
    ['Halvard Systems Community', 'Halvard Community'],
    ['Halvard Systems Documentation', 'Halvard Docs'],
    ['Cybersecurity and Infrastructure Security Agency', 'CISA'],
    ['National Vulnerability Database', 'NVD'],
  ]) assert.equal(short(name), label);
});

test('names survive older result lists leaving the snapshot', () => {
  const h = harness();
  const first = snapshot({ results: [{ key: 'old', query_id: 1, listed: [{ host: 'docs.python.org', site: 'Python Documentation', rank: 1, url: 'https://docs.python.org/' }] }] });
  h.publish(first);
  h.publish({ ...first, results: [] });
  assert.equal(h.root.querySelector('.site-group'), null);
  h.publish({ ...first, results: [], pages: [servedPage('https://docs.python.org/', { site: null })] });
  assert.equal(h.root.querySelector('.site-group').querySelector('.label').textContent, 'Python Documentation');
  h.dispose();
});

test('the World menu names the model choice and preserves its command', async () => {
  const h = harness();
  for (const kind of ['openrouter', 'anthropic', 'stub']) {
    h.publish({ ...fixture(), generator: { ...fixture().generator, kind } });
    const button = h.services.worldMenu.querySelector('.seg').children[1];
    assert.deepEqual(h.services.worldMenu.querySelector('.seg').children.map((b) => b.textContent), ['Prepared first', kind === 'stub' ? 'Improvised' : 'Always live', 'Off']);
    button.dispatchEvent(new Event('click'));
    await settle();
    assert.equal(h.posts.at(-1).body.command.new_pages, 'stub');
  }
  h.dispose();
});

test('completed background pages leave no making marks until opened', () => {
  for (const made of ['written_live', 'stubbed']) {
    const h = harness();
    const p = servedPage('https://a.com/page', { making: true, status: null, fetches: 0 });
    const pending = snapshot({ queries: [query(1)], pages: [p] });
    h.publish(pending);
    assert.equal(h.root.querySelector('.page').getAttribute('class'), 'page making');
    assert.match(h.root.textContent, /writing/);
    const completed = { ...pending, pages: [] };
    assert.deepEqual(diff(pending, completed), []);
    h.publish(completed);
    assert.equal(h.root.querySelectorAll('.page').length, 0);
    assert.ok(h.root.querySelectorAll('.site').every((n) => !/\bmaking\b/.test(n.getAttribute('class'))));
    assert.doesNotMatch(h.root.textContent, /writing/);
    const opened = { ...completed, pages: [{ ...p, making: false, status: 200, fetches: 1, cache: 'prefetched', made }] };
    assert.equal(diff(completed, opened)[0].type, 'page_opened');
    h.publish(opened);
    assert.equal(h.root.querySelector('.page').getAttribute('class'), 'page made');
    assert.doesNotMatch(h.root.textContent, /writing/);
    h.dispose();
  }
});

test('a request waiting for a background page stays making until served', () => {
  const h = harness();
  const p = servedPage('https://a.com/page', { making: true, status: null, fetches: 0 });
  const pending = snapshot({ queries: [query(1)], pages: [p] });
  h.publish(pending);
  const completed = { ...pending, revision: pending.revision + 1 };
  h.publish(completed);
  assert.match(h.root.textContent, /writing/);
  assert.equal(h.root.querySelector('.page').getAttribute('class'), 'page making');
  h.publish({ ...completed, pages: [{ ...p, making: false, status: 200, fetches: 1, cache: 'prefetched', made: 'written_live' }] });
  assert.equal(h.root.querySelector('.page').getAttribute('class'), 'page made');
  assert.doesNotMatch(h.root.textContent, /writing/);
  h.dispose();
});

test('off-map queries keep the last map search and target their site through every answer state', async () => {
  assert.equal(engine('you_tube'), 'YouTube');
  assert.equal(ENGINE_HOSTS.you_tube, 'youtube.com');
  for (const name of ['you_tube', 'video.example.com']) {
    for (const cache of ['fixed', 'generated', 'cached', 'planted', 'missing']) {
      const window = animationWindow(), h = harness(window);
      const s = fixture();
      h.publish(s);
      const lines = h.root.querySelectorAll('.result-group');
      const pending = query(16, { engine: name, search: 'halvard gateway failover', key: 'halvard gateway failover', outcome: { status: 'pending' }, cache: 'unknown' });
      const started = { ...s, queries: [...s.queries, pending] };
      assert.doesNotThrow(() => h.publish(started));
      const host = ENGINE_HOSTS[name] || name;
      const site = h.root.querySelectorAll('.site-group').find((g) => siteKey(g.getAttribute('data-host')) === host);
      assert.ok(site);
      const travel = window.calls.find((a) => a.node.getAttribute('class') === 'travel ink');
      assert.equal(travel.keyframes.at(-1).transform, `translate(${site.children[0].getAttribute('cx')}px, ${site.children[0].getAttribute('cy')}px)`);
      const answered = { ...started, queries: [...s.queries, { ...pending, outcome: { status: 'served' }, cache, carries: 1 }] };
      assert.doesNotThrow(() => h.publish(answered));
      assert.deepEqual(h.root.querySelectorAll('.result-group'), lines);
      assert.ok(h.root.querySelector('.thread'));
      assert.equal(site.getAttribute('class'), 'site-group opened');
      assert.equal(site.children[0].getAttribute('class'), `site ${queryTag(answered, answered.queries.at(-1))}`);
      if (cache === 'generated') assert.ok(window.calls.some((a) => a.node === site.children[0] && a.options.duration === 520));
      await window.finish();
      const before = window.calls.length;
      h.publish({ ...answered, refused: [{ name: 'wiki.corp', at_ms: 90000 }] });
      assert.ok(window.calls.slice(before).some((a) => a.node.getAttribute('class') === 'refused-mark'));
      assert.equal(rows(answered)[0].who, engine(name));
      assert.deepEqual(h.root.querySelectorAll('.result-group'), lines);
      h.dispose();
    }
  }
});

test('a mixed completed snapshot keeps Google result lines with YouTube queries between Google queries', () => {
  const h = harness(), s = fixture();
  const queries = [
    [14, 'you_tube', 'halvard gateway high availability failover', 'generated', 524631, 529584],
    [15, 'you_tube', 'halvard gateway high availability failover', 'cached', 541292, 541294],
    [16, 'you_tube', 'halvard gateway firmware upgrade', 'cached', 649704, 649706],
    [17, 'google', 'halvard gateway fixed version', 'generated', 759748, 763870],
    [18, 'bing', 'halvard pulls gateway firmware', 'generated', 779207, 783741],
    [19, 'google', 'halvard gateway hg-400 cve-2026-41877 advisory', 'generated', 820880, 825340],
    [20, 'google', 'halvard hg-400 firmware upgrade problems 7.2.5 7.2.4 failed', 'generated', 864189, 868988],
  ].map(([id, engine, key, cache, at_ms, answer_at_ms]) => query(id, { engine, key, search: key, cache, at_ms, answer_at_ms, via: id >= 19 ? 'web_search' : null }));
  const final = { ...s, revision: 199, at_ms: 868988, queries: [...s.queries, ...queries], results: [...s.results, { ...s.results.at(-1), key: queries.at(-1).key, query_id: 20 }] };
  h.publish(final);
  assert.equal(h.root.querySelectorAll('.result-group').length, 3);
  assert.ok(h.root.querySelectorAll('.site-group').some((g) => siteKey(g.getAttribute('data-host')) === 'youtube.com'));
  assert.equal(h.root.querySelector('.query-text').textContent, queries.at(-1).search.slice(0, 53) + '…');
  h.dispose();
});

test('fan-out waits for typing and a pulse, then reveals new sites and ranked lines together', async () => {
  const window = animationWindow(), h = harness(window), sequence = motionSequence();
  h.publish(sequence[0]); h.publish(sequence[1]);
  window.tick(0); window.tick(300);
  const typed = h.root.querySelector('.query-text').textContent;
  h.publish(sequence[2]);
  assert.equal(h.root.querySelector('.query-text').textContent, typed);
  const pulse = window.calls.find((a) => a.node.getAttribute('class') === 'engine stored' && a.options.duration === 380);
  assert.equal(pulse.options.delay, 300);
  const lines = window.calls.filter((a) => a.node.getAttribute('class') === 'result');
  assert.deepEqual(lines.map((a) => [a.options.duration, a.options.delay]), [[240, 680], [240, 716]]);
  const sites = window.calls.filter((a) => a.node.getAttribute('class')?.startsWith('site-group'));
  assert.deepEqual(sites.map((a) => [a.options.duration, a.options.delay, a.keyframes[0].opacity, a.options.fill]), [[320, 680, 0, 'backwards'], [320, 716, 0, 'backwards']]);
  await window.finish();
  assert.equal(h.root.querySelector('.query-text').textContent, sequence[2].queries[0].search);
  h.dispose();
});

test('sites arriving during a pending search stay hidden until the answer reveals them', () => {
  const window = animationWindow(), h = harness(window), sequence = motionSequence();
  h.publish(sequence[0]);
  h.publish({ ...sequence[1], results: sequence[2].results });
  assert.ok(h.root.querySelectorAll('.site-group').every((g) => g.style.opacity === '0'));
  assert.ok(!window.calls.some((a) => a.node.getAttribute('class')?.startsWith('site-group')));
  h.publish(sequence[2]);
  assert.equal(window.calls.filter((a) => a.node.getAttribute('class')?.startsWith('site-group')).length, 2);
  h.dispose();
});

test('pending searches show writing with marching dashes and a breathing ring that respects reduced motion', () => {
  const h = harness(), pending = snapshot({ queries: [query(1, { outcome: { status: 'pending' } })] });
  h.publish(pending);
  assert.equal(rows(pending)[0].badge, 'writing');
  assert.equal(h.root.querySelector('em.asking').textContent, 'writing');
  assert.equal(h.root.querySelector('.breathing').parentNode.getAttribute('class'), 'engine-group asking');
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(css, /\.engine\.asking\s*\{ animation: site-making 600ms linear infinite/);
  assert.match(css, /\.engine-group\.asking \.breathing\s*\{ animation: engine-breathing 1500ms/);
  assert.match(css, /@keyframes engine-breathing \{ from \{ r: 12; opacity: \.6; \} to \{ r: 15; opacity: 0;/);
  assert.match(css, /\.search-row em\.making, \.search-row em\.asking \{ color: var\(--app-mute\)/);
  assert.match(css, /\.search-world\.no-motion \.site\.making, \.search-world\.no-motion \.engine\.asking, \.search-world\.no-motion \.breathing \{ animation: none/);
  h.dispose();
});

test('fact threads draw, hold and fade before removal while result lines wait an extra beat', async () => {
  const window = animationWindow(), h = harness(window), sequence = motionSequence();
  h.publish(sequence[0]);
  h.publish({ ...sequence[2], queries: [{ ...sequence[2].queries[0], carries: 1 }] });
  const draw = window.calls.find((a) => a.node.getAttribute('class') === 'thread' && a.options.duration === 420);
  const fade = window.calls.find((a) => a.node === draw.node && a.options.duration === 3520);
  assert.equal(fade.keyframes[1].offset * fade.options.duration, 2920);
  assert.equal(fade.options.duration - 2920, 600);
  assert.equal(fade.keyframes[1].opacity, 1);
  assert.equal(fade.keyframes[2].opacity, 0);
  assert.deepEqual(window.calls.filter((a) => a.node.getAttribute('class') === 'result').map((a) => a.options.delay), [1280, 1316]);
  assert.match(readFileSync(new URL('./style.css', import.meta.url), 'utf8'), /\.thread \{[^}]*stroke-width: 2\.5/);
  await window.finish();
  assert.equal(h.root.querySelector('.thread'), null);
  h.dispose();
});

test('only applied plant commands close the World menu after a quarter second and disposal cancels the close', async () => {
  for (const kind of ['fact', 'page']) {
    for (const status of ['applied', 'pending', 'rejected']) {
      const window = animationWindow(), h = harness(window);
      h.publish(fixture());
      let closed = 0;
      h.services.closeWorldMenu = () => closed++;
      h.services.transport.post = async () => ({ status });
      const menu = h.services.worldMenu;
      menu.querySelector('#plant-fact').value = 'A fact';
      menu.querySelector('#plant-url').value = 'https://example.com/';
      menu.querySelector('textarea').value = 'A page';
      menu.querySelectorAll('button.act')[kind === 'fact' ? 0 : 1].click();
      await settle();
      window.advance(249); assert.equal(closed, 0);
      window.advance(1); assert.equal(closed, status === 'applied' ? 1 : 0);
      h.dispose();
    }
  }
  const window = animationWindow(), h = harness(window);
  h.publish(fixture());
  let closed = 0;
  h.services.closeWorldMenu = () => closed++;
  h.services.worldMenu.querySelectorAll('button.act')[0].click();
  await settle(); h.dispose(); window.advance(250);
  assert.equal(closed, 0);
});

test('the shell close service hides the menu, restores focus and is removed on disposal', async () => {
  const document = createDocument(), root = document.createElement('div');
  const source = document.createElement('source');
  source.close = () => {};
  const services = createServices({ watch: () => source }, {}, async () => ({ mount: () => () => {} }));
  const stop = appShell(root, services, { title: 'Search', hosts: [], panels: [{ kind: 'custom', area: 'workspace', title: 'Web', module: '/panels/search.mjs' }] });
  await settle();
  const menu = root.querySelector('#world-menu'), toggle = root.querySelector('.app-menu-button');
  toggle.click();
  const input = document.createElement('input'); services.worldMenu.append(input); input.focus();
  services.closeWorldMenu();
  assert.equal(menu.hidden, true);
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  assert.equal(document.activeElement, toggle);
  stop();
  assert.equal(services.closeWorldMenu, undefined);
  services.dispose();
});

test('unknown engines tolerate failed answers and reduced-motion repeats without losing result lines', async () => {
  for (const reduced of [false, true]) {
    for (const status of ['failed', 'undelivered', 'served']) {
      const window = animationWindow({ reduced }), h = harness(window), s = fixture();
      h.publish(s);
      const lines = h.root.querySelectorAll('.result-group');
      const q = query(5, { engine: 'you_tube', outcome: { status: 'pending' } });
      h.publish({ ...s, queries: [...s.queries, q] });
      assert.doesNotThrow(() => h.publish({ ...s, queries: [...s.queries, { ...q, outcome: { status }, cache: 'cached' }] }));
      assert.deepEqual(h.root.querySelectorAll('.result-group'), lines);
      await window.finish();
      h.dispose();
    }
  }
});

test('reduced motion reveals an early answer immediately without typing or fan-out delays', () => {
  const window = animationWindow({ reduced: true }), h = harness(window), sequence = motionSequence();
  h.publish(sequence[0]); h.publish(sequence[1]); h.publish(sequence[2]);
  assert.equal(h.root.querySelector('.query-text').textContent, sequence[2].queries[0].search);
  assert.ok(h.root.querySelectorAll('.site-group').every((g) => g.style.opacity === ''));
  assert.equal(window.calls.length, 0);
  assert.equal(window.frameCount, 0);
  h.dispose();
});

test('turning on reduced motion reveals sites held for a pending answer', () => {
  const window = animationWindow(), h = harness(window), sequence = motionSequence();
  h.publish(sequence[0]); h.publish({ ...sequence[1], results: sequence[2].results });
  assert.ok(h.root.querySelectorAll('.site-group').every((g) => g.style.opacity === '0'));
  window.media.matches = true; window.media.dispatchEvent(new Event('change'));
  assert.ok(h.root.querySelectorAll('.site-group').every((g) => g.style.opacity === ''));
  assert.equal(window.frameCount, 0);
  h.dispose();
});

test('a repeated YouTube answer pulses its site in full and reduced motion', async () => {
  for (const reduced of [false, true]) {
    const window = animationWindow({ reduced }), h = harness(window), s = fixture();
    const q = query(5, { engine: 'you_tube', cache: 'generated' });
    h.publish({ ...s, queries: [...s.queries, q] });
    const lines = h.root.querySelectorAll('.result-group');
    const repeat = { ...s, queries: [...s.queries, q, { ...q, id: 6, cache: 'cached' }] };
    h.publish(repeat);
    assert.deepEqual(h.root.querySelectorAll('.result-group'), lines);
    const site = h.root.querySelectorAll('.site-group').find((g) => siteKey(g.getAttribute('data-host')) === 'youtube.com');
    const ring = window.calls.find((a) => a.node.getAttribute('class') === 'ring again');
    assert.ok(ring);
    assert.equal(ring.node.getAttribute('cx'), site.children[0].getAttribute('cx'));
    assert.equal(ring.options.duration, reduced ? 150 : 500);
    await window.finish(); h.dispose();
  }
});

test('relative row times advance with the run and leave names and titles readable', () => {
  const h = harness();
  let now = 0;
  h.services.runTime = () => now;
  const p = servedPage('https://www.securityweek.com/a-long-path', { site: 'SecurityWeek', title: 'A security update', at_ms: 1000 });
  const s = snapshot({ pages: [p] });
  h.publish(s);
  const row = h.root.querySelector('.search-row');
  assert.equal(row.querySelector('time').textContent, 'now');
  assert.equal(row.children[1].textContent, 'SecurityWeek');
  assert.equal(row.querySelector('.row-text').textContent, 'A security update');
  assert.equal(row.querySelector('b').getAttribute('title'), p.url);
  now = 121;
  h.publish(s);
  assert.equal(h.root.querySelector('.search-row'), row);
  assert.equal(row.querySelector('time').textContent, '2 min ago');
  now = 7201;
  h.publish(s);
  assert.equal(row.querySelector('time').textContent, '2 hr ago');
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(css, /\.search-row \{[^}]*font: 13px var\(--sans\)/);
  assert.match(css, /\.made-dot \{ width: 6px; height: 6px;[^}]*background: var\(--app-made\)/);
  h.dispose();
});

test('missing pages stay hollow and say not found even on another visit', () => {
  const h = harness();
  for (const fetches of [1, 2]) {
    const p = servedPage('https://www.cnet.com/missing', { site: 'CNET', title: 'Page not found', status: 404, made: 'missing', fetches });
    h.publish(snapshot({ pages: [p] }));
    assert.equal(pageTag(p), 'missing');
    assert.equal(h.root.querySelector('.page').getAttribute('class'), 'page missing');
    assert.equal(h.root.querySelector('em.missing').textContent, 'not found');
    assert.equal(h.root.querySelector('.made-dot'), null);
  }
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(css, /\.page\.missing \{ fill: var\(--app-pane\); stroke: var\(--app-mute\); stroke-dasharray: 2 2/);
  assert.match(css, /\.search-row em\.missing,[^}]*color: var\(--app-mute\)/);
  h.dispose();
});

test('site labels wrap at the last fitting space before using an ellipsis', () => {
  const window = animationWindow({ reduced: true });
  const create = window.document.createElement;
  window.document.createElement = (tag) => {
    const node = create(tag);
    if (tag === 'tspan') node.getComputedTextLength = () => node.textContent.trimEnd().length * 7;
    return node;
  };
  const h = harness(window);
  h.publish(snapshot({ pages: [servedPage('https://a.com/', { site: 'Health and Safety Executive' })] }));
  const label = h.root.querySelector('.site-group').querySelector('.label');
  assert.deepEqual(label.querySelectorAll('tspan').map((n) => n.textContent), ['Health and ', 'Safety Executive']);
  assert.equal(label.querySelectorAll('tspan')[1].getAttribute('dy'), '13');
  assert.equal(label.textContent, 'Health and Safety Executive');
  h.publish(snapshot({ pages: [servedPage('https://a.com/', { site: 'Health and Safety Executive International Association' })] }));
  assert.deepEqual(label.querySelectorAll('tspan').map((n) => n.textContent), ['Health and ', 'Safety Executiv…']);
  assert.equal(label.querySelectorAll('tspan').length, 2);
  h.publish(snapshot({ pages: [servedPage('https://a.com/', { site: 'Mechanicalkeyboards' })] }));
  assert.deepEqual(label.querySelectorAll('tspan').map((n) => n.textContent), ['Mechanicalkeybo…']);
  h.dispose();
});

for (const reduced of [false, true]) test(`current site follows request times and results with reduced motion ${reduced}`, async () => {
  const window = animationWindow({ reduced }), h = harness(window);
  const a = servedPage('https://a.com/', { latest_serve_ms: 9000, at_ms: 2000 });
  const b = servedPage('https://b.com/', { latest_serve_ms: 8000, at_ms: 1000 });
  let s = snapshot({ pages: [a, b] });
  h.publish(s);
  const ring = h.root.querySelector('.current');
  const check = (node) => {
    assert.equal(ring.getAttribute('visibility'), 'visible');
    for (const key of ['cx', 'cy']) assert.equal(ring.getAttribute(key), node.getAttribute(key));
    assert.equal(Number(ring.getAttribute('r')), Number(node.getAttribute('r')) + 4);
  };
  check(h.root.querySelectorAll('.site-group').find((g) => g.getAttribute('data-host') === 'a.com').children[0]);
  await settle();
  const event = new Event('event');
  event.data = JSON.stringify({ source: 'http', kind: 'request', seq: 10, at: 10, fields: { kind: 'page', host: 'b.com' } });
  h.watch.dispatchEvent(event);
  s = { ...s, pages: [a, { ...b, latest_serve_ms: 1, fetches: 2 }] };
  h.publish(s);
  check(h.root.querySelectorAll('.site-group').find((g) => g.getAttribute('data-host') === 'b.com').children[0]);
  const q = query(1, { engine: 'bing', answer_at_ms: 11000 });
  s = { ...s, queries: [q] };
  h.publish(s);
  check(h.root.querySelectorAll('.engine')[1]);
  h.publish({ ...s, queries: [q, query(2, { outcome: { status: 'pending' }, at_ms: 12000 })] });
  check(h.root.querySelectorAll('.engine')[1]);
  h.publish(snapshot({ revision: 2 }));
  assert.equal(ring.getAttribute('visibility'), 'hidden');
  h.publish(snapshot({ revision: 2, pages: [{ ...b, at_ms: 12000, latest_serve_ms: 1 }], queries: [q] }));
  check(h.root.querySelector('.site-group').children[0]);
  const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8');
  assert.match(css, /\.current \{[^}]*stroke: var\(--app-ink\); stroke-width: 2;[^}]*transition: cx 300ms, cy 300ms, r 300ms/);
  assert.equal(h.root.classList.contains('no-motion'), reduced);
  h.dispose();
});

test('many searches retain opened and scenario sites plus only two recent result lists', () => {
  const h = harness();
  const seed = { sites: [{ host: 'story.com', site: 'Story' }, { host: 'community.story.com', site: 'Story Community' }] };
  const pages = ['cisa.gov', 'nvd.nist.gov', 'securityweek.com', 'theregister.com'].map((host) => servedPage(`https://${host}/`));
  let s = snapshot({ seed, pages });
  h.publish(s);
  for (let n = 1; n <= 80; n++) {
    const q = query(n, { key: `question ${n}` });
    const listed = [...pages.map((p) => ({ host: p.host, site: p.site, url: p.url })), ...Array.from({ length: 6 }, (_, i) => ({ host: `site-${n}-${i}.com`, site: `Site ${n} ${i}`, url: `https://site-${n}-${i}.com/` }))].map((r, i) => ({ ...r, rank: i + 1 }));
    s = { ...s, queries: [...s.queries, q].slice(-128), results: [...s.results, { key: q.key, query_id: n, listed }].slice(-24) };
    h.publish(s);
    const hosts = [...locations(h.root).keys()];
    assert.equal(hosts.length, n === 1 ? 12 : 18);
    for (const p of pages) assert.ok(hosts.includes(p.host));
    for (const site of seed.sites) assert.ok(hosts.includes(site.host));
    for (const host of hosts.filter((host) => host.startsWith('site-'))) assert.ok(host.startsWith(`site-${n}-`) || host.startsWith(`site-${n - 1}-`));
  }
  h.publish({ ...s, pages: [] });
  for (const p of pages) assert.ok(locations(h.root).has(p.host));
  h.dispose();
});

for (const reduced of [false, true]) test(`old listed sites fade and leave with reduced motion ${reduced}`, async () => {
  const window = animationWindow({ reduced }), h = harness(window);
  let s = snapshot();
  for (let n = 1; n <= 3; n++) {
    const q = query(n, { key: `question ${n}` });
    s = { ...s, queries: [...s.queries, q], results: [...s.results, { ...resultList(n), key: q.key }] };
    h.publish(s);
    if (n < 3) await window.finish();
  }
  const fade = window.calls.find((a) => a.options.duration === 320 && a.keyframes.at(-1).opacity === 0);
  if (reduced) {
    assert.equal(fade, undefined);
    assert.ok(![...locations(h.root).keys()].includes('site1.com'));
  } else {
    assert.ok(fade);
    assert.equal(fade.node.parentNode.getAttribute('class'), 'layer-fx');
    assert.deepEqual(fade.keyframes, [{ opacity: 1 }, { opacity: 0 }]);
    assert.ok(h.root.contains(fade.node));
    await window.finish();
    assert.ok(!h.root.contains(fade.node));
  }
  assert.deepEqual([...locations(h.root).keys()], ['site2.com', 'site3.com']);
  h.dispose();
});

test('row times update during a quiet running session and stop after disposal', () => {
  const window = animationWindow(), h = harness(window);
  let now = 1;
  h.services.runTime = () => now;
  h.services.clock.ended = false;
  h.publish(snapshot({ pages: [servedPage('https://a.com/', { at_ms: 1000 })] }));
  const row = h.root.querySelector('.search-row');
  assert.equal(row.querySelector('time').textContent, 'now');
  now = 121;
  window.advance(120000);
  assert.equal(row.querySelector('time').textContent, '2 min ago');
  assert.match(row.getAttribute('title'), /^2 min ago/);
  h.dispose();
  now = 181;
  window.advance(60000);
  assert.equal(row.querySelector('time').textContent, '2 min ago');
});
