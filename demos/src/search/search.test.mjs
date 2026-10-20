import test from 'node:test';
import assert from 'node:assert/strict';
import { createDocument } from '../../../dashboard/test-dom.mjs';
import * as dom from '../../../dashboard/dom.mjs';
import * as format from '../../../dashboard/format.mjs';
import { createSelection } from '../../../dashboard/selection.mjs';
import { counts, tree, queryKey, resultView, made, rootNote } from './model.mjs';
import { mount } from './view.mjs';

const settle = () => new Promise((resolve) => setImmediate(resolve));
const query = (id, status = 'served', extra = {}) => ({ id, seq: id * 10, answer_seq: id * 10 + 1, at_ms: 1234, sandbox: 'workstation', peer: '10.0.0.2', engine: 'google', search: 'A Question', key: 'a question', outcome: { status }, cache: 'generated', results: 10, serve_ms: 8, ...extra });
const page = (url, reason, extra = {}) => ({ url, host: new URL(url).hostname, seq: 100, at_ms: 1500, title: '<A page>', reason, made: 'stubbed', latest: 'stored', first_serve_ms: 12, serve_ms: 12, latest_serve_ms: 3, fetches: 2, ...extra });
function fixture() {
  return {
    seed: { name: 'Scenario', date: '2026-10-07', question: '<A question>', facts: ['A fact.'] },
    generator: { kind: 'stub', generate: true, generation_revision: 7, generation_at_ms: 2000 },
    queries: [query(1), query(2, 'served', { engine: 'bing', cache: 'cached' })],
    results: [{ key: 'a question', query_id: 1, cache: 'generated', listed: [{ rank: 1, title: '<Title>', host: 'made.com', url: 'https://made.com/a' }] }],
    pages: [page('https://made.com/a', { via: 'search', query: ' A  QUESTION ', rank: 1 }), page('https://made.com/b', { via: 'link', from: 'https://made.com/a' }), page('https://made.com/c', { via: 'link', from: 'https://made.com/b' }), page('https://typed.com/', { via: 'direct' }), page('https://fixed.com/', { via: 'fixed' }, { made: 'fixed' })],
    sites: [{ host: 'made.com', address: '23.1.2.3', reason: 'pool' }, { host: 'www.google.com', address: '142.250.1.1', reason: 'search_engine' }],
    refused: [{ name: 'printer.local', reason: 'reserved or private top-level domain', at_ms: 1000 }],
    omitted: { queries: 0, pages: 0 },
  };
}
function harness(t) {
  const document = createDocument(), root = document.createElement('div');
  const subscriptions = new Map(), pending = [], selected = createSelection(), moments = [];
  const timers = [], pairs = [];
  t.mock.method(globalThis, 'setTimeout', () => { timers.push('timeout'); });
  t.mock.method(globalThis, 'setInterval', () => { timers.push('interval'); });
  const services = {
    dom, format, selection: selected, packetPair: { set: (pair) => pairs.push(pair) },
    moment: (node) => moments.push(node),
    state(path, publish, error) { subscriptions.set(path, { publish, error }); return () => subscriptions.delete(path); },
    transport: {
      post(path, body, signal) { return new Promise((resolve, reject) => pending.push({ path, body, signal, resolve, reject })); },
      async get(path, args) { return { events: [{ seq: args.after + 1, sandbox: { name: 'workstation' }, fields: { request_id: 99 }, conn: 4, local: '23.1.2.3:443', peer: '10.0.0.2:52970' }] }; },
    },
  };
  const dispose = mount(root, services, { state: '/api/state/search' });
  subscriptions.get('/api/state/policy').publish({ value: { searcher: 'Firefox (scripted)', made_up: 'Every internet name', refused: 'Private names', forwarded: [] } });
  const publish = (value) => subscriptions.get('/api/state/search').publish({ revision: 500, value });
  const click = (parent, node) => { const e = new Event('click'); Object.defineProperty(e, 'target', { value: node }); parent.dispatchEvent(e); };
  return { root, subscriptions, pending, selected, moments, timers, pairs, publish, dispose, click };
}

test('stream renders every outcome, failure, host, cache and timing', (t) => {
  const h = harness(t), s = fixture();
  s.queries = [query(1, 'pending'), query(2), query(3, 'served', { results: 0, cache: 'missing' }), query(4, 'undelivered'), ...['budget', 'abandoned', 'backend_error', 'meta_error', 'error'].map((why, i) => query(i + 5, 'failed', { outcome: { status: 'failed', why, error: why === 'budget' || why === 'abandoned' ? null : `detail ${why}` } }))];
  h.publish(s);
  const stream = h.root.querySelector('.search-stream');
  assert.equal(stream.children.length, 9);
  assert.equal(stream.children[0].dataset.identity, '9');
  const empty = stream.children.find((row) => row.dataset.identity === '3');
  assert.match(empty.textContent, /Served with no results · Generation was off · 8 ms/);
  assert.equal(empty.textContent.match(/generation was off/gi).length, 1);
  const spent = stream.children.find((row) => row.dataset.identity === '5');
  assert.match(spent.textContent, /Failed: the run’s generation budget is spent · 8 ms/);
  assert.doesNotMatch(spent.textContent, /Made for this search/);
  for (const text of ['Pending', 'Served · 10 results', 'Not fully delivered', 'generation budget is spent', 'browser left before the answer', 'page maker failed — detail backend_error', 'page maker failed — detail meta_error', 'page maker failed — detail error', 'workstation · 10.0.0.2', 'Google', 'Made for this search', '8 ms']) assert.ok(stream.textContent.includes(text), text);
  assert.match(h.root.textContent, /Firefox \(scripted\)/);
  h.dispose();
});

test('until a search is selected, the result list follows the newest one', (t) => {
  const h = harness(t), s = fixture(); h.publish(s);
  const newest = s.queries.at(-1);
  const results = h.root.querySelector('.search-results');
  assert.match(results.textContent, new RegExp(`${newest.search} · `));
  assert.match(results.textContent, /Newest search; select one to keep it here\./);
  assert.equal(results.querySelector('ol').children.length, 1);
  const stream = h.root.querySelector('.search-stream');
  const older = stream.children.at(-1);
  h.click(stream, older);
  assert.doesNotMatch(results.textContent, /Newest search/);
  h.dispose();
});

test('results distinguish origin and reuse and link opened pages to their tree nodes', async (t) => {
  const h = harness(t), s = fixture(); h.publish(s);
  assert.equal(resultView(s, s.queries[0]).origin, 'Made for this search.');
  assert.match(resultView(s, s.queries[1]).origin, /First made for “A Question” on Google.*Reused/);
  const stream = h.root.querySelector('.search-stream');
  h.click(stream, stream.children[0]);
  assert.match(h.root.querySelector('.search-results').textContent, /A Question · Bing/);
  assert.match(h.root.querySelector('.search-results').textContent, /Opened.*Made by the stub generator.*12 ms/);
  assert.match(h.root.querySelector('.search-results').textContent, /Address from the world’s pool/);
  assert.match(h.root.querySelector('.search-results').textContent, /<Title>/);
  await settle();
  assert.equal(h.selected.get().event.seq, 21);
  assert.equal(h.selected.get().request, 99);
  assert.deepEqual(h.pairs.at(-1), { local: '23.1.2.3:443', peer: '10.0.0.2:52970' });
  const results = h.root.querySelector('ol');
  h.click(results, results.querySelector('button'));
  await settle();
  assert.equal(h.selected.get().event.seq, 100);
  assert.equal(h.root.querySelector('.search-node').getAttribute('aria-pressed'), 'true');
  h.dispose();
});

test('tree groups normalized searches, links, direct and fixed pages and preserves rank', (t) => {
  const s = fixture();
  s.pages.push(page('https://second.com/', { via: 'search', query: 'a question', rank: 2 }));
  const nodes = tree(s);
  assert.deepEqual(nodes.map((n) => [n.page?.url || n.id, n.depth]), [
    ['query:a question', 0], ['https://made.com/a', 1], ['https://made.com/b', 2], ['https://made.com/c', 3], ['https://second.com/', 1], ['direct', 0], ['https://typed.com/', 1], ['fixed', 0], ['https://fixed.com/', 1],
  ]);
  assert.equal(queryKey(' A\u0085\u001c B '), 'a b');
  assert.equal(queryKey('\ufeffA'), '\ufeffa');
  const h = harness(t); h.publish(s);
  assert.match(h.root.querySelector('.search-sites').textContent, /www.google.com.*142.250.1.1.*Search engine address/);
  const heads = h.root.querySelectorAll('.search-list-head');
  assert.deepEqual(heads.map((head) => [head.textContent, head.hidden]), [['Sites with no page in the tree', false], ['Names the world refused', false]]);
  assert.doesNotMatch(h.root.querySelector('.search-sites').textContent, /made.com/);
  assert.match(h.root.querySelector('.search-refused').textContent, /printer.local.*reserved or private/);
  for (const state of ['stubbed', 'stored', 'fixed', 'missing', 'not_made', 'written_live']) assert.ok(made(state).length > 5);
  h.dispose();
});

test('each search root says which engines asked, what it listed and what was opened', (t) => {
  const s = fixture();
  s.queries.push(
    query(3, 'served', { key: 'unopened', search: 'Unopened' }),
    query(4, 'served', { key: 'nothing', search: 'Nothing', results: 0, cache: 'missing' }),
    query(5, 'failed', { key: 'spent', search: 'Spent', results: null, cache: 'budget', outcome: { status: 'failed', why: 'budget' } }),
    query(6, 'served', { key: 'dropped', search: 'Dropped', engine: 'duckduckgo' }),
  );
  s.results.push({ key: 'unopened', query_id: 3, cache: 'generated', listed: [1, 2, 3].map((rank) => ({ rank, title: 'T', host: 'x.com', url: `https://x.com/${rank}` })) });
  s.results.push({ key: 'nothing', query_id: 4, cache: 'missing', listed: [] });
  s.pages.push(page('https://kept.com/', { via: 'search', query: 'Gone', rank: 4 }));
  const notes = new Map(tree(s).filter((n) => !n.page).map((n) => [n.id, rootNote(s, n)]));
  assert.equal(notes.get('query:a question'), 'Google, Bing · 1 result listed · 1 opened');
  assert.equal(notes.get('query:unopened'), 'Google · 3 results listed · none opened yet');
  s.pages.push(page('https://x.com/2', { via: 'direct' }));
  assert.equal(rootNote(s, tree(s).find((n) => n.id === 'query:unopened')), 'Google · 3 results listed · 1 opened · 1 shown under another reason');
  s.pages.pop();
  s.pages.push(page('https://x.com/3', { via: 'search', query: 'unopened', rank: 3 }));
  assert.equal(rootNote(s, tree(s).find((n) => n.id === 'query:unopened')), 'Google · 3 results listed · 1 opened');
  s.pages.pop();
  assert.equal(notes.get('query:nothing'), 'Google · No results listed');
  assert.equal(notes.get('query:spent'), 'Google · Failed: the run’s generation budget is spent');
  assert.equal(notes.get('query:gone'), 'Search no longer held · 1 opened');
  assert.equal(notes.get('query:dropped'), 'DuckDuckGo · 10 results listed · none opened yet');
  assert.equal(notes.get('direct'), '');
  const h = harness(t); h.publish(s);
  const roots = h.root.querySelectorAll('.search-root');
  assert.ok(roots.some((node) => /Unopened.*3 results listed · none opened yet/.test(node.textContent)));
  h.dispose();
});

test('list headings hide when their lists are empty and the switch is unknown until state arrives', (t) => {
  const h = harness(t);
  assert.equal(h.root.querySelector('.search-toggle').dataset.known, 'false');
  const s = fixture(); s.sites = []; s.refused = []; s.pages = []; s.queries = []; s.results = [];
  h.publish(s);
  assert.equal(h.root.querySelector('.search-toggle').dataset.known, 'true');
  assert.ok(h.root.querySelectorAll('.search-list-head').every((head) => head.hidden));
  const note = h.root.querySelectorAll('.search-empty').find((node) => node.textContent.startsWith('No pages yet'));
  assert.equal(note.hidden, false);
  h.dispose();
});

test('missing sources and cycles do not lose pages or loop', () => {
  const s = fixture();
  s.pages = [page('https://a.com/', { via: 'link', from: 'https://b.com/' }), page('https://b.com/', { via: 'link', from: 'https://a.com/' }), page('https://c.com/', { via: 'link', from: 'https://removed.com/' })];
  assert.equal(tree(s).filter((n) => n.page).length, 3);
});

test('counts exclude missing pages and separate served, empty and failed searches', (t) => {
  const s = fixture();
  s.queries.push(query(3, 'served', { results: 0 }), query(4, 'failed'), query(5, 'undelivered'), query(6, 'pending'));
  s.pages.push(page('https://missing.com/', { via: 'direct' }, { made: 'missing' }));
  assert.deepEqual(counts(s), { Searches: 6, Served: 2, 'No results': 1, Failed: 1, 'Pages made': 5, Sites: 2, Refused: 1 });
  s.omitted.pages = 4;
  const h = harness(t); h.publish(s);
  assert.match(h.root.textContent, /No longer held here: 4 pages\. The counts describe what is held\./);
  h.dispose();
});

test('switch posts the world revision, waits, reports stale and never retries', async (t) => {
  const h = harness(t), s = fixture(); h.publish(s);
  const toggle = h.root.querySelector('.search-toggle'); toggle.click();
  assert.equal(toggle.disabled, true);
  assert.match(toggle.textContent, /Waiting/);
  assert.deepEqual(h.pending[0].body.command, { command: 'set_generation', generate: false, expected_revision: 7 });
  assert.equal(h.pending[0].path, '/api/command/generation');
  toggle.click(); assert.equal(h.pending.length, 1);
  h.pending[0].reject({ body: { rejection: { reason: 'stale_revision', current: 8 } } });
  await settle();
  assert.match(h.root.textContent, /switch changed elsewhere. Current revision 8/);
  assert.equal(toggle.disabled, true);
  h.publish({ ...s, generator: { ...s.generator, generation_revision: 8, generate: false } });
  assert.equal(toggle.disabled, false);
  assert.equal(h.pending.length, 1);
  assert.equal(toggle.textContent, 'Serving only what exists');
  toggle.click();
  assert.equal(h.pending[1].body.command.expected_revision, 8);
  h.pending[1].resolve({ status: 'applied', reply: { revision: 9, at_ms: 6000 } });
  await settle();
  assert.match(h.root.textContent, /Applied at 6.00 s · revision 9/);
  assert.equal(toggle.disabled, true);
  h.publish({ ...s, generator: { ...s.generator, generation_revision: 9, generate: true } });
  assert.match(h.root.textContent, /Applied at 6.00 s · revision 9/);
  assert.equal(toggle.disabled, false);
  h.publish({ ...s, generator: { ...s.generator, generation_revision: 10, generate: false } });
  assert.equal(h.root.querySelector('.search-command').textContent, '');
  h.dispose();
});

test('diffing retains elements and scrolling and marks each new site once', (t) => {
  const h = harness(t), s = fixture(); h.publish(s);
  const stream = h.root.querySelector('.search-stream'), row = stream.children[0];
  const node = h.root.querySelector('.search-node');
  stream.scrollTop = 40;
  const moments = h.moments.length;
  h.publish(structuredClone(s));
  assert.equal(stream.children[0], row);
  assert.equal(h.root.querySelector('.search-node'), node);
  assert.equal(stream.scrollTop, 40);
  assert.equal(h.moments.length, moments);
  s.queries.push(query(3)); h.publish(s);
  assert.equal(stream.children[1], row);
  s.queries.shift(); h.publish(s);
  assert.equal(stream.children.length, 2);
  h.dispose();
});

test('dispose removes listeners and subscriptions, aborts requests and ignores late data', async (t) => {
  const h = harness(t); h.publish(fixture());
  const callbacks = [...h.subscriptions.values()];
  const elements = h.root.querySelectorAll('button').concat(h.root.querySelectorAll('div'), h.root.querySelectorAll('ol'));
  h.root.querySelector('.search-toggle').click();
  h.dispose();
  assert.equal(h.subscriptions.size, 0);
  assert.equal(h.pending[0].signal.aborted, true);
  assert.equal(h.timers.length, 0);
  assert.ok(elements.every((e) => e.listenerCount === 0));
  callbacks.forEach((cb) => cb.publish({ value: fixture() }));
  h.pending[0].resolve({ status: 'applied', reply: { revision: 8, at_ms: 6000 } });
  await settle();
  assert.equal(h.root.children.length, 0);
});

test('a later result list is never attributed to an earlier empty search', () => {
  const s = fixture();
  s.results[0].query_id = 9;
  assert.deepEqual(resultView(s, query(1, 'served', { results: 0, cache: 'missing' })), { origin: 'No results: generation was off for this search.', rows: [] });
  assert.match(resultView(s, s.queries[0]).origin, /made after this search/);
  assert.equal(resultView(s, query(3, 'pending')).rows.length, 0);
  assert.deepEqual(resultView(s, query(4, 'failed', { key: 'a question', results: null, outcome: { status: 'failed', why: 'budget' } })), { origin: 'Failed: the run’s generation budget is spent. The world made no result list for it.', rows: [] });
});

test('every page creation mode and first and latest latency render as words', (t) => {
  const h = harness(t), s = fixture();
  s.pages = ['stubbed', 'stored', 'fixed', 'missing', 'not_made', 'written_live'].map((state) => page(`https://${state.replace('_', '-')}.com/`, { via: 'direct' }, { made: state }));
  h.publish(s);
  const text = h.root.querySelector('.search-tree').textContent;
  for (const phrase of ['Made by the stub generator', 'Served from memory', 'Written into the seed', 'Not made, so 404', 'Not made: over the budget', 'Written by a model', 'first 12 ms · latest 3 ms · 2 fetches']) assert.ok(text.includes(phrase), phrase);
  h.dispose();
});

test('the first page on a new pool site gets the story moment, once per site', (t) => {
  const h = harness(t), s = fixture(); h.publish(s);
  assert.equal(h.moments.length, 0);
  s.sites.push({ host: 'new.com', address: '23.1.2.4', reason: 'pool' }, { host: 'engine.com', address: '23.1.2.5', reason: 'search_engine' });
  h.publish(s);
  assert.equal(h.moments.length, 0, 'a lookup with no page is not a moment');
  s.pages.push(page('https://new.com/', { via: 'direct' }), page('https://engine.com/', { via: 'direct' })); h.publish(s);
  assert.equal(h.moments.length, 1);
  assert.match(h.moments[0].textContent, /new\.com/);
  h.publish(structuredClone(s));
  assert.equal(h.moments.length, 1);
  s.pages.push(page('https://new.com/2', { via: 'direct' })); h.publish(s);
  assert.equal(h.moments.length, 1);
  s.pages.push(page('https://made.com/later', { via: 'direct' })); h.publish(s);
  assert.equal(h.moments.length, 1, 'sites already on screen when the panel opened get none');
  h.dispose();
});

test('refusals in the same millisecond remain separate rows', (t) => {
  const h = harness(t), s = fixture();
  s.refused.push({ ...s.refused[0] });
  h.publish(s);
  const list = h.root.querySelector('.search-refused');
  assert.equal(list.children.length, 2);
  const first = list.children[0];
  h.publish(structuredClone(s));
  assert.equal(list.children[0], first);
  assert.equal(list.children.length, 2);
  h.dispose();
});
