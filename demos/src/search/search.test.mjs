import test from 'node:test';
import assert from 'node:assert/strict';
import { createDocument } from '../../../dashboard/test-dom.mjs';
import { createServices } from '../../../dashboard/page.mjs';
import { picture, rows, queryTag, pageTag, short } from './model.mjs';
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

test('searches and pages say whether they were canned, made now or served again', () => {
  const s = fixture();
  assert.deepEqual(s.queries.map((q) => queryTag(s, q)), ['canned', 'canned', 'made', 'memory']);
  assert.equal(queryTag(s, query(9, { outcome: { status: 'pending' } })), 'asking');
  assert.equal(queryTag(s, query(9, { cache: 'missing', results: 0 })), 'missing');
  assert.equal(queryTag(s, query(9, { outcome: { status: 'failed', why: 'budget' } })), 'refused');
  assert.deepEqual(s.pages.map(pageTag), ['canned', 'memory']);
  assert.equal(pageTag(page('https://a.com/', { made: 'stubbed', latest: 'stored', fetches: 3 })), 'memory');
  assert.equal(pageTag(page('https://a.com/', { made: 'planted' })), 'planted');
  assert.equal(short('www.halvardsystems.com'), 'halvardsystems');
  assert.equal(short('www.theregister.co.uk'), 'theregister');
});

test('the rows are the newest six, newest first', () => {
  const s = fixture();
  const all = rows(s);
  assert.equal(all.length, 6);
  assert.deepEqual(all.map((row) => row.tag), ['planted', 'refused', 'memory', 'canned', 'memory', 'made']);
  assert.deepEqual(all[1], { at: 7000, who: 'DNS', what: 'wiki.corp', tag: 'refused' });
  assert.equal(all[2].what, '/r/x');
  assert.equal(rows(s, 2).length, 2);
  const agent = { ...s, queries: [query(9, { via: 'web_search', at_ms: 9000 })] };
  assert.equal(rows(agent)[0].who, 'WebSearch');
});

test('the picture shows the newest search, its engines and the sites its list named', () => {
  const view = picture(fixture());
  assert.equal(view.query, 'new words');
  assert.deepEqual(view.engines.map((e) => [e.label, e.tag]), [['Google', 'memory'], ['Bing', 'idle'], ['DuckDuckGo', 'made']]);
  assert.deepEqual(view.sites.map((site) => [site.label, site.pages, site.seed]), [['halvardsystems', 1, true], ['reddit', 1, false], ['theregister', 0, false]]);
  assert.equal(view.refused, 'wiki.corp');
  assert.deepEqual(view.planted, [{ label: 'fact', text: 'The fix is 7.2.5, not 7.2.4.' }]);
  assert.equal(picture({ ...fixture(), queries: [], results: [], refused: [], planted: [] }).query, null);
});

function harness() {
  const document = createDocument(), root = document.createElement('div');
  const subscriptions = new Map(), posts = [];
  const services = createServices({
    async post(path, body) { posts.push({ path, body }); return { status: 'applied', reply: { revision: 4, at_ms: 9000 } }; },
  });
  services.worldMenu = document.createElement('div');
  services.state = (path, publish) => { subscriptions.set(path, publish); return () => subscriptions.delete(path); };
  const dispose = mount(root, services, { state: '/api/state/search' });
  return { root, services, subscriptions, posts, dispose, publish: (value) => subscriptions.get('/api/state/search')({ value }) };
}

test('the world pane draws the picture and rows without explaining them', () => {
  const h = harness();
  h.publish(fixture());
  const text = h.root.textContent;
  for (const word of ['Google', 'Bing', 'DuckDuckGo', 'new words', 'halvardsystems', 'wiki.corp', 'planted']) assert.match(text, new RegExp(word));
  assert.equal(h.root.querySelectorAll('.search-row').length, 6);
  for (const caption of ['made up', 'stub generator', 'scripted', 'Firefox', 'seed', 'world']) assert.doesNotMatch(text, new RegExp(caption, 'i'));
  h.dispose();
  assert.equal(h.subscriptions.size, 0);
  assert.equal(h.services.worldMenu.children.length, 0);
});

test('the World menu chooses new pages, plants a fact and a page, and restarts at the shown revision', async () => {
  const h = harness();
  h.publish(fixture());
  const menu = h.services.worldMenu;
  const [canned, stub, off] = menu.querySelector('.seg').children;
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
