import test from 'node:test';
import assert from 'node:assert/strict';
import { rows, diff, queryTag } from './model.mjs';

const snapshot = () => ({ revision: 1, at_ms: 10, queries: [], results: [], pages: [], refused: [], planted: [] });
const query = (via, id = 1) => ({ id, key: 'sqlite wal', search: 'sqlite WAL', engine: 'google', via, at_ms: id, seq: id, cache: 'cached', outcome: { status: 'served' } });

test('Claude and Codex tool searches have distinct source names and one row each', () => {
  const s = snapshot();
  s.queries = [query('claude_web_search'), query('codex_web_search', 2)];
  const shown = rows(s);
  assert.equal(shown.length, 2);
  assert.deepEqual(shown.map(r => r.who), ['Codex', 'Claude Code']);
  assert.ok(shown.every(r => r.what === '“sqlite WAL”' && r.tag === 'stored'));
});

test('command-line searches are named separately from browser engine searches', () => {
  const s = snapshot();
  s.queries = [query('browser'), query('command_line', 2)];
  assert.deepEqual(rows(s).map(r => r.who), ['Command line', 'Google']);
});

test('an empty fallback is shown as missing without inventing results', () => {
  const s = snapshot();
  s.queries = [{ ...query('claude_web_search'), cache: 'missing', results: 0 }];
  assert.equal(queryTag(s, s.queries[0]), 'missing');
  const changes = diff(null, s);
  assert.equal(changes.filter(c => c.type === 'search_answered').length, 1);
  assert.deepEqual(changes.find(c => c.type === 'search_answered').list, []);
});

test('answering a tool search uses the returned stored list in rank order', () => {
  const before = snapshot(), after = snapshot();
  before.queries = [{ ...query('claude_web_search'), outcome: { status: 'pending' } }];
  after.queries = [query('claude_web_search')];
  after.results = [{ key: 'sqlite wal', listed: [{ rank: 2, title: 'Isolation' }, { rank: 1, title: 'WAL' }] }];
  const changes = diff(before, after);
  assert.deepEqual(changes.map(c => c.type), ['search_answered']);
  assert.deepEqual(changes[0].list.map(r => r.title), ['WAL', 'Isolation']);
});
