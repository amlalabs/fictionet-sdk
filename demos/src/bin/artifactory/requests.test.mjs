import test from 'node:test';
import assert from 'node:assert/strict';
import { harness, request, step, SCENARIO } from './fake-services.mjs';
import { mount, statusText } from './requests.mjs';
import { FAMILIES } from './common.mjs';

const REQUESTS = '/api/state/requests', DOORS = '/api/state/doors-tried';

function fixture() {
  const f = harness(mount, REQUESTS);
  f.requests = (rows, extra = {}, status) => f.publish(REQUESTS, { rows, dropped: 0, lost: 0, ...extra }, status);
  f.story = (story) => f.publish(DOORS, { rows: [], story, scenario: SCENARIO, dropped: 0, lost: 0 });
  return f;
}
const rows = (f) => f.root.querySelectorAll('tr.requests-row');
const cells = (tr) => tr.querySelectorAll('td').map((td) => td.textContent);

test('an empty table says rows come as the story runs', () => {
  const f = fixture();
  assert.match(f.root.textContent, /Loading requests/);
  f.requests([]);
  const empty = f.root.querySelector('.empty-cell');
  assert.equal(empty.textContent, 'No requests yet. They appear as the story runs.');
  assert.equal(empty.parent.parent.hidden, false);
  f.requests([request()]);
  assert.equal(empty.parent.parent.hidden, true);
  f.dispose();
});

test('each row shows its step, classification badge and answer', () => {
  const f = fixture();
  f.story([step('Try the lookalike'), step('Try a credentialed upload')]);
  f.requests([
    request({ seq: 3, classification: 'file', family: 'lookalike', path: '/packages/northwind-ledgr/w.whl', package: { project: 'northwind-ledgr', filename: 'w.whl', role: 'lookalike' } }),
    request({ seq: 4, method: 'POST', path: '/', classification: 'write_refused', family: 'write', credential: { scheme: 'basic', user: '<i>x</i>', secret_len: 1, secret: 'x' }, outcome: { status: 403, kind: 'refused', sent: 20, complete: true } }, { step: 'Try a credentialed upload', at: 30.12 }),
    request({ seq: 5, classification: 'upstream_fetch', family: 'upstream', ssrf_targets: 2, scan_complete: false, outcome: { status: 502, kind: 'failed', sent: 0, complete: false } }, { traffic: 'setup', step: 'setup' }),
    request({ seq: 6, host: null, classification: 'no_host', family: 'left' }, { traffic: 'other' }),
  ]);
  const [lookalike, upload, fetch, left] = rows(f);
  assert.deepEqual(cells(lookalike), ['2.0s', '1', 'file', 'GET', 'artifactory.northwind.internal', '/packages/northwind-ledgr/w.whl', '200 served', 'northwind-ledgr', '', '0']);
  assert.deepEqual(cells(upload), ['30.1s', '2', 'write refused', 'POST', 'artifactory.northwind.internal', '/', '403 refused', '', 'Basic, user <i>x</i>, 1-byte secret', '0']);
  assert.deepEqual(cells(fetch).slice(1), ['setup', 'upstream fetch', 'GET', 'artifactory.northwind.internal', '/simple/', '502 failed, cut off', '', '', '2+']);
  assert.equal(cells(left)[1], 'other');
  assert.equal(cells(left)[4], '(no host)');
  assert.deepEqual([lookalike, upload, fetch, left].map((tr) => tr.querySelectorAll('.pill')[0].getAttribute('class')), ['pill family-lookalike', 'pill family-write', 'pill family-upstream', 'pill family-left']);
  assert.equal(f.root.querySelector('i'), null);
  assert.doesNotMatch(f.root.textContent, /secret: /);
  f.dispose();
});

test('the legend names the five families', () => {
  const f = fixture();
  const legend = f.root.querySelector('.requests-legend');
  assert.deepEqual(legend.querySelectorAll('.pill').map((pill) => [pill.getAttribute('class'), pill.textContent]), FAMILIES.map(([id, label]) => [`pill family-${id}`, label]));
  f.dispose();
});

test('selecting a row selects its request and connection and opens its flow', () => {
  const f = fixture();
  f.requests([request({ seq: 3, conn: 17 }), request({ seq: 8, conn: null, local: null, peer: null })]);
  const [first, second] = rows(f);
  first.click();
  assert.equal(f.selection.get().request, 3);
  assert.equal(f.selection.get().connection, 17);
  assert.equal(f.selection.get().event, null);
  assert.equal(first.classList.contains('on'), true);
  const detail = f.root.querySelector('.requests-detail');
  assert.equal(detail.hidden, false);
  assert.match(detail.textContent, /GET artifactory.northwind.internal\/simple\/.*Connection17.*World address10.20.0.15:443.*Guest address10.0.0.2:40100/);
  const [events, packets] = detail.querySelectorAll('button');
  events.click();
  packets.click();
  assert.deepEqual(f.panels, ['events']);
  assert.deepEqual(f.pairs, [{ local: '10.20.0.15:443', peer: '10.0.0.2:40100' }]);
  second.click();
  assert.equal(f.selection.get().connection, null);
  assert.equal(events.disabled, true);
  assert.equal(packets.disabled, true);
  second.click();
  assert.equal(f.selection.get().request, null);
  assert.equal(detail.hidden, true);
  f.dispose();
});

test('a selection made elsewhere marks its row', () => {
  const f = fixture();
  f.requests([request({ seq: 3 }), request({ seq: 4 })]);
  f.selection.set({ request: 4, connection: 7 });
  assert.deepEqual(rows(f).map((tr) => tr.getAttribute('aria-selected')), ['false', 'true']);
  f.dispose();
});

test('dropped rows, lost observations and moments stay visible', () => {
  const f = fixture();
  f.requests([request({ seq: 600 })], { dropped: 89, lost: 2 }, { too_large: true });
  assert.match(f.root.querySelector('.loss-note').textContent, /89 older rows dropped. The page keeps the latest 1.*2 observations lost.*byte bound/);
  assert.equal(rows(f)[0].classList.contains('moment'), false);
  f.mark(600);
  assert.equal(rows(f)[0].classList.contains('moment'), true);
  f.fail(DOORS, new Error('<gone>'));
  assert.match(f.root.querySelector('.loss-note').textContent, /Could not load doors: <gone>/);
  f.dispose();
});

test('status text shows the code, kind and a cut-off answer', () => {
  assert.equal(statusText({ status: 404, kind: 'not_found', complete: true }), '404 not found');
  assert.equal(statusText({ status: null, kind: 'unanswered', complete: false }), 'unanswered, cut off');
  assert.equal(statusText(null), '—');
});

test('dispose releases subscriptions, listeners and moments', () => {
  const f = fixture();
  f.requests([request({ seq: 3 })]);
  const before = f.listeners();
  assert.ok(before >= 4);
  assert.equal(f.subscriptions.size, 2);
  assert.equal(f.momentListeners.size, 1);
  const tr = rows(f)[0], buttons = f.root.querySelectorAll('button');
  const update = f.subscriptions.get(REQUESTS);
  f.dispose();
  assert.equal(f.subscriptions.size, 0);
  assert.equal(f.momentListeners.size, 0);
  assert.equal(tr.listenerCount + buttons.reduce((n, node) => n + node.listenerCount, 0), 0);
  tr.click();
  assert.equal(f.selection.get().request, null);
  update({ value: { rows: [request()], dropped: 0, lost: 0 } });
  f.selection.set({ request: 3 });
  assert.equal(f.root.children.length, 0);
});
